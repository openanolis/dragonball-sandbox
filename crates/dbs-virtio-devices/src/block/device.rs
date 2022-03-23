// Copyright (C) 2019-2020 Alibaba Cloud. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::io::{Seek, SeekFrom};
use std::marker::PhantomData;
use std::sync::{mpsc, Arc};
use std::thread;
use std::any::Any;
use std::collections::HashMap;

use dbs_device::resources::ResourceConstraint;
use dbs_utils::{
    epoll_manager::{EpollManager, SubscriberId},
    rate_limiter::{BucketUpdate, RateLimiter},
};
use log::{debug, error, info, warn};
use virtio_bindings::bindings::virtio_blk::*;
use virtio_queue::QueueStateT;
use vm_memory::GuestMemoryRegion;
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use crate::{
    ActivateError, ActivateResult, DbsGuestAddressSpace, Error, Result, VirtioDevice,
    VirtioDeviceConfig, VirtioDeviceInfo, TYPE_BLOCK,
};

use super::{BlockEpollHandler, InnerBlockEpollHandler, KillEvent, Ufile, BLK_DRIVER_NAME, SECTOR_SHIFT, SECTOR_SIZE};

/// Supported fields in the configuration space:
/// - 64-bit disk size
/// - 32-bit size max
/// - 32-bit seg max
/// - 16-bit num_queues at offset 34
const CONFIG_SPACE_SIZE: usize = 64;

/// Max segments in a data request.
const CONFIG_MAX_SEG: u32 = 16;

fn build_device_id(disk_image: &dyn Ufile) -> Vec<u8> {
    let mut default_disk_image_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
    match disk_image.get_device_id() {
        Err(_) => warn!("Could not generate device id. We'll use a default."),
        Ok(m) => {
            // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
            // This will also zero out any leftover bytes.
            let disk_id = m.as_bytes();
            let bytes_to_copy = std::cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
            default_disk_image_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy])
        }
    }
    default_disk_image_id
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block<AS: DbsGuestAddressSpace> {
    pub(crate) device_info: VirtioDeviceInfo,
    disk_images: Vec<Box<dyn Ufile>>,
    rate_limiters: Vec<RateLimiter>,
    queue_sizes: Arc<Vec<u16>>,
    subscriber_id: Option<SubscriberId>,
    kill_evts: Vec<EventFd>,
    evt_senders: Vec<mpsc::Sender<KillEvent>>,
    epoll_threads: Vec<thread::JoinHandle<()>>,
    phantom: PhantomData<AS>,
}

impl<AS: DbsGuestAddressSpace> Block<AS> {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(
        mut disk_images: Vec<Box<dyn Ufile>>,
        is_disk_read_only: bool,
        queue_sizes: Arc<Vec<u16>>,
        epoll_mgr: EpollManager,
        rate_limiters: Vec<RateLimiter>,
    ) -> Result<Self> {
        let num_queues = disk_images.len();

        if num_queues == 0 {
            return Err(Error::InvalidInput);
        }

        let disk_image = &mut disk_images[0];

        let disk_size = disk_image.seek(SeekFrom::End(0)).map_err(Error::IOError)? as u64;
        if disk_size % SECTOR_SIZE != 0 {
            warn!(
                "Disk size {} is not a multiple of sector size {}; \
                 the remainder will not be visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }
        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;
        avail_features |= 1u64 << VIRTIO_BLK_F_SIZE_MAX;
        avail_features |= 1u64 << VIRTIO_BLK_F_SEG_MAX;

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        if num_queues > 1 {
            avail_features |= 1u64 << VIRTIO_BLK_F_MQ;
        }

        let config_space =
            Self::build_config_space(disk_size, disk_image.get_max_size(), num_queues as u16);

        Ok(Block {
            device_info: VirtioDeviceInfo::new(
                BLK_DRIVER_NAME.to_string(),
                avail_features,
                queue_sizes.clone(),
                config_space,
                epoll_mgr,
            ),
            disk_images,
            rate_limiters,
            queue_sizes,
            subscriber_id: None,
            phantom: PhantomData,
            evt_senders: Vec::with_capacity(num_queues),
            kill_evts: Vec::with_capacity(num_queues),
            epoll_threads: Vec::with_capacity(num_queues),
        })
    }

    fn build_config_space(disk_size: u64, max_size: u32, num_queues: u16) -> Vec<u8> {
        // The disk size field of the configuration space, which uses the first two words.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        // The config space is little endian.
        let mut config = Vec::with_capacity(CONFIG_SPACE_SIZE);
        let num_sectors = disk_size >> SECTOR_SHIFT;
        for i in 0..8 {
            config.push((num_sectors >> (8 * i)) as u8);
        }

        // The max_size field of the configuration space.
        for i in 0..4 {
            config.push((max_size >> (8 * i)) as u8);
        }

        // The max_seg field of the configuration space.
        let max_segs = CONFIG_MAX_SEG;
        for i in 0..4 {
            config.push((max_segs >> (8 * i)) as u8);
        }

        for _i in 0..18 {
            config.push(0_u8);
        }

        for i in 0..2 {
            config.push((num_queues >> (8 * i)) as u8);
        }

        config
    }

    pub fn set_patch_rate_limiters(&self, bytes: BucketUpdate, ops: BucketUpdate) -> Result<()> {
        if self.evt_senders.is_empty()
            || self.kill_evts.is_empty()
            || self.evt_senders.len() != self.kill_evts.len()
        {
            error!("virtio-blk: failed to establish channel to send rate-limiter patch data");
            return Err(Error::InternalError);
        }

        for sender in self.evt_senders.iter() {
            if sender
                .send(KillEvent::BucketUpdate(bytes.clone(), ops.clone()))
                .is_err()
            {
                error!("virtio-blk: failed to send rate-limiter patch data");
                return Err(Error::InternalError);
            }
        }

        for kill_evt in self.kill_evts.iter() {
            if let Err(e) = kill_evt.write(1) {
                error!(
                    "virtio-blk: failed to write rate-limiter patch event {:?}",
                    e
                );
                return Err(Error::InternalError);
            }
        }

        Ok(())
    }
}

impl<AS, Q, R> VirtioDevice<AS, Q, R> for Block<AS>
where
    AS: DbsGuestAddressSpace,
    Q: QueueStateT + Send + 'static,
    R: GuestMemoryRegion + Sync + Send + 'static,
{
    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn get_avail_features(&self, page: u32) -> u32 {
        self.device_info.get_avail_features(page)
    }

    fn set_acked_features(&mut self, page: u32, value: u32) {
        self.device_info.set_acked_features(page, value)
    }

    fn read_config(&mut self, offset: u64, data: &mut [u8]) {
        self.device_info.read_config(offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        self.device_info.write_config(offset, data)
    }

    fn activate(&mut self, mut config: VirtioDeviceConfig<AS, Q, R>) -> ActivateResult {
        self.device_info
            .check_queue_sizes(&config.queues[..])
            .map_err(|e| e)?;

        if self.disk_images.len() != config.queues.len() {
            error!(
                "The disk images number: {} is not equal to queues number: {}",
                self.disk_images.len(),
                config.queues.len()
            );
            return Err(ActivateError::InternalError);
        }
        let mut kill_evts = Vec::with_capacity(self.queue_sizes.len());

        let mut i = 0;
        // first to reverse the queue's order, thus to make sure the following
        // pop queue got the right queue order.
        config.queues.reverse();
        while let Some(queue) = config.queues.pop() {
            let disk_image = self.disk_images.pop().unwrap();
            let disk_image_id = build_device_id(disk_image.as_ref());

            let data_desc_vec =
                vec![Vec::with_capacity(CONFIG_MAX_SEG as usize); self.queue_sizes[0] as usize];
            let iovecs_vec =
                vec![Vec::with_capacity(CONFIG_MAX_SEG as usize); self.queue_sizes[0] as usize];

            let rate_limiter = self.rate_limiters.pop().unwrap_or_default();

            let (evt_sender, evt_receiver) = mpsc::channel();
            self.evt_senders.push(evt_sender);

            let kill_evt = EventFd::new(EFD_NONBLOCK)?;

            let mut handler = Box::new(InnerBlockEpollHandler {
                rate_limiter,
                disk_image,
                disk_image_id,
                pending_req_map: HashMap::new(),
                data_desc_vec,
                iovecs_vec,
                evt_receiver,
                vm_as: config.vm_as.clone(),
                queue,
                kill_evt: kill_evt.try_clone().unwrap(),
            });

            kill_evts.push(kill_evt.try_clone().unwrap());
            self.kill_evts.push(kill_evt);

            thread::Builder::new()
                .name(format!("{}_q{}", "blk_iothread", i))
                .spawn(move || {
                    if let Err(e) = handler.run() {
                        error!("Error running worker: {:?}", e);
                    }
                })
                .map(|thread| self.epoll_threads.push(thread))
                .map_err(|e| {
                    error!("failed to clone the virtio-block epoll thread: {}", e);
                    ActivateError::InternalError
                })?;

            i += 1;
        }
        let block_handler = Box::new(BlockEpollHandler {
            kill_evts,
            evt_senders: self.evt_senders.clone(),
            config,
        });

        // subscribe this handler for io drain.
        self.subscriber_id = Some(self.device_info.register_event_handler(block_handler));

        Ok(())
    }

    fn reset(&mut self) -> ActivateResult {
        Ok(())
    }

    fn remove(&mut self) {
        // if the subsriber_id is invalid, it has not been activated yet.
        if let Some(subscriber_id) = self.subscriber_id {
            // Remove BlockEpollHandler from event manager, so it could be dropped and the resources
            // could be freed, e.g. close disk_image, so vmm won't hold the backend file.
            match self.device_info.remove_event_handler(subscriber_id) {
                Ok(_) => debug!("virtio-blk: removed subscriber_id {:?}", subscriber_id),
                Err(e) => {
                    warn!("virtio-blk: failed to remove event handler: {:?}", e);
                }
            }
        }

        for sender in self.evt_senders.iter() {
            if sender.send(KillEvent::Kill).is_err() {
                error!("virtio-blk: failed to send kill event to epoller thread");
            }
        }

        // notify the io threads handlers to terminate.
        for kill_evt in self.kill_evts.iter() {
            if let Err(e) = kill_evt.write(1) {
                error!("virtio-blk: failed to write kill event {:?}", e);
            }
        }

        while let Some(thread) = self.epoll_threads.pop() {
            if let Err(e) = thread.join() {
                error!("virtio-blk: failed to reap the io threads: {:?}", e);
            } else {
                info!("io thread got reaped.");
            }
        }

        self.subscriber_id = None;
    }

    fn get_resource_requirements(
        &self,
        requests: &mut Vec<ResourceConstraint>,
        use_generic_irq: bool,
    ) {
        requests.push(ResourceConstraint::LegacyIrq { irq: None });
        if use_generic_irq {
            requests.push(ResourceConstraint::GenericIrq {
                size: (self.queue_sizes.len() + 1) as u32,
            });
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
