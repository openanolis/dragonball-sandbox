// Copyright 2022 Alibaba Cloud. All Rights Reserved.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use std::any::Any;
use std::marker::PhantomData;
use std::sync::Arc;

use dbs_device::resources::ResourceConstraint;
use dbs_utils::epoll_manager::{EpollManager, SubscriberId};
use log::trace;
use virtio_queue::QueueStateT;
use vm_memory::GuestAddressSpace;
use vm_memory::GuestMemoryRegion;

use super::backend::VsockBackend;
use super::defs::uapi;
use super::epoll_handler::VsockEpollHandler;
use super::muxer::{Error as MuxerError, VsockGenericMuxer, VsockMuxer};
use super::{Result, VsockError};
use crate::device::{VirtioDeviceConfig, VirtioDeviceInfo};
use crate::{ActivateResult, DbsGuestAddressSpace, VirtioDevice};

const VSOCK_DRIVER_NAME: &str = "virtio-vsock";
const VSOCK_CONFIG_SPACE_SIZE: usize = 8;
const VSOCK_AVAIL_FEATURES: u64 =
    1u64 << uapi::VIRTIO_F_VERSION_1 | 1u64 << uapi::VIRTIO_F_IN_ORDER;

/// This is the `VirtioDevice` implementation for our vsock device. It handles
/// the virtio-level device logic: feature negociation, device configuration,
/// and device activation. The run-time device logic (i.e. event-driven data
/// handling) is implemented by `super::epoll_handler::EpollHandler`.
///
/// The vsock device has two input parameters: a CID to identify the device, and
/// a `VsockBackend` to use for offloading vsock traffic.
///
/// Upon its activation, the vsock device creates its `EpollHandler`, passes it
/// the event-interested file descriptors, and registers these descriptors with
/// the VMM `EpollContext`. Going forward, the `EpollHandler` will get notified
/// whenever an event occurs on the just-registered FDs:
/// - an RX queue FD;
/// - a TX queue FD;
/// - an event queue FD; and
/// - a backend FD.
pub struct Vsock<AS: GuestAddressSpace, M: VsockGenericMuxer = VsockMuxer> {
    cid: u64,
    queue_sizes: Arc<Vec<u16>>,
    device_info: VirtioDeviceInfo,
    subscriber_id: Option<SubscriberId>,
    muxer: Option<M>,
    phantom: PhantomData<AS>,
}

// Default muxer implementation of Vsock
impl<AS: GuestAddressSpace> Vsock<AS> {
    /// Create a new virtio-vsock device with the given VM CID and vsock
    /// backend.
    pub fn new(cid: u64, queue_sizes: Arc<Vec<u16>>, epoll_mgr: EpollManager) -> Result<Self> {
        let muxer = VsockMuxer::new(cid).map_err(VsockError::Muxer)?;
        Self::new_with_muxer(cid, queue_sizes, epoll_mgr, muxer)
    }
}

impl<AS: GuestAddressSpace, M: VsockGenericMuxer> Vsock<AS, M> {
    pub(crate) fn new_with_muxer(
        cid: u64,
        queue_sizes: Arc<Vec<u16>>,
        epoll_mgr: EpollManager,
        muxer: M,
    ) -> Result<Self> {
        let mut config_space = Vec::with_capacity(VSOCK_CONFIG_SPACE_SIZE);
        for i in 0..VSOCK_CONFIG_SPACE_SIZE {
            config_space.push((cid >> (8 * i as u64)) as u8);
        }

        Ok(Vsock {
            cid,
            queue_sizes: queue_sizes.clone(),
            device_info: VirtioDeviceInfo::new(
                VSOCK_DRIVER_NAME.to_string(),
                VSOCK_AVAIL_FEATURES,
                queue_sizes,
                config_space,
                epoll_mgr,
            ),
            subscriber_id: None,
            muxer: Some(muxer),
            phantom: PhantomData,
        })
    }

    fn id(&self) -> &str {
        &self.device_info.driver_name
    }

    /// add backend for vsock muxer
    // NOTE: Backend is not allowed to add when vsock device is activated.
    pub fn add_backend(&mut self, backend: Box<dyn VsockBackend>, is_default: bool) -> Result<()> {
        if let Some(muxer) = self.muxer.as_mut() {
            muxer
                .add_backend(backend, is_default)
                .map_err(VsockError::Muxer)
        } else {
            Err(VsockError::Muxer(MuxerError::BackendAddAfterActivated))
        }
    }
}

impl<AS, Q, R, M> VirtioDevice<AS, Q, R> for Vsock<AS, M>
where
    AS: DbsGuestAddressSpace,
    Q: QueueStateT + Send + 'static,
    R: GuestMemoryRegion + Sync + Send + 'static,
    M: VsockGenericMuxer + 'static,
{
    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_VSOCK
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn get_avail_features(&self, page: u32) -> u32 {
        self.device_info.get_avail_features(page)
    }

    fn set_acked_features(&mut self, page: u32, value: u32) {
        trace!(target: "virtio-vsock", "{}: VirtioDevice::set_acked_features({}, 0x{:x})",
            self.id(), page, value
        );
        self.device_info.set_acked_features(page, value)
    }

    fn read_config(&mut self, offset: u64, data: &mut [u8]) {
        trace!(target: "virtio-vsock", "{}: VirtioDevice::read_config(0x{:x}, {:?})",
            self.id(), offset, data);
        self.device_info.read_config(offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        trace!(target: "virtio-vsock", "{}: VirtioDevice::write_config(0x{:x}, {:?})",
        self.id(), offset, data);
        self.device_info.write_config(offset, data)
    }

    fn activate(&mut self, config: VirtioDeviceConfig<AS, Q, R>) -> ActivateResult {
        trace!(target: "virtio-vsock", "{}: VirtioDevice::activate()", self.id());

        self.device_info.check_queue_sizes(&config.queues[..])?;
        let handler: VsockEpollHandler<AS, Q, R, M> = VsockEpollHandler::new(
            config,
            self.id().to_owned(),
            self.cid,
            // safe to unwrap, because we create muxer using New()
            self.muxer.take().unwrap(),
        );

        self.subscriber_id = Some(self.device_info.register_event_handler(Box::new(handler)));

        Ok(())
    }

    fn get_resource_requirements(
        &self,
        requests: &mut Vec<ResourceConstraint>,
        use_generic_irq: bool,
    ) {
        trace!(target: "virtio-vsock", "{}: VirtioDevice::get_resource_requirements()", self.id());

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
