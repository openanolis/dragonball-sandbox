// Copyright 2019-2020 Alibaba Cloud. All rights reserved.
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Traits and Structs to implement Virtio device backend drivers.

use std::any::Any;
use std::cmp;
use std::io::Write;
use std::ops::Deref;
use std::sync::Arc;

use dbs_device::resources::{DeviceResources, ResourceConstraint};
use dbs_interrupt::{InterruptNotifier, NoopNotifier};
use dbs_utils::epoll_manager::{EpollManager, EpollSubscriber, SubscriberId};
use kvm_ioctls::VmFd;
use log::{error, warn};
use virtio_queue::{AvailIter, QueueState, QueueStateT};
use vm_memory::{
    Address, GuestAddress, GuestAddressSpace, GuestMemory, GuestRegionMmap, GuestUsize,
};
use vmm_sys_util::eventfd::EventFd;

use crate::{ActivateError, ActivateResult, Error, Result};

/// Configuration information for a virtio queue.
///
/// This structure maintain all configuration information associated with a virtio queue.
/// It could be sent to a IO worker thread to process requests from the virtio queue,
/// to support multi-queue multi-worker-thread mode,
pub struct VirtioQueueConfig {
    /// Virtque object
    pub queue: QueueState,
    /// EventFd to receive queue notification from guest.
    pub eventfd: EventFd,
    /// Notifier to inject interrupt to guest.
    notifier: Box<dyn InterruptNotifier>,
    /// Queue index in the queue array.
    index: u16,
}

impl VirtioQueueConfig {
    /// Create a configuration object for a virtio queue.
    pub fn new(
        queue: QueueState,
        eventfd: EventFd,
        notifier: Box<dyn InterruptNotifier>,
        index: u16,
    ) -> Self {
        VirtioQueueConfig {
            queue,
            eventfd,
            notifier,
            index,
        }
    }

    /// Creates a VirtioQueueConfig with the specified queue size and index.
    pub fn create(queue_size: u16, index: u16) -> Result<Self> {
        let eventfd = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::IOError)?;

        Ok(VirtioQueueConfig {
            queue: QueueState::new(queue_size),
            eventfd,
            notifier: Box::new(NoopNotifier::new()),
            index,
        })
    }

    /// Get index of the queue.
    #[inline]
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Get the maximum queue size.
    #[inline]
    pub fn max_size(&self) -> u16 {
        self.queue.max_size()
    }

    /// Return the actual size of the queue, as the driver may not set up a
    /// queue as big as the device allows.
    #[inline]
    pub fn actual_size(&self) -> u16 {
        std::cmp::min(self.queue.size, self.queue.max_size)
    }

    /// A consuming iterator over all available descriptor chain heads offered by the driver.
    #[inline]
    pub fn iter<M>(&mut self, mem: M) -> Result<AvailIter<'_, M>>
    where
        M: Deref,
        M::Target: GuestMemory + Sized,
    {
        self.queue.iter(mem).map_err(Error::VirtioQueueError)
    }

    /// Puts an available descriptor head into the used ring for use by the guest.
    #[inline]
    pub fn add_used<M: GuestMemory>(&mut self, mem: &M, desc_index: u16, len: u32) {
        self.queue
            .add_used(mem, desc_index, len)
            .unwrap_or_else(|_| panic!("Failed to add used. index: {}", desc_index))
    }

    /// Consumes a notification event.
    #[inline]
    pub fn comsume_event(&self) -> Result<u64> {
        self.eventfd.read().map_err(Error::IOError)
    }

    /// Produces a queue notification.
    #[inline]
    pub fn generate_event(&self) -> Result<()> {
        self.eventfd.write(1).map_err(Error::IOError)
    }

    /// Injects an interrupt to guest to notify queue change events.
    #[inline]
    pub fn notify(&self) -> Result<()> {
        self.notifier.notify().map_err(Error::IOError)
    }

    /// Sets event notifier to inject intterupt.
    #[inline]
    pub fn set_notifier(&mut self, notifier: Box<dyn InterruptNotifier>) {
        self.notifier = notifier;
    }
}

/// Virtio device configuration information.
///
/// This structure maintains all configuration information for a virtio device. It will be passed
/// to VirtioDevice::activate() and the virito device will take ownership of the configuration
/// object. On VirtioDevice::reset(), the configuration object should be returned to the caller.
pub struct VirtioDeviceConfig<AS: GuestAddressSpace> {
    /// Guest memory accessor.
    pub vm_as: AS,
    /// VmFd associated with this virtio device.
    pub vm_fd: Arc<VmFd>,
    /// Resources this virtio device needs.
    pub resources: DeviceResources,
    /// Virtques for normal data requests.
    pub queues: Vec<VirtioQueueConfig>,
    /// Virtque for control requests.
    pub ctrl_queue: Option<VirtioQueueConfig>,
    /// Notifier to inject virtio device change interrupt to guest.
    pub device_change_notifier: Box<dyn InterruptNotifier>,
    /// Shared memory regions
    pub shm_regions: Option<VirtioSharedMemoryList>,
}

impl<AS: GuestAddressSpace> VirtioDeviceConfig<AS> {
    /// Creates a virtio device configuration instance.
    pub fn new(
        vm_as: AS,
        vm_fd: Arc<VmFd>,
        resources: DeviceResources,
        queues: Vec<VirtioQueueConfig>,
        ctrl_queue: Option<VirtioQueueConfig>,
        device_change_notifier: Box<dyn InterruptNotifier>,
    ) -> Self {
        VirtioDeviceConfig {
            vm_as,
            vm_fd,
            resources,
            queues,
            ctrl_queue,
            device_change_notifier,
            shm_regions: None,
        }
    }

    /// Injects a virtio device change notification to guest.
    pub fn notify_device_changes(&self) -> Result<()> {
        self.device_change_notifier.notify().map_err(Error::IOError)
    }

    /// Gets irq eventfd array for vritio vrings.
    pub fn get_vring_notifier(&self) -> Vec<&EventFd> {
        self.queues
            .iter()
            .map(|x| x.notifier.notifier().unwrap())
            .collect()
    }

    /// Sets shm regions to `VirtioDeviceConfig`
    pub fn set_shm_regions(&mut self, shm_regions: VirtioSharedMemoryList) {
        self.shm_regions = Some(shm_regions);
    }

    /// Gets host addr and guest addr of shm region base
    pub fn get_shm_region_addr(&self) -> Option<(u64, u64)> {
        self.shm_regions
            .as_ref()
            .map(|shms| (shms.host_addr, shms.guest_addr.raw_value()))
    }

    /// Gets a shared reference to the guest memory object.
    pub fn lock_guest_memory(&self) -> AS::T {
        self.vm_as.memory()
    }
}

/// Shared Memory between device and guest
#[derive(Clone, PartialEq, Debug)]
pub struct VirtioSharedMemory {
    /// offset from the base
    pub offset: u64,
    /// len of this shared memory region
    pub len: u64,
}

/// A list of Shared Memory regions
#[derive(Clone, Debug)]
pub struct VirtioSharedMemoryList {
    /// Host address
    pub host_addr: u64,
    /// Guest address
    pub guest_addr: GuestAddress,
    /// Length
    pub len: GuestUsize,
    /// kvm_userspace_memory_region flags
    pub kvm_userspace_memory_region_flags: u32,
    /// kvm_userspace_memory_region slot
    pub kvm_userspace_memory_region_slot: u32,
    /// List of shared regions.
    pub region_list: Vec<VirtioSharedMemory>,

    /// List of mmap()ed regions managed through GuestRegionMmap instances. Using
    /// GuestRegionMmap will perform the unmapping automatically when the instance
    /// is dropped, which happens when the VirtioDevice gets dropped.
    ///
    /// GuestRegionMmap is used instead of MmapRegion. Because We need to insert
    /// this region into vm_as，but vm_as uses GuestRegionMmap to manage regions.
    /// If MmapRegion is used in here, the MmapRegion needs to be clone() to create
    /// new GuestRegionMmap for vm_as. MmapRegion clone() will cause the problem of
    /// duplicate unmap during automatic drop, so we should try to avoid the clone
    /// of MmapRegion. This problem does not exist with GuestRegionMmap because
    /// vm_as and VirtioSharedMemoryList can share GuestRegionMmap through Arc.
    pub mmap_region: Arc<GuestRegionMmap>,
}

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. Once the guest driver has configured the device, `VirtioDevice::activate` will be called
/// and all the events, memory, and queues for device operation will be moved into the device.
/// Optionally, a virtio device can implement device reset in which it returns said resources and
/// resets its internal.
pub trait VirtioDevice<AS: GuestAddressSpace>: Send {
    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// The maximum size of each queue that this device supports.
    fn queue_max_sizes(&self) -> &[u16];

    /// The maxinum size of control queue
    fn ctrl_queue_max_sizes(&self) -> u16 {
        0
    }

    /// The set of feature bits shifted by `page * 32`.
    fn get_avail_features(&self, page: u32) -> u32 {
        let _ = page;
        0
    }

    /// Acknowledges that this set of features should be enabled.
    fn set_acked_features(&mut self, page: u32, value: u32);

    /// Reads this device configuration space at `offset`.
    fn read_config(&mut self, offset: u64, data: &mut [u8]);

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Activates this device for real usage.
    fn activate(&mut self, config: VirtioDeviceConfig<AS>) -> ActivateResult;

    /// Deactivates this device.
    fn reset(&mut self) -> ActivateResult {
        Err(ActivateError::InternalError)
    }

    /// every new device object has its resource requirements
    fn get_resource_requirements(
        &self,
        requests: &mut Vec<ResourceConstraint>,
        use_generic_irq: bool,
    );

    /// Assigns requested resources back to virtio device
    fn set_resource(
        &mut self,
        _vm_fd: Arc<VmFd>,
        _resource: DeviceResources,
    ) -> Result<Option<VirtioSharedMemoryList>> {
        Ok(None)
    }

    /// Removes this devices.
    fn remove(&mut self) {}

    /// Used to downcast to the specific type.
    fn as_any(&self) -> &dyn Any;
}

/// A helper struct to support basic operations for emulated VirtioDevice backend devices.
pub struct VirtioDeviceInfo {
    /// Name of the virtio backend device.
    pub driver_name: String,
    /// Available features of the virtio backend device.
    pub avail_features: u64,
    /// Acknowledged features of the virtio backend device.
    pub acked_features: u64,
    /// Array of queue sizes.
    pub queue_sizes: Arc<Vec<u16>>,
    /// Space to store device specific configuration data.
    pub config_space: Vec<u8>,
    /// EventManager SubscriberOps to register/unregister epoll events.
    pub epoll_manager: EpollManager,
}

/// A helper struct to support basic operations for emulated VirtioDevice backend devices.
impl VirtioDeviceInfo {
    /// Creates a VirtioDeviceInfo instance.
    pub fn new(
        driver_name: String,
        avail_features: u64,
        queue_sizes: Arc<Vec<u16>>,
        config_space: Vec<u8>,
        epoll_manager: EpollManager,
    ) -> Self {
        VirtioDeviceInfo {
            driver_name,
            avail_features,
            acked_features: 0u64,
            queue_sizes,
            config_space,
            epoll_manager,
        }
    }

    /// Gets available features of virtio backend device.
    #[inline]
    pub fn avail_features(&self) -> u64 {
        self.avail_features
    }

    /// Gets available features of virtio backend device.
    pub fn get_avail_features(&self, page: u32) -> u32 {
        match page {
            // Get the lower 32-bits of the features bitfield.
            0 => self.avail_features as u32,
            // Get the upper 32-bits of the features bitfield.
            1 => (self.avail_features >> 32) as u32,
            _ => {
                warn!("{}: query features page: {}", self.driver_name, page);
                0u32
            }
        }
    }

    /// Gets acknowledged features of virtio backend device.
    #[inline]
    pub fn acked_features(&self) -> u64 {
        self.acked_features
    }

    /// Sets acknowledged features of virtio backend device.
    pub fn set_acked_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => value as u64,
            1 => (value as u64) << 32,
            _ => {
                warn!("{}: ack unknown feature page: {}", self.driver_name, page);
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("{}: ackknowlege unknown feature: {:x}", self.driver_name, v);
            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    /// Reads device specific configuration data of virtio backend device.
    ///
    /// The `offset` is based of 0x100 from the MMIO configuration address space.
    pub fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!(
                "{}: config space read request out of range, offset {}",
                self.driver_name, offset
            );
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    /// Writes device specific configuration data of virtio backend device.
    ///
    /// The `offset` is based of 0x100 from the MMIO configuration address space.
    pub fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_len = self.config_space.len() as u64;
        if offset >= config_len
            || offset.checked_add(data_len).is_none()
            || offset + data_len > config_len
        {
            error!(
                "{}: config space write request out of range, offset {}",
                self.driver_name, offset
            );
            return;
        }
        let dst = &mut self.config_space[offset as usize..(offset + data_len) as usize];
        dst.copy_from_slice(data);
    }

    /// Validate size of queues and queue eventfds.
    pub fn check_queue_sizes(&self, queues: &[VirtioQueueConfig]) -> ActivateResult {
        if queues.is_empty() || queues.len() != self.queue_sizes.len() {
            error!(
                "{}: invalid configuration: maximum {} queue(s), got {} queues",
                self.driver_name,
                self.queue_sizes.len(),
                queues.len(),
            );
            return Err(ActivateError::InvalidParam);
        }
        Ok(())
    }

    /// Register event handler for the device.
    pub fn register_event_handler(&self, handler: EpollSubscriber) -> SubscriberId {
        self.epoll_manager.add_subscriber(handler)
    }

    /// Unregister event handler for the device.
    pub fn remove_event_handler(&mut self, id: SubscriberId) -> Result<EpollSubscriber> {
        self.epoll_manager.remove_subscriber(id).map_err(|e| {
            Error::IOError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("remove_event_handler failed: {:?}", e),
            ))
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{VIRTIO_INTR_CONFIG, VIRTIO_INTR_VRING};

    use dbs_interrupt::{
        InterruptManager, InterruptSourceType, InterruptStatusRegister32, LegacyNotifier,
    };
    use vm_memory::{GuestAddress, GuestMemoryMmap, GuestMemoryRegion, MmapRegion};

    pub fn create_virtio_device_config() -> VirtioDeviceConfig<Arc<GuestMemoryMmap>> {
        let (vmfd, irq_manager) = crate::tests::create_vm_and_irq_manager();
        let group = irq_manager
            .create_group(InterruptSourceType::LegacyIrq, 0, 1)
            .unwrap();
        let status = Arc::new(InterruptStatusRegister32::new());
        let device_change_notifier = Box::new(LegacyNotifier::new(
            group.clone(),
            status.clone(),
            VIRTIO_INTR_CONFIG,
        ));

        let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());

        let mut queues = Vec::new();
        for idx in 0..8 {
            queues.push(VirtioQueueConfig::new(
                QueueState::new(512),
                EventFd::new(0).unwrap(),
                Box::new(LegacyNotifier::new(
                    group.clone(),
                    status.clone(),
                    VIRTIO_INTR_VRING,
                )),
                idx,
            ));
        }

        VirtioDeviceConfig::new(
            mem,
            vmfd,
            DeviceResources::new(),
            queues,
            None,
            device_change_notifier,
        )
    }

    #[test]
    fn test_create_virtio_queue_config() {
        let (_vmfd, irq_manager) = crate::tests::create_vm_and_irq_manager();
        let group = irq_manager
            .create_group(InterruptSourceType::LegacyIrq, 0, 1)
            .unwrap();
        let status = Arc::new(InterruptStatusRegister32::new());
        let notifier = Box::new(LegacyNotifier::new(group, status, VIRTIO_INTR_VRING));

        let mut cfg = VirtioQueueConfig::create(1024, 1).unwrap();
        cfg.set_notifier(notifier);

        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        let mut iter = cfg.iter(mem).unwrap();
        assert!(matches!(iter.next(), None));

        cfg.notify().unwrap();
        assert_eq!(cfg.index(), 1);
        assert_eq!(cfg.max_size(), 1024);
        assert_eq!(cfg.actual_size(), 1024);
        cfg.generate_event().unwrap();
        assert_eq!(cfg.comsume_event().unwrap(), 1);
    }

    #[test]
    fn test_create_virtio_device_config() {
        let mut device_config = create_virtio_device_config();

        device_config.notify_device_changes().unwrap();
        assert_eq!(device_config.get_vring_notifier().len(), 8);

        let shared_mem =
            GuestRegionMmap::new(MmapRegion::new(4096).unwrap(), GuestAddress(0)).unwrap();

        let list = VirtioSharedMemoryList {
            host_addr: 0x1234,
            guest_addr: GuestAddress(0x5678),
            len: shared_mem.len(),
            kvm_userspace_memory_region_flags: 0,
            kvm_userspace_memory_region_slot: 1,
            region_list: vec![VirtioSharedMemory {
                offset: 0,
                len: 4096,
            }],
            mmap_region: Arc::new(shared_mem),
        };

        device_config.set_shm_regions(list);
        let (host_addr, guest_addr) = device_config.get_shm_region_addr().unwrap();
        assert_eq!(host_addr, 0x1234);
        assert_eq!(guest_addr, 0x5678);
    }
}
