// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

///////////////////////////////////////////////////////////////
// TODO: we really need better support of device reset, error recovery, exceptions handling.
///////////////////////////////////////////////////////////////

use std::ops::Deref;
use std::sync::Arc;

use dbs_device::resources::DeviceResources;
use dbs_interrupt::{DeviceInterruptManager, KvmIrqManager};
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{IoEventAddress, NoDatamatch, VmFd};
use log::{debug, error};
use virtio_queue::QueueStateT;
use vm_memory::{GuestAddressSpace, GuestMemoryRegion};

use crate::{
    mmio::*, Error, Result, VirtioDevice, VirtioQueueConfig, VirtioSharedMemory,
    VirtioSharedMemoryList,
};

/// The state of Virtio Mmio device.
pub struct MmioV2DeviceState<AS: GuestAddressSpace + Clone, Q: QueueStateT, R: GuestMemoryRegion> {
    device: Box<dyn VirtioDevice<AS, Q, R>>,
    vm_fd: Arc<VmFd>,
    vm_as: AS,
    intr_mgr: DeviceInterruptManager<Arc<KvmIrqManager>>,
    device_resources: DeviceResources,
    queues: Vec<VirtioQueueConfig<Q>>,

    mmio_base: u64,
    has_ctrl_queue: bool,
    device_activated: bool,
    ioevent_registered: bool,

    features_select: u32,
    acked_features_select: u32,
    queue_select: u32,

    msi: Option<Msi>,
    doorbell: Option<DoorBell>,

    shm_region_id: u32,
    shm_regions: Option<VirtioSharedMemoryList<R>>,
}

impl<AS, Q, R> MmioV2DeviceState<AS, Q, R>
where
    AS: GuestAddressSpace + Clone,
    Q: QueueStateT,
    R: GuestMemoryRegion,
{
    /// Returns a reference to the internal device object.
    pub fn get_inner_device(&self) -> &dyn VirtioDevice<AS, Q, R> {
        self.device.as_ref()
    }

    /// Returns a mutable reference to the internal device object.
    pub fn get_inner_device_mut(&mut self) -> &mut dyn VirtioDevice<AS, Q, R> {
        self.device.as_mut()
    }

    pub(crate) fn new(
        mut device: Box<dyn VirtioDevice<AS, Q, R>>,
        vm_fd: Arc<VmFd>,
        vm_as: AS,
        irq_manager: Arc<KvmIrqManager>,
        device_resources: DeviceResources,
        mmio_base: u64,
        doorbell_enabled: bool,
    ) -> Result<Self> {
        let intr_mgr =
            DeviceInterruptManager::new(irq_manager, &device_resources).map_err(Error::IOError)?;

        let (queues, has_ctrl_queue) = Self::create_queues(device.as_ref())?;

        // Assign requested device resources back to virtio device and let it do necessary setups,
        // as only virtio device knows how to use such resources. And if there's
        // VirtioSharedMemoryList returned, assigned it to MmioV2DeviceState
        let shm_regions = device
            .set_resource(vm_fd.clone(), device_resources.clone())
            .map_err(|e| {
                error!("Failed to assign device resource to virtio device: {}", e);
                e
            })?;

        let doorbell = if doorbell_enabled {
            Some(DoorBell::new(
                DRAGONBALL_MMIO_DOORBELL_OFFSET as u32,
                DRAGONBALL_MMIO_DOORBELL_SCALE as u32,
            ))
        } else {
            None
        };

        Ok(MmioV2DeviceState {
            device,
            vm_fd,
            vm_as,
            intr_mgr,
            device_resources,
            queues,
            mmio_base,
            has_ctrl_queue,
            ioevent_registered: false,
            device_activated: false,
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            doorbell,
            msi: None,
            shm_region_id: 0,
            shm_regions,
        })
    }

    fn create_queues(
        device: &dyn VirtioDevice<AS, Q, R>,
    ) -> Result<(Vec<VirtioQueueConfig<Q>>, bool)> {
        let mut queues = Vec::new();
        for (idx, size) in device.queue_max_sizes().iter().enumerate() {
            queues.push(VirtioQueueConfig::create(*size, idx as u16)?);
        }

        // The ctrl queue must be append to QueueState Vec, because the guest will
        // configure it which is same with other queues.
        let has_ctrl_queue = device.ctrl_queue_max_sizes() > 0;
        if has_ctrl_queue {
            queues.push(VirtioQueueConfig::create(
                device.ctrl_queue_max_sizes(),
                queues.len() as u16,
            )?);
        }

        Ok((queues, has_ctrl_queue))
    }

    fn register_ioevent(&mut self) -> Result<()> {
        for (i, queue) in self.queues.iter().enumerate() {
            if let Some(doorbell) = self.doorbell.as_ref() {
                let io_addr = IoEventAddress::Mmio(self.mmio_base + doorbell.queue_offset(i));
                if let Err(e) = self
                    .vm_fd
                    .register_ioevent(&queue.eventfd, &io_addr, NoDatamatch)
                {
                    self.revert_ioevent(i, &io_addr);
                    return Err(Error::IOError(std::io::Error::from_raw_os_error(e.errno())));
                }
            }
            // always register ioeventfd in MMIO_NOTIFY_REG_OFFSET to avoid guest kernel which not support doorbell
            let io_addr = IoEventAddress::Mmio(self.mmio_base + MMIO_NOTIFY_REG_OFFSET as u64);
            if let Err(e) = self
                .vm_fd
                .register_ioevent(&queue.eventfd, &io_addr, i as u32)
            {
                self.unregister_ioevent_doorbell();
                self.revert_ioevent(i, &io_addr);
                return Err(Error::IOError(std::io::Error::from_raw_os_error(e.errno())));
            }
        }
        self.ioevent_registered = true;

        Ok(())
    }

    fn deactivate(&mut self) {
        if self.device_activated {
            self.device_activated = false;
        }
    }

    fn unregister_ioevent(&mut self) {
        if self.ioevent_registered {
            let io_addr = IoEventAddress::Mmio(self.mmio_base + MMIO_NOTIFY_REG_OFFSET as u64);
            for (i, queue) in self.queues.iter().enumerate() {
                let _ = self
                    .vm_fd
                    .unregister_ioevent(&queue.eventfd, &io_addr, i as u32);
                self.ioevent_registered = false;
            }
        }
    }

    fn revert_ioevent(&mut self, num: usize, io_addr: &IoEventAddress) {
        assert!(num < self.queues.len());
        let mut idx = num;
        while idx > 0 {
            idx -= 1;
            let _ = self
                .vm_fd
                .unregister_ioevent(&self.queues[idx].eventfd, &io_addr, idx as u32);
        }
    }

    fn unregister_ioevent_doorbell(&mut self) {
        if let Some(doorbell) = self.doorbell.as_ref() {
            for (i, queue) in self.queues.iter().enumerate() {
                let io_addr = IoEventAddress::Mmio(self.mmio_base + doorbell.queue_offset(i));
                let _ = self
                    .vm_fd
                    .unregister_ioevent(&queue.eventfd, &io_addr, NoDatamatch);
            }
        }
    }

    fn check_queues_valid(&self) -> bool {
        let mem = self.vm_as.memory();
        // All queues must have been enabled, we doesn't allow disabled queues.
        self.queues.iter().all(|c| c.queue.is_valid(mem.deref()))
    }

    fn with_queue<U, F>(&self, d: U, f: F) -> U
    where
        F: FnOnce(&Q) -> U,
    {
        match self.queues.get(self.queue_select as usize) {
            Some(config) => f(&config.queue),
            None => d,
        }
    }

    fn with_queue_mut<F: FnOnce(&mut Q)>(&mut self, f: F) -> bool {
        if let Some(config) = self.queues.get_mut(self.queue_select as usize) {
            f(&mut config.queue);
            true
        } else {
            false
        }
    }

    fn get_shm_field<U, F>(&mut self, d: U, f: F) -> U
    where
        F: FnOnce(&VirtioSharedMemory) -> U,
    {
        if let Some(regions) = self.shm_regions.as_ref() {
            match regions.region_list.get(self.shm_region_id as usize) {
                Some(region) => f(region),
                None => d,
            }
        } else {
            d
        }
    }

    fn update_msi_cfg(&mut self) -> Result<()> {
        if let Some(msi) = self.msi.as_ref() {
            self.intr_mgr
                .set_msi_low_address(msi.index_select, msi.address_low)
                .map_err(Error::InterruptError)?;
            self.intr_mgr
                .set_msi_high_address(msi.index_select, msi.address_high)
                .map_err(Error::InterruptError)?;
            self.intr_mgr
                .set_msi_data(msi.index_select, msi.data)
                .map_err(Error::InterruptError)?;
            if self.intr_mgr.is_enabled() {
                self.intr_mgr
                    .update(msi.index_select)
                    .map_err(Error::InterruptError)?;
            }
        }

        Ok(())
    }

    fn mask_msi_int(&mut self, index: u32, mask: bool) -> Result<()> {
        if self.intr_mgr.is_enabled() {
            if let Some(group) = self.intr_mgr.get_group() {
                let old_mask = self
                    .intr_mgr
                    .get_msi_mask(index)
                    .map_err(Error::InterruptError)?;
                debug!("mmio_v2 old mask {}, mask {}", old_mask, mask);

                if !old_mask && mask {
                    group.mask(index)?;
                    self.intr_mgr
                        .set_msi_mask(index, true)
                        .map_err(Error::InterruptError)?;
                } else if old_mask && !mask {
                    group.unmask(index)?;
                    self.intr_mgr
                        .set_msi_mask(index, false)
                        .map_err(Error::InterruptError)?;
                }
            }
        }

        Ok(())
    }
}

impl<AS, Q, R> Drop for MmioV2DeviceState<AS, Q, R>
where
    AS: GuestAddressSpace + Clone,
    Q: QueueStateT,
    R: GuestMemoryRegion,
{
    fn drop(&mut self) {
        if let Some(memlist) = &self.shm_regions {
            let mmio_res = self.device_resources.get_mmio_address_ranges();
            let slots_res = self.device_resources.get_kvm_mem_slots();
            let shm_regions_num = mmio_res.len();
            let slots_num = slots_res.len();
            assert_eq!((shm_regions_num, slots_num), (1, 1));
            let kvm_mem_region = kvm_userspace_memory_region {
                slot: slots_res[0],
                flags: 0,
                guest_phys_addr: memlist.guest_addr.0,
                memory_size: 0,
                userspace_addr: memlist.host_addr,
            };
            unsafe {
                self.vm_fd.set_user_memory_region(kvm_mem_region).unwrap();
            }
        }
    }
}
