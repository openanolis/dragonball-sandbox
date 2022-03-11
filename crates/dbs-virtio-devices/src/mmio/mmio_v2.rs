// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use byteorder::{ByteOrder, LittleEndian};
use dbs_device::resources::{DeviceResources, Resource};
use dbs_device::{DeviceIo, IoAddress};
use dbs_interrupt::{InterruptStatusRegister32, KvmIrqManager};
use kvm_ioctls::VmFd;
use log::{debug, info, warn};
use virtio_queue::QueueStateT;
use vm_memory::{GuestAddressSpace, GuestMemoryRegion};

use crate::{
    mmio::*, Error, Result, VirtioDevice, DEVICE_ACKNOWLEDGE, DEVICE_DRIVER, DEVICE_DRIVER_OK,
    DEVICE_FAILED, DEVICE_FEATURES_OK, DEVICE_INIT, VIRTIO_INTR_VRING,
};

const DEVICE_STATUS_INIT: u32 = DEVICE_INIT;
const DEVICE_STATUS_ACKNOWLEDE: u32 = DEVICE_STATUS_INIT | DEVICE_ACKNOWLEDGE;
const DEVICE_STATUS_DRIVER: u32 = DEVICE_STATUS_ACKNOWLEDE | DEVICE_DRIVER;
const DEVICE_STATUS_FEATURE_OK: u32 = DEVICE_STATUS_DRIVER | DEVICE_FEATURES_OK;
const DEVICE_STATUS_DRIVER_OK: u32 = DEVICE_STATUS_FEATURE_OK | DEVICE_DRIVER_OK;

/// Implements the
/// [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
/// transport for virtio devices.
///
/// This requires 3 points of installation to work with a VM:
///
/// 1. Mmio reads and writes must be sent to this device at what is referred to here as MMIO base.
/// 1. `Mmio::queue_evts` must be installed at `MMIO_NOTIFY_REG_OFFSET` offset from the MMIO
/// base. Each event in the array must be signaled if the index is written at that offset.
/// 1. `Mmio::interrupt_evt` must signal an interrupt that the guest driver is listening to when it
/// is written to.
///
/// Typically one page (4096 bytes) of MMIO address space is sufficient to handle this transport
/// and inner virtio device.
pub struct MmioV2Device<AS: GuestAddressSpace + Clone, Q: QueueStateT, R: GuestMemoryRegion> {
    state: Mutex<MmioV2DeviceState<AS, Q, R>>,
    assigned_resources: DeviceResources,
    mmio_cfg_res: Resource,
    device_vendor: u32,
    driver_status: AtomicU32,
    config_generation: AtomicU32,
    interrupt_status: Arc<InterruptStatusRegister32>,
}

impl<AS, Q, R> MmioV2Device<AS, Q, R>
where
    AS: GuestAddressSpace + Clone,
    Q: QueueStateT + Clone,
    R: GuestMemoryRegion,
{
    /// Constructs a new MMIO transport for the given virtio device.
    pub fn new(
        vm_fd: Arc<VmFd>,
        vm_as: AS,
        irq_manager: Arc<KvmIrqManager>,
        device: Box<dyn VirtioDevice<AS, Q, R>>,
        resources: DeviceResources,
        mut features: Option<u32>,
    ) -> Result<Self> {
        let mut device_resources = DeviceResources::new();
        let mut mmio_cfg_resource = None;
        let mut mmio_base = 0;
        let mut doorbell_enabled = false;

        for res in resources.iter() {
            if let Resource::MmioAddressRange { base, size } = res {
                if mmio_cfg_resource.is_none()
                    && *size == MMIO_DEFAULT_CFG_SIZE + DRAGONBALL_MMIO_DOORBELL_SIZE
                {
                    mmio_base = *base;
                    mmio_cfg_resource = Some(res.clone());
                    continue;
                }
            }
            device_resources.append(res.clone());
        }
        let mmio_cfg_res = match mmio_cfg_resource {
            Some(v) => v,
            None => return Err(Error::InvalidInput),
        };

        let msi_feature = if resources.get_generic_msi_irqs().is_some() {
            DRAGONBALL_FEATURE_MSI_INTR
        } else {
            0
        };

        if let Some(ref mut ft) = features {
            if (*ft & DRAGONBALL_FEATURE_PER_QUEUE_NOTIFY != 0)
                && vm_fd.check_extension(kvm_ioctls::Cap::IoeventfdNoLength)
            {
                doorbell_enabled = true;
            } else {
                *ft &= !DRAGONBALL_FEATURE_PER_QUEUE_NOTIFY;
            }
        }

        debug!("mmiov2: fast-mmio enabled: {}", doorbell_enabled);

        let state = MmioV2DeviceState::new(
            device,
            vm_fd,
            vm_as,
            irq_manager,
            device_resources,
            mmio_base,
            doorbell_enabled,
        )?;

        let mut device_vendor = MMIO_VENDOR_ID_DRAGONBALL | msi_feature;
        if let Some(ft) = features {
            debug!("mmiov2: feature bit is 0x{:0X}", ft);
            device_vendor |= ft & DRAGONBALL_FEATURE_MASK;
        }

        Ok(MmioV2Device {
            state: Mutex::new(state),
            assigned_resources: resources,
            mmio_cfg_res,
            device_vendor,
            driver_status: AtomicU32::new(DEVICE_INIT),
            config_generation: AtomicU32::new(0),
            interrupt_status: Arc::new(InterruptStatusRegister32::new()),
        })
    }

    /// Acquires the state while holding the lock.
    pub fn state(&self) -> MutexGuard<MmioV2DeviceState<AS, Q, R>> {
        // Safe to unwrap() because we don't expect poisoned lock here.
        self.state.lock().unwrap()
    }

    /// Removes device.
    pub fn remove(&self) {
        self.state().get_inner_device_mut().remove();
    }

    /// Returns the Resource.
    pub fn get_mmio_cfg_res(&self) -> Resource {
        self.mmio_cfg_res.clone()
    }

    /// Returns the type of device.
    pub fn get_device_type(&self) -> u32 {
        self.state().get_inner_device().device_type()
    }

    pub(crate) fn interrupt_status(&self) -> Arc<InterruptStatusRegister32> {
        self.interrupt_status.clone()
    }

    #[inline]
    /// Atomic sets the drive state to fail.
    pub(crate) fn set_driver_failed(&self) {
        self.driver_status.fetch_or(DEVICE_FAILED, Ordering::SeqCst);
    }

    #[inline]
    pub(crate) fn driver_status(&self) -> u32 {
        self.driver_status.load(Ordering::SeqCst)
    }

    #[inline]
    fn check_driver_status(&self, set: u32, clr: u32) -> bool {
        self.driver_status() & (set | clr) == set
    }

    #[inline]
    fn exchange_driver_status(&self, old: u32, new: u32) -> std::result::Result<u32, u32> {
        self.driver_status
            .compare_exchange(old, new, Ordering::SeqCst, Ordering::SeqCst)
    }

    /// Update driver status according to the state machine defined by VirtIO Spec 1.0.
    /// Please refer to VirtIO Spec 1.0, section 2.1.1 and 3.1.1.
    ///
    /// The driver MUST update device status, setting bits to indicate the completed steps
    /// of the driver initialization sequence specified in 3.1. The driver MUST NOT clear
    /// a device status bit. If the driver sets the FAILED bit, the driver MUST later reset
    /// the device before attempting to re-initialize.
    fn update_driver_status(&self, v: u32) {
        // Serialize to update device state.
        let mut state = self.state();
        let mut result = Err(DEVICE_FAILED);
        if v == DEVICE_STATUS_ACKNOWLEDE {
            result = self.exchange_driver_status(DEVICE_STATUS_INIT, DEVICE_STATUS_ACKNOWLEDE);
        } else if v == DEVICE_STATUS_DRIVER {
            result = self.exchange_driver_status(DEVICE_STATUS_ACKNOWLEDE, DEVICE_STATUS_DRIVER);
        } else if v == DEVICE_STATUS_FEATURE_OK {
            result = self.exchange_driver_status(DEVICE_STATUS_DRIVER, DEVICE_STATUS_FEATURE_OK);
        } else if v == DEVICE_STATUS_DRIVER_OK {
            result = self.exchange_driver_status(DEVICE_STATUS_FEATURE_OK, DEVICE_STATUS_DRIVER_OK);
            if result.is_ok() {
                if let Err(e) = state.activate(self) {
                    // Reset internal status to initial state on failure.
                    state.reset();
                    warn!("failed to activate MMIO Virtio device: {:?}", e);
                    result = Err(DEVICE_FAILED);
                }
            }
        } else if v == 0 {
            if self.driver_status() == DEVICE_INIT {
                result = Ok(0);
            } else if state.device_activated() {
                let ret = state.get_inner_device_mut().reset();
                if ret.is_err() {
                    warn!("failed to reset MMIO Virtio device: {:?}.", ret);
                } else {
                    state.deactivate();
                    state.reset();
                    // it should reset the device's status to init, otherwise, the guest would
                    // get the wrong device's status.
                    result =
                        self.exchange_driver_status(DEVICE_STATUS_DRIVER_OK, DEVICE_STATUS_INIT);
                }
            }
        } else if v == self.driver_status() {
            // No real state change, nothing to do.
            result = Ok(0);
        } else if v & DEVICE_FAILED != 0 {
            // Guest driver marks device as failed.
            self.set_driver_failed();
            result = Ok(0);
        }

        if result.is_err() {
            warn!(
                "invalid virtio driver status transition: 0x{:x} -> 0x{:x}",
                self.driver_status(),
                v
            );
            // TODO: notify backend driver to stop the device
            self.set_driver_failed();
        }
    }

    fn update_queue_field<F: FnOnce(&mut Q)>(&self, f: F) {
        // Use mutex for state to protect device.write_config()
        let mut state = self.state();
        if self.check_driver_status(DEVICE_FEATURES_OK, DEVICE_DRIVER_OK | DEVICE_FAILED) {
            state.with_queue_mut(f);
        } else {
            info!(
                "update virtio queue in invalid state 0x{:x}",
                self.driver_status()
            );
        }
    }

    fn tweak_intr_flags(&self, flags: u32) -> u32 {
        // The MMIO virtio transport layer only supports legacy IRQs. And the typical way to
        // inject interrupt into the guest is:
        // 1) the vhost-user-net slave sends notifcaticaiton to dragonball by writing to eventfd.
        // 2) dragonball consumes the notification by read the eventfd.
        // 3) dragonball updates interrupt status register.
        // 4) dragonball injects interrupt to the guest by writing to an irqfd.
        //
        // We play a trick here to always report "descriptor ready in the used virtque".
        // This trick doesn't break the virtio spec because it allow virtio devices to inject
        // supurous interrupts. By applying this trick, the way to inject interrupts gets
        // simplified as:
        // 1) the vhost-user-net slave sends interrupt to the guest by writing to the irqfd.
        if self.device_vendor & DRAGONBALL_FEATURE_INTR_USED != 0 {
            flags | VIRTIO_INTR_VRING
        } else {
            flags
        }
    }

    fn device_features(&self) -> u32 {
        let state = self.state();
        let features_select = state.features_select();
        let mut features = state.get_inner_device().get_avail_features(features_select);
        if features_select == 1 {
            features |= 0x1; // enable support of VirtIO Version 1
        }
        features
    }

    fn set_acked_features(&self, v: u32) {
        // Use mutex for state to protect device.ack_features()
        let mut state = self.state();
        if self.check_driver_status(DEVICE_DRIVER, DEVICE_FEATURES_OK | DEVICE_FAILED) {
            state.set_acked_features(v);
        } else {
            info!(
                "ack virtio features in invalid state 0x{:x}",
                self.driver_status()
            );
        }
    }
}

impl<AS, Q, R> DeviceIo for MmioV2Device<AS, Q, R>
where
    AS: 'static + GuestAddressSpace + Clone + Send + Sync,
    Q: QueueStateT + Send + Clone,
    R: GuestMemoryRegion + Send + Sync,
{
    fn read(&self, _base: IoAddress, offset: IoAddress, data: &mut [u8]) {
        let offset = offset.raw_value();
        let guest_addr: u64 = match self.state().shm_regions() {
            Some(regions) => regions.guest_addr.0,
            None => 0,
        };

        if offset >= MMIO_CFG_SPACE_OFF {
        } else if data.len() == 4 {
            let v = match offset {
                REG_MMIO_MAGIC_VALUE => MMIO_MAGIC_VALUE,
                REG_MMIO_VERSION => MMIO_VERSION_2,
                REG_MMIO_DEVICE_ID => self.state().get_inner_device().device_type(),
                REG_MMIO_VENDOR_ID => self.device_vendor,
                REG_MMIO_DEVICE_FEATURE => self.device_features(),
                REG_MMIO_QUEUE_NUM_MA => self.state().with_queue(0, |q| q.max_size() as u32),
                REG_MMIO_QUEUE_READY => self.state().with_queue(0, |q| q.ready() as u32),
                REG_MMIO_QUEUE_NOTIF if self.state().doorbell().is_some() => {
                    // Safe to unwrap() because we have determined the option is a Some value.
                    self.state()
                        .doorbell()
                        .map(|doorbell| doorbell.register_data())
                        .unwrap()
                }
                REG_MMIO_INTERRUPT_STAT => self.tweak_intr_flags(self.interrupt_status.read()),
                REG_MMIO_STATUS => self.driver_status(),
                REG_MMIO_SHM_LEN_LOW => self.state().get_shm_field(0xffff_ffff, |s| s.len as u32),
                REG_MMIO_SHM_LEN_HIGH => self
                    .state()
                    .get_shm_field(0xffff_ffff, |s| (s.len >> 32) as u32),
                REG_MMIO_SHM_BASE_LOW => self
                    .state()
                    .get_shm_field(0xffff_ffff, |s| (s.offset + guest_addr) as u32),
                REG_MMIO_SHM_BASE_HIGH => self
                    .state()
                    .get_shm_field(0xffff_ffff, |s| ((s.offset + guest_addr) >> 32) as u32),
                REG_MMIO_CONFIG_GENERATI => self.config_generation.load(Ordering::SeqCst),
                _ => {
                    info!("unknown virtio mmio readl at 0x{:x}", offset);
                    return;
                }
            };
            LittleEndian::write_u32(data, v);
        } else if data.len() == 2 {
            let v = match offset {
                REG_MMIO_MSI_CSR => {
                    if (self.device_vendor & DRAGONBALL_FEATURE_MSI_INTR) != 0 {
                        MMIO_MSI_CSR_SUPPORTED
                    } else {
                        0
                    }
                }
                _ => {
                    info!("unknown virtio mmio readw from 0x{:x}", offset);
                    return;
                }
            };
            LittleEndian::write_u16(data, v as u16);
        } else {
            info!(
                "unknown virtio mmio register read: 0x{:x}/0x{:x}",
                offset,
                data.len()
            );
        }
    }

    fn write(&self, _base: IoAddress, offset: IoAddress, data: &[u8]) {
        let offset = offset.raw_value();
        // Write to the device configuration area.
        if (MMIO_CFG_SPACE_OFF..DRAGONBALL_MMIO_DOORBELL_OFFSET).contains(&offset) {
        } else if data.len() == 4 {
            let v = LittleEndian::read_u32(data);
            match offset {
                REG_MMIO_DEVICE_FEATURES_S => self.state().set_features_select(v),
                REG_MMIO_DRIVER_FEATURE => self.set_acked_features(v),
                REG_MMIO_DRIVER_FEATURES_S => self.state().set_acked_features_select(v),
                REG_MMIO_QUEUE_SEL => self.state().set_queue_select(v),
                REG_MMIO_QUEUE_NUM => self.update_queue_field(|q| q.set_size(v as u16)),
                REG_MMIO_QUEUE_READY => self.update_queue_field(|q| q.set_ready(v == 1)),
                REG_MMIO_INTERRUPT_AC => self.interrupt_status.clear_bits(v),
                REG_MMIO_STATUS => self.update_driver_status(v),
                REG_MMIO_QUEUE_DESC_LOW => {
                    self.update_queue_field(|q| q.set_desc_table_address(Some(v), None))
                }
                REG_MMIO_QUEUE_DESC_HIGH => {
                    self.update_queue_field(|q| q.set_desc_table_address(None, Some(v)))
                }
                REG_MMIO_QUEUE_AVAIL_LOW => {
                    self.update_queue_field(|q| q.set_avail_ring_address(Some(v), None))
                }
                REG_MMIO_QUEUE_AVAIL_HIGH => {
                    self.update_queue_field(|q| q.set_avail_ring_address(None, Some(v)))
                }
                REG_MMIO_QUEUE_USED_LOW => {
                    self.update_queue_field(|q| q.set_used_ring_address(Some(v), None))
                }
                REG_MMIO_QUEUE_USED_HIGH => {
                    self.update_queue_field(|q| q.set_used_ring_address(None, Some(v)))
                }
                REG_MMIO_SHM_SEL => self.state().set_shm_region_id(v),
                REG_MMIO_MSI_ADDRESS_L => self.state().set_msi_address_low(v),
                REG_MMIO_MSI_ADDRESS_H => self.state().set_msi_address_high(v),
                REG_MMIO_MSI_DATA => self.state().set_msi_data(v),
                _ => info!("unknown virtio mmio writel to 0x{:x}", offset),
            }
        } else if data.len() == 2 {
            let v = LittleEndian::read_u16(data);
            match offset {
                REG_MMIO_MSI_CSR => self.state().update_msi_enable(v, self),
                REG_MMIO_MSI_COMMAND => self.state().handle_msi_cmd(v, self),
                _ => {
                    info!("unknown virtio mmio writew to 0x{:x}", offset);
                }
            }
        } else {
            info!(
                "unknown virtio mmio register write: 0x{:x}/0x{:x}",
                offset,
                data.len()
            );
        }
    }

    fn get_assigned_resources(&self) -> DeviceResources {
        self.assigned_resources.clone()
    }

    fn get_trapped_io_resources(&self) -> DeviceResources {
        let mut resources = DeviceResources::new();

        resources.append(self.mmio_cfg_res.clone());

        resources
    }
}
