// Copyright (C) 2019 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Related to Dragonball MMIO extension.

/// Default size resrved for virtio-mmio doorbell address space.
///
/// This represents the size of the mmio device reserved for doorbell which used to per queue notify,
/// we need to request resource with the `MMIO_DEFAULT_CFG_SIZE + DRAGONBALL_MMIO_DOORBELL_SIZE`
pub const DRAGONBALL_MMIO_DOORBELL_SIZE: u64 = 0x1000;

/// Default offset of the mmio doorbell
pub const DRAGONBALL_MMIO_DOORBELL_OFFSET: u64 = 0x1000;

/// Max queue num when the `fast-mmio` enabled, because we only reserved 0x200 memory region for
/// per queue notify
pub const DRAGONBALL_MMIO_MAX_QUEUE_NUM: u64 = 255;

/// Scale of the doorbell for per queue notify
pub const DRAGONBALL_MMIO_DOORBELL_SCALE: u64 = 0x04;

/// This represents the offset at which the device should call DeviceIo::write in order to write
/// to its configuration space.
pub const MMIO_CFG_SPACE_OFF: u64 = 0x100;

// Define a 16-byte area to control MMIO MSI

// MSI control/status register offset
pub const VIRTIO_MMIO_MSI_CSR: u64 = 0x0c0;
// MSI command register offset
pub const VIRTIO_MMIO_MSI_COMMAND: u64 = 0x0c2;
// MSI address_lo register offset
pub const VIRTIO_MMIO_MSI_ADDRESS_L: u64 = 0x0c4;
// MSI address_hi register offset
pub const VIRTIO_MMIO_MSI_ADDRESS_H: u64 = 0x0c8;
// MSI data register offset
pub const VIRTIO_MMIO_MSI_DATA: u64 = 0x0cc;

// RW: MSI feature enabled
pub const VIRTIO_MMIO_MSI_CSR_ENABL: u64 = 0x8000;
// RO: Maximum queue size available
pub const VIRTIO_MMIO_MSI_CSR_QMAS: u64 = 0x07ff;
// Reserved
pub const VIRTIO_MMIO_MSI_CSR_RESERV: u64 = 0x7800;

pub const VIRTIO_MMIO_MSI_CMD_UPDAT: u64 = 0x1;
pub const VIRTIO_MMIO_MSI_CMD_CODE_MA: u64 = 0xf000;

/// Defines the offset and scale of the mmio doorbell.
///
/// Support per-virtque doorbell, so the guest kernel may directly write to the doorbells provided
/// by hardware virtio devices.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct DoorBell {
    offset: u32,
    scale: u32,
}

impl DoorBell {
    /// Creates a Doorbell.
    pub fn new(offset: u32, scale: u32) -> Self {
        Self { offset, scale }
    }

    /// Returns the offset.
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Returns the scale.
    pub fn scale(&self) -> u32 {
        self.scale
    }

    /// Returns the offset with the specified index of virtio queue.
    pub fn queue_offset(&self, queue_index: usize) -> u64 {
        (self.offset as u64) + (self.scale as u64) * (queue_index as u64)
    }

    /// Returns the register data.
    pub fn register_data(&self) -> u32 {
        self.offset | (self.scale << 16)
    }
}

/// MSI interrupts.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Msi {
    pub index_select: u32,
    pub address_low: u32,
    pub address_high: u32,
    pub data: u32,
}

impl Msi {
    /// Sets index select.
    pub fn set_index_select(&mut self, v: u32) {
        self.index_select = v;
    }
    /// Sets address low.
    pub fn set_address_low(&mut self, v: u32) {
        self.address_low = v;
    }
    /// Sets address high.
    pub fn set_address_high(&mut self, v: u32) {
        self.address_high = v;
    }
    /// Sets msi data.
    pub fn set_data(&mut self, v: u32) {
        self.data = v;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doorbell() {
        let door = DoorBell::new(
            DRAGONBALL_MMIO_DOORBELL_OFFSET as u32,
            DRAGONBALL_MMIO_DOORBELL_SCALE as u32,
        );
        assert_eq!(door.offset(), DRAGONBALL_MMIO_DOORBELL_OFFSET as u32);
        assert_eq!(door.scale(), DRAGONBALL_MMIO_DOORBELL_SCALE as u32);
        assert_eq!(door.queue_offset(0), DRAGONBALL_MMIO_DOORBELL_OFFSET as u64);
        assert_eq!(door.queue_offset(4), 0x1010);
        assert_eq!(door.register_data(), 0x1000 | 0x40000);
    }

    #[test]
    fn test_msi() {
        let mut msi = Msi::default();
        msi.set_index_select(1);
        msi.set_address_low(2);
        msi.set_address_high(3);
        msi.set_data(4);
        assert_eq!(
            msi,
            Msi {
                index_select: 1,
                address_low: 2,
                address_high: 3,
                data: 4
            }
        );
    }
}
