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

/// Defines the offset and scale of the mmio doorbell.
///
/// Support per-virtque doorbell, so the guest kernel may directly write to the doorbells provided
/// by hardware virtio devices.
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
}
