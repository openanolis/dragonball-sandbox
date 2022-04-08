// Copyright 2019-2020 Alibaba Cloud. All rights reserved.
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Interfaces and implementations of virtio devices.
//!
//! Please refer to [Virtio Specification]
//! (http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
//! for more information.

mod device;
pub use self::device::*;

mod notifier;
pub use self::notifier::*;

#[cfg(feature = "virtio-mmio")]
pub mod mmio;

#[cfg(feature = "virtio-vsock")]
pub mod vsock;

use std::io::Error as IOError;

use virtio_queue::Error as VqError;

/// Version of virtio specifications supported by PCI virtio devices.
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum VirtioVersion {
    /// Unknown/non-virtio VFIO device.
    VIRTIO_VERSION_UNKNOWN,
    /// Virtio specification 0.95(Legacy).
    VIRTIO_VERSION_0_95,
    /// Virtio specification 1.0/1.1.
    VIRTIO_VERSION_1_X,
}

/// Page size for legacy PCI virtio devices. Assume it's 4K.
pub const VIRTIO_LEGACY_PAGE_SIZE: u32 = 0x1000;

/// Initial state after device initialization/reset.
pub const DEVICE_INIT: u32 = 0x0;
/// Indicates that the guest OS has found the device and recognized it as a valid virtio device.
pub const DEVICE_ACKNOWLEDGE: u32 = 0x01;
/// Indicates that the guest OS knows how to drive the device.
pub const DEVICE_DRIVER: u32 = 0x02;
/// Indicates that the driver is set up and ready to drive the device.
pub const DEVICE_DRIVER_OK: u32 = 0x04;
/// Indicates that the driver has acknowledged all the features it understands, and feature
/// negotiation is complete.
pub const DEVICE_FEATURES_OK: u32 = 0x08;
/// Indicates that the device has experienced an error from which it can’t recover.
pub const DEVICE_NEEDS_RESET: u32 = 0x40;
/// Indicates that something went wrong in the guest, and it has given up on the device.
/// This could be an internal error, or the driver didn’t like the device for some reason, or even
/// a fatal error during device operation.
pub const DEVICE_FAILED: u32 = 0x80;

/// Virtio network card device.
pub const TYPE_NET: u32 = 1;
/// Virtio block device.
pub const TYPE_BLOCK: u32 = 2;
/// Virtio-rng device.
pub const TYPE_RNG: u32 = 4;
/// Virtio balloon device.
pub const TYPE_BALLOON: u32 = 5;
/// Virtio vsock device.
pub const TYPE_VSOCK: u32 = 19;
/// Virtio mem device.
pub const TYPE_MEM: u32 = 24;
/// Virtio-fs virtual device.
pub const TYPE_VIRTIO_FS: u32 = 26;
/// Virtio-pmem device.
pub const TYPE_PMEM: u32 = 27;

// Interrupt status flags for legacy interrupts. It happens to be the same for both PCI and MMIO
// virtio devices.
/// Data available in used queue.
pub const VIRTIO_INTR_VRING: u32 = 0x01;
/// Device configuration changed.
pub const VIRTIO_INTR_CONFIG: u32 = 0x02;

/// Error code for VirtioDevice::activate().
#[derive(Debug, thiserror::Error)]
pub enum ActivateError {
    #[error("Invalid param.")]
    InvalidParam,
    #[error("Internal error.")]
    InternalError,
    #[error("Invalid queue config.")]
    InvalidQueueConfig,
    #[error("IO: {0}.")]
    IOError(#[from] IOError),
}

/// Specialized std::result::Result for VirtioDevice::activate().
pub type ActivateResult = std::result::Result<(), ActivateError>;

/// Error for virtio devices to handle requests from guests.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid input parameter or status.
    #[error("invalid input parameter or status.")]
    InvalidInput,
    /// Generic IO error
    #[error("IO: {0}.")]
    IOError(#[from] IOError),
    /// Error from virtio_queue
    #[error("virtio queue error: {0}")]
    VirtioQueueError(#[from] VqError),
    /// Error from Device activate.
    #[error("Device activate error: {0}")]
    ActivateError(#[from] ActivateError),
    /// Error from Interrupt.
    #[error("Interrupt error: {0}")]
    InterruptError(IOError),
}

/// Specialized std::result::Result for Virtio device operations.
pub type Result<T> = std::result::Result<T, Error>;

macro_rules! warn_or_panic {
    ($($arg:tt)*) => {
        if cfg!(test) {
            panic!($($arg)*)
        } else {
            log::warn!($($arg)*)
        }
    }
}
pub(crate) use warn_or_panic;

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use dbs_interrupt::KvmIrqManager;
    use kvm_ioctls::{Kvm, VmFd};

    pub fn create_vm_and_irq_manager() -> (Arc<VmFd>, Arc<KvmIrqManager>) {
        let kvm = Kvm::new().unwrap();
        let vmfd = Arc::new(kvm.create_vm().unwrap());
        assert!(vmfd.create_irq_chip().is_ok());
        let irq_manager = Arc::new(KvmIrqManager::new(vmfd.clone()));
        assert!(irq_manager.initialize().is_ok());

        (vmfd, irq_manager)
    }
}
