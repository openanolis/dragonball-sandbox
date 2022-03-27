// Copyright 2021 Alibaba Cloud. All Rights Reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! CPU architecture specific constants, structures and utilities for the `aarch64` architecture.
/// Module for the global interrupt controller configuration.
pub mod gic;
/// Logic for configuring aarch64 registers.
pub mod regs;

use std::{fmt, result};

const MMIO_DEVICE_LEGACY_IRQ_NUMBER: usize = 1;

/// Error for arm64 architecture information
pub enum Error {
    /// MMIO device information error
    MMIODeviceInfoError,
    /// Invalid arguments
    InvalidArguments,
}

type Result<T> = result::Result<T, Error>;

/// Types of devices that can get attached to this platform.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
pub enum DeviceType {
    /// Device Type: Virtio.
    Virtio(u32),
    /// Device Type: Serial.
    #[cfg(target_arch = "aarch64")]
    Serial,
    /// Device Type: RTC.
    #[cfg(target_arch = "aarch64")]
    RTC,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Trait for devices to be added to the Flattened Device Tree.
pub trait DeviceInfoForFDT {
    /// Returns the address where this device will be loaded.
    fn addr(&self) -> u64;
    /// Returns the associated interrupt for this device.
    fn irq(&self) -> Result<u32>;
    /// Returns the amount of memory that needs to be reserved for this device.
    fn length(&self) -> u64;
    /// Get device id
    fn get_device_id(&self) -> Option<u32>;
}

/// MMIO device info used for FDT generating.
#[derive(Debug, Clone, PartialEq)]
pub struct MMIODeviceInfo {
    /// MMIO address base
    pub base: u64,
    /// MMIO address size
    pub size: u64,
    /// Device irq
    pub irqs: Vec<u32>,
    /// Only virtio devices that support platform msi have device id
    pub device_id: Option<u32>,
}

impl MMIODeviceInfo {
    /// Create mmio device info.
    pub fn new(base: u64, size: u64, irqs: Vec<u32>, device_id: Option<u32>) -> Self {
        MMIODeviceInfo {
            base,
            size,
            irqs,
            device_id,
        }
    }
}

impl DeviceInfoForFDT for MMIODeviceInfo {
    fn addr(&self) -> u64 {
        self.base
    }

    fn irq(&self) -> Result<u32> {
        // Currently mmio devices have only one legacy irq.
        if self.irqs.len() != MMIO_DEVICE_LEGACY_IRQ_NUMBER {
            return Err(Error::MMIODeviceInfoError);
        }
        Ok(self.irqs[0])
    }

    fn length(&self) -> u64 {
        self.size
    }

    fn get_device_id(&self) -> Option<u32> {
        self.device_id
    }
}
