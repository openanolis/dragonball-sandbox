// Copyright 2021-2022 Alibaba Cloud. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]

//! CPU architecture specific constants and utilities.
//!
//! This crate provides CPU architecture specific constants and utilities to abstract away CPU
//! architecture specific details from the Dragonball Sandbox or other VMMs.
use std::fmt;
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

/// Types of devices that can get attached to this platform.
#[derive(Versionize, Clone, Debug, PartialEq, Eq, Hash, Copy)]
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

/// Type for passing information about the initrd in the guest memory.
pub struct InitrdConfig {
    /// Load address of initrd in guest memory
    pub address: vm_memory::GuestAddress,
    /// Size of initrd in guest memory
    pub size: usize,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
