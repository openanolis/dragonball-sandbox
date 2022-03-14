// Copyright 2021-2022 Alibaba Cloud. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]

//! CPU architecture specific constants and utilities.
//!
//! This crate provides CPU architecture specific constants and utilities to abstract away CPU
//! architecture specific details from the Dragonball Sandbox or other VMMs.

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

/// Type for passing information about the initrd in the guest memory.
pub struct InitrdConfig {
    /// Load address of initrd in guest memory
    pub address: vm_memory::GuestAddress,
    /// Size of initrd in guest memory
    pub size: usize,
}
