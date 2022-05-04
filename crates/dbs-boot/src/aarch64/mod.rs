// Copyright 2021 Alibaba Cloud. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM boot related constants and utilities for `aarch64` architecture.

use vm_fdt::Error as VmFdtError;
use vm_memory::GuestMemoryError;
/// Magic addresses externally used to lay out aarch64 VMs.
pub mod layout;

/// FDT is used to inform the guest kernel of device tree information.
pub mod fdt;

/// Errors thrown while configuring the Flattened Device Tree for aarch64.
#[derive(Debug)]
pub enum Error {
    /// Failure in creating FDT
    CreateFdt(VmFdtError),
    /// Failure in writing FDT in memory.
    WriteFDTToMemory(GuestMemoryError),
    /// Invalid arguments
    InvalidArguments,
}

impl From<VmFdtError> for Error {
    fn from(e: VmFdtError) -> Self {
        Error::CreateFdt(e)
    }
}
