// Copyright 2021 Alibaba Cloud. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM boot related constants and utilities for `aarch64` architecture.

use std::ffi::NulError;
use std::io;
use vm_memory::GuestMemoryError;
/// Magic addresses externally used to lay out aarch64 VMs.
pub mod layout;

/// FDT is used to inform the guest kernel of device tree information.
pub mod fdt;

/// Errors thrown while configuring aarch64 system.
#[derive(Debug)]
pub enum Error {
    /// Failed to append node to the FDT.
    AppendFDTNode(io::Error),
    /// Failed to append a property to the FDT.
    AppendFDTProperty(io::Error),
    /// Syscall for creating FDT failed.
    CreateFDT(io::Error),
    /// Failed to obtain a C style string.
    CstringFDTTransform(NulError),
    /// Failure in calling syscall for terminating this FDT.
    FinishFDTReserveMap(io::Error),
    /// Failure in writing FDT in memory.
    WriteFDTToMemory(GuestMemoryError),
    /// Invalid arguments
    InvalidArguments,
}
