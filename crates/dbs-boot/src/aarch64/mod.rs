// Copyright 2021 Alibaba Cloud. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM boot related constants and utilities for `aarch64` architecture.

/// Magic addresses externally used to lay out aarch64 VMs.
pub mod layout;

/// FDT is used to inform the guest kernel of device tree information.
pub mod fdt;
