// Copyright 2021 Alibaba Cloud. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM boot related constants and utilities for `x86_64` architecture.

/// Magic addresses externally used to lay out x86_64 VMs.
pub mod layout;

/// Structure definitions for SMP machines following the Intel Multiprocessing Specification 1.1 and 1.4.
pub mod mpspec;

/// MP Table configurations used for defining VM boot status.
pub mod mptable;
