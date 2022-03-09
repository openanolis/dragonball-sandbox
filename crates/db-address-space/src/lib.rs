// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]

//! Traits and Structs to manage guest physical address space for virtual machines.
//!
//! The [vm-memory](https://crates.io/crates/vm-memory) implements mechanisms to manage and access
//! guest memory resident in guest physical address space. In addition to guest memory, there may
//! be other type of devices resident in the same guest physical address space.
//!
//! The `db-address-space` crate provides traits and structs to manage the guest physical address
//! space for virtual machines, and mechanisms to coordinate all the devices resident in the
//! guest physical address space.

pub mod numa;
pub use self::numa::{NumaIdTable, NumaNode, NumaNodeInfo, MPOL_MF_MOVE, MPOL_PREFERRED};

pub mod address_space;
pub use self::address_space::{
    AddressSpace, AddressSpaceBase, AddressSpaceError, AddressSpaceRegion, AddressSpaceRegionType,
};

mod layout;
pub use layout::AddressSpaceLayout;
