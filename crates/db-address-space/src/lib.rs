// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]

//! Address Manager traits and implementation.

pub mod numa;
pub use numa::{NumaIdTable, NumaNode, NumaNodeInfo, MPOL_MF_MOVE, MPOL_PREFERRED};

pub mod address_space;
pub use self::address_space::{
    AddressSpace, AddressSpaceBoundary, AddressSpaceError, AddressSpaceInternal,
    AddressSpaceRegion, AddressSpaceRegionType,
};
