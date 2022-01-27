// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Types for NUMA information.

use vm_memory::{GuestAddress, GuestUsize};

/// Strategy of mbind() and don't lead to OOM.
pub const MPOL_PREFERRED: u32 = 1;

/// Strategy of mbind()
pub const MPOL_MF_MOVE: u32 = 2;

/// Type for recording numa ids of different devices
pub struct NumaIdTable {
    /// vectors of numa id for each memory region
    pub memory: Vec<u32>,
    /// vectors of numa id for each cpu
    pub cpu: Vec<u32>,
}

/// Record numa node memory information.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct NumaNodeInfo {
    /// Base address of the region in guest physical address space.
    pub base: GuestAddress,
    /// Size of the address region.
    pub size: GuestUsize,
}

/// Record all region's info of a numa node.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct NumaNode {
    region_infos: Vec<NumaNodeInfo>,
    vcpu_ids: Vec<u32>,
}

impl NumaNode {
    /// get reference of region_infos in numa node.
    pub fn region_infos(&self) -> &Vec<NumaNodeInfo> {
        &self.region_infos
    }

    /// get vcpu ids belonging to a numa node.
    pub fn vcpu_ids(&self) -> &Vec<u32> {
        &self.vcpu_ids
    }

    /// add a new numa region info into this numa node.
    pub fn add_info(&mut self, info: &NumaNodeInfo) {
        self.region_infos.push(*info);
    }

    /// add a group of vcpu ids belong to this numa node
    pub fn add_vcpu_ids(&mut self, vcpu_ids: &[u32]) {
        self.vcpu_ids.extend(vcpu_ids)
    }

    /// create a new numa node struct
    pub fn new() -> NumaNode {
        NumaNode {
            region_infos: Vec::new(),
            vcpu_ids: Vec::new(),
        }
    }
}
