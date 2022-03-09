// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structs to manage guest memory for virtual machines.
//!
//! The `vm-memory` crate only provides traits and structs to access normal guest memory,
//! it doesn't support special guest memory like virtio-fs/virtio-pmem DAX window etc.
//! So this crate provides `GuestMemoryManager` over `vm-memory` to provide uniform abstraction
//! for all guest memory.
//!
//! It also provides interfaces to coordinate guest memory hotplug events.

use std::sync::Arc;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap};

mod hybrid;
pub use hybrid::{GuestMemoryHybrid, GuestRegionHybrid};

#[derive(Debug, Default)]
struct GuestMemoryHotplugManager {}

/// The `GuestMemoryManager` manages all guest memory for virtual machines.
///
/// The `GuestMemoryManager` fulfills several different responsibilities.
/// - First, it manages different types of guest memory, such as normal guest memory, virtio-fs
///   DAX window and virtio-pmem DAX window etc. Different clients may want to access different
///   types of memory. So the manager maintains two GuestMemory objects, one contains all guest
///   memory, the other contains only normal guest memory.
/// - Second, it coordinates memory/DAX window hotplug events, so clients may register hooks
///   to receive hotplug notifications.
#[derive(Debug, Clone)]
pub struct GuestMemoryManager {
    /// GuestMemory object hosts all guest memory.
    hybrid: GuestMemoryAtomic<GuestMemoryHybrid>,
    /// GuestMemory object hosts normal guest memory.
    normal: GuestMemoryAtomic<GuestMemoryMmap>,
    _hotplug: Arc<GuestMemoryHotplugManager>,
}

impl GuestMemoryManager {
    /// Create a new instance of `GuestMemoryManager`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a reference to the normal `GuestMemory` object.
    pub fn get_normal_guest_memory(&self) -> &GuestMemoryAtomic<GuestMemoryMmap> {
        &self.normal
    }

    /// Try to downcast the `GuestAddressSpace` object to a `GuestMemoryManager` object.
    pub fn to_manager<AS: GuestAddressSpace>(_m: &AS) -> Option<&Self> {
        None
    }
}

impl Default for GuestMemoryManager {
    fn default() -> Self {
        let hybrid = GuestMemoryAtomic::new(GuestMemoryHybrid::new());
        let normal = GuestMemoryAtomic::new(GuestMemoryMmap::new());

        GuestMemoryManager {
            hybrid,
            normal,
            _hotplug: Arc::new(GuestMemoryHotplugManager::default()),
        }
    }
}

impl GuestAddressSpace for GuestMemoryManager {
    type M = GuestMemoryHybrid;
    type T = GuestMemoryLoadGuard<GuestMemoryHybrid>;

    fn memory(&self) -> Self::T {
        // By default, it provides to the `GuestMemoryHybrid` object containing all guest memory.
        self.hybrid.memory()
    }
}
