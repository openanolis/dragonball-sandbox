// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Physical address space manager for virtual machines.

use std::sync::Arc;

use arc_swap::ArcSwap;
use vm_memory::{GuestAddress, GuestMemoryMmap};

use crate::{AddressSpaceError, AddressSpaceLayout, AddressSpaceRegion, AddressSpaceRegionType};

/// Base implementation to manage guest physical address space, without support of region hotplug.
#[derive(Clone)]
pub struct AddressSpaceBase {
    regions: Vec<Arc<AddressSpaceRegion>>,
    layout: AddressSpaceLayout,
}

impl AddressSpaceBase {
    /// Create an instance of `AddressSpaceBase` from an `AddressSpaceRegion` array.
    ///
    /// To achieve better performance by using binary search algorithm, the `regions` vector
    /// will gotten sorted by guest physical address.
    ///
    /// Note, panicking if some regions intersects with each other.
    ///
    /// # Arguments
    /// * `regions` - prepared regions to managed by the address space instance.
    /// * `layout` - prepared address space layout configuration.
    pub fn from_regions(
        mut regions: Vec<Arc<AddressSpaceRegion>>,
        layout: AddressSpaceLayout,
    ) -> Self {
        regions.sort_unstable_by_key(|v| v.base);
        for region in regions.iter() {
            if !layout.is_region_valid(region) {
                panic!(
                    "Invalid region {:?} for address space layout {:?}",
                    region, layout
                );
            }
        }
        for idx in 1..regions.len() {
            if regions[idx].intersect_with(&regions[idx - 1]) {
                panic!("address space regions intersect with each other");
            }
        }
        AddressSpaceBase { regions, layout }
    }

    /// Insert a new address space region into the address space.
    ///
    /// # Arguments
    /// * `region` - the new region to be inserted.
    pub fn insert_region(
        &mut self,
        region: Arc<AddressSpaceRegion>,
    ) -> Result<(), AddressSpaceError> {
        if !self.layout.is_region_valid(&region) {
            return Err(AddressSpaceError::InvalidAddressRange(
                region.start_addr().0,
                region.len(),
            ));
        }
        for idx in 0..self.regions.len() {
            if self.regions[idx].intersect_with(&region) {
                return Err(AddressSpaceError::InvalidAddressRange(
                    region.start_addr().0,
                    region.len(),
                ));
            }
        }
        self.regions.push(region);
        Ok(())
    }

    /// Enumerate all regions in the address space.
    ///
    /// # Arguments
    /// * `cb` - the callback function to apply to each region.
    pub fn walk_regions<F>(&self, mut cb: F) -> Result<(), AddressSpaceError>
    where
        F: FnMut(&Arc<AddressSpaceRegion>) -> Result<(), AddressSpaceError>,
    {
        for reg in self.regions.iter() {
            cb(reg)?;
        }

        Ok(())
    }

    /// Get address space layout associated with the address space.
    pub fn layout(&self) -> AddressSpaceLayout {
        self.layout.clone()
    }

    /// Get maximum of guest physical address in the address space.
    pub fn last_addr(&self) -> GuestAddress {
        let mut last_addr = GuestAddress(self.layout.mem_start);
        for reg in self.regions.iter() {
            if reg.ty != AddressSpaceRegionType::DAXMemory && reg.last_addr() > last_addr {
                last_addr = reg.last_addr();
            }
        }
        last_addr
    }

    /// Check whether the guest physical address `guest_addr` belongs to a DAX memory region.
    ///
    /// # Arguments
    /// * `guest_addr` - the guest physical address to inquire
    pub fn is_dax_region(&self, guest_addr: GuestAddress) -> bool {
        for reg in self.regions.iter() {
            // Safe because we have validate the region when creating the address space object.
            if reg.region_type() == AddressSpaceRegionType::DAXMemory
                && reg.start_addr() <= guest_addr
                && reg.start_addr().0 + reg.len() > guest_addr.0
            {
                return true;
            }
        }
        false
    }

    /// Get optional NUMA node id associated with guest physical address `gpa`.
    ///
    /// # Arguments
    /// * `gpa` - guest physical address to query.
    pub fn numa_node_id(&self, gpa: u64) -> Option<u32> {
        for reg in self.regions.iter() {
            if gpa >= reg.base.0 && gpa < (reg.base.0 + reg.size) {
                return reg.host_numa_node_id;
            }
        }
        None
    }
}

/// An address space implementation with region hotplug capability.
///
/// The `AddressSpaceAtomic` is a wrapper over [AddressSpaceInternal] to support hotplug of
/// address space regions.
#[derive(Clone)]
pub struct AddressSpace {
    state: Arc<ArcSwap<AddressSpaceBase>>,
}

impl AddressSpace {
    /// Convert a [GuestMemoryMmap] object into `GuestMemoryAtomic<GuestMemoryMmap>`.
    pub fn convert_into_vm_as(
        gm: GuestMemoryMmap,
    ) -> vm_memory::atomic::GuestMemoryAtomic<GuestMemoryMmap> {
        vm_memory::atomic::GuestMemoryAtomic::from(Arc::new(gm))
    }

    /// Create an instance of `AddressSpaceAtomic` from an `AddressSpaceRegion` array.
    ///
    /// To achieve better performance by using binary search algorithm, the `regions` vector
    /// will gotten sorted by guest physical address.
    ///
    /// Note, panicking if some regions intersects with each other.
    ///
    /// # Arguments
    /// * `regions` - prepared regions to managed by the address space instance.
    /// * `layout` - prepared address space layout configuration.
    pub fn from_regions(
        regions: Vec<Arc<AddressSpaceRegion>>,
        boundary: AddressSpaceLayout,
    ) -> Self {
        let internal = AddressSpaceBase::from_regions(regions, boundary);

        AddressSpace {
            state: Arc::new(ArcSwap::new(Arc::new(internal))),
        }
    }

    /// Insert a new address space region into the address space.
    ///
    /// # Arguments
    /// * `region` - the new region to be inserted.
    pub fn insert_region(
        &mut self,
        region: Arc<AddressSpaceRegion>,
    ) -> Result<(), AddressSpaceError> {
        let curr = self.state.load().regions.clone();
        let boundary = self.state.load().layout.clone();
        let mut internal = AddressSpaceBase::from_regions(curr, boundary);
        internal.insert_region(region)?;
        let _old = self.state.swap(Arc::new(internal));

        Ok(())
    }

    /// Enumerate all regions in the address space.
    ///
    /// # Arguments
    /// * `cb` - the callback function to apply to each region.
    pub fn walk_regions<F>(&self, cb: F) -> Result<(), AddressSpaceError>
    where
        F: FnMut(&Arc<AddressSpaceRegion>) -> Result<(), AddressSpaceError>,
    {
        self.state.load().walk_regions(cb)
    }

    /// Get address space layout associated with the address space.
    pub fn layout(&self) -> AddressSpaceLayout {
        self.state.load().layout()
    }

    /// Get maximum of guest physical address in the address space.
    pub fn last_addr(&self) -> GuestAddress {
        self.state.load().last_addr()
    }

    /// Check whether the guest physical address `guest_addr` belongs to a DAX memory region.
    ///
    /// # Arguments
    /// * `guest_addr` - the guest physical address to inquire
    pub fn is_dax_region(&self, guest_addr: GuestAddress) -> bool {
        self.state.load().is_dax_region(guest_addr)
    }

    /// Get optional NUMA node id associated with guest physical address `gpa`.
    ///
    /// # Arguments
    /// * `gpa` - guest physical address to query.
    pub fn numa_node_id(&self, gpa: u64) -> Option<u32> {
        self.state.load().numa_node_id(gpa)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use vm_memory::GuestUsize;
    use vmm_sys_util::tempfile::TempFile;

    // define macros for unit test
    const GUEST_PHYS_END: u64 = (1 << 46) - 1;
    const GUEST_MEM_START: u64 = 0;
    const GUEST_MEM_END: u64 = GUEST_PHYS_END >> 1;
    const GUEST_DEVICE_START: u64 = GUEST_MEM_END + 1;

    #[test]
    fn test_is_reserved_region() {
        let page_size = 4096;
        let address_space_region = vec![
            Arc::new(AddressSpaceRegion::new(
                AddressSpaceRegionType::DefaultMemory,
                GuestAddress(page_size),
                page_size as GuestUsize,
            )),
            Arc::new(AddressSpaceRegion::new(
                AddressSpaceRegionType::DefaultMemory,
                GuestAddress(page_size * 2),
                page_size as GuestUsize,
            )),
            Arc::new(AddressSpaceRegion::new(
                AddressSpaceRegionType::DAXMemory,
                GuestAddress(GUEST_DEVICE_START),
                page_size as GuestUsize,
            )),
        ];
        let boundary = AddressSpaceLayout::new(GUEST_PHYS_END, GUEST_MEM_START, GUEST_MEM_END);
        let address_space = AddressSpace::from_regions(address_space_region, boundary);

        assert!(!address_space.is_dax_region(GuestAddress(page_size)));
        assert!(!address_space.is_dax_region(GuestAddress(page_size * 2)));
        assert!(address_space.is_dax_region(GuestAddress(GUEST_DEVICE_START)));
        assert!(address_space.is_dax_region(GuestAddress(GUEST_DEVICE_START + 1)));
        assert!(!address_space.is_dax_region(GuestAddress(GUEST_DEVICE_START + page_size)));
        assert!(address_space.is_dax_region(GuestAddress(GUEST_DEVICE_START + page_size - 1)));
    }

    #[test]
    fn test_create_address_space_internal() {
        let mut file = TempFile::new().unwrap().into_file();
        let sample_buf = &[1, 2, 3, 4, 5];
        assert!(file.write_all(sample_buf).is_ok());
        file.set_len(0x10000).unwrap();

        let reg = Arc::new(
            AddressSpaceRegion::create_device_region(GuestAddress(GUEST_DEVICE_START), 0x1000)
                .unwrap(),
        );
        let regions = vec![reg];
        let boundary = AddressSpaceLayout::new(GUEST_PHYS_END, GUEST_MEM_START, GUEST_MEM_END);
        let address_space = AddressSpaceBase::from_regions(regions, boundary.clone());
        assert_eq!(address_space.layout(), boundary);
    }

    /*
    #[should_panic]
    #[test]
    fn test_create_address_space_internal_panic() {
        let mut file = TempFile::new().unwrap().into_file();
        let sample_buf = &[1, 2, 3, 4, 5];
        assert!(file.write_all(sample_buf).is_ok());
        file.set_len(0x10000).unwrap();

        let reg = Arc::new(
            AddressSpaceRegion::create_device_region(GuestAddress(0x10_0000), 0x1000).unwrap(),
        );
        let regions = vec![reg.clone(), reg];
        let boundary = AddressSpaceLayout::new(GUEST_PHYS_END, GUEST_MEM_START, GUEST_MEM_END);
        let _ = AddressSpaceBase::from_regions(regions, boundary);
    }
     */
}
