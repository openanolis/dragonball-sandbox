// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Physical address space manager for virtual machines.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use nix::sys::memfd;
use vm_memory::{
    Address, AtomicAccess, Bytes, FileOffset, GuestAddress, GuestMemoryError, GuestMemoryMmap,
    GuestMemoryRegion, GuestUsize, MemoryRegionAddress,
};

#[cfg(not(feature = "region-hotplug"))]
/// Concrete type to implement address space manager.
pub type AddressSpace = AddressSpaceBase;

#[cfg(feature = "region-hotplug")]
/// Concrete type to implement address space manager with region hotplug capability.
pub type AddressSpace = self::hotplug::AddressSpaceAtomic;

/// Errors associated with virtual machine address space management.
#[derive(Debug, thiserror::Error)]
pub enum AddressSpaceError {
    /// Invalid address space region type.
    #[error("invalid address space region type")]
    InvalidRegionType,

    /// Invalid address range.
    #[error("invalid address space region (0x{0:x}, 0x{1:x})")]
    InvalidAddressRange(u64, GuestUsize),

    /// Failed to create memfd to map anonymous memory.
    #[error("can not create memfd to map anonymous memory")]
    CreateMemFd(#[source] nix::Error),

    /// Failed to open memory file.
    #[error("can not open memory file")]
    OpenFile(#[source] std::io::Error),

    /// Failed to set size for memory file.
    #[error("can not set size for memory file")]
    SetFileSize(#[source] std::io::Error),

    /// Failed to unlink memory file.
    #[error("can not unlink memory file")]
    UnlinkFile(#[source] nix::Error),
}

/// Type of address space regions.
///
/// On physical machines, physical memory may have different properties, such as
/// volatile vs non-volatile, read-only vs read-write, non-executable vs executable etc.
/// On virtual machines, the concept of memory property may be extended to support better
/// cooperation between the hypervisor and the guest kernel. Here address space region type means
/// what the region will be used for by the guest OS, and different permissions and policies may
/// be applied to different address space regions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceRegionType {
    /// Normal memory accessible by CPUs and IO devices.
    DefaultMemory,
    /// MMIO address region for Devices.
    DeviceMemory,
    /// DAX address region for virtio-fs/virtio-pmem.
    DAXMemory,
}

/// Struct to maintain configuration information about a guest address region.
#[derive(Debug, Clone)]
pub struct AddressSpaceRegion {
    /// Type of address space regions.
    ty: AddressSpaceRegionType,
    /// Base address of the region in virtual machine's physical address space.
    base: GuestAddress,
    /// Size of the address space region.
    size: GuestUsize,
    /// File/offset tuple to back the memory allocation.
    file_offset: Option<FileOffset>,
    /// Mmap permission flags.
    perm_flags: i32,
    /// Hugepage madvise hint.
    ///
    /// It needs 'advise' or 'always' policy in host shmem config.
    is_hugepage: bool,
    /// Hotplug hint.
    is_hotplug: bool,
    /// Anonymous memory hint.
    ///
    /// It should be true for regions with the MADV_DONTFORK flag enabled.
    is_anon: bool,
    /// Host NUMA node ids assigned to this region.
    host_numa_node_id: Option<u32>,
}

impl AddressSpaceRegion {
    /// Create an address space region with default configuration.
    pub fn new(ty: AddressSpaceRegionType, base: GuestAddress, size: GuestUsize) -> Self {
        AddressSpaceRegion {
            ty,
            base,
            size,
            file_offset: None,
            perm_flags: libc::MAP_SHARED,
            is_hugepage: false,
            is_hotplug: false,
            is_anon: false,
            host_numa_node_id: None,
        }
    }

    /// Create an address space region with all configurable information.
    ///
    /// # Arguments
    /// * `ty` - Type of the address region
    /// * `base` - Base address in VM to map content
    /// * `size` - Length of content to map
    /// * `file_offset` - Optional file descriptor and offset to map content from
    /// * `perm_flags` - mmap permission flags
    /// * `numa_node_id` - Optional NUMA node id to allocate memory from
    /// * `is_hotplug` - Whether it's a region for hotplug.
    pub fn build(
        ty: AddressSpaceRegionType,
        base: GuestAddress,
        size: GuestUsize,
        file_offset: Option<FileOffset>,
        perm_flags: i32,
        host_numa_node_id: Option<u32>,
        is_hotplug: bool,
    ) -> Self {
        let mut region = Self::new(ty, base, size);

        region.set_file_offset(file_offset);
        region.set_perm_flags(perm_flags);
        region.set_host_numa_node_id(host_numa_node_id);
        if is_hotplug {
            region.set_hotplug();
        }

        region
    }

    /// Create an address space region to map memory into the virtual machine.
    ///
    /// # Arguments
    /// * `base` - Base address in VM to map content
    /// * `size` - Length of content to map
    /// * `mem_type` - Memory mapping from, 'shmem' or 'hugetlbfs'
    /// * `mem_file_path` - Memory file path
    /// * `numa_node_id` - Optional NUMA node id to allocate memory from
    /// * `mem_prealloc` - Whether to enable pre-allocation of guest memory
    /// * `is_hotplug` - Whether it's a region for hotplug.
    pub fn create_default_memory_region(
        base: GuestAddress,
        size: GuestUsize,
        mem_type: &str,
        mem_file_path: &str,
        numa_node_id: Option<u32>,
        mem_prealloc: bool,
        is_hotplug: bool,
    ) -> Result<AddressSpaceRegion, AddressSpaceError> {
        Self::create_memory_region(
            base,
            size,
            mem_type,
            mem_file_path,
            numa_node_id,
            mem_prealloc,
            is_hotplug,
        )
    }

    /// Create an address space region to map memory from memfd/hugetlbfs into the virtual machine.
    ///
    /// # Arguments
    /// * `base` - Base address in VM to map content
    /// * `size` - Length of content to map
    /// * `mem_type` - Memory mapping from, 'shmem' or 'hugetlbfs'
    /// * `mem_file_path` - Memory file path
    /// * `numa_node_id` - Optional NUMA node id to allocate memory from
    /// * `mem_prealloc` - Whether to enable pre-allocation of guest memory
    /// * `is_hotplug` - Whether it's a region for hotplug.
    pub fn create_memory_region(
        base: GuestAddress,
        size: GuestUsize,
        mem_type: &str,
        mem_file_path: &str,
        numa_node_id: Option<u32>,
        mem_prealloc: bool,
        is_hotplug: bool,
    ) -> Result<AddressSpaceRegion, AddressSpaceError> {
        let perm_flags = if mem_prealloc {
            libc::MAP_SHARED | libc::MAP_POPULATE
        } else {
            libc::MAP_SHARED
        };
        if Self::is_shmem(mem_type) || Self::is_hugeshmem(mem_type) {
            let fn_str = if Self::is_shmem(mem_type) {
                CString::new("shmem").expect("CString::new('shmem') failed")
            } else {
                CString::new("hugeshmem").expect("CString::new('hugeshmem') failed")
            };
            let filename = fn_str.as_c_str();
            let fd = memfd::memfd_create(filename, memfd::MemFdCreateFlag::empty())
                .map_err(AddressSpaceError::CreateMemFd)?;
            // Safe because we have just created the fd.
            let file: File = unsafe { File::from_raw_fd(fd) };
            file.set_len(size as u64)
                .map_err(AddressSpaceError::SetFileSize)?;
            let mut reg = Self::build(
                AddressSpaceRegionType::DefaultMemory,
                base,
                size,
                Some(FileOffset::new(file, 0)),
                perm_flags,
                numa_node_id,
                is_hotplug,
            );
            if Self::is_hugeshmem(mem_type) {
                reg.set_hugepage();
            }
            Ok(reg)
        } else if Self::is_anon(mem_type) || Self::is_hugeanon(mem_type) {
            let mut perm_flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            if mem_prealloc {
                perm_flags |= libc::MAP_POPULATE
            }
            let mut reg = Self::build(
                AddressSpaceRegionType::DefaultMemory,
                base,
                size,
                None,
                perm_flags,
                numa_node_id,
                is_hotplug,
            );
            if Self::is_hugeanon(mem_type) {
                reg.set_hugepage();
            }
            reg.set_anonpage();
            Ok(reg)
        } else if Self::is_hugetlbfs(mem_type) {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(mem_file_path)
                .map_err(AddressSpaceError::OpenFile)?;
            nix::unistd::unlink(mem_file_path).map_err(AddressSpaceError::UnlinkFile)?;
            file.set_len(size as u64)
                .map_err(AddressSpaceError::SetFileSize)?;
            let file_offset = FileOffset::new(file, 0);
            Ok(Self::build(
                AddressSpaceRegionType::DefaultMemory,
                base,
                size,
                Some(file_offset),
                perm_flags,
                numa_node_id,
                is_hotplug,
            ))
        } else {
            Err(AddressSpaceError::InvalidRegionType)
        }
    }

    /// Create an address region for device MMIO.
    ///
    /// # Arguments
    /// * `base` - Base address in VM to map content
    /// * `size` - Length of content to map
    pub fn create_device_region(
        base: GuestAddress,
        size: GuestUsize,
    ) -> Result<AddressSpaceRegion, AddressSpaceError> {
        Ok(Self::build(
            AddressSpaceRegionType::DeviceMemory,
            base,
            size,
            None,
            0,
            None,
            false,
        ))
    }

    /// Get type of the address space region.
    pub fn region_type(&self) -> AddressSpaceRegionType {
        self.ty
    }

    /// Get mmap permission flags of the address space region.
    pub fn perm_flags(&self) -> i32 {
        self.perm_flags
    }

    /// Set mmap permission flags for the address space region.
    pub fn set_perm_flags(&mut self, perm_flags: i32) {
        self.perm_flags = perm_flags;
    }

    /// Check whether the address space region is backed by a memory file.
    pub fn has_file(&self) -> bool {
        self.file_offset.is_some()
    }

    /// Set associated file/offset pair for the region.
    pub fn set_file_offset(&mut self, file_offset: Option<FileOffset>) {
        self.file_offset = file_offset;
    }

    /// Get host_numa_node_id flags
    pub fn host_numa_node_id(&self) -> Option<u32> {
        self.host_numa_node_id
    }

    /// Set associated NUMA node ID to allocate memory from for this region.
    pub fn set_host_numa_node_id(&mut self, host_numa_node_id: Option<u32>) {
        self.host_numa_node_id = host_numa_node_id;
    }

    /// Set the hotplug hint.
    pub fn set_hotplug(&mut self) {
        self.is_hotplug = true
    }

    /// Get the hotplug hint.
    pub fn is_hotplug(&self) -> bool {
        self.is_hotplug
    }

    /// Set hugepage hint for `madvise()`, only takes effect when the memory type is `shmem`.
    pub fn set_hugepage(&mut self) {
        self.is_hugepage = true
    }

    /// Get the hugepage hint.
    pub fn is_hugepage(&self) -> bool {
        self.is_hugepage
    }

    /// Set the anonymous memory hint.
    pub fn set_anonpage(&mut self) {
        self.is_anon = true
    }

    /// Get the anonymous memory hint.
    pub fn is_anonpage(&self) -> bool {
        self.is_anon
    }

    /// Check whether the address space region is valid.
    pub fn is_valid(&self) -> bool {
        self.base.checked_add(self.size).is_some()
    }

    /// Check whether the address space region intersects with another one.
    pub fn intersect_with(&self, other: &AddressSpaceRegion) -> bool {
        // Treat invalid address region as intersecting always
        let end1 = match self.base.checked_add(self.size) {
            Some(addr) => addr,
            None => return true,
        };
        let end2 = match other.base.checked_add(other.size) {
            Some(addr) => addr,
            None => return true,
        };

        !(end1 <= other.base || self.base >= end2)
    }

    fn is_shmem(mem_type: &str) -> bool {
        mem_type == "shmem"
    }

    fn is_hugeshmem(mem_type: &str) -> bool {
        mem_type == "hugeshmem"
    }

    fn is_hugetlbfs(mem_type: &str) -> bool {
        mem_type == "hugetlbfs"
    }

    fn is_anon(mem_type: &str) -> bool {
        mem_type == "anon"
    }

    fn is_hugeanon(mem_type: &str) -> bool {
        mem_type == "hugeanon"
    }
}

impl Bytes<MemoryRegionAddress> for AddressSpaceRegion {
    type E = GuestMemoryError;

    fn write(&self, _buf: &[u8], _addr: MemoryRegionAddress) -> Result<usize, Self::E> {
        unimplemented!()
    }

    fn read(&self, _buf: &mut [u8], _addr: MemoryRegionAddress) -> Result<usize, Self::E> {
        unimplemented!()
    }

    fn write_slice(&self, _buf: &[u8], _addr: MemoryRegionAddress) -> Result<(), Self::E> {
        unimplemented!()
    }

    fn read_slice(&self, _buf: &mut [u8], _addr: MemoryRegionAddress) -> Result<(), Self::E> {
        unimplemented!()
    }

    fn read_from<F>(
        &self,
        _addr: MemoryRegionAddress,
        _src: &mut F,
        _count: usize,
    ) -> Result<usize, Self::E>
    where
        F: Read,
    {
        unimplemented!()
    }

    fn read_exact_from<F>(
        &self,
        _addr: MemoryRegionAddress,
        _src: &mut F,
        _count: usize,
    ) -> Result<(), Self::E>
    where
        F: Read,
    {
        unimplemented!()
    }

    fn write_to<F>(
        &self,
        _addr: MemoryRegionAddress,
        _dst: &mut F,
        _count: usize,
    ) -> Result<usize, Self::E>
    where
        F: Write,
    {
        unimplemented!()
    }

    fn write_all_to<F>(
        &self,
        _addr: MemoryRegionAddress,
        _dst: &mut F,
        _count: usize,
    ) -> Result<(), Self::E>
    where
        F: Write,
    {
        unimplemented!()
    }
    fn store<T: AtomicAccess>(
        &self,
        _val: T,
        _addr: MemoryRegionAddress,
        _order: Ordering,
    ) -> Result<(), Self::E> {
        unimplemented!()
    }
    fn load<T: AtomicAccess>(
        &self,
        _addr: MemoryRegionAddress,
        _order: Ordering,
    ) -> Result<T, Self::E> {
        unimplemented!()
    }
}

impl GuestMemoryRegion for AddressSpaceRegion {
    type B = ();

    fn len(&self) -> GuestUsize {
        self.size
    }

    fn start_addr(&self) -> GuestAddress {
        self.base
    }

    fn bitmap(&self) -> &Self::B {
        &()
    }

    fn file_offset(&self) -> Option<&FileOffset> {
        self.file_offset.as_ref()
    }
}

/// Address space layout configuration.
///
/// The layout configuration must guarantee that `mem_start` <= `mem_end` <= `phys_end`.
/// Non-memory region should be arranged into the range [mem_end, phys_end).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressSpaceLayout {
    /// end of guest physical address
    pub phys_end: u64,
    /// start of guest memory address
    pub mem_start: u64,
    /// end of guest memory address
    pub mem_end: u64,
}

impl AddressSpaceLayout {
    /// Create a new instance of `AddressSpaceLayout`.
    pub fn new(phys_end: u64, mem_start: u64, mem_end: u64) -> Self {
        AddressSpaceLayout {
            phys_end,
            mem_start,
            mem_end,
        }
    }

    /// Check whether an region is valid with the constraints of the layout.
    pub fn is_region_valid(&self, region: &AddressSpaceRegion) -> bool {
        let region_end = match region.base.0.checked_add(region.size) {
            None => return false,
            Some(v) => v,
        };

        match region.ty {
            AddressSpaceRegionType::DefaultMemory => {
                if region.base.0 < self.mem_start || region_end > self.mem_end {
                    return false;
                }
            }
            AddressSpaceRegionType::DeviceMemory | AddressSpaceRegionType::DAXMemory => {
                if region.base.0 < self.mem_end || region_end > self.phys_end {
                    return false;
                }
            }
        }

        true
    }
}

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

    /// Create a [GuestMemoryMmap] object from the address space object.
    pub fn create_guest_memory() -> GuestMemoryMmap {
        GuestMemoryMmap::new()
    }

    /// Get address space layout associated with the address space.
    pub fn get_layout(&self) -> AddressSpaceLayout {
        self.layout.clone()
    }

    /// Get maximum of guest physical address in the address space.
    pub fn get_last_addr(&self) -> GuestAddress {
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
    pub fn get_numa_node_id(&self, gpa: u64) -> Option<u32> {
        for reg in self.regions.iter() {
            if gpa >= reg.base.0 && gpa < (reg.base.0 + reg.size) {
                return reg.host_numa_node_id;
            }
        }
        None
    }
}

#[cfg(feature = "region-hotplug")]
mod hotplug {
    use super::*;
    use arc_swap::ArcSwap;

    /// An address space implementation with region hotplug capability.
    ///
    /// The `AddressSpaceAtomic` is a wrapper over [AddressSpaceInternal] to support hotplug of
    /// address space regions.
    #[derive(Clone)]
    pub struct AddressSpaceAtomic {
        state: Arc<ArcSwap<AddressSpaceBase>>,
    }

    impl AddressSpaceAtomic {
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

            AddressSpaceAtomic {
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

        /// Create a [GuestMemoryMmap] object from the address space object.
        pub fn create_guest_memory() -> GuestMemoryMmap {
            AddressSpaceBase::create_guest_memory()
        }

        /// Get address space layout associated with the address space.
        pub fn get_layout(&self) -> AddressSpaceLayout {
            self.state.load().get_layout()
        }

        /// Get maximum of guest physical address in the address space.
        pub fn get_last_addr(&self) -> GuestAddress {
            self.state.load().get_last_addr()
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
        pub fn get_numa_node_id(&self, gpa: u64) -> Option<u32> {
            self.state.load().get_numa_node_id(gpa)
        }
    }
}

impl AddressSpace {
    #[cfg(feature == "memory-hotplug")]
    /// Convert a [GuestMemoryMmap] object into `GuestMemoryAtomic<GuestMemoryMmap>`.
    pub fn convert_into_vm_as(
        gm: GuestMemoryMmap,
    ) -> vm_memory::atomic::GuestMemoryAtomic<GuestMemoryMmap> {
        GuestMemoryAtomic::from(Arc::new(gm))
    }

    #[cfg(not(feature == "memory-hotplug"))]
    /// Convert a [GuestMemoryMmap] object into `GuestMemoryAtomic<GuestMemoryMmap>`.
    pub fn convert_into_vm_as(gm: GuestMemoryMmap) -> Arc<GuestMemoryMmap> {
        Arc::new(gm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_sys_util::tempfile::TempFile;
    // define macros for unit test
    const GUEST_PHYS_END: u64 = (1 << 46) - 1;
    const GUEST_MEM_START: u64 = 0;
    const GUEST_MEM_END: u64 = GUEST_PHYS_END >> 1;

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
                GuestAddress(page_size * 3),
                page_size as GuestUsize,
            )),
        ];
        let boundary = AddressSpaceLayout::new(GUEST_PHYS_END, GUEST_MEM_START, GUEST_MEM_END);
        let address_space = AddressSpace::from_regions(address_space_region, boundary);

        assert!(!address_space.is_dax_region(GuestAddress(page_size)));
        assert!(!address_space.is_dax_region(GuestAddress(page_size * 2)));
        assert!(address_space.is_dax_region(GuestAddress(page_size * 3)));
        assert!(address_space.is_dax_region(GuestAddress(page_size * 3 + 1)));
        assert!(!address_space.is_dax_region(GuestAddress(page_size * 3 + page_size)));
        assert!(address_space.is_dax_region(GuestAddress(page_size * 3 + page_size - 1)));
    }

    #[test]
    fn test_address_space_region_valid() {
        let reg1 = AddressSpaceRegion::new(
            AddressSpaceRegionType::DefaultMemory,
            GuestAddress(0xFFFFFFFFFFFFF000),
            0x2000,
        );
        assert!(!reg1.is_valid());
        let reg1 = AddressSpaceRegion::new(
            AddressSpaceRegionType::DefaultMemory,
            GuestAddress(0xFFFFFFFFFFFFF000),
            0x1000,
        );
        assert!(!reg1.is_valid());
        let reg1 = AddressSpaceRegion::new(
            AddressSpaceRegionType::DeviceMemory,
            GuestAddress(0xFFFFFFFFFFFFE000),
            0x1000,
        );
        assert!(reg1.is_valid());
        assert_eq!(reg1.start_addr(), GuestAddress(0xFFFFFFFFFFFFE000));
        assert_eq!(reg1.len(), 0x1000);
        assert!(!reg1.has_file());
        assert!(reg1.file_offset().is_none());
        assert_eq!(reg1.perm_flags(), libc::MAP_SHARED);
        assert_eq!(reg1.region_type(), AddressSpaceRegionType::DeviceMemory);

        let tmp_file = TempFile::new().unwrap();
        let mut f = tmp_file.into_file();
        let sample_buf = &[1, 2, 3, 4, 5];
        assert!(f.write_all(sample_buf).is_ok());
        let reg2 = AddressSpaceRegion::build(
            AddressSpaceRegionType::DefaultMemory,
            GuestAddress(0x1000),
            0x1000,
            Some(FileOffset::new(f, 0x0)),
            0x5a,
            None,
            false,
        );
        assert_eq!(reg2.region_type(), AddressSpaceRegionType::DefaultMemory);
        assert!(reg2.is_valid());
        assert_eq!(reg2.start_addr(), GuestAddress(0x1000));
        assert_eq!(reg2.len(), 0x1000);
        assert!(reg2.has_file());
        assert!(reg2.file_offset().is_some());
        assert_eq!(reg2.perm_flags(), 0x5a);
    }

    #[test]
    fn test_address_space_region_intersect() {
        let reg1 = AddressSpaceRegion::new(
            AddressSpaceRegionType::DefaultMemory,
            GuestAddress(0x1000),
            0x1000,
        );
        let reg2 = AddressSpaceRegion::new(
            AddressSpaceRegionType::DefaultMemory,
            GuestAddress(0x2000),
            0x1000,
        );
        let reg3 = AddressSpaceRegion::new(
            AddressSpaceRegionType::DefaultMemory,
            GuestAddress(0x1000),
            0x1001,
        );
        let reg4 = AddressSpaceRegion::new(
            AddressSpaceRegionType::DefaultMemory,
            GuestAddress(0x1100),
            0x100,
        );
        let reg5 = AddressSpaceRegion::new(
            AddressSpaceRegionType::DefaultMemory,
            GuestAddress(0xFFFFFFFFFFFFF000),
            0x2000,
        );

        assert!(!reg1.intersect_with(&reg2));
        assert!(!reg2.intersect_with(&reg1));

        // intersect with self
        assert!(reg1.intersect_with(&reg1));

        // intersect with others
        assert!(reg3.intersect_with(&reg2));
        assert!(reg2.intersect_with(&reg3));
        assert!(reg1.intersect_with(&reg4));
        assert!(reg4.intersect_with(&reg1));
        assert!(reg1.intersect_with(&reg5));
        assert!(reg5.intersect_with(&reg1));
    }

    #[test]
    fn test_create_device_region() {
        let reg = AddressSpaceRegion::create_device_region(GuestAddress(0x10000), 0x1000).unwrap();
        assert_eq!(reg.region_type(), AddressSpaceRegionType::DeviceMemory);
        assert_eq!(reg.start_addr(), GuestAddress(0x10000));
        assert_eq!(reg.len(), 0x1000);
    }

    #[test]
    fn test_create_default_memory_region() {
        AddressSpaceRegion::create_default_memory_region(
            GuestAddress(0x100000),
            0x100000,
            "invalid",
            "invalid",
            None,
            false,
            false,
        )
        .unwrap_err();

        let reg = AddressSpaceRegion::create_default_memory_region(
            GuestAddress(0x100000),
            0x100000,
            "shmem",
            "",
            None,
            false,
            false,
        )
        .unwrap();
        assert_eq!(reg.region_type(), AddressSpaceRegionType::DefaultMemory);
        assert_eq!(reg.start_addr(), GuestAddress(0x100000));
        assert_eq!(reg.len(), 0x100000);
        assert!(reg.file_offset().is_some());

        // TODO: test hugetlbfs
    }

    #[test]
    fn test_create_address_space_internal() {
        let mut file = TempFile::new().unwrap().into_file();
        let sample_buf = &[1, 2, 3, 4, 5];
        assert!(file.write_all(sample_buf).is_ok());
        file.set_len(0x10000).unwrap();

        let reg = Arc::new(
            AddressSpaceRegion::create_device_region(GuestAddress(0x100000), 0x1000).unwrap(),
        );
        let regions = vec![reg];
        let boundary = AddressSpaceLayout::new(GUEST_PHYS_END, GUEST_MEM_START, GUEST_MEM_END);
        let address_space = AddressSpaceBase::from_regions(regions, boundary.clone());
        assert_eq!(address_space.get_layout(), boundary);
    }

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
}
