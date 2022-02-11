// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Types for address space information.

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

/// Internal types for Address space.
#[cfg(not(feature = "atomic-guest-memory"))]
pub type AddressSpace = AddressSpaceInternal;

/// Internal types for Address space in atomic scenario.
/// This is a fundamental feature for memory hotplug
#[cfg(feature = "atomic-guest-memory")]
pub type AddressSpace = self::atomic::AddressSpaceAtomic;

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
    #[error("cannot create memfd to map anonymous memory")]
    CreateMemFd(#[source] nix::Error),

    /// Failed to open memory file.
    #[error("cannot open memory file")]
    OpenFile(#[source] std::io::Error),

    /// Failed to set size for memory file.
    #[error("cannot set size for memory file")]
    SetFileSize(#[source] std::io::Error),

    /// Failed to unlink memory file.
    #[error("cannot unlike memory file")]
    UnlinkFile(#[source] nix::Error),
}

/// Type of address space regions.
///
/// On physical machines, physical memory may have different properties, such as
/// volatile vs non-volatile, read-only vs read-write, non-executable vs
/// executable etc. On virtual machines, the concept of memory property may be
/// extended to support better cooperation between the hypervisor and the guest
/// kernel. Here address space region type means what the region will be used for by
/// the guest OS, and different permissions and policies may be applied to different
/// address space regions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceRegionType {
    /// Normal memory accessible by CPUs and IO devices
    DefaultMemory,
    /// Device MMIO address
    DeviceMemory,
    /// DAX address
    DAXMemory,
}

/// Represent a guest address region.
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
    /// Hugepage madvise hint, this needs 'advise' or 'always' policy in host shmem config
    is_hugepage: bool,
    /// hotplug hint, for hotplug_size region, should set 'true'
    is_hotplug: bool,
    /// anonymous memory, for add MADV_DONTFORK, should set 'true'
    is_anon: bool,
    /// host numa node id for this address space region to be allocated from
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

    /// Set hugeshme madvise hint, only has affect when memory type is shmem
    pub fn set_hugepage(&mut self) {
        self.is_hugepage = true
    }

    /// Set anonymous memory hint
    pub fn set_anonpage(&mut self) {
        self.is_anon = true
    }

    /// Set hotplug hint
    pub fn set_hotplug(&mut self) {
        self.is_hotplug = true
    }

    /// Create an address space region with all configurable information.
    ///
    /// # Arguments
    /// * `ty` - Type of the address region
    /// * `base` - Base address in VM to map content
    /// * `size` - Length of content to map
    /// * `file_offset` - Optional file descriptor and offset to map content from
    /// * `perm_flags` - mmap permission flags
    /// * `is_hugeshmem` - Enable THP on shmem
    pub fn build(
        ty: AddressSpaceRegionType,
        base: GuestAddress,
        size: GuestUsize,
        file_offset: Option<FileOffset>,
        perm_flags: i32,
        is_hotplug: bool,
        host_numa_node_id: Option<u32>,
    ) -> Self {
        AddressSpaceRegion {
            ty,
            base,
            size,
            file_offset,
            perm_flags,
            is_hugepage: false,
            is_hotplug,
            is_anon: false,
            host_numa_node_id,
        }
    }

    /// Create an address space region to map memory from memfd/hugetlbfs into the virtual machine.
    ///
    /// # Arguments
    /// * `base` - Base address in VM to map content
    /// * `size` - Length of content to map
    /// * `mem_type` - Memory mapping from, 'shmem' or 'hugetlbfs'
    /// * `mem_file_path` - Memory file path
    /// * `numa_node_id` - NUMA node id to allocate memory from
    /// * `mem_prealloc_enabled` - Enable prealloc of guest memory or not
    pub fn create_default_memory_region(
        base: GuestAddress,
        size: GuestUsize,
        mem_type: &str,
        mem_file_path: &str,
        numa_node_id: Option<u32>,
        mem_prealloc_enabled: bool,
        is_hotplug: bool,
    ) -> Result<AddressSpaceRegion, AddressSpaceError> {
        Self::create_memory_region(
            base,
            size,
            mem_type,
            mem_file_path,
            numa_node_id,
            mem_prealloc_enabled,
            is_hotplug,
            AddressSpaceRegionType::DefaultMemory,
        )
    }

    /// Create an address space region to map memory from memfd/hugetlbfs into the virtual machine.
    ///
    /// # Arguments
    /// * `base` - Base address in VM to map content
    /// * `size` - Length of content to map
    /// * `mem_type` - Memory mapping from, 'shmem' or 'hugetlbfs'
    /// * `mem_file_path` - Memory file path
    /// * `numa_node_id` - NUMA node id to allocate memory from
    /// * `mem_prealloc_enabled` - Enable prealloc of guest memory or not
    /// * `region_type` - The type of address spacee region
    #[allow(clippy::too_many_arguments)]
    pub fn create_memory_region(
        base: GuestAddress,
        size: GuestUsize,
        mem_type: &str,
        mem_file_path: &str,
        numa_node_id: Option<u32>,
        mem_prealloc_enabled: bool,
        is_hotplug: bool,
        region_type: AddressSpaceRegionType,
    ) -> Result<AddressSpaceRegion, AddressSpaceError> {
        let perm_flags = if mem_prealloc_enabled {
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
                region_type,
                base,
                size,
                Some(FileOffset::new(file, 0)),
                perm_flags,
                is_hotplug,
                numa_node_id,
            );
            if Self::is_hugeshmem(mem_type) {
                reg.set_hugepage();
            }
            Ok(reg)
        } else if Self::is_anon(mem_type) || Self::is_hugeanon(mem_type) {
            let mut perm_flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            if mem_prealloc_enabled {
                perm_flags |= libc::MAP_POPULATE
            }
            let mut reg = Self::build(
                region_type,
                base,
                size,
                None,
                perm_flags,
                is_hotplug,
                numa_node_id,
            );
            if Self::is_hugeanon(mem_type) {
                reg.set_hugepage();
            }
            reg.set_anonpage();
            Ok(reg)
        } else if Self::is_hugetlbfs(mem_type) {
            let offset = 0;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(mem_file_path)
                .map_err(AddressSpaceError::OpenFile)?;
            nix::unistd::unlink(mem_file_path).map_err(AddressSpaceError::UnlinkFile)?;
            file.set_len(size as u64)
                .map_err(AddressSpaceError::SetFileSize)?;
            let file_offset = FileOffset::new(file, offset);
            Ok(Self::build(
                region_type,
                base,
                size,
                Some(file_offset),
                perm_flags,
                is_hotplug,
                numa_node_id,
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
            false,
            None,
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

    /// Get hotplug hint
    pub fn is_hotplug(&self) -> bool {
        self.is_hotplug
    }

    /// Get hugepage flags
    pub fn is_hugepage(&self) -> bool {
        self.is_hugepage
    }

    /// Get anon flags
    pub fn is_anon_flags(&self) -> bool {
        self.is_anon
    }

    /// Get host_numa_node_id flags
    pub fn host_numa_node_id(&self) -> Option<u32> {
        self.host_numa_node_id
    }

    /// Check whether the address space region is backed by a memory file.
    pub fn has_file(&self) -> bool {
        self.file_offset.is_some()
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

// TODO: implement following methods on demand
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

    fn file_offset(&self) -> Option<&FileOffset> {
        self.file_offset.as_ref()
    }

    fn bitmap(&self) -> &Self::B {
        &()
    }
}

/// Struct to preserve several boundary of address space
#[derive(Debug, Clone, PartialEq)]
pub struct AddressSpaceBoundary {
    /// guest physical end address
    pub phys_end: u64,
    /// guest memory start address
    pub mem_start: u64,
    /// guest memory end address
    pub mem_end: u64,
}

impl AddressSpaceBoundary {
    /// Create a new boundary with several constraints.
    pub fn new(phys_end: u64, mem_start: u64, mem_end: u64) -> Self {
        AddressSpaceBoundary {
            phys_end,
            mem_start,
            mem_end,
        }
    }
}

/// Struct to manage virtual machine's physical address space.
#[derive(Clone)]
pub struct AddressSpaceInternal {
    regions: Vec<Arc<AddressSpaceRegion>>,
    boundary: AddressSpaceBoundary,
}

impl AddressSpaceInternal {
    /// Find the region to which the guest_addr belongs, and determine
    /// whether the type of the region is DAXMemory
    ///
    /// # Arguments
    /// * `guest_addr` - the guest physical address you want to inquire
    pub fn is_reserved_region(&self, guest_addr: GuestAddress) -> bool {
        for reg in self.regions.iter() {
            // Safe because region is allocated from ResourceManager's mem_pool
            // or mmio_pool, so reg.start_addr() + reg.len() will not overflow
            if reg.region_type() == AddressSpaceRegionType::DAXMemory
                && reg.start_addr() <= guest_addr
                && reg.start_addr().checked_add(reg.len()).unwrap() > guest_addr
            {
                return true;
            }
        }
        false
    }

    /// Create an address space instance from address space regions and boundary.
    ///
    /// To achieve better performance by using binary search algorithm, the `regions` vector will
    /// gotten sorted.
    /// Note, panicking if some regions intersects with each other.
    ///
    /// # Arguments
    /// * `regions` - prepared regions to managed by the address space instance.
    /// * `boundary` - prepared address space boundary.
    pub fn from_regions(
        mut regions: Vec<Arc<AddressSpaceRegion>>,
        boundary: AddressSpaceBoundary,
    ) -> Self {
        regions.sort_by_key(|v| v.base);
        for idx in 1..regions.len() {
            if regions[idx].intersect_with(&regions[idx - 1]) {
                panic!("address space regions intersect with each other");
            }
        }
        AddressSpaceInternal { regions, boundary }
    }

    /// Walk each regions and call a function
    ///
    /// # Arguments
    /// * `cb` - call back function applied to each region.
    pub fn walk_regions<F>(&self, mut cb: F) -> Result<(), AddressSpaceError>
    where
        F: FnMut(&Arc<AddressSpaceRegion>) -> Result<(), AddressSpaceError>,
    {
        for reg in self.regions.iter() {
            cb(reg)?;
        }

        Ok(())
    }

    /// Insert a new region into address space
    ///
    /// # Arguments
    /// * `region` - created new region to be inserted.
    pub fn insert_region(
        &mut self,
        region: Arc<AddressSpaceRegion>,
    ) -> Result<(), AddressSpaceError> {
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

    /// Get numa node id from region.
    ///
    /// # Arguments
    /// * `gpa` - guest physical address.
    pub fn get_numa_node_id(&self, gpa: u64) -> Option<u32> {
        for reg in self.regions.iter() {
            if gpa >= reg.base.0 && gpa < (reg.base.0 + reg.size) {
                return reg.host_numa_node_id;
            }
        }

        None
    }

    /// Get address space boundary
    pub fn get_boundary(&self) -> AddressSpaceBoundary {
        self.boundary.clone()
    }

    /// Get last valid address from regions
    pub fn get_last_addr(&self) -> GuestAddress {
        let mut last_addr = GuestAddress(self.boundary.mem_start);
        for reg in self.regions.iter() {
            if reg.ty != AddressSpaceRegionType::DAXMemory && reg.last_addr() > last_addr {
                last_addr = reg.last_addr();
            }
        }
        last_addr
    }

    /// Create an empty guest memory mmap.
    pub fn create_guest_memory() -> GuestMemoryMmap {
        GuestMemoryMmap::new()
    }

    #[cfg(not(feature = "atomic-guest-memory"))]
    /// Wrap GuestMemoryMmap with Arc.
    pub fn convert_into_vm_as(gm: GuestMemoryMmap) -> Arc<GuestMemoryMmap> {
        Arc::new(gm)
    }
}

#[cfg(feature = "atomic-guest-memory")]
mod atomic {
    use super::*;
    use arc_swap::ArcSwap;
    use std::sync::Arc;
    use vm_memory::atomic::GuestMemoryAtomic;

    /// Wrapper over `AddressSpaceInternal` to support atomic address space region.
    #[derive(Clone)]
    pub struct AddressSpaceAtomic {
        state: Arc<ArcSwap<AddressSpaceInternal>>,
    }

    impl AddressSpaceAtomic {
        /// Find the region to which the guest_addr belongs, and determine
        /// whether the type of the region is DAXMemory
        ///
        /// # Arguments
        /// * `guest_addr` - the guest physical address you want to inquire
        pub fn is_reserved_region(&self, guest_addr: GuestAddress) -> bool {
            let guard = self.state.load();
            guard.is_reserved_region(guest_addr)
        }

        pub fn from_regions(
            regions: Vec<Arc<AddressSpaceRegion>>,
            boundary: AddressSpaceBoundary,
        ) -> Self {
            let internal = AddressSpaceInternal::from_regions(regions, boundary);

            AddressSpaceAtomic {
                state: Arc::new(ArcSwap::new(Arc::new(internal))),
            }
        }

        pub fn insert_region(
            &mut self,
            region: Arc<AddressSpaceRegion>,
        ) -> Result<(), AddressSpaceError> {
            let curr = self.state.load().regions.clone();
            let boundary = self.state.load().boundary.clone();
            let mut internal = AddressSpaceInternal::from_regions(curr, boundary);
            internal.insert_region(region)?;
            let _old = self.state.swap(Arc::new(internal));

            Ok(())
        }

        pub fn walk_regions<F>(&self, cb: F) -> Result<(), AddressSpaceError>
        where
            F: FnMut(&Arc<AddressSpaceRegion>) -> Result<(), AddressSpaceError>,
        {
            let guard = self.state.load();
            guard.walk_regions(cb)
        }

        pub fn get_numa_node_id(&self, gpa: u64) -> Option<u32> {
            let guard = self.state.load();
            guard.get_numa_node_id(gpa)
        }

        pub fn get_boundary(&self) -> AddressSpaceBoundary {
            self.state.load().get_boundary()
        }

        pub fn get_last_addr(&self) -> GuestAddress {
            self.state.load().get_last_addr()
        }

        pub fn create_guest_memory() -> GuestMemoryMmap {
            AddressSpaceInternal::create_guest_memory()
        }

        pub fn convert_into_vm_as(gm: GuestMemoryMmap) -> GuestMemoryAtomic<GuestMemoryMmap> {
            GuestMemoryAtomic::from(Arc::new(gm))
        }
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
        let boundary = AddressSpaceBoundary::new(GUEST_PHYS_END, GUEST_MEM_START, GUEST_MEM_END);
        let address_space = AddressSpace::from_regions(address_space_region, boundary);

        assert!(!address_space.is_reserved_region(GuestAddress(page_size)));
        assert!(!address_space.is_reserved_region(GuestAddress(page_size * 2)));
        assert!(address_space.is_reserved_region(GuestAddress(page_size * 3)));
        assert!(address_space.is_reserved_region(GuestAddress(page_size * 3 + 1)));
        assert!(!address_space.is_reserved_region(GuestAddress(page_size * 3 + page_size)));
        assert!(address_space.is_reserved_region(GuestAddress(page_size * 3 + page_size - 1)));
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
            false,
            None,
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
        let boundary = AddressSpaceBoundary::new(GUEST_PHYS_END, GUEST_MEM_START, GUEST_MEM_END);
        let address_space = AddressSpaceInternal::from_regions(regions, boundary.clone());
        assert_eq!(address_space.get_boundary(), boundary);
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
        let boundary = AddressSpaceBoundary::new(GUEST_PHYS_END, GUEST_MEM_START, GUEST_MEM_END);
        let _ = AddressSpaceInternal::from_regions(regions, boundary);
    }
}
