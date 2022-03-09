// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use std::sync::atomic::Ordering;

use nix::sys::memfd;
use vm_memory::{
    Address, AtomicAccess, Bytes, FileOffset, GuestAddress, GuestMemoryError, GuestMemoryRegion,
    GuestUsize, MemoryRegionAddress,
};

use crate::AddressSpaceError;

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
    pub ty: AddressSpaceRegionType,
    /// Base address of the region in virtual machine's physical address space.
    pub base: GuestAddress,
    /// Size of the address space region.
    pub size: GuestUsize,
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
    pub(crate) host_numa_node_id: Option<u32>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_sys_util::tempfile::TempFile;

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
}
