# db-address-space

## Design

The db-address-space crate is an address space manager for virtual machines, which manages memory and MMIO resources resident in the guest physical address space.

```rust
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
```
AddressSpaceRegion is used to describe information about a region in the address space of guest memory, including type, base address, resgion size, and other corresponding arrtibutes.


## Usage
```rust
let reg = Arc::new(
    AddressSpaceRegion::create_device_region(GuestAddress(0x100000), 0x1000).unwrap(),
);
let regions = vec![reg];
let boundary = AddressSpaceBoundary::new(GUEST_PHYS_END, GUEST_MEM_START, GUEST_MEM_END);
let address_space = AddressSpaceInternal::from_regions(regions, boundary.clone());
assert_eq!(address_space.get_boundary(), boundary);
```

## License

This project is licensed under [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0.
