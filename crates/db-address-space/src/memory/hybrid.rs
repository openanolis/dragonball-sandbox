// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use vm_memory::bitmap::{Bitmap, BS};
use vm_memory::guest_memory::GuestMemoryIterator;
use vm_memory::mmap::{Error, NewBitmap};
use vm_memory::{
    guest_memory, AtomicAccess, Bytes, FileOffset, GuestAddress, GuestMemory, GuestMemoryRegion,
    GuestRegionMmap, GuestUsize, MemoryRegionAddress, VolatileSlice,
};

/// An adapter for different concrete implementations of `GuestMemoryRegion`.
#[derive(Debug)]
pub enum GuestRegionHybrid<B = ()> {
    /// Region of type `GuestRegionMmap`.
    Mmap(GuestRegionMmap<B>),
}

impl<B: Bitmap> GuestRegionHybrid<B> {
    /// Create a `GuestRegionHybrid` object from `GuestRegionMmap` object.
    pub fn from_mmap_region(region: GuestRegionMmap<B>) -> Self {
        GuestRegionHybrid::Mmap(region)
    }
}

impl<B: Bitmap> Bytes<MemoryRegionAddress> for GuestRegionHybrid<B> {
    type E = guest_memory::Error;

    fn write(&self, buf: &[u8], addr: MemoryRegionAddress) -> guest_memory::Result<usize> {
        match self {
            GuestRegionHybrid::Mmap(region) => region.write(buf, addr),
        }
    }

    fn read(&self, buf: &mut [u8], addr: MemoryRegionAddress) -> guest_memory::Result<usize> {
        match self {
            GuestRegionHybrid::Mmap(region) => region.read(buf, addr),
        }
    }

    fn write_slice(&self, buf: &[u8], addr: MemoryRegionAddress) -> guest_memory::Result<()> {
        match self {
            GuestRegionHybrid::Mmap(region) => region.write_slice(buf, addr),
        }
    }

    fn read_slice(&self, buf: &mut [u8], addr: MemoryRegionAddress) -> guest_memory::Result<()> {
        match self {
            GuestRegionHybrid::Mmap(region) => region.read_slice(buf, addr),
        }
    }

    fn read_from<F>(
        &self,
        addr: MemoryRegionAddress,
        src: &mut F,
        count: usize,
    ) -> guest_memory::Result<usize>
    where
        F: Read,
    {
        match self {
            GuestRegionHybrid::Mmap(region) => region.read_from(addr, src, count),
        }
    }

    fn read_exact_from<F>(
        &self,
        addr: MemoryRegionAddress,
        src: &mut F,
        count: usize,
    ) -> guest_memory::Result<()>
    where
        F: Read,
    {
        match self {
            GuestRegionHybrid::Mmap(region) => region.read_exact_from(addr, src, count),
        }
    }

    fn write_to<F>(
        &self,
        addr: MemoryRegionAddress,
        dst: &mut F,
        count: usize,
    ) -> guest_memory::Result<usize>
    where
        F: Write,
    {
        match self {
            GuestRegionHybrid::Mmap(region) => region.write_to(addr, dst, count),
        }
    }

    fn write_all_to<F>(
        &self,
        addr: MemoryRegionAddress,
        dst: &mut F,
        count: usize,
    ) -> guest_memory::Result<()>
    where
        F: Write,
    {
        match self {
            GuestRegionHybrid::Mmap(region) => region.write_all_to(addr, dst, count),
        }
    }

    fn store<T: AtomicAccess>(
        &self,
        val: T,
        addr: MemoryRegionAddress,
        order: Ordering,
    ) -> guest_memory::Result<()> {
        match self {
            GuestRegionHybrid::Mmap(region) => region.store(val, addr, order),
        }
    }

    fn load<T: AtomicAccess>(
        &self,
        addr: MemoryRegionAddress,
        order: Ordering,
    ) -> guest_memory::Result<T> {
        match self {
            GuestRegionHybrid::Mmap(region) => region.load(addr, order),
        }
    }
}

impl<B: Bitmap> GuestMemoryRegion for GuestRegionHybrid<B> {
    type B = B;

    fn len(&self) -> GuestUsize {
        match self {
            GuestRegionHybrid::Mmap(region) => region.len(),
        }
    }

    fn start_addr(&self) -> GuestAddress {
        match self {
            GuestRegionHybrid::Mmap(region) => region.start_addr(),
        }
    }

    fn bitmap(&self) -> &Self::B {
        match self {
            GuestRegionHybrid::Mmap(region) => region.bitmap(),
        }
    }

    fn get_host_address(&self, addr: MemoryRegionAddress) -> guest_memory::Result<*mut u8> {
        match self {
            GuestRegionHybrid::Mmap(region) => region.get_host_address(addr),
        }
    }

    fn file_offset(&self) -> Option<&FileOffset> {
        match self {
            GuestRegionHybrid::Mmap(region) => region.file_offset(),
        }
    }

    unsafe fn as_slice(&self) -> Option<&[u8]> {
        match self {
            GuestRegionHybrid::Mmap(region) => region.as_slice(),
        }
    }

    unsafe fn as_mut_slice(&self) -> Option<&mut [u8]> {
        match self {
            GuestRegionHybrid::Mmap(region) => region.as_mut_slice(),
        }
    }

    fn get_slice(
        &self,
        offset: MemoryRegionAddress,
        count: usize,
    ) -> guest_memory::Result<VolatileSlice<BS<B>>> {
        match self {
            GuestRegionHybrid::Mmap(region) => region.get_slice(offset, count),
        }
    }

    #[cfg(target_os = "linux")]
    fn is_hugetlbfs(&self) -> Option<bool> {
        match self {
            GuestRegionHybrid::Mmap(region) => region.is_hugetlbfs(),
        }
    }
}

/// [`GuestMemory`](trait.GuestMemory.html) implementation that manage hybrid types of guest memory
/// regions.
///
/// Represents the entire physical memory of the guest by tracking all its memory regions.
/// Each region is an instance of `GuestRegionHybrid`.
#[derive(Clone, Debug, Default)]
pub struct GuestMemoryHybrid<B = ()> {
    regions: Vec<Arc<GuestRegionHybrid<B>>>,
}

impl<B: NewBitmap> GuestMemoryHybrid<B> {
    /// Creates an empty `GuestMemoryHybrid` instance.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<B: Bitmap> GuestMemoryHybrid<B> {
    /// Creates a new `GuestMemoryHybrid` from a vector of regions.
    ///
    /// # Arguments
    ///
    /// * `regions` - The vector of regions.
    ///               The regions shouldn't overlap and they should be sorted
    ///               by the starting address.
    pub fn from_regions(mut regions: Vec<GuestRegionHybrid<B>>) -> Result<Self, Error> {
        Self::from_arc_regions(regions.drain(..).map(Arc::new).collect())
    }

    /// Creates a new `GuestMemoryHybrid` from a vector of Arc regions.
    ///
    /// Similar to the constructor `from_regions()` as it returns a
    /// `GuestMemoryHybrid`. The need for this constructor is to provide a way for
    /// consumer of this API to create a new `GuestMemoryHybrid` based on existing
    /// regions coming from an existing `GuestMemoryHybrid` instance.
    ///
    /// # Arguments
    ///
    /// * `regions` - The vector of `Arc` regions.
    ///               The regions shouldn't overlap and they should be sorted
    ///               by the starting address.
    pub fn from_arc_regions(regions: Vec<Arc<GuestRegionHybrid<B>>>) -> Result<Self, Error> {
        if regions.is_empty() {
            return Err(Error::NoMemoryRegion);
        }

        for window in regions.windows(2) {
            let prev = &window[0];
            let next = &window[1];

            if prev.start_addr() > next.start_addr() {
                return Err(Error::UnsortedMemoryRegions);
            }

            if prev.last_addr() >= next.start_addr() {
                return Err(Error::MemoryRegionOverlap);
            }
        }

        Ok(Self { regions })
    }

    /// Insert a region into the `GuestMemoryHybrid` object and return a new `GuestMemoryHybrid`.
    ///
    /// # Arguments
    /// * `region`: the memory region to insert into the guest memory object.
    pub fn insert_region(
        &self,
        region: Arc<GuestRegionHybrid<B>>,
    ) -> Result<GuestMemoryHybrid<B>, Error> {
        let mut regions = self.regions.clone();
        regions.push(region);
        regions.sort_by_key(|x| x.start_addr());

        Self::from_arc_regions(regions)
    }

    /// Remove a region into the `GuestMemoryHybrid` object and return a new `GuestMemoryHybrid`
    /// on success, together with the removed region.
    ///
    /// # Arguments
    /// * `base`: base address of the region to be removed
    /// * `size`: size of the region to be removed
    pub fn remove_region(
        &self,
        base: GuestAddress,
        size: GuestUsize,
    ) -> Result<(GuestMemoryHybrid<B>, Arc<GuestRegionHybrid<B>>), Error> {
        if let Ok(region_index) = self.regions.binary_search_by_key(&base, |x| x.start_addr()) {
            if self.regions.get(region_index).unwrap().len() as GuestUsize == size {
                let mut regions = self.regions.clone();
                let region = regions.remove(region_index);
                return Ok((Self { regions }, region));
            }
        }

        Err(Error::InvalidGuestRegion)
    }
}

/// An iterator over the elements of `GuestMemoryHybrid`.
///
/// This struct is created by `GuestMemory::iter()`. See its documentation for more.
pub struct Iter<'a, B>(std::slice::Iter<'a, Arc<GuestRegionHybrid<B>>>);

impl<'a, B> Iterator for Iter<'a, B> {
    type Item = &'a GuestRegionHybrid<B>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(AsRef::as_ref)
    }
}

impl<'a, B: 'a> GuestMemoryIterator<'a, GuestRegionHybrid<B>> for GuestMemoryHybrid<B> {
    type Iter = Iter<'a, B>;
}

impl<B: Bitmap + 'static> GuestMemory for GuestMemoryHybrid<B> {
    type R = GuestRegionHybrid<B>;

    type I = Self;

    fn num_regions(&self) -> usize {
        self.regions.len()
    }

    fn find_region(&self, addr: GuestAddress) -> Option<&GuestRegionHybrid<B>> {
        let index = match self.regions.binary_search_by_key(&addr, |x| x.start_addr()) {
            Ok(x) => Some(x),
            // Within the closest region with starting address < addr
            Err(x) if (x > 0 && addr <= self.regions[x - 1].last_addr()) => Some(x - 1),
            _ => None,
        };
        index.map(|x| self.regions[x].as_ref())
    }

    fn iter(&self) -> Iter<B> {
        Iter(self.regions.iter())
    }
}
