// Copyright 2022 Alibaba Cloud. All Rights Reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
#![cfg(target_arch = "x86_64")]
use std::{mem, result};

use dbs_address_space::AddressSpace;
use dbs_boot::{
    add_e820_entry,
    bootparam::{boot_params, E820_RAM},
    layout, BootParamsWrapper,
};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

// x86_64 boot constants. See https://www.kernel.org/doc/Documentation/x86/boot.txt for the full
// documentation.
// Header field: `boot_flag`. Must contain 0xaa55. This is the closest thing old Linux kernels
// have to a magic number.
const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
// Header field: `header`. Must contain the magic number `HdrS` (0x5372_6448).
const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
// Header field: `type_of_loader`. Unless using a pre-registered bootloader (which we aren't), this
// field must be set to 0xff.
const KERNEL_LOADER_OTHER: u8 = 0xff;
// Header field: `kernel_alignment`. Alignment unit required by a relocatable kernel.
const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
/// Errors pertaining to boot parameter setup.
pub enum Error {
    /// Empty AddressSpace from parameters.
    #[error("Empty AddressSpace from parameters")]
    AddressSpace,

    /// Highmem start address is past the guest memory end.
    #[error("Highmem start address is past the guest memory end.")]
    HimemStartPastMemEnd,

    /// Highmem start address is past the MMIO gap start.
    #[error("Highmem start address is past the MMIO gap start.")]
    HimemStartPastMmioGapStart,

    /// The MMIO gap end is past the guest memory end.
    #[error("The MMIO gap end is past the guest memory end.")]
    MmioGapPastMemEnd,

    /// The MMIO gap start is past the gap end.
    #[error("The MMIO gap start is past the gap end.")]
    MmioGapStartPastMmioGapEnd,

    /// Fail to boot system
    #[error("failed to boot system: {0}")]
    BootSystem(#[source] dbs_boot::Error),

    /// The zero page extends past the end of guest_mem.
    #[error("the guest zero page extends past the end of guest memory")]
    ZeroPagePastRamEnd,

    /// Error writing the zero page of guest memory.
    #[error("failed to write to guest zero page")]
    ZeroPageSetup,
}

/// Build boot parameters for ELF kernels following the Linux boot protocol.
///
/// # Arguments
///
/// * `guest_memory` - guest memory.
/// * `address_space` - address space.
/// * `himem_start` - address where high memory starts.
/// * `mmio_gap_start` - address where the MMIO gap starts.
/// * `mmio_gap_end` - address where the MMIO gap ends.
/// * `cmdline_addr` - Address in `guest_mem` where the kernel command line was
///   loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the
///   null terminator.
pub fn build_bootparams(
    guest_memory: &GuestMemoryMmap,
    address_space: &AddressSpace,
    himem_start: GuestAddress,
    mmio_gap_start: GuestAddress,
    mmio_gap_end: GuestAddress,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
) -> result::Result<(), Error> {
    if mmio_gap_start >= mmio_gap_end {
        return Err(Error::MmioGapStartPastMmioGapEnd);
    }

    let mut boot_params: BootParamsWrapper = BootParamsWrapper(boot_params::default());

    boot_params.0.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    boot_params.0.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    boot_params.0.hdr.header = KERNEL_HDR_MAGIC;
    boot_params.0.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;

    // Add the kernel command line to the boot parameters.
    boot_params.0.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
    boot_params.0.hdr.cmdline_size = cmdline_size as u32;

    // Add an entry for EBDA itself.
    add_e820_entry(&mut boot_params.0, 0, layout::EBDA_START, E820_RAM)
        .map_err(Error::BootSystem)?;

    // Add entries for the usable RAM regions (potentially surrounding the MMIO gap).
    let last_addr = address_space.last_addr();
    if last_addr < mmio_gap_start {
        add_e820_entry(
            &mut boot_params.0,
            himem_start.raw_value(),
            // The unchecked + 1 is safe because:
            // * overflow could only occur if last_addr - himem_start == u64::MAX
            // * last_addr is smaller than mmio_gap_start, a valid u64 value
            // * last_addr - himem_start is also smaller than mmio_gap_start
            last_addr
                .checked_offset_from(himem_start)
                .ok_or(Error::HimemStartPastMemEnd)? as u64
                + 1,
            E820_RAM,
        )
        .map_err(Error::BootSystem)?;
    } else {
        add_e820_entry(
            &mut boot_params.0,
            himem_start.raw_value(),
            mmio_gap_start
                .checked_offset_from(himem_start)
                .ok_or(Error::HimemStartPastMmioGapStart)?,
            E820_RAM,
        )
        .map_err(Error::BootSystem)?;

        if last_addr > mmio_gap_end {
            add_e820_entry(
                &mut boot_params.0,
                mmio_gap_end.raw_value() + 1,
                // The unchecked_offset_from is safe, guaranteed by the `if` condition above.
                // The unchecked + 1 is safe because:
                // * overflow could only occur if last_addr == u64::MAX and mmio_gap_end == 0
                // * mmio_gap_end > mmio_gap_start, which is a valid u64 => mmio_gap_end > 0
                last_addr.unchecked_offset_from(mmio_gap_end) as u64 + 1,
                E820_RAM,
            )
            .map_err(Error::BootSystem)?;
        }
    }

    // Write the boot parameters in the zeropage.
    let zero_page_addr = GuestAddress(layout::ZERO_PAGE_START);
    guest_memory
        .checked_offset(zero_page_addr, mem::size_of::<boot_params>())
        .ok_or(Error::ZeroPagePastRamEnd)?;
    guest_memory
        .write_obj(boot_params, zero_page_addr)
        .map_err(|_| Error::ZeroPageSetup)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::KernelConfig;
    use dbs_address_space::{AddressSpace, AddressSpaceLayout, AddressSpaceRegion};
    use dbs_boot::layout;
    use std::sync::Arc;

    fn create_address_space(base: GuestAddress, size: u64) -> Result<AddressSpace, Error> {
        // create several memory regions
        let reg = Arc::new(
            AddressSpaceRegion::create_default_memory_region(
                base, size, None, "shmem", "", false, false,
            )
            .unwrap(),
        );
        let regions = vec![reg];

        // create layout (depending on archs)
        let layout = AddressSpaceLayout::new(
            *layout::GUEST_PHYS_END,
            layout::GUEST_MEM_START,
            *layout::GUEST_MEM_END,
        );

        // create address space from regions and layout
        let address_space = AddressSpace::from_regions(regions, layout);

        Ok(address_space)
    }

    #[test]
    fn test_build_bootparams() {
        let guest_memory = GuestMemoryMmap::default();
        let address_space = create_address_space(GuestAddress(0), 1024).unwrap();
        let kernel_cfg = KernelConfig::default();
        let cmdline_addr = layout::CMDLINE_START;

        // Error case: MMIO gap start address is past its end address.
        assert_eq!(
            build_bootparams(
                &guest_memory,
                &address_space,
                GuestAddress(layout::HIMEM_START),
                GuestAddress(layout::MMIO_LOW_START),
                GuestAddress(layout::MMIO_LOW_START - 1),
                GuestAddress(cmdline_addr),
                (kernel_cfg.cmdline.as_str().len() + 1) as usize,
            )
            .err(),
            Some(Error::MmioGapStartPastMmioGapEnd)
        );

        // Error case: high memory starts after guest memory ends.
        let guest_memory =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), layout::HIMEM_START as usize - 1)])
                .unwrap();
        let address_space = create_address_space(GuestAddress(0), 1024).unwrap();
        assert_eq!(
            build_bootparams(
                &guest_memory,
                &address_space,
                GuestAddress(layout::HIMEM_START),
                GuestAddress(layout::MMIO_LOW_START),
                GuestAddress(layout::MMIO_LOW_END),
                GuestAddress(cmdline_addr),
                (kernel_cfg.cmdline.as_str().len() + 1) as usize,
            )
            .err(),
            Some(Error::HimemStartPastMemEnd)
        );

        // Error case: MMIO gap starts before high memory.
        let guest_memory = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), layout::MMIO_LOW_START as usize),
            (GuestAddress(layout::MMIO_LOW_END), 0x1000),
        ])
        .unwrap();
        let address_space =
            create_address_space(GuestAddress(layout::MMIO_LOW_START), 1024).unwrap();
        assert_eq!(
            build_bootparams(
                &guest_memory,
                &address_space,
                GuestAddress(layout::MMIO_LOW_START + 1),
                GuestAddress(layout::MMIO_LOW_START),
                GuestAddress(layout::MMIO_LOW_END),
                GuestAddress(cmdline_addr),
                (kernel_cfg.cmdline.as_str().len() + 1) as usize,
            )
            .err(),
            Some(Error::HimemStartPastMmioGapStart)
        );

        // Success case: 1 range preceding the MMIO gap.
        // Let's skip the setup header this time.
        let guest_memory =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), layout::MMIO_LOW_START as usize)])
                .unwrap();
        let address_space = create_address_space(GuestAddress(layout::HIMEM_START), 1024).unwrap();
        assert!(build_bootparams(
            &guest_memory,
            &address_space,
            GuestAddress(layout::HIMEM_START),
            GuestAddress(layout::MMIO_LOW_START),
            GuestAddress(layout::MMIO_LOW_END),
            GuestAddress(cmdline_addr),
            (kernel_cfg.cmdline.as_str().len() + 1) as usize,
        )
        .is_ok());
    }
}
