// Copyright 2021 Alibaba Cloud. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM boot related constants and utilities for `x86_64` architecture.

use db_arch::gdt::gdt_entry;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};

use self::layout::{BOOT_GDT_ADDRESS, BOOT_GDT_MAX, BOOT_IDT_ADDRESS};

/// Magic addresses externally used to lay out x86_64 VMs.
pub mod layout;

/// Structure definitions for SMP machines following the Intel Multiprocessing Specification 1.1 and 1.4.
pub mod mpspec;

/// MP Table configurations used for defining VM boot status.
pub mod mptable;

/// Initialize the 1:1 identity mapping table for guest memory range [0..1G).
pub fn setup_identity_mapping<M: GuestMemory>(mem: &M) -> Result<(), vm_memory::GuestMemoryError> {
    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = GuestAddress(layout::PML4_START);
    let boot_pdpte_addr = GuestAddress(layout::PDPTE_START);
    let boot_pde_addr = GuestAddress(layout::PDE_START);

    // Entry covering VA [0..512GB)
    mem.write_obj(boot_pdpte_addr.raw_value() as u64 | 0x03, boot_pml4_addr)?;

    // Entry covering VA [0..1GB)
    mem.write_obj(boot_pde_addr.raw_value() as u64 | 0x03, boot_pdpte_addr)?;

    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512 {
        mem.write_obj((i << 21) + 0x83u64, boot_pde_addr.unchecked_add(i * 8))?;
    }

    Ok(())
}

/// Get information to configure GDT/IDT.
pub fn get_descriptor_config_info() -> ([u64; BOOT_GDT_MAX], u64, u64) {
    let gdt_table: [u64; BOOT_GDT_MAX as usize] = [
        gdt_entry(0, 0, 0),            // NULL
        gdt_entry(0xa09b, 0, 0xfffff), // CODE
        gdt_entry(0xc093, 0, 0xfffff), // DATA
        gdt_entry(0x808b, 0, 0xfffff), // TSS
    ];

    (gdt_table, BOOT_GDT_ADDRESS, BOOT_IDT_ADDRESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{PDE_START, PDPTE_START, PML4_START};
    use vm_memory::GuestMemoryMmap;

    fn read_u64(gm: &GuestMemoryMmap, offset: u64) -> u64 {
        let read_addr = GuestAddress(offset as u64);
        gm.read_obj(read_addr).unwrap()
    }

    #[test]
    fn test_get_descriptor_config_info() {
        let (gdt_table, gdt_addr, idt_addr) = get_descriptor_config_info();

        assert_eq!(gdt_table.len(), BOOT_GDT_MAX);
        assert_eq!(gdt_addr, BOOT_GDT_ADDRESS);
        assert_eq!(idt_addr, BOOT_IDT_ADDRESS);
    }

    #[test]
    fn test_setup_identity_mapping() {
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        setup_identity_mapping(&gm).unwrap();
        assert_eq!(0xa003, read_u64(&gm, PML4_START));
        assert_eq!(0xb003, read_u64(&gm, PDPTE_START));
        for i in 0..512 {
            assert_eq!((i << 21) + 0x83u64, read_u64(&gm, PDE_START + (i * 8)));
        }
    }
}
