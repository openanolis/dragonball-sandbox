// Copyright 2019 Alibaba Cloud. All Rights Reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::{kvm_cpuid_entry2, CpuId};

use super::*;
use crate::cpuid::bit_helper::BitHelper;
use crate::cpuid::common::get_cpuid;
use crate::cpuid::transformer::Error::FamError;

// constants for setting the fields of kvm_cpuid2 structures
// CPUID bits in ebx, ecx, and edx.
const EBX_CLFLUSH_CACHELINE: u32 = 8; // Flush a cache line size.

pub fn update_feature_info_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpuid::cpu_leaf::leaf_0x1::*;

    // X86 hypervisor feature
    entry
        .ecx
        .write_bit(ecx::TSC_DEADLINE_TIMER_BITINDEX, true)
        .write_bit(ecx::HYPERVISOR_BITINDEX, true);

    entry
        .ebx
        .write_bits_in_range(&ebx::APICID_BITRANGE, u32::from(vm_spec.cpu_id))
        .write_bits_in_range(&ebx::CLFLUSH_SIZE_BITRANGE, EBX_CLFLUSH_CACHELINE)
        .write_bits_in_range(
            &ebx::CPU_COUNT_BITRANGE,
            u32::from(vm_spec.threads_per_core * vm_spec.cores_per_die * vm_spec.dies_per_socket),
        );

    // A value of 1 for HTT indicates the value in CPUID.1.Ebx[23:16]
    // (the Maximum number of addressable IDs for logical processors in this package)
    // is valid for the package
    entry
        .edx
        .write_bit(edx::HTT_BITINDEX, vm_spec.cpu_count > 1);

    Ok(())
}

pub fn update_extended_topology_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpuid::cpu_leaf::leaf_0xb::*;
    let thread_width = 8 - (vm_spec.threads_per_core - 1).leading_zeros();
    let core_width = (8 - (vm_spec.cores_per_die - 1).leading_zeros()) + thread_width;

    //reset eax, ebx, ecx
    entry.eax = 0_u32;
    entry.ebx = 0_u32;
    entry.ecx = 0_u32;
    // EDX bits 31..0 contain x2APIC ID of current logical processor
    // x2APIC increases the size of the APIC ID from 8 bits to 32 bits
    entry.edx = u32::from(vm_spec.cpu_id);
    match entry.index {
        // Thread Level Topology; index = 0
        0 => {
            // To get the next level APIC ID, shift right with at most 1 because we have
            // maximum 2 hyperthreads per core that can be represented by 1 bit.
            entry
                .eax
                .write_bits_in_range(&eax::APICID_BITRANGE, thread_width as u32);
            // When cpu_count == 1 or HT is disabled, there is 1 logical core at this level
            // Otherwise there are 2
            entry.ebx.write_bits_in_range(
                &ebx::NUM_LOGICAL_PROCESSORS_BITRANGE,
                vm_spec.threads_per_core as u32,
            );

            entry
                .ecx
                .write_bits_in_range(&ecx::LEVEL_TYPE_BITRANGE, LEVEL_TYPE_THREAD);
        }
        // Core Level Processor Topology; index = 1
        1 => {
            entry
                .eax
                .write_bits_in_range(&eax::APICID_BITRANGE, core_width as u32);
            entry
                .ecx
                .write_bits_in_range(&ecx::LEVEL_NUMBER_BITRANGE, entry.index as u32);
            entry.ebx.write_bits_in_range(
                &ebx::NUM_LOGICAL_PROCESSORS_BITRANGE,
                u32::from(vm_spec.threads_per_core * vm_spec.cores_per_die),
            );
            entry
                .ecx
                .write_bits_in_range(&ecx::LEVEL_TYPE_BITRANGE, LEVEL_TYPE_CORE);
        }
        // Core Level Processor Topology; index >=2
        // No other levels available; This should already be set to correctly,
        // and it is added here as a "re-enforcement" in case we run on
        // different hardware
        level => {
            entry.ecx = level;
        }
    }

    Ok(())
}

/// leaf_0x1f is a superset of leaf_0xb. It gives extra information like die_per_socket.
/// If leaf_0x1f is not implemented in cpu used in host, we'll turn to leaf_0xb to determine the cpu topology.
pub fn update_extended_topology_v2_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpuid::cpu_leaf::leaf_0x1f::*;
    let thread_width = 8 - (vm_spec.threads_per_core - 1).leading_zeros();
    let core_width = (8 - (vm_spec.cores_per_die - 1).leading_zeros()) + thread_width;
    let die_width = (8 - (vm_spec.dies_per_socket - 1).leading_zeros()) + core_width;

    //reset eax, ebx, ecx
    entry.eax = 0_u32;
    entry.ebx = 0_u32;
    entry.ecx = 0_u32;
    // EDX bits 31..0 contain x2APIC ID of current logical processor
    // x2APIC increases the size of the APIC ID from 8 bits to 32 bits
    entry.edx = u32::from(vm_spec.cpu_id);
    match entry.index {
        // Thread Level Topology; index = 0
        0 => {
            // To get the next level APIC ID, shift right with at most 1 because we have
            // maximum 2 hyperthreads per core that can be represented by 1 bit.
            entry
                .eax
                .write_bits_in_range(&eax::APICID_BITRANGE, thread_width as u32);
            // When cpu_count == 1 or HT is disabled, there is 1 logical core at this level
            // Otherwise there are 2
            entry.ebx.write_bits_in_range(
                &ebx::NUM_LOGICAL_PROCESSORS_BITRANGE,
                vm_spec.threads_per_core as u32,
            );

            entry
                .ecx
                .write_bits_in_range(&ecx::LEVEL_TYPE_BITRANGE, LEVEL_TYPE_THREAD);
        }
        // Core Level Processor Topology; index = 1
        1 => {
            entry
                .eax
                .write_bits_in_range(&eax::APICID_BITRANGE, core_width as u32);
            entry
                .ecx
                .write_bits_in_range(&ecx::LEVEL_NUMBER_BITRANGE, entry.index as u32);
            entry.ebx.write_bits_in_range(
                &ebx::NUM_LOGICAL_PROCESSORS_BITRANGE,
                u32::from(vm_spec.threads_per_core * vm_spec.cores_per_die),
            );
            entry
                .ecx
                .write_bits_in_range(&ecx::LEVEL_TYPE_BITRANGE, LEVEL_TYPE_CORE);
        }
        // Die Level Processor Topology; index = 5
        5 => {
            entry
                .eax
                .write_bits_in_range(&eax::APICID_BITRANGE, die_width as u32);
            entry
                .ecx
                .write_bits_in_range(&ecx::LEVEL_NUMBER_BITRANGE, entry.index as u32);
            entry.ebx.write_bits_in_range(
                &ebx::NUM_LOGICAL_PROCESSORS_BITRANGE,
                u32::from(
                    vm_spec.threads_per_core * vm_spec.cores_per_die * vm_spec.dies_per_socket,
                ),
            );
            entry
                .ecx
                .write_bits_in_range(&ecx::LEVEL_TYPE_BITRANGE, LEVEL_TYPE_DIE);
        }
        level => {
            entry.ecx = level;
        }
    }

    Ok(())
}

pub fn update_brand_string_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    let brand_string = &vm_spec.brand_string;
    entry.eax = brand_string.get_reg_for_leaf(entry.function, BsReg::Eax);
    entry.ebx = brand_string.get_reg_for_leaf(entry.function, BsReg::Ebx);
    entry.ecx = brand_string.get_reg_for_leaf(entry.function, BsReg::Ecx);
    entry.edx = brand_string.get_reg_for_leaf(entry.function, BsReg::Edx);

    Ok(())
}

pub fn update_cache_parameters_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpuid::cpu_leaf::leaf_cache_parameters::*;

    match entry.eax.read_bits_in_range(&eax::CACHE_LEVEL_BITRANGE) {
        // L1 & L2 Cache
        1 | 2 => {
            // The L1 & L2 cache is shared by at most 2 hyperthreads
            entry.eax.write_bits_in_range(
                &eax::MAX_CPUS_PER_CORE_BITRANGE,
                (vm_spec.cpu_count > 1 && vm_spec.threads_per_core == 2) as u32,
            );
        }
        // L3 Cache
        3 => {
            // The L3 cache is shared among all the logical threads
            entry.eax.write_bits_in_range(
                &eax::MAX_CPUS_PER_CORE_BITRANGE,
                u32::from(vm_spec.cpu_count - 1),
            );
        }
        _ => (),
    }

    Ok(())
}

/// Replaces the `cpuid` entries corresponding to `function` with the entries from the host's cpuid.
pub fn use_host_cpuid_function(
    cpuid: &mut CpuId,
    function: u32,
    use_count: bool,
) -> Result<(), Error> {
    // copy all the CpuId entries, except for the ones with the provided function
    cpuid.retain(|entry| entry.function != function);

    // add all the host leaves with the provided function
    let mut count: u32 = 0;
    while let Ok(entry) = get_cpuid(function, count) {
        if count > 0 && !use_count {
            break;
        }

        cpuid
            .push(kvm_cpuid_entry2 {
                function,
                index: count,
                flags: 0,
                eax: entry.eax,
                ebx: entry.ebx,
                ecx: entry.ecx,
                edx: entry.edx,
                padding: [0, 0, 0],
            })
            .map_err(FamError)?;

        count += 1;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use kvm_bindings::kvm_cpuid_entry2;

    use super::*;
    use crate::cpuid::common::tests::get_topoext_fn;
    use crate::cpuid::cpu_leaf::leaf_0x1f::LEVEL_TYPE_DIE;
    use crate::cpuid::cpu_leaf::leaf_0xb::LEVEL_TYPE_CORE;
    use crate::cpuid::cpu_leaf::leaf_0xb::LEVEL_TYPE_THREAD;
    use crate::cpuid::transformer::VmSpec;

    fn check_update_feature_info_entry(
        cpu_count: u8,
        expected_htt: bool,
        threads_per_core: u8,
        cores_per_die: u8,
        dies_per_socket: u8,
    ) {
        use crate::cpuid::cpu_leaf::leaf_0x1::*;

        let vm_spec = VmSpec::new(
            0,
            cpu_count,
            threads_per_core,
            cores_per_die,
            dies_per_socket,
            VpmuFeatureLevel::Disabled,
        )
        .expect("Error creating vm_spec");
        let entry = &mut kvm_cpuid_entry2 {
            function: 0x0,
            index: 0,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };

        assert!(update_feature_info_entry(entry, &vm_spec).is_ok());

        assert!(entry.edx.read_bit(edx::HTT_BITINDEX) == expected_htt);
        assert!(entry.ecx.read_bit(ecx::TSC_DEADLINE_TIMER_BITINDEX));
    }

    fn check_update_cache_parameters_entry(
        cpu_count: u8,
        cache_level: u32,
        expected_max_cpus_per_core: u32,
        threads_per_core: u8,
        cores_per_die: u8,
        dies_per_socket: u8,
    ) {
        use crate::cpuid::cpu_leaf::leaf_cache_parameters::*;

        let vm_spec = VmSpec::new(
            0,
            cpu_count,
            threads_per_core,
            cores_per_die,
            dies_per_socket,
            VpmuFeatureLevel::Disabled,
        )
        .expect("Error creating vm_spec");
        let entry = &mut kvm_cpuid_entry2 {
            function: 0x0,
            index: 0,
            flags: 0,
            eax: *(0_u32).write_bits_in_range(&eax::CACHE_LEVEL_BITRANGE, cache_level),
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };

        assert!(update_cache_parameters_entry(entry, &vm_spec).is_ok());

        assert!(
            entry
                .eax
                .read_bits_in_range(&eax::MAX_CPUS_PER_CORE_BITRANGE)
                == expected_max_cpus_per_core
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn check_update_extended_topology_entry(
        cpu_count: u8,
        index: u32,
        expected_apicid_shift_bit: u32,
        expected_num_logical_processors: u32,
        expected_level_type: u32,
        threads_per_core: u8,
        cores_per_die: u8,
        dies_per_socket: u8,
    ) {
        use crate::cpuid::cpu_leaf::leaf_0xb::*;

        let vm_spec = VmSpec::new(
            0,
            cpu_count,
            threads_per_core,
            cores_per_die,
            dies_per_socket,
            VpmuFeatureLevel::Disabled,
        )
        .expect("Error creating vm_spec");
        let entry = &mut kvm_cpuid_entry2 {
            function: 0x0,
            index,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };

        assert!(update_extended_topology_entry(entry, &vm_spec).is_ok());

        assert!(entry.eax.read_bits_in_range(&eax::APICID_BITRANGE) == expected_apicid_shift_bit);
        assert!(
            entry
                .ebx
                .read_bits_in_range(&ebx::NUM_LOGICAL_PROCESSORS_BITRANGE)
                == expected_num_logical_processors
        );
        assert!(entry.ecx.read_bits_in_range(&ecx::LEVEL_TYPE_BITRANGE) == expected_level_type);
        assert!(entry.ecx.read_bits_in_range(&ecx::LEVEL_NUMBER_BITRANGE) == index);
    }

    #[allow(clippy::too_many_arguments)]
    fn check_update_extended_topology_v2_entry(
        cpu_count: u8,
        index: u32,
        expected_apicid_shift_bit: u32,
        expected_num_logical_processors: u32,
        expected_level_type: u32,
        threads_per_core: u8,
        cores_per_die: u8,
        dies_per_socket: u8,
    ) {
        use crate::cpuid::cpu_leaf::leaf_0x1f::*;

        let vm_spec = VmSpec::new(
            0,
            cpu_count,
            threads_per_core,
            cores_per_die,
            dies_per_socket,
            VpmuFeatureLevel::Disabled,
        )
        .expect("Error creating vm_spec");
        let entry = &mut kvm_cpuid_entry2 {
            function: 0x0,
            index,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };

        assert!(update_extended_topology_v2_entry(entry, &vm_spec).is_ok());

        assert!(entry.eax.read_bits_in_range(&eax::APICID_BITRANGE) == expected_apicid_shift_bit);
        assert!(
            entry
                .ebx
                .read_bits_in_range(&ebx::NUM_LOGICAL_PROCESSORS_BITRANGE)
                == expected_num_logical_processors
        );
        assert!(entry.ecx.read_bits_in_range(&ecx::LEVEL_TYPE_BITRANGE) == expected_level_type);
        assert!(entry.ecx.read_bits_in_range(&ecx::LEVEL_NUMBER_BITRANGE) == index);
    }

    #[test]
    fn test_1vcpu_ht_off() {
        check_update_feature_info_entry(1, false, 1, 1, 1);

        // test update_deterministic_cache_entry
        // test L1
        check_update_cache_parameters_entry(1, 1, 0, 1, 1, 1);
        // test L2
        check_update_cache_parameters_entry(1, 2, 0, 1, 1, 1);
        // test L3
        check_update_cache_parameters_entry(1, 3, 0, 1, 1, 1);

        // test update_extended_topology_entry
        // index 0
        check_update_extended_topology_entry(1, 0, 0, 1, LEVEL_TYPE_THREAD, 1, 1, 1);
        check_update_extended_topology_v2_entry(1, 0, 0, 1, LEVEL_TYPE_THREAD, 1, 1, 1);
        // index 1
        check_update_extended_topology_entry(1, 1, 0, 1, LEVEL_TYPE_CORE, 1, 1, 1);
        check_update_extended_topology_v2_entry(1, 1, 0, 1, LEVEL_TYPE_CORE, 1, 1, 1);
        // index 5
        check_update_extended_topology_v2_entry(1, 5, 0, 1, LEVEL_TYPE_DIE, 1, 1, 1);
    }

    #[test]
    fn test_1vcpu_ht_on() {
        check_update_feature_info_entry(1, false, 2, 1, 1);

        // test update_deterministic_cache_entry
        // test L1
        check_update_cache_parameters_entry(1, 1, 0, 2, 1, 1);
        // test L2
        check_update_cache_parameters_entry(1, 2, 0, 2, 1, 1);
        // test L3
        check_update_cache_parameters_entry(1, 3, 0, 2, 1, 1);

        // test update_extended_topology_entry
        // index 0
        check_update_extended_topology_entry(1, 0, 1, 2, LEVEL_TYPE_THREAD, 2, 1, 1);
        check_update_extended_topology_v2_entry(1, 0, 1, 2, LEVEL_TYPE_THREAD, 2, 1, 1);
        // index 1
        check_update_extended_topology_entry(1, 1, 1, 2, LEVEL_TYPE_CORE, 2, 1, 1);
        check_update_extended_topology_v2_entry(1, 1, 1, 2, LEVEL_TYPE_CORE, 2, 1, 1);
        // index 5
        check_update_extended_topology_v2_entry(1, 5, 1, 2, LEVEL_TYPE_DIE, 2, 1, 1);
    }

    #[test]
    fn test_2vcpu_ht_off() {
        check_update_feature_info_entry(2, true, 1, 2, 1);

        // test update_deterministic_cache_entry
        // test L1
        check_update_cache_parameters_entry(2, 1, 0, 1, 2, 1);
        // test L2
        check_update_cache_parameters_entry(2, 2, 0, 1, 2, 1);
        // test L3
        check_update_cache_parameters_entry(2, 3, 1, 1, 2, 1);

        // test update_extended_topology_entry
        // index 0
        check_update_extended_topology_entry(2, 0, 0, 1, LEVEL_TYPE_THREAD, 1, 2, 1);
        check_update_extended_topology_v2_entry(2, 0, 0, 1, LEVEL_TYPE_THREAD, 1, 2, 1);
        // index 1
        check_update_extended_topology_entry(2, 1, 1, 2, LEVEL_TYPE_CORE, 1, 2, 1);
        check_update_extended_topology_v2_entry(2, 1, 1, 2, LEVEL_TYPE_CORE, 1, 2, 1);
        // index 5
        check_update_extended_topology_v2_entry(2, 5, 1, 2, LEVEL_TYPE_DIE, 1, 2, 1);
    }

    #[test]
    fn test_2vcpu_ht_on() {
        check_update_feature_info_entry(2, true, 2, 2, 1);

        // test update_deterministic_cache_entry
        // test L1
        check_update_cache_parameters_entry(2, 1, 1, 2, 2, 1);
        // test L2
        check_update_cache_parameters_entry(2, 2, 1, 2, 2, 1);
        // test L3
        check_update_cache_parameters_entry(2, 3, 1, 2, 2, 1);

        // test update_extended_topology_entry
        // index 0
        check_update_extended_topology_entry(2, 0, 1, 2, LEVEL_TYPE_THREAD, 2, 2, 1);
        check_update_extended_topology_v2_entry(2, 0, 1, 2, LEVEL_TYPE_THREAD, 2, 2, 1);
        // index 1
        check_update_extended_topology_entry(2, 1, 2, 4, LEVEL_TYPE_CORE, 2, 2, 1);
        check_update_extended_topology_v2_entry(2, 1, 2, 4, LEVEL_TYPE_CORE, 2, 2, 1);
        // index 5
        check_update_extended_topology_v2_entry(2, 5, 2, 4, LEVEL_TYPE_DIE, 2, 2, 1);
    }

    #[test]
    fn test_2dies_2vcpu_ht_off() {
        // test update_extended_topology_entry
        // index 0
        check_update_extended_topology_entry(2, 0, 0, 1, LEVEL_TYPE_THREAD, 1, 1, 2);
        check_update_extended_topology_v2_entry(2, 0, 0, 1, LEVEL_TYPE_THREAD, 1, 1, 2);
        // index 1
        check_update_extended_topology_entry(2, 1, 0, 1, LEVEL_TYPE_CORE, 1, 1, 2);
        check_update_extended_topology_v2_entry(2, 1, 0, 1, LEVEL_TYPE_CORE, 1, 1, 2);
        // index 5
        check_update_extended_topology_v2_entry(2, 5, 1, 2, LEVEL_TYPE_DIE, 1, 1, 2);
    }

    #[test]
    fn test_2dies_4vcpu_ht_on() {
        // test update_extended_topology_entry
        // index 0
        check_update_extended_topology_entry(4, 0, 1, 2, LEVEL_TYPE_THREAD, 2, 1, 2);
        check_update_extended_topology_v2_entry(4, 0, 1, 2, LEVEL_TYPE_THREAD, 2, 1, 2);
        // index 1
        check_update_extended_topology_entry(4, 1, 1, 2, LEVEL_TYPE_CORE, 2, 1, 2);
        check_update_extended_topology_v2_entry(4, 1, 1, 2, LEVEL_TYPE_CORE, 2, 1, 2);
        // index 5
        check_update_extended_topology_v2_entry(4, 5, 2, 4, LEVEL_TYPE_DIE, 2, 1, 2);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_use_host_cpuid_function_with_count() {
        // try to emulate the extended cache topology leaves
        let topoext_fn = get_topoext_fn();

        // check that it behaves correctly for TOPOEXT function
        let mut cpuid = CpuId::new(1).unwrap();
        cpuid.as_mut_slice()[0].function = topoext_fn;
        assert!(use_host_cpuid_function(&mut cpuid, topoext_fn, true).is_ok());
        let entries = cpuid.as_mut_slice();
        assert!(entries.len() > 1);
        for (count, entry) in entries.iter_mut().enumerate() {
            assert!(entry.function == topoext_fn);
            assert!(entry.index == count as u32);
            assert!(entry.eax != 0);
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_use_host_cpuid_function_without_count() {
        use crate::cpuid::cpu_leaf::leaf_0x1::*;
        // try to emulate the extended cache topology leaves
        let feature_info_fn = LEAF_NUM;

        // check that it behaves correctly for TOPOEXT function
        let mut cpuid = CpuId::new(1).unwrap();
        cpuid.as_mut_slice()[0].function = feature_info_fn;
        assert!(use_host_cpuid_function(&mut cpuid, feature_info_fn, false).is_ok());
        let entries = cpuid.as_mut_slice();
        assert!(entries.len() == 1);
        let entry = entries[0];

        assert!(entry.function == feature_info_fn);
        assert!(entry.index == 0);
        assert!(entry.eax != 0);
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_use_host_cpuid_function_err() {
        let topoext_fn = get_topoext_fn();
        // check that it returns Err when there are too many entriesentry.function == topoext_fn
        let mut cpuid = CpuId::new(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap();
        match use_host_cpuid_function(&mut cpuid, topoext_fn, true) {
            Err(Error::FamError(vmm_sys_util::fam::Error::SizeLimitExceeded)) => {}
            _ => panic!("Wrong behavior"),
        }
    }
}
