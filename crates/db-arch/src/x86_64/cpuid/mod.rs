// Copyright 2021 Alibaba Cloud. All Rights Reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Utility for configuring the CPUID (CPU identification) for the guest microVM.

use kvm_bindings::CpuId;

use transformer::*;
pub use transformer::{Error, VmSpec, VpmuFeatureLevel};

/// Contains helper methods for bit operations.
pub mod bit_helper;

mod common;
use common::*;

mod cpu_leaf;

mod brand_string;
mod transformer;

/// Setup CPUID entries for the given vCPU.
///
/// # Arguments
///
/// * `kvm_cpuid` - KVM related structure holding the relevant CPUID info.
/// * `vm_spec` - The specifications of the VM.
///
/// # Example
/// ```
/// use db_arch::cpuid::{process_cpuid, VmSpec, VpmuFeatureLevel};
/// use kvm_bindings::{CpuId, KVM_MAX_CPUID_ENTRIES};
/// use kvm_ioctls::Kvm;
///
/// let kvm = Kvm::new().unwrap();
/// let mut kvm_cpuid: CpuId = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
///
/// let vm_spec = VmSpec::new(0, 1, 1, 1, 1, VpmuFeatureLevel::Disabled).unwrap();
///
/// process_cpuid(&mut kvm_cpuid, &vm_spec).unwrap();
///
/// // Get expected `kvm_cpuid` entries.
/// let entries = kvm_cpuid.as_mut_slice();
/// ```
pub fn process_cpuid(kvm_cpuid: &mut CpuId, vm_spec: &VmSpec) -> Result<(), Error> {
    match vm_spec.cpu_vendor_id() {
        VENDOR_ID_INTEL => {
            let transformer = intel::IntelCpuidTransformer {};
            transformer.process_cpuid(kvm_cpuid, vm_spec)
        }
        VENDOR_ID_AMD => {
            let transformer = amd::AmdCpuidTransformer {};
            transformer.process_cpuid(kvm_cpuid, vm_spec)
        }
        _ => Err(Error::CpuNotSupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_cpuid() {
        let mut cpuid = CpuId::new(0).unwrap();
        let vm_spec = VmSpec::new(0, 2, 1, 1, 1, VpmuFeatureLevel::Disabled).unwrap();

        process_cpuid(&mut cpuid, &vm_spec).unwrap();
    }
}
