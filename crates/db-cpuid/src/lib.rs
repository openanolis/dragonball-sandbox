// Copyright 2021 Alibaba Cloud. All Rights Reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#![deny(missing_docs)]
//! Utility for configuring the CPUID (CPU identification) for the guest microVM.

#![cfg(target_arch = "x86_64")]

use kvm_bindings::CpuId;

mod common;
use common::*;

/// Contains helper methods for bit operations.
pub mod bit_helper;

mod cpu_leaf;

mod transformer;
use transformer::*;
pub use transformer::{Error, VmSpec, VpmuFeatureLevel};

mod brand_string;

pub mod x86_regs;

/// Sets up the CPUID entries for the given vcpu.
///
/// # Arguments
///
/// * `kvm_cpuid` - KVM related structure holding the relevant CPUID info.
/// * `vm_spec` - The specifications of the VM.
///
/// # Example
/// ```
/// use cpuid::{filter_cpuid, VmSpec, VpmuFeatureLevel};
/// use kvm_bindings::{CpuId, KVM_MAX_CPUID_ENTRIES};
/// use kvm_ioctls::Kvm;
///
/// let kvm = Kvm::new().unwrap();
/// let mut kvm_cpuid: CpuId = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
///
/// let vm_spec = VmSpec::new(0, 1, 1, 1, 1, VpmuFeatureLevel::Disabled).unwrap();
///
/// filter_cpuid(&mut kvm_cpuid, &vm_spec).unwrap();
///
/// // Get expected `kvm_cpuid` entries.
/// let entries = kvm_cpuid.as_mut_slice();
/// ```
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn filter_cpuid(kvm_cpuid: &mut CpuId, vm_spec: &VmSpec) -> Result<(), Error> {
    let maybe_cpuid_transformer: Option<&dyn CpuidTransformer> = match vm_spec.cpu_vendor_id() {
        VENDOR_ID_INTEL => Some(&intel::IntelCpuidTransformer {}),
        VENDOR_ID_AMD => Some(&amd::AmdCpuidTransformer {}),
        _ => None,
    };

    if let Some(cpuid_transformer) = maybe_cpuid_transformer {
        cpuid_transformer.process_cpuid(kvm_cpuid, &vm_spec)?;
    }

    Ok(())
}
