// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::aarch64::gic::{Error, Result};
use kvm_ioctls::DeviceFd;
use std::fmt::Debug;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

#[derive(Debug)]
/// The gic reg state which is serialize to do snapshot
pub struct GicRegState<T: Versionize> {
    pub(crate) chunks: Vec<T>,
}

impl<T: Versionize> Versionize for GicRegState<T> {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        version_map: &VersionMap,
        app_version: u16,
    ) -> VersionizeResult<()> {
        let chunks = &self.chunks;
        assert_eq!(std::mem::size_of_val(chunks), std::mem::size_of::<Self>());
        Versionize::serialize(chunks, writer, version_map, app_version)
    }

    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        version_map: &VersionMap,
        app_version: u16,
    ) -> VersionizeResult<Self> {
        let chunks = Versionize::deserialize(reader, version_map, app_version)?;
        assert_eq!(std::mem::size_of_val(&chunks), std::mem::size_of::<Self>());
        Ok(Self { chunks })
    }

    fn version() -> u16 {
        1
    }
}

/// Structure used for serializing the state of the GIC registers
#[derive(Debug, Default, Versionize)]
pub struct GicState {
    pub(crate) dist: Vec<GicRegState<u32>>,
    gic_vcpu_states: Vec<GicVcpuState>,
}

/// Structure used for serializing the state of the GIC registers for a specific vCPU
#[derive(Debug, Default, Versionize)]
pub struct GicVcpuState {
    rdist: Vec<GicRegState<u32>>,
    icc: VgicSysRegsState,
}

/// Structure for serializing the state of the Vgic ICC regs
#[derive(Debug, Default, Versionize)]
pub struct VgicSysRegsState {
    pub(crate) main_icc_regs: Vec<GicRegState<u64>>,
    pub(crate) ap_icc_regs: Vec<Option<GicRegState<u64>>>,
}

/// Save the state of the GIC device.
pub fn save_state(fd: &DeviceFd, mpidrs: &[u64]) -> Result<GicState> {
    // Flush redistributors pending tables to guest RAM.
    crate::aarch64::gic::save_pending_tables(fd)?;

    let mut vcpu_states = Vec::with_capacity(mpidrs.len());
    for mpidr in mpidrs {
        vcpu_states.push(GicVcpuState {
            rdist: super::redist_regs::get_redist_regs(fd, *mpidr)?,
            icc: super::icc_regs::get_icc_regs(fd, *mpidr)?,
        })
    }

    Ok(GicState {
        dist: super::dist_regs::get_dist_regs(fd)?,
        gic_vcpu_states: vcpu_states,
    })
}

/// Restore the state of the GIC device.
pub fn restore_state(fd: &DeviceFd, mpidrs: &[u64], state: &GicState) -> Result<()> {
    super::dist_regs::set_dist_regs(fd, &state.dist)?;

    if mpidrs.len() != state.gic_vcpu_states.len() {
        return Err(Error::InconsistentVcpuCount);
    }
    for (mpidr, vcpu_state) in mpidrs.iter().zip(&state.gic_vcpu_states) {
        super::redist_regs::set_redist_regs(fd, *mpidr, &vcpu_state.rdist)?;
        super::icc_regs::set_icc_regs(fd, *mpidr, &vcpu_state.icc)?;
    }

    Ok(())
}
