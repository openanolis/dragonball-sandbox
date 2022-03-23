// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::{mem, result};

use kvm_bindings::*;
use kvm_ioctls::VcpuFd;
use vmm_sys_util;

/// Errors thrown while setting aarch64 registers.
#[derive(Debug)]
pub enum Error {
    /// Failed to get core register (PC, PSTATE or general purpose ones).
    GetCoreRegister(kvm_ioctls::Error),
    /// Failed to set core register (PC, PSTATE or general purpose ones).
    SetCoreRegister(kvm_ioctls::Error),
    /// Failed to get a system register.
    GetSysRegister(kvm_ioctls::Error),
    /// Failed to get the register list.
    GetRegList(kvm_ioctls::Error),
    /// Failed to get a system register.
    SetRegister(kvm_ioctls::Error),
    /// Failed to init fam reglist
    FamRegister(vmm_sys_util::fam::Error),
}
type Result<T> = result::Result<T, Error>;

#[allow(non_upper_case_globals)]
// PSR (Processor State Register) bits.
// Taken from arch/arm64/include/uapi/asm/ptrace.h.
const PSR_MODE_EL1h: u64 = 0x0000_0005;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
// Taken from arch/arm64/kvm/inject_fault.c.
const PSTATE_FAULT_BITS_64: u64 = PSR_MODE_EL1h | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;
// Number of general purpose registers (i.e X0..X31)
const NR_GP_REGS: usize = 31;
// Number of FP_VREG registers.
const NR_FP_VREGS: usize = 32;

// Following are macros that help with getting the ID of a aarch64 core register.
// The core register are represented by the user_pt_regs structure. Look for it in
// arch/arm64/include/uapi/asm/ptrace.h.

// This macro gets the offset of a structure (i.e `str`) member (i.e `field`) without having
// an instance of that structure.
// It uses a null pointer to retrieve the offset to the field.
// Inspired by C solution: `#define offsetof(str, f) ((size_t)(&((str *)0)->f))`.
// Doing `offset__of!(user_pt_regs, pstate)` in our rust code will trigger the following:
// unsafe { &(*(0 as *const user_pt_regs)).pstate as *const _ as usize }
// The dereference expression produces an lvalue, but that lvalue is not actually read from,
// we're just doing pointer math on it, so in theory, it should safe.
macro_rules! offset__of {
    ($str:ty, $field:ident) => {
        unsafe { &(*(0 as *const $str)).$field as *const _ as usize }
    };
}

macro_rules! arm64_core_reg {
    ($reg: tt) => {
        // As per `kvm_arm_copy_reg_indices`, the id of a core register can be obtained like this:
        // `const u64 core_reg = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | i`, where i is obtained with:
        // `for (i = 0; i < sizeof(struct kvm_regs) / sizeof(__u32); i++) {`
        // We are using here `user_pt_regs` since this structure contains the core register and it is at
        // the start of `kvm_regs`.
        // struct kvm_regs {
        //	struct user_pt_regs regs;	/* sp = sp_el0 */
        //
        //	__u64	sp_el1;
        //	__u64	elr_el1;
        //
        //	__u64	spsr[KVM_NR_SPSR];
        //
        //	struct user_fpsimd_state fp_regs;
        //};
        // struct user_pt_regs {
        //	__u64		regs[31];
        //	__u64		sp;
        //	__u64		pc;
        //	__u64		pstate;
        //};
        // In our implementation we need: pc, pstate and user_pt_regs->regs[0].
        KVM_REG_ARM64 as u64
            | KVM_REG_SIZE_U64 as u64
            | u64::from(KVM_REG_ARM_CORE)
            | ((offset__of!(user_pt_regs, $reg) / mem::size_of::<u32>()) as u64)
    };
}

/// Gets a core id.
macro_rules! arm64_core_reg_id {
    ($size: tt, $offset: tt) => {
        // The core registers of an arm64 machine are represented
        // in kernel by the `kvm_regs` structure. This structure is a
        // mix of 32, 64 and 128 bit fields:
        // struct kvm_regs {
        //     struct user_pt_regs      regs;
        //
        //     __u64                    sp_el1;
        //     __u64                    elr_el1;
        //
        //     __u64                    spsr[KVM_NR_SPSR];
        //
        //     struct user_fpsimd_state fp_regs;
        // };
        // struct user_pt_regs {
        //     __u64 regs[31];
        //     __u64 sp;
        //     __u64 pc;
        //     __u64 pstate;
        // };
        // The id of a core register can be obtained like this:
        // offset = id & ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_ARM_CORE). Thus,
        // id = KVM_REG_ARM64 | KVM_REG_SIZE_U64/KVM_REG_SIZE_U32/KVM_REG_SIZE_U128 | KVM_REG_ARM_CORE | offset
        KVM_REG_ARM64 as u64
            | u64::from(KVM_REG_ARM_CORE)
            | $size
            | (($offset / mem::size_of::<u32>()) as u64)
    };
}

// This macro computes the ID of a specific ARM64 system register similar to how
// the kernel C macro does.
// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/uapi/asm/kvm.h#L203
macro_rules! arm64_sys_reg {
    ($name: tt, $op0: tt, $op1: tt, $crn: tt, $crm: tt, $op2: tt) => {
        const $name: u64 = KVM_REG_ARM64 as u64
            | KVM_REG_SIZE_U64 as u64
            | KVM_REG_ARM64_SYSREG as u64
            | ((($op0 as u64) << KVM_REG_ARM64_SYSREG_OP0_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP0_MASK as u64)
            | ((($op1 as u64) << KVM_REG_ARM64_SYSREG_OP1_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP1_MASK as u64)
            | ((($crn as u64) << KVM_REG_ARM64_SYSREG_CRN_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRN_MASK as u64)
            | ((($crm as u64) << KVM_REG_ARM64_SYSREG_CRM_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRM_MASK as u64)
            | ((($op2 as u64) << KVM_REG_ARM64_SYSREG_OP2_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP2_MASK as u64);
    };
}

// Constant imported from the Linux kernel:
// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/asm/sysreg.h#L135
arm64_sys_reg!(MPIDR_EL1, 3, 0, 0, 0, 5);

/// Configure core registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `cpu_id` - Index of current vcpu.
/// * `boot_ip` - Starting instruction pointer.
/// * `mem` - Reserved DRAM for current VM.
pub fn setup_regs(vcpu: &VcpuFd, cpu_id: u8, boot_ip: u64, fdt_address: u64) -> Result<()> {
    // Get the register index of the PSTATE (Processor State) register.
    vcpu.set_one_reg(arm64_core_reg!(pstate), PSTATE_FAULT_BITS_64)
        .map_err(Error::SetCoreRegister)?;

    // Other vCPUs are powered off initially awaiting PSCI wakeup.
    if cpu_id == 0 {
        // Setting the PC (Processor Counter) to the current program address (kernel address).
        vcpu.set_one_reg(arm64_core_reg!(pc), boot_ip)
            .map_err(Error::SetCoreRegister)?;

        // Last mandatory thing to set -> the address pointing to the FDT (also called DTB).
        // "The device tree blob (dtb) must be placed on an 8-byte boundary and must
        // not exceed 2 megabytes in size." -> https://www.kernel.org/doc/Documentation/arm64/booting.txt.
        // We are choosing to place it the end of DRAM. See `get_fdt_addr`.
        vcpu.set_one_reg(arm64_core_reg!(regs), fdt_address)
            .map_err(Error::SetCoreRegister)?;
    }
    Ok(())
}

/// Get the state of the core registers.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `state` - Structure for returning the state of the core registers.
pub fn save_core_registers(vcpu: &VcpuFd, state: &mut Vec<kvm_one_reg>) -> Result<()> {
    let mut off = offset__of!(user_pt_regs, regs);
    // There are 31 user_pt_regs:
    // https://elixir.free-electrons.com/linux/v4.14.174/source/arch/arm64/include/uapi/asm/ptrace.h#L72
    // These actually are the general-purpose registers of the Armv8-a
    // architecture (i.e x0-x30 if used as a 64bit register or w0-w30 when used as a 32bit register).
    for _ in 0..NR_GP_REGS {
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
        state.push(kvm_one_reg {
            id,
            addr: vcpu.get_one_reg(id).map_err(Error::GetCoreRegister)?,
        });
        off += std::mem::size_of::<u64>();
    }

    // We are now entering the "Other register" section of the ARMv8-a architecture.
    // First one, stack pointer.
    let off = offset__of!(user_pt_regs, sp);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu.get_one_reg(id).map_err(Error::GetCoreRegister)?,
    });

    // Second one, the program counter.
    let off = offset__of!(user_pt_regs, pc);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu.get_one_reg(id).map_err(Error::GetCoreRegister)?,
    });

    // Next is the processor state.
    let off = offset__of!(user_pt_regs, pstate);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu.get_one_reg(id).map_err(Error::GetCoreRegister)?,
    });

    // The stack pointer associated with EL1.
    let off = offset__of!(kvm_regs, sp_el1);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu.get_one_reg(id).map_err(Error::GetCoreRegister)?,
    });

    // Exception Link Register for EL1, when taking an exception to EL1, this register
    // holds the address to which to return afterwards.
    let off = offset__of!(kvm_regs, elr_el1);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu.get_one_reg(id).map_err(Error::GetCoreRegister)?,
    });

    // Saved Program Status Registers, there are 5 of them used in the kernel.
    let mut off = offset__of!(kvm_regs, spsr);
    for _ in 0..KVM_NR_SPSR {
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, off);
        state.push(kvm_one_reg {
            id,
            addr: vcpu.get_one_reg(id).map_err(Error::GetCoreRegister)?,
        });
        off += std::mem::size_of::<u64>();
    }

    // Now moving on to floating point registers which are stored in the user_fpsimd_state in the kernel:
    // https://elixir.free-electrons.com/linux/v4.9.62/source/arch/arm64/include/uapi/asm/kvm.h#L53
    let mut off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, vregs);
    for _ in 0..NR_FP_VREGS {
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U128, off);
        state.push(kvm_one_reg {
            id,
            addr: vcpu.get_one_reg(id).map_err(Error::GetCoreRegister)?,
        });
        off += mem::size_of::<u128>();
    }

    // Floating-point Status Register.
    let off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, fpsr);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U32, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu.get_one_reg(id).map_err(Error::GetCoreRegister)?,
    });

    // Floating-point Control Register.
    let off = offset__of!(kvm_regs, fp_regs) + offset__of!(user_fpsimd_state, fpcr);
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U32, off);
    state.push(kvm_one_reg {
        id,
        addr: vcpu.get_one_reg(id).map_err(Error::GetCoreRegister)?,
    });

    Ok(())
}

/// Get the state of the system registers.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `state` - Structure for returning the state of the system registers.
pub fn save_system_registers(vcpu: &VcpuFd, state: &mut Vec<kvm_one_reg>) -> Result<()> {
    // Call KVM_GET_REG_LIST to get all registers available to the guest. For ArmV8 there are
    // around 500 registers.
    let mut reg_list = RegList::new(512).map_err(Error::FamRegister)?;
    vcpu.get_reg_list(&mut reg_list)
        .map_err(Error::GetRegList)?;

    // At this point reg_list should contain: core registers and system registers.
    // The register list contains the number of registers and their ids. We will be needing to
    // call KVM_GET_ONE_REG on each id in order to save all of them. We carve out from the list
    // the core registers which are represented in the kernel by kvm_regs structure and for which
    // we can calculate the id based on the offset in the structure.
    reg_list.retain(|regid| is_system_register(*regid));

    // Now, for the rest of the registers left in the previously fetched register list, we are
    // simply calling KVM_GET_ONE_REG.
    let indices = reg_list.as_slice();
    for index in indices.iter() {
        state.push(kvm_bindings::kvm_one_reg {
            id: *index,
            addr: vcpu.get_one_reg(*index).map_err(Error::GetSysRegister)?,
        });
    }

    Ok(())
}

/// Set the state of the system registers.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `state` - Structure containing the state of the system registers.
pub fn restore_registers(vcpu: &VcpuFd, state: &[kvm_one_reg]) -> Result<()> {
    for reg in state {
        vcpu.set_one_reg(reg.id, reg.addr)
            .map_err(Error::SetRegister)?;
    }
    Ok(())
}
/// Specifies whether a particular register is a system register or not.
/// The kernel splits the registers on aarch64 in core registers and system registers.
/// So, below we get the system registers by checking that they are not core registers.
///
/// # Arguments
///
/// * `regid` - The index of the register we are checking.
pub fn is_system_register(regid: u64) -> bool {
    if (regid & KVM_REG_ARM_COPROC_MASK as u64) == KVM_REG_ARM_CORE as u64 {
        return false;
    }

    let size = regid & KVM_REG_SIZE_MASK;
    if size != KVM_REG_SIZE_U32 && size != KVM_REG_SIZE_U64 {
        panic!("Unexpected register size for system register {}", size);
    }
    true
}
/// Read the MPIDR - Multiprocessor Affinity Register.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn read_mpidr(vcpu: &VcpuFd) -> Result<u64> {
    vcpu.get_one_reg(MPIDR_EL1).map_err(Error::GetSysRegister)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_ioctls::Kvm;

    #[test]
    fn test_setup_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        match setup_regs(&vcpu, 0, 0x0, crate::gic::GIC_REG_END_ADDRESS).unwrap_err() {
            Error::SetCoreRegister(ref e) => assert_eq!(e.errno(), libc::ENOEXEC),
            _ => panic!("Expected to receive Error::SetCoreRegister"),
        }
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();

        assert!(setup_regs(&vcpu, 0, 0x0, crate::gic::GIC_REG_END_ADDRESS).is_ok());
    }
    #[test]
    fn test_read_mpidr() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        // Must fail when vcpu is not initialized yet.
        assert!(read_mpidr(&vcpu).is_err());

        vcpu.vcpu_init(&kvi).unwrap();
        assert_eq!(read_mpidr(&vcpu).unwrap(), 0x80000000);
    }
}
