// Copyright 2022 Alibaba Cloud. All Rights Reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use libc::siginfo_t;
use std::cell::RefCell;
use std::ffi::c_void;
use std::io::{self, stdin};
use std::os::raw::c_int;
use std::result;
use std::sync::{Arc, Barrier, Condvar, Mutex};

use dbs_device::device_manager::IoManager;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{
    kvm_debugregs, kvm_lapic_state, kvm_mp_state, kvm_regs, kvm_sregs, kvm_vcpu_events, kvm_xcrs,
    kvm_xsave, CpuId, Msrs,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
#[cfg(target_arch = "x86_64")]
use vm_memory::Address;
use vm_memory::{GuestAddress, GuestMemory};

#[cfg(target_arch = "x86_64")]
use dbs_arch::{
    cpuid::{VmSpec, VpmuFeatureLevel},
    gdt, msr,
};

use vmm_sys_util::errno::Error as Errno;
use vmm_sys_util::signal::{register_signal_handler, SIGRTMIN};
use vmm_sys_util::terminal::Terminal;

use utils::debug;

use crate::vm::VmRunState;

/// Errors encountered during vCPU operation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid number of vcpus specified in configuration.
    #[error("Invalid number of vcpus specified in configuration: {0}")]
    VcpuNumber(u8),

    /// Cannot get the supported MSRs.
    #[error("Cannot get the supported MSRs.")]
    #[cfg(target_arch = "x86_64")]
    GetSupportedMsrs(msr::Error),

    /// I/O Error.
    #[error("I/O Error: {0}")]
    IO(io::Error),

    /// Error issuing an ioctl to KVM.
    #[error("Error issuing an ioctl to KVM: {0}")]
    KvmIoctl(kvm_ioctls::Error),

    /// TLS already initialized.
    #[error("TLS already initialized.")]
    TlsInitialized,

    /// Unable to register signal handler.
    #[error("Unable to register signal handler: {0}")]
    RegisterSignalHandler(Errno),

    // These are all Save/Restore errors. Maybe it makes sense to move them
    // to a separate enum.
    #[error("FamError")]
    FamError(vmm_sys_util::fam::Error),

    /// Failed to get KVM vcpu debug regs.
    #[error("Failed to get KVM vcpu debug regs: {0}")]
    VcpuGetDebugRegs(kvm_ioctls::Error),

    /// Failed to get KVM vcpu lapic.
    #[error("Failed to get KVM vcpu lapic: {0}")]
    VcpuGetLapic(kvm_ioctls::Error),

    /// Failed to get KVM vcpu mp state.
    #[error("Failed to get KVM vcpu mp state: {0}")]
    VcpuGetMpState(kvm_ioctls::Error),

    /// The number of MSRS returned by the kernel is unexpected.
    #[error("The number of MSRS returned by the kernel is unexpected.")]
    VcpuGetMSRSIncomplete,

    /// Failed to get KVM vcpu msrs.
    #[error("Failed to get KVM vcpu msrs: {0}")]
    VcpuGetMsrs(kvm_ioctls::Error),

    /// Failed to get KVM vcpu regs.
    #[error("Failed to get KVM vcpu regs: {0}")]
    VcpuGetRegs(kvm_ioctls::Error),

    /// Failed to get KVM vcpu sregs.
    #[error("Failed to get KVM vcpu sregs: {0}")]
    VcpuGetSregs(kvm_ioctls::Error),

    /// Failed to get KVM vcpu event.
    #[error("Failed to get KVM vcpu event: {0}")]
    VcpuGetVcpuEvents(kvm_ioctls::Error),

    /// Failed to get KVM vcpu xcrs.
    #[error("Failed to get KVM vcpu xcrs: {0}")]
    VcpuGetXcrs(kvm_ioctls::Error),

    /// Failed to get KVM vcpu xsave.
    #[error("Failed to get KVM vcpu xsave: {0}")]
    VcpuGetXsave(kvm_ioctls::Error),

    /// Failed to get KVM vcpu cpuid.
    #[error("Failed to get KVM vcpu cpuid: {0}")]
    VcpuGetCpuid(kvm_ioctls::Error),

    /// Failed to get KVM TSC freq.
    #[error("Failed to get KVM TSC freq: {0}")]
    VcpuGetTSC(kvm_ioctls::Error),

    /// Failed to get KVM vcpu reglist.
    #[error("Failed to get KVM vcpu reglist: {0}")]
    VcpuGetRegList(kvm_ioctls::Error),

    /// Failed to get KVM vcpu reg.
    #[error("Failed to get KVM vcpu reg: {0}")]
    VcpuGetReg(kvm_ioctls::Error),

    /// Failed to get KVM vcpu MPIDR reg.
    #[error("Failed to get KVM vcpu MPIDR reg")]
    VcpuGetMpidrReg,

    /// Failed to set KVM vcpu cpuid.
    #[error("Failed to set KVM vcpu cpuid: {0}")]
    VcpuSetCpuid(kvm_ioctls::Error),

    /// Failed to set KVM vcpu debug regs.
    #[error("Failed to set KVM vcpu debug regs: {0}")]
    VcpuSetDebugRegs(kvm_ioctls::Error),

    /// Failed to set KVM vcpu lapic.
    #[error("Failed to set KVM vcpu lapic: {0}")]
    VcpuSetLapic(kvm_ioctls::Error),

    /// Failed to set KVM vcpu mp state.
    #[error("Failed to set KVM vcpu mp state: {0}")]
    VcpuSetMpState(kvm_ioctls::Error),

    /// Failed to set KVM vcpu msrs.
    #[error("Failed to set KVM vcpu msrs: {0}")]
    VcpuSetMsrs(kvm_ioctls::Error),

    /// Failed to set KVM vcpu regs.
    #[error("Failed to set KVM vcpu regs: {0}")]
    VcpuSetRegs(kvm_ioctls::Error),

    /// Failed to set KVM vcpu sregs.
    #[error("Failed to set KVM vcpu sregs: {0}")]
    VcpuSetSregs(kvm_ioctls::Error),

    /// Failed to set KVM vcpu event.
    #[error("Failed to set KVM vcpu event: {0}")]
    VcpuSetVcpuEvents(kvm_ioctls::Error),

    /// Failed to set KVM vcpu xcrs.
    #[error("Failed to set KVM vcpu xcrs: {0}")]
    VcpuSetXcrs(kvm_ioctls::Error),

    /// Failed to set KVM vcpu xsave.
    #[error("Failed to set KVM vcpu xsave: {0}")]
    VcpuSetXsave(kvm_ioctls::Error),

    /// Failed to set KVM vcpu reg.
    #[error("Failed to set KVM vcpu reg: {0}")]
    VcpuSetReg(kvm_ioctls::Error),

    /// A call to cpuid instruction failed on x86_64.
    #[error("failure while configuring CPUID for virtual CPU on x86_64")]
    #[cfg(target_arch = "x86_64")]
    CpuId(dbs_arch::cpuid::Error),

    /// The call to KVM_SET_CPUID2 failed on x86_64.
    #[error("failure while calling KVM_SET_CPUID2 on x86_64")]
    #[cfg(target_arch = "x86_64")]
    SetSupportedCpusFailed(#[source] kvm_ioctls::Error),

    /// Error configuring the MSR registers on x86_64.
    #[error("failure while configuring the MSR registers on x86_64")]
    #[cfg(target_arch = "x86_64")]
    MSRSConfiguration(dbs_arch::regs::Error),

    /// Error configuring the general purpose registers on x86_64.
    #[error("failure while configuring the general purpose registers on x86_64")]
    #[cfg(target_arch = "x86_64")]
    REGSConfiguration(dbs_arch::regs::Error),

    /// Error configuring the special registers on x86_64.
    #[error("failure while configuring the special registers on x86_64")]
    #[cfg(target_arch = "x86_64")]
    SREGSConfiguration(dbs_arch::regs::Error),

    /// Error configuring the page table on x86_64.
    #[error("failure while configuring the page table on x86_64")]
    #[cfg(target_arch = "x86_64")]
    PageTable(dbs_boot::Error),

    /// Error configuring the floating point related registers on x86_64.
    #[error("failure while configuring the floating point related registers on x86_64")]
    #[cfg(target_arch = "x86_64")]
    FPUConfiguration(dbs_arch::regs::Error),

    /// Cannot set the local interruption due to bad configuration on x86_64.
    #[error("cannot set the local interruption due to bad configuration on x86_64")]
    #[cfg(target_arch = "x86_64")]
    LocalIntConfiguration(dbs_arch::interrupts::Error),

    /// Cannot create msr.
    #[error("cannot create msr")]
    CreateMsrs,
}

/// Dedicated Result type.
pub type Result<T> = result::Result<T, Error>;

#[derive(Clone)]
pub struct VcpuConfig {
    pub id: u8,
    #[cfg(target_arch = "x86_64")]
    pub cpuid: CpuId,
    #[cfg(target_arch = "x86_64")]
    // This is just a workaround so that we can get a list of MSRS.
    // Just getting all the MSRS on a vcpu is not possible with KVM.
    pub msrs: Msrs,
}

#[derive(Clone)]
pub struct VcpuConfigList {
    pub configs: Vec<VcpuConfig>,
}

impl VcpuConfigList {
    /// Creates a default configuration list for vCPUs.
    pub fn new(_kvm: &Kvm, num_vcpus: u8) -> Result<Self> {
        if num_vcpus == 0 {
            return Err(Error::VcpuNumber(num_vcpus));
        }

        #[cfg(target_arch = "x86_64")]
        let base_cpuid = _kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::KvmIoctl)?;

        let supported_msr_list =
            msr::supported_guest_msrs(_kvm).map_err(Error::GetSupportedMsrs)?;
        #[cfg(target_arch = "x86_64")]
        let mut supported_msrs = Msrs::new(supported_msr_list.as_fam_struct_ref().nmsrs as usize)
            .map_err(|_| Error::CreateMsrs)?;
        let indices = supported_msr_list.as_slice();
        let msr_entries = supported_msrs.as_mut_slice();
        // We created the msrs from the msr_list. If the size is not the same,
        // there is a fatal programming error.
        assert_eq!(indices.len(), msr_entries.len());
        for (pos, index) in indices.iter().enumerate() {
            msr_entries[pos].index = *index;
        }

        let mut configs = Vec::new();
        for index in 0..num_vcpus {
            // Set CPUID.
            #[cfg(target_arch = "x86_64")]
            let mut cpuid = base_cpuid.clone();

            #[cfg(target_arch = "x86_64")]
            let vm_spec = VmSpec::new(0, 2, 1, 1, 1, VpmuFeatureLevel::Disabled).unwrap();

            #[cfg(target_arch = "x86_64")]
            dbs_arch::cpuid::process_cpuid(&mut cpuid, &vm_spec).map_err(Error::CpuId)?;

            #[cfg(target_arch = "x86_64")]
            let vcpu_config = VcpuConfig {
                cpuid,
                id: index,
                msrs: supported_msrs.clone(),
            };

            configs.push(vcpu_config);
        }

        Ok(VcpuConfigList { configs })
    }
}

/// Structure holding the kvm state for an x86_64 VCPU.
#[cfg(target_arch = "x86_64")]
#[derive(Clone)]
pub struct VcpuState {
    pub cpuid: CpuId,
    pub msrs: Msrs,
    pub debug_regs: kvm_debugregs,
    pub lapic: kvm_lapic_state,
    pub mp_state: kvm_mp_state,
    pub regs: kvm_regs,
    pub sregs: kvm_sregs,
    pub vcpu_events: kvm_vcpu_events,
    pub xcrs: kvm_xcrs,
    pub xsave: kvm_xsave,
    pub config: VcpuConfig,
}

/// Represents the current run state of the VCPUs.
#[derive(Default)]
pub struct VcpuRunState {
    pub(crate) vm_state: Mutex<VmRunState>,
    condvar: Condvar,
}

impl VcpuRunState {
    pub fn set_and_notify(&self, state: VmRunState) {
        *self.vm_state.lock().unwrap() = state;
        self.condvar.notify_all();
    }
}

/// Struct for interacting with vCPUs.
///
/// This struct is a temporary (and quite terrible) placeholder until the
/// [`vmm-vcpu`](https://github.com/rust-vmm/vmm-vcpu) crate is stabilized.
pub struct KvmVcpu {
    /// KVM file descriptor for a vCPU.
    pub(crate) vcpu_fd: VcpuFd,
    /// Device manager for bus accesses.
    device_mgr: Arc<Mutex<IoManager>>,
    config: VcpuConfig,
    run_barrier: Arc<Barrier>,
    pub(crate) run_state: Arc<VcpuRunState>,
}

impl KvmVcpu {
    thread_local!(static TLS_VCPU_PTR: RefCell<Option<*const KvmVcpu>> = RefCell::new(None));

    /// Create a new vCPU.
    pub fn new<M: GuestMemory>(
        vm_fd: &VmFd,
        device_mgr: Arc<Mutex<IoManager>>,
        config: VcpuConfig,
        run_barrier: Arc<Barrier>,
        run_state: Arc<VcpuRunState>,
        memory: &M,
    ) -> Result<Self> {
        #[cfg(target_arch = "x86_64")]
        let vcpu = KvmVcpu {
            vcpu_fd: vm_fd
                .create_vcpu(config.id.into())
                .map_err(Error::KvmIoctl)?,
            device_mgr,
            config,
            run_barrier,
            run_state,
        };

        #[cfg(target_arch = "x86_64")]
        {
            vcpu.configure_cpuid(&vcpu.config.cpuid)?;
            vcpu.configure_msrs()?;
            vcpu.configure_sregs(memory)?;
            vcpu.configure_lapic()?;
            vcpu.configure_fpu()?;
        }

        Ok(vcpu)
    }

    #[cfg(target_arch = "x86_64")]
    // Set the state of this `KvmVcpu`. Errors returned from this function
    // MUST not be ignored because they can lead to undefined behavior when
    // the state of the vCPU is only partially set.
    fn set_state(&mut self, state: VcpuState) -> Result<()> {
        self.vcpu_fd
            .set_cpuid2(&state.cpuid)
            .map_err(Error::VcpuSetCpuid)?;
        self.vcpu_fd
            .set_mp_state(state.mp_state)
            .map_err(Error::VcpuSetMpState)?;
        self.vcpu_fd
            .set_regs(&state.regs)
            .map_err(Error::VcpuSetRegs)?;
        self.vcpu_fd
            .set_sregs(&state.sregs)
            .map_err(Error::VcpuSetSregs)?;
        self.vcpu_fd
            .set_xsave(&state.xsave)
            .map_err(Error::VcpuSetXsave)?;
        self.vcpu_fd
            .set_xcrs(&state.xcrs)
            .map_err(Error::VcpuSetXcrs)?;
        self.vcpu_fd
            .set_debug_regs(&state.debug_regs)
            .map_err(Error::VcpuSetDebugRegs)?;
        self.vcpu_fd
            .set_lapic(&state.lapic)
            .map_err(Error::VcpuSetLapic)?;
        self.vcpu_fd
            .set_msrs(&state.msrs)
            .map_err(Error::VcpuSetMsrs)?;
        self.vcpu_fd
            .set_vcpu_events(&state.vcpu_events)
            .map_err(Error::VcpuSetVcpuEvents)?;
        Ok(())
    }

    /// Create a vCPU from a previously saved state.
    pub fn from_state<M: GuestMemory>(
        vm_fd: &VmFd,
        device_mgr: Arc<Mutex<IoManager>>,
        state: VcpuState,
        run_barrier: Arc<Barrier>,
        run_state: Arc<VcpuRunState>,
    ) -> Result<Self> {
        let mut vcpu = KvmVcpu {
            vcpu_fd: vm_fd
                .create_vcpu(state.config.id.into())
                .map_err(Error::KvmIoctl)?,
            device_mgr,
            config: state.config.clone(),
            run_barrier,
            run_state,
        };

        vcpu.set_state(state)?;
        Ok(vcpu)
    }

    // Set CPUID.
    #[cfg(target_arch = "x86_64")]
    fn configure_cpuid(&self, cpuid: &CpuId) -> Result<()> {
        self.vcpu_fd
            .set_cpuid2(cpuid)
            .map_err(Error::SetSupportedCpusFailed)
    }

    // Configure MSRs.
    #[cfg(target_arch = "x86_64")]
    fn configure_msrs(&self) -> Result<()> {
        dbs_arch::regs::setup_msrs(&self.vcpu_fd).map_err(Error::MSRSConfiguration)
    }

    // Configure regs.
    #[cfg(target_arch = "x86_64")]
    fn configure_regs(&self, instruction_pointer: GuestAddress) -> Result<()> {
        dbs_arch::regs::setup_regs(
            &self.vcpu_fd,
            instruction_pointer.raw_value(),
            dbs_boot::layout::BOOT_STACK_POINTER,
            dbs_boot::layout::BOOT_STACK_POINTER,
            dbs_boot::layout::ZERO_PAGE_START,
        )
        .map_err(Error::REGSConfiguration)
    }

    // Configure sregs.
    #[cfg(target_arch = "x86_64")]
    fn configure_sregs<M: GuestMemory>(&self, guest_memory: &M) -> Result<()> {
        let gdt_table: [u64; dbs_boot::layout::BOOT_GDT_MAX as usize] = [
            gdt::gdt_entry(0, 0, 0),            // NULL
            gdt::gdt_entry(0xa09b, 0, 0xfffff), // CODE
            gdt::gdt_entry(0xc093, 0, 0xfffff), // DATA
            gdt::gdt_entry(0x808b, 0, 0xfffff), // TSS
        ];
        let pgtable_addr =
            dbs_boot::setup_identity_mapping(guest_memory).map_err(Error::PageTable)?;
        dbs_arch::regs::setup_sregs(
            guest_memory,
            &self.vcpu_fd,
            pgtable_addr,
            &gdt_table,
            dbs_boot::layout::BOOT_GDT_OFFSET,
            dbs_boot::layout::BOOT_IDT_OFFSET,
        )
        .map_err(Error::SREGSConfiguration)
    }

    // Configure FPU.
    #[cfg(target_arch = "x86_64")]
    fn configure_fpu(&self) -> Result<()> {
        dbs_arch::regs::setup_fpu(&self.vcpu_fd).map_err(Error::FPUConfiguration)
    }

    // Configures LAPICs. LAPIC0 is set for external interrupts, LAPIC1 is set for NMI.
    #[cfg(target_arch = "x86_64")]
    fn configure_lapic(&self) -> Result<()> {
        dbs_arch::interrupts::set_lint(&self.vcpu_fd).map_err(Error::LocalIntConfiguration)
    }

    pub(crate) fn setup_signal_handler() -> Result<()> {
        extern "C" fn handle_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
            KvmVcpu::set_local_immediate_exit(1);
        }
        #[allow(clippy::identity_op)]
        register_signal_handler(SIGRTMIN() + 0, handle_signal)
            .map_err(Error::RegisterSignalHandler)?;
        Ok(())
    }

    fn init_tls(&mut self) -> Result<()> {
        Self::TLS_VCPU_PTR.with(|vcpu| {
            if vcpu.borrow().is_none() {
                *vcpu.borrow_mut() = Some(self as *const KvmVcpu);
                Ok(())
            } else {
                Err(Error::TlsInitialized)
            }
        })?;
        Ok(())
    }

    fn set_local_immediate_exit(value: u8) {
        Self::TLS_VCPU_PTR.with(|v| {
            if let Some(vcpu) = *v.borrow() {
                // The block below modifies a mmaped memory region (`kvm_run` struct) which is valid
                // as long as the `VMM` is still in scope. This function is called in response to
                // SIGRTMIN(), while the vCPU threads are still active. Their termination are
                // strictly bound to the lifespan of the `VMM` and it precedes the `VMM` dropping.
                unsafe {
                    let vcpu_ref = &*vcpu;
                    vcpu_ref.vcpu_fd.set_kvm_immediate_exit(value);
                };
            }
        });
    }

    /// vCPU emulation loop.
    ///
    /// # Arguments
    ///
    /// * `instruction_pointer`: Represents the start address of the vcpu. This can be None
    /// when the IP is specified using the platform dependent registers.
    #[allow(clippy::if_same_then_else)]
    pub fn run(&mut self, instruction_pointer: Option<GuestAddress>) -> Result<()> {
        if let Some(ip) = instruction_pointer {
            #[cfg(target_arch = "x86_64")]
            self.configure_regs(ip)?;
        }
        self.init_tls()?;

        self.run_barrier.wait();
        'vcpu_run: loop {
            let mut interrupted_by_signal = false;
            match self.vcpu_fd.run() {
                Ok(exit_reason) => {
                    // println!("{:#?}", exit_reason);
                    match exit_reason {
                        VcpuExit::Shutdown | VcpuExit::Hlt => {
                            println!("Guest shutdown: {:?}. Bye!", exit_reason);
                            if stdin().lock().set_canon_mode().is_err() {
                                eprintln!("Failed to set canon mode. Stdin will not echo.");
                            }
                            self.run_state.set_and_notify(VmRunState::Exiting);
                            break;
                        }
                        VcpuExit::IoOut(addr, data) => {
                            if (0x3f8..(0x3f8 + 8)).contains(&addr) {
                                // Write at the serial port.
                                if self
                                    .device_mgr
                                    .lock()
                                    .unwrap()
                                    .pio_write(addr, data)
                                    .is_err()
                                {
                                    debug!("Failed to write to serial port");
                                }
                            } else if addr == 0x060 || addr == 0x061 || addr == 0x064 {
                                // Write at the i8042 port.
                                //i8042 is registered at port 0x64.
                                // See https://wiki.osdev.org/%228042%22_PS/2_Controller#PS.2F2_Controller_IO_Ports
                                #[cfg(target_arch = "x86_64")]
                                if self
                                    .device_mgr
                                    .lock()
                                    .unwrap()
                                    .pio_write(addr, data)
                                    .is_err()
                                {
                                    debug!("Failed to write to i8042 port")
                                }
                            } else if (0x070..=0x07f).contains(&addr) {
                                // Write at the RTC port.
                            } else {
                                // Write at some other port.
                            }
                        }
                        VcpuExit::IoIn(addr, data) => {
                            if (0x3f8..(0x3f8 + 8)).contains(&addr) {
                                // Read from the serial port.
                                if self
                                    .device_mgr
                                    .lock()
                                    .unwrap()
                                    .pio_read(addr, data)
                                    .is_err()
                                {
                                    debug!("Failed to read from serial port");
                                }
                            } else {
                                // Read from some other port.
                            }
                        }
                        VcpuExit::MmioRead(addr, data) => {
                            if self
                                .device_mgr
                                .lock()
                                .unwrap()
                                .mmio_read(addr, data)
                                .is_err()
                            {
                                debug!("Failed to read from mmio addr={} data={:#?}", addr, data);
                            }
                        }
                        VcpuExit::MmioWrite(addr, data) => {
                            if self
                                .device_mgr
                                .lock()
                                .unwrap()
                                .mmio_write(addr, data)
                                .is_err()
                            {
                                debug!("Failed to write to mmio");
                            }
                        }
                        _other => {
                            // Unhandled KVM exit.
                            debug!("Unhandled vcpu exit: {:#?}", _other);
                        }
                    }
                }
                Err(e) => {
                    // During boot KVM can exit with `EAGAIN`. In that case, do not
                    // terminate the run loop.
                    match e.errno() {
                        libc::EAGAIN => {}
                        libc::EINTR => {
                            interrupted_by_signal = true;
                        }
                        _ => {
                            debug!("Emulation error: {}", e);
                            break;
                        }
                    }
                }
            }

            if interrupted_by_signal {
                self.vcpu_fd.set_kvm_immediate_exit(0);
                let mut run_state_lock = self.run_state.vm_state.lock().unwrap();
                loop {
                    match *run_state_lock {
                        VmRunState::Running => {
                            // The VM state is running, so we need to exit from this loop,
                            // and enter the kvm run loop.
                            break;
                        }
                        VmRunState::Suspending => {
                            // The VM is suspending. We run this loop until we get a different
                            // state.
                        }
                        VmRunState::Exiting => {
                            // The VM is exiting. We also exit from this VCPU thread.
                            break 'vcpu_run;
                        }
                    }
                    // Give ownership of our exclusive lock to the condition variable that will
                    // block. When the condition variable is notified, `wait` will unblock and
                    // return a new exclusive lock.
                    run_state_lock = self.run_state.condvar.wait(run_state_lock).unwrap();
                }
            }
        }

        Ok(())
    }

    /// Pause the vcpu. If the vcpu is already paused, this is a no-op.
    pub fn pause(&mut self) -> Result<()> {
        todo!()
    }

    #[cfg(target_arch = "x86_64")]
    pub fn save_state(&mut self) -> Result<VcpuState> {
        let mp_state = self.vcpu_fd.get_mp_state().map_err(Error::VcpuGetMpState)?;
        let regs = self.vcpu_fd.get_regs().map_err(Error::VcpuGetRegs)?;
        let sregs = self.vcpu_fd.get_sregs().map_err(Error::VcpuGetSregs)?;
        let xsave = self.vcpu_fd.get_xsave().map_err(Error::VcpuGetXsave)?;
        let xcrs = self.vcpu_fd.get_xcrs().map_err(Error::VcpuGetXcrs)?;
        let debug_regs = self
            .vcpu_fd
            .get_debug_regs()
            .map_err(Error::VcpuGetDebugRegs)?;
        let lapic = self.vcpu_fd.get_lapic().map_err(Error::VcpuGetLapic)?;

        let mut msrs = self.config.msrs.clone();
        let num_msrs = self.config.msrs.as_fam_struct_ref().nmsrs as usize;
        let nmsrs = self
            .vcpu_fd
            .get_msrs(&mut msrs)
            .map_err(Error::VcpuGetMsrs)?;
        if nmsrs != num_msrs {
            return Err(Error::VcpuGetMSRSIncomplete);
        }
        let vcpu_events = self
            .vcpu_fd
            .get_vcpu_events()
            .map_err(Error::VcpuGetVcpuEvents)?;

        let cpuid = self
            .vcpu_fd
            .get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::VcpuGetCpuid)?;

        Ok(VcpuState {
            cpuid,
            msrs,
            debug_regs,
            lapic,
            mp_state,
            regs,
            sregs,
            vcpu_events,
            xcrs,
            xsave,
            config: self.config.clone(),
        })
    }
}

impl Drop for KvmVcpu {
    fn drop(&mut self) {
        Self::TLS_VCPU_PTR.with(|v| {
            *v.borrow_mut() = None;
        });
    }
}
