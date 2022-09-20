// Copyright 2022 Alibaba Cloud. All Rights Reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//! Miniball built with dragonball-sandbox and rust-vmm components and minimal glue.
#![deny(missing_docs)]

use std::convert::TryFrom;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, stdin};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kvm_bindings::KVM_API_VERSION;
use kvm_ioctls::{
    Cap::{self, Ioeventfd, Irqchip, Irqfd, UserMemory},
    Kvm,
};
use linux_loader::cmdline;
#[cfg(target_arch = "x86_64")]
use linux_loader::configurator;
use linux_loader::loader::{self, KernelLoader, KernelLoaderResult};
#[cfg(target_arch = "x86_64")]
use linux_loader::loader::{
    bzimage::BzImage,
    elf::{self, Elf},
};
use virtio_queue::QueueStateSync;
use vm_allocator::AllocPolicy;
use vm_memory::atomic::GuestMemoryAtomic;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, GuestRegionMmap};
use vmm_sys_util::{eventfd::EventFd, terminal::Terminal};

use dbs_address_space::{AddressSpace, AddressSpaceLayout, AddressSpaceRegion};
use dbs_boot::layout;
use dbs_device::device_manager::{Error as IoManagerError, IoManager};
use dbs_device::resources::{Resource, ResourceConstraint};
use dbs_device::DeviceIo;
use dbs_interrupt::KvmIrqManager;
#[cfg(target_arch = "x86_64")]
use dbs_legacy_devices::SerialDevice;
#[cfg(target_arch = "x86_64")]
use dbs_legacy_devices::{EventFdTrigger, I8042Device, I8042DeviceMetrics};
use dbs_utils::epoll_manager::{EpollManager, EventOps, EventSet, Events, MutEventSubscriber};
use dbs_virtio_devices::{
    block::{aio::Aio, io_uring::IoUring, Block, LocalFile, Ufile},
    mmio::{
        MmioV2Device, DRAGONBALL_FEATURE_INTR_USED, DRAGONBALL_FEATURE_PER_QUEUE_NOTIFY,
        DRAGONBALL_MMIO_DOORBELL_SIZE, MMIO_DEFAULT_CFG_SIZE,
    },
    VirtioDevice,
};

use crate::boot::build_bootparams;
pub use crate::config::*;
use crate::device_manager::{
    self, console_manager::ConsoleManager, resource_manager::ResourceManager,
};
use vm_vcpu::vm::{self, ExitHandler, KvmVm, VmConfig};

/// Size of the MMIO gap.
#[cfg(target_arch = "x86_64")]
pub const MMIO_GAP_SIZE: u64 = layout::MMIO_LOW_END - layout::MMIO_LOW_START;
/// Default address for loading the kernel.
#[cfg(target_arch = "x86_64")]
pub const DEFAULT_KERNEL_LOAD_ADDR: u64 = layout::HIMEM_START;
/// Default kernel command line.
#[cfg(target_arch = "x86_64")]
pub const DEFAULT_KERNEL_CMDLINE: &str = "panic=1 pci=off";
/// Default address allocator alignment. It needs to be a power of 2.
pub const DEFAULT_ADDRESSS_ALIGNEMNT: u64 = 4;
/// Default allocation policy for address allocator.
pub const DEFAULT_ALLOC_POLICY: AllocPolicy = AllocPolicy::FirstMatch;

/// The I8042 Data Port (IO Port 0x60) is used for reading data that was received from a I8042 device or from the I8042 controller itself and writing data to a I8042 device or to the I8042 controller itself.
#[cfg(target_arch = "x86_64")]
pub const I8042_DATA_PORT: u16 = 0x60;

/// Register its interrupt fd with KVM. IRQ line 4 is typically used for serial port 1.
pub const COM1_IRQ: u32 = 4;
/// The base port address for the COM devices
pub const COM1_PORT1: u16 = 0x3f8;

/// Default queue size for VirtIo block devices.
pub const QUEUE_SIZE: u32 = 128;

/// VMM memory related errors.
#[derive(Debug)]
pub enum MemoryError {
    /// Not enough memory slots.
    NotEnoughMemorySlots,
    /// AddressAllocatorError
    AddressAllocatorError(vm_allocator::Error),
    /// Failed to configure guest memory.
    VmMemory(vm_memory::Error),
}

/// VMM errors.
#[derive(Debug)]
pub enum Error {
    /// Failed to write boot parameters to guest memory.
    #[cfg(target_arch = "x86_64")]
    BootConfigure(configurator::Error),
    /// Error configuring boot parameters.
    #[cfg(target_arch = "x86_64")]
    BootParam(crate::boot::Error),
    /// Error configuring the kernel command line.
    Cmdline(cmdline::Error),
    /// Error setting up the serial device.
    SerialDevice,
    /// Event management error.
    EventManager(event_manager::Error),
    /// I/O error.
    IO(io::Error),
    /// Failed to load kernel.
    KernelLoad(loader::Error),
    /// Address stored in the rip registry does not fit in guest memory.
    RipOutOfGuestMemory,
    /// Invalid KVM API version.
    KvmApiVersion(i32),
    /// Unsupported KVM capability.
    KvmCap(Cap),
    /// Error issuing an ioctl to KVM.
    KvmIoctl(kvm_ioctls::Error),
    /// Memory error.
    Memory(MemoryError),
    /// VM errors.
    Vm(vm::Error),
    /// Exit event errors.
    ExitEvent(io::Error),
    #[cfg(target_arch = "x86_64")]
    /// Cannot retrieve the supported MSRs.
    GetSupportedMsrs(dbs_arch::msr::Error),
    /// Cannot load command line string.
    LoadCommandline(linux_loader::loader::Error),
    /// Cannot add legacy device to Bus.
    BusError(dbs_device::device_manager::Error),
    /// Cannot create EventFd.
    EventFd(io::Error),
    /// Failed to register/deregister interrupt.
    IrqManager(vm_vcpu::vm::Error),
    /// Failed to get device resource.
    GetDeviceResource,
    /// Failed to perform an operation on the bus.
    IoManager(IoManagerError),
    /// No resource available.
    NoAvailResource,
    /// Failed to create block device.
    Block(dbs_virtio_devices::Error),
    /// Error from Virtio subsystem.
    Virtio(dbs_virtio_devices::Error),
    /// Resource constraint type error
    ResourceConstraintType,
    /// Cannot set mode for terminal.
    StdinHandle(vmm_sys_util::errno::Error),
    /// The device manager was not configured.
    DeviceManager(device_manager::DeviceMgrError),
}

impl std::convert::From<vm::Error> for Error {
    fn from(vm_error: vm::Error) -> Self {
        Self::Vm(vm_error)
    }
}

impl From<vm_allocator::Error> for Error {
    fn from(error: vm_allocator::Error) -> Self {
        Error::Memory(MemoryError::AddressAllocatorError(error))
    }
}

/// Dedicated [`Result`](https://doc.rust-lang.org/std/result/) type.
pub type Result<T> = std::result::Result<T, Error>;

type BlockDevice = Block<GuestMemoryAtomic<GuestMemoryMmap>>;

/// Type of the miniball virtio devices.
pub type DbsVirtioDevice =
    Box<dyn VirtioDevice<GuestMemoryAtomic<GuestMemoryMmap>, QueueStateSync, GuestRegionMmap>>;

/// Type of the dragonball virtio mmio devices.
pub type DbsMmioV2Device =
    MmioV2Device<GuestMemoryAtomic<GuestMemoryMmap>, QueueStateSync, GuestRegionMmap>;

/// A live VMM.
pub struct Vmm {
    vm: KvmVm<WrappedExitHandler>,
    kernel_cfg: KernelConfig,
    guest_memory: GuestMemoryMmap,
    address_space: AddressSpace,
    resource_mgr: ResourceManager,
    // The `device_mgr` is an Arc<Mutex> so that it can be shared between
    // the Vcpu threads, and modified when new devices are added.
    device_mgr: Arc<Mutex<IoManager>>,
    // Arc<Mutex<>> because the same device (a dyn DevicePio/DeviceMmio from IoManager's
    // perspective, and a dyn MutEventSubscriber from EventManager's) is managed by the 2 entities,
    // and isn't Copy-able; so once one of them gets ownership, the other one can't anymore.
    event_mgr: EpollManager,
    irq_mgr: Arc<KvmIrqManager>,
    con_manager: ConsoleManager,
    exit_handler: WrappedExitHandler,
    block_devices: Vec<Arc<DbsMmioV2Device>>,
}

// The `VmmExitHandler` is used as the mechanism for exiting from the event manager loop.
// The Vm is notifying us through the `kick` method when it exited. Once the Vm finished
// the execution, it is time for the event manager loop to also exit. This way, we can
// terminate the VMM process cleanly.
struct VmmExitHandler {
    exit_event: EventFd,
    keep_running: AtomicBool,
}

// The wrapped exit handler is needed because the ownership of the inner `VmmExitHandler` is
// shared between the `KvmVm` and the `EventManager`. Clone is required for implementing the
// `ExitHandler` trait.
#[derive(Clone)]
struct WrappedExitHandler(Arc<Mutex<VmmExitHandler>>);

impl WrappedExitHandler {
    fn new() -> Result<WrappedExitHandler> {
        Ok(WrappedExitHandler(Arc::new(Mutex::new(VmmExitHandler {
            exit_event: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::ExitEvent)?,
            keep_running: AtomicBool::new(true),
        }))))
    }

    fn keep_running(&self) -> bool {
        self.0.lock().unwrap().keep_running.load(Ordering::Acquire)
    }
}

impl ExitHandler for WrappedExitHandler {
    fn kick(&self) -> io::Result<()> {
        self.0.lock().unwrap().exit_event.write(1)
    }
}

impl MutEventSubscriber for VmmExitHandler {
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        if events.event_set().contains(EventSet::IN) {
            self.keep_running.store(false, Ordering::Release);
        }
        if events.event_set().contains(EventSet::ERROR) {
            // We cannot do much about the error (besides log it).
            // TODO: log this error once we have a logger set up.
            let _ = ops.remove(Events::new(&self.exit_event, EventSet::IN));
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        ops.add(Events::new(&self.exit_event, EventSet::IN))
            .expect("Cannot initialize exit handler.");
    }
}

impl TryFrom<VMMConfig> for Vmm {
    type Error = Error;

    fn try_from(config: VMMConfig) -> Result<Self> {
        let kvm = Kvm::new().map_err(Error::KvmIoctl)?;

        // Check that the KVM on the host is supported.
        let kvm_api_ver = kvm.get_api_version();
        if kvm_api_ver != KVM_API_VERSION as i32 {
            return Err(Error::KvmApiVersion(kvm_api_ver));
        }
        Vmm::check_kvm_capabilities(&kvm)?;

        let guest_memory = Vmm::create_guest_memory(&config.memory_config)?;
        let address_space = Vmm::create_address_space(&config.memory_config)?;
        let resource_mgr = Vmm::create_resource_manager()?;
        let device_mgr = Arc::new(Mutex::new(IoManager::new()));

        // Create the KvmVm.
        let vm_config = VmConfig::new(&kvm, config.vcpu_config.num)?;

        let wrapped_exit_handler = WrappedExitHandler::new()?;
        let vm = KvmVm::new(
            &kvm,
            vm_config,
            &guest_memory,
            wrapped_exit_handler.clone(),
            device_mgr.clone(),
        )?;
        let irq_mgr = Arc::new(KvmIrqManager::new(vm.vm_fd()));

        let event_manager = EpollManager::default();
        event_manager.add_subscriber(Box::new(wrapped_exit_handler.0.clone()));

        let logger = slog_scope::logger().new(slog::o!("vmm" => "Miniball"));

        let con_manager = ConsoleManager::new(event_manager.clone(), &logger);

        let mut vmm = Vmm {
            vm,
            kernel_cfg: config.kernel_config,
            guest_memory,
            address_space,
            event_mgr: event_manager,
            resource_mgr,
            device_mgr,
            irq_mgr,
            con_manager,
            block_devices: Vec::new(),
            exit_handler: wrapped_exit_handler,
        };

        let serial = vmm.create_serial_console()?;
        vmm.init_serial_console(serial)?;

        #[cfg(target_arch = "x86_64")]
        vmm.add_i8042_device()?;

        if let Some(cfg) = config.block_config.as_ref() {
            vmm.add_block_device(cfg)?;
        }

        Ok(vmm)
    }
}

impl Vmm {
    /// Run the VMM.
    pub fn run(&mut self) -> Result<()> {
        let load_result = self.load_kernel()?;
        #[cfg(target_arch = "x86_64")]
        let kernel_load_addr = self.compute_kernel_load_addr(&load_result)?;

        if stdin().lock().set_raw_mode().is_err() {
            eprintln!("Failed to set raw mode on terminal. Stdin will echo.");
        }

        self.vm.run(Some(kernel_load_addr)).map_err(Error::Vm)?;
        loop {
            match self.event_mgr.handle_events(-1) {
                Ok(_) => (),
                Err(e) => eprintln!("Failed to handle events: {:?}", e),
            }
            if !self.exit_handler.keep_running() {
                break;
            }
        }
        self.vm.shutdown();

        Ok(())
    }

    // Create guest memory regions.
    fn create_guest_memory(memory_config: &MemoryConfig) -> Result<GuestMemoryMmap> {
        let mem_size = ((memory_config.size_mib as u64) << 20) as usize;
        let mem_regions = Vmm::create_memory_regions(mem_size);

        // Create guest memory from regions.
        GuestMemoryMmap::from_ranges(&mem_regions)
            .map_err(|e| Error::Memory(MemoryError::VmMemory(e)))
    }

    fn create_memory_regions(mem_size: usize) -> Vec<(GuestAddress, usize)> {
        #[cfg(target_arch = "x86_64")]
        // On x86_64, they surround the MMIO gap (dedicated space for MMIO device slots) if the
        // configured memory size exceeds the latter's starting address.
        match mem_size.checked_sub(layout::MMIO_LOW_START as usize) {
            // Guest memory fits before the MMIO gap.
            None | Some(0) => vec![(GuestAddress(0), mem_size)],
            // Guest memory extends beyond the MMIO gap.
            Some(remaining) => vec![
                (GuestAddress(0), layout::MMIO_LOW_START as usize),
                (GuestAddress(layout::MMIO_LOW_END), remaining),
            ],
        }
    }

    fn create_address_space(memory_config: &MemoryConfig) -> Result<AddressSpace> {
        let mem_size = ((memory_config.size_mib as u64) << 20) as usize;
        // create several memory regions
        let reg = Arc::new(
            AddressSpaceRegion::create_default_memory_region(
                GuestAddress(layout::GUEST_MEM_START),
                mem_size as u64,
                None,
                "shmem",
                "",
                false,
                false,
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

    fn create_resource_manager() -> Result<ResourceManager> {
        let resource_mgr = ResourceManager::new(None);
        Ok(resource_mgr)
    }

    // Load the kernel into guest memory.
    #[cfg(target_arch = "x86_64")]
    fn load_kernel(&mut self) -> Result<KernelLoaderResult> {
        let mut kernel_image = File::open(&self.kernel_cfg.path).map_err(Error::IO)?;

        // Load the kernel into guest memory.
        let kernel_load = match Elf::load(
            &self.guest_memory,
            None,
            &mut kernel_image,
            Some(GuestAddress(self.kernel_cfg.load_addr)),
        ) {
            Ok(result) => result,
            Err(loader::Error::Elf(elf::Error::InvalidElfMagicNumber)) => BzImage::load(
                &self.guest_memory,
                None,
                &mut kernel_image,
                Some(GuestAddress(self.kernel_cfg.load_addr)),
            )
            .map_err(Error::KernelLoad)?,
            Err(e) => {
                return Err(Error::KernelLoad(e));
            }
        };

        // Load the kernel command line into guest memory.
        let cmdline_addr = dbs_boot::layout::CMDLINE_START;
        linux_loader::loader::load_cmdline(
            &self.guest_memory,
            GuestAddress(cmdline_addr),
            &self.kernel_cfg.cmdline,
        )
        .map_err(Error::LoadCommandline)?;

        // Generate boot parameters.
        build_bootparams(
            &self.guest_memory,
            &self.address_space,
            GuestAddress(self.kernel_cfg.load_addr),
            GuestAddress(layout::MMIO_LOW_START),
            GuestAddress(layout::MMIO_LOW_END),
            GuestAddress(cmdline_addr),
            (self.kernel_cfg.cmdline.as_str().len() + 1) as usize,
        )
        .map_err(Error::BootParam)?;

        Ok(kernel_load)
    }

    // Create and add a serial console to the VMM.
    fn create_serial_console(&mut self) -> Result<Arc<Mutex<SerialDevice>>> {
        // Create the serial console.
        let interrupt_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let serial = Arc::new(Mutex::new(SerialDevice::new(
            interrupt_evt.try_clone().map_err(Error::EventFd)?,
        )));

        // port_base defines the base port address for the COM devices.
        // Since every COM device has 8 data registers so we register the pio address range as size 0x8.
        let resources = [Resource::PioAddressRange {
            base: COM1_PORT1,
            size: 0x8,
        }];

        self.device_mgr
            .lock()
            .unwrap()
            .register_device_io(serial.clone(), &resources)
            .map_err(Error::BusError)?;

        // Register its interrupt fd with KVM. IRQ line 4 is typically used for serial port 1.
        // See more IRQ assignments & info: https://tldp.org/HOWTO/Serial-HOWTO-8.html
        self.vm
            .register_irqfd(&interrupt_evt, COM1_IRQ)
            .map_err(Error::IrqManager)?;

        self.kernel_cfg
            .cmdline
            .insert_str("console=ttyS0")
            .map_err(Error::Cmdline)?;

        Ok(serial)
    }

    // Init legacy devices with logger stream in associted virtual machine.
    fn init_serial_console(&mut self, serial: Arc<Mutex<SerialDevice>>) -> Result<()> {
        self.con_manager
            .create_stdio_console(serial)
            .map_err(Error::DeviceManager)?;

        Ok(())
    }

    // Create and add a i8042 device to the VMM.
    #[cfg(target_arch = "x86_64")]
    fn add_i8042_device(&mut self) -> Result<()> {
        let reset_evt =
            EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?);
        let i8042_device = Arc::new(Mutex::new(I8042Device::new(
            reset_evt.try_clone().map_err(Error::EventFd)?,
            Arc::new(I8042DeviceMetrics::default()),
        )));

        self.vm.register_irqfd(&reset_evt, 1)?;

        let resources = [Resource::PioAddressRange {
            // 0x60 and 0x64 are the io ports that i8042 devices used.
            // We register pio address range from 0x60 - 0x64 with base I8042_DATA_PORT for i8042 to use.
            base: I8042_DATA_PORT,
            size: 0x5,
        }];

        self.device_mgr
            .lock()
            .unwrap()
            .register_device_io(i8042_device, &resources)
            .map_err(Error::BusError)?;

        Ok(())
    }

    fn add_block_device(&mut self, cfg: &BlockConfig) -> Result<()> {
        let mut block_files: Vec<Box<dyn Ufile>> = vec![];
        let is_read_only = true;
        let io_uring_supported = IoUring::is_supported();
        let file = OpenOptions::new()
            .read(true)
            .write(!is_read_only)
            .open(&cfg.path)
            .unwrap();

        let queue_size = QUEUE_SIZE;

        if io_uring_supported {
            let io_engine = IoUring::new(file.as_raw_fd(), queue_size).unwrap();
            block_files.push(Box::new(LocalFile::new(file, false, io_engine).unwrap()));
        } else {
            let io_engine = Aio::new(file.as_raw_fd(), queue_size).unwrap();
            block_files.push(Box::new(LocalFile::new(file, false, io_engine).unwrap()));
        }

        let is_disk_read_only = true;

        let block = Box::new(
            BlockDevice::new(
                block_files,
                is_disk_read_only,
                Arc::new(vec![128]),
                self.event_mgr.clone(),
                vec![],
            )
            .map_err(Error::Block)?,
        );

        let block = self.create_mmio_virtio_device(block).unwrap();

        self.generate_kernel_boot_args(block.clone())?;

        self.block_devices.push(block);

        Ok(())
    }

    fn create_mmio_virtio_device(
        &mut self,
        device: DbsVirtioDevice,
    ) -> Result<Arc<DbsMmioV2Device>> {
        let use_shared_irq = false;
        let use_generic_irq = true;

        let features = DRAGONBALL_FEATURE_INTR_USED | DRAGONBALL_FEATURE_PER_QUEUE_NOTIFY;

        // Every emulated Virtio MMIO device needs a 4K configuration space,
        // and another 4K space for per queue notification.
        const MMIO_ADDRESS_DEFAULT: ResourceConstraint = ResourceConstraint::MmioAddress {
            range: None,
            align: 0,
            size: MMIO_DEFAULT_CFG_SIZE + DRAGONBALL_MMIO_DOORBELL_SIZE,
        };

        let mut requests = vec![MMIO_ADDRESS_DEFAULT];
        device.get_resource_requirements(&mut requests, use_generic_irq);
        let resources = self
            .resource_mgr
            .allocate_device_resources(&requests, use_shared_irq)
            .map_err(|_| Error::GetDeviceResource)?;

        let virtio_dev = match MmioV2Device::new(
            self.vm.vm_fd(),
            GuestMemoryAtomic::new(self.guest_memory.clone()),
            self.irq_mgr.clone(),
            device,
            resources.clone(),
            Some(features),
        ) {
            Ok(d) => Arc::new(d),
            Err(e) => return Err(Error::Virtio(e)),
        };

        // Register mmio device.
        self.device_mgr
            .lock()
            .unwrap()
            .register_device_io(virtio_dev.clone(), &resources)
            .map_err(Error::BusError)?;

        Ok(virtio_dev)
    }

    // Generated guest kernel commandline related to root block device.
    fn generate_kernel_boot_args(
        &mut self,
        device: Arc<DbsMmioV2Device>,
    ) -> std::result::Result<(), Error> {
        // set root path
        self.kernel_cfg
            .cmdline
            .insert("root", "/dev/vda")
            .map_err(Error::Cmdline)?;

        // set read only
        self.kernel_cfg
            .cmdline
            .insert_str("ro")
            .map_err(Error::Cmdline)?;

        // get device information
        let (mmio_base, mmio_size, irq) = self.get_virtio_device_info(&device)?;

        // as per doc, [virtio_mmio.]device=<size>@<baseaddr>:<irq> needs to be appended
        // to kernel commandline for virtio mmio devices to get recognized
        // the size parameter has to be transformed to KiB, so dividing hexadecimal value in
        // bytes to 1024; further, the '{}' formatting rust construct will automatically
        // transform it to decimal
        self.kernel_cfg
            .cmdline
            .insert(
                "virtio_mmio.device",
                &format!("{}K@0x{:08x}:{}", mmio_size / 1024, mmio_base, irq),
            )
            .map_err(Error::Cmdline)?;

        Ok(())
    }

    fn get_virtio_device_info(&mut self, device: &Arc<DbsMmioV2Device>) -> Result<(u64, u64, u32)> {
        let resources = device.get_assigned_resources();
        let irq = resources.get_legacy_irq().ok_or(Error::GetDeviceResource)?;
        let mmio_address_range = device.get_trapped_io_resources().get_mmio_address_ranges();

        // Assume the first MMIO region is virtio configuration region.
        // Virtio-fs needs to pay attention to this assumption.
        if let Some(range) = mmio_address_range.into_iter().next() {
            Ok((range.0, range.1, irq))
        } else {
            Err(Error::GetDeviceResource)
        }
    }

    // Helper function that computes the kernel_load_addr needed by the
    // VcpuState when creating the Vcpus.
    #[cfg(target_arch = "x86_64")]
    fn compute_kernel_load_addr(&self, kernel_load: &KernelLoaderResult) -> Result<GuestAddress> {
        // If the kernel format is bzImage, the real-mode code is offset by
        // 0x200, so that's where we have to point the rip register for the
        // first instructions to execute.
        // See https://www.kernel.org/doc/html/latest/x86/boot.html#memory-layout
        //
        // The kernel is a bzImage kernel if the protocol >= 2.00 and the 0x01
        // bit (LOAD_HIGH) in the loadflags field is set.
        let mut kernel_load_addr = self
            .guest_memory
            .check_address(kernel_load.kernel_load)
            .ok_or(Error::RipOutOfGuestMemory)?;
        if let Some(hdr) = kernel_load.setup_header {
            if hdr.version >= 0x200 && hdr.loadflags & 0x1 == 0x1 {
                // Yup, it's bzImage.
                kernel_load_addr = self
                    .guest_memory
                    .checked_offset(kernel_load_addr, 0x200)
                    .ok_or(Error::RipOutOfGuestMemory)?;
            }
        }

        Ok(kernel_load_addr)
    }

    fn check_kvm_capabilities(kvm: &Kvm) -> Result<()> {
        let capabilities = vec![Irqchip, Ioeventfd, Irqfd, UserMemory];

        // Check that all desired capabilities are supported.
        if let Some(c) = capabilities
            .iter()
            .find(|&capability| !kvm.check_extension(*capability))
        {
            Err(Error::KvmCap(*c))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    #[cfg(target_arch = "x86_64")]
    use std::path::Path;
    use std::path::PathBuf;

    #[cfg(target_arch = "x86_64")]
    use linux_loader::elf::Elf64_Ehdr;
    #[cfg(target_arch = "x86_64")]
    use linux_loader::loader::{self, bootparam::setup_header, elf::PvhBootCapability};
    #[cfg(target_arch = "x86_64")]
    use vm_memory::{
        bytes::{ByteValued, Bytes},
        Address, GuestAddress, GuestMemory,
    };
    use vmm_sys_util::{tempdir::TempDir, tempfile::TempFile};

    use super::*;
    use utils::resource_download::s3_download;

    const MEM_SIZE_MIB: u32 = 1024;
    const NUM_VCPUS: u8 = 1;

    #[cfg(target_arch = "x86_64")]
    fn default_bzimage_path() -> PathBuf {
        let tags = r#"
        {
            "halt_after_boot": true,
            "image_format": "bzimage"
        }
        "#;
        s3_download("kernel", Some(tags)).unwrap()
    }

    fn default_elf_path() -> PathBuf {
        let tags = r#"
        {
            "halt_after_boot": true,
            "image_format": "elf"
        }
        "#;
        s3_download("kernel", Some(tags)).unwrap()
    }

    fn default_vmm_config() -> VMMConfig {
        VMMConfig {
            kernel_config: KernelConfig {
                #[cfg(target_arch = "x86_64")]
                path: default_elf_path(),
                load_addr: DEFAULT_KERNEL_LOAD_ADDR,
                cmdline: KernelConfig::default_cmdline(),
            },
            memory_config: MemoryConfig {
                size_mib: MEM_SIZE_MIB,
            },
            vcpu_config: VcpuConfig { num: NUM_VCPUS },
            block_config: None,
            net_config: None,
        }
    }

    fn default_exit_handler() -> WrappedExitHandler {
        WrappedExitHandler(Arc::new(Mutex::new(VmmExitHandler {
            keep_running: AtomicBool::default(),
            exit_event: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        })))
    }

    // Returns a VMM which only has the memory configured. The purpose of the mock VMM
    // is to give a finer grained control to test individual private functions in the VMM.
    fn mock_vmm(vmm_config: VMMConfig) -> Vmm {
        let kvm = Kvm::new().unwrap();
        let guest_memory = Vmm::create_guest_memory(&vmm_config.memory_config).unwrap();
        let address_space = Vmm::create_address_space(&vmm_config.memory_config).unwrap();
        let resource_mgr = Vmm::create_resource_manager().unwrap();

        // Create the KvmVm.
        let vm_config = VmConfig::new(&kvm, vmm_config.vcpu_config.num).unwrap();
        let device_mgr = Arc::new(Mutex::new(IoManager::new()));
        let exit_handler = default_exit_handler();
        let vm = KvmVm::new(
            &kvm,
            vm_config,
            &guest_memory,
            exit_handler.clone(),
            device_mgr.clone(),
        )
        .unwrap();

        let event_manager = EpollManager::default();

        let logger = slog_scope::logger().new(slog::o!("vmm" => "Miniball"));
        let con_manager = ConsoleManager::new(event_manager.clone(), &logger);

        let irq_mgr = Arc::new(KvmIrqManager::new(vm.vm_fd()));

        Vmm {
            vm,
            kernel_cfg: vmm_config.kernel_config,
            guest_memory,
            address_space,
            resource_mgr,
            device_mgr,
            event_mgr: event_manager,
            irq_mgr,
            con_manager,
            exit_handler,
            block_devices: Vec::new(),
        }
    }

    // Return the address where an ELF file should be loaded, as specified in its header.
    #[cfg(target_arch = "x86_64")]
    fn elf_load_addr(elf_path: &Path) -> GuestAddress {
        let mut elf_file = File::open(elf_path).unwrap();
        let mut ehdr = Elf64_Ehdr::default();
        ehdr.as_bytes()
            .read_from(0, &mut elf_file, std::mem::size_of::<Elf64_Ehdr>())
            .unwrap();
        GuestAddress(ehdr.e_entry)
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_compute_kernel_load_addr() {
        let vmm_config = default_vmm_config();
        let vmm = mock_vmm(vmm_config);

        // ELF (vmlinux) kernel scenario: happy case
        let mut kern_load = KernelLoaderResult {
            kernel_load: GuestAddress(layout::HIMEM_START), // 1 MiB.
            kernel_end: 0,                                  // doesn't matter.
            setup_header: None,
            pvh_boot_cap: PvhBootCapability::PvhEntryNotPresent,
        };
        let actual_kernel_load_addr = vmm.compute_kernel_load_addr(&kern_load).unwrap();
        let expected_load_addr = kern_load.kernel_load;
        assert_eq!(actual_kernel_load_addr, expected_load_addr);

        kern_load.kernel_load = GuestAddress(vmm.guest_memory.last_addr().raw_value() + 1);
        assert!(matches!(
            vmm.compute_kernel_load_addr(&kern_load),
            Err(Error::RipOutOfGuestMemory)
        ));

        // bzImage kernel scenario: happy case
        // The difference is that kernel_load.setup_header is no longer None, because we found one
        // while parsing the bzImage file.
        kern_load.kernel_load = GuestAddress(0x0100_0000); // 1 MiB.
        kern_load.setup_header = Some(setup_header {
            version: 0x0200, // 0x200 (v2.00) is the minimum.
            loadflags: 1,
            ..Default::default()
        });
        let expected_load_addr = kern_load.kernel_load.unchecked_add(0x200);
        let actual_kernel_load_addr = vmm.compute_kernel_load_addr(&kern_load).unwrap();
        assert_eq!(expected_load_addr, actual_kernel_load_addr);

        // bzImage kernel scenario: error case: kernel_load + 0x200 (512 - size of bzImage header)
        // falls out of guest memory
        kern_load.kernel_load = GuestAddress(vmm.guest_memory.last_addr().raw_value() - 511);
        assert!(matches!(
            vmm.compute_kernel_load_addr(&kern_load),
            Err(Error::RipOutOfGuestMemory)
        ));
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_load_kernel() {
        // Test Case: load a valid elf.
        let mut vmm_config = default_vmm_config();
        vmm_config.kernel_config.path = default_elf_path();
        // ELF files start with a header that tells us where they want to be loaded.
        let kernel_load = elf_load_addr(&vmm_config.kernel_config.path);
        let mut vmm = mock_vmm(vmm_config);
        let kernel_load_result = vmm.load_kernel().unwrap();
        assert_eq!(kernel_load_result.kernel_load, kernel_load);
        assert!(kernel_load_result.setup_header.is_none());

        // Test case: load a valid bzImage.
        let mut vmm_config = default_vmm_config();
        vmm_config.kernel_config.path = default_bzimage_path();
        let mut vmm = mock_vmm(vmm_config);
        let kernel_load_result = vmm.load_kernel().unwrap();
        assert_eq!(
            kernel_load_result.kernel_load,
            GuestAddress(layout::HIMEM_START)
        );
        assert!(kernel_load_result.setup_header.is_some());
    }

    #[test]
    fn test_load_kernel_errors() {
        // Test case: kernel file does not exist.
        let mut vmm_config = default_vmm_config();
        vmm_config.kernel_config.path = PathBuf::from(TempFile::new().unwrap().as_path());
        let mut vmm = mock_vmm(vmm_config);
        assert!(
            matches!(vmm.load_kernel().unwrap_err(), Error::IO(e) if e.kind() == ErrorKind::NotFound)
        );

        // Test case: kernel image is invalid.
        let mut vmm_config = default_vmm_config();
        let temp_file = TempFile::new().unwrap();
        vmm_config.kernel_config.path = PathBuf::from(temp_file.as_path());
        let mut vmm = mock_vmm(vmm_config);

        let err = vmm.load_kernel().unwrap_err();
        #[cfg(target_arch = "x86_64")]
        assert!(matches!(
            err,
            Error::KernelLoad(loader::Error::Bzimage(
                loader::bzimage::Error::InvalidBzImage
            ))
        ));

        // Test case: kernel path doesn't point to a file.
        let mut vmm_config = default_vmm_config();
        let temp_dir = TempDir::new().unwrap();
        vmm_config.kernel_config.path = PathBuf::from(temp_dir.as_path());
        let mut vmm = mock_vmm(vmm_config);
        let err = vmm.load_kernel().unwrap_err();

        #[cfg(target_arch = "x86_64")]
        assert!(matches!(
            err,
            Error::KernelLoad(loader::Error::Elf(loader::elf::Error::ReadElfHeader))
        ));
    }

    #[test]
    fn test_cmdline_updates() {
        let mut vmm_config = default_vmm_config();
        vmm_config.kernel_config.path = default_elf_path();
        let mut vmm = mock_vmm(vmm_config);
        assert_eq!(vmm.kernel_cfg.cmdline.as_str(), DEFAULT_KERNEL_CMDLINE);
        vmm.create_serial_console().unwrap();
        #[cfg(target_arch = "x86_64")]
        assert!(vmm.kernel_cfg.cmdline.as_str().contains("console=ttyS0"));
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_create_guest_memory() {
        // Guest memory ends exactly at the MMIO gap: should succeed (last addressable value is
        // layout::MMIO_LOW_START - 1). There should be 1 memory region.
        let mut mem_cfg = MemoryConfig {
            size_mib: (layout::MMIO_LOW_START >> 20) as u32,
        };
        let guest_mem = Vmm::create_guest_memory(&mem_cfg).unwrap();
        assert_eq!(guest_mem.num_regions(), 1);
        assert_eq!(
            guest_mem.last_addr(),
            GuestAddress(layout::MMIO_LOW_START - 1)
        );

        // Guest memory ends exactly past the MMIO gap: not possible because it's specified in MiB.
        // But it can end 1 MiB within the MMIO gap. Should succeed.
        // There will be 2 regions, the 2nd ending at `size_mib << 20 + MMIO_GAP_SIZE`.
        mem_cfg.size_mib = (layout::MMIO_LOW_START >> 20) as u32 + 1;
        let guest_mem = Vmm::create_guest_memory(&mem_cfg).unwrap();
        assert_eq!(guest_mem.num_regions(), 2);
        assert_eq!(
            guest_mem.last_addr(),
            GuestAddress(layout::MMIO_LOW_START + MMIO_GAP_SIZE + (1 << 20) - 1)
        );

        // Guest memory ends exactly at the MMIO gap end: should succeed. There will be 2 regions,
        // the 2nd ending at `size_mib << 20 + MMIO_GAP_SIZE`.
        mem_cfg.size_mib = ((layout::MMIO_LOW_START + MMIO_GAP_SIZE) >> 20) as u32;
        let guest_mem = Vmm::create_guest_memory(&mem_cfg).unwrap();
        assert_eq!(guest_mem.num_regions(), 2);
        assert_eq!(
            guest_mem.last_addr(),
            GuestAddress(layout::MMIO_LOW_START + 2 * MMIO_GAP_SIZE - (1 << 20))
        );

        // Guest memory ends 1 MiB past the MMIO gap end: should succeed. There will be 2 regions,
        // the 2nd ending at `size_mib << 20 + MMIO_GAP_SIZE`.
        mem_cfg.size_mib = ((layout::MMIO_LOW_START + MMIO_GAP_SIZE) >> 20) as u32 + 1;
        let guest_mem = Vmm::create_guest_memory(&mem_cfg).unwrap();
        assert_eq!(guest_mem.num_regions(), 2);
        assert_eq!(
            guest_mem.last_addr(),
            GuestAddress(layout::MMIO_LOW_START + 2 * MMIO_GAP_SIZE)
        );

        // Guest memory size is 0: should fail, rejected by vm-memory with EINVAL.
        mem_cfg.size_mib = 0u32;
        assert!(matches!(
            Vmm::create_guest_memory(&mem_cfg),
            Err(Error::Memory(MemoryError::VmMemory(vm_memory::Error::MmapRegion(vm_memory::mmap::MmapRegionError::Mmap(e)))))
            if e.kind() == ErrorKind::InvalidInput
        ));
    }
    #[test]
    fn test_create_vcpus() {
        // The scopes force the created vCPUs to unmap their kernel memory at the end.
        let mut vmm_config = default_vmm_config();
        vmm_config.vcpu_config = VcpuConfig { num: 0 };

        // Creating 0 vCPUs throws an error.
        {
            assert!(matches!(
                Vmm::try_from(vmm_config.clone()),
                Err(Error::Vm(vm::Error::CreateVmConfig(
                    vm_vcpu::vcpu::Error::VcpuNumber(0)
                )))
            ));
        }

        // Creating one works.
        vmm_config.vcpu_config = VcpuConfig { num: 1 };
        {
            assert!(Vmm::try_from(vmm_config.clone()).is_ok());
        }

        // Creating 254 also works (that's the maximum number on x86 when using MP Table).
        vmm_config.vcpu_config = VcpuConfig { num: 254 };
        Vmm::try_from(vmm_config).unwrap();
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    // FIXME: We cannot run this on aarch64 because we do not have an image that just runs and
    // FIXME-continued: halts afterwards. Once we have this, we need to update `default_vmm_config`
    // FIXME-continued: and have a default PE image on aarch64.
    fn test_add_block() {
        let vmm_config = default_vmm_config();
        let mut vmm = mock_vmm(vmm_config);

        let tempfile = TempFile::new().unwrap();
        let block_config = BlockConfig {
            path: tempfile.as_path().to_path_buf(),
        };

        assert!(vmm.add_block_device(&block_config).is_ok());
        assert_eq!(vmm.block_devices.len(), 1);
        assert!(vmm.kernel_cfg.cmdline.as_str().contains("virtio"));

        let invalid_block_config = BlockConfig {
            // Let's create the tempfile directly here so that it gets out of scope immediately
            // and delete the underlying file.
            path: TempFile::new().unwrap().as_path().to_path_buf(),
        };

        let err = vmm.add_block_device(&invalid_block_config).unwrap_err();
        assert!(matches!(err, Error::Block(_)));
    }
}
