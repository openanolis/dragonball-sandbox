# 设备虚拟化

## 概述
设备虚拟化包含对 legacy 设备的和 virtio block 设备的配置，通过 `dbs-device` 、`dbs-legacy-devices`、`dbs-virtio-devices` crates 完成上述工作。过程中需要 `dbs-allocator`、`dbs-utils::epoll_manager` 等 crates 进行辅助。

## Legacy 设备
在虚拟化环境下，虚拟机与宿主机需要互相通信。Miniball实现了串行控制台（serial console）、键盘（i8042）等legacy设备，这些设备可以直接由虚拟机内核自带驱动程序驱动，并为虚拟机提供基本的输入输出功能。X86架构下，legacy设备主要通过IO端口进行控制和操作，因此Miniball采用IO总线来组织和管理所有的legacy设备。

在 Miniball 中，legacy 设备需要配置串行控制台和键盘 i8042 控制器，串行控制台仿真通过 `dbs-device` 和 `dbs-legacy-devices` crate 完成。设备事件处理通过 `dbs-utils::epoll_manager` 进行调解。

1. 要求：配置 KVM，配置 guest memory，配置irqchip（x86_64），配置 dbs-utils::epoll_manager
1. 输入：无
1. 步骤：
   1. 创建虚拟扬声器。
   1. 创建串行控制台。
   1. 创建 i8042 键盘控制器。

### 虚拟扬声器
在配置 IRQ 时创建虚拟扬声器。需要模拟虚拟扬声器是因为一些内核访问扬声器的端口，没有这个会导致 KVM 不断退出到用户空间。

```rust
#[cfg(target_arch = "x86_64")]
fn setup_irq_controller(&self) -> Result<()> {
    ...

    // The PIT is used during boot to configure the frequency.
    // The output from PIT channel 0 is connected to the PIC chip, so that it
    // generates an "IRQ 0" (system timer).
    // https://wiki.osdev.org/Programmable_Interval_Timer
    let pit_config = kvm_pit_config {
        // Set up the speaker PIT, because some kernels are musical and access the speaker port
        // during boot. Without this, KVM would continuously exit to userspace.
        flags: KVM_PIT_SPEAKER_DUMMY,
        ..Default::default()
        };
    self.fd
        .create_pit2(pit_config)
        .map_err(Error::SetupInterruptController)
    }
```

### 串行控制台
虚拟控制台由两部分组成：虚拟机中的前端和主机操作系统中的后端。 前端可以是 serial port、virtio-console 等，后端可以是 stdio 或 Unix 域套接字。Miniball 中仅展示前端使用 `serial`，后端使用 `stdio` 的情况。`console_manager` 将前端与后端连接起来。为了使 VMM 能够使用串行控制台，除了 `dbs-legacy-devices` crate中介绍的仿真部分之外，VMM 还需要执行以下操作：

- 创建 serial console 设备
- 定义连接串行后端
- 设置中断 IRQ
- cmdline中添加console=ttyS0
- 将串行端口添加到总线（PIO 或 MMIO）
- 事件处理

第 7 ～ 10 行，创建 serial console。第 14 ～ 17 行，创建 PioAddressRange 定义串行端口的地址和大小。第 19 ～ 23 行，注册 serial console。第 27 ～ 29 行，设置 irq 为 COM1_IRQ = 4，console manager 的 irq 为 4。第 31 ～ 34 行，要通过serial类型的console进入虚拟机的console，需要在虚拟机的cmdline中添加console=ttyS0。第 40 行，创建并连接 stdio 后端。第 67 ～ 69 行，通过 epoll_manager 进行事件处理。

```rust
pub const COM1_IRQ: u32 = 4;
pub const COM1_PORT1: u16 = 0x3f8;

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

/// Create a console backend device by using stdio streams.
pub fn create_stdio_console(&mut self, device: Arc<Mutex<SerialDevice>>) -> Result<()> {
    device
        .lock()
        .unwrap()
        .set_output_stream(Some(Box::new(std::io::stdout())));

    let stdin_handle = std::io::stdin();
    stdin_handle
        .lock()
        .set_raw_mode()
        .map_err(|e| DeviceMgrError::ConsoleManager(ConsoleManagerError::StdinHandle(e)))?;

    stdin_handle
        .lock()
        .set_non_block(true)
        .map_err(ConsoleManagerError::StdinHandle)
        .map_err(DeviceMgrError::ConsoleManager)?;

    let handler = ConsoleEpollHandler::new(device, Some(stdin_handle), None, &self.logger);
    self.subscriber_id = Some(self.epoll_mgr.add_subscriber(Box::new(handler)));
    self.backend = Some(Backend::StdinHandle(std::io::stdin()));

    Ok(())
}
```

### 键盘 i8042
I8042 数据端口（IO 端口 0x60）用于读取从 I8042 设备或 I8042 控制器本身接收的数据，并将数据写入 I8042 设备或 I8042 控制器本身。第 11 行，设置 irq 为 1，具有非常高的优先级。第 13 ～ 18 行，0x60 和 0x64 是 i8042 设备使用的 io 端口。将 pio 地址范围从 0x60 - 0x64 注册到 I8042_DATA_PORT 以供 i8042 使用。在 Miniball 中，i8042 PS/2 控制器仅模拟 CPU 复位命令，该命令用于通知 VMM Guest 关闭。

```rust
pub const I8042_DATA_PORT: u16 = 0x60;

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
```

## virtio 设备
### 配置 virtio block
配置 virtio block device。通过 `dbs-virtio-devices` crate 完成的。设备事件处理通过`dbs-utils::epoll_manager` 进行调解。

1. 要求：配置 KVM，配置 guest memory，配置irqchip（x86_64），配置 dbs-utils::epoll_manager。

### 半虚拟化和 Virtio 协议
基于virtio的virtio-blk是KVM-Qemu虚拟化生态中的虚拟化块存储的一种实现方式，利用了virtio共享内存的机制，提供了一种高效的块存储挂载的方法。Guest OS内核通过加载virtio-blk驱动，实现块存储的读写，无需额外的厂家专用驱动。Virtio-blk设备在虚拟机以一个磁盘的方式呈现，是目前应用最广泛的虚拟存储控制器。
虚拟化中对设备的模拟可以分成两类：全模拟和半模拟。全模拟即完全模拟物理设备的工作过程，使得运行在虚拟机上的软件完全感知不到自身运行环境的差异。例如qemu中实现了对IDE磁盘、LSI控制器(其上可接SCSI磁盘)等物理存储设备的模拟，原先运行在物理机上的IDE驱动、LSI驱动或应用程序不做任何改动即可运行在虚拟机中。因此，全模拟的优点比较明显，即不用提供专门针对虚拟化场景的设备驱动，完全可以复用物理环境下的驱动程序。那么全模拟有何缺点呢？全模拟时，虚拟机内部驱动会频繁访问虚拟机IO端口，KVM平台下会导致大量的陷入和陷出操作；另外虚拟机内外数据传输时只能通过以字节为单位的拷贝方式进行，无法直接采用共享内存的方式，因此存在较大的访问性能问题。
为解决全虚拟化在性能上的问题，半模拟技术应运而生。它构造了一种虚拟化环境所独有的存储设备，因此半虚拟化需要在虚拟机内部安装特定的驱动程序才能正常驱使该设备进行工作。通常我们称虚拟机内部的驱动为前端驱动，称负责实现其功能模拟的程序（例如KVM平台下的qemu程序）为后端程序，半模拟技术也常常被叫做前后端技术。采用半摸拟技术后，配合前端驱动，虚拟化设备完全可以采用全新的事件通知和数据传递机制进而大幅提升性能， 例如在virtio-blk磁盘中，采用io_event_fd进行前端到后端通知，采用中断注入方式实现后端到前端的通知，并通过IO环(vring)进行数据的共享。

### virtio-blk
qemu模拟的所有设备都通过总线相连，总线下可挂接若干设备，桥接设备又可生成子总线；整个PC只有一条总线(即Main System Bus，对应前端总线FSB)。因此，qemu内模拟的所有设备构成一棵总线与设备交替衍生的树。虽然virtio-blk仅在虚拟化环境下存在，但如果完全凭空创造一种新的设备类型，那前端驱动开发将是一个很大的挑战。PCI设备是PC中最为常见的一种设备类别，且有较为完善的规范说明，因此可将virtio-blk设备模拟成一种PCI设备，这样可复用虚拟机内部已有的PCI驱动。
virtio-blk设备从功能上来看，核心功能就是实现虚拟机内外的事件通知和数据传递：

- 虚拟机内部的前端驱动准备好待处理的IO请求和数据存放空间并通知后端；
- 虚拟机外部的后端程序获取待处理的请求并交给真正的IO子系统处理，完成后将处理结果通知前端。

实际上，除了虚拟磁盘，虚拟网卡也完全可以复用这套机制，从而实现半模拟的网络前后端(virtio-net)。如果将virtio-blk或virtio-net设计成不同类型的PCI设备，那么前端驱动中会存在大量关于事件通知和数据传递的重复代码。
综上分析，virtio-blk首先是PCI设备；其次为了复用半模拟中通用的事件通知和数据传递机制，抽象出一类virtio-pci设备，其内部通过virtio总线连接不同的virtio设备。这样virtio-blk设备就通过virtio总线连接到virtio-blk-pci设备的PCI接口上，virtio-net也通过virtio总线连接到virtio-net-pci设备的PCI接口上。在virtio-blk-pci或virtio-net-pci前端驱动加载时，最初识别到的都是virtio-pci设备，这样都可调用virtio-pci驱动进行事件通知和数据传递的初始化，后续也可使用virtio-pci中相关函数进行事件通知和数据传递。因此virtio-blk完全是基于通用的virtio框架实现的磁盘前后端，virtio框架中最为核心的就是事件通知和数据传递机制。

### 代码分析
创建 virtio block 设备共需要四步：

1. 创建 virtio block 设备
1. 创建 virtio mmio 设备
1. 注册 virtio mmio 设备
1. 生成 virtio block 的内核命令行参数

#### 创建 virtio block 设备
第 2 ～ 19 行，读取 `/resources/disk/make_rootfs.sh` 构建的一个 1 GiB 磁盘映像，其中包含一个带有 Ubuntu 20.04 映像的 `ext4` 文件系统。第 21 ～ 32 行，创建 block 设备。第 34 行，创建 Mmio 设备并注册。第 36 行，生成 virtio block 的内核命令行参数。第 38 行，保留创建的 virtio block 设备以备后用。

```rust
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
        .unwrap(),
    );

    let block = self.create_mmio_virtio_device(block).unwrap();
    
    self.generate_kernel_boot_args(block.clone())?;

    self.block_devices.push(block);

    Ok(())
}
```

#### 创建并注册 virtio mmio 设备
第 5 ～ 23 行，准备创建 mmio 设备的参数。其中，第 12 ～ 16 行，设置 mmio 的地址和大小，每个模拟的 Virtio MMIO 设备都需要一个 4K 配置空间，以及每个队列通知的另一个 4K 空间。第 18 ～ 19 行，从设备获得需要申请的资源列表。第 20 ～ 23 行，通过基于 `dbs-allocator` 构建的 `resource_manager` 分配资源。第 25 ～ 35 行，创建 MMIO 设备。第 38 ～ 42 行，注册 MMIO 设备。

```rust
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
```

#### 生成 virtio block 的内核命令行参数
第 4 ～ 7 行，设置 rootfs 路径。第 10 ～ 13 行，设置为只读。第 23 ～ 29 行，需要附加 `[virtio_mmio.]device=<size>@<baseaddr>:<irq>` 到内核命令行以便 virtio mmio 设备被识别大小参数必须转换为 KiB，因此除以十六进制以字节为单位的值到 1024。此外，'{}' 格式化 rust 结构会自动将其转换为十进制。

```rust
// Generated guest kernel commandline related to root block device.
fn generate_kernel_boot_args(&mut self, device: Arc<DbsMmioV2Device>) -> std::result::Result<(), Error> {
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
    let irq = resources
        .get_legacy_irq()
        .ok_or(Error::GetDeviceResource)?;
    let mmio_address_range = device.get_trapped_io_resources().get_mmio_address_ranges();

    // Assume the first MMIO region is virtio configuration region.
    // Virtio-fs needs to pay attention to this assumption.
    if let Some(range) = mmio_address_range.into_iter().next() {
        Ok((range.0, range.1, irq))
    } else {
        Err(Error::GetDeviceResource)
    }
}
```
