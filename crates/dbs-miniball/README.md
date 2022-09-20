# Miniball

Miniball is a minimal virtual machine manager. Miniball is the subset 
of the Dragonball Sandbox using components from dragonball-sandbox and rust-vmm.
The purpose of the Miniball Project is to provide anyone who is interested 
in virtualization a good approach to learn it and also test the crates from 
dragonball-sandbox.

## Overview

### Architecture

Miniball contains 2 main crates: 
[`vmm`](https://github.com/openanolis/dragonball-sandbox/tree/main/crates/dbs-miniball/src/vmm) and 
[`api`](https://github.com/openanolis/dragonball-sandbox/tree/main/crates/dbs-miniball/src/api), 
and 2 auxiliary crates: 
[`vm-vcpu`](https://github.com/openanolis/dragonball-sandbox/tree/main/crates/dbs-miniball/src/vm-vcpu),
[`utils`](https://github.com/openanolis/dragonball-sandbox/tree/main/crates/dbs-miniball/src/utils). 
The vmm crate exports an object struct Vmm that encapsulates all the 
dragonball-sandbox crates that provide functionality as dependencies. 
The api provides configuration of vcpu, memory, kernel, block, and CLI. 
The Miniball does not provide runtime configuration changes for the VM, 
it must provide the full VM configuration when the VM starts.

Miniball uses the crates included in [`rust-vmm`](http://github.com/rust-vmm): 
[`kvm-ioctls`](https://crates.io/crates/kvm-ioctls),
[`kvm-bindings`](https://crates.io/crates/kvm-bindings),
[`vm-memory`](https://crates.io/crates/vm-memory),
[`linux-loader`](https://crates.io/crates/linux-loader),
and the crates in [`dragonball-sandbox`](https://github.com/openanolis/dragonball-sandbox): 
[`dbs-address-space`](https://crates.io/crates/dbs-address-space),
[`dbs-allocator`](https://crates.io/crates/dbs-allocator),
[`dbs-boot`](https://crates.io/crates/dbs-boot),
[`dbs-arch`](https://crates.io/crates/dbs-arch),
[`dbs-device`](https://crates.io/crates/dbs-device),
[`dbs-interrupt`](https://crates.io/crates/dbs-interrupt),
[`dbs-legacy-devices`](https://github.com/openanolis/dragonball-sandbox/tree/main/crates/dbs-legacy-devices),
[`dbs-utils`](https://crates.io/crates/dbs-utils) and 
[`dbs-virtio-devices`](https://github.com/openanolis/dragonball-sandbox/tree/main/crates/dbs-virtio-devices).

The Miniball architecture diagram is as follows, showing the relationship 
between the various modules and the crates used by each module.

![Overview](docs/img/overview.png)

## Steps to running a guest

The Miniball obtains the configuration information for starting the VM from 
the input of the CLI, builds the Config (VcpuConfig, MemoryConfig, KernelConfig,
BlockConfig), configures the VM in sequence, and finally loads the kernel into 
the Guest memory and starts the virtual machine. The detailed process is as follows:

1. Set up KVM. This is done through [`kvm-ioctls`](https://crates.io/crates/kvm-ioctls). 
   It creates the KVM virtual machine in the host kernel.

    ```rust
    // src/vmm/src/vmm.rs
    
    let kvm = Kvm::new().map_err(Error::KvmIoctl)?;
    
    // Check that the KVM on the host is supported.
    let kvm_api_ver = kvm.get_api_version();
    if kvm_api_ver != KVM_API_VERSION as i32 {
    return Err(Error::KvmApiVersion(kvm_api_ver));
    }
    Vmm::check_kvm_capabilities(&kvm)?;
    ```

2. Configure guest memory. This is done through the [`vm-memory`](https://crates.io/crates/vm-memory) and 
   [`dbs-address-space`](https://crates.io/crates/dbs-address-space) crates. 
   The `vm-memory` creates and registers the guest memory with KVM.
   The `dbs-address-space` manage guest memory.
   See the [`Memory virtualization documentation`](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-miniball/docs/MemoryVirtualization.md)
   for details on this part.
   1. Requirements: KVM set up
   2. Inputs: 
      1. guest memory size

    ```rust
    // src/vmm/src/vmm.rs
    
    let guest_memory = Vmm::create_guest_memory(&config.memory_config)?;
    let address_space = Vmm::create_address_space(&config.memory_config)?;
    let address_allocator = Vmm::create_address_allocator(&config.memory_config)?;
    ```

3. Configure the vCPUs. This is done through [`vm-vcpu`](https://github.com/openanolis/dragonball-sandbox/tree/main/crates/dbs-miniball/src/vm-vcpu) 
   crate, which is a local crate. This is done partially through [`kvm-ioctls`](https://crates.io/crates/kvm-ioctls), 
   [`dbs-arch`](https://crates.io/crates/dbs-arch) and 
   [`dbs-boot`](https://crates.io/crates/dbs-boot). 
   See the [`CPU virtualization documentation`](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-miniball/docs/CPUVirtualization.md)
   for details on this part.
    
    ```rust
    // src/vmm/src/vmm.rs
    
    // Create the KvmVm.
    let vm_config = VmConfig::new(&kvm, config.vcpu_config.num)?;
    ```

   1. Requirements: KVM is configured, guest memory is configured
   2. Inputs: vCPU registry values - hardcoded / embedded in VMM for the same
      reasons as boot parameters.
   3. Breakdown (`x86_64`):

       1. Configure MPTables. These
        [tables](https://pdos.csail.mit.edu/6.828/2014/readings/ia32/MPspec.pdf)
        tell the guest OS what the multiprocessor configuration looks like,
        and are required even with a single vCPU.

            ```rust
            // src/vm-vcpu/src/vm.rs
            
            #[cfg(target_arch = "x86_64")]        
            mptable::setup_mptable(guest_memory, vm.config.num_vcpus, vm.config.num_vcpus)
            .map_err(Error::MpTable)?;
            ```

       2. Create KVM `irqchip`. This creates the virtual IOAPIC and virtual
        PIC and sets up future vCPUs for local APIC.

            ```rust
            // src/vm-vcpu/src/vm.rs
          
            #[cfg(target_arch = "x86_64")]
            vm.setup_irq_controller()?;
            ```

       3. Create vCPUs. An `fd` is registered with KVM for each vCPU.
      
            ```rust
            // src/vm-vcpu/src/vm.rs
            
            vm.create_vcpus(bus, vcpus_config, guest_memory)?;
            ```

       4. Configure CPUID. Required (at least) because it’s the means by which
        the guest finds out it’s virtualized.
      
            ```rust
            // src/vm-vcpu/src/vcpu/mod.rs
            
            let base_cpuid = _kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::KvmIoctl)?;
          
            dbs_arch::cpuid::process_cpuid(&mut cpuid, &vm_spec).map_err(|e| Error::CpuId(e))?;
            ```

       5. Configure MSRs (model specific registers). These registers control
        (among others) the processor features. See the
        [reference](https://www.intel.co.uk/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-system-programming-manual-325384.pdf#G14.8720).
      
            ```rust
            // src/vm-vcpu/src/vcpu/mod.rs
          
            #[cfg(target_arch = "x86_64")]
            dbs_arch::regs::setup_msrs(&self.vcpu_fd).map_err(Error::MSRSConfiguration)
            ```

       6. Configure other registers (`kvm_regs`, `kvm_sregs`, `fpu`) and the
        LAPICs.

            ```rust
            // src/vm-vcpu/src/vcpu/mod.rs
          
            #[cfg(target_arch = "x86_64")]
            {
                vcpu.configure_cpuid(&vcpu.config.cpuid)?;
                vcpu.configure_msrs()?;
                vcpu.configure_sregs(memory)?;
                vcpu.configure_lapic()?;
                vcpu.configure_fpu()?;
            }
            ```

4. Create event manager for device events.
   This is done through [`dbs-utils::epoll_manager`](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-utils/src/epoll_manager.rs).

    ```rust
    // src/vmm/src/vmm.rs
    
    let event_manager = EpollManager::default();
    event_manager.add_subscriber(Box::new(wrapped_exit_handler.0.clone()));
    ```

5. legacy devices need to be configured with serial console and keyboard i8042 controller,
   serial console emulation is done through [`dbs-device`](https://crates.io/crates/dbs-device)
   and [`dbs-legacy-devices`](https://github.com/openanolis/dragonball-sandbox/tree/main/crates/dbs-legacy-devices) crates.
   Device event handling is mediated through
   [`dbs-utils::epoll_manager`](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-utils/src/epoll_manager.rs).
   See the [`Device virtualization documentation`](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-miniball/docs/DeviceVirtualization.md)
   for details on this part.
   1. Requirements: KVM is configured, guest memory is configured, `irqchip`
      is configured (`x86_64`), event manager is configured
   2. Inputs: N/A
   3. Breakdown:
      1. Create dummy speakers. The virtual speaker must be emulated, otherwise
      the kernel keeps accessing the speaker's port causing the KVM to continuously exit.
      2. Create serial console. The serial console is used to provide communication 
      between the virtual machine and the host.
      3. Create i8042. The keyboard i8042 controller is used to simulate the CPU 
      reset command, which is used to notify the VMM Guest to shut down.

    ```rust
    // src/vmm/src/lib.rs
    
    let serial = vmm.create_serial_console()?;
    vmm.init_serial_console(serial)?;
    
    #[cfg(target_arch = "x86_64")]
    vmm.add_i8042_device()?;
    ```

6. Configure root block device. This is done through [`dbs-virtio-devices`](https://github.com/openanolis/dragonball-sandbox/tree/main/crates/dbs-virtio-devices). 
   Device event handling is mediated with [`dbs-utils::epoll_manager`](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-utils/src/epoll_manager.rs).
   See the [`Device virtualization documentation`](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-miniball/docs/DeviceVirtualization.md)
   for details on this part.
   1. Requirements: KVM is configured, guest memory is configured, `irqchip`
      is configured (`x86_64`), event manager is configured

    ```rust
    // src/vmm/src/lib.rs
    
    if let Some(cfg) = config.block_config.as_ref() {
        vmm.add_block_device(cfg)?;
    }
    ```

7. Load the guest kernel into guest memory. This is done through [`linux-loader`](https://crates.io/crates/linux-loader)
   and [`dbs-boot`](https://crates.io/crates/dbs-boot) crates.
   See the [`Memory virtualization documentation`](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-miniball/docs/MemoryVirtualization.md)
   for details on this part.
   1. Requirements: guest memory is configured
   2. Inputs:
      1. path to kernel file
      2. start of high memory (x86_64)
      3. kernel command line
      4. boot parameters - embedded in VMM
         5. Too complex to pass through the command line / other inputs:
            these are arch-dependent structs, built with `bindgen` and
            exported by `linux-loader`, that the user fills in outside
            `linux-loader` with arch- and use case-specific values.
         6. Some can be constants and can be externally specified, unless
            they make the UI unusable. Examples: kernel loader type, kernel
            boot flags, dedicated address for the kernel command line, etc.

```rust
// src/vmm/src/lib.rs

let load_result = self.load_kernel()?;
#[cfg(target_arch = "x86_64")]
let kernel_load_addr = self.compute_kernel_load_addr(&load_result)?;
```

## How To Use

### CLI reference

* `memory` - guest memory configurations
    * `size_mib` - `u32`, guest memory size in MiB (decimal)
        * default: 256 MiB
* `kernel` - guest kernel configurations
    * `path` - `String`, path to the guest kernel image
    * `cmdline` - `String`, kernel command line
        * default: "console=ttyS0 i8042.nokbd reboot=t panic=1 pci=off"
    * `kernel_load_addr` - `u64`, start address for high memory (decimal)
        * default: 0x100000
* `vcpus` - vCPU configurations
    * `num` - `u8`, number of vCPUs (decimal)
        * default: 1
* `block` - block device configuration
    * `path` - `String`, path to the root filesystem

*Note*: For now, only the path to the root block device can be configured
via command line. The block device will implicitly be read-write and with
`cache flush` command supported. Passing the `block` argument is optional,
if you want to skip it, make sure you pass to the `path` argument of the
`kernel` configuration, a suitable image (for example a Busybox one).
We plan on extending the API to be able to configure more block devices and
more parameters for those (not just the `path`).
We also want to offer the same support in the near future for network and
vsock devices.

#### Example: Override the kernel command line

```bash
dbs-miniball \
    --kernel path=/path/to/kernel/image,cmdline="reboot=t panic=1 pci=off"
```

#### Example: VM with 2 vCPUs and 1 GiB memory

```bash
dbs-miniball                           \
    --memory size_mib=1024          \
    --vcpu num=2                        \
    --kernel path=/path/to/kernel/image
```

### Getting Started

#### Prerequisites

##### OS & Hypervisor

Currently, the Miniball runs on Linux **x86_64** hosts, using the **KVM** 
hypervisor. To make sure KVM is accessible to your user, run:


```shell
[ -r /dev/kvm ] && [ -w /dev/kvm ] && echo "OK" || echo "FAIL"
```

To grant your user access to KVM, either:

1. If you have the ACL package for your distro installed:

    ```shell
    sudo setfacl -m u:${USER}:rw /dev/kvm
    ```

   or

2. If your distribution uses the `kvm` group to manage access to `/dev/kvm`:

    ```bash
    [ $(stat -c "%G" /dev/kvm) = kvm ] && sudo usermod -aG kvm ${USER}
    ```

   Then log out and back in.

#### Build the Miniball

To build the Miniball from source, you need to have the Rust compiler and
`cargo` installed on your system. The following toolchains are supported:

- `x86_64-unknown-linux-gnu` (Linux with `glibc`, **default**)
- `x86_64-unknown-linux-musl` (Linux with `musl libc`)

As the Miniball does not yet have any compile-time features, building it
is as simple as:

```bash
cargo build [--release]
```

This will produce a binary called `dbs-miniball` in the `cargo` build
directory (default: `target/${toolchain}/${mode}`, where mode can be `debug` or
`release`).

#### Run the Miniball

##### Kernel

To build a kernel for the Miniball to boot, check out the scripts in 
[resources/kernel](https://github.com/openanolis/dragonball-sandbox/tree/main/crates/dbs-miniball/resources/kernel).

- [`make_kernel_busybox_image.sh`](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-miniball/resources/kernel/make_kernel_busybox_image.sh) 
builds an ELF or bzImage kernel with a baked-in initramfs running [Busybox](https://busybox.net/). 
It uses a stripped-down [kernel config](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-miniball/resources/kernel/microvm-kernel-initramfs-hello-x86_64.config) 
and a statically linked [config](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-miniball/resources/kernel/busybox_1_32_1_static_config) 
for the Busybox initramfs.


Example:
```shell
sudo ./make_kernel_busybox_image.sh -f elf -k vmlinux-hello-busybox -w /tmp/kernel
```

produces a binary image called `vmlinux-hello-busybox` in the `/tmp/kernel` 
directory. Root privileges are needed to create device nodes.
Run `./make_kernel_busybox_image.sh` with no arguments to see the help.

- [`make_kernel_image_deb.sh`](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-miniball/resources/kernel/make_kernel_image_deb.sh) 
builds an ELF or bzImage kernel compatible with Ubuntu 20.04 from a stripped-down 
[kernel config](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-miniball/resources/kernel/microvm-kernel-5.4-x86_64.config), 
as well as `.deb` packages containing the Linux kernel image and modules, 
to be installed in the guest. By default, the script downloads the `.deb` packages 
from an [official Ubuntu mirror](http://security.ubuntu.com/ubuntu/pool/main/l/linux-hwe-5.4), 
but it can build them from the same sources as the kernel instead. Users can opt 
in for this behavior by setting the `MAKEDEB` environment variable before running the script.

Example:

```shell
./make_kernel_image_deb.sh -f bzimage -j 2 -k bzimage-focal -w /tmp/ubuntu-focal
```

produces a binary image called `bzimage-focal` in the `/tmp/ubuntu-focal` directory.
It downloads the `linux-modules` and `linux-image-unsigned` packages and places them 
inside the kernel source directory within `/tmp/ubuntu-focal` (the exact location is 
displayed at the end). Run `./make_kernel_image_deb.sh` with no arguments to see the help.

##### Devices

The Miniball only supports a serial console device for now. This section
will be expanded as other devices are added. Block devices are in the works.

###### Block Device

To build a block device with a root filesystem in it containing an OS for the Miniball, 
check out the scripts in [resources/disk](https://github.com/openanolis/dragonball-sandbox/tree/main/crates/dbs-miniball/resources/disk).

- [`make_rootfs.sh`](https://github.com/openanolis/dragonball-sandbox/blob/main/crates/dbs-miniball/resources/disk/make_rootfs.sh)
builds a 1 GiB disk image containing an ext4 filesystem with an Ubuntu 20.04 image.


Example:
```shell
sudo resources/disk/make_rootfs.sh -d /tmp/ubuntu-focal/deb -w /tmp/ubuntu-focal
```

produces a file called `rootfs.ext4` inside `/tmp/ubuntu-focal` containing the 
Ubuntu 20.04 image and the kernel image installed from the `.deb` packages expected
in `/tmp/ubuntu-focal/deb`. At the very least, the OS needs the `linux-image` and
`linux-modules` packages. These can either be downloaded or built from sources. 
See [this section](#kernel) for examples on how to acquire these packages using 
scripts from this repo. Root privileges are needed to manage mountpoints.

#### Putting It All Together

Once all the prerequisites are met, the Miniball can be run either directly through `cargo`,
passing on its specific [command line arguments](https://github.com/openanolis/dragonball-sandbox/tree/main/crates/dbs-miniball#cli-reference), 
or after building it with `cargo build`.

```shell
cargo run --release --            \
    --memory size_mib=1024        \
    --kernel path=${KERNEL_PATH}  \
    --vcpu num=1
```

```shell
cargo build --release
target/release/dbs-miniball       \
    --memory size_mib=1024        \
    --kernel path=${KERNEL_PATH}  \
    --vcpu num=1
```

Examples:
```shell
cargo run --release --            \
    --memory size_mib=1024        \
    --kernel path=/tmp/kernel/linux-5.4.81/vmlinux-hello-busybox  \
    --vcpu num=1        \
    --block path=/tmp/ubuntu-focal/rootfs.ext4
```

```shell
cargo build --release
target/release/dbs-miniball      \
    --memory size_mib=1024        \
    --kernel path=/tmp/kernel/linux-5.4.81/vmlinux-hello-busybox  \
    --vcpu num=1        \
    --block path=/tmp/ubuntu-focal/rootfs.ext4
```

## Platform Supported

### Host OS & hypervisor

Currently, this intersection resolves into `Linux hosts`
and the `KVM hypervisor`. The first iteration of the Miniball supports
only this configuration, returning errors when users attempt to run it on
something else.

### CPU

Long term, the Miniball will run on `x86_64` and `aarch64` platforms. 
Currently, only Intel `x86_64` CPUs are supported.

### Rust version

Rust 1.59.0

### Toolchain

The Miniball will support both `glibc` and `musl libc` (toolchains:
`x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`) with `glibc` being the
default due to `x86_64-unknown-linux-gnu` being
[Tier 1 supported](https://doc.rust-lang.org/nightly/rustc/platform-support.html#tier-1)
by Rust. Future extensions to `aarch64` support will introduce the
`aarch64-unknown-linux-gnu` and `aarch64-unknown-linux-musl` toolchains,
defaulting (probably) to `aarch64-unknown-linux-gnu` on ARM, because it's also
*Tier 1 supported* since Rust 1.49.

## Acknowledgement

The Miniball is inspired by the [vmm-reference](https://github.com/rust-vmm/vmm-reference) project. 
Part of the code is derived from the [vmm-reference](https://github.com/rust-vmm/vmm-reference) project.

## License

This project is licensed under either of:

* [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
* [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)