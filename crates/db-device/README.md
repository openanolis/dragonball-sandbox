# db-device

The db-device crate mainly contains:

- `DeviceIo` and `DeviceIoMut` trait: defining the read/write operation on specific device
- `IoManager`: managing all devices of virtual machine, (un)register their io resource callback
- `IoManagerContext` trait: transaction context for `IoManager` to (un)register devices
- `ResourceConstraint`, `Resource` and `DeviceResources`: abstractions for requiring and describing resources of a device

## Design

The db-device crate is designed to support the virtual machine's device model.

The core concepts of device model are [Port I/O](https://wiki.osdev.org/I/O_Ports) and [Memory-mapped I/O](https://en.wikipedia.org/wiki/Memory-mapped_I/O), which are two main methods of performing I/O between CPU and devices.

The `DeviceIo` and `DeviceIoMut` trait are used to define the operations of devices in vm when guest OS performing I/O to emulated devices.

In addition, we need to let CPU know the I/O operation would be sent to which device, so the devices also need to declare the resources they used for I/O operation, which are defined in `Resource` enum. It also defines the other resources that the device will use, such as interrupts, KVM slots and MAC addresses. And `DeviceResources` struct gathers a series resources of a device together.

When a device is creating, it may not yet know the specific parameters of the resources it uses, but only the constraint of resources it needs, so `ResourceConstraint` enum is used to describe the resources requirements for each device.

## Usage

First, a vm needs to create an `IoManager` to help it distribute I/O events to devices. And an `IoManager` has two types of bus, pio bus and mmio bus.

Then, when creating a device, it needs to implement the `DeviceIo` or `DeviceIoMut` trait to receive read or write events send by driver in guest OS:
- `read()` and `write()` methods is used to deal with MMIO events
- `pio_read()` and `pio_write()` methods is used to deal with PIO events
- `get_assigned_resources()` method is used to get all resources assigned to the device
- `get_trapped_io_resources()` method is used to get only MMIO/PIO resources assigned to the device

The difference of `DeviceIo` and `DeviceIoMut` is the reference type of `self` passed to method:
- `DeviceIo` trait would pass a immutable reference `&self` to method, so the implementation of device would provide interior mutability and thread-safe protection itself
- `DeviceIoMut` trait would pass a mutable reference `&mut self` to method, and it can give mutability to device which is wrapped by `Mutex` directly to simplify the difficulty of achieving interior mutability. Additionally, the `DeviceIo` trait would auto implement for `Mutex<T: DeviceIoMut>`

Last, the device needs to be added to `IoManager` by using `register_device_io()`, and the function would add device to pio bus or mmio bus by the resources it have. If a device has not only MMIO resource but PIO resource, it would be added to both pio bus and mmio bus. So the device would wrapped by `Arc<T>`.

From now on, the IoManager will be routing I/O requests for the registered address range to the device. The requests are dispatched by the client code, for example when handling VM exits, using IoManager's methods like `pio_read`, `pio_write`, `mmio_read` and `mmio_write`.

## Examples


```rust
use std::sync::Arc;

use db_device::device_manager::IoManager;
use db_device::resources::{DeviceResources, Resource};
use db_device::{DeviceIo, IoAddress, PioAddress};

struct DummyDevice {}

impl DeviceIo for DummyDevice {
    fn read(&self, base: IoAddress, offset: IoAddress, data: &mut [u8]) {
        println!(
            "mmio read, base: 0x{:x}, offset: 0x{:x}",
            base.raw_value(),
            offset.raw_value()
        );
    }

    fn write(&self, base: IoAddress, offset: IoAddress, data: &[u8]) {
        println!(
            "mmio write, base: 0x{:x}, offset: 0x{:x}",
            base.raw_value(),
            offset.raw_value()
        );
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_read(&self, base: PioAddress, offset: PioAddress, data: &mut [u8]) {
        println!(
            "pio read, base: 0x{:x}, offset: 0x{:x}",
            base.raw_value(),
            offset.raw_value()
        );
    }

    #[cfg(target_arch = "x86_64")]
    fn pio_write(&self, base: PioAddress, offset: PioAddress, data: &[u8]) {
        println!(
            "pio write, base: 0x{:x}, offset: 0x{:x}",
            base.raw_value(),
            offset.raw_value()
        );
    }
}

// Allocate resources for device
let mut resources = DeviceResources::new();
resources.append(Resource::MmioAddressRange {
    base: 0,
    size: 4096,
});
#[cfg(target_arch = "x86_64")]
resources.append(Resource::PioAddressRange { base: 0, size: 32 });

// Register device to `IoManager` with resources
let device = Arc::new(DummyDevice {});
let mut manager = IoManager::new();
manager.register_device_io(device, &resources).unwrap();

// Dispatch I/O event from `IoManager` to device
manager.mmio_write(0, &vec![0, 1]).unwrap();
#[cfg(target_arch = "x86_64")]
{
    let mut buffer = vec![0; 4];
    manager.pio_read(0, &mut buffer);
}
```

## License

This project is licensed under [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0.
