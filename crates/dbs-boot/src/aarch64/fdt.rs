// Copyright 2022 Alibaba Cloud. All Rights Reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Create Flatten Device Tree (FDT) for ARM64 systems.

use std::collections::HashMap;
use std::fmt::Debug;

use dbs_arch::gic::its::ItsType::{self, PciMsiIts, PlatformMsiIts};
use dbs_arch::gic::GICDevice;
use dbs_arch::{DeviceInfoForFDT, DeviceType};

use vm_fdt::FdtWriter;
use vm_memory::GuestMemoryRegion;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};

use super::layout::FDT_MAX_SIZE;
use super::Error;
use crate::{InitrdConfig, Result};

// This is a value for uniquely identifying the FDT node declaring the interrupt controller.
const GIC_PHANDLE: u32 = 1;
// This is a value for uniquely identifying the FDT node containing the clock definition.
const CLOCK_PHANDLE: u32 = 2;
// This is a value for uniquely identifying the FDT node containing the plaform msi ITS definition.
const GIC_PLATFORM_MSI_ITS_PHANDLE: u32 = 3;
// This is a value for uniquely identifying the FDT node containing the pci msi ITS definition.
const GIC_PCI_MSI_ITS_PHANDLE: u32 = 4;
// According to the arm, gic-v3.txt document, ITS' #msi-cells is fixed at 1.
const GIC_PLATFORM_MSI_ITS_CELLS_SIZE: u32 = 1;

// Read the documentation specified when appending the root node to the FDT.
const ADDRESS_CELLS: u32 = 0x2;
const SIZE_CELLS: u32 = 0x2;

// As per kvm tool and
// https://www.kernel.org/doc/Documentation/devicetree/bindings/interrupt-controller/arm%2Cgic.txt
// Look for "The 1st cell..."
const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
const GIC_FDT_IRQ_TYPE_PPI: u32 = 1;

// From https://elixir.bootlin.com/linux/v4.9.62/source/include/dt-bindings/interrupt-controller/irq.h#L17
const IRQ_TYPE_EDGE_RISING: u32 = 1;
const IRQ_TYPE_LEVEL_HI: u32 = 4;

// Auxiliary function to get the address where the device tree blob is loaded.
fn get_fdt_addr<M: GuestMemory>(mem: &M) -> u64 {
    // If the memory allocated is smaller than the size allocated for the FDT,
    // we return the start of the DRAM so that
    // we allow the code to try and load the FDT.

    if let Some(offset) = mem.last_addr().checked_sub(FDT_MAX_SIZE as u64 - 1) {
        if mem.address_in_range(offset) {
            return offset.raw_value();
        }
    }
    crate::layout::DRAM_MEM_START
}

/// Creates the flattened device tree for this aarch64 microVM.
pub fn create_fdt<T: DeviceInfoForFDT + Clone + Debug, M: GuestMemory>(
    guest_mem: &M,
    vcpu_mpidr: Vec<u64>,
    cmdline: &str,
    device_info: Option<&HashMap<(DeviceType, String), T>>,
    gic_device: &Box<dyn GICDevice>,
    initrd: &Option<InitrdConfig>,
) -> Result<Vec<u8>> {
    let mut fdt = FdtWriter::new()?;

    // For an explanation why these nodes were introduced in the blob take a look at
    // https://github.com/torvalds/linux/blob/master/Documentation/devicetree/booting-without-of.txt#L845
    // Look for "Required nodes and properties".

    // Header or the root node as per above mentioned documentation.
    let root_node = fdt.begin_node("")?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    // For info on #address-cells and size-cells read "Note about cells and address representation"
    // from the above mentioned txt file.
    fdt.property_u32("#address-cells", ADDRESS_CELLS)?;
    fdt.property_u32("#size-cells", SIZE_CELLS)?;
    // This is not mandatory but we use it to point the root node to the node
    // containing description of the interrupt controller for this VM.
    fdt.property_u32("interrupt-parent", GIC_PHANDLE)?;
    create_cpu_nodes(&mut fdt, &vcpu_mpidr)?;
    create_memory_node(&mut fdt, guest_mem)?;
    create_chosen_node(&mut fdt, cmdline, initrd)?;
    create_gic_node(&mut fdt, gic_device)?;
    create_timer_node(&mut fdt)?;
    create_clock_node(&mut fdt)?;
    create_psci_node(&mut fdt)?;
    device_info.map_or(Ok(()), |v| create_devices_node(&mut fdt, v))?;

    // End Header node.
    fdt.end_node(root_node)?;

    // Allocate another buffer so we can format and then write fdt to guest.
    let fdt_final = fdt.finish()?;

    // Write FDT to memory.
    let fdt_address = GuestAddress(get_fdt_addr(guest_mem));
    guest_mem
        .write_slice(fdt_final.as_slice(), fdt_address)
        .map_err(Error::WriteFDTToMemory)?;
    Ok(fdt_final)
}

// Following are the auxiliary function for creating the different nodes that we append to our FDT.
fn create_cpu_nodes(fdt: &mut FdtWriter, vcpu_mpidr: &Vec<u64>) -> Result<()> {
    // See https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/arm/cpus.yaml.
    let cpus_node = fdt.begin_node("cpus")?;
    // As per documentation, on ARM v8 64-bit systems value should be set to 2.
    fdt.property_u32("#address-cells", 0x02)?;
    fdt.property_u32("#size-cells", 0x0)?;
    let num_cpus = vcpu_mpidr.len();

    for cpu_index in 0..num_cpus {
        let cpu_name = format!("cpu@{:x}", cpu_index);
        let cpu_node = fdt.begin_node(&cpu_name)?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        if num_cpus > 1 {
            // This is required on armv8 64-bit. See aforementioned documentation.
            fdt.property_string("enable-method", "psci")?;
        }
        // Set the field to first 24 bits of the MPIDR - Multiprocessor Affinity Register.
        // See http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0488c/BABHBJCI.html.
        fdt.property_u64("reg", vcpu_mpidr[cpu_index] & 0x7FFFFF)?;
        fdt.end_node(cpu_node)?;
    }
    fdt.end_node(cpus_node)?;
    Ok(())
}

fn create_memory_node<M: GuestMemory>(fdt: &mut FdtWriter, guest_mem: &M) -> Result<()> {
    // See https://github.com/torvalds/linux/blob/v5.9/Documentation/devicetree/booting-without-of.rst
    for region in guest_mem.iter() {
        let memory_name = format!("memory@{:x}", region.start_addr().raw_value());
        let mem_reg_prop = &[region.start_addr().raw_value(), region.len()];
        let memory_node = fdt.begin_node(&memory_name)?;
        fdt.property_string("device_type", "memory")?;
        fdt.property_array_u64("reg", mem_reg_prop)?;
        fdt.end_node(memory_node)?;
    }
    Ok(())
}

fn create_chosen_node(
    fdt: &mut FdtWriter,
    cmdline: &str,
    initrd: &Option<InitrdConfig>,
) -> Result<()> {
    let chosen_node = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", cmdline)?;

    if let Some(initrd_config) = initrd {
        fdt.property_u64(
            "linux,initrd-start",
            initrd_config.address.raw_value() as u64,
        )?;
        fdt.property_u64(
            "linux,initrd-end",
            initrd_config.address.raw_value() + initrd_config.size as u64,
        )?;
    }

    fdt.end_node(chosen_node)?;

    Ok(())
}

fn append_its_common_property(fdt: &mut FdtWriter, registers_prop: &[u64]) -> Result<()> {
    fdt.property_string("compatible", "arm,gic-v3-its")?;
    fdt.property_null("msi-controller")?;
    fdt.property_array_u64("reg", registers_prop)?;
    Ok(())
}

fn create_its_node(
    fdt: &mut FdtWriter,
    gic_device: &Box<dyn GICDevice>,
    its_type: ItsType,
) -> Result<()> {
    let reg = gic_device.get_its_reg_range(&its_type);
    if let Some(registers) = reg {
        // There are two types of its, pci_msi_its and platform_msi_its.
        // If this is pci_msi_its, the fdt node of its is required to have no
        // #msi-cells attribute. If this is platform_msi_its, the #msi-cells
        // attribute of its fdt node is required, and the value is 1.
        match its_type {
            PlatformMsiIts => {
                let its_node = fdt.begin_node("gic-platform-its")?;
                append_its_common_property(fdt, &registers)?;
                fdt.property_u32("phandle", GIC_PLATFORM_MSI_ITS_PHANDLE)?;
                fdt.property_u32("#msi-cells", GIC_PLATFORM_MSI_ITS_CELLS_SIZE)?;
                fdt.end_node(its_node)?;
            }
            PciMsiIts => {
                let its_node = fdt.begin_node("gic-pci-its")?;
                append_its_common_property(fdt, &registers)?;
                fdt.property_u32("phandle", GIC_PCI_MSI_ITS_PHANDLE)?;
                fdt.end_node(its_node)?;
            }
        }
    }
    Ok(())
}

fn create_gic_node(fdt: &mut FdtWriter, gic_device: &Box<dyn GICDevice>) -> Result<()> {
    let gic_reg_prop = gic_device.device_properties();

    let intc_node = fdt.begin_node("intc")?;
    fdt.property_string("compatible", gic_device.fdt_compatibility())?;
    fdt.property_null("interrupt-controller")?;
    // "interrupt-cells" field specifies the number of cells needed to encode an
    // interrupt source. The type shall be a <u32> and the value shall be 3 if no PPI affinity description
    // is required.
    fdt.property_u32("#interrupt-cells", 3)?;
    fdt.property_array_u64("reg", gic_reg_prop)?;
    fdt.property_u32("phandle", GIC_PHANDLE)?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_null("ranges")?;
    let gic_intr_prop = &[
        GIC_FDT_IRQ_TYPE_PPI,
        gic_device.fdt_maint_irq(),
        IRQ_TYPE_LEVEL_HI,
    ];

    fdt.property_array_u32("interrupts", gic_intr_prop)?;
    create_its_node(fdt, gic_device, PlatformMsiIts)?;
    create_its_node(fdt, gic_device, PciMsiIts)?;
    fdt.end_node(intc_node)?;

    Ok(())
}

fn create_clock_node(fdt: &mut FdtWriter) -> Result<()> {
    // The Advanced Peripheral Bus (APB) is part of the Advanced Microcontroller Bus Architecture
    // (AMBA) protocol family. It defines a low-cost interface that is optimized for minimal power
    // consumption and reduced interface complexity.
    // PCLK is the clock source and this node defines exactly the clock for the APB.
    let clock_node = fdt.begin_node("apb-pclk")?;
    fdt.property_string("compatible", "fixed-clock")?;
    fdt.property_u32("#clock-cells", 0x0)?;
    fdt.property_u32("clock-frequency", 24000000)?;
    fdt.property_string("clock-output-names", "clk24mhz")?;
    fdt.property_u32("phandle", CLOCK_PHANDLE)?;
    fdt.end_node(clock_node)?;

    Ok(())
}

fn create_timer_node(fdt: &mut FdtWriter) -> Result<()> {
    // See
    // https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/interrupt-controller/arch_timer.txt
    // These are fixed interrupt numbers for the timer device.
    let irqs = [13, 14, 11, 10];
    let compatible = "arm,armv8-timer";

    let mut timer_reg_cells: Vec<u32> = Vec::new();
    for &irq in irqs.iter() {
        timer_reg_cells.push(GIC_FDT_IRQ_TYPE_PPI);
        timer_reg_cells.push(irq);
        timer_reg_cells.push(IRQ_TYPE_LEVEL_HI);
    }

    let timer_node = fdt.begin_node("timer")?;
    fdt.property_string("compatible", compatible)?;
    fdt.property_null("always-on")?;
    fdt.property_array_u32("interrupts", &timer_reg_cells)?;
    fdt.end_node(timer_node)?;

    Ok(())
}

fn create_psci_node(fdt: &mut FdtWriter) -> Result<()> {
    let compatible = "arm,psci-0.2";
    let psci_node = fdt.begin_node("psci")?;
    fdt.property_string("compatible", compatible)?;
    // Two methods available: hvc and smc.
    // As per documentation, PSCI calls between a guest and hypervisor may use the HVC conduit instead of SMC.
    // So, since we are using kvm, we need to use hvc.
    fdt.property_string("method", "hvc")?;
    fdt.end_node(psci_node)?;

    Ok(())
}

fn create_virtio_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let device_reg_prop = &[dev_info.addr(), dev_info.length()];
    let irq_number = dev_info.irq().map_err(|_| Error::InvalidArguments)?;
    let irq_property = &[GIC_FDT_IRQ_TYPE_SPI, irq_number, IRQ_TYPE_EDGE_RISING];

    let virtio_mmio_node = fdt.begin_node(&format!("virtio_mmio@{:x}", dev_info.addr()))?;
    fdt.property_string("compatible", "virtio,mmio")?;
    fdt.property_array_u64("reg", device_reg_prop)?;
    fdt.property_array_u32("interrupts", irq_property)?;
    fdt.property_u32("interrupt-parent", GIC_PHANDLE)?;
    fdt.end_node(virtio_mmio_node)?;

    Ok(())
}

fn create_serial_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let serial_reg_prop = &[dev_info.addr(), dev_info.length()];
    let irq_number = dev_info.irq().map_err(|_| Error::InvalidArguments)?;
    let irq_property = &[GIC_FDT_IRQ_TYPE_SPI, irq_number, IRQ_TYPE_EDGE_RISING];

    let uart_node = fdt.begin_node(&format!("uart@{:x}", dev_info.addr()))?;
    fdt.property_string("compatible", "ns16550a")?;
    fdt.property_array_u64("reg", serial_reg_prop)?;
    fdt.property_u32("clocks", CLOCK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.property_array_u32("interrupts", irq_property)?;
    fdt.end_node(uart_node)?;

    Ok(())
}

fn create_rtc_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let compatible = b"arm,pl031\0arm,primecell\0";
    let rtc_reg_prop = &[dev_info.addr(), dev_info.length()];
    let irq_number = dev_info.irq().map_err(|_| Error::InvalidArguments)?;
    let irq_property = &[GIC_FDT_IRQ_TYPE_SPI, irq_number, IRQ_TYPE_LEVEL_HI];

    let rtc_node = fdt.begin_node(&format!("rtc@{:x}", dev_info.addr()))?;
    fdt.property("compatible", compatible)?;
    fdt.property_array_u64("reg", rtc_reg_prop)?;
    fdt.property_array_u32("interrupts", irq_property)?;
    fdt.property_u32("clocks", CLOCK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.end_node(rtc_node)?;

    Ok(())
}

fn create_devices_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &HashMap<(DeviceType, String), T>,
) -> Result<()> {
    // Serial devices need to be registered in order
    let mut ordered_serial_device: Vec<&T> = Vec::new();
    // Create one temp Vec to store all virtio devices
    let mut ordered_virtio_device: Vec<&T> = Vec::new();

    for ((device_type, _device_id), info) in dev_info {
        match device_type {
            DeviceType::RTC => create_rtc_node(fdt, info)?,
            DeviceType::Serial => {
                ordered_serial_device.push(info);
            }
            DeviceType::Virtio(_) => {
                ordered_virtio_device.push(info);
            }
        }
    }

    // Sort out serial devices by address from low to high and insert them into fdt table.
    ordered_serial_device.sort_by(|a, b| a.addr().cmp(&b.addr()));
    for serial_device_info in ordered_serial_device.drain(..) {
        create_serial_node(fdt, serial_device_info)?;
    }
    // Sort out virtio devices by address from low to high and insert them into fdt table.
    ordered_virtio_device.sort_by(|a, b| a.addr().cmp(&b.addr()));
    for ordered_device_info in ordered_virtio_device.drain(..) {
        create_virtio_node(fdt, ordered_device_info)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::layout;
    use dbs_arch::gic::create_gic;
    use kvm_ioctls::Kvm;
    use std::cmp::min;
    use vm_memory::GuestMemoryMmap;

    const LEN: u64 = 4096;

    fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
        let dram_size = min(size as u64, layout::DRAM_MEM_MAX_SIZE) as usize;
        vec![(GuestAddress(layout::DRAM_MEM_START), dram_size)]
    }

    #[derive(Clone, Debug)]
    pub struct MMIODeviceInfo {
        addr: u64,
        irq: u32,
    }

    impl DeviceInfoForFDT for MMIODeviceInfo {
        fn addr(&self) -> u64 {
            self.addr
        }
        fn irq(&self) -> std::result::Result<u32, dbs_arch::Error> {
            Ok(self.irq)
        }
        fn length(&self) -> u64 {
            LEN
        }
        fn get_device_id(&self) -> Option<u32> {
            None
        }
    }
    // The `load` function from the `device_tree` will mistakenly check the actual size
    // of the buffer with the allocated size. This works around that.
    fn set_size(buf: &mut [u8], pos: usize, val: usize) {
        buf[pos] = ((val >> 24) & 0xff) as u8;
        buf[pos + 1] = ((val >> 16) & 0xff) as u8;
        buf[pos + 2] = ((val >> 8) & 0xff) as u8;
        buf[pos + 3] = (val & 0xff) as u8;
    }

    #[test]
    fn test_create_fdt_with_devices() {
        let regions = arch_memory_regions(layout::FDT_MAX_SIZE + 0x1000);
        let mem = GuestMemoryMmap::<()>::from_ranges(&regions).expect("Cannot initialize memory");
        let dev_info: HashMap<(DeviceType, std::string::String), MMIODeviceInfo> = [
            (
                (DeviceType::Serial, DeviceType::Serial.to_string()),
                MMIODeviceInfo { addr: 0x00, irq: 1 },
            ),
            (
                (DeviceType::Virtio(1), "virtio".to_string()),
                MMIODeviceInfo {
                    addr: 0x00 + LEN,
                    irq: 2,
                },
            ),
            (
                (DeviceType::RTC, "rtc".to_string()),
                MMIODeviceInfo {
                    addr: 0x00 + 2 * LEN,
                    irq: 3,
                },
            ),
        ]
        .iter()
        .cloned()
        .collect();
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic = create_gic(&vm, 1).unwrap();
        assert!(create_fdt(&mem, vec![0], "console=tty0", Some(&dev_info), &gic, &None,).is_ok())
    }

    #[test]
    fn test_create_fdt() {
        let regions = arch_memory_regions(layout::FDT_MAX_SIZE + 0x1000);
        let mem = GuestMemoryMmap::<()>::from_ranges(&regions).expect("Cannot initialize memory");
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic = create_gic(&vm, 1).unwrap();
        let mut dtb = create_fdt(
            &mem,
            vec![0],
            "console=tty0",
            None::<&std::collections::HashMap<(DeviceType, std::string::String), MMIODeviceInfo>>,
            &gic,
            &None,
        )
        .unwrap();

        // // Use this code when wanting to generate a new DTB sample.
        // // Do manually check dtb files with dtc
        // // See https://git.kernel.org/pub/scm/utils/dtc/dtc.git/plain/Documentation/manual.txt
        // {
        //     use std::fs;
        //     use std::io::Write;
        //     use std::path::PathBuf;
        //     let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        //     let mut output = fs::OpenOptions::new()
        //         .write(true)
        //         .create(true)
        //         .open(path.join("src/aarch64/output.dtb"))
        //         .unwrap();
        //     output.write_all(&dtb).unwrap();
        // }

        let bytes = include_bytes!("test/output.dtb");
        let pos = 4;
        let val = layout::FDT_MAX_SIZE;
        let mut buf = vec![];
        buf.extend_from_slice(bytes);

        set_size(&mut buf, pos, val);
        set_size(&mut dtb, pos, val);
        let original_fdt = device_tree::DeviceTree::load(&buf).unwrap();
        let generated_fdt = device_tree::DeviceTree::load(&dtb).unwrap();
        assert!(format!("{:?}", original_fdt) == format!("{:?}", generated_fdt));
    }

    #[test]
    fn test_create_fdt_with_initrd() {
        let regions = arch_memory_regions(layout::FDT_MAX_SIZE + 0x1000);
        let mem = GuestMemoryMmap::<()>::from_ranges(&regions).expect("Cannot initialize memory");
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic = create_gic(&vm, 1).unwrap();
        let initrd = InitrdConfig {
            address: GuestAddress(0x10000000),
            size: 0x1000,
        };

        let mut dtb = create_fdt(
            &mem,
            vec![0],
            "console=tty0",
            None::<&std::collections::HashMap<(DeviceType, std::string::String), MMIODeviceInfo>>,
            &gic,
            &Some(initrd),
        )
        .unwrap();

        // // Use this code when wanting to generate a new DTB sample.
        // // Do manually check dtb files with dtc
        // // See https://git.kernel.org/pub/scm/utils/dtc/dtc.git/plain/Documentation/manual.txt
        // {
        //     use std::fs;
        //     use std::io::Write;
        //     use std::path::PathBuf;
        //     let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        //     let mut output = fs::OpenOptions::new()
        //         .write(true)
        //         .create(true)
        //         .open(path.join("src/aarch64/output_with_initrd.dtb"))
        //         .unwrap();
        //     output.write_all(&dtb).unwrap();
        // }

        let bytes = include_bytes!("test/output_with_initrd.dtb");
        let pos = 4;
        let val = layout::FDT_MAX_SIZE;
        let mut buf = vec![];
        buf.extend_from_slice(bytes);

        set_size(&mut buf, pos, val);
        set_size(&mut dtb, pos, val);
        let original_fdt = device_tree::DeviceTree::load(&buf).unwrap();
        let generated_fdt = device_tree::DeviceTree::load(&dtb).unwrap();
        assert!(format!("{:?}", original_fdt) == format!("{:?}", generated_fdt));
    }
}
