# dragonball-sandbox

[![static](https://github.com/openanolis/dragonball-sandbox/actions/workflows/check.yaml/badge.svg)](https://github.com/openanolis/dragonball-sandbox/actions/workflows/check.yaml)
[![UT](https://github.com/openanolis/dragonball-sandbox/actions/workflows/test.yaml/badge.svg)](https://github.com/openanolis/dragonball-sandbox/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/openanolis/dragonball-sandbox/branch/main/graph/badge.svg?token=UE8OKM3QP2)](https://codecov.io/gh/openanolis/dragonball-sandbox)

Dragonball-sandbox is a collection of Rust crates to help build custom Virtual Machine Monitors and hypervisors. The crates here are considered to be the downstream of [rust-vmm](https://github.com/rust-vmm).

This repository contains the following crates:
| Name | Description | Links |
| --- | --- | --- |
| [dbs-acpi](crates/dbs-acpi) | acpi definitions for virtual machines| TBD |
| [dbs-address-space](crates/dbs-address-space) | manager for memory and MMIO resources resident in the guest physical address space | [![Crates.io](https://img.shields.io/crates/v/dbs-address-space)](https://crates.io/crates/dbs-address-space) |
| [dbs-allocator](crates/dbs-allocator) | allocator for vmm resource | [![Crates.io](https://img.shields.io/crates/v/dbs-allocator)](https://crates.io/crates/dbs-allocator) |
| [dbs-arch](crates/dbs-arch) | collections of CPU architecture related modules | [![Crates.io](https://img.shields.io/crates/v/dbs-arch)](https://crates.io/crates/dbs-arch) |
| [dbs-boot](crates/dbs-boot) | collections of constants, structs and utilities used during VM boot stage | [![Crates.io](https://img.shields.io/crates/v/dbs-boot)](https://crates.io/crates/dbs-boot) |
| [dbs-device](crates/dbs-device) | virtual machine's device model | [![Crates.io](https://img.shields.io/crates/v/dbs-device)](https://crates.io/crates/dbs-device) |
| [dbs-interrupt](crates/dbs-interrupt) | virtual machine's interrupt model | [![Crates.io](https://img.shields.io/crates/v/dbs-interrupt)](https://crates.io/crates/dbs-interrupt) |
| [dbs-legacy-devices](crates/dbs-legacy-devices) | emulation for legacy devices | [![Crates.io](https://img.shields.io/crates/v/dbs-legacy-devices)](https://crates.io/crates/dbs-legacy-devices) |
| [dbs-utils](crates/dbs-utils) | helpers and utilities used by multiple `dragonball-sandbox` components | [![Crates.io](https://img.shields.io/crates/v/dbs-utils)](https://crates.io/crates/dbs-utils) |
| [dbs-virtio-devices](crates/dbs-virtio-devices) | emulation for virtio devices | [![Crates.io](https://img.shields.io/crates/v/dbs-virtio-devices)](https://crates.io/crates/dbs-virtio-devices) |
| [dbs-upcall](crates/dbs-upcall) | dbs-upcall is a direct communication tool between VMM and guest developed upon vsock. | [![Crates.io](https://img.shields.io/crates/v/dbs-upcall)](https://crates.io/crates/dbs-upcall) |
| [dbs-miniball](crates/dbs-miniball) | dbs-miniball is a minimal virtual machine manager using components from dragonball-sandbox and rust-vmm. | / |

(Dragonball is a virtual machine monitor developed by Alibaba and dbs is the abbreviation for Dragonball.)

## How to build
```bash
cargo build --release
```

## License

This project is licensed under [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0.
