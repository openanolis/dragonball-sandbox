# dragonball-sandbox

[![static](https://github.com/openanolis/dragonball-sandbox/actions/workflows/check.yaml/badge.svg)](https://github.com/openanolis/dragonball-sandbox/actions/workflows/check.yaml)
[![UT](https://github.com/openanolis/dragonball-sandbox/actions/workflows/test.yaml/badge.svg)](https://github.com/openanolis/dragonball-sandbox/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/openanolis/dragonball-sandbox/branch/main/graph/badge.svg?token=UE8OKM3QP2)](https://codecov.io/gh/openanolis/dragonball-sandbox)

Dragonball-sandbox is a collection of Rust crates to help build custom Virtual Machine Monitors and hypervisors. The crates here are considered to be the downstream of [rust-vmm](https://github.com/rust-vmm).

This repository contains the following crates:
| Name | Description | Links |
| --- | --- | --- |
| [db-address-space](crates/db-address-space) | manager for memory and MMIO resources resident in the guest physical address space | TBD |
| [dbs-allocator](crates/dbs-allocator) | allocator for vmm resource | TBD |
| [db-arch](crates/db-arch) | collections of CPU architecture related modules | TBD |
| [dbs-boot](crates/dbs-boot) | collections of constants, structs and utilities used during VM boot stage | TBD |
| [dbs-device](crates/dbs-device) | virtual machine's device model | [![Crates.io](https://img.shields.io/crates/v/dbs-device)](https://crates.io/crates/dbs-device) |
| [dbs-interrupt](crates/dbs-interrupt) | virtual machine's interrupt model | TBD |
| [dbs-legacy-devices](crates/dbs-legacy-devices) | emulation for legacy devices | TBD |
| [dbs-utils](crates/dbs-utils) | helpers and utilities used by multiple `dragonball-sandbox` components | TBD |
| [dbs-virtio-devices](crates/dbs-virtio-devices) | emulation for virtio devices | TBD |

(Dragonball is a virtual machine monitor developed by Alibaba and dbs is the abbreviation for Dragonball.)

## How to build
```bash
cargo build --release
```

## License

This project is licensed under [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0.
