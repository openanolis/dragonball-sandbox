# dragonball-sandbox

[![static](https://github.com/openanolis/dragonball-sandbox/actions/workflows/check.yaml/badge.svg)](https://github.com/openanolis/dragonball-sandbox/actions/workflows/check.yaml)
[![UT](https://github.com/openanolis/dragonball-sandbox/actions/workflows/test.yaml/badge.svg)](https://github.com/openanolis/dragonball-sandbox/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/openanolis/dragonball-sandbox/branch/main/graph/badge.svg?token=UE8OKM3QP2)](https://codecov.io/gh/openanolis/dragonball-sandbox)

Dragonball-sandbox is a collection of Rust crates to help build custom Virtual Machine Monitors and hypervisors. The crates here are considered to be the downstream of [rust-vmm](https://github.com/rust-vmm).

This repository contains the following crates:
| Name | Description | Links |
| --- | --- | --- |
| [db-address-space](crates/db-address-space) | manager for memory and MMIO resources resident in the guest physical address space | TBD |
| [db-allocator](crates/db-allocator) | allocator for vmm resource | TBD |
| [db-arch](crates/db-arch) | collections of CPU architecture related modules | TBD |
| [db-boot](crates/db-boot) | collections of constants, structs and utilities used during VM boot stage | TBD |
| [dbs-device](crates/dbs-device) | virtual machine's device model | TBD |

(Dragonball is a virtual machine monitor developed by Alibaba and db is the abbreviation for Dragonball.)

## How to build
```bash
cargo build --release
```

## License

This project is licensed under [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0.
