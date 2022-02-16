# dragonball-sandbox
Dragonball-sandbox is a collection of Rust crates to help build custom Virtual Machine Monitors and hypervisors. The crates here are considered to be the downstream of [rust-vmm](https://github.com/rust-vmm).

This repository contains the following crates:
| Name | Description | Links |
| --- | --- | --- |
| [db-address-space](crates/db-address-space) | manager for memory and MMIO resources resident in the guest physical address space | TBD |
| [db-allocator](crates/db-allocator) | allocator for vmm resource | TBD |
| [db-arch](crates/db-arch) | collections of CPU architecture related modules | TBD |
| [db-boot](crates/db-boot) | collections of constants, structs and utilities used during VM boot stage | TBD |
| [db-device](crates/db-device) | virtual machine's device model | TBD |
| [db-micro-http](crates/db-micro-http) | implementation of the HTTP/1.0 and HTTP/1.1 protocols | TBD |

(Dragonball is a virtual machine monitor developed by Alibaba and db is the abbreviation for Dragonball.)

## How to build
```bash
cargo build --release
```
