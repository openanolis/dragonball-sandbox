# dragonball-sandbox
Dragonball-sandbox is a collection of Rust crates to help build custom Virtual Machine Monitors and hypervisors. The crates here are considered to be the downstream of [rust-vmm](https://github.com/rust-vmm).

This repository contains the following crates:
| Name | Description | Links |
| --- | --- | --- |
| [db-allocator](crates/db-allocator) | allocator for vmm resource | TBD |
| [db-arch](crates/db-arch) | collections of CPU architecture related modules | TBD |

(Dragonball is a virtual machine monitor developed by Alibaba and db is the abbreviation for Dragonball.)

## How to build
```bash
cargo build --release
```
