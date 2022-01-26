# db-boot

## Design

The `db-boot` crate is a collection of constants, structs and utilities used to boot virtual machines.

## Submodule List

This repository contains the following submodules:
| Name | Arch| Description |
| --- | --- | --- |
| [layout](src/x86_64/layout.rs) | x86_64 | x86_64 layout constants |
| [layout](src/aarch64/layout.rs/) | aarch64 | aarch64 layout constants |

## Acknowledgement

Part of the code is derived from the [Firecracker](https://github.com/firecracker-microvm/firecracker) project.

## License

This project is licensed under [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0.
