# dbs-arch

## Design

The `dbs-arch` crate is a collection of CPU architecture specific constants and utilities to hide CPU architecture details
away from the Dragonball Sandbox or other VMMs.

## Supported Architectures

- AMD64 (x86_64)
- ARM64 (aarch64)

## Submodule List

This repository contains the following submodules:
| Name | Arch| Description |
| --- | --- | --- |
| [cpuid](src/x86_64/cpuid/) | x86_64 |Facilities to process CPUID information. |
| [msr](src/x86_64/msr.rs) | x86_64 | Constant definitions for Model Specific Registers |

## Acknowledgement

Part of the code is derived from the [Firecracker](https://github.com/firecracker-microvm/firecracker) project.

## License

This project is licensed under [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0.
