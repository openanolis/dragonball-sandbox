# db-arch

## Design

db-arch crate is designed as the collection for cpu architecture, i.e. x86_64 (AMD64) and ARM64, related submodules. We define CPU architecture specified behaviour for VMM to use in this crate.

## Submodule List
This repository contains the following submodules:
| Name | Description |
| --- | --- |
| [cpuid](/crates/db-arch/src/x86/cpuid) | cpuid processor for vmm |