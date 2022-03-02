// Copyright 2019-2020 Alibaba Cloud. All rights reserved.
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Interfaces and implementations of virtio devices, queues and transport mechanisms.
//!
//! Please refer to [Virtio Specification]
//! (http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
//! for more information.

mod notifier;
pub use self::notifier::*;

// Interrupt status flags for legacy interrupts. It happens to be the same for both PCI and MMIO
// virtio devices.
/// Data available in used queue.
pub const VIRTIO_INTR_VRING: u32 = 0x01;
/// Device configuration changed.
pub const VIRTIO_INTR_CONFIG: u32 = 0x02;

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use dbs_interrupt::KvmIrqManager;
    use kvm_ioctls::{Kvm, VmFd};

    pub fn create_vm_and_irq_manager() -> (Arc<VmFd>, Arc<KvmIrqManager>) {
        let kvm = Kvm::new().unwrap();
        let vmfd = Arc::new(kvm.create_vm().unwrap());
        assert!(vmfd.create_irq_chip().is_ok());
        let irq_manager = Arc::new(KvmIrqManager::new(vmfd.clone()));
        assert!(irq_manager.initialize().is_ok());

        (vmfd, irq_manager)
    }
}
