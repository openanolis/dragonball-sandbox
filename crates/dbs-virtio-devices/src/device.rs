// Copyright 2019-2020 Alibaba Cloud. All rights reserved.
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Traits and Structs to implement Virtio device backend drivers.

use std::ops::Deref;

use dbs_interrupt::{InterruptNotifier, NoopNotifier};
use virtio_queue::{AvailIter, QueueState, QueueStateT};
use vm_memory::GuestMemory;
use vmm_sys_util::eventfd::EventFd;

use crate::{Error, Result};

/// Configuration information for a virtio queue.
///
/// This structure maintain all configuration information associated with a virtio queue.
/// It could be sent to a IO worker thread to process requests from the virtio queue,
/// to support multi-queue multi-worker-thread mode,
pub struct VirtioQueueConfig {
    /// Virtque object
    pub queue: QueueState,
    /// EventFd to receive queue notification from guest.
    pub eventfd: EventFd,
    /// Notifier to inject interrupt to guest.
    notifier: Box<dyn InterruptNotifier>,
    /// Queue index in the queue array.
    index: u16,
}

impl VirtioQueueConfig {
    /// Create a configuration object for a virtio queue.
    pub fn new(
        queue: QueueState,
        eventfd: EventFd,
        notifier: Box<dyn InterruptNotifier>,
        index: u16,
    ) -> Self {
        VirtioQueueConfig {
            queue,
            eventfd,
            notifier,
            index,
        }
    }

    /// Creates a VirtioQueueConfig with the specified queue size and index.
    pub fn create(queue_size: u16, index: u16) -> Result<Self> {
        let eventfd = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::IOError)?;

        Ok(VirtioQueueConfig {
            queue: QueueState::new(queue_size),
            eventfd,
            notifier: Box::new(NoopNotifier::new()),
            index,
        })
    }

    /// Get index of the queue.
    #[inline]
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Get the maximum queue size.
    #[inline]
    pub fn max_size(&self) -> u16 {
        self.queue.max_size()
    }

    /// Return the actual size of the queue, as the driver may not set up a
    /// queue as big as the device allows.
    #[inline]
    pub fn actual_size(&self) -> u16 {
        std::cmp::min(self.queue.size, self.queue.max_size)
    }

    /// A consuming iterator over all available descriptor chain heads offered by the driver.
    #[inline]
    pub fn iter<M>(&mut self, mem: M) -> Result<AvailIter<'_, M>>
    where
        M: Deref,
        M::Target: GuestMemory + Sized,
    {
        self.queue.iter(mem).map_err(Error::VirtioQueueError)
    }

    /// Puts an available descriptor head into the used ring for use by the guest.
    #[inline]
    pub fn add_used<M: GuestMemory>(&mut self, mem: &M, desc_index: u16, len: u32) {
        self.queue
            .add_used(mem, desc_index, len)
            .unwrap_or_else(|_| panic!("Failed to add used. index: {}", desc_index))
    }

    /// Consume a notification event.
    #[inline]
    pub fn comsume_event(&self) -> Result<u64> {
        self.eventfd.read().map_err(Error::IOError)
    }

    /// Produce a queue notification.
    #[inline]
    pub fn generate_event(&self) -> Result<()> {
        self.eventfd.write(1).map_err(Error::IOError)
    }

    /// Inject an interrupt to guest to notify queue change events.
    #[inline]
    pub fn notify(&self) -> Result<()> {
        self.notifier.notify().map_err(Error::IOError)
    }

    /// Set event notifier to inject intterupt.
    #[inline]
    pub fn set_notifier(&mut self, notifier: Box<dyn InterruptNotifier>) {
        self.notifier = notifier;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use dbs_interrupt::{
        InterruptManager, InterruptSourceType, InterruptStatusRegister32, LegacyNotifier,
    };
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    use super::*;
    use crate::{VIRTIO_INTR_VRING};

    #[test]
    fn test_create_virtio_queue_config() {
        let (_vmfd, irq_manager) = crate::tests::create_vm_and_irq_manager();
        let group = irq_manager
            .create_group(InterruptSourceType::LegacyIrq, 0, 1)
            .unwrap();
        let status = Arc::new(InterruptStatusRegister32::new());
        let notifier = Box::new(LegacyNotifier::new(group, status, VIRTIO_INTR_VRING));

        let mut cfg = VirtioQueueConfig::create(1024, 1).unwrap();
        cfg.set_notifier(notifier);

        let mem =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        let mut iter = cfg.iter(mem).unwrap();
        assert!(matches!(iter.next(), None));

        cfg.notify().unwrap();
        assert_eq!(cfg.index(), 1);
        assert_eq!(cfg.max_size(), 1024);
        assert_eq!(cfg.actual_size(), 1024);
        cfg.generate_event().unwrap();
        assert_eq!(cfg.comsume_event().unwrap(), 1);
    }
}
