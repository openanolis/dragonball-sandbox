// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::mem;

use dbs_utils::rate_limiter::RateLimiter;
use virtio_bindings::bindings::virtio_net::*;
use virtio_queue::QueueStateT;
use vm_memory::GuestAddress;

use crate::VirtioQueueConfig;

/// The maximum buffer size when segmentation offload is enabled. This
/// includes the 12-byte virtio net header.
/// http://docs.oasis-open.org/virtio/virtio/v1.0/virtio-v1.0.html#x1-1740003
const MAX_BUFFER_SIZE: usize = 65562;

struct TxVirtio<Q: QueueStateT> {
    queue: VirtioQueueConfig<Q>,
    rate_limiter: RateLimiter,
    iovec: Vec<(GuestAddress, usize)>,
    used_desc_heads: Vec<u16>,
    frame_buf: [u8; MAX_BUFFER_SIZE],
}

impl<Q: QueueStateT> TxVirtio<Q> {
    fn new(queue: VirtioQueueConfig<Q>, rate_limiter: RateLimiter) -> Self {
        let tx_queue_max_size = queue.max_size() as usize;

        TxVirtio {
            queue,
            rate_limiter,
            iovec: Vec::with_capacity(tx_queue_max_size),
            used_desc_heads: vec![0u16; tx_queue_max_size],
            frame_buf: [0u8; MAX_BUFFER_SIZE],
        }
    }
}

struct RxVirtio<Q: QueueStateT> {
    queue: VirtioQueueConfig<Q>,
    rate_limiter: RateLimiter,
    deferred_frame: bool,
    deferred_irqs: bool,
    bytes_read: usize,
    frame_buf: [u8; MAX_BUFFER_SIZE],
}

impl<Q: QueueStateT> RxVirtio<Q> {
    fn new(queue: VirtioQueueConfig<Q>, rate_limiter: RateLimiter) -> Self {
        RxVirtio {
            queue,
            rate_limiter,
            deferred_frame: false,
            deferred_irqs: false,
            bytes_read: 0,
            frame_buf: [0u8; MAX_BUFFER_SIZE],
        }
    }
}

fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}
