// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

pub mod backend;
pub mod csm;
mod device;
mod epoll_handler;
pub mod muxer;
mod packet;

use std::os::unix::io::AsRawFd;

use vm_memory::GuestMemoryError;

pub use self::defs::{NUM_QUEUES, QUEUE_SIZES};
pub use self::device::Vsock;
use self::muxer::Error as MuxerError;
pub use self::muxer::VsockMuxer;
use self::packet::VsockPacket;

mod defs {
    /// RX queue event: the driver added available buffers to the RX queue.
    pub const RXQ_EVENT: u32 = 0;
    /// TX queue event: the driver added available buffers to the RX queue.
    pub const TXQ_EVENT: u32 = 1;
    /// Event queue event: the driver added available buffers to the event
    /// queue.
    pub const EVQ_EVENT: u32 = 2;
    /// Backend event: the backend needs a kick.
    pub const BACKEND_EVENT: u32 = 3;

    /// Number of virtio queues.
    pub const NUM_QUEUES: usize = 3;
    /// Virtio queue sizes, in number of descriptor chain heads.
    ///
    /// There are 3 queues for a virtio device (in this order): RX, TX, Event
    pub const QUEUE_SIZES: &[u16] = &[256; NUM_QUEUES];

    /// Max vsock packet data/buffer size.
    pub const MAX_PKT_BUF_SIZE: usize = 64 * 1024;

    pub mod uapi {
        /// Virtio feature flags.
        ///
        /// Defined in `/include/uapi/linux/virtio_config.h`.
        ///
        /// The device processes available buffers in the same order in which
        /// the device offers them.
        pub const VIRTIO_F_IN_ORDER: usize = 35;
        /// The device conforms to the virtio spec version 1.0.
        pub const VIRTIO_F_VERSION_1: u32 = 32;

        /// Virtio vsock device ID.
        ///
        /// Defined in `include/uapi/linux/virtio_ids.h`.
        pub const VIRTIO_ID_VSOCK: u32 = 19;

        /// Vsock packet operation IDs.
        ///
        /// Defined in `/include/uapi/linux/virtio_vsock.h`.
        ///
        /// Connection request.
        pub const VSOCK_OP_REQUEST: u16 = 1;
        /// Connection response.
        pub const VSOCK_OP_RESPONSE: u16 = 2;
        /// Connection reset.
        pub const VSOCK_OP_RST: u16 = 3;
        /// Connection clean shutdown.
        pub const VSOCK_OP_SHUTDOWN: u16 = 4;
        /// Connection data (read/write).
        pub const VSOCK_OP_RW: u16 = 5;
        /// Flow control credit update.
        pub const VSOCK_OP_CREDIT_UPDATE: u16 = 6;
        /// Flow control credit update request.
        pub const VSOCK_OP_CREDIT_REQUEST: u16 = 7;

        /// Vsock packet flags. Defined in `/include/uapi/linux/virtio_vsock.h`.
        ///
        /// Valid with a VSOCK_OP_SHUTDOWN packet: the packet sender will
        /// receive no more data.
        pub const VSOCK_FLAGS_SHUTDOWN_RCV: u32 = 1;
        /// Valid with a VSOCK_OP_SHUTDOWN packet: the packet sender will send
        /// no more data.
        pub const VSOCK_FLAGS_SHUTDOWN_SEND: u32 = 2;

        /// Vsock packet type.
        /// Defined in `/include/uapi/linux/virtio_vsock.h`.
        ///
        /// Stream / connection-oriented packet (the only currently valid type).
        pub const VSOCK_TYPE_STREAM: u16 = 1;

        /// Well known vsock CID for host system.
        pub const VSOCK_HOST_CID: u64 = 2;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VsockError {
    /// vsock backend error
    #[error("Vsock backend error: {0}")]
    Backend(#[source] std::io::Error),
    /// The vsock data/buffer virtio descriptor is expected, but missing.
    #[error("The vsock data/buffer virtio descriptor is expected, but missing")]
    BufDescMissing,
    /// The vsock data/buffer virtio descriptor length is smaller than expected.
    #[error("The vsock data/buffer virtio descriptor length is smaller than expected")]
    BufDescTooSmall,
    /// Chained GuestMemory error.
    #[error("Chained GuestMemory error: {0}")]
    GuestMemory(#[source] GuestMemoryError),
    /// Bounds check failed on guest memory pointer.
    #[error("Bounds check failed on guest memory pointer, addr: {0}, size: {1}")]
    GuestMemoryBounds(u64, usize),
    /// The vsock header descriptor length is too small.
    #[error("The vsock header descriptor length {0} is too small")]
    HdrDescTooSmall(u32),
    /// The vsock header `len` field holds an invalid value.
    #[error("The vsock header `len` field holds an invalid value {0}")]
    InvalidPktLen(u32),
    /// vsock muxer error
    #[error("Vsock muxer error: {0}")]
    Muxer(#[source] MuxerError),
    /// A data fetch was attempted when no data was available.
    #[error("A data fetch was attempted when no data was available")]
    NoData,
    /// A data buffer was expected for the provided packet, but it is missing.
    #[error("A data buffer was expected for the provided packet, but it is missing")]
    PktBufMissing,
    /// Encountered an unexpected write-only virtio descriptor.
    #[error("Encountered an unexpected write-only virtio descriptor")]
    UnreadableDescriptor,
    /// Encountered an unexpected read-only virtio descriptor.
    #[error("Encountered an unexpected read-only virtio descriptor")]
    UnwritableDescriptor,
}

type Result<T> = std::result::Result<T, VsockError>;

/// A passive, event-driven object, that needs to be notified whenever an
/// epoll-able event occurs. An event-polling control loop will use
/// `get_polled_fd()` and `get_polled_evset()` to query the listener for the
/// file descriptor and the set of events it's interested in. When such an event
/// occurs, the control loop will route the event to the listener via
/// `notify()`.
pub trait VsockEpollListener: AsRawFd {
    /// Get the set of events for which the listener wants to be notified.
    fn get_polled_evset(&self) -> epoll::Events;

    /// Notify the listener that one ore more events have occured.
    fn notify(&mut self, evset: epoll::Events);
}

/// Any channel that handles vsock packet traffic: sending and receiving
/// packets. Since we're implementing the device model here, our responsibility
/// is to always process the sending of packets (i.e. the TX queue). So, any
/// locally generated data, addressed to the driver (e.g. a connection response
/// or RST), will have to be queued, until we get to processing the RX queue.
///
/// Note: `recv_pkt()` and `send_pkt()` are named analogous to `Read::read()`
///       and `Write::write()`, respectively. I.e. - `recv_pkt()` will read data
///       from the channel, and place it into a packet; and - `send_pkt()` will
///       fetch data from a packet, and place it into the channel.
pub trait VsockChannel {
    /// Read/receive an incoming packet from the channel.
    fn recv_pkt(&mut self, pkt: &mut VsockPacket) -> Result<()>;

    /// Write/send a packet through the channel.
    fn send_pkt(&mut self, pkt: &VsockPacket) -> Result<()>;

    /// Checks weather there is pending incoming data inside the channel,
    /// meaning that a subsequent call to `recv_pkt()` won't fail.
    fn has_pending_rx(&self) -> bool;
}
