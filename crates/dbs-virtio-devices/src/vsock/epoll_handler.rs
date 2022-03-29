// Copyright 2022 Alibaba Cloud. All Rights Reserved.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::ops::Deref;

use dbs_utils::epoll_manager::{EventOps, EventSet, Events, MutEventSubscriber};
use log::{error, trace, warn};
use virtio_queue::{QueueState, QueueStateT};
use vm_memory::{GuestMemoryRegion, GuestRegionMmap};

use super::defs;
use super::muxer::{VsockGenericMuxer, VsockMuxer};
use super::packet::VsockPacket;
use crate::device::VirtioDeviceConfig;
use crate::{DbsGuestAddressSpace, Result as VirtIoResult};

const QUEUE_RX: usize = 0;
const QUEUE_TX: usize = 1;
const QUEUE_CFG: usize = 2;

// TODO: Detect / handle queue deadlock:
// 1. If `self.backend.send_pkt()` errors out, TX queue processing will halt.
//    Try to process any pending backend RX, then try TX again. If it fails
//    again, we have a deadlock.
// 2. If the driver halts RX queue processing, we'll need to notify
//    `self.backend`, so that it can unregister any EPOLLIN listeners, since
//    otherwise it will keep spinning, unable to consume its EPOLLIN events.

/// The vsock `EpollHandler` implements the runtime logic of our vsock device:
/// 1. Respond to TX queue events by wrapping virtio buffers into
///    `VsockPacket`s, then sending those packets to the `VsockBackend`;
/// 2. Forward backend FD event notifications to the `VsockBackend`;
/// 3. Fetch incoming packets from the `VsockBackend` and place them into the
///    virtio RX queue;
/// 4. Whenever we have processed some virtio buffers (either TX or RX), let the
///    driver know by raising our assigned IRQ.
///
/// In a nutshell, the `EpollHandler` logic looks like this:
/// - on TX queue event:
///   - fetch all packets from the TX queue and send them to the backend; then
///   - if the backend has queued up any incoming packets, fetch them into any
///     available RX buffers.
/// - on RX queue event:
///   - fetch any incoming packets, queued up by the backend, into newly
///     available RX buffers.
/// - on backend event:
///   - forward the event to the backend; then
///   - again, attempt to fetch any incoming packets queued by the backend into
///     virtio RX buffers.
pub struct VsockEpollHandler<
    AS: DbsGuestAddressSpace,
    Q: QueueStateT + Send = QueueState,
    R: GuestMemoryRegion = GuestRegionMmap,
    M: VsockGenericMuxer = VsockMuxer,
> {
    pub(crate) config: VirtioDeviceConfig<AS, Q, R>,
    id: String,
    pub(crate) muxer: M,
    _cid: u64,
}

impl<AS, Q, R, M> VsockEpollHandler<AS, Q, R, M>
where
    AS: DbsGuestAddressSpace,
    Q: QueueStateT + Send,
    R: GuestMemoryRegion,
    M: VsockGenericMuxer,
{
    pub fn new(config: VirtioDeviceConfig<AS, Q, R>, id: String, cid: u64, muxer: M) -> Self {
        VsockEpollHandler {
            config,
            id,
            _cid: cid,
            muxer,
        }
    }

    /// Signal the guest driver that we've used some virtio buffers that it had
    /// previously made available.
    pub(crate) fn signal_used_queue(&self, idx: usize) -> VirtIoResult<()> {
        trace!("{}: raising IRQ", self.id);
        self.config.queues[idx].notify().map_err(|e| {
            error!("{}: failed to signal used queue {}, {:?}", self.id, idx, e);
            e
        })
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up
    /// with any data that we have pending.
    fn process_rx(&mut self, mem: &AS::M) {
        trace!("{}: epoll_handler::process_rx()", self.id);
        let mut raise_irq = false;
        {
            let rxvq = &mut self.config.queues[QUEUE_RX].queue_mut().lock();
            loop {
                let mut iter = match rxvq.iter(mem) {
                    Err(e) => {
                        error!("{}: failed to process rx queue. {}", self.id, e);
                        return;
                    }
                    Ok(iter) => iter,
                };

                if let Some(mut desc_chain) = iter.next() {
                    let used_len = match VsockPacket::from_rx_virtq_head(&mut desc_chain) {
                        Ok(mut pkt) => {
                            if self.muxer.recv_pkt(&mut pkt).is_ok() {
                                pkt.hdr().len() as u32 + pkt.len()
                            } else {
                                // We are using a consuming iterator over the virtio buffers, so, if we
                                // can't fill in this buffer, we'll need to undo the last iterator step.
                                iter.go_to_previous_position();
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("{}: RX queue error: {:?}", self.id, e);
                            0
                        }
                    };

                    raise_irq = true;
                    let _ = rxvq.add_used(mem, desc_chain.head_index(), used_len);
                } else {
                    break;
                }
            }
        }
        if raise_irq {
            if let Err(e) = self.signal_used_queue(QUEUE_RX) {
                error!("{}: failed to notify guest for RX queue, {:?}", self.id, e);
            }
        }
    }

    /// Walk the dirver-provided TX queue buffers, package them up as vsock
    /// packets, and send them to the backend for processing.
    fn process_tx(&mut self, mem: &AS::M) {
        trace!("{}: epoll_handler::process_tx()", self.id);
        let mut have_used = false;

        {
            let txvq = &mut self.config.queues[QUEUE_TX].queue_mut().lock();

            loop {
                let mut iter = match txvq.iter(mem) {
                    Err(e) => {
                        error!("{}: failed to process tx queue. {}", self.id, e);
                        return;
                    }
                    Ok(iter) => iter,
                };

                if let Some(mut desc_chain) = iter.next() {
                    let pkt = match VsockPacket::from_tx_virtq_head(&mut desc_chain) {
                        Ok(pkt) => pkt,
                        Err(e) => {
                            error!("{}: error reading TX packet: {:?}", self.id, e);
                            have_used = true;
                            let _ = txvq.add_used(mem, desc_chain.head_index(), 0);
                            continue;
                        }
                    };

                    if self.muxer.send_pkt(&pkt).is_err() {
                        iter.go_to_previous_position();
                        break;
                    }

                    have_used = true;
                    let _ = txvq.add_used(mem, desc_chain.head_index(), 0);
                } else {
                    break;
                }
            }
        }
        if have_used {
            if let Err(e) = self.signal_used_queue(QUEUE_TX) {
                error!("{}: failed to notify guest for TX queue, {:?}", self.id, e);
            }
        }
    }

    pub(crate) fn handle_rxq_event(&mut self, mem: &AS::M) {
        trace!("{}: handle RX queue event", self.id);
        if let Err(e) = self.config.queues[QUEUE_RX].consume_event() {
            error!("{}: failed to consume rx queue event, {:?}", self.id, e);
        } else if self.muxer.has_pending_rx() {
            self.process_rx(mem);
        }
    }

    pub(crate) fn handle_txq_event(&mut self, mem: &AS::M) {
        trace!("{}: handle TX queue event", self.id);
        if let Err(e) = self.config.queues[QUEUE_TX].consume_event() {
            error!("{}: failed to consume tx queue event, {:?}", self.id, e);
        } else {
            self.process_tx(mem);
            // The backend may have queued up responses to the packets
            // we sent during TX queue processing. If that happened, we
            // need to fetch those responses and place them into RX
            // buffers.
            if self.muxer.has_pending_rx() {
                self.process_rx(mem);
            }
        }
    }

    fn handle_evq_event(&mut self, _mem: &AS::M) {
        trace!("{}: handle event queue event", self.id);
        if let Err(e) = self.config.queues[QUEUE_CFG].consume_event() {
            error!("{}: failed to consume config queue event, {:?}", self.id, e);
        }
    }

    pub(crate) fn notify_backend_event(&mut self, events: &Events, mem: &AS::M) {
        trace!("{}: backend event", self.id);
        let events = epoll::Events::from_bits(events.event_set().bits()).unwrap();
        self.muxer.notify(events);
        // After the backend has been kicked, it might've freed up some
        // resources, so we can attempt to send it more data to process. In
        // particular, if `self.backend.send_pkt()` halted the TX queue
        // processing (by reurning an error) at some point in the past, now is
        // the time to try walking the TX queue again.
        self.process_tx(mem);
        // This event may have caused some packets to be queued up by the
        // backend. Make sure they are processed.
        if self.muxer.has_pending_rx() {
            self.process_rx(mem);
        }
    }
}

impl<AS, Q, R, M> MutEventSubscriber for VsockEpollHandler<AS, Q, R, M>
where
    AS: DbsGuestAddressSpace,
    Q: QueueStateT + Send,
    R: GuestMemoryRegion,
    M: VsockGenericMuxer + 'static,
{
    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        let guard = self.config.lock_guest_memory();
        let mem = guard.deref();

        match events.data() {
            defs::RXQ_EVENT => self.handle_rxq_event(mem),
            defs::TXQ_EVENT => self.handle_txq_event(mem),
            defs::EVQ_EVENT => self.handle_evq_event(mem),
            defs::BACKEND_EVENT => self.notify_backend_event(&events, mem),
            _ => error!("{}: unknown epoll event slot {}", self.id, events.data()),
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        trace!("{}: VsockEpollHandler::init()", self.id);

        let events = Events::with_data(
            self.config.queues[QUEUE_RX].eventfd.as_ref(),
            defs::RXQ_EVENT,
            EventSet::IN,
        );
        if let Err(e) = ops.add(events) {
            error!(
                "{}: failed to register epoll event for RX queue, {:?}.",
                self.id, e
            );
        }

        let events = Events::with_data(
            self.config.queues[QUEUE_TX].eventfd.as_ref(),
            defs::TXQ_EVENT,
            EventSet::IN,
        );
        if let Err(e) = ops.add(events) {
            error!(
                "{}: failed to register epoll event for TX queue, {:?}.",
                self.id, e
            );
        }

        let events = Events::with_data(
            self.config.queues[QUEUE_CFG].eventfd.as_ref(),
            defs::EVQ_EVENT,
            EventSet::IN,
        );
        if let Err(e) = ops.add(events) {
            error!(
                "{}: failed to register epoll event for config queue, {:?}.",
                self.id, e
            );
        }

        let be_fd = self.muxer.as_raw_fd();
        let be_evset = EventSet::from_bits(self.muxer.get_polled_evset().bits()).unwrap();
        let events = Events::with_data_raw(be_fd, defs::BACKEND_EVENT, be_evset);
        if let Err(e) = ops.add(events) {
            error!(
                "{}: failed to register epoll event for backend fd: {:?}, {:?}.",
                self.id, be_fd, e
            );
        }
    }
}
