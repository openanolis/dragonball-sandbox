// Copyright 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::io::Error as IOError;
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{mpsc, Arc, Mutex};

use dbs_utils::epoll_manager::{EventOps, EventSet, Events, MutEventSubscriber};
use dbs_utils::rate_limiter::{BucketUpdate, RateLimiter, TokenType};
use fuse_backend_rs::abi::virtio_fs::RemovemappingOne;
use fuse_backend_rs::api::server::Server;
use fuse_backend_rs::api::Vfs;
use fuse_backend_rs::transport::{FsCacheReqHandler, Reader, Writer};
use log::{debug, error, info, trace};
use threadpool::ThreadPool;
use virtio_queue::QueueStateT;
use vm_memory::{GuestAddressSpace, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

use crate::{Error, Result, VirtioDeviceConfig};

use super::{Error as FsError, VIRTIO_FS_NAME};

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u32 = 0;

// two rate limiter events
const RATE_LIMITER_EVENT_COUNT: u32 = 2;

// Attr and entry timeout values
const CACHE_ALWAYS_TIMEOUT: u64 = 86_400; // 1 day
const CACHE_AUTO_TIMEOUT: u64 = 1;
const CACHE_NONE_TIMEOUT: u64 = 0;

/// CacheHandler handles DAX window mmap/unmap operations
#[derive(Clone)]
pub struct CacheHandler {
    /// the size of memory region allocated for virtiofs
    cache_size: u64,

    /// the address of mmap region corresponding to the memory region
    mmap_cache_addr: u64,

    /// the device ID
    id: String,
}

impl CacheHandler {
    /// Make sure request is within cache range
    fn is_req_valid(&self, offset: u64, len: u64) -> bool {
        // TODO: do we need to validate alignment here?
        match offset.checked_add(len) {
            Some(n) => n <= self.cache_size,
            None => false,
        }
    }
}

impl FsCacheReqHandler for CacheHandler {
    // Do not close fd in here. The fd is automatically closed in the setupmapping
    // of passthrough_fs when destructing.
    fn map(
        &mut self,
        foffset: u64,
        moffset: u64,
        len: u64,
        flags: u64,
        fd: RawFd,
    ) -> std::result::Result<(), IOError> {
        let addr = self.mmap_cache_addr + moffset;
        trace!(
            target: VIRTIO_FS_NAME,
            "{}: CacheHandler::map(): fd={}, foffset=0x{:x}, moffset=0x{:x}(host addr: 0x{:x}), len=0x{:x}, flags=0x{:x}",
            self.id,
            fd,
            foffset,
            moffset,
            addr,
            len,
            flags
        );

        if !self.is_req_valid(moffset, len) {
            error!(
                "{}: CacheHandler::map(): Wrong offset or length, offset=0x{:x} len=0x{:x} cache_size=0x{:x}",
                self.id, moffset, len, self.cache_size
            );
            return Err(IOError::from_raw_os_error(libc::EINVAL));
        }

        // TODO:
        // In terms of security, DAX does not easily handle all kinds of write
        // scenarios, especially append write. Therefore, to prevent guest users
        // from using the DAX to write files maliciously, we do not support guest
        // write permission configuration. If DAX needs to support write, we can
        // add write permissions by Control path.
        let ret = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                len as usize,
                libc::PROT_READ as i32,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                foffset as libc::off_t,
            )
        };
        if ret == libc::MAP_FAILED {
            let e = IOError::last_os_error();
            error!("{}: CacheHandler::map() failed: {}", VIRTIO_FS_NAME, e);
            return Err(e);
        }

        Ok(())
    }

    fn unmap(&mut self, requests: Vec<RemovemappingOne>) -> std::result::Result<(), IOError> {
        trace!(target: VIRTIO_FS_NAME, "{}: CacheHandler::unmap()", self.id,);

        for req in requests {
            let mut offset = req.moffset;
            let mut len = req.len;

            // Ignore if the length is 0.
            if len == 0 {
                continue;
            }

            debug!(
                "{}: do unmap(): offset=0x{:x} len=0x{:x} cache_size=0x{:x}",
                self.id, offset, len, self.cache_size
            );

            // Need to handle a special case where the slave ask for the unmapping
            // of the entire mapping.
            if len == 0xffff_ffff_ffff_ffff {
                len = self.cache_size;
                offset = 0;
            }

            if !self.is_req_valid(offset, len) {
                error!(
                    "{}: CacheHandler::unmap(): Wrong offset or length, offset=0x{:x} len=0x{:x} cache_size=0x{:x}",
                    self.id, offset, len, self.cache_size
                );
                return Err(IOError::from_raw_os_error(libc::EINVAL));
            }

            let addr = self.mmap_cache_addr + offset;
            // Use mmap + PROT_NONE can reserve host userspace address while unmap memory.
            // In this way, guest will not be able to access the memory, and dragonball
            // also can reserve the HVA.
            let ret = unsafe {
                libc::mmap(
                    addr as *mut libc::c_void,
                    len as usize,
                    libc::PROT_NONE,
                    libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
                    -1,
                    0_i64,
                )
            };
            if ret == libc::MAP_FAILED {
                let e = IOError::last_os_error();
                error!("{}: CacheHandler::unmap() failed, {}", self.id, e);
                return Err(e);
            }
        }

        Ok(())
    }
}

pub(crate) struct VirtioFsEpollHandler<
    AS: 'static + GuestAddressSpace,
    Q: QueueStateT,
    R: GuestMemoryRegion,
> {
    pub(crate) config: Arc<Mutex<VirtioDeviceConfig<AS, Q, R>>>,
    server: Arc<Server<Arc<Vfs>>>,
    cache_handler: Option<CacheHandler>,
    thread_pool: Option<ThreadPool>,
    id: String,
    rate_limiter: RateLimiter,
    patch_rate_limiter_fd: EventFd,
    receiver: Option<mpsc::Receiver<(BucketUpdate, BucketUpdate)>>,
}

impl<AS, Q, R> VirtioFsEpollHandler<AS, Q, R>
where
    AS: GuestAddressSpace + Clone + Send,
    AS::T: Send,
    AS::M: Sync + Send,
    Q: QueueStateT + Send + 'static,
    R: GuestMemoryRegion + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: VirtioDeviceConfig<AS, Q, R>,
        fs: Arc<Vfs>,
        cache_handler: Option<CacheHandler>,
        thread_pool_size: u16,
        id: String,
        rate_limiter: RateLimiter,
        patch_rate_limiter_fd: EventFd,
        receiver: Option<mpsc::Receiver<(BucketUpdate, BucketUpdate)>>,
    ) -> Result<Self> {
        let thread_pool = if thread_pool_size > 0 {
            Some(ThreadPool::with_name(
                "virtiofs-thread".to_string(),
                thread_pool_size as usize,
            ))
        } else {
            None
        };
        let handler = Self {
            config: Arc::new(Mutex::new(config)),
            server: Arc::new(Server::new(fs)),
            cache_handler,
            thread_pool,
            id,
            rate_limiter,
            patch_rate_limiter_fd,
            receiver,
        };
        Ok(handler)
    }

    fn process_queue(&mut self, queue_index: usize) -> Result<()> {
        let mut config_guard = self.config.lock().unwrap();
        let mem = config_guard.lock_guest_memory();
        let vm_as = config_guard.vm_as.clone();
        let queue = &mut config_guard.queues[queue_index];
        let (tx, rx) = mpsc::channel::<(u16, u32)>();
        let mut used_count = 0;
        let mut rate_limited = false;
        // TODO: use multiqueue to process new entries.

        let mut queue_guard = queue.queue_mut().lock();
        let mut iter = queue_guard
            .iter(mem.clone())
            .map_err(Error::VirtioQueueError)?;

        for desc_chain in &mut iter {
            // Prepare a set of objects that can be moved to the worker thread.
            if !self.rate_limiter.consume(1, TokenType::Ops) {
                rate_limited = true;
                break;
            }

            let head_index = desc_chain.head_index();
            let server = self.server.clone();
            let vm_as = vm_as.clone();
            let config = self.config.clone();
            let pooled = self.is_multi_thread();
            let tx = tx.clone();
            used_count += 1;
            let mut cache_handler = self.cache_handler.clone();

            let work_func = move || {
                let guard = vm_as.memory();
                let mem = guard.deref();
                let reader = Reader::new(mem, desc_chain.clone())
                    .map_err(FsError::InvalidDescriptorChain)
                    .unwrap();
                let writer = Writer::new(mem, desc_chain)
                    .map_err(FsError::InvalidDescriptorChain)
                    .unwrap();
                let total = server
                    .handle_message(
                        reader,
                        writer,
                        cache_handler
                            .as_mut()
                            .map(|x| x as &mut dyn FsCacheReqHandler),
                        None,
                    )
                    .map_err(FsError::ProcessQueue)
                    .unwrap();

                if pooled {
                    let queue = &mut config.lock().unwrap().queues[queue_index];
                    queue.add_used(mem, head_index, total as u32);
                    if let Err(e) = queue.notify() {
                        error!("failed to signal used queue: {:?}", e);
                    }
                } else {
                    tx.send((head_index, total as u32))
                        .expect("virtiofs: failed to send fuse result");
                }
            };

            if let Some(pool) = &self.thread_pool {
                trace!("{}: poping new fuse req to thread pool.", VIRTIO_FS_NAME,);
                pool.execute(work_func);
            } else {
                work_func();
            }
        }
        if rate_limited {
            iter.go_to_previous_position();
        }

        let notify = !self.is_multi_thread() && used_count > 0;
        // unlock QueueStateT
        drop(queue_guard);
        while !self.is_multi_thread() && used_count > 0 {
            used_count -= 1;
            let (idx, ret) = rx
                .recv()
                .expect("virtiofs: failed to recv result from thread pool");
            queue.add_used(mem.deref(), idx, ret);
        }

        if notify {
            if let Err(e) = queue.notify() {
                error!("failed to signal used queue: {:?}", e);
            }
        }

        Ok(())
    }

    pub fn get_patch_rate_limiters(&mut self, bytes: BucketUpdate, ops: BucketUpdate) {
        info!("{}: Update rate limiter for fs device", VIRTIO_FS_NAME);
        match &bytes {
            BucketUpdate::Update(tb) => {
                info!(
                    "{}: update bandwidth, \"size\": {}, \"one_time_burst\": {}, \"refill_time\": {}",
                    VIRTIO_FS_NAME,
                    tb.capacity(),
                    tb.one_time_burst(),
                    tb.refill_time_ms()
                );
            }
            BucketUpdate::None => {
                info!("{}: no update for bandwidth", VIRTIO_FS_NAME);
            }
            _ => {
                info!("{}: bandwidth limiting is disabled", VIRTIO_FS_NAME);
            }
        }
        match &ops {
            BucketUpdate::Update(tb) => {
                info!(
                    "{}: update ops, \"size\": {}, \"one_time_burst\": {}, \"refill_time\": {}",
                    VIRTIO_FS_NAME,
                    tb.capacity(),
                    tb.one_time_burst(),
                    tb.refill_time_ms()
                );
            }
            BucketUpdate::None => {
                info!("{}: no update for ops", VIRTIO_FS_NAME);
            }
            _ => {
                info!("{}: ops limiting is disabled", VIRTIO_FS_NAME);
            }
        }
        self.rate_limiter.update_buckets(bytes, ops);
    }

    // True if thread pool is enabled.
    fn is_multi_thread(&self) -> bool {
        self.thread_pool.is_some()
    }
}

impl<AS, Q, R> MutEventSubscriber for VirtioFsEpollHandler<AS, Q, R>
where
    AS: GuestAddressSpace + Send + Sync + 'static + Clone,
    AS::T: Send,
    AS::M: Sync + Send,
    Q: QueueStateT + Send + 'static,
    R: GuestMemoryRegion + Send + Sync + 'static,
{
    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        trace!(
            target: VIRTIO_FS_NAME,
            "{}: VirtioFsHandler::process({})",
            self.id,
            events.data()
        );

        let slot = events.data();
        let config = &self.config.clone();
        let guard = config.lock().unwrap();
        let queues = &guard.queues;

        let queues_len = queues.len() as u32;
        // Rate limiter budget is now available.
        let rate_limiter_event = QUEUE_AVAIL_EVENT + queues_len;
        // patch request of rate limiter has arrived
        let patch_rate_limiter_event = rate_limiter_event + 1;

        match slot {
            s if s >= RATE_LIMITER_EVENT_COUNT + QUEUE_AVAIL_EVENT + queues_len => {
                error!("{}: unknown epoll event slot {}", VIRTIO_FS_NAME, slot);
            }

            s if s == rate_limiter_event => match self.rate_limiter.event_handler() {
                Ok(()) => {
                    drop(guard);
                    for idx in QUEUE_AVAIL_EVENT as usize..(QUEUE_AVAIL_EVENT + queues_len) as usize
                    {
                        if let Err(e) = self.process_queue(idx) {
                            error!("{}: error in queue {}, {:?}", VIRTIO_FS_NAME, idx, e);
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "{}: the rate limiter is disabled or is not blocked, {:?}",
                        VIRTIO_FS_NAME, e
                    );
                }
            },

            s if s == patch_rate_limiter_event => {
                if let Err(e) = self.patch_rate_limiter_fd.read() {
                    error!("{}: failed to get patch event, {:?}", VIRTIO_FS_NAME, e);
                }
                if let Some(receiver) = &self.receiver {
                    if let Ok((bytes, ops)) = receiver.try_recv() {
                        self.get_patch_rate_limiters(bytes, ops);
                    }
                }
            }

            // QUEUE_AVAIL_EVENT
            _ => {
                let idx = (slot - QUEUE_AVAIL_EVENT) as usize;
                if let Err(e) = queues[idx].consume_event() {
                    error!("{}: failed to read queue event, {:?}", VIRTIO_FS_NAME, e);
                    return;
                }
                drop(guard);

                if let Err(e) = self.process_queue(idx) {
                    error!(
                        "{}: process_queue failed due to error {:?}",
                        VIRTIO_FS_NAME, e
                    );
                }
            }
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        trace!(
            target: VIRTIO_FS_NAME,
            "{}: VirtioFsHandler::init()",
            self.id
        );

        let queues = &self.config.lock().unwrap().queues;

        for (idx, queue) in queues.iter().enumerate() {
            let events = Events::with_data(
                queue.eventfd.as_ref(),
                QUEUE_AVAIL_EVENT + idx as u32,
                EventSet::IN,
            );
            if let Err(e) = ops.add(events) {
                error!(
                    "{}: failed to register epoll event for event queue {}, {:?}",
                    VIRTIO_FS_NAME, idx, e
                );
            }
        }

        let rate_limiter_fd = self.rate_limiter.as_raw_fd();
        if rate_limiter_fd != -1 {
            if let Err(e) = ops.add(Events::with_data_raw(
                rate_limiter_fd,
                QUEUE_AVAIL_EVENT + queues.len() as u32,
                EventSet::IN,
            )) {
                error!(
                    "{}: failed to register rate limiter event, {:?}",
                    VIRTIO_FS_NAME, e
                );
            }
        }

        if let Err(e) = ops.add(Events::with_data(
            &self.patch_rate_limiter_fd,
            1 + QUEUE_AVAIL_EVENT + queues.len() as u32,
            EventSet::IN,
        )) {
            error!(
                "{}: failed to register rate limiter patch event {:?}",
                VIRTIO_FS_NAME, e
            );
        }
    }
}
