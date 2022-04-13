// Copyright 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use vmm_sys_util::aio::{IoContext, IoControlBlock, IoEvent, IOCB_FLAG_RESFD};
use vmm_sys_util::aio::{IOCB_CMD_PREADV, IOCB_CMD_PWRITEV};
use vmm_sys_util::eventfd::EventFd;

use super::IoEngine;
use crate::block::IoDataDesc;

/// Use AIO to perform asynchronous IO requests.
pub struct Aio {
    fd: RawFd,
    aio_evtfd: EventFd,
    aio_context: IoContext,
}

impl Aio {
    /// Creates a new Aio instence.
    ///
    /// # Arguments
    /// * `nr_events`: maximum number of concurrently processing IO operations.
    pub fn new(fd: RawFd, nr_events: u32) -> io::Result<Self> {
        let aio_context = IoContext::new(nr_events)?;
        Ok(Self {
            fd,
            aio_evtfd: EventFd::new(0)?,
            aio_context,
        })
    }
}

impl IoEngine for Aio {
    fn event_fd(&self) -> &EventFd {
        &self.aio_evtfd
    }

    fn readv(
        &mut self,
        offset: i64,
        iovecs: &mut Vec<IoDataDesc>,
        user_data: u64,
    ) -> io::Result<usize> {
        let iocbs = [&mut IoControlBlock {
            aio_fildes: self.fd as u32,
            aio_lio_opcode: IOCB_CMD_PREADV as u16,
            aio_resfd: self.aio_evtfd.as_raw_fd() as u32,
            aio_flags: IOCB_FLAG_RESFD,
            aio_buf: iovecs.as_mut_ptr() as u64,
            aio_offset: offset,
            aio_nbytes: iovecs.len() as u64,
            aio_data: user_data,
            ..Default::default()
        }];

        self.aio_context.submit(&iocbs[..])
    }

    fn writev(
        &mut self,
        offset: i64,
        iovecs: &mut Vec<IoDataDesc>,
        user_data: u64,
    ) -> io::Result<usize> {
        let iocbs = [&mut IoControlBlock {
            aio_fildes: self.fd as u32,
            aio_lio_opcode: IOCB_CMD_PWRITEV as u16,
            aio_resfd: self.aio_evtfd.as_raw_fd() as u32,
            aio_flags: IOCB_FLAG_RESFD,
            aio_buf: iovecs.as_mut_ptr() as u64,
            aio_offset: offset as i64,
            aio_nbytes: iovecs.len() as u64,
            aio_data: user_data,
            ..Default::default()
        }];

        self.aio_context.submit(&iocbs[..])
    }

    // For currently supported LocalFile and TdcFile backend, it must not return temporary errors
    // and may only return permanent errors. So the virtio-blk driver layer will not try to
    // recover and only pass errors up onto the device manager. When changing the error handling
    // policy, please do help to update BlockEpollHandler::io_complete().
    #[allow(clippy::uninit_assumed_init)]
    fn complete(&mut self) -> io::Result<Vec<(u64, i64)>> {
        let count = self.aio_evtfd.read()?;
        let mut v = Vec::with_capacity(count as usize);
        if count > 0 {
            let mut events =
                vec![
                    unsafe { std::mem::MaybeUninit::<IoEvent>::uninit().assume_init() };
                    count as usize
                ];
            while v.len() < count as usize {
                let r = self.aio_context.get_events(1, &mut events[0..], None)?;
                for idx in 0..r {
                    let index = events[idx as usize].data;
                    let res2 = events[idx as usize].res;
                    v.push((index, res2));
                }
            }
        }
        Ok(v)
    }
}
