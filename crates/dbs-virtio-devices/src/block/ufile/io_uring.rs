// Copyright 2022 Alibaba Cloud. All rights reserved.
// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use io_uring::{opcode, squeue, types, Probe};
use log::info;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use super::IoEngine;
use crate::block::IoDataDesc;

/// Use io_uring to perform asynchronous IO requests.
pub struct IoUring {
    fd: RawFd,
    io_uring: io_uring::IoUring,
    evtfd: EventFd,
}

impl IoUring {
    /// Creates a new IoUring instance.
    ///
    /// # Arguments
    /// * `entries`: size of queue, and its value should be the power of two.
    pub fn new(fd: RawFd, entries: u32) -> io::Result<Self> {
        let io_uring = io_uring::IoUring::new(entries)?;
        let evtfd = EventFd::new(EFD_NONBLOCK)?;

        // Register the io_uring eventfd that will notify when something in
        // the completion queue is ready.
        io_uring.submitter().register_eventfd(evtfd.as_raw_fd())?;

        Ok(Self {
            fd,
            evtfd,
            io_uring,
        })
    }

    /// Check if io_uring for block device can be used on the current system, as
    /// it correctly supports the expected io_uring features.
    pub fn is_supported() -> bool {
        let error_msg = "io_uring not supported:";

        // Check we can create an io_uring instance, which effectively verifies
        // that io_uring_setup() syscall is supported.
        let io_uring = match io_uring::IoUring::new(1) {
            Ok(io_uring) => io_uring,
            Err(e) => {
                info!("{} failed to create io_uring instance: {}", error_msg, e);
                return false;
            }
        };

        let submitter = io_uring.submitter();

        let mut probe = Probe::new();

        // Check we can register a probe to validate supported operations.
        match submitter.register_probe(&mut probe) {
            Ok(_) => {}
            Err(e) => {
                info!("{} failed to register a probe: {}", error_msg, e);
                return false;
            }
        }

        // Check IORING_OP_READ is supported
        if !probe.is_supported(opcode::Read::CODE) {
            info!("{} IORING_OP_READ operation not supported", error_msg);
            return false;
        }

        // Check IORING_OP_WRITE is supported
        if !probe.is_supported(opcode::Write::CODE) {
            info!("{} IORING_OP_WRITE operation not supported", error_msg);
            return false;
        }

        true
    }
}

impl IoEngine for IoUring {
    fn event_fd(&self) -> &EventFd {
        &self.evtfd
    }

    fn readv(
        &mut self,
        offset: i64,
        iovecs: &mut Vec<IoDataDesc>,
        user_data: u64,
    ) -> io::Result<usize> {
        let (submit, mut sq, _cq) = self.io_uring.split();

        // Safe because we know the file descriptor is valid and we
        // relied on vm-memory to provide the buffer address.
        let _ = unsafe {
            sq.push(
                &opcode::Readv::new(
                    types::Fd(self.fd),
                    iovecs.as_ptr() as *const libc::iovec,
                    iovecs.len() as u32,
                )
                .offset(offset)
                .build()
                .flags(squeue::Flags::ASYNC)
                .user_data(user_data),
            )
        };

        // Update the submission queue and submit new operations to the
        // io_uring instance.
        sq.sync();
        submit.submit()
    }

    fn writev(
        &mut self,
        offset: i64,
        iovecs: &mut Vec<IoDataDesc>,
        user_data: u64,
    ) -> io::Result<usize> {
        let (submit, mut sq, _cq) = self.io_uring.split();

        // Safe because we know the file descriptor is valid and we
        // relied on vm-memory to provide the buffer address.
        let _ = unsafe {
            sq.push(
                &opcode::Writev::new(
                    types::Fd(self.fd),
                    iovecs.as_ptr() as *const libc::iovec,
                    iovecs.len() as u32,
                )
                .offset(offset)
                .build()
                .flags(squeue::Flags::ASYNC)
                .user_data(user_data),
            )
        };

        // Update the submission queue and submit new operations to the
        // io_uring instance.
        sq.sync();
        submit.submit()
    }

    fn complete(&mut self) -> io::Result<Vec<(u64, i64)>> {
        let _ = self.evtfd.read()?;
        let mut completion_list = Vec::new();

        let cq = self.io_uring.completion();
        for cq_entry in cq {
            completion_list.push((cq_entry.user_data(), cq_entry.result() as i64));
        }

        Ok(completion_list)
    }
}
