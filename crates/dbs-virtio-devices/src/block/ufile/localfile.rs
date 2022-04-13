// Copyright (C) 2019 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::ManuallyDrop;
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};

use log::{debug, error, info, warn};
use virtio_bindings::bindings::virtio_blk::{VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK};
use vmm_sys_util::aio::{IoContext, IoControlBlock, IoEvent, IOCB_FLAG_RESFD};
use vmm_sys_util::aio::{IOCB_CMD_PREADV, IOCB_CMD_PWRITEV};
use vmm_sys_util::eventfd::EventFd;

use super::{IoDataDesc, Ufile};

pub struct LocalFile {
    pub(crate) file: ManuallyDrop<File>,
    no_drop: bool,
    capacity: u64,
    aio_evtfd: EventFd,
    aio_context: IoContext,
}

impl LocalFile {
    #[allow(dead_code)]
    pub fn new(
        is_direct: bool,
        is_read_only: bool,
        no_drop: bool,
        disk_image_path: String,
    ) -> io::Result<Self> {
        const O_DIRECT: i32 = libc::O_DIRECT;
        let custom_flags = if is_direct {
            debug!("Open block device \"{}\" in direct mode.", disk_image_path);
            O_DIRECT
        } else {
            debug!("Open block device \"{}\" in buffer mode.", disk_image_path);
            0
        };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(custom_flags)
            .write(!is_read_only)
            .open(disk_image_path)?;
        info!("block file opened");

        Self::new_from_file(file, no_drop)
    }

    pub fn new_from_file(mut file: File, no_drop: bool) -> io::Result<Self> {
        let capacity = file.seek(SeekFrom::End(0))?;

        let aio_context = match IoContext::new(256) {
            Ok(c) => c,
            Err(e) => {
                error!("LocalFile: create new aio context: {}", e);
                return Err(e);
            }
        };
        info!("block device aio context created");

        Ok(LocalFile {
            file: ManuallyDrop::new(file),
            no_drop,
            capacity,
            aio_evtfd: EventFd::new(0)?,
            aio_context,
        })
    }
}

// Implement our own Drop for LocalFile, as we don't want to close LocalFile.file if no_drop is
// enabled.
impl Drop for LocalFile {
    fn drop(&mut self) {
        if self.no_drop {
            info!("LocalFile: no_drop is enabled, don't close file on drop");
        } else {
            // Close the raw fd directly.
            let fd = self.file.as_raw_fd();
            if let Err(e) = nix::unistd::close(fd) {
                warn!("LocalFile: failed to close disk file: {:?}", e);
            }
        }
    }
}

impl Read for LocalFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for LocalFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for LocalFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

impl Ufile for LocalFile {
    fn get_capacity(&self) -> u64 {
        self.capacity
    }

    fn get_max_size(&self) -> u32 {
        // Set max size to 1M to avoid interferes with rate limiter.
        0x100000
    }

    fn get_device_id(&self) -> io::Result<String> {
        let blk_metadata = self.file.metadata()?;
        // This is how kvmtool does it.
        Ok(format!(
            "{}{}{}",
            blk_metadata.st_dev(),
            blk_metadata.st_rdev(),
            blk_metadata.st_ino()
        ))
    }

    fn get_data_evt_fd(&self) -> RawFd {
        self.aio_evtfd.as_raw_fd()
    }

    fn io_read_submit(
        &mut self,
        offset: i64,
        iovecs: &mut Vec<IoDataDesc>,
        user_data: u16,
    ) -> io::Result<usize> {
        let iocbs = [&mut IoControlBlock {
            aio_fildes: self.file.as_raw_fd() as u32,
            aio_lio_opcode: IOCB_CMD_PREADV as u16,
            aio_resfd: self.aio_evtfd.as_raw_fd() as u32,
            aio_flags: IOCB_FLAG_RESFD,
            aio_buf: iovecs.as_mut_ptr() as u64,
            aio_offset: offset as i64,
            aio_nbytes: iovecs.len() as u64,
            aio_data: user_data as u64,
            ..Default::default()
        }];
        self.aio_context.submit(&iocbs[..])
    }

    fn io_write_submit(
        &mut self,
        offset: i64,
        iovecs: &mut Vec<IoDataDesc>,
        user_data: u16,
    ) -> io::Result<usize> {
        let iocbs = [&mut IoControlBlock {
            aio_fildes: self.file.as_raw_fd() as u32,
            aio_lio_opcode: IOCB_CMD_PWRITEV as u16,
            aio_resfd: self.aio_evtfd.as_raw_fd() as u32,
            aio_flags: IOCB_FLAG_RESFD,
            aio_buf: iovecs.as_mut_ptr() as u64,
            aio_offset: offset as i64,
            aio_nbytes: iovecs.len() as u64,
            aio_data: user_data as u64,
            ..Default::default()
        }];
        self.aio_context.submit(&iocbs[..])
    }

    // For currently supported LocalFile and TdcFile backend, it must not return temporary errors
    // and may only return permanent errors. So the virtio-blk driver layer will not try to
    // recover and only pass errors up onto the device manager. When changing the error handling
    // policy, please do help to update BlockEpollHandler::io_complete().
    #[allow(clippy::uninit_assumed_init)]
    fn io_complete(&mut self) -> io::Result<Vec<(u16, u32)>> {
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
                    let index = events[idx as usize].data as u16;
                    let res2 = if events[idx as usize].res as i32 >= 0 {
                        VIRTIO_BLK_S_OK
                    } else {
                        VIRTIO_BLK_S_IOERR
                    };
                    v.push((index, res2));
                }
            }
        }
        Ok(v)
    }
}
