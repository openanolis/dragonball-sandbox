// Copyright (C) 2019 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::ManuallyDrop;
use std::os::linux::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, RawFd};

use log::{info, warn};
use virtio_bindings::bindings::virtio_blk::{VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK};

use super::{IoDataDesc, IoEngine, Ufile};

pub struct LocalFile<E> {
    pub(crate) file: ManuallyDrop<File>,
    no_drop: bool,
    capacity: u64,
    io_engine: E,
}

impl<E> LocalFile<E> {
    /// Creates a LocalFile instance.
    pub fn new(mut file: File, no_drop: bool, io_engine: E) -> io::Result<Self> {
        let capacity = file.seek(SeekFrom::End(0))?;

        Ok(Self {
            file: ManuallyDrop::new(file),
            no_drop,
            capacity,
            io_engine,
        })
    }
}

// Implement our own Drop for LocalFile, as we don't want to close LocalFile.file if no_drop is
// enabled.
impl<E> Drop for LocalFile<E> {
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

impl<E> Read for LocalFile<E> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl<E> Write for LocalFile<E> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl<E> Seek for LocalFile<E> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

impl<E: IoEngine + Send> Ufile for LocalFile<E> {
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
        self.io_engine.event_fd().as_raw_fd()
    }

    fn io_read_submit(
        &mut self,
        offset: i64,
        iovecs: &mut Vec<IoDataDesc>,
        user_data: u16,
    ) -> io::Result<usize> {
        self.io_engine.readv(offset, iovecs, user_data as u64)
    }

    fn io_write_submit(
        &mut self,
        offset: i64,
        iovecs: &mut Vec<IoDataDesc>,
        user_data: u16,
    ) -> io::Result<usize> {
        self.io_engine.writev(offset, iovecs, user_data as u64)
    }

    fn io_complete(&mut self) -> io::Result<Vec<(u16, u32)>> {
        Ok(self
            .io_engine
            .complete()?
            .iter()
            .map(|(user_data, res)| {
                (
                    *user_data as u16,
                    if *res >= 0 {
                        VIRTIO_BLK_S_OK
                    } else {
                        VIRTIO_BLK_S_IOERR
                    },
                )
            })
            .collect())
    }
}
