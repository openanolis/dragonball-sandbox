// Copyright 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

mod handler;
pub(crate) use self::handler::*;

use fuse_backend_rs::transport::Error as FuseTransportError;
use fuse_backend_rs::Error as FuseServerError;

pub const VIRTIO_FS_NAME: &str = "virtio-fs";

/// Error for virtio fs device.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid Virtio descriptor chain.
    #[error("invalid descriptorchain: {0}")]
    InvalidDescriptorChain(FuseTransportError),
    /// Processing queue failed.
    #[error("process queue failed: {0}")]
    ProcessQueue(FuseServerError),
}
