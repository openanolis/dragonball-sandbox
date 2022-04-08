// Copyright 2022 Alibaba Cloud. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

use log::info;

use super::super::{Result, VsockError};
use super::{VsockBackend, VsockBackendType, VsockStream};

impl VsockStream for UnixStream {
    fn backend_type(&self) -> VsockBackendType {
        VsockBackendType::UnixStream
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> std::io::Result<()> {
        UnixStream::set_nonblocking(self, nonblocking)
    }

    fn set_read_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_read_timeout(self, dur)
    }

    fn set_write_timeout(&mut self, dur: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_write_timeout(self, dur)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The backend implementation that using Unix Stream.
pub struct VsockUnixStreamBackend {
    /// The Unix socket, through which host-initiated connections are accepted.
    pub(crate) host_sock: UnixListener,
    /// The file system path of the host-side Unix socket.
    pub(crate) host_sock_path: String,
}

impl VsockUnixStreamBackend {
    pub fn new(host_sock_path: String) -> Result<Self> {
        info!("Open vsock uds: {}", host_sock_path);
        // Open/bind/listen on the host Unix socket, so we can accept
        // host-initiated connections.
        let host_sock = UnixListener::bind(&host_sock_path)
            .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
            .map_err(VsockError::Backend)?;
        info!("vsock uds opened");

        Ok(VsockUnixStreamBackend {
            host_sock,
            host_sock_path,
        })
    }
}

impl AsRawFd for VsockUnixStreamBackend {
    fn as_raw_fd(&self) -> RawFd {
        self.host_sock.as_raw_fd()
    }
}

impl VsockBackend for VsockUnixStreamBackend {
    fn accept(&mut self) -> std::io::Result<Box<dyn VsockStream>> {
        let (stream, _) = self.host_sock.accept()?;
        stream.set_nonblocking(true)?;

        Ok(Box::new(stream))
    }

    fn connect(&self, dst_port: u32) -> std::io::Result<Box<dyn VsockStream>> {
        // We can figure out the path to Unix sockets listening on specific
        // ports using `host_sock_path` field. I.e. "<this path>_<port number>".
        let port_path = format!("{}_{}", self.host_sock_path, dst_port);
        let stream = UnixStream::connect(port_path)?;
        stream.set_nonblocking(true)?;

        Ok(Box::new(stream))
    }

    fn r#type(&self) -> VsockBackendType {
        VsockBackendType::UnixStream
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
