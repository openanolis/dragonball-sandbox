// Copyright 2022 Alibaba Cloud. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::any::Any;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::Arc;
use std::time::Duration;

use log::error;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK, EFD_SEMAPHORE};

use super::{VsockBackend, VsockBackendType, VsockStream};

#[derive(Debug)]
enum InnerStreamRole {
    Internal,
    External,
}

/// The stream implementation of vsock inner backend. It can be used like a
/// normal unix stream.
///
/// When working with epoll, VsockInnerStream only can be used with
/// `level-trigged` mode.
pub struct VsockInnerStream {
    stream_event: Arc<EventFd>,
    peer_event: Arc<EventFd>,
    writer: Sender<Vec<u8>>,
    reader: Receiver<Vec<u8>>,
    read_buf: Option<(Vec<u8>, usize)>,
    stream_nonblocking: Arc<AtomicBool>,
    peer_nonblocking: Arc<AtomicBool>,
    read_timeout: Option<Duration>,
    role: InnerStreamRole,
}

impl VsockInnerStream {
    fn new(
        stream_event: Arc<EventFd>,
        peer_event: Arc<EventFd>,
        writer: Sender<Vec<u8>>,
        reader: Receiver<Vec<u8>>,
        stream_nonblocking: Arc<AtomicBool>,
        peer_nonblocking: Arc<AtomicBool>,
        role: InnerStreamRole,
    ) -> Self {
        VsockInnerStream {
            stream_event,
            peer_event,
            writer,
            reader,
            read_buf: None,
            stream_nonblocking,
            peer_nonblocking,
            read_timeout: None,
            role,
        }
    }

    fn recv_msg_from_channel(
        &mut self,
        buf: &mut [u8],
        msg: Vec<u8>,
        total_read_len: &mut usize,
    ) -> Result<bool> {
        let read_len = Self::read_msg_from_vec(buf, &msg, *total_read_len, 0);
        let mut read_finish = false;
        *total_read_len += read_len;

        if read_len < msg.len() {
            // buf is full, but msg is not fully read, save it in read_buf (the
            // previous read_buf should have been read through before)
            self.read_buf = Some((msg, read_len));
            read_finish = true;
        } else {
            // if msg is fully read, consume one event, and go
            // on read next message
            self.consume_event()?;
        }

        Ok(read_finish)
    }

    fn trigger_peer_event(&self) -> Result<()> {
        self.peer_event.write(1).map_err(|e| {
            error!(
                "vsock inner stream {:?}: trigger peer event failed: {:?}",
                self.role, e
            );
            e
        })?;

        Ok(())
    }

    fn consume_event(&self) -> Result<()> {
        self.stream_event.read().map_err(|e| {
            error!(
                "vsock inner stream {:?}: consume event failed: {:?}",
                self.role, e
            );
            e
        })?;

        Ok(())
    }

    fn read_msg_from_vec(buf: &mut [u8], msg: &[u8], buf_start: usize, msg_start: usize) -> usize {
        let min_len = std::cmp::min(buf.len() - buf_start, msg.len() - msg_start);
        buf[buf_start..buf_start + min_len].copy_from_slice(&msg[msg_start..msg_start + min_len]);
        min_len
    }
}

impl AsRawFd for VsockInnerStream {
    fn as_raw_fd(&self) -> RawFd {
        self.stream_event.as_raw_fd()
    }
}

impl Read for VsockInnerStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut total_read_len = 0;
        // if read_buf is not empty, get data from read_buf first
        if let Some((read_buf, buf_read_len)) = self.read_buf.as_mut() {
            let read_len = Self::read_msg_from_vec(buf, read_buf, total_read_len, *buf_read_len);
            total_read_len += read_len;
            *buf_read_len += read_len;

            // if read_buf is all read, consume one event
            if *buf_read_len == read_buf.len() {
                self.consume_event()?;
                self.read_buf.take();
            }
        }

        // if buf is full, just return
        if total_read_len == buf.len() {
            return Ok(total_read_len);
        }

        // continously fetch data from channel to fill the buf, until the buf is
        // full
        loop {
            // fetch data from channel
            match self.reader.try_recv() {
                Ok(msg) => {
                    if self.recv_msg_from_channel(buf, msg, &mut total_read_len)? {
                        return Ok(total_read_len);
                    }
                }
                // this arm indicates there's no more data can fetch from
                // channel
                Err(TryRecvError::Empty) => {
                    if total_read_len > 0 {
                        return Ok(total_read_len);
                    } else {
                        // - non-blocking mode: return `WouldBlock` directly
                        // - blocking mode: use channel's `recv`/`recv_timeout`
                        //   function to block until channel have new data again
                        if self.stream_nonblocking.load(Ordering::SeqCst) {
                            return Err(Error::from(ErrorKind::WouldBlock));
                        } else {
                            // - no read timeout: use channel's `recv` function
                            //   to block until a message comes
                            // - have read timeout: use channel's `recv_timeout`
                            //   to block until a message comes or reach the
                            //   timeout time
                            if let Some(dur) = self.read_timeout {
                                match self.reader.recv_timeout(dur) {
                                    Ok(msg) => {
                                        if self.recv_msg_from_channel(
                                            buf,
                                            msg,
                                            &mut total_read_len,
                                        )? {
                                            return Ok(total_read_len);
                                        }
                                    }
                                    Err(RecvTimeoutError::Timeout) => {
                                        return Err(Error::from(ErrorKind::TimedOut))
                                    }
                                    Err(RecvTimeoutError::Disconnected) => {
                                        return Err(Error::from(ErrorKind::ConnectionReset))
                                    }
                                }
                            } else {
                                match self.reader.recv() {
                                    Ok(msg) => {
                                        if self.recv_msg_from_channel(
                                            buf,
                                            msg,
                                            &mut total_read_len,
                                        )? {
                                            return Ok(total_read_len);
                                        }
                                    }
                                    Err(_) => return Err(Error::from(ErrorKind::ConnectionReset)),
                                }
                            }
                        }
                    }
                }
                Err(TryRecvError::Disconnected) => {
                    return Err(Error::from(ErrorKind::ConnectionReset));
                }
            }
        }
    }
}

impl Write for VsockInnerStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        // We need to carefully distinguish between the timing of the trigger
        // eventfd and the writing of data to the channel, because the streams
        // on both ends may be working in different threads, and these two
        // operations are not atomic!
        let peer_nonblocking = self.peer_nonblocking.load(Ordering::SeqCst);

        // In blocking mode, the other end will simulate blocking io by blocking
        // on the recv() method of the channel, at which point, if data is
        // written to the channel, the other end will immediately return and
        // perform the operation of fetching data, during this, one important
        // things is to confirm that all the data sent has been read in this
        // time, which is done by reading eventfd.
        //
        // However, if the other side executes faster and we haven't finished
        // the trigger eventfd by the time it reads the eventfd, then it will
        // return a failure. Therefore, in blocking mode, the eventfd should be
        // triggered before writing data to the channel.
        if !peer_nonblocking {
            self.trigger_peer_event()?;
        }

        if let Err(_e) = self.writer.send(buf.to_vec()) {
            return Err(Error::from(ErrorKind::ConnectionReset));
        }

        // On the contrary, in nonblocking mode, the peer does not block in the
        // recv() method of the channel, but generally adds eventfd to the epoll
        // event loop, at this point, if we trigger eventfd, the peer will
        // return immediately and perform the fetch operation, but if we do not
        // send the data to the channel, then the fetching may fail. Therefore,
        // in nonblocking mode, we need to trigger eventfd after writing data
        // to the channel.
        if peer_nonblocking {
            self.trigger_peer_event()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Drop for VsockInnerStream {
    fn drop(&mut self) {
        // we need to notify peer stream when dropping, peer stream will sense
        // that this side of read channel has been disconnected and return an
        // error for the upper layer to drop it
        if let Err(e) = self.trigger_peer_event() {
            error!(
                "VsockInnerStream {:?}: can't notify peer inner stream that should be drop: {}",
                self.role, e
            );
        }
    }
}

impl VsockStream for VsockInnerStream {
    fn backend_type(&self) -> VsockBackendType {
        VsockBackendType::Inner
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<()> {
        self.stream_nonblocking.store(nonblocking, Ordering::SeqCst);
        Ok(())
    }

    fn set_read_timeout(&mut self, dur: Option<Duration>) -> Result<()> {
        self.read_timeout = dur;
        Ok(())
    }

    fn set_write_timeout(&mut self, _dur: Option<Duration>) -> Result<()> {
        // here's a infinite channel for write, no need to consider about write
        // timeout.
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Vsock inner connector is used to connect to vsock inner backend.
#[derive(Clone)]
pub struct VsockInnerConnector {
    backend_event: Arc<EventFd>,
    conn_sender: Sender<VsockInnerStream>,
}

impl std::fmt::Debug for VsockInnerConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VsockInnerConnector")
    }
}

impl VsockInnerConnector {
    /// Connect to vsock inner backend and get a new inner stream.
    pub fn connect(&self) -> Result<Box<dyn VsockStream>> {
        self.connect_()
            .map(|stream| Box::new(stream) as Box<dyn VsockStream>)
    }

    fn connect_(&self) -> Result<VsockInnerStream> {
        let (internal_sender, external_receiver) = channel();
        let (external_sender, internal_receiver) = channel();
        // use `EFD_SEMAPHORE` mode to make EventFd as a write counter for
        // channel.
        let internal_event = Arc::new(EventFd::new(EFD_NONBLOCK | EFD_SEMAPHORE)?);
        let external_event = Arc::new(EventFd::new(EFD_NONBLOCK | EFD_SEMAPHORE)?);
        let internal_nonblocking = Arc::new(AtomicBool::new(false));
        let external_nonblocking = Arc::new(AtomicBool::new(false));

        let mut internal_stream = VsockInnerStream::new(
            internal_event.clone(),
            external_event.clone(),
            internal_sender,
            internal_receiver,
            internal_nonblocking.clone(),
            external_nonblocking.clone(),
            InnerStreamRole::Internal,
        );
        // internal stream is vsock internal used, we need non-blocking mode
        internal_stream.set_nonblocking(true)?;

        // external stream is used for others, the mode can be set by them.
        let external_stream = VsockInnerStream::new(
            external_event,
            internal_event,
            external_sender,
            external_receiver,
            external_nonblocking,
            internal_nonblocking,
            InnerStreamRole::External,
        );

        // send the inner stream to connection pending list for later accept.
        self.conn_sender.send(internal_stream).map_err(|e| {
            Error::new(
                ErrorKind::ConnectionRefused,
                format!("vsock inner stream sender err: {}", e),
            )
        })?;
        self.backend_event.write(1)?;

        Ok(external_stream)
    }
}

/// The backend implemenation that can be used in-process, no need to forward
/// data by the OS.
pub struct VsockInnerBackend {
    /// The eventfd used for notify the connection requests.
    backend_event: Arc<EventFd>,
    /// The pending connections waiting to be accepted.
    pending_conns: Receiver<VsockInnerStream>,
    /// A sender can Send pending connections to inner backend.
    conn_sender: Sender<VsockInnerStream>,
}

impl VsockInnerBackend {
    pub fn new() -> Result<Self> {
        let (conn_sender, pending_conns) = channel();
        // use `EFD_SEMAPHORE` mode to make EventFd as a write counter for
        // pending_conns channel.
        let backend_event = Arc::new(EventFd::new(EFD_NONBLOCK | EFD_SEMAPHORE)?);

        Ok(VsockInnerBackend {
            backend_event,
            pending_conns,
            conn_sender,
        })
    }

    /// Create a inner connector instance.
    pub fn get_connector(&self) -> VsockInnerConnector {
        VsockInnerConnector {
            backend_event: self.backend_event.clone(),
            conn_sender: self.conn_sender.clone(),
        }
    }

    fn accept_(&self) -> Result<VsockInnerStream> {
        self.backend_event.read()?;
        match self.pending_conns.try_recv() {
            Ok(stream) => Ok(stream),
            Err(_) => Err(Error::from(ErrorKind::ConnectionAborted)),
        }
    }
}

impl AsRawFd for VsockInnerBackend {
    /// Don't read/write this fd, just use it to get signal.
    fn as_raw_fd(&self) -> RawFd {
        self.backend_event.as_raw_fd()
    }
}

impl VsockBackend for VsockInnerBackend {
    fn accept(&mut self) -> Result<Box<dyn VsockStream>> {
        self.accept_()
            .map(|stream| Box::new(stream) as Box<dyn VsockStream>)
    }

    fn connect(&self, _dst_port: u32) -> Result<Box<dyn VsockStream>> {
        Err(Error::new(
            ErrorKind::ConnectionRefused,
            "vsock inner backend doesn't support incoming connection request",
        ))
    }

    fn r#type(&self) -> VsockBackendType {
        VsockBackendType::Inner
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
