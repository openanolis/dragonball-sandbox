// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use std::io::Write;

use dbs_device::{DeviceIoMut, IoAddress, PioAddress};
use log::error;
use vm_superio::{serial::SerialEvents, Serial, Trigger};

use crate::EventFdTrigger;

pub struct SerialEventsWrapper {
    pub buffer_ready_event_fd: Option<EventFdTrigger>,
}

impl SerialEvents for SerialEventsWrapper {
    fn buffer_read(&self) {}

    fn out_byte(&self) {}

    fn tx_lost_byte(&self) {}

    fn in_buffer_empty(&self) {
        match self
            .buffer_ready_event_fd
            .as_ref()
            .map_or(Ok(()), |buf_ready| buf_ready.write(1))
        {
            Ok(_) => (),
            Err(err) => error!(
                "Could not signal that serial device buffer is ready: {:?}",
                err
            ),
        }
    }
}

pub type SerialDevice = SerialWrapper<EventFdTrigger, SerialEventsWrapper, Box<dyn Write + Send>>;

pub struct SerialWrapper<T: Trigger, EV: SerialEvents, W: Write> {
    pub serial: Serial<T, EV, W>,
}

impl<W: Write + Send + 'static> DeviceIoMut
    for SerialWrapper<EventFdTrigger, SerialEventsWrapper, W>
{
    fn pio_read(&mut self, _base: PioAddress, offset: PioAddress, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }
        data[0] = self.serial.read(offset.raw_value() as u8);
    }
    fn pio_write(&mut self, _base: PioAddress, offset: PioAddress, data: &[u8]) {
        if data.len() != 1 {
            return;
        }
        if let Err(e) = self.serial.write(offset.raw_value() as u8, data[0]) {
            error!("Failed the pio write to serial: {:?}", e);
        }
    }

    fn read(&mut self, _base: IoAddress, offset: IoAddress, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }
        data[0] = self.serial.read(offset.raw_value() as u8);
    }
    fn write(&mut self, _base: IoAddress, offset: IoAddress, data: &[u8]) {
        if data.len() != 1 {
            return;
        }
        if let Err(e) = self.serial.write(offset.raw_value() as u8, data[0]) {
            error!("Failed the write to serial: {:?}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};
    use vmm_sys_util::eventfd::EventFd;

    #[derive(Clone)]
    struct SharedBuffer {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedBuffer {
        fn new() -> SharedBuffer {
            SharedBuffer {
                buf: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buf.lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.buf.lock().unwrap().flush()
        }
    }

    #[test]
    fn test_serial_bus_write() {
        let serial_out = SharedBuffer::new();
        let intr_evt = EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        let mut serial = SerialDevice {
            serial: Serial::with_events(
                intr_evt,
                SerialEventsWrapper {
                    buffer_ready_event_fd: None,
                },
                Box::new(serial_out.clone()),
            ),
        };
        <dyn DeviceIoMut>::pio_write(&mut serial, PioAddress(0), PioAddress(0), &[b'x', b'y']);

        assert_eq!(serial_out.buf.lock().unwrap().as_slice().len(), 0);
        <dyn DeviceIoMut>::write(&mut serial, IoAddress(0), IoAddress(0), &[b'x', b'y']);

        assert_eq!(serial_out.buf.lock().unwrap().as_slice().len(), 0);

        <dyn DeviceIoMut>::pio_write(&mut serial, PioAddress(0), PioAddress(0), &[b'a']);
        <dyn DeviceIoMut>::pio_write(&mut serial, PioAddress(0), PioAddress(0), &[b'b']);
        <dyn DeviceIoMut>::write(&mut serial, IoAddress(0), IoAddress(0), &[b'c']);
        assert_eq!(
            serial_out.buf.lock().unwrap().as_slice(),
            &[b'a', b'b', b'c']
        );
    }

    #[test]
    fn test_serial_bus_read() {
        let intr_evt = EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        let mut serial = SerialDevice {
            serial: Serial::with_events(
                intr_evt,
                SerialEventsWrapper {
                    buffer_ready_event_fd: None,
                },
                Box::new(std::io::sink()),
            ),
        };
        serial
            .serial
            .enqueue_raw_bytes(&[b'a', b'b', b'c'])
            .unwrap();

        let mut v = [0x00; 2];
        <dyn DeviceIoMut>::pio_read(&mut serial, PioAddress(0), PioAddress(0), &mut v);
        assert_eq!(v[0], b'\0');
        <dyn DeviceIoMut>::read(&mut serial, IoAddress(0), IoAddress(0), &mut v);
        assert_eq!(v[0], b'\0');

        let mut v = [0x00; 1];
        <dyn DeviceIoMut>::pio_read(&mut serial, PioAddress(0), PioAddress(0), &mut v);
        assert_eq!(v[0], b'a');

        <dyn DeviceIoMut>::pio_read(&mut serial, PioAddress(0), PioAddress(0), &mut v);
        assert_eq!(v[0], b'b');

        <dyn DeviceIoMut>::read(&mut serial, IoAddress(0), IoAddress(0), &mut v);
        assert_eq!(v[0], b'c');
    }
}
