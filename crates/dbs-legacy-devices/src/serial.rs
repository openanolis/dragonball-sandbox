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
