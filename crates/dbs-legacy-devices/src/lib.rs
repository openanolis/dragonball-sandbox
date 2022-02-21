// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Emulates virtual and hardware devices.
pub mod serial;
pub use self::serial::{SerialDevice, SerialWrapper};

use vm_superio::Trigger;
use vmm_sys_util::eventfd::EventFd;
/// Newtype for implementing the trigger functionality for `EventFd`.
///
/// The trigger is used for handling events in the legacy devices.
pub struct EventFdTrigger(EventFd);

impl Trigger for EventFdTrigger {
    type E = std::io::Error;

    fn trigger(&self) -> std::io::Result<()> {
        self.write(1)
    }
}
impl std::ops::Deref for EventFdTrigger {
    type Target = EventFd;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl EventFdTrigger {
    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(EventFdTrigger((**self).try_clone()?))
    }
    pub fn new(evt: EventFd) -> Self {
        Self(evt)
    }

    pub fn get_event(&self) -> EventFd {
        self.0.try_clone().unwrap()
    }
}
