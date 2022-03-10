// Copyright (C) 2019 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Implementations of the Virtio MMIO Transport Layer.
//!
//! The Virtio specifications have defined two versions for the Virtio MMIO transport layer. The
//! version 1 is called legacy mode, and the version 2 is preferred currently. The common parts
//! of both versions are defined here.

mod mmio_state;
pub use self::mmio_state::*;

mod dragonball;
pub use self::dragonball::*;

/// Offset from the base MMIO address of a virtio device used by the guest to notify the device of
/// queue events.
pub const MMIO_NOTIFY_REG_OFFSET: u32 = 0x50;
