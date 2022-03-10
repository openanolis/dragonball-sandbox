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

mod dragonball;
pub use self::dragonball::*;
