// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use dbs_versionize::{Version, Versionize, VersionizeError, VersionizeResult};

#[derive(Clone, Debug, PartialEq, Versionize, Eq)]
pub enum TestState {
    Zero,
    One(u32),
    #[version(start = "0.2.0", end = "0.9.0", default_fn = "default_state_two")]
    Two(u64),
}

impl TestState {
    fn default_state_two(&self, srouce_version: &Version) -> VersionizeResult<TestState> {
        match srouce_version.minor {
            1 => Ok(TestState::One(2)),
            i => Err(VersionizeError::Serialize(format!(
                "Unknown target version: {}",
                i
            ))),
        }
    }
}
