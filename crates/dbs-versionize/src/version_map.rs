// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A helper to record the crate version and crate name where the struct and enum are located.

use std::collections::HashMap;

use crate::{VersionizeError, VersionizeResult};

pub const MAX_VERSION_NUM: u64 = u16::MAX as u64;

/// The VersionMap API provides functionality to the crate version for each
/// type and attach them to specific crate name.
#[derive(Clone, Debug)]
pub struct VersionMap {
    crates: HashMap<String, semver::Version>,
}

impl Default for VersionMap {
    fn default() -> Self {
        VersionMap {
            crates: HashMap::new(),
        }
    }
}

impl VersionMap {
    /// Create a new version map.
    pub fn new() -> Self {
        Default::default()
    }

    /// Insert a mapping between a specific crate name and the crate version.
    /// If the given crate name already exists, and is different from the given version, an error will
    /// be returned.
    pub fn set_crate_version(&mut self, name: &str, ver: semver::Version) -> VersionizeResult<()> {
        if let Some(exist) = self.crates.get(name) {
            if *exist != ver {
                return Err(VersionizeError::MultipleVersion(
                    name.to_string(),
                    exist.to_string(),
                    ver.to_string(),
                ));
            }
        } else {
            self.crates.insert(name.to_owned(), ver);
        }

        Ok(())
    }

    /// Returns the version of the crate corresponding to the specified crate name.
    pub fn get_crate_version(&self, name: &str) -> VersionizeResult<semver::Version> {
        Ok(self
            .crates
            .get(name)
            .ok_or(VersionizeError::NotFound(name.to_owned()))?
            .clone())
    }
}

