// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//#![deny(missing_docs)]

pub mod crc;

pub mod version_map;
pub use version_map::VersionMap;

pub mod primitives;
//pub mod derive;
pub use semver;

use std::io::{Read, Write};

/// Versioned serialization/deserialization error definitions.
#[derive(Debug, PartialEq)]
pub enum VersionizeError {
    /// An IO error occured.
    Io(i32),
    /// Generic serialization error.
    Serialize(String),
    /// Generic deserialization error.
    Deserialize(String),
    /// String length exceeded.
    StringLength(usize),
    /// Vector length exceeded.
    VecLength(usize),
    /// HashMap length exceeded.
    HashMapLength(usize),
    /// HashSet length exceeded.
    HashSetLength(usize),
    /// Unsupported version.
    UnsuportVersion(String),
    /// Multiple version
    MultipleVersion(String, String, String),
}

impl std::fmt::Display for VersionizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        use VersionizeError::*;

        match self {
            Io(e) => write!(f, "An IO error occured: {}", e),
            Serialize(e) => write!(f, "A serialization error occured: {}", e),
            Deserialize(e) => write!(f, "A deserialization error occured: {}", e),
            StringLength(bad_len) => write!(
                f,
                "String length exceeded {} > {} bytes",
                bad_len,
                primitives::MAX_STRING_LEN
            ),
            VecLength(bad_len) => write!(
                f,
                "Vec of length {} exceeded maximum size of {} bytes",
                bad_len,
                primitives::MAX_VEC_SIZE
            ),
            HashMapLength(bad_len) => write!(
                f,
                "HashMap of length exceeded {} > {} bytes",
                bad_len,
                primitives::MAX_HASH_MAP_LEN
            ),
            HashSetLength(bad_len) => write!(
                f,
                "HashSet of length exceeded {} > {} bytes",
                bad_len,
                primitives::MAX_HASH_SET_LEN
            ),
            UnsuportVersion(ver) => write!(f, "{} version is NOT supported.", ver),
            MultipleVersion(rcrate, a, b) => write!(
                f,
                "There are multiple version {}, {} in {} crate.",
                a, b, rcrate,
            ),
        }
    }
}

/// Versioned serialization/deserialization result.
pub type VersionizeResult<T> = std::result::Result<T, VersionizeError>;

pub trait Versionize {
    fn serialize<W: Write>(&self, writer: W, version_map: &mut VersionMap) -> VersionizeResult<()>;

    fn deserialize<R: Read>(reader: R, version_map: &VersionMap) -> VersionizeResult<Self>
    where
        Self: Sized;
}
