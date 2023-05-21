// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]

//! Defines a generic interface for version tolerant serialization and
//! implements it for primitive data types using `bincode` as backend.
//!
//! The interface has two components:
//! - `Versionize` trait
//! - `VersionMap` helper
//!
//! `VersionMap` maps individual crate name to the crate Semver Version.
//! This mapping is required both when serializing or deserializing structures
//! as it needs to record the crate version and crate name for serializing,
//! and to know which crate version to be used for deserializing.
//!
//! `Versionize` trait is implemented for the following primitives:
//! u8, u16, u32, u64, usize, i8, i16, i32, i64, isize, char, f32, f64,
//! String, Vec<T>, Arrays up to 32 elements, Box<T>, Wrapping<T>, Option<T>,
//! FamStructWrapper<T>, and (T, U).
//!
//! Known issues and limitations:
//! - Union serialization is not supported via the `Versionize` proc macro.
//! - Implementing `Versionize` for non-repr(C) unions can result in undefined
//! behaviour and MUST be avoided.
//! - Versionize trait implementations for repr(C) unions must be backed by
//! extensive testing.
//! - Semantic serialization and deserialization is available only for
//! structures.

pub mod crc;
pub mod primitives;
pub mod version_map;

pub use semver;
pub use version_map::VersionMap;

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
    /// Semantic translation/validation error.
    Semantic(String),
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
    /// Not found version
    NotFound(String),
    /// Version parse error.
    ParseVersion(String, String),
}

impl std::fmt::Display for VersionizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        use VersionizeError::*;

        match self {
            Io(e) => write!(f, "An IO error occured: {}", e),
            Serialize(e) => write!(f, "A serialization error occured: {}", e),
            Deserialize(e) => write!(f, "A deserialization error occured: {}", e),
            Semantic(e) => write!(f, "A user generated semantic error occured: {}", e),
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
            NotFound(v) => write!(f, "Not found {}.", v),
            ParseVersion(ver, err) => write!(f, "Parse version {} failed. {}", ver, err),
        }
    }
}

/// Versioned serialization/deserialization result.
pub type VersionizeResult<T> = std::result::Result<T, VersionizeError>;

/// Trait that provides an interface for version aware serialization and
/// deserialization.
/// The [Versionize proc macro][1] can generate an implementation for a given
/// type if generics are not used, otherwise a manual implementation is
/// required.
///
/// Example implementation
/// ```
/// use dbs_versionize::{VersionMap, Versionize, VersionizeResult};
/// use versionize_derive::Versionize;
///
/// #[derive(Clone)]
/// struct MyType<T>(T);
///
/// impl<T> Versionize for MyType<T>
/// where
///     T: Versionize,
/// {
///     #[inline]
///     fn serialize<W: std::io::Write>(
///         &self,
///         writer: W,
///         version_map: &mut VersionMap,
///     ) -> VersionizeResult<()> {
///         self.0.serialize(writer, version_map)
///     }
///
///     #[inline]
///     fn deserialize<R: std::io::Read>(
///         reader: R,
///         version_map: &VersionMap,
///     ) -> VersionizeResult<Self> {
///         Ok(MyType(T::deserialize(reader, version_map)?))
///     }
/// }
/// ```
/// [1]: https://docs.rs/versionize_derive/latest/versionize_derive/derive.Versionize.html
pub trait Versionize: Clone {
    /// Serializes `self` using the specficifed `writer` and
    /// `version_map`.
    fn serialize<W: Write>(&self, writer: W, version_map: &mut VersionMap) -> VersionizeResult<()>;

    /// Returns a new instance of `Self` by deserializing using the specficifed `reader`
    /// and `version_map`.
    fn deserialize<R: Read>(reader: R, version_map: &VersionMap) -> VersionizeResult<Self>
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_error_debug_display() {
        // Validates Debug and Display are implemented.
        use crate::VersionizeError::*;
        let str = String::from("test");
        format!("{:?}{}", Io(0), Io(0));
        format!("{:?}{}", Serialize(str.clone()), Serialize(str.clone()));
        format!("{:?}{}", Deserialize(str.clone()), Deserialize(str.clone()));
        format!("{:?}{}", Semantic(str.clone()), Semantic(str));
    }
}
