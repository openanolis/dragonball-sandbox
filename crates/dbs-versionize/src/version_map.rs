// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A helper to map struct and enum versions to a sequence of root versions.
//! This helper is required to support the versioning of a hierarchy of
//! structures composed of individually versioned structures or enums.
//!
//! ```rust
//! extern crate versionize;
//! extern crate versionize_derive;
//!
//! use versionize::{VersionMap, Versionize, VersionizeResult};
//! use versionize_derive::Versionize;
//!
//! #[derive(Versionize)]
//! pub struct Struct1 {
//!     a: u32,
//!     #[version(start = 2)]
//!     b: u8,
//! }
//!
//! #[derive(Versionize)]
//! pub struct Struct2 {
//!     x: u32,
//!     #[version(start = 2)]
//!     y: u8,
//! }
//!
//! #[derive(Versionize)]
//! pub struct State {
//!     struct1: Struct1,
//!     struct2: Struct2,
//! }
//!
//! let mut version_map = VersionMap::new(); //
//! version_map
//!     .new_version()
//!     .set_type_version(Struct1::type_id(), 2)
//!     .new_version()
//!     .set_type_version(Struct2::type_id(), 2);
//!
//! // Check that there are 3 root versions.
//! assert_eq!(version_map.latest_version(), 3);
//!
//! // Check that root version 1 has all structs at version 1.
//! assert_eq!(version_map.get_type_version(1, Struct1::type_id()), 1);
//! assert_eq!(version_map.get_type_version(1, Struct2::type_id()), 1);
//! assert_eq!(version_map.get_type_version(1, State::type_id()), 1);
//!
//! // Check that root version 2 has Struct1 at version 2 and Struct2
//! // at version 1.
//! assert_eq!(version_map.get_type_version(2, Struct1::type_id()), 2);
//! assert_eq!(version_map.get_type_version(2, Struct2::type_id()), 1);
//! assert_eq!(version_map.get_type_version(2, State::type_id()), 1);
//!
//! // Check that root version 3 has Struct1 and Struct2 at version 2.
//! assert_eq!(version_map.get_type_version(3, Struct1::type_id()), 2);
//! assert_eq!(version_map.get_type_version(3, Struct2::type_id()), 2);
//! assert_eq!(version_map.get_type_version(3, State::type_id()), 1);
//! ```

use std::any::TypeId;
use std::collections::hash_map::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

const BASE_VERSION: u16 = 1;

/// Trait to check whether is specific `version` is supported by a `VersionMap`.
pub trait VersionFilter: Debug {
    /// Check whether the `version` is supported or not.
    fn is_supported(&self, version: u16) -> bool;
}

impl VersionFilter for () {
    fn is_supported(&self, _version: u16) -> bool {
        true
    }
}
///
/// The VersionMap API provides functionality to define the version for each
/// type and attach them to specific root versions.
#[derive(Clone, Debug)]
pub struct VersionMap {
    versions: Vec<HashMap<TypeId, u16>>,
    filter: Arc<dyn VersionFilter + Send + Sync>,
}

impl Default for VersionMap {
    fn default() -> Self {
        VersionMap {
            versions: vec![HashMap::new(); 1],
            filter: Arc::new(()),
        }
    }
}

impl VersionMap {
    /// Create a new version map initialized at version 1.
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a new version map with specified version filter.
    pub fn with_filter(filter: Arc<dyn VersionFilter + Send + Sync>) -> Self {
        VersionMap {
            versions: vec![HashMap::new(); 1],
            filter,
        }
    }

    /// Bumps root version by 1 to create a new root version.
    pub fn new_version(&mut self) -> &mut Self {
        self.versions.push(HashMap::new());
        self
    }

    /// Define a mapping between a specific type version and the latest root version.
    pub fn set_type_version(&mut self, type_id: TypeId, type_version: u16) -> &mut Self {
        // It is safe to unwrap since `self.versions` always has at least 1 element.
        self.versions
            .last_mut()
            .unwrap()
            .insert(type_id, type_version);
        self
    }

    /// Returns the version of `type_id` corresponding to the specified `root_version`.
    /// If `root_version` is out of range returns the version of `type_id` at latest version.
    pub fn get_type_version(&self, root_version: u16, type_id: TypeId) -> u16 {
        let version_space = if root_version > self.latest_version() || root_version == 0 {
            self.versions.as_slice()
        } else {
            self.versions.split_at(root_version as usize).0
        };

        for i in (0..version_space.len()).rev() {
            if let Some(version) = version_space[i].get(&type_id) {
                return *version;
            }
        }

        BASE_VERSION
    }

    /// Returns the latest version.
    pub fn latest_version(&self) -> u16 {
        self.versions.len() as u16
    }

    /// Check whether the `version` is supported by the version map.
    pub fn is_supported(&self, version: u16) -> bool {
        if version == 0 || version > self.latest_version() {
            false
        } else {
            self.filter.is_supported(version)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TypeId, VersionMap, BASE_VERSION};
    use std::sync::Arc;
    use version_map::VersionFilter;

    pub struct MyType;
    pub struct MySecondType;
    pub struct MyThirdType;

    #[derive(Debug)]
    struct MyFilter;

    impl VersionFilter for MyFilter {
        fn is_supported(&self, version: u16) -> bool {
            version < 5
        }
    }

    #[test]
    fn test_default_version() {
        let vm = VersionMap::new();
        assert_eq!(vm.latest_version(), 1);
    }

    #[test]
    fn test_new_versions() {
        let mut vm = VersionMap::new();
        vm.new_version().new_version();
        assert_eq!(vm.latest_version(), 3);
    }

    #[test]
    fn test_1_app_version() {
        let mut vm = VersionMap::new();
        vm.set_type_version(TypeId::of::<MyType>(), 1);
        vm.set_type_version(TypeId::of::<MySecondType>(), 2);
        vm.set_type_version(TypeId::of::<MyThirdType>(), 3);

        assert_eq!(vm.get_type_version(1, TypeId::of::<MyType>()), 1);
        assert_eq!(vm.get_type_version(1, TypeId::of::<MySecondType>()), 2);
        assert_eq!(vm.get_type_version(1, TypeId::of::<MyThirdType>()), 3);
    }

    #[test]
    fn test_100_app_version_full() {
        let mut vm = VersionMap::new();

        for i in 1..=100 {
            vm.set_type_version(TypeId::of::<MyType>(), i)
                .set_type_version(TypeId::of::<MySecondType>(), i + 1)
                .set_type_version(TypeId::of::<MyThirdType>(), i + 2)
                .new_version();
        }

        for i in 1..=100 {
            assert_eq!(vm.get_type_version(i, TypeId::of::<MyType>()), i);
            assert_eq!(vm.get_type_version(i, TypeId::of::<MySecondType>()), i + 1);
            assert_eq!(vm.get_type_version(i, TypeId::of::<MyThirdType>()), i + 2);
        }
    }

    #[test]
    fn test_version_map_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<VersionMap>();
    }

    #[test]
    fn test_app_versions_with_gap() {
        let my_type_id = TypeId::of::<MyType>();
        let my_second_type_id = TypeId::of::<MySecondType>();
        let my_third_type_id = TypeId::of::<MyThirdType>();

        let mut vm = VersionMap::new();
        vm.set_type_version(my_type_id, 1);
        vm.set_type_version(my_second_type_id, 1);
        vm.set_type_version(my_third_type_id, 1);
        vm.new_version();
        vm.set_type_version(my_type_id, 2);
        vm.new_version();
        vm.set_type_version(my_third_type_id, 2);
        vm.new_version();
        vm.set_type_version(my_second_type_id, 2);

        assert_eq!(vm.get_type_version(1, my_type_id), 1);
        assert_eq!(vm.get_type_version(1, my_second_type_id), 1);
        assert_eq!(vm.get_type_version(1, my_third_type_id), 1);

        assert_eq!(vm.get_type_version(2, my_type_id), 2);
        assert_eq!(vm.get_type_version(2, my_second_type_id), 1);
        assert_eq!(vm.get_type_version(2, my_third_type_id), 1);

        assert_eq!(vm.get_type_version(3, my_type_id), 2);
        assert_eq!(vm.get_type_version(3, my_second_type_id), 1);
        assert_eq!(vm.get_type_version(3, my_third_type_id), 2);

        assert_eq!(vm.get_type_version(4, my_type_id), 2);
        assert_eq!(vm.get_type_version(4, my_second_type_id), 2);
        assert_eq!(vm.get_type_version(4, my_third_type_id), 2);
    }

    #[test]
    fn test_unset_type() {
        let vm = VersionMap::new();
        assert_eq!(vm.get_type_version(1, TypeId::of::<MyType>()), BASE_VERSION);
    }

    #[test]
    fn test_invalid_root_version() {
        let mut vm = VersionMap::new();
        vm.new_version().set_type_version(TypeId::of::<MyType>(), 2);

        assert_eq!(vm.get_type_version(0, TypeId::of::<MyType>()), 2);

        assert_eq!(vm.latest_version(), 2);
        assert_eq!(vm.get_type_version(129, TypeId::of::<MyType>()), 2);
        assert_eq!(vm.get_type_version(1, TypeId::of::<MyType>()), BASE_VERSION);
    }

    #[test]
    fn test_version_filter() {
        let mut vm = VersionMap::default();
        vm.new_version();

        assert!(!vm.is_supported(0));
        assert!(vm.is_supported(1));
        assert!(vm.is_supported(2));
        assert!(!vm.is_supported(3));

        let mut vm = VersionMap::with_filter(Arc::new(MyFilter));
        vm.new_version();
        vm.new_version();
        vm.new_version();
        vm.new_version();
        vm.new_version();

        let vm1 = vm.clone();
        assert!(!vm1.is_supported(0));
        assert!(vm1.is_supported(1));
        assert!(vm1.is_supported(2));
        assert!(vm1.is_supported(3));
        assert!(vm1.is_supported(4));
        assert!(!vm1.is_supported(5));
        assert!(!vm1.is_supported(6));
        assert_eq!(vm.latest_version(), 6);
    }
}
