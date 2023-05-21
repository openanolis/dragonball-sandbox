// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

/// An interface for generating serialzer and deserializers based on
/// field descriptions.
pub trait Descriptor {
    /// Returns the serializer code block as a token stream.
    fn generate_serializer(&self) -> proc_macro2::TokenStream;
    /// Returns the deserializer code block as a token stream.
    fn generate_deserializer(&self) -> proc_macro2::TokenStream;
}

/// Describes a structure and it's fields.
pub(crate) struct GenericDescriptor<T> {
    // The structure type identifier.
    pub ty: syn::Ident,
    pub versions: BTreeMap<u64, Vec<u64>>,
    pub fields: Vec<T>,
}

// A trait that defines an interface to check if a certain field
// exists at a specified version.
pub(crate) trait Exists {
    fn exists_at(&self, minor: u64, patch: u64) -> bool {
        let start = self.start_version();
        let end = self.end_version();

        let default_start = || -> bool {
            if start.is_empty() {
                return true;
            } else if start.iter().all(|x| minor < x.minor) {
                return false;
            } else if start.iter().all(|x| minor > x.minor) {
                return true;
            }
            false
        };
        let default_end = || -> bool {
            if end.is_empty() {
                return true;
            } else if end.iter().all(|x| minor > x.minor) {
                return false;
            } else if end.iter().all(|x| minor < x.minor) {
                return true;
            }
            false
        };

        start
            .iter()
            .find(|list| list.minor == minor)
            .map_or_else(default_start, |found| patch >= found.patch)
            && end
                .iter()
                .find(|list| list.minor == minor)
                .map_or_else(default_end, |found| patch < found.patch)
    }

    fn list_versions(&self) -> Vec<semver::Version> {
        let mut rets = self.start_version().to_owned();
        rets.append(&mut self.end_version().to_owned());
        rets.sort();
        rets.dedup();
        rets
    }

    fn start_version(&self) -> &[semver::Version];
    fn end_version(&self) -> &[semver::Version];
}

// A trait that defines an interface for exposing a field type.
pub(crate) trait FieldType {
    fn ty(&self) -> syn::Type;
}
