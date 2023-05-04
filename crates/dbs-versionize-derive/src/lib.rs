// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]

//! Exports the `Versionize` derive proc macro that generates the Versionize
//! trait implementation.
//!
//! Versionize generates serialization and deserialization code only for
//! structures and enums.
//!
//! Supported primitives: u8, u16, u32, u64, usize, i8, i16, i32, i64, isize,
//! char, f32, f64, String, Vec<T>, Arrays up to 32 elements, Box<T>,
//! Wrapping<T>, Option<T>, FamStructWrapper<T>, and (T, U).
//!
//! Known issues and limitations:
//! - Union serialization is not supported via the `Versionize` proc macro.
//! - Implementing Versionize for non-repr(C) unions can result in undefined
//! behaviour and MUST be avoided.
//! - Versionize trait implementations for repr(C) unions must be backed by
//! extensive testing.
//! - Semantic serialization and deserialization is available only for structures.

extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate syn;

mod common;
mod descriptors;
mod fields;
mod helpers;

use common::Descriptor;
use descriptors::{enum_desc::EnumDescriptor, struct_desc::StructDescriptor};
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

pub(crate) const ATTRIBUTE_NAME: &str = "version";

/// Struct annotation constants.
pub(crate) const DEFAULT_FN: &str = "default_fn";
pub(crate) const SEMANTIC_SER_FN: &str = "ser_fn";
pub(crate) const SEMANTIC_DE_FN: &str = "de_fn";
pub(crate) const START_VERSION: &str = "start";
pub(crate) const END_VERSION: &str = "end";

/// Generates serialization and deserialization code as an implementation of
/// the `Versionize` trait.
///
/// Different code paths are generated for each version of the structure or
/// enum. There is no limit enforced on the maximum number of structure
/// versions.
///
/// ### Struct and enum requirements
/// - all members or enum variants need to implement the `Versionize` trait
/// - no generics are being used (this is currenly a limitation)
///
/// ## Annotations
///
/// To facilitate version tolerant serialization "history metadata" is attached
/// to the structure or enum. This is done by using the `version` attribute in
/// their definition. In the below example a new field is added to the
/// structure starting with version 2: `#[version(start = 2)]`.
///
/// ```ignore
/// extern crate versionize;
/// extern crate versionize_derive;
/// use versionize::{Versionize, VersionizeError, VersionizeResult};
/// use versionize_derive::Versionize;
///
/// #[derive(Versionize)]
/// struct Test {
///     a: u32,
///     #[version(start = 2)]
///     b: u8,
/// }
/// ```
///
/// Multiple version annotations can be defined for a field, like for example:
/// `#[version(start = 2, end = 3)]`. Field was added in structure version 2
/// and removed in version 3. The generated code will attempt to (de)serialize
/// this field only for version 2 of the structure.
///
/// ### Supported field attributes and usage
///
/// The `version` attribute accepts multiple key/value pairs to be specified in
/// order to support versioning, semantic serialization and default values for
/// fields. All of these are optional and a default behaviour is provided in
/// their absence.
///
/// #### default_fn
///
/// Provides an initialization value for a field when deserializing from an
/// older structure version which does not contain this field. If not specified
/// the `Default` trait isused to initialize the field.
///
/// ```ignore
/// extern crate versionize;
/// extern crate versionize_derive;
/// use versionize::{Versionize, VersionizeError, VersionizeResult};
/// use versionize_derive::Versionize;
///
/// #[derive(Versionize)]
/// struct TestStruct {
///     a: u32,
///     #[version(start = 2, default_fn = "default_b")]
///     b: u8,
/// }
///
/// impl TestStruct {
///     fn default_b(_source_version: u16) -> u8 {
///         12u8
///     }
/// }
/// ```
///
/// The function name needs to be specified as a string and its prototype must
/// take an u16 source version parameter and return a value of the same type as
/// as the field.
///
/// #### start/end
///
/// Defines the field version lifetime. Fields can be added by specifing the
/// start version of the structure when first defining them and can be later
/// on removed from serialization logic by adding and end version.
///
/// For example: `#[version(start = 2, end = 4)]`. The field would be present
/// in the structure v2 and v3, but starting with v4 it would no longer be
/// serialized or deserialized.
///
/// Once a field is removed, it can never be added again in a future version.
///
/// #### ser_fn
/// * Not supported for enums. *
///
/// Defines a semantic serialization function for a field. The function needs
/// to be specified as a string and implemented as a method attached to
/// the structure. The prototype of the function is
/// `fn(&mut self, u16) -> VersionizeResult<()>`.
///
/// If defined, the method is called when the field is skipped from
/// serialization because it does not exist in the target version of the
/// structure. Its implementation can perform any mutation of `self` or return
/// an error to stop serialization. Intended usage is to implement semantic
/// translation or semantic validations.
///
/// ```ignore
/// extern crate versionize;
/// extern crate versionize_derive;
/// use versionize::{Versionize, VersionizeError, VersionizeResult};
/// use versionize_derive::Versionize;
///
/// #[derive(Versionize)]
/// struct SomeStruct {
///     some_u32: u32,
///     #[version(start = 2, ser_fn = "ser_u16")]
///     some_u16: u16,
/// }
///
/// impl SomeStruct {
///     fn ser_u16(&mut self, target_version: u16) -> VersionizeResult<()> {
///         self.some_u32 = self.some_u32 & self.some_u16 as u32;
///         Ok(())
///     }
/// }
/// ```
///
/// #### de_fn
/// * Not supported for enums. *
///
/// Defines a semantic deserialization function for a field. The function needs
/// to be specified as a string and implemented as a method attached to
/// the structure. The prototype of the function is
/// `fn(&mut self, u16) -> VersionizeResult<()>`.
///
/// If defined, the method is called if the field is skipped from
/// deserialization because it does not exist in the source version of the
/// serialized structure. Its implementation can perform any mutation of `self`
/// or return an error to stop deserialization. Intended usage is to implement
/// semantic translation or semantic validations.
///
/// Both `default_fn` and `de_fn` can be specified for a field. `default_fn` is
/// always called first and `de_fn` last.
///
/// ```ignore
/// extern crate versionize;
/// extern crate versionize_derive;
/// use versionize::{Versionize, VersionizeError, VersionizeResult};
/// use versionize_derive::Versionize;
///
/// #[derive(Clone, Versionize)]
/// struct SomeStruct {
///     some_u32: u32,
///     #[version(start = 2, ser_fn = "ser_u16", de_fn = "de_u16")]
///     some_u16: u16,
/// }
///
/// impl SomeStruct {
///     fn ser_u16(&mut self, target_version: u16) -> VersionizeResult<()> {
///         self.some_u32 = self.some_u32 & self.some_u16 as u32;
///         Ok(())
///     }
///     fn de_u16(&mut self, source_version: u16) -> VersionizeResult<()> {
///         if source_version < 2 {
///             self.some_u16 = (self.some_u32 & 0xFF) as u16;
///         }
///         Ok(())
///     }
/// }
/// ```
#[proc_macro_derive(Versionize, attributes(version))]
pub fn impl_versionize(input: TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = input.ident.clone();
    let generics = input.generics.clone();

    let descriptor: Box<dyn Descriptor> = match &input.data {
        syn::Data::Struct(data_struct) => {
            Box::new(StructDescriptor::new(data_struct, ident.clone()))
        }
        syn::Data::Enum(data_enum) => Box::new(EnumDescriptor::new(data_enum, ident.clone())),
        syn::Data::Union(_) => {
            return (quote! {
                compile_error!("Union serialization is not supported.");
            })
            .into()
        }
    };

    let version = descriptor.version();
    let versioned_serializer = descriptor.generate_serializer();
    let deserializer = descriptor.generate_deserializer();
    let serializer = quote! {
        // Get the struct version for the input app_version.
        let version = version_map.get_type_version(app_version, <Self as Versionize>::type_id());
        // We will use this copy to perform semantic serialization.
        let mut copy_of_self = self.clone();
        match version {
            #versioned_serializer
            _ => panic!("Unknown {:?} version {}.", &<Self as Versionize>::type_id(), version)
        }
    };
    (quote! {
        impl Versionize for #ident #generics {
            fn serialize<W: std::io::Write>(&self, writer: &mut W, version_map: &VersionMap, app_version: u16) -> VersionizeResult<()> {
                #serializer
                Ok(())
            }

            fn deserialize<R: std::io::Read>(mut reader: &mut R, version_map: &VersionMap, app_version: u16) -> VersionizeResult<Self> {
                #deserializer
            }

            // Returns struct current version.
            fn version() -> u16 {
                #version
            }
        }
    }).into()
}
