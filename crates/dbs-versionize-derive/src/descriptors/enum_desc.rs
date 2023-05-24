// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::common::{Descriptor, GenericDescriptor};
use crate::fields::enum_variant::*;
use crate::helpers::collect_version;
use quote::quote;
use std::collections::BTreeMap;

pub(crate) type EnumDescriptor = GenericDescriptor<EnumVariant>;

impl Descriptor for EnumDescriptor {
    fn generate_serializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_serializers = proc_macro2::TokenStream::new();

        for field in &self.fields {
            versioned_serializers.extend(field.generate_serializer(u64::MAX, u64::MAX));
        }

        // Generate the serializer for current version only.
        quote! {
            match self {
                #versioned_serializers
            }
        }
    }

    // Versioned/semantic deserialization is not implemented for enums.
    fn generate_deserializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_deserializers = proc_macro2::TokenStream::new();

        for field in &self.fields {
            versioned_deserializers.extend(field.generate_deserializer(u64::MAX, u64::MAX));
        }

        quote! {
            let source = version_map.get_crate_version(env!("CARGO_PKG_NAME"))?;
            let variant_index = <u32 as dbs_versionize::Versionize>::deserialize(&mut reader, version_map)?;
            match variant_index {
                #versioned_deserializers
                x => return Err(dbs_versionize::VersionizeError::Deserialize(format!("Unknown variant_index {}", x)))
            }
        }
    }
}

impl EnumDescriptor {
    pub fn new(input: &syn::DataEnum, ident: syn::Ident) -> Self {
        let mut descriptor = EnumDescriptor {
            ty: ident,
            versions: BTreeMap::new(),
            fields: vec![],
        };

        descriptor.parse_enum_variants(&input.variants);
        descriptor.versions = collect_version(&descriptor.fields);
        descriptor
    }

    fn parse_enum_variants(
        &mut self,
        variants: &syn::punctuated::Punctuated<syn::Variant, syn::token::Comma>,
    ) {
        for (index, variant) in variants.iter().enumerate() {
            self.fields.push(EnumVariant::new(variant, index as u32));
        }
    }
}
