// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::common::{Descriptor, GenericDescriptor};
use crate::fields::struct_field::*;
use crate::helpers::collect_version;
use quote::{format_ident, quote};
use std::collections::BTreeMap;

pub(crate) type StructDescriptor = GenericDescriptor<StructField>;

impl Descriptor for StructDescriptor {
    fn generate_serializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_serializer = proc_macro2::TokenStream::new();
        let mut semantic_serializer = proc_macro2::TokenStream::new();

        // Generate field and semantic serializers for all fields.
        // Not all fields have semantic serializers defined and some fields
        // might be missing in version. In these cases the generate_serializer() and
        // generate_semantic_serializer() will return an empty token stream.
        for field in &self.fields {
            versioned_serializer.extend(field.generate_serializer(u64::MAX, u64::MAX));
            semantic_serializer.extend(field.generate_semantic_serializer(u64::MAX, u64::MAX));
        }

        quote! {
            #semantic_serializer
            #versioned_serializer
        }
    }

    fn generate_deserializer(&self) -> proc_macro2::TokenStream {
        let mut versioned_deserializers = proc_macro2::TokenStream::new();

        let mut first_minor = true;
        let mut last_minor = 0;
        for (minor, patchs) in &self.versions {
            if first_minor && *minor != 0 {
                let first_range = minor.wrapping_sub(1);
                let field_deserializers = self.generate_field_deserializer(first_range, 0);
                versioned_deserializers.extend(quote! {
                    (0..=#first_range, _) => {
                        #field_deserializers
                    }
                });
                first_minor = false;
            }
            let mut start = 0;
            for patch in patchs {
                // skip 0
                if *patch == start {
                    continue;
                }
                let end = patch - 1;
                let field_deserializers = self.generate_field_deserializer(*minor, end);
                versioned_deserializers.extend(quote! {
                    (#minor, #start..=#end) => {
                        #field_deserializers
                    }
                });
                start = *patch;
            }
            let field_deserializers = self.generate_field_deserializer(*minor, start);
            versioned_deserializers.extend(quote! {
                (#minor, #start..) => {
                    #field_deserializers
                }
            });
            last_minor = *minor + 1;
        }
        let field_deserializers = self.generate_field_deserializer(last_minor, 0);
        versioned_deserializers.extend(quote! {
            (#last_minor.., _) => {
                #field_deserializers
            }
        });

        // Generate code to map the app version to struct version and wrap the
        // deserializers with the `version` match.
        quote! {
            let source = version_map.get_crate_version(env!("CARGO_PKG_NAME"))?;
            match (source.minor, source.patch) {
                #versioned_deserializers
            }
        }
    }
}

impl StructDescriptor {
    pub fn new(input: &syn::DataStruct, ident: syn::Ident) -> Self {
        let mut descriptor = StructDescriptor {
            ty: ident,
            versions: BTreeMap::new(),
            fields: vec![],
        };

        // Fills self.fields.
        descriptor.parse_struct_fields(&input.fields);
        descriptor.versions = collect_version(&descriptor.fields);
        descriptor
    }

    fn parse_struct_fields(&mut self, fields: &syn::Fields) {
        match fields {
            syn::Fields::Named(ref named_fields) => {
                let pairs = named_fields.named.pairs();
                for field in pairs {
                    self.fields.push(StructField::new(field));
                }
            }
            _ => panic!("Only named fields are supported."),
        }
    }

    fn generate_field_deserializer(&self, minor: u64, patch: u64) -> proc_macro2::TokenStream {
        let struct_ident = format_ident!("{}", self.ty);
        let mut versioned_deserializer = proc_macro2::TokenStream::new();
        let mut semantic_deserializer = proc_macro2::TokenStream::new();

        // Generate field and semantic deserializers for all fields.
        // Not all fields have semantic deserializers defined and some fields
        // might be missing in version `i`. In these cases the generate_deserializer() and
        // generate_semantic_deserializer() will return an empty token stream.
        for field in &self.fields {
            versioned_deserializer.extend(field.generate_deserializer(minor, patch));
            semantic_deserializer.extend(field.generate_semantic_deserializer(minor, patch));
        }

        quote! {
            let mut object = #struct_ident {
                #versioned_deserializer
            };
            #semantic_deserializer
            Ok(object)
        }
    }
}
