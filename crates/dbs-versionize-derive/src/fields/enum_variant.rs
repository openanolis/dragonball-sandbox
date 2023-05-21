// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::common::Exists;
use crate::helpers::{get_ident_attr, get_version, parse_field_attributes};
use crate::{DEFAULT_FN, END_VERSION, START_VERSION};
use quote::{format_ident, quote};
use std::collections::HashMap;

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct EnumVariant {
    ident: syn::Ident,
    ty: Vec<syn::Type>,
    // Bincode uses u32 instead of usize also.
    variant_index: u32,
    start_version: Vec<semver::Version>,
    end_version: Vec<semver::Version>,
    attrs: HashMap<String, syn::Lit>,
}

impl Exists for EnumVariant {
    fn start_version(&self) -> &[semver::Version] {
        &self.start_version
    }

    fn end_version(&self) -> &[semver::Version] {
        &self.end_version
    }
}

impl EnumVariant {
    pub fn new(ast_variant: &syn::Variant, variant_index: u32) -> Self {
        let attrs = parse_field_attributes(&ast_variant.attrs);

        let ty = match &ast_variant.fields {
            syn::Fields::Unnamed(fields) => fields
                .unnamed
                .iter()
                .map(|field| field.ty.clone())
                .collect(),
            _ => Vec::new(),
        };

        EnumVariant {
            ident: ast_variant.ident.clone(),
            ty,
            variant_index,
            // Set base version.
            start_version: get_version(START_VERSION, &attrs),
            end_version: get_version(END_VERSION, &attrs),
            attrs,
        }
    }

    // Emits code that serializes an enum variant.
    pub fn generate_serializer(&self, minor: u64, patch: u64) -> proc_macro2::TokenStream {
        let field_ident = &self.ident;
        let variant_index = self.variant_index;

        if !self.exists_at(minor, patch) {
            if let Some(default_fn_ident) = get_ident_attr(&self.attrs, DEFAULT_FN) {
                let field_type_ident = if self.ty.is_empty() {
                    quote! { Self::#field_ident => }
                } else {
                    quote! { Self::#field_ident(..) => }
                };

                let mut serializer = proc_macro2::TokenStream::new();
                serializer.extend(field_type_ident);
                serializer.extend(self.default_fn_serializer(default_fn_ident));
                return serializer;
            } else {
                panic!("Variant {} does not exist in version {}.{}, please implement a default_fn function that provides a default value for this variant.", field_ident, minor, patch);
            }
        }

        let mut serialize_data = proc_macro2::TokenStream::new();
        let mut data_tuple = proc_macro2::TokenStream::new();

        for (index, _) in self.ty.iter().enumerate() {
            let data_ident = format_ident!("data_{}", index);
            data_tuple.extend(quote!(#data_ident,));
            serialize_data.extend(quote! {
                Versionize::serialize(#data_ident, &mut writer, version_map)?;
            });
        }

        if self.ty.is_empty() {
            quote! {
                Self::#field_ident => {
                    let index: u32 = #variant_index;
                    Versionize::serialize(&index, &mut writer, version_map)?;
                },
            }
        } else {
            quote! {
                Self::#field_ident(#data_tuple) => {
                    let index: u32 = #variant_index;
                    Versionize::serialize(&index, &mut writer, version_map)?;
                    #serialize_data
                },
            }
        }
    }

    pub fn generate_deserializer(&self, _minor: u64, _patch: u64) -> proc_macro2::TokenStream {
        let variant_index = self.variant_index;
        let ident = &self.ident;

        // Enum variant with no data.
        if self.ty.is_empty() {
            return quote! {
                #variant_index => {
                    return Ok(Self::#ident);
                },
            };
        }

        let mut deserialize_data = proc_macro2::TokenStream::new();
        let mut data_tuple = proc_macro2::TokenStream::new();
        for (index, data_type) in self.ty.iter().enumerate() {
            let data_ident = format_ident!("data_{}", index);
            data_tuple.extend(quote!(#data_ident,));
            deserialize_data.extend(
                quote! {
                    let #data_ident = <#data_type as Versionize>::deserialize(&mut reader, version_map)?;
                }
            );
        }

        quote! {
            #variant_index => {
                #deserialize_data
                return Ok(Self::#ident(#data_tuple));
            },
        }
    }

    fn default_fn_serializer(&self, default_fn_ident: syn::Ident) -> proc_macro2::TokenStream {
        quote! {
            {
                // Call user defined fn to provide a variant that exists in target version.
                let new_variant = self.#default_fn_ident(&current)?;
                // The new_variant will serialize its index and data.
                new_variant.serialize(writer, version_map)?;
            },
        }
    }
}
