// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::common::{Exists, FieldType};
use crate::helpers::{get_ident_attr, get_version, parse_field_attributes};
use crate::{DEFAULT_FN, END_VERSION, SEMANTIC_DE_FN, SEMANTIC_SER_FN, START_VERSION};
use quote::{format_ident, quote};
use std::collections::HashMap;

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct StructField {
    ty: syn::Type,
    name: String,
    start_version: Vec<semver::Version>,
    end_version: Vec<semver::Version>,
    attrs: HashMap<String, syn::Lit>,
}

impl Exists for StructField {
    fn start_version(&self) -> &[semver::Version] {
        &self.start_version
    }

    fn end_version(&self) -> &[semver::Version] {
        &self.end_version
    }
}

impl FieldType for StructField {
    fn ty(&self) -> syn::Type {
        self.ty.clone()
    }
}

impl StructField {
    pub fn new(ast_field: syn::punctuated::Pair<&syn::Field, &syn::token::Comma>) -> Self {
        let attrs = parse_field_attributes(&ast_field.value().attrs);

        StructField {
            ty: ast_field.value().ty.clone(),
            name: ast_field.value().ident.as_ref().unwrap().to_string(),
            start_version: get_version(START_VERSION, &attrs),
            end_version: get_version(END_VERSION, &attrs),
            attrs,
        }
    }

    pub fn generate_semantic_serializer(
        &self,
        _minor: u64,
        _patch: u64,
    ) -> proc_macro2::TokenStream {
        // Generate semantic serializer for this field only if it does not exist in target_version.
        if let Some(semantic_ser_fn) = get_ident_attr(&self.attrs, SEMANTIC_SER_FN) {
            return quote! {
                copy_of_self.#semantic_ser_fn(&current)?;
            };
        }
        quote! {}
    }

    pub fn generate_semantic_deserializer(
        &self,
        _minor: u64,
        _patch: u64,
    ) -> proc_macro2::TokenStream {
        // Generate semantic deserializer for this field only if it does not exist in source_version.
        if let Some(semantic_de_fn) = get_ident_attr(&self.attrs, SEMANTIC_DE_FN) {
            // Object is an instance of the structure.
            return quote! {
                // - `source` is set to version_map.get_crate_version();
                object.#semantic_de_fn(&source)?;
            };
        }
        quote! {}
    }

    pub fn generate_serializer(&self, minor: u64, patch: u64) -> proc_macro2::TokenStream {
        let field_ident = format_ident!("{}", self.name);

        // Generate serializer for this field only if it exists in target_version.
        if !self.exists_at(minor, patch) {
            return proc_macro2::TokenStream::new();
        }

        match &self.ty {
            syn::Type::Array(_) => quote! {
                for element in copy_of_self.#field_ident.iter() {
                    Versionize::serialize(element, &mut writer, version_map)?;
                }
            },
            syn::Type::Path(_) => quote! {
                Versionize::serialize(&copy_of_self.#field_ident, &mut writer, version_map)?;
            },
            syn::Type::Reference(_) => quote! {
                copy_of_self.#field_ident.serialize(&mut writer, version_map)?;
            },
            _ => panic!("Unsupported field type {:?}", self.ty),
        }
    }

    pub fn generate_deserializer(&self, minor: u64, patch: u64) -> proc_macro2::TokenStream {
        let field_ident = format_ident!("{}", self.name);

        // If the field does not exist in source version, use default annotation or Default trait.
        if !self.exists_at(minor, patch) {
            if let Some(default_fn) = get_ident_attr(&self.attrs, DEFAULT_FN) {
                return quote! {
                    // The default_fn is called with source version of the struct:
                    // - `source` is set to version_map.get_crate_version();
                    #field_ident: Self::#default_fn(&source),
                };
            } else {
                return quote! { #field_ident: Default::default(), };
            }
        }

        let ty = &self.ty;

        match ty {
            syn::Type::Array(array) => {
                let array_type_token;

                match *array.elem.clone() {
                    syn::Type::Path(token) => {
                        array_type_token = token;
                    }
                    _ => panic!("Unsupported array type."),
                }

                match &array.len {
                    syn::Expr::Lit(expr_lit) => match &expr_lit.lit {
                        syn::Lit::Int(lit_int) => {
                            let array_len: usize = lit_int.base10_parse().unwrap();
                            self.generate_array_deserializer(array_type_token, array_len)
                        }
                        _ => panic!("Unsupported array len literal."),
                    },
                    syn::Expr::Path(expr_path) => {
                        self.generate_array_deserializer(array_type_token, &expr_path.path)
                    }
                    _ => panic!("Unsupported array len expression."),
                }
            }
            syn::Type::Path(_) => quote! {
                #field_ident: <#ty as Versionize>::deserialize(&mut reader, version_map)?,
            },
            syn::Type::Reference(_) => quote! {
                #field_ident: <#ty as Versionize>::deserialize(&mut reader, version_map)?,
            },
            _ => panic!("Unsupported field type {:?}", self.ty),
        }
    }

    fn generate_array_deserializer<T: quote::ToTokens>(
        &self,
        array_type_token: syn::TypePath,
        array_len: T,
    ) -> proc_macro2::TokenStream {
        let field_ident = format_ident!("{}", self.name);

        quote! {
            #field_ident: {
                let mut array = [#array_type_token::default() ; #array_len];
                for i in 0..#array_len {
                    array[i] = <#array_type_token as Versionize>::deserialize(&mut reader, version_map)?;
                }
                array
            },
        }
    }
}
