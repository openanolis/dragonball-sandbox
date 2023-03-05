// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cmp::max;
use std::collections::{BTreeMap, HashMap};

use quote::format_ident;

use super::ATTRIBUTE_NAME;
use crate::common::Exists;

// Returns a string literal attribute as an Ident.
pub(crate) fn get_ident_attr(
    attrs: &HashMap<String, syn::Lit>,
    attr_name: &str,
) -> Option<syn::Ident> {
    attrs.get(attr_name).map(|default_fn| match default_fn {
        syn::Lit::Str(lit_str) => {
            return format_ident!("{}", lit_str.value());
        }
        _ => panic!("default_fn must be the function name as a String."),
    })
}

pub(crate) fn get_version(key: &str, attrs: &HashMap<String, syn::Lit>) -> Vec<semver::Version> {
    if let Some(version) = attrs.get(key) {
        return match version {
            syn::Lit::Str(lit_str) => parse_version(&lit_str.value()),
            _ => panic!("Field start/end version must be an semver"),
        };
    }
    Vec::new()
}

pub(crate) fn parse_version(versions: &str) -> Vec<semver::Version> {
    versions
        .split(',')
        .filter(|x| !x.is_empty())
        .map(|version| {
            let v = semver::Version::parse(version.trim()).expect("parse semver");
            if !v.pre.is_empty() || !v.build.is_empty() {
                panic!("Unsupported pre-release and build metadata.");
            }
            v
        })
        .collect()
}

// Returns an attribute hash_map constructed by processing a vector of syn::Attribute.
pub(crate) fn parse_field_attributes(attributes: &[syn::Attribute]) -> HashMap<String, syn::Lit> {
    let mut attrs = HashMap::new();

    for nested_attr in attributes
        .iter()
        .flat_map(|attr| -> Result<Vec<syn::NestedMeta>, ()> {
            if !attr.path.is_ident(ATTRIBUTE_NAME) {
                return Ok(Vec::new());
            }

            if let Ok(syn::Meta::List(meta)) = attr.parse_meta() {
                return Ok(meta.nested.into_iter().collect());
            }

            Ok(Vec::new())
        })
        .flatten()
    {
        if let syn::NestedMeta::Meta(syn::Meta::NameValue(attr_name_value)) = nested_attr {
            attrs.insert(
                attr_name_value.path.get_ident().unwrap().to_string(),
                attr_name_value.lit,
            );
        }
    }

    attrs
}

pub(crate) fn collect_version<T>(fields: &[T]) -> BTreeMap<u64, Vec<u64>>
where
    T: Exists,
{
    let mut vers = vec![];
    for field in fields {
        vers.append(&mut field.list_versions());
    }
    vers.sort();
    vers.dedup();
    let mut rets: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for v in &vers {
        if let Some(p) = rets.get_mut(&v.minor) {
            p.push(v.patch);
        } else {
            rets.insert(v.minor, vec![v.patch]);
        }
    }
    rets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        let versions = parse_version("2.7.14,2.8.4");
        assert_eq!(versions[0], semver::Version::new(2, 7, 14));
        assert_eq!(versions[1], semver::Version::new(2, 8, 4));

        let versions = parse_version(" 2.7.14, 2.8.4 ");
        assert_eq!(versions[0], semver::Version::new(2, 7, 14));
        assert_eq!(versions[1], semver::Version::new(2, 8, 4));
    }

    #[test]
    #[should_panic(expected = "Unsupported pre-release and build metadata.")]
    fn test_parse_version_panic_1() {
        parse_version("2.7.14-alpha");
    }

    #[test]
    #[should_panic(expected = "parse semver")]
    fn test_parse_version_panic_2() {
        parse_version("aaa");
    }

    struct TestField {
        start: Vec<semver::Version>,
        end: Vec<semver::Version>,
    }

    impl Exists for TestField {
        fn start_version(&self) -> &[semver::Version] {
            &self.start
        }
        fn end_version(&self) -> &[semver::Version] {
            &self.end
        }
    }

    #[test]
    fn test_collect_version() {
        let vers = vec![
            TestField {
                start: parse_version("2.7.7,2.8.3"),
                end: parse_version("2.7.11, 2.8.8"),
            },
            TestField {
                start: parse_version("2.8.0"),
                end: parse_version("2.8.8"),
            },
        ];
        let rets = collect_version(&vers);
        assert_eq!(
            rets,
            BTreeMap::from([(7, vec![7, 11]), (8, vec![0, 3, 8]),])
        );

        assert_eq!(
            collect_version(&vec![
                TestField {
                    start: parse_version("2.7.0"),
                    end: vec![],
                },
                TestField {
                    start: parse_version("2.7.3"),
                    end: vec![],
                },
                TestField {
                    start: parse_version("2.7.4"),
                    end: parse_version("2.7.5"),
                },
                TestField {
                    start: parse_version("2.8.0"),
                    end: vec![],
                },
                TestField {
                    start: parse_version("2.7.8, 2.8.3"),
                    end: vec![],
                },
                TestField {
                    start: parse_version("2.7.8, 2.8.3"),
                    end: vec![],
                },
                TestField {
                    start: parse_version("2.9.0"),
                    end: vec![],
                },
            ]),
            BTreeMap::from([(7, vec![0, 3, 4, 5, 8]), (8, vec![0, 3]), (9, vec![0])])
        );
    }

    #[test]
    fn test_exists_at() {
        let test = TestField {
            start: parse_version("2.7.7,2.8.3"),
            end: parse_version("2.7.11, 2.8.8"),
        };

        assert_eq!(test.exists_at(0, 0), false);
        assert_eq!(test.exists_at(7, 0), false);
        assert_eq!(test.exists_at(7, 7), true);
        assert_eq!(test.exists_at(7, 10), true);
        assert_eq!(test.exists_at(7, 11), false);
        assert_eq!(test.exists_at(8, 0), false);
        assert_eq!(test.exists_at(8, 3), true);
        assert_eq!(test.exists_at(8, 7), true);
        assert_eq!(test.exists_at(8, 8), false);
        assert_eq!(test.exists_at(9, 0), false);
        assert_eq!(test.exists_at(999, 9999), false);

        let test = TestField {
            start: parse_version(""),
            end: parse_version(""),
        };
        assert_eq!(test.exists_at(0, 0), true);
        assert_eq!(test.exists_at(7, 0), true);
        assert_eq!(test.exists_at(7, 99), true);
        assert_eq!(test.exists_at(8, 0), true);
        assert_eq!(test.exists_at(8, 99), true);
        assert_eq!(test.exists_at(9, 0), true);
        assert_eq!(test.exists_at(999, 9999), true);

        let test = TestField {
            start: parse_version("2.8.1"),
            end: parse_version(""),
        };
        assert_eq!(test.exists_at(0, 0), false);
        assert_eq!(test.exists_at(7, 0), false);
        assert_eq!(test.exists_at(7, 999), false);
        assert_eq!(test.exists_at(8, 0), false);
        assert_eq!(test.exists_at(8, 1), true);
        assert_eq!(test.exists_at(8, 999), true);
        assert_eq!(test.exists_at(9, 0), true);
        assert_eq!(test.exists_at(999, 9999), true);

        let test = TestField {
            start: parse_version(""),
            end: parse_version("2.8.8"),
        };
        assert_eq!(test.exists_at(0, 0), true);
        assert_eq!(test.exists_at(7, 0), true);
        assert_eq!(test.exists_at(7, 999), true);
        assert_eq!(test.exists_at(8, 0), true);
        assert_eq!(test.exists_at(8, 7), true);
        assert_eq!(test.exists_at(8, 8), false);
        assert_eq!(test.exists_at(8, 999), false);
        assert_eq!(test.exists_at(9, 0), false);
        assert_eq!(test.exists_at(999, 9999), false);

        let test = TestField {
            start: parse_version(""),
            end: parse_version("2.7.3, 2.8.8"),
        };
        assert_eq!(test.exists_at(0, 0), true);
        assert_eq!(test.exists_at(7, 2), true);
        assert_eq!(test.exists_at(7, 3), false);
        assert_eq!(test.exists_at(7, 999), false);
        assert_eq!(test.exists_at(8, 0), true);
        assert_eq!(test.exists_at(8, 7), true);
        assert_eq!(test.exists_at(8, 8), false);
        assert_eq!(test.exists_at(8, 999), false);
        assert_eq!(test.exists_at(9, 0), false);
        assert_eq!(test.exists_at(999, 9999), false);
    }
}
