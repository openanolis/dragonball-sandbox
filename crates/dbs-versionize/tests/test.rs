// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use dbs_versionize::{VersionMap, Versionize, VersionizeError};
use dbs_versionize_tests::TestState;

#[test]
fn test_hardcoded_enum_deserialization() {
    // We are testing separately also hardcoded snapshot deserialization for enums
    // as these have a different behavior in terms of serialization/deserialization.
    #[rustfmt::skip]
    let v1_hardcoded_snapshot: &[u8] = &[
        // Variant number (4 bytes), the first variant lacks a value.
        0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    let v2_hardcoded_snapshot: &[u8] = &[
        0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    let unexpected_v1_hardcoded_snapshot: &[u8] = &[
        // Second variant (4 bytes) + value of that variant (8 bytes).
        0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    let invalid_v1_hardcoded_snapshot: &[u8] = &[
        // Invalid enum variant number.
        0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut vm = VersionMap::new();
    vm.set_crate_version("dbs-versionize-tests", "0.1.0")
        .unwrap();

    let mut snapshot_blob = v1_hardcoded_snapshot;

    let mut restored_state =
        <TestState as Versionize>::deserialize(&mut snapshot_blob, &vm).unwrap();
    assert_eq!(restored_state, TestState::Zero);

    snapshot_blob = v2_hardcoded_snapshot;

    let mut vm = VersionMap::new();
    vm.set_crate_version("dbs-versionize-tests", "0.2.0")
        .unwrap();
    restored_state = <TestState as Versionize>::deserialize(&mut snapshot_blob, &vm).unwrap();
    assert_eq!(restored_state, TestState::Zero);

    snapshot_blob = unexpected_v1_hardcoded_snapshot;

    let mut vm = VersionMap::new();
    vm.set_crate_version("dbs-versionize-tests", "0.1.0")
        .unwrap();
    // Versioned deserialization is not implemented for enums, so even though we do not have
    // `Two` state available at version 2, restoring the data won't fail :(.
    // TODO: This must be fixed.
    restored_state = <TestState as Versionize>::deserialize(&mut snapshot_blob, &vm).unwrap();
    assert_eq!(restored_state, TestState::Two(5));

    // This snapshot contains a non-existent enum variant.
    snapshot_blob = invalid_v1_hardcoded_snapshot;

    assert_eq!(
        <TestState as Versionize>::deserialize(&mut snapshot_blob, &vm).unwrap_err(),
        VersionizeError::Deserialize("Unknown variant_index 3".to_owned())
    );
}
