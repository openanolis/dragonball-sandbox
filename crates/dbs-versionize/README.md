**Versionize is a framework for version tolerant serializion/deserialization of
Rust data structures, designed for usecases that need fast deserialization 
times and minimal size overhead. It does not aim to be a generic serialization 
framework and only the [bincode](https://crates.io/crates/bincode) backend is 
supported.**

## Important note

This crate is currently used for cross-version serialization with the 
[Firecracker snapshot-restore dev preview][1], but has not been tested for 
other use cases. It should be considered **experimental software** outside the 
Firecracker context. It’s likely that this crate will see both interface and 
implementation changes in the future.

## Versionize in action

```rust
extern crate versionize;
extern crate versionize_derive;

use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

// The test structure is at version 3.
#[derive(Debug, PartialEq, Versionize)]
pub struct Test {
    a: u32,
    #[version(start = 2, end = 3)]
    b: u8,
    #[version(start = 3, default_fn = "default_c")]
    c: String,
}

impl Test {
    // Default value for field `c`.
    // The callback is invoked when deserializing an older version
    // where the field did not exist.
    fn default_c(_source_version: u16) -> String {
        "test_string".to_owned()
    }
}

// Memory to hold the serialization output.
let mut mem = vec![0u8; 512];
// Create a new version map - it will start at app version 1.
let mut version_map = VersionMap::new();
// Map structure versions to app version.
version_map
    .new_version() // App version 2.
    .set_type_version(Test::type_id(), 2) // Struct(2) -> App(2).
    .new_version() // App version 3.
    .set_type_version(Test::type_id(), 3); // Struct(3) -> App(3).

let test_struct = Test {
    a: 1337,
    b: 0xFF,
    c: "c_value".to_owned(),
};

// Serialize to app version 2 - field c will not be serialized.
test_struct
    .serialize(&mut mem.as_mut_slice(), &version_map, 2)
    .unwrap();

// Deserialize from app version 2 - c should contain the default_fn() return value.
let restored_test_struct = Test::deserialize(&mut mem.as_slice(), &version_map, 2).unwrap();

assert_eq!(
    restored_test_struct,
    Test {
        a: 1337,
        b: 255,
        c: "test_string".to_owned()
    }
);
```

[1]: https://github.com/firecracker-microvm/firecracker/tree/v0.24.0