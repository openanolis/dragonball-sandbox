# v0.1.10

- Fixed a possible out of bounds memory access in FamStructWrapper::deserialize

# v0.1.9

- Implement Versionize for i128 and u128

# v0.1.8

- Fixed VersionMap not implementing Sync + Send in 0.1.7

# v0.1.7 [yanked]

- Use caret requirements instead of comparison requirements
  for specifying dependencies
- Update vmm-sys-utils to 0.11.0

# v0.1.6

- Upgraded vmm-sys-utils to v0.8.0

# v0.1.5

- Added more documentation and examples.

# v0.1.4

- Removed Versionize proc macro support for unions. Serializing unions can lead to undefined behaviour especially when no
layout guarantees are provided. The Versionize trait can still be implemented but only for repr(C) unions and extensive care
and testing is required from the implementer.

# v0.1.3

- Added extra validations in VersionMap::get_type_version().

# v0.1.2

- Improved edge cases handling for Vec serialization and deserialization.

# v0.1.0

- "versionize" v0.1.0 first release.
