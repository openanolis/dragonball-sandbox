// Copyright 2023 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::{Versionize, VersionizeError, VersionizeResult};

pub const MAX_VERSION_NUM: u64 = u16::MAX as u64;

/// The VersionMap API provides functionality to define the version for each
/// type and attach them to specific root versions.
#[derive(Clone, Debug)]
pub struct VersionMap {
    crates: HashMap<String, semver::Version>,
}

impl Default for VersionMap {
    fn default() -> Self {
        VersionMap {
            crates: HashMap::new(),
        }
    }
}

impl VersionMap {
    /// Create a new version map initialized.
    pub fn new() -> Self {
        Default::default()
    }

    pub fn get_crate_version(&self, crate_name: &str) -> semver::Version {
        self.crates.get(crate_name).expect("should exist").clone()
    }

    pub fn set_crate_version(
        &mut self,
        crate_name: &str,
        ver: semver::Version,
    ) -> VersionizeResult<()> {
        if let Some(exist) = self.crates.get(crate_name) {
            if *exist != ver {
                return Err(VersionizeError::MultipleVersion(
                    crate_name.to_string(),
                    exist.to_string(),
                    ver.to_string(),
                ));
            }
        } else {
            self.crates.insert(crate_name.to_owned(), ver);
        }

        Ok(())
    }
}

//impl Versionize for VersionMap {
//    fn serialize<W: std::io::Write>(
//        &self,
//        writer: &mut W,
//        version_map: &mut VersionMap,
//    ) -> VersionizeResult<()> {
//    }
//
//    fn deserialize<R: std::io::Read>(
//        reader: &mut R,
//        version_map: &VersionMap,
//    ) -> VersionizeResult<Self>
//    where
//        Self: Sized,
//    {
//    }
//}

///
impl Versionize for semver::Version {
    fn serialize<W: std::io::Write>(
        &self,
        mut writer: W,
        _version_map: &mut VersionMap,
    ) -> VersionizeResult<()> {
        // Only support release version.
        if !self.pre.is_empty() || !self.build.is_empty() {
            return Err(VersionizeError::UnsuportVersion(self.to_string()));
        }
        // To reduce snapshot size, only u16::MAX is supported, which should be enough.
        if self.major > MAX_VERSION_NUM
            || self.minor > MAX_VERSION_NUM
            || self.patch > MAX_VERSION_NUM
        {
            return Err(VersionizeError::UnsuportVersion(self.to_string()));
        }
        bincode::serialize_into(&mut writer, &(self.major as u16))
            .map_err(|err| VersionizeError::Serialize(format!("{:?}", err)))?;
        bincode::serialize_into(&mut writer, &(self.minor as u16))
            .map_err(|err| VersionizeError::Serialize(format!("{:?}", err)))?;
        bincode::serialize_into(&mut writer, &(self.patch as u16))
            .map_err(|err| VersionizeError::Serialize(format!("{:?}", err)))?;
        Ok(())
    }

    fn deserialize<R: std::io::Read>(
        mut reader: R,
        _version_map: &VersionMap,
    ) -> VersionizeResult<Self>
    where
        Self: Sized,
    {
        let major: u16 = bincode::deserialize_from(&mut reader)
            .map_err(|err| VersionizeError::Deserialize(format!("{:?}", err)))?;
        let minor: u16 = bincode::deserialize_from(&mut reader)
            .map_err(|err| VersionizeError::Deserialize(format!("{:?}", err)))?;
        let patch: u16 = bincode::deserialize_from(&mut reader)
            .map_err(|err| VersionizeError::Deserialize(format!("{:?}", err)))?;
        Ok(semver::Version::new(
            major as u64,
            minor as u64,
            patch as u64,
        ))
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{NativeEndian, ReadBytesExt};

    use super::*;
    use crate::{Versionize, VersionizeError, VersionizeResult};

    #[test]
    fn test_ser_de_semver_err() {
        let mut vm = VersionMap::new();
        let mut snapshot_mem = vec![0u8; 48];
        let sem_ver = semver::Version::new(1, 1, MAX_VERSION_NUM + 1);
        assert_eq!(
            sem_ver
                .serialize(snapshot_mem.as_mut_slice(), &mut vm)
                .unwrap_err(),
            VersionizeError::UnsuportVersion("1.1.65536".to_string())
        );

        let sem_ver = semver::Version::parse("1.0.0-alpha").unwrap();
        assert_eq!(
            sem_ver
                .serialize(snapshot_mem.as_mut_slice(), &mut vm)
                .unwrap_err(),
            VersionizeError::UnsuportVersion("1.0.0-alpha".to_string())
        );

        let sem_ver = semver::Version::parse("1.0.0+alpha").unwrap();
        assert_eq!(
            sem_ver
                .serialize(snapshot_mem.as_mut_slice(), &mut vm)
                .unwrap_err(),
            VersionizeError::UnsuportVersion("1.0.0+alpha".to_string())
        );
    }

    #[test]
    fn test_ser_de_semver() {
        let mut vm = VersionMap::new();
        let mut snapshot_mem = vec![0u8; 6];
        let sem_ver = semver::Version::new(3, 0, 14);
        sem_ver
            .serialize(&mut snapshot_mem.as_mut_slice(), &mut vm)
            .unwrap();

        assert_eq!(3, (&snapshot_mem[..2]).read_u16::<NativeEndian>().unwrap());
        assert_eq!(0, (&snapshot_mem[2..4]).read_u16::<NativeEndian>().unwrap());
        assert_eq!(
            14,
            (&snapshot_mem[4..6]).read_u16::<NativeEndian>().unwrap()
        );

        let de_ver: semver::Version =
            Versionize::deserialize(snapshot_mem.as_slice(), &vm).unwrap();
        assert_eq!(de_ver, semver::Version::parse("3.0.14").unwrap());
    }
}
