// Copyright (C) 2019 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic algorithms for VMM resource management.

#![deny(missing_docs)]

mod interval_tree;
pub use interval_tree::{IntervalTree, NodeState, Range};
use std::fmt::{Display, Formatter};
use std::result;

/// Error conditions that may appear during `Allocator` related operations.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Invalid Constraint Max and Min
    InvalidBoundary(u64, u64),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidBoundary(max, min) => {
                write!(f, "invalid constraint max ({}) and min ({})", max, min)
            }
        }
    }
}

/// Policy for resource allocation.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AllocPolicy {
    /// Default allocation policy.
    Default,
    /// Allocate from the first matched entry.
    FirstMatch,
}

/// Struct to describe resource allocation constraints.
#[derive(Copy, Clone, Debug)]
pub struct Constraint {
    /// Size to allocate.
    pub size: u64,
    /// Lower boundary for the allocated resource.
    pub min: u64,
    /// Upper boundary for the allocated resource.
    pub max: u64,
    /// Alignment for the allocated resource.
    pub align: u64,
    /// Resource allocation policy.
    pub policy: AllocPolicy,
}

/// Generic result type that may return `Allocator` errors.
pub type Result<T> = result::Result<T, Error>;

impl Constraint {
    /// Create a new constraint object with default settings.
    pub fn new<T>(size: T) -> Self
    where
        u64: From<T>,
    {
        Constraint {
            size: u64::from(size),
            min: 0,
            max: std::u64::MAX,
            align: 1,
            policy: AllocPolicy::Default,
        }
    }

    /// Set the min constraint.
    pub fn min<T>(&mut self, min: T) -> &mut Self
    where
        u64: From<T>,
    {
        self.min = u64::from(min);
        self
    }

    /// Set the max constraint.
    pub fn max<T>(&mut self, max: T) -> &mut Self
    where
        u64: From<T>,
    {
        self.max = u64::from(max);
        self
    }

    /// Set the alignment constraint.
    pub fn align<T>(&mut self, align: T) -> &mut Self
    where
        u64: From<T>,
    {
        self.align = u64::from(align);
        self
    }

    /// Set the allocation policy.
    pub fn policy(&mut self, policy: AllocPolicy) -> &mut Self {
        self.policy = policy;
        self
    }

    /// Validate the constraint
    pub fn validate(&self) -> Result<()> {
        if self.max < self.min {
            return Err(Error::InvalidBoundary(self.max, self.min));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_set_min() {
        let mut constraint = Constraint::new(2_u64);
        constraint.min(1_u64);
        assert_eq!(constraint.min, 1_u64);
    }

    #[test]
    fn test_set_max() {
        let mut constraint = Constraint::new(2_u64);
        constraint.max(100_u64);
        assert_eq!(constraint.max, 100_u64);
    }

    #[test]
    fn test_set_align() {
        let mut constraint = Constraint::new(2_u64);
        constraint.align(8_u64);
        assert_eq!(constraint.align, 8_u64);
    }

    #[test]
    fn test_set_policy() {
        let mut constraint = Constraint::new(2_u64);
        constraint.policy(AllocPolicy::FirstMatch);
        assert_eq!(constraint.policy, AllocPolicy::FirstMatch);
        constraint.policy(AllocPolicy::Default);
        assert_eq!(constraint.policy, AllocPolicy::Default);
    }

    #[test]
    fn test_consistently_change_constraint() {
        let mut constraint = Constraint::new(2_u64);
        constraint
            .min(1_u64)
            .max(100_u64)
            .align(8_u64)
            .policy(AllocPolicy::FirstMatch);
        assert_eq!(constraint.min, 1_u64);
        assert_eq!(constraint.max, 100_u64);
        assert_eq!(constraint.align, 8_u64);
        assert_eq!(constraint.policy, AllocPolicy::FirstMatch);
    }

    #[test]
    fn test_set_invalid_boundary() {
        let mut constraint = Constraint::new(2_u64);
        constraint.max(999_u64);
        constraint.min(1000_u64);
        assert_eq!(
            constraint.validate(),
            Err(Error::InvalidBoundary(999_u64, 1000_u64))
        )
    }
}
