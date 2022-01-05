// Copyright (C) 2019 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic algorithms for VMM resource management.

#![deny(missing_docs)]

mod interval_tree;
pub use interval_tree::{IntervalTree, NodeState, Range};

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
    pub fn min<T>(&mut self, min: T)
    where
        u64: From<T>,
    {
        let min = u64::from(min);
        if min > self.size {
            panic!("Constraint: Constraint min is invalid because it is larger than size");
        }
        self.min = min;
    }

    /// Set the max constraint.
    pub fn max<T>(&mut self, max: T)
    where
        u64: From<T>,
    {
        let max = u64::from(max);
        if max < self.size {
            panic!("Constraint: Constraint max is invalid because it is smaller than size");
        }
        self.max = max;
    }

    /// Set the alignment constraint.
    pub fn align<T>(&mut self, align: T)
    where
        u64: From<T>,
    {
        self.align = u64::from(align);
    }

    /// Set the allocation policy.
    pub fn policy(&mut self, policy: AllocPolicy) {
        self.policy = policy;
    }
}

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
    }

    #[should_panic]
    #[test]
    fn test_set_invalid_min() {
        let mut constraint = Constraint::new(2_u64);
        constraint.min(3_u64);
    }

    #[should_panic]
    #[test]
    fn test_set_invalid_max() {
        let mut constraint = Constraint::new(2_u64);
        constraint.max(1_u64);
    }
}
