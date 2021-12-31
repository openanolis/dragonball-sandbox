// Copyright (C) 2019 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic algorithms for VMM resource management.

#![deny(missing_docs)]

mod interval_tree;
pub use interval_tree::{IntervalTree, NodeState, Range};

/// Policy for resource allocation.
#[derive(Copy, Clone, Debug)]
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
    pub fn min<T>(mut self, min: T) -> Self
    where
        u64: From<T>,
    {
        self.min = u64::from(min);
        self
    }

    /// Set the max constraint.
    pub fn max<T>(mut self, max: T) -> Self
    where
        u64: From<T>,
    {
        self.max = u64::from(max);
        self
    }

    /// Set the alignment constraint.
    pub fn align<T>(mut self, align: T) -> Self
    where
        u64: From<T>,
    {
        self.align = u64::from(align);
        self
    }

    /// Set the allocation policy.
    pub fn policy(mut self, policy: AllocPolicy) -> Self {
        self.policy = policy;
        self
    }
}
