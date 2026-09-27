//! Declared runtime-resource values shared by the build/test graph and the
//! test daemon (I2.22).
//!
//! I2.22 requires that a test group *declare* its resource weight and its
//! exclusive resources, and that stateful ports, services, and database volumes
//! receive separate leases: "A worktree does not isolate runtime resources."
//! These three values are that declaration. They live in the build/test graph
//! because a governed work item is admitted on the instrument plane, which
//! depends on this crate and never on the test daemon; keeping one declaration
//! type on both sides of that edge is what stops two competing `ResourceClaim`
//! types from existing. `eliot-testd-core::resources` re-exports all three, so
//! every existing import site is unchanged.
//!
//! Lease *allocation* is not here. `eliot-testd-core` remains the allocator,
//! because a lease is only exclusive against a live holder set it owns.

use serde::{Deserialize, Serialize};

/// Kinds of exclusive runtime resource. A worktree does not isolate any of
/// them, so a claim on one excludes every other claim on the same resource.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// A stateful service instance.
    StatefulService,
    /// A bound TCP/UDP port.
    Port,
    /// A mutable fixture directory or volume.
    Fixture,
    /// A database volume.
    DatabaseVolume,
}

impl ResourceKind {
    /// Every declared kind, in canonical order.
    pub const ALL: [Self; 4] = [
        Self::StatefulService,
        Self::Port,
        Self::Fixture,
        Self::DatabaseVolume,
    ];

    /// Stable lease-record spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StatefulService => "stateful_service",
            Self::Port => "port",
            Self::Fixture => "fixture",
            Self::DatabaseVolume => "database_volume",
        }
    }
}

/// One exclusive runtime resource a test group requires.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceClaim {
    /// Claimed resource class.
    pub kind: ResourceKind,
    /// Declared resource name, unique within one job's claim set.
    pub name: String,
}

/// A declared resource name was blank, control-bearing, or whitespace-padded.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("resource claim {field}: {reason}")]
pub struct InvalidResourceClaim {
    /// Offending field.
    pub field: &'static str,
    /// Why the declaration is refused.
    pub reason: &'static str,
}

impl ResourceClaim {
    /// Validates the declared name.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidResourceClaim`] when the name is blank, carries
    /// control characters, or has surrounding whitespace, so two claims of one
    /// resource can never differ only by spelling.
    pub fn validate(&self) -> Result<(), InvalidResourceClaim> {
        let trimmed = self.name.trim();
        if trimmed.is_empty() || trimmed.chars().any(char::is_control) || trimmed != self.name {
            return Err(InvalidResourceClaim {
                field: "resource.name",
                reason: "must be non-blank, control-free, and free of surrounding whitespace",
            });
        }
        Ok(())
    }
}

/// Closed table of declared resource weights. The order is light to heavy.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceWeight {
    /// Default and background weight.
    #[default]
    Light,
    /// Ordinary test weight.
    Moderate,
    /// Weight for a group that saturates a constrained lane.
    Heavy,
}

impl ResourceWeight {
    /// The weight as a number, for weight sums in a lane budget.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Light => 1,
            Self::Moderate => 2,
            Self::Heavy => 3,
        }
    }
}
