//! Owner-neutral canonical context projections (CC-004).
//!
//! This module owns the versioned task, continuity, safety, and affordance
//! projections consumed mechanically by `eliot-context-candidates`. Each
//! projection carries its own [`ContextBinding`] (exact `WorkScopeId` plus
//! [`StateFence`]); a [`CanonicalProjectionSet`] bundles the four under one
//! shared binding with explicit [`OmissionRecord`] coverage.
//!
//! The mapper never retrieves canonical state and never invents missing role
//! prose: a missing or incompatible projection stays an explicit omission,
//! never filler. All projections in one set must share a compatible fence via
//! [`StateFence::is_compatible_with`]; any drift fails closed.

#![forbid(unsafe_code)]

use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContextBinding, ContextError, OmissionRecord, validate_text};

/// Exact schema version accepted by the projection shapes.
pub const CANONICAL_PROJECTIONS_SCHEMA_VERSION: u32 = 1;
/// Maximum entries carried by one repeated projection field.
pub const MAX_PROJECTION_ENTRIES: usize = 64;
/// Maximum bytes of one projection text field.
pub const MAX_PROJECTION_TEXT: usize = 1024;
/// Maximum omission records carried by one set.
pub const MAX_SET_OMISSIONS: usize = 64;

fn check_version(version: u32) -> Result<(), ContextError> {
    if version != CANONICAL_PROJECTIONS_SCHEMA_VERSION {
        return Err(ContextError::InvalidField("projections.schema_version"));
    }
    Ok(())
}

fn check_entries(values: &[String], field: &'static str) -> Result<(), ContextError> {
    if values.len() > MAX_PROJECTION_ENTRIES {
        return Err(ContextError::Bounds { field });
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        validate_text(value, field)?;
        if value.len() > MAX_PROJECTION_TEXT {
            return Err(ContextError::Bounds { field });
        }
        if !seen.insert(value.clone()) {
            return Err(ContextError::Duplicate(field));
        }
    }
    Ok(())
}

fn check_note(value: &str, field: &'static str) -> Result<(), ContextError> {
    validate_text(value, field)?;
    if value.len() > MAX_PROJECTION_TEXT {
        return Err(ContextError::Bounds { field });
    }
    Ok(())
}

/// Versioned task/goal projection: current goal plus exact commitments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskProjection {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Shared task/scope/fence/decision identity.
    pub binding: ContextBinding,
    /// Current goal text, non-blank, at most 1024 bytes.
    pub goal: String,
    /// Exact current commitments, each non-blank, at most 64 entries.
    pub commitments: Vec<String>,
}

impl TaskProjection {
    /// Validates intrinsic bounds without retrieving any canonical state.
    pub fn validate(&self) -> Result<(), ContextError> {
        check_version(self.schema_version)?;
        self.binding.validate()?;
        check_note(&self.goal, "task.goal")?;
        check_entries(&self.commitments, "task.commitments")?;
        Ok(())
    }
}

/// Versioned continuity/plan projection: current plan state plus a note.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContinuityProjection {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Shared task/scope/fence/decision identity.
    pub binding: ContextBinding,
    /// Current plan state text, non-blank, at most 1024 bytes.
    pub plan_state: String,
    /// Continuity note (open work, resume edge), non-blank.
    pub continuity_note: String,
}

impl ContinuityProjection {
    /// Validates intrinsic bounds without retrieving any canonical state.
    pub fn validate(&self) -> Result<(), ContextError> {
        check_version(self.schema_version)?;
        self.binding.validate()?;
        check_note(&self.plan_state, "continuity.plan_state")?;
        check_note(&self.continuity_note, "continuity.continuity_note")?;
        Ok(())
    }
}

/// Versioned safety projection with exact negative-memory triggers.
///
/// `negative_memory_triggers` are the exact trigger identities supplied by
/// the Governor owner (cue/negative triggers, blocked reasons). They are
/// copied verbatim; this contract never invents trigger prose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SafetyProjection {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Shared task/scope/fence/decision identity.
    pub binding: ContextBinding,
    /// Safety note, non-blank, at most 1024 bytes.
    pub safety_note: String,
    /// Exact negative-memory trigger identities, at most 64 entries.
    pub negative_memory_triggers: Vec<String>,
}

impl SafetyProjection {
    /// Validates intrinsic bounds without retrieving any canonical state.
    pub fn validate(&self) -> Result<(), ContextError> {
        check_version(self.schema_version)?;
        self.binding.validate()?;
        check_note(&self.safety_note, "safety.safety_note")?;
        check_entries(
            &self.negative_memory_triggers,
            "safety.negative_memory_triggers",
        )?;
        Ok(())
    }
}

/// Versioned affordance projection: authorized capabilities only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AffordanceProjection {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Shared task/scope/fence/decision identity.
    pub binding: ContextBinding,
    /// Authorized affordance identities, each non-blank, at most 64 entries.
    pub affordances: Vec<String>,
}

impl AffordanceProjection {
    /// Validates intrinsic bounds without retrieving any canonical state.
    pub fn validate(&self) -> Result<(), ContextError> {
        check_version(self.schema_version)?;
        self.binding.validate()?;
        if self.affordances.is_empty() {
            return Err(ContextError::MissingField("affordance.affordances"));
        }
        check_entries(&self.affordances, "affordance.affordances")?;
        Ok(())
    }
}

/// One set of the four canonical projections under a shared binding.
///
/// Consumers replace provider implementations behind this shape: the set is
/// versioned and owner-neutral, so a new task, safety, or affordance owner
/// can resupply the same four projections without rebuilding Smart
/// consumers, as long as the binding and fence gate still hold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanonicalProjectionSet {
    /// Shared task/scope/fence/decision identity every member must match.
    pub binding: ContextBinding,
    /// Current task/goal projection.
    pub task: TaskProjection,
    /// Current continuity/plan projection.
    pub continuity: ContinuityProjection,
    /// Current safety plus exact negative-memory triggers.
    pub safety: SafetyProjection,
    /// Current authorized affordances.
    pub affordance: AffordanceProjection,
    /// Explicit omissions/incomplete coverage for this set.
    pub omissions: Vec<OmissionRecord>,
}

impl CanonicalProjectionSet {
    /// Returns whether one fence can share this set's decision scope.
    ///
    /// This is the `is_compatible_with` gate: a projection built under a
    /// different epoch, generation, or revision is not silently absorbed.
    #[must_use]
    pub fn is_compatible_with(&self, fence: &StateFence) -> bool {
        self.binding.state_fence.is_compatible_with(fence)
    }

    /// Validates the full set: every member, the shared binding, one fence,
    /// and explicit omission coverage.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.task.validate()?;
        self.continuity.validate()?;
        self.safety.validate()?;
        self.affordance.validate()?;
        for projection_binding in [
            &self.task.binding,
            &self.continuity.binding,
            &self.safety.binding,
            &self.affordance.binding,
        ] {
            if projection_binding != &self.binding {
                return Err(ContextError::InvalidFence);
            }
            if !projection_binding
                .state_fence
                .is_compatible_with(&self.binding.state_fence)
                || !self
                    .binding
                    .state_fence
                    .is_compatible_with(&projection_binding.state_fence)
            {
                return Err(ContextError::InvalidFence);
            }
        }
        if self.omissions.len() > MAX_SET_OMISSIONS {
            return Err(ContextError::Bounds {
                field: "projections.omissions",
            });
        }
        for omission in &self.omissions {
            omission.validate(&self.binding)?;
        }
        Ok(())
    }
}
