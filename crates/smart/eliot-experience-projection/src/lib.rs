//! Immutable System Experience projection (#223).
//!
//! [`ExperienceProjectionView`] carries Governor-owned experience evidence
//! as handle-bound refs under one scope and one fence, with an exact
//! declared/observed/omitted denominator. The view transports references
//! only: no record body is carried or rewritten, no bank or journal is
//! owned, and no lifecycle transition is performed.
//!
//! The typed `SystemObservationJournal`, `EliotSystemExperienceBank`, and
//! `AgentFeedbackReceipt` projections stay `NOT_FROZEN` in
//! `crates/smart/cognitive-rev12-contract-schema-freeze.toml` and are never
//! invented here. The retired `eliot-system-experience` duplicate is reused
//! by reference only: this crate creates no second self-memory owner,
//! relation store, or lifecycle transition path.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, StateFence};
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Freeze identity this package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22";

/// Hard ceiling on evidence refs carried by one view.
pub const MAX_EXPERIENCE_REFS: usize = 256;
/// Hard ceiling on omission entries carried by one view.
pub const MAX_EXPERIENCE_OMISSIONS: usize = 256;
/// Maximum Unicode scalar values accepted for one scope identity.
pub const MAX_SCOPE_CHARS: usize = 256;

/// Experience-projection failure: every case fails closed with its reason.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExperienceError {
    /// An identity or fence shape is invalid.
    #[error("experience projection: invalid field {field}: {reason}")]
    InvalidField {
        /// Field at fault.
        field: &'static str,
        /// Why it is invalid.
        reason: &'static str,
    },
    /// The declared denominator contradicts the accounted volume.
    #[error("experience projection: declared {declared} contradicts observed {observed} plus omitted {omitted}")]
    DenominatorContradiction {
        /// Declared evidence total.
        declared: usize,
        /// Refs actually carried.
        observed: usize,
        /// Omissions actually named.
        omitted: usize,
    },
    /// One handle appears twice in the same view.
    #[error("experience projection: duplicate handle {handle}")]
    DuplicateHandle {
        /// Repeated handle text.
        handle: String,
    },
    /// A bound on refs, omissions, or scope text is exceeded.
    #[error("experience projection: out of bounds: {field}")]
    Bounds {
        /// Field at fault.
        field: &'static str,
    },
}

fn text(value: &str, field: &'static str) -> Result<(), ExperienceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ExperienceError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

/// Which Governor-owned evidence family a ref points at.
///
/// These are ref labels only. They do not define the typed journal, bank, or
/// feedback projection schemas; those stay `NOT_FROZEN` upstream.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExperienceEvidenceKind {
    /// System observation journal entry, by handle.
    SystemObservation,
    /// System experience bank record, by handle.
    ExperienceBankRecord,
    /// Agent feedback receipt, by handle.
    AgentFeedback,
}

/// One handle-bound experience evidence ref.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExperienceEvidenceRef {
    /// Exact canonical handle of the evidence.
    pub handle: ArtifactId,
    /// Which evidence family the handle names.
    pub kind: ExperienceEvidenceKind,
}

impl ExperienceEvidenceRef {
    /// Validate the ref shape.
    pub fn validate(&self) -> Result<(), ExperienceError> {
        text(self.handle.as_str(), "evidence_ref.handle")
    }
}

/// One explicitly omitted evidence item: handle plus the rule that omitted it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExperienceOmission {
    /// Handle of the omitted evidence.
    pub handle: ArtifactId,
    /// Stable bounded reason class for the omission.
    pub reason: String,
}

impl ExperienceOmission {
    /// Validate the omission shape.
    pub fn validate(&self) -> Result<(), ExperienceError> {
        text(&self.reason, "experience_omission.reason")
    }
}

/// Immutable handle-bound experience projection view.
///
/// `declared_total` is the exact evidence volume the supplying owner counted
/// at the named fence; it must equal carried refs plus named omissions.
/// Omissions are never silent loss.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExperienceProjectionView {
    /// Exact work scope the evidence was counted under.
    pub scope_id: WorkScopeId,
    /// Fence the evidence was counted under.
    pub state_fence: StateFence,
    /// Evidence refs in deterministic supply order.
    pub refs: Vec<ExperienceEvidenceRef>,
    /// Exact evidence volume declared by the supplying owner.
    pub declared_total: usize,
    /// Named omissions with exact reasons.
    pub omissions: Vec<ExperienceOmission>,
}

impl ExperienceProjectionView {
    /// Assemble a validated view.
    pub fn assemble(
        scope_id: WorkScopeId,
        state_fence: StateFence,
        refs: Vec<ExperienceEvidenceRef>,
        declared_total: usize,
        omissions: Vec<ExperienceOmission>,
    ) -> Result<Self, ExperienceError> {
        let view = Self {
            scope_id,
            state_fence,
            refs,
            declared_total,
            omissions,
        };
        view.validate()?;
        Ok(view)
    }

    /// Validate scope shape, fence, handle uniqueness, bounds, and the exact
    /// declared/observed/omitted denominator.
    pub fn validate(&self) -> Result<(), ExperienceError> {
        if self.scope_id.as_str().chars().count() > MAX_SCOPE_CHARS {
            return Err(ExperienceError::Bounds {
                field: "view.scope_id",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| ExperienceError::InvalidField {
                field: "view.state_fence",
                reason: "fence interval is invalid",
            })?;
        if self.refs.len() > MAX_EXPERIENCE_REFS {
            return Err(ExperienceError::Bounds { field: "view.refs" });
        }
        if self.omissions.len() > MAX_EXPERIENCE_OMISSIONS {
            return Err(ExperienceError::Bounds {
                field: "view.omissions",
            });
        }
        let mut seen = BTreeSet::new();
        for item in &self.refs {
            item.validate()?;
            if !seen.insert(item.handle.as_str().to_owned()) {
                return Err(ExperienceError::DuplicateHandle {
                    handle: item.handle.as_str().to_owned(),
                });
            }
        }
        for omission in &self.omissions {
            omission.validate()?;
            if !seen.insert(omission.handle.as_str().to_owned()) {
                return Err(ExperienceError::DuplicateHandle {
                    handle: omission.handle.as_str().to_owned(),
                });
            }
        }
        if self.declared_total != self.refs.len() + self.omissions.len() {
            return Err(ExperienceError::DenominatorContradiction {
                declared: self.declared_total,
                observed: self.refs.len(),
                omitted: self.omissions.len(),
            });
        }
        Ok(())
    }

    /// Handles of one evidence family, in supply order.
    #[must_use]
    pub fn handles_of(&self, kind: ExperienceEvidenceKind) -> Vec<&ArtifactId> {
        self.refs
            .iter()
            .filter(|item| item.kind == kind)
            .map(|item| &item.handle)
            .collect()
    }
}
