//! Closed, external-safe Context outcomes and validation errors.

use eliot_contracts::ArtifactId;
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AtomAvailability, ProviderRole};

/// Machine-readable Context failure code. The incomplete wire spelling is
/// deliberately different from generic failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContextErrorCode {
    #[serde(rename = "DECISION_CONTEXT_INCOMPLETE")]
    DecisionContextIncomplete,
    InvalidIdentity,
    DenominatorMismatch,
    StaleSafetyFloor,
    MissingSafetyFloor,
    BlockedSafetyFloor,
    OversizedSafetyFloor,
    PolicyRepresentationMismatch,
    UnknownMeasurement,
    CapacityExceeded,
    OmissionHandleInvalid,
    EconomyMismatch,
    QualityIncomplete,
    SelectionIntegrityMismatch,
    UnsupportedSchema,
    InvalidContract,
}

/// Pure validation failure. Details identify a bounded field, never payload.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContextError {
    /// Required text/field was absent.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// Text or identity was malformed.
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    /// A value exceeded its declared bound.
    #[error("field exceeds its bound: {field}")]
    Bounds { field: &'static str },
    /// Foundation or receipt fence failed validation.
    #[error("invalid State Fence")]
    InvalidFence,
    /// Collection contains a duplicate identity.
    #[error("duplicate identity: {0}")]
    Duplicate(&'static str),
    /// A provider/role denominator is incomplete or has extras.
    #[error("provider/role denominator does not reconcile")]
    DenominatorMismatch,
    /// Canonical identity was reused for changed material.
    #[error("identity content conflict")]
    IdentityConflict,
    /// A non-droppable unit is represented incompletely.
    #[error("whole unit representation required")]
    WholeUnitRequired,
    /// A mandatory floor member is absent.
    #[error("missing mandatory Safety Floor member")]
    MissingFloor,
    /// A mandatory floor member is stale.
    #[error("stale mandatory Safety Floor member")]
    StaleFloor,
    /// A mandatory floor member is blocked.
    #[error("blocked mandatory Safety Floor member")]
    BlockedFloor,
    /// A required floor cannot fit the qualified route.
    #[error("Safety Floor exceeds route capacity")]
    OversizedFloor,
    /// Independent capacity arithmetic overflowed.
    #[error("capacity arithmetic overflow")]
    Overflow,
    /// Capacity components cannot reconcile.
    #[error("capacity components exceed route capacity")]
    CapacityExceeded,
    /// Unknown measurement cannot prove fit.
    #[error("measurement is unknown or unavailable")]
    UnknownMeasurement,
    /// Omission handle does not bind to the decision context.
    #[error("omission handle binding is invalid")]
    OmissionHandleInvalid,
    /// Economy evidence does not conserve material/capacity.
    #[error("context economy receipt does not reconcile")]
    EconomyMismatch,
    /// Quality dimension is missing/unknown.
    #[error("quality scorecard is incomplete")]
    QualityIncomplete,
    /// Rendered and admitted identities differ.
    #[error("selection integrity does not match admitted membership")]
    SelectionIntegrityMismatch,
    /// Canonical digest is malformed.
    #[error("invalid digest: {0}")]
    InvalidDigest(&'static str),
}

/// A provider/role-specific floor gap retaining its canonical slot identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderRoleGap {
    pub slot: ProviderRole,
    pub state: AtomAvailability,
}

impl ProviderRoleGap {
    fn validate(&self) -> Result<(), ContextError> {
        self.slot.validate()?;
        if self.state == AtomAvailability::PresentCurrent {
            return Err(ContextError::InvalidField("provider_gap.state"));
        }
        Ok(())
    }
}

/// First-class incomplete outcome with exact floor gap identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionContextIncomplete {
    /// Exact external code; consumers must branch on this value.
    pub code: ContextErrorCode,
    /// Missing mandatory identities.
    pub missing: Vec<ArtifactId>,
    /// Stale mandatory identities.
    pub stale: Vec<ArtifactId>,
    /// Blocked mandatory identities.
    pub blocked: Vec<ArtifactId>,
    /// Mandatory providers/material that are unavailable.
    pub unavailable: Vec<ArtifactId>,
    /// Mandatory material omitted under an explicit omission policy.
    pub omitted: Vec<ArtifactId>,
    /// Mandatory material whose source was exhausted.
    pub exhausted: Vec<ArtifactId>,
    /// Mandatory material whose state is not known.
    pub unknown: Vec<ArtifactId>,
    /// Mandatory material whose authoritative source is known empty.
    pub known_empty: Vec<ArtifactId>,
    /// Mandatory material with only partial authoritative coverage.
    pub partial: Vec<ArtifactId>,
    /// Provider/role gaps retain the slot instead of manufacturing an atom ID.
    pub provider_gaps: Vec<ProviderRoleGap>,
    /// Oversized identities/allocations.
    pub oversized: Vec<ArtifactId>,
    /// Failed floor rule identity.
    pub failed_floor_rule: ArtifactId,
    /// Measurements that explain the gap.
    pub measurements: Vec<ArtifactId>,
    /// Safe decomposition/reopen/expansion requirements.
    pub reopening_requirements: Vec<String>,
    /// Maximum proof this incomplete result supports.
    pub proof_ceiling: ProofCeiling,
}

impl DecisionContextIncomplete {
    /// Construct the exact incomplete code.
    pub fn new(failed_floor_rule: ArtifactId) -> Self {
        Self {
            code: ContextErrorCode::DecisionContextIncomplete,
            missing: Vec::new(),
            stale: Vec::new(),
            blocked: Vec::new(),
            unavailable: Vec::new(),
            omitted: Vec::new(),
            exhausted: Vec::new(),
            unknown: Vec::new(),
            known_empty: Vec::new(),
            partial: Vec::new(),
            provider_gaps: Vec::new(),
            oversized: Vec::new(),
            failed_floor_rule,
            measurements: Vec::new(),
            reopening_requirements: Vec::new(),
            proof_ceiling: ProofCeiling::Observation,
        }
    }

    /// Validate that this cannot be mistaken for complete success.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.code != ContextErrorCode::DecisionContextIncomplete {
            return Err(ContextError::InvalidField("incomplete.code"));
        }
        if self.missing.is_empty()
            && self.stale.is_empty()
            && self.blocked.is_empty()
            && self.oversized.is_empty()
            && self.unavailable.is_empty()
            && self.omitted.is_empty()
            && self.exhausted.is_empty()
            && self.unknown.is_empty()
            && self.known_empty.is_empty()
            && self.partial.is_empty()
            && self.provider_gaps.is_empty()
        {
            return Err(ContextError::MissingFloor);
        }
        for (field, count) in [
            ("incomplete.missing", self.missing.len()),
            ("incomplete.stale", self.stale.len()),
            ("incomplete.blocked", self.blocked.len()),
            ("incomplete.unavailable", self.unavailable.len()),
            ("incomplete.omitted", self.omitted.len()),
            ("incomplete.exhausted", self.exhausted.len()),
            ("incomplete.unknown", self.unknown.len()),
            ("incomplete.known_empty", self.known_empty.len()),
            ("incomplete.partial", self.partial.len()),
            ("incomplete.provider_gaps", self.provider_gaps.len()),
            ("incomplete.oversized", self.oversized.len()),
            ("incomplete.measurements", self.measurements.len()),
        ] {
            if count > 256 {
                return Err(ContextError::Bounds { field });
            }
        }
        let mut all = std::collections::BTreeSet::new();
        for id in self
            .missing
            .iter()
            .chain(self.stale.iter())
            .chain(self.blocked.iter())
            .chain(self.unavailable.iter())
            .chain(self.omitted.iter())
            .chain(self.exhausted.iter())
            .chain(self.unknown.iter())
            .chain(self.known_empty.iter())
            .chain(self.partial.iter())
        {
            if !all.insert(id.clone()) {
                return Err(ContextError::Duplicate("incomplete.gap_ids"));
            }
        }
        let mut oversized = std::collections::BTreeSet::new();
        for id in &self.oversized {
            if !oversized.insert(id.clone()) {
                return Err(ContextError::Duplicate("incomplete.oversized"));
            }
        }
        let mut provider_gaps = std::collections::BTreeSet::new();
        for gap in &self.provider_gaps {
            gap.validate()?;
            if !provider_gaps.insert(gap.slot.clone()) {
                return Err(ContextError::Duplicate("incomplete.provider_gaps"));
            }
        }
        if self.reopening_requirements.len() > 64 {
            return Err(ContextError::Bounds {
                field: "incomplete.reopening_requirements",
            });
        }
        for requirement in &self.reopening_requirements {
            if requirement.trim().is_empty() {
                return Err(ContextError::InvalidField(
                    "incomplete.reopening_requirements",
                ));
            }
        }
        Ok(())
    }
}

/// Outcome of Context admission; incomplete is a separate sum type variant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum ContextOutcome<T> {
    /// A complete admitted set.
    Complete(T),
    /// A blocked decision floor with exact gaps.
    Incomplete(DecisionContextIncomplete),
}
