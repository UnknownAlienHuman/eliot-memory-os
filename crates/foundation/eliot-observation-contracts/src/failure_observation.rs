//! Versioned owner-neutral failure-observation and revision-evidence contracts.
//!
//! [`FailureObservation`] closes `CC-FAILURE-OBSERVATION-SCHEMA`: one exact
//! failure memory (trigger, failed action, outcome, violated invariant, scope,
//! reopen and extinction conditions per A14.3) projected from Governor journal
//! records by handle, with complete denominator, fence, scope, and omission
//! semantics. [`MemoryRevisionEvidence`] closes the revision side of
//! `CC-W9-MEMORY-REVISION`: post-dating evidence refs bearing on one
//! observation, with the same closure semantics.
//!
//! Placement: the wave briefs name the Governor canonical observation owner
//! as producer and no separate failure-observation crate, so this module is
//! the projection-schema owner beside `experience::projection`: it reuses this
//! crate's [`ObservationScope`], [`SourceRevisionHandle`],
//! [`CoverageEvidence`], handle, and fence vocabulary, and cites Governor
//! journal records by handle only. Live admission, enumeration, and rebuild
//! stay with `eliot-observation`; this module performs no admission,
//! retrieval, ranking, or promotion.
//!
//! Completeness doctrine, enforced below: observed volume arrives as owner
//! [`CoverageEvidence`] (disposition, denominator source ref, coverage digest
//! lineage, observed count, blind intervals), never as caller arithmetic.
//! Downstream `Complete` verdicts additionally require the owner `Complete`
//! disposition with empty blind intervals. Anything else is an explicit
//! partial read. Omissions use the closed [`FailureOmissionClass`];
//! free-form reason strings cannot cross this boundary.
//!
//! Fences are carried, not gated: each shape freezes the fence it was read
//! under, and consumers gate compatibility at their edge. Record-level fence
//! recovery stays a live-owner capability.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ContractVersion, StateFence, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    CONTRACT_VERSION, CoverageDisposition, CoverageEvidence, ObservationError, ObservationScope,
    SourceRevisionHandle,
};

/// Maximum journal/evidence handles carried by one shape.
pub const MAX_OBSERVATION_REFS: usize = 256;
/// Maximum omission entries carried by one shape.
pub const MAX_OBSERVATION_OMISSIONS: usize = 64;
/// Maximum characters accepted for one free-text condition or identity field.
pub const MAX_OBSERVATION_TEXT: usize = 1024;

fn text(value: &str, field: &'static str) -> Result<(), ObservationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ObservationError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

fn bounded_text(
    value: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), ObservationError> {
    text(value, field)?;
    if value.chars().count() > max_chars {
        return Err(ObservationError::InvalidField {
            field,
            reason: "exceeds bounded length",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), ObservationError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ObservationError::InvalidField {
            field,
            reason: "must be lowercase SHA-256 hex",
        });
    }
    Ok(())
}

fn id(value: &ArtifactId, field: &'static str) -> Result<(), ObservationError> {
    bounded_text(value.as_str(), field, MAX_OBSERVATION_TEXT)
}

fn fence_shape(value: &StateFence, field: &'static str) -> Result<(), ObservationError> {
    value
        .validate()
        .map_err(|_| ObservationError::InvalidField {
            field,
            reason: "fence interval is invalid",
        })
}

/// Closed omission classes for failure-observation reads.
///
/// A blind journal interval, a superseded revision cursor, a privacy
/// withholding, an expired cursor, or an unadmitted source each stays an
/// explicit omission; silent loss is never representable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureOmissionClass {
    JournalBlind,
    SupersededRevision,
    PrivacyWithheld,
    ExpiredCursor,
    UnadmittedSource,
}

/// One explicit omission in a failure-observation read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureOmission {
    /// Affected record handle, when the omission names one.
    pub handle: Option<ArtifactId>,
    /// Closed omission class.
    pub class: FailureOmissionClass,
    /// Bounded note naming what is missing.
    pub note: String,
}

impl FailureOmission {
    /// Validate the omission class, handle, and note.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if let Some(handle) = &self.handle {
            id(handle, "omission.handle")?;
        }
        bounded_text(&self.note, "omission.note", MAX_OBSERVATION_TEXT)
    }
}

/// Owner-neutral failure observation (CC-FAILURE-OBSERVATION-SCHEMA).
///
/// One exact failure memory: trigger, failed action, outcome, violated
/// invariant, scope, reopen condition, and extinction condition (A14.3),
/// projected from Governor journal records cited by handle at one revision
/// cursor under one fence. The original episode stays with the owner; this
/// shape narrows nothing and deletes nothing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureObservation {
    /// Exact contract version; must equal [`CONTRACT_VERSION`].
    pub contract_version: ContractVersion,
    /// Stable observation identity.
    pub observation_id: ArtifactId,
    /// Exact failure fingerprint identity (trigger, action, and outcome
    /// identity as admitted by the owner).
    pub fingerprint: String,
    /// Exact deterministic trigger identity.
    pub trigger: String,
    /// Failed action identity.
    pub failed_action: String,
    /// Observed outcome identity.
    pub outcome: String,
    /// Violated invariant identity.
    pub violated_invariant: String,
    /// Scope the failure was observed in.
    pub scope: ObservationScope,
    /// Fence the observation was read under, carried for edge gating.
    pub state_fence: StateFence,
    /// Governor journal record handles this observation projects, in
    /// deterministic supply order, unique.
    pub journal_refs: Vec<ArtifactId>,
    /// Revision cursor the observation was read at.
    pub journal_revision: SourceRevisionHandle,
    /// Owner coverage evidence for the read.
    pub coverage: CoverageEvidence,
    /// Reopen condition identity.
    pub reopen_condition: String,
    /// Extinction condition identity.
    pub extinction_condition: String,
    /// Explicit omissions in closed classes.
    pub omissions: Vec<FailureOmission>,
    /// Frozen digest over the observation shape, excluding this field.
    pub digest: String,
}

impl FailureObservation {
    /// Compute the frozen digest over the observation shape.
    pub fn compute_digest(&self) -> Result<String, ObservationError> {
        if self.journal_refs.len() > MAX_OBSERVATION_REFS {
            return Err(ObservationError::InvalidField {
                field: "observation.journal_refs",
                reason: "exceeds bounded ref count",
            });
        }
        canonical_json_bytes(&(
            &self.contract_version,
            &self.observation_id,
            &self.fingerprint,
            &self.trigger,
            &self.failed_action,
            &self.outcome,
            &self.violated_invariant,
            &self.scope,
            &self.state_fence,
            &self.journal_refs,
            &self.journal_revision,
            &self.coverage,
            &self.reopen_condition,
            &self.extinction_condition,
            &self.omissions,
        ))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ObservationError::InvalidField {
            field: "observation.digest",
            reason: "observation is not canonically encodable",
        })
    }

    /// Validate identity, A14.3 fields, scope, fence, refs, revision,
    /// coverage, omissions, and the frozen digest.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ObservationError::InvalidField {
                field: "observation.contract_version",
                reason: "contract version mismatch",
            });
        }
        id(&self.observation_id, "observation.observation_id")?;
        bounded_text(
            &self.fingerprint,
            "observation.fingerprint",
            MAX_OBSERVATION_TEXT,
        )?;
        bounded_text(&self.trigger, "observation.trigger", MAX_OBSERVATION_TEXT)?;
        bounded_text(
            &self.failed_action,
            "observation.failed_action",
            MAX_OBSERVATION_TEXT,
        )?;
        bounded_text(&self.outcome, "observation.outcome", MAX_OBSERVATION_TEXT)?;
        bounded_text(
            &self.violated_invariant,
            "observation.violated_invariant",
            MAX_OBSERVATION_TEXT,
        )?;
        self.scope.validate()?;
        fence_shape(&self.state_fence, "observation.state_fence")?;
        if self.journal_refs.len() > MAX_OBSERVATION_REFS {
            return Err(ObservationError::InvalidField {
                field: "observation.journal_refs",
                reason: "exceeds bounded ref count",
            });
        }
        let mut seen = BTreeSet::new();
        for handle in &self.journal_refs {
            id(handle, "observation.journal_refs")?;
            if !seen.insert(handle) {
                return Err(ObservationError::Duplicate {
                    field: "observation.journal_refs",
                    value: handle.to_string(),
                });
            }
        }
        self.journal_revision.validate()?;
        self.coverage.validate()?;
        bounded_text(
            &self.reopen_condition,
            "observation.reopen_condition",
            MAX_OBSERVATION_TEXT,
        )?;
        bounded_text(
            &self.extinction_condition,
            "observation.extinction_condition",
            MAX_OBSERVATION_TEXT,
        )?;
        if self.omissions.len() > MAX_OBSERVATION_OMISSIONS {
            return Err(ObservationError::InvalidField {
                field: "observation.omissions",
                reason: "exceeds bounded omission count",
            });
        }
        for omission in &self.omissions {
            omission.validate()?;
        }
        digest(&self.digest, "observation.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ObservationError::InvalidField {
                field: "observation.digest",
                reason: "digest does not match the observation",
            });
        }
        Ok(())
    }

    /// Owner coverage is `Complete` with no blind intervals.
    ///
    /// Downstream `Complete` verdicts require this; anything else is an
    /// explicit partial read.
    #[must_use]
    pub fn coverage_complete(&self) -> bool {
        self.coverage.disposition == CoverageDisposition::Complete
            && self.coverage.blind_intervals.is_empty()
    }
}

/// Owner-neutral memory-revision evidence (CC-W9-MEMORY-REVISION).
///
/// Post-dating evidence refs bearing on one [`FailureObservation`]: new
/// outcomes or observations the extinction candidate must weigh. Carries the
/// recurrence flag: a recurring failure with the same causal hypothesis
/// yields Mechanism Review rather than another equivalent retry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryRevisionEvidence {
    /// Exact contract version; must equal [`CONTRACT_VERSION`].
    pub contract_version: ContractVersion,
    /// Stable evidence identity.
    pub evidence_id: ArtifactId,
    /// Observation handle this evidence bears on.
    pub observation_ref: ArtifactId,
    /// Post-dating journal or verifier record handles, in deterministic
    /// supply order, unique.
    pub evidence_refs: Vec<ArtifactId>,
    /// Revision cursor the evidence was read at.
    pub evidence_revision: SourceRevisionHandle,
    /// Scope the evidence was observed in.
    pub scope: ObservationScope,
    /// Fence the evidence was read under, carried for edge gating.
    pub state_fence: StateFence,
    /// Owner coverage evidence for the read.
    pub coverage: CoverageEvidence,
    /// True when the failure recurs with the same causal hypothesis.
    pub same_hypothesis_recurrence: bool,
    /// Count of prior extinction attempts over this observation.
    pub prior_attempts: u32,
    /// Explicit omissions in closed classes.
    pub omissions: Vec<FailureOmission>,
    /// Frozen digest over the evidence shape, excluding this field.
    pub digest: String,
}

impl MemoryRevisionEvidence {
    /// Compute the frozen digest over the evidence shape.
    pub fn compute_digest(&self) -> Result<String, ObservationError> {
        if self.evidence_refs.len() > MAX_OBSERVATION_REFS {
            return Err(ObservationError::InvalidField {
                field: "evidence.evidence_refs",
                reason: "exceeds bounded ref count",
            });
        }
        canonical_json_bytes(&(
            &self.contract_version,
            &self.evidence_id,
            &self.observation_ref,
            &self.evidence_refs,
            &self.evidence_revision,
            &self.scope,
            &self.state_fence,
            &self.coverage,
            self.same_hypothesis_recurrence,
            self.prior_attempts,
            &self.omissions,
        ))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ObservationError::InvalidField {
            field: "evidence.digest",
            reason: "evidence is not canonically encodable",
        })
    }

    /// Validate identity, refs, scope, fence, revision, coverage, omissions,
    /// and the frozen digest.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ObservationError::InvalidField {
                field: "evidence.contract_version",
                reason: "contract version mismatch",
            });
        }
        id(&self.evidence_id, "evidence.evidence_id")?;
        id(&self.observation_ref, "evidence.observation_ref")?;
        if self.evidence_refs.len() > MAX_OBSERVATION_REFS {
            return Err(ObservationError::InvalidField {
                field: "evidence.evidence_refs",
                reason: "exceeds bounded ref count",
            });
        }
        let mut seen = BTreeSet::new();
        for handle in &self.evidence_refs {
            id(handle, "evidence.evidence_refs")?;
            if !seen.insert(handle) {
                return Err(ObservationError::Duplicate {
                    field: "evidence.evidence_refs",
                    value: handle.to_string(),
                });
            }
        }
        self.evidence_revision.validate()?;
        self.scope.validate()?;
        fence_shape(&self.state_fence, "evidence.state_fence")?;
        self.coverage.validate()?;
        if self.omissions.len() > MAX_OBSERVATION_OMISSIONS {
            return Err(ObservationError::InvalidField {
                field: "evidence.omissions",
                reason: "exceeds bounded omission count",
            });
        }
        for omission in &self.omissions {
            omission.validate()?;
        }
        digest(&self.digest, "evidence.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ObservationError::InvalidField {
                field: "evidence.digest",
                reason: "digest does not match the evidence",
            });
        }
        Ok(())
    }

    /// Owner coverage is `Complete` with no blind intervals.
    #[must_use]
    pub fn coverage_complete(&self) -> bool {
        self.coverage.disposition == CoverageDisposition::Complete
            && self.coverage.blind_intervals.is_empty()
    }
}
