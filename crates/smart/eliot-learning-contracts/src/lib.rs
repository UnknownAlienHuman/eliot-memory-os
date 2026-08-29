//! Immutable System Experience projection contracts.
//!
//! This crate owns no task or attempt lifecycle, scheduler, evaluator,
//! canonical writer, provider route, authority, or learning promotion.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use eliot_contracts::{
    ArtifactId, ContractError, ContractVersion, RequestId, StateFence, TaskId, TaskRevision,
    canonical_json_bytes, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.smart.learning-contracts";
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

const MAX_ATTEMPTS: usize = 4_096;
const MAX_HANDLES: usize = 512;
const MAX_TEXT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LearningContractError {
    #[error("foundation contract: {0}")]
    Foundation(#[from] ContractError),
    #[error("{field} must be non-blank, bounded, and free of control characters")]
    InvalidText { field: &'static str },
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} exceeds limit {limit}")]
    LimitExceeded { field: &'static str, limit: usize },
    #[error("duplicate identity or evidence {0}")]
    Duplicate(String),
    #[error("experience values use incompatible state fences")]
    FenceMismatch,
    #[error("task, campaign, or attempt binding does not match")]
    TaskBindingMismatch,
    #[error("owner coverage invariant failed: {0}")]
    CoverageInvalid(&'static str),
    #[error("outcome attribution invariant failed: {0}")]
    AttributionInvalid(&'static str),
    #[error("digest mismatch for {field}")]
    DigestMismatch { field: &'static str },
    #[error("cannot canonicalize contract value: {0}")]
    Canonicalization(String),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), LearningContractError> {
    if value.trim().is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(LearningContractError::InvalidText { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), LearningContractError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(LearningContractError::InvalidDigest { field });
    }
    Ok(())
}

fn validate_unique_handles(
    values: &[ArtifactId],
    field: &'static str,
) -> Result<(), LearningContractError> {
    if values.len() > MAX_HANDLES {
        return Err(LearningContractError::LimitExceeded {
            field,
            limit: MAX_HANDLES,
        });
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.as_str()) {
            return Err(LearningContractError::Duplicate(value.to_string()));
        }
    }
    Ok(())
}

fn validate_unique_text(
    values: &[String],
    field: &'static str,
) -> Result<(), LearningContractError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(value, field)?;
        if !seen.insert(value.as_str()) {
            return Err(LearningContractError::Duplicate(value.clone()));
        }
    }
    Ok(())
}

#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct CampaignId(String);

impl CampaignId {
    pub fn new(value: impl Into<String>) -> Result<Self, LearningContractError> {
        let value = value.into();
        validate_text(&value, "campaign_id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CampaignId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct AttemptId(String);

impl AttemptId {
    pub fn new(value: impl Into<String>) -> Result<Self, LearningContractError> {
        let value = value.into();
        validate_text(&value, "attempt_id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperienceIdentity {
    pub campaign_id: CampaignId,
    pub current_attempt_id: AttemptId,
    pub task_id: TaskId,
    pub task_revision: TaskRevision,
    pub state_fence: StateFence,
}

impl ExperienceIdentity {
    pub fn validate(&self) -> Result<(), LearningContractError> {
        validate_text(self.campaign_id.as_str(), "identity.campaign_id")?;
        validate_text(
            self.current_attempt_id.as_str(),
            "identity.current_attempt_id",
        )?;
        self.state_fence.validate()?;
        if self.state_fence.task_revision.is_some()
            && self.state_fence.task_revision != Some(self.task_revision)
        {
            return Err(LearningContractError::TaskBindingMismatch);
        }
        Ok(())
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExperienceOwnerKind {
    Task,
    Attempt,
    Trace,
    Artifact,
    Evaluator,
    Effect,
}

const REQUIRED_OWNERS: [ExperienceOwnerKind; 6] = [
    ExperienceOwnerKind::Task,
    ExperienceOwnerKind::Attempt,
    ExperienceOwnerKind::Trace,
    ExperienceOwnerKind::Artifact,
    ExperienceOwnerKind::Evaluator,
    ExperienceOwnerKind::Effect,
];

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExperienceCoverageState {
    NotQueried,
    Unavailable,
    Partial,
    Complete,
    Stale,
    Blocked,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperienceCoverage {
    pub owner: ExperienceOwnerKind,
    pub state: ExperienceCoverageState,
    pub revision: Option<String>,
    pub projection_handle: Option<ArtifactId>,
    pub observed_items: u32,
    pub expected_items: Option<u32>,
    pub missing_refs: Vec<String>,
}

impl ExperienceCoverage {
    pub fn validate(&self) -> Result<(), LearningContractError> {
        validate_unique_text(&self.missing_refs, "coverage.missing_refs")?;
        if let Some(revision) = self.revision.as_deref() {
            validate_text(revision, "coverage.revision")?;
        }
        match self.state {
            ExperienceCoverageState::Complete => {
                if self.revision.is_none()
                    || self.projection_handle.is_none()
                    || !self.missing_refs.is_empty()
                    || self
                        .expected_items
                        .is_some_and(|expected| expected != self.observed_items)
                {
                    return Err(LearningContractError::CoverageInvalid(
                        "complete owner has incomplete identity or count",
                    ));
                }
            }
            ExperienceCoverageState::Partial => {
                if self.revision.is_none()
                    || self.projection_handle.is_none()
                    || self.missing_refs.is_empty()
                    || self
                        .expected_items
                        .is_some_and(|expected| expected < self.observed_items)
                {
                    return Err(LearningContractError::CoverageInvalid(
                        "partial owner lacks missing-set evidence",
                    ));
                }
            }
            ExperienceCoverageState::Stale => {
                if self.revision.is_none() || self.projection_handle.is_none() {
                    return Err(LearningContractError::CoverageInvalid(
                        "stale owner requires retained revision and handle",
                    ));
                }
            }
            ExperienceCoverageState::NotQueried
            | ExperienceCoverageState::Unavailable
            | ExperienceCoverageState::Blocked => {
                if self.projection_handle.is_some() || self.observed_items != 0 {
                    return Err(LearningContractError::CoverageInvalid(
                        "unavailable owner cannot claim current items",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutcomeStatus {
    Succeeded,
    Failed,
    Partial,
    Unknown,
}

/// Sequence, association, supported contribution, and intervention stay distinct.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutcomeAttribution {
    ObservedSequence,
    ObservedAssociation,
    SupportedContribution,
    ObservedUnderIntervention,
    CompositeBenefit,
    Contradicted,
    Unknown,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedOutcome {
    pub outcome_id: String,
    pub status: OutcomeStatus,
    pub attribution: OutcomeAttribution,
    pub evidence_handles: Vec<ArtifactId>,
    pub observed_delta: String,
}

impl ObservedOutcome {
    pub fn validate(&self) -> Result<(), LearningContractError> {
        validate_text(&self.outcome_id, "outcome.outcome_id")?;
        validate_text(&self.observed_delta, "outcome.observed_delta")?;
        validate_unique_handles(&self.evidence_handles, "outcome.evidence_handles")?;
        if self.status != OutcomeStatus::Unknown && self.evidence_handles.is_empty() {
            return Err(LearningContractError::AttributionInvalid(
                "known outcome requires evidence",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptExperience {
    pub attempt_id: AttemptId,
    pub sequence_index: u32,
    pub strategy: String,
    pub hypothesis_handle: Option<ArtifactId>,
    pub trace_handles: Vec<ArtifactId>,
    pub artifact_handles: Vec<ArtifactId>,
    pub evaluator_handles: Vec<ArtifactId>,
    pub effect_handles: Vec<ArtifactId>,
    pub outcome: ObservedOutcome,
}

impl AttemptExperience {
    fn validate(&self) -> Result<(), LearningContractError> {
        validate_text(self.attempt_id.as_str(), "attempt.attempt_id")?;
        validate_text(&self.strategy, "attempt.strategy")?;
        if self.sequence_index == 0 {
            return Err(LearningContractError::CoverageInvalid(
                "attempt sequence starts at one",
            ));
        }
        validate_unique_handles(&self.trace_handles, "attempt.trace_handles")?;
        validate_unique_handles(&self.artifact_handles, "attempt.artifact_handles")?;
        validate_unique_handles(&self.evaluator_handles, "attempt.evaluator_handles")?;
        validate_unique_handles(&self.effect_handles, "attempt.effect_handles")?;
        self.outcome.validate()?;
        if matches!(
            self.outcome.attribution,
            OutcomeAttribution::SupportedContribution
                | OutcomeAttribution::ObservedUnderIntervention
        ) && (self.hypothesis_handle.is_none()
            || self.trace_handles.is_empty()
            || self.effect_handles.is_empty())
        {
            return Err(LearningContractError::AttributionInvalid(
                "mechanism-level attribution needs hypothesis, trace, and effect evidence",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemExperienceProjectionRequest {
    pub request_id: RequestId,
    pub identity: ExperienceIdentity,
    pub expected_owners: Vec<ExperienceOwnerKind>,
    pub state_fence: StateFence,
    pub maximum_attempts: u32,
    pub maximum_evidence_handles_per_attempt: u32,
}

pub fn validate_experience_projection_request(
    request: &SystemExperienceProjectionRequest,
) -> Result<(), LearningContractError> {
    request.identity.validate()?;
    request.state_fence.validate()?;
    if !request
        .identity
        .state_fence
        .is_compatible_with(&request.state_fence)
    {
        return Err(LearningContractError::FenceMismatch);
    }
    let owners: BTreeSet<_> = request.expected_owners.iter().copied().collect();
    if owners.len() != request.expected_owners.len()
        || owners != REQUIRED_OWNERS.into_iter().collect::<BTreeSet<_>>()
    {
        return Err(LearningContractError::CoverageInvalid(
            "request must preserve task/attempt/trace/artifact/evaluator/effect denominator",
        ));
    }
    if request.maximum_attempts == 0 || request.maximum_attempts as usize > MAX_ATTEMPTS {
        return Err(LearningContractError::LimitExceeded {
            field: "request.maximum_attempts",
            limit: MAX_ATTEMPTS,
        });
    }
    if request.maximum_evidence_handles_per_attempt == 0
        || request.maximum_evidence_handles_per_attempt as usize > MAX_HANDLES
    {
        return Err(LearningContractError::LimitExceeded {
            field: "request.maximum_evidence_handles_per_attempt",
            limit: MAX_HANDLES,
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalExperienceReadSnapshot {
    pub request_id: RequestId,
    pub identity: ExperienceIdentity,
    pub state_fence: StateFence,
    pub coverage: Vec<ExperienceCoverage>,
    pub attempts: Vec<AttemptExperience>,
    pub snapshot_sha256: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemExperienceProjection {
    pub source_snapshot_sha256: String,
    pub identity: ExperienceIdentity,
    pub state_fence: StateFence,
    pub coverage: Vec<ExperienceCoverage>,
    pub attempts: Vec<AttemptExperience>,
    pub projection_sha256: String,
}

fn normalize_attempt(attempt: &mut AttemptExperience) {
    attempt.trace_handles.sort();
    attempt.artifact_handles.sort();
    attempt.evaluator_handles.sort();
    attempt.effect_handles.sort();
    attempt.outcome.evidence_handles.sort();
}

pub fn canonical_experience_snapshot_digest(
    snapshot: &CanonicalExperienceReadSnapshot,
) -> Result<String, LearningContractError> {
    let mut normalized = snapshot.clone();
    normalized.snapshot_sha256.clear();
    normalized.coverage.sort_by_key(|coverage| coverage.owner);
    for coverage in &mut normalized.coverage {
        coverage.missing_refs.sort();
    }
    normalized
        .attempts
        .sort_by_key(|attempt| attempt.sequence_index);
    for attempt in &mut normalized.attempts {
        normalize_attempt(attempt);
    }
    let bytes = canonical_json_bytes(&normalized)
        .map_err(|error| LearningContractError::Canonicalization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn system_experience_projection_digest(
    projection: &SystemExperienceProjection,
) -> Result<String, LearningContractError> {
    let mut normalized = projection.clone();
    normalized.projection_sha256.clear();
    normalized.coverage.sort_by_key(|coverage| coverage.owner);
    for coverage in &mut normalized.coverage {
        coverage.missing_refs.sort();
    }
    normalized
        .attempts
        .sort_by_key(|attempt| attempt.sequence_index);
    for attempt in &mut normalized.attempts {
        normalize_attempt(attempt);
    }
    let bytes = canonical_json_bytes(&normalized)
        .map_err(|error| LearningContractError::Canonicalization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn validate_body(
    identity: &ExperienceIdentity,
    state_fence: &StateFence,
    coverage: &[ExperienceCoverage],
    attempts: &[AttemptExperience],
) -> Result<(), LearningContractError> {
    identity.validate()?;
    state_fence.validate()?;
    if !identity.state_fence.is_compatible_with(state_fence) {
        return Err(LearningContractError::FenceMismatch);
    }
    if coverage.len() != REQUIRED_OWNERS.len() {
        return Err(LearningContractError::CoverageInvalid(
            "projection requires one row per expected owner",
        ));
    }
    let mut owners = BTreeSet::new();
    for item in coverage {
        item.validate()?;
        if !owners.insert(item.owner) {
            return Err(LearningContractError::Duplicate(format!(
                "coverage:{:?}",
                item.owner
            )));
        }
    }
    for owner in REQUIRED_OWNERS {
        if !owners.contains(&owner) {
            return Err(LearningContractError::CoverageInvalid(
                "projection omits an expected owner",
            ));
        }
    }
    if attempts.len() > MAX_ATTEMPTS {
        return Err(LearningContractError::LimitExceeded {
            field: "projection.attempts",
            limit: MAX_ATTEMPTS,
        });
    }
    let mut ids = BTreeSet::new();
    let mut sequences = BTreeSet::new();
    for attempt in attempts {
        attempt.validate()?;
        if !ids.insert(attempt.attempt_id.as_str()) {
            return Err(LearningContractError::Duplicate(
                attempt.attempt_id.to_string(),
            ));
        }
        if !sequences.insert(attempt.sequence_index) {
            return Err(LearningContractError::Duplicate(format!(
                "sequence:{}",
                attempt.sequence_index
            )));
        }
    }
    let attempt_owner_complete = coverage.iter().any(|item| {
        item.owner == ExperienceOwnerKind::Attempt
            && item.state == ExperienceCoverageState::Complete
    });
    if attempt_owner_complete && !ids.contains(identity.current_attempt_id.as_str()) {
        return Err(LearningContractError::TaskBindingMismatch);
    }
    Ok(())
}

pub fn validate_canonical_experience_read_snapshot(
    snapshot: &CanonicalExperienceReadSnapshot,
) -> Result<(), LearningContractError> {
    validate_digest(&snapshot.snapshot_sha256, "snapshot.snapshot_sha256")?;
    validate_body(
        &snapshot.identity,
        &snapshot.state_fence,
        &snapshot.coverage,
        &snapshot.attempts,
    )?;
    if canonical_experience_snapshot_digest(snapshot)? != snapshot.snapshot_sha256 {
        return Err(LearningContractError::DigestMismatch {
            field: "snapshot.snapshot_sha256",
        });
    }
    Ok(())
}

pub fn validate_system_experience_projection(
    projection: &SystemExperienceProjection,
) -> Result<(), LearningContractError> {
    validate_digest(
        &projection.source_snapshot_sha256,
        "projection.source_snapshot_sha256",
    )?;
    validate_digest(
        &projection.projection_sha256,
        "projection.projection_sha256",
    )?;
    validate_body(
        &projection.identity,
        &projection.state_fence,
        &projection.coverage,
        &projection.attempts,
    )?;
    if system_experience_projection_digest(projection)? != projection.projection_sha256 {
        return Err(LearningContractError::DigestMismatch {
            field: "projection.projection_sha256",
        });
    }
    Ok(())
}
