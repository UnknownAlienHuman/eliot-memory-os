//! Store-neutral contracts for bounded canonical-memory reads and projections.
//!
//! This crate owns no store, writer, lifecycle transition, policy, scheduler,
//! model route, Context admission, delivery receipt, or external effect.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, ContractError, ContractVersion, OperationId, RequestId, StateFence, TaskId,
    canonical_json_bytes, sha256_hex,
};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.smart.memory-projection-contracts";
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

const MAX_RECORDS: usize = 16_384;
const MAX_CANDIDATES: usize = 4_096;
const MAX_HANDLES: usize = 256;
const MAX_TEXT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MemoryProjectionError {
    #[error("foundation contract: {0}")]
    Foundation(#[from] ContractError),
    #[error("{field} must be non-blank, bounded, and free of control characters")]
    InvalidText { field: &'static str },
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} exceeds limit {limit}")]
    LimitExceeded { field: &'static str, limit: usize },
    #[error("duplicate handle {0}")]
    DuplicateHandle(String),
    #[error("memory projection inputs use incompatible state fences")]
    FenceMismatch,
    #[error("coverage invariant failed: {0}")]
    CoverageInvalid(&'static str),
    #[error("memory dimensions were collapsed: {0}")]
    DimensionCollapsed(&'static str),
    #[error("candidate trace invariant failed: {0}")]
    TraceInvalid(&'static str),
    #[error("digest mismatch for {field}")]
    DigestMismatch { field: &'static str },
    #[error("cannot canonicalize contract value: {0}")]
    Canonicalization(String),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), MemoryProjectionError> {
    if value.trim().is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(MemoryProjectionError::InvalidText { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), MemoryProjectionError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(MemoryProjectionError::InvalidDigest { field });
    }
    Ok(())
}

fn validate_unique_handles(
    values: &[ArtifactId],
    field: &'static str,
) -> Result<(), MemoryProjectionError> {
    if values.len() > MAX_HANDLES {
        return Err(MemoryProjectionError::LimitExceeded {
            field,
            limit: MAX_HANDLES,
        });
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.as_str()) {
            return Err(MemoryProjectionError::DuplicateHandle(value.to_string()));
        }
    }
    Ok(())
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryReadCoverage {
    Complete,
    Partial,
    Unavailable,
    Blocked,
    Stale,
}

impl MemoryReadCoverage {
    const fn searched(self) -> bool {
        matches!(self, Self::Complete | Self::Partial | Self::Stale)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryRecordKind {
    WorkingContinuity,
    Episodic,
    SemanticClaim,
    Procedure,
    Commitment,
    Decision,
    Failure,
    Unknown,
    RivalModel,
    Counterevidence,
    Normative,
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryAccessibility {
    Payload,
    HandleOnly,
    Suppressed,
    Quarantined,
    Unavailable,
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermittedInfluence {
    Candidate,
    WarningOnly,
    ExactNegativeBlockCandidate,
    RequiresRevalidation,
    Denied,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCoverageDenominator {
    pub source_ref: String,
    pub revision: String,
    pub expected_records: Option<u32>,
    pub partitions: Vec<String>,
}

impl MemoryCoverageDenominator {
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        validate_text(&self.source_ref, "denominator.source_ref")?;
        validate_text(&self.revision, "denominator.revision")?;
        let mut seen = BTreeSet::new();
        for partition in &self.partitions {
            validate_text(partition, "denominator.partitions")?;
            if !seen.insert(partition.as_str()) {
                return Err(MemoryProjectionError::CoverageInvalid(
                    "denominator partitions contain duplicates",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalMemoryReadRequest {
    pub request_id: RequestId,
    pub read_operation_id: OperationId,
    pub scope_id: String,
    pub task_id: Option<TaskId>,
    pub canonical_revision: u64,
    pub state_fence: StateFence,
    pub requested_kinds: Vec<MemoryRecordKind>,
    pub maximum_records: u32,
}

impl CanonicalMemoryReadRequest {
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        validate_text(&self.scope_id, "read.scope_id")?;
        self.state_fence.validate()?;
        if self.canonical_revision == 0 {
            return Err(MemoryProjectionError::CoverageInvalid(
                "canonical revision must be nonzero",
            ));
        }
        if self.maximum_records == 0 || self.maximum_records as usize > MAX_RECORDS {
            return Err(MemoryProjectionError::LimitExceeded {
                field: "read.maximum_records",
                limit: MAX_RECORDS,
            });
        }
        let unique: BTreeSet<_> = self.requested_kinds.iter().copied().collect();
        if unique.len() != self.requested_kinds.len() {
            return Err(MemoryProjectionError::CoverageInvalid(
                "requested kinds contain duplicates",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryProjectionRecord {
    pub record_handle: ArtifactId,
    pub payload_handle: Option<ArtifactId>,
    pub kind: MemoryRecordKind,
    pub scope: String,
    pub source_revision: String,
    pub epistemic_status: EpistemicStatus,
    pub lifecycle: LifecycleState,
    pub accessibility: MemoryAccessibility,
    pub permitted_influence: PermittedInfluence,
    pub assertability: Assertability,
    pub provenance_handles: Vec<ArtifactId>,
    pub state_fence: StateFence,
    pub bounded_preview: Option<String>,
    pub negative_memory: bool,
    pub minority_or_counterevidence: bool,
}

impl MemoryProjectionRecord {
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        validate_text(&self.scope, "record.scope")?;
        validate_text(&self.source_revision, "record.source_revision")?;
        self.state_fence.validate()?;
        if self.provenance_handles.is_empty() {
            return Err(MemoryProjectionError::CoverageInvalid(
                "record requires exact provenance",
            ));
        }
        validate_unique_handles(&self.provenance_handles, "record.provenance_handles")?;
        if let Some(preview) = self.bounded_preview.as_deref() {
            validate_text(preview, "record.bounded_preview")?;
        }
        match self.accessibility {
            MemoryAccessibility::Payload => {
                if self.payload_handle.is_none() && self.bounded_preview.is_none() {
                    return Err(MemoryProjectionError::DimensionCollapsed(
                        "payload accessibility requires a payload handle or preview",
                    ));
                }
            }
            MemoryAccessibility::HandleOnly => {
                if self.payload_handle.is_none() {
                    return Err(MemoryProjectionError::DimensionCollapsed(
                        "handle-only accessibility requires a payload handle",
                    ));
                }
            }
            MemoryAccessibility::Suppressed
            | MemoryAccessibility::Quarantined
            | MemoryAccessibility::Unavailable => {
                if matches!(
                    self.permitted_influence,
                    PermittedInfluence::Candidate | PermittedInfluence::ExactNegativeBlockCandidate
                ) {
                    return Err(MemoryProjectionError::DimensionCollapsed(
                        "inaccessible record cannot directly influence selection",
                    ));
                }
            }
        }
        if self.permitted_influence == PermittedInfluence::ExactNegativeBlockCandidate
            && !self.negative_memory
        {
            return Err(MemoryProjectionError::DimensionCollapsed(
                "exact negative block requires negative-memory identity",
            ));
        }
        if matches!(
            self.epistemic_status,
            EpistemicStatus::Observed
                | EpistemicStatus::Unknown
                | EpistemicStatus::Contested
                | EpistemicStatus::Stale
                | EpistemicStatus::Superseded
                | EpistemicStatus::Rejected
        ) && self.assertability == Assertability::Assertable
        {
            return Err(MemoryProjectionError::DimensionCollapsed(
                "non-supported record cannot be assertable",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalMemoryReadSnapshot {
    pub request: CanonicalMemoryReadRequest,
    pub read_receipt_handle: Option<ArtifactId>,
    pub coverage: MemoryReadCoverage,
    pub denominator: Option<MemoryCoverageDenominator>,
    pub records: Vec<MemoryProjectionRecord>,
    pub missing_owner_refs: Vec<String>,
    pub snapshot_sha256: String,
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemorySelectionDimension {
    ExactCue,
    ScopeApplicability,
    Freshness,
    Provenance,
    DecisionRelevance,
    ActivationPrecision,
    NegativeMemory,
    MinorityOrCounterevidence,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectionDimensionResult {
    Known { basis_points: u16 },
    Unknown,
    NotApplicable,
}

impl SelectionDimensionResult {
    fn validate(self) -> Result<(), MemoryProjectionError> {
        match self {
            Self::Known { basis_points } if basis_points <= 10_000 => Ok(()),
            Self::Unknown | Self::NotApplicable => Ok(()),
            _ => Err(MemoryProjectionError::DimensionCollapsed(
                "selection dimension must fit 0..=10000",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySelectionAssessment {
    pub dimension: MemorySelectionDimension,
    pub result: SelectionDimensionResult,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryCandidateRepresentation {
    InlinePreview { value: String },
    ExactHandle { handle: ArtifactId },
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCandidate {
    pub record_handle: ArtifactId,
    pub representation: MemoryCandidateRepresentation,
    pub kind: MemoryRecordKind,
    pub epistemic_status: EpistemicStatus,
    pub accessibility: MemoryAccessibility,
    pub permitted_influence: PermittedInfluence,
    pub assessments: Vec<MemorySelectionAssessment>,
    pub source_handles: Vec<ArtifactId>,
}

impl MemoryCandidate {
    fn validate(&self) -> Result<(), MemoryProjectionError> {
        match &self.representation {
            MemoryCandidateRepresentation::InlinePreview { value } => {
                validate_text(value, "candidate.inline_preview")?;
                if self.accessibility != MemoryAccessibility::Payload {
                    return Err(MemoryProjectionError::DimensionCollapsed(
                        "inline preview requires payload accessibility",
                    ));
                }
            }
            MemoryCandidateRepresentation::ExactHandle { .. } => {
                if !matches!(
                    self.accessibility,
                    MemoryAccessibility::Payload | MemoryAccessibility::HandleOnly
                ) {
                    return Err(MemoryProjectionError::DimensionCollapsed(
                        "candidate handle cannot bypass accessibility",
                    ));
                }
            }
        }
        if matches!(
            self.permitted_influence,
            PermittedInfluence::Denied | PermittedInfluence::RequiresRevalidation
        ) {
            return Err(MemoryProjectionError::DimensionCollapsed(
                "selected candidate lacks current candidate influence",
            ));
        }
        if self.source_handles.is_empty() {
            return Err(MemoryProjectionError::CoverageInvalid(
                "candidate requires source handles",
            ));
        }
        validate_unique_handles(&self.source_handles, "candidate.source_handles")?;
        let mut dimensions = BTreeSet::new();
        for assessment in &self.assessments {
            assessment.result.validate()?;
            if !dimensions.insert(assessment.dimension) {
                return Err(MemoryProjectionError::TraceInvalid(
                    "candidate contains a duplicate assessment dimension",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCandidateSet {
    pub snapshot_sha256: String,
    pub state_fence: StateFence,
    pub candidates: Vec<MemoryCandidate>,
    pub considered_handles: Vec<ArtifactId>,
    pub selected_handles: Vec<ArtifactId>,
    pub set_sha256: String,
}

pub fn memory_read_snapshot_digest(
    snapshot: &CanonicalMemoryReadSnapshot,
) -> Result<String, MemoryProjectionError> {
    let mut normalized = snapshot.clone();
    normalized.snapshot_sha256.clear();
    normalized
        .records
        .sort_by(|left, right| left.record_handle.cmp(&right.record_handle));
    normalized.missing_owner_refs.sort();
    for record in &mut normalized.records {
        record.provenance_handles.sort();
    }
    if let Some(denominator) = &mut normalized.denominator {
        denominator.partitions.sort();
    }
    let bytes = canonical_json_bytes(&normalized)
        .map_err(|error| MemoryProjectionError::Canonicalization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn validate_memory_read_snapshot(
    snapshot: &CanonicalMemoryReadSnapshot,
) -> Result<(), MemoryProjectionError> {
    snapshot.request.validate()?;
    validate_digest(&snapshot.snapshot_sha256, "snapshot.snapshot_sha256")?;
    if snapshot.coverage.searched() && snapshot.denominator.is_none() {
        return Err(MemoryProjectionError::CoverageInvalid(
            "searched coverage requires a denominator",
        ));
    }
    if let Some(denominator) = &snapshot.denominator {
        denominator.validate()?;
    }
    match snapshot.coverage {
        MemoryReadCoverage::Complete => {
            if snapshot.read_receipt_handle.is_none() || !snapshot.missing_owner_refs.is_empty() {
                return Err(MemoryProjectionError::CoverageInvalid(
                    "complete read requires receipt and no missing owners",
                ));
            }
        }
        MemoryReadCoverage::Partial => {
            if snapshot.missing_owner_refs.is_empty() {
                return Err(MemoryProjectionError::CoverageInvalid(
                    "partial read must name missing owners",
                ));
            }
        }
        MemoryReadCoverage::Unavailable | MemoryReadCoverage::Blocked => {
            if !snapshot.records.is_empty() || snapshot.denominator.is_some() {
                return Err(MemoryProjectionError::CoverageInvalid(
                    "unavailable read cannot claim searched records",
                ));
            }
        }
        MemoryReadCoverage::Stale => {}
    }
    if snapshot.records.len() > snapshot.request.maximum_records as usize {
        return Err(MemoryProjectionError::LimitExceeded {
            field: "snapshot.records",
            limit: snapshot.request.maximum_records as usize,
        });
    }
    let mut handles = BTreeSet::new();
    for record in &snapshot.records {
        record.validate()?;
        if !snapshot
            .request
            .state_fence
            .is_compatible_with(&record.state_fence)
        {
            return Err(MemoryProjectionError::FenceMismatch);
        }
        if !handles.insert(record.record_handle.as_str()) {
            return Err(MemoryProjectionError::DuplicateHandle(
                record.record_handle.to_string(),
            ));
        }
    }
    if let Some(expected) = snapshot
        .denominator
        .as_ref()
        .and_then(|denominator| denominator.expected_records)
    {
        match snapshot.coverage {
            MemoryReadCoverage::Complete if expected as usize != snapshot.records.len() => {
                return Err(MemoryProjectionError::CoverageInvalid(
                    "complete count differs from denominator",
                ));
            }
            MemoryReadCoverage::Partial if (expected as usize) < snapshot.records.len() => {
                return Err(MemoryProjectionError::CoverageInvalid(
                    "partial result exceeds denominator",
                ));
            }
            _ => {}
        }
    }
    if memory_read_snapshot_digest(snapshot)? != snapshot.snapshot_sha256 {
        return Err(MemoryProjectionError::DigestMismatch {
            field: "snapshot.snapshot_sha256",
        });
    }
    Ok(())
}

pub fn memory_candidate_set_digest(
    set: &MemoryCandidateSet,
) -> Result<String, MemoryProjectionError> {
    let mut normalized = set.clone();
    normalized.set_sha256.clear();
    normalized
        .candidates
        .sort_by(|left, right| left.record_handle.cmp(&right.record_handle));
    normalized.considered_handles.sort();
    normalized.selected_handles.sort();
    for candidate in &mut normalized.candidates {
        candidate.source_handles.sort();
        candidate
            .assessments
            .sort_by_key(|assessment| assessment.dimension);
    }
    let bytes = canonical_json_bytes(&normalized)
        .map_err(|error| MemoryProjectionError::Canonicalization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn validate_memory_candidate_set(
    set: &MemoryCandidateSet,
) -> Result<(), MemoryProjectionError> {
    validate_digest(&set.snapshot_sha256, "candidate_set.snapshot_sha256")?;
    validate_digest(&set.set_sha256, "candidate_set.set_sha256")?;
    set.state_fence.validate()?;
    if set.candidates.len() > MAX_CANDIDATES {
        return Err(MemoryProjectionError::LimitExceeded {
            field: "candidate_set.candidates",
            limit: MAX_CANDIDATES,
        });
    }
    let mut candidates = BTreeSet::new();
    for candidate in &set.candidates {
        candidate.validate()?;
        if !candidates.insert(candidate.record_handle.as_str()) {
            return Err(MemoryProjectionError::DuplicateHandle(
                candidate.record_handle.to_string(),
            ));
        }
    }
    validate_unique_handles(&set.considered_handles, "candidate_set.considered_handles")?;
    validate_unique_handles(&set.selected_handles, "candidate_set.selected_handles")?;
    let considered: BTreeSet<_> = set
        .considered_handles
        .iter()
        .map(ArtifactId::as_str)
        .collect();
    let selected: BTreeSet<_> = set
        .selected_handles
        .iter()
        .map(ArtifactId::as_str)
        .collect();
    if selected != candidates || !selected.is_subset(&considered) {
        return Err(MemoryProjectionError::TraceInvalid(
            "selected, considered, and candidate handles do not reconcile",
        ));
    }
    if memory_candidate_set_digest(set)? != set.set_sha256 {
        return Err(MemoryProjectionError::DigestMismatch {
            field: "candidate_set.set_sha256",
        });
    }
    Ok(())
}
