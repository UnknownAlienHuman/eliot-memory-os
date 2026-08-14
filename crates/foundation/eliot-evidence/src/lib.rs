//! Contract-only semantic records for ELIOT cognitive inheritance.
//!
//! The crate owns no canonical store, index, promotion authority, or runtime
//! lifecycle.  It defines the small typed records consumed by those owners.
//! Raw observations remain immutable; changes to support, applicability,
//! accessibility, and influence are represented by forward transitions.

#![forbid(unsafe_code)]

use std::fmt;

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractVersion, DecisionId, SourceId, StateFence,
    TaskId, TaskRevision, canonical_json_bytes, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this contract surface.
pub const CONTRACT_NAME: &str = "eliot.foundation.evidence";
/// Current wire revision of this contract surface.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Validation failures for semantic evidence records.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvidenceError {
    /// A required text field is empty or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// A record contains no evidence lineage.
    #[error("{field} must contain at least one provenance source")]
    MissingProvenance { field: &'static str },
    /// A digest is not the canonical lowercase SHA-256 representation.
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    /// A status and its evidence dimensions contradict one another.
    #[error("status invariant failed for {field}: {reason}")]
    StatusInvariant {
        /// Field containing the contradiction.
        field: &'static str,
        /// Short machine-stable explanation.
        reason: &'static str,
    },
    /// A transition would rewrite immutable history or skip its predecessor.
    #[error("invalid lifecycle transition from {from} to {to}")]
    InvalidLifecycleTransition {
        from: LifecycleState,
        to: LifecycleState,
    },
    /// A temporal interval is inverted.
    #[error("{field} has an invalid temporal interval")]
    InvalidInterval { field: &'static str },
    /// A collection that is required for a semantic record is empty.
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    /// A serialized contract could not be canonicalized.
    #[error("cannot canonicalize contract shape: {0}")]
    Canonicalization(String),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), EvidenceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(EvidenceError::InvalidText { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), EvidenceError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(EvidenceError::InvalidDigest { field });
    }
    Ok(())
}

/// Epistemic status is independent from accessibility and physical lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpistemicStatus {
    /// Directly captured observation, not yet support for a claim.
    Observed,
    /// Evidence currently supports the proposition in its declared scope.
    Supported,
    /// Supported by an applicable evaluation contract and current verification run.
    Verified,
    /// Competing evidence or models remain unresolved.
    Contested,
    /// Once useful evidence whose freshness boundary has passed.
    Stale,
    /// Replaced by a later governed record while retained as history.
    Superseded,
    /// Explicitly rejected by a governed evaluation or adjudication.
    Rejected,
    /// The available material cannot establish a position.
    Unknown,
}

/// Whether a claim may be rendered as an ELIOT assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Assertability {
    /// The record may be stated within its scope.
    Assertable,
    /// The record may be attributed or discussed, but not asserted as ELIOT truth.
    NonAssertableUnverified,
    /// The safe action is to abstain or fence the dependent operation.
    AbstainOrFence,
}

/// Authority class of a normalized evidence result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceAuthority {
    /// Identity/provenance assertion from the source boundary.
    SourceIdentity,
    /// Compiler or parser semantic result.
    CompilerLanguage,
    /// Compiler-derived semantic result for the exact candidate.
    CompilerDerivedSemantics,
    /// Deterministic test or runtime observation.
    DeterministicRuntimeTest,
    /// Heuristic static inference.
    HeuristicStatic,
    /// Model-produced interpretation.
    ModelInterpretation,
}

/// Freshness of the evidence relative to a candidate `WorkScope`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceFreshness {
    /// Captured from the exact candidate under evaluation.
    ExactCandidate,
    /// Captured from the exact commit.
    ExactCommit,
    /// Captured from a quiesced exact worktree.
    ExactQuiescedWorktree,
    /// Known older snapshot.
    KnownOlderSnapshot,
    /// Known to be stale.
    Stale,
    /// Freshness cannot be established.
    Unknown,
}

/// Coverage of the queried relation or scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceCoverage {
    /// Complete for the declared scope.
    CompleteForScope,
    /// Partial for the declared scope.
    PartialForScope,
    /// Coverage does not apply to this evidence kind.
    NotApplicable,
    /// Coverage cannot be established.
    Unknown,
}

/// Physical/activation lifecycle of a memory record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleState {
    /// Available for normal governed influence.
    Active,
    /// Retained but not normally activated.
    Archived,
    /// Isolated from current influence pending a release condition.
    Quarantined,
    /// Temporarily suppressed from normal activation.
    Suppressed,
    /// Permanently logically extinguished while history remains addressable.
    Extinguished,
}

impl LifecycleState {
    /// Returns whether this state can participate in normal activation.
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    fn can_transition_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        !matches!(
            (self, next),
            (
                Self::Active | Self::Quarantined | Self::Suppressed,
                Self::Extinguished,
            ) | (Self::Archived, Self::Suppressed)
                | (Self::Extinguished, _)
        )
    }
}

impl fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Active => "ACTIVE",
            Self::Archived => "ARCHIVED",
            Self::Quarantined => "QUARANTINED",
            Self::Suppressed => "SUPPRESSED",
            Self::Extinguished => "EXTINGUISHED",
        })
    }
}

/// Stable class of a source origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceKind {
    /// Repository, worktree, file or generated source snapshot.
    Repository,
    /// Normative or research document.
    Document,
    /// Tool, process, test or instrument output.
    Instrument,
    /// Human-provided material.
    Human,
    /// Agent or model-provided material.
    Agent,
    /// External service or attached source.
    External,
}

/// Relationship between two semantic records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelationKind {
    /// Evidence supports a claim.
    Supports,
    /// Evidence contradicts a claim.
    Counters,
    /// One record supersedes another.
    Supersedes,
    /// One record was derived from another.
    DerivedFrom,
    /// A record applies to a scope or concept.
    AppliesTo,
    /// A record was observed in an experience.
    ObservedIn,
}

/// Source identity and capture lineage shared by all semantic records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// Source that produced or contained the record.
    pub source_id: SourceId,
    /// Stable route or instrument identity used for capture.
    pub capture_route: String,
    /// WorkScope-relative scope of the record.
    pub scope: String,
    /// Optional immutable raw evidence handle.
    pub raw_handle: Option<String>,
    /// Optional source revision or commit identity.
    pub revision: Option<String>,
}

impl Provenance {
    /// Validates source, route, scope and optional handle/revision text.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(self.capture_route.as_str(), "provenance.capture_route")?;
        validate_text(self.scope.as_str(), "provenance.scope")?;
        if let Some(value) = self.raw_handle.as_deref() {
            validate_text(value, "provenance.raw_handle")?;
        }
        if let Some(value) = self.revision.as_deref() {
            validate_text(value, "provenance.revision")?;
        }
        Ok(())
    }
}

/// Optional binding proving that a verified status has an applicable current run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerificationBinding {
    /// Evaluation contract identity.
    pub contract_id: ContractId,
    /// Current verification run identity.
    pub run_id: ArtifactId,
    /// Revision of the evaluated source/candidate.
    pub revision: String,
}

impl VerificationBinding {
    /// Validates the binding without claiming that a verifier actually ran.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(self.revision.as_str(), "verification.revision")
    }
}

/// Normalized evidence dimensions and lineage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelope {
    /// Authority is relative to the property being tested.
    pub authority: EvidenceAuthority,
    /// Freshness relative to the declared scope.
    pub freshness: EvidenceFreshness,
    /// Coverage of the queried scope.
    pub coverage: EvidenceCoverage,
    /// Epistemic position supported by this envelope.
    pub status: EpistemicStatus,
    /// Safe rendering/influence ceiling.
    pub assertability: Assertability,
    /// Exact source and route lineage.
    pub provenance: Provenance,
    /// Optional current verification binding.
    pub verification: Option<VerificationBinding>,
    /// Fence under which the envelope was captured.
    pub state_fence: StateFence,
}

impl EvidenceEnvelope {
    /// Validates provenance, fence and status/epistemic safety invariants.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        self.provenance.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| EvidenceError::StatusInvariant {
                field: "state_fence",
                reason: "fence must contain authority and resource identity",
            })?;
        if let Some(binding) = &self.verification {
            binding.validate()?;
        }
        if self.status == EpistemicStatus::Verified && self.verification.is_none() {
            return Err(EvidenceError::StatusInvariant {
                field: "status",
                reason: "verified requires a current verification binding",
            });
        }
        if matches!(
            self.status,
            EpistemicStatus::Observed | EpistemicStatus::Unknown
        ) && self.assertability == Assertability::Assertable
        {
            return Err(EvidenceError::StatusInvariant {
                field: "assertability",
                reason: "observed and unknown evidence cannot be assertable",
            });
        }
        if matches!(
            self.status,
            EpistemicStatus::Contested
                | EpistemicStatus::Stale
                | EpistemicStatus::Superseded
                | EpistemicStatus::Rejected
        ) && self.assertability == Assertability::Assertable
        {
            return Err(EvidenceError::StatusInvariant {
                field: "assertability",
                reason: "contested, stale, superseded and rejected evidence is not assertable",
            });
        }
        if self.status == EpistemicStatus::Verified
            && self.assertability != Assertability::Assertable
        {
            return Err(EvidenceError::StatusInvariant {
                field: "assertability",
                reason: "verified evidence must be assertable within its declared scope",
            });
        }
        Ok(())
    }
}

/// Immutable origin/snapshot/blob lineage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceRecord {
    /// Stable source identity.
    pub source_id: SourceId,
    /// Human-readable source label.
    pub label: String,
    /// Source category.
    pub kind: SourceKind,
    /// Stable locator or exact handle.
    pub locator: String,
    /// Content identity of the immutable source snapshot.
    pub content_sha256: String,
    /// Capture provenance (the source record may identify an upstream source).
    pub provenance: Option<Provenance>,
    /// Capture clock reading.
    pub captured_at: ClockReading,
    /// Physical/activation lifecycle, separate from epistemic status.
    pub lifecycle: LifecycleState,
}

impl SourceRecord {
    /// Validates the immutable source identity and lineage.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(self.label.as_str(), "source.label")?;
        validate_text(self.locator.as_str(), "source.locator")?;
        validate_digest(self.content_sha256.as_str(), "source.content_sha256")?;
        if let Some(provenance) = &self.provenance {
            provenance.validate()?;
        }
        self.captured_at
            .validate()
            .map_err(|_| EvidenceError::InvalidInterval {
                field: "source.captured_at",
            })
    }
}

/// What one route observed, retained independently of later interpretation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservationRecord {
    /// Stable observation identity.
    pub observation_id: ArtifactId,
    /// Source identity from which the observation was captured.
    pub source_id: SourceId,
    /// Subject or normalized property observed.
    pub subject: String,
    /// Bounded observation payload or preview.
    pub content: String,
    /// Capture clock reading.
    pub observed_at: ClockReading,
    /// Normalized dimensions and lineage.
    pub evidence: EvidenceEnvelope,
    /// Physical/activation lifecycle.
    pub lifecycle: LifecycleState,
}

impl ObservationRecord {
    /// Validates that an observation remains a capture, not an ungrounded claim.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(self.subject.as_str(), "observation.subject")?;
        validate_text(self.content.as_str(), "observation.content")?;
        self.observed_at
            .validate()
            .map_err(|_| EvidenceError::InvalidInterval {
                field: "observation.observed_at",
            })?;
        self.evidence.validate()
    }
}

/// A governed proposition or hypothesis with support and counterevidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    /// Stable claim identity.
    pub claim_id: DecisionId,
    /// Proposition text, retained as data rather than authority.
    pub statement: String,
    /// Scope in which the claim is evaluated.
    pub scope: String,
    /// Supporting observation/evidence handles.
    pub supporting_evidence: Vec<ArtifactId>,
    /// Counterevidence handles, preserved even when the claim is supported.
    pub counterevidence: Vec<ArtifactId>,
    /// Epistemic position and safe rendering ceiling.
    pub evidence: EvidenceEnvelope,
    /// Physical/activation lifecycle.
    pub lifecycle: LifecycleState,
}

impl ClaimRecord {
    /// Validates support, counterevidence, scope and status invariants.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(self.statement.as_str(), "claim.statement")?;
        validate_text(self.scope.as_str(), "claim.scope")?;
        if self.supporting_evidence.is_empty() && self.evidence.status != EpistemicStatus::Unknown {
            return Err(EvidenceError::EmptyCollection {
                field: "claim.supporting_evidence",
            });
        }
        self.evidence.validate()
    }
}

/// A typed edge in the causal/evidence graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationRecord {
    /// Stable relation identity.
    pub relation_id: ArtifactId,
    /// Source record/claim/experience handle.
    pub from: ArtifactId,
    /// Target record/claim/experience handle.
    pub to: ArtifactId,
    /// Semantic relation kind.
    pub kind: RelationKind,
    /// Status of the edge itself.
    pub status: EpistemicStatus,
    /// Lineage for the relation assertion.
    pub provenance: Provenance,
    /// Physical/activation lifecycle.
    pub lifecycle: LifecycleState,
}

impl RelationRecord {
    /// Validates relation identity and lineage.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        self.provenance.validate()
    }
}

/// Episode/action/outcome/failure material retained as experience.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExperienceRecord {
    /// Stable experience identity.
    pub experience_id: ArtifactId,
    /// Optional task that framed the episode.
    pub task_id: Option<TaskId>,
    /// Short episode description.
    pub episode: String,
    /// Action or inquiry performed.
    pub action: String,
    /// Observed outcome, including explicit unknown.
    pub outcome: String,
    /// Evidence status of the experience interpretation.
    pub evidence: EvidenceEnvelope,
    /// Physical/activation lifecycle.
    pub lifecycle: LifecycleState,
}

impl ExperienceRecord {
    /// Validates experience text and evidence dimensions.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(self.episode.as_str(), "experience.episode")?;
        validate_text(self.action.as_str(), "experience.action")?;
        validate_text(self.outcome.as_str(), "experience.outcome")?;
        self.evidence.validate()
    }
}

/// Governed view of decision-relevant understanding for one scope and revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnderstandingState {
    /// Scope to which this view applies.
    pub scope: String,
    /// Task-plan revision used to build the view.
    pub revision: TaskRevision,
    /// Bounded source/observation/evidence handles visible in the view.
    pub evidence_handles: Vec<ArtifactId>,
    /// Claims currently visible in the view.
    pub claim_handles: Vec<DecisionId>,
    /// Experiences currently visible in the view.
    pub experience_handles: Vec<ArtifactId>,
    /// Explicit unknowns; absence is not silently rendered as certainty.
    pub unknowns: Vec<String>,
    /// Fence under which the view was composed.
    pub state_fence: StateFence,
}

impl UnderstandingState {
    /// Validates bounded scope, handles and explicit fence.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(self.scope.as_str(), "understanding.scope")?;
        if self.evidence_handles.is_empty()
            && self.claim_handles.is_empty()
            && self.experience_handles.is_empty()
            && self.unknowns.is_empty()
        {
            return Err(EvidenceError::EmptyCollection {
                field: "understanding.contents",
            });
        }
        for unknown in &self.unknowns {
            validate_text(unknown.as_str(), "understanding.unknowns")?;
        }
        self.state_fence
            .validate()
            .map_err(|_| EvidenceError::StatusInvariant {
                field: "understanding.state_fence",
                reason: "view must be bound to a state fence",
            })
    }
}

/// Forward-only memory lifecycle change proposed/applied by the canonical owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryLifecycleTransition {
    /// Record being transitioned.
    pub record_id: ArtifactId,
    /// Previous lifecycle state.
    pub from: LifecycleState,
    /// New lifecycle state.
    pub to: LifecycleState,
    /// Governed reason for the change.
    pub reason: String,
    /// Scope of the change.
    pub scope: String,
    /// Evidence/provenance for the transition.
    pub provenance: Provenance,
    /// Fence under which the transition was admitted.
    pub state_fence: StateFence,
}

impl MemoryLifecycleTransition {
    /// Validates forward transition and provenance without applying it.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_text(self.reason.as_str(), "lifecycle.reason")?;
        validate_text(self.scope.as_str(), "lifecycle.scope")?;
        self.provenance.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| EvidenceError::StatusInvariant {
                field: "lifecycle.state_fence",
                reason: "transition must be fenced",
            })?;
        if !self.from.can_transition_to(self.to) {
            return Err(EvidenceError::InvalidLifecycleTransition {
                from: self.from,
                to: self.to,
            });
        }
        Ok(())
    }
}

/// Builds a stable content identity for any evidence contract shape.
pub fn evidence_shape_digest<T: Serialize>(shape: &T) -> Result<String, EvidenceError> {
    canonical_json_bytes(shape)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| EvidenceError::Canonicalization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration};

    fn source_id(value: &str) -> Result<SourceId, EvidenceError> {
        SourceId::new(value).map_err(|_| EvidenceError::InvalidText { field: "source_id" })
    }

    fn provenance() -> Result<Provenance, EvidenceError> {
        Ok(Provenance {
            source_id: source_id("fixture-source")?,
            capture_route: "fixture.route".to_owned(),
            scope: "fixture-scope".to_owned(),
            raw_handle: Some("eliot://evidence/fixture".to_owned()),
            revision: Some("r1".to_owned()),
        })
    }

    fn envelope(
        status: EpistemicStatus,
        assertability: Assertability,
    ) -> Result<EvidenceEnvelope, EvidenceError> {
        let verification = if status == EpistemicStatus::Verified {
            Some(VerificationBinding {
                contract_id: ContractId::new("fixture.contract").map_err(|_| {
                    EvidenceError::InvalidText {
                        field: "verification.contract_id",
                    }
                })?,
                run_id: ArtifactId::new("fixture-run").map_err(|_| EvidenceError::InvalidText {
                    field: "verification.run_id",
                })?,
                revision: "r1".to_owned(),
            })
        } else {
            None
        };
        Ok(EvidenceEnvelope {
            authority: EvidenceAuthority::DeterministicRuntimeTest,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            status,
            assertability,
            provenance: provenance()?,
            verification,
            state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        })
    }

    #[test]
    fn evidence_contract_roundtrips_and_schema_is_available()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = ObservationRecord {
            observation_id: ArtifactId::new("observation-1")?,
            source_id: source_id("fixture-source")?,
            subject: "cargo check".to_owned(),
            content: "passed".to_owned(),
            observed_at: ClockReading {
                valid_time_ms: Some(1),
                known_time_ms: Some(2),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            evidence: envelope(
                EpistemicStatus::Observed,
                Assertability::NonAssertableUnverified,
            )?,
            lifecycle: LifecycleState::Active,
        };
        record.validate()?;
        let json = serde_json::to_string(&record)?;
        let restored: ObservationRecord = serde_json::from_str(&json)?;
        assert_eq!(record, restored);
        let schema = schemars::schema_for!(ObservationRecord);
        assert!(serde_json::to_value(schema)?.is_object());
        Ok(())
    }

    #[test]
    fn verified_requires_binding_and_unknown_cannot_be_assertable()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut verified = envelope(EpistemicStatus::Verified, Assertability::Assertable)?;
        verified.verification = None;
        assert!(verified.validate().is_err());
        let unknown = envelope(EpistemicStatus::Unknown, Assertability::Assertable)?;
        assert!(unknown.validate().is_err());
        Ok(())
    }

    #[test]
    fn lifecycle_rejects_reactivation_from_extinguished() -> Result<(), Box<dyn std::error::Error>>
    {
        let transition = MemoryLifecycleTransition {
            record_id: ArtifactId::new("record-1")?,
            from: LifecycleState::Extinguished,
            to: LifecycleState::Active,
            reason: "fixture".to_owned(),
            scope: "fixture-scope".to_owned(),
            provenance: provenance()?,
            state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        };
        assert!(matches!(
            transition.validate(),
            Err(EvidenceError::InvalidLifecycleTransition { .. })
        ));
        Ok(())
    }

    #[test]
    fn malformed_consumer_fixtures_fail_closed() {
        let malformed = r#"{"source_id":"fixture","label":"x","kind":"REPOSITORY","locator":"x","content_sha256":42,"provenance":null,"captured_at":{"valid_time_ms":null,"known_time_ms":null,"transaction_sequence":null,"monotonic_ns":null},"lifecycle":"ACTIVE"}"#;
        assert!(serde_json::from_str::<SourceRecord>(malformed).is_err());
        let duplicate = r#"{"source_id":"fixture","label":"x","kind":"REPOSITORY","locator":"x","content_sha256":"0000000000000000000000000000000000000000000000000000000000000000","captured_at":{"valid_time_ms":null,"known_time_ms":null,"transaction_sequence":null,"monotonic_ns":null},"lifecycle":"ACTIVE","unexpected":true}"#;
        assert!(serde_json::from_str::<SourceRecord>(duplicate).is_err());
    }
}
