//! Provider-neutral contracts for instrument execution and verification.
//!
//! This crate describes requests and evidence only.  It does not execute a
//! process, persist a record, select a verifier, or decide task completion.
//! Raw evidence and its normalized projection remain separately addressable.

#![forbid(unsafe_code)]

use std::fmt;

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractVersion, RequestId, RequestMetadata, StateFence,
    canonical_json_bytes, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Stable identity of this contract surface.
pub const CONTRACT_NAME: &str = "eliot.instrument.api";
/// Current wire revision of this contract surface.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Validation failures for instrument contracts.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum InstrumentContractError {
    /// A required text value is blank or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// A digest is not a lowercase SHA-256 digest.
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    /// A collection required to correlate evidence is empty.
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    /// A lifecycle interval is inverted.
    #[error("{field} has an invalid interval")]
    InvalidInterval { field: &'static str },
    /// A status does not carry the evidence needed for that status.
    #[error("{field} has invalid evidence state: {reason}")]
    EvidenceState {
        field: &'static str,
        reason: &'static str,
    },
    /// A contract could not be canonicalized for a content digest.
    #[error("contract canonicalization failed: {0}")]
    Canonicalization(String),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), InstrumentContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(InstrumentContractError::InvalidText { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), InstrumentContractError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(InstrumentContractError::InvalidDigest { field });
    }
    Ok(())
}

/// The broad class of a governed instrument call.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstrumentKind {
    /// Compile or build an exact target.
    Build,
    /// Run selected tests or a test profile.
    Test,
    /// Run a static check or linter.
    Lint,
    /// Observe source, symbols, or workspace metadata.
    Inspect,
    /// Run a registered verifier profile.
    Verify,
    /// Format or parse without applying a mutation.
    Format,
}

/// Execution status of an instrument stage, independent of semantic verdict.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionStatus {
    /// The request was admitted but has not started.
    Accepted,
    /// The stage is still executing.
    Running,
    /// The stage completed normally.
    Succeeded,
    /// The stage produced a failed execution result.
    Failed,
    /// Only part of the declared stage scope was observed.
    Partial,
    /// The environment could not establish the outcome.
    Unknown,
    /// Policy or capability prevented execution.
    Blocked,
    /// The stage was cancelled before completion.
    Cancelled,
}

impl ExecutionStatus {
    /// Whether the status is terminal.
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Accepted | Self::Running)
    }
}

/// Epistemic status of normalized instrument evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    /// A direct observation with no semantic promotion.
    Observed,
    /// Evidence supports a proposition in its declared scope.
    Supported,
    /// Evidence is attached to an applicable verification run.
    Verified,
    /// Competing evidence remains unresolved.
    Contested,
    /// The freshness boundary has passed.
    Stale,
    /// The available material cannot establish a position.
    Unknown,
    /// The evidence was explicitly rejected by its owning evaluator.
    Rejected,
}

/// Whether a normalized result can be stated as an assertion.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Assertability {
    /// The result may be stated inside its exact scope.
    Assertable,
    /// The result may be attributed but not asserted as fact.
    NonAssertableUnverified,
    /// A dependent operation must abstain or fence.
    AbstainOrFence,
}

/// Whether evidence is available for normal projection.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Accessibility {
    /// The evidence can be read by an admitted consumer.
    Available,
    /// The evidence exists but is not currently readable.
    Inaccessible,
    /// Accessibility could not be established.
    Unknown,
}

/// Whether evidence is allowed to influence a derived decision.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Influence {
    /// The declared consumer may use the evidence within scope.
    Allowed,
    /// The evidence is retained but has no current influence.
    Suppressed,
    /// Influence cannot be established safely.
    Unknown,
}

/// Physical lifecycle of the source artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PhysicalState {
    /// The source artifact is present at the observed location.
    Present,
    /// The source artifact is absent while its evidence is retained.
    Missing,
    /// Physical existence is not known.
    Unknown,
}

/// Source security/taint dimension of an observation.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaintState {
    /// No source taint was recorded for this observation.
    Clear,
    /// The observation is tainted and must be constrained by its owner.
    Tainted,
    /// Taint has not been assessed.
    Unknown,
}

/// Freshness of an observation relative to its declared candidate scope.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceFreshness {
    /// Captured from the exact candidate under evaluation.
    ExactCandidate,
    /// Captured from the exact commit.
    ExactCommit,
    /// Captured from an exact quiesced worktree.
    ExactQuiescedWorktree,
    /// A known older snapshot.
    KnownOlderSnapshot,
    /// Explicitly known to be stale.
    Stale,
    /// Freshness cannot be established.
    Unknown,
}

/// Coverage of the declared evidence scope.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceCoverage {
    /// All required scope was observed.
    CompleteForScope,
    /// Only part of the scope was observed.
    PartialForScope,
    /// Coverage does not apply to this evidence kind.
    NotApplicable,
    /// Coverage cannot be established.
    Unknown,
}

/// The independent evidence axes carried with a normalized result.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAxes {
    /// Epistemic support/status axis.
    pub status: EvidenceStatus,
    /// Assertion ceiling.
    pub assertability: Assertability,
    /// Read/accessibility axis.
    pub accessibility: Accessibility,
    /// Allowed downstream influence.
    pub influence: Influence,
    /// Physical existence of the observed source.
    pub physical: PhysicalState,
    /// Source security/taint.
    pub taint: TaintState,
}

impl EvidenceAxes {
    /// A conservative axis set for a directly captured observation.
    pub const fn observed() -> Self {
        Self {
            status: EvidenceStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            accessibility: Accessibility::Available,
            influence: Influence::Allowed,
            physical: PhysicalState::Present,
            taint: TaintState::Clear,
        }
    }

    /// Validates the axis container. Each axis is intentionally independent;
    /// semantic promotion belongs to the evidence/verifier owner.
    pub const fn validate(self) -> Result<(), InstrumentContractError> {
        Ok(())
    }
}

/// Origin class of a raw evidence payload.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RawEvidenceSource {
    /// Captured from an external process stream.
    Process,
    /// Captured from a source or generated file.
    File,
    /// Captured from a tool response.
    Tool,
    /// Supplied as an inline deterministic fixture.
    Inline,
    /// Source class was not available.
    Unknown,
}

/// An immutable byte payload captured before parsing or normalization.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEvidence {
    /// Stable artifact handle for the payload.
    pub artifact_id: ArtifactId,
    /// Instrument invocation that captured the payload.
    pub invocation_id: RequestId,
    /// Source class of the payload.
    pub source: RawEvidenceSource,
    /// MIME-like type, such as `text/plain` or `application/json`.
    pub content_type: String,
    /// Exact captured bytes.  Storage is owned by a later adapter.
    pub bytes: Vec<u8>,
    /// Lowercase SHA-256 digest of `bytes`.
    pub sha256: String,
    /// Capture clock.
    pub captured_at: ClockReading,
    /// Whether the capture ended at an explicit truncation boundary.
    pub truncated: bool,
}

impl RawEvidence {
    /// Validates identity, digest, content type, and clock invariants.
    pub fn validate(&self) -> Result<(), InstrumentContractError> {
        validate_text(&self.content_type, "content_type")?;
        validate_digest(&self.sha256, "sha256")?;
        if sha256_hex(&self.bytes) != self.sha256 {
            return Err(InstrumentContractError::InvalidDigest { field: "sha256" });
        }
        self.captured_at
            .validate()
            .map_err(|_| InstrumentContractError::InvalidInterval {
                field: "captured_at",
            })
    }
}

/// Parsed evidence with explicit axes and lineage to one raw payload.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedEvidence {
    /// Stable evidence artifact handle.
    pub evidence_id: ArtifactId,
    /// Exact raw payload from which this projection was derived.
    pub raw_artifact_id: ArtifactId,
    /// Parser/normalizer contract identity.
    pub normalizer: ContractId,
    /// Stable type of the normalized value.
    pub kind: String,
    /// Human-readable summary; it is not authority.
    pub summary: String,
    /// Typed normalized value.
    pub value: Value,
    /// Independent evidence axes.
    pub axes: EvidenceAxes,
    /// Freshness relative to the declared scope.
    pub freshness: EvidenceFreshness,
    /// Coverage of the declared scope.
    pub coverage: EvidenceCoverage,
}

impl NormalizedEvidence {
    /// Validates lineage and semantic axes without promoting the evidence.
    pub fn validate(&self) -> Result<(), InstrumentContractError> {
        validate_text(&self.kind, "kind")?;
        validate_text(&self.summary, "summary")?;
        self.axes.validate()
    }
}

/// A typed request to execute one instrument profile.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentInvocation {
    /// Idempotent request and invocation identity.
    pub request: RequestMetadata,
    /// Registered instrument identity.
    pub instrument: ContractId,
    /// Instrument class.
    pub kind: InstrumentKind,
    /// Immutable profile name/revision selected by the caller.
    pub profile: String,
    /// Exact project/worktree target description.
    pub target: String,
    /// Bounded argument list after policy validation.
    pub arguments: Vec<String>,
    /// Input artifacts and generations supplied to the instrument.
    pub input_artifacts: Vec<ArtifactId>,
    /// Declared scope used for coverage and freshness.
    pub declared_scope: String,
    /// Request clock captured at admission.
    pub requested_at: ClockReading,
}

impl InstrumentInvocation {
    /// Validates the invocation without executing or admitting it to a store.
    pub fn validate(&self) -> Result<(), InstrumentContractError> {
        self.request
            .validate()
            .map_err(|_| InstrumentContractError::EvidenceState {
                field: "request",
                reason: "invalid common request metadata",
            })?;
        validate_text(&self.profile, "profile")?;
        validate_text(&self.target, "target")?;
        validate_text(&self.declared_scope, "declared_scope")?;
        for argument in &self.arguments {
            validate_text(argument, "arguments")?;
        }
        self.requested_at
            .validate()
            .map_err(|_| InstrumentContractError::InvalidInterval {
                field: "requested_at",
            })
    }
}

/// Semantic outcome of a verification run; it is not a finish decision.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationOutcome {
    /// The declared property was proven in the declared scope.
    Pass,
    /// A contradictory observation or failed required stage was found.
    Fail,
    /// Some required scope was measured and some was uncovered.
    Partial,
    /// The tools, parser, freshness, or coverage could not answer.
    Unknown,
    /// Policy or environment prevented the required proof.
    Blocked,
    /// No further effect was made and earlier evidence remains retained.
    Cancelled,
}

/// Compatibility spelling used by downstream verifier adapters.
pub type VerificationStatus = VerificationOutcome;
/// Compatibility spelling for consumers that call the outcome a result.
pub type VerificationResult = VerificationOutcome;

impl VerificationOutcome {
    /// Whether the outcome is a successful proof candidate.
    pub const fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// A property and scope-bound verification observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRun {
    /// Durable identity of this run.
    pub run_id: RequestId,
    /// Registered verifier definition.
    pub verifier: ContractId,
    /// Instrument invocation producing the run.
    pub invocation_id: RequestId,
    /// Property evaluated by the verifier.
    pub property: String,
    /// Exact scope evaluated by the verifier.
    pub scope: String,
    /// Execution status remains separate from this semantic outcome.
    pub execution: ExecutionStatus,
    /// Semantic result of the declared property.
    pub outcome: VerificationOutcome,
    /// Freshness of inputs/results.
    pub freshness: EvidenceFreshness,
    /// Coverage of the requested scope.
    pub coverage: EvidenceCoverage,
    /// Normalized evidence attached to the run.
    pub evidence: Vec<NormalizedEvidence>,
    /// Raw evidence handles retained for forensic readback.
    pub raw_evidence: Vec<ArtifactId>,
    /// State fence captured when the run was admitted.
    pub state_fence: StateFence,
    /// Start and completion observations.
    pub started_at: ClockReading,
    /// Completion observation, if the run has finished.
    pub finished_at: Option<ClockReading>,
}

impl VerificationRun {
    /// Validates lifecycle, scope, evidence lineage, and status separation.
    pub fn validate(&self) -> Result<(), InstrumentContractError> {
        validate_text(&self.property, "property")?;
        validate_text(&self.scope, "scope")?;
        self.state_fence
            .validate()
            .map_err(|_| InstrumentContractError::EvidenceState {
                field: "state_fence",
                reason: "invalid common state fence",
            })?;
        self.started_at
            .validate()
            .map_err(|_| InstrumentContractError::InvalidInterval {
                field: "started_at",
            })?;
        if let Some(finished) = self.finished_at {
            finished
                .validate()
                .map_err(|_| InstrumentContractError::InvalidInterval {
                    field: "finished_at",
                })?;
            if let (Some(start), Some(end)) =
                (self.started_at.known_time_ms, finished.known_time_ms)
                && end < start
            {
                return Err(InstrumentContractError::InvalidInterval {
                    field: "verification_run",
                });
            }
        }
        for item in &self.evidence {
            item.validate()?;
        }
        if self.execution.is_terminal() && self.evidence.is_empty() && self.raw_evidence.is_empty()
        {
            return Err(InstrumentContractError::EmptyCollection {
                field: "raw_evidence or evidence",
            });
        }
        if matches!(self.outcome, VerificationOutcome::Pass)
            && (!matches!(self.execution, ExecutionStatus::Succeeded)
                || !matches!(self.coverage, EvidenceCoverage::CompleteForScope))
        {
            return Err(InstrumentContractError::EvidenceState {
                field: "outcome",
                reason: "PASS requires succeeded execution and complete scope coverage",
            });
        }
        Ok(())
    }

    /// Canonical shape digest useful for contract/fixture identity.
    pub fn shape_digest(&self) -> Result<String, InstrumentContractError> {
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| InstrumentContractError::Canonicalization(error.to_string()))
    }
}

impl fmt::Display for VerificationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Partial => "PARTIAL",
            Self::Unknown => "UNKNOWN",
            Self::Blocked => "BLOCKED",
            Self::Cancelled => "CANCELLED",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ProductId, ResourceGeneration, SourceId};

    fn request() -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new("instrument-request-1").unwrap_or_else(|_| unreachable!()),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-1").unwrap_or_else(|_| unreachable!()),
            source_id: SourceId::new("source-1").unwrap_or_else(|_| unreachable!()),
            state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
            clock: ClockReading {
                valid_time_ms: Some(10),
                known_time_ms: Some(11),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
        }
    }

    fn artifact(value: &str) -> ArtifactId {
        ArtifactId::new(value).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn invocation_rejects_blank_profile_and_roundtrips() {
        let mut invocation = InstrumentInvocation {
            request: request(),
            instrument: ContractId::new("eliot.instrument.cargo")
                .unwrap_or_else(|_| unreachable!()),
            kind: InstrumentKind::Build,
            profile: "dev-fast".to_owned(),
            target: "worktree:a04".to_owned(),
            arguments: vec!["--locked".to_owned()],
            input_artifacts: vec![artifact("source-snapshot")],
            declared_scope: "workspace".to_owned(),
            requested_at: request().clock,
        };
        assert!(invocation.validate().is_ok());
        let encoded = serde_json::to_string(&invocation).unwrap_or_default();
        let decoded: InstrumentInvocation =
            serde_json::from_str(&encoded).unwrap_or_else(|_| unreachable!());
        assert_eq!(decoded, invocation);
        invocation.profile = " ".to_owned();
        assert!(invocation.validate().is_err());
    }

    #[test]
    fn raw_evidence_preserves_exact_digest() {
        let bytes = b"cargo check\n".to_vec();
        let raw = RawEvidence {
            artifact_id: artifact("raw-1"),
            invocation_id: request().request_id,
            source: RawEvidenceSource::Process,
            content_type: "text/plain".to_owned(),
            sha256: sha256_hex(&bytes),
            bytes,
            captured_at: request().clock,
            truncated: false,
        };
        assert!(raw.validate().is_ok());
        let mut malformed = raw.clone();
        malformed.sha256 = "0".repeat(64);
        assert!(malformed.validate().is_err());
    }

    #[test]
    fn evidence_axes_remain_independent() {
        let axes = EvidenceAxes {
            status: EvidenceStatus::Stale,
            assertability: Assertability::Assertable,
            ..EvidenceAxes::observed()
        };
        assert!(axes.validate().is_ok());
        let normalized = NormalizedEvidence {
            evidence_id: artifact("normalized-1"),
            raw_artifact_id: artifact("raw-1"),
            normalizer: ContractId::new("eliot.instrument.parser")
                .unwrap_or_else(|_| unreachable!()),
            kind: "diagnostic".to_owned(),
            summary: "one diagnostic".to_owned(),
            value: serde_json::json!({"code":"E0001"}),
            axes: EvidenceAxes::observed(),
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
        };
        assert!(normalized.validate().is_ok());
    }

    #[test]
    fn verification_pass_requires_execution_and_coverage() {
        let run = VerificationRun {
            run_id: request().request_id,
            verifier: ContractId::new("eliot.verifier.cargo").unwrap_or_else(|_| unreachable!()),
            invocation_id: request().request_id,
            property: "workspace compiles".to_owned(),
            scope: "workspace".to_owned(),
            execution: ExecutionStatus::Succeeded,
            outcome: VerificationOutcome::Pass,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            evidence: vec![NormalizedEvidence {
                evidence_id: artifact("evidence-1"),
                raw_artifact_id: artifact("raw-1"),
                normalizer: ContractId::new("eliot.instrument.parser")
                    .unwrap_or_else(|_| unreachable!()),
                kind: "status".to_owned(),
                summary: "pass".to_owned(),
                value: Value::String("pass".to_owned()),
                axes: EvidenceAxes::observed(),
                freshness: EvidenceFreshness::ExactCandidate,
                coverage: EvidenceCoverage::CompleteForScope,
            }],
            raw_evidence: vec![artifact("raw-1")],
            state_fence: request().state_fence,
            started_at: request().clock,
            finished_at: Some(ClockReading {
                known_time_ms: Some(12),
                ..request().clock
            }),
        };
        assert!(run.validate().is_ok());
        assert!(!run.shape_digest().unwrap_or_default().is_empty());
        let mut invalid = run;
        invalid.coverage = EvidenceCoverage::PartialForScope;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn unknown_terminal_result_retains_raw_lineage() {
        let mut run = VerificationRun {
            run_id: request().request_id,
            verifier: ContractId::new("eliot.verifier.cargo").unwrap_or_else(|_| unreachable!()),
            invocation_id: request().request_id,
            property: "workspace compiles".to_owned(),
            scope: "workspace".to_owned(),
            execution: ExecutionStatus::Unknown,
            outcome: VerificationOutcome::Unknown,
            freshness: EvidenceFreshness::Unknown,
            coverage: EvidenceCoverage::Unknown,
            evidence: Vec::new(),
            raw_evidence: vec![artifact("raw-timeout")],
            state_fence: request().state_fence,
            started_at: request().clock,
            finished_at: None,
        };
        assert!(run.validate().is_ok());
        run.raw_evidence.clear();
        assert!(run.validate().is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let value = serde_json::json!({"request": {}, "instrument": "x", "kind": "BUILD", "profile": "p", "target": "t", "arguments": [], "input_artifacts": [], "declared_scope": "s", "requested_at": {}, "extra": true});
        assert!(serde_json::from_value::<InstrumentInvocation>(value).is_err());
        let schema = schemars::schema_for!(VerificationRun);
        assert!(serde_json::to_vec(&schema).is_ok_and(|bytes| !bytes.is_empty()));
    }
}
