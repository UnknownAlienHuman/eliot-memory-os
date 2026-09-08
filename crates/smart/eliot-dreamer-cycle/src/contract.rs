//! Controller-local, provider-neutral cycle state and request records.

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, OperationId, PolicyRevision, ProductId, ReceiptId, RequestId, SourceId, StateFence,
};
use eliot_dreamer_contracts::{
    CandidateDisposition, DreamJobInput, ScreenBinding, TypedCurationHandlerRequest,
    TypedCurationHandlerResult, ValidationReceipt,
};
use eliot_receipts::{EffectClass, ProofCeiling, ReceiptEnvelope, ReceiptKind};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::error::CycleError;

/// Version of the controller-local cycle wire shape.
pub const CYCLE_SCHEMA_VERSION: u32 = 1;
/// Maximum pending or observed records in one transition input.
pub const MAX_RECORDS: usize = 256;
/// Maximum inert requests emitted by one transition.
pub const MAX_REQUESTS: usize = 64;
/// Maximum bytes represented by one canonical state transition.
pub const MAX_CANONICAL_BYTES: usize = 1_048_576;
/// Maximum text bytes accepted in controller-local fields.
pub const MAX_TEXT_BYTES: usize = 16_384;

/// Closed controller phases. Each successful call can move only one adjacent
/// phase; terminal and reconciliation phases are explicit boundaries.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CyclePhase {
    /// Input identities and the frozen bundle are structurally valid.
    Validated,
    /// Bundle validation has been observed.
    BundleValidated,
    /// Curation screening has been observed.
    Screened,
    /// A selected model invocation has been observed.
    ModelObserved,
    /// Grounding has been observed after model output.
    GroundingValidated,
    /// A-05 common validation has admitted the handler boundary.
    CommonValidated,
    /// A handler result has been observed.
    HandlerObserved,
    /// Intrinsic output checks have been observed.
    IntrinsicOutputChecked,
    /// A candidate is available for an external owner decision.
    CandidateBoundary,
    /// External candidate admission is being observed.
    ExternalAdmission,
    /// External closure evidence has been observed.
    ClosureObserved,
    /// An external effect or completion must be reconciled under its same operation.
    ReconciliationRequired,
    /// Progress is blocked by a typed condition.
    Blocked,
    /// Exact external terminal evidence has been observed.
    Terminal,
}

impl CyclePhase {
    /// Returns the legal adjacent phase after `self`.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Validated => Some(Self::BundleValidated),
            Self::BundleValidated => Some(Self::Screened),
            Self::Screened => Some(Self::ModelObserved),
            Self::ModelObserved => Some(Self::GroundingValidated),
            Self::GroundingValidated => Some(Self::CommonValidated),
            Self::CommonValidated => Some(Self::HandlerObserved),
            Self::HandlerObserved => Some(Self::IntrinsicOutputChecked),
            Self::IntrinsicOutputChecked => Some(Self::CandidateBoundary),
            Self::CandidateBoundary => Some(Self::ExternalAdmission),
            Self::ExternalAdmission => Some(Self::ClosureObserved),
            Self::ClosureObserved => None,
            Self::ReconciliationRequired | Self::Blocked | Self::Terminal => None,
        }
    }
}

/// Distinct disposition of an already-observed owner outcome.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutcomeDisposition {
    /// The owner accepted the requested operation.
    Accepted,
    /// The owner rejected the requested operation.
    Rejected,
    /// The owner explicitly did not attempt it.
    NotAttempted,
    /// The requested operation completed.
    Completed,
    /// Only a partial result is known.
    Partial,
    /// The owner failed before an external effect.
    FailedBeforeEffect,
    /// The external outcome remains unknown.
    Unknown,
    /// The operation was cancelled.
    Cancelled,
    /// The operation expired.
    Expired,
    /// The operation was superseded.
    Superseded,
    /// The owner or capability was unavailable.
    Unavailable,
    /// The observed input is stale.
    Stale,
}

/// Why an inert owner request is emitted.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestKind {
    /// Validate the frozen input bundle.
    BundleValidation,
    /// Run the curation screen before any model/handler work.
    CurationScreen,
    /// Invoke an already-selected model route as an inert proposal.
    ModelInvocation,
    /// Validate grounding evidence after model output.
    Grounding,
    /// Run the A-05 common validation boundary.
    CommonValidation,
    /// Invoke an already-selected typed semantic handler.
    SemanticHandler,
    /// Check intrinsic handler output shape.
    IntrinsicOutput,
    /// Ask the external owner to admit a candidate.
    ExternalAdmission,
    /// Observe external closure under a previously issued operation.
    Closure,
    /// Reconcile an uncertain possible effect under the same operation.
    EffectReconciliation,
    /// Ask the owner for one bounded clarification or probe.
    Clarification,
}

/// One pending owner operation in the immutable controller snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PendingRequest {
    /// Stable request identity.
    pub request_id: RequestId,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Idempotency identity supplied by the controller owner.
    pub idempotency_key: String,
    /// Product identity bound by the operation receipt.
    pub product_id: ProductId,
    /// Source identity bound by the operation receipt.
    pub source_id: SourceId,
    /// Operation kind bound by the operation receipt.
    pub operation_kind: String,
    /// Effect class bound by the operation receipt.
    pub effect: EffectClass,
    /// Maximum proof ceiling accepted from the owner.
    pub proof_ceiling: ProofCeiling,
    /// Exact owner identity expected in the receipt authority binding.
    pub owner: String,
    /// Controller request kind.
    pub kind: RequestKind,
    /// Phase this request may advance.
    pub phase: CyclePhase,
    /// Canonical attempt identity, included in the request digest.
    pub attempt_id: AgentAttemptId,
    /// Digest of the typed payload or request envelope.
    pub payload_digest: String,
    /// Job task identity.
    pub task_id: String,
    /// Job scope identity.
    pub scope_id: String,
    /// Exact state fence.
    pub state_fence: StateFence,
    /// Expected causal predecessor receipt.
    pub predecessor_receipt_id: Option<ReceiptId>,
    /// Optional exact A-31 request retained at the handler boundary.
    pub handler_request: Option<TypedCurationHandlerRequest>,
    /// Exact artifact bindings expected in the owner receipt.
    pub expected_artifacts: Vec<ExpectedArtifact>,
}

/// Frozen owner and operation binding for one controller phase.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PhasePolicyRule {
    /// Phase governed by this rule.
    pub phase: CyclePhase,
    /// Owner identity expected in neutral receipts.
    pub owner: String,
    /// Product identity expected in neutral receipts.
    pub product_id: ProductId,
    /// Source identity expected in neutral receipts.
    pub source_id: SourceId,
    /// Operation kind expected in neutral receipts.
    pub operation_kind: String,
    /// Effect class expected in neutral receipts.
    pub effect: EffectClass,
    /// Maximum proof ceiling accepted from this owner.
    pub proof_ceiling: ProofCeiling,
}

/// Exact artifact identity expected from an owner receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectedArtifact {
    /// Artifact identity.
    pub artifact_id: ArtifactId,
    /// Lowercase SHA-256 digest.
    pub sha256: String,
    /// Receipt artifact role.
    pub role: ReceiptKind,
    /// Optional source revision.
    pub source_revision: Option<String>,
}

/// One owner-issued observation supplied to a transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedOutcome {
    /// Neutral immutable receipt supplied by the owner.
    pub receipt: ReceiptEnvelope,
    /// Controller phase evidenced by this observation.
    pub phase: CyclePhase,
    /// Controller interpretation of the generic receipt disposition.
    pub disposition: OutcomeDisposition,
    /// Digest of the exact pending payload/request.
    pub payload_digest: String,
    /// Whether the receipt leaves a possible external effect unresolved.
    pub possible_effect: bool,
    /// Exact evidence handles retained with the observation.
    pub evidence_refs: Vec<ArtifactId>,
    /// Optional typed handler result, retained as evidence only.
    pub handler_result: Option<TypedCurationHandlerResult>,
    /// Optional A-05 validation receipt, retained as evidence only.
    pub validation_receipt: Option<ValidationReceipt>,
    /// Optional A-31 screen binding, retained as evidence only.
    pub screen_binding: Option<ScreenBinding>,
}

/// Candidate-only request emitted for another owner to execute or reconcile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InertOwnerRequest {
    /// Stable request identity.
    pub request_id: RequestId,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Canonical attempt identity.
    pub attempt_id: AgentAttemptId,
    /// Exact owner identity.
    pub owner: String,
    /// Request kind.
    pub kind: RequestKind,
    /// Requested adjacent phase or reconciliation boundary.
    pub phase: CyclePhase,
    /// Exact payload/request digest.
    pub payload_digest: String,
    /// Job task identity.
    pub task_id: String,
    /// Job scope identity.
    pub scope_id: String,
    /// Exact state fence.
    pub state_fence: StateFence,
    /// Existing operation predecessor, if any.
    pub predecessor_receipt_id: Option<ReceiptId>,
    /// Human-readable bounded reason, with no executable instruction.
    pub reason: String,
}

/// Disposition of one pure transition candidate.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StepDisposition {
    /// One adjacent phase was admitted.
    Advanced,
    /// Exact input state/outcomes replayed without change.
    Replayed,
    /// More observation is required for the same operation.
    ReconciliationRequired,
    /// A typed condition prevents progress.
    Blocked,
    /// A terminal external outcome is structurally evidenced.
    Terminal,
}

/// Immutable controller state consumed and returned by one step.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerCycleState {
    /// Exact cycle schema revision.
    pub schema_version: u32,
    /// Cycle identity.
    pub cycle_id: ArtifactId,
    /// Frozen Dreamer job input.
    pub job: DreamJobInput,
    /// Frozen policy identity used to validate this snapshot.
    pub policy_id: ArtifactId,
    /// Frozen policy revision used to validate this snapshot.
    pub policy_revision: PolicyRevision,
    /// Canonical digest of the frozen policy.
    pub policy_digest: String,
    /// Current controller phase.
    pub phase: CyclePhase,
    /// Monotonic controller revision.
    pub controller_revision: u32,
    /// Digest of the state supplied as predecessor.
    pub predecessor_digest: Option<String>,
    /// Pending requests in semantic sequence order.
    pub pending: Vec<PendingRequest>,
    /// Caller-supplied exact requests that may be activated for the next phase.
    pub proposed_requests: Vec<PendingRequest>,
    /// Previously accepted owner outcomes in causal sequence order.
    pub outcomes: Vec<ObservedOutcome>,
    /// Explicit unresolved material/frontier.
    pub frontier: Vec<String>,
    /// Independent consumed budget dimensions.
    pub budget_usage: eliot_dreamer_contracts::BudgetUsage,
    /// Explicit cancellation observation.
    pub cancellation_requested: bool,
    /// Frozen state digest.
    pub canonical_digest: String,
}

/// Result of one deterministic transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CycleStep {
    /// Digest of the consumed state.
    pub predecessor_digest: String,
    /// One adjacent next-state candidate.
    pub next_state: DreamerCycleState,
    /// Finite inert requests for external owners.
    pub requests: Vec<InertOwnerRequest>,
    /// Explicit disposition of this call.
    pub disposition: StepDisposition,
    /// Digest of the complete candidate transition.
    pub transition_digest: String,
}

/// Optional evidence retained from a typed candidate result without treating
/// it as canonical promotion or external completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvidence {
    /// Candidate disposition from A-03.
    pub disposition: CandidateDisposition,
}

/// Policy identity and independent limits frozen for one call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CyclePolicy {
    /// Exact policy schema revision.
    pub schema_version: u32,
    /// Frozen policy identity.
    pub policy_id: ArtifactId,
    /// Frozen policy revision.
    pub policy_revision: PolicyRevision,
    /// Exact fence under which this policy applies.
    pub state_fence: StateFence,
    /// Maximum pending records accepted.
    pub max_pending: u32,
    /// Maximum observed outcomes accepted.
    pub max_outcomes: u32,
    /// Maximum requests emitted.
    pub max_requests: u32,
    /// Maximum state transition count.
    pub max_transitions: u32,
    /// Maximum canonical transition bytes.
    pub max_bytes: u32,
    /// Optional injected deadline in Unix milliseconds.
    pub deadline_ms: Option<i64>,
    /// Explicit cancellation request.
    pub cancellation_requested: bool,
    /// Canonical policy digest.
    pub canonical_digest: String,
    /// Per-phase owner and operation rules. Each ordinary phase appears at
    /// most once; no single global owner is assumed for all phases.
    pub phase_rules: Vec<PhasePolicyRule>,
}

impl CyclePolicy {
    /// Seals the policy with a deterministic digest.
    pub fn seal(&mut self) -> Result<(), CycleError> {
        self.canonical_digest.clear();
        let bytes = eliot_contracts::canonical_json_bytes(self)
            .map_err(|error| CycleError::Encoding(error.to_string()))?;
        self.canonical_digest = eliot_contracts::sha256_hex(&bytes);
        Ok(())
    }

    /// Validates the frozen policy and its digest.
    pub fn validate(&self) -> Result<(), CycleError> {
        if self.schema_version != CYCLE_SCHEMA_VERSION {
            return Err(CycleError::BindingMismatch {
                field: "policy.schema_version",
                reason: "unsupported schema version",
            });
        }
        if self.policy_id.as_str().trim().is_empty() {
            return Err(CycleError::IncompleteOutcome("policy.policy_id"));
        }
        self.state_fence.validate()?;
        if self.phase_rules.is_empty() || self.phase_rules.len() > MAX_RECORDS {
            return Err(CycleError::Bound {
                field: "policy.phase_rules",
                maximum: MAX_RECORDS,
            });
        }
        let mut phases = BTreeSet::new();
        for rule in &self.phase_rules {
            if !phases.insert(rule.phase) || crate::policy::request_kind(rule.phase).is_none() {
                return Err(CycleError::PhaseViolation(
                    "policy phase rule is duplicate or non-operational",
                ));
            }
            validate_text(&rule.owner, "policy.phase_rule.owner")?;
            validate_text(rule.product_id.as_str(), "policy.phase_rule.product_id")?;
            validate_text(rule.source_id.as_str(), "policy.phase_rule.source_id")?;
            validate_text(&rule.operation_kind, "policy.phase_rule.operation_kind")?;
        }
        if self.max_bytes as usize > MAX_CANONICAL_BYTES {
            return Err(CycleError::Bound {
                field: "policy.max_bytes",
                maximum: MAX_CANONICAL_BYTES,
            });
        }
        let expected = policy_digest(self)?;
        if expected != self.canonical_digest {
            return Err(CycleError::IdentityConflict {
                identity: "policy.canonical_digest".to_owned(),
            });
        }
        Ok(())
    }
}

impl DreamerCycleState {
    /// Seals the immutable state with a deterministic digest.
    pub fn seal(&mut self) -> Result<(), CycleError> {
        self.canonical_digest.clear();
        let bytes = eliot_contracts::canonical_json_bytes(self)
            .map_err(|error| CycleError::Encoding(error.to_string()))?;
        if bytes.len() > MAX_CANONICAL_BYTES {
            return Err(CycleError::Bound {
                field: "state.canonical_bytes",
                maximum: MAX_CANONICAL_BYTES,
            });
        }
        self.canonical_digest = eliot_contracts::sha256_hex(&bytes);
        Ok(())
    }

    /// Validates immutable state shape and its digest.
    pub fn validate(&self) -> Result<(), CycleError> {
        if self.schema_version != CYCLE_SCHEMA_VERSION {
            return Err(CycleError::BindingMismatch {
                field: "state.schema_version",
                reason: "unsupported schema version",
            });
        }
        if self.cycle_id.as_str().trim().is_empty() {
            return Err(CycleError::IncompleteOutcome("state.cycle_id"));
        }
        self.job.validate()?;
        if self.policy_id.as_str().trim().is_empty() || !is_digest(&self.policy_digest) {
            return Err(CycleError::IncompleteOutcome("state.policy_identity"));
        }
        if self.pending.len() > MAX_RECORDS || self.outcomes.len() > MAX_RECORDS {
            return Err(CycleError::Bound {
                field: "state.records",
                maximum: MAX_RECORDS,
            });
        }
        let mut pending_ids = BTreeSet::new();
        for pending in &self.pending {
            validate_pending(pending, &self.job.state_fence, &mut pending_ids)?;
        }
        if self.proposed_requests.len() > MAX_REQUESTS {
            return Err(CycleError::Bound {
                field: "state.proposed_requests",
                maximum: MAX_REQUESTS,
            });
        }
        for pending in &self.proposed_requests {
            validate_pending(pending, &self.job.state_fence, &mut pending_ids)?;
        }
        let mut outcome_ids = BTreeSet::new();
        for outcome in &self.outcomes {
            let id = outcome.receipt.identity.receipt_id.as_str();
            if !outcome_ids.insert(id) {
                return Err(CycleError::IdentityConflict {
                    identity: id.to_owned(),
                });
            }
            outcome.receipt.validate()?;
            validate_text(&outcome.payload_digest, "outcome.payload_digest")?;
            if outcome.evidence_refs.len() > MAX_RECORDS {
                return Err(CycleError::Bound {
                    field: "outcome.evidence_refs",
                    maximum: MAX_RECORDS,
                });
            }
        }
        let expected = state_digest(self)?;
        if expected != self.canonical_digest {
            return Err(CycleError::IdentityConflict {
                identity: "state.canonical_digest".to_owned(),
            });
        }
        Ok(())
    }
}

fn validate_pending(
    pending: &PendingRequest,
    expected_fence: &StateFence,
    ids: &mut BTreeSet<String>,
) -> Result<(), CycleError> {
    if !ids.insert(pending.request_id.as_str().to_owned()) {
        return Err(CycleError::IdentityConflict {
            identity: pending.request_id.as_str().to_owned(),
        });
    }
    for (field, value) in [
        ("pending.idempotency_key", pending.idempotency_key.as_str()),
        ("pending.owner", pending.owner.as_str()),
        ("pending.attempt_id", pending.attempt_id.as_str()),
        ("pending.payload_digest", pending.payload_digest.as_str()),
        ("pending.task_id", pending.task_id.as_str()),
        ("pending.scope_id", pending.scope_id.as_str()),
    ] {
        validate_text(value, field)?;
    }
    if !is_digest(&pending.payload_digest) {
        return Err(CycleError::BindingMismatch {
            field: "pending.payload_digest",
            reason: "payload digest must be lowercase sha256",
        });
    }
    pending.state_fence.validate()?;
    if &pending.state_fence != expected_fence {
        return Err(CycleError::BindingMismatch {
            field: "pending.state_fence",
            reason: "pending request fence differs from job",
        });
    }
    validate_text(&pending.operation_kind, "pending.operation_kind")?;
    if pending.expected_artifacts.len() > MAX_RECORDS {
        return Err(CycleError::Bound {
            field: "pending.expected_artifacts",
            maximum: MAX_RECORDS,
        });
    }
    let mut artifact_ids = BTreeSet::new();
    let mut payload_bound = false;
    for expected in &pending.expected_artifacts {
        validate_text(
            expected.artifact_id.as_str(),
            "expected_artifact.artifact_id",
        )?;
        if !is_digest(&expected.sha256) {
            return Err(CycleError::BindingMismatch {
                field: "expected_artifact.sha256",
                reason: "artifact digest must be lowercase sha256",
            });
        }
        if expected.sha256 == pending.payload_digest {
            payload_bound = true;
        }
        if !artifact_ids.insert(expected.artifact_id.as_str()) {
            return Err(CycleError::IdentityConflict {
                identity: expected.artifact_id.as_str().to_owned(),
            });
        }
        if let Some(revision) = &expected.source_revision {
            validate_text(revision, "expected_artifact.source_revision")?;
        }
    }
    if !payload_bound {
        return Err(CycleError::IncompleteOutcome("pending.payload_artifact"));
    }
    if let Some(request) = &pending.handler_request {
        request.validate()?;
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), CycleError> {
    if value.trim().is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CycleError::BindingMismatch {
            field,
            reason: "text is blank, control-bearing or too long",
        });
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn policy_digest(value: &CyclePolicy) -> Result<String, CycleError> {
    let mut value = value.clone();
    value.canonical_digest.clear();
    let bytes = eliot_contracts::canonical_json_bytes(&value)
        .map_err(|error| CycleError::Encoding(error.to_string()))?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

fn state_digest(value: &DreamerCycleState) -> Result<String, CycleError> {
    let mut value = value.clone();
    value.canonical_digest.clear();
    let bytes = eliot_contracts::canonical_json_bytes(&value)
        .map_err(|error| CycleError::Encoding(error.to_string()))?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}
