//! Serde and JSON Schema contract types shared by MCP and EBP callers.

use std::collections::BTreeSet;

use eliot_protocol::{HARD_STRUCTURED_RESPONSE_BYTES, RequestIdentity};
use eliot_receipts::{ProofCeiling, SessionBinding};
use eliot_security_contracts::{EffectCeiling, InstructionTaint, PrivacyClass};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Final primary and isolated compatibility MCP protocol profiles.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum McpProtocolVersion {
    /// Final MCP specification profile.
    #[serde(rename = "2026-07-28")]
    #[default]
    Final2026_07_28,
    /// Isolated compatibility profile.
    #[serde(rename = "2025-11-25")]
    Compat2025_11_25,
}

/// Client features that only affect presentation, never ELIOT semantics.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCapabilities {
    /// Whether the client advertised MCP Tasks.
    pub tasks: bool,
}

/// Security labels forwarded unchanged to the Governor-owned admission path.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSecurityContext {
    /// Maximum privacy class declared for the request content.
    pub privacy_class: PrivacyClass,
    /// Instruction/data taint declared for the request content.
    pub instruction_taint: InstructionTaint,
    /// Maximum effect that may be proposed from the request content.
    pub effect_ceiling: EffectCeiling,
}

/// One complete application request. No field is inferred from a connection.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRequest {
    /// MCP compatibility profile used at the boundary.
    pub protocol_version: McpProtocolVersion,
    /// Explicit durable application Session binding.
    pub session: SessionBinding,
    /// C0-07 request, replay, deadline, cancellation, and fence identity.
    pub identity: RequestIdentity,
    /// Security labels forwarded to the actual policy owner.
    pub security: RequestSecurityContext,
    /// Presentation-only client features.
    #[serde(default)]
    pub client_capabilities: ClientCapabilities,
    /// Canonical semantic tool request or the isolated legacy alias.
    pub tool: ToolRequest,
}

/// Exact canonical tool requests plus one non-canonical compatibility alias.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "name", content = "arguments", deny_unknown_fields)]
pub enum ToolRequest {
    /// Current state projection.
    #[serde(rename = "eliot.state")]
    State(StateInput),
    /// Active Understanding View packet compilation.
    #[serde(rename = "eliot.packet")]
    Packet(PacketInput),
    /// Typed observation capture.
    #[serde(rename = "eliot.observe")]
    Observe(ObserveInput),
    /// Intent-bearing query.
    #[serde(rename = "eliot.query")]
    Query(QueryInput),
    /// Action-frame request.
    #[serde(rename = "eliot.act")]
    Act(ActInput),
    /// Verification intent.
    #[serde(rename = "eliot.verify")]
    Verify(VerifyInput),
    /// Execution-fabric operation.
    #[serde(rename = "eliot.coordinate")]
    Coordinate(CoordinateInput),
    /// Candidate finish attempt.
    #[serde(rename = "eliot.finish")]
    Finish(FinishAttemptDraft),
    /// Compatibility alias; normalized to `Observe::InfluenceAck` before dispatch.
    #[serde(rename = "eliot.memory_use")]
    LegacyMemoryUse(MemoryInfluenceAcknowledgement),
}

impl ToolRequest {
    /// Returns the canonical semantic tool name.
    #[must_use]
    pub const fn canonical_name(&self) -> &'static str {
        match self {
            Self::State(_) => "eliot.state",
            Self::Packet(_) => "eliot.packet",
            Self::Observe(_) | Self::LegacyMemoryUse(_) => "eliot.observe",
            Self::Query(_) => "eliot.query",
            Self::Act(_) => "eliot.act",
            Self::Verify(_) => "eliot.verify",
            Self::Coordinate(_) => "eliot.coordinate",
            Self::Finish(_) => "eliot.finish",
        }
    }

    /// Normalizes the sole legacy alias to its canonical observation form.
    #[must_use]
    pub fn canonicalized(self) -> Self {
        match self {
            Self::LegacyMemoryUse(value) => Self::Observe(ObserveInput::InfluenceAck(value)),
            value => value,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::State(value) => value.validate(),
            Self::Packet(value) => value.validate(),
            Self::Observe(value) => value.validate(),
            Self::Query(value) => value.validate(),
            Self::Act(value) => value.validate(),
            Self::Verify(value) => value.validate(),
            Self::Coordinate(value) => value.validate(),
            Self::Finish(value) => value.validate(),
            Self::LegacyMemoryUse(value) => value.validate(),
        }
    }
}

/// Current-state projection selector.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateInput {
    /// Named projection fields requested by the caller.
    #[serde(default)]
    pub include: Vec<String>,
}

impl StateInput {
    fn validate(&self) -> Result<(), ContractViolation> {
        unique_non_blank(&self.include, "state.include")
    }
}

/// Active Understanding View packet request.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketInput {
    /// Existing packet handle to refresh, if one is already bound.
    pub packet_ref: Option<String>,
    /// Requested material handles. Duplicate handles are invalid.
    #[serde(default)]
    pub material_refs: Vec<String>,
}

impl PacketInput {
    fn validate(&self) -> Result<(), ContractViolation> {
        optional_non_blank(self.packet_ref.as_deref(), "packet.packet_ref")?;
        unique_non_blank(&self.material_refs, "packet.material_refs")
    }
}

/// The assurance semantics of a broad query.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryIntent {
    /// Semantic query mode.
    pub mode: QueryMode,
    /// Exact time window or named temporal scope.
    pub time_scope: String,
    /// Branch and environment scope.
    pub branch_environment_scope: String,
    /// Required freshness behavior.
    pub freshness_policy: String,
    /// Required assurance/proof behavior.
    pub required_assurance: String,
}

impl QueryIntent {
    fn validate(&self) -> Result<(), ContractViolation> {
        non_blank(&self.time_scope, "query.intent.time_scope")?;
        non_blank(
            &self.branch_environment_scope,
            "query.intent.branch_environment_scope",
        )?;
        non_blank(&self.freshness_policy, "query.intent.freshness_policy")?;
        non_blank(&self.required_assurance, "query.intent.required_assurance")
    }
}

/// Closed query modes from the architecture contract.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryMode {
    /// Current supported position.
    CurrentPosition,
    /// Historical reconstruction, never silently current.
    HistoricalReconstruction,
    /// Provenance and lineage.
    Provenance,
    /// Navigation lead that is not evidence.
    Navigation,
    /// Verification-oriented retrieval.
    Verification,
    /// Change-impact analysis.
    ChangeImpact,
    /// Context reconstruction.
    ContextReconstruction,
}

/// Intent-bearing query. `intent` is deliberately not optional.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryInput {
    /// Explicit semantics for broad or mutable queries.
    pub intent: QueryIntent,
    /// Query text or exact selector.
    pub query: String,
    /// Immutable resource URI, when directly addressing a resource.
    pub exact_resource_uri: Option<String>,
}

impl QueryInput {
    fn validate(&self) -> Result<(), ContractViolation> {
        self.intent.validate()?;
        non_blank(&self.query, "query.query")?;
        optional_non_blank(
            self.exact_resource_uri.as_deref(),
            "query.exact_resource_uri",
        )
    }
}

/// Natural or structured observation content.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationContent {
    /// Natural text or a structured JSON payload.
    pub content: Value,
    /// Affected resources, when known.
    #[serde(default)]
    pub affected_resources: Vec<String>,
    /// Source handles, when available.
    #[serde(default)]
    pub source_handles: Vec<String>,
}

impl ObservationContent {
    fn validate(&self, field: &'static str) -> Result<(), ContractViolation> {
        if self.content.is_null() {
            return Err(ContractViolation::InvalidField {
                field,
                reason: "must not be null",
            });
        }
        unique_non_blank(&self.affected_resources, "observe.affected_resources")?;
        unique_non_blank(&self.source_handles, "observe.source_handles")
    }
}

/// The exact five observation suboperations.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObserveInput {
    /// What was observed.
    Observation(ObservationContent),
    /// Chosen path and alternatives.
    Decision(DecisionObservation),
    /// Failed path and next discriminator.
    Failure(FailureObservation),
    /// Actual artifact/effect/verifier outcome.
    Outcome(OutcomeObservation),
    /// Public memory influence acknowledgement.
    InfluenceAck(MemoryInfluenceAcknowledgement),
}

impl ObserveInput {
    fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::Observation(value) => value.validate("observe.observation.content"),
            Self::Decision(value) => value.validate(),
            Self::Failure(value) => value.validate(),
            Self::Outcome(value) => value.validate(),
            Self::InfluenceAck(value) => value.validate(),
        }
    }
}

/// Decision observation.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionObservation {
    /// Public choice rationale.
    pub chosen_path: String,
    /// Alternatives considered.
    #[serde(default)]
    pub alternatives: Vec<String>,
    /// Condition under which the decision must be revisited.
    pub revisit_condition: String,
}

impl DecisionObservation {
    fn validate(&self) -> Result<(), ContractViolation> {
        non_blank(&self.chosen_path, "observe.decision.chosen_path")?;
        non_blank(
            &self.revisit_condition,
            "observe.decision.revisit_condition",
        )?;
        unique_non_blank(&self.alternatives, "observe.decision.alternatives")
    }
}

/// Failure observation.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureObservation {
    /// Failed path.
    pub failed_path: String,
    /// Stable public failure signature.
    pub signature: String,
    /// Evidence handles.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Next distinguishing probe.
    pub next_discriminator: String,
}

impl FailureObservation {
    fn validate(&self) -> Result<(), ContractViolation> {
        non_blank(&self.failed_path, "observe.failure.failed_path")?;
        non_blank(&self.signature, "observe.failure.signature")?;
        non_blank(
            &self.next_discriminator,
            "observe.failure.next_discriminator",
        )?;
        unique_non_blank(&self.evidence_refs, "observe.failure.evidence_refs")
    }
}

/// Outcome observation without a caller-created finish verdict.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeObservation {
    /// Public outcome description.
    pub outcome: String,
    /// Exact artifact handles.
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    /// Exact effect receipt handles.
    #[serde(default)]
    pub effect_refs: Vec<String>,
    /// Exact verifier run handles.
    #[serde(default)]
    pub verifier_run_refs: Vec<String>,
}

impl OutcomeObservation {
    fn validate(&self) -> Result<(), ContractViolation> {
        non_blank(&self.outcome, "observe.outcome.outcome")?;
        unique_non_blank(&self.artifact_refs, "observe.outcome.artifact_refs")?;
        unique_non_blank(&self.effect_refs, "observe.outcome.effect_refs")?;
        unique_non_blank(&self.verifier_run_refs, "observe.outcome.verifier_run_refs")
    }
}

/// Public influence classes; none imply hidden-reasoning access.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InfluenceClass {
    /// Memory changed the next public action.
    ChangedAction,
    /// Memory changed the selected verifier.
    ChangedVerifier,
    /// Memory prevented a repeated public failure.
    PreventedFailure,
    /// Memory was visible but did not affect the public next step.
    SeenButNotUsed,
    /// Memory was loaded without a measured public delta.
    LoadedWithoutDelta,
    /// Memory was suppressed as stale.
    SuppressedAsStale,
    /// Memory was suppressed as wrong-scope.
    SuppressedAsWrongScope,
}

/// Influence acknowledgement used by both canonical observe and the alias.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInfluenceAcknowledgement {
    /// Exact delivered memory handle.
    pub memory_handle: String,
    /// Bounded public influence class.
    pub influence_class: InfluenceClass,
    /// Applicable public action, verification, or outcome reference.
    pub downstream_public_ref: Option<String>,
}

impl MemoryInfluenceAcknowledgement {
    fn validate(&self) -> Result<(), ContractViolation> {
        non_blank(&self.memory_handle, "observe.influence_ack.memory_handle")?;
        optional_non_blank(
            self.downstream_public_ref.as_deref(),
            "observe.influence_ack.downstream_public_ref",
        )?;
        if matches!(
            self.influence_class,
            InfluenceClass::ChangedAction
                | InfluenceClass::ChangedVerifier
                | InfluenceClass::PreventedFailure
        ) && self.downstream_public_ref.is_none()
        {
            return Err(ContractViolation::InvalidField {
                field: "observe.influence_ack.downstream_public_ref",
                reason: "is required for a claimed public action/verifier/outcome delta",
            });
        }
        Ok(())
    }
}

/// Caller contribution used to request a prefilled `ActionFrame`.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActInput {
    /// Public action intent.
    pub intent: String,
    /// Expected observable fixed before the action.
    pub expected_observable: String,
    /// Remaining material uncertainty.
    pub remaining_uncertainty: String,
    /// Requested affected resources; authority is not accepted here.
    #[serde(default)]
    pub affected_resources: Vec<String>,
}

impl ActInput {
    fn validate(&self) -> Result<(), ContractViolation> {
        non_blank(&self.intent, "act.intent")?;
        non_blank(&self.expected_observable, "act.expected_observable")?;
        non_blank(&self.remaining_uncertainty, "act.remaining_uncertainty")?;
        unique_non_blank(&self.affected_resources, "act.affected_resources")
    }
}

/// Closed verification intents, not executable shell strings.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerifyIntent {
    /// Fast crate verifier.
    CrateFast,
    /// Component contract/conformance verifier.
    ComponentConformance,
    /// Deterministic simulation replay.
    SimReplay,
    /// Structured trace inspection.
    TraceInspect,
}

/// Verification request; it cannot carry a caller verdict.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyInput {
    /// Admitted verification intent.
    pub intent: VerifyIntent,
    /// Immutable artifacts to verify.
    pub artifact_refs: Vec<String>,
    /// Exact verifier/instrument profile revision.
    pub verifier_profile_ref: String,
}

impl VerifyInput {
    fn validate(&self) -> Result<(), ContractViolation> {
        if self.artifact_refs.is_empty() {
            return Err(ContractViolation::InvalidField {
                field: "verify.artifact_refs",
                reason: "must contain at least one artifact",
            });
        }
        unique_non_blank(&self.artifact_refs, "verify.artifact_refs")?;
        non_blank(&self.verifier_profile_ref, "verify.verifier_profile_ref")
    }
}

/// Exact execution-fabric operations.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoordinateInput {
    /// Create a bounded work item/attempt.
    Delegate(DelegateRequest),
    /// Request independent review over a sealed packet.
    Audit(AuditRequest),
    /// Compare isolated candidates by deterministic criteria.
    Compare(CompareRequest),
    /// Await durable run/job change.
    Wait(JobReference),
    /// Inspect run lineage/evidence/route/capacity.
    Inspect(JobReference),
    /// Cancel or reconcile a run/subtree.
    Cancel(CancelRequest),
    /// Send a durable mailbox/attention response.
    Send(SendRequest),
}

impl CoordinateInput {
    fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::Delegate(value) => value.validate(),
            Self::Audit(value) => value.validate(),
            Self::Compare(value) => value.validate(),
            Self::Wait(value) | Self::Inspect(value) => value.validate(),
            Self::Cancel(value) => value.validate(),
            Self::Send(value) => value.validate(),
        }
    }
}

/// Bounded delegation without route/vendor knobs.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegateRequest {
    /// Bounded goal.
    pub goal: String,
    /// Owned artifact/resource scope.
    pub owned_resources: Vec<String>,
    /// Expected result contract.
    pub expected_result: String,
}

impl DelegateRequest {
    fn validate(&self) -> Result<(), ContractViolation> {
        non_blank(&self.goal, "coordinate.delegate.goal")?;
        if self.owned_resources.is_empty() {
            return Err(ContractViolation::InvalidField {
                field: "coordinate.delegate.owned_resources",
                reason: "must contain at least one owned resource",
            });
        }
        unique_non_blank(&self.owned_resources, "coordinate.delegate.owned_resources")?;
        non_blank(&self.expected_result, "coordinate.delegate.expected_result")
    }
}

/// Independent audit request over a sealed artifact packet.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRequest {
    /// Sealed artifact packet URI/ref.
    pub sealed_packet_ref: String,
    /// Evaluation contract revision.
    pub evaluation_contract_ref: String,
}

impl AuditRequest {
    fn validate(&self) -> Result<(), ContractViolation> {
        non_blank(
            &self.sealed_packet_ref,
            "coordinate.audit.sealed_packet_ref",
        )?;
        non_blank(
            &self.evaluation_contract_ref,
            "coordinate.audit.evaluation_contract_ref",
        )
    }
}

/// Isolated candidate comparison request.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompareRequest {
    /// Ordered candidate identities.
    pub candidate_refs: Vec<String>,
    /// Ordered deterministic criteria.
    pub criteria: Vec<String>,
}

impl CompareRequest {
    fn validate(&self) -> Result<(), ContractViolation> {
        if self.candidate_refs.len() < 2 {
            return Err(ContractViolation::InvalidField {
                field: "coordinate.compare.candidate_refs",
                reason: "must contain at least two candidates",
            });
        }
        unique_non_blank(&self.candidate_refs, "coordinate.compare.candidate_refs")?;
        if self.criteria.is_empty() {
            return Err(ContractViolation::InvalidField {
                field: "coordinate.compare.criteria",
                reason: "must contain at least one criterion",
            });
        }
        unique_non_blank(&self.criteria, "coordinate.compare.criteria")
    }
}

/// Durable run/job identity.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobReference {
    /// Durable ELIOT job identity.
    pub job_id: String,
    /// Last observed revision for optimistic waiting/inspection.
    pub expected_revision: u64,
}

impl JobReference {
    fn validate(&self) -> Result<(), ContractViolation> {
        non_blank(&self.job_id, "coordinate.job_id")?;
        positive(self.expected_revision, "coordinate.expected_revision")
    }
}

/// Durable cancellation request.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    /// Durable ELIOT job identity.
    pub job_id: String,
    /// Last observed revision.
    pub expected_revision: u64,
    /// Public cancellation reason.
    pub reason: String,
    /// Whether the owned descendant subtree is included.
    pub include_descendants: bool,
}

impl CancelRequest {
    fn validate(&self) -> Result<(), ContractViolation> {
        non_blank(&self.job_id, "coordinate.cancel.job_id")?;
        positive(
            self.expected_revision,
            "coordinate.cancel.expected_revision",
        )?;
        non_blank(&self.reason, "coordinate.cancel.reason")
    }
}

/// Durable mailbox/attention response.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    /// Durable recipient handle.
    pub recipient_ref: String,
    /// Public structured message.
    pub message: Value,
    /// Causal predecessor refs.
    #[serde(default)]
    pub predecessor_refs: Vec<String>,
}

impl SendRequest {
    fn validate(&self) -> Result<(), ContractViolation> {
        non_blank(&self.recipient_ref, "coordinate.send.recipient_ref")?;
        if self.message.is_null() {
            return Err(ContractViolation::InvalidField {
                field: "coordinate.send.message",
                reason: "must not be null",
            });
        }
        unique_non_blank(&self.predecessor_refs, "coordinate.send.predecessor_refs")
    }
}

/// Candidate-only public finish input. There is no `CompletionProof` field.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishAttemptDraft {
    /// Task named by the request metadata and finish candidate.
    pub task_id: String,
    /// Expected current task revision.
    pub expected_task_revision: u64,
    /// Requested outcome candidate, not a decision.
    pub requested_outcome: RequestedFinishOutcome,
    /// Immutable artifact handles.
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    /// Observation handles.
    #[serde(default)]
    pub observation_refs: Vec<String>,
    /// Executed verifier-run handles.
    #[serde(default)]
    pub verifier_run_refs: Vec<String>,
    /// Unknowns disclosed by the caller.
    #[serde(default)]
    pub remaining_unknowns_declared_by_caller: Vec<String>,
    /// Public rationale candidate.
    pub rationale_candidate: String,
}

impl FinishAttemptDraft {
    fn validate(&self) -> Result<(), ContractViolation> {
        non_blank(&self.task_id, "finish.task_id")?;
        positive(self.expected_task_revision, "finish.expected_task_revision")?;
        unique_non_blank(&self.artifact_refs, "finish.artifact_refs")?;
        unique_non_blank(&self.observation_refs, "finish.observation_refs")?;
        unique_non_blank(&self.verifier_run_refs, "finish.verifier_run_refs")?;
        unique_non_blank(
            &self.remaining_unknowns_declared_by_caller,
            "finish.remaining_unknowns_declared_by_caller",
        )?;
        non_blank(&self.rationale_candidate, "finish.rationale_candidate")
    }
}

/// Caller-requested finish outcome. The Governor derives the actual outcome.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestedFinishOutcome {
    /// Request evaluation for complete work.
    CompleteCandidate,
    /// Declare partial work.
    Partial,
    /// Declare a blocker.
    Blocked,
    /// Declare a verification failure.
    FailedVerification,
    /// Declare degraded proof.
    DegradedNoProof,
    /// Declare that finishing would be unsafe.
    UnsafeToFinish,
    /// Declare cancellation.
    Cancelled,
    /// Declare supersession.
    Superseded,
}

/// Contract-level validation failure before the Kernel/Governor port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContractViolation {
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
}

pub(crate) fn validate_proof_ceiling(value: ProofCeiling) -> Result<(), ContractViolation> {
    if value.is_at_most(ProofCeiling::ScopedVerification) {
        Ok(())
    } else {
        Err(ContractViolation::InvalidField {
            field: "response.proof_ceiling",
            reason: "MCP projections cannot claim an external-effect or completion ceiling",
        })
    }
}

fn non_blank(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ContractViolation::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn optional_non_blank(value: Option<&str>, field: &'static str) -> Result<(), ContractViolation> {
    value.map_or(Ok(()), |value| non_blank(value, field))
}

fn unique_non_blank(values: &[String], field: &'static str) -> Result<(), ContractViolation> {
    let mut seen = BTreeSet::new();
    for value in values {
        non_blank(value, field)?;
        if !seen.insert(value) {
            return Err(ContractViolation::InvalidField {
                field,
                reason: "must not contain duplicates",
            });
        }
    }
    Ok(())
}

fn positive(value: u64, field: &'static str) -> Result<(), ContractViolation> {
    if value == 0 {
        Err(ContractViolation::InvalidField {
            field,
            reason: "must be greater than zero",
        })
    } else {
        Ok(())
    }
}

/// Top-level protected envelope keys. Duplicates of these keys are rejected
/// before any `Value` map collapse, including escape-equivalent forms.
pub const PROTECTED_ENVELOPE_KEYS: [&str; 6] = [
    "protocol_version",
    "session",
    "identity",
    "security",
    "client_capabilities",
    "tool",
];

/// Explicitly admitted tool variants, including the sole legacy alias.
/// Unknown variants are rejected before collapse; no trial decoding is used.
pub const ADMITTED_TOOL_NAMES: [&str; 9] = [
    "eliot.state",
    "eliot.packet",
    "eliot.observe",
    "eliot.query",
    "eliot.act",
    "eliot.verify",
    "eliot.coordinate",
    "eliot.finish",
    "eliot.memory_use",
];

/// Maximum decoded control-name length echoed in diagnostics. Longer names
/// are truncated so diagnostics never echo protected bodies.
const MAX_CONTROL_NAME_CHARS: usize = 64;

/// Maximum JSON nesting depth admitted by the raw protected scan.
const MAX_RAW_DEPTH: usize = 64;

/// Typed raw-ingress rejection. Diagnostics carry only bounded control names
/// and static reasons; they never echo secrets or protected bodies.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TypedRejection {
    /// A duplicate object key was observed in the raw bytes.
    #[error("DUPLICATE_PROTECTED_KEY: {key}")]
    DuplicateKey {
        /// Bounded decoded duplicate key name.
        key: String,
    },
    /// An explicitly unlisted protected variant was observed.
    #[error("UNKNOWN_PROTECTED_VARIANT: {variant}")]
    UnknownVariant {
        /// Bounded variant name (tool selector).
        variant: String,
    },
    /// Raw bytes are not a well-formed protected envelope.
    #[error("MALFORMED_PROTECTED_REQUEST: {reason}")]
    Malformed {
        /// Static redacted reason.
        reason: &'static str,
    },
    /// Raw bytes exceed the hard bound.
    #[error("PROTECTED_REQUEST_OVERSIZED: {actual} exceeds {maximum}")]
    Oversized {
        /// Observed byte length.
        actual: usize,
        /// Hard maximum.
        maximum: usize,
    },
}

/// Decodes one protected application request from raw bytes.
///
/// The raw scan rejects duplicate object keys (comparing fully decoded key
/// strings, so escape-equivalent forms such as `"tool"` and
/// `"\u0074ool"` conflict) before any `serde_json::Value` map collapse.
/// Unknown tool variants from the explicit admission list are rejected
/// before typed construction. Supported compatibility (`eliot.memory_use`)
/// is admitted explicitly; no trial decoding is performed. Opaque tool data
/// (`content`/`message` values) remains inert `Value` and is never consulted
/// for selector, identity, policy, authority, effect-ceiling, or `Finish`
/// routing.
pub fn decode_protected_request_bytes(bytes: &[u8]) -> Result<ApplicationRequest, TypedRejection> {
    if bytes.len() > HARD_STRUCTURED_RESPONSE_BYTES {
        return Err(TypedRejection::Oversized {
            actual: bytes.len(),
            maximum: HARD_STRUCTURED_RESPONSE_BYTES,
        });
    }
    reject_duplicate_keys(bytes)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| TypedRejection::Malformed {
        reason: "request is not well-formed JSON",
    })?;
    if let Some(variant) = tool_variant_name(&value)
        && !ADMITTED_TOOL_NAMES.contains(&variant.as_str())
    {
        return Err(TypedRejection::UnknownVariant {
            variant: bound_control_name(&variant),
        });
    }
    serde_json::from_slice::<ApplicationRequest>(bytes).map_err(|error| {
        let message = error.to_string();
        if message.starts_with("duplicate field") {
            TypedRejection::DuplicateKey {
                key: bound_control_name(&duplicate_field_name(&message)),
            }
        } else if message.starts_with("unknown variant") {
            TypedRejection::UnknownVariant {
                variant: bound_control_name(&unknown_variant_name(&message)),
            }
        } else {
            TypedRejection::Malformed {
                reason: "request failed protected typed decoding",
            }
        }
    })
}

fn bound_control_name(value: &str) -> String {
    value.chars().take(MAX_CONTROL_NAME_CHARS).collect()
}

fn duplicate_field_name(message: &str) -> String {
    field_between_backticks(message).unwrap_or_else(|| "request".to_owned())
}

fn unknown_variant_name(message: &str) -> String {
    field_between_backticks(message).unwrap_or_else(|| "tool.name".to_owned())
}

fn field_between_backticks(message: &str) -> Option<String> {
    let start = message.find('`')?;
    let rest = &message[start + 1..];
    let end = rest.find('`')?;
    Some(rest[..end].to_owned())
}

fn tool_variant_name(value: &Value) -> Option<String> {
    value.get("tool")?.get("name")?.as_str().map(str::to_owned)
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), TypedRejection> {
    let text = std::str::from_utf8(bytes).map_err(|_| TypedRejection::Malformed {
        reason: "request is not valid UTF-8 JSON",
    })?;
    let input = text.as_bytes();
    let mut pos = skip_ws(input, 0);
    pos = parse_value(input, pos, 0)?;
    pos = skip_ws(input, pos);
    if pos != input.len() {
        return Err(TypedRejection::Malformed {
            reason: "request has trailing bytes after the envelope",
        });
    }
    Ok(())
}

fn skip_ws(input: &[u8], mut pos: usize) -> usize {
    while pos < input.len() && matches!(input[pos], b' ' | b'\n' | b'\r' | b'\t') {
        pos += 1;
    }
    pos
}

fn parse_value(input: &[u8], pos: usize, depth: usize) -> Result<usize, TypedRejection> {
    if depth > MAX_RAW_DEPTH {
        return Err(TypedRejection::Malformed {
            reason: "request nesting exceeds the hard bound",
        });
    }
    let pos = skip_ws(input, pos);
    let byte = input.get(pos).ok_or(TypedRejection::Malformed {
        reason: "request ends inside a value",
    })?;
    match byte {
        b'{' => parse_object(input, pos, depth),
        b'[' => parse_array(input, pos, depth),
        b'"' => {
            let (_, next) = parse_string(input, pos)?;
            Ok(next)
        }
        b't' => parse_literal(input, pos, "true"),
        b'f' => parse_literal(input, pos, "false"),
        b'n' => parse_literal(input, pos, "null"),
        b'-' | b'0'..=b'9' => parse_number(input, pos),
        _ => Err(TypedRejection::Malformed {
            reason: "request contains an unexpected value",
        }),
    }
}

fn parse_object(input: &[u8], pos: usize, depth: usize) -> Result<usize, TypedRejection> {
    debug_assert_eq!(input.get(pos), Some(&b'{'));
    let mut pos = skip_ws(input, pos + 1);
    if input.get(pos) == Some(&b'}') {
        return Ok(pos + 1);
    }
    let mut seen = BTreeSet::new();
    loop {
        let pos_ws = skip_ws(input, pos);
        if input.get(pos_ws) != Some(&b'"') {
            return Err(TypedRejection::Malformed {
                reason: "object keys must be strings",
            });
        }
        let (key, next) = parse_string(input, pos_ws)?;
        if !seen.insert(key.clone()) {
            return Err(TypedRejection::DuplicateKey {
                key: bound_control_name(&key),
            });
        }
        pos = skip_ws(input, next);
        if input.get(pos) != Some(&b':') {
            return Err(TypedRejection::Malformed {
                reason: "object key is missing its separator",
            });
        }
        pos = parse_value(input, pos + 1, depth + 1)?;
        pos = skip_ws(input, pos);
        match input.get(pos) {
            Some(b',') => {
                pos = skip_ws(input, pos + 1);
                if input.get(pos) == Some(&b'}') {
                    return Err(TypedRejection::Malformed {
                        reason: "object has a trailing separator",
                    });
                }
            }
            Some(b'}') => return Ok(pos + 1),
            _ => {
                return Err(TypedRejection::Malformed {
                    reason: "object is not closed",
                });
            }
        }
    }
}

fn parse_array(input: &[u8], pos: usize, depth: usize) -> Result<usize, TypedRejection> {
    debug_assert_eq!(input.get(pos), Some(&b'['));
    let mut pos = skip_ws(input, pos + 1);
    if input.get(pos) == Some(&b']') {
        return Ok(pos + 1);
    }
    loop {
        pos = parse_value(input, pos, depth + 1)?;
        pos = skip_ws(input, pos);
        match input.get(pos) {
            Some(b',') => {
                pos = skip_ws(input, pos + 1);
                if input.get(pos) == Some(&b']') {
                    return Err(TypedRejection::Malformed {
                        reason: "array has a trailing separator",
                    });
                }
            }
            Some(b']') => return Ok(pos + 1),
            _ => {
                return Err(TypedRejection::Malformed {
                    reason: "array is not closed",
                });
            }
        }
    }
}

fn parse_string(input: &[u8], pos: usize) -> Result<(String, usize), TypedRejection> {
    debug_assert_eq!(input.get(pos), Some(&b'"'));
    let mut out = String::new();
    let mut pos = pos + 1;
    while let Some(byte) = input.get(pos) {
        match byte {
            b'"' => return Ok((out, pos + 1)),
            b'\\' => {
                let (ch, next) = parse_escape(input, pos)?;
                out.push(ch);
                // Surrogate-pair escapes push a second char via replacement handling below.
                // `parse_escape` already combines pairs; push any trailing char it returns
                // through the single `ch` plus an optional second push encoded in `next`
                // as an extra step is unnecessary because pairs are combined inside.
                pos = next;
            }
            0x00..=0x1F => {
                return Err(TypedRejection::Malformed {
                    reason: "string contains an unescaped control character",
                });
            }
            _ => {
                let start = pos;
                while pos < input.len()
                    && input[pos] >= 0x20
                    && input[pos] != b'"'
                    && input[pos] != b'\\'
                {
                    pos += 1;
                }
                let chunk = std::str::from_utf8(&input[start..pos]).map_err(|_| {
                    TypedRejection::Malformed {
                        reason: "string is not valid UTF-8",
                    }
                })?;
                out.push_str(chunk);
            }
        }
    }
    Err(TypedRejection::Malformed {
        reason: "string is not terminated",
    })
}

fn parse_escape(input: &[u8], pos: usize) -> Result<(char, usize), TypedRejection> {
    debug_assert_eq!(input.get(pos), Some(&b'\\'));
    let esc = *input.get(pos + 1).ok_or(TypedRejection::Malformed {
        reason: "escape sequence is truncated",
    })?;
    match esc {
        b'"' => Ok(('"', pos + 2)),
        b'\\' => Ok(('\\', pos + 2)),
        b'/' => Ok(('/', pos + 2)),
        b'b' => Ok(('\u{0008}', pos + 2)),
        b'f' => Ok(('\u{000C}', pos + 2)),
        b'n' => Ok(('\n', pos + 2)),
        b'r' => Ok(('\r', pos + 2)),
        b't' => Ok(('\t', pos + 2)),
        b'u' => parse_unicode_escape(input, pos),
        _ => Err(TypedRejection::Malformed {
            reason: "escape sequence is not supported",
        }),
    }
}

fn parse_unicode_escape(input: &[u8], pos: usize) -> Result<(char, usize), TypedRejection> {
    let first = parse_hex4(input, pos + 2)?;
    let mut next = pos + 6;
    let code = if (0xD800..0xDC00).contains(&first) {
        if input.get(next) == Some(&b'\\') && input.get(next + 1) == Some(&b'u') {
            let second = parse_hex4(input, next + 2)?;
            if !(0xDC00..0xE000).contains(&second) {
                return Err(TypedRejection::Malformed {
                    reason: "lone surrogate escape is not allowed",
                });
            }
            next += 6;
            0x10000 + ((u32::from(first - 0xD800) << 10) | u32::from(second - 0xDC00))
        } else {
            return Err(TypedRejection::Malformed {
                reason: "lone surrogate escape is not allowed",
            });
        }
    } else {
        if (0xDC00..0xE000).contains(&first) {
            return Err(TypedRejection::Malformed {
                reason: "lone surrogate escape is not allowed",
            });
        }
        u32::from(first)
    };
    char::from_u32(code).map_or(
        Err(TypedRejection::Malformed {
            reason: "unicode escape is not a valid character",
        }),
        |ch| Ok((ch, next)),
    )
}

fn parse_hex4(input: &[u8], pos: usize) -> Result<u16, TypedRejection> {
    if pos + 4 > input.len() {
        return Err(TypedRejection::Malformed {
            reason: "unicode escape is truncated",
        });
    }
    let mut value: u16 = 0;
    for byte in &input[pos..pos + 4] {
        let digit = match byte {
            b'0'..=b'9' => u16::from(byte - b'0'),
            b'a'..=b'f' => u16::from(byte - b'a') + 10,
            b'A'..=b'F' => u16::from(byte - b'A') + 10,
            _ => {
                return Err(TypedRejection::Malformed {
                    reason: "unicode escape is not hexadecimal",
                });
            }
        };
        value = value * 16 + digit;
    }
    Ok(value)
}

fn parse_literal(
    input: &[u8],
    pos: usize,
    expected: &'static str,
) -> Result<usize, TypedRejection> {
    if input.len() >= pos + expected.len()
        && &input[pos..pos + expected.len()] == expected.as_bytes()
    {
        Ok(pos + expected.len())
    } else {
        Err(TypedRejection::Malformed {
            reason: "literal is not well-formed",
        })
    }
}

fn parse_number(input: &[u8], mut pos: usize) -> Result<usize, TypedRejection> {
    if input.get(pos) == Some(&b'-') {
        pos += 1;
    }
    match input.get(pos) {
        Some(b'0') => {
            pos += 1;
        }
        Some(b'1'..=b'9') => {
            while matches!(input.get(pos), Some(b'0'..=b'9')) {
                pos += 1;
            }
        }
        _ => {
            return Err(TypedRejection::Malformed {
                reason: "number is not well-formed",
            });
        }
    }
    if input.get(pos) == Some(&b'.') {
        pos += 1;
        if !matches!(input.get(pos), Some(b'0'..=b'9')) {
            return Err(TypedRejection::Malformed {
                reason: "number is not well-formed",
            });
        }
        while matches!(input.get(pos), Some(b'0'..=b'9')) {
            pos += 1;
        }
    }
    if matches!(input.get(pos), Some(b'e' | b'E')) {
        pos += 1;
        if matches!(input.get(pos), Some(b'+' | b'-')) {
            pos += 1;
        }
        if !matches!(input.get(pos), Some(b'0'..=b'9')) {
            return Err(TypedRejection::Malformed {
                reason: "number is not well-formed",
            });
        }
        while matches!(input.get(pos), Some(b'0'..=b'9')) {
            pos += 1;
        }
    }
    Ok(pos)
}
