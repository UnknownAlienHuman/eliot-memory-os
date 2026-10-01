//! Versioned cognitive-memory, responsibility-routing, autonomy, and operator contracts.

use crate::semantic_memory::{
    CognitiveFailureLocalizationReport, CognitiveTransferLabReport, ExperienceBrief,
    ExperienceCase, ExperiencePattern, MemoryApplicabilityDecision, MemoryCorpusProfile,
    NegativeTransferRecord, TaskMeaningFrame,
};
use crate::{
    AgentResultDisposition, AgentResultEnvelope, AgentSessionHostBinding, AgentSessionId,
    BackupInventoryEntry, ClaimCard, ClaimSummary, CompletionProof, ControllerLease,
    IncidentRecord, MemoryLifecyclePacketView, MemoryRevision, OperationJob,
    ProceduralSkillPacketView, ProjectId, RecoveryAction, TaskContract, TaskId, TaskRoleLease,
    VerificationResult, WorkConflict, WorkItem, WorkItemId, WorkLease, WorktreeLease,
    WriteReceiptRef,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;
use time::OffsetDateTime;

pub const OPERATOR_SCHEMA_VERSION: &str = "eliot-operator-contract-v1";
pub const OPERATOR_IPC_PROTOCOL_VERSION: &str = "eliot-ipc-l3-v2";
pub const OPERATOR_CONTRACT_MANIFEST: &str = include_str!("../schema/operator-contract-v1.json");

pub fn operator_contract_hash() -> String {
    operator_contract_hash_for_manifest(OPERATOR_CONTRACT_MANIFEST)
}

fn operator_contract_hash_for_manifest(manifest: &str) -> String {
    let parsed = match serde_json::from_str::<Value>(manifest) {
        Ok(parsed) => parsed,
        Err(error) => panic!("embedded operator contract manifest must be valid JSON: {error}"),
    };
    let canonical = canonicalize_json_value(&parsed);
    let canonical_bytes = match serde_json::to_vec(&canonical) {
        Ok(bytes) => bytes,
        Err(error) => panic!("operator contract JSON must serialize canonically: {error}"),
    };
    blake3::hash(&canonical_bytes).to_hex().to_string()
}

fn canonicalize_json_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_json_value).collect()),
        Value::Object(fields) => {
            let mut entries = fields.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.clone(), canonicalize_json_value(value)))
                    .collect(),
            )
        }
        scalar => scalar.clone(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketQualityResult {
    Sufficient,
    Degraded,
    Insufficient,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketQualityReport {
    pub packet_id: String,
    pub task_id: String,
    pub revision_fence: MemoryRevision,
    pub structured_bytes: usize,
    pub estimated_tokens: usize,
    pub task_frame_present: bool,
    pub current_truth_coverage: f32,
    pub causal_bridge_hops: usize,
    pub causal_bridge_missing_hops: Vec<String>,
    pub negative_memory_checked: bool,
    pub exact_atoms_count: usize,
    pub material_unknowns: usize,
    pub verifier_present: bool,
    pub stale_items_suppressed: usize,
    pub wrong_scope_items_suppressed: usize,
    pub tool_schema_bytes_visible: usize,
    pub instruction_hotset_size: usize,
    pub signal_density: f32,
    pub result: PacketQualityResult,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentTruthSnapshot {
    pub project_id: ProjectId,
    pub task_id: String,
    pub branch: String,
    pub commit: String,
    pub environment: Vec<String>,
    pub revision_fence: MemoryRevision,
    #[serde(with = "time::serde::rfc3339")]
    pub captured_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalBridgeHop {
    pub from: String,
    pub relation: String,
    pub to: String,
    pub evidence_ref: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpistemicPacketState {
    pub supported: Vec<String>,
    pub assumed: Vec<String>,
    pub conflicted: Vec<String>,
    pub unknown: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionLocalitySuffix {
    pub exact_load_bearing_atoms: Vec<String>,
    pub open_unknowns: Vec<String>,
    pub cheapest_discriminative_probes: Vec<String>,
    pub responsibility_contour_route_refs: Vec<String>,
    pub next_allowed_action: String,
    pub expected_observable: String,
    pub verifier: String,
    pub stop_condition: String,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictionConfidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaivedInvariant {
    pub invariant_ref: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialPacketFrame {
    pub acceptance_items: Vec<String>,
    pub environment: Vec<String>,
    pub active_plan: Vec<String>,
    pub completed_work: Vec<String>,
    pub killed_paths: Vec<String>,
    pub causal_bridge: Vec<CausalBridgeHop>,
    pub negative_memory_checked: bool,
    pub exact_load_bearing_atoms: Vec<String>,
    pub cheapest_discriminative_probes: Vec<String>,
    pub responsibility_contour_route_refs: Vec<String>,
    pub next_allowed_action: String,
    pub expected_observable: String,
    pub verifier: String,
    pub stop_condition: String,
    pub tool_schema_bytes_visible: usize,
    pub instruction_hotset_size: usize,
    /// BREAKING CANDIDATE, deliberately NOT corrected in this increment (#708).
    ///
    /// `#[serde(default)]` is RETAINED on the five prediction/invariant fields
    /// because removing it is *not* a compatible requiredness correction on this
    /// wire. These five fields are agent-supplied input on the published
    /// `eliot.packet` tool, and this type derives `JsonSchema`, so the published
    /// `required` set is generated from the `serde` attributes:
    /// `mcp_contract.rs::compile_packet_input_schema` (`:150`) serializes
    /// `schemars::schema_for!(CompilePacketToolInput)`, whose `material_frame`
    /// subschema is generated from this struct. `schemars` excludes
    /// `#[serde(default)]` fields from `required`; removing `default` therefore
    /// *adds* five names to the published `required` set, which changes
    /// `tools/list` output for every connected agent.
    ///
    /// Two independent in-tree facts confirm the required set does NOT already
    /// contain them, and that a same-file edit here would break its own owner:
    ///
    /// 1. `crates/eliot-types/tests/ul_contract_schema.rs::t01_schema_required_set_is_exact`
    ///    pins the exact `material_frame` required set as 16 names, and these five
    ///    are not among them.
    /// 2. `mcp_contract.rs::compile_packet_minimal_example` (`:155`) — the
    ///    `minimal_valid_example` this crate's own owner returns to agents on
    ///    invalid tool input (`crates/eliot-app/src/mcp_stdio/input_validation.rs:28`
    ///    and `:43`, `crates/eliot-app/src/mcp_stdio/task_handlers.rs:206`) —
    ///    omits all five keys, and
    ///    `crates/eliot-types/tests/ul_contract_schema.rs::t95`-path decode
    ///    (`serde_json::from_value::<CompilePacketToolInput>(minimal)`, `:95`)
    ///    requires that example to keep decoding. Making these fields required
    ///    would make the owner ship an example its own decoder rejects.
    ///
    /// W4 disposition: this is NOT an invented version field and NOT a
    /// trial-accept compensation. The named/versioned boundary for this wire
    /// is the `eliot.packet` tool contract revision owned by `eliot-mcp`
    /// (`crates/surfaces/eliot-mcp/src/schema.rs::descriptor` ->
    /// `canonical_tool_schemas` -> `published_mcp_tool_surface` -> `tools/list`),
    /// which is outside this issue's exclusive mutable scope and needs its own
    /// integration turn. Required owner: `crates/surfaces/eliot-mcp` plus the
    /// `eliot.packet` catalogue bump; the exact consumer change needed is a
    /// `material_frame` `required` bump in the published schema together with a
    /// `compile_packet_minimal_example` that carries the five keys. Base SHA is
    /// recorded in the #708 report.
    ///
    /// Proof ceiling: source-attested only. No test was executed in this lane.
    #[serde(default)]
    pub invariant_refs: Vec<String>,
    /// See `invariant_refs` above: one breaking-candidate decision covers all
    /// five prediction/invariant fields on this record (#708).
    #[serde(default)]
    pub waived_invariants: Vec<WaivedInvariant>,
    /// See `invariant_refs` above: one breaking-candidate decision covers all
    /// five prediction/invariant fields on this record (#708).
    #[serde(default)]
    pub prediction_confidence: Option<PredictionConfidence>,
    /// See `invariant_refs` above: one breaking-candidate decision covers all
    /// five prediction/invariant fields on this record (#708).
    #[serde(default)]
    pub predicted_changed_paths: Vec<String>,
    /// See `invariant_refs` above: one breaking-candidate decision covers all
    /// five prediction/invariant fields on this record (#708).
    #[serde(default)]
    pub predicted_failing_verifiers: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnderstandingOutcome {
    Validated,
    Revised,
    Refuted,
    Inconclusive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnderstandingOutcomeRecord {
    pub task_id: TaskId,
    pub session_id: AgentSessionId,
    pub packet_id: String,
    pub expected_owner_or_module: String,
    pub selected_owner_or_module: String,
    pub proposed_causal_bridge: Vec<CausalBridgeHop>,
    pub exact_handles_used: Vec<String>,
    pub predicted_observable: String,
    pub selected_probe_or_action: String,
    pub selected_write_set: Vec<String>,
    pub selected_verifier: String,
    pub actual_changed_artifacts: Vec<String>,
    pub actual_observation: String,
    pub verifier_result: VerificationResult,
    pub causal_bridge_validated: bool,
    pub wrong_path_attempts: u32,
    pub avoidable_tool_calls: u32,
    pub revision_required: bool,
    pub outcome: UnderstandingOutcome,
    pub evidence_refs: Vec<String>,
    /// A missing receipt stays absent; absence never authenticates canonical storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

/// Epistemic state of a causal edge. An intervention outcome is recorded
/// separately and does not itself choose a new status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CausalEdgeStatus {
    Hypothetical,
    Supported,
    ObservedUnderIntervention,
}

/// The assigned next check for a causal candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "description")]
pub enum CausalCheckAssignment {
    VerifierWorkItem(WorkItemId),
    BoundedInquiry(String),
}

/// I14.1 work class a causal discriminative check is submitted through.
///
/// Both assigned-check forms — a verifier work item and a bounded inquiry —
/// route through `verification`, so the check that makes a causal claim
/// load-bearing for a Critical action stays a verification-class work unit.
pub const CAUSAL_DISCRIMINATIVE_CHECK_WORK_CLASS: &str = "verification";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CausalCandidateValidationError {
    #[error("material causal candidate is missing A6.5 field `{field}`")]
    MissingA65Field { field: &'static str },
    #[error("A6.5 field `{field}` contains a blank list entry")]
    EmptyA65ListEntry { field: &'static str },
    #[error("candidate requires a rival explanation or rationale for none")]
    MissingRivalOrRationale,
    #[error("candidate contains a blank no-plausible-rival rationale")]
    EmptyNoPlausibleRivalRationale,
    #[error("causal candidate calibration must be nonblank")]
    MissingCalibration,
    #[error("candidate contains an empty rival explanation")]
    EmptyRivalExplanation,
    #[error("candidate contains an empty assigned bounded inquiry")]
    EmptyBoundedInquiry,
    #[error("Critical-action candidate requires an assigned verifier or bounded inquiry")]
    MissingCriticalCheck,
    #[error("intervention outcome is linked to another candidate")]
    OutcomeCandidateMismatch,
    #[error("intervention outcome has an empty observation or verifier/artifact")]
    EmptyOutcomeEvidence,
    #[error("intervention outcome before-state does not match the candidate's current state")]
    OutcomeBeforeStateMismatch,
    #[error("intervention outcome contains an empty rival explanation")]
    EmptyOutcomeRival,
    #[error("rival removal requires explicit update evidence")]
    MissingRivalUpdateEvidence,
    #[error("intervention outcome assessment is incomplete")]
    IncompleteOutcomeAssessment,
    #[error("existing intervention outcome history is invalid or discontinuous")]
    InvalidOutcomeHistory,
}

/// A causal outcome preserves both the previous and revised candidate state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalInterventionOutcomeRecord {
    pub candidate_id: String,
    pub observed_outcome: String,
    pub verifier_or_artifact: String,
    /// Explicit interpretation input, independent of recording the outcome.
    pub assessment_basis: String,
    pub status_before: CausalEdgeStatus,
    pub status_after: CausalEdgeStatus,
    pub rival_set_before: Vec<String>,
    pub rival_set_after: Vec<String>,
    pub no_plausible_rival_rationale_before: Option<String>,
    pub no_plausible_rival_rationale_after: Option<String>,
    /// Required when an assessment removes any previously recorded rival.
    pub rival_update_evidence: Vec<String>,
    pub calibration_before: String,
    pub calibration_after: String,
    pub transfer_boundary_before: String,
    pub transfer_boundary_after: String,
}

/// Decision-material causal model with its intervention history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalCandidate {
    pub candidate_id: String,
    pub mechanism: String,
    pub intervention: String,
    pub predicted_observable: String,
    pub counterfactual: String,
    pub possible_confounders: Vec<String>,
    pub interacting_causes: Vec<String>,
    pub temporal_lag: String,
    pub abstraction_level: String,
    pub rival_explanations: Vec<String>,
    pub no_plausible_rival_rationale: Option<String>,
    pub transfer_boundary: String,
    pub edge_status: CausalEdgeStatus,
    pub calibration: String,
    /// Explicit presence for the assigned check and the intervention history
    /// (#708).
    ///
    /// `assigned_check` is the verifier-or-bounded-inquiry binding a critical
    /// action depends on: `validate_for_critical_action` already treats `None`
    /// as "no check assigned" and refuses, so absence is meaningful and must be
    /// stated. Defaulting it let an omitted key decode as an unassigned check
    /// on a candidate that never declared one. `intervention_outcomes` is the
    /// append-only history `record_intervention_outcome` appends to; an absent
    /// key decoded as "no outcome was ever recorded", which `validate_intervention_history`
    /// then reads as a first-generation candidate. Both are now required keys;
    /// absence is a typed missing-field error rather than a manufactured fact.
    /// `CausalCandidate` has exactly one in-tree construction surface and no
    /// published schema, so this is a compatible requiredness correction with
    /// unchanged accepted and emitted bytes.
    pub assigned_check: Option<CausalCheckAssignment>,
    pub intervention_outcomes: Vec<CausalInterventionOutcomeRecord>,
}

impl CausalCandidate {
    /// Check the complete A6.5 record and validate any assigned check.
    pub fn validate_material(&self) -> Result<(), CausalCandidateValidationError> {
        for (field, value) in [
            ("candidate_id", self.candidate_id.as_str()),
            ("mechanism", self.mechanism.as_str()),
            ("intervention", self.intervention.as_str()),
            ("predicted_observable", self.predicted_observable.as_str()),
            ("counterfactual", self.counterfactual.as_str()),
            ("temporal_lag", self.temporal_lag.as_str()),
            ("abstraction_level", self.abstraction_level.as_str()),
            ("transfer_boundary", self.transfer_boundary.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(CausalCandidateValidationError::MissingA65Field { field });
            }
        }
        if self
            .possible_confounders
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(CausalCandidateValidationError::EmptyA65ListEntry {
                field: "possible_confounders",
            });
        }
        if self
            .interacting_causes
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(CausalCandidateValidationError::EmptyA65ListEntry {
                field: "interacting_causes",
            });
        }

        if self.rival_explanations.is_empty() {
            if self
                .no_plausible_rival_rationale
                .as_deref()
                .is_none_or(|rationale| rationale.trim().is_empty())
            {
                return Err(CausalCandidateValidationError::MissingRivalOrRationale);
            }
        } else if self
            .rival_explanations
            .iter()
            .any(|rival| rival.trim().is_empty())
        {
            return Err(CausalCandidateValidationError::EmptyRivalExplanation);
        }
        if self
            .no_plausible_rival_rationale
            .as_deref()
            .is_some_and(|rationale| rationale.trim().is_empty())
        {
            return Err(CausalCandidateValidationError::EmptyNoPlausibleRivalRationale);
        }
        if self.calibration.trim().is_empty() {
            return Err(CausalCandidateValidationError::MissingCalibration);
        }

        if let Some(CausalCheckAssignment::BoundedInquiry(description)) = &self.assigned_check
            && description.trim().is_empty()
        {
            return Err(CausalCandidateValidationError::EmptyBoundedInquiry);
        }

        self.validate_intervention_history()
    }

    /// Critical-action admission uses the same complete candidate prerequisites.
    pub fn validate_for_critical_action(&self) -> Result<(), CausalCandidateValidationError> {
        self.validate_material()?;
        if self.assigned_check.is_none() {
            return Err(CausalCandidateValidationError::MissingCriticalCheck);
        }
        Ok(())
    }

    /// Admit a causal claim as load-bearing for a Critical action and hand the
    /// dispatcher the assigned discriminative check with its work class.
    ///
    /// Runs the [`CausalCandidate::validate_for_critical_action`] gate — recorded
    /// predicted observable, rival explanation or explicit no-rival rationale,
    /// and assigned verifier or bounded inquiry — then returns the check bound
    /// to [`CAUSAL_DISCRIMINATIVE_CHECK_WORK_CLASS`], so submission stays in
    /// the I14.1 `verification` class whichever check form is assigned.
    pub fn critical_action_check(
        &self,
    ) -> Result<(&CausalCheckAssignment, &'static str), CausalCandidateValidationError> {
        self.validate_for_critical_action()?;
        match &self.assigned_check {
            Some(check) => Ok((check, CAUSAL_DISCRIMINATIVE_CHECK_WORK_CLASS)),
            None => Err(CausalCandidateValidationError::MissingCriticalCheck),
        }
    }

    /// Append an explicitly assessed intervention outcome and update current state atomically.
    pub fn record_intervention_outcome(
        &mut self,
        outcome: CausalInterventionOutcomeRecord,
    ) -> Result<(), CausalCandidateValidationError> {
        self.validate_material()?;
        if outcome.candidate_id != self.candidate_id {
            return Err(CausalCandidateValidationError::OutcomeCandidateMismatch);
        }
        if outcome.status_before != self.edge_status
            || outcome.rival_set_before != self.rival_explanations
            || outcome.no_plausible_rival_rationale_before != self.no_plausible_rival_rationale
            || outcome.calibration_before != self.calibration
            || outcome.transfer_boundary_before != self.transfer_boundary
        {
            return Err(CausalCandidateValidationError::OutcomeBeforeStateMismatch);
        }

        let mut next = self.clone();
        next.edge_status = outcome.status_after;
        next.rival_explanations.clone_from(&outcome.rival_set_after);
        next.no_plausible_rival_rationale
            .clone_from(&outcome.no_plausible_rival_rationale_after);
        next.calibration.clone_from(&outcome.calibration_after);
        next.transfer_boundary
            .clone_from(&outcome.transfer_boundary_after);
        next.intervention_outcomes.push(outcome);
        next.validate_material()?;
        *self = next;
        Ok(())
    }

    fn validate_intervention_history(&self) -> Result<(), CausalCandidateValidationError> {
        for (index, outcome) in self.intervention_outcomes.iter().enumerate() {
            if outcome.candidate_id != self.candidate_id {
                return Err(CausalCandidateValidationError::OutcomeCandidateMismatch);
            }
            if outcome.observed_outcome.trim().is_empty()
                || outcome.verifier_or_artifact.trim().is_empty()
            {
                return Err(CausalCandidateValidationError::EmptyOutcomeEvidence);
            }
            if outcome.assessment_basis.trim().is_empty()
                || outcome.calibration_before.trim().is_empty()
                || outcome.calibration_after.trim().is_empty()
                || outcome.transfer_boundary_before.trim().is_empty()
                || outcome.transfer_boundary_after.trim().is_empty()
            {
                return Err(CausalCandidateValidationError::IncompleteOutcomeAssessment);
            }
            if outcome
                .no_plausible_rival_rationale_before
                .as_deref()
                .is_some_and(|rationale| rationale.trim().is_empty())
                || outcome
                    .no_plausible_rival_rationale_after
                    .as_deref()
                    .is_some_and(|rationale| rationale.trim().is_empty())
            {
                return Err(CausalCandidateValidationError::EmptyNoPlausibleRivalRationale);
            }
            if (outcome.rival_set_before.is_empty()
                && outcome
                    .no_plausible_rival_rationale_before
                    .as_deref()
                    .is_none_or(|rationale| rationale.trim().is_empty()))
                || (outcome.rival_set_after.is_empty()
                    && outcome
                        .no_plausible_rival_rationale_after
                        .as_deref()
                        .is_none_or(|rationale| rationale.trim().is_empty()))
            {
                return Err(CausalCandidateValidationError::MissingRivalOrRationale);
            }
            if outcome
                .rival_set_before
                .iter()
                .chain(outcome.rival_set_after.iter())
                .any(|rival| rival.trim().is_empty())
            {
                return Err(CausalCandidateValidationError::EmptyOutcomeRival);
            }
            let removed_rival = outcome
                .rival_set_before
                .iter()
                .any(|rival| !outcome.rival_set_after.contains(rival));
            if removed_rival && outcome.rival_update_evidence.is_empty() {
                return Err(CausalCandidateValidationError::MissingRivalUpdateEvidence);
            }
            if outcome
                .rival_update_evidence
                .iter()
                .any(|evidence| evidence.trim().is_empty())
            {
                return Err(CausalCandidateValidationError::MissingRivalUpdateEvidence);
            }
            if let Some(previous) = index
                .checked_sub(1)
                .and_then(|previous_index| self.intervention_outcomes.get(previous_index))
                && (outcome.status_before != previous.status_after
                    || outcome.rival_set_before != previous.rival_set_after
                    || outcome.no_plausible_rival_rationale_before
                        != previous.no_plausible_rival_rationale_after
                    || outcome.calibration_before != previous.calibration_after
                    || outcome.transfer_boundary_before != previous.transfer_boundary_after)
            {
                return Err(CausalCandidateValidationError::InvalidOutcomeHistory);
            }
        }

        if let Some(last) = self.intervention_outcomes.last()
            && (last.status_after != self.edge_status
                || last.rival_set_after != self.rival_explanations
                || last.no_plausible_rival_rationale_after != self.no_plausible_rival_rationale
                || last.calibration_after != self.calibration
                || last.transfer_boundary_after != self.transfer_boundary)
        {
            return Err(CausalCandidateValidationError::InvalidOutcomeHistory);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAdmissionDecision {
    IncludeVerified,
    IncludeSupported,
    RequireRevalidation,
    PreserveConflict,
    SuppressStale,
    SuppressWrongScope,
    RejectTainted,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryInfluenceClass {
    UsedAndChangedAction,
    UsedForVerification,
    PreventedRepeatedFailure,
    SuppressedAsStale,
    SuppressedAsWrongScope,
    SeenButNotUsed,
    LoadedWithoutDelta,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct MemoryInfluenceTrace {
    pub task_id: TaskId,
    pub session_id: AgentSessionId,
    pub memory_handle: String,
    pub packet_id: String,
    pub admission_decision: MemoryAdmissionDecision,
    pub inclusion_or_suppression_reason: String,
    pub epistemic_status_at_use: String,
    pub cited_in_understanding_proof: bool,
    pub action_or_probe_changed: bool,
    pub write_set_changed: bool,
    pub verifier_changed: bool,
    pub repeated_failure_prevented: bool,
    pub suppressed_as_stale_or_wrong_scope: bool,
    pub downstream_outcome_ref: Option<String>,
    pub influence_class: MemoryInfluenceClass,
    #[schemars(with = "Option<serde_json::Value>")]
    /// A missing receipt stays absent; absence never authenticates canonical storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDecisionReceipt {
    pub task_id: TaskId,
    pub memory_handle: String,
    pub source_and_anchor: String,
    pub scope: Vec<String>,
    pub status: String,
    pub freshness: String,
    pub authority: String,
    pub conflicts: Vec<String>,
    pub admission: MemoryAdmissionDecision,
    pub action_effect: String,
    pub verifier_effect: String,
    pub future_activation: String,
    /// A missing receipt stays absent; absence never authenticates canonical storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextCargoReceipt {
    pub receipt_id: String,
    pub task_id: TaskId,
    pub session_id: AgentSessionId,
    pub memory_handle: String,
    pub packet_load_count: u32,
    pub decision_delta_count: u32,
    pub verifier_delta_count: u32,
    pub disposition: MemoryInfluenceClass,
    pub demotion_candidate: bool,
    pub reason: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    /// A missing receipt stays absent; absence never authenticates canonical storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryValueExperiment {
    pub task_b_hash: String,
    pub host_model_harness: String,
    pub current_truth_snapshot: CurrentTruthSnapshot,
    pub reusable_memory_handles: Vec<String>,
    pub stale_or_wrong_scope_control_handles: Vec<String>,
    pub expected_decision_delta: Vec<String>,
    pub primary_metrics: Vec<String>,
    pub counter_metrics: Vec<String>,
    pub contamination_controls: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningDecisionRecord {
    pub first_action_or_probe: String,
    pub selected_owner_or_module: String,
    pub selected_write_set: Vec<String>,
    pub selected_verifier: String,
    pub wrong_path_attempts: u32,
    pub tool_calls_before_correct_boundary: u32,
    pub material_unknowns: Vec<String>,
    pub confidence: f32,
    pub estimated_tokens: usize,
    pub latency_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryValueComparison {
    pub task_b_hash: String,
    pub control: PlanningDecisionRecord,
    pub treatment: PlanningDecisionRecord,
    pub changed_dimensions: Vec<String>,
    pub observable_decision_delta: bool,
    pub treatment_preferred: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NegativeMemoryDecision {
    Allow,
    BlockRepeatedFailure,
    RequireDiscriminativeProbe,
    Reopen,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryGateInput {
    pub fingerprint: String,
    pub repeated_count: u64,
    pub scope_matches: bool,
    pub reopen_conditions: Vec<String>,
    pub satisfied_reopen_conditions: Vec<String>,
    pub discriminative_evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryDecisionReceipt {
    pub receipt_id: String,
    pub fingerprint: String,
    pub decision: NegativeMemoryDecision,
    pub reasons: Vec<String>,
    pub reopen_conditions: Vec<String>,
    pub evidence_refs: Vec<String>,
    /// A missing receipt stays absent; absence never authenticates canonical storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponsibilityContour {
    Framing,
    Planning,
    Understanding,
    Research,
    Implementation,
    Audit,
    Verification,
    Recovery,
    MemoryCuration,
    OperatorApproval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContourPolicyScope {
    System,
    Project,
    Task,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContourPreferredRoute {
    pub host_id: String,
    pub model_route_optional: Option<String>,
    pub requested_role: String,
    pub capability_requirements: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContourRoutePolicy {
    pub policy_id: String,
    pub scope: ContourPolicyScope,
    pub project_id: Option<ProjectId>,
    pub task_id: Option<TaskId>,
    pub contour: ResponsibilityContour,
    pub preferred_routes: Vec<ContourPreferredRoute>,
    pub allowed_fallbacks: Vec<ContourPreferredRoute>,
    pub deterministic_adapter_preference: bool,
    pub max_parallelism: u32,
    pub cost_or_token_budget: Option<String>,
    pub wall_time_budget_seconds: u64,
    pub required_evidence: Vec<String>,
    pub required_verifier: Vec<String>,
    pub escalation_route: Option<ContourPreferredRoute>,
    #[serde(with = "time::serde::rfc3339")]
    pub effective_from: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub policy_snapshot_id: String,
    pub owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContourRouteDecision {
    pub task_id: TaskId,
    pub work_item_id: WorkItemId,
    pub contour: ResponsibilityContour,
    pub candidate_routes: Vec<ContourPreferredRoute>,
    pub selected_route: ContourPreferredRoute,
    pub capability_evidence: Vec<String>,
    pub availability_evidence: Vec<String>,
    pub policy_refs: Vec<String>,
    pub cost_latency_estimate: String,
    pub fallback: Option<ContourPreferredRoute>,
    pub decision_receipt: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveContourRoute {
    pub route: ContourPreferredRoute,
    pub available: bool,
    pub retention_allowed: bool,
    pub capability_evidence: Vec<String>,
    pub availability_evidence: Vec<String>,
    pub cost_latency_estimate: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutonomyRunState {
    Draft,
    Ready,
    Running,
    Verifying,
    DoneVerified,
    PausedByOperator,
    BlockedByUnknown,
    BlockedByApproval,
    Degraded,
    PartialProgress,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyRunContract {
    pub autonomy_run_id: String,
    pub project_id: ProjectId,
    pub root_task_id: TaskId,
    pub user_goal: String,
    pub acceptance_items: Vec<String>,
    pub contour_route_policy_ref: String,
    pub allowed_projects: Vec<ProjectId>,
    pub max_work_items: u32,
    pub max_active_agents: u32,
    pub max_model_invocations: u32,
    pub max_tool_calls: u32,
    pub max_wall_time_seconds: u64,
    pub cost_or_token_budget: Option<String>,
    pub allowed_paths: Vec<String>,
    pub forbidden_paths: Vec<String>,
    pub forbidden_effects: Vec<String>,
    pub allowed_risk_tiers: Vec<String>,
    pub required_verifiers: Vec<String>,
    pub approval_boundaries: Vec<String>,
    pub pause_conditions: Vec<String>,
    pub stop_conditions: Vec<String>,
    pub fallback_routes: Vec<ContourPreferredRoute>,
    pub recovery_policy_ref: String,
    pub policy_snapshot_id: String,
    pub created_by: String,
    pub state: AutonomyRunState,
    pub state_revision: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyRunTransitionReceipt {
    pub transition_id: String,
    pub autonomy_run_id: String,
    pub from: AutonomyRunState,
    pub to: AutonomyRunState,
    pub state_revision: u64,
    pub reason: String,
    pub risk_tier: String,
    pub exact_approval_hash: Option<String>,
    pub verifier_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub transitioned_at: OffsetDateTime,
    /// A missing receipt stays absent; absence never authenticates canonical storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveDecisionState {
    pub task_id: TaskId,
    pub packet_id: String,
    pub revision_fence: MemoryRevision,
    pub selected_owner_or_module: Option<String>,
    pub next_allowed_action: String,
    pub expected_observable: String,
    pub verifier: String,
    pub stop_condition: String,
    pub killed_paths: Vec<String>,
    pub open_unknowns: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCognitionView {
    pub task_contract: TaskContract,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_meaning: Option<TaskMeaningFrame>,
    pub active_decision_state: Option<ActiveDecisionState>,
    pub current_truth: Vec<ClaimSummary>,
    pub epistemic_state: EpistemicPacketState,
    pub causal_bridge: Vec<CausalBridgeHop>,
    /// Explicit presence for the four optional cognition sections (#708).
    ///
    /// `TaskCognitionView` is the read-back half of `OperatorSnapshot`, and the
    /// operator snapshot is a *projection*: an absent `experience_priors` /
    /// `negative_memory` / `procedural_skills` key must not be able to read back
    /// as "this task has no experience priors, no negative memory, no
    /// procedural skills". Those are different claims from "the producer did not
    /// populate this section", and the three sections decide what an agent is
    /// told about prior failures.
    ///
    /// Compatibility: `OperatorSnapshot` is produced by exactly one function,
    /// `crates/eliot-app/src/mcp_stdio/operator.rs::dispatch_operator_snapshot`
    /// (the full `OperatorSnapshot` literal at :679 and both view literals at
    /// :385 and :438 set every field explicitly, including when the packet is
    /// absent — those paths then use the explicit empty/`default` value, which
    /// `Serialize` still writes), and read back by
    /// `operator.rs::dispatch_operator_query` (:773) and
    /// `crates/eliot-app/src/mcp_stdio/memory_grant.rs::merge_memory_grant_input`.
    /// It is projected over the pipe, not persisted, so no durable
    /// already-omitted payload exists. `Serialize` is untouched, so emitted
    /// bytes are unchanged; this is a compatible requiredness correction whose
    /// only effect is that a truncated or foreign snapshot fails with a typed
    /// missing-field error instead of silently shrinking a view.
    pub experience_priors: Vec<ExperienceBrief>,
    pub negative_memory: Vec<ClaimCard>,
    pub selected_memory: Vec<MemoryDecisionReceipt>,
    pub suppressed_memory: Vec<MemoryDecisionReceipt>,
    pub procedural_skills: ProceduralSkillPacketView,
    pub packet_quality: Option<PacketQualityReport>,
    pub understanding_outcomes: Vec<UnderstandingOutcomeRecord>,
    pub completion_proof: Option<CompletionProof>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInspectorView {
    pub project_id: ProjectId,
    pub active_current_claim_refs: Vec<String>,
    pub recalled_candidate_refs: Vec<String>,
    pub stale_or_superseded_refs: Vec<String>,
    pub support_and_counterevidence_refs: Vec<String>,
    pub decisions: Vec<MemoryDecisionReceipt>,
    pub influence: Vec<MemoryInfluenceTrace>,
    pub cargo: Vec<ContextCargoReceipt>,
    /// Explicit presence for the seven optional memory-analysis sections (#708).
    ///
    /// The same reason as `TaskCognitionView` above, with a sharper edge here:
    /// this is the *memory inspector* projection, and a defaulted
    /// `applicability_decisions` / `negative_transfer` / `cognitive_lab_results`
    /// reads back as "this project has no applicability decisions, no negative
    /// transfer and no lab results" — a completeness claim about a canonical
    /// store that the projection never actually made. `lifecycle` is the
    /// lifecycle view; an omitted key decoded as "every memory is in its default
    /// lifecycle state".
    ///
    /// Compatibility: one producer, `crates/eliot-app/src/mcp_stdio/operator.rs::dispatch_operator_snapshot`
    /// (`MemoryInspectorView` literal at :438 sets all eleven fields), read back
    /// in the same snapshot consumer. Projected, never persisted, so no durable
    /// omitted payload exists; `Serialize` is untouched. Compatible requiredness
    /// correction, unchanged accepted and emitted bytes.
    pub lifecycle: MemoryLifecyclePacketView,
    pub experience_cases: Vec<ExperienceCase>,
    pub experience_patterns: Vec<ExperiencePattern>,
    pub applicability_decisions: Vec<MemoryApplicabilityDecision>,
    pub negative_transfer: Vec<NegativeTransferRecord>,
    pub cognitive_lab_results: Vec<CognitiveTransferLabReport>,
    pub failure_localization: Vec<CognitiveFailureLocalizationReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_profile: Option<MemoryCorpusProfile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRoutingView {
    pub host_session_refs: Vec<String>,
    pub task_role_lease_refs: Vec<String>,
    pub work_or_action_lease_refs: Vec<String>,
    pub route_policies: Vec<ContourRoutePolicy>,
    pub route_decisions: Vec<ContourRouteDecision>,
    /// Explicit presence for the nine delegation/lease/result sections (#708).
    ///
    /// This is the routing half of `OperatorSnapshot`, and its defaulted fields
    /// are exactly the authority-bearing ones: `task_role_leases`,
    /// `work_leases`, `worktree_leases`, `controller_leases` and
    /// `agent_result_dispositions` decide which authority and which write scope
    /// the operator surface shows. An omitted key decoded as "no live worktree
    /// lease", "no controller lease" or "no result disposition" — a
    /// no-authority claim about a governance surface, which is the strongest
    /// form of the defect this issue exists to remove (A0.3: hidden creation or
    /// expansion of authority; a stale read must not read as a revoked one).
    ///
    /// Compatibility: one producer,
    /// `crates/eliot-app/src/mcp_stdio/operator.rs::dispatch_operator_snapshot`
    /// (`AgentRoutingView` literal at :693 sets all fifteen fields). The
    /// snapshot is projected over the operator pipe, not persisted, so no
    /// durable already-omitted payload exists. `Serialize` is untouched, so
    /// emitted bytes are unchanged. Compatible requiredness correction.
    pub host_sessions: Vec<AgentSessionHostBinding>,
    pub task_role_leases: Vec<TaskRoleLease>,
    pub controller_leases: Vec<ControllerLease>,
    pub operation_jobs: Vec<OperationJob>,
    pub agent_results: Vec<AgentResultEnvelope>,
    pub agent_result_dispositions: Vec<AgentResultDisposition>,
    pub work_items: Vec<WorkItem>,
    pub work_leases: Vec<WorkLease>,
    pub worktree_leases: Vec<WorktreeLease>,
    pub work_conflicts: Vec<WorkConflict>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyRunView {
    pub contract: AutonomyRunContract,
    pub work_item_refs: Vec<String>,
    pub assignment_refs: Vec<String>,
    pub verifier_result_refs: Vec<String>,
    /// Explicit presence for the run ledger and completion sections (#708).
    ///
    /// `model_invocations_used`, `tool_calls_used` and `wall_time_used_seconds`
    /// are the budget denominators for an autonomy run, and `cost_or_tokens_used`
    /// is the cost-authority record (A14.7). An omitted key decoded as
    /// `0` / absent, i.e. "this run spent no model invocations, no tokens and no
    /// time" — a measured-zero claim for a run whose actual consumption was
    /// never recorded. `completion_proof` is the proof-bearing field: an absent
    /// key decoded as "no completion proof", which is a *weaker* claim than the
    /// honest one but is still a proof-status claim manufactured by omission.
    /// `route_decision_refs` / `recovery_event_refs` /
    /// `pause_resume_reassignment_refs` are the ordering and recovery
    /// trajectory.
    ///
    /// Compatibility: one producer,
    /// `crates/eliot-app/src/mcp_stdio/autonomy.rs::operator_run_view` (the
    /// `AutonomyRunView` literal at :246 sets all eleven fields, including
    /// `cost_or_tokens_used: Some(...)`). `eliot-store`'s
    /// `CanonicalAutonomyRunView` is a *separate* read-only projection type in
    /// `crates/eliot-store/src/canonical_projection_views.rs` and does not
    /// decode this struct, so this change does not move the canonical store
    /// read-back path. `Serialize` is untouched, so emitted bytes are
    /// unchanged. Compatible requiredness correction.
    pub route_decision_refs: Vec<String>,
    pub recovery_event_refs: Vec<String>,
    pub model_invocations_used: u32,
    pub tool_calls_used: u32,
    pub wall_time_used_seconds: u64,
    pub cost_or_tokens_used: Option<String>,
    pub pause_resume_reassignment_refs: Vec<String>,
    pub completion_proof: Option<CompletionProof>,
    pub finish_status: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyTripwireKind {
    RepeatedFailureSignature,
    NoNovelty,
    ContextSqueeze,
    CalibrationCollapse,
    RepeatedRefutation,
    ProviderFailure,
    LeaseExpiry,
    WriteSetConflict,
    VerifierFailure,
    BudgetExhaustion,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyRecoveryRecord {
    pub recovery_id: String,
    pub autonomy_run_id: String,
    pub work_item_id: Option<WorkItemId>,
    pub tripwire: AutonomyTripwireKind,
    pub actions_taken: Vec<RecoveryAction>,
    pub prior_route_ref: Option<String>,
    pub next_route_ref: Option<String>,
    pub preserved_artifact_refs: Vec<String>,
    pub state_revision: u64,
    pub evidence_refs: Vec<String>,
    /// A missing receipt stays absent; absence never authenticates the recovery write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_receipt: Option<WriteReceiptRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalView {
    pub approval_id: String,
    pub exact_action_hash: String,
    pub risk_tier: String,
    pub write_or_resource_set: Vec<String>,
    pub reason_summary: String,
    pub verifier: String,
    pub rollback_or_compensation: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub decision_receipt: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceTimelineView {
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub event_refs: Vec<String>,
    pub incident_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorSnapshot {
    pub schema_version: String,
    pub protocol_version: String,
    pub protocol_hash: String,
    pub runtime_id: String,
    pub auth_generation: String,
    pub health_refs: Vec<String>,
    pub task_cognition: Vec<TaskCognitionView>,
    pub memory_inspector: Option<MemoryInspectorView>,
    pub routing: AgentRoutingView,
    pub runs: Vec<AutonomyRunView>,
    pub approvals: Vec<ApprovalView>,
    pub timeline: TraceTimelineView,
    /// Explicit presence for the four operator-surface extensions (#708).
    ///
    /// `incidents` and `log_handles` are the operator's incident and log
    /// evidence surface, and `backup_inventory` is the recovery/backup
    /// visibility surface. An omitted key decoded as "no open incidents", "no
    /// log handles" and "no backups exist" — three claims about *absence of
    /// adverse evidence and of recoverability*, which is precisely the
    /// untraceable-effect direction A0.3 fails closed on. `project_refs` is the
    /// snapshot's project scope; a defaulted empty list made a truncated
    /// snapshot indistinguishable from a genuinely empty one.
    ///
    /// Compatibility: one producer,
    /// `crates/eliot-app/src/mcp_stdio/operator.rs::dispatch_operator_snapshot`
    /// (the `OperatorSnapshot` literal at :679 sets all four, at :718-721).
    /// The snapshot travels over the operator pipe and is decoded by
    /// `operator.rs::dispatch_operator_query` (:773); it is not persisted to
    /// the canonical store, so no durable already-omitted payload exists.
    /// `Serialize` is untouched, so emitted bytes are unchanged and the
    /// hash-pinned contract manifest `schema/operator-contract-v1.json`
    /// (`OPERATOR_CONTRACT_MANIFEST` → `operator_contract_hash`) is not a
    /// struct-shape digest and does not move. Compatible requiredness
    /// correction.
    pub project_refs: Vec<String>,
    pub backup_inventory: Vec<BackupInventoryEntry>,
    pub incidents: Vec<IncidentRecord>,
    pub log_handles: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorProjectionKind {
    Overview,
    TasksWork,
    TaskCognition,
    MemoryExplorer,
    CausalProvenance,
    SchemaContracts,
    QueryLab,
    ExperienceSkills,
    SleepMeta,
    AgentsRouting,
    Autonomy,
    Approvals,
    TimelineOperations,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorProjectionFilter {
    pub search: Option<String>,
    pub record_kind: Option<String>,
    pub status: Option<String>,
    pub lifecycle: Option<String>,
    pub authority: Option<String>,
    pub observed_after: Option<String>,
    pub observed_before: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorQueryRequest {
    pub projection: OperatorProjectionKind,
    pub project_id: Option<ProjectId>,
    pub task_id: Option<TaskId>,
    #[serde(default)]
    pub filter: OperatorProjectionFilter,
    pub cursor: Option<String>,
    pub page_size: u32,
    #[serde(default)]
    pub query_operation: Option<OperatorQueryOperation>,
    #[serde(default)]
    pub query_parameters: Option<Value>,
    #[serde(default)]
    pub result_mode: OperatorResultMode,
    #[serde(default)]
    pub selected_ref: Option<String>,
    #[serde(default = "default_operator_graph_depth")]
    pub expand_depth: u8,
}

const fn default_operator_graph_depth() -> u8 {
    1
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorQueryOperation {
    CurrentState,
    RecallPreview,
    ExactEvidence,
    RelationshipSlice,
    TraceReplay,
    HealthReport,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorResultMode {
    #[default]
    Human,
    Json,
    Graph,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorFieldView {
    pub label: String,
    pub value: String,
    pub copyable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRelationshipView {
    pub relation: String,
    pub target_ref: String,
    pub evidence_ref: Option<String>,
    pub observed_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorActionView {
    pub command: String,
    pub label: String,
    pub risk_tier: String,
    pub requires_reason: bool,
    pub requires_exact_action_hash: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRecordView {
    pub record_ref: String,
    pub record_kind: String,
    pub title: String,
    pub summary: String,
    pub status: String,
    pub lifecycle: Option<String>,
    pub authority: String,
    pub observed_at: Option<String>,
    pub fields: Vec<OperatorFieldView>,
    pub relationships: Vec<OperatorRelationshipView>,
    pub actions: Vec<OperatorActionView>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorProjectionPage {
    pub schema_version: String,
    pub runtime_id: String,
    pub auth_generation: String,
    pub projection: OperatorProjectionKind,
    pub project_id: Option<ProjectId>,
    pub task_id: Option<TaskId>,
    pub task_revision: Option<MemoryRevision>,
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub page_size: u32,
    pub returned: usize,
    pub total_matching: usize,
    pub total_is_exact: bool,
    pub truncated: bool,
    pub records: Vec<OperatorRecordView>,
    pub result_mode: OperatorResultMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_payload: Option<Value>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCurationPreviewRequest {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub at_revision: MemoryRevision,
    pub ruleset_version: String,
    pub cursor: Option<String>,
    pub page_size: u16,
}

fn deserialize_duplicate_rejecting_string_usize_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct DuplicateRejectingMap;

    impl<'de> serde::de::Visitor<'de> for DuplicateRejectingMap {
        type Value = BTreeMap<String, usize>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON object with unique string keys")
        }

        fn visit_map<A>(self, mut access: A) -> Result<BTreeMap<String, usize>, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut entries = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, usize>()? {
                if entries.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate map key"));
                }
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_map(DuplicateRejectingMap)
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCurationCorpusProfile {
    pub scanned_records: usize,
    pub scan_limit: usize,
    pub scan_truncated: bool,
    #[serde(deserialize_with = "deserialize_duplicate_rejecting_string_usize_map")]
    pub receipt_kind_counts: BTreeMap<String, usize>,
    #[serde(deserialize_with = "deserialize_duplicate_rejecting_string_usize_map")]
    pub lifecycle_counts: BTreeMap<String, usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryCurationFindingKind {
    Duplicate,
    SemanticDuplicate,
    WrongScope,
    LowUtility,
    LowUtilityInsufficientEvidence,
    RepeatedLowDelta,
    StaleSuperseded,
    UnsafeInstruction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCurationCandidate {
    pub handle: String,
    pub kind: String,
    pub lifecycle: String,
    pub authority: String,
    pub finding_kind: MemoryCurationFindingKind,
    pub evidence_refs: Vec<String>,
    pub counterevidence_refs: Vec<String>,
    pub confidence: u16,
    pub proposed_reversible_action: String,
    pub restore_requirements: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCurationPreviewResponse {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub snapshot_revision: MemoryRevision,
    pub ruleset_version: String,
    pub read_only: bool,
    pub corpus_profile: MemoryCurationCorpusProfile,
    pub candidates: Vec<MemoryCurationCandidate>,
    pub protected_refs: Vec<String>,
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub total_matching: usize,
    pub total_is_exact: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperatorCommand {
    SelectTask {
        task_id: TaskId,
    },
    RefreshPacket {
        task_id: TaskId,
    },
    RequestRevalidation {
        task_id: TaskId,
        memory_handle: String,
    },
    CreateAutonomyRun {
        contract: Box<AutonomyRunContract>,
    },
    PreviewAutonomyEdit {
        autonomy_run_id: String,
        proposed_contract: Box<AutonomyRunContract>,
    },
    StartRun {
        autonomy_run_id: String,
    },
    PauseRun {
        autonomy_run_id: String,
        reason: String,
    },
    ResumeRun {
        autonomy_run_id: String,
    },
    CancelRun {
        autonomy_run_id: String,
        reason: String,
    },
    DispositionAgentResult {
        result_id: String,
        disposition: String,
    },
    ContestMemory {
        task_id: TaskId,
        memory_handle: String,
        evidence_refs: Vec<String>,
    },
    SuppressMemory {
        task_id: TaskId,
        memory_handle: String,
        reason: String,
    },
    ArchiveMemory {
        task_id: TaskId,
        memory_handle: String,
        reason: String,
    },
    RestoreMemory {
        task_id: TaskId,
        memory_handle: String,
        evidence_refs: Vec<String>,
    },
    ReviewCandidate {
        task_id: TaskId,
        candidate_ref: String,
        disposition: String,
        evidence_refs: Vec<String>,
    },
    TriggerBackupValidation {
        task_id: TaskId,
    },
    RequestImportPreview {
        task_id: TaskId,
        source_ref: String,
    },
    GrantApproval {
        approval_id: String,
        exact_action_hash: String,
    },
    DenyApproval {
        approval_id: String,
        exact_action_hash: String,
        reason: String,
    },
    FinishGapPreview {
        task_id: TaskId,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorCommandReceipt {
    /// The exact retained UI idempotency identity that the owner evaluated.
    pub operation_id: String,
    /// The task revision supplied by the caller and checked before dispatch.
    pub expected_revision: u64,
    pub command_id: String,
    pub accepted: bool,
    pub executed: bool,
    pub outcome: String,
    pub task_id: Option<TaskId>,
    pub action: String,
    pub revision: Option<MemoryRevision>,
    pub reasons: Vec<String>,
    pub canonical_receipt: Option<WriteReceiptRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<Value>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorControlRequest {
    pub request_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub operation: String,
    pub target_ref: String,
    pub disposition: String,
    pub exact_action_hash: Option<String>,
    pub reason_or_evidence_refs: Vec<String>,
    pub requested_by: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// A missing receipt stays absent; absence never authenticates canonical storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_receipt: Option<WriteReceiptRef>,
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn operator_contract_manifest_is_parseable_and_hash_pinned() -> Result<(), serde_json::Error> {
        let manifest: serde_json::Value = serde_json::from_str(OPERATOR_CONTRACT_MANIFEST)?;
        assert_eq!(
            manifest
                .get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some(OPERATOR_SCHEMA_VERSION)
        );
        let hash = operator_contract_hash();
        assert_eq!(
            hash,
            "b00a82807e003ad1e1b9b717a9759024335ffe461a0cc3f5d67867ec8750394f"
        );
        let lf = OPERATOR_CONTRACT_MANIFEST.replace("\r\n", "\n");
        let crlf = lf.replace('\n', "\r\n");
        let pretty = serde_json::to_string_pretty(&manifest)?;
        let compact = serde_json::to_string(&manifest)?;
        for equivalent_manifest in [&lf, &crlf, &pretty, &compact] {
            assert_eq!(
                operator_contract_hash_for_manifest(equivalent_manifest),
                hash
            );
        }
        Ok(())
    }
}
