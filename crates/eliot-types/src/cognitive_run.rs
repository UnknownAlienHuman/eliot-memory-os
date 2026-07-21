use crate::{
    AgentHostId, AgentResultDispositionKind, AgentSessionId, MemoryRevision, ProjectId, ReceiptId,
    SessionId, TaskId, WriteId, WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

pub const COGNITIVE_RUN_SCHEMA_VERSION: &str = "eliot-cognitive-run-v2";
pub const COGNITIVE_RUN_EXACT_CALLS: usize = 18;
pub const COGNITIVE_RUN_RAW_VERIFIER_CALLS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveInvocationRole {
    Target,
    Control,
    SourceWrite,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveRunCallPlan {
    pub call_number: u8,
    pub call_id: String,
    pub case_id: String,
    pub host: AgentHostId,
    pub model: String,
    pub invocation_role: CognitiveInvocationRole,
    /// Stable harness variant, for example `treatment` or `control`.
    pub variant: String,
    /// Present only for the two reciprocal LC flows.
    pub reciprocal_flow_id: Option<String>,
    /// True only for calls 17 and 18.
    pub requires_shared_gate: bool,
    /// Governor-admitted deterministic candidate `WriteId` for source-write calls only.
    pub candidate_write_id: Option<WriteId>,
    /// SHA-256 of the exact candidate-submit JSON body for source-write calls only.
    pub candidate_body_sha256: Option<String>,
    pub prompt_sha256: String,
    /// SHA-256 of the exact provider authority bundle admitted for this call:
    /// the copied `OpenCode` integration tree or copied `Antigravity` agent manifest bundle.
    pub expected_provider_bundle_sha256: String,
    /// Exact canonical truth revision exposed to this call.
    pub expected_truth_revision: String,
    /// Exact ordered memory handles admitted to this call.
    pub expected_exposure_handles: Vec<String>,
    pub exposure_sha256: String,
    pub expected_output_schema_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveRunContract {
    pub schema_version: String,
    pub harness_version: String,
    pub instance_name: String,
    pub run_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub governor_nonce: Uuid,
    pub harness_script_sha256: String,
    pub cases_sha256: String,
    pub exposure_map_sha256: String,
    pub output_contract_sha256: String,
    pub models_sha256: String,
    /// Exact Git commit embedded into the Governor binary at build time.
    pub source_commit: String,
    /// Deterministic hash of the cases, exposure, output, models and source policy inputs.
    pub policy_snapshot_id: String,
    /// Canonical slash-normalized owned output root sealed for the whole run.
    pub output_root: String,
    /// Uniform hard deadline for each provider call in this run.
    pub timeout_seconds: u64,
    pub exact_plan: Vec<CognitiveRunCallPlan>,
    pub hard_provider_call_cap: u8,
    /// SHA-256 of the canonical JSON contract with this field set to an empty string.
    pub contract_sha256: String,
    #[serde(with = "time::serde::rfc3339")]
    pub sealed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalCaseDisposition {
    pub case_id: String,
    pub task_id: TaskId,
    /// Canonical candidate `WriteId` or governed `AgentResultEnvelope.result_id`.
    pub candidate_result_id: String,
    pub disposition_id: String,
    pub disposition_kind: AgentResultDispositionKind,
    pub actor_session_id: AgentSessionId,
    pub actor_role_lease_id: String,
    pub evidence_refs: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub write_receipt_id: ReceiptId,
    pub task_revision_before: MemoryRevision,
    pub task_revision_after: MemoryRevision,
    pub source_commit: String,
    pub policy_snapshot_id: String,
    pub resolved_from_store: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveExecutionSeal {
    /// Exact binary launched by the native runner (which may be the ELIOT host wrapper).
    pub executable_sha256: String,
    /// Exact `OpenCode` or `Antigravity` provider binary selected behind the wrapper.
    pub provider_executable_sha256: String,
    pub argv_sha256: String,
    pub environment_sha256: String,
    pub cwd_sha256: String,
    pub bundle_sha256: String,
    pub prompt_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveSharedGateBinding {
    pub gate_revision: u64,
    pub gate_receipt: WriteReceiptRef,
    pub contract_receipt: WriteReceiptRef,
    /// Exact canonical successful terminal chain for calls 1 through 16.
    pub pre_gate_terminal_receipts: Vec<WriteReceiptRef>,
    /// Exact canonical dispositions for the two source candidates.
    pub source_disposition_receipts: Vec<WriteReceiptRef>,
    /// Exact canonical verification receipts for the two dispositions.
    pub reciprocal_verification_receipts: Vec<WriteReceiptRef>,
    /// Full store-resolved authority chains for the two reciprocal source cases.
    pub canonical_case_dispositions: Vec<CanonicalCaseDisposition>,
    pub condition_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveCandidateCapability {
    pub capability_id: String,
    pub contract_sha256: String,
    pub run_id: String,
    pub call_id: String,
    pub call_number: u8,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub host: AgentHostId,
    pub invocation_role: CognitiveInvocationRole,
    /// Exact canonical truth revision admitted to this child session.
    pub expected_truth_revision: String,
    /// Exact ordered memory handles the child may observe or fetch.
    pub expected_exposure_handles: Vec<String>,
    pub expected_write_id: Option<WriteId>,
    pub expected_body_sha256: Option<String>,
    pub token_sha256: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveHostObservation {
    pub observation_version: String,
    pub governor_session_id: Option<SessionId>,
    pub vendor_session_id: Option<String>,
    pub host: AgentHostId,
    pub observed_model: Option<String>,
    pub outer_protocol_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveToolObservation {
    pub schema_version: String,
    pub run_id: String,
    #[serde(default)]
    pub call_subject_ref: String,
    #[serde(default)]
    pub observation_id: String,
    pub call_id: String,
    pub call_number: u8,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub host: AgentHostId,
    pub attempt_receipt: WriteReceiptRef,
    pub tool_name: String,
    pub outcome: String,
    /// Semantic truth revision label sealed in the exact call plan.
    pub sealed_truth_revision: String,
    /// Canonical project memory revision returned by the trusted read tool.
    pub observed_memory_revision: Option<u64>,
    pub arguments_sha256: String,
    pub result_sha256: String,
    pub requested_handles: Vec<String>,
    pub returned_handles: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveRunCallStatus {
    Attempting,
    Succeeded,
    Failed,
    UnknownOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveRunAttempt {
    pub schema_version: String,
    pub run_id: String,
    pub call_id: String,
    pub call_number: u8,
    pub run_revision: u64,
    pub expected_previous_revision: u64,
    pub contract_receipt: WriteReceiptRef,
    pub invocation_id: String,
    pub candidate_write_id: Option<WriteId>,
    pub provider_calls_consumed: u8,
    pub hard_provider_call_cap: u8,
    pub status: CognitiveRunCallStatus,
    pub execution: CognitiveExecutionSeal,
    pub capability: Option<CognitiveCandidateCapability>,
    pub shared_gate: Option<CognitiveSharedGateBinding>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveRunTerminal {
    pub schema_version: String,
    pub run_id: String,
    pub call_id: String,
    pub call_number: u8,
    pub run_revision: u64,
    pub expected_previous_revision: u64,
    pub attempt_receipt: WriteReceiptRef,
    pub status: CognitiveRunCallStatus,
    pub execution: CognitiveExecutionSeal,
    pub process_sha256: Option<String>,
    pub stdout_sha256: Option<String>,
    pub stderr_sha256: Option<String>,
    pub provider_output_sha256: Option<String>,
    pub candidate_write_id: Option<WriteId>,
    pub candidate_receipt: Option<WriteReceiptRef>,
    pub host_observation: Option<CognitiveHostObservation>,
    pub tool_observation_receipts: Vec<WriteReceiptRef>,
    pub raw_verifier_receipts: Vec<WriteReceiptRef>,
    pub reason: String,
    pub no_redispatch: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CognitiveRawVerifierEvidence {
    pub schema_version: String,
    pub run_id: String,
    pub call_id: String,
    pub call_number: u8,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub attempt_receipt: WriteReceiptRef,
    pub execution: CognitiveExecutionSeal,
    pub process_sha256: Option<String>,
    pub stdout_sha256: Option<String>,
    pub stderr_sha256: Option<String>,
    pub provider_output_sha256: Option<String>,
    pub host_observation: Option<CognitiveHostObservation>,
    pub tool_observation_receipts: Vec<WriteReceiptRef>,
    pub verifier_version: String,
    pub checks_sha256: String,
    pub passed: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub verified_at: OffsetDateTime,
}
