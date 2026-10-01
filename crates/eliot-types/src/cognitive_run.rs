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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct CognitiveHostObservation {
    pub observation_version: String,
    pub governor_session_id: Option<SessionId>,
    pub vendor_session_id: Option<String>,
    pub host: AgentHostId,
    pub observed_model: Option<String>,
    pub outer_protocol_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveToolObservation {
    pub schema_version: String,
    pub run_id: String,
    /// No legacy wire form omits this field: the owner producer always seals the
    /// exact call subject and the owner binding check rejects any other value, so
    /// a missing field is refused rather than decoded to an empty identity.
    pub call_subject_ref: String,
    /// No legacy wire form omits this field: the owner producer always seals a
    /// fresh `UUIDv7` and the owner binding check rejects any other value, so a
    /// missing field is refused rather than decoded to an empty identity.
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Owner version selection for the canonical cognitive-run records.
///
/// `COGNITIVE_RUN_SCHEMA_VERSION` is the only schema this build produces or reads:
/// every producer above stamps `COGNITIVE_RUN_SCHEMA_VERSION`, and a repository-wide
/// search finds no other `eliot-cognitive-run-v*` literal anywhere. There is therefore
/// NO supported legacy revision and no named migration to fall back to, so version
/// selection is a single named owner step applied at the real decoding boundary
/// instead of being inferred from the presence of a `schema_version` string.
///
/// I5.22: "core schema is explicit and versioned". I5.16: absence of a closure or
/// coverage record means `unknown`, not unrestricted/complete - a record whose
/// version is not the current one is therefore `unknown`, never "close enough".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CognitiveRunSchemaSelection {
    /// The declared version is the schema this build reads and interprets.
    Current,
    /// The declared version is not one this build reads; the bytes are refused
    /// rather than reinterpreted under current field meanings.
    Unsupported,
}

impl CognitiveRunSchemaSelection {
    /// Classify one declared `schema_version` against the current owner constant.
    #[must_use]
    pub fn for_version(version: &str) -> Self {
        if version == COGNITIVE_RUN_SCHEMA_VERSION {
            Self::Current
        } else {
            Self::Unsupported
        }
    }

    /// The declared version that this selection admits, or `None` when it admits none.
    #[must_use]
    pub fn admitted_version(self) -> Option<&'static str> {
        match self {
            Self::Current => Some(COGNITIVE_RUN_SCHEMA_VERSION),
            Self::Unsupported => None,
        }
    }
}

/// Version-selection owner step shared by every schema-bearing cognitive-run record.
///
/// Returns the admitted version, or `None` when the declared version is not one this
/// build reads. `None` means the record carries no meaning as current data and the
/// caller MUST NOT let it authorize candidate submission, terminal progression,
/// shared-gate/disposition logic or tool evidence.
#[must_use]
pub fn cognitive_run_schema_selection(version: &str) -> Option<&'static str> {
    CognitiveRunSchemaSelection::for_version(version).admitted_version()
}

/// A schema-bearing cognitive-run record whose `schema_version` is owner-checked.
///
/// Implemented by exactly the records this build reads back from the canonical store
/// and acts on: the contract, the attempt, the terminal, the tool observation and the
/// raw-verifier evidence.
pub trait CognitiveRunSchemaVersioned {
    /// The canonical-record kind this versioned record is stored under, used in the
    /// refusal message so the operator sees which boundary rejected the bytes.
    const COGNITIVE_RECORD_KIND: &'static str;

    /// The version this record declares.
    fn schema_version(&self) -> &str;

    /// The admitted owner version, or `None` when the declared version is not one
    /// this build reads.
    fn schema_selection(&self) -> Option<&'static str>;
}

impl CognitiveRunSchemaVersioned for CognitiveRunContract {
    const COGNITIVE_RECORD_KIND: &'static str = "cognitive_run_contract";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn schema_selection(&self) -> Option<&'static str> {
        cognitive_run_schema_selection(&self.schema_version)
    }
}

impl CognitiveRunSchemaVersioned for CognitiveRunAttempt {
    const COGNITIVE_RECORD_KIND: &'static str = "cognitive_run_attempt";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn schema_selection(&self) -> Option<&'static str> {
        cognitive_run_schema_selection(&self.schema_version)
    }
}

impl CognitiveRunSchemaVersioned for CognitiveRunTerminal {
    const COGNITIVE_RECORD_KIND: &'static str = "cognitive_run_terminal";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn schema_selection(&self) -> Option<&'static str> {
        cognitive_run_schema_selection(&self.schema_version)
    }
}

impl CognitiveRunSchemaVersioned for CognitiveToolObservation {
    const COGNITIVE_RECORD_KIND: &'static str = "cognitive_tool_observation";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn schema_selection(&self) -> Option<&'static str> {
        cognitive_run_schema_selection(&self.schema_version)
    }
}

impl CognitiveRunSchemaVersioned for CognitiveRawVerifierEvidence {
    const COGNITIVE_RECORD_KIND: &'static str = "cognitive_raw_verifier";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }

    fn schema_selection(&self) -> Option<&'static str> {
        cognitive_run_schema_selection(&self.schema_version)
    }
}

/// A cognitive-run record whose declared `schema_version` this build does not read.
///
/// Refusing here means "no meaning as current data"; it never means "reinterpret these
/// bytes under current field meanings".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CognitiveRunSchemaMismatch {
    /// The canonical-record kind that was refused.
    pub record_kind: &'static str,
    /// The version the decoded bytes declared.
    pub declared_version: String,
    /// The only version this build reads.
    pub supported_version: &'static str,
}

impl std::fmt::Display for CognitiveRunSchemaMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} declares schema_version {:?}; this build reads only {:?}",
            self.record_kind, self.declared_version, self.supported_version
        )
    }
}

impl std::error::Error for CognitiveRunSchemaMismatch {}

/// The single owner validation step for schema-bearing cognitive-run records.
///
/// Applied at every real decoding boundary - the `eliot-app` cognitive decoders and the
/// `eliot-engine` writer / cognitive-disposition loaders - before a record may authorize
/// candidate submission, terminal progression, shared-gate/disposition logic or tool
/// evidence. Typed, so the failure stays typed across the layer boundary.
pub fn require_current_cognitive_run_schema<T: CognitiveRunSchemaVersioned>(
    record: &T,
) -> Result<&'static str, CognitiveRunSchemaMismatch> {
    record
        .schema_selection()
        .ok_or_else(|| CognitiveRunSchemaMismatch {
            record_kind: T::COGNITIVE_RECORD_KIND,
            declared_version: record.schema_version().to_owned(),
            supported_version: COGNITIVE_RUN_SCHEMA_VERSION,
        })
}

#[cfg(test)]
mod schema_selection_tests {
    use super::*;

    const ATTEMPT: &str = r#"{
      "schema_version": "eliot-cognitive-run-v2",
      "run_id": "run-fixture-001",
      "call_id": "LC-01-source-opencode",
      "call_number": 5,
      "run_revision": 9,
      "expected_previous_revision": 8,
      "contract_receipt": {
        "receipt_id": "11111111-1111-1111-1111-111111111111",
        "write_id": "22222222-2222-2222-2222-222222222222"
      },
      "invocation_id": "invocation-fixture-001",
      "candidate_write_id": null,
      "provider_calls_consumed": 4,
      "hard_provider_call_cap": 18,
      "status": "attempting",
      "execution": {
        "executable_sha256": "seal-executable-fixture",
        "provider_executable_sha256": "seal-provider-fixture",
        "argv_sha256": "seal-argv-fixture",
        "environment_sha256": "seal-environment-fixture",
        "cwd_sha256": "seal-cwd-fixture",
        "bundle_sha256": "seal-bundle-fixture",
        "prompt_sha256": "seal-prompt-fixture"
      },
      "capability": null,
      "shared_gate": null,
      "created_at": "2026-09-30T11:41:12Z"
    }"#;

    const ATTEMPT_FOREIGN: &str = r#"{
      "schema_version": "eliot-cognitive-run-v1",
      "run_id": "run-fixture-001",
      "call_id": "LC-01-source-opencode",
      "call_number": 5,
      "run_revision": 9,
      "expected_previous_revision": 8,
      "contract_receipt": {
        "receipt_id": "11111111-1111-1111-1111-111111111111",
        "write_id": "22222222-2222-2222-2222-222222222222"
      },
      "invocation_id": "invocation-fixture-001",
      "candidate_write_id": null,
      "provider_calls_consumed": 4,
      "hard_provider_call_cap": 18,
      "status": "attempting",
      "execution": {
        "executable_sha256": "seal-executable-fixture",
        "provider_executable_sha256": "seal-provider-fixture",
        "argv_sha256": "seal-argv-fixture",
        "environment_sha256": "seal-environment-fixture",
        "cwd_sha256": "seal-cwd-fixture",
        "bundle_sha256": "seal-bundle-fixture",
        "prompt_sha256": "seal-prompt-fixture"
      },
      "capability": null,
      "shared_gate": null,
      "created_at": "2026-09-30T11:41:12Z"
    }"#;

    const TERMINAL: &str = r#"{
      "schema_version": "eliot-cognitive-run-v2",
      "run_id": "run-fixture-001",
      "call_id": "LC-01-source-opencode",
      "call_number": 5,
      "run_revision": 10,
      "expected_previous_revision": 9,
      "attempt_receipt": {
        "receipt_id": "33333333-3333-3333-3333-333333333333",
        "write_id": "44444444-4444-4444-4444-444444444444"
      },
      "status": "succeeded",
      "execution": {
        "executable_sha256": "seal-executable-fixture",
        "provider_executable_sha256": "seal-provider-fixture",
        "argv_sha256": "seal-argv-fixture",
        "environment_sha256": "seal-environment-fixture",
        "cwd_sha256": "seal-cwd-fixture",
        "bundle_sha256": "seal-bundle-fixture",
        "prompt_sha256": "seal-prompt-fixture"
      },
      "process_sha256": null,
      "stdout_sha256": null,
      "stderr_sha256": null,
      "provider_output_sha256": null,
      "candidate_write_id": null,
      "candidate_receipt": null,
      "host_observation": null,
      "tool_observation_receipts": [],
      "raw_verifier_receipts": [],
      "reason": "provider exited zero",
      "no_redispatch": true,
      "finished_at": "2026-09-30T11:42:12Z"
    }"#;

    const TERMINAL_FOREIGN: &str = r#"{
      "schema_version": "eliot-cognitive-run-v1",
      "run_id": "run-fixture-001",
      "call_id": "LC-01-source-opencode",
      "call_number": 5,
      "run_revision": 10,
      "expected_previous_revision": 9,
      "attempt_receipt": {
        "receipt_id": "33333333-3333-3333-3333-333333333333",
        "write_id": "44444444-4444-4444-4444-444444444444"
      },
      "status": "succeeded",
      "execution": {
        "executable_sha256": "seal-executable-fixture",
        "provider_executable_sha256": "seal-provider-fixture",
        "argv_sha256": "seal-argv-fixture",
        "environment_sha256": "seal-environment-fixture",
        "cwd_sha256": "seal-cwd-fixture",
        "bundle_sha256": "seal-bundle-fixture",
        "prompt_sha256": "seal-prompt-fixture"
      },
      "process_sha256": null,
      "stdout_sha256": null,
      "stderr_sha256": null,
      "provider_output_sha256": null,
      "candidate_write_id": null,
      "candidate_receipt": null,
      "host_observation": null,
      "tool_observation_receipts": [],
      "raw_verifier_receipts": [],
      "reason": "provider exited zero",
      "no_redispatch": true,
      "finished_at": "2026-09-30T11:42:12Z"
    }"#;

    const OBSERVATION: &str = r#"{
      "schema_version": "eliot-cognitive-run-v2",
      "run_id": "run-fixture-001",
      "call_subject_ref": "subject-fixture-001",
      "observation_id": "55555555-5555-5555-5555-555555555555",
      "call_id": "LC-01-source-opencode",
      "call_number": 5,
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "session_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
      "host": "opencode",
      "attempt_receipt": {
        "receipt_id": "33333333-3333-3333-3333-333333333333",
        "write_id": "44444444-4444-4444-4444-444444444444"
      },
      "tool_name": "eliot_recall_l0",
      "outcome": "observed",
      "sealed_truth_revision": "fixture-revision-5",
      "observed_memory_revision": null,
      "arguments_sha256": "arguments-fixture",
      "result_sha256": "result-fixture",
      "requested_handles": [],
      "returned_handles": [],
      "observed_at": "2026-09-30T11:41:30Z"
    }"#;

    const OBSERVATION_FOREIGN: &str = r#"{
      "schema_version": "eliot-cognitive-run-v1",
      "run_id": "run-fixture-001",
      "call_subject_ref": "subject-fixture-001",
      "observation_id": "55555555-5555-5555-5555-555555555555",
      "call_id": "LC-01-source-opencode",
      "call_number": 5,
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "session_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
      "host": "opencode",
      "attempt_receipt": {
        "receipt_id": "33333333-3333-3333-3333-333333333333",
        "write_id": "44444444-4444-4444-4444-444444444444"
      },
      "tool_name": "eliot_recall_l0",
      "outcome": "observed",
      "sealed_truth_revision": "fixture-revision-5",
      "observed_memory_revision": null,
      "arguments_sha256": "arguments-fixture",
      "result_sha256": "result-fixture",
      "requested_handles": [],
      "returned_handles": [],
      "observed_at": "2026-09-30T11:41:30Z"
    }"#;

    const EVIDENCE: &str = r#"{
      "schema_version": "eliot-cognitive-run-v2",
      "run_id": "run-fixture-001",
      "call_id": "LC-01-target-opencode-treatment",
      "call_number": 1,
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "attempt_receipt": {
        "receipt_id": "33333333-3333-3333-3333-333333333333",
        "write_id": "44444444-4444-4444-4444-444444444444"
      },
      "execution": {
        "executable_sha256": "seal-executable-fixture",
        "provider_executable_sha256": "seal-provider-fixture",
        "argv_sha256": "seal-argv-fixture",
        "environment_sha256": "seal-environment-fixture",
        "cwd_sha256": "seal-cwd-fixture",
        "bundle_sha256": "seal-bundle-fixture",
        "prompt_sha256": "seal-prompt-fixture"
      },
      "process_sha256": null,
      "stdout_sha256": null,
      "stderr_sha256": null,
      "provider_output_sha256": null,
      "host_observation": null,
      "tool_observation_receipts": [],
      "verifier_version": "verifier-fixture-1",
      "checks_sha256": "checks-fixture",
      "passed": true,
      "verified_at": "2026-09-30T11:43:12Z"
    }"#;

    const EVIDENCE_FOREIGN: &str = r#"{
      "schema_version": "eliot-cognitive-run-v1",
      "run_id": "run-fixture-001",
      "call_id": "LC-01-target-opencode-treatment",
      "call_number": 1,
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "attempt_receipt": {
        "receipt_id": "33333333-3333-3333-3333-333333333333",
        "write_id": "44444444-4444-4444-4444-444444444444"
      },
      "execution": {
        "executable_sha256": "seal-executable-fixture",
        "provider_executable_sha256": "seal-provider-fixture",
        "argv_sha256": "seal-argv-fixture",
        "environment_sha256": "seal-environment-fixture",
        "cwd_sha256": "seal-cwd-fixture",
        "bundle_sha256": "seal-bundle-fixture",
        "prompt_sha256": "seal-prompt-fixture"
      },
      "process_sha256": null,
      "stdout_sha256": null,
      "stderr_sha256": null,
      "provider_output_sha256": null,
      "host_observation": null,
      "tool_observation_receipts": [],
      "verifier_version": "verifier-fixture-1",
      "checks_sha256": "checks-fixture",
      "passed": true,
      "verified_at": "2026-09-30T11:43:12Z"
    }"#;

    const CONTRACT: &str = r#"{
      "schema_version": "eliot-cognitive-run-v2",
      "harness_version": "harness-fixture-1",
      "instance_name": "instance-fixture",
      "run_id": "run-fixture-001",
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "governor_nonce": "dddddddd-dddd-dddd-dddd-dddddddddddd",
      "harness_script_sha256": "harness-script-fixture",
      "cases_sha256": "cases-fixture",
      "exposure_map_sha256": "exposure-map-fixture",
      "output_contract_sha256": "output-contract-fixture",
      "models_sha256": "models-fixture",
      "source_commit": "source-commit-fixture",
      "policy_snapshot_id": "policy-snapshot-fixture",
      "output_root": "output-root-fixture",
      "timeout_seconds": 120,
      "exact_plan": [],
      "hard_provider_call_cap": 18,
      "contract_sha256": "contract-fixture",
      "sealed_at": "2026-09-30T11:40:12Z"
    }"#;

    const CONTRACT_FOREIGN: &str = r#"{
      "schema_version": "eliot-cognitive-run-v1",
      "harness_version": "harness-fixture-1",
      "instance_name": "instance-fixture",
      "run_id": "run-fixture-001",
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "governor_nonce": "dddddddd-dddd-dddd-dddd-dddddddddddd",
      "harness_script_sha256": "harness-script-fixture",
      "cases_sha256": "cases-fixture",
      "exposure_map_sha256": "exposure-map-fixture",
      "output_contract_sha256": "output-contract-fixture",
      "models_sha256": "models-fixture",
      "source_commit": "source-commit-fixture",
      "policy_snapshot_id": "policy-snapshot-fixture",
      "output_root": "output-root-fixture",
      "timeout_seconds": 120,
      "exact_plan": [],
      "hard_provider_call_cap": 18,
      "contract_sha256": "contract-fixture",
      "sealed_at": "2026-09-30T11:40:12Z"
    }"#;

    fn refused<T>(raw: &str, kind: &'static str) -> Result<CognitiveRunSchemaMismatch, String>
    where
        T: serde::de::DeserializeOwned + CognitiveRunSchemaVersioned,
    {
        let record: T = serde_json::from_str(raw)
            .map_err(|error| format!("fixture {kind} must decode structurally: {error}"))?;
        match require_current_cognitive_run_schema(&record) {
            Ok(admitted) => Err(format!("fixture {kind} must be refused, admitted {admitted:?}")),
            Err(mismatch) => {
                assert_eq!(mismatch.record_kind, kind);
                assert_eq!(mismatch.declared_version, "eliot-cognitive-run-v1");
                assert_eq!(mismatch.supported_version, COGNITIVE_RUN_SCHEMA_VERSION);
                Ok(mismatch)
            }
        }
    }

    // WORK_UNIT_CASE: 935/9
    #[test]
    fn run_schema_selection_admits_only_the_current_owner_version() {
        assert_eq!(
            cognitive_run_schema_selection(COGNITIVE_RUN_SCHEMA_VERSION),
            Some(COGNITIVE_RUN_SCHEMA_VERSION)
        );
        // No supported legacy is recorded anywhere in the repository: the only
        // emitted literal is `COGNITIVE_RUN_SCHEMA_VERSION`, so even the
        // plausible-looking predecessor name is refused rather than migrated.
        for foreign in [
            "",
            "v2",
            "eliot-cognitive-run-v1",
            "eliot-cognitive-run-v3",
            "ELIOT-COGNITIVE-RUN-V2",
            " eliot-cognitive-run-v2",
        ] {
            assert_eq!(
                cognitive_run_schema_selection(foreign),
                None,
                "owner selection must refuse {foreign:?}"
            );
        }
    }

    // WORK_UNIT_CASE: 935/7
    #[test]
    fn current_run_records_decode_and_pass_owner_selection() -> Result<(), serde_json::Error> {
        fn admitted<T>(raw: &str) -> Result<&'static str, CognitiveRunSchemaMismatch>
        where
            T: serde::de::DeserializeOwned + CognitiveRunSchemaVersioned,
        {
            let record: T = serde_json::from_str(raw)?;
            require_current_cognitive_run_schema(&record)
        }
        assert_eq!(
            admitted::<CognitiveRunContract>(CONTRACT)?,
            COGNITIVE_RUN_SCHEMA_VERSION
        );
        assert_eq!(
            admitted::<CognitiveRunAttempt>(ATTEMPT)?,
            COGNITIVE_RUN_SCHEMA_VERSION
        );
        assert_eq!(
            admitted::<CognitiveRunTerminal>(TERMINAL)?,
            COGNITIVE_RUN_SCHEMA_VERSION
        );
        assert_eq!(
            admitted::<CognitiveToolObservation>(OBSERVATION)?,
            COGNITIVE_RUN_SCHEMA_VERSION
        );
        assert_eq!(
            admitted::<CognitiveRawVerifierEvidence>(EVIDENCE)?,
            COGNITIVE_RUN_SCHEMA_VERSION
        );
        Ok(())
    }

    // WORK_UNIT_CASE: 935/8
    #[test]
    fn foreign_run_records_decode_but_fail_owner_selection() -> Result<(), String> {
        refused::<CognitiveRunContract>(CONTRACT_FOREIGN, "cognitive_run_contract")?;
        refused::<CognitiveRunAttempt>(ATTEMPT_FOREIGN, "cognitive_run_attempt")?;
        refused::<CognitiveRunTerminal>(TERMINAL_FOREIGN, "cognitive_run_terminal")?;
        refused::<CognitiveToolObservation>(OBSERVATION_FOREIGN, "cognitive_tool_observation")?;
        refused::<CognitiveRawVerifierEvidence>(EVIDENCE_FOREIGN, "cognitive_raw_verifier")?;
        Ok(())
    }

    // WORK_UNIT_CASE: 935/15
    #[test]
    fn owner_refusal_precedes_any_authority_consumption() -> Result<(), String> {
        let attempt: CognitiveRunAttempt = serde_json::from_str(ATTEMPT_FOREIGN)
            .map_err(|error| format!("foreign attempt must still decode structurally: {error}"))?;
        // The candidate-submit path consumes `status`, `capability` and
        // `candidate_write_id` as authority. The refusal must land first: no
        // authority field may be read before this check passes.
        let message = match require_current_cognitive_run_schema(&attempt) {
            Ok(admitted) => {
                return Err(format!("foreign attempt must be refused, admitted {admitted:?}"));
            }
            Err(refusal) => refusal.to_string(),
        };
        assert!(
            message.contains("cognitive_run_attempt")
                && message.contains("eliot-cognitive-run-v1")
                && message.contains(COGNITIVE_RUN_SCHEMA_VERSION),
            "refusal must name the kind, the declared version and the supported version: {message}"
        );
        Ok(())
    }
}
