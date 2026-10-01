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

/// Named legacy `eliot-cognitive-run` versions this build admits, each paired with the
/// current version its bytes are read under.
///
/// Empty by evidence, not by omission: a repository-wide search finds exactly one
/// `eliot-cognitive-run-v*` literal, [`COGNITIVE_RUN_SCHEMA_VERSION`], and every
/// producer of the schema-bearing records in this file stamps that constant. No legacy
/// revision has ever been written, so there is no named migration to preserve here. A
/// future supported legacy revision MUST be added to this table by name together with
/// its migration; it MUST NOT be inferred from the presence of a `schema_version`
/// string on decoded bytes.
pub const COGNITIVE_RUN_NAMED_LEGACY_MIGRATIONS: &[(&str, &str)] = &[];

/// A schema-bearing cognitive-run record whose declared `schema_version` this build
/// selects explicitly.
///
/// Implemented by exactly the records this build reads back from the canonical store
/// and then acts on: the sealed contract, the per-call attempt, the per-call terminal,
/// the daemon-observed tool event and the raw-verifier evidence. The generic decoders
/// (`CanonicalStore::canonical_record_by_write_id<T>`,
/// `CanonicalStore::canonical_records_by_subject_ref<T>` and
/// `cognitive_record_by_revision<T>`) only deserialize `T`, so without this owner step
/// a foreign or future layout that happens to fit the current fields would be consumed
/// as current authority.
pub trait CognitiveRunSchemaVersioned {
    /// The canonical-record kind this record is stored under, named in the refusal so
    /// an operator can see which boundary rejected the bytes.
    const COGNITIVE_RECORD_KIND: &'static str;

    /// The version these decoded bytes declare.
    fn schema_version(&self) -> &str;
}

/// A decoded cognitive-run record whose declared `schema_version` this build does not
/// read.
///
/// Refusing here means "no meaning as current data". It never means "reinterpret these
/// bytes under current field meanings".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CognitiveRunSchemaMismatch {
    /// The canonical-record kind that was refused.
    pub record_kind: &'static str,
    /// The version the decoded bytes declared.
    pub declared_version: String,
    /// The only version this build reads and interprets.
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

/// The single owner validation step for every schema-bearing cognitive-run record.
///
/// Returns the version this build reads the record under, or refuses. This is the ONLY
/// version scheme for these records; it reuses the existing
/// [`COGNITIVE_RUN_SCHEMA_VERSION`] constant and the existing
/// [`COGNITIVE_RUN_NAMED_LEGACY_MIGRATIONS`] table, and adds no second mechanism.
///
/// Callers MUST apply this at the real decoding/admission boundary, before a decoded
/// record may authorize candidate submission, terminal progression,
/// shared-gate/disposition logic or tool evidence. Structural closure alone
/// (`deny_unknown_fields`) proves the shape, never the version.
pub fn require_current_cognitive_run_schema<T: CognitiveRunSchemaVersioned>(
    record: &T,
) -> Result<&'static str, CognitiveRunSchemaMismatch> {
    let declared = record.schema_version();
    if declared == COGNITIVE_RUN_SCHEMA_VERSION {
        return Ok(COGNITIVE_RUN_SCHEMA_VERSION);
    }
    COGNITIVE_RUN_NAMED_LEGACY_MIGRATIONS
        .iter()
        .find(|(legacy, _)| *legacy == declared)
        .map(|(_, admitted)| *admitted)
        .ok_or_else(|| CognitiveRunSchemaMismatch {
            record_kind: T::COGNITIVE_RECORD_KIND,
            declared_version: declared.to_owned(),
            supported_version: COGNITIVE_RUN_SCHEMA_VERSION,
        })
}

impl CognitiveRunSchemaVersioned for CognitiveRunContract {
    const COGNITIVE_RECORD_KIND: &'static str = "cognitive_run_contract";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }
}

impl CognitiveRunSchemaVersioned for CognitiveRunAttempt {
    const COGNITIVE_RECORD_KIND: &'static str = "cognitive_run_attempt";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }
}

impl CognitiveRunSchemaVersioned for CognitiveRunTerminal {
    const COGNITIVE_RECORD_KIND: &'static str = "cognitive_run_terminal";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }
}

impl CognitiveRunSchemaVersioned for CognitiveToolObservation {
    const COGNITIVE_RECORD_KIND: &'static str = "cognitive_tool_observation";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }
}

impl CognitiveRunSchemaVersioned for CognitiveRawVerifierEvidence {
    const COGNITIVE_RECORD_KIND: &'static str = "cognitive_raw_verifier";

    fn schema_version(&self) -> &str {
        &self.schema_version
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod schema_selection_tests {
    use super::*;
    use crate::{PROJECT_UNDERSTANDING_SCHEMA_VERSION, ProjectUnderstandingModel};

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

    const UNDERSTANDING: &str = r#"{
      "schema_version": "project-understanding-v1",
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "task-fixture-001",
      "revision_fence": 7,
      "intent": {
        "exact_user_goal_ref": "eliot/task/task-fixture-001@7",
        "normalized_goal": "fixture goal",
        "desired_state_transition": "fixture transition",
        "non_goals": [],
        "acceptance_refs": ["accept:fixture-1"]
      },
      "system": {
        "project_purpose": "fixture purpose",
        "subsystem_refs": ["sub:core"],
        "owner_modules": ["mod:core"],
        "entrypoint_refs": ["ep:main"]
      },
      "causal_model": {
        "hops": [{
          "hop_kind": "intent_to_concept",
          "from": "intent:task-fixture-001",
          "relation": "scoped_to",
          "to": "concept:core",
          "evidence_refs": ["artifact:fixture-1"],
          "status": "supported"
        }],
        "unknown_hops": [],
        "required_probes": []
      },
      "invariants": ["inv:fixture-1"],
      "danger_and_negative_memory": [],
      "current_truth_refs": ["claim:fixture-1"],
      "historical_or_stale_refs": [],
      "memory_refs_used": [],
      "files_to_inspect": [],
      "files_to_change": [],
      "predicted_changed_paths": [],
      "predicted_failing_verifiers": [],
      "next_allowed_action": "act-fixture",
      "expected_observable": "obs-fixture",
      "verifier_ref": "verifier:ci-fixture",
      "stop_condition": "stop-fixture"
    }"#;

    /// Substitute only the declared `schema_version` literal, leaving every other byte of
    /// the fixture identical. The foreign-version document must stay structurally
    /// decodable, so the refusal is proven to come from version selection and not from a
    /// shape rejection.
    fn with_version(document: &str, current: &str, foreign: &str) -> String {
        document.replace(current, foreign)
    }

    // Positive case: a canonical record carrying the CURRENT supported schema_version
    // still decodes byte-for-byte and is admitted, so its existing effect (candidate
    // submission authority, terminal progression, shared-gate/disposition, tool
    // evidence, and project-understanding admission) is unchanged.
    #[test]
    fn current_schema_version_still_decodes_and_is_admitted() {
        let attempt: CognitiveRunAttempt =
            serde_json::from_str(ATTEMPT).expect("current-version attempt must decode");
        assert_eq!(
            require_current_cognitive_run_schema(&attempt).expect("current schema is admitted"),
            COGNITIVE_RUN_SCHEMA_VERSION,
        );
        // The decoded fields the admission boundary authorizes on are intact.
        assert_eq!(attempt.status, CognitiveRunCallStatus::Attempting);
        assert_eq!(attempt.call_id, "LC-01-source-opencode");
        assert_eq!(
            attempt.contract_receipt.write_id.to_string(),
            "22222222-2222-2222-2222-222222222222",
        );

        let terminal: CognitiveRunTerminal =
            serde_json::from_str(TERMINAL).expect("current-version terminal must decode");
        assert_eq!(
            require_current_cognitive_run_schema(&terminal).expect("current schema is admitted"),
            COGNITIVE_RUN_SCHEMA_VERSION,
        );
        assert_eq!(terminal.status, CognitiveRunCallStatus::Succeeded);

        let model: ProjectUnderstandingModel =
            serde_json::from_str(UNDERSTANDING).expect("current-version model must decode");
        assert_eq!(
            model.admission().expect("current schema is admitted"),
            PROJECT_UNDERSTANDING_SCHEMA_VERSION,
        );
    }

    // Refusal case: a record carrying a foreign or future schema_version decodes
    // structurally but is refused at the SAME owner step, so it produces no candidate
    // submission, no terminal progression, no shared-gate/disposition and no
    // tool-evidence reconciliation, and cannot be consumed as current project proof.
    #[test]
    fn foreign_schema_version_is_refused_at_the_admission_boundary() {
        let attempt: CognitiveRunAttempt = serde_json::from_str(&with_version(
            ATTEMPT,
            COGNITIVE_RUN_SCHEMA_VERSION,
            "eliot-cognitive-run-v99",
        ))
        .expect("foreign-version bytes must still decode structurally");
        let mismatch = require_current_cognitive_run_schema(&attempt)
            .expect_err("a foreign version must be refused, never reinterpreted");
        assert_eq!(mismatch.record_kind, "cognitive_run_attempt");
        assert_eq!(mismatch.declared_version, "eliot-cognitive-run-v99");
        assert_eq!(mismatch.supported_version, COGNITIVE_RUN_SCHEMA_VERSION);

        let terminal: CognitiveRunTerminal = serde_json::from_str(&with_version(
            TERMINAL,
            COGNITIVE_RUN_SCHEMA_VERSION,
            "eliot-cognitive-run-v99",
        ))
        .expect("foreign-version bytes must still decode structurally");
        let mismatch = require_current_cognitive_run_schema(&terminal)
            .expect_err("a foreign version must be refused, never reinterpreted");
        assert_eq!(mismatch.record_kind, "cognitive_run_terminal");

        let model: ProjectUnderstandingModel = serde_json::from_str(&with_version(
            UNDERSTANDING,
            PROJECT_UNDERSTANDING_SCHEMA_VERSION,
            "project-understanding-v99",
        ))
        .expect("foreign-version bytes must still decode structurally");
        let mismatch = model
            .admission()
            .expect_err("a foreign version must be refused, never reinterpreted");
        assert_eq!(mismatch.declared_version, "project-understanding-v99");
        assert_eq!(mismatch.supported_version, PROJECT_UNDERSTANDING_SCHEMA_VERSION);
    }
}
