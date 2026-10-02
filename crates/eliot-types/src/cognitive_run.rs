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

/// The named legacy `eliot-cognitive-run` revisions this build still reads, each paired
/// with the current revision its bytes are read under.
///
/// Empty by evidence, not by omission: the only `eliot-cognitive-run-v*` spelling in the
/// repository is [`COGNITIVE_RUN_SCHEMA_VERSION`], and every producer of the
/// schema-bearing records below stamps exactly that constant, so no other revision has
/// ever been written. `I5.22` requires migration identity to be explicit and immutable
/// after release, so a legacy revision this build admits must be added here BY NAME
/// together with the migration that gives it meaning. It must never be inferred from the
/// presence of a `schema_version` string on decoded bytes.
pub const COGNITIVE_RUN_NAMED_LEGACY_MIGRATIONS: &[(&str, &str)] = &[];

/// Bounded refusal for a cognitive-run schema version this build does not own.
///
/// A decoded attempt, terminal, tool observation or raw-verifier record IS current
/// authority: it admits a capability-bound candidate, progresses a terminal, settles the
/// reciprocal shared gate and reconciles tool evidence. A layout this build does not own
/// must therefore fail at the decoder instead of being read on the current field
/// meanings. `deny_unknown_fields` closed only the shape. The message is fixed and never
/// echoes the received version back onto an operator surface, matching the control-wal
/// refusals in `runtime_supervision`.
fn unsupported_cognitive_run_schema_version<E>(expected: &str) -> E
where
    E: serde::de::Error,
{
    E::custom(format!("unsupported schema version; expected {expected}"))
}

/// The one owner version-selection step for every schema-bearing cognitive-run record in
/// this file.
///
/// Every `Deserialize` below binds `schema_version` here, so the real decoders --
/// `CanonicalStore::canonical_record_by_write_id<T>`,
/// `CanonicalStore::canonical_records_by_subject_ref<T>`, `cognitive_record_by_revision<T>`
/// and every direct `serde_json::from_value`/`from_reader` -- select the version as
/// CONTENT of the decoded document before a record exists. There is no second scheme and
/// no per-caller copy: a caller that holds one of these records already holds a version
/// this build owns, or the decode refused. A MISSING `schema_version` has no
/// `serde(default)` and is refused by the missing-field path.
fn select_cognitive_run_schema_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let declared = String::deserialize(deserializer)?;
    if declared == COGNITIVE_RUN_SCHEMA_VERSION
        || COGNITIVE_RUN_NAMED_LEGACY_MIGRATIONS
            .iter()
            .any(|(legacy, _)| *legacy == declared)
    {
        Ok(declared)
    } else {
        Err(unsupported_cognitive_run_schema_version(
            COGNITIVE_RUN_SCHEMA_VERSION,
        ))
    }
}

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
    /// Selected by [`select_cognitive_run_schema_version`] at the decoder: the sealed
    /// contract selects the exact plan, the run identity and the reciprocal gate every
    /// other record in this file is authorized against.
    #[serde(deserialize_with = "select_cognitive_run_schema_version")]
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
    /// Selected by [`select_cognitive_run_schema_version`] at the decoder: these
    /// observations are reconciled into a terminal's evidence set and decide whether a
    /// call saw its sealed job fetch, its candidate submission and its exact memory
    /// exposure.
    #[serde(deserialize_with = "select_cognitive_run_schema_version")]
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
    /// Selected by [`select_cognitive_run_schema_version`] at the decoder: the attempt is
    /// the capability and write-identity authority that admits a candidate submission
    /// and that a terminal is written against.
    #[serde(deserialize_with = "select_cognitive_run_schema_version")]
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
    /// Selected by [`select_cognitive_run_schema_version`] at the decoder: `Succeeded`,
    /// the receipt chain, the verifier count and the shared-gate facts are all read from
    /// a terminal, so a layout this build does not own must not decode as one.
    #[serde(deserialize_with = "select_cognitive_run_schema_version")]
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
    /// Selected by [`select_cognitive_run_schema_version`] at the decoder: this evidence
    /// supplies the raw-verifier references a canonical case disposition is built from.
    #[serde(deserialize_with = "select_cognitive_run_schema_version")]
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

#[cfg(test)]
mod schema_version_selection {
    use super::*;

    /// One owner producer's exact wire form for a `CognitiveRunAttempt`, carrying the
    /// current schema version and every field the capability-bound candidate-submission
    /// admission path authorizes on.
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
        "candidate_write_id": "33333333-3333-3333-3333-333333333333",
        "provider_calls_consumed": 4,
        "hard_provider_call_cap": 18,
        "status": "attempting",
        "execution": {
          "executable_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
          "provider_executable_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
          "argv_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
          "environment_sha256": "4444444444444444444444444444444444444444444444444444444444444444",
          "cwd_sha256": "5555555555555555555555555555555555555555555555555555555555555555",
          "bundle_sha256": "6666666666666666666666666666666666666666666666666666666666666666",
          "prompt_sha256": "7777777777777777777777777777777777777777777777777777777777777777"
        },
        "capability": null,
        "shared_gate": null,
        "created_at": "2026-09-30T11:41:12Z"
      }"#;

    /// The terminal whose `Succeeded`, receipt chain and verifier count settle the
    /// reciprocal shared gate and the canonical case disposition.
    const TERMINAL: &str = r#"{
        "schema_version": "eliot-cognitive-run-v2",
        "run_id": "run-fixture-001",
        "call_id": "LC-01-source-opencode",
        "call_number": 5,
        "run_revision": 10,
        "expected_previous_revision": 9,
        "attempt_receipt": {
          "receipt_id": "11111111-1111-1111-1111-111111111111",
          "write_id": "22222222-2222-2222-2222-222222222222"
        },
        "status": "succeeded",
        "execution": {
          "executable_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
          "provider_executable_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
          "argv_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
          "environment_sha256": "4444444444444444444444444444444444444444444444444444444444444444",
          "cwd_sha256": "5555555555555555555555555555555555555555555555555555555555555555",
          "bundle_sha256": "6666666666666666666666666666666666666666666666666666666666666666",
          "prompt_sha256": "7777777777777777777777777777777777777777777777777777777777777777"
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

    /// The daemon-observed tool event reconciled into a terminal's receipt set.
    const TOOL_OBSERVATION: &str = r#"{
        "schema_version": "eliot-cognitive-run-v2",
        "run_id": "run-fixture-001",
        "call_subject_ref": "run-fixture-001:call:5",
        "observation_id": "44444444-4444-4444-4444-444444444444",
        "call_id": "LC-01-source-opencode",
        "call_number": 5,
        "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "session_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
        "host": "opencode",
        "attempt_receipt": {
          "receipt_id": "11111111-1111-1111-1111-111111111111",
          "write_id": "22222222-2222-2222-2222-222222222222"
        },
        "tool_name": "eliot_agent_candidate_submit",
        "outcome": "succeeded",
        "sealed_truth_revision": "claim:fixture-1",
        "observed_memory_revision": null,
        "arguments_sha256": "8888888888888888888888888888888888888888888888888888888888888888",
        "result_sha256": "9999999999999999999999999999999999999999999999999999999999999999",
        "requested_handles": [],
        "returned_handles": [],
        "observed_at": "2026-09-30T11:41:30Z"
      }"#;

    /// The raw-verifier evidence whose `passed` fact becomes a disposition verifier ref.
    const RAW_VERIFIER: &str = r#"{
        "schema_version": "eliot-cognitive-run-v2",
        "run_id": "run-fixture-001",
        "call_id": "LC-01-source-opencode",
        "call_number": 5,
        "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "attempt_receipt": {
          "receipt_id": "11111111-1111-1111-1111-111111111111",
          "write_id": "22222222-2222-2222-2222-222222222222"
        },
        "execution": {
          "executable_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
          "provider_executable_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
          "argv_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
          "environment_sha256": "4444444444444444444444444444444444444444444444444444444444444444",
          "cwd_sha256": "5555555555555555555555555555555555555555555555555555555555555555",
          "bundle_sha256": "6666666666666666666666666666666666666666666666666666666666666666",
          "prompt_sha256": "7777777777777777777777777777777777777777777777777777777777777777"
        },
        "process_sha256": null,
        "stdout_sha256": null,
        "stderr_sha256": null,
        "provider_output_sha256": null,
        "host_observation": null,
        "tool_observation_receipts": [],
        "verifier_version": "verifier-fixture-001",
        "checks_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "passed": true,
        "verified_at": "2026-09-30T11:42:30Z"
      }"#;

    /// The sealed contract whose exact plan selects every other record in this file.
    const CONTRACT: &str = r#"{
        "schema_version": "eliot-cognitive-run-v2",
        "harness_version": "harness-fixture-001",
        "instance_name": "instance-fixture-001",
        "run_id": "run-fixture-001",
        "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "governor_nonce": "dddddddd-dddd-dddd-dddd-dddddddddddd",
        "harness_script_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        "cases_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
        "exposure_map_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
        "output_contract_sha256": "4444444444444444444444444444444444444444444444444444444444444444",
        "models_sha256": "5555555555555555555555555555555555555555555555555555555555555555",
        "source_commit": "commit-fixture-001",
        "policy_snapshot_id": "policy-fixture-001",
        "output_root": "out/run-fixture-001",
        "timeout_seconds": 120,
        "exact_plan": [],
        "hard_provider_call_cap": 18,
        "contract_sha256": "6666666666666666666666666666666666666666666666666666666666666666",
        "sealed_at": "2026-09-30T11:40:12Z"
      }"#;

    /// Every owner record, with the label its refusal is reported under.
    const RECORDS: [(&str, &str); 5] = [
        ("attempt", ATTEMPT),
        ("terminal", TERMINAL),
        ("tool observation", TOOL_OBSERVATION),
        ("raw verifier", RAW_VERIFIER),
        ("contract", CONTRACT),
    ];

    /// Replace only the declared version literal. The refused document stays byte-for-byte
    /// otherwise identical and structurally well formed, so the refusal is proven to come
    /// from version selection and not from a shape rejection.
    fn with_version(document: &str, foreign: &str) -> String {
        document.replace(COGNITIVE_RUN_SCHEMA_VERSION, foreign)
    }

    /// Drop the declared version member entirely, so the refusal is proven to come from the
    /// missing-version path and not from a defaulted empty string.
    fn without_version(document: &str) -> String {
        document
            .lines()
            .filter(|line| !line.contains("\"schema_version\""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    // Positive case: every schema-bearing record still decodes under the CURRENT version
    // and keeps exactly the fields its authorization path reads, so candidate submission,
    // terminal progression, shared-gate/disposition and tool evidence behave unchanged.
    #[test]
    fn current_schema_version_still_decodes_and_keeps_its_authorization_fields() {
        let attempt: CognitiveRunAttempt = decode(ATTEMPT, "attempt");
        assert_eq!(attempt.schema_version, COGNITIVE_RUN_SCHEMA_VERSION);
        assert_eq!(attempt.status, CognitiveRunCallStatus::Attempting);
        assert_eq!(attempt.call_id, "LC-01-source-opencode");
        assert_eq!(
            attempt.contract_receipt.write_id.to_string(),
            "22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(
            attempt.candidate_write_id.map(|id| id.to_string()),
            Some("33333333-3333-3333-3333-333333333333".to_owned())
        );
        let terminal: CognitiveRunTerminal = decode(TERMINAL, "terminal");
        assert_eq!(terminal.status, CognitiveRunCallStatus::Succeeded);
        assert!(terminal.no_redispatch);
        let observation: CognitiveToolObservation = decode(TOOL_OBSERVATION, "tool observation");
        assert_eq!(observation.call_subject_ref, "run-fixture-001:call:5");
        assert_eq!(observation.host, AgentHostId::OpenCode);
        let evidence: CognitiveRawVerifierEvidence = decode(RAW_VERIFIER, "raw verifier");
        assert!(evidence.passed);
        let contract: CognitiveRunContract = decode(CONTRACT, "contract");
        assert_eq!(contract.run_id, "run-fixture-001");
        // An admitted record re-encodes and re-decodes under its own accepted bytes, so no
        // accepted wire form, digest input or list order moved.
        let encoded = match serde_json::to_string(&attempt) {
            Ok(encoded) => encoded,
            Err(error) => panic!("an admitted attempt must serialize: {error}"),
        };
        assert!(
            serde_json::from_str::<CognitiveRunAttempt>(&encoded).is_ok(),
            "an admitted attempt must re-decode under its own accepted bytes"
        );
    }

    // Refusal case: for every schema-bearing record a well-formed but WRONG version and a
    // MISSING version are both refused by the owner step, so neither can authorize
    // candidate submission, terminal progression, shared-gate/disposition logic or tool
    // evidence.
    #[test]
    fn unsupported_and_missing_schema_versions_are_refused_at_the_decoder() {
        // Every foreign document is still a well-formed JSON object, so the typed refusal
        // below cannot be a shape rejection.
        for (label, current) in RECORDS {
            if let Err(error) = serde_json::from_str::<serde_json::Value>(&with_version(
                current,
                "eliot-cognitive-run-v99",
            )) {
                panic!("the foreign {label} fixture must stay well formed: {error}");
            }
        }
        assert_refused::<CognitiveRunAttempt>(ATTEMPT, "attempt");
        assert_refused::<CognitiveRunTerminal>(TERMINAL, "terminal");
        assert_refused::<CognitiveToolObservation>(TOOL_OBSERVATION, "tool observation");
        assert_refused::<CognitiveRawVerifierEvidence>(RAW_VERIFIER, "raw verifier");
        assert_refused::<CognitiveRunContract>(CONTRACT, "contract");
    }

    /// Decode one owner record fixture under the current version, naming the record on
    /// failure.
    fn decode<T: serde::de::DeserializeOwned>(document: &str, label: &str) -> T {
        match serde_json::from_str(document) {
            Ok(record) => record,
            Err(error) => panic!("the current-version {label} must decode: {error}"),
        }
    }

    /// Assert that the foreign and the missing spellings of one owner record are both
    /// refused by the owner step, and that the refusal names the version this build owns.
    fn assert_refused<T: serde::de::DeserializeOwned>(current: &str, label: &str) {
        let foreign = with_version(current, "eliot-cognitive-run-v99");
        let Err(error) = serde_json::from_str::<T>(&foreign) else {
            panic!("a foreign layout must not decode as a current {label}")
        };
        assert!(
            error.to_string().contains(COGNITIVE_RUN_SCHEMA_VERSION),
            "the {label} refusal must name the version this build owns, got: {error}"
        );
        let missing = without_version(current);
        assert!(
            serde_json::from_str::<T>(&missing).is_err(),
            "a missing schema_version on a {label} must be refused, never defaulted"
        );
    }
}
