use crate::host_runtime::supervised_process::{
    ChildCriticality, ProcessRestartPolicy, RestartStrategy, SupervisedChildKind,
    SupervisedProcessSpec, run_supervised_process_blocking,
};
use anyhow::{Context, Result, bail, ensure};
use eliot_engine::{
    CognitiveFieldGradingService, HostBrokerService, validate_external_agent_execution_request,
    validate_provider_runtime_contract,
};
use eliot_types::{
    AdapterCapability, AdapterContext, AdapterRequest, AdapterResultStatus,
    AgentCapabilityEnvelope, AgentHostId, AgentInvocationRequest, AgentRole, AgentSessionState,
    AuthorityLeaseState, COGNITIVE_CORE_CONTINUATION_EXPECTED_PROVIDER_CALLS,
    COGNITIVE_CORE_CONTINUATION_MAX_PROVIDER_CALLS, COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION,
    COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS, COGNITIVE_DETERMINISTIC_EVIDENCE_SCHEMA_VERSION,
    COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION, COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION,
    COGNITIVE_FIELD_ORACLE_SCHEMA_VERSION, COGNITIVE_FIELD_PLAN_SCHEMA_VERSION,
    COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION, COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION,
    COGNITIVE_FIELD_PROVIDER_PROJECTION_SCHEMA_VERSION, COGNITIVE_FIELD_WORKER_SCHEMA_VERSION,
    COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION, COGNITIVE_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
    CognitiveDeterministicEvidenceReceipt, CognitiveDeterministicReport, CognitiveFieldCase,
    CognitiveFieldExecutionKey, CognitiveFieldPlan, CognitiveFieldPlanItem,
    CognitiveFieldProviderCallPlan, CognitiveFieldProviderEvidenceReceipt,
    CognitiveFieldProviderOutputProjection, CognitiveFieldProviderOutputReceipt,
    CognitiveFieldProviderPlan, CognitiveFieldProviderProjection, CognitiveFieldRole,
    CognitiveFieldRunContract, CognitiveFieldSuite, CognitiveFieldValidationReport,
    CognitiveHardGateEvidence, CognitiveHardGateKind, CognitiveJudgeResult,
    CognitiveMemoryCondition, CognitiveProviderMcpServer, CognitiveProviderRuntimeContract,
    CognitiveRuntimePreflightReceipt, CognitiveUnderstandingAnswer, CognitiveWorkerResult,
    ExternalAgentExecutionRequest, ExternalAgentPurpose, HostLaunchContract, HostMode,
    OperationJob, OperationJobState, OperationPhase, ProjectId, ProviderExecutionEvidence,
    ProviderRuntimeContract, SEAL_STAGING_CHECKPOINT_SCHEMA_VERSION, SealStagingCheckpoint,
    SealStagingState, TaskId, TaskIntentOracle, WorkItem, WorkItemId, WorkItemStatus, WorkScope,
    cognitive_judge_result_schema, cognitive_understanding_answer_schema,
    cognitive_worker_result_schema, inspect_secret_bytes,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::os::windows::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use uuid::Uuid;

pub fn validate(suite_path: &Path) -> Result<()> {
    let (_, report, _) = load_and_validate_suite(suite_path)?;
    print_json(&report)?;
    ensure!(
        report.valid,
        "cognitive field suite failed validation: {}",
        report.errors.join("; ")
    );
    Ok(())
}

pub fn schema(kind: &str) -> Result<()> {
    let schema = match kind.trim().to_ascii_lowercase().as_str() {
        "worker" => cognitive_worker_result_schema()?,
        "reader" => cognitive_understanding_answer_schema(),
        "judge" => cognitive_judge_result_schema()?,
        other => {
            bail!("unsupported cognitive field schema {other}; expected worker, reader, or judge")
        }
    };
    print_json(&schema)
}

const READER_SCHEMA_JSON_PLACEHOLDER: &str = "{{COGNITIVE_UNDERSTANDING_SCHEMA_JSON}}";
const READER_SCHEMA_SHA256_PLACEHOLDER: &str = "{{COGNITIVE_UNDERSTANDING_SCHEMA_SHA256}}";

#[derive(Clone, Debug, Eq, PartialEq)]
struct RenderedProviderContract {
    canonical_json: String,
    sha256: String,
}

const CORE_ROLE_EVIDENCE_PLAN_SCHEMA_VERSION: &str = "eliot-core-role-evidence-plan-v1";
const CORE_ROLE_REUSE_PROJECTION_SCHEMA_VERSION: &str = "eliot-core-role-reuse-projection-v1";
const LEGACY_EVIDENCE_ADMISSION_SCHEMA_VERSION: &str = "eliot-legacy-evidence-admission-v1";
const LEGACY_RUNTIME_BINDING_SCHEMA_VERSION: &str =
    "eliot-cognitive-provider-runtime-legacy-binding-v1";
const LEGACY_RUNTIME_RECONSTRUCTION_STATUS: &str = "derived_from_immutable_provider_receipt";
const LEGACY_WORKER_SOURCE_RUN_ID: &str = "cq-core-20260729-003";
const LEGACY_WORKER_SOURCE_CALL_ID: &str = "6f04e449-ecab-4555-8bd0-4a6bd762c1b4";
const LEGACY_WORKER_CASE_ID: &str = "U03";
const LEGACY_WORKER_ACCEPTANCE_RUN_ID: &str = "cq-core-20260730-005";
const LEGACY_WORKER_MISSING_FIELD: &str = "source_call.canonical_schema_sha256";
const PROVIDER_PLAN_SEAL_RECORD_SCHEMA_VERSION: &str = "eliot-provider-plan-seal-v1";
const SEAL_ARTIFACT_MANIFEST_SCHEMA_VERSION: &str = "eliot-seal-artifact-manifest-v1";
const ABANDONED_SEAL_ATTEMPT_SCHEMA_VERSION: &str = "eliot-abandoned-seal-attempt-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProviderPlanSealState {
    Validating,
    Staged,
    Activated,
    Published,
    Abandoned,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderPlanSealRecord {
    schema_version: String,
    seal_attempt_id: String,
    run_id: String,
    generation: u64,
    state: ProviderPlanSealState,
    contract_sha256: String,
    role_evidence_plan_sha256: String,
    staged_manifest_sha256: String,
    provider_plan_sha256: Option<String>,
    session_ids: Vec<eliot_types::AgentSessionId>,
    role_lease_ids: Vec<String>,
    work_item_ids: Vec<WorkItemId>,
    operation_job_ids: Vec<String>,
    staging_root: String,
    published_root: String,
    activated_at: Option<OffsetDateTime>,
    published_at: Option<OffsetDateTime>,
    abandoned_at: Option<OffsetDateTime>,
    failure_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealArtifactEntry {
    logical_kind: String,
    relative_path: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealArtifactManifest {
    schema_version: String,
    seal_attempt_id: String,
    run_id: String,
    generation: u64,
    entries: Vec<SealArtifactEntry>,
    manifest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AbandonedSealAttemptRecord {
    schema_version: String,
    seal_attempt_id: String,
    run_id: String,
    generation: u64,
    recovery_state: SealRecoveryRecordState,
    recovery_guarantee: String,
    failed_phase: ProviderPlanSealState,
    exact_error: String,
    created_session_ids: Vec<eliot_types::AgentSessionId>,
    created_role_lease_ids: Vec<String>,
    created_work_item_ids: Vec<WorkItemId>,
    created_operation_job_ids: Vec<String>,
    #[serde(default)]
    referenced_work_item_ids: Vec<WorkItemId>,
    #[serde(default)]
    referenced_invocation_ids: Vec<String>,
    #[serde(default)]
    present_work_item_ids: Vec<WorkItemId>,
    #[serde(default)]
    present_operation_job_ids: Vec<String>,
    #[serde(default)]
    transitioned_work_item_ids: Vec<WorkItemId>,
    #[serde(default)]
    transitioned_operation_job_ids: Vec<String>,
    #[serde(default)]
    missing_projections: Vec<MissingAuthorityProjection>,
    #[serde(default)]
    non_projection_proofs: Vec<NonProjectionProof>,
    #[serde(default)]
    recovery_steps: Vec<SealRecoveryStep>,
    quarantine_manifest_ref: String,
    authority_revocation_refs: Vec<String>,
    replacement_generation: Option<u64>,
    recorded_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SealRecoveryRecordState {
    InProgress,
    Complete,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MissingAuthorityProjection {
    authority_kind: String,
    referenced_id: String,
    reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NonProjectionProof {
    schema_version: String,
    authority_kind: String,
    owner_store_path: String,
    owner_store_load_ok: bool,
    owner_record_count: usize,
    #[serde(with = "time::serde::rfc3339")]
    owner_store_modified_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    first_request_modified_at: OffsetDateTime,
    owner_store_predates_first_request: bool,
    scan_roots: Vec<String>,
    scanned_file_count: usize,
    scan_exclusions: Vec<String>,
    scan_errors: Vec<String>,
    matching_paths: Vec<String>,
    source_evidence_ref: Option<String>,
    complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealRecoveryStep {
    step: String,
    outcome: String,
    detail: String,
    #[serde(with = "time::serde::rfc3339")]
    recorded_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StagedSealAuthority {
    call_id: String,
    host: AgentHostId,
    project_id: ProjectId,
    task_id: TaskId,
    agent_session_id: eliot_types::AgentSessionId,
    client_instance_id: String,
    work_item_id: WorkItemId,
    role_lease_id: String,
    role_lease_epoch: u64,
    operation_generation: u64,
    runtime_contract_sha256: String,
    invocation_id: String,
    operation_job_id: String,
    capability_scope: Vec<String>,
    expires_at: OffsetDateTime,
}

type StagedSealArtifact = (String, String, Vec<u8>);
type RenderedExternalProviderCalls = (Vec<StagedSealAuthority>, Vec<StagedSealArtifact>);

#[derive(Clone, Debug)]
struct PreparedProviderPlanSeal {
    record: ProviderPlanSealRecord,
    plan: CognitiveFieldProviderPlan,
    role_evidence_plan: Option<CoreRoleEvidencePlan>,
    authority: Vec<StagedSealAuthority>,
    manifest: SealArtifactManifest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SealRecoveryDecision {
    AbandonAndRevokeSafePredispatch,
    AlreadyAbandoned,
    BlockedProviderEvidence,
    BlockedIntegrityMismatch,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealRecoveryInspection {
    schema_version: String,
    run_id: String,
    generation: u64,
    decision: SealRecoveryDecision,
    execution_request_paths: Vec<String>,
    provider_runtime_paths: Vec<String>,
    session_ids: Vec<eliot_types::AgentSessionId>,
    role_lease_ids: Vec<String>,
    referenced_work_item_ids: Vec<WorkItemId>,
    referenced_invocation_ids: Vec<String>,
    present_work_item_ids: Vec<WorkItemId>,
    present_operation_job_ids: Vec<String>,
    missing_work_item_ids: Vec<WorkItemId>,
    missing_invocation_ids: Vec<String>,
    non_projection_proofs: Vec<NonProjectionProof>,
    scoped_authority_exact: bool,
    legacy_authority_cas_ready: bool,
    provider_plan_present: bool,
    provider_reservation_count: usize,
    provider_result_count: usize,
    provider_artifact_paths: Vec<String>,
    exact_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyEvidenceAdmissionRecord {
    schema_version: String,
    admitting_run_id: String,
    source_run_id: String,
    source_call_id: String,
    case_id: String,
    role: CognitiveFieldRole,
    missing_historical_field: String,
    accepted_role_evidence_run_id: String,
    accepted_role_evidence_plan_hash: String,
    output_schema_sha256: String,
    historical_runtime_binding_sha256: String,
    fresh_provider_authority: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyProviderRuntimeBinding {
    schema_version: String,
    reconstruction_status: String,
    source_run_id: String,
    source_call_id: String,
    source_commit: String,
    provider_session_id: String,
    provider_receipt_ref: String,
    provider_executable: String,
    provider_executable_sha256: String,
    prompt_sha256: String,
    raw_stdout_sha256: String,
    raw_stderr_sha256: String,
    receipt_sha256: String,
    zero_model_preflight_available: bool,
    fresh_role_authority: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreRoleEvidencePlan {
    schema_version: String,
    run_id: String,
    sources: Vec<CoreRoleEvidenceSource>,
    plan_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCoreRoleEvidencePlanV0 {
    schema_version: String,
    run_id: String,
    sources: Vec<LegacyCoreRoleEvidenceSourceV0>,
    plan_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source_kind", rename_all = "snake_case", deny_unknown_fields)]
#[allow(
    clippy::large_enum_variant,
    reason = "legacy evidence wire variants must retain their established serialized shape"
)]
enum LegacyCoreRoleEvidenceSourceV0 {
    FreshProviderCall {
        planned_call_id: String,
    },
    AcceptedPriorRoleArtifact {
        source_run_id: String,
        source_call_id: String,
        role: CognitiveFieldRole,
        case_id: String,
        provider_session_id: String,
        source_commit: String,
        provider_executable_sha256: String,
        output_schema_sha256: String,
        artifact_sha256: String,
        provider_receipt_ref: String,
        deterministic_receipt_refs: Vec<String>,
        contamination_receipt_ref: String,
        worktree_diff_sha256: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source_kind", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
enum CoreRoleEvidenceSource {
    FreshProviderCall {
        planned_call_id: String,
    },
    AcceptedPriorRoleArtifact {
        source_run_id: String,
        source_call_id: String,
        role: CognitiveFieldRole,
        case_id: String,
        provider_session_id: String,
        source_commit: String,
        provider_executable_sha256: String,
        output_schema_sha256: String,
        artifact_sha256: String,
        #[serde(default)]
        prompt_sha256: String,
        #[serde(default)]
        oracle_sha256: String,
        #[serde(default)]
        runtime_contract_sha256: String,
        #[serde(default)]
        input_artifact_sha256s: Vec<String>,
        #[serde(default)]
        deterministic_report_sha256s: Vec<String>,
        #[serde(default)]
        executions: Vec<CognitiveFieldExecutionKey>,
        provider_receipt_ref: String,
        deterministic_receipt_refs: Vec<String>,
        contamination_receipt_ref: String,
        worktree_diff_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        legacy_evidence_admission: Option<LegacyEvidenceAdmissionRecord>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreRoleReuseProjection {
    schema_version: String,
    run_id: String,
    contract_hash: String,
    provider_plan_hash: String,
    source_run_id: String,
    source_call_id: String,
    role: CognitiveFieldRole,
    case_id: String,
    provider_session_id: String,
    provider_receipt_ref: String,
    provider_executable_sha256: String,
    output_schema_sha256: String,
    artifact_sha256: String,
    prompt_sha256: String,
    oracle_sha256: String,
    runtime_contract_sha256: String,
    input_artifact_sha256s: Vec<String>,
    deterministic_report_sha256s: Vec<String>,
    executions: Vec<CognitiveFieldExecutionKey>,
    deterministic_receipt_refs: Vec<String>,
    contamination_receipt_ref: String,
    worktree_diff_sha256: Option<String>,
    outputs: Vec<CognitiveFieldProviderOutputProjection>,
    recorded_at: OffsetDateTime,
}

#[derive(Debug)]
struct VerifiedPriorRole {
    source_private_root: PathBuf,
    outputs: Vec<(CognitiveFieldExecutionKey, Vec<u8>)>,
    candidate_diff: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CognitiveCallScopeBinding {
    schema_version: String,
    run_id: String,
    case_id: String,
    project_id: ProjectId,
    task_id: TaskId,
}

#[derive(Clone, Debug)]
struct SealedPromptBinding {
    project_id: ProjectId,
    task_id: TaskId,
    repository: PathBuf,
}

enum ProviderRuntimeBinding {
    Current(Box<ProviderRuntimeContract>),
    Legacy(Box<CognitiveProviderRuntimeContract>),
}

impl ProviderRuntimeBinding {
    fn runtime_contract_sha256(&self) -> &str {
        match self {
            Self::Current(contract) => &contract.runtime_contract_sha256,
            Self::Legacy(contract) => &contract.runtime_contract_sha256,
        }
    }

    const fn host(&self) -> AgentHostId {
        match self {
            Self::Current(contract) => contract.host,
            Self::Legacy(contract) => contract.host,
        }
    }

    fn provider_executable_sha256(&self) -> &str {
        match self {
            Self::Current(contract) => &contract.provider_executable_sha256,
            Self::Legacy(contract) => &contract.provider_executable_sha256,
        }
    }

    fn expected_mcp_tool_names(&self) -> &[String] {
        match self {
            Self::Current(contract) => &contract.expected_mcp_tool_names,
            Self::Legacy(contract) => &contract.expected_mcp_tool_names,
        }
    }

    fn forbidden_mcp_server_names(&self) -> &[String] {
        match self {
            Self::Current(contract) => &contract.forbidden_mcp_server_names,
            Self::Legacy(contract) => &contract.forbidden_mcp_server_names,
        }
    }

    const fn is_current(&self) -> bool {
        matches!(self, Self::Current(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CognitiveHarnessOnlyEquivalence {
    schema_version: String,
    product_source_commit: String,
    governor_build_source_commit: String,
    exact_diff_sha256: String,
    changed_paths: Vec<String>,
}

const CODEX_COGNITIVE_EXPECTED_TOOLS: &[&str] = &[
    "eliot_current_state",
    "eliot_recall_l0",
    "eliot_fetch_l2",
    "eliot_compile_packet_l3",
    "eliot_agent_candidate_submit",
    "eliot_memory_influence_trace",
    "eliot_write_cognitive_observation",
];
const COGNITIVE_RUNTIME_PREFLIGHT_LIMIT: Duration = Duration::from_secs(20);
const APPROVED_HARNESS_PATHS: &[&str] = &[
    "crates/eliot-app/src/cognitive_field_runner.rs",
    "crates/eliot-app/src/main.rs",
    "crates/eliot-types/src/cognitive_field.rs",
    "crates/eliot-types/src/lib.rs",
    "crates/eliot-types/src/secret_boundary.rs",
];

fn codex_cognitive_runtime_contract(
    provider_executable: &Path,
    worktree: &Path,
    governor_executable: &Path,
    governor_build_source_commit: Option<&str>,
) -> Result<CognitiveProviderRuntimeContract> {
    let provider_executable = canonical_file(provider_executable, "Codex provider executable")?;
    let worktree = canonical_directory(worktree, "isolated cognitive worktree")?;
    let governor_executable = canonical_file(governor_executable, "Eliot Governor executable")?;
    if let Some(commit) = governor_build_source_commit {
        ensure!(
            commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Governor build source commit must be a 40-character hexadecimal object id"
        );
    }

    let provider_executable = canonical_path(&provider_executable);
    let provider_cwd = canonical_path(&worktree);
    let governor_executable_path = canonical_path(&governor_executable);
    let governor_args = vec![
        "mcp".to_owned(),
        "stdio".to_owned(),
        "--host".to_owned(),
        "codex".to_owned(),
        "--profile".to_owned(),
        "codex_worker".to_owned(),
        "--instance".to_owned(),
        "default".to_owned(),
    ];
    let provider_argv = vec![
        "exec".to_owned(),
        "--cd".to_owned(),
        provider_cwd.clone(),
        "-c".to_owned(),
        format!(
            "mcp_servers.eliot-governor.command={}",
            serde_json::to_string(&governor_executable_path)?
        ),
        "-c".to_owned(),
        format!(
            "mcp_servers.eliot-governor.args={}",
            serde_json::to_string(&governor_args)?
        ),
        "-c".to_owned(),
        format!(
            "mcp_servers.eliot-governor.cwd={}",
            serde_json::to_string(&provider_cwd)?
        ),
        "-c".to_owned(),
        "mcp_servers.eliot-governor.required=true".to_owned(),
        "-c".to_owned(),
        "mcp_servers.eliot_surrealdb.enabled=false".to_owned(),
    ];
    let mut contract = CognitiveProviderRuntimeContract {
        schema_version: COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION.to_owned(),
        host: AgentHostId::Codex,
        provider_executable: provider_executable.clone(),
        provider_executable_sha256: sha256_bytes(&fs::read(&provider_executable)?),
        provider_cwd: provider_cwd.clone(),
        provider_argv,
        nonsecret_environment: BTreeMap::new(),
        mcp_servers: vec![
            CognitiveProviderMcpServer {
                name: "eliot-governor".to_owned(),
                command: governor_executable_path,
                args: governor_args,
                cwd: provider_cwd,
                required: true,
                enabled: true,
                executable_sha256: sha256_bytes(&fs::read(&governor_executable)?),
                build_source_commit: governor_build_source_commit.map(str::to_owned),
            },
            CognitiveProviderMcpServer {
                name: "eliot_surrealdb".to_owned(),
                command: String::new(),
                args: Vec::new(),
                cwd: String::new(),
                required: false,
                enabled: false,
                executable_sha256: String::new(),
                build_source_commit: None,
            },
        ],
        expected_mcp_tool_names: CODEX_COGNITIVE_EXPECTED_TOOLS
            .iter()
            .map(ToString::to_string)
            .collect(),
        forbidden_mcp_server_names: vec!["eliot_surrealdb".to_owned()],
        runtime_contract_sha256: String::new(),
    };
    seal_runtime_contract(&mut contract)?;
    Ok(contract)
}

fn runtime_contract_without_hash(
    contract: &CognitiveProviderRuntimeContract,
) -> CognitiveProviderRuntimeContract {
    let mut material = contract.clone();
    material.runtime_contract_sha256.clear();
    material
}

fn normalize_runtime_contract(contract: &mut CognitiveProviderRuntimeContract) {
    contract
        .mcp_servers
        .sort_by(|left, right| left.name.cmp(&right.name));
    contract
        .expected_mcp_tool_names
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    contract.expected_mcp_tool_names.dedup();
    contract
        .forbidden_mcp_server_names
        .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    contract.forbidden_mcp_server_names.dedup();
}

fn seal_runtime_contract(contract: &mut CognitiveProviderRuntimeContract) -> Result<()> {
    normalize_runtime_contract(contract);
    contract.runtime_contract_sha256.clear();
    contract.runtime_contract_sha256 = computed_runtime_contract_sha256(contract)?;
    validate_runtime_contract(contract)
}

fn computed_runtime_contract_sha256(contract: &CognitiveProviderRuntimeContract) -> Result<String> {
    let mut material = runtime_contract_without_hash(contract);
    normalize_runtime_contract(&mut material);
    Ok(sha256_bytes(&serde_json::to_vec(&material)?))
}

fn validate_runtime_contract(contract: &CognitiveProviderRuntimeContract) -> Result<()> {
    ensure!(
        contract.schema_version == COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION,
        "provider runtime schema version is invalid"
    );
    let mut normalized = contract.clone();
    normalize_runtime_contract(&mut normalized);
    ensure!(
        normalized == *contract,
        "provider runtime unordered fields must be sorted and deduplicated"
    );
    ensure!(
        is_sha256(&contract.provider_executable_sha256)
            && is_sha256(&contract.runtime_contract_sha256)
            && computed_runtime_contract_sha256(contract)? == contract.runtime_contract_sha256,
        "provider runtime hashes are invalid"
    );
    let provider_executable = canonical_file(
        Path::new(&contract.provider_executable),
        "provider executable",
    )?;
    let provider_cwd = canonical_directory(
        Path::new(&contract.provider_cwd),
        "provider working directory",
    )?;
    ensure!(
        canonical_path(&provider_executable) == contract.provider_executable
            && canonical_path(&provider_cwd) == contract.provider_cwd
            && sha256_bytes(&fs::read(provider_executable)?) == contract.provider_executable_sha256,
        "provider runtime executable or cwd differs from its canonical binding"
    );
    ensure!(
        !contract.provider_argv.is_empty() && !contract.forbidden_mcp_server_names.is_empty(),
        "provider runtime argv and forbidden servers are required"
    );
    for server in &contract.mcp_servers {
        ensure!(
            safe_segment(&server.name),
            "provider runtime MCP server name is unsafe"
        );
        if server.enabled {
            let executable = canonical_file(Path::new(&server.command), "MCP server executable")?;
            let cwd = canonical_directory(Path::new(&server.cwd), "MCP server cwd")?;
            ensure!(
                canonical_path(&executable) == server.command
                    && canonical_path(&cwd) == server.cwd
                    && is_sha256(&server.executable_sha256)
                    && sha256_bytes(&fs::read(executable)?) == server.executable_sha256,
                "enabled MCP server runtime binding is invalid"
            );
            if let Some(commit) = &server.build_source_commit {
                ensure!(
                    commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
                    "MCP server build source commit is invalid"
                );
            }
        }
    }
    if contract.host == AgentHostId::Codex {
        ensure!(
            !contract.expected_mcp_tool_names.is_empty(),
            "Codex cognitive runtime requires expected MCP tools"
        );
        let governor = contract
            .mcp_servers
            .iter()
            .find(|server| server.name == "eliot-governor")
            .context("Codex cognitive runtime lacks eliot-governor")?;
        ensure!(
            governor.enabled
                && governor.required
                && governor.build_source_commit.is_some()
                && governor.args
                    == [
                        "mcp",
                        "stdio",
                        "--host",
                        "codex",
                        "--profile",
                        "codex_worker",
                        "--instance",
                        "default",
                    ]
                    .map(str::to_owned)
                && contract
                    .mcp_servers
                    .iter()
                    .filter(|server| {
                        server.name.to_ascii_lowercase().contains("surreal")
                            && server.name != "eliot-governor"
                    })
                    .all(|server| !server.enabled),
            "Codex cognitive runtime must require Governor codex_worker and disable raw SurrealDB"
        );
    }
    Ok(())
}

fn validate_governor_product_provenance(
    contract: &CognitiveProviderRuntimeContract,
    product_source_commit: &str,
    equivalence: Option<&CognitiveHarnessOnlyEquivalence>,
) -> Result<()> {
    ensure!(
        product_source_commit.len() == 40
            && product_source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "product-under-test source commit is invalid"
    );
    let governor_commit = contract
        .mcp_servers
        .iter()
        .find(|server| server.name == "eliot-governor" && server.enabled)
        .and_then(|server| server.build_source_commit.as_deref())
        .context("Governor runtime lacks exact build source provenance")?;
    if governor_commit == product_source_commit {
        return Ok(());
    }
    let equivalence =
        equivalence.context("Governor build source differs without a harness-only equivalence")?;
    ensure!(
        equivalence.schema_version == "eliot-cognitive-harness-equivalence-v1"
            && equivalence.product_source_commit == product_source_commit
            && equivalence.governor_build_source_commit == governor_commit
            && is_sha256(&equivalence.exact_diff_sha256)
            && !equivalence.changed_paths.is_empty()
            && equivalence
                .changed_paths
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && equivalence
                .changed_paths
                .iter()
                .all(|path| APPROVED_HARNESS_PATHS.contains(&path.as_str())),
        "Governor source mismatch equivalence is absent, unordered, or not harness-only"
    );
    Ok(())
}

fn codex_mcp_list_argv(contract: &CognitiveProviderRuntimeContract) -> Result<Vec<String>> {
    let (subcommand, runtime_args) = contract
        .provider_argv
        .split_first()
        .context("Codex runtime argv is empty")?;
    ensure!(
        subcommand == "exec",
        "Codex cognitive provider argv must begin with exec"
    );
    let mut args = runtime_args.to_vec();
    args.extend(["mcp", "list", "--json"].map(str::to_owned));
    Ok(args)
}

fn configured_mcp_servers(value: &Value) -> Result<Vec<(String, bool)>> {
    let entries = value
        .as_array()
        .or_else(|| value.get("servers").and_then(Value::as_array))
        .context("Codex MCP list JSON is neither an array nor a servers object")?;
    let mut servers = entries
        .iter()
        .map(|entry| {
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .context("Codex MCP entry lacks a name")?;
            let enabled = entry
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            Ok((name.to_owned(), enabled))
        })
        .collect::<Result<Vec<_>>>()?;
    servers.sort();
    servers.dedup();
    Ok(servers)
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded preflight state machine keeps process policy and output conversion together"
)]
fn supervised_preflight_command(
    config_path: &Path,
    command: &Command,
    stdin_payload: Option<Vec<u8>>,
    operation_id: String,
    timeout: Duration,
    child_kind: SupervisedChildKind,
) -> Result<std::process::Output> {
    let mut environment = [
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "PATH",
        "PATHEXT",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "TEMP",
        "TMP",
    ]
    .into_iter()
    .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
    .collect::<BTreeMap<_, _>>();
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            environment.insert(name.into(), value.into());
        } else {
            environment.remove(name);
        }
    }
    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let operation_id_for_context = operation_id.clone();
    let output = run_supervised_process_blocking(
        SupervisedProcessSpec {
            operation_id,
            invocation_id: None,
            generation: 1,
            child_kind,
            criticality: ChildCriticality::InvocationDependency,
            restart_policy: ProcessRestartPolicy {
                strategy: RestartStrategy::Never,
                max_restarts: 0,
                restart_window_seconds: 60,
                base_backoff_ms: 0,
                pre_dispatch_only: false,
            },
            executable: command.get_program().into(),
            args: command.get_args().map(OsString::from).collect(),
            cwd: command
                .get_current_dir()
                .map(ToOwned::to_owned)
                .map_or_else(std::env::current_dir, Ok)?,
            environment,
            stdin_payload,
            stdout_limit_bytes: 4 * 1024 * 1024,
            stderr_limit_bytes: 4 * 1024 * 1024,
            timeout_profile: eliot_types::ProviderTimeoutProfile {
                profile_id: "cognitive-preflight-v1".to_owned(),
                provider: "eliot-governor".to_owned(),
                route_or_operation_class: "cognitive-preflight".to_owned(),
                spawn_deadline_ms: Some(5_000),
                dispatch_ack_deadline_ms: None,
                first_output_deadline_ms: Some(timeout_ms),
                idle_output_deadline_ms: Some(timeout_ms),
                absolute_runtime_deadline_ms: timeout_ms,
                cancellation_grace_ms: 25,
                cleanup_grace_ms: 5_000,
                reconciliation_window_ms: 0,
                output_heartbeat_supported: true,
                status_lookup_supported: false,
                evidence_basis: vec!["bounded cognitive runtime preflight".to_owned()],
                assumptions: Vec::new(),
                hard_upper_bounds: vec!["20 second preflight limit".to_owned()],
                policy_version: "runtime-supervision-v1".to_owned(),
            },
            runtime_contract_sha256: None,
            role_lease_id: None,
            role_lease_epoch: None,
        },
        eliot_engine::runtime_supervision::AdapterExecutionContext {
            operation_id: operation_id_for_context,
            generation: 1,
            cancellation: eliot_engine::runtime_supervision::CancellationToken::new(),
            deadline: tokio::time::Instant::now() + timeout,
            runtime_store:
                crate::host_runtime::supervised_process::daemon_operation_runtime_handle(
                    config_path,
                )?,
            role_lease_id: None,
            role_lease_epoch: None,
            runtime_contract_sha256: None,
        },
    )?;
    ensure!(
        !output.timed_out && output.reap_receipt.proves_complete_reap(),
        "supervised cognitive preflight timed out or did not reap its Job Object"
    );
    ensure!(
        output.worker_error.is_none(),
        "supervised cognitive preflight failed: {:?}",
        output.worker_error
    );
    Ok(std::process::Output {
        status: std::process::ExitStatus::from_raw(
            output.exit_code.unwrap_or(i32::MAX).cast_unsigned(),
        ),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn json_rpc_response_by_id(responses: &[Value], id: u64) -> Result<&Value> {
    responses
        .iter()
        .find(|response| response.get("id").and_then(Value::as_u64) == Some(id))
        .with_context(|| format!("Governor MCP returned no JSON-RPC response for id {id}"))
}

#[allow(clippy::too_many_lines)]
fn preflight_codex_cognitive_runtime(
    config_path: &Path,
    contract: &CognitiveProviderRuntimeContract,
    scoped_environment: &BTreeMap<String, String>,
) -> Result<CognitiveRuntimePreflightReceipt> {
    let started = Instant::now();
    validate_runtime_contract(contract)?;
    ensure!(
        contract.host == AgentHostId::Codex,
        "Codex runtime preflight requires a Codex contract"
    );

    let mut config_command = Command::new(&contract.provider_executable);
    config_command
        .args(codex_mcp_list_argv(contract)?)
        .current_dir(&contract.provider_cwd)
        .envs(scoped_environment);
    let config_output = supervised_preflight_command(
        config_path,
        &config_command,
        None,
        format!("cognitive-config-preflight-{}", Uuid::now_v7()),
        COGNITIVE_RUNTIME_PREFLIGHT_LIMIT,
        SupervisedChildKind::Verifier,
    )
    .context("run zero-model Codex MCP configuration listing")?;
    ensure!(
        config_output.status.success(),
        "Codex MCP configuration listing failed: {}",
        String::from_utf8_lossy(&config_output.stderr)
    );
    let config_json: Value = serde_json::from_slice(&config_output.stdout)
        .context("parse zero-model Codex MCP configuration listing")?;
    let configured_servers = configured_mcp_servers(&config_json)?;
    let observed_server_names = configured_servers
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let forbidden_servers_absent = configured_servers.iter().all(|(name, enabled)| {
        !enabled
            || (!contract.forbidden_mcp_server_names.contains(name)
                && !name.to_ascii_lowercase().contains("surreal"))
    });
    ensure!(
        configured_servers
            .iter()
            .any(|(name, enabled)| name == "eliot-governor" && *enabled)
            && forbidden_servers_absent,
        "Codex MCP listing did not prove enabled Governor and disabled/absent raw SurrealDB"
    );

    let governor = contract
        .mcp_servers
        .iter()
        .find(|server| server.name == "eliot-governor")
        .context("runtime contract lacks Governor server")?;
    let requests = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "eliot-cognitive-runtime-preflight",
                    "version": COGNITIVE_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
                },
            },
        }),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "eliot_host_session_status", "arguments": {}},
        }),
    ];
    let mut request_bytes = Vec::new();
    for request in requests {
        request_bytes.extend_from_slice(&serde_json::to_vec(&request)?);
        request_bytes.push(b'\n');
    }
    let mut governor_command = Command::new(&governor.command);
    governor_command
        .args(&governor.args)
        .current_dir(&governor.cwd)
        .envs(scoped_environment);
    let mcp_output = supervised_preflight_command(
        config_path,
        &governor_command,
        Some(request_bytes),
        format!("cognitive-mcp-preflight-{}", Uuid::now_v7()),
        COGNITIVE_RUNTIME_PREFLIGHT_LIMIT,
        SupervisedChildKind::McpPreflight,
    )
    .context("run exact Governor MCP stdio child")?;
    ensure!(
        mcp_output.status.success(),
        "Governor MCP preflight failed: {}",
        String::from_utf8_lossy(&mcp_output.stderr)
    );
    let responses = String::from_utf8(mcp_output.stdout)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    let result = (|| -> Result<(Vec<String>, bool)> {
        let initialize = json_rpc_response_by_id(&responses, 1)?;
        ensure!(
            initialize.get("error").is_none() && initialize.get("result").is_some(),
            "Governor MCP initialize failed: {initialize}"
        );
        let tools = json_rpc_response_by_id(&responses, 2)?;
        ensure!(
            tools.get("error").is_none(),
            "Governor MCP tools/list failed: {tools}"
        );
        let mut observed_tools = tools
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .context("Governor MCP tools/list lacks result.tools")?
            .iter()
            .map(|tool| {
                tool.get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .context("Governor MCP tool lacks a name")
            })
            .collect::<Result<Vec<_>>>()?;
        observed_tools.sort();
        observed_tools.dedup();
        ensure!(
            contract
                .expected_mcp_tool_names
                .iter()
                .all(|expected| observed_tools.contains(expected)),
            "Governor MCP tools/list lacks one or more expected cognitive tools"
        );

        let status = json_rpc_response_by_id(&responses, 3)?;
        let scoped_status_read_passed =
            status.get("error").is_none() && status.get("result").is_some();
        Ok((observed_tools, scoped_status_read_passed))
    })();

    let (observed_mcp_tool_names, scoped_status_read_passed) = result?;
    let elapsed_ms =
        u64::try_from(started.elapsed().as_millis()).context("preflight duration exceeds u64")?;
    ensure!(
        started.elapsed() <= COGNITIVE_RUNTIME_PREFLIGHT_LIMIT,
        "Governor MCP preflight exceeded 20 seconds"
    );
    Ok(CognitiveRuntimePreflightReceipt {
        schema_version: COGNITIVE_RUNTIME_PREFLIGHT_SCHEMA_VERSION.to_owned(),
        runtime_contract_sha256: contract.runtime_contract_sha256.clone(),
        config_list_passed: true,
        mcp_process_started: true,
        mcp_initialized: true,
        tools_listed: true,
        expected_tools_present: true,
        forbidden_servers_absent,
        scoped_status_read_passed,
        observed_server_names,
        observed_tool_names: observed_mcp_tool_names,
        governor_executable_sha256: governor.executable_sha256.clone(),
        governor_build_source_commit: governor.build_source_commit.clone(),
        elapsed_ms,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn codex_runtime_preflight(
    config_path: &Path,
    provider_executable: &Path,
    worktree: &Path,
    governor_executable: &Path,
    governor_build_source_commit: Option<&str>,
    product_source_commit: &str,
    equivalence_record: Option<&Path>,
    contract_output: &Path,
    receipt_output: &Path,
) -> Result<()> {
    let contract = codex_cognitive_runtime_contract(
        provider_executable,
        worktree,
        governor_executable,
        governor_build_source_commit,
    )?;
    let equivalence = equivalence_record
        .map(read_json::<CognitiveHarnessOnlyEquivalence>)
        .transpose()?;
    validate_governor_product_provenance(&contract, product_source_commit, equivalence.as_ref())?;
    let receipt = preflight_codex_cognitive_runtime(config_path, &contract, &BTreeMap::new())?;
    write_new_or_same_json(contract_output, &contract)?;
    write_new_or_same_json(receipt_output, &receipt)?;
    print_json(&json!({
        "status": "cognitive_runtime_preflight_passed",
        "runtime_contract_sha256": contract.runtime_contract_sha256,
        "contract_output": canonical_path(&absolute_path(contract_output)?),
        "receipt_output": canonical_path(&absolute_path(receipt_output)?),
        "elapsed_ms": receipt.elapsed_ms,
        "scoped_status_read_passed": receipt.scoped_status_read_passed,
    }))
}

fn provider_compatible_reader_schema(canonical: &Value) -> Result<Value> {
    let mut provider = canonical.clone();
    let root = provider
        .as_object_mut()
        .context("CognitiveUnderstandingAnswer schema root must be an object")?;
    root.remove("$schema");
    sort_json_object_keys(&mut provider);
    Ok(provider)
}

fn render_provider_contract(schema: &Value) -> Result<RenderedProviderContract> {
    let mut stable = schema.clone();
    sort_json_object_keys(&mut stable);
    let canonical_json = serde_json::to_string(&stable)?;
    Ok(RenderedProviderContract {
        sha256: sha256_bytes(canonical_json.as_bytes()),
        canonical_json,
    })
}

fn render_reader_prompt(template: &str, contract: &RenderedProviderContract) -> Result<String> {
    ensure!(
        template.matches(READER_SCHEMA_JSON_PLACEHOLDER).count() == 1
            && template.matches(READER_SCHEMA_SHA256_PLACEHOLDER).count() == 1,
        "Reader prompt must contain each generated schema placeholder exactly once"
    );
    let rendered = template
        .replace(
            READER_SCHEMA_JSON_PLACEHOLDER,
            contract.canonical_json.as_str(),
        )
        .replace(READER_SCHEMA_SHA256_PLACEHOLDER, contract.sha256.as_str());
    ensure!(
        rendered.matches(&contract.canonical_json).count() == 1
            && rendered.matches(&contract.sha256).count() == 1,
        "Reader prompt must contain the generated schema bytes and hash exactly once"
    );
    Ok(rendered)
}

fn sort_json_object_keys(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let mut sorted = object
                .iter_mut()
                .map(|(key, value)| {
                    sort_json_object_keys(value);
                    (key.clone(), std::mem::take(value))
                })
                .collect::<Vec<_>>();
            sorted.sort_by(|left, right| left.0.cmp(&right.0));
            object.clear();
            object.extend(sorted);
        }
        Value::Array(values) => {
            for value in values {
                sort_json_object_keys(value);
            }
        }
        _ => {}
    }
}

fn schema_validation_projection(schema: &Value) -> Value {
    const ANNOTATIONS: [&str; 7] = [
        "$schema",
        "$id",
        "title",
        "description",
        "examples",
        "default",
        "deprecated",
    ];
    match schema {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(key, _)| !ANNOTATIONS.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), schema_validation_projection(value)))
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.iter().map(schema_validation_projection).collect())
        }
        _ => schema.clone(),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn prepare(
    suite_path: &Path,
    run_id: &str,
    primary_repository: &Path,
    second_repository: &Path,
    report_root: &Path,
    private_root: &Path,
) -> Result<()> {
    ensure!(!run_id.trim().is_empty(), "run_id must not be empty");
    let (suite, report, suite_bytes) = load_and_validate_suite(suite_path)?;
    ensure!(
        report.valid,
        "cognitive field suite failed validation: {}",
        report.errors.join("; ")
    );
    let primary = canonical_directory(primary_repository, "primary repository")?;
    let second = canonical_directory(second_repository, "second repository")?;
    ensure!(
        primary != second,
        "second repository must differ from primary"
    );
    ensure!(
        second.join("Cargo.toml").is_file(),
        "second repository must be a real Rust repository with Cargo.toml"
    );
    ensure!(
        permissive_license_declared(&second)?,
        "second repository must declare MIT, Apache-2.0, BSD-2-Clause, or BSD-3-Clause"
    );
    let primary_commit = git_commit(&primary)?;
    let second_commit = git_commit(&second)?;

    let report_root = absolute_path(report_root)?;
    let private_root = absolute_path(private_root)?;
    ensure!(
        !private_root.starts_with(&primary) && !private_root.starts_with(&second),
        "private certification root must remain outside both Git repositories"
    );
    fs::create_dir_all(&report_root)?;
    fs::create_dir_all(private_root.join("oracles"))?;
    let canonical_private_root = fs::canonicalize(&private_root)?;

    let suite_sha256 = sha256_bytes(&suite_bytes);
    let private_root_sha256 = sha256_bytes(canonical_path(&canonical_private_root).as_bytes());
    let contract_path = report_root.join("contract.json");
    let existing_contract = contract_path
        .is_file()
        .then(|| read_json::<CognitiveFieldRunContract>(&contract_path))
        .transpose()?;
    let mut contract = CognitiveFieldRunContract {
        schema_version: COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        suite_sha256,
        source_commit: primary_commit,
        primary_repository: canonical_path(&primary),
        second_repository: canonical_path(&second),
        second_repository_commit: second_commit,
        output_root: canonical_path(&report_root),
        private_root_sha256,
        hard_provider_call_cap: suite.hard_provider_call_cap,
        contract_hash: String::new(),
        sealed_at: existing_contract
            .as_ref()
            .map_or_else(OffsetDateTime::now_utc, |existing| existing.sealed_at),
    };
    contract.contract_hash =
        CognitiveFieldGradingService::hash_json(&contract_without_hash(&contract))?;
    if let Some(existing) = existing_contract {
        ensure!(
            existing == contract,
            "existing sealed contract differs from the resumed prepare request"
        );
        contract = existing;
    }
    let mut plan = CognitiveFieldPlan {
        schema_version: COGNITIVE_FIELD_PLAN_SCHEMA_VERSION.to_owned(),
        run_id: run_id.to_owned(),
        contract_hash: contract.contract_hash.clone(),
        items: suite
            .cases
            .iter()
            .map(|case| CognitiveFieldPlanItem {
                case_id: case.case_id.clone(),
                tier: case.tier,
                model_backed: case.model_backed,
                roles: case.required_roles.clone(),
                memory_conditions: case.memory_conditions.clone(),
                oracle_ref: case.oracle_ref.clone(),
                deterministic_verifier_refs: case.deterministic_verifier_refs.clone(),
            })
            .collect(),
        planned_provider_calls: suite.hard_provider_call_cap,
        hard_provider_call_cap: suite.hard_provider_call_cap,
        plan_hash: String::new(),
    };
    plan.plan_hash = CognitiveFieldGradingService::hash_json(&plan_without_hash(&plan))?;

    let suite_root = suite_path
        .parent()
        .context("field suite path has no parent")?;
    let worker_prompt = fs::read(suite_root.join("templates/worker-prompt.txt"))?;
    let reader_prompt_template =
        fs::read_to_string(suite_root.join("templates/reader-prompt.txt"))?;
    let canonical_reader_schema = cognitive_understanding_answer_schema();
    let provider_reader_schema = provider_compatible_reader_schema(&canonical_reader_schema)?;
    ensure!(
        schema_validation_projection(&canonical_reader_schema)
            == schema_validation_projection(&provider_reader_schema),
        "provider-compatible Reader schema changed validation semantics"
    );
    let canonical_reader_contract = render_provider_contract(&canonical_reader_schema)?;
    let provider_reader_contract = render_provider_contract(&provider_reader_schema)?;
    let reader_prompt =
        render_reader_prompt(&reader_prompt_template, &provider_reader_contract)?.into_bytes();
    let reader_schema = provider_reader_contract.canonical_json.as_bytes().to_vec();
    let core_qualification = suite.harness_version == COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION;
    let core_surfaces = core_qualification
        .then(|| {
            let exposure_path = private_root
                .join("contamination")
                .join("eliot-exposure-set.json");
            ensure!(
                exposure_path.is_file(),
                "core qualification requires a private ELIOT exposure-set export"
            );
            Ok::<_, anyhow::Error>(vec![
                (
                    "fixture-repo-and-git-history".to_owned(),
                    git_history(&primary)?,
                ),
                (
                    "provider-environment".to_owned(),
                    provider_environment_surface(),
                ),
                (
                    "accessible-contract".to_owned(),
                    serde_json::to_vec(&contract)?,
                ),
                ("accessible-plan".to_owned(), serde_json::to_vec(&plan)?),
                ("eliot-exposure-set".to_owned(), fs::read(exposure_path)?),
            ])
        })
        .transpose()?
        .unwrap_or_default();
    let mut leak_reports = Vec::new();
    for (index, case) in suite.cases.iter().enumerate() {
        let mut oracle = if core_qualification {
            read_json::<TaskIntentOracle>(
                &private_root
                    .join("oracle-inputs")
                    .join(format!("{}.json", case.case_id)),
            )
            .with_context(|| format!("load private core oracle input for {}", case.case_id))?
        } else {
            generated_oracle(case, index, &contract, &suite_bytes)
        };
        if core_qualification {
            ensure!(
                oracle.source_commit == contract.source_commit,
                "core oracle source commit differs from the sealed contract"
            );
            ensure!(
                oracle.exact_user_prompt_hash == sha256_bytes(case.title.as_bytes()),
                "core oracle prompt hash differs from the scenario task"
            );
        }
        CognitiveFieldGradingService::seal_oracle(&mut oracle)?;
        let mut surfaces = vec![
            ("worker-prompt".to_owned(), worker_prompt.clone()),
            ("reader-prompt".to_owned(), reader_prompt.clone()),
            ("reader-output-schema".to_owned(), reader_schema.clone()),
            ("suite-manifest".to_owned(), suite_bytes.clone()),
        ];
        surfaces.extend(core_surfaces.clone());
        let scan = CognitiveFieldGradingService::scan_reader_surfaces(&oracle, &surfaces);
        ensure!(
            scan.clean,
            "reader pre-dispatch surface leaked hidden oracle values for {}",
            case.case_id
        );
        leak_reports.push(json!({
            "case_id": case.case_id,
            "clean": scan.clean,
            "scanned_surfaces": scan.scanned_surfaces,
            "finding_count": scan.findings.len(),
        }));
        write_new_or_same_json(
            &private_root
                .join("oracles")
                .join(format!("{}.json", case.case_id)),
            &oracle,
        )?;
    }

    write_new_or_same(&report_root.join("suite.json"), &suite_bytes)?;
    write_new_or_same(
        &report_root.join("schemas/reader-canonical.json"),
        canonical_reader_contract.canonical_json.as_bytes(),
    )?;
    write_new_or_same(
        &report_root.join("schemas/reader-provider.json"),
        provider_reader_contract.canonical_json.as_bytes(),
    )?;
    write_new_or_same(
        &private_root.join("schemas/reader-canonical.json"),
        canonical_reader_contract.canonical_json.as_bytes(),
    )?;
    write_new_or_same(
        &private_root.join("schemas/reader-provider.json"),
        provider_reader_contract.canonical_json.as_bytes(),
    )?;
    write_new_or_same(
        &private_root.join("schemas/reader-prompt-bound.txt"),
        &reader_prompt,
    )?;
    write_new_or_same_json(&contract_path, &contract)?;
    write_new_or_same_json(&report_root.join("plan.json"), &plan)?;
    write_new_or_same_json(
        &report_root.join("preflight.json"),
        &json!({
            "schema_version": "eliot-cognitive-field-preflight-v1",
            "run_id": run_id,
            "suite_valid": true,
            "case_count": suite.cases.len(),
            "oracle_count": leak_reports.len(),
            "reader_surface_scans": leak_reports,
            "private_root_sha256": contract.private_root_sha256,
            "canonical_reader_schema_sha256": canonical_reader_contract.sha256,
            "provider_reader_schema_sha256": provider_reader_contract.sha256,
            "rendered_reader_prompt_sha256": sha256_bytes(&reader_prompt),
            "provider_calls": 0,
        }),
    )?;
    print_json(&json!({
        "status": "prepared",
        "run_id": run_id,
        "contract_hash": contract.contract_hash,
        "plan_hash": plan.plan_hash,
        "source_commit": contract.source_commit,
        "second_repository_commit": contract.second_repository_commit,
        "case_count": suite.cases.len(),
        "provider_calls": 0,
        "report_root": report_root,
        "private_root_sha256": contract.private_root_sha256,
    }))
}

#[allow(clippy::too_many_lines)]
pub fn record_deterministic(
    report_root: &Path,
    private_root: &Path,
    case_id: &str,
    memory_condition: &str,
    receipt_path: &Path,
) -> Result<()> {
    let report_root = canonical_directory(report_root, "cognitive report root")?;
    let private_root = canonical_directory(private_root, "private certification root")?;
    let receipt_path = fs::canonicalize(receipt_path)
        .with_context(|| format!("resolve deterministic receipt {}", receipt_path.display()))?;
    ensure!(
        receipt_path.starts_with(&private_root),
        "deterministic receipt must remain inside the private certification root"
    );
    let suite: CognitiveFieldSuite = read_json(&report_root.join("suite.json"))?;
    let contract: CognitiveFieldRunContract = read_json(&report_root.join("contract.json"))?;
    ensure!(
        contract_path_matches(&report_root, &contract.output_root),
        "report root differs from the sealed contract"
    );
    ensure!(
        contract_private_root_matches(&private_root, &contract.private_root_sha256),
        "private certification root does not match the sealed contract"
    );
    ensure!(
        git_commit(Path::new(&contract.primary_repository))? == contract.source_commit,
        "primary repository HEAD moved after the field contract was sealed"
    );
    let case = suite
        .cases
        .iter()
        .find(|case| case.case_id == case_id)
        .with_context(|| format!("unknown cognitive field case {case_id}"))?;
    let condition = parse_condition(memory_condition)?;
    ensure!(
        execution_conditions(case).contains(&condition),
        "memory condition {memory_condition} is not planned for {case_id}"
    );
    let receipt: CognitiveDeterministicEvidenceReceipt = read_json(&receipt_path)?;
    validate_deterministic_receipt(&contract, case, condition, &private_root, &receipt)?;
    let receipt_hash = CognitiveFieldGradingService::hash_json(&receipt)?;
    let (project_id, task_id) =
        if suite.harness_version == COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION {
            let binding: CoreQualificationBinding = read_json(
                &private_root
                    .join("bindings")
                    .join(format!("{}.json", case.case_id)),
            )
            .with_context(|| format!("load private core binding for {}", case.case_id))?;
            ensure!(
                binding.schema_version == "eliot-core-qualification-binding-v1"
                    && binding.run_id == contract.run_id
                    && binding.case_id == case.case_id,
                "private core binding differs from the sealed execution"
            );
            (
                ProjectId::from_uuid(
                    Uuid::parse_str(&binding.project_id).context("parse core project id")?,
                ),
                TaskId::from_uuid(Uuid::parse_str(&binding.task_id).context("parse core task id")?),
            )
        } else {
            let binding = format!(
                "{}:{}:{}:{}",
                contract.run_id,
                case.case_id,
                condition_name(condition),
                contract.source_commit
            );
            stable_binding_ids(&binding)
        };
    let gate_evidence = CognitiveHardGateKind::ALL
        .into_iter()
        .map(|gate| CognitiveHardGateEvidence {
            gate,
            passed: true,
            evidence_refs: vec![
                format!("deterministic-receipt:{receipt_hash}"),
                format!("contract:{}", contract.contract_hash),
            ],
            explanation: format!(
                "The sealed verifier receipt and field contract satisfy the {gate:?} hard gate"
            ),
        })
        .collect();
    let mut report = CognitiveDeterministicReport {
        schema_version: COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION.to_owned(),
        case_id: case.case_id.clone(),
        project_id,
        task_id,
        source_commit: contract.source_commit.clone(),
        verifier_refs: receipt.verifier_refs.clone(),
        hard_gate_evidence: gate_evidence,
        controller_provider_calls: receipt.controller_provider_calls,
        truth_revision_before: receipt.truth_revision_before.clone(),
        truth_revision_after_observability: receipt.truth_revision_after_observability.clone(),
        report_hash: String::new(),
        passed: true,
    };
    CognitiveFieldGradingService::seal_deterministic_report(&mut report)?;
    let evidence_root = report_root
        .join("evidence")
        .join(&case.case_id)
        .join(condition_name(condition));
    write_new_or_same_json(&evidence_root.join("deterministic.json"), &report)?;
    write_new_or_same_json(
        &evidence_root.join("verifier-receipt.json"),
        &json!({
            "schema_version": "eliot-cognitive-sanitized-verifier-receipt-v1",
            "run_id": receipt.run_id,
            "case_id": receipt.case_id,
            "memory_condition": receipt.memory_condition,
            "source_commit": receipt.source_commit,
            "verifier_refs": receipt.verifier_refs,
            "commands": receipt.commands.iter().map(|command| json!({
                "command_ref": command.command_ref,
                "arguments_sha256": command.arguments_sha256,
                "exit_code": command.exit_code,
                "elapsed_ms": command.elapsed_ms,
                "stdout_sha256": command.stdout_sha256,
                "stderr_sha256": command.stderr_sha256,
            })).collect::<Vec<_>>(),
            "controller_provider_calls": receipt.controller_provider_calls,
            "truth_revision_before": receipt.truth_revision_before,
            "truth_revision_after_observability": receipt.truth_revision_after_observability,
            "private_receipt_hash": receipt_hash,
        }),
    )?;
    print_json(&json!({
        "status": "deterministic_evidence_recorded",
        "run_id": contract.run_id,
        "case_id": case.case_id,
        "memory_condition": condition_name(condition),
        "deterministic_report_hash": report.report_hash,
        "private_receipt_hash": receipt_hash,
        "provider_calls": 0,
    }))
}

fn deterministic_seal_uuid(material: &str) -> Uuid {
    let digest = blake3::hash(material.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn deterministic_seal_id(prefix: &str, material: &str) -> String {
    format!("{prefix}:{}", deterministic_seal_uuid(material))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "transactional seal rendering validates all authority and artifact bindings in one state-machine phase"
)]
fn render_external_provider_calls(
    config_path: &Path,
    suite: &CognitiveFieldSuite,
    contract: &CognitiveFieldRunContract,
    private_root: &Path,
    seal_attempt_id: &str,
    generation: u64,
    reference_prefix: &str,
    calls: &mut [CognitiveFieldProviderCallPlan],
) -> Result<RenderedExternalProviderCalls> {
    ensure!(generation > 0, "seal generation must be nonzero");
    let broker = crate::delegation_runtime::load_state(
        &crate::delegation_runtime::root_from_config(config_path),
    )?;
    let mut next_epochs =
        broker
            .task_role_leases
            .iter()
            .fold(BTreeMap::<TaskId, u64>::new(), |mut epochs, lease| {
                epochs
                    .entry(lease.task_id)
                    .and_modify(|epoch| *epoch = (*epoch).max(lease.epoch))
                    .or_insert(lease.epoch);
                epochs
            });
    let mut authority_entries = Vec::new();
    let mut artifacts = Vec::new();
    for call in calls
        .iter_mut()
        .filter(|call| call.host != AgentHostId::Codex)
    {
        ensure!(
            call.role == CognitiveFieldRole::UnderstandingReader,
            "only external UnderstandingReader calls are admitted by the cognitive cutover"
        );
        let prompt_path = private_relative_file(private_root, &call.prompt_ref, "provider prompt")?;
        let prompt_bytes = fs::read(&prompt_path)?;
        ensure!(
            sha256_bytes(&prompt_bytes) == call.prompt_sha256,
            "external provider prompt differs from its sealed call hash"
        );
        let prompt = std::str::from_utf8(&prompt_bytes).context("provider prompt is not UTF-8")?;
        let prompt_binding = sealed_prompt_binding(prompt, suite, contract, private_root, call)?;
        let role_lease_epoch = {
            let epoch = next_epochs.entry(prompt_binding.task_id).or_insert(0);
            *epoch += 1;
            *epoch
        };
        let authority_material = format!(
            "{}\n{}\n{}\n{}",
            seal_attempt_id,
            generation,
            call.call_id,
            call.host.as_str()
        );
        let authority = StagedSealAuthority {
            call_id: call.call_id.clone(),
            host: call.host,
            project_id: prompt_binding.project_id,
            task_id: prompt_binding.task_id,
            agent_session_id: eliot_types::AgentSessionId::from_uuid(deterministic_seal_uuid(
                &format!("session\n{authority_material}"),
            )),
            client_instance_id: format!(
                "cognitive-field:{}:{}:g{}",
                contract.run_id, call.call_id, generation
            ),
            work_item_id: WorkItemId::from_uuid(deterministic_seal_uuid(&format!(
                "work-item\n{authority_material}"
            ))),
            role_lease_id: deterministic_seal_id(
                "task-role-lease",
                &format!("role\n{authority_material}"),
            ),
            role_lease_epoch,
            operation_generation: generation,
            runtime_contract_sha256: call.runtime_contract_sha256.clone(),
            invocation_id: format!("cognitive-field-{}-{}", contract.run_id, call.call_id),
            operation_job_id: deterministic_seal_id(
                "operation-job",
                &format!("job\n{authority_material}"),
            ),
            capability_scope: vec![
                "emit_candidate_observation".to_owned(),
                "request_controller_review".to_owned(),
            ],
            expires_at: contract.sealed_at + time::Duration::days(30),
        };
        let execution = cognitive_external_execution_request(
            contract,
            private_root,
            call,
            &prompt_binding,
            &prompt_path,
            &authority,
        )?;
        validate_external_agent_execution_request(&execution)?;
        let preview = crate::host_runtime::prepare_external_agent_runtime(
            config_path,
            call.host,
            &execution,
        )?;
        ensure!(
            preview.runtime_contract.host == call.host
                && preview.runtime_contract.requested_model == call.requested_model,
            "production adapter preview differs from the sealed provider route"
        );
        let request_relative = format!(
            "{reference_prefix}/runtime/{}-execution-request.json",
            call.call_id
        );
        let runtime_relative = format!(
            "{reference_prefix}/runtime/{}-provider-runtime.json",
            call.call_id
        );
        let mut request_bytes = serde_json::to_vec_pretty(&execution)?;
        request_bytes.push(b'\n');
        let mut runtime_bytes = serde_json::to_vec_pretty(&preview.runtime_contract)?;
        runtime_bytes.push(b'\n');
        call.adapter_id = preview.adapter_id;
        call.adapter_version = preview.adapter_version;
        call.execution_request_ref.clone_from(&request_relative);
        call.execution_request_sha256 = sha256_bytes(&request_bytes);
        call.runtime_contract_ref.clone_from(&runtime_relative);
        call.runtime_contract_sha256
            .clone_from(&preview.runtime_contract.runtime_contract_sha256);
        call.expected_provider_executable_sha256 =
            preview.runtime_contract.provider_executable_sha256;
        artifacts.push((
            "execution_request".to_owned(),
            request_relative,
            request_bytes,
        ));
        artifacts.push((
            "provider_runtime".to_owned(),
            runtime_relative,
            runtime_bytes,
        ));
        authority_entries.push(authority);
    }
    authority_entries.sort_by(|left, right| left.call_id.cmp(&right.call_id));
    artifacts.sort_by(|left, right| left.1.cmp(&right.1));
    Ok((authority_entries, artifacts))
}

#[allow(
    clippy::too_many_lines,
    reason = "the request builder keeps one sealed authority contract visible end to end"
)]
fn cognitive_external_execution_request(
    contract: &CognitiveFieldRunContract,
    private_root: &Path,
    call: &CognitiveFieldProviderCallPlan,
    binding: &SealedPromptBinding,
    prompt_path: &Path,
    authority: &StagedSealAuthority,
) -> Result<ExternalAgentExecutionRequest> {
    let output_schema_path = private_root.join("schemas").join("reader-provider.json");
    let output_schema_path = canonical_file(&output_schema_path, "Reader provider output schema")?;
    ensure!(
        sha256_bytes(&fs::read(&output_schema_path)?) == call.provider_schema_sha256,
        "Reader provider output schema differs from the sealed call"
    );
    ensure!(
        authority.call_id == call.call_id
            && authority.host == call.host
            && authority.project_id == binding.project_id
            && authority.task_id == binding.task_id,
        "staged seal authority differs from the cognitive call binding"
    );
    let planned_verifier_ref = format!(
        "cognitive-field-provider-verifier:{}:{}",
        contract.run_id, call.call_id
    );
    let invocation_id = format!("cognitive-field-{}-{}", contract.run_id, call.call_id);
    let idempotency_key = format!("cognitive-field:{}:{}", contract.run_id, call.call_id);
    let expected_tools = cognitive_expected_mcp_tools(call);
    let allowed_provider_tools = cognitive_allowed_provider_tools(call.host, &expected_tools);
    let mut launch_contract = HostLaunchContract {
        invocation_id: invocation_id.clone(),
        host_profile_ref: format!("external-agent-adapter:{}", call.host.as_str()),
        mode: HostMode::Supervised,
        project_id: Some(binding.project_id),
        agent_session_id: Some(authority.agent_session_id),
        task_id: Some(binding.task_id),
        work_item_id: Some(authority.work_item_id),
        role_lease_id: Some(authority.role_lease_id.clone()),
        role_lease_epoch: authority.role_lease_epoch,
        operation_generation: authority.operation_generation,
        work_lease_id: None,
        worktree_lease_id: None,
        planned_verifier_ref: Some(planned_verifier_ref.clone()),
        cwd_or_worktree: canonical_path(&binding.repository),
        baseline_commit: Some(contract.source_commit.clone()),
        allowed_paths: Vec::new(),
        forbidden_paths: vec![
            "provider-credential-roots".to_owned(),
            "raw-database".to_owned(),
            "truth-promotion".to_owned(),
        ],
        integration_bundle_ref: canonical_path(private_root),
        mcp_config_ref: format!("runtime/{}/provider-mcp", call.call_id),
        skill_bundle_ref: format!("runtime/{}/skills", call.call_id),
        lifecycle_bridge_ref: "external-agent-adapter".to_owned(),
        environment_allowlist: Vec::new(),
        permission_profile: "external_auditor".to_owned(),
        model_route_if_selected: Some(call.requested_model.clone()),
        max_turns_or_steps: Some(24),
        wall_clock_budget_seconds: 900,
        cost_budget_if_supported: None,
        session_id: None,
        resume_policy: "fresh_only".to_owned(),
        structured_output_schema_ref: Some(canonical_path(&output_schema_path)),
        stdout_stderr_spool: format!("runtime/{}/spool", call.call_id),
        artifact_manifest_ref: format!("runtime/{}/artifacts.json", call.call_id),
        idempotency_key: idempotency_key.clone(),
        expected_result_kind: "provider_execution_evidence".to_owned(),
        contract_hash: String::new(),
    };
    launch_contract.contract_hash = blake3::hash(&serde_json::to_vec(&launch_contract)?)
        .to_hex()
        .to_string();
    let invocation = AgentInvocationRequest {
        invocation_id,
        project_id: binding.project_id,
        task_id: binding.task_id,
        work_item_id: authority.work_item_id,
        requested_capabilities: vec![
            "emit_candidate_observation".to_owned(),
            "request_controller_review".to_owned(),
        ],
        role_lease_id: authority.role_lease_id.clone(),
        role_lease_epoch: authority.role_lease_epoch,
        operation_generation: authority.operation_generation,
        runtime_contract_sha256: Some(authority.runtime_contract_sha256.clone()),
        work_lease_id: None,
        packet_refs: Vec::new(),
        expected_result_kind: "provider_execution_evidence".to_owned(),
        verifier_ref: planned_verifier_ref,
        idempotency_key,
    };
    let execution = ExternalAgentExecutionRequest {
        invocation,
        launch_contract,
        purpose: ExternalAgentPurpose::UnderstandingReader,
        prompt_ref: canonical_path(prompt_path),
        prompt_sha256: call.prompt_sha256.clone(),
        output_schema_ref: canonical_path(&output_schema_path),
        output_schema_sha256: call.provider_schema_sha256.clone(),
        requested_model: call.requested_model.clone(),
        max_turns_or_steps: 24,
        timeout_profile_ref: format!("cognitive-field-{}-900s", call.host.as_str()),
        allowed_provider_tools,
        denied_provider_tools: vec![
            "Bash".to_owned(),
            "Edit".to_owned(),
            "NotebookEdit".to_owned(),
            "WebFetch".to_owned(),
            "WebSearch".to_owned(),
            "Write".to_owned(),
        ],
        expected_mcp_tool_names: expected_tools,
        forbidden_mcp_server_names: vec!["eliot_surrealdb".to_owned(), "surrealdb".to_owned()],
        read_only: true,
        candidate_only: true,
    };
    validate_external_agent_execution_request(&execution)?;
    Ok(execution)
}

#[allow(dead_code)]
fn validate_execution_request_binding(
    execution: &ExternalAgentExecutionRequest,
    call: &CognitiveFieldProviderCallPlan,
    binding: &SealedPromptBinding,
    prompt_path: &Path,
    private_root: &Path,
) -> Result<()> {
    let schema_path = canonical_file(
        &private_root.join("schemas").join("reader-provider.json"),
        "Reader provider output schema",
    )?;
    ensure!(
        execution.invocation.project_id == binding.project_id
            && execution.invocation.task_id == binding.task_id
            && execution.launch_contract.cwd_or_worktree == canonical_path(&binding.repository)
            && execution.prompt_ref == canonical_path(prompt_path)
            && execution.prompt_sha256 == call.prompt_sha256
            && execution.output_schema_ref == canonical_path(&schema_path)
            && execution.output_schema_sha256 == call.provider_schema_sha256
            && execution.requested_model == call.requested_model
            && execution.purpose == ExternalAgentPurpose::UnderstandingReader
            && execution.read_only
            && execution.candidate_only,
        "stored external execution request differs from the sealed cognitive call"
    );
    Ok(())
}

fn sealed_prompt_binding(
    prompt: &str,
    suite: &CognitiveFieldSuite,
    contract: &CognitiveFieldRunContract,
    private_root: &Path,
    call: &CognitiveFieldProviderCallPlan,
) -> Result<SealedPromptBinding> {
    ensure!(
        call.executions.len() == 1,
        "each external cognitive call must contain exactly one execution"
    );
    let execution = &call.executions[0];
    let case = suite
        .cases
        .iter()
        .find(|case| case.case_id == execution.case_id)
        .context("external cognitive call names an unknown case")?;
    let project_id: ProjectId = serde_json::from_value(Value::String(
        prompt_field(prompt, "PROJECT_ID")?.to_owned(),
    ))?;
    let task_id: TaskId =
        serde_json::from_value(Value::String(prompt_field(prompt, "TASK_ID")?.to_owned()))?;
    let repository = canonical_directory(
        Path::new(prompt_field(prompt, "REPOSITORY")?),
        "external cognitive repository",
    )?;
    let worktrees_root = canonical_directory(
        &private_root.join("worktrees"),
        "private cognitive worktrees root",
    )?;
    ensure!(
        prompt_field(prompt, "RUN")? == contract.run_id
            && prompt_field(prompt, "CALL")? == call.call_id
            && prompt_field(prompt, "CASE")? == execution.case_id
            && prompt_field(prompt, "MEMORY_CONDITION")?
                == condition_name(execution.memory_condition)
            && prompt_field(prompt, "SOURCE_COMMIT")? == contract.source_commit
            && repository.starts_with(&worktrees_root)
            && git_commit(&repository)? == contract.source_commit,
        "external cognitive prompt binding differs from the sealed run/call/worktree"
    );
    ensure!(
        prompt.contains(&case.title),
        "external cognitive prompt omits the exact public task"
    );
    let binding_path = private_root
        .join("bindings")
        .join(format!("{}.json", execution.case_id));
    let binding: CognitiveCallScopeBinding = read_json(&binding_path)?;
    ensure!(
        binding.run_id == contract.run_id
            && binding.case_id == execution.case_id
            && binding.project_id == project_id
            && binding.task_id == task_id,
        "private scope binding differs from the provider prompt"
    );
    Ok(SealedPromptBinding {
        project_id,
        task_id,
        repository,
    })
}

fn prompt_field<'a>(prompt: &'a str, name: &str) -> Result<&'a str> {
    let prefix = format!("{name}: ");
    prompt
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("provider prompt is missing {name}"))
}

fn cognitive_expected_mcp_tools(call: &CognitiveFieldProviderCallPlan) -> Vec<String> {
    if call.executions[0].memory_condition == CognitiveMemoryCondition::MemoryFreeControl {
        return Vec::new();
    }
    let mut tools = vec![
        "eliot_current_state".to_owned(),
        "eliot_fetch_l2".to_owned(),
        "eliot_memory_influence_trace".to_owned(),
        "eliot_recall_l0".to_owned(),
    ];
    tools.sort();
    tools
}

fn cognitive_allowed_provider_tools(host: AgentHostId, expected: &[String]) -> Vec<String> {
    if host == AgentHostId::Claude {
        expected
            .iter()
            .map(|tool| format!("mcp__eliot-governor__{tool}"))
            .collect()
    } else {
        expected.to_vec()
    }
}

fn private_relative_ref(private_root: &Path, path: &Path) -> Result<String> {
    let path = if path.exists() {
        fs::canonicalize(path)?
    } else {
        absolute_path(path)?
    };
    let relative = path
        .strip_prefix(private_root)
        .context("private artifact escaped the certification root")?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn seal_attempt_component(run_id: &str, generation: u64) -> String {
    let digest = blake3::hash(format!("{run_id}\n{generation}").as_bytes())
        .to_hex()
        .to_string();
    format!("seal-{}-g{generation}", &digest[..16])
}

fn seal_record_path(private_root: &Path, seal_attempt_id: &str) -> PathBuf {
    let component = seal_attempt_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    private_root
        .join("seal-records")
        .join(format!("{component}.json"))
}

fn load_seal_records(private_root: &Path) -> Result<Vec<ProviderPlanSealRecord>> {
    let root = private_root.join("seal-records");
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    paths
        .into_iter()
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .map(|path| read_json(&path))
        .collect()
}

fn next_seal_generation(
    private_root: &Path,
    existing_plan: Option<&CognitiveFieldProviderPlan>,
) -> Result<u64> {
    if let Some(plan) = existing_plan
        && plan.seal_generation > 0
    {
        return Ok(plan.seal_generation);
    }
    Ok(load_seal_records(private_root)?
        .iter()
        .map(|record| record.generation)
        .max()
        .unwrap_or(0)
        + 1)
}

fn encode_pretty_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn atomic_stage_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("staged artifact path has no parent directory")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("artifact")
    ));
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    Ok(())
}

fn stage_artifacts_with_cleanup(
    private_root: &Path,
    staging_root: &Path,
    artifacts: &[(String, String, Vec<u8>)],
    fail_after: Option<usize>,
) -> Result<()> {
    ensure!(
        !staging_root.exists(),
        "seal staging root already exists: {}",
        staging_root.display()
    );
    let outcome = (|| -> Result<()> {
        fs::create_dir_all(staging_root)?;
        for (index, (_kind, relative_path, bytes)) in artifacts.iter().enumerate() {
            if fail_after == Some(index) {
                bail!("injected seal staging failure after {index} artifacts");
            }
            let path = private_root.join(relative_path);
            ensure!(
                path.starts_with(staging_root),
                "staged artifact escaped the generation staging root"
            );
            atomic_stage_write(&path, bytes)?;
        }
        Ok(())
    })();
    if outcome.is_err() {
        let _ = fs::remove_dir_all(staging_root);
    }
    outcome
}

fn seal_manifest_hash(manifest: &SealArtifactManifest) -> Result<String> {
    let mut unsigned = manifest.clone();
    unsigned.manifest_sha256.clear();
    Ok(sha256_bytes(&serde_json::to_vec(&unsigned)?))
}

fn write_seal_record(private_root: &Path, record: &ProviderPlanSealRecord) -> Result<()> {
    crate::runtime_instance::atomic_write_json(
        &seal_record_path(private_root, &record.seal_attempt_id),
        record,
    )
}

fn provider_plan_seal_response(
    run_id: &str,
    seal_attempt_id: &str,
    generation: u64,
    plan: &CognitiveFieldProviderPlan,
    staged_manifest_sha256: &str,
) -> Value {
    json!({
        "status": "provider_plan_sealed",
        "run_id": run_id,
        "seal_attempt_id": seal_attempt_id,
        "seal_generation": generation,
        "provider_plan_hash": plan.plan_hash,
        "staged_manifest_sha256": staged_manifest_sha256,
        "planned_provider_calls": plan.planned_provider_calls,
        "planned_smoke_calls": plan.planned_smoke_calls,
        "planned_reused_roles": plan.planned_reused_roles,
        "total_calls": plan.calls.len(),
    })
}

#[allow(clippy::too_many_lines)]
pub async fn seal_provider_plan_with_mode(
    config_path: &Path,
    report_root: &Path,
    private_root: &Path,
    calls_path: &Path,
    dry_run: bool,
) -> Result<()> {
    let report_root = canonical_directory(report_root, "cognitive report root")?;
    let private_root = canonical_directory(private_root, "private certification root")?;
    let calls_path = fs::canonicalize(calls_path)
        .with_context(|| format!("resolve provider calls {}", calls_path.display()))?;
    ensure!(
        calls_path.starts_with(&private_root) && calls_path.is_file(),
        "provider calls must be a file inside the private certification root"
    );
    let suite: CognitiveFieldSuite = read_json(&report_root.join("suite.json"))?;
    let contract: CognitiveFieldRunContract = read_json(&report_root.join("contract.json"))?;
    validate_report_roots(&contract, &report_root, &private_root)?;
    ensure!(
        git_commit(Path::new(&contract.primary_repository))? == contract.source_commit,
        "primary repository HEAD moved after the field contract was sealed"
    );
    if suite.harness_version != COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION {
        ensure_deterministic_evidence_complete(&suite, &report_root)?;
    }
    let plan_path = report_root.join("provider-plan.json");
    let existing = plan_path
        .is_file()
        .then(|| read_json::<CognitiveFieldProviderPlan>(&plan_path))
        .transpose()?;
    if let Some(plan) = &existing {
        let published_record = load_seal_records(&private_root)?.into_iter().any(|record| {
            record.run_id == contract.run_id
                && record.seal_attempt_id.as_str() == plan.seal_attempt_id.as_deref().unwrap_or("")
                && record.generation == plan.seal_generation
                && record.state == ProviderPlanSealState::Published
        });
        ensure!(
            published_record,
            "provider-plan exists without a matching Published seal record; recovery is required"
        );
    }
    let generation = next_seal_generation(&private_root, existing.as_ref())?;
    let seal_attempt_id = existing
        .as_ref()
        .and_then(|plan| plan.seal_attempt_id.clone())
        .unwrap_or_else(|| {
            format!(
                "provider-plan-seal:{}",
                seal_attempt_component(&contract.run_id, generation)
            )
        });
    let incomplete = load_seal_records(&private_root)?
        .into_iter()
        .filter(|record| {
            record.run_id == contract.run_id
                && matches!(
                    record.state,
                    ProviderPlanSealState::Staged | ProviderPlanSealState::Activated
                )
        })
        .collect::<Vec<_>>();
    ensure!(
        incomplete.is_empty()
            || incomplete
                .iter()
                .all(|record| record.seal_attempt_id == seal_attempt_id),
        "an incomplete provider-plan seal requires recovery before a new generation"
    );
    let staging_component = seal_attempt_component(&contract.run_id, generation);
    let staging_prefix = format!("seal-staging/{staging_component}");
    let final_prefix = format!("sealed/{generation}");
    let staging_root = private_root.join(&staging_prefix);
    let published_root = private_root.join(&final_prefix);
    ensure!(
        !staging_root.exists(),
        "seal staging root already exists and must be recovered before sealing: {}",
        staging_root.display()
    );
    let mut calls: Vec<CognitiveFieldProviderCallPlan> = read_json(&calls_path)?;
    let (authority, mut private_artifacts) = render_external_provider_calls(
        config_path,
        &suite,
        &contract,
        &private_root,
        &seal_attempt_id,
        generation,
        &staging_prefix,
        &mut calls,
    )?;
    stage_artifacts_with_cleanup(&private_root, &staging_root, &private_artifacts, None)?;
    let validation = (|| -> Result<(Option<CoreRoleEvidencePlan>, u8, u8, u8)> {
        let role_evidence_plan =
            load_core_role_evidence_plan(&suite, &contract, &report_root, &private_root, &calls)?;
        let role_sources = role_evidence_plan
            .as_ref()
            .map_or(&[][..], |plan| plan.sources.as_slice());
        let (planned_provider_calls, planned_smoke_calls) =
            validate_provider_calls_with_sources(&suite, &calls, &private_root, role_sources)?;
        let planned_reused_roles = u8::try_from(prior_role_sources(role_sources).count())
            .context("reused role count exceeds u8")?;
        Ok((
            role_evidence_plan,
            planned_provider_calls,
            planned_smoke_calls,
            planned_reused_roles,
        ))
    })();
    let (role_evidence_plan, planned_provider_calls, planned_smoke_calls, planned_reused_roles) =
        match validation {
            Ok(validated) => validated,
            Err(error) => {
                let _ = fs::remove_dir_all(&staging_root);
                return Err(error.context("validate staged provider-plan artifacts"));
            }
        };
    for call in &mut calls {
        if let Some(relative) = call.execution_request_ref.strip_prefix(&staging_prefix) {
            call.execution_request_ref = format!("{final_prefix}{relative}");
        }
        if let Some(relative) = call.runtime_contract_ref.strip_prefix(&staging_prefix) {
            call.runtime_contract_ref = format!("{final_prefix}{relative}");
        }
    }
    let contract_bytes = encode_pretty_json(&contract)?;
    private_artifacts.push((
        "run_contract".to_owned(),
        format!("{staging_prefix}/contract.json"),
        contract_bytes,
    ));
    if let Some(role_plan) = &role_evidence_plan {
        private_artifacts.push((
            "role_evidence_plan".to_owned(),
            format!("{staging_prefix}/role-evidence-plan.json"),
            encode_pretty_json(role_plan)?,
        ));
    }
    private_artifacts.sort_by(|left, right| left.1.cmp(&right.1));
    for (_kind, relative_path, bytes) in &private_artifacts {
        let path = private_root.join(relative_path);
        if !path.is_file()
            && let Err(error) = atomic_stage_write(&path, bytes)
        {
            let _ = fs::remove_dir_all(&staging_root);
            return Err(error.context("complete provider-plan staging"));
        }
    }
    let mut manifest = SealArtifactManifest {
        schema_version: SEAL_ARTIFACT_MANIFEST_SCHEMA_VERSION.to_owned(),
        seal_attempt_id: seal_attempt_id.clone(),
        run_id: contract.run_id.clone(),
        generation,
        entries: private_artifacts
            .iter()
            .map(|(kind, relative_path, bytes)| SealArtifactEntry {
                logical_kind: kind.clone(),
                relative_path: relative_path.replacen(&staging_prefix, &final_prefix, 1),
                sha256: sha256_bytes(bytes),
                size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            })
            .collect(),
        manifest_sha256: String::new(),
    };
    manifest
        .entries
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    manifest.manifest_sha256 = seal_manifest_hash(&manifest)?;
    let authority_activation_ref = format!(
        "seal-records/{}.json",
        seal_record_path(&private_root, &seal_attempt_id)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("seal-record.json")
    );
    let mut plan = CognitiveFieldProviderPlan {
        schema_version: COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION.to_owned(),
        run_id: contract.run_id.clone(),
        contract_hash: contract.contract_hash.clone(),
        calls,
        planned_provider_calls,
        planned_smoke_calls,
        planned_reused_roles,
        role_evidence_plan_hash: role_evidence_plan
            .as_ref()
            .map(|role_plan| role_plan.plan_hash.clone()),
        seal_attempt_id: Some(seal_attempt_id.clone()),
        seal_generation: generation,
        authority_activation_ref: Some(authority_activation_ref),
        runtime_manifest_sha256: Some(manifest.manifest_sha256.clone()),
        artifact_manifest_sha256: Some(manifest.manifest_sha256.clone()),
        plan_hash: String::new(),
        sealed_at: existing.as_ref().map_or(
            contract.sealed_at
                + time::Duration::nanoseconds(i64::try_from(generation).unwrap_or(i64::MAX)),
            |plan| plan.sealed_at,
        ),
    };
    plan.plan_hash = CognitiveFieldGradingService::hash_json(&provider_plan_without_hash(&plan))?;
    let role_evidence_plan_sha256 = role_evidence_plan.as_ref().map_or_else(
        || sha256_bytes(b"none"),
        |role_plan| {
            serde_json::to_vec(role_plan)
                .map_or_else(|_| sha256_bytes(b"invalid"), |bytes| sha256_bytes(&bytes))
        },
    );
    let mut record = ProviderPlanSealRecord {
        schema_version: PROVIDER_PLAN_SEAL_RECORD_SCHEMA_VERSION.to_owned(),
        seal_attempt_id: seal_attempt_id.clone(),
        run_id: contract.run_id.clone(),
        generation,
        state: ProviderPlanSealState::Staged,
        contract_sha256: sha256_bytes(&serde_json::to_vec(&contract)?),
        role_evidence_plan_sha256,
        staged_manifest_sha256: manifest.manifest_sha256.clone(),
        provider_plan_sha256: Some(sha256_bytes(&encode_pretty_json(&plan)?)),
        session_ids: authority
            .iter()
            .map(|entry| entry.agent_session_id)
            .collect(),
        role_lease_ids: authority
            .iter()
            .map(|entry| entry.role_lease_id.clone())
            .collect(),
        work_item_ids: authority.iter().map(|entry| entry.work_item_id).collect(),
        operation_job_ids: authority
            .iter()
            .map(|entry| entry.operation_job_id.clone())
            .collect(),
        staging_root: staging_root.display().to_string(),
        published_root: published_root.display().to_string(),
        activated_at: None,
        published_at: None,
        abandoned_at: None,
        failure_ref: None,
    };
    record.session_ids.sort();
    record.role_lease_ids.sort();
    record.work_item_ids.sort();
    record.operation_job_ids.sort();
    let prepared = PreparedProviderPlanSeal {
        record: record.clone(),
        plan: plan.clone(),
        role_evidence_plan: role_evidence_plan.clone(),
        authority,
        manifest,
    };
    atomic_stage_write(
        &staging_root.join("artifact-manifest.json"),
        &encode_pretty_json(&prepared.manifest)?,
    )?;
    atomic_stage_write(
        &staging_root.join("candidate-provider-plan.json"),
        &encode_pretty_json(&prepared.plan)?,
    )?;
    if let Some(existing) = existing {
        ensure!(
            existing == plan,
            "existing sealed provider plan differs from the requested call plan"
        );
        let broker = crate::delegation_runtime::load_state(
            &crate::delegation_runtime::root_from_config(config_path),
        )?;
        let current_authority = prepared.record.role_lease_ids.iter().all(|role_lease_id| {
            broker.task_role_leases.iter().any(|lease| {
                lease.role_lease_id == *role_lease_id
                    && lease.state == AuthorityLeaseState::Active
                    && lease.generation == generation
                    && broker.agent_host_sessions.iter().any(|session| {
                        session.agent_session_id == lease.agent_session_id
                            && session.state == AgentSessionState::Active
                            && session.generation == generation
                    })
            })
        });
        ensure!(
            current_authority,
            "Published provider-plan authority is missing or stale; recovery is required"
        );
        fs::remove_dir_all(&staging_root)?;
        return print_json(&provider_plan_seal_response(
            &contract.run_id,
            &seal_attempt_id,
            generation,
            &existing,
            &prepared.manifest.manifest_sha256,
        ));
    }
    if dry_run {
        fs::remove_dir_all(&staging_root)?;
        return print_json(&json!({
            "status": "provider_plan_seal_dry_run",
            "run_id": contract.run_id,
            "seal_attempt_id": seal_attempt_id,
            "seal_generation": generation,
            "provider_plan_hash": plan.plan_hash,
            "staged_manifest_sha256": prepared.manifest.manifest_sha256,
            "authority_side_effects": 0,
            "planned_sessions": prepared.record.session_ids,
            "planned_role_leases": prepared.record.role_lease_ids,
            "planned_work_items": prepared.record.work_item_ids,
            "planned_operation_jobs": prepared.record.operation_job_ids,
        }));
    }
    let runtime_store =
        crate::host_runtime::supervised_process::daemon_operation_runtime_handle(config_path)?;
    if let Err(error) = runtime_store
        .put_seal_staging(SealStagingCheckpoint {
            schema_version: SEAL_STAGING_CHECKPOINT_SCHEMA_VERSION.to_owned(),
            seal_attempt_id: seal_attempt_id.clone(),
            run_id: contract.run_id.clone(),
            generation,
            staging_root: staging_root.display().to_string(),
            manifest_sha256: prepared.manifest.manifest_sha256.clone(),
            state: SealStagingState::Staged,
            updated_at: OffsetDateTime::now_utc().to_string(),
        })
        .await
    {
        let _ = fs::remove_dir_all(&staging_root);
        return Err(error).context("persist staged provider-plan seal checkpoint");
    }
    if let Err(error) = write_seal_record(&private_root, &record) {
        let _ = fs::remove_dir_all(&staging_root);
        let _ = runtime_store
            .remove_seal_staging(seal_attempt_id.clone())
            .await;
        return Err(error).context("persist staged provider-plan seal record");
    }
    if let Err(error) =
        activate_provider_seal_authority(config_path, &contract, &prepared.authority)
    {
        abandon_provider_seal(
            config_path,
            &private_root,
            Some(&plan_path),
            &mut record,
            &prepared.authority,
            &error.to_string(),
        )?;
        let _ = runtime_store
            .remove_seal_staging(seal_attempt_id.clone())
            .await;
        return Err(error.context("activate provider-plan seal authority"));
    }
    record.state = ProviderPlanSealState::Activated;
    record.activated_at = Some(OffsetDateTime::now_utc());
    let activated_checkpoint = SealStagingCheckpoint {
        schema_version: SEAL_STAGING_CHECKPOINT_SCHEMA_VERSION.to_owned(),
        seal_attempt_id: seal_attempt_id.clone(),
        run_id: contract.run_id.clone(),
        generation,
        staging_root: staging_root.display().to_string(),
        manifest_sha256: prepared.manifest.manifest_sha256.clone(),
        state: SealStagingState::Activated,
        updated_at: OffsetDateTime::now_utc().to_string(),
    };
    if let Err(error) = write_seal_record(&private_root, &record) {
        abandon_provider_seal(
            config_path,
            &private_root,
            Some(&plan_path),
            &mut record,
            &prepared.authority,
            &error.to_string(),
        )?;
        let _ = runtime_store
            .remove_seal_staging(seal_attempt_id.clone())
            .await;
        return Err(error).context("persist Activated provider-plan seal record");
    }
    if let Err(error) = runtime_store.put_seal_staging(activated_checkpoint).await {
        abandon_provider_seal(
            config_path,
            &private_root,
            Some(&plan_path),
            &mut record,
            &prepared.authority,
            &error.to_string(),
        )?;
        let _ = runtime_store
            .remove_seal_staging(seal_attempt_id.clone())
            .await;
        return Err(error).context("persist Activated provider-plan seal checkpoint");
    }
    let publish_result = (|| -> Result<()> {
        ensure!(
            !published_root.exists(),
            "immutable seal generation root already exists"
        );
        fs::create_dir_all(
            published_root
                .parent()
                .context("published seal root has no parent")?,
        )?;
        fs::rename(&staging_root, &published_root)?;
        if let Some(role_plan) = &prepared.role_evidence_plan {
            write_new_or_same_json(&report_root.join("role-evidence-plan.json"), role_plan)?;
            materialize_accepted_prior_roles(
                &suite,
                &contract,
                &plan,
                role_plan,
                &report_root,
                &private_root,
            )?;
        }
        write_new_or_same_json(&plan_path, &plan)?;
        Ok(())
    })();
    if let Err(error) = publish_result {
        abandon_provider_seal(
            config_path,
            &private_root,
            Some(&plan_path),
            &mut record,
            &prepared.authority,
            &error.to_string(),
        )?;
        let _ = runtime_store
            .remove_seal_staging(seal_attempt_id.clone())
            .await;
        return Err(error.context("publish provider-plan seal"));
    }
    if let Err(error) = mark_provider_seal_jobs_published(config_path, &prepared.authority) {
        abandon_provider_seal(
            config_path,
            &private_root,
            Some(&plan_path),
            &mut record,
            &prepared.authority,
            &error.to_string(),
        )?;
        let _ = runtime_store
            .remove_seal_staging(seal_attempt_id.clone())
            .await;
        return Err(error).context("mark provider-plan authority published");
    }
    record.state = ProviderPlanSealState::Published;
    record.published_at = Some(OffsetDateTime::now_utc());
    if let Err(error) = write_seal_record(&private_root, &record) {
        abandon_provider_seal(
            config_path,
            &private_root,
            Some(&plan_path),
            &mut record,
            &prepared.authority,
            &error.to_string(),
        )?;
        let _ = runtime_store
            .remove_seal_staging(seal_attempt_id.clone())
            .await;
        return Err(error).context("persist Published provider-plan seal record");
    }
    runtime_store
        .remove_seal_staging(seal_attempt_id.clone())
        .await?;
    if let Some(role_plan) = &prepared.role_evidence_plan {
        ensure!(
            report_root.join("role-evidence-plan.json").is_file()
                && !role_plan.plan_hash.is_empty(),
            "published role-evidence projection is missing"
        );
    }
    print_json(&provider_plan_seal_response(
        &contract.run_id,
        &seal_attempt_id,
        generation,
        &plan,
        &prepared.manifest.manifest_sha256,
    ))
}

#[allow(
    clippy::too_many_lines,
    reason = "two-owner seal activation is intentionally kept as one auditable transactional state machine"
)]
fn activate_provider_seal_authority(
    config_path: &Path,
    contract: &CognitiveFieldRunContract,
    authority: &[StagedSealAuthority],
) -> Result<()> {
    let root = crate::delegation_runtime::root_from_config(config_path);
    let mut broker = crate::delegation_runtime::load_state(&root)?;
    let mut work = crate::delegation_runtime::load_work_state(&root)?;
    let mut next_broker = broker.clone();
    let mut next_work = work.clone();
    let mut grants = Vec::with_capacity(authority.len());
    let now = OffsetDateTime::now_utc();
    for entry in authority {
        HostBrokerService.register_session_generation(
            &mut next_broker,
            entry.agent_session_id,
            entry.host,
            entry.host.as_str().to_owned(),
            entry.client_instance_id.clone(),
            AgentCapabilityEnvelope {
                capabilities: entry.capability_scope.clone(),
                structured_output: true,
                resumable: true,
                interactive: false,
                supervised: true,
            },
            entry.operation_generation,
            Some(entry.operation_job_id.clone()),
        )?;
        HostBrokerService.bind_session_scope(
            &mut next_broker,
            entry.agent_session_id,
            entry.project_id,
            entry.task_id,
        )?;
        let mut grant = HostBrokerService.prepare_role_grant(
            &next_broker,
            entry.task_id,
            entry.agent_session_id,
            AgentRole::Auditor,
            entry.capability_scope.clone(),
            30 * 24 * 60,
            Some(entry.operation_job_id.clone()),
        )?;
        grant.role_lease_id.clone_from(&entry.role_lease_id);
        grant.epoch = entry.role_lease_epoch;
        grant.expires_at = entry.expires_at;
        grants.push(grant);
        if !next_work
            .work_items
            .iter()
            .any(|item| item.work_item_id == entry.work_item_id)
        {
            next_work.work_items.push(WorkItem {
                work_item_id: entry.work_item_id,
                project_id: entry.project_id,
                task_id: entry.task_id,
                project: entry.project_id.to_string(),
                task: entry.task_id.to_string(),
                goal: format!(
                    "cognitive field UnderstandingReader {} generation {}",
                    entry.call_id, entry.operation_generation
                ),
                scope: WorkScope {
                    repo_root: contract.primary_repository.clone(),
                    read_set: vec![contract.primary_repository.clone()],
                    write_set: Vec::new(),
                    verifier_set: vec![format!(
                        "cognitive-field-provider-verifier:{}:{}",
                        contract.run_id, entry.call_id
                    )],
                    authority: eliot_types::AuthorityProfile::read_only(),
                    risk_tier: eliot_types::RiskTier::Low,
                    max_files: 0,
                    requires_active_work_lease: false,
                },
                status: WorkItemStatus::Open,
                required: true,
                allowed_roles: vec![AgentRole::Auditor],
                required_verifiers: Vec::new(),
                created_by: entry.agent_session_id,
                active_lease_id: None,
                lease_refs: Vec::new(),
                conflict_refs: Vec::new(),
                created_at: now,
                updated_at: now,
                completed_at: None,
                write_receipt: None,
            });
        }
    }
    let seal_attempt_id = authority.first().map_or_else(
        || {
            format!(
                "provider-plan-seal:{}",
                seal_attempt_component(&contract.run_id, 1)
            )
        },
        |entry| {
            format!(
                "provider-plan-seal:{}",
                seal_attempt_component(&contract.run_id, entry.operation_generation)
            )
        },
    );
    let activated = HostBrokerService.activate_role_grants(
        &mut next_broker,
        &grants,
        &seal_attempt_id,
        authority
            .first()
            .map_or(1, |entry| entry.operation_generation),
    )?;
    ensure!(
        activated.len() == authority.len(),
        "seal authority activation did not activate every prepared lease"
    );
    for entry in authority {
        if !next_broker
            .agent_invocations
            .iter()
            .any(|invocation| invocation.invocation_id == entry.invocation_id)
        {
            next_broker.agent_invocations.push(AgentInvocationRequest {
                invocation_id: entry.invocation_id.clone(),
                project_id: entry.project_id,
                task_id: entry.task_id,
                work_item_id: entry.work_item_id,
                requested_capabilities: entry.capability_scope.clone(),
                role_lease_id: entry.role_lease_id.clone(),
                role_lease_epoch: entry.role_lease_epoch,
                operation_generation: entry.operation_generation,
                runtime_contract_sha256: Some(entry.runtime_contract_sha256.clone()),
                work_lease_id: None,
                packet_refs: Vec::new(),
                expected_result_kind: "provider_execution_evidence".to_owned(),
                verifier_ref: format!(
                    "cognitive-field-provider-verifier:{}:{}",
                    contract.run_id, entry.call_id
                ),
                idempotency_key: format!("cognitive-field:{}:{}", contract.run_id, entry.call_id),
            });
        }
        if !next_broker
            .operation_jobs
            .iter()
            .any(|job| job.job_id == entry.operation_job_id)
        {
            next_broker.operation_jobs.push(OperationJob {
                job_id: entry.operation_job_id.clone(),
                invocation_id: entry.invocation_id.clone(),
                host_id: entry.host,
                state: OperationJobState::Queued,
                attempt: 0,
                resume_session_id: None,
                result_ref: None,
                idempotency_key: format!("cognitive-field:{}:{}", contract.run_id, entry.call_id),
                created_at: now,
                updated_at: now,
                generation: entry.operation_generation,
                phase: OperationPhase::AuthorityActivating,
                phase_started_at: Some(now),
                last_progress_at: Some(now),
                phase_deadline_at: None,
                absolute_deadline_at: None,
                restart_count: 0,
                runtime_contract_sha256: Some(entry.runtime_contract_sha256.clone()),
                role_lease_id: Some(entry.role_lease_id.clone()),
                role_lease_epoch: Some(entry.role_lease_epoch),
            });
        }
    }
    crate::delegation_runtime::save_work_state(&root, &next_work)?;
    crate::delegation_runtime::save_host_broker_state(&root, &next_broker)?;
    broker = next_broker;
    work = next_work;
    ensure!(
        broker.task_role_leases.iter().all(|lease| {
            !authority
                .iter()
                .any(|entry| entry.role_lease_id == lease.role_lease_id)
                || (lease.state == eliot_types::AuthorityLeaseState::Active
                    && lease.generation
                        == authority
                            .iter()
                            .find(|entry| entry.role_lease_id == lease.role_lease_id)
                            .map_or(0, |entry| entry.operation_generation))
        }) && work.work_items.iter().all(|item| {
            !authority
                .iter()
                .any(|entry| entry.work_item_id == item.work_item_id)
                || item.status == WorkItemStatus::Open
        }),
        "persisted provider-plan authority failed post-activation integrity"
    );
    Ok(())
}

fn mark_provider_seal_jobs_published(
    config_path: &Path,
    authority: &[StagedSealAuthority],
) -> Result<()> {
    let root = crate::delegation_runtime::root_from_config(config_path);
    let mut broker = crate::delegation_runtime::load_state(&root)?;
    let now = OffsetDateTime::now_utc();
    for entry in authority {
        let job = broker
            .operation_jobs
            .iter_mut()
            .find(|job| job.job_id == entry.operation_job_id)
            .context("activated seal operation job disappeared before publication")?;
        ensure!(
            job.generation == entry.operation_generation
                && job.role_lease_epoch == Some(entry.role_lease_epoch),
            "seal operation job generation fence changed before publication"
        );
        job.phase = OperationPhase::Published;
        job.phase_started_at = Some(now);
        job.last_progress_at = Some(now);
        job.updated_at = now;
    }
    crate::delegation_runtime::save_host_broker_state(&root, &broker)
}

fn quarantine_tree_manifest(root: &Path) -> Result<Vec<SealArtifactEntry>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut pending = vec![root.to_path_buf()];
    let mut entries = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for child in fs::read_dir(&path)? {
                pending.push(child?.path());
            }
        } else if path.is_file() {
            let bytes = fs::read(&path)?;
            entries.push(SealArtifactEntry {
                logical_kind: "quarantined_seal_artifact".to_owned(),
                relative_path: path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/"),
                sha256: sha256_bytes(&bytes),
                size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            });
        }
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(entries)
}

#[allow(
    clippy::too_many_lines,
    reason = "seal compensation performs ordered fencing, quarantine, and receipt publication as one recovery state machine"
)]
fn abandon_provider_seal(
    config_path: &Path,
    private_root: &Path,
    public_plan_path: Option<&Path>,
    record: &mut ProviderPlanSealRecord,
    authority: &[StagedSealAuthority],
    error: &str,
) -> Result<()> {
    let root = crate::delegation_runtime::root_from_config(config_path);
    let mut broker = crate::delegation_runtime::load_state(&root)?;
    let mut work = crate::delegation_runtime::load_work_state(&root)?;
    for entry in authority {
        if let Some(lease) = broker
            .task_role_leases
            .iter()
            .find(|lease| lease.role_lease_id == entry.role_lease_id)
            .cloned()
        {
            HostBrokerService.revoke_role(
                &mut broker,
                &entry.role_lease_id,
                lease.epoch,
                "partial_seal_before_provider_plan",
                Some(lease.epoch + 1),
            )?;
        }
        if broker
            .agent_host_sessions
            .iter()
            .any(|binding| binding.agent_session_id == entry.agent_session_id)
        {
            HostBrokerService.retire_session(
                &mut broker,
                entry.agent_session_id,
                "partial_seal_before_provider_plan",
            )?;
        }
        if broker
            .operation_jobs
            .iter()
            .any(|job| job.job_id == entry.operation_job_id)
        {
            HostBrokerService.abandon_operation(
                &mut broker,
                &entry.operation_job_id,
                "partial_seal_before_provider_plan",
            )?;
        }
        if let Some(item) = work
            .work_items
            .iter_mut()
            .find(|item| item.work_item_id == entry.work_item_id)
        {
            item.status = WorkItemStatus::Revoked;
            item.updated_at = OffsetDateTime::now_utc();
        }
    }
    crate::delegation_runtime::save_work_state(&root, &work)?;
    crate::delegation_runtime::save_host_broker_state(&root, &broker)?;
    let quarantine_root = private_root
        .join("quarantine")
        .join(seal_attempt_component(&record.run_id, record.generation));
    fs::create_dir_all(&quarantine_root)?;
    let mut quarantine_sources = vec![
        PathBuf::from(&record.staging_root),
        PathBuf::from(&record.published_root),
    ];
    quarantine_sources.extend(
        public_plan_path
            .filter(|path| path.exists())
            .map(Path::to_path_buf),
    );
    for source in quarantine_sources {
        if source.exists() {
            let manifest = quarantine_tree_manifest(&source)?;
            let target = quarantine_root.join(
                source
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("seal-artifacts"),
            );
            if !target.exists() {
                fs::rename(&source, &target)?;
            }
            write_new_or_same_json(
                &quarantine_root.join(format!(
                    "{}-manifest.json",
                    target
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("seal")
                )),
                &manifest,
            )?;
        }
    }
    let revocation_refs = broker
        .authority_revocation_receipts
        .iter()
        .filter(|receipt| {
            authority
                .iter()
                .any(|entry| entry.role_lease_id == receipt.role_lease_id)
        })
        .map(|receipt| receipt.receipt_id.clone())
        .collect::<Vec<_>>();
    let abandoned = AbandonedSealAttemptRecord {
        schema_version: ABANDONED_SEAL_ATTEMPT_SCHEMA_VERSION.to_owned(),
        seal_attempt_id: record.seal_attempt_id.clone(),
        run_id: record.run_id.clone(),
        generation: record.generation,
        recovery_state: SealRecoveryRecordState::Complete,
        recovery_guarantee:
            "ordered idempotent resumable recovery; no cross-file atomicity claimed".to_owned(),
        failed_phase: record.state,
        exact_error: error.to_owned(),
        created_session_ids: record.session_ids.clone(),
        created_role_lease_ids: record.role_lease_ids.clone(),
        created_work_item_ids: record.work_item_ids.clone(),
        created_operation_job_ids: record.operation_job_ids.clone(),
        referenced_work_item_ids: record.work_item_ids.clone(),
        referenced_invocation_ids: authority
            .iter()
            .map(|entry| entry.invocation_id.clone())
            .collect(),
        present_work_item_ids: record.work_item_ids.clone(),
        present_operation_job_ids: record.operation_job_ids.clone(),
        transitioned_work_item_ids: record.work_item_ids.clone(),
        transitioned_operation_job_ids: record.operation_job_ids.clone(),
        missing_projections: Vec::new(),
        non_projection_proofs: Vec::new(),
        recovery_steps: vec![SealRecoveryStep {
            step: "abandon_provider_seal".to_owned(),
            outcome: "complete".to_owned(),
            detail: "all minted authority was revoked or abandoned before quarantine".to_owned(),
            recorded_at: OffsetDateTime::now_utc(),
        }],
        quarantine_manifest_ref: private_relative_ref(private_root, &quarantine_root)?,
        authority_revocation_refs: revocation_refs,
        replacement_generation: Some(record.generation + 1),
        recorded_at: OffsetDateTime::now_utc(),
    };
    crate::runtime_instance::atomic_write_json(
        &private_root.join("abandoned-seals").join(format!(
            "{}.json",
            seal_attempt_component(&record.run_id, record.generation)
        )),
        &abandoned,
    )?;
    record.state = ProviderPlanSealState::Abandoned;
    record.abandoned_at = Some(OffsetDateTime::now_utc());
    record.failure_ref = Some(format!(
        "abandoned-seals/{}.json",
        seal_attempt_component(&record.run_id, record.generation)
    ));
    write_seal_record(private_root, record)
}

pub(crate) fn recover_incomplete_seal_checkpoint(
    config_path: &Path,
    checkpoint: &SealStagingCheckpoint,
) -> Result<bool> {
    let staging_root = PathBuf::from(&checkpoint.staging_root);
    let private_root = staging_root
        .parent()
        .and_then(Path::parent)
        .context("seal staging checkpoint has no private certification root")?;
    let mut record = load_seal_records(private_root)?
        .into_iter()
        .find(|record| record.seal_attempt_id == checkpoint.seal_attempt_id)
        .context("seal staging checkpoint has no matching seal record")?;
    if matches!(
        record.state,
        ProviderPlanSealState::Published | ProviderPlanSealState::Abandoned
    ) {
        return Ok(true);
    }
    ensure!(
        matches!(
            record.state,
            ProviderPlanSealState::Staged | ProviderPlanSealState::Activated
        ),
        "startup seal recovery found an unsupported seal state"
    );
    let root = crate::delegation_runtime::root_from_config(config_path);
    let broker = crate::delegation_runtime::load_state(&root)?;
    let mut authority = Vec::new();
    for (index, role_lease_id) in record.role_lease_ids.iter().enumerate() {
        let lease = broker
            .task_role_leases
            .iter()
            .find(|lease| lease.role_lease_id == *role_lease_id)
            .with_context(|| {
                format!(
                    "activated seal {} is missing role lease {}",
                    record.seal_attempt_id, role_lease_id
                )
            })?;
        let invocation = broker
            .agent_invocations
            .iter()
            .find(|invocation| invocation.role_lease_id == *role_lease_id)
            .context("activated seal role lease has no invocation")?;
        let job = broker
            .operation_jobs
            .iter()
            .find(|job| job.invocation_id == invocation.invocation_id)
            .context("activated seal invocation has no OperationJob")?;
        let session = broker
            .agent_host_sessions
            .iter()
            .find(|session| session.agent_session_id == lease.agent_session_id)
            .context("activated seal role lease has no AgentSession")?;
        authority.push(StagedSealAuthority {
            call_id: invocation.invocation_id.clone(),
            host: job.host_id,
            project_id: invocation.project_id,
            task_id: invocation.task_id,
            agent_session_id: lease.agent_session_id,
            client_instance_id: session.host_identity.client_instance_id.clone(),
            work_item_id: record
                .work_item_ids
                .get(index)
                .copied()
                .unwrap_or(invocation.work_item_id),
            role_lease_id: role_lease_id.clone(),
            role_lease_epoch: lease.epoch,
            operation_generation: lease.generation,
            runtime_contract_sha256: invocation
                .runtime_contract_sha256
                .clone()
                .or_else(|| job.runtime_contract_sha256.clone())
                .unwrap_or_else(|| sha256_bytes(b"unknown-runtime-contract")),
            invocation_id: invocation.invocation_id.clone(),
            operation_job_id: job.job_id.clone(),
            capability_scope: lease.capability_scope.clone(),
            expires_at: lease.expires_at,
        });
    }
    let (report_root, _) = resolve_cognitive_run_roots(&record.run_id, None, Some(private_root))?;
    abandon_provider_seal(
        config_path,
        private_root,
        Some(&report_root.join("provider-plan.json")),
        &mut record,
        &authority,
        "startup_recovery_incomplete_provider_plan_seal",
    )?;
    Ok(true)
}

fn resolve_cognitive_run_roots(
    run_id: &str,
    report_root: Option<&Path>,
    private_root: Option<&Path>,
) -> Result<(PathBuf, PathBuf)> {
    ensure!(safe_segment(run_id), "cognitive run ID is unsafe");
    let report = report_root.map_or_else(
        || {
            std::env::current_dir().map(|cwd| {
                cwd.join("reports")
                    .join("cognitive-field")
                    .join("core-qualification")
                    .join(run_id)
            })
        },
        |path| Ok(path.to_path_buf()),
    )?;
    let private = private_root.map_or_else(
        || {
            std::env::var_os("LOCALAPPDATA").map_or_else(
                || bail!("LOCALAPPDATA is required to locate the private cognitive run"),
                |root| {
                    Ok(PathBuf::from(root)
                        .join("Eliot")
                        .join("cognitive-field")
                        .join("core-qualification")
                        .join(run_id))
                },
            )
        },
        |path| Ok(path.to_path_buf()),
    )?;
    Ok((
        canonical_directory(&report, "cognitive report root")?,
        canonical_directory(&private, "private cognitive run root")?,
    ))
}

fn recursive_files(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for child in fs::read_dir(path)? {
                pending.push(child?.path());
            }
        } else if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn scan_projection_refs(
    roots: &[PathBuf],
    ids: &[String],
) -> (usize, Vec<String>, Vec<String>, Vec<String>) {
    let mut scanned_file_count = 0;
    let mut scan_exclusions = Vec::new();
    let mut scan_errors = Vec::new();
    let mut matching_paths = Vec::new();
    for root in roots {
        let files = match recursive_files(root) {
            Ok(files) => files,
            Err(error) => {
                scan_errors.push(format!("{}: {error:#}", root.display()));
                continue;
            }
        };
        for path in files {
            if path
                .extension()
                .is_some_and(|extension| extension == "redb")
            {
                scan_exclusions.push(format!(
                    "{}: ControlWal binary is not an authority projection owner and may be live-locked",
                    path.display()
                ));
                continue;
            }
            scanned_file_count += 1;
            match fs::read(&path) {
                Ok(bytes) => {
                    if ids.iter().any(|id| bytes_contain(&bytes, id.as_bytes())) {
                        matching_paths.push(path.display().to_string());
                    }
                }
                Err(error) => scan_errors.push(format!("{}: {error}", path.display())),
            }
        }
    }
    scan_exclusions.sort();
    scan_exclusions.dedup();
    matching_paths.sort();
    matching_paths.dedup();
    (
        scanned_file_count,
        scan_exclusions,
        scan_errors,
        matching_paths,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the proof constructor records every independently verified absence condition"
)]
fn build_non_projection_proof(
    authority_kind: &str,
    owner_store_path: &Path,
    owner_record_count: usize,
    first_request_modified_at: OffsetDateTime,
    scan_roots: &[PathBuf],
    referenced_ids: &[String],
    require_owner_predates_request: bool,
    source_evidence_ref: Option<String>,
) -> Result<NonProjectionProof> {
    ensure!(
        owner_store_path.is_file(),
        "{authority_kind} owner store is absent: {}",
        owner_store_path.display()
    );
    let owner_store_modified_at = OffsetDateTime::from(fs::metadata(owner_store_path)?.modified()?);
    let owner_store_predates_first_request = owner_store_modified_at < first_request_modified_at;
    let (scanned_file_count, scan_exclusions, scan_errors, matching_paths) =
        scan_projection_refs(scan_roots, referenced_ids);
    let owner_store_load_ok = true;
    let complete = owner_store_load_ok
        && owner_record_count > 0
        && scan_errors.is_empty()
        && matching_paths.is_empty()
        && ((!require_owner_predates_request || owner_store_predates_first_request)
            && (require_owner_predates_request || source_evidence_ref.is_some()));
    Ok(NonProjectionProof {
        schema_version: "eliot-non-projection-proof-v1".to_owned(),
        authority_kind: authority_kind.to_owned(),
        owner_store_path: owner_store_path.display().to_string(),
        owner_store_load_ok,
        owner_record_count,
        owner_store_modified_at,
        first_request_modified_at,
        owner_store_predates_first_request,
        scan_roots: scan_roots
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        scanned_file_count,
        scan_exclusions,
        scan_errors,
        matching_paths,
        source_evidence_ref,
        complete,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "run recovery inspection is a single fail-closed classification over all seal evidence"
)]
fn inspect_seal_recovery(
    config_path: &Path,
    run_id: &str,
    report_root: &Path,
    private_root: &Path,
) -> Result<SealRecoveryInspection> {
    let calls: Vec<CognitiveFieldProviderCallPlan> = read_json(&private_root.join("calls.json"))?;
    let external_calls = calls
        .iter()
        .filter(|call| call.host != AgentHostId::Codex)
        .collect::<Vec<_>>();
    let root = crate::delegation_runtime::root_from_config(config_path);
    let broker = crate::delegation_runtime::load_state(&root)?;
    let work = crate::delegation_runtime::load_work_state(&root)?;
    let mut execution_request_paths = Vec::new();
    let mut provider_runtime_paths = Vec::new();
    let mut session_ids = Vec::new();
    let mut role_lease_ids = Vec::new();
    let mut referenced_work_item_ids = Vec::new();
    let mut referenced_invocation_ids = Vec::new();
    let mut present_work_item_ids = Vec::new();
    let mut present_operation_job_ids = Vec::new();
    let mut invocation_ids = Vec::new();
    let mut requests = Vec::new();
    let mut request_modified_at = Vec::new();
    for call in &external_calls {
        let request_path = private_root
            .join("runtime")
            .join(format!("{}-execution-request.json", call.call_id));
        let runtime_path = private_root
            .join("runtime")
            .join(format!("{}-provider-runtime.json", call.call_id));
        if request_path.is_file() {
            let request: ExternalAgentExecutionRequest = read_json(&request_path)?;
            execution_request_paths.push(private_relative_ref(private_root, &request_path)?);
            invocation_ids.push(request.invocation.invocation_id.clone());
            referenced_invocation_ids.push(request.invocation.invocation_id.clone());
            referenced_work_item_ids.push(request.invocation.work_item_id);
            request_modified_at.push(OffsetDateTime::from(
                fs::metadata(&request_path)?.modified()?,
            ));
            if let Some(session_id) = request.launch_contract.agent_session_id
                && broker
                    .agent_host_sessions
                    .iter()
                    .any(|binding| binding.agent_session_id == session_id)
            {
                session_ids.push(session_id);
            }
            if broker
                .task_role_leases
                .iter()
                .any(|lease| lease.role_lease_id == request.invocation.role_lease_id)
            {
                role_lease_ids.push(request.invocation.role_lease_id.clone());
            }
            if work
                .work_items
                .iter()
                .any(|item| item.work_item_id == request.invocation.work_item_id)
            {
                present_work_item_ids.push(request.invocation.work_item_id);
            }
            present_operation_job_ids.extend(
                broker
                    .operation_jobs
                    .iter()
                    .filter(|job| job.invocation_id == request.invocation.invocation_id)
                    .map(|job| job.job_id.clone()),
            );
            requests.push(request);
        }
        if runtime_path.is_file() {
            provider_runtime_paths.push(private_relative_ref(private_root, &runtime_path)?);
        }
    }
    execution_request_paths.sort();
    provider_runtime_paths.sort();
    session_ids.sort();
    session_ids.dedup();
    role_lease_ids.sort();
    role_lease_ids.dedup();
    referenced_work_item_ids.sort();
    referenced_work_item_ids.dedup();
    referenced_invocation_ids.sort();
    referenced_invocation_ids.dedup();
    present_work_item_ids.sort();
    present_work_item_ids.dedup();
    present_operation_job_ids.sort();
    present_operation_job_ids.dedup();
    let present_invocation_ids = broker
        .operation_jobs
        .iter()
        .filter(|job| referenced_invocation_ids.contains(&job.invocation_id))
        .map(|job| job.invocation_id.clone())
        .collect::<BTreeSet<_>>();
    let missing_work_item_ids = referenced_work_item_ids
        .iter()
        .filter(|id| !present_work_item_ids.contains(id))
        .copied()
        .collect::<Vec<_>>();
    let missing_invocation_ids = referenced_invocation_ids
        .iter()
        .filter(|id| !present_invocation_ids.contains(*id))
        .cloned()
        .collect::<Vec<_>>();
    let scoped_session_ids = broker
        .agent_host_sessions
        .iter()
        .filter(|binding| {
            binding
                .host_identity
                .client_instance_id
                .starts_with(&format!("cognitive-field:{run_id}:"))
        })
        .map(|binding| binding.agent_session_id)
        .collect::<BTreeSet<_>>();
    let expected_session_ids = session_ids.iter().copied().collect::<BTreeSet<_>>();
    let scoped_role_lease_ids = broker
        .task_role_leases
        .iter()
        .filter(|lease| expected_session_ids.contains(&lease.agent_session_id))
        .map(|lease| lease.role_lease_id.clone())
        .collect::<BTreeSet<_>>();
    let expected_role_lease_ids = role_lease_ids.iter().cloned().collect::<BTreeSet<_>>();
    let scoped_authority_exact = scoped_session_ids == expected_session_ids
        && scoped_role_lease_ids == expected_role_lease_ids;
    let legacy_authority_cas_ready = session_ids.iter().all(|id| {
        broker.agent_host_sessions.iter().any(|binding| {
            binding.agent_session_id == *id
                && binding.state == AgentSessionState::Active
                && binding.generation == 0
                && binding.owner_operation_id.is_none()
        })
    }) && role_lease_ids.iter().all(|id| {
        broker.task_role_leases.iter().any(|lease| {
            lease.role_lease_id == *id
                && lease.state == AuthorityLeaseState::Active
                && lease.generation == 0
                && lease.owner_operation_id.is_none()
                && lease.seal_attempt_id.is_none()
        })
    });
    let work_bindings_valid = present_work_item_ids.iter().all(|id| {
        let Some(item) = work.work_items.iter().find(|item| item.work_item_id == *id) else {
            return false;
        };
        requests.iter().any(|request| {
            request.invocation.work_item_id == *id
                && item.project_id == request.invocation.project_id
                && item.task_id == request.invocation.task_id
                && request
                    .launch_contract
                    .agent_session_id
                    .is_none_or(|session_id| item.created_by == session_id)
        })
    });
    let job_bindings_valid = broker
        .operation_jobs
        .iter()
        .filter(|job| referenced_invocation_ids.contains(&job.invocation_id))
        .all(|job| {
            requests.iter().any(|request| {
                request.invocation.invocation_id == job.invocation_id
                    && job.generation == 0
                    && job.role_lease_id.as_deref()
                        == Some(request.invocation.role_lease_id.as_str())
            })
        });
    let mut non_projection_proofs = Vec::new();
    if let Some(first_request_modified_at) = request_modified_at.iter().min().copied() {
        let scan_roots = vec![root.join("reports"), root.join("control")];
        if present_work_item_ids.is_empty() && !referenced_work_item_ids.is_empty() {
            non_projection_proofs.push(build_non_projection_proof(
                "work_item",
                &root.join("reports/work/state.json"),
                work.work_items.len(),
                first_request_modified_at,
                &scan_roots,
                &referenced_work_item_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                true,
                None,
            )?);
        }
        if present_operation_job_ids.is_empty() && !referenced_invocation_ids.is_empty() {
            non_projection_proofs.push(build_non_projection_proof(
                "operation_job",
                &root.join("reports/delegation-state/latest.json"),
                broker.operation_jobs.len(),
                first_request_modified_at,
                &scan_roots,
                &referenced_invocation_ids,
                false,
                Some(
                    "git:8d2db4a:crates/eliot-app/src/cognitive_field_runner.rs\
                     #cognitive_external_execution_request_minted_ids_without_job_projection"
                        .to_owned(),
                ),
            )?);
        }
    }
    let work_projection_safe = (present_work_item_ids.len() == 4
        && missing_work_item_ids.is_empty()
        && work_bindings_valid)
        || (present_work_item_ids.is_empty()
            && non_projection_proofs
                .iter()
                .any(|proof| proof.authority_kind == "work_item" && proof.complete));
    let job_projection_safe = (present_operation_job_ids.len() == 4
        && missing_invocation_ids.is_empty()
        && job_bindings_valid)
        || (present_operation_job_ids.is_empty()
            && non_projection_proofs
                .iter()
                .any(|proof| proof.authority_kind == "operation_job" && proof.complete));
    let call_ids = external_calls
        .iter()
        .map(|call| call.call_id.as_str())
        .collect::<Vec<_>>();
    let provider_reservation_count = broker
        .provider_call_reservations
        .iter()
        .filter(|reservation| {
            serde_json::to_string(reservation)
                .ok()
                .is_some_and(|value| call_ids.iter().any(|call_id| value.contains(call_id)))
        })
        .count();
    let provider_result_count = broker
        .agent_results
        .iter()
        .filter(|result| invocation_ids.contains(&result.invocation_id))
        .count();
    let provider_artifact_paths = recursive_files(private_root)?
        .into_iter()
        .filter(|path| {
            let relative = path
                .strip_prefix(private_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            !relative.starts_with("runtime/")
                && call_ids.iter().any(|call_id| relative.contains(call_id))
                && (relative.contains("spool")
                    || relative.contains("raw")
                    || relative.starts_with("outputs/")
                    || relative.starts_with("receipts/provider-"))
        })
        .map(|path| private_relative_ref(private_root, &path))
        .collect::<Result<Vec<_>>>()?;
    let provider_plan_present = report_root.join("provider-plan.json").is_file();
    let abandoned_exists = load_seal_records(private_root)?.iter().any(|record| {
        record.run_id == run_id
            && record.generation == 1
            && record.state == ProviderPlanSealState::Abandoned
    });
    let exact_partial_shape = external_calls.len() == 4
        && execution_request_paths.len() == 4
        && provider_runtime_paths.len() == 4
        && session_ids.len() == 4
        && role_lease_ids.len() == 4
        && referenced_work_item_ids.len() == 4
        && referenced_invocation_ids.len() == 4
        && scoped_authority_exact
        && legacy_authority_cas_ready
        && work_projection_safe
        && job_projection_safe
        && !provider_plan_present
        && provider_reservation_count == 0
        && provider_result_count == 0
        && provider_artifact_paths.is_empty();
    let decision = if abandoned_exists {
        SealRecoveryDecision::AlreadyAbandoned
    } else if provider_reservation_count > 0
        || provider_result_count > 0
        || !provider_artifact_paths.is_empty()
    {
        SealRecoveryDecision::BlockedProviderEvidence
    } else if exact_partial_shape {
        SealRecoveryDecision::AbandonAndRevokeSafePredispatch
    } else {
        SealRecoveryDecision::BlockedIntegrityMismatch
    };
    let mut integrity_errors = Vec::new();
    if !scoped_authority_exact {
        integrity_errors.push("scoped session/lease sets differ from the four request bindings");
    }
    if !legacy_authority_cas_ready {
        integrity_errors.push("legacy authority is not Active generation-0 CAS-ready");
    }
    if !work_projection_safe {
        integrity_errors.push("WorkItem projection is partial, misbound, or lacks absence proof");
    }
    if !job_projection_safe {
        integrity_errors
            .push("OperationJob projection is partial, misbound, or lacks absence proof");
    }
    Ok(SealRecoveryInspection {
        schema_version: "eliot-seal-recovery-inspection-v1".to_owned(),
        run_id: run_id.to_owned(),
        generation: 1,
        decision,
        execution_request_paths,
        provider_runtime_paths,
        session_ids,
        role_lease_ids,
        referenced_work_item_ids,
        referenced_invocation_ids,
        present_work_item_ids,
        present_operation_job_ids,
        missing_work_item_ids,
        missing_invocation_ids,
        non_projection_proofs,
        scoped_authority_exact,
        legacy_authority_cas_ready,
        provider_plan_present,
        provider_reservation_count,
        provider_result_count,
        provider_artifact_paths,
        exact_error: (decision == SealRecoveryDecision::BlockedIntegrityMismatch).then(|| {
            if integrity_errors.is_empty() {
                "partial seal shape differs from the exact four-call run006 contract".to_owned()
            } else {
                integrity_errors.join("; ")
            }
        }),
    })
}

pub fn seal_status(
    config_path: &Path,
    run_id: &str,
    report_root: Option<&Path>,
    private_root: Option<&Path>,
) -> Result<()> {
    let (report_root, private_root) =
        resolve_cognitive_run_roots(run_id, report_root, private_root)?;
    let inspection = inspect_seal_recovery(config_path, run_id, &report_root, &private_root)?;
    let records = load_seal_records(&private_root)?;
    print_json(&json!({
        "component": "cognitive_field_seal_status",
        "run_id": run_id,
        "inspection": inspection,
        "seal_records": records,
    }))
}

#[allow(clippy::too_many_lines)]
pub fn recover_seal(
    config_path: &Path,
    run_id: &str,
    report_root: Option<&Path>,
    private_root: Option<&Path>,
    dry_run: bool,
    apply: bool,
) -> Result<()> {
    ensure!(
        dry_run ^ apply,
        "recover-seal requires exactly one of --dry-run or --apply"
    );
    let (report_root, private_root) =
        resolve_cognitive_run_roots(run_id, report_root, private_root)?;
    let inspection = inspect_seal_recovery(config_path, run_id, &report_root, &private_root)?;
    if dry_run || inspection.decision == SealRecoveryDecision::AlreadyAbandoned {
        return print_json(&inspection);
    }
    ensure!(
        inspection.decision == SealRecoveryDecision::AbandonAndRevokeSafePredispatch,
        "seal recovery is not safe to apply: {:?}",
        inspection.decision
    );
    let root = crate::delegation_runtime::root_from_config(config_path);
    let seal_attempt_id = format!("provider-plan-seal:legacy-{run_id}-generation-1");
    let quarantine_root = private_root
        .join("quarantine")
        .join(seal_attempt_component(run_id, 1));
    let manifest_path = quarantine_root.join("generation-1-manifest.json");
    let abandoned_path = private_root
        .join("abandoned-seals")
        .join(format!("{}.json", seal_attempt_component(run_id, 1)));
    let mut manifest = SealArtifactManifest {
        schema_version: SEAL_ARTIFACT_MANIFEST_SCHEMA_VERSION.to_owned(),
        seal_attempt_id: seal_attempt_id.clone(),
        run_id: run_id.to_owned(),
        generation: 1,
        entries: Vec::new(),
        manifest_sha256: String::new(),
    };
    for relative in inspection
        .execution_request_paths
        .iter()
        .chain(&inspection.provider_runtime_paths)
    {
        let source = private_root.join(relative);
        let bytes = fs::read(&source)?;
        manifest.entries.push(SealArtifactEntry {
            logical_kind: if relative.ends_with("-execution-request.json") {
                "execution_request".to_owned()
            } else {
                "provider_runtime".to_owned()
            },
            relative_path: relative.clone(),
            sha256: sha256_bytes(&bytes),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
    }
    manifest
        .entries
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    ensure!(
        manifest.entries.len() == 8,
        "legacy seal recovery must hash exactly eight immutable artifacts before mutation"
    );
    manifest.manifest_sha256 = seal_manifest_hash(&manifest)?;
    let missing_projections = inspection
        .missing_work_item_ids
        .iter()
        .map(|id| MissingAuthorityProjection {
            authority_kind: "work_item".to_owned(),
            referenced_id: id.to_string(),
            reason: "never_projected".to_owned(),
        })
        .chain(
            inspection
                .missing_invocation_ids
                .iter()
                .map(|id| MissingAuthorityProjection {
                    authority_kind: "operation_job".to_owned(),
                    referenced_id: id.clone(),
                    reason: "never_projected".to_owned(),
                }),
        )
        .collect::<Vec<_>>();
    let mut abandoned = AbandonedSealAttemptRecord {
        schema_version: ABANDONED_SEAL_ATTEMPT_SCHEMA_VERSION.to_owned(),
        seal_attempt_id: seal_attempt_id.clone(),
        run_id: run_id.to_owned(),
        generation: 1,
        recovery_state: SealRecoveryRecordState::InProgress,
        recovery_guarantee:
            "ordered idempotent resumable recovery; no cross-file atomicity claimed".to_owned(),
        failed_phase: ProviderPlanSealState::Activated,
        exact_error: "partial seal before provider-plan publication".to_owned(),
        created_session_ids: inspection.session_ids.clone(),
        created_role_lease_ids: inspection.role_lease_ids.clone(),
        created_work_item_ids: inspection.present_work_item_ids.clone(),
        created_operation_job_ids: inspection.present_operation_job_ids.clone(),
        referenced_work_item_ids: inspection.referenced_work_item_ids.clone(),
        referenced_invocation_ids: inspection.referenced_invocation_ids.clone(),
        present_work_item_ids: inspection.present_work_item_ids.clone(),
        present_operation_job_ids: inspection.present_operation_job_ids.clone(),
        transitioned_work_item_ids: Vec::new(),
        transitioned_operation_job_ids: Vec::new(),
        missing_projections,
        non_projection_proofs: inspection.non_projection_proofs.clone(),
        recovery_steps: vec![SealRecoveryStep {
            step: "pre_mutation_inventory".to_owned(),
            outcome: "complete".to_owned(),
            detail: format!(
                "hashed {} immutable files; pre-provider and non-projection gates passed",
                manifest.entries.len()
            ),
            recorded_at: OffsetDateTime::now_utc(),
        }],
        quarantine_manifest_ref: private_relative_ref(&private_root, &manifest_path)?,
        authority_revocation_refs: Vec::new(),
        replacement_generation: Some(2),
        recorded_at: OffsetDateTime::now_utc(),
    };
    crate::runtime_instance::atomic_write_json(&abandoned_path, &abandoned)?;
    let mut broker = crate::delegation_runtime::load_state(&root)?;
    let mut work = crate::delegation_runtime::load_work_state(&root)?;
    for role_lease_id in &inspection.role_lease_ids {
        let lease = broker
            .task_role_leases
            .iter()
            .find(|lease| lease.role_lease_id == *role_lease_id)
            .cloned()
            .context("run006 role lease disappeared before typed recovery")?;
        HostBrokerService.revoke_role(
            &mut broker,
            role_lease_id,
            lease.epoch,
            "partial_seal_before_provider_plan",
            Some(lease.epoch + 1),
        )?;
    }
    for session_id in &inspection.session_ids {
        HostBrokerService.retire_session(
            &mut broker,
            *session_id,
            "partial_seal_before_provider_plan",
        )?;
    }
    for job_id in &inspection.present_operation_job_ids {
        HostBrokerService.abandon_operation(
            &mut broker,
            job_id,
            "partial_seal_before_provider_plan",
        )?;
        abandoned
            .transitioned_operation_job_ids
            .push(job_id.clone());
    }
    for work_item_id in &inspection.present_work_item_ids {
        let item = work
            .work_items
            .iter_mut()
            .find(|item| item.work_item_id == *work_item_id)
            .context("run006 WorkItem disappeared before typed recovery")?;
        item.status = WorkItemStatus::Revoked;
        item.updated_at = OffsetDateTime::now_utc();
        abandoned.transitioned_work_item_ids.push(*work_item_id);
    }
    if !abandoned.transitioned_work_item_ids.is_empty() {
        crate::delegation_runtime::save_work_state(&root, &work)?;
    }
    crate::delegation_runtime::save_host_broker_state(&root, &broker)?;
    abandoned.recovery_steps.push(SealRecoveryStep {
        step: "authority_compensation".to_owned(),
        outcome: "complete".to_owned(),
        detail: format!(
            "revoked {} leases, retired {} sessions, abandoned {} jobs and {} WorkItems",
            inspection.role_lease_ids.len(),
            inspection.session_ids.len(),
            abandoned.transitioned_operation_job_ids.len(),
            abandoned.transitioned_work_item_ids.len()
        ),
        recorded_at: OffsetDateTime::now_utc(),
    });
    crate::runtime_instance::atomic_write_json(&abandoned_path, &abandoned)?;
    fs::create_dir_all(quarantine_root.join("runtime"))?;
    for entry in &manifest.entries {
        let relative = &entry.relative_path;
        let source = private_root.join(relative);
        let target = quarantine_root.join(relative);
        fs::create_dir_all(target.parent().context("quarantine target has no parent")?)?;
        fs::rename(&source, &target)?;
        let quarantined = fs::read(&target)?;
        ensure!(
            sha256_bytes(&quarantined) == entry.sha256
                && u64::try_from(quarantined.len()).unwrap_or(u64::MAX) == entry.size_bytes,
            "quarantined artifact differs from its pre-mutation digest: {}",
            target.display()
        );
    }
    write_new_or_same_json(&manifest_path, &manifest)?;
    abandoned.recovery_steps.push(SealRecoveryStep {
        step: "artifact_quarantine".to_owned(),
        outcome: "complete".to_owned(),
        detail: "all eight post-move digests equal their pre-move digests".to_owned(),
        recorded_at: OffsetDateTime::now_utc(),
    });
    crate::runtime_instance::atomic_write_json(&abandoned_path, &abandoned)?;
    let fresh_broker = crate::delegation_runtime::load_state(&root)?;
    let fresh_work = crate::delegation_runtime::load_work_state(&root)?;
    ensure!(
        inspection.role_lease_ids.iter().all(|role_lease_id| {
            fresh_broker.task_role_leases.iter().any(|lease| {
                lease.role_lease_id == *role_lease_id
                    && lease.state == AuthorityLeaseState::Revoked
                    && lease.revoke_reason.as_deref() == Some("partial_seal_before_provider_plan")
            })
        }),
        "fresh post-recovery load found a role lease that was not revoked"
    );
    ensure!(
        inspection.session_ids.iter().all(|session_id| {
            fresh_broker.agent_host_sessions.iter().any(|binding| {
                binding.agent_session_id == *session_id
                    && binding.state == AgentSessionState::Retired
                    && binding.disconnect_reason.as_deref()
                        == Some("partial_seal_before_provider_plan")
            })
        }),
        "fresh post-recovery load found a session that was not retired"
    );
    ensure!(
        inspection
            .referenced_work_item_ids
            .iter()
            .all(|work_item_id| {
                fresh_work
                    .work_items
                    .iter()
                    .find(|item| item.work_item_id == *work_item_id)
                    .is_none_or(|item| item.status == WorkItemStatus::Revoked)
            }),
        "fresh post-recovery load found an active matching WorkItem"
    );
    ensure!(
        inspection
            .referenced_invocation_ids
            .iter()
            .all(|invocation_id| {
                fresh_broker
                    .operation_jobs
                    .iter()
                    .filter(|job| job.invocation_id == *invocation_id)
                    .all(|job| job.state == OperationJobState::Abandoned)
            }),
        "fresh post-recovery load found an active matching OperationJob"
    );
    abandoned.authority_revocation_refs = fresh_broker
        .authority_revocation_receipts
        .iter()
        .filter(|receipt| inspection.role_lease_ids.contains(&receipt.role_lease_id))
        .map(|receipt| receipt.receipt_id.clone())
        .collect::<Vec<_>>();
    abandoned.recovery_steps.push(SealRecoveryStep {
        step: "fresh_postcondition_reload".to_owned(),
        outcome: "complete".to_owned(),
        detail: "no active matching session, lease, WorkItem, or OperationJob remains".to_owned(),
        recorded_at: OffsetDateTime::now_utc(),
    });
    let record = ProviderPlanSealRecord {
        schema_version: PROVIDER_PLAN_SEAL_RECORD_SCHEMA_VERSION.to_owned(),
        seal_attempt_id,
        run_id: run_id.to_owned(),
        generation: 1,
        state: ProviderPlanSealState::Abandoned,
        contract_sha256: read_json::<CognitiveFieldRunContract>(&report_root.join("contract.json"))
            .and_then(|contract| serde_json::to_vec(&contract).map_err(Into::into))
            .map(|bytes| sha256_bytes(&bytes))?,
        role_evidence_plan_sha256: sha256_bytes(b"legacy-partial-seal"),
        staged_manifest_sha256: manifest.manifest_sha256.clone(),
        provider_plan_sha256: None,
        session_ids: inspection.session_ids.clone(),
        role_lease_ids: inspection.role_lease_ids.clone(),
        work_item_ids: inspection.present_work_item_ids.clone(),
        operation_job_ids: inspection.present_operation_job_ids.clone(),
        staging_root: private_root.join("runtime").display().to_string(),
        published_root: String::new(),
        activated_at: None,
        published_at: None,
        abandoned_at: Some(OffsetDateTime::now_utc()),
        failure_ref: Some(private_relative_ref(&private_root, &abandoned_path)?),
    };
    write_seal_record(&private_root, &record)?;
    abandoned.recovery_state = SealRecoveryRecordState::Complete;
    abandoned.recovery_steps.push(SealRecoveryStep {
        step: "typed_abandonment_publication".to_owned(),
        outcome: "complete".to_owned(),
        detail: "generation-1 seal is Abandoned and generation 2 may be minted".to_owned(),
        recorded_at: OffsetDateTime::now_utc(),
    });
    crate::runtime_instance::atomic_write_json(&abandoned_path, &abandoned)?;
    let after = inspect_seal_recovery(config_path, run_id, &report_root, &private_root)?;
    ensure!(
        after.decision == SealRecoveryDecision::AlreadyAbandoned
            && after.provider_result_count == 0
            && after.provider_reservation_count == 0,
        "run006 recovery did not converge to an idempotent abandoned state"
    );
    print_json(&json!({
        "status": "seal_recovery_applied",
        "decision": "ABANDON_AND_REVOKE_SAFE_PREDISPATCH",
        "run_id": run_id,
        "generation": 1,
        "replacement_generation": 2,
        "quarantine_manifest": private_relative_ref(&private_root, &manifest_path)?,
        "quarantined_files": manifest.entries.len(),
        "provider_calls": 0,
    }))
}

#[allow(clippy::too_many_lines)]
pub async fn execute_provider(
    config_path: &Path,
    report_root: &Path,
    private_root: &Path,
    call_id: &str,
) -> Result<()> {
    let report_root = canonical_directory(report_root, "cognitive report root")?;
    let private_root = canonical_directory(private_root, "private certification root")?;
    ensure!(safe_segment(call_id), "provider call ID is unsafe");
    let receipt_path = private_root
        .join("receipts")
        .join(format!("provider-{call_id}.json"));
    if receipt_path.is_file() {
        return record_provider(&report_root, &private_root, &receipt_path);
    }
    let contract: CognitiveFieldRunContract = read_json(&report_root.join("contract.json"))?;
    let plan: CognitiveFieldProviderPlan = read_json(&report_root.join("provider-plan.json"))?;
    validate_report_roots(&contract, &report_root, &private_root)?;
    validate_provider_plan_hash(&plan)?;
    let seal_attempt_id = plan
        .seal_attempt_id
        .as_deref()
        .context("provider plan has no transactional seal attempt binding")?;
    let seal_record: ProviderPlanSealRecord =
        read_json(&seal_record_path(&private_root, seal_attempt_id))?;
    let provider_plan_sha256 = sha256_bytes(&encode_pretty_json(&plan)?);
    ensure!(
        seal_record.state == ProviderPlanSealState::Published
            && seal_record.generation == plan.seal_generation
            && seal_record.provider_plan_sha256.as_deref() == Some(provider_plan_sha256.as_str()),
        "provider dispatch is fenced until the transactional seal is Published"
    );
    let call = plan
        .calls
        .iter()
        .find(|call| call.call_id == call_id)
        .with_context(|| format!("provider call {call_id} is absent from the sealed plan"))?;
    ensure!(
        call.host != AgentHostId::Codex && call.role == CognitiveFieldRole::UnderstandingReader,
        "execute-provider accepts only external UnderstandingReader calls"
    );
    let runtime = provider_runtime_contract(&private_root, call)?;
    let ProviderRuntimeBinding::Current(sealed_runtime) = runtime else {
        bail!("external cognitive call does not use the current provider runtime contract");
    };
    let sealed_runtime = *sealed_runtime;
    let request_path = private_relative_file(
        &private_root,
        &call.execution_request_ref,
        "external execution request",
    )?;
    let execution: ExternalAgentExecutionRequest = read_json(&request_path)?;
    validate_external_agent_execution_request(&execution)?;
    let preview =
        crate::host_runtime::prepare_external_agent_runtime(config_path, call.host, &execution)?;
    ensure!(
        preview.adapter_id == call.adapter_id
            && preview.adapter_version == call.adapter_version
            && preview.runtime_contract == sealed_runtime,
        "production adapter preview differs from the sealed cognitive runtime"
    );
    let agent_session_id = execution
        .launch_contract
        .agent_session_id
        .context("external cognitive request has no AgentSession")?;
    let adapter_request = AdapterRequest {
        request_id: format!("cognitive-field-adapter:{call_id}"),
        adapter_id: call.adapter_id.clone(),
        requested_capability: AdapterCapability::EmitCandidateObservation,
        context: AdapterContext {
            project_id: execution.invocation.project_id,
            task_id: execution.invocation.task_id,
            session_id: Some(agent_session_id),
            trace_id: format!("cognitive-field:{}:{call_id}", contract.run_id),
            created_at: OffsetDateTime::now_utc(),
            role_lease_id: Some(execution.invocation.role_lease_id.clone()),
            role_lease_epoch: Some(execution.invocation.role_lease_epoch),
            operation_generation: Some(execution.invocation.operation_generation),
            runtime_contract_sha256: Some(call.runtime_contract_sha256.clone()),
        },
        input: serde_json::to_value(&execution)?,
    };
    let supervisor = crate::host_runtime::production_external_agent_supervisor(config_path)?;
    let result = supervisor
        .execute(&call.adapter_id, adapter_request, None)
        .await?;
    ensure!(
        result.status == AdapterResultStatus::Succeeded,
        "production provider adapter failed: {}",
        serde_json::to_string(&result)?
    );
    let evidence: ProviderExecutionEvidence = serde_json::from_value(
        result
            .output
            .get("provider_execution_evidence")
            .cloned()
            .context("adapter result has no ProviderExecutionEvidence")?,
    )?;
    let observed_runtime: ProviderRuntimeContract = serde_json::from_value(
        result
            .output
            .get("provider_runtime_contract")
            .cloned()
            .context("adapter result has no ProviderRuntimeContract")?,
    )?;
    ensure!(
        observed_runtime == sealed_runtime
            && evidence.runtime_contract_sha256 == call.runtime_contract_sha256
            && evidence.requested_model == call.requested_model
            && evidence.resolved_model == call.requested_model
            && evidence.exit_code == Some(0)
            && !evidence.unknown_outcome,
        "adapter execution evidence differs from the sealed cognitive call"
    );
    let invocation_root = private_root.join("provider-invocations").join(call_id);
    fs::create_dir_all(&invocation_root)?;
    let stdout = copy_external_agent_blob(
        config_path,
        evidence.stdout_ref.as_deref(),
        evidence.stdout_sha256.as_deref(),
        &invocation_root.join("stdout.bin"),
        "provider stdout",
    )?;
    let stderr = copy_external_agent_blob(
        config_path,
        evidence.stderr_ref.as_deref(),
        evidence.stderr_sha256.as_deref(),
        &invocation_root.join("stderr.bin"),
        "provider stderr",
    )?;
    let structured = copy_external_agent_blob(
        config_path,
        evidence.structured_output_ref.as_deref(),
        evidence.structured_output_sha256.as_deref(),
        &invocation_root.join("structured.json"),
        "provider structured output",
    )?;
    let structured_value: Value = serde_json::from_slice(&structured)?;
    ensure!(
        evidence.structured_output.as_ref() == Some(&structured_value),
        "adapter structured spool differs from the parsed provider value"
    );
    let execution_key = call
        .executions
        .first()
        .context("external provider call has no execution")?
        .clone();
    let mut observed_servers = evidence.observed_mcp_server_names.clone();
    observed_servers.sort();
    observed_servers.dedup();
    let mut observed_tools = evidence.observed_mcp_tool_names.clone();
    observed_tools.sort();
    observed_tools.dedup();
    let receipt = CognitiveFieldProviderEvidenceReceipt {
        schema_version: COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION.to_owned(),
        run_id: contract.run_id.clone(),
        contract_hash: contract.contract_hash.clone(),
        provider_plan_hash: plan.plan_hash.clone(),
        source_commit: contract.source_commit.clone(),
        call_id: call.call_id.clone(),
        role: call.role,
        host: call.host,
        requested_model: call.requested_model.clone(),
        resolved_model: evidence.resolved_model,
        provider_session_id: evidence.provider_session_id,
        provider_receipt_ref: format!("external-agent-result:{}", result.result_id),
        provider_executable: sealed_runtime.provider_executable,
        provider_executable_sha256: sealed_runtime.provider_executable_sha256,
        prompt_path: call.prompt_ref.clone(),
        prompt_sha256: call.prompt_sha256.clone(),
        raw_stdout_path: private_relative_ref(&private_root, &invocation_root.join("stdout.bin"))?,
        raw_stdout_sha256: sha256_bytes(&stdout),
        raw_stderr_path: private_relative_ref(&private_root, &invocation_root.join("stderr.bin"))?,
        raw_stderr_sha256: sha256_bytes(&stderr),
        outputs: vec![CognitiveFieldProviderOutputReceipt {
            execution: execution_key,
            output_path: private_relative_ref(
                &private_root,
                &invocation_root.join("structured.json"),
            )?,
            output_sha256: sha256_bytes(&structured),
        }],
        provider_calls: 1,
        exit_code: evidence.exit_code.unwrap_or(-1),
        elapsed_ms: evidence.duration_ms,
        timed_out: evidence.terminal_status == "timeout",
        unknown_outcome: evidence.unknown_outcome,
        controller_substitution: false,
        oracle_exposed: false,
        worker_transcript_exposed: false,
        read_only: true,
        runtime_contract_sha256: evidence.runtime_contract_sha256,
        observed_mcp_server_names: observed_servers,
        observed_mcp_tool_names: observed_tools,
    };
    write_new_or_same_json(&receipt_path, &receipt)?;
    record_provider(&report_root, &private_root, &receipt_path)
}

fn copy_external_agent_blob(
    config_path: &Path,
    reference: Option<&str>,
    expected_sha256: Option<&str>,
    target: &Path,
    label: &str,
) -> Result<Vec<u8>> {
    let reference = reference.with_context(|| format!("{label} reference is absent"))?;
    let expected_sha256 = expected_sha256.with_context(|| format!("{label} SHA-256 is absent"))?;
    let source = crate::host_runtime::external_agent_blob_path(config_path, reference)?;
    let bytes = fs::read(source)?;
    ensure!(
        sha256_bytes(&bytes) == expected_sha256,
        "{label} differs from AdapterSupervisor evidence"
    );
    write_new_or_same(target, &bytes)?;
    Ok(bytes)
}

#[allow(clippy::too_many_lines)]
pub fn record_provider(report_root: &Path, private_root: &Path, receipt_path: &Path) -> Result<()> {
    let report_root = canonical_directory(report_root, "cognitive report root")?;
    let private_root = canonical_directory(private_root, "private certification root")?;
    let receipt_path = fs::canonicalize(receipt_path)
        .with_context(|| format!("resolve provider receipt {}", receipt_path.display()))?;
    ensure!(
        receipt_path.starts_with(&private_root) && receipt_path.is_file(),
        "provider receipt must be a file inside the private certification root"
    );
    let suite: CognitiveFieldSuite = read_json(&report_root.join("suite.json"))?;
    let contract: CognitiveFieldRunContract = read_json(&report_root.join("contract.json"))?;
    let plan: CognitiveFieldProviderPlan = read_json(&report_root.join("provider-plan.json"))?;
    validate_report_roots(&contract, &report_root, &private_root)?;
    ensure!(
        git_commit(Path::new(&contract.primary_repository))? == contract.source_commit,
        "primary repository HEAD moved after the field contract was sealed"
    );
    validate_provider_plan_hash(&plan)?;
    let receipt_bytes = fs::read(&receipt_path)?;
    enforce_provider_secret_boundary("provider receipt", &receipt_bytes)?;
    let receipt: CognitiveFieldProviderEvidenceReceipt = serde_json::from_slice(&receipt_bytes)?;
    ensure!(
        receipt.schema_version == COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION,
        "provider evidence schema version is invalid"
    );
    ensure!(
        receipt.run_id == contract.run_id
            && receipt.contract_hash == contract.contract_hash
            && receipt.provider_plan_hash == plan.plan_hash
            && receipt.source_commit == contract.source_commit,
        "provider evidence differs from the sealed run authority"
    );
    let call = plan
        .calls
        .iter()
        .find(|call| call.call_id == receipt.call_id)
        .with_context(|| {
            format!(
                "provider call {} is not in the sealed plan",
                receipt.call_id
            )
        })?;
    validate_provider_receipt_envelope(call, &receipt, &private_root)?;
    let current_adapter_runtime = provider_runtime_contract(&private_root, call)?.is_current();

    let mut output_receipts = receipt
        .outputs
        .iter()
        .map(|output| (output.execution.clone(), output))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        output_receipts.len() == receipt.outputs.len()
            && output_receipts.keys().eq(call.executions.iter()),
        "provider outputs do not exactly match the sealed call executions"
    );

    let prompt_bytes = fs::read(private_file(
        &private_root,
        &receipt.prompt_path,
        &receipt.prompt_sha256,
        "provider prompt",
    )?)?;
    let raw_stdout = fs::read(private_file(
        &private_root,
        &receipt.raw_stdout_path,
        &receipt.raw_stdout_sha256,
        "provider stdout",
    )?)?;
    let raw_stderr = fs::read(private_file(
        &private_root,
        &receipt.raw_stderr_path,
        &receipt.raw_stderr_sha256,
        "provider stderr",
    )?)?;
    enforce_provider_secret_boundary("provider prompt", &prompt_bytes)?;
    enforce_provider_secret_boundary("provider stdout", &raw_stdout)?;
    enforce_provider_secret_boundary("provider stderr", &raw_stderr)?;
    let stdout_text = String::from_utf8_lossy(&raw_stdout);
    let mut required_stdout_attestations = vec![receipt.provider_session_id.as_str()];
    if !current_adapter_runtime {
        required_stdout_attestations.push(receipt.provider_receipt_ref.as_str());
    }
    if suite.harness_version != COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION
        || receipt.host != AgentHostId::Codex
    {
        required_stdout_attestations.push(receipt.resolved_model.as_str());
    }
    for required in required_stdout_attestations {
        ensure!(
            stdout_text.contains(required),
            "provider stdout does not attest the exact model/session/receipt identity"
        );
    }

    let mut admitted = Vec::with_capacity(call.executions.len());
    for execution in &call.executions {
        let output = output_receipts
            .remove(execution)
            .context("sealed provider output is missing")?;
        let output_path = private_file(
            &private_root,
            &output.output_path,
            &output.output_sha256,
            "provider structured output",
        )?;
        let bytes = fs::read(&output_path)?;
        enforce_provider_secret_boundary("provider structured output", &bytes)?;
        let evidence_root = report_root
            .join("evidence")
            .join(&execution.case_id)
            .join(condition_name(execution.memory_condition));
        let deterministic: CognitiveDeterministicReport =
            read_json(&evidence_root.join("deterministic.json"))?;
        ensure!(
            deterministic_report_is_valid(&deterministic)?,
            "provider output is bound to invalid deterministic evidence"
        );
        let case = suite
            .cases
            .iter()
            .find(|case| case.case_id == execution.case_id)
            .context("provider output case is absent from the suite")?;
        let oracle: TaskIntentOracle = read_json(
            &private_root
                .join("oracles")
                .join(format!("{}.json", case.case_id)),
        )?;
        if receipt.role != CognitiveFieldRole::CodexJudge {
            let leak = CognitiveFieldGradingService::scan_reader_surfaces(
                &oracle,
                &[
                    ("provider-prompt".to_owned(), prompt_bytes.clone()),
                    ("provider-stdout".to_owned(), raw_stdout.clone()),
                    ("provider-output".to_owned(), bytes.clone()),
                ],
            );
            ensure!(
                leak.clean,
                "Worker/Reader provider surface contains private oracle values"
            );
        }
        let (target_name, reader_binding) = match receipt.role {
            CognitiveFieldRole::CodexWorker => {
                let worker: CognitiveWorkerResult = serde_json::from_slice(&bytes)?;
                validate_worker_output(&worker, execution, case, &deterministic)?;
                ("worker.json", None)
            }
            CognitiveFieldRole::UnderstandingReader => {
                let value: Value = serde_json::from_slice(&bytes)?;
                let canonical_schema = cognitive_understanding_answer_schema();
                let provider_schema = provider_compatible_reader_schema(&canonical_schema)?;
                validate_json_schema_instance(
                    &provider_schema,
                    &value,
                    "Reader provider-compatible output",
                )?;
                validate_json_schema_instance(
                    &canonical_schema,
                    &value,
                    "Reader canonical output",
                )?;
                let reader: CognitiveUnderstandingAnswer = serde_json::from_value(value)?;
                validate_reader_output(&reader, execution, &deterministic)?;
                (
                    "reader.json",
                    Some(json!({
                        "schema_version": "eliot-cognitive-reader-binding-v1",
                        "run_id": contract.run_id,
                        "source_commit": contract.source_commit,
                        "case_id": execution.case_id,
                        "memory_condition": condition_name(execution.memory_condition),
                        "reader_output_hash":
                            CognitiveFieldGradingService::hash_json(&reader)?,
                        "reader_output_sha256": output.output_sha256,
                    })),
                )
            }
            CognitiveFieldRole::CodexJudge => {
                let judge: CognitiveJudgeResult = serde_json::from_slice(&bytes)?;
                validate_judge_output(&judge, execution, &oracle, &deterministic)?;
                ("judge.json", None)
            }
        };
        admitted.push((
            evidence_root,
            target_name,
            bytes,
            output.output_sha256.clone(),
            reader_binding,
        ));
    }

    let invocation_path = report_root
        .join("provider-invocations")
        .join(format!("{}.json", call.call_id));
    let existing = invocation_path
        .is_file()
        .then(|| read_json::<CognitiveFieldProviderProjection>(&invocation_path))
        .transpose()?;
    let projection = CognitiveFieldProviderProjection {
        schema_version: COGNITIVE_FIELD_PROVIDER_PROJECTION_SCHEMA_VERSION.to_owned(),
        run_id: contract.run_id.clone(),
        contract_hash: contract.contract_hash.clone(),
        provider_plan_hash: plan.plan_hash.clone(),
        source_commit: contract.source_commit.clone(),
        call_id: call.call_id.clone(),
        role: call.role,
        host: call.host,
        requested_model: call.requested_model.clone(),
        resolved_model: receipt.resolved_model.clone(),
        provider_session_id: receipt.provider_session_id.clone(),
        provider_receipt_ref: receipt.provider_receipt_ref.clone(),
        provider_executable_sha256: receipt.provider_executable_sha256.clone(),
        prompt_sha256: receipt.prompt_sha256.clone(),
        raw_stdout_sha256: receipt.raw_stdout_sha256.clone(),
        raw_stderr_sha256: receipt.raw_stderr_sha256.clone(),
        outputs: call
            .executions
            .iter()
            .map(|execution| {
                let output_sha256 = receipt
                    .outputs
                    .iter()
                    .find(|output| output.execution == *execution)
                    .map(|output| output.output_sha256.clone())
                    .unwrap_or_default();
                CognitiveFieldProviderOutputProjection {
                    execution: execution.clone(),
                    output_sha256,
                }
            })
            .collect(),
        provider_smoke: call.provider_smoke,
        counts_against_cap: call.counts_against_cap,
        elapsed_ms: receipt.elapsed_ms,
        runtime_contract_sha256: receipt.runtime_contract_sha256.clone(),
        recorded_at: existing
            .as_ref()
            .map_or_else(OffsetDateTime::now_utc, |projection| projection.recorded_at),
    };
    if let Some(existing) = existing {
        ensure!(
            existing == projection,
            "provider invocation already exists with different evidence"
        );
    }
    write_new_or_same_json(&invocation_path, &projection)?;
    for (evidence_root, target_name, bytes, _, reader_binding) in &admitted {
        write_new_or_same(&evidence_root.join(target_name), bytes)?;
        if let Some(reader_binding) = reader_binding {
            write_new_or_same_json(&evidence_root.join("reader-binding.json"), reader_binding)?;
        }
        write_new_or_same_json(
            &evidence_root.join(format!("provider-{}.json", role_name(call.role))),
            &projection,
        )?;
    }
    print_json(&json!({
        "status": "provider_evidence_recorded",
        "run_id": contract.run_id,
        "call_id": call.call_id,
        "role": role_name(call.role),
        "host": call.host.as_str(),
        "resolved_model": receipt.resolved_model,
        "execution_count": admitted.len(),
        "counts_against_cap": call.counts_against_cap,
        "provider_smoke": call.provider_smoke,
    }))
}

#[allow(clippy::too_many_lines)]
pub fn grade(report_root: &Path, private_root: &Path) -> Result<()> {
    let report_root = canonical_directory(report_root, "cognitive report root")?;
    let private_root = canonical_directory(private_root, "private certification root")?;
    let suite: CognitiveFieldSuite = read_json(&report_root.join("suite.json"))?;
    let contract: CognitiveFieldRunContract = read_json(&report_root.join("contract.json"))?;
    let validation = CognitiveFieldGradingService::validate_suite(&suite);
    ensure!(
        validation.valid,
        "stored suite is invalid: {}",
        validation.errors.join("; ")
    );
    validate_report_roots(&contract, &report_root, &private_root)?;
    let provider_plan = report_root
        .join("provider-plan.json")
        .is_file()
        .then(|| read_json::<CognitiveFieldProviderPlan>(&report_root.join("provider-plan.json")))
        .transpose()?;
    let role_plan = if let Some(plan) = &provider_plan {
        validate_provider_plan_hash(plan)?;
        ensure!(
            plan.run_id == contract.run_id && plan.contract_hash == contract.contract_hash,
            "provider plan differs from the sealed run contract"
        );
        let role_plan = plan
            .role_evidence_plan_hash
            .as_ref()
            .map(|expected_hash| {
                let role_plan: CoreRoleEvidencePlan =
                    read_json(&report_root.join("role-evidence-plan.json"))?;
                ensure!(
                    role_plan.plan_hash == *expected_hash
                        && role_plan.run_id == contract.run_id
                        && role_plan.schema_version == CORE_ROLE_EVIDENCE_PLAN_SCHEMA_VERSION,
                    "role evidence plan differs from the sealed provider plan"
                );
                let mut material = role_plan.clone();
                material.plan_hash.clear();
                ensure!(
                    CognitiveFieldGradingService::hash_json(&material)? == role_plan.plan_hash,
                    "role evidence plan hash is invalid"
                );
                Ok::<_, anyhow::Error>(role_plan)
            })
            .transpose()?;
        let role_sources = role_plan
            .as_ref()
            .map_or(&[][..], |role_plan| role_plan.sources.as_slice());
        let (capped, smokes) =
            validate_provider_calls_with_sources(&suite, &plan.calls, &private_root, role_sources)?;
        let reused = u8::try_from(prior_role_sources(role_sources).count())
            .context("reused role count exceeds u8")?;
        ensure!(
            capped == plan.planned_provider_calls
                && smokes == plan.planned_smoke_calls
                && reused == plan.planned_reused_roles,
            "provider plan summary counts are invalid"
        );
        role_plan
    } else {
        None
    };
    let provider_invocations = load_provider_projections(&report_root)?;
    let actual_provider_calls = provider_invocations
        .values()
        .filter(|projection| projection.counts_against_cap)
        .count();
    let actual_smoke_calls = provider_invocations
        .values()
        .filter(|projection| projection.provider_smoke)
        .count();
    let provider_plan_complete = provider_plan.as_ref().is_some_and(|plan| {
        let planned = plan
            .calls
            .iter()
            .map(|call| call.call_id.as_str())
            .collect::<BTreeSet<_>>();
        let recorded = provider_invocations
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        planned == recorded
            && actual_provider_calls == usize::from(plan.planned_provider_calls)
            && actual_smoke_calls == usize::from(plan.planned_smoke_calls)
            && plan.planned_reused_roles <= 1
            && actual_provider_calls <= usize::from(contract.hard_provider_call_cap)
    });

    let mut deterministic_results = Vec::new();
    let mut judge_results = Vec::new();
    let mut expected_executions = 0usize;
    let mut passed_executions = 0usize;
    let mut missing_executions = 0usize;
    let mut semantic_scores = Vec::new();
    for case in &suite.cases {
        let conditions = execution_conditions(case);
        for condition in conditions {
            expected_executions = expected_executions.saturating_add(1);
            let condition_name = condition_name(condition);
            let evidence_root = report_root
                .join("evidence")
                .join(&case.case_id)
                .join(condition_name);
            let deterministic_path = evidence_root.join("deterministic.json");
            if !deterministic_path.is_file() {
                missing_executions = missing_executions.saturating_add(1);
                deterministic_results.push(json!({
                    "case_id": case.case_id,
                    "memory_condition": condition_name,
                    "status": "not_run",
                }));
                continue;
            }
            let deterministic: CognitiveDeterministicReport = read_json(&deterministic_path)?;
            let deterministic_valid = deterministic_report_is_valid(&deterministic)?;
            deterministic_results.push(json!({
                "case_id": case.case_id,
                "memory_condition": condition_name,
                "status": if deterministic_valid { "passed" } else { "failed" },
                "report_hash": deterministic.report_hash,
                "verifier_refs": deterministic.verifier_refs,
            }));
            if !case.model_backed {
                if deterministic_valid {
                    passed_executions = passed_executions.saturating_add(1);
                }
                continue;
            }
            let worker_path = evidence_root.join("worker.json");
            let reader_path = evidence_root.join("reader.json");
            let judge_path = evidence_root.join("judge.json");
            if provider_plan.is_none()
                || !worker_path.is_file()
                || !reader_path.is_file()
                || !judge_path.is_file()
            {
                missing_executions = missing_executions.saturating_add(1);
                judge_results.push(json!({
                    "case_id": case.case_id,
                    "memory_condition": condition_name,
                    "status": "not_run",
                    "reason": "sealed Worker/Reader/Judge provider evidence is incomplete",
                }));
                continue;
            }
            let execution = CognitiveFieldExecutionKey {
                case_id: case.case_id.clone(),
                memory_condition: condition,
            };
            let provider_errors = provider_role_errors(
                provider_plan
                    .as_ref()
                    .context("provider plan disappeared")?,
                role_plan.as_ref(),
                &provider_invocations,
                &evidence_root,
                &execution,
            )?;
            if !provider_errors.is_empty() {
                judge_results.push(json!({
                    "case_id": case.case_id,
                    "memory_condition": condition_name,
                    "status": "failed",
                    "provider_role_errors": provider_errors,
                }));
                continue;
            }
            let worker: CognitiveWorkerResult = read_json(&worker_path)?;
            let reader: CognitiveUnderstandingAnswer = read_json(&reader_path)?;
            let judge: CognitiveJudgeResult = read_json(&judge_path)?;
            let oracle: TaskIntentOracle = read_json(
                &private_root
                    .join("oracles")
                    .join(format!("{}.json", case.case_id)),
            )?;
            validate_worker_output(&worker, &execution, case, &deterministic)?;
            validate_reader_output(&reader, &execution, &deterministic)?;
            validate_judge_output(&judge, &execution, &oracle, &deterministic)?;
            let grade = CognitiveFieldGradingService::grade_case(
                &suite,
                case,
                &oracle,
                &reader,
                &deterministic,
                &judge,
            );
            if grade.passed {
                passed_executions = passed_executions.saturating_add(1);
            }
            semantic_scores.push(grade.semantic_average_milli);
            judge_results.push(json!({
                "case_id": case.case_id,
                "memory_condition": condition_name,
                "status": if grade.passed { "passed" } else { "failed" },
                "grade": grade,
            }));
        }
    }

    let all_passed = missing_executions == 0
        && passed_executions == expected_executions
        && expected_executions > 0
        && provider_plan_complete;
    let median_semantic_milli = median(&mut semantic_scores);
    let status = if all_passed {
        "COGNITIVE_FIELD_CERTIFIED_INTERNAL_RC"
    } else {
        "MECHANISMS_COMPLETE_FIELD_CERTIFICATION_BLOCKED"
    };
    let metrics = json!({
        "schema_version": "eliot-cognitive-field-metrics-v1",
        "run_id": contract.run_id,
        "expected_executions": expected_executions,
        "passed_executions": passed_executions,
        "missing_executions": missing_executions,
        "median_semantic_milli": median_semantic_milli,
        "provider_call_cap": contract.hard_provider_call_cap,
        "provider_plan_sealed": provider_plan.is_some(),
        "provider_plan_complete": provider_plan_complete,
        "actual_provider_calls": actual_provider_calls,
        "actual_smoke_calls": actual_smoke_calls,
        "reused_provider_roles": provider_plan
            .as_ref()
            .map_or(0, |plan| plan.planned_reused_roles),
        "status": status,
    });
    crate::runtime_instance::atomic_write_json(
        &report_root.join("deterministic-results.json"),
        &deterministic_results,
    )?;
    crate::runtime_instance::atomic_write_json(
        &report_root.join("judge-results.json"),
        &judge_results,
    )?;
    crate::runtime_instance::atomic_write_json(&report_root.join("metrics.json"), &metrics)?;
    let markdown = render_report(
        &contract,
        status,
        expected_executions,
        passed_executions,
        missing_executions,
        median_semantic_milli,
        actual_provider_calls,
        actual_smoke_calls,
        provider_plan_complete,
    );
    crate::runtime_instance::atomic_write_bytes(
        &report_root.join("report.md"),
        markdown.as_bytes(),
    )?;
    print_json(&metrics)?;
    ensure!(all_passed, "cognitive field certification is incomplete");
    Ok(())
}

fn load_provider_projections(
    report_root: &Path,
) -> Result<BTreeMap<String, CognitiveFieldProviderProjection>> {
    let root = report_root.join("provider-invocations");
    if !root.is_dir() {
        return Ok(BTreeMap::new());
    }
    let mut projections = BTreeMap::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        ensure!(
            path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("json"),
            "provider invocation registry contains a non-JSON entry"
        );
        let projection: CognitiveFieldProviderProjection = read_json(&path)?;
        ensure!(
            projection.schema_version == COGNITIVE_FIELD_PROVIDER_PROJECTION_SCHEMA_VERSION
                && safe_segment(&projection.call_id)
                && projections
                    .insert(projection.call_id.clone(), projection)
                    .is_none(),
            "provider invocation registry contains invalid or duplicate evidence"
        );
    }
    Ok(projections)
}

#[allow(clippy::too_many_lines)]
fn provider_role_errors(
    plan: &CognitiveFieldProviderPlan,
    role_plan: Option<&CoreRoleEvidencePlan>,
    invocations: &BTreeMap<String, CognitiveFieldProviderProjection>,
    evidence_root: &Path,
    execution: &CognitiveFieldExecutionKey,
) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    let mut sessions = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    for role in [
        CognitiveFieldRole::CodexWorker,
        CognitiveFieldRole::UnderstandingReader,
        CognitiveFieldRole::CodexJudge,
    ] {
        let target = evidence_root.join(match role {
            CognitiveFieldRole::CodexWorker => "worker.json",
            CognitiveFieldRole::UnderstandingReader => "reader.json",
            CognitiveFieldRole::CodexJudge => "judge.json",
        });
        let reuse_path = evidence_root.join("reused-roles.json");
        if reuse_path.is_file() {
            let projections: Vec<CoreRoleReuseProjection> = read_json(&reuse_path)?;
            if let Some(projection) = projections.into_iter().find(|projection| {
                projection.role == role
                    && projection
                        .outputs
                        .iter()
                        .any(|output| output.execution == *execution)
            }) {
                let output = projection
                    .outputs
                    .iter()
                    .find(|output| output.execution == *execution);
                let output_hash_matches = output.is_some_and(|output| {
                    target
                        .is_file()
                        .then(|| fs::read(&target).ok())
                        .flatten()
                        .is_some_and(|bytes| sha256_bytes(&bytes) == output.output_sha256)
                });
                let source_matches = role_plan.is_some_and(|role_plan| {
                    prior_role_sources(&role_plan.sources).any(|source| {
                        let CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
                            source_run_id,
                            source_call_id,
                            role,
                            case_id,
                            provider_session_id,
                            provider_executable_sha256,
                            output_schema_sha256,
                            artifact_sha256,
                            prompt_sha256,
                            oracle_sha256,
                            runtime_contract_sha256,
                            input_artifact_sha256s,
                            deterministic_report_sha256s,
                            executions,
                            provider_receipt_ref,
                            deterministic_receipt_refs,
                            contamination_receipt_ref,
                            worktree_diff_sha256,
                            ..
                        } = source
                        else {
                            return false;
                        };
                        projection.source_run_id == *source_run_id
                            && projection.source_call_id == *source_call_id
                            && projection.role == *role
                            && projection.case_id == *case_id
                            && projection.provider_session_id == *provider_session_id
                            && projection.provider_executable_sha256 == *provider_executable_sha256
                            && projection.output_schema_sha256 == *output_schema_sha256
                            && projection.artifact_sha256 == *artifact_sha256
                            && projection.prompt_sha256 == *prompt_sha256
                            && projection.oracle_sha256 == *oracle_sha256
                            && projection.runtime_contract_sha256 == *runtime_contract_sha256
                            && projection.input_artifact_sha256s == *input_artifact_sha256s
                            && projection.deterministic_report_sha256s
                                == *deterministic_report_sha256s
                            && projection.executions == *executions
                            && projection.provider_receipt_ref == *provider_receipt_ref
                            && projection.deterministic_receipt_refs == *deterministic_receipt_refs
                            && projection.contamination_receipt_ref == *contamination_receipt_ref
                            && projection.worktree_diff_sha256 == *worktree_diff_sha256
                    })
                });
                if projection.schema_version != CORE_ROLE_REUSE_PROJECTION_SCHEMA_VERSION
                    || projection.run_id != plan.run_id
                    || projection.contract_hash != plan.contract_hash
                    || projection.provider_plan_hash != plan.plan_hash
                    || projection.case_id != execution.case_id
                    || plan.planned_reused_roles != 4
                    || plan.role_evidence_plan_hash.is_none()
                    || !source_matches
                    || !output_hash_matches
                    || evidence_root
                        .join(format!("provider-{}.json", role_name(role)))
                        .is_file()
                {
                    errors.push(format!(
                        "{} reuse projection failed its plan/session/output binding",
                        role_name(role)
                    ));
                }
                sessions.insert(projection.provider_session_id);
                receipts.insert(projection.provider_receipt_ref);
                continue;
            }
        }
        let projection_path = evidence_root.join(format!("provider-{}.json", role_name(role)));
        if !projection_path.is_file() {
            errors.push(format!(
                "{} provider projection is missing",
                role_name(role)
            ));
            continue;
        }
        let projection: CognitiveFieldProviderProjection = read_json(&projection_path)?;
        let Some(call) = plan
            .calls
            .iter()
            .find(|call| call.call_id == projection.call_id)
        else {
            errors.push(format!(
                "{} projection references an unplanned call",
                role_name(role)
            ));
            continue;
        };
        let registered = invocations.get(&projection.call_id);
        let output = projection
            .outputs
            .iter()
            .find(|output| output.execution == *execution);
        let output_hash_matches = output.is_some_and(|output| {
            target
                .is_file()
                .then(|| fs::read(&target).ok())
                .flatten()
                .is_some_and(|bytes| sha256_bytes(&bytes) == output.output_sha256)
        });
        if projection.schema_version != COGNITIVE_FIELD_PROVIDER_PROJECTION_SCHEMA_VERSION
            || projection.provider_plan_hash != plan.plan_hash
            || projection.role != role
            || call.role != role
            || call.host != projection.host
            || call.requested_model != projection.requested_model
            || projection.requested_model != projection.resolved_model
            || !call.executions.contains(execution)
            || registered != Some(&projection)
            || !output_hash_matches
        {
            errors.push(format!(
                "{} provider projection failed its plan/session/output binding",
                role_name(role)
            ));
        }
        sessions.insert(projection.provider_session_id.clone());
        receipts.insert(projection.provider_receipt_ref.clone());
    }
    if sessions.len() != 3 {
        errors
            .push("Worker, Reader, and Judge must use three distinct provider sessions".to_owned());
    }
    if receipts.len() != 3 {
        errors.push(
            "Worker, Reader, and Judge must have three distinct provider receipts".to_owned(),
        );
    }
    Ok(errors)
}

fn load_and_validate_suite(
    suite_path: &Path,
) -> Result<(CognitiveFieldSuite, CognitiveFieldValidationReport, Vec<u8>)> {
    let suite_bytes =
        fs::read(suite_path).with_context(|| format!("read {}", suite_path.display()))?;
    let suite: CognitiveFieldSuite = serde_json::from_slice(&suite_bytes)?;
    let mut report = CognitiveFieldGradingService::validate_suite(&suite);
    let suite_root = suite_path
        .parent()
        .context("field suite path has no parent")?;
    let reader_schema = cognitive_understanding_answer_schema();
    validate_schema_asset(
        &mut report,
        &suite_root.join(&suite.reader_output_schema_ref),
        &reader_schema,
        "reader",
    );
    let judge_schema = cognitive_judge_result_schema()?;
    validate_schema_asset(
        &mut report,
        &suite_root.join(&suite.judge_output_schema_ref),
        &judge_schema,
        "judge",
    );
    if !suite_root.join("contamination-rules.json").is_file() {
        report
            .errors
            .push("contamination-rules.json is missing".to_owned());
    }
    if !suite_root.join("templates/worker-prompt.txt").is_file() {
        report.errors.push("worker prompt is missing".to_owned());
    }
    for case in &suite.cases {
        if !suite_root.join(&case.reader_prompt_ref).is_file() {
            report.errors.push(format!(
                "reader prompt for {} does not exist: {}",
                case.case_id, case.reader_prompt_ref
            ));
        }
    }
    report.valid = report.errors.is_empty();
    Ok((suite, report, suite_bytes))
}

fn validate_schema_asset(
    report: &mut CognitiveFieldValidationReport,
    path: &Path,
    generated: &Value,
    kind: &str,
) {
    let checked_in = fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let Some(checked_in) = checked_in else {
        report
            .errors
            .push(format!("{kind} output schema is missing or invalid"));
        return;
    };
    let differs = if kind == "reader" {
        checked_in != *generated
    } else {
        required_set(&checked_in) != required_set(generated)
    };
    if differs {
        report.errors.push(format!(
            "{kind} output schema differs from the Rust-derived contract"
        ));
    }
}

fn required_set(value: &Value) -> BTreeSet<String> {
    value
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn generated_oracle(
    case: &CognitiveFieldCase,
    case_index: usize,
    contract: &CognitiveFieldRunContract,
    suite_bytes: &[u8],
) -> TaskIntentOracle {
    let private_ref = |kind: &str| {
        format!(
            "private-{kind}:{}",
            sha256_bytes(
                format!(
                    "{}:{}:{kind}:{}",
                    contract.run_id,
                    case.case_id,
                    sha256_bytes(suite_bytes)
                )
                .as_bytes()
            )
        )
    };
    let private_marker = format!(
        "PRIVATE-ORACLE-{}",
        sha256_bytes(format!("{}:{}", contract.run_id, case.case_id).as_bytes())
    );
    TaskIntentOracle {
        schema_version: COGNITIVE_FIELD_ORACLE_SCHEMA_VERSION.to_owned(),
        oracle_id: format!("oracle:{}:{}", contract.run_id, case.case_id),
        exact_user_prompt_hash: sha256_bytes(case.title.as_bytes()),
        exact_user_prompt_ref: format!("suite.json#/cases/{case_index}/title"),
        source_commit: contract.source_commit.clone(),
        normalized_goal: case.title.clone(),
        desired_state: vec![format!("{} is satisfied with current evidence", case.title)],
        acceptance_items: vec![private_ref("acceptance")],
        non_goals: vec![
            "Do not substitute controller output for a provider role".to_owned(),
            "Do not promote candidate-only evidence to current truth".to_owned(),
        ],
        architecture_constraints: vec![
            "Current source and deterministic verifier evidence outrank memory".to_owned(),
            "Worker, Reader, and Judge sessions remain isolated".to_owned(),
        ],
        expected_subsystem_set: vec![private_ref("subsystem")],
        acceptable_owner_file_symbol_alternatives: vec![private_ref("owner-alternative")],
        required_invariant_refs: vec![private_ref("invariant")],
        required_verifier_refs: vec![private_ref("verifier")],
        forbidden_conclusions: vec![private_marker],
        authoritative_source_refs: vec![
            format!("git:{}", contract.source_commit),
            format!("suite:{}", case.case_id),
        ],
        oracle_hash: String::new(),
    }
}

fn git_history(repository: &Path) -> Result<Vec<u8>> {
    const MAX_HISTORY_BYTES: usize = 64 * 1024 * 1024;
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["log", "--all", "-p", "--no-ext-diff", "--no-textconv"])
        .output()
        .context("read fixture repository Git history for contamination scan")?;
    ensure!(
        output.status.success(),
        "fixture repository Git history scan command failed"
    );
    ensure!(
        output.stdout.len() <= MAX_HISTORY_BYTES,
        "fixture repository Git history exceeds the bounded contamination-scan surface"
    );
    Ok(output.stdout)
}

fn provider_environment_surface() -> Vec<u8> {
    let mut entries = std::env::vars_os()
        .map(|(key, value)| {
            let key = key.to_string_lossy();
            let upper = key.to_ascii_uppercase();
            let sensitive = ["TOKEN", "PASSWORD", "SECRET", "COOKIE", "AUTH", "API_KEY"]
                .iter()
                .any(|marker| upper.contains(marker));
            if sensitive {
                format!("{key}=<redacted>")
            } else {
                format!("{key}={}", value.to_string_lossy())
            }
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries.join("\n").into_bytes()
}

fn execution_conditions(case: &CognitiveFieldCase) -> Vec<CognitiveMemoryCondition> {
    if case.model_backed {
        return case.memory_conditions.clone();
    }
    case.memory_conditions
        .first()
        .copied()
        .into_iter()
        .collect()
}

fn condition_name(condition: CognitiveMemoryCondition) -> &'static str {
    match condition {
        CognitiveMemoryCondition::Treatment => "treatment",
        CognitiveMemoryCondition::MemoryFreeControl => "memory_free_control",
        CognitiveMemoryCondition::RawCorpus => "raw_corpus",
        CognitiveMemoryCondition::DistilledCorpus => "distilled_corpus",
    }
}

fn parse_condition(value: &str) -> Result<CognitiveMemoryCondition> {
    match value.trim().to_ascii_lowercase().as_str() {
        "treatment" => Ok(CognitiveMemoryCondition::Treatment),
        "memory_free_control" => Ok(CognitiveMemoryCondition::MemoryFreeControl),
        "raw_corpus" => Ok(CognitiveMemoryCondition::RawCorpus),
        "distilled_corpus" => Ok(CognitiveMemoryCondition::DistilledCorpus),
        other => bail!("unsupported cognitive memory condition {other}"),
    }
}

fn role_name(role: CognitiveFieldRole) -> &'static str {
    match role {
        CognitiveFieldRole::CodexWorker => "worker",
        CognitiveFieldRole::UnderstandingReader => "reader",
        CognitiveFieldRole::CodexJudge => "judge",
    }
}

fn enforce_provider_secret_boundary(label: &str, bytes: &[u8]) -> Result<()> {
    inspect_secret_bytes(bytes)
        .map_err(|violation| anyhow::anyhow!("{label} failed secret boundary: {violation}"))
}

fn validate_report_roots(
    contract: &CognitiveFieldRunContract,
    report_root: &Path,
    private_root: &Path,
) -> Result<()> {
    ensure!(
        contract_path_matches(report_root, &contract.output_root),
        "report root differs from the sealed contract"
    );
    ensure!(
        contract_private_root_matches(private_root, &contract.private_root_sha256),
        "private certification root does not match the sealed contract"
    );
    Ok(())
}

fn ensure_deterministic_evidence_complete(
    suite: &CognitiveFieldSuite,
    report_root: &Path,
) -> Result<()> {
    for case in &suite.cases {
        for condition in execution_conditions(case) {
            let path = report_root
                .join("evidence")
                .join(&case.case_id)
                .join(condition_name(condition))
                .join("deterministic.json");
            ensure!(
                path.is_file(),
                "deterministic evidence is incomplete; missing {}",
                path.display()
            );
            let report: CognitiveDeterministicReport = read_json(&path)?;
            ensure!(
                deterministic_report_is_valid(&report)?,
                "deterministic evidence is invalid for {}",
                case.case_id
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[cfg(test)]
fn validate_provider_calls(
    suite: &CognitiveFieldSuite,
    calls: &[CognitiveFieldProviderCallPlan],
    private_root: &Path,
) -> Result<(u8, u8)> {
    validate_provider_calls_with_sources(suite, calls, private_root, &[])
}

fn provider_runtime_contract(
    private_root: &Path,
    call: &CognitiveFieldProviderCallPlan,
) -> Result<ProviderRuntimeBinding> {
    ensure!(
        !call.runtime_contract_ref.trim().is_empty() && is_sha256(&call.runtime_contract_sha256),
        "new provider calls require a sealed runtime contract reference and SHA-256"
    );
    let path = private_relative_file(
        private_root,
        &call.runtime_contract_ref,
        "provider runtime contract",
    )?;
    let value: Value = read_json(&path)?;
    let schema_version = value
        .get("schema_version")
        .and_then(Value::as_str)
        .context("provider runtime contract has no schema version")?;
    let binding = if schema_version == eliot_types::PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION {
        let contract: ProviderRuntimeContract = serde_json::from_value(value)?;
        validate_provider_runtime_contract(&contract)?;
        ProviderRuntimeBinding::Current(Box::new(contract))
    } else {
        let contract: CognitiveProviderRuntimeContract = serde_json::from_value(value)?;
        validate_runtime_contract(&contract)?;
        ProviderRuntimeBinding::Legacy(Box::new(contract))
    };
    ensure!(
        binding.runtime_contract_sha256() == call.runtime_contract_sha256
            && binding.host() == call.host
            && binding.provider_executable_sha256() == call.expected_provider_executable_sha256,
        "provider runtime contract differs from the sealed call plan"
    );
    if call.host != AgentHostId::Codex
        && (!call.adapter_id.is_empty()
            || !call.adapter_version.is_empty()
            || !call.execution_request_ref.is_empty()
            || !call.execution_request_sha256.is_empty())
    {
        ensure!(
            binding.is_current()
                && !call.adapter_id.trim().is_empty()
                && !call.adapter_version.trim().is_empty()
                && !call.execution_request_ref.trim().is_empty()
                && is_sha256(&call.execution_request_sha256),
            "external cognitive call lacks current production-adapter bindings"
        );
        let request_path = private_relative_file(
            private_root,
            &call.execution_request_ref,
            "external execution request",
        )?;
        ensure!(
            sha256_bytes(&fs::read(&request_path)?) == call.execution_request_sha256,
            "external execution request hash differs from the sealed call"
        );
        let request: ExternalAgentExecutionRequest = read_json(&request_path)?;
        validate_external_agent_execution_request(&request)?;
        ensure!(
            request.requested_model == call.requested_model
                && request.prompt_sha256 == call.prompt_sha256
                && request.output_schema_sha256 == call.provider_schema_sha256,
            "external execution request differs from the sealed cognitive fields"
        );
    }
    Ok(binding)
}

fn accepted_prior_executions(
    source: &CoreRoleEvidenceSource,
) -> Result<&[CognitiveFieldExecutionKey]> {
    let CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
        role,
        case_id,
        executions,
        ..
    } = source
    else {
        bail!("fresh provider call is not a prior role artifact");
    };
    ensure!(
        case_id == "U03"
            && !executions.is_empty()
            && executions.windows(2).all(|pair| pair[0] < pair[1])
            && executions
                .iter()
                .all(|execution| execution.case_id == *case_id),
        "Task-02R2 permits only explicit, sorted U03 prior-role executions"
    );
    let conditions = executions
        .iter()
        .map(|execution| execution.memory_condition)
        .collect::<BTreeSet<_>>();
    match role {
        CognitiveFieldRole::CodexWorker | CognitiveFieldRole::CodexJudge => ensure!(
            executions.len() == 2
                && conditions
                    == [
                        CognitiveMemoryCondition::Treatment,
                        CognitiveMemoryCondition::MemoryFreeControl,
                    ]
                    .into_iter()
                    .collect(),
            "reused U03 Worker/Judge must cover treatment and control"
        ),
        CognitiveFieldRole::UnderstandingReader => ensure!(
            executions.len() == 1
                && matches!(
                    executions[0].memory_condition,
                    CognitiveMemoryCondition::Treatment
                        | CognitiveMemoryCondition::MemoryFreeControl
                ),
            "each reused U03 Reader must preserve one treatment/control identity"
        ),
    }
    Ok(executions)
}

fn sorted_unique_sha256s(values: &[String]) -> bool {
    !values.is_empty()
        && values.iter().all(|value| is_sha256(value))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

#[allow(clippy::too_many_lines)]
fn validate_core_reused_role_dependencies(role_sources: &[CoreRoleEvidenceSource]) -> Result<()> {
    let sources = prior_role_sources(role_sources).collect::<Vec<_>>();
    if sources.is_empty() {
        return Ok(());
    }
    ensure!(
        sources.len() == 4,
        "Task-02R2 continuation requires exactly four accepted U03 role sources"
    );
    let mut execution_roles = BTreeSet::new();
    let mut source_calls = BTreeSet::new();
    let mut oracle_hashes = BTreeSet::new();
    let mut reader_artifacts = BTreeSet::new();
    let mut judge_inputs = None;
    for source in sources {
        let CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
            source_call_id,
            role,
            provider_executable_sha256,
            output_schema_sha256,
            artifact_sha256,
            prompt_sha256,
            oracle_sha256,
            runtime_contract_sha256,
            input_artifact_sha256s,
            deterministic_report_sha256s,
            contamination_receipt_ref,
            worktree_diff_sha256,
            ..
        } = source
        else {
            unreachable!("filtered accepted prior role");
        };
        ensure!(
            safe_segment(source_call_id)
                && source_calls.insert(source_call_id.clone())
                && [
                    provider_executable_sha256,
                    output_schema_sha256,
                    artifact_sha256,
                    prompt_sha256,
                    oracle_sha256,
                    runtime_contract_sha256,
                ]
                .into_iter()
                .all(|value| is_sha256(value))
                && sorted_unique_sha256s(input_artifact_sha256s)
                && sorted_unique_sha256s(deterministic_report_sha256s),
            "accepted U03 role source has missing, duplicate, or invalid exact dependencies"
        );
        oracle_hashes.insert(oracle_sha256.clone());
        for execution in accepted_prior_executions(source)? {
            ensure!(
                execution_roles.insert((execution.clone(), *role)),
                "accepted U03 role source duplicates an execution role"
            );
        }
        match role {
            CognitiveFieldRole::CodexWorker => ensure!(
                worktree_diff_sha256
                    .as_ref()
                    .is_some_and(|hash| is_sha256(hash) && input_artifact_sha256s.contains(hash))
                    && deterministic_report_sha256s.len() == 2,
                "reused U03 Worker lacks candidate-diff or deterministic dependencies"
            ),
            CognitiveFieldRole::UnderstandingReader => {
                ensure!(
                    worktree_diff_sha256.is_none()
                        && deterministic_report_sha256s.len() == 1
                        && !contamination_receipt_ref.trim().is_empty(),
                    "reused U03 Reader dependencies are incomplete"
                );
                reader_artifacts.insert(artifact_sha256.clone());
            }
            CognitiveFieldRole::CodexJudge => {
                ensure!(
                    worktree_diff_sha256.is_none() && deterministic_report_sha256s.len() == 2,
                    "reused U03 Judge dependencies are incomplete"
                );
                judge_inputs = Some(input_artifact_sha256s.clone());
            }
        }
    }
    ensure!(
        oracle_hashes.len() == 1
            && reader_artifacts.len() == 2
            && judge_inputs.is_some_and(|inputs| {
                reader_artifacts
                    .iter()
                    .all(|artifact| inputs.contains(artifact))
            }),
        "U03 reused roles do not share one oracle or Judge is not bound to both Reader artifacts"
    );
    let expected = [
        (
            CognitiveFieldExecutionKey {
                case_id: "U03".to_owned(),
                memory_condition: CognitiveMemoryCondition::Treatment,
            },
            CognitiveFieldRole::CodexWorker,
        ),
        (
            CognitiveFieldExecutionKey {
                case_id: "U03".to_owned(),
                memory_condition: CognitiveMemoryCondition::MemoryFreeControl,
            },
            CognitiveFieldRole::CodexWorker,
        ),
        (
            CognitiveFieldExecutionKey {
                case_id: "U03".to_owned(),
                memory_condition: CognitiveMemoryCondition::Treatment,
            },
            CognitiveFieldRole::UnderstandingReader,
        ),
        (
            CognitiveFieldExecutionKey {
                case_id: "U03".to_owned(),
                memory_condition: CognitiveMemoryCondition::MemoryFreeControl,
            },
            CognitiveFieldRole::UnderstandingReader,
        ),
        (
            CognitiveFieldExecutionKey {
                case_id: "U03".to_owned(),
                memory_condition: CognitiveMemoryCondition::Treatment,
            },
            CognitiveFieldRole::CodexJudge,
        ),
        (
            CognitiveFieldExecutionKey {
                case_id: "U03".to_owned(),
                memory_condition: CognitiveMemoryCondition::MemoryFreeControl,
            },
            CognitiveFieldRole::CodexJudge,
        ),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    ensure!(
        execution_roles == expected,
        "accepted U03 roles do not cover Worker, treatment/control Readers and Judge exactly once"
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_provider_calls_with_sources(
    suite: &CognitiveFieldSuite,
    calls: &[CognitiveFieldProviderCallPlan],
    private_root: &Path,
    role_sources: &[CoreRoleEvidenceSource],
) -> Result<(u8, u8)> {
    ensure!(!calls.is_empty(), "provider call plan must not be empty");
    let core_qualification = suite.harness_version == COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION;
    if core_qualification {
        validate_core_reused_role_dependencies(role_sources)?;
    }
    let mut call_ids = BTreeSet::new();
    let mut observed =
        BTreeMap::<(String, CognitiveMemoryCondition, CognitiveFieldRole), u8>::new();
    let mut source_call_ids = BTreeSet::new();
    let mut reused_roles = 0_u8;
    for source in role_sources {
        match source {
            CoreRoleEvidenceSource::FreshProviderCall { planned_call_id } => {
                ensure!(
                    safe_segment(planned_call_id)
                        && source_call_ids.insert(planned_call_id.clone()),
                    "role evidence plan contains a duplicate or unsafe fresh call id"
                );
            }
            source @ CoreRoleEvidenceSource::AcceptedPriorRoleArtifact { .. } => {
                ensure!(
                    core_qualification,
                    "accepted prior roles are limited to core qualification"
                );
                reused_roles = reused_roles
                    .checked_add(1)
                    .context("reused role count overflow")?;
                let role = match source {
                    CoreRoleEvidenceSource::AcceptedPriorRoleArtifact { role, .. } => *role,
                    CoreRoleEvidenceSource::FreshProviderCall { .. } => unreachable!(),
                };
                for execution in accepted_prior_executions(source)? {
                    observed.insert(
                        (execution.case_id.clone(), execution.memory_condition, role),
                        1,
                    );
                }
            }
        }
    }
    let mut smoke_cases = BTreeSet::new();
    let mut capped = 0_u8;
    let mut smokes = 0_u8;
    for (index, call) in calls.iter().enumerate() {
        ensure!(
            usize::from(call.call_number) == index + 1,
            "provider call numbers must be contiguous and ordered from 1"
        );
        ensure!(
            safe_segment(&call.call_id) && call_ids.insert(call.call_id.clone()),
            "provider call_id is duplicate or unsafe"
        );
        ensure!(
            explicit_model_id(&call.requested_model),
            "provider model must be an explicit versioned ID, not a floating alias"
        );
        ensure!(
            is_sha256(&call.expected_provider_executable_sha256)
                && is_sha256(&call.prompt_sha256)
                && is_sha256(&call.canonical_schema_sha256)
                && is_sha256(&call.provider_schema_sha256),
            "provider executable, prompt, and output schema hashes must be SHA-256 values"
        );
        provider_runtime_contract(private_root, call)?;
        let prompt_path = private_relative_file(private_root, &call.prompt_ref, "provider prompt")?;
        let prompt_bytes = fs::read(&prompt_path)?;
        ensure!(
            sha256_bytes(&prompt_bytes) == call.prompt_sha256,
            "provider prompt hash differs from the sealed call plan"
        );
        let (canonical_contract, provider_contract) = role_schema_contracts(call.role)?;
        ensure!(
            call.canonical_schema_sha256 == canonical_contract.sha256
                && call.provider_schema_sha256 == provider_contract.sha256,
            "provider output schema hashes differ from the Rust-owned role contract"
        );
        if call.role == CognitiveFieldRole::UnderstandingReader {
            let prompt = String::from_utf8(prompt_bytes).context("Reader prompt must be UTF-8")?;
            ensure!(
                prompt.matches(&provider_contract.canonical_json).count() == 1
                    && prompt.matches(&provider_contract.sha256).count() == 1
                    && prompt.contains("BEGIN_COGNITIVE_UNDERSTANDING_SCHEMA")
                    && prompt.contains("END_COGNITIVE_UNDERSTANDING_SCHEMA"),
                "Reader prompt is not bound to the exact generated provider schema"
            );
        }
        ensure!(
            !call.executions.is_empty() && call.executions.windows(2).all(|pair| pair[0] < pair[1]),
            "provider call executions must be non-empty, unique, and sorted"
        );
        if core_qualification
            && matches!(
                call.role,
                CognitiveFieldRole::CodexWorker | CognitiveFieldRole::CodexJudge
            )
        {
            let case_ids = call
                .executions
                .iter()
                .map(|execution| execution.case_id.as_str())
                .collect::<BTreeSet<_>>();
            let conditions = call
                .executions
                .iter()
                .map(|execution| execution.memory_condition)
                .collect::<BTreeSet<_>>();
            ensure!(
                call.executions.len() == 2
                    && case_ids.len() == 1
                    && conditions
                        == [
                            CognitiveMemoryCondition::Treatment,
                            CognitiveMemoryCondition::MemoryFreeControl,
                        ]
                        .into_iter()
                        .collect(),
                "core Worker and Judge calls must cover both conditions for exactly one case"
            );
        } else {
            let memory_condition = call.executions[0].memory_condition;
            ensure!(
                call.executions
                    .iter()
                    .all(|execution| execution.memory_condition == memory_condition),
                "one provider call must not mix memory conditions"
            );
        }
        match call.role {
            CognitiveFieldRole::CodexWorker | CognitiveFieldRole::CodexJudge => ensure!(
                call.host == AgentHostId::Codex,
                "Worker and Judge calls must use Codex-owned sessions"
            ),
            CognitiveFieldRole::UnderstandingReader => ensure!(
                matches!(
                    call.host,
                    AgentHostId::Claude | AgentHostId::Antigravity | AgentHostId::OpenCode
                ),
                "Reader calls must use Claude, Antigravity, or OpenCode"
            ),
        }
        if core_qualification && call.role == CognitiveFieldRole::UnderstandingReader {
            ensure!(
                call.executions.len() == 1,
                "each core Reader call must cover exactly one condition"
            );
            let expected_host = match call.executions[0].case_id.as_str() {
                "U03" => AgentHostId::Claude,
                "U06" => AgentHostId::Antigravity,
                "U11" => AgentHostId::OpenCode,
                _ => bail!("core Reader call targets an unknown scenario"),
            };
            ensure!(
                call.host == expected_host,
                "core Reader host does not match the scenario contract"
            );
        }
        ensure!(
            call.provider_smoke != call.counts_against_cap,
            "exactly one of provider_smoke or counts_against_cap must be true"
        );
        if call.counts_against_cap {
            capped = capped
                .checked_add(1)
                .context("provider call count overflow")?;
        } else {
            smokes = smokes
                .checked_add(1)
                .context("provider smoke count overflow")?;
            ensure!(
                call.executions.len() == 1,
                "a provider smoke must contain exactly one execution"
            );
            let execution = &call.executions[0];
            let expected_host = match execution.case_id.as_str() {
                "H01" => AgentHostId::Codex,
                "H02" => AgentHostId::Claude,
                "H03" => AgentHostId::Antigravity,
                "H04" => AgentHostId::OpenCode,
                _ => bail!("provider smoke must target H01, H02, H03, or H04"),
            };
            ensure!(
                call.host == expected_host && smoke_cases.insert(execution.case_id.clone()),
                "provider smoke host/case binding is invalid or duplicated"
            );
        }
        for execution in &call.executions {
            let case = suite
                .cases
                .iter()
                .find(|case| case.case_id == execution.case_id)
                .context("provider plan contains an unknown case")?;
            ensure!(
                case.model_backed
                    && execution_conditions(case).contains(&execution.memory_condition)
                    && case.required_roles.contains(&call.role),
                "provider plan execution is not admitted by the suite"
            );
            let count = observed
                .entry((
                    execution.case_id.clone(),
                    execution.memory_condition,
                    call.role,
                ))
                .or_default();
            *count = count.saturating_add(1);
        }
    }
    ensure!(
        capped <= suite.hard_provider_call_cap,
        "sealed provider plan exceeds the hard provider-call cap"
    );
    if !role_sources.is_empty() {
        ensure!(
            source_call_ids == call_ids,
            "role evidence plan must name every fresh provider call exactly once"
        );
    }
    if core_qualification {
        if reused_roles == 0 {
            ensure!(
                capped == COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS && smokes == 0,
                "fresh core qualification must seal twelve provider calls and no smokes"
            );
        } else {
            ensure!(
                capped == COGNITIVE_CORE_CONTINUATION_EXPECTED_PROVIDER_CALLS
                    && capped <= COGNITIVE_CORE_CONTINUATION_MAX_PROVIDER_CALLS
                    && reused_roles == 4
                    && capped.saturating_add(reused_roles)
                        == COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS
                    && smokes == 0,
                "Task-02R2 must seal eight fresh calls, four reused U03 roles, and no smokes"
            );
        }
    }
    let expected_smokes = ["H01", "H02", "H03", "H04"]
        .into_iter()
        .filter(|case_id| suite.cases.iter().any(|case| case.case_id == *case_id))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    ensure!(
        smoke_cases == expected_smokes,
        "provider plan must contain one exact smoke for every configured live host case"
    );
    let mut expected = BTreeMap::new();
    for case in suite.cases.iter().filter(|case| case.model_backed) {
        for condition in execution_conditions(case) {
            for role in &case.required_roles {
                expected.insert((case.case_id.clone(), condition, *role), 1_u8);
            }
        }
    }
    ensure!(
        observed == expected,
        "provider plan must cover every model-backed execution role exactly once"
    );
    Ok((capped, smokes))
}

fn prior_role_sources(
    sources: &[CoreRoleEvidenceSource],
) -> impl Iterator<Item = &CoreRoleEvidenceSource> {
    sources.iter().filter(|source| {
        matches!(
            source,
            CoreRoleEvidenceSource::AcceptedPriorRoleArtifact { .. }
        )
    })
}

fn load_core_role_evidence_plan(
    suite: &CognitiveFieldSuite,
    contract: &CognitiveFieldRunContract,
    report_root: &Path,
    private_root: &Path,
    calls: &[CognitiveFieldProviderCallPlan],
) -> Result<Option<CoreRoleEvidencePlan>> {
    if suite.harness_version != COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION {
        return Ok(None);
    }
    let path = private_root.join("core-role-evidence.json");
    ensure!(
        path.is_file(),
        "core qualification requires private core-role-evidence.json"
    );
    let mut plan: CoreRoleEvidencePlan = read_json(&path)?;
    ensure!(
        plan.schema_version == CORE_ROLE_EVIDENCE_PLAN_SCHEMA_VERSION
            && plan.run_id == contract.run_id,
        "core role evidence plan differs from the sealed run"
    );
    let mut material = plan.clone();
    material.plan_hash.clear();
    let expected_hash = CognitiveFieldGradingService::hash_json(&material)?;
    ensure!(
        plan.plan_hash.is_empty() || expected_hash == plan.plan_hash,
        "core role evidence plan hash is invalid"
    );
    plan.plan_hash = expected_hash;
    validate_provider_calls_with_sources(suite, calls, private_root, &plan.sources)?;
    for source in prior_role_sources(&plan.sources) {
        verify_accepted_prior_role(suite, contract, report_root, private_root, source)?;
    }
    Ok(Some(plan))
}

fn source_run_roots(
    report_root: &Path,
    private_root: &Path,
    source_run_id: &str,
) -> Result<(PathBuf, PathBuf)> {
    ensure!(
        safe_segment(source_run_id),
        "prior role source run id is unsafe"
    );
    let source_report_root = canonical_directory(
        &report_root
            .parent()
            .context("current report root has no qualification parent")?
            .join(source_run_id),
        "prior cognitive report root",
    )?;
    let source_private_root = canonical_directory(
        &private_root
            .parent()
            .context("current private root has no qualification parent")?
            .join(source_run_id),
        "prior private certification root",
    )?;
    Ok((source_report_root, source_private_root))
}

fn content_ref_path(reference: &str, allowed_roots: &[&Path]) -> Result<PathBuf> {
    let (path, expected_sha256) = reference
        .rsplit_once("#sha256=")
        .context("content reference must end with #sha256=<hex>")?;
    ensure!(
        is_sha256(expected_sha256),
        "content reference hash is not SHA-256"
    );
    let path =
        fs::canonicalize(path).with_context(|| format!("resolve content reference {path}"))?;
    ensure!(
        path.is_file() && allowed_roots.iter().any(|root| path.starts_with(root)),
        "content reference is outside the accepted prior run roots"
    );
    ensure!(
        sha256_bytes(&fs::read(&path)?) == expected_sha256,
        "content reference hash mismatch for {}",
        path.display()
    );
    Ok(path)
}

fn git_diff_bytes(repository: &Path) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["diff", "--binary", "--no-ext-diff", "HEAD", "--"])
        .output()
        .with_context(|| format!("read candidate diff from {}", repository.display()))?;
    ensure!(
        output.status.success(),
        "git diff failed for {}: {}",
        repository.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

fn paired_artifact_sha256(outputs: &[(CognitiveFieldExecutionKey, Vec<u8>)]) -> Result<String> {
    let mut material = Vec::new();
    for (execution, bytes) in outputs {
        let execution = serde_json::to_vec(execution)?;
        for part in [&execution, bytes] {
            let length = u64::try_from(part.len()).context("artifact part length exceeds u64")?;
            material.extend_from_slice(&length.to_le_bytes());
            material.extend_from_slice(part);
        }
    }
    Ok(sha256_bytes(&material))
}

#[allow(clippy::too_many_arguments)]
fn validate_legacy_evidence_admission_record(
    admission: &LegacyEvidenceAdmissionRecord,
    admitting_run_id: &str,
    source_run_id: &str,
    source_call_id: &str,
    role: CognitiveFieldRole,
    case_id: &str,
    output_schema_sha256: &str,
    runtime_binding_sha256: &str,
) -> Result<()> {
    ensure!(
        admission.schema_version == LEGACY_EVIDENCE_ADMISSION_SCHEMA_VERSION
            && admission.admitting_run_id == admitting_run_id
            && admission.source_run_id == LEGACY_WORKER_SOURCE_RUN_ID
            && admission.source_run_id == source_run_id
            && admission.source_call_id == LEGACY_WORKER_SOURCE_CALL_ID
            && admission.source_call_id == source_call_id
            && admission.case_id == LEGACY_WORKER_CASE_ID
            && admission.case_id == case_id
            && admission.role == CognitiveFieldRole::CodexWorker
            && admission.role == role
            && admission.missing_historical_field == LEGACY_WORKER_MISSING_FIELD
            && admission.accepted_role_evidence_run_id == LEGACY_WORKER_ACCEPTANCE_RUN_ID
            && !admission.accepted_role_evidence_plan_hash.is_empty()
            && admission.output_schema_sha256 == output_schema_sha256
            && admission.historical_runtime_binding_sha256 == runtime_binding_sha256
            && is_sha256(&admission.output_schema_sha256)
            && is_sha256(&admission.historical_runtime_binding_sha256)
            && !admission.fresh_provider_authority,
        "legacy evidence admission is outside the one frozen historical Worker tuple"
    );
    Ok(())
}

fn verify_legacy_worker_acceptance_plan(
    report_root: &Path,
    private_root: &Path,
    admission: &LegacyEvidenceAdmissionRecord,
    source: &CoreRoleEvidenceSource,
) -> Result<()> {
    let CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
        source_run_id,
        source_call_id,
        role,
        case_id,
        provider_session_id,
        source_commit,
        provider_executable_sha256,
        output_schema_sha256,
        artifact_sha256,
        provider_receipt_ref,
        deterministic_receipt_refs,
        contamination_receipt_ref,
        worktree_diff_sha256,
        ..
    } = source
    else {
        bail!("legacy evidence admission cannot authorize a fresh provider call");
    };
    let (accepted_report_root, _) =
        source_run_roots(report_root, private_root, LEGACY_WORKER_ACCEPTANCE_RUN_ID)?;
    let accepted_plan_path = accepted_report_root.join("role-evidence-plan.json");
    let mut historical_plan: LegacyCoreRoleEvidencePlanV0 = read_json(&accepted_plan_path)?;
    let recorded_historical_plan_hash = historical_plan.plan_hash.clone();
    historical_plan.plan_hash.clear();
    let expected_historical_plan_hash = CognitiveFieldGradingService::hash_json(&historical_plan)?;
    ensure!(
        historical_plan.schema_version == CORE_ROLE_EVIDENCE_PLAN_SCHEMA_VERSION
            && historical_plan.run_id == LEGACY_WORKER_ACCEPTANCE_RUN_ID
            && recorded_historical_plan_hash == expected_historical_plan_hash
            && admission.accepted_role_evidence_plan_hash == recorded_historical_plan_hash,
        "legacy evidence admission differs from the immutable run005 role-evidence plan"
    );
    let accepted_plan: CoreRoleEvidencePlan = read_json(&accepted_plan_path)?;
    ensure!(
        accepted_plan.schema_version == CORE_ROLE_EVIDENCE_PLAN_SCHEMA_VERSION
            && accepted_plan.run_id == LEGACY_WORKER_ACCEPTANCE_RUN_ID
            && accepted_plan.plan_hash == recorded_historical_plan_hash,
        "legacy evidence admission differs from the immutable run005 role-evidence plan"
    );
    let accepted_source = accepted_plan
        .sources
        .iter()
        .find(|candidate| {
            matches!(
                candidate,
                CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
                    source_run_id: candidate_run_id,
                    source_call_id: candidate_call_id,
                    role: CognitiveFieldRole::CodexWorker,
                    case_id: candidate_case_id,
                    ..
                } if candidate_run_id == LEGACY_WORKER_SOURCE_RUN_ID
                    && candidate_call_id == LEGACY_WORKER_SOURCE_CALL_ID
                    && candidate_case_id == LEGACY_WORKER_CASE_ID
            )
        })
        .context("run005 role-evidence plan lacks the accepted legacy Worker binding")?;
    let CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
        source_run_id: accepted_source_run_id,
        source_call_id: accepted_source_call_id,
        role: accepted_role,
        case_id: accepted_case_id,
        provider_session_id: accepted_provider_session_id,
        source_commit: accepted_source_commit,
        provider_executable_sha256: accepted_provider_executable_sha256,
        output_schema_sha256: accepted_output_schema_sha256,
        artifact_sha256: accepted_artifact_sha256,
        provider_receipt_ref: accepted_provider_receipt_ref,
        deterministic_receipt_refs: accepted_deterministic_receipt_refs,
        contamination_receipt_ref: accepted_contamination_receipt_ref,
        worktree_diff_sha256: accepted_worktree_diff_sha256,
        legacy_evidence_admission: accepted_admission,
        ..
    } = accepted_source
    else {
        unreachable!("filtered accepted prior role");
    };
    ensure!(
        accepted_source_run_id == source_run_id
            && accepted_source_call_id == source_call_id
            && accepted_role == role
            && accepted_case_id == case_id
            && accepted_provider_session_id == provider_session_id
            && accepted_source_commit == source_commit
            && accepted_provider_executable_sha256 == provider_executable_sha256
            && accepted_output_schema_sha256 == output_schema_sha256
            && accepted_artifact_sha256 == artifact_sha256
            && accepted_provider_receipt_ref == provider_receipt_ref
            && accepted_deterministic_receipt_refs == deterministic_receipt_refs
            && accepted_contamination_receipt_ref == contamination_receipt_ref
            && accepted_worktree_diff_sha256 == worktree_diff_sha256
            && accepted_admission.is_none(),
        "legacy Worker dependency differs from the binding already accepted by run005"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_legacy_provider_runtime_binding(
    current_private_root: &Path,
    source_private_root: &Path,
    source_run_id: &str,
    source_call_id: &str,
    source_commit: &str,
    provider_session_id: &str,
    provider_receipt_ref: &str,
    provider_executable_sha256: &str,
    prompt_sha256: &str,
    runtime_binding_sha256: &str,
    receipt_path: &Path,
    receipt: &CognitiveFieldProviderEvidenceReceipt,
) -> Result<()> {
    let relative = format!("historical-runtime-bindings/{source_call_id}.json");
    let binding_path = private_relative_file(
        current_private_root,
        &relative,
        "historical runtime binding",
    )?;
    let binding_bytes = fs::read(&binding_path)?;
    ensure!(
        sha256_bytes(&binding_bytes) == runtime_binding_sha256,
        "historical runtime binding hash differs from the exact role dependency"
    );
    let binding: LegacyProviderRuntimeBinding = serde_json::from_slice(&binding_bytes)?;
    ensure!(
        binding.schema_version == LEGACY_RUNTIME_BINDING_SCHEMA_VERSION
            && binding.reconstruction_status == LEGACY_RUNTIME_RECONSTRUCTION_STATUS
            && binding.source_run_id == source_run_id
            && binding.source_call_id == source_call_id
            && binding.source_commit == source_commit
            && binding.provider_session_id == provider_session_id
            && binding.provider_receipt_ref == provider_receipt_ref
            && binding.provider_executable == receipt.provider_executable
            && binding.provider_executable_sha256 == provider_executable_sha256
            && binding.prompt_sha256 == prompt_sha256
            && binding.raw_stdout_sha256 == receipt.raw_stdout_sha256
            && binding.raw_stderr_sha256 == receipt.raw_stderr_sha256
            && binding.receipt_sha256 == sha256_bytes(&fs::read(receipt_path)?)
            && receipt_path.starts_with(source_private_root)
            && !binding.zero_model_preflight_available
            && !binding.fresh_role_authority,
        "historical runtime binding is not an immutable receipt-derived non-authority record"
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn find_prior_provider_receipt(
    source_private_root: &Path,
    source_call_id: &str,
) -> Result<(CognitiveFieldProviderEvidenceReceipt, PathBuf)> {
    fn visit(
        directory: &Path,
        source_call_id: &str,
        matches: &mut Vec<(CognitiveFieldProviderEvidenceReceipt, PathBuf)>,
        depth: u8,
    ) -> Result<()> {
        ensure!(
            depth <= 4,
            "provider receipt search exceeded its depth bound"
        );
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit(&path, source_call_id, matches, depth.saturating_add(1))?;
            } else if path.file_name().and_then(|name| name.to_str()) == Some("receipt.json")
                && let Ok(receipt) = read_json::<CognitiveFieldProviderEvidenceReceipt>(&path)
                && receipt.call_id == source_call_id
            {
                matches.push((receipt, fs::canonicalize(path)?));
            }
        }
        Ok(())
    }
    let root = source_private_root.join("provider-calls");
    let mut matches = Vec::new();
    visit(&root, source_call_id, &mut matches, 0)?;
    ensure!(
        matches.len() == 1,
        "accepted prior role requires exactly one matching private provider receipt"
    );
    Ok(matches.remove(0))
}

#[allow(clippy::too_many_lines)]
fn verify_accepted_prior_role(
    suite: &CognitiveFieldSuite,
    contract: &CognitiveFieldRunContract,
    report_root: &Path,
    private_root: &Path,
    source: &CoreRoleEvidenceSource,
) -> Result<VerifiedPriorRole> {
    let CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
        source_run_id,
        source_call_id,
        role,
        case_id,
        provider_session_id,
        source_commit,
        provider_executable_sha256,
        output_schema_sha256,
        artifact_sha256,
        prompt_sha256,
        oracle_sha256,
        runtime_contract_sha256,
        deterministic_report_sha256s,
        executions,
        provider_receipt_ref,
        deterministic_receipt_refs,
        contamination_receipt_ref,
        worktree_diff_sha256,
        legacy_evidence_admission,
        ..
    } = source
    else {
        bail!("fresh provider call is not a prior role artifact");
    };
    accepted_prior_executions(source)?;
    let (source_report_root, source_private_root) =
        source_run_roots(report_root, private_root, source_run_id)?;
    let source_contract: CognitiveFieldRunContract =
        read_json(&source_report_root.join("contract.json"))?;
    ensure!(
        source_contract.run_id == *source_run_id
            && source_contract.source_commit == *source_commit
            && contract.source_commit == *source_commit
            && same_git_repository(
                Path::new(&source_contract.primary_repository),
                Path::new(&contract.primary_repository),
            )?,
        "accepted prior role repository or source commit differs from the resumed run"
    );
    let source_plan: Value = read_json(&source_report_root.join("provider-plan.json"))?;
    ensure!(
        source_plan.get("run_id").and_then(Value::as_str) == Some(source_run_id)
            && source_plan.get("contract_hash").and_then(Value::as_str)
                == Some(source_contract.contract_hash.as_str()),
        "accepted prior provider plan differs from its run contract"
    );
    let source_call = source_plan
        .get("calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|call| call.get("call_id").and_then(Value::as_str) == Some(source_call_id))
        .context("accepted prior role call is absent from its provider plan")?;
    let expected_role = serde_json::to_value(role)?;
    let expected_host = match role {
        CognitiveFieldRole::CodexWorker | CognitiveFieldRole::CodexJudge => "codex",
        CognitiveFieldRole::UnderstandingReader => "claude",
    };
    ensure!(
        source_call.get("role") == Some(&expected_role)
            && source_call.get("host").and_then(Value::as_str) == Some(expected_host)
            && source_call
                .get("expected_provider_executable_sha256")
                .and_then(Value::as_str)
                == Some(provider_executable_sha256)
            && source_call.get("prompt_sha256").and_then(Value::as_str) == Some(prompt_sha256)
            && source_call
                .get("counts_against_cap")
                .and_then(Value::as_bool)
                == Some(true)
            && source_call.get("provider_smoke").and_then(Value::as_bool) == Some(false),
        "accepted prior role call plan binding is invalid"
    );
    let (canonical_schema, _) = role_schema_contracts(*role)?;
    ensure!(
        canonical_schema.sha256 == *output_schema_sha256,
        "accepted prior output schema differs from the current Rust contract"
    );
    match source_call.get("canonical_schema_sha256") {
        Some(Value::String(source_schema_sha256)) => ensure!(
            source_schema_sha256 == output_schema_sha256 && legacy_evidence_admission.is_none(),
            "accepted prior output schema differs from the current Rust contract"
        ),
        None => {
            let admission = legacy_evidence_admission.as_ref().context(
                "missing historical source_call.canonical_schema_sha256 lacks typed admission",
            )?;
            validate_legacy_evidence_admission_record(
                admission,
                &contract.run_id,
                source_run_id,
                source_call_id,
                *role,
                case_id,
                output_schema_sha256,
                runtime_contract_sha256,
            )?;
            verify_legacy_worker_acceptance_plan(report_root, private_root, admission, source)?;
        }
        Some(_) => bail!("accepted prior canonical schema field is present but is not a string"),
    }
    let prompt_ref = source_call
        .get("prompt_ref")
        .and_then(Value::as_str)
        .context("accepted prior call lacks prompt_ref")?;
    let prompt_path =
        private_relative_file(&source_private_root, prompt_ref, "accepted prior prompt")?;
    ensure!(
        sha256_bytes(&fs::read(prompt_path)?) == *prompt_sha256,
        "accepted prior prompt bytes differ from the dependency"
    );

    let source_suite: CognitiveFieldSuite = read_json(&source_report_root.join("suite.json"))?;
    let current_case = suite
        .cases
        .iter()
        .find(|candidate| candidate.case_id == *case_id)
        .context("current suite lacks accepted prior case")?;
    let source_case = source_suite
        .cases
        .iter()
        .find(|candidate| candidate.case_id == *case_id)
        .context("prior suite lacks accepted case")?;
    ensure!(
        current_case == source_case,
        "accepted prior public task differs from the resumed scenario"
    );
    let source_oracle_path = source_private_root
        .join("oracles")
        .join(format!("{case_id}.json"));
    let source_oracle_bytes = fs::read(&source_oracle_path)?;
    let source_oracle: TaskIntentOracle = serde_json::from_slice(&source_oracle_bytes)?;
    let current_oracle: TaskIntentOracle =
        read_json(&private_root.join("oracles").join(format!("{case_id}.json")))?;
    ensure!(
        sha256_bytes(&source_oracle_bytes) == *oracle_sha256
            && source_oracle.oracle_hash == current_oracle.oracle_hash
            && source_oracle.source_commit == contract.source_commit,
        "accepted prior private oracle differs from the exact dependency"
    );

    let projection: CognitiveFieldProviderProjection = read_json(
        &source_report_root
            .join("provider-invocations")
            .join(format!("{source_call_id}.json")),
    )?;
    ensure!(
        projection.run_id == *source_run_id
            && projection.call_id == *source_call_id
            && projection.role == *role
            && projection.provider_session_id == *provider_session_id
            && projection.provider_receipt_ref == *provider_receipt_ref
            && projection.provider_executable_sha256 == *provider_executable_sha256
            && projection.prompt_sha256 == *prompt_sha256
            && projection.source_commit == *source_commit
            && projection.contract_hash == source_contract.contract_hash
            && source_plan.get("plan_hash").and_then(Value::as_str)
                == Some(projection.provider_plan_hash.as_str())
            && projection.outputs.len() == executions.len(),
        "accepted prior provider projection differs from the sealed dependency"
    );
    let (receipt, receipt_path) =
        find_prior_provider_receipt(&source_private_root, source_call_id)?;
    ensure!(
        receipt.run_id == *source_run_id
            && receipt.call_id == *source_call_id
            && receipt.role == *role
            && receipt.provider_session_id == *provider_session_id
            && receipt.provider_receipt_ref == *provider_receipt_ref
            && receipt.provider_executable_sha256 == *provider_executable_sha256
            && receipt.prompt_sha256 == *prompt_sha256
            && receipt.source_commit == *source_commit
            && receipt.contract_hash == source_contract.contract_hash
            && receipt.provider_plan_hash == projection.provider_plan_hash
            && receipt.provider_calls == 1
            && receipt.exit_code == 0
            && !receipt.timed_out
            && !receipt.unknown_outcome
            && !receipt.controller_substitution,
        "accepted prior provider receipt is not one known successful invocation"
    );
    let receipt_executions = receipt
        .outputs
        .iter()
        .map(|output| output.execution.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        receipt_executions == executions.iter().cloned().collect(),
        "accepted prior receipt executions differ from the role dependency"
    );
    match (
        projection.runtime_contract_sha256.is_empty(),
        receipt.runtime_contract_sha256.is_empty(),
    ) {
        (false, false) => ensure!(
            projection.runtime_contract_sha256 == *runtime_contract_sha256
                && receipt.runtime_contract_sha256 == *runtime_contract_sha256,
            "accepted prior runtime contract differs from the exact role dependency"
        ),
        (true, true) => verify_legacy_provider_runtime_binding(
            private_root,
            &source_private_root,
            source_run_id,
            source_call_id,
            source_commit,
            provider_session_id,
            provider_receipt_ref,
            provider_executable_sha256,
            prompt_sha256,
            runtime_contract_sha256,
            &receipt_path,
            &receipt,
        )?,
        _ => bail!("accepted prior runtime dependency is only partially recorded"),
    }

    let mut outputs = Vec::new();
    let mut observed_deterministic_hashes = Vec::new();
    for output in &receipt.outputs {
        let output_path = fs::canonicalize(&output.output_path)?;
        ensure!(
            output_path.starts_with(&source_private_root) && output_path.is_file(),
            "accepted prior output is outside its private run"
        );
        let bytes = fs::read(&output_path)?;
        ensure!(
            sha256_bytes(&bytes) == output.output_sha256
                && projection.outputs.iter().any(|candidate| {
                    candidate.execution == output.execution
                        && candidate.output_sha256 == output.output_sha256
                }),
            "accepted prior output bytes differ from provider evidence"
        );
        let evidence_root = source_report_root
            .join("evidence")
            .join(case_id)
            .join(condition_name(output.execution.memory_condition));
        let target_name = match role {
            CognitiveFieldRole::CodexWorker => "worker.json",
            CognitiveFieldRole::UnderstandingReader => "reader.json",
            CognitiveFieldRole::CodexJudge => "judge.json",
        };
        ensure!(
            fs::read(evidence_root.join(target_name))? == bytes,
            "accepted prior public role artifact differs from provider-owned bytes"
        );
        let public_projection: CognitiveFieldProviderProjection =
            read_json(&evidence_root.join(format!("provider-{}.json", role_name(*role))))?;
        ensure!(
            public_projection == projection,
            "accepted prior public provider projection differs from its registry"
        );
        let deterministic_path = evidence_root.join("deterministic.json");
        let deterministic_bytes = fs::read(&deterministic_path)?;
        let deterministic: CognitiveDeterministicReport =
            serde_json::from_slice(&deterministic_bytes)?;
        ensure!(
            deterministic_report_is_valid(&deterministic)?
                && deterministic.source_commit == *source_commit,
            "accepted prior deterministic report is invalid"
        );
        observed_deterministic_hashes.push(sha256_bytes(&deterministic_bytes));
        match role {
            CognitiveFieldRole::CodexWorker => {
                let worker: CognitiveWorkerResult = serde_json::from_slice(&bytes)?;
                validate_worker_output(&worker, &output.execution, current_case, &deterministic)?;
            }
            CognitiveFieldRole::UnderstandingReader => {
                let reader: CognitiveUnderstandingAnswer = serde_json::from_slice(&bytes)?;
                validate_reader_output(&reader, &output.execution, &deterministic)?;
            }
            CognitiveFieldRole::CodexJudge => {
                let judge: CognitiveJudgeResult = serde_json::from_slice(&bytes)?;
                validate_judge_output(&judge, &output.execution, &source_oracle, &deterministic)?;
            }
        }
        outputs.push((output.execution.clone(), bytes));
    }
    outputs.sort_by(|left, right| left.0.cmp(&right.0));
    observed_deterministic_hashes.sort();
    observed_deterministic_hashes.dedup();
    ensure!(
        paired_artifact_sha256(&outputs)? == *artifact_sha256
            && observed_deterministic_hashes == *deterministic_report_sha256s,
        "accepted prior role artifact or deterministic report hash differs"
    );

    ensure!(
        deterministic_receipt_refs.len() == executions.len(),
        "accepted prior role lacks exact deterministic receipt references"
    );
    for reference in deterministic_receipt_refs {
        let path = content_ref_path(reference, &[&source_report_root, &source_private_root])?;
        let value: Value = read_json(&path)?;
        ensure!(
            value.get("case_id").and_then(Value::as_str) == Some(case_id)
                && value.get("source_commit").and_then(Value::as_str) == Some(source_commit),
            "accepted prior deterministic receipt differs from role dependencies"
        );
    }
    content_ref_path(
        contamination_receipt_ref,
        &[&source_report_root, &source_private_root],
    )?;
    let preflight: Value = read_json(&source_report_root.join("preflight.json"))?;
    ensure!(
        preflight
            .get("reader_surface_scans")
            .and_then(Value::as_array)
            .is_some_and(|scans| {
                !scans.is_empty()
                    && scans
                        .iter()
                        .all(|scan| scan.get("clean").and_then(Value::as_bool) == Some(true))
            }),
        "accepted prior contamination preflight was not clean"
    );

    let candidate_diff = match (role, worktree_diff_sha256) {
        (CognitiveFieldRole::CodexWorker, Some(expected)) => {
            ensure!(is_sha256(expected), "candidate diff hash is not SHA-256");
            let candidate_root = canonical_directory(
                &source_private_root.join("worktrees/cq1"),
                "prior CQ1 worktree",
            )?;
            ensure!(
                git_commit(&candidate_root)? == *source_commit,
                "prior CQ1 worktree base commit differs from Worker source"
            );
            let bytes = git_diff_bytes(&candidate_root)?;
            ensure!(
                !bytes.is_empty() && sha256_bytes(&bytes) == *expected,
                "prior CQ1 candidate diff is absent or hash-mismatched"
            );
            Some(bytes)
        }
        (CognitiveFieldRole::CodexWorker, None) => {
            bail!("Task-02R2 U03 Worker reuse requires a candidate diff hash")
        }
        (_, None) => None,
        (_, Some(_)) => bail!("only the U03 Worker may carry a candidate diff"),
    };
    Ok(VerifiedPriorRole {
        source_private_root,
        outputs,
        candidate_diff,
    })
}

#[allow(clippy::too_many_lines)]
fn materialize_accepted_prior_roles(
    suite: &CognitiveFieldSuite,
    contract: &CognitiveFieldRunContract,
    provider_plan: &CognitiveFieldProviderPlan,
    role_plan: &CoreRoleEvidencePlan,
    report_root: &Path,
    private_root: &Path,
) -> Result<()> {
    let mut projections_by_execution = BTreeMap::<PathBuf, Vec<CoreRoleReuseProjection>>::new();
    for source in prior_role_sources(&role_plan.sources) {
        let verified =
            verify_accepted_prior_role(suite, contract, report_root, private_root, source)?;
        let CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
            source_run_id,
            source_call_id,
            role,
            case_id,
            provider_session_id,
            provider_executable_sha256,
            output_schema_sha256,
            artifact_sha256,
            prompt_sha256,
            oracle_sha256,
            runtime_contract_sha256,
            input_artifact_sha256s,
            deterministic_report_sha256s,
            executions,
            provider_receipt_ref,
            deterministic_receipt_refs,
            contamination_receipt_ref,
            worktree_diff_sha256,
            ..
        } = source
        else {
            unreachable!("filtered prior role source");
        };
        let outputs = verified
            .outputs
            .iter()
            .map(
                |(execution, bytes)| CognitiveFieldProviderOutputProjection {
                    execution: execution.clone(),
                    output_sha256: sha256_bytes(bytes),
                },
            )
            .collect::<Vec<_>>();
        let reuse_root = private_root.join("reused").join(artifact_sha256);
        for (execution, bytes) in &verified.outputs {
            write_new_or_same(
                &reuse_root.join(format!(
                    "{}-{}.json",
                    condition_name(execution.memory_condition),
                    role_name(*role),
                )),
                bytes,
            )?;
        }
        if let Some(candidate_diff) = &verified.candidate_diff {
            write_new_or_same(&reuse_root.join("candidate.diff"), candidate_diff)?;
        }
        write_new_or_same_json(
            &reuse_root.join("source-private-root.json"),
            &json!({
                "source_private_root_sha256":
                    sha256_bytes(canonical_path(&verified.source_private_root).as_bytes()),
                "source_run_id": source_run_id,
            }),
        )?;
        let projection = CoreRoleReuseProjection {
            schema_version: CORE_ROLE_REUSE_PROJECTION_SCHEMA_VERSION.to_owned(),
            run_id: contract.run_id.clone(),
            contract_hash: contract.contract_hash.clone(),
            provider_plan_hash: provider_plan.plan_hash.clone(),
            source_run_id: source_run_id.clone(),
            source_call_id: source_call_id.clone(),
            role: *role,
            case_id: case_id.clone(),
            provider_session_id: provider_session_id.clone(),
            provider_receipt_ref: provider_receipt_ref.clone(),
            provider_executable_sha256: provider_executable_sha256.clone(),
            output_schema_sha256: output_schema_sha256.clone(),
            artifact_sha256: artifact_sha256.clone(),
            prompt_sha256: prompt_sha256.clone(),
            oracle_sha256: oracle_sha256.clone(),
            runtime_contract_sha256: runtime_contract_sha256.clone(),
            input_artifact_sha256s: input_artifact_sha256s.clone(),
            deterministic_report_sha256s: deterministic_report_sha256s.clone(),
            executions: executions.clone(),
            deterministic_receipt_refs: deterministic_receipt_refs.clone(),
            contamination_receipt_ref: contamination_receipt_ref.clone(),
            worktree_diff_sha256: worktree_diff_sha256.clone(),
            outputs,
            recorded_at: provider_plan.sealed_at,
        };
        for (execution, bytes) in verified.outputs {
            let evidence_root = report_root
                .join("evidence")
                .join(&execution.case_id)
                .join(condition_name(execution.memory_condition));
            let deterministic: CognitiveDeterministicReport =
                read_json(&evidence_root.join("deterministic.json"))?;
            let case = suite
                .cases
                .iter()
                .find(|case| case.case_id == execution.case_id)
                .context("resumed role case is absent from suite")?;
            ensure!(
                deterministic_report_is_valid(&deterministic)?
                    && deterministic.source_commit == contract.source_commit,
                "resumed deterministic binding differs from accepted role evidence"
            );
            let target = match role {
                CognitiveFieldRole::CodexWorker => {
                    let worker: CognitiveWorkerResult = serde_json::from_slice(&bytes)?;
                    validate_worker_output(&worker, &execution, case, &deterministic)?;
                    "worker.json"
                }
                CognitiveFieldRole::UnderstandingReader => {
                    let reader: CognitiveUnderstandingAnswer = serde_json::from_slice(&bytes)?;
                    validate_reader_output(&reader, &execution, &deterministic)?;
                    "reader.json"
                }
                CognitiveFieldRole::CodexJudge => {
                    let judge: CognitiveJudgeResult = serde_json::from_slice(&bytes)?;
                    let oracle: TaskIntentOracle = read_json(
                        &private_root
                            .join("oracles")
                            .join(format!("{}.json", execution.case_id)),
                    )?;
                    validate_judge_output(&judge, &execution, &oracle, &deterministic)?;
                    "judge.json"
                }
            };
            write_new_or_same(&evidence_root.join(target), &bytes)?;
            projections_by_execution
                .entry(evidence_root)
                .or_default()
                .push(projection.clone());
        }
    }
    for (evidence_root, mut projections) in projections_by_execution {
        projections.sort_by(|left, right| {
            (left.role, left.source_call_id.as_str())
                .cmp(&(right.role, right.source_call_id.as_str()))
        });
        write_new_or_same_json(&evidence_root.join("reused-roles.json"), &projections)?;
    }
    Ok(())
}

fn role_schema_contracts(
    role: CognitiveFieldRole,
) -> Result<(RenderedProviderContract, RenderedProviderContract)> {
    let canonical = match role {
        CognitiveFieldRole::CodexWorker => cognitive_worker_result_schema()?,
        CognitiveFieldRole::UnderstandingReader => cognitive_understanding_answer_schema(),
        CognitiveFieldRole::CodexJudge => cognitive_judge_result_schema()?,
    };
    let provider = if role == CognitiveFieldRole::UnderstandingReader {
        provider_compatible_reader_schema(&canonical)?
    } else {
        canonical.clone()
    };
    Ok((
        render_provider_contract(&canonical)?,
        render_provider_contract(&provider)?,
    ))
}

fn validate_provider_plan_hash(plan: &CognitiveFieldProviderPlan) -> Result<()> {
    ensure!(
        plan.schema_version == COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION,
        "provider plan schema version is invalid"
    );
    ensure!(
        CognitiveFieldGradingService::hash_json(&provider_plan_without_hash(plan))?
            == plan.plan_hash,
        "provider plan hash is invalid"
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_provider_receipt_envelope(
    call: &CognitiveFieldProviderCallPlan,
    receipt: &CognitiveFieldProviderEvidenceReceipt,
    private_root: &Path,
) -> Result<()> {
    let runtime_contract = provider_runtime_contract(private_root, call)?;
    ensure!(
        receipt.role == call.role
            && receipt.host == call.host
            && receipt.requested_model == call.requested_model
            && receipt.resolved_model == call.requested_model,
        "provider role, host, or exact resolved model differs from the sealed call"
    );
    ensure!(
        receipt.runtime_contract_sha256 == call.runtime_contract_sha256
            && receipt.runtime_contract_sha256 == runtime_contract.runtime_contract_sha256(),
        "provider receipt runtime hash differs from the sealed call"
    );
    ensure!(
        receipt
            .observed_mcp_server_names
            .windows(2)
            .all(|pair| pair[0] < pair[1])
            && receipt
                .observed_mcp_tool_names
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
        "provider-observed MCP server and tool names must be sorted and deduplicated"
    );
    ensure!(
        receipt.observed_mcp_server_names.iter().all(|name| {
            !runtime_contract.forbidden_mcp_server_names().contains(name)
                && !name.to_ascii_lowercase().contains("surreal")
        }) && runtime_contract
            .expected_mcp_tool_names()
            .iter()
            .all(|name| receipt.observed_mcp_tool_names.contains(name)),
        "provider receipt did not prove expected tools and absence of raw SurrealDB"
    );
    if call
        .executions
        .iter()
        .all(|execution| execution.memory_condition == CognitiveMemoryCondition::MemoryFreeControl)
    {
        ensure!(
            receipt.observed_mcp_tool_names.is_empty(),
            "memory-free control provider used an ELIOT MCP tool"
        );
    }
    if matches!(
        receipt.role,
        CognitiveFieldRole::CodexWorker | CognitiveFieldRole::CodexJudge
    ) {
        ensure!(
            receipt
                .observed_mcp_server_names
                .contains(&"eliot-governor".to_owned()),
            "Codex Worker/Judge receipt lacks the observed Governor server"
        );
    }
    ensure!(
        !receipt.provider_session_id.trim().is_empty()
            && !receipt.provider_receipt_ref.trim().is_empty(),
        "provider-owned session and receipt identities are required"
    );
    ensure!(
        receipt.provider_calls == 1
            && receipt.exit_code == 0
            && receipt.elapsed_ms > 0
            && !receipt.timed_out
            && !receipt.unknown_outcome
            && !receipt.controller_substitution,
        "provider call did not end as one known successful provider-owned invocation"
    );
    ensure!(
        receipt.oracle_exposed == (receipt.role == CognitiveFieldRole::CodexJudge)
            && !receipt.worker_transcript_exposed,
        "provider role isolation flags are invalid"
    );
    if matches!(
        receipt.role,
        CognitiveFieldRole::UnderstandingReader | CognitiveFieldRole::CodexJudge
    ) {
        ensure!(
            receipt.read_only,
            "Reader and Judge sessions must be read-only"
        );
    }
    ensure!(
        receipt.provider_executable_sha256 == call.expected_provider_executable_sha256
            && is_sha256(&receipt.provider_executable_sha256),
        "provider executable hash differs from the sealed plan"
    );
    let executable = fs::canonicalize(&receipt.provider_executable)
        .context("resolve provider executable from evidence")?;
    ensure!(
        executable.is_file()
            && sha256_bytes(&fs::read(executable)?) == receipt.provider_executable_sha256,
        "provider executable no longer matches the sealed hash"
    );
    let prompt = private_file(
        private_root,
        &receipt.prompt_path,
        &receipt.prompt_sha256,
        "provider prompt",
    )?;
    let expected_prompt = private_relative_file(private_root, &call.prompt_ref, "provider prompt")?;
    ensure!(
        prompt == expected_prompt
            && receipt.prompt_sha256 == call.prompt_sha256
            && is_sha256(&receipt.prompt_sha256),
        "provider prompt differs from the sealed call"
    );
    ensure!(
        is_sha256(&receipt.raw_stdout_sha256)
            && is_sha256(&receipt.raw_stderr_sha256)
            && receipt.outputs.iter().all(|output| {
                is_sha256(&output.output_sha256) && call.executions.contains(&output.execution)
            }),
        "provider evidence contains an invalid output hash or execution"
    );
    Ok(())
}

fn validate_worker_output(
    worker: &CognitiveWorkerResult,
    execution: &CognitiveFieldExecutionKey,
    case: &CognitiveFieldCase,
    deterministic: &CognitiveDeterministicReport,
) -> Result<()> {
    ensure!(
        worker.schema_version == COGNITIVE_FIELD_WORKER_SCHEMA_VERSION
            && worker.case_id == execution.case_id
            && worker.memory_condition == execution.memory_condition
            && worker.project_id == deterministic.project_id
            && worker.task_id == deterministic.task_id,
        "Worker output binding is invalid"
    );
    ensure!(
        !worker.work_summary.trim().is_empty()
            && !worker.current_truth_refs.is_empty()
            && !worker.observation_refs.is_empty()
            && !worker.verifier_refs.is_empty()
            && !worker.next_state_ref.trim().is_empty(),
        "Worker output omits required governed task state"
    );
    ensure!(
        worker
            .verifier_refs
            .iter()
            .any(|reference| case.deterministic_verifier_refs.contains(reference)),
        "Worker output omits every registered case verifier"
    );
    if execution.memory_condition == CognitiveMemoryCondition::MemoryFreeControl {
        ensure!(
            worker.memory_handles_used.is_empty() && worker.influence_receipt_refs.is_empty(),
            "memory-free Worker output contains memory exposure or influence"
        );
    }
    if execution.case_id == "M08"
        && execution.memory_condition == CognitiveMemoryCondition::Treatment
    {
        ensure!(
            !worker.influence_receipt_refs.is_empty(),
            "M08 treatment requires a real influence receipt"
        );
    }
    Ok(())
}

fn validate_json_schema_instance(schema: &Value, instance: &Value, label: &str) -> Result<()> {
    let errors = json_schema_errors(schema, schema, instance, "$", 0);
    ensure!(
        errors.is_empty(),
        "{label} failed JSON Schema validation: {}",
        errors.join("; ")
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn json_schema_errors(
    root: &Value,
    schema: &Value,
    instance: &Value,
    path: &str,
    depth: usize,
) -> Vec<String> {
    if depth > 64 {
        return vec![format!("{path}: schema recursion exceeded 64 levels")];
    }
    if schema == &Value::Bool(true) {
        return Vec::new();
    }
    if schema == &Value::Bool(false) {
        return vec![format!("{path}: rejected by false schema")];
    }
    let Some(object) = schema.as_object() else {
        return vec![format!("{path}: schema node is not an object or boolean")];
    };
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let Some(pointer) = reference.strip_prefix('#') else {
            return vec![format!(
                "{path}: non-local schema ref {reference} is unsupported"
            )];
        };
        let Some(target) = root.pointer(pointer) else {
            return vec![format!("{path}: unresolved schema ref {reference}")];
        };
        return json_schema_errors(root, target, instance, path, depth + 1);
    }

    let mut errors = Vec::new();
    if let Some(expected) = object.get("const")
        && expected != instance
    {
        errors.push(format!("{path}: value differs from const"));
    }
    if let Some(variants) = object.get("enum").and_then(Value::as_array)
        && !variants.contains(instance)
    {
        errors.push(format!("{path}: value is outside enum"));
    }
    if let Some(types) = object.get("type") {
        let type_matches = match types {
            Value::String(expected) => json_type_matches(expected, instance),
            Value::Array(expected) => expected
                .iter()
                .filter_map(Value::as_str)
                .any(|expected| json_type_matches(expected, instance)),
            _ => false,
        };
        if !type_matches {
            errors.push(format!(
                "{path}: actual type {} does not satisfy schema type {types}",
                json_type_name(instance)
            ));
            return errors;
        }
    }

    if let Some(all_of) = object.get("allOf").and_then(Value::as_array) {
        for branch in all_of {
            errors.extend(json_schema_errors(root, branch, instance, path, depth + 1));
        }
    }
    if let Some(any_of) = object.get("anyOf").and_then(Value::as_array)
        && !any_of
            .iter()
            .any(|branch| json_schema_errors(root, branch, instance, path, depth + 1).is_empty())
    {
        errors.push(format!("{path}: no anyOf branch accepted the value"));
    }
    if let Some(one_of) = object.get("oneOf").and_then(Value::as_array) {
        let accepted = one_of
            .iter()
            .filter(|branch| json_schema_errors(root, branch, instance, path, depth + 1).is_empty())
            .count();
        if accepted != 1 {
            errors.push(format!(
                "{path}: expected exactly one oneOf branch, accepted {accepted}"
            ));
        }
    }

    if let Some(actual) = instance.as_object() {
        let required = object
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        for key in required {
            if !actual.contains_key(key) {
                errors.push(format!("{path}/{key}: required property is missing"));
            }
        }
        let properties = object.get("properties").and_then(Value::as_object);
        if let Some(properties) = properties {
            for (key, value) in actual {
                if let Some(property_schema) = properties.get(key) {
                    errors.extend(json_schema_errors(
                        root,
                        property_schema,
                        value,
                        &format!("{path}/{}", escape_json_pointer(key)),
                        depth + 1,
                    ));
                    continue;
                }
                match object.get("additionalProperties") {
                    Some(Value::Bool(false)) => errors.push(format!(
                        "{path}/{}: additional property is forbidden",
                        escape_json_pointer(key)
                    )),
                    Some(additional @ (Value::Object(_) | Value::Bool(true))) => {
                        errors.extend(json_schema_errors(
                            root,
                            additional,
                            value,
                            &format!("{path}/{}", escape_json_pointer(key)),
                            depth + 1,
                        ));
                    }
                    _ => {}
                }
            }
        } else if let Some(additional @ Value::Object(_)) = object.get("additionalProperties") {
            for (key, value) in actual {
                errors.extend(json_schema_errors(
                    root,
                    additional,
                    value,
                    &format!("{path}/{}", escape_json_pointer(key)),
                    depth + 1,
                ));
            }
        }
        check_size_bound(
            object,
            "minProperties",
            actual.len(),
            path,
            true,
            &mut errors,
        );
        check_size_bound(
            object,
            "maxProperties",
            actual.len(),
            path,
            false,
            &mut errors,
        );
    }

    if let Some(actual) = instance.as_array() {
        if let Some(item_schema) = object.get("items") {
            for (index, value) in actual.iter().enumerate() {
                errors.extend(json_schema_errors(
                    root,
                    item_schema,
                    value,
                    &format!("{path}/{index}"),
                    depth + 1,
                ));
            }
        }
        check_size_bound(object, "minItems", actual.len(), path, true, &mut errors);
        check_size_bound(object, "maxItems", actual.len(), path, false, &mut errors);
        if object.get("uniqueItems") == Some(&Value::Bool(true)) {
            for (index, value) in actual.iter().enumerate() {
                if actual[..index].contains(value) {
                    errors.push(format!("{path}/{index}: array item is not unique"));
                }
            }
        }
    }

    if let Some(actual) = instance.as_str() {
        let length = actual.chars().count();
        check_size_bound(object, "minLength", length, path, true, &mut errors);
        check_size_bound(object, "maxLength", length, path, false, &mut errors);
    }

    if let Some(actual) = instance.as_f64() {
        for (keyword, comparison) in [
            ("minimum", std::cmp::Ordering::Less),
            ("maximum", std::cmp::Ordering::Greater),
        ] {
            if let Some(bound) = object.get(keyword).and_then(Value::as_f64)
                && actual.partial_cmp(&bound) == Some(comparison)
            {
                errors.push(format!("{path}: number violates {keyword} {bound}"));
            }
        }
        if let Some(bound) = object.get("exclusiveMinimum").and_then(Value::as_f64)
            && actual <= bound
        {
            errors.push(format!("{path}: number violates exclusiveMinimum {bound}"));
        }
        if let Some(bound) = object.get("exclusiveMaximum").and_then(Value::as_f64)
            && actual >= bound
        {
            errors.push(format!("{path}: number violates exclusiveMaximum {bound}"));
        }
    }
    errors
}

fn check_size_bound(
    schema: &serde_json::Map<String, Value>,
    keyword: &str,
    actual: usize,
    path: &str,
    minimum: bool,
    errors: &mut Vec<String>,
) {
    let Some(bound) = schema
        .get(keyword)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return;
    };
    if (minimum && actual < bound) || (!minimum && actual > bound) {
        errors.push(format!("{path}: size {actual} violates {keyword} {bound}"));
    }
}

fn json_type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "string" => value.is_string(),
        _ => false,
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn validate_reader_output(
    reader: &CognitiveUnderstandingAnswer,
    execution: &CognitiveFieldExecutionKey,
    deterministic: &CognitiveDeterministicReport,
) -> Result<()> {
    ensure!(
        reader.schema_version == eliot_types::COGNITIVE_UNDERSTANDING_SCHEMA_VERSION
            && reader.case_id == execution.case_id
            && reader.memory_condition == execution.memory_condition
            && reader.project_id == deterministic.project_id
            && reader.task_id == deterministic.task_id,
        "Reader output binding is invalid"
    );
    if execution.memory_condition == CognitiveMemoryCondition::MemoryFreeControl {
        ensure!(
            reader.memory_handles_received.is_empty()
                && reader.memory_handles_expanded.is_empty()
                && reader.memory_handles_used.is_empty()
                && reader.influence_receipt_refs.is_empty(),
            "memory-free Reader output contains memory exposure or influence"
        );
    }
    Ok(())
}

fn validate_judge_output(
    judge: &CognitiveJudgeResult,
    execution: &CognitiveFieldExecutionKey,
    oracle: &TaskIntentOracle,
    deterministic: &CognitiveDeterministicReport,
) -> Result<()> {
    ensure!(
        judge.schema_version == eliot_types::COGNITIVE_JUDGE_SCHEMA_VERSION
            && judge.case_id == execution.case_id
            && judge.oracle_hash == oracle.oracle_hash
            && judge.deterministic_report_hash == deterministic.report_hash,
        "Judge output binding is invalid"
    );
    Ok(())
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn explicit_model_id(value: &str) -> bool {
    let value = value.trim();
    let lower = value.to_ascii_lowercase();
    !value.is_empty()
        && value.bytes().any(|byte| byte.is_ascii_digit())
        && (value.contains('-') || value.contains('/'))
        && !matches!(
            lower.as_str(),
            "opus" | "sonnet" | "haiku" | "flash" | "pro" | "default" | "auto" | "latest"
        )
}

fn private_relative_file(private_root: &Path, relative: &str, label: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    ensure!(
        !relative.is_absolute()
            && relative
                .components()
                .all(|component| { matches!(component, std::path::Component::Normal(_)) }),
        "{label} ref must be a safe path relative to the private root"
    );
    let path = fs::canonicalize(private_root.join(relative))
        .with_context(|| format!("resolve {label} ref {}", relative.display()))?;
    ensure!(
        path.starts_with(private_root) && path.is_file(),
        "{label} ref escaped the private root or is not a file"
    );
    Ok(path)
}

fn private_file(
    private_root: &Path,
    value: &str,
    expected_sha256: &str,
    label: &str,
) -> Result<PathBuf> {
    let path = Path::new(value);
    let path = if path.is_absolute() {
        fs::canonicalize(path)
    } else {
        fs::canonicalize(private_root.join(path))
    }
    .with_context(|| format!("resolve {label} {value}"))?;
    ensure!(
        path.starts_with(private_root)
            && path.is_file()
            && sha256_bytes(&fs::read(&path)?) == expected_sha256,
        "{label} escaped the private root or failed its SHA-256 binding"
    );
    Ok(path)
}

fn validate_deterministic_receipt(
    contract: &CognitiveFieldRunContract,
    case: &CognitiveFieldCase,
    condition: CognitiveMemoryCondition,
    private_root: &Path,
    receipt: &CognitiveDeterministicEvidenceReceipt,
) -> Result<()> {
    ensure!(
        receipt.schema_version == COGNITIVE_DETERMINISTIC_EVIDENCE_SCHEMA_VERSION,
        "deterministic evidence schema version is invalid"
    );
    ensure!(
        receipt.run_id == contract.run_id
            && receipt.case_id == case.case_id
            && receipt.memory_condition == condition
            && receipt.source_commit == contract.source_commit,
        "deterministic evidence binding differs from the sealed plan"
    );
    ensure!(
        receipt.controller_provider_calls == 0,
        "controller substitution is forbidden in deterministic evidence"
    );
    ensure!(
        !receipt.truth_revision_before.trim().is_empty()
            && receipt.truth_revision_before == receipt.truth_revision_after_observability,
        "observability changed or omitted the truth revision"
    );
    let expected = case
        .deterministic_verifier_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let observed = receipt
        .verifier_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure!(
        expected == observed && expected.len() == receipt.verifier_refs.len(),
        "deterministic evidence does not exactly cover the registered verifier refs"
    );
    ensure!(
        !receipt.commands.is_empty(),
        "deterministic evidence has no command receipts"
    );
    for command in &receipt.commands {
        ensure!(
            !command.command_ref.trim().is_empty()
                && is_sha256(&command.arguments_sha256)
                && command.exit_code == 0
                && is_sha256(&command.stdout_sha256)
                && is_sha256(&command.stderr_sha256),
            "deterministic command receipt is incomplete or failed"
        );
        verify_private_log(private_root, &command.stdout_path, &command.stdout_sha256)?;
        verify_private_log(private_root, &command.stderr_path, &command.stderr_sha256)?;
    }
    Ok(())
}

fn verify_private_log(private_root: &Path, path: &str, expected_sha256: &str) -> Result<()> {
    let path = fs::canonicalize(path).with_context(|| format!("resolve private log {path}"))?;
    ensure!(
        path.starts_with(private_root) && path.is_file(),
        "verifier log must be a file inside the private certification root"
    );
    ensure!(
        sha256_bytes(&fs::read(&path)?) == expected_sha256,
        "verifier log hash mismatch for {}",
        path.display()
    );
    Ok(())
}

fn stable_binding_ids(binding: &str) -> (ProjectId, TaskId) {
    (
        ProjectId::from_uuid(stable_uuid(&format!("project:{binding}"))),
        TaskId::from_uuid(stable_uuid(&format!("task:{binding}"))),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreQualificationBinding {
    schema_version: String,
    run_id: String,
    case_id: String,
    project_id: String,
    task_id: String,
}

fn stable_uuid(value: &str) -> Uuid {
    let digest = Sha256::digest(value.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn deterministic_report_is_valid(report: &CognitiveDeterministicReport) -> Result<bool> {
    let original_hash = report.report_hash.clone();
    let original_passed = report.passed;
    let mut expected = report.clone();
    CognitiveFieldGradingService::seal_deterministic_report(&mut expected)?;
    Ok(original_passed && expected.passed && expected.report_hash == original_hash)
}

fn contract_without_hash(contract: &CognitiveFieldRunContract) -> CognitiveFieldRunContract {
    let mut material = contract.clone();
    material.contract_hash.clear();
    material
}

fn plan_without_hash(plan: &CognitiveFieldPlan) -> CognitiveFieldPlan {
    let mut material = plan.clone();
    material.plan_hash.clear();
    material
}

fn provider_plan_without_hash(plan: &CognitiveFieldProviderPlan) -> CognitiveFieldProviderPlan {
    let mut material = plan.clone();
    material.plan_hash.clear();
    material
}

fn git_commit(repository: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["-C"])
        .arg(repository)
        .args(["rev-parse", "HEAD"])
        .output()?;
    ensure!(
        output.status.success(),
        "git rev-parse failed for {}: {}",
        repository.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let commit = String::from_utf8(output.stdout)?.trim().to_owned();
    ensure!(
        commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "git returned a non-SHA commit for {}",
        repository.display()
    );
    Ok(commit)
}

fn same_git_repository(left: &Path, right: &Path) -> Result<bool> {
    fn common_directory(repository: &Path) -> Result<PathBuf> {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(["rev-parse", "--git-common-dir"])
            .output()
            .with_context(|| {
                format!("resolve Git common directory for {}", repository.display())
            })?;
        ensure!(
            output.status.success(),
            "git rev-parse --git-common-dir failed for {}: {}",
            repository.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        let value = String::from_utf8(output.stdout)?.trim().to_owned();
        let path = PathBuf::from(value);
        let path = if path.is_absolute() {
            path
        } else {
            repository.join(path)
        };
        fs::canonicalize(path).context("canonicalize Git common directory")
    }
    Ok(common_directory(left)? == common_directory(right)?)
}

fn permissive_license_declared(repository: &Path) -> Result<bool> {
    let manifest = fs::read_to_string(repository.join("Cargo.toml"))?.to_ascii_lowercase();
    if ["mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause"]
        .iter()
        .any(|license| manifest.contains(license))
    {
        return Ok(true);
    }
    for entry in fs::read_dir(repository)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if (name.starts_with("license") || name.starts_with("copying")) && entry.path().is_file() {
            let text = fs::read_to_string(entry.path())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if text.contains("mit license")
                || text.contains("apache license")
                || text.contains("bsd 2-clause")
                || text.contains("bsd 3-clause")
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_new_or_same_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_new_or_same(path, &bytes)
}

fn write_new_or_same(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.is_file() {
        ensure!(
            fs::read(path)? == bytes,
            "sealed output already exists with different content: {}",
            path.display()
        );
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("{label} does not exist: {}", path.display()))?;
    ensure!(canonical.is_dir(), "{label} is not a directory");
    Ok(canonical)
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("{label} does not exist: {}", path.display()))?;
    ensure!(canonical.is_file(), "{label} is not a file");
    Ok(canonical)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(path))
}

fn canonical_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        return format!("//{}", rest.replace('\\', "/"));
    }
    value
        .strip_prefix(r"\\?\")
        .unwrap_or(&value)
        .replace('\\', "/")
}

fn legacy_canonical_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn contract_path_matches(path: &Path, expected: &str) -> bool {
    canonical_path(path) == expected || legacy_canonical_path(path) == expected
}

fn contract_private_root_matches(path: &Path, expected_sha256: &str) -> bool {
    [canonical_path(path), legacy_canonical_path(path)]
        .into_iter()
        .any(|value| sha256_bytes(value.as_bytes()) == expected_sha256)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn median(values: &mut [u16]) -> Option<u16> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        Some(
            values[middle - 1]
                .saturating_add(values[middle])
                .saturating_div(2),
        )
    } else {
        Some(values[middle])
    }
}

#[allow(clippy::too_many_arguments)]
fn render_report(
    contract: &CognitiveFieldRunContract,
    status: &str,
    expected: usize,
    passed: usize,
    missing: usize,
    semantic_median: Option<u16>,
    actual_provider_calls: usize,
    actual_smoke_calls: usize,
    provider_plan_complete: bool,
) -> String {
    format!(
        "# Cognitive field certification\n\n\
         - Status: `{status}`\n\
         - Run: `{run_id}`\n\
         - Source commit: `{source_commit}`\n\
         - Second repository commit: `{second_commit}`\n\
         - Expected executions: {expected}\n\
         - Passed executions: {passed}\n\
         - Missing executions: {missing}\n\
         - Median semantic score (milli-points): {semantic_median:?}\n\
         - Provider call cap: {provider_cap}\n\n\
         - Actual capped provider calls: {actual_provider_calls}\n\
         - Actual provider smokes: {actual_smoke_calls}\n\
         - Sealed provider plan complete: {provider_plan_complete}\n\n\
         Raw provider transcripts and private oracle material are not included in this report.\n",
        run_id = contract.run_id,
        source_commit = contract.source_commit,
        second_commit = contract.second_repository_commit,
        provider_cap = contract.hard_provider_call_cap,
    )
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    writeln!(stdout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AbandonedSealAttemptRecord, CognitiveHarnessOnlyEquivalence, CoreRoleEvidenceSource,
        ExternalAgentExecutionRequest, LEGACY_EVIDENCE_ADMISSION_SCHEMA_VERSION,
        LEGACY_WORKER_ACCEPTANCE_RUN_ID, LEGACY_WORKER_CASE_ID, LEGACY_WORKER_MISSING_FIELD,
        LEGACY_WORKER_SOURCE_CALL_ID, LEGACY_WORKER_SOURCE_RUN_ID, LegacyEvidenceAdmissionRecord,
        ProviderPlanSealRecord, ProviderPlanSealState, READER_SCHEMA_JSON_PLACEHOLDER,
        READER_SCHEMA_SHA256_PLACEHOLDER, SealRecoveryDecision, SealedPromptBinding,
        StagedSealAuthority, abandon_provider_seal, canonical_path,
        codex_cognitive_runtime_contract, cognitive_external_execution_request,
        computed_runtime_contract_sha256, execution_conditions, generated_oracle,
        inspect_seal_recovery, load_seal_records, provider_compatible_reader_schema,
        provider_plan_seal_response, provider_plan_without_hash, record_provider, recover_seal,
        render_provider_contract, render_reader_prompt, role_schema_contracts,
        schema_validation_projection, seal_attempt_component, seal_runtime_contract, sha256_bytes,
        stage_artifacts_with_cleanup, validate_deterministic_receipt,
        validate_governor_product_provenance, validate_json_schema_instance,
        validate_legacy_evidence_admission_record, validate_provider_calls,
        validate_provider_calls_with_sources, validate_provider_receipt_envelope,
        validate_reader_output, write_new_or_same_json,
    };
    use eliot_engine::CognitiveFieldGradingService;
    use eliot_types::{
        AgentCapabilityEnvelope, AgentHostId, AgentHostIdentity, AgentInvocationRequest, AgentRole,
        AgentSessionHostBinding, AgentSessionId, AgentSessionState, AuthorityLeaseState,
        COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION, COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS,
        COGNITIVE_DETERMINISTIC_EVIDENCE_SCHEMA_VERSION,
        COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION, COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION,
        COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION,
        COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION, COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION,
        CognitiveDeterministicEvidenceReceipt, CognitiveDeterministicReport,
        CognitiveFieldExecutionKey, CognitiveFieldProviderCallPlan,
        CognitiveFieldProviderEvidenceReceipt, CognitiveFieldProviderOutputReceipt,
        CognitiveFieldProviderPlan, CognitiveFieldRole, CognitiveFieldRunContract,
        CognitiveFieldSuite, CognitiveHardGateEvidence, CognitiveMemoryCondition,
        CognitiveProviderMcpServer, CognitiveProviderRuntimeContract, CognitiveUnderstandingAnswer,
        CognitiveVerifierCommandReceipt, OperationJob, OperationJobState, OperationPhase,
        ProjectId, TaskId, TaskRoleLease, WorkItem, WorkItemId, WorkItemStatus, WorkScope,
        cognitive_understanding_answer_schema, minimal_cognitive_understanding_answer,
    };
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::Path;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[test]
    fn seal_stage_failure_cleans_private_root_and_retry_succeeds_without_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let private_root =
            std::env::temp_dir().join(format!("eliot-seal-stage-failure-{}", Uuid::new_v4()));
        fs::create_dir_all(&private_root)?;
        let private_root = fs::canonicalize(private_root)?;
        let staging_root = private_root.join("seal-staging").join("fixture-g1");
        let artifacts = vec![
            (
                "execution_request".to_owned(),
                "seal-staging/fixture-g1/runtime/request.json".to_owned(),
                b"{\"request\":1}\n".to_vec(),
            ),
            (
                "provider_runtime".to_owned(),
                "seal-staging/fixture-g1/runtime/runtime.json".to_owned(),
                b"{\"runtime\":1}\n".to_vec(),
            ),
        ];
        let broker = eliot_types::DelegationState::default();
        let work = eliot_engine::WorkState::default();
        assert!(
            stage_artifacts_with_cleanup(&private_root, &staging_root, &artifacts, Some(1))
                .is_err()
        );
        assert!(!staging_root.exists());
        assert!(broker.agent_host_sessions.is_empty());
        assert!(broker.task_role_leases.is_empty());
        assert!(broker.operation_jobs.is_empty());
        assert!(work.work_items.is_empty());
        stage_artifacts_with_cleanup(&private_root, &staging_root, &artifacts, None)?;
        assert!(staging_root.join("runtime/request.json").is_file());
        assert!(staging_root.join("runtime/runtime.json").is_file());
        fs::remove_dir_all(&private_root)?;
        Ok(())
    }

    #[test]
    fn published_seal_replay_response_is_byte_identical() -> Result<(), Box<dyn std::error::Error>>
    {
        let plan = CognitiveFieldProviderPlan {
            schema_version: COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION.to_owned(),
            run_id: "run-idempotent".to_owned(),
            contract_hash: "a".repeat(64),
            calls: Vec::new(),
            planned_provider_calls: 0,
            planned_smoke_calls: 0,
            planned_reused_roles: 0,
            role_evidence_plan_hash: None,
            seal_attempt_id: Some("seal-idempotent".to_owned()),
            seal_generation: 2,
            authority_activation_ref: Some("seal-records/seal-idempotent.json".to_owned()),
            runtime_manifest_sha256: Some("b".repeat(64)),
            artifact_manifest_sha256: Some("b".repeat(64)),
            plan_hash: "c".repeat(64),
            sealed_at: OffsetDateTime::now_utc(),
        };
        let first = provider_plan_seal_response(
            "run-idempotent",
            "seal-idempotent",
            2,
            &plan,
            &"b".repeat(64),
        );
        let replay = provider_plan_seal_response(
            "run-idempotent",
            "seal-idempotent",
            2,
            &plan,
            &"b".repeat(64),
        );
        assert_eq!(serde_json::to_vec(&first)?, serde_json::to_vec(&replay)?);
        assert_eq!(
            first.get("status").and_then(Value::as_str),
            Some("provider_plan_sealed")
        );
        assert!(first.get("idempotent").is_none());
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the S11 failure-injection test asserts the full compensation postcondition set"
    )]
    fn activated_seal_failure_revokes_authority_and_quarantines_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-activated-seal-compensation-{}",
            Uuid::new_v4()
        ));
        let config_path = root.join("config/governor.toml");
        fs::create_dir_all(
            config_path
                .parent()
                .ok_or_else(|| std::io::Error::other("config path has no parent"))?,
        )?;
        let private_root = root.join("cognitive-field/run-s11");
        let report_root = root.join("reports/run-s11");
        let staging_root = private_root.join("seal-staging/seal-s11-g1");
        let published_root = private_root.join("sealed/1");
        fs::create_dir_all(&staging_root)?;
        fs::create_dir_all(&report_root)?;
        fs::write(staging_root.join("artifact.json"), b"{\"staged\":true}\n")?;
        let public_plan_path = report_root.join("provider-plan.json");
        fs::write(&public_plan_path, b"{\"published\":true}\n")?;
        let private_root = fs::canonicalize(private_root)?;

        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let session_id = AgentSessionId::new_v7();
        let work_item_id = WorkItemId::new_v7();
        let now = OffsetDateTime::now_utc();
        let role_lease_id = "role-lease:s11".to_owned();
        let invocation_id = "invocation:s11".to_owned();
        let job_id = "operation-job:s11".to_owned();
        let mut broker = eliot_types::DelegationState::default();
        broker.agent_host_sessions.push(AgentSessionHostBinding {
            agent_session_id: session_id,
            host_identity: AgentHostIdentity {
                host_id: AgentHostId::Claude,
                implementation_name: "claude-code".to_owned(),
                client_instance_id: "s11-client".to_owned(),
            },
            capability_envelope: AgentCapabilityEnvelope {
                capabilities: vec!["emit_candidate_observation".to_owned()],
                structured_output: true,
                resumable: true,
                interactive: false,
                supervised: true,
            },
            bound_project_id: Some(project_id),
            bound_task_id: Some(task_id),
            task_role_lease_refs: vec![role_lease_id.clone()],
            state: AgentSessionState::Active,
            generation: 1,
            owner_operation_id: Some(job_id.clone()),
            disconnected_at: None,
            disconnect_reason: None,
        });
        broker.task_role_leases.push(TaskRoleLease {
            role_lease_id: role_lease_id.clone(),
            task_id,
            agent_session_id: session_id,
            role: AgentRole::Implementer,
            capability_scope: vec!["emit_candidate_observation".to_owned()],
            expires_at: now + time::Duration::minutes(30),
            epoch: 1,
            state: AuthorityLeaseState::Active,
            owner_operation_id: Some(job_id.clone()),
            seal_attempt_id: Some("seal-attempt:s11".to_owned()),
            generation: 1,
            issued_at: Some(now),
            activated_at: Some(now),
            consumed_at: None,
            revoked_at: None,
            revoke_reason: None,
            superseded_by_epoch: None,
        });
        broker.agent_invocations.push(AgentInvocationRequest {
            invocation_id: invocation_id.clone(),
            project_id,
            task_id,
            work_item_id,
            requested_capabilities: vec!["emit_candidate_observation".to_owned()],
            role_lease_id: role_lease_id.clone(),
            role_lease_epoch: 1,
            operation_generation: 1,
            runtime_contract_sha256: Some("a".repeat(64)),
            work_lease_id: None,
            packet_refs: Vec::new(),
            expected_result_kind: "provider_execution_evidence".to_owned(),
            verifier_ref: "verifier:s11".to_owned(),
            idempotency_key: "idempotency:s11".to_owned(),
        });
        broker.operation_jobs.push(OperationJob {
            job_id: job_id.clone(),
            invocation_id: invocation_id.clone(),
            host_id: AgentHostId::Claude,
            state: OperationJobState::Queued,
            attempt: 0,
            resume_session_id: None,
            result_ref: None,
            idempotency_key: "idempotency:s11".to_owned(),
            created_at: now,
            updated_at: now,
            generation: 1,
            phase: OperationPhase::AuthorityActivating,
            phase_started_at: Some(now),
            last_progress_at: Some(now),
            phase_deadline_at: None,
            absolute_deadline_at: None,
            restart_count: 0,
            runtime_contract_sha256: Some("a".repeat(64)),
            role_lease_id: Some(role_lease_id.clone()),
            role_lease_epoch: Some(1),
        });
        crate::delegation_runtime::save_host_broker_state(&root, &broker)?;
        crate::delegation_runtime::save_work_state(&root, &eliot_engine::WorkState::default())?;

        let authority = vec![StagedSealAuthority {
            call_id: "call:s11".to_owned(),
            host: AgentHostId::Claude,
            project_id,
            task_id,
            agent_session_id: session_id,
            client_instance_id: "s11-client".to_owned(),
            work_item_id,
            role_lease_id: role_lease_id.clone(),
            role_lease_epoch: 1,
            operation_generation: 1,
            runtime_contract_sha256: "a".repeat(64),
            invocation_id,
            operation_job_id: job_id,
            capability_scope: vec!["emit_candidate_observation".to_owned()],
            expires_at: now + time::Duration::minutes(30),
        }];
        let mut record = ProviderPlanSealRecord {
            schema_version: "eliot-provider-plan-seal-v1".to_owned(),
            seal_attempt_id: "seal-attempt:s11".to_owned(),
            run_id: "run-s11".to_owned(),
            generation: 1,
            state: ProviderPlanSealState::Activated,
            contract_sha256: "b".repeat(64),
            role_evidence_plan_sha256: "c".repeat(64),
            staged_manifest_sha256: "d".repeat(64),
            provider_plan_sha256: Some("e".repeat(64)),
            session_ids: vec![session_id],
            role_lease_ids: vec![role_lease_id],
            work_item_ids: vec![work_item_id],
            operation_job_ids: vec!["operation-job:s11".to_owned()],
            staging_root: staging_root.display().to_string(),
            published_root: published_root.display().to_string(),
            activated_at: Some(now),
            published_at: None,
            abandoned_at: None,
            failure_ref: None,
        };
        abandon_provider_seal(
            &config_path,
            &private_root,
            Some(&public_plan_path),
            &mut record,
            &authority,
            "injected_failure_after_activation",
        )?;

        let recovered = crate::delegation_runtime::load_state(&root)?;
        assert_eq!(
            recovered.task_role_leases[0].state,
            AuthorityLeaseState::Revoked
        );
        assert_eq!(
            recovered.agent_host_sessions[0].state,
            AgentSessionState::Retired
        );
        assert_eq!(
            recovered.operation_jobs[0].state,
            OperationJobState::Abandoned
        );
        assert!(!public_plan_path.exists());
        assert_eq!(record.state, ProviderPlanSealState::Abandoned);
        assert!(
            load_seal_records(&private_root)?
                .iter()
                .any(|stored| stored.state == ProviderPlanSealState::Abandoned)
        );
        let abandoned_path = fs::read_dir(private_root.join("abandoned-seals"))?
            .next()
            .ok_or_else(|| std::io::Error::other("abandoned seal record is missing"))??
            .path();
        let _typed: AbandonedSealAttemptRecord =
            serde_json::from_slice(&fs::read(abandoned_path)?)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "S14 deliberately reconstructs the complete four-call legacy recovery boundary"
    )]
    fn exact_run006_partial_shape_is_recovered_once_without_provider_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let run_id = "run-s14";
        let root =
            std::env::temp_dir().join(format!("eliot-exact-run006-recovery-{}", Uuid::new_v4()));
        let config_path = root.join("config/governor.toml");
        let private_root = root.join("cognitive-field").join(run_id);
        let report_root = root.join("reports").join(run_id);
        let runtime_root = private_root.join("runtime");
        let schema_root = private_root.join("schemas");
        fs::create_dir_all(
            config_path
                .parent()
                .ok_or_else(|| std::io::Error::other("config path has no parent"))?,
        )?;
        fs::create_dir_all(&runtime_root)?;
        fs::create_dir_all(&schema_root)?;
        fs::create_dir_all(&report_root)?;
        fs::write(&config_path, b"# S14 fixture\n")?;
        let private_root = fs::canonicalize(private_root)?;
        let report_root = fs::canonicalize(report_root)?;
        let repository = fs::canonicalize(&root)?;
        let now = OffsetDateTime::now_utc();
        let contract = CognitiveFieldRunContract {
            schema_version: COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION.to_owned(),
            run_id: run_id.to_owned(),
            suite_sha256: "1".repeat(64),
            source_commit: "2".repeat(40),
            primary_repository: repository.display().to_string(),
            second_repository: repository.display().to_string(),
            second_repository_commit: "3".repeat(40),
            output_root: report_root.display().to_string(),
            private_root_sha256: sha256_bytes(private_root.display().to_string().as_bytes()),
            hard_provider_call_cap: 4,
            contract_hash: "4".repeat(64),
            sealed_at: now,
        };
        crate::runtime_instance::atomic_write_json(&report_root.join("contract.json"), &contract)?;
        let schema_path = schema_root.join("reader-provider.json");
        fs::write(&schema_path, b"{\"type\":\"object\"}\n")?;
        let schema_sha256 = sha256_bytes(&fs::read(&schema_path)?);
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let hosts = [
            AgentHostId::Claude,
            AgentHostId::Antigravity,
            AgentHostId::OpenCode,
            AgentHostId::Claude,
        ];
        let models = [
            "claude-opus-5",
            "gemini-3.6-flash-high",
            "opencode/mimo-v2.5-free",
            "claude-opus-5",
        ];
        let mut calls = Vec::new();
        let mut broker = eliot_types::DelegationState::default();
        let mut work = eliot_engine::WorkState::default();
        for (index, (host, model)) in hosts.into_iter().zip(models).enumerate() {
            let call_id = format!("s14-call-{}", index + 1);
            let prompt_path = private_root.join(format!("prompts/{call_id}.md"));
            fs::create_dir_all(
                prompt_path
                    .parent()
                    .ok_or_else(|| std::io::Error::other("prompt path has no parent"))?,
            )?;
            fs::write(&prompt_path, format!("S14 provider prompt {call_id}\n"))?;
            let prompt_sha256 = sha256_bytes(&fs::read(&prompt_path)?);
            let session_id = AgentSessionId::new_v7();
            let work_item_id = WorkItemId::new_v7();
            let role_lease_id = format!("task-role-lease:s14-{}", index + 1);
            let invocation_id = format!("cognitive-field-{run_id}-{call_id}");
            let operation_job_id = format!("operation-job:s14-{}", index + 1);
            let runtime_contract_sha256 = format!("{:064x}", index + 10);
            let call = CognitiveFieldProviderCallPlan {
                call_number: u8::try_from(index + 1)?,
                call_id: call_id.clone(),
                role: CognitiveFieldRole::UnderstandingReader,
                host,
                requested_model: model.to_owned(),
                expected_provider_executable_sha256: "5".repeat(64),
                prompt_ref: canonical_path(&prompt_path),
                prompt_sha256,
                canonical_schema_sha256: schema_sha256.clone(),
                provider_schema_sha256: schema_sha256.clone(),
                provider_smoke: false,
                counts_against_cap: true,
                executions: vec![CognitiveFieldExecutionKey {
                    case_id: format!("S14-{}", index + 1),
                    memory_condition: CognitiveMemoryCondition::Treatment,
                }],
                runtime_contract_ref: format!("runtime/{call_id}-provider-runtime.json"),
                runtime_contract_sha256: runtime_contract_sha256.clone(),
                adapter_id: format!("s14-{}", host.as_str()),
                adapter_version: "fixture-v1".to_owned(),
                execution_request_ref: format!("runtime/{call_id}-execution-request.json"),
                execution_request_sha256: String::new(),
            };
            let authority = StagedSealAuthority {
                call_id: call_id.clone(),
                host,
                project_id,
                task_id,
                agent_session_id: session_id,
                client_instance_id: format!("cognitive-field:{run_id}:{call_id}:g1"),
                work_item_id,
                role_lease_id: role_lease_id.clone(),
                role_lease_epoch: 1,
                operation_generation: 1,
                runtime_contract_sha256: runtime_contract_sha256.clone(),
                invocation_id: invocation_id.clone(),
                operation_job_id: operation_job_id.clone(),
                capability_scope: vec!["emit_candidate_observation".to_owned()],
                expires_at: now + time::Duration::minutes(30),
            };
            let binding = SealedPromptBinding {
                project_id,
                task_id,
                repository: repository.clone(),
            };
            let execution = cognitive_external_execution_request(
                &contract,
                &private_root,
                &call,
                &binding,
                &prompt_path,
                &authority,
            )?;
            crate::runtime_instance::atomic_write_json(
                &runtime_root.join(format!("{call_id}-execution-request.json")),
                &execution,
            )?;
            crate::runtime_instance::atomic_write_json(
                &runtime_root.join(format!("{call_id}-provider-runtime.json")),
                &json!({
                    "schema_version": "s14-provider-runtime-fixture-v1",
                    "call_id": call_id,
                    "runtime_contract_sha256": runtime_contract_sha256,
                }),
            )?;
            broker.agent_host_sessions.push(AgentSessionHostBinding {
                agent_session_id: session_id,
                host_identity: AgentHostIdentity {
                    host_id: host,
                    implementation_name: format!("s14-{}", host.as_str()),
                    client_instance_id: authority.client_instance_id.clone(),
                },
                capability_envelope: AgentCapabilityEnvelope {
                    capabilities: authority.capability_scope.clone(),
                    structured_output: true,
                    resumable: true,
                    interactive: false,
                    supervised: true,
                },
                bound_project_id: Some(project_id),
                bound_task_id: Some(task_id),
                task_role_lease_refs: vec![role_lease_id.clone()],
                state: AgentSessionState::Active,
                generation: 0,
                owner_operation_id: None,
                disconnected_at: None,
                disconnect_reason: None,
            });
            broker.task_role_leases.push(TaskRoleLease {
                role_lease_id: role_lease_id.clone(),
                task_id,
                agent_session_id: session_id,
                role: AgentRole::Auditor,
                capability_scope: authority.capability_scope.clone(),
                expires_at: authority.expires_at,
                epoch: 1,
                state: AuthorityLeaseState::Active,
                owner_operation_id: None,
                seal_attempt_id: None,
                generation: 0,
                issued_at: Some(now),
                activated_at: Some(now),
                consumed_at: None,
                revoked_at: None,
                revoke_reason: None,
                superseded_by_epoch: None,
            });
            broker.agent_invocations.push(execution.invocation.clone());
            broker.operation_jobs.push(OperationJob {
                job_id: operation_job_id,
                invocation_id,
                host_id: host,
                state: OperationJobState::Queued,
                attempt: 0,
                resume_session_id: None,
                result_ref: None,
                idempotency_key: format!("cognitive-field:{run_id}:{call_id}"),
                created_at: now,
                updated_at: now,
                generation: 0,
                phase: OperationPhase::AuthorityActivating,
                phase_started_at: Some(now),
                last_progress_at: Some(now),
                phase_deadline_at: None,
                absolute_deadline_at: None,
                restart_count: 0,
                runtime_contract_sha256: Some(authority.runtime_contract_sha256.clone()),
                role_lease_id: Some(role_lease_id),
                role_lease_epoch: Some(1),
            });
            work.work_items.push(WorkItem {
                work_item_id,
                project_id,
                task_id,
                project: "s14".to_owned(),
                task: call_id.clone(),
                goal: "recover the exact run006 partial seal shape".to_owned(),
                scope: WorkScope {
                    repo_root: repository.display().to_string(),
                    read_set: vec![repository.display().to_string()],
                    write_set: Vec::new(),
                    verifier_set: vec!["s14".to_owned()],
                    authority: eliot_types::AuthorityProfile::read_only(),
                    risk_tier: eliot_types::RiskTier::Low,
                    max_files: 0,
                    requires_active_work_lease: false,
                },
                status: WorkItemStatus::Open,
                required: true,
                allowed_roles: vec![AgentRole::Auditor],
                required_verifiers: Vec::new(),
                created_by: session_id,
                active_lease_id: None,
                lease_refs: Vec::new(),
                conflict_refs: Vec::new(),
                created_at: now,
                updated_at: now,
                completed_at: None,
                write_receipt: None,
            });
            calls.push(call);
        }
        crate::runtime_instance::atomic_write_json(&private_root.join("calls.json"), &calls)?;
        crate::delegation_runtime::save_host_broker_state(&root, &broker)?;
        crate::delegation_runtime::save_work_state(&root, &work)?;
        for call in &calls {
            let request: ExternalAgentExecutionRequest = serde_json::from_slice(&fs::read(
                private_root
                    .join("runtime")
                    .join(format!("{}-execution-request.json", call.call_id)),
            )?)?;
            assert_eq!(request.invocation.operation_generation, 1);
            assert_eq!(request.launch_contract.operation_generation, 1);
        }
        assert!(
            broker
                .agent_host_sessions
                .iter()
                .all(|session| { session.generation == 0 && session.owner_operation_id.is_none() })
        );
        assert!(broker.task_role_leases.iter().all(|lease| {
            lease.generation == 0
                && lease.owner_operation_id.is_none()
                && lease.seal_attempt_id.is_none()
        }));
        assert!(broker.operation_jobs.iter().all(|job| job.generation == 0));

        let before = inspect_seal_recovery(&config_path, run_id, &report_root, &private_root)?;
        assert_eq!(
            before.decision,
            SealRecoveryDecision::AbandonAndRevokeSafePredispatch
        );
        assert_eq!(before.execution_request_paths.len(), 4);
        assert_eq!(before.provider_runtime_paths.len(), 4);
        assert_eq!(before.present_work_item_ids.len(), 4);
        assert_eq!(before.present_operation_job_ids.len(), 4);
        assert_eq!(before.provider_reservation_count, 0);
        assert_eq!(before.provider_result_count, 0);
        assert!(before.provider_artifact_paths.is_empty());
        assert!(before.legacy_authority_cas_ready);
        assert!(before.scoped_authority_exact);
        assert!(before.exact_error.is_none());
        assert!(before.non_projection_proofs.is_empty());

        recover_seal(
            &config_path,
            run_id,
            Some(&report_root),
            Some(&private_root),
            false,
            true,
        )?;
        let recovered_broker = crate::delegation_runtime::load_state(&root)?;
        let recovered_work = crate::delegation_runtime::load_work_state(&root)?;
        let seal_component = seal_attempt_component(run_id, 1);
        let manifest_path = private_root
            .join("quarantine")
            .join(&seal_component)
            .join("generation-1-manifest.json");
        let abandoned_path = private_root
            .join("abandoned-seals")
            .join(format!("{seal_component}.json"));
        let manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        assert_eq!(
            manifest
                .get("entries")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(8)
        );
        assert!(recovered_broker.task_role_leases.iter().all(|lease| {
            lease.state == AuthorityLeaseState::Revoked
                && lease.revoke_reason.as_deref() == Some("partial_seal_before_provider_plan")
        }));
        assert!(recovered_broker.agent_host_sessions.iter().all(|session| {
            session.state == AgentSessionState::Retired
                && session.disconnect_reason.as_deref() == Some("partial_seal_before_provider_plan")
        }));
        assert!(
            recovered_broker
                .operation_jobs
                .iter()
                .all(|job| job.state == OperationJobState::Abandoned)
        );
        assert!(
            recovered_work
                .work_items
                .iter()
                .all(|item| item.status == WorkItemStatus::Revoked)
        );
        assert!(!report_root.join("provider-plan.json").exists());
        assert!(fs::read_dir(private_root.join("runtime"))?.next().is_none());
        let after = inspect_seal_recovery(&config_path, run_id, &report_root, &private_root)?;
        assert_eq!(after.decision, SealRecoveryDecision::AlreadyAbandoned);
        assert_eq!(after.provider_reservation_count, 0);
        assert_eq!(after.provider_result_count, 0);
        assert!(after.provider_artifact_paths.is_empty());
        let broker_snapshot = serde_json::to_vec(&recovered_broker)?;
        let work_snapshot = serde_json::to_vec(&recovered_work)?;
        let manifest_snapshot = fs::read(&manifest_path)?;
        let abandoned_snapshot = fs::read(&abandoned_path)?;
        recover_seal(
            &config_path,
            run_id,
            Some(&report_root),
            Some(&private_root),
            false,
            true,
        )?;
        assert_eq!(
            serde_json::to_vec(&crate::delegation_runtime::load_state(&root)?)?,
            broker_snapshot
        );
        assert_eq!(
            serde_json::to_vec(&crate::delegation_runtime::load_work_state(&root)?)?,
            work_snapshot
        );
        assert_eq!(fs::read(manifest_path)?, manifest_snapshot);
        assert_eq!(fs::read(abandoned_path)?, abandoned_snapshot);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn provider_test_prompt(
        role: CognitiveFieldRole,
        label: &str,
    ) -> Result<(String, String, String), Box<dyn std::error::Error>> {
        let (canonical, provider) = role_schema_contracts(role)?;
        let prompt = if role == CognitiveFieldRole::UnderstandingReader {
            format!(
                "{label}\nBEGIN_COGNITIVE_UNDERSTANDING_SCHEMA\nsha256={}\n{}\nEND_COGNITIVE_UNDERSTANDING_SCHEMA\n",
                provider.sha256, provider.canonical_json
            )
        } else {
            format!("{label} exact provider role prompt\n")
        };
        Ok((prompt, canonical.sha256, provider.sha256))
    }

    fn provider_test_runtime(
        private_root: &Path,
        host: AgentHostId,
        call_id: &str,
        executable: &Path,
    ) -> Result<(String, String, String), Box<dyn std::error::Error>> {
        if let Some(parent) = executable.parent() {
            fs::create_dir_all(parent)?;
        }
        if !executable.is_file() {
            fs::write(
                executable,
                format!("synthetic provider executable for {call_id}"),
            )?;
        }
        let executable = fs::canonicalize(executable)?;
        let private_root = fs::canonicalize(private_root)?;
        let mut contract = if host == AgentHostId::Codex {
            codex_cognitive_runtime_contract(
                &executable,
                &private_root,
                &executable,
                Some("0123456789abcdef0123456789abcdef01234567"),
            )?
        } else {
            let mut contract = CognitiveProviderRuntimeContract {
                schema_version: COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION.to_owned(),
                host,
                provider_executable: canonical_path(&executable),
                provider_executable_sha256: sha256_bytes(&fs::read(&executable)?),
                provider_cwd: canonical_path(&private_root),
                provider_argv: vec!["synthetic-provider-run".to_owned()],
                nonsecret_environment: BTreeMap::new(),
                mcp_servers: vec![CognitiveProviderMcpServer {
                    name: "eliot_surrealdb".to_owned(),
                    command: String::new(),
                    args: Vec::new(),
                    cwd: String::new(),
                    required: false,
                    enabled: false,
                    executable_sha256: String::new(),
                    build_source_commit: None,
                }],
                expected_mcp_tool_names: Vec::new(),
                forbidden_mcp_server_names: vec!["eliot_surrealdb".to_owned()],
                runtime_contract_sha256: String::new(),
            };
            seal_runtime_contract(&mut contract)?;
            contract
        };
        seal_runtime_contract(&mut contract)?;
        let runtime_ref = format!("provider-runtime/{call_id}.json");
        write_new_or_same_json(&private_root.join(&runtime_ref), &contract)?;
        Ok((
            contract.provider_executable_sha256,
            runtime_ref,
            contract.runtime_contract_sha256,
        ))
    }

    #[allow(clippy::too_many_lines)]
    fn core_reused_role_sources() -> Result<Vec<CoreRoleEvidenceSource>, Box<dyn std::error::Error>>
    {
        let (worker_schema, _) = role_schema_contracts(CognitiveFieldRole::CodexWorker)?;
        let (reader_schema, _) = role_schema_contracts(CognitiveFieldRole::UnderstandingReader)?;
        let (judge_schema, _) = role_schema_contracts(CognitiveFieldRole::CodexJudge)?;
        let treatment = CognitiveFieldExecutionKey {
            case_id: "U03".to_owned(),
            memory_condition: CognitiveMemoryCondition::Treatment,
        };
        let control = CognitiveFieldExecutionKey {
            case_id: "U03".to_owned(),
            memory_condition: CognitiveMemoryCondition::MemoryFreeControl,
        };
        let source_commit = "9e6d9161a133d7e501c163a6cc69a3da86713e7a".to_owned();
        let oracle_sha256 = "2".repeat(64);
        let runtime_contract_sha256 = "3".repeat(64);
        let treatment_artifact = "4".repeat(64);
        let control_artifact = "6".repeat(64);
        Ok(vec![
            CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
                source_run_id: "cq-core-20260729-003".to_owned(),
                source_call_id: "6f04e449-ecab-4555-8bd0-4a6bd762c1b4".to_owned(),
                role: CognitiveFieldRole::CodexWorker,
                case_id: "U03".to_owned(),
                provider_session_id: "worker-session".to_owned(),
                source_commit: source_commit.clone(),
                provider_executable_sha256: "a".repeat(64),
                output_schema_sha256: worker_schema.sha256,
                artifact_sha256: "b".repeat(64),
                prompt_sha256: "1".repeat(64),
                oracle_sha256: oracle_sha256.clone(),
                runtime_contract_sha256: runtime_contract_sha256.clone(),
                input_artifact_sha256s: vec!["f".repeat(64)],
                deterministic_report_sha256s: vec!["c".repeat(64), "d".repeat(64)],
                executions: vec![treatment.clone(), control.clone()],
                provider_receipt_ref: "receipt:accepted-worker".to_owned(),
                deterministic_receipt_refs: vec![
                    "treatment#sha256=".to_owned() + &"c".repeat(64),
                    "control#sha256=".to_owned() + &"d".repeat(64),
                ],
                contamination_receipt_ref: "contamination:worker".to_owned(),
                worktree_diff_sha256: Some("f".repeat(64)),
                legacy_evidence_admission: None,
            },
            CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
                source_run_id: "cq-core-20260730-005".to_owned(),
                source_call_id: "f03d7867-82b9-4f2a-847e-424f90d9ec3f".to_owned(),
                role: CognitiveFieldRole::UnderstandingReader,
                case_id: "U03".to_owned(),
                provider_session_id: "treatment-reader-session".to_owned(),
                source_commit: source_commit.clone(),
                provider_executable_sha256: "a".repeat(64),
                output_schema_sha256: reader_schema.sha256.clone(),
                artifact_sha256: treatment_artifact.clone(),
                prompt_sha256: "5".repeat(64),
                oracle_sha256: oracle_sha256.clone(),
                runtime_contract_sha256: runtime_contract_sha256.clone(),
                input_artifact_sha256s: vec!["b".repeat(64)],
                deterministic_report_sha256s: vec!["c".repeat(64)],
                executions: vec![treatment.clone()],
                provider_receipt_ref: "receipt:accepted-treatment-reader".to_owned(),
                deterministic_receipt_refs: vec!["treatment#sha256=".to_owned() + &"c".repeat(64)],
                contamination_receipt_ref: "contamination:treatment-reader".to_owned(),
                worktree_diff_sha256: None,
                legacy_evidence_admission: None,
            },
            CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
                source_run_id: "cq-core-20260730-005".to_owned(),
                source_call_id: "e976e8db-17d8-477c-83a6-7d7d1c64f928".to_owned(),
                role: CognitiveFieldRole::UnderstandingReader,
                case_id: "U03".to_owned(),
                provider_session_id: "control-reader-session".to_owned(),
                source_commit: source_commit.clone(),
                provider_executable_sha256: "a".repeat(64),
                output_schema_sha256: reader_schema.sha256,
                artifact_sha256: control_artifact.clone(),
                prompt_sha256: "7".repeat(64),
                oracle_sha256: oracle_sha256.clone(),
                runtime_contract_sha256: runtime_contract_sha256.clone(),
                input_artifact_sha256s: vec!["b".repeat(64)],
                deterministic_report_sha256s: vec!["d".repeat(64)],
                executions: vec![control.clone()],
                provider_receipt_ref: "receipt:accepted-control-reader".to_owned(),
                deterministic_receipt_refs: vec!["control#sha256=".to_owned() + &"d".repeat(64)],
                contamination_receipt_ref: "contamination:control-reader".to_owned(),
                worktree_diff_sha256: None,
                legacy_evidence_admission: None,
            },
            CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
                source_run_id: "cq-core-20260730-005".to_owned(),
                source_call_id: "8a079450-0357-4abc-9dc3-918afac453cc".to_owned(),
                role: CognitiveFieldRole::CodexJudge,
                case_id: "U03".to_owned(),
                provider_session_id: "judge-session".to_owned(),
                source_commit,
                provider_executable_sha256: "a".repeat(64),
                output_schema_sha256: judge_schema.sha256,
                artifact_sha256: "8".repeat(64),
                prompt_sha256: "9".repeat(64),
                oracle_sha256,
                runtime_contract_sha256,
                input_artifact_sha256s: vec![treatment_artifact, control_artifact],
                deterministic_report_sha256s: vec!["c".repeat(64), "d".repeat(64)],
                executions: vec![treatment, control],
                provider_receipt_ref: "receipt:accepted-judge".to_owned(),
                deterministic_receipt_refs: vec![
                    "treatment#sha256=".to_owned() + &"c".repeat(64),
                    "control#sha256=".to_owned() + &"d".repeat(64),
                ],
                contamination_receipt_ref: "contamination:judge".to_owned(),
                worktree_diff_sha256: None,
                legacy_evidence_admission: None,
            },
        ])
    }

    fn legacy_worker_admission(
        admitting_run_id: &str,
        output_schema_sha256: &str,
        runtime_binding_sha256: &str,
    ) -> LegacyEvidenceAdmissionRecord {
        LegacyEvidenceAdmissionRecord {
            schema_version: LEGACY_EVIDENCE_ADMISSION_SCHEMA_VERSION.to_owned(),
            admitting_run_id: admitting_run_id.to_owned(),
            source_run_id: LEGACY_WORKER_SOURCE_RUN_ID.to_owned(),
            source_call_id: LEGACY_WORKER_SOURCE_CALL_ID.to_owned(),
            case_id: LEGACY_WORKER_CASE_ID.to_owned(),
            role: CognitiveFieldRole::CodexWorker,
            missing_historical_field: LEGACY_WORKER_MISSING_FIELD.to_owned(),
            accepted_role_evidence_run_id: LEGACY_WORKER_ACCEPTANCE_RUN_ID.to_owned(),
            accepted_role_evidence_plan_hash: "blake3:accepted-run005-plan".to_owned(),
            output_schema_sha256: output_schema_sha256.to_owned(),
            historical_runtime_binding_sha256: runtime_binding_sha256.to_owned(),
            fresh_provider_authority: false,
        }
    }

    #[test]
    fn legacy_worker_schema_admission_accepts_only_the_frozen_tuple()
    -> Result<(), Box<dyn std::error::Error>> {
        let run_id = "cq-core-20260730-006";
        let (worker_schema, _) = role_schema_contracts(CognitiveFieldRole::CodexWorker)?;
        let runtime_binding_sha256 = "3".repeat(64);
        let admission =
            legacy_worker_admission(run_id, &worker_schema.sha256, &runtime_binding_sha256);
        validate_legacy_evidence_admission_record(
            &admission,
            run_id,
            LEGACY_WORKER_SOURCE_RUN_ID,
            LEGACY_WORKER_SOURCE_CALL_ID,
            CognitiveFieldRole::CodexWorker,
            LEGACY_WORKER_CASE_ID,
            &worker_schema.sha256,
            &runtime_binding_sha256,
        )?;
        Ok(())
    }

    #[test]
    fn legacy_worker_schema_admission_rejects_tuple_or_authority_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let run_id = "cq-core-20260730-006";
        let (worker_schema, _) = role_schema_contracts(CognitiveFieldRole::CodexWorker)?;
        let runtime_binding_sha256 = "3".repeat(64);
        let admission =
            legacy_worker_admission(run_id, &worker_schema.sha256, &runtime_binding_sha256);
        let mut wrong_tuple = admission.clone();
        wrong_tuple.source_call_id = "fresh-call".to_owned();
        assert!(
            validate_legacy_evidence_admission_record(
                &wrong_tuple,
                run_id,
                LEGACY_WORKER_SOURCE_RUN_ID,
                LEGACY_WORKER_SOURCE_CALL_ID,
                CognitiveFieldRole::CodexWorker,
                LEGACY_WORKER_CASE_ID,
                &worker_schema.sha256,
                &runtime_binding_sha256,
            )
            .is_err()
        );
        let mut fresh_authority = admission.clone();
        fresh_authority.fresh_provider_authority = true;
        assert!(
            validate_legacy_evidence_admission_record(
                &fresh_authority,
                run_id,
                LEGACY_WORKER_SOURCE_RUN_ID,
                LEGACY_WORKER_SOURCE_CALL_ID,
                CognitiveFieldRole::CodexWorker,
                LEGACY_WORKER_CASE_ID,
                &worker_schema.sha256,
                &runtime_binding_sha256,
            )
            .is_err()
        );
        let mut wrong_missing_field = admission;
        wrong_missing_field.missing_historical_field =
            "provider_receipt.runtime_contract_sha256".to_owned();
        assert!(
            validate_legacy_evidence_admission_record(
                &wrong_missing_field,
                run_id,
                LEGACY_WORKER_SOURCE_RUN_ID,
                LEGACY_WORKER_SOURCE_CALL_ID,
                CognitiveFieldRole::CodexWorker,
                LEGACY_WORKER_CASE_ID,
                &worker_schema.sha256,
                &runtime_binding_sha256,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn runtime_contract_hash_changes_for_every_load_bearing_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let root =
            std::env::temp_dir().join(format!("eliot-runtime-contract-hash-{}", Uuid::new_v4()));
        fs::create_dir_all(&root)?;
        let provider = root.join("codex.exe");
        let governor = root.join("eliot-governor.exe");
        fs::write(&provider, b"codex fixture")?;
        fs::write(&governor, b"governor fixture")?;
        let contract = codex_cognitive_runtime_contract(
            &provider,
            &root,
            &governor,
            Some("0123456789abcdef0123456789abcdef01234567"),
        )?;
        let baseline = contract.runtime_contract_sha256.clone();
        let mutations: Vec<Box<dyn Fn(&mut CognitiveProviderRuntimeContract)>> = vec![
            Box::new(|value| value.provider_executable.push_str(".changed")),
            Box::new(|value| value.provider_argv.push("--changed".to_owned())),
            Box::new(|value| value.provider_cwd.push_str("/changed")),
            Box::new(|value| value.mcp_servers[0].command.push_str(".changed")),
            Box::new(|value| value.mcp_servers[0].args.push("--changed".to_owned())),
            Box::new(|value| value.mcp_servers[0].cwd.push_str("/changed")),
            Box::new(|value| value.mcp_servers[0].required = false),
            Box::new(|value| {
                if let Some(server) = value
                    .mcp_servers
                    .iter_mut()
                    .find(|server| server.name == "eliot_surrealdb")
                {
                    server.enabled = true;
                }
            }),
            Box::new(|value| {
                value
                    .expected_mcp_tool_names
                    .push("eliot_changed_tool".to_owned());
            }),
        ];
        for mutate in mutations {
            let mut changed = contract.clone();
            mutate(&mut changed);
            assert_ne!(computed_runtime_contract_sha256(&changed)?, baseline);
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn codex_runtime_contract_is_self_contained_without_project_config()
    -> Result<(), Box<dyn std::error::Error>> {
        let root =
            std::env::temp_dir().join(format!("eliot-runtime-self-contained-{}", Uuid::new_v4()));
        fs::create_dir_all(&root)?;
        let provider = root.join("codex.exe");
        let governor = root.join("eliot-governor.exe");
        fs::write(&provider, b"codex fixture")?;
        fs::write(&governor, b"governor fixture")?;
        assert!(!root.join(".codex/config.toml").exists());
        let contract = codex_cognitive_runtime_contract(
            &provider,
            &root,
            &governor,
            Some("0123456789abcdef0123456789abcdef01234567"),
        )?;
        let argv = contract.provider_argv.join("\n");
        assert!(argv.contains("mcp_servers.eliot-governor.command="));
        assert!(argv.contains("mcp_servers.eliot-governor.args="));
        assert!(argv.contains("\"--profile\",\"codex_worker\""));
        assert!(argv.contains("mcp_servers.eliot-governor.required=true"));
        assert!(argv.contains("mcp_servers.eliot_surrealdb.enabled=false"));
        let canonical_root = canonical_path(&fs::canonicalize(&root)?);
        assert!(
            contract
                .provider_argv
                .windows(2)
                .any(|pair| pair[0] == "--cd" && pair[1] == canonical_root)
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn governor_product_source_mismatch_requires_exact_harness_only_equivalence()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-runtime-product-provenance-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root)?;
        let provider = root.join("codex.exe");
        let governor = root.join("eliot-governor.exe");
        fs::write(&provider, b"codex fixture")?;
        fs::write(&governor, b"governor fixture")?;
        let build_commit = "0123456789abcdef0123456789abcdef01234567";
        let product_commit = "9e6d9161a133d7e501c163a6cc69a3da86713e7a";
        let contract =
            codex_cognitive_runtime_contract(&provider, &root, &governor, Some(build_commit))?;
        assert!(validate_governor_product_provenance(&contract, product_commit, None).is_err());
        let equivalence = CognitiveHarnessOnlyEquivalence {
            schema_version: "eliot-cognitive-harness-equivalence-v1".to_owned(),
            product_source_commit: product_commit.to_owned(),
            governor_build_source_commit: build_commit.to_owned(),
            exact_diff_sha256: "a".repeat(64),
            changed_paths: vec![
                "crates/eliot-app/src/cognitive_field_runner.rs".to_owned(),
                "crates/eliot-types/src/cognitive_field.rs".to_owned(),
            ],
        };
        validate_governor_product_provenance(&contract, product_commit, Some(&equivalence))?;
        let mut invalid = equivalence;
        invalid
            .changed_paths
            .push("crates/eliot-engine/src/cognitive_field.rs".to_owned());
        invalid.changed_paths.sort();
        assert!(
            validate_governor_product_provenance(&contract, product_commit, Some(&invalid))
                .is_err()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn complete_reader(condition: CognitiveMemoryCondition) -> CognitiveUnderstandingAnswer {
        let mut reader = minimal_cognitive_understanding_answer();
        reader.case_id = "U03".to_owned();
        reader.memory_condition = condition;
        reader.files_to_change = vec!["crates/eliot-engine/src/host.rs".to_owned()];
        reader.known_failures = vec!["failure:stale-cli-discovery".to_owned()];
        reader.stale_or_rejected_memory_refs = vec!["claim:rejected-route".to_owned()];
        reader.open_unknowns = vec!["unknown:future-desktop-cache-layout".to_owned()];
        reader.predicted_changed_paths = vec!["crates/eliot-engine/src/host.rs".to_owned()];
        reader.predicted_failing_verifiers = vec!["cargo:test:host-integration".to_owned()];
        reader
            .confidence_by_section
            .insert("causal_hops".to_owned(), 3);
        if condition == CognitiveMemoryCondition::Treatment {
            reader.memory_handles_received = vec!["claim:received".to_owned()];
            reader.memory_handles_expanded = vec!["claim:expanded".to_owned()];
            reader.memory_handles_used = vec!["claim:used".to_owned()];
            reader.influence_receipt_refs = vec!["influence:verified".to_owned()];
        } else {
            reader.memory_handles_received.clear();
            reader.memory_handles_expanded.clear();
            reader.memory_handles_used.clear();
            reader.influence_receipt_refs.clear();
        }
        reader
    }

    #[test]
    fn canonical_and_provider_reader_contracts_accept_complete_fixture()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = complete_reader(CognitiveMemoryCondition::Treatment);
        let value = serde_json::to_value(&fixture)?;
        let canonical = cognitive_understanding_answer_schema();
        let provider = provider_compatible_reader_schema(&canonical)?;
        validate_json_schema_instance(&canonical, &value, "canonical fixture")?;
        validate_json_schema_instance(&provider, &value, "provider fixture")?;
        let roundtrip: CognitiveUnderstandingAnswer = serde_json::from_value(value.clone())?;
        assert_eq!(roundtrip, fixture);
        let properties = canonical["properties"]
            .as_object()
            .ok_or("canonical properties object")?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let serialized = value
            .as_object()
            .ok_or("serialized reader object")?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(serialized, properties);
        Ok(())
    }

    #[test]
    fn provider_transform_preserves_recursive_validation_semantics()
    -> Result<(), Box<dyn std::error::Error>> {
        let canonical = cognitive_understanding_answer_schema();
        let provider = provider_compatible_reader_schema(&canonical)?;
        assert!(canonical.get("$schema").is_some());
        assert!(provider.get("$schema").is_none());
        assert_eq!(
            schema_validation_projection(&canonical),
            schema_validation_projection(&provider)
        );
        Ok(())
    }

    #[test]
    fn desired_state_is_array_in_provider_contract() -> Result<(), Box<dyn std::error::Error>> {
        let canonical = cognitive_understanding_answer_schema();
        let provider = provider_compatible_reader_schema(&canonical)?;
        let mut valid = serde_json::to_value(complete_reader(CognitiveMemoryCondition::Treatment))?;
        valid["desired_state"] = json!([]);
        validate_json_schema_instance(&canonical, &valid, "canonical desired_state array")?;
        validate_json_schema_instance(&provider, &valid, "provider desired_state array")?;

        let mut invalid = valid;
        invalid["desired_state"] = json!("text");
        let canonical_error =
            validate_json_schema_instance(&canonical, &invalid, "canonical desired_state");
        let provider_error =
            validate_json_schema_instance(&provider, &invalid, "provider desired_state");
        assert!(canonical_error.is_err());
        assert!(provider_error.is_err());
        let canonical_message = canonical_error
            .err()
            .ok_or("canonical schema accepted desired_state string")?
            .to_string();
        let provider_message = provider_error
            .err()
            .ok_or("provider schema accepted desired_state string")?
            .to_string();
        assert!(canonical_message.contains("/desired_state"));
        assert!(provider_message.contains("/desired_state"));
        Ok(())
    }

    #[test]
    fn nested_causal_hop_is_closed_and_typed() -> Result<(), Box<dyn std::error::Error>> {
        let canonical = cognitive_understanding_answer_schema();
        let provider = provider_compatible_reader_schema(&canonical)?;
        let valid = serde_json::to_value(complete_reader(CognitiveMemoryCondition::Treatment))?;
        for field in [
            "hop_kind",
            "from",
            "relation",
            "to",
            "evidence_refs",
            "status",
        ] {
            let mut missing = valid.clone();
            missing["causal_hops"][0]
                .as_object_mut()
                .ok_or("causal hop object")?
                .remove(field);
            assert!(
                validate_json_schema_instance(&canonical, &missing, "missing causal field")
                    .is_err()
            );
            assert!(
                validate_json_schema_instance(&provider, &missing, "missing causal field").is_err()
            );

            let mut wrong = valid.clone();
            wrong["causal_hops"][0][field] = if field == "evidence_refs" {
                json!("not-an-array")
            } else {
                json!(7)
            };
            assert!(
                validate_json_schema_instance(&canonical, &wrong, "wrong causal field type")
                    .is_err()
            );
            assert!(
                validate_json_schema_instance(&provider, &wrong, "wrong causal field type")
                    .is_err()
            );
        }
        let mut additional = valid;
        additional["causal_hops"][0]["seventh"] = json!(true);
        assert!(
            validate_json_schema_instance(&canonical, &additional, "additional causal field")
                .is_err()
        );
        assert!(
            validate_json_schema_instance(&provider, &additional, "additional causal field")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn treatment_and_control_reader_fixtures_preserve_binding_and_isolation()
    -> Result<(), Box<dyn std::error::Error>> {
        let canonical = cognitive_understanding_answer_schema();
        let provider = provider_compatible_reader_schema(&canonical)?;
        for condition in [
            CognitiveMemoryCondition::Treatment,
            CognitiveMemoryCondition::MemoryFreeControl,
        ] {
            let reader = complete_reader(condition);
            let value = serde_json::to_value(&reader)?;
            validate_json_schema_instance(&canonical, &value, "canonical bound fixture")?;
            validate_json_schema_instance(&provider, &value, "provider bound fixture")?;
            let roundtrip: CognitiveUnderstandingAnswer = serde_json::from_value(value)?;
            let execution = CognitiveFieldExecutionKey {
                case_id: reader.case_id.clone(),
                memory_condition: condition,
            };
            let deterministic = CognitiveDeterministicReport {
                schema_version: COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION.to_owned(),
                case_id: reader.case_id.clone(),
                project_id: reader.project_id,
                task_id: reader.task_id,
                source_commit: "a".repeat(40),
                verifier_refs: vec!["verifier:test".to_owned()],
                hard_gate_evidence: Vec::new(),
                controller_provider_calls: 0,
                truth_revision_before: "revision:1".to_owned(),
                truth_revision_after_observability: "revision:1".to_owned(),
                report_hash: "report".to_owned(),
                passed: true,
            };
            validate_reader_output(&roundtrip, &execution, &deterministic)?;
            if condition == CognitiveMemoryCondition::MemoryFreeControl {
                assert!(roundtrip.memory_handles_received.is_empty());
                assert!(roundtrip.memory_handles_expanded.is_empty());
                assert!(roundtrip.memory_handles_used.is_empty());
                assert!(roundtrip.influence_receipt_refs.is_empty());
            }
        }
        Ok(())
    }

    #[test]
    fn reader_prompt_binds_exact_generated_schema_and_hash_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let template = fs::read_to_string(
            suite_root.join("tests/cognitive/field-v2/templates/reader-prompt.txt"),
        )?;
        let provider_schema =
            provider_compatible_reader_schema(&cognitive_understanding_answer_schema())?;
        let contract = render_provider_contract(&provider_schema)?;
        let prompt = render_reader_prompt(&template, &contract)?;
        assert_eq!(prompt.matches(&contract.canonical_json).count(), 1);
        assert_eq!(prompt.matches(&contract.sha256).count(), 1);
        assert_eq!(
            sha256_bytes(contract.canonical_json.as_bytes()),
            contract.sha256
        );
        assert!(!prompt.contains("all plural fields are arrays"));
        assert!(!prompt.contains("do not emit any key other than"));
        assert_eq!(
            provider_schema["properties"]["desired_state"]["type"],
            json!("array")
        );
        let (_, canonical_hash, provider_hash) =
            provider_test_prompt(CognitiveFieldRole::UnderstandingReader, "reader")?;
        assert_eq!(provider_hash, contract.sha256);
        assert_ne!(canonical_hash, provider_hash);
        Ok(())
    }

    #[test]
    fn provider_transform_rejects_at_least_one_hundred_invalid_mutations()
    -> Result<(), Box<dyn std::error::Error>> {
        let canonical = cognitive_understanding_answer_schema();
        let provider = provider_compatible_reader_schema(&canonical)?;
        let valid = serde_json::to_value(complete_reader(CognitiveMemoryCondition::Treatment))?;
        let required = canonical["required"]
            .as_array()
            .ok_or("required field array")?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let array_fields = canonical["properties"]
            .as_object()
            .ok_or("properties object")?
            .iter()
            .filter(|(_, schema)| schema.get("type") == Some(&json!("array")))
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        assert!(!required.is_empty());
        assert!(!array_fields.is_empty());
        for index in 0..120_usize {
            let mut mutation = valid.clone();
            match index % 6 {
                0 => {
                    let field = &array_fields[index % array_fields.len()];
                    mutation[field] = json!("wrong-array-type");
                }
                1 => {
                    let field = &required[index % required.len()];
                    mutation
                        .as_object_mut()
                        .ok_or("reader object")?
                        .remove(field);
                }
                2 => mutation["unknown_contract_field"] = json!(index),
                3 => mutation["memory_condition"] = json!("invalid_condition"),
                4 => mutation["causal_hops"][0]["evidence_refs"] = json!([7]),
                _ => mutation["confidence_by_section"]["project_purpose"] = json!(256),
            }
            assert!(
                validate_json_schema_instance(
                    &canonical,
                    &mutation,
                    "canonical deterministic mutation"
                )
                .is_err(),
                "canonical schema accepted mutation {index}"
            );
            assert!(
                validate_json_schema_instance(
                    &provider,
                    &mutation,
                    "provider deterministic mutation"
                )
                .is_err(),
                "provider schema widened semantics for mutation {index}"
            );
        }
        Ok(())
    }

    #[test]
    fn reader_contract_has_one_rust_owner_and_placeholder_only_template()
    -> Result<(), Box<dyn std::error::Error>> {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let owner =
            fs::read_to_string(workspace.join("crates/eliot-types/src/cognitive_field.rs"))?;
        let runner =
            fs::read_to_string(workspace.join("crates/eliot-app/src/cognitive_field_runner.rs"))?;
        let template = fs::read_to_string(
            workspace.join("tests/cognitive/field-v2/templates/reader-prompt.txt"),
        )?;
        assert_eq!(
            owner
                .matches("schema_for!(CognitiveUnderstandingAnswer)")
                .count(),
            1
        );
        let production_runner = runner
            .split("#[cfg(test)]")
            .next()
            .ok_or("production runner section")?;
        let forbidden_derivation = ["schema_for!(", "CognitiveUnderstandingAnswer", ")"].concat();
        assert_eq!(production_runner.matches(&forbidden_derivation).count(), 0);
        assert_eq!(template.matches(READER_SCHEMA_JSON_PLACEHOLDER).count(), 1);
        assert_eq!(
            template.matches(READER_SCHEMA_SHA256_PLACEHOLDER).count(),
            1
        );
        assert!(!template.contains("all plural fields are arrays"));
        assert!(!template.contains("`desired_state`"));
        assert!(!template.contains("do not emit any key other than"));
        Ok(())
    }

    #[test]
    fn generated_private_oracle_values_are_absent_from_the_versioned_suite()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let suite_bytes = std::fs::read(root.join("tests/cognitive/field-v2/suite.json"))?;
        let suite: CognitiveFieldSuite = serde_json::from_slice(&suite_bytes)?;
        let contract = CognitiveFieldRunContract {
            schema_version: COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION.to_owned(),
            run_id: "preflight-test".to_owned(),
            suite_sha256: sha256_bytes(&suite_bytes),
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            primary_repository: "C:/primary".to_owned(),
            second_repository: "C:/second".to_owned(),
            second_repository_commit: "fedcba9876543210fedcba9876543210fedcba98".to_owned(),
            output_root: "C:/reports".to_owned(),
            private_root_sha256: "private-root".to_owned(),
            hard_provider_call_cap: suite.hard_provider_call_cap,
            contract_hash: "contract".to_owned(),
            sealed_at: OffsetDateTime::UNIX_EPOCH,
        };
        for (index, case) in suite.cases.iter().enumerate() {
            let mut oracle = generated_oracle(case, index, &contract, &suite_bytes);
            CognitiveFieldGradingService::seal_oracle(&mut oracle)?;
            let scan = CognitiveFieldGradingService::scan_reader_surfaces(
                &oracle,
                &[("suite-manifest".to_owned(), suite_bytes.clone())],
            );
            assert!(scan.clean, "{}: {:?}", case.case_id, scan.findings);
        }
        Ok(())
    }

    #[test]
    fn windows_verbatim_prefix_does_not_change_field_path_identity() {
        let ordinary = Path::new(r"C:\field\run");
        let verbatim = Path::new(r"\\?\C:\field\run");
        assert_eq!(
            super::canonical_path(ordinary),
            super::canonical_path(verbatim)
        );
        assert!(super::contract_path_matches(
            verbatim,
            &super::canonical_path(ordinary)
        ));
    }

    #[test]
    fn deterministic_receipt_requires_real_private_logs_and_exact_hashes()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-cognitive-deterministic-receipt-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root)?;
        let stdout = root.join("stdout.log");
        let stderr = root.join("stderr.log");
        fs::write(&stdout, b"focused verifier passed\n")?;
        fs::write(&stderr, b"")?;
        let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let suite: CognitiveFieldSuite = serde_json::from_slice(&fs::read(
            suite_root.join("tests/cognitive/field-v2/suite.json"),
        )?)?;
        let case = suite
            .cases
            .iter()
            .find(|case| case.case_id == "U01")
            .ok_or("find U01")?;
        let contract = CognitiveFieldRunContract {
            schema_version: COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION.to_owned(),
            run_id: "receipt-test".to_owned(),
            suite_sha256: "0".repeat(64),
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            primary_repository: "C:/primary".to_owned(),
            second_repository: "C:/second".to_owned(),
            second_repository_commit: "fedcba9876543210fedcba9876543210fedcba98".to_owned(),
            output_root: "C:/reports".to_owned(),
            private_root_sha256: sha256_bytes(root.to_string_lossy().as_bytes()),
            hard_provider_call_cap: suite.hard_provider_call_cap,
            contract_hash: "contract".to_owned(),
            sealed_at: OffsetDateTime::UNIX_EPOCH,
        };
        let mut receipt = CognitiveDeterministicEvidenceReceipt {
            schema_version: COGNITIVE_DETERMINISTIC_EVIDENCE_SCHEMA_VERSION.to_owned(),
            run_id: contract.run_id.clone(),
            case_id: case.case_id.clone(),
            memory_condition: CognitiveMemoryCondition::Treatment,
            source_commit: contract.source_commit.clone(),
            verifier_refs: case.deterministic_verifier_refs.clone(),
            commands: vec![CognitiveVerifierCommandReceipt {
                command_ref: "cargo:test/cognitive_field_grading".to_owned(),
                arguments_sha256: "1".repeat(64),
                exit_code: 0,
                elapsed_ms: 12,
                stdout_path: stdout.to_string_lossy().into_owned(),
                stdout_sha256: sha256_bytes(&fs::read(&stdout)?),
                stderr_path: stderr.to_string_lossy().into_owned(),
                stderr_sha256: sha256_bytes(&fs::read(&stderr)?),
            }],
            controller_provider_calls: 0,
            truth_revision_before: "revision:1".to_owned(),
            truth_revision_after_observability: "revision:1".to_owned(),
        };
        validate_deterministic_receipt(
            &contract,
            case,
            CognitiveMemoryCondition::Treatment,
            &fs::canonicalize(&root)?,
            &receipt,
        )?;
        receipt.commands[0].stdout_sha256 = "2".repeat(64);
        assert!(
            validate_deterministic_receipt(
                &contract,
                case,
                CognitiveMemoryCondition::Treatment,
                &fs::canonicalize(&root)?,
                &receipt,
            )
            .is_err()
        );
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn provider_plan_covers_three_isolated_roles_with_bounded_calls()
    -> Result<(), Box<dyn std::error::Error>> {
        let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let suite: CognitiveFieldSuite = serde_json::from_slice(&fs::read(
            suite_root.join("tests/cognitive/field-v2/suite.json"),
        )?)?;
        let private_root =
            std::env::temp_dir().join(format!("eliot-cognitive-provider-plan-{}", Uuid::new_v4()));
        fs::create_dir_all(private_root.join("prompts"))?;
        let private_root = fs::canonicalize(private_root)?;
        let mut calls = Vec::new();
        let mut by_role_condition = BTreeMap::<
            (CognitiveFieldRole, CognitiveMemoryCondition),
            Vec<CognitiveFieldExecutionKey>,
        >::new();
        let smoke_role = |case_id: &str| match case_id {
            "H01" => Some(CognitiveFieldRole::CodexWorker),
            "H02" | "H03" | "H04" => Some(CognitiveFieldRole::UnderstandingReader),
            _ => None,
        };
        for case in suite.cases.iter().filter(|case| case.model_backed) {
            for condition in execution_conditions(case) {
                for role in &case.required_roles {
                    if smoke_role(&case.case_id) == Some(*role)
                        && condition == CognitiveMemoryCondition::Treatment
                    {
                        continue;
                    }
                    by_role_condition
                        .entry((*role, condition))
                        .or_default()
                        .push(CognitiveFieldExecutionKey {
                            case_id: case.case_id.clone(),
                            memory_condition: condition,
                        });
                }
            }
        }
        for executions in by_role_condition.values_mut() {
            executions.sort();
        }
        let model = |host: AgentHostId| match host {
            AgentHostId::Codex => "gpt-5.6-codex",
            AgentHostId::Claude => "claude-opus-5",
            AgentHostId::Antigravity => "gemini-3-flash",
            AgentHostId::OpenCode => "openai/gpt-5.6-codex",
        };
        let mut add_call = |role: CognitiveFieldRole,
                            host: AgentHostId,
                            provider_smoke: bool,
                            executions: Vec<CognitiveFieldExecutionKey>|
         -> Result<(), Box<dyn std::error::Error>> {
            let call_number = u8::try_from(calls.len() + 1)?;
            let call_id = format!("field-call-{call_number:02}");
            let prompt_ref = format!("prompts/{call_id}.txt");
            let (prompt, canonical_schema_sha256, provider_schema_sha256) =
                provider_test_prompt(role, &call_id)?;
            fs::write(private_root.join(&prompt_ref), prompt.as_bytes())?;
            let executable = private_root
                .join("providers")
                .join(format!("{call_id}.exe"));
            let (
                expected_provider_executable_sha256,
                runtime_contract_ref,
                runtime_contract_sha256,
            ) = provider_test_runtime(&private_root, host, &call_id, &executable)?;
            calls.push(CognitiveFieldProviderCallPlan {
                call_number,
                call_id,
                role,
                host,
                requested_model: model(host).to_owned(),
                expected_provider_executable_sha256,
                prompt_ref,
                prompt_sha256: sha256_bytes(prompt.as_bytes()),
                canonical_schema_sha256,
                provider_schema_sha256,
                provider_smoke,
                counts_against_cap: !provider_smoke,
                executions,
                runtime_contract_ref,
                runtime_contract_sha256,
                adapter_id: String::new(),
                adapter_version: String::new(),
                execution_request_ref: String::new(),
                execution_request_sha256: String::new(),
            });
            Ok(())
        };
        for (case_id, host, role) in [
            ("H01", AgentHostId::Codex, CognitiveFieldRole::CodexWorker),
            (
                "H02",
                AgentHostId::Claude,
                CognitiveFieldRole::UnderstandingReader,
            ),
            (
                "H03",
                AgentHostId::Antigravity,
                CognitiveFieldRole::UnderstandingReader,
            ),
            (
                "H04",
                AgentHostId::OpenCode,
                CognitiveFieldRole::UnderstandingReader,
            ),
        ] {
            add_call(
                role,
                host,
                true,
                vec![CognitiveFieldExecutionKey {
                    case_id: case_id.to_owned(),
                    memory_condition: CognitiveMemoryCondition::Treatment,
                }],
            )?;
        }
        for role in [
            CognitiveFieldRole::CodexWorker,
            CognitiveFieldRole::UnderstandingReader,
            CognitiveFieldRole::CodexJudge,
        ] {
            let host = if role == CognitiveFieldRole::UnderstandingReader {
                AgentHostId::Claude
            } else {
                AgentHostId::Codex
            };
            for (condition, target_chunks) in [
                (CognitiveMemoryCondition::Treatment, 4_usize),
                (CognitiveMemoryCondition::MemoryFreeControl, 2),
                (CognitiveMemoryCondition::RawCorpus, 1),
                (CognitiveMemoryCondition::DistilledCorpus, 1),
            ] {
                let executions = by_role_condition
                    .remove(&(role, condition))
                    .ok_or("missing role/condition executions")?;
                let chunk_size = executions.len().div_ceil(target_chunks);
                for chunk in executions.chunks(chunk_size) {
                    add_call(role, host, false, chunk.to_vec())?;
                }
            }
        }
        let (capped, smokes) = validate_provider_calls(&suite, &calls, &private_root)?;
        assert_eq!(capped, suite.hard_provider_call_cap);
        assert_eq!(smokes, 4);
        assert_eq!(usize::from(capped) + usize::from(smokes), calls.len());

        calls[0].requested_model = "opus".to_owned();
        assert!(validate_provider_calls(&suite, &calls, &private_root).is_err());
        fs::remove_dir_all(&private_root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn core_provider_plan_uses_four_fresh_calls_per_scenario()
    -> Result<(), Box<dyn std::error::Error>> {
        let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let mut suite: CognitiveFieldSuite = serde_json::from_slice(&fs::read(
            suite_root.join("tests/cognitive/field-v2/suite.json"),
        )?)?;
        suite.harness_version = COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION.to_owned();
        suite.hard_provider_call_cap = COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS;
        suite
            .cases
            .retain(|case| matches!(case.case_id.as_str(), "U03" | "U06" | "U11"));

        let private_root =
            std::env::temp_dir().join(format!("eliot-core-provider-plan-{}", Uuid::new_v4()));
        fs::create_dir_all(private_root.join("prompts"))?;
        let private_root = fs::canonicalize(private_root)?;
        let mut calls = Vec::new();
        for (case_id, reader_host, reader_model) in [
            ("U03", AgentHostId::Claude, "claude-opus-5"),
            ("U06", AgentHostId::Antigravity, "gemini-3-flash"),
            ("U11", AgentHostId::OpenCode, "openai/gpt-5.6-codex"),
        ] {
            for (role, host, model, conditions) in [
                (
                    CognitiveFieldRole::CodexWorker,
                    AgentHostId::Codex,
                    "gpt-5.6-codex",
                    vec![
                        CognitiveMemoryCondition::Treatment,
                        CognitiveMemoryCondition::MemoryFreeControl,
                    ],
                ),
                (
                    CognitiveFieldRole::UnderstandingReader,
                    reader_host,
                    reader_model,
                    vec![CognitiveMemoryCondition::Treatment],
                ),
                (
                    CognitiveFieldRole::UnderstandingReader,
                    reader_host,
                    reader_model,
                    vec![CognitiveMemoryCondition::MemoryFreeControl],
                ),
                (
                    CognitiveFieldRole::CodexJudge,
                    AgentHostId::Codex,
                    "gpt-5.6-codex",
                    vec![
                        CognitiveMemoryCondition::Treatment,
                        CognitiveMemoryCondition::MemoryFreeControl,
                    ],
                ),
            ] {
                let call_number = u8::try_from(calls.len() + 1)?;
                let call_id = format!("core-call-{call_number:02}");
                let prompt_ref = format!("prompts/{call_id}.txt");
                let (prompt, canonical_schema_sha256, provider_schema_sha256) =
                    provider_test_prompt(role, &call_id)?;
                fs::write(private_root.join(&prompt_ref), prompt.as_bytes())?;
                let executable = private_root
                    .join("providers")
                    .join(format!("{call_id}.exe"));
                let (
                    expected_provider_executable_sha256,
                    runtime_contract_ref,
                    runtime_contract_sha256,
                ) = provider_test_runtime(&private_root, host, &call_id, &executable)?;
                let mut executions = conditions
                    .into_iter()
                    .map(|memory_condition| CognitiveFieldExecutionKey {
                        case_id: case_id.to_owned(),
                        memory_condition,
                    })
                    .collect::<Vec<_>>();
                executions.sort();
                calls.push(CognitiveFieldProviderCallPlan {
                    call_number,
                    call_id,
                    role,
                    host,
                    requested_model: model.to_owned(),
                    expected_provider_executable_sha256,
                    prompt_ref,
                    prompt_sha256: sha256_bytes(prompt.as_bytes()),
                    canonical_schema_sha256,
                    provider_schema_sha256,
                    provider_smoke: false,
                    counts_against_cap: true,
                    executions,
                    runtime_contract_ref,
                    runtime_contract_sha256,
                    adapter_id: String::new(),
                    adapter_version: String::new(),
                    execution_request_ref: String::new(),
                    execution_request_sha256: String::new(),
                });
            }
        }

        let (capped, smokes) = validate_provider_calls(&suite, &calls, &private_root)?;
        assert_eq!(capped, COGNITIVE_CORE_QUALIFICATION_PROVIDER_CALLS);
        assert_eq!(smokes, 0);
        assert_eq!(calls.len(), 12);

        calls[1].host = AgentHostId::OpenCode;
        assert!(validate_provider_calls(&suite, &calls, &private_root).is_err());
        fs::remove_dir_all(&private_root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn core_provider_preflight_accepts_eight_fresh_calls_plus_four_exact_u03_roles()
    -> Result<(), Box<dyn std::error::Error>> {
        let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let mut suite: CognitiveFieldSuite = serde_json::from_slice(&fs::read(
            suite_root.join("tests/cognitive/field-v2/suite.json"),
        )?)?;
        suite.harness_version = COGNITIVE_CORE_QUALIFICATION_HARNESS_VERSION.to_owned();
        suite.hard_provider_call_cap = eliot_types::COGNITIVE_CORE_CONTINUATION_MAX_PROVIDER_CALLS;
        suite
            .cases
            .retain(|case| matches!(case.case_id.as_str(), "U03" | "U06" | "U11"));
        let private_root =
            std::env::temp_dir().join(format!("eliot-core-resume-plan-{}", Uuid::new_v4()));
        fs::create_dir_all(private_root.join("prompts"))?;
        let private_root = fs::canonicalize(private_root)?;
        let mut calls = Vec::new();
        for (case_id, reader_host, reader_model) in [
            ("U03", AgentHostId::Claude, "claude-opus-5"),
            ("U06", AgentHostId::Antigravity, "gemini-3.6-flash-high"),
            ("U11", AgentHostId::OpenCode, "openai/gpt-5.4"),
        ] {
            for (role, host, model, conditions) in [
                (
                    CognitiveFieldRole::CodexWorker,
                    AgentHostId::Codex,
                    "gpt-5.6-sol",
                    vec![
                        CognitiveMemoryCondition::Treatment,
                        CognitiveMemoryCondition::MemoryFreeControl,
                    ],
                ),
                (
                    CognitiveFieldRole::UnderstandingReader,
                    reader_host,
                    reader_model,
                    vec![CognitiveMemoryCondition::Treatment],
                ),
                (
                    CognitiveFieldRole::UnderstandingReader,
                    reader_host,
                    reader_model,
                    vec![CognitiveMemoryCondition::MemoryFreeControl],
                ),
                (
                    CognitiveFieldRole::CodexJudge,
                    AgentHostId::Codex,
                    "gpt-5.6-sol",
                    vec![
                        CognitiveMemoryCondition::Treatment,
                        CognitiveMemoryCondition::MemoryFreeControl,
                    ],
                ),
            ] {
                if case_id == "U03" {
                    continue;
                }
                let call_number = u8::try_from(calls.len() + 1)?;
                let call_id = format!("resumed-call-{call_number:02}");
                let prompt_ref = format!("prompts/{call_id}.txt");
                let (prompt, canonical_schema_sha256, provider_schema_sha256) =
                    provider_test_prompt(role, &call_id)?;
                fs::write(private_root.join(&prompt_ref), prompt.as_bytes())?;
                let executable = private_root
                    .join("providers")
                    .join(format!("{call_id}.exe"));
                let (
                    expected_provider_executable_sha256,
                    runtime_contract_ref,
                    runtime_contract_sha256,
                ) = provider_test_runtime(&private_root, host, &call_id, &executable)?;
                let mut executions = conditions
                    .into_iter()
                    .map(|memory_condition| CognitiveFieldExecutionKey {
                        case_id: case_id.to_owned(),
                        memory_condition,
                    })
                    .collect::<Vec<_>>();
                executions.sort();
                calls.push(CognitiveFieldProviderCallPlan {
                    call_number,
                    call_id,
                    role,
                    host,
                    requested_model: model.to_owned(),
                    expected_provider_executable_sha256,
                    prompt_ref,
                    prompt_sha256: sha256_bytes(prompt.as_bytes()),
                    canonical_schema_sha256,
                    provider_schema_sha256,
                    provider_smoke: false,
                    counts_against_cap: true,
                    executions,
                    runtime_contract_ref,
                    runtime_contract_sha256,
                    adapter_id: String::new(),
                    adapter_version: String::new(),
                    execution_request_ref: String::new(),
                    execution_request_sha256: String::new(),
                });
            }
        }
        let mut sources = calls
            .iter()
            .map(|call| CoreRoleEvidenceSource::FreshProviderCall {
                planned_call_id: call.call_id.clone(),
            })
            .collect::<Vec<_>>();
        sources.extend(core_reused_role_sources()?);
        let (fresh, smokes) =
            validate_provider_calls_with_sources(&suite, &calls, &private_root, &sources)?;
        assert_eq!(fresh, 8);
        assert_eq!(smokes, 0);
        assert_eq!(calls.len() + 4, 12);

        let treatment_index = sources
            .iter()
            .position(|source| {
                matches!(
                    source,
                    CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
                        role: CognitiveFieldRole::UnderstandingReader,
                        executions,
                        ..
                    } if executions[0].memory_condition == CognitiveMemoryCondition::Treatment
                )
            })
            .ok_or("find treatment Reader source")?;
        if let CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
            artifact_sha256, ..
        } = &mut sources[treatment_index]
        {
            *artifact_sha256 = "5".repeat(64);
        }
        assert!(
            validate_provider_calls_with_sources(&suite, &calls, &private_root, &sources).is_err()
        );

        sources = calls
            .iter()
            .map(|call| CoreRoleEvidenceSource::FreshProviderCall {
                planned_call_id: call.call_id.clone(),
            })
            .chain(core_reused_role_sources()?)
            .collect();
        if let Some(CoreRoleEvidenceSource::AcceptedPriorRoleArtifact { case_id, .. }) =
            sources.iter_mut().find(|source| {
                matches!(
                    source,
                    CoreRoleEvidenceSource::AcceptedPriorRoleArtifact {
                        role: CognitiveFieldRole::CodexWorker,
                        ..
                    }
                )
            })
        {
            *case_id = "U06".to_owned();
        }
        assert!(
            validate_provider_calls_with_sources(&suite, &calls, &private_root, &sources).is_err()
        );
        fs::remove_dir_all(&private_root)?;
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one fixture exercises runtime, model, timeout, control-isolation, and binary-drift gates"
    )]
    fn provider_receipt_rejects_aliases_unknown_outcomes_and_binary_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let private_root = std::env::temp_dir().join(format!(
            "eliot-cognitive-provider-receipt-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(private_root.join("prompts"))?;
        let executable = private_root.join("claude.exe");
        let prompt = private_root.join("prompts/reader-01.txt");
        fs::write(&executable, b"provider executable fixture")?;
        fs::write(&prompt, b"isolated reader prompt")?;
        let private_root = fs::canonicalize(private_root)?;
        let execution = CognitiveFieldExecutionKey {
            case_id: "U01".to_owned(),
            memory_condition: CognitiveMemoryCondition::Treatment,
        };
        let model = "claude-opus-5";
        let (executable_sha256, runtime_contract_ref, runtime_contract_sha256) =
            provider_test_runtime(&private_root, AgentHostId::Claude, "reader-01", &executable)?;
        let prompt_sha256 = sha256_bytes(&fs::read(&prompt)?);
        let (_, canonical_schema_sha256, provider_schema_sha256) =
            provider_test_prompt(CognitiveFieldRole::UnderstandingReader, "reader-01")?;
        let call = CognitiveFieldProviderCallPlan {
            call_number: 1,
            call_id: "reader-01".to_owned(),
            role: CognitiveFieldRole::UnderstandingReader,
            host: AgentHostId::Claude,
            requested_model: model.to_owned(),
            expected_provider_executable_sha256: executable_sha256.clone(),
            prompt_ref: "prompts/reader-01.txt".to_owned(),
            prompt_sha256: prompt_sha256.clone(),
            canonical_schema_sha256,
            provider_schema_sha256,
            provider_smoke: false,
            counts_against_cap: true,
            executions: vec![execution.clone()],
            runtime_contract_ref,
            runtime_contract_sha256: runtime_contract_sha256.clone(),
            adapter_id: String::new(),
            adapter_version: String::new(),
            execution_request_ref: String::new(),
            execution_request_sha256: String::new(),
        };
        let mut receipt = CognitiveFieldProviderEvidenceReceipt {
            schema_version: eliot_types::COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION
                .to_owned(),
            run_id: "run".to_owned(),
            contract_hash: "contract".to_owned(),
            provider_plan_hash: "plan".to_owned(),
            source_commit: "a".repeat(40),
            call_id: call.call_id.clone(),
            role: call.role,
            host: call.host,
            requested_model: model.to_owned(),
            resolved_model: model.to_owned(),
            provider_session_id: "session-1".to_owned(),
            provider_receipt_ref: "provider-receipt-1".to_owned(),
            provider_executable: executable.to_string_lossy().into_owned(),
            provider_executable_sha256: executable_sha256,
            prompt_path: prompt.to_string_lossy().into_owned(),
            prompt_sha256,
            raw_stdout_path: "stdout.json".to_owned(),
            raw_stdout_sha256: "b".repeat(64),
            raw_stderr_path: "stderr.log".to_owned(),
            raw_stderr_sha256: "c".repeat(64),
            outputs: vec![CognitiveFieldProviderOutputReceipt {
                execution,
                output_path: "reader.json".to_owned(),
                output_sha256: "d".repeat(64),
            }],
            provider_calls: 1,
            exit_code: 0,
            elapsed_ms: 10,
            timed_out: false,
            unknown_outcome: false,
            controller_substitution: false,
            oracle_exposed: false,
            worker_transcript_exposed: false,
            read_only: true,
            runtime_contract_sha256,
            observed_mcp_server_names: Vec::new(),
            observed_mcp_tool_names: Vec::new(),
        };
        validate_provider_receipt_envelope(&call, &receipt, &private_root)?;
        let mut control_call = call.clone();
        control_call.executions[0].memory_condition = CognitiveMemoryCondition::MemoryFreeControl;
        receipt.observed_mcp_tool_names = vec!["eliot_recall_l0".to_owned()];
        let control_result =
            validate_provider_receipt_envelope(&control_call, &receipt, &private_root);
        assert!(control_result.is_err());
        receipt.observed_mcp_tool_names.clear();
        let accepted_runtime_sha256 = receipt.runtime_contract_sha256.clone();
        receipt.runtime_contract_sha256 = "e".repeat(64);
        assert!(validate_provider_receipt_envelope(&call, &receipt, &private_root).is_err());
        receipt.runtime_contract_sha256 = accepted_runtime_sha256;
        receipt.resolved_model = "opus".to_owned();
        assert!(validate_provider_receipt_envelope(&call, &receipt, &private_root).is_err());
        receipt.resolved_model = model.to_owned();
        receipt.unknown_outcome = true;
        assert!(validate_provider_receipt_envelope(&call, &receipt, &private_root).is_err());
        receipt.unknown_outcome = false;
        fs::write(&executable, b"drifted provider executable")?;
        assert!(validate_provider_receipt_envelope(&call, &receipt, &private_root).is_err());
        fs::remove_dir_all(&private_root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn provider_import_writes_only_sanitized_bound_reader_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-cognitive-provider-import-{}",
            Uuid::new_v4()
        ));
        let report_root = root.join("report");
        let private_root = root.join("private");
        fs::create_dir_all(&report_root)?;
        fs::create_dir_all(private_root.join("oracles"))?;
        fs::create_dir_all(private_root.join("prompts"))?;
        fs::create_dir_all(private_root.join("outputs"))?;
        let report_root = fs::canonicalize(report_root)?;
        let private_root = fs::canonicalize(private_root)?;
        let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("resolve workspace root")?;
        let suite_bytes = fs::read(suite_root.join("tests/cognitive/field-v2/suite.json"))?;
        let suite: CognitiveFieldSuite = serde_json::from_slice(&suite_bytes)?;
        let case = suite
            .cases
            .iter()
            .find(|case| case.case_id == "U01")
            .ok_or("find U01")?;
        let contract = CognitiveFieldRunContract {
            schema_version: COGNITIVE_FIELD_CONTRACT_SCHEMA_VERSION.to_owned(),
            run_id: "provider-import".to_owned(),
            suite_sha256: sha256_bytes(&suite_bytes),
            source_commit: super::git_commit(suite_root)?,
            primary_repository: suite_root.to_string_lossy().into_owned(),
            second_repository: "C:/second".to_owned(),
            second_repository_commit: "b".repeat(40),
            output_root: super::canonical_path(&report_root),
            private_root_sha256: sha256_bytes(super::canonical_path(&private_root).as_bytes()),
            hard_provider_call_cap: suite.hard_provider_call_cap,
            contract_hash: "contract".to_owned(),
            sealed_at: OffsetDateTime::UNIX_EPOCH,
        };
        write_new_or_same_json(&report_root.join("suite.json"), &suite)?;
        write_new_or_same_json(&report_root.join("contract.json"), &contract)?;

        let mut oracle = generated_oracle(case, 0, &contract, &suite_bytes);
        CognitiveFieldGradingService::seal_oracle(&mut oracle)?;
        write_new_or_same_json(&private_root.join("oracles/U01.json"), &oracle)?;
        let project_id = eliot_types::ProjectId::new_v7();
        let task_id = eliot_types::TaskId::new_v7();
        let mut deterministic = CognitiveDeterministicReport {
            schema_version: COGNITIVE_DETERMINISTIC_REPORT_SCHEMA_VERSION.to_owned(),
            case_id: case.case_id.clone(),
            project_id,
            task_id,
            source_commit: contract.source_commit.clone(),
            verifier_refs: case.deterministic_verifier_refs.clone(),
            hard_gate_evidence: suite
                .shared_hard_gates
                .iter()
                .copied()
                .map(|gate| CognitiveHardGateEvidence {
                    gate,
                    passed: true,
                    evidence_refs: vec!["test:provider-import".to_owned()],
                    explanation: "test hard gate passed".to_owned(),
                })
                .collect(),
            controller_provider_calls: 0,
            truth_revision_before: "revision:1".to_owned(),
            truth_revision_after_observability: "revision:1".to_owned(),
            report_hash: String::new(),
            passed: true,
        };
        CognitiveFieldGradingService::seal_deterministic_report(&mut deterministic)?;
        let evidence_root = report_root.join("evidence/U01/treatment");
        write_new_or_same_json(&evidence_root.join("deterministic.json"), &deterministic)?;

        let executable = private_root.join("claude.exe");
        let prompt = private_root.join("prompts/reader-01.txt");
        fs::write(&executable, b"provider executable fixture")?;
        fs::write(&prompt, b"isolated reader prompt without oracle")?;
        let model = "claude-opus-5";
        let execution = CognitiveFieldExecutionKey {
            case_id: "U01".to_owned(),
            memory_condition: CognitiveMemoryCondition::Treatment,
        };
        let (_, canonical_schema_sha256, provider_schema_sha256) =
            provider_test_prompt(CognitiveFieldRole::UnderstandingReader, "reader-01")?;
        let (expected_provider_executable_sha256, runtime_contract_ref, runtime_contract_sha256) =
            provider_test_runtime(&private_root, AgentHostId::Claude, "reader-01", &executable)?;
        let call = CognitiveFieldProviderCallPlan {
            call_number: 1,
            call_id: "reader-01".to_owned(),
            role: CognitiveFieldRole::UnderstandingReader,
            host: AgentHostId::Claude,
            requested_model: model.to_owned(),
            expected_provider_executable_sha256,
            prompt_ref: "prompts/reader-01.txt".to_owned(),
            prompt_sha256: sha256_bytes(&fs::read(&prompt)?),
            canonical_schema_sha256,
            provider_schema_sha256,
            provider_smoke: false,
            counts_against_cap: true,
            executions: vec![execution.clone()],
            runtime_contract_ref,
            runtime_contract_sha256: runtime_contract_sha256.clone(),
            adapter_id: String::new(),
            adapter_version: String::new(),
            execution_request_ref: String::new(),
            execution_request_sha256: String::new(),
        };
        let mut provider_plan = CognitiveFieldProviderPlan {
            schema_version: COGNITIVE_FIELD_PROVIDER_PLAN_SCHEMA_VERSION.to_owned(),
            run_id: contract.run_id.clone(),
            contract_hash: contract.contract_hash.clone(),
            calls: vec![call.clone()],
            planned_provider_calls: 1,
            planned_smoke_calls: 0,
            planned_reused_roles: 0,
            role_evidence_plan_hash: None,
            seal_attempt_id: None,
            seal_generation: 0,
            authority_activation_ref: None,
            runtime_manifest_sha256: None,
            artifact_manifest_sha256: None,
            plan_hash: String::new(),
            sealed_at: OffsetDateTime::UNIX_EPOCH,
        };
        provider_plan.plan_hash =
            CognitiveFieldGradingService::hash_json(&provider_plan_without_hash(&provider_plan))?;
        write_new_or_same_json(&report_root.join("provider-plan.json"), &provider_plan)?;

        let mut reader = minimal_cognitive_understanding_answer();
        reader.case_id = "U01".to_owned();
        reader.project_id = project_id;
        reader.task_id = task_id;
        reader.memory_condition = CognitiveMemoryCondition::Treatment;
        let reader_path = private_root.join("outputs/reader.json");
        write_new_or_same_json(&reader_path, &reader)?;
        let raw_stdout = private_root.join("raw.stdout.json");
        let raw_stderr = private_root.join("raw.stderr.log");
        fs::write(
            &raw_stdout,
            format!(
                "{{\"model\":\"{model}\",\"session\":\"session-1\",\"receipt\":\"provider-receipt-1\"}}"
            ),
        )?;
        fs::write(&raw_stderr, b"")?;
        let receipt = CognitiveFieldProviderEvidenceReceipt {
            schema_version: COGNITIVE_FIELD_PROVIDER_EVIDENCE_SCHEMA_VERSION.to_owned(),
            run_id: contract.run_id.clone(),
            contract_hash: contract.contract_hash.clone(),
            provider_plan_hash: provider_plan.plan_hash.clone(),
            source_commit: contract.source_commit.clone(),
            call_id: call.call_id.clone(),
            role: call.role,
            host: call.host,
            requested_model: model.to_owned(),
            resolved_model: model.to_owned(),
            provider_session_id: "session-1".to_owned(),
            provider_receipt_ref: "provider-receipt-1".to_owned(),
            provider_executable: executable.to_string_lossy().into_owned(),
            provider_executable_sha256: call.expected_provider_executable_sha256,
            prompt_path: prompt.to_string_lossy().into_owned(),
            prompt_sha256: call.prompt_sha256,
            raw_stdout_path: raw_stdout.to_string_lossy().into_owned(),
            raw_stdout_sha256: sha256_bytes(&fs::read(&raw_stdout)?),
            raw_stderr_path: raw_stderr.to_string_lossy().into_owned(),
            raw_stderr_sha256: sha256_bytes(&fs::read(&raw_stderr)?),
            outputs: vec![CognitiveFieldProviderOutputReceipt {
                execution,
                output_path: reader_path.to_string_lossy().into_owned(),
                output_sha256: sha256_bytes(&fs::read(&reader_path)?),
            }],
            provider_calls: 1,
            exit_code: 0,
            elapsed_ms: 12,
            timed_out: false,
            unknown_outcome: false,
            controller_substitution: false,
            oracle_exposed: false,
            worker_transcript_exposed: false,
            read_only: true,
            runtime_contract_sha256,
            observed_mcp_server_names: Vec::new(),
            observed_mcp_tool_names: Vec::new(),
        };
        let receipt_path = private_root.join("receipt.json");
        write_new_or_same_json(&receipt_path, &receipt)?;
        record_provider(&report_root, &private_root, &receipt_path)?;
        assert!(evidence_root.join("reader.json").is_file());
        let reader_binding: serde_json::Value =
            serde_json::from_slice(&fs::read(evidence_root.join("reader-binding.json"))?)?;
        assert_eq!(
            reader_binding["reader_output_hash"],
            CognitiveFieldGradingService::hash_json(&reader)?
        );
        assert_eq!(
            reader_binding["reader_output_sha256"],
            sha256_bytes(&fs::read(&reader_path)?)
        );
        assert!(evidence_root.join("provider-reader.json").is_file());
        assert!(
            report_root
                .join("provider-invocations/reader-01.json")
                .is_file()
        );
        assert!(!evidence_root.join("worker.json").exists());
        assert!(!evidence_root.join("judge.json").exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
