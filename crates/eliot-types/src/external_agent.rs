use crate::{
    AgentHostId, AgentInvocationRequest, AgentRole, AgentSessionHostBinding, AgentSessionId,
    AuthorityRevocationReceipt, HostLaunchContract, HostLaunchScope, OperationJob,
    OperationJobState, ProjectId, ProviderRoutePolicy, ProviderRoutePolicyBinding, TaskId,
    TaskRoleLease, WriteReceiptRef,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use time::OffsetDateTime;

pub const PROVIDER_RUNTIME_CONTRACT_SCHEMA_VERSION: &str = "eliot-provider-runtime-v2";
pub const PROVIDER_RUNTIME_PREFLIGHT_SCHEMA_VERSION: &str = "eliot-provider-runtime-preflight-v1";
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAgentPurpose {
    #[default]
    ProviderSmoke,
    ExternalAudit,
    CognitiveWorker,
    UnderstandingReader,
    MemoryFreeControl,
    CognitiveJudge,
    ReasoningJob,
    CapsuleRefinement,
    UnderstandingExam,
    McpPreflight,
}

pub const OPERATION_AUTHORITY_SCHEMA_VERSION: &str = "eliot-operation-authority-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAuthorityOpenRequest {
    pub schema_version: String,
    pub operation_id: String,
    pub purpose: ExternalAgentPurpose,
    pub generation: u64,
    pub host: AgentHostId,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub agent_session_id: AgentSessionId,
    pub role: AgentRole,
    pub capability_scope: Vec<String>,
    pub ttl_seconds: u64,
    pub client_instance_id: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAuthorityOpenReceipt {
    pub operation_id: String,
    pub purpose: ExternalAgentPurpose,
    pub generation: u64,
    pub launch_scope: HostLaunchScope,
    pub operation_job_id: String,
    pub role_authority_receipt: WriteReceiptRef,
    pub host_binding_authority_receipt: WriteReceiptRef,
    pub operation_job_authority_receipt: WriteReceiptRef,
    pub state_hash: String,
    pub idempotent_replay: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub opened_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationAuthorityTerminalOutcome {
    Completed,
    FailedBeforeDispatch,
    FailedAfterDispatch,
    Cancelled,
    TimedOut,
    ReconciledUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAuthorityCloseRequest {
    pub schema_version: String,
    pub operation_id: String,
    pub purpose: ExternalAgentPurpose,
    pub generation: u64,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub agent_session_id: AgentSessionId,
    pub role_lease_id: String,
    pub expected_epoch: u64,
    pub terminal_outcome: OperationAuthorityTerminalOutcome,
    pub result_or_failure_ref: Option<String>,
    pub reason: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAuthorityCloseReceipt {
    pub operation_id: String,
    pub purpose: ExternalAgentPurpose,
    pub generation: u64,
    pub authority_revocation_receipt: AuthorityRevocationReceipt,
    pub canonical_revoked_role_receipt: WriteReceiptRef,
    pub canonical_retired_binding_receipt: WriteReceiptRef,
    pub canonical_terminal_job_receipt: WriteReceiptRef,
    pub final_role_lease: TaskRoleLease,
    pub final_host_binding: AgentSessionHostBinding,
    pub final_operation_job: OperationJob,
    pub final_job_state: OperationJobState,
    pub state_hash: String,
    pub idempotent_replay: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStructuredOutputMode {
    NativeJsonSchema,
    NativeJson,
    #[default]
    SentinelJson,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAuthenticationState {
    Authenticated,
    Unauthenticated,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderMcpServerContract {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub required: bool,
    pub enabled: bool,
    pub executable_sha256: String,
    pub build_source_commit: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderMcpToolProfileBinding {
    pub profile_id: String,
    pub profile_hash_blake3: String,
    pub tool_names: Vec<String>,
}

impl ProviderMcpToolProfileBinding {
    pub fn new(profile_id: impl Into<String>, mut tool_names: Vec<String>) -> Self {
        let profile_id = profile_id.into();
        tool_names.sort();
        tool_names.dedup();
        let canonical = format!("{}\n{}", profile_id, tool_names.join("\n"));
        Self {
            profile_id,
            profile_hash_blake3: blake3::hash(canonical.as_bytes()).to_hex().to_string(),
            tool_names,
        }
    }

    pub fn hash_is_valid(&self) -> bool {
        Self::new(self.profile_id.clone(), self.tool_names.clone()).profile_hash_blake3
            == self.profile_hash_blake3
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRuntimeContract {
    pub schema_version: String,
    #[schemars(with = "String")]
    pub host: AgentHostId,
    #[serde(default)]
    pub purpose: ExternalAgentPurpose,

    pub provider_executable: String,
    pub provider_executable_sha256: String,
    #[serde(default)]
    pub provider_version: String,

    #[serde(default)]
    pub requested_model: String,
    #[serde(default)]
    pub model_selection_mechanism: String,

    pub provider_cwd: String,
    pub provider_argv: Vec<String>,
    pub nonsecret_environment: BTreeMap<String, String>,

    pub mcp_servers: Vec<ProviderMcpServerContract>,
    pub mcp_tool_profile: ProviderMcpToolProfileBinding,
    pub expected_mcp_tool_names: Vec<String>,
    pub forbidden_mcp_server_names: Vec<String>,

    #[serde(default)]
    pub allowed_provider_tools: Vec<String>,
    #[serde(default)]
    pub denied_provider_tools: Vec<String>,
    #[serde(default)]
    pub permission_profile: String,

    #[serde(default)]
    pub structured_output_mode: ProviderStructuredOutputMode,
    #[serde(default)]
    pub output_schema_sha256: String,

    #[serde(default)]
    pub timeout_profile_ref: String,
    pub provider_route_policy: ProviderRoutePolicyBinding,
    #[serde(default)]
    pub process_containment: String,
    #[serde(default)]
    pub candidate_only: bool,

    pub runtime_contract_sha256: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProviderRuntimePreflightReceipt {
    pub schema_version: String,
    pub runtime_contract_sha256: String,
    pub config_list_passed: bool,
    pub mcp_process_started: bool,
    pub mcp_initialized: bool,
    pub tools_listed: bool,
    pub expected_tools_present: bool,
    pub forbidden_servers_absent: bool,
    pub scoped_status_read_passed: bool,
    pub observed_server_names: Vec<String>,
    pub observed_tool_names: Vec<String>,
    pub governor_executable_sha256: String,
    pub governor_build_source_commit: Option<String>,
    pub elapsed_ms: u64,
}

/// Report-only compatibility surface for evidence created before the unified
/// provider runtime contract. Product runtime code must not construct these
/// values; it may only decode them when reading historical evidence.
pub mod legacy {
    use super::{ProviderMcpServerContract, ProviderRuntimePreflightReceipt};
    use crate::AgentHostId;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    pub const COGNITIVE_PROVIDER_RUNTIME_SCHEMA_VERSION: &str =
        "eliot-cognitive-provider-runtime-v1";
    pub const COGNITIVE_RUNTIME_PREFLIGHT_SCHEMA_VERSION: &str =
        "eliot-cognitive-runtime-preflight-v1";

    #[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct CognitiveProviderRuntimeContract {
        pub schema_version: String,
        #[schemars(with = "String")]
        pub host: AgentHostId,
        pub provider_executable: String,
        pub provider_executable_sha256: String,
        pub provider_cwd: String,
        pub provider_argv: Vec<String>,
        pub nonsecret_environment: BTreeMap<String, String>,
        pub mcp_servers: Vec<ProviderMcpServerContract>,
        pub expected_mcp_tool_names: Vec<String>,
        pub forbidden_mcp_server_names: Vec<String>,
        pub runtime_contract_sha256: String,
    }

    pub type CognitiveProviderMcpServer = ProviderMcpServerContract;
    pub type CognitiveRuntimePreflightReceipt = ProviderRuntimePreflightReceipt;
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAgentExecutionRequest {
    #[schemars(with = "Value")]
    pub invocation: AgentInvocationRequest,
    #[schemars(with = "Value")]
    pub launch_contract: HostLaunchContract,
    #[serde(default)]
    pub campaign_id: String,
    pub purpose: ExternalAgentPurpose,
    pub mcp_tool_profile: ProviderMcpToolProfileBinding,

    pub prompt_ref: String,
    pub prompt_sha256: String,
    pub output_schema_ref: String,
    pub output_schema_sha256: String,

    pub requested_model: String,
    pub max_turns_or_steps: u32,
    pub timeout_profile_ref: String,
    pub provider_route_policy: ProviderRoutePolicy,

    pub allowed_provider_tools: Vec<String>,
    pub denied_provider_tools: Vec<String>,
    pub expected_mcp_tool_names: Vec<String>,
    pub forbidden_mcp_server_names: Vec<String>,

    pub read_only: bool,
    pub candidate_only: bool,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecutionEvidence {
    pub runtime_contract_sha256: String,
    pub provider_route_policy: ProviderRoutePolicyBinding,

    pub requested_model: String,
    pub resolved_model: String,
    pub provider_session_id: String,

    pub exit_code: Option<i32>,
    pub terminal_status: String,
    pub unknown_outcome: bool,

    pub structured_output: Option<Value>,
    #[serde(default)]
    pub structured_output_ref: Option<String>,
    pub structured_output_sha256: Option<String>,

    pub stdout_ref: Option<String>,
    pub stdout_sha256: Option<String>,
    pub stderr_ref: Option<String>,
    pub stderr_sha256: Option<String>,

    pub observed_mcp_server_names: Vec<String>,
    pub observed_mcp_tool_names: Vec<String>,
    pub provider_tool_call_refs: Vec<String>,

    pub changed_paths: Vec<String>,
    pub diff_ref: Option<String>,

    pub token_or_cost_telemetry: Option<String>,
    pub duration_ms: u64,
}
// ---------------------------------------------------------------------------
// PRODUCTION INGRESS RECORDS (issue #933, Work step 7). Four residuals, gathered
// here at the END of the file on purpose: anchoring each block above its
// declaration reads better, but it shifts every later line number, and about
// thirty-four `external_agent.rs:<line>` citations live in other crates' suites,
// in the acceptance corpus, in `adapter.rs` and in `provider_invocation.rs`.
// A record whose own coordinates are wrong is worse than a record that is merely
// further from its declaration, and each block below names its declaration
// explicitly, so nothing is lost but adjacency.
//
// Block 1 -> `ProviderRuntimeContract` (declared below)
// Block 2 -> `legacy::CognitiveProviderRuntimeContract` (declared below)
// Block 3 -> `ExternalAgentExecutionRequest` (declared below)
// Block 4 -> `ProviderExecutionEvidence` (declared below)
//
// # Duplicate-key refusal on the sealed runtime-contract ingress is UNRESOLVED
//
// The `#[serde(deny_unknown_fields)]` decoder below refuses an unknown member,
// and serde's derived struct decoder refuses a REPEATED member, but that refusal
// is reachable only when RAW JSON TEXT reaches `Deserialize`. It is NOT reachable
// on the production ingress for this type:
//
// 1. `crates/eliot-app/src/provider_runtime_contract.rs:730` reads the sealed
//    on-disk contract as `let value: Value = read_json(&path)?;`.
// 2. `read_json` is `crates/eliot-app/src/cognitive_field_runner.rs:9123`, body
//    `serde_json::from_slice(&fs::read(path)?)`. At this call site the
//    `DeserializeOwned` parameter is instantiated as `serde_json::Value`, so the
//    file's raw bytes are parsed straight into a `Value`.
// 3. No `preserve_order` feature is enabled for `serde_json` anywhere in this
//    workspace (zero hits in `Cargo.lock` and in every crate manifest), so
//    `serde_json::Map` is a `BTreeMap` and a physically repeated member is
//    already collapsed LAST-WINS at `provider_runtime_contract.rs:730`.
// 4. `crates/eliot-app/src/provider_runtime_contract.rs:736` then decodes this
//    type with `serde_json::from_value(value)`. The repeat is gone before this
//    decoder runs, so on that path an ambiguous identity silently resolves to
//    the last occurrence instead of being refused.
//
// OWNER, NOT REPAIRED BY #933: the ingress is `eliot-app`'s
// `provider_runtime_contract::provider_runtime_contract`
// (`crates/eliot-app/src/provider_runtime_contract.rs:717`). Issue #933's
// production scope is four `eliot-types` files, so that caller is outside this
// issue and needs an ingress-owner repair; the duplicate-key row is therefore
// retained as UNRESOLVED under #933 Work step 7, which requires naming the exact
// location and owner, retaining the row, and completing independent local work.
//
// Governing rule, `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12`:
// "authority, scope, effect, privacy, ordering and receipt fields are never
// silently defaulted". #933 Work step 2 requires a duplicate to be refused
// "while reading the raw map, before insertion into Value/maps". That boundary is
// upstream of this type, so it cannot be met by a change here.
//
// The OTHER `from_value` ingress for this type is NOT a collapse residual:
// `crates/eliot-app/src/cognitive_field_runner.rs:5255` decodes
// `result.output.get("provider_runtime_contract").cloned()`, and
// `AdapterResult::output` is ALREADY a `serde_json::Value` field
// (`crates/eliot-types/src/adapter.rs:186`) that the adapter built in process, so
// no JSON text ever existed on that path and nothing was ever lost there. It is
// named here only so the next reader does not mistake it for the residual above.
// The legacy counterpart of [`super::ProviderRuntimeContract`] inherits that
// type's UNRESOLVED duplicate-key ingress unchanged.
// `crates/eliot-app/src/provider_runtime_contract.rs:740` decodes this type
// with `serde_json::from_value(value)` from the SAME `Value` that was already
// collapsed at `crates/eliot-app/src/provider_runtime_contract.rs:730`, so a
// physically repeated member of a sealed legacy contract file is resolved
// LAST-WINS before this decoder runs and the `#[serde(deny_unknown_fields)]`
// duplicate-key refusal is unreachable. The owner is the same
// `eliot-app` ingress `provider_runtime_contract::provider_runtime_contract`
// (`crates/eliot-app/src/provider_runtime_contract.rs:717`), which is outside
// #933's four-file production scope and is therefore NOT repaired by #933;
// the row stays UNRESOLVED under #933 Work step 7. See
// [`super::ProviderRuntimeContract`] for the full causal chain and for
// `docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md:12`.
//
// This remains report-only historical evidence: product runtime code must not
// construct these values, so repairing the ingress is a decode-hardening
// obligation, not a new authority surface.
// COVERED END TO END: every production ingress for this type hands RAW BYTES to
// the derived struct decoder, so a physically repeated member in the request text
// is refused here rather than collapsed into a last-wins `Value`. No `Value`
// intermediate exists on any production ingress:
// - `crates/eliot-app/src/cognitive_field_runner.rs:2086` decodes
//   `serde_json::from_slice(&request_bytes)` where `request_bytes` is
//   `fs::read(&request_path)` (`crates/eliot-app/src/cognitive_field_runner.rs:2085`).
// - `crates/eliot-app/src/cognitive_field_runner.rs:3446`, `:5202` and `:6601`
//   call `read_json(&request_path)`, which is
//   `crates/eliot-app/src/cognitive_field_runner.rs:9123`
//   (`serde_json::from_slice(&fs::read(path)?)`) instantiated with THIS type as
//   its `DeserializeOwned` parameter, not with `Value`.
// - `crates/eliot-app/src/provider_runtime_contract.rs:773` is the same
//   `read_json` helper with this type as its `DeserializeOwned` parameter, so it
//   is raw bytes too. Contrast `provider_runtime_contract.rs:730` in the same
//   file, which instantiates `Value` and is the unresolved residual recorded on
//   [`ProviderRuntimeContract`].
//
// The one `from_value` site for this type,
// `crates/eliot-app/src/host_runtime/external_agent.rs:2523`, decodes
// `request.input.clone()` where `AdapterRequest::input` is ALREADY a
// `serde_json::Value` (`crates/eliot-types/src/adapter.rs:151`) that production
// code builds in process with `serde_json::to_value` of an already-typed request
// (`crates/eliot-app/src/cognitive_field_runner.rs:5231`,
// `crates/eliot-app/src/host_runtime/external_agent.rs:2011`). No JSON text
// existed on that path, so it is a re-decode of a validated value, NOT a
// collapse residual. Recorded so the next reader does not repeat the
// measurement.
// NOT a collapse residual, and deliberately recorded as such.
// `crates/eliot-app/src/cognitive_field_runner.rs:5248` decodes this type with
// `serde_json::from_value`, but its input is
// `result.output.get("provider_execution_evidence").cloned()`
// (`crates/eliot-app/src/cognitive_field_runner.rs:5249` to `:5253`) and
// `result.output` is ALREADY a `serde_json::Value` field of `AdapterResult`
// (`crates/eliot-types/src/adapter.rs:186`) that the adapter built in process
// (`crates/eliot-app/src/host_runtime/external_agent.rs:3402`). There was never
// JSON TEXT on that path, so no repeated member was ever lost there and there is
// no ingress to repair. The `from_value` shape alone is not evidence of a
// collapse; the provenance of the `Value` is what decides it, exactly as for the
// second `from_value` site on [`ProviderRuntimeContract`].
