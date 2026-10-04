use crate::{
    AgentRole, AgentSessionId, BlackboardItemId, BlobRef, MailboxMessageId, ProjectId, TaintClass,
    TaskId, WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterClass {
    InternalTest,
    Health,
    LocalService,
    ExternalCandidate,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterCapability {
    HealthCheck,
    ExecuteTest,
    EmitCandidateObservation,
    EmitArtifactHandle,
    RequestControllerReview,
    WriteTruth,
    RequestPatch,
    FinishTask,
}

impl AdapterCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HealthCheck => "health_check",
            Self::ExecuteTest => "execute_test",
            Self::EmitCandidateObservation => "emit_candidate_observation",
            Self::EmitArtifactHandle => "emit_artifact_handle",
            Self::RequestControllerReview => "request_controller_review",
            Self::WriteTruth => "write_truth",
            Self::RequestPatch => "request_patch",
            Self::FinishTask => "finish_task",
        }
    }

    pub fn from_wire_name(value: &str) -> Option<Self> {
        Some(match value {
            "health_check" => Self::HealthCheck,
            "execute_test" => Self::ExecuteTest,
            "emit_candidate_observation" => Self::EmitCandidateObservation,
            "emit_artifact_handle" => Self::EmitArtifactHandle,
            "request_controller_review" => Self::RequestControllerReview,
            "write_truth" => Self::WriteTruth,
            "request_patch" => Self::RequestPatch,
            "finish_task" => Self::FinishTask,
            _ => return None,
        })
    }

    pub const fn is_forbidden_authority(self) -> bool {
        matches!(
            self,
            Self::WriteTruth | Self::RequestPatch | Self::FinishTask
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterAuthorityProfile {
    pub allowed_projects: Vec<ProjectId>,
    pub allowed_roles: Vec<AgentRole>,
    pub allowed_capabilities: Vec<AdapterCapability>,
    pub can_write_truth: bool,
    pub can_request_patch: bool,
    pub can_finish_task: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterLimits {
    pub timeout_ms: u64,
    pub max_payload_bytes: usize,
    pub max_output_bytes: usize,
    pub max_concurrent_requests: usize,
    pub circuit_breaker_failures: u32,
}

impl Default for AdapterLimits {
    fn default() -> Self {
        Self {
            timeout_ms: 500,
            max_payload_bytes: 16_384,
            max_output_bytes: 16_384,
            max_concurrent_requests: 1,
            circuit_breaker_failures: 2,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionPolicy {
    pub process_spawn_allowed: bool,
    pub allowed_executables: Vec<String>,
    pub inherit_environment: bool,
    pub network_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    pub adapter_id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub adapter_class: AdapterClass,
    pub capabilities: Vec<AdapterCapability>,
    pub authority_profile: AdapterAuthorityProfile,
    pub limits: AdapterLimits,
    pub enabled_by_default: bool,
    pub process_policy: ProcessExecutionPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterContext {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub session_id: Option<AgentSessionId>,
    pub trace_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default)]
    pub role_lease_id: Option<String>,
    #[serde(default)]
    pub role_lease_epoch: Option<u64>,
    #[serde(default)]
    pub operation_generation: Option<u64>,
    #[serde(default)]
    pub runtime_contract_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterRequest {
    pub request_id: String,
    pub adapter_id: String,
    pub requested_capability: AdapterCapability,
    pub context: AdapterContext,
    pub input: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterResultStatus {
    Succeeded,
    TransportFailure,
    IntegrityFailure,
    NoResults,
    StaleIndex,
    UnsupportedCapability,
    Failed,
    Timeout,
    Rejected,
    OutputTooLarge,
    CircuitOpen,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterResult {
    pub result_id: String,
    pub request_id: String,
    pub adapter_id: String,
    pub status: AdapterResultStatus,
    pub output: Value,
    pub output_blob: Option<BlobRef>,
    pub observations: Vec<AdapterObservation>,
    pub error: Option<AdapterError>,
    pub duration_ms: u64,
    pub trace_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterObservation {
    pub observation_id: String,
    pub adapter_id: String,
    pub result_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub summary: String,
    pub payload: Value,
    pub payload_ref: String,
    pub raw_blob_ref: Option<BlobRef>,
    pub taint: TaintClass,
    pub write_receipt: Option<WriteReceiptRef>,
    pub blackboard_item_id: Option<BlackboardItemId>,
    pub mailbox_message_id: Option<MailboxMessageId>,
    pub controller_review_required: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterState {
    Registered,
    Healthy,
    Degraded,
    Unavailable,
    Executing,
    CircuitOpen,
    Shutdown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterHealth {
    pub adapter_id: String,
    pub name: String,
    pub state: AdapterState,
    pub healthy: bool,
    pub message: String,
    pub consecutive_failures: u32,
    pub circuit_open: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
}
// ---------------------------------------------------------------------------
// PRODUCTION INGRESS RECORD (issue #933, Work step 7). Gathered at the END of
// the file on purpose. Anchoring this block above its declaration reads better,
// but it shifts every later line number, and this crate's line coordinates are
// cited from other crates' acceptance suites, from the generated inventory and
// from the control plane - while `main` itself is moving underneath the lane.
// A record whose own coordinates are wrong is worse than one that is merely
// further from its declaration, and this block names its declaration explicitly.
//
// Record applies to:
//   AdapterRequest::input  and  AdapterResult::output

// OPAQUE, UNTRUSTED, BOUNDED DATA - never an envelope.
//
// `input` carries adapter call data only. It must never be read as, or
// promoted into, a protected envelope, control or authority field; the
// typed siblings of this member (`request_id`, `adapter_id`,
// `requested_capability`, `context`) are the carriers of identity and
// authority. The `#[serde(deny_unknown_fields)]` above closes THIS struct's
// own field set and constrains nothing inside this `Value`.
//
// RECORDED, UNRESOLVED. The causal owner is #933's own opaque-vs-envelope
// boundary decision plus the `eliot-engine` adapter request contract; this
// file owns neither, so the row is named here, not repaired here. One
// present-day production consumer does read control meaning out of this
// opaque payload: it lifts the protected `ProviderRoutePolicy` (policy
// identity `policy_id` / `policy_hash_blake3`, declared at
// `crates/eliot-types/src/provider_invocation.rs:289`) out of
// `input["provider_route_policy"]` with `serde_json::from_value`, at
// `crates/eliot-engine/src/adapter.rs:263-270`, and that policy's
// `timeout_profile()` then steers the adapter's absolute deadline and its
// cancellation and cleanup grace. That is a measured property of the tree,
// NOT a sanctioned property of this payload.
//
// MITIGATING FACT, AS MEASURED, NOT OVERSTATED: both present-day
// `AdapterRequest` construction sites
// (`crates/eliot-app/src/cognitive_field_runner.rs:5231`,
// `crates/eliot-app/src/host_runtime/external_agent.rs:2011`) build `input`
// in process with `serde_json::to_value` over a typed Rust value, never
// from untrusted wire text. So today there is no duplicate-key collapse and
// no untrusted-text path into this member. The exposure is exactly this:
// the boundary is a producer-side convention that no decoder here enforces,
// so the first producer that sources `input` from text inherits the problem
// silently.
//
// No envelope member, no new policy, no authorization gate, no second
// parser and no `Value` preprocessing step is added for this row: #933
// Work steps 5 and 6 keep decoder closure and authorization as separate
// gates and forbid imposing ELIOT control semantics on third-party content.
// OPAQUE ADAPTER-PRODUCED DATA - never an envelope.
//
// `output` is data produced by the adapter call, byte-bounded by
// `AdapterLimits::max_output_bytes` in the `eliot-engine` supervisor
// (`enforce_output_limit`, which may replace this member with a spill
// descriptor and set `output_blob`), not by this declaration. It must never
// be read as a protected envelope, control or authority field: `status`,
// `error`, `observations` and the identity members of this result are the
// typed carriers of control meaning, and the same opaque-payload rule
// recorded on `AdapterRequest::input` applies here.
