use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{AgentHostId, BlobRef, ProcessReapReceipt};

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderInvocationState {
    Prepared,
    Reserved,
    DispatchStarting,
    Dispatched,
    Running,
    ProcessTerminal,
    OutputObserved,
    CompletedCaptured,
    ReviewNormalized,
    PreDispatchAborted,
    DispatchAckUnknown,
    TimeoutPendingReconciliation,
    ProcessExitedNonzero,
    CancelledAfterDispatch,
    LocalCaptureFailed,
    ProtocolParseFailed,
    CleanupFailedAfterComplete,
    ReconciledCompleted,
    ReconciledFailed,
    NonReconcilableUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTimeoutClass {
    SpawnTimeout,
    DispatchAckTimeout,
    FirstOutputTimeout,
    IdleOutputTimeout,
    AbsoluteRuntimeTimeout,
    CancellationTimeout,
    CleanupTimeout,
    UnknownTimeoutBoundary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderInvocationOutcomeClass {
    CompletedReview,
    PreDispatchFailure,
    SpawnFailure,
    DispatchAckUnknown,
    ProviderQueueTimeout,
    FirstOutputTimeout,
    IdleOutputTimeout,
    AbsoluteDeadlineTimeout,
    ProcessExitNonzero,
    LocalCaptureFailure,
    CleanupFailureAfterComplete,
    ProtocolParseFailure,
    CancelledAfterDispatch,
    NonReconcilableUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderReconciliationMethod {
    LocalWal,
    RawOutputSpool,
    ProcessExitRecord,
    JobObjectRecord,
    AdapterLog,
    OfficialStatusLookup,
    OfficialResultFetch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderResultCompleteness {
    Complete,
    Partial,
    Missing,
    Mismatched,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRootCauseStatus {
    Unknown,
    Supported,
    Verified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRouteReadinessVerdict {
    ReadyForFreshCanary,
    BlockedByLocalRoute,
    BlockedByProvider,
    BlockedByUnknownTimeoutContract,
    RequiresOperatorAuthorization,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInvocationTransition {
    pub transition_id: String,
    pub from: Option<ProviderInvocationState>,
    pub to: ProviderInvocationState,
    #[serde(with = "time::serde::rfc3339")]
    pub recorded_at: OffsetDateTime,
    pub evidence_refs: Vec<String>,
}

/// Decoder: derived and closed. The ten required-nullable outcome fields below
/// (`provider_route_policy`, `timeout_class`, `process_reap_receipt`,
/// `process_timed_out`, `process_cancelled`, `process_worker_error`,
/// `stdout_total_bytes`, `stderr_total_bytes`, `stdout_truncated`,
/// `stderr_truncated`) each carry
/// `#[serde(deserialize_with = "deserialize_required_nullable")]` and no
/// `#[serde(default)]`, so an absent key is a typed missing-field failure
/// rather than a silent `None`, while an explicit null still decodes to `None`.
///
/// Those ten fields carry timeout/cancel/truncation, byte-count and
/// route-policy meaning for a governed external process. Defaulting them let a
/// record that never recorded a timeout, a reap receipt, a cancellation, a
/// truncation or its route-policy binding read as if it had recorded
/// `false`/`0`/absent — an absent observation presented as a measured one, which
/// is exactly the silent absence this record must not carry.
/// `provider_route_policy` matters most here: it is the binding between an
/// attempt and the governed route policy it was dispatched under.
///
/// Compatibility: this record is durably journaled to disk by
/// `ProviderInvocationJournal::{create, persist}`
/// (`eliot-engine/src/provider_invocation.rs`), one file per attempt, and read
/// back on reconciliation and timeout repair. Every current producer sets all
/// ten explicitly, including `None`:
/// `eliot-engine/src/antigravity.rs:5109`,
/// `eliot-app/src/host_runtime/external_agent.rs:2567` and
/// `eliot-app/src/delegation_runtime.rs:844` all construct the full literal.
/// `Serialize` is untouched, so accepted and emitted bytes are unchanged and
/// this is a compatible requiredness correction. No named/versioned legacy
/// decoder exists for this record and none may be invented (W4), so a record
/// written by an older build now fails loudly instead of decoding as an
/// attempt that measured nothing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInvocationAttempt {
    pub invocation_attempt_id: String,
    pub provider: String,
    pub campaign_id: String,
    pub preregistration_id: String,
    pub reservation_id: String,
    pub idempotency_key: String,
    pub external_invocation_ref: Option<String>,
    pub frozen_input_hash: String,
    pub request_payload_hash: String,
    pub route_or_model: Option<String>,
    pub adapter_version: Option<String>,
    pub executable_or_transport: Option<String>,
    pub cwd: Option<String>,
    pub environment_fingerprint: Option<String>,
    pub timeout_profile_id: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub provider_route_policy: Option<ProviderRoutePolicyBinding>,
    pub state_transitions: Vec<ProviderInvocationTransition>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub dispatch_started_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub process_started_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub provider_ack_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub first_output_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_output_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub process_exit_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub cleanup_completed_at: Option<OffsetDateTime>,
    pub stdout_blob_or_hash: Option<BlobRef>,
    pub stderr_blob_or_hash: Option<BlobRef>,
    pub structured_output_blob_or_hash: Option<BlobRef>,
    pub exit_code_or_signal: Option<String>,
    pub process_or_job_identity: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub timeout_class: Option<ProviderTimeoutClass>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub process_reap_receipt: Option<ProcessReapReceipt>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub process_timed_out: Option<bool>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub process_cancelled: Option<bool>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub process_worker_error: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub stdout_total_bytes: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub stderr_total_bytes: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub stdout_truncated: Option<bool>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub stderr_truncated: Option<bool>,
    pub quota_or_cost_if_known: Option<String>,
    pub original_closeout_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRoutePolicyBinding {
    pub policy_id: String,
    pub policy_hash_blake3: String,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDeclaredBudget {
    absolute_runtime_deadline_ms: u64,
    spawn_deadline_ms: Option<u64>,
    first_output_deadline_ms: Option<u64>,
    idle_output_deadline_ms: Option<u64>,
    cancellation_grace_ms: u64,
    cleanup_grace_ms: u64,
    reconciliation_window_ms: u64,
    output_limit_bytes: u64,
}

impl ProviderDeclaredBudget {
    #[must_use]
    pub const fn new(absolute_runtime_deadline_ms: u64, output_limit_bytes: u64) -> Self {
        Self {
            absolute_runtime_deadline_ms,
            spawn_deadline_ms: Some(5_000),
            first_output_deadline_ms: Some(absolute_runtime_deadline_ms),
            idle_output_deadline_ms: None,
            cancellation_grace_ms: 100,
            cleanup_grace_ms: 5_000,
            reconciliation_window_ms: 5_000,
            output_limit_bytes,
        }
    }

    #[must_use]
    pub const fn with_spawn_deadline_ms(mut self, value: Option<u64>) -> Self {
        self.spawn_deadline_ms = value;
        self
    }

    #[must_use]
    pub const fn with_first_output_deadline_ms(mut self, value: Option<u64>) -> Self {
        self.first_output_deadline_ms = value;
        self
    }

    #[must_use]
    pub const fn with_idle_output_deadline_ms(mut self, value: Option<u64>) -> Self {
        self.idle_output_deadline_ms = value;
        self
    }

    #[must_use]
    pub const fn with_cancellation_grace_ms(mut self, value: u64) -> Self {
        self.cancellation_grace_ms = value;
        self
    }

    #[must_use]
    pub const fn with_cleanup_grace_ms(mut self, value: u64) -> Self {
        self.cleanup_grace_ms = value;
        self
    }

    #[must_use]
    pub const fn with_reconciliation_window_ms(mut self, value: u64) -> Self {
        self.reconciliation_window_ms = value;
        self
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRoutePolicy {
    policy_id: String,
    policy_hash_blake3: String,
    #[schemars(with = "String")]
    host: AgentHostId,
    operation_class: String,
    timeout_profile: ProviderTimeoutProfile,
    output_limit_bytes: u64,
    incremental_output_supported: bool,
    status_lookup_supported: bool,
}

impl ProviderRoutePolicy {
    #[must_use]
    pub fn for_route(
        host: AgentHostId,
        operation_class: impl Into<String>,
        declared_budget: ProviderDeclaredBudget,
    ) -> Self {
        let operation_class = operation_class.into();
        let policy_hash_blake3 = route_policy_hash(host, &operation_class, &declared_budget);
        let operation_id = operation_class
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect::<String>()
            .trim_matches('-')
            .to_owned();
        let policy_id = format!(
            "provider-route-policy-v1:{}:{}:{}",
            host.as_str(),
            if operation_id.is_empty() {
                "provider"
            } else {
                &operation_id
            },
            &policy_hash_blake3[..16]
        );
        let timeout_profile = ProviderTimeoutProfile {
            profile_id: policy_id.clone(),
            provider: host.as_str().to_owned(),
            route_or_operation_class: operation_class.clone(),
            spawn_deadline_ms: declared_budget.spawn_deadline_ms,
            dispatch_ack_deadline_ms: None,
            first_output_deadline_ms: declared_budget.first_output_deadline_ms,
            idle_output_deadline_ms: declared_budget.idle_output_deadline_ms,
            absolute_runtime_deadline_ms: declared_budget.absolute_runtime_deadline_ms,
            cancellation_grace_ms: declared_budget.cancellation_grace_ms,
            cleanup_grace_ms: declared_budget.cleanup_grace_ms,
            reconciliation_window_ms: declared_budget.reconciliation_window_ms,
            output_heartbeat_supported: true,
            status_lookup_supported: false,
            evidence_basis: vec!["caller-declared provider budget".to_owned()],
            assumptions: Vec::new(),
            hard_upper_bounds: vec![
                format!(
                    "absolute_runtime_deadline_ms={}",
                    declared_budget.absolute_runtime_deadline_ms
                ),
                "one process generation; no runner retry".to_owned(),
            ],
            policy_version: "provider-route-policy-v1".to_owned(),
        };
        Self {
            policy_id,
            policy_hash_blake3,
            host,
            operation_class,
            timeout_profile,
            output_limit_bytes: declared_budget.output_limit_bytes,
            incremental_output_supported: true,
            status_lookup_supported: false,
        }
    }

    #[must_use]
    pub fn binding(&self) -> ProviderRoutePolicyBinding {
        ProviderRoutePolicyBinding {
            policy_id: self.policy_id.clone(),
            policy_hash_blake3: self.policy_hash_blake3.clone(),
        }
    }

    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    #[must_use]
    pub fn policy_hash_blake3(&self) -> &str {
        &self.policy_hash_blake3
    }

    #[must_use]
    pub const fn host(&self) -> AgentHostId {
        self.host
    }

    #[must_use]
    pub fn operation_class(&self) -> &str {
        &self.operation_class
    }

    #[must_use]
    pub const fn timeout_profile(&self) -> &ProviderTimeoutProfile {
        &self.timeout_profile
    }

    #[must_use]
    pub const fn output_limit_bytes(&self) -> u64 {
        self.output_limit_bytes
    }

    #[must_use]
    pub const fn incremental_output_supported(&self) -> bool {
        self.incremental_output_supported
    }

    #[must_use]
    pub const fn status_lookup_supported(&self) -> bool {
        self.status_lookup_supported
    }
}

fn route_policy_hash(
    host: AgentHostId,
    operation_class: &str,
    budget: &ProviderDeclaredBudget,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, "provider-route-policy-v1");
    hash_field(&mut hasher, host.as_str());
    hash_field(&mut hasher, operation_class);
    hash_optional_u64(&mut hasher, budget.spawn_deadline_ms);
    hash_optional_u64(&mut hasher, budget.first_output_deadline_ms);
    hash_optional_u64(&mut hasher, budget.idle_output_deadline_ms);
    for value in [
        budget.absolute_runtime_deadline_ms,
        budget.cancellation_grace_ms,
        budget.cleanup_grace_ms,
        budget.reconciliation_window_ms,
        budget.output_limit_bytes,
    ] {
        hasher.update(&value.to_le_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn hash_field(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn hash_optional_u64(hasher: &mut blake3::Hasher, value: Option<u64>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            hasher.update(&value.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderTimeoutProfile {
    profile_id: String,
    provider: String,
    route_or_operation_class: String,
    spawn_deadline_ms: Option<u64>,
    dispatch_ack_deadline_ms: Option<u64>,
    first_output_deadline_ms: Option<u64>,
    idle_output_deadline_ms: Option<u64>,
    absolute_runtime_deadline_ms: u64,
    cancellation_grace_ms: u64,
    cleanup_grace_ms: u64,
    reconciliation_window_ms: u64,
    output_heartbeat_supported: bool,
    status_lookup_supported: bool,
    evidence_basis: Vec<String>,
    assumptions: Vec<String>,
    hard_upper_bounds: Vec<String>,
    policy_version: String,
}

impl ProviderTimeoutProfile {
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub const fn spawn_deadline_ms(&self) -> Option<u64> {
        self.spawn_deadline_ms
    }

    #[must_use]
    pub const fn dispatch_ack_deadline_ms(&self) -> Option<u64> {
        self.dispatch_ack_deadline_ms
    }

    #[must_use]
    pub const fn first_output_deadline_ms(&self) -> Option<u64> {
        self.first_output_deadline_ms
    }

    #[must_use]
    pub const fn idle_output_deadline_ms(&self) -> Option<u64> {
        self.idle_output_deadline_ms
    }

    #[must_use]
    pub const fn absolute_runtime_deadline_ms(&self) -> u64 {
        self.absolute_runtime_deadline_ms
    }

    #[must_use]
    pub const fn cancellation_grace_ms(&self) -> u64 {
        self.cancellation_grace_ms
    }

    #[must_use]
    pub const fn cleanup_grace_ms(&self) -> u64 {
        self.cleanup_grace_ms
    }

    #[must_use]
    pub const fn reconciliation_window_ms(&self) -> u64 {
        self.reconciliation_window_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct ProviderInvocationOutcome {
    pub outcome_id: String,
    pub invocation_attempt_ref: String,
    pub effective_state: ProviderInvocationState,
    pub outcome_class: ProviderInvocationOutcomeClass,
    pub timeout_class: Option<ProviderTimeoutClass>,
    pub dispatch_proven: bool,
    pub slot_consumed: bool,
    pub result_complete: bool,
    pub review_created: bool,
    pub raw_output_preserved: bool,
    pub exact_failure_evidence_refs: Vec<String>,
    pub unresolved_questions: Vec<String>,
    pub retry_same_campaign_allowed: bool,
    pub next_allowed_transition: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentityCheck {
    pub field: String,
    pub expected: Option<String>,
    pub observed: Option<String>,
    pub matched: Option<bool>,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderReconciliationRecord {
    pub reconciliation_id: String,
    pub invocation_attempt_ref: String,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub completed_at: OffsetDateTime,
    pub methods_attempted: Vec<ProviderReconciliationMethod>,
    pub provider_generating_call_performed: bool,
    pub identity_checks: Vec<ProviderIdentityCheck>,
    pub recovered_artifacts: Vec<String>,
    pub mismatched_artifacts_quarantined: Vec<String>,
    pub result_completeness: ProviderResultCompleteness,
    pub effective_state_after: ProviderInvocationState,
    pub review_id_if_recovered: Option<String>,
    pub unresolved_questions: Vec<String>,
    pub verifier_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct ExternalResultCompletenessReceipt {
    pub completeness_receipt_id: String,
    pub invocation_attempt_ref: String,
    pub raw_output_ref: Option<String>,
    pub parser_version: String,
    pub expected_schema: String,
    pub terminal_marker_or_protocol_status: Option<String>,
    pub required_fields_present: bool,
    pub truncation_detected: bool,
    pub stream_closed_cleanly: bool,
    pub result_complete: bool,
    pub normalization_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderFailureIncident {
    pub incident_id: String,
    pub source_phase: String,
    pub source_commit: String,
    pub invocation_attempt_ref: String,
    pub original_status: String,
    pub symptom: String,
    pub verified_facts: Vec<String>,
    pub assumptions: Vec<String>,
    pub missing_observability: Vec<String>,
    pub root_cause_status: ProviderRootCauseStatus,
    pub root_cause: String,
    pub affected_invariants: Vec<String>,
    pub slot_consumption_correct: bool,
    pub repeated_call_prevented: bool,
    pub remediation_refs: Vec<String>,
    pub resolved_when: Vec<String>,
}

/// Decoder: derived and closed. The nine readiness observations below
/// (`installed` through `console_headless_ready`) are plain `bool` with no
/// `#[serde(default)]`, so an absent key already fails decoding.
/// `last_successful_smoke_ref` carries
/// `#[serde(deserialize_with = "deserialize_required_nullable")]` and no
/// `#[serde(default)]`, so its key must be present while an explicit null
/// still decodes to `None`.
///
/// Defaulting them conflated "the gate observed this is false / no smoke has
/// ever succeeded" with "the gate never observed it at all". Both readings fed
/// the same `verdict`, so a partial or truncated gate record could present a
/// fail-closed `false` as a measured negative. The default direction *is*
/// fail-closed, so this was not an authority-escalation defect — but absent and
/// measured are still different facts, and `ProviderRouteReadinessService::evaluate`
/// (`eliot-engine/src/provider_invocation.rs:657`) is the only producer and
/// sets all ten explicitly, so current payloads are unchanged and this is a
/// compatible requiredness correction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct ProviderRouteReadinessGate {
    pub readiness_gate_id: String,
    pub provider: String,
    pub route_or_model: String,
    pub local_adapter_health: bool,
    pub executable_available: bool,
    pub auth_or_configuration_present: bool,
    pub installed: bool,
    pub provider_authenticated: bool,
    pub exact_model_selectable: bool,
    pub mcp_config_valid: bool,
    pub mcp_process_started: bool,
    pub mcp_initialized: bool,
    pub required_tools_visible: bool,
    pub structured_output_ready: bool,
    pub console_headless_ready: bool,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub last_successful_smoke_ref: Option<String>,
    pub provider_gate_current: bool,
    pub last_incident_class: ProviderInvocationOutcomeClass,
    pub timeout_profile_ref: String,
    pub durable_capture_ready: bool,
    pub reconciliation_capability: String,
    pub process_tree_cancellation_ready: bool,
    pub historical_latency_or_timeout_evidence: Vec<String>,
    pub quota_or_cost_visibility: bool,
    pub fresh_campaign_required: bool,
    pub operator_authorization_required: bool,
    pub verdict: ProviderRouteReadinessVerdict,
    pub reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

// UNRESOLVED INGRESS ROW, recorded under #933. Placement note: this block is
// anchored here, after :654 (the highest line number in this file that is
// cited anywhere else in the repository), rather than at the declaration it
// describes, so that no currently cited coordinate shifts. The subject is
// `ProviderRoutePolicy` at :287-299, its `impl` at :301-416.
//
// Subject. `ProviderRoutePolicy` (:289) is a protected, authority-bearing
// control type, not data. It carries `policy_id` (:290),
// `policy_hash_blake3` (:291), `host` (:293) and the whole
// `timeout_profile` (:295), and its accessors `policy_id()` (:378),
// `policy_hash_blake3()` (:383) and `timeout_profile()` (:398) hand those
// values to callers as governing facts.
//
// 1. The container it travels in is opaque. Its one direct production decode
// site reads it out of `AdapterRequest.input`, and
// `crates/eliot-types/src/adapter.rs:151` declares that member as a bare
// `pub input: Value` — `serde_json::Value`, imported at that file's :6 —
// sitting beside otherwise typed identity and authority fields
// (`request_id` :147, `adapter_id` :148, `requested_capability` :149,
// `context` :150). Correction to the record that motivated this row:
// `crates/eliot-types/src/adapter.rs` carries no doc comment on
// `AdapterRequest` or on any other item (that file has zero `///` and zero
// `//!` lines across all 241 lines), so the opacity of `input` is established
// by its declared type and by #933's own opaque-payload-versus-envelope-field
// boundary prose — not by a doc comment on the declaration. The distinction
// this row protects is real either way: `input` has no typed identity,
// authority or status of its own, yet a policy that steers process lifetime
// is read back out of it.
//
// 2. The decode site, re-measured: `crates/eliot-engine/src/adapter.rs:241-248`
// — `request.input.get("provider_route_policy").cloned()`, a missing key
// rejected as "external adapter request has no provider route policy", then
// `serde_json::from_value::<ProviderRoutePolicy>(route_policy)?` at :248. It
// runs only for `AdapterClass::ExternalCandidate` (:240). The general request
// gate `validate_request` (`crates/eliot-engine/src/adapter.rs:1196-1221`)
// checks adapter identity, capability membership, forbidden authority and
// `serde_json::to_vec(&request.input)?.len()` against `max_payload_bytes`
// (:1216) — it never inspects the structure of `input`, so :248 is the only
// thing standing between an opaque payload and a governing deadline.
//
// 3. What the consumer obtains. `crates/eliot-engine/src/adapter.rs:249-253`
// takes `route_policy.timeout_profile()` — `&ProviderTimeoutProfile`, declared
// at `provider_invocation.rs:398` — and reads
// `absolute_runtime_deadline_ms()` (:508), `cancellation_grace_ms()` (:513)
// and `cleanup_grace_ms()` (:518), summing them into `timeout_ms`. That value
// becomes the absolute `deadline` handed to `AdapterExecutionContext`
// (:257-259, :263-272) and `deadline_at`, recorded as `phase_deadline_at` and
// `absolute_deadline_at` on the runtime checkpoint (:274-297). It therefore
// steers process lifetime and cleanup, not a label. `policy_id` and
// `policy_hash_blake3` are NOT consulted by this consumer at all; the
// identity members of the policy are carried but unread on this path.
//
// 4. There is no validator of its own in this file. This module contains no
// `validate_*` function, no sealed-reference check and no digest check for
// `ProviderRoutePolicy`. `route_policy_hash` (:418-440) is a private helper
// whose only call site is `for_route` (:309), so a decoded policy's
// `policy_hash_blake3` is never recomputed against its own budget here, and
// `for_route` is a constructor, not a decoder check. A downstream partial
// check exists outside this crate and is recorded here so the row is not
// overstated: `validate_external_agent_execution_request`
// (`crates/eliot-engine/src/external_agent/mod.rs:160`) rejects a
// non-empty-`policy_id` and a `policy_hash_blake3` whose *length* is not 64
// (:206-207), plus `timeout_profile_ref == policy_id` (:208), a host-name
// suffix match (:209-211) and non-zero `absolute_runtime_deadline_ms` /
// `output_limit_bytes` (:217-222). That is a shape and length check; the blake3
// digest is never recomputed, so a self-consistent-looking forged digest of
// length 64 satisfies it. This check runs before the adapter on the cognitive
// path (`crates/eliot-app/src/cognitive_field_runner.rs:5203`) but is never
// called on the smoke path that builds an `AdapterRequest`
// (`crates/eliot-app/src/host_runtime/external_agent.rs:1784-2012`; its only
// in-file callers are :265 and :2525), and it never runs at the engine decode
// site of point 2.
//
// 5. The two in-scope construction sites of `AdapterRequest` do NOT have the
// same provenance, and the difference is load-bearing.
//   - `crates/eliot-app/src/host_runtime/external_agent.rs:1996`, with
//     `input: serde_json::to_value(execution)?` at :2011, over an in-process
//     `ExternalAgentExecutionRequest` whose policy was produced by
//     `ProviderRoutePolicy::for_route` at :1953 and never round-tripped
//     through text. No bytes, therefore no duplicate-key collapse on this
//     path. It is not, strictly, a hand-written `Value` literal either: it is
//     the serde projection of a typed request.
//   - `crates/eliot-app/src/cognitive_field_runner.rs:5216`, with
//     `input: serde_json::to_value(&execution)?` at :5231, where `execution`
//     was decoded from raw file bytes at :5202 by `read_json`
//     (`crates/eliot-app/src/cognitive_field_runner.rs:9123-9125`, which is
//     `serde_json::from_slice(&fs::read(path)?)`). This path DOES have a
//     raw-bytes ingress, and `serde_json` collapses duplicate members before
//     `deny_unknown_fields` is consulted, so a duplicated policy member in
//     that request file resolves last-wins with no surviving evidence of the
//     duplicate. It also does not match the "in-process literal" description.
// Both sites nonetheless carry the policy as a TYPED member of a typed
// envelope: `ExternalAgentExecutionRequest`
// (`crates/eliot-types/src/external_agent.rs:282` on `origin/main`,
// `#[serde(deny_unknown_fields)]`; that file is under concurrent edit in this
// working tree, so the declaration is named rather than pinned)
// declares `pub provider_route_policy: ProviderRoutePolicy` (baseline :300).
// So the honest
// statement of the gap is not "unvalidated data from the wire" and not "a
// lost-duplicate-evidence residual". It is: a protected control type is
// presently sourced from an opaque payload whose authority depends on a
// producer-side convention — place the policy at the `provider_route_policy`
// key of the serialized request — that no decoder in `eliot-engine` enforces
// beyond a successful typed decode, and whose erasure happens at exactly one
// place, `AdapterRequest.input: Value`.
//   - For completeness of the producer set: `AdapterRequest` is also built at
//     `crates/eliot-engine/src/external_review.rs:679` (adapter_id
//     `"test-echo"`, `input` a `json!` literal at :694-699 carrying no
//     `provider_route_policy`, so that request takes the non-`ExternalCandidate`
//     branch at `crates/eliot-engine/src/adapter.rs:255` and never reaches the
//     decode) and at `crates/eliot-app/src/host_runtime/external_agent.rs:4752`
//     inside a `#[cfg(test)]` module. Neither is a third route-policy ingress.
//
// 6. Owner and disposition: UNRESOLVED, and deliberately not repaired here. The
// causal owner is whoever decides that a protected route policy may travel
// inside an opaque adapter payload — that is the adapter request contract in
// `crates/eliot-engine/src/adapter.rs:240-253` together with the
// opaque-payload-versus-envelope-field boundary declared at
// `crates/eliot-types/src/adapter.rs:146-152`. The repair is outside this file
// and outside #933's scope: #933 cannot add a new envelope member, mint a new
// policy, or introduce an authorization gate here, because decoder closure and
// authorization are separate gates (Work step 5) and third-party content must
// not be given Eliot control semantics (Work step 6). No authorization
// decision is made or implied by this comment; it records a boundary and a
// named owner, nothing more.
//
// What this file's other types can and cannot reach, so the row delimits the
// boundary rather than only listing the gap:
//   - `ProviderInvocationAttempt` (:155) IS reached from raw bytes:
//     `ProviderInvocationJournal::load`
//     (`crates/eliot-engine/src/provider_invocation.rs:159-163`) reads
//     `fs::read(&path)` and calls `serde_json::from_slice(&bytes)` at :162. Its
//     duplicate-key refusal is therefore reachable in production today.
//   - `ProviderRoutePolicy` is reached from a `Value`, never directly from raw
//     bytes by name (point 2), but it is reached from raw bytes TRANSITIVELY
//     on the cognitive path, because `read_json` decodes an
//     `ExternalAgentExecutionRequest` whose member is a typed
//     `ProviderRoutePolicy` (point 5). A `serde_json::Value` cannot hold a
//     duplicate key at all, so by the time :248 runs, any duplicate has
//     already been collapsed upstream — the collapse is unrecoverable there,
//     not merely unguarded.
//   - `ProviderReconciliationRecord` (:560), `ProviderRouteReadinessGate`
//     (:637) and `ProviderResultCompleteness` (:86) have no production
//     `from_slice`/`from_value`/`from_str`/`from_reader` decode site outside
//     this crate; their closed-decode refusal is currently reachable only from
//     tests. Falsifier: a decode reached through a type alias, a
//     `Vec`/`Option` container decode, or a split across lines, which a
//     same-line type-name-plus-decode-token search would miss.
