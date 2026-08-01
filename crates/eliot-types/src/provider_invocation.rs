use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{AgentHostId, BlobRef, ProcessReapReceipt};

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
pub struct ProviderInvocationTransition {
    pub transition_id: String,
    pub from: Option<ProviderInvocationState>,
    pub to: ProviderInvocationState,
    #[serde(with = "time::serde::rfc3339")]
    pub recorded_at: OffsetDateTime,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    #[serde(default)]
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
    #[serde(default)]
    pub timeout_class: Option<ProviderTimeoutClass>,
    #[serde(default)]
    pub process_reap_receipt: Option<ProcessReapReceipt>,
    #[serde(default)]
    pub process_timed_out: Option<bool>,
    #[serde(default)]
    pub process_cancelled: Option<bool>,
    #[serde(default)]
    pub process_worker_error: Option<String>,
    #[serde(default)]
    pub stdout_total_bytes: Option<u64>,
    #[serde(default)]
    pub stderr_total_bytes: Option<u64>,
    #[serde(default)]
    pub stdout_truncated: Option<bool>,
    #[serde(default)]
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
pub struct ProviderIdentityCheck {
    pub field: String,
    pub expected: Option<String>,
    pub observed: Option<String>,
    pub matched: Option<bool>,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProviderRouteReadinessGate {
    pub readiness_gate_id: String,
    pub provider: String,
    pub route_or_model: String,
    pub local_adapter_health: bool,
    pub executable_available: bool,
    pub auth_or_configuration_present: bool,
    #[serde(default)]
    pub installed: bool,
    #[serde(default)]
    pub provider_authenticated: bool,
    #[serde(default)]
    pub exact_model_selectable: bool,
    #[serde(default)]
    pub mcp_config_valid: bool,
    #[serde(default)]
    pub mcp_process_started: bool,
    #[serde(default)]
    pub mcp_initialized: bool,
    #[serde(default)]
    pub required_tools_visible: bool,
    #[serde(default)]
    pub structured_output_ready: bool,
    #[serde(default)]
    pub console_headless_ready: bool,
    #[serde(default)]
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
