use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::BlobRef;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderInvocationState {
    Prepared,
    Reserved,
    DispatchStarting,
    Dispatched,
    Running,
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
    pub quota_or_cost_if_known: Option<String>,
    pub original_closeout_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderTimeoutProfile {
    pub profile_id: String,
    pub provider: String,
    pub route_or_operation_class: String,
    pub spawn_deadline_ms: Option<u64>,
    pub dispatch_ack_deadline_ms: Option<u64>,
    pub first_output_deadline_ms: Option<u64>,
    pub idle_output_deadline_ms: Option<u64>,
    pub absolute_runtime_deadline_ms: u64,
    pub cancellation_grace_ms: u64,
    pub cleanup_grace_ms: u64,
    pub reconciliation_window_ms: u64,
    pub output_heartbeat_supported: bool,
    pub status_lookup_supported: bool,
    pub evidence_basis: Vec<String>,
    pub assumptions: Vec<String>,
    pub hard_upper_bounds: Vec<String>,
    pub policy_version: String,
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
