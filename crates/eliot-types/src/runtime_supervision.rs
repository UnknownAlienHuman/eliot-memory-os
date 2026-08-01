use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub const OPERATION_RUNTIME_CHECKPOINT_SCHEMA_VERSION: &str = "eliot-operation-runtime-v1";
pub const OPERATION_RESTART_WINDOW_SCHEMA_VERSION: &str = "eliot-operation-restart-window-v1";
pub const SEAL_STAGING_CHECKPOINT_SCHEMA_VERSION: &str = "eliot-seal-staging-checkpoint-v1";
pub const RUNTIME_INTEGRITY_REPORT_SCHEMA_VERSION: &str = "eliot-runtime-integrity-v1";

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationPhase {
    #[default]
    Prepared,
    Validating,
    Staging,
    AuthorityActivating,
    Published,
    DispatchStarting,
    AwaitingDispatchAck,
    AwaitingFirstOutput,
    Running,
    OutputDraining,
    Cancelling,
    Reaping,
    Reconciling,
    Completed,
    Failed,
    Abandoned,
}

impl OperationPhase {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Abandoned)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDispatchState {
    #[default]
    NotStarted,
    Starting,
    Proven,
    AckUnknown,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationCancellationState {
    #[default]
    NotRequested,
    Requested,
    Graceful,
    Forced,
    Reaped,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationReconciliationState {
    #[default]
    NotRequired,
    Pending,
    Completed,
    Failed,
    NonReconcilableUnknown,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterCircuitState {
    #[default]
    Closed,
    Open,
    HalfOpen,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRuntimeCheckpoint {
    pub schema_version: String,
    pub operation_id: String,
    pub invocation_id: Option<String>,
    pub adapter_id: Option<String>,
    pub generation: u64,
    pub phase: OperationPhase,
    pub dispatch_state: ProviderDispatchState,
    pub cancellation_state: OperationCancellationState,
    pub reconciliation_state: OperationReconciliationState,
    pub root_pid: Option<u32>,
    pub root_process_start_ticks: Option<u64>,
    pub root_executable_sha256: Option<String>,
    pub job_object_name: Option<String>,
    pub active_process_count: u32,
    pub stdin_bytes: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub phase_started_at: OffsetDateTime,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub last_progress_at: OffsetDateTime,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub phase_deadline_at: OffsetDateTime,
    #[schemars(with = "String")]
    #[serde(with = "time::serde::rfc3339")]
    pub absolute_deadline_at: OffsetDateTime,
    pub restart_count: u32,
    pub restart_window_started_at: Option<String>,
    pub role_lease_id: Option<String>,
    pub role_lease_epoch: Option<u64>,
    pub runtime_contract_sha256: Option<String>,
    pub last_error_class: Option<String>,
    pub last_evidence_refs: Vec<String>,
}

impl OperationRuntimeCheckpoint {
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.phase.is_terminal()
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRestartWindow {
    pub schema_version: String,
    pub key: String,
    pub restart_timestamps: Vec<String>,
    pub circuit_state: AdapterCircuitState,
    pub consecutive_failures: u32,
    #[serde(default)]
    pub last_success_at: Option<String>,
    #[serde(default)]
    pub last_failure_at: Option<String>,
    pub last_failure_class: Option<String>,
    #[serde(default)]
    pub last_terminal_operation_ref: Option<String>,
    pub updated_at: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealStagingState {
    #[default]
    Staged,
    Activated,
    Published,
    Abandoned,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealStagingCheckpoint {
    pub schema_version: String,
    pub seal_attempt_id: String,
    pub run_id: String,
    pub generation: u64,
    pub staging_root: String,
    pub manifest_sha256: String,
    pub state: SealStagingState,
    pub updated_at: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProcessReapReceipt {
    pub operation_id: String,
    pub generation: u64,
    pub job_object_name: String,
    pub root_pid: Option<u32>,
    pub process_count_before: u32,
    pub process_count_after: u32,
    pub graceful_attempted: bool,
    pub forced_termination: bool,
    pub stdout_closed: bool,
    pub stderr_closed: bool,
    pub all_tasks_joined: bool,
    pub elapsed_ms: u64,
    pub terminal_error_codes: Vec<u32>,
}

impl ProcessReapReceipt {
    #[must_use]
    pub fn proves_complete_reap(&self) -> bool {
        self.process_count_after == 0
            && self.stdout_closed
            && self.stderr_closed
            && self.all_tasks_joined
            && (self.forced_termination || self.terminal_error_codes.is_empty())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the runtime health wire contract exposes independent readiness dimensions"
)]
pub struct RuntimeCoreHealth {
    pub ready: bool,
    pub ipc_ready: bool,
    pub db_ready: bool,
    pub writer_ready: bool,
    pub read_service_ready: bool,
    pub service_generation: Option<String>,
    pub executable_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAdapterHealth {
    pub adapter_id: String,
    pub installed: bool,
    pub authenticated: bool,
    pub ready: bool,
    pub circuit_state: AdapterCircuitState,
    pub active_operations: u32,
    pub queued_operations: u32,
    pub restart_count_window: u32,
    pub last_success_at: Option<String>,
    pub last_failure_at: Option<String>,
    pub last_failure_class: Option<String>,
    #[serde(default)]
    pub last_terminal_operation_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOperationDetail {
    pub operation_id: String,
    pub generation: u64,
    pub phase: OperationPhase,
    pub last_progress_at: String,
    pub phase_deadline_at: String,
    pub root_pid: Option<u32>,
    pub active_process_count: u32,
    pub stdin_state: String,
    pub stdout_state: String,
    pub stderr_state: String,
    pub cancellation_state: OperationCancellationState,
    pub reconciliation_state: OperationReconciliationState,
    pub role_lease_id: Option<String>,
    pub role_lease_epoch: Option<u64>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOperationHealth {
    pub active: u32,
    pub stuck: u32,
    pub awaiting_reconciliation: u32,
    pub cleanup_pending: u32,
    pub orphan_processes: u32,
    pub oldest_last_progress_at: Option<String>,
    pub details: Vec<RuntimeOperationDetail>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAuthorityIntegrity {
    pub active_sessions: u32,
    pub active_role_leases: u32,
    pub pending_role_leases: u32,
    pub orphaned_role_leases: u32,
    pub revoked_role_leases: u32,
    pub stale_epoch_results: u32,
    pub partial_seals: u32,
    pub published_plans_without_authority: u32,
    pub published_seal_runtime_drift: u32,
    pub authority_without_published_plan: u32,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIntegrityHealth {
    pub clean: bool,
    pub expected_governor_sha256: Option<String>,
    pub observed_governor_sha256: Option<String>,
    pub locked_active_binary: Option<String>,
    pub process_orphans: u32,
    pub incomplete_staging_roots: u32,
    pub quarantine_records: u32,
    pub last_startup_recovery_ref: Option<String>,
    pub last_watchdog_action_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOverallStatus {
    Ready,
    Degraded,
    IntegrityFailed,
    NotReady,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSupervisionReport {
    pub schema_version: String,
    pub generated_at: String,
    pub core: RuntimeCoreHealth,
    pub adapters: Vec<RuntimeAdapterHealth>,
    pub operations: RuntimeOperationHealth,
    pub authority_integrity: RuntimeAuthorityIntegrity,
    pub runtime_integrity: RuntimeIntegrityHealth,
    pub overall: RuntimeOverallStatus,
    pub reason: String,
    pub provider_dispatch_safe: bool,
    pub integrity_errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReconcileDecision {
    pub operation_id: String,
    pub generation: u64,
    pub decision: String,
    pub mutates: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReconcileDryRun {
    pub schema_version: String,
    pub generated_at: String,
    pub dry_run: bool,
    pub decisions: Vec<RuntimeReconcileDecision>,
    pub provider_calls: u32,
    pub writes: u32,
}

#[cfg(test)]
mod tests {
    use super::ProcessReapReceipt;

    #[test]
    fn runtime_supervision_reap_receipt_requires_zero_members_and_joined_pipes() {
        let mut receipt = ProcessReapReceipt {
            operation_id: "op-1".to_owned(),
            generation: 1,
            job_object_name: "Eliot-op-1-g1".to_owned(),
            root_pid: Some(10),
            process_count_before: 2,
            process_count_after: 1,
            graceful_attempted: false,
            forced_termination: true,
            stdout_closed: true,
            stderr_closed: true,
            all_tasks_joined: true,
            elapsed_ms: 20,
            terminal_error_codes: Vec::new(),
        };
        assert!(!receipt.proves_complete_reap());
        receipt.process_count_after = 0;
        assert!(receipt.proves_complete_reap());
        receipt.terminal_error_codes.push(109);
        assert!(receipt.proves_complete_reap());
        receipt.forced_termination = false;
        assert!(!receipt.proves_complete_reap());
    }
}
