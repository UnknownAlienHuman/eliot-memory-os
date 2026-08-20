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

pub const DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION: &str = "eliot-descendants-at-root-exit-v1";
pub const MAX_DESCENDANTS_AT_ROOT_EXIT: usize = 64;
pub const MAX_DESCENDANT_IMAGE_PATH_CHARS: usize = 4096;
pub const MAX_DESCENDANT_DETAIL_CHARS: usize = 512;
pub const MAX_DESCENDANT_IMAGE_SHA256_CHARS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescendantFileIdentity {
    pub volume_serial_number: u32,
    pub file_index: u64,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescendantProcessSnapshot {
    pub pid: u32,
    pub start_ticks: u64,
    pub image_path: String,
    pub file_identity: DescendantFileIdentity,
    pub image_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescendantsCaptureErrorKind {
    Overflow,
    EnumerationFailed,
    AccessDenied,
    Ambiguous,
    Duplicate,
    InvalidPid,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescendantsAtRootExitCaptured {
    pub schema_version: String,
    pub root_pid: u32,
    pub root_exit_code: Option<i32>,
    pub capture_elapsed_ms: u64,
    pub descendants: Vec<DescendantProcessSnapshot>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescendantsAtRootExitFailed {
    pub schema_version: String,
    pub root_pid: Option<u32>,
    pub root_exit_code: Option<i32>,
    pub capture_elapsed_ms: u64,
    pub error_kind: DescendantsCaptureErrorKind,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DescendantsAtRootExit {
    Captured(DescendantsAtRootExitCaptured),
    Failed(DescendantsAtRootExitFailed),
}

impl DescendantsAtRootExit {
    pub fn captured(
        root_pid: u32,
        root_exit_code: Option<i32>,
        capture_elapsed_ms: u64,
        mut descendants: Vec<DescendantProcessSnapshot>,
    ) -> Result<Self, String> {
        if root_pid == 0 {
            return Err("root_pid must be non-zero".to_owned());
        }
        if descendants.len() > MAX_DESCENDANTS_AT_ROOT_EXIT {
            return Err(format!(
                "descendants overflow: {} > {}",
                descendants.len(),
                MAX_DESCENDANTS_AT_ROOT_EXIT
            ));
        }
        descendants.sort_by_key(|entry| entry.pid);
        for window in descendants.windows(2) {
            if window[0].pid == window[1].pid {
                return Err(format!("duplicate pid {}", window[0].pid));
            }
        }
        for entry in &descendants {
            Self::validate_snapshot(entry, root_pid)?;
        }
        Ok(Self::Captured(DescendantsAtRootExitCaptured {
            schema_version: DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION.to_owned(),
            root_pid,
            root_exit_code,
            capture_elapsed_ms,
            descendants,
        }))
    }

    pub fn failed(
        root_pid: Option<u32>,
        root_exit_code: Option<i32>,
        capture_elapsed_ms: u64,
        error_kind: DescendantsCaptureErrorKind,
        detail: impl Into<String>,
    ) -> Result<Self, String> {
        let detail = detail.into();
        if detail.chars().count() > MAX_DESCENDANT_DETAIL_CHARS {
            return Err(format!(
                "detail overflow: {} > {}",
                detail.chars().count(),
                MAX_DESCENDANT_DETAIL_CHARS
            ));
        }
        if let Some(pid) = root_pid
            && pid == 0
        {
            return Err("root_pid must be non-zero".to_owned());
        }
        Ok(Self::Failed(DescendantsAtRootExitFailed {
            schema_version: DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION.to_owned(),
            root_pid,
            root_exit_code,
            capture_elapsed_ms,
            error_kind,
            detail,
        }))
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Captured(captured) => {
                if captured.schema_version != DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION {
                    return Err(format!(
                        "invalid schema_version {}",
                        captured.schema_version
                    ));
                }
                if captured.root_pid == 0 {
                    return Err("root_pid must be non-zero".to_owned());
                }
                if captured.descendants.len() > MAX_DESCENDANTS_AT_ROOT_EXIT {
                    return Err("descendants overflow".to_owned());
                }
                let mut sorted = captured.descendants.clone();
                sorted.sort_by_key(|entry| entry.pid);
                if sorted != captured.descendants {
                    return Err("descendants must be sorted by pid".to_owned());
                }
                for entry in &captured.descendants {
                    Self::validate_snapshot(entry, captured.root_pid)?;
                }
                for window in captured.descendants.windows(2) {
                    if window[0].pid == window[1].pid {
                        return Err(format!("duplicate pid {}", window[0].pid));
                    }
                }
                Ok(())
            }
            Self::Failed(failed) => {
                if failed.schema_version != DESCENDANTS_AT_ROOT_EXIT_SCHEMA_VERSION {
                    return Err(format!("invalid schema_version {}", failed.schema_version));
                }
                if failed.detail.chars().count() > MAX_DESCENDANT_DETAIL_CHARS {
                    return Err("detail overflow".to_owned());
                }
                if let Some(pid) = failed.root_pid
                    && pid == 0
                {
                    return Err("root_pid must be non-zero".to_owned());
                }
                Ok(())
            }
        }
    }

    fn validate_snapshot(entry: &DescendantProcessSnapshot, root_pid: u32) -> Result<(), String> {
        if entry.pid == 0 {
            return Err("pid must be non-zero".to_owned());
        }
        if entry.pid == root_pid {
            return Err(format!("descendant pid {} equals root pid", entry.pid));
        }
        if entry.image_path.chars().count() > MAX_DESCENDANT_IMAGE_PATH_CHARS {
            return Err(format!(
                "image_path overflow: {} > {}",
                entry.image_path.chars().count(),
                MAX_DESCENDANT_IMAGE_PATH_CHARS
            ));
        }
        if entry.image_path.is_empty() {
            return Err("image_path must be non-empty".to_owned());
        }
        if let Some(sha) = &entry.image_sha256 {
            if sha.chars().count() > MAX_DESCENDANT_IMAGE_SHA256_CHARS {
                return Err("image_sha256 overflow".to_owned());
            }
            if sha.is_empty() {
                return Err("image_sha256 must be non-empty".to_owned());
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn is_captured(&self) -> bool {
        matches!(self, Self::Captured(_))
    }

    #[must_use]
    pub fn descendants(&self) -> Option<&[DescendantProcessSnapshot]> {
        match self {
            Self::Captured(captured) => Some(&captured.descendants),
            Self::Failed(_) => None,
        }
    }
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
    pub descendants_at_root_exit: DescendantsAtRootExit,
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        DescendantFileIdentity, DescendantProcessSnapshot, DescendantsAtRootExit,
        DescendantsCaptureErrorKind, MAX_DESCENDANT_DETAIL_CHARS, MAX_DESCENDANT_IMAGE_PATH_CHARS,
        MAX_DESCENDANTS_AT_ROOT_EXIT, ProcessReapReceipt,
    };

    fn empty_captured(root_pid: u32) -> DescendantsAtRootExit {
        DescendantsAtRootExit::captured(root_pid, Some(0), 10, Vec::new()).unwrap()
    }

    fn descendant(pid: u32, _root_pid: u32) -> DescendantProcessSnapshot {
        DescendantProcessSnapshot {
            pid,
            start_ticks: 1_000 + u64::from(pid),
            image_path: format!("C:\\Windows\\System32\\descendant-{pid}.exe"),
            file_identity: DescendantFileIdentity {
                volume_serial_number: 0x1234,
                file_index: u64::from(pid) * 10,
            },
            image_sha256: Some(format!("{pid:064x}")),
        }
    }

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
            descendants_at_root_exit: empty_captured(10),
        };
        assert!(!receipt.proves_complete_reap());
        receipt.process_count_after = 0;
        assert!(receipt.proves_complete_reap());
        receipt.terminal_error_codes.push(109);
        assert!(receipt.proves_complete_reap());
        receipt.forced_termination = false;
        assert!(!receipt.proves_complete_reap());
    }

    #[test]
    fn descendants_captured_rejects_pid_zero_and_root_pid() {
        assert!(DescendantsAtRootExit::captured(10, None, 0, vec![descendant(0, 10)]).is_err());
        assert!(DescendantsAtRootExit::captured(10, None, 0, vec![descendant(10, 10)]).is_err());
    }

    #[test]
    fn descendants_captured_enforces_sort_and_dedup() {
        let first = descendant(20, 10);
        let second = descendant(21, 10);
        let out_of_order =
            DescendantsAtRootExit::captured(10, None, 5, vec![second.clone(), first.clone()]);
        assert!(out_of_order.is_ok());
        if let DescendantsAtRootExit::Captured(captured) = out_of_order.unwrap() {
            assert_eq!(captured.descendants[0].pid, 20);
            assert_eq!(captured.descendants[1].pid, 21);
        } else {
            panic!("expected captured");
        }
        let duplicate =
            DescendantsAtRootExit::captured(10, None, 5, vec![first.clone(), first.clone()]);
        assert!(duplicate.is_err());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn descendants_captured_rejects_overflow_and_path_bounds() {
        let many = (1..=MAX_DESCENDANTS_AT_ROOT_EXIT + 1)
            .map(|pid| descendant(u32::try_from(pid).unwrap() + 100, 10))
            .collect::<Vec<_>>();
        assert!(DescendantsAtRootExit::captured(10, None, 0, many).is_err());
        let mut long = descendant(30, 10);
        long.image_path = "a".repeat(MAX_DESCENDANT_IMAGE_PATH_CHARS + 1);
        assert!(DescendantsAtRootExit::captured(10, None, 0, vec![long]).is_err());
    }

    #[test]
    fn descendants_failed_rejects_detail_overflow() {
        let long = "x".repeat(MAX_DESCENDANT_DETAIL_CHARS + 1);
        assert!(
            DescendantsAtRootExit::failed(
                Some(10),
                None,
                0,
                DescendantsCaptureErrorKind::Overflow,
                long
            )
            .is_err()
        );
    }

    #[test]
    fn descendants_serialization_round_trips_and_validates_bounds() {
        let captured =
            DescendantsAtRootExit::captured(10, Some(0), 5, vec![descendant(20, 10)]).unwrap();
        let json = serde_json::to_string(&captured).unwrap();
        let decoded: DescendantsAtRootExit = serde_json::from_str(&json).unwrap();
        assert!(decoded.validate().is_ok());
        assert_eq!(captured, decoded);
        let receipt = ProcessReapReceipt {
            operation_id: "op-2".to_owned(),
            generation: 1,
            job_object_name: "Eliot-op-2-g1".to_owned(),
            root_pid: Some(10),
            process_count_before: 2,
            process_count_after: 0,
            graceful_attempted: false,
            forced_termination: true,
            stdout_closed: true,
            stderr_closed: true,
            all_tasks_joined: true,
            elapsed_ms: 20,
            terminal_error_codes: Vec::new(),
            descendants_at_root_exit: captured,
        };
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        let decoded_receipt: ProcessReapReceipt = serde_json::from_str(&receipt_json).unwrap();
        assert!(decoded_receipt.descendants_at_root_exit.validate().is_ok());
    }

    #[test]
    fn old_receipt_without_descendants_fails_to_deserialize() {
        let old = serde_json::json!({
            "operation_id": "op-1",
            "generation": 1,
            "job_object_name": "Eliot-op-1-g1",
            "root_pid": 10,
            "process_count_before": 1,
            "process_count_after": 0,
            "graceful_attempted": false,
            "forced_termination": true,
            "stdout_closed": true,
            "stderr_closed": true,
            "all_tasks_joined": true,
            "elapsed_ms": 20,
            "terminal_error_codes": []
        });
        let decoded: Result<ProcessReapReceipt, _> = serde_json::from_value(old);
        assert!(decoded.is_err());
    }

    #[test]
    fn failed_snapshot_is_not_authoritative_empty() {
        let failed = DescendantsAtRootExit::failed(
            Some(10),
            Some(1),
            5,
            DescendantsCaptureErrorKind::AccessDenied,
            "access denied",
        )
        .unwrap();
        assert!(!failed.is_captured());
        assert!(failed.descendants().is_none());
        assert!(failed.validate().is_ok());
        let captured_empty = empty_captured(10);
        assert!(captured_empty.is_captured());
        assert_eq!(captured_empty.descendants().unwrap().len(), 0);
    }

    #[test]
    fn schema_version_must_match_constant() {
        let mut captured = DescendantsAtRootExit::captured(10, None, 0, Vec::new()).unwrap();
        if let DescendantsAtRootExit::Captured(ref mut inner) = captured {
            inner.schema_version = "wrong".to_owned();
        }
        assert!(captured.validate().is_err());
    }
}
