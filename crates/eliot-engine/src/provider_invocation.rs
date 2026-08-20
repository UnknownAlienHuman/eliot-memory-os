use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use eliot_types::{
    BlobRef, ExternalResultCompletenessReceipt, ProviderIdentityCheck, ProviderInvocationAttempt,
    ProviderInvocationOutcome, ProviderInvocationOutcomeClass, ProviderInvocationState,
    ProviderInvocationTransition, ProviderReconciliationMethod, ProviderReconciliationRecord,
    ProviderResultCompleteness, ProviderRouteReadinessGate, ProviderRouteReadinessVerdict,
    ProviderTimeoutClass,
};
use time::{Duration, OffsetDateTime};

use crate::EngineError;
use crate::antigravity::ProviderProcessOutcome;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderOutputCapture {
    pub blob_ref: BlobRef,
    pub excerpt: String,
    pub truncation_detected: bool,
    pub stream_closed_cleanly: bool,
    pub output_observed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProviderCompletenessInput {
    pub receipt_id: String,
    pub invocation_attempt_ref: String,
    pub raw_output_ref: Option<String>,
    pub expected_schema: String,
    pub terminal_marker_or_protocol_status: Option<String>,
    pub required_fields_present: bool,
    pub truncation_detected: bool,
    pub stream_closed_cleanly: bool,
    pub process_exit_success: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProviderReconciliationInput {
    pub reconciliation_id: String,
    pub outcome_id: String,
    pub invocation_attempt_ref: String,
    pub methods_attempted: Vec<ProviderReconciliationMethod>,
    pub identity_checks: Vec<ProviderIdentityCheck>,
    pub recovered_artifacts: Vec<String>,
    pub mismatched_artifacts_quarantined: Vec<String>,
    pub completeness: ExternalResultCompletenessReceipt,
    pub recovered_review_id: Option<String>,
    pub terminal_failure_proven: bool,
    pub terminal_failure_class: Option<ProviderInvocationOutcomeClass>,
    pub dispatch_proven: bool,
    pub slot_consumed: bool,
    pub raw_output_preserved: bool,
    pub timeout_class: Option<ProviderTimeoutClass>,
    pub exact_failure_evidence_refs: Vec<String>,
    pub unresolved_questions: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub started_at: OffsetDateTime,
    pub completed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReconciliationResult {
    pub record: ProviderReconciliationRecord,
    pub outcome: ProviderInvocationOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProviderReadinessInput {
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
    pub last_successful_smoke_ref: Option<String>,
    pub provider_gate_current: bool,
    pub provider_explicitly_unavailable: bool,
    pub timeout_contract_complete: bool,
    pub timeout_profile_ref: String,
    pub durable_capture_ready: bool,
    pub reconciliation_capability: String,
    pub process_tree_cancellation_ready: bool,
    pub historical_latency_or_timeout_evidence: Vec<String>,
    pub quota_or_cost_visibility: bool,
    pub operator_authorized: bool,
    pub last_incident_class: ProviderInvocationOutcomeClass,
    pub evaluated_at: OffsetDateTime,
}

#[derive(Clone, Debug)]
pub struct ProviderInvocationJournal {
    root: PathBuf,
}

impl ProviderInvocationJournal {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn create(
        &self,
        mut attempt: ProviderInvocationAttempt,
    ) -> Result<ProviderInvocationAttempt, EngineError> {
        if !attempt.state_transitions.is_empty() {
            return Err(EngineError::WriteRejected(
                "new provider invocation attempt must not contain preexisting transitions"
                    .to_owned(),
            ));
        }
        let transition = ProviderInvocationTransition {
            transition_id: format!("{}:transition:0", attempt.invocation_attempt_id),
            from: None,
            to: ProviderInvocationState::Prepared,
            recorded_at: OffsetDateTime::now_utc(),
            evidence_refs: Vec::new(),
        };
        attempt.state_transitions.push(transition);
        self.persist_new(&attempt)?;
        Ok(attempt)
    }

    pub fn load(&self, attempt_id: &str) -> Result<ProviderInvocationAttempt, EngineError> {
        let path = self.attempt_path(attempt_id);
        let bytes = fs::read(&path)?;
        serde_json::from_slice(&bytes).map_err(EngineError::from)
    }

    pub fn transition(
        &self,
        attempt: &mut ProviderInvocationAttempt,
        next: ProviderInvocationState,
        evidence_refs: Vec<String>,
    ) -> Result<(), EngineError> {
        let current = attempt
            .state_transitions
            .last()
            .map(|transition| transition.to)
            .ok_or_else(|| {
                EngineError::WriteRejected("provider invocation has no initial state".to_owned())
            })?;
        if !ProviderInvocationLifecycleService::transition_allowed(current, next) {
            return Err(EngineError::WriteRejected(format!(
                "invalid provider invocation transition {current:?} -> {next:?}"
            )));
        }
        let mut updated = attempt.clone();
        let index = updated.state_transitions.len();
        updated
            .state_transitions
            .push(ProviderInvocationTransition {
                transition_id: format!("{}:transition:{index}", updated.invocation_attempt_id),
                from: Some(current),
                to: next,
                recorded_at: OffsetDateTime::now_utc(),
                evidence_refs,
            });
        self.persist(&updated)?;
        *attempt = updated;
        Ok(())
    }

    pub fn record_process_terminal(
        &self,
        attempt: &mut ProviderInvocationAttempt,
        process: &ProviderProcessOutcome,
    ) -> Result<(), EngineError> {
        let mut terminal = attempt.clone();
        terminal.process_started_at = Some(process.process_started_at);
        terminal.first_output_at = process.first_output_at;
        terminal.last_output_at = process.last_output_at;
        terminal.process_exit_at = process.process_exit_at;
        terminal.cleanup_completed_at = Some(process.cleanup_completed_at);
        terminal.exit_code_or_signal = Some(process.exit_code.map_or_else(
            || {
                if process.reap_receipt.forced_termination {
                    "forced_termination".to_owned()
                } else if process.cancelled {
                    "cancelled_without_exit_code".to_owned()
                } else if process.timed_out {
                    format!("timeout:{:?}", process.timeout_class)
                } else {
                    "unknown_without_exit_code".to_owned()
                }
            },
            |code| format!("exit_code:{code}"),
        ));
        let root_pid = process
            .reap_receipt
            .root_pid
            .map_or_else(|| "unknown".to_owned(), |pid| pid.to_string());
        terminal.process_or_job_identity = Some(format!(
            "pid:{};job={};reap_complete={};observed_processes={}",
            root_pid,
            process.reap_receipt.job_object_name,
            process.reap_receipt.proves_complete_reap(),
            process.observed_processes.len()
        ));
        terminal.timeout_class = process.timeout_class;
        terminal.process_reap_receipt = Some(process.reap_receipt.clone());
        terminal.process_timed_out = Some(process.timed_out);
        terminal.process_cancelled = Some(process.cancelled);
        terminal
            .process_worker_error
            .clone_from(&process.worker_error);
        terminal.stdout_total_bytes = Some(process.stdout_total_bytes);
        terminal.stderr_total_bytes = Some(process.stderr_total_bytes);
        terminal.stdout_truncated = Some(process.stdout_truncated);
        terminal.stderr_truncated = Some(process.stderr_truncated);
        let evidence_refs = vec![
            format!("job_object:{}", process.reap_receipt.job_object_name),
            format!("exit_code:{:?}", process.exit_code),
            format!("timeout_class:{:?}", process.timeout_class),
            format!(
                "reap_complete:{}",
                process.reap_receipt.proves_complete_reap()
            ),
        ];
        if let Err(error) = self.transition(
            &mut terminal,
            ProviderInvocationState::ProcessTerminal,
            evidence_refs,
        ) {
            return match self.persist_terminal_reconciliation(&terminal, process, &error) {
                Ok(reconciliation_ref) => Err(EngineError::WriteRejected(format!(
                    "provider process outcome returned but terminal journal persistence failed; provider redispatch is forbidden; reconciliation required at {reconciliation_ref}: {error}"
                ))),
                Err(sidecar_error) => Err(EngineError::WriteRejected(format!(
                    "provider process outcome returned but both terminal journal and reconciliation sidecar persistence failed; provider redispatch is forbidden; journal_error={error}; sidecar_error={sidecar_error}"
                ))),
            };
        }
        *attempt = terminal;
        Ok(())
    }

    pub fn record_post_dispatch_failure(
        &self,
        attempt: &mut ProviderInvocationAttempt,
        mut evidence_refs: Vec<String>,
    ) -> Result<(), EngineError> {
        evidence_refs.push("provider_redispatch_forbidden:true".to_owned());
        if let Err(error) = self.transition(
            attempt,
            ProviderInvocationState::TimeoutPendingReconciliation,
            evidence_refs.clone(),
        ) {
            return match self.persist_post_dispatch_reconciliation(attempt, &evidence_refs, &error)
            {
                Ok(reconciliation_ref) => Err(EngineError::WriteRejected(format!(
                    "post-dispatch provider failure could not be journaled; provider redispatch is forbidden; reconciliation required at {reconciliation_ref}: {error}"
                ))),
                Err(sidecar_error) => Err(EngineError::WriteRejected(format!(
                    "post-dispatch provider failure could not be journaled and its reconciliation sidecar also failed; provider redispatch is forbidden; journal_error={error}; sidecar_error={sidecar_error}"
                ))),
            };
        }
        Ok(())
    }

    pub fn record_captured_output(
        &self,
        attempt: &mut ProviderInvocationAttempt,
        stdout: BlobRef,
        stderr: BlobRef,
    ) -> Result<(), EngineError> {
        let mut updated = attempt.clone();
        updated.stdout_blob_or_hash = Some(stdout);
        updated.stderr_blob_or_hash = Some(stderr);
        self.persist(&updated)?;
        *attempt = updated;
        Ok(())
    }

    pub fn persist(&self, attempt: &ProviderInvocationAttempt) -> Result<(), EngineError> {
        let path = self.attempt_path(&attempt.invocation_attempt_id);
        let bytes = serde_json::to_vec_pretty(attempt)?;
        atomic_write(&path, &bytes)
    }

    fn persist_new(&self, attempt: &ProviderInvocationAttempt) -> Result<(), EngineError> {
        let path = self.attempt_path(&attempt.invocation_attempt_id);
        let parent = path.parent().ok_or_else(|| {
            EngineError::WriteRejected("provider attempt path has no parent".to_owned())
        })?;
        fs::create_dir_all(parent)?;
        let bytes = serde_json::to_vec_pretty(attempt)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                EngineError::WriteRejected(format!(
                    "provider invocation attempt create-only CAS failed at {}: {error}",
                    path.display()
                ))
            })?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn attempt_path(&self, attempt_id: &str) -> PathBuf {
        self.root
            .join("runtime/provider-invocations")
            .join(format!("{}.json", safe_component(attempt_id)))
    }

    fn persist_terminal_reconciliation(
        &self,
        attempt: &ProviderInvocationAttempt,
        process: &ProviderProcessOutcome,
        persistence_error: &EngineError,
    ) -> Result<String, EngineError> {
        let relative_path = format!(
            "runtime/provider-invocation-reconciliation/{}.json",
            safe_component(&attempt.invocation_attempt_id)
        );
        let value = serde_json::json!({
            "schema_version": "provider-terminal-reconciliation-v1",
            "invocation_attempt_id": attempt.invocation_attempt_id,
            "reconciliation_required": true,
            "provider_redispatch_forbidden": true,
            "process_started_at": process.process_started_at,
            "first_output_at": process.first_output_at,
            "last_output_at": process.last_output_at,
            "process_exit_at": process.process_exit_at,
            "cleanup_completed_at": process.cleanup_completed_at,
            "exit_code": process.exit_code,
            "timed_out": process.timed_out,
            "timeout_class": process.timeout_class,
            "cancelled": process.cancelled,
            "worker_error": process.worker_error,
            "stdout_total_bytes": process.stdout_total_bytes,
            "stderr_total_bytes": process.stderr_total_bytes,
            "stdout_truncated": process.stdout_truncated,
            "stderr_truncated": process.stderr_truncated,
            "reap_receipt": process.reap_receipt,
            "journal_persistence_error": persistence_error.to_string(),
            "recorded_at": OffsetDateTime::now_utc(),
        });
        atomic_write(
            &self.root.join(&relative_path),
            &serde_json::to_vec_pretty(&value)?,
        )?;
        Ok(relative_path)
    }

    fn persist_post_dispatch_reconciliation(
        &self,
        attempt: &ProviderInvocationAttempt,
        evidence_refs: &[String],
        persistence_error: &EngineError,
    ) -> Result<String, EngineError> {
        let relative_path = format!(
            "runtime/provider-invocation-reconciliation/{}.json",
            safe_component(&attempt.invocation_attempt_id)
        );
        let value = serde_json::json!({
            "schema_version": "provider-post-dispatch-reconciliation-v1",
            "invocation_attempt_id": attempt.invocation_attempt_id,
            "reconciliation_required": true,
            "provider_redispatch_forbidden": true,
            "last_durable_state": attempt.state_transitions.last().map(|transition| transition.to),
            "evidence_refs": evidence_refs,
            "journal_persistence_error": persistence_error.to_string(),
            "recorded_at": OffsetDateTime::now_utc(),
        });
        atomic_write(
            &self.root.join(&relative_path),
            &serde_json::to_vec_pretty(&value)?,
        )?;
        Ok(relative_path)
    }
}

pub struct ProviderInvocationLifecycleService;

impl ProviderInvocationLifecycleService {
    pub fn transition_allowed(
        current: ProviderInvocationState,
        next: ProviderInvocationState,
    ) -> bool {
        use ProviderInvocationState as State;
        matches!(
            (current, next),
            (State::Prepared, State::Reserved | State::PreDispatchAborted)
                | (
                    State::Reserved,
                    State::DispatchStarting | State::PreDispatchAborted
                )
                | (
                    State::DispatchStarting,
                    State::Dispatched
                        | State::ProcessTerminal
                        | State::DispatchAckUnknown
                        | State::PreDispatchAborted
                )
                | (
                    State::Dispatched,
                    State::Running
                        | State::ProcessTerminal
                        | State::TimeoutPendingReconciliation
                        | State::ProcessExitedNonzero
                        | State::CancelledAfterDispatch
                        | State::LocalCaptureFailed
                )
                | (
                    State::Running,
                    State::ProcessTerminal | State::TimeoutPendingReconciliation
                )
                | (
                    State::ProcessTerminal,
                    State::OutputObserved
                        | State::CompletedCaptured
                        | State::TimeoutPendingReconciliation
                        | State::ProcessExitedNonzero
                        | State::CancelledAfterDispatch
                        | State::LocalCaptureFailed
                        | State::ProtocolParseFailed
                        | State::CleanupFailedAfterComplete
                        | State::NonReconcilableUnknown
                )
                | (
                    State::OutputObserved,
                    State::CompletedCaptured
                        | State::TimeoutPendingReconciliation
                        | State::ProcessExitedNonzero
                        | State::CancelledAfterDispatch
                        | State::LocalCaptureFailed
                        | State::ProtocolParseFailed
                        | State::CleanupFailedAfterComplete
                )
                | (
                    State::CompletedCaptured,
                    State::ReviewNormalized
                        | State::CleanupFailedAfterComplete
                        | State::ReconciledCompleted
                )
                | (
                    State::TimeoutPendingReconciliation
                        | State::DispatchAckUnknown
                        | State::LocalCaptureFailed,
                    State::ReconciledCompleted
                        | State::ReconciledFailed
                        | State::NonReconcilableUnknown
                )
                | (
                    State::CleanupFailedAfterComplete,
                    State::ReconciledCompleted
                )
        )
    }
}

pub struct ProviderOutputSpool;

impl ProviderOutputSpool {
    pub fn capture<R: Read>(
        &self,
        root: &Path,
        invocation_attempt_id: &str,
        stream_name: &str,
        mut reader: R,
        max_bytes: u64,
    ) -> Result<ProviderOutputCapture, EngineError> {
        if !matches!(stream_name, "stdout" | "stderr" | "structured" | "log") {
            return Err(EngineError::WriteRejected(
                "provider output stream name is not governed".to_owned(),
            ));
        }
        let mut buffer = [0_u8; 8192];
        let limit = usize::try_from(max_bytes).map_err(|_| {
            EngineError::WriteRejected("provider output limit does not fit usize".to_owned())
        })?;
        let mut bytes = Vec::new();
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let remaining = limit.saturating_add(1).saturating_sub(bytes.len());
            bytes.extend_from_slice(&buffer[..read.min(remaining)]);
        }
        if bytes.len() > limit {
            bytes.fill(0);
            return Err(EngineError::WriteRejected(
                "secret boundary rejected provider output: output_too_large".to_owned(),
            ));
        }
        if let Err(violation) = eliot_types::inspect_secret_bytes(&bytes) {
            bytes.fill(0);
            return Err(EngineError::WriteRejected(format!(
                "secret boundary rejected provider output: {}",
                violation.rule
            )));
        }
        let relative_path = format!(
            "spool/provider-invocations/{}/{}.bin",
            safe_component(invocation_attempt_id),
            stream_name
        );
        let path = root.join(&relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut output = File::create(&path)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        let digest_hex = blake3::hash(&bytes).to_hex().to_string();
        let persisted = u64::try_from(bytes.len()).map_err(|_| {
            EngineError::WriteRejected("provider output size does not fit u64".to_owned())
        })?;
        let excerpt = String::from_utf8_lossy(&bytes[..bytes.len().min(2_000)]).into_owned();
        Ok(ProviderOutputCapture {
            blob_ref: BlobRef {
                algorithm: "blake3".to_owned(),
                digest_hex,
                size_bytes: persisted,
                relative_path,
            },
            excerpt,
            truncation_detected: false,
            stream_closed_cleanly: true,
            output_observed: !bytes.is_empty(),
        })
    }
}

pub struct ExternalResultCompletenessService;

impl ExternalResultCompletenessService {
    pub fn evaluate(&self, input: ProviderCompletenessInput) -> ExternalResultCompletenessReceipt {
        let complete = input.process_exit_success
            && input.required_fields_present
            && input.terminal_marker_or_protocol_status.is_some()
            && !input.truncation_detected
            && input.stream_closed_cleanly;
        ExternalResultCompletenessReceipt {
            completeness_receipt_id: input.receipt_id,
            invocation_attempt_ref: input.invocation_attempt_ref,
            raw_output_ref: input.raw_output_ref,
            parser_version: "provider-completeness-1".to_owned(),
            expected_schema: input.expected_schema,
            terminal_marker_or_protocol_status: input.terminal_marker_or_protocol_status,
            required_fields_present: input.required_fields_present,
            truncation_detected: input.truncation_detected,
            stream_closed_cleanly: input.stream_closed_cleanly,
            result_complete: complete,
            normalization_allowed: complete,
        }
    }
}

pub struct ProviderReconciliationService;

impl ProviderReconciliationService {
    pub fn reconcile(&self, input: ProviderReconciliationInput) -> ProviderReconciliationResult {
        let identity_matched = !input.identity_checks.is_empty()
            && input
                .identity_checks
                .iter()
                .all(|check| check.matched == Some(true));
        let recovered_complete = input.completeness.result_complete
            && identity_matched
            && input.recovered_review_id.is_some();
        let (effective_state, outcome_class, result_completeness) = if recovered_complete {
            (
                ProviderInvocationState::ReconciledCompleted,
                ProviderInvocationOutcomeClass::CompletedReview,
                ProviderResultCompleteness::Complete,
            )
        } else if input.terminal_failure_proven {
            (
                ProviderInvocationState::ReconciledFailed,
                input
                    .terminal_failure_class
                    .unwrap_or(ProviderInvocationOutcomeClass::ProcessExitNonzero),
                if input.completeness.raw_output_ref.is_some() {
                    ProviderResultCompleteness::Partial
                } else {
                    ProviderResultCompleteness::Missing
                },
            )
        } else {
            (
                ProviderInvocationState::NonReconcilableUnknown,
                ProviderInvocationOutcomeClass::NonReconcilableUnknown,
                if input
                    .identity_checks
                    .iter()
                    .any(|check| check.matched == Some(false))
                {
                    ProviderResultCompleteness::Mismatched
                } else if input.completeness.raw_output_ref.is_some() {
                    ProviderResultCompleteness::Partial
                } else {
                    ProviderResultCompleteness::Missing
                },
            )
        };
        let record = ProviderReconciliationRecord {
            reconciliation_id: input.reconciliation_id,
            invocation_attempt_ref: input.invocation_attempt_ref.clone(),
            started_at: input.started_at,
            completed_at: input.completed_at,
            methods_attempted: input.methods_attempted,
            provider_generating_call_performed: false,
            identity_checks: input.identity_checks,
            recovered_artifacts: input.recovered_artifacts,
            mismatched_artifacts_quarantined: input.mismatched_artifacts_quarantined,
            result_completeness,
            effective_state_after: effective_state,
            review_id_if_recovered: recovered_complete
                .then_some(input.recovered_review_id)
                .flatten(),
            unresolved_questions: input.unresolved_questions.clone(),
            verifier_refs: input.verifier_refs,
        };
        let outcome = ProviderInvocationOutcome {
            outcome_id: input.outcome_id,
            invocation_attempt_ref: input.invocation_attempt_ref,
            effective_state,
            outcome_class,
            timeout_class: input.timeout_class,
            dispatch_proven: input.dispatch_proven,
            slot_consumed: input.slot_consumed,
            result_complete: recovered_complete,
            review_created: recovered_complete,
            raw_output_preserved: input.raw_output_preserved,
            exact_failure_evidence_refs: input.exact_failure_evidence_refs,
            unresolved_questions: input.unresolved_questions,
            retry_same_campaign_allowed: false,
            next_allowed_transition:
                "fresh campaign after route readiness and operator authorization".to_owned(),
        };
        ProviderReconciliationResult { record, outcome }
    }
}

pub struct ProviderRouteReadinessService;

impl ProviderRouteReadinessService {
    pub fn evaluate(&self, input: ProviderReadinessInput) -> ProviderRouteReadinessGate {
        let (verdict, reasons) = if !input.local_adapter_health
            || !input.executable_available
            || !input.auth_or_configuration_present
            || !input.installed
            || !input.provider_authenticated
            || !input.exact_model_selectable
            || !input.mcp_config_valid
            || !input.mcp_process_started
            || !input.mcp_initialized
            || !input.required_tools_visible
            || !input.structured_output_ready
            || !input.console_headless_ready
            || !input.durable_capture_ready
            || !input.process_tree_cancellation_ready
        {
            (
                ProviderRouteReadinessVerdict::BlockedByLocalRoute,
                vec!["local provider route or durable supervision is incomplete".to_owned()],
            )
        } else if input.provider_explicitly_unavailable || !input.provider_gate_current {
            (
                ProviderRouteReadinessVerdict::BlockedByProvider,
                vec!["provider gate is unavailable or stale".to_owned()],
            )
        } else if !input.timeout_contract_complete {
            (
                ProviderRouteReadinessVerdict::BlockedByUnknownTimeoutContract,
                vec![
                    "critical timeout or reconciliation contract fields remain unknown".to_owned(),
                ],
            )
        } else if !input.operator_authorized {
            (
                ProviderRouteReadinessVerdict::RequiresOperatorAuthorization,
                vec!["technical route is ready but no fresh-call authorization exists".to_owned()],
            )
        } else {
            (
                ProviderRouteReadinessVerdict::ReadyForFreshCanary,
                vec!["technical gates and separate operator authorization are present".to_owned()],
            )
        };
        ProviderRouteReadinessGate {
            readiness_gate_id: input.readiness_gate_id,
            provider: input.provider,
            route_or_model: input.route_or_model,
            local_adapter_health: input.local_adapter_health,
            executable_available: input.executable_available,
            auth_or_configuration_present: input.auth_or_configuration_present,
            installed: input.installed,
            provider_authenticated: input.provider_authenticated,
            exact_model_selectable: input.exact_model_selectable,
            mcp_config_valid: input.mcp_config_valid,
            mcp_process_started: input.mcp_process_started,
            mcp_initialized: input.mcp_initialized,
            required_tools_visible: input.required_tools_visible,
            structured_output_ready: input.structured_output_ready,
            console_headless_ready: input.console_headless_ready,
            last_successful_smoke_ref: input.last_successful_smoke_ref,
            provider_gate_current: input.provider_gate_current,
            last_incident_class: input.last_incident_class,
            timeout_profile_ref: input.timeout_profile_ref,
            durable_capture_ready: input.durable_capture_ready,
            reconciliation_capability: input.reconciliation_capability,
            process_tree_cancellation_ready: input.process_tree_cancellation_ready,
            historical_latency_or_timeout_evidence: input.historical_latency_or_timeout_evidence,
            quota_or_cost_visibility: input.quota_or_cost_visibility,
            fresh_campaign_required: true,
            operator_authorization_required: true,
            verdict,
            reasons,
            expires_at: input.evaluated_at + Duration::hours(24),
        }
    }
}

pub fn antigravity_plan_route_policy() -> eliot_types::ProviderRoutePolicy {
    eliot_types::ProviderRoutePolicy::for_route(
        eliot_types::AgentHostId::Antigravity,
        "agy plan print audit",
        eliot_types::ProviderDeclaredBudget::new(310_000, 8 * 1024 * 1024)
            .with_spawn_deadline_ms(None)
            .with_first_output_deadline_ms(None)
            .with_cancellation_grace_ms(5_000)
            .with_cleanup_grace_ms(45_000)
            .with_reconciliation_window_ms(86_400_000),
    )
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), EngineError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let next = path.with_extension("json.next");
    let backup = path.with_extension("json.previous");
    let mut file = File::create(&next)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if path.exists() {
        if backup.exists() {
            fs::remove_file(&backup)?;
        }
        fs::rename(path, &backup)?;
    }
    if let Err(error) = fs::rename(&next, path) {
        if backup.exists() {
            let _ = fs::rename(&backup, path);
        }
        return Err(error.into());
    }
    if backup.exists() {
        fs::remove_file(backup)?;
    }
    Ok(())
}

fn safe_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::ProviderOutputSpool;

    #[test]
    fn secret_spool_is_rejected_before_file_creation() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-provider-secret-boundary-{}",
            uuid::Uuid::new_v4()
        ));
        let relative = "spool/provider-invocations/attempt/stdout.bin";
        let Some(error) = ProviderOutputSpool
            .capture(
                &root,
                "attempt",
                "stdout",
                std::io::Cursor::new(
                    b"Authorization: Bearer synthetic-token-value-12345".as_slice(),
                ),
                64 * 1024,
            )
            .err()
        else {
            return Err(
                std::io::Error::other("secret-bearing provider output was accepted").into(),
            );
        };
        assert!(error.to_string().contains("authorization_header"));
        assert!(!root.join(relative).exists());
        if root.exists() {
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }
}
