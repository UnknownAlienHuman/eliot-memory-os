//! Shared-executor research provider execution.
//!
//! `ProviderBridge` is deliberately an adapter around the one public
//! `ProcessExecutor` contract. It builds no executable intent or permit: the
//! injected `ResearchRequestPort` is the composition seam that consumes a
//! Kernel-authorized request and the exact typed wire bytes. Every operation
//! remains operation-local; timeout, cancellation, crash, and unknown outcomes
//! are retained as evidence and are never converted into a clean retry.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eliot_process::{
    CancellationReceipt, EnvironmentInheritance, ExitDisposition, OperationId, ProcessEvidence,
    ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView, ProcessExecutor,
    ProcessLifecycle, ProcessRequest, ProcessStartReceipt,
};
use eliot_process_executor::{CapturedStream, WindowsProcessExecutor};
use eliot_research_exchange_api::{
    CompletionDisposition, CoverageGap, CoverageGapKind, ResearchEvidenceBundle,
    ResearchQueryRequest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::BridgeError;
use crate::admission::ProviderAdmission;
use crate::evidence::{
    ProviderAttemptReceipt, ProviderCleanupReceipt, RawProviderEvidence, sha256_hex,
};
use crate::protocol::{
    CoverageDenominator, PROVIDER_WIRE_ARGUMENT, ResultFrame, SubmitAck, SubmitEnvelope,
    scan_result_frame,
};

/// Compile-time proof that the production binding uses the shared P-03/P-04
/// contract rather than a private process launcher.
const _: fn() = || {
    fn requires_shared_contract<E: ProcessExecutor>() {}
    requires_shared_contract::<WindowsProcessExecutor>();
};

/// Default fallback wait ceiling. An admission always narrows this to its
/// absolute deadline before start.
pub const BOUND_RUN_DEADLINE: Duration = Duration::from_secs(30);
const BOUND_RUN_POLL: Duration = Duration::from_millis(25);
const MAX_ADMISSION_WAIT: Duration = Duration::from_hours(24);

/// Typed failure of the request-minting/delivery port.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RequestPortError {
    /// No Kernel-issued process authority is available in this scope.
    #[error("no Kernel-issued process authority is available in this scope")]
    NoAuthority,
    /// The port refused to mint a request for this operation.
    #[error("the request port refused the binding")]
    Refused,
    /// The port did not deliver the exact admitted wire bytes.
    #[error("the request port did not deliver the admitted wire envelope")]
    WireDeliveryRefused,
    /// The pre-start intent record could not be durably recorded.
    #[error("the request port could not persist the provider intent record")]
    EvidenceUnavailable,
}

/// Composition-root seam that mints an authorized request and delivers the
/// exact wire bytes to the child-facing launch material.
pub trait ResearchRequestPort: Send + Sync {
    /// Binds one admitted operation and exact wire envelope to one process
    /// request. Implementations must place `wire_bytes` in the child launch
    /// material; the bridge verifies that fact before start.
    fn bind(
        &self,
        admission: &ProviderAdmission,
        envelope: &SubmitEnvelope,
        wire_bytes: &[u8],
    ) -> Result<ProcessRequest, RequestPortError>;
}

/// Terminal provider outcome in provider-local terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOutcome {
    /// Provider completed and a candidate frame was correlated.
    Completed,
    /// Provider completed with a crash/failure disposition.
    Crashed,
    /// The terminal wait exceeded the admitted deadline.
    TimedOut,
    /// Cancellation stopped the tree and was receipted.
    Cancelled,
    /// The external outcome cannot be classified yet.
    Unknown,
}

/// Why a provider attempt cannot be treated as a successful result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFailureKind {
    /// Typed provider result reported failure.
    ProviderFailed,
    /// Provider reported cancellation.
    ProviderCancelled,
    /// Wire was malformed or failed exact correlation.
    Protocol,
    /// Raw/process evidence is incomplete.
    Evidence,
    /// Timeout/unknown/crash outcome.
    Process,
}

/// One executed provider attempt and its durable operation receipt.
#[derive(Clone, Debug)]
pub struct ProviderExecution {
    /// Stable admitted operation identity, never the provider job id.
    pub job_id: String,
    pub outcome: ProviderOutcome,
    /// Immutable raw stdout/stderr/exit/lineage evidence.
    pub evidence: RawProviderEvidence,
    /// Provider-local correlation reference, if decoded.
    pub provider_job_ref: Option<String>,
    /// Exact provider result frame, if decoded.
    pub result_frame: Option<ResultFrame>,
    /// Canonical submit wire bytes actually delivered to the child.
    pub wire_bytes: Vec<u8>,
    /// Full route/privacy/budget/usage/deadline/cancel/cleanup receipt.
    pub receipt: ProviderAttemptReceipt,
    /// Candidate-only evidence/coverage material, if a result was available.
    pub candidate: Option<ResearchEvidenceBundle>,
    /// Stable failure projection for this attempt, if any.
    pub failure: Option<ProviderFailureKind>,
}

impl ProviderExecution {
    /// Projects this physical/provider outcome to a stable bridge error.
    #[must_use]
    pub fn bridge_error(&self) -> Option<BridgeError> {
        match self.failure {
            None => None,
            Some(ProviderFailureKind::ProviderCancelled | ProviderFailureKind::Process)
                if self.outcome == ProviderOutcome::Cancelled =>
            {
                Some(BridgeError::Cancelled {
                    reason: "provider reported cancellation",
                })
            }
            Some(ProviderFailureKind::ProviderCancelled) => Some(BridgeError::Cancelled {
                reason: "provider reported cancellation",
            }),
            Some(ProviderFailureKind::ProviderFailed) => Some(BridgeError::ProviderFailed {
                reason: "provider reported a failed acquisition",
            }),
            Some(ProviderFailureKind::Protocol) => Some(BridgeError::ProtocolViolation {
                reason: "provider result was not correlated to the admitted operation",
            }),
            Some(ProviderFailureKind::Evidence) => Some(BridgeError::EvidenceIncomplete {
                reason: "provider evidence or terminal disposition is incomplete",
            }),
            Some(ProviderFailureKind::Process) => match self.outcome {
                ProviderOutcome::TimedOut => Some(BridgeError::TimedOut),
                ProviderOutcome::Unknown => Some(BridgeError::UnknownOutcome),
                ProviderOutcome::Crashed => Some(BridgeError::ProviderFailed {
                    reason: "provider process crashed or exceeded a resource limit",
                }),
                ProviderOutcome::Cancelled => Some(BridgeError::Cancelled {
                    reason: "provider reported cancellation",
                }),
                ProviderOutcome::Completed => Some(BridgeError::EvidenceIncomplete {
                    reason: "provider completed without a correlated result",
                }),
            },
        }
    }
}

struct BoundOperation {
    admission: ProviderAdmission,
    operation: OperationId,
    digest: String,
    envelope: SubmitEnvelope,
    wire_bytes: Vec<u8>,
    deadline_at: Instant,
    deadline_unix_ms: i64,
    process_request: Option<ProcessRequest>,
    start_receipt: Option<ProcessStartReceipt>,
}

/// Stateless shared-executor runner for admitted research operations.
pub struct ProviderBridge {
    executor: Arc<WindowsProcessExecutor>,
    port: Arc<dyn ResearchRequestPort>,
    sink: Arc<dyn ProcessEvidenceSink>,
    deadline: Duration,
}

impl ProviderBridge {
    /// Binds the runner to the shared executor, an authorized request port,
    /// and an evidence sink. Starts nothing and grants no authority.
    #[must_use]
    pub fn new(
        executor: Arc<WindowsProcessExecutor>,
        port: Arc<dyn ResearchRequestPort>,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Self {
        Self {
            executor,
            port,
            sink,
            deadline: BOUND_RUN_DEADLINE,
        }
    }

    /// Overrides only the outer fallback wait; the admitted absolute deadline
    /// remains authoritative and is always narrower.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Returns the shared executor handle.
    #[must_use]
    pub fn executor(&self) -> &Arc<WindowsProcessExecutor> {
        &self.executor
    }

    /// Executes one admitted request through the governed contour.
    pub fn execute(
        &self,
        admission: &ProviderAdmission,
        request: &ResearchQueryRequest,
    ) -> Result<ProviderExecution, BridgeError> {
        let mut bound = self.bind_operation(admission, request)?;
        let process_request =
            bound
                .process_request
                .take()
                .ok_or(BridgeError::EvidenceIncomplete {
                    reason: "admitted process request was not available for start",
                })?;
        let start_receipt = match block_on(self.executor.start(process_request, self.sink.clone()))
        {
            Ok(receipt) => receipt,
            Err(error) => {
                let prelaunch_contract_failure =
                    matches!(&error, ProcessExecutionError::Contract(_));
                if !prelaunch_contract_failure {
                    let reconciliation = self.reconcile_operation(&bound.operation).ok();
                    return self.finish_unobserved_with_reconciliation(
                        bound,
                        ProviderOutcome::Unknown,
                        None,
                        reconciliation,
                        Some(&error),
                    );
                }
                return Err(map_start_error(error));
            }
        };
        if start_receipt.operation_id() != &bound.operation
            || start_receipt.request_digest() != bound.digest
            || start_receipt.accepted_generation() != admission.process_generation()
        {
            let reconciliation = self.reconcile_operation(&bound.operation).ok();
            return self.finish_unobserved_with_reconciliation(
                bound,
                ProviderOutcome::Unknown,
                None,
                reconciliation,
                None,
            );
        }
        bound.start_receipt = Some(start_receipt);
        match self.await_terminal(&bound) {
            Ok(view) => self.finish_terminal(bound, &view, None),
            Err(WaitFailure::TimedOut) => {
                let cancellation = self.cancel_operation(&bound.operation).ok();
                let reconciliation = self.reconcile_operation(&bound.operation).ok();
                self.finish_unobserved_with_reconciliation(
                    bound,
                    ProviderOutcome::TimedOut,
                    cancellation,
                    reconciliation,
                    None,
                )
            }
            Err(WaitFailure::Unknown | WaitFailure::Process) => {
                let reconciliation = self.reconcile_operation(&bound.operation).ok();
                self.finish_unobserved_with_reconciliation(
                    bound,
                    ProviderOutcome::Unknown,
                    None,
                    reconciliation,
                    None,
                )
            }
        }
    }

    /// Validates the request/admission binding, builds the exact wire before
    /// port binding, and starts only the revalidated process request.
    fn bind_operation(
        &self,
        admission: &ProviderAdmission,
        request: &ResearchQueryRequest,
    ) -> Result<BoundOperation, BridgeError> {
        request.validate().map_err(|_| BridgeError::NotAdmitted {
            reason: "research request failed validation",
        })?;
        admission
            .validate_request(request)
            .map_err(|refusal| BridgeError::NotAdmitted {
                reason: refusal.reason(),
            })?;
        let request_bytes =
            serde_json::to_vec(request).map_err(|_| BridgeError::ProtocolViolation {
                reason: "research request is not canonical wire JSON",
            })?;
        let request_sha256 = sha256_hex(&request_bytes);
        let envelope = SubmitEnvelope::from_admission(request, admission, request_sha256.clone());
        let wire_bytes = envelope
            .encode()
            .map_err(|refusal| BridgeError::ProtocolViolation {
                reason: refusal.reason(),
            })?;
        let process_request =
            self.port
                .bind(admission, &envelope, &wire_bytes)
                .map_err(|error| match error {
                    RequestPortError::NoAuthority => BridgeError::ProviderUnavailable,
                    RequestPortError::Refused => BridgeError::NotAdmitted {
                        reason: "Kernel request port refused the admitted process binding",
                    },
                    RequestPortError::WireDeliveryRefused => BridgeError::ProtocolViolation {
                        reason: "request port refused exact provider wire delivery",
                    },
                    RequestPortError::EvidenceUnavailable => BridgeError::EvidenceIncomplete {
                        reason: "request port could not persist the pre-start provider intent",
                    },
                })?;
        check_minted_request(admission, &envelope, &wire_bytes, &process_request)?;
        let operation = process_request.operation_id().clone();
        let digest = process_request.invocation_digest().to_owned();
        Ok(BoundOperation {
            admission: admission.clone(),
            operation,
            digest,
            envelope,
            wire_bytes,
            deadline_at: self.deadline_at(admission)?,
            deadline_unix_ms: admission.deadline_ms(),
            process_request: Some(process_request),
            start_receipt: None,
        })
    }

    fn deadline_at(&self, admission: &ProviderAdmission) -> Result<Instant, BridgeError> {
        let now = now_unix_ms();
        let remaining_ms = admission.deadline_ms().saturating_sub(now);
        if remaining_ms <= 0 {
            return Err(BridgeError::TimedOut);
        }
        let remaining = Duration::from_millis(u64::try_from(remaining_ms).unwrap_or(u64::MAX));
        let bounded = self.deadline.min(remaining).min(MAX_ADMISSION_WAIT);
        if bounded.is_zero() {
            return Err(BridgeError::TimedOut);
        }
        Instant::now()
            .checked_add(bounded)
            .ok_or(BridgeError::TimedOut)
    }

    fn await_terminal(&self, bound: &BoundOperation) -> Result<ProcessExecutionView, WaitFailure> {
        loop {
            let view = match block_on(self.executor.inspect(bound.operation.clone())) {
                Ok(view) => view,
                Err(ProcessExecutionError::UnknownOutcome) => return Err(WaitFailure::Unknown),
                Err(_) => return Err(WaitFailure::Process),
            };
            if view.operation_id() != &bound.operation || view.request_digest() != bound.digest {
                return Err(WaitFailure::Unknown);
            }
            if view.lifecycle().is_terminal() {
                return Ok(view);
            }
            if Instant::now() >= bound.deadline_at {
                return Err(WaitFailure::TimedOut);
            }
            std::thread::sleep(BOUND_RUN_POLL);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn finish_terminal(
        &self,
        bound: BoundOperation,
        view: &ProcessExecutionView,
        cancellation: Option<CancellationReceipt>,
    ) -> Result<ProviderExecution, BridgeError> {
        let reconciliation = self.reconcile_operation(&bound.operation).ok();
        let captured = self
            .executor
            .captured_output(&bound.operation)
            .map_err(BridgeError::Process);
        let Ok((stdout, stderr)) = captured else {
            return self.finish_unobserved_with_reconciliation(
                bound,
                ProviderOutcome::Unknown,
                cancellation,
                reconciliation,
                None,
            );
        };
        let Some(exit) = view.exit() else {
            return self.finish_unobserved_with_reconciliation(
                bound,
                ProviderOutcome::Unknown,
                cancellation,
                reconciliation,
                None,
            );
        };
        let descendants = view.descendants();
        let descendants_complete = descendants
            .is_some_and(|descendants| descendants.complete() && descendants.tree_terminated());
        let tree_terminated =
            descendants.is_some_and(eliot_process::DescendantEvidence::tree_terminated);
        let lineage_handle = descendants
            .and_then(|descendants| descendants.evidence_ref())
            .map(str::to_owned);
        let evidence = RawProviderEvidence::materialize(
            bound.operation.as_str(),
            &bound.digest,
            exit,
            &stdout,
            &stderr,
            descendants_complete,
        );
        let process_outcome = classify_terminal(view.lifecycle(), exit, descendants_complete);
        let mut outcome = process_outcome;
        let mut failure = match process_outcome {
            ProviderOutcome::Completed => None,
            ProviderOutcome::Crashed => Some(ProviderFailureKind::ProviderFailed),
            ProviderOutcome::TimedOut => Some(ProviderFailureKind::Process),
            ProviderOutcome::Cancelled => Some(ProviderFailureKind::ProviderCancelled),
            ProviderOutcome::Unknown => Some(ProviderFailureKind::Evidence),
        };
        let mut provider_job_ref = None;
        let mut result_frame = None;
        if process_outcome == ProviderOutcome::Completed {
            let ack_line = stdout
                .bytes
                .split(|byte| *byte == b'\n')
                .next()
                .unwrap_or_default();
            if let Ok(ack) = SubmitAck::decode(
                ack_line,
                bound.envelope.operation_id.as_str(),
                bound.envelope.request_sha256.as_str(),
            ) {
                provider_job_ref = Some(ack.provider_job_id);
            } else {
                outcome = ProviderOutcome::Unknown;
                failure = Some(ProviderFailureKind::Protocol);
            }
            if failure.is_none() {
                match scan_result_frame(
                    &stdout.bytes,
                    &bound.envelope.operation_id,
                    &bound.envelope.request_sha256,
                    &bound.envelope.route_id,
                ) {
                    Ok(Some(frame)) => {
                        let disposition = frame.disposition;
                        let over_budget = frame.usage_units > bound.envelope.budget_units;
                        result_frame = Some(frame);
                        if over_budget {
                            outcome = ProviderOutcome::Unknown;
                            failure = Some(ProviderFailureKind::Protocol);
                        } else {
                            outcome = match disposition {
                                crate::protocol::ProviderResultDisposition::CompletedCandidateAvailable => ProviderOutcome::Completed,
                                crate::protocol::ProviderResultDisposition::ProviderCancelled => ProviderOutcome::Cancelled,
                                crate::protocol::ProviderResultDisposition::ProviderFailed => ProviderOutcome::Crashed,
                            };
                            failure = match disposition {
                                crate::protocol::ProviderResultDisposition::CompletedCandidateAvailable => None,
                                crate::protocol::ProviderResultDisposition::ProviderCancelled => Some(ProviderFailureKind::ProviderCancelled),
                                crate::protocol::ProviderResultDisposition::ProviderFailed => Some(ProviderFailureKind::ProviderFailed),
                            };
                        }
                    }
                    Ok(None) => {
                        outcome = ProviderOutcome::Unknown;
                        failure = Some(ProviderFailureKind::Evidence);
                    }
                    Err(_) => {
                        outcome = ProviderOutcome::Unknown;
                        failure = Some(ProviderFailureKind::Protocol);
                    }
                }
            }
        }
        let evidence = attach_evidence_handles(evidence, reconciliation.as_ref())
            .with_lineage_handle(lineage_handle);
        let receipt = build_receipt(
            &bound,
            &evidence,
            outcome,
            descendants_complete,
            cancellation,
            reconciliation,
            None,
            tree_terminated,
            provider_job_ref.clone(),
            result_frame.as_ref(),
        );
        let candidate = build_candidate_bundle(
            &bound.admission,
            &bound,
            result_frame.as_ref(),
            outcome,
            &evidence,
        );
        Ok(ProviderExecution {
            job_id: bound.operation.as_str().to_owned(),
            outcome,
            evidence,
            provider_job_ref,
            result_frame,
            wire_bytes: bound.wire_bytes,
            receipt,
            candidate,
            failure,
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn finish_unobserved_with_reconciliation(
        &self,
        bound: BoundOperation,
        outcome: ProviderOutcome,
        cancellation: Option<CancellationReceipt>,
        reconciliation: Option<ProcessEvidence>,
        start_error: Option<&ProcessExecutionError>,
    ) -> Result<ProviderExecution, BridgeError> {
        let streams = self
            .executor
            .captured_output(&bound.operation)
            .unwrap_or_else(|_| empty_streams());
        let descendants_complete = reconciliation
            .as_ref()
            .and_then(|value| value.view().descendants())
            .is_some_and(|descendants| descendants.complete() && descendants.tree_terminated());
        let tree_terminated = reconciliation
            .as_ref()
            .and_then(|value| value.view().descendants())
            .is_some_and(eliot_process::DescendantEvidence::tree_terminated);
        let evidence = reconciliation
            .as_ref()
            .and_then(|value| value.view().exit())
            .map_or_else(
                || {
                    RawProviderEvidence::unknown(
                        bound.operation.as_str(),
                        &bound.digest,
                        &streams.0,
                        &streams.1,
                    )
                },
                |exit| {
                    RawProviderEvidence::materialize(
                        bound.operation.as_str(),
                        &bound.digest,
                        exit,
                        &streams.0,
                        &streams.1,
                        descendants_complete,
                    )
                },
            );
        let evidence = attach_evidence_handles(evidence, reconciliation.as_ref());
        let receipt = build_receipt(
            &bound,
            &evidence,
            outcome,
            descendants_complete,
            cancellation,
            reconciliation,
            start_error.map(ToString::to_string),
            tree_terminated,
            None,
            None,
        );
        let candidate = build_candidate_bundle(&bound.admission, &bound, None, outcome, &evidence);
        let failure = Some(if start_error.is_some() {
            ProviderFailureKind::Process
        } else {
            match outcome {
                ProviderOutcome::TimedOut => ProviderFailureKind::Process,
                ProviderOutcome::Cancelled => ProviderFailureKind::ProviderCancelled,
                ProviderOutcome::Crashed => ProviderFailureKind::ProviderFailed,
                ProviderOutcome::Unknown | ProviderOutcome::Completed => {
                    ProviderFailureKind::Evidence
                }
            }
        });
        Ok(ProviderExecution {
            job_id: bound.operation.as_str().to_owned(),
            outcome,
            evidence,
            provider_job_ref: None,
            result_frame: None,
            wire_bytes: bound.wire_bytes,
            receipt,
            candidate,
            failure,
        })
    }

    /// Requests cancellation and returns the exact receipt to the caller.
    pub fn cancel_operation(
        &self,
        operation: &OperationId,
    ) -> Result<CancellationReceipt, BridgeError> {
        block_on(self.executor.cancel(operation.clone())).map_err(BridgeError::Process)
    }

    /// Reconciles the bound operation's unknown external result.
    pub fn reconcile_operation(
        &self,
        operation: &OperationId,
    ) -> Result<ProcessEvidence, BridgeError> {
        block_on(self.executor.reconcile(operation.clone())).map_err(BridgeError::Process)
    }
}

enum WaitFailure {
    TimedOut,
    Unknown,
    Process,
}

fn map_start_error(error: ProcessExecutionError) -> BridgeError {
    match error {
        ProcessExecutionError::Unavailable(_) => BridgeError::ProviderUnavailable,
        ProcessExecutionError::UnknownOutcome => BridgeError::UnknownOutcome,
        other => BridgeError::Process(other),
    }
}

fn empty_streams() -> (CapturedStream, CapturedStream) {
    (
        CapturedStream {
            bytes: Vec::new(),
            total_bytes: 0,
            truncated: false,
            complete: false,
            captured: false,
        },
        CapturedStream {
            bytes: Vec::new(),
            total_bytes: 0,
            truncated: false,
            complete: false,
            captured: false,
        },
    )
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

fn attach_evidence_handles(
    evidence: RawProviderEvidence,
    reconciliation: Option<&ProcessEvidence>,
) -> RawProviderEvidence {
    let Some(process_evidence) = reconciliation else {
        return evidence;
    };
    let stdout = process_evidence
        .stdout()
        .and_then(|stream| stream.source())
        .map(|source| source.locator().to_owned());
    let stderr = process_evidence
        .stderr()
        .and_then(|stream| stream.source())
        .map(|source| source.locator().to_owned());
    let lineage = process_evidence
        .view()
        .descendants()
        .and_then(|descendants| descendants.evidence_ref())
        .map(str::to_owned);
    evidence.with_evidence_handles(stdout, stderr, lineage)
}

#[allow(clippy::too_many_arguments)]
fn build_receipt(
    bound: &BoundOperation,
    evidence: &RawProviderEvidence,
    outcome: ProviderOutcome,
    descendants_complete: bool,
    cancellation: Option<CancellationReceipt>,
    reconciliation: Option<ProcessEvidence>,
    process_error: Option<String>,
    tree_terminated: bool,
    provider_job_ref: Option<String>,
    result_frame: Option<&ResultFrame>,
) -> ProviderAttemptReceipt {
    let envelope = &bound.envelope;
    let admission = &bound.admission;
    let cleanup_proven =
        descendants_complete && tree_terminated && evidence.lineage_evidence_ref.is_some();
    ProviderAttemptReceipt {
        operation_id: envelope.operation_id.clone(),
        invocation_digest: bound.digest.clone(),
        process_error,
        outcome,
        start_receipt: bound.start_receipt.clone(),
        artifact_sha256: admission.bridge().executable_sha256().to_owned(),
        config_digest: admission.config_digest().to_owned(),
        protocol_digest: admission.protocol_digest().to_owned(),
        registry_evidence_sha256: envelope.registry_evidence_sha256.clone(),
        module_id: admission.module_id().to_owned(),
        module_generation_id: admission.module_generation_id().to_owned(),
        provider_id: envelope.provider_id.clone(),
        bridge_generation: envelope.bridge_generation.clone(),
        protocol_revision: envelope.protocol_revision,
        required_schema: envelope.required_schema.clone(),
        process_generation: envelope.process_generation,
        authority_epoch: admission.epoch().clone(),
        state_fence: admission.fence().clone(),
        route_id: envelope.route_id.clone(),
        disclosure: envelope.disclosure,
        data_class: envelope.data_class.clone(),
        credential_binding_id: envelope.credential_binding_id.clone(),
        credential_owner_principal: admission.credential_binding().owner_principal.clone(),
        credential_acting_principal: admission.credential_binding().acting_principal.clone(),
        budget_units: envelope.budget_units,
        usage_units: result_frame.map_or(0, |frame| frame.usage_units),
        deadline_unix_ms: bound.deadline_unix_ms,
        cancellation_id: envelope.cancellation_id.clone(),
        wire_sha256: sha256_hex(&bound.wire_bytes),
        raw_evidence: evidence.clone(),
        reconciliation,
        cancellation,
        cleanup: ProviderCleanupReceipt {
            descendants_complete,
            tree_terminated,
            lineage_evidence_ref: evidence.lineage_evidence_ref.clone(),
            cleanup_proven,
        },
        provider_job_ref,
        result_disposition: result_frame.map(|frame| frame.disposition),
        source_handles: result_frame
            .map(|frame| frame.source_handles.clone())
            .unwrap_or_default(),
        provenance_handles: result_frame
            .map(|frame| frame.provenance_handles.clone())
            .unwrap_or_default(),
        coverage_gaps: result_frame
            .map(|frame| frame.coverage_gaps.clone())
            .unwrap_or_default(),
        coverage_denominator: result_frame.map(|frame| frame.coverage_denominator),
    }
}

#[allow(clippy::unnecessary_wraps)]
fn build_candidate_bundle(
    admission: &ProviderAdmission,
    bound: &BoundOperation,
    result_frame: Option<&ResultFrame>,
    outcome: ProviderOutcome,
    evidence: &RawProviderEvidence,
) -> Option<ResearchEvidenceBundle> {
    let envelope = &bound.envelope;
    let (gap_kind, disposition, detail, failed) = match (result_frame, outcome) {
        (Some(frame), ProviderOutcome::Completed)
            if frame.coverage_denominator != CoverageDenominator::CompleteScope =>
        {
            (
                CoverageGapKind::Unknown,
                CompletionDisposition::IncompleteCoverage,
                "provider returned candidate material without a complete frozen-scope denominator",
                Vec::new(),
            )
        }
        (Some(_frame), ProviderOutcome::Completed) => (
            CoverageGapKind::Unknown,
            CompletionDisposition::Inconclusive,
            "candidate-only provider result awaits Governor admission",
            Vec::new(),
        ),
        (_, ProviderOutcome::Cancelled) => (
            CoverageGapKind::Cancelled,
            CompletionDisposition::Cancelled,
            "provider acquisition was cancelled before a complete candidate result was proven",
            vec!["provider cancellation".to_owned()],
        ),
        (_, ProviderOutcome::TimedOut) => (
            CoverageGapKind::Timeout,
            CompletionDisposition::IncompleteCoverage,
            "provider acquisition exceeded the admitted deadline",
            vec!["provider timeout".to_owned()],
        ),
        (_, ProviderOutcome::Crashed) => (
            CoverageGapKind::Unknown,
            CompletionDisposition::IncompleteCoverage,
            "provider process crashed or reported acquisition failure",
            vec!["provider crash/failure".to_owned()],
        ),
        (_, ProviderOutcome::Unknown | ProviderOutcome::Completed) => (
            CoverageGapKind::Unknown,
            CompletionDisposition::IncompleteCoverage,
            "provider result is unknown or lacks correlated source/coverage evidence",
            vec!["provider unknown/incomplete result".to_owned()],
        ),
    };
    let source_handle = result_frame
        .and_then(|frame| frame.source_handles.first().cloned())
        .unwrap_or_else(|| format!("provider:{}", envelope.route_id));
    let coverage_gaps = vec![CoverageGap {
        source_handle,
        kind: gap_kind,
        detail: detail.to_owned(),
    }];
    let coverage_unknowns = if result_frame.is_some() {
        vec!["provider source/provenance/coverage metadata is candidate-only until Governor admission".to_owned()]
    } else {
        vec!["no provider result frame was correlated".to_owned()]
    };
    let artifact_handles = result_frame
        .map(|frame| vec![format!("provider-candidate:{}", frame.candidate_sha256)])
        .unwrap_or_default();
    let digest_input = format!(
        "{}:{}:{}:{}",
        envelope.operation_id, envelope.request_sha256, envelope.route_id, evidence.stdout.sha256
    );
    Some(ResearchEvidenceBundle {
        exchange_id: envelope.exchange_id.clone(),
        job_id: envelope.operation_id.clone(),
        system_generation: admission.module_generation_id().to_owned(),
        immutable_bundle_digest: sha256_hex(digest_input.as_bytes()),
        origin_authentication: admission.bridge().executable_sha256().to_owned(),
        state_fence: admission.fence().clone(),
        sources: Vec::new(),
        claims: Vec::new(),
        bounded_excerpts: Vec::new(),
        artifact_handles,
        coverage_unknowns,
        failed_acquisition: failed,
        coverage_gaps,
        disposition,
        synthesis_is_candidate: true,
        disclosure: envelope.disclosure,
        invalidation: Some("candidate-only; normal Governor admission required".to_owned()),
    })
}

fn check_minted_request(
    admission: &ProviderAdmission,
    expected_envelope: &SubmitEnvelope,
    wire_bytes: &[u8],
    request: &ProcessRequest,
) -> Result<(), BridgeError> {
    request.validate().map_err(|_| BridgeError::NotAdmitted {
        reason: "minted process request failed validation",
    })?;
    if request.executable() != admission.bridge().executable()
        || request.executable_sha256() != admission.bridge().executable_sha256()
    {
        return Err(BridgeError::NotAdmitted {
            reason: "minted process request names an unapproved artifact",
        });
    }
    let expected_working_directory =
        Path::new(request.executable())
            .parent()
            .ok_or(BridgeError::NotAdmitted {
                reason: "approved provider artifact has no installation directory",
            })?;
    if request.working_directory() != expected_working_directory.to_string_lossy().as_ref() {
        return Err(BridgeError::NotAdmitted {
            reason: "minted process request permits a caller-selected working directory",
        });
    }
    if request.operation_id() != admission.operation_id() {
        return Err(BridgeError::NotAdmitted {
            reason: "minted process request binds a foreign operation",
        });
    }
    if request.generation() != admission.process_generation() {
        return Err(BridgeError::NotAdmitted {
            reason: "minted process request carries a stale generation",
        });
    }
    if !request
        .fence()
        .authority_epoch()
        .is_same_authority(admission.epoch())
        || request.fence().generation().get() != admission.process_generation().get()
        || request.fence().nonce() != admission.cancellation().cancellation_id
    {
        return Err(BridgeError::NotAdmitted {
            reason: "minted process request disagrees on the full process fence or cancellation identity",
        });
    }
    if request.environment().inheritance() != EnvironmentInheritance::None
        || !request.environment().non_secret().is_empty()
        || !request.environment().secret_refs().is_empty()
    {
        return Err(BridgeError::NotAdmitted {
            reason: "minted process request permits ambient environment or secret injection",
        });
    }
    let argv = request.argv();
    if argv.len() != 2
        || argv[0] != PROVIDER_WIRE_ARGUMENT
        || argv[1] != std::str::from_utf8(wire_bytes).unwrap_or("")
    {
        return Err(BridgeError::ProtocolViolation {
            reason: "minted process request did not deliver the exact provider wire envelope",
        });
    }
    let delivered =
        SubmitEnvelope::decode(wire_bytes).map_err(|refusal| BridgeError::ProtocolViolation {
            reason: refusal.reason(),
        })?;
    if delivered != *expected_envelope {
        return Err(BridgeError::ProtocolViolation {
            reason: "delivered provider wire does not match the admitted envelope",
        });
    }
    let remaining = admission.deadline_ms().saturating_sub(now_unix_ms()).max(1);
    if request.resource_limits().wall_timeout_ms() > u64::try_from(remaining).unwrap_or(u64::MAX) {
        return Err(BridgeError::NotAdmitted {
            reason: "minted process request exceeds the admitted deadline",
        });
    }
    if request.resource_limits().stdout_bytes() == 0
        || request.resource_limits().stderr_bytes() == 0
        || request.resource_limits().max_descendants() == 0
    {
        return Err(BridgeError::NotAdmitted {
            reason: "minted process request has incomplete resource or stream bounds",
        });
    }
    Ok(())
}

fn classify_terminal(
    lifecycle: ProcessLifecycle,
    exit: &eliot_process::ExitStatus,
    descendants_complete: bool,
) -> ProviderOutcome {
    if lifecycle == ProcessLifecycle::UnknownOutcome {
        return ProviderOutcome::Unknown;
    }
    match exit.disposition() {
        ExitDisposition::Completed if descendants_complete => ProviderOutcome::Completed,
        ExitDisposition::Completed | ExitDisposition::Unknown => ProviderOutcome::Unknown,
        ExitDisposition::Cancelled => ProviderOutcome::Cancelled,
        ExitDisposition::Signalled | ExitDisposition::ResourceLimit => ProviderOutcome::Crashed,
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn terminal_classification_never_invents_success() {
        let completed =
            eliot_process::ExitStatus::new(ExitDisposition::Completed, Some(0), None, 1)
                .expect("exit");
        assert_eq!(
            classify_terminal(ProcessLifecycle::Exited, &completed, true),
            ProviderOutcome::Completed
        );
        assert_eq!(
            classify_terminal(ProcessLifecycle::Exited, &completed, false),
            ProviderOutcome::Unknown
        );
        let cancelled = eliot_process::ExitStatus::new(ExitDisposition::Cancelled, None, None, 1)
            .expect("exit");
        assert_eq!(
            classify_terminal(ProcessLifecycle::Exited, &cancelled, true),
            ProviderOutcome::Cancelled
        );
    }

    #[test]
    fn wire_marker_is_part_of_the_exact_launch_contract() {
        assert_eq!(PROVIDER_WIRE_ARGUMENT, "--eliot-research-wire");
    }
}
