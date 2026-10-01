//! Retained Claude provider invocation for one already admitted native-worker
//! attempt. All Claude records and the process request are supplied by their
//! existing owners; this module compares their identities and never issues a
//! provider binding, admission receipt, credential, or process permit.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use eliot_agent_api::{
    AdmittedRouteReceipt, AgentResult, EffectCeiling, ProviderExecutionBinding, UsageReceipt,
};
use eliot_agent_claude::{
    CancellationEnvelope, ClaudeCandidateDisposition, ClaudeFactoryInput, ClaudeRunningSidecar,
    ClaudeSidecarError, ClaudeSidecarRequest, ClaudeSidecarResponse,
    ClaudeTerminalCandidate, ClaudeLaunchPort, UnknownOutcomeGate,
    execution::{
        ClaudeFactoryOutcome, restore_running_sidecar_after_reconcile, sidecar_stdin_line,
        translate_candidate_result, ClaudeResultInput, ClaudeSidecarFactory,
    },
    claude_local_digest_256_hex,
};
use eliot_contracts::sha256_hex;
use eliot_native_worker_core::{
    ClaimAdmissionRequest, NativeWorkerRetainedOperationIdentity,
    NativeWorkerRetainedOperationOutcome, NativeWorkerRetainedOutcomeKind, WorkerError,
    WorkerHello,
};
use eliot_process::{
    CancellationStatus, FencingToken, Generation, OperationId, ProcessEvidence,
    ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView, ProcessExecutor,
    ProcessLifecycle, ProcessRequest, ProcessStartReceipt,
};
use eliot_process_executor::WindowsProcessExecutor;
use serde::{Deserialize, Serialize};

use crate::adapter_registry::{
    AdapterIdentity, AdapterRegistry, FactoryLedger, RegistryError, ValidatedDispatch,
    begin_invoke, truncate_detail,
};

/// Complete output and candidate projection from one unchanged operation.
/// `process_evidence` and `agent_result` are the producer-owned values; the
/// native-worker carrier is only a bounded bridge handoff projection.
#[derive(Serialize)]
pub struct RetainedClaudeResult {
    /// Original daemon dispatch/attempt identity, preserved exactly.
    pub identity: NativeWorkerRetainedOperationIdentity,
    /// Candidate-only Claude result bound to the original provider binding.
    pub agent_result: AgentResult,
    /// Exact process evidence returned by same-operation reconcile.
    pub process_evidence: ProcessEvidence,
    /// Bounded body and commitment for the daemon bridge handoff.
    pub outcome: NativeWorkerRetainedOperationOutcome,
}

/// Start may return an exact replay with no new process, a started attempt, or
/// a retained attempt that must be reconciled after a missing/ambiguous start
/// acknowledgement. Every attempt is reserved in the factory ledger before
/// calling P-04, so a failure cannot trigger a second launch in this worker.
pub enum RetainedClaudeStart {
    /// Started once through the injected process owner.
    Started(RetainedClaudeAttempt),
    /// Start acknowledgement did not prove the result; inspect/cancel/reconcile
    /// the same saved operation before any later admission.
    PendingReconcile(RetainedClaudeAttempt),
    /// Claude factory idempotency recognized the original exact request.
    ReplayDuplicate {
        /// Original owner-issued operation identity.
        identity: NativeWorkerRetainedOperationIdentity,
        /// Digest of the prior terminal result; no process was started.
        prior_result_digest: String,
    },
}

/// Stateful per-attempt facade over the existing Windows process owner. It
/// retains the original provider request and immutable identity, not a child
/// process handle or a second lifecycle table.
pub struct RetainedClaudeAttempt {
    identity: NativeWorkerRetainedOperationIdentity,
    factory: ClaudeSidecarFactory<OneShotStdinProcessExecutor>,
    process_executor: Arc<WindowsProcessExecutor>,
    process_operation_id: OperationId,
    process_request_digest: String,
    process_fence: FencingToken,
    process_generation: Generation,
    provider_binding: ProviderExecutionBinding,
    provider_request: ClaudeSidecarRequest,
    started_at_unix_ms: u64,
    route_receipt: AdmittedRouteReceipt,
    effect_ceiling: EffectCeiling,
    usage: UsageReceipt,
    gate: UnknownOutcomeGate,
    running: Option<ClaudeRunningSidecar>,
}

impl RetainedClaudeAttempt {
    /// Original retained identity for every daemon owner lookup.
    pub const fn identity(&self) -> &NativeWorkerRetainedOperationIdentity {
        &self.identity
    }

    /// Inspect the original operation through the exact ProcessExecutor.
    /// The caller must pass the persisted identity it is checking; a changed
    /// dispatch/cancellation/attempt field is refused.
    pub async fn inspect(
        &self,
        identity: &NativeWorkerRetainedOperationIdentity,
    ) -> Result<RetainedClaudeInspection, RegistryError> {
        self.require_same_identity(identity)?;
        let view = self
            .factory
            .inspect_same_operation(&self.process_operation_id, &self.identity.attempt_id)
            .await
            .map_err(map_claude_error)?;
        Ok(RetainedClaudeInspection {
            identity: self.identity.clone(),
            view,
        })
    }

    /// Cancel the original operation through the real ProcessExecutor.
    /// `cancellation_id` must equal the persisted daemon identity before the
    /// provider cancellation envelope reaches the executor.
    pub async fn cancel(
        &self,
        identity: &NativeWorkerRetainedOperationIdentity,
        cancellation_id: &str,
        envelope: &CancellationEnvelope,
    ) -> Result<RetainedClaudeCancellation, RegistryError> {
        self.require_same_identity(identity)?;
        if cancellation_id != self.identity.cancellation_id {
            return Err(RegistryError::BadInput {
                field: "cancellation_id",
                detail: "cancellation does not name the persisted retained operation".to_owned(),
            });
        }
        let record = self
            .factory
            .cancel_same_operation(
                &self.process_operation_id,
                &self.identity.attempt_id,
                envelope,
            )
            .await
            .map_err(map_claude_error)?;
        if record.operation_id() != &self.process_operation_id {
            return Err(RegistryError::BadClaim(WorkerError::AdmissionMismatch(
                "retained_cancel_operation",
            )));
        }
        let evidence_ref = self
            .factory
            .inspect_same_operation(&self.process_operation_id, &self.identity.attempt_id)
            .await
            .ok()
            .and_then(|view| view.descendants().and_then(|item| item.evidence_ref()))
            .map(str::to_owned);
        Ok(RetainedClaudeCancellation {
            identity: self.identity.clone(),
            cancellation_id: self.identity.cancellation_id.clone(),
            status: record.status(),
            lifecycle: record.lifecycle(),
            no_effect_proven: record.no_effect_proven(),
            descendants_complete: record.descendants_complete(),
            evidence_ref,
        })
    }

    /// Reconcile and parse the exact retained stdout source. A candidate is
    /// emitted only when P-04 proves complete raw transport bytes, the bytes
    /// bind to the same ProcessEvidence, every NDJSON line passes the existing
    /// Claude cursor, and the terminal candidate binds to the original
    /// ProviderExecutionBinding. No second launch occurs on this path.
    pub async fn reconcile(
        &mut self,
        identity: &NativeWorkerRetainedOperationIdentity,
        observed_at_unix_ms: u64,
    ) -> Result<RetainedClaudeResult, RegistryError> {
        self.require_same_identity(identity)?;
        if observed_at_unix_ms == 0 {
            return Err(RegistryError::BadInput {
                field: "reconcile_time",
                detail: "observed reconcile time must be non-zero".to_owned(),
            });
        }
        let (_reconciled, evidence) = self
            .factory
            .reconcile_same_operation_bound_with_evidence(
                &self.process_operation_id,
                &self.identity.attempt_id,
                &self.process_request_digest,
                &self.process_fence,
                self.process_generation,
                &mut self.gate,
            )
            .await
            .map_err(map_claude_error)?;
        if self.running.is_none() {
            self.running = Some(
                restore_running_sidecar_after_reconcile(
                    self.provider_binding.clone(),
                    self.provider_request.clone(),
                    self.process_operation_id.clone(),
                    &self.process_request_digest,
                    &self.process_fence,
                    self.process_generation,
                    &evidence,
                    self.started_at_unix_ms,
                )
                .map_err(map_claude_error)?,
            );
        }
        let stdout = self
            .process_executor
            .readback_complete_stdout_bytes(&self.process_operation_id, &evidence)
            .ok();
        let terminal = stdout.as_deref().and_then(|bytes| {
            let running = self.running.as_mut()?;
            ingest_complete_stdout(running, bytes, observed_at_unix_ms).ok().flatten()
        });
        let unknown_reason = terminal.is_none().then(|| {
            "complete terminal Claude output was not proven by retained stdout evidence".to_owned()
        });
        let agent_result = translate_candidate_result(
            ClaudeResultInput {
                terminal: terminal.clone(),
                usage: self.usage.clone(),
                cancelled: false,
                unknown_reason,
            },
            &self.provider_binding,
            &self.route_receipt,
            &self.effect_ceiling,
        )
        .map_err(map_claude_error)?;
        let result_body = terminal
            .as_ref()
            .map(|value| value.candidate().output.as_bytes().to_vec());
        let result_digest = result_body.as_deref().map(sha256_hex);
        let evidence_bytes = serde_json::to_vec(&evidence).map_err(|_| RegistryError::BadInput {
            field: "process_evidence",
            detail: "reconciled process evidence could not be serialized".to_owned(),
        })?;
        let process_evidence_digest = Some(sha256_hex(&evidence_bytes));
        let kind = terminal.as_ref().map_or(
            NativeWorkerRetainedOutcomeKind::UnknownOutcome,
            |value| match &value.candidate().disposition {
                ClaudeCandidateDisposition::CandidateReady => {
                    NativeWorkerRetainedOutcomeKind::CandidateReady
                }
                ClaudeCandidateDisposition::CandidatePartial => {
                    NativeWorkerRetainedOutcomeKind::CandidatePartial
                }
                ClaudeCandidateDisposition::CandidateFailed => {
                    NativeWorkerRetainedOutcomeKind::CandidateFailed
                }
            },
        );
        let mut evidence_refs = agent_result.evidence_refs.clone();
        append_process_evidence_refs(&evidence, &mut evidence_refs);
        let outcome = NativeWorkerRetainedOperationOutcome {
            identity: self.identity.clone(),
            kind,
            result_body,
            artifact_refs: Vec::new(),
            evidence_refs,
            result_digest,
            process_evidence_digest,
            owner_receipt_ref: None,
        };
        outcome.validate().map_err(RegistryError::BadClaim)?;
        Ok(RetainedClaudeResult {
            identity: self.identity.clone(),
            agent_result,
            process_evidence: evidence,
            outcome,
        })
    }

    fn require_same_identity(
        &self,
        identity: &NativeWorkerRetainedOperationIdentity,
    ) -> Result<(), RegistryError> {
        if identity != &self.identity {
            return Err(RegistryError::BadInput {
                field: "retained_identity",
                detail: "operation identity differs from the originally retained dispatch".to_owned(),
            });
        }
        identity.validate().map_err(RegistryError::BadClaim)
    }
}

/// Same-operation inspect response for the daemon.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedClaudeInspection {
    /// Original retained identity.
    pub identity: NativeWorkerRetainedOperationIdentity,
    /// Process-owner view for that operation.
    pub view: ProcessExecutionView,
}

fn append_process_evidence_refs(evidence: &ProcessEvidence, references: &mut Vec<String>) {
    for stream in [evidence.stdout(), evidence.stderr()].into_iter().flatten() {
        if let Some(source) = stream.source() {
            references.push(source.locator().to_owned());
            references.push(source.ready_receipt_ref().to_owned());
        }
    }
    if let Some(reference) = evidence
        .view()
        .descendants()
        .and_then(|item| item.evidence_ref())
    {
        references.push(reference.to_owned());
    }
}

/// Exact cancellation observation plus the persisted cancellation id.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedClaudeCancellation {
    /// Original retained identity.
    pub identity: NativeWorkerRetainedOperationIdentity,
    /// Exact persisted cancellation identity accepted by this call.
    pub cancellation_id: String,
    /// Process-owner cancellation status.
    pub status: CancellationStatus,
    /// Process-owner lifecycle after cancellation.
    pub lifecycle: ProcessLifecycle,
    /// Whether no physical effect was proven.
    pub no_effect_proven: bool,
    /// Descendant closure when explicitly observed.
    pub descendants_complete: Option<bool>,
    /// Exact P-04 descendant evidence locator when available.
    pub evidence_ref: Option<String>,
}

/// Launch one exact provider attempt after validating the daemon identity
/// against the independently issued claim, handshake, sealed ProcessRequest,
/// ProviderExecutionBinding, and AgentAttempt. The launch port and all route
/// ceilings/receipts remain owner supplied. The supplied executor must be the
/// same WindowsProcessExecutor owner used by the composed native-worker; no
/// child process owner is created here.
#[allow(clippy::too_many_arguments)]
pub async fn launch_retained_claude_attempt(
    registry: &AdapterRegistry,
    validated: &ValidatedDispatch,
    claim_admission: &ClaimAdmissionRequest,
    hello: &WorkerHello,
    identity: NativeWorkerRetainedOperationIdentity,
    input: ClaudeFactoryInput,
    launch_port: &dyn ClaudeLaunchPort,
    route_receipt: AdmittedRouteReceipt,
    effect_ceiling: EffectCeiling,
    usage: UsageReceipt,
    evidence_sink: Arc<dyn ProcessEvidenceSink>,
    process_executor: Arc<WindowsProcessExecutor>,
    ledger: &mut FactoryLedger,
    started_at_unix_ms: u64,
) -> Result<RetainedClaudeStart, RegistryError> {
    let _entry = begin_invoke(registry, validated, AdapterIdentity::Claude, ledger)?;
    identity.validate_against(claim_admission, hello, &input.process_request)?;
    require_owner_binding(&identity, validated, claim_admission, hello, &input)?;
    if started_at_unix_ms == 0 || started_at_unix_ms >= identity.deadline_unix_ms {
        return Err(RegistryError::BadInput {
            field: "started_at_unix_ms",
            detail: "provider start is outside the persisted attempt deadline".to_owned(),
        });
    }
    let request = input.request.clone();
    let plan = request
        .launch_plan
        .as_ref()
        .ok_or(RegistryError::BadInput {
            field: "claude_launch_plan",
            detail: "admitted query has no launch plan".to_owned(),
        })?;
    let sidecar_deadline = started_at_unix_ms
        .checked_add(plan.wall_time_ms)
        .ok_or(RegistryError::BadInput {
            field: "claude_deadline",
            detail: "provider deadline arithmetic overflowed".to_owned(),
        })?;
    if sidecar_deadline > identity.deadline_unix_ms {
        return Err(RegistryError::BadInput {
            field: "claude_deadline",
            detail: "provider wall-time limit exceeds the persisted attempt deadline".to_owned(),
        });
    }
    let request_json = serde_json::to_string(plan).map_err(|_| RegistryError::BadInput {
        field: "claude_launch_plan",
        detail: "provider launch plan could not be serialized".to_owned(),
    })?;
    let expected_plan_digest = claude_local_digest_256_hex(request_json.as_bytes());
    let admitted = eliot_agent_claude::admit_with_port(launch_port, &request)
        .map_err(map_claude_error)?;
    admitted.validate().map_err(map_claude_error)?;
    if admitted.request_id != request.request_id || admitted.plan_digest != expected_plan_digest {
        return Err(RegistryError::BadInput {
            field: "claude_owner_admission",
            detail: "owner route receipt does not bind the exact query and launch plan".to_owned(),
        });
    }
    let process_operation_id = input.process_request.operation_id().clone();
    let process_request_digest = input.process_request.invocation_digest().to_owned();
    let process_fence = input.process_request.fence().clone();
    let process_generation = input.process_request.generation();
    let provider_binding = input.binding.clone();
    let provider_request = input.request.clone();
    let gate = input
        .gate
        .clone()
        .unwrap_or_else(|| UnknownOutcomeGate::new(identity.attempt_id.clone()));
    let mut prepared = match eliot_agent_claude::execution::prepare(input)
        .map_err(map_claude_error)?
    {
        ClaudeFactoryOutcome::ReplayDuplicate {
            prior_result_digest,
            process_request: _unused_request,
        } => {
            return Ok(RetainedClaudeStart::ReplayDuplicate {
                identity,
                prior_result_digest,
            });
        }
        ClaudeFactoryOutcome::Prepared(prepared) => prepared,
    };
    let stdin = sidecar_stdin_line(&prepared).map_err(map_claude_error)?;
    ledger.record_attempt_before_launch(AdapterIdentity::Claude, validated)?;
    let one_shot_executor = Arc::new(OneShotStdinProcessExecutor::new(
        Arc::clone(&process_executor),
        stdin.into_bytes(),
    ));
    let factory = ClaudeSidecarFactory::new(one_shot_executor);
    let mut attempt = RetainedClaudeAttempt {
        identity,
        factory,
        process_executor,
        process_operation_id,
        process_request_digest,
        process_fence,
        process_generation,
        provider_binding,
        provider_request,
        started_at_unix_ms,
        route_receipt,
        effect_ceiling,
        usage,
        gate,
        running: None,
    };
    match attempt
        .factory
        .launch(&mut prepared, evidence_sink, started_at_unix_ms)
        .await
    {
        Ok(running) => {
            attempt.running = Some(running);
            Ok(RetainedClaudeStart::Started(attempt))
        }
        Err(_ambiguous_or_refused) => Ok(RetainedClaudeStart::PendingReconcile(attempt)),
    }
}

fn require_owner_binding(
    identity: &NativeWorkerRetainedOperationIdentity,
    validated: &ValidatedDispatch,
    admission: &ClaimAdmissionRequest,
    hello: &WorkerHello,
    input: &ClaudeFactoryInput,
) -> Result<(), RegistryError> {
    let claim = admission.claim();
    if identity.task_id != validated.task_id()
        || identity.claim_id != validated.claim_id()
        || identity.attempt_id != validated.attempt_id()
        || identity.operation_id != validated.operation_id()
        || identity.worker_generation != validated.worker_generation()
        || identity.binding_digest != validated.binding_digest()
        || identity.task_id != claim.task_id.as_str()
        || identity.route_ref != hello.route_ref
        || identity.route_class != eliot_agent_claude::CLAUDE_SIDECAR_ROUTE_CLASS
        || input.binding.attempt_id.as_str() != identity.attempt_id
        || input.admitted.id.as_str() != identity.attempt_id
        || input.admitted.task_id.as_str() != identity.task_id
        || input.binding.runtime_generation.get() != identity.worker_generation
        || input.binding.state_fence != identity.state_fence
        || input.current_fence != identity.state_fence
        || input.process_request.operation_id().as_str() != identity.operation_id
        || input.process_request.generation().get() != identity.worker_generation
        || input.request.kind != eliot_agent_claude::ClaudeRequestKind::Query
    {
        return Err(RegistryError::BadClaim(WorkerError::AdmissionMismatch(
            "retained_claude_provider_binding",
        )));
    }
    Ok(())
}

/// Output parser shared by successful launch and unknown-start reconciliation.
/// It accepts only complete newline-terminated transport bytes; the existing
/// Claude line cursor validates each exact raw frame and the final terminal.
fn ingest_complete_stdout(
    running: &mut ClaudeRunningSidecar,
    bytes: &[u8],
    now_unix_ms: u64,
) -> Result<Option<ClaudeTerminalCandidate>, ClaudeSidecarError> {
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Ok(None);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ClaudeSidecarError::MalformedFrame("stdout is not UTF-8"))?;
    let mut terminal_line: Option<&str> = None;
    let mut candidate = None;
    for raw_line in text.split_inclusive('\n') {
        let event = running.ingest_line(raw_line, now_unix_ms)?;
        let response = ClaudeSidecarResponse::from_ndjson_line(raw_line)?;
        if event.is_terminal {
            terminal_line = Some(raw_line);
            candidate = response.candidate_result;
        }
    }
    let Some(raw_line) = terminal_line else {
        return Ok(None);
    };
    let Some(candidate) = candidate else {
        return Err(ClaudeSidecarError::MalformedFrame(
            "terminal result carries no candidate",
        ));
    };
    running
        .complete_terminal(&candidate, raw_line)
        .map(Some)
}

fn map_claude_error(error: ClaudeSidecarError) -> RegistryError {
    RegistryError::BadInput {
        field: "claude_execution",
        detail: truncate_detail(&error.to_string()),
    }
}

/// The one-shot stdin decorator delegates every process lifecycle call to
/// the pre-existing P-04 owner. Its only local state is one bounded request
/// buffer, consumed exactly once by `start` and never retained after handoff.
struct OneShotStdinProcessExecutor {
    inner: Arc<WindowsProcessExecutor>,
    stdin: Mutex<Option<Vec<u8>>>,
}

impl OneShotStdinProcessExecutor {
    fn new(inner: Arc<WindowsProcessExecutor>, stdin: Vec<u8>) -> Self {
        Self {
            inner,
            stdin: Mutex::new(Some(stdin)),
        }
    }
}

impl ProcessExecutor for OneShotStdinProcessExecutor {
    async fn start(
        &self,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        let stdin = self
            .stdin
            .lock()
            .map_err(|_| ProcessExecutionError::UnknownOutcome)?
            .take()
            .ok_or_else(|| ProcessExecutionError::Unavailable("Claude stdin was consumed".to_owned()))?;
        self.inner.start_with_stdin(request, sink, Some(&stdin))
    }

    async fn inspect(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessExecutionView, ProcessExecutionError> {
        self.inner.inspect(operation_id).await
    }

    async fn cancel(
        &self,
        operation_id: OperationId,
    ) -> Result<eliot_process::CancellationReceipt, ProcessExecutionError> {
        self.inner.cancel(operation_id).await
    }

    async fn reconcile(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        self.inner.reconcile(operation_id).await
    }
}
