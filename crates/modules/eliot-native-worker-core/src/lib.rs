//! A-13's provider-neutral isolated native-worker protocol core.
//!
//! A-13 owns the worker protocol and lifecycle. G-01-facing admission,
//! P-03 process execution, and durable replay/cursor storage are injected.
//! This crate never starts a process directly, opens a database, persists a
//! private journal, or converts a public request into authority.

#![forbid(unsafe_code)]

mod ports;
mod protocol;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use eliot_agent_api::{AuthorizedEffect, ProposedEffect};
use eliot_process::{
    CancellationStatus, EvidenceSinkError, FencingToken, OperationId,
    PROCESS_CONTRACT_SCHEMA_VERSION, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessExecutionView, ProcessExecutor, ProcessLifecycle, ProcessRequest, ProcessStartReceipt,
};
use eliot_receipts::{ProofCeiling, ReceiptDisposition};
use thiserror::Error;

use ports::{AdmissionLiveness, CapabilityGrant, EffectAdmissionGrant, ProcessBindingSnapshot};
pub use ports::{
    AdmissionLivenessFacts, AdmissionLivenessOutcome, CapabilityAdmissionFacts,
    CapabilityAdmissionOutcome, CapabilityAdmissionPort, CapabilityAdmissionRequest,
    CapabilityLivenessRequest, CheckpointProviderOutcome, CheckpointReceiptFacts,
    DurableCheckpointPort, DurableCheckpointRequest, DurableReplayPort, DurableRequestDecision,
    EffectAdmissionFacts, EffectAdmissionOutcome, EffectAdmissionRequest, ProviderFailure,
};
pub use protocol::{
    AckPhase, CancelRequest, CheckpointRequest, DeliveryClass, EventAckReceipt,
    JSON_ENCODING_PROFILE, PROTOCOL_VERSION, ReconnectRequest, WorkerEventDraft,
    WorkerEventEnvelope, WorkerEventPayload, WorkerFrame, WorkerFrameBody, WorkerHello,
    WorkerLifecycle, WorkerReady, WorkerRecovery, WorkerRequest,
};

pub const PROCESS_CONTRACT_VERSION: &str = PROCESS_CONTRACT_SCHEMA_VERSION;
pub const PROCESS_PROVIDER_PLAN_GAP: &str = "PLAN_GAP:A-13:P-03-PROCESS-EXECUTOR-UNAVAILABLE";
pub const PROCESS_EVIDENCE_PLAN_GAP: &str = "PLAN_GAP:A-13:P-03-EVIDENCE-SINK-UNAVAILABLE";
pub const ADMISSION_PROVIDER_PLAN_GAP: &str = "PLAN_GAP:A-13:G-01-ADMISSION-UNAVAILABLE";
pub const REPLAY_PROVIDER_PLAN_GAP: &str = "PLAN_GAP:A-13:DURABLE-REPLAY-UNAVAILABLE";
pub const CHECKPOINT_PROVIDER_PLAN_GAP: &str = "PLAN_GAP:A-13:DURABLE-CHECKPOINT-UNAVAILABLE";

struct ObservingEvidenceSink {
    downstream: Arc<dyn ProcessEvidenceSink>,
    observed: Mutex<Vec<ProcessEvidence>>,
}

impl ObservingEvidenceSink {
    fn new(downstream: Arc<dyn ProcessEvidenceSink>) -> Self {
        Self {
            downstream,
            observed: Mutex::new(Vec::new()),
        }
    }

    fn snapshot(&self) -> Result<Vec<ProcessEvidence>, WorkerError> {
        self.observed
            .lock()
            .map(|observed| observed.clone())
            .map_err(|_| WorkerError::Process("P-03 evidence observer lock failed".to_owned()))
    }
}

impl ProcessEvidenceSink for ObservingEvidenceSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        self.downstream.record(evidence.clone())?;
        self.observed
            .lock()
            .map_err(|_| EvidenceSinkError {
                message: "A-13 evidence observer lock failed".to_owned(),
            })?
            .push(evidence);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkerError {
    #[error("native-worker protocol version is unsupported")]
    UnsupportedVersion,
    #[error("native-worker encoding profile is unsupported")]
    UnsupportedEncoding,
    #[error("invalid handshake field {0}")]
    InvalidHandshake(&'static str),
    #[error("invalid frame field {0}")]
    InvalidFrame(&'static str),
    #[error("invalid request field {0}")]
    InvalidRequest(&'static str),
    #[error("worker is not attached and ready")]
    NotReady,
    #[error("worker lifecycle transition is invalid")]
    InvalidLifecycle,
    #[error("worker frame connection is stale")]
    StaleConnection,
    #[error("worker authority epoch is stale")]
    StaleEpoch,
    #[error("worker state fence is stale")]
    StaleFence,
    #[error("worker lease is stale or expired")]
    StaleLease,
    #[error("worker admission revision is stale")]
    StaleRevision,
    #[error("worker admission was revoked at {0}")]
    Revoked(String),
    #[error("worker deadline expired")]
    DeadlineExpired,
    #[error("admission was rejected: {0}")]
    AdmissionRejected(String),
    #[error("admission outcome did not bind {0}")]
    AdmissionMismatch(&'static str),
    #[error("effect admission was rejected: {0}")]
    EffectRejected(String),
    #[error("effect admission outcome did not bind {0}")]
    EffectMismatch(&'static str),
    #[error("checkpoint provider rejected request: {0}")]
    CheckpointRejected(String),
    #[error("checkpoint receipt did not bind {0}")]
    CheckpointReceiptMismatch(&'static str),
    #[error("request id was reused with different content")]
    IdempotencyConflict,
    #[error("durable replay contract rejected {0}")]
    ReplayContract(&'static str),
    #[error("provider failure: {0}")]
    Provider(String),
    #[error("process contract failure: {0}")]
    Process(String),
    #[error("process start receipt did not bind {0}")]
    ProcessReceiptMismatch(&'static str),
    #[error("process outcome is unknown and requires reconciliation")]
    UnknownOutcome,
    #[error("{code}: {detail}")]
    PlanGap {
        code: &'static str,
        detail: &'static str,
    },
}

/// A-13's composition core. Generic P-03 injection is required because the
/// canonical `ProcessExecutor` async trait deliberately remains provider-neutral.
pub struct WorkerCore<E, A, R, C> {
    executor: Option<E>,
    admission: Option<A>,
    replay: Option<R>,
    checkpoint: Option<C>,
    evidence_sink: Option<Arc<dyn ProcessEvidenceSink>>,
    lifecycle: WorkerLifecycle,
    grant: Option<CapabilityGrant>,
    process_binding: Option<ProcessBindingSnapshot>,
    process_start_receipt: Option<ProcessStartReceipt>,
    connection_id: Option<String>,
    last_event_id: Option<String>,
    last_event_sequence: u64,
}

impl<E, A, R, C> WorkerCore<E, A, R, C>
where
    E: ProcessExecutor,
    A: CapabilityAdmissionPort,
    R: DurableReplayPort,
    C: DurableCheckpointPort,
{
    #[must_use]
    pub fn new(
        executor: Option<E>,
        admission: Option<A>,
        replay: Option<R>,
        checkpoint: Option<C>,
        evidence_sink: Option<Arc<dyn ProcessEvidenceSink>>,
    ) -> Self {
        Self {
            executor,
            admission,
            replay,
            checkpoint,
            evidence_sink,
            lifecycle: WorkerLifecycle::Created,
            grant: None,
            process_binding: None,
            process_start_receipt: None,
            connection_id: None,
            last_event_id: None,
            last_event_sequence: 0,
        }
    }

    #[must_use]
    pub const fn lifecycle(&self) -> WorkerLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub const fn process_state(&self) -> eliot_runtime_contracts::ServiceProcessState {
        self.lifecycle.service_state()
    }

    #[must_use]
    pub const fn process_start_receipt(&self) -> Option<&ProcessStartReceipt> {
        self.process_start_receipt.as_ref()
    }

    /// Admits an exact route/capability envelope, invokes P-03, and becomes
    /// ready only after the returned start receipt binds the exact request.
    #[allow(clippy::too_many_lines)]
    pub async fn demand_start(
        &mut self,
        hello: WorkerHello,
        process: ProcessRequest,
    ) -> Result<WorkerReady, WorkerError> {
        if !matches!(
            self.lifecycle,
            WorkerLifecycle::Created | WorkerLifecycle::Stopped
        ) {
            return Err(WorkerError::InvalidLifecycle);
        }
        hello.validate()?;
        process
            .validate()
            .map_err(|error| WorkerError::Process(error.to_string()))?;
        eliot_security_contracts::contract_identity()
            .map_err(|error| WorkerError::Provider(error.to_string()))?;
        self.require_replay()?;
        self.require_executor()?;
        let evidence_sink = self.evidence_sink.clone().ok_or(WorkerError::PlanGap {
            code: PROCESS_EVIDENCE_PLAN_GAP,
            detail: "P-03 evidence sink was not injected",
        })?;

        let admission_request = CapabilityAdmissionRequest::from_start(&hello, &process);
        let admission_outcome = self
            .admission
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: ADMISSION_PROVIDER_PLAN_GAP,
                detail: "G-01-facing admission provider was not injected",
            })?
            .admit(&admission_request)
            .map_err(provider_error)?;
        let grant = match admission_outcome {
            CapabilityAdmissionOutcome::Admitted(facts) => CapabilityGrant::seal(*facts),
            CapabilityAdmissionOutcome::Rejected { reason } => {
                return Err(WorkerError::AdmissionRejected(reason));
            }
            CapabilityAdmissionOutcome::Revoked { revision } => {
                return Err(WorkerError::Revoked(revision));
            }
        };
        validate_grant(&grant, &hello, &process)?;
        let process_binding = ProcessBindingSnapshot::from_request(&process);

        self.transition(WorkerLifecycle::Starting)?;
        let observing_sink = Arc::new(ObservingEvidenceSink::new(evidence_sink));
        let process_sink: Arc<dyn ProcessEvidenceSink> = observing_sink.clone();
        let start_result = self
            .executor
            .as_ref()
            .ok_or(WorkerError::PlanGap {
                code: PROCESS_PROVIDER_PLAN_GAP,
                detail: "P-03 ProcessExecutor was not injected",
            })?
            .start(process, process_sink)
            .await;

        let receipt = match start_result {
            Ok(receipt) => receipt,
            Err(ProcessExecutionError::UnknownOutcome) => {
                self.install_binding(&hello, grant, process_binding);
                self.transition(WorkerLifecycle::UnknownOutcome)?;
                let _ = self.append_from_hello(
                    &hello,
                    "worker.unknown_outcome",
                    WorkerEventPayload::UnknownOutcome,
                    ReceiptDisposition::Unknown {
                        reason: "process start outcome requires reconciliation".to_owned(),
                    },
                    DeliveryClass::DurableControl,
                    true,
                )?;
                return Err(WorkerError::UnknownOutcome);
            }
            Err(ProcessExecutionError::Unavailable(_)) => {
                self.lifecycle = WorkerLifecycle::Created;
                return Err(WorkerError::PlanGap {
                    code: PROCESS_PROVIDER_PLAN_GAP,
                    detail: "P-03 ProcessExecutor is unavailable",
                });
            }
            Err(error) => {
                self.lifecycle = WorkerLifecycle::Created;
                return Err(WorkerError::Process(error.to_string()));
            }
        };
        if let Err(error) = validate_start_receipt(&receipt, &process_binding) {
            return self.reject_start_proof(
                &hello,
                grant,
                process_binding.clone(),
                "process start receipt did not bind the admitted request",
                error,
            );
        }

        let observed = observing_sink.snapshot()?;
        if observed.is_empty() {
            return self.reject_start_proof(
                &hello,
                grant,
                process_binding.clone(),
                "P-03 start produced no observed process evidence",
                WorkerError::PlanGap {
                    code: PROCESS_EVIDENCE_PLAN_GAP,
                    detail: "P-03 start produced no observed process evidence",
                },
            );
        }
        let inspected = match self
            .executor
            .as_ref()
            .ok_or(WorkerError::PlanGap {
                code: PROCESS_PROVIDER_PLAN_GAP,
                detail: "P-03 ProcessExecutor was not injected",
            })?
            .inspect(process_binding.operation_id().clone())
            .await
        {
            Ok(view) => view,
            Err(error) => {
                let error = map_start_inspect_error(error);
                return self.reject_start_proof(
                    &hello,
                    grant,
                    process_binding.clone(),
                    "P-03 readiness inspection was unavailable or unknown",
                    error,
                );
            }
        };
        if let Err(error) = validate_start_proof(&receipt, &observed, &inspected, &process_binding)
        {
            return self.reject_start_proof(
                &hello,
                grant,
                process_binding.clone(),
                "P-03 evidence or inspection did not bind readiness",
                error,
            );
        }

        self.install_binding(&hello, grant, process_binding);
        self.process_start_receipt = Some(receipt.clone());
        self.transition(WorkerLifecycle::Ready)?;
        let ready_event = self.append_from_hello(
            &hello,
            "worker.ready",
            WorkerEventPayload::Ready,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableControl,
            true,
        )?;
        let grant = self.grant.as_ref().ok_or(WorkerError::NotReady)?;
        Ok(WorkerReady {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            encoding_profile: JSON_ENCODING_PROFILE.to_owned(),
            connection_id: hello.connection_id,
            request_id: hello.request_id,
            admission_revision: grant.admission_revision().to_owned(),
            stream_id: grant.stream_id().to_owned(),
            process_start_receipt: receipt,
            ready_event,
        })
    }

    /// Restores an exact process/admission binding after an A-13 restart without
    /// launching a duplicate process. P-03 inspect and durable replay are the source.
    pub async fn recover_after_restart(
        &mut self,
        hello: WorkerHello,
        process: ProcessRequest,
        replay_after_sequence: u64,
    ) -> Result<WorkerRecovery, WorkerError> {
        if !matches!(
            self.lifecycle,
            WorkerLifecycle::Created | WorkerLifecycle::Stopped
        ) {
            return Err(WorkerError::InvalidLifecycle);
        }
        hello.validate()?;
        process
            .validate()
            .map_err(|error| WorkerError::Process(error.to_string()))?;
        self.require_replay()?;
        self.require_executor()?;
        let admission_request = CapabilityAdmissionRequest::from_start(&hello, &process);
        let grant = match self
            .admission
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: ADMISSION_PROVIDER_PLAN_GAP,
                detail: "G-01-facing admission provider was not injected",
            })?
            .admit(&admission_request)
            .map_err(provider_error)?
        {
            CapabilityAdmissionOutcome::Admitted(facts) => CapabilityGrant::seal(*facts),
            CapabilityAdmissionOutcome::Rejected { reason } => {
                return Err(WorkerError::AdmissionRejected(reason));
            }
            CapabilityAdmissionOutcome::Revoked { revision } => {
                return Err(WorkerError::Revoked(revision));
            }
        };
        validate_grant(&grant, &hello, &process)?;
        let process_binding = ProcessBindingSnapshot::from_request(&process);
        let view = self
            .executor
            .as_ref()
            .ok_or(WorkerError::PlanGap {
                code: PROCESS_PROVIDER_PLAN_GAP,
                detail: "P-03 ProcessExecutor was not injected",
            })?
            .inspect(process_binding.operation_id().clone())
            .await
            .map_err(map_process_error)?;
        validate_process_evidence_binding(
            view.operation_id(),
            view.request_digest(),
            view.fence(),
            &process_binding,
        )?;
        validate_recovered_process_view(&view, &process_binding)?;
        let recovered_lifecycle = worker_lifecycle_from_process(view.lifecycle());
        let replayed_events = self
            .replay
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: REPLAY_PROVIDER_PLAN_GAP,
                detail: "durable replay provider was not injected",
            })?
            .replay(grant.stream_id(), replay_after_sequence)
            .map_err(provider_error)?;
        validate_replayed_events(&replayed_events, &grant, Some(replay_after_sequence))?;
        self.install_binding(&hello, grant, process_binding);
        self.lifecycle = recovered_lifecycle;
        if let Some(tail) = replayed_events.last() {
            self.last_event_id = Some(tail.event_id.clone());
            self.last_event_sequence = tail.sequence;
        }
        Ok(WorkerRecovery {
            connection_id: hello.connection_id,
            lifecycle: recovered_lifecycle,
            replayed_events,
        })
    }

    /// Handles one complete native-worker protocol frame.
    pub async fn handle(
        &mut self,
        frame: WorkerFrame,
    ) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        frame.validate_shape()?;
        let grant = self.grant.clone().ok_or(WorkerError::NotReady)?;
        self.validate_frame_binding(&frame, &grant)?;
        self.revalidate_admission(&grant, frame.deadline_unix_ms)?;

        if let WorkerFrameBody::Acknowledge(receipt) = &frame.body {
            validate_ack(receipt, &grant)?;
            self.replay
                .as_mut()
                .ok_or(WorkerError::PlanGap {
                    code: REPLAY_PROVIDER_PLAN_GAP,
                    detail: "durable replay provider was not injected",
                })?
                .acknowledge(receipt)
                .map_err(provider_error)?;
            return Ok(Vec::new());
        }

        let fingerprint = serde_json::to_string(&frame.body)
            .map_err(|_| WorkerError::InvalidFrame("fingerprint"))?;
        match self
            .replay
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: REPLAY_PROVIDER_PLAN_GAP,
                detail: "durable replay provider was not injected",
            })?
            .lookup_request(grant.stream_id(), &frame.request_id, &fingerprint)
            .map_err(provider_error)?
        {
            DurableRequestDecision::New => {}
            DurableRequestDecision::Replay(events) => {
                if events.is_empty() {
                    return Err(WorkerError::ReplayContract("incomplete_request"));
                }
                validate_replayed_events(&events, &grant, None)?;
                validate_request_replay(&events, &frame.request_id)?;
                return Ok(events);
            }
            DurableRequestDecision::Conflict => return Err(WorkerError::IdempotencyConflict),
        }
        let prepared_effect = self.prepare_body(&frame.body, &grant)?;
        match self
            .replay
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: REPLAY_PROVIDER_PLAN_GAP,
                detail: "durable replay provider was not injected",
            })?
            .begin_request(grant.stream_id(), &frame.request_id, &fingerprint)
            .map_err(provider_error)?
        {
            DurableRequestDecision::New => {}
            DurableRequestDecision::Replay(events) => {
                if events.is_empty() {
                    return Err(WorkerError::ReplayContract("incomplete_request"));
                }
                validate_replayed_events(&events, &grant, None)?;
                validate_request_replay(&events, &frame.request_id)?;
                return Ok(events);
            }
            DurableRequestDecision::Conflict => return Err(WorkerError::IdempotencyConflict),
        }

        match frame.body.clone() {
            WorkerFrameBody::Execute(request) => self.execute(&frame, request, prepared_effect),
            WorkerFrameBody::Cancel(request) => self.cancel(&frame, request).await,
            WorkerFrameBody::Heartbeat => self.heartbeat(&frame),
            WorkerFrameBody::Health => self.health(&frame),
            WorkerFrameBody::Checkpoint(request) => self.checkpoint(&frame, request),
            WorkerFrameBody::Quiesce => self.quiesce(&frame),
            WorkerFrameBody::Reconnect(request) => self.reconnect(&frame, request),
            WorkerFrameBody::Reconcile => self.reconcile(&frame).await,
            WorkerFrameBody::Shutdown => self.shutdown(&frame),
            WorkerFrameBody::Acknowledge(_) => unreachable!("ack handled before idempotency"),
        }
    }

    fn execute(
        &mut self,
        frame: &WorkerFrame,
        request: WorkerRequest,
        authorized: Option<AuthorizedEffect>,
    ) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        if self.lifecycle == WorkerLifecycle::Ready {
            self.transition(WorkerLifecycle::Running)?;
        }
        let mut events = vec![self.append_from_frame(
            frame,
            "worker.accepted",
            WorkerEventPayload::Accepted {
                attempt_id: request.attempt_id.clone(),
            },
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableObservation,
            true,
        )?];
        if let (Some(proposal), Some(authorized_effect)) = (request.proposed_effect, authorized) {
            events.push(self.append_from_frame(
                frame,
                "worker.candidate_effect",
                WorkerEventPayload::CandidateOnly {
                    proposal: Box::new(proposal),
                    authorized_effect: Box::new(authorized_effect),
                },
                ReceiptDisposition::Success {
                    proof: ProofCeiling::CandidateArtifact,
                },
                DeliveryClass::DurableObservation,
                true,
            )?);
        }
        Ok(events)
    }

    fn prepare_body(
        &mut self,
        body: &WorkerFrameBody,
        grant: &CapabilityGrant,
    ) -> Result<Option<AuthorizedEffect>, WorkerError> {
        match body {
            WorkerFrameBody::Execute(request) => {
                if !matches!(
                    self.lifecycle,
                    WorkerLifecycle::Ready | WorkerLifecycle::Running
                ) {
                    return Err(WorkerError::InvalidLifecycle);
                }
                request.validate_shape()?;
                if !grant.capabilities().contains(&request.capability) {
                    return Err(WorkerError::AdmissionRejected(
                        "capability was not admitted".to_owned(),
                    ));
                }
                request
                    .proposed_effect
                    .as_ref()
                    .map(|proposal| self.authorize_effect(grant, request, proposal))
                    .transpose()
            }
            WorkerFrameBody::Cancel(request) => {
                if request.reason.trim().is_empty() {
                    return Err(WorkerError::InvalidRequest("cancel_reason"));
                }
                if !matches!(
                    self.lifecycle,
                    WorkerLifecycle::Ready | WorkerLifecycle::Running | WorkerLifecycle::Quiescing
                ) {
                    return Err(WorkerError::InvalidLifecycle);
                }
                Ok(None)
            }
            WorkerFrameBody::Checkpoint(request) => {
                if request.checkpoint_ref.trim().is_empty() {
                    return Err(WorkerError::InvalidRequest("checkpoint_ref"));
                }
                Ok(None)
            }
            WorkerFrameBody::Quiesce => {
                if !matches!(
                    self.lifecycle,
                    WorkerLifecycle::Ready | WorkerLifecycle::Running
                ) {
                    return Err(WorkerError::InvalidLifecycle);
                }
                Ok(None)
            }
            WorkerFrameBody::Reconnect(request) => {
                if self.connection_id.as_deref() != Some(request.previous_connection_id.as_str())
                    || request.new_connection_id.trim().is_empty()
                {
                    return Err(WorkerError::StaleConnection);
                }
                Ok(None)
            }
            WorkerFrameBody::Reconcile => {
                if self.lifecycle != WorkerLifecycle::UnknownOutcome {
                    return Err(WorkerError::InvalidLifecycle);
                }
                Ok(None)
            }
            WorkerFrameBody::Shutdown => {
                if !matches!(
                    self.lifecycle,
                    WorkerLifecycle::Quiescing
                        | WorkerLifecycle::Cancelled
                        | WorkerLifecycle::Reconciled
                ) {
                    return Err(WorkerError::InvalidLifecycle);
                }
                Ok(None)
            }
            WorkerFrameBody::Heartbeat | WorkerFrameBody::Health => Ok(None),
            WorkerFrameBody::Acknowledge(_) => unreachable!("ack prepared separately"),
        }
    }

    async fn cancel(
        &mut self,
        frame: &WorkerFrame,
        request: CancelRequest,
    ) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        if request.reason.trim().is_empty() {
            return Err(WorkerError::InvalidRequest("cancel_reason"));
        }
        if !matches!(
            self.lifecycle,
            WorkerLifecycle::Ready | WorkerLifecycle::Running | WorkerLifecycle::Quiescing
        ) {
            return Err(WorkerError::InvalidLifecycle);
        }
        let operation_id = self
            .process_binding
            .as_ref()
            .ok_or(WorkerError::NotReady)?
            .operation_id()
            .clone();
        let outcome = self
            .executor
            .as_ref()
            .ok_or(WorkerError::PlanGap {
                code: PROCESS_PROVIDER_PLAN_GAP,
                detail: "P-03 ProcessExecutor was not injected",
            })?
            .cancel(operation_id)
            .await;
        match outcome {
            Ok(receipt) => {
                self.lifecycle = match receipt.status() {
                    CancellationStatus::Completed => WorkerLifecycle::Cancelled,
                    CancellationStatus::UnknownOutcome => WorkerLifecycle::UnknownOutcome,
                    _ => WorkerLifecycle::Cancelling,
                };
                Ok(vec![self.append_from_frame(
                    frame,
                    "worker.cancel",
                    WorkerEventPayload::Cancellation {
                        status: receipt.status(),
                        reason: request.reason,
                    },
                    ReceiptDisposition::Cancelled {
                        reason: "P-03 cancellation accepted".to_owned(),
                    },
                    DeliveryClass::DurableControl,
                    true,
                )?])
            }
            Err(ProcessExecutionError::UnknownOutcome) => {
                self.lifecycle = WorkerLifecycle::UnknownOutcome;
                Ok(vec![self.append_from_frame(
                    frame,
                    "worker.unknown_outcome",
                    WorkerEventPayload::UnknownOutcome,
                    ReceiptDisposition::Unknown {
                        reason: "cancellation outcome requires reconciliation".to_owned(),
                    },
                    DeliveryClass::DurableControl,
                    true,
                )?])
            }
            Err(error) => Err(map_process_error(error)),
        }
    }

    async fn reconcile(
        &mut self,
        frame: &WorkerFrame,
    ) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        if self.lifecycle != WorkerLifecycle::UnknownOutcome {
            return Err(WorkerError::InvalidLifecycle);
        }
        let process = self.process_binding.clone().ok_or(WorkerError::NotReady)?;
        let evidence = self
            .executor
            .as_ref()
            .ok_or(WorkerError::PlanGap {
                code: PROCESS_PROVIDER_PLAN_GAP,
                detail: "P-03 ProcessExecutor was not injected",
            })?
            .reconcile(process.operation_id().clone())
            .await
            .map_err(map_process_error)?;
        validate_process_evidence(&evidence, &process)?;
        if evidence.view().lifecycle() == ProcessLifecycle::UnknownOutcome {
            return Err(WorkerError::UnknownOutcome);
        }
        if evidence.view().lifecycle() != ProcessLifecycle::Reconciled {
            return Err(WorkerError::ProcessReceiptMismatch("reconcile_lifecycle"));
        }
        self.lifecycle = WorkerLifecycle::Reconciled;
        Ok(vec![self.append_from_frame(
            frame,
            "worker.reconciled",
            WorkerEventPayload::Reconciled {
                process_lifecycle: evidence.view().lifecycle(),
            },
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableControl,
            true,
        )?])
    }

    fn heartbeat(&mut self, frame: &WorkerFrame) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        Ok(vec![self.append_from_frame(
            frame,
            "worker.heartbeat",
            WorkerEventPayload::Heartbeat,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::BestEffortTelemetry,
            false,
        )?])
    }

    fn health(&mut self, frame: &WorkerFrame) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        Ok(vec![self.append_from_frame(
            frame,
            "worker.health",
            WorkerEventPayload::Health {
                state: self.process_state(),
            },
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableObservation,
            true,
        )?])
    }

    fn checkpoint(
        &mut self,
        frame: &WorkerFrame,
        request: CheckpointRequest,
    ) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        if request.checkpoint_ref.trim().is_empty() {
            return Err(WorkerError::InvalidRequest("checkpoint_ref"));
        }
        let grant = self.grant.clone().ok_or(WorkerError::NotReady)?;
        let process = self.process_binding.clone().ok_or(WorkerError::NotReady)?;
        let durable_request = DurableCheckpointRequest::new(
            request.checkpoint_ref.clone(),
            frame.request_id.clone(),
            &grant,
            &process,
        );
        let receipt = match self
            .checkpoint
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: CHECKPOINT_PROVIDER_PLAN_GAP,
                detail: "durable checkpoint provider was not injected",
            })?
            .persist_checkpoint(&durable_request)
            .map_err(provider_error)?
        {
            CheckpointProviderOutcome::Stored(receipt) => *receipt,
            CheckpointProviderOutcome::Rejected { reason } => {
                return Err(WorkerError::CheckpointRejected(reason));
            }
        };
        validate_checkpoint_receipt(&receipt, &durable_request)?;
        Ok(vec![self.append_from_frame(
            frame,
            "worker.checkpoint",
            WorkerEventPayload::Checkpoint {
                checkpoint_ref: request.checkpoint_ref,
            },
            ReceiptDisposition::Success {
                proof: ProofCeiling::CandidateArtifact,
            },
            DeliveryClass::DurableControl,
            true,
        )?])
    }

    fn quiesce(&mut self, frame: &WorkerFrame) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        if !matches!(
            self.lifecycle,
            WorkerLifecycle::Ready | WorkerLifecycle::Running
        ) {
            return Err(WorkerError::InvalidLifecycle);
        }
        let event = self.append_from_frame(
            frame,
            "worker.quiescing",
            WorkerEventPayload::Quiescing,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableControl,
            true,
        )?;
        self.transition(WorkerLifecycle::Quiescing)?;
        Ok(vec![event])
    }

    fn reconnect(
        &mut self,
        frame: &WorkerFrame,
        request: ReconnectRequest,
    ) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        let current = self.connection_id.as_deref().ok_or(WorkerError::NotReady)?;
        if request.previous_connection_id != current || request.new_connection_id.trim().is_empty()
        {
            return Err(WorkerError::StaleConnection);
        }
        if request.replay_after_sequence > self.last_event_sequence {
            return Err(WorkerError::ReplayContract("cursor_ahead"));
        }
        let known_last_sequence = self.last_event_sequence;
        let grant = self.grant.clone().ok_or(WorkerError::NotReady)?;
        let mut events = self
            .replay
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: REPLAY_PROVIDER_PLAN_GAP,
                detail: "durable replay provider was not injected",
            })?
            .replay(grant.stream_id(), request.replay_after_sequence)
            .map_err(provider_error)?;
        validate_replayed_events(&events, &grant, Some(request.replay_after_sequence))?;
        if known_last_sequence > request.replay_after_sequence
            && events.last().map_or(0, |event| event.sequence) < known_last_sequence
        {
            return Err(WorkerError::ReplayContract("stale_replay_tail"));
        }
        if let Some(tail) = events.last() {
            self.last_event_id = Some(tail.event_id.clone());
            self.last_event_sequence = tail.sequence;
        }
        let previous = request.previous_connection_id;
        let new_connection = request.new_connection_id;
        let reconnect_event = self.append_from_frame(
            frame,
            "worker.reconnected",
            WorkerEventPayload::Reconnected {
                previous_connection_id: previous,
                new_connection_id: new_connection.clone(),
            },
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableControl,
            true,
        )?;
        self.connection_id = Some(new_connection);
        events.push(reconnect_event);
        Ok(events)
    }

    fn shutdown(&mut self, frame: &WorkerFrame) -> Result<Vec<WorkerEventEnvelope>, WorkerError> {
        if !matches!(
            self.lifecycle,
            WorkerLifecycle::Quiescing | WorkerLifecycle::Cancelled | WorkerLifecycle::Reconciled
        ) {
            return Err(WorkerError::InvalidLifecycle);
        }
        let event = self.append_from_frame(
            frame,
            "worker.shutdown",
            WorkerEventPayload::Shutdown,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            DeliveryClass::DurableControl,
            true,
        )?;
        self.lifecycle = WorkerLifecycle::Stopped;
        Ok(vec![event])
    }

    fn authorize_effect(
        &mut self,
        grant: &CapabilityGrant,
        request: &WorkerRequest,
        proposal: &ProposedEffect,
    ) -> Result<AuthorizedEffect, WorkerError> {
        proposal
            .validate_against(&grant.authority().effect_ceiling)
            .map_err(|_| {
                WorkerError::EffectRejected("effect exceeds admitted ceiling".to_owned())
            })?;
        let effect_request =
            EffectAdmissionRequest::new(proposal.clone(), request.attempt_id.clone(), grant);
        let outcome = self
            .admission
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: ADMISSION_PROVIDER_PLAN_GAP,
                detail: "G-01-facing admission provider was not injected",
            })?
            .authorize_effect(&effect_request)
            .map_err(provider_error)?;
        let effect_grant = match outcome {
            EffectAdmissionOutcome::Authorized(facts) => EffectAdmissionGrant::seal(*facts),
            EffectAdmissionOutcome::Rejected { reason } => {
                return Err(WorkerError::EffectRejected(reason));
            }
            EffectAdmissionOutcome::Revoked { revision } => {
                return Err(WorkerError::Revoked(revision));
            }
        };
        validate_effect_grant(&effect_grant, grant, proposal)?;
        Ok(effect_grant.authorized_effect().clone())
    }

    fn validate_frame_binding(
        &self,
        frame: &WorkerFrame,
        grant: &CapabilityGrant,
    ) -> Result<(), WorkerError> {
        if self.connection_id.as_deref() != Some(frame.connection_id.as_str()) {
            return Err(WorkerError::StaleConnection);
        }
        if frame.authority_epoch != grant.authority().epoch {
            return Err(WorkerError::StaleEpoch);
        }
        if frame.state_fence != grant.authority().state_fence {
            return Err(WorkerError::StaleFence);
        }
        if frame.lease_id != grant.authority().lease.as_str() {
            return Err(WorkerError::StaleLease);
        }
        if frame.admission_revision != grant.admission_revision() {
            return Err(WorkerError::StaleRevision);
        }
        if frame.producer_generation != grant.worker_generation() {
            return Err(WorkerError::StaleEpoch);
        }
        Ok(())
    }

    fn revalidate_admission(
        &mut self,
        grant: &CapabilityGrant,
        deadline_unix_ms: u64,
    ) -> Result<(), WorkerError> {
        let liveness_request = CapabilityLivenessRequest::from_grant(grant);
        let outcome = self
            .admission
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: ADMISSION_PROVIDER_PLAN_GAP,
                detail: "G-01-facing admission provider was not injected",
            })?
            .revalidate(&liveness_request)
            .map_err(provider_error)?;
        let live = match outcome {
            AdmissionLivenessOutcome::Live(facts) => AdmissionLiveness::seal(facts),
            AdmissionLivenessOutcome::Rejected { reason } => {
                return Err(WorkerError::AdmissionRejected(reason));
            }
            AdmissionLivenessOutcome::Revoked { revision } => {
                return Err(WorkerError::Revoked(revision));
            }
        };
        if live.revoked() {
            return Err(WorkerError::Revoked(live.admission_revision().to_owned()));
        }
        if live.admission_id() != grant.admission_id()
            || live.lease() != &grant.authority().lease
            || live.authority_epoch() != &grant.authority().epoch
        {
            return Err(WorkerError::StaleLease);
        }
        if live.state_fence() != &grant.authority().state_fence {
            return Err(WorkerError::StaleFence);
        }
        if live.admission_revision() != grant.admission_revision()
            || live.revocation_revision() != grant.revocation_revision()
        {
            return Err(WorkerError::StaleRevision);
        }
        if live.expires_at_unix_ms() != grant.expires_at_unix_ms()
            || live.observed_at_unix_ms() >= live.expires_at_unix_ms()
        {
            return Err(WorkerError::StaleLease);
        }
        if live.observed_at_unix_ms() > deadline_unix_ms {
            return Err(WorkerError::DeadlineExpired);
        }
        Ok(())
    }

    fn append_from_hello(
        &mut self,
        hello: &WorkerHello,
        payload_type: &'static str,
        payload: WorkerEventPayload,
        disposition: ReceiptDisposition,
        delivery_class: DeliveryClass,
        ack_required: bool,
    ) -> Result<WorkerEventEnvelope, WorkerError> {
        self.append_event(
            &hello.request_id,
            &hello.trace_context,
            payload_type,
            payload,
            disposition,
            delivery_class,
            ack_required,
        )
    }

    fn append_from_frame(
        &mut self,
        frame: &WorkerFrame,
        payload_type: &'static str,
        payload: WorkerEventPayload,
        disposition: ReceiptDisposition,
        delivery_class: DeliveryClass,
        ack_required: bool,
    ) -> Result<WorkerEventEnvelope, WorkerError> {
        self.append_event(
            &frame.request_id,
            &frame.trace_context,
            payload_type,
            payload,
            disposition,
            delivery_class,
            ack_required,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_event(
        &mut self,
        request_id: &str,
        trace_context: &BTreeMap<String, String>,
        payload_type: &'static str,
        payload: WorkerEventPayload,
        disposition: ReceiptDisposition,
        delivery_class: DeliveryClass,
        ack_required: bool,
    ) -> Result<WorkerEventEnvelope, WorkerError> {
        let grant = self.grant.clone().ok_or(WorkerError::NotReady)?;
        let causal_predecessor_refs: Vec<String> = self.last_event_id.iter().cloned().collect();
        let expected_causal_predecessor_refs = causal_predecessor_refs.clone();
        let expected_payload = payload.clone();
        let expected_disposition = disposition.clone();
        let draft = WorkerEventDraft::new(
            grant.stream_id().to_owned(),
            grant.producer_id().to_owned(),
            grant.worker_generation(),
            grant.authority().epoch,
            request_id.to_owned(),
            causal_predecessor_refs,
            delivery_class,
            ack_required,
            payload_type,
            payload,
            disposition,
            grant.authority().state_fence.clone(),
            trace_context.clone(),
        );
        let event = self
            .replay
            .as_mut()
            .ok_or(WorkerError::PlanGap {
                code: REPLAY_PROVIDER_PLAN_GAP,
                detail: "durable replay provider was not injected",
            })?
            .append(draft)
            .map_err(provider_error)?;
        validate_event(
            &event,
            &grant,
            request_id,
            payload_type,
            &expected_payload,
            &expected_disposition,
            trace_context,
            &expected_causal_predecessor_refs,
            delivery_class,
            ack_required,
        )?;
        if event.sequence <= self.last_event_sequence {
            return Err(WorkerError::ReplayContract("event_sequence"));
        }
        self.last_event_id = Some(event.event_id.clone());
        self.last_event_sequence = event.sequence;
        Ok(event)
    }

    fn install_binding(
        &mut self,
        hello: &WorkerHello,
        grant: CapabilityGrant,
        process: ProcessBindingSnapshot,
    ) {
        self.connection_id = Some(hello.connection_id.clone());
        self.grant = Some(grant);
        self.process_binding = Some(process);
    }

    fn reject_start_proof(
        &mut self,
        hello: &WorkerHello,
        grant: CapabilityGrant,
        process: ProcessBindingSnapshot,
        reason: &str,
        error: WorkerError,
    ) -> Result<WorkerReady, WorkerError> {
        self.install_binding(hello, grant, process);
        self.transition(WorkerLifecycle::UnknownOutcome)?;
        let _ = self.append_from_hello(
            hello,
            "worker.unknown_outcome",
            WorkerEventPayload::UnknownOutcome,
            ReceiptDisposition::Unknown {
                reason: reason.to_owned(),
            },
            DeliveryClass::DurableControl,
            true,
        )?;
        Err(error)
    }

    fn transition(&mut self, next: WorkerLifecycle) -> Result<(), WorkerError> {
        if self.lifecycle.can_transition_to(next) {
            self.lifecycle = next;
            Ok(())
        } else {
            Err(WorkerError::InvalidLifecycle)
        }
    }

    fn require_executor(&self) -> Result<(), WorkerError> {
        self.executor.as_ref().map_or_else(
            || {
                Err(WorkerError::PlanGap {
                    code: PROCESS_PROVIDER_PLAN_GAP,
                    detail: "P-03 ProcessExecutor was not injected",
                })
            },
            |_| Ok(()),
        )
    }

    fn require_replay(&self) -> Result<(), WorkerError> {
        self.replay.as_ref().map_or_else(
            || {
                Err(WorkerError::PlanGap {
                    code: REPLAY_PROVIDER_PLAN_GAP,
                    detail: "durable replay provider was not injected",
                })
            },
            |_| Ok(()),
        )
    }
}

fn validate_grant(
    grant: &CapabilityGrant,
    hello: &WorkerHello,
    process: &ProcessRequest,
) -> Result<(), WorkerError> {
    grant
        .authority()
        .validate()
        .map_err(|_| WorkerError::AdmissionMismatch("authority"))?;
    for (field, value) in [
        ("admission_id", grant.admission_id()),
        ("admission_revision", grant.admission_revision()),
        ("stream_id", grant.stream_id()),
        ("producer_id", grant.producer_id()),
        ("route_ref", grant.route_ref()),
        ("artifact_manifest_digest", grant.artifact_manifest_digest()),
        ("process_request_digest", grant.process_request_digest()),
    ] {
        if value.trim().is_empty() {
            return Err(WorkerError::AdmissionMismatch(field));
        }
    }
    if grant.observed_at_unix_ms() >= grant.expires_at_unix_ms()
        || grant.observed_at_unix_ms() > hello.deadline_unix_ms
    {
        return Err(WorkerError::StaleLease);
    }
    if grant.route_ref() != hello.route_ref {
        return Err(WorkerError::AdmissionMismatch("route_ref"));
    }
    if grant.artifact_manifest_digest() != hello.artifact_manifest_digest {
        return Err(WorkerError::AdmissionMismatch("artifact_manifest_digest"));
    }
    if grant.worker_generation() != hello.worker_generation
        || grant.process_generation() != process.generation()
        || grant.worker_generation() != process.generation().get()
    {
        return Err(WorkerError::AdmissionMismatch("generation"));
    }
    if grant.authority().epoch != hello.authority_epoch {
        return Err(WorkerError::AdmissionMismatch("authority_epoch"));
    }
    if grant.authority().state_fence != hello.state_fence
        || !grant.process_fence().matches(process.fence())
    {
        return Err(WorkerError::AdmissionMismatch("state_fence"));
    }
    if grant.operation_id() != process.operation_id()
        || grant.process_tree_id() != process.process_tree_id()
        || grant.process_request_digest() != process.invocation_digest()
        || grant.resource_limits() != process.resource_limits()
    {
        return Err(WorkerError::AdmissionMismatch("process_request"));
    }
    if grant.capabilities().is_empty()
        || !grant
            .capabilities()
            .is_subset(&hello.requested_capabilities)
    {
        return Err(WorkerError::AdmissionMismatch("capabilities"));
    }
    Ok(())
}

fn validate_start_receipt(
    receipt: &ProcessStartReceipt,
    process: &ProcessBindingSnapshot,
) -> Result<(), WorkerError> {
    if receipt.operation_id() != process.operation_id() {
        return Err(WorkerError::ProcessReceiptMismatch("operation_id"));
    }
    if receipt.request_digest() != process.request_digest() {
        return Err(WorkerError::ProcessReceiptMismatch("request_digest"));
    }
    if receipt.accepted_generation() != process.generation() {
        return Err(WorkerError::ProcessReceiptMismatch("generation"));
    }
    if !matches!(
        receipt.lifecycle(),
        ProcessLifecycle::Starting | ProcessLifecycle::Running
    ) {
        return Err(WorkerError::ProcessReceiptMismatch("lifecycle"));
    }
    Ok(())
}

fn validate_start_proof(
    receipt: &ProcessStartReceipt,
    observed: &[ProcessEvidence],
    inspected: &ProcessExecutionView,
    process: &ProcessBindingSnapshot,
) -> Result<(), WorkerError> {
    if receipt.lifecycle() != ProcessLifecycle::Running {
        return Err(WorkerError::ProcessReceiptMismatch("receipt_not_running"));
    }
    for evidence in observed {
        validate_process_evidence(evidence, process)?;
    }
    let latest = observed.last().ok_or(WorkerError::ProcessReceiptMismatch(
        "missing_process_evidence",
    ))?;
    if latest.view() != inspected {
        return Err(WorkerError::ProcessReceiptMismatch("inspect_evidence_view"));
    }
    validate_process_evidence_binding(
        inspected.operation_id(),
        inspected.request_digest(),
        inspected.fence(),
        process,
    )?;
    if inspected.lifecycle() != ProcessLifecycle::Running || !inspected.health().ready() {
        return Err(WorkerError::ProcessReceiptMismatch("readiness_lifecycle"));
    }
    let identity = inspected
        .identity()
        .ok_or(WorkerError::ProcessReceiptMismatch("process_identity"))?;
    if identity.process_tree_id() != process.process_tree_id()
        || identity.generation() != process.generation()
        || identity.executable_sha256() != process.executable_sha256()
    {
        return Err(WorkerError::ProcessReceiptMismatch("process_identity"));
    }
    Ok(())
}

fn validate_recovered_process_view(
    view: &ProcessExecutionView,
    process: &ProcessBindingSnapshot,
) -> Result<(), WorkerError> {
    if view.lifecycle() == ProcessLifecycle::Running {
        if !view.health().ready() {
            return Err(WorkerError::ProcessReceiptMismatch("recovery_readiness"));
        }
        let identity = view
            .identity()
            .ok_or(WorkerError::ProcessReceiptMismatch("recovery_identity"))?;
        if identity.process_tree_id() != process.process_tree_id()
            || identity.generation() != process.generation()
            || identity.executable_sha256() != process.executable_sha256()
        {
            return Err(WorkerError::ProcessReceiptMismatch("recovery_identity"));
        }
    }
    Ok(())
}

fn validate_effect_grant(
    effect: &EffectAdmissionGrant,
    grant: &CapabilityGrant,
    proposal: &ProposedEffect,
) -> Result<(), WorkerError> {
    if effect.revoked() {
        return Err(WorkerError::Revoked(effect.admission_revision().to_owned()));
    }
    if effect.authorized_effect().proposal != *proposal {
        return Err(WorkerError::EffectMismatch("proposal"));
    }
    effect
        .authorized_effect()
        .validate(grant.authority())
        .map_err(|_| WorkerError::EffectMismatch("authority"))?;
    if effect.lease() != &grant.authority().lease {
        return Err(WorkerError::StaleLease);
    }
    if effect.state_fence() != &grant.authority().state_fence {
        return Err(WorkerError::StaleFence);
    }
    if effect.admission_revision() != grant.admission_revision()
        || effect.revocation_revision() != grant.revocation_revision()
    {
        return Err(WorkerError::StaleRevision);
    }
    if effect.observed_at_unix_ms() >= effect.expires_at_unix_ms()
        || effect.expires_at_unix_ms() > grant.expires_at_unix_ms()
    {
        return Err(WorkerError::StaleLease);
    }
    Ok(())
}

fn validate_checkpoint_receipt(
    receipt: &CheckpointReceiptFacts,
    request: &DurableCheckpointRequest,
) -> Result<(), WorkerError> {
    if receipt.receipt_id().trim().is_empty() || receipt.durable_at_unix_ms() == 0 {
        return Err(WorkerError::CheckpointReceiptMismatch("durable_identity"));
    }
    if receipt.checkpoint_ref() != request.checkpoint_ref()
        || receipt.request_id() != request.request_id()
        || receipt.stream_id() != request.stream_id()
        || receipt.producer_generation() != request.producer_generation()
        || receipt.authority_epoch() != request.authority_epoch()
        || receipt.state_fence() != request.state_fence()
        || receipt.admission_revision() != request.admission_revision()
        || receipt.operation_id() != request.operation_id()
        || receipt.process_request_digest() != request.process_request_digest()
    {
        return Err(WorkerError::CheckpointReceiptMismatch("request_binding"));
    }
    Ok(())
}

fn validate_ack(receipt: &EventAckReceipt, grant: &CapabilityGrant) -> Result<(), WorkerError> {
    if receipt.stream_id != grant.stream_id()
        || receipt.producer_generation != grant.worker_generation()
        || receipt.event_id.trim().is_empty()
        || receipt.sequence == 0
        || receipt.acknowledged_at_unix_ms == 0
    {
        return Err(WorkerError::ReplayContract("ack_identity"));
    }
    if receipt.authority_epoch != grant.authority().epoch {
        return Err(WorkerError::StaleEpoch);
    }
    if receipt.state_fence != grant.authority().state_fence {
        return Err(WorkerError::StaleFence);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_event(
    event: &WorkerEventEnvelope,
    grant: &CapabilityGrant,
    request_id: &str,
    payload_type: &str,
    payload: &WorkerEventPayload,
    disposition: &ReceiptDisposition,
    trace_context: &BTreeMap<String, String>,
    causal_predecessor_refs: &[String],
    delivery_class: DeliveryClass,
    ack_required: bool,
) -> Result<(), WorkerError> {
    if event.stream_id != grant.stream_id()
        || event.producer_id != grant.producer_id()
        || event.producer_generation != grant.worker_generation()
        || event.authority_epoch != grant.authority().epoch
        || event.state_fence != grant.authority().state_fence
        || event.event_id.trim().is_empty()
        || event.sequence == 0
        || event.request_id != request_id
        || event.payload_type != payload_type
        || event.payload != *payload
        || event.disposition != *disposition
        || event.trace_context != *trace_context
        || event.causal_predecessor_refs != causal_predecessor_refs
        || event.delivery_class != delivery_class
        || event.ack_required != ack_required
    {
        return Err(WorkerError::ReplayContract("event_binding"));
    }
    Ok(())
}

fn validate_replayed_events(
    events: &[WorkerEventEnvelope],
    grant: &CapabilityGrant,
    after_sequence: Option<u64>,
) -> Result<(), WorkerError> {
    let mut prior_sequence = after_sequence.unwrap_or(0);
    let mut prior_event_id: Option<&str> = None;
    let mut event_ids = std::collections::BTreeSet::new();
    for event in events {
        if event.stream_id != grant.stream_id()
            || event.producer_id != grant.producer_id()
            || event.producer_generation != grant.worker_generation()
            || event.authority_epoch != grant.authority().epoch
            || event.state_fence != grant.authority().state_fence
            || event.event_id.trim().is_empty()
            || event.sequence == 0
            || event.request_id.trim().is_empty()
            || event.payload_type.trim().is_empty()
            || event.sequence <= prior_sequence
            || (after_sequence.is_some() && event.sequence != prior_sequence.saturating_add(1))
            || !event_ids.insert(event.event_id.as_str())
            || event
                .causal_predecessor_refs
                .iter()
                .any(|reference| reference.trim().is_empty() || reference == &event.event_id)
            || (event.sequence > 1 && event.causal_predecessor_refs.is_empty())
            || prior_event_id.is_some_and(|prior| {
                !event
                    .causal_predecessor_refs
                    .iter()
                    .any(|reference| reference == prior)
            })
            || !delivery_ack_is_valid(event.delivery_class, event.ack_required)
        {
            return Err(WorkerError::ReplayContract("replay_binding"));
        }
        prior_sequence = event.sequence;
        prior_event_id = Some(&event.event_id);
    }
    Ok(())
}

fn validate_request_replay(
    events: &[WorkerEventEnvelope],
    request_id: &str,
) -> Result<(), WorkerError> {
    if events.iter().any(|event| event.request_id != request_id) {
        return Err(WorkerError::ReplayContract("request_replay_binding"));
    }
    Ok(())
}

const fn delivery_ack_is_valid(delivery_class: DeliveryClass, ack_required: bool) -> bool {
    match delivery_class {
        DeliveryClass::DurableControl | DeliveryClass::DurableObservation => ack_required,
        DeliveryClass::BestEffortTelemetry => !ack_required,
    }
}

fn validate_process_evidence(
    evidence: &ProcessEvidence,
    process: &ProcessBindingSnapshot,
) -> Result<(), WorkerError> {
    validate_process_evidence_binding(
        evidence.operation_id(),
        evidence.request_digest(),
        evidence.view().fence(),
        process,
    )
}

fn validate_process_evidence_binding(
    operation_id: &OperationId,
    request_digest: &str,
    fence: &FencingToken,
    process: &ProcessBindingSnapshot,
) -> Result<(), WorkerError> {
    if operation_id != process.operation_id()
        || request_digest != process.request_digest()
        || !fence.matches(process.fence())
    {
        return Err(WorkerError::ProcessReceiptMismatch("process_evidence"));
    }
    Ok(())
}

fn worker_lifecycle_from_process(lifecycle: ProcessLifecycle) -> WorkerLifecycle {
    match lifecycle {
        ProcessLifecycle::Created | ProcessLifecycle::Starting => WorkerLifecycle::Starting,
        ProcessLifecycle::Running => WorkerLifecycle::Ready,
        ProcessLifecycle::Cancelling => WorkerLifecycle::Cancelling,
        ProcessLifecycle::Exited | ProcessLifecycle::Quarantined | ProcessLifecycle::Failed => {
            WorkerLifecycle::Stopped
        }
        ProcessLifecycle::UnknownOutcome => WorkerLifecycle::UnknownOutcome,
        ProcessLifecycle::Reconciled => WorkerLifecycle::Reconciled,
    }
}

fn provider_error(error: ProviderFailure) -> WorkerError {
    let ProviderFailure { provider, detail } = error;
    WorkerError::Provider(format!("provider {provider} failed: {detail}"))
}

fn map_process_error(error: ProcessExecutionError) -> WorkerError {
    match error {
        ProcessExecutionError::Unavailable(_) => WorkerError::PlanGap {
            code: PROCESS_PROVIDER_PLAN_GAP,
            detail: "P-03 ProcessExecutor is unavailable",
        },
        ProcessExecutionError::UnknownOutcome => WorkerError::UnknownOutcome,
        other => WorkerError::Process(other.to_string()),
    }
}

fn map_start_inspect_error(error: ProcessExecutionError) -> WorkerError {
    match error {
        ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome => {
            WorkerError::UnknownOutcome
        }
        other => map_process_error(other),
    }
}

#[cfg(test)]
mod tests;
