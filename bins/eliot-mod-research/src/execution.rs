//! Shared-executor research provider execution.
//!
//! A [`ProviderBridge`] runs one admitted operation through the shared
//! governed Windows [`ProcessExecutor`] contour: the request-minting port
//! (owned by the runtime composition root, which holds Kernel-issued process
//! authority) binds the admitted operation to exactly one [`ProcessRequest`],
//! and the bridge validates that binding before the executor is contacted.
//! The bridge mints no intent, no permit, and no argv; it never reads ambient
//! environment, task text, or stdin, and it never spawns a child directly.
//!
//! Execution is synchronous over the executor's async contour via the
//! established P-04 `block_on` precedent (P-04 futures complete without a
//! reactor). Every refusal below happens before `start` unless the error says
//! otherwise.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use eliot_process::{
    CancellationReceipt, EnvironmentInheritance, ExitDisposition, OperationId, ProcessEvidence,
    ProcessEvidenceSink, ProcessExecutor, ProcessLifecycle, ProcessRequest,
};
use eliot_process_executor::WindowsProcessExecutor;
use eliot_research_exchange_api::ResearchQueryRequest;
use thiserror::Error;

use crate::BridgeError;
use crate::admission::ProviderAdmission;
use crate::admitted_disclosure_wire;
use crate::evidence::{CancellationEvidence, RawProviderEvidence, exit_code_of, sha256_hex};
use crate::protocol::{
    RESEARCH_PROVIDER_WIRE_VERSION, ResultFrame, SubmitAck, SubmitEnvelope, scan_result_frame,
};
use crate::{StartAttemptContext, SubmissionRecord};

/// Compile-time proof that the bound executor implements the shared
/// [`ProcessExecutor`] contract: if P-04 ever stops implementing P-03, the
/// binding fails to build instead of silently targeting a fork.
const _: fn() = || {
    fn requires_shared_contract<E: ProcessExecutor>() {}
    requires_shared_contract::<WindowsProcessExecutor>();
};

/// Default bound for the terminal-lifecycle wait (matches the established
/// executor test precedent of a 30-second horizon with 25 ms polls).
pub const BOUND_RUN_DEADLINE: Duration = Duration::from_secs(30);
/// Poll interval for the terminal-lifecycle wait.
const BOUND_RUN_POLL: Duration = Duration::from_millis(25);

/// Typed failure of the request-minting port. The port is the only party that
/// may mint [`ProcessRequest`] values; its failures carry no payload, and the
/// bridge maps them to the typed source-unavailable gap (degradation, never a
/// fabricated result).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RequestPortError {
    /// No Kernel-issued process authority is available in this scope.
    #[error("no Kernel-issued process authority is available in this scope")]
    NoAuthority,
    /// The port refused to mint a request for this operation.
    #[error("the request port refused the binding")]
    Refused,
}

/// Composition-root seam minting authorized [`ProcessRequest`] values.
///
/// Dispatch permits are Kernel-issued authority, so the bridge never mints
/// requests itself. The first element of `submit_binding` is the exact
/// canonical request digest the minted request must execute for; the second is
/// the digest of the bounded submit projection that the minted request's argv
/// must carry, so the provider can verify exactly which request it answers.
/// That projection now covers the eight admitted identities (artifact/config/
/// protocol digest, Module/Capability Registry evidence, process generation,
/// Authority Epoch, State Fence, privacy/data class, budget/deadline and
/// cancellation identity), so the digest is a commitment to all of them rather
/// than to correlation alone. The bridge re-validates the returned request
/// against both before the executor is contacted, and re-proves the
/// projection's own content against the admission.
pub trait ResearchRequestPort: Send + Sync {
    /// Binds one admitted operation to exactly one authorized process request.
    ///
    /// # Errors
    ///
    /// Returns [`RequestPortError`] when no authority is available or the
    /// port refuses the binding.
    fn bind(
        &self,
        admission: &ProviderAdmission,
        submit_binding: &(String, String),
    ) -> Result<ProcessRequest, RequestPortError>;
}

/// Terminal provider outcome in provider-local terms. This is acquisition
/// evidence, never a semantic verdict and never task finish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderOutcome {
    /// Provider completed and the submit ack decoded.
    Completed,
    /// Provider completed with a non-zero code or a crash-class disposition.
    Crashed,
    /// The terminal wait exceeded the deadline.
    TimedOut,
    /// Cancellation stopped the tree.
    Cancelled,
    /// The external outcome cannot be classified yet; reconciliation by the
    /// stable operation identity is required before any retry.
    Unknown,
}

/// Whether the executor's captured provider streams were read back, and what
/// that readback produced.
///
/// The three states are distinct and never collapse into one another. Both
/// `NotAttempted` and `Unobserved` carry no bytes at all, so no consumer can
/// read the digest or the byte count of a genuinely empty stream out of them:
/// a stream that was never asked for and a stream whose readback never
/// answered are both unknown, and only `Observed` reports the provider's own
/// bytes. Within `Observed` the record keeps the empty/partial/complete
/// distinction on its own terms, so an observed empty stream and an observed
/// partial stream stay different states there as well.
#[derive(Clone, Debug)]
pub enum EvidenceObservation {
    /// Stream readback was never attempted on this path.
    NotAttempted,
    /// Stream readback was attempted and the executor did not answer, so what
    /// the provider wrote is unknown rather than empty.
    Unobserved,
    /// The executor's captured streams were read back successfully.
    Observed(Box<RawProviderEvidence>),
}

impl EvidenceObservation {
    /// Returns the materialized evidence, when the readback answered.
    #[must_use]
    pub fn observed(&self) -> Option<&RawProviderEvidence> {
        match self {
            Self::Observed(evidence) => Some(evidence),
            Self::NotAttempted | Self::Unobserved => None,
        }
    }
}

/// One bounded follow-up action a deadline overrun had to attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Obligation {
    /// Stopping the operation's process tree.
    Cancellation,
    /// Reading the operation's captured streams back as evidence.
    StreamReadback,
}

/// What the deadline arm's cancellation attempt actually produced.
///
/// The receipt is the only proof a cancellation was attempted and what it
/// achieved, so it is retained whenever the executor answered. An
/// unanswered cancellation is its own state: it is not a clean stop, and it
/// never becomes the same thing as never having tried.
#[derive(Clone, Debug)]
pub enum CancellationOutcome {
    /// No cancellation was attempted on this path.
    NotAttempted,
    /// A cancellation was issued and the executor returned a receipt.
    Confirmed(Box<CancellationEvidence>),
    /// A cancellation was issued and the executor did not answer, so whether it
    /// took effect is unknown.
    Unresolved,
}

impl CancellationOutcome {
    /// Returns the retained receipt, when the cancellation was confirmed.
    #[must_use]
    pub fn receipt(&self) -> Option<&CancellationEvidence> {
        match self {
            Self::Confirmed(receipt) => Some(receipt),
            Self::NotAttempted | Self::Unresolved => None,
        }
    }
}

/// A bounded follow-up obligation the primary failure could not discharge.
///
/// This is a secondary obligation attached to the one primary cause, never a
/// second terminal event. The refusal is retained as its own typed
/// [`BridgeError`] rather than folded into the primary cause's reason text, so
/// nothing is collapsed into prose and no provider output reaches the error
/// message. A deadline overrun makes at most two such attempts, so this list
/// is bounded by construction.
#[derive(Debug)]
pub struct UndischargedObligation {
    /// Which follow-up obligation was attempted.
    pub obligation: Obligation,
    /// The typed refusal that attempt produced, retained verbatim.
    pub refusal: BridgeError,
}

/// One executed provider attempt: the stable job identity, the typed outcome,
/// the immutable raw evidence, the provider-local job reference, the
/// cancellation receipt when one was actually issued, and the terminal result
/// frame when the provider emitted one.
#[derive(Clone, Debug)]
pub struct ProviderExecution {
    /// Stable admitted operation identity (the only identity the exchange
    /// keys on).
    pub job_id: String,
    /// Typed terminal outcome.
    pub outcome: ProviderOutcome,
    /// Immutable raw evidence (stdout/stderr/exit/lineage digests).
    pub evidence: RawProviderEvidence,
    /// Provider-local job reference (correlation only, never identity).
    pub provider_job_ref: String,
    /// Cancellation receipt, retained when cancellation was actually issued.
    pub cancellation: Option<CancellationEvidence>,
    /// Terminal result frame when present in provider output.
    pub result_frame: Option<ResultFrame>,
    /// Canonical submit wire bytes retained as the exact reconciliation
    /// record.
    pub wire_bytes: Vec<u8>,
    /// Bounded submit-binding digest projected into the admitted argv.
    pub submit_binding_sha256: String,
}

/// One started operation with its sealed bindings: the stable operation
/// identity, the invocation digest every observation must preserve, the
/// canonical submit wire bytes, and the delivered submit-binding digest.
struct BoundOperation {
    operation: OperationId,
    digest: String,
    wire_bytes: Vec<u8>,
    submit_binding_sha256: String,
}

/// Stateless shared-executor runner for admitted research operations.
///
/// The runner stores the executor handle, the request-minting port, the
/// evidence sink, and the terminal-wait deadline. It owns no admission and no
/// per-operation state: one bounded operation's lifecycle lives with the
/// admitted bridge in `lib.rs`, which is the only caller of
/// [`ProviderBridge::execute`].
pub struct ProviderBridge {
    executor: Arc<WindowsProcessExecutor>,
    port: Arc<dyn ResearchRequestPort>,
    sink: Arc<dyn ProcessEvidenceSink>,
    deadline: Duration,
    bound_identity: Mutex<Option<OperationId>>,
    submission: Mutex<Option<SubmissionRecord>>,
}

impl ProviderBridge {
    /// Binds the runner to a shared executor, a request-minting port, and an
    /// evidence sink. Starts nothing; grants no execution.
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
            bound_identity: Mutex::new(None),
            submission: Mutex::new(None),
        }
    }

    /// Returns the exact submit reconciliation record after a verified start
    /// receipt passes its identity checks.
    ///
    /// A failed start handoff carries this record on its typed error and the
    /// existing submitted-state owner rather than installing it before the
    /// executor responds.
    pub fn last_submission(&self) -> Option<crate::SubmissionRecord> {
        self.submission
            .lock()
            .ok()
            .and_then(|record| record.clone())
    }

    /// Returns the stable identity of the operation this runner bound after a
    /// verified start receipt.
    ///
    pub fn last_bound_operation(&self) -> Option<String> {
        self.bound_identity.lock().ok().and_then(|operation| {
            operation
                .as_ref()
                .map(OperationId::as_str)
                .map(str::to_owned)
        })
    }

    /// Overrides the terminal-lifecycle wait bound.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Returns the bound shared executor.
    #[must_use]
    pub fn executor(&self) -> &Arc<WindowsProcessExecutor> {
        &self.executor
    }

    /// Executes one admitted request through the shared governed contour.
    ///
    /// Order (all fail-closed): request/admission binding, submit-binding
    /// projection, port minting, minted-request re-validation (artifact,
    /// operation, generation, epoch, no ambient environment inheritance,
    /// delivered submit binding, and the delivered binding's own admitted
    /// identities re-proved against the admission), executor start with receipt
    /// checks, terminal wait with deadline, stream readback with immutable
    /// evidence materialization, typed ack decode. A provider terminal state
    /// that cannot be classified returns [`ProviderOutcome::Unknown`] with the
    /// evidence preserved, and must be reconciled by operation identity before
    /// any retry.
    pub fn execute(
        &self,
        admission: &ProviderAdmission,
        request: &ResearchQueryRequest,
    ) -> Result<ProviderExecution, BridgeError> {
        let (request_sha256, submit_binding, submit_binding_sha256) =
            build_submit_binding_digests(admission, request)?;
        let process_request = self
            .port
            .bind(admission, &(request_sha256, submit_binding_sha256.clone()))
            .map_err(|_| BridgeError::ProviderUnavailable)?;
        let bound = self.bind_operation(
            admission,
            &submit_binding,
            &submit_binding_sha256,
            process_request,
        )?;
        let view = self.await_terminal(&bound, self.admitted_wait_bound(admission))?;
        self.finish_terminal(bound, &view)
    }

    /// Resolves the terminal-lifecycle wait bound for one admitted operation.
    ///
    /// The wait used to be [`BOUND_RUN_DEADLINE`] alone, and
    /// [`ProviderBridge::with_deadline`] was the only way to change it — a
    /// builder with no production caller, so every real run waited a fixed
    /// thirty seconds whatever the Kernel admitted. The admitted deadline was
    /// compared and receipted but governed nothing this process actually
    /// enforced, which is a carried value, not a bound one.
    ///
    /// The bound is now the **lesser** of the two, so it is a strict tightening
    /// of the existing horizon rather than a replacement of it: a run can never
    /// wait past the ceiling the Kernel admitted, and it can never wait longer
    /// than it did before. A deadline already in the past leaves no remaining
    /// budget at all, which is reported as zero rather than extended, so an
    /// expired ceiling ends the wait immediately instead of being ignored.
    fn admitted_wait_bound(&self, admission: &ProviderAdmission) -> Duration {
        let remaining = crate::dispatch_authority::remaining_admitted_ms(
            admission,
            crate::dispatch_authority::unix_ms(),
        );
        Duration::from_millis(remaining).min(self.deadline)
    }

    /// Re-validates the minted binding, seals the canonical submit envelope,
    /// and starts the operation with receipt checks. Everything here happens
    /// before any provider output exists.
    fn bind_operation(
        &self,
        admission: &ProviderAdmission,
        submit_binding: &crate::protocol::SubmitBinding,
        submit_binding_sha256: &str,
        process_request: ProcessRequest,
    ) -> Result<BoundOperation, BridgeError> {
        check_minted_request(
            admission,
            &process_request,
            submit_binding,
            submit_binding_sha256,
        )?;
        let operation = process_request.operation_id().clone();
        let digest = process_request.invocation_digest().to_owned();
        let generation = process_request.generation();
        // The envelope is the delivered binding plus the sealed process-request
        // digest, so the retained reconciliation record keeps every admitted
        // identity the provider was bound to instead of only its correlation.
        let envelope = SubmitEnvelope::from_binding(submit_binding, &digest);
        // These three refusals happen before the executor is contacted, so no
        // provider output exists to retain: `NotAttempted` says exactly that,
        // and is deliberately not the digest of an empty stream.
        let wire_bytes = envelope
            .encode()
            .map_err(|refusal| BridgeError::ProtocolViolation {
                reason: refusal.reason(),
                evidence: None,
                disposition: None,
            })?;
        // Fail-closed serializer check: the retained reconciliation record must
        // decode back to the same operation, and its delivered projection must
        // be the exact binding the port put in argv. Because the projection now
        // carries the full admitted-identity block, comparing that one digest
        // re-proves every bound identity survived serialization — a stripped or
        // altered envelope cannot reproduce the delivered digest.
        let round_trip = SubmitEnvelope::decode(&wire_bytes).map_err(|refusal| {
            BridgeError::ProtocolViolation {
                reason: refusal.reason(),
                evidence: None,
                disposition: None,
            }
        })?;
        if round_trip.operation_id != envelope.operation_id
            || round_trip.invocation_digest != envelope.invocation_digest
            || round_trip.request_sha256 != envelope.request_sha256
            || round_trip.binding().digest().ok().as_deref() != Some(submit_binding_sha256)
            || round_trip.binding() != *submit_binding
        {
            return Err(BridgeError::ProtocolViolation {
                reason: "submit envelope failed its round-trip binding check",
                evidence: None,
                disposition: None,
            });
        }
        // Preserve the sealed submit and ProcessExecutor identity in the
        // bounded start result. Runner-wide bound fields are installed only
        // after the executor answers with a receipt that preserves this exact
        // request.
        let attempt = StartAttemptContext {
            operation_id: operation.clone(),
            invocation_digest: digest.clone(),
            process_generation: generation.get(),
            submission: SubmissionRecord {
                submit_binding_sha256: submit_binding_sha256.to_owned(),
                envelope_sha256: sha256_hex(&wire_bytes),
                envelope_bytes: wire_bytes.clone(),
            },
        };
        let receipt = block_on(self.executor.start(process_request, self.sink.clone())).map_err(
            |source| BridgeError::StartFailed {
                context: Box::new(attempt.clone()),
                source: Box::new(source),
            },
        )?;
        if receipt.operation_id() != &operation
            || receipt.request_digest() != digest
            || receipt.accepted_generation() != generation
        {
            // The operation may already exist despite a missing or mismatched
            // receipt. The same context identifies it for reconciliation; it
            // does not authorize a fresh start.
            return Err(BridgeError::StartReceiptMismatch {
                context: Box::new(attempt),
            });
        }
        let mut bound_identity =
            self.bound_identity
                .lock()
                .map_err(|_| BridgeError::StartBindingInstallFailed {
                    context: Box::new(attempt.clone()),
                    reason: "bound operation identity lock poisoned",
                })?;
        let mut submission =
            self.submission
                .lock()
                .map_err(|_| BridgeError::StartBindingInstallFailed {
                    context: Box::new(attempt.clone()),
                    reason: "submit reconciliation lock poisoned",
                })?;
        *bound_identity = Some(operation.clone());
        *submission = Some(attempt.submission.clone());
        Ok(BoundOperation {
            operation,
            digest,
            wire_bytes,
            submit_binding_sha256: submit_binding_sha256.to_owned(),
        })
    }

    /// Waits for the terminal lifecycle of one started operation, preserving
    /// the request binding on every observation. A deadline overrun attempts
    /// cancellation, retains the cancellation receipt, reads the executor's
    /// captured streams back so the provider's real stdout/stderr survive as
    /// evidence, and stays explicit: the outcome is unconfirmed and
    /// reconciliation by operation identity is required before any retry.
    ///
    /// `wait_bound` is the already-resolved admitted ceiling from
    /// [`ProviderBridge::admitted_wait_bound`]; it is passed in rather than
    /// read from `self` so this arm can only ever overrun by a value the
    /// admission actually carried.
    ///
    /// The deadline observation is captured FIRST, because it is the primary
    /// cause of this failure. Cancellation and stream readback are then two
    /// independent attempts whose typed outcomes are collected rather than
    /// propagated: `?` on either one would replace the timeout with a
    /// cancellation transport failure, or discard a cancellation receipt that
    /// had already been obtained. A secondary failure is therefore recorded as
    /// a bounded obligation on the same timeout, never as a different terminal
    /// event and never as the loss of what was already observed.
    fn await_terminal(
        &self,
        bound: &BoundOperation,
        wait_bound: Duration,
    ) -> Result<eliot_process::ProcessExecutionView, BridgeError> {
        let started = Instant::now();
        loop {
            let view = block_on(self.executor.inspect(bound.operation.clone()))
                .map_err(BridgeError::Process)?;
            if view.operation_id() != &bound.operation || view.request_digest() != bound.digest {
                return Err(BridgeError::EvidenceIncomplete {
                    reason: "executor observation does not preserve the bound request",
                });
            }
            if view.lifecycle().is_terminal() {
                return Ok(view);
            }
            if started.elapsed() >= wait_bound {
                // Cancellation and stream readback are independent: each is
                // attempted and each keeps its own typed outcome. Neither may
                // erase the deadline, and neither may erase a receipt the other
                // already obtained.
                let mut undischarged = Vec::new();
                let cancellation = match block_on(self.executor.cancel(bound.operation.clone())) {
                    Ok(receipt) => CancellationOutcome::Confirmed(Box::new(
                        CancellationEvidence::from_receipt(&receipt),
                    )),
                    Err(refusal) => {
                        // A cancellation that never answered is not a clean
                        // stop and not a proof of no effect. The timeout stays
                        // the primary cause and this is its recorded
                        // obligation.
                        undischarged.push(UndischargedObligation {
                            obligation: Obligation::Cancellation,
                            refusal: BridgeError::Process(refusal),
                        });
                        CancellationOutcome::Unresolved
                    }
                };
                let evidence = match self.timeout_evidence(bound, &view) {
                    Ok(evidence) => EvidenceObservation::Observed(Box::new(evidence)),
                    Err(refusal) => {
                        // The readback never answered, so the provider's
                        // streams are unknown. The cancellation receipt obtained
                        // above is retained with the timeout regardless, and the
                        // source gap is recorded as its own obligation rather
                        // than rendered as an empty capture.
                        undischarged.push(UndischargedObligation {
                            obligation: Obligation::StreamReadback,
                            refusal,
                        });
                        EvidenceObservation::Unobserved
                    }
                };
                return Err(BridgeError::TimedOut {
                    cancellation: Box::new(cancellation),
                    evidence: Box::new(evidence),
                    undischarged,
                });
            }
            std::thread::sleep(BOUND_RUN_POLL);
        }
    }

    /// Materializes the evidence a deadline overrun retains.
    ///
    /// The timeout arm never reaches `finish_terminal`, which is where the
    /// crate's only stream readback lives, so the executor's captured streams
    /// are read back here too. The provider's real stdout/stderr therefore
    /// survive a timeout instead of being replaced by
    /// `RawProviderEvidence::absent`, which has no digest or byte count and
    /// reports `NoHandle` even though the executor held a live drain. `stderr`
    /// is never discarded on the failure path.
    ///
    /// The exit and descendant fields are read from the last bounded
    /// observation this wait actually made and are never recomputed or
    /// invented: a wait that reached the deadline arm saw no terminal
    /// lifecycle, so those stay empty and explicit while the streams are the
    /// provider's own recorded bytes.
    fn timeout_evidence(
        &self,
        bound: &BoundOperation,
        view: &eliot_process::ProcessExecutionView,
    ) -> Result<RawProviderEvidence, BridgeError> {
        let (stdout, stderr) =
            self.executor
                .captured_output(&bound.operation)
                .map_err(|source| BridgeError::StreamReadbackFailed {
                    disposition: None,
                    source: Box::new(source),
                })?;
        let descendants_complete = view
            .descendants()
            .is_some_and(|descendants| descendants.complete() && descendants.tree_terminated());
        Ok(RawProviderEvidence::materialize_optional(
            bound.operation.as_str(),
            &bound.digest,
            view.exit(),
            &stdout,
            &stderr,
            descendants_complete,
        ))
    }

    /// Materializes immutable evidence from one terminal observation and
    /// decodes the typed provider ack. Unknown terminal states stay explicit
    /// with the evidence preserved; provider output never becomes identity.
    ///
    /// The evidence is materialized BEFORE any provider output is decoded, and
    /// every refusal from that decode carries it. A malformed acknowledgement or
    /// result frame is a statement about the wire, not about the process: the
    /// provider's stdout, stderr, exit and lineage were already observed, and
    /// discarding them would replace real custody with an absence record. The
    /// observed process disposition is likewise retained on the refusal, so a
    /// protocol violation and a crashed process remain two separately readable
    /// facts rather than one collapsed classification.
    fn finish_terminal(
        &self,
        bound: BoundOperation,
        view: &eliot_process::ProcessExecutionView,
    ) -> Result<ProviderExecution, BridgeError> {
        let exit = view.exit().ok_or(BridgeError::EvidenceIncomplete {
            reason: "executor reported a terminal lifecycle without an exit observation",
        })?;
        let descendants_complete = view
            .descendants()
            .is_some_and(|descendants| descendants.complete() && descendants.tree_terminated());
        // Preserve the process fact independently from a failure to read its
        // streams: evidence transport is not the process outcome.
        let outcome = classify_terminal(view.lifecycle(), exit, descendants_complete);
        let (stdout, stderr) =
            self.executor
                .captured_output(&bound.operation)
                .map_err(|source| BridgeError::StreamReadbackFailed {
                    disposition: Some(outcome),
                    source: Box::new(source),
                })?;
        let evidence = Box::new(RawProviderEvidence::materialize(
            bound.operation.as_str(),
            &bound.digest,
            exit,
            &stdout,
            &stderr,
            descendants_complete,
        ));
        // The physical disposition of the process is classified before the wire
        // is decoded, so it is available to every refusal below.
        if outcome == ProviderOutcome::Unknown {
            return Err(BridgeError::UnknownOutcome {
                evidence: Some(evidence.clone()),
            });
        }
        let ack_line = stdout
            .bytes
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default();
        // Both refusals below retain the exact evidence captured above and the
        // provider's observed process disposition. The `reason` stays a stable
        // code and the provider's bytes stay in the evidence record: a wire
        // violation must never concatenate provider output into error prose.
        let ack =
            SubmitAck::decode(ack_line).map_err(|refusal| BridgeError::ProtocolViolation {
                reason: refusal.reason(),
                evidence: Some(evidence.clone()),
                disposition: Some(outcome),
            })?;
        let result_frame =
            scan_result_frame(&stdout.bytes).map_err(|refusal| BridgeError::ProtocolViolation {
                reason: refusal.reason(),
                evidence: Some(evidence.clone()),
                disposition: Some(outcome),
            })?;
        Ok(ProviderExecution {
            job_id: bound.operation.as_str().to_owned(),
            outcome,
            evidence: *evidence,
            provider_job_ref: ack.provider_job_id,
            cancellation: None,
            result_frame,
            wire_bytes: bound.wire_bytes,
            submit_binding_sha256: bound.submit_binding_sha256,
        })
    }

    /// Observes the stored operation record for the bound operation identity.
    ///
    /// Used before a cancellation so ownership is proven at cancel time, not
    /// only at start time: a stored operation that no longer answers to the
    /// admitted identity or Authority Epoch is refused rather than cancelled.
    pub fn observe_bound_operation(
        &self,
    ) -> Result<eliot_process::ProcessExecutionView, BridgeError> {
        let operation = self
            .bound_identity
            .lock()
            .map_err(|_| BridgeError::EvidenceIncomplete {
                reason: "bound operation identity lock poisoned",
            })?
            .clone()
            .ok_or(BridgeError::NotAdmitted {
                reason: "no started operation is bound to this bridge",
            })?;
        self.observe_operation(&operation)
    }

    /// Observes an exact `ProcessExecutor` operation identity supplied by its
    /// admitted attempt owner. This also covers a start-response loss, where
    /// runner binding fields correctly remain uninstalled.
    pub fn observe_operation(
        &self,
        operation: &OperationId,
    ) -> Result<eliot_process::ProcessExecutionView, BridgeError> {
        block_on(self.executor.inspect(operation.clone())).map_err(BridgeError::Process)
    }

    /// Requests cancellation of the bound operation through the executor.
    pub fn cancel_operation(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<CancellationReceipt, BridgeError> {
        block_on(self.executor.cancel(operation.clone())).map_err(BridgeError::Process)
    }

    /// Reconciles the bound operation's unknown external result.
    pub fn reconcile_operation(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<ProcessEvidence, BridgeError> {
        block_on(self.executor.reconcile(operation.clone())).map_err(BridgeError::Process)
    }
}

/// Builds the bounded submit projection and the exact request digest for one
/// admitted operation.
///
/// Both the bridge and the request-minting port compute this from the same
/// admitted inputs, independently. The bridge then re-checks that the minted
/// argv carries the digest it computed itself, so a port that projected a
/// different binding is refused before the executor is contacted.
///
/// The projection carries the eight identities issue #24 requires the provider
/// to be bound to — exact artifact/config/protocol digest, Module/Capability
/// Registry evidence, process generation, Authority Epoch, State Fence,
/// privacy/data class, budget/deadline and cancellation identity. Every one is
/// read from a [`ProviderAdmission`] accessor; none is derived, defaulted or
/// widened here, and the assembled projection is immediately re-proved against
/// the same record by [`ProviderAdmission::validate_submit_binding`] before it
/// is returned, so this function cannot hand out a binding that merely *looks*
/// admitted. That self-check is what makes the digest comparison on the
/// mint-time side meaningful: both sides compare against a projection already
/// proven equal to the admission.
///
/// A coverage or absence claim must name its scope, revision, and the method
/// by which the denominator can be checked independently (A05.07). The frozen
/// inquiry's exact source-role portfolio / coverage denominator digest is bound
/// into the admission and re-checked here, so no admitted acquisition can run
/// against an undeclared denominator.
///
/// # Errors
///
/// Returns [`BridgeError::NotAdmitted`] when the request or the admission fails
/// validation, the coverage denominator digest is malformed, the two disagree on
/// a bound dimension, or the assembled projection does not re-prove against the
/// admission; and [`BridgeError::ProtocolViolation`] when the request or the
/// projection cannot be encoded.
pub fn build_submit_binding(
    admission: &ProviderAdmission,
    request: &ResearchQueryRequest,
) -> Result<(String, crate::protocol::SubmitBinding), BridgeError> {
    request.validate().map_err(|_| BridgeError::NotAdmitted {
        reason: "research request failed validation",
    })?;
    admission
        .validate_request(request)
        .map_err(|refusal| BridgeError::NotAdmitted {
            reason: refusal.reason(),
        })?;
    if !crate::is_lowercase_sha256(admission.denominator_digest())
        || !crate::is_lowercase_sha256(admission.inquiry_digest())
    {
        return Err(BridgeError::NotAdmitted {
            reason: "admitted inquiry or coverage denominator digest is malformed",
        });
    }
    let request_bytes =
        serde_json::to_vec(request).map_err(|_| BridgeError::ProtocolViolation {
            reason: "research request is not canonical wire JSON",
            evidence: None,
            disposition: None,
        })?;
    let request_sha256 = sha256_hex(&request_bytes);
    let binding = crate::protocol::SubmitBinding {
        wire_version: RESEARCH_PROVIDER_WIRE_VERSION,
        operation_id: admission.operation_id().as_str().to_owned(),
        exchange_id: request.exchange_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        protocol_revision: request.protocol_revision,
        required_schema: request.required_schema.clone(),
        request_sha256: request_sha256.clone(),
        executable_sha256: admission.bridge().executable_sha256().to_owned(),
        config_digest: admission.config_digest().to_owned(),
        protocol_digest: admission.protocol_digest().to_owned(),
        module_id: admission.module_id().to_owned(),
        module_generation_id: admission.module_generation_id().to_owned(),
        process_generation: admission.process_generation().get(),
        authority_epoch: admission.epoch().clone(),
        state_fence: admission.fence().clone(),
        disclosure: admitted_disclosure_wire(admission.disclosure()).to_owned(),
        budget_units: admission.budget_units(),
        deadline_ms: admission.deadline_ms(),
        cancellation_id: admission.cancellation_id().to_owned(),
    };
    // Fail-closed: the projection is proven against the record it was read from
    // before its digest is projected into the admitted argv. A binding whose
    // digest the provider is given must never be one this record does not own.
    admission
        .validate_submit_binding(&binding)
        .map_err(|refusal| BridgeError::NotAdmitted {
            reason: refusal.reason(),
        })?;
    Ok((request_sha256, binding))
}

/// Returns the exact request digest, the delivered submit binding, and that
/// binding's canonical digest for one admitted operation.
///
/// This runs before the process request exists, which is exactly why the
/// delivered projection is the envelope *minus* the process-request digest (see
/// `protocol`). The triple is the exact material the request-minting port
/// embeds and the bridge re-checks; the binding itself is returned so the
/// mint-time check can compare its **content** against the admission instead of
/// only its digest.
///
/// # Errors
///
/// Propagates every refusal from [`build_submit_binding`], plus
/// [`BridgeError::ProtocolViolation`] when the projection cannot be encoded.
pub fn build_submit_binding_digests(
    admission: &ProviderAdmission,
    request: &ResearchQueryRequest,
) -> Result<(String, crate::protocol::SubmitBinding, String), BridgeError> {
    let (request_sha256, binding) = build_submit_binding(admission, request)?;
    let binding_sha256 = binding
        .digest()
        .map_err(|refusal| BridgeError::ProtocolViolation {
            reason: refusal.reason(),
            evidence: None,
            disposition: None,
        })?;
    Ok((request_sha256, binding, binding_sha256))
}

/// Re-validates a port-minted request against the admission before the
/// executor is contacted: exact artifact identity, exact operation identity,
/// exact process generation, epoch agreement, structural validity, the exact
/// delivered submit binding in argv, and no ambient environment inheritance
/// (the child receives only explicit values, so credentials, proxy
/// configuration, and user resources cannot leak in).
///
/// The delivered submit binding is re-proved here by **content**, not only by
/// digest. The digest in argv proves the port projected the same bytes the
/// bridge computed; comparing the binding's own fields against the admission
/// proves those bytes are this operation's admitted identities — exact
/// artifact/config/protocol digest, Module/Capability Registry evidence,
/// process generation, Authority Epoch, State Fence, privacy/data class,
/// budget/deadline and cancellation identity. Without that second comparison a
/// binding that is self-consistent but foreign would satisfy the digest check
/// on its own, and the provider would be handed an identity nobody admitted.
fn check_minted_request(
    admission: &ProviderAdmission,
    request: &ProcessRequest,
    binding: &crate::protocol::SubmitBinding,
    submit_binding_sha256: &str,
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
    {
        return Err(BridgeError::NotAdmitted {
            reason: "minted process request disagrees on authority epoch",
        });
    }
    if request.environment().inheritance() != EnvironmentInheritance::None {
        return Err(BridgeError::NotAdmitted {
            reason: "minted process request does not restrict environment inheritance",
        });
    }
    if !carries_submit_binding(request, submit_binding_sha256) {
        return Err(BridgeError::NotAdmitted {
            reason: "minted process request does not carry the delivered submit binding",
        });
    }
    admission
        .validate_submit_binding(binding)
        .map_err(|refusal| BridgeError::NotAdmitted {
            reason: refusal.reason(),
        })?;
    Ok(())
}

/// Returns whether the admitted argv carries exactly the delivered submit
/// binding and the admitted operation identity.
///
/// The argv is inside the intent's sealed `effect_digest`, so a provider that
/// answers a different operation, or a binding that was tampered with after
/// admission, cannot reach the executor.
fn carries_submit_binding(request: &ProcessRequest, submit_binding_sha256: &str) -> bool {
    let argv = request.argv();
    let value_after = |selector: &str| {
        argv.windows(2)
            .find(|pair| pair[0] == selector)
            .map(|pair| pair[1].as_str())
    };
    value_after(crate::dispatch_authority::SUBMIT_BINDING_ARGV) == Some(submit_binding_sha256)
        && value_after(crate::dispatch_authority::OPERATION_ARGV)
            == Some(request.operation_id().as_str())
}

/// Classifies one terminal observation into a provider-local outcome.
/// Anything that is not a clean completed exit with proven tree closure stays
/// explicit: crash-class dispositions, a non-zero exit code, missing descendant
/// proof, and unknown lifecycles never decode as success.
fn classify_terminal(
    lifecycle: ProcessLifecycle,
    exit: &eliot_process::ExitStatus,
    descendants_complete: bool,
) -> ProviderOutcome {
    if lifecycle == ProcessLifecycle::UnknownOutcome {
        return ProviderOutcome::Unknown;
    }
    match exit.disposition() {
        ExitDisposition::Completed => {
            // A `Completed` disposition is a physical observation, not a
            // success verdict. The provider that asked for a clean exit and
            // returned a non-zero code crashed, so the numeric code is read
            // here and the outcome stays `Crashed` exactly as
            // `ProviderOutcome::Crashed` documents. The code is recovered from
            // the serialized exit observation because the typed contract
            // exposes only the coarse disposition.
            if exit_code_of(exit) != Some(0) {
                return ProviderOutcome::Crashed;
            }
            if descendants_complete {
                ProviderOutcome::Completed
            } else {
                ProviderOutcome::Unknown
            }
        }
        ExitDisposition::Cancelled => ProviderOutcome::Cancelled,
        ExitDisposition::Signalled | ExitDisposition::ResourceLimit => ProviderOutcome::Crashed,
        ExitDisposition::Unknown => ProviderOutcome::Unknown,
    }
}

/// Drives one executor future to completion on the calling thread.
///
/// Established precedent: the production `block_on_sink` drain path and the
/// `block_on` test driver in `eliot-process-executor` spin a noop waker with
/// `yield_now`. P-04 futures complete without a reactor; this performs no
/// sleeping, no retry, and no I/O of its own.
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

    use std::collections::BTreeMap;
    use std::num::NonZeroU64;
    use std::sync::Arc;

    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, EnvironmentInheritance,
        EnvironmentProjection, ExitDisposition, ExitStatus, FencingToken, Generation, ImageId,
        JobId, KernelDispatchKey, OperationId, PermitIssuance, ProcessIntent, ProcessTreeId,
        ResourceLimits, SessionId,
    };
    use eliot_research_exchange_api::DisclosureClass;

    use crate::support::{
        DIGEST_A, DIGEST_B, test_admission, test_epoch, test_identity, test_request,
    };

    use super::*;

    /// Authority port that must never be contacted: every test here fails
    /// before the executor is reached, so any call is a test failure.
    struct UnreachedPort;

    impl eliot_process_executor::DispatchValidationPort for UnreachedPort {
        fn validate_and_consume(
            &self,
            _request: ProcessRequest,
            _observed: eliot_process::SuspendedProcessIdentity,
        ) -> Result<eliot_process::ValidatedDispatch, eliot_process::ProcessExecutionError>
        {
            panic!("refusal tests must not reach the executor");
        }
    }

    /// Request port that must never be contacted: binding validation must
    /// refuse before minting is attempted.
    struct UnreachedBindPort;

    impl ResearchRequestPort for UnreachedBindPort {
        fn bind(
            &self,
            _admission: &ProviderAdmission,
            _submit_binding: &(String, String),
        ) -> Result<ProcessRequest, RequestPortError> {
            panic!("binding validation must refuse before the port is contacted");
        }
    }

    /// Evidence sink that accepts and drops everything.
    #[derive(Default)]
    struct DropSink;

    impl ProcessEvidenceSink for DropSink {
        fn record(
            &self,
            _evidence: eliot_process::ProcessEvidence,
        ) -> Result<(), eliot_process::EvidenceSinkError> {
            Ok(())
        }
    }

    /// Mints one structurally valid process request with test authority,
    /// following the P-04 test precedent. Field overrides let each refusal
    /// test present a valid request bound to the wrong operation.
    fn mint_request(
        exe: &str,
        digest: &str,
        operation: &str,
        generation: u64,
        epoch: &EpochId,
        inheritance: EnvironmentInheritance,
        nonce: &str,
    ) -> ProcessRequest {
        let generation = Generation::new(generation).expect("generation");
        let environment = match inheritance {
            EnvironmentInheritance::None => EnvironmentProjection::default(),
            EnvironmentInheritance::Allowlisted => EnvironmentProjection::new(
                BTreeMap::new(),
                Vec::new(),
                EnvironmentInheritance::Allowlisted,
            )
            .expect("environment"),
        };
        let intent = ProcessIntent::new(
            OperationId::new(operation).expect("operation"),
            ProcessTreeId::new("tree-24-test").expect("tree"),
            JobId::new("job-24-test").expect("job"),
            ImageId::new("image-24-test").expect("image"),
            SessionId::new("session-24-test").expect("session"),
            generation,
            exe,
            digest,
            vec!["--execute".to_owned()],
            std::env::temp_dir().to_string_lossy().into_owned(),
            environment,
            ResourceLimits::new(30_000, Some(10_000), Some(512_000_000), 4_096, 4_096, 4)
                .expect("limits"),
        )
        .expect("intent");
        let fence = FencingToken::new(epoch.clone(), generation, format!("fence-24-{nonce}"))
            .expect("fence");
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("auth-24-test").expect("authority"),
            KernelDispatchKey::from_secret_bytes([0x5a; 32]).expect("key"),
        );
        let permit = authority
            .issue(
                &intent,
                PermitIssuance::new(
                    ActionLeaseRef::new(format!("lease-24-{nonce}")).expect("lease"),
                    fence,
                    BTreeMap::new(),
                    100,
                    10_000,
                    format!("nonce-24-{nonce}"),
                )
                .expect("issuance"),
            )
            .expect("permit");
        ProcessRequest::new(intent, permit).expect("request")
    }

    /// Request port minting one fixed valid request per test.
    struct MintingPort {
        exe: String,
        digest: String,
        operation: String,
        generation: u64,
        epoch: EpochId,
        inheritance: EnvironmentInheritance,
        nonce: String,
    }

    impl ResearchRequestPort for MintingPort {
        fn bind(
            &self,
            _admission: &ProviderAdmission,
            _submit_binding: &(String, String),
        ) -> Result<ProcessRequest, RequestPortError> {
            Ok(mint_request(
                &self.exe,
                &self.digest,
                &self.operation,
                self.generation,
                &self.epoch,
                self.inheritance,
                &self.nonce,
            ))
        }
    }

    /// Request port that always refuses: no authority is available in scope.
    struct RefusingPort;

    impl ResearchRequestPort for RefusingPort {
        fn bind(
            &self,
            _admission: &ProviderAdmission,
            _submit_binding: &(String, String),
        ) -> Result<ProcessRequest, RequestPortError> {
            Err(RequestPortError::NoAuthority)
        }
    }

    fn runner_with(port: Arc<dyn ResearchRequestPort>) -> ProviderBridge {
        let executor = Arc::new(WindowsProcessExecutor::new(Arc::new(UnreachedPort)));
        ProviderBridge::new(executor, port, Arc::new(DropSink))
    }

    fn matching_port(nonce: &str) -> MintingPort {
        MintingPort {
            exe: test_identity().executable().to_owned(),
            digest: DIGEST_A.to_owned(),
            operation: "op-24-slice-a".to_owned(),
            generation: 3,
            epoch: test_epoch(),
            inheritance: EnvironmentInheritance::None,
            nonce: nonce.to_owned(),
        }
    }

    #[test]
    fn request_admission_mismatch_fails_before_port_contact() {
        let runner = runner_with(Arc::new(UnreachedBindPort));
        let mut widened = test_request();
        widened.disclosure = DisclosureClass::Public;
        assert!(
            matches!(
                runner.execute(&test_admission(), &widened),
                Err(BridgeError::NotAdmitted { .. })
            ),
            "privacy widening must be refused before the port is contacted"
        );
    }

    #[test]
    fn refusing_port_maps_to_source_unavailable() {
        let runner = runner_with(Arc::new(RefusingPort));
        assert!(
            matches!(
                runner.execute(&test_admission(), &test_request()),
                Err(BridgeError::ProviderUnavailable)
            ),
            "absent process authority must degrade to the typed gap"
        );
    }

    #[test]
    fn minted_unapproved_artifact_is_refused_before_start() {
        let runner = runner_with(Arc::new(MintingPort {
            exe: "C:\\evil\\tool.exe".to_owned(),
            digest: DIGEST_B.to_owned(),
            ..matching_port("artifact")
        }));
        assert!(
            matches!(
                runner.execute(&test_admission(), &test_request()),
                Err(BridgeError::NotAdmitted { .. })
            ),
            "environment-selected executable must be refused before start"
        );
    }

    #[test]
    fn minted_foreign_operation_is_refused_before_start() {
        let runner = runner_with(Arc::new(MintingPort {
            operation: "op-foreign".to_owned(),
            ..matching_port("operation")
        }));
        assert!(
            matches!(
                runner.execute(&test_admission(), &test_request()),
                Err(BridgeError::NotAdmitted { .. })
            ),
            "a request bound to a foreign operation must be refused before start"
        );
    }

    #[test]
    fn minted_stale_generation_is_refused_before_start() {
        let runner = runner_with(Arc::new(MintingPort {
            generation: 9,
            ..matching_port("generation")
        }));
        assert!(
            matches!(
                runner.execute(&test_admission(), &test_request()),
                Err(BridgeError::NotAdmitted { .. })
            ),
            "a stale process generation must be refused before start"
        );
    }

    #[test]
    fn minted_epoch_mismatch_is_refused_before_start() {
        let other_epoch = EpochId::new(
            EpochLineageId::new("6ba7b810-9dad-11d1-80b4-00c04fd430c8").expect("lineage"),
            NonZeroU64::new(7).expect("sequence"),
        )
        .expect("epoch");
        let runner = runner_with(Arc::new(MintingPort {
            epoch: other_epoch,
            ..matching_port("epoch")
        }));
        assert!(
            matches!(
                runner.execute(&test_admission(), &test_request()),
                Err(BridgeError::NotAdmitted { .. })
            ),
            "authority epoch disagreement must be refused before start"
        );
    }

    #[test]
    fn minted_ambient_inheritance_is_refused_before_start() {
        let runner = runner_with(Arc::new(MintingPort {
            inheritance: EnvironmentInheritance::Allowlisted,
            ..matching_port("inheritance")
        }));
        assert!(
            matches!(
                runner.execute(&test_admission(), &test_request()),
                Err(BridgeError::NotAdmitted { .. })
            ),
            "ambient environment inheritance must be refused before start"
        );
    }

    #[test]
    fn terminal_classification_never_invents_success() {
        let completed =
            ExitStatus::new(ExitDisposition::Completed, Some(0), None, 1).expect("exit");
        assert_eq!(
            classify_terminal(ProcessLifecycle::Exited, &completed, true),
            ProviderOutcome::Completed
        );
        // A completed exit without proven tree closure is unknown, not success.
        assert_eq!(
            classify_terminal(ProcessLifecycle::Exited, &completed, false),
            ProviderOutcome::Unknown
        );
        // An unknown lifecycle poisons even a clean exit observation.
        assert_eq!(
            classify_terminal(ProcessLifecycle::UnknownOutcome, &completed, true),
            ProviderOutcome::Unknown
        );
        let signalled =
            ExitStatus::new(ExitDisposition::Signalled, None, Some(15), 1).expect("exit");
        assert_eq!(
            classify_terminal(ProcessLifecycle::Failed, &signalled, true),
            ProviderOutcome::Crashed
        );
        let limited = ExitStatus::new(ExitDisposition::ResourceLimit, None, None, 1).expect("exit");
        assert_eq!(
            classify_terminal(ProcessLifecycle::Failed, &limited, true),
            ProviderOutcome::Crashed
        );
        let cancelled = ExitStatus::new(ExitDisposition::Cancelled, None, None, 1).expect("exit");
        assert_eq!(
            classify_terminal(ProcessLifecycle::Exited, &cancelled, true),
            ProviderOutcome::Cancelled
        );
        let unknown = ExitStatus::new(ExitDisposition::Unknown, None, None, 1).expect("exit");
        assert_eq!(
            classify_terminal(ProcessLifecycle::Exited, &unknown, true),
            ProviderOutcome::Unknown
        );
    }

    #[test]
    fn runner_binds_executor_port_and_default_deadline() {
        let runner = runner_with(Arc::new(RefusingPort)).with_deadline(Duration::from_secs(5));
        let _ = runner.executor();
        assert_eq!(BOUND_RUN_DEADLINE, Duration::from_secs(30));
    }
}
