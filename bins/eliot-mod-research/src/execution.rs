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
use std::sync::Arc;
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
use crate::admission::AdmittedProviderAdmission;
use crate::evidence::{RawProviderEvidence, sha256_hex};
use crate::protocol::{
    RESEARCH_PROVIDER_WIRE_VERSION, ResultFrame, SubmitAck, SubmitEnvelope, scan_result_frame,
};

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
/// requests itself. `request_sha256` binds the exact canonical request bytes
/// the minted request must execute for; the bridge re-validates the returned
/// request against the admission before the executor is contacted.
pub trait ResearchRequestPort: Send + Sync {
    /// Binds one admitted operation to exactly one authorized process request.
    ///
    /// # Errors
    ///
    /// Returns [`RequestPortError`] when no authority is available or the
    /// port refuses the binding.
    fn bind(
        &self,
        admission: &AdmittedProviderAdmission,
        request_sha256: &str,
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

/// One executed provider attempt: the stable job identity, the typed outcome,
/// the immutable raw evidence, the provider-local job reference, and the
/// terminal result frame when the provider emitted one.
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
    /// Terminal result frame when present in provider output.
    pub result_frame: Option<ResultFrame>,
    /// Canonical submit wire bytes sent to the port binding.
    pub wire_bytes: Vec<u8>,
}

/// One started operation with its sealed bindings: the stable operation
/// identity, the invocation digest every observation must preserve, and the
/// canonical submit wire bytes.
struct BoundOperation {
    operation: OperationId,
    digest: String,
    wire_bytes: Vec<u8>,
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
        }
    }

    /// Overrides the terminal-lifecycle wait bound.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Executes one admitted request through the shared governed contour.
    ///
    /// Order (all fail-closed): request/admission binding, port minting,
    /// minted-request re-validation (artifact, operation, generation, epoch,
    /// no ambient environment inheritance), executor start with receipt
    /// checks, terminal wait with deadline, stream readback with immutable
    /// evidence materialization, typed ack decode. A provider terminal state
    /// that cannot be classified returns [`ProviderOutcome::Unknown`] with
    /// the evidence preserved, and must be reconciled by operation identity
    /// before any retry.
    pub(crate) fn execute(
        &self,
        admission: &AdmittedProviderAdmission,
        request: &ResearchQueryRequest,
    ) -> Result<ProviderExecution, BridgeError> {
        admission
            .validate()
            .map_err(|refusal| BridgeError::NotAdmitted {
                reason: refusal.reason(),
            })?;
        let bound = self.bind_operation(admission, request)?;
        let view = self.await_terminal(&bound)?;
        self.finish_terminal(bound, &view)
    }

    /// Validates the request/admission binding, mints the process request
    /// through the port, re-validates the minted binding, and starts the
    /// operation with receipt checks. Everything here happens before any
    /// provider output exists.
    fn bind_operation(
        &self,
        admission: &AdmittedProviderAdmission,
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
        let process_request = self
            .port
            .bind(admission, &request_sha256)
            .map_err(|_| BridgeError::ProviderUnavailable)?;
        check_minted_request(admission, &process_request)?;
        let operation = process_request.operation_id().clone();
        let digest = process_request.invocation_digest().to_owned();
        let generation = process_request.generation();
        let envelope = SubmitEnvelope {
            wire_version: RESEARCH_PROVIDER_WIRE_VERSION,
            operation_id: operation.as_str().to_owned(),
            exchange_id: request.exchange_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            invocation_digest: digest.clone(),
            protocol_revision: request.protocol_revision,
            required_schema: request.required_schema.clone(),
            request_sha256,
        };
        let wire_bytes = envelope
            .encode()
            .map_err(|refusal| BridgeError::ProtocolViolation {
                reason: refusal.reason(),
            })?;
        // Fail-closed serializer check: the wire we hand to the port binding
        // must decode back to the same operation and invocation binding.
        let round_trip = SubmitEnvelope::decode(&wire_bytes).map_err(|refusal| {
            BridgeError::ProtocolViolation {
                reason: refusal.reason(),
            }
        })?;
        if round_trip.operation_id != envelope.operation_id
            || round_trip.invocation_digest != envelope.invocation_digest
        {
            return Err(BridgeError::ProtocolViolation {
                reason: "submit envelope failed its round-trip binding check",
            });
        }
        let receipt = block_on(self.executor.start(process_request, self.sink.clone()))
            .map_err(BridgeError::Process)?;
        if receipt.operation_id() != &operation
            || receipt.request_digest() != digest
            || receipt.accepted_generation() != generation
        {
            return Err(BridgeError::EvidenceIncomplete {
                reason: "executor start receipt does not preserve the bound request",
            });
        }
        Ok(BoundOperation {
            operation,
            digest,
            wire_bytes,
        })
    }

    /// Waits for the terminal lifecycle of one started operation, preserving
    /// the request binding on every observation. A deadline overrun attempts
    /// cancellation and stays explicit: the outcome is unconfirmed.
    fn await_terminal(
        &self,
        bound: &BoundOperation,
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
            if started.elapsed() >= self.deadline {
                let _ = block_on(self.executor.cancel(bound.operation.clone()));
                return Err(BridgeError::TimedOut);
            }
            std::thread::sleep(BOUND_RUN_POLL);
        }
    }

    /// Materializes immutable evidence from one terminal observation and
    /// decodes the typed provider ack. Unknown terminal states stay explicit
    /// with the evidence preserved; provider output never becomes identity.
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
        let (stdout, stderr) = self
            .executor
            .captured_output(&bound.operation)
            .map_err(BridgeError::Process)?;
        let evidence = RawProviderEvidence::materialize(
            bound.operation.as_str(),
            &bound.digest,
            exit,
            &stdout,
            &stderr,
            descendants_complete,
        );
        let outcome = classify_terminal(view.lifecycle(), exit, descendants_complete);
        if outcome == ProviderOutcome::Unknown {
            return Err(BridgeError::UnknownOutcome);
        }
        let ack_line = stdout
            .bytes
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default();
        let ack =
            SubmitAck::decode(ack_line).map_err(|refusal| BridgeError::ProtocolViolation {
                reason: refusal.reason(),
            })?;
        let result_frame =
            scan_result_frame(&stdout.bytes).map_err(|refusal| BridgeError::ProtocolViolation {
                reason: refusal.reason(),
            })?;
        Ok(ProviderExecution {
            job_id: bound.operation.as_str().to_owned(),
            outcome,
            evidence,
            provider_job_ref: ack.provider_job_id,
            result_frame,
            wire_bytes: bound.wire_bytes,
        })
    }

    /// Requests cancellation of the bound operation through the executor.
    pub(crate) fn cancel_operation(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<CancellationReceipt, BridgeError> {
        block_on(self.executor.cancel(operation.clone())).map_err(BridgeError::Process)
    }

    /// Reconciles the bound operation's unknown external result.
    pub(crate) fn reconcile_operation(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<ProcessEvidence, BridgeError> {
        block_on(self.executor.reconcile(operation.clone())).map_err(BridgeError::Process)
    }
}

/// Re-validates a port-minted request against the admission before the
/// executor is contacted: exact artifact identity, exact operation identity,
/// exact process generation, epoch agreement, structural validity, and no
/// ambient environment inheritance (the child receives only explicit values,
/// so credentials, proxy configuration, and user resources cannot leak in).
fn check_minted_request(
    admission: &AdmittedProviderAdmission,
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
    Ok(())
}

/// Classifies one terminal observation into a provider-local outcome.
/// Anything that is not a clean completed exit with proven tree closure stays
/// explicit: crash-class dispositions, missing descendant proof, and unknown
/// lifecycles never decode as success.
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
            _admission: &AdmittedProviderAdmission,
            _request_sha256: &str,
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
            _admission: &AdmittedProviderAdmission,
            _request_sha256: &str,
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
            _admission: &AdmittedProviderAdmission,
            _request_sha256: &str,
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
    fn shape_only_admission_is_refused_before_authority_port_contact() {
        let runner = runner_with(Arc::new(RefusingPort));
        assert!(
            matches!(
                runner.execute(&test_admission(), &test_request()),
                Err(BridgeError::NotAdmitted { .. })
            ),
            "shape-only admission must be refused before the authority port is contacted"
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
        let _runner = runner_with(Arc::new(RefusingPort)).with_deadline(Duration::from_secs(5));
        assert_eq!(BOUND_RUN_DEADLINE, Duration::from_secs(30));
    }
}
