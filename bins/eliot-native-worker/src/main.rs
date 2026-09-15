#![forbid(unsafe_code)]

use std::io::{self, Write};

use eliot_native_worker::{
    AdmittedLifecycle, KERNEL_ADMISSION_REQUIRED, KernelNativeWorkerClient, NativeWorker,
    NativeWorkerError,
    admitted_material::{
        ADMITTED_DISPATCH_RESIDUAL, ValidatedAdmittedMaterial, read_admitted_material,
    },
    drive_admitted_claimed, select_factory_for_admitted,
};
use eliot_native_worker_core::{
    CapabilityAdmissionPort, DurableCheckpointPort, DurableReplayPort, WorkerError,
};
use eliot_process::{ProcessExecutor, ProcessRequest};

const KERNEL_ADMISSION_EXIT: i32 = 78;
/// Exit for admitted drive/serve failures that are not admission refusals.
///
/// Reserved so exit 78 keeps its single meaning: missing or refused admission
/// before (or at) the Kernel's admission verdict. Anything else that breaks
/// after admission was presented — failed start, lost receipt, broken serve
/// pipe — fails the run without claiming admission semantics.
const ADMITTED_DRIVE_FAILED_EXIT: i32 = 1;
/// Transport is open but no provider runtime may run here: attaining Ready
/// and executing provider work are owned by issues #22 (worker runtime) and
/// #874 (adapter registry). The worker exits fail-closed without provider
/// work, keeping the exit-78 convention with a distinct payload.
///
/// Emitted if and only if the Kernel transport is open but the dispatch
/// contour delivered no session-bound claim material to this invocation. The
/// admitted arm (validated material present) never emits this line: it
/// drives to Ready and serves, or denies with a typed admission refusal.
const PROVIDER_RUNTIME_DEFERRED: &str = "PROVIDER_RUNTIME_DEFERRED";
/// Terminal code for an admitted drive/serve failure that is not an admission
/// refusal. Carries the typed drive detail; never the deferred line.
const ADMITTED_DRIVE_FAILED: &str = "ADMITTED_DRIVE_FAILED";

fn main() {
    std::process::exit(run());
}

/// Admitted native-worker driver.
///
/// Sequence (T9-06, slice D consumer half): connect the authenticated Kernel
/// front door, consume the Kernel-delivered session-bound claim material
/// (protected dispatch file plus launch nonce per I7.5/I15.2, never argv or
/// env), then drive the exact registration/claim/hello/process presentation
/// through `drive_admitted_claimed` (register, claim, reconcile, checked
/// `start_claimed` through `WorkerCore::demand_start_claimed`, readiness),
/// and on `Ready` serve the bounded frame loop.
///
/// Gate table:
/// - transport closed → 78 `KERNEL_ADMISSION_REQUIRED`;
/// - transport open but nothing delivered → 78 `PROVIDER_RUNTIME_DEFERRED`
///   (preserved fail-closed);
/// - delivered but invalid → 78 typed `KERNEL_ADMISSION_REQUIRED` denial;
/// - validated but resolving to no factory (no v2 join, route/nonce/factory
///   mismatch) → 78 typed `KERNEL_ADMISSION_REQUIRED` denial, never the
///   deferred line;
/// - validated and factory-resolved but the kernel dispatch launch seam
///   (T9-07) has not delivered the in-memory execution context
///   (`ProcessRequest`, never deserialized, plus the composed provider
///   ports) → 78 typed residual denial, never the deferred line;
/// - driven: `Ready` plus served frames → 0; a Kernel/owner admission refusal
///   at submit or in the claim join → 78; any other drive/serve failure → 1.
///   The admitted arm never emits `PROVIDER_RUNTIME_DEFERRED`.
///
/// T9-05 coordinator verification is not consumed by this contour. No user
/// authentication is performed (owner decision #1376). No worker-local
/// replay journal is created (thin transport over T9-03 only). No
/// signing/token service is invented here: the Kernel stays the
/// provider-capability supplier over the authenticated front-door session
/// plus ORS records bound to the attempt (M2), and the worker only presents
/// and re-proves.
fn run() -> i32 {
    let lifecycle = match KernelNativeWorkerClient::connect() {
        Ok(client) => client,
        Err(error) => return deny_transport(&error.to_string()),
    };
    let material = match read_admitted_material() {
        Ok(Some(material)) => material,
        Ok(None) => return deny_absent_material(),
        Err(error) => return deny_invalid_material(&error.to_string()),
    };
    // T9-07 (WRITER-B): the validated route resolves to exactly one factory
    // through the registry seam (`select_factory_for_admitted`, bound by
    // Writer A's `src/adapter_registry.rs` at integration). An unresolvable
    // route is a refused presentation: typed 78 denial, never the deferred
    // line and never a drive.
    let selection = match select_factory_for_admitted(&material) {
        Ok(selection) => selection,
        Err(error) => return deny_invalid_material(&error.to_string()),
    };
    // HONESTY STOP (issue #874 binding): the factory is resolved, but the
    // in-memory execution context (the executor-bound `ProcessRequest` plus
    // the composed P-03 dispatch validation, G-01-facing admission, and
    // durable checkpoint ports) arrives only with the kernel dispatch launch
    // seam, which has no native-worker writer (owner file
    // `bins/eliot-kernel/src/dispatch_launch.rs` serves Doctor/testd only).
    // The validated envelope carries only digests and labels — the
    // `process_invocation_digest`, never the invocation material; the
    // admitted route labels, never the live owner record — and
    // `ProcessRequest` is deliberately `Serialize`-only, so no byte surface
    // can present it. This binary mints none of it: no deserialized process
    // request, no local authority, no private supervisor. Until that seam
    // lands the validated material cannot drive, so the run denies with the
    // dispatch residual — never the deferred line, which is reserved for
    // genuinely missing material.
    let _ = &lifecycle;
    let _ = &material;
    let _ = &selection;
    let _ = ADMITTED_DISPATCH_RESIDUAL;
    deny_dispatch_residual()
}

/// Drives one validated admitted presentation to `Ready` and serves.
///
/// Genuine drive wiring (not a probe): the lifecycle transport, the composed
/// worker with its real provider ports, the validated Kernel-delivered
/// material, and the in-memory executor-bound process arrive fully injected;
/// the contour performs the exact register/claim/reconcile/`start_claimed`/
/// readiness sequence and then serves the bounded frame loop. The dispatch
/// launch seam calls this shape once it provisions the execution context;
/// until then it stays wired but unreached, which keeps the residual denial
/// above honest. Proven through `drive_admitted_claimed` plus
/// `serve_one_frame` in the admitted-material behaviour check below.
#[allow(
    dead_code,
    reason = "admitted drive awaits the T9-07 kernel dispatch launch seam for its in-memory execution context; exercised via drive_admitted_claimed plus serve_one_frame in the admitted-material behaviour check"
)]
fn drive_admitted_material<E, A, R, C, L>(
    lifecycle: &mut L,
    worker: &mut NativeWorker<E, A, R, C>,
    material: ValidatedAdmittedMaterial,
    process: ProcessRequest,
) -> i32
where
    E: ProcessExecutor,
    A: CapabilityAdmissionPort,
    R: DurableReplayPort,
    C: DurableCheckpointPort,
    L: AdmittedLifecycle,
{
    match block_on(drive_admitted_claimed(
        lifecycle,
        worker,
        material.admission.registration(),
        &material.admission,
        material.hello,
        process,
        &material.reconcile,
        &material.readiness,
    )) {
        Ok(_ready) => {}
        Err(error) => return fail_drive(&error),
    }
    match block_on(worker.serve_stdio()) {
        Ok(()) => 0,
        Err(error) => {
            emit(ADMITTED_DRIVE_FAILED, &error.to_string());
            ADMITTED_DRIVE_FAILED_EXIT
        }
    }
}

/// Emits one typed drive failure and projects its exit.
///
/// A Kernel/owner admission refusal keeps exit 78 (the admission was truly
/// refused); any other drive failure takes the distinct admitted-drive
/// failure exit without the deferred line.
fn fail_drive(error: &NativeWorkerError) -> i32 {
    let exit = exit_for_drive_error(error);
    let code = if exit == KERNEL_ADMISSION_EXIT {
        KERNEL_ADMISSION_REQUIRED
    } else {
        ADMITTED_DRIVE_FAILED
    };
    emit(code, &error.to_string());
    exit
}

/// Projects one admitted-drive error to its process exit.
///
/// Exit 78 stays reserved for the claim/admission join and owner-verdict
/// refusal family (plus Kernel-transport refusals): the presentation did not
/// bind or the owner said no. Everything else — failed start, lost receipt,
/// broken serve pipe — is a post-admission mechanical failure and takes the
/// distinct drive-failed exit.
fn exit_for_drive_error(error: &NativeWorkerError) -> i32 {
    match error {
        NativeWorkerError::KernelAdmissionRequired(_) => KERNEL_ADMISSION_EXIT,
        NativeWorkerError::Core(worker) if is_refused_admission(worker) => KERNEL_ADMISSION_EXIT,
        _ => ADMITTED_DRIVE_FAILED_EXIT,
    }
}

/// Reports whether a core failure is an admission refusal.
///
/// True for exactly the claim/admission join and owner-verdict family: the
/// `from_claim` executable-join mismatches, stale epoch/fence, expired
/// window, and the admission owner's rejected/revoked/mismatched verdicts.
/// All other core failures (lifecycle, lease, frame, process, replay,
/// provider) happen at or after an admitted start and are not refusals.
fn is_refused_admission(error: &WorkerError) -> bool {
    matches!(
        error,
        WorkerError::InvalidRequest(_)
            | WorkerError::UnsupportedVersion
            | WorkerError::StaleEpoch
            | WorkerError::StaleFence
            | WorkerError::DeadlineExpired
            | WorkerError::AdmissionRejected(_)
            | WorkerError::AdmissionMismatch(_)
            | WorkerError::Revoked(_)
    )
}

fn deny_transport(detail: &str) -> i32 {
    emit(KERNEL_ADMISSION_REQUIRED, detail);
    KERNEL_ADMISSION_EXIT
}

fn deny_absent_material() -> i32 {
    emit(
        PROVIDER_RUNTIME_DEFERRED,
        &NativeWorkerError::KernelAdmissionRequired(
            "Kernel transport is open but no session-bound claim and Ready receipt exist; provider execution is owned by #22/#874, so the worker exits fail-closed without provider work"
                .to_owned(),
        )
        .to_string(),
    );
    KERNEL_ADMISSION_EXIT
}

fn deny_invalid_material(detail: &str) -> i32 {
    emit(KERNEL_ADMISSION_REQUIRED, detail);
    KERNEL_ADMISSION_EXIT
}

fn deny_dispatch_residual() -> i32 {
    emit(KERNEL_ADMISSION_REQUIRED, ADMITTED_DISPATCH_RESIDUAL);
    KERNEL_ADMISSION_EXIT
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(output) => return output,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn emit(code: &str, detail: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{{\"error\":\"{code}\",\"detail\":\"{detail}\"}}");
}

#[cfg(test)]
mod tests {
    //! Slice-D behaviour check: Kernel-delivered claim bytes reach `Ready`
    //! and serve, while missing/refused admission stays exit 78.
    //!
    //! T9-07 (WRITER-B) adds the factory-resolution half: validated material
    //! resolves to exactly one factory through `select_factory_for_admitted`,
    //! a rewired route resolves to none (typed 78), and the admitted arm
    //! never emits the deferred line. The execution-context half (in-memory
    //! `ProcessRequest` plus composed ports) remains the named residual.
    //!
    //! Windows-only trusted composition. The REAL admitted
    //! `WindowsProcessExecutor` runs a real bounded child in-process; every
    //! production validator runs (envelope binding, the `from_claim` join,
    //! the executable gate, grant checks, receipt/proof checks). Kernel
    //! admission transport is doubled here because a live Kernel is
    //! unavailable in this environment (clearly-marked `FakeLifecycle` /
    //! `FakeTransport` below, echo-checking the actual route contracts);
    //! there is no fake executor, no deserialized `ProcessRequest`, and no
    //! direct `std::process::Command`. The in-memory execution context (test
    //! permit authority plus composed ports) stands in for the T9-07 kernel
    //! dispatch launch seam, which is the only piece this binary still
    //! awaits in production.

    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt::Debug;
    use std::io::Cursor;
    use std::sync::{Arc, Mutex, MutexGuard};

    use eliot_contracts::{
        ClockReading, DecisionId, EpochId, EpochLineageId, ResourceGeneration, SessionId,
        StateFence, TaskId, WorkLeaseId, sha256_hex,
    };
    use eliot_native_worker::admitted_material::{
        ADMITTED_DISPATCH_RESIDUAL, AdmittedClaimEnvelope, read_admitted_material_from,
    };
    use eliot_native_worker::{
        AdmittedLifecycle, KernelReplayPort, KernelReplayTransport, NativeWorker,
        NativeWorkerError, drive_admitted_claimed, select_factory_for_admitted,
    };
    use eliot_native_worker_core::{
        AdmissionLivenessFacts, AdmissionLivenessOutcome, AuthorityEnvelope, BudgetEnvelope,
        CapabilityAdmissionFacts, CapabilityAdmissionOutcome, CapabilityAdmissionPort,
        CapabilityAdmissionRequest, CapabilityLivenessRequest, CheckpointProviderOutcome,
        CheckpointReceiptFacts, ClaimAdmissionRequest, DurableCheckpointPort,
        DurableCheckpointRequest, DurableRequestDecision, EXECUTION_UNIT_SCHEMA_VERSION,
        EffectAdmissionOutcome, EffectAdmissionRequest, EffectCeiling, EffectKind,
        JSON_ENCODING_PROFILE, NATIVE_WORKER_CLAIM_WIRE_VERSION,
        NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION, NativeClaimId,
        NativeRegistrationId, NativeRenewalId, NativeWorkerClaim, NativeWorkerExecutableBinding,
        NativeWorkerExecutableExpectation, NativeWorkerRegistration, PROTOCOL_VERSION,
        ProviderFailure, WorkerCore, WorkerEventEnvelope, WorkerFrame, WorkerFrameBody,
        WorkerHello, WorkerLifecycle,
    };
    use eliot_process::SessionId as ProcessSessionId;
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
        EnvironmentInheritance, EnvironmentProjection, EvidenceSinkError, FencingToken, Generation,
        ImageId, JobId, KernelDispatchKey, OperationId, PermitIssuance, ProcessEvidence,
        ProcessEvidenceSink, ProcessExecutionError, ProcessIntent, ProcessRequest, ProcessTreeId,
        ResourceLimits, SuspendedProcessIdentity, ValidatedDispatch,
    };
    use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};

    use super::{
        ADMITTED_DRIVE_FAILED_EXIT, KERNEL_ADMISSION_EXIT, PROVIDER_RUNTIME_DEFERRED, block_on,
        deny_absent_material, deny_dispatch_residual, deny_invalid_material, deny_transport,
        exit_for_drive_error,
    };

    /// Fake authenticated lifecycle: validates the exact presentation and
    /// echoes submitted identities like the real Kernel routes, never minting
    /// authority. Test-only: a live Kernel is unavailable here.
    struct FakeLifecycle {
        registration: Option<NativeWorkerRegistration>,
        claim: Option<NativeWorkerClaim>,
    }

    impl FakeLifecycle {
        fn new() -> Self {
            Self {
                registration: None,
                claim: None,
            }
        }
    }

    fn fake_now_ms() -> u64 {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis(),
        )
        .expect("clock range")
    }

    impl AdmittedLifecycle for FakeLifecycle {
        fn submit_registration(
            &mut self,
            registration: &NativeWorkerRegistration,
        ) -> Result<serde_json::Value, NativeWorkerError> {
            registration.validate()?;
            self.registration = Some(registration.clone());
            self.claim = None;
            Ok(serde_json::json!({
                "registration_id": registration.registration_id.as_str(),
                "worker_generation": registration.worker_generation,
            }))
        }

        fn submit_claim(
            &mut self,
            admission: &ClaimAdmissionRequest,
        ) -> Result<serde_json::Value, NativeWorkerError> {
            admission.validate_binding()?;
            let registration = self.registration.as_ref().ok_or_else(|| {
                NativeWorkerError::KernelAdmissionRequired(
                    "no exact current registration".to_owned(),
                )
            })?;
            let claim = admission.claim();
            if claim.registration_id != registration.registration_id
                || claim.worker_generation != registration.worker_generation
            {
                return Err(NativeWorkerError::KernelAdmissionRequired(
                    "claim is not bound to the registration".to_owned(),
                ));
            }
            self.claim = Some(claim.clone());
            Ok(serde_json::json!({
                "claim_id": claim.claim_id.as_str(),
                "binding_digest": claim.binding_digest.as_str(),
                "decision": {"kind": "ADMITTED"},
            }))
        }

        fn submit_reconcile(
            &mut self,
            submission: &eliot_native_worker::ReconcileSubmission,
        ) -> Result<serde_json::Value, NativeWorkerError> {
            submission.validate()?;
            let stored = self.claim.as_ref().ok_or_else(|| {
                NativeWorkerError::KernelAdmissionRequired("no exact claimed unit".to_owned())
            })?;
            let claim = submission.claim();
            if claim.claim_id != stored.claim_id || claim.binding_digest != stored.binding_digest {
                return Err(NativeWorkerError::KernelAdmissionRequired(
                    "reconcile claim is not the exact claimed unit".to_owned(),
                ));
            }
            Ok(serde_json::json!({
                "kind": "native_worker_reconciled",
                "reconcile_id": submission.reconcile_id(),
                "claim_id": claim.claim_id.as_str(),
                "binding_digest": claim.binding_digest.as_str(),
            }))
        }

        fn submit_readiness(
            &mut self,
            submission: &eliot_native_worker_core::ReadinessSubmission,
        ) -> Result<serde_json::Value, NativeWorkerError> {
            submission.validate_binding(fake_now_ms())?;
            let stored = self.claim.as_ref().ok_or_else(|| {
                NativeWorkerError::KernelAdmissionRequired("no exact claimed unit".to_owned())
            })?;
            let claim = submission.claim();
            if claim.claim_id != stored.claim_id || claim.binding_digest != stored.binding_digest {
                return Err(NativeWorkerError::KernelAdmissionRequired(
                    "readiness claim is not the exact claimed unit".to_owned(),
                ));
            }
            match submission.readiness() {
                eliot_native_worker_core::NativeWorkerReadiness::Ready(report) => {
                    Ok(serde_json::json!({
                        "kind": "native_worker_ready",
                        "ready_id": report.ready_id.as_str(),
                        "claim_id": report.claim_id.as_str(),
                        "decision": {"kind": "ADMITTED"},
                    }))
                }
                eliot_native_worker_core::NativeWorkerReadiness::Blocked(report) => {
                    Ok(serde_json::json!({
                        "kind": "native_worker_blocked",
                        "ready_id": report.ready_id.as_str(),
                        "claim_id": report.claim_id.as_str(),
                    }))
                }
            }
        }
    }

    /// Fake Kernel replay transport: echo-checks the claim/replay binding and
    /// seals durable receipts from an in-memory store. Test-only: the thin
    /// T9-03 transport double for a live Kernel that is unavailable here.
    struct FakeTransport {
        claim_id: String,
        worker_generation: u64,
        stream_id: String,
        next_sequence: u64,
    }

    impl FakeTransport {
        fn new(claim: &NativeWorkerClaim) -> Self {
            Self {
                claim_id: claim.claim_id.as_str().to_owned(),
                worker_generation: claim.worker_generation,
                stream_id: format!(
                    "{}/gen-{}",
                    claim.claim_id.as_str(),
                    claim.worker_generation
                ),
                next_sequence: 0,
            }
        }

        fn seal(&self, operation: &str, reply: serde_json::Value) -> serde_json::Value {
            serde_json::json!({
                "kind": "native_worker_replay",
                "operation": operation,
                "claim_id": self.claim_id,
                "stream_id": self.stream_id,
                "worker_generation": self.worker_generation,
                "reply": reply,
                "decided_at_unix_ms": 1_u64,
                "receipt_digest": "0".repeat(64),
            })
        }
    }

    impl KernelReplayTransport for FakeTransport {
        fn transact(
            &mut self,
            operation: &str,
            payload: serde_json::Value,
        ) -> Result<serde_json::Value, NativeWorkerError> {
            let binding = payload.get("binding").cloned().unwrap_or_default();
            if binding.get("claim_id").and_then(serde_json::Value::as_str)
                != Some(self.claim_id.as_str())
                || binding.get("stream_id").and_then(serde_json::Value::as_str)
                    != Some(self.stream_id.as_str())
                || binding
                    .get("worker_generation")
                    .and_then(serde_json::Value::as_u64)
                    != Some(self.worker_generation)
            {
                return Err(NativeWorkerError::KernelAdmissionRequired(
                    "replay binding does not match the bound claim".to_owned(),
                ));
            }
            match operation {
                "native_worker.replay_lookup" | "native_worker.replay_begin" => Ok(self.seal(
                    operation,
                    serde_json::json!({ "decision": serde_json::to_value(&DurableRequestDecision::New).expect("decision") }),
                )),
                "native_worker.replay_append" => {
                    let mut draft = payload.get("draft").cloned().unwrap_or_default();
                    self.next_sequence += 1;
                    draft["event_id"] =
                        serde_json::Value::String(format!("event-{}", self.next_sequence));
                    draft["sequence"] = serde_json::Value::from(self.next_sequence);
                    let envelope: WorkerEventEnvelope =
                        serde_json::from_value(draft).map_err(|error| {
                            NativeWorkerError::KernelAdmissionRequired(format!(
                                "fake replay cannot seal envelope: {error}"
                            ))
                        })?;
                    Ok(self.seal(
                        operation,
                        serde_json::json!({ "envelope": serde_json::to_value(&envelope).expect("envelope") }),
                    ))
                }
                "native_worker.replay" => Ok(self.seal(
                    operation,
                    serde_json::json!({ "events": serde_json::Value::Array(Vec::new()) }),
                )),
                "native_worker.replay_acknowledge" => {
                    Ok(self.seal(operation, serde_json::json!({ "ok": true })))
                }
                _ => Err(NativeWorkerError::KernelAdmissionRequired(
                    "unknown replay operation".to_owned(),
                )),
            }
        }
    }

    /// Production dispatch validation behind a test-owned key and nonce ledger.
    ///
    /// The authority is the production `DispatchPermitAuthority` (real
    /// one-shot permit validation); it is owned in-process only because the
    /// P-07 controller lives in `bins/eliot-kernel` and arrives with the T9-07
    /// launch seam in production. The executor itself is real.
    struct TestAuthorityPort {
        authority: Mutex<DispatchPermitAuthority>,
        context: DispatchValidationContext,
    }

    impl DispatchValidationPort for TestAuthorityPort {
        fn validate_and_consume(
            &self,
            request: ProcessRequest,
            observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            let mut authority = lock(&self.authority);
            authority
                .validate_and_consume(request, observed, &self.context)
                .map_err(Into::into)
        }
    }

    /// Admission double seeded from owner-produced records: echoes the
    /// presented claim digest and the presented executable join as the live
    /// owner expectation. Every production grant check still runs. Test-only.
    struct TestAdmission {
        admissions: Arc<Mutex<usize>>,
    }

    impl CapabilityAdmissionPort for TestAdmission {
        fn admit(
            &mut self,
            request: &CapabilityAdmissionRequest,
        ) -> Result<CapabilityAdmissionOutcome, ProviderFailure> {
            *lock(&self.admissions) += 1;
            let stream_id = request.claim().map_or_else(
                || "worker-stream-1".to_owned(),
                |presented| {
                    format!(
                        "{}/gen-{}",
                        presented.claim().claim_id.as_str(),
                        presented.claim().worker_generation
                    )
                },
            );
            let mut facts = CapabilityAdmissionFacts::new(
                "admission-1",
                "admission-revision-1",
                1,
                100,
                10_000,
                stream_id,
                "worker-producer-1",
                request.hello().route_ref.clone(),
                request.hello().artifact_manifest_digest.clone(),
                request.hello().worker_generation,
                authority(request.hello().state_fence.clone()),
                request.hello().requested_capabilities.clone(),
                request.operation_id().clone(),
                request.process_tree_id().clone(),
                request.process_generation(),
                request.process_fence().clone(),
                request.process_request_digest(),
                *request.resource_limits(),
            );
            if let Some(presented) = request.claim() {
                facts = facts.with_claim_binding(presented.claim());
                if let Some(join) = &presented.claim().executable_binding {
                    facts = facts.with_executable_expectation(NativeWorkerExecutableExpectation {
                        current: join.clone(),
                        revoked: false,
                    });
                }
            }
            Ok(CapabilityAdmissionOutcome::Admitted(Box::new(facts)))
        }

        fn revalidate(
            &mut self,
            request: &CapabilityLivenessRequest,
        ) -> Result<AdmissionLivenessOutcome, ProviderFailure> {
            Ok(AdmissionLivenessOutcome::Live(AdmissionLivenessFacts::new(
                request.admission_id(),
                request.admission_revision(),
                request.revocation_revision(),
                request.lease().clone(),
                request.authority_epoch().clone(),
                request.state_fence().clone(),
                200,
                10_000,
                false,
            )))
        }

        fn authorize_effect(
            &mut self,
            _request: &EffectAdmissionRequest,
        ) -> Result<EffectAdmissionOutcome, ProviderFailure> {
            Err(ProviderFailure::new(
                "admission",
                "slice-D check never authorizes effects",
            ))
        }
    }

    /// Test-owned checkpoint double (durable owner stand-in, not Kernel
    /// transport). Test-only.
    #[derive(Clone)]
    struct TestCheckpoint;

    impl DurableCheckpointPort for TestCheckpoint {
        fn persist_checkpoint(
            &mut self,
            request: &DurableCheckpointRequest,
        ) -> Result<CheckpointProviderOutcome, ProviderFailure> {
            Ok(CheckpointProviderOutcome::Stored(Box::new(
                CheckpointReceiptFacts::new(
                    "checkpoint-receipt-1",
                    request.checkpoint_ref(),
                    request.request_id(),
                    request.stream_id(),
                    request.producer_generation(),
                    request.authority_epoch().clone(),
                    request.state_fence().clone(),
                    request.admission_revision(),
                    request.operation_id().clone(),
                    request.process_request_digest(),
                    300,
                ),
            )))
        }
    }

    struct RecordingSink {
        evidence: Arc<Mutex<Vec<ProcessEvidence>>>,
    }

    impl ProcessEvidenceSink for RecordingSink {
        fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
            lock(&self.evidence).push(evidence);
            Ok(())
        }
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(_) => panic!("slice-D fixture lock failed"),
        }
    }

    fn load<T, E: Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("slice-D fixture failed: {error:?}"),
        }
    }

    fn epoch() -> EpochId {
        load(EpochId::new(
            load(EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")),
            load(std::num::NonZeroU64::new(1).ok_or("non-zero")),
        ))
    }

    fn fence() -> StateFence {
        StateFence::new(epoch(), load(ResourceGeneration::new(1)))
    }

    fn authority(state_fence: StateFence) -> AuthorityEnvelope {
        AuthorityEnvelope {
            epoch: epoch(),
            scope_ref: "scope-1".to_owned(),
            effect_ceiling: EffectCeiling {
                scope_ref: "scope-1".to_owned(),
                allowed: [EffectKind::WriteCandidate].into_iter().collect(),
                max_external_effects: 0,
            },
            lease: load(serde_json::from_value::<WorkLeaseId>(
                serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"}),
            )),
            state_fence,
            valid_until: "provider-owned".to_owned(),
        }
    }

    fn revisions() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("authority".to_owned(), "a".repeat(64)),
            ("state".to_owned(), "b".repeat(64)),
        ])
    }

    fn limits() -> ResourceLimits {
        load(ResourceLimits::new(
            30_000,
            Some(10_000),
            Some(512_000_000),
            4_096,
            4_096,
            4,
        ))
    }

    fn executable_path() -> String {
        r"C:\Windows\System32\cmd.exe".to_owned()
    }

    fn executable_digest() -> String {
        let bytes = std::fs::read(executable_path())
            .unwrap_or_else(|_| panic!("admitted executable is missing"));
        sha256_hex(&bytes)
    }

    fn working_directory() -> String {
        std::env::temp_dir().to_string_lossy().into_owned()
    }

    fn test_environment() -> EnvironmentProjection {
        let system_root =
            std::env::var("SystemRoot").unwrap_or_else(|_| panic!("SystemRoot is not set"));
        let path = format!("{system_root}\\System32;{system_root}");
        load(EnvironmentProjection::new(
            BTreeMap::from([
                ("SystemRoot".to_owned(), system_root),
                ("PATH".to_owned(), path),
            ]),
            Vec::new(),
            EnvironmentInheritance::None,
        ))
    }

    const SUCCESS_BAT: &str = "@echo off\r\necho SLICE-D-BOUNDED-STDOUT\r\nping -n 3 127.0.0.1\r\n";

    fn write_bat(tag: &str, contents: &str) -> String {
        let path = std::env::temp_dir().join(format!("eliot-slice-d-{tag}.bat"));
        std::fs::write(&path, contents).expect("write batch program");
        path.to_string_lossy().into_owned()
    }

    fn remove_bat(tag: &str) {
        let _ = std::fs::remove_file(std::env::temp_dir().join(format!("eliot-slice-d-{tag}.bat")));
    }

    fn build_process(
        operation: &str,
        tree: &str,
        argv: Vec<String>,
        nonce: &str,
    ) -> (ProcessRequest, DispatchPermitAuthority) {
        let generation = load(Generation::new(1));
        let intent = load(ProcessIntent::new(
            load(OperationId::new(operation)),
            load(ProcessTreeId::new(tree)),
            load(JobId::new(format!("job-{operation}"))),
            load(ImageId::new(format!("image-{operation}"))),
            load(ProcessSessionId::new(format!("session-{operation}"))),
            generation,
            executable_path(),
            executable_digest(),
            argv,
            working_directory(),
            test_environment(),
            limits(),
        ));
        let fence = load(FencingToken::new(
            epoch(),
            generation,
            format!("process-fence-{operation}"),
        ));
        let mut authority = DispatchPermitAuthority::activate(
            load(DispatchAuthorityId::new("native-worker-authority")),
            load(KernelDispatchKey::from_secret_bytes([0x5a; 32])),
        );
        let permit = load(authority.issue(
            &intent,
            load(PermitIssuance::new(
                load(ActionLeaseRef::new("native-worker-lease")),
                fence,
                revisions(),
                100,
                10_000,
                nonce,
            )),
        ));
        (load(ProcessRequest::new(intent, permit)), authority)
    }

    fn authority_port(
        authority: DispatchPermitAuthority,
        fence: FencingToken,
    ) -> Arc<dyn DispatchValidationPort> {
        let context = load(DispatchValidationContext::new(
            ClockReading {
                valid_time_ms: Some(150),
                known_time_ms: Some(150),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            epoch(),
            revisions(),
            41,
        ));
        Arc::new(TestAuthorityPort {
            authority: Mutex::new(authority),
            context,
        })
    }

    fn hello() -> WorkerHello {
        WorkerHello {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            encoding_profile: JSON_ENCODING_PROFILE.to_owned(),
            connection_id: "connection-claim-1".to_owned(),
            request_id: "start-claim-1".to_owned(),
            trace_context: BTreeMap::from([("trace_id".to_owned(), "trace-claim-1".to_owned())]),
            deadline_unix_ms: 5_000,
            artifact_manifest_digest: "manifest-digest-1".to_owned(),
            launch_nonce: "launch-nonce-slice-d-1".to_owned(),
            worker_generation: 1,
            authority_epoch: epoch(),
            state_fence: fence(),
            route_ref: "route-1".to_owned(),
            requested_capabilities: BTreeSet::from(["inspect".to_owned()]),
        }
    }

    fn registration() -> NativeWorkerRegistration {
        NativeWorkerRegistration {
            registration_id: load(NativeRegistrationId::new("registration-1")),
            installation_id: "installation-1".to_owned(),
            worker_artifact_digest: "a".repeat(64),
            worker_config_digest: "b".repeat(64),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            worker_generation: 1,
            process_id: 4242,
            process_start_100ns: 120,
            process_image_digest: "c".repeat(64),
            principal_ref: "principal-1".to_owned(),
            session_id: load(SessionId::new("session-operation-1")),
            connection_id: "connection-claim-1".to_owned(),
            authority_epoch: epoch(),
            state_fence: fence(),
            lease_id: "lease-reg-1".to_owned(),
            lease_expires_at_unix_ms: 4_000_000_001_000,
            renewal_id: load(NativeRenewalId::new("renewal-1")),
            execution_unit_schema_version: EXECUTION_UNIT_SCHEMA_VERSION,
            resource_limits: limits(),
            invalidation_set: BTreeSet::new(),
        }
    }

    fn owner_issued_digest() -> String {
        sha256_hex(b"slice-d owner-issued executable digest stand-in")
    }

    fn valid_join(
        registration: &NativeWorkerRegistration,
        hello_value: &WorkerHello,
        process: &ProcessRequest,
    ) -> NativeWorkerExecutableBinding {
        NativeWorkerExecutableBinding {
            route_ref: hello_value.route_ref.clone(),
            adapter_id: "adapter-test".to_owned(),
            adapter_revision: 3,
            config_digest: registration.worker_config_digest.clone(),
            facet_manifest_ref: "facet-manifest-7".to_owned(),
            grant_graph_revision: 5,
            replay_stream_id: "claim-1/gen-1".to_owned(),
            launch_nonce: hello_value.launch_nonce.clone(),
            process_invocation_digest: process.invocation_digest().to_owned(),
            authority_epoch: epoch(),
            generation: load(ResourceGeneration::new(1)),
            state_fence: fence(),
            deadline_unix_ms: 8_000,
            expires_at_unix_ms: 4_000_000_001_000,
            executable_wire_version: NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
            executable_binding_digest: owner_issued_digest(),
        }
    }

    fn claim_for(
        registration: &NativeWorkerRegistration,
        hello_value: &WorkerHello,
        process: &ProcessRequest,
    ) -> NativeWorkerClaim {
        let join = valid_join(registration, hello_value, process);
        let draft = NativeWorkerClaim {
            claim_id: load(NativeClaimId::new("claim-1")),
            registration_id: registration.registration_id.clone(),
            worker_generation: 1,
            parent_job_id: "job-parent-1".to_owned(),
            task_id: load(TaskId::new("task-1")),
            work_scope_id: "scope-1".to_owned(),
            decision_id: load(DecisionId::new("decision-1")),
            attempt_id: load(eliot_native_worker_core::AttemptId::new("attempt-1")),
            operation_id: process.operation_id().clone(),
            route_class: "test-route".to_owned(),
            budget: BudgetEnvelope {
                context_tokens: 100,
                wall_time_ms: 4_000,
                output_bytes: 4_096,
                cost_microunits: 1_000,
                max_depth: 4,
                max_descendants: 8,
            },
            deadline_unix_ms: 4_000_000_000_000,
            cancellation_policy_id: "policy-1".to_owned(),
            expected_result_schema: "result-schema-1".to_owned(),
            expected_result_schema_version: 1,
            predecessor_revision: "rev-0".to_owned(),
            authority_epoch: epoch(),
            state_fence: fence(),
            wire_version: NATIVE_WORKER_CLAIM_WIRE_VERSION,
            executable_binding: Some(join),
            binding_digest: String::new(),
        };
        load(draft.with_computed_digest())
    }

    fn claim_request(
        registration: &NativeWorkerRegistration,
        claim: &NativeWorkerClaim,
    ) -> ClaimAdmissionRequest {
        load(serde_json::from_value(serde_json::json!({
            "registration": registration,
            "claim": claim,
        })))
    }

    fn readiness_for(claim: &NativeWorkerClaim) -> eliot_native_worker_core::ReadinessSubmission {
        let report = serde_json::json!({
            "ready_id": "ready-1",
            "claim_id": claim.claim_id.as_str(),
            "registration_id": claim.registration_id.as_str(),
            "worker_generation": claim.worker_generation,
            "authority_epoch": serde_json::to_value(&claim.authority_epoch).expect("epoch"),
            "state_fence": serde_json::to_value(&claim.state_fence).expect("fence"),
            "claim_binding_digest": claim.binding_digest.as_str(),
            "adapter_registry_revision": "test-revision-1",
            "credential_refs": [],
            "ready_at_unix_ms": 8_000,
        });
        load(serde_json::from_value(serde_json::json!({
            "claim": claim,
            "readiness": {"kind": "READY", "payload": report},
        })))
    }

    fn reconcile_for(claim: &NativeWorkerClaim) -> eliot_native_worker::ReconcileSubmission {
        eliot_native_worker::ReconcileSubmission::new("reconcile-1".to_owned(), claim.clone(), None)
    }

    fn health_frame() -> WorkerFrame {
        let lease: WorkLeaseId = load(serde_json::from_value(
            serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"}),
        ));
        WorkerFrame {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            encoding_profile: JSON_ENCODING_PROFILE.to_owned(),
            connection_id: "connection-claim-1".to_owned(),
            request_id: "health-1".to_owned(),
            trace_context: BTreeMap::from([("trace_id".to_owned(), "trace-health-1".to_owned())]),
            deadline_unix_ms: 5_000,
            authority_epoch: epoch(),
            state_fence: fence(),
            lease_id: lease,
            admission_revision: "admission-revision-1".to_owned(),
            producer_generation: 1,
            body: WorkerFrameBody::Health,
        }
    }

    fn encode_frame(frame: &WorkerFrame) -> Vec<u8> {
        let body = serde_json::to_vec(frame).expect("frame");
        let mut out = u32::try_from(body.len())
            .expect("len")
            .to_le_bytes()
            .to_vec();
        out.extend_from_slice(&body);
        out
    }

    fn decode_response(bytes: &[u8]) -> eliot_native_worker::WorkerResponse {
        let (prefix, body) = bytes.split_at(4);
        let length = u32::from_le_bytes(prefix.try_into().expect("prefix")) as usize;
        assert_eq!(length, body.len());
        serde_json::from_slice(body).expect("response")
    }

    type SliceDWorker = NativeWorker<
        WindowsProcessExecutor,
        TestAdmission,
        KernelReplayPort<FakeTransport>,
        TestCheckpoint,
    >;

    #[allow(clippy::too_many_lines)]
    #[test]
    #[cfg(windows)]
    fn admitted_claim_material_reaches_ready_and_serves_while_absence_and_refusal_stay_78() {
        let bat = write_bat("drive", SUCCESS_BAT);
        let argv = vec!["/c".to_owned(), bat.clone()];
        let (process, authority) = build_process(
            "operation-slice-d-1",
            "tree-slice-d-1",
            argv,
            "nonce-slice-d-1",
        );
        let hello_value = hello();
        let registration = registration();
        let claim_value = claim_for(&registration, &hello_value, &process);
        let admission = claim_request(&registration, &claim_value);
        let reconcile = reconcile_for(&claim_value);
        let readiness = readiness_for(&claim_value);

        // Stage the Kernel-deliverable bytes: the exact envelope the dispatch
        // contour writes next to the binary. The in-memory process plus the
        // composed ports stand in for the T9-07 launch seam.
        let envelope = AdmittedClaimEnvelope {
            admission: admission.clone(),
            hello: hello_value.clone(),
            reconcile: reconcile.clone(),
            readiness: readiness.clone(),
            nonce: hello_value.launch_nonce.clone(),
        };
        let staged = std::env::temp_dir().join("eliot-slice-d-admitted-claim.json");
        std::fs::write(
            &staged,
            serde_json::to_vec(&envelope).expect("envelope bytes"),
        )
        .expect("stage envelope");

        // Admitted bytes validate, bind the session nonce, and are consumed
        // once — the admitted arm they open never emits the deferred line.
        let material = read_admitted_material_from(&staged)
            .expect("valid envelope must read")
            .expect("valid envelope must be present");
        assert!(!staged.exists(), "validated material must be consumed once");
        assert_eq!(material.nonce, hello_value.launch_nonce);
        assert_eq!(
            material.admission.claim().binding_digest,
            claim_value.binding_digest
        );

        // T9-07 (WRITER-B): the validated material resolves to exactly one
        // factory through the registry seam — no default, no ambiguity.
        let selection = match select_factory_for_admitted(&material) {
            Ok(selection) => selection,
            Err(error) => panic!("factory selection must resolve, got {error:?}"),
        };
        assert_eq!(selection.adapter_id, "adapter-test");
        assert_eq!(selection.adapter_revision, 3);
        assert_eq!(selection.route_ref, "route-1");
        assert_eq!(
            selection.process_invocation_digest,
            process.invocation_digest()
        );

        // The validated material drives the exact admitted contour to `Ready`
        // through the real executor: no deferred line, no exit 78.
        let port = authority_port(authority, process.fence().clone());
        let executor = WindowsProcessExecutor::new(port);
        let admissions = Arc::new(Mutex::new(0_usize));
        let test_admission = TestAdmission {
            admissions: Arc::clone(&admissions),
        };
        let transport = FakeTransport::new(&claim_value);
        let replay = KernelReplayPort::new(transport, claim_value.clone(), registration.clone())
            .unwrap_or_else(|_| panic!("replay port binds"));
        let evidence = Arc::new(Mutex::new(Vec::new()));
        let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(RecordingSink {
            evidence: Arc::clone(&evidence),
        });
        let core = WorkerCore::new(
            Some(executor),
            Some(test_admission),
            Some(replay),
            Some(TestCheckpoint),
            Some(sink),
        );
        let mut worker: SliceDWorker = NativeWorker::new(core);
        let mut lifecycle = FakeLifecycle::new();
        let ready = block_on(drive_admitted_claimed(
            &mut lifecycle,
            &mut worker,
            &registration,
            &material.admission,
            material.hello,
            process,
            &material.reconcile,
            &material.readiness,
        ))
        .unwrap_or_else(|error| panic!("admitted drive must reach Ready, got {error:?}"));
        assert_eq!(worker.lifecycle(), WorkerLifecycle::Ready);
        assert_eq!(ready.request_id, "start-claim-1");
        assert_eq!(ready.stream_id, "claim-1/gen-1");
        assert_eq!(*lock(&admissions), 1);
        assert_eq!(lock(&evidence).len(), 1);

        // One admitted contour serves a bounded frame with durable events.
        let frame = health_frame();
        let mut reader = Cursor::new(encode_frame(&frame));
        let mut writer = Vec::new();
        let shutdown = block_on(worker.serve_one_frame(&mut reader, &mut writer))
            .unwrap_or_else(|error| panic!("bounded frame must serve, got {error:?}"));
        assert!(!shutdown);
        let response = decode_response(&writer);
        assert!(!response.events.is_empty());
        assert!(
            response
                .events
                .iter()
                .all(|event| event.stream_id == "claim-1/gen-1")
        );

        // Missing delivery stays the fail-closed 78 without admission work.
        let missing = read_admitted_material_from(
            &std::env::temp_dir().join("eliot-slice-d-absent-claim.json"),
        )
        .expect("missing file is absence, not an error");
        assert!(missing.is_none());
        assert_eq!(deny_absent_material(), KERNEL_ADMISSION_EXIT);

        // Refused delivery (a nonce the hello never presented) stays a typed
        // 78 denial and never drives.
        let mut refused = envelope.clone();
        refused.nonce = "refused-nonce-slice-d-1".to_owned();
        std::fs::write(
            &staged,
            serde_json::to_vec(&refused).expect("refused bytes"),
        )
        .expect("stage refused envelope");
        let denied = read_admitted_material_from(&staged).expect_err("refused nonce must deny");
        assert_eq!(
            deny_invalid_material(&denied.to_string()),
            KERNEL_ADMISSION_EXIT
        );
        let _ = std::fs::remove_file(&staged);

        // A route-rewired presentation reads (the envelope reader does not
        // own route selection) but resolves to no factory: typed 78, never
        // the deferred line, never a drive.
        let mut rewired = envelope.clone();
        rewired.hello.route_ref = "rewired-route-slice-d-1".to_owned();
        let rewired_bytes = match serde_json::to_vec(&rewired) {
            Ok(bytes) => bytes,
            Err(error) => panic!("rewired envelope must encode: {error:?}"),
        };
        match std::fs::write(&staged, rewired_bytes) {
            Ok(()) => {}
            Err(error) => panic!("rewired envelope must stage: {error:?}"),
        }
        let rewired_material = match read_admitted_material_from(&staged) {
            Ok(Some(material)) => material,
            Ok(None) => panic!("rewired envelope must be present"),
            Err(error) => panic!("rewired envelope must read: {error:?}"),
        };
        let Err(unresolved) = select_factory_for_admitted(&rewired_material) else {
            panic!("rewired route must not resolve")
        };
        assert!(matches!(
            unresolved,
            NativeWorkerError::KernelAdmissionRequired(_)
        ));
        assert_eq!(
            deny_invalid_material(&unresolved.to_string()),
            KERNEL_ADMISSION_EXIT
        );
        let _ = std::fs::remove_file(&staged);

        // Exit projection: only missing or refused admission exits 78.
        assert_eq!(deny_transport("test detail"), KERNEL_ADMISSION_EXIT);
        assert_eq!(deny_dispatch_residual(), KERNEL_ADMISSION_EXIT);
        // The admitted arm never emits the deferred line: factory refusals
        // and the dispatch residual both carry the admission-required code,
        // which is distinct from the missing-material deferral.
        assert_ne!(
            eliot_native_worker::KERNEL_ADMISSION_REQUIRED,
            PROVIDER_RUNTIME_DEFERRED
        );
        assert_ne!(ADMITTED_DISPATCH_RESIDUAL, PROVIDER_RUNTIME_DEFERRED);
        assert_eq!(
            exit_for_drive_error(&NativeWorkerError::KernelAdmissionRequired(
                "Kernel refused the presentation".to_owned()
            )),
            KERNEL_ADMISSION_EXIT
        );
        assert_eq!(
            exit_for_drive_error(&NativeWorkerError::Core(
                eliot_native_worker_core::WorkerError::InvalidRequest("claim_operation")
            )),
            KERNEL_ADMISSION_EXIT
        );
        assert_eq!(
            exit_for_drive_error(&NativeWorkerError::Core(
                eliot_native_worker_core::WorkerError::Process("P-03 start failed".to_owned())
            )),
            ADMITTED_DRIVE_FAILED_EXIT
        );
        assert_ne!(ADMITTED_DRIVE_FAILED_EXIT, KERNEL_ADMISSION_EXIT);

        remove_bat("drive");
    }
}
