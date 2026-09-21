//! WASM P-03 process adapter: the owner-blessed A-12 port implementation.
//!
//! This module implements [`P03ProcessPort`] and [`P03ReceiptVerifierPort`]
//! (both owned by the neutral A-12 `eliot-wasm-runtime` facade) on top of the
//! real [`ProcessExecutor`] owned by this crate, so the WASM host can seat
//! genuine P-03 process authority inside the sealed A-12 pipeline instead of
//! agreeing with the neutral crate's private test mocks.
//!
//! ## Authority stance (fail-closed)
//!
//! This adapter mints nothing. It holds no key, no permit authority, and no
//! issuer capability of any kind, per the P-04 rule that the physical executor
//! never becomes a second authority owner (see
//! [`eliot_process::DispatchPermitAuthority`], whose production instance stays
//! with the P-07/Kernel lane). A Kernel-admitted [`ProcessRequest`] enters
//! through [`WasmP03ProcessAdapter::stage_admitted_request`] — the existing
//! P-03 contract for an intent bound to an issued one-shot permit — and
//! [`P03ProcessPort::prepare`] only binds that staged admission to the
//! presented [`ProcessLaunchEnvelope`]. With no staged admission, `prepare`
//! returns [`PortError::Unavailable`]: unknown authority is never manufactured
//! as ready.
//!
//! The adapter keeps no operation registry, no job table, and spawns no child
//! directly: `start`, `cancel`, and `reconcile` delegate verbatim to the
//! injected executor, which remains the sole owner of process state. The async
//! executor boundary is driven synchronously on the calling thread using this
//! crate's established spin recipe; no async runtime is required.
//!
//! ## Dependency note
//!
//! This crate depends on `eliot-wasm-runtime` for the port contracts only
//! (traits plus the envelope/binding carriers). The edge runs contract →
//! adapter: the neutral facade owns no process implementation and gains none
//! here, so no dependency cycle and no second owner are created.
//!
//! ## Proof
//!
//! `cargo test --offline -p eliot-process-executor wasm_p03` drives the
//! adapter against the real [`WindowsProcessExecutor`] with real suspended
//! Windows children. `reconcile` is poll-safe: while the child is still
//! driving it reports [`PortError::UnknownOutcome`] via a non-destructive
//! `inspect` guard (the executor's terminal-only reconcile would otherwise
//! join live capture streams and quarantine the op), so callers retry; an
//! already-unknown op still passes through to the executor's
//! quarantine-reconcile path. The Governor-side ports stay out of scope (see
//! the `1955-owner-ports-handoff.md` lane handoff held by root).
//!
//! Documentation route `sha256:2a9f0ffe…`, read receipt `sha256:5c4f2dab…`,
//! bundle `sha256:dbe40aaf…` (39/39 required items read before mutation).

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use eliot_process::{
    CancellationReceipt, ContractError, ProcessEvidence, ProcessEvidenceSink,
    ProcessExecutionError, ProcessExecutor, ProcessLifecycle, ProcessRequest, ProcessStartReceipt,
};
use eliot_wasm_runtime::{
    P03ProcessPort, P03ReceiptVerifierPort, PortError, ProcessBinding, ProcessLaunchEnvelope,
};

use crate::WindowsProcessExecutor;

/// Owner-blessed A-12 P-03 adapter fronting the real process executor.
///
/// Construct with the production [`WindowsProcessExecutor`] (wired to the
/// P-07 validation port and the Kernel launch admission by composition) and
/// the evidence sink the owning lane designated. The Kernel lane hands one
/// admitted [`ProcessRequest`] per invocation through
/// [`stage_admitted_request`](Self::stage_admitted_request); `prepare` binds
/// it to the envelope exactly once and drops the slot either way, so staged
/// material can never serve two invocations.
pub struct WasmP03ProcessAdapter {
    executor: Arc<WindowsProcessExecutor>,
    sink: Arc<dyn ProcessEvidenceSink>,
    staged: Mutex<Option<ProcessRequest>>,
}

impl WasmP03ProcessAdapter {
    /// Composes the adapter around a real executor and its evidence sink.
    pub fn new(executor: Arc<WindowsProcessExecutor>, sink: Arc<dyn ProcessEvidenceSink>) -> Self {
        Self {
            executor,
            sink,
            staged: Mutex::new(None),
        }
    }

    /// Stages one Kernel-admitted request for the next `prepare` call.
    ///
    /// The request is revalidated here so malformed authority material fails
    /// closed at the handoff, not inside the sealed pipeline. A second stage
    /// without an intervening `prepare` is rejected: the slot carries exactly
    /// one invocation's admission, never a queue.
    ///
    /// # Errors
    ///
    /// Returns a [`ContractError`] when the request is invalid, the slot is
    /// already occupied, or the slot lock is poisoned.
    pub fn stage_admitted_request(&self, request: ProcessRequest) -> Result<(), ContractError> {
        request.validate()?;
        let mut staged = self
            .staged
            .lock()
            .map_err(|_| ContractError::InvalidValue {
                field: "wasm_p03_admission_slot",
                reason: "admission slot lock poisoned",
            })?;
        if staged.is_some() {
            return Err(ContractError::DuplicateValue {
                field: "wasm_p03_admission_slot",
            });
        }
        *staged = Some(request);
        Ok(())
    }

    fn take_staged(&self) -> Result<ProcessRequest, PortError> {
        let mut staged = self.staged.lock().map_err(|_| PortError::UnknownOutcome)?;
        staged.take().ok_or(PortError::Unavailable)
    }
}

impl P03ProcessPort for WasmP03ProcessAdapter {
    fn prepare(&mut self, envelope: &ProcessLaunchEnvelope) -> Result<ProcessRequest, PortError> {
        let staged = self.take_staged()?;
        staged.validate().map_err(|_| PortError::Denied)?;
        if !envelope_binds(&staged, envelope) {
            return Err(PortError::Denied);
        }
        Ok(staged)
    }

    fn start(&mut self, request: ProcessRequest) -> Result<ProcessStartReceipt, PortError> {
        let sink = Arc::clone(&self.sink);
        drive_blocking(self.executor.start(request, sink)).map_err(map_start_error)
    }

    fn cancel(&mut self, binding: &ProcessBinding) -> Result<CancellationReceipt, PortError> {
        drive_blocking(self.executor.cancel(binding.operation_id().clone()))
            .map_err(map_observe_error)
    }

    fn reconcile(&mut self, binding: &ProcessBinding) -> Result<ProcessEvidence, PortError> {
        let operation_id = binding.operation_id().clone();
        // Poll-safe guard (root cause of the `verifiers_reject_foreign_binding`
        // `UnknownOutcome` abort): the executor's `reconcile` is terminal-only.
        // It joins — cancelling — live capture streams and quarantines the
        // operation on any join gap, so invoking it while the child is still
        // driving both fails AND fences the op. `inspect` only refreshes the
        // lifecycle view and never touches capture threads, so while the op is
        // still driving we report the outcome as unknown and let the caller
        // retry with nothing fenced. An already-unknown op passes through, so
        // the executor's quarantine-reconcile path still runs unchanged.
        let view = drive_blocking(self.executor.inspect(operation_id.clone()))
            .map_err(map_observe_error)?;
        if matches!(
            view.lifecycle(),
            ProcessLifecycle::Created
                | ProcessLifecycle::Starting
                | ProcessLifecycle::Running
                | ProcessLifecycle::Cancelling
        ) {
            return Err(PortError::UnknownOutcome);
        }
        drive_blocking(self.executor.reconcile(operation_id)).map_err(map_observe_error)
    }
}

impl P03ReceiptVerifierPort for WasmP03ProcessAdapter {
    fn verify_start(
        &mut self,
        binding: &ProcessBinding,
        receipt: &ProcessStartReceipt,
        envelope: &ProcessLaunchEnvelope,
    ) -> Result<(), PortError> {
        let coherent = receipt.operation_id() == binding.operation_id()
            && receipt.request_digest() == binding.request_digest()
            && receipt.accepted_generation() == binding.generation()
            && receipt.binding().state_fence().matches(binding.fence())
            && matches!(
                receipt.lifecycle(),
                ProcessLifecycle::Starting | ProcessLifecycle::Running
            )
            && same_lease_authority(binding, envelope);
        if coherent {
            Ok(())
        } else {
            Err(PortError::Denied)
        }
    }

    fn verify_cancellation(
        &mut self,
        binding: &ProcessBinding,
        receipt: &CancellationReceipt,
        envelope: &ProcessLaunchEnvelope,
    ) -> Result<(), PortError> {
        let observed = receipt.binding();
        let coherent = observed.operation_id() == binding.operation_id()
            && observed.process_tree_id() == binding.process_tree_id()
            && observed.request_digest() == binding.request_digest()
            && observed.state_fence().matches(binding.fence())
            && same_lease_authority(binding, envelope);
        if coherent {
            Ok(())
        } else {
            Err(PortError::Denied)
        }
    }

    fn verify_reconciliation(
        &mut self,
        binding: &ProcessBinding,
        evidence: &ProcessEvidence,
        envelope: &ProcessLaunchEnvelope,
    ) -> Result<(), PortError> {
        let observed = evidence.binding();
        let coherent = observed.operation_id() == binding.operation_id()
            && observed.process_tree_id() == binding.process_tree_id()
            && observed.request_digest() == binding.request_digest()
            && observed.state_fence().matches(binding.fence())
            && same_lease_authority(binding, envelope);
        if coherent {
            Ok(())
        } else {
            Err(PortError::Denied)
        }
    }
}

/// Checks the staged request against the envelope it must serve.
///
/// This mirrors the neutral facade's `validate_process_binding` gate so a
/// misbound admission is denied at the owner boundary with the same fields
/// the pipeline re-checks: operation, tree, generation, fence epoch and
/// generation, and the wall/memory/stdout ceilings.
fn envelope_binds(request: &ProcessRequest, envelope: &ProcessLaunchEnvelope) -> bool {
    request.operation_id().as_str() == envelope.invocation_id.as_str()
        && request.process_tree_id().as_str() == envelope.work_scope.work_scope.to_string()
        && request.generation().get() == envelope.generation.generation.value()
        && request
            .fence()
            .authority_epoch()
            .is_same_authority(&envelope.lease.state_fence.authority_epoch)
        && request.fence().generation().get() == envelope.generation.generation.value()
        && request.resource_limits().wall_timeout_ms() == envelope.limits.wall_deadline_ms
        && request.resource_limits().memory_bytes() == Some(envelope.limits.max_memory_bytes)
        && request.resource_limits().stdout_bytes() == envelope.limits.max_output_bytes
}

/// Checks the binding fence epoch against the envelope lease epoch.
fn same_lease_authority(binding: &ProcessBinding, envelope: &ProcessLaunchEnvelope) -> bool {
    binding
        .fence()
        .authority_epoch()
        .is_same_authority(&envelope.lease.state_fence.authority_epoch)
}

/// Maps a real executor `start` failure onto the port contract.
///
/// A contract rejection means the request itself was denied by the owning
/// authority; unavailability means the physical executor is absent; every
/// other outcome (including a sink rejection) leaves the outcome unknown
/// rather than manufacturing a denial or an acceptance.
fn map_start_error(error: ProcessExecutionError) -> PortError {
    match error {
        ProcessExecutionError::Contract(_) => PortError::Denied,
        ProcessExecutionError::Unavailable(_) => PortError::Unavailable,
        ProcessExecutionError::NotFound
        | ProcessExecutionError::EvidenceSink(_)
        | ProcessExecutionError::UnknownOutcome => PortError::UnknownOutcome,
    }
}

/// Maps a real executor `cancel`/`reconcile` failure onto the port contract.
///
/// Observation failures leave the outcome unknown; only a missing physical
/// executor surfaces as unavailable.
fn map_observe_error(error: ProcessExecutionError) -> PortError {
    match error {
        ProcessExecutionError::Unavailable(_) => PortError::Unavailable,
        _ => PortError::UnknownOutcome,
    }
}

/// Drives one already-created executor future to completion on the calling
/// thread, using this crate's established spin recipe: the executor futures
/// are thread-driven, so a `yield_now` spin terminates without an async
/// runtime and without inventing a second executor or scheduler.
fn drive_blocking<F: Future>(future: F) -> F::Output {
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

#[cfg(windows)]
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_platform::ClockObservation;
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
        EnvironmentProjection, EvidenceSinkError, FencingToken, Generation, ImageId, JobId,
        KernelDispatchKey, OperationId, PermitIssuance, ProcessIntent, ProcessLifecycle,
        ProcessRequest, ProcessTreeId, ResourceLimits, SessionId, SuspendedProcessIdentity,
        ValidatedDispatch,
    };
    use eliot_wasm_runtime::{
        ArtifactAccessLimits, CancellationPolicy, EpochPolicy, InvocationId, InvocationLimits,
        OwnerId, ProcessBinding, ProcessLaunchEnvelope, Revision, Sha256Digest, WorkUnitId,
    };
    use serde_json::json;

    use super::*;
    use crate::DispatchValidationPort;

    fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("wasm-p03 fixture failed: {error:?}"),
        }
    }

    fn test_epoch(sequence: u64) -> EpochId {
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn revisions() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("authority".to_owned(), "a".repeat(64)),
            ("state".to_owned(), "b".repeat(64)),
        ])
    }

    /// Test-only permit authority. Production issuance belongs to the
    /// Kernel/P-07 lane; this test plays that lane exactly as this crate's
    /// own executor tests do, with key material that never leaves test code.
    fn test_authority() -> DispatchPermitAuthority {
        DispatchPermitAuthority::activate(
            must(DispatchAuthorityId::new("wasm-p03-test-authority")),
            must(KernelDispatchKey::from_secret_bytes([0x5a; 32])),
        )
    }

    struct FakePort {
        authority: Mutex<DispatchPermitAuthority>,
        context: DispatchValidationContext,
    }

    impl FakePort {
        fn new(authority: DispatchPermitAuthority, fence: FencingToken) -> Self {
            let context = must(DispatchValidationContext::new(
                ClockObservation {
                    valid_time_ms: Some(150),
                    known_time_ms: Some(150),
                    transaction_sequence: None,
                    monotonic_ns: Some(1),
                },
                fence,
                test_epoch(1),
                revisions(),
                41,
            ));
            Self {
                authority: Mutex::new(authority),
                context,
            }
        }
    }

    impl DispatchValidationPort for FakePort {
        fn validate_and_consume(
            &self,
            request: ProcessRequest,
            observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            let mut authority = self.authority.lock().map_err(|_| {
                ProcessExecutionError::Unavailable("dispatch authority lock poisoned".to_owned())
            })?;
            authority
                .validate_and_consume(request, observed, &self.context)
                .map_err(Into::into)
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        evidence: Mutex<Vec<ProcessEvidence>>,
    }

    impl ProcessEvidenceSink for RecordingSink {
        fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
            match self.evidence.lock() {
                Ok(mut guard) => {
                    guard.push(evidence);
                    Ok(())
                }
                Err(_) => Err(EvidenceSinkError {
                    message: "recording sink lock poisoned".to_owned(),
                }),
            }
        }
    }

    impl RecordingSink {
        fn recorded_len(&self) -> usize {
            match self.evidence.lock() {
                Ok(guard) => guard.len(),
                Err(_) => usize::MAX,
            }
        }
    }

    fn envelope(tag: &str) -> ProcessLaunchEnvelope {
        let manifest = must(serde_json::from_value(json!({
            "component_id": "component-1",
            "world": "eliot:test/world",
            "wit_version": "1.0.0",
            "guest_target": "wasm32-wasip2",
            "artifact_digest": "a".repeat(64),
            "interface_digest": "b".repeat(64),
            "source_digest": "c".repeat(64),
            "configuration_digest": "d".repeat(64),
            "state_contract_digest": "e".repeat(64),
            "imports": ["log"],
            "exports": ["run"],
            "admitted_privacy_classes": ["INTERNAL"],
            "required_verifier": "verifier:a12",
            "engine": {
                "implementation_id": "engine.test.v1",
                "exact_version": "1.2.3",
                "engine_artifact_digest": "8".repeat(64),
                "engine_configuration_digest": "9".repeat(64),
                "wit_interface_digest": "b".repeat(64)
            }
        })));
        let generation = must(serde_json::from_value(json!({
            "module_id": "component-1",
            "generation": 1,
            "artifact_id": "a".repeat(64),
            "state": "READY",
            "health": {
                "liveness": "HEALTHY", "readiness": "HEALTHY",
                "freshness": "HEALTHY", "compatibility": "HEALTHY",
                "integrity": "HEALTHY", "capacity": "HEALTHY"
            },
            "state_fence": {
                "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 1},
                "resource_generation": 1,
                "task_revision": 1, "policy_revision": 1,
                "integration_revision": null
            }
        })));
        let lease = must(serde_json::from_value(json!({
            "lease_id": "lease-1",
            "scope_ref": "wasm-p03-scope",
            "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 1},
            "state_fence": {
                "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 1},
                "resource_generation": 1,
                "task_revision": 1, "policy_revision": 1,
                "integration_revision": null
            },
            "state": "ACTIVE"
        })));
        let work_scope = must(serde_json::from_value(json!({
            "work_scope": "wasm-p03-scope",
            "task_ref": "task-1",
            "attempt_ref": "work-1",
            "module_or_route_ref": "component-1"
        })));
        ProcessLaunchEnvelope {
            invocation_id: must(InvocationId::new(format!("wasm-p03-op-{tag}"))),
            request_digest: Sha256Digest::of_bytes(format!("wasm-p03-request-{tag}").as_bytes()),
            owner: must(OwnerId::new("owner-1")),
            work_unit: must(WorkUnitId::new("work-1")),
            work_scope,
            manifest,
            generation,
            lease,
            authority_revision: must(Revision::new(1)),
            lifecycle_revision: must(Revision::new(1)),
            limits: InvocationLimits {
                max_input_bytes: 128,
                max_output_bytes: 4_096,
                max_host_calls: 4,
                max_fuel: 1_000,
                max_memory_bytes: 512_000_000,
                max_table_elements: 64,
                max_instances: 2,
                max_stack_bytes: 8_192,
                wall_deadline_ms: 60_000,
                epoch: EpochPolicy {
                    deadline_ticks: 50,
                    cancellation: CancellationPolicy::EpochAndFuel,
                },
                artifact_access: ArtifactAccessLimits {
                    allowed_digests: [Sha256Digest::of_bytes(b"a")].into_iter().collect(),
                    max_reads: 2,
                    max_bytes: 1_024,
                },
            },
        }
    }

    /// Builds the Kernel-side admission for one envelope: intent plus a permit
    /// issued by the test authority. In production this construction belongs
    /// to the Kernel/P-07 lane; the test plays that lane with test-only key
    /// material, exactly as this crate's own executor tests do.
    fn admitted_request(
        authority: &mut DispatchPermitAuthority,
        envelope: &ProcessLaunchEnvelope,
        argv: Vec<String>,
    ) -> ProcessRequest {
        let executable = r"C:\Windows\System32\cmd.exe";
        let digest = must(crate::sha256_file(std::path::Path::new(executable)));
        let generation = must(Generation::new(envelope.generation.generation.value()));
        let working_directory = must(std::env::temp_dir().to_str().map(str::to_owned).ok_or(
            eliot_process::ContractError::InvalidValue {
                field: "working_directory",
                reason: "temp directory is not valid unicode",
            },
        ));
        let intent = must(ProcessIntent::new(
            must(OperationId::new(envelope.invocation_id.as_str())),
            must(ProcessTreeId::new(
                envelope.work_scope.work_scope.to_string(),
            )),
            must(JobId::new(format!(
                "job-{}",
                envelope.invocation_id.as_str()
            ))),
            must(ImageId::new(format!(
                "image-{}",
                envelope.invocation_id.as_str()
            ))),
            must(SessionId::new(format!(
                "session-{}",
                envelope.invocation_id.as_str()
            ))),
            generation,
            executable,
            digest,
            argv,
            working_directory,
            EnvironmentProjection::default(),
            must(ResourceLimits::new(
                envelope.limits.wall_deadline_ms,
                Some(10_000),
                Some(envelope.limits.max_memory_bytes),
                envelope.limits.max_output_bytes,
                envelope.limits.max_output_bytes,
                4,
            )),
        ));
        let fence = must(FencingToken::new(
            test_epoch(1),
            generation,
            format!("fence-{}", envelope.invocation_id.as_str()),
        ));
        let permit = must(authority.issue(
            &intent,
            must(PermitIssuance::new(
                must(ActionLeaseRef::new(format!(
                    "lease-{}",
                    envelope.invocation_id.as_str()
                ))),
                fence,
                revisions(),
                100,
                120_000,
                format!("nonce-{}", envelope.invocation_id.as_str()),
            )),
        ));
        must(ProcessRequest::new(intent, permit))
    }

    fn fence_for(envelope: &ProcessLaunchEnvelope) -> FencingToken {
        must(FencingToken::new(
            test_epoch(1),
            must(Generation::new(envelope.generation.generation.value())),
            format!("fence-{}", envelope.invocation_id.as_str()),
        ))
    }

    fn adapter_with(
        authority: DispatchPermitAuthority,
        fence: FencingToken,
    ) -> (WasmP03ProcessAdapter, Arc<RecordingSink>) {
        let executor = Arc::new(WindowsProcessExecutor::new(Arc::new(FakePort::new(
            authority, fence,
        ))));
        let sink = Arc::new(RecordingSink::default());
        let sink_dyn: Arc<dyn ProcessEvidenceSink> = sink.clone();
        let adapter = WasmP03ProcessAdapter::new(executor, sink_dyn);
        (adapter, sink)
    }

    /// Long-running child argv for start/cancel tests.
    fn slow_child() -> Vec<String> {
        vec![
            "/c".to_owned(),
            "ping".to_owned(),
            "-n".to_owned(),
            "30".to_owned(),
            "127.0.0.1".to_owned(),
        ]
    }

    /// Fast-exiting child argv for the reap test.
    fn fast_child() -> Vec<String> {
        vec![
            "/c".to_owned(),
            "ping".to_owned(),
            "-n".to_owned(),
            "2".to_owned(),
            "127.0.0.1".to_owned(),
        ]
    }

    /// Polls the adapter until the executor mints terminal evidence.
    ///
    /// Transient [`PortError::UnknownOutcome`] while the real child is still
    /// driving is retried: the adapter's poll-safe guard reports unknown with
    /// nothing fenced. Only terminal evidence breaks the loop; the deadline
    /// panics instead of passing, so a genuinely unclosable tree can never
    /// slip through as success.
    fn reconcile_terminal(
        adapter: &mut WasmP03ProcessAdapter,
        binding: &ProcessBinding,
    ) -> Result<ProcessEvidence, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match adapter.reconcile(binding) {
                Ok(evidence) => {
                    if evidence.view().lifecycle().is_terminal() {
                        return Ok(evidence);
                    }
                }
                Err(PortError::UnknownOutcome) => {}
                Err(other) => {
                    return Err(format!("reconcile failed while polling: {other:?}").into());
                }
            }
            if Instant::now() > deadline {
                panic!("reconcile did not yield terminal evidence within 20s");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn prepare_without_staged_admission_is_unavailable() {
        let fixture = envelope("unstaged");
        let (mut adapter, _) = adapter_with(test_authority(), fence_for(&fixture));
        assert_eq!(adapter.prepare(&fixture), Err(PortError::Unavailable));
    }

    #[test]
    fn stage_twice_without_prepare_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = envelope("twice");
        let other = envelope("twice-b");
        let (adapter, _) = adapter_with(test_authority(), fence_for(&fixture));
        let mut authority = test_authority();
        let first = admitted_request(&mut authority, &fixture, slow_child());
        adapter.stage_admitted_request(first)?;
        // A second admission — even for a different invocation — is rejected
        // while the slot is occupied.
        let second = admitted_request(&mut authority, &other, slow_child());
        assert!(adapter.stage_admitted_request(second).is_err());
        Ok(())
    }

    #[test]
    fn prepare_binds_staged_admission_to_envelope() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = envelope("bind");
        let (mut adapter, _) = adapter_with(test_authority(), fence_for(&fixture));
        let mut authority = test_authority();
        let staged = admitted_request(&mut authority, &fixture, slow_child());
        let expected_digest = staged.invocation_digest().to_owned();
        adapter.stage_admitted_request(staged)?;
        let prepared = adapter.prepare(&fixture)?;
        assert_eq!(prepared.invocation_digest(), expected_digest);
        // The slot is consumed exactly once: a second prepare has no admission.
        assert_eq!(adapter.prepare(&fixture), Err(PortError::Unavailable));
        Ok(())
    }

    #[test]
    fn prepare_rejects_foreign_envelope() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = envelope("foreign-a");
        let other = envelope("foreign-b");
        let (mut adapter, _) = adapter_with(test_authority(), fence_for(&fixture));
        let mut authority = test_authority();
        adapter.stage_admitted_request(admitted_request(&mut authority, &fixture, slow_child()))?;
        assert_eq!(adapter.prepare(&other), Err(PortError::Denied));
        Ok(())
    }

    #[test]
    fn start_mints_real_receipt_and_start_verifier_accepts()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = envelope("start");
        // The issuing authority and the validating authority are the same
        // instance: the one-shot nonce ledger lives in memory, so issuance
        // must precede the move into the executor's validation port.
        let mut authority = test_authority();
        let staged = admitted_request(&mut authority, &fixture, slow_child());
        let (mut adapter, sink) = adapter_with(authority, fence_for(&fixture));
        adapter.stage_admitted_request(staged)?;
        let prepared = adapter.prepare(&fixture)?;
        let binding = ProcessBinding::from_request(&prepared);
        let receipt = adapter.start(prepared)?;
        assert!(sink.recorded_len() >= 1);
        assert!(matches!(
            receipt.lifecycle(),
            ProcessLifecycle::Starting | ProcessLifecycle::Running
        ));
        adapter.verify_start(&binding, &receipt, &fixture)?;
        Ok(())
    }

    #[test]
    fn reconcile_reaps_exited_child_and_reconciliation_verifier_accepts()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = envelope("reap");
        let mut authority = test_authority();
        let staged = admitted_request(&mut authority, &fixture, fast_child());
        let (mut adapter, _) = adapter_with(authority, fence_for(&fixture));
        adapter.stage_admitted_request(staged)?;
        let prepared = adapter.prepare(&fixture)?;
        let binding = ProcessBinding::from_request(&prepared);
        let receipt = adapter.start(prepared)?;
        let _ = receipt;
        let evidence = reconcile_terminal(&mut adapter, &binding)?;
        adapter.verify_reconciliation(&binding, &evidence, &fixture)?;
        Ok(())
    }

    #[test]
    fn cancel_terminates_long_child_and_cancellation_verifier_accepts()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = envelope("cancel");
        let mut authority = test_authority();
        let staged = admitted_request(&mut authority, &fixture, slow_child());
        let (mut adapter, _) = adapter_with(authority, fence_for(&fixture));
        adapter.stage_admitted_request(staged)?;
        let prepared = adapter.prepare(&fixture)?;
        let binding = ProcessBinding::from_request(&prepared);
        let receipt = adapter.start(prepared)?;
        let _ = receipt;
        let cancellation = adapter.cancel(&binding)?;
        adapter.verify_cancellation(&binding, &cancellation, &fixture)?;
        Ok(())
    }

    #[test]
    fn verifiers_reject_foreign_binding() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = envelope("deny-a");
        let other = envelope("deny-b");
        let mut authority = test_authority();
        let staged = admitted_request(&mut authority, &fixture, fast_child());
        let (mut adapter, _) = adapter_with(authority, fence_for(&fixture));
        adapter.stage_admitted_request(staged)?;
        let prepared = adapter.prepare(&fixture)?;
        let genuine = ProcessBinding::from_request(&prepared);
        let receipt = adapter.start(prepared)?;
        // A binding derived from a different admission is denied everywhere,
        // even against genuine executor-minted material.
        let mut foreign_authority = test_authority();
        let foreign_staged = admitted_request(&mut foreign_authority, &other, slow_child());
        let foreign = ProcessBinding::from_request(&foreign_staged);
        assert_eq!(
            adapter.verify_start(&foreign, &receipt, &fixture),
            Err(PortError::Denied)
        );
        let evidence = reconcile_terminal(&mut adapter, &genuine)?;
        assert_eq!(
            adapter.verify_reconciliation(&foreign, &evidence, &fixture),
            Err(PortError::Denied)
        );
        Ok(())
    }
}
