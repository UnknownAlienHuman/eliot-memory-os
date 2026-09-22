//! Isolated-child guest engine (issue #1955, I14.19).
//!
//! [`IsolatedChildEngine`] is a [`ComponentEnginePort`] that never executes
//! in-process: the guest already ran inside the P03-admitted/reaped child
//! (this binary in one-shot `--guest-exec` mode), and this engine observes
//! that same operation's evidence plus its P03-captured stdout to build the
//! [`EngineReport`]. One operation, one child, one guest execution —
//! pairing this engine with the in-process provider would execute twice,
//! so a composition seats exactly one of them, selected by the admitted
//! manifest engine binding (the runtime already enforces
//! `ports.engine.binding() == manifest.engine` before anything runs).
//!
//! The manifest gate mirrors the Wasmtime provider's exactly (artifact,
//! engine, configuration, stack, world, version, closed imports, single
//! `run` export, input and artifact-access ceilings): a divergent fixture
//! is denied before any observation is read. Non-exited terminals and
//! incomplete captures report [`PortError::UnknownOutcome`] rather than
//! manufacturing output — the bytes must be proven, never assumed.
//!
//! Usage metering honesty: the child Store's observations cross the
//! process boundary ONLY through the strict metering line on captured
//! stderr (schema owned by the guest-runner module). Fuel, peak memory,
//! table, and epoch-tick values below are those child-observed numbers —
//! never parent estimates. A completed run without a parseable metering
//! line reports unknown: unmeasured success is never manufactured.
//! Artifact reads stay zero with an empty digest set: the component bytes
//! were read by the child, not here.

use std::sync::Arc;
use std::time::Instant;

use eliot_process::ProcessLifecycle;
use eliot_process_executor::{WindowsProcessExecutor, wasm_p03_adapter::WasmP03ProcessAdapter};
use eliot_wasm_runtime::{
    CapabilityId, ComponentEnginePort, EngineBinding, EngineInvocation, EngineReport,
    EngineTermination, EngineUsage, P03ProcessPort, PortError, Sha256Digest,
};

use crate::grant_authorization::AuthorizedGrant;
use crate::guest_exec::parse_metering_line;
use crate::shadow::{enforce_shadow_no_effect, shadow_port_error};
use crate::wasmtime_provider::{PROVIDER_STACK_SIZE, WIT_VERSION, WIT_WORLD};

/// Engine implementation identity for the isolated-child contour. The
/// admitted manifest names exactly this; any other binding is refused by
/// the runtime's engine-binding gate before this engine is even invoked.
pub const ISOLATED_CHILD_IMPLEMENTATION_ID: &str = "wasmtime-component-isolated-child";

/// Closed-world `run` export, mirroring the provider world.
const RUN_EXPORT: &str = "run";

/// Child-executing engine bound to one P03 operation owner.
///
/// Constructed around the shared executor (same [`WindowsProcessExecutor`]
/// the P03 ports front, so `reconcile` observes the identical operation —
/// never a second one) plus the admitted engine/artifact identity the
/// manifest gate enforces.
pub struct IsolatedChildEngine {
    process: WasmP03ProcessAdapter,
    executor: Arc<WindowsProcessExecutor>,
    binding: EngineBinding,
    artifact_digest: Sha256Digest,
    component_configuration_digest: Sha256Digest,
}

impl IsolatedChildEngine {
    /// Composes the isolated engine over the shared operation owner.
    /// The verifier-side adapter never stages (its slot stays empty):
    /// `reconcile` observes, it never launches.
    pub fn new(
        executor: Arc<WindowsProcessExecutor>,
        sink: Arc<dyn eliot_process::ProcessEvidenceSink>,
        binding: EngineBinding,
        artifact_digest: Sha256Digest,
        component_configuration_digest: Sha256Digest,
    ) -> Self {
        let process = WasmP03ProcessAdapter::new(Arc::clone(&executor), sink);
        Self {
            process,
            executor,
            binding,
            artifact_digest,
            component_configuration_digest,
        }
    }

    /// Composes the isolated engine from an authorized grant.
    ///
    /// The engine's admitted artifact identity is the grant-proven digest —
    /// the digest [`authorize_grant`](crate::grant_authorization::authorize_grant)
    /// re-hashed against the staged component bytes — never a caller claim.
    /// The manifest gate at [`invoke`](ComponentEnginePort::invoke) enforces
    /// exactly this digest. `component_configuration_digest` stays threaded
    /// from the admitted manifest, alongside the engine binding.
    pub fn for_authorized_grant(
        executor: Arc<WindowsProcessExecutor>,
        sink: Arc<dyn eliot_process::ProcessEvidenceSink>,
        binding: EngineBinding,
        grant: &AuthorizedGrant,
        component_configuration_digest: Sha256Digest,
    ) -> Self {
        Self::new(
            executor,
            sink,
            binding,
            grant.artifact_digest().clone(),
            component_configuration_digest,
        )
    }

    /// Returns the grant-proven artifact digest this engine enforces at
    /// invoke. Introspection for the composition and its proof only; the
    /// manifest gate remains the enforcement point.
    #[must_use]
    pub const fn admitted_artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }
}

impl ComponentEnginePort for IsolatedChildEngine {
    fn binding(&self) -> &EngineBinding {
        &self.binding
    }

    fn invoke(&mut self, invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
        let started = Instant::now();
        let manifest = &invocation.manifest;
        let expected_export = CapabilityId::new(RUN_EXPORT).map_err(|_| PortError::Denied)?;
        if invocation.input.len() as u64 > invocation.limits.max_input_bytes
            || manifest.artifact_digest != self.artifact_digest
            || manifest.engine != self.binding
            || manifest.configuration_digest != self.component_configuration_digest
            || usize::try_from(invocation.limits.max_stack_bytes).ok() != Some(PROVIDER_STACK_SIZE)
            || manifest.world.as_str() != WIT_WORLD
            || manifest.wit_version != WIT_VERSION
            || !manifest.imports.is_empty()
            || manifest.exports.len() != 1
            || !manifest.exports.contains(&expected_export)
        {
            return Err(PortError::Denied);
        }
        // Same-operation observation: the child this invocation started is
        // reaped through the shared owner — no second invocation, permit,
        // or child exists on this path.
        let evidence = self
            .process
            .reconcile(&invocation.process_binding)
            .map_err(|_| PortError::UnknownOutcome)?;
        if !matches!(evidence.view().lifecycle(), ProcessLifecycle::Exited) {
            return Err(PortError::UnknownOutcome);
        }
        let (captured, captured_stderr) = self
            .executor
            .captured_output(invocation.process_binding.operation_id())
            .map_err(|_| PortError::UnknownOutcome)?;
        let (termination, output, attempted_output_bytes) =
            if captured.complete && !captured.truncated {
                (
                    EngineTermination::Completed,
                    captured.bytes,
                    captured.total_bytes,
                )
            } else if captured.truncated {
                (
                    EngineTermination::OutputLimit,
                    Vec::new(),
                    captured.total_bytes,
                )
            } else {
                // Exited but the bytes are unproven: no output is manufactured.
                return Err(PortError::UnknownOutcome);
            };
        // Child-observed metering is required for a contract-valid
        // Completed report: the neutral gate demands measured peak, table,
        // and epoch ticks. The values below are parsed strictly from the
        // P03-captured stderr bytes the child emitted (retained session
        // bytes — not evidence previews, which carry no retention promise
        // here). Absent, truncated, non-UTF-8, or malformed metering fails
        // closed as unknown, never defaulted. The OutputLimit path carries
        // no Store detail (observed only through capture totals), mirroring
        // unmeasured-limit reports.
        let (fuel_consumed, peak_memory_bytes, table_elements, epoch_ticks) =
            if matches!(termination, EngineTermination::Completed) {
                let metering_text = if captured_stderr.complete && !captured_stderr.truncated {
                    match String::from_utf8(captured_stderr.bytes) {
                        Ok(text) => text,
                        Err(_) => return Err(PortError::UnknownOutcome),
                    }
                } else {
                    return Err(PortError::UnknownOutcome);
                };
                let Some(metering) = parse_metering_line(&metering_text) else {
                    return Err(PortError::UnknownOutcome);
                };
                (
                    metering.fuel_consumed,
                    Some(metering.peak_memory_bytes),
                    Some(metering.table_elements),
                    Some(metering.epoch_ticks),
                )
            } else {
                (0, None, None, None)
            };
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let report = EngineReport {
            request_digest: invocation.request_digest.clone(),
            termination,
            usage: EngineUsage {
                attempted_output_bytes,
                output_bytes: output.len() as u64,
                host_calls: 0,
                fuel_consumed,
                peak_memory_bytes,
                table_elements,
                instances: 1,
                stack_bytes: None,
                enforced_stack_limit_bytes: Some(invocation.limits.max_stack_bytes),
                elapsed_ms,
                effective_epoch_policy: invocation.limits.epoch,
                epoch_ticks,
                artifact_reads: 0,
                artifact_bytes: 0,
                accessed_artifact_digests: Vec::new(),
            },
            output,
            host_calls: Vec::new(),
            proposed_effects: Vec::new(),
            observed_state_delta: Vec::new(),
            post_commit_known: true,
        };
        enforce_shadow_no_effect(invocation.contour, &invocation.limits, &report)
            .map(|()| report)
            .map_err(shadow_port_error)
    }

    fn reconcile(&mut self, _invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
        Err(PortError::UnknownOutcome)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_process::{
        EvidenceSinkError, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
        ProcessRequest, SuspendedProcessIdentity, ValidatedDispatch,
    };

    struct DummyPort;

    impl eliot_process_executor::DispatchValidationPort for DummyPort {
        fn validate_and_consume(
            &self,
            _request: ProcessRequest,
            _observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            Err(ProcessExecutionError::Unavailable(
                "dummy port must not be called pre-spawn".to_owned(),
            ))
        }
    }

    struct NoopSink;

    impl ProcessEvidenceSink for NoopSink {
        fn record(&self, _evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
            Ok(())
        }
    }

    fn test_fence_epoch() -> (eliot_contracts::StateFence, eliot_contracts::EpochId) {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
        use std::num::NonZeroU64;
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("test lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("sequence")).expect("epoch");
        let fence = StateFence::new(epoch.clone(), ResourceGeneration::genesis());
        (fence, epoch)
    }

    #[test]
    fn authorized_grant_digest_becomes_engine_identity() {
        use crate::grant_authorization::authorize_grant;
        use crate::grant_client::AcceptedGrant;
        let artifact = b"component-artifact-bytes";
        let interface = b"wit-world-bytes";
        let host_path = "C:\\Kernel\\eliot-wasm-host.exe";
        let host_digest = Sha256Digest::of_bytes(b"installed-wasm-host-image-bytes");
        let (fence, epoch) = test_fence_epoch();
        let accepted = AcceptedGrant {
            component_id: "component-1955".to_owned(),
            artifact_digest: Sha256Digest::of_bytes(artifact),
            interface_digest: Sha256Digest::of_bytes(interface),
            fence,
            epoch,
            nonce: "nonce-1955".to_owned(),
            deadline_unix_ms: 9_999_999_999_999,
            host_executable_path: host_path.to_owned(),
            host_artifact_digest: host_digest.clone(),
        };
        let grant = authorize_grant(&accepted, host_path, &host_digest, artifact, interface)
            .expect("matching grant authorizes");
        let executor = Arc::new(WindowsProcessExecutor::new(Arc::new(DummyPort)));
        let sink: Arc<dyn eliot_process::ProcessEvidenceSink> = Arc::new(NoopSink);
        let binding = EngineBinding {
            implementation_id: ISOLATED_CHILD_IMPLEMENTATION_ID.to_owned(),
            exact_version: "47.0.4".to_owned(),
            engine_artifact_digest: Sha256Digest::of_bytes(b"engine-fixture"),
            engine_configuration_digest: Sha256Digest::of_bytes(b"config-fixture"),
            wit_interface_digest: Sha256Digest::of_bytes(interface),
        };
        let engine = IsolatedChildEngine::for_authorized_grant(
            executor,
            sink,
            binding,
            &grant,
            Sha256Digest::of_bytes(b"component-config-fixture"),
        );
        // The seated engine enforces exactly the grant-proven digest: a
        // caller-claimed digest cannot reach the manifest gate.
        assert_eq!(
            engine.admitted_artifact_digest(),
            &Sha256Digest::of_bytes(artifact)
        );
        assert_eq!(engine.admitted_artifact_digest(), grant.artifact_digest());
    }
}
