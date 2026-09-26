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

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use eliot_process::{OperationId, ProcessExecutor, ProcessLifecycle};
use eliot_process_executor::{WindowsProcessExecutor, wasm_p03_adapter::WasmP03ProcessAdapter};
use eliot_wasm_runtime::{
    CapabilityId, ComponentEnginePort, EngineBinding, EngineInvocation, EngineReport,
    EngineTermination, EngineUsage, GuestInterruptHandle, P03ProcessPort, PortError, Sha256Digest,
};

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
    operation: Option<OperationId>,
}

impl IsolatedChildEngine {
    /// Composes the isolated engine over the shared operation owner.
    /// The verifier-side adapter never stages (its slot stays empty):
    /// `reconcile` observes, it never launches. The operation identity names
    /// the one child this engine serves; it arms the cross-thread
    /// interruption handle, and an unparseable identity disarms it (`None`).
    pub fn new(
        executor: Arc<WindowsProcessExecutor>,
        sink: Arc<dyn eliot_process::ProcessEvidenceSink>,
        binding: EngineBinding,
        artifact_digest: Sha256Digest,
        component_configuration_digest: Sha256Digest,
        operation_id: &str,
    ) -> Self {
        let process = WasmP03ProcessAdapter::new(Arc::clone(&executor), sink);
        Self {
            process,
            executor,
            binding,
            artifact_digest,
            component_configuration_digest,
            operation: OperationId::new(operation_id.to_owned()).ok(),
        }
    }
}

/// Cloneable cross-thread interruption for isolated-child guest execution
/// (#2568 A3). Fires the owner-blessed P03 cancellation for exactly the
/// operation this engine serves, so the worker's observed reap settles
/// promptly and the invocation reports unknown instead of running to its
/// wall deadline. Best-effort and idempotent: firing before the child
/// starts, after it settles, or twice resolves to the same terminated
/// observation, and the caller retries while the command is outstanding.
#[derive(Clone)]
pub struct ChildInterruptHandle {
    executor: Arc<WindowsProcessExecutor>,
    operation: OperationId,
}

impl GuestInterruptHandle for ChildInterruptHandle {
    fn interrupt(&self) {
        let _ = drive_executor_future(self.executor.cancel(self.operation.clone()));
    }
}

/// Drives one already-created executor future to completion on the calling
/// thread, using this tree's established spin recipe: the executor futures
/// are thread-driven, so a `yield_now` spin terminates without an async
/// runtime and without inventing a second executor or scheduler. (Same
/// recipe as the P03 adapter's private driver.)
fn drive_executor_future<F: Future>(future: F) -> F::Output {
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

    fn interrupt_handle(&self) -> Option<Arc<dyn GuestInterruptHandle>> {
        let operation = self.operation.clone()?;
        let handle: Arc<dyn GuestInterruptHandle> = Arc::new(ChildInterruptHandle {
            executor: Arc::clone(&self.executor),
            operation,
        });
        Some(handle)
    }
}
