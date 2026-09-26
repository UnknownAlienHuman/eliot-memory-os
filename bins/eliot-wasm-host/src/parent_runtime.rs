//! Production parent-drive runtime assembly (issue #1955, #2568).
//!
//! Connects the owner-admitted delivery set to the injected WASM runtime
//! through live-constructed execution ports. Every input is owner-issued or
//! caller-provided: the material (owner-published bytes), the local owner
//! adapters (built from those same records inside
//! [`resolve_kernel_port_grant`](crate::admission::resolve_kernel_port_grant)),
//! the installed image (re-hashed real bytes), and edge time (read once at
//! the composition boundary, enforced against the owner window by the
//! contour and permit types). Nothing here mints authority, issues
//! caller-clock freshness, or fabricates receipts: the ephemeral permit
//! authority binds only the owner grant, and unbound inputs refuse
//! fail-closed before any spawn.
//!
//! Exactly one engine mode is seated per granted execution, inside the port
//! resolution: the isolated parent/child owner this P-03 profile requires.
//! The in-process Wasmtime provider is never paired with it, and the
//! one-shot guest-child protocol and the experimental describe path stay
//! separate modes reachable only through their own CLI branches.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eliot_process::{
    EnvironmentInheritance, EnvironmentProjection, EvidenceSinkError, Generation, ImageId, JobId,
    OperationId, ProcessEvidence, ProcessEvidenceSink, ProcessIntent, ProcessTreeId,
    ResourceLimits, SessionId,
};
use eliot_wasm_runtime::{EngineBinding, InvocationRequest, Sha256Digest, WasmRuntime};

use crate::WasmHostRunner;
use crate::admission::{LiveAuthority, PortGrantError, resolve_kernel_port_grant};
use crate::contour::AdmittedGeneration;
use crate::dispatch_drive::{DriveError, drive_admission};
use crate::dispatch_material::{
    ValidatedDispatchMaterial, WASM_HOST_GUEST_ARTIFACT_FILE_NAME, WASM_HOST_GUEST_INPUT_FILE_NAME,
};
use crate::installed_binary::WasmHostBinaryBinding;

/// Mailbox capacity ceiling: the loop is a bounded request surface, never
/// an unbounded queue.
const MAX_MAILBOX_CAPACITY: usize = 8;
/// Data-concurrency ceiling: the admitted profile's instance ceiling
/// bounds it further, so this is only the outer guard.
const MAX_CONCURRENCY: usize = 4;
/// One reserved control slot per mailbox, so cancellation, reconciliation,
/// and shutdown stay processable while guest work is pending.
const CONTROL_RESERVE: usize = 1;
/// One selection per ready lane before the scheduler rotates.
const FAIRNESS_QUANTUM: usize = 1;
/// A single admission runs one operation; a second failure has no budget.
const RESTART_BUDGET: usize = 0;
/// Rolling restart window in seconds.
const RESTART_WINDOW_SECONDS: u64 = 1;
/// Initial restart delay in milliseconds.
const RESTART_BACKOFF_MS: u64 = 1;

/// Bounded production evidence sink: retains evidence up to the cap, then
/// fails closed (never drops retained evidence silently).
pub(crate) struct BoundedParentSink {
    retained: Mutex<Vec<ProcessEvidence>>,
}

impl BoundedParentSink {
    const CAP: usize = 1024;

    pub(crate) fn new() -> Self {
        Self {
            retained: Mutex::new(Vec::new()),
        }
    }
}

impl ProcessEvidenceSink for BoundedParentSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        let mut guard = self.retained.lock().map_err(|_| EvidenceSinkError {
            message: "parent sink lock poisoned".to_owned(),
        })?;
        if guard.len() >= Self::CAP {
            return Err(EvidenceSinkError {
                message: "parent sink at capacity".to_owned(),
            });
        }
        guard.push(evidence);
        Ok(())
    }
}

/// Derives the exact immutable `ProcessIntent` for the admitted child.
/// Every identity is admitted material; paths are the OS loader layout.
pub(crate) fn derive_parent_intent(
    material: &ValidatedDispatchMaterial,
    executable: &std::path::Path,
    host_digest: &Sha256Digest,
    working_directory: &std::path::Path,
) -> Result<ProcessIntent, DriveError> {
    let intent_field = |field: &'static str| DriveError::Intent { field };
    let executable_text = executable
        .to_str()
        .ok_or_else(|| intent_field("executable"))?;
    let working_text = working_directory
        .to_str()
        .ok_or_else(|| intent_field("working-directory"))?;
    let short = host_digest
        .as_str()
        .get(..16)
        .ok_or_else(|| intent_field("host-digest"))?;
    let environment =
        EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
            .map_err(|_| intent_field("environment"))?;
    let ceilings = &material.ceilings;
    let limits = ResourceLimits::new(
        ceilings.wall_deadline_ms,
        None,
        Some(ceilings.max_memory_bytes),
        ceilings.max_output_bytes,
        ceilings.max_output_bytes,
        1,
    )
    .map_err(|_| intent_field("limits"))?;
    let generation =
        Generation::new(material.generation).map_err(|_| intent_field("generation"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| intent_field("executable-dir"))?;
    let argv = crate::dispatch_drive::guest_exec_argv(
        material.profile,
        &directory.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME),
        &directory.join(WASM_HOST_GUEST_INPUT_FILE_NAME),
        ceilings,
    );
    ProcessIntent::new(
        OperationId::new(material.operation_id.clone()).map_err(|_| intent_field("operation"))?,
        ProcessTreeId::new(material.work.work_scope.clone()).map_err(|_| intent_field("tree"))?,
        JobId::new(material.operation_id.clone()).map_err(|_| intent_field("job"))?,
        ImageId::new(format!("wasm-host-image-{short}")).map_err(|_| intent_field("image"))?,
        SessionId::new(material.claim_id.clone()).map_err(|_| intent_field("session"))?,
        generation,
        executable_text.to_owned(),
        host_digest.as_str().to_owned(),
        argv,
        working_text.to_owned(),
        environment,
        limits,
    )
    .map_err(|_| intent_field("intent"))
}

/// A granted execution assembled and ready to serve requests: the runner
/// with its single admitted engine mode, the exact sealed invocation, the
/// admitted generation the request must match, the seated engine binding,
/// and the live authority cell the loop keeps current.
pub struct AdmittedRuntime {
    /// Runner over the resolved local port set.
    pub runner: WasmHostRunner,
    /// The exact sealed invocation assembled from admitted material.
    pub invocation: InvocationRequest,
    /// The admitted generation the request is gated against.
    pub admitted: AdmittedGeneration,
    /// The engine mode actually seated.
    pub engine_binding: EngineBinding,
    /// Shared live authority cell for the granted window.
    pub live: Arc<LiveAuthority>,
}

/// Bounds the composed scheduler by the admitted profile: instance ceiling
/// for data capacity, a fixed reserved control slot, and the granted wall
/// deadline as the shutdown grace so drain work can never outlive the grant.
fn runtime_config(material: &ValidatedDispatchMaterial) -> eliot_runtime::RuntimeConfig {
    let instances = usize::try_from(material.ceilings.max_instances)
        .unwrap_or(1)
        .max(1);
    eliot_runtime::RuntimeConfig {
        mailbox_capacity: instances.min(MAX_MAILBOX_CAPACITY),
        control_reserve: CONTROL_RESERVE,
        concurrency: instances.min(MAX_CONCURRENCY),
        control_concurrency_reserve: CONTROL_RESERVE,
        fairness_quantum: FAIRNESS_QUANTUM,
        restart_budget: RESTART_BUDGET,
        restart_window: Duration::from_secs(RESTART_WINDOW_SECONDS),
        restart_backoff: Duration::from_millis(RESTART_BACKOFF_MS),
        shutdown_grace: Duration::from_millis(material.ceilings.wall_deadline_ms),
    }
}

/// Assembles the granted execution for one owner-admitted delivery set.
///
/// Order: pure admission over admitted values, the installation binding for
/// this process's own image, the local port-set resolution (one-shot P-03
/// permit over the real executor plus the local owner proxies), and finally
/// the runner over exactly that port set. Any unbound or substituted input
/// refuses before any spawn.
pub fn build_admitted_runtime(
    material: &ValidatedDispatchMaterial,
    now_ms: u64,
) -> Result<AdmittedRuntime, DriveError> {
    let (invocation, admitted) = drive_admission(material)?;
    // The host bootstraps only through the approved launch path: its own
    // installation-approved image, re-proven against the owner-measured
    // digest. No ambient path, build output, or environment participates.
    let executable =
        std::env::current_exe().map_err(|_| DriveError::Execution { stage: "locator" })?;
    let binding = WasmHostBinaryBinding::new(executable, material.host_artifact_digest.clone())
        .map_err(|_| DriveError::Admission {
            field: "image-binding",
        })?;
    let grant = resolve_kernel_port_grant(material, &binding, now_ms)
        .map_err(|error: PortGrantError| DriveError::Grant { code: error.code() })?;
    let runtime = eliot_runtime::Runtime::new(runtime_config(material), None)
        .map_err(|_| DriveError::Admission { field: "runtime" })?;
    let runner = WasmHostRunner::new(
        material.profile,
        runtime,
        WasmRuntime::new(Some(grant.ports)),
    )
    .map_err(|_| DriveError::Admission { field: "runner" })?;
    Ok(AdmittedRuntime {
        runner,
        invocation,
        admitted,
        engine_binding: grant.engine_binding,
        live: grant.live,
    })
}
