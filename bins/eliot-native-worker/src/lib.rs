//! Thin composition boundary for one isolated native-worker generation.
//!
//! The binary owns framing and process lifetime only. Admission, process
//! execution, evidence, replay, and checkpoint persistence remain injected
//! ports owned by the governing services.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

use eliot_native_worker_core::{
    CapabilityAdmissionPort, ClaimAdmissionRequest, DurableCheckpointPort, DurableReplayPort,
    NativeWorkerClaim, NativeWorkerRegistration, ReadinessSubmission, WorkerCore, WorkerError,
    WorkerEventEnvelope, WorkerFrame, WorkerHello, WorkerLifecycle, WorkerReady,
};
use eliot_process::{ProcessExecutor, ProcessRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod dispatch_authority;
mod kernel_admission_client;

/// Private finite immutable four-factory adapter registry, owned by this
/// crate so the admitted seam and the wiring proof address identical types.
///
/// `pub` (rather than crate-private) so the `tests/` wiring proof imports
/// the same module instead of compiling a second copy via `#[path]`, which
/// would fork the types and void the proof.
pub mod adapter_registry;

pub use dispatch_authority::{
    NativeWorkerDispatchAuthority, ValidatedDispatchGrant, now_unix_ms as dispatch_now_unix_ms,
};
pub use kernel_admission_client::{
    KernelCheckpointPort, KernelNativeWorkerClient, KernelReplayPort, KernelReplayTransport,
    NATIVE_WORKER_CANCEL_OBSERVE_OPERATION, NATIVE_WORKER_CHECKPOINT_OPERATION,
    NATIVE_WORKER_CLAIM_OPERATION, NATIVE_WORKER_HEARTBEAT_OPERATION,
    NATIVE_WORKER_READY_OPERATION, NATIVE_WORKER_RECONCILE_OPERATION,
    NATIVE_WORKER_REGISTRATION_OPERATION, NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION,
    NATIVE_WORKER_REPLAY_APPEND_OPERATION, NATIVE_WORKER_REPLAY_BEGIN_OPERATION,
    NATIVE_WORKER_REPLAY_LOOKUP_OPERATION, NATIVE_WORKER_REPLAY_OPERATION,
    NATIVE_WORKER_RESULT_SUBMIT_OPERATION, ReconcileRetainedReceipt, ReconcileSubmission,
    SharedKernelTransport,
};

const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;
pub const KERNEL_ADMISSION_REQUIRED: &str = "KERNEL_ADMISSION_REQUIRED";

/// A transport response containing only durable events produced by the core.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerResponse {
    /// Events that the replay owner accepted and returned for delivery.
    pub events: Vec<WorkerEventEnvelope>,
}

/// Errors at the process composition boundary.
#[derive(Debug, Error)]
pub enum NativeWorkerError {
    #[error("{KERNEL_ADMISSION_REQUIRED}: {0}")]
    KernelAdmissionRequired(String),
    #[error("worker core error: {0}")]
    Core(#[from] WorkerError),
    #[error("worker transport I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("worker transport JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("native-worker frame is {actual} bytes; maximum is {maximum}")]
    FrameTooLarge { actual: u32, maximum: u32 },
    #[error("native-worker frame length cannot be zero")]
    EmptyFrame,
}

/// Composed native-worker generation with all governing dependencies explicit.
pub struct NativeWorker<E, A, R, C> {
    core: WorkerCore<E, A, R, C>,
}

impl<E, A, R, C> NativeWorker<E, A, R, C>
where
    E: ProcessExecutor,
    A: eliot_native_worker_core::CapabilityAdmissionPort,
    R: eliot_native_worker_core::DurableReplayPort,
    C: eliot_native_worker_core::DurableCheckpointPort,
{
    /// Composes the worker without creating providers or authority locally.
    #[must_use]
    pub fn new(core: WorkerCore<E, A, R, C>) -> Self {
        Self { core }
    }

    /// Performs the governed admission and process start handshake.
    pub async fn start(
        &mut self,
        hello: WorkerHello,
        process: ProcessRequest,
    ) -> Result<eliot_native_worker_core::WorkerReady, NativeWorkerError> {
        self.core
            .demand_start(hello, process)
            .await
            .map_err(NativeWorkerError::from)
    }

    /// Performs the claimed admission and process start handshake for one
    /// exact Kernel-issued claim presentation (T2-S05 first consumer).
    ///
    /// Binds the existing claimed start path without minting authority: the
    /// supplied `claim`, `hello`, and `process` are validated through the
    /// production `from_claim` join and executable gate before the injected
    /// admission port and P-03 executor run. The existing unclaimed `start`
    /// is untouched; `ProcessRequest` stays an in-memory composition value
    /// and never enters a wire type.
    pub async fn start_claimed(
        &mut self,
        claim: eliot_native_worker_core::ClaimAdmissionRequest,
        hello: WorkerHello,
        process: ProcessRequest,
    ) -> Result<eliot_native_worker_core::WorkerReady, NativeWorkerError> {
        self.core
            .demand_start_claimed(claim, hello, process)
            .await
            .map_err(NativeWorkerError::from)
    }

    /// Restores an exact fenced binding and replays durable events.
    pub async fn recover(
        &mut self,
        hello: WorkerHello,
        process: ProcessRequest,
        replay_after_sequence: u64,
    ) -> Result<eliot_native_worker_core::WorkerRecovery, NativeWorkerError> {
        self.core
            .recover_after_restart(hello, process, replay_after_sequence)
            .await
            .map_err(NativeWorkerError::from)
    }

    /// Restores one exact claimed binding after a restart without launching
    /// a second process.
    ///
    /// Preserves the existing unclaimed [`NativeWorker::recover`]; the
    /// production claimed path uses this method so a lost start response or
    /// restart reconciles through retained P-03 inspect plus the durable
    /// replay suffix, never a duplicate start. Invalid admission invokes no
    /// factory and starts nothing; the typed core refusal surfaces instead.
    pub async fn recover_claimed(
        &mut self,
        claim: eliot_native_worker_core::ClaimAdmissionRequest,
        hello: WorkerHello,
        process: ProcessRequest,
        replay_after_sequence: u64,
    ) -> Result<eliot_native_worker_core::WorkerRecovery, NativeWorkerError> {
        self.core
            .recover_after_restart_claimed(claim, hello, process, replay_after_sequence)
            .await
            .map_err(NativeWorkerError::from)
    }

    /// Handles one already-decoded EBP worker frame.
    pub async fn handle(
        &mut self,
        frame: WorkerFrame,
    ) -> Result<Vec<WorkerEventEnvelope>, NativeWorkerError> {
        self.core
            .handle(frame)
            .await
            .map_err(NativeWorkerError::from)
    }

    /// Returns the logical lifecycle owned by the worker protocol.
    #[must_use]
    pub const fn lifecycle(&self) -> WorkerLifecycle {
        self.core.lifecycle()
    }

    /// Serves length-delimited JSON frames after the caller has completed start.
    ///
    /// The blocking stdin read runs on a dedicated reader thread that drains
    /// the OS pipe promptly into a bounded channel, while this loop handles
    /// frames (including `Cancel`/`Heartbeat` bodies through the core) and
    /// writes responses. A slow `Execute` handler therefore cannot starve a
    /// concurrent cancellation or heartbeat observation: the reader keeps
    /// buffering while the handler runs, and cancel/heartbeat frames are
    /// handled as soon as the current frame completes instead of being stuck
    /// behind a blocked read. T9-05 coordinator verification is not consumed
    /// by this contour.
    pub async fn serve_stdio(&mut self) -> Result<(), NativeWorkerError> {
        let (sender, receiver) =
            std::sync::mpsc::sync_channel::<Result<Option<WorkerFrame>, NativeWorkerError>>(64);
        std::thread::spawn(move || {
            loop {
                let frame = read_frame();
                let done = matches!(&frame, Ok(None) | Err(_));
                if sender.send(frame).is_err() || done {
                    return;
                }
            }
        });
        loop {
            let frame = receiver.recv().map_err(|_| {
                NativeWorkerError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "native-worker stdin reader stopped",
                ))
            })??;
            let Some(frame) = frame else {
                return Ok(());
            };
            if self.serve_frame(frame).await? {
                return Ok(());
            }
        }
    }

    /// Handles one frame and writes its response, returning true on shutdown.
    async fn serve_frame(&mut self, frame: WorkerFrame) -> Result<bool, NativeWorkerError> {
        let shutdown = matches!(
            frame.body,
            eliot_native_worker_core::WorkerFrameBody::Shutdown
        );
        let events = self.handle(frame).await?;
        write_frame(&WorkerResponse { events })?;
        Ok(shutdown)
    }

    /// Serves exactly one length-delimited frame from `reader` into `writer`.
    ///
    /// Testable bounded-frame helper for the admitted contour: reads one
    /// frame, handles it through the claimed core, and writes one response.
    /// Returns `Ok(true)` on `Shutdown`, `Ok(false)` otherwise. Uses blocking
    /// I/O like the stdio loop; cancellation/heartbeat split is owned by
    /// [`NativeWorker::serve_stdio`].
    pub async fn serve_one_frame<Reader: Read, Writer: Write>(
        &mut self,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> Result<bool, NativeWorkerError> {
        let Some(frame) = read_frame_from(reader)? else {
            return Ok(true);
        };
        let shutdown = matches!(
            frame.body,
            eliot_native_worker_core::WorkerFrameBody::Shutdown
        );
        let events = self.handle(frame).await?;
        write_frame_to(&WorkerResponse { events }, writer)?;
        Ok(shutdown)
    }
}

/// Thin lifecycle transport for the admitted driver.
///
/// Implemented by [`KernelNativeWorkerClient`] in production and by
/// clearly-marked test doubles where a live Kernel is unavailable. T9-05
/// coordinator verification is not consumed by this contour.
pub trait AdmittedLifecycle {
    /// Registers (or renews) one worker generation.
    fn submit_registration(
        &mut self,
        registration: &NativeWorkerRegistration,
    ) -> Result<serde_json::Value, NativeWorkerError>;
    /// Claims exactly one Kernel-owned execution unit.
    fn submit_claim(
        &mut self,
        admission: &ClaimAdmissionRequest,
    ) -> Result<serde_json::Value, NativeWorkerError>;
    /// Reconciles one exact claim after a lost acknowledgement.
    fn submit_reconcile(
        &mut self,
        submission: &crate::ReconcileSubmission,
    ) -> Result<serde_json::Value, NativeWorkerError>;
    /// Submits one typed ready-or-blocked verdict for the claimed unit.
    fn submit_readiness(
        &mut self,
        submission: &ReadinessSubmission,
    ) -> Result<serde_json::Value, NativeWorkerError>;
}

impl AdmittedLifecycle for KernelNativeWorkerClient {
    fn submit_registration(
        &mut self,
        registration: &NativeWorkerRegistration,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        KernelNativeWorkerClient::submit_registration(self, registration)
    }

    fn submit_claim(
        &mut self,
        admission: &ClaimAdmissionRequest,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        KernelNativeWorkerClient::submit_claim(self, admission)
    }

    fn submit_reconcile(
        &mut self,
        submission: &crate::ReconcileSubmission,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        KernelNativeWorkerClient::submit_reconcile(self, submission)
    }

    fn submit_readiness(
        &mut self,
        submission: &ReadinessSubmission,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        KernelNativeWorkerClient::submit_readiness(self, submission)
    }
}

/// Drives one admitted native-worker generation to `Ready`.
///
/// Sequence: register, claim the exact authenticated unit, reconcile any
/// retained operation (lost start response or restart reconciles through the
/// retained record, never a second process), compose-checked
/// `start_claimed` through the exact `WorkerCore::demand_start_claimed` gate,
/// then submit readiness. Invalid admission fails before any factory or
/// process start is invoked: the lifecycle transport refuses first, and the
/// claimed core gate refuses before P-03 starts anything. No coordinator
/// verification is consumed here (T9-05 is not part of this contour); no user
/// authentication is performed (owner decision #1376); no worker-local replay
/// journal is created (thin transport over T9-03 only).
pub async fn drive_admitted_claimed<E, A, R, C, L>(
    lifecycle: &mut L,
    worker: &mut NativeWorker<E, A, R, C>,
    registration: &NativeWorkerRegistration,
    admission: &ClaimAdmissionRequest,
    hello: WorkerHello,
    process: ProcessRequest,
    reconcile: &crate::ReconcileSubmission,
    readiness: &ReadinessSubmission,
) -> Result<WorkerReady, NativeWorkerError>
where
    E: ProcessExecutor,
    A: CapabilityAdmissionPort,
    R: DurableReplayPort,
    C: DurableCheckpointPort,
    L: AdmittedLifecycle,
{
    lifecycle.submit_registration(registration)?;
    lifecycle.submit_claim(admission)?;
    lifecycle.submit_reconcile(reconcile)?;
    let ready = worker
        .start_claimed(admission.clone(), hello, process)
        .await?;
    lifecycle.submit_readiness(readiness)?;
    Ok(ready)
}

/// Admitted factory-resolution seam (T9-07, issue #874; supersedes PR #1125).
/// BOUND by INTEGRATOR-T9-07: this is the single resolution function. It
/// projects the owner-produced v2 executable join (`adapter_id`,
/// `adapter_revision`, `route_ref`, plus the carried digests) already bound
/// by [`admitted_material::read_admitted_material`], then backs the projected
/// identity with the live [`adapter_registry::AdapterRegistry`] —
///
/// ```text
/// run() -> select_factory_for_admitted() -> AdapterRegistry::four_factory().resolve()
/// ```
///
/// — and refuses anything that does not resolve to exactly one registered
/// factory. The hypothetical second function from the Writer-B draft
/// (`resolve_admitted_factory`) was never created; no duplicate resolution
/// path exists. This seam mints nothing, admits nothing, and starts nothing:
/// the downstream `from_claim` join, executable gate, grant checks, and
/// receipt/proof validation in [`drive_admitted_claimed`] re-prove everything
/// before any process starts. It never equates the admitted `route_class`
/// label with a full route fingerprint, never defaults a factory, and never
/// lets an ambiguous or unknown route resolve.
///
/// FAIL-CLOSED FAMILY (every variant maps to exit 78 in the binary via the
/// typed `KERNEL_ADMISSION_REQUIRED` denial, never the deferred line and
/// never a drive): the claim carries no v2 executable join (old wire can
/// never select a factory); the join route does not equal the presented
/// hello route; the join nonce is not the session nonce; the factory identity
/// is blank; the adapter revision is zero; the projected identity plus
/// revision matches no live registry entry (unknown, ambiguous, or revision
/// mismatch). Full shape, digest, epoch, fence, and window checks stay with
/// the envelope reader and the drive; this seam is the route-resolution
/// projection plus the live registry lookup only.
///
/// HONESTY BOUNDARY (issue #874 binding): this seam resolves the factory
/// identity only. It does not derive the executor-bound `ProcessRequest`
/// (never deserialized, never minted) and does not compose the P-03/G-01/
/// checkpoint ports. Those arrive with the kernel dispatch launch seam
/// (DISPATCH-CAUSE-FIX child half): the validated launch grant plus the
/// canonical intent rule ([`derive_admitted_intent`]) issued through the
/// in-child [`NativeWorkerDispatchAuthority`]. Until a cooperating owner
/// publishes the matching join digest, even validated material denies at the
/// executable gate — never the deferred line, which is reserved for
/// genuinely missing material (see `bins/eliot-native-worker/src/main.rs::run`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactorySelection {
    /// Owner-produced adapter/factory identity from the v2 executable join.
    pub adapter_id: String,
    /// Owner-produced adapter revision from the join; always nonzero.
    pub adapter_revision: u64,
    /// Full canonical route label from the join, bound to the hello route.
    pub route_ref: String,
    /// Lowercase SHA-256 of the admitted worker configuration bytes.
    pub config_digest: String,
    /// Replay stream identity bound to the claim generation.
    pub replay_stream_id: String,
    /// Lowercase SHA-256 of the exact process invocation the join binds.
    ///
    /// Digest only: the invocation material itself is never carried here and
    /// can never be inverted from this digest.
    pub process_invocation_digest: String,
}

/// Resolves one validated admitted route to exactly one factory identity.
///
/// See the [`FactorySelection`] seam documentation for the binding contract
/// and the honesty boundary.
pub fn select_factory_for_admitted(
    material: &admitted_material::ValidatedAdmittedMaterial,
) -> Result<FactorySelection, NativeWorkerError> {
    let selection = select_factory_from_presented(
        material.admission.claim(),
        &material.hello,
        &material.nonce,
    )?;
    // Back the projected identity with the live four-factory registry: an
    // unknown, ambiguous, or revision-mismatched projection is a refused
    // presentation (typed 78 in the binary), never a default and never a
    // drive. The admitted arm never emits the deferred line.
    adapter_registry::AdapterRegistry::four_factory()
        .resolve(&selection.adapter_id, selection.adapter_revision)
        .map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "admitted factory unresolved: {error}"
            ))
        })?;
    Ok(selection)
}

/// Projects one presented claim plus hello plus session nonce to exactly one
/// factory identity, fail-closed.
///
/// `crate`-internal so the [`FactorySelection`] seam stays the single public
/// projection while tests prove every refusal branch directly.
fn select_factory_from_presented(
    claim: &NativeWorkerClaim,
    hello: &WorkerHello,
    nonce: &str,
) -> Result<FactorySelection, NativeWorkerError> {
    let join = claim.executable_binding.as_ref().ok_or_else(|| {
        NativeWorkerError::KernelAdmissionRequired(
            "admitted claim carries no executable join; old wire cannot select a factory"
                .to_owned(),
        )
    })?;
    if join.route_ref != hello.route_ref {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "admitted route does not bind the presented hello".to_owned(),
        ));
    }
    if join.launch_nonce != nonce {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "admitted factory nonce is not bound to the session material".to_owned(),
        ));
    }
    if join.adapter_id.trim().is_empty() {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "admitted factory identity is missing".to_owned(),
        ));
    }
    if join.adapter_revision == 0 {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "admitted factory revision is missing".to_owned(),
        ));
    }
    Ok(FactorySelection {
        adapter_id: join.adapter_id.clone(),
        adapter_revision: join.adapter_revision,
        route_ref: join.route_ref.clone(),
        config_digest: join.config_digest.clone(),
        replay_stream_id: join.replay_stream_id.clone(),
        process_invocation_digest: join.process_invocation_digest.clone(),
    })
}

/// Requires the Kernel launch grant funding the in-process one-shot permit.
///
/// A validated legacy envelope proves its claim but carries no grant, so it
/// cannot drive: the caller denies fail-closed (exit 78) instead of
/// reaching for a permit that was never issued.
///
/// # Errors
///
/// Returns [`NativeWorkerError::KernelAdmissionRequired`] when the material
/// carries no grant.
pub fn require_launch_grant(
    material: &admitted_material::ValidatedAdmittedMaterial,
) -> Result<&ValidatedDispatchGrant, NativeWorkerError> {
    material.grant.as_ref().ok_or_else(|| {
        NativeWorkerError::KernelAdmissionRequired(
            "Kernel launch grant is missing: the admitted envelope carries no launch grant to issue a one-shot permit from"
                .to_owned(),
        )
    })
}

/// Derives the executor-bound [`ProcessIntent`][eliot_process::ProcessIntent]
/// for one validated admitted claim.
///
/// THE CANONICAL INTENT RULE (the owner-side publisher runs the identical
/// forward computation; every field is fixed before the claim binding digest
/// exists, so the derivation is acyclic):
///
/// ```text
/// operation_id      = the admitted claim operation identity
/// process_tree_id   = the admitted claim identity (the tree lineage
///                     executing exactly this claim; distinct types, one
///                     value — no synthetic namespace to collide or overflow)
/// job_id            = the Kernel-owned parent job identity, carried exactly
/// image_id          = "{adapter_id}-r{adapter_revision}" from the resolved
///                     factory selection (this is how the selection informs
///                     the intent)
/// session_id        = the admitted claim identity (the session executing
///                     exactly this claim)
/// generation        = the claiming worker generation
/// executable        = the deployment-pinned worker executable locator (the
///                     caller passes `current_exe`; authority is the admitted
///                     digest, which the executor re-hashes from the file)
/// executable_sha256 = the owner-measured worker artifact digest from the
///                     admitted material (never hashed here; the executor
///                     verifies it against the file before any start)
/// argv              = empty (the Kernel spawns workers argument-less)
/// working_directory = the deployment-pinned working directory locator
///                     (the caller passes the executable parent directory)
/// environment       = empty secret-free projection (the Kernel spawns
///                     workers with a secret-free environment)
/// resource_limits   = the admitted budget projected onto executor ceilings
///                     (wall time from the budget; each byte stream capped at
///                     the admitted output budget; no CPU/memory dimensions in
///                     the budget, so those stay unset)
/// ```
///
/// Nothing comes from argv, stdin, or environment variables: identities and
/// ceilings come from the validated claim, the factory identity from the
/// resolved selection, and the two paths from the OS loader layout. The
/// `from_claim` join plus the executable gate re-prove the derived intent at
/// drive time (`process_invocation_digest` equality), so a derivation that
/// disagrees with the owner-published join fails closed there, never
/// silently.
///
/// # Errors
///
/// Returns [`NativeWorkerError::KernelAdmissionRequired`] for any unmappable
/// identity, non-UTF-8 locator path, or contract violation — all fail-closed
/// to exit 78 without effect.
pub fn derive_admitted_intent(
    material: &admitted_material::ValidatedAdmittedMaterial,
    selection: &FactorySelection,
    executable: &std::path::Path,
    working_directory: &std::path::Path,
) -> Result<eliot_process::ProcessIntent, NativeWorkerError> {
    use eliot_process::{
        EnvironmentInheritance, EnvironmentProjection, Generation, ImageId, JobId, ProcessIntent,
        ProcessTreeId, ResourceLimits, SessionId,
    };
    let claim = material.admission.claim();
    let executable_str = executable.to_str().ok_or_else(|| {
        NativeWorkerError::KernelAdmissionRequired(
            "dispatch executable locator is not well-formed".to_owned(),
        )
    })?;
    let working_directory_str = working_directory.to_str().ok_or_else(|| {
        NativeWorkerError::KernelAdmissionRequired(
            "dispatch working directory locator is not well-formed".to_owned(),
        )
    })?;
    let environment = EnvironmentProjection::new(
        std::collections::BTreeMap::new(),
        Vec::new(),
        EnvironmentInheritance::None,
    )
    .map_err(|error| {
        NativeWorkerError::KernelAdmissionRequired(format!(
            "dispatch environment projection failed: {error}"
        ))
    })?;
    let limits = ResourceLimits::new(
        claim.budget.wall_time_ms,
        None,
        None,
        claim.budget.output_bytes,
        claim.budget.output_bytes,
        claim.budget.max_descendants,
    )
    .map_err(|error| {
        NativeWorkerError::KernelAdmissionRequired(format!(
            "dispatch resource limits failed: {error}"
        ))
    })?;
    ProcessIntent::new(
        claim.operation_id.clone(),
        ProcessTreeId::new(claim.claim_id.as_str().to_owned()).map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "dispatch process tree identity failed: {error}"
            ))
        })?,
        JobId::new(claim.parent_job_id.clone()).map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "dispatch job identity failed: {error}"
            ))
        })?,
        ImageId::new(format!(
            "{}-r{}",
            selection.adapter_id, selection.adapter_revision
        ))
        .map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "dispatch image identity failed: {error}"
            ))
        })?,
        SessionId::new(claim.claim_id.as_str().to_owned()).map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "dispatch session identity failed: {error}"
            ))
        })?,
        Generation::new(claim.worker_generation).map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "dispatch generation failed: {error}"
            ))
        })?,
        executable_str.to_owned(),
        material.worker_artifact_digest.clone(),
        Vec::new(),
        working_directory_str.to_owned(),
        environment,
        limits,
    )
    .map_err(|error| {
        NativeWorkerError::KernelAdmissionRequired(format!("dispatch intent failed: {error}"))
    })
}

/// Production G-01-facing admission port: a claim-echo projection.
///
/// `WorkerCore` needs a [`CapabilityAdmissionPort`][eliot_native_worker_core::CapabilityAdmissionPort]
/// to seal its internal grant, and no G-01 owner record is reachable from
/// this dependency-frozen child. This port therefore projects the admission
/// facts from the validated presentation itself — claim/registration binding
/// re-validated, every bound identity echoed from the joined hello/process,
/// the presented executable join carried as the expectation — and the
/// downstream production gates (`validate_grant`, the executable gate, the
/// `from_claim` join) re-prove those bindings before anything starts. The
/// owner-currentness half (is this join still the live owner record?) stays
/// kernel-side: the dispatch contour admitted the claim against the live
/// record at prepare, and every submit re-gates it there. Unclaimed
/// presentations are refused outright: this contour serves claims only.
/// Ambient effects are never authorized.
///
/// The port retains its admission observation window and echoes it back on
/// revalidation, so liveness answers the exact sealed grant instead of a
/// fresh clock reading that could never match it.
pub struct PresentationEchoAdmission {
    /// Admission observation window installed by `admit`, echoed by
    /// `revalidate`.
    observed: std::sync::Mutex<Option<(u64, u64)>>,
}

impl PresentationEchoAdmission {
    /// Creates one echo port with no retained admission.
    #[must_use]
    pub fn new() -> Self {
        Self {
            observed: std::sync::Mutex::new(None),
        }
    }
}

impl Default for PresentationEchoAdmission {
    fn default() -> Self {
        Self::new()
    }
}

impl eliot_native_worker_core::CapabilityAdmissionPort for PresentationEchoAdmission {
    fn admit(
        &mut self,
        request: &eliot_native_worker_core::CapabilityAdmissionRequest,
    ) -> Result<
        eliot_native_worker_core::CapabilityAdmissionOutcome,
        eliot_native_worker_core::ProviderFailure,
    > {
        use eliot_native_worker_core::{
            AuthorityEnvelope, CapabilityAdmissionFacts, CapabilityAdmissionOutcome,
            NativeWorkerExecutableExpectation, ProviderFailure,
        };
        let presented = request.claim().ok_or_else(|| {
            ProviderFailure::new(
                "presentation-echo-admission",
                "unclaimed presentation refused: the admitted contour serves claims only",
            )
        })?;
        presented.validate_binding().map_err(|error| {
            ProviderFailure::new("presentation-echo-admission", error.to_string())
        })?;
        let claim = presented.claim();
        let join = claim.executable_binding.as_ref().ok_or_else(|| {
            ProviderFailure::new(
                "presentation-echo-admission",
                "admitted claim carries no executable join",
            )
        })?;
        let now = crate::dispatch_authority::now_unix_ms().map_err(|error| {
            ProviderFailure::new("presentation-echo-admission", error.to_string())
        })?;
        let digest = claim.binding_digest.clone();
        let epoch_value = serde_json::to_value(&claim.authority_epoch).map_err(|error| {
            ProviderFailure::new("presentation-echo-admission", error.to_string())
        })?;
        let fence_value = serde_json::to_value(&claim.state_fence).map_err(|error| {
            ProviderFailure::new("presentation-echo-admission", error.to_string())
        })?;
        let authority_value = serde_json::json!({
            "epoch": epoch_value,
            "scope_ref": claim.work_scope_id,
            "effect_ceiling": {
                "scope_ref": claim.work_scope_id,
                "allowed": ["write_candidate"],
                "max_external_effects": 0,
            },
            "lease": {
                "namespace": "eliot.governor.work-lease",
                "revision": "v1",
                "value": format!("native-worker-lease-{digest}"),
            },
            "state_fence": fence_value,
            "valid_until": "kernel-submit-bound",
        });
        let authority: AuthorityEnvelope =
            serde_json::from_value(authority_value).map_err(|error| {
                ProviderFailure::new("presentation-echo-admission", error.to_string())
            })?;
        authority.validate().map_err(|error| {
            ProviderFailure::new("presentation-echo-admission", error.to_string())
        })?;
        let facts = CapabilityAdmissionFacts::new(
            format!("native-worker-admission-{digest}"),
            "1",
            0,
            now,
            now.saturating_add(60_000),
            join.replay_stream_id.clone(),
            format!("worker-producer-{}", claim.worker_generation),
            request.hello().route_ref.clone(),
            request.hello().artifact_manifest_digest.clone(),
            claim.worker_generation,
            authority,
            request.hello().requested_capabilities.clone(),
            request.operation_id().clone(),
            request.process_tree_id().clone(),
            request.process_generation(),
            request.process_fence().clone(),
            request.process_request_digest().to_owned(),
            *request.resource_limits(),
        )
        .with_claim_binding(claim)
        .with_executable_expectation(NativeWorkerExecutableExpectation {
            current: join.clone(),
            revoked: false,
        });
        *self.observed.lock().map_err(|_| {
            ProviderFailure::new(
                "presentation-echo-admission",
                "admission observation lock poisoned",
            )
        })? = Some((now, now.saturating_add(60_000)));
        Ok(CapabilityAdmissionOutcome::Admitted(Box::new(facts)))
    }

    fn revalidate(
        &mut self,
        request: &eliot_native_worker_core::CapabilityLivenessRequest,
    ) -> Result<
        eliot_native_worker_core::AdmissionLivenessOutcome,
        eliot_native_worker_core::ProviderFailure,
    > {
        use eliot_native_worker_core::{
            AdmissionLivenessFacts, AdmissionLivenessOutcome, ProviderFailure,
        };
        let guard = self.observed.lock().map_err(|_| {
            ProviderFailure::new(
                "presentation-echo-admission",
                "admission observation lock poisoned",
            )
        })?;
        let Some((observed_at, expires_at)) = *guard else {
            return Err(ProviderFailure::new(
                "presentation-echo-admission",
                "no retained admission to revalidate",
            ));
        };
        drop(guard);
        Ok(AdmissionLivenessOutcome::Live(AdmissionLivenessFacts::new(
            request.admission_id(),
            request.admission_revision(),
            request.revocation_revision(),
            request.lease().clone(),
            request.authority_epoch().clone(),
            request.state_fence().clone(),
            observed_at,
            expires_at,
            false,
        )))
    }

    fn authorize_effect(
        &mut self,
        _request: &eliot_native_worker_core::EffectAdmissionRequest,
    ) -> Result<
        eliot_native_worker_core::EffectAdmissionOutcome,
        eliot_native_worker_core::ProviderFailure,
    > {
        Err(eliot_native_worker_core::ProviderFailure::new(
            "presentation-echo-admission",
            "the admitted worker authorizes no ambient effects",
        ))
    }
}

/// Production P-03 evidence sink: bounded memory plus supervisor-capturable
/// stderr.
///
/// The start path requires an evidence sink, and no durable evidence owner
/// is reachable from this dependency-frozen child. Records are retained in
/// a bounded in-memory ring (256 entries; beyond that only a dropped
/// counter survives) and each record is also emitted as one JSON line on
/// stderr, which the supervising Kernel launch retains with the child
/// streams. Emission is best-effort and never fails the run; only a
/// poisoned lock fails a record.
pub struct BoundedEvidenceSink {
    /// Retained records, bounded by [`BoundedEvidenceSink::MAX_RETAINED`].
    records: std::sync::Mutex<Vec<eliot_process::ProcessEvidence>>,
    /// Records dropped after the bound was reached.
    dropped: std::sync::Mutex<u64>,
}

impl BoundedEvidenceSink {
    /// Maximum retained evidence records.
    pub const MAX_RETAINED: usize = 256;

    /// Creates one empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: std::sync::Mutex::new(Vec::new()),
            dropped: std::sync::Mutex::new(0),
        }
    }

    /// Returns the number of retained records.
    pub fn recorded_len(&self) -> usize {
        self.records.lock().map_or(0, |records| records.len())
    }

    /// Returns the number of records dropped after the bound.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.lock().map_or(0, |count| *count)
    }
}

impl Default for BoundedEvidenceSink {
    fn default() -> Self {
        Self::new()
    }
}

impl eliot_process::ProcessEvidenceSink for BoundedEvidenceSink {
    fn record(
        &self,
        evidence: eliot_process::ProcessEvidence,
    ) -> Result<(), eliot_process::EvidenceSinkError> {
        if let Ok(bytes) = serde_json::to_vec(&evidence) {
            use std::io::Write;
            let mut stderr = std::io::stderr().lock();
            let _ = stderr.write_all(&bytes);
            let _ = stderr.write_all(b"\n");
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| eliot_process::EvidenceSinkError {
                message: "native-worker evidence lock poisoned".to_owned(),
            })?;
        if records.len() < Self::MAX_RETAINED {
            records.push(evidence);
        } else {
            drop(records);
            let mut dropped =
                self.dropped
                    .lock()
                    .map_err(|_| eliot_process::EvidenceSinkError {
                        message: "native-worker evidence lock poisoned".to_owned(),
                    })?;
            *dropped = dropped.saturating_add(1);
        }
        Ok(())
    }
}

/// Bins-local admitted-claim material reader for the native-worker dispatch
/// contour (slice D, T9-07 consumer half, DISPATCH-CAUSE-FIX child half).
///
/// This module binds the admitted driver
/// ([`drive_admitted_claimed`]) to session-bound claim bytes delivered by the
/// Kernel dispatch contour, and keeps the binary fail-closed until that
/// delivery validates. It owns no wire contract, mints no authority, and
/// changes no shared type.
///
/// Delivery shape (I7.5/I15.2): the dispatch contour writes exactly one file
/// named
/// [`ADMITTED_MATERIAL_FILE_NAME`][crate::admitted_material::ADMITTED_MATERIAL_FILE_NAME]
/// next to this executable before spawn
/// and reaps it after the run. The locator is derived from
/// [`std::env::current_exe`], which reads the OS loader image path, not the
/// environment block; no value is taken from argv, stdin, or environment
/// variables, and no ownership is inferred from the path itself
/// (`bins/AGENTS.md`: the file is untrusted presenter bytes until every
/// identity below is re-proved).
///
/// Two file shapes are accepted for the one file name:
/// - the Kernel launch-grant shape (`request`, `receipt`, `epoch`,
///   `generation`, `nonce`, `grant`), written by the Kernel dispatch contour
///   (`bins/eliot-kernel/src/dispatch_launch.rs`,
///   `native_worker_material_bytes`). The `request` is the exact admitted
///   `NativeWorkerClaimRequest`, the `receipt` its Kernel-issued
///   `NativeWorkerClaimReceipt`, and the `grant` the shared `DispatchGrant`.
///   From these the reader converts the worker-side claim, registration,
///   hello, reconcile, and readiness presentations in-process (all
///   worker-originated or claim-derived, never caller bytes) and validates
///   the grant into a [`ValidatedDispatchGrant`][crate::ValidatedDispatchGrant]
///   through the production `FencingToken` / `ActionLeaseRef` constructors.
///   The kernel `nonce` is the I7.5/I15.2 session nonce: it is independent of
///   the join/hello launch nonce by kernel design and is carried for
///   correlation, never equated with the join nonce.
/// - the legacy hello/join envelope (`admission`, `hello`, `reconcile`,
///   `readiness`, `nonce`), kept byte-for-byte for the existing contour
///   proofs. It carries no launch grant, so it validates but cannot drive:
///   the binary denies fail-closed when no grant is present.
///
/// Validation (all before any drive, all fail-closed to exit 78 without
/// effect):
///
/// - envelope wire shape plus bounded input, then the exact
///   claim/registration cross-binding through the production
///   [`ClaimAdmissionRequest::validate_binding`][eliot_native_worker_core::ClaimAdmissionRequest::validate_binding];
/// - for the Kernel shape additionally: the closed request shape (wire,
///   protocol, schema, digests) through a conversion into the worker-side
///   claim, whose production `validate` recomputes the canonical binding
///   digest — a tampered or foreign claim is refused here; the receipt
///   answering the exact request (claim, binding, and operation identity
///   plus the receipt digest); the live epoch and generation binding the
///   claim; the well-formed session nonce; and the grant (digest shape,
///   live window, fence/lease construction, epoch agreement with the claim);
/// - the session nonce rules per shape (envelope: equal to the presented
///   hello and join launch nonces; Kernel file: well-formed and carried);
/// - the reconcile and readiness presentations each validating through
///   their production gates and answering the exact admitted claim (claim
///   identity plus binding digest).
///
/// A validated file is consumed once (best-effort removal; removal failure
/// never fails the run). A missing file is not an error: it means the
/// dispatch contour delivered nothing to this invocation, and the caller
/// keeps the exact fail-closed path. A present but invalid file is a typed
/// denial, never a drive.
///
/// What this module deliberately does NOT deliver: the concrete
/// [`ProcessRequest`] is an in-memory
/// composition value that is never deserialized from a wire type. It is
/// derived in-process from the validated grant plus the canonical intent
/// rule ([`derive_admitted_intent`][crate::derive_admitted_intent]) and
/// issued through the in-child [`NativeWorkerDispatchAuthority`][crate::NativeWorkerDispatchAuthority]
/// (the documented broker pattern). The factory-identity half of the seam
/// landed as [`FactorySelection`][crate::FactorySelection] plus
/// [`select_factory_for_admitted`][crate::select_factory_for_admitted]; the
/// drive itself re-proves everything through the production `from_claim`
/// join, executable gate, grant checks, and receipt/proof validation, so
/// these pre-filters never weaken (and never replace) any existing check.
pub mod admitted_material {
    use std::fs;
    use std::path::{Path, PathBuf};

    use eliot_native_worker_core::{
        ClaimAdmissionRequest, NativeWorkerClaim, ReadinessSubmission, WorkerHello,
    };
    use serde::{Deserialize, Serialize};

    use crate::ReconcileSubmission;
    use crate::dispatch_authority::ValidatedDispatchGrant;

    /// Bins-local dispatch file name, read from the executable directory only.
    /// See the module documentation: locator, never authority.
    pub const ADMITTED_MATERIAL_FILE_NAME: &str = "eliot-native-worker.admitted-claim.json";

    /// Upper bound for the dispatch file. The typed presentations are each a
    /// few kilobytes; this adds ample headroom for the executable join plus
    /// the session nonce and the launch grant without accepting unbounded
    /// input.
    pub const ADMITTED_MATERIAL_LIMIT_BYTES: u64 = 256 * 1024;

    /// Session-nonce shape bounds (I7.5): opaque, bounded, never invented here.
    pub const ADMITTED_NONCE_MIN_LEN: usize = 16;
    /// Session-nonce shape bounds (I7.5): opaque, bounded, never invented here.
    pub const ADMITTED_NONCE_MAX_LEN: usize = 256;

    /// Kernel claim-wire identity, mirroring
    /// `eliot_kernel_service::NATIVE_WORKER_CLAIM_WIRE_ID`. The child cannot
    /// depend on that crate, so the literal is pinned here with its source;
    /// a wire drift fails closed at parse time.
    const KERNEL_CLAIM_WIRE_ID: &str = "eliot.kernel.native-worker-claim";

    /// Bins-local dispatch envelope (NOT a wire contract change).
    ///
    /// Carries exactly the serializable presentations
    /// [`drive_admitted_claimed`][crate::drive_admitted_claimed] binds, plus
    /// the I7.5 session `nonce`. The concrete
    /// [`ProcessRequest`][eliot_process::ProcessRequest] is intentionally
    /// absent: it is never deserialized and never minted here. Every field is
    /// untrusted presenter bytes until [`read_admitted_material`] validates
    /// it; the drive re-proves everything again.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AdmittedClaimEnvelope {
        /// Exact claim presentation: one validated registration plus one
        /// validated claim.
        pub admission: ClaimAdmissionRequest,
        /// Owner-supplied handshake the claim join binds.
        pub hello: WorkerHello,
        /// Lost-acknowledgement reconcile bound to the exact claim.
        pub reconcile: ReconcileSubmission,
        /// Typed ready-or-blocked verdict bound to the exact claim.
        pub readiness: ReadinessSubmission,
        /// I7.5 session nonce; must equal the presented hello launch nonce
        /// (and the v2 executable-join launch nonce when present).
        pub nonce: String,
    }

    /// Session-bound claim material validated against itself.
    ///
    /// Carries exactly the presentations the admitted driver binds, plus —
    /// on the Kernel launch-grant path — the validated grant that funds the
    /// in-process one-shot permit. The legacy envelope path carries no grant
    /// and therefore validates but cannot drive.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ValidatedAdmittedMaterial {
        /// Validated claim presentation.
        pub admission: ClaimAdmissionRequest,
        /// Validated owner-supplied handshake (legacy path) or the
        /// worker-originated handshake derived from the admitted claim
        /// (Kernel path).
        pub hello: WorkerHello,
        /// Validated reconcile bound to the exact admitted claim.
        pub reconcile: ReconcileSubmission,
        /// Validated readiness verdict bound to the exact admitted claim.
        pub readiness: ReadinessSubmission,
        /// Session nonce bound to the presented hello and join (legacy path)
        /// or to the derived hello and join (Kernel path: the join launch
        /// nonce, which the factory seam resolves).
        pub nonce: String,
        /// Validated Kernel launch grant. `Some` on the Kernel file path
        /// (the drive issues its one-shot permit from this); `None` on the
        /// legacy envelope path (which therefore cannot drive).
        pub grant: Option<ValidatedDispatchGrant>,
        /// Kernel session nonce from the launch-grant file. Independent of
        /// the join/hello launch nonce by kernel design; carried for
        /// correlation, never equated. `None` on the legacy path.
        pub kernel_nonce: Option<String>,
        /// Owner-measured worker artifact digest (Kernel path: the admitted
        /// request field; legacy path: the admitted registration field).
        /// Feeds the canonical intent derivation; the executor re-hashes the
        /// file before any start.
        pub worker_artifact_digest: String,
    }

    /// Typed failure for the dispatch-file read. Every variant is fail-closed:
    /// the binary entry maps each to exit 78 without effect.
    #[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
    pub enum AdmittedMaterialError {
        /// The dispatch file exists but cannot be read.
        #[error("admitted material unreadable: {0}")]
        Io(String),
        /// The dispatch file exceeds the bounded input limit.
        #[error("admitted material exceeds {maximum} bytes (observed {actual})")]
        TooLarge {
            /// Enforced input bound.
            maximum: u64,
            /// Observed file length.
            actual: u64,
        },
        /// The dispatch file is not a closed claim envelope.
        #[error("admitted material is not a closed claim envelope: {0}")]
        Malformed(String),
        /// The dispatch material violates the production claim contract
        /// (admission binding, reconcile shape, or readiness verdict).
        #[error("admitted material violates the claim contract: {0}")]
        Contract(String),
        /// The session nonce, reconcile, or readiness does not bind the
        /// exact presented claim.
        #[error("admitted material does not bind the presented claim: {0}")]
        Binding(String),
        /// The session nonce is missing or malformed.
        #[error(
            "admitted material nonce is missing or malformed: a well-formed session nonce bound to the presented hello is required"
        )]
        BadNonce,
    }

    /// Derives the bins-local dispatch file path: the executable directory plus
    /// [`ADMITTED_MATERIAL_FILE_NAME`].
    ///
    /// Locator only, never authority: [`std::env::current_exe`] reads the OS
    /// loader image path, not the environment block, and the file found there
    /// is untrusted presenter bytes until validated. Returns `None` when the
    /// image path is unavailable, which the caller treats as absent material.
    #[must_use]
    pub fn admitted_material_path() -> Option<PathBuf> {
        let executable = std::env::current_exe().ok()?;
        let directory = executable.parent()?;
        Some(directory.join(ADMITTED_MATERIAL_FILE_NAME))
    }

    /// Reads and validates the session-bound claim material for this
    /// invocation.
    ///
    /// Returns `Ok(None)` when no dispatch file was delivered (the caller keeps
    /// the exact fail-closed path), `Ok(Some(_))` when the file validated and
    /// was consumed once, and `Err(_)` typed fail-closed when a file is
    /// present but invalid. Never reads argv, stdin, or environment.
    pub fn read_admitted_material()
    -> Result<Option<ValidatedAdmittedMaterial>, AdmittedMaterialError> {
        let Some(path) = admitted_material_path() else {
            return Ok(None);
        };
        read_admitted_material_from(&path)
    }

    /// Reads and validates session-bound claim material from one explicit
    /// path, for the production locator plus bounded tests.
    ///
    /// The path parameter exists so tests can stage material without touching
    /// the executable directory; production always passes
    /// [`admitted_material_path`]. Semantics match
    /// [`read_admitted_material`].
    pub fn read_admitted_material_from(
        path: &Path,
    ) -> Result<Option<ValidatedAdmittedMaterial>, AdmittedMaterialError> {
        if let Some(actual) = bounded_file_len(path)? {
            return Err(AdmittedMaterialError::TooLarge {
                maximum: ADMITTED_MATERIAL_LIMIT_BYTES,
                actual,
            });
        }
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(AdmittedMaterialError::Io(error.to_string())),
        };
        let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual > ADMITTED_MATERIAL_LIMIT_BYTES {
            return Err(AdmittedMaterialError::TooLarge {
                maximum: ADMITTED_MATERIAL_LIMIT_BYTES,
                actual,
            });
        }
        match serde_json::from_slice::<AdmittedClaimEnvelope>(&bytes) {
            Ok(envelope) => {
                let validated = validate_envelope(envelope)?;
                consume_material(path);
                Ok(Some(validated))
            }
            Err(envelope_error) => {
                if is_kernel_grant_file(&bytes) {
                    let validated = validate_kernel_file_bytes(&bytes)?;
                    consume_material(path);
                    Ok(Some(validated))
                } else {
                    Err(AdmittedMaterialError::Malformed(truncate_detail(
                        &envelope_error.to_string(),
                    )))
                }
            }
        }
    }

    /// Consume-once: a validated presentation must not linger for a later
    /// invocation to replay. Removal is best-effort; the kernel launch reaps
    /// the file regardless, and removal failure never fails the run.
    fn consume_material(path: &Path) {
        let _ = fs::remove_file(path);
    }

    /// Peeks whether delivered bytes carry the Kernel launch-grant shape.
    ///
    /// The two accepted shapes share one file name, so the reader branches
    /// on content: a JSON object carrying the `grant` key takes the Kernel
    /// path (which re-validates everything through its closed structs);
    /// anything else stays on the legacy envelope path with its exact
    /// existing errors. A hybrid carrying both shapes fails closed in both
    /// parsers (`deny_unknown_fields` on each side).
    fn is_kernel_grant_file(bytes: &[u8]) -> bool {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .is_some_and(|object| object.contains_key("grant"))
    }

    /// Pre-checks the file length so an unbounded file is refused before it is
    /// read. Returns `Ok(None)` when the length is within bounds or unknown
    /// (the post-read check still applies); returns the observed length when it
    /// already exceeds the bound. A missing file surfaces as `Ok(None)` here so
    /// the read below can report absence exactly once.
    fn bounded_file_len(path: &Path) -> Result<Option<u64>, AdmittedMaterialError> {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(AdmittedMaterialError::Io(error.to_string())),
        };
        let actual = metadata.len();
        if actual > ADMITTED_MATERIAL_LIMIT_BYTES {
            Ok(Some(actual))
        } else {
            Ok(None)
        }
    }

    /// Validates one parsed envelope through the production gates. Every check
    /// is fail-closed; the order is cheapest-first and performs no transport,
    /// no execution, and no authority minting. The admitted drive re-proves
    /// the full `from_claim` join, executable gate, grant checks, and
    /// receipt/proof validation, so these pre-filters never weaken it; in
    /// particular an old-wire (v1) claim is left for the drive to refuse
    /// rather than being promoted or silently repaired here.
    fn validate_envelope(
        envelope: AdmittedClaimEnvelope,
    ) -> Result<ValidatedAdmittedMaterial, AdmittedMaterialError> {
        validate_nonce(&envelope.nonce)?;
        envelope.admission.validate_binding().map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;
        if envelope.nonce != envelope.hello.launch_nonce {
            return Err(AdmittedMaterialError::Binding(
                "session nonce is not bound to the presented hello launch nonce".to_owned(),
            ));
        }
        let claim = envelope.admission.claim();
        if let Some(join) = claim.executable_binding.as_ref()
            && envelope.nonce != join.launch_nonce
        {
            return Err(AdmittedMaterialError::Binding(
                "session nonce is not bound to the presented executable join launch nonce"
                    .to_owned(),
            ));
        }
        envelope.reconcile.validate().map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;
        require_same_claim("reconcile", envelope.reconcile.claim(), claim)?;
        let now = now_unix_ms()?;
        envelope.readiness.validate_binding(now).map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;
        require_same_claim("readiness", envelope.readiness.claim(), claim)?;
        let worker_artifact_digest = envelope
            .admission
            .registration()
            .worker_artifact_digest
            .clone();
        Ok(ValidatedAdmittedMaterial {
            admission: envelope.admission,
            hello: envelope.hello,
            reconcile: envelope.reconcile,
            readiness: envelope.readiness,
            nonce: envelope.nonce,
            grant: None,
            kernel_nonce: None,
            worker_artifact_digest,
        })
    }

    /// Requires the reconcile/readiness presentation to answer the exact
    /// admitted claim: same claim identity with the same binding digest. A
    /// rewired verdict is a refusal, never a silent supersede.
    fn require_same_claim(
        origin: &str,
        candidate: &NativeWorkerClaim,
        admitted: &NativeWorkerClaim,
    ) -> Result<(), AdmittedMaterialError> {
        if candidate.claim_id != admitted.claim_id
            || candidate.binding_digest != admitted.binding_digest
        {
            return Err(AdmittedMaterialError::Binding(format!(
                "{origin} verdict does not answer the exact admitted claim"
            )));
        }
        Ok(())
    }

    /// Requires a well-formed opaque session nonce: bounded length over an
    /// explicit hyphen/underscore/dot alphanumeric alphabet. The value is never
    /// interpreted, only carried for the kernel-side session proof.
    fn validate_nonce(nonce: &str) -> Result<(), AdmittedMaterialError> {
        if !(ADMITTED_NONCE_MIN_LEN..=ADMITTED_NONCE_MAX_LEN).contains(&nonce.len())
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(AdmittedMaterialError::BadNonce);
        }
        Ok(())
    }

    /// Validates one parsed Kernel launch-grant file through the production
    /// gates, then converts it into the exact presentations the admitted
    /// driver binds. Every check is fail-closed; the order is cheapest-first
    /// and performs no transport, no execution, and no authority minting.
    ///
    /// The file shape is `{request, receipt, epoch, generation, nonce,
    /// grant}` (see the module documentation). The `request` converts into
    /// the worker-side claim whose production `validate` recomputes the
    /// canonical binding digest — the strongest local anchor: a tampered or
    /// foreign claim is refused even when every other field is well-formed.
    /// The receipt must answer that exact request (claim, binding, and
    /// operation identity); the live epoch and generation must bind the
    /// claim; the grant must be well-formed, live, and epoch-bound to the
    /// claim, with its fence and lease rebuilt through the production
    /// constructors. Registration, hello, reconcile, and readiness are
    /// derived from admitted material plus live process observables (own
    /// PID, wall clock) — never from argv, stdin, or environment — and each
    /// re-validates through its production gate. The admitted drive re-proves
    /// everything again through the `from_claim` join, executable gate,
    /// grant checks, and receipt/proof validation.
    fn validate_kernel_file_bytes(
        bytes: &[u8],
    ) -> Result<ValidatedAdmittedMaterial, AdmittedMaterialError> {
        let file: KernelDispatchFile = serde_json::from_slice(bytes).map_err(|error| {
            AdmittedMaterialError::Malformed(truncate_detail(&error.to_string()))
        })?;
        let now = now_unix_ms()?;
        validate_kernel_file(file, now)
    }

    /// Closed mirror of the Kernel-written launch-grant file.
    ///
    /// Mirrors `native_worker_material_bytes` in
    /// `bins/eliot-kernel/src/dispatch_launch.rs` (`request`,
    /// `NativeWorkerClaimRequest`; `receipt`, `NativeWorkerClaimReceipt`;
    /// `epoch`, live authority; `generation`, live activation generation;
    /// `nonce`, session nonce; `grant`, shared `DispatchGrant`). The
    /// request, receipt, and epoch stay untyped JSON here because this crate
    /// cannot depend on `eliot-kernel-service` or `eliot-contracts`: the
    /// request converts field-by-field into the worker-side claim (whose
    /// validators then own every check), and every cross-binding compares
    /// canonical JSON values.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct KernelDispatchFile {
        /// Exact admitted claim request.
        request: serde_json::Value,
        /// Kernel-issued receipt answering the request.
        receipt: serde_json::Value,
        /// Live authority epoch bound at admission.
        epoch: serde_json::Value,
        /// Live activation generation bound at admission.
        generation: u64,
        /// Session nonce, independent of the join launch nonce by design.
        nonce: String,
        /// Shared launch grant funding the in-child one-shot permit.
        grant: KernelGrantFile,
    }

    /// Closed mirror of the shared `DispatchGrant`.
    ///
    /// Mirrors `DispatchGrant` in `bins/eliot-kernel/src/dispatch_launch.rs`.
    /// The authority epoch stays untyped JSON (proven equal to the admitted
    /// claim epoch, whose typed value feeds the fence constructor).
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct KernelGrantFile {
        /// Digest binding the grant fields plus the admission identity.
        grant_digest: String,
        /// Live authority epoch for `FencingToken::new`.
        authority_epoch: serde_json::Value,
        /// Live activation generation for `Generation::new`.
        fence_generation: u64,
        /// Per-identity fence nonce for `FencingToken::new`.
        fence_nonce: String,
        /// Per-identity lease for `ActionLeaseRef::new`.
        idempotency_key: String,
        /// Grant expiry in Unix milliseconds for `PermitIssuance::new`.
        expires_at: u64,
    }

    /// Validates one parsed Kernel file and converts it into the admitted
    /// presentations.
    #[allow(clippy::too_many_lines)]
    fn validate_kernel_file(
        file: KernelDispatchFile,
        now_ms: u64,
    ) -> Result<ValidatedAdmittedMaterial, AdmittedMaterialError> {
        use eliot_native_worker_core::{
            EXECUTION_UNIT_SCHEMA_VERSION, JSON_ENCODING_PROFILE, NATIVE_WORKER_CLAIM_WIRE_VERSION,
            NativeWorkerRegistration, PROTOCOL_VERSION,
        };
        use eliot_process::{ActionLeaseRef, FencingToken, Generation};

        let request = file.request.as_object().ok_or_else(|| {
            AdmittedMaterialError::Malformed("kernel file request is not an object".to_owned())
        })?;
        // Closed request shape: the wire, protocol, and schema pins use the
        // worker-core constants so a drift on either side fails closed here
        // instead of passing a stranger through to the drive.
        if request.get("wire_id").and_then(serde_json::Value::as_str) != Some(KERNEL_CLAIM_WIRE_ID)
        {
            return Err(AdmittedMaterialError::Contract(
                "kernel file request carries an unknown claim wire".to_owned(),
            ));
        }
        if request
            .get("wire_version")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::from(NATIVE_WORKER_CLAIM_WIRE_VERSION))
        {
            return Err(AdmittedMaterialError::Contract(
                "kernel file request carries an unsupported claim wire version".to_owned(),
            ));
        }
        if request
            .get("protocol_version")
            .and_then(serde_json::Value::as_str)
            != Some(PROTOCOL_VERSION)
        {
            return Err(AdmittedMaterialError::Contract(
                "kernel file request carries an unsupported worker protocol".to_owned(),
            ));
        }
        if request
            .get("execution_unit_schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::from(EXECUTION_UNIT_SCHEMA_VERSION))
        {
            return Err(AdmittedMaterialError::Contract(
                "kernel file request carries an unsupported execution-unit schema".to_owned(),
            ));
        }
        for key in [
            "binding_digest",
            "request_digest",
            "worker_artifact_digest",
            "worker_config_digest",
        ] {
            match request.get(key).and_then(serde_json::Value::as_str) {
                Some(digest) if is_lowercase_sha256(digest) => {}
                _ => {
                    return Err(AdmittedMaterialError::Contract(format!(
                        "kernel file request digest {key} is not a lowercase SHA-256 digest"
                    )));
                }
            }
        }
        if !request
            .get("executable_binding")
            .is_some_and(serde_json::Value::is_object)
        {
            return Err(AdmittedMaterialError::Contract(
                "kernel file request carries no owner-produced executable join".to_owned(),
            ));
        }
        // Convert the Kernel request into the worker-side claim. Field names
        // match the worker shape exactly (the Kernel projection reuses the
        // T9-01 names; transparent newtypes serialize to identical JSON), so
        // this is a verbatim field map, never a reinterpretation.
        let claim_json = serde_json::json!({
            "claim_id": request.get("claim_id").cloned().unwrap_or(serde_json::Value::Null),
            "registration_id": request.get("registration_id").cloned().unwrap_or(serde_json::Value::Null),
            "worker_generation": request.get("worker_generation").cloned().unwrap_or(serde_json::Value::Null),
            "parent_job_id": request.get("parent_job_id").cloned().unwrap_or(serde_json::Value::Null),
            "task_id": request.get("task_id").cloned().unwrap_or(serde_json::Value::Null),
            "work_scope_id": request.get("work_scope_id").cloned().unwrap_or(serde_json::Value::Null),
            "decision_id": request.get("decision_id").cloned().unwrap_or(serde_json::Value::Null),
            "attempt_id": request.get("attempt_id").cloned().unwrap_or(serde_json::Value::Null),
            "operation_id": request.get("operation_id").cloned().unwrap_or(serde_json::Value::Null),
            "route_class": request.get("route_class").cloned().unwrap_or(serde_json::Value::Null),
            "budget": request.get("budget").cloned().unwrap_or(serde_json::Value::Null),
            "deadline_unix_ms": request.get("deadline_unix_ms").cloned().unwrap_or(serde_json::Value::Null),
            "cancellation_policy_id": request.get("cancellation_policy_id").cloned().unwrap_or(serde_json::Value::Null),
            "expected_result_schema": request.get("expected_result_schema").cloned().unwrap_or(serde_json::Value::Null),
            "expected_result_schema_version": request.get("expected_result_schema_version").cloned().unwrap_or(serde_json::Value::Null),
            "predecessor_revision": request.get("predecessor_revision").cloned().unwrap_or(serde_json::Value::Null),
            "authority_epoch": request.get("authority_epoch").cloned().unwrap_or(serde_json::Value::Null),
            "state_fence": request.get("state_fence").cloned().unwrap_or(serde_json::Value::Null),
            "wire_version": request.get("wire_version").cloned().unwrap_or(serde_json::Value::Null),
            "executable_binding": request.get("executable_binding").cloned().unwrap_or(serde_json::Value::Null),
            "binding_digest": request.get("binding_digest").cloned().unwrap_or(serde_json::Value::Null),
        });
        let claim: NativeWorkerClaim =
            serde_json::from_value(claim_json.clone()).map_err(|error| {
                AdmittedMaterialError::Malformed(truncate_detail(&error.to_string()))
            })?;
        // The strongest local anchor: the production claim validator
        // recomputes the canonical binding digest over the converted fields.
        claim.validate().map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;
        let binding_digest = claim.binding_digest.clone();
        let join = claim.executable_binding.as_ref().ok_or_else(|| {
            AdmittedMaterialError::Contract(
                "kernel file claim carries no owner-produced executable join".to_owned(),
            )
        })?;

        // The receipt must answer this exact request: same claim, same
        // binding, same operation, same authority. A kernel file paired with
        // another claim's receipt is refused here.
        let receipt = file.receipt.as_object().ok_or_else(|| {
            AdmittedMaterialError::Malformed("kernel file receipt is not an object".to_owned())
        })?;
        if receipt.get("wire_id").and_then(serde_json::Value::as_str) != Some(KERNEL_CLAIM_WIRE_ID)
        {
            return Err(AdmittedMaterialError::Contract(
                "kernel file receipt carries an unknown claim wire".to_owned(),
            ));
        }
        if receipt.get("claim_id").and_then(serde_json::Value::as_str)
            != Some(claim.claim_id.as_str())
        {
            return Err(AdmittedMaterialError::Binding(
                "kernel file receipt does not answer the presented claim".to_owned(),
            ));
        }
        if receipt
            .get("binding_digest")
            .and_then(serde_json::Value::as_str)
            != Some(binding_digest.as_str())
        {
            return Err(AdmittedMaterialError::Binding(
                "kernel file receipt digest does not bind the presented claim".to_owned(),
            ));
        }
        if receipt
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            != Some(claim.operation_id.as_str())
        {
            return Err(AdmittedMaterialError::Binding(
                "kernel file receipt operation does not bind the presented claim".to_owned(),
            ));
        }
        match receipt
            .get("receipt_digest")
            .and_then(serde_json::Value::as_str)
        {
            Some(digest) if is_lowercase_sha256(digest) => {}
            _ => {
                return Err(AdmittedMaterialError::Contract(
                    "kernel file receipt digest is not a lowercase SHA-256 digest".to_owned(),
                ));
            }
        }
        if receipt.get("authority_epoch") != request.get("authority_epoch") {
            return Err(AdmittedMaterialError::Binding(
                "kernel file receipt epoch does not bind the presented claim".to_owned(),
            ));
        }
        // The live authority binds the claim: the file epoch is the epoch
        // the contour admitted under, and the file generation is the live
        // activation generation the grant fences. Either disagreeing with
        // the claim means a foreign or stale file.
        if file.epoch != request["authority_epoch"] {
            return Err(AdmittedMaterialError::Binding(
                "kernel file epoch does not bind the presented claim".to_owned(),
            ));
        }
        if file.generation == 0 || file.generation != claim.worker_generation {
            return Err(AdmittedMaterialError::Binding(
                "kernel file generation does not bind the presented claim generation".to_owned(),
            ));
        }

        // The session nonce is well-formed and carried for correlation. It
        // is deliberately NOT equated with the join launch nonce: the kernel
        // mints it independently per dispatch.
        validate_nonce(&file.nonce)?;

        // The grant funds the in-child one-shot permit. Digest shape, live
        // window, fence/lease construction through the production
        // constructors, and epoch agreement with the admitted claim — a
        // foreign or stale grant is refused before anything issues.
        let grant = &file.grant;
        if !is_lowercase_sha256(&grant.grant_digest) {
            return Err(AdmittedMaterialError::Contract(
                "kernel file grant digest is not a lowercase SHA-256 digest".to_owned(),
            ));
        }
        if grant.expires_at == 0 || grant.expires_at <= now_ms {
            return Err(AdmittedMaterialError::Contract(
                "kernel file grant window is stale or expired".to_owned(),
            ));
        }
        if grant.authority_epoch != request["authority_epoch"] {
            return Err(AdmittedMaterialError::Binding(
                "kernel file grant epoch does not bind the presented claim".to_owned(),
            ));
        }
        if grant.fence_generation != claim.worker_generation {
            return Err(AdmittedMaterialError::Binding(
                "kernel file grant generation does not bind the presented claim generation"
                    .to_owned(),
            ));
        }
        let fence_generation = Generation::new(grant.fence_generation).map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;
        // The window opens at the receipt admission time carried in the
        // file — the same instant the Kernel grant window opens — so both
        // owner and child derive identical freshness without mirroring any
        // kernel window constant.
        let admitted_at = receipt
            .get("admitted_at_unix_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        if admitted_at == 0 || admitted_at > now_ms || grant.expires_at <= admitted_at {
            return Err(AdmittedMaterialError::Contract(
                "kernel file grant window does not open at admission".to_owned(),
            ));
        }
        let fence = FencingToken::new(
            claim.authority_epoch.clone(),
            fence_generation,
            grant.fence_nonce.clone(),
        )
        .map_err(|error| AdmittedMaterialError::Contract(truncate_detail(&error.to_string())))?;
        let lease = ActionLeaseRef::new(grant.idempotency_key.clone()).map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;
        let validated_grant = ValidatedDispatchGrant::new(
            fence,
            lease,
            grant.grant_digest.clone(),
            admitted_at,
            grant.expires_at,
        )
        .map_err(|error| AdmittedMaterialError::Contract(truncate_detail(&error.to_string())))?;

        // Registration derived from admitted material plus live process
        // observables. Every identity-carrying field comes from the admitted
        // request; only the observation-bound fields (own PID, wall-clock
        // lease window) come from the live process, and the worker-originated
        // presentation identities derive deterministically from the proven
        // binding digest so they can never collide across claims.
        let limits = admitted_limits(request.get("budget").unwrap_or(&serde_json::Value::Null))?;
        let limits_json = serde_json::to_value(limits).map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;
        let lease_expires_at = now_ms.saturating_add(60_000);
        if lease_expires_at <= now_ms {
            return Err(AdmittedMaterialError::Contract(
                "worker lease window is not well-formed".to_owned(),
            ));
        }
        let installation_id = request
            .get("installation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let registration_json = serde_json::json!({
            "registration_id": request.get("registration_id").cloned().unwrap_or(serde_json::Value::Null),
            "installation_id": installation_id,
            "worker_artifact_digest": request.get("worker_artifact_digest").cloned().unwrap_or(serde_json::Value::Null),
            "worker_config_digest": request.get("worker_config_digest").cloned().unwrap_or(serde_json::Value::Null),
            "protocol_version": request.get("protocol_version").cloned().unwrap_or(serde_json::Value::Null),
            "worker_generation": claim.worker_generation,
            "process_id": std::process::id(),
            "process_start_100ns": now_ms.saturating_mul(10_000),
            "process_image_digest": request.get("worker_artifact_digest").cloned().unwrap_or(serde_json::Value::Null),
            "principal_ref": installation_id,
            "session_id": format!("native-worker-session-{binding_digest}"),
            "connection_id": format!("native-worker-conn-{binding_digest}"),
            "authority_epoch": request.get("authority_epoch").cloned().unwrap_or(serde_json::Value::Null),
            "state_fence": request.get("state_fence").cloned().unwrap_or(serde_json::Value::Null),
            "lease_id": format!("native-worker-lease-{binding_digest}"),
            "lease_expires_at_unix_ms": lease_expires_at,
            "renewal_id": format!("native-worker-renewal-{binding_digest}"),
            "execution_unit_schema_version": request.get("execution_unit_schema_version").cloned().unwrap_or(serde_json::Value::Null),
            "resource_limits": limits_json,
            "invalidation_set": [],
        });
        let registration: NativeWorkerRegistration =
            serde_json::from_value(registration_json.clone()).map_err(|error| {
                AdmittedMaterialError::Malformed(truncate_detail(&error.to_string()))
            })?;
        registration.validate().map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;
        let admission_json =
            serde_json::json!({"registration": registration_json, "claim": claim_json});
        let admission: ClaimAdmissionRequest =
            serde_json::from_value(admission_json).map_err(|error| {
                AdmittedMaterialError::Malformed(truncate_detail(&error.to_string()))
            })?;
        admission.validate_binding().map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;

        // Worker-originated handshake for the admitted claim. Every
        // join-bound field echoes the validated join (route, launch nonce,
        // generation, epoch, fence); the deadline sits strictly inside both
        // the claim window and the binding window; the remaining fields are
        // worker-ambient (connection/request/trace/capabilities/manifest
        // reference) and carry no authority — the `from_claim` join plus the
        // executable gate re-prove the bound fields at drive time.
        let window_cap = claim.deadline_unix_ms.min(join.expires_at_unix_ms);
        let hello_deadline = now_ms
            .saturating_add(30_000)
            .min(window_cap.saturating_sub(1));
        if hello_deadline == 0 {
            return Err(AdmittedMaterialError::Contract(
                "kernel file claim window cannot host a handshake deadline".to_owned(),
            ));
        }
        let hello = WorkerHello {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            encoding_profile: JSON_ENCODING_PROFILE.to_owned(),
            connection_id: format!("native-worker-conn-{binding_digest}"),
            request_id: format!("native-worker-start-{binding_digest}"),
            trace_context: std::collections::BTreeMap::from([(
                "eliot.dispatch_nonce".to_owned(),
                file.nonce.clone(),
            )]),
            deadline_unix_ms: hello_deadline,
            artifact_manifest_digest: join.facet_manifest_ref.clone(),
            launch_nonce: join.launch_nonce.clone(),
            worker_generation: claim.worker_generation,
            authority_epoch: claim.authority_epoch.clone(),
            state_fence: claim.state_fence.clone(),
            route_ref: join.route_ref.clone(),
            requested_capabilities: std::collections::BTreeSet::from([
                "execute".to_owned(),
                "inspect".to_owned(),
            ]),
        };

        // Worker-originated reconcile and readiness for the exact admitted
        // claim, each through its production gate. The registry revision
        // echoes the admitted join identity and revision — the same values
        // the factory seam resolves — while the drive re-proves the live
        // resolution before anything starts.
        let reconcile = ReconcileSubmission::new(
            format!("native-worker-reconcile-{binding_digest}"),
            claim.clone(),
            None,
        );
        reconcile.validate().map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;
        let claim_epoch_json = serde_json::to_value(&claim.authority_epoch).map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;
        let claim_fence_json = serde_json::to_value(&claim.state_fence).map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;
        let readiness_json = serde_json::json!({
            "claim": claim_json,
            "readiness": {
                "kind": "READY",
                "payload": {
                    "ready_id": format!("native-worker-ready-{binding_digest}"),
                    "claim_id": claim.claim_id.as_str(),
                    "registration_id": claim.registration_id.as_str(),
                    "worker_generation": claim.worker_generation,
                    "authority_epoch": claim_epoch_json,
                    "state_fence": claim_fence_json,
                    "claim_binding_digest": binding_digest,
                    "adapter_registry_revision": format!("{}-r{}", join.adapter_id, join.adapter_revision),
                    "credential_refs": [],
                    "ready_at_unix_ms": now_ms,
                },
            },
        });
        let readiness: ReadinessSubmission =
            serde_json::from_value(readiness_json).map_err(|error| {
                AdmittedMaterialError::Malformed(truncate_detail(&error.to_string()))
            })?;
        readiness.validate_binding(now_ms).map_err(|error| {
            AdmittedMaterialError::Contract(truncate_detail(&error.to_string()))
        })?;

        let worker_artifact_digest = request
            .get("worker_artifact_digest")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Ok(ValidatedAdmittedMaterial {
            admission,
            hello,
            reconcile,
            readiness,
            nonce: join.launch_nonce.clone(),
            grant: Some(validated_grant),
            kernel_nonce: Some(file.nonce),
            worker_artifact_digest,
        })
    }

    /// Projects the admitted budget onto bounded executor limits.
    ///
    /// The claim budget carries no CPU or memory dimensions, so those stay
    /// unset; each byte stream is capped independently at the admitted
    /// output budget. The executor enforces the ceilings at start.
    fn admitted_limits(
        budget: &serde_json::Value,
    ) -> Result<eliot_process::ResourceLimits, AdmittedMaterialError> {
        use eliot_process::ResourceLimits;
        let wall_timeout_ms = budget
            .get("wall_time_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        let output_bytes = budget
            .get("output_bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        let max_descendants = budget
            .get("max_descendants")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or_default();
        ResourceLimits::new(
            wall_timeout_ms,
            None,
            None,
            output_bytes,
            output_bytes,
            max_descendants,
        )
        .map_err(|error| AdmittedMaterialError::Contract(truncate_detail(&error.to_string())))
    }

    /// Returns true for a lowercase SHA-256 digest shape.
    fn is_lowercase_sha256(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }

    /// Current Unix time in milliseconds for readiness deadline checks.
    fn now_unix_ms() -> Result<u64, AdmittedMaterialError> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| AdmittedMaterialError::Contract("worker clock is unavailable".to_owned()))?
            .as_millis()
            .try_into()
            .map_err(|_| AdmittedMaterialError::Contract("worker clock is out of range".to_owned()))
    }

    /// Bounds third-party error detail carried into deny lines.
    fn truncate_detail(detail: &str) -> String {
        const LIMIT: usize = 256;
        detail.chars().take(LIMIT).collect()
    }
}

fn write_frame(response: &WorkerResponse) -> Result<(), NativeWorkerError> {
    let mut output = io::stdout().lock();
    write_frame_to(response, &mut output)
}

fn read_frame() -> Result<Option<WorkerFrame>, NativeWorkerError> {
    let mut prefix = [0_u8; 4];
    let mut input = io::stdin().lock();
    match input.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(NativeWorkerError::Io(error)),
    }
    let length = u32::from_le_bytes(prefix);
    if length == 0 {
        return Err(NativeWorkerError::EmptyFrame);
    }
    if length > MAX_FRAME_BYTES {
        return Err(NativeWorkerError::FrameTooLarge {
            actual: length,
            maximum: MAX_FRAME_BYTES,
        });
    }
    let mut body = vec![0_u8; length as usize];
    input.read_exact(&mut body)?;
    Ok(Some(serde_json::from_slice(&body)?))
}

fn read_frame_from<R: Read>(reader: &mut R) -> Result<Option<WorkerFrame>, NativeWorkerError> {
    let mut prefix = [0_u8; 4];
    match reader.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(NativeWorkerError::Io(error)),
    }
    let length = u32::from_le_bytes(prefix);
    if length == 0 {
        return Err(NativeWorkerError::EmptyFrame);
    }
    if length > MAX_FRAME_BYTES {
        return Err(NativeWorkerError::FrameTooLarge {
            actual: length,
            maximum: MAX_FRAME_BYTES,
        });
    }
    let mut body = vec![0_u8; length as usize];
    reader.read_exact(&mut body)?;
    Ok(Some(serde_json::from_slice(&body)?))
}

fn write_frame_to<W: Write>(
    response: &WorkerResponse,
    writer: &mut W,
) -> Result<(), NativeWorkerError> {
    let body = serde_json::to_vec(response)?;
    let length = u32::try_from(body.len()).map_err(|_| NativeWorkerError::FrameTooLarge {
        actual: u32::MAX,
        maximum: MAX_FRAME_BYTES,
    })?;
    if length > MAX_FRAME_BYTES {
        return Err(NativeWorkerError::FrameTooLarge {
            actual: length,
            maximum: MAX_FRAME_BYTES,
        });
    }
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt::Debug;

    use eliot_cli::kernel_client::KernelClientError;
    use eliot_contracts::{
        DecisionId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
    };
    use eliot_native_worker_core::{
        AttemptId, BudgetEnvelope, JSON_ENCODING_PROFILE, NATIVE_WORKER_CLAIM_WIRE_VERSION,
        NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION, NativeClaimId,
        NativeRegistrationId, NativeWorkerExecutableBinding, PROTOCOL_VERSION,
    };
    use eliot_process::OperationId;

    use super::*;
    use crate::kernel_admission_client::kernel_admission_error;

    #[test]
    fn missing_session_bound_claim_is_typed_admission_failure() {
        let error = kernel_admission_error(&KernelClientError::MissingRequestIdentity);

        assert!(matches!(
            error,
            NativeWorkerError::KernelAdmissionRequired(detail)
                if detail == "kernel request identity is missing"
        ));
    }

    fn load<T, E: Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("admitted factory fixture failed: {error:?}"),
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

    fn join(route: &str, adapter: &str, nonce: &str) -> NativeWorkerExecutableBinding {
        NativeWorkerExecutableBinding {
            route_ref: route.to_owned(),
            adapter_id: adapter.to_owned(),
            adapter_revision: 3,
            config_digest: "c".repeat(64),
            facet_manifest_ref: "facet-manifest-7".to_owned(),
            grant_graph_revision: 5,
            replay_stream_id: "claim-1/gen-1".to_owned(),
            launch_nonce: nonce.to_owned(),
            process_invocation_digest: "d".repeat(64),
            authority_epoch: epoch(),
            generation: load(ResourceGeneration::new(1)),
            state_fence: fence(),
            deadline_unix_ms: 8_000,
            expires_at_unix_ms: 4_000_000_001_000,
            executable_wire_version: NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
            executable_binding_digest: "e".repeat(64),
        }
    }

    fn claim_with(route: &str, adapter: &str, nonce: &str, with_join: bool) -> NativeWorkerClaim {
        NativeWorkerClaim {
            claim_id: load(NativeClaimId::new("claim-1")),
            registration_id: load(NativeRegistrationId::new("registration-1")),
            worker_generation: 1,
            parent_job_id: "job-parent-1".to_owned(),
            task_id: load(TaskId::new("task-1")),
            work_scope_id: "scope-1".to_owned(),
            decision_id: load(DecisionId::new("decision-1")),
            attempt_id: load(AttemptId::new("attempt-1")),
            operation_id: load(OperationId::new("operation-1")),
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
            executable_binding: with_join.then(|| join(route, adapter, nonce)),
            binding_digest: "f".repeat(64),
        }
    }

    fn hello_with(route: &str, nonce: &str) -> WorkerHello {
        WorkerHello {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            encoding_profile: JSON_ENCODING_PROFILE.to_owned(),
            connection_id: "connection-1".to_owned(),
            request_id: "request-1".to_owned(),
            trace_context: BTreeMap::from([("trace_id".to_owned(), "trace-1".to_owned())]),
            deadline_unix_ms: 5_000,
            artifact_manifest_digest: "manifest-digest-1".to_owned(),
            launch_nonce: nonce.to_owned(),
            worker_generation: 1,
            authority_epoch: epoch(),
            state_fence: fence(),
            route_ref: route.to_owned(),
            requested_capabilities: BTreeSet::from(["inspect".to_owned()]),
        }
    }

    #[test]
    fn admitted_factory_selection_resolves_exactly_one_factory() {
        let nonce = "launch-nonce-factory-0001";
        let claim = claim_with("route-1", "adapter-test", nonce, true);
        let hello = hello_with("route-1", nonce);
        let selection = match select_factory_from_presented(&claim, &hello, nonce) {
            Ok(selection) => selection,
            Err(error) => panic!("factory selection must resolve: {error:?}"),
        };
        assert_eq!(selection.adapter_id, "adapter-test");
        assert_eq!(selection.adapter_revision, 3);
        assert_eq!(selection.route_ref, "route-1");
        assert_eq!(selection.config_digest, "c".repeat(64));
        assert_eq!(selection.replay_stream_id, "claim-1/gen-1");
        assert_eq!(selection.process_invocation_digest, "d".repeat(64));
    }

    #[test]
    fn admitted_factory_selection_is_fail_closed() {
        let nonce = "launch-nonce-factory-0002";
        let hello = hello_with("route-1", nonce);
        // Old wire without a join selects nothing.
        let joinless = claim_with("route-1", "adapter-test", nonce, false);
        assert!(matches!(
            select_factory_from_presented(&joinless, &hello, nonce),
            Err(NativeWorkerError::KernelAdmissionRequired(_))
        ));
        // A rewired route selects nothing.
        let claim = claim_with("route-1", "adapter-test", nonce, true);
        let rewired = hello_with("rewired-route-1", nonce);
        assert!(matches!(
            select_factory_from_presented(&claim, &rewired, nonce),
            Err(NativeWorkerError::KernelAdmissionRequired(_))
        ));
        // A rebound nonce selects nothing.
        assert!(matches!(
            select_factory_from_presented(&claim, &hello, "rebound-nonce-factory-0003"),
            Err(NativeWorkerError::KernelAdmissionRequired(_))
        ));
        // A missing factory identity selects nothing.
        let anonymous = claim_with("route-1", "   ", nonce, true);
        assert!(matches!(
            select_factory_from_presented(&anonymous, &hello, nonce),
            Err(NativeWorkerError::KernelAdmissionRequired(_))
        ));
        // A missing factory revision selects nothing.
        let mut unrevised = claim_with("route-1", "adapter-test", nonce, true);
        match unrevised.executable_binding.as_mut() {
            Some(binding) => binding.adapter_revision = 0,
            None => panic!("fixture must carry a join"),
        }
        assert!(matches!(
            select_factory_from_presented(&unrevised, &hello, nonce),
            Err(NativeWorkerError::KernelAdmissionRequired(_))
        ));
    }

    #[test]
    fn contour_sha256_matches_standard_vectors_and_canonical_hasher() {
        use crate::dispatch_authority::{hex_bytes, sha256_bytes};
        // Published SHA-256 vectors: the dependency-frozen implementation
        // must reproduce them exactly, or owner-side key derivation (which
        // uses the canonical hasher) diverges and no join ever closes.
        assert_eq!(
            hex_bytes(&sha256_bytes(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_bytes(&sha256_bytes(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Byte-for-byte against the repository hasher on non-trivial input:
        // two independent implementations agreeing here is the interop proof.
        let input = b"eliot-native-worker dispatch contour interop probe 0123456789 abcdefghijklmnopqrstuvwxyz";
        assert_eq!(
            hex_bytes(&sha256_bytes(input)),
            eliot_contracts::sha256_hex(input)
        );
    }
}
