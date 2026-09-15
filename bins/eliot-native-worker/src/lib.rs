//! Thin composition boundary for one isolated native-worker generation.
//!
//! The binary owns framing and process lifetime only. Admission, process
//! execution, evidence, replay, and checkpoint persistence remain injected
//! ports owned by the governing services.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

use eliot_native_worker_core::{
    CapabilityAdmissionPort, ClaimAdmissionRequest, DurableCheckpointPort, DurableReplayPort,
    NativeWorkerRegistration, ReadinessSubmission, WorkerCore, WorkerError, WorkerEventEnvelope,
    WorkerFrame, WorkerHello, WorkerLifecycle, WorkerReady,
};
use eliot_process::{ProcessExecutor, ProcessRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod kernel_admission_client;

pub use kernel_admission_client::{
    KernelNativeWorkerClient, KernelReplayPort, KernelReplayTransport,
    NATIVE_WORKER_CANCEL_OBSERVE_OPERATION, NATIVE_WORKER_CHECKPOINT_OPERATION,
    NATIVE_WORKER_CLAIM_OPERATION, NATIVE_WORKER_HEARTBEAT_OPERATION,
    NATIVE_WORKER_READY_OPERATION, NATIVE_WORKER_RECONCILE_OPERATION,
    NATIVE_WORKER_REGISTRATION_OPERATION, NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION,
    NATIVE_WORKER_REPLAY_APPEND_OPERATION, NATIVE_WORKER_REPLAY_BEGIN_OPERATION,
    NATIVE_WORKER_REPLAY_LOOKUP_OPERATION, NATIVE_WORKER_REPLAY_OPERATION,
    NATIVE_WORKER_RESULT_SUBMIT_OPERATION, ReconcileRetainedReceipt, ReconcileSubmission,
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

/// Bins-local admitted-claim material reader for the native-worker dispatch
/// contour (slice D, T9-07 consumer half).
///
/// This module binds the admitted driver
/// ([`drive_admitted_claimed`]) to session-bound claim bytes delivered by the
/// Kernel dispatch contour, and keeps the binary fail-closed until that
/// delivery lands. It owns no wire contract, mints no authority, and changes
/// no shared type.
///
/// Delivery shape (I7.5/I15.2): the dispatch contour writes exactly one file
/// named
/// [`ADMITTED_MATERIAL_FILE_NAME`][crate::admitted_material::ADMITTED_MATERIAL_FILE_NAME]
/// next to this executable before spawn
/// and reaps it after the run. The file
/// carries the five serializable presentations the admitted driver binds
/// (registration plus claim, hello, reconcile, readiness) plus the I7.5
/// session nonce. The locator is derived from [`std::env::current_exe`],
/// which reads the OS loader image path, not the environment block; no value
/// is taken from argv, stdin, or environment variables, and no ownership is
/// inferred from the path itself (`bins/AGENTS.md`: the file is untrusted
/// presenter bytes until every identity below is re-proved).
///
/// Validation (all before any drive, all fail-closed to exit 78 without
/// effect):
///
/// - envelope wire shape plus bounded input, then the exact
///   claim/registration cross-binding through the production
///   [`ClaimAdmissionRequest::validate_binding`][eliot_native_worker_core::ClaimAdmissionRequest::validate_binding];
/// - the session nonce must be well-formed (opaque, bounded) and equal the
///   presented `hello.launch_nonce` and, when the claim carries the v2
///   executable join, the join `launch_nonce`. The authoritative nonce proof
///   happens kernel-side at submit (front-door session plus the
///   echo/decision checks in the lifecycle spans), so the child never invents
///   it and never drives without it;
/// - the reconcile and readiness presentations must each validate through
///   their production gates and answer the exact admitted claim (claim
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
/// composition value that is never deserialized from a wire type and never
/// minted here, and the composed provider ports (P-03 dispatch validation,
/// G-01-facing admission, durable checkpoint) arrive only with the kernel
/// dispatch launch (T9-07, WRITER-B). Those gaps are named by
/// [`ADMITTED_DISPATCH_RESIDUAL`][crate::admitted_material::ADMITTED_DISPATCH_RESIDUAL];
/// until they land even a validated file cannot drive. The drive itself
/// re-proves everything through the production `from_claim` join,
/// executable gate, grant checks, and receipt/proof validation, so this
/// pre-filter never weakens (and never replaces) any existing check.
pub mod admitted_material {
    use std::fs;
    use std::path::{Path, PathBuf};

    use eliot_native_worker_core::{
        ClaimAdmissionRequest, NativeWorkerClaim, ReadinessSubmission, WorkerHello,
    };
    use serde::{Deserialize, Serialize};

    use crate::ReconcileSubmission;

    /// Bins-local dispatch file name, read from the executable directory only.
    /// See the module documentation: locator, never authority.
    pub const ADMITTED_MATERIAL_FILE_NAME: &str = "eliot-native-worker.admitted-claim.json";

    /// Upper bound for the dispatch file. The five typed presentations are
    /// each a few kilobytes; this adds ample headroom for the executable join
    /// plus the session nonce without accepting unbounded input.
    pub const ADMITTED_MATERIAL_LIMIT_BYTES: u64 = 256 * 1024;

    /// Session-nonce shape bounds (I7.5): opaque, bounded, never invented here.
    pub const ADMITTED_NONCE_MIN_LEN: usize = 16;
    /// Session-nonce shape bounds (I7.5): opaque, bounded, never invented here.
    pub const ADMITTED_NONCE_MAX_LEN: usize = 256;

    /// Residual naming the kernel half that must land before validated bytes
    /// can drive (T9-07, WRITER-B). The executor-bound `ProcessRequest`
    /// (never deserialized, never minted here) plus the composed provider
    /// ports (P-07 dispatch validation, G-01-facing admission, durable
    /// checkpoint) arrive only with the kernel dispatch launch; validated
    /// claim bytes alone never drive.
    pub const ADMITTED_DISPATCH_RESIDUAL: &str = "issue-22 T9-07 follow-up: kernel dispatch launch delivering the executor-bound ProcessRequest plus the composed provider ports (P-07 dispatch validation, G-01-facing admission, durable checkpoint) alongside the session-bound claim bytes to the native-worker invocation";

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
    /// Carries exactly the presentations the admitted driver binds. The
    /// concrete process request and the composed provider ports still arrive
    /// only with the kernel dispatch launch, so this value alone never
    /// drives; it is the validated input the launch seam will complete.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ValidatedAdmittedMaterial {
        /// Validated claim presentation.
        pub admission: ClaimAdmissionRequest,
        /// Validated owner-supplied handshake.
        pub hello: WorkerHello,
        /// Validated reconcile bound to the exact admitted claim.
        pub reconcile: ReconcileSubmission,
        /// Validated readiness verdict bound to the exact admitted claim.
        pub readiness: ReadinessSubmission,
        /// Well-formed session nonce bound to the presented hello (and join).
        pub nonce: String,
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
        let envelope: AdmittedClaimEnvelope = serde_json::from_slice(&bytes).map_err(|error| {
            AdmittedMaterialError::Malformed(truncate_detail(&error.to_string()))
        })?;
        let validated = validate_envelope(envelope)?;
        // Consume-once: a validated presentation must not linger for a later
        // invocation to replay. Removal is best-effort; the kernel launch reaps
        // the file regardless, and removal failure never fails the run.
        let _ = fs::remove_file(path);
        Ok(Some(validated))
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
        Ok(ValidatedAdmittedMaterial {
            admission: envelope.admission,
            hello: envelope.hello,
            reconcile: envelope.reconcile,
            readiness: envelope.readiness,
            nonce: envelope.nonce,
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
    use eliot_cli::kernel_client::KernelClientError;

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
}
