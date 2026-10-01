//! The one lifecycle-owned canonical Watchdog signals ingress (#2569 BK4).
//!
//! Architecture anchors: A12.2 (principal and session binding), A13.2 (failure
//! domains), ARCH-AUTH-01, ARCH-SEC-01, ARCH-SEC-02.
//! Implementation anchors: I1.4 (supervision tree), I1.5 (runtime and
//! supervision ownership), I7.3 (handshake), I7.4 (lifecycle messages), I7.5
//! (named pipes), I15.2 (local IPC identity binding), I8.1/I8.2 (independent
//! observation routes).
//!
//! Responsibility: own the ONE server on `EliotPipeName::watchdog_signals`, prove
//! the connected peer from the operating system before a single frame is read,
//! decode one canonical `#954` backup request from the existing framed IPC
//! payload, dispatch it through [`BackupControlHandle`] against the owners this
//! process actually holds, and publish the owner's own result back on the same
//! authenticated connection.
//!
//! Nothing here is new. The pipe is the canonical name the protocol owner already
//! declares; the codec is `eliot-ipc`'s existing bounded frame codec; the owners
//! are the same spool capture and isolated-restore owners this composition already
//! binds; and the typed requests are the `#954` canonical request types
//! themselves. There is no second transport, no second spool, no second method
//! table, and no second request shape.
//!
//! Peer authentication, stated at exactly the granularity the code proves:
//!
//! - the pipe DACL is built from the SID this service's own live token
//!   observation reports, remote clients are rejected, and the transport verifies
//!   that DACL on every connect;
//! - `NamedPipeServer::wait_for_authenticated_client` reads the fixed transport
//!   preface, resolves the CLIENT process id from the connected server-end HANDLE,
//!   opens that one process, captures PID, creation time, and image path from
//!   that same handle, and compares the process token SID and session id with the
//!   expectation — all before any frame is read;
//! - this module then compares the OS-observed client image against the
//!   installer-approved `eliot-kernel.exe` of THIS approved generation and
//!   against that image's no-follow file identity, so a same-service process that
//!   is not the approved Kernel is refused even though it shares the service
//!   token;
//! - the canonical `#954` request that follows is bound by
//!   [`BackupControlHandle::admit`] against this composition's own retained
//!   admission — session identity, owner generation, source installation,
//!   destination binding — and against the `#954` role/attester matrix, never
//!   against a peer identity the request itself carried.
//!
//! What this does NOT claim: no launcher nonce, MAC, or secret is exchanged on
//! this pipe, because the existing framed IPC carries none on any server in this
//! repository and this module adds no authentication layer of its own. The
//! exchange is therefore the same strength as the Kernel front door's, plus an
//! exact approved-Kernel image and file-identity check.
//!
//! Restart: the composed listener is a supervised child of THIS composition, so
//! the bounded in-memory retained-operation table dies with the composition and is
//! never consulted as a recovery authority. The durable recovery decision for
//! `RECONCILE_RESTORE` is read by the owner itself from the admitted destination
//! installation's own retained spool records, and `READ_SNAPSHOT_PAGE` is a pure
//! owner read re-observed live from the owner's own `watchdog.redb`. A restarted
//! owner therefore answers a repeated operation from spool records, not from
//! anything this process remembers.
//!
//! Typed refusals are preserved, not widened: `VERIFY_ARCHIVE` and
//! `RESTORE_STATUS` reach the same started handle as before and are refused
//! there, before any owner effect and before the operation is claimed, because
//! this owner holds no archive verifier and no restore-status projection. This
//! module never answers either with a value of its own.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_ipc::{DeliveryOutcome, NamedPipeServer, PeerIdentity, TransportError, TransportLimits};
use eliot_platform_windows::{
    NamedPipePeerExpectation, ServiceBootstrapArguments, current_process_named_pipe_expectation,
    file_identity_for_path, windows_paths_equal,
};
use eliot_protocol::EliotPipeName;
use eliot_protocol::backup::{
    BACKUP_ARCHIVE_VERIFICATION_WIRE_ID, BACKUP_RESTORE_RECONCILE_WIRE_ID,
    BACKUP_RESTORE_STATUS_WIRE_ID, BACKUP_SNAPSHOT_PAGE_READ_WIRE_ID, BackupArchiveVerification,
    BackupRestoreReconcile, BackupRestoreStatus, BackupSnapshotPageRead,
};
use eliot_runtime::{
    CancelHandle, CancellationDisposition, CancellationToken, ChildClass, SpawnDisposition,
    Supervisor, TaskFailure,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::CompositionError;
use crate::backup_control::{
    BackupControlError, BackupControlHandle, WatchdogBackupChannelOutcome, WatchdogBackupRequest,
};
use crate::watchdog_spool::backup::{SpoolRestoreDisposition, WatchdogSpoolSnapshotPage};
use crate::{
    AdmittedIsolatedDestination, SERVICE_NAME, SpoolError, SpoolRestoreStep, WatchdogComposition,
    WatchdogRuntimeBinding, admit_isolated_destination,
};

/// Stable refusal class published for a registered-but-unexecutable method.
///
/// One fixed class rather than the owner's internal wording: the wire carries the
/// class, and the owner's own typed reason stays in this composition's bounded
/// diagnostics.
pub const RECOGNIZED_WITHOUT_OWNER_METHOD: &str = "recognized_without_owner_method";

/// Stable reason a response write carries no durable application success.
const DELIVERY_IS_NOT_COMMIT: &str = "delivered_is_not_durable_commit";

/// Returns the exact canonical pipe this process serves.
///
/// Read from the protocol owner that already declares it, so the served name and
/// the client endpoint can never drift apart: `EliotPipeName::watchdog_signals`
/// renders `\\.\pipe\eliot\watchdog\signals`, the name
/// `bins/eliot-kernel/src/backup_owner_clients.rs` already publishes as
/// `WATCHDOG_BACKUP_PIPE`.
#[must_use]
pub fn watchdog_signals_pipe() -> String {
    EliotPipeName::watchdog_signals().to_string()
}

/// Fail-closed refusals of the canonical signals ingress.
///
/// Every variant happens before any owner effect, and none of them restates an
/// owner result: the owner's own typed refusal travels on the wire as
/// [`WatchdogSignalsOutcome`], never as this error.
#[derive(Debug, Error)]
pub enum WatchdogSignalsError {
    /// The listener could not be bound, or this composition could not start it.
    #[error("watchdog signals listener refused: {0}")]
    Listener(String),
    /// The authenticated peer could not be proved, or the frame was not one this
    /// owner can decode.
    #[error("watchdog signals transport refused: {0}")]
    Transport(#[from] TransportError),
    /// The composition refused to start the listener.
    #[error("watchdog signals listener refused: {0}")]
    Composition(#[from] BackupControlError),
    /// A presented SCM bootstrap is not canonical bootstrap data.
    #[error("watchdog signals destination bootstrap refused: {0}")]
    Bootstrap(String),
}

/// The installer-approved Kernel peer this listener admits.
///
/// Retains the live service-token expectation AND the exact approved Kernel image
/// of the generation this process was admitted under. Both are read from this
/// installation's own retained admission, never from a request: the expectation is
/// this service's live token observation, and the image is the approved manifest's
/// `kernel_executable_path` together with its no-follow file identity.
struct KernelPeerAdmission {
    expectation: NamedPipePeerExpectation,
    kernel_image: PathBuf,
    kernel_file: (u32, u64),
}

impl KernelPeerAdmission {
    /// Observes this service's own token expectation and the approved Kernel image
    /// of the retained generation.
    ///
    /// # Errors
    ///
    /// Returns [`WatchdogSignalsError::Listener`] when this service's token cannot
    /// be observed or the approved Kernel image cannot be retained with a
    /// no-follow file identity.
    fn observe(binding: &WatchdogRuntimeBinding) -> Result<Self, WatchdogSignalsError> {
        let expectation = current_process_named_pipe_expectation()
            .map_err(|error| WatchdogSignalsError::Listener(error.to_string()))?;
        let kernel_image = binding.approved_kernel_image().to_path_buf();
        let file = file_identity_for_path(&kernel_image)
            .map_err(|error| WatchdogSignalsError::Listener(error.to_string()))?;
        Ok(Self {
            expectation,
            kernel_image,
            kernel_file: (file.volume_serial_number, file.file_index),
        })
    }

    /// Returns whether the OS-authenticated peer is exactly this approved Kernel.
    ///
    /// Both halves are OS-observed: the image path comes from the connected
    /// client's own process handle, and the file identity is the no-follow
    /// identity of that same image path resolved by the platform adapter during
    /// authentication. An unauthenticated peer never reaches here — the transport
    /// refuses it first.
    fn admits(&self, peer: &PeerIdentity) -> bool {
        let PeerIdentity::Authenticated { proof, .. } = peer else {
            return false;
        };
        if proof.process.executable_file_identity() != Some(self.kernel_file) {
            return false;
        }
        windows_paths_equal(Path::new(proof.process.image_path()), &self.kernel_image)
    }
}

/// The bounded owner result this Watchdog publishes on the canonical transport.
///
/// Every variant carries the OWNER's own values, read from the owner that produced
/// them. `SnapshotPage` carries the owner's bounded page beside the owner's own
/// fence identity — never a re-derived or a caller's view of either.
/// `RecognizedWithoutOwnerMethod` exists because recognition is not availability:
/// this owner registers `VERIFY_ARCHIVE` and `RESTORE_STATUS` so they answer with
/// an explicit typed refusal instead of vanishing, and that refusal is the owner's
/// own, reached through the same handle and the same dispatch as any executable
/// method.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "outcome")]
pub enum WatchdogSignalsOutcome {
    /// The capture owner's fence identity and the bounded page read from it.
    SnapshotPage {
        /// The owner's own fence identity for this exact operation.
        fence: SignalsFenceIdentity,
        /// The owner's own bounded page.
        page: WatchdogSpoolSnapshotPage,
    },
    /// The isolated-restore owner's own disposition.
    Restore {
        /// Owner-observed disposition. `UNKNOWN` is publishable and blocking, so an
        /// unresolved signal stays visible instead of reading as success.
        disposition: SpoolRestoreDisposition,
    },
    /// A typed refusal of a registered-but-unexecutable method.
    RecognizedWithoutOwnerMethod {
        /// Stable canonical wire identity of the refused operation.
        operation: &'static str,
        /// Stable refusal class, never presented content.
        reason: &'static str,
    },
}

/// The bounded, owner-issued identity of one captured spool fence.
///
/// Read from the fence the owner itself produced. It is deliberately not the fence:
/// the fence holds the owner's private retained-entry vector and its coverage
/// report, and publishing those would widen what leaves this process without adding
/// anything a requester can use — the page itself carries the members, and
/// `content_digest` binds them.
#[derive(Clone, Debug, Serialize)]
pub struct SignalsFenceIdentity {
    /// Fence shape schema version.
    pub schema_version: u16,
    /// Owner-derived digest over the ordered entries this fence holds.
    pub content_digest: String,
    /// Durable high-water sequence bound by the capture.
    pub high_water: u64,
    /// Owner-derived digest over the canonical high-water bytes.
    pub high_water_digest: String,
    /// First retained sequence this fence's window covers.
    pub first_sequence: u64,
    /// Next sequence this fence's window ends at.
    pub next_sequence: u64,
    /// Exact retained-record count this fence covers.
    pub retained_members: u64,
    /// Exact retained byte total this fence covers.
    pub total_bytes: u64,
    /// The owner's own capture anchor.
    pub captured_at_ms: u64,
    /// Owner-held source installation the capture came from.
    pub source_installation: String,
    /// Owner-held generation the capture is bound to.
    pub watchdog_generation: u64,
    /// Admitted requester principal the capture was taken for.
    pub requester_principal: String,
    /// Stable snapshot operation identity this capture is bound to.
    pub snapshot_operation_id: String,
}

/// One isolated-restore request as it arrives on the canonical transport.
///
/// The canonical `BackupRestoreReconcile` is carried verbatim under `request` and
/// validated by its own `validate()`. The two owner-side inputs it does not carry
/// are carried beside it and are never trusted on their own:
///
/// - `steps` is this crate's own [`SpoolRestoreStep`], re-validated by the owner's
///   own chain check inside `import_isolated`;
/// - `destination` is a CLAIM. It is turned into the non-caller-constructible
///   [`AdmittedIsolatedDestination`] by the existing [`admit_isolated_destination`]
///   chain against the destination's OWN registry, approved generation, service
///   approvals, and artifact digests, before the owner is entered. A claim that
///   does not match that registry is refused.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsRestoreReconcile {
    /// Canonical reconcile request; the only authority-bearing payload.
    pub request: BackupRestoreReconcile,
    /// Bounded, operation-bound restore step chain to reconcile.
    pub steps: Vec<SpoolRestoreStep>,
    /// The destination installation's own registry and SCM bootstrap claims.
    pub destination: SignalsDestinationClaim,
}

/// One destination installation's registry and SCM bootstrap claims.
///
/// Both are claims, and both are proved against the destination's OWN registry by
/// [`admit_isolated_destination`]: the registry must be the destination's exact
/// approved Host child, and every bootstrap value must equal the approved manifest
/// that registry selects. Nothing here is an identity.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsDestinationClaim {
    /// Absolute path of the destination installation's registry file.
    pub registry_path: PathBuf,
    /// The destination's own installer-approved SCM bootstrap values.
    pub bootstrap: SignalsServiceBootstrapClaim,
}

/// One destination installation's claimed SCM bootstrap values.
///
/// The complete set the platform owner compares by equality against the
/// destination's own approved service registration: a partial claim could not be
/// equal to it, so it is refused rather than silently completed.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsServiceBootstrapClaim {
    /// Approved configuration-descriptor path.
    pub config_descriptor_path: PathBuf,
    /// Approved configuration-descriptor digest.
    pub config_descriptor_digest: String,
    /// Approved installation identity.
    pub installation_id: String,
    /// Approved authority generation.
    pub transaction_plan_generation: u64,
    /// Approved Host state root selector.
    pub host_state_root: Option<PathBuf>,
    /// Approved per-installation registration nonce.
    pub registration_nonce: Option<String>,
    /// Any additional installer-rendered bootstrap argv, in caller order.
    pub extra_args: Vec<String>,
}

impl SignalsServiceBootstrapClaim {
    /// Rebuilds the platform owner's typed bootstrap binding from this claim.
    ///
    /// # Errors
    ///
    /// Returns [`WatchdogSignalsError::Bootstrap`] when the platform owner refuses
    /// the claim as non-canonical bootstrap data.
    fn bind(&self) -> Result<ServiceBootstrapArguments, WatchdogSignalsError> {
        let bootstrap = ServiceBootstrapArguments::new(
            self.config_descriptor_path.clone(),
            self.config_descriptor_digest.clone(),
            self.installation_id.clone(),
            self.transaction_plan_generation,
            self.extra_args.clone(),
        )
        .map_err(|error| WatchdogSignalsError::Bootstrap(error.to_string()))?;
        let bootstrap = match &self.host_state_root {
            Some(root) => bootstrap
                .with_host_state_root(root.clone())
                .map_err(|error| WatchdogSignalsError::Bootstrap(error.to_string()))?,
            None => bootstrap,
        };
        match &self.registration_nonce {
            Some(nonce) => bootstrap
                .with_registration_nonce(nonce.clone())
                .map_err(|error| WatchdogSignalsError::Bootstrap(error.to_string())),
            None => Ok(bootstrap),
        }
    }
}

/// The live, lifecycle-owned canonical signals listener for ONE composition.
///
/// Owns the supervised child that binds `EliotPipeName::watchdog_signals` and the
/// started [`BackupControlHandle`] every admitted request dispatches through.
/// There is exactly one: the child runs on this composition's own runtime under a
/// one-for-one supervisor, so a listener failure restarts only the listener and can
/// never stop, stall, or quarantine supervision.
pub struct WatchdogSignalsServer {
    cancellation: CancelHandle,
    handle: Arc<BackupControlHandle>,
    pipe: String,
    owner_spool_high_water: u64,
}

impl std::fmt::Debug for WatchdogSignalsServer {
    /// Renders only bounded admission facts: the served pipe and the owner's
    /// durable high-water sequence.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WatchdogSignalsServer")
            .field("pipe", &self.pipe)
            .field("owner_spool_high_water", &self.owner_spool_high_water)
            .finish_non_exhaustive()
    }
}

impl WatchdogSignalsServer {
    /// Starts the canonical signals listener on this composition's own runtime.
    ///
    /// The pipe is bound INSIDE the supervised child, so a listener restart rebinds
    /// from scratch and never races a stale instance. The peer admission is observed
    /// once, here, from this process's live token and this installation's retained
    /// approved generation, and is then immutable for the listener's whole life: a
    /// fence movement is never observed by re-reading a request, it is observed by
    /// the owner handle refusing a stale generation.
    ///
    /// `handle` is shared, not moved: the listener and the composition's release
    /// point hold the SAME registration, so a refused listener costs no
    /// registration and a released registration can never leave a live listener
    /// dispatching.
    ///
    /// # Errors
    ///
    /// Returns [`WatchdogSignalsError::Composition`] when this composition retains
    /// no approved admission or its runtime is already shutting down and admits no
    /// child, and [`WatchdogSignalsError::Listener`] when this service's token or
    /// the approved Kernel image cannot be observed.
    pub fn start(
        composition: &WatchdogComposition,
        handle: Arc<BackupControlHandle>,
    ) -> Result<Self, WatchdogSignalsError> {
        let Some(binding) = composition.active_runtime_binding() else {
            return Err(BackupControlError::Composition(CompositionError::InvalidConfiguration(
                "watchdog signals listener refuses to start without this installation's retained approved admission"
                    .to_owned(),
            ))
            .into());
        };
        let peer = Arc::new(KernelPeerAdmission::observe(&binding)?);
        let pipe = watchdog_signals_pipe();
        let child = Arc::clone(&handle);
        let served = pipe.clone();
        let supervised: Supervisor = composition.signals_supervisor();
        let admitted = supervised.spawn(
            SERVICE_NAME,
            ChildClass::Worker,
            move |token| {
                let peer = Arc::clone(&peer);
                let handle = Arc::clone(&child);
                let pipe = served.clone();
                async move { run_signals_listener(pipe, peer, handle, token).await }
            },
        );
        let running = match admitted {
            SpawnDisposition::Admitted(running) => running,
            SpawnDisposition::DeniedShuttingDown => {
                return Err(BackupControlError::Composition(CompositionError::InvalidConfiguration(
                    "watchdog signals listener is refused because this composition is already shutting down"
                        .to_owned(),
                ))
                .into());
            }
        };
        let owner_spool_high_water = handle.owner_spool_high_water();
        tracing::info!(
            event = "watchdog.signals_listener_admitted",
            observation = "admitted",
            owner_spool_high_water,
            owner_generation = handle.owner_generation(),
            "watchdog canonical signals listener admitted against the installer-approved Kernel peer expectation"
        );
        Ok(Self {
            cancellation: running.cancellation(),
            handle,
            pipe,
            owner_spool_high_water,
        })
    }

    /// Returns the exact canonical pipe this listener serves.
    #[must_use]
    pub fn pipe(&self) -> &str {
        &self.pipe
    }

    /// Returns the owner's durable spool high-water sequence observed when the
    /// started handle was registered and re-observed when it was started.
    #[must_use]
    pub const fn owner_spool_high_water(&self) -> u64 {
        self.owner_spool_high_water
    }

    /// Cancels the listener.
    ///
    /// Cancellation is cooperative and bounded, and it stops a REAL listener: the
    /// accept wait and the connection both live inside `select!` arms over this
    /// token, so a cancelled loop drops the pipe handle rather than leaving a bound
    /// instance behind.
    ///
    /// This method never releases the backup-control registration. The listener and
    /// the registration share one handle precisely so the composition's single
    /// release point stays the single place a bounded slot is released and the
    /// single place unresolved work is reported; cancelling here and releasing
    /// there cannot double-release and cannot leave a listener dispatching through
    /// a released slot.
    pub fn cancel(&self) {
        let disposition = self.cancellation.cancel();
        tracing::info!(
            event = "watchdog.signals_listener_stopping",
            observation = cancellation_observation(disposition),
            unresolved_operations = self
                .handle
                .unresolved_operations()
                .unwrap_or(usize::MAX),
            "watchdog signals listener cancellation requested"
        );
    }
}

/// Names one cancellation disposition for a bounded trace field.
fn cancellation_observation(disposition: CancellationDisposition) -> &'static str {
    match disposition {
        CancellationDisposition::Requested => "requested",
        CancellationDisposition::AlreadyRequested => "already_requested",
        CancellationDisposition::AlreadyFinished => "already_finished",
    }
}

/// The supervised listener loop: bind, authenticate, serve, rebind.
///
/// Every iteration creates a fresh FIRST pipe instance, so a restart or a rebind
/// after a served connection can never leave a stale instance on the canonical name
/// and a second process cannot take the name while this one is alive.
async fn run_signals_listener(
    pipe: String,
    peer: Arc<KernelPeerAdmission>,
    handle: Arc<BackupControlHandle>,
    token: CancellationToken,
) -> Result<(), TaskFailure> {
    let limits = TransportLimits::default();
    loop {
        let mut server =
            NamedPipeServer::create(&pipe, &peer.expectation).map_err(|error| {
                TaskFailure::Failed(format!("watchdog signals bind refused: {error}"))
            })?;
        // Cancellation closes the real handle here: the accept wait is dropped
        // together with the server, so a stopped listener leaves no live pipe.
        let authenticated = tokio::select! {
            () = token.cancelled() => return Ok(()),
            accepted = tokio::time::timeout(
                limits.operation_timeout,
                server.wait_for_authenticated_client(limits.operation_timeout, &peer.expectation),
            ) => accepted,
        };
        match authenticated {
            Err(_) => continue,
            Ok(Err(error)) => {
                observe_fenced_peer("peer failed OS authentication; no frame was read", &error.to_string());
                continue;
            }
            Ok(Ok(())) => {}
        }
        if !peer.admits(server.peer_identity()) {
            observe_fenced_peer(
                "authenticated client is not this installation's approved Kernel image",
                "approved_image_mismatch",
            );
            continue;
        }
        tracing::info!(
            event = "watchdog.signals_peer_admitted",
            observation = "admitted",
            "watchdog signals peer authenticated against the approved Kernel image and file identity"
        );
        serve_one_connection(&mut server, &handle, limits).await;
    }
}

/// Records one bounded, secret-free fenced-peer observation.
///
/// Detail is truncated and never carries peer material: it names the refusal class,
/// not the presented bytes.
fn observe_fenced_peer(reason: &'static str, detail: &str) {
    tracing::warn!(
        event = "watchdog.signals_peer_fenced",
        observation = "fenced",
        reason,
        detail = detail.chars().take(256).collect::<String>().as_str(),
        "watchdog signals peer refused before any frame was read"
    );
}

/// Serves exactly one authenticated request/response exchange.
///
/// The connection id is taken from the RECEIVED frame and echoed on the answer, so
/// a response can never be delivered against a different connection identity than
/// the request arrived on.
async fn serve_one_connection(
    server: &mut NamedPipeServer,
    handle: &BackupControlHandle,
    limits: TransportLimits,
) {
    let frame = match tokio::time::timeout(limits.operation_timeout, server.receive_frame(limits))
        .await
    {
        Err(_) | Ok(Err(_)) => return,
        Ok(Ok(frame)) => frame,
    };
    let connection_id = frame.connection_id.clone();
    let request = match decode_signals_request(&frame) {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!(
                event = "watchdog.signals_request_refused",
                observation = "refused",
                detail = bounded_detail(&error.to_string()).as_str(),
                "watchdog signals request refused before any owner effect"
            );
            return;
        }
    };
    let Some(outcome) = dispatch(handle, request) else {
        return;
    };
    let response = match encode_signals_response(&connection_id, &outcome) {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(
                event = "watchdog.signals_response_refused",
                observation = "refused",
                detail = bounded_detail(&error.to_string()).as_str(),
                "watchdog signals owner result could not be encoded on this connection"
            );
            return;
        }
    };
    let delivered =
        tokio::time::timeout(limits.operation_timeout, server.send_frame(&response, limits))
            .await;
    match delivered {
        Ok(Ok(DeliveryOutcome::Delivered)) => {}
        Ok(Ok(DeliveryOutcome::UnknownOutcome)) => tracing::warn!(
            event = "watchdog.signals_response_unknown",
            observation = "unknown",
            reason = DELIVERY_IS_NOT_COMMIT,
            "watchdog signals response outcome is unknown; the owner result stays the owner's and is reconciled by operation identity"
        ),
        Ok(Err(error)) => tracing::warn!(
            event = "watchdog.signals_response_fenced",
            observation = "fenced",
            detail = bounded_detail(&error.to_string()).as_str(),
            "watchdog signals response could not be delivered on this authenticated connection"
        ),
        Err(_) => tracing::warn!(
            event = "watchdog.signals_response_unknown",
            observation = "unknown",
            reason = DELIVERY_IS_NOT_COMMIT,
            "watchdog signals response timed out; the owner result stays the owner's and is reconciled by operation identity"
        ),
    }
}

/// Admits one destination installation from its presented claims.
///
/// This is the ONLY path from a presented destination to an
/// [`AdmittedIsolatedDestination`]: the existing admission owner reads the
/// destination's own registry, selects its approved generation, verifies its
/// service approvals and artifact digests, and retains its roots. A claim that does
/// not match that registry never becomes an admitted destination.
///
/// # Errors
///
/// Returns [`SpoolError`] with the owner's own typed reason when the claim does not
/// describe an installer-approved isolated installation.
fn prepare_isolated_destination(
    claim: &SignalsDestinationClaim,
) -> Result<AdmittedIsolatedDestination, SpoolError> {
    let bootstrap = claim
        .bootstrap
        .bind()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    admit_isolated_destination(claim.registry_path.clone(), &bootstrap)
}

/// One decoded canonical request on this endpoint's closed ingress surface.
enum SignalsRequest {
    /// Bounded page read of an owner snapshot.
    SnapshotPage(BackupSnapshotPageRead),
    /// Archive verification; registered so it can be refused explicitly.
    ArchiveVerification(BackupArchiveVerification),
    /// Restore status; registered so it can be refused explicitly.
    RestoreStatus(BackupRestoreStatus),
    /// Bounded restore reconciliation toward an admitted isolated destination.
    RestoreReconcile(SignalsRestoreReconcile),
}

/// Decodes one canonical `#954` request from the framed IPC payload.
///
/// The discriminator is the canonical `wire_id` the request types already carry
/// and already validate for themselves, so this module mirrors no method name and
/// invents no method vocabulary. A payload that is not a JSON object, that names
/// no registered wire identity, or whose body does not deserialize into its own
/// canonical type is refused here, before the owner handle is touched.
///
/// # Errors
///
/// Returns [`WatchdogSignalsError::Transport`] for any frame this owner cannot
/// decode into one of its own registered canonical requests.
fn decode_signals_request(
    frame: &eliot_protocol::Frame,
) -> Result<SignalsRequest, WatchdogSignalsError> {
    frame.validate().map_err(map_protocol_error)?;
    if frame.kind != eliot_protocol::FrameKind::Control
        || frame.message_type != eliot_protocol::MessageType::Start
        || frame.request_id.is_some()
        || frame.request_identity.is_some()
    {
        return Err(TransportError::SessionFenced.into());
    }
    let eliot_protocol::ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(TransportError::SessionFenced.into());
    };
    let object = payload
        .as_object()
        .ok_or(TransportError::SessionFenced)?;
    // A reconcile request carries the owner-side inputs its canonical type does
    // not, so it arrives inside an envelope; every other registered method is the
    // bare canonical object.
    if let Some(nested) = object.get("request") {
        let reconcile: SignalsRestoreReconcile = decode_json(nested)?;
        if reconcile.request.wire_id != BACKUP_RESTORE_RECONCILE_WIRE_ID {
            return Err(TransportError::SessionFenced.into());
        }
        return Ok(SignalsRequest::RestoreReconcile(reconcile));
    }
    let wire_id = object
        .get("wire_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    match wire_id {
        BACKUP_SNAPSHOT_PAGE_READ_WIRE_ID => {
            Ok(SignalsRequest::SnapshotPage(decode_json(payload)?))
        }
        BACKUP_ARCHIVE_VERIFICATION_WIRE_ID => {
            Ok(SignalsRequest::ArchiveVerification(decode_json(payload)?))
        }
        BACKUP_RESTORE_STATUS_WIRE_ID => Ok(SignalsRequest::RestoreStatus(decode_json(payload)?)),
        _ => Err(TransportError::SessionFenced.into()),
    }
}

/// Deserializes one canonical typed request from its own payload.
///
/// # Errors
///
/// Returns [`WatchdogSignalsError::Transport`] when the payload is not exactly the
/// canonical type, including an unknown or a missing field.
fn decode_json<T: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
) -> Result<T, WatchdogSignalsError> {
    serde_json::from_value(value.clone()).map_err(|_| TransportError::SessionFenced.into())
}

/// Admits and runs exactly one typed request through the started handle.
///
/// The request never reaches an owner unless the handle admits it: the `#954`
/// contract validates the request through its own canonical validator, and the
/// handle compares its session identity, generation fence, source installation,
/// destination binding, and attesting role against this composition's own retained
/// admission and the owner's role matrix.
///
/// Returns `None` when nothing reached an owner, so there is no owner result to
/// publish: an admission refusal is not an owner result. The one refusal that IS an
/// owner statement — a registered method this owner holds no method for — is
/// published as [`WatchdogSignalsOutcome::RecognizedWithoutOwnerMethod`], taken from
/// the owner's own registered/executable tables rather than from a second list here.
fn dispatch(handle: &BackupControlHandle, request: SignalsRequest) -> Option<WatchdogSignalsOutcome> {
    match request {
        SignalsRequest::SnapshotPage(read) => {
            dispatch_admitted(handle, WatchdogBackupRequest::SnapshotPageRead(&read))
        }
        SignalsRequest::ArchiveVerification(verification) => {
            dispatch_admitted(handle, WatchdogBackupRequest::ArchiveVerification(&verification))
        }
        SignalsRequest::RestoreStatus(status) => {
            dispatch_admitted(handle, WatchdogBackupRequest::RestoreStatus(&status))
        }
        SignalsRequest::RestoreReconcile(reconcile) => {
            let destination = match prepare_isolated_destination(&reconcile.destination) {
                Ok(destination) => destination,
                Err(error) => {
                    tracing::warn!(
                        event = "watchdog.signals_destination_refused",
                        observation = "refused",
                        detail = bounded_detail(&error.to_string()).as_str(),
                        "watchdog signals destination claim refused by the installation admission owner"
                    );
                    return None;
                }
            };
            let Ok(active) = handle.active_runtime_binding() else {
                tracing::warn!(
                    event = "watchdog.signals_destination_refused",
                    observation = "refused",
                    detail = "this owner retains no ACTIVE installation admission to prove isolation against",
                    "watchdog signals reconcile cannot be proved isolated from any ACTIVE installation"
                );
                return None;
            };
            dispatch_admitted(
                handle,
                WatchdogBackupRequest::RestoreReconcile {
                    request: &reconcile.request,
                    destination: &destination,
                    active,
                    steps: &reconcile.steps,
                },
            )
        }
    }
}

/// Admits and runs one typed request through the started handle.
///
/// The owner operation is read from the request's own typed variant before the
/// handle is touched, so a refusal can be traced by its canonical wire name; the
/// owner operation that actually runs is still selected by the handle's own
/// admission, never by this module.
///
/// A registered-but-unexecutable method is published as the owner's own typed
/// refusal, read from the owner's registered/executable tables through
/// [`BackupControlHandle::is_recognized_without_owner_method`] rather than from a
/// second list here. Every other refusal returns `None`: it took no owner effect
/// and there is therefore no owner result to publish.
fn dispatch_admitted(
    handle: &BackupControlHandle,
    request: WatchdogBackupRequest<'_>,
) -> Option<WatchdogSignalsOutcome> {
    let operation = request.operation();
    let refused_without_owner_method = |error: &BackupControlError| {
        if handle.is_recognized_without_owner_method(operation) {
            Some(WatchdogSignalsOutcome::RecognizedWithoutOwnerMethod {
                operation: operation.wire_id(),
                reason: RECOGNIZED_WITHOUT_OWNER_METHOD,
            })
        } else {
            tracing::warn!(
                event = "watchdog.signals_refused",
                observation = "refused",
                operation = operation.wire_id(),
                detail = bounded_detail(&error.to_string()).as_str(),
                "watchdog signals request refused before any owner effect"
            );
            None
        }
    };
    let admitted = match handle.admit(request) {
        Ok(admitted) => admitted,
        Err(error) => return refused_without_owner_method(&error),
    };
    match handle.execute(&admitted) {
        Ok(outcome) => Some(project_outcome(outcome)),
        Err(error) => refused_without_owner_method(&error),
    }
}

/// Projects one admitted request's owner result onto the wire.
///
/// Every owner result reaches the wire unchanged: the capture contour keeps the
/// owner's fence identity and the owner's page, the reconcile contour keeps the
/// owner's disposition. Nothing is recomputed, defaulted, or upgraded here.
fn project_outcome(outcome: WatchdogBackupChannelOutcome) -> WatchdogSignalsOutcome {
    match outcome {
        WatchdogBackupChannelOutcome::Capture { fence, page } => {
            WatchdogSignalsOutcome::SnapshotPage {
                fence: SignalsFenceIdentity {
                    schema_version: fence.schema_version,
                    content_digest: fence.content_digest.clone(),
                    high_water: fence.high_water,
                    high_water_digest: fence.high_water_digest.clone(),
                    first_sequence: fence.header_first_sequence(),
                    next_sequence: fence.header_next_sequence(),
                    retained_members: fence.denominator().retained_members,
                    total_bytes: fence.total_bytes(),
                    captured_at_ms: fence.captured_at_ms,
                    source_installation: fence.source_installation.clone(),
                    watchdog_generation: fence.watchdog_generation,
                    requester_principal: fence.requester_principal.clone(),
                    snapshot_operation_id: fence.snapshot_operation_id.clone(),
                },
                page: *page,
            }
        }
        WatchdogBackupChannelOutcome::Restore(disposition) => {
            WatchdogSignalsOutcome::Restore { disposition }
        }
    }
}

/// Builds the response frame for one owner result.
///
/// # Errors
///
/// Returns [`WatchdogSignalsError::Transport`] when the owner's own result cannot
/// be encoded on this connection identity.
fn encode_signals_response(
    connection_id: &str,
    outcome: &WatchdogSignalsOutcome,
) -> Result<eliot_protocol::Frame, WatchdogSignalsError> {
    let frame = eliot_protocol::Frame {
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        encoding_profile: eliot_protocol::EncodingProfile::JsonV1,
        connection_id: connection_id.to_owned(),
        request_id: None,
        kind: eliot_protocol::FrameKind::Control,
        message_type: eliot_protocol::MessageType::Ready,
        request_identity: None,
        payload: eliot_protocol::ProtocolPayload::Json(
            serde_json::to_value(outcome).map_err(|_| TransportError::SessionFenced)?,
        ),
        trace_context: std::collections::BTreeMap::new(),
    };
    frame.validate().map_err(map_protocol_error)?;
    Ok(frame)
}

/// Maps the protocol owner's own typed frame rejection onto the transport refusal.
///
/// The protocol owner stays the only place a frame is judged; this only records a
/// bounded, secret-free trace of its own rejection and returns the transport's
/// single fail-closed frame refusal.
fn map_protocol_error(error: eliot_protocol::ProtocolError) -> TransportError {
    tracing::debug!(
        event = "watchdog.signals_frame_fenced",
        observation = "fenced",
        detail = bounded_detail(&error.to_string()).as_str(),
        "watchdog signals frame refused by the protocol contract"
    );
    TransportError::SessionFenced
}

/// Bounds one diagnostic detail so no pipe byte, credential, or database material
/// can reach a log field.
fn bounded_detail(value: &str) -> String {
    value.chars().take(256).collect()
}
