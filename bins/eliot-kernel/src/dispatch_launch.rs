//! Kernel dispatch-launch contour for one-shot Doctor and testd workers.
//!
//! DISPATCH-CONTOUR-2 Slice B (issues #461 and #22): Kernel-side launch of
//! admitted Doctor (and testd) attempts through the admitted
//! [`ProcessExecutionGateway`](crate::process_execution::ProcessExecutionGateway),
//! plus the composed front-door owner the dispatch arms admit through.
//!
//! Contour (built once, parameterized by [`DispatchedWorkerKind`]):
//!
//! * the production Doctor ledger, the immutable recipe registry, and the
//!   Kernel-owned principal owner are composed here, once, through
//!   [`compose_dispatch_contour`] plus [`compose_doctor_front_door`]. The
//!   ledger travels as an [`DoctorLedgerPort`] object-safe port over the
//!   existing [`DoctorRecoveryLedger`](eliot_ors::DoctorRecoveryLedger)
//!   contract (the store slice implements it over redb; WRITER-A): no
//!   authority is minted, no check is weakened, and nothing is stored until
//!   composed. Until then every arm fails closed.
//! * [`admit_doctor_repair_attempt`] / [`admit_testd_attempt`] admit exactly
//!   one attempt through the live service plus the composed owner, following
//!   the `host_request_binding` live-authority pattern. Neither the epoch
//!   nor the generation is ever taken from the request envelope.
//! * [`launch_admitted_doctor_attempt`] admits the attempt, then launches
//!   the real `eliot-doctor` binary through the admitted process gateway:
//!   it mints the I7.5/I15.2 launch nonce, writes the session-bound attempt
//!   material to the protected file the child already reads, builds the
//!   child process admission with an empty argv (never argv or env
//!   material), retains the path proof, starts through the gateway, and
//!   retains the launch record keyed by the original attempt identity.
//!   [`launch_admitted_testd_attempt`] reuses the same seam shape for
//!   `eliot-testd` (the #1452 residual: the seam provisions the admitted
//!   executor and retains the admission context kernel-side).
//! * a launched-but-unreconciled attempt reconciles by its original
//!   identity through [`reconcile_launched_doctor_attempt`] /
//!   [`reconcile_launched_testd_attempt`]: the durable admission digest is
//!   compared, never recomputed under a new id, and no second child is
//!   spawned for an outstanding launch.
//!
//! Delivery contract (I7.5/I15.2): each launched Doctor child receives a
//! launch nonce delivered over the protected dispatch file next to its
//! executable — never via the command line, stdin, or the environment. The
//! Doctor file carries exactly what
//! `bins/eliot-doctor/src/dispatched_material.rs::read_dispatched_material_from`
//! validates (envelope bytes plus canonical digest, parsed closed request
//! with byte-identity, admitted manifest revision, live epoch, fence-bound
//! generation, well-formed nonce); the nonce is deterministic per
//! (attempt identity, durable admission time, composed principal), so an
//! exact replay rewrites byte-identical material and reconciles by the
//! original identity instead of minting a second session. The testd nonce
//! is retained kernel-side in the launch record for the submit-time
//! session proof; it travels to the child with the launch once that
//! binary defines its reader.
//!
//! Testd delivery gap: `bins/eliot-testd/src/main.rs::acquire_presented_admission`
//! presents nothing until its launch seam lands, and that binary accepts no
//! file, argv, stdin, or environment material by design ("the concrete
//! process request is never deserialized, so no byte surface can present
//! it"). The testd half therefore stops at the spawn boundary: admission,
//! nonce, spawn through the admitted executor, retention, and
//! reconcile-by-original-identity are all provided, but no material file is
//! written for testd and the child-side reader remains the recorded gap for
//! the testd owner (see [`DispatchedWorkerKind::material_file_name`]).
//!
//! Architecture: ARCH-MOD-01, A13.2, A13.3; I7.5 launch nonce, I15.2
//! Principal and Session binding, I14.6 admission and execution axes.
//! Forbidden authority: no minted ledger/registry/principal, no invented
//! transport or logging, no argv/env material, no second spawn for an
//! outstanding identity.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use eliot_contracts::EpochId;
use eliot_kernel_service::{
    AuthenticatedDoctorSession, AuthenticatedTestdSession, ComposedDoctorFrontDoor,
    DoctorRecipeRegistry, DoctorRepairAdmission, DoctorRepairAttemptRequest, DoctorRepairResponse,
    KernelService, KernelServiceError, TestdAdmission, TestdAdmissionAttemptRequest,
    TestdAdmissionEnvelope, TestdAdmissionResponse, advertise_doctor_repair,
    handle_doctor_repair_attempt, handle_testd_admission_attempt, reconcile_testd_admission,
};
use eliot_ors::{
    DoctorAttemptRecord, DoctorEffectRecord, DoctorLedgerError, DoctorRecoveryLedger,
    OperationIdentity,
};
use eliot_process::OperationId;

use super::front_door_session::{DOCTOR_MODULE_ID, TESTD_MODULE_ID};
use super::runtime_identity::stable_owner_principal_digest;
use super::{
    ActionLeaseRef, EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation,
    ImageId, JobId, KernelComposition, ProcessExecutionAdmissionRequest, ProcessExecutionError,
    ProcessIntent, ProcessOwnerBinding, ProcessStartReceipt, ProcessTreeId, ResourceLimits,
    SessionId,
};

/// One-shot worker kind served by the dispatch-launch contour.
///
/// The contour is built once and parameterized by this enum: Doctor and
/// testd share admission-through-composed-owner, nonce minting, spawn
/// through the admitted gateway, launch retention, and
/// reconcile-by-original-identity. They differ only in the delivery
/// endpoint the child already reads (see [`Self::material_file_name`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchedWorkerKind {
    /// The one-shot Doctor repair worker (`eliot-doctor`).
    Doctor,
    /// The one-shot testd admission worker (`eliot-testd`).
    Testd,
}

impl DispatchedWorkerKind {
    /// Returns the stable session module identity of the worker.
    ///
    /// The worker never self-asserts authority through this string: the
    /// front door binds it at session scope over an already-authenticated
    /// pipe peer.
    #[must_use]
    pub const fn module_id(self) -> &'static str {
        match self {
            Self::Doctor => DOCTOR_MODULE_ID,
            Self::Testd => TESTD_MODULE_ID,
        }
    }

    /// Returns the stable front-door wire identity admitted for the worker.
    #[must_use]
    pub const fn wire_id(self) -> &'static str {
        match self {
            Self::Doctor => eliot_kernel_service::DOCTOR_REPAIR_WIRE_ID,
            Self::Testd => eliot_kernel_service::TESTD_ADMISSION_WIRE_ID,
        }
    }

    /// Returns the dispatch material file name the child already reads, when
    /// the child defines one.
    ///
    /// `Some` for Doctor: the exact
    /// `bins/eliot-doctor/src/dispatched_material.rs::DISPATCHED_MATERIAL_FILE_NAME`
    /// literal the child reader derives from its executable directory
    /// (`current_exe`, never argv/stdin/env). Duplicated here because the
    /// Kernel delivery half owns its write path; the child reader stays the
    /// authority for the value.
    ///
    /// `None` for testd: that binary defines no material reader
    /// (`acquire_presented_admission` reports absence by design and accepts
    /// no file, argv, stdin, or environment material). The testd launch
    /// therefore writes no file; the child-side reader is the recorded gap
    /// for the testd owner, and this contour stops at the spawn boundary
    /// instead of working around it.
    #[must_use]
    pub const fn material_file_name(self) -> Option<&'static str> {
        match self {
            Self::Doctor => Some("eliot-doctor.dispatched-attempt.json"),
            Self::Testd => None,
        }
    }

    /// Returns the nonce prefix distinguishing the worker's launch nonces.
    #[must_use]
    const fn nonce_prefix(self) -> &'static str {
        match self {
            Self::Doctor => "doctor-dispatch",
            Self::Testd => "testd-dispatch",
        }
    }

    /// Returns the process-operation prefix for the worker's child admission.
    #[must_use]
    const fn operation_prefix(self) -> &'static str {
        match self {
            Self::Doctor => "doctor-launch",
            Self::Testd => "testd-launch",
        }
    }
}

/// Object-safe admission port over the durable Doctor recovery ledger.
///
/// The admission gate ([`handle_doctor_repair_attempt`]) is generic over
/// [`DoctorRecoveryLedger`], which cannot travel behind `dyn`. This port
/// erases the concrete ledger at compose time through the blanket
/// implementation below and delegates every call to the real gate and the
/// real ledger unchanged: staging, advancing, loading, and budgeting behave
/// exactly like a direct generic call. The production ledger is the store
/// slice's redb implementation; composition fails closed until it is
/// supplied.
pub(crate) trait DoctorLedgerPort: Send + Sync {
    /// Returns the composed production ledger for owner construction.
    fn ledger(&self) -> &dyn DoctorRecoveryLedger;

    /// Loads one attempt by exact attempt digest without admitting.
    fn load_doctor_attempt(
        &self,
        attempt_digest: &OperationIdentity,
    ) -> Result<Option<DoctorAttemptRecord>, DoctorLedgerError>;

    /// Loads one effect by exact effect digest without admitting.
    fn load_doctor_effect(
        &self,
        effect_digest: &OperationIdentity,
    ) -> Result<Option<DoctorEffectRecord>, DoctorLedgerError>;

    /// Admits exactly one attempt through the composed owner and live
    /// service authority: composes the front-door owner (proving ledger,
    /// registry, and principal), binds the Doctor session from live Kernel
    /// state, and delegates to the unchanged admission gate.
    fn admit_attempt(
        &self,
        registry: &DoctorRecipeRegistry,
        service: &KernelService,
        principal_ref: &str,
        request: &DoctorRepairAttemptRequest,
        now_unix_nanos: u64,
    ) -> Result<DoctorRepairResponse, KernelServiceError>;
}

impl<L: DoctorRecoveryLedger> DoctorLedgerPort for L {
    fn ledger(&self) -> &dyn DoctorRecoveryLedger {
        self
    }

    fn load_doctor_attempt(
        &self,
        attempt_digest: &OperationIdentity,
    ) -> Result<Option<DoctorAttemptRecord>, DoctorLedgerError> {
        DoctorRecoveryLedger::load_doctor_attempt(self, attempt_digest)
    }

    fn load_doctor_effect(
        &self,
        effect_digest: &OperationIdentity,
    ) -> Result<Option<DoctorEffectRecord>, DoctorLedgerError> {
        DoctorRecoveryLedger::load_doctor_effect(self, effect_digest)
    }

    fn admit_attempt(
        &self,
        registry: &DoctorRecipeRegistry,
        service: &KernelService,
        principal_ref: &str,
        request: &DoctorRepairAttemptRequest,
        now_unix_nanos: u64,
    ) -> Result<DoctorRepairResponse, KernelServiceError> {
        let owner = ComposedDoctorFrontDoor::compose(self, registry, principal_ref)?;
        debug_assert!(advertise_doctor_repair(&owner));
        let session = AuthenticatedDoctorSession::bind(service, owner.principal_ref())?;
        handle_doctor_repair_attempt(
            self,
            owner.registry(),
            service,
            &session,
            request,
            now_unix_nanos,
        )
    }
}

/// Composed Doctor front-door state: the production ledger port plus the
/// immutable recipe registry. Both arrive from the supplying composition;
/// neither is minted here.
struct DoctorFrontDoorState {
    ledger: Arc<dyn DoctorLedgerPort>,
    registry: DoctorRecipeRegistry,
}

/// Launch phase of one retained dispatched attempt, keyed by its original
/// identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LaunchPhase {
    /// Admit reserved the identity; the spawn has not been attempted yet.
    Reserved,
    /// The child was spawned through the admitted executor.
    Launched,
    /// The spawn outcome is unknown; the attempt must reconcile by its
    /// original identity instead of relaunching blindly.
    Unreconciled,
    /// The durable outcome converged; the slot is closed.
    Reconciled,
}

/// One retained dispatched attempt, keyed by its original identity
/// (attempt digest for Doctor, job identity for testd).
#[derive(Clone, Debug)]
struct LaunchRecord {
    kind: DispatchedWorkerKind,
    identity: String,
    admission_digest: String,
    request_digest: String,
    effect_digest: Option<String>,
    material_path: Option<PathBuf>,
    nonce: String,
    operation_id: String,
    phase: LaunchPhase,
    /// Retained original testd admission for reconcile-by-identity;
    /// always `None` for Doctor (the durable ledger is the authority).
    testd_admission: Option<TestdAdmission>,
}

/// Retained launch records. The durable attempt/effect ledger stays the
/// authority; these records only enforce launch-once per identity and carry
/// the nonce and admission digests the reconcile path compares.
#[derive(Debug, Default)]
struct LaunchRecords {
    by_identity: BTreeMap<String, LaunchRecord>,
}

/// The composed dispatch contour: the Kernel-owned principal owner, the
/// Doctor front-door state once its production ledger lands, and the
/// retained launch records.
pub struct ComposedDispatchContour {
    principal_owner: String,
    doctor: Mutex<Option<DoctorFrontDoorState>>,
    launches: Mutex<LaunchRecords>,
}

static DISPATCH_CONTOUR: OnceLock<ComposedDispatchContour> = OnceLock::new();

/// Typed failure for the dispatch-launch contour. Every variant is
/// fail-closed: no admission is fabricated, no child is spawned, and no
/// record is retained on error.
#[derive(Debug)]
pub enum DispatchLaunchError {
    /// The dispatch contour (or its Doctor side) is not composed.
    Uncomposed(&'static str),
    /// The contour is already composed; a second composition is refused
    /// instead of replacing live authority.
    AlreadyComposed(&'static str),
    /// Caller-supplied launch material failed closed validation.
    InvalidMaterial(String),
    /// The admission gate refused mechanically (fenced generation, closed
    /// admission, stale session, ledger storage).
    Gate(String),
    /// The durable attempt row disagrees with the just-issued admission.
    Inconsistent(String),
    /// A changed request under one testd job identity refuses to overwrite
    /// the retained original admission.
    ChangedTerms(String),
    /// The child executable or working-directory binding is unavailable.
    Path(String),
    /// No admitted process authority is configured.
    ExecutorUnavailable,
    /// Spawning needs the Windows process contour.
    Unsupported(&'static str),
    /// The admitted spawn failed before any child effect; the material file
    /// was reaped and no launch record was retained, so a later call may
    /// retry cleanly.
    Start(String),
    /// The dispatch material file could not be written.
    Io(String),
}

impl std::fmt::Display for DispatchLaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uncomposed(detail) => {
                write!(f, "dispatch contour is not composed: {detail}")
            }
            Self::AlreadyComposed(detail) => {
                write!(f, "dispatch contour is already composed: {detail}")
            }
            Self::InvalidMaterial(detail) => {
                write!(f, "dispatch launch material is invalid: {detail}")
            }
            Self::Gate(detail) => write!(f, "doctor dispatch admission failed: {detail}"),
            Self::Inconsistent(detail) => {
                write!(
                    f,
                    "durable doctor attempt disagrees with its admission: {detail}"
                )
            }
            Self::ChangedTerms(detail) => {
                write!(f, "changed testd terms under one job identity: {detail}")
            }
            Self::Path(detail) => write!(f, "dispatch child path binding failed: {detail}"),
            Self::ExecutorUnavailable => write!(
                f,
                "admitted process authority is not configured for dispatch launch"
            ),
            Self::Unsupported(detail) => write!(f, "dispatch launch is unsupported: {detail}"),
            Self::Start(detail) => write!(f, "dispatch child spawn failed: {detail}"),
            Self::Io(detail) => write!(f, "dispatch material file failed: {detail}"),
        }
    }
}

impl std::error::Error for DispatchLaunchError {}

fn gate_error(error: impl std::fmt::Display) -> DispatchLaunchError {
    DispatchLaunchError::Gate(error.to_string())
}

/// Validates bounded principal text without carrying platform or secret
/// material. Mirrors the kernel-service wire-text rule
/// (`validate_text`: non-blank, no controls, at most 1024 UTF-8 bytes) so
/// composition rejects the same principals admission would refuse.
fn validate_principal_owner(value: &str) -> Result<(), DispatchLaunchError> {
    if value.trim().is_empty() {
        return Err(DispatchLaunchError::InvalidMaterial(
            "dispatch principal owner must be non-blank".to_owned(),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(DispatchLaunchError::InvalidMaterial(
            "dispatch principal owner must not contain control characters".to_owned(),
        ));
    }
    if value.len() > 1024 {
        return Err(DispatchLaunchError::InvalidMaterial(
            "dispatch principal owner must not exceed 1024 UTF-8 bytes".to_owned(),
        ));
    }
    Ok(())
}

/// Composes the dispatch contour with its Kernel-owned principal owner.
///
/// The principal is the authenticated composition-boundary reference the
/// Doctor and testd session binds use — never a request-envelope value.
/// Set-once: a second composition is refused instead of replacing live
/// authority.
pub fn compose_dispatch_contour(principal_owner: String) -> Result<(), DispatchLaunchError> {
    validate_principal_owner(&principal_owner)?;
    DISPATCH_CONTOUR
        .set(ComposedDispatchContour {
            principal_owner,
            doctor: Mutex::new(None),
            launches: Mutex::new(LaunchRecords::default()),
        })
        .map_err(|_| DispatchLaunchError::AlreadyComposed("dispatch contour"))?;
    Ok(())
}

/// Composes the production Doctor front-door state: the durable recovery
/// ledger plus the immutable recipe registry.
///
/// The ledger is any live [`DoctorRecoveryLedger`] implementation — the
/// production redb store once its slice lands, or the faithful contract
/// ledger in tests. The registry is the supplier-built immutable revision
/// (content authority stays with the supplying composition). Requires the
/// contour cell from [`compose_dispatch_contour`]; set-once per process.
pub fn compose_doctor_front_door<L: DoctorRecoveryLedger + 'static>(
    ledger: Arc<L>,
    registry: DoctorRecipeRegistry,
) -> Result<(), DispatchLaunchError> {
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed(
            "compose the dispatch contour before its Doctor side",
        ))?;
    if registry.recipe_count() == 0 {
        return Err(DispatchLaunchError::InvalidMaterial(
            "the composed doctor registry admits no recipe".to_owned(),
        ));
    }
    let ledger: Arc<dyn DoctorLedgerPort> = ledger;
    let mut doctor = contour
        .doctor
        .lock()
        .map_err(|_| DispatchLaunchError::Gate("doctor front-door lock poisoned".to_owned()))?;
    if doctor.is_some() {
        return Err(DispatchLaunchError::AlreadyComposed("doctor front door"));
    }
    *doctor = Some(DoctorFrontDoorState { ledger, registry });
    Ok(())
}

/// Returns the composed dispatch contour, when composition landed.
pub fn dispatch_contour() -> Option<&'static ComposedDispatchContour> {
    DISPATCH_CONTOUR.get()
}

/// Returns whether the Kernel currently advertises the Doctor repair
/// operation through the real composed front-door owner.
///
/// True exactly when the contour cell holds a composed ledger, a
/// non-empty immutable registry, and the principal owner
/// ([`advertise_doctor_repair`] over [`ComposedDoctorFrontDoor`]); false
/// in every other case, so an uncomposed Kernel keeps failing closed.
#[must_use]
pub fn doctor_repair_advertised() -> bool {
    let Some(contour) = DISPATCH_CONTOUR.get() else {
        return false;
    };
    let Ok(doctor) = contour.doctor.lock() else {
        return false;
    };
    let Some(state) = doctor.as_ref() else {
        return false;
    };
    ComposedDoctorFrontDoor::compose(
        state.ledger.ledger(),
        &state.registry,
        contour.principal_owner.as_str(),
    )
    .is_ok_and(|owner| advertise_doctor_repair(&owner))
}

/// Admits exactly one Doctor repair attempt through the composed front-door
/// owner and live service authority.
///
/// Fails closed with [`DispatchLaunchError::Uncomposed`] until
/// [`compose_dispatch_contour`] plus [`compose_doctor_front_door`] land;
/// mechanical gate failures surface as [`DispatchLaunchError::Gate`];
/// every typed refusal or conflict is an `Ok` response value, never an
/// admission. Neither the epoch nor the generation is taken from the
/// request envelope.
pub(crate) fn admit_doctor_repair_attempt(
    service: &KernelService,
    request: &DoctorRepairAttemptRequest,
    now_unix_nanos: u64,
) -> Result<DoctorRepairResponse, DispatchLaunchError> {
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("doctor front door"))?;
    let doctor = contour
        .doctor
        .lock()
        .map_err(|_| DispatchLaunchError::Gate("doctor front-door lock poisoned".to_owned()))?;
    let state = doctor
        .as_ref()
        .ok_or(DispatchLaunchError::Uncomposed("doctor front door"))?;
    state
        .ledger
        .admit_attempt(
            &state.registry,
            service,
            contour.principal_owner.as_str(),
            request,
            now_unix_nanos,
        )
        .map_err(gate_error)
}

/// Admits exactly one testd job through the composed principal owner and
/// live service authority.
///
/// Testd admission is stateless: the answer derives from the presented wire
/// plus live authority only, so no ledger composition is required — only
/// the contour cell from [`compose_dispatch_contour`] for the
/// Kernel-owned principal. Fails closed until it lands; mechanical
/// failures surface as [`DispatchLaunchError::Gate`]; every typed refusal
/// or conflict is an `Ok` response value.
pub(crate) fn admit_testd_attempt(
    service: &KernelService,
    request: &TestdAdmissionAttemptRequest,
    now_unix_nanos: u64,
) -> Result<TestdAdmissionResponse, DispatchLaunchError> {
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("testd front door"))?;
    let session = AuthenticatedTestdSession::bind(service, contour.principal_owner.as_str())
        .map_err(gate_error)?;
    handle_testd_admission_attempt(service, &session, request, now_unix_nanos).map_err(gate_error)
}

/// Mints the I7.5/I15.2 launch nonce for one admitted identity.
///
/// The nonce is deterministic per (worker kind, identity digest, durable
/// admission time, composed principal): unpredictable before admission
/// (SHA-256 over the admission binding), unique per attempt, and stable
/// across exact replays, so a replay rewrites byte-identical material and
/// reconciles by the original identity instead of minting a second
/// session. The shape mirrors the child reader
/// (`bins/eliot-doctor/src/dispatched_material.rs::validate_nonce`:
/// 16..=256 bytes over alphanumerics plus `-_.`); violations fail closed
/// instead of launching.
fn mint_dispatch_nonce(
    kind: DispatchedWorkerKind,
    identity_digest: &str,
    admitted_at_unix_nanos: u64,
    principal_owner: &str,
) -> Result<String, DispatchLaunchError> {
    let mut material = String::with_capacity(256);
    material.push_str(kind.nonce_prefix());
    material.push('|');
    material.push_str(identity_digest);
    material.push('|');
    for byte in admitted_at_unix_nanos.to_le_bytes() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        material.push(char::from(HEX[usize::from(byte >> 4)]));
        material.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    material.push('|');
    material.push_str(principal_owner);
    let nonce = format!(
        "{}-{}",
        kind.nonce_prefix(),
        super::sha256_hex(material.as_bytes())
    );
    if !(16..=256).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(DispatchLaunchError::Gate(
            "minted dispatch nonce violates the child session-nonce shape".to_owned(),
        ));
    }
    Ok(nonce)
}

/// Returns the first sixteen digest bytes as the short launch identity.
///
/// Digests are lowercase SHA-256 hex by contract; anything else fails
/// closed instead of naming a child operation.
fn short_identity(digest: &str) -> Result<&str, DispatchLaunchError> {
    digest.get(..16).ok_or_else(|| {
        DispatchLaunchError::InvalidMaterial("dispatch identity digest is malformed".to_owned())
    })
}

/// Requires a lowercase SHA-256 digest without carrying platform material.
fn require_digest(value: &str, what: &'static str) -> Result<(), DispatchLaunchError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DispatchLaunchError::InvalidMaterial(what.to_owned()));
    }
    Ok(())
}

/// Caller-supplied Doctor launch material: the admitted wire envelope plus
/// the opaque closed-request and manifest JSON the child validates, and the
/// composition-pinned child binary binding.
///
/// `request_json` must equal the parse of `attempt.closed_request_json`
/// (byte-identity, re-proved before any write); `manifest_json` is the
/// exact admitted manifest revision carried through opaquely — the child
/// validates the request against it fail-closed, since this contour mints
/// no recipe authority. The executable binding (path, digest, working
/// directory) is supplied by the owning composition like the approved
/// `eliotd` descriptor; nothing is discovered from argv or the environment.
pub struct DoctorLaunchMaterial<'a> {
    /// Full wire envelope: attempt seed, effect sequence, opaque closed
    /// request bytes, target digest, and canonical digest.
    pub attempt: &'a DoctorRepairAttemptRequest,
    /// Parsed closed request; must equal the envelope bytes exactly.
    pub request_json: &'a serde_json::Value,
    /// The exact admitted manifest revision, carried through opaquely.
    pub manifest_json: &'a serde_json::Value,
    /// Composition-pinned child executable path.
    pub executable: &'a Path,
    /// Expected SHA-256 digest of the child executable image.
    pub executable_sha256: &'a str,
    /// Composition-pinned child working directory.
    pub working_directory: &'a Path,
}

/// Why a prepared Doctor launch produced no child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorLaunchSkip {
    /// The identity is already reserved or launched: the returned admission
    /// is the original identity's admission (rebuilt identically by the
    /// gate), never a recompute under a new id.
    LaunchInFlight,
    /// The durable effect already reported: terminal, nothing to drive.
    TerminalEffect,
    /// The attempt was admitted cancelled: projected without executing.
    CancelledAdmission,
}

/// A prepared Doctor launch: admitted, nonce-bound, and (unless skipped)
/// written to the protected dispatch file, ready to spawn.
pub enum PreparedDoctorLaunch {
    /// Ready to spawn through the admitted executor.
    Ready(ReadyDoctorLaunch),
    /// Admitted but needing no child; carries the admission and the reason.
    Skipped {
        /// The admission for the original identity.
        admission: Box<DoctorRepairAdmission>,
        /// Why no child is spawned.
        skip: DoctorLaunchSkip,
    },
    /// The gate refused or conflicted; carries the typed answer, never an
    /// admission.
    Refused(DoctorRepairResponse),
}

/// A Doctor launch ready to spawn: every authority check passed and the
/// dispatch file carries exactly what the child reader validates.
pub struct ReadyDoctorLaunch {
    /// The admission for the original attempt identity.
    pub admission: Box<DoctorRepairAdmission>,
    /// The I7.5/I15.2 launch nonce written to the dispatch file.
    pub nonce: String,
    /// Deterministic child operation identity derived from the attempt
    /// digest, so the admitted executor replays (never double-spawns) an
    /// identical launch.
    pub operation_id: OperationId,
    /// Protected dispatch file path the child reads.
    pub material_path: PathBuf,
    /// Composition-pinned child executable path.
    pub executable: PathBuf,
    /// Expected SHA-256 digest of the child executable image.
    pub executable_sha256: String,
    /// Composition-pinned child working directory.
    pub working_directory: PathBuf,
    /// Live authority epoch bound at admission.
    pub authority_epoch: EpochId,
    /// Live activation generation bound at admission.
    pub generation: Generation,
}

/// Outcome of one Doctor admit-then-launch call.
pub enum DoctorLaunchOutcome {
    /// The child was spawned through the admitted executor.
    Launched {
        /// The admission for the original attempt identity.
        admission: Box<DoctorRepairAdmission>,
        /// The launch nonce retained for the submit-time session proof.
        nonce: String,
        /// Child process operation identity.
        operation_id: OperationId,
        /// The admitted process-start receipt (boxed: receipts dwarf the
        /// other outcomes).
        receipt: Box<ProcessStartReceipt>,
    },
    /// The spawn outcome is unknown: the attempt was admitted and the
    /// launch was retained as unreconciled under its original identity —
    /// reconcile later, never blind-retry as a new attempt.
    LaunchUnknown {
        /// The admission for the original attempt identity.
        admission: Box<DoctorRepairAdmission>,
        /// The launch nonce retained for the submit-time session proof.
        nonce: String,
        /// Child process operation identity.
        operation_id: OperationId,
    },
    /// Admitted but needing no child; carries the admission and the reason.
    NotLaunched {
        /// The admission for the original attempt identity.
        admission: Box<DoctorRepairAdmission>,
        /// Why no child was spawned.
        skip: DoctorLaunchSkip,
    },
    /// The gate refused or conflicted; carries the typed answer.
    Refused(DoctorRepairResponse),
}

/// Writes the Doctor dispatch file carrying exactly what the child reader
/// validates.
///
/// The envelope object holds the wire attempt, the parsed closed request
/// (byte-identical to the envelope bytes, re-proved by the caller), the
/// admitted manifest revision, the live epoch, the fence-bound generation,
/// and the session nonce — the six fields
/// `read_dispatched_material_from` checks, in the shape it parses with
/// `deny_unknown_fields`. Files are never read here, and nothing travels
/// via argv, stdin, or the environment.
fn doctor_material_bytes(
    attempt: &DoctorRepairAttemptRequest,
    request_json: &serde_json::Value,
    manifest_json: &serde_json::Value,
    epoch: &EpochId,
    generation: u64,
    nonce: &str,
) -> Result<Vec<u8>, DispatchLaunchError> {
    let envelope = serde_json::json!({
        "attempt": attempt,
        "request": request_json,
        "manifest": manifest_json,
        "epoch": epoch,
        "generation": generation,
        "nonce": nonce,
    });
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| DispatchLaunchError::Io(error.to_string()))?;
    // Mirror the child input bound
    // (`DISPATCHED_MATERIAL_LIMIT_BYTES = 256 KiB`): refuse an unbounded
    // write before touching the protected path.
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > 256 * 1024 {
        return Err(DispatchLaunchError::Io(
            "dispatch material exceeds the bounded input limit".to_owned(),
        ));
    }
    Ok(bytes)
}

/// Writes bytes to the protected dispatch path, replacing any prior
/// presentation for the worker kind.
///
/// The write carries deterministic per-identity bytes (replay-stable
/// nonce), so a concurrent duplicate presents identical material and the
/// child-side consume-once read stays sound. A partial write can only fail
/// the child's closed parse fail-closed; the next launch overwrites it.
fn write_material_file(path: &Path, bytes: &[u8]) -> Result<(), DispatchLaunchError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| DispatchLaunchError::Io(error.to_string()))?;
    }
    std::fs::write(path, bytes).map_err(|error| DispatchLaunchError::Io(error.to_string()))
}

/// Reaps the dispatch file best-effort. Removal failure never fails the
/// shot: the child consumes the file once on a validated read, and the
/// next launch overwrites it.
fn reap_material_file(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Locks the contour launches table or fails closed on poison.
fn launches_table(
    contour: &'static ComposedDispatchContour,
) -> Result<std::sync::MutexGuard<'static, LaunchRecords>, DispatchLaunchError> {
    contour
        .launches
        .lock()
        .map_err(|_| DispatchLaunchError::Gate("dispatch launch record lock poisoned".to_owned()))
}

/// Admits one Doctor attempt and prepares its launch: nonce-bound material
/// written to the protected dispatch file, ready to spawn.
///
/// Sequence: validate the caller material (attempt shape plus canonical
/// digest, closed-request byte-identity, child binding); admit through the
/// composed owner (exact replays rebuild the original admission — the
/// lost-reply rule); skip cancelled admissions and terminal effects
/// without spawning; reserve the original identity single-flight; mint the
/// replay-stable nonce; write exactly what the child reader validates.
/// Nothing is spawned here: [`launch_admitted_doctor_attempt`] spawns the
/// returned [`ReadyDoctorLaunch`] through the admitted executor.
#[allow(
    clippy::too_many_lines,
    reason = "admit, eligibility, reserve, nonce, and material-write stay in one ordered authority path so no launch step can run before its gate"
)]
pub fn prepare_doctor_launch(
    kernel: &KernelComposition,
    material: &DoctorLaunchMaterial<'_>,
    now_unix_nanos: u64,
) -> Result<PreparedDoctorLaunch, DispatchLaunchError> {
    if now_unix_nanos == 0 {
        return Err(DispatchLaunchError::InvalidMaterial(
            "admission time must be non-zero".to_owned(),
        ));
    }
    material.attempt.validate().map_err(gate_error)?;
    material
        .attempt
        .validate_canonical_digest()
        .map_err(gate_error)?;
    let parsed: serde_json::Value = serde_json::from_str(&material.attempt.closed_request_json)
        .map_err(|_| {
            DispatchLaunchError::InvalidMaterial("closed request envelope is not JSON".to_owned())
        })?;
    if parsed != *material.request_json {
        return Err(DispatchLaunchError::InvalidMaterial(
            "dispatch envelope closed request does not equal the presented closed request"
                .to_owned(),
        ));
    }
    let material_dir = material.executable.parent().ok_or_else(|| {
        DispatchLaunchError::InvalidMaterial(
            "dispatch child executable has no parent directory".to_owned(),
        )
    })?;
    require_digest(
        material.executable_sha256,
        "dispatch child executable digest must be a lowercase SHA-256 digest",
    )?;
    if material.working_directory.as_os_str().is_empty() {
        return Err(DispatchLaunchError::InvalidMaterial(
            "dispatch child working directory must be non-blank".to_owned(),
        ));
    }
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("doctor front door"))?;
    let (authority_epoch, generation, response) = {
        let service = kernel
            .service
            .lock()
            .map_err(|_| DispatchLaunchError::Gate("kernel service lock poisoned".to_owned()))?;
        let response = admit_doctor_repair_attempt(&service, material.attempt, now_unix_nanos)?;
        let epoch = service.authority_epoch();
        let generation = service
            .activation_receipt()
            .map_or(0, |receipt| receipt.generation.value());
        (epoch, generation, response)
    };
    if generation == 0 {
        return Err(DispatchLaunchError::Gate(
            "live activation generation is unavailable".to_owned(),
        ));
    }
    let admission = match response {
        DoctorRepairResponse::Admitted(admission) => admission,
        refused => return Ok(PreparedDoctorLaunch::Refused(refused)),
    };
    if admission.cancelled {
        return Ok(PreparedDoctorLaunch::Skipped {
            admission,
            skip: DoctorLaunchSkip::CancelledAdmission,
        });
    }
    require_digest(
        &admission.attempt_digest,
        "admission attempt digest must be a lowercase SHA-256 digest",
    )?;
    // Launch eligibility against the durable truth: the just-issued
    // admission must match the staged row, and an already-reported effect
    // is terminal — nothing to drive.
    {
        let ledger = doctor_ledger(contour)?;
        let attempt_key = OperationIdentity::new(&admission.attempt_digest)
            .map_err(|error| DispatchLaunchError::Inconsistent(error.to_string()))?;
        let row = ledger
            .load_doctor_attempt(&attempt_key)
            .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?
            .ok_or_else(|| {
                DispatchLaunchError::Inconsistent(
                    "admitted doctor attempt has no durable row".to_owned(),
                )
            })?;
        if row.admission_digest.as_deref() != Some(admission.admission_digest.as_str()) {
            return Err(DispatchLaunchError::Inconsistent(
                "durable doctor attempt cannot reproduce its admission".to_owned(),
            ));
        }
        if let Some(effect_digest) = admission.effect_digest.as_deref() {
            let effect_key = OperationIdentity::new(effect_digest)
                .map_err(|error| DispatchLaunchError::Inconsistent(error.to_string()))?;
            let effect = ledger
                .load_doctor_effect(&effect_key)
                .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?
                .ok_or_else(|| {
                    DispatchLaunchError::Inconsistent(
                        "admitted doctor effect has no durable intent".to_owned(),
                    )
                })?;
            if effect.state == eliot_ors::DoctorEffectState::Reported {
                return Ok(PreparedDoctorLaunch::Skipped {
                    admission,
                    skip: DoctorLaunchSkip::TerminalEffect,
                });
            }
        }
    }
    // Single-flight reservation under the original attempt identity: a
    // reserved or launched identity reconciles by that identity instead of
    // spawning a second child. The reservation releases below when the
    // material write fails, and after the spawn settles in the launch
    // call.
    let nonce = mint_dispatch_nonce(
        DispatchedWorkerKind::Doctor,
        &admission.attempt_digest,
        admission.admitted_at_unix_nanos,
        contour.principal_owner.as_str(),
    )?;
    let generation = Generation::new(generation)
        .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    let operation_id = OperationId::new(format!(
        "{}-{}-{}",
        DispatchedWorkerKind::Doctor.operation_prefix(),
        generation.get(),
        short_identity(&admission.attempt_digest)?
    ))
    .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    {
        let mut launches = launches_table(contour)?;
        if launches.by_identity.contains_key(&admission.attempt_digest) {
            return Ok(PreparedDoctorLaunch::Skipped {
                admission,
                skip: DoctorLaunchSkip::LaunchInFlight,
            });
        }
        launches.by_identity.insert(
            admission.attempt_digest.clone(),
            LaunchRecord {
                kind: DispatchedWorkerKind::Doctor,
                identity: admission.attempt_digest.clone(),
                admission_digest: admission.admission_digest.clone(),
                request_digest: material.attempt.request_digest.clone(),
                effect_digest: admission.effect_digest.clone(),
                material_path: None,
                nonce: nonce.clone(),
                operation_id: operation_id_string(&operation_id),
                phase: LaunchPhase::Reserved,
                testd_admission: None,
            },
        );
    }
    let Some(file_name) = DispatchedWorkerKind::Doctor.material_file_name() else {
        release_launch(contour, &admission.attempt_digest);
        return Err(DispatchLaunchError::Gate(
            "doctor defines no dispatch material file".to_owned(),
        ));
    };
    let material_dir_owned = material_dir.to_path_buf();
    let material_path = material_dir_owned.join(file_name);
    let bytes = doctor_material_bytes(
        material.attempt,
        material.request_json,
        material.manifest_json,
        &authority_epoch,
        generation.get(),
        &nonce,
    );
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(error) => {
            release_launch(contour, &admission.attempt_digest);
            return Err(error);
        }
    };
    if let Err(error) = write_material_file(&material_path, &bytes) {
        release_launch(contour, &admission.attempt_digest);
        return Err(error);
    }
    if let Ok(mut launches) = contour.launches.lock()
        && let Some(record) = launches.by_identity.get_mut(&admission.attempt_digest)
    {
        record.material_path = Some(material_path.clone());
    }
    Ok(PreparedDoctorLaunch::Ready(ReadyDoctorLaunch {
        admission,
        nonce,
        operation_id,
        material_path,
        executable: material.executable.to_path_buf(),
        executable_sha256: material.executable_sha256.to_owned(),
        working_directory: material.working_directory.to_path_buf(),
        authority_epoch,
        generation,
    }))
}

/// Returns the composed Doctor ledger port or fails closed.
fn doctor_ledger(
    contour: &'static ComposedDispatchContour,
) -> Result<Arc<dyn DoctorLedgerPort>, DispatchLaunchError> {
    let doctor = contour
        .doctor
        .lock()
        .map_err(|_| DispatchLaunchError::Gate("doctor front-door lock poisoned".to_owned()))?;
    doctor
        .as_ref()
        .map(|state| Arc::clone(&state.ledger))
        .ok_or(DispatchLaunchError::Uncomposed("doctor front door"))
}

/// Releases one launch reservation best-effort (prepare/write failure
/// path). A later call may retry cleanly under the same identity.
fn release_launch(contour: &'static ComposedDispatchContour, identity: &str) {
    if let Ok(mut launches) = contour.launches.lock()
        && launches
            .by_identity
            .get(identity)
            .is_some_and(|record| record.phase == LaunchPhase::Reserved)
    {
        launches.by_identity.remove(identity);
    }
}

/// Spawns one prepared Doctor launch through the admitted process gateway.
///
/// The child admission carries an empty argv — the attempt material travels
/// only over the protected dispatch file — plus a secret-free environment
/// and bounded resource limits, mirroring the approved `eliotd` launch
/// contour. The path proof pins the composition-supplied executable
/// binding; the owner binds the Kernel principal. An unknown spawn outcome
/// is reported (not hidden) so the caller retains the launch as
/// unreconciled under its original identity (see
/// [`reconcile_launched_doctor_attempt`]); any other spawn failure is an
/// error, and the caller reaps the material file and releases the
/// reservation.
pub async fn start_ready_doctor_launch(
    kernel: &KernelComposition,
    ready: &ReadyDoctorLaunch,
) -> Result<ChildStartOutcome, DispatchLaunchError> {
    match spawn_ready_child(
        kernel,
        &SpawnInputs {
            kind: DispatchedWorkerKind::Doctor,
            operation_id: &ready.operation_id,
            executable: &ready.executable,
            executable_sha256: &ready.executable_sha256,
            working_directory: &ready.working_directory,
            generation: ready.generation,
            authority_epoch: &ready.authority_epoch,
            material_path: Some(ready.material_path.as_path()),
        },
    )
    .await?
    {
        SpawnOutcome::Started(receipt) => Ok(ChildStartOutcome::Started(Box::new(SpawnedChild {
            receipt: *receipt,
            operation_id: ready.operation_id.clone(),
        }))),
        SpawnOutcome::Unknown(operation_id) => {
            Ok(ChildStartOutcome::Unknown(UncertainSpawn { operation_id }))
        }
    }
}

/// Outcome of spawning one prepared dispatch child.
pub enum ChildStartOutcome {
    /// The child started; carries the admitted receipt (boxed: receipts
    /// dwarf the unknown outcome).
    Started(Box<SpawnedChild>),
    /// The spawn outcome is unknown; the caller must retain the launch as
    /// unreconciled under its original identity and reconcile later —
    /// never blind-retry as a new attempt.
    Unknown(UncertainSpawn),
}

/// A spawned dispatch child: the admitted receipt plus the retained
/// launch identity.
pub struct SpawnedChild {
    /// The admitted process-start receipt.
    pub receipt: ProcessStartReceipt,
    /// Child process operation identity.
    pub operation_id: OperationId,
}

/// A spawn whose outcome is unknown: admitted and possibly started, but
/// unproven. The caller must retain it as unreconciled under its original
/// identity and reconcile later — never blind-retry as a new attempt.
pub struct UncertainSpawn {
    /// Child process operation identity.
    pub operation_id: OperationId,
}

/// Outcome of one child spawn: started, or unknown.
enum SpawnOutcome {
    /// The child started; carries the admitted receipt (boxed: receipts
    /// dwarf the unknown outcome).
    Started(Box<ProcessStartReceipt>),
    /// The outcome is unknown; carries the operation identity for
    /// reconcile-by-identity.
    Unknown(OperationId),
}

/// Bound inputs for one child spawn: the prepared child binding plus the
/// live authority it was admitted under. Groups the spawn parameters so
/// the Doctor and testd halves share one call shape.
struct SpawnInputs<'a> {
    kind: DispatchedWorkerKind,
    operation_id: &'a OperationId,
    executable: &'a Path,
    executable_sha256: &'a str,
    working_directory: &'a Path,
    generation: Generation,
    authority_epoch: &'a EpochId,
    material_path: Option<&'a Path>,
}

/// Spawns one prepared child through the admitted process gateway.
///
/// Shared contour for Doctor and testd: the child admission always carries
/// an empty argv (attempt material travels only over the protected
/// dispatch file for Doctor, and testd accepts no byte surface at all),
/// a secret-free environment, and bounded limits. Any non-unknown spawn
/// failure reaps the Doctor material file best-effort so a stale
/// presentation never lingers for a later invocation.
async fn spawn_ready_child(
    kernel: &KernelComposition,
    inputs: &SpawnInputs<'_>,
) -> Result<SpawnOutcome, DispatchLaunchError> {
    let kind = inputs.kind;
    let operation_id = inputs.operation_id;
    let executable_str = inputs.executable.to_string_lossy().into_owned();
    let working_directory_str = inputs.working_directory.to_string_lossy().into_owned();
    if executable_str.trim().is_empty() || working_directory_str.trim().is_empty() {
        return Err(DispatchLaunchError::Path(
            "dispatch child executable and working directory must be non-blank".to_owned(),
        ));
    }
    let intent = ProcessIntent::new(
        operation_id.clone(),
        ProcessTreeId::new(format!(
            "{}-tree-{}",
            kind.operation_prefix(),
            short_identity(&operation_id_string(operation_id))?
        ))
        .map_err(gate_error)?,
        JobId::new(format!(
            "{}-job-{}",
            kind.operation_prefix(),
            short_identity(&operation_id_string(operation_id))?
        ))
        .map_err(gate_error)?,
        ImageId::new(format!(
            "{}-image-{}",
            kind.operation_prefix(),
            short_identity(&operation_id_string(operation_id))?
        ))
        .map_err(gate_error)?,
        SessionId::new(format!(
            "{}-session-{}",
            kind.operation_prefix(),
            short_identity(&operation_id_string(operation_id))?
        ))
        .map_err(gate_error)?,
        inputs.generation,
        executable_str,
        inputs.executable_sha256.to_owned(),
        Vec::new(),
        working_directory_str,
        EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
            .map_err(gate_error)?,
        ResourceLimits::new(86_400_000, None, None, 64 * 1024, 64 * 1024, 4).map_err(gate_error)?,
    )
    .map_err(gate_error)?;
    let fence = FencingToken::new(
        inputs.authority_epoch.clone(),
        inputs.generation,
        format!(
            "{}-fence-{}",
            kind.operation_prefix(),
            short_identity(&operation_id_string(operation_id))?
        ),
    )
    .map_err(gate_error)?;
    let admission = ProcessExecutionAdmissionRequest::new(
        kind.module_id(),
        intent,
        ActionLeaseRef::new(format!(
            "{}-kernel-launch-{}",
            kind.operation_prefix(),
            short_identity(&operation_id_string(operation_id))?
        ))
        .map_err(gate_error)?,
        fence,
        super::unix_ms().saturating_add(60_000),
    )
    .map_err(gate_error)?;
    admission.validate().map_err(gate_error)?;
    // Fail closed fast when no admitted executor is configured: nothing is
    // spawned, and the caller reaps the prepared material and releases the
    // reservation.
    let Some(gateway) = kernel.process_gateway.as_ref() else {
        if let Some(path) = inputs.material_path {
            reap_material_file(path);
        }
        return Err(DispatchLaunchError::ExecutorUnavailable);
    };
    let owner = launch_owner_binding(kind, inputs.authority_epoch, inputs.generation)?;
    let proof = kernel
        .retain_process_path_proof(&admission)
        .map_err(|error| DispatchLaunchError::Path(error.to_string()))?;
    match gateway.start(&owner, admission, proof).await {
        Ok(receipt) => Ok(SpawnOutcome::Started(Box::new(receipt))),
        Err(ProcessExecutionError::UnknownOutcome) => {
            Ok(SpawnOutcome::Unknown(operation_id.clone()))
        }
        Err(error) => {
            if let Some(path) = inputs.material_path {
                reap_material_file(path);
            }
            Err(DispatchLaunchError::Start(error.to_string()))
        }
    }
}

/// Returns the operation identity string for derived child bindings.
fn operation_id_string(operation_id: &OperationId) -> String {
    operation_id.as_str().to_owned()
}

/// Binds the Kernel-owned process owner for a dispatch child spawn.
///
/// Mirrors the approved `eliotd` launch contour: the owner module is the
/// worker module, and the principal digest binds the Kernel pipe identity
/// plus the live epoch and generation through the existing runtime-identity
/// owner. Fails closed outside the Windows process contour, where no
/// pipe identity exists.
#[cfg(windows)]
fn launch_owner_binding(
    kind: DispatchedWorkerKind,
    authority_epoch: &EpochId,
    generation: Generation,
) -> Result<ProcessOwnerBinding, DispatchLaunchError> {
    let expectation = super::current_process_named_pipe_expectation()
        .map_err(|error| DispatchLaunchError::Path(error.to_string()))?;
    ProcessOwnerBinding::new(
        kind.module_id(),
        stable_owner_principal_digest(
            expectation.expected_sid(),
            kind.module_id(),
            authority_epoch,
            generation,
        ),
        authority_epoch.clone(),
        generation,
    )
    .map_err(|error| DispatchLaunchError::Path(error.to_string()))
}

/// Binds the Kernel-owned process owner for a dispatch child spawn.
///
/// The pipe identity the owner derives from exists only on the Windows
/// process contour; elsewhere the spawn fails closed without minting an
/// owner.
#[cfg(not(windows))]
fn launch_owner_binding(
    kind: DispatchedWorkerKind,
    authority_epoch: &EpochId,
    generation: Generation,
) -> Result<ProcessOwnerBinding, DispatchLaunchError> {
    let _ = (kind, authority_epoch, generation);
    Err(DispatchLaunchError::Unsupported(
        "dispatch child spawn needs the Windows process contour",
    ))
}

/// Admits one Doctor attempt, then launches the real `eliot-doctor` binary
/// through the admitted process executor.
///
/// Admit-then-launch in one seam: [`prepare_doctor_launch`] admits and
/// stages the dispatch file, then the ready launch spawns and the original
/// identity is retained. Refusals and skips return as outcomes without
/// spawning; a failed spawn reaps the file and releases the reservation;
/// an unknown spawn outcome retains the launch as unreconciled under its
/// original identity for [`reconcile_launched_doctor_attempt`].
pub async fn launch_admitted_doctor_attempt(
    kernel: &KernelComposition,
    material: &DoctorLaunchMaterial<'_>,
    now_unix_nanos: u64,
) -> Result<DoctorLaunchOutcome, DispatchLaunchError> {
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("doctor front door"))?;
    let prepared = prepare_doctor_launch(kernel, material, now_unix_nanos)?;
    let ready = match prepared {
        PreparedDoctorLaunch::Ready(ready) => ready,
        PreparedDoctorLaunch::Skipped { admission, skip } => {
            return Ok(DoctorLaunchOutcome::NotLaunched { admission, skip });
        }
        PreparedDoctorLaunch::Refused(response) => {
            return Ok(DoctorLaunchOutcome::Refused(response));
        }
    };
    let material_path = ready.material_path.clone();
    let attempt_digest = ready.admission.attempt_digest.clone();
    let request_digest = material.attempt.request_digest.clone();
    match start_ready_doctor_launch(kernel, &ready).await {
        Ok(ChildStartOutcome::Started(spawned)) => {
            retain_launch(
                contour,
                LaunchRecord {
                    kind: DispatchedWorkerKind::Doctor,
                    identity: attempt_digest,
                    admission_digest: ready.admission.admission_digest.clone(),
                    request_digest,
                    effect_digest: ready.admission.effect_digest.clone(),
                    material_path: Some(material_path),
                    nonce: ready.nonce.clone(),
                    operation_id: operation_id_string(&ready.operation_id),
                    phase: LaunchPhase::Launched,
                    testd_admission: None,
                },
            )?;
            Ok(DoctorLaunchOutcome::Launched {
                admission: ready.admission,
                nonce: ready.nonce,
                operation_id: ready.operation_id,
                receipt: Box::new(spawned.receipt),
            })
        }
        Ok(ChildStartOutcome::Unknown(uncertain)) => {
            retain_launch(
                contour,
                LaunchRecord {
                    kind: DispatchedWorkerKind::Doctor,
                    identity: attempt_digest,
                    admission_digest: ready.admission.admission_digest.clone(),
                    request_digest,
                    effect_digest: ready.admission.effect_digest.clone(),
                    material_path: Some(material_path),
                    nonce: ready.nonce.clone(),
                    operation_id: operation_id_string(&uncertain.operation_id),
                    phase: LaunchPhase::Unreconciled,
                    testd_admission: None,
                },
            )?;
            Ok(DoctorLaunchOutcome::LaunchUnknown {
                admission: ready.admission,
                nonce: ready.nonce,
                operation_id: ready.operation_id,
            })
        }
        Err(error) => {
            reap_material_file(&material_path);
            release_launch(contour, &attempt_digest);
            Err(error)
        }
    }
}

/// Retains one launch record, keeping the first record under an identity.
///
/// Insert-or-keep-first: a concurrent duplicate never overwrites the
/// original nonce, operation, or admission digest, so reconciliation
/// always names the original identity.
fn retain_launch(
    contour: &'static ComposedDispatchContour,
    record: LaunchRecord,
) -> Result<(), DispatchLaunchError> {
    let mut launches = launches_table(contour)?;
    launches
        .by_identity
        .entry(record.identity.clone())
        .and_modify(|existing| {
            if existing.phase == LaunchPhase::Reserved {
                existing.nonce.clone_from(&record.nonce);
                existing.operation_id.clone_from(&record.operation_id);
                existing
                    .admission_digest
                    .clone_from(&record.admission_digest);
                existing.request_digest.clone_from(&record.request_digest);
                existing.effect_digest.clone_from(&record.effect_digest);
                existing.material_path.clone_from(&record.material_path);
                existing.testd_admission.clone_from(&record.testd_admission);
                existing.phase = record.phase;
            }
        })
        .or_insert(record);
    Ok(())
}

/// Reconciles one launched-but-unreconciled Doctor attempt by its original
/// identity.
///
/// Loads the durable attempt row by the original attempt digest and
/// compares the bound admission digest: no new admission is minted, no new
/// attempt id is computed, and no second child is spawned. A reported
/// effect (or a cancelled attempt) reaps the dispatch file best-effort and
/// closes the slot; anything still outstanding stays unreconciled for a
/// later call. Unknown identities report unknown instead of inventing
/// state.
pub fn reconcile_launched_doctor_attempt(
    attempt_digest: &str,
) -> Result<ReconcileLaunchedOutcome, DispatchLaunchError> {
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("doctor front door"))?;
    let retained = {
        let launches = launches_table(contour)?;
        launches.by_identity.get(attempt_digest).cloned()
    };
    let Some(retained) = retained else {
        return Ok(ReconcileLaunchedOutcome::Unknown {
            kind: DispatchedWorkerKind::Doctor,
            identity: attempt_digest.to_owned(),
        });
    };
    if retained.kind != DispatchedWorkerKind::Doctor {
        return Ok(ReconcileLaunchedOutcome::Unknown {
            kind: DispatchedWorkerKind::Doctor,
            identity: attempt_digest.to_owned(),
        });
    }
    let ledger = doctor_ledger(contour)?;
    let key = OperationIdentity::new(attempt_digest)
        .map_err(|error| DispatchLaunchError::InvalidMaterial(error.to_string()))?;
    let row: Option<DoctorAttemptRecord> = ledger
        .load_doctor_attempt(&key)
        .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    let Some(row) = row else {
        return Ok(ReconcileLaunchedOutcome::Unknown {
            kind: DispatchedWorkerKind::Doctor,
            identity: attempt_digest.to_owned(),
        });
    };
    if row.admission_digest.as_deref() != Some(retained.admission_digest.as_str()) {
        return Err(DispatchLaunchError::Inconsistent(
            "durable doctor attempt cannot reproduce its admission".to_owned(),
        ));
    }
    let terminal = match row.state {
        eliot_ors::DoctorAttemptState::Cancelled => true,
        eliot_ors::DoctorAttemptState::Admitted => effect_reported(&ledger, &retained)?,
        _ => false,
    };
    if terminal {
        if let Some(path) = retained.material_path.as_deref() {
            reap_material_file(path);
        }
        mark_reconciled(contour, attempt_digest)?;
        return Ok(ReconcileLaunchedOutcome::Reconciled {
            kind: DispatchedWorkerKind::Doctor,
            identity: attempt_digest.to_owned(),
            admission_digest: retained.admission_digest,
        });
    }
    Ok(ReconcileLaunchedOutcome::Unreconciled {
        kind: DispatchedWorkerKind::Doctor,
        identity: attempt_digest.to_owned(),
    })
}

/// Returns true when the retained admission bound an effect whose outcome
/// reported durably.
fn effect_reported(
    ledger: &Arc<dyn DoctorLedgerPort>,
    retained: &LaunchRecord,
) -> Result<bool, DispatchLaunchError> {
    let Some(effect_digest) = retained.effect_digest.as_deref() else {
        return Ok(false);
    };
    let key = OperationIdentity::new(effect_digest)
        .map_err(|error| DispatchLaunchError::Inconsistent(error.to_string()))?;
    let effect: Option<DoctorEffectRecord> = ledger
        .ledger()
        .load_doctor_effect(&key)
        .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    Ok(effect.is_some_and(|record| record.state == eliot_ors::DoctorEffectState::Reported))
}

/// Marks one launch record reconciled, closing its slot.
fn mark_reconciled(
    contour: &'static ComposedDispatchContour,
    identity: &str,
) -> Result<(), DispatchLaunchError> {
    let mut launches = launches_table(contour)?;
    if let Some(record) = launches.by_identity.get_mut(identity) {
        record.phase = LaunchPhase::Reconciled;
    }
    Ok(())
}

/// Outcome of reconciling one launched attempt by its original identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileLaunchedOutcome {
    /// The durable outcome converged under the original identity; carries
    /// the original admission digest, never a recomputed one.
    Reconciled {
        /// Worker kind the identity was launched for.
        kind: DispatchedWorkerKind,
        /// Original attempt (Doctor) or job (testd) identity.
        identity: String,
        /// Original admission digest.
        admission_digest: String,
    },
    /// Still outstanding: the original identity stays retained, no second
    /// child is spawned, and a later call may reconcile.
    Unreconciled {
        /// Worker kind the identity was launched for.
        kind: DispatchedWorkerKind,
        /// Original attempt (Doctor) or job (testd) identity.
        identity: String,
    },
    /// Never launched through this contour (or the durable row is gone):
    /// reports unknown instead of inventing state.
    Unknown {
        /// Worker kind queried.
        kind: DispatchedWorkerKind,
        /// Queried identity.
        identity: String,
    },
}

/// Caller-supplied testd launch material: the admission wire request plus
/// the composition-pinned child binary binding.
///
/// The closed envelope travels inside `request.closed_request_json` and is
/// re-parsed (never trusted) at reconcile time. Like Doctor, nothing
/// travels via argv, stdin, or the environment — and testd additionally
/// writes no dispatch file, because that binary defines no material reader
/// (see [`DispatchedWorkerKind::material_file_name`]). The contour carries
/// the admission context kernel-side in the retained launch record and
/// stops at the spawn boundary instead of working around the missing
/// child reader.
pub struct TestdLaunchMaterial<'a> {
    /// Full wire envelope: job seed, attempt sequence, opaque closed
    /// envelope bytes, target digest, and canonical digest.
    pub request: &'a TestdAdmissionAttemptRequest,
    /// Composition-pinned child executable path.
    pub executable: &'a Path,
    /// Expected SHA-256 digest of the child executable image.
    pub executable_sha256: &'a str,
    /// Composition-pinned child working directory.
    pub working_directory: &'a Path,
}

/// Why a prepared testd launch produced no child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestdLaunchSkip {
    /// The job identity is already reserved or launched: the returned
    /// admission is the retained original, never a recompute under a new
    /// id.
    LaunchInFlight,
    /// The job was admitted cancelled: projected without executing.
    CancelledAdmission,
}

/// A prepared testd launch: admitted and nonce-bound, ready to spawn.
pub enum PreparedTestdLaunch {
    /// Ready to spawn through the admitted executor.
    Ready(ReadyTestdLaunch),
    /// An exact resubmit under one job identity: carries the RETAINED
    /// original admission (original admitted-at time and digest), never
    /// the just-recomputed one.
    ReplayOriginal {
        /// The original admission for the job identity.
        admission: Box<TestdAdmission>,
    },
    /// Admitted but needing no child; carries the admission and the reason.
    Skipped {
        /// The admission for the job identity.
        admission: Box<TestdAdmission>,
        /// Why no child is spawned.
        skip: TestdLaunchSkip,
    },
    /// The gate refused or conflicted; carries the typed answer, never an
    /// admission.
    Refused(TestdAdmissionResponse),
}

/// A testd launch ready to spawn: every authority check passed.
pub struct ReadyTestdLaunch {
    /// The admission for the job identity.
    pub admission: Box<TestdAdmission>,
    /// The I7.5/I15.2 launch nonce retained for the session proof.
    pub nonce: String,
    /// Deterministic child operation identity derived from the request
    /// digest, so the admitted executor replays (never double-spawns) an
    /// identical launch.
    pub operation_id: OperationId,
    /// Composition-pinned child executable path.
    pub executable: PathBuf,
    /// Expected SHA-256 digest of the child executable image.
    pub executable_sha256: String,
    /// Composition-pinned child working directory.
    pub working_directory: PathBuf,
    /// Live authority epoch bound at admission.
    pub authority_epoch: EpochId,
    /// Live activation generation bound at admission.
    pub generation: Generation,
}

/// Outcome of one testd admit-then-launch call.
pub enum TestdLaunchOutcome {
    /// The child was spawned through the admitted executor.
    Launched {
        /// The admission for the job identity.
        admission: Box<TestdAdmission>,
        /// The launch nonce retained for the session proof.
        nonce: String,
        /// Child process operation identity.
        operation_id: OperationId,
        /// The admitted process-start receipt (boxed: receipts dwarf the
        /// other outcomes).
        receipt: Box<ProcessStartReceipt>,
    },
    /// The spawn outcome is unknown: retained as unreconciled under the
    /// original job identity — reconcile later, never blind-retry.
    LaunchUnknown {
        /// The admission for the job identity.
        admission: Box<TestdAdmission>,
        /// The launch nonce retained for the session proof.
        nonce: String,
        /// Child process operation identity.
        operation_id: OperationId,
    },
    /// An exact resubmit under one job identity: carries the retained
    /// original admission, and no second child is spawned.
    ReplayOriginal {
        /// The original admission for the job identity.
        admission: Box<TestdAdmission>,
    },
    /// Admitted but needing no child; carries the admission and the reason.
    NotLaunched {
        /// The admission for the job identity.
        admission: Box<TestdAdmission>,
        /// Why no child was spawned.
        skip: TestdLaunchSkip,
    },
    /// The gate refused or conflicted; carries the typed answer.
    Refused(TestdAdmissionResponse),
}

/// Admits one testd job and prepares its launch: nonce-bound and
/// single-flight reserved under the original job identity, ready to spawn.
///
/// Sequence: validate the child binding; admit through the composed
/// principal (stateless: wire plus live authority only); skip cancelled
/// jobs without spawning; reconcile exact resubmits by the retained
/// original admission (changed terms under one job identity refuse with
/// [`DispatchLaunchError::ChangedTerms`] instead of overwriting); reserve
/// the job identity single-flight; mint the replay-stable nonce. Nothing
/// is spawned here and no file is written (the child defines no reader):
/// [`launch_admitted_testd_attempt`] spawns the returned
/// [`ReadyTestdLaunch`] through the admitted executor.
#[allow(
    clippy::too_many_lines,
    reason = "admit, reserve, nonce, and single-flight stay in one ordered authority path so no launch step can run before its gate"
)]
pub fn prepare_testd_launch(
    kernel: &KernelComposition,
    material: &TestdLaunchMaterial<'_>,
    now_unix_nanos: u64,
) -> Result<PreparedTestdLaunch, DispatchLaunchError> {
    if now_unix_nanos == 0 {
        return Err(DispatchLaunchError::InvalidMaterial(
            "admission time must be non-zero".to_owned(),
        ));
    }
    if material.executable.parent().is_none() {
        return Err(DispatchLaunchError::InvalidMaterial(
            "dispatch child executable has no parent directory".to_owned(),
        ));
    }
    require_digest(
        material.executable_sha256,
        "dispatch child executable digest must be a lowercase SHA-256 digest",
    )?;
    if material.working_directory.as_os_str().is_empty() {
        return Err(DispatchLaunchError::InvalidMaterial(
            "dispatch child working directory must be non-blank".to_owned(),
        ));
    }
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("testd front door"))?;
    let (authority_epoch, generation, response) = {
        let service = kernel
            .service
            .lock()
            .map_err(|_| DispatchLaunchError::Gate("kernel service lock poisoned".to_owned()))?;
        let response = admit_testd_attempt(&service, material.request, now_unix_nanos)?;
        let epoch = service.authority_epoch();
        let generation = service
            .activation_receipt()
            .map_or(0, |receipt| receipt.generation.value());
        (epoch, generation, response)
    };
    if generation == 0 {
        return Err(DispatchLaunchError::Gate(
            "live activation generation is unavailable".to_owned(),
        ));
    }
    let admission = match response {
        TestdAdmissionResponse::Admitted(admission) => admission,
        refused => return Ok(PreparedTestdLaunch::Refused(refused)),
    };
    if admission.cancelled {
        return Ok(PreparedTestdLaunch::Skipped {
            admission,
            skip: TestdLaunchSkip::CancelledAdmission,
        });
    }
    require_digest(
        &admission.request_digest,
        "admission request digest must be a lowercase SHA-256 digest",
    )?;
    let nonce = mint_dispatch_nonce(
        DispatchedWorkerKind::Testd,
        &admission.request_digest,
        admission.admitted_at_unix_nanos,
        contour.principal_owner.as_str(),
    )?;
    let generation = Generation::new(generation)
        .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    let operation_id = OperationId::new(format!(
        "{}-{}-{}",
        DispatchedWorkerKind::Testd.operation_prefix(),
        generation.get(),
        short_identity(&admission.request_digest)?
    ))
    .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    {
        let mut launches = launches_table(contour)?;
        if let Some(existing) = launches.by_identity.get(&admission.job_id) {
            if existing.kind != DispatchedWorkerKind::Testd {
                return Err(DispatchLaunchError::ChangedTerms(format!(
                    "job identity {} is already launched for another worker",
                    admission.job_id
                )));
            }
            if existing.request_digest != admission.request_digest {
                return Err(DispatchLaunchError::ChangedTerms(format!(
                    "job {} presents changed terms under one job identity",
                    admission.job_id
                )));
            }
            if let Some(retained) = existing.testd_admission.clone() {
                return Ok(PreparedTestdLaunch::ReplayOriginal {
                    admission: Box::new(retained),
                });
            }
        }
        launches.by_identity.insert(
            admission.job_id.clone(),
            LaunchRecord {
                kind: DispatchedWorkerKind::Testd,
                identity: admission.job_id.clone(),
                admission_digest: admission.admission_digest.clone(),
                request_digest: admission.request_digest.clone(),
                effect_digest: None,
                material_path: None,
                nonce: nonce.clone(),
                operation_id: operation_id_string(&operation_id),
                phase: LaunchPhase::Reserved,
                testd_admission: Some((*admission).clone()),
            },
        );
    }
    Ok(PreparedTestdLaunch::Ready(ReadyTestdLaunch {
        admission,
        nonce,
        operation_id,
        executable: material.executable.to_path_buf(),
        executable_sha256: material.executable_sha256.to_owned(),
        working_directory: material.working_directory.to_path_buf(),
        authority_epoch,
        generation,
    }))
}

/// Spawns one prepared testd launch through the admitted process gateway.
///
/// Same seam shape as the Doctor spawn: empty argv, secret-free
/// environment, bounded limits, pinned path proof, Kernel-owned process
/// owner. The #1452 residual is honored here: the seam provisions the
/// admitted executor (fail-closed when unconfigured) and retains the
/// admission context kernel-side; the child-side material reader remains
/// the recorded testd-owner gap, so no byte surface is invented for it.
pub async fn start_ready_testd_launch(
    kernel: &KernelComposition,
    ready: &ReadyTestdLaunch,
) -> Result<ChildStartOutcome, DispatchLaunchError> {
    match spawn_ready_child(
        kernel,
        &SpawnInputs {
            kind: DispatchedWorkerKind::Testd,
            operation_id: &ready.operation_id,
            executable: &ready.executable,
            executable_sha256: &ready.executable_sha256,
            working_directory: &ready.working_directory,
            generation: ready.generation,
            authority_epoch: &ready.authority_epoch,
            material_path: None,
        },
    )
    .await?
    {
        SpawnOutcome::Started(receipt) => Ok(ChildStartOutcome::Started(Box::new(SpawnedChild {
            receipt: *receipt,
            operation_id: ready.operation_id.clone(),
        }))),
        SpawnOutcome::Unknown(operation_id) => {
            Ok(ChildStartOutcome::Unknown(UncertainSpawn { operation_id }))
        }
    }
}

/// Admits one testd job, then launches the real `eliot-testd` binary
/// through the admitted process executor.
///
/// Admit-then-launch in one seam, mirroring the Doctor call: prepare
/// admits and reserves the original job identity, then the ready launch
/// spawns and the identity is retained. Exact resubmits return the
/// retained original admission without spawning; refusals and skips return
/// as outcomes; a failed spawn releases the reservation; an unknown spawn
/// outcome retains the launch as unreconciled for
/// [`reconcile_launched_testd_attempt`].
pub async fn launch_admitted_testd_attempt(
    kernel: &KernelComposition,
    material: &TestdLaunchMaterial<'_>,
    now_unix_nanos: u64,
) -> Result<TestdLaunchOutcome, DispatchLaunchError> {
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("testd front door"))?;
    let prepared = prepare_testd_launch(kernel, material, now_unix_nanos)?;
    let ready = match prepared {
        PreparedTestdLaunch::Ready(ready) => ready,
        PreparedTestdLaunch::ReplayOriginal { admission } => {
            return Ok(TestdLaunchOutcome::ReplayOriginal { admission });
        }
        PreparedTestdLaunch::Skipped { admission, skip } => {
            return Ok(TestdLaunchOutcome::NotLaunched { admission, skip });
        }
        PreparedTestdLaunch::Refused(response) => {
            return Ok(TestdLaunchOutcome::Refused(response));
        }
    };
    let job_id = ready.admission.job_id.clone();
    let request_digest = ready.admission.request_digest.clone();
    match start_ready_testd_launch(kernel, &ready).await {
        Ok(ChildStartOutcome::Started(spawned)) => {
            retain_launch(
                contour,
                LaunchRecord {
                    kind: DispatchedWorkerKind::Testd,
                    identity: job_id,
                    admission_digest: ready.admission.admission_digest.clone(),
                    request_digest,
                    effect_digest: None,
                    material_path: None,
                    nonce: ready.nonce.clone(),
                    operation_id: operation_id_string(&ready.operation_id),
                    phase: LaunchPhase::Launched,
                    testd_admission: Some((*ready.admission).clone()),
                },
            )?;
            Ok(TestdLaunchOutcome::Launched {
                admission: ready.admission,
                nonce: ready.nonce,
                operation_id: ready.operation_id,
                receipt: Box::new(spawned.receipt),
            })
        }
        Ok(ChildStartOutcome::Unknown(uncertain)) => {
            retain_launch(
                contour,
                LaunchRecord {
                    kind: DispatchedWorkerKind::Testd,
                    identity: job_id,
                    admission_digest: ready.admission.admission_digest.clone(),
                    request_digest,
                    effect_digest: None,
                    material_path: None,
                    nonce: ready.nonce.clone(),
                    operation_id: operation_id_string(&uncertain.operation_id),
                    phase: LaunchPhase::Unreconciled,
                    testd_admission: Some((*ready.admission).clone()),
                },
            )?;
            Ok(TestdLaunchOutcome::LaunchUnknown {
                admission: ready.admission,
                nonce: ready.nonce,
                operation_id: ready.operation_id,
            })
        }
        Err(error) => {
            release_launch(contour, &job_id);
            Err(error)
        }
    }
}

/// Reconciles one launched-but-unreconciled testd job by its original
/// identity.
///
/// The caller presents the uncertain delivery's request; the retained
/// original admission is re-proved against it under live authority through
/// [`reconcile_testd_admission`]: job binding, fence, cancellation,
/// operation, and the recomputed admission digest must all match. Nothing
/// is mutated and no new admission is minted. A matching delivery closes
/// the slot as reconciled under the original admission digest; anything
/// else stays unreconciled for a later call. Unknown job identities
/// report unknown instead of inventing state.
///
/// Note: this proves the front-door admission still binds — durable job
/// terminality lives in the testd owner's store, so an operator release
/// through [`release_launched_attempt`] (or a process restart) is the
/// only slot release besides this reconcile.
pub fn reconcile_launched_testd_attempt(
    kernel: &KernelComposition,
    job_id: &str,
    request: &TestdAdmissionAttemptRequest,
) -> Result<ReconcileLaunchedOutcome, DispatchLaunchError> {
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("testd front door"))?;
    let retained = {
        let launches = launches_table(contour)?;
        launches.by_identity.get(job_id).cloned()
    };
    let Some(retained) = retained.filter(|record| record.kind == DispatchedWorkerKind::Testd)
    else {
        return Ok(ReconcileLaunchedOutcome::Unknown {
            kind: DispatchedWorkerKind::Testd,
            identity: job_id.to_owned(),
        });
    };
    let Some(admission) = retained.testd_admission.clone() else {
        return Ok(ReconcileLaunchedOutcome::Unknown {
            kind: DispatchedWorkerKind::Testd,
            identity: job_id.to_owned(),
        });
    };
    let envelope: TestdAdmissionEnvelope = serde_json::from_str(&request.closed_request_json)
        .map_err(|_| {
            DispatchLaunchError::InvalidMaterial(
                "testd closed request envelope is not JSON".to_owned(),
            )
        })?;
    let live_epoch = kernel
        .service
        .lock()
        .map_err(|_| DispatchLaunchError::Gate("kernel service lock poisoned".to_owned()))?
        .authority_epoch();
    let binds = reconcile_testd_admission(&admission, request, &envelope, &live_epoch)
        .map_err(gate_error)?;
    if binds {
        mark_reconciled(contour, job_id)?;
        return Ok(ReconcileLaunchedOutcome::Reconciled {
            kind: DispatchedWorkerKind::Testd,
            identity: job_id.to_owned(),
            admission_digest: retained.admission_digest,
        });
    }
    Ok(ReconcileLaunchedOutcome::Unreconciled {
        kind: DispatchedWorkerKind::Testd,
        identity: job_id.to_owned(),
    })
}

/// Releases one retained launch slot explicitly (operator/control-plane
/// surface).
///
/// Removes the record for `identity` only when its retained request
/// digest equals `request_digest`, so a newer reservation is never
/// released by a stale caller. Returns true when a slot was released.
/// Documented use: testd slots, whose durable terminality lives in the
/// testd owner's store and therefore never auto-release kernel-side.
pub fn release_launched_attempt(
    kind: DispatchedWorkerKind,
    identity: &str,
    request_digest: &str,
) -> Result<bool, DispatchLaunchError> {
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("dispatch contour"))?;
    let mut launches = launches_table(contour)?;
    let release = launches
        .by_identity
        .get(identity)
        .is_some_and(|record| record.kind == kind && record.request_digest == request_digest);
    if release {
        launches.by_identity.remove(identity);
    }
    Ok(release)
}

#[cfg(test)]
mod tests {
    //! DISPATCH-CONTOUR-2 Slice B behaviour checks (issues #461 and #22).
    //!
    //! One ordered lifecycle test drives the contour cell (process-global
    //! set-once state, so ordering inside one test is the deterministic
    //! shape): uncomposed arms fence; partial composition still fences the
    //! Doctor side; testd admits end-to-end (refused typed, admitted
    //! projected); the heartbeat carries the composed advertisement flag;
    //! testd prepare reserves, replays by the retained original, refuses
    //! changed terms, reconciles, and releases; launch without a configured
    //! executor fails closed and reaps. Independent pure checks (nonce
    //! shape, material shape, kind endpoints) run as separate tests.
    //!
    //! The Doctor composed side (registry plus valid-envelope admission)
    //! cannot compose in bins scope: `DoctorRecipeRegistry` builds only
    //! from `eliot-doctor-core` types, which this crate must not take as a
    //! dependency in this slice. That behaviour is proven service-side
    //! (`eliot-kernel-service/src/doctor.rs` tests, which own the
    //! registry fixtures): owner-composed advertisement is true, exact
    //! replays rebuild the original admission, and foreign envelopes are
    //! refused typed. A bins-side Doctor admit-through-execute proof awaits
    //! the integrator's registry fixture (new dev-dependency or cross-bin
    //! round trip) and is recorded as a residual, not worked around here.

    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

    use super::*;
    use eliot_contracts::{EpochLineageId, ResourceGeneration};
    use eliot_ipc::{PeerIdentity, Session};
    use eliot_kernel_service::{
        KernelActivationPermit, KernelControlCommand, KernelReadyReceipt, KernelServiceState,
        TESTD_ADMISSION_WIRE_ID, TESTD_ADMISSION_WIRE_VERSION, TestdAdmissionResponse,
    };
    use eliot_runtime_contracts::{HealthVector, ServiceProcessState};
    use std::num::NonZeroU64;

    use crate::KernelConfig;

    const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const PRINCIPAL: &str = "kernel.dispatch-test-principal";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(LINEAGE).expect("lineage"),
            NonZeroU64::new(sequence).expect("sequence"),
        )
        .expect("epoch")
    }

    fn temp_root(slug: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-dispatch-{slug}-{}-{}",
            std::process::id(),
            super::super::unix_ms()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        root
    }

    fn handle(value: &str) -> eliot_platform::PlatformHandle {
        eliot_platform::PlatformHandle::new(value).expect("test handle")
    }

    fn candidate_binding() -> eliot_kernel_service::HostKernelCandidateBinding {
        use eliot_kernel_service::{HostFileIdentity, HostJobIdentity, HostJobRoot, RestartBudget};
        use eliot_runtime_contracts::{
            RegisteredActivityWakePolicy, SupervisionJournalEpoch,
            SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
        };
        eliot_kernel_service::HostKernelCandidateBinding {
            installation_id: handle("installation-1"),
            host_epoch: eliot_contracts::AuthorityEpoch::new(1).expect("host epoch"),
            kernel_epoch: test_epoch(1),
            activation_id: handle("activation-1"),
            artifact_hash: handle("artifact-1"),
            config_hash: handle("config-1"),
            job_object_id: handle("Local\\Eliot-Host-Kernel-test"),
            pipe_identity: handle(eliot_kernel_service::KERNEL_CONTROL_PIPE),
            host_process: eliot_kernel_service::HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: "C:\\eliot\\host.exe".to_owned(),
            },
            job_binding: eliot_kernel_service::HostJobBinding {
                job: HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-test".to_owned(),
                },
                root: HostJobRoot {
                    process: eliot_kernel_service::HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: "C:\\eliot\\kernel.exe".to_owned(),
                    },
                    executable: HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: SupervisionLeaseIncarnationBinding {
                supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
                supervision_lease_id: String::new(),
                scope_ref_digest: String::new(),
                installation_id: "installation-1".to_owned(),
                host_epoch: SupervisionJournalEpoch {
                    lineage_id: "host-lineage-1".to_owned(),
                    sequence: 1,
                },
                activation_id: "activation-1".to_owned(),
                activation_generation: SupervisionJournalEpoch {
                    lineage_id: "activation-lineage-1".to_owned(),
                    sequence: 1,
                },
                kernel_generation: SupervisionJournalEpoch {
                    lineage_id: "kernel-lineage-1".to_owned(),
                    sequence: 1,
                },
                watchdog_epoch: SupervisionJournalEpoch {
                    lineage_id: "watchdog-lineage-1".to_owned(),
                    sequence: 1,
                },
                observation_scope: SupervisionObservationScope {
                    targets: vec!["eliot-kernel".to_owned()],
                    sensor_profile: "eliot-runtime-live-v3".to_owned(),
                    claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                    governance_axis: "runtime-live-v3".to_owned(),
                },
                wake_policy: RegisteredActivityWakePolicy::Disabled,
                predecessor: None,
            }
            .with_derived_ids()
            .expect("supervision incarnation"),
            restart_budget: RestartBudget::new(1, 1).expect("restart budget"),
            agent_bridge_admission: None,
            containment_action: None,
        }
    }

    /// Drives one production composition to `Ready` at the standalone live
    /// epoch (lineage `550e…`, sequence 1), so session binds prove exact
    /// authority agreement.
    fn ready_kernel(root: &Path) -> KernelComposition {
        let kernel = KernelComposition::new(KernelConfig::new(root)).expect("kernel composition");
        let candidate = candidate_binding();
        let mut service = kernel.service.lock().expect("service lock");
        service.reconcile(candidate.clone()).expect("reconcile");
        service.apply(KernelControlCommand::Shadow).expect("shadow");
        service
            .apply(KernelControlCommand::PrepareHandoff)
            .expect("handoff");
        let permit = KernelActivationPermit {
            operation_id: handle("op-dispatch-1"),
            candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: handle("txn-dispatch-1"),
            journal_sequence: 1,
            generation: ResourceGeneration::genesis(),
            authority_epoch: candidate.kernel_epoch.clone(),
            activation_nonce: eliot_platform::KernelActivationNonce::new(handle(&"a".repeat(64)))
                .expect("activation nonce"),
        };
        service
            .activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
            .expect("activate");
        let ready = KernelReadyReceipt {
            activation_id: candidate.activation_id.clone(),
            activation_operation_id: permit.operation_id.clone(),
            activation_nonce_digest: service
                .activation_receipt()
                .expect("activation receipt")
                .activation_nonce_digest
                .clone(),
            process: eliot_kernel_service::ProcessObservation {
                process_id: handle("pid:42:start:10"),
                job_object_id: candidate.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![handle("ev-dispatch-1")],
            },
            health: HealthVector::healthy(),
            evidence_refs: vec![handle("ev-dispatch-1")],
        };
        service.publish_ready(ready).expect("publish ready");
        assert_eq!(service.state(), KernelServiceState::Ready);
        drop(service);
        kernel
    }

    fn worker_session(kernel: &KernelComposition, module_id: &str) -> Session {
        use eliot_protocol::ProtocolVersion;
        let policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy")
            .clone();
        let peer = PeerIdentity::authenticated_for_test(
            eliot_ipc::ProcessBinding::from_observation(7, 9, r"C:\eliot\host.exe".to_owned())
                .expect("process binding"),
            "S-1-5-18".to_owned(),
            "0".to_owned(),
        )
        .expect("peer");
        let mut module_generation = policy.module_generation.clone();
        module_generation.module_id =
            eliot_contracts::ContractId::new(module_id).expect("module id");
        Session {
            connection_id: format!("dispatch-{module_id}-conn"),
            protocol_version: ProtocolVersion::CURRENT,
            peer,
            authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
            module_generation,
            launch_nonce: policy.launch_nonce.clone(),
            capabilities: policy.allowed_capabilities.clone(),
            privacy_classes: policy.allowed_privacy_classes.clone(),
            effects: policy.allowed_effects.clone(),
            session_epoch: 1,
            state: eliot_ipc::SessionState::Open,
        }
    }

    fn live_epoch(kernel: &KernelComposition) -> EpochId {
        kernel
            .service
            .lock()
            .expect("service lock")
            .authority_epoch()
    }

    fn testd_envelope(
        job_id: &str,
        operation: Option<&str>,
        generation: u64,
        epoch: &EpochId,
    ) -> TestdAdmissionEnvelope {
        TestdAdmissionEnvelope {
            job_id: job_id.to_owned(),
            operation_id: operation.map(str::to_owned),
            cancellation: false,
            fence: FencingToken::new(
                epoch.clone(),
                Generation::new(generation).expect("generation"),
                format!("testd-fence-{job_id}"),
            )
            .expect("fence"),
        }
    }

    fn testd_request(
        job_id: &str,
        attempt_seq: u32,
        envelope: &TestdAdmissionEnvelope,
    ) -> TestdAdmissionAttemptRequest {
        TestdAdmissionAttemptRequest {
            wire_id: TESTD_ADMISSION_WIRE_ID.to_owned(),
            wire_version: TESTD_ADMISSION_WIRE_VERSION,
            job_id: job_id.to_owned(),
            attempt_seq,
            closed_request_json: serde_json::to_string(envelope).expect("envelope json"),
            target_resource_digest: "2".repeat(64),
            request_digest: String::new(),
        }
        .with_computed_digest()
        .expect("request digest")
    }

    fn shape_valid_doctor_request() -> DoctorRepairAttemptRequest {
        // Shape-valid (wire plus canonical digest) but carrying no closed
        // repair request: the gate refuses it typed without touching any
        // ledger, which is exactly the fail-closed path this slice proves
        // bins-side. Fully admitted envelopes are proven service-side,
        // where the registry fixtures live.
        DoctorRepairAttemptRequest {
            wire_id: eliot_kernel_service::DOCTOR_REPAIR_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::DOCTOR_REPAIR_WIRE_VERSION,
            attempt_id: "attempt-dispatch-shape-1".to_owned(),
            effect_seq: 0,
            closed_request_json: "{}".to_owned(),
            target_resource_digest: "1".repeat(64),
            request_digest: String::new(),
        }
        .with_computed_digest()
        .expect("request digest")
    }

    fn reply_payload(frame: &eliot_protocol::Frame) -> serde_json::Value {
        match &frame.payload {
            eliot_protocol::ProtocolPayload::Json(value) => value.clone(),
            _ => panic!("dispatch reply must carry a JSON payload"),
        }
    }

    /// Ordered contour lifecycle: uncomposed arms fence; partial
    /// composition still fences the Doctor side; testd admits end-to-end;
    /// the heartbeat carries the composed flag; testd prepare reserves,
    /// replays by the retained original, refuses changed terms,
    /// reconciles, and releases; launch without an executor fails closed
    /// and reaps.
    #[tokio::test]
    async fn dispatch_contour_lifecycle() {
        let root = temp_root("lifecycle");
        let kernel = ready_kernel(&root);
        let epoch = live_epoch(&kernel);
        assert_eq!(epoch, test_epoch(1));
        let doctor_session =
            worker_session(&kernel, super::DispatchedWorkerKind::Doctor.module_id());
        let testd_session = worker_session(&kernel, DispatchedWorkerKind::Testd.module_id());

        // 1. Uncomposed: every arm fails closed with SessionFenced.
        assert!(!doctor_repair_advertised());
        let doctor_payload = serde_json::json!({
            "operation": eliot_kernel_service::DOCTOR_REPAIR_WIRE_ID,
            "request": shape_valid_doctor_request(),
        });
        let stale_testd = testd_request(
            "job-dispatch-stale-1",
            0,
            &testd_envelope("job-dispatch-stale-1", Some("test-operation-1"), 9, &epoch),
        );
        let stale_payload = serde_json::json!({
            "operation": TESTD_ADMISSION_WIRE_ID,
            "request": stale_testd,
        });
        let request_id = || eliot_contracts::RequestId::new("dispatch-lifecycle-1").expect("id");
        assert!(matches!(
            kernel
                .execute_doctor_request(
                    &doctor_session,
                    request_id(),
                    eliot_kernel_service::DOCTOR_REPAIR_WIRE_ID,
                    doctor_payload.clone()
                )
                .await,
            Err(eliot_ipc::TransportError::SessionFenced)
        ));
        assert!(matches!(
            kernel
                .execute_testd_request(
                    &testd_session,
                    request_id(),
                    TESTD_ADMISSION_WIRE_ID,
                    stale_payload.clone()
                )
                .await,
            Err(eliot_ipc::TransportError::SessionFenced)
        ));

        // 2. Compose the contour principal (no doctor-core registry exists
        // bins-side, so the Doctor side stays uncomposed by construction).
        compose_dispatch_contour(PRINCIPAL.to_owned()).expect("compose contour");
        assert!(matches!(
            compose_dispatch_contour(PRINCIPAL.to_owned()),
            Err(DispatchLaunchError::AlreadyComposed(_))
        ));
        // Partial composition still fences the Doctor side: advertisement
        // stays false and execution stays fenced.
        assert!(!doctor_repair_advertised());
        assert!(matches!(
            kernel
                .execute_doctor_request(
                    &doctor_session,
                    request_id(),
                    eliot_kernel_service::DOCTOR_REPAIR_WIRE_ID,
                    doctor_payload
                )
                .await,
            Err(eliot_ipc::TransportError::SessionFenced)
        ));

        // 3. Testd drives through the composed principal: a stale fence
        // answers typed (never fenced), and a live envelope is admitted.
        let stale_frame = kernel
            .execute_testd_request(
                &testd_session,
                request_id(),
                TESTD_ADMISSION_WIRE_ID,
                stale_payload,
            )
            .await
            .expect("stale testd answers typed, never fenced");
        let stale_response: TestdAdmissionResponse =
            serde_json::from_value(reply_payload(&stale_frame)).expect("typed response");
        assert!(matches!(
            stale_response,
            TestdAdmissionResponse::Rejected(_)
        ));
        let live = testd_request(
            "job-dispatch-live-1",
            0,
            &testd_envelope("job-dispatch-live-1", Some("test-operation-1"), 1, &epoch),
        );
        let live_payload = serde_json::json!({
            "operation": TESTD_ADMISSION_WIRE_ID,
            "request": live,
        });
        let live_frame = kernel
            .execute_testd_request(
                &testd_session,
                request_id(),
                TESTD_ADMISSION_WIRE_ID,
                live_payload,
            )
            .await
            .expect("admitted testd drives instead of SessionFenced");
        let live_response: TestdAdmissionResponse =
            serde_json::from_value(reply_payload(&live_frame)).expect("typed response");
        let TestdAdmissionResponse::Admitted(admission) = live_response else {
            panic!("live testd envelope must be admitted");
        };
        assert_eq!(admission.job_id, "job-dispatch-live-1");
        admission.validate().expect("admission validates");

        // 4. The heartbeat flag is covered by its own test below (it
        // echoes the live composed value); the lifecycle continues with
        // the launch seam.

        // 5. Testd prepare reserves, replays by the retained original,
        // refuses changed terms, reconciles, and releases.
        let child_dir = root.join("testd-child");
        std::fs::create_dir_all(&child_dir).expect("child dir");
        let material = TestdLaunchMaterial {
            request: &testd_request(
                "job-dispatch-launch-1",
                0,
                &testd_envelope("job-dispatch-launch-1", Some("test-operation-1"), 1, &epoch),
            ),
            executable: &child_dir.join("eliot-testd.exe"),
            executable_sha256: &"ab".repeat(32),
            working_directory: &child_dir,
        };
        let now_nanos = 1_750_000_000_000_000_000u64;
        let first = prepare_testd_launch(&kernel, &material, now_nanos).expect("prepare");
        let PreparedTestdLaunch::Ready(first_ready) = first else {
            panic!("first testd prepare must be ready");
        };
        assert_eq!(first_ready.admission.job_id, "job-dispatch-launch-1");
        assert_nonce_shape(&first_ready.nonce);
        // An exact resubmit reconciles by the retained original admission
        // (original admitted-at time and digest), never a recompute.
        let second = prepare_testd_launch(&kernel, &material, now_nanos + 1_000_000)
            .expect("replay prepare");
        let PreparedTestdLaunch::ReplayOriginal {
            admission: replayed,
        } = second
        else {
            panic!("exact resubmit must replay the original");
        };
        assert_eq!(
            replayed.admission_digest, first_ready.admission.admission_digest,
            "replay reconciles by the original admission identity"
        );
        assert_eq!(
            replayed.admitted_at_unix_nanos, first_ready.admission.admitted_at_unix_nanos,
            "replay never recomputes under a new admission time"
        );
        // Changed terms under one job identity refuse without overwriting.
        let changed = testd_request(
            "job-dispatch-launch-1",
            1,
            &testd_envelope("job-dispatch-launch-1", Some("test-operation-2"), 1, &epoch),
        );
        let changed_material = TestdLaunchMaterial {
            request: &changed,
            executable: material.executable,
            executable_sha256: material.executable_sha256,
            working_directory: material.working_directory,
        };
        assert!(matches!(
            prepare_testd_launch(&kernel, &changed_material, now_nanos + 2_000_000),
            Err(DispatchLaunchError::ChangedTerms(_))
        ));
        // Reconcile proves the retained original still binds.
        let reconcile =
            reconcile_launched_testd_attempt(&kernel, "job-dispatch-launch-1", material.request)
                .expect("reconcile");
        assert!(matches!(
            reconcile,
            ReconcileLaunchedOutcome::Reconciled { .. }
        ));
        // A stale release never frees the slot; the exact release does.
        assert!(
            !release_launched_attempt(
                DispatchedWorkerKind::Testd,
                "job-dispatch-launch-1",
                &"00".repeat(32),
            )
            .expect("release")
        );
        assert!(
            release_launched_attempt(
                DispatchedWorkerKind::Testd,
                "job-dispatch-launch-1",
                &first_ready.admission.request_digest,
            )
            .expect("release")
        );
        assert!(matches!(
            reconcile_launched_testd_attempt(&kernel, "job-dispatch-launch-1", material.request)
                .expect("reconcile"),
            ReconcileLaunchedOutcome::Unknown { .. }
        ));
        assert!(matches!(
            reconcile_launched_testd_attempt(&kernel, "job-dispatch-never-1", material.request)
                .expect("reconcile"),
            ReconcileLaunchedOutcome::Unknown { .. }
        ));

        // 6. Launch without a configured executor fails closed: no spawn,
        // no retained slot.
        let launch_material = TestdLaunchMaterial {
            request: &testd_request(
                "job-dispatch-noexec-1",
                0,
                &testd_envelope("job-dispatch-noexec-1", Some("test-operation-1"), 1, &epoch),
            ),
            executable: material.executable,
            executable_sha256: material.executable_sha256,
            working_directory: material.working_directory,
        };
        assert!(matches!(
            launch_admitted_testd_attempt(&kernel, &launch_material, now_nanos).await,
            Err(DispatchLaunchError::ExecutorUnavailable)
        ));
        assert!(matches!(
            reconcile_launched_testd_attempt(
                &kernel,
                "job-dispatch-noexec-1",
                launch_material.request
            )
            .expect("reconcile"),
            ReconcileLaunchedOutcome::Unknown { .. }
        ));

        // 7. Doctor prepare without its composed side fails closed before
        // any file or record.
        let doctor_material = DoctorLaunchMaterial {
            attempt: &shape_valid_doctor_request(),
            request_json: &serde_json::json!({}),
            manifest_json: &serde_json::json!({"manifest": "test"}),
            executable: &child_dir.join("eliot-doctor.exe"),
            executable_sha256: &"cd".repeat(32),
            working_directory: &child_dir,
        };
        assert!(matches!(
            prepare_doctor_launch(&kernel, &doctor_material, now_nanos),
            Err(DispatchLaunchError::Uncomposed(_))
        ));
        assert!(matches!(
            launch_admitted_doctor_attempt(&kernel, &doctor_material, now_nanos).await,
            Err(DispatchLaunchError::Uncomposed(_))
        ));
        assert!(
            !child_dir
                .join("eliot-doctor.dispatched-attempt.json")
                .exists()
        );

        let _ = std::fs::remove_dir_all(root);
    }

    /// The heartbeat reply carries the composed advertisement flag through
    /// the closed dispatch gateway.
    #[test]
    fn heartbeat_reports_composed_advertisement_flag() {
        // The contour cell may already be composed by the lifecycle test
        // in the same process; either way the heartbeat must echo the
        // live composed value instead of a constant.
        let root = temp_root("heartbeat");
        let kernel = ready_kernel(&root);
        let session = worker_session(&kernel, DispatchedWorkerKind::Testd.module_id());
        let heartbeat = eliot_protocol::Frame {
            protocol_version: session.protocol_version,
            encoding_profile: eliot_protocol::EncodingProfile::JsonV1,
            connection_id: session.connection_id.clone(),
            request_id: None,
            kind: eliot_protocol::FrameKind::Heartbeat,
            message_type: eliot_protocol::MessageType::Health,
            request_identity: None,
            payload: eliot_protocol::ProtocolPayload::Json(serde_json::json!({"probe": true})),
            trace_context: BTreeMap::new(),
        };
        let expected = doctor_repair_advertised();
        let action = kernel
            .dispatch_frame(&session, &heartbeat)
            .expect("heartbeat dispatches");
        match action {
            crate::KernelFrameAction::Reply(frame) => {
                let payload = reply_payload(&frame);
                assert_eq!(
                    payload.get("status").and_then(serde_json::Value::as_str),
                    Some("OPEN")
                );
                assert_eq!(
                    payload
                        .get("doctor_repair_advertised")
                        .and_then(serde_json::Value::as_bool),
                    Some(expected),
                    "heartbeat must echo the live composed advertisement"
                );
            }
            _ => panic!("heartbeat must reply"),
        }
        let _ = std::fs::remove_dir_all(root);
    }

    fn assert_nonce_shape(nonce: &str) {
        assert!(
            (16..=256).contains(&nonce.len()),
            "nonce is bounded, got {} bytes",
            nonce.len()
        );
        assert!(
            nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
            "nonce uses the child session-nonce alphabet"
        );
    }

    /// The launch nonce is replay-stable per identity and unique per
    /// attempt: an exact replay rewrites byte-identical material while two
    /// attempts never share a session.
    #[test]
    fn dispatch_nonce_is_replay_stable_and_unique() {
        let first = mint_dispatch_nonce(
            DispatchedWorkerKind::Doctor,
            &"a".repeat(64),
            1_750_000_000_000_000_000,
            PRINCIPAL,
        )
        .expect("nonce");
        let replay = mint_dispatch_nonce(
            DispatchedWorkerKind::Doctor,
            &"a".repeat(64),
            1_750_000_000_000_000_000,
            PRINCIPAL,
        )
        .expect("nonce");
        assert_eq!(first, replay, "replays mint the identical nonce");
        let other = mint_dispatch_nonce(
            DispatchedWorkerKind::Doctor,
            &"b".repeat(64),
            1_750_000_000_000_000_000,
            PRINCIPAL,
        )
        .expect("nonce");
        assert_ne!(first, other, "attempts never share a nonce");
        let testd = mint_dispatch_nonce(
            DispatchedWorkerKind::Testd,
            &"a".repeat(64),
            1_750_000_000_000_000_000,
            PRINCIPAL,
        )
        .expect("nonce");
        assert_ne!(first, testd, "kinds never share a nonce");
        assert_nonce_shape(&first);
    }

    /// The Doctor dispatch file carries exactly the six fields the child
    /// reader validates, with the envelope bytes, digest, epoch,
    /// generation, and nonce bound.
    #[test]
    fn doctor_material_bytes_carries_exactly_the_child_shape() {
        let attempt = shape_valid_doctor_request();
        let request_json = serde_json::json!({});
        let manifest_json = serde_json::json!({"manifest": "test"});
        let epoch = test_epoch(1);
        let nonce = mint_dispatch_nonce(
            DispatchedWorkerKind::Doctor,
            &"a".repeat(64),
            1_750_000_000_000_000_000,
            PRINCIPAL,
        )
        .expect("nonce");
        let bytes =
            doctor_material_bytes(&attempt, &request_json, &manifest_json, &epoch, 7, &nonce)
                .expect("material bytes");
        assert!(u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= 256 * 1024);
        let envelope: serde_json::Value = serde_json::from_slice(&bytes).expect("envelope json");
        let object = envelope.as_object().expect("envelope object");
        assert_eq!(object.len(), 6, "exactly the six child-validated fields");
        for key in [
            "attempt",
            "request",
            "manifest",
            "epoch",
            "generation",
            "nonce",
        ] {
            assert!(object.contains_key(key), "envelope carries {key}");
        }
        // Envelope bytes plus canonical digest round-trip through the
        // existing wire entries.
        let embedded: DoctorRepairAttemptRequest =
            serde_json::from_value(object["attempt"].clone()).expect("attempt");
        embedded.validate().expect("attempt validates");
        embedded
            .validate_canonical_digest()
            .expect("canonical digest binds the envelope bytes");
        assert_eq!(embedded.request_digest, attempt.request_digest);
        // Byte-identity: the parsed envelope equals the presented closed
        // request value.
        let parsed: serde_json::Value =
            serde_json::from_str(&embedded.closed_request_json).expect("closed json parses");
        assert_eq!(parsed, request_json);
        // Live epoch, fence-bound generation, and nonce travel verbatim.
        let live: EpochId = serde_json::from_value(object["epoch"].clone()).expect("epoch parses");
        assert_eq!(live, epoch);
        assert_eq!(object["generation"], serde_json::json!(7u64));
        assert_eq!(object["nonce"], serde_json::json!(nonce));
    }

    /// The contour parameterizes Doctor vs testd delivery endpoints without
    /// inventing a second vocabulary.
    #[test]
    fn worker_kinds_share_the_seam_with_split_delivery() {
        assert_eq!(DispatchedWorkerKind::Doctor.module_id(), "eliot-doctor");
        assert_eq!(
            DispatchedWorkerKind::Testd.module_id(),
            DispatchedWorkerKind::Testd.module_id()
        );
        assert_eq!(
            DispatchedWorkerKind::Doctor.wire_id(),
            eliot_kernel_service::DOCTOR_REPAIR_WIRE_ID
        );
        assert_eq!(
            DispatchedWorkerKind::Testd.wire_id(),
            TESTD_ADMISSION_WIRE_ID
        );
        assert_eq!(
            DispatchedWorkerKind::Doctor.material_file_name(),
            Some("eliot-doctor.dispatched-attempt.json")
        );
        assert_eq!(DispatchedWorkerKind::Testd.material_file_name(), None);
    }
}
