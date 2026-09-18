//! Kernel dispatch-launch contour for one-shot Doctor, testd, native-worker,
//! and Dreamer workers.
//!
//! DISPATCH-CONTOUR-2 Slice B (issues #461 and #22) plus DISPATCH-CAUSE-FIX:
//! Kernel-side launch of admitted Doctor, testd, and native-worker attempts
//! through the admitted
//! [`ProcessExecutionGateway`](crate::process_execution::ProcessExecutionGateway),
//! plus the composed front-door owner the dispatch arms admit through.
//! T12-09 (issue #702) wires the Dreamer arm through the same contour:
//! admitted Dreamer launch through the admitted process executor with
//! protected dispatch material, launch-once lineage, and worker-side
//! `LeaseExact` claim fencing (see [`dreamer_dispatch_launch`]).
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
//!   nor the generation is ever taken from the request envelope. The native
//!   worker admits through live service authority plus the ORS claim table
//!   (`KernelService::admit_native_worker_claim`, existing vocabulary).
//! * [`launch_admitted_doctor_attempt`] admits the attempt, then launches
//!   the real `eliot-doctor` binary through the admitted process gateway:
//!   it mints the I7.5/I15.2 launch nonce, writes the session-bound attempt
//!   material plus the launch grant to the protected file the child already
//!   reads, builds the child process admission with an empty argv (never
//!   argv or env material), retains the path proof, starts through the
//!   gateway, and retains the launch record keyed by the original attempt
//!   identity. [`launch_admitted_testd_attempt`] reuses the same seam shape
//!   for `eliot-testd`, writing `eliot-testd.admitted-attempt.json` plus the
//!   same grant object through [`write_material_file`].
//!   [`launch_admitted_native_worker_attempt`] reuses the same seam shape
//!   for `eliot-native-worker`, writing
//!   `eliot-native-worker.admitted-claim.json` plus the same grant object.
//! * [`trigger_admitted_doctor_launch`] is the T6-D2 front-door trigger:
//!   pre-admit through the composed gate, derive the launch material from
//!   the composed registry (admitted manifest revision plus installed
//!   executable digest — never caller bytes), then delegate to the launch
//!   seam above. The absolute child anchor arrives from the owning
//!   composition ([`DoctorChildBinding`]).
//! * a launched-but-unreconciled attempt reconciles by its original
//!   identity through [`reconcile_launched_doctor_attempt`] /
//!   [`reconcile_launched_testd_attempt`] /
//!   [`reconcile_launched_native_worker_attempt`]: the durable admission
//!   digest is compared, never recomputed under a new id, and no second
//!   child is spawned for an outstanding launch.
//!
//! Delivery contract (I7.5/I15.2): each launched child receives a launch
//! nonce plus a launch grant delivered over the protected dispatch file
//! next to its executable — never via the command line, stdin, or the
//! environment. The Doctor file carries exactly what
//! `bins/eliot-doctor/src/dispatched_material.rs::read_dispatched_material_from`
//! validates (envelope bytes plus canonical digest, parsed closed request
//! with byte-identity, admitted manifest revision, live epoch, fence-bound
//! generation, well-formed nonce) plus the additive `grant` object
//! (`grant_digest`, `authority_epoch`, `fence_generation`, `fence_nonce`,
//! `idempotency_key`, `expires_at`) the child uses to construct its own
//! local `DispatchPermitAuthority` (broker pattern). The nonce and grant
//! are deterministic per (attempt identity, durable admission time,
//! composed principal), so an exact replay rewrites byte-identical material
//! and reconciles by the original identity instead of minting a second
//! session. Testd and native-worker files carry the same `grant` object
//! alongside their admitted attempt/claim.
//!
//! Testd delivery (DISPATCH-CAUSE-FIX): the contour now writes
//! `eliot-testd.admitted-attempt.json` (request + envelope + admission +
//! epoch + generation + nonce + grant) through the existing
//! `write_material_file` helper; the child-side reader lands with Writer-T.
//!
//! Native-worker delivery (DISPATCH-CAUSE-FIX): the contour writes
//! `eliot-native-worker.admitted-claim.json` (request + receipt + epoch +
//! generation + nonce + grant) through the same helper; the durable ORS
//! `NativeWorkerClaimRecord` stays the reconcile authority (see
//! `native_worker_lifecycle_route::NATIVE_WORKER_CLAIM_OPERATION`).
//!
//! Dreamer delivery (T12-09, Implements #702): the contour records one
//! launch lineage for the exact queued job/attempt and writes
//! `eliot-dreamer.admitted-job.json` (job/attempt/revision/scope/fence +
//! epoch + generation + nonce + grant) through the same helper; the durable
//! Store Dreamer ledger (K1 gateway) stays the terminal authority, while the
//! lineage table enforces launch-once per job identity and fences the
//! worker-side `LeaseExact` claim. Material, lineage, and validation live in
//! [`dreamer_dispatch_launch`]; the arm below wires them to this contour.
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
    KernelService, KernelServiceError, NATIVE_WORKER_CLAIM_WIRE_ID, NativeWorkerClaimReceipt,
    NativeWorkerClaimRequest, NativeWorkerClaimResponse, TestdAdmission,
    TestdAdmissionAttemptRequest, TestdAdmissionEnvelope, TestdAdmissionResponse,
    advertise_doctor_repair, advertise_testd_admission_when_composed, handle_doctor_repair_attempt,
    handle_testd_admission_attempt, reconcile_testd_admission,
};
use eliot_ors::{
    DoctorAttemptRecord, DoctorEffectRecord, DoctorLedgerError, DoctorRecoveryLedger,
    NativeWorkerClaimRecord, OperationIdentity,
};
use eliot_process::OperationId;
use eliot_protocol::dreamer_job::{DurableJobResponse, JobState};
use serde::{Deserialize, Serialize};

/// Protected Dreamer dispatch-launch material and launch lineage (T12-09).
///
/// Sibling-file seam: the Dreamer envelope, nonce, validation, and
/// launch-once lineage table live here so the contour core above stays
/// untouched; the Dreamer arm below wires them to the admitted executor.
/// Declared with an explicit path so no neighbouring composition root needs
/// to change for this slice.
#[path = "dreamer_dispatch_launch.rs"]
pub(crate) mod dreamer_dispatch_launch;

use dreamer_dispatch_launch::{
    DreamerChildBinding, DreamerDispatchedEnvelope, DreamerLaunchKeys, DreamerLaunchPhase,
    DreamerLaunchRecord, DreamerLeaseExpectation, DreamerMaterialError, DreamerReconcileOutcome,
    DreamerReserveOutcome,
};

use super::doctor_recovery_ledger::KernelDoctorRecoveryLedger;
use super::front_door_session::{DOCTOR_MODULE_ID, NATIVE_MODULE_ID, TESTD_MODULE_ID};
use super::runtime_identity::stable_owner_principal_digest;
use super::{
    ActionLeaseRef, EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation,
    ImageId, JobId, KernelComposition, ProcessExecutionAdmissionRequest, ProcessExecutionError,
    ProcessIntent, ProcessOwnerBinding, ProcessStartReceipt, ProcessTreeId, ResourceLimits,
    SessionId,
};

/// One-shot worker kind served by the dispatch-launch contour.
///
/// The contour is built once and parameterized by this enum: Doctor, testd,
/// the native worker, and Dreamer share admission-through-composed-owner
/// (Doctor via its ledger port, testd stateless via the principal owner,
/// native via the ORS claim table through
/// `KernelService::admit_native_worker_claim`, Dreamer via its durable
/// `QUEUED` ledger response plus live authority through
/// [`prepare_dreamer_launch`]), nonce minting, spawn through the admitted
/// gateway, launch retention, and reconcile-by-original-identity. They
/// differ only in the delivery endpoint the child already reads (see
/// [`Self::material_file_name`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchedWorkerKind {
    /// The one-shot Doctor repair worker (`eliot-doctor`).
    Doctor,
    /// The one-shot testd admission worker (`eliot-testd`).
    Testd,
    /// The one-shot native-worker claim worker (`eliot-native-worker`).
    NativeWorker,
    /// The one-shot Dreamer job worker (`eliot-dreamer`, T12-09).
    Dreamer,
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
            Self::NativeWorker => NATIVE_MODULE_ID,
            Self::Dreamer => dreamer_dispatch_launch::DREAMER_MODULE_ID,
        }
    }

    /// Returns the stable front-door wire identity admitted for the worker.
    #[must_use]
    pub const fn wire_id(self) -> &'static str {
        match self {
            Self::Doctor => eliot_kernel_service::DOCTOR_REPAIR_WIRE_ID,
            Self::Testd => eliot_kernel_service::TESTD_ADMISSION_WIRE_ID,
            Self::NativeWorker => NATIVE_WORKER_CLAIM_WIRE_ID,
            Self::Dreamer => super::dreamer_job_dispatch::DREAMER_JOB_WIRE_ID,
        }
    }

    /// Returns the dispatch material file name the child already reads.
    ///
    /// `Some` for Doctor: the exact
    /// `bins/eliot-doctor/src/dispatched_material.rs::DISPATCHED_MATERIAL_FILE_NAME`
    /// literal the child reader derives from its executable directory
    /// (`current_exe`, never argv/stdin/env). Duplicated here because the
    /// Kernel delivery half owns its write path; the child reader stays the
    /// authority for the value.
    ///
    /// `Some` for testd: `eliot-testd.admitted-attempt.json` next to the
    /// child executable (DISPATCH-CAUSE-FIX: the testd child reader lands
    /// with Writer-T; this contour now writes through the existing
    /// `write_material_file` helper instead of stopping at the spawn
    /// boundary).
    ///
    /// `Some` for the native worker: the exact
    /// `bins/eliot-native-worker/src/lib.rs::ADMITTED_MATERIAL_FILE_NAME`
    /// literal (`eliot-native-worker.admitted-claim.json`) the child reader
    /// derives from its executable directory. Duplicated here because the
    /// Kernel delivery half owns its write path; the child reader stays the
    /// authority for the value. No other writer exists on this base (the
    /// residual in `admitted_material` names this Kernel half as the gap),
    /// so this seam is the single writer.
    ///
    /// `Some` for Dreamer (T12-09): the exact
    /// [`DREAMER_MATERIAL_FILE_NAME`](dreamer_dispatch_launch::DREAMER_MATERIAL_FILE_NAME)
    /// literal the MGR02 child reader derives from its executable
    /// directory. The child reader stays the authority for the value.
    #[must_use]
    pub const fn material_file_name(self) -> Option<&'static str> {
        match self {
            Self::Doctor => Some("eliot-doctor.dispatched-attempt.json"),
            Self::Testd => Some("eliot-testd.admitted-attempt.json"),
            Self::NativeWorker => Some("eliot-native-worker.admitted-claim.json"),
            Self::Dreamer => Some(dreamer_dispatch_launch::DREAMER_MATERIAL_FILE_NAME),
        }
    }

    /// Returns the nonce prefix distinguishing the worker's launch nonces.
    #[must_use]
    const fn nonce_prefix(self) -> &'static str {
        match self {
            Self::Doctor => "doctor-dispatch",
            Self::Testd => "testd-dispatch",
            Self::NativeWorker => "native-worker-dispatch",
            Self::Dreamer => dreamer_dispatch_launch::DREAMER_NONCE_PREFIX,
        }
    }

    /// Returns the process-operation prefix for the worker's child admission.
    #[must_use]
    const fn operation_prefix(self) -> &'static str {
        match self {
            Self::Doctor => "doctor-launch",
            Self::Testd => "testd-launch",
            Self::NativeWorker => "native-worker-launch",
            Self::Dreamer => dreamer_dispatch_launch::DREAMER_OPERATION_PREFIX,
        }
    }
}

/// Kernel-issued launch-grant material for one dispatched child.
///
/// This is the Kernel half of the merged User Broker pattern
/// (`bins/eliot-user-broker/src/lib.rs:120-216`): the child constructs its
/// own local `DispatchPermitAuthority` via `activate`, then builds its
/// single `ProcessRequest` in-process via `FencingToken::new` +
/// `PermitIssuance::new` + `DispatchValidationContext::new` +
/// `ProcessRequest::new` through `WindowsProcessExecutor::new(authority)`.
/// The Kernel never sends the sealed `ProcessRequest` (which is
/// `Serialize`-only, never `Deserialize`); it sends only these six
/// launch-grant fields, all derived Kernel-side from live authority plus
/// the durable admission identity. No argv/env material, no executable
/// bytes, no minted ledger/registry/principal.
///
/// JSON shape (all three workers share this exact object under the
/// `grant` key; field names are the contract for Writer-D/Writer-T and the
/// native child):
/// ```json
/// {
///   "grant_digest": "lowercase-sha256-hex",
///   "authority_epoch": {"lineage_id": "uuid", "sequence": 1},
///   "fence_generation": 1,
///   "fence_nonce": "native-worker-launch-fence-<short>",
///   "idempotency_key": "native-worker-launch-lease-<short>",
///   "expires_at": 1750000060000
/// }
/// ```
/// * `grant_digest: String` — lowercase SHA-256 over the canonical grant
///   binding (identity digest + epoch + generation + fence nonce +
///   idempotency key + expiry); carried as the child-side `one_shot_nonce`
///   plus the `launch-grant` revision-head value (both require opaque/hex
///   shape, which hex satisfies).
/// * `authority_epoch: EpochId` — canonical lineage-aware epoch
///   (`eliot_contracts::EpochId`); the child calls
///   `FencingToken::new(authority_epoch, Generation, fence_nonce)`.
/// * `fence_generation: u64` — non-zero live activation generation; the
///   child calls `Generation::new(fence_generation)`.
/// * `fence_nonce: String` — deterministic per-identity fence nonce
///   (`<operation_prefix>-fence-<short_identity>`); the child passes it to
///   `FencingToken::new`.
/// * `idempotency_key: String` — deterministic per-identity lease
///   (`<operation_prefix>-lease-<short_identity>`); the child calls
///   `ActionLeaseRef::new(idempotency_key)`.
/// * `expires_at: u64` — Unix milliseconds
///   (`admitted_at_ms.saturating_add(60_000)`); the child passes it as
///   `PermitIssuance::new(..., issued_at = now_ms, expires_at, ...)`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchGrant {
    /// Lowercase SHA-256 binding the grant fields plus the admission
    /// identity digest.
    pub grant_digest: String,
    /// Live authority epoch bound at admission (canonical `EpochId`).
    pub authority_epoch: EpochId,
    /// Live activation generation bound at admission (non-zero).
    pub fence_generation: u64,
    /// Deterministic per-identity fence nonce for `FencingToken::new`.
    pub fence_nonce: String,
    /// Deterministic per-identity lease for `ActionLeaseRef::new`.
    pub idempotency_key: String,
    /// Grant expiry in Unix milliseconds for `PermitIssuance::new`.
    pub expires_at: u64,
}

impl DispatchGrant {
    /// Validates the grant shape through the exact broker types the child
    /// uses: `FencingToken::new`, `ActionLeaseRef::new`, plus digest bounds.
    /// Returns the fence and lease the child would build (the child
    /// rebuilds them itself; this only proves the material is well-formed).
    pub fn validate_for_child(
        &self,
    ) -> Result<(FencingToken, ActionLeaseRef), DispatchLaunchError> {
        require_digest(
            &self.grant_digest,
            "grant digest must be a lowercase SHA-256 digest",
        )?;
        if self.fence_generation == 0 {
            return Err(DispatchLaunchError::InvalidMaterial(
                "grant fence generation must be non-zero".to_owned(),
            ));
        }
        if self.expires_at == 0 {
            return Err(DispatchLaunchError::InvalidMaterial(
                "grant expiry must be non-zero".to_owned(),
            ));
        }
        let generation = Generation::new(self.fence_generation).map_err(gate_error)?;
        let fence = FencingToken::new(
            self.authority_epoch.clone(),
            generation,
            self.fence_nonce.clone(),
        )
        .map_err(gate_error)?;
        let lease = ActionLeaseRef::new(self.idempotency_key.clone()).map_err(gate_error)?;
        Ok((fence, lease))
    }
}

/// Builds the deterministic launch grant for one admitted identity.
///
/// Inputs are all Kernel-side live authority plus the durable admission
/// identity: `identity_digest` is the admission-bound digest
/// (`attempt_digest` for Doctor, `request_digest` for testd,
/// `binding_digest` for native — all lowercase SHA-256 by contract),
/// `authority_epoch`/`generation` are the live values bound at admission,
/// and `admitted_at_unix_nanos` is the durable admission time (for native,
/// `admitted_at_unix_ms * 1_000_000`). Derivations are replay-stable, so an
/// exact replay rebuilds byte-identical grant bytes and reconciles by the
/// original identity instead of minting a second grant.
fn dispatch_grant_for(
    kind: DispatchedWorkerKind,
    identity_digest: &str,
    authority_epoch: &EpochId,
    generation: Generation,
    admitted_at_unix_nanos: u64,
) -> Result<DispatchGrant, DispatchLaunchError> {
    require_digest(
        identity_digest,
        "grant identity digest must be a lowercase SHA-256 digest",
    )?;
    if admitted_at_unix_nanos == 0 {
        return Err(DispatchLaunchError::InvalidMaterial(
            "grant admission time must be non-zero".to_owned(),
        ));
    }
    let short = short_identity(identity_digest)?.to_owned();
    let fence_nonce = format!("{}-fence-{short}", kind.operation_prefix());
    let idempotency_key = format!("{}-lease-{short}", kind.operation_prefix());
    let admitted_at_ms = admitted_at_unix_nanos / 1_000_000;
    let expires_at = admitted_at_ms.saturating_add(60_000);
    if expires_at == 0 {
        return Err(DispatchLaunchError::InvalidMaterial(
            "grant expiry must be non-zero".to_owned(),
        ));
    }
    // Canonical digest binding: identity + epoch + generation + fence +
    // lease + expiry. The epoch serializes via its canonical JSON shape;
    // everything else is fixed-order text, so equal logical grants hash
    // identically on both sides of the boundary.
    let epoch_json = serde_json::to_string(authority_epoch)
        .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    let mut material = String::with_capacity(256);
    material.push_str(identity_digest);
    material.push('|');
    material.push_str(&epoch_json);
    material.push('|');
    material.push_str(&generation.get().to_string());
    material.push('|');
    material.push_str(&fence_nonce);
    material.push('|');
    material.push_str(&idempotency_key);
    material.push('|');
    material.push_str(&expires_at.to_string());
    let grant_digest = super::sha256_hex(material.as_bytes());
    let grant = DispatchGrant {
        grant_digest,
        authority_epoch: authority_epoch.clone(),
        fence_generation: generation.get(),
        fence_nonce,
        idempotency_key,
        expires_at,
    };
    // Prove the material satisfies the exact broker constructors before it
    // is ever written: the child will call these same entries.
    grant.validate_for_child()?;
    Ok(grant)
}

/// Owner-side mirrored native-worker dispatch derivation domain.
///
/// Byte-identical to
/// `bins/eliot-native-worker/src/dispatch_authority.rs::DISPATCH_DERIVATION_DOMAIN`.
/// The Kernel (owner) runs the identical forward computation so it can publish
/// the matching T9-02 executable join (`process_invocation_digest`): the child
/// derives its one-shot permit deterministically because fresh entropy could
/// never close the join gate (see the child module docs).
pub const NATIVE_WORKER_DISPATCH_DERIVATION_DOMAIN: &str = "eliot-native-worker-dispatch/v1";
/// Owner-side authority-identity prefix, byte-identical to the child
/// (`"native-worker-dispatch-authority-" + hex(SHA-256("authority:" + base))`).
pub const NATIVE_WORKER_DISPATCH_AUTHORITY_PREFIX: &str = "native-worker-dispatch-authority-";
/// Owner-side single revision head name, byte-identical to the child
/// (`LAUNCH_GRANT_HEAD = "launch-grant"`).
pub const NATIVE_WORKER_DISPATCH_LAUNCH_GRANT_HEAD: &str = "launch-grant";

/// Owner-side mirrored dispatch derivation material for one admitted claim.
///
/// Byte-identical to the child
/// (`bins/eliot-native-worker/src/dispatch_authority.rs:209-249,277-284`):
/// ```text
/// base      = ["eliot-native-worker-dispatch/v1", claim_id, operation_id,
///              worker_generation, authority_epoch_json, launch_nonce]
/// key       = SHA-256("key:" + base_json)
/// authority = "native-worker-dispatch-authority-" + hex(SHA-256("authority:" + base_json))
/// heads     = {"launch-grant": hex(SHA-256("head:" + base_json))}
/// nonce     = the claim-bound launch nonce (the join `launch_nonce`)
/// ```
/// No wall-clock enters the permit: freshness comes from the grant window
/// (`DispatchGrant::expires_at` over the receipt admission time), never from
/// `now` at derivation time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeWorkerDispatchDerivation {
    /// Canonical derivation base JSON (the exact child `derivation_base`).
    pub base_json: String,
    /// Lowercase hex of `SHA-256("key:" + base)` (the child `KernelDispatchKey` bytes).
    pub key_hex: String,
    /// Child-identical authority identity string.
    pub authority_id: String,
    /// Lowercase hex of `SHA-256("head:" + base)` (the `launch-grant` head value).
    pub head_digest: String,
}

/// Builds the owner-side dispatch derivation from typed admitted material.
///
/// `authority_epoch` serializes via its canonical JSON shape exactly like the
/// child (`serde_json::to_value(&claim.authority_epoch)` embedded in the base
/// array), so equal logical claims hash identically on both sides.
pub fn native_worker_dispatch_derivation(
    claim_id: &str,
    operation_id: &str,
    worker_generation: u64,
    authority_epoch: &EpochId,
    launch_nonce: &str,
) -> Result<NativeWorkerDispatchDerivation, DispatchLaunchError> {
    let epoch_json = serde_json::to_value(authority_epoch)
        .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    native_worker_dispatch_derivation_from_epoch_json(
        claim_id,
        operation_id,
        worker_generation,
        &epoch_json,
        launch_nonce,
    )
}

/// Builds the owner-side dispatch derivation from an already-canonical epoch
/// JSON value (the exact child input shape: the `authority_epoch_json` Value
/// the child embeds in its base array).
pub fn native_worker_dispatch_derivation_from_epoch_json(
    claim_id: &str,
    operation_id: &str,
    worker_generation: u64,
    authority_epoch_json: &serde_json::Value,
    launch_nonce: &str,
) -> Result<NativeWorkerDispatchDerivation, DispatchLaunchError> {
    if claim_id.trim().is_empty()
        || operation_id.trim().is_empty()
        || launch_nonce.trim().is_empty()
    {
        return Err(DispatchLaunchError::InvalidMaterial(
            "dispatch derivation identities must be non-blank".to_owned(),
        ));
    }
    let base_json = serde_json::to_string(&serde_json::json!([
        NATIVE_WORKER_DISPATCH_DERIVATION_DOMAIN,
        claim_id,
        operation_id,
        worker_generation,
        authority_epoch_json,
        launch_nonce,
    ]))
    .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    let key_hex = dispatch_tagged_hex("key", &base_json);
    let authority_id = format!(
        "{NATIVE_WORKER_DISPATCH_AUTHORITY_PREFIX}{}",
        dispatch_tagged_hex("authority", &base_json)
    );
    let head_digest = dispatch_tagged_hex("head", &base_json);
    Ok(NativeWorkerDispatchDerivation {
        base_json,
        key_hex,
        authority_id,
        head_digest,
    })
}

/// Hashes one domain-separated derivation input exactly like the child
/// (`tagged_hash`: `SHA-256(tag + ":" + base_json)`, lowercase hex).
fn dispatch_tagged_hex(tag: &str, base_json: &str) -> String {
    let mut material =
        String::with_capacity(tag.len().saturating_add(1).saturating_add(base_json.len()));
    material.push_str(tag);
    material.push(':');
    material.push_str(base_json);
    super::sha256_hex(material.as_bytes())
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
/// (attempt digest for Doctor, job identity for testd, claim identity for
/// the native worker).
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
    /// always `None` for Doctor (the durable ledger is the authority) and
    /// for the native worker (which retains its receipt below).
    testd_admission: Option<TestdAdmission>,
    /// Retained original native-worker claim receipt for
    /// reconcile-by-identity; always `None` for Doctor/Testd.
    native_receipt: Option<NativeWorkerClaimReceipt>,
    /// Retained original native-worker claim request for binding checks;
    /// always `None` for Doctor/Testd.
    native_request: Option<NativeWorkerClaimRequest>,
}

/// Retained launch records. The durable attempt/effect ledger stays the
/// authority; these records only enforce launch-once per identity and carry
/// the nonce and admission digests the reconcile path compares.
#[derive(Debug, Default)]
struct LaunchRecords {
    by_identity: BTreeMap<String, LaunchRecord>,
}

/// The composed dispatch contour: the Kernel-owned principal owner, the
/// Doctor front-door state once its production ledger lands, the installed
/// testd/native-worker digests once their production sides compose, and the
/// retained launch records.
pub struct ComposedDispatchContour {
    principal_owner: String,
    doctor: Mutex<Option<DoctorFrontDoorState>>,
    testd_installed_digest: Mutex<Option<String>>,
    native_worker_installed_digest: Mutex<Option<String>>,
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
            testd_installed_digest: Mutex::new(None),
            native_worker_installed_digest: Mutex::new(None),
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

/// Composes the production Doctor front-door state from the durable
/// Kernel-owned ledger plus the installed-health-probe registry.
///
/// `installed_doctor_digest` is the installed Doctor package artifact
/// digest (lowercase SHA-256) from the installation manifest through the
/// Host injection — never minted here. A malformed digest fails closed
/// with [`DispatchLaunchError::InvalidMaterial`] before any cell is
/// touched; otherwise this delegates to [`compose_doctor_front_door`],
/// so the contour-first, non-empty-registry, and set-once rules hold
/// unchanged. This is the production caller `main` uses once the contour
/// carries the digest.
pub fn compose_production_doctor_front_door(
    ledger: Arc<KernelDoctorRecoveryLedger>,
    installed_doctor_digest: &str,
) -> Result<(), DispatchLaunchError> {
    let registry = DoctorRecipeRegistry::production_health_probe(installed_doctor_digest)
        .map_err(|error| DispatchLaunchError::InvalidMaterial(error.to_string()))?;
    compose_doctor_front_door(ledger, registry)
}

/// Composes the production testd side from its installed package artifact
/// digest (Implements #461 DISPATCH-WIRE E2E).
///
/// `installed_testd_digest` is the installed testd package artifact digest
/// (lowercase SHA-256) from the installation manifest through the Host
/// injection — never minted here. Testd admission is stateless (wire plus
/// live authority only), so no ledger composition is required: this records
/// the verified digest on the contour cell from
/// [`compose_dispatch_contour`] as the production-composed marker the
/// Kernel launch chain reads back. A malformed digest fails closed with
/// [`DispatchLaunchError::InvalidMaterial`] before any cell is touched;
/// a second composition is refused instead of replacing live authority.
/// This is the production caller `main` uses once the contour carries the
/// digest, mirroring [`compose_production_doctor_front_door`].
pub fn compose_production_testd_front_door(
    installed_testd_digest: &str,
) -> Result<(), DispatchLaunchError> {
    require_digest(
        installed_testd_digest,
        "installed testd digest must be a lowercase SHA-256 digest",
    )?;
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed(
            "compose the dispatch contour before its testd side",
        ))?;
    let mut composed = contour
        .testd_installed_digest
        .lock()
        .map_err(|_| DispatchLaunchError::Gate("testd front-door lock poisoned".to_owned()))?;
    if composed.is_some() {
        return Err(DispatchLaunchError::AlreadyComposed("testd front door"));
    }
    *composed = Some(installed_testd_digest.to_owned());
    Ok(())
}

/// Composes the production native-worker side from its installed package
/// artifact digest (Implements #461 DISPATCH-WIRE E2E).
///
/// `installed_native_worker_digest` is the installed native-worker package
/// artifact digest (lowercase SHA-256) from the installation manifest
/// through the Host injection — never minted here. Native-worker admission
/// runs through live service authority plus the ORS claim table, so no
/// ledger composition is required: this records the verified digest on the
/// contour cell from [`compose_dispatch_contour`] as the
/// production-composed marker the Kernel launch chain reads back. A
/// malformed digest fails closed with
/// [`DispatchLaunchError::InvalidMaterial`] before any cell is touched;
/// a second composition is refused instead of replacing live authority.
/// This is the production caller `main` uses once the contour carries the
/// digest, mirroring [`compose_production_doctor_front_door`].
pub fn compose_production_native_worker_front_door(
    installed_native_worker_digest: &str,
) -> Result<(), DispatchLaunchError> {
    require_digest(
        installed_native_worker_digest,
        "installed native-worker digest must be a lowercase SHA-256 digest",
    )?;
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed(
            "compose the dispatch contour before its native-worker side",
        ))?;
    let mut composed = contour.native_worker_installed_digest.lock().map_err(|_| {
        DispatchLaunchError::Gate("native-worker front-door lock poisoned".to_owned())
    })?;
    if composed.is_some() {
        return Err(DispatchLaunchError::AlreadyComposed(
            "native-worker front door",
        ));
    }
    *composed = Some(installed_native_worker_digest.to_owned());
    Ok(())
}

/// Returns whether the production testd side is composed with its installed
/// digest.
///
/// True exactly when [`compose_production_testd_front_door`] landed after
/// the contour cell; false in every other case. This is the production-side
/// marker only: [`testd_admission_advertised`] keeps its contour-cell
/// semantics unchanged, so the child advertise probe this path never
/// touches keeps failing closed exactly as before until the contour lands.
#[must_use]
pub fn testd_production_composed() -> bool {
    DISPATCH_CONTOUR.get().is_some_and(|contour| {
        contour
            .testd_installed_digest
            .lock()
            .is_ok_and(|composed| composed.is_some())
    })
}

/// Returns whether the production native-worker side is composed with its
/// installed digest.
///
/// True exactly when [`compose_production_native_worker_front_door`]
/// landed after the contour cell; false in every other case.
#[must_use]
pub fn native_worker_production_composed() -> bool {
    DISPATCH_CONTOUR.get().is_some_and(|contour| {
        contour
            .native_worker_installed_digest
            .lock()
            .is_ok_and(|composed| composed.is_some())
    })
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

/// Returns whether the Kernel currently advertises the testd admission
/// operation.
///
/// True exactly when the dispatch contour cell is composed: testd admission
/// is stateless (wire plus live authority only), so no ledger composition
/// is required — only the contour cell from [`compose_dispatch_contour`]
/// for the Kernel-owned principal. The inert
/// `TESTD_ADMISSION_ADVERTISED` default never flips in place; this path
/// flips only through the composed contour, via
/// `advertise_testd_admission_when_composed`.
#[must_use]
pub fn testd_admission_advertised() -> bool {
    let composed = DISPATCH_CONTOUR.get().is_some();
    advertise_testd_admission_when_composed(composed)
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
/// validates, plus the Kernel-issued launch grant.
///
/// The envelope object holds the wire attempt, the parsed closed request
/// (byte-identical to the envelope bytes, re-proved by the caller), the
/// admitted manifest revision, the live epoch, the fence-bound generation,
/// and the session nonce — the six fields
/// `read_dispatched_material_from` checks — plus a seventh `grant` object
/// carrying the launch-grant material the child needs to construct its own
/// local `DispatchPermitAuthority` (`grant_digest`, `authority_epoch`,
/// `fence_generation`, `fence_nonce`, `idempotency_key`, `expires_at`).
/// Every pre-existing field serializes byte-identically to before; only the
/// additive `grant` key is new (Writer-D reads the same shape). Files are
/// never read here, and nothing travels via argv, stdin, or the
/// environment.
fn doctor_material_bytes(
    attempt: &DoctorRepairAttemptRequest,
    request_json: &serde_json::Value,
    manifest_json: &serde_json::Value,
    epoch: &EpochId,
    generation: u64,
    nonce: &str,
    grant: &DispatchGrant,
) -> Result<Vec<u8>, DispatchLaunchError> {
    let envelope = serde_json::json!({
        "attempt": attempt,
        "request": request_json,
        "manifest": manifest_json,
        "epoch": epoch,
        "generation": generation,
        "nonce": nonce,
        "grant": grant,
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

/// Writes the testd dispatch file carrying the admitted attempt plus the
/// Kernel-issued launch grant.
///
/// JSON shape for Writer-T (all keys required, `deny_unknown_fields` on
/// the child side):
/// ```json
/// {
///   "request": TestdAdmissionAttemptRequest,
///   "envelope": TestdAdmissionEnvelope,
///   "admission": TestdAdmission,
///   "epoch": EpochId,
///   "generation": 1,
///   "nonce": "testd-dispatch-<hex>",
///   "grant": DispatchGrant
/// }
/// ```
/// * `request` — the full wire envelope the contour admitted
///   (`job_id`, `attempt_seq`, `closed_request_json`, digests).
/// * `envelope` — the parsed `closed_request_json`
///   (`TestdAdmissionEnvelope`: `job_id`, `operation_id`, `cancellation`,
///   `fence`); derived Kernel-side by re-parsing, never taken as extra
///   caller bytes beyond the already-admitted `request`.
/// * `admission` — the Kernel-issued receipt (`TestdAdmission`); its
///   `operation_id` is the bounded evidence handle the child maps to
///   `PresentedAdmission.evidence_ref`, and `cancelled` maps to
///   `PresentedAdmission.cancelled`.
/// * `epoch` — the live authority epoch (maps to
///   `PresentedAdmission.epoch`; never envelope bytes).
/// * `generation` — the live activation generation (the child proves its
///   fence generation against this).
/// * `nonce` — the I7.5/I15.2 session nonce.
/// * `grant` — the shared `DispatchGrant` object (see its docs).
///
/// The concrete `ProcessRequest` is never serialized (it is
/// `Serialize`-only by design on the child side and `Clone`-only here);
/// the child rebuilds it in-process from `grant` via `FencingToken::new` +
/// `PermitIssuance::new` + `DispatchValidationContext::new` +
/// `ProcessRequest::new`. No executable bytes are taken from caller input:
/// the child binding (path/digest/workdir) stays composition-pinned like
/// Doctor.
fn testd_material_bytes(
    request: &TestdAdmissionAttemptRequest,
    envelope: &TestdAdmissionEnvelope,
    admission: &TestdAdmission,
    epoch: &EpochId,
    generation: u64,
    nonce: &str,
    grant: &DispatchGrant,
) -> Result<Vec<u8>, DispatchLaunchError> {
    let body = serde_json::json!({
        "request": request,
        "envelope": envelope,
        "admission": admission,
        "epoch": epoch,
        "generation": generation,
        "nonce": nonce,
        "grant": grant,
    });
    let bytes =
        serde_json::to_vec(&body).map_err(|error| DispatchLaunchError::Io(error.to_string()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > 256 * 1024 {
        return Err(DispatchLaunchError::Io(
            "dispatch material exceeds the bounded input limit".to_owned(),
        ));
    }
    Ok(bytes)
}

/// Writes the native-worker dispatch file carrying the admitted claim plus
/// the Kernel-issued launch grant.
///
/// JSON shape for the native child (all keys required):
/// ```json
/// {
///   "request": NativeWorkerClaimRequest,
///   "receipt": NativeWorkerClaimReceipt,
///   "epoch": EpochId,
///   "generation": 1,
///   "nonce": "native-worker-dispatch-<hex>",
///   "grant": DispatchGrant
/// }
/// ```
/// * `request` — the exact `NativeWorkerClaimRequest` the contour admitted
///   (existing `eliot-kernel-service` vocabulary; never a parallel type).
/// * `receipt` — the Kernel-issued `NativeWorkerClaimReceipt` (existing
///   vocabulary; its `receipt_digest` is the admission identity).
/// * `epoch`/`generation` — the live authority bound at admission.
/// * `nonce` — the I7.5/I15.2 session nonce (must equal the v2
///   executable-join launch nonce when the join is present; the caller
///   request already binds it, and the child re-proves binding).
/// * `grant` — the shared `DispatchGrant` object.
///
/// The concrete `ProcessRequest` plus the composed provider ports arrive
/// only with the execution context the child builds in-process from `grant`
/// (same broker pattern as Doctor/Testd); validated claim bytes alone never
/// drive. Binds to the existing `NativeWorkerClaimRecord` durably
/// kernel-side (the ORS claim table stages/loads it; see
/// `native_worker_lifecycle_route::NATIVE_WORKER_CLAIM_OPERATION`): the
/// material carries the request/receipt projection, while the record stays
/// the durable authority for reconcile.
fn native_worker_material_bytes(
    request: &NativeWorkerClaimRequest,
    receipt: &NativeWorkerClaimReceipt,
    epoch: &EpochId,
    generation: u64,
    nonce: &str,
    grant: &DispatchGrant,
) -> Result<Vec<u8>, DispatchLaunchError> {
    // Bind to the existing claim vocabulary without inventing a parallel
    // one: the lifecycle route owns `native_worker.claim`, and ORS owns the
    // record. Referencing the operation here keeps the dispatch seam on the
    // same vocabulary (a mismatched operation name fails closed at the
    // route; the dispatch seam never mints its own).
    debug_assert_eq!(
        crate::native_worker_lifecycle_route::NATIVE_WORKER_CLAIM_OPERATION,
        "native_worker.claim"
    );
    let body = serde_json::json!({
        "request": request,
        "receipt": receipt,
        "epoch": epoch,
        "generation": generation,
        "nonce": nonce,
        "grant": grant,
    });
    let bytes =
        serde_json::to_vec(&body).map_err(|error| DispatchLaunchError::Io(error.to_string()))?;
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
                native_receipt: None,
                native_request: None,
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
    let grant = dispatch_grant_for(
        DispatchedWorkerKind::Doctor,
        &admission.attempt_digest,
        &authority_epoch,
        generation,
        admission.admitted_at_unix_nanos,
    )?;
    let bytes = doctor_material_bytes(
        material.attempt,
        material.request_json,
        material.manifest_json,
        &authority_epoch,
        generation.get(),
        &nonce,
        &grant,
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
                    native_receipt: None,
                    native_request: None,
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
                    native_receipt: None,
                    native_request: None,
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

/// Composition-supplied child binary anchor for the Doctor trigger.
///
/// The executable path plus the working directory are the one trigger
/// input the dispatch contour cannot derive: the contour owns the
/// principal, the ledger, the immutable registry (including the installed
/// artifact digest bound into the admitted executable binding), and the
/// live epoch/generation — but the absolute installed-generation root is
/// Host installation state. The production composition root supplies it
/// from Host injection through the installation manifest
/// (manager-serialized `main` call-in); this struct only carries it.
/// Never wire bytes, never argv/env discovery.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub struct DoctorChildBinding<'a> {
    /// Absolute path of the composition-pinned `eliot-doctor` executable.
    /// The dispatch file is staged next to it.
    pub executable: &'a Path,
    /// Absolute working directory the child spawns under.
    pub working_directory: &'a Path,
}

/// Contour-derived Doctor launch material: the admitted manifest revision
/// plus the admitted executable digest, both read back from the composed
/// registry — never caller bytes.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
struct ContourDoctorMaterial {
    /// The exact admitted manifest revision, serialized from the composed
    /// registry.
    manifest_json: serde_json::Value,
    /// Expected SHA-256 of the child image, from the admitted operation's
    /// executable binding in the composed registry.
    executable_sha256: String,
}

/// Returns a clone of the composed Doctor registry or fails closed.
///
/// Cloned (one operation plus one recipe) so the trigger holds no contour
/// lock across admission and launch.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
fn composed_doctor_registry(
    contour: &'static ComposedDispatchContour,
) -> Result<DoctorRecipeRegistry, DispatchLaunchError> {
    let doctor = contour
        .doctor
        .lock()
        .map_err(|_| DispatchLaunchError::Gate("doctor front-door lock poisoned".to_owned()))?;
    doctor
        .as_ref()
        .map(|state| state.registry.clone())
        .ok_or(DispatchLaunchError::Uncomposed("doctor front door"))
}

/// Derives the contour-owned half of [`DoctorLaunchMaterial`] from the
/// composed registry for one admitted attempt.
///
/// Fail-closed: the admission must bind this contour's manifest revision
/// (`admission.manifest_digest` equals the composed registry digest — a
/// stale or foreign admission is `Inconsistent`, never staged), and the
/// admitted operation must resolve to an executable binding in the
/// composed manifest (an unknown or forged operation is
/// `InvalidMaterial`, never staged). The returned digest is the installed
/// artifact digest the supplying composition composed through
/// [`compose_production_doctor_front_door`]; the caller supplies only the
/// absolute binary anchor ([`DoctorChildBinding`]).
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
fn contour_doctor_material(
    registry: &DoctorRecipeRegistry,
    admission: &DoctorRepairAdmission,
) -> Result<ContourDoctorMaterial, DispatchLaunchError> {
    if admission.manifest_digest != registry.manifest_digest() {
        return Err(DispatchLaunchError::Inconsistent(
            "admitted doctor attempt does not bind the composed manifest revision".to_owned(),
        ));
    }
    let manifest = registry.manifest();
    let executable_sha256 = manifest
        .operations
        .iter()
        .find(|entry| entry.operation_id == admission.operation_id)
        .map(|entry| entry.binding.artifact_digest.clone())
        .ok_or_else(|| {
            DispatchLaunchError::InvalidMaterial(
                "admitted doctor operation resolves no composed executable binding".to_owned(),
            )
        })?;
    require_digest(
        &executable_sha256,
        "composed doctor executable digest must be a lowercase SHA-256 digest",
    )?;
    let manifest_json = serde_json::to_value(manifest)
        .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    Ok(ContourDoctorMaterial {
        manifest_json,
        executable_sha256,
    })
}

/// Admits one Doctor attempt through the composed contour and launches the
/// admitted effect through the existing launch seam: the T6-D2 front-door
/// trigger (issue #461, plan slice 5).
///
/// Owner: the dispatch contour owns this trigger — not the frame dispatch
/// arm and not the front-door driver pump. The frame arm
/// (`frame_dispatch::execute_doctor_request`) admits and replies but never
/// spawns, keeping the admission and execution axes separate (I14.6); the
/// driver arm (`front_door_driver`) serves one bounded request/response per
/// frame and has nowhere to report a spawn. The contour already owns admit
/// (owner plus ledger plus principal), reserve, nonce, material-write,
/// spawn, and reconcile-by-identity, so the trigger lives here: pre-admit
/// through the composed gate, derive the launch material from the composed
/// contour (admitted manifest revision plus installed executable digest —
/// never caller bytes), then delegate to
/// [`launch_admitted_doctor_attempt`] (prepare, start-ready, and launch
/// through the admitted executor; no second launch path). Reconcile stays
/// with [`reconcile_launched_doctor_attempt`] by the original identity.
///
/// Fail-closed: an uncomposed contour errors before touching state; every
/// typed refusal or conflict returns as [`DoctorLaunchOutcome::Refused`]
/// with no file staged and no slot retained; a forged operation or a stale
/// manifest binding errors before staging any file; a replay rebuilds the
/// original admission (the lost-reply rule) and the delegated prepare
/// single-flights it (`LaunchInFlight`) instead of spawning twice — the
/// concurrent-duplicate case included, since reservation happens inside the
/// delegated prepare. The absolute child anchor comes from the owning
/// composition ([`DoctorChildBinding`], supplied by Host injection through
/// the installation manifest) — never from the wire, argv, or the
/// environment.
///
/// Production call-in (manager-serialized, outside this slice): the
/// composition root calls this after `execute_doctor_request` admits, with
/// the Host-injected binding, and reconciles through
/// `reconcile_launched_doctor_attempt`; both need the `lib.rs`
/// `dispatch_launch` re-export extended.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub async fn trigger_admitted_doctor_launch(
    kernel: &KernelComposition,
    attempt: &DoctorRepairAttemptRequest,
    child: &DoctorChildBinding<'_>,
    now_unix_nanos: u64,
) -> Result<DoctorLaunchOutcome, DispatchLaunchError> {
    if now_unix_nanos == 0 {
        return Err(DispatchLaunchError::InvalidMaterial(
            "admission time must be non-zero".to_owned(),
        ));
    }
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("doctor front door"))?;
    let request_json: serde_json::Value = serde_json::from_str(&attempt.closed_request_json)
        .map_err(|_| {
            DispatchLaunchError::InvalidMaterial("closed request envelope is not JSON".to_owned())
        })?;
    let response = {
        let service = kernel
            .service
            .lock()
            .map_err(|_| DispatchLaunchError::Gate("kernel service lock poisoned".to_owned()))?;
        admit_doctor_repair_attempt(&service, attempt, now_unix_nanos)?
    };
    let DoctorRepairResponse::Admitted(admission) = response else {
        return Ok(DoctorLaunchOutcome::Refused(response));
    };
    let derived = contour_doctor_material(&composed_doctor_registry(contour)?, &admission)?;
    let material = DoctorLaunchMaterial {
        attempt,
        request_json: &request_json,
        manifest_json: &derived.manifest_json,
        executable: child.executable,
        executable_sha256: &derived.executable_sha256,
        working_directory: child.working_directory,
    };
    launch_admitted_doctor_attempt(kernel, &material, now_unix_nanos).await
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
                existing.native_receipt.clone_from(&record.native_receipt);
                existing.native_request.clone_from(&record.native_request);
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
/// re-parsed (never trusted) at prepare and reconcile time. Like Doctor,
/// nothing travels via argv, stdin, or the environment; the admitted
/// attempt plus the launch grant travels only over the protected dispatch
/// file (`eliot-testd.admitted-attempt.json`, see
/// [`DispatchedWorkerKind::material_file_name`]). No executable bytes are
/// taken from caller input: the child binding (path/digest/workdir) stays
/// composition-pinned.
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
    /// Protected dispatch file path the child reads.
    pub material_path: PathBuf,
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
/// the job identity single-flight; mint the replay-stable nonce; write the
/// admitted attempt plus the launch grant to the protected dispatch file
/// through [`write_material_file`]. Nothing is spawned here:
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
                native_receipt: None,
                native_request: None,
            },
        );
    }
    let Some(file_name) = DispatchedWorkerKind::Testd.material_file_name() else {
        release_launch(contour, &admission.job_id);
        return Err(DispatchLaunchError::Gate(
            "testd defines no dispatch material file".to_owned(),
        ));
    };
    let material_path = material_dir.to_path_buf().join(file_name);
    // The envelope is derived Kernel-side by re-parsing the already-admitted
    // closed request; no extra caller bytes are taken (never executable
    // bytes). A parse failure here releases the reservation fail-closed.
    let envelope: TestdAdmissionEnvelope =
        serde_json::from_str(&material.request.closed_request_json).map_err(|_| {
            release_launch(contour, &admission.job_id);
            DispatchLaunchError::InvalidMaterial(
                "testd closed request envelope is not JSON".to_owned(),
            )
        })?;
    let grant = dispatch_grant_for(
        DispatchedWorkerKind::Testd,
        &admission.request_digest,
        &authority_epoch,
        generation,
        admission.admitted_at_unix_nanos,
    )
    .inspect_err(|_| {
        release_launch(contour, &admission.job_id);
    })?;
    let bytes = testd_material_bytes(
        material.request,
        &envelope,
        &admission,
        &authority_epoch,
        generation.get(),
        &nonce,
        &grant,
    );
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(error) => {
            release_launch(contour, &admission.job_id);
            return Err(error);
        }
    };
    if let Err(error) = write_material_file(&material_path, &bytes) {
        release_launch(contour, &admission.job_id);
        return Err(error);
    }
    if let Ok(mut launches) = contour.launches.lock()
        && let Some(record) = launches.by_identity.get_mut(&admission.job_id)
    {
        record.material_path = Some(material_path.clone());
    }
    Ok(PreparedTestdLaunch::Ready(ReadyTestdLaunch {
        admission,
        nonce,
        operation_id,
        executable: material.executable.to_path_buf(),
        executable_sha256: material.executable_sha256.to_owned(),
        working_directory: material.working_directory.to_path_buf(),
        material_path,
        authority_epoch,
        generation,
    }))
}

/// Spawns one prepared testd launch through the admitted process gateway.
///
/// Same seam shape as the Doctor spawn: empty argv, secret-free
/// environment, bounded limits, pinned path proof, Kernel-owned process
/// owner. The admitted attempt material travels only over the protected
/// dispatch file the child reads; a spawn failure reaps the file
/// best-effort so a stale presentation never lingers.
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
    let material_path = ready.material_path.clone();
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
                    material_path: Some(material_path),
                    nonce: ready.nonce.clone(),
                    operation_id: operation_id_string(&ready.operation_id),
                    phase: LaunchPhase::Launched,
                    testd_admission: Some((*ready.admission).clone()),
                    native_receipt: None,
                    native_request: None,
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
                    material_path: Some(material_path),
                    nonce: ready.nonce.clone(),
                    operation_id: operation_id_string(&uncertain.operation_id),
                    phase: LaunchPhase::Unreconciled,
                    testd_admission: Some((*ready.admission).clone()),
                    native_receipt: None,
                    native_request: None,
                },
            )?;
            Ok(TestdLaunchOutcome::LaunchUnknown {
                admission: ready.admission,
                nonce: ready.nonce,
                operation_id: ready.operation_id,
            })
        }
        Err(error) => {
            reap_material_file(&material_path);
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
        if let Some(path) = retained.material_path.as_deref() {
            reap_material_file(path);
        }
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
/// Documented use: testd and native-worker slots, whose durable
/// terminality lives in the owner store and therefore never auto-release
/// kernel-side. The dispatch file is reaped best-effort on release so a
/// stale presentation never lingers for a later invocation.
pub fn release_launched_attempt(
    kind: DispatchedWorkerKind,
    identity: &str,
    request_digest: &str,
) -> Result<bool, DispatchLaunchError> {
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("dispatch contour"))?;
    let material_path = {
        let launches = launches_table(contour)?;
        launches
            .by_identity
            .get(identity)
            .filter(|record| record.kind == kind && record.request_digest == request_digest)
            .and_then(|record| record.material_path.clone())
    };
    let mut launches = launches_table(contour)?;
    let release = launches
        .by_identity
        .get(identity)
        .is_some_and(|record| record.kind == kind && record.request_digest == request_digest);
    if release {
        launches.by_identity.remove(identity);
    }
    drop(launches);
    if release && let Some(path) = material_path {
        reap_material_file(&path);
    }
    Ok(release)
}

/// Caller-supplied native-worker launch material: the claim wire request
/// plus the composition-pinned child binary binding.
///
/// The claim request (`NativeWorkerClaimRequest`, existing
/// `eliot-kernel-service` vocabulary) travels by value; the ORS claim
/// record (`NativeWorkerClaimRecord`, existing `eliot-ors` vocabulary)
/// stays the durable authority kernel-side. Like Doctor/Testd, nothing
/// travels via argv, stdin, or the environment; the admitted claim plus
/// the launch grant travels only over the protected dispatch file
/// (`eliot-native-worker.admitted-claim.json`, see
/// [`DispatchedWorkerKind::material_file_name`]). No executable bytes are
/// taken from caller input: the child binding (path/digest/workdir) stays
/// composition-pinned, and the `executable_binding` join inside the request
/// is validated closed (never minted here).
pub struct NativeWorkerLaunchMaterial<'a> {
    /// Full wire envelope: claim/binding digests plus the T9-02
    /// executable-binding join when present.
    pub request: &'a NativeWorkerClaimRequest,
    /// Composition-pinned child executable path.
    pub executable: &'a Path,
    /// Expected SHA-256 digest of the child executable image.
    pub executable_sha256: &'a str,
    /// Composition-pinned child working directory.
    pub working_directory: &'a Path,
}

/// Why a prepared native-worker launch produced no child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWorkerLaunchSkip {
    /// The claim identity is already reserved or launched: the returned
    /// receipt is the original identity's receipt (rebuilt identically by
    /// the gate), never a recompute under a new id.
    LaunchInFlight,
}

/// A prepared native-worker launch: admitted, nonce-bound, and (unless
/// skipped) written to the protected dispatch file, ready to spawn.
#[allow(
    clippy::large_enum_variant,
    reason = "Ready carries the full spawn binding like PreparedDoctorLaunch::Ready; boxing it would diverge from the Doctor/Testd seam shape"
)]
pub enum PreparedNativeWorkerLaunch {
    /// Ready to spawn through the admitted executor.
    Ready(ReadyNativeWorkerLaunch),
    /// An exact resubmit under one claim identity: carries the RETAINED
    /// original receipt (original admitted-at time and digest), never the
    /// just-recomputed one.
    ReplayOriginal {
        /// The original receipt for the claim identity.
        receipt: Box<NativeWorkerClaimReceipt>,
    },
    /// Admitted but needing no child; carries the receipt and the reason.
    Skipped {
        /// The receipt for the claim identity.
        receipt: Box<NativeWorkerClaimReceipt>,
        /// Why no child is spawned.
        skip: NativeWorkerLaunchSkip,
    },
    /// The gate refused or conflicted; carries the typed answer, never a
    /// receipt (boxed: the response dwarfs the other outcomes).
    Refused(Box<NativeWorkerClaimResponse>),
}

/// A native-worker launch ready to spawn: every authority check passed and
/// the dispatch file carries exactly what the child reader validates.
pub struct ReadyNativeWorkerLaunch {
    /// The receipt for the claim identity.
    pub receipt: Box<NativeWorkerClaimReceipt>,
    /// The I7.5/I15.2 launch nonce written to the dispatch file.
    pub nonce: String,
    /// Deterministic child operation identity derived from the binding
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

/// Outcome of one native-worker admit-then-launch call.
#[allow(
    clippy::large_enum_variant,
    reason = "Refused is boxed; Launched carries two boxed receipts plus identities like Doctor/Testd outcomes"
)]
pub enum NativeWorkerLaunchOutcome {
    /// The child was spawned through the admitted executor.
    Launched {
        /// The receipt for the claim identity.
        receipt: Box<NativeWorkerClaimReceipt>,
        /// The launch nonce retained for the submit-time session proof.
        nonce: String,
        /// Child process operation identity.
        operation_id: OperationId,
        /// The admitted process-start receipt (boxed: receipts dwarf the
        /// other outcomes).
        receipt_process: Box<ProcessStartReceipt>,
    },
    /// The spawn outcome is unknown: retained as unreconciled under the
    /// original claim identity — reconcile later, never blind-retry.
    LaunchUnknown {
        /// The receipt for the claim identity.
        receipt: Box<NativeWorkerClaimReceipt>,
        /// The launch nonce retained for the session proof.
        nonce: String,
        /// Child process operation identity.
        operation_id: OperationId,
    },
    /// An exact resubmit under one claim identity: carries the retained
    /// original receipt, and no second child is spawned.
    ReplayOriginal {
        /// The original receipt for the claim identity.
        receipt: Box<NativeWorkerClaimReceipt>,
    },
    /// Admitted but needing no child; carries the receipt and the reason.
    NotLaunched {
        /// The receipt for the claim identity.
        receipt: Box<NativeWorkerClaimReceipt>,
        /// Why no child was spawned.
        skip: NativeWorkerLaunchSkip,
    },
    /// The gate refused or conflicted; carries the typed answer (boxed: the
    /// response dwarfs the other outcomes).
    Refused(Box<NativeWorkerClaimResponse>),
}

/// Admits one native-worker claim and prepares its launch: nonce-bound
/// material written to the protected dispatch file, ready to spawn.
///
/// Sequence: validate the child binding plus the closed claim shape and
/// canonical digest; admit through live service authority plus the ORS
/// claim table (`KernelService::admit_native_worker_claim` — the existing
/// vocabulary, never a parallel one; exact replays rebuild the original
/// receipt); reserve the original claim identity single-flight (changed
/// terms under one identity refuse with `ChangedTerms`); mint the
/// replay-stable nonce; write the admitted claim plus the launch grant
/// through [`write_material_file`]. Nothing is spawned here:
/// [`launch_admitted_native_worker_attempt`] spawns the returned
/// [`ReadyNativeWorkerLaunch`] through the admitted executor.
#[allow(
    clippy::too_many_lines,
    reason = "admit, reserve, nonce, and material-write stay in one ordered authority path so no launch step can run before its gate"
)]
pub fn prepare_native_worker_launch(
    kernel: &KernelComposition,
    material: &NativeWorkerLaunchMaterial<'_>,
    now_unix_nanos: u64,
) -> Result<PreparedNativeWorkerLaunch, DispatchLaunchError> {
    if now_unix_nanos == 0 {
        return Err(DispatchLaunchError::InvalidMaterial(
            "admission time must be non-zero".to_owned(),
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
    material.request.validate().map_err(gate_error)?;
    material
        .request
        .validate_canonical_digest()
        .map_err(gate_error)?;
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("native-worker front door"))?;
    let now_unix_ms = now_unix_nanos / 1_000_000;
    if now_unix_ms == 0 {
        return Err(DispatchLaunchError::InvalidMaterial(
            "admission time must be non-zero milliseconds".to_owned(),
        ));
    }
    let (authority_epoch, generation, response) = {
        let service = kernel
            .service
            .lock()
            .map_err(|_| DispatchLaunchError::Gate("kernel service lock poisoned".to_owned()))?;
        let response = service
            .admit_native_worker_claim(
                kernel.generation_gateway.ors.as_ref(),
                material.request,
                now_unix_ms,
            )
            .map_err(gate_error)?;
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
    let receipt = match response {
        NativeWorkerClaimResponse::Admitted(receipt) => receipt,
        refused => return Ok(PreparedNativeWorkerLaunch::Refused(Box::new(refused))),
    };
    require_digest(
        &receipt.binding_digest,
        "native receipt binding digest must be a lowercase SHA-256 digest",
    )?;
    require_digest(
        &receipt.receipt_digest,
        "native receipt digest must be a lowercase SHA-256 digest",
    )?;
    // The admitted receipt must answer the presented request: same claim,
    // same binding. A rewired receipt never prepares.
    if receipt.claim_id != material.request.claim_id
        || receipt.binding_digest != material.request.binding_digest
    {
        return Err(DispatchLaunchError::Inconsistent(
            "native receipt does not answer the presented claim".to_owned(),
        ));
    }
    let admitted_at_nanos = receipt
        .admitted_at_unix_ms
        .checked_mul(1_000_000)
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            DispatchLaunchError::Inconsistent("native admission time is not well-formed".to_owned())
        })?;
    let nonce = mint_dispatch_nonce(
        DispatchedWorkerKind::NativeWorker,
        &receipt.binding_digest,
        admitted_at_nanos,
        contour.principal_owner.as_str(),
    )?;
    let generation = Generation::new(generation)
        .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    let operation_id = OperationId::new(format!(
        "{}-{}-{}",
        DispatchedWorkerKind::NativeWorker.operation_prefix(),
        generation.get(),
        short_identity(&receipt.binding_digest)?
    ))
    .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    {
        let mut launches = launches_table(contour)?;
        if let Some(existing) = launches.by_identity.get(&receipt.claim_id) {
            if existing.kind != DispatchedWorkerKind::NativeWorker {
                return Err(DispatchLaunchError::ChangedTerms(format!(
                    "claim identity {} is already launched for another worker",
                    receipt.claim_id
                )));
            }
            if existing.request_digest != material.request.request_digest {
                return Err(DispatchLaunchError::ChangedTerms(format!(
                    "claim {} presents changed terms under one claim identity",
                    receipt.claim_id
                )));
            }
            if let Some(retained) = existing.native_receipt.clone() {
                return Ok(PreparedNativeWorkerLaunch::ReplayOriginal {
                    receipt: Box::new(retained),
                });
            }
        }
        launches.by_identity.insert(
            receipt.claim_id.clone(),
            LaunchRecord {
                kind: DispatchedWorkerKind::NativeWorker,
                identity: receipt.claim_id.clone(),
                admission_digest: receipt.receipt_digest.clone(),
                request_digest: material.request.request_digest.clone(),
                effect_digest: None,
                material_path: None,
                nonce: nonce.clone(),
                operation_id: operation_id_string(&operation_id),
                phase: LaunchPhase::Reserved,
                testd_admission: None,
                native_receipt: Some(receipt.clone()),
                native_request: Some(material.request.clone()),
            },
        );
    }
    let Some(file_name) = DispatchedWorkerKind::NativeWorker.material_file_name() else {
        release_launch(contour, &receipt.claim_id);
        return Err(DispatchLaunchError::Gate(
            "native worker defines no dispatch material file".to_owned(),
        ));
    };
    let material_path = material_dir.to_path_buf().join(file_name);
    let grant = dispatch_grant_for(
        DispatchedWorkerKind::NativeWorker,
        &receipt.binding_digest,
        &authority_epoch,
        generation,
        admitted_at_nanos,
    )
    .inspect_err(|_| {
        release_launch(contour, &receipt.claim_id);
    })?;
    let bytes = native_worker_material_bytes(
        material.request,
        &receipt,
        &authority_epoch,
        generation.get(),
        &nonce,
        &grant,
    );
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(error) => {
            release_launch(contour, &receipt.claim_id);
            return Err(error);
        }
    };
    if let Err(error) = write_material_file(&material_path, &bytes) {
        release_launch(contour, &receipt.claim_id);
        return Err(error);
    }
    if let Ok(mut launches) = contour.launches.lock()
        && let Some(record) = launches.by_identity.get_mut(&receipt.claim_id)
    {
        record.material_path = Some(material_path.clone());
    }
    Ok(PreparedNativeWorkerLaunch::Ready(ReadyNativeWorkerLaunch {
        receipt: Box::new(receipt),
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

/// Spawns one prepared native-worker launch through the admitted process
/// gateway.
///
/// Same seam shape as the Doctor/testd spawn: empty argv, secret-free
/// environment, bounded limits, pinned path proof, Kernel-owned process
/// owner. The admitted-claim material travels only over the protected
/// dispatch file the child reads; a spawn failure reaps the file
/// best-effort so a stale presentation never lingers.
pub async fn start_ready_native_worker_launch(
    kernel: &KernelComposition,
    ready: &ReadyNativeWorkerLaunch,
) -> Result<ChildStartOutcome, DispatchLaunchError> {
    match spawn_ready_child(
        kernel,
        &SpawnInputs {
            kind: DispatchedWorkerKind::NativeWorker,
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

/// Admits one native-worker claim, then launches the real
/// `eliot-native-worker` binary through the admitted process executor.
///
/// Admit-then-launch in one seam, mirroring the testd call: prepare admits
/// and reserves the original claim identity plus writes the
/// admitted-claim material, then the ready launch spawns and the identity
/// is retained. Exact resubmits return the retained original receipt
/// without spawning; refusals and skips return as outcomes; a failed spawn
/// reaps the file and releases the reservation; an unknown spawn outcome
/// retains the launch as unreconciled for
/// [`reconcile_launched_native_worker_attempt`].
pub async fn launch_admitted_native_worker_attempt(
    kernel: &KernelComposition,
    material: &NativeWorkerLaunchMaterial<'_>,
    now_unix_nanos: u64,
) -> Result<NativeWorkerLaunchOutcome, DispatchLaunchError> {
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("native-worker front door"))?;
    let prepared = prepare_native_worker_launch(kernel, material, now_unix_nanos)?;
    let ready = match prepared {
        PreparedNativeWorkerLaunch::Ready(ready) => ready,
        PreparedNativeWorkerLaunch::ReplayOriginal { receipt } => {
            return Ok(NativeWorkerLaunchOutcome::ReplayOriginal { receipt });
        }
        PreparedNativeWorkerLaunch::Skipped { receipt, skip } => {
            return Ok(NativeWorkerLaunchOutcome::NotLaunched { receipt, skip });
        }
        PreparedNativeWorkerLaunch::Refused(response) => {
            return Ok(NativeWorkerLaunchOutcome::Refused(response));
        }
    };
    let claim_id = ready.receipt.claim_id.clone();
    let request_digest = {
        let launches = launches_table(contour)?;
        launches.by_identity.get(&claim_id).map_or_else(
            || ready.receipt.binding_digest.clone(),
            |record| record.request_digest.clone(),
        )
    };
    let material_path = ready.material_path.clone();
    match start_ready_native_worker_launch(kernel, &ready).await {
        Ok(ChildStartOutcome::Started(spawned)) => {
            let native_request = {
                let launches = launches_table(contour)?;
                launches
                    .by_identity
                    .get(&claim_id)
                    .and_then(|record| record.native_request.clone())
            };
            retain_launch(
                contour,
                LaunchRecord {
                    kind: DispatchedWorkerKind::NativeWorker,
                    identity: claim_id,
                    admission_digest: ready.receipt.receipt_digest.clone(),
                    request_digest,
                    effect_digest: None,
                    material_path: Some(material_path),
                    nonce: ready.nonce.clone(),
                    operation_id: operation_id_string(&ready.operation_id),
                    phase: LaunchPhase::Launched,
                    testd_admission: None,
                    native_receipt: Some((*ready.receipt).clone()),
                    native_request,
                },
            )?;
            Ok(NativeWorkerLaunchOutcome::Launched {
                receipt: ready.receipt,
                nonce: ready.nonce,
                operation_id: ready.operation_id,
                receipt_process: Box::new(spawned.receipt),
            })
        }
        Ok(ChildStartOutcome::Unknown(uncertain)) => {
            let native_request = {
                let launches = launches_table(contour)?;
                launches
                    .by_identity
                    .get(&claim_id)
                    .and_then(|record| record.native_request.clone())
            };
            retain_launch(
                contour,
                LaunchRecord {
                    kind: DispatchedWorkerKind::NativeWorker,
                    identity: claim_id,
                    admission_digest: ready.receipt.receipt_digest.clone(),
                    request_digest,
                    effect_digest: None,
                    material_path: Some(material_path),
                    nonce: ready.nonce.clone(),
                    operation_id: operation_id_string(&uncertain.operation_id),
                    phase: LaunchPhase::Unreconciled,
                    testd_admission: None,
                    native_receipt: Some((*ready.receipt).clone()),
                    native_request,
                },
            )?;
            Ok(NativeWorkerLaunchOutcome::LaunchUnknown {
                receipt: ready.receipt,
                nonce: ready.nonce,
                operation_id: ready.operation_id,
            })
        }
        Err(error) => {
            reap_material_file(&material_path);
            release_launch(contour, &claim_id);
            Err(error)
        }
    }
}

/// Reconciles one launched-but-unreconciled native-worker claim by its
/// original identity.
///
/// Loads the durable ORS claim record (`NativeWorkerClaimRecord`, the
/// existing vocabulary) by the original claim identity and compares the
/// bound receipt digest: no new admission is minted, no new claim id is
/// computed, and no second child is spawned. The retained receipt is then
/// re-proved against the retained request through the existing service
/// owner (`KernelService::reconcile_native_worker_claim_admission`) under
/// live authority (same-authority epoch). A converged receipt reaps the
/// dispatch file best-effort and closes the slot; anything still
/// outstanding stays unreconciled for a later call. Unknown identities
/// report unknown instead of inventing state.
pub fn reconcile_launched_native_worker_attempt(
    kernel: &KernelComposition,
    claim_id: &str,
) -> Result<ReconcileLaunchedOutcome, DispatchLaunchError> {
    let contour = DISPATCH_CONTOUR
        .get()
        .ok_or(DispatchLaunchError::Uncomposed("native-worker front door"))?;
    let retained = {
        let launches = launches_table(contour)?;
        launches.by_identity.get(claim_id).cloned()
    };
    let Some(retained) =
        retained.filter(|record| record.kind == DispatchedWorkerKind::NativeWorker)
    else {
        return Ok(ReconcileLaunchedOutcome::Unknown {
            kind: DispatchedWorkerKind::NativeWorker,
            identity: claim_id.to_owned(),
        });
    };
    let (Some(receipt), Some(request)) = (
        retained.native_receipt.clone(),
        retained.native_request.clone(),
    ) else {
        return Ok(ReconcileLaunchedOutcome::Unknown {
            kind: DispatchedWorkerKind::NativeWorker,
            identity: claim_id.to_owned(),
        });
    };
    // Durable truth: the ORS claim record must still bind this receipt.
    // Uses the existing `NativeWorkerClaimRecord` vocabulary; never a
    // parallel type.
    let record_key = OperationIdentity::new(claim_id)
        .map_err(|error| DispatchLaunchError::InvalidMaterial(error.to_string()))?;
    let record: Option<NativeWorkerClaimRecord> = kernel
        .generation_gateway
        .ors
        .load_native_worker_claim(&record_key)
        .map_err(|error| DispatchLaunchError::Gate(error.to_string()))?;
    let Some(record) = record else {
        return Ok(ReconcileLaunchedOutcome::Unknown {
            kind: DispatchedWorkerKind::NativeWorker,
            identity: claim_id.to_owned(),
        });
    };
    if record.receipt_digest.as_deref() != Some(receipt.receipt_digest.as_str())
        || record.binding_digest != receipt.binding_digest
    {
        return Err(DispatchLaunchError::Inconsistent(
            "durable native claim cannot reproduce its receipt".to_owned(),
        ));
    }
    let live_epoch = kernel
        .service
        .lock()
        .map_err(|_| DispatchLaunchError::Gate("kernel service lock poisoned".to_owned()))?
        .authority_epoch();
    if !receipt.authority_epoch.is_same_authority(&live_epoch) {
        return Ok(ReconcileLaunchedOutcome::Unreconciled {
            kind: DispatchedWorkerKind::NativeWorker,
            identity: claim_id.to_owned(),
        });
    }
    let binds = kernel
        .service
        .lock()
        .map_err(|_| DispatchLaunchError::Gate("kernel service lock poisoned".to_owned()))?
        .reconcile_native_worker_claim_admission(&receipt, &request)
        .map_err(gate_error)?;
    if binds {
        if let Some(path) = retained.material_path.as_deref() {
            reap_material_file(path);
        }
        mark_reconciled(contour, claim_id)?;
        return Ok(ReconcileLaunchedOutcome::Reconciled {
            kind: DispatchedWorkerKind::NativeWorker,
            identity: claim_id.to_owned(),
            admission_digest: retained.admission_digest,
        });
    }
    Ok(ReconcileLaunchedOutcome::Unreconciled {
        kind: DispatchedWorkerKind::NativeWorker,
        identity: claim_id.to_owned(),
    })
}

/// Caller-supplied Dreamer launch material: the job/attempt lookup keys, the
/// Kernel-loaded admitted `QUEUED` ledger response, plus the
/// composition-pinned child binary binding.
///
/// Only the keys arrive from the caller; scope, fence, revision, epoch, and
/// generation always bind from `queued` plus live authority, never from
/// caller bytes. Like Doctor/Testd/native, nothing travels via argv, stdin,
/// or the environment; the admitted job plus the launch grant travels only
/// over the protected dispatch file
/// (`eliot-dreamer.admitted-job.json`, see
/// [`DispatchedWorkerKind::material_file_name`]). No executable bytes are
/// taken from caller input: the child binding (path/digest/workdir) stays
/// composition-pinned.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub struct DreamerLaunchMaterial<'a> {
    /// Job/attempt lookup keys; must be answered by `queued`.
    pub keys: DreamerLaunchKeys<'a>,
    /// Admitted `QUEUED` ledger response loaded Kernel-side through the
    /// existing K1 gateway (no new transport or pipe). The durable Store
    /// ledger stays the terminal authority; this arm binds from the
    /// response and never mints ledger state.
    pub queued: &'a DurableJobResponse,
    /// Composition-pinned child binary anchor.
    pub child: DreamerChildBinding<'a>,
}

/// Why a prepared Dreamer launch produced no child.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DreamerLaunchSkip {
    /// The admitted response is not `QUEUED` (already leased, running, or
    /// terminal): nothing to drive, no child spawned.
    NotQueued,
}

/// A prepared Dreamer launch: admitted, lineage-bound, and (unless skipped)
/// written to the protected dispatch file, ready to spawn.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
#[allow(
    clippy::large_enum_variant,
    reason = "Ready carries the full spawn binding like PreparedDoctorLaunch::Ready; boxing it would diverge from the sibling seam shape"
)]
pub enum PreparedDreamerLaunch {
    /// Ready to spawn through the admitted executor.
    Ready(ReadyDreamerLaunch),
    /// An exact resubmit under one job identity: carries the RETAINED
    /// original record (original nonce, operation, and grant digest), never
    /// a recomputed one. No second worker may spawn from this outcome.
    ReplayOriginal {
        /// The original lineage for the job identity.
        record: Box<DreamerLaunchRecord>,
    },
    /// Admitted but needing no child; carries the response and the reason.
    Skipped {
        /// The admitted response for the job identity.
        response: Box<DurableJobResponse>,
        /// Why no child was spawned.
        skip: DreamerLaunchSkip,
    },
    /// The admitted response does not answer the presented keys; carries
    /// the reason, never a lineage.
    Refused(String),
}

/// A Dreamer launch ready to spawn: every authority check passed and the
/// dispatch file carries exactly what the child reader validates.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub struct ReadyDreamerLaunch {
    /// Exact queued job identity (lineage key for spawn settle).
    pub job_id: String,
    /// The I7.5/I15.2 launch nonce written to the dispatch file.
    pub nonce: String,
    /// Deterministic child operation identity derived from the lineage, so
    /// the admitted executor replays (never double-spawns) an identical
    /// launch.
    pub operation_id: OperationId,
    /// Protected dispatch file path the child reads.
    pub material_path: PathBuf,
    /// Composition-pinned child executable path.
    pub executable: PathBuf,
    /// Expected SHA-256 digest of the child executable image.
    pub executable_sha256: String,
    /// Composition-pinned child working directory.
    pub working_directory: PathBuf,
    /// Live authority epoch bound at launch.
    pub authority_epoch: EpochId,
    /// Live activation generation bound at launch.
    pub generation: Generation,
}

/// Outcome of one Dreamer admit-then-launch call.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub enum DreamerLaunchOutcome {
    /// The child was spawned through the admitted executor.
    Launched {
        /// The launch nonce retained for the claim-time session proof.
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
        /// The launch nonce retained for the session proof.
        nonce: String,
        /// Child process operation identity.
        operation_id: OperationId,
    },
    /// An exact resubmit under one job identity: carries the retained
    /// original record, and no second child is spawned.
    ReplayOriginal {
        /// The original lineage for the job identity.
        record: Box<DreamerLaunchRecord>,
    },
    /// Admitted but needing no child; carries the response and the reason.
    NotLaunched {
        /// The admitted response for the job identity.
        response: Box<DurableJobResponse>,
        /// Why no child was spawned.
        skip: DreamerLaunchSkip,
    },
    /// The admitted response does not answer the presented keys; carries
    /// the reason, never a lineage.
    Refused(String),
}

/// Maps a contour error into the Dreamer launch error: caller-material
/// defects stay `InvalidMaterial`, everything else fails closed as `Gate`.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
fn dreamer_launch_error(error: DispatchLaunchError) -> DreamerMaterialError {
    match error {
        DispatchLaunchError::InvalidMaterial(detail) => {
            DreamerMaterialError::InvalidMaterial(detail)
        }
        other => DreamerMaterialError::Gate(other.to_string()),
    }
}

/// Admits one Dreamer job and prepares its launch: lineage-bound material
/// written to the protected dispatch file, ready to spawn.
///
/// Sequence: validate the caller keys plus the composition-pinned child
/// binding; validate the Kernel-loaded `QUEUED` response through its owning
/// K0 contract and require it to answer the presented job/attempt (anything
/// else is `Refused`, never staged); skip non-`QUEUED` responses without
/// spawning; reserve the original job identity single-flight (exact
/// resubmits return the retained original record, changed terms under one
/// identity refuse); mint the replay-stable nonce plus the shared launch
/// grant through the contour entries; closed-loop prove the staged envelope
/// against the exact child contract plus a parse readback; write through
/// [`write_material_file`]. Nothing is spawned here:
/// [`launch_admitted_dreamer_attempt`] spawns the returned
/// [`ReadyDreamerLaunch`] through the admitted executor.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
#[allow(
    clippy::too_many_lines,
    reason = "admit, reserve, nonce, grant, closed-loop proof, and material-write stay in one ordered authority path so no launch step can run before its gate"
)]
pub fn prepare_dreamer_launch(
    kernel: &KernelComposition,
    material: &DreamerLaunchMaterial<'_>,
    now_unix_nanos: u64,
) -> Result<PreparedDreamerLaunch, DreamerMaterialError> {
    use dreamer_dispatch_launch::{
        dreamer_material_bytes, mint_dreamer_nonce, note_dreamer_material_path,
        parse_dreamer_material_bytes, release_dreamer_reservation, reserve_dreamer_launch,
        validate_dreamer_child_binding, validate_dreamer_launch_keys, validate_dreamer_material,
    };
    if now_unix_nanos == 0 {
        return Err(DreamerMaterialError::InvalidMaterial(
            "admission time must be non-zero".to_owned(),
        ));
    }
    validate_dreamer_launch_keys(&material.keys)?;
    validate_dreamer_child_binding(&material.child)?;
    let material_dir = material.child.executable.parent().ok_or_else(|| {
        DreamerMaterialError::InvalidMaterial(
            "dreamer child executable has no parent directory".to_owned(),
        )
    })?;
    material
        .queued
        .validate()
        .map_err(|error| DreamerMaterialError::InvalidMaterial(error.to_string()))?;
    if material.queued.state != JobState::Queued {
        return Ok(PreparedDreamerLaunch::Skipped {
            response: Box::new(material.queued.clone()),
            skip: DreamerLaunchSkip::NotQueued,
        });
    }
    if material.queued.job_id.as_str() != material.keys.job_id
        || material.queued.attempt_id.as_str() != material.keys.attempt_id
    {
        return Ok(PreparedDreamerLaunch::Refused(
            "admitted dreamer response does not answer the presented job attempt".to_owned(),
        ));
    }
    let (authority_epoch, generation) = {
        let service = kernel
            .service
            .lock()
            .map_err(|_| DreamerMaterialError::Gate("kernel service lock poisoned".to_owned()))?;
        let epoch = service.authority_epoch();
        let generation = service
            .activation_receipt()
            .map_or(0, |receipt| receipt.generation.value());
        (epoch, generation)
    };
    if generation == 0 {
        return Err(DreamerMaterialError::Gate(
            "live activation generation is unavailable".to_owned(),
        ));
    }
    let generation = Generation::new(generation)
        .map_err(|error| DreamerMaterialError::Gate(error.to_string()))?;
    let scope_id = material.queued.scope.scope_id.as_str().to_owned();
    let fence = material.queued.scope.state_fence.clone();
    let revision = material.queued.revision;
    let nonce = mint_dreamer_nonce(
        material.keys.job_id,
        material.keys.attempt_id,
        revision,
        &authority_epoch,
        generation.get(),
        material.child.executable_sha256,
    )?;
    let identity_digest = super::sha256_hex(
        format!(
            "dreamer-launch|{}|{}|{revision}",
            material.keys.job_id, material.keys.attempt_id
        )
        .as_bytes(),
    );
    let operation_id = OperationId::new(format!(
        "{}-{}-{}",
        DispatchedWorkerKind::Dreamer.operation_prefix(),
        generation.get(),
        short_identity(&identity_digest).map_err(dreamer_launch_error)?
    ))
    .map_err(|error| DreamerMaterialError::Gate(error.to_string()))?;
    let grant = dispatch_grant_for(
        DispatchedWorkerKind::Dreamer,
        &identity_digest,
        &authority_epoch,
        generation,
        now_unix_nanos,
    )
    .map_err(dreamer_launch_error)?;
    // Single-flight reservation under the original job identity: a
    // reserved or launched identity replays by that identity instead of
    // spawning a second child. The reservation releases below when the
    // closed-loop proof or the material write fails.
    let record = DreamerLaunchRecord {
        job_id: material.keys.job_id.to_owned(),
        attempt_id: material.keys.attempt_id.to_owned(),
        revision,
        scope_id: scope_id.clone(),
        fence: fence.clone(),
        executable_sha256: material.child.executable_sha256.to_owned(),
        material_path: None,
        nonce: nonce.clone(),
        operation_id: operation_id_string(&operation_id),
        grant_digest: grant.grant_digest.clone(),
        phase: DreamerLaunchPhase::Reserved,
    };
    if let DreamerReserveOutcome::ReplayOriginal(retained) = reserve_dreamer_launch(record)? {
        return Ok(PreparedDreamerLaunch::ReplayOriginal { record: retained });
    }
    let envelope = DreamerDispatchedEnvelope {
        job_id: material.keys.job_id.to_owned(),
        attempt_id: material.keys.attempt_id.to_owned(),
        revision,
        scope_id,
        fence,
        epoch: authority_epoch.clone(),
        generation: generation.get(),
        nonce: nonce.clone(),
        grant,
    };
    // Closed-loop proof before staging: the envelope must satisfy the exact
    // child contract under the live epoch, and the staged bytes must parse
    // back byte-identical through the closed shape.
    let validated = validate_dreamer_material(&envelope, &authority_epoch).inspect_err(|_| {
        release_dreamer_reservation(material.keys.job_id);
    })?;
    if validated.generation != generation.get()
        || validated.epoch != authority_epoch
        || validated.nonce != nonce
    {
        release_dreamer_reservation(material.keys.job_id);
        return Err(DreamerMaterialError::InvalidMaterial(
            "dreamer launch invariant failed before staging".to_owned(),
        ));
    }
    let bytes = dreamer_material_bytes(&envelope).inspect_err(|_| {
        release_dreamer_reservation(material.keys.job_id);
    })?;
    let roundtrip = parse_dreamer_material_bytes(&bytes).inspect_err(|_| {
        release_dreamer_reservation(material.keys.job_id);
    })?;
    if roundtrip != envelope {
        release_dreamer_reservation(material.keys.job_id);
        return Err(DreamerMaterialError::Io(
            "dreamer dispatch material readback disagrees with its binding".to_owned(),
        ));
    }
    let Some(file_name) = DispatchedWorkerKind::Dreamer.material_file_name() else {
        release_dreamer_reservation(material.keys.job_id);
        return Err(DreamerMaterialError::Gate(
            "dreamer defines no dispatch material file".to_owned(),
        ));
    };
    let material_path = material_dir.to_path_buf().join(file_name);
    if let Err(error) = write_material_file(&material_path, &bytes) {
        release_dreamer_reservation(material.keys.job_id);
        return Err(DreamerMaterialError::Io(error.to_string()));
    }
    note_dreamer_material_path(material.keys.job_id, material_path.clone());
    Ok(PreparedDreamerLaunch::Ready(ReadyDreamerLaunch {
        job_id: material.keys.job_id.to_owned(),
        nonce,
        operation_id,
        material_path,
        executable: material.child.executable.to_path_buf(),
        executable_sha256: material.child.executable_sha256.to_owned(),
        working_directory: material.child.working_directory.to_path_buf(),
        authority_epoch,
        generation,
    }))
}

/// Spawns one prepared Dreamer launch through the admitted process gateway.
///
/// Same seam shape as the Doctor/testd/native spawns: empty argv,
/// secret-free environment, bounded limits, pinned path proof, Kernel-owned
/// process owner. The admitted-job material travels only over the protected
/// dispatch file the child reads; a spawn failure reaps the file
/// best-effort so a stale presentation never lingers.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub async fn start_ready_dreamer_launch(
    kernel: &KernelComposition,
    ready: &ReadyDreamerLaunch,
) -> Result<ChildStartOutcome, DreamerMaterialError> {
    match spawn_ready_child(
        kernel,
        &SpawnInputs {
            kind: DispatchedWorkerKind::Dreamer,
            operation_id: &ready.operation_id,
            executable: &ready.executable,
            executable_sha256: &ready.executable_sha256,
            working_directory: &ready.working_directory,
            generation: ready.generation,
            authority_epoch: &ready.authority_epoch,
            material_path: Some(ready.material_path.as_path()),
        },
    )
    .await
    .map_err(dreamer_launch_error)?
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

/// Admits one Dreamer job, then launches the real `eliot-dreamer` binary
/// through the admitted process executor.
///
/// Admit-then-launch in one seam, mirroring the testd/native calls: prepare
/// admits and reserves the original job identity plus writes the
/// admitted-job material, then the ready launch spawns and the identity is
/// retained. Exact resubmits return the retained original record without
/// spawning; refusals and skips return as outcomes; a failed spawn reaps
/// the file and releases the reservation; an unknown spawn outcome retains
/// the launch as unreconciled for
/// [`reconcile_launched_dreamer_attempt`].
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub async fn launch_admitted_dreamer_attempt(
    kernel: &KernelComposition,
    material: &DreamerLaunchMaterial<'_>,
    now_unix_nanos: u64,
) -> Result<DreamerLaunchOutcome, DreamerMaterialError> {
    use dreamer_dispatch_launch::{release_dreamer_reservation, retain_dreamer_launch_as};
    let prepared = prepare_dreamer_launch(kernel, material, now_unix_nanos)?;
    let ready = match prepared {
        PreparedDreamerLaunch::Ready(ready) => ready,
        PreparedDreamerLaunch::ReplayOriginal { record } => {
            return Ok(DreamerLaunchOutcome::ReplayOriginal { record });
        }
        PreparedDreamerLaunch::Skipped { response, skip } => {
            return Ok(DreamerLaunchOutcome::NotLaunched { response, skip });
        }
        PreparedDreamerLaunch::Refused(reason) => {
            return Ok(DreamerLaunchOutcome::Refused(reason));
        }
    };
    let job_id = ready.job_id.clone();
    let material_path = ready.material_path.clone();
    match start_ready_dreamer_launch(kernel, &ready).await {
        Ok(ChildStartOutcome::Started(spawned)) => {
            retain_dreamer_launch_as(&job_id, DreamerLaunchPhase::Launched, Some(material_path))?;
            Ok(DreamerLaunchOutcome::Launched {
                nonce: ready.nonce,
                operation_id: ready.operation_id,
                receipt: Box::new(spawned.receipt),
            })
        }
        Ok(ChildStartOutcome::Unknown(uncertain)) => {
            // The uncertain spawn carries the same deterministic operation
            // identity the reservation holds; reconciliation always names
            // the original lineage.
            debug_assert_eq!(uncertain.operation_id.as_str(), ready.operation_id.as_str());
            retain_dreamer_launch_as(
                &job_id,
                DreamerLaunchPhase::Unreconciled,
                Some(material_path),
            )?;
            Ok(DreamerLaunchOutcome::LaunchUnknown {
                nonce: ready.nonce,
                operation_id: ready.operation_id,
            })
        }
        Err(error) => {
            reap_material_file(&material_path);
            release_dreamer_reservation(&job_id);
            Err(error)
        }
    }
}

/// Reconciles one launched-but-unreconciled Dreamer job by its original job
/// identity.
///
/// The presented expectation must reproduce the retained lineage exactly
/// under still-current authority; no new lineage is minted, no new job id
/// is computed, and no second child is spawned. A converged lineage reaps
/// the dispatch file best-effort and closes the slot; anything still
/// outstanding stays unreconciled for a later call. Unknown identities
/// report unknown instead of inventing state.
///
/// Note: durable job terminality lives in the Store Dreamer ledger, so an
/// operator release through
/// [`dreamer_dispatch_launch::release_dreamer_launch`] (or a process
/// restart) is the only slot release besides this reconcile — the same
/// shape as the testd arm.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub fn reconcile_launched_dreamer_attempt(
    kernel: &KernelComposition,
    expected: &DreamerLeaseExpectation,
) -> Result<DreamerReconcileOutcome, DreamerMaterialError> {
    let live_epoch = kernel
        .service
        .lock()
        .map_err(|_| DreamerMaterialError::Gate("kernel service lock poisoned".to_owned()))?
        .authority_epoch();
    let outcome = dreamer_dispatch_launch::reconcile_dreamer_launch(expected, &live_epoch)?;
    if let DreamerReconcileOutcome::Reconciled {
        material_path: Some(path),
        ..
    } = &outcome
    {
        reap_material_file(path);
    }
    Ok(outcome)
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
    //!
    //! The T6-D2 trigger (plan slice 5) is proven bins-side for every class
    //! short of a real admission: refusal, replay, and forgery through the
    //! real gate, contour-material derivation from the composed registry,
    //! and replay-stable material bytes. The admitted-to-spawn leg awaits
    //! the same registry-fixture residual plus the production call-in
    //! (`lib.rs` re-export and the `main` binding injection,
    //! manager-serialized).

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

    fn native_live_fence() -> eliot_contracts::StateFence {
        eliot_contracts::StateFence::new(test_epoch(1), ResourceGeneration::genesis())
    }

    /// Exact process invocation value the R1 Governor producer canonicalizes.
    ///
    /// The same `canonical_json_bytes` + `sha256_hex` the Governor
    /// `process_invocation_digest_for` helper runs, so the join below carries
    /// the real record digest into the dispatch gate instead of a placeholder.
    fn native_test_invocation(claim_id: &str, operation_id: &str) -> serde_json::Value {
        serde_json::json!({
            "claim_id": claim_id,
            "operation_id": operation_id,
            "argv": ["--check"],
            "fence": {"generation": 1},
        })
    }

    /// Derives the R1 production `process_invocation_digest` from the exact
    /// invocation bytes (never canned).
    fn native_test_invocation_digest(claim_id: &str, operation_id: &str) -> String {
        let invocation = native_test_invocation(claim_id, operation_id);
        let bytes =
            eliot_contracts::canonical_json_bytes(&invocation).expect("canonical invocation");
        eliot_contracts::sha256_hex(&bytes)
    }

    /// Derives the opaque owner-produced executable digest from the real
    /// published binding material through the real hash procedure.
    ///
    /// Carried by value and compared for equality only (the route never
    /// recomputes the Governor domain); derived here from the claim-bound
    /// nonce plus the real invocation digest so no stand-in seed remains on
    /// the exercised path.
    fn native_test_owner_digest(
        claim_id: &str,
        operation_id: &str,
        nonce: &str,
        invocation_digest: &str,
    ) -> String {
        let material = serde_json::json!({
            "claim_id": claim_id,
            "operation_id": operation_id,
            "launch_nonce": nonce,
            "process_invocation_digest": invocation_digest,
        });
        let bytes =
            eliot_contracts::canonical_json_bytes(&material).expect("canonical owner material");
        eliot_contracts::sha256_hex(&bytes)
    }

    fn native_executable_join_for(
        claim_id: &str,
        operation_id: &str,
    ) -> eliot_kernel_service::NativeWorkerExecutableBinding {
        // Fixed times bound to the lifecycle admit time (1_750_000_000_000
        // ms): well-formed (deadline < expiry, non-zero) and live at admit.
        // Both digests are derived from the real binding record through the
        // production canonical procedure, never canned.
        let nonce = "launch-nonce-0123456789abcdef";
        let invocation_digest = native_test_invocation_digest(claim_id, operation_id);
        let owner_digest =
            native_test_owner_digest(claim_id, operation_id, nonce, &invocation_digest);
        eliot_kernel_service::NativeWorkerExecutableBinding {
            route_ref: "route://test/full-canonical-route".to_owned(),
            adapter_id: "adapter-test".to_owned(),
            adapter_revision: 3,
            config_digest: "b".repeat(64),
            facet_manifest_ref: "facet-manifest-7".to_owned(),
            grant_graph_revision: 5,
            replay_stream_id: "stream-claim-t9-02-1/gen-1".to_owned(),
            launch_nonce: nonce.to_owned(),
            process_invocation_digest: invocation_digest,
            authority_epoch: test_epoch(1),
            generation: ResourceGeneration::genesis(),
            state_fence: native_live_fence(),
            deadline_unix_ms: 1_750_000_100_000,
            expires_at_unix_ms: 1_750_000_200_000,
            executable_wire_version:
                eliot_kernel_service::NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
            executable_binding_digest: owner_digest,
        }
    }

    fn native_claim_request(
        claim_id: &str,
        registration_id: &str,
        attempt_id: &str,
        operation_id: &str,
    ) -> eliot_kernel_service::NativeWorkerClaimRequest {
        use eliot_kernel_service::{
            NATIVE_WORKER_CLAIM_WIRE_ID, NATIVE_WORKER_CLAIM_WIRE_VERSION,
            NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION, NATIVE_WORKER_PROTOCOL_VERSION,
            NativeWorkerClaimBudget,
        };
        let mut request = eliot_kernel_service::NativeWorkerClaimRequest {
            wire_id: NATIVE_WORKER_CLAIM_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_CLAIM_WIRE_VERSION,
            claim_id: claim_id.to_owned(),
            registration_id: registration_id.to_owned(),
            worker_generation: 1,
            installation_id: "installation-1".to_owned(),
            worker_artifact_digest: "a".repeat(64),
            worker_config_digest: "b".repeat(64),
            protocol_version: NATIVE_WORKER_PROTOCOL_VERSION.to_owned(),
            execution_unit_schema_version: NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION,
            parent_job_id: "parent-job-1".to_owned(),
            task_id: "task-1".to_owned(),
            work_scope_id: "scope-1".to_owned(),
            decision_id: "decision-1".to_owned(),
            attempt_id: attempt_id.to_owned(),
            operation_id: operation_id.to_owned(),
            route_class: "test-route".to_owned(),
            budget: NativeWorkerClaimBudget {
                context_tokens: 8,
                wall_time_ms: 1_000,
                output_bytes: 1_024,
                cost_microunits: 10,
                max_depth: 2,
                max_descendants: 4,
            },
            deadline_unix_ms: 1_750_000_120_000,
            cancellation_policy_id: "cancel-1".to_owned(),
            expected_result_schema: "result-schema".to_owned(),
            expected_result_schema_version: 1,
            predecessor_revision: "rev-1".to_owned(),
            authority_epoch: test_epoch(1),
            state_fence: native_live_fence(),
            executable_binding: Some(native_executable_join_for(claim_id, operation_id)),
            binding_digest: String::new(),
            request_digest: String::new(),
        };
        request.binding_digest = request.compute_binding_digest().expect("binding digest");
        request.request_digest = request.canonical_request_digest().expect("request digest");
        request.validate().expect("claim validates");
        request
            .validate_canonical_digest()
            .expect("canonical digest validates");
        request
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
    /// the production Doctor side composes once (durable ledger plus
    /// health-probe registry) and refuses a second composition; the
    /// heartbeat carries the composed flag; testd prepare reserves,
    /// replays by the retained original, refuses changed terms,
    /// reconciles, and releases; native prepare reserves the real claim
    /// through the live service plus ORS, writes the dispatch file with a
    /// validated grant, and reconciles by the durable record; launch
    /// without an executor fails closed and reaps. The live child-image
    /// steps run as separate ignored tests (TESTPHASE LIVE-DISPATCH-3).
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

        // 2b. The production testd/native sides compose once through their
        // installed digests (Implements #461 DISPATCH-WIRE E2E, mirroring
        // the `main` production order right after the contour): a valid
        // digest lands and flips only its own production-side marker, a
        // second composition is refused instead of replacing live
        // authority, and a malformed digest fails closed even once
        // composed. The child advertise probe keeps its contour-cell
        // semantics, so this step changes no admit behavior below.
        let installed_testd_digest =
            eliot_contracts::sha256_hex(b"eliot-testd-installed-package-bytes");
        compose_production_testd_front_door(&installed_testd_digest)
            .expect("production testd composition");
        assert!(
            testd_production_composed(),
            "composed testd side must report composed"
        );
        assert!(matches!(
            compose_production_testd_front_door(&installed_testd_digest),
            Err(DispatchLaunchError::AlreadyComposed(_))
        ));
        let installed_native_digest =
            eliot_contracts::sha256_hex(b"eliot-native-worker-installed-package-bytes");
        compose_production_native_worker_front_door(&installed_native_digest)
            .expect("production native composition");
        assert!(
            native_worker_production_composed(),
            "composed native side must report composed"
        );
        assert!(matches!(
            compose_production_native_worker_front_door(&installed_native_digest),
            Err(DispatchLaunchError::AlreadyComposed(_))
        ));
        assert!(matches!(
            compose_production_testd_front_door("not-a-sha256-digest"),
            Err(DispatchLaunchError::InvalidMaterial(_))
        ));
        assert!(matches!(
            compose_production_native_worker_front_door("not-a-sha256-digest"),
            Err(DispatchLaunchError::InvalidMaterial(_))
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
        // DISPATCH-CAUSE-FIX: testd prepare now writes material (was None).
        // The file lives next to the child executable and carries the same
        // grant object the child uses for its local dispatch authority.
        let testd_file = child_dir.join(
            DispatchedWorkerKind::Testd
                .material_file_name()
                .expect("testd material file"),
        );
        assert_eq!(
            testd_file, first_ready.material_path,
            "ready carries the protected dispatch path"
        );
        assert!(
            testd_file.exists(),
            "testd prepare writes the admitted-attempt material file"
        );
        let testd_bytes = std::fs::read(&testd_file).expect("read testd material");
        let testd_json: serde_json::Value =
            serde_json::from_slice(&testd_bytes).expect("testd material is JSON");
        let testd_object = testd_json.as_object().expect("testd material object");
        for key in [
            "request",
            "envelope",
            "admission",
            "epoch",
            "generation",
            "nonce",
            "grant",
        ] {
            assert!(
                testd_object.contains_key(key),
                "testd material carries {key}"
            );
        }
        let testd_grant: DispatchGrant =
            serde_json::from_value(testd_object["grant"].clone()).expect("testd grant parses");
        assert_eq!(testd_grant.authority_epoch, epoch);
        assert_eq!(testd_grant.fence_generation, 1);
        testd_grant
            .validate_for_child()
            .expect("testd grant validates");
        assert_eq!(
            testd_object["nonce"],
            serde_json::json!(first_ready.nonce),
            "material nonce equals the retained session nonce"
        );
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
        // Reconcile reaps the dispatch file best-effort so a stale
        // presentation never lingers.
        assert!(!testd_file.exists(), "reconciled testd material is reaped");
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

        // 5b. Native-worker prepare reserves, writes material with the same
        // grant object, replays by the retained original, reconciles by the
        // ORS record, and releases. Real admission through the live service
        // plus the real ORS claim table; no mocks.
        assert_eq!(
            DispatchedWorkerKind::NativeWorker.module_id(),
            "eliot-native-worker"
        );
        assert_eq!(
            DispatchedWorkerKind::NativeWorker.wire_id(),
            "eliot.kernel.native-worker-claim"
        );
        assert_eq!(
            DispatchedWorkerKind::NativeWorker.material_file_name(),
            Some("eliot-native-worker.admitted-claim.json")
        );
        let native_request =
            native_claim_request("claim-dispatch-1", "reg-dispatch-1", "attempt-1", "op-1");
        let native_material = NativeWorkerLaunchMaterial {
            request: &native_request,
            executable: &child_dir.join("eliot-native-worker.exe"),
            executable_sha256: &"ef".repeat(32),
            working_directory: &child_dir,
        };
        let native_first =
            prepare_native_worker_launch(&kernel, &native_material, now_nanos).expect("prepare");
        let PreparedNativeWorkerLaunch::Ready(native_ready) = native_first else {
            panic!("first native prepare must be ready");
        };
        assert_eq!(native_ready.receipt.claim_id, "claim-dispatch-1");
        assert_nonce_shape(&native_ready.nonce);
        let native_file = child_dir.join(
            DispatchedWorkerKind::NativeWorker
                .material_file_name()
                .expect("native material file"),
        );
        assert_eq!(
            native_file, native_ready.material_path,
            "native ready carries the protected dispatch path"
        );
        assert!(
            native_file.exists(),
            "native prepare writes the admitted-claim material file"
        );
        let native_bytes = std::fs::read(&native_file).expect("read native material");
        let native_json: serde_json::Value =
            serde_json::from_slice(&native_bytes).expect("native material is JSON");
        let native_object = native_json.as_object().expect("native material object");
        for key in [
            "request",
            "receipt",
            "epoch",
            "generation",
            "nonce",
            "grant",
        ] {
            assert!(
                native_object.contains_key(key),
                "native material carries {key}"
            );
        }
        let native_grant: DispatchGrant =
            serde_json::from_value(native_object["grant"].clone()).expect("native grant parses");
        assert_eq!(native_grant.authority_epoch, epoch);
        native_grant
            .validate_for_child()
            .expect("native grant validates");
        assert_eq!(
            native_object["nonce"],
            serde_json::json!(native_ready.nonce),
            "native material nonce equals the retained session nonce"
        );
        // Exact resubmit replays the original receipt, never a recompute.
        let native_second =
            prepare_native_worker_launch(&kernel, &native_material, now_nanos + 1_000_000)
                .expect("replay prepare");
        let PreparedNativeWorkerLaunch::ReplayOriginal {
            receipt: native_replayed,
        } = native_second
        else {
            panic!("exact native resubmit must replay the original");
        };
        assert_eq!(
            native_replayed.receipt_digest, native_ready.receipt.receipt_digest,
            "native replay reconciles by the original receipt identity"
        );
        // Reconcile proves the durable ORS record still binds the receipt.
        let native_reconcile =
            reconcile_launched_native_worker_attempt(&kernel, "claim-dispatch-1")
                .expect("native reconcile");
        assert!(matches!(
            native_reconcile,
            ReconcileLaunchedOutcome::Reconciled { .. }
        ));
        assert!(
            !native_file.exists(),
            "reconciled native material is reaped"
        );
        // Release uses the retained request digest (the ORS-backed binding),
        // never a recomputed id: stale digests never free the slot.
        assert!(
            !release_launched_attempt(
                DispatchedWorkerKind::NativeWorker,
                "claim-dispatch-1",
                &"00".repeat(32),
            )
            .expect("stale native release"),
            "stale native release never frees the slot"
        );
        assert!(
            release_launched_attempt(
                DispatchedWorkerKind::NativeWorker,
                "claim-dispatch-1",
                &native_request.request_digest,
            )
            .expect("exact native release"),
            "exact native release frees the slot"
        );
        assert!(matches!(
            reconcile_launched_native_worker_attempt(&kernel, "claim-dispatch-1")
                .expect("native reconcile after release"),
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
        assert!(
            !child_dir.join("eliot-testd.admitted-attempt.json").exists(),
            "failed testd launch reaps its material and releases the slot"
        );
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

        // 8. The production Doctor side composes once through the durable
        // Kernel-owned ledger plus the installed-health-probe registry: the
        // advertisement flips, and a second composition fails closed
        // instead of replacing live authority. This runs last because the
        // earlier steps prove the uncomposed fail-closed shape.
        let doctor_dir = root.join("doctor-ledger");
        std::fs::create_dir_all(&doctor_dir).expect("doctor ledger dir");
        let production_ledger = Arc::new(
            crate::KernelDoctorRecoveryLedger::open(&doctor_dir).expect("production doctor ledger"),
        );
        let installed_doctor_digest =
            eliot_contracts::sha256_hex(b"eliot-doctor-installed-package-bytes");
        compose_production_doctor_front_door(
            Arc::clone(&production_ledger),
            &installed_doctor_digest,
        )
        .expect("production doctor composition");
        assert!(
            doctor_repair_advertised(),
            "composed doctor side must advertise repair"
        );
        assert!(matches!(
            compose_production_doctor_front_door(production_ledger, &installed_doctor_digest),
            Err(DispatchLaunchError::AlreadyComposed(_))
        ));

        // 9. T6-D2 trigger (issue #461, plan slice 5): the contour-owned
        // trigger refuses without staging and derives contour material.
        // Shape-valid-but-empty envelopes refuse typed through the real
        // gate (no admission, no file, no slot); a well-formed wire
        // forgery with recomputed digests refuses typed the same way; a
        // tampered digest fails closed before any gate; a replay of a
        // refused attempt refuses again without staging anything new. The
        // derived contour material (admitted manifest revision plus
        // installed executable digest, read back from the composed
        // registry) flows through the real prepare seam, which refuses
        // the shape request typed — proving the trigger constructs
        // exactly what prepare validates.
        let trigger_child_dir = root.join("doctor-trigger-child");
        std::fs::create_dir_all(&trigger_child_dir).expect("trigger child dir");
        let trigger_executable = trigger_child_dir.join("eliot-doctor.exe");
        let trigger_binding = DoctorChildBinding {
            executable: &trigger_executable,
            working_directory: &trigger_child_dir,
        };
        let trigger_file = trigger_child_dir.join(
            DispatchedWorkerKind::Doctor
                .material_file_name()
                .expect("doctor material file"),
        );
        let trigger_shape_request = |attempt_id: &str| DoctorRepairAttemptRequest {
            wire_id: eliot_kernel_service::DOCTOR_REPAIR_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::DOCTOR_REPAIR_WIRE_VERSION,
            attempt_id: attempt_id.to_owned(),
            effect_seq: 0,
            closed_request_json: "{}".to_owned(),
            target_resource_digest: "1".repeat(64),
            request_digest: String::new(),
        }
        .with_computed_digest()
        .expect("trigger request digest");
        assert!(
            matches!(
                trigger_admitted_doctor_launch(
                    &kernel,
                    &trigger_shape_request("attempt-trigger-refused-1"),
                    &trigger_binding,
                    now_nanos,
                )
                .await,
                Ok(DoctorLaunchOutcome::Refused(_))
            ),
            "shape-valid-but-empty trigger attempt refuses typed"
        );
        assert!(
            !trigger_file.exists(),
            "refused trigger attempt stages no dispatch material"
        );
        let mut forged = trigger_shape_request("attempt-trigger-forged-1");
        forged.closed_request_json = r#"{"forged":true}"#.to_owned();
        forged.request_digest = String::new();
        let forged = forged
            .with_computed_digest()
            .expect("forged request digest");
        assert!(
            matches!(
                trigger_admitted_doctor_launch(&kernel, &forged, &trigger_binding, now_nanos,).await,
                Ok(DoctorLaunchOutcome::Refused(_))
            ),
            "well-formed wire forgery refuses typed"
        );
        assert!(
            !trigger_file.exists(),
            "wire forgery stages no dispatch material"
        );
        let mut tampered = trigger_shape_request("attempt-trigger-tampered-1");
        tampered.request_digest = "00".repeat(32);
        assert!(
            matches!(
                trigger_admitted_doctor_launch(&kernel, &tampered, &trigger_binding, now_nanos,)
                    .await,
                Ok(DoctorLaunchOutcome::Refused(_))
            ),
            "tampered digest refuses typed before any staging"
        );
        assert!(
            !trigger_file.exists(),
            "tampered digest stages no dispatch material"
        );
        assert!(
            matches!(
                trigger_admitted_doctor_launch(
                    &kernel,
                    &trigger_shape_request("attempt-trigger-refused-1"),
                    &trigger_binding,
                    now_nanos + 5_000_000,
                )
                .await,
                Ok(DoctorLaunchOutcome::Refused(_))
            ),
            "replay of a refused attempt refuses again"
        );
        assert!(
            !trigger_file.exists(),
            "replay of a refusal stages nothing new"
        );
        let composed_registry = dispatch_contour()
            .expect("composed contour")
            .doctor
            .lock()
            .expect("doctor front-door lock")
            .as_ref()
            .expect("composed doctor side")
            .registry
            .clone();
        let trigger_admission = DoctorRepairAdmission {
            wire_id: eliot_kernel_service::DOCTOR_REPAIR_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::DOCTOR_REPAIR_WIRE_VERSION,
            attempt_id: "attempt-trigger-derived-1".to_owned(),
            attempt_digest: "ab".repeat(32),
            effect_digest: Some("cd".repeat(32)),
            recipe_digest: "ef".repeat(32),
            manifest_digest: composed_registry.manifest_digest().to_owned(),
            operation_id: composed_registry.manifest().operations[0].operation_id.clone(),
            lease_id: "lease-trigger-1".to_owned(),
            lease_owner: "kernel.doctor-recovery".to_owned(),
            lease_expires_unix_nanos: now_nanos + 60_000_000_000,
            allowed_effects: [composed_registry.manifest().operations[0].operation_id.clone()]
                .into_iter()
                .collect(),
            budget_units: 1,
            deadline_unix_nanos: now_nanos + 60_000_000_000,
            approval_present: false,
            cancelled: false,
            admitted_at_unix_nanos: now_nanos,
            admission_digest: "12".repeat(32),
        };
        let derived = contour_doctor_material(&composed_registry, &trigger_admission)
            .expect("contour material derives");
        assert_eq!(
            derived.manifest_json,
            serde_json::to_value(composed_registry.manifest()).expect("manifest json"),
            "derived manifest is the composed manifest revision"
        );
        assert_eq!(
            derived.executable_sha256, installed_doctor_digest,
            "derived executable digest is the composed installed digest"
        );
        let derived_material = DoctorLaunchMaterial {
            attempt: &trigger_shape_request("attempt-trigger-derived-1"),
            request_json: &serde_json::json!({}),
            manifest_json: &derived.manifest_json,
            executable: &trigger_executable,
            executable_sha256: &derived.executable_sha256,
            working_directory: &trigger_child_dir,
        };
        assert!(
            matches!(
                prepare_doctor_launch(&kernel, &derived_material, now_nanos),
                Ok(PreparedDoctorLaunch::Refused(_))
            ),
            "derived contour material flows through the real prepare seam"
        );
        assert!(
            !trigger_file.exists(),
            "derived-material refusal stages no dispatch material"
        );
        let forged_operation = DoctorRepairAdmission {
            operation_id: "forged-operation-9".to_owned(),
            ..trigger_admission.clone()
        };
        assert!(
            matches!(
                contour_doctor_material(&composed_registry, &forged_operation),
                Err(DispatchLaunchError::InvalidMaterial(_))
            ),
            "forged operation resolves no composed binding"
        );
        let stale_manifest = DoctorRepairAdmission {
            manifest_digest: "00".repeat(32),
            ..trigger_admission.clone()
        };
        assert!(
            matches!(
                contour_doctor_material(&composed_registry, &stale_manifest),
                Err(DispatchLaunchError::Inconsistent(_))
            ),
            "stale manifest binding never stages"
        );
        assert!(
            matches!(
                reconcile_launched_doctor_attempt(&"ff".repeat(32)).expect("reconcile"),
                ReconcileLaunchedOutcome::Unknown { .. }
            ),
            "reconcile reports unknown instead of inventing state"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    /// DISPATCH-LIVE native-worker image (Implements #461): the real
    /// `eliot-native-worker` image is admitted through the live service
    /// plus the real ORS claim table, bound to the protected dispatch file
    /// with a validated grant, and carried to the spawn boundary with the
    /// replay-stable owner derivation. Requires the built child binary, so
    /// it runs in TESTPHASE LIVE-DISPATCH-3 only.
    #[tokio::test]
    #[ignore = "live image: run in TESTPHASE LIVE-DISPATCH-3 after cargo build of the child binaries"]
    async fn dispatch_contour_lifecycle_native_live_image() {
        let root = temp_root("lifecycle-native-live");
        let kernel = ready_kernel(&root);
        let epoch = live_epoch(&kernel);
        assert_eq!(epoch, test_epoch(1));
        // Minimal contour for isolation: the contour cell is process-global
        // set-once state, so tolerate a prior composition when this test
        // shares its process with the in-process lifecycle test.
        if let Err(error) = compose_dispatch_contour(PRINCIPAL.to_owned()) {
            assert!(
                matches!(error, DispatchLaunchError::AlreadyComposed(_)),
                "compose contour: {error}"
            );
        }
        let now_nanos = 1_750_000_000_000_000_000u64;
        // 5c. DISPATCH-LIVE W-C E2E (kernel binary): the real
        // `eliot-native-worker` image is admitted through the live service
        // plus the real ORS claim table, bound to the protected dispatch
        // file with a validated grant, and carried to the spawn boundary
        // with the owner dispatch derivation every Governor join publisher
        // must source. No doubles: the claim request carries real computed
        // digests and the executable digest is read from the real image
        // bytes (staged as a byte-identical copy under this test root, so
        // the dispatch file never lands in the build tree).
        //
        // DEPENDS-ON-INTEGRATION: the final spawn-to-`Ready` step needs the
        // admitted process authority plus a live Kernel front door for the
        // child's register/claim/readiness submits, so this step proves
        // everything up to the spawn boundary in isolation and asserts the
        // exact fail-closed (`ExecutorUnavailable`, file reaped, slot
        // released) when no executor is configured.
        let live_child_dir = root.join("native-live-child");
        std::fs::create_dir_all(&live_child_dir).expect("live child dir");
        let live_binary = real_native_worker_binary();
        let live_bytes = std::fs::read(&live_binary).unwrap_or_else(|_| {
            panic!(
                "DEPENDS-ON-INTEGRATION: build the native worker image first \
                 (`cargo build -p eliot-native-worker`); missing {live_binary:?}"
            )
        });
        let live_digest = eliot_contracts::sha256_hex(&live_bytes);
        let staged_binary = live_child_dir.join(format!(
            "eliot-native-worker{}",
            std::env::consts::EXE_SUFFIX
        ));
        std::fs::write(&staged_binary, &live_bytes).expect("stage real image");
        assert_eq!(
            eliot_contracts::sha256_hex(
                &std::fs::read(&staged_binary).expect("staged image reads")
            ),
            live_digest,
            "staged image must stay byte-identical to the real binary"
        );
        let live_request = native_claim_request(
            "claim-dispatch-live-1",
            "reg-dispatch-live-1",
            "attempt-dispatch-live-1",
            "op-dispatch-live-1",
        );
        let live_material = NativeWorkerLaunchMaterial {
            request: &live_request,
            executable: &staged_binary,
            executable_sha256: &live_digest,
            working_directory: &live_child_dir,
        };
        let live_prepared =
            prepare_native_worker_launch(&kernel, &live_material, now_nanos).expect("prepare");
        let PreparedNativeWorkerLaunch::Ready(live_ready) = live_prepared else {
            panic!("live native prepare must be ready");
        };
        assert_eq!(live_ready.receipt.claim_id, "claim-dispatch-live-1");
        assert_nonce_shape(&live_ready.nonce);
        let live_file = live_child_dir.join(
            DispatchedWorkerKind::NativeWorker
                .material_file_name()
                .expect("native material file"),
        );
        assert_eq!(
            live_file, live_ready.material_path,
            "live native ready carries the protected dispatch path"
        );
        let live_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&live_file).expect("live dispatch file"))
                .expect("live dispatch file is JSON");
        let live_object = live_json.as_object().expect("live dispatch object");
        for key in [
            "request",
            "receipt",
            "epoch",
            "generation",
            "nonce",
            "grant",
        ] {
            assert!(
                live_object.contains_key(key),
                "live dispatch file carries {key}"
            );
        }
        assert_eq!(
            live_object["nonce"],
            serde_json::json!(live_ready.nonce),
            "live dispatch nonce equals the retained session nonce"
        );
        let live_grant: DispatchGrant =
            serde_json::from_value(live_object["grant"].clone()).expect("live grant parses");
        assert_eq!(live_grant.authority_epoch, epoch);
        live_grant
            .validate_for_child()
            .expect("live grant validates");
        // R1 owner record (Implements #22): the derivation every Governor
        // join publisher must source runs over the live admitted material
        // here. Deterministic: an exact recompute agrees bit-for-bit, so a
        // replay re-derives the identical owner record.
        let live_first = native_worker_dispatch_derivation(
            &live_request.claim_id,
            &live_request.operation_id,
            live_request.worker_generation,
            &epoch,
            &live_ready.nonce,
        )
        .expect("owner derivation builds over live material");
        let live_replay = native_worker_dispatch_derivation(
            &live_request.claim_id,
            &live_request.operation_id,
            live_request.worker_generation,
            &epoch,
            &live_ready.nonce,
        )
        .expect("owner derivation replays");
        assert_eq!(live_first, live_replay, "owner derivation is replay-stable");
        assert_eq!(
            live_first.authority_id.len(),
            NATIVE_WORKER_DISPATCH_AUTHORITY_PREFIX.len() + 64
        );
        assert!(
            live_first
                .authority_id
                .starts_with(NATIVE_WORKER_DISPATCH_AUTHORITY_PREFIX),
            "owner authority carries the child-identical prefix"
        );
        for digest in [&live_first.key_hex, &live_first.head_digest] {
            assert_eq!(digest.len(), 64, "derivation digests are SHA-256 hex");
            assert!(
                digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "derivation digests are lowercase hex"
            );
        }
        // No admitted process authority in isolation: a first launch of a
        // fresh claim fails closed at the spawn boundary (after its own
        // admit + material write), reaps the file, and releases the slot.
        let live_spawn_request = native_claim_request(
            "claim-dispatch-live-2",
            "reg-dispatch-live-2",
            "attempt-dispatch-live-2",
            "op-dispatch-live-2",
        );
        let live_spawn_material = NativeWorkerLaunchMaterial {
            request: &live_spawn_request,
            executable: &staged_binary,
            executable_sha256: &live_digest,
            working_directory: &live_child_dir,
        };
        assert!(matches!(
            launch_admitted_native_worker_attempt(&kernel, &live_spawn_material, now_nanos).await,
            Err(DispatchLaunchError::ExecutorUnavailable)
        ));
        assert!(
            !live_file.exists(),
            "failed live launch reaps its material and releases the slot"
        );
        assert!(matches!(
            reconcile_launched_native_worker_attempt(&kernel, "claim-dispatch-live-2")
                .expect("reconcile"),
            ReconcileLaunchedOutcome::Unknown { .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    /// DISPATCH-LIVE testd image (Implements #461): the real `eliot-testd`
    /// image is admitted through the live service plus the composed
    /// principal, bound to the protected dispatch file with a validated
    /// grant, and carried to the spawn boundary. Requires the built child
    /// binary, so it runs in TESTPHASE LIVE-DISPATCH-3 only.
    #[tokio::test]
    #[ignore = "live image: run in TESTPHASE LIVE-DISPATCH-3 after cargo build of the child binaries"]
    async fn dispatch_contour_lifecycle_testd_live_image() {
        let root = temp_root("lifecycle-testd-live");
        let kernel = ready_kernel(&root);
        let epoch = live_epoch(&kernel);
        assert_eq!(epoch, test_epoch(1));
        // Minimal contour for isolation: the contour cell is process-global
        // set-once state, so tolerate a prior composition when this test
        // shares its process with the in-process lifecycle test.
        if let Err(error) = compose_dispatch_contour(PRINCIPAL.to_owned()) {
            assert!(
                matches!(error, DispatchLaunchError::AlreadyComposed(_)),
                "compose contour: {error}"
            );
        }
        let now_nanos = 1_750_000_000_000_000_000u64;
        // 5d. DISPATCH-LIVE testd image (kernel binary, Implements #461):
        // the real `eliot-testd` image is admitted through the live service
        // plus the composed principal, bound to the protected dispatch file
        // with a validated grant, and carried to the spawn boundary. No
        // doubles: the request carries real computed digests and the
        // executable digest is read from the real image bytes (staged as a
        // byte-identical copy under this test root, so the dispatch file
        // never lands in the build tree).
        let testd_live_dir = root.join("testd-live-child");
        std::fs::create_dir_all(&testd_live_dir).expect("testd live child dir");
        let testd_binary = real_testd_binary();
        let testd_bytes = std::fs::read(&testd_binary).unwrap_or_else(|_| {
            panic!(
                "DEPENDS-ON-INTEGRATION: build the testd image first \
                 (`cargo build -p eliot-testd`); missing {testd_binary:?}"
            )
        });
        let testd_live_digest = eliot_contracts::sha256_hex(&testd_bytes);
        let staged_testd =
            testd_live_dir.join(format!("eliot-testd{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&staged_testd, &testd_bytes).expect("stage real testd image");
        assert_eq!(
            eliot_contracts::sha256_hex(
                &std::fs::read(&staged_testd).expect("staged testd image reads")
            ),
            testd_live_digest,
            "staged testd image must stay byte-identical to the real binary"
        );
        let testd_live_material = TestdLaunchMaterial {
            request: &testd_request(
                "job-dispatch-live-img-1",
                0,
                &testd_envelope(
                    "job-dispatch-live-img-1",
                    Some("test-operation-1"),
                    1,
                    &epoch,
                ),
            ),
            executable: &staged_testd,
            executable_sha256: &testd_live_digest,
            working_directory: &testd_live_dir,
        };
        let testd_live_prepared = prepare_testd_launch(&kernel, &testd_live_material, now_nanos)
            .expect("live testd prepare");
        let PreparedTestdLaunch::Ready(testd_live_ready) = testd_live_prepared else {
            panic!("live testd prepare must be ready");
        };
        assert_eq!(testd_live_ready.admission.job_id, "job-dispatch-live-img-1");
        assert_nonce_shape(&testd_live_ready.nonce);
        let testd_live_file = testd_live_dir.join(
            DispatchedWorkerKind::Testd
                .material_file_name()
                .expect("testd material file"),
        );
        assert_eq!(
            testd_live_file, testd_live_ready.material_path,
            "live testd ready carries the protected dispatch path"
        );
        let testd_live_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&testd_live_file).expect("live testd file"))
                .expect("live testd file is JSON");
        let testd_live_object = testd_live_json
            .as_object()
            .expect("live testd dispatch object");
        for key in [
            "request",
            "envelope",
            "admission",
            "epoch",
            "generation",
            "nonce",
            "grant",
        ] {
            assert!(
                testd_live_object.contains_key(key),
                "live testd dispatch file carries {key}"
            );
        }
        assert_eq!(
            testd_live_object["nonce"],
            serde_json::json!(testd_live_ready.nonce),
            "live testd dispatch nonce equals the retained session nonce"
        );
        let testd_live_grant: DispatchGrant =
            serde_json::from_value(testd_live_object["grant"].clone())
                .expect("live testd grant parses");
        assert_eq!(testd_live_grant.authority_epoch, epoch);
        testd_live_grant
            .validate_for_child()
            .expect("live testd grant validates");
        // No admitted process authority in isolation: a first launch of a
        // fresh job fails closed at the spawn boundary (after its own
        // admit + material write), reaps the file, and releases the slot.
        let testd_spawn_request = testd_request(
            "job-dispatch-live-img-2",
            0,
            &testd_envelope(
                "job-dispatch-live-img-2",
                Some("test-operation-1"),
                1,
                &epoch,
            ),
        );
        let testd_spawn_material = TestdLaunchMaterial {
            request: &testd_spawn_request,
            executable: &staged_testd,
            executable_sha256: &testd_live_digest,
            working_directory: &testd_live_dir,
        };
        assert!(matches!(
            launch_admitted_testd_attempt(&kernel, &testd_spawn_material, now_nanos).await,
            Err(DispatchLaunchError::ExecutorUnavailable)
        ));
        assert!(
            !testd_live_file.exists(),
            "failed live testd launch reaps its material and releases the slot"
        );
        assert!(matches!(
            reconcile_launched_testd_attempt(
                &kernel,
                "job-dispatch-live-img-2",
                &testd_spawn_request
            )
            .expect("reconcile"),
            ReconcileLaunchedOutcome::Unknown { .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    /// DISPATCH-LIVE doctor image (Implements #461): the real `eliot-doctor`
    /// image is staged byte-identical under the test root and bound by its
    /// real digest, then the admit gate refuses the shape-valid-but-empty
    /// closed request typed. Requires the built child binary, so it runs
    /// in TESTPHASE LIVE-DISPATCH-3 only.
    #[tokio::test]
    #[ignore = "live image: run in TESTPHASE LIVE-DISPATCH-3 after cargo build of the child binaries"]
    async fn dispatch_contour_lifecycle_doctor_live_image() {
        let root = temp_root("lifecycle-doctor-live");
        let kernel = ready_kernel(&root);
        // Minimal contour for isolation: the contour cell is process-global
        // set-once state, so tolerate a prior composition when this test
        // shares its process with the in-process lifecycle test.
        if let Err(error) = compose_dispatch_contour(PRINCIPAL.to_owned()) {
            assert!(
                matches!(error, DispatchLaunchError::AlreadyComposed(_)),
                "compose contour: {error}"
            );
        }
        let doctor_dir = root.join("doctor-ledger");
        std::fs::create_dir_all(&doctor_dir).expect("doctor ledger dir");
        let production_ledger = Arc::new(
            crate::KernelDoctorRecoveryLedger::open(&doctor_dir).expect("production doctor ledger"),
        );
        let installed_doctor_digest =
            eliot_contracts::sha256_hex(b"eliot-doctor-installed-package-bytes");
        if let Err(error) =
            compose_production_doctor_front_door(production_ledger, &installed_doctor_digest)
        {
            assert!(
                matches!(error, DispatchLaunchError::AlreadyComposed(_)),
                "compose doctor side: {error}"
            );
        }
        let now_nanos = 1_750_000_000_000_000_000u64;
        // 8b. DISPATCH-LIVE doctor image (kernel binary, Implements #461):
        // the real `eliot-doctor` image is staged byte-identical under this
        // test root and bound by its real digest, then the admit gate
        // refuses the shape-valid-but-empty closed request typed. No
        // doubles: the digest is read from the real image bytes, and the
        // refusal proves the live service plus the composed production
        // side ran (fully admitted envelopes are proven service-side,
        // where the registry fixtures live). Refusal writes no material
        // file, retains no slot, and spawns no child.
        let doctor_live_dir = root.join("doctor-live-child");
        std::fs::create_dir_all(&doctor_live_dir).expect("doctor live child dir");
        let doctor_binary = real_doctor_binary();
        let doctor_bytes = std::fs::read(&doctor_binary).unwrap_or_else(|_| {
            panic!(
                "DEPENDS-ON-INTEGRATION: build the doctor image first \
                 (`cargo build -p eliot-doctor`); missing {doctor_binary:?}"
            )
        });
        let doctor_live_digest = eliot_contracts::sha256_hex(&doctor_bytes);
        let staged_doctor =
            doctor_live_dir.join(format!("eliot-doctor{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&staged_doctor, &doctor_bytes).expect("stage real doctor image");
        assert_eq!(
            eliot_contracts::sha256_hex(
                &std::fs::read(&staged_doctor).expect("staged doctor image reads")
            ),
            doctor_live_digest,
            "staged doctor image must stay byte-identical to the real binary"
        );
        let doctor_live_material = DoctorLaunchMaterial {
            attempt: &shape_valid_doctor_request(),
            request_json: &serde_json::json!({}),
            manifest_json: &serde_json::json!({"manifest": "test"}),
            executable: &staged_doctor,
            executable_sha256: &doctor_live_digest,
            working_directory: &doctor_live_dir,
        };
        let doctor_live = prepare_doctor_launch(&kernel, &doctor_live_material, now_nanos)
            .expect("live doctor prepare answers");
        assert!(
            matches!(doctor_live, PreparedDoctorLaunch::Refused(_)),
            "shape-valid-but-empty doctor request is refused typed, never admitted"
        );
        assert!(
            !doctor_live_dir
                .join("eliot-doctor.dispatched-attempt.json")
                .exists(),
            "refused doctor prepare writes no dispatch material"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Resolves the real `eliot-native-worker` image beside this test
    /// executable (the `deps`/`debug` layout cargo produces). The digest
    /// below binds the exact bytes before any launch step reads them, so
    /// the path itself never confers ownership (`bins/AGENTS.md`).
    fn real_native_worker_binary() -> PathBuf {
        let exe = std::env::current_exe().expect("test executable path");
        let deps = exe.parent().expect("deps dir");
        let profile = deps.parent().expect("profile dir");
        profile.join(format!(
            "eliot-native-worker{}",
            std::env::consts::EXE_SUFFIX
        ))
    }

    /// Resolves the real `eliot-doctor` image beside this test executable
    /// (the `deps`/`debug` layout cargo produces). The digest below binds
    /// the exact bytes before any launch step reads them, so the path
    /// itself never confers ownership (`bins/AGENTS.md`).
    fn real_doctor_binary() -> PathBuf {
        let exe = std::env::current_exe().expect("test executable path");
        let deps = exe.parent().expect("deps dir");
        let profile = deps.parent().expect("profile dir");
        profile.join(format!("eliot-doctor{}", std::env::consts::EXE_SUFFIX))
    }

    /// Resolves the real `eliot-testd` image beside this test executable
    /// (the `deps`/`debug` layout cargo produces). The digest below binds
    /// the exact bytes before any launch step reads them, so the path
    /// itself never confers ownership (`bins/AGENTS.md`).
    fn real_testd_binary() -> PathBuf {
        let exe = std::env::current_exe().expect("test executable path");
        let deps = exe.parent().expect("deps dir");
        let profile = deps.parent().expect("profile dir");
        profile.join(format!("eliot-testd{}", std::env::consts::EXE_SUFFIX))
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

    /// Testd advertisement mirrors the contour cell exactly: the inert
    /// default never flips in place, so the flag equals the live composed
    /// state whatever the parallel lifecycle test has composed so far.
    #[test]
    fn testd_advertisement_mirrors_the_composed_contour_cell() {
        assert_eq!(testd_admission_advertised(), dispatch_contour().is_some());
    }

    /// Production Doctor composition fails closed before touching any cell
    /// when the installed digest is malformed: no ledger, registry, or
    /// principal is minted, and the global contour is never contacted.
    #[test]
    fn production_doctor_compose_rejects_a_malformed_installed_digest() {
        let root = temp_root("production-digest");
        let ledger =
            Arc::new(crate::KernelDoctorRecoveryLedger::open(&root).expect("doctor ledger opens"));
        assert!(matches!(
            compose_production_doctor_front_door(ledger, "not-a-sha256-digest"),
            Err(DispatchLaunchError::InvalidMaterial(_))
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    /// Production testd/native sides fail closed before touching any cell
    /// when the installed digest is malformed (Implements #461
    /// DISPATCH-WIRE E2E). The digest shape check precedes the contour
    /// contact, so this proof never writes global state and stays
    /// order-independent next to the parallel lifecycle test; the
    /// successful composition path is proven inside the lifecycle
    /// (step 2b), where the contour order is deterministic.
    #[test]
    fn production_testd_and_native_reject_malformed_installed_digests() {
        assert!(matches!(
            compose_production_testd_front_door("not-a-sha256-digest"),
            Err(DispatchLaunchError::InvalidMaterial(_))
        ));
        assert!(matches!(
            compose_production_native_worker_front_door("not-a-sha256-digest"),
            Err(DispatchLaunchError::InvalidMaterial(_))
        ));
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
    /// generation, and nonce bound, plus the additive launch grant.
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
        let grant = dispatch_grant_for(
            DispatchedWorkerKind::Doctor,
            &"a".repeat(64),
            &epoch,
            Generation::new(7).expect("generation"),
            1_750_000_000_000_000_000,
        )
        .expect("grant");
        let bytes = doctor_material_bytes(
            &attempt,
            &request_json,
            &manifest_json,
            &epoch,
            7,
            &nonce,
            &grant,
        )
        .expect("material bytes");
        assert!(u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= 256 * 1024);
        let envelope: serde_json::Value = serde_json::from_slice(&bytes).expect("envelope json");
        let object = envelope.as_object().expect("envelope object");
        assert_eq!(
            object.len(),
            7,
            "six child-validated fields plus the additive grant"
        );
        for key in [
            "attempt",
            "request",
            "manifest",
            "epoch",
            "generation",
            "nonce",
            "grant",
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
        // Additive grant: exact field names and broker-compatible types.
        let grant_value = object["grant"].clone();
        let grant_object = grant_value.as_object().expect("grant object");
        assert_eq!(grant_object.len(), 6, "grant carries exactly six fields");
        for key in [
            "grant_digest",
            "authority_epoch",
            "fence_generation",
            "fence_nonce",
            "idempotency_key",
            "expires_at",
        ] {
            assert!(grant_object.contains_key(key), "grant carries {key}");
        }
        let parsed_grant: DispatchGrant =
            serde_json::from_value(grant_value).expect("grant parses");
        assert_eq!(parsed_grant, grant);
        // The grant validates through the exact broker constructors.
        let (fence, lease) = parsed_grant.validate_for_child().expect("grant validates");
        assert!(fence.authority_epoch().is_same_authority(&epoch));
        assert_eq!(fence.generation().get(), 7);
        assert_eq!(parsed_grant.fence_generation, 7);
        assert!(!parsed_grant.fence_nonce.is_empty());
        assert!(!parsed_grant.idempotency_key.is_empty());
        assert!(parsed_grant.expires_at > 0);
        let _ = lease;
    }

    /// The trigger derives its launch material from the composed registry —
    /// never caller bytes — and refuses forgeries before staging anything.
    ///
    /// Global-state-free: the registry is built locally from the installed
    /// digest through the real production builders, and the admission is a
    /// literal carrying the registry's own operation and manifest digest.
    /// The full trigger-through-gate path runs inside the ordered lifecycle
    /// test, which owns the process-global contour cell.
    #[test]
    fn doctor_trigger_material_comes_from_the_composed_registry() {
        let installed_digest = eliot_contracts::sha256_hex(b"eliot-doctor-installed-package-bytes");
        let registry = DoctorRecipeRegistry::production_health_probe(&installed_digest)
            .expect("probe registry builds from the installed digest");
        let operation_id = registry.manifest().operations[0].operation_id.clone();
        let admission = DoctorRepairAdmission {
            wire_id: eliot_kernel_service::DOCTOR_REPAIR_WIRE_ID.to_owned(),
            wire_version: eliot_kernel_service::DOCTOR_REPAIR_WIRE_VERSION,
            attempt_id: "attempt-trigger-standalone-1".to_owned(),
            attempt_digest: "ab".repeat(32),
            effect_digest: Some("cd".repeat(32)),
            recipe_digest: "ef".repeat(32),
            manifest_digest: registry.manifest_digest().to_owned(),
            operation_id: operation_id.clone(),
            lease_id: "lease-trigger-1".to_owned(),
            lease_owner: "kernel.doctor-recovery".to_owned(),
            lease_expires_unix_nanos: 1_750_000_060_000_000_000,
            allowed_effects: [operation_id].into_iter().collect(),
            budget_units: 1,
            deadline_unix_nanos: 1_750_000_060_000_000_000,
            approval_present: false,
            cancelled: false,
            admitted_at_unix_nanos: 1_750_000_000_000_000_000,
            admission_digest: "12".repeat(32),
        };
        let derived =
            contour_doctor_material(&registry, &admission).expect("contour material derives");
        assert_eq!(
            derived.manifest_json,
            serde_json::to_value(registry.manifest()).expect("manifest json"),
            "derived manifest is the composed manifest revision"
        );
        assert_eq!(
            derived.executable_sha256, installed_digest,
            "derived executable digest is the composed installed digest"
        );
        let forged = DoctorRepairAdmission {
            operation_id: "forged-operation-9".to_owned(),
            ..admission.clone()
        };
        assert!(
            matches!(
                contour_doctor_material(&registry, &forged),
                Err(DispatchLaunchError::InvalidMaterial(_))
            ),
            "forged operation resolves no composed binding"
        );
        let stale = DoctorRepairAdmission {
            manifest_digest: "00".repeat(32),
            ..admission.clone()
        };
        assert!(
            matches!(
                contour_doctor_material(&registry, &stale),
                Err(DispatchLaunchError::Inconsistent(_))
            ),
            "stale manifest binding never stages"
        );
    }

    /// An exact replay rewrites byte-identical Doctor material: the nonce
    /// and grant are deterministic per (attempt identity, durable admission
    /// time, composed principal), so a replay stages nothing new while two
    /// attempts never share a session.
    #[test]
    fn doctor_trigger_material_bytes_are_replay_stable() {
        let attempt = shape_valid_doctor_request();
        let request_json = serde_json::json!({});
        let manifest_json = serde_json::json!({"manifest": "test"});
        let epoch = test_epoch(1);
        let now_nanos = 1_750_000_000_000_000_000u64;
        let material = |identity: &str| {
            let nonce =
                mint_dispatch_nonce(DispatchedWorkerKind::Doctor, identity, now_nanos, PRINCIPAL)
                    .expect("nonce");
            let grant = dispatch_grant_for(
                DispatchedWorkerKind::Doctor,
                identity,
                &epoch,
                Generation::new(7).expect("generation"),
                now_nanos,
            )
            .expect("grant");
            doctor_material_bytes(
                &attempt,
                &request_json,
                &manifest_json,
                &epoch,
                7,
                &nonce,
                &grant,
            )
            .expect("material bytes")
        };
        assert_eq!(
            material(&"a".repeat(64)),
            material(&"a".repeat(64)),
            "replay rewrites byte-identical material"
        );
        assert_ne!(
            material(&"a".repeat(64)),
            material(&"b".repeat(64)),
            "attempts never share a session"
        );
    }

    /// The contour parameterizes Doctor vs testd vs native-worker delivery
    /// endpoints without inventing a second vocabulary.
    #[test]
    fn worker_kinds_share_the_seam_with_split_delivery() {
        assert_eq!(DispatchedWorkerKind::Doctor.module_id(), "eliot-doctor");
        assert_eq!(
            DispatchedWorkerKind::Testd.module_id(),
            DispatchedWorkerKind::Testd.module_id()
        );
        assert_eq!(
            DispatchedWorkerKind::NativeWorker.module_id(),
            "eliot-native-worker"
        );
        assert_eq!(
            DispatchedWorkerKind::NativeWorker.module_id(),
            NATIVE_MODULE_ID
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
            DispatchedWorkerKind::NativeWorker.wire_id(),
            eliot_kernel_service::NATIVE_WORKER_CLAIM_WIRE_ID
        );
        assert_eq!(
            DispatchedWorkerKind::NativeWorker.wire_id(),
            "eliot.kernel.native-worker-claim"
        );
        assert_eq!(
            DispatchedWorkerKind::Doctor.material_file_name(),
            Some("eliot-doctor.dispatched-attempt.json")
        );
        assert_eq!(
            DispatchedWorkerKind::Testd.material_file_name(),
            Some("eliot-testd.admitted-attempt.json")
        );
        assert_eq!(
            DispatchedWorkerKind::NativeWorker.material_file_name(),
            Some("eliot-native-worker.admitted-claim.json")
        );
        // The native file name equals the child reader constant by
        // construction (the child reader stays the authority; this seam
        // duplicates the literal and the focused test below re-asserts it).
        assert_eq!(
            DispatchedWorkerKind::NativeWorker.material_file_name(),
            Some("eliot-native-worker.admitted-claim.json")
        );
    }

    /// R1 byte-identity: the owner-side mirrored dispatch derivation is
    /// byte-identical to the child
    /// (`bins/eliot-native-worker/src/dispatch_authority.rs:209-249,277-284`)
    /// for a fixed vector. The child test asserts the same literals; both
    /// sides agreeing here is the interop proof (no wall-clock in the permit).
    #[test]
    fn owner_dispatch_derivation_matches_child_vector() {
        let epoch = test_epoch(3);
        let epoch_json = serde_json::to_value(&epoch).expect("epoch json");
        let derived = native_worker_dispatch_derivation(
            "claim-dispatch-r1-001",
            "operation-dispatch-r1-001",
            7,
            &epoch,
            "launch-nonce-r1-0001-abcdef0123",
        )
        .expect("derivation builds");
        let from_json = native_worker_dispatch_derivation_from_epoch_json(
            "claim-dispatch-r1-001",
            "operation-dispatch-r1-001",
            7,
            &epoch_json,
            "launch-nonce-r1-0001-abcdef0123",
        )
        .expect("derivation from epoch json builds");
        assert_eq!(derived, from_json, "typed and json inputs must agree");
        assert_eq!(
            derived.base_json,
            "[\"eliot-native-worker-dispatch/v1\",\"claim-dispatch-r1-001\",\"operation-dispatch-r1-001\",7,{\"lineage_id\":\"550e8400-e29b-41d4-a716-446655440000\",\"sequence\":3},\"launch-nonce-r1-0001-abcdef0123\"]"
        );
        assert_eq!(
            derived.key_hex,
            "4c82b9a89995676ac0d0114db3615a47a8de2f9e59080c59d8354af881211f16"
        );
        assert_eq!(
            derived.authority_id,
            "native-worker-dispatch-authority-4354a8cb909128f86c445a7c19de3e0345b5b1f63e5dfbfe3a20ce6e6da3a6ff"
        );
        assert_eq!(
            derived.head_digest,
            "d0fb93eaece8fc98051cd9501616d9c9f4eb8f755cc010931a6b2b80aac32197"
        );
        assert_eq!(
            NATIVE_WORKER_DISPATCH_DERIVATION_DOMAIN,
            "eliot-native-worker-dispatch/v1"
        );
        assert_eq!(NATIVE_WORKER_DISPATCH_LAUNCH_GRANT_HEAD, "launch-grant");
    }

    /// R1 Governor-sourced digest feed (Implements #22): the executable join
    /// carries the real invocation digest derived from the exact invocation
    /// bytes plus the opaque owner digest derived from the real binding
    /// material. Matching digests validate; a mutated invocation digest is
    /// well-formed but different (the gate observes it as `Conflict`); a
    /// missing digest fails the closed shape (typed refusal, never silent).
    #[test]
    fn native_executable_join_carries_real_derived_digests() {
        let join = native_executable_join_for("claim-r1-join-1", "op-r1-join-1");
        for digest in [
            &join.process_invocation_digest,
            &join.executable_binding_digest,
        ] {
            assert_eq!(digest.len(), 64, "join digests are SHA-256 hex");
            assert!(
                digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "join digests are lowercase hex"
            );
        }
        // The carried invocation digest equals the production forward
        // computation over the exact invocation value.
        let expected_invocation = native_test_invocation("claim-r1-join-1", "op-r1-join-1");
        let expected_bytes =
            eliot_contracts::canonical_json_bytes(&expected_invocation).expect("canonical");
        assert_eq!(
            join.process_invocation_digest,
            eliot_contracts::sha256_hex(&expected_bytes),
            "join must carry the derived invocation digest"
        );
        join.validate().expect("derived join validates");
        // The claim-bound request carrying the derived join validates with
        // real computed envelope digests.
        let request = native_claim_request(
            "claim-r1-join-1",
            "reg-r1-join-1",
            "attempt-r1-join-1",
            "op-r1-join-1",
        );
        let presented = request
            .executable_binding
            .as_ref()
            .expect("claim carries the join");
        assert_eq!(
            presented.process_invocation_digest, join.process_invocation_digest,
            "claim must carry the derived join digest"
        );
        // A mutated invocation digest stays well-formed so the gate reaches
        // its typed currentness arm (`Conflict` on
        // `.process_invocation_digest`) instead of stopping at shape.
        let mut mutated = request.clone();
        let mutated_join = mutated
            .executable_binding
            .as_mut()
            .expect("mutated claim carries the join");
        let mutated_invocation = serde_json::json!({
            "claim_id": "claim-r1-join-1",
            "operation_id": "op-r1-join-1",
            "argv": ["--mutated"],
            "fence": {"generation": 1},
        });
        let mutated_bytes =
            eliot_contracts::canonical_json_bytes(&mutated_invocation).expect("canonical");
        mutated_join.process_invocation_digest = eliot_contracts::sha256_hex(&mutated_bytes);
        assert_ne!(
            mutated_join.process_invocation_digest, join.process_invocation_digest,
            "mutated invocation must derive a different digest"
        );
        mutated_join.validate().expect("mutated join stays well-formed");
        mutated.binding_digest = mutated
            .compute_binding_digest()
            .expect("rebind mutated binding");
        mutated.request_digest = mutated
            .canonical_request_digest()
            .expect("rebind mutated envelope");
        mutated.validate().expect("mutated claim stays shape-valid");
        // A missing digest fails the closed join shape: typed refusal, never
        // a silent admit.
        let mut missing = request.clone();
        missing
            .executable_binding
            .as_mut()
            .expect("missing claim carries the join")
            .process_invocation_digest
            .clear();
        assert!(
            missing
                .executable_binding
                .as_ref()
                .expect("join present")
                .validate()
                .is_err(),
            "missing invocation digest must fail the closed shape"
        );
    }
}
