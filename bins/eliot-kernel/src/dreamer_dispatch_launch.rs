//! Protected Dreamer dispatch-launch material and launch lineage (T12-09,
//! Implements #702).
//!
//! Kernel half of the protected Dreamer launch + `LeaseExact` claim seam.
//! Mirrors the Doctor/testd/native-worker `dispatched_material` shape
//! (`bins/eliot-doctor/src/dispatched_material.rs`, Writer-T/Writer-N halves):
//! the Kernel records one launch lineage for the exact queued job/attempt
//! before spawn, binds the admitted artifact/config/protocol/generation/fence
//! from live authority plus the durable `QUEUED` ledger response, and stages
//! protected handoff bytes next to the child executable. The managed child
//! verifies those bytes against its authenticated session and then performs
//! `LeaseExact` through the K2 bound-worker arm
//! (`super::super::dreamer_job_dispatch`); a tampered, foreign, or replayed
//! launch never starts a second worker.
//!
//! Delivery contract (I7.5/I15.2, I1.5 demand-start): the file carries the
//! exact queued job/attempt/revision/scope/fence, the live authority epoch,
//! the fence-bound generation, the deterministic launch nonce, and the shared
//! [`DispatchGrant`](super::DispatchGrant) object the child uses to derive
//! its one-shot permit in-process (`FencingToken::new` +
//! `PermitIssuance::new` + `DispatchValidationContext::new` +
//! `ProcessRequest::new`, broker pattern from #1460). The concrete
//! `ProcessRequest` is never serialized here. Nothing travels via argv,
//! stdin, or the environment; caller bytes supply only the job/attempt lookup
//! keys, never scope, fence, revision, epoch, or generation.
//!
//! Single-flight and reconcile state lives in the process-local lineage table
//! below, keyed by the exact job identity: an exact replay returns the
//! retained original lineage (same nonce, same operation, same grant digest)
//! instead of minting a second worker, while changed terms under one job
//! identity refuse with [`DreamerMaterialError::ChangedTerms`]. The durable
//! job ledger (Store S0/S1 over the K1 gateway) stays the terminal authority;
//! this table only enforces launch-once per identity and carries the values
//! the claim and reconcile paths compare. A persisted launch nonce is never
//! authority without current session/grant verification (performed at claim
//! time by the K2 arm and at reconcile time here against the live epoch).
//!
//! Termination/no-orphan: the dispatch file is reaped best-effort on spawn
//! failure, on reconcile, and on explicit release, and the lineage slot
//! closes on reconcile/release, so a stale presentation never lingers for a
//! later invocation. The child additionally consumes the file once on a
//! validated read (MGR02 `kernel_port` half).
//!
//! Architecture: ARCH-MOD-01, A13.2; I1.5 demand-start, I1.8 exact ownership
//! and call paths, I7.5 launch nonce, I15.2 Principal and Session binding.
//! Forbidden authority: no minted ledger/registry/principal, no invented
//! transport or listener, no argv/env material, no second spawn for an
//! outstanding identity, no Dreamer semantic/model/source admission (owners
//! #18/#781, MGR02 binary half).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use eliot_contracts::{EpochId, StateFence};
use serde::{Deserialize, Serialize};

use super::DispatchGrant;

/// Stable session module identity of the one-shot Dreamer worker.
///
/// The worker never self-asserts authority through this string: the K2
/// bound-worker arm admits it only with a retained launch lineage for the
/// exact queued job plus a presented [`JobRole::Worker`](eliot_protocol::dreamer_job::JobRole)
/// `LeaseExact` that agrees with it, and the front door binds the session
/// over an already-authenticated pipe peer. Canonical home of the Dreamer
/// module string on this base (no `front_door_session` Dreamer binding
/// exists yet; the dedicated least-privilege session bind is a
/// manager-serialized follow-up, see the MGR02 handoff).
pub const DREAMER_MODULE_ID: &str = "eliot-dreamer";

/// Protected dispatch file name the Dreamer child reads from its executable
/// directory (`current_exe`, never argv/stdin/env).
///
/// The Kernel delivery half owns this write path; the child reader
/// (`bins/eliot-dreamer/src/kernel_port.rs`, MGR02) stays the authority for
/// the value. No other writer exists, so this seam is the single writer.
pub const DREAMER_MATERIAL_FILE_NAME: &str = "eliot-dreamer.admitted-job.json";

/// Upper bound for the dispatch file: the admitted job envelope is small
/// (identities, fence, epoch, nonce, grant); this adds ample headroom
/// without accepting unbounded input. Mirrors the Doctor/testd bound.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub const DREAMER_MATERIAL_LIMIT_BYTES: u64 = 256 * 1024;

/// Session-nonce shape bounds (I7.5): opaque, bounded, never invented by the
/// child.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub const DREAMER_NONCE_MIN_LEN: usize = 16;
/// Session-nonce shape bounds (I7.5): opaque, bounded, never invented by the
/// child.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub const DREAMER_NONCE_MAX_LEN: usize = 256;

/// Nonce prefix distinguishing Dreamer launch nonces. Matches
/// [`DispatchedWorkerKind::Dreamer`](super::DispatchedWorkerKind)
/// parameterization.
pub const DREAMER_NONCE_PREFIX: &str = "dreamer-dispatch";

/// Operation prefix for the Dreamer child admission, so the admitted
/// executor replays (never double-spawns) an identical launch.
pub const DREAMER_OPERATION_PREFIX: &str = "dreamer-launch";

/// Typed failure for Dreamer dispatch material and lineage. Every variant is
/// fail-closed: no lineage is retained, no file is staged, and no child is
/// spawned on error.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
#[derive(Debug)]
pub enum DreamerMaterialError {
    /// Caller-supplied launch keys or composition-pinned child binding
    /// failed closed validation.
    InvalidMaterial(String),
    /// Changed terms under one retained job identity; the retained original
    /// is never overwritten.
    ChangedTerms(String),
    /// A mechanical gate failed (lock poison, serialization, live authority
    /// unavailable).
    Gate(String),
    /// The dispatch material file could not be written.
    Io(String),
}

impl std::fmt::Display for DreamerMaterialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMaterial(detail) => {
                write!(f, "dreamer launch material is invalid: {detail}")
            }
            Self::ChangedTerms(detail) => {
                write!(f, "changed dreamer terms under one job identity: {detail}")
            }
            Self::Gate(detail) => write!(f, "dreamer launch gate failed: {detail}"),
            Self::Io(detail) => write!(f, "dreamer material file failed: {detail}"),
        }
    }
}

impl std::error::Error for DreamerMaterialError {}

/// Kernel-staged protected handoff for one admitted Dreamer job.
///
/// Every identity-bearing value except the two lookup keys is bound
/// Kernel-side from the durable `QUEUED` ledger response plus live
/// authority; the child re-proves each binding against its authenticated
/// session fail-closed (MGR02 reader). The concrete `ProcessRequest` is
/// intentionally absent: the child derives its one-shot permit in-process
/// from `grant` through the exact broker constructors.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamerDispatchedEnvelope {
    /// Exact queued job identity (lookup key; must answer the ledger).
    pub job_id: String,
    /// Exact queued attempt identity (lookup key; must answer the ledger).
    pub attempt_id: String,
    /// Exact ledger revision the worker must claim.
    pub revision: u64,
    /// Scope the ledger bound to this job (never caller bytes).
    pub scope_id: String,
    /// Fence the ledger bound to this job (never caller bytes).
    pub fence: StateFence,
    /// Live authority epoch bound at launch (never envelope bytes).
    pub epoch: EpochId,
    /// Live activation generation bound at launch (non-zero).
    pub generation: u64,
    /// I7.5/I15.2 launch nonce, deterministic per lineage.
    pub nonce: String,
    /// Kernel-issued launch grant the child derives its permit from.
    pub grant: DispatchGrant,
}

/// Session-bound Dreamer material validated against live authority.
///
/// Carries exactly what the managed child needs to prove its claim: the
/// admitted job/attempt/revision/scope/fence, the live epoch/generation it
/// bound against, the session nonce, and the Kernel-issued launch grant.
/// This value alone (without the local dispatch authority the child builds
/// from `grant`) never drives execution.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDreamerMaterial {
    /// Exact queued job identity.
    pub job_id: String,
    /// Exact queued attempt identity.
    pub attempt_id: String,
    /// Exact ledger revision the worker must claim.
    pub revision: u64,
    /// Scope the ledger bound to this job.
    pub scope_id: String,
    /// Fence the ledger bound to this job.
    pub fence: StateFence,
    /// Live epoch this material bound against.
    pub epoch: EpochId,
    /// Generation this material bound against.
    pub generation: u64,
    /// Well-formed session nonce.
    pub nonce: String,
    /// Validated Kernel-issued launch grant.
    pub grant: DispatchGrant,
}

/// Caller-presented Dreamer launch keys: the job/attempt lookup identities
/// only. Scope, fence, revision, epoch, and generation always come from the
/// durable ledger response plus live authority, never from these keys.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DreamerLaunchKeys<'a> {
    /// Exact queued job identity to look up.
    pub job_id: &'a str,
    /// Exact queued attempt identity the response must answer.
    pub attempt_id: &'a str,
}

/// Composition-supplied Dreamer child binary anchor.
///
/// The executable path plus the working directory are the trigger inputs the
/// launch seam cannot derive: the absolute installed-generation root is Host
/// installation state. The production composition root supplies it from Host
/// injection through the installation manifest; never from wire, argv, or
/// the environment. `executable_sha256` is the composition-pinned installed
/// Dreamer image digest the launch binds (never minted here).
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DreamerChildBinding<'a> {
    /// Absolute path of the composition-pinned `eliot-dreamer` executable.
    /// The dispatch file is staged next to it.
    pub executable: &'a std::path::Path,
    /// Expected SHA-256 digest of the child executable image.
    pub executable_sha256: &'a str,
    /// Absolute working directory the child spawns under.
    pub working_directory: &'a std::path::Path,
}

/// Launch phase of one retained Dreamer lineage, keyed by job identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DreamerLaunchPhase {
    /// Launch reserved; the spawn has not been attempted yet.
    Reserved,
    /// The child was spawned through the admitted executor.
    Launched,
    /// The spawn outcome is unknown; the job must reconcile by its original
    /// identity instead of relaunching blindly.
    Unreconciled,
    /// The durable outcome converged; the slot is closed.
    Reconciled,
}

/// One retained Dreamer launch lineage: the exact queued job/attempt the
/// worker may claim, plus the launch binding it must prove.
#[derive(Clone, Debug)]
pub struct DreamerLaunchRecord {
    /// Exact queued job identity (lineage key).
    pub job_id: String,
    /// Exact queued attempt identity.
    pub attempt_id: String,
    /// Exact ledger revision the worker must claim.
    pub revision: u64,
    /// Scope the ledger bound to this job.
    pub scope_id: String,
    /// Fence the ledger bound to this job.
    pub fence: StateFence,
    /// Composition-pinned installed Dreamer image digest bound at launch.
    pub executable_sha256: String,
    /// Protected dispatch file path the child reads, once staged.
    pub material_path: Option<PathBuf>,
    /// I7.5/I15.2 launch nonce written to the dispatch file.
    #[allow(
        dead_code,
        reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
    )]
    pub nonce: String,
    /// Deterministic child operation identity.
    #[allow(
        dead_code,
        reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
    )]
    pub operation_id: String,
    /// Grant digest binding the launch (`DispatchGrant::grant_digest`).
    pub grant_digest: String,
    /// Current launch phase.
    pub phase: DreamerLaunchPhase,
}

/// Expected Dreamer lineage for one claim/reconcile proof: the exact queued
/// values the presenter must reproduce. Nothing here is trusted until it
/// equals the retained lineage under live authority.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DreamerLeaseExpectation {
    /// Exact queued job identity.
    pub job_id: String,
    /// Exact queued attempt identity.
    pub attempt_id: String,
    /// Exact ledger revision.
    pub revision: u64,
    /// Scope bound to the job.
    pub scope_id: String,
    /// Fence bound to the job.
    pub fence: StateFence,
}

/// Outcome of reserving one Dreamer launch lineage.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
#[derive(Clone, Debug)]
pub enum DreamerReserveOutcome {
    /// Freshly reserved under the job identity.
    Reserved,
    /// An exact resubmit under one job identity: carries the RETAINED
    /// original record (original nonce, operation, and grant digest), never
    /// a recomputed one. No second worker may spawn from this outcome.
    ReplayOriginal(Box<DreamerLaunchRecord>),
}

/// Outcome of reconciling one launched Dreamer lineage by its original job
/// identity.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DreamerReconcileOutcome {
    /// The lineage converged under the original identity; carries the
    /// original grant digest, never a recomputed one. The caller reaps the
    /// staged dispatch file best-effort.
    Reconciled {
        /// Original job identity.
        job_id: String,
        /// Original grant digest.
        grant_digest: String,
        /// Staged dispatch file to reap, when one was staged.
        material_path: Option<PathBuf>,
    },
    /// Still outstanding: the original identity stays retained, no second
    /// child is spawned, and a later call may reconcile.
    Unreconciled {
        /// Original job identity.
        job_id: String,
    },
    /// Never launched through this seam: reports unknown instead of
    /// inventing state.
    Unknown {
        /// Queried job identity.
        job_id: String,
    },
}

static DREAMER_LAUNCHES: OnceLock<Mutex<BTreeMap<String, DreamerLaunchRecord>>> = OnceLock::new();

/// Returns the process-local Dreamer lineage table, initializing it once.
///
/// The table enforces launch-once per job identity; the durable Store ledger
/// stays the terminal authority. Poison fails closed at every caller.
fn dreamer_launches() -> &'static Mutex<BTreeMap<String, DreamerLaunchRecord>> {
    DREAMER_LAUNCHES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Requires bounded non-blank text without control characters, mirroring the
/// kernel-service wire-text rule so staged identities match what admission
/// would refuse.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn require_dreamer_text(
    value: &str,
    what: &'static str,
) -> Result<(), DreamerMaterialError> {
    if value.trim().is_empty() {
        return Err(DreamerMaterialError::InvalidMaterial(format!(
            "dreamer {what} must be non-blank"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(DreamerMaterialError::InvalidMaterial(format!(
            "dreamer {what} must not contain control characters"
        )));
    }
    if value.len() > 1024 {
        return Err(DreamerMaterialError::InvalidMaterial(format!(
            "dreamer {what} must not exceed 1024 UTF-8 bytes"
        )));
    }
    Ok(())
}

/// Requires a lowercase SHA-256 digest, mirroring the Kernel grant gate.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn require_dreamer_digest(
    value: &str,
    what: &'static str,
) -> Result<(), DreamerMaterialError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DreamerMaterialError::InvalidMaterial(format!(
            "dreamer {what} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

/// Validates caller-presented Dreamer launch keys: the job/attempt lookup
/// identities only. Scope, fence, revision, epoch, and generation always
/// come from the durable ledger response plus live authority, never from
/// these keys.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn validate_dreamer_launch_keys(
    keys: &DreamerLaunchKeys<'_>,
) -> Result<(), DreamerMaterialError> {
    require_dreamer_text(keys.job_id, "job identity")?;
    require_dreamer_text(keys.attempt_id, "attempt identity")?;
    Ok(())
}

/// Validates the composition-pinned Dreamer child binary binding.
///
/// The executable must have a parent directory (the dispatch file is staged
/// next to it), its expected digest must be well-formed, and the working
/// directory must be non-blank. Nothing is discovered from argv or the
/// environment.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn validate_dreamer_child_binding(
    binding: &DreamerChildBinding<'_>,
) -> Result<(), DreamerMaterialError> {
    if binding.executable.parent().is_none() {
        return Err(DreamerMaterialError::InvalidMaterial(
            "dreamer child executable has no parent directory".to_owned(),
        ));
    }
    require_dreamer_digest(
        binding.executable_sha256,
        "dispatch child executable digest",
    )?;
    if binding.working_directory.as_os_str().is_empty() {
        return Err(DreamerMaterialError::InvalidMaterial(
            "dreamer child working directory must be non-blank".to_owned(),
        ));
    }
    Ok(())
}

/// Requires a well-formed opaque session nonce: bounded length over the
/// explicit hyphen/underscore/dot alphanumeric alphabet. The value is never
/// interpreted, only carried for the Kernel-side claim proof.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
fn validate_dreamer_nonce(nonce: &str) -> Result<(), DreamerMaterialError> {
    if !(DREAMER_NONCE_MIN_LEN..=DREAMER_NONCE_MAX_LEN).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(DreamerMaterialError::InvalidMaterial(
            "dreamer launch nonce is missing or malformed: a well-formed session nonce is required"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Mints the I7.5/I15.2 launch nonce for one admitted Dreamer lineage.
///
/// The nonce is deterministic per (job, attempt, revision, live epoch, live
/// generation, pinned executable digest): unpredictable before admission
/// (the live authority join), unique per lineage, and stable across exact
/// replays, so a replay rewrites byte-identical material and reconciles by
/// the original identity instead of minting a second session. The live
/// epoch/generation bind replaces the contour-principal bind used by the
/// Doctor/testd/native mint: the epoch already identifies the authority
/// lineage, and the lineage table (not a shared contour cell) owns this
/// seam. Violations fail closed instead of launching.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn mint_dreamer_nonce(
    job_id: &str,
    attempt_id: &str,
    revision: u64,
    epoch: &EpochId,
    generation: u64,
    executable_digest: &str,
) -> Result<String, DreamerMaterialError> {
    require_dreamer_text(job_id, "job identity")?;
    require_dreamer_text(attempt_id, "attempt identity")?;
    if revision == 0 {
        return Err(DreamerMaterialError::InvalidMaterial(
            "dreamer lineage revision must be non-zero".to_owned(),
        ));
    }
    if generation == 0 {
        return Err(DreamerMaterialError::InvalidMaterial(
            "dreamer launch generation must be non-zero".to_owned(),
        ));
    }
    require_dreamer_digest(executable_digest, "executable digest")?;
    let epoch_json = serde_json::to_string(epoch)
        .map_err(|error| DreamerMaterialError::Gate(error.to_string()))?;
    let mut material = String::with_capacity(256);
    material.push_str(DREAMER_NONCE_PREFIX);
    material.push('|');
    material.push_str(job_id);
    material.push('|');
    material.push_str(attempt_id);
    material.push('|');
    material.push_str(&revision.to_string());
    material.push('|');
    material.push_str(&epoch_json);
    material.push('|');
    material.push_str(&generation.to_string());
    material.push('|');
    material.push_str(executable_digest);
    let nonce = format!(
        "{DREAMER_NONCE_PREFIX}-{}",
        crate::sha256_hex(material.as_bytes())
    );
    validate_dreamer_nonce(&nonce)?;
    Ok(nonce)
}

/// Serializes one Kernel-bound envelope to protected-file bytes.
///
/// The envelope must already carry only Kernel-bound values (ledger
/// identities/scope/fence/revision plus live epoch/generation/nonce/grant);
/// this function proves the bound (size) but never the authority. Files are
/// never read here, and nothing travels via argv, stdin, or the
/// environment.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn dreamer_material_bytes(
    envelope: &DreamerDispatchedEnvelope,
) -> Result<Vec<u8>, DreamerMaterialError> {
    let bytes = serde_json::to_vec(envelope)
        .map_err(|error| DreamerMaterialError::Io(error.to_string()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > DREAMER_MATERIAL_LIMIT_BYTES {
        return Err(DreamerMaterialError::Io(
            "dreamer dispatch material exceeds the bounded input limit".to_owned(),
        ));
    }
    Ok(bytes)
}

/// Parses protected-file bytes into the closed Dreamer envelope.
///
/// Unknown fields are rejected so the handoff cannot be widened without a
/// contract change. The parsed value is still untrusted presenter bytes
/// until [`validate_dreamer_material`] binds it against live authority.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn parse_dreamer_material_bytes(
    bytes: &[u8],
) -> Result<DreamerDispatchedEnvelope, DreamerMaterialError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > DREAMER_MATERIAL_LIMIT_BYTES {
        return Err(DreamerMaterialError::InvalidMaterial(
            "dreamer dispatch material exceeds the bounded input limit".to_owned(),
        ));
    }
    serde_json::from_slice(bytes).map_err(|error| {
        DreamerMaterialError::InvalidMaterial(format!(
            "dreamer dispatch material is not a closed dispatch envelope: {}",
            truncate_detail(&error.to_string())
        ))
    })
}

/// Validates one parsed envelope against the live authority epoch.
///
/// Every check is fail-closed and cheapest-first, performing no transport,
/// no execution, and no authority minting: identity shapes, ledger revision,
/// fence shape plus generation agreement, exact-tuple epoch equality, nonce
/// shape, then the launch grant through the exact broker constructors the
/// child derives its permit from (`DispatchGrant::validate_for_child`) bound
/// to the live epoch and the presented generation. A foreign or stale epoch,
/// generation, or grant is a refusal, never a fallback.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn validate_dreamer_material(
    envelope: &DreamerDispatchedEnvelope,
    live_epoch: &EpochId,
) -> Result<ValidatedDreamerMaterial, DreamerMaterialError> {
    require_dreamer_text(&envelope.job_id, "job identity")?;
    require_dreamer_text(&envelope.attempt_id, "attempt identity")?;
    require_dreamer_text(&envelope.scope_id, "scope identity")?;
    if envelope.revision == 0 {
        return Err(DreamerMaterialError::InvalidMaterial(
            "dreamer lineage revision must be non-zero".to_owned(),
        ));
    }
    envelope
        .fence
        .validate()
        .map_err(|error| DreamerMaterialError::InvalidMaterial(error.to_string()))?;
    if envelope.generation == 0 {
        return Err(DreamerMaterialError::InvalidMaterial(
            "dreamer launch generation must be non-zero".to_owned(),
        ));
    }
    if envelope.fence.resource_generation.value() != envelope.generation {
        return Err(DreamerMaterialError::InvalidMaterial(
            "dreamer launch generation does not equal the ledger fence generation".to_owned(),
        ));
    }
    if envelope.epoch != *live_epoch {
        return Err(DreamerMaterialError::InvalidMaterial(format!(
            "dreamer material epoch is foreign or stale: presented {presented:?}, live {live_epoch:?}",
            presented = envelope.epoch,
        )));
    }
    validate_dreamer_nonce(&envelope.nonce)?;
    envelope
        .grant
        .validate_for_child()
        .map_err(|error| DreamerMaterialError::InvalidMaterial(error.to_string()))?;
    if envelope.grant.authority_epoch != *live_epoch {
        return Err(DreamerMaterialError::InvalidMaterial(format!(
            "dreamer grant epoch is foreign or stale: presented {presented:?}, live {live_epoch:?}",
            presented = envelope.grant.authority_epoch,
        )));
    }
    if envelope.grant.fence_generation != envelope.generation {
        return Err(DreamerMaterialError::InvalidMaterial(format!(
            "dreamer grant generation {} does not equal the presented session generation {}",
            envelope.grant.fence_generation, envelope.generation,
        )));
    }
    Ok(ValidatedDreamerMaterial {
        job_id: envelope.job_id.clone(),
        attempt_id: envelope.attempt_id.clone(),
        revision: envelope.revision,
        scope_id: envelope.scope_id.clone(),
        fence: envelope.fence.clone(),
        epoch: envelope.epoch.clone(),
        generation: envelope.generation,
        nonce: envelope.nonce.clone(),
        grant: envelope.grant.clone(),
    })
}

/// Reserves one Dreamer launch lineage under its job identity.
///
/// Insert-or-replay: a fresh identity reserves; an exact resubmit (same
/// attempt, revision, scope, fence, and executable binding) returns the
/// RETAINED original record so the caller rewrites byte-identical material
/// and never spawns a second worker; changed terms under one identity
/// refuse instead of overwriting the original.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn reserve_dreamer_launch(
    record: DreamerLaunchRecord,
) -> Result<DreamerReserveOutcome, DreamerMaterialError> {
    let mut launches = dreamer_launches().lock().map_err(|_| {
        DreamerMaterialError::Gate("dreamer launch record lock poisoned".to_owned())
    })?;
    if let Some(existing) = launches.get(&record.job_id) {
        if existing.attempt_id == record.attempt_id
            && existing.revision == record.revision
            && existing.scope_id == record.scope_id
            && existing.fence == record.fence
            && existing.executable_sha256 == record.executable_sha256
        {
            return Ok(DreamerReserveOutcome::ReplayOriginal(Box::new(
                existing.clone(),
            )));
        }
        return Err(DreamerMaterialError::ChangedTerms(format!(
            "job {} presents changed terms under one job identity",
            record.job_id
        )));
    }
    launches.insert(record.job_id.clone(), record);
    Ok(DreamerReserveOutcome::Reserved)
}

/// Notes the staged dispatch file on one reserved lineage.
///
/// Best-effort: a missing (already released) slot is not an error; the file
/// write itself already succeeded and the caller carries the path.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn note_dreamer_material_path(job_id: &str, material_path: PathBuf) {
    if let Ok(mut launches) = dreamer_launches().lock()
        && let Some(record) = launches.get_mut(job_id)
    {
        record.material_path = Some(material_path);
    }
}

/// Releases one launch reservation best-effort (prepare/write failure path).
/// A later call may retry cleanly under the same identity. Only a still
/// `Reserved` slot is released, so a concurrently launched lineage is never
/// freed by a stale caller.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn release_dreamer_reservation(job_id: &str) {
    if let Ok(mut launches) = dreamer_launches().lock()
        && launches
            .get(job_id)
            .is_some_and(|record| record.phase == DreamerLaunchPhase::Reserved)
    {
        launches.remove(job_id);
    }
}

/// Promotes one reserved lineage after the spawn settles, keeping the first
/// record under the identity.
///
/// A concurrent duplicate never overwrites the original nonce, operation, or
/// grant digest, so the claim proof and reconciliation always name the
/// original lineage.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn retain_dreamer_launch_as(
    job_id: &str,
    phase: DreamerLaunchPhase,
    material_path: Option<PathBuf>,
) -> Result<(), DreamerMaterialError> {
    let mut launches = dreamer_launches().lock().map_err(|_| {
        DreamerMaterialError::Gate("dreamer launch record lock poisoned".to_owned())
    })?;
    if let Some(record) = launches.get_mut(job_id)
        && record.phase == DreamerLaunchPhase::Reserved
    {
        record.phase = phase;
        if material_path.is_some() {
            record.material_path = material_path;
        }
    }
    Ok(())
}

/// Returns whether one retained lineage permits a worker `LeaseExact` claim.
///
/// Exact-match only: the job identity must be retained and not yet
/// reconciled, and the presented scope, revision, and fence must equal the
/// retained lineage. Anything else fails closed (the K2 arm fences without
/// a store call). Lock poison also fails closed.
pub(crate) fn dreamer_launch_permits_lease(
    job_id: &str,
    scope_id: &str,
    revision: u64,
    fence: &StateFence,
) -> bool {
    dreamer_launches().lock().is_ok_and(|launches| {
        launches.get(job_id).is_some_and(|record| {
            record.phase != DreamerLaunchPhase::Reconciled
                && record.scope_id == scope_id
                && record.revision == revision
                && record.fence == *fence
        })
    })
}

/// Reconciles one launched lineage by its original job identity.
///
/// The presented expectation must reproduce the retained lineage exactly,
/// and the retained fence epoch must still identify the live authority
/// (same-authority); a persisted nonce alone is never authority. A matching
/// lineage closes its slot; the caller reaps the staged dispatch file
/// best-effort from the returned path. Anything still outstanding stays
/// unreconciled for a later call, and unknown identities report unknown
/// instead of inventing state.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn reconcile_dreamer_launch(
    expected: &DreamerLeaseExpectation,
    live_epoch: &EpochId,
) -> Result<DreamerReconcileOutcome, DreamerMaterialError> {
    let mut launches = dreamer_launches().lock().map_err(|_| {
        DreamerMaterialError::Gate("dreamer launch record lock poisoned".to_owned())
    })?;
    let Some(record) = launches.get_mut(&expected.job_id) else {
        return Ok(DreamerReconcileOutcome::Unknown {
            job_id: expected.job_id.clone(),
        });
    };
    let binds = record.attempt_id == expected.attempt_id
        && record.revision == expected.revision
        && record.scope_id == expected.scope_id
        && record.fence == expected.fence;
    if binds && record.fence.authority_epoch.is_same_authority(live_epoch) {
        record.phase = DreamerLaunchPhase::Reconciled;
        return Ok(DreamerReconcileOutcome::Reconciled {
            job_id: record.job_id.clone(),
            grant_digest: record.grant_digest.clone(),
            material_path: record.material_path.clone(),
        });
    }
    Ok(DreamerReconcileOutcome::Unreconciled {
        job_id: expected.job_id.clone(),
    })
}

/// Releases one retained lineage slot explicitly (operator/control-plane
/// surface).
///
/// Removes the record only when its retained grant digest equals
/// `grant_digest`, so a newer reservation is never released by a stale
/// caller. Returns the staged dispatch file to reap when a slot was
/// released. Documented use: the durable terminality of a Dreamer job lives
/// in the Store ledger, so an operator release (or process restart) is the
/// only slot release besides reconcile.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
pub(crate) fn release_dreamer_launch(
    job_id: &str,
    grant_digest: &str,
) -> Result<Option<PathBuf>, DreamerMaterialError> {
    let material_path = {
        let launches = dreamer_launches().lock().map_err(|_| {
            DreamerMaterialError::Gate("dreamer launch record lock poisoned".to_owned())
        })?;
        launches
            .get(job_id)
            .filter(|record| record.grant_digest == grant_digest)
            .and_then(|record| record.material_path.clone())
    };
    let mut launches = dreamer_launches().lock().map_err(|_| {
        DreamerMaterialError::Gate("dreamer launch record lock poisoned".to_owned())
    })?;
    let release = launches
        .get(job_id)
        .is_some_and(|record| record.grant_digest == grant_digest);
    if release {
        launches.remove(job_id);
    }
    Ok(material_path.filter(|_| release))
}

/// Returns the retained lineage for one job identity, if any.
///
/// Test and claim-gate read path only; mutation stays with the
/// reserve/retain/reconcile/release entries above.
#[cfg(test)]
pub(crate) fn retained_dreamer_launch(job_id: &str) -> Option<DreamerLaunchRecord> {
    dreamer_launches()
        .lock()
        .ok()
        .and_then(|launches| launches.get(job_id).cloned())
}

/// Bounds third-party error detail carried into deny lines.
#[allow(
    dead_code,
    reason = "production call-in lands with the manager-serialized lib.rs re-export; tests drive it meanwhile"
)]
fn truncate_detail(detail: &str) -> String {
    const LIMIT: usize = 256;
    detail.chars().take(LIMIT).collect()
}

#[cfg(test)]
mod dreamer_dispatch_launch_tests {
    //! T12-09 material and lineage behaviour proofs (Implements #702).
    //!
    //! Pure Kernel-side checks: nonce determinism/shape, material
    //! round-trip plus forgery denial, and lineage single-flight with
    //! reconcile/release. The live-epoch and fence values are real
    //! `eliot_contracts` constructions; the full launch/claim flow (QUEUED
    //! ledger response, K2 worker `LeaseExact`, no second worker,
    //! termination/no-orphan) is proven by the focused K2 test in
    //! `dreamer_job_dispatch_tests`, which owns the ledger fixtures.

    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

    use super::*;
    use eliot_contracts::{EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(LINEAGE).expect("lineage"),
            NonZeroU64::new(sequence).expect("sequence"),
        )
        .expect("epoch")
    }

    fn test_fence() -> StateFence {
        StateFence::new(test_epoch(1), ResourceGeneration::genesis())
    }

    fn test_grant(epoch: &EpochId, generation: u64, identity_digest: &str) -> DispatchGrant {
        let short = identity_digest.get(..16).expect("short identity");
        let material = format!(
            "{identity_digest}|{}|{generation}|dreamer-launch-fence-{short}|dreamer-launch-lease-{short}|1750000060000",
            serde_json::to_string(epoch).expect("epoch json"),
        );
        DispatchGrant {
            grant_digest: crate::sha256_hex(material.as_bytes()),
            authority_epoch: epoch.clone(),
            fence_generation: generation,
            fence_nonce: format!("dreamer-launch-fence-{short}"),
            idempotency_key: format!("dreamer-launch-lease-{short}"),
            expires_at: 1_750_000_060_000,
        }
    }

    fn test_envelope(job_tag: &str) -> DreamerDispatchedEnvelope {
        let epoch = test_epoch(1);
        let generation = ResourceGeneration::genesis().value();
        let executable_digest = "ab".repeat(32);
        let nonce = mint_dreamer_nonce(
            job_tag,
            "attempt-t12-09-01",
            1,
            &epoch,
            generation,
            &executable_digest,
        )
        .expect("nonce mints");
        let identity_digest =
            crate::sha256_hex(format!("dreamer-launch|{job_tag}|attempt-t12-09-01|1").as_bytes());
        DreamerDispatchedEnvelope {
            job_id: job_tag.to_owned(),
            attempt_id: "attempt-t12-09-01".to_owned(),
            revision: 1,
            scope_id: "scope-t12-09".to_owned(),
            fence: test_fence(),
            epoch: epoch.clone(),
            generation,
            nonce,
            grant: test_grant(&epoch, generation, &identity_digest),
        }
    }

    fn unique_job(tag: &str) -> String {
        format!(
            "job-t12-09-{tag}-{}-{}",
            std::process::id(),
            crate::unix_ms()
        )
    }

    #[test]
    fn dreamer_nonce_is_deterministic_and_shaped() {
        let epoch = test_epoch(1);
        let generation = ResourceGeneration::genesis().value();
        let digest = "cd".repeat(32);
        let first = mint_dreamer_nonce("job-a", "attempt-a", 3, &epoch, generation, &digest)
            .expect("nonce mints");
        let replay = mint_dreamer_nonce("job-a", "attempt-a", 3, &epoch, generation, &digest)
            .expect("replay mints identically");
        assert_eq!(first, replay, "exact replay mints byte-identical nonce");
        assert!(first.starts_with("dreamer-dispatch-"));
        assert!((DREAMER_NONCE_MIN_LEN..=DREAMER_NONCE_MAX_LEN).contains(&first.len()));
        let other_job = mint_dreamer_nonce("job-b", "attempt-a", 3, &epoch, generation, &digest)
            .expect("distinct job mints");
        assert_ne!(first, other_job, "distinct lineage mints distinct nonce");
        assert!(mint_dreamer_nonce("job-a", "attempt-a", 0, &epoch, generation, &digest).is_err());
        assert!(mint_dreamer_nonce("job-a", "attempt-a", 3, &epoch, 0, &digest).is_err());
        assert!(
            mint_dreamer_nonce("job-a", "attempt-a", 3, &epoch, generation, "not-a-digest")
                .is_err()
        );
    }

    #[test]
    fn dreamer_material_round_trip_and_forgery_denied() {
        let envelope = test_envelope("job-material-01");
        let bytes = dreamer_material_bytes(&envelope).expect("material serializes");
        let parsed = parse_dreamer_material_bytes(&bytes).expect("material parses");
        assert_eq!(parsed, envelope, "closed envelope round-trips exactly");
        let live_epoch = test_epoch(1);
        let validated =
            validate_dreamer_material(&parsed, &live_epoch).expect("material validates");
        assert_eq!(validated.job_id, "job-material-01");
        assert_eq!(validated.grant, envelope.grant);

        // Widened wire (one extra key) is rejected at parse.
        let mut widened: serde_json::Value =
            serde_json::to_value(&envelope).expect("envelope json");
        widened
            .as_object_mut()
            .expect("envelope object")
            .insert("debug".to_owned(), serde_json::Value::Bool(true));
        let widened_bytes = serde_json::to_vec(&widened).expect("widened bytes");
        assert!(
            parse_dreamer_material_bytes(&widened_bytes).is_err(),
            "widened handoff must not parse"
        );

        // Tampered nonce is denied.
        let mut tampered = envelope.clone();
        tampered.nonce = "forged".to_owned();
        assert!(validate_dreamer_material(&tampered, &live_epoch).is_err());

        // Foreign epoch is denied.
        let mut foreign = envelope.clone();
        foreign.epoch = test_epoch(9);
        assert!(validate_dreamer_material(&foreign, &live_epoch).is_err());

        // Stale generation binding is denied.
        let mut stale = envelope.clone();
        stale.generation = envelope.generation.saturating_add(1);
        assert!(validate_dreamer_material(&stale, &live_epoch).is_err());

        // Foreign grant epoch is denied even with a matching envelope epoch.
        let mut bad_grant = envelope.clone();
        bad_grant.grant.authority_epoch = test_epoch(9);
        assert!(validate_dreamer_material(&bad_grant, &live_epoch).is_err());
    }

    #[test]
    fn dreamer_lineage_single_flight_reconcile_and_release() {
        let job_id = unique_job("lineage");
        let fence = test_fence();
        let record = DreamerLaunchRecord {
            job_id: job_id.clone(),
            attempt_id: "attempt-lineage-01".to_owned(),
            revision: 1,
            scope_id: "scope-lineage".to_owned(),
            fence: fence.clone(),
            executable_sha256: "ef".repeat(32),
            material_path: None,
            nonce: "dreamer-dispatch-lineage-nonce".to_owned(),
            operation_id: "dreamer-launch-1-lineage".to_owned(),
            grant_digest: "12".repeat(32),
            phase: DreamerLaunchPhase::Reserved,
        };
        assert!(matches!(
            reserve_dreamer_launch(record.clone()).expect("reserve"),
            DreamerReserveOutcome::Reserved
        ));
        // Exact replay returns the retained original, never a new lineage.
        match reserve_dreamer_launch(record.clone()).expect("replay") {
            DreamerReserveOutcome::ReplayOriginal(retained) => {
                assert_eq!(retained.nonce, record.nonce);
                assert_eq!(retained.operation_id, record.operation_id);
                assert_eq!(retained.grant_digest, record.grant_digest);
            }
            DreamerReserveOutcome::Reserved => panic!("replay must not reserve twice"),
        }
        // Changed terms under one identity refuse.
        let mut changed = record.clone();
        changed.revision = 2;
        assert!(
            reserve_dreamer_launch(changed).is_err(),
            "changed terms must refuse"
        );
        // The exact lineage permits a worker claim; near-misses do not.
        assert!(dreamer_launch_permits_lease(
            &job_id,
            "scope-lineage",
            1,
            &fence
        ));
        assert!(!dreamer_launch_permits_lease(
            &job_id,
            "scope-foreign",
            1,
            &fence
        ));
        assert!(!dreamer_launch_permits_lease(
            &job_id,
            "scope-lineage",
            2,
            &fence
        ));
        assert!(!dreamer_launch_permits_lease(
            "job-unknown",
            "scope-lineage",
            1,
            &fence
        ));

        // Reconcile with the exact expectation closes the slot.
        let expectation = DreamerLeaseExpectation {
            job_id: job_id.clone(),
            attempt_id: "attempt-lineage-01".to_owned(),
            revision: 1,
            scope_id: "scope-lineage".to_owned(),
            fence: fence.clone(),
        };
        // A mismatched expectation stays unreconciled instead of closing.
        let mismatched = DreamerLeaseExpectation {
            revision: 2,
            ..expectation.clone()
        };
        assert!(
            matches!(
                reconcile_dreamer_launch(&mismatched, &test_epoch(1)).expect("reconcile"),
                DreamerReconcileOutcome::Unreconciled { .. }
            ),
            "mismatched expectation stays unreconciled"
        );
        assert!(
            matches!(
                reconcile_dreamer_launch(&expectation, &test_epoch(1)).expect("reconcile"),
                DreamerReconcileOutcome::Reconciled { .. }
            ),
            "exact expectation reconciles"
        );
        // A reconciled lineage permits no further worker claim.
        assert!(!dreamer_launch_permits_lease(
            &job_id,
            "scope-lineage",
            1,
            &fence
        ));
        // A stale release never frees; the exact release does.
        assert!(
            release_dreamer_launch(&job_id, &"00".repeat(32))
                .expect("stale release")
                .is_none()
        );
        assert!(retained_dreamer_launch(&job_id).is_some());
        release_dreamer_launch(&job_id, &"12".repeat(32)).expect("exact release");
        assert!(retained_dreamer_launch(&job_id).is_none());
        assert!(
            matches!(
                reconcile_dreamer_launch(&expectation, &test_epoch(1)).expect("reconcile"),
                DreamerReconcileOutcome::Unknown { .. }
            ),
            "released lineage reports unknown"
        );
    }
}
