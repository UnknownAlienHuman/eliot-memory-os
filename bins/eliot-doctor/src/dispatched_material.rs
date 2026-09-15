#![forbid(unsafe_code)]

//! Bins-local dispatch-contour material reader for the one-shot Doctor.
//!
//! This module binds the already-existing one-shot driver
//! ([`drive_admitted_attempt`][crate::kernel_client::drive_admitted_attempt])
//! to session-bound attempt material delivered over a protected file, and
//! keeps the shot fail-closed until that delivery lands. It owns no wire
//! contract, mints no authority, and changes no shared type.
//!
//! Delivery shape (I7.5/I15.2): each launched child is presented a random
//! session nonce delivered via a protected inherited handle/file, never via
//! the command line. No existing protected-handle reader fits a one-shot
//! doctor child with zero new dependencies: the sealed-snapshot codec
//! (`WindowsDispatchSnapshotCodec::seal`/`open`), the DPAPI secret pair
//! (`protect_secret`/`unprotect_secret`), and the path-lease pair
//! (`retain_process_path_lease`, `ProtectedPathLease`) all require platform
//! or store crates this composition root must not take (no manifest or
//! lockfile change is in scope), and no inherited-handle enumeration API is
//! available here. Per the Slice-C child-consume brief, this module
//! therefore defines the MINIMAL bins-local JSON envelope mirroring the
//! [`PresentedAttempt`][crate::kernel_client::PresentedAttempt] fields the
//! driver binds (`attempt`, `request`, `manifest`, `epoch`) plus the
//! session `nonce`, the claimed `generation`, and the Kernel-issued launch
//! `grant` the local dispatch authority consumes. The envelope is documented
//! as bins-local: it is not a contract change, and the kernel delivery half
//! (`launch_doctor`, WRITER-B) owns its own type and may supersede the
//! locator once it lands.
//!
//! Locator (untrusted bytes, never authority): the dispatch contour writes
//! exactly one file named [`DISPATCHED_MATERIAL_FILE_NAME`] next to this
//! executable before spawn and reaps it after the shot. The path is derived
//! from [`std::env::current_exe`], which reads the OS loader image path,
//! not the environment block; no value is taken from argv, stdin, or
//! environment variables, and no ownership is inferred from the path itself
//! (`bins/AGENTS.md`: the file is untrusted presenter bytes until every
//! identity below is re-proved).
//!
//! Validation (all before any drive, all fail-closed to exit 78 without
//! effect):
//!
//! - envelope wire identity plus canonical digest, then closed-request
//!   byte-identity (the parsed envelope must equal the presented closed
//!   request, exactly like the driver re-proves);
//! - closed-request validation against the presented manifest (fence shape,
//!   lease, deadline, budget, recipe identity, admitted operations);
//! - session binding: the presented epoch must equal the live bootstrap
//!   epoch as an exact tuple, and the request fence lineage must check
//!   against that same live epoch (foreign/stale lineage is denied here,
//!   before any submit);
//! - the presented generation must be non-zero and equal the request fence
//!   generation (a stale generation is denied here; the Kernel admission
//!   gate re-proves generation authoritatively at submit);
//! - the Kernel-issued launch grant must be well-formed through the exact
//!   broker constructors (`FencingToken::new` with a non-zero generation,
//!   `ActionLeaseRef::new`), bound to the live epoch as an exact tuple and
//!   to the presented session generation (a foreign/stale grant is refused
//!   here, never a fallback);
//! - the session nonce must be present and well-formed (opaque, bounded);
//!   the authoritative nonce proof happens kernel-side at submit once the
//!   dispatch launch lands, so the child never invents it and never drives
//!   without it.
//!
//! A validated file is consumed once (best-effort removal; removal failure
//! never fails the shot). A missing file is not an error: it means the
//! dispatch contour delivered nothing to this invocation, and the caller
//! keeps the exact `DenyNoPresentedAttempt` fail-closed path. A present but
//! invalid file is a typed denial, never a drive.
//!
//! What this module deliberately does NOT deliver: the concrete
//! [`ProcessRequest`][eliot_process::ProcessRequest] is an in-memory
//! composition value that is never deserialized from a wire type and never
//! minted here, and effect execution needs a concrete executor this
//! composition root does not own. Those arrive only with the dispatch
//! launch; until then even a validated file cannot drive, and the entry
//! denies with the dispatch residual.

use std::fs;
use std::path::{Path, PathBuf};

use eliot_contracts::EpochId;
use eliot_doctor_core::{ClosedRepairRequest, RepairRecipeManifest, check_fence_against_epoch};
use eliot_kernel_service::DoctorRepairAttemptRequest;
use eliot_process::{ActionLeaseRef, FencingToken, Generation};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Bins-local dispatch file name, read from the executable directory only.
/// See the module documentation: locator, never authority.
pub const DISPATCHED_MATERIAL_FILE_NAME: &str = "eliot-doctor.dispatched-attempt.json";

/// Upper bound for the dispatch file. The closed envelope is bounded by the
/// wire (`DOCTOR_MAX_ENVELOPE_BYTES`); this adds ample headroom for the
/// manifest, epoch, generation, and nonce without accepting unbounded input.
pub const DISPATCHED_MATERIAL_LIMIT_BYTES: u64 = 256 * 1024;

/// Session-nonce shape bounds (I7.5): opaque, bounded, never invented here.
pub const DISPATCH_NONCE_MIN_LEN: usize = 16;
/// Session-nonce shape bounds (I7.5): opaque, bounded, never invented here.
pub const DISPATCH_NONCE_MAX_LEN: usize = 256;

/// Kernel-issued launch-grant material for one dispatched doctor child.
///
/// Bins-local mirror of the Kernel half (`bins/eliot-kernel` dispatch
/// launch): the Kernel never sends the sealed [`ProcessRequest`][eliot_process::ProcessRequest]
/// (it is `Serialize`-only by design, never `Deserialize`), only these six
/// fields, all derived Kernel-side from live authority plus the durable
/// admission identity. Every field is untrusted presenter bytes until
/// [`read_dispatched_material`] validates it fail-closed; an invalid grant
/// is a refusal, never a fallback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchGrant {
    /// Lowercase SHA-256 binding the grant fields plus the admission
    /// identity digest; carried child-side as the one-shot nonce plus the
    /// `launch-grant` revision-head value.
    pub grant_digest: String,
    /// Live authority epoch bound at admission (canonical `EpochId`); must
    /// equal the live bootstrap epoch as an exact tuple.
    pub authority_epoch: EpochId,
    /// Live activation generation bound at admission (non-zero); must equal
    /// the presented session `generation`.
    pub fence_generation: u64,
    /// Deterministic per-identity fence nonce for `FencingToken::new`.
    pub fence_nonce: String,
    /// Deterministic per-identity lease for `ActionLeaseRef::new`.
    pub idempotency_key: String,
    /// Grant expiry in Unix milliseconds for `PermitIssuance::new`
    /// (non-zero; freshness is enforced at issue time).
    pub expires_at: u64,
}

/// Bins-local dispatch envelope (NOT a wire contract change).
///
/// Mirrors the [`PresentedAttempt`][crate::kernel_client::PresentedAttempt]
/// fields the one-shot driver binds, plus the I7.5 session `nonce`, the
/// claimed `generation`, and the Kernel-issued launch `grant` the local
/// dispatch authority consumes. The concrete [`ProcessRequest`][eliot_process::ProcessRequest]
/// is intentionally absent: it is never deserialized and never minted here.
/// Every field is untrusted presenter bytes until
/// [`read_dispatched_material`] validates it against the live bootstrap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchedAttemptEnvelope {
    /// Full wire envelope: attempt seed, effect sequence, opaque closed
    /// request bytes, target digest, and canonical digest.
    pub attempt: DoctorRepairAttemptRequest,
    /// Parsed closed request; must equal the envelope bytes exactly.
    pub request: ClosedRepairRequest,
    /// The exact admitted manifest revision the operations resolve against.
    pub manifest: RepairRecipeManifest,
    /// Dispatch-claimed live epoch; must equal the bootstrap live epoch as
    /// an exact tuple.
    pub epoch: EpochId,
    /// Dispatch-claimed live generation; must be non-zero and equal the
    /// request fence generation.
    pub generation: u64,
    /// I7.5 session nonce; opaque, bounded, never invented here.
    pub nonce: String,
    /// Kernel-issued launch grant; validated fail-closed, never a fallback.
    pub grant: DispatchGrant,
}

/// Session-bound attempt material validated against the live bootstrap.
///
/// Carries exactly the [`PresentedAttempt`][crate::kernel_client::PresentedAttempt]
/// fields a dispatch file can supply. The concrete process request and the
/// executor still arrive only with the dispatch launch, so this value alone
/// never drives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDispatchedAttempt {
    /// Validated wire envelope.
    pub attempt: DoctorRepairAttemptRequest,
    /// Validated closed request, byte-identical to the envelope.
    pub request: ClosedRepairRequest,
    /// Validated manifest revision.
    pub manifest: RepairRecipeManifest,
    /// Live epoch this material bound against (equals the bootstrap epoch).
    pub epoch: EpochId,
    /// Generation this material bound against (equals the fence generation).
    pub generation: u64,
    /// Well-formed session nonce.
    pub nonce: String,
    /// Validated Kernel-issued launch grant bound to the live epoch and the
    /// presented generation.
    pub grant: DispatchGrant,
}

/// Typed failure for the dispatch-file read. Every variant is fail-closed:
/// the one-shot entry maps each to exit 78 without effect.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DispatchedMaterialError {
    /// The dispatch file exists but cannot be read.
    #[error("dispatch material unreadable: {0}")]
    Io(String),
    /// The dispatch file exceeds the bounded input limit.
    #[error("dispatch material exceeds {maximum} bytes (observed {actual})")]
    TooLarge {
        /// Enforced input bound.
        maximum: u64,
        /// Observed file length.
        actual: u64,
    },
    /// The dispatch file is not a closed dispatch envelope.
    #[error("dispatch material is not a closed dispatch envelope: {0}")]
    Malformed(String),
    /// The dispatch material violates the closed contract (wire identity,
    /// canonical digest, byte-identity, or closed validation).
    #[error("dispatch material violates the closed contract: {0}")]
    Contract(String),
    /// The presented epoch (or the request fence lineage) disagrees with
    /// the live bootstrap epoch.
    #[error("dispatch material epoch is foreign or stale: presented {presented}, live {live}")]
    StaleEpoch {
        /// Presented epoch value.
        presented: String,
        /// Live bootstrap epoch value.
        live: String,
    },
    /// The presented generation is zero or disagrees with the request fence
    /// generation.
    #[error(
        "dispatch material generation is stale or unbound: presented {presented}, fence {fence}"
    )]
    StaleGeneration {
        /// Presented generation value.
        presented: u64,
        /// Request fence generation value.
        fence: u64,
    },
    /// The session nonce is missing or malformed.
    #[error(
        "dispatch material nonce is missing or malformed: a well-formed session nonce is required"
    )]
    BadNonce,
    /// The Kernel-issued launch grant is malformed, foreign, or stale.
    /// An invalid grant is a refusal, never a fallback.
    #[error("dispatch material launch grant is invalid or foreign: {0}")]
    BadGrant(String),
}

/// Derives the bins-local dispatch file path: the executable directory plus
/// [`DISPATCHED_MATERIAL_FILE_NAME`].
///
/// Locator only, never authority: [`std::env::current_exe`] reads the OS
/// loader image path, not the environment block, and the file found there
/// is untrusted presenter bytes until validated. Returns `None` when the
/// image path is unavailable, which the caller treats as absent material.
#[must_use]
pub fn dispatched_material_path() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let directory = executable.parent()?;
    Some(directory.join(DISPATCHED_MATERIAL_FILE_NAME))
}

/// Reads and validates the session-bound attempt material for this
/// invocation against the live bootstrap epoch.
///
/// Returns `Ok(None)` when no dispatch file was delivered (the caller keeps
/// the exact `DenyNoPresentedAttempt` path), `Ok(Some(_))` when the file
/// validated and was consumed once, and `Err(_)` typed fail-closed when a
/// file is present but invalid. Never reads argv, stdin, or environment.
pub fn read_dispatched_material(
    live_epoch: &EpochId,
) -> Result<Option<ValidatedDispatchedAttempt>, DispatchedMaterialError> {
    let Some(path) = dispatched_material_path() else {
        return Ok(None);
    };
    read_dispatched_material_from(&path, live_epoch)
}

/// Reads and validates session-bound attempt material from one explicit
/// path, for the production locator plus bounded tests.
///
/// The path parameter exists so tests can stage material without touching
/// the executable directory; production always passes
/// [`dispatched_material_path`]. Semantics match
/// [`read_dispatched_material`].
pub fn read_dispatched_material_from(
    path: &Path,
    live_epoch: &EpochId,
) -> Result<Option<ValidatedDispatchedAttempt>, DispatchedMaterialError> {
    if let Some(actual) = bounded_file_len(path)? {
        return Err(DispatchedMaterialError::TooLarge {
            maximum: DISPATCHED_MATERIAL_LIMIT_BYTES,
            actual,
        });
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(DispatchedMaterialError::Io(error.to_string())),
    };
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > DISPATCHED_MATERIAL_LIMIT_BYTES {
        return Err(DispatchedMaterialError::TooLarge {
            maximum: DISPATCHED_MATERIAL_LIMIT_BYTES,
            actual,
        });
    }
    let envelope: DispatchedAttemptEnvelope = serde_json::from_slice(&bytes)
        .map_err(|error| DispatchedMaterialError::Malformed(truncate_detail(&error.to_string())))?;
    let validated = validate_envelope(envelope, live_epoch)?;
    // Consume-once: a validated presentation must not linger for a later
    // invocation to replay. Removal is best-effort; the kernel launch reaps
    // the file regardless, and removal failure never fails the shot.
    let _ = fs::remove_file(path);
    Ok(Some(validated))
}

/// Pre-checks the file length so an unbounded file is refused before it is
/// read. Returns `Ok(None)` when the length is within bounds or unknown
/// (the post-read check still applies); returns the observed length when it
/// already exceeds the bound. A missing file surfaces as `Ok(None)` here so
/// the read below can report absence exactly once.
fn bounded_file_len(path: &Path) -> Result<Option<u64>, DispatchedMaterialError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(DispatchedMaterialError::Io(error.to_string())),
    };
    let actual = metadata.len();
    if actual > DISPATCHED_MATERIAL_LIMIT_BYTES {
        Ok(Some(actual))
    } else {
        Ok(None)
    }
}

/// Validates one parsed envelope against the live bootstrap epoch. Every
/// check is fail-closed; the order is cheapest-first and performs no
/// transport, no execution, and no authority minting.
fn validate_envelope(
    envelope: DispatchedAttemptEnvelope,
    live_epoch: &EpochId,
) -> Result<ValidatedDispatchedAttempt, DispatchedMaterialError> {
    validate_nonce(&envelope.nonce)?;
    envelope
        .attempt
        .validate()
        .map_err(|error| DispatchedMaterialError::Contract(truncate_detail(&error.to_string())))?;
    envelope
        .attempt
        .validate_canonical_digest()
        .map_err(|error| DispatchedMaterialError::Contract(truncate_detail(&error.to_string())))?;
    let parsed: ClosedRepairRequest = serde_json::from_str(&envelope.attempt.closed_request_json)
        .map_err(|error| {
        DispatchedMaterialError::Contract(truncate_detail(&error.to_string()))
    })?;
    if parsed != envelope.request {
        return Err(DispatchedMaterialError::Contract(
            "dispatch envelope closed request does not equal the presented closed request"
                .to_owned(),
        ));
    }
    envelope
        .request
        .validate_closed(&envelope.manifest, OffsetDateTime::now_utc())
        .map_err(|error| DispatchedMaterialError::Contract(truncate_detail(&error.to_string())))?;
    if envelope.epoch != *live_epoch {
        return Err(DispatchedMaterialError::StaleEpoch {
            presented: format!("{epoch:?}", epoch = envelope.epoch),
            live: format!("{live_epoch:?}"),
        });
    }
    check_fence_against_epoch(&envelope.request.fence, live_epoch).map_err(|_| {
        DispatchedMaterialError::StaleEpoch {
            presented: format!("{fence:?}", fence = envelope.request.fence.authority_epoch),
            live: format!("{live_epoch:?}"),
        }
    })?;
    if envelope.generation == 0 || envelope.generation != envelope.request.fence.generation {
        return Err(DispatchedMaterialError::StaleGeneration {
            presented: envelope.generation,
            fence: envelope.request.fence.generation,
        });
    }
    validate_grant(&envelope.grant, live_epoch, envelope.generation)?;
    Ok(ValidatedDispatchedAttempt {
        attempt: envelope.attempt,
        request: envelope.request,
        manifest: envelope.manifest,
        epoch: envelope.epoch,
        generation: envelope.generation,
        nonce: envelope.nonce,
        grant: envelope.grant,
    })
}

/// Requires a well-formed opaque session nonce: bounded length over an
/// explicit hyphen/underscore/dot alphanumeric alphabet. The value is never
/// interpreted, only carried for the kernel-side session proof.
fn validate_nonce(nonce: &str) -> Result<(), DispatchedMaterialError> {
    if !(DISPATCH_NONCE_MIN_LEN..=DISPATCH_NONCE_MAX_LEN).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(DispatchedMaterialError::BadNonce);
    }
    Ok(())
}

/// Validates the Kernel-issued launch grant fail-closed against the live
/// bootstrap epoch and the presented session generation.
///
/// The grant is proved through the exact broker constructors the local
/// dispatch authority consumes (`FencingToken::new` with a non-zero
/// `Generation::new`, plus `ActionLeaseRef::new`), then bound: its
/// authority epoch must equal the live epoch as an exact tuple (a
/// foreign/stale grant is refused here, before any issue), its fence
/// generation must equal the presented session generation (the Kernel
/// writes both from the same live activation generation), and its digest
/// and expiry must be well-formed. An invalid grant is a refusal, never a
/// fallback. Freshness against the wall clock is enforced at issue time by
/// the authority, not here.
fn validate_grant(
    grant: &DispatchGrant,
    live_epoch: &EpochId,
    presented_generation: u64,
) -> Result<(), DispatchedMaterialError> {
    require_lowercase_digest(&grant.grant_digest).map_err(DispatchedMaterialError::BadGrant)?;
    if grant.expires_at == 0 {
        return Err(DispatchedMaterialError::BadGrant(
            "grant expiry must be non-zero".to_owned(),
        ));
    }
    let generation = Generation::new(grant.fence_generation)
        .map_err(|error| DispatchedMaterialError::BadGrant(truncate_detail(&error.to_string())))?;
    FencingToken::new(
        grant.authority_epoch.clone(),
        generation,
        grant.fence_nonce.clone(),
    )
    .map_err(|error| DispatchedMaterialError::BadGrant(truncate_detail(&error.to_string())))?;
    ActionLeaseRef::new(grant.idempotency_key.clone())
        .map_err(|error| DispatchedMaterialError::BadGrant(truncate_detail(&error.to_string())))?;
    if grant.authority_epoch != *live_epoch {
        return Err(DispatchedMaterialError::BadGrant(format!(
            "grant epoch is foreign or stale: presented {presented:?}, live {live_epoch:?}",
            presented = grant.authority_epoch,
        )));
    }
    if grant.fence_generation != presented_generation {
        return Err(DispatchedMaterialError::BadGrant(format!(
            "grant generation {presented} does not equal the presented session generation {presented_generation}",
            presented = grant.fence_generation,
        )));
    }
    Ok(())
}

/// Requires a lowercase SHA-256 hex digest, mirroring the Kernel grant
/// gate: exactly 64 lowercase hex characters.
fn require_lowercase_digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("grant digest must be a lowercase SHA-256 digest".to_owned());
    }
    Ok(())
}

/// Bounds third-party error detail carried into deny lines.
fn truncate_detail(detail: &str) -> String {
    const LIMIT: usize = 256;
    detail.chars().take(LIMIT).collect()
}
