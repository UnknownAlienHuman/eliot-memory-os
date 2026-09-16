#![forbid(unsafe_code)]

//! Protected Dreamer launch-claim port: the Dreamer child half of the T12-09
//! protected launch (Implements #702).
//!
//! The Kernel half landed separately (`bins/eliot-kernel/src/
//! dreamer_dispatch_launch.rs`, reference-only here): before spawn it records
//! one launch lineage for the exact queued job/attempt and stages protected
//! handoff bytes as `eliot-dreamer.admitted-job.json` next to the child
//! executable. This module is the only Dreamer-side consumer of those bytes.
//!
//! Locator (untrusted bytes, never authority): the path is derived from
//! [`std::env::current_exe`] (the OS loader image path, not the environment
//! block); nothing is taken from argv, stdin, or environment variables, and no
//! ownership is inferred from the path itself. The staged envelope is closed
//! ([`DreamerDispatchedEnvelope`] mirrors the Kernel shape field-for-field
//! with `deny_unknown_fields`; a bins-on-bins `eliot-kernel` dependency is
//! forbidden, so the shape is mirrored locally like the Doctor precedent).
//!
//! Validation is cheapest-first, mirroring `validate_dreamer_material`: text
//! shapes, ledger revision, fence shape plus generation agreement, exact-tuple
//! epoch equality, nonce shape, then the launch grant through the exact broker
//! constructors the local authority consumes, bound to the live epoch and the
//! presented generation. Every failure is fail-closed: no permit is derived,
//! no claim is transacted, and the caller maps the typed denial to
//! `KernelAdmissionRequired` (exit 78) without effect.
//!
//! The in-process dispatch permit follows the #1460 child-local authority
//! with the Doctor ephemeral-key shape: [`DreamerDispatchAuthority`] activates
//! one per-process authority around fresh in-memory key material (never
//! persisted, never transported) and issues exactly one [`ProcessRequest`]
//! via `FencingToken::new` + `ActionLeaseRef::new` + `PermitIssuance::new` +
//! `DispatchValidationContext::new` + `ProcessRequest::new`. The issued request
//! is derived and then dropped: it proves the grant binds through the real
//! contour constructors now, and dropping the authority admits no second
//! issuance in this process. Authority itself stays Kernel-side: the staged
//! file is consumed once, and the K2 bound-worker arm re-gates the exact
//! job/scope/revision/fence against the retained launch lineage at claim
//! time, so a tampered, foreign, or replayed presentation never starts a
//! second worker.
//!
//! The claim itself is `LeaseExact` then `Start` through the authenticated
//! worker session over the sync [`KernelClient::transact_json`] path (which
//! bridges onto its own current-thread runtime internally, so this module
//! stays sync and takes no direct `tokio` dependency): the transport identity
//! is bound with `set_request_identity` before every transact, the `Start`
//! reuses only the lease the `LeaseExact` reply carried, and both replies are
//! bound with `DurableJobResponse::validate_for`. On non-Windows hosts the
//! transport reports `FrontDoorClosed`, which fails closed like any other
//! transport denial.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_cli::kernel_client::{KernelClient, KernelClientError};
use eliot_contracts::{
    ClockReading, EpochId, ProductId, RequestId, RequestMetadata, SourceId, StateFence, sha256_hex,
};
use eliot_platform::ClockObservation;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    FencingToken, Generation, ImageId, JobId, KernelDispatchKey, OperationId, PermitIssuance,
    ProcessExecutionError, ProcessIntent, ProcessRequest, ProcessTreeId, ResourceLimits, SessionId,
    SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::DispatchValidationPort;
use eliot_protocol::RequestIdentity;
use eliot_protocol::dreamer_job::{
    DurableJobError, DurableJobRequest, DurableJobResponse, DurableRequestIdentity, JobOperation,
    JobRole,
};
use eliot_protocol::dreamer_job::JobState as ProtocolJobState;

/// Stable session module identity of the one-shot Dreamer worker.
///
/// Mirrors the Kernel constant; the worker never self-asserts authority
/// through this string. It names the local claim intent image and documents
/// which session the K2 bound-worker arm admits.
pub(crate) const DREAMER_MODULE_ID: &str = "eliot-dreamer";

/// Protected dispatch file name the Dreamer child reads from its executable
/// directory (`current_exe`, never argv/stdin/env).
///
/// Mirrors the Kernel constant; the child reader stays the authority for the
/// value on this side of the seam.
pub(crate) const DREAMER_MATERIAL_FILE_NAME: &str = "eliot-dreamer.admitted-job.json";

/// Upper bound for the dispatch file, mirroring the Kernel bound.
pub(crate) const DREAMER_MATERIAL_LIMIT_BYTES: u64 = 256 * 1024;

/// Session-nonce shape bounds (I7.5), mirroring the Kernel bounds.
pub(crate) const DREAMER_NONCE_MIN_LEN: usize = 16;
/// Session-nonce shape bounds (I7.5), mirroring the Kernel bounds.
pub(crate) const DREAMER_NONCE_MAX_LEN: usize = 256;

/// Closed wire identity of the K2 Dreamer job route.
///
/// Mirrors the Kernel constant as a local string (a bins-on-bins dependency
/// is forbidden); the operation string only selects the closed route, and the
/// typed envelope below still proves the claim.
pub(crate) const DREAMER_JOB_WIRE_ID: &str = "eliot.kernel.dreamer-job";

/// Operation prefix for the Dreamer child admission, mirroring the Kernel
/// prefix. The admitted executor replays (never double-spawns) an identical
/// launch under this lineage.
const DREAMER_OPERATION_PREFIX: &str = "dreamer-launch";

/// Revision head binding the grant digest on every issuance and its
/// validation context, mirroring the broker's `launch-grant` head.
const LAUNCH_GRANT_HEAD: &str = "launch-grant";

/// Validation revision carried on every validation context, mirroring the
/// broker.
const VALIDATION_REVISION: u64 = 1;

/// Product/source identity carried on the claim transport envelope.
const CLAIM_PRODUCT_ID: &str = "eliot-dreamer";
/// Source identity carried on the claim transport envelope.
const CLAIM_SOURCE_ID: &str = "eliot-dreamer";

/// Fresh-transport deadline horizon for one claim transact, in milliseconds.
const CLAIM_DEADLINE_HORIZON_MS: u64 = 30_000;

/// Single candidate for an exact claim: the worker claims one exact queued
/// job, never a selection.
const LEASE_EXACT_MAX_CANDIDATES: u32 = 1;

/// Kernel-issued launch-grant material for one dispatched Dreamer child.
///
/// Bins-local mirror of the Kernel half: only these six fields cross the
/// seam (the concrete [`ProcessRequest`] is never serialized). Every field is
/// untrusted presenter bytes until [`read_material_from`] validates it
/// fail-closed; an invalid grant is a refusal, never a fallback.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispatchGrant {
    /// Lowercase SHA-256 binding the grant fields plus the admission
    /// identity digest; carried as the one-shot nonce plus the
    /// `launch-grant` revision-head value.
    pub(crate) grant_digest: String,
    /// Live authority epoch bound at admission; must equal the live epoch as
    /// an exact tuple.
    pub(crate) authority_epoch: EpochId,
    /// Live activation generation bound at admission (non-zero); must equal
    /// the presented session generation.
    pub(crate) fence_generation: u64,
    /// Deterministic per-identity fence nonce for `FencingToken::new`.
    pub(crate) fence_nonce: String,
    /// Deterministic per-identity lease for `ActionLeaseRef::new`.
    pub(crate) idempotency_key: String,
    /// Grant expiry in Unix milliseconds for `PermitIssuance::new`
    /// (non-zero; freshness is enforced at issue time).
    pub(crate) expires_at: u64,
}

/// Kernel-staged protected handoff for one admitted Dreamer job.
///
/// Bins-local mirror of `DreamerDispatchedEnvelope`: the two lookup keys plus
/// the Kernel-bound revision/scope/fence/epoch/generation/nonce/grant. The
/// parsed value is still untrusted presenter bytes until [`validate_envelope`]
/// binds it against the live authority.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DreamerDispatchedEnvelope {
    /// Exact queued job identity (lookup key; must answer the ledger).
    pub(crate) job_id: String,
    /// Exact queued attempt identity (lookup key; must answer the ledger).
    pub(crate) attempt_id: String,
    /// Exact ledger revision the worker must claim.
    pub(crate) revision: u64,
    /// Scope the ledger bound to this job (never caller bytes).
    pub(crate) scope_id: String,
    /// Fence the ledger bound to this job (never caller bytes).
    pub(crate) fence: StateFence,
    /// Live authority epoch bound at launch (never envelope bytes alone).
    pub(crate) epoch: EpochId,
    /// Live activation generation bound at launch (non-zero).
    pub(crate) generation: u64,
    /// I7.5/I15.2 launch nonce, deterministic per lineage.
    pub(crate) nonce: String,
    /// Kernel-issued launch grant the child derives its permit from.
    pub(crate) grant: DispatchGrant,
}

/// Session-bound Dreamer material validated against the live authority.
///
/// Carries exactly what the managed child needs to prove its claim. This
/// value alone (without the local dispatch permit derived from `grant` and
/// without the K2 claim) never drives execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedDreamerMaterial {
    /// Exact queued job identity.
    pub(crate) job_id: String,
    /// Exact queued attempt identity.
    pub(crate) attempt_id: String,
    /// Exact ledger revision the worker must claim.
    pub(crate) revision: u64,
    /// Scope the ledger bound to this job.
    pub(crate) scope_id: String,
    /// Fence the ledger bound to this job.
    pub(crate) fence: StateFence,
    /// Live epoch this material bound against.
    pub(crate) epoch: EpochId,
    /// Generation this material bound against.
    pub(crate) generation: u64,
    /// Well-formed session nonce.
    pub(crate) nonce: String,
    /// Validated Kernel-issued launch grant.
    pub(crate) grant: DispatchGrant,
}

/// Typed failure for the Dreamer launch-claim port. Every variant is
/// fail-closed: the one-shot entry maps each to exit 78 without effect.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum KernelPortError {
    /// The dispatch file exists but cannot be read.
    #[error("dreamer dispatch material unreadable: {0}")]
    Io(String),
    /// The dispatch file exceeds the bounded input limit.
    #[error("dreamer dispatch material exceeds {maximum} bytes (observed {actual})")]
    TooLarge {
        /// Enforced input bound.
        maximum: u64,
        /// Observed file length.
        actual: u64,
    },
    /// The dispatch file is not a closed dispatch envelope.
    #[error("dreamer dispatch material is not a closed dispatch envelope: {0}")]
    Malformed(String),
    /// The dispatch material violates the closed contract.
    #[error("dreamer dispatch material violates the closed contract: {0}")]
    InvalidMaterial(String),
    /// The presented epoch disagrees with the live authority epoch.
    #[error("dreamer dispatch material epoch is foreign or stale: presented {presented}, live {live}")]
    StaleEpoch {
        /// Presented epoch value.
        presented: String,
        /// Live authority epoch value.
        live: String,
    },
    /// The presented generation is zero or disagrees with the ledger fence
    /// generation.
    #[error(
        "dreamer dispatch material generation is stale or unbound: presented {presented}, fence {fence}"
    )]
    StaleGeneration {
        /// Presented generation value.
        presented: u64,
        /// Ledger fence generation value.
        fence: u64,
    },
    /// The session nonce is missing or malformed.
    #[error(
        "dreamer dispatch material nonce is missing or malformed: a well-formed session nonce is required"
    )]
    BadNonce,
    /// The Kernel-issued launch grant is malformed, foreign, or stale.
    /// An invalid grant is a refusal, never a fallback.
    #[error("dreamer dispatch material launch grant is invalid or foreign: {0}")]
    BadGrant(String),
    /// The authenticated Kernel transport refused the claim.
    #[error("dreamer Kernel claim transport failed: {0}")]
    Transport(String),
    /// A locally built claim or a Kernel reply violated the closed wire
    /// contract.
    #[error("dreamer Kernel claim violated the closed contract: {0}")]
    Contract(String),
}

/// Derives the bins-local dispatch file path: the executable directory plus
/// [`DREAMER_MATERIAL_FILE_NAME`].
///
/// Locator only, never authority: [`std::env::current_exe`] reads the OS
/// loader image path, not the environment block, and the file found there is
/// untrusted presenter bytes until validated. Returns `None` when the image
/// path is unavailable, which the caller treats as absent material.
#[must_use]
pub(crate) fn material_path() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let directory = executable.parent()?;
    Some(directory.join(DREAMER_MATERIAL_FILE_NAME))
}

/// Resolves the executable/working-directory pair the local claim intent
/// binds: the OS loader image path and its parent directory. Nothing is
/// discovered from argv or the environment.
pub(crate) fn claim_executable_paths() -> Result<(PathBuf, PathBuf), KernelPortError> {
    let executable = std::env::current_exe()
        .map_err(|error| KernelPortError::Io(truncate_detail(&error.to_string())))?;
    let Some(directory) = executable.parent() else {
        return Err(KernelPortError::InvalidMaterial(
            "dreamer child executable has no parent directory".to_owned(),
        ));
    };
    let directory = directory.to_path_buf();
    Ok((executable, directory))
}

/// Parses the live authority epoch echoed by the authenticated health reply.
///
/// The health reply is already authenticated by [`KernelClient::probe`]
/// (generation-bound `ServerHello` plus binding checks inside the client); the
/// epoch echoed here is the only epoch staged material binds against.
pub(crate) fn live_epoch_from_health(
    health: &serde_json::Value,
) -> Result<EpochId, KernelPortError> {
    let epoch_value = health.get("authority_epoch").ok_or_else(|| {
        KernelPortError::Contract(
            "kernel health reply carries no live authority epoch".to_owned(),
        )
    })?;
    serde_json::from_value(epoch_value.clone()).map_err(|_| {
        KernelPortError::Contract(
            "kernel health reply authority epoch is not a lineaged epoch".to_owned(),
        )
    })
}

/// Reads and validates the session-bound Dreamer material for this
/// invocation against the live authority epoch.
///
/// Returns `Ok(None)` when no dispatch file was delivered (the caller keeps
/// the exact fail-closed path), `Ok(Some(_))` when the file validated and was
/// consumed once, and `Err(_)` typed fail-closed when a file is present but
/// invalid. Never reads argv, stdin, or environment.
pub(crate) fn read_material(
    live_epoch: &EpochId,
) -> Result<Option<ValidatedDreamerMaterial>, KernelPortError> {
    let Some(path) = material_path() else {
        return Ok(None);
    };
    read_material_from(&path, live_epoch)
}

/// Reads and validates session-bound Dreamer material from one explicit
/// path, for the production locator plus bounded tests.
///
/// The path parameter exists so tests can stage material without touching
/// the executable directory; production always passes [`material_path`].
/// Semantics match [`read_material`].
pub(crate) fn read_material_from(
    path: &Path,
    live_epoch: &EpochId,
) -> Result<Option<ValidatedDreamerMaterial>, KernelPortError> {
    if let Some(actual) = bounded_file_len(path)? {
        return Err(KernelPortError::TooLarge {
            maximum: DREAMER_MATERIAL_LIMIT_BYTES,
            actual,
        });
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(KernelPortError::Io(truncate_detail(&error.to_string()))),
    };
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > DREAMER_MATERIAL_LIMIT_BYTES {
        return Err(KernelPortError::TooLarge {
            maximum: DREAMER_MATERIAL_LIMIT_BYTES,
            actual,
        });
    }
    let envelope: DreamerDispatchedEnvelope = serde_json::from_slice(&bytes)
        .map_err(|error| KernelPortError::Malformed(truncate_detail(&error.to_string())))?;
    let validated = validate_envelope(&envelope, live_epoch)?;
    // Consume-once: a validated presentation must not linger for a later
    // invocation to replay. Removal is best-effort; the Kernel launch reaps
    // the file regardless, and removal failure never fails the claim.
    let _ = fs::remove_file(path);
    Ok(Some(validated))
}

/// Pre-checks the file length so an unbounded file is refused before it is
/// read. Returns `Ok(None)` when the length is within bounds or unknown
/// (the post-read check still applies); returns the observed length when it
/// already exceeds the bound. A missing file surfaces as `Ok(None)` here so
/// the read below can report absence exactly once.
fn bounded_file_len(path: &Path) -> Result<Option<u64>, KernelPortError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(KernelPortError::Io(truncate_detail(&error.to_string()))),
    };
    let actual = metadata.len();
    if actual > DREAMER_MATERIAL_LIMIT_BYTES {
        Ok(Some(actual))
    } else {
        Ok(None)
    }
}

/// Validates one parsed envelope against the live authority epoch.
///
/// Every check is fail-closed and cheapest-first, mirroring
/// `validate_dreamer_material`, performing no transport, no execution, and
/// no authority minting: identity shapes, ledger revision, fence shape plus
/// generation agreement, exact-tuple epoch equality, nonce shape, then the
/// launch grant through the exact broker constructors the child derives its
/// permit from, bound to the live epoch and the presented generation. A
/// foreign or stale epoch, generation, or grant is a refusal, never a
/// fallback.
fn validate_envelope(
    envelope: &DreamerDispatchedEnvelope,
    live_epoch: &EpochId,
) -> Result<ValidatedDreamerMaterial, KernelPortError> {
    require_dreamer_text(&envelope.job_id, "job identity")?;
    require_dreamer_text(&envelope.attempt_id, "attempt identity")?;
    require_dreamer_text(&envelope.scope_id, "scope identity")?;
    if envelope.revision == 0 {
        return Err(KernelPortError::InvalidMaterial(
            "dreamer lineage revision must be non-zero".to_owned(),
        ));
    }
    envelope
        .fence
        .validate()
        .map_err(|error| KernelPortError::InvalidMaterial(error.to_string()))?;
    if envelope.generation == 0 {
        return Err(KernelPortError::InvalidMaterial(
            "dreamer launch generation must be non-zero".to_owned(),
        ));
    }
    if envelope.fence.resource_generation.value() != envelope.generation {
        return Err(KernelPortError::StaleGeneration {
            presented: envelope.generation,
            fence: envelope.fence.resource_generation.value(),
        });
    }
    if envelope.epoch != *live_epoch {
        return Err(KernelPortError::StaleEpoch {
            presented: format!("{:?}", envelope.epoch),
            live: format!("{live_epoch:?}"),
        });
    }
    validate_nonce(&envelope.nonce)?;
    validate_grant(&envelope.grant, live_epoch, envelope.generation)?;
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

/// Requires non-blank, control-free, bounded identity text, mirroring the
/// Kernel gate.
fn require_dreamer_text(value: &str, what: &'static str) -> Result<(), KernelPortError> {
    if value.trim().is_empty() {
        return Err(KernelPortError::InvalidMaterial(format!(
            "dreamer {what} must be non-blank"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(KernelPortError::InvalidMaterial(format!(
            "dreamer {what} must not contain control characters"
        )));
    }
    if value.len() > 1024 {
        return Err(KernelPortError::InvalidMaterial(format!(
            "dreamer {what} must not exceed 1024 UTF-8 bytes"
        )));
    }
    Ok(())
}

/// Requires a well-formed opaque session nonce: bounded length over the
/// explicit hyphen/underscore/dot alphanumeric alphabet, mirroring the Kernel
/// gate. The value is never interpreted, only carried for the Kernel-side
/// claim proof.
fn validate_nonce(nonce: &str) -> Result<(), KernelPortError> {
    if !(DREAMER_NONCE_MIN_LEN..=DREAMER_NONCE_MAX_LEN).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(KernelPortError::BadNonce);
    }
    Ok(())
}

/// Validates the Kernel-issued launch grant fail-closed against the live
/// authority epoch and the presented session generation.
///
/// The grant is proved through the exact broker constructors the local
/// dispatch authority consumes (`FencingToken::new` with a non-zero
/// `Generation::new`, plus `ActionLeaseRef::new`), then bound: its authority
/// epoch must equal the live epoch as an exact tuple (a foreign/stale grant
/// is refused here, before any issue), its fence generation must equal the
/// presented session generation (the Kernel writes both from the same live
/// activation generation), and its digest and expiry must be well-formed. An
/// invalid grant is a refusal, never a fallback. Freshness against the wall
/// clock is enforced at issue time by the authority, not here.
fn validate_grant(
    grant: &DispatchGrant,
    live_epoch: &EpochId,
    presented_generation: u64,
) -> Result<(), KernelPortError> {
    require_lowercase_digest(&grant.grant_digest).map_err(KernelPortError::BadGrant)?;
    if grant.expires_at == 0 {
        return Err(KernelPortError::BadGrant(
            "grant expiry must be non-zero".to_owned(),
        ));
    }
    let generation = Generation::new(grant.fence_generation)
        .map_err(|error| KernelPortError::BadGrant(truncate_detail(&error.to_string())))?;
    FencingToken::new(
        grant.authority_epoch.clone(),
        generation,
        grant.fence_nonce.clone(),
    )
    .map_err(|error| KernelPortError::BadGrant(truncate_detail(&error.to_string())))?;
    ActionLeaseRef::new(grant.idempotency_key.clone())
        .map_err(|error| KernelPortError::BadGrant(truncate_detail(&error.to_string())))?;
    if grant.authority_epoch != *live_epoch {
        return Err(KernelPortError::BadGrant(format!(
            "grant epoch is foreign or stale: presented {:?}, live {live_epoch:?}",
            grant.authority_epoch,
        )));
    }
    if grant.fence_generation != presented_generation {
        return Err(KernelPortError::BadGrant(format!(
            "grant generation {} does not equal the presented session generation {presented_generation}",
            grant.fence_generation,
        )));
    }
    Ok(())
}

/// Requires a lowercase SHA-256 hex digest, mirroring the Kernel grant gate:
/// exactly 64 lowercase hex characters.
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

/// Ephemeral Dreamer-owned dispatch authority. The key lives only in this
/// process's memory for one shot; the authority instance plus the stored
/// validation context bind exactly one issued permit to its consuming
/// validation, mirroring the broker and the Doctor child.
pub(crate) struct DreamerDispatchAuthority {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
}

impl DreamerDispatchAuthority {
    /// Activates one ephemeral Dreamer authority around fresh in-memory key
    /// material. The authority id names this process invocation; the key
    /// never leaves this process.
    pub(crate) fn new() -> Result<Self, KernelPortError> {
        let pid = std::process::id();
        let nanos = system_nanos();
        let authority_id = DispatchAuthorityId::new(format!("dreamer-dispatch-{pid}-{nanos}"))
            .map_err(|error| KernelPortError::Contract(truncate_detail(&error.to_string())))?;
        let key = KernelDispatchKey::from_secret_bytes(fresh_key_bytes())
            .map_err(|error| KernelPortError::Contract(truncate_detail(&error.to_string())))?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
        })
    }

    /// Issues the single permit-bound process request for one validated
    /// grant and one caller-supplied admitted intent.
    ///
    /// Mirrors the broker exactly: the fence comes from the grant epoch,
    /// generation, and fence nonce; the lease from the grant idempotency
    /// key; the `launch-grant` revision head and the one-shot nonce both
    /// carry the grant digest; issuance runs from just before `now_unix_ms`
    /// to the grant expiry; and the stored validation context pins revision 1. Freshness (`issued_at < expires_at` at issue time and `now < expires_at` at consume time) is enforced by the contour types, never assumed.
    pub(crate) fn issue(
        &self,
        intent: &ProcessIntent,
        grant: &DispatchGrant,
        now_unix_ms: u64,
    ) -> Result<ProcessRequest, KernelPortError> {
        let invalid = |error: eliot_process::ContractError| {
            KernelPortError::Contract(truncate_detail(&error.to_string()))
        };
        let generation = Generation::new(grant.fence_generation).map_err(&invalid)?;
        let fence = FencingToken::new(
            grant.authority_epoch.clone(),
            generation,
            grant.fence_nonce.clone(),
        )
        .map_err(&invalid)?;
        let lease = ActionLeaseRef::new(grant.idempotency_key.clone()).map_err(&invalid)?;
        let heads = BTreeMap::from([(LAUNCH_GRANT_HEAD.to_owned(), grant.grant_digest.clone())]);
        let issuance = PermitIssuance::new(
            lease,
            fence.clone(),
            heads.clone(),
            now_unix_ms.saturating_sub(1).max(1),
            grant.expires_at,
            grant.grant_digest.clone(),
        )
        .map_err(&invalid)?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| {
                KernelPortError::Contract("dreamer authority lock poisoned".to_owned())
            })?
            .issue(intent, issuance)
            .map_err(&invalid)?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(i64::try_from(now_unix_ms).unwrap_or(i64::MAX)),
                known_time_ms: Some(i64::try_from(now_unix_ms).unwrap_or(i64::MAX)),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            grant.authority_epoch.clone(),
            heads,
            VALIDATION_REVISION,
        )
        .map_err(&invalid)?;
        *self
            .context
            .lock()
            .map_err(|_| {
                KernelPortError::Contract("dreamer context lock poisoned".to_owned())
            })? = Some(context);
        ProcessRequest::new(intent.clone(), permit).map_err(invalid)
    }
}

impl DispatchValidationPort for DreamerDispatchAuthority {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let current = self
            .context
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("dreamer context lock poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("missing dreamer validation context".to_owned())
            })?;
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("dreamer authority lock poisoned".to_owned())
            })?
            .validate_and_consume(request, observed, &current)
            .map_err(ProcessExecutionError::from)
    }
}

/// Derives the process-invocation component of the authority id from the
/// wall clock. Uniqueness (not secrecy) is load-bearing here: the id only
/// names the instance.
fn system_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        })
}

/// Generates fresh per-process key bytes from process-unique std sources
/// mixed through splitmix64, without adding a randomness dependency.
///
/// The load-bearing property is per-process uniqueness, not
/// unpredictability: the key never leaves this process, is never persisted,
/// and only binds permits issued by this same authority instance. The replay
/// fence is per-instance regardless, and the process exits after one shot.
fn fresh_key_bytes() -> [u8; 32] {
    static MIXER: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    let probe = 0u64;
    let stack = std::ptr::addr_of!(probe) as usize as u64;
    let pid = u64::from(std::process::id());
    let count = MIXER.fetch_add(1, Ordering::Relaxed);
    let mut state = system_nanos()
        ^ pid.wrapping_mul(0xBF58_476D_1CE4_E5B9)
        ^ stack.rotate_left(17)
        ^ count.wrapping_mul(0x94D0_49BB_1331_11EB);
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        chunk.copy_from_slice(&splitmix64(&mut state).to_le_bytes());
    }
    if out.iter().all(|byte| *byte == 0) {
        out[31] = 1;
    }
    out
}

/// Derives the admitted claim intent the local dispatch authority issues
/// against: the exact queued job/attempt under the validated generation, with
/// the OS-loader executable binding measured from real file bytes.
///
/// Every identity comes from the validated material (never argv/stdin/env):
/// the operation correlates this one-shot launch lineage, the tree/session
/// name the exact queued attempt, the job names the exact queued job, and the
/// image names this worker module. The executable path and working directory
/// come from the OS loader layout; the executable digest is measured from the
/// loader image file bytes (never asserted, never transported). The intent
/// takes no argv: the child consumes nothing from its command line. Resource
/// ceilings are fixed local fence bounds for a worker that spawns nothing.
/// The resulting permit never crosses a boundary: it proves the grant binds
/// through the real contour constructors in this process, while claim
/// authority stays Kernel-side at `LeaseExact`.
pub(crate) fn derive_claim_intent(
    material: &ValidatedDreamerMaterial,
    executable: &Path,
    working_directory: &Path,
) -> Result<ProcessIntent, KernelPortError> {
    let contract = |error: eliot_process::ContractError| {
        KernelPortError::Contract(truncate_detail(&error.to_string()))
    };
    let short = short_digest(&material.grant.grant_digest);
    let executable_str = executable.to_str().ok_or_else(|| {
        KernelPortError::InvalidMaterial(
            "dreamer claim executable locator is not well-formed".to_owned(),
        )
    })?;
    let working_directory_str = working_directory.to_str().ok_or_else(|| {
        KernelPortError::InvalidMaterial(
            "dreamer claim working directory locator is not well-formed".to_owned(),
        )
    })?;
    let image_bytes = fs::read(executable)
        .map_err(|error| KernelPortError::Io(truncate_detail(&error.to_string())))?;
    let environment = eliot_process::EnvironmentProjection::new(
        BTreeMap::new(),
        Vec::new(),
        eliot_process::EnvironmentInheritance::None,
    )
    .map_err(&contract)?;
    let limits = ResourceLimits::new(60_000, None, None, 65_536, 65_536, 0).map_err(&contract)?;
    ProcessIntent::new(
        OperationId::new(format!("{DREAMER_OPERATION_PREFIX}-{short}")).map_err(&contract)?,
        ProcessTreeId::new(material.attempt_id.clone()).map_err(&contract)?,
        JobId::new(material.job_id.clone()).map_err(&contract)?,
        ImageId::new(DREAMER_MODULE_ID).map_err(&contract)?,
        SessionId::new(material.attempt_id.clone()).map_err(&contract)?,
        Generation::new(material.generation).map_err(&contract)?,
        executable_str.to_owned(),
        sha256_hex(&image_bytes),
        Vec::new(),
        working_directory_str.to_owned(),
        environment,
        limits,
    )
    .map_err(&contract)
}

/// Derives the in-process dispatch permit for one validated material and
/// proves it seals.
///
/// The ephemeral authority is dropped on return: exactly one issuance is
/// possible in this process, and the sealed request proves the grant binds
/// through the real contour constructors now. Claim authority itself stays
/// Kernel-side at `LeaseExact`.
pub(crate) fn derive_permit(
    material: &ValidatedDreamerMaterial,
    executable: &Path,
    working_directory: &Path,
) -> Result<ProcessRequest, KernelPortError> {
    let authority = DreamerDispatchAuthority::new()?;
    let intent = derive_claim_intent(material, executable, working_directory)?;
    let now_unix_ms = unix_ms()?;
    let request = authority.issue(&intent, &material.grant, now_unix_ms)?;
    request
        .validate()
        .map_err(|error| KernelPortError::Contract(truncate_detail(&error.to_string())))?;
    Ok(request)
}

/// Short correlation suffix derived from the grant digest for locally minted
/// operation identities. The digest is already proved to be 64 lowercase hex
/// characters by validation; the take is still defensive.
fn short_digest(digest: &str) -> String {
    digest.chars().take(16).collect()
}

/// Current Unix time in milliseconds for issuance freshness and transport
/// clocks.
fn unix_ms() -> Result<u64, KernelPortError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| KernelPortError::Contract("dreamer clock is unavailable".to_owned()))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| KernelPortError::Contract("dreamer clock is out of range".to_owned()))
}

/// Bounds third-party error detail carried into deny lines.
fn truncate_detail(detail: &str) -> String {
    const LIMIT: usize = 256;
    detail.chars().take(LIMIT).collect()
}

/// Authenticated claim transport: binds the EBP request identity from the
/// admitted fence before every transact, then sends one exact operation
/// through the Kernel front door.
///
/// Implemented by [`KernelClaimTransport`] in production (through the
/// authenticated [`KernelClient::transact_json`]) and by a clearly-marked
/// fake in tests where a live Kernel is unavailable. Transport failures stay
/// transport failures; they are never mapped to admission or success.
pub(crate) trait ClaimTransport {
    /// Binds the exact caller identity for the next transact: the admitted
    /// fence plus the submitted operation identity and a live clock. Must be
    /// called before every transact; the production client fails closed with
    /// `MissingRequestIdentity` when it was not.
    fn bind_identity(
        &mut self,
        fence: &StateFence,
        operation_id: &str,
    ) -> Result<(), KernelPortError>;
    /// Sends one exact operation; the operation string is a contract
    /// selector, not a local command authority.
    fn transact(
        &mut self,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelPortError>;
}

/// Production claim transport over the installation-owned Kernel client.
pub(crate) struct KernelClaimTransport {
    client: KernelClient,
}

impl KernelClaimTransport {
    /// Wraps an authenticated client whose health handshake already passed.
    pub(crate) fn new(client: KernelClient) -> Self {
        Self { client }
    }
}

/// Builds the EBP request-identity JSON from the admitted fence snapshot.
///
/// The fence JSON must be the admitted [`StateFence`] (never invented
/// locally); the clock is the live observation. The request/idempotency/
/// deadline/cancellation bind the exact submitted operation identity.
/// Deserialization targets the exact [`RequestIdentity`] shape the client
/// binds, so a shape drift fails closed here instead of sending a stranger.
fn transport_identity_value(
    fence_json: &serde_json::Value,
    operation_id: &str,
    now_unix_ms: u64,
) -> Result<serde_json::Value, KernelPortError> {
    if !fence_json.is_object() {
        return Err(KernelPortError::Contract(
            "admitted fence snapshot is missing for the request identity".to_owned(),
        ));
    }
    if operation_id.trim().is_empty()
        || operation_id.chars().any(char::is_control)
        || operation_id.len() > 256
    {
        return Err(KernelPortError::Contract(
            "request identity operation is invalid".to_owned(),
        ));
    }
    let now_i64 = i64::try_from(now_unix_ms)
        .map_err(|_| KernelPortError::Contract("dreamer clock is out of range".to_owned()))?;
    let deadline = now_unix_ms.saturating_add(CLAIM_DEADLINE_HORIZON_MS);
    if deadline == 0 {
        return Err(KernelPortError::Contract(
            "request identity deadline is invalid".to_owned(),
        ));
    }
    Ok(serde_json::json!({
        "request": {
            "metadata": {
                "request_id": operation_id,
                "session_id": null,
                "task_id": null,
                "product_id": CLAIM_PRODUCT_ID,
                "source_id": CLAIM_SOURCE_ID,
                "state_fence": fence_json,
                "clock": {
                    "valid_time_ms": now_i64,
                    "known_time_ms": now_i64,
                    "transaction_sequence": null,
                    "monotonic_ns": null
                }
            },
            "state_fence": fence_json
        },
        "idempotency_key": operation_id,
        "deadline_unix_ms": deadline,
        "cancellation_id": format!("{operation_id}:cancel"),
    }))
}

impl ClaimTransport for KernelClaimTransport {
    fn bind_identity(
        &mut self,
        fence: &StateFence,
        operation_id: &str,
    ) -> Result<(), KernelPortError> {
        let now_unix_ms = unix_ms()?;
        let fence_json = serde_json::to_value(fence)
            .map_err(|error| KernelPortError::Contract(truncate_detail(&error.to_string())))?;
        let value = transport_identity_value(&fence_json, operation_id, now_unix_ms)?;
        let identity: RequestIdentity = serde_json::from_value(value).map_err(|error| {
            KernelPortError::Contract(format!(
                "admitted request identity shape failed: {}",
                truncate_detail(&error.to_string())
            ))
        })?;
        self.client.set_request_identity(identity);
        Ok(())
    }

    fn transact(
        &mut self,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelPortError> {
        self.client
            .transact_json(operation, payload)
            .map_err(|error: KernelClientError| {
                KernelPortError::Transport(truncate_detail(&error.to_string()))
            })
    }
}

/// Builds the typed `LeaseExact` claim for the exact queued values the staged
/// material binds: the ledger job/scope/revision under the live fence, with
/// the worker role the K2 bound-worker arm derives from the authenticated
/// session.
///
/// The operation binding carries the grant idempotency key as the stable
/// mutation identity (a retry keeps it while fresh transport correlation
/// rotates); the canonical digest is computed over the exact typed values so
/// the Kernel-side `DurableJobRequest::validate` re-proves role capability,
/// fence bindings, and hash agreement. The worker artifact names the exact
/// queued attempt: this worker claims only its own admitted attempt.
fn lease_exact_request(
    material: &ValidatedDreamerMaterial,
    operation_id: &str,
    now_unix_ms: u64,
) -> Result<DurableJobRequest, KernelPortError> {
    let contract = |error: DurableJobError| {
        KernelPortError::Contract(truncate_detail(&error.to_string()))
    };
    let fence_json = serde_json::to_value(&material.fence)
        .map_err(|error| KernelPortError::Contract(truncate_detail(&error.to_string())))?;
    let operation_value = serde_json::json!({
        "operation": "LEASE_EXACT",
        "selector": {
            "scope_id": material.scope_id,
            "expected_revision": material.revision,
            "expected_fence": fence_json,
            "worker_artifact_id": material.attempt_id,
            "max_candidates": LEASE_EXACT_MAX_CANDIDATES,
        },
        "job_id": material.job_id,
    });
    let operation: JobOperation = serde_json::from_value(operation_value).map_err(|error| {
        KernelPortError::Contract(format!(
            "dreamer lease claim shape failed: {}",
            truncate_detail(&error.to_string())
        ))
    })?;
    let identity_value = serde_json::json!({
        "request": transport_identity_value(&fence_json, operation_id, now_unix_ms)?,
        "operation": {
            "operation_id": operation_id,
            "request_id": operation_id,
            "idempotency_key": material.grant.idempotency_key,
            "operation_kind": "LEASE_EXACT",
            "effect": "CANDIDATE",
            "state_fence": fence_json,
        },
        "canonical_request_hash": "0".repeat(64),
    });
    let mut identity: DurableRequestIdentity =
        serde_json::from_value(identity_value).map_err(|error| {
            KernelPortError::Contract(format!(
                "dreamer lease identity shape failed: {}",
                truncate_detail(&error.to_string())
            ))
        })?;
    identity.canonical_request_hash = DurableRequestIdentity::digest_for(
        &identity.operation,
        &identity.request,
        &operation,
        JobRole::Worker,
    )
    .map_err(&contract)?;
    let request = DurableJobRequest {
        request_identity: identity,
        role: JobRole::Worker,
        operation,
    };
    request.validate().map_err(&contract)?;
    Ok(request)
}

/// Builds the typed `Start` for the lease the `LeaseExact` reply carried.
///
/// The lease is never invented: it is the exact projection the Kernel bound
/// to the claim. The operation binding rotates to a fresh `Start` mutation
/// identity while the lease pin stays stable.
fn start_request(
    material: &ValidatedDreamerMaterial,
    lease: &eliot_protocol::dreamer_job::JobLease,
    operation_id: &str,
    now_unix_ms: u64,
) -> Result<DurableJobRequest, KernelPortError> {
    let contract = |error: DurableJobError| {
        KernelPortError::Contract(truncate_detail(&error.to_string()))
    };
    let fence_json = serde_json::to_value(&material.fence)
        .map_err(|error| KernelPortError::Contract(truncate_detail(&error.to_string())))?;
    let operation = JobOperation::Start {
        lease: lease.clone(),
        now_unix_ms,
    };
    let identity_value = serde_json::json!({
        "request": transport_identity_value(&fence_json, operation_id, now_unix_ms)?,
        "operation": {
            "operation_id": operation_id,
            "request_id": operation_id,
            "idempotency_key": format!("{}:start", material.grant.idempotency_key),
            "operation_kind": "START_JOB",
            "effect": "CANDIDATE",
            "state_fence": fence_json,
        },
        "canonical_request_hash": "0".repeat(64),
    });
    let mut identity: DurableRequestIdentity =
        serde_json::from_value(identity_value).map_err(|error| {
            KernelPortError::Contract(format!(
                "dreamer start identity shape failed: {}",
                truncate_detail(&error.to_string())
            ))
        })?;
    identity.canonical_request_hash = DurableRequestIdentity::digest_for(
        &identity.operation,
        &identity.request,
        &operation,
        JobRole::Worker,
    )
    .map_err(&contract)?;
    let request = DurableJobRequest {
        request_identity: identity,
        role: JobRole::Worker,
        operation,
    };
    request.validate().map_err(&contract)?;
    Ok(request)
}

/// Builds the typed `Status` observation for the claimed job.
///
/// The worker role admits `Status` as a pure observation (never a mutation):
/// the operation binds the exact queued job/attempt/revision under the
/// admitted fence with the `READ` effect class, and the reply carries no
/// mutation disposition. The correlation identity rotates per call while the
/// idempotency key stays derived from the grant, so an exact retry replays
/// the same observation instead of mutating.
fn status_request(
    material: &ValidatedDreamerMaterial,
    operation_id: &str,
    now_unix_ms: u64,
) -> Result<DurableJobRequest, KernelPortError> {
    let contract = |error: DurableJobError| {
        KernelPortError::Contract(truncate_detail(&error.to_string()))
    };
    let fence_json = serde_json::to_value(&material.fence)
        .map_err(|error| KernelPortError::Contract(truncate_detail(&error.to_string())))?;
    let operation_value = serde_json::json!({
        "operation": "STATUS",
        "job_id": material.job_id,
        "attempt_id": material.attempt_id,
        "expected_revision": material.revision,
        "expected_fence": fence_json,
    });
    let operation: JobOperation = serde_json::from_value(operation_value).map_err(|error| {
        KernelPortError::Contract(format!(
            "dreamer status claim shape failed: {}",
            truncate_detail(&error.to_string())
        ))
    })?;
    let identity_value = serde_json::json!({
        "request": transport_identity_value(&fence_json, operation_id, now_unix_ms)?,
        "operation": {
            "operation_id": operation_id,
            "request_id": operation_id,
            "idempotency_key": format!("{}:status", material.grant.idempotency_key),
            "operation_kind": "STATUS",
            "effect": "READ",
            "state_fence": fence_json,
        },
        "canonical_request_hash": "0".repeat(64),
    });
    let mut identity: DurableRequestIdentity =
        serde_json::from_value(identity_value).map_err(|error| {
            KernelPortError::Contract(format!(
                "dreamer status identity shape failed: {}",
                truncate_detail(&error.to_string())
            ))
        })?;
    identity.canonical_request_hash = DurableRequestIdentity::digest_for(
        &identity.operation,
        &identity.request,
        &operation,
        JobRole::Worker,
    )
    .map_err(&contract)?;
    let request = DurableJobRequest {
        request_identity: identity,
        role: JobRole::Worker,
        operation,
    };
    request.validate().map_err(&contract)?;
    Ok(request)
}

/// Frames one validated claim request for the K2 Dreamer route: the closed
/// operation string plus the fenced store context under `context` and the
/// full typed K0 request under `request`.
fn dreamer_payload(
    request: &DurableJobRequest,
    context_id: &str,
    now_unix_ms: u64,
) -> Result<serde_json::Value, KernelPortError> {
    let fence = request.request_identity.operation.state_fence.clone();
    let now_i64 = i64::try_from(now_unix_ms)
        .map_err(|_| KernelPortError::Contract("dreamer clock is out of range".to_owned()))?;
    let context = RequestMetadata {
        request_id: RequestId::new(context_id).map_err(|error| {
            KernelPortError::Contract(truncate_detail(&error.to_string()))
        })?,
        session_id: None,
        task_id: None,
        product_id: ProductId::new(CLAIM_PRODUCT_ID).map_err(|error| {
            KernelPortError::Contract(truncate_detail(&error.to_string()))
        })?,
        source_id: SourceId::new(CLAIM_SOURCE_ID).map_err(|error| {
            KernelPortError::Contract(truncate_detail(&error.to_string()))
        })?,
        state_fence: fence,
        clock: ClockReading {
            valid_time_ms: Some(now_i64),
            known_time_ms: Some(now_i64),
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    let context_json = serde_json::to_value(&context)
        .map_err(|error| KernelPortError::Contract(truncate_detail(&error.to_string())))?;
    let request_json = serde_json::to_value(request)
        .map_err(|error| KernelPortError::Contract(truncate_detail(&error.to_string())))?;
    Ok(serde_json::json!({
        "operation": DREAMER_JOB_WIRE_ID,
        "context": context_json,
        "request": request_json,
    }))
}

/// Parses one Kernel reply and binds it to the request it must answer.
///
/// The reply must decode as the closed [`DurableJobResponse`] and pass
/// `validate_for` against the exact submitted request: exact identity echo,
/// per-kind job/scope/revision binding, and disposition presence. Anything
/// else fails closed and never invents a lease.
fn checked_response(
    reply: serde_json::Value,
    request: &DurableJobRequest,
) -> Result<DurableJobResponse, KernelPortError> {
    let response: DurableJobResponse = serde_json::from_value(reply).map_err(|error| {
        KernelPortError::Contract(format!(
            "dreamer Kernel reply is not a closed job response: {}",
            truncate_detail(&error.to_string())
        ))
    })?;
    response.validate_for(request).map_err(|error| {
        KernelPortError::Contract(format!(
            "dreamer Kernel reply does not bind the submitted claim: {}",
            truncate_detail(&error.to_string())
        ))
    })?;
    Ok(response)
}

/// Performs the validated one-shot claim: `LeaseExact` for the exact queued
/// job through the authenticated worker session, then `Start` on the lease
/// the claim reply carried.
///
/// Order is load-bearing: `Start` is built only from a validated
/// `LeaseExact` reply bound to the submitted claim, so a tampered, foreign,
/// or replayed presentation (already refused by validation) can never reach
/// this path, and a lost or refused claim never starts. Returns the validated
/// `Start` response the caller projects.
pub(crate) fn claim_once<T: ClaimTransport>(
    material: &ValidatedDreamerMaterial,
    transport: &mut T,
) -> Result<DurableJobResponse, KernelPortError> {
    let short = short_digest(&material.grant.grant_digest);
    let lease_operation_id = format!("dreamer-lease-{short}");
    let now_unix_ms = unix_ms()?;
    let lease_request = lease_exact_request(material, &lease_operation_id, now_unix_ms)?;
    transport.bind_identity(&material.fence, &lease_operation_id)?;
    let lease_payload = dreamer_payload(
        &lease_request,
        &format!("{lease_operation_id}-ctx"),
        now_unix_ms,
    )?;
    let lease_reply = transport.transact(DREAMER_JOB_WIRE_ID, lease_payload)?;
    let lease_response = checked_response(lease_reply, &lease_request)?;
    let Some(lease) = lease_response.lease.clone() else {
        return Err(KernelPortError::Contract(
            "dreamer Kernel lease claim carried no lease".to_owned(),
        ));
    };
    let start_operation_id = format!("dreamer-start-{short}");
    let start_now_unix_ms = unix_ms()?;
    let start_operation = start_request(material, &lease, &start_operation_id, start_now_unix_ms)?;
    transport.bind_identity(&material.fence, &start_operation_id)?;
    let start_payload = dreamer_payload(
        &start_operation,
        &format!("{start_operation_id}-ctx"),
        start_now_unix_ms,
    )?;
    let start_reply = transport.transact(DREAMER_JOB_WIRE_ID, start_payload)?;
    let started = checked_response(start_reply, &start_operation)?;
    if started.state != ProtocolJobState::Running {
        return Err(KernelPortError::Contract(format!(
            "dreamer Kernel start did not report a running job (state {:?})",
            started.state,
        )));
    }
    Ok(started)
}

/// Observes the Kernel-proved disposition of the claimed job.
///
/// Runs only after [`claim_once`]: the `Status` observation binds the exact
/// claimed job/attempt/revision/fence, proves liveness without effects, and
/// preserves the exact terminal or reconciling disposition the Kernel
/// reports. A refused or unbound reply fails closed and never invents a view.
pub(crate) fn status_once<T: ClaimTransport>(
    material: &ValidatedDreamerMaterial,
    transport: &mut T,
) -> Result<DurableJobResponse, KernelPortError> {
    let short = short_digest(&material.grant.grant_digest);
    let operation_id = format!("dreamer-status-{short}");
    let now_unix_ms = unix_ms()?;
    let request = status_request(material, &operation_id, now_unix_ms)?;
    transport.bind_identity(&material.fence, &operation_id)?;
    let payload = dreamer_payload(
        &request,
        &format!("{operation_id}-ctx"),
        now_unix_ms,
    )?;
    let reply = transport.transact(DREAMER_JOB_WIRE_ID, payload)?;
    checked_response(reply, &request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> Result<EpochId, String> {
        let lineage = EpochLineageId::new(TEST_LINEAGE).map_err(|error| error.to_string())?;
        let sequence = NonZeroU64::new(sequence).ok_or_else(|| "test sequence is zero".to_owned())?;
        EpochId::new(lineage, sequence).map_err(|error| error.to_string())
    }

    fn test_fence(sequence: u64, generation: u64) -> Result<StateFence, String> {
        let epoch = test_epoch(sequence)?;
        let resource_generation =
            ResourceGeneration::new(generation).map_err(|error| error.to_string())?;
        Ok(StateFence::new(epoch, resource_generation))
    }

    fn test_digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn valid_envelope_value() -> Result<serde_json::Value, String> {
        let fence = test_fence(7, 3)?;
        let fence_json = serde_json::to_value(&fence).map_err(|error| error.to_string())?;
        let epoch_json = serde_json::to_value(fence.authority_epoch.clone())
            .map_err(|error| error.to_string())?;
        Ok(serde_json::json!({
            "job_id": "dreamer-job-1",
            "attempt_id": "dreamer-attempt-1",
            "revision": 1,
            "scope_id": "dreamer-scope-1",
            "fence": fence_json,
            "epoch": epoch_json,
            "generation": 3,
            "nonce": "dreamer-dispatch-abcdef0123456789",
            "grant": {
                "grant_digest": test_digest(0x61),
                "authority_epoch": epoch_json,
                "fence_generation": 3,
                "fence_nonce": "dreamer-launch-fence-test01",
                "idempotency_key": "dreamer-launch-lease-test01",
                "expires_at": 4_100_000_000_000u64,
            },
        }))
    }

    fn next_temp_path() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "eliot-dreamer-kernel-port-test-{}-{count}.json",
            std::process::id(),
        ))
    }

    fn stage_material(value: &serde_json::Value) -> Result<PathBuf, String> {
        let path = next_temp_path();
        let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
        fs::write(&path, bytes).map_err(|error| error.to_string())?;
        Ok(path)
    }

    fn validated_material_value() -> Result<(serde_json::Value, EpochId), String> {
        let value = valid_envelope_value()?;
        let live = test_epoch(7)?;
        Ok((value, live))
    }

    /// Closed fake claim transport: validates each payload through the real
    /// K0 decoder (role, shape, canonical digest, fence bindings) like the K2
    /// arm, answers `LeaseExact` then `Start` from real typed responses, and
    /// refuses any second claim so a replay can never start a second worker.
    struct FakeClaimTransport {
        calls: Vec<String>,
        now_unix_ms: u64,
    }

    impl FakeClaimTransport {
        fn fresh(now_unix_ms: u64) -> Self {
            Self {
                calls: Vec::new(),
                now_unix_ms,
            }
        }

        fn submitted_request(
            payload: &serde_json::Value,
        ) -> Result<DurableJobRequest, String> {
            if payload.get("operation").and_then(serde_json::Value::as_str)
                != Some(DREAMER_JOB_WIRE_ID)
            {
                return Err("fake transport admits only the dreamer job wire".to_owned());
            }
            let request_value = payload.get("request").cloned().ok_or_else(|| {
                "fake transport payload carries no typed request".to_owned()
            })?;
            let request: DurableJobRequest =
                serde_json::from_value(request_value).map_err(|error| error.to_string())?;
            request.validate().map_err(|error| error.to_string())?;
            if request.role != JobRole::Worker {
                return Err("fake transport admits only the worker claim arm".to_owned());
            }
            Ok(request)
        }

        fn lease_json(
            request: &DurableJobRequest,
            lease: &serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({
                "request_identity": serde_json::to_value(&request.request_identity)
                    .map_err(|error| error.to_string())?,
                "job_id": "dreamer-job-1",
                "attempt_id": "dreamer-attempt-1",
                "scope": {
                    "scope_id": "dreamer-scope-1",
                    "product_id": CLAIM_PRODUCT_ID,
                    "resource_generation": 3,
                    "state_fence": serde_json::to_value(&request.request_identity.operation.state_fence)
                        .map_err(|error| error.to_string())?,
                },
                "revision": 1,
                "state": "LEASED",
                "disposition": "COMMITTED",
                "receipt_id": "dreamer-receipt-lease01",
                "lease": lease,
                "checkpoint": null,
                "result_under_verification": null,
                "outcome": null,
                "selection_coverage": [],
                "selection_frontier": null,
            }))
        }

        fn lease_projection(&self, request: &DurableJobRequest) -> Result<serde_json::Value, String> {
            let fence_json =
                serde_json::to_value(&request.request_identity.operation.state_fence)
                    .map_err(|error| error.to_string())?;
            Ok(serde_json::json!({
                "job_id": "dreamer-job-1",
                "attempt_id": "dreamer-attempt-1",
                "lease_id": {
                    "namespace": "eliot.governor.work-lease",
                    "revision": "v1",
                    "value": "dreamer-lease-test01",
                },
                "owner_artifact_id": "dreamer-attempt-1",
                "resource_generation": 3,
                "state_fence": fence_json,
                "issued_at_unix_ms": self.now_unix_ms.saturating_sub(1_000).max(1),
                "expires_at_unix_ms": self.now_unix_ms.saturating_add(60_000),
                "revision": 1,
            }))
        }

        fn answer(
            &self,
            request: &DurableJobRequest,
            kind: &str,
        ) -> Result<serde_json::Value, String> {
            if kind == "LEASE_EXACT" {
                let lease = self.lease_projection(request)?;
                return Self::lease_json(request, &lease);
            }
            if kind == "STATUS" {
                // A status observation replays the claimed lease pin with no
                // mutation disposition and no owner receipt: pure readback.
                let lease = self.lease_projection(request)?;
                let mut response = Self::lease_json(request, &lease)?;
                response["state"] = serde_json::Value::String("RUNNING".to_owned());
                response["disposition"] = serde_json::Value::Null;
                response["receipt_id"] = serde_json::Value::Null;
                return Ok(response);
            }
            let JobOperation::Start { lease, .. } = &request.operation else {
                return Err("fake transport start requires the claimed lease".to_owned());
            };
            let lease_json =
                serde_json::to_value(lease).map_err(|error| error.to_string())?;
            let mut response = Self::lease_json(request, &lease_json)?;
            response["state"] = serde_json::Value::String("RUNNING".to_owned());
            response["receipt_id"] = serde_json::Value::String("dreamer-receipt-start01".to_owned());
            Ok(response)
        }
    }

    impl ClaimTransport for FakeClaimTransport {
        fn bind_identity(
            &mut self,
            _fence: &StateFence,
            _operation_id: &str,
        ) -> Result<(), KernelPortError> {
            Ok(())
        }

        fn transact(
            &mut self,
            operation: &str,
            payload: serde_json::Value,
        ) -> Result<serde_json::Value, KernelPortError> {
            let denied = |detail: String| KernelPortError::Transport(detail);
            if operation != DREAMER_JOB_WIRE_ID {
                return Err(denied(
                    "fake transport admits only the dreamer job wire".to_owned(),
                ));
            }
            let request = Self::submitted_request(&payload).map_err(denied)?;
            let kind = request.operation.kind();
            let kind_name = kind.as_str().to_owned();
            if kind == eliot_protocol::dreamer_job::JobOperationKind::LeaseExact {
                if self.calls.iter().any(|call| call == "LEASE_EXACT") {
                    return Err(denied("fake transport refuses a second worker claim".to_owned()));
                }
            } else if kind == eliot_protocol::dreamer_job::JobOperationKind::Start {
                if !self.calls.iter().any(|call| call == "LEASE_EXACT") {
                    return Err(denied("fake transport refuses Start before LeaseExact".to_owned()));
                }
            } else if kind == eliot_protocol::dreamer_job::JobOperationKind::Status {
                if !self.calls.iter().any(|call| call == "START_JOB") {
                    return Err(denied("fake transport refuses Status before Start".to_owned()));
                }
            } else {
                return Err(denied(
                    "fake transport admits only LeaseExact then Start then Status".to_owned(),
                ));
            }
            self.calls.push(kind_name.clone());
            self.answer(&request, &kind_name).map_err(denied)
        }
    }

    fn claim_executable_for_test() -> Result<(PathBuf, PathBuf), String> {
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        let directory = executable
            .parent()
            .ok_or_else(|| "test executable has no parent".to_owned())?
            .to_path_buf();
        Ok((executable, directory))
    }

    /// A staged claim drives `LeaseExact` then `Start` exactly once: the
    /// staged file is consumed, the permit seals through the real contour
    /// constructors, both replies bind, and no second claim is possible.
    #[test]
    fn staged_claim_drives_lease_exact_then_start_once() -> Result<(), String> {
        let live = test_epoch(7)?;
        let path = stage_material(&valid_envelope_value()?)?;
        let material = read_material_from(&path, &live)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "staged material must validate".to_owned())?;
        if path.exists() {
            return Err("validated presentation must be consumed once".to_owned());
        }
        if material.job_id != "dreamer-job-1" || material.nonce != "dreamer-dispatch-abcdef0123456789" {
            return Err("validated material must carry the staged identities".to_owned());
        }
        let (executable, directory) = claim_executable_for_test()?;
        let permit = derive_permit(&material, &executable, &directory)
            .map_err(|error| error.to_string())?;
        permit.validate().map_err(|error| error.to_string())?;
        let now_unix_ms = unix_ms().map_err(|error| error.to_string())?;
        let mut transport = FakeClaimTransport::fresh(now_unix_ms);
        let started = claim_once(&material, &mut transport).map_err(|error| error.to_string())?;
        if transport.calls != ["LEASE_EXACT", "START_JOB"] {
            return Err(format!(
                "claim must run LeaseExact then Start in order, observed {:?}",
                transport.calls,
            ));
        }
        if started.state != ProtocolJobState::Running {
            return Err("claim must project the running job".to_owned());
        }
        if read_material_from(&path, &live).map_err(|error| error.to_string())?.is_some() {
            return Err("consumed presentation must not replay".to_owned());
        }
        match claim_once(&material, &mut transport) {
            Err(KernelPortError::Transport(_)) => Ok(()),
            Err(error) => Err(format!("second claim must fence at the transport, got {error}")),
            Ok(_) => Err("second claim must never start a second worker".to_owned()),
        }
    }

    /// A staged claim drives `Status` only after `Start`: the observation
    /// binds the exact claimed job/attempt/revision, carries no mutation
    /// disposition, replays with identical identity, and refuses before the
    /// claim completes.
    #[test]
    fn staged_claim_status_confirms_running_job() -> Result<(), String> {
        let live = test_epoch(7)?;
        let path = stage_material(&valid_envelope_value()?)?;
        let material = read_material_from(&path, &live)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "staged material must validate".to_owned())?;
        let now_unix_ms = unix_ms().map_err(|error| error.to_string())?;
        let mut transport = FakeClaimTransport::fresh(now_unix_ms);
        let started = claim_once(&material, &mut transport).map_err(|error| error.to_string())?;
        if started.state != ProtocolJobState::Running {
            return Err("claim must project the running job".to_owned());
        }
        let observed = status_once(&material, &mut transport).map_err(|error| error.to_string())?;
        if transport.calls != ["LEASE_EXACT", "START_JOB", "STATUS"] {
            return Err(format!(
                "claim must run LeaseExact then Start then Status in order, observed {:?}",
                transport.calls,
            ));
        }
        if observed.state != ProtocolJobState::Running {
            return Err("status must confirm the running job".to_owned());
        }
        if observed.job_id.as_str() != material.job_id
            || observed.attempt_id.as_str() != material.attempt_id
            || observed.revision != material.revision
        {
            return Err("status must bind the exact claimed job identity".to_owned());
        }
        if observed.disposition.is_some() {
            return Err("status is a pure observation and must carry no mutation disposition".to_owned());
        }
        let replayed =
            status_once(&material, &mut transport).map_err(|error| error.to_string())?;
        if replayed.revision != observed.revision || replayed.state != observed.state {
            return Err("exact status replay must return the same checkpoint identity".to_owned());
        }
        let mut unclaimed = FakeClaimTransport::fresh(now_unix_ms);
        match status_once(&material, &mut unclaimed) {
            Err(KernelPortError::Transport(_)) => Ok(()),
            Err(error) => Err(format!("status before start must fence at the transport, got {error}")),
            Ok(_) => Err("status before start must never observe an unclaimed job".to_owned()),
        }
    }

    /// Frozen worker-role capability boundary the adapter relies on: the
    /// child claim port may lease, start, and observe, but cancel origination
    /// stays Kernel-owned (`RequestCancel` is Requester/Controller-only) and
    /// semantic submit stays Requester-owned. Consumes the protocol
    /// projection read-only; pins the assumption so a protocol drift fails
    /// here instead of silently widening the child.
    #[test]
    fn worker_role_capability_freeze() -> Result<(), String> {
        use eliot_protocol::dreamer_job::{JobOperationKind, JobRole};
        for kind in [
            JobOperationKind::LeaseExact,
            JobOperationKind::Start,
            JobOperationKind::Status,
            JobOperationKind::Reconcile,
        ] {
            if !JobRole::Worker.permits(kind) {
                return Err(format!("worker role must admit {kind} on the claim port"));
            }
        }
        for kind in [JobOperationKind::Submit, JobOperationKind::RequestCancel] {
            if JobRole::Worker.permits(kind) {
                return Err(format!("worker role must never originate {kind} from the child"));
            }
        }
        Ok(())
    }

    fn corrupt_blank_job(value: &mut serde_json::Value) {
        value["job_id"] = serde_json::Value::String("   ".to_owned());
    }

    fn corrupt_widened_wire(value: &mut serde_json::Value) {
        value["foreign_key"] = serde_json::Value::String("widened".to_owned());
    }

    fn corrupt_zero_revision(value: &mut serde_json::Value) {
        value["revision"] = serde_json::Value::from(0);
    }

    fn corrupt_generation_mismatch(value: &mut serde_json::Value) {
        value["generation"] = serde_json::Value::from(9);
    }

    fn corrupt_foreign_epoch(value: &mut serde_json::Value) {
        value["epoch"]["sequence"] = serde_json::Value::from(8);
    }

    fn corrupt_bad_nonce(value: &mut serde_json::Value) {
        value["nonce"] = serde_json::Value::String("short".to_owned());
    }

    fn corrupt_bad_grant_digest(value: &mut serde_json::Value) {
        value["grant"]["grant_digest"] = serde_json::Value::String("AA".repeat(32));
    }

    fn corrupt_foreign_grant_epoch(value: &mut serde_json::Value) {
        value["grant"]["authority_epoch"]["sequence"] = serde_json::Value::from(8);
    }

    fn corrupt_grant_generation(value: &mut serde_json::Value) {
        value["grant"]["fence_generation"] = serde_json::Value::from(9);
    }

    fn corrupt_zero_expiry(value: &mut serde_json::Value) {
        value["grant"]["expires_at"] = serde_json::Value::from(0);
    }

    /// One denial row: the case name, the mutator staging the corruption,
    /// and the expected denial variant proving validation order.
    type DenialCase = (&'static str, fn(&mut serde_json::Value), &'static str);

    /// Each table entry names the corruption, the mutator staging it, and the
    /// expected denial variant, proving validation order and fail-closed
    /// claim gating.
    fn denial_cases() -> Vec<DenialCase> {
        vec![
            ("widened wire rejected by the closed shape", corrupt_widened_wire, "Malformed"),
            ("blank job refused before epoch checks", corrupt_blank_job, "InvalidMaterial"),
            ("zero revision refused", corrupt_zero_revision, "InvalidMaterial"),
            ("stale generation refused", corrupt_generation_mismatch, "StaleGeneration"),
            ("foreign epoch refused", corrupt_foreign_epoch, "StaleEpoch"),
            ("malformed nonce refused", corrupt_bad_nonce, "BadNonce"),
            ("tampered grant digest refused", corrupt_bad_grant_digest, "BadGrant"),
            ("foreign grant epoch refused", corrupt_foreign_grant_epoch, "BadGrant"),
            ("grant generation mismatch refused", corrupt_grant_generation, "BadGrant"),
            ("zero grant expiry refused", corrupt_zero_expiry, "BadGrant"),
        ]
    }

    fn variant_name(error: &KernelPortError) -> &'static str {
        match error {
            KernelPortError::Io(_) => "Io",
            KernelPortError::TooLarge { .. } => "TooLarge",
            KernelPortError::Malformed(_) => "Malformed",
            KernelPortError::InvalidMaterial(_) => "InvalidMaterial",
            KernelPortError::StaleEpoch { .. } => "StaleEpoch",
            KernelPortError::StaleGeneration { .. } => "StaleGeneration",
            KernelPortError::BadNonce => "BadNonce",
            KernelPortError::BadGrant(_) => "BadGrant",
            KernelPortError::Transport(_) => "Transport",
            KernelPortError::Contract(_) => "Contract",
        }
    }

    /// Tampered, foreign, and replayed presentations refuse fail-closed with
    /// no claim transact, so no second worker can start from them. The claim
    /// entry takes only validated material, so a refused presentation can
    /// never reach the transport; the loop proves every refusal happens at
    /// validation with zero transport calls available on that path.
    #[test]
    fn tampered_foreign_replayed_presentations_refuse_without_claim() -> Result<(), String> {
        let live = test_epoch(7)?;
        for (name, corrupt, expected) in denial_cases() {
            let mut value = valid_envelope_value()?;
            corrupt(&mut value);
            let path = stage_material(&value)?;
            let outcome = read_material_from(&path, &live);
            let _ = fs::remove_file(&path);
            let Err(error) = outcome else {
                return Err(format!("{name} must refuse"));
            };
            if variant_name(&error) != expected {
                return Err(format!(
                    "{name} must deny with {expected}, got {} ({error})",
                    variant_name(&error),
                ));
            }
        }
        // The foreign-epoch bytes are well-formed: rebased onto their own
        // presented epoch they validate, proving the denial above is about
        // live-authority binding rather than shape.
        let (mut foreign_value, _) = validated_material_value()?;
        foreign_value["epoch"]["sequence"] = serde_json::Value::from(8);
        foreign_value["grant"]["authority_epoch"]["sequence"] = serde_json::Value::from(8);
        let foreign_path = stage_material(&foreign_value)?;
        let presented = test_epoch(8)?;
        let foreign_outcome = read_material_from(&foreign_path, &presented);
        let _ = fs::remove_file(&foreign_path);
        match foreign_outcome {
            Ok(Some(_)) => {},
            Ok(None) => return Err("foreign-epoch bytes must validate under the presented epoch".to_owned()),
            Err(error) => return Err(format!("foreign-epoch bytes must be well-formed, got {error}")),
        }
        let bound = usize::try_from(DREAMER_MATERIAL_LIMIT_BYTES)
            .map_err(|_| "material bound exceeds the test address space".to_owned())?;
        let oversize = vec![0x7bu8; bound + 1];
        let big_path = next_temp_path();
        fs::write(&big_path, oversize).map_err(|error| error.to_string())?;
        let big_outcome = read_material_from(&big_path, &live);
        let _ = fs::remove_file(&big_path);
        match big_outcome {
            Err(KernelPortError::TooLarge { .. }) => Ok(()),
            Err(error) => Err(format!("oversize presentation must deny TooLarge, got {error}")),
            Ok(_) => Err("oversize presentation must refuse".to_owned()),
        }
    }
}
