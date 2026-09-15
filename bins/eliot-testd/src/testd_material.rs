#![forbid(unsafe_code)]

//! Bins-local dispatch-contour material reader for the one-shot testd child.
//!
//! This module reads the session-bound admitted-attempt file the Kernel
//! dispatch contour writes next to this executable before spawn
//! (`eliot-testd.admitted-attempt.json`; canonical owner:
//! `DispatchedWorkerKind::material_file_name` in
//! `bins/eliot-kernel/src/dispatch_launch.rs`). It owns no wire contract,
//! mints no authority, and changes no shared type: every struct below is a
//! bins-local mirror of the exact kernel field shapes, validated fail-closed
//! before any drive.
//!
//! Material shape (all keys required, `deny_unknown_fields` on parse):
//! `request` ([`TestdMaterialRequest`]), `envelope`
//! ([`TestdMaterialEnvelope`], re-parsed kernel-side from
//! `request.closed_request_json`), `admission`
//! ([`TestdMaterialAdmission`]), `epoch` (live [`EpochId`]), `generation`
//! (live `u64`), `nonce` (session nonce), `grant` ([`DispatchGrant`]).
//!
//! Locator (untrusted bytes, never authority): the path is derived from
//! [`std::env::current_exe`], which reads the OS loader image path, not the
//! environment block. No value is taken from argv, stdin, or environment
//! variables, and no ownership is inferred from the path itself: the file is
//! untrusted presenter bytes until every identity below is re-proved.
//!
//! Validation (all before any drive, all fail-closed):
//!
//! - bounded input (256 KiB, mirroring the kernel write bound and the doctor
//!   reader `DISPATCHED_MATERIAL_LIMIT_BYTES`);
//! - session-nonce shape (opaque, 16..=256, alphanumeric plus `-_.`);
//! - wire identity plus canonical digests for the request and the admission,
//!   recomputed over the exact kernel canonical shapes;
//! - closed-request byte-identity: the parsed `closed_request_json` must
//!   equal the carried `envelope`, and the envelope job must equal the
//!   request job;
//! - admission binding: the admission echoes the request job and request
//!   digest, and carries a non-zero admission time;
//! - session binding: the carried epoch must equal the grant epoch as an
//!   exact tuple, the carried generation must be non-zero and equal both the
//!   grant fence generation and the envelope fence generation, and the
//!   envelope fence lineage must check against the same epoch (foreign/stale
//!   lineage is denied here, before any submit);
//! - grant proof: the grant digest is recomputed over the exact kernel
//!   binding (`request_digest | epoch_json | fence_generation | fence_nonce |
//!   idempotency_key | expires_at`), and the fence plus lease rebuild
//!   through the exact broker constructors (`FencingToken::new`,
//!   `ActionLeaseRef::new`, `Generation::new`);
//! - grant freshness: an expired grant (`expires_at` not after now) is
//!   refused, because no permit issuance could bind it.
//!
//! A validated file is consumed once (best-effort removal; removal failure
//! never fails the shot). A missing file is not an error: it means the
//! dispatch contour delivered nothing to this invocation, and the caller
//! keeps the exact `DenyNoPresentedAttempt` fail-closed path. A present but
//! invalid file is a typed denial, never a drive; the file is left in place
//! for forensics.
//!
//! What this module deliberately does NOT deliver:
//!
//! - The concrete [`ProcessRequest`][eliot_process::ProcessRequest]: it is
//!   `Serialize`-only by design (neither `Clone` nor `Deserialize`;
//!   `crates/kernel/eliot-process/src/lib.rs`), so the kernel never
//!   serializes it into the file and this child never deserializes it. The
//!   [`ProcessIntent`][eliot_process::ProcessIntent] for the single start
//!   is derived in the crate root from the admitted profile binding (closed
//!   registry in `eliot-testd-core` plus the installed tool file hash),
//!   never from delivered executable authority.
//! - The broker-mirror dispatch authority: it lives in the crate root
//!   (`TestdDispatchAuthority`), built over a real
//!   `eliot_platform::ClockObservation` exactly like the broker/doctor, and
//!   consumes the validated grant below. Any `validate_and_consume`
//!   without that context would forge validation.
//!
//! With those bindings landed, a validated file drives the bounded admitted
//! probe: the admission already binds the closed profile record, the grant
//! already rebuilds through the broker constructors, and the Drive derives
//! the intent from the binding plus the installed tool bytes.

use std::fs;
use std::path::{Path, PathBuf};

use eliot_contracts::{EpochId, canonical_json_bytes, sha256_hex};
use eliot_process::{ActionLeaseRef, FencingToken, Generation};
use serde::{Deserialize, Serialize};

/// Bins-local dispatch file name, read from the executable directory only.
/// See the module documentation: locator, never authority. This is the exact
/// name the kernel contour writes
/// (`DispatchedWorkerKind::Testd.material_file_name`).
pub const TESTD_MATERIAL_FILE_NAME: &str = "eliot-testd.admitted-attempt.json";

/// Upper bound for the dispatch file, mirroring the kernel write bound and
/// the doctor reader bound.
pub const TESTD_MATERIAL_LIMIT_BYTES: u64 = 256 * 1024;

/// Kernel testd-admission wire identity mirrored here (canonical owner:
/// `TESTD_ADMISSION_WIRE_ID` in
/// `crates/kernel/eliot-kernel-service/src/testd_front_door.rs`). This crate
/// has no dependency on that vocabulary crate, so the value is mirrored, not
/// imported; the wire pair is re-proved on every read.
pub const TESTD_MATERIAL_WIRE_ID: &str = "eliot.kernel.testd-admission";
/// Kernel testd-admission wire revision mirrored here (canonical owner:
/// `TESTD_ADMISSION_WIRE_VERSION`).
pub const TESTD_MATERIAL_WIRE_VERSION: u16 = 1;
/// Closed-request bound mirrored here (canonical owner:
/// `TESTD_MAX_ENVELOPE_BYTES`).
pub const TESTD_MATERIAL_MAX_CLOSED_BYTES: usize = 65_536;

/// Session-nonce shape bounds, mirroring the doctor reader: opaque, bounded,
/// never invented here.
pub const TESTD_NONCE_MIN_LEN: usize = 16;
/// Session-nonce shape bounds, mirroring the doctor reader.
pub const TESTD_NONCE_MAX_LEN: usize = 256;

/// Bins-local mirror of the kernel `DispatchGrant` (exact field names;
/// canonical owner: `DispatchGrant` in
/// `bins/eliot-kernel/src/dispatch_launch.rs`). The child rebuilds the fence
/// and lease from these fields through the exact broker constructors; the
/// digest is recomputed over the exact kernel binding.
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

/// Bins-local mirror of the kernel `TestdAdmissionAttemptRequest` (exact
/// field names; canonical owner: `testd_front_door.rs`). The closed envelope
/// travels opaquely inside `closed_request_json`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdMaterialRequest {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Testd job identity seed bound to the envelope job identity.
    pub job_id: String,
    /// Execution attempt sequence distinguishing several attempts of one job.
    pub attempt_seq: u32,
    /// Canonical JSON bytes of the presented closed envelope.
    pub closed_request_json: String,
    /// Opaque digest of the target resource envelope; compared byte-wise,
    /// never interpreted.
    pub target_resource_digest: String,
    /// Canonical digest over this request envelope.
    pub request_digest: String,
}

/// Bins-local mirror of the kernel `TestdAdmissionEnvelope` (exact field
/// names; canonical owner: `testd_front_door.rs`). Note the genuine absence:
/// this envelope carries no executable, argv, working-directory,
/// environment, or limit binding, so no [`ProcessIntent`][eliot_process::ProcessIntent]
/// can be derived from admitted material without inventing authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdMaterialEnvelope {
    /// Testd job identity this admission binds.
    pub job_id: String,
    /// Single admitted operation, when the envelope carries execution work.
    pub operation_id: Option<String>,
    /// Whether this envelope cancels the job instead of executing it.
    pub cancellation: bool,
    /// Consumed fence; validated against the live admission epoch and never
    /// minted here.
    pub fence: FencingToken,
}

/// Bins-local mirror of the kernel `TestdAdmission` receipt (exact field
/// names; canonical owner: `testd_front_door.rs`). Its `operation_id` is the
/// bounded evidence handle the future drive maps to
/// `PresentedAdmission.evidence_ref`, and `cancelled` maps to
/// `PresentedAdmission.cancelled`. The admitted profile record (`profile`
/// plus `profile_binding_digest`) rides here: the closed envelope stays
/// `{job_id, operation_id, cancellation, fence}`, and the executable
/// binding (relative program, fixed argv, environment allowlist,
/// timeout/output caps) is bound through this record's digest instead.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdMaterialAdmission {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Admitted testd job identity.
    pub job_id: String,
    /// Canonical digest of the exact admitted request envelope.
    pub request_digest: String,
    /// Admitted operation. Cancelled admissions carry the presented
    /// operation but bind no process identity.
    pub operation_id: String,
    /// Admitted testd profile. Exactly one profile is admitted in this
    /// slice; anything else is refused.
    pub profile: String,
    /// Canonical definition digest over the static admitted profile
    /// fields. The per-host installed artifact digest binds later at Drive
    /// time through the intent's `executable_sha256`.
    pub profile_binding_digest: String,
    /// Whether the job was admitted cancelled; cancelled admissions never
    /// stage execution work.
    pub cancelled: bool,
    /// Admission time in Unix nanoseconds.
    pub admitted_at_unix_nanos: u64,
    /// Canonical digest over this admission envelope.
    pub admission_digest: String,
}

/// Bins-local dispatch file envelope (NOT a wire contract change): the exact
/// seven keys the kernel contour writes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestdMaterialFile {
    request: TestdMaterialRequest,
    envelope: TestdMaterialEnvelope,
    admission: TestdMaterialAdmission,
    epoch: EpochId,
    generation: u64,
    nonce: String,
    grant: DispatchGrant,
}

/// Session-bound attempt material validated against itself.
///
/// Internal consistency only: every cross-field identity in the file is
/// re-proved (digests, wire pair, byte-identity, epoch/generation/nonce
/// binding, grant proof, freshness, admitted profile record). The live-bootstrap
/// agreement (presented epoch against the authenticated Kernel epoch) is
/// owned by the future drive seam, which carries the live epoch; this value
/// exposes `epoch` and `generation` for exactly that proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedTestdMaterial {
    /// Admitted testd job identity.
    pub job_id: String,
    /// Admitted operation: the bounded evidence handle for the future drive.
    pub operation_id: String,
    /// Admitted testd profile (exactly one is admitted).
    pub profile: String,
    /// Canonical definition digest over the static admitted profile fields.
    pub profile_binding_digest: String,
    /// Canonical digest of the exact admitted request envelope.
    pub request_digest: String,
    /// Canonical digest of the admission receipt.
    pub admission_digest: String,
    /// Live authority epoch carried by the file (future seam proves it
    /// against the bootstrap epoch).
    pub epoch: EpochId,
    /// Live activation generation carried by the file.
    pub generation: u64,
    /// Well-formed session nonce.
    pub nonce: String,
    /// Re-proved grant digest binding the grant fields plus the admission
    /// identity digest.
    pub grant_digest: String,
    /// Validated Kernel-issued launch grant; the dispatch authority
    /// consumes exactly this value at issuance time.
    pub grant: DispatchGrant,
    /// Rebuilt fence from the validated grant (broker constructors).
    pub fence: FencingToken,
    /// Whether the job was admitted cancelled; cancelled admissions never
    /// execute.
    pub cancelled: bool,
}

/// Typed failure for the dispatch-file read. Every variant is fail-closed:
/// the one-shot entry maps each to exit 78 without effect.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TestdMaterialError {
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
    /// canonical digest, byte-identity, or binding check).
    #[error("dispatch material violates the closed contract: {0}")]
    Contract(String),
    /// The presented epoch (or the envelope fence lineage, or the grant
    /// epoch) disagrees within the material: foreign or stale authority.
    #[error("dispatch material epoch is foreign or stale: presented {presented}, live {live}")]
    StaleEpoch {
        /// Presented epoch value.
        presented: String,
        /// Carried live epoch value it must equal.
        live: String,
    },
    /// The presented generation is zero or disagrees with the grant fence
    /// generation or the envelope fence generation.
    #[error(
        "dispatch material generation is stale or unbound: presented {presented}, fence {fence}"
    )]
    StaleGeneration {
        /// Presented generation value.
        presented: u64,
        /// Fence generation value it must equal.
        fence: u64,
    },
    /// The session nonce is missing or malformed.
    #[error(
        "dispatch material nonce is missing or malformed: a well-formed session nonce is required"
    )]
    BadNonce,
}

/// Derives the bins-local dispatch file path: the executable directory plus
/// [`TESTD_MATERIAL_FILE_NAME`].
///
/// Locator only, never authority: [`std::env::current_exe`] reads the OS
/// loader image path, not the environment block, and the file found there
/// is untrusted presenter bytes until validated. Returns `None` when the
/// image path is unavailable, which the caller treats as absent material.
#[must_use]
pub fn testd_material_path() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let directory = executable.parent()?;
    Some(directory.join(TESTD_MATERIAL_FILE_NAME))
}

/// Reads and validates the session-bound attempt material for this
/// invocation.
///
/// Returns `Ok(None)` when no dispatch file was delivered (the caller keeps
/// the exact `DenyNoPresentedAttempt` path), `Ok(Some(_))` when the file
/// validated and was consumed once, and `Err(_)` typed fail-closed when a
/// file is present but invalid. Never reads argv, stdin, or environment.
/// Validation is internal-consistency only (see
/// [`ValidatedTestdMaterial`]); the live-epoch agreement is owned by the
/// future drive seam.
pub fn read_testd_material() -> Result<Option<ValidatedTestdMaterial>, TestdMaterialError> {
    let Some(path) = testd_material_path() else {
        return Ok(None);
    };
    read_testd_material_from(&path)
}

/// Reads and validates session-bound attempt material from one explicit
/// path, for the production locator plus bounded tests.
///
/// The path parameter exists so tests can stage material without touching
/// the executable directory; production always passes
/// [`testd_material_path`]. Semantics match [`read_testd_material`].
pub fn read_testd_material_from(
    path: &Path,
) -> Result<Option<ValidatedTestdMaterial>, TestdMaterialError> {
    if let Some(actual) = bounded_file_len(path)? {
        return Err(TestdMaterialError::TooLarge {
            maximum: TESTD_MATERIAL_LIMIT_BYTES,
            actual,
        });
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(TestdMaterialError::Io(error.to_string())),
    };
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > TESTD_MATERIAL_LIMIT_BYTES {
        return Err(TestdMaterialError::TooLarge {
            maximum: TESTD_MATERIAL_LIMIT_BYTES,
            actual,
        });
    }
    let file: TestdMaterialFile = serde_json::from_slice(&bytes)
        .map_err(|error| TestdMaterialError::Malformed(truncate_detail(&error.to_string())))?;
    let validated = validate_material(file, now_ms())?;
    // Consume-once: a validated presentation must not linger for a later
    // invocation to replay. Removal is best-effort; the kernel launch reaps
    // the file regardless, and removal failure never fails the shot. An
    // invalid file is deliberately left in place for forensics.
    let _ = fs::remove_file(path);
    Ok(Some(validated))
}

/// Pre-checks the file length so an unbounded file is refused before it is
/// read. Returns `Ok(None)` when the length is within bounds or unknown
/// (the post-read check still applies); returns the observed length when it
/// already exceeds the bound. A missing file surfaces as `Ok(None)` here so
/// the read below can report absence exactly once.
fn bounded_file_len(path: &Path) -> Result<Option<u64>, TestdMaterialError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(TestdMaterialError::Io(error.to_string())),
    };
    let actual = metadata.len();
    if actual > TESTD_MATERIAL_LIMIT_BYTES {
        Ok(Some(actual))
    } else {
        Ok(None)
    }
}

/// Validates one parsed material file. Every check is fail-closed; the order
/// is cheapest-first and performs no transport, no execution, and no
/// authority minting.
fn validate_material(
    file: TestdMaterialFile,
    now_unix_ms: u64,
) -> Result<ValidatedTestdMaterial, TestdMaterialError> {
    validate_nonce(&file.nonce)?;
    validate_request(&file.request)?;
    // Closed-request byte-identity: the parsed closed request must equal
    // the carried envelope, and bind the same job.
    let parsed: TestdMaterialEnvelope = serde_json::from_str(&file.request.closed_request_json)
        .map_err(|error| TestdMaterialError::Contract(truncate_detail(&error.to_string())))?;
    if parsed != file.envelope {
        return Err(TestdMaterialError::Contract(
            "dispatch envelope closed request does not equal the presented envelope".to_owned(),
        ));
    }
    if file.envelope.job_id != file.request.job_id {
        return Err(TestdMaterialError::Contract(
            "dispatch envelope job disagrees with the request job".to_owned(),
        ));
    }
    validate_admission(&file.admission, &file.request)?;
    validate_session_binding(&file)?;
    let (fence, _lease) = validate_grant(&file.grant, &file.admission, now_unix_ms)?;
    Ok(ValidatedTestdMaterial {
        job_id: file.request.job_id,
        operation_id: file.admission.operation_id.clone(),
        profile: file.admission.profile.clone(),
        profile_binding_digest: file.admission.profile_binding_digest.clone(),
        request_digest: file.admission.request_digest,
        admission_digest: file.admission.admission_digest,
        epoch: file.epoch,
        generation: file.generation,
        nonce: file.nonce,
        grant_digest: file.grant.grant_digest.clone(),
        grant: file.grant,
        fence,
        cancelled: file.admission.cancelled,
    })
}

/// Validates the request envelope: wire pair, bounded shape, and canonical
/// digest over the exact kernel canonical fields.
fn validate_request(request: &TestdMaterialRequest) -> Result<(), TestdMaterialError> {
    if request.wire_id != TESTD_MATERIAL_WIRE_ID
        || request.wire_version != TESTD_MATERIAL_WIRE_VERSION
    {
        return Err(TestdMaterialError::Contract(
            "unsupported testd dispatch wire".to_owned(),
        ));
    }
    validate_wire_text(&request.job_id, "testd_material.job_id")?;
    if request.closed_request_json.is_empty()
        || request.closed_request_json.len() > TESTD_MATERIAL_MAX_CLOSED_BYTES
    {
        return Err(TestdMaterialError::Contract(
            "testd_material.closed_request_json is missing or exceeds its bound".to_owned(),
        ));
    }
    validate_wire_digest(
        &request.target_resource_digest,
        "testd_material.target_resource_digest",
    )?;
    validate_wire_digest(&request.request_digest, "testd_material.request_digest")?;
    if request.canonical_request_digest()? != request.request_digest {
        return Err(TestdMaterialError::Contract(
            "testd_material.request_digest mismatch".to_owned(),
        ));
    }
    Ok(())
}

/// Validates the admission receipt: wire pair, job/digest echo of the
/// request, admitted profile record, non-zero admission time, and canonical
/// digest over the exact kernel canonical fields.
fn validate_admission(
    admission: &TestdMaterialAdmission,
    request: &TestdMaterialRequest,
) -> Result<(), TestdMaterialError> {
    if admission.wire_id != TESTD_MATERIAL_WIRE_ID
        || admission.wire_version != TESTD_MATERIAL_WIRE_VERSION
    {
        return Err(TestdMaterialError::Contract(
            "unsupported testd dispatch wire".to_owned(),
        ));
    }
    validate_wire_text(&admission.job_id, "testd_material.job_id")?;
    validate_wire_text(&admission.operation_id, "testd_material.operation_id")?;
    // Admitted profile record: exactly one profile is admitted, and its
    // definition digest must equal the closed registry digest. A
    // substituted profile or widened binding fails here, before any drive.
    if admission.profile != eliot_testd_core::TESTD_ADMITTED_PROFILE {
        return Err(TestdMaterialError::Contract(
            "testd admits only the closed cargo-test tool-probe profile".to_owned(),
        ));
    }
    validate_wire_digest(
        &admission.profile_binding_digest,
        "testd_material.profile_binding_digest",
    )?;
    let expected_binding = eliot_testd_core::testd_definition_digest()
        .map_err(|error| TestdMaterialError::Contract(truncate_detail(&error.to_string())))?;
    if admission.profile_binding_digest != expected_binding {
        return Err(TestdMaterialError::Contract(
            "testd_material.profile_binding_digest mismatch".to_owned(),
        ));
    }
    if admission.job_id != request.job_id {
        return Err(TestdMaterialError::Contract(
            "testd admission job disagrees with the request job".to_owned(),
        ));
    }
    if admission.request_digest != request.request_digest {
        return Err(TestdMaterialError::Contract(
            "testd admission request digest disagrees with the request envelope".to_owned(),
        ));
    }
    validate_wire_digest(&admission.request_digest, "testd_material.request_digest")?;
    validate_wire_digest(
        &admission.admission_digest,
        "testd_material.admission_digest",
    )?;
    if admission.admitted_at_unix_nanos == 0 {
        return Err(TestdMaterialError::Contract(
            "testd admission time must be non-zero".to_owned(),
        ));
    }
    if admission.compute_digest()? != admission.admission_digest {
        return Err(TestdMaterialError::Contract(
            "testd_material.admission_digest mismatch".to_owned(),
        ));
    }
    Ok(())
}

/// Validates the session binding inside the material: the carried epoch must
/// equal the grant epoch as an exact tuple, the carried generation must be
/// non-zero and equal both the grant fence generation and the envelope fence
/// generation, and the envelope fence lineage must check against the same
/// epoch. Foreign or stale authority is denied here, before any submit.
fn validate_session_binding(file: &TestdMaterialFile) -> Result<(), TestdMaterialError> {
    if file.epoch != file.grant.authority_epoch {
        return Err(TestdMaterialError::StaleEpoch {
            presented: format!("{:?}", file.grant.authority_epoch),
            live: format!("{:?}", file.epoch),
        });
    }
    if !file
        .envelope
        .fence
        .authority_epoch()
        .is_same_authority(&file.epoch)
    {
        return Err(TestdMaterialError::StaleEpoch {
            presented: format!("{:?}", file.envelope.fence.authority_epoch()),
            live: format!("{:?}", file.epoch),
        });
    }
    if file.generation == 0 || file.generation != file.grant.fence_generation {
        return Err(TestdMaterialError::StaleGeneration {
            presented: file.generation,
            fence: file.grant.fence_generation,
        });
    }
    if file.envelope.fence.generation().get() != file.generation {
        return Err(TestdMaterialError::StaleGeneration {
            presented: file.generation,
            fence: file.envelope.fence.generation().get(),
        });
    }
    Ok(())
}

/// Validates the grant fail-closed: digest recomputed over the exact kernel
/// binding, fence plus lease rebuilt through the exact broker constructors,
/// and freshness (an expired grant binds no permit issuance).
///
/// Returns the rebuilt fence and lease the future authority slice consumes;
/// the caller re-proves them at issuance time.
fn validate_grant(
    grant: &DispatchGrant,
    admission: &TestdMaterialAdmission,
    now_unix_ms: u64,
) -> Result<(FencingToken, ActionLeaseRef), TestdMaterialError> {
    validate_wire_digest(&grant.grant_digest, "testd_material.grant_digest")?;
    if grant.fence_generation == 0 {
        return Err(TestdMaterialError::Contract(
            "testd grant fence generation must be non-zero".to_owned(),
        ));
    }
    if grant.expires_at == 0 {
        return Err(TestdMaterialError::Contract(
            "testd grant expiry must be non-zero".to_owned(),
        ));
    }
    let generation = Generation::new(grant.fence_generation)
        .map_err(|error| TestdMaterialError::Contract(truncate_detail(&error.to_string())))?;
    let fence = FencingToken::new(
        grant.authority_epoch.clone(),
        generation,
        grant.fence_nonce.clone(),
    )
    .map_err(|error| TestdMaterialError::Contract(truncate_detail(&error.to_string())))?;
    let lease = ActionLeaseRef::new(grant.idempotency_key.clone())
        .map_err(|error| TestdMaterialError::Contract(truncate_detail(&error.to_string())))?;
    if recomputed_grant_digest(grant, &admission.request_digest)? != grant.grant_digest {
        return Err(TestdMaterialError::Contract(
            "testd_material.grant_digest mismatch".to_owned(),
        ));
    }
    if grant.expires_at <= now_unix_ms {
        return Err(TestdMaterialError::Contract(
            "testd grant is expired and binds no permit issuance".to_owned(),
        ));
    }
    Ok((fence, lease))
}

/// Recomputes the grant digest over the exact kernel binding
/// (`identity_digest | epoch_json | fence_generation | fence_nonce |
/// idempotency_key | expires_at`, canonical owner: `dispatch_grant_for` in
/// `bins/eliot-kernel/src/dispatch_launch.rs`). The epoch serializes via the
/// same `serde_json::to_string` over the same `EpochId` shape, so equal
/// logical grants hash identically on both sides of the boundary.
fn recomputed_grant_digest(
    grant: &DispatchGrant,
    identity_digest: &str,
) -> Result<String, TestdMaterialError> {
    let epoch_json = serde_json::to_string(&grant.authority_epoch).map_err(|_| {
        TestdMaterialError::Contract(
            "testd_material.grant authority epoch cannot canonicalize".to_owned(),
        )
    })?;
    let mut material = String::with_capacity(256);
    material.push_str(identity_digest);
    material.push('|');
    material.push_str(&epoch_json);
    material.push('|');
    material.push_str(&grant.fence_generation.to_string());
    material.push('|');
    material.push_str(&grant.fence_nonce);
    material.push('|');
    material.push_str(&grant.idempotency_key);
    material.push('|');
    material.push_str(&grant.expires_at.to_string());
    Ok(sha256_hex(material.as_bytes()))
}

impl TestdMaterialRequest {
    /// Computes the canonical digest over the presenting envelope bytes
    /// (exact kernel canonical fields).
    fn canonical_request_digest(&self) -> Result<String, TestdMaterialError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            job_id: &'a str,
            attempt_seq: u32,
            closed_request_json: &'a str,
            target_resource_digest: &'a str,
        }
        let canonical = Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            job_id: &self.job_id,
            attempt_seq: self.attempt_seq,
            closed_request_json: &self.closed_request_json,
            target_resource_digest: &self.target_resource_digest,
        };
        canonical_json_bytes(&canonical)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| {
                TestdMaterialError::Contract(
                    "testd_material.request_digest cannot canonicalize request".to_owned(),
                )
            })
    }
}

impl TestdMaterialAdmission {
    /// Computes the canonical admission digest (exact kernel canonical
    /// fields, including the admitted profile record).
    fn compute_digest(&self) -> Result<String, TestdMaterialError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            job_id: &'a str,
            request_digest: &'a str,
            operation_id: &'a str,
            profile: &'a str,
            profile_binding_digest: &'a str,
            cancelled: bool,
            admitted_at_unix_nanos: u64,
        }
        let canonical = Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            job_id: &self.job_id,
            request_digest: &self.request_digest,
            operation_id: &self.operation_id,
            profile: &self.profile,
            profile_binding_digest: &self.profile_binding_digest,
            cancelled: self.cancelled,
            admitted_at_unix_nanos: self.admitted_at_unix_nanos,
        };
        canonical_json_bytes(&canonical)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| {
                TestdMaterialError::Contract(
                    "testd_material.admission_digest cannot canonicalize admission".to_owned(),
                )
            })
    }
}

/// Requires a well-formed opaque session nonce: bounded length over an
/// explicit hyphen/underscore/dot alphanumeric alphabet. The value is never
/// interpreted, only carried for the kernel-side session proof.
fn validate_nonce(nonce: &str) -> Result<(), TestdMaterialError> {
    if !(TESTD_NONCE_MIN_LEN..=TESTD_NONCE_MAX_LEN).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(TestdMaterialError::BadNonce);
    }
    Ok(())
}

/// Validates bounded wire text without carrying platform or secret material.
fn validate_wire_text(value: &str, field: &'static str) -> Result<(), TestdMaterialError> {
    if value.trim().is_empty() {
        return Err(TestdMaterialError::Contract(format!(
            "{field} must be non-blank"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(TestdMaterialError::Contract(format!(
            "{field} must not contain control characters"
        )));
    }
    if value.len() > 1024 {
        return Err(TestdMaterialError::Contract(format!(
            "{field} must not exceed 1024 UTF-8 bytes"
        )));
    }
    Ok(())
}

/// Returns true when the value is a lowercase SHA-256 digest.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_wire_digest(value: &str, field: &'static str) -> Result<(), TestdMaterialError> {
    if !is_lowercase_sha256(value) {
        return Err(TestdMaterialError::Contract(format!(
            "{field} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

/// Bounds third-party error detail carried into deny lines.
fn truncate_detail(detail: &str) -> String {
    const LIMIT: usize = 256;
    detail.chars().take(LIMIT).collect()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
