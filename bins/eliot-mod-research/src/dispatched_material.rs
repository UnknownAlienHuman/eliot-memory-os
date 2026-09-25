//! Bins-local admitted-material reader for the one-shot research provider.
//!
//! The one-shot binary needs one Kernel-issued research dispatch (artifact,
//! generation, epoch, fence, privacy, budget, deadline, inquiry/denominator
//! digests) plus the matching exchange request. Neither may come from argv,
//! stdin, an environment variable, or a caller-supplied path (A1). They are
//! therefore read from a single bounded dispatch file written by the dispatch
//! contour next to this executable, exactly like
//! `bins/eliot-doctor/src/dispatched_material.rs`.
//!
//! Locator (untrusted bytes, never authority): the path is derived from
//! [`std::env::current_exe`], which reads the OS loader image path, not the
//! environment block. No value is taken from argv, stdin, or environment
//! variables, and no ownership is inferred from the path itself
//! (`bins/AGENTS.md`: the file is untrusted presenter bytes until every
//! identity below is re-proved).
//!
//! Validation (all before any dispatch, all fail-closed):
//!
//! - the envelope's own canonical digest;
//! - the Kernel-owned [`ResearchProviderDispatch::validate`] shape;
//! - the exchange request's own contract validation;
//! - the presented Authority Epoch must be the same authority as the live
//!   Kernel epoch observed on a fresh authenticated handshake;
//! - the request and dispatch must agree on exchange identity, idempotency
//!   key, protocol revision, and required result schema;
//! - the presented request digest must equal the digest of the canonical
//!   request bytes.
//!
//! A validated file is consumed once (best-effort removal; a removal failure
//! never fails the shot). A missing file is not a fabricated empty result: it
//! means the dispatch contour delivered nothing, and the caller keeps the exact
//! fail-closed `KERNEL_ADMISSION_REQUIRED` path. A present but invalid file is
//! a typed denial, never a drive.

use std::fs;
use std::path::{Path, PathBuf};

use eliot_contracts::EpochId;
use eliot_kernel_service::ResearchProviderDispatch;
use eliot_research_exchange_api::ResearchQueryRequest;
use serde::{Deserialize, Serialize};

use crate::evidence::sha256_hex;

/// Bins-local admitted-material file name, read from the executable directory
/// only. See the module documentation: locator, never authority.
pub const DISPATCHED_MATERIAL_FILE_NAME: &str = "eliot-mod-research.admitted-operation.json";

/// Upper bound for the admitted-material file. The dispatch wire is bounded by
/// `RESEARCH_PROVIDER_MAX_TEXT`; this adds ample headroom for the request body
/// without accepting unbounded input.
pub const DISPATCHED_MATERIAL_LIMIT_BYTES: u64 = 256 * 1024;

/// Typed fail-closed admission-material failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdmittedMaterialError {
    /// The presented file exceeds the bounded read limit.
    #[error("admitted material exceeds the bounded read limit: {actual} bytes")]
    TooLarge {
        /// Observed byte count.
        actual: u64,
    },
    /// The presented bytes are not the admitted envelope shape.
    #[error("admitted material is not the admitted envelope: {0}")]
    Malformed(String),
    /// The presented Authority Epoch is not the live Kernel authority.
    #[error("admitted material carries a stale authority epoch")]
    StaleEpoch,
    /// The exchange request disagrees with the admitted dispatch binding.
    #[error("admitted material request disagrees with the dispatch: {0}")]
    BindingMismatch(String),
    /// The presented request digest does not match the canonical request bytes.
    #[error("admitted material request digest mismatch")]
    RequestDigestMismatch,
    /// The presented file could not be read.
    #[error("admitted material read failed: {0}")]
    Io(String),
}

/// Bins-local admitted-material envelope (NOT a wire contract change).
///
/// It carries exactly the Kernel-owned dispatch type plus the exchange request
/// it binds, and its own canonical digest. Every field is untrusted presenter
/// bytes until [`read_admitted_material`] re-proves it against the live Kernel
/// authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmittedOperationEnvelope {
    /// The Kernel-owned research dispatch.
    dispatch: ResearchProviderDispatch,
    /// The exchange request bound to that dispatch.
    request: ResearchQueryRequest,
    /// SHA-256 of the canonical exchange request bytes.
    request_sha256: String,
    /// Canonical digest over this envelope, excluding this field.
    envelope_sha256: String,
}

/// Validated admitted material for exactly one bounded operation.
#[derive(Clone, Debug)]
pub struct AdmittedOperation {
    /// The Kernel-issued dispatch, re-proved against the live authority.
    pub dispatch: ResearchProviderDispatch,
    /// The exchange request bound to that dispatch.
    pub request: ResearchQueryRequest,
}

/// Returns the admitted-material path next to this executable, or `None` when
/// the loader image path is unavailable.
#[must_use]
pub fn admitted_material_path() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let directory = executable.parent()?;
    Some(directory.join(DISPATCHED_MATERIAL_FILE_NAME))
}

/// Reads and validates the admitted material for this invocation against the
/// live Kernel authority epoch.
///
/// Returns `Ok(None)` when no dispatch file was delivered, `Ok(Some(_))` when
/// the file validated and was consumed once, and a typed error when a file is
/// present but invalid. Never reads argv, stdin, or environment.
pub fn read_admitted_material(
    live_epoch: &EpochId,
) -> Result<Option<AdmittedOperation>, AdmittedMaterialError> {
    let Some(path) = admitted_material_path() else {
        return Ok(None);
    };
    read_admitted_material_from(&path, live_epoch)
}

/// Reads and validates admitted material from one explicit path.
///
/// The path parameter exists so a caller can stage material deterministically;
/// production always passes [`admitted_material_path`]. Semantics match
/// [`read_admitted_material`].
pub fn read_admitted_material_from(
    path: &Path,
    live_epoch: &EpochId,
) -> Result<Option<AdmittedOperation>, AdmittedMaterialError> {
    if let Some(actual) = bounded_file_len(path)? {
        return Err(AdmittedMaterialError::TooLarge { actual });
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(AdmittedMaterialError::Io(bound(&error.to_string()))),
    };
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > DISPATCHED_MATERIAL_LIMIT_BYTES {
        return Err(AdmittedMaterialError::TooLarge { actual });
    }
    let envelope: AdmittedOperationEnvelope = serde_json::from_slice(&bytes)
        .map_err(|error| AdmittedMaterialError::Malformed(bound(&error.to_string())))?;
    let validated = validate_envelope(envelope, live_epoch)?;
    // Consume-once: a validated presentation must not linger for a later
    // invocation to replay.
    let _ = fs::remove_file(path);
    Ok(Some(validated))
}

/// Validates one presented envelope fail-closed and returns it.
fn validate_envelope(
    envelope: AdmittedOperationEnvelope,
    live_epoch: &EpochId,
) -> Result<AdmittedOperation, AdmittedMaterialError> {
    let expected = envelope_digest(
        &envelope.dispatch,
        &envelope.request,
        &envelope.request_sha256,
    );
    if expected != envelope.envelope_sha256 {
        return Err(AdmittedMaterialError::Malformed(
            "envelope digest mismatch".to_owned(),
        ));
    }
    envelope
        .dispatch
        .validate()
        .map_err(|error| AdmittedMaterialError::Malformed(bound(&error.to_string())))?;
    envelope
        .request
        .validate()
        .map_err(|error| AdmittedMaterialError::Malformed(bound(&error.to_string())))?;
    if !envelope
        .dispatch
        .authority_epoch
        .is_same_authority(live_epoch)
        || !envelope
            .dispatch
            .state_fence
            .authority_epoch
            .is_same_authority(live_epoch)
    {
        return Err(AdmittedMaterialError::StaleEpoch);
    }
    if envelope.request.exchange_id != envelope.dispatch.exchange_id
        || envelope.request.idempotency_key != envelope.dispatch.idempotency_key
        || envelope.request.bridge_generation != envelope.dispatch.bridge_generation
        || envelope.request.required_schema != envelope.dispatch.required_schema
    {
        return Err(AdmittedMaterialError::BindingMismatch(
            "request and dispatch disagree on correlation or route".to_owned(),
        ));
    }
    let request_bytes = serde_json::to_vec(&envelope.request)
        .map_err(|error| AdmittedMaterialError::Malformed(bound(&error.to_string())))?;
    if sha256_hex(&request_bytes) != envelope.request_sha256 {
        return Err(AdmittedMaterialError::RequestDigestMismatch);
    }
    Ok(AdmittedOperation {
        dispatch: envelope.dispatch,
        request: envelope.request,
    })
}

/// Returns the canonical digest over the presented admitted material.
fn envelope_digest(
    dispatch: &ResearchProviderDispatch,
    request: &ResearchQueryRequest,
    request_sha256: &str,
) -> String {
    #[derive(Serialize)]
    struct Preimage<'a> {
        dispatch: &'a ResearchProviderDispatch,
        request: &'a ResearchQueryRequest,
        request_sha256: &'a str,
    }
    let preimage = Preimage {
        dispatch,
        request,
        request_sha256,
    };
    eliot_contracts::canonical_json_bytes(&preimage)
        .map_or_else(|_| String::new(), |bytes| sha256_hex(&bytes))
}

/// Seals the canonical digest a producer must write into the envelope.
#[must_use]
pub fn admitted_envelope_digest(
    dispatch: &ResearchProviderDispatch,
    request: &ResearchQueryRequest,
    request_sha256: &str,
) -> String {
    envelope_digest(dispatch, request, request_sha256)
}

/// Pre-checks the file length so an unbounded file is refused before it is
/// read.
fn bounded_file_len(path: &Path) -> Result<Option<u64>, AdmittedMaterialError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(AdmittedMaterialError::Io(bound(&error.to_string()))),
    };
    let actual = metadata.len();
    if actual > DISPATCHED_MATERIAL_LIMIT_BYTES {
        Ok(Some(actual))
    } else {
        Ok(None)
    }
}

/// Bounds one error detail to a fixed character budget.
fn bound(detail: &str) -> String {
    const LIMIT: usize = 256;
    detail.chars().take(LIMIT).collect()
}
