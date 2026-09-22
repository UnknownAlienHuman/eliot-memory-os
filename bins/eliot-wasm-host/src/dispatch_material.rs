//! WASM dispatch material reader (issue #1955, I14.19).
//!
//! Consumes the owner-published dispatch envelope the delivery half stages
//! next to the installed child image: the material file plus the colocated
//! guest artifact/input files. Locator discipline mirrors the native-worker
//! precedent — the executable directory derives every path (`current_exe`,
//! never argv/stdin/env), the child reader stays the authority for the
//! file-name literals, the file is consumed once, and every digest is
//! re-hashed against observed bytes.
//!
//! The envelope shape mirrors `eliot-kernel-service::wasm_dispatch`
//! field-for-field (`deny_unknown_fields` both sides); wire identity and
//! version must match exactly. Validation rebuilds the fence and lease
//! through the production broker types and returns the
//! [`ValidatedDispatchGrant`](crate::dispatch_authority::ValidatedDispatchGrant)
//! the authority issues from — the reader never issues anything itself.
//!
//! Failure discipline: stable codes only. No paths, bytes, digests, or
//! envelope content echoed.

use std::path::{Path, PathBuf};

use eliot_contracts::EpochId;
use eliot_process::{ActionLeaseRef, FencingToken, Generation};
use eliot_wasm_runtime::Sha256Digest;

use crate::dispatch_authority::{DispatchAuthorityError, ValidatedDispatchGrant};

/// Dispatch material file name derived from the executable directory.
/// The child reader stays the authority for this literal; the Kernel
/// delivery half owns its write path.
pub const WASM_HOST_MATERIAL_FILE_NAME: &str = "eliot-wasm-host.admitted-dispatch.json";
/// Colocated guest artifact file staged with the material.
pub const WASM_HOST_GUEST_ARTIFACT_FILE_NAME: &str = "eliot-wasm-host.guest-artifact.bin";
/// Colocated guest input file staged with the material.
pub const WASM_HOST_GUEST_INPUT_FILE_NAME: &str = "eliot-wasm-host.guest-input.bin";
/// Material envelope wire identity, matched exactly.
pub const WASM_DISPATCH_MATERIAL_WIRE_ID: &str = "eliot.wasm.dispatch-material";
/// Material envelope wire version, matched exactly.
pub const WASM_DISPATCH_MATERIAL_WIRE_VERSION: u16 = 1;
/// Allocation guard for the material file: JSON text of a few dozen short
/// handles plus the grant and ceiling records.
pub const DISPATCH_MATERIAL_MAX_BYTES: u64 = 64 * 1024;

/// Fail-closed material errors. Stable codes only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterialError {
    /// No material file was delivered; the caller keeps its fail-closed path.
    Missing,
    /// The material file exceeds the allocation guard.
    TooLarge,
    /// The material file could not be read (kind string only).
    Unreadable(String),
    /// The material bytes are not a valid envelope.
    Malformed,
    /// An observed file digest does not match the envelope record.
    DigestMismatch,
    /// A validated record failed shape checks.
    InvalidRecord {
        /// Stable field name.
        field: &'static str,
    },
    /// The dispatch authority refused the rebuilt grant.
    Authority(DispatchAuthorityError),
}

impl MaterialError {
    /// Stable code for this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Missing => "DISPATCH_MATERIAL_MISSING",
            Self::TooLarge => "DISPATCH_MATERIAL_TOO_LARGE",
            Self::Unreadable(_) => "DISPATCH_MATERIAL_UNREADABLE",
            Self::Malformed => "DISPATCH_MATERIAL_MALFORMED",
            Self::DigestMismatch => "DISPATCH_MATERIAL_DIGEST_MISMATCH",
            Self::InvalidRecord { .. } => "DISPATCH_MATERIAL_INVALID_RECORD",
            Self::Authority(_) => "DISPATCH_MATERIAL_AUTHORITY_REFUSED",
        }
    }
}

impl std::fmt::Display for MaterialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(kind) => {
                write!(formatter, "DISPATCH_MATERIAL_UNREADABLE:{kind}")
            }
            Self::InvalidRecord { field } => {
                write!(formatter, "DISPATCH_MATERIAL_INVALID_RECORD:{field}")
            }
            Self::Authority(error) => write!(formatter, "{error}"),
            other => formatter.write_str(other.code()),
        }
    }
}

impl std::error::Error for MaterialError {}

/// Wire mirror of the owner-published grant record.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialGrantMirror {
    grant_digest: String,
    authority_epoch: EpochId,
    fence_generation: u64,
    fence_nonce: String,
    idempotency_key: String,
    expires_at: u64,
    host_artifact_digest: String,
}

/// Wire mirror of the guest invocation ceilings record.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestCeilingsMirror {
    artifact_digest: String,
    input_digest: String,
    max_output_bytes: u64,
    max_fuel: u64,
    max_memory_bytes: u64,
    wall_deadline_ms: u64,
    epoch_deadline_ticks: u64,
    component_id: String,
}

/// Wire mirror of the dispatch material envelope, field-for-field with the
/// owner publisher.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialEnvelopeMirror {
    wire_id: String,
    wire_version: u16,
    claim_id: String,
    operation_id: String,
    generation: u64,
    authority_epoch: EpochId,
    launch_nonce: String,
    admitted_at_unix_ms: u64,
    grant: MaterialGrantMirror,
    guest: GuestCeilingsMirror,
    profile: String,
}

/// Validated guest ceilings carried for intent derivation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedGuestCeilings {
    /// Pinned component identity.
    pub component_id: String,
    /// Re-proven artifact digest.
    pub artifact_digest: Sha256Digest,
    /// Re-proven input digest.
    pub input_digest: Sha256Digest,
    /// Output byte ceiling.
    pub max_output_bytes: u64,
    /// Fuel ceiling.
    pub max_fuel: u64,
    /// Memory byte ceiling.
    pub max_memory_bytes: u64,
    /// Wall deadline (ms).
    pub wall_deadline_ms: u64,
    /// Epoch deadline ticks.
    pub epoch_deadline_ticks: u64,
}

/// Session-bound dispatch material validated against itself, plus the
/// colocated file bytes re-hashed against the envelope records.
///
/// Carries exactly what the parent drive binds: pre-binding derivation
/// identities, the validated grant funding the one-shot permit, the
/// owner-measured host digest, and the proven guest bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDispatchMaterial {
    /// Admitted claim identity feeding the derivation base.
    pub claim_id: String,
    /// Admitted operation identity feeding the derivation base.
    pub operation_id: String,
    /// Claiming generation feeding the derivation base.
    pub generation: u64,
    /// Live authority epoch bound at admission.
    pub authority_epoch: EpochId,
    /// Claim-bound launch nonce (derivation + permit nonce).
    pub launch_nonce: String,
    /// Durable admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Validated grant funding the one-shot permit.
    pub grant: ValidatedDispatchGrant,
    /// Owner-measured installed-image digest.
    pub host_artifact_digest: Sha256Digest,
    /// Owner-selected composition profile, compiled into this binary.
    pub profile: crate::cli_contract::Profile,
    /// Validated guest ceilings and pinned identities.
    pub ceilings: ValidatedGuestCeilings,
    /// Observed guest artifact bytes matching the envelope digest.
    pub artifact_bytes: Vec<u8>,
    /// Observed guest input bytes matching the envelope digest.
    pub input_bytes: Vec<u8>,
}

/// Derives the material file path from the executable directory.
/// `None` when the loader path is unavailable: no fallback source exists.
#[must_use]
pub fn admitted_material_path() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let directory = executable.parent()?;
    Some(directory.join(WASM_HOST_MATERIAL_FILE_NAME))
}

/// Reads and validates the session-bound dispatch material for this
/// invocation. `Ok(None)` when no file was delivered (caller keeps its
/// fail-closed path); a validated file is consumed once.
pub fn read_dispatch_material() -> Result<Option<ValidatedDispatchMaterial>, MaterialError> {
    let Some(path) = admitted_material_path() else {
        return Ok(None);
    };
    read_dispatch_material_from(&path)
}

/// Reads and validates dispatch material from one explicit path: the
/// production locator plus bounded tests stage through here. Production
/// always passes [`admitted_material_path`].
pub fn read_dispatch_material_from(
    path: &Path,
) -> Result<Option<ValidatedDispatchMaterial>, MaterialError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(MaterialError::Unreadable(error.kind().to_string())),
    };
    if metadata.len() > DISPATCH_MATERIAL_MAX_BYTES {
        return Err(MaterialError::TooLarge);
    }
    let bytes =
        std::fs::read(path).map_err(|error| MaterialError::Unreadable(error.kind().to_string()))?;
    if bytes.len() as u64 > DISPATCH_MATERIAL_MAX_BYTES {
        return Err(MaterialError::TooLarge);
    }
    let envelope: MaterialEnvelopeMirror =
        serde_json::from_slice(&bytes).map_err(|_| MaterialError::Malformed)?;
    let validated = validate_envelope(&envelope, path)?;
    consume_material(path);
    Ok(Some(validated))
}

/// Consume-once: a validated presentation must not linger for a later
/// invocation to replay. Removal is best-effort; the next delivery
/// overwrites it.
fn consume_material(path: &Path) {
    let _ = std::fs::remove_file(path);
}

fn hex_digest(hex: &str, field: &'static str) -> Result<Sha256Digest, MaterialError> {
    Sha256Digest::new(hex).map_err(|_| MaterialError::InvalidRecord { field })
}

/// Validates the envelope records and re-hashes the colocated files.
/// The directory holding the material file stages the guest files; every
/// digest check binds observed bytes, never carried values.
fn validate_envelope(
    envelope: &MaterialEnvelopeMirror,
    path: &Path,
) -> Result<ValidatedDispatchMaterial, MaterialError> {
    let invalid = |field: &'static str| MaterialError::InvalidRecord { field };
    check_envelope_identities(envelope)?;
    let profile: crate::cli_contract::Profile =
        envelope.profile.parse().map_err(|_| invalid("profile"))?;
    if !profile.is_compiled() {
        return Err(invalid("profile"));
    }
    let grant = rebuild_grant(envelope)?;
    let ceilings = check_guest_ceilings(envelope)?;
    let directory = path.parent().ok_or_else(|| invalid("material-dir"))?;
    let artifact_bytes = read_colocated(
        &directory.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME),
        &ceilings.artifact_digest,
    )?;
    let input_bytes = read_colocated(
        &directory.join(WASM_HOST_GUEST_INPUT_FILE_NAME),
        &ceilings.input_digest,
    )?;
    Ok(ValidatedDispatchMaterial {
        claim_id: envelope.claim_id.clone(),
        operation_id: envelope.operation_id.clone(),
        generation: envelope.generation,
        authority_epoch: envelope.authority_epoch.clone(),
        launch_nonce: envelope.launch_nonce.clone(),
        admitted_at_unix_ms: envelope.admitted_at_unix_ms,
        grant: grant.grant,
        host_artifact_digest: grant.host_digest,
        profile,
        ceilings: ValidatedGuestCeilings {
            component_id: ceilings.component_id.clone(),
            artifact_digest: ceilings.artifact_digest.clone(),
            input_digest: ceilings.input_digest.clone(),
            max_output_bytes: ceilings.max_output_bytes,
            max_fuel: ceilings.max_fuel,
            max_memory_bytes: ceilings.max_memory_bytes,
            wall_deadline_ms: ceilings.wall_deadline_ms,
            epoch_deadline_ticks: ceilings.epoch_deadline_ticks,
        },
        artifact_bytes,
        input_bytes,
    })
}

/// Checks envelope wire identity plus claim/operation/generation/nonce/
/// admission-time shape. Pure record checks; digest and grant proofs below.
fn check_envelope_identities(envelope: &MaterialEnvelopeMirror) -> Result<(), MaterialError> {
    let invalid = |field: &'static str| MaterialError::InvalidRecord { field };
    if envelope.wire_id != WASM_DISPATCH_MATERIAL_WIRE_ID
        || envelope.wire_version != WASM_DISPATCH_MATERIAL_WIRE_VERSION
    {
        return Err(invalid("wire"));
    }
    if envelope.claim_id.trim().is_empty() {
        return Err(invalid("claim-id"));
    }
    if envelope.operation_id.trim().is_empty() {
        return Err(invalid("operation-id"));
    }
    if envelope.generation == 0 {
        return Err(invalid("generation"));
    }
    if envelope.launch_nonce.trim().is_empty() {
        return Err(invalid("launch-nonce"));
    }
    if envelope.admitted_at_unix_ms == 0 {
        return Err(invalid("admitted-at"));
    }
    Ok(())
}

/// Rebuilt grant inputs: the validated grant plus the owner-measured host
/// digest, proven against the envelope records.
struct RebuiltGrant {
    grant: ValidatedDispatchGrant,
    host_digest: Sha256Digest,
}

/// Rebuilds the fence and lease through the production broker types and
/// validates the grant window and epoch agreement.
fn rebuild_grant(envelope: &MaterialEnvelopeMirror) -> Result<RebuiltGrant, MaterialError> {
    let invalid = |field: &'static str| MaterialError::InvalidRecord { field };
    if envelope.grant.fence_generation == 0 {
        return Err(invalid("fence-generation"));
    }
    if envelope.grant.expires_at <= envelope.admitted_at_unix_ms {
        return Err(invalid("grant-window"));
    }
    let host_digest = hex_digest(&envelope.grant.host_artifact_digest, "host-artifact-digest")?;
    let generation = Generation::new(envelope.grant.fence_generation)
        .map_err(|_| invalid("fence-generation"))?;
    let fence = FencingToken::new(
        envelope.grant.authority_epoch.clone(),
        generation,
        envelope.grant.fence_nonce.clone(),
    )
    .map_err(|_| invalid("fence"))?;
    if fence.authority_epoch() != &envelope.authority_epoch {
        return Err(invalid("epoch-agreement"));
    }
    let lease = ActionLeaseRef::new(envelope.grant.idempotency_key.clone())
        .map_err(|_| invalid("lease"))?;
    let grant = ValidatedDispatchGrant::new(
        fence,
        lease,
        envelope.grant.grant_digest.clone(),
        envelope.admitted_at_unix_ms,
        envelope.grant.expires_at,
    )
    .map_err(MaterialError::Authority)?;
    Ok(RebuiltGrant { grant, host_digest })
}

/// Checked guest ceilings record: non-blank component, non-zero ceilings,
/// well-shaped digests.
struct CheckedCeilings {
    component_id: String,
    artifact_digest: Sha256Digest,
    input_digest: Sha256Digest,
    max_output_bytes: u64,
    max_fuel: u64,
    max_memory_bytes: u64,
    wall_deadline_ms: u64,
    epoch_deadline_ticks: u64,
}

fn check_guest_ceilings(
    envelope: &MaterialEnvelopeMirror,
) -> Result<CheckedCeilings, MaterialError> {
    let invalid = |field: &'static str| MaterialError::InvalidRecord { field };
    let guest = &envelope.guest;
    if guest.component_id.trim().is_empty() {
        return Err(invalid("guest-component-id"));
    }
    for value in [
        guest.max_output_bytes,
        guest.max_fuel,
        guest.max_memory_bytes,
        guest.wall_deadline_ms,
        guest.epoch_deadline_ticks,
    ] {
        if value == 0 {
            return Err(invalid("guest-ceilings"));
        }
    }
    Ok(CheckedCeilings {
        component_id: guest.component_id.clone(),
        artifact_digest: hex_digest(&guest.artifact_digest, "guest-artifact-digest")?,
        input_digest: hex_digest(&guest.input_digest, "guest-input-digest")?,
        max_output_bytes: guest.max_output_bytes,
        max_fuel: guest.max_fuel,
        max_memory_bytes: guest.max_memory_bytes,
        wall_deadline_ms: guest.wall_deadline_ms,
        epoch_deadline_ticks: guest.epoch_deadline_ticks,
    })
}

/// Reads one colocated guest file and binds its observed bytes to the
/// envelope digest (single-read TOCTOU discipline).
fn read_colocated(path: &Path, expected: &Sha256Digest) -> Result<Vec<u8>, MaterialError> {
    let bytes =
        std::fs::read(path).map_err(|error| MaterialError::Unreadable(error.kind().to_string()))?;
    if bytes.is_empty() {
        return Err(MaterialError::InvalidRecord {
            field: "guest-empty",
        });
    }
    if Sha256Digest::of_bytes(&bytes) != *expected {
        return Err(MaterialError::DigestMismatch);
    }
    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fixture_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("eliot-1955-dispatch-{tag}"));
        std::fs::create_dir_all(&dir).expect("fixture dir");
        dir
    }

    fn artifact_bytes() -> Vec<u8> {
        let mut bytes = b"\x00asm\x02\x00\x00\x00".to_vec();
        bytes.extend_from_slice(b"dispatch-material-component-body");
        bytes
    }

    fn input_bytes() -> Vec<u8> {
        b"dispatch-material-input-body".to_vec()
    }

    fn envelope_json(artifact_hex: &str, input_hex: &str) -> Vec<u8> {
        format!(
            r#"{{
            "wire_id": "eliot.wasm.dispatch-material",
            "wire_version": 1,
            "claim_id": "claim-wasm-r1-001",
            "operation_id": "operation-wasm-r1-001",
            "generation": 7,
            "authority_epoch": {{
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 3
            }},
            "launch_nonce": "launch-nonce-wasm-r1-0001",
            "admitted_at_unix_ms": 4000000000000,
            "profile": "D2_OPERATIONAL",
            "grant": {{
                "grant_digest": "{}",
                "authority_epoch": {{
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 3
                }},
                "fence_generation": 7,
                "fence_nonce": "wasm-host-launch-fence-aaaaaaaaaaaaaaa",
                "idempotency_key": "wasm-host-launch-lease-aaaaaaaaaaaaaaa",
                "expires_at": 4000000060000,
                "host_artifact_digest": "{}"
            }},
            "guest": {{
                "artifact_digest": "{artifact_hex}",
                "input_digest": "{input_hex}",
                "max_output_bytes": 1024,
                "max_fuel": 100000,
                "max_memory_bytes": 1048576,
                "wall_deadline_ms": 10000,
                "epoch_deadline_ticks": 100,
                "component_id": "component-1955"
            }}
        }}"#,
            "e".repeat(64),
            "d".repeat(64),
        )
        .into_bytes()
    }

    fn stage_fixtures(tag: &str) -> PathBuf {
        let dir = fixture_dir(tag);
        let artifact = artifact_bytes();
        let input = input_bytes();
        let artifact_hex = Sha256Digest::of_bytes(&artifact).as_str().to_owned();
        let input_hex = Sha256Digest::of_bytes(&input).as_str().to_owned();
        std::fs::write(dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME), &artifact)
            .expect("artifact fixture");
        std::fs::write(dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME), &input).expect("input fixture");
        std::fs::write(
            dir.join(WASM_HOST_MATERIAL_FILE_NAME),
            envelope_json(&artifact_hex, &input_hex),
        )
        .expect("material fixture");
        dir
    }

    fn unstage(dir: &Path) {
        let _ = std::fs::remove_file(dir.join(WASM_HOST_MATERIAL_FILE_NAME));
        let _ = std::fs::remove_file(dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME));
        let _ = std::fs::remove_file(dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME));
        let _ = std::fs::remove_dir(dir);
    }

    #[test]
    fn valid_material_validates_and_consumes_once() {
        let dir = stage_fixtures("valid");
        let path = dir.join(WASM_HOST_MATERIAL_FILE_NAME);
        let material = read_dispatch_material_from(&path).expect("valid material reads");
        let material = material.expect("material present");
        assert_eq!(material.claim_id, "claim-wasm-r1-001");
        assert_eq!(material.ceilings.component_id, "component-1955");
        assert_eq!(material.artifact_bytes, artifact_bytes());
        assert_eq!(material.input_bytes, input_bytes());
        assert_eq!(material.grant.expires_at(), 4_000_000_060_000);
        assert_eq!(
            material.profile,
            crate::cli_contract::Profile::D2Operational
        );
        // Consumed once: the file is gone, the next read reports missing.
        assert!(!path.exists(), "material file is consumed once");
        assert_eq!(read_dispatch_material_from(&path), Ok(None));
        unstage(&dir);
    }

    #[test]
    fn uncompiled_profile_fails_closed() {
        // FANCY_PROFILE parses to nothing: the composition selection is
        // denied before any authority is touched.
        let dir = stage_fixtures("profile");
        let path = dir.join(WASM_HOST_MATERIAL_FILE_NAME);
        let raw = std::fs::read(&path).expect("material fixture");
        let text = String::from_utf8(raw).expect("envelope is utf8");
        std::fs::write(&path, text.replace("D2_OPERATIONAL", "FANCY_PROFILE"))
            .expect("profile fixture");
        assert!(matches!(
            read_dispatch_material_from(&path).map(|_| ()),
            Err(MaterialError::InvalidRecord { .. })
        ));
        unstage(&dir);
    }

    #[test]
    fn missing_file_reports_absence() {
        let dir = fixture_dir("missing");
        let path = dir.join(WASM_HOST_MATERIAL_FILE_NAME);
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_dispatch_material_from(&path), Ok(None));
        unstage(&dir);
    }

    #[test]
    fn tampered_bytes_and_wire_fail_closed() {
        // Tampered artifact breaks the envelope digest binding.
        let dir = stage_fixtures("tampered");
        std::fs::write(
            dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME),
            b"tampered-component-bytes",
        )
        .expect("tamper fixture");
        assert_eq!(
            read_dispatch_material_from(&dir.join(WASM_HOST_MATERIAL_FILE_NAME)).map(|_| ()),
            Err(MaterialError::DigestMismatch)
        );
        unstage(&dir);
        // Wrong wire identity is malformed-shape (unknown value, known keys).
        let dir = fixture_dir("wire");
        let artifact = artifact_bytes();
        let input = input_bytes();
        let mut raw = envelope_json(
            Sha256Digest::of_bytes(&artifact).as_str(),
            Sha256Digest::of_bytes(&input).as_str(),
        );
        let text = String::from_utf8(raw.clone()).expect("envelope is utf8");
        raw = text
            .replace("eliot.wasm.dispatch-material", "eliot.wasm.other")
            .into_bytes();
        std::fs::write(dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME), &artifact)
            .expect("artifact fixture");
        std::fs::write(dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME), &input).expect("input fixture");
        std::fs::write(dir.join(WASM_HOST_MATERIAL_FILE_NAME), &raw).expect("material fixture");
        assert!(matches!(
            read_dispatch_material_from(&dir.join(WASM_HOST_MATERIAL_FILE_NAME)).map(|_| ()),
            Err(MaterialError::InvalidRecord { .. })
        ));
        unstage(&dir);
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(MaterialError::Missing.code(), "DISPATCH_MATERIAL_MISSING");
        assert_eq!(
            MaterialError::DigestMismatch.to_string(),
            "DISPATCH_MATERIAL_DIGEST_MISMATCH"
        );
    }
}
