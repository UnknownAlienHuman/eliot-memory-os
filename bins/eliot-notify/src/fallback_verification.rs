//! Signed Watchdog fallback verification material.
//!
//! Architecture: A11.5 Notifications — the fallback path is a restricted
//! installer-pinned, signed-envelope verification route that never opens the
//! Kernel front door or `UserBroker`; it verifies a pre-published
//! `SignedWatchdogFallbackEnvelope` against an installer-owned declaration.
//! See `ARCH-AUTH-01` (authority is the installer declaration plus the
//! Watchdog signing key), `ARCH-SEC-02` (protected `ProgramData` contour and
//! pinned-artifact checks), `ARCH-RES-01` (no repair or canonical-state
//! ownership).
//!
//! Implementation: I1.3 notification adapter (this crate is the `P-01`/`A-10`
//! adapter binding), I11.7 (Watchdog fallback registration), I14.21 unknown
//! outcome where applicable — unknown publication/delivery is never collapsed
//! into success or failure.
//!
//! State: fallback is signed Watchdog-envelope verification only and owns no
//! canonical state or repair authority. The one-shot ledger durability and
//! compare-and-swap lives in `lib.rs`; this module owns only declaration
//! parsing, validation, and digest helpers.

use std::path::Path;

use ed25519_dalek::VerifyingKey;
use eliot_platform::{PlatformHandle, PortError, ProviderError, ProviderErrorCode};
use eliot_platform_windows::{ProtectedPathLease, protected_program_data_path};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::NotifyBuildError;
use crate::{FALLBACK_BYTES_LIMIT, FALLBACK_VERIFIER_RELATIVE};
use crate::{WATCHDOG_SIGNATURE_ALGORITHM, WATCHDOG_SIGNATURE_DOMAIN};

/// Installer-pinned public material for the separately registered X-01 route.
/// The private signing key is never persisted here or accepted from the user
/// process. The protected declaration binds the public key to one installation,
/// audience, authority epoch, algorithm, key id and signature domain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FallbackVerificationDeclaration {
    pub(crate) installation_identity: PlatformHandle,
    pub(crate) audience: PlatformHandle,
    pub(crate) authority_epoch: u64,
    pub(crate) algorithm: String,
    pub(crate) key_id: PlatformHandle,
    pub(crate) domain: String,
    pub(crate) public_key: String,
    pub(crate) notify_executable: String,
    pub(crate) notify_artifact_sha256: String,
    pub(crate) interactive_user_sid: String,
    pub(crate) interactive_session_id: u32,
}

pub(crate) struct FallbackMaterial {
    pub(crate) declaration: FallbackVerificationDeclaration,
    pub(crate) declaration_digest: String,
    pub(crate) lease: Option<ProtectedPathLease>,
}

impl FallbackMaterial {
    pub(crate) fn validate_live(&self) -> Result<FallbackVerificationDeclaration, PortError> {
        if let Some(lease) = &self.lease {
            lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|_| fallback_provider_error(ProviderErrorCode::Unavailable))?;
            let bytes = lease
                .read_bounded(FALLBACK_BYTES_LIMIT)
                .map_err(|_| fallback_provider_error(ProviderErrorCode::Unavailable))?;
            if sha256_hex(&bytes) != self.declaration_digest {
                return Err(fallback_provider_error(ProviderErrorCode::InvalidRequest));
            }
            let declaration: FallbackVerificationDeclaration = serde_json::from_slice(&bytes)
                .map_err(|_| fallback_provider_error(ProviderErrorCode::InvalidRequest))?;
            if declaration != self.declaration
                || eliot_receipts::canonical_json_bytes(&declaration)
                    .map_err(|_| fallback_provider_error(ProviderErrorCode::InvalidRequest))?
                    != bytes
            {
                return Err(fallback_provider_error(ProviderErrorCode::InvalidRequest));
            }
        }
        Ok(self.declaration.clone())
    }
}

pub(crate) fn fallback_provider_error(code: ProviderErrorCode) -> PortError {
    PortError::Provider(ProviderError {
        code,
        retryable: matches!(
            code,
            ProviderErrorCode::Unavailable | ProviderErrorCode::Timeout
        ),
    })
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn decode_hex(value: &str, expected_bytes: usize) -> Option<Vec<u8>> {
    if value.len() != expected_bytes.checked_mul(2)?
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = u8::try_from((pair[0] as char).to_digit(16)?).ok()?;
            let low = u8::try_from((pair[1] as char).to_digit(16)?).ok()?;
            Some((high << 4) | low)
        })
        .collect()
}

pub(crate) fn validate_fallback_declaration(
    declaration: &FallbackVerificationDeclaration,
) -> Result<(), String> {
    if declaration.authority_epoch == 0
        || declaration.installation_identity.as_str().trim().is_empty()
        || declaration.audience.as_str().trim().is_empty()
        || declaration.key_id.as_str().trim().is_empty()
        || declaration.algorithm != WATCHDOG_SIGNATURE_ALGORITHM
        || declaration.domain != WATCHDOG_SIGNATURE_DOMAIN
        || declaration.public_key.len() != 64
        || !declaration
            .public_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !Path::new(&declaration.notify_executable).is_absolute()
        || !valid_sha256(&declaration.notify_artifact_sha256)
        || !valid_sid(&declaration.interactive_user_sid)
        || declaration.interactive_session_id == 0
    {
        return Err("watchdog verification declaration is invalid".to_owned());
    }
    let bytes = decode_hex(&declaration.public_key, 32)
        .ok_or_else(|| "watchdog public key is not valid hex".to_owned())?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "watchdog public key has the wrong length".to_owned())?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| format!("watchdog public key is invalid: {error}"))?;
    Ok(())
}

pub(crate) fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn valid_sid(value: &str) -> bool {
    value.strip_prefix("S-1-").is_some_and(|tail| {
        !tail.is_empty()
            && tail.len() <= 180
            && tail
                .chars()
                .all(|character| character.is_ascii_digit() || character == '-')
    })
}

pub(crate) fn load_fallback_material() -> Result<FallbackMaterial, NotifyBuildError> {
    let path = protected_program_data_path(FALLBACK_VERIFIER_RELATIVE)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let lease = ProtectedPathLease::open_existing_absolute(&path)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let bytes = lease
        .read_bounded(FALLBACK_BYTES_LIMIT)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let declaration: FallbackVerificationDeclaration =
        serde_json::from_slice(&bytes).map_err(|error| {
            NotifyBuildError::Fallback(format!("decode verifier material: {error}"))
        })?;
    validate_fallback_declaration(&declaration).map_err(NotifyBuildError::Fallback)?;
    if eliot_receipts::canonical_json_bytes(&declaration).map_err(|error| {
        NotifyBuildError::Fallback(format!("canonicalize verifier material: {error}"))
    })? != bytes
    {
        return Err(NotifyBuildError::Fallback(
            "watchdog verification material is not canonical JSON".to_owned(),
        ));
    }
    Ok(FallbackMaterial {
        declaration,
        declaration_digest: sha256_hex(&bytes),
        lease: Some(lease),
    })
}
