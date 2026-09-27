//! Installer-owned signed Watchdog fallback declaration contract.

use std::path::Path;

use super::sha256_hex;
use crate::{WATCHDOG_SIGNATURE_ALGORITHM, WATCHDOG_SIGNATURE_DOMAIN};
use ed25519_dalek::VerifyingKey;
use eliot_platform::PlatformHandle;
use eliot_receipts::canonical_json_bytes;
use serde::{Deserialize, Serialize};

/// Protected relative path for the installer-owned Watchdog verifier declaration.
pub const NOTIFY_FALLBACK_VERIFIER_RELATIVE: &str = "Eliot/notify/watchdog-verification.json";

/// Installer-pinned public material for the separately registered X-01 route.
/// The private signing key is never persisted here or accepted from the user
/// process. The declaration binds the public key to one installation,
/// audience, authority epoch, algorithm, key id and signature domain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackVerificationDeclaration {
    /// Installation identity bound to the declaration.
    pub installation_identity: PlatformHandle,
    /// Declared fallback audience.
    pub audience: PlatformHandle,
    /// Non-zero authority epoch.
    pub authority_epoch: u64,
    /// Signature algorithm required by the fallback contract.
    pub algorithm: String,
    /// Watchdog signing key identifier.
    pub key_id: PlatformHandle,
    /// Signature domain required by the fallback contract.
    pub domain: String,
    /// Lowercase hexadecimal Watchdog verifying key.
    pub public_key: String,
    /// Absolute installed path of the eliot-notify image.
    pub notify_executable: String,
    /// Lowercase SHA-256 digest of the installed image.
    pub notify_artifact_sha256: String,
    /// Interactive user SID authorized for the fallback.
    pub interactive_user_sid: String,
    /// Interactive session authorized for the fallback.
    pub interactive_session_id: u32,
}

/// Explicit installer inputs for one fallback declaration publication.
///
/// Values come from the installation record, key ceremony, current
/// interactive session and staged Notify artifact receipt. Nothing is
/// defaulted, probed, or inferred here.
#[derive(Clone, Debug)]
pub struct NotifyDeclarationInputs {
    /// Installation identity bound to the declaration.
    pub installation_identity: PlatformHandle,
    /// Declared audience for the fallback route.
    pub audience: PlatformHandle,
    /// Non-zero authority epoch.
    pub authority_epoch: u64,
    /// Watchdog signing key identifier.
    pub key_id: PlatformHandle,
    /// Lowercase hexadecimal Watchdog verifying key.
    pub public_key: String,
    /// Absolute installed path of the eliot-notify image.
    pub notify_executable: String,
    /// Lowercase SHA-256 of the installed image bytes.
    pub notify_artifact_sha256: String,
    /// Interactive user SID.
    pub interactive_user_sid: String,
    /// Interactive session id.
    pub interactive_session_id: u32,
}

/// Rendered declaration publication: destination plus exact canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedNotifyDeclaration {
    /// Protected relative declaration path.
    pub relative_path: &'static str,
    /// Canonical JSON declaration bytes to publish.
    pub canonical_bytes: Vec<u8>,
    /// SHA-256 of the canonical bytes (verifier pin).
    pub declaration_digest: String,
}

/// Fail-closed declaration rendering errors. Values and key material are not echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotifyDeclarationError {
    /// One named input field is malformed.
    InvalidField(&'static str),
    /// Canonical serialization failed.
    Unencodable,
}

impl NotifyDeclarationError {
    /// Stable code for this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidField(_) => "NOTIFY_DECLARATION_INVALID_FIELD",
            Self::Unencodable => "NOTIFY_DECLARATION_UNENCODABLE",
        }
    }

    /// Name of the rejected input field, if any.
    #[must_use]
    pub const fn field(&self) -> Option<&'static str> {
        match self {
            Self::InvalidField(field) => Some(field),
            Self::Unencodable => None,
        }
    }
}

impl std::fmt::Display for NotifyDeclarationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField(field) => {
                write!(formatter, "NOTIFY_DECLARATION_INVALID_FIELD:{field}")
            }
            Self::Unencodable => formatter.write_str(Self::Unencodable.code()),
        }
    }
}

impl std::error::Error for NotifyDeclarationError {}

/// Renders one canonical fallback declaration from explicit installer inputs.
///
/// The reader validation gates are enforced before return. Re-parsing and
/// re-encoding prove canonical-byte stability. The caller publishes the bytes.
///
/// # Errors
///
/// Returns [`NotifyDeclarationError::InvalidField`] naming the rejected input,
/// or [`NotifyDeclarationError::Unencodable`] when
/// canonical serialization fails.
pub fn render_notify_fallback_declaration(
    inputs: &NotifyDeclarationInputs,
) -> Result<RenderedNotifyDeclaration, NotifyDeclarationError> {
    let declaration = FallbackVerificationDeclaration {
        installation_identity: inputs.installation_identity.clone(),
        audience: inputs.audience.clone(),
        authority_epoch: inputs.authority_epoch,
        algorithm: WATCHDOG_SIGNATURE_ALGORITHM.to_owned(),
        key_id: inputs.key_id.clone(),
        domain: WATCHDOG_SIGNATURE_DOMAIN.to_owned(),
        public_key: inputs.public_key.clone(),
        notify_executable: inputs.notify_executable.clone(),
        notify_artifact_sha256: inputs.notify_artifact_sha256.clone(),
        interactive_user_sid: inputs.interactive_user_sid.clone(),
        interactive_session_id: inputs.interactive_session_id,
    };
    validate_fallback_declaration(&declaration)
        .map_err(|_| NotifyDeclarationError::InvalidField("declaration"))?;
    let canonical_bytes =
        canonical_json_bytes(&declaration).map_err(|_| NotifyDeclarationError::Unencodable)?;
    let reparsed: FallbackVerificationDeclaration = serde_json::from_slice(&canonical_bytes)
        .map_err(|_| NotifyDeclarationError::Unencodable)?;
    if reparsed != declaration {
        return Err(NotifyDeclarationError::Unencodable);
    }
    let canonical_again =
        canonical_json_bytes(&reparsed).map_err(|_| NotifyDeclarationError::Unencodable)?;
    if canonical_again != canonical_bytes {
        return Err(NotifyDeclarationError::Unencodable);
    }
    Ok(RenderedNotifyDeclaration {
        relative_path: NOTIFY_FALLBACK_VERIFIER_RELATIVE,
        declaration_digest: sha256_hex(&canonical_bytes),
        canonical_bytes,
    })
}

/// Validates the installer-owned fallback declaration contract.
///
/// # Errors
///
/// Returns a stable validation detail when the declaration is malformed.
pub fn validate_fallback_declaration(
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
    let bytes = decode_fallback_key_hex(&declaration.public_key, 32)
        .ok_or_else(|| "watchdog public key is not valid hex".to_owned())?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "watchdog public key has the wrong length".to_owned())?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| format!("watchdog public key is invalid: {error}"))?;
    Ok(())
}

/// Decodes exact lowercase hexadecimal bytes.
#[must_use]
pub fn decode_fallback_key_hex(value: &str, expected_bytes: usize) -> Option<Vec<u8>> {
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

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_sid(value: &str) -> bool {
    value.strip_prefix("S-1-").is_some_and(|tail| {
        !tail.is_empty()
            && tail.len() <= 180
            && tail
                .chars()
                .all(|character| character.is_ascii_digit() || character == '-')
    })
}
