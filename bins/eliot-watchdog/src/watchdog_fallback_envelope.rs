//! Watchdog-side producer (minter) of the minimal signed fallback envelope.
//!
//! This module mints the five-field [`WatchdogFallbackEnvelope`] content
//! (incident class, installation identity, timestamp, evidence digest, and
//! the fixed `EliotRecoveryStatus` instruction) and signs its canonical
//! [`watchdog_signature_payload`] with the caller-supplied Watchdog secret
//! key, producing the [`SignedWatchdogFallbackEnvelope`] consumed by the
//! separately registered `eliot-notify` fallback route.
//!
//! Key custody: this module NEVER loads, stores, or provisions keys. The
//! caller supplies the raw 32-byte secret (`signing_key`); key provisioning
//! and ceremony are owned by the installer-ceremony follow-up. The secret
//! bytes must come from the installer's protected binding, never from user
//! input, logs, or canonical state.
//!
//! Size policy: the canonical envelope bytes must fit
//! [`WATCHDOG_FALLBACK_ENVELOPE_MAX_BYTES`], imported from
//! `eliot-notify-core` (policy owner). This module defines no size bound of
//! its own.
//!
//! Path policy: [`publish_watchdog_fallback_envelope`] takes the ABSOLUTE
//! destination path as input and duplicates no path constant. Resolving the
//! protected `ProgramData` `Eliot/notify/watchdog-fallback-envelope.json`
//! destination is owned by the watchdog composition follow-up that calls the
//! minter.

use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};
use eliot_notify_core::{
    RecoveryInstruction, SignedWatchdogFallbackEnvelope, WATCHDOG_FALLBACK_ENVELOPE_MAX_BYTES,
    WATCHDOG_SIGNATURE_ALGORITHM, WATCHDOG_SIGNATURE_DOMAIN, WatchdogFallbackEnvelope,
    watchdog_signature_payload,
};
use eliot_platform::PlatformHandle;
use thiserror::Error;

/// Maximum accepted length for `incident_class`, in characters (ASCII-only,
/// so bytes and characters coincide).
const INCIDENT_CLASS_MAX: usize = 64;
/// Maximum accepted length for `installation_identity` and `key_id`, in
/// bytes. Mirrors the transport-local installation-identity bound; the
/// canonical byte cap is enforced separately at publish time.
const IDENTITY_MAX: usize = 128;
/// Exact length of `evidence_digest`: one lowercase-hex SHA-256.
const EVIDENCE_DIGEST_LEN: usize = 64;

/// Plain caller-supplied inputs for one fallback-envelope mint.
///
/// All fields are plain `String`s; every bound is validated inside
/// [`mint_watchdog_fallback_envelope`]. No key material appears here: the
/// signing secret travels only through the explicit `signing_key` parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogFallbackMintInputs {
    /// `SCREAMING_SNAKE_CASE` incident class, 1..=64 ASCII `[A-Z0-9_]` chars.
    pub incident_class: String,
    /// Owning installation identity: non-blank, no controls, <=128 bytes.
    pub installation_identity: String,
    /// Evidence binding: exactly 64 lowercase-hex chars (SHA-256).
    pub evidence_digest: String,
    /// Host-clock timestamp, milliseconds since Unix epoch; must be >= 0.
    pub timestamp_ms: i64,
    /// Installer-bound key id selecting the verification key: non-blank, no
    /// controls, <=128 bytes.
    pub key_id: String,
}

/// Local mint/publish failure. No variant carries key or secret material.
#[derive(Debug, Error)]
pub enum WatchdogFallbackMintError {
    #[error("invalid incident_class: {0}")]
    InvalidIncidentClass(String),
    #[error("invalid installation_identity: {0}")]
    InvalidInstallationIdentity(String),
    #[error("invalid evidence_digest: {0}")]
    InvalidEvidenceDigest(String),
    #[error("invalid timestamp_ms: {0}")]
    InvalidTimestamp(String),
    #[error("invalid key_id: {0}")]
    InvalidKeyId(String),
    #[error("signed fallback envelope is {len} bytes, above the {max}-byte cap")]
    EnvelopeTooLarge { len: usize, max: usize },
    #[error("fallback envelope serialization failed: {0}")]
    Serialization(String),
    #[error("fallback envelope storage failed: {0}")]
    Storage(String),
}

/// Validates `inputs`, builds the five-field envelope with the fixed
/// `EliotRecoveryStatus` recovery instruction, and signs the canonical
/// [`watchdog_signature_payload`] with `signing_key`.
///
/// The signature is lowercase-hex encoded and stored with
/// `algorithm = "ED25519"` and the fixed signature domain. The caller owns
/// key custody: this function receives only raw secret bytes and performs
/// no key loading, storage, or provisioning.
///
/// # Errors
///
/// Returns [`WatchdogFallbackMintError`] when any field violates its cap,
/// when canonical serialization fails, or when the minted envelope exceeds
/// the imported byte cap.
pub fn mint_watchdog_fallback_envelope(
    inputs: &WatchdogFallbackMintInputs,
    signing_key: &[u8; 32],
) -> Result<SignedWatchdogFallbackEnvelope, WatchdogFallbackMintError> {
    validate_incident_class(&inputs.incident_class)?;
    validate_bounded_identity(
        &inputs.installation_identity,
        WatchdogFallbackMintError::InvalidInstallationIdentity,
        "installation_identity",
    )?;
    validate_evidence_digest(&inputs.evidence_digest)?;
    if inputs.timestamp_ms < 0 {
        return Err(WatchdogFallbackMintError::InvalidTimestamp(
            "timestamp_ms is negative".to_owned(),
        ));
    }
    validate_bounded_identity(
        &inputs.key_id,
        WatchdogFallbackMintError::InvalidKeyId,
        "key_id",
    )?;

    let incident_class = PlatformHandle::new(inputs.incident_class.clone())
        .map_err(|error| WatchdogFallbackMintError::InvalidIncidentClass(error.to_string()))?;
    let installation_identity =
        PlatformHandle::new(inputs.installation_identity.clone()).map_err(|error| {
            WatchdogFallbackMintError::InvalidInstallationIdentity(error.to_string())
        })?;
    let key_id = PlatformHandle::new(inputs.key_id.clone())
        .map_err(|error| WatchdogFallbackMintError::InvalidKeyId(error.to_string()))?;

    let envelope = WatchdogFallbackEnvelope {
        incident_class,
        installation_identity,
        timestamp_ms: inputs.timestamp_ms,
        evidence_digest: inputs.evidence_digest.clone(),
        recovery_instruction: RecoveryInstruction::EliotRecoveryStatus,
    };
    // Skeleton carries the exact metadata the payload binds; the detached
    // signature itself is excluded from the signed bytes.
    let skeleton = SignedWatchdogFallbackEnvelope {
        envelope,
        algorithm: WATCHDOG_SIGNATURE_ALGORITHM.to_owned(),
        key_id,
        domain: WATCHDOG_SIGNATURE_DOMAIN.to_owned(),
        signature: String::new(),
    };
    let payload = watchdog_signature_payload(&skeleton)
        .map_err(|error| WatchdogFallbackMintError::Serialization(error.to_string()))?;
    let signing_key = SigningKey::from_bytes(signing_key);
    let signature = signing_key.sign(&payload);
    let signed = SignedWatchdogFallbackEnvelope {
        signature: hex_encode_lower(&signature.to_bytes()),
        ..skeleton
    };
    enforce_size_cap(&signed)?;
    Ok(signed)
}

/// Serializes `signed` to canonical JSON, enforces the imported byte cap,
/// writes it to the caller-supplied ABSOLUTE `path`, and verifies the write
/// with a readback byte comparison.
///
/// Returns the lowercase-hex SHA-256 digest of the published bytes (the
/// readback-verified digest the scheduler/notify consumer can re-derive).
///
/// # Errors
///
/// Returns [`WatchdogFallbackMintError`] when serialization fails, the
/// canonical bytes exceed the cap, the write/readback fails, or the
/// readback bytes differ from what was written.
pub fn publish_watchdog_fallback_envelope(
    path: &Path,
    signed: &SignedWatchdogFallbackEnvelope,
) -> Result<String, WatchdogFallbackMintError> {
    // Reject malformed envelopes before touching the filesystem.
    watchdog_signature_payload(signed)
        .map_err(|error| WatchdogFallbackMintError::Serialization(error.to_string()))?;
    enforce_size_cap(signed)?;
    let bytes = eliot_receipts::canonical_json_bytes(signed)
        .map_err(|error| WatchdogFallbackMintError::Serialization(error.to_string()))?;
    std::fs::write(path, &bytes)
        .map_err(|error| WatchdogFallbackMintError::Storage(error.to_string()))?;
    let readback = std::fs::read(path)
        .map_err(|error| WatchdogFallbackMintError::Storage(error.to_string()))?;
    if readback != bytes {
        return Err(WatchdogFallbackMintError::Storage(
            "published envelope readback differs from the written bytes".to_owned(),
        ));
    }
    Ok(eliot_receipts::sha256_hex(&bytes))
}

/// Enforces the policy-owner byte cap on the canonical encoding.
fn enforce_size_cap(
    signed: &SignedWatchdogFallbackEnvelope,
) -> Result<(), WatchdogFallbackMintError> {
    let bytes = eliot_receipts::canonical_json_bytes(signed)
        .map_err(|error| WatchdogFallbackMintError::Serialization(error.to_string()))?;
    if bytes.len() > WATCHDOG_FALLBACK_ENVELOPE_MAX_BYTES {
        return Err(WatchdogFallbackMintError::EnvelopeTooLarge {
            len: bytes.len(),
            max: WATCHDOG_FALLBACK_ENVELOPE_MAX_BYTES,
        });
    }
    Ok(())
}

/// Validates the `SCREAMING_SNAKE_CASE` incident class: 1..=64 ASCII
/// `[A-Z0-9_]` characters.
fn validate_incident_class(value: &str) -> Result<(), WatchdogFallbackMintError> {
    let reject = |detail: &str| {
        WatchdogFallbackMintError::InvalidIncidentClass(format!(
            "incident_class {detail}: length={} (bound 1..={INCIDENT_CLASS_MAX})",
            value.len()
        ))
    };
    if value.is_empty() || value.len() > INCIDENT_CLASS_MAX {
        return Err(reject("violates the length bound"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(reject("is not ASCII SCREAMING_SNAKE_CASE [A-Z0-9_]"));
    }
    Ok(())
}

/// Validates a bounded identity (`installation_identity`, `key_id`):
/// non-blank, no control characters, <=128 bytes.
fn validate_bounded_identity(
    value: &str,
    wrap: fn(String) -> WatchdogFallbackMintError,
    field: &'static str,
) -> Result<(), WatchdogFallbackMintError> {
    if value.trim().is_empty() {
        return Err(wrap(format!("{field} is blank")));
    }
    if value.chars().any(char::is_control) {
        return Err(wrap(format!("{field} contains control characters")));
    }
    if value.len() > IDENTITY_MAX {
        return Err(wrap(format!(
            "{field} is {} bytes (bound <={IDENTITY_MAX})",
            value.len()
        )));
    }
    Ok(())
}

/// Validates the evidence digest: exactly 64 lowercase-hex characters.
fn validate_evidence_digest(value: &str) -> Result<(), WatchdogFallbackMintError> {
    if value.len() != EVIDENCE_DIGEST_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(WatchdogFallbackMintError::InvalidEvidenceDigest(
            "evidence_digest must be exactly 64 lowercase-hex characters".to_owned(),
        ));
    }
    Ok(())
}

/// Lowercase-hex encodes signature bytes for the explicit wire contract.
fn hex_encode_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().checked_mul(2).unwrap_or(0));
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    const TEST_SIGNING_KEY: [u8; 32] = [0x42; 32];

    fn valid_inputs() -> WatchdogFallbackMintInputs {
        WatchdogFallbackMintInputs {
            incident_class: "KERNEL_UNRESPONSIVE".to_owned(),
            installation_identity: "installation-7".to_owned(),
            evidence_digest: "ab".repeat(32),
            timestamp_ms: 1_755_000_000_000,
            key_id: "watchdog-fallback-key-1".to_owned(),
        }
    }

    fn maximal_inputs() -> WatchdogFallbackMintInputs {
        WatchdogFallbackMintInputs {
            incident_class: "A".repeat(INCIDENT_CLASS_MAX),
            installation_identity: "i".repeat(IDENTITY_MAX),
            evidence_digest: "cd".repeat(32),
            timestamp_ms: i64::MAX,
            key_id: "k".repeat(IDENTITY_MAX),
        }
    }

    fn decode_hex_lower(value: &str) -> Option<Vec<u8>> {
        if value.len() % 2 != 0
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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

    fn unique_test_dir(name: &str) -> std::path::PathBuf {
        let id = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "eliot-watchdog-fallback-{name}-{}-{id}",
            std::process::id()
        ))
    }

    #[test]
    fn mint_round_trip_verifies_with_watcher_payload_logic() {
        let signed =
            mint_watchdog_fallback_envelope(&valid_inputs(), &TEST_SIGNING_KEY).expect("mint");
        assert_eq!(signed.algorithm, WATCHDOG_SIGNATURE_ALGORITHM);
        assert_eq!(signed.domain, WATCHDOG_SIGNATURE_DOMAIN);
        assert_eq!(
            signed.envelope.recovery_instruction,
            RecoveryInstruction::EliotRecoveryStatus
        );
        assert_eq!(signed.signature.len(), 128);
        assert!(decode_hex_lower(&signed.signature).is_some_and(|bytes| bytes.len() == 64));

        // Same payload function the notify-side verifier uses.
        let payload = watchdog_signature_payload(&signed).expect("payload");
        let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
        let verifying = signing.verifying_key();
        let raw = decode_hex_lower(&signed.signature).expect("signature hex");
        let bytes: [u8; 64] = raw.try_into().expect("signature length");
        let signature = Signature::from_bytes(&bytes);
        verifying
            .verify_strict(&payload, &signature)
            .expect("minted signature verifies");

        // Cross-check against an independently derived verifying key.
        let expected = VerifyingKey::from_bytes(&signing.verifying_key().to_bytes()).expect("key");
        assert_eq!(verifying, expected);
    }

    #[test]
    fn tampered_payload_fails_strict_verification() {
        let signed =
            mint_watchdog_fallback_envelope(&valid_inputs(), &TEST_SIGNING_KEY).expect("mint");
        let payload = watchdog_signature_payload(&signed).expect("payload");
        let signing = SigningKey::from_bytes(&TEST_SIGNING_KEY);
        let raw = decode_hex_lower(&signed.signature).expect("signature hex");
        let bytes: [u8; 64] = raw.try_into().expect("signature length");
        let signature = Signature::from_bytes(&bytes);
        let mut tampered = payload.clone();
        tampered[0] ^= 0x01;
        assert!(
            signing
                .verifying_key()
                .verify_strict(&tampered, &signature)
                .is_err()
        );
    }

    #[test]
    fn bad_fields_are_rejected() {
        let cases: Vec<(&'static str, Box<dyn Fn(&mut WatchdogFallbackMintInputs)>)> = vec![
            (
                "empty incident_class",
                Box::new(|inputs| {
                    inputs.incident_class.clear();
                }),
            ),
            (
                "lowercase incident_class",
                Box::new(|inputs| {
                    inputs.incident_class = "kernel_down".to_owned();
                }),
            ),
            (
                "incident_class with dash",
                Box::new(|inputs| {
                    inputs.incident_class = "KERNEL-DOWN".to_owned();
                }),
            ),
            (
                "incident_class too long",
                Box::new(|inputs| {
                    inputs.incident_class = "A".repeat(INCIDENT_CLASS_MAX + 1);
                }),
            ),
            (
                "blank installation_identity",
                Box::new(|inputs| {
                    inputs.installation_identity = "   ".to_owned();
                }),
            ),
            (
                "installation_identity with control",
                Box::new(|inputs| {
                    inputs.installation_identity = "installation-\u{7}7".to_owned();
                }),
            ),
            (
                "installation_identity too long",
                Box::new(|inputs| {
                    inputs.installation_identity = "i".repeat(IDENTITY_MAX + 1);
                }),
            ),
            (
                "evidence_digest too short",
                Box::new(|inputs| {
                    inputs.evidence_digest = "ab".repeat(31);
                }),
            ),
            (
                "evidence_digest uppercase",
                Box::new(|inputs| {
                    inputs.evidence_digest = "AB".repeat(32);
                }),
            ),
            (
                "evidence_digest non-hex",
                Box::new(|inputs| {
                    inputs.evidence_digest = "zz".repeat(32);
                }),
            ),
            (
                "negative timestamp",
                Box::new(|inputs| {
                    inputs.timestamp_ms = -1;
                }),
            ),
            (
                "blank key_id",
                Box::new(|inputs| {
                    inputs.key_id.clear();
                }),
            ),
            (
                "key_id with control",
                Box::new(|inputs| {
                    inputs.key_id = "key\n1".to_owned();
                }),
            ),
            (
                "key_id too long",
                Box::new(|inputs| {
                    inputs.key_id = "k".repeat(IDENTITY_MAX + 1);
                }),
            ),
        ];
        for (name, mutate) in cases {
            let mut inputs = valid_inputs();
            mutate(&mut inputs);
            assert!(
                mint_watchdog_fallback_envelope(&inputs, &TEST_SIGNING_KEY).is_err(),
                "bad field case unexpectedly minted: {name}"
            );
        }
    }

    #[test]
    fn maximal_envelope_fits_the_imported_cap() {
        let signed =
            mint_watchdog_fallback_envelope(&maximal_inputs(), &TEST_SIGNING_KEY).expect("mint");
        let bytes = eliot_receipts::canonical_json_bytes(&signed).expect("canonical bytes");
        assert!(
            bytes.len() <= WATCHDOG_FALLBACK_ENVELOPE_MAX_BYTES,
            "maximal envelope is {} bytes, above the {WATCHDOG_FALLBACK_ENVELOPE_MAX_BYTES}-byte cap",
            bytes.len()
        );
    }

    #[test]
    fn publish_round_trip_writes_canonical_bytes_and_returns_digest() {
        let signed =
            mint_watchdog_fallback_envelope(&valid_inputs(), &TEST_SIGNING_KEY).expect("mint");
        let dir = unique_test_dir("publish");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("watchdog-fallback-envelope.json");
        let digest = publish_watchdog_fallback_envelope(&path, &signed).expect("publish");
        let on_disk = std::fs::read(&path).expect("read published file");
        let canonical = eliot_receipts::canonical_json_bytes(&signed).expect("canonical bytes");
        assert_eq!(on_disk, canonical);
        assert_eq!(digest, eliot_receipts::sha256_hex(&canonical));
        let decoded: SignedWatchdogFallbackEnvelope =
            serde_json::from_slice(&on_disk).expect("decode published envelope");
        assert_eq!(decoded, signed);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn publish_rejects_oversized_envelopes() {
        // Bypass mint validation with a directly built oversized envelope:
        // every handle passes `PlatformHandle` shape checks, only the byte
        // cap fails.
        let oversized = SignedWatchdogFallbackEnvelope {
            envelope: WatchdogFallbackEnvelope {
                incident_class: PlatformHandle::new("KERNEL_UNRESPONSIVE").expect("handle"),
                installation_identity: PlatformHandle::new("i".repeat(4096)).expect("handle"),
                timestamp_ms: 1_755_000_000_000,
                evidence_digest: "ab".repeat(32),
                recovery_instruction: RecoveryInstruction::EliotRecoveryStatus,
            },
            algorithm: WATCHDOG_SIGNATURE_ALGORITHM.to_owned(),
            key_id: PlatformHandle::new("watchdog-fallback-key-1").expect("handle"),
            domain: WATCHDOG_SIGNATURE_DOMAIN.to_owned(),
            signature: "00".repeat(64),
        };
        let dir = unique_test_dir("oversized");
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("watchdog-fallback-envelope.json");
        let result = publish_watchdog_fallback_envelope(&path, &oversized);
        assert!(
            matches!(
                result,
                Err(WatchdogFallbackMintError::EnvelopeTooLarge { .. })
            ),
            "oversized envelope unexpectedly published: {result:?}"
        );
        assert!(!path.exists());
        let _ = std::fs::remove_dir(&dir);
    }
}
