//! Watchdog fallback composition call-in (W3/W5).
//!
//! This module is the Watchdog's production producer of the minimal signed
//! fallback envelope. [`publish_control_loss_fallback`] runs on the runtime's
//! real control-loss event — the same bounded gap the Watchdog already durably
//! records in its own spool — and mints and publishes the five-field envelope
//! through the existing minter
//! ([`crate::watchdog_fallback_envelope`]).
//!
//! Contract (I11.6:3): the fallback envelope is produced by Watchdog. Content
//! (I11.6:17): the fixed five-field set — incident class, installation
//! identity, timestamp, evidence digest, and `eliot recovery status`
//! instruction. The envelope contains no secrets, no project content, and no
//! large evidence, and grants no repair authority: the recovery instruction
//! passes through display-only, and this module never adds repair semantics.
//!
//! Key custody: this module never PROVISIONS a key. The installer key ceremony
//! writes the protected binding record and the Watchdog only ever reads it
//! through a verified protected lease ([`ProtectedFallbackKeyBinding`]). The
//! secret is used for one mint and never logged, echoed into an error, a
//! receipt, or a log line. An all-zero secret fails closed as
//! [`FallbackCompositionError::InvalidKey`], and a secret that does not derive
//! the installer-pinned public key fails closed as
//! [`FallbackCompositionError::KeyBindingMismatch`].
//!
//! Two seams mirror the existing `export_driver` pattern: the
//! [`FallbackPublishEffects`] seam around minting/publishing and the
//! [`ControlLossFallbackBinding`] seam around the installer-owned material.
//! The live implementations are [`LiveFallbackEffects`] and
//! [`ProtectedFallbackKeyBinding`].
//!
//! Path policy: the publish destination is the protected
//! [`WATCHDOG_FALLBACK_ENVELOPE_RELATIVE`] the installed consumer reads, resolved
//! through the platform protected-`ProgramData` contour. No ambient authority
//! is read: no environment, no loader path, no current-exe inference.
//!
//! Freshness: validated locally against the policy-owner constants
//! [`WATCHDOG_FALLBACK_FRESHNESS_MS`] and [`WATCHDOG_FALLBACK_CLOCK_SKEW_MS`]
//! imported from `eliot-notify-core` (no local redefinition).

use std::path::Path;

use ed25519_dalek::SigningKey;
use eliot_notify_core::{
    SignedWatchdogFallbackEnvelope, WATCHDOG_FALLBACK_CLOCK_SKEW_MS, WATCHDOG_FALLBACK_FRESHNESS_MS,
};
use eliot_platform_windows::{ProtectedPathLease, protected_program_data_path};
use thiserror::Error;

use crate::watchdog_fallback_envelope::{
    WatchdogFallbackMintError, WatchdogFallbackMintInputs, mint_watchdog_fallback_envelope,
    publish_watchdog_fallback_envelope,
};
use crate::{GapRecoveryDisposition, GapRecoveryReason};

/// Protected relative destination the `eliot-notify` fallback route reads.
///
/// Mirrors `eliot_notify::FALLBACK_ENVELOPE_RELATIVE`; the Watchdog must not
/// depend on the notify binary crate (dependency direction), so the same
/// installed path is pinned here and the consumer's own protected-lease load
/// is the independent check. Any divergence fails closed on the consumer.
pub const WATCHDOG_FALLBACK_ENVELOPE_RELATIVE: &str =
    "Eliot/notify/watchdog-fallback-envelope.json";

/// Protected relative record holding the installer-ceremony key binding the
/// Watchdog needs to mint a fallback envelope.
///
/// The record is written by the installer key ceremony, never by this process:
/// the Watchdog only ever reads it through a verified protected lease, and an
/// absent record fails closed (the control-loss evidence then stays durable in
/// the Watchdog spool, which is exactly what I11.6:19 requires).
pub const WATCHDOG_FALLBACK_KEY_RELATIVE: &str = "Eliot/watchdog/watchdog-fallback-key.json";

/// Installer-owned fallback verification declaration read by the notify
/// fallback route. The producer reads only its public half to prove that the
/// secret it holds derives the key the consumer will accept.
pub const NOTIFY_FALLBACK_DECLARATION_RELATIVE: &str = "Eliot/notify/watchdog-verification.json";

/// Upper bound for each protected record read. Both are small fixed-field
/// documents; anything larger fails closed before parsing.
const FALLBACK_RECORD_BYTES_LIMIT: u64 = 64 * 1024;

/// Plain caller-supplied inputs for one mint-and-publish call.
///
/// `signing_key` is caller-supplied per call and never stored: provisioning
/// is owned by the installer ceremony (see module docs). The borrow ends with
/// the call.
#[derive(Debug)]
pub struct FallbackMintInput<'a> {
    /// `SCREAMING_SNAKE_CASE` incident class; bounds enforced by the minter.
    pub incident_class: String,
    /// Owning installation identity; must equal `installation_identity_expected`.
    pub installation_identity: String,
    /// Independently expected installation identity (admission binding echo).
    pub installation_identity_expected: String,
    /// Host-clock timestamp, milliseconds since Unix epoch; must be >= 0 and
    /// inside the imported freshness/skew window around `clock_now_ms`.
    pub timestamp_ms: i64,
    /// Evidence binding: exactly 64 lowercase-hex chars; bounds enforced by
    /// the minter.
    pub evidence_digest: String,
    /// Installer-bound key id selecting the verification key.
    pub key_id: String,
    /// Caller-supplied 32-byte Watchdog secret; never stored, never logged.
    /// Provisioning is owned by the installer ceremony follow-up.
    pub signing_key: &'a [u8; 32],
    /// Owner-clock now, milliseconds since Unix epoch, for the local
    /// freshness check.
    pub clock_now_ms: u64,
    /// Caller-resolved ABSOLUTE publish destination. This module resolves no
    /// path of its own.
    pub destination: std::path::PathBuf,
}

/// Stable publish receipt. Carries no secret or key material: only the
/// readback-verified envelope digest, the destination echo, and the envelope
/// timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackPublishReceipt {
    /// Lowercase-hex SHA-256 of the published canonical bytes.
    pub envelope_digest: String,
    /// Echo of the caller-supplied destination the bytes were written to.
    pub published_path: std::path::PathBuf,
    /// Envelope timestamp that was minted and published.
    pub timestamp_ms: i64,
}

/// Fail-closed composition failure. No variant carries key or secret
/// material.
#[derive(Debug, Error)]
pub enum FallbackCompositionError {
    #[error("fallback timestamp is stale")]
    StaleTimestamp,
    #[error("fallback timestamp is too far in the future")]
    FutureTimestampSkew,
    #[error("fallback timestamp is invalid")]
    InvalidTimestamp,
    #[error("installation identity does not match the expected binding")]
    IdentityMismatch,
    #[error("signing key is unusable")]
    InvalidKey,
    #[error("fallback publish destination is not an absolute path")]
    InvalidDestination,
    #[error("fallback mint failed: {0}")]
    MintFailed(String),
    #[error("fallback publish failed: {0}")]
    PublishFailed(String),
    /// The installer-ceremony key binding is absent, unreadable, or malformed.
    #[error("fallback key binding is unavailable")]
    KeyBindingUnavailable,
    /// The held secret does not derive the installer-pinned public key, or the
    /// binding disagrees with the consumer's pinned declaration.
    #[error("fallback key binding does not match the pinned public key")]
    KeyBindingMismatch,
}

/// Injected mint/publish seam. The live implementation calls the real minter
/// functions; callers (including tests) inject a fake through this trait.
/// Implementations must not load, store, or provision keys.
pub trait FallbackPublishEffects {
    /// Mints the signed envelope with the caller-supplied secret.
    ///
    /// # Errors
    ///
    /// Returns [`WatchdogFallbackMintError`] when any field violates its cap
    /// or canonical serialization fails.
    fn mint(
        &self,
        inputs: &WatchdogFallbackMintInputs,
        signing_key: &[u8; 32],
    ) -> Result<SignedWatchdogFallbackEnvelope, WatchdogFallbackMintError>;

    /// Publishes the signed envelope to the caller-supplied ABSOLUTE path and
    /// returns the readback-verified digest.
    ///
    /// # Errors
    ///
    /// Returns [`WatchdogFallbackMintError`] when serialization, the byte cap,
    /// or the write/readback fails.
    fn publish(
        &self,
        destination: &Path,
        signed: &SignedWatchdogFallbackEnvelope,
    ) -> Result<String, WatchdogFallbackMintError>;
}

/// Live effects: delegates directly to the existing minter functions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LiveFallbackEffects;

impl FallbackPublishEffects for LiveFallbackEffects {
    fn mint(
        &self,
        inputs: &WatchdogFallbackMintInputs,
        signing_key: &[u8; 32],
    ) -> Result<SignedWatchdogFallbackEnvelope, WatchdogFallbackMintError> {
        mint_watchdog_fallback_envelope(inputs, signing_key)
    }

    fn publish(
        &self,
        destination: &Path,
        signed: &SignedWatchdogFallbackEnvelope,
    ) -> Result<String, WatchdogFallbackMintError> {
        publish_watchdog_fallback_envelope(destination, signed)
    }
}

/// Mints and publishes one fallback envelope through the injected effects.
///
/// Steps: (1) reject an unusable key fail-closed (all-zero secret); (2)
/// require the installation identity to equal the expected binding; (3)
/// validate the timestamp against the imported freshness/skew window around
/// `input.clock_now_ms`; (4) require an absolute caller-supplied destination;
/// (5) mint via the effects seam; (6) publish via the effects seam and return
/// the stable receipt. The recovery instruction passes through display-only;
/// no repair authority is added.
///
/// # Errors
///
/// Returns [`FallbackCompositionError`] fail-closed on a stale, future, or
/// negative timestamp, an identity mismatch, an unusable key, a relative
/// destination, or a mint/publish failure. Errors never echo secret material.
pub fn mint_and_publish_fallback(
    input: FallbackMintInput<'_>,
    effects: &impl FallbackPublishEffects,
) -> Result<FallbackPublishReceipt, FallbackCompositionError> {
    if input.signing_key == &[0u8; 32] {
        return Err(FallbackCompositionError::InvalidKey);
    }
    if input.installation_identity != input.installation_identity_expected {
        return Err(FallbackCompositionError::IdentityMismatch);
    }
    if input.timestamp_ms < 0 {
        return Err(FallbackCompositionError::InvalidTimestamp);
    }
    let timestamp = u64::try_from(input.timestamp_ms)
        .map_err(|_| FallbackCompositionError::InvalidTimestamp)?;
    if timestamp <= input.clock_now_ms {
        let age = input.clock_now_ms.saturating_sub(timestamp);
        if age > WATCHDOG_FALLBACK_FRESHNESS_MS {
            return Err(FallbackCompositionError::StaleTimestamp);
        }
    } else {
        let future = timestamp.saturating_sub(input.clock_now_ms);
        if future > WATCHDOG_FALLBACK_CLOCK_SKEW_MS {
            return Err(FallbackCompositionError::FutureTimestampSkew);
        }
    }
    if !input.destination.is_absolute() {
        return Err(FallbackCompositionError::InvalidDestination);
    }
    let mint_inputs = WatchdogFallbackMintInputs {
        incident_class: input.incident_class,
        installation_identity: input.installation_identity,
        evidence_digest: input.evidence_digest,
        timestamp_ms: input.timestamp_ms,
        key_id: input.key_id,
    };
    let signed = effects
        .mint(&mint_inputs, input.signing_key)
        .map_err(|error| FallbackCompositionError::MintFailed(error.to_string()))?;
    let envelope_digest = effects
        .publish(&input.destination, &signed)
        .map_err(|error| FallbackCompositionError::PublishFailed(error.to_string()))?;
    Ok(FallbackPublishReceipt {
        envelope_digest,
        published_path: input.destination,
        timestamp_ms: input.timestamp_ms,
    })
}

/// Installer-owned material the Watchdog needs to mint one fallback envelope.
///
/// This is the `export_driver`-style boundary: the trait is the seam, the live
/// implementation below reads the protected records, and the production caller
/// is [`publish_control_loss_fallback`] on the Watchdog runtime's control-loss
/// path. It exists so the runtime never touches a path constant, a clock, or a
/// key outside this one boundary.
pub trait ControlLossFallbackBinding {
    /// Owning installation identity declared by the key ceremony.
    fn installation_identity(&self) -> &str;
    /// Installer-bound key id the envelope names.
    fn key_id(&self) -> &str;
    /// Installer-pinned lowercase-hex public key the consumer will verify
    /// against.
    fn public_key(&self) -> &str;
    /// The raw 32-byte Watchdog secret, derived only for the duration of one
    /// mint and never retained, logged, or echoed.
    ///
    /// # Errors
    ///
    /// Returns [`FallbackCompositionError`] when the held material cannot
    /// produce a usable Ed25519 secret.
    fn signing_key(&self) -> Result<[u8; 32], FallbackCompositionError>;
    /// Absolute publish destination the notify fallback route reads.
    fn destination(&self) -> std::path::PathBuf;
}

/// Reads the installer-ceremony key binding from the protected contour.
///
/// The record is `installation_identity`, `key_id`, `public_key`, and
/// `signing_key`, each a bounded non-blank identity or a 64-character
/// lowercase-hex value. Two independent bindings are proved before any secret
/// is used:
///
/// - the secret must derive exactly the declared `public_key`; and
/// - the declared `public_key` must equal the `public_key` the installed
///   notify fallback route verifies against in its own installer-pinned
///   declaration, whose `key_id` and `installation_identity` must match too.
///
/// A substituted, foreign, or partially rewritten record therefore cannot mint
/// an envelope the installed consumer would accept, and an absent record fails
/// closed without touching the filesystem for writing.
pub struct ProtectedFallbackKeyBinding {
    installation_identity: String,
    key_id: String,
    public_key: String,
    signing_key: [u8; 32],
    destination: std::path::PathBuf,
}

impl ProtectedFallbackKeyBinding {
    /// Loads and proves the installer-ceremony binding.
    ///
    /// # Errors
    ///
    /// Returns [`FallbackCompositionError::KeyBindingUnavailable`] when either
    /// protected record is absent, unreadable, oversized, or not the exact
    /// bounded shape, and [`FallbackCompositionError::KeyBindingMismatch`] when
    /// the two records disagree or the secret does not derive the pinned public
    /// key.
    pub fn load() -> Result<Self, FallbackCompositionError> {
        let key_record = read_protected_record(WATCHDOG_FALLBACK_KEY_RELATIVE)?;
        let declaration = read_protected_record(NOTIFY_FALLBACK_DECLARATION_RELATIVE)?;
        let installation_identity = bounded_identity_field(&key_record, "installation_identity")?;
        let key_id = bounded_identity_field(&key_record, "key_id")?;
        let public_key = hex_field(&key_record, "public_key")?;
        let signing_key = decode_hex_32(&hex_field(&key_record, "signing_key")?)?;
        if bounded_identity_field(&declaration, "installation_identity")? != installation_identity
            || bounded_identity_field(&declaration, "key_id")? != key_id
            || hex_field(&declaration, "public_key")? != public_key
        {
            return Err(FallbackCompositionError::KeyBindingMismatch);
        }
        let derived = SigningKey::from_bytes(&signing_key)
            .verifying_key()
            .to_bytes();
        if derived
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            != public_key
        {
            return Err(FallbackCompositionError::KeyBindingMismatch);
        }
        Ok(Self {
            installation_identity,
            key_id,
            public_key,
            signing_key,
            destination: protected_program_data_path(WATCHDOG_FALLBACK_ENVELOPE_RELATIVE)
                .map_err(|_| FallbackCompositionError::KeyBindingUnavailable)?,
        })
    }
}

impl ControlLossFallbackBinding for ProtectedFallbackKeyBinding {
    fn installation_identity(&self) -> &str {
        &self.installation_identity
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_key(&self) -> &str {
        &self.public_key
    }

    fn signing_key(&self) -> Result<[u8; 32], FallbackCompositionError> {
        Ok(self.signing_key)
    }

    fn destination(&self) -> std::path::PathBuf {
        self.destination.clone()
    }
}

/// Reads one bounded protected record and decodes it as a JSON object.
fn read_protected_record(
    relative: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, FallbackCompositionError> {
    let path = protected_program_data_path(relative)
        .map_err(|_| FallbackCompositionError::KeyBindingUnavailable)?;
    let lease = ProtectedPathLease::open_existing_absolute(&path)
        .map_err(|_| FallbackCompositionError::KeyBindingUnavailable)?;
    lease
        .verify_stable_identity()
        .and_then(|()| lease.verify_path_identity())
        .map_err(|_| FallbackCompositionError::KeyBindingUnavailable)?;
    let bytes = lease
        .read_bounded(FALLBACK_RECORD_BYTES_LIMIT)
        .map_err(|_| FallbackCompositionError::KeyBindingUnavailable)?;
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        _ => Err(FallbackCompositionError::KeyBindingUnavailable),
    }
}

/// Reads one bounded, non-blank, control-free identity field.
fn bounded_identity_field(
    record: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<String, FallbackCompositionError> {
    let value = record
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(FallbackCompositionError::KeyBindingUnavailable)?;
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(FallbackCompositionError::KeyBindingUnavailable);
    }
    Ok(value.to_owned())
}

/// Reads one exact 64-character lowercase-hex field.
fn hex_field(
    record: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<String, FallbackCompositionError> {
    let value = record
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(FallbackCompositionError::KeyBindingUnavailable)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(FallbackCompositionError::KeyBindingUnavailable);
    }
    Ok(value.to_owned())
}

/// Decodes one already-validated 64-character lowercase-hex field into the
/// exact 32 secret bytes. The length and alphabet were checked by
/// [`hex_field`]; anything unexpected here still fails closed.
fn decode_hex_32(value: &str) -> Result<[u8; 32], FallbackCompositionError> {
    let mut out = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(FallbackCompositionError::KeyBindingUnavailable)?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(FallbackCompositionError::KeyBindingUnavailable)?;
        out[index] = u8::try_from((high << 4) | low)
            .map_err(|_| FallbackCompositionError::KeyBindingUnavailable)?;
    }
    Ok(out)
}

/// Maps one observed control-loss gap onto its fixed `SCREAMING_SNAKE_CASE`
/// incident class.
///
/// I11.6:17 bounds the envelope to an incident class, an installation
/// identity, a timestamp, an evidence digest, and the fixed recovery
/// instruction. The class is drawn from this closed table so no free text, no
/// project content, and no secret can ever enter the envelope. The mapping is
/// total, so an unrecognised reason still produces a valid class rather than an
/// unminted envelope.
#[must_use]
pub fn incident_class_for(reason: GapRecoveryReason) -> &'static str {
    match reason {
        GapRecoveryReason::AdmissionUnavailable => "CONTROL_LOSS_ADMISSION_UNAVAILABLE",
        GapRecoveryReason::LeaseStale => "CONTROL_LOSS_LEASE_STALE",
        GapRecoveryReason::LeaseInvalid => "CONTROL_LOSS_LEASE_INVALID",
        GapRecoveryReason::LeaseFenced => "CONTROL_LOSS_LEASE_FENCED",
        GapRecoveryReason::HostAbsentOrStopped => "CONTROL_LOSS_HOST_ABSENT",
        GapRecoveryReason::HostPidReused => "CONTROL_LOSS_HOST_PID_REUSED",
        GapRecoveryReason::HostImageSubstituted => "CONTROL_LOSS_HOST_IMAGE_SUBSTITUTED",
        GapRecoveryReason::HostIdentityChanged => "CONTROL_LOSS_HOST_IDENTITY_CHANGED",
        GapRecoveryReason::HostUnknown => "CONTROL_LOSS_HOST_UNKNOWN",
        GapRecoveryReason::SpoolPressure => "CONTROL_LOSS_SPOOL_PRESSURE",
    }
}

/// Derives the control-loss evidence digest from the durable gap record.
///
/// The digest is the canonical-bytes digest of the exact
/// [`GapRecoveryDisposition`] the Watchdog appended to its own spool, so the
/// envelope's evidence field points at real retained control-loss evidence
/// instead of an invented value. It carries no payload text: the disposition is
/// the fixed record type, service name, timestamp, reason code, and the
/// `coverage_claimed: false` flag.
fn control_loss_evidence_digest(
    disposition: &GapRecoveryDisposition,
) -> Result<String, FallbackCompositionError> {
    let bytes = eliot_receipts::canonical_json_bytes(disposition)
        .map_err(|error| FallbackCompositionError::MintFailed(error.to_string()))?;
    Ok(eliot_receipts::sha256_hex(&bytes))
}

/// Mints and publishes the signed minimal envelope for one observed control
/// loss.
///
/// This is the Watchdog's production producer path (I11.6:9-11, "control-loss
/// fallback: Watchdog spool + Windows Event Log -> signed minimal envelope").
/// It runs on the runtime's real control-loss event, after the Watchdog has
/// durably recorded the bounded gap observation, and it is the only caller of
/// [`mint_and_publish_fallback`] outside tests.
///
/// The envelope is the closed five-field set: incident class (from the closed
/// table above), installation identity (proved equal to the runtime's admitted
/// installation), timestamp (the observation clock), evidence digest (the
/// canonical digest of the retained gap record), and the fixed
/// `eliot recovery status` instruction. It contains no secret, no project
/// content, and no large evidence, and it grants no repair authority.
///
/// # Errors
///
/// Returns [`FallbackCompositionError`] fail-closed when the installer key
/// binding is absent or inconsistent with the consumer's pinned declaration, or
/// when minting or publishing fails. No variant carries key material.
pub fn publish_control_loss_fallback(
    disposition: &GapRecoveryDisposition,
    admitted_installation_id: &str,
    binding: &impl ControlLossFallbackBinding,
    effects: &impl FallbackPublishEffects,
    clock_now_ms: u64,
) -> Result<FallbackPublishReceipt, FallbackCompositionError> {
    if admitted_installation_id.trim().is_empty() {
        return Err(FallbackCompositionError::IdentityMismatch);
    }
    let timestamp_ms =
        i64::try_from(clock_now_ms).map_err(|_| FallbackCompositionError::InvalidTimestamp)?;
    mint_and_publish_fallback(
        FallbackMintInput {
            incident_class: incident_class_for(disposition.reason).to_owned(),
            installation_identity: binding.installation_identity().to_owned(),
            installation_identity_expected: admitted_installation_id.to_owned(),
            timestamp_ms,
            evidence_digest: control_loss_evidence_digest(disposition)?,
            key_id: binding.key_id().to_owned(),
            signing_key: &binding.signing_key()?,
            clock_now_ms,
            destination: binding.destination(),
        },
        effects,
    )
}
