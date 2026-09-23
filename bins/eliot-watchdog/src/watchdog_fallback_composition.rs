//! Watchdog fallback composition call-in (W3/W5).
//!
//! This module is the single production call-in that mints and publishes the
//! minimal signed fallback envelope via the existing minter
//! ([`crate::watchdog_fallback_envelope`]). It performs no key custody and no
//! destination resolution of its own.
//!
//! Contract (I11.6:3): the fallback envelope is produced by Watchdog. Content
//! (I11.6:17): the fixed five-field set — incident class, installation
//! identity, timestamp, evidence digest, and `eliot recovery status`
//! instruction. The envelope contains no secrets, no project content, and no
//! large evidence, and grants no repair authority: the recovery instruction
//! passes through display-only, and this module never adds repair semantics.
//!
//! Key provisioning: this module NEVER loads, stores, or provisions keys. The
//! caller supplies the raw 32-byte secret (`signing_key`) on every call and
//! must source it from the installer's protected binding; key provisioning
//! and ceremony are owned by the installer-ceremony follow-up. The secret is
//! held only as a borrow for the duration of the call, never retained, and
//! never echoed into errors, receipts, or logs. An all-zero secret fails
//! closed as [`FallbackCompositionError::InvalidKey`].
//!
//! Path policy: the caller supplies the ABSOLUTE destination path in
//! [`FallbackMintInput::destination`]. This module resolves no protected
//! `ProgramData` path and reads no ambient authority (no environment,
//! no current-exe inference).
//!
//! Freshness: validated locally against the policy-owner constants
//! [`WATCHDOG_FALLBACK_FRESHNESS_MS`] and [`WATCHDOG_FALLBACK_CLOCK_SKEW_MS`]
//! imported from `eliot-notify-core` (no local redefinition).

use std::path::Path;

use eliot_notify_core::{
    SignedWatchdogFallbackEnvelope, WATCHDOG_FALLBACK_CLOCK_SKEW_MS, WATCHDOG_FALLBACK_FRESHNESS_MS,
};
use thiserror::Error;

use crate::watchdog_fallback_envelope::{
    WatchdogFallbackMintError, WatchdogFallbackMintInputs, mint_watchdog_fallback_envelope,
    publish_watchdog_fallback_envelope,
};

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
