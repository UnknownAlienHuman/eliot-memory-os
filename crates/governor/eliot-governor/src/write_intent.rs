//! Governor-owned declaration of the stable write intent for each internal
//! semantic admission leg (issue #1925).
//!
//! [`I05-05-write-envelope.md`](../../../docs/architecture/I05-05-write-envelope.md)
//! gives `write_intent_id` exactly one purpose: the stable user/agent intent
//! across typed correction attempts. It is a THIRD, DISTINCT identity beside
//! `operation_id` (which rotates per attempt) and `idempotency_key` (which
//! rotates per correction, per
//! [`I06-08`](../../../docs/architecture/I06-08-contract-rejection.md)), so it
//! is never derived from either of them.
//!
//! The Governor admission legs in this crate are not user/agent envelope
//! submissions: each one is an internal semantic decision that commits exactly
//! one owner-issued subject (a committed record digest, an admitted candidate
//! digest, a revocation closure, a selection-chain head, a finish-evidence
//! snapshot, and so on). That subject IS the leg's stable intent. A typed
//! correction of the same leg re-derives the same subject and therefore the
//! same intent, while a corrected attempt under I6.8 still receives a new
//! operation identity, a new canonical request hash, and normally a new
//! idempotency key — so the three identities stay genuinely distinct.
//!
//! [`admission_write_intent`] is the ONE declaration used by every such leg. It
//! is domain-separated by leg name so two legs that happen to commit the same
//! subject never collide, and it refuses a blank leg or subject instead of
//! manufacturing one. It is deliberately not a default, not an `Option`, and
//! not a second identity type: the member itself remains the single owner
//! type, and this function only decides its text from the leg's own subject.
//!
//! The alternative paths stay separate and are NOT routed here: the atomic
//! all-absent genesis seed declares the absence of a user/agent intent through
//! [`eliot_store_api::GENESIS_STORE_SEED_WRITE_INTENT`], and a real
//! `VersionedWriteSubmission` takes the caller's value verbatim
//! ([`eliot_canonical::VersionedWriteSubmission::bind`]).

#![forbid(unsafe_code)]

use eliot_canonical::write_envelope::WRITE_ENVELOPE_PROTOCOL_VERSION;

/// Declares the stable write intent of one Governor admission leg.
///
/// This is a thin delegation, not a second derivation: the `write_intent_id`
/// member on `PreparedTransition` and the genesis exemption beside it are
/// owned by `eliot-store-api`, which is the only one of these boundary
/// crates the Kernel's own automation/notification/reactive/lifecycle legs
/// depend on, so the declaration of an intent belongs there. Those legs call
/// the SAME owner function; a Governor-local copy would be a second scheme
/// producing two different values for one leg.
///
/// # Errors
///
/// Returns `None` when `leg` or `subject` is blank or contains a control
/// character. The caller must then REFUSE the admission: a leg with no
/// owner-issued subject has no intent to declare, and substituting a
/// placeholder would make a missing owner value silently acceptable.
#[must_use]
pub fn admission_write_intent(leg: &str, subject: &str) -> Option<String> {
    eliot_store_api::admission_write_intent(leg, subject)
}

/// The write-envelope protocol revision these internal legs are admitted under.
///
/// Re-exported from the owning boundary so a Governor leg never names a
/// version literal of its own: `eliot-canonical` owns the exact supported
/// revision and refuses any other.
pub const GOVERNOR_ADMISSION_WRITE_ENVELOPE_PROTOCOL_VERSION: u32 = WRITE_ENVELOPE_PROTOCOL_VERSION;
