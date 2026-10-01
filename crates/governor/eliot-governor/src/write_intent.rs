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
// The workspace's ONE shared canonical encoder and digest helper. Reusing them
// keeps this declaration on the same byte-authority as every other owner
// digest, and adds no dependency edge to this crate.
use eliot_contracts::{canonical_json_bytes, sha256_hex};

/// Domain separator for every Governor admission-leg write intent.
///
/// Versioned with the derivation so a future change of spelling is a new
/// value, never a silent reinterpretation of a retained intent.
const ADMISSION_WRITE_INTENT_DOMAIN: &str = "eliot.governor.admission_write_intent.v1";

/// Declares the stable write intent of one Governor admission leg.
///
/// `leg` names the closed admission leg (for example
/// `"capability-evidence-commit"`) and `subject` is that leg's own
/// owner-issued, stable semantic subject: the exact committed record digest,
/// admitted candidate digest, closure identity, or chain head. The declared
/// value is stable across typed correction attempts of the same subject and is
/// domain-separated per leg, so it is never conflated with the per-attempt
/// `operation_id` or the per-correction `idempotency_key`.
///
/// # Errors
///
/// Returns `None` when `leg` or `subject` is blank or contains a control
/// character. The caller must then REFUSE the admission: a leg with no
/// owner-issued subject has no intent to declare, and substituting a
/// placeholder would make a missing owner value silently acceptable.
#[must_use]
pub fn admission_write_intent(leg: &str, subject: &str) -> Option<String> {
    if !is_declared_text(leg) || !is_declared_text(subject) {
        return None;
    }
    let shape = (ADMISSION_WRITE_INTENT_DOMAIN, leg, subject);
    // `canonical_json_bytes` cannot fail for this tuple of owned strings, so
    // the digest is total; a caller never sees a partially declared intent.
    let bytes = canonical_json_bytes(&shape).ok()?;
    Some(format!("governor-intent-{}", sha256_hex(&bytes)))
}

/// The write-envelope protocol revision these internal legs are admitted under.
///
/// Re-exported from the owning boundary so a Governor leg never names a
/// version literal of its own: `eliot-canonical` owns the exact supported
/// revision and refuses any other.
pub const GOVERNOR_ADMISSION_WRITE_ENVELOPE_PROTOCOL_VERSION: u32 = WRITE_ENVELOPE_PROTOCOL_VERSION;

fn is_declared_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_same_leg_and_subject_declare_the_same_stable_intent() {
        let first = admission_write_intent("capability-evidence-commit", "record-digest-1")
            .expect("declared leg and subject");
        let corrected = admission_write_intent("capability-evidence-commit", "record-digest-1")
            .expect("a typed correction of the same subject redeclares the same intent");
        assert_eq!(first, corrected);
        assert!(first.starts_with("governor-intent-"));
        assert_eq!(first.len(), "governor-intent-".len() + 64);
    }

    #[test]
    fn different_legs_and_different_subjects_declare_different_intents() {
        let base = admission_write_intent("leg-a", "subject-1").expect("declared");
        assert_ne!(
            base,
            admission_write_intent("leg-b", "subject-1").expect("declared"),
            "the leg name is domain-separated, so two legs never collide"
        );
        assert_ne!(
            base,
            admission_write_intent("leg-a", "subject-2").expect("declared"),
            "a different owner-issued subject is a different intent"
        );
    }

    #[test]
    fn a_blank_leg_or_subject_declares_nothing_rather_than_a_placeholder() {
        for (leg, subject) in [
            ("", "subject-1"),
            ("   ", "subject-1"),
            ("leg-a", ""),
            ("leg-a", "  "),
            ("leg\na", "subject-1"),
            ("leg-a", "subject\u{0}1"),
        ] {
            assert!(
                admission_write_intent(leg, subject).is_none(),
                "a leg with no owner-issued subject must refuse, got ({leg:?}, {subject:?})"
            );
        }
    }
}
