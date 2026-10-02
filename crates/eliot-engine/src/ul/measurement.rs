//! The one #783 Source-Token-Unit estimator for every UL consumer.
//!
//! `crates/eliot-types` used to own `ul_token_estimate`, whose body was a local
//! `(len + 3) / 4`. That is a second byte-to-token ratio beside the normative
//! `STU(bytes) = ceil(UTF-8 bytes / 3)` owned solely by #704 in
//! [`eliot_context_measurement::stu_for_bytes`], and because the ratio differs
//! it changed real admission outcomes: `ul_token_estimate` gates
//! `PACKET_PYRAMID_BUDGET` in the MCP packet builder and bounds every pyramid
//! artifact in [`crate::ul::capsule`].
//!
//! This module is the estimator's new home rather than a new estimator: the
//! ratio is not restated here. Every value is produced by calling #704's owner
//! directly, so the division lives in exactly one crate. `eliot-types` cannot
//! call #704 -- it is a contract hub that six packages depend on and the frozen
//! owner map confines #704's implementation to
//! `crates/smart/eliot-context-measurement/src/{stu.rs,lib.rs}` -- so the
//! estimator sits in the nearest layer that already declares that dependency
//! (see `crates/eliot-engine/Cargo.toml`).
//!
//! [`stu_for_bytes`] returns [`ContextError`], not a saturating count, because
//! a byte length that cannot be rounded without overflowing has no representable
//! estimate. That refusal is propagated to the caller rather than degraded to
//! `u32::MAX`, which would let an unmeasurable payload read as a finite budget
//! cost.

use crate::EngineError;
use eliot_context_contracts::ContextError;
use eliot_context_measurement::stu_for_bytes;

/// Canonical `STU(bytes) = ceil(UTF-8 bytes / 3)` for one in-memory payload.
///
/// The input is measured as its exact UTF-8 byte length, which is what a
/// `&str` already carries; no character count and no separate encoding step is
/// involved, so a multi-byte character contributes the bytes it occupies.
#[must_use]
pub fn ul_token_estimate(text: &str) -> Result<u32, EngineError> {
    let bytes = u64::try_from(text.len()).map_err(|_| ContextError::Overflow)?;
    ul_token_estimate_for_bytes(bytes)
}

/// Canonical estimate for an already-counted UTF-8 byte length.
///
/// Used where a caller observes exact serialized bytes (a tool's measured
/// input/output, a sum of ledger byte counters) rather than holding the text.
#[must_use]
pub fn ul_token_estimate_for_bytes(bytes: u64) -> Result<u32, EngineError> {
    let units = stu_for_bytes(bytes)?;
    Ok(u32::try_from(units).map_err(|_| ContextError::Overflow)?)
}

#[cfg(test)]
mod tests {
    use super::{ul_token_estimate, ul_token_estimate_for_bytes};
    use crate::EngineError;
    use eliot_context_contracts::ContextError;
    use eliot_context_measurement::stu_for_bytes;

    /// The positive discriminator for #783.
    ///
    /// The payload is 20 three-byte UTF-8 characters, so its UTF-8 byte length
    /// is 60 while its character count is 20. Measuring bytes is what widens
    /// the gap against the retired local `ceil(bytes / 4)`: the canonical
    /// value is 20 and the retired expression would have returned 15, so this
    /// assertion cannot pass against the old implementation. A character-count
    /// estimator would instead return 5, so it cannot pass either.
    #[test]
    fn multi_byte_payload_measures_the_canonical_thirds_not_quarters() {
        let payload = "\u{00e9}".repeat(20);
        assert_eq!(payload.chars().count(), 20);
        assert_eq!(payload.len(), 60);

        let units = ul_token_estimate(&payload).expect("a 60-byte payload is measurable");
        assert_eq!(units, 20);
        assert_eq!(ul_token_estimate_for_bytes(60).expect("measurable"), 20);
        assert_ne!(units, 60_u32.div_ceil(4), "the retired /4 ratio is still live");
        assert_ne!(units, 20_u32.div_ceil(4), "a character count is not a byte length");
    }

    /// The refusal discriminator for #783.
    ///
    /// #704's `stu_for_bytes` adds a rounding term of two with
    /// [`u64::checked_add`], so a byte length that cannot absorb that term has
    /// no representable estimate and must refuse with
    /// [`ContextError::Overflow`] rather than wrap or saturate. That refusal
    /// has to reach the caller; degrading it to a `u32::MAX` would let an
    /// unmeasurable payload read as a finite budget cost.
    ///
    /// The reachable refusal is pinned at both layers this module owns. The
    /// owner's own rounding overflow refuses for `u64::MAX` and
    /// `u64::MAX - 1`; exactly one byte lower the term fits again, and that
    /// length is still refused here because its unit count passes `u32::MAX`,
    /// so the two refusal layers are asserted separately rather than merged.
    /// A `&str` input cannot reach either: its length is bounded by
    /// [`isize::MAX`], far below both boundaries.
    #[test]
    fn unrepresentable_byte_length_refuses_instead_of_saturating() {
        // #704's checked rounding term overflows for exactly these two.
        for unrepresentable in [u64::MAX, u64::MAX - 1] {
            assert!(
                matches!(
                    ul_token_estimate_for_bytes(unrepresentable),
                    Err(EngineError::ContextMeasurement(ContextError::Overflow))
                ),
                "byte length {unrepresentable} must refuse, not saturate"
            );
        }
        // One byte lower the owner's rounding term fits, so the owner accepts
        // it; this module still refuses, because the resulting unit count is
        // past `u32::MAX`. That separates the two refusal layers.
        assert!(
            matches!(
                ul_token_estimate_for_bytes(u64::MAX - 2),
                Err(EngineError::ContextMeasurement(ContextError::Overflow))
            ),
            "u64::MAX - 2 still exceeds u32::MAX units, so it must refuse"
        );

        // One byte past the largest representable `u32` unit count: the owner
        // rounds it fine, and this module's narrowing refuses it.
        let overflow_units = u64::from(u32::MAX) * 3 + 1;
        assert_eq!(
            stu_for_bytes(overflow_units).expect("owner rounds this"),
            u64::from(u32::MAX) + 1,
            "the refusal above is this module's narrowing, not the owner's"
        );
        assert!(matches!(
            ul_token_estimate_for_bytes(overflow_units),
            Err(EngineError::ContextMeasurement(ContextError::Overflow))
        ));

        // The largest length whose estimate is still representable keeps its
        // exact value, so the refusal above is a boundary and not a blanket
        // rejection of large inputs.
        assert_eq!(
            ul_token_estimate_for_bytes(overflow_units - 1).expect("still representable"),
            u32::MAX
        );
    }
}