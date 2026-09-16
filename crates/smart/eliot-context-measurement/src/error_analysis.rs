//! Independent two-direction error analysis over one shared capacity
//! identity.
//!
//! Only a compatible exact observation derives comparison: `estimated fit
//! AND observed overflow` is false-safe overflow, while `estimated
//! overflow/decompose AND observed fit` is false rejection or unnecessary
//! decomposition. Error sign alone proves neither direction, and a missing,
//! stale, mismatched, transformed or unknown observation leaves comparison
//! and both flags explicitly unknown.

/// Explicit zero-observation rule for relative error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZeroObservationRule {
    /// Relative error is unknown whenever the observed count is zero;
    /// no division ever runs, so a zero observation cannot panic or lie.
    RelativeErrorUnknownWhenObservedIsZero,
}

/// Signed/absolute/relative error with both operational error directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorAnalysis {
    /// Estimated fit echoed from capacity analysis.
    pub estimated_fit: Option<bool>,
    /// Observed fit echoed from capacity analysis.
    pub observed_fit: Option<bool>,
    /// `Some(true)` only for estimated fit with observed overflow.
    pub false_safe_overflow: Option<bool>,
    /// `Some(true)` only for estimated overflow with observed fit.
    pub false_reject_or_decomposition: Option<bool>,
    /// Estimated minus observed in the shared unit, when both are known.
    pub signed_error: Option<i128>,
    /// Absolute error in the shared unit, when both totals are known.
    pub absolute_error: Option<u128>,
    /// Parts-per-million relative error; `None` under the explicit
    /// zero-observation rule or when unrepresentable in [`u64`].
    pub relative_error_ppm: Option<u64>,
    /// The explicit zero-observation rule in force.
    pub zero_observation_rule: ZeroObservationRule,
}

/// Analyze error directions and magnitudes over one capacity identity.
///
/// Totals must already share the capacity unit and reserve identity; this
/// function compares them without reloading any policy or observation.
pub fn analyze_error(
    estimated_total: Option<u64>,
    estimated_fit: Option<bool>,
    observed_total: Option<u64>,
    observed_fit: Option<bool>,
) -> ErrorAnalysis {
    let (false_safe_overflow, false_reject_or_decomposition) =
        match (estimated_fit, observed_fit) {
            (Some(estimated), Some(observed)) => {
                (Some(estimated && !observed), Some(!estimated && observed))
            }
            _ => (None, None),
        };
    let (signed_error, absolute_error, relative_error_ppm) =
        match (estimated_total, observed_total) {
            (Some(estimated), Some(observed)) => {
                let signed = i128::from(estimated) - i128::from(observed);
                let absolute = signed.unsigned_abs();
                let relative = if observed == 0 {
                    None
                } else {
                    u64::try_from(
                        absolute.saturating_mul(1_000_000) / u128::from(observed),
                    )
                    .ok()
                };
                (Some(signed), Some(absolute), relative)
            }
            _ => (None, None, None),
        };
    ErrorAnalysis {
        estimated_fit,
        observed_fit,
        false_safe_overflow,
        false_reject_or_decomposition,
        signed_error,
        absolute_error,
        relative_error_ppm,
        zero_observation_rule: ZeroObservationRule::RelativeErrorUnknownWhenObservedIsZero,
    }
}
