//! Pure, shared cue normalization for capture and firing.
//!
//! A-11 keeps observed spelling immutable and derives comparison keys only from
//! an explicit, bounded caller-supplied policy. It performs no I/O, matching,
//! admission, indexing, storage or authority decision.

#![forbid(unsafe_code)]

mod bounds;
mod error;
mod normalize;
mod policy;

pub use error::NormalizationError;
pub use normalize::{NormalizationEnvelope, PolicyBinding};
/// A-11 wire revision for policy and normalization envelopes.
pub const A11_CONTRACT_REVISION: &str = "1.0.0";

pub use policy::{
    CasePolicy, MAX_ALGORITHM_REFERENCE_BYTES, MAX_OWNER_REFERENCE_BYTES, MAX_POLICY_ID_BYTES,
    MAX_POLICY_RULES, NormalizationPolicy, NormalizationRule, PolicyRule, SeparatorPolicy,
};

pub use bounds::{MAX_INPUT_BYTES, MAX_KEYS, MAX_OUTPUT_BYTES, MAX_STEPS};

use eliot_cue_contracts::{NormalizationProfile, ObservedCue};

/// Normalizes one observed cue under one exact policy and profile binding.
pub fn normalize_cue(
    observed: &ObservedCue,
    policy: &NormalizationPolicy,
    profile: &NormalizationProfile,
) -> Result<NormalizationEnvelope, NormalizationError> {
    normalize::run(observed, policy, profile)
}

/// Capture-side entry point. It deliberately delegates to the shared operation.
pub fn capture_cue(
    observed: &ObservedCue,
    policy: &NormalizationPolicy,
    profile: &NormalizationProfile,
) -> Result<NormalizationEnvelope, NormalizationError> {
    normalize_cue(observed, policy, profile)
}

/// Fire-side entry point. It deliberately delegates to the shared operation.
pub fn fire_cue(
    observed: &ObservedCue,
    policy: &NormalizationPolicy,
    profile: &NormalizationProfile,
) -> Result<NormalizationEnvelope, NormalizationError> {
    normalize_cue(observed, policy, profile)
}
