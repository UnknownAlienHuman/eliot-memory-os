//! The advisory-use decision a consumer must make about derived activations.
//!
//! `I12.15` step 6 admits derived results into the candidate and Context
//! admission path as advisory retrieval signals. They may rank, suggest or
//! carry lineage. What they may not do is issue a lease, change canonical
//! truth, mark a task complete, suppress mandatory counterevidence, or block an
//! effect on their own strength.
//!
//! This module turns that rule into a decision a consumer can read rather than
//! a convention it has to remember. The distinction that matters is between
//! two coverage domains: a derived hit never substitutes for a direct one, and a
//! real negative-memory rule is checked on its own exact scope, trigger and
//! authority gate regardless of what the graph says.
//!
//! The four substitutions this exists to prevent are explicit:
//!
//! - advisory is *compared* with the actual result, not merely known because a
//!   derived vector is non-empty;
//! - a real safety rule is re-checked against its own gate, never inherited
//!   from a graph score;
//! - the decision is made from the owner-produced result plus its validated
//!   bindings, never from a structurally valid arbitrary output.

use eliot_cue_contracts::{ActivationResult, DirectActivation};
use serde::{Deserialize, Serialize};

/// What a consumer may do with one cue activation result.
///
/// The variants are dispositions, not suggestions. A consumer that cannot name
/// one of these for a result has no permitted use for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum CueUse {
    /// The result carries an exact direct hit. The exact cue is usable on its
    /// own evidence, and this stays true when optional spread is disabled,
    /// truncated or unqualified.
    DirectEvidence {
        /// How many direct activations the owner-produced result carries.
        direct_hits: usize,
    },
    /// The result carries derived activations only. It may rank or suggest; it
    /// is never a lease, a canonical truth claim, a completion, or a block.
    AdvisoryOnly {
        /// How many derived activations the owner-produced result carries.
        derived_hits: usize,
    },
    /// The owner-produced result carries no activation at all.
    NoCueEvidence,
}

/// The advisory-use decision for one validated result.
///
/// This is a projection of the result, not a new authority: it names what the
/// result may be used for and never re-derives, upgrades or discards a single
/// activation. The exact cue keeps its priority over any larger popular
/// neighborhood because the decision is taken from the direct vector, and a
/// derived-only result is advisory by construction.
#[must_use]
pub fn classify(result: &ActivationResult) -> CueUse {
    if !result.direct.is_empty() {
        return CueUse::DirectEvidence {
            direct_hits: result.direct.len(),
        };
    }
    if !result.derived.is_empty() {
        return CueUse::AdvisoryOnly {
            derived_hits: result.derived.len(),
        };
    }
    CueUse::NoCueEvidence
}

/// Whether a blocking admission or effect disposition is admissible for this
/// result, and on what evidence.
///
/// A derived-only result is never blocking. That is the whole point: the graph
/// score is not a blocking justification, so a disposition that blocks on it is
/// refused here rather than discovered later. A result with a direct hit may
/// block, and the returned activations are the exact evidence it would rest on;
/// this seam does not weaken that evidence or re-derive it.
#[must_use]
pub fn blocking_evidence(result: &ActivationResult) -> Option<&[DirectActivation]> {
    match classify(result) {
        CueUse::DirectEvidence { .. } => Some(&result.direct),
        CueUse::AdvisoryOnly { .. } | CueUse::NoCueEvidence => None,
    }
}

/// The exact direct activations a real safety rule would have to be checked
/// against, independent of any blocking decision.
///
/// A consumer that enforces a real safety rule reads the direct activations
/// themselves rather than a score. Returning them keeps that check anchored to
/// the exact owner result, and it is why a derived hit can never stand in for a
/// rule that already passed its own exact scope, trigger and authority gate.
#[must_use]
pub fn direct_activations(result: &ActivationResult) -> &[DirectActivation] {
    &result.direct
}
