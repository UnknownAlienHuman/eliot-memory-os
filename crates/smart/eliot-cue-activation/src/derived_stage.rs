//! The typed disposition of the optional relation-derived activation stage.
//!
//! `I12.15` makes spreading activation a derived feature *after* an exact direct
//! cue. The two coverage domains are therefore independent: the direct domain is
//! required evidence, while relation evidence is optional material that may be
//! absent, stale, unqualified, or cut short by an admitted bound without that
//! changing the validity of an already completed direct result.
//!
//! These types carry that separation. A consumer reads the direct activations
//! and the direct completeness from the result, and reads every reason the
//! optional stage did not contribute from [`DerivedStage`]. An optional-stage
//! gap never becomes a direct-match absence, and a derived hit stays an advisory
//! retrieval signal: it is not a lease, a canonical truth claim, a task
//! completion, or a blocking disposition.

use eliot_cue_contracts::RelationEdgeId;
use serde::{Deserialize, Serialize};

/// Why the optional relation domain could not contribute.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum RelationCoverage {
    /// No relation evidence was published for this request. The direct domain
    /// is unaffected; there is simply no relation domain to expand.
    Absent,
    /// Published relation evidence is stale, revoked, or otherwise not current
    /// under the request's State Fence.
    NotCurrent,
    /// The relation-registry revision the profile admits is not the revision
    /// the published evidence carries.
    RegistryRevisionChanged,
    /// The profile admits no weight for at least one published relation kind,
    /// so that edge has no admissible direction or weight.
    KindNotAdmitted,
}

/// The typed disposition of the optional relation-derived stage.
///
/// Every variant is a statement about the optional domain only. None of them
/// retracts, weakens, or reclassifies a direct activation, and none of them is
/// a refusal of the whole evaluation: the direct result is preserved in every
/// case where the direct domain itself completed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum DerivedStage {
    /// The request forbids relation spreading. No relation evidence was
    /// required, acquired, validated, started, or rebuilt.
    Disabled,
    /// Relation spreading ran over the published relation evidence and stayed
    /// inside every admitted bound.
    Evaluated,
    /// The optional relation evidence could not be used. The completed direct
    /// result stands, and `unusable` names the supplied edges left un-followed
    /// so a resumable derivation still knows where it stopped.
    Unavailable {
        /// Why the optional domain could not contribute.
        reason: RelationCoverage,
        /// Supplied relation edges left un-followed for the typed reason.
        unusable: Vec<RelationEdgeId>,
    },
    /// The optional stage stopped at an admitted bound. The completed direct
    /// result, the derived hits already reached, and the un-followed frontier
    /// are all preserved rather than discarded.
    BoundReached {
        /// The admitted bound that stopped the optional stage.
        field: String,
    },
}
