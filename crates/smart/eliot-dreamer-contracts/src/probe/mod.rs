//! Canonical A-03 declarations consumed by the pure A-17b probe planner.

pub mod affordance;
pub mod bounds;
pub mod objective;
pub mod result;
pub(crate) mod validation;

pub use affordance::{
    AffordanceSetStatus, INQUIRY_AFFORDANCE_SCHEMA_VERSION,
    INQUIRY_AFFORDANCE_SET_SCHEMA_VERSION, InquiryAffordanceDescriptor, InquiryAffordanceSet,
    ProbeEffectClass, ProbeEstimate, ProbeFeasibility, ProbeRequirementState, ProbeReversibility,
};
pub use bounds::{
    MAX_PROBE_BRANCHES, MAX_PROBE_ITEMS, MAX_PROBE_TEXT_BYTES, MAX_PROBE_UPDATES_PER_BRANCH,
    MAX_PROBE_WIRE_BYTES, PROBE_OBJECTIVE_SCHEMA_VERSION, PROBE_RESULT_SCHEMA_VERSION,
};
pub use objective::{
    ProbeObjective, ProbeObjectiveOrigin, ProbeObjectiveRef, ProbeObjectiveTarget, ProbeOwnerRef,
};
pub use result::{
    GapUpdateMeaning, PossibleResultSchema, PossibleResultValue, ResultBranch, ResultTarget,
    ResultUpdate, RivalUpdateMeaning,
};
