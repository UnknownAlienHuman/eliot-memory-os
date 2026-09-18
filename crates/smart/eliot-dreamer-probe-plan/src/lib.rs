//! Bounded candidate-only discriminative probe planning for ELIOT Dreamer.
//!
//! Cell `smart.dreamer.probe_plan`, order 17. This crate is a pure planning
//! owner: it consumes a [`DreamInputBundle`], a [`ValidatedDreamDraft`], a
//! [`RivalModelSet`], a closed [`InquiryAffordanceSet`], and independent
//! [`BudgetLimits`], and emits a frozen [`ProbePlan`] of ranked
//! candidate-only [`ProbeProposal`] values plus explicit [`ProbeOmission`]
//! gaps. It executes no tool, reserves no route or budget, decides no
//! policy or authority, and grades no evidence: unauthorized, unfeasible, or
//! over-budget inquiries remain proposals or gaps only, never actions.

#![forbid(unsafe_code)]

mod bounds;
mod model;
mod plan;

pub use bounds::{
    MAX_PROBE_PLAN_ITEMS, MAX_PROBE_PLAN_MERGED, MAX_PROBE_PLAN_TEXT_BYTES,
    MAX_PROBE_PLAN_WIRE_BYTES, PROBE_PLAN_SCHEMA_VERSION,
};
pub use eliot_dreamer_contracts::ContractViolation;
pub use model::{
    OmissionKind, ProbeDimensions, ProbeOmission, ProbePlan, ProbePlanParams, ProbeProposal,
    ProbeTarget,
};

/// Re-exported contract inputs consumed by the planner.
pub use eliot_dreamer_contracts::{
    BudgetLimits, DreamInputBundle, InquiryAffordanceSet, RivalModelSet, ValidatedDreamDraft,
};
