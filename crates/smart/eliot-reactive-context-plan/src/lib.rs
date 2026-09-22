//! Pure planning of one bounded reactive Context injection.
//!
//! The planner consumes immutable A-15, A-10, session, Attention, coverage
//! and policy projections. It emits an inert downstream request or a complete
//! no-injection accounting record. It performs no I/O, delivery, receipt
//! issuance, session mutation, authority grant or Attention resolution.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err, clippy::large_enum_variant)]

mod bridge_admission;
mod input;
mod owner_retention;
mod owner_supply;
mod plan;
mod result;
mod settled_plan_feed;

pub use bridge_admission::{
    BridgeAdmissionBatch, BridgeAdmissionDelivery, BridgeAdmissionError,
    BridgeAdmissionInstruction, BridgeAdmissionSeverity, MAX_BRIDGE_RELATIONS,
    plan_bridge_admissions,
};

pub use input::{
    AttentionDisclosureRule, ReactiveCueActivation, ReactiveCueActivationParts,
    ReactiveDeliveryPolicy, ReactiveDeliveryPolicyParts, ReactiveTargetBinding,
    produce_reactive_cue_activation, produce_reactive_delivery_policy,
};
pub use owner_retention::{
    MAX_RETAINED_PROJECTION_SETS, ReactiveOwnerRetention, RestoredOwnerSnapshots,
    ingest_restored_projection_set,
};
pub use owner_supply::{
    MAX_OWNER_SNAPSHOT_BYTES, OwnerProjectionBytes, OwnerProjectionSet, OwnerSupplyError,
    read_owner_projection_set, supply_context_planning_view,
    supply_critical_attention_projection, supply_integration_coverage_profile,
    supply_reactive_cue_activation, supply_reactive_delivery_policy,
    supply_session_delivery_snapshot,
};
pub use plan::plan_pending_context_injection;
pub use result::{
    ActivationEvidenceKind, DeliveryDisposition, InertDeliveryRequest, NoInjectionDisposition,
    PendingContextInjectionPlan, PlannedAttentionBinding, PlannedContextItem, PlannedItemKind,
    PlanningAccounting, PlanningErrorDisposition, PlanningErrorKind, ReactiveContextPlanResult,
    ReactiveContextPlanningError,
};
pub use settled_plan_feed::{
    LiveActivationBindings, SettledPlanFeed, SettledPlanFeedError, SettledPlanFeedInputs,
    SettledPlanFeedOutcome, drive_live_feed, produce_settled_plan_feed,
};
