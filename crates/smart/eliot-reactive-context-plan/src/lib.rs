//! Pure planning of one bounded reactive Context injection.
//!
//! The planner consumes immutable A-15, A-10, session, Attention, coverage
//! and policy projections. It emits an inert downstream request or a complete
//! no-injection accounting record. It performs no I/O, delivery, receipt
//! issuance, session mutation, authority grant or Attention resolution.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err, clippy::large_enum_variant)]

mod bridge_admission;
mod compiler;
mod input;
mod plan;
mod result;
mod retrieval_plan;
mod settled_plan_feed;

pub use bridge_admission::{
    BridgeAdmissionBatch, BridgeAdmissionDelivery, BridgeAdmissionError,
    BridgeAdmissionInstruction, BridgeAdmissionSeverity, MAX_BRIDGE_RELATIONS,
    plan_bridge_admissions,
};

pub use compiler::{CampaignQueryParts, PlanParts, compile_retrieval_plan};

pub use input::{
    AttentionDisclosureRule, ReactiveCueActivation, ReactiveDeliveryPolicy, ReactiveTargetBinding,
};
pub use plan::plan_pending_context_injection;
pub use result::{
    ActivationEvidenceKind, DeliveryDisposition, InertDeliveryRequest, NoInjectionDisposition,
    PendingContextInjectionPlan, PlannedAttentionBinding, PlannedContextItem, PlannedItemKind,
    PlanningAccounting, PlanningErrorDisposition, PlanningErrorKind, ReactiveContextPlanResult,
    ReactiveContextPlanningError,
};
pub use retrieval_plan::{
    CampaignBudgets, CampaignExperienceQuery, CampaignIntent, CampaignOutputMode,
    RetrievalPlan, RetrievalRouteKind, RouteExecution, RouteExecutionOrder, SourceProjectionFence,
    MAX_PLAN_HANDLES, MAX_PLAN_ROUTES, MAX_PLAN_TEXT_CHARS,
};
pub use settled_plan_feed::{
    LiveActivationBindings, SettledPlanFeed, SettledPlanFeedError, SettledPlanFeedInputs,
    SettledPlanFeedOutcome, drive_live_feed, produce_settled_plan_feed,
};
