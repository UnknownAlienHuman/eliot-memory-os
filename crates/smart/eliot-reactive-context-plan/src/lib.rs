//! Pure planning of one bounded reactive Context injection.
//!
//! The planner consumes immutable A-15, A-10, session, Attention, coverage
//! and policy projections. It emits an inert downstream request or a complete
//! no-injection accounting record. It performs no I/O, delivery, receipt
//! issuance, session mutation, authority grant or Attention resolution.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err, clippy::large_enum_variant)]

mod input;
mod plan;
mod result;

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
