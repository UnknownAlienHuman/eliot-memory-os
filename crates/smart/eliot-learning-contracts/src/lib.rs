//! Provider-neutral, candidate-only contracts for bounded online learning.
//!
//! This crate describes evidence and lineage. It deliberately does not own a
//! campaign aggregate, derive a result, invoke a provider, activate an
//! overlay, admit canonical state, or promote a generation.

#![forbid(unsafe_code)]

pub mod activation;
pub mod assessment;
pub mod closure;
pub mod delta;
pub mod error;
pub mod identity;
pub mod overlay;
pub mod state_view;

pub use activation::{
    HarnessActivationReceiptCandidate, LifecycleStage, MetricObservation, StageDisposition,
    StageObservation,
};
pub use assessment::{
    AssessmentDimension, CausalCeiling, DimensionAssessment, DimensionStatus,
    LearningAssessmentCandidate,
};
pub use closure::{ClosureHandoff, ExternalDecisionClass, OwnerProof};
pub use delta::{
    AttemptFailure, AttemptLearningDeltaCandidate, AttemptLearningOutcome, AttemptLearningResult,
    ChangeOperation, ChangeSurface, InverseChange, NoChangeDisposition, NoChangeReason, ValueState,
};
pub use error::LearningContractError;
pub use identity::{
    AgentAttemptId, CampaignId, ContractBinding, LearningTargetId, MemberId, OverlayId, OwnerId,
    ProofCeiling, SlotId, TargetId, WorkScopeId,
};
pub use overlay::{CampaignHarnessOverlayCandidate, OverlayChange, OverlayOrigin};
pub use state_view::{
    CampaignLearningStateView, Completeness, LearningStateViewRecipe, MemberProjection,
    OmissionPolicy, OwnerDisagreement, SlotDisposition, SlotProjection, SlotRequirement, SlotSpec,
    SourceDenominator,
};
