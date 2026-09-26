//! Provider-neutral, candidate-only contracts for bounded online learning.
//!
//! This crate describes evidence and lineage. It deliberately does not own a
//! campaign aggregate, derive a result, invoke a provider, activate an
//! overlay, admit canonical state, or promote a generation.

#![forbid(unsafe_code)]

pub mod activation;
pub mod assessment;
pub mod attribution;
pub mod closure;
pub mod delta;
pub mod error;
pub mod experiment;
pub mod identity;
pub mod overlay;
pub mod promotion;
pub mod state_view;

pub use activation::{
    ActivationSection, ActivationStatus, AdherenceSection, AdherenceStatus, CrossTaskAdmission,
    DeliverySection, DeliveryStatus, HarnessActivationReceiptCandidate, LifecycleStage,
    MetricObservation, OverlayEligibility, RetrievalSection, RetrievalStatus, StageDisposition,
    StageObservation, overlay_eligibility,
};
pub use assessment::{
    AssessmentDimension, CausalCeiling, DimensionAssessment, DimensionStatus,
    LearningAssessmentCandidate,
};
pub use attribution::{
    AttributedSubject, NonUseDeclaration, SubjectKind, UseAttributionCandidate, UseBasis,
    UseDisposition,
};
pub use closure::{ClosureHandoff, ExternalDecisionClass, OwnerProof};
pub use delta::{
    AttemptFailure, AttemptLearningDeltaCandidate, AttemptLearningOutcome, AttemptLearningResult,
    ChangeOperation, ChangeSurface, InverseChange, NoChangeDisposition, NoChangeReason, ValueState,
};
pub use error::LearningContractError;
pub use experiment::{AssignmentKind, ImprovementExperimentCandidate};
pub use identity::{
    AgentAttemptId, CampaignId, ContractBinding, LearningTargetId, MemberId, OverlayId, OwnerId,
    ProofCeiling, SlotId, TargetId, WorkScopeId,
};
pub use overlay::{CampaignHarnessOverlayCandidate, OverlayChange, OverlayOrigin};
pub use promotion::{
    HistoryRetention, PromotionBoundaryCandidate, PromotionMutationTarget, RolloutBoundary,
};
pub use state_view::{
    CampaignActiveOverlayPolicy, CampaignHistoryPlanReference, CampaignLearningStateProvenance,
    CampaignLearningStateView, CampaignOwnerRecordId, CampaignOwnerRevision, CampaignPositionKind,
    CampaignPositionRef, CampaignSlotProjectionDigest, CampaignSourceBinding,
    CampaignSourceRequirement, CampaignSourceResolution, CampaignSourceResolutionStatus,
    CampaignSourceRevisionRef, CampaignSourceRole, CampaignViewRebuildReason, Completeness,
    LearningStateViewRecipe, MemberProjection, OmissionPolicy, OwnerDisagreement, SlotDisposition,
    SlotProjection, SlotRequirement, SlotSpec, SourceDenominator,
};

pub use state_view::TASK_CONTROLLER_CAMPAIGN_OWNER_ID;
