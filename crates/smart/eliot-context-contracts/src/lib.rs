//! Provider-neutral Context contracts.
//!
//! This package owns closed, immutable schemas and intrinsic validation for
//! the source → whole atom → candidate → admitted set → assembled view chain.
//! It performs no provider I/O, retrieval, ranking, rendering, tokenization,
//! mutable state, authority or Finish operation.

#![forbid(unsafe_code)]

mod admission;
mod admission_input;
mod atom;
mod boundary;
mod canonical_projections;
mod decision_lineage;
mod economy;
mod error;
mod headroom;
mod identity;
mod learning_ticket;
mod measurement;
mod omission;
mod quality;
mod reactive_attention;
mod reactive_coverage;
mod reactive_input;
mod reactive_session;
mod readback;
mod recipe;
mod view;

pub use admission::{
    AdmissionRecord, AdmittedContextSet, ContextCandidateSet, DecisionSafetyFloor,
    SafetyFloorMember,
};
pub use admission_input::{
    AdmissionDecisionEvidence, AdmissionInput, AdmissionMeasuredCost, AdmissionMeasurement,
    AdmissionMeasurementBinding, AdmissionPriorityClass, AdmissionResult, AdmissionRuleIdentity,
    CandidatePriority, MeasurementAggregationMode, MeasurementCompositionProfile, MeasurementUnit,
    PriorityPolicyIdentity, SafetyFloorIdentity, SuppliedOmissionBinding,
};
pub use atom::{
    AdmissionDisposition, AdmittedAtom, AtomAvailability, AtomRepresentation, AuthorityClass,
    CapacityLimits, ContextCandidate, ContextRecipe, LearningProvenance, LossPolicy,
    MAX_ATOM_SOURCE_RANGE_UNITS, MeasurementRef, PrivacyClass, ProviderDisposition,
    ProviderRoleDenominator, RepresentationKind, RoleLossRule,
};
pub use boundary::{
    BOUNDARY_METADATA_SCHEMA_REVISION, BoundaryCompleteness, BoundaryCoordinateSystem,
    BoundaryDenominator, BoundaryDisposition, BoundaryDispositionRecord, BoundaryGap,
    BoundaryGapReason, BoundaryMember, BoundaryMemberCoverage, BoundaryMemberOrigin,
    BoundaryMemberReference, BoundaryMemberRelation, BoundaryMemberRole, BoundaryMetadataEnvelope,
    BoundaryMetadataSet, BoundaryPrecision, BoundaryRecovery, BoundaryTransformRelation,
    BoundaryTransformerRevision, BoundaryUnitKind, BoundaryValidationLimits, ExactSourceRange,
};

pub use canonical_projections::{
    AffordanceProjection, CANONICAL_PROJECTIONS_SCHEMA_VERSION, CanonicalProjectionSet,
    ContinuityProjection, MAX_PROJECTION_ENTRIES, MAX_PROJECTION_TEXT, MAX_SET_OMISSIONS,
    SafetyProjection, TaskProjection,
};
pub use decision_lineage::{
    DecisionExecutionLineageRefs, DecisionLineageActionContractRef, DecisionLineageAnchorLink,
    DecisionLineageArtifact, DecisionLineageAuthorization, DecisionLineageCompleteness,
    DecisionLineageEffect, DecisionLineageEpochRefs, DecisionLineageExpectedObservable,
    DecisionLineagePhase, DecisionLineageRef, DecisionLineageReferenceKind, DecisionLineageReview,
    DecisionLineageRival, DecisionLineageSlot, DecisionLineageSupersession,
    DecisionLineageVerifier,
};
pub use economy::{ContextEconomyReceipt, EconomyAllocations};
pub use error::{
    ContextError, ContextErrorCode, ContextOutcome, DecisionContextIncomplete, ProviderRoleGap,
};
pub use headroom::{
    DOWNSTREAM_HEADROOM_SCHEMA_VERSION, DownstreamHeadroomRequest, DownstreamHeadroomResult,
    HeadroomAllocationLedger, HeadroomAttempt, HeadroomConsumer, HeadroomDecision, HeadroomDemand,
    HeadroomDimension, HeadroomOutcome, HeadroomPurpose, HeadroomQuantity, HeadroomRefusal,
    HeadroomRelease, HeadroomReleaseCondition, HeadroomReleaseInstruction, PurposeAllocation,
};
pub use identity::{
    CONTEXT_CONTRACT_NAME, CONTEXT_CONTRACT_VERSION, ContextBinding, DecisionRevision,
    ProofBinding, ProviderId, ProviderRole, SemanticRole, SourceSnapshot,
};
pub use learning_ticket::{
    LEARNING_TICKET_DIGEST_DOMAIN, LEARNING_TICKET_SCHEMA_VERSION, LearningAdmissionTicket,
    learning_ticket_digest, ticket_fresh_for,
};
pub use measurement::{
    MeasurementStatus, SerializedContextMeasurement, StuEstimate, TokenizerObservation,
};
pub use omission::{ExpansionHandle, NonRecoverableReason, OmissionReason, OmissionRecord};
pub use quality::{
    QUALITY_APPLICABILITY_INPUTS, QUALITY_DIMENSIONS, QUALITY_RESULT_SCHEMA_VERSION,
    QUALITY_SCORECARD_SCHEMA_VERSION, QualityApplicability, QualityApplicabilityInput,
    QualityApplicabilityResolution, QualityApplicabilityResolutionSet, QualityDimension,
    QualityDimensionResult, QualityDimensionState, QualityOperation, QualityOutputBinding,
    QualityRefusal, QualityRefusalKind, QualityScorecard, QualitySuitability,
};
pub use reactive_attention::{
    AttentionAcknowledgement, AttentionInfluence, AttentionOwnerClosure, AttentionResolution,
    CriticalAttentionMember, CriticalAttentionProjection,
};
pub use reactive_coverage::{
    CoverageAxis, CoverageEvidence, CoverageFreshness, IntegrationCoverageProfile,
    ReactiveDeliveryMode,
};
pub(crate) use reactive_input::bounded_preflight;
pub use reactive_input::{
    ContextPlanningView, ReactiveInputError, ReactivePlanningBindings, ReactivePlanningBounds,
    canonical_planning_digest,
};
pub use reactive_session::{
    DeliveryEvidenceClosure, PriorDeliveryBinding, SessionDeliverySnapshot, SnapshotCompleteness,
    SnapshotDenominator,
};
pub use readback::{
    IndexPreview, MAX_EXCERPT_BYTES, MAX_PREVIEW_BYTES, PreviewAuthority, ProjectedCitation,
    ReadbackRefusal, ReadbackRefusalKind, ReadbackRequest,
};
pub use recipe::{
    ApprovedRecipeCatalogue, CONTEXT_RECIPE_POLICY_DIGEST_DOMAIN,
    CONTEXT_RECIPE_POLICY_SCHEMA_VERSION, CONTEXT_RECIPE_RESOLUTION_DIGEST_DOMAIN,
    ContextRecipePolicy, ContextSectionBudget, CounterMetricMovement, GoverningContextRequirements,
    ProtectedReservePolicy, RecipeAdmissionPolicy, RecipeApplicability,
    RecipeApplicabilityDimension, RecipeCandidateRejection, RecipeCounterMetric,
    RecipeExecutionContour, RecipeLayoutPolicy, RecipeOmissionPolicy, RecipePolicyIdentity,
    RecipeQualification, RecipeQualificationState, RecipeRejectionReason, RecipeResolutionRefusal,
    RecipeRolePosition, RecipeStage, RecipeSupersession, ResolvedContextRecipe,
};
pub use view::{ActiveUnderstandingView, RenderedAtom, SelectionIntegrityProof};

/// Compatibility spelling for a provider-produced whole atom.
pub type ContextAtom = ContextCandidate;
/// Compatibility spelling for the immutable assembled Context view.
pub type ContextView = ActiveUnderstandingView;

use eliot_contracts::sha256_hex;

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), ContextError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ContextError::InvalidField(field))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<(), ContextError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Err(ContextError::InvalidDigest(field))
    } else {
        Ok(())
    }
}

/// Compute canonical identity bytes for a serializable contract value.
pub fn canonical_digest<T: serde::Serialize>(value: &T) -> Result<String, ContextError> {
    let bytes = eliot_contracts::canonical_json_bytes(value)
        .map_err(|_| ContextError::InvalidField("canonical_value"))?;
    Ok(sha256_hex(&bytes))
}

/// Compute the canonical digest bound to one state fence.
///
/// This is sha256 over the canonical JSON bytes of `binding.state_fence`;
/// `StateFence` is canonical by construction via
/// `StateFence::new(EpochId, ResourceGeneration)`.
pub fn canonical_fence_digest(fence: &eliot_contracts::StateFence) -> Result<String, ContextError> {
    let bytes = eliot_contracts::canonical_json_bytes(fence)
        .map_err(|_| ContextError::InvalidField("canonical_fence"))?;
    Ok(sha256_hex(&bytes))
}
