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
mod economy;
mod error;
mod identity;
mod measurement;
mod omission;
mod quality;
mod reactive_attention;
mod reactive_coverage;
mod reactive_input;
mod reactive_session;
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
    CapacityLimits, ContextCandidate, ContextRecipe, LossPolicy, MeasurementRef, PrivacyClass,
    ProviderDisposition, ProviderRoleDenominator, RepresentationKind, RoleLossRule,
};
pub use economy::{ContextEconomyReceipt, EconomyAllocations};
pub use error::{
    ContextError, ContextErrorCode, ContextOutcome, DecisionContextIncomplete, ProviderRoleGap,
};
pub use identity::{
    CONTEXT_CONTRACT_NAME, CONTEXT_CONTRACT_VERSION, ContextBinding, DecisionRevision,
    ProofBinding, ProviderId, ProviderRole, SemanticRole, SourceSnapshot,
};
pub use measurement::{
    MeasurementStatus, SerializedContextMeasurement, StuEstimate, TokenizerObservation,
};
pub use omission::{ExpansionHandle, NonRecoverableReason, OmissionReason, OmissionRecord};
pub use quality::{QualityDimension, QualityDimensionResult, QualityScorecard};
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
