//! A03 diagnosis evidence contracts.
//!
//! This surface is immutable and candidate-only. Product context and
//! current-discriminator declarations are composed from canonical foundation,
//! evaluation, receipt, evidence and existing Dreamer attempt primitives.

pub mod discriminator;
pub mod identity;
pub mod repair;
mod validation;

pub use discriminator::{
    CURRENT_DISCRIMINATOR_SCHEMA_VERSION, ConfirmationIndependenceClaim, CurrentDiscriminator,
    CurrentObservation, DiscriminatorPrecondition, ObservationDeclaration, ObservedValueKind,
    ObservedValueRef, PostHocConfirmation, PreconditionState, ReplayBinding,
    RunEvidenceAssociation, SuppliedRunBinding,
};
pub use identity::{
    ACCEPTANCE_BINDING_SCHEMA_VERSION, AcceptanceBinding, MAX_DIAGNOSIS_CONTEXT_ITEMS,
    PRODUCT_CONTEXT_SCHEMA_VERSION, ProductContext, UnavailableEvidence, UnavailableField,
    product_context_contract_version,
};
pub use repair::{
    LoadBearingChange, MechanismExercise, MechanismProjection, REPAIR_LINEAGE_SCHEMA_VERSION,
    RepairAttemptEntry, RepairAttemptRecord, RepairContextEndpoint, RepairContextUnavailable,
    RepairEvent, RepairEventEntry, RepairEventOutcome, RepairHistoryPresence, RepairLineage,
    RepairStageKind, RepeatJustification, RepeatReason,
};
pub use validation::{
    MAX_DIAGNOSIS_CANONICAL_BYTES, MAX_DIAGNOSIS_SEQUENCE_ITEMS, MAX_DIAGNOSIS_TEXT_BYTES,
};
