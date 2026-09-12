//! Immutable provider-neutral rival declaration and projection contracts.
//!
//! The module exposes canonical outer semantic tables while preserving the
//! order of meaningful inner sequences. Slot, reference, coverage, and
//! projection validation remain intrinsic; portfolio construction, conflict
//! analysis, and execution policy belong to consumers.

mod validation;

pub mod model;
pub mod prediction;
pub mod set;

pub use model::{
    ClaimDeclarations, CommonModeDisclosure, CurrentPositionAvailability, CurrentPositionBinding,
    DeclarationAvailability, MaterialClaimRef, RIVAL_DECLARATION_SET_SCHEMA_VERSION,
    RIVAL_MODEL_SCHEMA_VERSION, RelatedRivalModelReference, RivalAssumptionSlot, RivalClaimSlot,
    RivalCoverageDeclaration, RivalCoverageReceipt, RivalDeclarationSet, RivalDeclarationSetParams,
    RivalDependency, RivalModelDeclaration, RivalModelDeclarationParams, RivalModelRef,
    RivalModelSlot, RivalPredictionRef, RivalPredictionSlot, RivalSourceSlot, SuppliedLineage,
    TemporalAvailability,
};
pub use prediction::{
    ConditionAssumptionRef, ForecastAvailability, PredictionAvailability,
    RIVAL_PREDICTION_SCHEMA_VERSION, RivalForecast, RivalPrediction, RivalPredictionParams,
    VerifierAvailability,
};
pub use set::{
    RIVAL_MODEL_SET_SCHEMA_VERSION, RivalModelSet, RivalModelSetDisposition, RivalModelSetParams,
    RivalObjectiveOmission, RivalObjectiveOmissionReason,
};
