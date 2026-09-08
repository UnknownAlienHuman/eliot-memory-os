//! Observation-only composition for the A-32 learning lifecycle contracts.
//!
//! This crate constructs candidate records from supplied owner observations. It
//! does not collect events, authenticate owners, activate candidates, persist a
//! receipt, or promote a causal claim.
//!
//! Calls are bounded to 4 MiB of input and output, 1 MiB per text/byte leaf,
//! 65,536 items per collection, and 128 nested containers. These are local
//! implementation limits, not claims about upstream source completeness.

#![forbid(unsafe_code)]

mod assessment;
mod bounds;
mod contracts;
mod error;

pub use assessment::{AssessmentInput, AssessmentResultOrIncomplete, assess_learning_activation};
pub use contracts::{
    AssessmentPolicy, AssessmentResult, IncompleteAssessment, MAX_DIMENSIONS, MAX_INPUT_BYTES,
    MAX_METRICS, MAX_OUTPUT_BYTES, MAX_REFERENCES, MAX_STAGES, MissingAssessmentField,
};
pub use error::ActivationAssessmentError;

pub use eliot_learning_contracts::{
    AssessmentDimension, AttemptLearningDeltaCandidate, CampaignHarnessOverlayCandidate,
    CampaignLearningStateView, CausalCeiling, ContractBinding, DimensionAssessment,
    DimensionStatus, HarnessActivationReceiptCandidate, LearningAssessmentCandidate,
    LifecycleStage, MetricObservation, SourceDenominator, StageDisposition, StageObservation,
};
