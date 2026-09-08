//! Stable result and diagnostic shapes owned by the A-05 gate.

use eliot_dreamer_contracts::{
    BudgetUsage, DreamInputBundle, DreamJobInput, GroundedDreamDraft, ModelDraft,
    PreservationReport, ValidatedDreamDraft,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::input::ValidationPolicy;

/// A bounded semantic reason for retaining a rejected candidate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RejectionCode {
    /// Job, bundle, draft, task, scope, or fence identities disagree.
    IdentityMismatch,
    /// A model handle or grounded lineage points outside supplied material.
    LineageMismatch,
    /// Candidate content asks the gate to make an unsupported claim.
    UnsupportedPrecision,
    /// The supplied independent usage cannot authorize this input.
    BudgetExceeded,
    /// The injected observation is at or beyond the frozen deadline.
    DeadlineExceeded,
    /// The caller explicitly cancelled this validation.
    Cancelled,
    /// One of the seven preservation dimensions is not proven.
    PreservationFailed,
    /// A common job shape is outside this gate's supported contract.
    UnsupportedJobShape,
}

/// Exact supplied material retained when semantic validation rejects a draft.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateRejectionReport {
    /// Frozen job supplied to the gate.
    pub job: DreamJobInput,
    /// Exact input bundle supplied to the gate.
    pub bundle: DreamInputBundle,
    /// Structured model draft, retained without rewriting.
    pub model: ModelDraft,
    /// Grounding residues, retained without deduplication or normalization.
    pub grounded: GroundedDreamDraft,
    /// The caller-supplied seven-dimension report.
    pub preservation: PreservationReport,
    /// Exact independent usage supplied to the validator.
    pub usage: BudgetUsage,
    /// Exact caller policy bound by the input preimage.
    pub policy: ValidationPolicy,
    /// Explicit observation time used for deadline comparison.
    pub observation_time_ms: Option<u64>,
    /// Explicit cancellation input used by the gate.
    pub cancellation_requested: bool,
    /// Stable machine-readable rejection class.
    pub code: RejectionCode,
    /// Bounded diagnostic detail; never model authority.
    pub detail: String,
    /// Digest of the receipt-excluded validation input preimage.
    pub input_digest: String,
}

/// A successful A-05 result retaining the exact A-03 values consumed by the gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidatedCandidate {
    /// Frozen job supplied to the gate.
    pub job: DreamJobInput,
    /// Exact input bundle, including materials and accounted omissions.
    pub bundle: DreamInputBundle,
    /// Original structured model value.
    pub model: ModelDraft,
    /// Original grounded value and every residue.
    pub grounded: GroundedDreamDraft,
    /// Exact seven-dimension preservation report.
    pub preservation: PreservationReport,
    /// Exact independent usage supplied to the validator.
    pub usage: BudgetUsage,
    /// Exact caller policy bound by the receipt input preimage.
    pub policy: ValidationPolicy,
    /// Explicit observation time used for deadline comparison.
    pub observation_time_ms: Option<u64>,
    /// Explicit cancellation input used by the gate.
    pub cancellation_requested: bool,
    /// A-03 validated wrapper carrying the immutable validation receipt.
    pub validated: ValidatedDreamDraft,
}

/// Result of one pure pre-handler validation call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum CandidateValidationOutcome {
    /// The draft passed common validation and remains candidate-only.
    Accepted(Box<ValidatedCandidate>),
    /// The draft was retained as an inert diagnostic.
    Rejected(Box<CandidateRejectionReport>),
}

/// Typed failures before a candidate rejection report can be safely formed.
#[derive(Debug, Error)]
pub enum DreamDraftValidationError {
    /// A hostile nested input exceeds this gate's preflight bound.
    #[error("{field} exceeds the bounded limit {maximum}: got {actual}")]
    Bound {
        /// Stable field path.
        field: &'static str,
        /// Maximum admitted count or bytes.
        maximum: usize,
        /// Observed count or bytes.
        actual: usize,
    },
    /// A canonical preimage could not be encoded.
    #[error("canonical encoding failed for {field}: {detail}")]
    Encoding {
        /// Preimage kind.
        field: &'static str,
        /// Encoding diagnostic.
        detail: String,
    },
    /// An A-03 value was not structurally valid enough to preserve safely.
    ///
    /// The canonical error's caller-controlled reason is deliberately
    /// redacted; exact supplied values remain available only in bounded
    /// rejection reports after the report itself passes size checks.
    #[error("invalid {phase} contract at {field}")]
    InvalidContract {
        /// Validation phase.
        phase: &'static str,
        /// Stable field or dimension identifier.
        field: &'static str,
    },
}

pub(crate) fn summarize_contract(
    phase: &'static str,
    error: &eliot_dreamer_contracts::ContractViolation,
) -> DreamDraftValidationError {
    use eliot_dreamer_contracts::ContractViolation;
    let field = match error {
        ContractViolation::UnknownVariant { field, .. }
        | ContractViolation::MissingField(field)
        | ContractViolation::ImplicitDefault(field)
        | ContractViolation::OutOfBounds { field, .. }
        | ContractViolation::BindingMismatch { field, .. }
        | ContractViolation::Malformed { field, .. } => *field,
        ContractViolation::Budget { dimension, .. } => *dimension,
        ContractViolation::CrossStage(_)
        | ContractViolation::KindPayload(_)
        | ContractViolation::Registry(_)
        | ContractViolation::ScreenIneligible(_)
        | ContractViolation::Preservation(_)
        | ContractViolation::ForbiddenCarry(_) => "contract",
    };
    DreamDraftValidationError::InvalidContract { phase, field }
}
