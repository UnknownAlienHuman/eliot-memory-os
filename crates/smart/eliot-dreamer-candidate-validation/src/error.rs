//! Stable result and diagnostic shapes owned by the A-05 gate.

use eliot_dreamer_contracts::{
    BudgetUsage, DreamInputBundle, DreamJobInput, GroundedDreamDraft, ModelDraft,
    PreservationReport,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use eliot_dreamer_contracts::validation::{
    DreamDraftValidationError, ValidatedCandidate, ValidationPolicy,
};

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

/// Result of one pure pre-handler validation call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum CandidateValidationOutcome {
    /// The draft passed common validation and remains candidate-only.
    Accepted(Box<ValidatedCandidate>),
    /// The draft was retained as an inert diagnostic.
    Rejected(Box<CandidateRejectionReport>),
}

pub(crate) use eliot_dreamer_contracts::validation::error::summarize_contract;
