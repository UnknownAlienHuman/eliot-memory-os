//! Receipt-excluded canonical preimages for the A05 validation result.

use serde::Serialize;

use super::{DreamDraftValidationError, ValidationPolicy, bounds::MAX_CANONICAL_BYTES};
use crate::{
    BudgetLimits, BudgetUsage, DreamInputBundle, DreamJobInput, GroundedDreamDraft, ModelDraft,
    PreservationReport,
};

/// Validator contract identity retained for compatibility with A05 receipts.
pub const VALIDATOR_CONTRACT: &str = "smart.dreamer.candidate_validation@1";
/// Proof ceiling retained for compatibility with A05 receipts.
pub const PROOF_CEILING: &str = "candidate-only";

#[derive(Serialize)]
pub struct InputPreimage<'a> {
    pub job: &'a DreamJobInput,
    pub bundle: &'a DreamInputBundle,
    pub model: &'a ModelDraft,
    pub grounded: &'a GroundedDreamDraft,
    pub policy: &'a ValidationPolicy,
    pub usage: BudgetUsage,
    pub preservation: &'a PreservationReport,
    pub observation_time_ms: Option<u64>,
    pub cancellation_requested: bool,
}

#[derive(Serialize)]
struct OutputPreimage<'a> {
    job: &'a DreamJobInput,
    bundle: &'a DreamInputBundle,
    model: &'a ModelDraft,
    grounded: &'a GroundedDreamDraft,
    preservation: &'a PreservationReport,
    policy: &'a ValidationPolicy,
    usage: BudgetUsage,
    observation_time_ms: Option<u64>,
    cancellation_requested: bool,
    draft_digest: &'a str,
    bundle_digest: &'a str,
    terminal_disposition: &'a str,
}

pub struct OutputContext<'a> {
    pub job: &'a DreamJobInput,
    pub bundle: &'a DreamInputBundle,
    pub model: &'a ModelDraft,
    pub grounded: &'a GroundedDreamDraft,
    pub preservation: &'a PreservationReport,
    pub policy: &'a ValidationPolicy,
    pub usage: &'a BudgetUsage,
    pub observation_time_ms: Option<u64>,
    pub cancellation_requested: bool,
    pub draft_digest: &'a str,
    pub bundle_digest: &'a str,
    pub terminal_disposition: &'a str,
}

fn digest<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<(String, usize), DreamDraftValidationError> {
    let bytes =
        crate::canonical_bytes(value).map_err(|error| DreamDraftValidationError::Encoding {
            field,
            detail: error.to_string(),
        })?;
    if bytes.len() > MAX_CANONICAL_BYTES {
        return Err(DreamDraftValidationError::Bound {
            field,
            maximum: MAX_CANONICAL_BYTES,
            actual: bytes.len(),
        });
    }
    Ok((crate::digest_hex(&bytes), bytes.len()))
}

pub fn input_digest_and_size(
    preimage: &InputPreimage<'_>,
) -> Result<(String, usize), DreamDraftValidationError> {
    digest(preimage, "validation.input")
}

pub fn model_digest(model: &ModelDraft) -> Result<String, DreamDraftValidationError> {
    digest(model, "model.draft_digest").map(|(digest, _)| digest)
}

pub fn bundle_digest(bundle: &DreamInputBundle) -> Result<String, DreamDraftValidationError> {
    digest(bundle, "bundle.digest").map(|(digest, _)| digest)
}

pub fn preservation_digest(
    preservation: &PreservationReport,
) -> Result<String, DreamDraftValidationError> {
    digest(preservation, "preservation.digest").map(|(digest, _)| digest)
}

pub fn budget_digest(
    job: &DreamJobInput,
    usage: &BudgetUsage,
) -> Result<String, DreamDraftValidationError> {
    #[derive(Serialize)]
    struct BudgetPreimage<'a> {
        budget: &'a BudgetLimits,
        usage: BudgetUsage,
    }
    digest(
        &BudgetPreimage {
            budget: &job.budget,
            usage: *usage,
        },
        "budget.digest",
    )
    .map(|(digest, _)| digest)
}

pub fn output_digest(
    context: &OutputContext<'_>,
) -> Result<(String, usize), DreamDraftValidationError> {
    digest(
        &OutputPreimage {
            job: context.job,
            bundle: context.bundle,
            model: context.model,
            grounded: context.grounded,
            preservation: context.preservation,
            policy: context.policy,
            usage: *context.usage,
            observation_time_ms: context.observation_time_ms,
            cancellation_requested: context.cancellation_requested,
            draft_digest: context.draft_digest,
            bundle_digest: context.bundle_digest,
            terminal_disposition: context.terminal_disposition,
        },
        "validation.output",
    )
}
