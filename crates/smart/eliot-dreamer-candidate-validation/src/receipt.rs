//! Receipt-excluded canonical preimages for the A-05 result.

use eliot_dreamer_contracts::{
    DreamInputBundle, DreamJobInput, GroundedDreamDraft, ModelDraft, PreservationReport,
    ValidatedDreamDraft, ValidationReceipt,
};
use serde::Serialize;

use crate::error::{
    CandidateRejectionReport, CandidateValidationOutcome, DreamDraftValidationError,
    summarize_contract,
};
use crate::input::ValidationPolicy;

pub(crate) const VALIDATOR_CONTRACT: &str = "smart.dreamer.candidate_validation@1";
pub(crate) const PROOF_CEILING: &str = "candidate-only";

#[derive(Serialize)]
pub(crate) struct InputPreimage<'a> {
    pub job: &'a DreamJobInput,
    pub bundle: &'a DreamInputBundle,
    pub model: &'a ModelDraft,
    pub grounded: &'a GroundedDreamDraft,
    pub policy: &'a ValidationPolicy,
    pub usage: eliot_dreamer_contracts::BudgetUsage,
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
    usage: eliot_dreamer_contracts::BudgetUsage,
    observation_time_ms: Option<u64>,
    cancellation_requested: bool,
    draft_digest: &'a str,
    bundle_digest: &'a str,
    terminal_disposition: &'a str,
}

pub(crate) struct OutputContext<'a> {
    pub job: &'a DreamJobInput,
    pub bundle: &'a DreamInputBundle,
    pub model: &'a ModelDraft,
    pub grounded: &'a GroundedDreamDraft,
    pub preservation: &'a PreservationReport,
    pub policy: &'a ValidationPolicy,
    pub usage: &'a eliot_dreamer_contracts::BudgetUsage,
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
    let bytes = eliot_dreamer_contracts::canonical_bytes(value).map_err(|error| {
        DreamDraftValidationError::Encoding {
            field,
            detail: error.to_string(),
        }
    })?;
    if bytes.len() > crate::bounds::MAX_CANONICAL_BYTES {
        return Err(DreamDraftValidationError::Bound {
            field,
            maximum: crate::bounds::MAX_CANONICAL_BYTES,
            actual: bytes.len(),
        });
    }
    Ok((eliot_dreamer_contracts::digest_hex(&bytes), bytes.len()))
}

pub(crate) fn input_digest_and_size(
    preimage: &InputPreimage<'_>,
) -> Result<(String, usize), DreamDraftValidationError> {
    digest(preimage, "validation.input")
}

pub(crate) fn model_digest(model: &ModelDraft) -> Result<String, DreamDraftValidationError> {
    digest(model, "model.draft_digest").map(|(digest, _)| digest)
}

pub(crate) fn bundle_digest(
    bundle: &DreamInputBundle,
) -> Result<String, DreamDraftValidationError> {
    digest(bundle, "bundle.digest").map(|(digest, _)| digest)
}

pub(crate) fn preservation_digest(
    preservation: &PreservationReport,
) -> Result<String, DreamDraftValidationError> {
    digest(preservation, "preservation.digest").map(|(digest, _)| digest)
}

pub(crate) fn budget_digest(
    job: &DreamJobInput,
    usage: &eliot_dreamer_contracts::BudgetUsage,
) -> Result<String, DreamDraftValidationError> {
    #[derive(Serialize)]
    struct BudgetPreimage<'a> {
        budget: &'a eliot_dreamer_contracts::BudgetLimits,
        usage: eliot_dreamer_contracts::BudgetUsage,
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

pub(crate) fn output_digest(
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

pub(crate) fn rejection_size(
    report: &CandidateRejectionReport,
) -> Result<usize, DreamDraftValidationError> {
    let outcome = CandidateValidationOutcome::Rejected(Box::new(report.clone()));
    digest(&outcome, "validation.rejection_report").map(|(_, size)| size)
}

pub(crate) fn make_receipt(
    context: &ReceiptContext<'_>,
) -> Result<ValidatedDreamDraft, DreamDraftValidationError> {
    let job = context.job;
    let bundle = context.bundle;
    let policy = context.policy;
    let receipt = ValidationReceipt {
        schema_version: 1,
        validator_contract: VALIDATOR_CONTRACT.to_owned(),
        validator_policy: policy.policy_id.clone(),
        job_id: job.canonical_id(),
        draft_digest: context.draft_digest.to_owned(),
        bundle_digest: context.bundle_digest.to_owned(),
        manifest_digest: bundle.manifest_digest.clone(),
        task_id: job.task_id.clone(),
        scope_id: job.scope_id.clone(),
        input_digest: context.input_digest.to_owned(),
        output_digest: context.output_digest.to_owned(),
        terminal_disposition: context.terminal_disposition.to_owned(),
        proof_ceiling: PROOF_CEILING.to_owned(),
        state_fence: job.state_fence.clone(),
        preservation_digest: preservation_digest(context.preservation)?,
        budget_digest: budget_digest(job, context.usage)?,
    };
    let validated = ValidatedDreamDraft {
        receipt,
        draft_digest: context.draft_digest.to_owned(),
        scope_id: job.scope_id.clone(),
        task_id: job.task_id.clone(),
        state_fence: job.state_fence.clone(),
    };
    validated
        .validate()
        .map_err(|error| summarize_contract("validated output", &error))?;
    Ok(validated)
}

pub(crate) struct ReceiptContext<'a> {
    pub job: &'a DreamJobInput,
    pub bundle: &'a DreamInputBundle,
    pub policy: &'a ValidationPolicy,
    pub preservation: &'a PreservationReport,
    pub usage: &'a eliot_dreamer_contracts::BudgetUsage,
    pub input_digest: &'a str,
    pub output_digest: &'a str,
    pub draft_digest: &'a str,
    pub bundle_digest: &'a str,
    pub terminal_disposition: &'a str,
}
