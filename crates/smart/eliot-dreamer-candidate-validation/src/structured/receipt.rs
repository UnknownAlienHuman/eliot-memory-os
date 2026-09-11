//! v2 receipt construction over the A03 structured preimages.

use super::StructuredCandidateValidationOutcome;
use super::bounds::{policy_cap, stream_accepted_size};
use crate::RejectionCode;
use eliot_dreamer_contracts::validation::structured::{
    GroundingValidationInput, STRUCTURED_VALIDATOR_CONTRACT, ValidatedGroundingCandidate,
};
use eliot_dreamer_contracts::validation::{DreamDraftValidationError, PROOF_CEILING};
use eliot_dreamer_contracts::{ValidatedDreamDraft, ValidationReceipt};

pub(crate) fn issue(
    input: &GroundingValidationInput,
    input_digest: String,
    terminal_disposition: &'static str,
) -> Result<StructuredCandidateValidationOutcome, DreamDraftValidationError> {
    let (output_digest, output_bytes) = input.output_digest_and_size(terminal_disposition)?;
    let cap = policy_cap(input);
    if output_bytes > cap {
        return super::validate::reject(
            input,
            RejectionCode::BudgetExceeded,
            "structured validation output exceeds the policy canonical-byte ceiling",
            input_digest,
        );
    }

    let grounded = &input.grounded;
    let model = &grounded.input;
    let preservation_digest =
        eliot_dreamer_contracts::validation::preservation_digest(&input.preservation)?;
    let budget_digest =
        eliot_dreamer_contracts::validation::budget_digest(&model.job, &input.usage)?;
    let receipt = ValidationReceipt {
        schema_version: 1,
        validator_contract: STRUCTURED_VALIDATOR_CONTRACT.to_owned(),
        validator_policy: input.policy.policy_id.clone(),
        job_id: grounded.job_id.clone(),
        draft_digest: model.draft_digest.clone(),
        bundle_digest: model.bundle_digest.clone(),
        manifest_digest: model.bundle.manifest_digest.clone(),
        task_id: grounded.task_id.to_string(),
        scope_id: grounded.scope_id.clone(),
        input_digest: input_digest.clone(),
        output_digest,
        terminal_disposition: terminal_disposition.to_owned(),
        proof_ceiling: PROOF_CEILING.to_owned(),
        state_fence: grounded.state_fence.clone(),
        preservation_digest,
        budget_digest,
    };
    let validated = ValidatedDreamDraft {
        draft_digest: receipt.draft_digest.clone(),
        scope_id: receipt.scope_id.clone(),
        task_id: receipt.task_id.clone(),
        state_fence: receipt.state_fence.clone(),
        receipt,
    };
    let result_size = stream_accepted_size(input, &validated)?;
    let result_size = u64::try_from(result_size).unwrap_or(u64::MAX);
    if result_size > input.grounded.input.job.budget.output_bytes.unwrap_or(0)
        || result_size > input.usage.output_bytes
    {
        return super::validate::reject(
            input,
            RejectionCode::BudgetExceeded,
            "structured accepted result exceeds its output budget",
            input_digest,
        );
    }
    let candidate = ValidatedGroundingCandidate::new(input.clone(), validated)?;
    Ok(StructuredCandidateValidationOutcome::Accepted(Box::new(
        candidate,
    )))
}

pub(crate) fn rejection_size(
    input: &GroundingValidationInput,
    code: RejectionCode,
    detail: &str,
    input_digest: &str,
) -> Result<usize, DreamDraftValidationError> {
    super::bounds::stream_rejected_size(input, code, detail, input_digest)
}
