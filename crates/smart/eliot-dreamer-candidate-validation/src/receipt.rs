//! A05 receipt issuance adapter over the A03-owned preimages.

use crate::error::{CandidateRejectionReport, CandidateValidationOutcome};
pub(crate) use eliot_dreamer_contracts::validation::{
    DreamDraftValidationError, InputPreimage, MAX_CANONICAL_BYTES, OutputContext, PROOF_CEILING,
    VALIDATOR_CONTRACT, ValidationPolicy, budget_digest, bundle_digest, input_digest_and_size,
    model_digest, output_digest, preservation_digest,
};
use eliot_dreamer_contracts::{
    DreamInputBundle, DreamJobInput, PreservationReport, ValidatedDreamDraft, ValidationReceipt,
};

pub(crate) fn rejection_size(
    report: &CandidateRejectionReport,
) -> Result<usize, DreamDraftValidationError> {
    let outcome = CandidateValidationOutcome::Rejected(Box::new(report.clone()));
    let bytes = eliot_dreamer_contracts::canonical_bytes(&outcome).map_err(|error| {
        DreamDraftValidationError::Encoding {
            field: "validation.rejection_report",
            detail: error.to_string(),
        }
    })?;
    if bytes.len() > MAX_CANONICAL_BYTES {
        return Err(DreamDraftValidationError::Bound {
            field: "validation.rejection_report",
            maximum: MAX_CANONICAL_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(bytes.len())
}

/// A05 receipt issuance context. Canonical field encoding is owned by A03.
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

pub(crate) fn make_receipt(
    context: &ReceiptContext<'_>,
) -> Result<ValidatedDreamDraft, DreamDraftValidationError> {
    let receipt = ValidationReceipt {
        schema_version: 1,
        validator_contract: VALIDATOR_CONTRACT.to_owned(),
        validator_policy: context.policy.policy_id.clone(),
        job_id: context.job.canonical_id(),
        draft_digest: context.draft_digest.to_owned(),
        bundle_digest: context.bundle_digest.to_owned(),
        manifest_digest: context.bundle.manifest_digest.clone(),
        task_id: context.job.task_id.clone(),
        scope_id: context.job.scope_id.clone(),
        input_digest: context.input_digest.to_owned(),
        output_digest: context.output_digest.to_owned(),
        terminal_disposition: context.terminal_disposition.to_owned(),
        proof_ceiling: PROOF_CEILING.to_owned(),
        state_fence: context.job.state_fence.clone(),
        preservation_digest: preservation_digest(context.preservation)?,
        budget_digest: budget_digest(context.job, context.usage)?,
    };
    let validated = ValidatedDreamDraft {
        receipt,
        draft_digest: context.draft_digest.to_owned(),
        scope_id: context.job.scope_id.clone(),
        task_id: context.job.task_id.clone(),
        state_fence: context.job.state_fence.clone(),
    };
    validated.validate().map_err(|error| {
        eliot_dreamer_contracts::validation::error::summarize_contract("validated output", &error)
    })?;
    Ok(validated)
}
