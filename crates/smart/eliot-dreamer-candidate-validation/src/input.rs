//! A-05 input gate and pure semantic validation entry point.

use std::collections::BTreeSet;

use crate::bounds::{MAX_CANONICAL_BYTES, preflight_inputs};
use crate::error::{
    CandidateRejectionReport, CandidateValidationOutcome, RejectionCode, ValidatedCandidate,
};
use crate::receipt::{
    InputPreimage, OutputContext, ReceiptContext, bundle_digest, input_digest_and_size,
    make_receipt, model_digest, output_digest, rejection_size,
};
use crate::validate::validate_preservation;
use eliot_dreamer_contracts::validation::{DreamDraftValidationError, ValidationPolicy};
use eliot_dreamer_contracts::{
    BudgetUsage, BundleCompleteness, ContractViolation, DreamInputBundle, DreamJobInput,
    GroundedDreamDraft, ModelDraft, PreservationReport, SourceDisposition, SupportState,
};

#[derive(Clone, Copy)]
struct ValidationInputs<'a> {
    job: &'a DreamJobInput,
    bundle: &'a DreamInputBundle,
    model: &'a ModelDraft,
    grounded: &'a GroundedDreamDraft,
    policy: &'a ValidationPolicy,
    usage: &'a BudgetUsage,
    preservation: &'a PreservationReport,
    observation_time_ms: Option<u64>,
    cancellation_requested: bool,
}

fn invalid_contract(
    phase: &'static str,
    result: Result<(), ContractViolation>,
) -> Result<(), DreamDraftValidationError> {
    result.map_err(|error| {
        eliot_dreamer_contracts::validation::error::summarize_contract(phase, &error)
    })
}

/// Validates one supplied A-03 model/grounded pair before semantic handling.
///
/// The observation time is explicit so this function has no ambient clock.
/// Rejected candidates are returned as inert reports retaining every supplied
/// A-03 value; malformed contract shapes return a typed validation error.
#[allow(clippy::too_many_arguments)]
pub fn validate_grounded_dream_draft_at(
    job: &DreamJobInput,
    bundle: &DreamInputBundle,
    model: &ModelDraft,
    grounded: &GroundedDreamDraft,
    policy: &ValidationPolicy,
    usage: &BudgetUsage,
    preservation: &PreservationReport,
    observation_time_ms: Option<u64>,
    cancellation_requested: bool,
) -> Result<CandidateValidationOutcome, DreamDraftValidationError> {
    let inputs = ValidationInputs {
        job,
        bundle,
        model,
        grounded,
        policy,
        usage,
        preservation,
        observation_time_ms,
        cancellation_requested,
    };
    preflight_inputs(job, bundle, model, grounded, preservation)?;
    validate_contracts(&inputs)?;
    let preimage = InputPreimage {
        job,
        bundle,
        model,
        grounded,
        policy,
        usage: *usage,
        preservation,
        observation_time_ms,
        cancellation_requested,
    };
    let (input_digest, input_bytes) = input_digest_and_size(&preimage)?;
    let draft_digest = model_digest(model)?;
    if let Err((code, detail)) = validate_lineage(&inputs, &draft_digest) {
        return reject(&inputs, code, detail, input_digest);
    }
    let policy_cap = usize::try_from(policy.max_canonical_bytes).unwrap_or(usize::MAX);
    if input_bytes > policy_cap {
        return reject(
            &inputs,
            RejectionCode::BudgetExceeded,
            "validation input exceeds the policy canonical-byte ceiling",
            input_digest,
        );
    }
    if let Some((code, detail)) = validate_budget_deadline(&inputs, input_bytes) {
        return reject(&inputs, code, detail, input_digest);
    }
    if let Err(error) = validate_preservation(preservation) {
        return reject(
            &inputs,
            RejectionCode::PreservationFailed,
            error.to_string(),
            input_digest,
        );
    }
    assemble_accepted(&inputs, input_digest, &draft_digest)
}

fn validate_contracts(inputs: &ValidationInputs<'_>) -> Result<(), DreamDraftValidationError> {
    invalid_contract("job", inputs.job.validate())?;
    invalid_contract("bundle", inputs.bundle.validate())?;
    invalid_contract("model draft", inputs.model.validate())?;
    invalid_contract("grounded draft", inputs.grounded.validate())?;
    invalid_contract("preservation report", inputs.preservation.validate())?;
    inputs.policy.validate()
}

fn validate_budget_deadline(
    inputs: &ValidationInputs<'_>,
    input_bytes: usize,
) -> Option<(RejectionCode, String)> {
    if inputs.cancellation_requested {
        return Some((
            RejectionCode::Cancelled,
            "validation was explicitly cancelled".to_owned(),
        ));
    }
    if let Some(deadline) = inputs.job.deadline_ms {
        let Some(observed) = inputs.observation_time_ms else {
            return Some((
                RejectionCode::DeadlineExceeded,
                "deadline validation requires an injected observation time".to_owned(),
            ));
        };
        if observed >= deadline {
            return Some((
                RejectionCode::DeadlineExceeded,
                "validation observation is at or beyond the job deadline".to_owned(),
            ));
        }
    }
    if let Err(error) = inputs
        .job
        .budget
        .require_exact()
        .and_then(|()| inputs.usage.fits(&inputs.job.budget))
    {
        return Some((RejectionCode::BudgetExceeded, error.to_string()));
    }
    if inputs.usage.input_bytes < input_bytes as u64 {
        return Some((
            RejectionCode::BudgetExceeded,
            "supplied input byte usage is below the canonical input size".to_owned(),
        ));
    }
    if inputs.usage.source_width < inputs.model.source_handles.len() as u64 {
        return Some((
            RejectionCode::BudgetExceeded,
            "supplied source width is below the model's admitted source handles".to_owned(),
        ));
    }
    let Some(reference_count) = inputs
        .bundle
        .materials
        .len()
        .checked_add(inputs.bundle.omissions.len())
    else {
        return Some((
            RejectionCode::BudgetExceeded,
            "bundle reference count overflows the bounded counter".to_owned(),
        ));
    };
    if inputs.usage.reference_width < reference_count as u64 {
        return Some((
            RejectionCode::BudgetExceeded,
            "supplied reference width is below the carried bundle references".to_owned(),
        ));
    }
    if inputs.usage.candidates == 0 {
        return Some((
            RejectionCode::BudgetExceeded,
            "a successful validation requires one candidate budget unit".to_owned(),
        ));
    }
    None
}

fn assemble_accepted(
    inputs: &ValidationInputs<'_>,
    input_digest: String,
    draft_digest: &str,
) -> Result<CandidateValidationOutcome, DreamDraftValidationError> {
    let bundle_digest_value = bundle_digest(inputs.bundle)?;
    let terminal_disposition = if inputs.grounded.residues.iter().any(|residue| {
        matches!(
            residue.state,
            SupportState::Partial | SupportState::Contradicted
        )
    }) {
        "partial"
    } else {
        "accepted"
    };
    let (output_digest_value, output_bytes) = output_digest(&OutputContext {
        job: inputs.job,
        bundle: inputs.bundle,
        model: inputs.model,
        grounded: inputs.grounded,
        preservation: inputs.preservation,
        policy: inputs.policy,
        usage: inputs.usage,
        observation_time_ms: inputs.observation_time_ms,
        cancellation_requested: inputs.cancellation_requested,
        draft_digest,
        bundle_digest: &bundle_digest_value,
        terminal_disposition,
    })?;
    let policy_cap = usize::try_from(inputs.policy.max_canonical_bytes).unwrap_or(usize::MAX);
    if output_bytes > policy_cap {
        return reject(
            inputs,
            RejectionCode::BudgetExceeded,
            "validation output exceeds the policy canonical-byte ceiling",
            input_digest,
        );
    }
    if inputs.usage.output_bytes < output_bytes as u64 {
        return reject(
            inputs,
            RejectionCode::BudgetExceeded,
            "supplied output byte usage is below the canonical output size",
            input_digest,
        );
    }
    let receipt_context = ReceiptContext {
        job: inputs.job,
        bundle: inputs.bundle,
        policy: inputs.policy,
        preservation: inputs.preservation,
        usage: inputs.usage,
        input_digest: &input_digest,
        output_digest: &output_digest_value,
        draft_digest,
        bundle_digest: &bundle_digest_value,
        terminal_disposition,
    };
    let validated = make_receipt(&receipt_context)?;
    if validated.state_fence != inputs.job.state_fence
        || validated.receipt.state_fence != inputs.job.state_fence
    {
        return Err(
            eliot_dreamer_contracts::validation::error::summarize_contract(
                "validated output",
                &ContractViolation::BindingMismatch {
                    field: "state_fence",
                    reason: "validated draft fence differs from frozen job fence".to_owned(),
                },
            ),
        );
    }
    let candidate = retained_candidate(inputs, validated);
    let outcome = CandidateValidationOutcome::Accepted(Box::new(candidate.clone()));
    let candidate_bytes = accepted_result_size(&outcome)?;
    let max_result = usize::try_from(
        inputs
            .policy
            .max_canonical_bytes
            .min(inputs.job.budget.output_bytes.unwrap_or(0)),
    )
    .unwrap_or(usize::MAX);
    if candidate_bytes > max_result || candidate_bytes > MAX_CANONICAL_BYTES {
        return reject(
            inputs,
            RejectionCode::BudgetExceeded,
            "accepted result exceeds its bounded output capacity",
            input_digest,
        );
    }
    if inputs.usage.output_bytes < candidate_bytes as u64 {
        return reject(
            inputs,
            RejectionCode::BudgetExceeded,
            "supplied output byte usage is below the retained accepted result size",
            input_digest,
        );
    }
    Ok(CandidateValidationOutcome::Accepted(Box::new(candidate)))
}

fn retained_candidate(
    inputs: &ValidationInputs<'_>,
    validated: eliot_dreamer_contracts::ValidatedDreamDraft,
) -> ValidatedCandidate {
    ValidatedCandidate {
        job: inputs.job.clone(),
        bundle: inputs.bundle.clone(),
        model: inputs.model.clone(),
        grounded: inputs.grounded.clone(),
        preservation: inputs.preservation.clone(),
        usage: *inputs.usage,
        policy: inputs.policy.clone(),
        observation_time_ms: inputs.observation_time_ms,
        cancellation_requested: inputs.cancellation_requested,
        validated,
    }
}

fn accepted_result_size(
    outcome: &CandidateValidationOutcome,
) -> Result<usize, DreamDraftValidationError> {
    let bytes = eliot_dreamer_contracts::canonical_bytes(outcome).map_err(|error| {
        DreamDraftValidationError::Encoding {
            field: "validation.accepted_result",
            detail: error.to_string(),
        }
    })?;
    Ok(bytes.len())
}
fn reject(
    inputs: &ValidationInputs<'_>,
    code: RejectionCode,
    detail: impl Into<String>,
    input_digest: String,
) -> Result<CandidateValidationOutcome, DreamDraftValidationError> {
    let report = CandidateRejectionReport {
        job: inputs.job.clone(),
        bundle: inputs.bundle.clone(),
        model: inputs.model.clone(),
        grounded: inputs.grounded.clone(),
        preservation: inputs.preservation.clone(),
        usage: *inputs.usage,
        policy: inputs.policy.clone(),
        observation_time_ms: inputs.observation_time_ms,
        cancellation_requested: inputs.cancellation_requested,
        code,
        detail: detail.into(),
        input_digest,
    };
    let report_bytes = rejection_size(&report)?;
    let max_report = usize::try_from(
        inputs
            .policy
            .max_canonical_bytes
            .min(inputs.job.budget.report_bytes.unwrap_or(0)),
    )
    .unwrap_or(usize::MAX);
    if report_bytes > max_report || report_bytes > MAX_CANONICAL_BYTES {
        return Err(DreamDraftValidationError::Bound {
            field: "validation.rejection_report",
            maximum: max_report.min(MAX_CANONICAL_BYTES),
            actual: report_bytes,
        });
    }
    if inputs.usage.report_bytes < report_bytes as u64 {
        return Err(DreamDraftValidationError::Bound {
            field: "validation.rejection_report",
            maximum: usize::try_from(inputs.usage.report_bytes).unwrap_or(usize::MAX),
            actual: report_bytes,
        });
    }
    Ok(CandidateValidationOutcome::Rejected(Box::new(report)))
}

fn validate_lineage(
    inputs: &ValidationInputs<'_>,
    draft_digest: &str,
) -> Result<(), (RejectionCode, &'static str)> {
    let job_id = inputs.job.canonical_id();
    if inputs.bundle.job_id != job_id
        || inputs.model.job_id != job_id
        || inputs.grounded.job_id != job_id
    {
        return Err((
            RejectionCode::IdentityMismatch,
            "job canonical identity differs across supplied A-03 values",
        ));
    }
    if inputs.job.policy_ref != inputs.policy.policy_id {
        return Err((
            RejectionCode::IdentityMismatch,
            "job policy_ref differs from supplied validator policy",
        ));
    }
    if inputs.grounded.draft_digest != draft_digest {
        return Err((
            RejectionCode::LineageMismatch,
            "grounded draft digest differs from the canonical model draft",
        ));
    }
    if inputs.bundle.task_id != inputs.job.task_id
        || inputs.bundle.scope_id != inputs.job.scope_id
        || inputs.bundle.state_fence != inputs.job.state_fence
        || inputs.bundle.manifest_digest != inputs.job.frozen_manifest_digest
    {
        return Err((
            RejectionCode::LineageMismatch,
            "bundle task, scope, fence or manifest is outside the frozen job",
        ));
    }
    let material_handles: BTreeSet<&str> = inputs
        .bundle
        .materials
        .iter()
        .filter(|material| material.disposition != SourceDisposition::Excluded)
        .map(|material| material.handle.as_str())
        .collect();
    let omission_handles: BTreeSet<&str> = inputs
        .bundle
        .omissions
        .iter()
        .map(|item| item.handle.as_str())
        .collect();
    for handle in &inputs.model.source_handles {
        if !material_handles.contains(handle.as_str()) {
            if omission_handles.contains(handle.as_str()) {
                return Err((
                    RejectionCode::LineageMismatch,
                    "model source handle is explicitly omitted",
                ));
            }
            return Err((
                RejectionCode::LineageMismatch,
                "model source handle is outside the bundle manifest",
            ));
        }
    }
    for residue in &inputs.grounded.residues {
        if matches!(
            residue.state,
            SupportState::OutsideManifest | SupportState::UnsupportedPrecision
        ) {
            return Err((
                RejectionCode::UnsupportedPrecision,
                "grounded residue is outside the admitted manifest precision",
            ));
        }
    }
    if matches!(inputs.bundle.completeness, BundleCompleteness::Unknown) {
        return Err((
            RejectionCode::LineageMismatch,
            "bundle completeness is unknown for a validated draft",
        ));
    }
    Ok(())
}
