//! Borrowed input bounds applied before expensive canonicalization.

use crate::{DreamInputBundle, DreamJobInput, GroundedDreamDraft, ModelDraft, PreservationReport};

/// Maximum canonical bytes admitted by this prototype.
pub const MAX_CANONICAL_BYTES: usize = 1_048_576;
/// Maximum entries in each locally traversed collection.
pub const MAX_RECORDS: usize = 1_024;

fn add_bytes(
    total: &mut usize,
    value: &str,
) -> Result<(), crate::validation::DreamDraftValidationError> {
    *total = total.checked_add(value.len()).ok_or(
        crate::validation::DreamDraftValidationError::Bound {
            field: "validation.input_fields",
            maximum: MAX_CANONICAL_BYTES,
            actual: usize::MAX,
        },
    )?;
    if *total > MAX_CANONICAL_BYTES {
        return Err(crate::validation::DreamDraftValidationError::Bound {
            field: "validation.input_fields",
            maximum: MAX_CANONICAL_BYTES,
            actual: *total,
        });
    }
    Ok(())
}

fn check_records(
    actual: usize,
    field: &'static str,
) -> Result<(), crate::validation::DreamDraftValidationError> {
    if actual > MAX_RECORDS {
        return Err(crate::validation::DreamDraftValidationError::Bound {
            field,
            maximum: MAX_RECORDS,
            actual,
        });
    }
    Ok(())
}

/// Accounts every nested string and collection before canonicalization.
pub fn preflight_inputs(
    job: &DreamJobInput,
    bundle: &DreamInputBundle,
    model: &ModelDraft,
    grounded: &GroundedDreamDraft,
    preservation: &PreservationReport,
) -> Result<(), crate::validation::DreamDraftValidationError> {
    check_records(bundle.materials.len(), "bundle.materials")?;
    check_records(bundle.omissions.len(), "bundle.omissions")?;
    check_records(model.source_handles.len(), "model.source_handles")?;
    check_records(model.counterevidence.len(), "model.counterevidence")?;
    check_records(model.recommended_probes.len(), "model.recommended_probes")?;
    check_records(
        model.invalidation_conditions.len(),
        "model.invalidation_conditions",
    )?;
    check_records(
        model.declared_confirmed_handles.len(),
        "model.declared_confirmed_handles",
    )?;
    check_records(grounded.residues.len(), "grounded.residues")?;
    check_records(preservation.verdicts.len(), "preservation.verdicts")?;

    let mut bytes = 0usize;
    add_bytes(&mut bytes, &job.requester.principal)?;
    if let Some(session) = &job.requester.session {
        add_bytes(&mut bytes, session)?;
    }
    for value in [
        &job.operation_id,
        &job.idempotency_key,
        &job.task_id,
        &job.scope_id,
        &job.privacy_profile,
        &job.contract_ref,
        &job.policy_ref,
        &job.frozen_manifest_digest,
        &bundle.job_id,
        &bundle.scope_id,
        &bundle.task_id,
        &bundle.manifest_digest,
        &model.job_id,
        &model.statement,
        &model.uncertainty,
        &model.expected_benefit,
        &grounded.job_id,
        &grounded.draft_digest,
        &grounded.coverage_note,
    ] {
        add_bytes(&mut bytes, value)?;
    }
    if let Some(denominator) = &bundle.authoritative_denominator {
        add_bytes(&mut bytes, denominator)?;
    }
    for material in &bundle.materials {
        add_bytes(&mut bytes, &material.handle)?;
        add_bytes(&mut bytes, &material.digest)?;
    }
    for omission in &bundle.omissions {
        for value in [
            &omission.handle,
            &omission.reason,
            &omission.scope_id,
            &omission.task_id,
            &omission.digest,
        ] {
            add_bytes(&mut bytes, value)?;
        }
        if let Some(reason) = &omission.nonrecoverable_reason {
            add_bytes(&mut bytes, reason)?;
        }
    }
    for values in [
        &model.source_handles,
        &model.counterevidence,
        &model.recommended_probes,
        &model.invalidation_conditions,
        &model.declared_confirmed_handles,
    ] {
        for value in values {
            add_bytes(&mut bytes, value)?;
        }
    }
    for residue in &grounded.residues {
        add_bytes(&mut bytes, &residue.claim)?;
        add_bytes(&mut bytes, &residue.detail)?;
    }
    for verdict in &preservation.verdicts {
        add_bytes(&mut bytes, &verdict.note)?;
    }
    Ok(())
}
