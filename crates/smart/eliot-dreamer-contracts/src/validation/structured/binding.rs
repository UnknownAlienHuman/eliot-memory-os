//! Intrinsic context and receipt joins for the structured bridge.

use super::encoding as structured_encoding;
use super::{
    GroundingValidationInput, STRUCTURED_VALIDATION_SCHEMA_VERSION, ValidatedGroundingCandidate,
};
use crate::error::ContractViolation;
use crate::grounding::{AuthorizedReference, MaterialClaim};
use crate::rival::{RivalClaimSlot, RivalSourceSlot};
use crate::validation::{
    DreamDraftValidationError, PROOF_CEILING, encoding as v1_encoding, error, preservation_digest,
};

/// Versioned A05 validator identity for the grounding-v2 bridge.
pub const STRUCTURED_VALIDATOR_CONTRACT: &str = "smart.dreamer.candidate_validation@2-grounding-v2";

pub(super) fn validate_input(
    input: &GroundingValidationInput,
) -> Result<(), DreamDraftValidationError> {
    structured_encoding::preflight_input(input)?;
    if input.schema_version != STRUCTURED_VALIDATION_SCHEMA_VERSION {
        return Err(invalid("structured.schema_version"));
    }
    input
        .grounded
        .validate()
        .map_err(|error| summarize("grounded", &error))?;
    input.policy.validate()?;
    if input.policy.policy_id != input.grounded.input.job.policy_ref {
        return Err(invalid("structured.policy.policy_ref"));
    }
    input
        .preservation
        .validate()
        .map_err(|error| summarize("preservation", &error))?;
    input
        .usage
        .fits(&input.grounded.input.job.budget)
        .map_err(|error| summarize("usage", &error))?;
    if let Some(rival) = &input.rival_declarations {
        rival
            .validate()
            .map_err(|error| summarize("rival declarations", &error))?;
        validate_rival_context(rival, input)?;
    }
    Ok(())
}

pub(super) fn validate_receipt_binding(
    candidate: &ValidatedGroundingCandidate,
) -> Result<(), DreamDraftValidationError> {
    structured_encoding::preflight_output(candidate)?;
    let input = &candidate.input;
    let receipt = &candidate.validated.receipt;
    candidate
        .validated
        .validate()
        .map_err(|error| summarize("validated receipt", &error))?;
    if receipt.validator_contract != STRUCTURED_VALIDATOR_CONTRACT
        || receipt.proof_ceiling != PROOF_CEILING
        || !matches!(
            receipt.terminal_disposition.as_str(),
            "accepted" | "partial"
        )
    {
        return Err(invalid("structured.receipt.format"));
    }
    let grounded = &input.grounded;
    let model = &grounded.input;
    if candidate.validated.state_fence != receipt.state_fence
        || receipt.state_fence != grounded.state_fence
        || receipt.job_id != grounded.job_id
        || receipt.task_id != grounded.task_id.to_string()
        || receipt.scope_id != grounded.scope_id
        || candidate.validated.task_id != receipt.task_id
        || candidate.validated.scope_id != receipt.scope_id
        || receipt.validator_policy != input.policy.policy_id
        || input.policy.policy_id != model.job.policy_ref
        || receipt.draft_digest != model.draft_digest
        || receipt.bundle_digest != model.bundle_digest
        // This receipt field retains the existing frozen job/bundle manifest
        // meaning. The A-14b allowed-reference manifest is bound by `grounded`.
        || receipt.manifest_digest != model.bundle.manifest_digest
    {
        return Err(invalid("structured.receipt.identity"));
    }
    let preservation = preservation_digest(&input.preservation)?;
    if receipt.preservation_digest != preservation {
        return Err(error::binding("structured.receipt.preservation_digest"));
    }
    let budget = v1_encoding::budget_digest(&model.job, &input.usage)?;
    if receipt.budget_digest != budget {
        return Err(error::binding("structured.receipt.budget_digest"));
    }
    let (input_digest, _) = input.input_digest_and_size()?;
    if receipt.input_digest != input_digest {
        return Err(error::binding("structured.receipt.input_digest"));
    }
    let output_digest = structured_encoding::output_digest(candidate)?;
    if receipt.output_digest != output_digest {
        return Err(error::binding("structured.receipt.output_digest"));
    }
    Ok(())
}

fn validate_rival_context(
    rival: &crate::rival::RivalDeclarationSet,
    input: &GroundingValidationInput,
) -> Result<(), DreamDraftValidationError> {
    let grounded = &input.grounded;
    if rival.task_id != grounded.task_id
        || rival.scope != grounded.scope_id
        || rival.state_fence != grounded.state_fence
    {
        return Err(invalid("rival.context"));
    }
    for slot in &rival.claims {
        match slot {
            RivalClaimSlot::Retained { claim } => {
                let Some(expected) = grounded
                    .input
                    .claims
                    .iter()
                    .find(|candidate| candidate.claim_id == claim.claim_id)
                else {
                    return Err(invalid("rival.claim.source"));
                };
                if claim.as_ref() != expected {
                    return Err(invalid("rival.claim.source"));
                }
            }
            RivalClaimSlot::Unavailable {
                claim_id,
                proposition,
                claim_preimage_digest,
                ..
            } => validate_partial_claim(
                grounded
                    .input
                    .claims
                    .iter()
                    .find(|claim| &claim.claim_id == claim_id),
                proposition.as_ref(),
                claim_preimage_digest.as_deref(),
            )?,
        }
    }
    for slot in &rival.sources {
        match slot {
            RivalSourceSlot::Retained { reference } => {
                let Some(expected) = grounded.manifest.references.get(&reference.handle) else {
                    return Err(invalid("rival.source.manifest"));
                };
                if !same_authorized_reference(reference.as_ref(), expected) {
                    return Err(invalid("rival.source.manifest"));
                }
            }
            RivalSourceSlot::Unavailable {
                handle,
                content_digest,
                source_revision,
                ..
            } => validate_partial_source(
                grounded.manifest.references.get(handle),
                content_digest.as_deref(),
                source_revision.as_deref(),
            )?,
        }
    }
    Ok(())
}

fn validate_partial_claim(
    expected: Option<&MaterialClaim>,
    proposition: Option<&crate::grounding::PropositionId>,
    digest: Option<&str>,
) -> Result<(), DreamDraftValidationError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if proposition.is_some_and(|value| value != &expected.proposition)
        || digest.is_some_and(|value| value != expected.source_preimage_digest.as_str())
    {
        return Err(invalid("rival.claim.partial"));
    }
    Ok(())
}

fn validate_partial_source(
    expected: Option<&AuthorizedReference>,
    digest: Option<&str>,
    revision: Option<&str>,
) -> Result<(), DreamDraftValidationError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if digest.is_some_and(|value| value != expected.content_digest.as_str())
        || revision.is_some_and(|value| value != expected.source_revision.as_str())
    {
        return Err(invalid("rival.source.partial"));
    }
    Ok(())
}

fn same_authorized_reference(actual: &AuthorizedReference, expected: &AuthorizedReference) -> bool {
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    actual
        .assertions
        .sort_by(|left, right| left.assertion_id.cmp(&right.assertion_id));
    expected
        .assertions
        .sort_by(|left, right| left.assertion_id.cmp(&right.assertion_id));
    actual == expected
}

fn summarize(phase: &'static str, error: &ContractViolation) -> DreamDraftValidationError {
    error::summarize_contract(phase, error)
}

fn invalid(field: &'static str) -> DreamDraftValidationError {
    error::binding(field)
}
