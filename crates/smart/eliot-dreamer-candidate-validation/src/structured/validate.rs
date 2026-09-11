//! Common v2 semantic checks, with deterministic phase ordering.

use super::bounds::policy_cap;
use super::receipt;
use super::{StructuredCandidateRejectionReport, StructuredCandidateValidationOutcome};
use crate::RejectionCode;
use crate::error::DreamDraftValidationError;
use eliot_dreamer_contracts::ContractViolation;
use eliot_dreamer_contracts::JobClass;
use eliot_dreamer_contracts::SourceDisposition;
use eliot_dreamer_contracts::grounding::{
    GROUNDING_SCHEMA_VERSION, GroundedDreamDraft, PositionAssertability, PrivacyHandling,
    SupportResult,
};
use eliot_dreamer_contracts::validation::structured::{
    GroundingValidationInput, STRUCTURED_VALIDATION_SCHEMA_VERSION,
};
use std::collections::BTreeSet;

pub(crate) fn validate_shallow_shape(
    input: &GroundingValidationInput,
) -> Result<(), DreamDraftValidationError> {
    let grounded = &input.grounded;
    let model = &grounded.input;
    let versions = [
        (
            input.schema_version,
            STRUCTURED_VALIDATION_SCHEMA_VERSION,
            "structured.schema_version",
        ),
        (
            grounded.schema_version,
            GROUNDING_SCHEMA_VERSION,
            "grounded.schema_version",
        ),
        (
            model.schema_version,
            GROUNDING_SCHEMA_VERSION,
            "grounding.model.schema_version",
        ),
        (model.bundle.schema_version, 1, "bundle.schema_version"),
    ];
    for (actual, expected, field) in versions {
        if actual != expected {
            return Err(DreamDraftValidationError::InvalidContract {
                phase: "structured shape",
                field,
            });
        }
    }
    if model.attempt.attempt_number == 0
        || model.attempt.attempt_number > model.attempt.maximum_attempts
    {
        return Err(DreamDraftValidationError::InvalidContract {
            phase: "structured shape",
            field: "grounding.model.attempt",
        });
    }
    Ok(())
}

/// Runs only owner shape checks. Cross-owner joins and budget usage remain in
/// the ordered semantic phases below, so an unsafe or identity failure cannot
/// be hidden behind `BudgetUsage::fits`.
pub(crate) fn validate_owner_shape(
    input: &GroundingValidationInput,
) -> Result<(), DreamDraftValidationError> {
    input.policy.validate()?;
    let model = &input.grounded.input;
    validate_contract("grounding job", model.job.validate())?;
    validate_contract("grounding bundle", model.bundle.validate())?;
    validate_contract("grounding model", model.validate())?;
    validate_contract("preservation", input.preservation.validate())?;
    validate_contract("grounding policy", input.grounded.policy.validate())?;
    validate_contract("grounding manifest", input.grounded.manifest.validate())?;
    validate_contract("grounding ledger", input.grounded.ledger.validate())?;
    if let Some(rival) = &input.rival_declarations {
        validate_contract("rival declarations", rival.validate())?;
    }
    Ok(())
}

fn validate_contract(
    phase: &'static str,
    result: Result<(), ContractViolation>,
) -> Result<(), DreamDraftValidationError> {
    result.map_err(|error| summarize_contract(phase, &error))
}

fn summarize_contract(phase: &'static str, error: &ContractViolation) -> DreamDraftValidationError {
    eliot_dreamer_contracts::validation::error::summarize_contract(phase, error)
}

pub(crate) fn validate_identity(
    input: &GroundingValidationInput,
) -> Option<(RejectionCode, &'static str)> {
    let grounded = &input.grounded;
    let model = &grounded.input;
    let job_id = model.job.canonical_id();
    if grounded.job_id != job_id
        || model.job_id != job_id
        || model.job.policy_ref != input.policy.policy_id
    {
        return Some((
            RejectionCode::IdentityMismatch,
            "structured job or policy identity differs",
        ));
    }
    if grounded.task_id != model.task_id || grounded.scope_id != model.scope_id {
        return Some((
            RejectionCode::IdentityMismatch,
            "structured task or scope identity differs",
        ));
    }
    if grounded.state_fence != model.state_fence || model.job.state_fence != grounded.state_fence {
        return Some((
            RejectionCode::IdentityMismatch,
            "structured state fence differs",
        ));
    }
    if let Some(rival) = &input.rival_declarations
        && (rival.task_id != grounded.task_id
            || rival.scope != grounded.scope_id
            || rival.state_fence != grounded.state_fence)
    {
        return Some((
            RejectionCode::IdentityMismatch,
            "rival declarations are bound to a different task, scope, or fence",
        ));
    }
    None
}

pub(crate) fn validate_unsafe_ceilings(
    input: &GroundingValidationInput,
) -> Option<(RejectionCode, &'static str)> {
    let grounded = &input.grounded;
    if grounded
        .manifest
        .references
        .values()
        .any(|reference| reference.invalidated)
    {
        let invalidated: BTreeSet<_> = grounded
            .manifest
            .references
            .iter()
            .filter_map(|(handle, reference)| reference.invalidated.then_some(handle))
            .collect();
        let used = grounded.ledger.records.values().any(|record| {
            record
                .accepted_support
                .iter()
                .chain(record.accepted_counterevidence.iter())
                .any(|handle| invalidated.contains(handle))
        });
        if used {
            return Some((
                RejectionCode::UnsupportedPrecision,
                "grounding ledger relies on an invalidated admitted reference",
            ));
        }
    }
    if used_ceiling_exceeds_source(grounded) {
        return Some((
            RejectionCode::UnsupportedPrecision,
            "grounding ledger exceeds a retained source grade or assertability ceiling",
        ));
    }
    None
}

fn used_ceiling_exceeds_source(grounded: &GroundedDreamDraft) -> bool {
    grounded.ledger.records.values().any(|record| {
        let disposition_base = match record.disposition {
            SupportResult::Supported => PositionAssertability::HypothesisCandidate,
            SupportResult::Partial | SupportResult::Unsupported => {
                PositionAssertability::HypothesisCandidate
            }
            SupportResult::Contradicted
            | SupportResult::Unknown
            | SupportResult::OutsideManifest
            | SupportResult::Stale
            | SupportResult::Superseded
            | SupportResult::JustifiedNotApplicable => {
                PositionAssertability::UnknownWithheldQuarantined
            }
        };
        if assertability_rank(record.assertability_ceiling) > assertability_rank(disposition_base) {
            return true;
        }
        if assertability_rank(record.assertability_ceiling)
            > assertability_rank(PositionAssertability::HypothesisCandidate)
        {
            return true;
        }
        if record
            .grade
            .as_ref()
            .and_then(|assignment| assignment.grade)
            .is_some_and(|observed| observed > record.grade_ceiling)
        {
            return true;
        }
        let component_support: Vec<_> = record.component_outcomes.values().copied().collect();
        record
            .accepted_support
            .iter()
            .chain(record.accepted_counterevidence.iter())
            .any(|handle| {
                grounded
                    .manifest
                    .references
                    .get(handle)
                    .is_some_and(|reference| {
                        if record.grade_ceiling > reference.grade_ceiling {
                            return true;
                        }
                        let mut available = reference.assertability_ceiling;
                        for cap in [
                            PositionAssertability::authority_cap(reference.authority),
                            PositionAssertability::disclosure_cap(reference.disclosure),
                            privacy_cap(reference.privacy),
                            PositionAssertability::grade_cap(reference.grade_ceiling),
                        ] {
                            available = weaker(available, cap);
                        }
                        if !component_support.is_empty()
                            && let Ok(cap) = PositionAssertability::support_cap(&component_support)
                        {
                            available = weaker(available, cap);
                        }
                        exceeds_assertability(record.assertability_ceiling, available)
                    })
            })
    })
}

fn privacy_cap(privacy: PrivacyHandling) -> PositionAssertability {
    match privacy {
        PrivacyHandling::Unrestricted => PositionAssertability::MaterialEffect,
        PrivacyHandling::RestrictedHandling => PositionAssertability::QualifiedInference,
        PrivacyHandling::Purged => PositionAssertability::HypothesisCandidate,
    }
}

fn weaker(left: PositionAssertability, right: PositionAssertability) -> PositionAssertability {
    if assertability_rank(left) <= assertability_rank(right) {
        left
    } else {
        right
    }
}

fn exceeds_assertability(
    requested: PositionAssertability,
    available: PositionAssertability,
) -> bool {
    assertability_rank(requested) > assertability_rank(available)
}

fn assertability_rank(value: PositionAssertability) -> u8 {
    match value {
        PositionAssertability::UnknownWithheldQuarantined => 0,
        PositionAssertability::PlanningOnly => 1,
        PositionAssertability::HypothesisCandidate => 2,
        PositionAssertability::ConflictQualificationRequired => 3,
        PositionAssertability::QualifiedInference => 4,
        PositionAssertability::ObservedFact => 5,
        PositionAssertability::MaterialEffect => 6,
    }
}

pub(crate) fn validate_lineage(
    input: &GroundingValidationInput,
) -> Option<(RejectionCode, &'static str)> {
    let grounded = &input.grounded;
    let model = &grounded.input;
    if model.draft_digest != grounded.draft_digest
        || model.input_manifest_digest != grounded.manifest_digest
        || grounded.manifest.digest != grounded.manifest_digest
        || grounded.ledger.draft_digest != grounded.draft_digest
        || grounded.ledger.manifest_digest != grounded.manifest_digest
        || grounded.ledger.policy_digest != grounded.policy_digest
    {
        return Some((
            RejectionCode::LineageMismatch,
            "grounding manifest, ledger, or draft lineage differs",
        ));
    }
    for record in grounded.ledger.records.values() {
        for handle in record
            .accepted_support
            .iter()
            .chain(record.accepted_counterevidence.iter())
        {
            let Some(reference) = grounded.manifest.references.get(handle) else {
                return Some((
                    RejectionCode::LineageMismatch,
                    "an admitted grounding source is absent from the retained manifest",
                ));
            };
            let material = grounded.input.bundle.materials.iter().find(|material| {
                material.handle == handle.as_str()
                    && material.disposition != SourceDisposition::Excluded
            });
            if material.is_none_or(|material| material.digest != reference.content_digest) {
                return Some((
                    RejectionCode::LineageMismatch,
                    "an admitted source is not bound to an included bundle material",
                ));
            }
        }
    }
    None
}

pub(crate) fn validate_budget_deadline(
    input: &GroundingValidationInput,
    input_bytes: usize,
) -> Option<(RejectionCode, String)> {
    let job = &input.grounded.input.job;
    if input.cancellation_requested {
        return Some((
            RejectionCode::Cancelled,
            "validation was explicitly cancelled".to_owned(),
        ));
    }
    if let Some(deadline) = job.deadline_ms {
        let Some(observed) = input.observation_time_ms else {
            return Some((
                RejectionCode::DeadlineExceeded,
                "deadline validation requires an explicit observation".to_owned(),
            ));
        };
        if observed >= deadline {
            return Some((
                RejectionCode::DeadlineExceeded,
                "validation observation is at or beyond the job deadline".to_owned(),
            ));
        }
    }
    if input.usage.input_bytes < input_bytes as u64 {
        return Some((
            RejectionCode::BudgetExceeded,
            "input byte usage is below the structured preimage size".to_owned(),
        ));
    }
    if let Err(error) = job
        .budget
        .require_exact()
        .and_then(|()| input.usage.fits(&job.budget))
    {
        return Some((RejectionCode::BudgetExceeded, error.to_string()));
    }
    if input.usage.attempts < u64::from(input.grounded.input.attempt.attempt_number) {
        return Some((
            RejectionCode::BudgetExceeded,
            "attempt usage is below the retained attempt number".to_owned(),
        ));
    }
    let reference_count = retained_reference_count(input);
    if input.usage.reference_width < reference_count as u64 {
        return Some((
            RejectionCode::BudgetExceeded,
            "reference width is below retained bundle/manifest references".to_owned(),
        ));
    }
    if input.usage.source_width < source_width(&input.grounded) as u64 {
        return Some((
            RejectionCode::BudgetExceeded,
            "source width is below retained manifest sources".to_owned(),
        ));
    }
    if input.usage.attempts == 0 || input.usage.model_calls == 0 || input.usage.candidates == 0 {
        return Some((
            RejectionCode::BudgetExceeded,
            "successful validation requires an attempt, model call, and candidate unit".to_owned(),
        ));
    }
    let cap = policy_cap(input);
    if input_bytes > cap {
        return Some((
            RejectionCode::BudgetExceeded,
            "structured input exceeds the policy canonical-byte ceiling".to_owned(),
        ));
    }
    None
}

fn retained_reference_count(input: &GroundingValidationInput) -> usize {
    let bundle = &input.grounded.input.bundle;
    let manifest = &input.grounded.manifest;
    let mut handles = BTreeSet::new();
    handles.extend(
        bundle
            .materials
            .iter()
            .map(|material| material.handle.as_str()),
    );
    handles.extend(
        bundle
            .omissions
            .iter()
            .map(|omission| omission.handle.as_str()),
    );
    handles.extend(
        manifest
            .references
            .keys()
            .map(eliot_dreamer_contracts::grounding::ArtifactId::as_str),
    );
    handles.len()
}

fn source_width(grounded: &GroundedDreamDraft) -> usize {
    let mut owners = BTreeSet::new();
    for (handle, reference) in &grounded.manifest.references {
        if let Some(lineage) = &reference.source_lineage {
            owners.insert(format!("owner:{:?}", lineage.owner));
        } else {
            owners.insert(format!("handle:{handle:?}"));
        }
    }
    owners.len()
}

/// Checks the seven-dimensional lossless pre-handler evidence boundary:
/// complete partition; claim/proposition/component identity; validated
/// raw/draft/bundle/manifest/ledger lineage; reconstructible unchanged input;
/// preceding authority ceilings; claim/dependency closure with unknown and
/// counter-data retained; and original provenance/history in the input
/// preimage. This proves structural retention, not external rollback or a
/// future handler result.
pub(crate) fn validate_preservation_evidence(input: &GroundingValidationInput) -> Option<String> {
    if let Err(error) = input.preservation.overall() {
        return Some(error.to_string());
    }
    let grounded = &input.grounded;
    let expected: BTreeSet<_> = grounded
        .input
        .claims
        .iter()
        .map(|claim| claim.claim_id.as_str())
        .collect();
    let accounted: BTreeSet<_> = grounded
        .ledger
        .records
        .keys()
        .map(String::as_str)
        .chain(
            grounded
                .ledger
                .unprocessed_claim_ids
                .iter()
                .map(String::as_str),
        )
        .collect();
    if expected != accounted {
        return Some(
            "preservation coverage is not evidenced by the complete ledger partition".to_owned(),
        );
    }
    if grounded.input.draft_digest != grounded.draft_digest
        || grounded.input.input_manifest_digest != grounded.manifest_digest
        || grounded.manifest.digest != grounded.manifest_digest
        || grounded.ledger.draft_digest != grounded.draft_digest
        || grounded.ledger.manifest_digest != grounded.manifest_digest
    {
        return Some(
            "preservation does not retain the exact draft and manifest identities".to_owned(),
        );
    }
    for claim in &grounded.input.claims {
        let Some(record) = grounded.ledger.records.get(&claim.claim_id) else {
            continue;
        };
        if record.kind != claim.kind
            || record.proposed_support != claim.proposed_support
            || record.proposed_counterevidence != claim.proposed_counterevidence
            || record.proposition != claim.proposition
            || record.proposition_digest != claim.proposition_digest
            || record.component_outcomes.keys().collect::<BTreeSet<_>>()
                != claim.component_digests.keys().collect::<BTreeSet<_>>()
        {
            return Some(
                "preservation evidence changed a retained claim or evidence partition".to_owned(),
            );
        }
        if record
            .accepted_support
            .iter()
            .chain(record.accepted_counterevidence.iter())
            .any(|handle| !grounded.manifest.references.contains_key(handle))
        {
            return Some("preservation evidence contains an unresolved accepted source".to_owned());
        }
    }
    None
}

pub(crate) fn validate_family(
    input: &GroundingValidationInput,
) -> Option<(RejectionCode, &'static str)> {
    if matches!(input.grounded.input.job.job_class, JobClass::Curation) {
        return Some((
            RejectionCode::UnsupportedJobShape,
            "Curation requires its separate typed post-handler carrier",
        ));
    }
    None
}

pub(crate) fn assemble_accepted(
    input: &GroundingValidationInput,
    input_digest: String,
) -> Result<StructuredCandidateValidationOutcome, DreamDraftValidationError> {
    let terminal = if input.grounded.ledger.unprocessed_claim_ids.is_empty()
        && input
            .grounded
            .input
            .claims
            .iter()
            .all(|claim| fully_supported_claim(&input.grounded, &claim.claim_id))
    {
        "accepted"
    } else {
        "partial"
    };
    receipt::issue(input, input_digest, terminal)
}

fn fully_supported_claim(grounded: &GroundedDreamDraft, root: &str) -> bool {
    let mut pending = vec![root.to_owned()];
    let mut visited = BTreeSet::new();
    while let Some(claim_id) = pending.pop() {
        if !visited.insert(claim_id.clone()) {
            return false;
        }
        let Some(claim) = grounded
            .input
            .claims
            .iter()
            .find(|claim| claim.claim_id == claim_id)
        else {
            return false;
        };
        let Some(record) = grounded.ledger.records.get(&claim_id) else {
            return false;
        };
        if !matches!(record.disposition, SupportResult::Supported)
            || record
                .grade
                .as_ref()
                .and_then(|assignment| assignment.grade)
                .is_none()
            || record.accepted_support.is_empty() && claim.subclaim_ids.is_empty()
            || !record.rejected_support.is_empty()
            || !record.unresolved_support.is_empty()
            || !record.rejected_counterevidence.is_empty()
            || !record.unresolved_counterevidence.is_empty()
            || !record.unknowns.is_empty()
            || !record.precision_findings.is_empty()
            || !record.accepted_counterevidence.is_empty()
            || record
                .component_outcomes
                .values()
                .any(|outcome| !matches!(outcome, SupportResult::Supported))
        {
            return false;
        }
        if record.component_outcomes.keys().any(|component| {
            !record
                .witnesses
                .iter()
                .any(|witness| witness.component == *component)
        }) {
            return false;
        }
        pending.extend(claim.subclaim_ids.iter().cloned());
    }
    true
}

pub(crate) fn reject(
    input: &GroundingValidationInput,
    code: RejectionCode,
    detail: impl Into<String>,
    input_digest: String,
) -> Result<StructuredCandidateValidationOutcome, DreamDraftValidationError> {
    let detail = detail.into();
    let report_bytes = receipt::rejection_size(input, code, &detail, &input_digest)?;
    let cap = usize::try_from(input.grounded.input.job.budget.report_bytes.unwrap_or(0))
        .unwrap_or(usize::MAX)
        .min(eliot_dreamer_contracts::validation::MAX_CANONICAL_BYTES);
    if report_bytes > cap {
        return Err(DreamDraftValidationError::Bound {
            field: "structured.rejection",
            maximum: cap,
            actual: report_bytes,
        });
    }
    if input.usage.report_bytes < report_bytes as u64 {
        return Err(DreamDraftValidationError::Bound {
            field: "structured.rejection.usage",
            maximum: usize::try_from(input.usage.report_bytes).unwrap_or(usize::MAX),
            actual: report_bytes,
        });
    }
    let report = StructuredCandidateRejectionReport {
        input: input.clone(),
        code,
        detail,
        input_digest,
    };
    Ok(StructuredCandidateValidationOutcome::Rejected(Box::new(
        report,
    )))
}
