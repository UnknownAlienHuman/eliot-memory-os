//! Candidate assembly and context-aware A03 sealing.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_dreamer_contracts::{
    CandidateDisposition, ClassificationAssignmentSnapshot, ClassificationCandidate,
    ClassificationCandidateClosure, ClassificationInput, ClassificationRollback, ContractViolation,
    CurationAcceptanceCtx, CurationKind, OrientationClassificationProfile, canonical_bytes,
    classification_input_digest, digest_hex, seal_classification,
    validate_classification_acceptance,
};
use eliot_evidence::{EvidenceFreshness, LifecycleState};
use eliot_receipts::ProofCeiling;
use serde::{Deserialize, Serialize};

use crate::policy::{BudgetReceipt, ClassificationPolicy};
use crate::selection::{AlternativeTrace, SelectionKind, SelectionReport, select};
use crate::semantics::ClassificationSemantics;

/// User-visible semantic outcome, with dispositions finer than the shared
/// candidate transport enum where the latter has no refinement/cancel state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ClassificationDisposition {
    Candidate,
    Duplicate,
    Refinement,
    Conflicted,
    Ambiguous,
    UnsupportedTaxonomy,
    Incomplete,
    Blocked,
    Abstention,
    Cancelled,
    BoundedOut,
    Invalid,
    Internal,
}

/// Both prior and proposed positions are retained for an incompatible change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationConflict {
    pub prior_assignment_id: ArtifactId,
    pub prior_alternative_id: Option<ArtifactId>,
    pub proposed_alternative_id: ArtifactId,
}

/// Complete result of one deterministic, candidate-only invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationResult {
    pub disposition: ClassificationDisposition,
    pub candidate: Option<ClassificationCandidate>,
    pub sealed: Option<ClassificationCandidateClosure>,
    pub traces: Vec<AlternativeTrace>,
    pub omitted_alternatives: Vec<ArtifactId>,
    pub conflict: Option<ClassificationConflict>,
    pub budget: BudgetReceipt,
    pub result_digest: String,
    pub reason: String,
}

/// Semantic Orientation classification result without a fabricated Curation
/// candidate or A-03 seal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrientationClassificationResult {
    pub profile_digest: String,
    pub policy_digest: String,
    pub target_id: ArtifactId,
    pub target_revision: String,
    pub disposition: ClassificationDisposition,
    pub selected_alternative_id: Option<ArtifactId>,
    pub traces: Vec<AlternativeTrace>,
    pub omitted_alternatives: Vec<ArtifactId>,
    pub conflict: Option<ClassificationConflict>,
    pub budget: BudgetReceipt,
    pub result_digest: String,
    pub reason: String,
}

/// Runs the pure post-admission selector and returns an unsealed candidate.
fn classify_unsealed(
    input: &ClassificationInput,
    policy: &ClassificationPolicy,
) -> Result<ClassificationResult, ContractViolation> {
    if input.policy_digest != policy.policy_digest {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.policy_digest",
            reason: "input does not bind the supplied execution policy".to_owned(),
        });
    }
    validate_target(input, policy)?;
    let budget = policy.preflight(input)?;
    let report = select(input, policy)?;
    let candidate = assemble_candidate(input, &report)?;
    let disposition = result_disposition(&report.kind);
    let conflict = conflict_set(input, &report.kind);
    let mut traces = report.traces;
    traces.sort_by(|left, right| left.alternative_id.cmp(&right.alternative_id));
    let mut omitted_alternatives = report.omitted_alternatives;
    omitted_alternatives.sort();
    let mut result = ClassificationResult {
        disposition,
        candidate: Some(candidate),
        sealed: None,
        traces,
        omitted_alternatives,
        conflict,
        budget,
        result_digest: String::new(),
        reason: report.reason,
    };
    reconcile_output(&mut result, policy.max_output_bytes)?;
    result.result_digest = digest_result(&result)?;
    Ok(result)
}

/// Runs A05/A03 acceptance and then seals the same candidate closure.
pub fn classify(
    input: &ClassificationInput,
    context: &CurationAcceptanceCtx<'_>,
    policy: &ClassificationPolicy,
) -> Result<ClassificationResult, ContractViolation> {
    validate_classification_acceptance(&input.item, context)?;
    if context.job.operation_id != input.operation_id.as_str()
        || context.job.idempotency_key != input.idempotency_key
        || context.request.request_id != input.request_id
    {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.operation_request",
            reason: "context operation, idempotency or request identity differs".to_owned(),
        });
    }
    if context.usage.stu_used != policy.observed_stu {
        return Err(ContractViolation::Budget {
            dimension: "stu",
            reason: "policy STU usage differs from accepted context usage".to_owned(),
        });
    }
    input.preflight()?;
    let budget = policy.preflight(input)?;
    if let Some(job_input) = context.job.budget.input_bytes
        && budget.input_bytes > job_input
    {
        return Err(ContractViolation::Budget {
            dimension: "input_bytes",
            reason: format!(
                "{} exceeds accepted job ceiling {job_input}",
                budget.input_bytes
            ),
        });
    }
    enforce_job_deadline(context, policy)?;
    let retained = input.clone();
    let mut result = classify_unsealed(input, policy)?;
    if let Some(candidate) = result.candidate.clone() {
        let closure = seal_classification(retained, candidate, context)?;
        result.sealed = Some(closure);
    }
    let job_output = context
        .job
        .budget
        .output_bytes
        .ok_or(ContractViolation::Budget {
            dimension: "output_bytes",
            reason: "accepted job has no output ceiling".to_owned(),
        })?;
    reconcile_output(&mut result, policy.max_output_bytes.min(job_output))?;
    result.result_digest = digest_result(&result)?;
    Ok(result)
}

/// Runs the shared taxonomy/evidence selector over an original Orientation
/// owner profile. The result is semantic output only; Curation-specific
/// acceptance and candidate sealing are deliberately not invoked.
pub fn classify_orientation(
    input: &OrientationClassificationProfile,
    policy: &ClassificationPolicy,
) -> Result<OrientationClassificationResult, ContractViolation> {
    input.validate()?;
    if input.policy_digest != policy.policy_digest {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.policy_digest",
            reason: "Orientation profile does not bind the supplied execution policy".to_owned(),
        });
    }
    let semantics = ClassificationSemantics::from_orientation(input);
    validate_target_semantics(&semantics, policy)?;
    let mut budget = policy.preflight_orientation(input)?;
    let report = crate::selection::select_orientation(input, policy)?;
    let profile_digest = digest_hex(&canonical_bytes(input)?);
    let disposition = result_disposition(&report.kind);
    let selected_alternative_id = selected_id(&report.kind);
    let conflict = conflict_set_for(input.prior_assignment.as_ref(), &report.kind);
    let mut traces = report.traces;
    traces.sort_by(|left, right| left.alternative_id.cmp(&right.alternative_id));
    let mut omitted_alternatives = report.omitted_alternatives;
    omitted_alternatives.sort();
    let mut result = OrientationClassificationResult {
        profile_digest,
        policy_digest: input.policy_digest.clone(),
        target_id: input.target.target_id.clone(),
        target_revision: input.target.target_revision.clone(),
        disposition,
        selected_alternative_id,
        traces,
        omitted_alternatives,
        conflict,
        budget,
        result_digest: String::new(),
        reason: report.reason,
    };
    for _ in 0..8 {
        let observed = u64::try_from(canonical_bytes(&result)?.len()).map_err(|_| {
            ContractViolation::Budget {
                dimension: "output_bytes",
                reason: "output length cannot be represented".to_owned(),
            }
        })?;
        if observed > policy.max_output_bytes {
            return Err(ContractViolation::Budget {
                dimension: "output_bytes",
                reason: format!("{observed} exceeds {}", policy.max_output_bytes),
            });
        }
        if result.budget.output_bytes == observed {
            break;
        }
        budget.output_bytes = observed;
        result.budget = budget.clone();
    }
    result.result_digest = orientation_result_digest(&result)?;
    Ok(result)
}

fn enforce_job_deadline(
    context: &CurationAcceptanceCtx<'_>,
    policy: &ClassificationPolicy,
) -> Result<(), ContractViolation> {
    if let Some(deadline) = context.job.deadline_ms {
        let now = policy.now_ms.ok_or(ContractViolation::Budget {
            dimension: "deadline",
            reason: "accepted job deadline requires an explicit observation time".to_owned(),
        })?;
        if now >= deadline {
            return Err(ContractViolation::Budget {
                dimension: "deadline",
                reason: "accepted job deadline elapsed".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_target(
    input: &ClassificationInput,
    policy: &ClassificationPolicy,
) -> Result<(), ContractViolation> {
    let semantics = ClassificationSemantics::from_curation(input);
    validate_target_semantics(&semantics, policy)
}

fn validate_target_semantics(
    input: &ClassificationSemantics<'_>,
    policy: &ClassificationPolicy,
) -> Result<(), ContractViolation> {
    if input.target.lifecycle != LifecycleState::Active {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.target.lifecycle",
            reason: "only active admitted targets may be classified".to_owned(),
        });
    }
    if matches!(
        input.target.freshness,
        EvidenceFreshness::Stale
            | EvidenceFreshness::Unknown
            | EvidenceFreshness::KnownOlderSnapshot
    ) {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.target.freshness",
            reason: "stale or unknown target freshness cannot be classified".to_owned(),
        });
    }
    if matches!(
        policy.target_status,
        eliot_evidence::EpistemicStatus::Stale
            | eliot_evidence::EpistemicStatus::Superseded
            | eliot_evidence::EpistemicStatus::Rejected
    ) {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.target.status",
            reason: "stale, superseded or rejected target cannot be classified".to_owned(),
        });
    }
    if input.target.source_handles.is_empty() {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.target.source_handles",
            reason: "admitted target must retain at least one source/history handle".to_owned(),
        });
    }
    Ok(())
}

fn assemble_candidate(
    input: &ClassificationInput,
    report: &SelectionReport,
) -> Result<ClassificationCandidate, ContractViolation> {
    let selected = selected_id(&report.kind);
    let alternative = selected.as_ref().and_then(|id| {
        input
            .taxonomy
            .alternatives
            .iter()
            .find(|a| a.alternative_id == *id)
    });
    let family_ref =
        alternative.map_or_else(|| "unresolved".to_owned(), |a| a.family.as_str().to_owned());
    let subtype_ref = alternative.and_then(|a| a.subtype_ref.clone());
    let input_digest = classification_input_digest(input)?;
    let candidate_id = ClassificationCandidate::expected_candidate_id(
        input.operation_id.as_str(),
        &input_digest,
        &input.policy_digest,
        selected.as_ref(),
    );
    let (before, after) = snapshots(input, alternative);
    let (evidence_refs, counterevidence_refs) = trace_refs(report);
    let source_handles = source_handles(input);
    let sole_legal = input.taxonomy.alternatives.len() == 1
        && input.taxonomy.declared_alternative_ids.len() == 1;
    let disposition = candidate_disposition(&report.kind);
    let rollback = ClassificationRollback {
        target_id: input.target.target_id.clone(),
        predecessor: input
            .prior_assignment
            .as_ref()
            .map(|p| p.assignment_id.clone()),
        rollback_handles: source_handles.clone(),
        invalidation_handles: source_handles.clone(),
        raw_history_handles: source_handles.clone(),
        note: "candidate retains raw target history and reversible predecessor".to_owned(),
    };
    let candidate = ClassificationCandidate {
        candidate_id,
        operation_id: input.operation_id.clone(),
        input_digest,
        policy_digest: input.policy_digest.clone(),
        kind: CurationKind::Classification,
        target_id: input.target.target_id.clone(),
        target_revision: input.target.target_revision.clone(),
        selected_alternative_id: selected,
        sole_legal_alternative_proof: sole_legal,
        family_ref,
        subtype_ref,
        disposition,
        alternatives: unique_ids(input.taxonomy.declared_alternative_ids.clone()),
        source_handles,
        evidence_refs,
        counterevidence_refs,
        before,
        after,
        rollback,
        preservation: input.preservation.clone(),
        proof_ceiling: ProofCeiling::CandidateArtifact,
    };
    Ok(candidate)
}

fn selected_id(kind: &SelectionKind) -> Option<ArtifactId> {
    match kind {
        SelectionKind::Candidate { alternative_id, .. }
        | SelectionKind::Duplicate { alternative_id }
        | SelectionKind::Conflict { alternative_id } => Some(alternative_id.clone()),
        SelectionKind::Ambiguous
        | SelectionKind::Incomplete
        | SelectionKind::Unsupported
        | SelectionKind::Abstention => None,
    }
}

fn snapshots(
    input: &ClassificationInput,
    alternative: Option<&eliot_dreamer_contracts::TaxonomyAlternative>,
) -> (
    ClassificationAssignmentSnapshot,
    ClassificationAssignmentSnapshot,
) {
    let before = input
        .prior_assignment
        .as_ref()
        .map_or_else(empty_snapshot, |prior| ClassificationAssignmentSnapshot {
            alternative_id: prior.selected_alternative_id.clone(),
            family_ref: prior.selected_family.clone(),
            subtype_ref: prior.selected_subtype.clone(),
            assignment_digest: Some(prior.assignment_digest.clone()),
        });
    let after = alternative.map_or_else(empty_snapshot, |a| ClassificationAssignmentSnapshot {
        alternative_id: Some(a.alternative_id.clone()),
        family_ref: Some(a.family.as_str().to_owned()),
        subtype_ref: a.subtype_ref.clone(),
        assignment_digest: None,
    });
    (before, after)
}

fn trace_refs(report: &SelectionReport) -> (Vec<ArtifactId>, Vec<ArtifactId>) {
    let evidence = report
        .traces
        .iter()
        .flat_map(|trace| trace.evidence_refs.iter().cloned())
        .collect();
    let counter = report
        .traces
        .iter()
        .flat_map(|trace| trace.counterevidence_refs.iter().cloned())
        .collect();
    (unique_ids(evidence), unique_ids(counter))
}

fn source_handles(input: &ClassificationInput) -> Vec<ArtifactId> {
    unique_ids(
        input
            .target
            .source_handles
            .iter()
            .cloned()
            .chain(
                input
                    .evidence
                    .iter()
                    .flat_map(|e| e.source_handles.iter().cloned()),
            )
            .collect(),
    )
}

fn candidate_disposition(kind: &SelectionKind) -> CandidateDisposition {
    match kind {
        SelectionKind::Candidate { .. } => CandidateDisposition::Candidate,
        SelectionKind::Duplicate { .. } => CandidateDisposition::Duplicate,
        SelectionKind::Conflict { .. } => CandidateDisposition::Conflict,
        SelectionKind::Ambiguous | SelectionKind::Abstention => CandidateDisposition::Abstention,
        SelectionKind::Incomplete => CandidateDisposition::Partial,
        SelectionKind::Unsupported => CandidateDisposition::Unsupported,
    }
}

fn result_disposition(kind: &SelectionKind) -> ClassificationDisposition {
    match kind {
        SelectionKind::Candidate {
            refinement: true, ..
        } => ClassificationDisposition::Refinement,
        SelectionKind::Candidate { .. } => ClassificationDisposition::Candidate,
        SelectionKind::Duplicate { .. } => ClassificationDisposition::Duplicate,
        SelectionKind::Conflict { .. } => ClassificationDisposition::Conflicted,
        SelectionKind::Ambiguous => ClassificationDisposition::Ambiguous,
        SelectionKind::Incomplete => ClassificationDisposition::Incomplete,
        SelectionKind::Unsupported => ClassificationDisposition::UnsupportedTaxonomy,
        SelectionKind::Abstention => ClassificationDisposition::Abstention,
    }
}
fn conflict_set(
    input: &ClassificationInput,
    kind: &SelectionKind,
) -> Option<ClassificationConflict> {
    conflict_set_for(input.prior_assignment.as_ref(), kind)
}

fn conflict_set_for(
    prior_assignment: Option<&eliot_dreamer_contracts::PriorAssignmentRef>,
    kind: &SelectionKind,
) -> Option<ClassificationConflict> {
    match kind {
        SelectionKind::Conflict { alternative_id } => {
            prior_assignment.map(|p| ClassificationConflict {
                prior_assignment_id: p.assignment_id.clone(),
                prior_alternative_id: p.selected_alternative_id.clone(),
                proposed_alternative_id: alternative_id.clone(),
            })
        }
        _ => None,
    }
}

#[derive(Serialize)]
struct OrientationResultPreimage<'a> {
    profile_digest: &'a str,
    policy_digest: &'a str,
    target_id: &'a ArtifactId,
    target_revision: &'a str,
    disposition: ClassificationDisposition,
    selected_alternative_id: &'a Option<ArtifactId>,
    traces: &'a [AlternativeTrace],
    omitted_alternatives: &'a [ArtifactId],
    conflict: &'a Option<ClassificationConflict>,
    budget: &'a BudgetReceipt,
    reason: &'a str,
}

fn orientation_result_digest(
    result: &OrientationClassificationResult,
) -> Result<String, ContractViolation> {
    let preimage = OrientationResultPreimage {
        profile_digest: &result.profile_digest,
        policy_digest: &result.policy_digest,
        target_id: &result.target_id,
        target_revision: &result.target_revision,
        disposition: result.disposition,
        selected_alternative_id: &result.selected_alternative_id,
        traces: &result.traces,
        omitted_alternatives: &result.omitted_alternatives,
        conflict: &result.conflict,
        budget: &result.budget,
        reason: &result.reason,
    };
    Ok(digest_hex(&canonical_bytes(&preimage)?))
}
fn empty_snapshot() -> ClassificationAssignmentSnapshot {
    ClassificationAssignmentSnapshot {
        alternative_id: None,
        family_ref: None,
        subtype_ref: None,
        assignment_digest: None,
    }
}
fn unique_ids(mut ids: Vec<ArtifactId>) -> Vec<ArtifactId> {
    let mut seen = BTreeSet::new();
    ids.retain(|id| seen.insert(id.as_str().to_owned()));
    ids.sort_by_key(|id| id.as_str().to_owned());
    ids
}
fn reconcile_output(result: &mut ClassificationResult, max: u64) -> Result<(), ContractViolation> {
    for _ in 0..8 {
        let previous = result.budget.output_bytes;
        let len = u64::try_from(canonical_bytes(result)?.len()).map_err(|_| {
            ContractViolation::Budget {
                dimension: "output_bytes",
                reason: "output length cannot be represented".to_owned(),
            }
        })?;
        if len > max {
            return Err(ContractViolation::Budget {
                dimension: "output_bytes",
                reason: format!("{len} exceeds {max}"),
            });
        }
        if previous == len {
            return Ok(());
        }
        result.budget.output_bytes = len;
    }
    Ok(())
}
#[derive(Serialize)]
struct ResultPreimage<'a> {
    disposition: ClassificationDisposition,
    candidate: &'a Option<ClassificationCandidate>,
    sealed_identity: &'a Option<String>,
    traces: &'a [AlternativeTrace],
    omitted_alternatives: &'a [ArtifactId],
    conflict: &'a Option<ClassificationConflict>,
    budget: &'a BudgetReceipt,
    reason: &'a str,
}

fn digest_result(result: &ClassificationResult) -> Result<String, ContractViolation> {
    let sealed_identity = result
        .sealed
        .as_ref()
        .map(|closure| {
            closure
                .canonical_bytes()
                .map(|bytes| eliot_dreamer_contracts::digest_hex(&bytes))
        })
        .transpose()?;
    let pre = ResultPreimage {
        disposition: result.disposition,
        candidate: &result.candidate,
        sealed_identity: &sealed_identity,
        traces: &result.traces,
        omitted_alternatives: &result.omitted_alternatives,
        conflict: &result.conflict,
        budget: &result.budget,
        reason: &result.reason,
    };
    Ok(eliot_dreamer_contracts::digest_hex(&canonical_bytes(&pre)?))
}
