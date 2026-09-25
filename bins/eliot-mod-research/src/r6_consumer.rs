//! Evidence-first R6 consumer.
//!
//! Submission and provider acknowledgement are not inquiry outcomes. This
//! module accepts only a completed exchange job, derives source/coverage/
//! audit/debt material from its typed provider bundle, and applies the
//! closure gates before producing a candidate disposition.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde::Serialize;

use eliot_epistemic_contracts::ClaimAuditOutcome;
use eliot_research_exchange::{ExchangeJob, ExchangeStatus};
use eliot_research_exchange_api::{
    CompletionDisposition, CoverageGap, ResearchEvidenceBundle, ResearchQueryRequest,
    SourceSnapshot,
};
use eliot_researcher::{
    ClaimAudit, EvidenceFreeze, EvidenceGrade, InquiryDisposition, InquiryDispositionRecord,
    InquiryLane, InquiryReopenGate, ResearchDebt, ResearchDebtKind, ResearchDebtProblemBinding,
    SourceAdmissibilityRecord, SourceEligibility, SourceIndependence, SourceLimits, SourceProposal,
    SourceProvenance, SourceTaint, TaskGraphCompilationReceipt, TaskGraphCompilationRequest,
    UnsupportedPrecisionItem,
};
use eliot_store_api::WriteReceiptStatus;

use super::{R6CompositionError, R6SubmissionOutput, canonical_digest, sha256_hex};

/// Coverage accounting derived only from the completed provider bundle and
/// its owner-bound request. No caller-provided coverage projection is
/// accepted.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct R6CoverageReceipt {
    expected_handles: Vec<String>,
    observed_handles: Vec<String>,
    gap_handles: Vec<String>,
    unknown_handles: Vec<String>,
    failed_acquisition: Vec<String>,
    invalidation: Option<String>,
    complete_scope: bool,
    denominator_kind: String,
    denominator_digest: String,
    digest: String,
}

fn derive_r6_coverage(
    bundle: &ResearchEvidenceBundle,
    query: &ResearchQueryRequest,
) -> Result<R6CoverageReceipt, R6CompositionError> {
    let expected: BTreeSet<String> = query
        .allowed_references
        .source_handles
        .iter()
        .chain(query.allowed_references.evidence_handles.iter())
        .chain(query.allowed_references.artifact_handles.iter())
        .cloned()
        .collect();
    let observed: BTreeSet<String> = bundle
        .sources
        .iter()
        .map(|source| source.source_handle.clone())
        .chain(bundle.artifact_handles.iter().cloned())
        .collect();
    let gaps: BTreeSet<String> = bundle
        .coverage_gaps
        .iter()
        .map(|gap| gap.source_handle.clone())
        .collect();
    let unknown: BTreeSet<String> = bundle.coverage_unknowns.iter().cloned().collect();
    let failed: BTreeSet<String> = bundle.failed_acquisition.iter().cloned().collect();
    let invalidation = bundle.invalidation.clone();
    if observed.intersection(&gaps).next().is_some()
        || observed.intersection(&unknown).next().is_some()
        || !expected.is_superset(&observed)
        || !expected.is_superset(&gaps)
    {
        return Err(R6CompositionError::InvalidBinding(
            "provider coverage contains a source outside the exact denominator or overlaps a gap"
                .to_owned(),
        ));
    }
    let accounted: BTreeSet<String> = observed.union(&gaps).cloned().collect();
    let complete_scope = expected == accounted
        && unknown.is_empty()
        && failed.is_empty()
        && invalidation.is_none()
        && bundle.coverage_gaps.is_empty();
    let denominator_digest = canonical_digest(&(
        &query.exchange_id,
        &query.allowed_references.digest,
        &expected,
    ))?;
    let expected_handles = expected.into_iter().collect::<Vec<_>>();
    let observed_handles = observed.into_iter().collect::<Vec<_>>();
    let gap_handles = gaps.into_iter().collect::<Vec<_>>();
    let unknown_handles = unknown.into_iter().collect::<Vec<_>>();
    let failed_acquisition = failed.into_iter().collect::<Vec<_>>();
    let digest = canonical_digest(&(
        &expected_handles,
        &observed_handles,
        &gap_handles,
        &unknown_handles,
        &failed_acquisition,
        &invalidation,
        complete_scope,
        if complete_scope {
            "complete_scope"
        } else {
            "unknown"
        },
        &denominator_digest,
    ))?;
    Ok(R6CoverageReceipt {
        expected_handles,
        observed_handles,
        gap_handles,
        unknown_handles,
        failed_acquisition,
        invalidation,
        complete_scope,
        denominator_kind: if complete_scope {
            "complete_scope".to_owned()
        } else {
            "unknown".to_owned()
        },
        denominator_digest,
        digest,
    })
}

/// Output from the evidence-consuming half of R6. The exchange job is
/// required to be `Completed` with a result; an `Accepted` job is never
/// interpreted as an answer.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct R6CompletedOutput {
    inquiry_id: String,
    binding: eliot_researcher::InquiryExecutionBinding,
    task_compilation: TaskGraphCompilationReceipt,
    canonical_compilation_receipt: eliot_store_api::WriteReceipt,
    exchange_job: ExchangeJob,
    source_records: Vec<SourceAdmissibilityRecord>,
    coverage: R6CoverageReceipt,
    evidence_freeze: Option<EvidenceFreeze>,
    claim_audits: Vec<ClaimAudit>,
    research_debts: Vec<ResearchDebt>,
    problem_bindings: Vec<ResearchDebtProblemBinding>,
    unsupported_precision: Vec<UnsupportedPrecisionItem>,
    disposition: InquiryDispositionRecord,
    /// Candidate reopen authorization for a non-closing result. The Task
    /// Controller/Governor still owns the actual reopen transition.
    reopen_gate: Option<InquiryReopenGate>,
    candidate_only: bool,
    canonical_write_authorized: bool,
}

/// Read-only production projection of the completed R6 consumer. It has no
/// public constructor and exposes only serialization/audit access to the
/// private candidate record.
#[derive(Clone, Debug, Serialize)]
pub struct R6CompletionProjection {
    completed: R6CompletedOutput,
}

impl R6CompletionProjection {
    pub(crate) fn from_completed(completed: R6CompletedOutput) -> Self {
        Self { completed }
    }

    /// Serializes the immutable candidate projection for an authenticated
    /// owner surface; this does not create a canonical write.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.completed)
    }

    /// Returns whether the projection is candidate-only.
    #[must_use]
    pub const fn candidate_only(&self) -> bool {
        self.completed.candidate_only
    }

    /// Returns whether canonical writing is authorized (always false for this
    /// candidate record).
    #[must_use]
    pub const fn canonical_write_authorized(&self) -> bool {
        self.completed.canonical_write_authorized
    }
}

fn source_proposal(
    source: &SourceSnapshot,
    submission: &R6SubmissionOutput,
    route: &str,
) -> Result<SourceProposal, R6CompositionError> {
    let profile = &submission.binding.profile;
    let query = &submission.binding.query;
    let captured = source
        .captured_at
        .valid_time_ms
        .or(source.captured_at.known_time_ms)
        .ok_or_else(|| {
            R6CompositionError::InvalidBinding(
                "provider source has no observed capture time".to_owned(),
            )
        })?;
    Ok(SourceProposal {
        task_id: profile.task_id.clone(),
        task_definition_digest: profile.task_definition_digest.clone(),
        profile_id: profile.profile_id.clone(),
        profile_revision: profile.revision,
        profile_digest: profile.digest.clone(),
        provenance: SourceProvenance {
            source_handle: source.source_handle.clone(),
            source_class: source.class,
            locator: source.locator.clone(),
            content_digest: source.snapshot_digest.clone(),
            operation_id: submission.binding.provider_operation_id.clone(),
            receipt_handle: submission.raw_evidence_digest.clone(),
            route_id: route.to_owned(),
            provider_generation: submission.binding.provider_generation.clone(),
            state_fence: submission.binding.state_fence.clone(),
            // A provider source snapshot does not prove common lineage. Keeping
            // this unknown prevents repeated/derived sources from receiving
            // independent-source credit.
            lineage_root: None,
        },
        requested_anchor_precision: query.allowed_references.allowed_anchor_precision,
        independence: SourceIndependence::Unknown,
        evidence_set_id: submission.binding.evidence_set_id.clone(),
        scope: query.question_scope.clone(),
        assessment_time_ms: captured,
        taint: BTreeSet::<SourceTaint>::new(),
        limits: SourceLimits {
            max_anchor_precision: query.allowed_references.allowed_anchor_precision,
            allowed_uses: profile.allowed_uses.clone(),
            freshness_deadline_ms: Some(query.deadline_ms),
            retrieved_at_ms: Some(captured),
            disclosure: query.disclosure,
        },
    })
}

fn derive_source_records(
    bundle: &ResearchEvidenceBundle,
    submission: &R6SubmissionOutput,
) -> Result<Vec<SourceAdmissibilityRecord>, R6CompositionError> {
    if submission.binding.routes.len() != 1 {
        return Err(R6CompositionError::InvalidBinding(
            "provider evidence does not carry an exact route projection for multiple routes"
                .to_owned(),
        ));
    }
    let route = submission.binding.routes.first().cloned().ok_or_else(|| {
        R6CompositionError::InvalidBinding("owner binding has no admitted route".to_owned())
    })?;
    bundle
        .sources
        .iter()
        .map(|source| {
            let proposal = source_proposal(source, submission, &route)?;
            SourceAdmissibilityRecord::evaluate(
                &submission.binding.profile,
                &submission.binding.evidence_set_id,
                &proposal,
            )
            .map_err(R6CompositionError::Governance)
        })
        .collect()
}

fn derive_audits(
    bundle: &ResearchEvidenceBundle,
    submission: &R6SubmissionOutput,
) -> Result<(Vec<ClaimAudit>, Vec<UnsupportedPrecisionItem>), R6CompositionError> {
    let mut audits = Vec::with_capacity(bundle.claims.len());
    let mut unsupported = Vec::new();
    for claim in &bundle.claims {
        audits.push(
            ClaimAudit::from_provider_claim(
                &submission.binding.profile,
                &submission.binding.query.allowed_references,
                claim,
            )
            .map_err(R6CompositionError::Governance)?,
        );
        for citation in &claim.citations {
            if citation.excerpt.as_deref().is_none_or(str::is_empty)
                || submission
                    .binding
                    .query
                    .allowed_references
                    .allowed_anchor_precision
                    < citation.precision
            {
                unsupported.push(UnsupportedPrecisionItem {
                    asserted: format!("{}:{}", citation.source_handle, citation.anchor),
                    highest_supported: format!(
                        "{:?}",
                        submission
                            .binding
                            .query
                            .allowed_references
                            .allowed_anchor_precision
                    ),
                    basis: "provider evidence bundle".to_owned(),
                    risk: "provider citation is outside the admitted anchor/excerpt contract"
                        .to_owned(),
                    required_probe: "obtain an exact admitted excerpt or narrow the claim"
                        .to_owned(),
                });
            }
        }
    }
    Ok((audits, unsupported))
}

fn derive_debts(
    bundle: &ResearchEvidenceBundle,
    submission: &R6SubmissionOutput,
    audits: &[ClaimAudit],
    unsupported: &[UnsupportedPrecisionItem],
) -> Result<Vec<ResearchDebt>, R6CompositionError> {
    let mut debts = Vec::new();
    for gap in &bundle.coverage_gaps {
        debts.push(
            ResearchDebt::new(
                format!("debt-{}", gap.source_handle),
                ResearchDebtKind::Coverage,
                gap.detail.clone(),
                "Researcher",
                "reconcile the admitted coverage gap with a new provider attempt",
                Some(submission.binding.query.deadline_ms),
            )
            .map_err(R6CompositionError::Governance)?,
        );
    }
    for unknown in &bundle.coverage_unknowns {
        debts.push(
            ResearchDebt::new(
                format!("debt-unknown-{unknown}"),
                ResearchDebtKind::Epistemic,
                unknown.clone(),
                "Researcher",
                "resolve the explicit unknown before strong release",
                Some(submission.binding.query.deadline_ms),
            )
            .map_err(R6CompositionError::Governance)?,
        );
    }
    for failed in &bundle.failed_acquisition {
        debts.push(
            ResearchDebt::new(
                format!("debt-failed-{failed}"),
                ResearchDebtKind::Provenance,
                failed.clone(),
                "Researcher",
                "reconcile failed acquisition with immutable raw evidence",
                Some(submission.binding.query.deadline_ms),
            )
            .map_err(R6CompositionError::Governance)?,
        );
    }
    if let Some(invalidation) = &bundle.invalidation {
        debts.push(
            ResearchDebt::new(
                format!("debt-invalidation-{}", sha256_hex(invalidation.as_bytes())),
                ResearchDebtKind::Authority,
                invalidation.clone(),
                "Researcher",
                "reconcile invalidated provider evidence before any release",
                Some(submission.binding.query.deadline_ms),
            )
            .map_err(R6CompositionError::Governance)?,
        );
    }
    for audit in audits {
        if audit.canonical_outcome != ClaimAuditOutcome::Supported {
            debts.push(
                ResearchDebt::new(
                    format!("debt-audit-{}", audit.claim_id),
                    ResearchDebtKind::Verification,
                    format!("claim audit is {:?}", audit.canonical_outcome),
                    "Researcher",
                    "resolve the claim audit before release",
                    Some(submission.binding.query.deadline_ms),
                )
                .map_err(R6CompositionError::Governance)?,
            );
        }
    }
    for item in unsupported {
        debts.push(
            ResearchDebt::new(
                format!("debt-precision-{}", item.asserted),
                ResearchDebtKind::Fidelity,
                format!("unsupported precision: {}", item.risk),
                "Researcher",
                "obtain exact admitted evidence or narrow the claim",
                Some(submission.binding.query.deadline_ms),
            )
            .map_err(R6CompositionError::Governance)?,
        );
    }
    Ok(debts)
}

fn build_freeze(
    bundle: &ResearchEvidenceBundle,
    submission: &R6SubmissionOutput,
    coverage: &R6CoverageReceipt,
    debts: &[ResearchDebt],
) -> Result<Option<EvidenceFreeze>, R6CompositionError> {
    if bundle.sources.is_empty() {
        return Ok(None);
    }
    let mut frozen_at_ms: Option<i64> = None;
    for source in &bundle.sources {
        let Some(observed_at) = source
            .captured_at
            .valid_time_ms
            .or(source.captured_at.known_time_ms)
        else {
            return Ok(None);
        };
        frozen_at_ms = Some(frozen_at_ms.map_or(observed_at, |current| current.max(observed_at)));
    }
    let frozen_at_ms = frozen_at_ms.ok_or_else(|| {
        R6CompositionError::InvalidBinding("evidence freeze has no observed source time".to_owned())
    })?;
    Ok(Some(
        EvidenceFreeze::new(
            format!("freeze-{}", submission.binding.evidence_set_id),
            &submission.binding.profile,
            submission.binding.portfolio_digest.clone(),
            submission.binding.manifest_digest.clone(),
            coverage.digest.clone(),
            bundle
                .sources
                .iter()
                .map(|source| source.source_handle.clone())
                .collect(),
            bundle
                .coverage_gaps
                .iter()
                .map(|gap| gap.source_handle.clone())
                .collect(),
            bundle
                .claims
                .iter()
                .flat_map(|claim| claim.counterclaim_ids.clone())
                .collect(),
            debts.iter().map(|debt| debt.debt_id.clone()).collect(),
            frozen_at_ms,
        )
        .map_err(R6CompositionError::Governance)?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn disposition_for(
    bundle: &ResearchEvidenceBundle,
    coverage: &R6CoverageReceipt,
    source_records: &[SourceAdmissibilityRecord],
    freeze: Option<&EvidenceFreeze>,
    audits: &[ClaimAudit],
    debts: &[ResearchDebt],
    unsupported: &[UnsupportedPrecisionItem],
    profile: &eliot_researcher::InquiryProtocolProfile,
) -> Result<InquiryDisposition, R6CompositionError> {
    match bundle.disposition {
        CompletionDisposition::AnsweredWithSupportedResult => {
            if !coverage.complete_scope
                || source_records.is_empty()
                || source_records
                    .iter()
                    .any(|record| record.eligibility != SourceEligibility::Eligible)
                || freeze.is_none()
                || audits.is_empty()
                || audits
                    .iter()
                    .any(|audit| audit.canonical_outcome != ClaimAuditOutcome::Supported)
                || !debts.is_empty()
                || !unsupported.is_empty()
                || bundle.invalidation.is_some()
            {
                return Err(R6CompositionError::InvalidBinding(
                    "answered disposition lacks eligible sources, a freeze, audits, or complete coverage"
                        .to_owned(),
                ));
            }
            if profile.evidence_grade == EvidenceGrade::ScienceGrade {
                if !matches!(
                    profile.lane,
                    InquiryLane::Confirmatory | InquiryLane::MixedWithDeclaredSplit
                ) {
                    return Err(R6CompositionError::InvalidBinding(
                        "E3/ScienceGrade output requires a confirmatory or declared-split lane"
                            .to_owned(),
                    ));
                }
                let independent_families = source_records
                    .iter()
                    .filter(|record| record.independence == SourceIndependence::Known)
                    .count();
                let minimum_independent_families = usize::try_from(
                    profile
                        .independence_and_blinding_policy
                        .minimum_independent_families,
                )
                .map_err(|_| {
                    R6CompositionError::InvalidBinding(
                        "E3 independent-family floor is not representable".to_owned(),
                    )
                })?;
                if independent_families < minimum_independent_families {
                    return Err(R6CompositionError::InvalidBinding(
                        "E3/ScienceGrade output lacks the declared independent-family floor"
                            .to_owned(),
                    ));
                }
            }
            Ok(InquiryDisposition::AnsweredWithSupportedResult)
        }
        CompletionDisposition::NoMatchInCompleteScope => {
            if !coverage.complete_scope
                || bundle.sources.is_empty()
                || source_records.is_empty()
                || source_records
                    .iter()
                    .any(|record| record.eligibility != SourceEligibility::Eligible)
                || freeze.is_none()
                || !bundle.claims.is_empty()
                || !audits.is_empty()
                || !debts.is_empty()
                || !unsupported.is_empty()
                || bundle.invalidation.is_some()
            {
                return Err(R6CompositionError::InvalidBinding(
                    "negative disposition requires a complete denominator with eligible frozen evidence and no unknown or partial result"
                        .to_owned(),
                ));
            }
            Ok(InquiryDisposition::NoMatchInCompleteScope)
        }
        CompletionDisposition::SourceUnavailable => Ok(InquiryDisposition::SourceUnavailable),
        CompletionDisposition::StaleSourceOrIndex => Ok(InquiryDisposition::StaleSourceOrIndex),
        CompletionDisposition::PolicyOrDisclosureDenied => {
            Ok(InquiryDisposition::PolicyOrDisclosureDenied)
        }
        CompletionDisposition::IncompleteCoverage => Ok(InquiryDisposition::IncompleteCoverage),
        CompletionDisposition::NoNewUsefulEvidence => Ok(InquiryDisposition::NoNewUsefulEvidence),
        CompletionDisposition::Inconclusive => Ok(InquiryDisposition::Inconclusive),
        CompletionDisposition::Cancelled => Ok(InquiryDisposition::Cancelled),
    }
}

fn validate_submission(submission: &R6SubmissionOutput) -> Result<(), R6CompositionError> {
    submission
        .binding
        .validate_integrity()
        .map_err(R6CompositionError::Governance)?;
    if submission.raw_evidence_digest.len() != 64
        || submission
            .raw_evidence_digest
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(R6CompositionError::InvalidBinding(
            "R6 completion has no canonical raw provider evidence binding".to_owned(),
        ));
    }
    if !submission.candidate_only() || submission.canonical_write_authorized() {
        return Err(R6CompositionError::InvalidBinding(
            "R6 submission is not candidate-only".to_owned(),
        ));
    }
    if submission.canonical_compilation_receipt.validate().is_err()
        || submission.canonical_compilation_receipt.status != WriteReceiptStatus::Committed
        || submission.canonical_compilation_receipt.transition_class
            != eliot_store_api::TransitionClass::CaptureCandidate
        || submission.canonical_compilation_receipt.state_fence != submission.binding.state_fence
    {
        return Err(R6CompositionError::InvalidBinding(
            "R6 compiler receipt was not durably committed before evidence consumption".to_owned(),
        ));
    }
    let request = TaskGraphCompilationRequest {
        task_id: submission.binding.profile.task_id.clone(),
        task_definition_digest: submission.binding.profile.task_definition_digest.clone(),
        profile_id: submission.binding.profile.profile_id.clone(),
        profile_revision: submission.binding.profile.revision,
        profile_digest: submission.binding.profile.digest.clone(),
        obligation_ids: submission.task_compilation.obligation_ids().to_vec(),
        obligation_digests: submission.task_compilation.obligation_digests().to_vec(),
        state_fence: submission.binding.state_fence.clone(),
        inquiry_binding_digest: submission.binding.digest.clone(),
    };
    submission
        .task_compilation
        .validate_against(&request)
        .map_err(|error| R6CompositionError::InvalidBinding(error.to_string()))?;
    Ok(())
}

/// Consumes one completed admitted provider result and derives all R6
/// candidate artifacts from it. This is the only closure-bearing consumer;
/// submission and provider acknowledgement are intentionally insufficient.
#[allow(clippy::too_many_lines)]
pub(crate) fn compose_r6_completed(
    submission: &R6SubmissionOutput,
) -> Result<R6CompletedOutput, R6CompositionError> {
    validate_submission(submission)?;
    if submission.exchange_job.status != ExchangeStatus::Completed
        || submission.exchange_job.result.is_none()
    {
        return Err(R6CompositionError::InvalidBinding(
            "an Accepted or non-completed exchange job cannot close or govern R6".to_owned(),
        ));
    }
    let bundle = submission.exchange_job.result.as_ref().ok_or_else(|| {
        R6CompositionError::InvalidBinding("completed exchange job has no result bundle".to_owned())
    })?;
    bundle
        .validate_against(&submission.binding.query)
        .map_err(|error| R6CompositionError::InvalidBinding(error.to_string()))?;
    if bundle.exchange_id != submission.binding.query.exchange_id
        || bundle.job_id != submission.exchange_job.job_id
        || bundle.state_fence != submission.binding.state_fence
        || bundle.system_generation != submission.binding.provider_generation
        || (bundle.origin_authentication != submission.binding.provider_operation_id
            && bundle.origin_authentication != submission.binding.provider_admission_digest)
    {
        return Err(R6CompositionError::InvalidBinding(
            "provider result is not bound to the owner-issued exchange job/fence".to_owned(),
        ));
    }
    let coverage = derive_r6_coverage(bundle, &submission.binding.query)?;
    let source_records = derive_source_records(bundle, submission)?;
    let (claim_audits, unsupported_precision) = derive_audits(bundle, submission)?;
    let research_debts = derive_debts(bundle, submission, &claim_audits, &unsupported_precision)?;
    let problem_evidence_refs: BTreeSet<String> = bundle
        .coverage_gaps
        .iter()
        .map(|gap| gap.source_handle.clone())
        .chain(bundle.coverage_unknowns.iter().cloned())
        .chain(bundle.failed_acquisition.iter().cloned())
        .chain(std::iter::once(bundle.immutable_bundle_digest.clone()))
        .chain(bundle.invalidation.clone())
        .collect();
    let problem_bindings = research_debts
        .iter()
        .map(|debt| {
            debt.problem_binding(
                &submission.inquiry_id,
                &submission.binding.profile.task_id,
                &submission.binding.profile.digest,
                &submission.binding.state_fence,
                problem_evidence_refs.iter().cloned().collect(),
            )
            .map_err(R6CompositionError::Governance)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let evidence_freeze = build_freeze(bundle, submission, &coverage, &research_debts)?;
    let disposition = disposition_for(
        bundle,
        &coverage,
        &source_records,
        evidence_freeze.as_ref(),
        &claim_audits,
        &research_debts,
        &unsupported_precision,
        &submission.binding.profile,
    )?;
    let continuation = if disposition.may_close() {
        None
    } else {
        Some(
            bundle
                .coverage_gaps
                .first()
                .map(|gap: &CoverageGap| gap.detail.clone())
                .or_else(|| bundle.coverage_unknowns.first().cloned())
                .unwrap_or_else(|| "reopen with a newly admitted provider result".to_owned()),
        )
    };
    let disposition_record = InquiryDispositionRecord::new(
        &submission.inquiry_id,
        &submission.binding.profile,
        &submission.binding.evidence_set_id,
        Some(submission.binding.portfolio_digest.clone()),
        Some(submission.binding.manifest_digest.clone()),
        Some(coverage.digest.clone()),
        disposition,
        continuation,
        None,
        if disposition.may_close() {
            None
        } else {
            Some("provider result remains open".to_owned())
        },
    )
    .map_err(R6CompositionError::Governance)?;
    let reopen_gate = if disposition.may_close() {
        None
    } else {
        let evidence_refs: BTreeSet<String> = bundle
            .coverage_gaps
            .iter()
            .map(|gap| gap.source_handle.clone())
            .chain(bundle.coverage_unknowns.iter().cloned())
            .chain(bundle.failed_acquisition.iter().cloned())
            .chain(std::iter::once(bundle.immutable_bundle_digest.clone()))
            .collect();
        let reason = submission
            .binding
            .profile
            .output_contract_and_reopen_conditions
            .reopen_conditions
            .first()
            .cloned()
            .ok_or_else(|| {
                R6CompositionError::InvalidBinding(
                    "non-closing R6 profile has no declared reopen condition".to_owned(),
                )
            })?;
        Some(
            InquiryReopenGate::authorize(
                &submission.binding.profile,
                &disposition_record,
                evidence_refs.into_iter().collect(),
                reason,
            )
            .map_err(R6CompositionError::Governance)?,
        )
    };
    Ok(R6CompletedOutput {
        inquiry_id: submission.inquiry_id.clone(),
        binding: submission.binding.clone(),
        task_compilation: submission.task_compilation.clone(),
        canonical_compilation_receipt: submission.canonical_compilation_receipt.clone(),
        exchange_job: submission.exchange_job.clone(),
        source_records,
        coverage,
        evidence_freeze,
        claim_audits,
        research_debts,
        problem_bindings,
        unsupported_precision,
        disposition: disposition_record,
        reopen_gate,
        candidate_only: true,
        canonical_write_authorized: false,
    })
}

// Keep the digest helper in this module's public dependency surface obvious
// to static boundary checks without exposing a second canonicalization path.
#[allow(dead_code)]
fn _consumer_digest(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}
