//! Evidence-first R6 consumer.
//!
//! Submission and provider acknowledgement are not inquiry outcomes. This
//! module accepts only a completed exchange job, derives source/coverage/
//! audit/debt material from its typed provider bundle, and applies the
//! closure gates before producing a candidate disposition.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use eliot_epistemic_contracts::ClaimAuditOutcome;
use eliot_research_exchange::{ExchangeJob, ExchangeStatus};
use eliot_research_exchange_api::{
    CompletionDisposition, CoverageGap, ResearchEvidenceBundle, ResearchQueryRequest,
    SourceSnapshot,
};
use eliot_researcher::{
    ClaimAudit, EvidenceFreeze, EvidenceGrade, InquiryDisposition, InquiryDispositionRecord,
    InquiryLane, ResearchDebt, ResearchDebtKind, ResearchDebtProblemBinding,
    SourceAdmissibilityRecord,
    SourceEligibility, SourceIndependence, SourceLimits, SourceProposal, SourceProvenance,
    SourceTaint, TaskGraphCompilationReceipt, UnsupportedPrecisionItem,
};

use super::{R6CompositionError, R6SubmissionOutput, canonical_digest, sha256_hex};

/// Coverage accounting derived only from the completed provider bundle and
/// its owner-bound request. No caller-provided coverage projection is
/// accepted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R6CoverageReceipt {
    pub expected_handles: Vec<String>,
    pub observed_handles: Vec<String>,
    pub gap_handles: Vec<String>,
    pub unknown_handles: Vec<String>,
    pub failed_acquisition: Vec<String>,
    pub complete_scope: bool,
    pub denominator_digest: String,
    pub digest: String,
}

fn derive_r6_coverage(
    bundle: &ResearchEvidenceBundle,
    query: &ResearchQueryRequest,
) -> Result<R6CoverageReceipt, R6CompositionError> {
    let expected: BTreeSet<String> = query
        .allowed_references
        .source_handles
        .iter()
        .cloned()
        .collect();
    let observed: BTreeSet<String> = bundle
        .sources
        .iter()
        .map(|source| source.source_handle.clone())
        .collect();
    let gaps: BTreeSet<String> = bundle
        .coverage_gaps
        .iter()
        .map(|gap| gap.source_handle.clone())
        .collect();
    let unknown: BTreeSet<String> = bundle.coverage_unknowns.iter().cloned().collect();
    let failed: BTreeSet<String> = bundle.failed_acquisition.iter().cloned().collect();
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
        complete_scope,
        &denominator_digest,
    ))?;
    Ok(R6CoverageReceipt {
        expected_handles,
        observed_handles,
        gap_handles,
        unknown_handles,
        failed_acquisition,
        complete_scope,
        denominator_digest,
        digest,
    })
}

/// Output from the evidence-consuming half of R6. The exchange job is
/// required to be `Completed` with a result; an `Accepted` job is never
/// interpreted as an answer.
#[derive(Clone, Debug, Serialize)]
pub struct R6CompletedOutput {
    pub inquiry_id: String,
    pub binding: eliot_researcher::InquiryExecutionBinding,
    pub task_compilation: TaskGraphCompilationReceipt,
    pub exchange_job: ExchangeJob,
    pub source_records: Vec<SourceAdmissibilityRecord>,
    pub coverage: R6CoverageReceipt,
    pub evidence_freeze: Option<EvidenceFreeze>,
    pub claim_audits: Vec<ClaimAudit>,
    pub research_debts: Vec<ResearchDebt>,
    pub problem_bindings: Vec<ResearchDebtProblemBinding>,
    pub unsupported_precision: Vec<UnsupportedPrecisionItem>,
    pub disposition: InquiryDispositionRecord,
    pub candidate_only: bool,
    pub canonical_write_authorized: bool,
}

fn source_proposal(
    source: &SourceSnapshot,
    bundle: &ResearchEvidenceBundle,
    submission: &R6SubmissionOutput,
    route: &str,
) -> SourceProposal {
    let profile = &submission.binding.profile;
    let query = &submission.binding.query;
    let captured = source
        .captured_at
        .valid_time_ms
        .or(source.captured_at.known_time_ms)
        .unwrap_or(1);
    SourceProposal {
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
            operation_id: submission.binding.provider_admission_digest.clone(),
            receipt_handle: bundle.immutable_bundle_digest.clone(),
            route_id: route.to_owned(),
            provider_generation: submission.binding.provider_admission_digest.clone(),
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
    }
}

fn derive_source_records(
    bundle: &ResearchEvidenceBundle,
    submission: &R6SubmissionOutput,
) -> Result<Vec<SourceAdmissibilityRecord>, R6CompositionError> {
    let route = submission
        .binding
        .routes
        .first()
        .cloned()
        .ok_or_else(|| R6CompositionError::InvalidBinding("owner binding has no admitted route".to_owned()))?;
    bundle
        .sources
        .iter()
        .map(|source| {
            SourceAdmissibilityRecord::evaluate(
                &submission.binding.profile,
                &submission.binding.evidence_set_id,
                &source_proposal(source, bundle, submission, &route),
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
            if citation.excerpt.is_none()
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
    let frozen_at_ms = bundle
        .sources
        .first()
        .and_then(|source| source.captured_at.valid_time_ms)
        .unwrap_or(1);
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

fn disposition_for(
    bundle: &ResearchEvidenceBundle,
    coverage: &R6CoverageReceipt,
    source_records: &[SourceAdmissibilityRecord],
    freeze: &Option<EvidenceFreeze>,
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
            {
                return Err(R6CompositionError::InvalidBinding(
                    "answered disposition lacks eligible sources, a freeze, audits, or complete coverage"
                        .to_owned(),
                ));
            }
            if profile.evidence_grade == EvidenceGrade::ScienceGrade
                && !matches!(
                    profile.lane,
                    InquiryLane::Confirmatory | InquiryLane::MixedWithDeclaredSplit
                )
            {
                return Err(R6CompositionError::InvalidBinding(
                    "E3/ScienceGrade output requires a confirmatory or declared-split lane"
                        .to_owned(),
                ));
            }
            Ok(InquiryDisposition::AnsweredWithSupportedResult)
        }
        CompletionDisposition::NoMatchInCompleteScope => {
            if !coverage.complete_scope
                || !bundle.sources.is_empty()
                || !bundle.claims.is_empty()
                || !bundle.coverage_unknowns.is_empty()
                || !bundle.failed_acquisition.is_empty()
            {
                return Err(R6CompositionError::InvalidBinding(
                    "negative disposition requires a complete denominator with no unknown or partial result"
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

/// Consumes one completed admitted provider result and derives all R6
/// candidate artifacts from it. This is the only closure-bearing consumer;
/// submission and provider acknowledgement are intentionally insufficient.
pub fn compose_r6_completed(
    submission: &R6SubmissionOutput,
) -> Result<R6CompletedOutput, R6CompositionError> {
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
    {
        return Err(R6CompositionError::InvalidBinding(
            "provider result is not bound to the owner-issued exchange job/fence".to_owned(),
        ));
    }
    let coverage = derive_r6_coverage(bundle, &submission.binding.query)?;
    let source_records = derive_source_records(bundle, submission)?;
    let (claim_audits, unsupported_precision) = derive_audits(bundle, submission)?;
    let research_debts = derive_debts(bundle, submission)?;
    let problem_bindings = research_debts
        .iter()
        .map(|debt| {
            debt.problem_binding(
                &submission.inquiry_id,
                &submission.binding.profile.task_id,
                &submission.binding.profile.digest,
                &submission.binding.state_fence,
                bundle
                    .coverage_gaps
                    .iter()
                    .map(|gap| gap.source_handle.clone())
                    .chain(bundle.coverage_unknowns.iter().cloned())
                    .collect(),
            )
            .map_err(R6CompositionError::Governance)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let evidence_freeze = build_freeze(bundle, submission, &coverage, &research_debts)?;
    let disposition = disposition_for(
        bundle,
        &coverage,
        &source_records,
        &evidence_freeze,
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
    Ok(R6CompletedOutput {
        inquiry_id: submission.inquiry_id.clone(),
        binding: submission.binding.clone(),
        task_compilation: submission.task_compilation.clone(),
        exchange_job: submission.exchange_job.clone(),
        source_records,
        coverage,
        evidence_freeze,
        claim_audits,
        research_debts,
        problem_bindings,
        unsupported_precision,
        disposition: disposition_record,
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
