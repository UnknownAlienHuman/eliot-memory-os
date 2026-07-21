use eliot_types::{
    CalibrationCorpusEligibility, CalibrationCorpusSampleKind, CalibrationEvidenceClass,
    CalibrationEvidenceCounts, CalibrationEvidenceGapReport, CalibrationExcludedCounts,
    CalibrationIntegrityStatus, CampaignIntegrityIncidentDetails, CampaignIntegrityIncidentStatus,
    CampaignIntegrityRootCauseStatus, DelegationCalibrationCampaign,
    DelegationCalibrationCampaignCloseoutStatus, DelegationCalibrationCampaignState,
    DelegationCalibrationCampaignTransition, DelegationCalibrationConfig,
    DelegationCalibrationReadiness, DelegationCalibrationSample, DelegationCalibrationState,
    DelegationCalibrationTaskFamily, DelegationCounterfactualKind, DelegationCounterfactualLabel,
    DelegationDecisionKind, DelegationEvidenceFloorSnapshot, DelegationFamilyCalibration,
    DelegationFindingMateriality, DelegationPolicyCandidate, DelegationPolicyCandidateStatus,
    DelegationPolicyPromotionDecision, DelegationPolicyPromotionDecisionKind,
    DelegationPolicyPromotionReason, DelegationPromotionReadinessVerdict, DelegationReason,
    DelegationShadowDecisionKind, DelegationShadowRecord, DelegationTriggerChange,
    DelegationTriggerChangeKind, ExecutedProviderReview, ExecutedProviderReviewStatus,
    IncidentKind, IncidentRecord, IncidentSeverity, IncidentStatus, IndependentEvidenceKind,
    IndependentEvidenceResult, IndependentOutcomeEvidence, ProviderCallLineage,
    ProviderCallLineageTerminalState, ProviderCallReservation, ProviderCallReservationState,
    ProviderFindingDisposition, ProviderFindingMateriality, ProviderFindingNovelty,
    ProviderFindingVerdict, ProviderReviewPreRegistration, ProviderUtilityAssessment,
    ProviderUtilityReason, TaskId, WorkLeaseId,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use time::OffsetDateTime;

pub struct DelegationCalibrationIngestService;

impl DelegationCalibrationIngestService {
    pub fn ingest(
        &self,
        state: &mut DelegationCalibrationState,
        sample: DelegationCalibrationSample,
    ) -> Result<bool, String> {
        if state
            .samples
            .iter()
            .any(|existing| existing.sample_id == sample.sample_id)
        {
            return Ok(false);
        }
        if sample.evidence_class == CalibrationEvidenceClass::HistoricalImportedRecord
            && (!sample.completeness.route_decision_present
                || !sample.completeness.final_task_outcome_present)
        {
            return Err(
                "historical record requires complete source receipts and final outcome refs"
                    .to_owned(),
            );
        }
        state.samples.push(sample);
        Ok(true)
    }
}

#[derive(Clone, Debug, Default)]
pub struct DelegationOutcomeEvidence {
    pub verifier_refs: Vec<String>,
    pub human_evidence_refs: Vec<String>,
    pub accepted_findings: u32,
    pub rejected_findings: u32,
    pub duplicate_findings: u32,
    pub false_positive_findings: u32,
    pub malformed_findings: u32,
    pub changed_controller_decision: bool,
    pub provider_claimed_useful: bool,
}

pub struct DelegationOutcomeLabelService;

impl DelegationOutcomeLabelService {
    pub fn independent_evidence_present(&self, evidence: &DelegationOutcomeEvidence) -> bool {
        !evidence.verifier_refs.is_empty() || !evidence.human_evidence_refs.is_empty()
    }

    pub fn provider_useful(&self, evidence: &DelegationOutcomeEvidence) -> Option<bool> {
        if !self.independent_evidence_present(evidence) {
            return None;
        }
        Some(evidence.accepted_findings > 0 || evidence.changed_controller_decision)
    }

    pub fn false_positive_count(&self, evidence: &DelegationOutcomeEvidence) -> u32 {
        if self.independent_evidence_present(evidence) {
            evidence.false_positive_findings
        } else {
            0
        }
    }
}

pub struct DelegationCalibrationCampaignService;

pub struct ProviderReviewPreRegistrationService;

impl ProviderReviewPreRegistrationService {
    #[must_use]
    pub fn idempotency_key(
        campaign_id: &str,
        task_id: TaskId,
        provider: &str,
        baseline_commit: &str,
        frozen_input_hash: &str,
    ) -> String {
        stable_hash(&format!(
            "{campaign_id}\n{task_id}\n{provider}\n{baseline_commit}\n{frozen_input_hash}"
        ))
    }

    #[must_use]
    pub fn execution_token(preregistration: &ProviderReviewPreRegistration) -> String {
        format!(
            "l1c-once:{}",
            stable_hash(&format!(
                "{}\n{}\n{}\n{}",
                preregistration.preregistration_id,
                preregistration.campaign_id,
                preregistration.frozen_input_hash,
                preregistration.idempotency_key
            ))
        )
    }

    pub fn validate_token(
        preregistration: &ProviderReviewPreRegistration,
        token: &str,
    ) -> Result<(), String> {
        if preregistration.execution_token_hash != stable_hash(token) {
            return Err("execution token does not match sealed preregistration".to_owned());
        }
        if preregistration.max_provider_calls != 1 {
            return Err("sealed provider call budget cannot be widened".to_owned());
        }
        if preregistration.sealed_at < preregistration.created_at {
            return Err("preregistration sealed_at precedes created_at".to_owned());
        }
        Ok(())
    }

    pub fn validate_before_reservation(
        preregistration: &ProviderReviewPreRegistration,
        reservation: &ProviderCallReservation,
    ) -> Result<(), String> {
        if preregistration.sealed_at > reservation.reserved_at {
            return Err("preregistration was not sealed before reservation".to_owned());
        }
        if preregistration.campaign_id != reservation.campaign_id
            || preregistration.real_task_id != reservation.task_id
            || preregistration.idempotency_key != reservation.idempotency_key
            || preregistration.provider != reservation.provider
        {
            return Err("reservation does not match sealed preregistration".to_owned());
        }
        Ok(())
    }

    pub fn validate_sealed_replay(
        sealed: &ProviderReviewPreRegistration,
        candidate: &ProviderReviewPreRegistration,
    ) -> Result<(), String> {
        if sealed == candidate {
            return Ok(());
        }
        if sealed.frozen_input_hash != candidate.frozen_input_hash
            || sealed.review_questions != candidate.review_questions
            || sealed.materiality_rule != candidate.materiality_rule
            || sealed.independent_evidence_plan != candidate.independent_evidence_plan
            || sealed.utility_attribution_rule_version != candidate.utility_attribution_rule_version
            || sealed.max_provider_calls != candidate.max_provider_calls
            || sealed.idempotency_key != candidate.idempotency_key
        {
            return Err(
                "semantic amendment requires a new preregistration and campaign attempt".to_owned(),
            );
        }
        Ok(())
    }
}

impl DelegationCalibrationCampaignService {
    pub const fn is_terminal(state: DelegationCalibrationCampaignState) -> bool {
        matches!(
            state,
            DelegationCalibrationCampaignState::Closed
                | DelegationCalibrationCampaignState::ReleasedPreDispatch
                | DelegationCalibrationCampaignState::UnknownOutcome
                | DelegationCalibrationCampaignState::GateDenied
                | DelegationCalibrationCampaignState::BlockedProviderUnavailable
                | DelegationCalibrationCampaignState::BlockedQuota
                | DelegationCalibrationCampaignState::FailedProvider
                | DelegationCalibrationCampaignState::Inconclusive
                | DelegationCalibrationCampaignState::Cancelled
        )
    }

    #[allow(clippy::too_many_lines)]
    pub fn transition(
        &self,
        campaign: &mut DelegationCalibrationCampaign,
        next: DelegationCalibrationCampaignState,
    ) -> Result<bool, String> {
        if campaign.state == next {
            return Ok(false);
        }
        if Self::is_terminal(campaign.state) {
            return Err(format!(
                "terminal campaign state {:?} is immutable",
                campaign.state
            ));
        }
        let previous = campaign.state;
        let allowed = matches!(
            (campaign.state, next),
            (
                DelegationCalibrationCampaignState::Draft,
                DelegationCalibrationCampaignState::Preregistered
                    | DelegationCalibrationCampaignState::Ready
                    | DelegationCalibrationCampaignState::Cancelled
            ) | (
                DelegationCalibrationCampaignState::Preregistered,
                DelegationCalibrationCampaignState::Ready
                    | DelegationCalibrationCampaignState::Cancelled
            ) | (
                DelegationCalibrationCampaignState::Ready,
                DelegationCalibrationCampaignState::Reserved
                    | DelegationCalibrationCampaignState::ProviderExecuting
                    | DelegationCalibrationCampaignState::GateDenied
                    | DelegationCalibrationCampaignState::BlockedProviderUnavailable
                    | DelegationCalibrationCampaignState::BlockedQuota
                    | DelegationCalibrationCampaignState::Cancelled
            ) | (
                DelegationCalibrationCampaignState::Reserved,
                DelegationCalibrationCampaignState::Dispatching
                    | DelegationCalibrationCampaignState::ReleasedPreDispatch
                    | DelegationCalibrationCampaignState::Cancelled
            ) | (
                DelegationCalibrationCampaignState::Dispatching,
                DelegationCalibrationCampaignState::ProviderExecuted
                    | DelegationCalibrationCampaignState::FailedProvider
                    | DelegationCalibrationCampaignState::UnknownOutcome
            ) | (
                DelegationCalibrationCampaignState::ProviderExecuting,
                DelegationCalibrationCampaignState::ProviderExecuted
                    | DelegationCalibrationCampaignState::FailedProvider
                    | DelegationCalibrationCampaignState::Cancelled
            ) | (
                DelegationCalibrationCampaignState::ProviderExecuted,
                DelegationCalibrationCampaignState::AwaitingIndependentEvidence
            ) | (
                DelegationCalibrationCampaignState::AwaitingIndependentEvidence,
                DelegationCalibrationCampaignState::Attributed
                    | DelegationCalibrationCampaignState::Inconclusive
                    | DelegationCalibrationCampaignState::Cancelled
            ) | (
                DelegationCalibrationCampaignState::Attributed,
                DelegationCalibrationCampaignState::EligibilityDecided
                    | DelegationCalibrationCampaignState::RolledUp
            ) | (
                DelegationCalibrationCampaignState::EligibilityDecided,
                DelegationCalibrationCampaignState::RolledUp
            ) | (
                DelegationCalibrationCampaignState::RolledUp,
                DelegationCalibrationCampaignState::Closed
            )
        );
        if !allowed {
            return Err(format!(
                "invalid campaign transition {:?} -> {next:?}",
                campaign.state
            ));
        }
        campaign.state = next;
        campaign
            .transition_history
            .push(DelegationCalibrationCampaignTransition {
                from: previous,
                to: next,
                evidence_ref: None,
                transitioned_at: OffsetDateTime::now_utc(),
            });
        if Self::is_terminal(next) {
            campaign.closed_at = Some(OffsetDateTime::now_utc());
            campaign.closeout_status = match next {
                DelegationCalibrationCampaignState::Closed
                    if campaign.integrity_violations.is_empty() =>
                {
                    DelegationCalibrationCampaignCloseoutStatus::DoneVerified
                }
                DelegationCalibrationCampaignState::Closed => {
                    DelegationCalibrationCampaignCloseoutStatus::FailedVerifier
                }
                DelegationCalibrationCampaignState::Inconclusive => {
                    DelegationCalibrationCampaignCloseoutStatus::Inconclusive
                }
                DelegationCalibrationCampaignState::Cancelled
                | DelegationCalibrationCampaignState::ReleasedPreDispatch => {
                    DelegationCalibrationCampaignCloseoutStatus::Cancelled
                }
                _ => DelegationCalibrationCampaignCloseoutStatus::BlockedExternalDependency,
            };
        }
        Ok(true)
    }

    pub fn ingest_review(
        &self,
        state: &mut DelegationCalibrationState,
        review: ExecutedProviderReview,
    ) -> Result<bool, String> {
        let campaign = state
            .campaigns
            .iter_mut()
            .find(|campaign| campaign.campaign_id == review.campaign_id)
            .ok_or_else(|| "review campaign does not exist".to_owned())?;
        if campaign.baseline_state_hash.is_empty() || campaign.frozen_input_refs.is_empty() {
            return Err("campaign baseline must be frozen before provider execution".to_owned());
        }
        if review.baseline_state_hash != campaign.baseline_state_hash
            || review.frozen_input_refs != campaign.frozen_input_refs
        {
            return Err("executed review does not match the frozen campaign baseline".to_owned());
        }
        if !review.candidate_only {
            return Err("provider review must remain candidate-only".to_owned());
        }
        if state
            .executed_reviews
            .iter()
            .any(|existing| existing.review_id == review.review_id)
        {
            return Ok(false);
        }
        if !campaign.executed_review_ids.contains(&review.review_id) {
            campaign.executed_review_ids.push(review.review_id.clone());
        }
        state.executed_reviews.push(review);
        Ok(true)
    }
}

pub struct CampaignIntegrityReconciliationService;

impl CampaignIntegrityReconciliationService {
    #[allow(clippy::too_many_lines)]
    pub fn reconcile(
        &self,
        state: &mut DelegationCalibrationState,
        campaign_id: &str,
    ) -> Result<IncidentRecord, String> {
        let campaign = state
            .campaigns
            .iter()
            .find(|campaign| campaign.campaign_id == campaign_id)
            .ok_or_else(|| "campaign does not exist".to_owned())?
            .clone();
        let mut reviews = state
            .executed_reviews
            .iter()
            .filter(|review| review.campaign_id == campaign_id)
            .cloned()
            .collect::<Vec<_>>();
        reviews.sort_by_key(|review| review.started_at);
        if reviews.len() <= campaign.budget.max_provider_calls as usize {
            return Err("campaign has no provider call budget incident".to_owned());
        }
        if bounded_count(reviews.len()) != campaign.observed_provider_calls {
            return Err(
                "campaign review history does not match observed provider calls".to_owned(),
            );
        }

        let campaign_sample_ids = reviews
            .iter()
            .map(sample_id_for_review)
            .collect::<BTreeSet<_>>();
        for sample in state
            .samples
            .iter_mut()
            .filter(|sample| campaign_sample_ids.contains(&sample.sample_id))
        {
            sample.labels.provider_useful = None;
            sample.labels.accepted_findings = 0;
            sample.labels.rejected_findings = 0;
            sample.labels.false_positive_findings = 0;
            sample.labels.changed_controller_decision = None;
            sample.verifier_refs.clear();
            sample.completeness.verifier_or_human_evidence_present = false;
            sample.completeness.complete_for_provider_quality = false;
            if !sample
                .completeness
                .missing_refs
                .iter()
                .any(|item| item == "verifier_or_human_evidence")
            {
                sample
                    .completeness
                    .missing_refs
                    .push("verifier_or_human_evidence".to_owned());
            }
        }
        let assessments = state
            .utility_assessments
            .iter()
            .filter_map(|assessment| {
                reviews
                    .iter()
                    .find(|review| review.review_id == assessment.review_id)
                    .map(|review| (review.clone(), assessment.clone()))
            })
            .collect::<Vec<_>>();
        for (review, assessment) in assessments {
            ProviderUtilityAssessmentService.apply(state, &review, &assessment);
        }

        state.corpus_eligibility.retain(|eligibility| {
            !reviews.iter().any(|review| {
                eligibility.sample_ref == review.review_id
                    || eligibility.sample_ref == review.request_ref
                    || eligibility.sample_ref == sample_id_for_review(review)
            }) && !campaign
                .shadow_evaluation_ids
                .contains(&eligibility.sample_ref)
                && !state.utility_assessments.iter().any(|assessment| {
                    assessment.campaign_id == campaign_id
                        && eligibility.sample_ref == assessment.assessment_id
                })
        });
        for (index, review) in reviews.iter().enumerate() {
            let in_budget = index < campaign.budget.max_provider_calls as usize;
            let complete_utility = state.utility_assessments.iter().any(|assessment| {
                assessment.review_id == review.review_id && !assessment.evidence_refs.is_empty()
            });
            let status = if !in_budget {
                CalibrationIntegrityStatus::OverBudget
            } else if complete_utility {
                CalibrationIntegrityStatus::Valid
            } else {
                CalibrationIntegrityStatus::Incomplete
            };
            let reasons = if !in_budget {
                vec!["campaign_call_budget_exceeded".to_owned()]
            } else if !complete_utility {
                vec!["missing_independent_outcome_evidence".to_owned()]
            } else {
                Vec::new()
            };
            let promotion_eligible = in_budget && complete_utility;
            for (sample_ref, sample_kind) in [
                (
                    review.request_ref.clone(),
                    CalibrationCorpusSampleKind::ProviderCall,
                ),
                (
                    review.review_id.clone(),
                    CalibrationCorpusSampleKind::ExecutedReview,
                ),
                (
                    sample_id_for_review(review),
                    CalibrationCorpusSampleKind::CalibrationSample,
                ),
            ] {
                state.corpus_eligibility.push(CalibrationCorpusEligibility {
                    sample_ref,
                    sample_kind,
                    observed: true,
                    integrity_status: status,
                    promotion_eligible,
                    exclusion_reasons: reasons.clone(),
                    decided_by_rule_version: "l1b-r-integrity-1".to_owned(),
                    evidence_refs: vec![
                        review.provider_gate_decision_ref.clone(),
                        review.trace_ref.clone(),
                    ],
                    decided_at: OffsetDateTime::now_utc(),
                });
            }
        }
        for assessment in state
            .utility_assessments
            .iter()
            .filter(|assessment| assessment.campaign_id == campaign_id)
        {
            let review_eligible = reviews
                .iter()
                .position(|review| review.review_id == assessment.review_id)
                .is_some_and(|index| index < campaign.budget.max_provider_calls as usize);
            state.corpus_eligibility.push(CalibrationCorpusEligibility {
                sample_ref: assessment.assessment_id.clone(),
                sample_kind: CalibrationCorpusSampleKind::UtilityAssessment,
                observed: true,
                integrity_status: if review_eligible {
                    CalibrationIntegrityStatus::Valid
                } else {
                    CalibrationIntegrityStatus::OverBudget
                },
                promotion_eligible: review_eligible,
                exclusion_reasons: if review_eligible {
                    Vec::new()
                } else {
                    vec!["campaign_call_budget_exceeded".to_owned()]
                },
                decided_by_rule_version: "l1b-r-integrity-1".to_owned(),
                evidence_refs: assessment.evidence_refs.clone(),
                decided_at: OffsetDateTime::now_utc(),
            });
        }
        for shadow_id in &campaign.shadow_evaluation_ids {
            if !state
                .corpus_eligibility
                .iter()
                .any(|eligibility| eligibility.sample_ref == *shadow_id)
            {
                state.corpus_eligibility.push(CalibrationCorpusEligibility {
                    sample_ref: shadow_id.clone(),
                    sample_kind: CalibrationCorpusSampleKind::ShadowEvaluation,
                    observed: true,
                    integrity_status: CalibrationIntegrityStatus::DispatchAmbiguous,
                    promotion_eligible: false,
                    exclusion_reasons: vec![
                        "mixed_campaign_lineage_contains_over_budget_call".to_owned(),
                    ],
                    decided_by_rule_version: "l1b-r-integrity-1".to_owned(),
                    evidence_refs: vec![campaign.campaign_id.clone()],
                    decided_at: OffsetDateTime::now_utc(),
                });
            }
        }

        let incident_id = format!(
            "campaign-integrity:{}",
            campaign.campaign_id.replace(':', "_")
        );
        if let Some(existing) = state
            .integrity_incidents
            .iter()
            .find(|incident| incident.incident_id == incident_id)
        {
            return Ok(existing.clone());
        }
        let call_lineage = reviews
            .iter()
            .enumerate()
            .map(|(index, review)| ProviderCallLineage {
                invocation_index: u32::try_from(index + 1).unwrap_or(u32::MAX),
                trigger_command_or_target: if index == 0 {
                    "explicit governed delegate request".to_owned()
                } else {
                    "transient retry after post-dispatch worktree cleanup failure".to_owned()
                },
                idempotency_key_if_any: None,
                reservation_ref_if_any: None,
                gate_ref: review.provider_gate_decision_ref.clone(),
                dispatch_started_at: review.started_at,
                provider_request_or_process_ref: review.trace_ref.clone(),
                review_ref: review.review_id.clone(),
                terminal_state: ProviderCallLineageTerminalState::Completed,
            })
            .collect::<Vec<_>>();
        let opened_at = reviews
            .first()
            .map_or(campaign.created_at, |review| review.started_at);
        let details = CampaignIntegrityIncidentDetails {
            phase: "L1B".to_owned(),
            campaign_id: campaign.campaign_id.clone(),
            invariant: "campaign_provider_call_budget_preserved".to_owned(),
            campaign_limit: campaign.budget.max_provider_calls,
            observed_calls: campaign.observed_provider_calls,
            gate_decision_refs: reviews
                .iter()
                .map(|review| review.provider_gate_decision_ref.clone())
                .collect(),
            review_refs: reviews
                .iter()
                .map(|review| review.review_id.clone())
                .collect(),
            call_lineage,
            root_cause_status: CampaignIntegrityRootCauseStatus::Verified,
            root_cause: "post-dispatch cleanup failure was recorded as a zero-call ProviderFailed outcome; the legacy budget was refunded and transient retry dispatched again without a campaign reservation or stable idempotency key".to_owned(),
            contributing_conditions: vec![
                "campaign max_provider_calls was report-only rather than an authority boundary"
                    .to_owned(),
                "provider execution and cleanup shared one error path".to_owned(),
                "unknown external outcome was fail-open refunded".to_owned(),
                "transient retry used a separate counter from real provider calls".to_owned(),
            ],
            failed_control_boundary: "atomic campaign call-slot reservation before external dispatch"
                .to_owned(),
            affected_reports: vec![
                "reports/phase-l1b/latest.json".to_owned(),
                "reports/delegation-calibration-campaign/latest.json".to_owned(),
                "reports/delegation-promotion-gate/latest.json".to_owned(),
            ],
            promotion_eligibility_effect:
                "second provider call, review, calibration sample and utility assessment remain observed but are excluded from promotion inputs"
                    .to_owned(),
            containment: vec![
                "historical L1B remains FAILED_VERIFIER".to_owned(),
                "over-budget lineage is promotion_eligible=false".to_owned(),
                "L1B-R verification permits zero external provider dispatches".to_owned(),
            ],
            permanent_prevention: vec![
                "file-locked persisted ProviderCallReservationOwner".to_owned(),
                "stable campaign-scoped idempotency key".to_owned(),
                "unknown dispatch outcome consumes slot and forbids blind retry".to_owned(),
                "report, replay and closeout remain observation-only".to_owned(),
            ],
            regression_test_refs: vec![
                "phase_l1b_r_provider_budget_integrity".to_owned(),
                "provider_call_concurrency".to_owned(),
                "provider_call_crash_recovery".to_owned(),
            ],
            resolved_at: None,
            status: CampaignIntegrityIncidentStatus::Contained,
        };
        let incident = IncidentRecord {
            incident_id,
            severity: IncidentSeverity::Critical,
            status: IncidentStatus::Mitigated,
            kind: IncidentKind::CampaignProviderCallBudgetExceeded,
            project_id: Some(campaign.project_id),
            affected_surfaces: vec![
                "delegation campaign budget".to_owned(),
                "provider dispatch".to_owned(),
                "promotion corpus".to_owned(),
            ],
            opened_at,
            acknowledged_at: Some(OffsetDateTime::now_utc()),
            closed_at: None,
            evidence_refs: vec![
                "reports/phase-l1b/latest.json".to_owned(),
                "reports/delegation-calibration-campaign/latest.json".to_owned(),
            ],
            last_known_safe_refs: vec![campaign.baseline_commit.clone()],
            recovery_commands: vec!["just phase-l1b-r".to_owned()],
            summary: "L1B provider call budget exceeded: two real calls under a one-call campaign"
                .to_owned(),
            campaign_integrity: Some(details),
        };
        state.integrity_incidents.push(incident.clone());
        Ok(incident)
    }

    pub fn resolve(
        &self,
        state: &mut DelegationCalibrationState,
        incident_id: &str,
    ) -> Result<IncidentRecord, String> {
        let incident = state
            .integrity_incidents
            .iter_mut()
            .find(|incident| incident.incident_id == incident_id)
            .ok_or_else(|| "campaign integrity incident does not exist".to_owned())?;
        let now = OffsetDateTime::now_utc();
        incident.status = IncidentStatus::Closed;
        incident.closed_at = Some(now);
        let details = incident
            .campaign_integrity
            .as_mut()
            .ok_or_else(|| "incident lacks campaign integrity details".to_owned())?;
        details.status = CampaignIntegrityIncidentStatus::Resolved;
        details.resolved_at = Some(now);
        Ok(incident.clone())
    }
}

pub struct IndependentOutcomeEvidenceService;

impl IndependentOutcomeEvidenceService {
    pub fn attach(
        &self,
        state: &mut DelegationCalibrationState,
        evidence: IndependentOutcomeEvidence,
    ) -> Result<bool, String> {
        let review = state
            .executed_reviews
            .iter()
            .find(|review| review.review_id == evidence.review_id)
            .ok_or_else(|| "independent evidence review does not exist".to_owned())?;
        if review.campaign_id != evidence.campaign_id || review.real_task_id != evidence.task_id {
            return Err("independent evidence scope does not match review and task".to_owned());
        }
        if !evidence.independent_from_provider
            || evidence.contamination_checks.producer_is_provider
            || evidence
                .contamination_checks
                .criteria_added_after_provider_output
            || evidence
                .contamination_checks
                .provider_output_used_as_verifier_input
            || !evidence.contamination_checks.scope_matches_review
        {
            return Err("provider-derived or contaminated evidence is not independent".to_owned());
        }
        if evidence.producer_identity.trim().is_empty()
            || evidence.authority.trim().is_empty()
            || evidence.exact_anchor_refs.is_empty()
        {
            return Err(
                "independent evidence requires producer, authority and exact anchors".to_owned(),
            );
        }
        if !registered_independent_producer(&evidence) {
            return Err(
                "independent evidence producer is not registered for its authority class"
                    .to_owned(),
            );
        }
        if state
            .independent_evidence
            .iter()
            .any(|existing| existing.evidence_id == evidence.evidence_id)
        {
            return Ok(false);
        }
        let campaign = state
            .campaigns
            .iter_mut()
            .find(|campaign| campaign.campaign_id == evidence.campaign_id)
            .ok_or_else(|| "independent evidence campaign does not exist".to_owned())?;
        if !campaign
            .independent_evidence_ids
            .contains(&evidence.evidence_id)
        {
            campaign
                .independent_evidence_ids
                .push(evidence.evidence_id.clone());
        }
        state.independent_evidence.push(evidence);
        Ok(true)
    }
}

pub struct ProviderUtilityAssessmentService;

impl ProviderUtilityAssessmentService {
    #[allow(clippy::too_many_lines)]
    pub fn assess(
        &self,
        review: &ExecutedProviderReview,
        task_family: DelegationCalibrationTaskFamily,
        evidence: &[IndependentOutcomeEvidence],
    ) -> ProviderUtilityAssessment {
        let scoped = evidence
            .iter()
            .filter(|item| item.review_id == review.review_id)
            .collect::<Vec<_>>();
        let mut reason = ProviderUtilityReason::MissingIndependentEvidence;
        let mut useful = None;
        let mut uncertainty = Vec::new();
        let threshold = materiality_threshold(task_family);
        let contaminated = scoped.iter().any(|item| {
            !item.independent_from_provider
                || item.contamination_checks.producer_is_provider
                || item
                    .contamination_checks
                    .criteria_added_after_provider_output
                || item
                    .contamination_checks
                    .provider_output_used_as_verifier_input
                || !item.contamination_checks.scope_matches_review
        });
        let contradictory = scoped
            .iter()
            .any(|item| item.result == IndependentEvidenceResult::Contradictory)
            || finding_sets_conflict(&scoped);
        let confirmed = scoped
            .iter()
            .copied()
            .filter(|item| {
                item.result == IndependentEvidenceResult::Confirmed && item.materiality >= threshold
            })
            .collect::<Vec<_>>();
        let refuted = scoped
            .iter()
            .copied()
            .filter(|item| {
                item.result == IndependentEvidenceResult::Refuted && item.materiality >= threshold
            })
            .collect::<Vec<_>>();
        let confirmed_ids = finding_ids(&confirmed, true);
        let refuted_ids = finding_ids(&refuted, false);
        let quality_delta = scoped.iter().map(|item| item.verified_quality_delta).sum();
        let cost_delta = scoped
            .iter()
            .map(|item| item.verified_cost_or_latency_delta)
            .sum();
        if scoped.is_empty() {
            uncertainty.push("no independent evidence attached".to_owned());
        } else if contaminated {
            reason = ProviderUtilityReason::ContaminatedEvidence;
            uncertainty.push("evidence independence check failed".to_owned());
        } else if contradictory {
            reason = ProviderUtilityReason::ContradictoryEvidence;
            uncertainty.push("independent evidence conflicts on the same finding".to_owned());
        } else if confirmed.iter().any(|item| item.prevented_verified_failure) {
            reason = ProviderUtilityReason::ConfirmedFailurePrevention;
            useful = Some(true);
        } else if confirmed.iter().any(|item| item.changed_controller_action) {
            reason = ProviderUtilityReason::ConfirmedMaterialActionChange;
            useful = Some(true);
        } else if !confirmed_ids.is_empty() {
            reason = ProviderUtilityReason::ConfirmedMaterialNovelFinding;
            useful = Some(true);
        } else if cost_delta > 0 && quality_delta >= 0 {
            reason = ProviderUtilityReason::VerifiedCostOrLatencyBenefit;
            useful = Some(true);
        } else if !refuted_ids.is_empty() || scoped.iter().any(|item| item.unnecessary_work) {
            reason = ProviderUtilityReason::RefutedOrFalsePositiveOutput;
            useful = Some(false);
        } else if scoped
            .iter()
            .any(|item| item.result == IndependentEvidenceResult::Inconclusive)
        {
            reason = ProviderUtilityReason::InconclusiveEvidence;
            uncertainty.push("registered verifier outcome was inconclusive".to_owned());
        } else if scoped.iter().any(|item| item.materiality < threshold) {
            reason = ProviderUtilityReason::BelowMaterialityThreshold;
            uncertainty.push(format!(
                "evidence is below the {threshold:?} task-family materiality threshold"
            ));
        } else {
            reason = ProviderUtilityReason::NoMaterialOutcomeDelta;
            uncertainty
                .push("independent evidence showed no attributable material delta".to_owned());
        }
        ProviderUtilityAssessment {
            assessment_id: format!("utility-assessment:{}", review.review_id),
            campaign_id: review.campaign_id.clone(),
            review_id: review.review_id.clone(),
            provider_useful: useful,
            reason,
            material_findings_confirmed: bounded_count(confirmed_ids.len()),
            material_findings_refuted: bounded_count(refuted_ids.len()),
            novel_confirmed_findings: bounded_count(confirmed_ids.len()),
            duplicate_confirmed_findings: 0,
            false_positive_findings: bounded_count(refuted_ids.len()),
            missed_material_issues_if_known: None,
            verified_quality_delta: quality_delta,
            verified_cost_or_latency_delta: cost_delta,
            residual_uncertainty: uncertainty,
            evidence_refs: if contaminated || contradictory {
                Vec::new()
            } else {
                scoped.iter().map(|item| item.evidence_id.clone()).collect()
            },
            attribution_rule_version: "l1b-deterministic-1".to_owned(),
            decided_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn assess_preregistered(
        &self,
        review: &ExecutedProviderReview,
        task_family: DelegationCalibrationTaskFamily,
        evidence: &[IndependentOutcomeEvidence],
        dispositions: &[ProviderFindingDisposition],
        rule_version: &str,
    ) -> ProviderUtilityAssessment {
        let mut assessment = self.assess(review, task_family, evidence);
        rule_version.clone_into(&mut assessment.attribution_rule_version);
        let scoped_dispositions = dispositions
            .iter()
            .filter(|item| item.review_id == review.review_id)
            .collect::<Vec<_>>();
        let scoped_evidence = evidence
            .iter()
            .filter(|item| item.review_id == review.review_id)
            .collect::<Vec<_>>();
        let all_findings_accounted = review.normalized_findings.iter().all(|finding_id| {
            scoped_dispositions
                .iter()
                .any(|item| item.finding_id == *finding_id)
        });
        let all_material_resolved = scoped_dispositions.iter().all(|item| {
            item.materiality != ProviderFindingMateriality::Material
                || (item.verdict != ProviderFindingVerdict::Unresolved
                    && !item.independent_evidence_refs.is_empty())
        });
        let evidence_complete = !scoped_evidence.is_empty()
            && scoped_evidence.iter().all(|item| {
                item.independent_from_provider
                    && !item.contamination_checks.producer_is_provider
                    && !item
                        .contamination_checks
                        .criteria_added_after_provider_output
                    && !item
                        .contamination_checks
                        .provider_output_used_as_verifier_input
                    && item.contamination_checks.scope_matches_review
            });
        let novel_confirmed = scoped_dispositions
            .iter()
            .filter(|item| {
                item.materiality == ProviderFindingMateriality::Material
                    && item.novelty == ProviderFindingNovelty::Novel
                    && item.verdict == ProviderFindingVerdict::Confirmed
            })
            .count();
        let duplicate_confirmed = scoped_dispositions
            .iter()
            .filter(|item| {
                item.verdict == ProviderFindingVerdict::Confirmed
                    && matches!(
                        item.novelty,
                        ProviderFindingNovelty::Duplicate | ProviderFindingNovelty::AlreadyCovered
                    )
            })
            .count();
        let material_refuted = scoped_dispositions
            .iter()
            .filter(|item| {
                item.materiality == ProviderFindingMateriality::Material
                    && item.verdict == ProviderFindingVerdict::Refuted
            })
            .count();
        assessment.novel_confirmed_findings = bounded_count(novel_confirmed);
        assessment.duplicate_confirmed_findings = bounded_count(duplicate_confirmed);
        assessment.material_findings_refuted = bounded_count(material_refuted);
        assessment.false_positive_findings = bounded_count(material_refuted);
        if !all_findings_accounted || !all_material_resolved || !evidence_complete {
            assessment.provider_useful = None;
            assessment.reason = ProviderUtilityReason::InconclusiveEvidence;
            assessment.residual_uncertainty.push(
                "preregistered finding coverage or independent evidence is incomplete".to_owned(),
            );
        } else if novel_confirmed > 0 && assessment.provider_useful == Some(true) {
            assessment.provider_useful = Some(true);
            assessment.reason = ProviderUtilityReason::ConfirmedMaterialNovelFinding;
        } else {
            assessment.provider_useful = Some(false);
            assessment.reason = if material_refuted > 0 {
                ProviderUtilityReason::RefutedOrFalsePositiveOutput
            } else {
                ProviderUtilityReason::NoMaterialOutcomeDelta
            };
            assessment.residual_uncertainty.clear();
        }
        assessment
    }

    pub fn apply(
        &self,
        state: &mut DelegationCalibrationState,
        review: &ExecutedProviderReview,
        assessment: &ProviderUtilityAssessment,
    ) -> bool {
        let mut changed = false;
        if let Some(existing) = state
            .utility_assessments
            .iter_mut()
            .find(|item| item.review_id == review.review_id)
        {
            if existing != assessment {
                existing.clone_from(assessment);
                changed = true;
            }
        } else {
            state.utility_assessments.push(assessment.clone());
            changed = true;
        }
        let expected_sample_id = format!(
            "calibration:{}",
            review
                .review_id
                .strip_prefix("executed-review:")
                .unwrap_or(&review.review_id)
        );
        let exact_index = state
            .samples
            .iter()
            .position(|sample| sample.sample_id == expected_sample_id);
        let task_matches = state
            .samples
            .iter()
            .enumerate()
            .filter(|(_, sample)| sample.task_id == review.real_task_id)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let sample_index = exact_index.or_else(|| {
            if task_matches.len() == 1 {
                task_matches.first().copied()
            } else {
                None
            }
        });
        if let Some(sample) = sample_index.and_then(|index| state.samples.get_mut(index)) {
            let before = sample.clone();
            sample.labels.provider_useful = assessment.provider_useful;
            sample.labels.accepted_findings = assessment.material_findings_confirmed;
            sample.labels.rejected_findings = assessment.material_findings_refuted;
            sample.labels.false_positive_findings = assessment.false_positive_findings;
            sample.labels.changed_controller_decision = if assessment.evidence_refs.is_empty() {
                None
            } else {
                Some(assessment.reason == ProviderUtilityReason::ConfirmedMaterialActionChange)
            };
            sample.verifier_refs.clone_from(&assessment.evidence_refs);
            sample.completeness.verifier_or_human_evidence_present =
                !assessment.evidence_refs.is_empty();
            sample.completeness.complete_for_provider_quality =
                !assessment.evidence_refs.is_empty()
                    && sample.completeness.provider_result_present
                    && sample.completeness.worktree_cleanup_present
                    && sample.completeness.live_tree_integrity_present;
            if assessment.evidence_refs.is_empty() {
                if !sample
                    .completeness
                    .missing_refs
                    .iter()
                    .any(|item| item == "verifier_or_human_evidence")
                {
                    sample
                        .completeness
                        .missing_refs
                        .push("verifier_or_human_evidence".to_owned());
                }
            } else {
                sample
                    .completeness
                    .missing_refs
                    .retain(|item| item != "verifier_or_human_evidence");
            }
            changed |= &before != sample;
        }
        changed
    }
}

pub struct L1cCorpusEligibilityService;

impl L1cCorpusEligibilityService {
    #[allow(clippy::too_many_lines)]
    pub fn decide(
        &self,
        state: &mut DelegationCalibrationState,
        campaign_id: &str,
        reservation: &ProviderCallReservation,
    ) -> Result<Vec<CalibrationCorpusEligibility>, String> {
        let campaign = state
            .campaigns
            .iter()
            .find(|item| item.campaign_id == campaign_id)
            .ok_or_else(|| "L1C campaign does not exist".to_owned())?
            .clone();
        let preregistration = state
            .preregistrations
            .iter()
            .find(|item| item.campaign_id == campaign_id)
            .ok_or_else(|| "L1C preregistration does not exist".to_owned())?
            .clone();
        let reviews = state
            .executed_reviews
            .iter()
            .filter(|item| item.campaign_id == campaign_id)
            .cloned()
            .collect::<Vec<_>>();
        if reviews.len() != 1 {
            return Err("L1C eligibility requires exactly one executed review".to_owned());
        }
        let review = &reviews[0];
        let assessment = state
            .utility_assessments
            .iter()
            .find(|item| item.review_id == review.review_id)
            .cloned()
            .ok_or_else(|| "L1C utility assessment does not exist".to_owned())?;
        let independent_evidence_complete = !assessment.evidence_refs.is_empty()
            && assessment.evidence_refs.iter().all(|evidence_id| {
                state.independent_evidence.iter().any(|evidence| {
                    evidence.evidence_id == *evidence_id
                        && evidence.review_id == review.review_id
                        && evidence.independent_from_provider
                })
            });
        let valid_lineage = campaign.selected_task_ids == [review.real_task_id]
            && campaign.observed_provider_calls == 1
            && campaign.integrity_violations.is_empty()
            && preregistration.real_task_id == review.real_task_id
            && preregistration.max_provider_calls == 1
            && preregistration.sealed_at <= reservation.reserved_at
            && preregistration.idempotency_key == reservation.idempotency_key
            && reservation.campaign_id == campaign_id
            && reservation.state == ProviderCallReservationState::Completed
            && reservation.dispatch_started_at.is_some()
            && reservation.external_invocation_ref.is_some()
            && reservation.review_ref.as_deref() == Some(review.review_id.as_str())
            && review.status == ExecutedProviderReviewStatus::Succeeded
            && review.candidate_only
            && !review.trace_ref.is_empty()
            && !review.raw_output_ref.is_empty();
        let promotion_eligible =
            valid_lineage && independent_evidence_complete && assessment.provider_useful.is_some();
        let integrity_status = if valid_lineage {
            CalibrationIntegrityStatus::Valid
        } else {
            CalibrationIntegrityStatus::Incomplete
        };
        let exclusion_reasons = if promotion_eligible {
            Vec::new()
        } else if !valid_lineage {
            vec!["incomplete_preregistration_reservation_review_lineage".to_owned()]
        } else if assessment.provider_useful.is_none() {
            vec!["utility_attribution_null".to_owned()]
        } else {
            vec!["independent_evidence_incomplete".to_owned()]
        };
        let sample_id = sample_id_for_review(review);
        let evidence_refs = vec![
            preregistration.preregistration_id.clone(),
            reservation.reservation_id.clone(),
            review.review_id.clone(),
            assessment.assessment_id.clone(),
        ];
        let now = OffsetDateTime::now_utc();
        let mut records = [
            (
                reservation.reservation_id.clone(),
                CalibrationCorpusSampleKind::ProviderCall,
            ),
            (
                review.review_id.clone(),
                CalibrationCorpusSampleKind::ExecutedReview,
            ),
            (sample_id, CalibrationCorpusSampleKind::CalibrationSample),
            (
                assessment.assessment_id.clone(),
                CalibrationCorpusSampleKind::UtilityAssessment,
            ),
        ]
        .into_iter()
        .map(|(sample_ref, sample_kind)| CalibrationCorpusEligibility {
            sample_ref,
            sample_kind,
            observed: true,
            integrity_status,
            promotion_eligible,
            exclusion_reasons: exclusion_reasons.clone(),
            decided_by_rule_version: "l1c-integrity-attribution-1".to_owned(),
            evidence_refs: evidence_refs.clone(),
            decided_at: now,
        })
        .collect::<Vec<_>>();
        for shadow_id in &campaign.shadow_evaluation_ids {
            records.push(CalibrationCorpusEligibility {
                sample_ref: shadow_id.clone(),
                sample_kind: CalibrationCorpusSampleKind::ShadowEvaluation,
                observed: true,
                integrity_status,
                promotion_eligible,
                exclusion_reasons: exclusion_reasons.clone(),
                decided_by_rule_version: "l1c-integrity-attribution-1".to_owned(),
                evidence_refs: evidence_refs.clone(),
                decided_at: now,
            });
        }
        let current_refs = records
            .iter()
            .map(|record| record.sample_ref.as_str())
            .collect::<BTreeSet<_>>();
        state
            .corpus_eligibility
            .retain(|record| !current_refs.contains(record.sample_ref.as_str()));
        state.corpus_eligibility.extend(records.clone());
        Ok(records)
    }
}

pub struct CalibrationEvidenceGapService;

impl CalibrationEvidenceGapService {
    #[allow(clippy::too_many_lines)]
    pub fn report(
        &self,
        state: &DelegationCalibrationState,
        config: &DelegationCalibrationConfig,
        recursive_executions: u32,
    ) -> CalibrationEvidenceGapReport {
        let observed_real = state
            .samples
            .iter()
            .filter(|sample| {
                matches!(
                    sample.evidence_class,
                    CalibrationEvidenceClass::RealExecutedTask
                        | CalibrationEvidenceClass::RealNoProviderTask
                )
            })
            .collect::<Vec<_>>();
        let eligible_real = observed_real
            .iter()
            .copied()
            .filter(|sample| sample_is_promotion_eligible(state, &sample.sample_id))
            .collect::<Vec<_>>();
        let observed_calls = bounded_count(
            observed_real
                .iter()
                .filter(|sample| sample.labels.provider_called)
                .count(),
        );
        let eligible_calls = bounded_count(
            eligible_real
                .iter()
                .filter(|sample| sample.labels.provider_called)
                .count(),
        );
        let observed_complete = bounded_count(
            observed_real
                .iter()
                .filter(|sample| sample.completeness.complete_for_routing_quality)
                .count(),
        );
        let eligible_complete = bounded_count(
            eligible_real
                .iter()
                .filter(|sample| sample.completeness.complete_for_routing_quality)
                .count(),
        );
        let observed_counts = CalibrationEvidenceCounts {
            real_tasks: bounded_count(observed_real.len()),
            executed_reviews: observed_calls,
            shadow_tasks: bounded_count(state.shadows.len()),
            complete_outcomes: observed_complete,
        };
        let eligible_counts = CalibrationEvidenceCounts {
            real_tasks: bounded_count(eligible_real.len()),
            executed_reviews: eligible_calls,
            shadow_tasks: bounded_count(
                state
                    .shadows
                    .iter()
                    .filter(|shadow| sample_is_promotion_eligible(state, &shadow.shadow_id))
                    .count(),
            ),
            complete_outcomes: eligible_complete,
        };
        let floors = floor_snapshot(config);
        let completeness = if eligible_real.is_empty() {
            0.0
        } else {
            f64::from(eligible_complete) / f64::from(bounded_count(eligible_real.len()))
        };
        let campaign_integrity_failed = state.campaigns.iter().any(|campaign| {
            !campaign.integrity_violations.is_empty()
                || campaign.observed_provider_calls > campaign.budget.max_provider_calls
        });
        let campaign_integrity_contained = campaign_integrity_failed
            && state.integrity_incidents.iter().any(|incident| {
                incident.campaign_integrity.as_ref().is_some_and(|details| {
                    matches!(
                        details.status,
                        CampaignIntegrityIncidentStatus::Contained
                            | CampaignIntegrityIncidentStatus::Resolved
                    )
                })
            });
        let integrity_blocked = recursive_executions > 0
            || (campaign_integrity_failed && !campaign_integrity_contained)
            || eligible_real.iter().any(|sample| {
                sample.labels.authority_violations > 0 || sample.labels.live_tree_violations > 0
            });
        let floors_met = eligible_counts.real_tasks >= floors.minimum_real_tasks_total
            && eligible_counts.executed_reviews >= floors.minimum_executed_reviews_total
            && eligible_counts.shadow_tasks >= floors.minimum_shadow_tasks_total
            && completeness >= floors.minimum_complete_outcome_fraction;
        let promotion_readiness = if integrity_blocked {
            DelegationPromotionReadinessVerdict::BlockedByIntegrity
        } else if !floors_met {
            DelegationPromotionReadinessVerdict::InsufficientData
        } else if state.utility_assessments.iter().any(|assessment| {
            assessment.provider_useful == Some(true)
                && sample_is_promotion_eligible(state, &assessment.assessment_id)
        }) {
            DelegationPromotionReadinessVerdict::EligibleForPromotion
        } else {
            DelegationPromotionReadinessVerdict::RejectedByEvidence
        };
        let excluded_counts = CalibrationExcludedCounts {
            over_budget_calls: bounded_count(
                state
                    .corpus_eligibility
                    .iter()
                    .filter(|eligibility| {
                        eligibility.sample_kind == CalibrationCorpusSampleKind::ProviderCall
                            && eligibility.integrity_status
                                == CalibrationIntegrityStatus::OverBudget
                    })
                    .count(),
            ),
            unknown_dispatch_calls: bounded_count(
                state
                    .corpus_eligibility
                    .iter()
                    .filter(|eligibility| {
                        eligibility.sample_kind == CalibrationCorpusSampleKind::ProviderCall
                            && eligibility.integrity_status
                                == CalibrationIntegrityStatus::DispatchAmbiguous
                    })
                    .count(),
            ),
            incomplete_samples: bounded_count(
                state
                    .corpus_eligibility
                    .iter()
                    .filter(|eligibility| {
                        eligibility.sample_kind == CalibrationCorpusSampleKind::CalibrationSample
                            && eligibility.integrity_status
                                == CalibrationIntegrityStatus::Incomplete
                    })
                    .count(),
            ),
            contaminated_samples: bounded_count(
                state
                    .corpus_eligibility
                    .iter()
                    .filter(|eligibility| {
                        eligibility.integrity_status == CalibrationIntegrityStatus::Contaminated
                    })
                    .count(),
            ),
        };
        CalibrationEvidenceGapReport {
            current_counts: observed_counts.clone(),
            observed_counts,
            promotion_eligible_counts: eligible_counts,
            excluded_counts,
            required_floors: floors,
            completeness,
            missing_task_families: all_task_families()
                .into_iter()
                .filter(|family| {
                    eligible_real
                        .iter()
                        .filter(|sample| sample.task_family == *family)
                        .count()
                        < config.minimum_real_tasks_per_family as usize
                })
                .collect(),
            missing_independent_evidence: state
                .executed_reviews
                .iter()
                .filter(|review| sample_is_promotion_eligible(state, &review.review_id))
                .filter(|review| {
                    !state
                        .independent_evidence
                        .iter()
                        .any(|evidence| evidence.review_id == review.review_id)
                })
                .map(|review| review.review_id.clone())
                .collect(),
            null_utility_causes: state
                .utility_assessments
                .iter()
                .filter(|assessment| assessment.provider_useful.is_none())
                .map(|assessment| assessment.reason)
                .collect(),
            next_highest_value_sample: "real task in the least-covered eligible family with registered independent verifier".to_owned(),
            estimated_provider_calls_to_floor: config
                .minimum_executed_reviews_total
                .saturating_sub(eligible_calls),
            promotion_readiness,
            campaign_integrity: if campaign_integrity_contained {
                "failed_contained".to_owned()
            } else if campaign_integrity_failed {
                "failed_open".to_owned()
            } else {
                "valid".to_owned()
            },
            promotion_corpus_integrity: if state
                .corpus_eligibility
                .iter()
                .any(|eligibility| !eligibility.promotion_eligible)
            {
                "valid_after_exclusion".to_owned()
            } else {
                "valid".to_owned()
            },
        }
    }
}

pub struct DelegationShadowEvaluationService;

impl DelegationShadowEvaluationService {
    pub fn evaluate(
        &self,
        sample: &DelegationCalibrationSample,
        observed: DelegationDecisionKind,
        candidate_ref: &str,
    ) -> DelegationShadowRecord {
        let (decision, reasons) = match sample.task_family {
            DelegationCalibrationTaskFamily::SecurityBoundary
            | DelegationCalibrationTaskFamily::ExternalIntegration => (
                DelegationShadowDecisionKind::WouldExecute,
                vec![DelegationReason::SecurityBoundary],
            ),
            DelegationCalibrationTaskFamily::TrivialDeterministicTask => (
                DelegationShadowDecisionKind::WouldNotExecute,
                vec![DelegationReason::TrivialDeterministicTask],
            ),
            _ => (
                DelegationShadowDecisionKind::InsufficientEvidence,
                vec![DelegationReason::EvidenceGap],
            ),
        };
        DelegationShadowRecord {
            shadow_id: new_id("delegation-shadow"),
            project_id: sample.project_id,
            task_id: sample.task_id,
            task_family: sample.task_family,
            observed_l0_decision: observed,
            shadow_candidate_policy_ref: candidate_ref.to_owned(),
            shadow_decision: decision,
            reasons,
            provider_was_actually_called: sample.labels.provider_called,
            final_outcome_known: sample.completeness.final_task_outcome_present,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub const fn launches_provider(&self) -> bool {
        false
    }
}

pub struct DelegationCounterfactualService;

impl DelegationCounterfactualService {
    pub fn label(
        &self,
        shadow: &DelegationShadowRecord,
        evidence_refs: Vec<String>,
    ) -> DelegationCounterfactualLabel {
        let label = if evidence_refs.is_empty() || !shadow.final_outcome_known {
            DelegationCounterfactualKind::Inconclusive
        } else {
            match (shadow.shadow_decision, shadow.provider_was_actually_called) {
                (DelegationShadowDecisionKind::WouldExecute, true) => {
                    DelegationCounterfactualKind::CorrectCall
                }
                (DelegationShadowDecisionKind::WouldNotExecute, false) => {
                    DelegationCounterfactualKind::CorrectNoCall
                }
                (DelegationShadowDecisionKind::WouldExecute, false) => {
                    DelegationCounterfactualKind::PossibleFalseNegative
                }
                (DelegationShadowDecisionKind::WouldNotExecute, true) => {
                    DelegationCounterfactualKind::PossibleFalsePositive
                }
                _ => DelegationCounterfactualKind::Inconclusive,
            }
        };
        DelegationCounterfactualLabel {
            label_id: new_id("counterfactual"),
            shadow_ref: shadow.shadow_id.clone(),
            label,
            evidence_refs,
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct DelegationCalibrationRollupService;

impl DelegationCalibrationRollupService {
    pub fn rollup(
        &self,
        state: &DelegationCalibrationState,
        config: &DelegationCalibrationConfig,
    ) -> Vec<DelegationFamilyCalibration> {
        let mut families = BTreeSet::new();
        families.extend(state.samples.iter().map(|sample| sample.task_family));
        families.extend(state.shadows.iter().map(|shadow| shadow.task_family));
        families
            .into_iter()
            .map(|family| Self::family(state, config, family))
            .collect()
    }

    #[allow(clippy::too_many_lines)]
    fn family(
        state: &DelegationCalibrationState,
        config: &DelegationCalibrationConfig,
        family: DelegationCalibrationTaskFamily,
    ) -> DelegationFamilyCalibration {
        let samples = state
            .samples
            .iter()
            .filter(|sample| {
                sample.task_family == family
                    && sample_is_promotion_eligible(state, &sample.sample_id)
            })
            .collect::<Vec<_>>();
        let real = samples
            .iter()
            .copied()
            .filter(|sample| {
                matches!(
                    sample.evidence_class,
                    CalibrationEvidenceClass::RealExecutedTask
                        | CalibrationEvidenceClass::RealNoProviderTask
                )
            })
            .collect::<Vec<_>>();
        let provider = real
            .iter()
            .copied()
            .filter(|sample| sample.labels.provider_called)
            .collect::<Vec<_>>();
        let complete_provider = bounded_count(
            provider
                .iter()
                .filter(|sample| sample.completeness.complete_for_provider_quality)
                .count(),
        );
        let complete_routing = bounded_count(
            real.iter()
                .filter(|sample| sample.completeness.complete_for_routing_quality)
                .count(),
        );
        let mut runtimes = provider
            .iter()
            .filter_map(|sample| sample.costs.provider_runtime_ms)
            .collect::<Vec<_>>();
        runtimes.sort_unstable();
        let median = percentile(&runtimes, 50);
        let p95 = percentile(&runtimes, 95);
        let safety = real.iter().any(|sample| {
            sample.labels.authority_violations > 0 || sample.labels.live_tree_violations > 0
        });
        let readiness = if safety {
            DelegationCalibrationReadiness::PromotionBlockedBySafety
        } else if real.is_empty()
            && state.shadows.iter().any(|shadow| {
                shadow.task_family == family
                    && sample_is_promotion_eligible(state, &shadow.shadow_id)
            })
        {
            DelegationCalibrationReadiness::ShadowOnly
        } else if real.len() < config.minimum_real_tasks_per_family as usize {
            DelegationCalibrationReadiness::InsufficientData
        } else if complete_routing < config.minimum_real_tasks_per_family {
            DelegationCalibrationReadiness::DataQualityBlocked
        } else if complete_provider >= config.minimum_executed_reviews_per_candidate_family {
            DelegationCalibrationReadiness::CandidatePolicyReady
        } else {
            DelegationCalibrationReadiness::InsufficientData
        };
        DelegationFamilyCalibration {
            calibration_id: new_id("family-calibration"),
            task_family: family,
            real_task_count: bounded_count(real.len()),
            real_provider_call_count: bounded_count(provider.len()),
            shadow_task_count: bounded_count(
                state
                    .shadows
                    .iter()
                    .filter(|shadow| {
                        shadow.task_family == family
                            && sample_is_promotion_eligible(state, &shadow.shadow_id)
                    })
                    .count(),
            ),
            complete_provider_quality_samples: complete_provider,
            complete_routing_quality_samples: complete_routing,
            accepted_finding_count: real
                .iter()
                .map(|sample| sample.labels.accepted_findings)
                .sum(),
            unique_finding_count: real
                .iter()
                .map(|sample| sample.labels.unique_findings)
                .sum(),
            duplicate_finding_count: real
                .iter()
                .map(|sample| sample.labels.duplicate_findings)
                .sum(),
            false_positive_count: real
                .iter()
                .map(|sample| sample.labels.false_positive_findings)
                .sum(),
            useful_outcome_count: bounded_count(
                real.iter()
                    .filter(|sample| sample.labels.provider_useful == Some(true))
                    .count(),
            ),
            redundant_outcome_count: bounded_count(
                real.iter()
                    .filter(|sample| sample.labels.provider_useful == Some(false))
                    .count(),
            ),
            provider_failure_count: bounded_count(
                real.iter()
                    .filter(|sample| {
                        sample.labels.provider_called && sample.costs.provider_call_count == 0
                    })
                    .count(),
            ),
            median_provider_runtime_ms: median,
            p95_provider_runtime_ms: p95,
            readiness,
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct DelegationPolicyCandidateService;

impl DelegationPolicyCandidateService {
    pub fn generate(
        &self,
        families: &[DelegationFamilyCalibration],
        evidence_refs: Vec<String>,
    ) -> DelegationPolicyCandidate {
        let enabled = families
            .iter()
            .filter(|family| {
                family.readiness == DelegationCalibrationReadiness::CandidatePolicyReady
            })
            .map(|family| family.task_family)
            .collect::<Vec<_>>();
        let disabled = families
            .iter()
            .filter(|family| {
                family.readiness != DelegationCalibrationReadiness::CandidatePolicyReady
            })
            .map(|family| family.task_family)
            .collect::<Vec<_>>();
        let changes = families
            .iter()
            .map(|family| DelegationTriggerChange {
                task_family: family.task_family,
                change: if family.readiness == DelegationCalibrationReadiness::CandidatePolicyReady
                {
                    DelegationTriggerChangeKind::ConsiderAutoReview
                } else {
                    DelegationTriggerChangeKind::KeepShadowOnly
                },
                reason: format!(
                    "family readiness is {:?}; candidate does not activate routing",
                    family.readiness
                ),
            })
            .collect();
        DelegationPolicyCandidate {
            candidate_id: new_id("delegation-policy-candidate"),
            base_policy_ref: "git:761f969ec46743951efbb7e2fe064baddf0452fd".to_owned(),
            version: "l1a-draft-1".to_owned(),
            enabled_families: enabled.clone(),
            disabled_families: disabled,
            proposed_trigger_changes: changes,
            proposed_budget_changes: Vec::new(),
            evidence_refs,
            safety_constraints: vec![
                "candidate_only".to_owned(),
                "no_policy_activation".to_owned(),
                "zero_authority_live_tree_recursive_violations".to_owned(),
            ],
            status: if enabled.is_empty() {
                DelegationPolicyCandidateStatus::InsufficientData
            } else {
                DelegationPolicyCandidateStatus::ReadyForEvaluation
            },
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct DelegationPromotionGateService;

impl DelegationPromotionGateService {
    pub fn decide(
        &self,
        state: &DelegationCalibrationState,
        candidate: &DelegationPolicyCandidate,
        config: &DelegationCalibrationConfig,
        recursive_executions: u32,
    ) -> DelegationPolicyPromotionDecision {
        let real = state
            .samples
            .iter()
            .filter(|sample| {
                matches!(
                    sample.evidence_class,
                    CalibrationEvidenceClass::RealExecutedTask
                        | CalibrationEvidenceClass::RealNoProviderTask
                ) && sample_is_promotion_eligible(state, &sample.sample_id)
            })
            .collect::<Vec<_>>();
        let calls = bounded_count(
            real.iter()
                .filter(|sample| sample.labels.provider_called)
                .count(),
        );
        let authority: u32 = real
            .iter()
            .map(|sample| sample.labels.authority_violations)
            .sum();
        let live_tree: u32 = real
            .iter()
            .map(|sample| sample.labels.live_tree_violations)
            .sum();
        let complete = bounded_count(
            real.iter()
                .filter(|sample| sample.completeness.complete_for_routing_quality)
                .count(),
        );
        let fraction = if real.is_empty() {
            0.0
        } else {
            f64::from(complete) / f64::from(bounded_count(real.len()))
        };
        let mut reasons = Vec::new();
        if authority > 0 {
            reasons.push(DelegationPolicyPromotionReason::AuthorityViolationObserved);
        }
        if live_tree > 0 {
            reasons.push(DelegationPolicyPromotionReason::LiveTreeViolationObserved);
        }
        if recursive_executions > 0 {
            reasons.push(DelegationPolicyPromotionReason::RecursiveExecutionObserved);
        }
        let safety_block = (config.require_zero_authority_violations && authority > 0)
            || (config.require_zero_live_tree_violations && live_tree > 0)
            || (config.require_zero_recursive_executions && recursive_executions > 0);
        let decision = if safety_block {
            DelegationPolicyPromotionDecisionKind::DenySafetyViolation
        } else if real.len() < config.minimum_real_tasks_total as usize {
            reasons.push(DelegationPolicyPromotionReason::RealTaskCountTooLow);
            DelegationPolicyPromotionDecisionKind::InsufficientData
        } else if calls < config.minimum_executed_reviews_total {
            reasons.push(DelegationPolicyPromotionReason::ExecutedReviewCountTooLow);
            DelegationPolicyPromotionDecisionKind::RequireMoreExecutedReviews
        } else if fraction < config.minimum_complete_outcome_fraction {
            reasons.push(DelegationPolicyPromotionReason::IncompleteOutcomeEvidence);
            DelegationPolicyPromotionDecisionKind::RequireMoreRealTasks
        } else if state
            .shadows
            .iter()
            .filter(|shadow| sample_is_promotion_eligible(state, &shadow.shadow_id))
            .count()
            < config.minimum_shadow_tasks_total as usize
        {
            reasons.push(DelegationPolicyPromotionReason::ShadowTaskCountTooLow);
            DelegationPolicyPromotionDecisionKind::RequireMoreRealTasks
        } else {
            reasons.push(DelegationPolicyPromotionReason::DataQualitySufficient);
            DelegationPolicyPromotionDecisionKind::RequireHumanReview
        };
        DelegationPolicyPromotionDecision {
            decision_id: new_id("delegation-promotion"),
            candidate_ref: candidate.candidate_id.clone(),
            decision,
            reasons,
            required_followups: vec![
                "human review is mandatory before any L1B experiment".to_owned(),
            ],
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct DelegationCalibrationDoctorIntegration;
impl DelegationCalibrationDoctorIntegration {
    pub fn report(&self, state: &DelegationCalibrationState) -> Value {
        json!({"component":"delegation_calibration_doctor","real_samples":state.samples.iter().filter(|s| matches!(s.evidence_class, CalibrationEvidenceClass::RealExecutedTask | CalibrationEvidenceClass::RealNoProviderTask)).count(),"executed_reviews":state.samples.iter().filter(|s| s.labels.provider_called).count(),"shadow_count":state.shadows.len(),"incomplete_samples":state.samples.iter().filter(|s| !s.completeness.complete_for_routing_quality || (s.labels.provider_called && !s.completeness.complete_for_provider_quality)).count(),"candidate_status":state.policy_candidate.as_ref().map(|c| c.status),"promotion_decision":state.promotion_decision.as_ref().map(|d| d.decision),"authority_violations":state.samples.iter().map(|s| u64::from(s.labels.authority_violations)).sum::<u64>(),"live_tree_violations":state.samples.iter().map(|s| u64::from(s.labels.live_tree_violations)).sum::<u64>()})
    }
}

fn sample_id_for_review(review: &ExecutedProviderReview) -> String {
    format!(
        "calibration:{}",
        review
            .review_id
            .strip_prefix("executed-review:")
            .unwrap_or(&review.review_id)
    )
}

fn sample_is_promotion_eligible(state: &DelegationCalibrationState, sample_ref: &str) -> bool {
    state
        .corpus_eligibility
        .iter()
        .find(|eligibility| eligibility.sample_ref == sample_ref)
        .is_none_or(|eligibility| eligibility.promotion_eligible)
}

fn percentile(values: &[u64], percentile: usize) -> Option<u64> {
    if values.is_empty() {
        None
    } else if percentile == 50 && values.len().is_multiple_of(2) {
        let upper = values.len() / 2;
        Some(values[upper - 1].saturating_add(values[upper]) / 2)
    } else {
        Some(values[((values.len() - 1) * percentile).div_ceil(100)])
    }
}
fn bounded_count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn materiality_threshold(family: DelegationCalibrationTaskFamily) -> DelegationFindingMateriality {
    match family {
        DelegationCalibrationTaskFamily::TrivialDeterministicTask => {
            DelegationFindingMateriality::High
        }
        _ => DelegationFindingMateriality::Medium,
    }
}

fn registered_independent_producer(evidence: &IndependentOutcomeEvidence) -> bool {
    match evidence.evidence_kind {
        IndependentEvidenceKind::Verifier => {
            [
                "cargo-nextest",
                "cargo-test",
                "cargo-check",
                "cargo-clippy",
                "eliot-verifier",
            ]
            .contains(&evidence.producer_identity.as_str())
                && evidence.authority == "registered_deterministic_verifier"
        }
        IndependentEvidenceKind::Human => evidence.authority.starts_with("anchored_human_receipt:"),
        IndependentEvidenceKind::Artifact => {
            evidence.producer_identity == "eliot-artifact-verifier"
                && evidence.authority == "registered_artifact_verifier"
        }
        IndependentEvidenceKind::Runtime => {
            evidence.producer_identity == "eliot-runtime-verifier"
                && evidence.authority == "registered_runtime_verifier"
        }
        IndependentEvidenceKind::AcceptedDiff | IndependentEvidenceKind::RejectedDiff => {
            evidence.producer_identity == "eliot-diff-verifier"
                && evidence.authority == "registered_diff_verifier"
        }
        IndependentEvidenceKind::MeasuredCost => {
            evidence.producer_identity == "eliot-metrics-verifier"
                && evidence.authority == "registered_metrics_verifier"
        }
    }
}

fn finding_ids(items: &[&IndependentOutcomeEvidence], supported: bool) -> BTreeSet<String> {
    items
        .iter()
        .flat_map(|item| {
            if supported {
                item.supports_provider_finding_ids.iter()
            } else {
                item.refutes_provider_finding_ids.iter()
            }
        })
        .cloned()
        .collect()
}

fn finding_sets_conflict(items: &[&IndependentOutcomeEvidence]) -> bool {
    let supported = items
        .iter()
        .flat_map(|item| item.supports_provider_finding_ids.iter())
        .collect::<BTreeSet<_>>();
    items
        .iter()
        .flat_map(|item| item.refutes_provider_finding_ids.iter())
        .any(|finding| supported.contains(finding))
}

fn floor_snapshot(config: &DelegationCalibrationConfig) -> DelegationEvidenceFloorSnapshot {
    DelegationEvidenceFloorSnapshot {
        minimum_real_tasks_total: config.minimum_real_tasks_total,
        minimum_real_tasks_per_family: config.minimum_real_tasks_per_family,
        minimum_executed_reviews_total: config.minimum_executed_reviews_total,
        minimum_executed_reviews_per_candidate_family: config
            .minimum_executed_reviews_per_candidate_family,
        minimum_complete_outcome_fraction: config.minimum_complete_outcome_fraction,
        minimum_shadow_tasks_total: config.minimum_shadow_tasks_total,
    }
}

fn all_task_families() -> [DelegationCalibrationTaskFamily; 9] {
    [
        DelegationCalibrationTaskFamily::SecurityBoundary,
        DelegationCalibrationTaskFamily::ExternalIntegration,
        DelegationCalibrationTaskFamily::ArchitectureDesign,
        DelegationCalibrationTaskFamily::BroadDiffReview,
        DelegationCalibrationTaskFamily::VerifierDesign,
        DelegationCalibrationTaskFamily::RepeatedFailureDiagnosis,
        DelegationCalibrationTaskFamily::EvidenceGapReview,
        DelegationCalibrationTaskFamily::TrivialDeterministicTask,
        DelegationCalibrationTaskFamily::Other,
    ]
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}:{}", WorkLeaseId::new_v7())
}

fn stable_hash(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}
