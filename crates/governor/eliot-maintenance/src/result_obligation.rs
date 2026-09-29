//! The result-to-observation obligation one maintenance source result owes.
//!
//! This crate owns maintenance decisions and the bounded Durable Job lifecycle.
//! It does not publish observations and it does not run the canonical path. What
//! it does own is the fact that **every** source result it produces owes a
//! canonical observation, and that the obligation travels with the source
//! transition itself rather than being reconstructed later from a success branch
//! or a diagnostic line.
//!
//! Two different things live here, and keeping them apart is the point:
//!
//! - [`MaintenanceResultObligation`] is the **durable source-side intent**. It is
//!   appended to the job revision the transition already saves, so the existing
//!   [`MaintenanceStateStore::save`](super::MaintenanceStateStore::save) is the
//!   obligation's atomic boundary: the job state and the observation it owes
//!   become durable in one write, or in neither. It carries only evidence the
//!   transition really holds, so a no-attempt decision cannot grow an execution
//!   reference it never had.
//! - [`maintenance_observation_record`] is the **producer** that turns that
//!   intent into the observation-family record the existing canonical route
//!   admits. It is total over the outcome vocabulary: completed, partial,
//!   failed, cancelled, unknown, proven-no-effect and the no-attempt
//!   non-execution decision all produce a record, and none is dropped for not
//!   being a success.
//!
//! Two properties are load-bearing:
//!
//! * **Publication identity comes from the source event, never from retry
//!   time.** It is a pure function of the job identity, the lifecycle state and
//!   the attempt ordinal, so a retry of the same source result republishes one
//!   identity and the store reconciles it instead of creating a second record.
//! * **A later reconciliation appends; it never erases.** An unknown outcome
//!   stays in the job's obligation history and the reconciliation names it as
//!   its predecessor, so resolving an uncertainty adds linked evidence and
//!   leaves the original uncertainty visible.
//!
//! The observation store is a distinct store from the maintenance job ledger and
//! nothing here claims they commit together. The obligation is persisted with
//! the source transition; publication is reconciled afterwards through the
//! existing receipt-returning route, so a lost acknowledgement is read back
//! rather than assumed.

use eliot_contracts::{ContractVersion, StateFence};
use eliot_observation_contracts::{
    CoverageDisposition, CoverageEvidence, CoverageInterval, MAINTENANCE_RESULT_CONTRACT_VERSION,
    MaintenanceDeliveryState, MaintenanceExecutionOutcome, MaintenanceMetricAssessment,
    MaintenanceMetricEvaluationV1, MaintenanceMetricResult, MaintenanceRecord, MaintenanceResultV1,
    MaintenanceUtilityEvidenceV1, MaintenanceUtilityVerdict, ObservationEventCore,
    ObservationEventIdentity, ObservationKind, ObservationScope, PrivacyRetentionDisclosure,
    ProducerTrace,
};
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{MaintenanceError, MaintenanceFamily, MaintenanceJob, MaintenanceJobState};

/// Version of the source-side obligation record this crate persists.
pub const MAINTENANCE_OBLIGATION_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Upper bound on retained obligations per job.
///
/// The lifecycle is what actually bounds this: obligations are appended only by
/// result-bearing transitions of a bounded job state machine. The bound is a
/// fail-closed guard, never a truncation, because dropping the oldest obligation
/// would erase the original uncertainty this type exists to preserve.
pub const MAX_RESULT_OBLIGATIONS: usize = 16;

/// Named reason recorded when a delayed comparison has not been observed.
///
/// This is the honest state at a source result: the follow-up window has not
/// elapsed, so no value exists. It is a reason reference, not a zero and not a
/// benefit.
pub const FOLLOW_UP_PENDING_REASON: &str = "maintenance.follow-up-window-not-elapsed";

/// Named reason recorded when a metric does not apply to this outcome.
///
/// A decision that produced no execution attempt has no recurrence rate and no
/// cost; saying so is different from reporting zero.
pub const NOT_APPLICABLE_REASON: &str = "maintenance.metric-does-not-apply-to-this-outcome";

/// The evaluation method the source-side producer records for a metric whose
/// comparison has not run.
///
/// Named and versioned so a later revision is distinguishable, and naming the
/// owner that will run the comparison rather than claiming one already ran.
pub const SOURCE_EVALUATION_METHOD: &str = "eliot.governor.maintenance:self-quality-comparison";

/// Revision of [`SOURCE_EVALUATION_METHOD`].
pub const SOURCE_EVALUATION_METHOD_REVISION: &str = "1.0.0";

/// One maintenance source result's durable obligation to publish a canonical
/// observation.
///
/// Appended by every result-bearing transition onto the job revision that
/// transition already persists, so the obligation and the transition share one
/// atomic write. It is intent, not publication: `delivery` starts
/// [`MaintenanceDeliveryState::Pending`] and only the receipt returned by the
/// canonical route settles it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceResultObligation {
    /// Exact version of this obligation record.
    pub contract_version: ContractVersion,
    /// Stable publication identity, derived from the source event and its
    /// revisions and never from retry time. It equals the observation
    /// `record_id`, so a retry republishes one identity.
    pub publication_id: String,
    /// Trigger identity whose decision produced this result.
    pub source_trigger_ref: String,
    /// The exact source decision, including a no-attempt deferral decision.
    pub decision_ref: String,
    /// Registered maintenance family.
    pub family: MaintenanceFamily,
    /// Exact affected scope.
    pub scope_ref: String,
    /// Durable job identity when the decision admitted one.
    pub job_ref: Option<String>,
    /// Execution attempt identity when execution began.
    pub attempt_ref: Option<String>,
    /// Execution receipt the source owner issued, when it issued one.
    pub execution_receipt_ref: Option<String>,
    /// Fence the source decision and transition ran under.
    pub state_fence: StateFence,
    /// Revision of the original source outcome; stable across retries.
    pub source_outcome_revision: String,
    /// Actual effect evidence the transition really holds.
    pub actual_effect_refs: Vec<String>,
    /// Durable execution checkpoints the transition really holds.
    pub checkpoint_refs: Vec<String>,
    /// Reconciliation evidence the transition really holds.
    pub reconciliation_refs: Vec<String>,
    /// Execution outcome class, independent of delivery and utility.
    pub execution_outcome: MaintenanceExecutionOutcome,
    /// Delivery of this result into the observation path.
    pub delivery: MaintenanceDeliveryState,
    /// Starts at one and advances when a later reconciliation appends.
    pub evaluation_revision: u64,
    /// Prior obligation this one appends to, when this is not the first.
    pub predecessor_obligation_ref: Option<String>,
}

impl MaintenanceResultObligation {
    /// Validates the obligation's identity, coherence and append chain.
    ///
    /// Coherence is checked against the source facts, not against a copy of the
    /// caller's own field list: a no-attempt decision is refused any execution
    /// evidence, and an attempted outcome is refused without the job and attempt
    /// identities that make it checkable.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        if self.contract_version != MAINTENANCE_OBLIGATION_CONTRACT_VERSION {
            return Err(MaintenanceError::InvalidField(
                "result_obligation.contract_version",
            ));
        }
        for (value, field) in [
            (&self.publication_id, "result_obligation.publication_id"),
            (
                &self.source_trigger_ref,
                "result_obligation.source_trigger_ref",
            ),
            (&self.decision_ref, "result_obligation.decision_ref"),
            (&self.scope_ref, "result_obligation.scope_ref"),
            (
                &self.source_outcome_revision,
                "result_obligation.source_outcome_revision",
            ),
        ] {
            text(value, field)?;
        }
        for (value, field) in [
            (&self.job_ref, "result_obligation.job_ref"),
            (&self.attempt_ref, "result_obligation.attempt_ref"),
            (
                &self.execution_receipt_ref,
                "result_obligation.execution_receipt_ref",
            ),
            (
                &self.predecessor_obligation_ref,
                "result_obligation.predecessor_obligation_ref",
            ),
        ] {
            if let Some(value) = value {
                text(value, field)?;
            }
        }
        self.state_fence
            .validate()
            .map_err(|_| MaintenanceError::FenceMismatch)?;
        unique_text(
            &self.actual_effect_refs,
            "result_obligation.actual_effect_refs",
        )?;
        unique_text(&self.checkpoint_refs, "result_obligation.checkpoint_refs")?;
        unique_text(
            &self.reconciliation_refs,
            "result_obligation.reconciliation_refs",
        )?;
        if self.evaluation_revision == 0
            || (self.evaluation_revision == 1 && self.predecessor_obligation_ref.is_some())
            || (self.evaluation_revision > 1 && self.predecessor_obligation_ref.is_none())
        {
            return Err(MaintenanceError::InvalidField(
                "result_obligation.evaluation_revision",
            ));
        }
        if self.predecessor_obligation_ref.as_deref() == Some(self.publication_id.as_str()) {
            return Err(MaintenanceError::InvalidField(
                "result_obligation.predecessor_obligation_ref",
            ));
        }
        match &self.delivery {
            MaintenanceDeliveryState::Pending { obligation_ref } => {
                text(obligation_ref, "result_obligation.delivery.obligation_ref")?;
                if obligation_ref != &self.publication_id {
                    return Err(MaintenanceError::InvalidField(
                        "result_obligation.delivery.obligation_ref",
                    ));
                }
            }
            MaintenanceDeliveryState::Published {
                observation_receipt_ref,
            } => text(
                observation_receipt_ref,
                "result_obligation.delivery.observation_receipt_ref",
            )?,
            MaintenanceDeliveryState::Unavailable { coverage_gap_ref } => text(
                coverage_gap_ref,
                "result_obligation.delivery.coverage_gap_ref",
            )?,
        }
        match self.execution_outcome {
            MaintenanceExecutionOutcome::NotAttempted => {
                if self.attempt_ref.is_some()
                    || self.execution_receipt_ref.is_some()
                    || !self.actual_effect_refs.is_empty()
                    || !self.checkpoint_refs.is_empty()
                    || !self.reconciliation_refs.is_empty()
                {
                    return Err(MaintenanceError::InvalidField(
                        "result_obligation.execution_outcome",
                    ));
                }
            }
            _ if self.job_ref.is_none() || self.attempt_ref.is_none() => {
                return Err(MaintenanceError::InvalidField(
                    "result_obligation.execution_outcome",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

/// The execution outcome class a transition into this lifecycle state produces.
///
/// Total over the lifecycle, so a new state cannot be added without naming what
/// a source result for it means. Deliberately not total in the other direction:
/// `Admitted`, `Running` and `Deferred` are not results, so they produce no
/// obligation at all rather than a fabricated outcome.
const fn result_outcome(state: MaintenanceJobState) -> Option<MaintenanceExecutionOutcome> {
    match state {
        MaintenanceJobState::Checkpointed => Some(MaintenanceExecutionOutcome::Partial),
        MaintenanceJobState::Completed => Some(MaintenanceExecutionOutcome::Completed),
        MaintenanceJobState::Failed => Some(MaintenanceExecutionOutcome::Failed),
        MaintenanceJobState::Cancelled => Some(MaintenanceExecutionOutcome::Cancelled),
        MaintenanceJobState::UnknownOutcome | MaintenanceJobState::RollbackRequired => {
            Some(MaintenanceExecutionOutcome::Unknown)
        }
        MaintenanceJobState::Admitted
        | MaintenanceJobState::Running
        | MaintenanceJobState::Deferred => None,
    }
}

/// The stable publication identity for one source result.
///
/// A pure function of the source event and its revisions: the job identity, the
/// lifecycle state and the attempt ordinal. Retry time is deliberately absent, so
/// republishing the same source result republishes the same identity.
fn publication_id_for(job_id: &str, state: MaintenanceJobState, attempts: u32) -> String {
    format!("maintenance-result:{job_id}:{state}:{attempts}")
}

/// Appends the obligation for one result-bearing job transition.
///
/// Called by the job owner from inside the transition and before the single
/// [`MaintenanceStateStore::save`](super::MaintenanceStateStore::save) that
/// persists the revision, so the obligation and the state it describes become
/// durable together. `predecessor` is the prior obligation in the job's history
/// when this transition reconciles an earlier result, which is what makes a
/// reconciliation an append rather than a rewrite.
pub(crate) fn append_result_obligation(
    job: &mut MaintenanceJob,
    predecessor: Option<&MaintenanceResultObligation>,
) -> Result<(), MaintenanceError> {
    let Some(execution_outcome) = result_outcome(job.state) else {
        return Ok(());
    };
    if job.result_obligations.len() >= MAX_RESULT_OBLIGATIONS {
        return Err(MaintenanceError::InvalidField("job.result_obligations"));
    }
    let publication_id = publication_id_for(&job.job_id, job.state, job.attempts);
    // Execution evidence is taken from what the transition really persisted. A
    // cancellation records none, so it carries none; a checkpointed partial
    // result carries the checkpoint it saved; a completion, failure or unknown
    // outcome carries the outcome reference its own transition set.
    let (execution_receipt_ref, actual_effect_refs, checkpoint_refs, reconciliation_refs) =
        match execution_outcome {
            MaintenanceExecutionOutcome::Completed | MaintenanceExecutionOutcome::Failed => {
                let reference = job.outcome_ref.clone();
                (reference.clone(), reference.into_iter().collect(), Vec::new(), Vec::new())
            }
            MaintenanceExecutionOutcome::Partial => (
                None,
                Vec::new(),
                job.checkpoint
                    .as_ref()
                    .map(|checkpoint| vec![checkpoint.stage_ref.clone()])
                    .unwrap_or_default(),
                Vec::new(),
            ),
            MaintenanceExecutionOutcome::Unknown => {
                // The evidence that made the outcome unknown is reconciliation
                // evidence, not an effect the attempt produced.
                let reference = job.outcome_ref.clone();
                (reference.clone(), Vec::new(), Vec::new(), reference.into_iter().collect())
            }
            _ => (None, Vec::new(), Vec::new(), Vec::new()),
        };
    let obligation = MaintenanceResultObligation {
        contract_version: MAINTENANCE_OBLIGATION_CONTRACT_VERSION,
        publication_id: publication_id.clone(),
        source_trigger_ref: job.trigger_id.clone(),
        decision_ref: job.decision_ref.clone(),
        family: job.family,
        scope_ref: job.scope_ref.clone(),
        job_ref: Some(job.job_id.clone()),
        // Derived from the same source facts as the publication identity, so the
        // two can never disagree about which attempt produced this result.
        attempt_ref: Some(format!("maintenance-attempt:{}:{}", job.job_id, job.attempts)),
        execution_receipt_ref,
        state_fence: job.state_fence.clone(),
        source_outcome_revision: format!("{}:{}", job.state, job.attempts),
        actual_effect_refs,
        checkpoint_refs,
        reconciliation_refs,
        execution_outcome,
        delivery: MaintenanceDeliveryState::Pending {
            obligation_ref: publication_id,
        },
        evaluation_revision: predecessor.map_or(1, |prior| prior.evaluation_revision + 1),
        predecessor_obligation_ref: predecessor.map(|prior| prior.publication_id.clone()),
    };
    obligation.validate()?;
    job.result_obligations.push(obligation);
    Ok(())
}

/// Appends the obligation for a job transition that reconciles an earlier
/// result, naming that earlier obligation as its predecessor.
///
/// The prior obligation stays in the job's history: a reconciliation adds linked
/// evidence and never erases the uncertainty it resolves.
pub(crate) fn append_reconciliation_obligation(
    job: &mut MaintenanceJob,
    predecessor: &MaintenanceResultObligation,
) -> Result<(), MaintenanceError> {
    if job.result_obligations.len() >= MAX_RESULT_OBLIGATIONS {
        return Err(MaintenanceError::InvalidField("job.result_obligations"));
    }
    let revision = predecessor.evaluation_revision + 1;
    let publication_id = format!(
        "maintenance-result:{job_id}:{state}:{attempts}:reconciled-r{revision}",
        job_id = job.job_id,
        state = job.state,
        attempts = job.attempts,
    );
    // The reconciled outcome is whatever the lifecycle state now says. A
    // proven-no-effect reconciliation lands on `Deferred`, which is not itself a
    // result state, so the proven absence is stated explicitly rather than lost
    // to a state that produces no obligation.
    let execution_outcome = match job.state {
        MaintenanceJobState::Completed => MaintenanceExecutionOutcome::Completed,
        MaintenanceJobState::Failed => MaintenanceExecutionOutcome::Failed,
        _ => MaintenanceExecutionOutcome::ProvenNoEffect,
    };
    let obligation = MaintenanceResultObligation {
        contract_version: MAINTENANCE_OBLIGATION_CONTRACT_VERSION,
        publication_id: publication_id.clone(),
        source_trigger_ref: job.trigger_id.clone(),
        decision_ref: job.decision_ref.clone(),
        family: job.family,
        scope_ref: job.scope_ref.clone(),
        job_ref: Some(job.job_id.clone()),
        attempt_ref: predecessor.attempt_ref.clone(),
        execution_receipt_ref: job.outcome_ref.clone(),
        state_fence: job.state_fence.clone(),
        source_outcome_revision: format!("{}:{}:reconciled", job.state, job.attempts),
        actual_effect_refs: Vec::new(),
        checkpoint_refs: Vec::new(),
        // The reconciliation's own evidence is what links it to the uncertainty
        // it resolves.
        reconciliation_refs: job.outcome_ref.clone().into_iter().collect(),
        execution_outcome,
        delivery: MaintenanceDeliveryState::Pending {
            obligation_ref: publication_id,
        },
        evaluation_revision: revision,
        predecessor_obligation_ref: Some(predecessor.publication_id.clone()),
    };
    obligation.validate()?;
    job.result_obligations.push(obligation);
    Ok(())
}

/// The obligation this job most recently appended, if any.
pub(crate) fn latest_obligation(
    job: &MaintenanceJob,
) -> Option<&MaintenanceResultObligation> {
    job.result_obligations.last()
}

/// The producer: turns one maintenance source result into the exact
/// observation-family record the existing canonical route admits.
///
/// The maintained subsystem's own scope, provenance and privacy disclosure are
/// carried through unchanged, so publishing into the governed self scope is a
/// projection of source data rather than permission to copy project contents
/// into a global record.
///
/// Every required utility metric is reported honestly. A source result whose
/// follow-up window has not elapsed says so explicitly instead of reporting a
/// zero, and a completion is `PENDING` rather than `BENEFICIAL`: work performed
/// is not utility, and a completion is not a benefit.
pub fn maintenance_observation_record(
    obligation: &MaintenanceResultObligation,
    observed_at_unix_ms: u64,
) -> Result<MaintenanceRecord, MaintenanceError> {
    obligation.validate()?;
    let attempted = obligation.execution_outcome != MaintenanceExecutionOutcome::NotAttempted;
    let work_scope = WorkScopeId::new(obligation.scope_ref.clone())
        .map_err(|_| MaintenanceError::InvalidField("result_obligation.scope_ref"))?;
    let scope = ObservationScope {
        work_scope,
        task_ref: None,
        attempt_ref: obligation.attempt_ref.clone(),
        module_or_route_ref: Some(obligation.family.to_string()),
    };
    // The comparison window observed *so far* is the single instant the source
    // result was recorded. It is zero-width on purpose: no follow-up window has
    // elapsed, and widening it here would invent coverage nobody observed.
    let window = CoverageInterval::new(observed_at_unix_ms, observed_at_unix_ms)
        .map_err(|_| MaintenanceError::InvalidField("result_obligation.comparison_window"))?;
    let coverage = || CoverageEvidence {
        // An attempted result is partially covered: the execution is observed,
        // the delayed comparison is not. A no-attempt decision has no execution
        // to cover at all, and saying `UNAVAILABLE` keeps it distinct from an
        // attempt that was observed and produced nothing.
        disposition: if attempted {
            CoverageDisposition::IncompleteCoverage
        } else {
            CoverageDisposition::Unavailable
        },
        denominator_source_ref: format!("maintenance-family:{}", obligation.family),
        interval: Some(window),
        blind_intervals: Vec::new(),
        observed_count: u64::from(attempted),
    };
    let metric = |applicable: bool, unit: &str| MaintenanceMetricEvaluationV1 {
        baseline_observation_ref: None,
        // Immediate evidence the source really holds is preserved even while the
        // delayed comparison is still outstanding.
        immediate_observation_refs: if applicable {
            obligation.actual_effect_refs.clone()
        } else {
            Vec::new()
        },
        follow_up_observation_ref: None,
        comparison_window: window,
        unit: unit.to_owned(),
        coverage: coverage(),
        // No baseline observation has been admitted for this comparison yet, so
        // the metric is `UNKNOWN` with the reason it is unknown. It is not
        // reported as zero, and it is not reported as a pending follow-up
        // against a baseline that does not exist.
        result: if applicable {
            MaintenanceMetricResult::Unknown {
                reason_ref: FOLLOW_UP_PENDING_REASON.to_owned(),
            }
        } else {
            MaintenanceMetricResult::NotApplicable {
                reason_ref: NOT_APPLICABLE_REASON.to_owned(),
            }
        },
        // No measured delta means no direction. An unknown or inapplicable metric
        // never carries a directional assessment.
        directional_assessment: MaintenanceMetricAssessment::Unresolved,
        evaluation_method_ref: SOURCE_EVALUATION_METHOD.to_owned(),
        evaluation_method_revision: SOURCE_EVALUATION_METHOD_REVISION.to_owned(),
        exposure_workload_change_refs: Vec::new(),
        rival_explanation_refs: Vec::new(),
    };
    let utility = MaintenanceUtilityEvidenceV1 {
        recurrence: metric(true, "recurrences-per-window"),
        product_recovery_delta: metric(true, "recovery-events"),
        false_changes: metric(true, "false-changes"),
        cost: metric(attempted, "cost-units"),
        operator_burden: metric(attempted, "operator-minutes"),
    };
    let result = MaintenanceResultV1 {
        contract_version: MAINTENANCE_RESULT_CONTRACT_VERSION,
        source_trigger_ref: obligation.source_trigger_ref.clone(),
        decision_ref: obligation.decision_ref.clone(),
        family: obligation.family.to_string(),
        scope: scope.clone(),
        problem_ref: None,
        job_ref: obligation.job_ref.clone(),
        attempt_ref: obligation.attempt_ref.clone(),
        execution_receipt_ref: obligation.execution_receipt_ref.clone(),
        // The maintenance owner's own contract revision is the policy revision
        // that governed this decision; no policy owner publishes a finer one.
        policy_revision: format!("{}:{}", crate::CONTRACT_NAME, crate::CONTRACT_VERSION),
        recipe_revision: None,
        route_revision: None,
        build_revision: None,
        state_fence: obligation.state_fence.clone(),
        source_outcome_revision: obligation.source_outcome_revision.clone(),
        actual_effect_refs: obligation.actual_effect_refs.clone(),
        checkpoint_refs: obligation.checkpoint_refs.clone(),
        reconciliation_refs: obligation.reconciliation_refs.clone(),
        observation_coverage: coverage(),
        publication_id: obligation.publication_id.clone(),
        evaluation_revision: obligation.evaluation_revision,
        predecessor_evaluation_ref: obligation.predecessor_obligation_ref.clone(),
        execution_outcome: obligation.execution_outcome,
        delivery_state: obligation.delivery.clone(),
        utility_verdict: MaintenanceUtilityVerdict::Pending,
        utility,
    };
    let mut evidence = obligation.actual_effect_refs.clone();
    for reference in obligation
        .checkpoint_refs
        .iter()
        .chain(obligation.reconciliation_refs.iter())
    {
        if !evidence.contains(reference) {
            evidence.push(reference.clone());
        }
    }
    if let Some(receipt) = &obligation.execution_receipt_ref
        && !evidence.contains(receipt)
    {
        evidence.push(receipt.clone());
    }
    let core = ObservationEventCore {
        event_id_and_time: ObservationEventIdentity {
            event_id: obligation.publication_id.clone(),
            clock: eliot_contracts::ClockReading {
                valid_time_ms: i64::try_from(observed_at_unix_ms).ok(),
                known_time_ms: i64::try_from(observed_at_unix_ms).ok(),
                transaction_sequence: None,
                monotonic_ns: None,
            },
        },
        producer_generation_and_trace: ProducerTrace {
            producer: crate::CONTRACT_NAME.to_owned(),
            generation: obligation.state_fence.resource_generation.value().to_string(),
            trace_ref: Some(obligation.publication_id.clone()),
        },
        kind: ObservationKind::Maintenance,
        affected_scope: scope,
        observed_delta: format!(
            "maintenance outcome {:?} for family {} under job {:?}",
            obligation.execution_outcome, obligation.family, obligation.job_ref
        ),
        expected_baseline: None,
        evidence_and_raw_handles: evidence,
        coverage_and_blind_intervals: coverage(),
        privacy_retention_and_disclosure: PrivacyRetentionDisclosure {
            // The maintained subsystem's own scope and contract remain the
            // privacy domain and the retention policy: the governed self scope is
            // a projection, not a new disclosure authority.
            privacy_domain_ref: obligation.scope_ref.clone(),
            retention_policy_ref: format!("{}:{}", crate::CONTRACT_NAME, crate::CONTRACT_VERSION),
            disclosure_class: "maintenance-self-observation".to_owned(),
        },
        candidate_importance: 1,
        dedup_key: obligation.publication_id.clone(),
    };
    let record = MaintenanceRecord {
        record_id: obligation.publication_id.clone(),
        core,
        maintenance_action: format!("maintenance:{:?}", obligation.execution_outcome),
        trigger_ref: obligation.source_trigger_ref.clone(),
        result: Some(Box::new(result)),
    };
    record.validate().map_err(|error| {
        MaintenanceError::Store(format!("maintenance observation record: {error}"))
    })?;
    Ok(record)
}

fn text(value: &str, field: &'static str) -> Result<(), MaintenanceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(MaintenanceError::InvalidField(field));
    }
    Ok(())
}

fn unique_text(values: &[String], field: &'static str) -> Result<(), MaintenanceError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(MaintenanceError::IdentityConflict);
        }
    }
    Ok(())
}
