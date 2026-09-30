//! The delayed utility evaluation one maintenance source result owes.
//!
//! Three facts stay apart here, exactly as the source-side producer keeps them
//! apart. Work performed is not utility. A published observation is not
//! utility. Only **measured evidence about the maintained subsystem, compared
//! against an admitted baseline** is utility evidence — which is why this
//! module reads prior outcomes instead of reading the job that produced them.
//!
//! The bounded read is the job's own append-only
//! [`MaintenanceResultObligation`](crate::MaintenanceResultObligation) chain on
//! the retained durable revision. That chain is what makes a delayed
//! comparison possible at all: a reconciliation obligation carries the
//! resolved outcome of an earlier uncertainty, so an earlier result's
//! follow-up comparison is anchored to an obligation the owner really
//! recorded rather than to a prediction.
//!
//! Four rules are the whole point:
//!
//! * **A completed process cannot establish utility.** Nothing here reads
//!   [`MaintenanceJobState`](crate::MaintenanceJobState) or `outcome_ref`. The
//!   only input is the obligation chain, so a result nobody reconciled carries
//!   no measurable follow-up and its verdict stays `PENDING` however cleanly
//!   it completed.
//! * **Evidence is bound to the operation it compares.** Every measurement
//!   must name two obligations this job's own chain holds. A comparison
//!   anchored to evidence the job never recorded is refused, not believed.
//! * **A later evaluation appends; it never erases.** The evaluation rides on
//!   a *new* obligation appended to the chain, with `evaluation_revision`
//!   advanced and `predecessor_obligation_ref` naming what it appends to. The
//!   original revision and its `UNKNOWN` metrics stay in the chain untouched.
//! * **Repeated unchanged failure stays visible.** The evaluator reaches no
//!   trigger, admits no job, starts no timer and appends no lifecycle
//!   transition. It is a pure function from one obligation chain plus one
//!   measured comparison set to one appended evaluation revision, so feeding
//!   the same unchanged evidence twice yields the same revision and the store
//!   reconciles them rather than accumulating. Nothing closes its own loop.
//!
//! Every metric is reported through the existing
//! [`MaintenanceMetricEvaluationV1`] vocabulary and every directional verdict
//! is decided by the contract's own
//! [`supports_benefit_claim`](eliot_observation_contracts::MaintenanceUtilityEvidenceV1::supports_benefit_claim)
//! / [`supports_harm_claim`](eliot_observation_contracts::MaintenanceUtilityEvidenceV1::supports_harm_claim)
//! predicates, which `MaintenanceResultV1::validate_utility_verdict` also
//! enforces. This module never decides direction itself and never relaxes a
//! threshold.

use std::collections::BTreeMap;

use eliot_observation_contracts::{
    BlindInterval, CoverageDisposition, CoverageEvidence, CoverageInterval, MaintenanceDeliveryState,
    MaintenanceMetricAssessment, MaintenanceMetricEvaluationV1, MaintenanceMetricResult,
    MaintenanceMetricValueBasis, MaintenanceUtilityEvidenceV1, MaintenanceUtilityVerdict,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::result_obligation::{
    MAX_RESULT_OBLIGATIONS, SOURCE_EVALUATION_METHOD, SOURCE_EVALUATION_METHOD_REVISION,
};
use crate::{
    AdmittedObservationReceipt, MaintenanceError, MaintenanceJob, MaintenanceResultObligation,
};

/// Named reason recorded when a required metric's comparison was never
/// observed.
///
/// The honest state at an unmeasured comparison. It is a reason reference, not
/// a zero and not a benefit, and it is what keeps an unobserved interval from
/// reading as "no recurrence".
pub const MEASUREMENT_UNOBSERVED_REASON: &str = "maintenance.metric-comparison-not-observed";

/// The unit the contract's cost metric is expressed in.
///
/// Reused verbatim from the source-side producer's projection, so the baseline
/// revision and this appended evaluation revision state the same cost unit
/// rather than each naming its own.
const COST_UNIT: &str = "cost-units";

/// One of the four required metrics a delayed comparison binds.
///
/// `cost` is deliberately absent: I14.22's cost is the billed/actual cost of
/// the maintenance action, which belongs to the budget and usage owners rather
/// than to a comparison this crate can measure from its own obligation chain.
/// Leaving it out is precisely what stops a completion from reading as a
/// benefit, because the contract refuses `BENEFICIAL` unless all five of its
/// required metrics carry complete measured evidence — so benefit becomes
/// reachable exactly when a real cost owner supplies one, and not before.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequiredUtilityMetric {
    /// Failures observed for this family and scope inside the window.
    Recurrence,
    /// Product or recovery events inside the window.
    ProductRecoveryDelta,
    /// Changes the action introduced that were wrong.
    FalseChanges,
    /// Operator time or burden, never inferred from silence.
    OperatorBurden,
}

impl RequiredUtilityMetric {
    /// The named unit this metric's value is expressed in.
    ///
    /// Reused verbatim from the source-side producer's projection, so the
    /// baseline revision and this appended evaluation revision state the same
    /// unit for the same metric rather than each naming its own.
    const fn unit(self) -> &'static str {
        match self {
            Self::Recurrence => "recurrences-per-window",
            Self::ProductRecoveryDelta => "recovery-events",
            Self::FalseChanges => "false-changes",
            Self::OperatorBurden => "operator-minutes",
        }
    }
}

/// One measured comparison for a single required metric, supplied by the owner
/// that actually observed it.
///
/// The evaluator measures nothing itself and accepts no bare score. It binds
/// the caller's measurement to the evidence supporting it: both observation
/// references must name obligations in the job's own retained chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtilityMetricMeasurement {
    /// Which required metric this measurement is for.
    pub metric: RequiredUtilityMetric,
    /// The observed value in [`MaintenanceMetricEvaluationV1::unit`].
    pub value: String,
    /// How the value was obtained, so an estimate is never read as billed or
    /// actual cost.
    pub basis: MaintenanceMetricValueBasis,
    /// The prior obligation this comparison measures against.
    pub baseline_observation_ref: String,
    /// The obligation carrying the follow-up observation.
    pub follow_up_observation_ref: String,
    /// The exact window the two observations bound.
    pub comparison_window: CoverageInterval,
    /// Whether that window was fully and independently observed.
    ///
    /// A caller admitting a blind interval is stating that part of the interval
    /// was not observed. The blind interval is preserved as evidence and the
    /// contract's predicate then refuses a directional claim on it, which is
    /// the mechanism behind "no failures during an unobserved interval is not
    /// zero recurrence".
    pub coverage: CoverageEvidence,
    /// Direction the caller's named evaluation method assigned.
    pub directional_assessment: MaintenanceMetricAssessment,
    /// Evaluator identity the caller measured under.
    pub evaluation_method_ref: String,
    /// Revision of that evaluator.
    pub evaluation_method_revision: String,
    /// Named exposure or workload changes relevant to attribution.
    pub exposure_workload_change_refs: Vec<String>,
    /// Named rival explanations that remain live for this comparison.
    pub rival_explanation_refs: Vec<String>,
}

impl UtilityMetricMeasurement {
    /// Binds this measurement into the shared comparison vocabulary.
    ///
    /// No evidence identity is checked here: binding a reference to an
    /// obligation the job really recorded is
    /// [`evaluate_maintenance_utility`]'s job, because only it holds the chain.
    /// The projected metric states the measured value and its basis; the
    /// contract's own validators check its coherence.
    #[must_use]
    pub fn to_metric_evaluation(&self) -> MaintenanceMetricEvaluationV1 {
        MaintenanceMetricEvaluationV1 {
            baseline_observation_ref: Some(self.baseline_observation_ref.clone()),
            immediate_observation_refs: Vec::new(),
            follow_up_observation_ref: Some(self.follow_up_observation_ref.clone()),
            comparison_window: self.comparison_window,
            unit: self.metric.unit().to_owned(),
            coverage: self.coverage.clone(),
            result: MaintenanceMetricResult::Value {
                value: self.value.clone(),
                basis: self.basis,
            },
            directional_assessment: self.directional_assessment,
            evaluation_method_ref: self.evaluation_method_ref.clone(),
            evaluation_method_revision: self.evaluation_method_revision.clone(),
            exposure_workload_change_refs: self.exposure_workload_change_refs.clone(),
            rival_explanation_refs: self.rival_explanation_refs.clone(),
        }
    }
}

/// The measured comparison set one caller presents for evaluation.
///
/// Nothing here is derived from work performed. The caller supplies only the
/// comparisons it genuinely observed. An empty set is the honest state at a
/// fresh source result: the follow-up window has not elapsed, so nothing was
/// measured, and the evaluation yields `PENDING` rather than a verdict.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UtilityEvaluationEvidence {
    /// Measured comparisons, at most one per required metric.
    pub measurements: Vec<UtilityMetricMeasurement>,
}

/// One appended delayed evaluation revision of one maintenance source result.
///
/// This is data about a comparison, not its effect: it names what was measured,
/// against which exact prior evidence, over which window, and what the
/// contract's own predicates concluded. It never closes a problem, promotes a
/// policy, raises a model budget, or admits any work.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceUtilityEvaluation {
    /// The source result revision this evaluation appends to.
    pub source_publication_id: String,
    /// The conclusion, decided by the contract's predicates.
    pub utility_verdict: MaintenanceUtilityVerdict,
    /// Every required metric, measured or explicitly unknown.
    pub utility: MaintenanceUtilityEvidenceV1,
    /// The exact window every reported comparison was bounded by.
    pub comparison_window: CoverageInterval,
}

/// Evaluates one maintenance source result's delayed utility against the
/// evidence its own obligation chain holds.
///
/// This is the whole evaluator, and it is pure: the same source result, chain
/// and evidence always produce the same evaluation, so a retry reconciles
/// instead of accumulating. It reaches no trigger, job, store or clock.
///
/// # How a verdict becomes reachable
///
/// The verdict is the contract's conclusion, reached through the same
/// predicates `MaintenanceResultV1::validate_utility_verdict` enforces:
///
/// * `BENEFICIAL` requires all five of the contract's required metrics —
///   recurrence, product/recovery delta, false changes, cost and operator
///   burden — to carry directly observed values with both admitted observation
///   references, complete coverage, no blind interval and a benefit or
///   no-material-change direction. This module binds four of those five and
///   deliberately does not invent a cost measurement, so benefit becomes
///   reachable exactly when a real cost owner supplies one. It cannot be
///   reached from a completion alone, by construction.
/// * `HARMFUL` requires a measured harm direction on complete unblinded
///   evidence and no metric claiming benefit.
/// * `INCONCLUSIVE` is reached when comparisons were observed but the evidence
///   establishes neither direction.
/// * `PENDING` is reached when no comparison has been observed at all.
///
/// # Errors
///
/// Returns [`MaintenanceError::InvalidField`] when the source obligation is
/// malformed, when the evaluation window is inverted, when a measurement names
/// a baseline or follow-up reference that is not an obligation in this job's
/// own chain, when a measurement's declared coverage interval disagrees with
/// its comparison window, when a measurement's window lies outside the
/// evaluation window, or when a measurement's baseline is not strictly earlier
/// in the chain than its follow-up. Returns [`MaintenanceError::IdentityConflict`]
/// when two measurements claim the same metric.
#[allow(
    clippy::too_many_lines,
    reason = "one fail-closed evidence-binding clause per rule, checked together so none can be reordered past another"
)]
pub fn evaluate_maintenance_utility(
    source: &MaintenanceResultObligation,
    chain: &[MaintenanceResultObligation],
    evaluation_window: CoverageInterval,
    evidence: &UtilityEvaluationEvidence,
) -> Result<MaintenanceUtilityEvaluation, MaintenanceError> {
    source.validate()?;
    // Freshness of the binding itself: an evaluation whose window ends before
    // it starts has no elapsed comparison to report over.
    if evaluation_window.end < evaluation_window.start {
        return Err(MaintenanceError::InvalidField(
            "utility_evaluation.evaluation_window",
        ));
    }
    let position = |publication_id: &str| {
        chain
            .iter()
            .position(|entry| entry.publication_id == publication_id)
    };
    // The chain must hold the source result. Evaluating a result the retained
    // chain does not contain would bind the comparison to nothing.
    if position(&source.publication_id).is_none() {
        return Err(MaintenanceError::InvalidField(
            "utility_evaluation.source_publication_id",
        ));
    }
    let mut by_metric = BTreeMap::new();
    for measurement in &evidence.measurements {
        if measurement.coverage.interval != Some(measurement.comparison_window) {
            return Err(MaintenanceError::InvalidField("utility_evaluation.coverage"));
        }
        if measurement.comparison_window.start < evaluation_window.start
            || measurement.comparison_window.end > evaluation_window.end
        {
            return Err(MaintenanceError::InvalidField(
                "utility_evaluation.comparison_window",
            ));
        }
        // Evidence is bound to the operation it compares: both references must
        // name obligations this job's own retained chain holds, and the
        // baseline must precede the follow-up in that chain. A reversed
        // comparison is refused rather than reported.
        let (Some(baseline), Some(follow_up)) = (
            position(&measurement.baseline_observation_ref),
            position(&measurement.follow_up_observation_ref),
        ) else {
            return Err(MaintenanceError::InvalidField(
                "utility_evaluation.observation_ref",
            ));
        };
        if baseline >= follow_up {
            return Err(MaintenanceError::InvalidField(
                "utility_evaluation.observation_ref",
            ));
        }
        if by_metric
            .insert(measurement.metric, measurement.to_metric_evaluation())
            .is_some()
        {
            return Err(MaintenanceError::IdentityConflict);
        }
    }
    let metric = |metric: RequiredUtilityMetric| match by_metric.get(&metric) {
        Some(measured) => measured.clone(),
        // A metric with no observed comparison is reported as explicitly
        // unknown over the same window, so a reader sees which evidence is
        // missing rather than a missing metric.
        None => unobserved_metric(metric.unit(), evaluation_window),
    };
    let utility = MaintenanceUtilityEvidenceV1 {
        recurrence: metric(RequiredUtilityMetric::Recurrence),
        product_recovery_delta: metric(RequiredUtilityMetric::ProductRecoveryDelta),
        false_changes: metric(RequiredUtilityMetric::FalseChanges),
        // Cost stays explicitly unobserved under its own unit. This module holds
        // no billing evidence, and reporting the job's reserved budget as a
        // cost would let a budget read as a spent one.
        cost: unobserved_metric(COST_UNIT, evaluation_window),
        operator_burden: metric(RequiredUtilityMetric::OperatorBurden),
    };
    // The verdict is the contract's conclusion, not this function's. Both
    // predicates are the ones the record validator enforces, so a verdict
    // reached here is one the contract accepts.
    let utility_verdict = if utility.supports_benefit_claim() {
        MaintenanceUtilityVerdict::Beneficial
    } else if utility.supports_harm_claim() {
        MaintenanceUtilityVerdict::Harmful
    } else if any_measured(&utility) {
        MaintenanceUtilityVerdict::Inconclusive
    } else {
        MaintenanceUtilityVerdict::Pending
    };
    Ok(MaintenanceUtilityEvaluation {
        source_publication_id: source.publication_id.clone(),
        utility_verdict,
        utility,
        comparison_window: evaluation_window,
    })
}

/// Appends one delayed evaluation revision to a job's obligation chain.
///
/// The evaluation is durable: it is appended through the caller's existing
/// single [`MaintenanceStateStore::save`](crate::MaintenanceStateStore::save),
/// so the revision and the job state it describes become durable together or in
/// neither, and a restart re-reads the same evaluation rather than recomputing
/// it from nothing. The evaluation rides on the appended obligation itself, so
/// re-presenting it publishes the same verdict under the same identity.
///
/// # Errors
///
/// Returns [`MaintenanceError::InvalidField`] when the job is malformed, when
/// the named source result is not the job's latest obligation, when that latest
/// obligation is already an appended evaluation, when the chain is already at
/// its retained bound, or when the evaluation's window disagrees with the metric
/// projections it carries. Returns [`MaintenanceError::Store`] when the
/// appended revision does not validate.
pub fn append_utility_evaluation(
    job: &MaintenanceJob,
    evaluation: &MaintenanceUtilityEvaluation,
) -> Result<MaintenanceJob, MaintenanceError> {
    job.validate()?;
    let source = job
        .result_obligations
        .last()
        .ok_or(MaintenanceError::InvalidField("job.result_obligations"))?;
    if source.publication_id != evaluation.source_publication_id {
        return Err(MaintenanceError::InvalidField(
            "utility_evaluation.source_publication_id",
        ));
    }
    // The chain's tail must be a source result, never an appended evaluation.
    // This is the structural reason repeated evaluation of an unchanged result
    // cannot become an autonomous feedback loop: once the evaluation is
    // appended there is no longer an un-evaluated source result at the tail, so
    // re-evaluation is refused rather than chained. A later comparison arrives
    // through a later source result, not by evaluating this one again.
    if source.utility_evaluation.is_some() {
        return Err(MaintenanceError::InvalidField(
            "utility_evaluation.already_evaluated",
        ));
    }
    if job.result_obligations.len() >= MAX_RESULT_OBLIGATIONS {
        return Err(MaintenanceError::InvalidField("job.result_obligations"));
    }
    for metric in [
        &evaluation.utility.recurrence,
        &evaluation.utility.product_recovery_delta,
        &evaluation.utility.false_changes,
        &evaluation.utility.cost,
        &evaluation.utility.operator_burden,
    ] {
        if metric.comparison_window != evaluation.comparison_window {
            return Err(MaintenanceError::InvalidField(
                "utility_evaluation.comparison_window",
            ));
        }
    }
    // The appended revision keeps the source result's identity except for the
    // derived revision suffix, so it is a pure function of the source event:
    // re-evaluating the same source against the same evidence republishes one
    // identity and the store reconciles it rather than writing a second record.
    let evaluation_revision = source.evaluation_revision + 1;
    let publication_id = format!(
        "{}:evaluated-r{evaluation_revision}",
        source.publication_id
    );
    let appended = MaintenanceResultObligation {
        publication_id: publication_id.clone(),
        source_outcome_revision: format!(
            "{}:evaluated-r{evaluation_revision}",
            source.source_outcome_revision
        ),
        evaluation_revision,
        predecessor_obligation_ref: Some(source.publication_id.clone()),
        // A delayed evaluation is a claim about evidence, never about
        // execution, so it carries the source result's execution evidence
        // verbatim and re-enters no lifecycle transition.
        execution_outcome: source.execution_outcome,
        delivery: MaintenanceDeliveryState::Pending {
            obligation_ref: publication_id,
        },
        utility_evaluation: Some(evaluation.clone()),
        ..source.clone()
    };
    appended.validate()?;
    let mut next = job.clone();
    next.result_obligations.push(appended);
    next.validate()?;
    Ok(next)
}

/// Whether one maintenance result owes a delayed utility evaluation at all.
///
/// A result is only evaluable once the canonical route has admitted its
/// observation: a comparison anchored to a publication the store never accepted
/// would measure nothing. This is the same admission test the coverage pass
/// uses, read from the same independent admitted-receipt set — never from the
/// job's own `outcome_ref`, which is a reference a caller could predict.
///
/// # Errors
///
/// Propagates every [`MaintenanceError`] from
/// [`MaintenanceResultObligation::validate`] and
/// [`AdmittedObservationReceipt::validate`].
pub fn result_is_evaluable(
    obligation: &MaintenanceResultObligation,
    admitted: &[AdmittedObservationReceipt],
) -> Result<bool, MaintenanceError> {
    obligation.validate()?;
    for receipt in admitted {
        receipt.validate()?;
    }
    Ok(matches!(
        obligation.delivery,
        MaintenanceDeliveryState::Published { .. }
    ) && admitted
        .iter()
        .any(|receipt| receipt.publication_id == obligation.publication_id))
}

/// The honest projection for a required metric with no observed comparison.
///
/// `UNKNOWN` with the reason it is unknown, and `UNRESOLVED` direction, over
/// the evaluation window with that window preserved as a blind interval. Never a
/// zero, never a benefit, and never a `PENDING` against a baseline that does
/// not exist.
fn unobserved_metric(
    unit: &str,
    evaluation_window: CoverageInterval,
) -> MaintenanceMetricEvaluationV1 {
    MaintenanceMetricEvaluationV1 {
        baseline_observation_ref: None,
        immediate_observation_refs: Vec::new(),
        follow_up_observation_ref: None,
        comparison_window: evaluation_window,
        unit: unit.to_owned(),
        coverage: CoverageEvidence {
            disposition: CoverageDisposition::IncompleteCoverage,
            denominator_source_ref: format!("maintenance-metric:{unit}"),
            interval: Some(evaluation_window),
            // The unobserved comparison is preserved as a blind interval rather
            // than dropped: dropping it is what would let an unobserved
            // interval read as zero recurrence.
            blind_intervals: vec![BlindInterval {
                interval: evaluation_window,
                reason_ref: MEASUREMENT_UNOBSERVED_REASON.to_owned(),
            }],
            observed_count: 0,
        },
        result: MaintenanceMetricResult::Unknown {
            reason_ref: MEASUREMENT_UNOBSERVED_REASON.to_owned(),
        },
        directional_assessment: MaintenanceMetricAssessment::Unresolved,
        evaluation_method_ref: SOURCE_EVALUATION_METHOD.to_owned(),
        evaluation_method_revision: SOURCE_EVALUATION_METHOD_REVISION.to_owned(),
        exposure_workload_change_refs: Vec::new(),
        rival_explanation_refs: Vec::new(),
    }
}

/// Whether any required metric carries an observed value.
fn any_measured(utility: &MaintenanceUtilityEvidenceV1) -> bool {
    [
        &utility.recurrence,
        &utility.product_recovery_delta,
        &utility.false_changes,
        &utility.cost,
        &utility.operator_burden,
    ]
    .into_iter()
    .any(|metric| matches!(metric.result, MaintenanceMetricResult::Value { .. }))
}