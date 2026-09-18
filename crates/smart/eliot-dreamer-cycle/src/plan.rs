//! One-cycle-horizon plan with at most one automatic experiment per target.
//!
//! A [`CyclePlan`] views the single adjacent controller phase reachable from
//! the frozen [`DreamerCycleState`](crate::contract::DreamerCycleState) through
//! the already-supplied [`CycleSample`](crate::sample::CycleSample). It emits
//! inert [`InertOwnerRequest`](crate::contract::InertOwnerRequest) projections
//! mirroring the pure one-snapshot controller plus at most one bounded
//! [`ExperimentCandidate`] per target, all within exactly one cycle. It
//! performs no store read, model call, outside execution, or timed dispatch,
//! and it carries no durable-job, wake, lease, route-reservation, or
//! re-enqueue field: the single
//! [`CyclePhase`](crate::contract::CyclePhase) chain remains the only
//! lifecycle vocabulary.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::contract::{
    CYCLE_SCHEMA_VERSION, CyclePhase, CyclePolicy, DreamerCycleState, InertOwnerRequest,
    MAX_CANONICAL_BYTES, MAX_REQUESTS, MAX_TEXT_BYTES, OutcomeDisposition, PendingRequest,
    validate_text,
};
use crate::error::CycleError;
use crate::sample::CycleSample;

/// Closed automatic experiment vocabulary.
///
/// An experiment is a bounded observation-only probe inside the single
/// adjacent phase. It never executes a lifecycle transition, reserves a
/// route, or enqueues further work.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExperimentKind {
    /// Ask the owner for one bounded clarification or probe.
    ClarificationProbe,
    /// Reconcile one already-observed possible effect under the same operation.
    ReconciliationProbe,
}

/// Exact plan horizon. The only representable horizon is one cycle.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlanHorizon {
    /// The plan covers exactly the single adjacent controller phase.
    OneCycle,
}

/// One bounded automatic experiment candidate for one target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExperimentCandidate {
    /// Opaque sampled target identity; not an executable instruction.
    pub target: String,
    /// Closed experiment vocabulary.
    pub kind: ExperimentKind,
    /// Plan horizon, always exactly one cycle.
    pub horizon: PlanHorizon,
    /// Human-readable bounded reason, with no executable instruction.
    pub reason: String,
}

impl ExperimentCandidate {
    /// Validates target/reason text shape and the single-cycle horizon.
    pub fn validate(&self) -> Result<(), CycleError> {
        validate_text(&self.target, "experiment.target")?;
        validate_text(&self.reason, "experiment.reason")?;
        match self.horizon {
            PlanHorizon::OneCycle => Ok(()),
        }
    }
}

/// One-cycle plan over a frozen sample of a frozen snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CyclePlan {
    /// Exact cycle schema revision.
    pub schema_version: u32,
    /// Cycle identity planned from the frozen state.
    pub cycle_id: ArtifactId,
    /// Controller phase the frozen state was sampled in.
    pub from_phase: CyclePhase,
    /// The single adjacent phase this plan covers.
    pub to_phase: CyclePhase,
    /// Plan horizon, always exactly one cycle.
    pub horizon: PlanHorizon,
    /// Digest of the complete frozen job.
    pub job_digest: String,
    /// Digest of the frozen input bundle.
    pub bundle_digest: String,
    /// Canonical digest of the frozen policy.
    pub policy_digest: String,
    /// Canonical digest of the frozen state.
    pub state_digest: String,
    /// Coverage digest of the frozen sample this plan was derived from.
    pub sample_digest: String,
    /// At most one automatic experiment per target, in sample order.
    pub experiments: Vec<ExperimentCandidate>,
    /// Inert owner request projections for the sampled scope.
    pub requests: Vec<InertOwnerRequest>,
    /// Unresolved material carried whole from the frozen state.
    pub frontier: Vec<String>,
    /// Digest of this plan payload excluding this field.
    pub plan_digest: String,
}

impl CyclePlan {
    /// Computes the plan digest while excluding the digest field itself.
    pub fn computed_digest(&self) -> Result<String, CycleError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            schema_version: u32,
            cycle_id: &'a ArtifactId,
            from_phase: CyclePhase,
            to_phase: CyclePhase,
            horizon: PlanHorizon,
            job_digest: &'a str,
            bundle_digest: &'a str,
            policy_digest: &'a str,
            state_digest: &'a str,
            sample_digest: &'a str,
            experiments: &'a [ExperimentCandidate],
            requests: &'a [InertOwnerRequest],
            frontier: &'a [String],
        }
        let bytes = eliot_contracts::canonical_json_bytes(&Payload {
            schema_version: self.schema_version,
            cycle_id: &self.cycle_id,
            from_phase: self.from_phase,
            to_phase: self.to_phase,
            horizon: self.horizon,
            job_digest: &self.job_digest,
            bundle_digest: &self.bundle_digest,
            policy_digest: &self.policy_digest,
            state_digest: &self.state_digest,
            sample_digest: &self.sample_digest,
            experiments: &self.experiments,
            requests: &self.requests,
            frontier: &self.frontier,
        })
        .map_err(|error| CycleError::Encoding(error.to_string()))?;
        if bytes.len() > MAX_CANONICAL_BYTES {
            return Err(CycleError::Bound {
                field: "plan.canonical_bytes",
                maximum: MAX_CANONICAL_BYTES,
            });
        }
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Validates the plan against its frozen sample, snapshot, and policy.
    pub fn validate(
        &self,
        sample: &CycleSample,
        state: &DreamerCycleState,
        policy: &CyclePolicy,
    ) -> Result<(), CycleError> {
        sample.validate(state, policy)?;
        if self.schema_version != CYCLE_SCHEMA_VERSION {
            return Err(CycleError::BindingMismatch {
                field: "plan.schema_version",
                reason: "unsupported schema version",
            });
        }
        let Some(expected_phase) = self.from_phase.next() else {
            return Err(CycleError::PhaseViolation(
                "plan horizon has no adjacent phase",
            ));
        };
        if self.from_phase != state.phase
            || self.from_phase != sample.phase
            || self.to_phase != expected_phase
        {
            return Err(CycleError::PhaseViolation(
                "plan does not cover exactly the single adjacent phase",
            ));
        }
        match self.horizon {
            PlanHorizon::OneCycle => {}
        }
        if self.cycle_id != state.cycle_id
            || self.job_digest != sample.job_digest
            || self.bundle_digest != sample.bundle_digest
            || self.policy_digest != sample.policy_digest
            || self.state_digest != sample.state_digest
            || self.sample_digest != sample.coverage_digest
        {
            return Err(CycleError::BindingMismatch {
                field: "plan.snapshot_binding",
                reason: "plan digests differ from the frozen sample",
            });
        }
        if self.frontier != state.frontier {
            return Err(CycleError::BindingMismatch {
                field: "plan.frontier",
                reason: "plan frontier differs from the frozen state",
            });
        }
        self.validate_experiments(sample)?;
        self.validate_requests(sample, policy)?;
        if self.plan_digest != self.computed_digest()? {
            return Err(CycleError::IdentityConflict {
                identity: "plan.plan_digest".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_experiments(&self, sample: &CycleSample) -> Result<(), CycleError> {
        if self.experiments.len() > MAX_REQUESTS {
            return Err(CycleError::Bound {
                field: "plan.experiments",
                maximum: MAX_REQUESTS,
            });
        }
        let mut targets = BTreeSet::new();
        for experiment in &self.experiments {
            experiment.validate()?;
            // At most one automatic experiment per target.
            if !targets.insert(experiment.target.clone()) {
                return Err(CycleError::IdentityConflict {
                    identity: experiment.target.clone(),
                });
            }
            let sampled = sample
                .sampled_pending
                .iter()
                .any(|identity| identity.as_str() == experiment.target);
            if !sampled {
                return Err(CycleError::BindingMismatch {
                    field: "experiment.target",
                    reason: "experiment target is outside the frozen sample",
                });
            }
        }
        Ok(())
    }

    fn validate_requests(
        &self,
        sample: &CycleSample,
        policy: &CyclePolicy,
    ) -> Result<(), CycleError> {
        if self.requests.len() > policy.max_requests as usize || self.requests.len() > MAX_REQUESTS
        {
            return Err(CycleError::BudgetBlocked);
        }
        for request in &self.requests {
            validate_text(&request.reason, "plan.request.reason")?;
            if request.reason.len() > MAX_TEXT_BYTES {
                return Err(CycleError::Bound {
                    field: "plan.request.reason",
                    maximum: MAX_TEXT_BYTES,
                });
            }
            let sampled = sample
                .sampled_pending
                .iter()
                .any(|identity| identity == &request.request_id);
            if !sampled {
                return Err(CycleError::BindingMismatch {
                    field: "plan.request",
                    reason: "plan request is outside the frozen sample",
                });
            }
        }
        Ok(())
    }
}

/// Returns whether a pending request already has a blocking owner outcome.
///
/// This mirrors the controller transition so a plan never probes a target the
/// controller itself has stopped requesting.
fn pending_has_blocked_outcome(state: &DreamerCycleState, pending: &PendingRequest) -> bool {
    state
        .outcomes
        .iter()
        .rev()
        .find(|outcome| outcome.receipt.core.request.metadata.request_id == pending.request_id)
        .is_some_and(|outcome| {
            !matches!(
                outcome.disposition,
                OutcomeDisposition::Accepted | OutcomeDisposition::Unknown
            )
        })
}

fn experiment_kind_for(state: &DreamerCycleState, pending: &PendingRequest) -> ExperimentKind {
    let needs_reconciliation = state
        .outcomes
        .iter()
        .any(|outcome| outcome.receipt.core.request.metadata.request_id == pending.request_id);
    if needs_reconciliation {
        ExperimentKind::ReconciliationProbe
    } else {
        ExperimentKind::ClarificationProbe
    }
}

/// Derives a one-cycle plan over a frozen sample of a frozen snapshot.
///
/// Requests restate the controller's own inert surface for the sampled,
/// unblocked pending scope; experiments probe only targets in the single
/// adjacent phase with at most one automatic experiment per target. The
/// frozen sample, snapshot, policy, and dispatch budget are validated first.
pub fn plan_cycle(
    sample: &CycleSample,
    state: &DreamerCycleState,
    policy: &CyclePolicy,
    observation_time_ms: Option<i64>,
) -> Result<CyclePlan, CycleError> {
    sample.validate(state, policy)?;
    crate::policy::check_dispatch_budget(state, policy, observation_time_ms)?;
    let Some(to_phase) = state.phase.next() else {
        return Err(CycleError::PhaseViolation(
            "plan horizon has no adjacent phase",
        ));
    };
    let mut requests = Vec::new();
    let mut experiments = Vec::new();
    let mut planned_targets = BTreeSet::new();
    for identity in &sample.sampled_pending {
        let Some(pending) = state
            .pending
            .iter()
            .find(|pending| &pending.request_id == identity)
        else {
            return Err(CycleError::BindingMismatch {
                field: "plan.request",
                reason: "sampled pending identity is missing from frozen state",
            });
        };
        if pending_has_blocked_outcome(state, pending) {
            continue;
        }
        requests.push(InertOwnerRequest {
            request_id: pending.request_id.clone(),
            operation_id: pending.operation_id.clone(),
            attempt_id: pending.attempt_id.clone(),
            owner: pending.owner.clone(),
            kind: pending.kind,
            phase: pending.phase,
            payload_digest: pending.payload_digest.clone(),
            task_id: pending.task_id.clone(),
            scope_id: pending.scope_id.clone(),
            state_fence: pending.state_fence.clone(),
            predecessor_receipt_id: pending.predecessor_receipt_id.clone(),
            reason: "awaiting an externally supplied owner observation".to_owned(),
        });
        // Only adjacent-phase targets are actionable within one cycle, and
        // each target receives at most one automatic experiment.
        if pending.phase == to_phase && planned_targets.insert(identity.as_str().to_owned()) {
            experiments.push(ExperimentCandidate {
                target: identity.as_str().to_owned(),
                kind: experiment_kind_for(state, pending),
                horizon: PlanHorizon::OneCycle,
                reason: "one bounded automatic probe within the single adjacent phase".to_owned(),
            });
        }
    }
    if requests.len() > policy.max_requests as usize || requests.len() > MAX_REQUESTS {
        return Err(CycleError::BudgetBlocked);
    }
    if experiments.len() > MAX_REQUESTS {
        return Err(CycleError::Bound {
            field: "plan.experiments",
            maximum: MAX_REQUESTS,
        });
    }
    let mut plan = CyclePlan {
        schema_version: CYCLE_SCHEMA_VERSION,
        cycle_id: state.cycle_id.clone(),
        from_phase: state.phase,
        to_phase,
        horizon: PlanHorizon::OneCycle,
        job_digest: sample.job_digest.clone(),
        bundle_digest: sample.bundle_digest.clone(),
        policy_digest: sample.policy_digest.clone(),
        state_digest: sample.state_digest.clone(),
        sample_digest: sample.coverage_digest.clone(),
        experiments,
        requests,
        frontier: state.frontier.clone(),
        plan_digest: String::new(),
    };
    plan.plan_digest = plan.computed_digest()?;
    plan.validate(sample, state, policy)?;
    Ok(plan)
}
