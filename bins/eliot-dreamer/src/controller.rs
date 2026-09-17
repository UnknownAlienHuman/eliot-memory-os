//! Governed controller handoff for admitted Dreamer jobs (issue #702, Slice 2).
//!
//! After `dispatch_admission` admits a job class,
//! the binary hands the admitted job to the #806 owner transition
//! ([`step_dreamer_cycle_at`](eliot_dreamer_cycle::step_dreamer_cycle_at))
//! exactly once, then to the A-04 bundle stage. This module owns no transition
//! algorithm, performs no I/O, fetch, ranking, or model work, and invents no
//! state: the pure owner function decides, this composition only calls it once
//! and maps its typed refusal fail-closed.
//!
//! Stage order is `dispatch_admission`, then the
//! controller step here, then
//! [`plan_admitted_bundle`](crate::bundle_stage::plan_admitted_bundle): a
//! refused class returns at dispatch with zero controller and zero bundle
//! work, and a failed controller step never reaches the bundle stage.

use eliot_dreamer_cycle::{
    CycleError, CyclePolicy, CycleStep, DreamerCycleState, ObservedOutcome, step_dreamer_cycle_at,
};

use crate::{DreamJobInput, DreamerError, KernelJobAdmission};

/// Verifies that a flat semantic input names exactly the Kernel-admitted job.
///
/// Runs before any controller or bundle work, so invalid or stale Kernel
/// input fails closed with zero stage calls. The fence/identity binding is
/// defense in depth alongside the claim-port check: admission freshness comes
/// from [`KernelJobAdmission::validate`], claimed-identity binding from the
/// job/scope match.
pub(crate) fn verify_admitted_binding(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<(), DreamerError> {
    job.validate()?;
    admission.validate()?;
    if admission.job_id != job.job_id || admission.scope_id != job.scope_id {
        return Err(DreamerError::KernelAdmissionRequired(
            "job/attempt identity does not match the admitted semantic input".to_owned(),
        ));
    }
    Ok(())
}

/// Resolves the #806 inputs for one admitted job.
///
/// Fails closed: any invalid/stale admission or identity mismatch refuses here
/// with zero owner-transition calls. The Governor-issued controller snapshot
/// (frozen state, observed outcomes, policy, bundle digest) arrives through a
/// source-owner port in a later slice; until then resolution refuses rather
/// than synthesizing state, because a locally built state would be self-issued
/// authority (I9.4: the denominator arrives with governed material; Dreamer
/// never selects it).
pub(crate) fn resolve_cycle_inputs(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<
    (
        DreamerCycleState,
        Vec<ObservedOutcome>,
        CyclePolicy,
        Option<i64>,
    ),
    DreamerError,
> {
    verify_admitted_binding(admission, job)?;
    Err(DreamerError::InvalidAdmission(
        "admitted controller inputs require Governor-resolved material",
    ))
}

/// Runs the admitted #806 transition exactly once.
///
/// `step_once` is `FnOnce`: the owner transition cannot run twice for one
/// admission through this seam. Production passes
/// [`step_dreamer_cycle_at`](eliot_dreamer_cycle::step_dreamer_cycle_at);
/// deterministic tests pass a counting wrapper around the real function to
/// prove the once-per-admission call shape.
pub(crate) fn step_admitted_cycle_with(
    state: &DreamerCycleState,
    observed: &[ObservedOutcome],
    policy: &CyclePolicy,
    observation_time_ms: Option<i64>,
    step_once: impl FnOnce(
        &DreamerCycleState,
        &[ObservedOutcome],
        &CyclePolicy,
        Option<i64>,
    ) -> Result<CycleStep, CycleError>,
) -> Result<CycleStep, DreamerError> {
    step_once(state, observed, policy, observation_time_ms).map_err(|error| cycle_denied(&error))
}

/// Production entry: the real #806 one-step transition, once per admission.
pub(crate) fn step_admitted_cycle(
    state: &DreamerCycleState,
    observed: &[ObservedOutcome],
    policy: &CyclePolicy,
    observation_time_ms: Option<i64>,
) -> Result<CycleStep, DreamerError> {
    step_admitted_cycle_with(
        state,
        observed,
        policy,
        observation_time_ms,
        step_dreamer_cycle_at,
    )
}

/// Maps an owner transition refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code: the admission itself was valid, the
/// controller inputs were not. Dynamic payloads (identities, digests) are
/// dropped in favor of bounded static reasons; nothing secret flows.
fn cycle_denied(error: &CycleError) -> DreamerError {
    match error {
        CycleError::BindingMismatch { field, .. } | CycleError::Bound { field, .. } => {
            DreamerError::InvalidAdmission(field)
        }
        CycleError::PhaseViolation(reason) | CycleError::IncompleteOutcome(reason) => {
            DreamerError::InvalidAdmission(reason)
        }
        CycleError::IdentityConflict { .. } => {
            DreamerError::InvalidAdmission("controller identity conflict")
        }
        CycleError::BudgetBlocked => DreamerError::InvalidAdmission(
            "controller budget or cancellation blocked the transition",
        ),
        CycleError::Contract(_) => DreamerError::InvalidAdmission("controller contract violation"),
        CycleError::Receipt(_) => DreamerError::InvalidAdmission("controller receipt violation"),
        CycleError::Encoding(_) => DreamerError::InvalidAdmission("controller encoding failure"),
    }
}

#[cfg(test)]
mod slice_2_controller_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use eliot_contracts::{EpochId, EpochLineageId, PolicyRevision, ResourceGeneration, StateFence};
    use eliot_dreamer_contracts::{
        BudgetLimits, DreamJobAdmission, JobClass, Requester, RequesterOrigin,
    };
    use eliot_dreamer_cycle::CyclePhase;

    use crate::KERNEL_ADMISSION_REQUIRED;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            std::num::NonZeroU64::new(1).expect("nonzero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn admission_with_deadline(deadline_unix_ms: u64) -> KernelJobAdmission {
        KernelJobAdmission {
            job_id: "job-slice-2".to_owned(),
            attempt_id: "attempt-slice-2".to_owned(),
            scope_id: "scope-slice-2".to_owned(),
            request_id: "request-slice-2".to_owned(),
            idempotency_key: "job-slice-2:attempt-slice-2".to_owned(),
            cancellation_id: "cancel-slice-2".to_owned(),
            deadline_unix_ms,
            state_fence: fence(),
        }
    }

    fn job_for(admission: &KernelJobAdmission) -> DreamJobInput {
        DreamJobInput {
            job_id: admission.job_id.clone(),
            job_class: JobClass::Orientation,
            exact_question: "What does ELIOT know about this scope?".to_owned(),
            requester: "test-harness".to_owned(),
            scope_id: admission.scope_id.clone(),
            task_id: None,
            state_fence: "kernel-owned".to_owned(),
            evidence_handles: Vec::new(),
            memory_handles: Vec::new(),
            architecture_handles: Vec::new(),
            implementation_handles: Vec::new(),
            conformance_handles: Vec::new(),
            conflicts_and_unknowns: Vec::new(),
            privacy_profile: "local_only".to_owned(),
            allowed_tools: Vec::new(),
            allowed_model_routes: vec!["route-test".to_owned()],
            budget_units: 1,
            deadline_ms: 1,
            output_schema: "eliot.dreamer.v1".to_owned(),
            forbidden_effects: Vec::new(),
        }
    }

    /// Stale Kernel input fails closed at resolution with zero transition
    /// calls: resolution precedes the step, so there is no step to count —
    /// the refusal itself is the proof, and it carries the request-rejected
    /// code, never the Kernel-admission code for a mere stale deadline.
    #[test]
    fn stale_admission_fails_closed_before_any_step() {
        let admission = admission_with_deadline(1);
        let job = job_for(&admission);
        let refused = resolve_cycle_inputs(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission("Kernel deadline is stale"))
            ),
            "stale admission must fail closed, got {refused:?}"
        );
    }

    /// A caller-switched job identity fails closed at the binding check with
    /// the Kernel-admission code and zero transition calls.
    #[test]
    fn switched_job_identity_fails_closed_before_any_step() {
        let admission = admission_with_deadline(u64::MAX);
        let mut job = job_for(&admission);
        job.job_id = "caller-switched-job".to_owned();
        let refused = resolve_cycle_inputs(&admission, &job);
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err(KERNEL_ADMISSION_REQUIRED)
        );
    }

    /// A valid admission with matching identity reaches the material
    /// boundary: the refusal names the missing Governor-resolved material
    /// instead of synthesizing controller state (no self-issued authority).
    #[test]
    fn valid_admission_waits_for_governed_material() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_for(&admission);
        let refused = resolve_cycle_inputs(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "admitted controller inputs require Governor-resolved material"
                ))
            ),
            "valid input must wait for governed material, got {refused:?}"
        );
    }

    /// Builds a constructible-but-invalid owner state/policy pair. The values
    /// are deliberately unsealed (zero schema, empty digests), so the real
    /// owner transition must refuse them; the test proves it runs exactly
    /// once and the refusal maps fail-closed.
    fn invalid_owner_inputs() -> (DreamerCycleState, Vec<ObservedOutcome>, CyclePolicy) {
        let job = DreamJobAdmission {
            schema_version: 0,
            job_class: JobClass::Orientation,
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "test-harness".to_owned(),
                session: None,
            },
            operation_id: "op-slice-2".to_owned(),
            idempotency_key: "idem-slice-2".to_owned(),
            task_id: "task-slice-2".to_owned(),
            scope_id: "scope-slice-2".to_owned(),
            state_fence: fence(),
            privacy_profile: "local_only".to_owned(),
            contract_ref: "contract-slice-2".to_owned(),
            policy_ref: "policy-slice-2".to_owned(),
            budget: BudgetLimits {
                input_bytes: None,
                output_bytes: None,
                source_width: None,
                reference_width: None,
                model_calls: None,
                attempts: None,
                candidates: None,
                wall_ms: None,
                work_fan_out: None,
                report_bytes: None,
                max_stu: None,
            },
            deadline_ms: None,
            frozen_manifest_digest: "0".repeat(64),
        };
        let state = DreamerCycleState {
            schema_version: 0,
            cycle_id: eliot_contracts::ArtifactId::new("cycle-slice-2").expect("test cycle id"),
            job,
            bundle_digest: String::new(),
            policy_id: eliot_contracts::ArtifactId::new("policy-slice-2").expect("test policy id"),
            policy_revision: PolicyRevision::genesis(),
            policy_digest: String::new(),
            phase: CyclePhase::Validated,
            controller_revision: 0,
            predecessor_digest: None,
            pending: Vec::new(),
            proposed_requests: Vec::new(),
            outcomes: Vec::new(),
            frontier: Vec::new(),
            budget_usage: eliot_dreamer_contracts::BudgetUsage {
                input_bytes: 0,
                output_bytes: 0,
                source_width: 0,
                reference_width: 0,
                model_calls: 0,
                attempts: 0,
                candidates: 0,
                wall_ms: 0,
                work_fan_out: 0,
                report_bytes: 0,
                stu_used: 0,
            },
            cancellation_requested: false,
            canonical_digest: String::new(),
        };
        let policy = CyclePolicy {
            schema_version: 0,
            policy_id: eliot_contracts::ArtifactId::new("policy-slice-2").expect("test policy id"),
            policy_revision: PolicyRevision::genesis(),
            state_fence: fence(),
            max_pending: 0,
            max_outcomes: 0,
            max_requests: 0,
            max_transitions: 0,
            max_bytes: 0,
            deadline_ms: None,
            cancellation_requested: false,
            canonical_digest: String::new(),
            phase_rules: Vec::new(),
        };
        (state, Vec::new(), policy)
    }

    /// The real #806 transition runs exactly once per admitted admission: one
    /// counting wrapper around the production function, one refused input,
    /// one call, one typed fail-closed refusal with the request-rejected
    /// code.
    #[test]
    fn owner_transition_runs_exactly_once_per_admission() {
        let (state, observed, policy) = invalid_owner_inputs();
        let calls = AtomicU64::new(0);
        let refused = step_admitted_cycle_with(&state, &observed, &policy, None, |s, o, p, t| {
            calls.fetch_add(1, Ordering::SeqCst);
            step_dreamer_cycle_at(s, o, p, t)
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "owner transition must run exactly once per admission"
        );
        let Err(error) = refused else {
            panic!("invalid controller inputs must refuse");
        };
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert!(
            !matches!(error, DreamerError::KernelAdmissionRequired(_)),
            "controller refusal must not borrow the Kernel-admission code"
        );
    }

    /// Every owner refusal shape maps to the request-rejected code, never to
    /// the Kernel-admission code.
    #[test]
    fn every_owner_refusal_maps_fail_closed() {
        let cases = [
            CycleError::BindingMismatch {
                field: "cycle_policy.state_fence",
                reason: "policy fence differs from cycle job",
            },
            CycleError::IdentityConflict {
                identity: "receipt-1".to_owned(),
            },
            CycleError::PhaseViolation("pending phase is not adjacent"),
            CycleError::IncompleteOutcome("outcome.pending_request"),
            CycleError::Bound {
                field: "observed_external_outcomes",
                maximum: 8,
            },
            CycleError::BudgetBlocked,
            CycleError::Contract("contract".to_owned()),
            CycleError::Receipt("receipt".to_owned()),
            CycleError::Encoding("encoding".to_owned()),
        ];
        assert_eq!(cases.len(), 9);
        for error in cases {
            let refused = cycle_denied(&error);
            assert_eq!(refused.code(), "DREAMER_REQUEST_REJECTED");
        }
    }
}
