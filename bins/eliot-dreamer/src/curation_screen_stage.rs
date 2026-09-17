//! Pre-model curation screen stage for admitted Dreamer jobs (issue #702, Slice 3).
//!
//! After dispatch admits a job class, the A-20 pre-model screen filters the
//! Curation target set through the #588 owner
//! ([`ScreenBinding::validate`](eliot_dreamer_contracts::ScreenBinding::validate))
//! exactly once, leaving only eligible targets. This module owns no screening
//! algorithm, performs no I/O, fetch, ranking, or model work, and invents no
//! state: the pure owner function decides, this composition only calls it once
//! and maps its typed refusal fail-closed.
//!
//! Stage order is dispatch, then the controller step, then the screen here,
//! then [`plan_admitted_bundle`](crate::bundle_stage::plan_admitted_bundle):
//! non-Curation classes pass through with zero screen work, a refused class
//! returns at dispatch with zero screen work, and a failed screen never
//! reaches the bundle stage.

use eliot_dreamer_contracts::{ContractViolation, JobClass, ScreenBinding};

use crate::controller::verify_admitted_binding;
use crate::{DreamJobInput, DreamerError, KernelJobAdmission};

/// Minimal admitted screen inputs for one job.
///
/// Carries only the admitted job class today: the Governor-issued source
/// snapshot and screen profile arrive through a source-owner port in a later
/// slice, so there are no snapshot/profile handle fields to fill locally yet.
/// For Curation jobs (the only class the screen filters) resolution therefore
/// refuses rather than synthesizing governed material, because locally built
/// snapshots would be self-issued authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenInputs {
    /// Admitted job class carried for dispatch context.
    pub job_class: JobClass,
}

/// Admitted screen outcome: pass-through for classes the screen does not
/// filter, or the owner-screened eligible target set for Curation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ScreenDecision {
    /// Non-Curation classes need no pre-model screen: zero screen work, and
    /// the bundle stage sees the admitted job unchanged.
    PassThrough(ScreenInputs),
    /// Curation targets that survived the owner screen, carried unmodified:
    /// no target is added, rewritten, or re-selected here.
    #[allow(
        dead_code,
        reason = "constructed by screen_admitted_targets once the Governor-material slice supplies the screen binding"
    )]
    Screened {
        /// Inputs the eligible set was screened from.
        inputs: ScreenInputs,
        /// Eligible targets, exactly as the owner screen returned them.
        eligible_targets: Vec<String>,
    },
}

/// Resolves the A-20 screen decision for one admitted job.
///
/// Fails closed: any invalid/stale admission or identity mismatch refuses here
/// with zero owner-screen calls. Non-Curation classes pass through with no
/// screen work. Curation jobs wait for the Governor-issued source snapshot
/// and screen profile (later slice) and refuse until then rather than
/// synthesizing screen inputs, because locally selected materials would be
/// self-issued authority (A-20 runs pre-model on governed material; Dreamer
/// never selects it).
pub(crate) fn resolve_screen_inputs(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<ScreenDecision, DreamerError> {
    verify_admitted_binding(admission, job)?;
    if job.job_class == JobClass::Curation {
        return Err(DreamerError::InvalidAdmission(
            "admitted screen inputs require Governor-resolved snapshot and profile",
        ));
    }
    Ok(ScreenDecision::PassThrough(ScreenInputs {
        job_class: job.job_class,
    }))
}

/// Screens the admitted Curation targets exactly once.
///
/// `screen_once` is `FnOnce`: the owner screen cannot run twice for one
/// admission through this seam. Production passes a closure over the real
/// [`ScreenBinding::validate`](eliot_dreamer_contracts::ScreenBinding::validate);
/// deterministic tests pass a counting wrapper around the real function to
/// prove the once-per-admission call shape. The surviving targets are carried
/// unmodified into [`ScreenDecision::Screened`]: no target is dropped beyond
/// what the owner refused, thinned, or re-selected here.
#[allow(
    dead_code,
    reason = "wired by submit once the Governor-material slice supplies the screen binding"
)]
pub(crate) fn screen_admitted_targets_with(
    inputs: ScreenInputs,
    binding: ScreenBinding,
    screen_once: impl FnOnce(ScreenBinding) -> Result<Vec<String>, ContractViolation>,
) -> Result<ScreenDecision, DreamerError> {
    screen_once(binding)
        .map(|eligible_targets| ScreenDecision::Screened {
            inputs,
            eligible_targets,
        })
        .map_err(|error| screen_denied(&error))
}

/// Production entry: the real A-20 owner screen, once per admission.
#[allow(
    dead_code,
    reason = "wired by submit once the Governor-material slice supplies the screen binding"
)]
pub(crate) fn screen_admitted_targets(
    inputs: ScreenInputs,
    binding: ScreenBinding,
) -> Result<ScreenDecision, DreamerError> {
    screen_admitted_targets_with(inputs, binding, |candidate| {
        candidate.validate()?;
        Ok(candidate.screened_targets)
    })
}

/// Maps an owner screen refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code: the admission itself was valid, the screen
/// inputs were not. Dynamic payloads (handles, digests, reasons) are dropped
/// in favor of bounded static field names; nothing secret flows.
#[allow(
    dead_code,
    reason = "reached through screen_admitted_targets_with once the Governor-material slice wires it"
)]
fn screen_denied(error: &ContractViolation) -> DreamerError {
    match error {
        ContractViolation::UnknownVariant { field, .. }
        | ContractViolation::OutOfBounds { field, .. }
        | ContractViolation::BindingMismatch { field, .. }
        | ContractViolation::Malformed { field, .. }
        | ContractViolation::MissingField(field)
        | ContractViolation::ImplicitDefault(field)
        | ContractViolation::CrossStage(field) => DreamerError::InvalidAdmission(field),
        ContractViolation::Budget { dimension, .. } => DreamerError::InvalidAdmission(dimension),
        ContractViolation::KindPayload(_) => {
            DreamerError::InvalidAdmission("kind/payload mismatch")
        }
        ContractViolation::Registry(_) => {
            DreamerError::InvalidAdmission("handler registry conflict")
        }
        ContractViolation::ScreenIneligible(_) => {
            DreamerError::InvalidAdmission("screen ineligible")
        }
        ContractViolation::Preservation(_) => {
            DreamerError::InvalidAdmission("preservation failure")
        }
        ContractViolation::ForbiddenCarry(_) => {
            DreamerError::InvalidAdmission("forbidden candidate carry")
        }
    }
}

#[cfg(test)]
mod slice_3_screen_tests {
    use super::*;
    use std::num::NonZeroU64;
    use std::sync::atomic::{AtomicU64, Ordering};

    use eliot_contracts::{
        EpochId, EpochLineageId, ReceiptId, RequestId, ResourceGeneration, StateFence,
    };
    use eliot_dreamer_contracts::ScreenState;

    use crate::KERNEL_ADMISSION_REQUIRED;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(1).expect("nonzero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn admission_with_deadline(deadline_unix_ms: u64) -> KernelJobAdmission {
        KernelJobAdmission {
            job_id: "job-slice-3".to_owned(),
            attempt_id: "attempt-slice-3".to_owned(),
            scope_id: "scope-slice-3".to_owned(),
            request_id: "request-slice-3".to_owned(),
            idempotency_key: "job-slice-3:attempt-slice-3".to_owned(),
            cancellation_id: "cancel-slice-3".to_owned(),
            deadline_unix_ms,
            state_fence: fence(),
        }
    }

    fn job_of_class(admission: &KernelJobAdmission, job_class: JobClass) -> DreamJobInput {
        DreamJobInput {
            job_id: admission.job_id.clone(),
            job_class,
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

    /// Stale Kernel input fails closed at resolution with zero screen calls:
    /// resolution precedes the screen, so there is no screen to count — the
    /// refusal itself is the proof, and it carries the request-rejected code,
    /// never the Kernel-admission code for a mere stale deadline.
    #[test]
    fn stale_admission_fails_closed_before_any_screen() {
        let admission = admission_with_deadline(1);
        let job = job_of_class(&admission, JobClass::Orientation);
        let refused = resolve_screen_inputs(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission("Kernel deadline is stale"))
            ),
            "stale admission must fail closed, got {refused:?}"
        );
    }

    /// A caller-switched job identity fails closed at the binding check with
    /// the Kernel-admission code and zero screen calls.
    #[test]
    fn switched_job_identity_fails_closed_before_any_screen() {
        let admission = admission_with_deadline(u64::MAX);
        let mut job = job_of_class(&admission, JobClass::Orientation);
        job.job_id = "caller-switched-job".to_owned();
        let refused = resolve_screen_inputs(&admission, &job);
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err(KERNEL_ADMISSION_REQUIRED)
        );
    }

    /// Every non-Curation class passes through with zero screen work: the
    /// decision carries the admitted class unchanged and filters nothing.
    #[test]
    fn valid_non_curation_passes_through() {
        let admitted = [
            JobClass::Orientation,
            JobClass::Clarification,
            JobClass::ResearchSynthesis,
            JobClass::ArchitectureSelfQuery,
            JobClass::DevelopmentDiagnosis,
            JobClass::Maintenance,
            JobClass::OrchestrationPlanning,
            JobClass::ConfigurationAssistance,
        ];
        assert_eq!(admitted.len(), 8);
        let admission = admission_with_deadline(u64::MAX);
        for job_class in admitted {
            let job = job_of_class(&admission, job_class);
            let decision =
                resolve_screen_inputs(&admission, &job).expect("non-Curation must pass through");
            assert_eq!(
                decision,
                ScreenDecision::PassThrough(ScreenInputs { job_class }),
                "class {job_class:?} must pass through unfiltered"
            );
        }
    }

    /// A valid Curation admission with matching identity reaches the material
    /// boundary: the refusal names the missing Governor-resolved snapshot and
    /// profile instead of synthesizing screen inputs (no self-issued
    /// authority).
    #[test]
    fn valid_curation_waits_for_governed_material() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_of_class(&admission, JobClass::Curation);
        let refused = resolve_screen_inputs(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "admitted screen inputs require Governor-resolved snapshot and profile"
                ))
            ),
            "valid Curation input must wait for governed material, got {refused:?}"
        );
    }

    /// Builds an owner screen binding whose result digest is corrupted. The
    /// shape is otherwise valid (eligible state, well-formed item digest,
    /// distinct identities), so the real owner validation must refuse it; the
    /// test proves it runs exactly once and the refusal maps fail-closed.
    fn digest_corrupted_binding() -> ScreenBinding {
        ScreenBinding {
            request_id: RequestId::new("req-slice-3").expect("request id"),
            receipt_id: ReceiptId::new("rcpt-slice-3").expect("receipt id"),
            screened_targets: vec!["target-slice-3".to_owned()],
            source_snapshot: "snapshot-slice-3".to_owned(),
            source_revision: "revision-slice-3".to_owned(),
            profile: "profile-slice-3".to_owned(),
            task_id: "task-slice-3".to_owned(),
            scope_id: "scope-slice-3".to_owned(),
            state_fence: fence(),
            state: ScreenState::Eligible,
            result_digest: "corrupted-digest".to_owned(),
            item_digest: "b".repeat(64),
        }
    }

    /// Builds a fully valid owner screen binding: eligible state, well-formed
    /// digests, and distinct request/receipt identities.
    fn valid_binding() -> ScreenBinding {
        ScreenBinding {
            result_digest: "a".repeat(64),
            ..digest_corrupted_binding()
        }
    }

    fn curation_inputs() -> ScreenInputs {
        ScreenInputs {
            job_class: JobClass::Curation,
        }
    }

    /// The real A-20 owner screen runs exactly once per admitted admission:
    /// one counting wrapper around the production validation over a
    /// digest-corrupted binding, one call, one typed fail-closed refusal with
    /// the request-rejected code.
    #[test]
    fn owner_screen_runs_exactly_once_per_admission() {
        let binding = digest_corrupted_binding();
        let calls = AtomicU64::new(0);
        let refused = screen_admitted_targets_with(curation_inputs(), binding, |candidate| {
            calls.fetch_add(1, Ordering::SeqCst);
            candidate.validate()?;
            Ok(candidate.screened_targets)
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "owner screen must run exactly once per admission"
        );
        let Err(error) = refused else {
            panic!("digest-corrupted screen inputs must refuse");
        };
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert!(
            !matches!(error, DreamerError::KernelAdmissionRequired(_)),
            "screen refusal must not borrow the Kernel-admission code"
        );
    }

    /// A valid owner screen carries its eligible set through unmodified: the
    /// production entry returns the screened targets exactly as validated,
    /// bound to the admitted inputs.
    #[test]
    fn valid_screen_preserves_eligible_targets() {
        let binding = valid_binding();
        let expected = binding.screened_targets.clone();
        assert!(
            !expected.is_empty(),
            "fixture must carry at least one eligible target"
        );
        let decision =
            screen_admitted_targets(curation_inputs(), binding).expect("valid screen must pass");
        assert_eq!(
            decision,
            ScreenDecision::Screened {
                inputs: curation_inputs(),
                eligible_targets: expected,
            }
        );
    }

    /// Every owner screen refusal shape maps to the request-rejected code,
    /// never to the Kernel-admission code.
    #[test]
    fn every_owner_refusal_maps_fail_closed() {
        let cases = [
            ContractViolation::MissingField("screened_targets"),
            ContractViolation::ImplicitDefault("screen_state"),
            ContractViolation::CrossStage("screened"),
            ContractViolation::UnknownVariant {
                field: "screen_state",
                value: "tenth".to_owned(),
            },
            ContractViolation::OutOfBounds {
                field: "screened_targets",
                min: 1,
                max: 1024,
                got: 0,
            },
            ContractViolation::BindingMismatch {
                field: "screened_targets",
                reason: "duplicate screened target".to_owned(),
            },
            ContractViolation::Malformed {
                field: "result_digest",
                reason: "expected 64 lowercase hex chars".to_owned(),
            },
            ContractViolation::Budget {
                dimension: "screened_targets",
                reason: "over".to_owned(),
            },
            ContractViolation::KindPayload("kind".to_owned()),
            ContractViolation::Registry("registry".to_owned()),
            ContractViolation::ScreenIneligible("screen binding is not eligible".to_owned()),
            ContractViolation::Preservation("preservation".to_owned()),
            ContractViolation::ForbiddenCarry("carry".to_owned()),
        ];
        assert_eq!(cases.len(), 13);
        for error in cases {
            let refused = screen_denied(&error);
            assert_eq!(refused.code(), "DREAMER_REQUEST_REJECTED");
            assert!(
                !matches!(refused, DreamerError::KernelAdmissionRequired(_)),
                "screen refusal {error:?} must not borrow the Kernel-admission code"
            );
        }
    }
}
