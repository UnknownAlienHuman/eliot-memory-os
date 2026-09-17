//! Model stage for admitted Dreamer jobs (issue #702, Slice 4).
//!
//! After the A-04 bundle stage ([`plan_admitted_bundle`](crate::bundle_stage::plan_admitted_bundle)),
//! the binary issues the bounded model call through the admitted route via the
//! contracts/rival-model owners exactly once per admitted job. This module owns
//! no model algorithm, performs no I/O, ranking, or synthesis, and invents no
//! model output text: the [`ModelInputs`] arrive Governor-resolved (later
//! material), and the returned owner [`StructuredDraft`] is surfaced
//! unmodified so the closed structured-draft denominator is preserved
//! losslessly (T12-07 / #702: the route admission and budget proof arrive with
//! governed material; Dreamer never mints them).

use eliot_dreamer_contracts::ContractViolation;

use crate::controller::verify_admitted_binding;
use crate::{DreamJobInput, DreamerError, KernelJobAdmission};

/// Closed model inputs for one admitted job.
///
/// Minimal: the Governor-admitted provider route plus the admitted budget in
/// opaque units. The route admission proof and the budget proof themselves are
/// Governor-issued material resolved in a later slice; this carrier only names
/// them, never mints them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ModelInputs {
    /// Governor-admitted provider route for the single model call.
    pub(crate) route: String,
    /// Governor-admitted budget in opaque units; must be positive.
    pub(crate) budget_units: u64,
}

/// Minimal closed structured draft surfaced from the owner model call.
///
/// Closed carrier only: the admitted route that produced the draft plus the
/// owner-computed draft digest binding it. No model output text lives here —
/// hypotheses, claims, and evidence stay in the owner draft types, never in
/// this seam.
#[allow(
    dead_code,
    reason = "constructed by run_admitted_model once the Governor-material slice supplies the route admission"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StructuredDraft {
    /// Admitted route that produced the draft.
    pub(crate) route: String,
    /// Owner-computed digest binding the structured draft.
    pub(crate) digest: String,
}

/// Owner refusal type for the admitted model call.
///
/// The structured-draft owner surface is [`ContractViolation`]
/// (`eliot-dreamer-contracts` draft validation plus the rival-model budget
/// bound, both already in this binary's dependency tree); no new dependency is
/// introduced for this seam.
#[allow(
    dead_code,
    reason = "consumed by run_admitted_model_with once the Governor-material slice wires it"
)]
pub(crate) type OwnerError = ContractViolation;

/// Resolves the model inputs for one admitted job.
///
/// Fails closed: any invalid/stale admission or identity mismatch refuses here
/// with zero owner-model calls, and any empty route set or zero budget refuses
/// as well (mirroring the [`DreamJobInput::validate`] subset). A fully valid
/// input still refuses rather than synthesizing a draft locally, because the
/// route admission and budget proof are Governor-issued: a locally built draft
/// would be self-issued authority.
pub(crate) fn resolve_model_inputs(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<ModelInputs, DreamerError> {
    verify_admitted_binding(admission, job)?;
    if job.allowed_model_routes.is_empty() {
        return Err(DreamerError::InvalidAdmission(
            "no model route was admitted",
        ));
    }
    if job.budget_units == 0 {
        return Err(DreamerError::InvalidAdmission(
            "budget and deadline must be positive",
        ));
    }
    Err(DreamerError::InvalidAdmission(
        "admitted model inputs require Governor-resolved route and budget",
    ))
}

/// Runs the admitted model call exactly once.
///
/// `run_once` is `FnOnce`: the owner model call cannot run twice for one
/// admission through this seam. Production passes [`governor_model_call`], the
/// real owner-typed call below; deterministic tests pass a counting wrapper
/// around the real mapping to prove the once-per-admission call shape. The
/// resulting draft is returned unmodified: no route is substituted and no text
/// is invented here.
#[allow(
    dead_code,
    reason = "wired by submit once the Governor-material slice supplies the route admission"
)]
pub(crate) fn run_admitted_model_with(
    inputs: ModelInputs,
    run_once: impl FnOnce(ModelInputs) -> Result<StructuredDraft, OwnerError>,
) -> Result<StructuredDraft, DreamerError> {
    run_once(inputs).map_err(|error| model_denied(&error))
}

/// Production entry: the real owner-typed model call, once per admission.
///
/// Binds the owner [`OwnerError`] refusal shape through [`governor_model_call`]:
/// until Governor-resolved route admission and budget proof material lands,
/// the call refuses with the owner `CrossStage` variant (model text lives in a
/// later stage, never synthesized here) rather than minting draft text.
#[allow(
    dead_code,
    reason = "wired by submit once the Governor-material slice supplies the route admission"
)]
pub(crate) fn run_admitted_model(inputs: ModelInputs) -> Result<StructuredDraft, DreamerError> {
    run_admitted_model_with(inputs, governor_model_call)
}

/// Real owner-typed model-call binding for the production path.
///
/// Names the missing Governor-resolved stage through the owner error type
/// instead of synthesizing model output text: the draft is produced from
/// governed material in a later slice, never invented in this binary.
#[allow(
    dead_code,
    reason = "reached through run_admitted_model once the Governor-material slice wires it"
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "the FnOnce seam takes ModelInputs by value so the owner call cannot run twice for one admission"
)]
fn governor_model_call(inputs: ModelInputs) -> Result<StructuredDraft, OwnerError> {
    let _ = inputs;
    Err(ContractViolation::CrossStage("model.draft"))
}

/// Maps an owner model refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code: the admission itself was valid, the model
/// inputs were not. Dynamic payloads (identities, digests, reasons) are
/// dropped in favor of bounded static field names; nothing secret flows.
/// Exhaustive with no wildcard arm: extending the closed owner taxonomy breaks
/// compilation here until the new refusal is assigned a mapping.
#[allow(
    dead_code,
    reason = "reached through run_admitted_model_with once the Governor-material slice wires it"
)]
fn model_denied(error: &OwnerError) -> DreamerError {
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
mod slice_4_model_tests {
    use super::*;
    use std::num::NonZeroU64;
    use std::sync::atomic::{AtomicU64, Ordering};

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_dreamer_contracts::JobClass;

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
            job_id: "job-slice-4".to_owned(),
            attempt_id: "attempt-slice-4".to_owned(),
            scope_id: "scope-slice-4".to_owned(),
            request_id: "request-slice-4".to_owned(),
            idempotency_key: "job-slice-4:attempt-slice-4".to_owned(),
            cancellation_id: "cancel-slice-4".to_owned(),
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

    fn model_inputs() -> ModelInputs {
        ModelInputs {
            route: "route-test".to_owned(),
            budget_units: 1,
        }
    }

    /// Stale Kernel input fails closed at resolution with zero model calls:
    /// resolution precedes the call, so there is no call to count — the
    /// refusal itself is the proof, and it carries the request-rejected code,
    /// never the Kernel-admission code for a mere stale deadline.
    #[test]
    fn stale_admission_fails_closed_before_any_model_call() {
        let admission = admission_with_deadline(1);
        let job = job_for(&admission);
        let refused = resolve_model_inputs(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission("Kernel deadline is stale"))
            ),
            "stale admission must fail closed, got {refused:?}"
        );
    }

    /// A caller-switched job identity fails closed at the binding check with
    /// the Kernel-admission code and zero model calls.
    #[test]
    fn switched_job_identity_fails_closed_before_any_model_call() {
        let admission = admission_with_deadline(u64::MAX);
        let mut job = job_for(&admission);
        job.job_id = "caller-switched-job".to_owned();
        let refused = resolve_model_inputs(&admission, &job);
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err(KERNEL_ADMISSION_REQUIRED)
        );
    }

    /// A valid admission with matching identity reaches the material boundary:
    /// the refusal names the missing Governor-resolved route and budget
    /// instead of synthesizing a draft (no self-issued authority).
    #[test]
    fn valid_admission_waits_for_governed_material() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_for(&admission);
        let refused = resolve_model_inputs(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "admitted model inputs require Governor-resolved route and budget"
                ))
            ),
            "valid input must wait for governed material, got {refused:?}"
        );
    }

    /// The real owner-typed call runs exactly once per admitted admission: one
    /// counting wrapper around the production binding over refused inputs, one
    /// call, one typed fail-closed refusal with the request-rejected code.
    #[test]
    fn owner_model_call_runs_exactly_once_per_admission() {
        let inputs = model_inputs();
        let calls = AtomicU64::new(0);
        let refused = run_admitted_model_with(inputs, |owned| {
            calls.fetch_add(1, Ordering::SeqCst);
            governor_model_call(owned)
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "owner model call must run exactly once per admission"
        );
        let Err(error) = refused else {
            panic!("model inputs without governed material must refuse");
        };
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert!(
            !matches!(error, DreamerError::KernelAdmissionRequired(_)),
            "model refusal must not borrow the Kernel-admission code"
        );
    }

    /// The production entry refuses fail-closed without governed material: no
    /// draft text is synthesized, and the refusal carries the request-rejected
    /// code.
    #[test]
    fn production_entry_refuses_without_governed_material() {
        let Err(error) = run_admitted_model(model_inputs()) else {
            panic!("production model call without governed material must refuse");
        };
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert!(
            !matches!(error, DreamerError::KernelAdmissionRequired(_)),
            "model refusal must not borrow the Kernel-admission code"
        );
    }

    /// Every owner refusal shape maps to the request-rejected code, never to
    /// the Kernel-admission code.
    #[test]
    fn every_owner_refusal_maps_fail_closed() {
        let cases = [
            ContractViolation::MissingField("model.draft"),
            ContractViolation::ImplicitDefault("schema_version"),
            ContractViolation::CrossStage("model.draft"),
            ContractViolation::UnknownVariant {
                field: "terminal_disposition",
                value: "tenth".to_owned(),
            },
            ContractViolation::OutOfBounds {
                field: "source_handles",
                min: 1,
                max: 1024,
                got: 0,
            },
            ContractViolation::BindingMismatch {
                field: "model.draft_digest",
                reason: "digest differs".to_owned(),
            },
            ContractViolation::Malformed {
                field: "model.statement",
                reason: "blank".to_owned(),
            },
            ContractViolation::Budget {
                dimension: "model_calls",
                reason: "over".to_owned(),
            },
            ContractViolation::KindPayload("kind".to_owned()),
            ContractViolation::Registry("registry".to_owned()),
            ContractViolation::ScreenIneligible("screen".to_owned()),
            ContractViolation::Preservation("preservation".to_owned()),
            ContractViolation::ForbiddenCarry("carry".to_owned()),
        ];
        assert_eq!(cases.len(), 13);
        for error in cases {
            let refused = model_denied(&error);
            assert_eq!(refused.code(), "DREAMER_REQUEST_REJECTED");
            assert!(
                !matches!(refused, DreamerError::KernelAdmissionRequired(_)),
                "model refusal must not borrow the Kernel-admission code"
            );
        }
    }
}
