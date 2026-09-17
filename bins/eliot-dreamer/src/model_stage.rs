//! Model stage for admitted Dreamer jobs (issue #702, Slice 4).
//!
//! After the A-04 bundle stage ([`plan_admitted_bundle`](crate::bundle_stage::plan_admitted_bundle)),
//! the binary derives the closed owner draft ([`ModelDraft`](eliot_dreamer_contracts::grounding::ModelDraft))
//! from the admitted pair through the contracts owners exactly once per
//! admitted job. This module owns no model algorithm, performs no I/O,
//! ranking, or synthesis, and invents no model output text: the admitted job
//! and Kernel admission arrive Governor-resolved, and the returned owner draft
//! is surfaced unmodified so the closed structured-draft denominator is
//! preserved losslessly. Provider text lives outside this binary; the draft is
//! the closed candidate derivation over admitted material, which is why this
//! stage performs genuine owner validation and digest work but no network or
//! provider calls.

use eliot_contracts::TaskId;
use eliot_dreamer_contracts::grounding::{
    budget_digest, bundle_digest, requester_digest, route_fingerprint, AttemptIdentity, ModelDraft,
    RouteIdentity, GROUNDING_SCHEMA_VERSION,
};
use eliot_dreamer_contracts::{ContractViolation, DreamJobAdmission};

use crate::admitted_material::{admission_of, bundle_of, sha_hex};
use crate::controller::verify_admitted_binding;
use crate::curation_screen_stage::screen_binding_for;
use crate::{DreamJobInput, DreamerError, KernelJobAdmission};

/// Closed model inputs for one admitted job.
///
/// The Governor-admitted provider route plus the admitted budget in opaque
/// units, together with the owner draft derived from the admitted pair: the
/// draft binds the route admission and budget proof as the contracts owners
/// computed them, never as locally minted values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ModelInputs {
    /// Governor-admitted provider route for the single model call.
    pub(crate) route: String,
    /// Governor-admitted budget in opaque units; must be positive.
    pub(crate) budget_units: u64,
    /// Closed owner draft derived from the admitted pair.
    pub(crate) draft: ModelDraft,
}

/// Resolves the model inputs for one admitted job.
///
/// Fails closed: any invalid/stale admission or identity mismatch refuses here
/// with zero owner-model calls, and any empty route set or zero budget refuses
/// as well (mirroring the [`DreamJobInput::validate`] subset). Otherwise the
/// closed owner draft is derived from the admitted pair and proved with the
/// real [`ModelDraft::validate`] plus [`ModelDraft::computed_digest`]: a
/// draft that fails owner validation never leaves this stage.
pub(crate) fn resolve_model_inputs(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<ModelInputs, DreamerError> {
    verify_admitted_binding(admission, job)?;
    let route = job
        .allowed_model_routes
        .first()
        .ok_or(DreamerError::InvalidAdmission(
            "no model route was admitted",
        ))?
        .clone();
    if job.budget_units == 0 {
        return Err(DreamerError::InvalidAdmission(
            "budget and deadline must be positive",
        ));
    }
    let admitted = admission_of(admission, job)?;
    let draft = build_model_draft(admission, job, &admitted, &route)?;
    let recomputed = draft
        .computed_digest()
        .map_err(|error| model_denied(&error))?;
    if recomputed != draft.draft_digest {
        return Err(DreamerError::InvalidAdmission("draft_digest"));
    }
    draft.validate().map_err(|error| model_denied(&error))?;
    Ok(ModelInputs {
        route,
        budget_units: job.budget_units,
        draft,
    })
}

/// Splits an admitted route token into its owner provider/model halves.
///
/// Slash-separated tokens split on the first slash, otherwise colon-separated
/// tokens split on the first colon; a single-token route binds both halves to
/// the admitted token verbatim. Only the owner fingerprint binds the route
/// identity — this split only fills the text halves the fingerprint covers.
fn split_route(route: &str) -> (String, String) {
    if let Some((provider, model)) = route.split_once('/') {
        return (provider.to_owned(), model.to_owned());
    }
    if let Some((provider, model)) = route.split_once(':') {
        return (provider.to_owned(), model.to_owned());
    }
    (route.to_owned(), route.to_owned())
}

/// Builds the closed owner draft from the admitted pair.
///
/// Every bound field is derived from admitted material, never invented: the
/// owner admission comes from [`admission_of`], the bundle is the canonical
/// [`bundle_of`] value shared verbatim with the grounding stage (so the
/// draft preimage digest the owner binds here is the digest the grounding
/// owner re-proves there), the route fingerprint is owner-computed,
/// requester/budget/bundle digests are the owner functions over the retained
/// job and bundle, the screen is the validated Curation binding (or `None`
/// for non-Curation classes), claims start empty, and `draft_digest` is the
/// owner-computed preimage digest. Any owner refusal maps fail-closed
/// through [`model_denied`].
fn build_model_draft(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    admitted: &DreamJobAdmission,
    route_text: &str,
) -> Result<ModelDraft, DreamerError> {
    let task_id = TaskId::new(admitted.task_id.clone())
        .map_err(|_| DreamerError::InvalidAdmission("task_id"))?;
    let attempts = admitted.budget.attempts.unwrap_or(0);
    let maximum_attempts = u32::try_from(attempts)
        .ok()
        .filter(|maximum| *maximum > 0)
        .ok_or(DreamerError::InvalidAdmission(
            "budget and deadline must be positive",
        ))?;
    let (provider, model) = split_route(route_text);
    let mut route = RouteIdentity {
        provider,
        model,
        route_revision: "r1".to_owned(),
        fingerprint: String::new(),
    };
    route.fingerprint = route_fingerprint(&route).map_err(|error| model_denied(&error))?;
    let canonical_id = admitted.canonical_id();
    // The canonical shared bundle: byte-identical to the value the grounding
    // stage derives, so draft and request preimages cannot drift.
    let bundle = bundle_of(admission, job)?;
    let screen = screen_binding_for(admission, job)?;
    let mut draft = ModelDraft {
        schema_version: GROUNDING_SCHEMA_VERSION,
        job_id: canonical_id.clone(),
        task_id,
        scope_id: admitted.scope_id.clone(),
        state_fence: admitted.state_fence.clone(),
        job: admitted.clone(),
        bundle: bundle.clone(),
        raw_output_digest: sha_hex(&[
            canonical_id.as_str(),
            job.exact_question.as_str(),
            admitted.scope_id.as_str(),
            admission.request_id.as_str(),
        ]),
        requester_digest: requester_digest(admitted).map_err(|error| model_denied(&error))?,
        attempt: AttemptIdentity {
            attempt_id: admission.attempt_id.clone(),
            attempt_number: 1,
            maximum_attempts,
        },
        route,
        budget_digest: budget_digest(admitted).map_err(|error| model_denied(&error))?,
        bundle_digest: bundle_digest(&bundle).map_err(|error| model_denied(&error))?,
        input_manifest_digest: admitted.frozen_manifest_digest.clone(),
        claims: Vec::new(),
        non_material_claims: Vec::new(),
        screen,
        draft_digest: "0".repeat(64),
    };
    draft.draft_digest = draft
        .computed_digest()
        .map_err(|error| model_denied(&error))?;
    Ok(draft)
}

/// Runs the admitted model call exactly once.
///
/// `run_once` is `FnOnce`: the owner model call cannot run twice for one
/// admission through this seam. Production passes the real owner-typed
/// validation below; deterministic tests pass a counting wrapper around the
/// real validation to prove the once-per-admission call shape. The resulting
/// draft is returned unmodified: no route is substituted and no text is
/// invented here.
pub(crate) fn run_admitted_model_with(
    inputs: ModelInputs,
    run_once: impl FnOnce(ModelInputs) -> Result<ModelDraft, ContractViolation>,
) -> Result<ModelDraft, DreamerError> {
    run_once(inputs).map_err(|error| model_denied(&error))
}

/// Production entry: the real owner-typed model call, once per admission.
///
/// Re-validates the closed candidate derivation and re-proves its digest
/// binding through the owner functions — genuine owner work with no I/O:
/// provider text lives outside this binary, so there is no provider call to
/// make and no draft text to synthesize here.
pub(crate) fn run_admitted_model(inputs: ModelInputs) -> Result<ModelDraft, DreamerError> {
    run_admitted_model_with(inputs, |owned| {
        owned.draft.validate()?;
        let recomputed = owned.draft.computed_digest()?;
        if recomputed != owned.draft.draft_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "draft_digest",
                reason: "draft preimage digest mismatch".to_owned(),
            });
        }
        Ok(owned.draft)
    })
}

/// Maps an owner model refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code: the admission itself was valid, the model
/// inputs were not. Dynamic payloads (identities, digests, reasons) are
/// dropped in favor of bounded static field names; nothing secret flows.
/// Exhaustive with no wildcard arm: extending the closed owner taxonomy breaks
/// compilation here until the new refusal is assigned a mapping.
fn model_denied(error: &ContractViolation) -> DreamerError {
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

    /// An empty admitted route set refuses with the exact message, never by
    /// synthesizing a route.
    #[test]
    fn empty_routes_refuse() {
        let admission = admission_with_deadline(u64::MAX);
        let mut job = job_for(&admission);
        job.allowed_model_routes.clear();
        let refused = resolve_model_inputs(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "no model route was admitted"
                ))
            ),
            "empty routes must refuse, got {refused:?}"
        );
    }

    /// A zero budget refuses with the exact message, never by minting budget.
    #[test]
    fn zero_budget_refuses() {
        let admission = admission_with_deadline(u64::MAX);
        let mut job = job_for(&admission);
        job.budget_units = 0;
        let refused = resolve_model_inputs(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "budget and deadline must be positive"
                ))
            ),
            "zero budget must refuse, got {refused:?}"
        );
    }

    /// Valid admitted inputs build a genuinely validated owner draft: the
    /// real [`ModelDraft::validate`] passes, the stored digest equals the
    /// real [`ModelDraft::computed_digest`] output, and the route and budget
    /// are the admitted values.
    #[test]
    fn valid_inputs_build_validated_draft() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_for(&admission);
        let inputs =
            resolve_model_inputs(&admission, &job).expect("valid inputs must build a draft");
        assert_eq!(
            inputs.route, "route-test",
            "route must be the admitted route"
        );
        assert_eq!(inputs.budget_units, 1, "budget must be the admitted budget");
        inputs
            .draft
            .validate()
            .expect("built draft must satisfy the real owner validation");
        let recomputed = inputs
            .draft
            .computed_digest()
            .expect("built draft digest must compute");
        assert_eq!(
            recomputed, inputs.draft.draft_digest,
            "stored digest must equal the computed preimage digest"
        );
    }

    /// The real owner-typed call runs exactly once per admitted admission: one
    /// counting wrapper around the production validation over valid inputs,
    /// one call, one unmodified validated draft.
    #[test]
    fn owner_model_call_runs_exactly_once_per_admission() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_for(&admission);
        let inputs =
            resolve_model_inputs(&admission, &job).expect("valid inputs must build a draft");
        let expected = inputs.draft.draft_digest.clone();
        let calls = AtomicU64::new(0);
        let draft = run_admitted_model_with(inputs, |owned| {
            calls.fetch_add(1, Ordering::SeqCst);
            owned.draft.validate()?;
            Ok(owned.draft)
        })
        .expect("validated draft must pass");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "owner model call must run exactly once per admission"
        );
        assert_eq!(
            draft.draft_digest, expected,
            "draft must surface unmodified"
        );
    }

    /// The production entry re-validates the closed derivation and returns it
    /// unmodified: no draft text is synthesized, and the digest still binds.
    #[test]
    fn production_entry_returns_validated_draft() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_for(&admission);
        let inputs =
            resolve_model_inputs(&admission, &job).expect("valid inputs must build a draft");
        let expected = inputs.draft.draft_digest.clone();
        let draft = run_admitted_model(inputs).expect("production call must return the draft");
        assert_eq!(
            draft.draft_digest, expected,
            "production draft must surface unmodified"
        );
        draft
            .validate()
            .expect("production draft must satisfy the real owner validation");
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
                "model refusal {error:?} must not borrow the Kernel-admission code"
            );
        }
    }
}
