//! A-14b grounding stage for admitted Dreamer jobs (issue #702, Slice 5).
//!
//! After the A-04 bundle stage, the binary grounds the structured draft
//! against the frozen evidence universe through the #602 owner
//! ([`ground_draft_with_controls`](eliot_dreamer_claim_grounding::ground_draft_with_controls))
//! exactly once per admitted job. This module performs no local retrieval,
//! ranking, or truth promotion: the structured draft arrives from the model
//! stage, the frozen manifest and bundle are derived from the admitted pair
//! through [`admitted_material`], and the returned owner [`GroundedDreamDraft`](eliot_dreamer_contracts::grounding::GroundedDreamDraft)
//! is surfaced unmodified so the frozen claim denominator is preserved
//! losslessly (the denominator arrives with governed material; Dreamer never
//! selects it, and never synthesizes a frozen universe locally).

use eliot_dreamer_claim_grounding::{GroundingRequest, ground_draft_with_controls};
use eliot_dreamer_contracts::ContractViolation;
use eliot_dreamer_contracts::grounding::{GroundedDreamDraft, ModelDraft};

use crate::admitted_material::{admission_of, bundle_of, grounding_policy, manifest_of};
use crate::controller::verify_admitted_binding;
use crate::{DreamJobInput, DreamerError, KernelJobAdmission};

/// Resolves the A-14b inputs for one admitted job.
///
/// Fails closed: any invalid/stale admission or identity mismatch refuses here
/// with zero owner-grounding calls, as does any derived binding the owner
/// rejects. The structured draft arrives from the model stage and is carried
/// verbatim; the job, bundle, manifest, and policy are derived from the
/// admitted pair through [`admitted_material`], and the manifest digest is
/// asserted to equal the bundle's digest before the request is built, so a
/// drifted frozen universe can never reach the owner.
pub(crate) fn resolve_grounding_inputs(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    draft: ModelDraft,
) -> Result<GroundingRequest, DreamerError> {
    verify_admitted_binding(admission, job)?;
    let admitted = admission_of(admission, job)?;
    let bundle = bundle_of(admission, job)?;
    let manifest = manifest_of(&bundle)?;
    if manifest.digest != bundle.manifest_digest {
        return Err(DreamerError::InvalidAdmission("manifest binding drift"));
    }
    let policy = grounding_policy();
    Ok(GroundingRequest::new(
        admitted, bundle, manifest, draft, policy,
    ))
}

/// Grounds the admitted structured draft exactly once.
///
/// `ground_once` is `FnOnce`: the owner grounding cannot run twice for one
/// admission through this seam. Production passes
/// [`ground_draft_with_controls`](eliot_dreamer_claim_grounding::ground_draft_with_controls);
/// deterministic tests pass a counting wrapper around the real function to
/// prove the once-per-admission call shape. The resulting grounded draft is
/// returned unmodified: no claim is dropped, re-graded, or re-selected here.
pub(crate) fn ground_admitted_draft_with(
    request: GroundingRequest,
    ground_once: impl FnOnce(GroundingRequest) -> Result<GroundedDreamDraft, ContractViolation>,
) -> Result<GroundedDreamDraft, DreamerError> {
    ground_once(request).map_err(|error| grounding_denied(&error))
}

/// Production entry: the real A-14b grounding, once per admission.
///
/// Unwired until the pipeline threads the model draft through; `submit`
/// cannot supply a [`ModelDraft`] yet, so the entry is exercised by the slice
/// tests below. Remove the allowance once the pipeline calls this entry.
#[allow(
    dead_code,
    reason = "wired once the pipeline threads the model draft; tests cover it until then"
)]
pub(crate) fn ground_admitted_draft(
    request: GroundingRequest,
) -> Result<GroundedDreamDraft, DreamerError> {
    ground_admitted_draft_with(request, ground_draft_with_controls)
}

/// Maps an owner grounding refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code: the admission itself was valid, the
/// grounding inputs were not. Dynamic payloads (digests, reasons, values) are
/// dropped in favor of bounded static field names; nothing secret flows.
fn grounding_denied(error: &ContractViolation) -> DreamerError {
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
mod slice_5_grounding_tests {
    use crate::admitted_material as governed;
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::NonZeroU64;
    use std::sync::atomic::{AtomicU64, Ordering};

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId};
    use eliot_dreamer_claim_grounding::ground_draft_with_controls;
    use eliot_dreamer_contracts::grounding::{
        AllowedReferenceManifest, AttemptIdentity, GROUNDING_SCHEMA_VERSION, GroundingPolicy,
        ModelDraft, RouteIdentity, budget_digest, bundle_digest, requester_digest,
        route_fingerprint,
    };
    use eliot_dreamer_contracts::{
        BudgetLimits, BundleCompleteness, DreamInputBundle, DreamJobAdmission, JobClass, Requester,
        RequesterOrigin,
    };

    use crate::KERNEL_ADMISSION_REQUIRED;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let Ok(lineage) = EpochLineageId::new(TEST_LINEAGE) else {
            panic!("test lineage must parse");
        };
        let Some(sequence) = NonZeroU64::new(1) else {
            panic!("test sequence must be nonzero");
        };
        let Ok(epoch) = EpochId::new(lineage, sequence) else {
            panic!("test epoch must construct");
        };
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn admission_with_deadline(deadline_unix_ms: u64) -> KernelJobAdmission {
        KernelJobAdmission {
            job_id: "job-slice-5".to_owned(),
            attempt_id: "attempt-slice-5".to_owned(),
            scope_id: "scope-slice-5".to_owned(),
            request_id: "request-slice-5".to_owned(),
            idempotency_key: "job-slice-5:attempt-slice-5".to_owned(),
            cancellation_id: "cancel-slice-5".to_owned(),
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

    /// A draft that is never validated: resolution fails at the binding check
    /// before the draft is touched, so stale/switched inputs need only a
    /// well-formed value, never governed material.
    fn dummy_draft() -> ModelDraft {
        let Ok(task_id) = TaskId::new("task-slice-5") else {
            panic!("test task identity must construct");
        };
        ModelDraft {
            schema_version: GROUNDING_SCHEMA_VERSION,
            job_id: "job-slice-5".to_owned(),
            task_id,
            scope_id: "scope-slice-5".to_owned(),
            state_fence: fence(),
            job: grounding_job(),
            bundle: grounding_bundle(),
            raw_output_digest: "0".repeat(64),
            requester_digest: "0".repeat(64),
            attempt: AttemptIdentity {
                attempt_id: "attempt-slice-5".to_owned(),
                attempt_number: 1,
                maximum_attempts: 2,
            },
            route: RouteIdentity {
                provider: "provider-slice-5".to_owned(),
                model: "model-slice-5".to_owned(),
                route_revision: "r1".to_owned(),
                fingerprint: "0".repeat(64),
            },
            budget_digest: "0".repeat(64),
            bundle_digest: "0".repeat(64),
            input_manifest_digest: "0".repeat(64),
            claims: Vec::new(),
            non_material_claims: Vec::new(),
            screen: None,
            draft_digest: "0".repeat(64),
        }
    }

    /// Builds the governed inline draft for a valid admission: the admitted
    /// job and bundle verbatim, empty claims, the admitted route with its
    /// owner fingerprint, owner-computed digests, and the owner preimage
    /// digest. Mirrors the model stage derivation so the test proves what the
    /// pipeline will carry, not a second implementation.
    fn governed_draft(admission: &KernelJobAdmission, job: &DreamJobInput) -> ModelDraft {
        let Ok(admitted) = governed::admission_of(admission, job) else {
            panic!("test admission must derive");
        };
        let Ok(bundle) = governed::bundle_of(admission, job) else {
            panic!("test bundle must derive");
        };
        let Ok(task_id) = TaskId::new(admitted.task_id.clone()) else {
            panic!("test task identity must construct");
        };
        let Some(route_text) = job.allowed_model_routes.first() else {
            panic!("test route must be admitted");
        };
        let Some(attempt_cap) = admitted.budget.attempts else {
            panic!("test attempts budget must be explicit");
        };
        let Ok(maximum_attempts) = u32::try_from(attempt_cap) else {
            panic!("test attempts budget must fit the owner counter");
        };
        let mut route = RouteIdentity {
            provider: route_text.clone(),
            model: route_text.clone(),
            route_revision: "r1".to_owned(),
            fingerprint: String::new(),
        };
        let Ok(fingerprint) = route_fingerprint(&route) else {
            panic!("test route fingerprint must compute");
        };
        route.fingerprint = fingerprint;
        let canonical_id = admitted.canonical_id();
        let Ok(requester) = requester_digest(&admitted) else {
            panic!("test requester digest must compute");
        };
        let Ok(budget) = budget_digest(&admitted) else {
            panic!("test budget digest must compute");
        };
        let Ok(bundle_sum) = bundle_digest(&bundle) else {
            panic!("test bundle digest must compute");
        };
        let mut draft = ModelDraft {
            schema_version: GROUNDING_SCHEMA_VERSION,
            job_id: canonical_id.clone(),
            task_id,
            scope_id: admitted.scope_id.clone(),
            state_fence: admitted.state_fence.clone(),
            job: admitted.clone(),
            bundle: bundle.clone(),
            raw_output_digest: governed::sha_hex(&[
                canonical_id.as_str(),
                job.exact_question.as_str(),
                admitted.scope_id.as_str(),
                admission.request_id.as_str(),
            ]),
            requester_digest: requester,
            attempt: AttemptIdentity {
                attempt_id: admission.attempt_id.clone(),
                attempt_number: 1,
                maximum_attempts,
            },
            route,
            budget_digest: budget,
            bundle_digest: bundle_sum,
            input_manifest_digest: admitted.frozen_manifest_digest.clone(),
            claims: Vec::new(),
            non_material_claims: Vec::new(),
            screen: None,
            draft_digest: "0".repeat(64),
        };
        let Ok(computed) = draft.computed_digest() else {
            panic!("test draft digest must compute");
        };
        draft.draft_digest = computed;
        draft
    }

    /// Stale Kernel input fails closed at resolution with zero grounding
    /// calls: resolution precedes grounding, so there is no grounding to
    /// count — the refusal itself is the proof, and it carries the
    /// request-rejected code for a stale deadline, never synthesized inputs.
    #[test]
    fn stale_admission_fails_closed_before_any_grounding() {
        let admission = admission_with_deadline(1);
        let job = job_for(&admission);
        let refused = resolve_grounding_inputs(&admission, &job, dummy_draft());
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission("Kernel deadline is stale"))
            ),
            "stale admission must fail closed, got {refused:?}"
        );
    }

    /// A caller-switched job identity fails closed at the binding check with
    /// the Kernel-admission code and zero grounding calls.
    #[test]
    fn switched_job_identity_fails_closed_before_any_grounding() {
        let admission = admission_with_deadline(u64::MAX);
        let mut job = job_for(&admission);
        job.job_id = "caller-switched-job".to_owned();
        let refused = resolve_grounding_inputs(&admission, &job, dummy_draft());
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err(KERNEL_ADMISSION_REQUIRED)
        );
    }

    /// A valid admission with matching identity and one evidence handle
    /// grounds successfully through the real owner: resolution carries the
    /// governed material, the owner proves it, and the grounded draft binds
    /// the admitted canonical identity with the frozen manifest digest.
    #[test]
    fn valid_admission_grounds_successfully() {
        let admission = admission_with_deadline(u64::MAX);
        let mut job = job_for(&admission);
        job.evidence_handles.push("evidence-slice-5".to_owned());
        let draft = governed_draft(&admission, &job);
        let Ok(request) = resolve_grounding_inputs(&admission, &job, draft) else {
            panic!("valid admission must resolve governed material");
        };
        assert_eq!(
            request.bundle.materials.len(),
            1,
            "the admitted evidence handle must be carried"
        );
        assert_eq!(
            request.bundle.materials[0].handle, "evidence-slice-5",
            "the carried material must keep the admitted handle verbatim"
        );
        let Ok(grounded) = ground_admitted_draft(request) else {
            panic!("governed material must ground through the real owner");
        };
        let Ok(admitted) = governed::admission_of(&admission, &job) else {
            panic!("test admission must derive");
        };
        assert_eq!(
            grounded.job_id,
            admitted.canonical_id(),
            "the grounded draft must bind the admitted canonical identity"
        );
        assert_eq!(
            grounded.manifest_digest, admitted.frozen_manifest_digest,
            "the grounded draft must bind the frozen manifest digest"
        );
    }

    /// The derived bundle and the rebuilt frozen manifest agree: the manifest
    /// digest equals the bundle's manifest digest, and both pass the real
    /// owner validation, so the frozen universe cannot drift between stages.
    #[test]
    fn manifest_bundle_digest_agreement() {
        let admission = admission_with_deadline(u64::MAX);
        let mut job = job_for(&admission);
        job.evidence_handles.push("evidence-slice-5".to_owned());
        let Ok(bundle) = governed::bundle_of(&admission, &job) else {
            panic!("test bundle must derive");
        };
        let Ok(()) = bundle.validate() else {
            panic!("derived bundle must satisfy the real owner validation");
        };
        let Ok(manifest) = governed::manifest_of(&bundle) else {
            panic!("test manifest must derive");
        };
        let Ok(()) = manifest.validate() else {
            panic!("derived manifest must satisfy the real owner validation");
        };
        assert_eq!(
            manifest.digest, bundle.manifest_digest,
            "manifest digest must equal the bundle manifest digest"
        );
    }

    fn grounding_job() -> DreamJobAdmission {
        DreamJobAdmission {
            schema_version: 1,
            job_class: JobClass::Orientation,
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "test-harness".to_owned(),
                session: None,
            },
            operation_id: "op-slice-5".to_owned(),
            idempotency_key: "idem-slice-5".to_owned(),
            task_id: "task-slice-5".to_owned(),
            scope_id: "scope-slice-5".to_owned(),
            state_fence: fence(),
            privacy_profile: "local_only".to_owned(),
            contract_ref: "contract-slice-5".to_owned(),
            policy_ref: "policy-slice-5".to_owned(),
            budget: BudgetLimits {
                input_bytes: Some(1_048_576),
                output_bytes: Some(524_288),
                source_width: Some(32),
                reference_width: Some(32),
                model_calls: Some(4),
                attempts: Some(2),
                candidates: Some(2),
                wall_ms: Some(60_000),
                work_fan_out: Some(4),
                report_bytes: Some(1_048_576),
                max_stu: Some(100),
            },
            deadline_ms: None,
            // Digest-corrupted: not lowercase hex, so the real owner refuses
            // at `job.validate` before any claim work runs.
            frozen_manifest_digest: "digest-corrupted".to_owned(),
        }
    }

    fn grounding_bundle() -> DreamInputBundle {
        DreamInputBundle {
            schema_version: 1,
            job_id: "job-slice-5".to_owned(),
            scope_id: "scope-slice-5".to_owned(),
            task_id: "task-slice-5".to_owned(),
            state_fence: fence(),
            manifest_digest: "manifest-slice-5".to_owned(),
            materials: Vec::new(),
            omissions: Vec::new(),
            completeness: BundleCompleteness::Unknown,
            authoritative_denominator: None,
        }
    }

    fn grounding_manifest() -> AllowedReferenceManifest {
        let Ok(task_id) = TaskId::new("task-slice-5") else {
            panic!("test task identity must construct");
        };
        AllowedReferenceManifest {
            schema_version: GROUNDING_SCHEMA_VERSION,
            manifest_id: "manifest-slice-5".to_owned(),
            run_id: "run-slice-5".to_owned(),
            task_id,
            scope_id: "scope-slice-5".to_owned(),
            state_fence: fence(),
            source_snapshot: "snapshot-slice-5".to_owned(),
            source_revision: "revision-slice-5".to_owned(),
            references: BTreeMap::new(),
            coverage_denominators: BTreeMap::new(),
            coverage_receipts: BTreeMap::new(),
            dependence_groups: BTreeSet::new(),
            digest: String::new(),
        }
    }

    fn grounding_policy() -> GroundingPolicy {
        GroundingPolicy {
            schema_version: GROUNDING_SCHEMA_VERSION,
            policy_id: "policy-slice-5".to_owned(),
            revision: "r1".to_owned(),
            permitted_kinds: BTreeSet::new(),
            permitted_nonmaterial_classes: BTreeSet::new(),
            max_claims: 1,
            max_subclaims_per_claim: 1,
            max_support_handles_per_claim: 1,
            max_output_bytes: 1024,
            digest: String::new(),
        }
    }

    /// Digest-corrupted owner input: the remaining components are only
    /// carried, never validated, because the real owner refuses the corrupted
    /// frozen manifest digest at `job.validate` before any claim work.
    fn corrupted_request() -> GroundingRequest {
        let job = grounding_job();
        let bundle = grounding_bundle();
        let manifest = grounding_manifest();
        let policy = grounding_policy();
        let Ok(task_id) = TaskId::new("task-slice-5") else {
            panic!("test task identity must construct");
        };
        let draft = ModelDraft {
            schema_version: GROUNDING_SCHEMA_VERSION,
            job_id: "job-slice-5".to_owned(),
            task_id,
            scope_id: "scope-slice-5".to_owned(),
            state_fence: fence(),
            job: job.clone(),
            bundle: bundle.clone(),
            raw_output_digest: String::new(),
            requester_digest: String::new(),
            attempt: AttemptIdentity {
                attempt_id: "attempt-slice-5".to_owned(),
                attempt_number: 1,
                maximum_attempts: 2,
            },
            route: RouteIdentity {
                provider: "provider-slice-5".to_owned(),
                model: "model-slice-5".to_owned(),
                route_revision: "r1".to_owned(),
                fingerprint: "fingerprint-slice-5".to_owned(),
            },
            budget_digest: String::new(),
            bundle_digest: String::new(),
            input_manifest_digest: String::new(),
            claims: Vec::new(),
            non_material_claims: Vec::new(),
            screen: None,
            draft_digest: String::new(),
        };
        GroundingRequest::new(job, bundle, manifest, draft, policy)
    }

    /// The real A-14b grounding runs exactly once per admitted admission: one
    /// counting wrapper around the production function over a digest-corrupted
    /// request, one call, one typed fail-closed refusal with the
    /// request-rejected code.
    #[test]
    fn owner_grounding_runs_exactly_once_per_admission() {
        let request = corrupted_request();
        let calls = AtomicU64::new(0);
        let refused = ground_admitted_draft_with(request, |request| {
            calls.fetch_add(1, Ordering::SeqCst);
            ground_draft_with_controls(request)
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "owner grounding must run exactly once per admission"
        );
        let Err(error) = refused else {
            panic!("digest-corrupted grounding inputs must refuse");
        };
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert!(
            !matches!(error, DreamerError::KernelAdmissionRequired(_)),
            "grounding refusal must not borrow the Kernel-admission code"
        );
    }

    /// Every owner grounding refusal shape maps to the request-rejected code,
    /// never to the Kernel-admission code.
    #[test]
    fn production_entry_refuses_through_the_real_owner() {
        let refused = ground_admitted_draft(corrupted_request());
        let code = match &refused {
            Err(error) => error.code(),
            Ok(_) => "UNEXPECTED_OK",
        };
        assert_eq!(code, "DREAMER_REQUEST_REJECTED");
        assert!(
            !matches!(refused, Err(DreamerError::KernelAdmissionRequired(_))),
            "production refusal must not borrow the Kernel-admission code"
        );
    }

    /// Every owner grounding refusal shape maps to the request-rejected code,
    /// never to the Kernel-admission code.
    #[test]
    fn every_owner_refusal_maps_fail_closed() {
        let cases = [
            ContractViolation::MissingField("request.frozen_manifest_digest"),
            ContractViolation::ImplicitDefault("schema_version"),
            ContractViolation::CrossStage("raw"),
            ContractViolation::UnknownVariant {
                field: "job_class",
                value: "tenth".to_owned(),
            },
            ContractViolation::OutOfBounds {
                field: "claim.subclaim_ids",
                min: 0,
                max: 16_384,
                got: 16_385,
            },
            ContractViolation::BindingMismatch {
                field: "grounding_input",
                reason: "manifest differs".to_owned(),
            },
            ContractViolation::Malformed {
                field: "cancellation.reason",
                reason: "control characters".to_owned(),
            },
            ContractViolation::Budget {
                dimension: "grounding_output_bytes",
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
            let refused = grounding_denied(&error);
            assert_eq!(refused.code(), "DREAMER_REQUEST_REJECTED");
        }
    }
}
