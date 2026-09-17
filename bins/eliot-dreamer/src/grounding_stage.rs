//! A-14b grounding stage for admitted Dreamer jobs (issue #702, Slice 5).
//!
//! After the A-04 bundle stage, the binary grounds the structured draft
//! against the frozen evidence universe through the #602 owner
//! ([`ground_draft_with_controls`](eliot_dreamer_claim_grounding::ground_draft_with_controls))
//! exactly once per admitted job. This module performs no local retrieval,
//! ranking, or truth promotion: the structured draft and the frozen manifest
//! arrive Governor-resolved through a source-owner port in a later slice,
//! and the returned owner [`GroundedDreamDraft`](eliot_dreamer_contracts::grounding::GroundedDreamDraft)
//! is surfaced unmodified so the frozen claim denominator is preserved
//! losslessly (the denominator arrives with governed material; Dreamer never
//! selects it, and never synthesizes a frozen universe locally).

use eliot_dreamer_claim_grounding::{GroundingRequest, ground_draft_with_controls};
use eliot_dreamer_contracts::ContractViolation;
use eliot_dreamer_contracts::grounding::GroundedDreamDraft;

use crate::controller::verify_admitted_binding;
use crate::{DreamJobInput, DreamerError, KernelJobAdmission};

/// Admitted grounding identity for one Dreamer job.
///
/// A placeholder until the Governor-resolved draft and frozen manifest arrive
/// through a source-owner port in a later slice: it carries only the admitted
/// job identity and the frozen manifest digest it must bind, never assembled
/// evidence. Resolution refuses rather than filling these handles locally,
/// because a locally built universe would be self-issued authority.
///
/// Constructed by the Governor-material slice once the source-owner port
/// lands; until then the slice tests pin its identity-only shape.
#[allow(
    dead_code,
    reason = "constructed by the Governor-material slice; tests pin it until then"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GroundingInputs {
    pub job_id: String,
    pub manifest_digest: String,
}

/// Resolves the A-14b inputs for one admitted job.
///
/// Fails closed: any invalid/stale admission or identity mismatch refuses here
/// with zero owner-grounding calls. The Governor-issued structured draft and
/// frozen evidence universe arrive through a source-owner port in a later
/// slice; until then resolution refuses rather than synthesizing a frozen
/// universe locally, because locally assembled evidence would be self-issued
/// authority.
///
/// Called by `submit` once the Governor-material slice lands; until then the
/// slice tests exercise the fail-closed boundary.
#[allow(
    dead_code,
    reason = "called by submit in the Governor-material slice; tests cover it until then"
)]
pub(crate) fn resolve_grounding_inputs(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<GroundingInputs, DreamerError> {
    verify_admitted_binding(admission, job)?;
    Err(DreamerError::InvalidAdmission(
        "admitted grounding inputs require Governor-resolved draft and manifest",
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
/// Unwired until the Governor-material slice lands: `submit` cannot supply a
/// [`GroundingRequest`] yet, so the entry is exercised by the slice tests
/// below. Remove the allowance once the pipeline calls this entry.
#[allow(
    dead_code,
    reason = "wired by the Governor-material slice; tests cover it until then"
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
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::NonZeroU64;
    use std::sync::atomic::{AtomicU64, Ordering};

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId};
    use eliot_dreamer_claim_grounding::ground_draft_with_controls;
    use eliot_dreamer_contracts::grounding::{
        AllowedReferenceManifest, AttemptIdentity, GROUNDING_SCHEMA_VERSION, GroundingPolicy,
        ModelDraft, RouteIdentity,
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

    /// Stale Kernel input fails closed at resolution with zero grounding
    /// calls: resolution precedes grounding, so there is no grounding to
    /// count — the refusal itself is the proof, and it carries the
    /// request-rejected code for a stale deadline, never synthesized inputs.
    #[test]
    fn stale_admission_fails_closed_before_any_grounding() {
        let admission = admission_with_deadline(1);
        let job = job_for(&admission);
        let refused = resolve_grounding_inputs(&admission, &job);
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
        let refused = resolve_grounding_inputs(&admission, &job);
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err(KERNEL_ADMISSION_REQUIRED)
        );
    }

    /// A valid admission with matching identity reaches the material
    /// boundary: the refusal names the missing Governor-resolved draft and
    /// manifest instead of synthesizing a frozen universe locally (no
    /// self-issued authority).
    #[test]
    fn valid_admission_waits_for_governed_material() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_for(&admission);
        let refused = resolve_grounding_inputs(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "admitted grounding inputs require Governor-resolved draft and manifest"
                ))
            ),
            "valid input must wait for governed material, got {refused:?}"
        );
    }

    /// The admitted grounding handle carries identity only: the job it binds
    /// and the frozen manifest digest it must match. No assembled evidence
    /// travels here, so resolution output cannot become a locally synthesized
    /// universe behind the Governor's back.
    #[test]
    fn grounding_inputs_hold_identity_only() {
        let inputs = GroundingInputs {
            job_id: "job-slice-5".to_owned(),
            manifest_digest: "manifest-slice-5".to_owned(),
        };
        assert_eq!(inputs.job_id, "job-slice-5");
        assert_eq!(inputs.manifest_digest, "manifest-slice-5");
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
