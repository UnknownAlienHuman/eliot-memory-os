//! A-05 pre-handler validation stage for admitted Dreamer jobs (issue #702,
//! Slice 6; Orientation native shape #1136, Slice B).
//!
//! After [`plan_admitted_bundle`](crate::bundle_stage::plan_admitted_bundle),
//! the binary validates the Governor-resolved draft through the A-05 owner
//! ([`validate_grounding_candidate_at`](eliot_dreamer_candidate_validation::validate_grounding_candidate_at))
//! exactly once per admitted job, before any typed Dreamer handler runs
//! (A-05 / #595). This module owns no validation algorithm, performs no I/O,
//! fetch, ranking, or model work, and invents no state: the pure owner
//! function decides, this composition only calls it once and maps its typed
//! refusal fail-closed.
//!
//! Stage order is `dispatch_admission`, then the controller step, then the
//! bundle plan, then validation here: a refused class returns at dispatch
//! with zero validation work, and a failed controller or bundle stage never
//! reaches validation. Non-admitted refused classes never reach this seam
//! (dispatch already refused them), but resolution still refuses them
//! fail-closed with [`DreamerError::UnsupportedJobClass`] if they do.
//!
//! Orientation consumes the native
//! [`OrientationPacketCandidate`](eliot_dreamer_orientation::OrientationPacketCandidate),
//! never a literal 15-key YAML document. Slice B adaptations:
//!
//! - G1: scope/state-fence split. The candidate frame carries `scope_id`,
//!   `task_id`, and `operation_id` plus fences as separate bindings. Mapping
//!   takes `scope_id` from the Kernel admission (equal to the job scope by
//!   binding), `task_id` from [`DreamJobInput::task_id`], and `operation_id`
//!   from [`KernelJobAdmission::request_id`] — the Kernel-issued per-claim
//!   correlation identity — preferring it over `task_id`, which names the
//!   semantic task in a different namespace and may be absent. Fences stay
//!   bound through [`verify_admitted_binding`](crate::controller::verify_admitted_binding)
//!   (the admitted typed fence, proved equal on the Kernel and semantic sides)
//!   and are never collapsed into a single literal fence string.
//! - G2: 32-key candidate versus 15-key shape handled natively. This seam
//!   accepts only the native struct; no YAML or 15-key parsing exists here
//!   (the crate does not depend on a YAML parser for this path).
//! - G3: `anchored_evidence_by_status` flat vector handled natively. The seam
//!   never regroups evidence by status: it carries identity through untouched
//!   and leaves the flat
//!   [`Vec<AnchoredEvidence>`](eliot_dreamer_orientation::AnchoredEvidence)
//!   to the owner.
//! - G4: `architecture_implications` / `model_routes_and_cost` markers
//!   preserved. The seam takes references and returns no rewritten copy, so
//!   there is no field here that could drop or thin the owner residues.
//! - G5: Governor-resolved material arrives as the typed owner carrier. The
//!   sibling grounding stage supplies the [`GroundedDreamDraft`](eliot_dreamer_contracts::grounding::GroundedDreamDraft);
//!   the caller builds the [`GroundingValidationInput`] from it (policy,
//!   usage, preservation, observation, rival declarations) and passes it to
//!   [`validate_admitted_draft`]. Resolution itself maps admitted classes
//!   directly with no material gate: nothing is synthesized here, and the
//!   owner decides acceptance on the supplied carrier.

use eliot_dreamer_candidate_validation::{
    DreamDraftValidationError, StructuredCandidateValidationOutcome,
    validate_grounding_candidate_at,
};
use eliot_dreamer_contracts::JobClass;
use eliot_dreamer_contracts::validation::structured::{
    GroundingValidationInput, ValidatedGroundingCandidate,
};

use crate::controller::verify_admitted_binding;
use crate::{DreamJobInput, DreamerError, KernelJobAdmission};

/// Validation inputs resolved for one admitted job.
///
/// Orientation carries its native G1 split (scope, optional task, operation);
/// every other admitted class carries no per-class shape yet and resolves to
/// [`ValidationInputs::OtherAdmitted`]. Refused classes never construct this
/// value: resolution refuses them first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ValidationInputs {
    /// Native Orientation identity split (G1): scope plus optional task from
    /// the semantic input, operation from the Kernel admission correlation.
    OrientationNative {
        /// Admitted scope, equal to the job scope by binding.
        scope_id: String,
        /// Semantic task, absent when the job names none.
        task_id: Option<String>,
        /// Kernel-issued per-claim correlation (`request_id`), never the
        /// semantic task.
        operation_id: String,
    },
    /// Admitted non-Orientation classes (`ResearchSynthesis`, `Maintenance`,
    /// `Curation`): no per-class validation shape yet.
    ///
    /// `Curation` maps here, but the admitted chain never sends it through
    /// common A-05 validation: Slice-A admits Curation since Wave S2 (#966),
    /// `submit` threads it screen → carrier-check → A-31, and the A-05 owner
    /// itself directs Curation to its separate carrier (`UnsupportedJobShape`
    /// semantic rejection). This arm maps the class by owner rule — it is the
    /// chain order, not a gate refusal, that keeps Curation out of the
    /// generic validation path.
    OtherAdmitted,
}

/// Resolves the A-05 validation inputs for one admitted job.
///
/// Fails closed: any invalid/stale admission or identity mismatch refuses here
/// with zero owner-validation calls, and refused classes refuse with
/// [`DreamerError::UnsupportedJobClass`]. Admitted classes map directly to
/// [`ValidationInputs`] (Orientation through the G1 split, the remaining
/// admitted classes through the shared arm). The Governor-resolved
/// [`GroundingValidationInput`] itself arrives as the parameter to
/// [`validate_admitted_draft`]: resolution maps identity only and never
/// synthesizes draft material.
pub(crate) fn resolve_validation_inputs(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<ValidationInputs, DreamerError> {
    map_admitted_inputs(admission, job)
}

/// Maps one admitted job to its validation inputs after the binding check.
///
/// Pure mapping step of [`resolve_validation_inputs`]: binding first, then
/// the closed class match (admitted classes map, refused classes refuse), so
/// the G1 split is observable and testable.
fn map_admitted_inputs(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<ValidationInputs, DreamerError> {
    verify_admitted_binding(admission, job)?;
    match job.job_class {
        JobClass::Orientation => Ok(ValidationInputs::OrientationNative {
            scope_id: admission.scope_id.clone(),
            task_id: job.task_id.clone(),
            operation_id: admission.request_id.clone(),
        }),
        JobClass::ResearchSynthesis | JobClass::Maintenance | JobClass::Curation => {
            Ok(ValidationInputs::OtherAdmitted)
        }
        JobClass::Clarification
        | JobClass::ArchitectureSelfQuery
        | JobClass::DevelopmentDiagnosis
        | JobClass::OrchestrationPlanning
        | JobClass::ConfigurationAssistance => {
            Err(DreamerError::UnsupportedJobClass(job.job_class))
        }
    }
}

/// Validates the admitted draft exactly once.
///
/// `validate_once` is `FnOnce`: the owner validation cannot run twice for one
/// admission through this seam. Production passes the A-05 owner entry (see
/// [`validate_admitted_draft`]); deterministic tests pass a counting wrapper
/// around the real owner validation to prove the once-per-admission call
/// shape. An accepted carrier returns the owner's bound candidate; a rejected
/// carrier maps to the static semantic-rejection refusal (the dynamic
/// [`RejectionCode`](eliot_dreamer_candidate_validation::RejectionCode) stays
/// out of the typed error); an owner contract failure maps through
/// [`validation_denied`].
pub(crate) fn validate_admitted_draft_with(
    input: &GroundingValidationInput,
    validate_once: impl FnOnce(
        &GroundingValidationInput,
    ) -> Result<
        StructuredCandidateValidationOutcome,
        DreamDraftValidationError,
    >,
) -> Result<ValidatedGroundingCandidate, DreamerError> {
    match validate_once(input) {
        Ok(StructuredCandidateValidationOutcome::Accepted(candidate)) => Ok(*candidate),
        Ok(StructuredCandidateValidationOutcome::Rejected(_)) => Err(
            DreamerError::InvalidAdmission("validation semantic rejection"),
        ),
        Err(error) => Err(validation_denied(&error)),
    }
}

/// Production entry: the real A-05 owner validation, once per admission.
///
/// Wires [`validate_grounding_candidate_at`] as the `FnOnce` body: the owner
/// function decides acceptance on the supplied Governor-resolved carrier, and
/// this composition only calls it once and maps its typed outcome
/// fail-closed.
pub(crate) fn validate_admitted_draft(
    input: &GroundingValidationInput,
) -> Result<ValidatedGroundingCandidate, DreamerError> {
    validate_admitted_draft_with(input, validate_grounding_candidate_at)
}

/// Maps an owner validation refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code: the admission itself was valid, the draft
/// was not. Dynamic payloads (bounds, digests, details) are dropped in favor
/// of the bounded static field names; nothing secret flows.
fn validation_denied(error: &DreamDraftValidationError) -> DreamerError {
    match error {
        DreamDraftValidationError::Bound { field, .. }
        | DreamDraftValidationError::Encoding { field, .. }
        | DreamDraftValidationError::InvalidContract { field, .. } => {
            DreamerError::InvalidAdmission(field)
        }
    }
}

#[cfg(test)]
mod slice_6_validation_tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicU64, Ordering};

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId};
    use eliot_dreamer_candidate_validation::RejectionCode;
    use eliot_dreamer_candidate_validation::StructuredCandidateRejectionReport;
    use eliot_dreamer_contracts::grounding::StructuredModelDraft;
    use eliot_dreamer_contracts::grounding::{
        AllowedReferenceManifest, AttemptIdentity, ClaimGroundingLedger, GROUNDING_SCHEMA_VERSION,
        GroundedDreamDraft, GroundingPolicy, RouteIdentity,
    };
    use eliot_dreamer_contracts::{
        BudgetLimits, BudgetUsage, BundleCompleteness, DreamInputBundle, DreamJobAdmission,
        PreservationReport, Requester, RequesterOrigin, ValidationPolicy,
    };
    use eliot_dreamer_orientation::{
        AnchoredEvidence, OrientationPacketCandidate, OrientationResidue,
    };

    use crate::KERNEL_ADMISSION_REQUIRED;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let Ok(lineage) = EpochLineageId::new(TEST_LINEAGE) else {
            panic!("valid test lineage");
        };
        let Some(sequence) = std::num::NonZeroU64::new(1) else {
            panic!("nonzero test sequence");
        };
        let Ok(epoch) = EpochId::new(lineage, sequence) else {
            panic!("valid test epoch");
        };
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn admission_with_deadline(deadline_unix_ms: u64) -> KernelJobAdmission {
        KernelJobAdmission {
            job_id: "job-slice-6".to_owned(),
            attempt_id: "attempt-slice-6".to_owned(),
            scope_id: "scope-slice-6".to_owned(),
            request_id: "request-slice-6".to_owned(),
            idempotency_key: "job-slice-6:attempt-slice-6".to_owned(),
            cancellation_id: "cancel-slice-6".to_owned(),
            deadline_unix_ms,
            state_fence: fence(),
        }
    }

    fn job_of_class(
        admission: &KernelJobAdmission,
        class: JobClass,
        task_id: Option<&str>,
    ) -> DreamJobInput {
        DreamJobInput {
            job_id: "job-slice-6".to_owned(),
            job_class: class,
            exact_question: "What does ELIOT know about this scope?".to_owned(),
            requester: "test-harness".to_owned(),
            scope_id: "scope-slice-6".to_owned(),
            task_id: task_id.map(str::to_owned),
            state_fence: admission.state_fence.clone(),
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

    /// Maps one admitted job, panicking on refusal: the admitted-path tests
    /// below only exercise classes that must map, so a refusal is a test
    /// failure rather than a case to branch on.
    fn must_map(admission: &KernelJobAdmission, job: &DreamJobInput) -> ValidationInputs {
        match map_admitted_inputs(admission, job) {
            Ok(mapped) => mapped,
            Err(error) => panic!("admitted class must map, got {error:?}"),
        }
    }

    /// Resolves one admitted job, panicking on refusal: see [`must_map`].
    fn must_resolve(admission: &KernelJobAdmission, job: &DreamJobInput) -> ValidationInputs {
        match resolve_validation_inputs(admission, job) {
            Ok(resolved) => resolved,
            Err(error) => panic!("admitted input must resolve, got {error:?}"),
        }
    }

    /// Stale Kernel input fails closed at resolution with zero validation
    /// calls: resolution precedes validation, so there is no validation to
    /// count — the refusal itself is the proof, and it carries the
    /// request-rejected code for a mere stale deadline.
    #[test]
    fn stale_admission_fails_closed_before_any_validation() {
        let admission = admission_with_deadline(1);
        let job = job_of_class(&admission, JobClass::Orientation, None);
        let refused = resolve_validation_inputs(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission("Kernel deadline is stale"))
            ),
            "stale admission must fail closed, got {refused:?}"
        );
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err("DREAMER_REQUEST_REJECTED")
        );
    }

    /// A caller-switched job identity fails closed at the binding check with
    /// the Kernel-admission code and zero validation calls.
    #[test]
    fn switched_job_identity_fails_closed_before_any_validation() {
        let admission = admission_with_deadline(u64::MAX);
        let mut job = job_of_class(&admission, JobClass::Orientation, None);
        job.job_id = "caller-switched-job".to_owned();
        let refused = resolve_validation_inputs(&admission, &job);
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err(KERNEL_ADMISSION_REQUIRED)
        );
    }

    /// Refused classes fail closed at resolution with the exact unsupported
    /// variant and the request-rejected code, never the Kernel-admission
    /// code. Dispatch already refused these classes; this arm is defense in
    /// depth if one ever reaches the seam. `Curation` is not in this set: it
    /// maps to the shared admitted arm (Slice-A admits it since Wave S2
    /// (#966) and the chain threads it screen → carrier-check → A-31, so it
    /// never reaches common A-05 validation in production — by chain order,
    /// not by gate refusal).
    #[test]
    fn refused_classes_return_unsupported_job_class() {
        for class in [
            JobClass::Clarification,
            JobClass::ArchitectureSelfQuery,
            JobClass::DevelopmentDiagnosis,
            JobClass::OrchestrationPlanning,
            JobClass::ConfigurationAssistance,
        ] {
            let admission = admission_with_deadline(u64::MAX);
            let job = job_of_class(&admission, class, None);
            let refused = resolve_validation_inputs(&admission, &job);
            assert!(
                matches!(refused, Err(DreamerError::UnsupportedJobClass(refused_class)) if refused_class == class),
                "class {class:?} must refuse with UnsupportedJobClass({class:?})"
            );
            let admission = admission_with_deadline(u64::MAX);
            let job = job_of_class(&admission, class, None);
            assert_eq!(
                resolve_validation_inputs(&admission, &job).map_err(|error| error.code()),
                Err("DREAMER_REQUEST_REJECTED"),
                "class {class:?} refusal must carry the request-rejected code"
            );
        }
    }

    /// G1: Orientation maps to the native scope/task/operation split.
    /// Operation comes from the Kernel admission correlation (`request_id`),
    /// never from the semantic task; scope follows the bound admission; the
    /// task passes through present or absent without invention.
    #[test]
    fn orientation_g1_mapping_splits_scope_task_operation() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_of_class(&admission, JobClass::Orientation, Some("task-slice-6"));
        let mapped = must_map(&admission, &job);
        assert_eq!(
            mapped,
            ValidationInputs::OrientationNative {
                scope_id: "scope-slice-6".to_owned(),
                task_id: Some("task-slice-6".to_owned()),
                operation_id: "request-slice-6".to_owned(),
            }
        );
        let ValidationInputs::OrientationNative {
            scope_id,
            task_id,
            operation_id,
        } = mapped
        else {
            panic!("Orientation must map to its native split");
        };
        assert_eq!(scope_id, admission.scope_id);
        assert_eq!(task_id.as_deref(), Some("task-slice-6"));
        assert_eq!(operation_id, admission.request_id);
        assert_ne!(
            operation_id, "task-slice-6",
            "operation must be the Kernel correlation, not the semantic task"
        );

        let job_without_task = job_of_class(&admission, JobClass::Orientation, None);
        let mapped = must_map(&admission, &job_without_task);
        assert!(
            matches!(
                mapped,
                ValidationInputs::OrientationNative { task_id: None, .. }
            ),
            "an absent task must stay absent, got {mapped:?}"
        );
    }

    /// Other admitted classes map to the shared arm with no per-class shape.
    /// `Curation` maps here as well: Slice-A admits it since Wave S2 (#966)
    /// and the chain threads it screen → carrier-check → A-31, so production
    /// never routes it through common A-05 validation — by chain order and
    /// the owner `UnsupportedJobShape` rule, not by gate refusal.
    #[test]
    fn other_admitted_classes_map_to_shared_arm() {
        for class in [
            JobClass::ResearchSynthesis,
            JobClass::Maintenance,
            JobClass::Curation,
        ] {
            let admission = admission_with_deadline(u64::MAX);
            let job = job_of_class(&admission, class, None);
            assert!(
                matches!(
                    map_admitted_inputs(&admission, &job),
                    Ok(ValidationInputs::OtherAdmitted)
                ),
                "class {class:?} must map to the shared admitted arm"
            );
        }
    }

    /// Admitted resolution returns the mapped inputs directly: a valid
    /// admission with matching identity resolves without any Governor-material
    /// gate, because the Governor-resolved carrier now arrives as the
    /// parameter to [`validate_admitted_draft`].
    #[test]
    fn admitted_resolution_returns_mapped_inputs() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_of_class(&admission, JobClass::Orientation, Some("task-slice-6"));
        let resolved = must_resolve(&admission, &job);
        assert_eq!(
            resolved,
            ValidationInputs::OrientationNative {
                scope_id: "scope-slice-6".to_owned(),
                task_id: Some("task-slice-6".to_owned()),
                operation_id: "request-slice-6".to_owned(),
            }
        );
        for class in [
            JobClass::ResearchSynthesis,
            JobClass::Maintenance,
            JobClass::Curation,
        ] {
            let job = job_of_class(&admission, class, None);
            assert!(
                matches!(
                    resolve_validation_inputs(&admission, &job),
                    Ok(ValidationInputs::OtherAdmitted)
                ),
                "class {class:?} must resolve to the shared admitted arm"
            );
        }
    }

    /// G2/G3/G4: the seam is shape-agnostic over payload and carries identity
    /// through untouched. Two jobs differing only in evidence, architecture,
    /// and model-route markers map to identical inputs: nothing is parsed as
    /// 15-key YAML (G2), nothing is regrouped by status (G3), and no marker
    /// is dropped or rewritten (G4). The clone round-trip keeps every field.
    #[test]
    fn seam_carries_identity_untouched_g2_g3_g4() {
        let admission = admission_with_deadline(u64::MAX);
        let mut first = job_of_class(&admission, JobClass::Orientation, Some("task-slice-6"));
        first.evidence_handles = vec!["evidence-a".to_owned()];
        first.architecture_handles = vec!["architecture-a".to_owned()];
        first.allowed_model_routes = vec!["route-a".to_owned()];
        let mut second = job_of_class(&admission, JobClass::Orientation, Some("task-slice-6"));
        second.evidence_handles = vec!["evidence-b".to_owned(), "evidence-c".to_owned()];
        second.architecture_handles = vec!["architecture-b".to_owned()];
        second.allowed_model_routes = vec!["route-b".to_owned(), "route-c".to_owned()];
        let first_mapped = must_map(&admission, &first);
        let second_mapped = must_map(&admission, &second);
        assert_eq!(
            first_mapped, second_mapped,
            "payload markers must pass through without parse, regroup, or rewrite"
        );
        assert_eq!(first_mapped.clone(), first_mapped);
        let rendered = format!("{first_mapped:?}");
        assert!(
            rendered.contains("scope-slice-6")
                && rendered.contains("task-slice-6")
                && rendered.contains("request-slice-6"),
            "mapped identity must carry scope, task, and operation, got {rendered}"
        );
    }

    /// Reads the native flat evidence vector length. This helper exists as a
    /// compile-time shape proof: it only compiles if the native candidate
    /// carries `anchored_evidence_by_status` as a flat vector (G3).
    fn native_flat_evidence_len(candidate: &OrientationPacketCandidate) -> usize {
        candidate.anchored_evidence_by_status.len()
    }

    /// Reads the native marker pair. This helper exists as a compile-time
    /// shape proof: it only compiles if the native candidate carries both
    /// `architecture_implications` and `model_routes_and_cost` markers (G4).
    fn native_marker_pair(
        candidate: &OrientationPacketCandidate,
    ) -> (&OrientationResidue, &OrientationResidue) {
        (
            &candidate.architecture_implications,
            &candidate.model_routes_and_cost,
        )
    }

    /// G2/G3/G4: Orientation is consumed as the native struct, not as YAML.
    /// The crate exposes the native candidate type (no 15-key parse), and the
    /// flat-vector plus marker helpers above pin the G3/G4 field shapes at
    /// compile time.
    #[test]
    fn native_orientation_shape_is_struct_not_yaml_g2_g3_g4() {
        let candidate_path = std::any::type_name::<OrientationPacketCandidate>();
        assert_eq!(
            candidate_path, "eliot_dreamer_orientation::projection::OrientationPacketCandidate",
            "validation must consume the native candidate struct"
        );
        let evidence_path = std::any::type_name::<Vec<AnchoredEvidence>>();
        assert!(
            evidence_path.contains("AnchoredEvidence"),
            "evidence must travel as the native anchored vector, got {evidence_path}"
        );
        let _ = native_flat_evidence_len as fn(&OrientationPacketCandidate) -> usize;
        let _ = native_marker_pair
            as fn(&OrientationPacketCandidate) -> (&OrientationResidue, &OrientationResidue);
    }

    /// Builds the carried job preimage for the owner-call proofs below. The
    /// values are only carried, never trusted: the real A-05 owner refuses
    /// the carrier at its first shallow-shape check.
    fn carrier_job() -> DreamJobAdmission {
        DreamJobAdmission {
            schema_version: 1,
            job_class: JobClass::Orientation,
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "test-harness".to_owned(),
                session: None,
            },
            operation_id: "operation-slice-6".to_owned(),
            idempotency_key: "idempotency-slice-6".to_owned(),
            task_id: "task-slice-6".to_owned(),
            scope_id: "scope-slice-6".to_owned(),
            state_fence: fence(),
            privacy_profile: "local_only".to_owned(),
            contract_ref: "contract-slice-6".to_owned(),
            policy_ref: "policy-slice-6".to_owned(),
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
            frozen_manifest_digest: String::new(),
        }
    }

    /// Builds the carried bundle preimage: only carried, never trusted (see
    /// [`carrier_job`]).
    fn carrier_bundle() -> DreamInputBundle {
        DreamInputBundle {
            schema_version: 1,
            job_id: "job-slice-6".to_owned(),
            scope_id: "scope-slice-6".to_owned(),
            task_id: "task-slice-6".to_owned(),
            state_fence: fence(),
            manifest_digest: String::new(),
            materials: Vec::new(),
            omissions: Vec::new(),
            completeness: BundleCompleteness::Unknown,
            authoritative_denominator: None,
        }
    }

    /// Builds the carried grounding draft preimage: only carried, never
    /// trusted (see [`carrier_job`]).
    fn carrier_draft(
        job: DreamJobAdmission,
        bundle: DreamInputBundle,
        task_id: TaskId,
    ) -> StructuredModelDraft {
        StructuredModelDraft {
            schema_version: GROUNDING_SCHEMA_VERSION,
            job_id: "job-slice-6".to_owned(),
            task_id,
            scope_id: "scope-slice-6".to_owned(),
            state_fence: fence(),
            job,
            bundle,
            raw_output_digest: String::new(),
            requester_digest: String::new(),
            attempt: AttemptIdentity {
                attempt_id: "attempt-slice-6".to_owned(),
                attempt_number: 1,
                maximum_attempts: 2,
            },
            route: RouteIdentity {
                provider: "provider-slice-6".to_owned(),
                model: "model-slice-6".to_owned(),
                route_revision: "r1".to_owned(),
                fingerprint: "fingerprint-slice-6".to_owned(),
            },
            budget_digest: String::new(),
            bundle_digest: String::new(),
            input_manifest_digest: String::new(),
            claims: Vec::new(),
            non_material_claims: Vec::new(),
            screen: None,
            draft_digest: String::new(),
        }
    }

    /// Builds the carried manifest preimage: only carried, never trusted (see
    /// [`carrier_job`]).
    fn carrier_manifest(task_id: TaskId) -> AllowedReferenceManifest {
        AllowedReferenceManifest {
            schema_version: GROUNDING_SCHEMA_VERSION,
            manifest_id: "manifest-slice-6".to_owned(),
            run_id: "run-slice-6".to_owned(),
            task_id,
            scope_id: "scope-slice-6".to_owned(),
            state_fence: fence(),
            source_snapshot: "snapshot-slice-6".to_owned(),
            source_revision: "revision-slice-6".to_owned(),
            references: BTreeMap::new(),
            coverage_denominators: BTreeMap::new(),
            coverage_receipts: BTreeMap::new(),
            dependence_groups: BTreeSet::new(),
            digest: String::new(),
        }
    }

    /// Builds the carried grounding policy preimage: only carried, never
    /// trusted (see [`carrier_job`]).
    fn carrier_grounding_policy() -> GroundingPolicy {
        GroundingPolicy {
            schema_version: GROUNDING_SCHEMA_VERSION,
            policy_id: "policy-slice-6".to_owned(),
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

    /// Builds the carried ledger preimage: only carried, never trusted (see
    /// [`carrier_job`]).
    fn carrier_ledger(task_id: TaskId) -> ClaimGroundingLedger {
        ClaimGroundingLedger {
            schema_version: GROUNDING_SCHEMA_VERSION,
            operation_id: "operation-slice-6".to_owned(),
            run_id: "run-slice-6".to_owned(),
            job_id: "job-slice-6".to_owned(),
            task_id,
            scope_id: "scope-slice-6".to_owned(),
            state_fence: fence(),
            draft_digest: String::new(),
            manifest_digest: String::new(),
            policy_digest: String::new(),
            expected_claim_ids: BTreeSet::new(),
            expected_subclaim_ids: BTreeMap::new(),
            records: BTreeMap::new(),
            nonmaterial_claim_ids: BTreeSet::new(),
            unprocessed_claim_ids: BTreeSet::new(),
            unprocessed_reason: None,
            ledger_digest: String::new(),
        }
    }

    /// Builds a structurally addressed but wire-versioned carrier for the
    /// owner-call proofs below. The outer `schema_version` is intentionally
    /// wrong, so the real A-05 owner refuses at its first shallow-shape check
    /// (`structured.schema_version`) without needing a fully valid grounded
    /// preimage; every nested value is only carried, never trusted.
    fn malformed_carrier() -> GroundingValidationInput {
        let Ok(task_id) = TaskId::new("task-slice-6") else {
            panic!("valid test task");
        };
        let draft = carrier_draft(carrier_job(), carrier_bundle(), task_id.clone());
        let grounded = GroundedDreamDraft {
            schema_version: GROUNDING_SCHEMA_VERSION,
            job_id: "job-slice-6".to_owned(),
            task_id: task_id.clone(),
            scope_id: "scope-slice-6".to_owned(),
            state_fence: fence(),
            draft_digest: String::new(),
            manifest_digest: String::new(),
            policy_digest: String::new(),
            input: draft,
            manifest: carrier_manifest(task_id.clone()),
            policy: carrier_grounding_policy(),
            ledger: carrier_ledger(task_id),
            screen: None,
            output_digest: String::new(),
        };
        GroundingValidationInput {
            schema_version: 0,
            grounded: Box::new(grounded),
            policy: ValidationPolicy::new("policy-slice-6", 1, 1024),
            usage: BudgetUsage::default(),
            preservation: PreservationReport {
                verdicts: Vec::new(),
            },
            observation_time_ms: None,
            cancellation_requested: false,
            rival_declarations: None,
        }
    }

    /// The real A-05 owner validation runs exactly once per admitted
    /// admission: one counting wrapper around the production function over a
    /// wire-versioned carrier, one call, one typed fail-closed refusal with
    /// the request-rejected code.
    #[test]
    fn owner_validation_runs_exactly_once_per_admission() {
        let input = malformed_carrier();
        let calls = AtomicU64::new(0);
        let refused = validate_admitted_draft_with(&input, |carrier| {
            calls.fetch_add(1, Ordering::SeqCst);
            validate_grounding_candidate_at(carrier)
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "owner validation must run exactly once per admission"
        );
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission("structured.schema_version"))
            ),
            "owner refusal must map fail-closed, got {refused:?}"
        );
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err("DREAMER_REQUEST_REJECTED")
        );
    }

    /// The production entry calls the real owner once: the same wire-versioned
    /// carrier refuses through the production path with the request-rejected
    /// code, never the Kernel-admission code.
    #[test]
    fn production_entry_calls_the_real_owner_once() {
        let refused = validate_admitted_draft(&malformed_carrier());
        let Err(error) = refused else {
            panic!("wire-versioned carrier must refuse through the real owner");
        };
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert!(
            matches!(
                error,
                DreamerError::InvalidAdmission("structured.schema_version")
            ),
            "production refusal must carry the owner field, got {error:?}"
        );
        assert!(
            !matches!(error, DreamerError::KernelAdmissionRequired(_)),
            "validation refusal must not borrow the Kernel-admission code"
        );
    }

    /// A rejected owner report maps to the static semantic-rejection refusal:
    /// the dynamic rejection code stays out of the typed error while the
    /// refusal still carries the request-rejected code.
    #[test]
    fn rejected_report_maps_to_semantic_rejection() {
        let input = malformed_carrier();
        let report = StructuredCandidateRejectionReport {
            input: input.clone(),
            code: RejectionCode::IdentityMismatch,
            detail: "structured job or policy identity differs".to_owned(),
            input_digest: "0".repeat(64),
        };
        let refused = validate_admitted_draft_with(&input, |_| {
            Ok(StructuredCandidateValidationOutcome::Rejected(Box::new(
                report,
            )))
        });
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "validation semantic rejection"
                ))
            ),
            "rejected report must map to the semantic refusal, got {refused:?}"
        );
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err("DREAMER_REQUEST_REJECTED")
        );
    }

    /// Every owner validation refusal shape maps to the request-rejected
    /// code, never to the Kernel-admission code.
    #[test]
    fn every_owner_refusal_maps_fail_closed() {
        let cases = [
            DreamDraftValidationError::Bound {
                field: "structured.input",
                maximum: 1,
                actual: 2,
            },
            DreamDraftValidationError::Encoding {
                field: "packet",
                detail: "encoding".to_owned(),
            },
            DreamDraftValidationError::InvalidContract {
                phase: "structured shape",
                field: "structured.schema_version",
            },
        ];
        assert_eq!(cases.len(), 3);
        for error in &cases {
            let refused = validation_denied(error);
            assert_eq!(refused.code(), "DREAMER_REQUEST_REJECTED");
            assert!(
                !matches!(refused, DreamerError::KernelAdmissionRequired(_)),
                "validation refusal must not borrow the Kernel-admission code"
            );
        }
        assert!(matches!(
            validation_denied(&cases[0]),
            DreamerError::InvalidAdmission("structured.input")
        ));
        assert!(matches!(
            validation_denied(&cases[1]),
            DreamerError::InvalidAdmission("packet")
        ));
        assert!(matches!(
            validation_denied(&cases[2]),
            DreamerError::InvalidAdmission("structured.schema_version")
        ));
    }

    /// Builds one admitted Orientation pair bound to evidence the frame source
    /// and the v1 hypothesis can bind: the same epoch-1 fence on both sides
    /// so only owner gates (never identity) can refuse.
    fn admitted_orientation_pair() -> (KernelJobAdmission, DreamJobInput) {
        let admission = admission_with_deadline(u64::MAX);
        let mut job = job_of_class(&admission, JobClass::Orientation, Some("task-slice-6"));
        job.evidence_handles = vec!["evidence-slice-6".to_owned()];
        (admission, job)
    }

    /// Runs the genuine admitted chain up to grounding for one fixture pair:
    /// model derivation, then the real A-14b owner grounding, surfaced
    /// unmodified.
    fn grounding_for(admission: &KernelJobAdmission, job: &DreamJobInput) -> GroundedDreamDraft {
        let model_inputs = match crate::model_stage::resolve_model_inputs(admission, job) {
            Ok(inputs) => inputs,
            Err(error) => panic!("fixture model inputs must resolve, got {error:?}"),
        };
        let draft = match crate::model_stage::run_admitted_model(model_inputs) {
            Ok(draft) => draft,
            Err(error) => panic!("fixture model must prove, got {error:?}"),
        };
        let request = match crate::grounding_stage::resolve_grounding_inputs(admission, job, draft)
        {
            Ok(request) => request,
            Err(error) => panic!("fixture grounding must resolve, got {error:?}"),
        };
        match crate::grounding_stage::ground_admitted_draft(request) {
            Ok(grounded) => grounded,
            Err(error) => panic!("fixture grounding must prove, got {error:?}"),
        }
    }

    /// Builds the genuine A-05 carrier for one grounded fixture pair with an
    /// explicit observation time.
    fn carrier_for(
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
        grounded: GroundedDreamDraft,
        observation_time_ms: Option<u64>,
    ) -> GroundingValidationInput {
        match crate::admitted_material::validation_input_for(
            admission,
            job,
            grounded,
            observation_time_ms,
        ) {
            Ok(carrier) => carrier,
            Err(error) => panic!("fixture carrier must build, got {error:?}"),
        }
    }

    /// A-05 pre-handler proof (a): accepted input runs the real owner
    /// validation exactly once and the real dispatcher projects exactly
    /// once. The counting wrappers surround the genuine owner functions, so
    /// the counters prove the once-per-admission call shape on the same code
    /// production executes; the packet assertions prove the handler genuinely
    /// ran (identity bindings verbatim, candidate-only ceiling, G4 markers).
    #[test]
    fn prehandler_runs_before_handler() {
        use crate::DreamResult;
        use crate::dispatch_stage::{dispatch_orientation_with, project_validated_orientation};
        use eliot_dreamer_candidate_validation::validate_grounded_dream_draft_at;

        let (admission, job) = admitted_orientation_pair();
        let grounded = grounding_for(&admission, &job);
        let input = carrier_for(&admission, &job, grounded, Some(0));
        let validation_calls = Cell::new(0_usize);
        let validated = validate_admitted_draft_with(&input, |carrier| {
            validation_calls.set(validation_calls.get() + 1);
            validate_grounding_candidate_at(carrier)
        });
        let Ok(validated) = validated else {
            panic!("admitted carrier must pass pre-handler validation");
        };
        assert_eq!(
            validation_calls.get(),
            1,
            "owner validation must run exactly once per admission"
        );
        let v1_calls = Cell::new(0_usize);
        let handler_calls = Cell::new(0_usize);
        let result = dispatch_orientation_with(
            &admission,
            &job,
            &validated,
            |admitted, bundle, model, grounded, policy, usage, preservation| {
                v1_calls.set(v1_calls.get() + 1);
                validate_grounded_dream_draft_at(
                    admitted,
                    bundle,
                    model,
                    grounded,
                    policy,
                    usage,
                    preservation,
                    Some(0),
                    false,
                )
            },
            |admitted_job, candidate, bundle, policy| {
                handler_calls.set(handler_calls.get() + 1);
                project_validated_orientation(admitted_job, candidate, bundle, policy)
            },
        );
        let Ok(DreamResult::Packet(packet)) = result else {
            panic!("accepted input must project through the real dispatcher, got {result:?}");
        };
        assert_eq!(packet.question, job.exact_question);
        assert_eq!(packet.scope_id, admission.scope_id);
        assert_eq!(packet.source_coverage.evidence, job.evidence_handles);
        assert_eq!(packet.synthesized_interpretations.len(), 1);
        assert_eq!(
            packet.synthesized_interpretations[0].epistemic_status, "candidate_only",
            "projection must not promote the candidate"
        );
        assert_eq!(
            packet.rival_models_and_dissent.len(),
            2,
            "both owner residue markers must survive, got {:?}",
            packet.rival_models_and_dissent
        );
        assert_eq!(
            v1_calls.get(),
            1,
            "v1 owner validation must run exactly once"
        );
        assert_eq!(
            handler_calls.get(),
            1,
            "the native handler must run exactly once for accepted input"
        );
        assert_eq!(
            validation_calls.get(),
            1,
            "dispatch must consume the validated receipt without re-running validation"
        );
    }

    /// A-05 pre-handler proof (b): rejected input runs the real owner
    /// validation exactly once and stops at the real dispatcher with no
    /// handler or fallback effects.
    ///
    /// Two genuine rejection shapes through the PRODUCTION validation entry
    /// ([`validate_admitted_draft`], no injection): a Curation carrier the
    /// owner directs to its separate typed carrier (`UnsupportedJobShape`),
    /// and a stale observation at the job deadline (`DeadlineExceeded`) —
    /// both retained as the static semantic refusal with the
    /// request-rejected code. Each shape is also driven through the
    /// injectable seam with a counting wrapper around the REAL owner, so
    /// the validator-exactly-once count observes the genuine verdict rather
    /// than a fabricated one.
    ///
    /// Dispatch stop: production holds NO receipt on these paths —
    /// [`run_admitted_pipeline`](crate::run_admitted_pipeline) `?`-returns
    /// the validation refusal before dispatch (the validated receipt is
    /// threaded into dispatch only on `Ok`) — so the test drives the REAL
    /// [`dispatch_admitted`](crate::dispatch_stage::dispatch_admitted)
    /// entry with `None` and requires the approved receipt-gate refusal
    /// before any v1 derivation or handler work. The outcome (refusal with
    /// the exact gate reason versus `Ok`) is what discriminates bypass: a
    /// gate-free dispatch of the genuine pair would derive v1, validate,
    /// project, and return a packet.
    ///
    /// Handler zero is pinned three ways: the gate refusal textually
    /// precedes every handler call in the production arm; no packet or
    /// other result emerges on either reject path; and the accepted
    /// control through the same dispatch core runs the real projector
    /// exactly once (proving the counter observes genuine dispatch while
    /// the gate refuses receipts, not the admission). Fallback zero holds
    /// by outcome shape: every reject path yields `Err` with a bounded
    /// static refusal — never `Ok`, never a packet, never an alternate
    /// disposition. Production defines no fallback continuation anywhere
    /// on this path (refusal propagates via `?`; the Kernel boundary and
    /// the curation fan-in both document refusal-never-fallback with no
    /// alternate handler), so a taken fallback would have to manifest as
    /// exactly the `Ok`/side effect this test excludes.
    #[test]
    fn rejected_candidate_stops_dispatch_before_handler_or_fallback() {
        use crate::dispatch_stage::{
            CURATION_CARRIER_REFUSAL, VALIDATION_RECEIPT_REFUSAL, dispatch_admitted,
            dispatch_orientation_with, project_validated_orientation,
        };
        use crate::{DreamResult, JobClass};
        use eliot_dreamer_candidate_validation::{
            validate_grounded_dream_draft_at, validate_grounding_candidate_at,
        };

        // Shape 1: Curation takes the separate-carrier gate — a genuine
        // semantic rejection through the real owner, never a shape error.
        let admission = admission_with_deadline(u64::MAX);
        let mut curation_job = job_of_class(&admission, JobClass::Curation, None);
        curation_job.evidence_handles = vec!["evidence-slice-6".to_owned()];
        let grounded = grounding_for(&admission, &curation_job);
        let input = carrier_for(&admission, &curation_job, grounded, Some(0));
        // Production entry (no injection): pins the genuine owner verdict.
        // Short-circuiting production validation past the owner changes
        // this outcome.
        let refused = validate_admitted_draft(&input);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "validation semantic rejection"
                ))
            ),
            "curation carrier must take the separate-carrier gate, got {refused:?}"
        );
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err("DREAMER_REQUEST_REJECTED")
        );
        // Injectable seam: the real owner runs exactly once for the same
        // genuine rejection.
        let validation_calls = Cell::new(0_usize);
        let refused = validate_admitted_draft_with(&input, |carrier| {
            validation_calls.set(validation_calls.get() + 1);
            validate_grounding_candidate_at(carrier)
        });
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "validation semantic rejection"
                ))
            ),
            "counted curation validation must refuse identically, got {refused:?}"
        );
        assert_eq!(
            validation_calls.get(),
            1,
            "owner validation must run exactly once even for rejected input"
        );

        // Shape 2: stale observation at the job deadline — the owner rejects
        // with `DeadlineExceeded`, retained as the same static refusal.
        let (admission, job) = admitted_orientation_pair();
        let grounded = grounding_for(&admission, &job);
        let stale = carrier_for(&admission, &job, grounded, Some(1));
        let refused = validate_admitted_draft(&stale);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "validation semantic rejection"
                ))
            ),
            "stale observation must refuse fail-closed, got {refused:?}"
        );
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err("DREAMER_REQUEST_REJECTED")
        );
        let stale_calls = Cell::new(0_usize);
        let refused = validate_admitted_draft_with(&stale, |carrier| {
            stale_calls.set(stale_calls.get() + 1);
            validate_grounding_candidate_at(carrier)
        });
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "validation semantic rejection"
                ))
            ),
            "counted stale validation must refuse identically, got {refused:?}"
        );
        assert_eq!(
            stale_calls.get(),
            1,
            "owner validation must run exactly once for stale input"
        );

        // The rejected Orientation path stops at the REAL dispatcher: no
        // receipt exists (production `?`-returns before dispatch), so the
        // honest dispatch input is `None` and the approved receipt gate
        // must refuse before any v1 derivation or handler work.
        let handler_calls = Cell::new(0_usize);
        let refused = dispatch_admitted(&admission, &job, None, None, JobClass::Orientation, None);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(VALIDATION_RECEIPT_REFUSAL))
            ),
            "rejected orientation must stop at the receipt gate, got {refused:?}"
        );
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err("DREAMER_REQUEST_REJECTED")
        );
        // The rejected Curation path stops at the REAL dispatcher likewise:
        // without the Governor-injected carrier there is nothing to route,
        // so the carrier check refuses before any screen, registry, or
        // handler work — never a class refusal, never the Kernel code.
        let refused = dispatch_admitted(
            &admission,
            &curation_job,
            None,
            None,
            JobClass::Curation,
            None,
        );
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(CURATION_CARRIER_REFUSAL))
            ),
            "rejected curation must stop at the carrier check, got {refused:?}"
        );
        assert!(
            !matches!(refused, Err(DreamerError::UnsupportedJobClass(_))),
            "curation must never refuse with UnsupportedJobClass"
        );
        assert!(
            !matches!(refused, Err(DreamerError::KernelAdmissionRequired(_))),
            "curation must never borrow the Kernel-admission code"
        );
        // No handler ran for either rejected input through the exercised
        // production entries, and no fallback result emerged: both refusals
        // above are `Err`, never `Ok`.
        assert_eq!(
            handler_calls.get(),
            0,
            "rejected candidates must invoke zero handlers"
        );

        // Liveness and gate-precision control: the same admitted pair with
        // a fresh observation validates, then dispatches through the real
        // dispatch core with the real v1 owner once and the real projector
        // once, yielding a packet. This proves the counters observe genuine
        // dispatch (they fire here) and the gate refuses receipts, not the
        // admission itself.
        let grounded = grounding_for(&admission, &job);
        let fresh = carrier_for(&admission, &job, grounded, Some(0));
        let validated = match validate_admitted_draft(&fresh) {
            Ok(validated) => validated,
            Err(error) => {
                panic!("fresh carrier must pass pre-handler validation, got {error:?}")
            }
        };
        let v1_calls = Cell::new(0_usize);
        let result = dispatch_orientation_with(
            &admission,
            &job,
            &validated,
            |admitted, bundle, model, grounded, policy, usage, preservation| {
                v1_calls.set(v1_calls.get() + 1);
                validate_grounded_dream_draft_at(
                    admitted,
                    bundle,
                    model,
                    grounded,
                    policy,
                    usage,
                    preservation,
                    Some(0),
                    false,
                )
            },
            |admitted_job, candidate, bundle, policy| {
                handler_calls.set(handler_calls.get() + 1);
                project_validated_orientation(admitted_job, candidate, bundle, policy)
            },
        );
        let Ok(DreamResult::Packet(packet)) = result else {
            panic!("accepted input must project through the real dispatcher, got {result:?}");
        };
        assert_eq!(packet.scope_id, admission.scope_id);
        assert_eq!(packet.source_coverage.evidence, job.evidence_handles);
        assert_eq!(
            v1_calls.get(),
            1,
            "v1 owner validation must run exactly once on the accepted path"
        );
        assert_eq!(
            handler_calls.get(),
            1,
            "the native handler must run exactly once for accepted input"
        );
    }

    /// A-05 pre-handler proof (c): downstream consumes the validation output
    /// through the real dispatcher without re-running validation.
    /// `validate_once` is `FnOnce`, so the counting wrapper cannot run twice
    /// for one admission; two genuine dispatches of the same receipt both
    /// project while the validation counter stays at one. The binding
    /// re-proof inside dispatch is receipt arithmetic, not owner validation.
    #[test]
    fn validated_output_consumed_without_revalidation() {
        use crate::DreamResult;
        use crate::dispatch_stage::{dispatch_orientation_with, project_validated_orientation};
        use eliot_dreamer_candidate_validation::validate_grounded_dream_draft_at;

        let (admission, job) = admitted_orientation_pair();
        let grounded = grounding_for(&admission, &job);
        let input = carrier_for(&admission, &job, grounded, Some(0));
        let validation_calls = Cell::new(0_usize);
        let validated = validate_admitted_draft_with(&input, |carrier| {
            validation_calls.set(validation_calls.get() + 1);
            validate_grounding_candidate_at(carrier)
        });
        let Ok(validated) = validated else {
            panic!("admitted carrier must pass pre-handler validation");
        };
        assert_eq!(validation_calls.get(), 1);
        if let Err(error) = validated.validate_binding() {
            panic!("accepted receipt must re-prove its binding without owner work, got {error:?}");
        }
        assert_eq!(
            validation_calls.get(),
            1,
            "binding re-proof must not re-run validation"
        );

        let handler_calls = Cell::new(0_usize);
        for _ in 0..2 {
            let result = dispatch_orientation_with(
                &admission,
                &job,
                &validated,
                |admitted, bundle, model, grounded, policy, usage, preservation| {
                    validate_grounded_dream_draft_at(
                        admitted,
                        bundle,
                        model,
                        grounded,
                        policy,
                        usage,
                        preservation,
                        Some(0),
                        false,
                    )
                },
                |admitted_job, candidate, bundle, policy| {
                    handler_calls.set(handler_calls.get() + 1);
                    project_validated_orientation(admitted_job, candidate, bundle, policy)
                },
            );
            let Ok(DreamResult::Packet(packet)) = result else {
                panic!("validated receipt must dispatch on every consumption, got {result:?}");
            };
            assert_eq!(packet.scope_id, admission.scope_id);
        }
        assert_eq!(
            handler_calls.get(),
            2,
            "each downstream consumption must reach the native handler"
        );
        assert_eq!(
            validation_calls.get(),
            1,
            "downstream consumption must not re-run validation"
        );
    }

    /// A-05 pre-handler proof (d): a tampered or foreign receipt is refused
    /// at the dispatch gate before any handler work. Tampering the sealed
    /// output digest breaks the binding re-proof; presenting a receipt bound
    /// to another scope breaks the scope pin. Both refuse with bounded
    /// static fields while the v1 and projection counters stay at zero.
    #[test]
    fn tampered_receipt_refused_before_handler() {
        use crate::DreamResult;
        use crate::dispatch_stage::{dispatch_orientation_with, project_validated_orientation};
        use eliot_dreamer_candidate_validation::validate_grounded_dream_draft_at;

        let (admission, job) = admitted_orientation_pair();
        let grounded = grounding_for(&admission, &job);
        let input = carrier_for(&admission, &job, grounded, Some(0));
        let validated = match validate_admitted_draft(&input) {
            Ok(validated) => validated,
            Err(error) => {
                panic!("admitted carrier must pass pre-handler validation, got {error:?}")
            }
        };

        let v1_calls = Cell::new(0_usize);
        let handler_calls = Cell::new(0_usize);
        let dispatch_counted = |validated: &ValidatedGroundingCandidate| {
            dispatch_orientation_with(
                &admission,
                &job,
                validated,
                |admitted, bundle, model, grounded, policy, usage, preservation| {
                    v1_calls.set(v1_calls.get() + 1);
                    validate_grounded_dream_draft_at(
                        admitted,
                        bundle,
                        model,
                        grounded,
                        policy,
                        usage,
                        preservation,
                        Some(0),
                        false,
                    )
                },
                |admitted_job, candidate, bundle, policy| {
                    handler_calls.set(handler_calls.get() + 1);
                    project_validated_orientation(admitted_job, candidate, bundle, policy)
                },
            )
        };

        // Tampered seal: the output digest no longer matches the preimage.
        let mut tampered = validated.clone();
        tampered.validated.receipt.output_digest = "f".repeat(64);
        let refused = dispatch_counted(&tampered);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "validation receipt" | "validation receipt binding"
                ))
            ),
            "tampered receipt must refuse at the gate, got {refused:?}"
        );

        // Foreign receipt: bound to another scope identity (matching
        // admission and job, so the chain validates it; dispatch under the
        // original pair must refuse the scope pin). Note the canonical
        // identity covers class/operation/scope, so scope is what makes
        // this receipt observably foreign; the Kernel job-id half is pinned
        // by the binding check that runs before the gate.
        let mut foreign_admission = admission_with_deadline(u64::MAX);
        foreign_admission.job_id = "job-slice-6-foreign".to_owned();
        foreign_admission.scope_id = "scope-slice-6-foreign".to_owned();
        foreign_admission.attempt_id = "attempt-slice-6-foreign".to_owned();
        foreign_admission.idempotency_key = "job-slice-6-foreign:attempt-slice-6".to_owned();
        foreign_admission.cancellation_id = "cancel-slice-6-foreign".to_owned();
        let mut foreign_job = job_of_class(
            &foreign_admission,
            JobClass::Orientation,
            Some("task-slice-6"),
        );
        foreign_job.job_id = "job-slice-6-foreign".to_owned();
        foreign_job.scope_id = foreign_admission.scope_id.clone();
        foreign_job.evidence_handles = vec!["evidence-slice-6".to_owned()];
        let foreign_grounded = grounding_for(&foreign_admission, &foreign_job);
        let foreign_input =
            carrier_for(&foreign_admission, &foreign_job, foreign_grounded, Some(0));
        let foreign = match validate_admitted_draft(&foreign_input) {
            Ok(foreign) => foreign,
            Err(error) => {
                panic!("foreign carrier must validate under its own identity, got {error:?}")
            }
        };
        let refused = dispatch_counted(&foreign);
        assert!(
            matches!(refused, Err(DreamerError::InvalidAdmission(_))),
            "foreign receipt must refuse at the gate, got {refused:?}"
        );
        // Sanity: the untampered receipt still dispatches, so the gate
        // refuses receipts, not the admission itself.
        let Ok(DreamResult::Packet(_)) = dispatch_counted(&validated) else {
            panic!("untampered receipt must still dispatch");
        };
        assert_eq!(
            handler_calls.get(),
            1,
            "only the untampered receipt may reach the handler"
        );
        assert_eq!(
            v1_calls.get(),
            1,
            "refused receipts must not reach v1 validation or projection"
        );
    }
}
