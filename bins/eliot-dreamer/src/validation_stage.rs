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
//! reaches validation. Non-Curation refused classes never reach this seam
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
//!   (the Kernel-owned typed fence plus the semantic fence string) and are
//!   never collapsed into a single literal fence string.
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
//! - G5: Governor-record sourcing host-side for admitted drafts and
//!   positions. Positions and the draft are never synthesized locally:
//!   resolution fail-closes until the Governor-resolved material arrives
//!   through a source-owner port, because locally built material would be
//!   self-issued authority.

use eliot_dreamer_candidate_validation::{
    DreamDraftValidationError, validate_grounding_candidate_at,
};
use eliot_dreamer_contracts::JobClass;

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
    /// Admitted non-Orientation classes (`ResearchSynthesis`, `Maintenance`):
    /// no per-class validation shape yet.
    OtherAdmitted,
}

/// Resolves the A-05 validation inputs for one admitted job.
///
/// Fails closed: any invalid/stale admission or identity mismatch refuses here
/// with zero owner-validation calls, and refused classes refuse with
/// [`DreamerError::UnsupportedJobClass`]. Admitted classes map to
/// [`ValidationInputs`] (Orientation through the G1 split) and then still
/// fail closed with the Governor-material refusal, because the
/// Governor-resolved draft and epistemic positions arrive through a
/// source-owner port in a later slice; until then resolution refuses rather
/// than synthesizing draft material (G5).
pub(crate) fn resolve_validation_inputs(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<ValidationInputs, DreamerError> {
    let _inputs = map_admitted_inputs(admission, job)?;
    Err(DreamerError::InvalidAdmission(
        "admitted validation inputs require Governor-resolved draft and positions",
    ))
}

/// Maps one admitted job to its validation inputs after the binding check.
///
/// Pure mapping step of [`resolve_validation_inputs`]: binding first, then
/// the closed class match (admitted classes map, refused classes refuse), so
/// the G1 split is observable and testable ahead of the G5 material gate.
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
        JobClass::ResearchSynthesis | JobClass::Maintenance => Ok(ValidationInputs::OtherAdmitted),
        JobClass::Curation
        | JobClass::Clarification
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
/// around real owner validation to prove the once-per-admission call shape.
#[allow(
    dead_code,
    reason = "wired by submit once the Governor-material slice supplies the validated draft"
)]
pub(crate) fn validate_admitted_draft_with(
    inputs: &ValidationInputs,
    validate_once: impl FnOnce(&ValidationInputs) -> Result<(), DreamDraftValidationError>,
) -> Result<(), DreamerError> {
    validate_once(inputs).map_err(|error| validation_denied(&error))
}

/// Production entry: the real A-05 owner validation, once per admission.
///
/// Wires [`validate_grounding_candidate_at`] as the `FnOnce` body: the
/// function item is referenced here so the wiring is exact at compile time
/// (an owner rename breaks this build), and the call itself runs once the
/// Governor-resolved draft port lands. Until then (G5) the body fail-closes
/// instead of synthesizing draft material, so this entry is unreachable while
/// [`resolve_validation_inputs`] still waits for governed material.
#[allow(
    dead_code,
    reason = "wired by submit once the Governor-material slice supplies the validated draft"
)]
pub(crate) fn validate_admitted_draft(inputs: &ValidationInputs) -> Result<(), DreamerError> {
    validate_admitted_draft_with(inputs, |resolved| {
        let _ = resolved;
        let _ = validate_grounding_candidate_at;
        Err(DreamDraftValidationError::InvalidContract {
            phase: "governor material",
            field: "governor.draft",
        })
    })
}

/// Maps an owner validation refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code: the admission itself was valid, the draft
/// was not. Dynamic payloads (bounds, digests, details) are dropped in favor
/// of the bounded static field names; nothing secret flows.
#[allow(
    dead_code,
    reason = "reached through validate_admitted_draft_with once the Governor-material slice wires it"
)]
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
    use std::sync::atomic::{AtomicU64, Ordering};

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_dreamer_orientation::{
        AnchoredEvidence, OrientationPacketCandidate, OrientationResidue,
    };

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

    fn job_of_class(class: JobClass, task_id: Option<&str>) -> DreamJobInput {
        DreamJobInput {
            job_id: "job-slice-6".to_owned(),
            job_class: class,
            exact_question: "What does ELIOT know about this scope?".to_owned(),
            requester: "test-harness".to_owned(),
            scope_id: "scope-slice-6".to_owned(),
            task_id: task_id.map(str::to_owned),
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

    /// Stale Kernel input fails closed at resolution with zero validation
    /// calls: resolution precedes validation, so there is no validation to
    /// count — the refusal itself is the proof, and it carries the
    /// request-rejected code for a mere stale deadline.
    #[test]
    fn stale_admission_fails_closed_before_any_validation() {
        let admission = admission_with_deadline(1);
        let job = job_of_class(JobClass::Orientation, None);
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
        let mut job = job_of_class(JobClass::Orientation, None);
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
    /// depth if one ever reaches the seam.
    #[test]
    fn refused_classes_return_unsupported_job_class() {
        for class in [
            JobClass::Curation,
            JobClass::Clarification,
            JobClass::ArchitectureSelfQuery,
            JobClass::DevelopmentDiagnosis,
            JobClass::OrchestrationPlanning,
            JobClass::ConfigurationAssistance,
        ] {
            let admission = admission_with_deadline(u64::MAX);
            let job = job_of_class(class, None);
            let refused = resolve_validation_inputs(&admission, &job);
            assert!(
                matches!(refused, Err(DreamerError::UnsupportedJobClass(refused_class)) if refused_class == class),
                "class {class:?} must refuse with UnsupportedJobClass({class:?})"
            );
            let admission = admission_with_deadline(u64::MAX);
            let job = job_of_class(class, None);
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
        let job = job_of_class(JobClass::Orientation, Some("task-slice-6"));
        let mapped = map_admitted_inputs(&admission, &job).expect("admitted class must map");
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

        let job_without_task = job_of_class(JobClass::Orientation, None);
        let mapped = map_admitted_inputs(&admission, &job_without_task)
            .expect("admitted class must map");
        assert!(
            matches!(
                mapped,
                ValidationInputs::OrientationNative {
                    task_id: None,
                    ..
                }
            ),
            "an absent task must stay absent, got {mapped:?}"
        );
    }

    /// Other admitted classes map to the shared arm with no per-class shape.
    #[test]
    fn other_admitted_classes_map_to_shared_arm() {
        for class in [JobClass::ResearchSynthesis, JobClass::Maintenance] {
            let admission = admission_with_deadline(u64::MAX);
            let job = job_of_class(class, None);
            assert!(
                matches!(
                    map_admitted_inputs(&admission, &job),
                    Ok(ValidationInputs::OtherAdmitted)
                ),
                "class {class:?} must map to the shared admitted arm"
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
        let mut first = job_of_class(JobClass::Orientation, Some("task-slice-6"));
        first.evidence_handles = vec!["evidence-a".to_owned()];
        first.architecture_handles = vec!["architecture-a".to_owned()];
        first.allowed_model_routes = vec!["route-a".to_owned()];
        let mut second = job_of_class(JobClass::Orientation, Some("task-slice-6"));
        second.evidence_handles = vec!["evidence-b".to_owned(), "evidence-c".to_owned()];
        second.architecture_handles = vec!["architecture-b".to_owned()];
        second.allowed_model_routes = vec!["route-b".to_owned(), "route-c".to_owned()];
        let first_mapped =
            map_admitted_inputs(&admission, &first).expect("admitted class must map");
        let second_mapped =
            map_admitted_inputs(&admission, &second).expect("admitted class must map");
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
            candidate_path,
            "eliot_dreamer_orientation::projection::OrientationPacketCandidate",
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

    /// G5: a valid admission with matching identity reaches the governed
    /// material gate. Resolution names the missing Governor-resolved draft
    /// and positions instead of synthesizing them, and the production entry
    /// fail-closes the same way with the request-rejected code.
    #[test]
    fn valid_admission_waits_for_governed_material_g5() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_of_class(JobClass::Orientation, Some("task-slice-6"));
        let refused = resolve_validation_inputs(&admission, &job);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(
                    "admitted validation inputs require Governor-resolved draft and positions"
                ))
            ),
            "valid input must wait for governed material, got {refused:?}"
        );
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err("DREAMER_REQUEST_REJECTED")
        );

        let inputs = map_admitted_inputs(&admission, &job).expect("admitted class must map");
        let refused = validate_admitted_draft(&inputs);
        let Err(error) = refused else {
            panic!("production validation without governed draft must refuse");
        };
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert!(
            !matches!(error, DreamerError::KernelAdmissionRequired(_)),
            "material refusal must not borrow the Kernel-admission code"
        );
    }

    /// The owner validation runs exactly once per admitted admission: one
    /// counting wrapper, one refused input, one call, one typed fail-closed
    /// refusal with the request-rejected code.
    #[test]
    fn owner_validation_runs_exactly_once_per_admission() {
        let inputs = ValidationInputs::OrientationNative {
            scope_id: "scope-slice-6".to_owned(),
            task_id: Some("task-slice-6".to_owned()),
            operation_id: "request-slice-6".to_owned(),
        };
        let calls = AtomicU64::new(0);
        let refused = validate_admitted_draft_with(&inputs, |resolved| {
            assert_eq!(resolved, &inputs, "owner must see the resolved inputs");
            calls.fetch_add(1, Ordering::SeqCst);
            Err(DreamDraftValidationError::InvalidContract {
                phase: "structured shape",
                field: "structured.schema_version",
            })
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
}
