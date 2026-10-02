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
//! bundle plan, then
//! [`resolve_model_inputs`](crate::model_stage::resolve_model_inputs) /
//! [`run_admitted_model`](crate::model_stage::run_admitted_model) /
//! [`resolve_grounding_inputs`](crate::grounding_stage::resolve_grounding_inputs),
//! then validation here: a refused class returns at dispatch with zero
//! validation work, and a failed controller, bundle, model or grounding stage
//! never reaches validation. Non-admitted refused classes never reach this
//! seam (dispatch already refused them), but resolution still refuses them
//! fail-closed with [`DreamerError::UnsupportedJobClass`] if they do.
//!
//! [`resolve_validation_inputs`] is a fail-closed gate in production and
//! nothing more. It has exactly ONE production caller, which discards the
//! mapped value (`lib.rs` binds it to `_validation`); the end-to-end pipeline
//! proof is `#![cfg(test)]` and binds it to `_inputs`, so it is a test caller
//! and not a second production one. No downstream stage reads `scope_id`,
//! `task_id` or `operation_id` off [`ValidationInputs`], so the G1 split is
//! observable and testable here but is not currently an effect on any later
//! stage; the identity the owner validates arrives inside the
//! Governor-resolved [`GroundingValidationInput`] instead.
//!
//! Slice B adaptations:
//!
//! - G1: scope/state-fence split. Mapping returns `scope_id`, `task_id`, and
//!   `operation_id` plus fences as separate bindings. Mapping takes `scope_id`
//!   from the Kernel admission (equal to the job scope by binding — an equality
//!   [`verify_admitted_binding`](crate::controller::verify_admitted_binding)
//!   requires, so the provenance of that field is not falsifiable here),
//!   `task_id` from [`DreamJobInput::task_id`], and `operation_id` from
//!   [`KernelJobAdmission::request_id`] — the Kernel-issued per-claim
//!   correlation identity — preferring it over `task_id`, which names the
//!   semantic task in a different namespace and may be absent. Fences stay
//!   bound through the same check (the admitted typed fence, proved equal on
//!   the Kernel and semantic sides) and are never collapsed into a single
//!   literal fence string.
//! - G2: VACUOUS at this seam. This module consumes no Orientation candidate
//!   at all, in production or in tests, so there is no 15-key YAML parse here
//!   and no native-struct alternative here either: nothing is parsed because
//!   nothing is read. The G2 question is not decided in this file.
//! - G3: VACUOUS at this seam, for the same reason. No
//!   `anchored_evidence_by_status` vector is read, carried, or regrouped by
//!   status here, because no candidate is read here.
//! - G4: VACUOUS at this seam, for the same reason. No
//!   `architecture_implications` or `model_routes_and_cost` marker passes
//!   through here, so no marker can be dropped or thinned here.
//! - G5: the A-14b -> A-05 carrier is owned by the grounding crate, not built
//!   here. This stage supplies only the A-05 data the owner cannot know
//!   ([`ValidationAttachment`]: policy, usage, preservation, the
//!   CALLER-SUPPLIED observation time, the ASSERTED cancellation negative, and
//!   the absent rival declarations, derived in
//!   [`admitted_material`](crate::admitted_material)) and calls the single
//!   production owner entry
//!   [`ground_and_bind_validation_carrier`] -> [`ground_for_validation`],
//!   which grounds the draft through this crate's own production grounding and
//!   constructs the [`GroundingValidationInput`] at the owner's one
//!   construction site. A grounding refusal the owner collapsed back to one
//!   static is mapped through the composition's own exhaustive refusal table
//!   ([`handoff_denied`]) so no refusal class is lost in translation. This root
//!   never constructs a carrier and never
//!   restates the grounded leg's identity, scope, fence, or task joins. The
//!   result is passed to [`validate_admitted_draft`]. Resolution itself maps
//!   admitted classes directly with no material gate: nothing is synthesized
//!   here, and the owner decides acceptance on the supplied carrier.

use eliot_dreamer_candidate_validation::{
    DreamDraftValidationError, StructuredCandidateValidationOutcome,
    validate_grounding_candidate_at,
};
use eliot_dreamer_claim_grounding::{
    GroundingRequest, GroundingValidationRequest, ValidationAttachment, ground_draft_with_controls,
    ground_for_validation,
};
use eliot_dreamer_contracts::grounding::GroundedDreamDraft;
use eliot_dreamer_contracts::validation::structured::{
    GroundingValidationInput, ValidatedGroundingCandidate,
};
use eliot_dreamer_contracts::{ContractViolation, JobClass};

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
///
/// In production the mapped value is DISCARDED by the one production caller
/// (`lib.rs` binds it to `_validation`); the end-to-end pipeline proof is
/// `#![cfg(test)]` and binds it to `_inputs`. No downstream stage reads
/// `scope_id`, `task_id` or `operation_id` off it, so the observable production
/// effect of this function is the fail-closed `?` and nothing else. The G1
/// split below is proved here in this file's tests, not asserted as an effect
/// on a later stage.
pub(crate) fn resolve_validation_inputs(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<ValidationInputs, DreamerError> {
    map_admitted_inputs(admission, job)
}

/// Maps one admitted job to its validation inputs after the binding check.
///
/// Pure mapping step of [`resolve_validation_inputs`], which adds nothing to it:
/// binding first, then the closed class match (admitted classes map, refused
/// classes refuse).
///
/// The read set is exactly four fields — `admission.scope_id`,
/// `admission.request_id`, `job.job_class` and `job.task_id` — and the returned
/// value carries no payload field. Every other field of either input is unread,
/// which is the shape-agnostic property this module's tests pin (see
/// `seam_mapping_reads_only_class_and_task` in the test module below).
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

/// Production entry for the A-14b -> A-05 handoff, once per admission.
///
/// `handoff_once` is `FnOnce`: the owner handoff consumes its request by value
/// and cannot run twice for one admission through this seam. Production passes
/// [`ground_for_validation`]; deterministic tests pass a counting wrapper
/// around the real owner entry to prove the once-per-admission call shape.
///
/// Wiring and contract construction only, per `bins/AGENTS.md`: the grounded
/// leg, the carrier construction, and the candidate-only refusal all belong to
/// the owning crate, so this function supplies the two independently owned
/// inputs and maps the owner's typed outcome. A refusal is never softened
/// into a default, an empty carrier, or a success — see
/// [`ground_and_bind_validation_carrier`].
///
/// The seam retains its own request so a refusal the owner collapsed can still
/// be named precisely; see [`handoff_denied`]. The owner consumes its request
/// by value, so the retention is a clone, and the grounding it performs is
/// never run on the retained copy unless the handoff has already refused.
///
/// `recover_grounding` is the grounding function the refusal-recovery path
/// re-runs, supplied separately from the handoff so a caller can observe every
/// GROUNDING ENTRY this seam makes into an injected grounding closure, rather
/// than only every handoff entry. That is the whole of what the entry counter
/// sees, and the honest limit is symmetric on both sides: a grounding this seam
/// performed by calling
/// [`ground_admitted_draft_with`](crate::grounding_stage::ground_admitted_draft_with)
/// with an owner grounding it invoked directly, rather than through the
/// injected closure, would ground while the counter stayed where it is. The
/// counter therefore measures entries into injected closures, never groundings
/// performed. Production passes [`ground_draft_with_controls`] there and the
/// real handoff above, so
/// the recovery still runs the owner's own grounding and this root gains no
/// second grounding authority; a proof can wrap the function itself and count
/// grounding entries. It is a second grounding when it fires, and that is
/// deliberate: the count of grounding entries on a refused collapsed handoff is
/// 2, and the count of handoff entries on the same path is 1, so the two are
/// not interchangeable.
pub(crate) fn ground_and_bind_validation_carrier_with(
    grounding: GroundingRequest,
    attachment: ValidationAttachment,
    handoff_once: impl FnOnce(
        GroundingValidationRequest,
    ) -> Result<GroundingValidationInput, DreamDraftValidationError>,
    recover_grounding: impl FnOnce(GroundingRequest) -> Result<GroundedDreamDraft, ContractViolation>,
) -> Result<GroundingValidationInput, DreamerError> {
    let retained = grounding.clone();
    handoff_once(GroundingValidationRequest::new(grounding, attachment))
        .map_err(|error| handoff_denied(&error, &retained, recover_grounding))
}

/// The owner's grounding phase name, as passed to its own `summarize_contract`.
const GROUNDING_PHASE: &str = "claim grounding";

/// The single static the owner's `summarize_contract` reduces six refusal
/// classes to.
const COLLAPSED_CONTRACT_FIELD: &str = "contract";

/// Maps the owner handoff's refusal, naming the precise grounding refusal the
/// owner collapsed.
///
/// The owning crate reduces a `ContractViolation` through its own
/// `summarize_contract` before this composition ever sees it, and that
/// reduction maps `CrossStage`, `KindPayload`, `Registry`, `ScreenIneligible`,
/// `Preservation`, and `ForbiddenCarry` onto the single static `"contract"`
/// (`eliot_dreamer_contracts::validation::error::summarize_contract`). Six
/// distinguishable refusals would therefore leave this root indistinguishable,
/// which is strictly less than the owner decided, so this mapping recovers
/// them: when — and only when — the refusal is exactly that collapsed
/// grounding refusal, the same pure owner grounding is re-run over the request
/// this seam already retains, through the composition's own grounding seam
/// ([`ground_admitted_draft_with`](crate::grounding_stage::ground_admitted_draft_with)),
/// so the precise bounded static its exhaustive
/// [`grounding_denied`](crate::grounding_stage::grounding_denied) table assigns
/// is what this root reports. No second table and no new error variant is
/// introduced for that.
///
/// The recovery is fail-closed in both directions. It cannot mint a refusal the
/// owner did not raise, because a re-run that succeeds keeps the owner's own
/// field; and it cannot soften one, because the re-run is the owner's own pure
/// grounding over the owner's own retained request. Every other refusal — the
/// ceiling refusal, the carrier's own contract validation, an encoding or bound
/// failure — keeps [`validation_denied`] unchanged.
///
/// A recovery that fails with a refusal class other than
/// [`DreamerError::InvalidAdmission`] is returned to the caller unchanged
/// rather than being replaced by the collapsed static. That class is
/// unreachable today, because
/// [`grounding_denied`](crate::grounding_stage::grounding_denied) is exhaustive
/// and maps every `ContractViolation` to `InvalidAdmission`; the arm exists so
/// that a refusal the recovery did produce is never silently discarded and
/// reported as the owner's collapsed field instead.
fn handoff_denied(
    error: &DreamDraftValidationError,
    retained: &GroundingRequest,
    recover_grounding: impl FnOnce(GroundingRequest) -> Result<GroundedDreamDraft, ContractViolation>,
) -> DreamerError {
    let DreamDraftValidationError::InvalidContract { phase, field } = error else {
        return validation_denied(error);
    };
    if *phase != GROUNDING_PHASE || *field != COLLAPSED_CONTRACT_FIELD {
        return validation_denied(error);
    }
    match crate::grounding_stage::ground_admitted_draft_with(retained.clone(), recover_grounding) {
        Err(DreamerError::InvalidAdmission(precise)) => DreamerError::InvalidAdmission(precise),
        Err(other) => other,
        Ok(_) => validation_denied(error),
    }
}

/// Production entry: the real owner handoff, once per admission.
///
/// Wires [`ground_for_validation`] as the `FnOnce` body. That entry grounds the
/// supplied A03 v2 context through the owner's own production grounding and
/// then binds the A-05 carrier at the owner's single construction site, so the
/// carrier this function returns was built by its owner rather than by this
/// composition root.
///
/// The owner's authority ceiling is preserved on this path and cannot be
/// bypassed through it. A grounded value whose own retained records claim an
/// epistemic position above the candidate-only ceiling is refused by the owner
/// before any carrier exists; the typed refusal is mapped fail-closed here
/// through the same [`validation_denied`] the A-05 gate uses, so it keeps the
/// request-rejected code and can never arrive as a fabricated default or an
/// empty success. The root neither inspects nor repairs the grounded leg, so
/// it has no way to launder a self-certified record into a validated carrier.
///
/// Refusal precision is preserved here too: a grounding refusal the owner
/// collapsed to one static is mapped through the composition's exhaustive
/// table by [`handoff_denied`], so the six classes the owner reduces stay six
/// distinguishable refusals on this path.
pub(crate) fn ground_and_bind_validation_carrier(
    grounding: GroundingRequest,
    attachment: ValidationAttachment,
) -> Result<GroundingValidationInput, DreamerError> {
    ground_and_bind_validation_carrier_with(
        grounding,
        attachment,
        ground_for_validation,
        ground_draft_with_controls,
    )
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
///
/// One mapping serves both owner calls on this path — the A-14b -> A-05 handoff
/// and the A-05 gate itself — because both refuse with the same typed error and
/// neither may be softened on its way out. Sharing it keeps a second, laxer
/// refusal mapping from appearing beside the first.
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

    /// Resolves one admitted job, panicking on refusal: the admitted-path tests
    /// below only exercise classes that must resolve, so a refusal is a test
    /// failure rather than a case to branch on. Every admitted-path assertion in
    /// this module goes through the public entry
    /// [`resolve_validation_inputs`], not the private mapping step, so the
    /// wrapper is covered once rather than twice.
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
    ///
    /// Only `operation_id` is a DISCRIMINATING provenance claim here, and it
    /// discriminates through the `assert_ne!` below: operation comes from the
    /// Kernel admission correlation (`request_id`) and is never the semantic
    /// task.
    ///
    /// `scope_id` provenance is UNFALSIFIABLE on this fixture and is therefore
    /// not claimed: [`verify_admitted_binding`] requires
    /// `admission.scope_id == job.scope_id`, so reading either side yields the
    /// same string and no assertion here can tell them apart. `task_id`
    /// provenance is likewise not a discriminator between two sources — the
    /// admission carries no task field at all — but the ABSENCE case below is
    /// real: a job naming no task must map to `None` rather than to an invented
    /// or borrowed value.
    #[test]
    fn orientation_g1_mapping_splits_scope_task_operation() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_of_class(&admission, JobClass::Orientation, Some("task-slice-6"));
        let mapped = must_resolve(&admission, &job);
        assert_eq!(
            mapped,
            ValidationInputs::OrientationNative {
                scope_id: "scope-slice-6".to_owned(),
                task_id: Some("task-slice-6".to_owned()),
                operation_id: "request-slice-6".to_owned(),
            }
        );
        let ValidationInputs::OrientationNative { operation_id, .. } = mapped else {
            panic!("Orientation must map to its native split");
        };
        assert_eq!(operation_id, admission.request_id);
        assert_ne!(
            operation_id, "task-slice-6",
            "operation must be the Kernel correlation, not the semantic task"
        );

        let job_without_task = job_of_class(&admission, JobClass::Orientation, None);
        let mapped = must_resolve(&admission, &job_without_task);
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
                    resolve_validation_inputs(&admission, &job),
                    Ok(ValidationInputs::OtherAdmitted)
                ),
                "class {class:?} must map to the shared admitted arm"
            );
        }
    }

    /// THE SOLE test of the public wrapper [`resolve_validation_inputs`]: a valid
    /// admission with matching identity resolves without any Governor-material
    /// gate, because the Governor-resolved carrier arrives as the parameter to
    /// [`validate_admitted_draft`].
    ///
    /// The neighbouring tests assert what the mapping step produces, so this one
    /// earns its place by covering the ENTRY the production callers actually
    /// call. It does not re-assert the G1 field provenance — see
    /// [`orientation_g1_mapping_splits_scope_task_operation`] for what is and is
    /// not discriminating there — or the shared-arm class set, which those tests
    /// already own; it asserts that the wrapper adds no gate of its own and
    /// returns the mapped inputs unchanged.
    #[test]
    fn admitted_resolution_returns_mapped_inputs() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_of_class(&admission, JobClass::Orientation, Some("task-slice-6"));
        let resolved = resolve_validation_inputs(&admission, &job);
        assert!(
            matches!(resolved, Ok(ValidationInputs::OrientationNative { .. })),
            "the wrapper must resolve Orientation through its native split, got {resolved:?}"
        );
        let for_other = JobClass::Maintenance;
        let job = job_of_class(&admission, for_other, None);
        assert!(
            matches!(
                resolve_validation_inputs(&admission, &job),
                Ok(ValidationInputs::OtherAdmitted)
            ),
            "the wrapper must resolve a non-Orientation admitted class to the shared arm"
        );
    }

    /// The mapping is shape-agnostic over the job payload, and THAT is the whole
    /// G2/G3/G4 claim available at this seam.
    ///
    /// [`map_admitted_inputs`] reads exactly two fields of the job — `job_class`
    /// and `task_id` — plus `admission.scope_id` and `admission.request_id`, and
    /// [`ValidationInputs`] carries no payload field of any kind. So two jobs
    /// differing only in `evidence_handles`, `architecture_handles` and
    /// `allowed_model_routes` MUST map to identical inputs: those fields are
    /// unread, and there is nowhere in the returned value that could parse,
    /// regroup, drop or rewrite them. The assertion below therefore pins a real
    /// property of the mapping's read set, not a claim about Orientation
    /// candidates: this seam consumes no candidate, so G2, G3 and G4 are vacuous
    /// here. G2 and G4 are decided elsewhere in the crate - G2 at
    /// `production_orientation.rs:600` and G4 at `dispatch_stage.rs:685-686`,
    /// which both consume a packet this seam never builds. G3's flat-vector
    /// shape is not pinned anywhere in this crate: `anchored_evidence_by_status`
    /// appears in this module only in the documentation of the field, never in a
    /// read, so nothing here would go red if that shape changed.
    ///
    /// The identity the mapping DOES read is carried through whole, which is
    /// what the rendered check below shows. No claim is made that the payload
    /// markers themselves are preserved downstream — nothing here can observe
    /// that, because this seam drops them.
    #[test]
    fn seam_mapping_reads_only_class_and_task() {
        let admission = admission_with_deadline(u64::MAX);
        let mut first = job_of_class(&admission, JobClass::Orientation, Some("task-slice-6"));
        first.evidence_handles = vec!["evidence-a".to_owned()];
        first.architecture_handles = vec!["architecture-a".to_owned()];
        first.allowed_model_routes = vec!["route-a".to_owned()];
        let mut second = job_of_class(&admission, JobClass::Orientation, Some("task-slice-6"));
        second.evidence_handles = vec!["evidence-b".to_owned(), "evidence-c".to_owned()];
        second.architecture_handles = vec!["architecture-b".to_owned()];
        second.allowed_model_routes = vec!["route-b".to_owned(), "route-c".to_owned()];
        let first_mapped = must_resolve(&admission, &first);
        let second_mapped = must_resolve(&admission, &second);
        assert_eq!(
            first_mapped, second_mapped,
            "the mapping reads only job_class and task_id, so payload markers cannot affect it"
        );
        let rendered = format!("{first_mapped:?}");
        assert!(
            rendered.contains("scope-slice-6")
                && rendered.contains("task-slice-6")
                && rendered.contains("request-slice-6"),
            "mapped identity must carry scope, task, and operation, got {rendered}"
        );
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
    /// wrong, so the real A-05 owner refuses at `validate_shallow_shape` — its
    /// SECOND check, after `bounds::stream_size(input, "structured.input",
    /// MAX_CANONICAL_BYTES)` (`crates/smart/eliot-dreamer-candidate-validation/src/structured/mod.rs`,
    /// owner call order `stream_size` then `validate_shallow_shape`) — because
    /// this fixture's canonical preimage fits under that ceiling. Every nested
    /// value is only carried, never trusted.
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

    /// Builds a grounding request for the A-14b -> A-05 handoff proofs: the
    /// same carried-only parts as [`carrier_job`], and the retained job's
    /// `frozen_manifest_digest` is empty, so the real owner refuses at
    /// `job.validate` before any claim work. Only carried, never trusted.
    fn handoff_request() -> GroundingRequest {
        let Ok(task_id) = TaskId::new("task-slice-6") else {
            panic!("valid test task");
        };
        let job = carrier_job();
        let bundle = carrier_bundle();
        let manifest = carrier_manifest(task_id.clone());
        let policy = carrier_grounding_policy();
        let draft = carrier_draft(job.clone(), bundle.clone(), task_id);
        GroundingRequest::new(job, bundle, manifest, draft, policy)
    }

    /// Builds the A-05 half the composition root supplies for one admission.
    ///
    /// Carried, never trusted: the owner refuses at grounding on
    /// [`handoff_request`] before any of this reaches carrier construction, so
    /// only the shape matters here. Of the two members the root does not hold,
    /// only `rival_declarations` is recorded as absent rather than filled in,
    /// exactly as
    /// [`validation_attachment_for`](crate::admitted_material::validation_attachment_for)
    /// supplies it: that field admits an absent state and uses it.
    /// `cancellation_requested` is not an absence record here, and is not
    /// described as one: the frozen field is a non-optional `bool`, so it admits
    /// no absent state at all, and the `false` below is the ASSERTED negative
    /// this path carries — the same assertion
    /// [`validation_attachment_for`](crate::admitted_material::validation_attachment_for)
    /// makes, and never a placeholder standing in for an observation this root
    /// could not make. The observation is a carried placeholder for the same
    /// reason and is never read: production measures the attempt's elapsed wall
    /// time through
    /// [`observed_attempt_wall_ms`](crate::admitted_material::observed_attempt_wall_ms).
    fn handoff_attachment() -> ValidationAttachment {
        ValidationAttachment {
            policy: ValidationPolicy::new("policy-slice-6", 1, 1024),
            usage: BudgetUsage::default(),
            preservation: PreservationReport {
                verdicts: Vec::new(),
            },
            observation_time_ms: Some(0),
            cancellation_requested: false,
            rival_declarations: None,
        }
    }

    /// GROUNDING ENTRIES — entries into the injected grounding closures, not
    /// groundings performed — total exactly one per admitted admission, over a
    /// request whose retained job carries an empty frozen manifest digest, which
    /// refuses at the owner with the request-rejected code before any claim work.
    ///
    /// The oracle covers BOTH grounding entries this seam has, because
    /// `handoff_denied`'s refusal-recovery path re-runs the same pure grounding
    /// through the composition's own grounding seam: a count taken only on the
    /// handoff closure reads 1 while a second grounding entry has happened. Both
    /// entries therefore increment ONE counter here.
    ///
    /// Two honest limits, stated rather than papered over, one per side of the
    /// seam:
    ///
    /// - HANDOFF SIDE: the grounding inside [`ground_for_validation`] is the
    ///   owner's own and cannot be intercepted from this crate — the owner's
    ///   carrier binding is `pub(crate)` to it — so this entry is counted at the
    ///   boundary this composition controls.
    /// - RECOVERY SIDE: the counter sees only entries into the injected
    ///   closure. A grounding the seam performed by calling
    ///   [`ground_admitted_draft_with`](crate::grounding_stage::ground_admitted_draft_with)
    ///   with an owner grounding it invoked directly instead of through the
    ///   injected closure would happen while this counter stayed where it is.
    ///
    /// So the unit is ENTRY, and the number 1 below means one entry — not one
    /// grounding proven and not one grounding proven to be the only grounding.
    /// What this count deliberately does NOT assert is that the composition can
    /// never ground twice. This fixture's refusal is not the owner's collapsed
    /// static, so no recovery fires and 1 is the whole truth FOR THIS REQUEST;
    /// [`collapsed_refusal_recovery_is_a_second_visible_grounding_entry`] is the
    /// paired disclosure that a collapsed refusal makes the same count read 2.
    #[test]
    fn grounding_entry_runs_exactly_once_per_admission() {
        let grounding_entries = AtomicU64::new(0);
        let refused = ground_and_bind_validation_carrier_with(
            handoff_request(),
            handoff_attachment(),
            |request| {
                // `ground_for_validation` grounds exactly once, then binds.
                grounding_entries.fetch_add(1, Ordering::SeqCst);
                ground_for_validation(request)
            },
            |request| {
                grounding_entries.fetch_add(1, Ordering::SeqCst);
                ground_draft_with_controls(request)
            },
        );
        assert_eq!(
            grounding_entries.load(Ordering::SeqCst),
            1,
            "this request must produce exactly ONE grounding entry across BOTH injected \
             closures: the owner handoff grounds once and its refusal here is not the collapsed \
             static, so no refusal-recovery re-run happens. The unit is the entry, not a \
             grounding proven to have occurred"
        );
        let Err(error) = refused else {
            panic!("a request with an empty frozen manifest digest must refuse at the owner");
        };
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert!(
            !matches!(error, DreamerError::KernelAdmissionRequired(_)),
            "a handoff refusal must not borrow the Kernel-admission code, got {error:?}"
        );
    }

    /// A collapsed refusal produces a SECOND GROUNDING ENTRY, and the entry count
    /// sees it: when the handoff refuses with exactly the owner's collapsed
    /// static, the same pure grounding is re-run over the retained request
    /// through the composition's own seam, so the grounding-ENTRY count on that
    /// path is 2 while the handoff-ENTRY count is still 1.
    ///
    /// This is the disclosure the previous oracle omitted. It is why "grounds
    /// exactly once" can only ever be read as a statement about one request's
    /// path — the seam makes two grounding entries on a collapsed refusal, and a
    /// count that does not cover both entries reports 1 and looks green.
    ///
    /// The unit is the ENTRY into an injected closure, on both counts, and this
    /// proof does not claim the two numbers are comparable with the paired
    /// proof's. The handoff closure above is a STUB: it grounds nothing and
    /// returns the collapsed error directly, so of the two entries counted here
    /// exactly one has a real grounding behind it. The paired proof's 1 is a real
    /// grounding at the same kind of entry boundary, which is why the two proofs'
    /// counts do NOT mean the same thing: this one reads 2 where a
    /// groundings-performed count would read 1.
    ///
    /// The second entry is produced by the RECOVERY closure the seam calls, over
    /// the `GroundingRequest` the seam retained. That request is ASSERTED here
    /// against an independently constructed expectation — built from the same
    /// fixture parts, not cloned from what the seam handed the closure — because
    /// `GroundingRequest` is `PartialEq`, so this proof does not merely claim the
    /// retained request was re-run: it fails if the seam retained, reconstructed,
    /// or mutated a different one. This proof never invokes the owner grounding a
    /// second time to reach the number.
    #[test]
    fn collapsed_refusal_recovery_is_a_second_visible_grounding_entry() {
        let grounding_entries = AtomicU64::new(0);
        let handoff_entries = AtomicU64::new(0);
        let refused = ground_and_bind_validation_carrier_with(
            handoff_request(),
            handoff_attachment(),
            |_request| {
                handoff_entries.fetch_add(1, Ordering::SeqCst);
                // This stub grounds NOTHING and returns the collapsed error
                // directly, so the entry counted below has no real grounding
                // behind it. It is counted because the unit under test is an
                // ENTRY into the closure, and the owner-side limit on what can
                // be intercepted applies to the paired proof (see its note).
                grounding_entries.fetch_add(1, Ordering::SeqCst);
                // The owner's `summarize_contract` reduces six refusal classes
                // onto this one static. This fixture's own refusal is NOT one of
                // them, so the collapsed error is supplied deliberately here to
                // exercise the recovery branch; nothing about the count depends on
                // where the error came from.
                Err(DreamDraftValidationError::InvalidContract {
                    phase: GROUNDING_PHASE,
                    field: COLLAPSED_CONTRACT_FIELD,
                })
            },
            |request| {
                // The seam's OWN recovery closure, reached only because the
                // handoff above refused with the collapsed static.
                //
                // D9: `request` is claimed to be the `GroundingRequest` the seam
                // retained and re-runs, so it is ASSERTED here rather than
                // assumed. The expectation is built independently from the same
                // fixture parts [`handoff_request`] builds — NOT cloned from
                // what the seam handed this closure, which would only compare
                // the seam against itself. `GroundingRequest` is
                // `Clone + Debug + PartialEq`, so this fails if the seam
                // retained, reconstructed, or mutated a different request.
                assert_eq!(
                    request,
                    handoff_request(),
                    "the recovery must re-run the GroundingRequest the seam retained, unchanged"
                );
                grounding_entries.fetch_add(1, Ordering::SeqCst);
                ground_draft_with_controls(request)
            },
        );
        assert_eq!(
            handoff_entries.load(Ordering::SeqCst),
            1,
            "the owner handoff itself still makes exactly ONE handoff entry"
        );
        assert_eq!(
            grounding_entries.load(Ordering::SeqCst),
            2,
            "a collapsed refusal must make TWO grounding ENTRIES — the handoff-boundary entry \
             and the refusal-recovery re-run — which is exactly what the handoff-only count \
             could not see. The unit is the ENTRY: only the second has a real grounding behind \
             it, because the stub handoff closure above returns the collapsed error WITHOUT \
             grounding. This 2 is therefore NOT comparable with the paired proof's 1, which \
             counts a boundary entry over a real grounding"
        );
        let Err(error) = refused else {
            panic!("a collapsed refusal must never produce a carrier");
        };
        assert!(
            !matches!(
                error,
                DreamerError::InvalidAdmission(COLLAPSED_CONTRACT_FIELD)
            ),
            "the recovery must replace the collapsed static with the precise one, got {error:?}"
        );
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
    }

    /// The production handoff entry wires the real owner and preserves its
    /// refusal verbatim: a refused grounding never becomes a carrier, a
    /// fabricated default, or an empty success, and the refusal keeps the
    /// request-rejected code.
    ///
    /// No "once" is claimed: this proof carries no counter, so it says nothing
    /// about call count. The once-ness of the injected closures is structural
    /// (`FnOnce`) and is observed by the counting proofs above.
    #[test]
    fn production_handoff_entry_calls_the_real_owner() {
        let refused = ground_and_bind_validation_carrier(handoff_request(), handoff_attachment());
        let Err(error) = refused else {
            panic!(
                "a request with an empty frozen manifest digest must refuse at the owner handoff"
            );
        };
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert!(
            !matches!(error, DreamerError::KernelAdmissionRequired(_)),
            "a handoff refusal must not borrow the Kernel-admission code, got {error:?}"
        );
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

    /// The production entry calls the real owner: the same wire-versioned
    /// carrier refuses through the production path with the request-rejected
    /// code, never the Kernel-admission code.
    ///
    /// No "once" is claimed: this proof carries no counter, so it says nothing
    /// about call count. See [`owner_validation_runs_exactly_once_per_admission`]
    /// for the counted form.
    #[test]
    fn production_entry_calls_the_real_owner() {
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
}
