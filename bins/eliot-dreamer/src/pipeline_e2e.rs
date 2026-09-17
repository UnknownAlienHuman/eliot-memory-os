#![cfg(test)]

//! End-to-end pipeline proofs for admitted Dreamer jobs (issue #702, Slices
//! 3-8; #1136 Slice B).
//!
//! Threads the admitted stages in canonical order — screen, model, grounding,
//! validation (non-Curation), dispatch, result — for one Orientation job
//! (proved packet receipt through the real native projector) and one Curation
//! job (A-31 routing without class refusal, plus the genuine v2 semantic
//! gate). Deterministic: no I/O, no sleeps, no process launch, no files. The
//! result edge asserts the Slice-8 stdout contract: exactly one JSONL line
//! that round-trips to the identical view.
//!
//! `submit` itself is not driven here: the Slice-2 controller/bundle stages
//! (merged scope) still gate on Governor-resolved material ahead of these
//! stages, and the live view needs a Kernel transport. These proofs cover
//! the stages this workstream owns, in the exact order `submit` threads them.

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_dreamer_claim_grounding::GroundingRequest;
use eliot_dreamer_contracts::grounding::{GroundedDreamDraft, ModelDraft};

use crate::admitted_material::{admission_of, validation_input_for};
use crate::controller::verify_admitted_binding;
use crate::curation_screen_stage::{ScreenDecision, resolve_screen_inputs};
use crate::dispatch_stage::dispatch_admitted;
use crate::grounding_stage::{ground_admitted_draft, resolve_grounding_inputs};
use crate::model_stage::{resolve_model_inputs, run_admitted_model};
use crate::result_stage::{project_result_view, render_jsonl};
use crate::validation_stage::{resolve_validation_inputs, validate_admitted_draft};
use eliot_dreamer_contracts::validation::structured::{
    GroundingValidationInput, ValidatedGroundingCandidate,
};
use crate::{
    DreamJobInput, DreamResult, DreamerError, JobClass, JobState, KERNEL_ADMISSION_REQUIRED,
    KernelJobAdmission,
};

const TEST_LINEAGE_E2E: &str = "550e8400-e29b-41d4-a716-446655440000";
const SCOPE_E2E: &str = "scope-e2e";

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_E2E).expect("valid e2e lineage"),
        NonZeroU64::new(sequence).expect("nonzero e2e sequence"),
    )
    .expect("valid e2e epoch")
}

/// An admitted Kernel identity: live deadline plus the real typed fence, so
/// every stage binding check passes and only owner gates (not identity) can
/// refuse.
fn admitted_admission(job_id: &str) -> KernelJobAdmission {
    KernelJobAdmission {
        job_id: job_id.to_owned(),
        attempt_id: format!("{job_id}-attempt-1"),
        scope_id: SCOPE_E2E.to_owned(),
        request_id: format!("{job_id}-request-1"),
        idempotency_key: format!("{job_id}:attempt-1"),
        cancellation_id: format!("{job_id}-cancel-1"),
        deadline_unix_ms: u64::MAX,
        state_fence: StateFence::new(test_epoch(1), ResourceGeneration::genesis()),
    }
}

fn job_with_handles(job_id: &str, job_class: JobClass) -> DreamJobInput {
    DreamJobInput {
        job_id: job_id.to_owned(),
        job_class,
        exact_question: "What does ELIOT know about this scope?".to_owned(),
        requester: "e2e-harness".to_owned(),
        scope_id: SCOPE_E2E.to_owned(),
        task_id: Some("task-e2e".to_owned()),
        state_fence: "kernel-owned".to_owned(),
        evidence_handles: vec!["evidence-e2e-1".to_owned(), "evidence-e2e-2".to_owned()],
        memory_handles: vec!["memory-e2e-1".to_owned()],
        architecture_handles: vec!["architecture-e2e-1".to_owned()],
        implementation_handles: Vec::new(),
        conformance_handles: Vec::new(),
        conflicts_and_unknowns: vec!["No explicit conflict set was supplied.".to_owned()],
        privacy_profile: "local_only".to_owned(),
        allowed_tools: Vec::new(),
        allowed_model_routes: vec!["route-e2e".to_owned()],
        budget_units: 4,
        deadline_ms: 60_000,
        output_schema: "eliot.dreamer.v1".to_owned(),
        forbidden_effects: Vec::new(),
    }
}

/// Threads screen, model, grounding, and v2 validation for one admitted job,
/// returning the validated candidate. Every stage genuinely invokes its
/// owner; any refusal fails the proof.
fn validate_through_model(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> ValidatedGroundingCandidate {
    verify_admitted_binding(admission, job).expect("e2e binding must verify");
    match resolve_screen_inputs(admission, job).expect("e2e screen must resolve") {
        ScreenDecision::PassThrough(_) => {}
        ScreenDecision::Screened {
            eligible_targets, ..
        } => {
            assert!(
                !eligible_targets.is_empty(),
                "a screened Curation set must stay non-empty"
            );
        }
    }
    let model_inputs = resolve_model_inputs(admission, job).expect("e2e model must resolve");
    assert!(!model_inputs.route.is_empty(), "admitted route must be named");
    assert!(model_inputs.budget_units > 0, "admitted budget must be positive");
    let draft: ModelDraft = run_admitted_model(model_inputs).expect("e2e model must prove");
    let request: GroundingRequest =
        resolve_grounding_inputs(admission, job, draft).expect("e2e grounding must resolve");
    let grounded: GroundedDreamDraft =
        ground_admitted_draft(request).expect("e2e grounding must prove");
    let _inputs = resolve_validation_inputs(admission, job).expect("e2e validation must map");
    let carrier: GroundingValidationInput =
        validation_input_for(admission, job, grounded, Some(0)).expect("e2e carrier must build");
    validate_admitted_draft(&carrier).expect("e2e validation must accept")
}

/// Orientation passes the full owned pipeline: genuine owner calls at every
/// stage, a native packet out of dispatch, and a single-line JSONL receipt
/// that round-trips to the identical view.
#[test]
fn orientation_pipeline_threads_screen_to_packet_receipt() {
    let admission = admitted_admission("job-e2e-orientation");
    let job = job_with_handles("job-e2e-orientation", JobClass::Orientation);
    let validated = validate_through_model(&admission, &job);
    assert!(
        !validated
            .output_digest()
            .expect("accepted candidate must digest")
            .is_empty(),
        "accepted candidate must bind its output digest"
    );
    let result = dispatch_admitted(&admission, &job, None, JobClass::Orientation);
    let Ok(DreamResult::Packet(packet)) = result else {
        panic!("orientation dispatch must project, got {result:?}");
    };
    assert_eq!(packet.packet_id.len(), 64);
    let canonical = admission_of(&admission, &job)
        .expect("e2e admission must derive")
        .canonical_id();
    assert_eq!(packet.job_id, canonical);
    assert_eq!(packet.question, job.exact_question);
    assert_eq!(packet.scope_id, SCOPE_E2E);
    assert_eq!(packet.source_coverage.evidence, job.evidence_handles);
    assert_eq!(packet.synthesized_interpretations.len(), 1);
    // G4: exactly the two owner residue markers travel as rival entries.
    assert_eq!(packet.rival_models_and_dissent.len(), 2);
    let job_id = packet.job_id.clone();
    let view = project_result_view(&job_id, JobState::Completed, Some(DreamResult::Packet(packet)));
    let line = render_jsonl(&view).expect("receipt must render");
    assert!(!line.contains('\n'), "receipt must be exactly one line");
    let roundtrip: crate::JobView =
        serde_json::from_str(&line).expect("receipt must round-trip");
    assert_eq!(roundtrip, view);
}

/// Curation routes to the A-31 sole fan-in without class refusal: the screen
/// admits a non-empty eligible set, the v2 owner itself directs Curation to
/// its separate carrier (`UnsupportedJobShape` semantic rejection, never a
/// shape error), and dispatch names the live-port boundary — never
/// `UnsupportedJobClass`, never the Kernel-admission code.
#[test]
fn curation_pipeline_routes_a31_without_class_refusal() {
    let admission = admitted_admission("job-e2e-curation");
    let job = job_with_handles("job-e2e-curation", JobClass::Curation);
    verify_admitted_binding(&admission, &job).expect("e2e binding must verify");
    let ScreenDecision::Screened {
        eligible_targets,
        binding,
        ..
    } = resolve_screen_inputs(&admission, &job).expect("e2e screen must admit")
    else {
        panic!("curation must screen, not pass through");
    };
    assert_eq!(eligible_targets.len(), 4);
    binding
        .validate()
        .expect("screened binding must satisfy the real owner check");
    let model_inputs = resolve_model_inputs(&admission, &job).expect("e2e model must resolve");
    let draft = run_admitted_model(model_inputs).expect("e2e model must prove");
    let request = resolve_grounding_inputs(&admission, &job, draft).expect("e2e grounding must resolve");
    let grounded = ground_admitted_draft(request).expect("e2e grounding must prove");
    // The common A-05 owner directs Curation to its separate typed carrier:
    // a genuine semantic gate firing exactly as designed.
    let carrier =
        validation_input_for(&admission, &job, grounded, Some(0)).expect("e2e carrier must build");
    let rejected = validate_admitted_draft(&carrier);
    assert!(
        matches!(
            rejected,
            Err(DreamerError::InvalidAdmission("validation semantic rejection"))
        ),
        "curation must take the separate-carrier gate, got {rejected:?}"
    );
    // A-31 fan-in: precise port-boundary refusal, never a class refusal.
    let refused = dispatch_admitted(&admission, &job, Some(binding), JobClass::Curation);
    assert!(
        !matches!(refused, Err(DreamerError::UnsupportedJobClass(_))),
        "curation must never refuse with UnsupportedJobClass, got {refused:?}"
    );
    let Err(error) = refused else {
        panic!("curation without injected ports must wait at the boundary");
    };
    assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
    assert_ne!(error.code(), KERNEL_ADMISSION_REQUIRED);
    let message = format!("{error}");
    assert!(
        message.contains("ports") || message.contains("screen"),
        "refusal must name the boundary, got {message}"
    );
}
