#![cfg(test)]

//! End-to-end pipeline proofs for admitted Dreamer jobs (issue #702, Slices
//! 3-8; #1136 Slice B).
//!
//! Threads the admitted stages in canonical order — screen, then (for
//! Curation) the execution-carrier check and A-31, or (otherwise) model,
//! grounding, validation (non-Curation), dispatch, result — for one
//! Orientation job (proved packet receipt through the real native projector)
//! and Curation jobs (carrier-gated A-31 routing without class refusal, the
//! genuine v2 semantic gate, and the injected-carrier success path).
//! Deterministic: no I/O, no sleeps, no process launch, no files. The
//! result edge asserts the Slice-8 stdout contract: exactly one JSONL line
//! that round-trips to the identical view.
//!
//! `submit` itself is not driven here: the Slice-A gate (proved separately),
//! the Slice-2 controller/bundle stages (merged scope), and the live view
//! (Kernel transport) frame the chain on both sides. The chain tests below
//! drive [`run_admitted_pipeline`](crate::run_admitted_pipeline) — the exact
//! function `submit` calls (production passes `None` for the
//! Governor-injected Curation carrier) — so stage order and terminal outcomes
//! are proved for the same code `submit` executes.

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_dreamer_claim_grounding::GroundingRequest;
use eliot_dreamer_contracts::grounding::{GroundedDreamDraft, ModelDraft};

use crate::admitted_material::{admission_of, validation_input_for};
use crate::controller::verify_admitted_binding;
use crate::curation_screen_stage::{ScreenDecision, resolve_screen_inputs};
use crate::dispatch_stage::{
    CURATION_CARRIER_REFUSAL, curation_test_support::CurationTestHarness, dispatch_admitted,
};
use crate::grounding_stage::{ground_admitted_draft, resolve_grounding_inputs};
use crate::model_stage::{resolve_model_inputs, run_admitted_model};
use crate::result_stage::{project_result_view, render_jsonl};
use crate::validation_stage::{resolve_validation_inputs, validate_admitted_draft};
use eliot_dreamer_contracts::validation::structured::{
    GroundingValidationInput, ValidatedGroundingCandidate,
};
use crate::{
    DreamJobInput, DreamResult, DreamerError, JobClass, JobState, KERNEL_ADMISSION_REQUIRED,
    KernelJobAdmission, run_admitted_pipeline,
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
    let result = dispatch_admitted(&admission, &job, None, None, JobClass::Orientation);
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
/// shape error), and dispatch without an injected carrier refuses at the
/// carrier check with the precise reason — never `UnsupportedJobClass`,
/// never the Kernel-admission code. (The live-port boundary behind the
/// carrier is proved by the dispatch-level tests, which inject the carrier.)
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
    // A-31 fan-in without an injected carrier: the precise carrier-check
    // refusal, never a class refusal.
    let refused = dispatch_admitted(&admission, &job, Some(binding), None, JobClass::Curation);
    assert!(
        !matches!(refused, Err(DreamerError::UnsupportedJobClass(_))),
        "curation must never refuse with UnsupportedJobClass, got {refused:?}"
    );
    let Err(error) = refused else {
        panic!("curation without an injected carrier must refuse at the carrier check");
    };
    assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
    assert_ne!(error.code(), KERNEL_ADMISSION_REQUIRED);
    assert!(
        matches!(
            error,
            DreamerError::InvalidAdmission(reason) if reason == CURATION_CARRIER_REFUSAL
        ),
        "refusal must be exactly the carrier-check reason, got {error:?}"
    );
}

/// The exact admitted chain `submit` executes past the bundle plan-factor for
/// Orientation: one call proves screen, model, grounding, validation, and
/// native dispatch run in canonical order to a packet result. (`submit`
/// itself additionally needs the Slice-2 controller/bundle gates and a live
/// Kernel transport, so the chain — the same function `submit` calls — is
/// the provable unit in-process.)
#[test]
fn submit_chain_returns_orientation_packet_with_jsonl() {
    let admission = admitted_admission("job-e2e-chain-orientation");
    let job = job_with_handles("job-e2e-chain-orientation", JobClass::Orientation);
    let result = run_admitted_pipeline(&admission, &job, None);
    let Ok(DreamResult::Packet(packet)) = result else {
        panic!("submit chain must project orientation, got {result:?}");
    };
    assert_eq!(packet.scope_id, SCOPE_E2E);
    assert_eq!(packet.source_coverage.evidence, job.evidence_handles);
    let job_id = packet.job_id.clone();
    let view = project_result_view(&job_id, JobState::Completed, Some(DreamResult::Packet(packet)));
    let line = render_jsonl(&view).expect("chain receipt must render");
    assert!(!line.contains('\n'), "chain receipt must be one JSONL line");
    let roundtrip: crate::JobView =
        serde_json::from_str(&line).expect("chain receipt must round-trip");
    assert_eq!(roundtrip, view);
}

/// The exact admitted chain `submit` executes, for Curation without an
/// injected carrier: the A-20 screen admits the eligible set, then the
/// carrier check refuses with exactly [`CURATION_CARRIER_REFUSAL`] — right
/// after the screen, BEFORE any model/grounding work. This proves no
/// premature gate blocks Curation before the screen, and no generic stage
/// burns before the refusal: the chain fails only at the carrier check,
/// never with a class refusal and never silently.
#[test]
fn submit_chain_threads_screen_binding_to_a31_boundary() {
    let admission = admitted_admission("job-e2e-chain-curation");
    let job = job_with_handles("job-e2e-chain-curation", JobClass::Curation);
    // The screen stage the chain threads must admit a valid binding first.
    let ScreenDecision::Screened {
        eligible_targets,
        binding,
        ..
    } = resolve_screen_inputs(&admission, &job).expect("chain screen must admit")
    else {
        panic!("curation must screen, not pass through");
    };
    assert!(!eligible_targets.is_empty());
    binding
        .validate()
        .expect("threaded binding must satisfy the real owner check");
    // The whole chain then refuses at the carrier check with the exact
    // reason — never a class refusal, never silent, never the Kernel code.
    let refused = run_admitted_pipeline(&admission, &job, None);
    assert!(
        !matches!(refused, Err(DreamerError::UnsupportedJobClass(_))),
        "chain must never refuse curation by class, got {refused:?}"
    );
    let Err(error) = refused else {
        panic!("curation without an injected carrier must refuse at the carrier check");
    };
    assert!(
        matches!(
            error,
            DreamerError::InvalidAdmission(reason) if reason == CURATION_CARRIER_REFUSAL
        ),
        "chain must refuse with exactly the carrier-check reason, got {error:?}"
    );
    assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
    assert_ne!(error.code(), KERNEL_ADMISSION_REQUIRED);
    assert!(
        !matches!(error, DreamerError::KernelAdmissionRequired(_)),
        "chain refusal must not borrow the Kernel-admission code, got {error:?}"
    );
}

/// The exact admitted chain `submit` executes, for Curation with a
/// Governor-injected carrier: the screen admits, the carrier check passes,
/// and A-31 routes to a `Curation` result whose candidates carry non-blank
/// identity and handles. The Slice-8 edge then projects the result view and
/// proves the single-line JSONL round-trip, so the Curation terminal edge is
/// proved exactly like the Orientation one.
#[test]
fn submit_chain_curation_success_with_injected_carrier() {
    let admission = admitted_admission("job-e2e-chain-curation-ok");
    let job = job_with_handles("job-e2e-chain-curation-ok", JobClass::Curation);
    let ScreenDecision::Screened {
        eligible_targets,
        binding,
        ..
    } = resolve_screen_inputs(&admission, &job).expect("chain screen must admit")
    else {
        panic!("curation must screen, not pass through");
    };
    assert!(!eligible_targets.is_empty());
    binding
        .validate()
        .expect("threaded binding must satisfy the real owner check");
    let harness =
        CurationTestHarness::for_screen(&binding, &admission, &job).expect("harness must build");
    let result = run_admitted_pipeline(&admission, &job, Some(harness.carrier()));
    let Ok(DreamResult::Curation {
        job_id,
        candidates,
        provenance,
    }) = result
    else {
        panic!("injected-carrier chain must route curation, got {result:?}");
    };
    let canonical = admission_of(&admission, &job)
        .expect("e2e admission must derive")
        .canonical_id();
    assert_eq!(job_id, canonical);
    assert!(
        !candidates.is_empty(),
        "a routed curation must name candidates"
    );
    for candidate in &candidates {
        assert!(
            !candidate.candidate_id.trim().is_empty(),
            "every candidate must carry a non-blank id"
        );
        assert!(
            !candidate.kind.trim().is_empty(),
            "every candidate must carry a non-blank kind"
        );
        assert!(
            !candidate.source_handles.is_empty(),
            "every candidate must carry source handles"
        );
        for handle in &candidate.source_handles {
            assert!(
                !handle.trim().is_empty(),
                "every candidate handle must be non-blank"
            );
        }
    }
    let view = project_result_view(
        &job_id,
        JobState::Completed,
        Some(DreamResult::Curation {
            job_id: job_id.clone(),
            candidates: candidates.clone(),
            provenance: provenance.clone(),
        }),
    );
    let line = render_jsonl(&view).expect("chain receipt must render");
    assert!(!line.contains('\n'), "chain receipt must be one JSONL line");
    let roundtrip: crate::JobView =
        serde_json::from_str(&line).expect("chain receipt must round-trip");
    assert_eq!(roundtrip, view);
}

/// The carrier check runs before any generic stage: for a fully valid
/// Curation job (the success twin proves model/grounding would pass this
/// input), the carrier-less chain refuses with exactly
/// [`CURATION_CARRIER_REFUSAL`] — no generic grounding runs only to fail
/// later at the port boundary. The refusal site is structural:
/// `run_admitted_pipeline` checks the carrier immediately after the screen,
/// textually before any model/grounding call. The dispatch-level check
/// refuses identically.
#[test]
fn submit_chain_curation_stops_before_generic_stages_without_carrier() {
    let admission = admitted_admission("job-e2e-chain-curation-early");
    let job = job_with_handles("job-e2e-chain-curation-early", JobClass::Curation);
    // Chain level: the screen admits, then the carrier check refuses before
    // any generic model/grounding work could run.
    let refused = run_admitted_pipeline(&admission, &job, None);
    let Err(error) = refused else {
        panic!("carrier-less curation must refuse at the carrier check");
    };
    assert!(
        matches!(
            error,
            DreamerError::InvalidAdmission(reason) if reason == CURATION_CARRIER_REFUSAL
        ),
        "chain must refuse with exactly the carrier-check reason, got {error:?}"
    );
    assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
    assert_ne!(error.code(), KERNEL_ADMISSION_REQUIRED);
    // Dispatch level: the same missing carrier refuses with the same reason.
    let refused = dispatch_admitted(&admission, &job, None, None, JobClass::Curation);
    let Err(error) = refused else {
        panic!("carrier-less dispatch must refuse at the carrier check");
    };
    assert!(
        matches!(
            error,
            DreamerError::InvalidAdmission(reason) if reason == CURATION_CARRIER_REFUSAL
        ),
        "dispatch must refuse with exactly the carrier-check reason, got {error:?}"
    );
    assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
}
