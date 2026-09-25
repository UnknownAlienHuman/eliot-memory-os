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
//!
//! The public-path tests at the bottom drive
//! [`AuthenticatedKernelJobPort::submit`](crate::AuthenticatedKernelJobPort)
//! through the `for_test` port — closed test transport, matching
//! material/admission fixtures, and an optional counting carrier source — so
//! the screen-first carrier refusal, the A-31 exactly-once run up to the
//! closed front door, the live-bound success tail returning the Curation
//! result view, the refused-class gate, and the Slice-2 controller gate
//! are proved on the same code production executes.

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_dreamer_claim_grounding::GroundingRequest;
use eliot_dreamer_contracts::grounding::{GroundedDreamDraft, StructuredModelDraft};

use crate::admitted_material::{admission_of, validation_input_for};
use crate::controller::verify_admitted_binding;
use crate::curation_screen_stage::{ScreenDecision, resolve_screen_inputs};
use crate::dispatch_stage::dispatch_admitted;
use crate::grounding_stage::{ground_admitted_draft, resolve_grounding_inputs};
use crate::model_stage::{resolve_model_inputs, run_admitted_model};
use crate::result_stage::{project_result_view, render_jsonl};
use crate::validation_stage::{resolve_validation_inputs, validate_admitted_draft};
use crate::{
    DreamJobInput, DreamResult, DreamerError, JobClass, JobState, KernelJobAdmission,
    run_admitted_pipeline,
};
use eliot_dreamer_contracts::validation::structured::{
    GroundingValidationInput, ValidatedGroundingCandidate,
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
        // Same epoch-1 fence every admission fixture binds, so the binding
        // check proves agreement and only owner gates can refuse.
        state_fence: StateFence::new(test_epoch(1), ResourceGeneration::genesis()),
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
    match resolve_screen_inputs(admission, job, None).expect("e2e screen must resolve") {
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
    assert!(
        !model_inputs.route.is_empty(),
        "admitted route must be named"
    );
    assert!(
        model_inputs.budget_units > 0,
        "admitted budget must be positive"
    );
    let draft: StructuredModelDraft =
        run_admitted_model(model_inputs).expect("e2e model must prove");
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
    let result = dispatch_admitted(
        &admission,
        &job,
        None,
        None,
        JobClass::Orientation,
        Some(&validated),
    );
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
    let view = project_result_view(
        &job_id,
        JobState::Completed,
        Some(DreamResult::Packet(packet)),
    );
    let line = render_jsonl(&view).expect("receipt must render");
    assert!(!line.contains('\n'), "receipt must be exactly one line");
    let roundtrip: crate::JobView = serde_json::from_str(&line).expect("receipt must round-trip");
    assert_eq!(roundtrip, view);
}

/// Curation cannot enter the generic pipeline from semantic handles alone.
/// The production composition supplies the exact owner-admitted material over
/// the protected Kernel handoff; this negative seam proves that omission is a
/// fail-closed request rejection before any model, grounding, or A-31 work.
#[test]
fn curation_without_owner_material_refuses_before_generic_stages() {
    let admission = admitted_admission("job-e2e-curation-missing-owner");
    let job = job_with_handles("job-e2e-curation-missing-owner", JobClass::Curation);
    let refused = run_admitted_pipeline(&admission, &job, None, None);
    assert!(matches!(
        refused,
        Err(DreamerError::InvalidAdmission(
            "admitted curation requires owner-resolved screen binding"
        ))
    ));
}

#[test]
fn protected_claim_without_owner_material_never_synthesizes_identity() {
    let epoch = test_epoch(1);
    let fence = StateFence::new(epoch.clone(), ResourceGeneration::genesis());
    let material = crate::kernel_port::ValidatedDreamerMaterial {
        job_id: "job-missing-owner-material".to_owned(),
        attempt_id: "attempt-missing-owner-material".to_owned(),
        revision: 1,
        scope_id: SCOPE_E2E.to_owned(),
        fence: fence.clone(),
        admitted_curation: None,
        epoch: epoch.clone(),
        generation: 1,
        nonce: "dreamer-dispatch-test-nonce".to_owned(),
        grant: crate::kernel_port::DispatchGrant {
            grant_digest: "ab".repeat(32),
            authority_epoch: epoch,
            fence_generation: 1,
            fence_nonce: "dreamer-dispatch-fence-test".to_owned(),
            idempotency_key: "missing-owner-material-idem".to_owned(),
            expires_at: u64::MAX,
        },
    };
    let Err(error) = crate::claim_admission(&material) else {
        panic!("missing owner material must not synthesize a claim admission");
    };
    assert!(matches!(
        error,
        DreamerError::KernelAdmissionRequired(reason)
            if reason == "protected launch omitted owner-admitted semantic material"
    ));
}
