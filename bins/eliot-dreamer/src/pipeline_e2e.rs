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
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_dreamer_claim_grounding::GroundingRequest;
use eliot_dreamer_contracts::ScreenBinding;
use eliot_dreamer_contracts::grounding::{GroundedDreamDraft, StructuredModelDraft};
use eliot_dreamer_curation::{NativeCurationPort, NativeCurationPortSet};

use crate::admitted_material::{admission_of, validation_input_for};
use crate::controller::verify_admitted_binding;
use crate::curation_screen_stage::{ScreenDecision, resolve_screen_inputs};
use crate::dispatch_stage::{
    CURATION_CARRIER_REFUSAL, CurationExecutionCarrier,
    curation_test_support::{
        CountingRoutingHandler, CurationTestHarness, test_batch_for, test_port_bindings,
    },
    dispatch_admitted,
};
use crate::grounding_stage::{ground_admitted_draft, resolve_grounding_inputs};
use crate::kernel_port::{
    ClaimTransport, DREAMER_JOB_WIRE_ID, DispatchGrant, KernelPortError, ValidatedDreamerMaterial,
};
use crate::model_stage::{resolve_model_inputs, run_admitted_model};
use crate::result_stage::{project_result_view, render_jsonl};
use crate::validation_stage::{resolve_validation_inputs, validate_admitted_draft};
use crate::{
    AuthenticatedKernelJobPort, CurationCarrierSource, DreamJobInput, DreamResult, DreamerError,
    JobClass, JobState, KERNEL_ADMISSION_REQUIRED, KernelJobAdmission, KernelJobPort,
    run_admitted_pipeline,
};
use eliot_dreamer_contracts::validation::structured::{
    GroundingValidationInput, ValidatedGroundingCandidate,
};
use eliot_protocol::dreamer_job::{DurableJobRequest, JobOperation, JobRole};

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
    let request =
        resolve_grounding_inputs(&admission, &job, draft).expect("e2e grounding must resolve");
    let grounded = ground_admitted_draft(request).expect("e2e grounding must prove");
    // The common A-05 owner directs Curation to its separate typed carrier:
    // a genuine semantic gate firing exactly as designed.
    let carrier =
        validation_input_for(&admission, &job, grounded, Some(0)).expect("e2e carrier must build");
    let rejected = validate_admitted_draft(&carrier);
    assert!(
        matches!(
            rejected,
            Err(DreamerError::InvalidAdmission(
                "validation semantic rejection"
            ))
        ),
        "curation must take the separate-carrier gate, got {rejected:?}"
    );
    // A-31 fan-in without an injected carrier: the precise carrier-check
    // refusal, never a class refusal.
    let refused = dispatch_admitted(
        &admission,
        &job,
        Some(binding),
        None,
        JobClass::Curation,
        None,
    );
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
    let view = project_result_view(
        &job_id,
        JobState::Completed,
        Some(DreamResult::Packet(packet)),
    );
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
    let refused = dispatch_admitted(&admission, &job, None, None, JobClass::Curation, None);
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

// ---------------------------------------------------------------------------
// Public-path `submit` proofs (issue #702 fix4, auditor B1).
//
// These tests drive [`AuthenticatedKernelJobPort::submit`] through the
// `for_test` port — closed test transport, matching material/admission
// fixtures, and an optional counting carrier source — instead of the private
// chain. Against the sibling `lib.rs` contract:
// `crate::CurationCarrierSource::resolve_carrier`, the `for_test`
// constructor, and the [`KernelJobPort`] `submit` call shape.
// ---------------------------------------------------------------------------

/// Closed test transport: binds identity but refuses every transact with a
/// typed transport denial. Owned with no borrows, so it satisfies any
/// `'static` box bound on the port constructor.
struct ClosedTestTransport;

impl ClaimTransport for ClosedTestTransport {
    fn bind_identity(
        &mut self,
        _fence: &StateFence,
        _operation_id: &str,
    ) -> Result<(), KernelPortError> {
        Ok(())
    }

    fn transact(
        &mut self,
        _operation: &str,
        _payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelPortError> {
        Err(KernelPortError::Transport(
            "test front door is closed".to_owned(),
        ))
    }
}

/// Test curation-carrier source: owns a counting echo handler and resolves a
/// batch plus ten-port carrier for the presented screen, admission, and job.
/// The batch and the port halves come from the shared test builders, so no
/// digest/pin/seal logic is duplicated by hand. Owns everything, so the port
/// holds it behind a plain shared borrow with no lifetime entanglement.
struct TestCarrierSource {
    handler: CountingRoutingHandler,
}

impl TestCarrierSource {
    fn new() -> Self {
        Self {
            handler: CountingRoutingHandler::new(),
        }
    }

    /// Returns the number of routed A-31 handler invocations so far: the
    /// exactly-once proof observes this after `submit`.
    fn calls(&self) -> u64 {
        self.handler.calls()
    }
}

impl Default for TestCarrierSource {
    fn default() -> Self {
        Self::new()
    }
}

impl CurationCarrierSource for TestCarrierSource {
    fn resolve_carrier<'s>(
        &'s self,
        screen: &ScreenBinding,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<CurationExecutionCarrier<'s>, DreamerError> {
        let batch = test_batch_for(screen, admission, job)?;
        let ports: Vec<NativeCurationPort<'_>> = test_port_bindings()?
            .into_iter()
            .map(|binding| NativeCurationPort {
                port: binding.port,
                owner_package: binding.owner_package,
                owner_revision: binding.owner_revision,
                handler: &self.handler,
            })
            .collect();
        Ok(CurationExecutionCarrier {
            batch,
            ports: NativeCurationPortSet { ports },
        })
    }
}

/// Validated claim material for one submit-path job: real epoch fence,
/// revision/generation 1, and a well-formed grant whose digest, authority
/// epoch, fence generation, idempotency key, and expiry the admission fixture
/// mirrors exactly.
fn submit_material(job_id: &str) -> ValidatedDreamerMaterial {
    let epoch = test_epoch(1);
    ValidatedDreamerMaterial {
        job_id: job_id.to_owned(),
        attempt_id: format!("{job_id}-attempt-1"),
        revision: 1,
        scope_id: SCOPE_E2E.to_owned(),
        fence: StateFence::new(epoch.clone(), ResourceGeneration::genesis()),
        epoch: epoch.clone(),
        generation: 1,
        nonce: "e2e-submit-nonce-0123456789abcdef".to_owned(),
        grant: DispatchGrant {
            grant_digest: "c".repeat(64),
            authority_epoch: epoch,
            fence_generation: 1,
            fence_nonce: format!("{job_id}-fence-nonce"),
            idempotency_key: format!("{job_id}:attempt-1"),
            expires_at: u64::MAX,
        },
    }
}

/// Kernel admission mirroring the claim material exactly — job, scope, fence,
/// and idempotency key match, and the deadline stays live — so only stage
/// gates (never identity) can refuse the submit path.
fn submit_admission(material: &ValidatedDreamerMaterial) -> KernelJobAdmission {
    KernelJobAdmission {
        job_id: material.job_id.clone(),
        attempt_id: material.attempt_id.clone(),
        scope_id: material.scope_id.clone(),
        request_id: format!("{}-request-1", material.job_id),
        idempotency_key: material.grant.idempotency_key.clone(),
        cancellation_id: format!("{}-cancel-1", material.job_id),
        deadline_unix_ms: u64::MAX,
        state_fence: material.fence.clone(),
    }
}

/// Curation job admitting exactly one screenable target: the routed batch
/// then carries one item, so the A-31 handler runs exactly once and the
/// exactly-once proof observes `calls() == 1`.
fn single_target_job(job_id: &str) -> DreamJobInput {
    let mut job = job_with_handles(job_id, JobClass::Curation);
    job.evidence_handles = vec!["evidence-e2e-single".to_owned()];
    job.memory_handles.clear();
    job.architecture_handles.clear();
    job.implementation_handles.clear();
    job.conformance_handles.clear();
    job
}

/// The public `submit` path with an injected carrier runs the screen, then
/// A-31 exactly once, and only then fails closed at the test front door: the
/// full pipeline executes in-process, and the live view cannot pass without a
/// Kernel. Typed result content itself is proved at chain level
/// (`submit_chain_curation_success_with_injected_carrier`); `submit`
/// in-process cannot project a result view past `live_view` without a live
/// Kernel transport, so the closed-transport refusal is the terminal proof
/// here. The empty-handles twin refuses at the screen with zero handler
/// calls, proving screen-first ordering through `submit`.
#[test]
fn submit_curation_with_source_runs_a31_then_fails_closed_at_transport() {
    let job_id = "job-e2e-submit-curation-ok";
    let material = submit_material(job_id);
    let admission = submit_admission(&material);
    let job = single_target_job(job_id);
    let source = TestCarrierSource::new();
    let mut port = AuthenticatedKernelJobPort::for_test(
        material,
        admission.clone(),
        Box::new(ClosedTestTransport),
        Some(&source),
    )
    .expect("test port must construct");
    let refused =
        <AuthenticatedKernelJobPort as KernelJobPort>::submit(&mut port, &admission, &job);
    let Err(error) = refused else {
        panic!("curation submit with a carrier must fail closed at the test front door");
    };
    assert!(
        matches!(error, DreamerError::KernelAdmissionRequired(_)),
        "closed transport must surface after the full pipeline, got {error:?}"
    );
    assert_eq!(error.code(), KERNEL_ADMISSION_REQUIRED);
    assert!(
        !matches!(error, DreamerError::InvalidAdmission(_)),
        "pipeline success must not refuse as invalid admission, got {error:?}"
    );
    assert!(
        !matches!(error, DreamerError::UnsupportedJobClass(_)),
        "curation must never refuse by class, got {error:?}"
    );
    assert_eq!(
        source.calls(),
        1,
        "A-31 must invoke the routed handler exactly once"
    );

    // Empty-handles twin: the screen refuses first, so A-31 never runs.
    let empty_job_id = "job-e2e-submit-curation-empty";
    let empty_material = submit_material(empty_job_id);
    let empty_admission = submit_admission(&empty_material);
    let mut empty_job = job_with_handles(empty_job_id, JobClass::Curation);
    empty_job.evidence_handles.clear();
    empty_job.memory_handles.clear();
    empty_job.architecture_handles.clear();
    empty_job.implementation_handles.clear();
    empty_job.conformance_handles.clear();
    let empty_source = TestCarrierSource::new();
    let mut empty_port = AuthenticatedKernelJobPort::for_test(
        empty_material,
        empty_admission.clone(),
        Box::new(ClosedTestTransport),
        Some(&empty_source),
    )
    .expect("empty-handles test port must construct");
    let refused = <AuthenticatedKernelJobPort as KernelJobPort>::submit(
        &mut empty_port,
        &empty_admission,
        &empty_job,
    );
    let Err(error) = refused else {
        panic!("handle-less curation submit must refuse at the screen");
    };
    assert!(
        matches!(error, DreamerError::InvalidAdmission(_)),
        "handle-less curation must refuse at the screen, got {error:?}"
    );
    assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
    assert!(
        !matches!(error, DreamerError::KernelAdmissionRequired(_)),
        "screen refusal must precede any transport contact, got {error:?}"
    );
    assert_eq!(
        empty_source.calls(),
        0,
        "a screen-first refusal must never reach A-31"
    );
}

/// The public `submit` path without an injected carrier refuses at the
/// carrier check with exactly [`CURATION_CARRIER_REFUSAL`] — before any
/// transport contact: the closed front door would surface
/// `KernelAdmissionRequired`, never the request-rejected code.
#[test]
fn submit_curation_without_source_refuses_carrier_before_transport() {
    let job_id = "job-e2e-submit-curation-bare";
    let material = submit_material(job_id);
    let admission = submit_admission(&material);
    let job = job_with_handles(job_id, JobClass::Curation);
    let mut port = AuthenticatedKernelJobPort::for_test(
        material,
        admission.clone(),
        Box::new(ClosedTestTransport),
        None,
    )
    .expect("test port must construct");
    let refused =
        <AuthenticatedKernelJobPort as KernelJobPort>::submit(&mut port, &admission, &job);
    let Err(error) = refused else {
        panic!("carrier-less curation submit must refuse at the carrier check");
    };
    assert!(
        matches!(
            error,
            DreamerError::InvalidAdmission(reason) if reason == CURATION_CARRIER_REFUSAL
        ),
        "refusal must be exactly the carrier-check reason, got {error:?}"
    );
    assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
}

/// The public `submit` path refuses a non-admitted class at the Slice-A gate
/// with its exact class payload — before any transport contact.
#[test]
fn submit_refused_class_refuses_before_transport() {
    let job_id = "job-e2e-submit-clarification";
    let material = submit_material(job_id);
    let admission = submit_admission(&material);
    let job = job_with_handles(job_id, JobClass::Clarification);
    let mut port = AuthenticatedKernelJobPort::for_test(
        material,
        admission.clone(),
        Box::new(ClosedTestTransport),
        None,
    )
    .expect("test port must construct");
    let refused =
        <AuthenticatedKernelJobPort as KernelJobPort>::submit(&mut port, &admission, &job);
    assert!(
        matches!(
            refused,
            Err(DreamerError::UnsupportedJobClass(JobClass::Clarification))
        ),
        "clarification submit must refuse with its class payload, got {refused:?}"
    );
    assert_eq!(
        refused.as_ref().map_err(DreamerError::code),
        Err("DREAMER_REQUEST_REJECTED")
    );
}

/// The public `submit` path stops a valid generic-track job at the Slice-2
/// controller gate: the refusal names the Governor-resolved controller
/// material — no class refusal, no transport contact.
#[test]
fn submit_orientation_stops_at_controller_gate() {
    let job_id = "job-e2e-submit-orientation";
    let material = submit_material(job_id);
    let admission = submit_admission(&material);
    let job = job_with_handles(job_id, JobClass::Orientation);
    let mut port = AuthenticatedKernelJobPort::for_test(
        material,
        admission.clone(),
        Box::new(ClosedTestTransport),
        None,
    )
    .expect("test port must construct");
    let refused =
        <AuthenticatedKernelJobPort as KernelJobPort>::submit(&mut port, &admission, &job);
    let Err(error) = refused else {
        panic!("orientation submit must stop at the controller gate");
    };
    assert!(
        matches!(
            &error,
            DreamerError::InvalidAdmission(reason) if reason.contains("Governor-resolved")
        ),
        "controller gate must name the Governor-resolved material, got {error:?}"
    );
    assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
    assert!(
        !matches!(error, DreamerError::UnsupportedJobClass(_)),
        "orientation is admitted and must never refuse by class, got {error:?}"
    );
    assert!(
        !matches!(error, DreamerError::KernelAdmissionRequired(_)),
        "the controller gate must precede any transport contact, got {error:?}"
    );
}

/// Echo claim transport for the public-path success proof: binds identity,
/// then answers the live-tail `STATUS` observation by echoing the submitted
/// request — never hardcoded job ids.
///
/// Mirrors the `kernel_port.rs` fake's `STATUS` answer shape (`RUNNING` state,
/// null disposition, null receipt) but derives every binding from the decoded
/// request: job/attempt/revision echo the `Status` operation, the fence echoes
/// the operation fence, and the lease pins the echoed attempt under the echoed
/// generation with a fresh wall-clock pin. The scope id rides from the test
/// material (the `Status` operation carries no scope field, so there is
/// nothing to echo); every other binding is request-derived. Any non-`STATUS`
/// kind fails closed: `submit`'s live tail only ever sends `STATUS`.
struct SuccessClaimTransport {
    scope_id: String,
}

impl SuccessClaimTransport {
    /// Binds the scope the echoed `STATUS` reply projects: the `Status`
    /// operation carries job/attempt/revision/fence but no scope, so the
    /// material scope travels here instead of being invented per reply.
    fn for_scope(scope_id: &str) -> Self {
        Self {
            scope_id: scope_id.to_owned(),
        }
    }

    /// Decodes and validates the submitted request from the wire payload,
    /// like the `kernel_port.rs` fake's `submitted_request`: the closed wire
    /// id selects the route, the typed `request` field must decode and
    /// validate, and only the worker claim arm answers.
    fn submitted_request(
        payload: &serde_json::Value,
    ) -> Result<DurableJobRequest, KernelPortError> {
        let denied = |detail: String| KernelPortError::Transport(detail);
        if payload.get("operation").and_then(serde_json::Value::as_str) != Some(DREAMER_JOB_WIRE_ID)
        {
            return Err(denied(
                "success transport admits only the dreamer job wire".to_owned(),
            ));
        }
        let request_value = payload.get("request").cloned().ok_or_else(|| {
            denied("success transport payload carries no typed request".to_owned())
        })?;
        let request: DurableJobRequest =
            serde_json::from_value(request_value).map_err(|error| denied(error.to_string()))?;
        request
            .validate()
            .map_err(|error| denied(error.to_string()))?;
        if request.role != JobRole::Worker {
            return Err(denied(
                "success transport admits only the worker claim arm".to_owned(),
            ));
        }
        Ok(request)
    }

    /// Answers one `STATUS` observation by echoing the submitted request into
    /// the fake's `RUNNING` reply shape: exact identity echo, echoed
    /// job/attempt/revision/scope/fence bindings, and the echoed lease pin
    /// with a fresh wall-clock interval (`issued_at` < `expires_at`, expiry in
    /// the future). Any other operation kind fails closed.
    fn status_reply(
        &self,
        request: &DurableJobRequest,
    ) -> Result<serde_json::Value, KernelPortError> {
        let denied = |detail: String| KernelPortError::Transport(detail);
        let JobOperation::Status {
            job_id,
            attempt_id,
            expected_revision,
            expected_fence,
        } = &request.operation
        else {
            return Err(denied(
                "success transport admits only the STATUS observation".to_owned(),
            ));
        };
        let fence_json =
            serde_json::to_value(expected_fence).map_err(|error| denied(error.to_string()))?;
        let generation = fence_json
            .get("resource_generation")
            .cloned()
            .ok_or_else(|| denied("echoed fence carries no resource generation".to_owned()))?;
        let identity_json = serde_json::to_value(&request.request_identity)
            .map_err(|error| denied(error.to_string()))?;
        let product_id = request
            .request_identity
            .request
            .request
            .metadata
            .product_id
            .as_str()
            .to_owned();
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_millis()),
        )
        .unwrap_or(0);
        let issued_at = now_ms.saturating_sub(1_000).max(1);
        let expires_at = now_ms
            .saturating_add(60_000)
            .max(issued_at.saturating_add(1));
        let lease = serde_json::json!({
            "job_id": job_id.as_str(),
            "attempt_id": attempt_id.as_str(),
            "lease_id": {
                "namespace": "eliot.governor.work-lease",
                "revision": "v1",
                "value": format!("{}-lease", attempt_id.as_str()),
            },
            "owner_artifact_id": attempt_id.as_str(),
            "resource_generation": generation.clone(),
            "state_fence": fence_json.clone(),
            "issued_at_unix_ms": issued_at,
            "expires_at_unix_ms": expires_at,
            "revision": expected_revision,
        });
        Ok(serde_json::json!({
            "request_identity": identity_json,
            "job_id": job_id.as_str(),
            "attempt_id": attempt_id.as_str(),
            "scope": {
                "scope_id": self.scope_id.as_str(),
                "product_id": product_id,
                "resource_generation": generation,
                "state_fence": fence_json,
            },
            "revision": expected_revision,
            "state": "RUNNING",
            "disposition": null,
            "receipt_id": null,
            "lease": lease,
            "checkpoint": null,
            "result_under_verification": null,
            "outcome": null,
            "selection_coverage": [],
            "selection_frontier": null,
        }))
    }
}

impl ClaimTransport for SuccessClaimTransport {
    fn bind_identity(
        &mut self,
        _fence: &StateFence,
        _operation_id: &str,
    ) -> Result<(), KernelPortError> {
        Ok(())
    }

    fn transact(
        &mut self,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, KernelPortError> {
        if operation != DREAMER_JOB_WIRE_ID {
            return Err(KernelPortError::Transport(
                "success transport admits only the dreamer job wire".to_owned(),
            ));
        }
        let request = Self::submitted_request(&payload)?;
        self.status_reply(&request)
    }
}

/// The public `submit` path with an injected carrier and a live-bound echo
/// transport succeeds end to end: the screen admits, A-31 routes exactly
/// once, and the live tail observes `RUNNING` from the echoed `STATUS` reply,
/// so `submit` returns `Ok` with the Kernel-owned state and the computed
/// Curation result attached. The closed-transport twin proves the fail-closed
/// tail; this test proves the success tail on the same code production
/// executes.
#[test]
fn submit_curation_with_source_succeeds_with_curation_result_view() {
    let job_id = "job-e2e-submit-curation-live";
    let material = submit_material(job_id);
    let admission = submit_admission(&material);
    let job = single_target_job(job_id);
    let source = TestCarrierSource::new();
    let mut port = AuthenticatedKernelJobPort::for_test(
        material.clone(),
        admission.clone(),
        Box::new(SuccessClaimTransport::for_scope(&material.scope_id)),
        Some(&source),
    )
    .expect("test port must construct");
    let view = <AuthenticatedKernelJobPort as KernelJobPort>::submit(&mut port, &admission, &job)
        .expect("curation submit with a live-bound transport must succeed");
    assert_eq!(view.state, JobState::Running);
    assert_eq!(view.job_id.as_str(), job_id);
    let Some(DreamResult::Curation {
        job_id: result_job_id,
        candidates,
        ..
    }) = view.result
    else {
        panic!("curation submit must project a curation result view, got {view:?}");
    };
    let canonical = admission_of(&admission, &job)
        .expect("e2e admission must derive")
        .canonical_id();
    assert_eq!(result_job_id, canonical);
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
    assert_eq!(
        source.calls(),
        1,
        "A-31 must invoke the routed handler exactly once"
    );
}
