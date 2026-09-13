//! H1 native-invocation proof: a test double implementing the new A-03
//! [`NativeCurationHandler`][eliot_dreamer_contracts::NativeCurationHandler]
//! trait is invoked once against the selected injected port and receives the
//! full typed result content back.
//!
//! Imports are compile-time truth for scope: this file uses only
//! `eliot_dreamer_contracts`, `eliot_contracts`, `std`, and `serde_json` —
//! no concrete handler crate and no A-05 `eliot-dreamer-candidate-validation`
//! import. The manifest/source absence of that dependency is proven
//! executably by `no_a05_dependency` in `tests/rejection_vocab.rs`.

#![allow(clippy::expect_used)]

use std::cell::Cell;

use eliot_contracts::{
    AuthorityEpoch, ReceiptId, RequestId, ResourceGeneration, StateFence, sha256_hex,
};
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::curation::{MergePayload, TargetEvidence};
use eliot_dreamer_contracts::registry::family_kinds;
use eliot_dreamer_contracts::{
    AtomicityMode, BoundCurationCall, BudgetLimits, BudgetUsage, BundleCompleteness,
    BundleMaterial, CandidateDisposition, ContractViolation, CurationAcceptanceCtx, CurationFamily,
    CurationHandlerDescriptor, CurationHandlerPort, CurationHandlerRegistry, CurationKind,
    CurationPayload, DreamInputBundle, DreamJobInput, FullCurationResult, GroundedDreamDraft,
    JobClass, NativeCurationHandler, PreservationDimension, PreservationReport,
    ProducedCurationContent, Requester, RequesterOrigin, ScreenBinding, ScreenState,
    SourceDisposition, TargetDenominator, TypedCurationHandlerRequest, ValidatedCurationItem,
    ValidationReceipt, canonical_bytes, digest_hex, invoke, request_digest_of,
};
use eliot_dreamer_contracts::{ClaimResidue, SupportState};
use eliot_dreamer_contracts::{OmissionHandle, job};

/// Faithful test double for the new A-03 trait: counts real calls, verifies
/// it observed the selected binding, and echoes the accepted payload facets
/// so the hub's retarget/invented-evidence checks run against real content.
struct FixtureHandler {
    calls: Cell<usize>,
    port_id: String,
    handler_id: String,
    counterevidence_refs: Vec<String>,
}

fn passing_report() -> PreservationReport {
    PreservationReport {
        verdicts: eliot_dreamer_contracts::PRESERVATION_DIMENSIONS
            .iter()
            .map(|dimension| DimensionVerdict {
                dimension: PreservationDimension::parse(dimension).expect("known dimension"),
                passed: true,
                known: true,
                note: format!("{dimension} holds"),
            })
            .collect(),
    }
}

impl NativeCurationHandler for FixtureHandler {
    fn handle(
        &self,
        call: &BoundCurationCall,
    ) -> Result<ProducedCurationContent, ContractViolation> {
        self.calls.set(self.calls.get() + 1);
        if call.port.port_id != self.port_id || call.port.descriptor.handler_id != self.handler_id {
            return Err(ContractViolation::BindingMismatch {
                field: "port_id",
                reason: "double observed an unselected binding".to_owned(),
            });
        }
        Ok(ProducedCurationContent {
            payload: call.request.payload.clone(),
            disposition: CandidateDisposition::Candidate,
            preservation: passing_report(),
            support_note: "supported by source-b".to_owned(),
            rollback_note: "drop result to roll back".to_owned(),
            counterevidence_refs: self.counterevidence_refs.clone(),
        })
    }
}

struct Fixtures {
    job: DreamJobInput,
    bundle: DreamInputBundle,
    grounded: GroundedDreamDraft,
    item: ValidatedCurationItem,
    screen: ScreenBinding,
    request: TypedCurationHandlerRequest,
    usage: BudgetUsage,
    port: CurationHandlerPort,
    registry: CurationHandlerRegistry,
}

fn material(handle: &str) -> BundleMaterial {
    BundleMaterial {
        handle: handle.to_owned(),
        disposition: SourceDisposition::Required,
        bytes: 12,
        digest: sha256_hex(handle.as_bytes()),
    }
}

fn closed_registry() -> CurationHandlerRegistry {
    let mut registry = CurationHandlerRegistry::new();
    for (family, id) in [
        (CurationFamily::Classification, "acc-cls"),
        (CurationFamily::Relation, "acc-rel"),
        (CurationFamily::Episode, "acc-ep"),
        (CurationFamily::Concept, "acc-con"),
        (CurationFamily::Procedure, "acc-proc"),
        (CurationFamily::Failure, "acc-fail"),
        (CurationFamily::StructureRepair, "acc-sr"),
        (CurationFamily::Reconsolidation, "acc-recon"),
        (CurationFamily::Accessibility, "acc-a11y"),
        (CurationFamily::MemoryRepair, "acc-mr"),
    ] {
        registry
            .register(CurationHandlerDescriptor {
                family,
                handler_id: id.to_owned(),
                accepted_kinds: family_kinds(family).to_vec(),
            })
            .expect("fixture descriptor registers");
    }
    registry
}

fn fixture_fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn fixture_job(fence: &StateFence) -> DreamJobInput {
    DreamJobInput {
        schema_version: job::DREAM_JOB_SCHEMA_VERSION,
        job_class: JobClass::Curation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".to_owned(),
            session: None,
        },
        operation_id: "op-1".to_owned(),
        idempotency_key: "idem-1".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence.clone(),
        privacy_profile: job::PRIVACY_LOCAL_ONLY.to_owned(),
        contract_ref: "contract-1".to_owned(),
        policy_ref: "policy-1".to_owned(),
        budget: BudgetLimits {
            input_bytes: Some(1024),
            output_bytes: Some(1024),
            source_width: Some(8),
            reference_width: Some(8),
            model_calls: Some(4),
            attempts: Some(2),
            candidates: Some(2),
            wall_ms: Some(1000),
            work_fan_out: Some(2),
            report_bytes: Some(1024),
            max_stu: Some(10),
        },
        deadline_ms: None,
        frozen_manifest_digest: sha256_hex(b"manifest"),
    }
}

fn fixture_bundle(fence: &StateFence) -> DreamInputBundle {
    DreamInputBundle {
        schema_version: 1,
        job_id: "job-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence.clone(),
        manifest_digest: sha256_hex(b"manifest"),
        materials: vec![
            material("source-a"),
            material("a"),
            material("b"),
            material("ab"),
        ],
        omissions: vec![OmissionHandle {
            handle: "source-b".to_owned(),
            reason: "upstream unavailable".to_owned(),
            reversible: true,
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            digest: sha256_hex(b"omission-source-b"),
            nonrecoverable_reason: None,
        }],
        completeness: BundleCompleteness::PartialForScope,
        authoritative_denominator: None,
    }
}

fn fixture_grounded() -> GroundedDreamDraft {
    GroundedDreamDraft {
        schema_version: 1,
        job_id: "job-1".to_owned(),
        draft_digest: sha256_hex(b"model-draft"),
        residues: vec![ClaimResidue {
            claim: "Caching cuts tail latency.".to_owned(),
            state: SupportState::Partial,
            detail: "supported for warm keys only".to_owned(),
        }],
        coverage_note: "covers the single model claim".to_owned(),
    }
}

fn fixture_receipt(fence: &StateFence, grounded: &GroundedDreamDraft) -> ValidationReceipt {
    ValidationReceipt {
        schema_version: 1,
        validator_contract: "a05-validator".to_owned(),
        validator_policy: "policy-7".to_owned(),
        job_id: "job-1".to_owned(),
        draft_digest: grounded.draft_digest.clone(),
        bundle_digest: sha256_hex(b"bundle"),
        manifest_digest: sha256_hex(b"manifest"),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        input_digest: sha256_hex(b"validator-input"),
        output_digest: sha256_hex(b"validator-output"),
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: "candidate-only".to_owned(),
        state_fence: fence.clone(),
        preservation_digest: sha256_hex(b"preservation"),
        budget_digest: sha256_hex(b"budget"),
    }
}

fn fixture_payload() -> CurationPayload {
    CurationPayload::Merge(MergePayload {
        left: "a".to_owned(),
        right: "b".to_owned(),
        merged: "ab".to_owned(),
        target_evidence: TargetEvidence {
            targets: vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()],
            evidence_refs: vec!["source-b".to_owned()],
        },
    })
}

fn fixture_denominator() -> TargetDenominator {
    TargetDenominator {
        mode: AtomicityMode::AllOrNothing,
        members: vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()],
        expected_total: 3,
    }
}

fn fixture_item(
    fence: &StateFence,
    job: &DreamJobInput,
    receipt: &ValidationReceipt,
    payload: &CurationPayload,
    denominator: &TargetDenominator,
) -> ValidatedCurationItem {
    ValidatedCurationItem {
        receipt: receipt.clone(),
        kind_spelling: "merge".to_owned(),
        family_spelling: "structure_repair".to_owned(),
        payload: payload.clone(),
        denominator: denominator.clone(),
        source_digest: sha256_hex(b"source-a"),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence.clone(),
        job_digest: digest_hex(&canonical_bytes(job).expect("job has canonical bytes")),
        requester: job.requester.clone(),
        budget_note: "within dimension".to_owned(),
    }
}

fn fixture_screen(
    fence: &StateFence,
    item: &ValidatedCurationItem,
    grounded: &GroundedDreamDraft,
) -> ScreenBinding {
    ScreenBinding {
        request_id: RequestId::new("req-1").expect("request id"),
        receipt_id: ReceiptId::new("rcpt-1").expect("receipt id"),
        screened_targets: vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()],
        source_snapshot: "snap-1".to_owned(),
        source_revision: "rev-1".to_owned(),
        profile: "default".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence.clone(),
        state: ScreenState::Eligible,
        result_digest: "a".repeat(64),
        item_digest: item.item_digest(grounded).expect("item digest"),
    }
}

fn fixture_request(
    fence: &StateFence,
    payload: &CurationPayload,
    denominator: &TargetDenominator,
    screen: &ScreenBinding,
) -> TypedCurationHandlerRequest {
    TypedCurationHandlerRequest {
        request_id: "req-1".to_owned(),
        receipt_id: "rcpt-1".to_owned(),
        source_snapshot: "snap-1".to_owned(),
        source_revision: "rev-1".to_owned(),
        profile: "default".to_owned(),
        kind: CurationKind::Merge,
        family: CurationFamily::StructureRepair,
        job_id: "job-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence.clone(),
        payload: payload.clone(),
        denominator: denominator.clone(),
        screen_binding: Some(screen.clone()),
    }
}

fn fixture_port() -> CurationHandlerPort {
    CurationHandlerPort {
        port_id: "port-sr-1".to_owned(),
        descriptor: CurationHandlerDescriptor {
            family: CurationFamily::StructureRepair,
            handler_id: "acc-sr".to_owned(),
            accepted_kinds: family_kinds(CurationFamily::StructureRepair).to_vec(),
        },
    }
}

fn fixtures() -> Fixtures {
    let fence = fixture_fence();
    let job = fixture_job(&fence);
    let bundle = fixture_bundle(&fence);
    let grounded = fixture_grounded();
    let receipt = fixture_receipt(&fence, &grounded);
    let payload = fixture_payload();
    let denominator = fixture_denominator();
    let item = fixture_item(&fence, &job, &receipt, &payload, &denominator);
    let screen = fixture_screen(&fence, &item, &grounded);
    let request = fixture_request(&fence, &payload, &denominator, &screen);
    Fixtures {
        job,
        bundle,
        grounded,
        item,
        screen,
        request,
        usage: BudgetUsage::default(),
        port: fixture_port(),
        registry: closed_registry(),
    }
}

fn ctx_for<'a>(fx: &'a Fixtures, item: &'a ValidatedCurationItem) -> CurationAcceptanceCtx<'a> {
    CurationAcceptanceCtx {
        job: &fx.job,
        bundle: &fx.bundle,
        receipt: &item.receipt,
        screen: &fx.screen,
        grounded: &fx.grounded,
        request: &fx.request,
        usage: &fx.usage,
    }
}

fn handler() -> FixtureHandler {
    FixtureHandler {
        calls: Cell::new(0),
        port_id: "port-sr-1".to_owned(),
        handler_id: "acc-sr".to_owned(),
        counterevidence_refs: vec!["e-9".to_owned()],
    }
}

fn assert_binding(err: &ContractViolation, field: &str) {
    assert!(
        matches!(err, ContractViolation::BindingMismatch { field: got, .. } if *got == field),
        "expected BindingMismatch on {field}, got {err:?}"
    );
}

#[test]
fn invoke_calls_selected_binding_once_with_full_result_content() {
    let fx = fixtures();
    let handler = handler();
    let ctx = ctx_for(&fx, &fx.item);
    let result = invoke(&fx.port, &handler, &fx.item, &ctx, &fx.registry).expect("invoke accepts");
    assert_eq!(
        handler.calls.get(),
        1,
        "selected binding invoked exactly once"
    );

    assert_eq!(result.request_id, "req-1");
    assert_eq!(result.job_id, "job-1");
    assert_eq!(result.scope_id, "scope-1");
    assert_eq!(result.task_id, "task-1");
    assert_eq!(result.kind, CurationKind::Merge);
    assert_eq!(result.family, CurationFamily::StructureRepair);
    assert_eq!(result.handler_id, "acc-sr");
    assert_eq!(result.port_id, "port-sr-1");
    assert_eq!(
        result.registry_digest,
        fx.registry.digest().expect("closed registry digests")
    );
    assert_eq!(result.state_fence, fx.item.state_fence);

    // Full typed content, not a digest alone.
    assert_eq!(result.content.payload, fx.item.payload);
    assert_eq!(result.content.payload.kind(), CurationKind::Merge);
    assert!(result.content.preservation.overall().is_ok());
    assert_eq!(
        result.content.payload.facets().targets,
        vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()]
    );
    assert_eq!(
        result.content.payload.facets().evidence_refs,
        vec!["source-b".to_owned()]
    );
    assert_eq!(result.content.counterevidence_refs, vec!["e-9".to_owned()]);
    assert_eq!(result.content.disposition, CandidateDisposition::Candidate);

    // Digests bind the exact call and content.
    assert_eq!(
        result.request_digest,
        request_digest_of(&fx.request).expect("request digests")
    );
    result.validate().expect("sealed result validates");
    let wire = serde_json::to_string(&result).expect("result serializes");
    let back: FullCurationResult = serde_json::from_str(&wire).expect("result deserializes");
    assert_eq!(back, result);
    back.validate().expect("round-tripped result validates");
}

#[test]
fn altered_item_fence_port_and_result_bindings_fail_closed() {
    let fx = fixtures();
    let handler = handler();

    // Mutated item identity fails before any handler call.
    let mut bad_item = fx.item.clone();
    bad_item.task_id = "task-9".to_owned();
    let err = invoke(
        &fx.port,
        &handler,
        &bad_item,
        &ctx_for(&fx, &bad_item),
        &fx.registry,
    )
    .expect_err("mutated item must fail");
    assert_binding(&err, "task_scope_fence");
    assert_eq!(handler.calls.get(), 0);

    // Fence drift between the accepted item and the job fails closed.
    let mut bad_fence = fx.item.clone();
    let generation = ResourceGeneration::new(2).expect("generation");
    bad_fence.state_fence = StateFence::new(AuthorityEpoch::genesis(), generation);
    bad_fence.receipt.state_fence = bad_fence.state_fence.clone();
    let err = invoke(
        &fx.port,
        &handler,
        &bad_fence,
        &ctx_for(&fx, &bad_fence),
        &fx.registry,
    )
    .expect_err("fence drift must fail");
    assert_binding(&err, "state_fence");
    assert_eq!(handler.calls.get(), 0);

    // A live port carrying a valid but unregistered descriptor fails.
    let mut rogue = fx.port.clone();
    rogue.descriptor.handler_id = "rogue-sr".to_owned();
    let err = invoke(
        &rogue,
        &handler,
        &fx.item,
        &ctx_for(&fx, &fx.item),
        &fx.registry,
    )
    .expect_err("unregistered descriptor must fail");
    assert_binding(&err, "handler_descriptor");
    assert_eq!(handler.calls.get(), 0);

    // A registered port of the wrong family fails the request binding.
    let other_port = CurationHandlerPort {
        port_id: "port-cls-1".to_owned(),
        descriptor: CurationHandlerDescriptor {
            family: CurationFamily::Classification,
            handler_id: "acc-cls".to_owned(),
            accepted_kinds: family_kinds(CurationFamily::Classification).to_vec(),
        },
    };
    let err = invoke(
        &other_port,
        &handler,
        &fx.item,
        &ctx_for(&fx, &fx.item),
        &fx.registry,
    )
    .expect_err("wrong-family port must fail");
    assert_binding(&err, "family");
    assert_eq!(handler.calls.get(), 0);

    // A sealed result with rewritten content no longer binds its digest.
    let ctx = ctx_for(&fx, &fx.item);
    let result = invoke(&fx.port, &handler, &fx.item, &ctx, &fx.registry).expect("invoke accepts");
    assert_eq!(handler.calls.get(), 1);
    let mut tampered = result.clone();
    tampered.content.support_note = "rewritten".to_owned();
    assert_binding(
        &tampered
            .validate()
            .expect_err("rewritten content must fail"),
        "result_digest",
    );
    let mut swapped = result.clone();
    swapped.registry_digest = "b".repeat(64);
    assert_binding(
        &swapped
            .validate()
            .expect_err("swapped registry digest must fail"),
        "result_digest",
    );
}

#[test]
fn evidence_ref_in_targets_and_counterevidence_as_target_rejected() {
    let fx = fixtures();
    let handler = handler();

    // An immutable evidence handle promoted to a mutable target never validates.
    let mut bad_item = fx.item.clone();
    if let CurationPayload::Merge(inner) = &mut bad_item.payload {
        inner.target_evidence.targets.push("source-b".to_owned());
    }
    let err = invoke(
        &fx.port,
        &handler,
        &bad_item,
        &ctx_for(&fx, &bad_item),
        &fx.registry,
    )
    .expect_err("evidence-as-target must fail");
    assert!(
        matches!(err, ContractViolation::KindPayload(_)),
        "expected KindPayload, got {err:?}"
    );
    assert_eq!(handler.calls.get(), 0);

    // Counterevidence naming a mutable target is rejected after the call.
    let counter = FixtureHandler {
        calls: Cell::new(0),
        port_id: "port-sr-1".to_owned(),
        handler_id: "acc-sr".to_owned(),
        counterevidence_refs: vec!["a".to_owned()],
    };
    let err = invoke(
        &fx.port,
        &counter,
        &fx.item,
        &ctx_for(&fx, &fx.item),
        &fx.registry,
    )
    .expect_err("counterevidence-as-target must fail");
    assert_binding(&err, "counterevidence_refs");
    assert_eq!(
        counter.calls.get(),
        1,
        "handler ran; the hub rejected its output"
    );
}
