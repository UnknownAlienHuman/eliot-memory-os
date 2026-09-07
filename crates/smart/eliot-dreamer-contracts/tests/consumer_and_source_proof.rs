//! Consumer-compile and source-proof integration tests.
//! Markers 44/45: hub consumers compile without reverse imports; hub sources
//! contain no algorithm, provider, I/O, or escape-hatch surface (`include_str!`).

#![allow(clippy::expect_used)]

use eliot_contracts::{AuthorityEpoch, ReceiptId, RequestId, ResourceGeneration, StateFence};
use eliot_dreamer_contracts::curation::{ClassificationPayload, TargetEvidence, route_payload};
use eliot_dreamer_contracts::job::{Requester, RequesterOrigin};
use eliot_dreamer_contracts::{
    AtomicityMode, BudgetLimits, BudgetUsage, BundleCompleteness, BundleMaterial,
    CURATION_WIRE_KINDS, ClaimResidue, ContractViolation, CurationAcceptanceCtx, CurationFamily,
    CurationHandlerDescriptor, CurationHandlerPort, CurationHandlerRegistry, CurationKind,
    CurationPayload, DreamInputBundle, DreamJobInput, GroundedDreamDraft, JobClass, ModelDraft,
    OmissionHandle, ScreenBinding, ScreenEligibility, ScreenReference, ScreenState,
    SourceDisposition, SupportState, TargetDenominator, TypedCurationHandlerRequest,
    ValidatedCurationItem, ValidationReceipt, canonical_bytes, digest_hex, family_of, parse_kind,
};

fn assert_stable(check: impl Fn() -> bool, ctx: &str) {
    assert_eq!(check(), check(), "{ctx} must be stable");
}
fn assembler_shape(job: &DreamJobInput, bundle: &DreamInputBundle) {
    assert_stable(|| job.validate().is_ok(), "assembler job");
    assert_stable(|| bundle.validate().is_ok(), "assembler bundle");
}
fn validator_shape(draft: &ModelDraft, receipt: &ValidationReceipt) {
    assert_stable(|| draft.validate().is_ok(), "validator draft");
    assert_stable(|| receipt.validate().is_ok(), "validator receipt");
}
fn replacer_shape(registry: &CurationHandlerRegistry, screen: &ScreenReference) {
    assert_stable(|| registry.validate_closure().is_ok(), "replacer registry");
    assert_stable(|| screen.validate().is_ok(), "replacer screen");
}
fn handler_shape(job: &DreamJobInput, registry: &CurationHandlerRegistry) {
    assert_stable(|| job.validate().is_ok(), "handler job");
    assert_stable(|| registry.validate_closure().is_ok(), "handler registry");
}

fn consumer_shape(
    bundle: &DreamInputBundle,
    draft: &ModelDraft,
    receipt: &ValidationReceipt,
    screen: &ScreenReference,
) {
    assert_stable(|| bundle.validate().is_ok(), "consumer bundle");
    assert_stable(|| draft.validate().is_ok(), "consumer draft");
    assert_stable(|| receipt.validate().is_ok(), "consumer receipt");
    assert_stable(|| screen.validate().is_ok(), "consumer screen");
}

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn fixture_job() -> DreamJobInput {
    DreamJobInput {
        schema_version: 1,
        job_class: JobClass::Orientation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".to_owned(),
            session: None,
        },
        operation_id: "op-44".to_owned(),
        idempotency_key: "idem-44".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        privacy_profile: "local_only".to_owned(),
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
        frozen_manifest_digest: "f".repeat(64),
    }
}

fn fixture_bundle() -> DreamInputBundle {
    DreamInputBundle {
        schema_version: 1,
        job_id: "job-44".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
        manifest_digest: "f".repeat(64),
        materials: vec![
            BundleMaterial {
                handle: "a".to_owned(),
                disposition: SourceDisposition::Required,
                bytes: 12,
                digest: "a".repeat(64),
            },
            BundleMaterial {
                handle: "b".to_owned(),
                disposition: SourceDisposition::Required,
                bytes: 12,
                digest: "b".repeat(64),
            },
            BundleMaterial {
                handle: "ab".to_owned(),
                disposition: SourceDisposition::Required,
                bytes: 12,
                digest: "ab".repeat(32),
            },
        ],
        omissions: vec![OmissionHandle {
            handle: "e-1".to_owned(),
            reason: "upstream unavailable".to_owned(),
            reversible: true,
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            digest: "e".repeat(64),
            nonrecoverable_reason: None,
        }],
        completeness: BundleCompleteness::PartialForScope,
        authoritative_denominator: None,
    }
}

fn fixture_draft() -> ModelDraft {
    ModelDraft {
        schema_version: 1,
        job_id: "job-44".to_owned(),
        statement: "Caching cuts tail latency.".to_owned(),
        source_handles: vec!["source-a".to_owned()],
        counterevidence: Vec::new(),
        uncertainty: "medium".to_owned(),
        expected_benefit: "Lower p99 if hit rate holds.".to_owned(),
        recommended_probes: Vec::new(),
        invalidation_conditions: Vec::new(),
        declared_confirmed_handles: Vec::new(),
    }
}

fn fixture_receipt() -> ValidationReceipt {
    ValidationReceipt {
        schema_version: 1,
        validator_contract: "a05-validator".to_owned(),
        validator_policy: "policy-7".to_owned(),
        job_id: "job-44".to_owned(),
        draft_digest: "a".repeat(64),
        bundle_digest: "f".repeat(64),
        manifest_digest: "f".repeat(64),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        input_digest: "b".repeat(64),
        output_digest: "c".repeat(64),
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: "candidate-only".to_owned(),
        state_fence: fence(),
        preservation_digest: "d".repeat(64),
        budget_digest: "e".repeat(64),
    }
}

fn fixture_grounded() -> GroundedDreamDraft {
    GroundedDreamDraft {
        schema_version: 1,
        job_id: "job-44".to_owned(),
        draft_digest: "a".repeat(64),
        residues: vec![ClaimResidue {
            claim: "cache helps".to_owned(),
            state: SupportState::Supported,
            detail: "manifest covers it".to_owned(),
        }],
        coverage_note: "covered".to_owned(),
    }
}

fn fixture_registry() -> (CurationHandlerRegistry, Vec<CurationHandlerPort>) {
    let mut registry = CurationHandlerRegistry::new();
    let mut ports = Vec::new();
    let mut seen: Vec<CurationFamily> = Vec::new();
    for spelling in CURATION_WIRE_KINDS {
        let family = family_of(parse_kind(spelling).expect("known wire kind"));
        if !seen.contains(&family) {
            seen.push(family);
        }
    }
    assert_eq!(seen.len(), 10, "fixture must cover ten families");
    for family in seen {
        let kinds: Vec<CurationKind> = CURATION_WIRE_KINDS
            .iter()
            .map(|spelling| parse_kind(spelling).expect("known wire kind"))
            .filter(|kind| family_of(*kind) == family)
            .collect();
        let descriptor = CurationHandlerDescriptor {
            family,
            handler_id: std::format!("acc-{}", family.as_str()),
            accepted_kinds: kinds,
        };
        registry
            .register(descriptor.clone())
            .expect("fixture descriptor registers");
        ports.push(CurationHandlerPort {
            port_id: std::format!("port-{}", family.as_str()),
            descriptor,
        });
    }
    (registry, ports)
}

fn fixture_screen() -> ScreenReference {
    ScreenReference {
        screen_id: "screen-44".to_owned(),
        request_id: RequestId::new("req-44").expect("request id"),
        receipt_id: ReceiptId::new("rcpt-44").expect("receipt id"),
        target_id: "target-44".to_owned(),
        result_digest: "c".repeat(64),
        item_digest: "d".repeat(64),
        profile: "default".to_owned(),
        source_snapshot: "snapshot-1".to_owned(),
        source_revision: "rev-7".to_owned(),
        denominator: "population".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        state: ScreenState::Eligible,
    }
}

fn typed_wire(kind: CurationKind) -> String {
    let body = match kind {
        CurationKind::Classification => r#""label":"memory","confidence_bps":9000"#,
        CurationKind::Relation => r#""from_handle":"a","to_handle":"b","relation":"refines""#,
        CurationKind::Episode => r#""episode":"ep-7","observed_at_ms":1700000000000"#,
        CurationKind::Concept => r#""concept":"fence","definition":"state dependency""#,
        CurationKind::Procedure => r#""procedure":"rotate","steps":3"#,
        CurationKind::Failure => r#""fingerprint":"fp-1","signature":"sig-1""#,
        CurationKind::Merge => r#""left":"a","right":"b","merged":"ab""#,
        CurationKind::Split => r#""whole":"ab","first":"a","second":"b""#,
        CurationKind::Reconsolidation => r#""target":"a","update":"refresh""#,
        CurationKind::Accessibility => r#""handle":"a","note":"captioned""#,
        CurationKind::Repair => r#""target":"a","repair":"relink""#,
    };
    std::format!(
        r#"{{"kind":"{kind_tag}",{body},"target_evidence":{{"targets":["a","b","ab"],"evidence_refs":["e-1"]}}}}"#,
        kind_tag = kind.as_str()
    )
}

fn assert_typed_dispatch(registry: &CurationHandlerRegistry, ports: &[CurationHandlerPort]) {
    let screened = vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()];
    let binding = ScreenBinding {
        request_id: RequestId::new("req-44").expect("request id"),
        receipt_id: ReceiptId::new("rcpt-44").expect("receipt id"),
        screened_targets: screened.clone(),
        source_snapshot: "snapshot-1".to_owned(),
        source_revision: "rev-7".to_owned(),
        profile: "default".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        state: ScreenState::Eligible,
        result_digest: "a".repeat(64),
        item_digest: "b".repeat(64),
    };
    let denominator = TargetDenominator {
        mode: AtomicityMode::PerMember,
        members: [screened, vec!["extra".to_owned()]].concat(),
        expected_total: 4,
    };
    for spelling in CURATION_WIRE_KINDS {
        let kind = parse_kind(spelling).expect("known wire kind");
        let family = family_of(kind);
        let port = ports.iter().find(|p| p.descriptor.family == family);
        let port = port.expect("ported family");
        assert!(port.descriptor.accepted_kinds.contains(&kind));
        port.validate().expect("port validates");
        assert!(registry.handlers.iter().any(|h| h == &port.descriptor));
        let payload = route_payload(kind, &typed_wire(kind)).expect("typed payload routes");
        assert_eq!(payload.kind(), kind, "discriminant routing");
        let request = TypedCurationHandlerRequest {
            request_id: "req-44".to_owned(),
            receipt_id: "rcpt-44".to_owned(),
            source_snapshot: "snapshot-1".to_owned(),
            source_revision: "rev-7".to_owned(),
            profile: "default".to_owned(),
            kind,
            family,
            job_id: "job-44".to_owned(),
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            state_fence: fence(),
            payload,
            denominator: denominator.clone(),
            screen_binding: Some(binding.clone()),
        };
        request.validate().expect("typed request validates");
        assert_eq!(request.family, port.descriptor.family);
    }
}

fn seam_fixtures(
    job: &DreamJobInput,
) -> (
    GroundedDreamDraft,
    BudgetUsage,
    String,
    Vec<String>,
    TargetDenominator,
) {
    let grounded = fixture_grounded();
    grounded.validate().expect("grounded validates");
    let usage = BudgetUsage::default();
    let job_digest = digest_hex(&canonical_bytes(job).expect("canonical job"));
    let screened = vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()];
    let denominator = TargetDenominator {
        mode: AtomicityMode::AllOrNothing,
        members: screened.clone(),
        expected_total: 3,
    };
    (grounded, usage, job_digest, screened, denominator)
}

fn seam_item(
    kind: CurationKind,
    family: CurationFamily,
    payload: CurationPayload,
    receipt: &ValidationReceipt,
    denominator: &TargetDenominator,
    job_digest: &str,
) -> ValidatedCurationItem {
    ValidatedCurationItem {
        receipt: receipt.clone(),
        kind_spelling: kind.as_str().to_owned(),
        family_spelling: family.as_str().to_owned(),
        payload,
        denominator: denominator.clone(),
        source_digest: "a".repeat(64),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        budget_note: "within limits".to_owned(),
        job_digest: job_digest.to_owned(),
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".to_owned(),
            session: None,
        },
    }
}

fn seam_screen(item_digest: &str) -> ScreenBinding {
    ScreenBinding {
        request_id: RequestId::new("req-44").expect("request id"),
        receipt_id: ReceiptId::new("rcpt-44").expect("receipt id"),
        screened_targets: vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()],
        source_snapshot: "snapshot-1".to_owned(),
        source_revision: "rev-7".to_owned(),
        profile: "default".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        state: ScreenState::Eligible,
        result_digest: "a".repeat(64),
        item_digest: item_digest.to_owned(),
    }
}

fn seam_request(
    kind: CurationKind,
    family: CurationFamily,
    payload: CurationPayload,
    denominator: &TargetDenominator,
    screen: &ScreenBinding,
) -> TypedCurationHandlerRequest {
    TypedCurationHandlerRequest {
        request_id: "req-44".to_owned(),
        receipt_id: "rcpt-44".to_owned(),
        source_snapshot: "snapshot-1".to_owned(),
        source_revision: "rev-7".to_owned(),
        profile: "default".to_owned(),
        kind,
        family,
        job_id: "job-44".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
        payload,
        denominator: denominator.clone(),
        screen_binding: Some(screen.clone()),
    }
}

fn seam_ctx<'a>(
    parts: (
        &'a DreamJobInput,
        &'a DreamInputBundle,
        &'a ValidationReceipt,
        &'a GroundedDreamDraft,
        &'a BudgetUsage,
    ),
    screen: &'a ScreenBinding,
    request: &'a TypedCurationHandlerRequest,
) -> CurationAcceptanceCtx<'a> {
    let (job, bundle, receipt, grounded, usage) = parts;
    CurationAcceptanceCtx {
        job,
        bundle,
        receipt,
        screen,
        grounded,
        usage,
        request,
    }
}

fn assert_item_accept_seam(
    job: &DreamJobInput,
    bundle: &DreamInputBundle,
    receipt: &ValidationReceipt,
) {
    let (grounded, usage, job_digest, _screened, denominator) = seam_fixtures(job);
    let parts = (job, bundle, receipt, &grounded, &usage);
    for spelling in CURATION_WIRE_KINDS {
        let kind = parse_kind(spelling).expect("known wire kind");
        let family = family_of(kind);
        let payload = route_payload(kind, &typed_wire(kind)).expect("typed payload routes");
        assert_eq!(payload.kind(), kind, "discriminant routing");
        let item = seam_item(
            kind,
            family,
            payload.clone(),
            receipt,
            &denominator,
            &job_digest,
        );
        item.validate().expect("item validates");
        let digest = item.item_digest(&grounded).expect("item digest");
        assert_eq!(digest.len(), 64, "item digest is sha256 hex");
        let mut probe = item.clone();
        probe.task_id = "task-9".into();
        assert_ne!(
            probe.item_digest(&grounded).expect("digest"),
            digest,
            "digest tracks task identity"
        );
        let screen = seam_screen(&digest);
        let request = seam_request(kind, family, payload, &denominator, &screen);
        request.validate().expect("seam request validates");
        let ctx = seam_ctx(parts, &screen, &request);
        item.accept(&ctx).expect("accept ok");
        assert_eq!(item.family_spelling, family.as_str());
    }
}

fn assert_item_accept_negatives(
    job: &DreamJobInput,
    bundle: &DreamInputBundle,
    receipt: &ValidationReceipt,
) {
    let (grounded, usage, job_digest, screened, denominator) = seam_fixtures(job);
    let parts = (job, bundle, receipt, &grounded, &usage);
    let kind = parse_kind(CURATION_WIRE_KINDS[0]).expect("known wire kind");
    let family = family_of(kind);
    let payload = route_payload(kind, &typed_wire(kind)).expect("typed payload routes");
    let item = seam_item(
        kind,
        family,
        payload.clone(),
        receipt,
        &denominator,
        &job_digest,
    );
    let digest = item.item_digest(&grounded).expect("item digest");
    let screen = seam_screen(&digest);
    let request = seam_request(kind, family, payload, &denominator, &screen);
    let mut wrong_screen = screen.clone();
    wrong_screen.item_digest = "c".repeat(64);
    let ctx = seam_ctx(parts, &wrong_screen, &request);
    assert!(item.accept(&ctx).is_err(), "wrong screen digest must fail");
    let mut loose = item.clone();
    loose.denominator = TargetDenominator {
        mode: AtomicityMode::PerMember,
        members: [screened, vec!["extra".to_owned()]].concat(),
        expected_total: 4,
    };
    let mut loose_screen = screen.clone();
    loose_screen.item_digest = loose.item_digest(&grounded).expect("digest");
    let mut loose_request = request.clone();
    loose_request.denominator = loose.denominator.clone();
    let ctx = seam_ctx(parts, &loose_screen, &loose_request);
    loose.accept(&ctx).expect("per-member subset accepts");
    loose.denominator.mode = AtomicityMode::AllOrNothing;
    let mut strict_screen = screen.clone();
    strict_screen.item_digest = loose.item_digest(&grounded).expect("digest");
    let ctx = seam_ctx(parts, &strict_screen, &request);
    assert!(
        loose.accept(&ctx).is_err(),
        "all-or-nothing subset must fail"
    );
}

fn assert_target_evidence_roles() {
    let overlap = TargetEvidence {
        targets: vec!["a".into()],
        evidence_refs: vec!["a".into()],
    };
    assert!(matches!(
        overlap.validate("classification"),
        Err(ContractViolation::KindPayload(_))
    ));
    let bad = CurationPayload::Classification(ClassificationPayload {
        label: "m".into(),
        confidence_bps: 9_000,
        target_evidence: overlap,
    });
    let bad_err = bad.validate().expect_err("bad payload must fail");
    assert!(matches!(bad_err, ContractViolation::KindPayload(_)));
    let empty = TargetEvidence {
        targets: Vec::new(),
        evidence_refs: vec!["e-1".into()],
    };
    assert!(matches!(
        empty.validate("classification"),
        Err(ContractViolation::MissingField("targets"))
    ));
}

// WORK_UNIT_CASE: 578/44
#[test]
fn marker_44_independent_consumer_compile_fixtures() {
    let job = fixture_job();
    assert!(job.validate().is_ok(), "fixture job must validate");
    let bundle = fixture_bundle();
    assert!(bundle.validate().is_ok(), "fixture bundle must validate");
    let draft = fixture_draft();
    assert!(draft.validate().is_ok(), "fixture draft must validate");
    let receipt = fixture_receipt();
    assert!(receipt.validate().is_ok(), "fixture receipt must validate");
    let (registry, ports) = fixture_registry();
    assert!(registry.validate_closure().is_ok(), "registry must close");
    let screen = fixture_screen();
    assert!(screen.validate().is_ok() && screen.eligibility() == ScreenEligibility::Eligible);

    assembler_shape(&job, &bundle);
    validator_shape(&draft, &receipt);
    replacer_shape(&registry, &screen);
    handler_shape(&job, &registry);
    consumer_shape(&bundle, &draft, &receipt, &screen);
    assert_eq!(ports.len(), 10, "ten injected ports");
    assert_typed_dispatch(&registry, &ports);
    assert_item_accept_seam(&job, &bundle, &receipt);
    assert_item_accept_negatives(&job, &bundle, &receipt);
    assert_target_evidence_roles();
}

// WORK_UNIT_CASE: 578/45
#[test]
fn marker_45_source_proof_of_no_algorithms() {
    const SOURCES: &[(&str, &str)] = &[
        ("lib.rs", include_str!("../src/lib.rs")),
        ("error.rs", include_str!("../src/error.rs")),
        ("budget.rs", include_str!("../src/budget.rs")),
        ("bundle.rs", include_str!("../src/bundle.rs")),
        ("candidate.rs", include_str!("../src/candidate.rs")),
        ("curation.rs", include_str!("../src/curation.rs")),
        ("draft.rs", include_str!("../src/draft.rs")),
        ("encoding.rs", include_str!("../src/encoding.rs")),
        ("job.rs", include_str!("../src/job.rs")),
        ("registry.rs", include_str!("../src/registry.rs")),
        ("screen.rs", include_str!("../src/screen.rs")),
    ];
    const FORBIDDEN: &[&str] = &[
        concat!("serde_json::", "Value"),
        concat!("unimplemented", "!"),
        concat!("todo", "!"),
        "unsafe ",
        "std::fs",
        "std::net",
        "std::process",
        "reqwest",
        "tokio",
        "provider_sdk",
        "Model::",
        "execute_effect",
    ];
    for (name, source) in SOURCES {
        assert!(!source.is_empty(), "hub source {name} must be non-empty");
        for token in FORBIDDEN {
            assert!(!source.contains(token), "{name} must not contain {token}");
        }
    }
}
