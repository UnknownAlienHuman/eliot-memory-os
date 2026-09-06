//! Consumer-compile and source-proof integration tests.
//!
//! Marker 44 proves independent consumers (shaped like the A-04 assembler,
//! A-05 validator, A-14b replacer, a typed handler, and the A-31 consumer)
//! compile against the hub without reverse imports: no handler, algorithm,
//! provider, or runtime crate is imported here. Marker 45 proves the hub
//! sources contain no algorithm, provider, I/O, or escape-hatch surface by
//! scanning the sources with `include_str!`.

#![allow(clippy::expect_used)]

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_dreamer_contracts::job::{Requester, RequesterOrigin};
use eliot_dreamer_contracts::{
    BudgetLimits, BundleCompleteness, CURATION_WIRE_KINDS, CurationFamily,
    CurationHandlerDescriptor, CurationHandlerRegistry, CurationKind, DreamInputBundle,
    DreamJobInput, JobClass, ModelDraft, ScreenEligibility, ScreenReference, ScreenState,
    ValidationReceipt, family_of, parse_kind,
};

// Marker 44: consumer-shaped fixtures taking hub types by reference.

fn assembler_shape(job: &DreamJobInput, bundle: &DreamInputBundle) {
    let first = job.validate().is_ok();
    let second = job.validate().is_ok();
    assert_eq!(first, second, "assembler view of job must be stable");
    let first = bundle.validate().is_ok();
    let second = bundle.validate().is_ok();
    assert_eq!(first, second, "assembler view of bundle must be stable");
}

fn validator_shape(draft: &ModelDraft, receipt: &ValidationReceipt) {
    let first = draft.validate().is_ok();
    let second = draft.validate().is_ok();
    assert_eq!(first, second, "validator view of draft must be stable");
    let first = receipt.validate().is_ok();
    let second = receipt.validate().is_ok();
    assert_eq!(first, second, "validator view of receipt must be stable");
}

fn replacer_shape(registry: &CurationHandlerRegistry, screen: &ScreenReference) {
    let first = registry.validate_closure().is_ok();
    let second = registry.validate_closure().is_ok();
    assert_eq!(first, second, "replacer view of registry must be stable");
    let first = screen.validate().is_ok();
    let second = screen.validate().is_ok();
    assert_eq!(first, second, "replacer view of screen must be stable");
}

fn handler_shape(job: &DreamJobInput, registry: &CurationHandlerRegistry) {
    let first = job.validate().is_ok();
    let second = job.validate().is_ok();
    assert_eq!(first, second, "handler view of job must be stable");
    let first = registry.validate_closure().is_ok();
    let second = registry.validate_closure().is_ok();
    assert_eq!(first, second, "handler view of registry must be stable");
}

fn consumer_shape(
    bundle: &DreamInputBundle,
    draft: &ModelDraft,
    receipt: &ValidationReceipt,
    screen: &ScreenReference,
) {
    for stable in [
        bundle.validate().is_ok() == bundle.validate().is_ok(),
        draft.validate().is_ok() == draft.validate().is_ok(),
        receipt.validate().is_ok() == receipt.validate().is_ok(),
        screen.validate().is_ok() == screen.validate().is_ok(),
    ] {
        assert!(stable, "consumer view of hub types must be stable");
    }
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
        frozen_manifest_digest: "e".repeat(64),
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
        materials: Vec::new(),
        omissions: Vec::new(),
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
    }
}

fn fixture_registry() -> CurationHandlerRegistry {
    let mut registry = CurationHandlerRegistry::new();
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
        registry
            .register(CurationHandlerDescriptor {
                family,
                handler_id: std::format!("acc-{}", family.as_str()),
                accepted_kinds: kinds,
            })
            .expect("fixture descriptor registers");
    }
    registry
}

fn fixture_screen() -> ScreenReference {
    ScreenReference {
        screen_id: "screen-44".to_owned(),
        request_id: "req-44".to_owned(),
        receipt_id: "rcpt-44".to_owned(),
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
    let registry = fixture_registry();
    assert!(
        registry.validate_closure().is_ok(),
        "fixture registry must close"
    );
    let screen = fixture_screen();
    assert!(screen.validate().is_ok());
    assert_eq!(screen.eligibility(), ScreenEligibility::Eligible);

    assembler_shape(&job, &bundle);
    validator_shape(&draft, &receipt);
    replacer_shape(&registry, &screen);
    handler_shape(&job, &registry);
    consumer_shape(&bundle, &draft, &receipt, &screen);
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
    // Tokens are assembled with `concat!` so this test's own denylist does
    // not self-match naive source scanners; the runtime strings are identical
    // and still detect any real occurrence in the scanned hub sources above.
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
        assert!(
            !source.is_empty(),
            "hub source {name} must exist and be non-empty"
        );
        for token in FORBIDDEN {
            assert!(
                !source.contains(token),
                "hub source {name} must not contain forbidden token {token}"
            );
        }
    }
}
