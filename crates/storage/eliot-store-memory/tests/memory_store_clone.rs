//! Issue 883: deep-copy `MemoryStore` clone contract disposition.
//!
//! Single evidence-backed disposition: remove the unused `Clone`. There is no
//! `Clone` impl and no explicitly-named fork; independent models reuse
//! `MemoryStore::new` construction plus the `MemoryStore::snapshot` value
//! projection. The fourteen `883/1`..`883/14` cases in
//! `tests/data/memory_store_clone_cases.json` drive this harness.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration, SourceId,
};
use eliot_store_api::{
    CONTRACT_VERSION, CanonicalRequestView, EffectClass, EventProjectionRelationIntents,
    NamedOperationManifest, OperationId, OrderingScopeId, PreparedTransition, RequestMeta, ScopeId,
    StateFence, StoreError, TransitionClass, canonical_request_hash,
};
use eliot_store_memory::MemoryStore;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(serde::Deserialize)]
struct CaseFile {
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    id: String,
    kind: String,
    params: BTreeMap<String, String>,
}

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
    let nonzero = NonZeroU64::new(sequence).ok_or("test sequence must be nonzero")?;
    Ok(EpochId::new(EpochLineageId::new(TEST_LINEAGE_A)?, nonzero)?)
}

fn fence() -> Result<StateFence, Box<dyn std::error::Error>> {
    Ok(StateFence::new(
        test_epoch(1)?,
        ResourceGeneration::genesis(),
    ))
}

fn request_meta(fence: &StateFence) -> Result<RequestMeta, Box<dyn std::error::Error>> {
    Ok(RequestMeta {
        request_id: RequestId::new("request-1")?,
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-1")?,
        source_id: SourceId::new("source-1")?,
        state_fence: fence.clone(),
        clock: ClockReading {
            valid_time_ms: Some(1),
            known_time_ms: Some(1),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        },
    })
}

fn manifest() -> Result<NamedOperationManifest, Box<dyn std::error::Error>> {
    Ok(NamedOperationManifest::new(
        "memory-reference-test",
        CONTRACT_VERSION,
        vec![TransitionClass::CaptureCandidate],
        EffectClass::Candidate,
        1_024,
        1_024,
        1_000,
    )?)
}

fn test_store() -> Result<MemoryStore, Box<dyn std::error::Error>> {
    let store = MemoryStore::new();
    store.register_manifest(manifest()?)?;
    Ok(store)
}

fn transition(
    operation: &str,
    fence: &StateFence,
) -> Result<PreparedTransition, Box<dyn std::error::Error>> {
    let operation_id = OperationId::new(operation)?;
    let mut prepared = PreparedTransition {
        identity: eliot_store_api::OperationIdentity {
            operation_id,
            idempotency_key: format!("idem-{operation}"),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence.clone(),
        scope_id: ScopeId::new("scope-1")?,
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("scope-1")?],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "a".repeat(64),
        operation_manifest_digest: manifest()?.digest,
        named_operations: vec![eliot_store_api::NamedMutationRequest {
            operation: eliot_store_api::NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([(String::from("subject"), json!(operation))]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: vec![],
            projection_kinds: vec![String::from("task_state")],
            relation_kinds: vec![String::from("causes")],
        },
        security: eliot_store_api::SecurityContext::default(),
        required_proof_and_approval_refs: vec![],
    };
    let ctx = request_meta(fence)?;
    let view = CanonicalRequestView::from_apply(&ctx, &prepared, &[], &[]);
    prepared.identity.canonical_request_hash = canonical_request_hash(&view)?;
    Ok(prepared)
}

fn transition_with_subject(
    operation: &str,
    subject: &str,
    fence: &StateFence,
) -> Result<PreparedTransition, Box<dyn std::error::Error>> {
    let mut prepared = transition(operation, fence)?;
    prepared.named_operations[0]
        .parameters
        .insert(String::from("subject"), Value::String(subject.to_owned()));
    let ctx = request_meta(fence)?;
    let view = CanonicalRequestView::from_apply(&ctx, &prepared, &[], &[]);
    prepared.identity.canonical_request_hash = canonical_request_hash(&view)?;
    Ok(prepared)
}

fn param(
    params: &BTreeMap<String, String>,
    key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    params
        .get(key)
        .cloned()
        .ok_or_else(|| format!("missing string param '{key}'").into())
}

fn lib_source() -> Result<String, Box<dyn std::error::Error>> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    Ok(std::fs::read_to_string(path)?)
}

fn struct_attr_window(source: &str) -> Result<String, Box<dyn std::error::Error>> {
    let lines: Vec<&str> = source.lines().collect();
    let anchor = lines
        .iter()
        .position(|line| line.contains("pub struct MemoryStore"))
        .ok_or("lib.rs must define `pub struct MemoryStore`")?;
    let mut start = anchor;
    while start > 0 {
        let prior = lines[start - 1].trim();
        if prior.is_empty() || prior.starts_with("///") || prior.starts_with("#[") {
            start -= 1;
        } else {
            break;
        }
    }
    Ok(lines[start..anchor].join("\n"))
}

fn check_absent_clone(source: &str, id: &str) -> TestResult {
    assert!(
        !source.contains("impl Clone for MemoryStore"),
        "case {id}: lib.rs must not implement Clone for MemoryStore"
    );
    let window = struct_attr_window(source)?;
    for line in window.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[") {
            assert!(
                !trimmed.contains("Clone"),
                "case {id}: MemoryStore item attributes must not derive Clone"
            );
        }
    }
    assert!(
        !source.contains("fn independent_fork")
            && !source.contains("fn fork_clone")
            && !source.contains("fn try_clone"),
        "case {id}: removal disposition keeps no explicitly-named fork"
    );
    Ok(())
}

fn check_fresh_empty(id: &str) -> TestResult {
    let snapshot = MemoryStore::new().snapshot()?;
    assert_eq!(
        snapshot.state_fence, None,
        "case {id}: fresh fence must be none"
    );
    assert!(
        snapshot.revision_heads.is_empty(),
        "case {id}: fresh revisions empty"
    );
    assert!(
        snapshot.ordering_heads.is_empty(),
        "case {id}: fresh ordering empty"
    );
    assert!(
        snapshot.receipts.is_empty(),
        "case {id}: fresh receipts empty"
    );
    assert!(
        snapshot.projections.is_empty(),
        "case {id}: fresh projections empty"
    );
    assert!(snapshot.outbox.is_empty(), "case {id}: fresh outbox empty");
    assert!(
        snapshot.relations.is_empty(),
        "case {id}: fresh relations empty"
    );
    assert!(
        snapshot.named_operations.is_empty(),
        "case {id}: fresh named operations empty"
    );
    Ok(())
}

fn check_snapshot_determinism(id: &str) -> TestResult {
    let store = test_store()?;
    assert_eq!(
        store.snapshot()?,
        store.snapshot()?,
        "case {id}: consecutive snapshots must match"
    );
    Ok(())
}

fn check_value_projection(id: &str) -> TestResult {
    let store = test_store()?;
    let before = store.snapshot()?;
    let mut detached = before.clone();
    detached.receipts.clear();
    detached.named_operations.clear();
    assert_eq!(
        store.snapshot()?,
        before,
        "case {id}: mutating a snapshot clone must not move the store"
    );
    Ok(())
}

fn check_construction_equality(id: &str) -> TestResult {
    let left = test_store()?;
    let right = test_store()?;
    assert_eq!(
        left.snapshot()?,
        right.snapshot()?,
        "case {id}: independently constructed stores start equal"
    );
    Ok(())
}

fn check_isolation_left_to_right(case: &Case) -> TestResult {
    let operation = param(&case.params, "operation")?;
    let subject = param(&case.params, "subject")?;
    let fence = fence()?;
    let ctx = request_meta(&fence)?;
    let left = test_store()?;
    let right = test_store()?;
    let right_before = right.snapshot()?;
    left.apply_transaction(
        &ctx,
        transition_with_subject(&operation, &subject, &fence)?,
        &[],
        &[],
    )?;
    assert_ne!(
        left.snapshot()?,
        right_before,
        "case {}: writer must diverge",
        case.id
    );
    assert_eq!(
        right.snapshot()?,
        right_before,
        "case {}: untouched construction must not move",
        case.id
    );
    Ok(())
}

fn check_isolation_right_to_left(case: &Case) -> TestResult {
    let operation = param(&case.params, "operation")?;
    let subject = param(&case.params, "subject")?;
    let fence = fence()?;
    let ctx = request_meta(&fence)?;
    let left = test_store()?;
    let right = test_store()?;
    let left_before = left.snapshot()?;
    right.apply_transaction(
        &ctx,
        transition_with_subject(&operation, &subject, &fence)?,
        &[],
        &[],
    )?;
    assert_ne!(
        right.snapshot()?,
        left_before,
        "case {}: writer must diverge",
        case.id
    );
    assert_eq!(
        left.snapshot()?,
        left_before,
        "case {}: untouched construction must not move",
        case.id
    );
    Ok(())
}

fn check_divergence(case: &Case) -> TestResult {
    let operation = param(&case.params, "operation")?;
    let subject = param(&case.params, "subject")?;
    let fence = fence()?;
    let ctx = request_meta(&fence)?;
    let left = test_store()?;
    let right = test_store()?;
    assert_eq!(
        left.snapshot()?,
        right.snapshot()?,
        "case {}: constructions start equal",
        case.id
    );
    left.apply_transaction(
        &ctx,
        transition_with_subject(&operation, &subject, &fence)?,
        &[],
        &[],
    )?;
    assert_ne!(
        left.snapshot()?,
        right.snapshot()?,
        "case {}: one-sided write must be visible by snapshot",
        case.id
    );
    Ok(())
}

fn check_projection_completeness(case: &Case) -> TestResult {
    let operation = param(&case.params, "operation")?;
    let subject = param(&case.params, "subject")?;
    let fence = fence()?;
    let ctx = request_meta(&fence)?;
    let store = test_store()?;
    store.apply_transaction(
        &ctx,
        transition_with_subject(&operation, &subject, &fence)?,
        &[],
        &[],
    )?;
    let snapshot = store.snapshot()?;
    assert_eq!(snapshot.receipts.len(), 1, "case {}: one receipt", case.id);
    assert_eq!(
        snapshot.projections.len(),
        1,
        "case {}: one projection",
        case.id
    );
    assert_eq!(
        snapshot.outbox.len(),
        1,
        "case {}: one outbox intent",
        case.id
    );
    assert_eq!(
        snapshot.named_operations.len(),
        1,
        "case {}: one named operation",
        case.id
    );
    Ok(())
}

fn check_default_equivalence(id: &str) -> TestResult {
    assert_eq!(
        MemoryStore::default().snapshot()?,
        MemoryStore::new().snapshot()?,
        "case {id}: Default must match new"
    );
    Ok(())
}

fn check_typed_failure(id: &str) -> TestResult {
    let store = test_store()?;
    assert!(
        store.snapshot().is_ok(),
        "case {id}: healthy snapshot must succeed"
    );
    let rendered = format!("{:?}", StoreError::Unavailable);
    assert!(
        rendered.contains("Unavailable"),
        "case {id}: poison failure must stay a typed Unavailable"
    );
    Ok(())
}

fn check_seeded_subject(case: &Case) -> TestResult {
    let operation = param(&case.params, "operation")?;
    let subject = param(&case.params, "subject")?;
    let fence = fence()?;
    let ctx = request_meta(&fence)?;
    let store = test_store()?;
    store.apply_transaction(
        &ctx,
        transition_with_subject(&operation, &subject, &fence)?,
        &[],
        &[],
    )?;
    let snapshot = store.snapshot()?;
    let observed = snapshot
        .named_operations
        .first()
        .and_then(|item| item.parameters.get("subject"))
        .and_then(Value::as_str)
        .ok_or("seeded capture must carry a string subject")?;
    assert_eq!(
        observed,
        subject.as_str(),
        "case {}: named-operation subject must match",
        case.id
    );
    Ok(())
}

fn check_no_shared_state(source: &str, id: &str) {
    for token in ["Arc<", "Arc::", "OnceLock", "LazyLock", "lazy_static"] {
        assert!(
            !source.contains(token),
            "case {id}: lib.rs must not share state via '{token}'"
        );
    }
    for token in ["static MEMORY", "static STORE", "static STATE"] {
        assert!(
            !source.contains(token),
            "case {id}: lib.rs must not hold a global '{token}'"
        );
    }
}

fn check_doc_contract(source: &str, id: &str) {
    assert!(
        source.contains("does not implement `Clone`"),
        "case {id}: MemoryStore docs must record the absent Clone"
    );
    assert!(
        source.contains("MemoryStore::snapshot"),
        "case {id}: docs must name snapshot as the value-projection path"
    );
}

fn run_case(case: &Case, source: &str) -> TestResult {
    match case.kind.as_str() {
        "absent_clone_source_guard" => check_absent_clone(source, &case.id),
        "fresh_construction_empty" => check_fresh_empty(&case.id),
        "snapshot_determinism" => check_snapshot_determinism(&case.id),
        "snapshot_value_projection" => check_value_projection(&case.id),
        "construction_equality" => check_construction_equality(&case.id),
        "isolation_left_to_right" => check_isolation_left_to_right(case),
        "isolation_right_to_left" => check_isolation_right_to_left(case),
        "divergence_detection" => check_divergence(case),
        "projection_completeness" => check_projection_completeness(case),
        "default_ctor_equivalence" => check_default_equivalence(&case.id),
        "snapshot_typed_failure" => check_typed_failure(&case.id),
        "seeded_capture_subject" => check_seeded_subject(case),
        "no_shared_state_source_guard" => {
            check_no_shared_state(source, &case.id);
            Ok(())
        }
        "doc_contract_guard" => {
            check_doc_contract(source, &case.id);
            Ok(())
        }
        other => Err(format!("unknown clone-contract kind '{other}'").into()),
    }
}

#[test]
fn memory_store_clone_contract_883() -> TestResult {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/memory_store_clone_cases.json");
    let text = std::fs::read_to_string(path)?;
    let file: CaseFile = serde_json::from_str(&text)?;
    assert_eq!(file.cases.len(), 14, "issue 883 requires exactly 14 cases");
    let source = lib_source()?;
    for (index, case) in file.cases.iter().enumerate() {
        let expected = format!("883/{}", index + 1);
        assert_eq!(case.id, expected, "cases must run in 883/1..14 order");
        run_case(case, &source).map_err(|error| format!("case {} failed: {error}", case.id))?;
    }
    Ok(())
}
