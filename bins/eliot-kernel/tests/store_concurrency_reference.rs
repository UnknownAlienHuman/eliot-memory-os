//! Sequential-reference acceptance for S-CONC-ACCEPT (issue #994).
//!
//! Drives the unchanged in-memory reference (`eliot-store-memory`) through
//! the frozen corpus in `data/store_concurrency_cases.json` and the frozen
//! profile in `data/store_concurrency_profile.toml`. The reference need not
//! be physically concurrent; it pins deterministic sequential semantics that
//! the product suite (`store_concurrency_product.rs`) replays against the
//! real Surreal path.
//!
//! Suite allocation (frozen): 994/1, 994/4, 994/5, 994/6, 994/7, 994/8,
//! 994/20. The remaining cases 994/2, 994/3, 994/9-994/19 live exactly once
//! in the product suite.

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration,
    SourceId, StateFence,
};
use eliot_store_api::{
    CanonicalRequestView, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, NamedOperationManifest, OperationIdentity, OrderingHeadExpectation,
    OrderingScopeId, PreparedTransition, RequestMeta, RevisionHeadExpectation, RevisionKey,
    ScopeId, SecurityContext, StoreError, TransitionClass, canonical_request_hash,
    generated_operation_manifests, operation_manifest_set_digest, validate_store_receipt_envelope,
};
use eliot_store_memory::{MemorySnapshot, MemoryStore};
use serde_json::Value;

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const FOREIGN_LINEAGE: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
const REFERENCE_CASES: [u64; 7] = [1, 4, 5, 6, 7, 8, 20];
const PRODUCT_CASES: [u64; 13] = [2, 3, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn corpus() -> Value {
    let bytes = std::fs::read(data_dir().join("store_concurrency_cases.json"))
        .expect("corpus must be readable");
    serde_json::from_slice(&bytes).expect("corpus must be valid JSON")
}

fn profile_text() -> String {
    std::fs::read_to_string(data_dir().join("store_concurrency_profile.toml"))
        .expect("profile must be readable")
}

/// Minimal flat-TOML lookup: finds `key = value` under any section. The
/// profile is frozen flat key/value pairs precisely so no new dependency is
/// needed to read it.
fn profile_value(key: &str) -> String {
    for line in profile_text().lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('[') || line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once('=')
            && name.trim() == key
        {
            let value = value.trim().trim_matches('"').to_owned();
            assert!(!value.is_empty(), "profile key must be non-empty: {key}");
            return value;
        }
    }
    panic!("profile key missing: {key}")
}

fn epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE).expect("lineage"),
        NonZeroU64::new(sequence).expect("non-zero"),
    )
    .expect("epoch")
}

fn fence() -> StateFence {
    StateFence::new(epoch(1), ResourceGeneration::genesis())
}

fn foreign_fence() -> StateFence {
    // A genuinely foreign fence: distinct lineage, so the rejection proves
    // lineage mismatch, never an epoch transition on the owning lineage.
    StateFence::new(
        EpochId::new(
            EpochLineageId::new(FOREIGN_LINEAGE).expect("lineage"),
            NonZeroU64::new(1).expect("non-zero"),
        )
        .expect("epoch"),
        ResourceGeneration::genesis(),
    )
}

fn changed_epoch_fence() -> StateFence {
    // Same owning lineage, distinct epoch: the corpus changed-epoch fence.
    StateFence::new(epoch(2), ResourceGeneration::genesis())
}

fn ctx_for(operation: &str, fence: &StateFence) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(format!("request-994-{operation}")).expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-994").expect("product"),
        source_id: SourceId::new("source-994").expect("source"),
        state_fence: fence.clone(),
        clock: ClockReading {
            valid_time_ms: Some(1_000),
            known_time_ms: Some(1_001),
            ..ClockReading::default()
        },
    }
}

/// Selects the generated catalogue entry that admits the frozen
/// `CaptureObservation` shape. The transition digest is that entry's own
/// digest; the Surreal path instead binds the catalogue *set* digest, and
/// case 994/2 normalizes exactly that representation difference.
fn admitting_manifest() -> NamedOperationManifest {
    let entries = generated_operation_manifests().expect("generated catalogue");
    assert!(!entries.is_empty(), "catalogue must be non-empty");
    let probe = PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new("op-994-probe").expect("operation"),
            idempotency_key: "idem-994-probe".to_owned(),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("scope-994-a").expect("scope"),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("scope-994-a").expect("ordering")],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: entries[0].digest.clone(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([("subject".to_owned(), serde_json::json!("probe"))]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    entries
        .into_iter()
        .find(|entry| {
            let mut candidate = probe.clone();
            candidate.operation_manifest_digest = entry.digest.clone();
            candidate.validate_against_manifest(entry).is_ok()
        })
        .expect("one generated entry must admit CaptureObservation")
}

fn reference_store() -> (MemoryStore, NamedOperationManifest) {
    let store = MemoryStore::new();
    for entry in generated_operation_manifests().expect("generated catalogue") {
        store.register_manifest(entry).expect("register");
    }
    let manifest = admitting_manifest();
    (store, manifest)
}

#[allow(clippy::too_many_arguments)]
fn build_transition(
    operation: &str,
    scope: &str,
    ordering_scopes: &[&str],
    subject: &str,
    fence: &StateFence,
    ctx: &RequestMeta,
    manifest: &NamedOperationManifest,
    revisions: &[RevisionHeadExpectation],
    orderings: &[OrderingHeadExpectation],
) -> PreparedTransition {
    let mut transition = PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(operation).expect("operation"),
            idempotency_key: format!("idem-994-{operation}"),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence.clone(),
        scope_id: ScopeId::new(scope).expect("scope"),
        task_id: None,
        ordering_scopes: ordering_scopes
            .iter()
            .map(|scope| OrderingScopeId::new(*scope).expect("ordering"))
            .collect(),
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: manifest.digest.clone(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([("subject".to_owned(), serde_json::json!(subject))]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    transition.identity.canonical_request_hash = canonical_request_hash(
        &CanonicalRequestView::from_apply(ctx, &transition, revisions, orderings),
    )
    .expect("request hash");
    transition
}

fn admitted(
    operation: &str,
    scope: &str,
    subject: &str,
    fence: &StateFence,
    manifest: &NamedOperationManifest,
) -> (RequestMeta, PreparedTransition) {
    let ctx = ctx_for(operation, fence);
    let transition = build_transition(
        operation,
        scope,
        &[scope],
        subject,
        fence,
        &ctx,
        manifest,
        &[],
        &[],
    );
    (ctx, transition)
}

/// Canonical ordering-scope acquisition order for multiscope claims. The
/// single ORS coordinator requires lexicographic scope order (corpus
/// `causal_partial_order`), so overlapping claims serialize with no partial
/// acquisition and no cyclic wait.
fn canonical_ordering<'a>(scopes: &[&'a str]) -> Vec<&'a str> {
    let mut canonical = scopes.to_vec();
    canonical.sort_unstable();
    canonical.dedup();
    canonical
}

fn revision_of(snapshot: &MemorySnapshot, key: &str) -> u64 {
    snapshot
        .revision_heads
        .iter()
        .find(|head| head.key.as_str() == key)
        .unwrap_or_else(|| panic!("revision head must exist: {key}"))
        .revision
}

fn ordering_of(snapshot: &MemorySnapshot, scope: &str) -> u64 {
    snapshot
        .ordering_heads
        .iter()
        .find(|head| head.scope.as_str() == scope)
        .unwrap_or_else(|| panic!("ordering head must exist: {scope}"))
        .sequence
}

// WORK_UNIT_CASE: 994/1
#[test]
fn implementation_profile_operation_corpus_denominator() {
    let fx = corpus();
    assert_eq!(
        fx["schema"].as_str().expect("schema"),
        "eliot.sconc.workload/v1"
    );
    assert_eq!(fx["issue"].as_u64().expect("issue"), 994);
    assert_eq!(
        fx["contract_version"].as_str().expect("contract"),
        eliot_store_api::CONTRACT_VERSION.to_string().as_str()
    );
    let cases = fx["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 20, "corpus must freeze exactly 20 cases");
    let mut numbers: Vec<u64> = cases
        .iter()
        .map(|c| c["case"].as_u64().expect("case"))
        .collect();
    numbers.sort_unstable();
    assert_eq!(numbers, (1u64..=20u64).collect::<Vec<_>>());
    let mut reference: Vec<u64> = cases
        .iter()
        .filter(|c| c["suite"].as_str().expect("suite") == "reference")
        .map(|c| c["case"].as_u64().expect("case"))
        .collect();
    reference.sort_unstable();
    assert_eq!(reference, REFERENCE_CASES);
    let mut product: Vec<u64> = cases
        .iter()
        .filter(|c| c["suite"].as_str().expect("suite") == "product")
        .map(|c| c["case"].as_u64().expect("case"))
        .collect();
    product.sort_unstable();
    assert_eq!(product, PRODUCT_CASES);
    // Profile owns the numbers; corpus mirrors them.
    assert_eq!(profile_value("lanes"), "2");
    assert_eq!(profile_value("max_pending"), "8");
    assert_eq!(profile_value("accepted_generation"), "v2");
    assert_eq!(profile_value("tx_rendezvous_parties"), "3");
    assert_eq!(profile_value("admitted_operation"), "CaptureObservation");
    assert_eq!(fx["queue_limits"]["lanes"].as_u64().expect("lanes"), 2);
    assert_eq!(
        fx["queue_limits"]["max_pending"].as_u64().expect("pending"),
        8
    );
    // The generated catalogue digest computes and is stable within this run.
    let entries = generated_operation_manifests().expect("generated catalogue");
    let first = operation_manifest_set_digest(&entries).expect("set digest");
    let second = operation_manifest_set_digest(
        &generated_operation_manifests().expect("generated catalogue"),
    )
    .expect("set digest");
    assert_eq!(first, second, "catalogue digest must be deterministic");
    assert_eq!(first.as_str().len(), 64, "set digest must be SHA-256 hex");
}

// WORK_UNIT_CASE: 994/4
#[test]
fn overlapping_scopes_consistently_ordered() {
    let fx = corpus();
    let case = fx["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["case"].as_u64() == Some(4))
        .expect("case 4");
    assert_eq!(case["suite"].as_str().expect("suite"), "reference");
    let scopes: Vec<&str> = case["scopes"]
        .as_array()
        .expect("scopes")
        .iter()
        .map(|scope| scope.as_str().expect("scope"))
        .collect();
    assert_eq!(scopes, vec!["scope-994-a", "scope-994-b"]);
    let operations: Vec<&str> = case["operations"]
        .as_array()
        .expect("operations")
        .iter()
        .map(|operation| operation.as_str().expect("operation"))
        .collect();
    assert_eq!(operations, vec!["op-994-seq-1", "op-994-seq-2"]);
    let (store, manifest) = reference_store();
    let fence = fence();
    // Corpus-faithful overlap: both transitions declare the overlapping
    // ordering-scope set, each applied on its own corpus scope.
    let overlap = ["scope-994-a", "scope-994-b"];
    let ctx1 = ctx_for("op-994-seq-1", &fence);
    let first = build_transition(
        "op-994-seq-1",
        "scope-994-a",
        &overlap,
        "subject-994-04-1",
        &fence,
        &ctx1,
        &manifest,
        &[],
        &[],
    );
    let receipt1 = store
        .apply_transaction(&ctx1, first.clone(), &[], &[])
        .expect("first commits");
    validate_store_receipt_envelope(&ctx1, &first, &receipt1).expect("envelope");
    let ctx2 = ctx_for("op-994-seq-2", &fence);
    let second = build_transition(
        "op-994-seq-2",
        "scope-994-b",
        &overlap,
        "subject-994-04-2",
        &fence,
        &ctx2,
        &manifest,
        &[],
        &[],
    );
    let receipt2 = store
        .apply_transaction(&ctx2, second.clone(), &[], &[])
        .expect("second commits");
    validate_store_receipt_envelope(&ctx2, &second, &receipt2).expect("envelope");
    // Both receipts carry both ordering heads in canonical order, never erased.
    let heads1: Vec<&str> = receipt1
        .ordering_sequences
        .iter()
        .map(|head| head.scope.as_str())
        .collect();
    assert_eq!(heads1, vec!["scope-994-a", "scope-994-b"]);
    let heads2: Vec<&str> = receipt2
        .ordering_sequences
        .iter()
        .map(|head| head.scope.as_str())
        .collect();
    assert_eq!(heads2, vec!["scope-994-a", "scope-994-b"]);
    // One consistent precedence: the second arrival follows the first on
    // every overlapping scope.
    for scope in overlap {
        let first_sequence = receipt1
            .ordering_sequences
            .iter()
            .find(|head| head.scope.as_str() == scope)
            .expect("scope in first receipt")
            .sequence;
        let second_sequence = receipt2
            .ordering_sequences
            .iter()
            .find(|head| head.scope.as_str() == scope)
            .expect("scope in second receipt")
            .sequence;
        assert!(
            second_sequence > first_sequence,
            "consistent precedence on {scope}"
        );
    }
    assert_eq!(receipt1.revision_before_after.len(), 1);
    assert_eq!(receipt2.revision_before_after.len(), 1);
    // Each receipt advances its own primary-scope revision key 1 -> 2; the
    // keys differ, so cross-receipt ordering is proved on ordering heads.
    assert_eq!(
        receipt1.revision_before_after[0].key.as_str(),
        "scope:scope-994-a"
    );
    assert_eq!(
        receipt2.revision_before_after[0].key.as_str(),
        "scope:scope-994-b"
    );
    let snapshot = store.snapshot().expect("snapshot");
    assert!(ordering_of(&snapshot, "scope-994-a") >= 2);
    assert!(ordering_of(&snapshot, "scope-994-b") >= 2);
    assert!(revision_of(&snapshot, "scope:scope-994-a") >= 2);
    assert!(revision_of(&snapshot, "scope:scope-994-b") >= 2);
    // Deterministic: the same arrival order replays to the identical snapshot.
    let (replay, replay_manifest) = reference_store();
    let rctx1 = ctx_for("op-994-seq-1", &fence);
    let rfirst = build_transition(
        "op-994-seq-1",
        "scope-994-a",
        &overlap,
        "subject-994-04-1",
        &fence,
        &rctx1,
        &replay_manifest,
        &[],
        &[],
    );
    let rctx2 = ctx_for("op-994-seq-2", &fence);
    let rsecond = build_transition(
        "op-994-seq-2",
        "scope-994-b",
        &overlap,
        "subject-994-04-2",
        &fence,
        &rctx2,
        &replay_manifest,
        &[],
        &[],
    );
    let first_receipt = replay
        .apply_transaction(&rctx1, rfirst, &[], &[])
        .expect("replay first");
    let second_receipt = replay
        .apply_transaction(&rctx2, rsecond, &[], &[])
        .expect("replay second");
    assert_eq!(first_receipt, receipt1);
    assert_eq!(second_receipt, receipt2);
    assert_eq!(replay.snapshot().expect("snapshot"), snapshot);
}

// WORK_UNIT_CASE: 994/5
#[test]
fn multiscope_claim_without_cyclic_wait() {
    let fx = corpus();
    let case = fx["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["case"].as_u64() == Some(5))
        .expect("case 5");
    assert_eq!(case["suite"].as_str().expect("suite"), "reference");
    let scopes: Vec<&str> = case["scopes"]
        .as_array()
        .expect("scopes")
        .iter()
        .map(|scope| scope.as_str().expect("scope"))
        .collect();
    assert_eq!(scopes, vec!["scope-994-a", "scope-994-b", "scope-994-c"]);
    let operations: Vec<&str> = case["operations"]
        .as_array()
        .expect("operations")
        .iter()
        .map(|operation| operation.as_str().expect("operation"))
        .collect();
    assert_eq!(operations, vec!["op-994-multi-ab", "op-994-multi-bc"]);
    let (store, manifest) = reference_store();
    let fence = fence();
    // Each multiscope transition declares its ordering scopes in the
    // coordinator's canonical acquisition order: no partial acquisition, no
    // cyclic wait.
    let ab_scopes = canonical_ordering(&["scope-994-a", "scope-994-b"]);
    let bc_scopes = canonical_ordering(&["scope-994-b", "scope-994-c"]);
    assert_eq!(ab_scopes, vec!["scope-994-a", "scope-994-b"]);
    assert_eq!(bc_scopes, vec!["scope-994-b", "scope-994-c"]);
    let ctx_ab = ctx_for("op-994-multi-ab", &fence);
    let claim_ab = build_transition(
        "op-994-multi-ab",
        "scope-994-a",
        &ab_scopes,
        "subject-994-05-ab",
        &fence,
        &ctx_ab,
        &manifest,
        &[],
        &[],
    );
    assert!(
        claim_ab
            .ordering_scopes
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "A+B declares canonical acquisition order"
    );
    let ctx_bc = ctx_for("op-994-multi-bc", &fence);
    let claim_bc = build_transition(
        "op-994-multi-bc",
        "scope-994-b",
        &bc_scopes,
        "subject-994-05-bc",
        &fence,
        &ctx_bc,
        &manifest,
        &[],
        &[],
    );
    assert!(
        claim_bc
            .ordering_scopes
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "B+C declares canonical acquisition order"
    );
    let receipt_ab = store
        .apply_transaction(&ctx_ab, claim_ab.clone(), &[], &[])
        .expect("A+B commits");
    validate_store_receipt_envelope(&ctx_ab, &claim_ab, &receipt_ab).expect("envelope");
    let receipt_bc = store
        .apply_transaction(&ctx_bc, claim_bc.clone(), &[], &[])
        .expect("B+C commits");
    validate_store_receipt_envelope(&ctx_bc, &claim_bc, &receipt_bc).expect("envelope");
    // Each receipt carries exactly its declared canonical ordering scopes.
    let ab_heads: Vec<&str> = receipt_ab
        .ordering_sequences
        .iter()
        .map(|head| head.scope.as_str())
        .collect();
    assert_eq!(ab_heads, vec!["scope-994-a", "scope-994-b"]);
    let bc_heads: Vec<&str> = receipt_bc
        .ordering_sequences
        .iter()
        .map(|head| head.scope.as_str())
        .collect();
    assert_eq!(bc_heads, vec!["scope-994-b", "scope-994-c"]);
    // Shared scope-994-b carries one consistent precedence edge, no gap.
    let seq_ab = receipt_ab
        .ordering_sequences
        .iter()
        .find(|h| h.scope.as_str() == "scope-994-b")
        .expect("b in A+B")
        .sequence;
    let seq_bc = receipt_bc
        .ordering_sequences
        .iter()
        .find(|h| h.scope.as_str() == "scope-994-b")
        .expect("b in B+C")
        .sequence;
    assert!(seq_bc > seq_ab, "shared scope keeps arrival precedence");
    // Exact forward structure: first arrival takes 2 on both its scopes, the
    // shared scope advances to 3 on the second arrival.
    assert_eq!(
        receipt_ab
            .ordering_sequences
            .iter()
            .find(|h| h.scope.as_str() == "scope-994-a")
            .expect("a in A+B")
            .sequence,
        2
    );
    assert_eq!(seq_ab, 2);
    assert_eq!(seq_bc, 3);
    assert_eq!(
        receipt_bc
            .ordering_sequences
            .iter()
            .find(|h| h.scope.as_str() == "scope-994-c")
            .expect("c in B+C")
            .sequence,
        2
    );
    // No partial acquisition: every declared scope advanced contiguously.
    // Reference head convention: a fresh scope implies head 1, so the first
    // commit stores 2 and the shared scope stores 3 after both claims.
    let snapshot = store.snapshot().expect("snapshot");
    assert_eq!(ordering_of(&snapshot, "scope-994-a"), 2);
    assert_eq!(ordering_of(&snapshot, "scope-994-b"), 3);
    assert_eq!(ordering_of(&snapshot, "scope-994-c"), 2);
    // Reverse arrival order keeps per-scope contiguity too (precedence follows arrival, never cycles).
    // Same canonical declarations, same semantic structure apart from arrival
    // precedence: first arrival takes 2, the shared scope advances to 3.
    let (reversed, _) = reference_store();
    let (cbc, tbc) = {
        let ctx = ctx_for("op-994-multi-bc", &fence);
        let transition = build_transition(
            "op-994-multi-bc",
            "scope-994-b",
            &bc_scopes,
            "subject-994-05-bc",
            &fence,
            &ctx,
            &manifest,
            &[],
            &[],
        );
        (ctx, transition)
    };
    let (cab, tab) = {
        let ctx = ctx_for("op-994-multi-ab", &fence);
        let transition = build_transition(
            "op-994-multi-ab",
            "scope-994-a",
            &ab_scopes,
            "subject-994-05-ab",
            &fence,
            &ctx,
            &manifest,
            &[],
            &[],
        );
        (ctx, transition)
    };
    let receipt_bc_first = reversed
        .apply_transaction(&cbc, tbc, &[], &[])
        .expect("B+C first");
    let receipt_ab_second = reversed
        .apply_transaction(&cab, tab, &[], &[])
        .expect("A+B second");
    let bc_first_heads: Vec<&str> = receipt_bc_first
        .ordering_sequences
        .iter()
        .map(|head| head.scope.as_str())
        .collect();
    assert_eq!(bc_first_heads, vec!["scope-994-b", "scope-994-c"]);
    let ab_second_heads: Vec<&str> = receipt_ab_second
        .ordering_sequences
        .iter()
        .map(|head| head.scope.as_str())
        .collect();
    assert_eq!(ab_second_heads, vec!["scope-994-a", "scope-994-b"]);
    let first_b = receipt_bc_first
        .ordering_sequences
        .iter()
        .find(|h| h.scope.as_str() == "scope-994-b")
        .expect("b")
        .sequence;
    let second_b = receipt_ab_second
        .ordering_sequences
        .iter()
        .find(|h| h.scope.as_str() == "scope-994-b")
        .expect("b")
        .sequence;
    assert!(second_b > first_b);
    assert_eq!(first_b, 2);
    assert_eq!(second_b, 3);
    assert_eq!(
        receipt_bc_first
            .ordering_sequences
            .iter()
            .find(|h| h.scope.as_str() == "scope-994-c")
            .expect("c")
            .sequence,
        2
    );
    assert_eq!(
        receipt_ab_second
            .ordering_sequences
            .iter()
            .find(|h| h.scope.as_str() == "scope-994-a")
            .expect("a")
            .sequence,
        2
    );
    let reversed_snapshot = reversed.snapshot().expect("snapshot");
    assert_eq!(ordering_of(&reversed_snapshot, "scope-994-a"), 2);
    assert_eq!(ordering_of(&reversed_snapshot, "scope-994-b"), 3);
    assert_eq!(ordering_of(&reversed_snapshot, "scope-994-c"), 2);
    // Both arrival orders converge on identical per-scope heads.
    assert_eq!(
        reversed_snapshot.ordering_heads, snapshot.ordering_heads,
        "arrival order changes precedence, never the per-scope mapping"
    );
}

// WORK_UNIT_CASE: 994/6
#[test]
fn concurrent_exact_replay_single_effect() {
    // One frozen catalogue construction binds the concurrent store and its
    // admitting manifest: exact replay must prove identity against the same
    // registered instance, never two independent generations.
    let (store, manifest) = reference_store();
    let store = Arc::new(store);
    let fence = fence();
    let barrier = Arc::new(Barrier::new(3));
    let before = store.snapshot().expect("snapshot");
    let mut handles = Vec::new();
    for _ in 0..2 {
        let store = Arc::clone(&store);
        let manifest = manifest.clone();
        let fence = fence.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let ctx = ctx_for("op-994-replay", &fence);
            let transition = build_transition(
                "op-994-replay",
                "scope-994-a",
                &["scope-994-a"],
                "subject-994-06",
                &fence,
                &ctx,
                &manifest,
                &[],
                &[],
            );
            barrier.wait();
            store.apply_transaction(&ctx, transition, &[], &[])
        }));
    }
    barrier.wait();
    let mut receipts = Vec::new();
    for handle in handles {
        receipts.push(handle.join().expect("thread").expect("replay commits"));
    }
    assert_eq!(
        receipts[0], receipts[1],
        "exact replay returns the original receipt"
    );
    let after = store.snapshot().expect("snapshot");
    assert_eq!(
        after.receipts.len(),
        before.receipts.len() + 1,
        "one effect only"
    );
    // Reference head convention: a fresh scope implies revision 1, so the
    // first commit stores revision 2 exactly once for two racing replays.
    assert_eq!(revision_of(&after, "scope:scope-994-a"), 2);
    // A third identical replay adds nothing further.
    let (ctx, transition) = admitted(
        "op-994-replay",
        "scope-994-a",
        "subject-994-06",
        &fence,
        &manifest,
    );
    let third = store
        .apply_transaction(&ctx, transition, &[], &[])
        .expect("replay");
    assert_eq!(third, receipts[0]);
    assert_eq!(store.snapshot().expect("snapshot"), after);
}

// WORK_UNIT_CASE: 994/7
#[test]
fn changed_same_operation_input_conflicts() {
    let (store, manifest) = reference_store();
    let fence = fence();
    let (ctx, first) = admitted(
        "op-994-fork",
        "scope-994-a",
        "subject-994-07",
        &fence,
        &manifest,
    );
    let receipt = store
        .apply_transaction(&ctx, first, &[], &[])
        .expect("first commits");
    let before = store.snapshot().expect("snapshot");
    // Same identity, changed input, correctly recomputed claim: identity conflict, no mutation.
    let fork_ctx = ctx_for("op-994-fork", &fence);
    let forked = build_transition(
        "op-994-fork",
        "scope-994-a",
        &["scope-994-a"],
        "subject-994-07-changed",
        &fence,
        &fork_ctx,
        &manifest,
        &[],
        &[],
    );
    assert_ne!(
        forked.identity.canonical_request_hash,
        receipt.canonical_request_hash
    );
    // Corpus case 7 permits IdentityConflict or digest mismatch for changed
    // same-operation input; the oracle must accept the family, never a single
    // implementation-specific variant. No mutation either way.
    assert!(
        matches!(
            store.apply_transaction(&fork_ctx, forked, &[], &[]),
            Err(StoreError::IdentityConflict | StoreError::TransitionDigestMismatch { .. })
        ),
        "changed same-operation input must conflict without mutation"
    );
    assert_eq!(store.snapshot().expect("snapshot"), before);
    // Same identity, tampered bytes under the original claim: digest mismatch, no mutation.
    let mut tampered = build_transition(
        "op-994-fork",
        "scope-994-a",
        &["scope-994-a"],
        "subject-994-07",
        &fence,
        &fork_ctx,
        &manifest,
        &[],
        &[],
    );
    tampered.named_operations[0]
        .parameters
        .insert("subject".to_owned(), serde_json::json!("tampered"));
    let tamper_error = store
        .apply_transaction(&fork_ctx, tampered, &[], &[])
        .expect_err("tampered bytes must fail");
    assert!(
        matches!(tamper_error, StoreError::TransitionDigestMismatch { .. }),
        "tamper must be TRANSITION_DIGEST_MISMATCH, got {tamper_error:?}"
    );
    assert_eq!(store.snapshot().expect("snapshot"), before);
}

// WORK_UNIT_CASE: 994/8
#[test]
fn stale_head_fence_epoch_cannot_commit() {
    let fx = corpus();
    let case = fx["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["case"].as_u64() == Some(8))
        .expect("case 8");
    assert_eq!(case["suite"].as_str().expect("suite"), "reference");
    let scopes: Vec<&str> = case["scopes"]
        .as_array()
        .expect("scopes")
        .iter()
        .map(|scope| scope.as_str().expect("scope"))
        .collect();
    assert_eq!(scopes, vec!["scope-994-a"]);
    let (store, manifest) = reference_store();
    let fence = fence();
    let (ctx, first) = admitted(
        "op-994-baseline",
        "scope-994-a",
        "subject-994-08-base",
        &fence,
        &manifest,
    );
    store
        .apply_transaction(&ctx, first, &[], &[])
        .expect("baseline commits");
    let before = store.snapshot().expect("snapshot");
    assert!(revision_of(&before, "scope:scope-994-a") >= 2);
    // Stale revision expectation cannot commit.
    let stale_revision = vec![RevisionHeadExpectation {
        key: RevisionKey::new("scope:scope-994-a").expect("key"),
        expected_revision: 1,
        state_fence: fence.clone(),
    }];
    let stale_ordering_ok = vec![OrderingHeadExpectation {
        scope: OrderingScopeId::new("scope-994-a").expect("ordering"),
        expected_sequence: ordering_of(&before, "scope-994-a"),
        state_fence: fence.clone(),
    }];
    let stale_ctx = ctx_for("op-994-stale", &fence);
    let stale = build_transition(
        "op-994-stale",
        "scope-994-a",
        &["scope-994-a"],
        "subject-994-08",
        &fence,
        &stale_ctx,
        &manifest,
        &stale_revision,
        &stale_ordering_ok,
    );
    assert_eq!(
        store.apply_transaction(&stale_ctx, stale, &stale_revision, &stale_ordering_ok),
        Err(StoreError::RevisionConflict)
    );
    // Stale ordering expectation cannot commit.
    let current_revision = vec![RevisionHeadExpectation {
        key: RevisionKey::new("scope:scope-994-a").expect("key"),
        expected_revision: revision_of(&before, "scope:scope-994-a"),
        state_fence: fence.clone(),
    }];
    let stale_ordering = vec![OrderingHeadExpectation {
        scope: OrderingScopeId::new("scope-994-a").expect("ordering"),
        expected_sequence: 1,
        state_fence: fence.clone(),
    }];
    let stale_ctx2 = ctx_for("op-994-stale-ord", &fence);
    let stale_ord = build_transition(
        "op-994-stale-ord",
        "scope-994-a",
        &["scope-994-a"],
        "subject-994-08-ord",
        &fence,
        &stale_ctx2,
        &manifest,
        &current_revision,
        &stale_ordering,
    );
    assert_eq!(
        store.apply_transaction(&stale_ctx2, stale_ord, &current_revision, &stale_ordering),
        Err(StoreError::OrderingConflict)
    );
    // Changed epoch on the owning lineage cannot commit, even with
    // otherwise-current revision and ordering expectations: the epoch alone
    // is the rejector, distinct from stale-head and foreign-lineage fences.
    let changed = changed_epoch_fence();
    let current_revision = vec![RevisionHeadExpectation {
        key: RevisionKey::new("scope:scope-994-a").expect("key"),
        expected_revision: revision_of(&before, "scope:scope-994-a"),
        state_fence: changed.clone(),
    }];
    let current_ordering = vec![OrderingHeadExpectation {
        scope: OrderingScopeId::new("scope-994-a").expect("ordering"),
        expected_sequence: ordering_of(&before, "scope-994-a"),
        state_fence: changed.clone(),
    }];
    let changed_ctx = ctx_for("op-994-epoch", &changed);
    let changed_transition = build_transition(
        "op-994-epoch",
        "scope-994-a",
        &["scope-994-a"],
        "subject-994-08-epoch",
        &changed,
        &changed_ctx,
        &manifest,
        &current_revision,
        &current_ordering,
    );
    assert_eq!(
        store.apply_transaction(
            &changed_ctx,
            changed_transition,
            &current_revision,
            &current_ordering
        ),
        Err(StoreError::FenceMismatch)
    );
    assert_eq!(
        store.snapshot().expect("snapshot"),
        before,
        "changed-epoch rejection changes nothing"
    );
    // Foreign fence cannot commit.
    let foreign = foreign_fence();
    let (fctx, ftransition) = admitted(
        "op-994-foreign",
        "scope-994-a",
        "subject-994-08-f",
        &foreign,
        &manifest,
    );
    assert_eq!(
        store.apply_transaction(&fctx, ftransition, &[], &[]),
        Err(StoreError::FenceMismatch)
    );
    assert_eq!(
        store.snapshot().expect("snapshot"),
        before,
        "failed commits change nothing"
    );
}

// WORK_UNIT_CASE: 994/20
#[test]
fn source_proof_guard() {
    // Corpus allocation is frozen and complete.
    let fx = corpus();
    let cases = fx["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 20);
    let mut all: BTreeSet<u64> = BTreeSet::new();
    for case in cases {
        assert!(
            all.insert(case["case"].as_u64().expect("case")),
            "case numbers unique"
        );
        assert!(!case["name"].as_str().expect("name").is_empty());
        assert!(
            !case["expectation"]
                .as_str()
                .expect("expectation")
                .is_empty()
        );
    }
    assert_eq!(all, (1u64..=20u64).collect::<BTreeSet<_>>());
    // Every cased scope is declared in scope_groups; no invented scope.
    let groups = fx["scope_groups"].as_object().expect("scope_groups");
    let mut declared = BTreeSet::new();
    for value in groups.values() {
        match value {
            Value::Array(items) => {
                for item in items {
                    if let Some(scope) = item.as_str() {
                        declared.insert(scope.to_owned());
                    } else if let Some(pair) = item.as_array() {
                        for scope in pair {
                            declared.insert(scope.as_str().expect("scope").to_owned());
                        }
                    }
                }
            }
            _ => panic!("scope group must be an array"),
        }
    }
    for case in cases {
        for scope in case["scopes"].as_array().expect("scopes") {
            let scope = scope.as_str().expect("scope");
            assert!(declared.contains(scope), "undeclared scope: {scope}");
        }
    }
    // Own source binds exactly the frozen reference allocation: no missing
    // scenario, no extra substantive test.
    let own = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/store_concurrency_reference.rs"),
    )
    .expect("own source");
    let mut markers = BTreeSet::new();
    for line in own.lines() {
        if let Some(rest) = line.trim().strip_prefix("// WORK_UNIT_CASE: 994/") {
            markers.insert(rest.trim().parse::<u64>().expect("marker"));
        }
    }
    assert_eq!(
        markers,
        REFERENCE_CASES.into_iter().collect::<BTreeSet<_>>()
    );
    // Product suite must bind exactly the frozen product allocation; the
    // corpus freezes that allocation before the suite lands. The read is
    // unconditional: a missing product half must fail the guard, never pass
    // it by assuming complete corpus realization.
    let product_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/store_concurrency_product.rs");
    let product = std::fs::read_to_string(&product_path).expect("product source required");
    let mut product_markers = BTreeSet::new();
    for line in product.lines() {
        if let Some(rest) = line.trim().strip_prefix("// WORK_UNIT_CASE: 994/") {
            product_markers.insert(rest.trim().parse::<u64>().expect("marker"));
        }
    }
    assert_eq!(
        product_markers,
        PRODUCT_CASES.into_iter().collect::<BTreeSet<_>>()
    );
    let union: BTreeSet<u64> = markers.union(&product_markers).copied().collect();
    assert_eq!(
        union,
        (1u64..=20u64).collect::<BTreeSet<_>>(),
        "cases allocated exactly once"
    );
    // Manifest guard: Store reference/adapter edges must be test-only.
    // The production dependency table must not carry them; they must be
    // declared in the member-local test dependency table instead.
    let manifest =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("member manifest");
    let mut section = String::new();
    let mut production_hits = Vec::new();
    let mut test_edges = BTreeSet::new();
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            section = trimmed.to_owned();
        } else if section == "[dependencies]"
            && (trimmed.starts_with("eliot-store-memory")
                || trimmed.starts_with("eliot-store-surreal-adapter")
                || trimmed.starts_with("secrecy"))
        {
            production_hits.push(trimmed.to_owned());
        } else if section == "[dev-dependencies]"
            && (trimmed.starts_with("eliot-store-memory")
                || trimmed.starts_with("eliot-store-surreal-adapter")
                || trimmed.starts_with("secrecy"))
        {
            test_edges.insert(trimmed.to_owned());
        }
    }
    assert!(
        production_hits.is_empty(),
        "production deps must not carry test-only edges: {production_hits:?}"
    );
    // Exact pinned forms: the memory edge stays a member-local path+version
    // edge (no root workspace entry, no version upgrade), the adapter and
    // secrecy edges stay workspace-inherited. Name presence alone is not
    // enough; the representation is the test-only contract.
    assert_eq!(
        test_edges,
        BTreeSet::from([
            "eliot-store-memory = { path = \"../../crates/storage/eliot-store-memory\", version = \"0.1.0\" }"
                .to_owned(),
            "eliot-store-surreal-adapter.workspace = true".to_owned(),
            "secrecy.workspace = true".to_owned(),
        ]),
        "all Store reference/adapter test-only edges must be member-local dev-dependencies in exact pinned form"
    );
    let root =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml"))
            .expect("root manifest");
    // The reference crate is a workspace member (members list), but the root
    // [workspace.dependencies] table must not gain an edge for it: the only
    // edge is the member-local test-only path+version edge from slice 1.
    let mut root_section = String::new();
    let mut root_hits = Vec::new();
    for line in root.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            root_section = trimmed.to_owned();
        } else if root_section == "[workspace.dependencies]"
            && trimmed.starts_with("eliot-store-memory")
        {
            root_hits.push(trimmed.to_owned());
        }
    }
    assert!(
        root_hits.is_empty(),
        "root workspace.dependencies keeps no reference edge: {root_hits:?}"
    );
    // No run evidence inside committed testdata: only corpus/profile fixtures.
    let mut committed: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(data_dir()).expect("data dir") {
        let entry = entry.expect("entry");
        committed.push(entry.file_name().to_string_lossy().into_owned());
    }
    for name in &committed {
        let extension = std::path::Path::new(name)
            .extension()
            .and_then(|ext| ext.to_str());
        assert!(
            extension == Some("json") || extension == Some("toml"),
            "testdata carries fixtures only, found: {name}"
        );
        assert!(
            !name.contains("evidence") && !name.contains("run") && !name.contains("receipt"),
            "no run evidence in testdata: {name}"
        );
    }
    assert!(
        committed
            .iter()
            .any(|name| name == "store_concurrency_cases.json")
    );
    assert!(
        committed
            .iter()
            .any(|name| name == "store_concurrency_profile.toml")
    );
}
