//! Issue 883: deep-copy `MemoryStore` clone contract disposition.
//!
//! Single evidence-backed disposition: remove the unused `Clone`. There is no
//! `Clone` impl and no explicitly-named fork; independent models reuse
//! `MemoryStore::new` construction plus the `MemoryStore::snapshot` value
//! projection. The fourteen `883/1`..`883/14` cases in
//! `tests/data/memory_store_clone_cases.json` drive this harness.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Mutex;

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
    assert!(
        !source.contains("into_inner"),
        "case {id}: no poisoned-lock recovery via into_inner may remain"
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
    // Issue 883 case 6, historical half: the inspected historical Clone was
    // a deep copy (independent state, not shared handles). This non-production
    // replica binds that semantic so the record shows what was removed; the
    // current-result half above preserves independence via construction plus
    // snapshot, with no Clone impl remaining (guarded by 883/1).
    let historical = HistoricalDeepCopyStore::seeded();
    let fork = historical.historical_clone();
    fork.put("k", "forked")?;
    assert_eq!(
        historical.get("k")?,
        Some("seed".to_owned()),
        "case {}: historical deep copy must be independent, not shared",
        case.id
    );
    historical.put("j", "origin")?;
    assert_eq!(
        fork.get("j")?,
        None,
        "case {}: historical independence must hold both ways",
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
    // Live 883/7 denominator also binds here (snapshot carries the
    // projected fields); the marked 883/7 test owns the obligation.
    check_state_field_denominator(&case.id)?;
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
    // Live 883/8 poison history also binds here (typed failure is the live
    // 883/13 obligation's core); the marked 883/8 test owns that obligation.
    check_historical_poison(id)?;
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

/// Minimal non-production replica of the inspected historical `MemoryStore`
/// Clone (issue 883, inspected base `aed215f...`): lock plus deep copy of the
/// state into a new mutex, with the poisoned branch recovering through
/// `into_inner().clone()` into a valid store. Test-only regression fixture;
/// never a production API and never a substitute fork.
#[derive(Debug, Default)]
struct HistoricalDeepCopyStore {
    state: Mutex<BTreeMap<String, String>>,
}

impl HistoricalDeepCopyStore {
    fn seeded() -> Self {
        Self {
            state: Mutex::new(BTreeMap::from([(String::from("k"), String::from("seed"))])),
        }
    }

    fn historical_clone(&self) -> Self {
        match self.state.lock() {
            Ok(guard) => Self {
                state: Mutex::new(guard.clone()),
            },
            Err(poisoned) => Self {
                state: Mutex::new(poisoned.into_inner().clone()),
            },
        }
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, String>>, Box<dyn std::error::Error>>
    {
        match self.state.lock() {
            Ok(guard) => Ok(guard),
            Err(error) => Err(format!("historical fixture lock poisoned: {error}").into()),
        }
    }

    fn put(&self, key: &str, value: &str) -> TestResult {
        self.lock()?.insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        Ok(self.lock()?.get(key).cloned())
    }

    fn snapshot_content(&self) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
        Ok(self.lock()?.clone())
    }

    fn poison(&self) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Ok(_guard) = self.state.lock() else {
                panic!("historical fixture must start healthy");
            };
            panic!("intentional historical-fixture poisoning");
        }));
        assert!(outcome.is_err(), "poisoning must unwind");
        assert!(
            self.state.is_poisoned(),
            "fixture mutex must be poisoned after the unwind"
        );
    }
}

/// Exact `MemoryState` field denominator at the inspected revision: every
/// field the removed deep copy duplicated. Sourced from `src/lib.rs`; the
/// guard using it fails on any silent field addition or removal.
const MEMORY_STATE_FIELDS: [&str; 17] = [
    "epistemic_positions",
    "fences",
    "recovery_records",
    "recovery_jobs",
    "revision_heads",
    "ordering_heads",
    "receipts_by_operation",
    "receipts_by_idempotency",
    "projections",
    "outbox",
    "relations",
    "named_operations",
    "manifests",
    "erasure_intents",
    "erased_subjects",
    "next_commit_sequence",
    "next_outbox_sequence",
];

/// Extracts the brace-balanced body of `struct <name>` from Rust source.
fn struct_block(source: &str, name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let anchor = format!("struct {name}");
    let start = source
        .find(anchor.as_str())
        .ok_or_else(|| format!("lib.rs must define `struct {name}`"))?;
    let after = &source[start..];
    let open = after
        .find('{')
        .ok_or_else(|| format!("`struct {name}` must have a body"))?;
    let mut depth = 0usize;
    for (offset, ch) in after.char_indices().skip(open) {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            if depth == 0 {
                return Ok(after[open..=offset].to_owned());
            }
        }
    }
    Err(format!("`struct {name}` body is unbalanced").into())
}

/// Issue 883 cases 1..5: executable workspace denominator. Every exact
/// `MemoryStore` reference known at this revision is read and asserted
/// construction- or comment-only: no Clone adjacency, no cloned store
/// receiver, and no Clone trait bound on the type. The
/// full tracked-workspace grep (`MemoryStore` across `crates/` and `bins/`)
/// was run during review and recorded in the work report; this test binds
/// the resulting file list so silent new consumers fail the gate instead of
/// passing unnoticed. Generic `.clone()` calls on other types (fences,
/// digests, receipts, parameters) are excluded by receiver resolution: only
/// lines naming `MemoryStore` are inspected.
fn check_workspace_denominator(id: &str) -> TestResult {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // (relative path, MemoryStore lines allowed to mention): the memory
    // package's own `src/lib.rs` and this harness are covered by dedicated
    // source guards (`check_absent_clone` plus the `compile_fail` doctest),
    // so they are not re-scanned line-wise here.
    let files = [
        "src/epistemic_tests.rs",
        "../eliot-backup/tests/restore_contract.rs",
        "../eliot-store-surreal-adapter/src/apply/read_boundary.rs",
    ];
    for rel in files {
        let text = std::fs::read_to_string(manifest_dir.join(rel))
            .map_err(|error| format!("case {id}: cannot read denominator file {rel}: {error}"))?;
        for line in text.lines() {
            if line.contains("MemoryStore") && (line.contains("Clone") || line.contains("clone")) {
                return Err(format!(
                    "case {id}: unexpected Clone-adjacent MemoryStore use in {rel}: {line}"
                )
                .into());
            }
        }
        if text.contains("MemoryStore") {
            assert!(
                !text.contains("store.clone()"),
                "case {id}: no MemoryStore receiver may be cloned in {rel}"
            );
        }
    }
    // Clone-trait-bound scan. This harness file itself is excluded: the
    // guard literals below name the pattern (self-reference), and a foreign
    // `impl Clone for MemoryStore` here would be a compile error (E0117),
    // so the compile gate already proves its absence.
    for rel in ["src/lib.rs", "src/epistemic_tests.rs"] {
        let text = std::fs::read_to_string(manifest_dir.join(rel))
            .map_err(|error| format!("case {id}: cannot read bound file {rel}: {error}"))?;
        assert!(
            !text.contains("MemoryStore: Clone") && !text.contains("MemoryStore:Clone"),
            "case {id}: no Clone trait bound on MemoryStore may exist in {rel}"
        );
    }
    Ok(())
}

/// Universe of files that may name `MemoryStore`, bound by the tracked
/// workspace grep recorded in the delivery report. `src/lib.rs` (definition)
/// and this harness are covered by dedicated guards; the rest are read here.
fn denominator_files() -> [&'static str; 5] {
    [
        "src/lib.rs",
        "src/epistemic_tests.rs",
        "tests/memory_store_clone.rs",
        "../eliot-backup/tests/restore_contract.rs",
        "../eliot-store-surreal-adapter/src/apply/read_boundary.rs",
    ]
}

fn read_relative(rel: &str, id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(manifest_dir.join(rel))
        .map_err(|error| format!("case {id}: cannot read {rel}: {error}").into())
}

/// Live 883/2: generic `.clone()` call sites excluded unless a
/// `MemoryStore` receiver resolves. Executable proof: no cloned store
/// receiver exists in any universe file, and no `MemoryStore` clone path
/// exists. Guard-assertion lines (which name the pattern inside `contains(`)
/// are not call sites and are skipped; every other match fails the gate.
fn check_generic_clone_exclusion(id: &str) -> TestResult {
    for rel in denominator_files() {
        let text = read_relative(rel, id)?;
        for line in text.lines() {
            if line.contains("contains(") {
                continue;
            }
            assert!(
                !line.contains("store.clone()"),
                "case {id}: generic clone must not resolve to a store in {rel}: {line}"
            );
            assert!(
                !line.contains("MemoryStore::clone") && !line.contains("MemoryStore.clone()"),
                "case {id}: no MemoryStore clone path may exist in {rel}: {line}"
            );
        }
    }
    Ok(())
}

/// Collects every `MemoryStore::<item>` associated-function mention in text.
/// Guard-assertion lines (naming the pattern inside `contains(`) are skipped:
/// they quote the pattern, never call it.
fn associated_items(text: &str) -> Vec<String> {
    let mut items = Vec::new();
    for line in text.lines() {
        if line.contains("contains(") {
            continue;
        }
        let mut rest = line;
        while let Some(pos) = rest.find("MemoryStore::") {
            let after = &rest[pos + "MemoryStore::".len()..];
            let end = after
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(after.len());
            if end > 0 {
                items.push(after[..end].to_owned());
            }
            rest = &after[end.min(after.len())..];
        }
    }
    items
}

/// Live 883/3: every in-package production `MemoryStore::` call accounted
/// for. The exact inventory at this revision is construction (`new`),
/// value projection (`snapshot`), manifest admission, transaction apply, and
/// the erasure intent/apply/outcome reads; anything else fails closed.
fn check_production_calls(id: &str) -> TestResult {
    let allowed = [
        "new",
        "snapshot",
        "register_manifest",
        "apply_transaction",
        "record_erasure_intent",
        "apply_erasure",
        "erasure_outcomes",
        "erased_subjects",
        "projections",
        "outbox",
    ];
    for rel in ["src/lib.rs", "src/epistemic_tests.rs"] {
        let text = read_relative(rel, id)?;
        for item in associated_items(&text) {
            assert!(
                allowed.contains(&item.as_str()),
                "case {id}: unaccounted production MemoryStore::{item} in {rel}"
            );
        }
    }
    Ok(())
}

/// Live 883/4: every package-test `MemoryStore::` call accounted for.
/// Tests construct only via `new`/`default` and read only via `snapshot`.
fn check_package_test_calls(id: &str) -> TestResult {
    let text = read_relative("tests/memory_store_clone.rs", id)?;
    for item in associated_items(&text) {
        assert!(
            ["new", "default", "snapshot"].contains(&item.as_str()),
            "case {id}: unaccounted test MemoryStore::{item}"
        );
    }
    // Fork-name scan is line-wise: this file's own guard strings (which quote
    // the names inside `contains(`) are not definitions.
    for line in text.lines() {
        if line.contains("contains(") {
            continue;
        }
        assert!(
            !line.contains("independent_fork")
                && !line.contains("fork_clone")
                && !line.contains("try_clone"),
            "case {id}: test scope must not name a replacement fork: {line}"
        );
    }
    Ok(())
}

/// Live 883/5: trait/generic Clone requirements accounted for. The
/// `compile_fail` doctest (`needs_clone::<MemoryStore>()`) is the executable
/// bound proof — it runs in the package doctest gate; this test pins its
/// presence so silent removal fails — plus a source bound scan.
fn check_clone_bounds(id: &str) -> TestResult {
    let source = lib_source()?;
    assert!(
        source.contains("```compile_fail"),
        "case {id}: absent-Clone compile proof must remain a compile_fail doctest"
    );
    assert!(
        source.contains("needs_clone::<MemoryStore>();"),
        "case {id}: compile proof must deny the Clone bound on MemoryStore"
    );
    for rel in ["src/lib.rs", "src/epistemic_tests.rs"] {
        let text = read_relative(rel, id)?;
        assert!(
            !text.contains("MemoryStore: Clone") && !text.contains("MemoryStore:Clone"),
            "case {id}: no Clone trait bound on MemoryStore may exist in {rel}"
        );
    }
    Ok(())
}

/// Live 883/7: cloned/forked state-field and cost denominator, explicit and
/// source-bound. Removal eliminates the copy, so no copy-cost claim is made
/// or measured; the denominator names every field the removed deep copy used
/// to duplicate, plus the snapshot projection that remains.
fn check_state_field_denominator(id: &str) -> TestResult {
    let source = lib_source()?;
    let state_block = struct_block(&source, "MemoryState")?;
    for field in MEMORY_STATE_FIELDS {
        assert!(
            state_block.contains(field),
            "case {id}: MemoryState denominator must name '{field}'"
        );
    }
    let snapshot_block = struct_block(&source, "MemorySnapshot")?;
    for field in [
        "state_fence",
        "revision_heads",
        "ordering_heads",
        "receipts",
        "projections",
        "outbox",
        "relations",
        "named_operations",
    ] {
        assert!(
            snapshot_block.contains(field),
            "case {id}: MemorySnapshot denominator must name '{field}'"
        );
    }
    Ok(())
}

/// Live 883/8: historical poison behavior in isolation, plus proof the
/// selected removal boundary does not reproduce silent successful poisoned
/// copying. The replica demonstrates the removed `into_inner().clone()`
/// recovery succeeding on poisoned state; the source guards prove no such
/// path remains. (The private mutex cannot be poisoned from an integration
/// test, so poisoned-lock execution proof lives in the package-local inline
/// test `poisoned_store_refuses_snapshot_and_reports_unavailable`, run by the
/// same package gate.)
fn check_historical_poison(id: &str) -> TestResult {
    let historical = HistoricalDeepCopyStore::seeded();
    let before = historical.historical_clone().snapshot_content()?;
    historical.poison();
    let copied = historical.historical_clone();
    assert_eq!(
        copied.snapshot_content()?,
        before,
        "case {id}: historical poisoned branch copied state silently"
    );
    let source = lib_source()?;
    assert!(
        source.contains("map_err(|_| StoreError::Unavailable)"),
        "case {id}: poisoned locks must map to typed Unavailable"
    );
    assert!(
        !source.contains("into_inner"),
        "case {id}: poisoned state must not be recoverable into a new store"
    );
    Ok(())
}

/// Live 883/9 (removal branch): public Clone absent and real package
/// consumers compile. Absence is source-guarded here and compile-proved by
/// the `compile_fail` doctest; the real consumer
/// (`eliot-backup/tests/restore_contract.rs`) is read here to bind its
/// construction-only use, and its compile is proved by the
/// `cargo test --no-run -p eliot-backup` gate recorded in delivery.
fn check_removal_absence(id: &str) -> TestResult {
    let source = lib_source()?;
    check_absent_clone(&source, id)?;
    let consumer = read_relative("../eliot-backup/tests/restore_contract.rs", id)?;
    assert!(
        consumer.contains("eliot_store_memory::MemoryStore::new()"),
        "case {id}: real consumer must construct via MemoryStore::new()"
    );
    for line in consumer.lines() {
        if line.contains("contains(") {
            continue;
        }
        assert!(
            !line.contains("store.clone()"),
            "case {id}: real consumer must never clone the store: {line}"
        );
    }
    Ok(())
}

/// Live 883/11 (removal branch): existing snapshot behavior retained and
/// independently exercised without Clone — fresh empty, deterministic reads,
/// and one write carrying receipt, projection, and outbox.
fn check_snapshot_retained(id: &str) -> TestResult {
    check_fresh_empty(id)?;
    check_snapshot_determinism(id)?;
    let fence = fence()?;
    let ctx = request_meta(&fence)?;
    let store = test_store()?;
    store.apply_transaction(
        &ctx,
        transition_with_subject("op-883-11-live", "subject-883-11-live", &fence)?,
        &[],
        &[],
    )?;
    let snapshot = store.snapshot()?;
    assert_eq!(
        snapshot.receipts.len(),
        1,
        "case {id}: one receipt retained"
    );
    assert_eq!(
        snapshot.projections.len(),
        1,
        "case {id}: one projection retained"
    );
    assert_eq!(
        snapshot.outbox.len(),
        1,
        "case {id}: one outbox intent retained"
    );
    assert_eq!(
        snapshot.named_operations.len(),
        1,
        "case {id}: one named operation retained"
    );
    assert_eq!(
        store.snapshot()?,
        snapshot,
        "case {id}: retained snapshot reads must be deterministic"
    );
    Ok(())
}

/// Live 883/12 (removal branch): independently constructed stores stay
/// isolated under mutations in both directions, with no shared state.
fn check_bidirectional_isolation(id: &str) -> TestResult {
    let fence = fence()?;
    let ctx = request_meta(&fence)?;
    let left = test_store()?;
    let right = test_store()?;
    let left_before = left.snapshot()?;
    let right_before = right.snapshot()?;
    assert_eq!(
        left_before, right_before,
        "case {id}: constructions must start equal"
    );
    left.apply_transaction(
        &ctx,
        transition_with_subject("op-883-12-left", "subject-883-12-left", &fence)?,
        &[],
        &[],
    )?;
    assert_ne!(
        left.snapshot()?,
        right_before,
        "case {id}: left write must diverge"
    );
    assert_eq!(
        right.snapshot()?,
        right_before,
        "case {id}: right construction must not move on left write"
    );
    right.apply_transaction(
        &ctx,
        transition_with_subject("op-883-12-right", "subject-883-12-right", &fence)?,
        &[],
        &[],
    )?;
    assert_ne!(
        right.snapshot()?,
        right_before,
        "case {id}: right write must diverge"
    );
    assert_eq!(
        left.snapshot()?,
        left.snapshot()?,
        "case {id}: left store must be stable across right write"
    );
    let source = lib_source()?;
    check_no_shared_state(&source, id);
    Ok(())
}

fn run_case(case: &Case, source: &str) -> TestResult {
    match case.kind.as_str() {
        "absent_clone_source_guard" => {
            check_absent_clone(source, &case.id)?;
            check_workspace_denominator(&case.id)
        }
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

/// Runs exactly one `883/<n>` fixture case (1-based `index` + 1) with the
/// same order and source guards as the full-matrix sweep above, so each
/// `// WORK_UNIT_CASE` test below executes its case substantively.
fn run_single(index: usize) -> TestResult {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/memory_store_clone_cases.json");
    let text = std::fs::read_to_string(path)?;
    let file: CaseFile = serde_json::from_str(&text)?;
    assert_eq!(file.cases.len(), 14, "issue 883 requires exactly 14 cases");
    let case = file
        .cases
        .get(index)
        .ok_or_else(|| format!("missing clone-contract case at index {index}"))?;
    let expected = format!("883/{}", index + 1);
    assert_eq!(case.id, expected, "cases must run in 883/1..14 order");
    let source = lib_source()?;
    run_case(case, &source).map_err(|error| format!("case {} failed: {error}", case.id))?;
    Ok(())
}

// WORK_UNIT_CASE: 883/1 — live 1 (workspace source/type denominator) plus
// live 9/10 absence guards. Substantive: denominator file reads inside.
#[test]
fn clone_contract_01_absent_clone_and_denominator() -> TestResult {
    run_single(0)
}

// WORK_UNIT_CASE: 883/2 — live 2 (generic `.clone()` excluded unless a
// MemoryStore receiver resolves). Fixture sweep stays supplemental.
#[test]
fn clone_contract_02_fresh_construction_empty() -> TestResult {
    run_single(1)?;
    check_generic_clone_exclusion("883/2")
}

// WORK_UNIT_CASE: 883/3 — live 3 (every in-package production call
// accounted for). Fixture sweep stays supplemental.
#[test]
fn clone_contract_03_snapshot_determinism() -> TestResult {
    run_single(2)?;
    check_production_calls("883/3")
}

// WORK_UNIT_CASE: 883/4 — live 4 (every package-test call accounted for).
// Fixture sweep stays supplemental.
#[test]
fn clone_contract_04_snapshot_value_projection() -> TestResult {
    run_single(3)?;
    check_package_test_calls("883/4")
}

// WORK_UNIT_CASE: 883/5 — live 5 (trait/generic Clone requirements
// accounted for). Fixture sweep stays supplemental.
#[test]
fn clone_contract_05_construction_equality() -> TestResult {
    run_single(4)?;
    check_clone_bounds("883/5")
}

// WORK_UNIT_CASE: 883/6 — live 6 (historical independent-copy fixture;
// current construction-plus-snapshot preserves independence).
#[test]
fn clone_contract_06_isolation_and_historical_copy() -> TestResult {
    run_single(5)
}

// WORK_UNIT_CASE: 883/7 — live 7 (state-field and cost denominator,
// explicit, no measured cost claims). Fixture sweep stays supplemental.
#[test]
fn clone_contract_07_isolation_right_to_left() -> TestResult {
    run_single(6)?;
    check_state_field_denominator("883/7")
}

// WORK_UNIT_CASE: 883/8 — live 8 (historical poison fixture; removal
// boundary has no silent poisoned copy). Fixture sweep stays supplemental.
#[test]
fn clone_contract_08_divergence_detection() -> TestResult {
    run_single(7)?;
    check_historical_poison("883/8")
}

// WORK_UNIT_CASE: 883/9 — live 9 removal branch (public Clone absent; real
// consumer construction-only and compiling via the recorded --no-run gate).
// Fixture sweep stays supplemental.
#[test]
fn clone_contract_09_projection_and_field_denominator() -> TestResult {
    run_single(8)?;
    check_removal_absence("883/9")
}

// WORK_UNIT_CASE: 883/10 — live 10 removal branch (neither Clone nor an
// unjustified replacement fork, Arc, shared state, or global).
#[test]
fn clone_contract_10_default_ctor_equivalence() -> TestResult {
    run_single(9)?;
    let source = lib_source()?;
    check_absent_clone(&source, "883/10")?;
    check_no_shared_state(&source, "883/10");
    Ok(())
}

// WORK_UNIT_CASE: 883/11 — live 11 removal branch (snapshot behavior
// retained and exercised without Clone). Typed-failure sweep stays
// supplemental.
#[test]
fn clone_contract_11_poison_contract_and_history() -> TestResult {
    run_single(10)?;
    check_snapshot_retained("883/11")
}

// WORK_UNIT_CASE: 883/12 — live 12 removal branch (bidirectional isolation
// of independently constructed stores; no shared state introduced). Seeded
// subject sweep stays supplemental.
#[test]
fn clone_contract_12_seeded_capture_subject() -> TestResult {
    run_single(11)?;
    check_bidirectional_isolation("883/12")
}

// WORK_UNIT_CASE: 883/13 — live 13 removal branch (no clone/fork escape;
// poison/error contract retained). Shared-state sweep stays supplemental.
#[test]
fn clone_contract_13_no_shared_state() -> TestResult {
    run_single(12)?;
    let source = lib_source()?;
    check_absent_clone(&source, "883/13")?;
    check_typed_failure("883/13")
}

// WORK_UNIT_CASE: 883/14 — live 14 (diff guard: no Arc/shared global, no
// fork, snapshot path named; file-scope binding recorded in delivery).
#[test]
fn clone_contract_14_doc_contract() -> TestResult {
    run_single(13)?;
    let source = lib_source()?;
    check_absent_clone(&source, "883/14")?;
    check_no_shared_state(&source, "883/14");
    Ok(())
}
