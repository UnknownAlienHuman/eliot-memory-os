//! #1144 read-owner proof: single stateless owner + full failure matrix.
//!
//! DISPOSITION (WIRE): `ReadService` is the one Governor read projection in
//! this package. It holds no cache, no freshness state, and no second
//! consistency algorithm: the only field is the caller-owned store client,
//! and every read re-queries that client under the caller fence. These tests
//! prove the in-package consequences of that disposition against a minimal
//! in-test [`CanonicalReadClient`] that derives every field from the incoming
//! request (operation/fence/scope gates, request-derived payloads and heads):
//!
//! - stateless single owner: repeated reads re-dispatch (counted), a head
//!   change is served fresh (never cached), exact replay is byte-stable;
//! - stale/conflict degradation: minimum-revision breach, exact-fence drift,
//!   mid-read churn, and foreign fence/operation responses all fail typed;
//! - store boundary: `Unavailable` (and every other [`StoreError`]
//!   discriminant) keeps its exact [`StoreReadFailure`] identity and never
//!   becomes a successful empty/current result;
//! - restart/rebuild: a generation cutover fails closed with typed
//!   `FenceMismatch`, and a rebuilt client serves the new generation only;
//! - closed contract: intent dimensions are enums, selectors are bounded
//!   scalars, the retired free-text query field is gone from the wire.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::task::{Context, Poll, Waker};

use eliot_contracts::{
    ClockReading, ContractError, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
    ResourceGeneration, SourceId, StateFence,
};
use eliot_read::{
    BranchEnvironmentScope, EliotResourceUri, FreshnessPolicy, NamedParameters, QueryIntent,
    QueryMode, QueryRequest, ReadApi, ReadError, ReadService, RequiredAssurance, ResourceRequest,
    StateRequest, StoreReadFailure, TimeScope,
};
use eliot_store_api::{
    CanonicalReadClient, NamedReadOperation, NamedReadRequest, NamedReadResponse, ReadConsistency,
    RevisionHead, RevisionKey, ScopeId, StoreError,
};
use serde_json::{Value, json};

/// Drives the read facade without an async runtime (this crate has none):
/// every test future is immediately ready because the in-test client performs
/// no I/O.
fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut pinned = Box::pin(future);
    loop {
        match pinned.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn test_epoch(sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
    use std::num::NonZeroU64;
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?;
    let sequence = NonZeroU64::new(sequence).ok_or(StoreError::InvalidField {
        field: "test.sequence",
        reason: "must be non-zero",
    })?;
    Ok(EpochId::new(lineage, sequence)?)
}

fn fence(generation: u64) -> Result<StateFence, Box<dyn std::error::Error>> {
    Ok(StateFence::new(
        test_epoch(1)?,
        ResourceGeneration::new(generation)?,
    ))
}

fn metadata(fence: &StateFence, tag: &str) -> Result<RequestMetadata, Box<dyn std::error::Error>> {
    Ok(RequestMetadata {
        request_id: RequestId::new(format!("request-proof-{tag}"))?,
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-proof")?,
        source_id: SourceId::new("source-proof")?,
        state_fence: fence.clone(),
        clock: ClockReading {
            valid_time_ms: Some(1),
            known_time_ms: Some(1),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        },
    })
}

fn scope_key() -> Result<RevisionKey, StoreError> {
    RevisionKey::new("scope:scope-proof")
}

fn scope_id() -> Result<ScopeId, StoreError> {
    ScopeId::new("scope-proof")
}

fn current_position_intent() -> QueryIntent {
    QueryIntent {
        mode: QueryMode::CurrentPosition,
        time_scope: TimeScope::DeclaredFence,
        branch_environment_scope: BranchEnvironmentScope::RequestScope,
        freshness_policy: FreshnessPolicy::ExactFence,
        required_assurance: RequiredAssurance::InputReconstructionOnly,
    }
}

fn state_request(consistency: ReadConsistency, minimum: u64) -> Result<StateRequest, StoreError> {
    let mut dependencies = BTreeMap::new();
    if minimum > 0 {
        dependencies.insert(scope_key()?, minimum);
    }
    Ok(StateRequest {
        operation: NamedReadOperation::GetScopeRevisionView,
        scope_id: Some(scope_id()?),
        consistency,
        dependency_revisions: dependencies,
        parameters: NamedParameters::new(),
        provenance_handles: Vec::new(),
    })
}

fn query_request(consistency: ReadConsistency, minimum: u64) -> Result<QueryRequest, StoreError> {
    let mut dependencies = BTreeMap::new();
    if minimum > 0 {
        dependencies.insert(scope_key()?, minimum);
    }
    Ok(QueryRequest {
        intent: current_position_intent(),
        operation: NamedReadOperation::GetScopeRevisionView,
        scope_id: Some(scope_id()?),
        consistency,
        dependency_revisions: dependencies,
        parameters: NamedParameters::new(),
        provenance_handles: Vec::new(),
    })
}

/// Shared dispatch counters owned by the test while the service owns the
/// client: every store call is observable, so caching would be visible as a
/// missing dispatch.
#[derive(Clone, Default)]
struct DispatchCounts {
    heads_calls: Arc<AtomicUsize>,
    execute_calls: Arc<AtomicUsize>,
}

/// Minimal in-test read table with counted dispatch and deterministic faults.
///
/// Every response field derives from the incoming request: operation/fence
/// gates mirror the production adapters, heads carry the served revision,
/// and the payload echoes scope, served revision, and fence generation.
/// Nothing is canned: tests mutate `revision`, `flip_heads`, `unavailable`,
/// `wrong_fence`, and `wrong_operation` to drive each matrix cell.
struct OwnerProofClient {
    fence: StateFence,
    revision: Arc<AtomicU64>,
    flip_heads: AtomicBool,
    unavailable: AtomicBool,
    wrong_fence: Option<StateFence>,
    wrong_operation: AtomicBool,
    counts: DispatchCounts,
}

impl OwnerProofClient {
    fn new(fence: StateFence) -> Self {
        Self::with_counts(fence, DispatchCounts::default())
    }

    fn with_counts(fence: StateFence, counts: DispatchCounts) -> Self {
        Self::with_shared(fence, counts, Arc::new(AtomicU64::new(1)))
    }

    fn with_shared(fence: StateFence, counts: DispatchCounts, revision: Arc<AtomicU64>) -> Self {
        Self {
            fence,
            revision,
            flip_heads: AtomicBool::new(false),
            unavailable: AtomicBool::new(false),
            wrong_fence: None,
            wrong_operation: AtomicBool::new(false),
            counts,
        }
    }

    fn served_revision(&self) -> u64 {
        if self.flip_heads.load(Ordering::SeqCst) {
            // Odd dispatch calls observe revision 1, even calls revision 2,
            // so a stable-scope read deterministically observes churn.
            if self.counts.heads_calls.load(Ordering::SeqCst) % 2 == 1 {
                1
            } else {
                2
            }
        } else {
            self.revision.load(Ordering::SeqCst)
        }
    }

    fn head(&self, key: RevisionKey, revision: u64) -> RevisionHead {
        RevisionHead {
            key,
            revision,
            state_fence: self.fence.clone(),
        }
    }
}

impl CanonicalReadClient for OwnerProofClient {
    async fn revision_heads(
        &self,
        keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        self.counts.heads_calls.fetch_add(1, Ordering::SeqCst);
        let revision = self.served_revision();
        keys.into_iter()
            .map(|key| Ok(self.head(key, revision)))
            .collect()
    }

    async fn execute_named(
        &self,
        request: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        self.counts.execute_calls.fetch_add(1, Ordering::SeqCst);
        request.validate()?;
        if request.operation != NamedReadOperation::GetScopeRevisionView {
            return Err(StoreError::UnknownOperation);
        }
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        if request.state_fence != self.fence {
            return Err(StoreError::FenceMismatch);
        }
        let scope = request.scope_id.clone().ok_or(StoreError::InvalidField {
            field: "scope_id",
            reason: "proof read requires scope_id",
        })?;
        let operation = if self.wrong_operation.load(Ordering::SeqCst) {
            NamedReadOperation::GetMailbox
        } else {
            request.operation
        };
        let fence = self
            .wrong_fence
            .clone()
            .unwrap_or_else(|| self.fence.clone());
        let revision = self.revision.load(Ordering::SeqCst);
        let response = NamedReadResponse {
            operation,
            state_fence: fence.clone(),
            revision_heads: vec![self.head(scope_key()?, revision)],
            payload: json!({
                "scope": scope.as_str(),
                "revision": revision,
                "generation": fence.resource_generation.value(),
            }),
        };
        response.validate()?;
        Ok(response)
    }
}

fn payload_revision(payload: &Value) -> Option<u64> {
    payload.get("revision")?.as_u64()
}

#[test]
fn read_service_is_stateless_single_owner_every_read_requeries_store()
-> Result<(), Box<dyn std::error::Error>> {
    // No cache exists between calls: every read dispatches (counted below),
    // and a head change is served fresh instead of from a stale projection.
    let fence_one = fence(1)?;
    let ctx = metadata(&fence_one, "stateless")?;
    let counts = DispatchCounts::default();
    let revision = Arc::new(AtomicU64::new(1));
    let client = OwnerProofClient::with_shared(fence_one.clone(), counts.clone(), revision.clone());
    let service = ReadService::new(client);

    let first = block_on(service.state(&ctx, state_request(ReadConsistency::Eventual, 0)?))?;
    assert_eq!(payload_revision(&first.payload), Some(1));
    // Eventual with no dependencies issues no head pre-read: one dispatch,
    // zero head calls.
    assert_eq!(counts.execute_calls.load(Ordering::SeqCst), 1);
    assert_eq!(counts.heads_calls.load(Ordering::SeqCst), 0);

    // A repeat read re-dispatches instead of hitting a cache.
    let second = block_on(service.state(&ctx, state_request(ReadConsistency::Eventual, 0)?))?;
    assert_eq!(first, second);
    assert_eq!(counts.execute_calls.load(Ordering::SeqCst), 2);
    assert_eq!(counts.heads_calls.load(Ordering::SeqCst), 0);

    // Exact-fence reads observe before/after heads on every call: one
    // dispatch plus two head reads, then the new revision served fresh.
    let fenced = block_on(service.state(&ctx, state_request(ReadConsistency::ExactFence, 1)?))?;
    assert_eq!(payload_revision(&fenced.payload), Some(1));
    assert_eq!(fenced.state_fence, fence_one);
    assert_eq!(fenced.revision_heads.len(), 1);
    assert_eq!(counts.execute_calls.load(Ordering::SeqCst), 3);
    assert_eq!(counts.heads_calls.load(Ordering::SeqCst), 2);

    // A head change between calls is served fresh: the facade holds no
    // cached projection that could go stale.
    revision.store(2, Ordering::SeqCst);
    let fresh = block_on(service.state(&ctx, state_request(ReadConsistency::Eventual, 0)?))?;
    assert_eq!(payload_revision(&fresh.payload), Some(2));
    assert_eq!(counts.execute_calls.load(Ordering::SeqCst), 4);
    Ok(())
}

#[test]
fn exact_replay_is_stable() -> Result<(), Box<dyn std::error::Error>> {
    let fence_one = fence(1)?;
    let ctx = metadata(&fence_one, "replay")?;
    let service = ReadService::new(OwnerProofClient::new(fence_one));
    let first = block_on(service.query(&ctx, query_request(ReadConsistency::Eventual, 0)?))?;
    let second = block_on(service.query(&ctx, query_request(ReadConsistency::Eventual, 0)?))?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn stale_minimum_rejects_before_dispatch() -> Result<(), Box<dyn std::error::Error>> {
    let fence_one = fence(1)?;
    let ctx = metadata(&fence_one, "stale")?;
    let client = OwnerProofClient::new(fence_one);
    let service = ReadService::new(client);
    // Declared minimum 5 over served revision 1: stale, never current.
    let result = block_on(service.state(&ctx, state_request(ReadConsistency::ExactFence, 5)?));
    assert_eq!(result, Err(ReadError::StaleRevision));
    Ok(())
}

#[test]
fn exact_fence_drift_is_stale_not_current() -> Result<(), Box<dyn std::error::Error>> {
    let fence_one = fence(1)?;
    let ctx = metadata(&fence_one, "drift")?;
    let client = OwnerProofClient::new(fence_one);
    client.revision.store(2, Ordering::SeqCst);
    let service = ReadService::new(client);
    // Minimum 1 is satisfied, but the exact-fence identity moved to 2.
    let result = block_on(service.state(&ctx, state_request(ReadConsistency::ExactFence, 1)?));
    assert_eq!(result, Err(ReadError::StaleRevision));
    Ok(())
}

#[test]
fn mid_read_churn_conflicts() -> Result<(), Box<dyn std::error::Error>> {
    let fence_one = fence(1)?;
    let ctx = metadata(&fence_one, "churn")?;
    let client = OwnerProofClient::new(fence_one);
    client.flip_heads.store(true, Ordering::SeqCst);
    let service = ReadService::new(client);
    let result = block_on(service.state(&ctx, state_request(ReadConsistency::ExactFence, 1)?));
    assert_eq!(result, Err(ReadError::RevisionChurn));
    Ok(())
}

#[test]
fn foreign_fence_and_operation_responses_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let fence_one = fence(1)?;
    let ctx = metadata(&fence_one, "mismatch")?;
    let fence_other = fence(2)?;

    let mut fenced_client = OwnerProofClient::new(fence_one.clone());
    fenced_client.wrong_fence = Some(fence_other);
    let fenced_service = ReadService::new(fenced_client);
    let result = block_on(fenced_service.state(&ctx, state_request(ReadConsistency::Eventual, 0)?));
    assert_eq!(result, Err(ReadError::ResponseMismatch));

    let op_client = OwnerProofClient::new(fence_one);
    op_client.wrong_operation.store(true, Ordering::SeqCst);
    let op_service = ReadService::new(op_client);
    let result = block_on(op_service.state(&ctx, state_request(ReadConsistency::Eventual, 0)?));
    assert_eq!(result, Err(ReadError::ResponseMismatch));
    Ok(())
}

#[test]
fn unavailable_is_typed_never_empty_success() -> Result<(), Box<dyn std::error::Error>> {
    let fence_one = fence(1)?;
    let ctx = metadata(&fence_one, "unavailable")?;
    let client = OwnerProofClient::new(fence_one);
    client.unavailable.store(true, Ordering::SeqCst);
    let service = ReadService::new(client);
    // The typed identity survives end to end; no payload is produced.
    let result = block_on(service.state(&ctx, state_request(ReadConsistency::Eventual, 0)?));
    assert_eq!(result, Err(ReadError::Store(StoreReadFailure::Unavailable)));
    let query = block_on(service.query(&ctx, query_request(ReadConsistency::Eventual, 0)?));
    assert_eq!(query, Err(ReadError::Store(StoreReadFailure::Unavailable)));
    Ok(())
}

#[test]
fn generation_restart_invalidates_and_rebuild_serves_new_generation_only()
-> Result<(), Box<dyn std::error::Error>> {
    let fence_one = fence(1)?;
    let ctx_one = metadata(&fence_one, "gen-one")?;
    let service = ReadService::new(OwnerProofClient::new(fence_one.clone()));
    let first = block_on(service.state(&ctx_one, state_request(ReadConsistency::Eventual, 0)?))?;
    assert_eq!(
        first.payload.get("generation").and_then(Value::as_u64),
        Some(1)
    );

    // The same service under the cut-over fence fails closed with the exact
    // typed fence identity: generation one is never served as current.
    let fence_two = fence(2)?;
    let ctx_two = metadata(&fence_two, "gen-two")?;
    let stale = block_on(service.state(&ctx_two, state_request(ReadConsistency::Eventual, 0)?));
    assert_eq!(
        stale,
        Err(ReadError::Store(StoreReadFailure::FenceMismatch))
    );

    // Rebuild under the new generation serves the new generation only.
    let rebuilt = ReadService::new(OwnerProofClient::new(fence_two.clone()));
    let second = block_on(rebuilt.state(&ctx_two, state_request(ReadConsistency::Eventual, 0)?))?;
    assert_eq!(second.state_fence, fence_two);
    assert_eq!(
        second.payload.get("generation").and_then(Value::as_u64),
        Some(2)
    );
    assert_ne!(first.payload, second.payload);
    Ok(())
}

/// Every value-constructible `StoreError` discriminant paired with its exact
/// `StoreReadFailure` identity. (`Foundation`/`Security`/`Receipt` inners keep
/// their exact display text; only `Foundation` is value-constructible from
/// this package's dependencies, the other two arms are compiler-exhaustive.)
fn store_failure_cases() -> Vec<(StoreError, StoreReadFailure)> {
    let foundation = ContractError::Blank { field: "proof" }.to_string();
    vec![
        (
            StoreError::InvalidField {
                field: "proof",
                reason: "malformed",
            },
            StoreReadFailure::InvalidField {
                field: "proof".to_owned(),
                reason: "malformed".to_owned(),
            },
        ),
        (
            StoreError::Empty { field: "proof" },
            StoreReadFailure::Empty {
                field: "proof".to_owned(),
            },
        ),
        (
            StoreError::Duplicate { field: "proof" },
            StoreReadFailure::Duplicate {
                field: "proof".to_owned(),
            },
        ),
        (
            StoreError::Foundation(ContractError::Blank { field: "proof" }),
            StoreReadFailure::Foundation(foundation),
        ),
        (
            StoreError::UnknownOperation,
            StoreReadFailure::UnknownOperation,
        ),
        (
            StoreError::ManifestMismatch,
            StoreReadFailure::ManifestMismatch,
        ),
        (
            StoreError::TransitionClassExceeded,
            StoreReadFailure::TransitionClassExceeded,
        ),
        (
            StoreError::EffectCeilingExceeded,
            StoreReadFailure::EffectCeilingExceeded,
        ),
        (StoreError::FenceMismatch, StoreReadFailure::FenceMismatch),
        (
            StoreError::RevisionConflict,
            StoreReadFailure::RevisionConflict,
        ),
        (
            StoreError::OrderingConflict,
            StoreReadFailure::OrderingConflict,
        ),
        (
            StoreError::InvalidProjection,
            StoreReadFailure::InvalidProjection,
        ),
        (StoreError::InvalidOutbox, StoreReadFailure::InvalidOutbox),
        (StoreError::InvalidReceipt, StoreReadFailure::InvalidReceipt),
        (
            StoreError::IdentityConflict,
            StoreReadFailure::IdentityConflict,
        ),
        (
            StoreError::TransitionDigestMismatch {
                expected: "expected-digest".to_owned(),
                observed: "observed-digest".to_owned(),
            },
            StoreReadFailure::TransitionDigestMismatch {
                expected: "expected-digest".to_owned(),
                observed: "observed-digest".to_owned(),
            },
        ),
        (
            StoreError::ReceiptNotFound,
            StoreReadFailure::ReceiptNotFound,
        ),
        (
            StoreError::MissingReceiptEnvelope,
            StoreReadFailure::MissingReceiptEnvelope,
        ),
        (
            StoreError::PayloadTooLarge,
            StoreReadFailure::PayloadTooLarge,
        ),
        (StoreError::Unavailable, StoreReadFailure::Unavailable),
        (
            StoreError::Serialization("proof-serialization".to_owned()),
            StoreReadFailure::Serialization("proof-serialization".to_owned()),
        ),
    ]
}

#[test]
fn store_failures_keep_typed_identity() -> Result<(), Box<dyn std::error::Error>> {
    // Each discriminant maps to exactly one failure; displays stay distinct
    // and every failure survives a serde round trip.
    let cases = store_failure_cases();
    let mut displays = BTreeSet::new();
    for (store, expected) in &cases {
        let mapped = StoreReadFailure::from(store.clone());
        assert_eq!(&mapped, expected);
        // The `ReadError` conversion delegates without erasure.
        assert_eq!(
            ReadError::from(store.clone()),
            ReadError::Store(expected.clone())
        );
        assert!(!format!("{mapped}").is_empty());
        assert!(displays.insert(format!("{mapped}")));
        // Wire round trip preserves the exact typed identity.
        let wire = serde_json::to_value(ReadError::Store(mapped))?;
        let back: ReadError = serde_json::from_value(wire)?;
        assert_eq!(back, ReadError::Store(expected.clone()));
    }
    assert_eq!(displays.len(), cases.len());
    Ok(())
}

#[test]
fn named_parameters_reject_unbounded_filters() -> Result<(), Box<dyn std::error::Error>> {
    assert!(NamedParameters::new().is_empty());
    assert_eq!(NamedParameters::new().len(), 0);
    // Numbers and booleans are closed scalar selectors.
    let scalars = NamedParameters::from_map(BTreeMap::from([
        ("attempt".to_owned(), json!(3)),
        ("complete".to_owned(), json!(true)),
    ]))?;
    assert_eq!(scalars.len(), 2);

    // Null, nested filters, and reserved retired-selector names fail.
    let null = NamedParameters::from_map(BTreeMap::from([("subject".to_owned(), Value::Null)]));
    assert!(matches!(
        null,
        Err(ReadError::InvalidField { field, .. }) if field == "named_parameter"
    ));
    let nested = NamedParameters::from_map(BTreeMap::from([(
        "filter".to_owned(),
        json!({"any": ["edge-1"]}),
    )]));
    assert!(matches!(
        nested,
        Err(ReadError::InvalidField { field, .. }) if field == "named_parameter"
    ));
    let listed = NamedParameters::from_map(BTreeMap::from([("ids".to_owned(), json!(["a"]))]));
    assert!(matches!(
        listed,
        Err(ReadError::InvalidField { field, .. }) if field == "named_parameter"
    ));
    for reserved in ["query", "exact_resource_uri"] {
        let smuggled = NamedParameters::from_map(BTreeMap::from([(
            reserved.to_owned(),
            Value::String("selector".to_owned()),
        )]));
        assert!(
            matches!(
                smuggled,
                Err(ReadError::DuplicateField(field)) if field == "named_parameters"
            ),
            "{reserved} must fail closed"
        );
    }

    // Shape bounds fail: blank key, control characters, over-long key and
    // text, and more than 32 selectors.
    assert!(matches!(
        NamedParameters::from_map(BTreeMap::from([("  ".to_owned(), json!("x"))])),
        Err(ReadError::EmptyField(_))
    ));
    assert!(matches!(
        NamedParameters::from_map(BTreeMap::from([("a\tb".to_owned(), json!("x"))])),
        Err(ReadError::InvalidField { .. })
    ));
    assert!(matches!(
        NamedParameters::from_map(BTreeMap::from([("k".repeat(129), json!("x"))])),
        Err(ReadError::InvalidField { .. })
    ));
    assert!(matches!(
        NamedParameters::from_map(BTreeMap::from([("k".to_owned(), json!("x".repeat(8193)))])),
        Err(ReadError::InvalidField { .. })
    ));
    let crowded: BTreeMap<String, Value> = (0..33)
        .map(|index| (format!("selector-{index}"), json!(index)))
        .collect();
    assert!(matches!(
        NamedParameters::from_map(crowded),
        Err(ReadError::InvalidField { field, .. }) if field == "named_parameters"
    ));

    // Facade-bound exact identities cannot be shadowed by caller selectors.
    let mut bound = NamedParameters::new();
    bound.insert_exact("resource_uri", "eliot://resource/1")?;
    assert!(matches!(
        bound.insert_exact("resource_uri", "eliot://resource/2"),
        Err(ReadError::DuplicateField(field)) if field == "named_parameters"
    ));
    Ok(())
}

#[test]
fn intent_gate_admits_closed_modes_rejects_foreign_operation()
-> Result<(), Box<dyn std::error::Error>> {
    let intent_for = |mode| QueryIntent {
        mode,
        time_scope: TimeScope::DeclaredFence,
        branch_environment_scope: BranchEnvironmentScope::RequestScope,
        freshness_policy: FreshnessPolicy::ExactFence,
        required_assurance: RequiredAssurance::InputReconstructionOnly,
    };
    // One admitted operation per mode validates with its scope rule.
    let admitted: Vec<(QueryMode, NamedReadOperation, Option<&str>)> = vec![
        (
            QueryMode::CurrentPosition,
            NamedReadOperation::GetScopeRevisionView,
            Some("scope-proof"),
        ),
        (
            QueryMode::HistoricalReconstruction,
            NamedReadOperation::GetAuditRange,
            Some("scope-proof"),
        ),
        (
            QueryMode::Provenance,
            NamedReadOperation::ResolveWriteReceipt,
            None,
        ),
        (
            QueryMode::Navigation,
            NamedReadOperation::GetRevisionHeads,
            None,
        ),
        (
            QueryMode::Verification,
            NamedReadOperation::GetEvidencePack,
            Some("scope-proof"),
        ),
        (
            QueryMode::ChangeImpact,
            NamedReadOperation::GetEvidencePack,
            Some("scope-proof"),
        ),
        (
            QueryMode::ContextReconstruction,
            NamedReadOperation::GetTaskState,
            Some("scope-proof"),
        ),
    ];
    for (mode, operation, scope) in admitted {
        let mut parameters = NamedParameters::new();
        if operation == NamedReadOperation::GetEvidencePack {
            parameters = NamedParameters::from_map(BTreeMap::from([
                ("subject".to_owned(), Value::String("proof".to_owned())),
                ("max_records".to_owned(), Value::String("4".to_owned())),
            ]))?;
        }
        let request = QueryRequest {
            intent: intent_for(mode),
            operation,
            scope_id: scope.map(ScopeId::new).transpose()?,
            consistency: ReadConsistency::ExactFence,
            dependency_revisions: BTreeMap::new(),
            parameters,
            provenance_handles: Vec::new(),
        };
        request.validate()?;
        // `GetMailbox` belongs to no query mode: uniformly refused at the
        // intent gate (scoped so the request reaches that gate).
        let refused = QueryRequest {
            intent: intent_for(mode),
            operation: NamedReadOperation::GetMailbox,
            scope_id: Some(scope_id()?),
            consistency: ReadConsistency::ExactFence,
            dependency_revisions: BTreeMap::new(),
            parameters: NamedParameters::new(),
            provenance_handles: Vec::new(),
        };
        assert!(
            matches!(
                refused.validate(),
                Err(ReadError::InvalidIntentOperation { .. })
            ),
            "{mode:?} must refuse GetMailbox"
        );
    }
    Ok(())
}

#[test]
fn resource_expansion_binds_exact_uri() -> Result<(), Box<dyn std::error::Error>> {
    let fence_one = fence(1)?;
    let ctx = metadata(&fence_one, "resource")?;
    let service = ReadService::new(OwnerProofClient::new(fence_one.clone()));
    let uri = EliotResourceUri::new("eliot://resource/proof-1")?;
    let request = ResourceRequest {
        uri: uri.clone(),
        operation: NamedReadOperation::GetScopeRevisionView,
        scope_id: Some(scope_id()?),
        consistency: ReadConsistency::Eventual,
        dependency_revisions: BTreeMap::new(),
        parameters: NamedParameters::new(),
        provenance_handles: Vec::new(),
    };
    let content = block_on(service.resource(&ctx, request))?;
    assert_eq!(content.uri, uri);
    assert_eq!(content.state_fence, fence_one);
    assert_eq!(content.revision_heads.len(), 1);

    // A caller-supplied `resource_uri` selector cannot shadow the exact URI.
    let shadowed = ResourceRequest {
        uri,
        operation: NamedReadOperation::GetScopeRevisionView,
        scope_id: Some(scope_id()?),
        consistency: ReadConsistency::Eventual,
        dependency_revisions: BTreeMap::new(),
        parameters: NamedParameters::from_map(BTreeMap::from([(
            "resource_uri".to_owned(),
            Value::String("eliot://resource/foreign".to_owned()),
        )]))?,
        provenance_handles: Vec::new(),
    };
    assert!(
        block_on(service.resource(&ctx, shadowed)).is_err(),
        "shadowed exact URI must fail closed"
    );
    Ok(())
}

#[test]
fn wire_shape_has_no_free_text_query() -> Result<(), Box<dyn std::error::Error>> {
    // The serialized query carries closed enum dimensions and selectors only:
    // no `query` text field, no request-level resource URI, no free-text
    // intent dimensions.
    let request = query_request(ReadConsistency::ExactFence, 1)?;
    let wire = serde_json::to_value(&request)?;
    let object = wire
        .as_object()
        .ok_or("query request serializes as an object")?;
    assert!(!object.contains_key("query"), "free-text query is gone");
    assert!(
        !object.contains_key("exact_resource_uri"),
        "request-level URI is gone"
    );
    let intent = object.get("intent").ok_or("intent serializes")?;
    assert_eq!(
        intent.get("mode").and_then(Value::as_str),
        Some("current_position")
    );
    assert_eq!(
        intent.get("time_scope").and_then(Value::as_str),
        Some("declared_fence")
    );
    let back: QueryRequest = serde_json::from_value(wire)?;
    assert_eq!(back, request);

    // Unknown future intent prose fails decoding instead of widening the read.
    let foreign = json!({
        "mode": "current_position",
        "time_scope": "whenever",
        "branch_environment_scope": "request_scope",
        "freshness_policy": "exact_fence",
        "required_assurance": "input_reconstruction_only",
    });
    assert!(serde_json::from_value::<QueryIntent>(foreign).is_err());
    Ok(())
}
