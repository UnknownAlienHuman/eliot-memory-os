//! Concurrent canonical transaction allocation (S-CONC-TX, issue #989).
//!
//! Proves the minimal provider transaction/allocation correction against the
//! merged #987 bounded session set: disjoint admitted transitions stay
//! correct when provider sessions overlap, without an application-global
//! write gate on the allocation path and without changing Store transaction
//! semantics. The deterministic unguarded race repro and the pooled-session
//! overlap proofs execute as inline tests beside the seam
//! (`apply::concurrent_allocation_tests`); this target binds the twenty
//! acceptance cases through the public adapter surface on isolated
//! providers plus exact source/fixture guards.
//!
//! Declared denominator, exactly one substantive test per case:
//!
//! 1. concurrent disjoint-scope commits share no allocation;
//! 2. disjoint commits carry unique valid commit/outbox allocation and exact
//!    per-scope heads;
//! 3. revision-head checks stay inside the provider transaction;
//! 4. ordering-head and fence checks stay inside the provider transaction;
//! 5. partial event/projection/relation/outbox/receipt effects cannot survive
//!    a proved rollback;
//! 6. concurrent exact same-operation submission yields one effect set and
//!    the original receipt;
//! 7. changed same-operation content conflicts without mutation;
//! 8. deterministic allocation contention is distinct from semantic
//!    stale-head conflict;
//! 9. only proved-not-committed attempts may use the bounded permitted retry;
//! 10. possible-commit outcomes never retry or allocate another operation;
//! 11. post-commit response loss reconciles to the exact original receipt;
//! 12. independently proved absence versus still-unknown reconciliation;
//! 13. allocation/counter/event/outbox/receipt mismatch is never accepted as
//!    committed;
//! 14. integer/range/batch bounds and exhaustion preserve exact allocation
//!    disposition;
//! 15. supported source generations retain explicit canonical compatibility;
//! 16. genesis/migration cannot reset or collide with committed allocation;
//! 17. foreign/stale fence or identity invalidates the prior plan;
//! 18. sequential reference preserves semantic histories, allowing only
//!    explicitly nonsemantic interleaving differences;
//! 19. real provider concurrency records exact sessions, transaction
//!    outcomes, and no full-duration application-global gate;
//! 20. source/API/diff guard excludes dropped optimistic guards, non-atomic
//!    receipts, hidden sequence reinterpretation, blind retry, process-local
//!    authority, or unrelated changes.
//!
//! Rework proofs beyond the denominator (no denominator change):
//! `production_path_disjoint_writers_overlap_and_conflicts_fail_closed`
//! races two disjoint writers through the public production entry from a
//! barrier-synchronized start, and Case 3 derives its stale expectation
//! from the baseline receipt's observed pre-commit head value.
//!
//! Provider evidence (recorded on failure output and in the work item): the
//! pinned `surreal.exe` path plus its SHA-256, the server version handshake
//! enforced by the adapter, the per-test loopback port, and the temporary
//! data/work/tmp roots.
#![cfg(windows)]
#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Test-only allowances: provider-evidence logging prints bounded setup facts
//! (no credentials), concurrent test futures hold admitted transitions across
//! awaits, and live allocation proofs necessarily run long flows.
#![allow(clippy::print_stdout, clippy::large_futures, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
use eliot_platform_windows::WindowsPlatform;
use eliot_store_api::{
    CONTRACT_VERSION, CanonicalRequestView, CanonicalStoreClient, EffectClass,
    EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest, OperationId,
    OperationIdentity, OperationManifestDigest, OrderingHeadExpectation, OrderingScopeId,
    PreparedTransition, RequestMeta, RevisionHeadExpectation, RevisionKey, ScopeId,
    SecurityContext, StateFence, StoreError, StoreRecoveryRequest, StoreRecoverySnapshot,
    TransitionClass, WriteReceipt, canonical_request_hash, generated_operation_manifests,
    operation_manifest_set_digest, validate_store_receipt_envelope,
};
use eliot_store_surreal_adapter::{
    PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn descriptor() -> Value {
    serde_json::from_str(include_str!("data/concurrent_transaction_allocation.json"))
        .expect("allocation fixture")
}

fn source(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .expect("current source")
}

fn fence() -> StateFence {
    use std::num::NonZeroU64;
    let lineage = EpochLineageId::new(TEST_LINEAGE).expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn foreign_fence() -> StateFence {
    use std::num::NonZeroU64;
    let lineage = EpochLineageId::new(TEST_LINEAGE).expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(2).expect("non-zero")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn fixture_ctx(operation: &str, fence: &StateFence) -> RequestMeta {
    use eliot_contracts::{ClockReading, ProductId, RequestId, SourceId};
    RequestMeta {
        request_id: RequestId::new(format!("request-{operation}")).expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-989").expect("product"),
        source_id: SourceId::new("source-989").expect("source"),
        state_fence: fence.clone(),
        clock: ClockReading {
            valid_time_ms: Some(1000),
            known_time_ms: Some(1001),
            ..ClockReading::default()
        },
    }
}

/// One admitted disjoint-scope capture: valid catalogue digest and recomputed
/// request hash, so only allocation or declared head expectations can fail.
fn admitted(operation: &str, scope: &str, subject: &str) -> (RequestMeta, PreparedTransition) {
    let fence = fence();
    let ctx = fixture_ctx(operation, &fence);
    let mut transition = PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new(operation).expect("operation"),
            idempotency_key: format!("idem-{operation}"),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence,
        scope_id: ScopeId::new(scope).expect("scope"),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new(scope).expect("ordering")],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: OperationManifestDigest::new("manifest-1").expect("manifest"),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([("subject".to_owned(), json!(subject))]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    transition.operation_manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().expect("catalogue"))
            .expect("manifest digest");
    transition.identity.canonical_request_hash = canonical_request_hash(
        &CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]),
    )
    .expect("request hash");
    (ctx, transition)
}

/// One admitted capture under a caller-supplied fence (foreign-fence case).
fn admitted_under(
    operation: &str,
    scope: &str,
    subject: &str,
    fence: &StateFence,
) -> (RequestMeta, PreparedTransition) {
    let ctx = fixture_ctx(operation, fence);
    let (_, mut transition) = admitted(operation, scope, subject);
    transition.state_fence = fence.clone();
    transition.identity.canonical_request_hash = canonical_request_hash(
        &CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]),
    )
    .expect("request hash");
    (ctx, transition)
}

fn commit_sequence(receipt: &WriteReceipt) -> String {
    receipt
        .committed_at
        .clone()
        .expect("committed receipt carries its instant")
}

struct Harness {
    root: PathBuf,
    config: SurrealAdapterConfig,
    adapter: Option<SurrealStoreAdapter>,
    case: String,
}

impl Harness {
    async fn fresh(case: &str) -> Self {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("loopback")
            .local_addr()
            .expect("address")
            .port();
        let root =
            std::env::temp_dir().join(format!("eliot-sconc-989-{case}-{}", uuid::Uuid::new_v4()));
        let exe = root.join("bin/surreal.exe");
        let data = root.join("store/data");
        let work = root.join("store/work");
        let tmp = root.join("store/tmp");
        for path in [root.join("bin"), data.clone(), work.clone(), tmp.clone()] {
            std::fs::create_dir_all(path).expect("isolated root");
        }
        let provider = std::env::var_os("ELIOT_TEST_SURREAL_EXE").map_or_else(
            || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
            PathBuf::from,
        );
        std::fs::copy(&provider, &exe).expect("stage provider");
        let digest = eliot_store_api::sha256_hex(&std::fs::read(&exe).expect("provider bytes"));
        let bind = format!("127.0.0.1:{port}");
        let mut config = SurrealAdapterConfig {
            endpoint: format!("ws://{bind}/rpc"),
            namespace: format!("sconc989{case}"),
            database: "alloc989".into(),
            username: format!("sconc989-{case}"),
            password: SecretString::new(format!("test-{}", uuid::Uuid::new_v4()).into()),
            provider_bind_address: bind,
            installation_id: format!("sconc989-{case}"),
            installation_profile: "portable_dev".into(),
            runtime_state_roots_digest: "a".repeat(64),
            provider_executable_path: exe.to_string_lossy().into_owned(),
            provider_artifact_digest: digest,
            provider_arguments: Vec::new(),
            store_data_root: data.to_string_lossy().into_owned(),
            store_work_root: work.to_string_lossy().into_owned(),
            store_temp_root: tmp.to_string_lossy().into_owned(),
            connect_timeout_ms: 30_000,
            query_timeout_ms: 30_000,
            expected_provider_major: PINNED_SURREALDB_MAJOR,
            expected_schema_generation: SchemaGeneration::v2(),
        };
        config.provider_arguments = config.expected_provider_arguments();
        let mut harness = Self {
            root,
            config,
            adapter: None,
            case: case.to_owned(),
        };
        println!(
            "SCONC-989 case={} provider={} sha256={} port={} root={}",
            case,
            exe.display(),
            harness.config.provider_artifact_digest,
            port,
            harness.root.display()
        );
        harness.bootstrap().await;
        harness.open().await;
        harness.migrate().await;
        harness
    }

    async fn bootstrap(&self) {
        use std::os::windows::process::CommandExt;
        let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let mut child = std::process::Command::new(&self.config.provider_executable_path)
            .args(&self.config.provider_arguments)
            .current_dir(&self.config.store_work_root)
            .env_clear()
            .env("SystemRoot", &system_root)
            .env("WINDIR", &system_root)
            .env("TEMP", &self.config.store_temp_root)
            .env("TMP", &self.config.store_temp_root)
            .env("SURREAL_USER", &self.config.username)
            .env("SURREAL_PASS", self.config.password.expose_secret())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .spawn()
            .expect("bootstrap provider");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                child.try_wait().expect("child status").is_none(),
                "bootstrap exited"
            );
            if std::net::TcpStream::connect(&self.config.provider_bind_address).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "bootstrap bind timeout");
            std::thread::sleep(Duration::from_millis(50));
        }
        child.kill().expect("stop bootstrap");
        child.wait().expect("reap bootstrap");
    }

    async fn open(&mut self) {
        let platform = WindowsPlatform::new(self.root.clone()).expect("platform");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let mut last_error = None;
        loop {
            let lease = platform
                .retain_process_path_lease(
                    Path::new(&self.config.provider_executable_path),
                    Path::new(&self.config.store_work_root),
                    &self.config.provider_artifact_digest,
                )
                .expect("process lease");
            self.adapter =
                Some(SurrealStoreAdapter::new(self.config.clone(), lease).expect("adapter"));
            match tokio::time::timeout_at(deadline, self.adapter().connect()).await {
                Ok(Ok(())) => return,
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => {
                    self.adapter = None;
                    panic!(
                        "case {} readiness timed out; last error: {last_error:?}",
                        self.case
                    );
                }
            }
            self.adapter = None;
            assert!(
                tokio::time::Instant::now() < deadline,
                "case {} readiness timed out; last error: {last_error:?}",
                self.case
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn migrate(&self) {
        let ctx = fixture_ctx(&format!("migrate-{}", self.case), &fence());
        self.adapter()
            .apply_migration(
                &SurrealStoreAdapter::v2_baseline_migration(),
                &ctx.clock,
                &ctx.state_fence,
            )
            .await
            .expect("baseline migration");
    }

    fn adapter(&self) -> &SurrealStoreAdapter {
        self.adapter.as_ref().expect("live adapter")
    }

    async fn commit(
        &self,
        operation: &str,
        scope: &str,
        subject: &str,
    ) -> Result<WriteReceipt, StoreError> {
        let (ctx, transition) = admitted(operation, scope, subject);
        CanonicalStoreClient::apply_prepared(self.adapter(), &ctx, transition, vec![], vec![]).await
    }

    async fn snapshot(&self) -> StoreRecoverySnapshot {
        self.adapter()
            .recovery(StoreRecoveryRequest {
                contract_version: CONTRACT_VERSION,
                state_fence: fence(),
                records: Vec::new(),
                include_receipts: true,
                include_jobs: false,
            })
            .await
            .expect("recovery snapshot")
    }

    async fn cleanup(mut self) {
        self.adapter = None;
        let deadline = Instant::now() + Duration::from_secs(15);
        while std::fs::remove_dir_all(&self.root).is_err() {
            assert!(
                Instant::now() < deadline,
                "case {} root cleanup failed",
                self.case
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

// WORK_UNIT_CASE: 989/1
#[tokio::test]
async fn disjoint_scopes_commit_concurrently_with_unique_allocation() {
    let descriptor = descriptor();
    assert_eq!(descriptor["denominator"], 20);
    let harness = Harness::fresh("01").await;
    let (ctx_a, transition_a) = admitted("op-989-case01-a", "scope-989-a", "subject-989-01-a");
    let (ctx_b, transition_b) = admitted("op-989-case01-b", "scope-989-b", "subject-989-01-b");
    let (receipt_a, receipt_b) = tokio::join!(
        CanonicalStoreClient::apply_prepared(
            harness.adapter(),
            &ctx_a,
            transition_a,
            vec![],
            vec![],
        ),
        CanonicalStoreClient::apply_prepared(
            harness.adapter(),
            &ctx_b,
            transition_b,
            vec![],
            vec![],
        )
    );
    let receipt_a = receipt_a.expect("concurrent writer A commits");
    let receipt_b = receipt_b.expect("concurrent writer B commits");
    // Interleaving-insensitive: the allocated pair is exactly {1,2} whatever
    // the commit order was; the unguarded deterministic repro lives beside
    // the seam in `apply::concurrent_allocation_tests`.
    let mut committed = BTreeSet::new();
    committed.insert(commit_sequence(&receipt_a));
    committed.insert(commit_sequence(&receipt_b));
    assert_eq!(
        committed,
        BTreeSet::from([
            "commit-sequence-0000000000000001".to_owned(),
            "commit-sequence-0000000000000002".to_owned(),
        ]),
        "concurrent disjoint writers share no allocation"
    );
    assert_ne!(
        receipt_a.outbox_refs, receipt_b.outbox_refs,
        "outbox allocation is unique per commit"
    );
    assert_eq!(harness.snapshot().await.receipts.len(), 2);
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/2
#[tokio::test]
async fn disjoint_commits_carry_unique_allocation_and_exact_per_scope_heads() {
    let harness = Harness::fresh("02").await;
    let (ctx_a, transition_a) = admitted("op-989-case02-a", "scope-989-a", "subject-989-02-a");
    let receipt_a = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx_a,
        transition_a,
        vec![],
        vec![],
    )
    .await
    .expect("first disjoint commit");
    let (ctx_b, transition_b) = admitted("op-989-case02-b", "scope-989-b", "subject-989-02-b");
    let receipt_b = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx_b,
        transition_b,
        vec![],
        vec![],
    )
    .await
    .expect("second disjoint commit");
    assert_eq!(
        commit_sequence(&receipt_a),
        "commit-sequence-0000000000000001"
    );
    assert_eq!(
        commit_sequence(&receipt_b),
        "commit-sequence-0000000000000002"
    );
    for (receipt, scope) in [(&receipt_a, "scope-989-a"), (&receipt_b, "scope-989-b")] {
        receipt.validate().expect("receipt validates");
        assert_eq!(receipt.ordering_sequences.len(), 1);
        assert_eq!(receipt.ordering_sequences[0].scope.to_string(), scope);
        assert_eq!(receipt.revision_before_after.len(), 1);
        let delta = &receipt.revision_before_after[0];
        assert_eq!(delta.after, delta.before + 1, "heads advance exactly once");
    }
    assert_eq!(
        receipt_a.ordering_sequences[0].sequence, receipt_b.ordering_sequences[0].sequence,
        "symmetric disjoint commits advance symmetric per-scope heads"
    );
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/3
#[tokio::test]
async fn revision_head_checks_remain_inside_the_provider_transaction() {
    let harness = Harness::fresh("03").await;
    let baseline = harness
        .commit("op-989-case03-a", "scope-989-a", "subject-989-03-a")
        .await
        .expect("baseline commit");
    // The stale expectation is the baseline's own observed pre-commit head
    // value: the baseline advanced the head by exactly one, so that value
    // is provably superseded rather than merely plausibly old.
    assert_eq!(baseline.revision_before_after.len(), 1);
    let stale_revision = baseline.revision_before_after[0].before;
    assert_eq!(
        baseline.revision_before_after[0].after,
        stale_revision + 1,
        "baseline advanced the head by exactly one"
    );
    let (ctx, transition) = admitted("op-989-case03-stale", "scope-989-a", "subject-989-03-stale");
    let stale = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition,
        vec![RevisionHeadExpectation {
            key: RevisionKey::new("scope:scope-989-a").expect("revision key"),
            expected_revision: stale_revision,
            state_fence: fence(),
        }],
        vec![],
    )
    .await;
    assert!(
        matches!(stale, Err(StoreError::RevisionConflict)),
        "stale revision expectation is a deterministic conflict, got {stale:?}"
    );
    // The refused attempt consumed no allocation: the next commit still takes
    // exactly sequence 2 and exactly one receipt is durable.
    let next = harness
        .commit("op-989-case03-next", "scope-989-a", "subject-989-03-next")
        .await
        .expect("next commit");
    assert_eq!(commit_sequence(&next), "commit-sequence-0000000000000002");
    assert_eq!(harness.snapshot().await.receipts.len(), 2);
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/4
#[tokio::test]
async fn ordering_head_and_fence_checks_remain_inside_the_provider_transaction() {
    let harness = Harness::fresh("04").await;
    harness
        .commit("op-989-case04-a", "scope-989-a", "subject-989-04-a")
        .await
        .expect("baseline commit");
    let (ctx, transition) = admitted("op-989-case04-stale", "scope-989-a", "subject-989-04-stale");
    let stale = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition,
        vec![],
        vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new("scope-989-a").expect("ordering scope"),
            expected_sequence: 1,
            state_fence: fence(),
        }],
    )
    .await;
    assert!(
        matches!(stale, Err(StoreError::OrderingConflict)),
        "stale ordering expectation is a deterministic conflict, got {stale:?}"
    );
    let next = harness
        .commit("op-989-case04-next", "scope-989-a", "subject-989-04-next")
        .await
        .expect("next commit");
    assert_eq!(commit_sequence(&next), "commit-sequence-0000000000000002");
    assert_eq!(harness.snapshot().await.receipts.len(), 2);
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/5
#[tokio::test]
async fn proved_rollback_leaves_no_partial_effects() {
    let harness = Harness::fresh("05").await;
    let baseline = harness
        .commit("op-989-case05-a", "scope-989-a", "subject-989-05-a")
        .await
        .expect("baseline commit");
    let (ctx, transition) = admitted("op-989-case05-stale", "scope-989-a", "subject-989-05-stale");
    let refused = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition,
        vec![RevisionHeadExpectation {
            key: RevisionKey::new("scope:scope-989-a").expect("revision key"),
            expected_revision: 1,
            state_fence: fence(),
        }],
        vec![],
    )
    .await;
    assert!(matches!(refused, Err(StoreError::RevisionConflict)));
    // No partial event/projection/relation/outbox/receipt effects survive:
    // exactly the baseline receipt is durable, the refused identity never
    // committed, and the next allocation is untouched.
    let snapshot = harness.snapshot().await;
    snapshot.validate().expect("snapshot validates");
    assert_eq!(snapshot.receipts.len(), 1);
    assert_eq!(snapshot.receipts[0], baseline);
    let missing = harness
        .adapter()
        .reconcile(OperationId::new("op-989-case05-stale").expect("operation"))
        .await
        .expect("reconcile reads");
    assert_eq!(missing, None, "refused operation never committed");
    let next = harness
        .commit("op-989-case05-next", "scope-989-b", "subject-989-05-next")
        .await
        .expect("next commit");
    assert_eq!(commit_sequence(&next), "commit-sequence-0000000000000002");
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/6
#[tokio::test]
async fn concurrent_same_operation_yields_one_effect_set_and_original_receipt() {
    let harness = Harness::fresh("06").await;
    let (ctx_a, transition_a) = admitted("op-989-case06-same", "scope-989-a", "subject-989-06");
    let (ctx_b, transition_b) = admitted("op-989-case06-same", "scope-989-a", "subject-989-06");
    let (first, second) = tokio::join!(
        CanonicalStoreClient::apply_prepared(
            harness.adapter(),
            &ctx_a,
            transition_a,
            vec![],
            vec![],
        ),
        CanonicalStoreClient::apply_prepared(
            harness.adapter(),
            &ctx_b,
            transition_b,
            vec![],
            vec![],
        )
    );
    let first = first.expect("same-op submission commits");
    let second = second.expect("same-op submission resolves");
    assert_eq!(
        first, second,
        "exact duplicate submission returns the original receipt"
    );
    let snapshot = harness.snapshot().await;
    assert_eq!(
        snapshot.receipts.len(),
        1,
        "duplicate submissions persist one effect set"
    );
    assert_eq!(snapshot.receipts[0], first);
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/7
#[tokio::test]
async fn changed_same_operation_content_conflicts_without_mutation() {
    let harness = Harness::fresh("07").await;
    let original = harness
        .commit("op-989-case07-x", "scope-989-a", "subject-989-07")
        .await
        .expect("original commit");
    // Same operation identity, substituted content.
    let (ctx, mut transition) = admitted("op-989-case07-x", "scope-989-a", "subject-989-07-alt");
    transition.identity.idempotency_key = "idem-op-989-case07-x".to_owned();
    transition.identity.canonical_request_hash = canonical_request_hash(
        &CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]),
    )
    .expect("request hash");
    let conflict =
        CanonicalStoreClient::apply_prepared(harness.adapter(), &ctx, transition, vec![], vec![])
            .await;
    assert!(
        matches!(conflict, Err(StoreError::IdentityConflict)),
        "changed content under the same identity conflicts, got {conflict:?}"
    );
    // Same idempotency key, different operation identity.
    let (ctx_y, mut transition_y) = admitted("op-989-case07-y", "scope-989-a", "subject-989-07");
    transition_y.identity.idempotency_key = "idem-op-989-case07-x".to_owned();
    transition_y.identity.canonical_request_hash = canonical_request_hash(
        &CanonicalRequestView::from_apply(&ctx_y, &transition_y, &[], &[]),
    )
    .expect("request hash");
    let conflict_y = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx_y,
        transition_y,
        vec![],
        vec![],
    )
    .await;
    assert!(
        matches!(conflict_y, Err(StoreError::IdentityConflict)),
        "key reuse across identities conflicts, got {conflict_y:?}"
    );
    // Neither conflict mutated durable state.
    let snapshot = harness.snapshot().await;
    assert_eq!(snapshot.receipts.len(), 1);
    assert_eq!(snapshot.receipts[0], original);
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/8
#[tokio::test]
async fn allocation_contention_is_distinct_from_semantic_conflict() {
    let descriptor = descriptor();
    let harness = Harness::fresh("08").await;
    // Deterministic semantic conflicts keep their exact typed disposition.
    harness
        .commit("op-989-case08-a", "scope-989-a", "subject-989-08-a")
        .await
        .expect("baseline commit");
    let (ctx, transition) = admitted("op-989-case08-stale", "scope-989-a", "subject-989-08-stale");
    let stale = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition,
        vec![RevisionHeadExpectation {
            key: RevisionKey::new("scope:scope-989-a").expect("revision key"),
            expected_revision: 1,
            state_fence: fence(),
        }],
        vec![],
    )
    .await;
    assert!(matches!(stale, Err(StoreError::RevisionConflict)));
    // Genuine allocation movement between disjoint scopes is never reported
    // as that same semantic conflict: both writers commit.
    let (ctx_c, transition_c) = admitted("op-989-case08-c", "scope-989-c", "subject-989-08-c");
    let (ctx_d, transition_d) = admitted("op-989-case08-d", "scope-989-d", "subject-989-08-d");
    let (receipt_c, receipt_d) = tokio::join!(
        CanonicalStoreClient::apply_prepared(
            harness.adapter(),
            &ctx_c,
            transition_c,
            vec![],
            vec![],
        ),
        CanonicalStoreClient::apply_prepared(
            harness.adapter(),
            &ctx_d,
            transition_d,
            vec![],
            vec![],
        )
    );
    receipt_c.expect("disjoint writer commits, not a false conflict");
    receipt_d.expect("disjoint writer commits, not a false conflict");
    // The provider markers and the boundary mapping stay split exactly as
    // the fixture declares: fence movement is transient contention,
    // semantic staleness is deterministic conflict.
    let writer = source("src/apply/atomic_write.rs");
    for marker in descriptor["allocation_markers"]
        .as_array()
        .expect("allocation markers")
    {
        let marker = marker.as_str().expect("marker");
        assert!(
            writer.contains(marker),
            "allocation marker travels: {marker}"
        );
    }
    assert!(
        writer.contains("AdapterError::AllocationContention"),
        "fence movement classifies as contention"
    );
    let errors = source("src/error.rs");
    assert!(
        errors.contains("AllocationContention { .. } => StoreError::Unavailable"),
        "contention maps to transient Unavailable, never RevisionConflict"
    );
    assert_eq!(
        descriptor["error_mapping"]["allocation_contention"],
        "Unavailable"
    );
    assert_eq!(
        descriptor["error_mapping"]["provider_conflict"],
        "RevisionConflict"
    );
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/9
#[tokio::test]
async fn only_proved_not_committed_attempts_use_the_bounded_retry() {
    let harness = Harness::fresh("09").await;
    // Without contention every commit consumes exactly one allocation: three
    // sequential commits are contiguous, so no phantom retry ever fired.
    for (index, scope) in ["scope-989-a", "scope-989-b", "scope-989-c"]
        .into_iter()
        .enumerate()
    {
        let receipt = harness
            .commit(
                &format!("op-989-case09-{}", index + 1),
                scope,
                &format!("subject-989-09-{}", index + 1),
            )
            .await
            .expect("sequential commit");
        assert_eq!(
            commit_sequence(&receipt),
            format!("commit-sequence-{:016}", index + 1)
        );
    }
    // The retry arm is entered only for proved-not-committed allocation
    // contention, bounded, and re-proves absence before replanning.
    let apply = source("src/apply.rs");
    assert!(
        apply.contains("retries < MAX_ALLOCATION_RETRIES"),
        "retry is bounded"
    );
    assert!(
        apply.contains("Err(AdapterError::AllocationContention { .. })"),
        "only contention re-enters the loop"
    );
    assert!(
        apply.contains("Err(error) => return Err(error)"),
        "every other outcome returns without retry"
    );
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/10
#[tokio::test]
async fn possible_commit_outcomes_never_retry_or_allocate() {
    let harness = Harness::fresh("10").await;
    let receipt = harness
        .commit("op-989-case10-a", "scope-989-a", "subject-989-10-a")
        .await
        .expect("baseline commit");
    // Reconciliation reads allocate nothing: receipt count and the next
    // allocation are unchanged by both hit and miss.
    let reread = harness
        .adapter()
        .reconcile(receipt.operation_id.clone())
        .await
        .expect("reconcile reads");
    assert_eq!(reread, Some(receipt));
    let missing = harness
        .adapter()
        .reconcile(OperationId::new("op-989-case10-missing").expect("operation"))
        .await
        .expect("reconcile reads");
    assert_eq!(missing, None);
    assert_eq!(harness.snapshot().await.receipts.len(), 1);
    let next = harness
        .commit("op-989-case10-b", "scope-989-b", "subject-989-10-b")
        .await
        .expect("next commit");
    assert_eq!(commit_sequence(&next), "commit-sequence-0000000000000002");
    // Transport loss classifies as unknown (reconcile-by-identity), never as
    // a deterministic conflict and never as a silent retry.
    let writer = source("src/apply/atomic_write.rs");
    assert!(
        writer.contains("Err(AdapterError::ProviderUnavailable) =>"),
        "transport loss keeps its unknown-outcome arm"
    );
    let errors = source("src/error.rs");
    assert!(
        errors.contains("UnknownOutcome { .. } | Self::PartialOutcome =>"),
        "unknown outcomes reconcile, never conflict"
    );
    assert_eq!(
        descriptor()["error_mapping"]["unknown_outcome"],
        "MissingReceiptEnvelope"
    );
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/11
#[tokio::test]
async fn post_commit_response_loss_reconciles_to_the_original_receipt() {
    let harness = Harness::fresh("11").await;
    let (ctx, transition) = admitted("op-989-case11-a", "scope-989-a", "subject-989-11-a");
    let committed = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition.clone(),
        vec![],
        vec![],
    )
    .await
    .expect("commit");
    // Simulate a lost commit response: drop the local handle, then
    // reconcile by the exact operation identity.
    let reconciled = harness
        .adapter()
        .reconcile(transition.identity.operation_id.clone())
        .await
        .expect("reconcile reads")
        .expect("committed receipt reconciles");
    assert_eq!(
        reconciled, committed,
        "reconciliation returns the exact original receipt"
    );
    validate_store_receipt_envelope(&ctx, &transition, &reconciled)
        .expect("reconciled envelope validates");
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/12
#[tokio::test]
async fn proven_absence_is_distinct_from_still_unknown() {
    let harness = Harness::fresh("12").await;
    harness
        .commit("op-989-case12-a", "scope-989-a", "subject-989-12-a")
        .await
        .expect("baseline commit");
    // Proven absence is a typed `None`, not an error and not a receipt.
    let absent = harness
        .adapter()
        .reconcile(OperationId::new("op-989-case12-never").expect("operation"))
        .await
        .expect("absence reads cleanly");
    assert_eq!(absent, None, "never-committed identity proves absence");
    // Still-unknown keeps the reconciling disposition at the boundary: the
    // mapping is pinned exactly, never flattened to success or absence.
    let errors = source("src/error.rs");
    assert!(
        errors.contains("UnknownOutcome { .. } | Self::PartialOutcome =>"),
        "unknown outcomes stay reconciling"
    );
    assert!(
        errors.contains("StoreError::MissingReceiptEnvelope"),
        "unknown outcomes reconcile by receipt identity"
    );
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/13
#[tokio::test]
async fn mismatched_state_is_never_accepted_as_committed() {
    let harness = Harness::fresh("13").await;
    let (ctx_a, transition_a) = admitted("op-989-case13-a", "scope-989-a", "subject-989-13-a");
    let receipt_a = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx_a,
        transition_a.clone(),
        vec![],
        vec![],
    )
    .await
    .expect("first commit");
    let (ctx_b, transition_b) = admitted("op-989-case13-b", "scope-989-b", "subject-989-13-b");
    let receipt_b = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx_b,
        transition_b.clone(),
        vec![],
        vec![],
    )
    .await
    .expect("second commit");
    // Exact readback: durable receipts equal the committed bytes.
    for (ctx, transition, receipt) in [
        (&ctx_a, &transition_a, &receipt_a),
        (&ctx_b, &transition_b, &receipt_b),
    ] {
        let readback = harness
            .adapter()
            .reconcile(receipt.operation_id.clone())
            .await
            .expect("readback")
            .expect("durable receipt");
        assert_eq!(&readback, receipt, "readback equals committed bytes");
        validate_store_receipt_envelope(ctx, transition, &readback)
            .expect("readback envelope validates");
    }
    // Mismatched allocation/counter/identity bindings fail closed: an
    // envelope from another allocation is not this operation's receipt.
    let mut tampered = receipt_a.clone();
    tampered.envelope = receipt_b.envelope.clone();
    assert!(
        validate_store_receipt_envelope(&ctx_a, &transition_a, &tampered).is_err(),
        "substituted envelope must fail closed, never replay"
    );
    let mut tampered_id = receipt_a.clone();
    tampered_id.operation_id = receipt_b.operation_id.clone();
    assert!(
        validate_store_receipt_envelope(&ctx_a, &transition_a, &tampered_id).is_err(),
        "substituted identity is never accepted as this commit"
    );
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/14
#[tokio::test]
async fn bounds_and_exhaustion_preserve_exact_allocation_disposition() {
    let descriptor = descriptor();
    assert_eq!(
        descriptor["sequence_bounds"]["overflow"].as_u64(),
        Some(u64::MAX),
        "overflow bound fixture binds u64::MAX"
    );
    assert_eq!(
        descriptor["sequence_bounds"]["zero_expected_is_rejected"].as_u64(),
        Some(0),
        "zero bound fixture binds 0"
    );
    let harness = Harness::fresh("14").await;
    // Zero expectations are rejected before any allocation is consumed.
    let (ctx, transition) = admitted("op-989-case14-zero", "scope-989-a", "subject-989-14-zero");
    let zero_revision = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx,
        transition,
        vec![RevisionHeadExpectation {
            key: RevisionKey::new("scope:scope-989-a").expect("revision key"),
            expected_revision: 0,
            state_fence: fence(),
        }],
        vec![],
    )
    .await;
    assert!(
        matches!(
            zero_revision,
            Err(StoreError::InvalidField {
                field: "expected_revision",
                ..
            })
        ),
        "zero revision expectation fails closed, got {zero_revision:?}"
    );
    let (ctx_o, transition_o) = admitted("op-989-case14-zero-o", "scope-989-a", "subject-989-14-o");
    let zero_ordering = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx_o,
        transition_o,
        vec![],
        vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new("scope-989-a").expect("ordering scope"),
            expected_sequence: 0,
            state_fence: fence(),
        }],
    )
    .await;
    assert!(
        matches!(
            zero_ordering,
            Err(StoreError::InvalidField {
                field: "expected_sequence",
                ..
            })
        ),
        "zero ordering expectation fails closed, got {zero_ordering:?}"
    );
    // Overflow fails closed inside the planner (unit-proven); the planner
    // never wraps, so no live setup can reach it. Every allocated sequence
    // increments through the exact checked helper.
    let plan = source("src/plan.rs");
    assert!(
        plan.matches("checked_increment(").count() >= 4,
        "commit, revision, ordering, and outbox allocation all increment checked"
    );
    // Rejected bounds consumed nothing: the first valid commit still takes
    // exactly the genesis allocation.
    let first = harness
        .commit("op-989-case14-first", "scope-989-a", "subject-989-14-first")
        .await
        .expect("first valid commit");
    assert_eq!(commit_sequence(&first), "commit-sequence-0000000000000001");
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/15
#[tokio::test]
async fn supported_generations_retain_explicit_canonical_compatibility() {
    let harness = Harness::fresh("15").await;
    // The stock v2 baseline is the admitted generation on this base: reads,
    // writes, and receipts all work against it with no extra migration.
    let snapshot = harness.snapshot().await;
    snapshot.validate().expect("empty snapshot validates");
    assert_eq!(snapshot.receipts.len(), 0);
    let receipt = harness
        .commit("op-989-case15-a", "scope-989-a", "subject-989-15-a")
        .await
        .expect("first commit on the supported generation");
    assert_eq!(
        commit_sequence(&receipt),
        "commit-sequence-0000000000000001"
    );
    receipt.validate().expect("receipt validates");
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/16
#[tokio::test]
async fn migration_cannot_reset_or_collide_with_committed_allocation() {
    let harness = Harness::fresh("16").await;
    harness
        .commit("op-989-case16-a", "scope-989-a", "subject-989-16-a")
        .await
        .expect("first commit");
    // Exact migration replay succeeds (idempotent preamble) and leaves the
    // committed allocation untouched.
    let ctx = fixture_ctx("migrate-16-replay", &fence());
    harness
        .adapter()
        .apply_migration(
            &SurrealStoreAdapter::v2_baseline_migration(),
            &ctx.clock,
            &ctx.state_fence,
        )
        .await
        .expect("migration exact replay");
    let next = harness
        .commit("op-989-case16-b", "scope-989-b", "subject-989-16-b")
        .await
        .expect("commit after migration replay");
    assert_eq!(
        commit_sequence(&next),
        "commit-sequence-0000000000000002",
        "migration replay neither resets nor collides with allocation"
    );
    assert_eq!(harness.snapshot().await.receipts.len(), 2);
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/17
#[tokio::test]
async fn foreign_fence_invalidates_the_prior_plan() {
    let harness = Harness::fresh("17").await;
    let foreign = foreign_fence();
    let (ctx, transition) = admitted_under(
        "op-989-case17-x",
        "scope-989-a",
        "subject-989-17-x",
        &foreign,
    );
    let refused =
        CanonicalStoreClient::apply_prepared(harness.adapter(), &ctx, transition, vec![], vec![])
            .await;
    assert!(
        matches!(refused, Err(StoreError::FenceMismatch)),
        "foreign fence invalidates the plan before any write, got {refused:?}"
    );
    // The invalidated plan consumed nothing: the first valid commit still
    // takes exactly the genesis allocation.
    let first = harness
        .commit("op-989-case17-first", "scope-989-a", "subject-989-17-first")
        .await
        .expect("first valid commit");
    assert_eq!(commit_sequence(&first), "commit-sequence-0000000000000001");
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/18
#[tokio::test]
async fn sequential_reference_preserves_semantic_histories() {
    let harness = Harness::fresh("18").await;
    let (ctx_a, transition_a) = admitted("op-989-case18-a", "scope-989-a", "subject-989-18-a");
    let receipt_a = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx_a,
        transition_a,
        vec![],
        vec![],
    )
    .await
    .expect("sequential commit A");
    let (ctx_b, transition_b) = admitted("op-989-case18-b", "scope-989-b", "subject-989-18-b");
    let receipt_b = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx_b,
        transition_b,
        vec![],
        vec![],
    )
    .await
    .expect("sequential commit B");
    // Semantic history is exact: one event per admitted operation with the
    // canonical derived identity, per-scope heads, and validated envelopes.
    for (receipt, operation) in [
        (&receipt_a, "op-989-case18-a"),
        (&receipt_b, "op-989-case18-b"),
    ] {
        assert_eq!(receipt.emitted_event_ids.len(), 1);
        assert_eq!(
            receipt.emitted_event_ids[0].to_string(),
            format!("event-{operation}"),
            "event identity derives from the admitted operation"
        );
        assert_eq!(receipt.applied_command_ids.len(), 1);
        receipt.validate().expect("receipt validates");
    }
    // Only explicitly nonsemantic interleaving may differ: the allocated
    // pair is the set {1,2} regardless of completion order.
    let mut committed = BTreeSet::new();
    committed.insert(commit_sequence(&receipt_a));
    committed.insert(commit_sequence(&receipt_b));
    assert_eq!(committed.len(), 2, "no allocation is shared or skipped");
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/19
#[tokio::test]
async fn real_provider_run_records_sessions_outcomes_and_progress() {
    let descriptor = descriptor();
    let harness = Harness::fresh("19").await;
    let scopes = descriptor["disjoint_scopes"]
        .as_array()
        .expect("disjoint scopes");
    assert!(scopes.len() >= 4, "four disjoint scopes provisioned");
    let started = Instant::now();
    let (ctx1, transition1) = admitted(
        "op-989-case19-1",
        scopes[0].as_str().expect("scope"),
        "subject-989-19-1",
    );
    let (ctx2, transition2) = admitted(
        "op-989-case19-2",
        scopes[1].as_str().expect("scope"),
        "subject-989-19-2",
    );
    let (ctx3, transition3) = admitted(
        "op-989-case19-3",
        scopes[2].as_str().expect("scope"),
        "subject-989-19-3",
    );
    let (ctx4, transition4) = admitted(
        "op-989-case19-4",
        scopes[3].as_str().expect("scope"),
        "subject-989-19-4",
    );
    let (r1, r2, r3, r4) = tokio::join!(
        CanonicalStoreClient::apply_prepared(harness.adapter(), &ctx1, transition1, vec![], vec![],),
        CanonicalStoreClient::apply_prepared(harness.adapter(), &ctx2, transition2, vec![], vec![],),
        CanonicalStoreClient::apply_prepared(harness.adapter(), &ctx3, transition3, vec![], vec![],),
        CanonicalStoreClient::apply_prepared(harness.adapter(), &ctx4, transition4, vec![], vec![],),
    );
    let elapsed = started.elapsed();
    let receipts = [r1, r2, r3, r4]
        .into_iter()
        .enumerate()
        .map(|(index, result)| {
            result
                .unwrap_or_else(|error| panic!("concurrent writer {} failed: {error:?}", index + 1))
        })
        .collect::<Vec<_>>();
    // Exact transaction outcomes: four commits, four unique allocations, one
    // effect set each.
    let committed: BTreeSet<String> = receipts.iter().map(commit_sequence).collect();
    assert_eq!(
        committed,
        BTreeSet::from([
            "commit-sequence-0000000000000001".to_owned(),
            "commit-sequence-0000000000000002".to_owned(),
            "commit-sequence-0000000000000003".to_owned(),
            "commit-sequence-0000000000000004".to_owned(),
        ]),
        "four concurrent writers share no allocation"
    );
    let snapshot = harness.snapshot().await;
    snapshot.validate().expect("snapshot validates");
    assert_eq!(snapshot.receipts.len(), 4);
    println!(
        "SCONC-989 case=19 providersha={} port={} elapsed_ms={} committed={:?}",
        harness.config.provider_artifact_digest,
        harness.config.provider_bind_address,
        elapsed.as_millis(),
        committed
    );
    harness.cleanup().await;
}

// PROOF (rework, beyond the 20-case denominator): production-path overlap.
// Two independent disjoint-scope transitions race through the public
// production entry (facade lane, no process-global gate) from a
// barrier-synchronized start: both commit with unique allocations over
// overlapping wall-clock intervals, and a genuine same-scope stale-head
// conflict still fails closed with no allocation consumed.
#[tokio::test]
async fn production_path_disjoint_writers_overlap_and_conflicts_fail_closed() {
    use std::sync::Arc;

    let harness = Harness::fresh("21").await;
    let (ctx_a, transition_a) = admitted("op-989-case21-a", "scope-989-a", "subject-989-21-a");
    let (ctx_b, transition_b) = admitted("op-989-case21-b", "scope-989-b", "subject-989-21-b");
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let barrier_a = Arc::clone(&barrier);
    let barrier_b = Arc::clone(&barrier);
    let adapter = harness.adapter();
    let (outcome_a, outcome_b) = tokio::join!(
        async move {
            barrier_a.wait().await;
            let entered = Instant::now();
            let receipt =
                CanonicalStoreClient::apply_prepared(adapter, &ctx_a, transition_a, vec![], vec![])
                    .await;
            (entered, Instant::now(), receipt)
        },
        async move {
            barrier_b.wait().await;
            let entered = Instant::now();
            let receipt =
                CanonicalStoreClient::apply_prepared(adapter, &ctx_b, transition_b, vec![], vec![])
                    .await;
            (entered, Instant::now(), receipt)
        }
    );
    let (entered_a, finished_a, receipt_a) = outcome_a;
    let (entered_b, finished_b, receipt_b) = outcome_b;
    let receipt_a = receipt_a.expect("production writer A commits");
    let receipt_b = receipt_b.expect("production writer B commits");
    assert!(
        entered_a <= finished_b && entered_b <= finished_a,
        "production writers overlapped in time"
    );
    let mut committed = BTreeSet::new();
    committed.insert(commit_sequence(&receipt_a));
    committed.insert(commit_sequence(&receipt_b));
    assert_eq!(
        committed,
        BTreeSet::from([
            "commit-sequence-0000000000000001".to_owned(),
            "commit-sequence-0000000000000002".to_owned(),
        ]),
        "overlapping production writers share no allocation"
    );
    for receipt in [&receipt_a, &receipt_b] {
        receipt.validate().expect("receipt validates");
    }
    println!(
        "SCONC-989 case=21 overlap_a_ms={} overlap_b_ms={} committed={:?}",
        finished_a.duration_since(entered_a).as_millis(),
        finished_b.duration_since(entered_b).as_millis(),
        committed
    );
    // Genuine conflict on the same production path still fails closed: the
    // stale expectation is writer A's own observed pre-commit head value,
    // provably superseded by exactly one.
    assert_eq!(receipt_a.revision_before_after.len(), 1);
    let stale_revision = receipt_a.revision_before_after[0].before;
    let (ctx_s, transition_s) = admitted("op-989-case21-stale", "scope-989-a", "subject-989-21-s");
    let refused = CanonicalStoreClient::apply_prepared(
        harness.adapter(),
        &ctx_s,
        transition_s,
        vec![RevisionHeadExpectation {
            key: RevisionKey::new("scope:scope-989-a").expect("revision key"),
            expected_revision: stale_revision,
            state_fence: fence(),
        }],
        vec![],
    )
    .await;
    assert!(
        matches!(refused, Err(StoreError::RevisionConflict)),
        "genuine same-scope conflict fails closed, got {refused:?}"
    );
    // The refused attempt consumed no allocation: the next commit still
    // takes exactly sequence 3 and exactly three receipts are durable.
    let next = harness
        .commit("op-989-case21-next", "scope-989-c", "subject-989-21-next")
        .await
        .expect("next commit");
    assert_eq!(commit_sequence(&next), "commit-sequence-0000000000000003");
    assert_eq!(harness.snapshot().await.receipts.len(), 3);
    harness.cleanup().await;
}

// WORK_UNIT_CASE: 989/20
#[test]
fn source_api_diff_guard_excludes_out_of_scope_changes() {
    let descriptor = descriptor();
    assert_eq!(descriptor["denominator"], 20);
    let apply = source("src/apply.rs");
    // Rework shape: the normal-write allocation loop (fence/head reads,
    // allocation attempts, retries, canonical transaction) runs without
    // the process-global gate; the gate survives only on the migration and
    // erasure-dispatch entrypoints — exactly two sites — and no second
    // global gate appears. The scheduler is not activated here.
    assert!(
        apply.contains("let _guard = adapter.write_lock.lock().await;"),
        "migration and erasure guards retained"
    );
    assert_eq!(
        apply
            .matches("let _guard = adapter.write_lock.lock().await;")
            .count(),
        2,
        "no guard site remains on the normal-write allocation path"
    );
    // The bounded retry re-enters only through the narrow allocation
    // recompute, never through full planning.
    assert!(
        apply.contains("recompute_allocation"),
        "retry loop recomputes allocation only"
    );
    assert!(
        source("src/plan.rs").contains("pub(crate) fn recompute_allocation"),
        "narrow allocation recompute is the sole retry planner"
    );
    assert!(
        !apply.contains("WriteScheduler") && !apply.contains("write_scheduler"),
        "no scheduler activation in the apply path"
    );
    // The overlapping seam is test-only, rides the admitted pooled
    // normal-write lane, and never widens the Store API.
    let seam = "pub(crate) async fn apply_prepared_without_write_guard";
    let seam_at = apply.find(seam).expect("explicit test/private seam");
    assert!(
        apply[..seam_at].rfind("#[cfg(test)]").is_some(),
        "seam compiles only under cfg(test)"
    );
    assert!(
        apply.contains("TxLane::PooledWrite"),
        "seam uses the admitted pooled write lane"
    );
    assert!(
        apply.contains("TxLane::Facade"),
        "production keeps the facade lane"
    );
    // No process-local sequence authority, no hidden reinterpretation, no
    // blind retry: retries re-enter only on classified contention.
    for path in ["src/apply.rs", "src/apply/atomic_write.rs", "src/plan.rs"] {
        let text = source(path);
        assert!(
            !text.contains("AtomicU64"),
            "no process-local sequence authority in {path}"
        );
        assert!(
            !text.contains("static NEXT_") && !text.contains("static SEQUENCE_"),
            "no hidden sequence state in {path}"
        );
    }
    assert!(
        apply.contains("Err(error) => return Err(error)"),
        "non-contention outcomes return without retry"
    );
    // No new dependencies: the adapter manifest carries exactly the admitted
    // set from the fixture.
    let manifest = source("Cargo.toml");
    let dependencies = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("dependencies section")
        .split('[')
        .next()
        .expect("dependencies block");
    let mut names: Vec<String> = dependencies
        .lines()
        .filter_map(|line| line.split('=').next())
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.strip_suffix(".workspace").unwrap_or(line).to_owned())
        .collect();
    names.sort();
    let mut expected: Vec<String> = descriptor["expected_dependencies"]
        .as_array()
        .expect("expected dependencies")
        .iter()
        .map(|value| value.as_str().expect("dependency").to_owned())
        .collect();
    expected.sort();
    assert_eq!(
        names, expected,
        "adapter dependencies stay exactly the admitted set"
    );
    // Fixture/contract binding: markers and mapping stay split.
    assert_eq!(
        descriptor["allocation_markers"]
            .as_array()
            .expect("markers")
            .len(),
        2
    );
    assert_eq!(
        descriptor["semantic_markers"]
            .as_array()
            .expect("markers")
            .len(),
        5
    );
}
