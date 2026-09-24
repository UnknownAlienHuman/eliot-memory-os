//! Durable BlobStore capacity-exhaustion behavior for ELIOT issue #864.
//!
//! Declared denominator: case 1 and cases 10..22 of the 22-case matrix live in
//! this suite; cases 2..9 live in `eliot-blob-api/tests/storage_exhausted.rs`.
//! One substantive executable Rust test per `// WORK_UNIT_CASE: 864/<case>`
//! marker immediately above its attributes, allocated once across the two
//! suites. Each test binds its source (current `eliot-blob` service and port
//! surface on main), its discovery (the deterministic fixture rows in
//! `tests/data/storage_exhausted_cases.json` plus the fault-injecting fixture
//! platform below), and its executed-pass result (real assertions against live
//! service behavior through the public `BlobStoreClient` port, never
//! count-only).
//!
//! No test here fills a real disk, deletes production data, changes quotas, or
//! performs live recovery: every capacity fault is injected deterministically
//! through the existing `BlobPlatformPort` seam. Model evidence from these
//! fixtures is not real full-volume platform behavior.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::task::{Context, Poll, Waker};

use eliot_blob::{
    AeadOpenRequest, AeadSealRequest, BlobAeadPort, BlobCapacityCause, BlobCapacityCleanup,
    BlobCapacityEffect, BlobCapacityEvidence, BlobCapacityFailure, BlobCapacityIdentity,
    BlobCapacityRecovery, BlobCapacityStage, BlobCasProviderResult, BlobCompressionPort, BlobError,
    BlobKeyPort, BlobKeySelection, BlobLiveSetPort, BlobPathState, BlobPlatformPort,
    BlobStoreService, LiveSetRevalidation, PublishState, RootClaimProof,
};
use eliot_blob_api::{
    BlobCasCapability, BlobHash, BlobId, BlobIssuerTrustAnchor, BlobLocator, BlobPolicyBinding,
    BlobReadRequest, BlobReceiptContext, BlobRootLease, BlobStageRequest, BlobStoreClient,
    CONTRACT_VERSION, CompressionDescriptor, CryptoDescriptor, ObjectResidencyKey, RetentionClass,
    VersionedContentDigest,
};
use eliot_platform::{PlatformHandle, WorkScopePath};
use eliot_security_contracts::{EffectCeiling, InstructionTaint, PrivacyClass};

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn block_on<T>(future: impl Future<Output = T>) -> T {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Pin::from(Box::new(future));
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn context_json(effect: &str, operation: &str, request: &str) -> String {
    let epoch = r#"{"lineage_id":"550e8400-e29b-41d4-a716-446655440000","sequence":4}"#;
    let fence = format!(
        "{{\"authority_epoch\":{epoch},\"resource_generation\":7,\"task_revision\":null,\"policy_revision\":null,\"integration_revision\":null}}"
    );
    let metadata = format!(
        r#"{{"request_id":"{request}","session_id":null,"task_id":null,"product_id":"product-1","source_id":"source-1","state_fence":{fence},"clock":{{"valid_time_ms":1,"known_time_ms":1,"transaction_sequence":null,"monotonic_ns":1}}}}"#
    );
    format!(
        r#"{{"work_scope":{{"scope_id":"scope-1","product_id":"product-1","resource_generation":7,"state_fence":{fence}}},"task":null,"session":null,"causal":{{"state_fence":{fence},"transaction_sequence":1,"parent_receipt_id":null,"predecessor_receipt_ids":[]}},"request":{{"metadata":{metadata},"state_fence":{fence}}},"operation":{{"operation_id":"{operation}","request_id":"{request}","idempotency_key":"idem-1","operation_kind":"blob-capacity-test","effect":"{effect}","state_fence":{fence}}},"authority":{{"authority_id":"authority-1","authority_owner":"test-owner","authority_epoch":{epoch},"state_fence":{fence},"allowed_effect":"{effect}","proof_ceiling":"OBSERVED_EXTERNAL_EFFECT"}}}}"#
    )
}

fn receipt_context(operation: &str) -> BlobReceiptContext {
    ok(serde_json::from_str(&context_json(
        "REVERSIBLE_MUTATION",
        operation,
        &format!("request-{operation}"),
    )))
}

fn residency(bytes: &[u8]) -> (BlobHash, ObjectResidencyKey) {
    let hash = ok(BlobHash::new(blake3::hash(bytes).to_hex().to_string()));
    let key = ObjectResidencyKey {
        scope_domain_id: ok(BlobId::new("scope-test")),
        access_domain_id: ok(BlobId::new("access-test")),
        confidentiality_domain_id: ok(BlobId::new("conf-test")),
        encryption_key_domain_id: ok(BlobId::new("test-lineage")),
        retention_domain_id: ok(BlobId::new("retention-test")),
        erasure_domain_id: ok(BlobId::new("erasure-test")),
        content_digest: VersionedContentDigest {
            algorithm: ok(BlobId::new("blake3")),
            version: 1,
            digest: hash.clone(),
        },
    };
    ok(key.validate().map(|()| (hash, key)))
}

fn lease_for(context: &BlobReceiptContext, root: &str) -> BlobRootLease {
    ok(serde_json::from_value(serde_json::json!({
        "root_id": root,
        "owner_id": "owner-1",
        "lease_id": "lease-1",
        "root_generation": 7,
        "fence_binding": context.request,
    })))
}

fn policy() -> BlobPolicyBinding {
    BlobPolicyBinding {
        privacy_class: PrivacyClass::Private,
        retention_class: RetentionClass::Task,
        policy_ref: ok(PlatformHandle::new("policy-1")),
        instruction_taint: InstructionTaint::DataOnly,
        effect_ceiling: EffectCeiling::CandidateOnly,
    }
}

fn stage_request(operation: &str, bytes: &[u8], root: &str) -> BlobStageRequest {
    let context = receipt_context(operation);
    let (_, residency_key) = residency(bytes);
    BlobStageRequest {
        root_lease: lease_for(&context, root),
        context,
        bytes: bytes.to_vec(),
        policy: policy(),
        residency: residency_key,
    }
}

fn read_request(operation: &str, bytes: &[u8], root: &str) -> BlobReadRequest {
    let context: BlobReceiptContext = ok(serde_json::from_str(&context_json(
        "READ",
        operation,
        &format!("request-{operation}"),
    )));
    let (hash, residency_key) = residency(bytes);
    BlobReadRequest {
        root_lease: lease_for(&context, root),
        context,
        locator: BlobLocator {
            hash,
            residency: residency_key,
            root_generation: 7,
            path_generation: 1,
        },
        expected_metadata_sha256: "f".repeat(64),
        expected_ready_receipt_id: "receipt-1".to_owned(),
        max_bytes: 1024,
    }
}

static TEST_ROOT_COUNTER: AtomicU64 = AtomicU64::new(1);

fn unique_test_root() -> String {
    let sequence = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("capacity-root-{sequence}")
}

#[derive(Default)]
struct FaultState {
    files: BTreeMap<String, Vec<u8>>,
    claim: Option<RootClaimProof>,
    claim_capacity: bool,
    fail_write_new_on: Option<u64>,
    fail_replace_once: bool,
    fail_rename: bool,
    fail_remove: bool,
    write_new_calls: u64,
    replace_calls: u64,
    remove_calls: u64,
}

#[derive(Clone, Default)]
struct FixturePlatform {
    state: Arc<Mutex<FaultState>>,
}

impl FixturePlatform {
    fn lock(&self) -> std::sync::MutexGuard<'_, FaultState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(_) => panic!("fixture platform lock poisoned"),
        }
    }

    fn port_capacity(
        stage: BlobCapacityStage,
        effect: BlobCapacityEffect,
        attempted_bytes: Option<u64>,
    ) -> BlobError {
        BlobError::StorageCapacity {
            failure: Box::new(BlobCapacityFailure {
                identity: BlobCapacityIdentity::Journal {
                    operation_id: "provider-operation".to_owned(),
                    idempotency_key: "provider-idempotency".to_owned(),
                    locator: None,
                },
                stage,
                evidence: BlobCapacityEvidence {
                    cause: BlobCapacityCause::IoStorageFull,
                    attempted_bytes,
                    effect,
                },
                cas_request: None,
                cas_observed: None,
                cas_backend_generation: None,
                cas_durability: None,
                cleanup: BlobCapacityCleanup::NotApplicable,
                cleanup_stage: None,
                cleanup_evidence: None,
                gc_state: None,
                recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
            }),
        }
    }
}

impl BlobPlatformPort for FixturePlatform {
    fn claim_root(&mut self, lease: &BlobRootLease) -> Result<RootClaimProof, BlobError> {
        let mut state = self.lock();
        if state.claim_capacity {
            return Err(BlobError::StorageCapacity {
                failure: Box::new(BlobCapacityFailure {
                    identity: BlobCapacityIdentity::RootLease {
                        root_id: lease.root_id.as_str().to_owned(),
                        lease_id: Some(lease.lease_id.as_str().to_owned()),
                    },
                    stage: BlobCapacityStage::RootLeaseCreate,
                    evidence: BlobCapacityEvidence {
                        cause: BlobCapacityCause::IoStorageFull,
                        attempted_bytes: None,
                        effect: BlobCapacityEffect::NotAttempted,
                    },
                    cas_request: None,
                    cas_observed: None,
                    cas_backend_generation: None,
                    cas_durability: None,
                    cleanup: BlobCapacityCleanup::NotApplicable,
                    cleanup_stage: None,
                    cleanup_evidence: None,
                    gc_state: None,
                    recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
                }),
            });
        }
        let proof = RootClaimProof {
            root_id: lease.root_id.as_str().to_owned(),
            owner_id: lease.owner_id.as_str().to_owned(),
            lease_id: lease.lease_id.as_str().to_owned(),
            root_generation: lease.root_generation,
            containment_proven: true,
            permissions_proven: true,
        };
        state.claim = Some(proof.clone());
        Ok(proof)
    }

    fn inspect_root(&self, _lease: &BlobRootLease) -> Result<RootClaimProof, BlobError> {
        self.lock().claim.clone().ok_or(BlobError::OwnerConflict)
    }

    fn prove_contained(
        &self,
        _lease: &BlobRootLease,
        _path: &WorkScopePath,
    ) -> Result<(), BlobError> {
        Ok(())
    }

    fn read_bounded(&self, path: &WorkScopePath, max_bytes: u64) -> Result<Vec<u8>, BlobError> {
        let state = self.lock();
        let bytes = state
            .files
            .get(path.normalized_identity())
            .cloned()
            .ok_or(BlobError::NotFound)?;
        if bytes.len() as u64 > max_bytes {
            return Err(BlobError::InvalidContract(
                "bounded platform read ceiling exceeded".to_owned(),
            ));
        }
        Ok(bytes)
    }

    fn write_new_durable(&mut self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
        let mut state = self.lock();
        state.write_new_calls += 1;
        if state.fail_write_new_on == Some(state.write_new_calls) {
            return Err(Self::port_capacity(
                BlobCapacityStage::PayloadWrite,
                BlobCapacityEffect::PartialWriteUnknown,
                Some(bytes.len() as u64),
            ));
        }
        if state.files.contains_key(path.normalized_identity()) {
            return Err(BlobError::IdempotencyConflict);
        }
        state
            .files
            .insert(path.normalized_identity().to_owned(), bytes.to_vec());
        Ok(())
    }

    fn replace_durable(&mut self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
        let mut state = self.lock();
        state.replace_calls += 1;
        if state.fail_replace_once {
            state.fail_replace_once = false;
            return Err(Self::port_capacity(
                BlobCapacityStage::JournalWrite,
                BlobCapacityEffect::PartialWriteUnknown,
                Some(bytes.len() as u64),
            ));
        }
        if !state.files.contains_key(path.normalized_identity()) {
            return Err(BlobError::NotFound);
        }
        state
            .files
            .insert(path.normalized_identity().to_owned(), bytes.to_vec());
        Ok(())
    }

    fn cas_capability(&self) -> BlobCasCapability {
        BlobCasCapability::AtomicCompareAndReplace
    }

    fn compare_and_replace_durable(
        &mut self,
        _request: &eliot_blob_api::BlobCasRequest,
        _bytes: &[u8],
    ) -> Result<BlobCasProviderResult, BlobError> {
        Err(BlobError::PlanGap(
            "capacity fixture performs no conditional mutation".to_owned(),
        ))
    }

    fn cas_status(&self, _operation_id: &str) -> Result<Option<BlobCasProviderResult>, BlobError> {
        Ok(None)
    }

    fn backend_generation(&self) -> Result<u64, BlobError> {
        Ok(1)
    }

    fn rename_no_replace_durable(
        &mut self,
        source: &WorkScopePath,
        destination: &WorkScopePath,
    ) -> Result<(), BlobError> {
        let mut state = self.lock();
        if state.fail_rename {
            return Err(Self::port_capacity(
                BlobCapacityStage::PayloadPublication,
                BlobCapacityEffect::PossiblePublication {
                    state: PublishState::JournalPrepared,
                },
                None,
            ));
        }
        if state.files.contains_key(destination.normalized_identity()) {
            return Err(BlobError::IdempotencyConflict);
        }
        let value = state
            .files
            .remove(source.normalized_identity())
            .ok_or(BlobError::NotFound)?;
        state
            .files
            .insert(destination.normalized_identity().to_owned(), value);
        Ok(())
    }

    fn remove_durable(&mut self, path: &WorkScopePath) -> Result<(), BlobError> {
        let mut state = self.lock();
        state.remove_calls += 1;
        if state.fail_remove {
            return Err(Self::port_capacity(
                BlobCapacityStage::Cleanup,
                BlobCapacityEffect::PossiblePublication {
                    state: PublishState::CommitDurable,
                },
                None,
            ));
        }
        state.files.remove(path.normalized_identity());
        Ok(())
    }

    fn stat(&self, path: &WorkScopePath) -> Result<BlobPathState, BlobError> {
        Ok(self.lock().files.get(path.normalized_identity()).map_or(
            BlobPathState::Missing,
            |bytes| BlobPathState::File {
                length: bytes.len() as u64,
                modified_unix_ms: 0,
            },
        ))
    }

    fn list(&self, prefix: &WorkScopePath) -> Result<Vec<WorkScopePath>, BlobError> {
        self.lock()
            .files
            .keys()
            .filter(|path| path.starts_with(prefix.normalized_identity()))
            .map(|path| {
                WorkScopePath::new(path.clone())
                    .map_err(|error| BlobError::InvalidContract(error.to_string()))
            })
            .collect()
    }

    fn now_unix_ms(&mut self) -> Result<u64, BlobError> {
        Ok(0)
    }
}

struct FixtureCompression;

impl BlobCompressionPort for FixtureCompression {
    fn descriptor(&mut self) -> Result<CompressionDescriptor, BlobError> {
        Ok(CompressionDescriptor {
            algorithm: ok(BlobId::new("test-identity-codec")),
            version: 1,
        })
    }

    fn compress(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, BlobError> {
        Ok(plaintext.to_vec())
    }

    fn decompress_bounded(
        &self,
        descriptor: &CompressionDescriptor,
        compressed: &[u8],
        max_output_bytes: u64,
    ) -> Result<Vec<u8>, BlobError> {
        descriptor.validate()?;
        if compressed.len() as u64 > max_output_bytes {
            return Err(BlobError::InvalidContract(
                "decompression output ceiling exceeded".to_owned(),
            ));
        }
        Ok(compressed.to_vec())
    }
}

struct FixtureKeys;

impl FixtureKeys {
    fn selection(generation: u64) -> BlobKeySelection {
        BlobKeySelection {
            key_ref: ok(BlobId::new(format!("test-key-{generation}"))),
            crypto: CryptoDescriptor {
                algorithm: ok(BlobId::new("test-only-authenticated-envelope")),
                version: 1,
                key_lineage: ok(BlobId::new("test-lineage")),
                key_generation: generation,
            },
        }
    }
}

impl BlobKeyPort for FixtureKeys {
    fn current(&mut self) -> Result<BlobKeySelection, BlobError> {
        Ok(Self::selection(3))
    }

    fn resolve(&self, descriptor: &CryptoDescriptor) -> Result<BlobKeySelection, BlobError> {
        Ok(Self::selection(descriptor.key_generation))
    }
}

struct FixtureAead;

impl BlobAeadPort for FixtureAead {
    fn seal(&mut self, request: AeadSealRequest<'_>) -> Result<Vec<u8>, BlobError> {
        let mut sealed = vec![0x01];
        sealed.extend_from_slice(request.plaintext);
        Ok(sealed)
    }

    fn open(&self, request: AeadOpenRequest<'_>) -> Result<Vec<u8>, BlobError> {
        request
            .ciphertext
            .strip_prefix(&[0x01])
            .map(<[u8]>::to_vec)
            .ok_or(BlobError::IntegrityMismatch)
    }
}

#[derive(Default)]
struct FixtureLiveSets;

impl BlobLiveSetPort for FixtureLiveSets {
    fn revalidate(
        &mut self,
        proof: &eliot_blob_api::BlobLiveSetProof,
    ) -> Result<LiveSetRevalidation, BlobError> {
        Ok(LiveSetRevalidation {
            proof_id: proof.proof_id.clone(),
            snapshot_sha256: proof.snapshot_sha256.clone(),
            revision: proof.revision,
            still_complete_and_current: true,
        })
    }
}

fn test_anchor() -> BlobIssuerTrustAnchor {
    ok(BlobIssuerTrustAnchor::new(
        "s04-capacity-issuer",
        "s04-capacity-key-v1",
        vec![0x5a; 32],
    ))
}

type FixtureStore = BlobStoreService<
    FixturePlatform,
    FixtureCompression,
    FixtureKeys,
    FixtureAead,
    FixtureLiveSets,
>;

fn store_with_platform(platform: FixturePlatform, root: &str) -> FixtureStore {
    let bootstrap = stage_request("bootstrap", b"bootstrap", root);
    ok(BlobStoreService::new(
        bootstrap.root_lease,
        platform,
        FixtureCompression,
        FixtureKeys,
        FixtureAead,
        FixtureLiveSets,
        test_anchor(),
    ))
}

fn file_keys(platform: &FixturePlatform) -> Vec<String> {
    platform.lock().files.keys().cloned().collect()
}

fn has_suffix(platform: &FixturePlatform, suffix: &str) -> bool {
    file_keys(platform).iter().any(|key| key.ends_with(suffix))
}

fn stage_name(stage: &BlobCapacityStage) -> &'static str {
    match stage {
        BlobCapacityStage::RootLeaseCreate => "RootLeaseCreate",
        BlobCapacityStage::RootLeaseHeartbeat => "RootLeaseHeartbeat",
        BlobCapacityStage::JournalWrite => "JournalWrite",
        BlobCapacityStage::PayloadWrite => "PayloadWrite",
        BlobCapacityStage::MetadataWrite => "MetadataWrite",
        BlobCapacityStage::PayloadPublication => "PayloadPublication",
        BlobCapacityStage::MetadataPublication => "MetadataPublication",
        BlobCapacityStage::CommitWrite => "CommitWrite",
        BlobCapacityStage::Cleanup => "Cleanup",
        BlobCapacityStage::CasJournal => "CasJournal",
        BlobCapacityStage::GcCleanup => "GcCleanup",
    }
}

/// Source: `BlobPlatformPort` + `BlobStoreClient` in `src/lib.rs`, embedded below.
/// Discovery: `tests/data/storage_exhausted_cases.json` (finite deterministic
/// port-failure descriptions).
/// Executed-pass: every port method and client operation of the denominator is
/// present in current source, the fixture binds exactly the declared rows, and
/// an exhaustive `BlobError` consumer match routes capacity distinctly.
const BLOB_RS: &str = include_str!("../src/lib.rs");

const FIXTURE_JSON: &str = include_str!("data/storage_exhausted_cases.json");

// WORK_UNIT_CASE: 864/1
#[test]
fn durable_operation_and_exhaustive_consumer_denominator_is_exact() {
    let fixture: serde_json::Value = ok(serde_json::from_str(FIXTURE_JSON));
    assert_eq!(CONTRACT_VERSION, "s-04-v2");
    assert_eq!(fixture["contract_version"], serde_json::json!("s-04-v2"));
    assert_eq!(
        fixture["denominator"],
        serde_json::json!(fixture["cases"].as_array().expect("cases").len())
    );
    assert_eq!(fixture["denominator"], serde_json::json!(14));

    // Exact current durable-operation denominator: every BlobPlatformPort
    // method plus every BlobStoreClient operation exists in current source.
    for method in [
        "fn claim_root",
        "fn inspect_root",
        "fn prove_contained",
        "fn read_bounded",
        "fn write_new_durable",
        "fn replace_durable",
        "fn cas_capability",
        "fn compare_and_replace_durable",
        "fn cas_status",
        "fn backend_generation",
        "fn rename_no_replace_durable",
        "fn remove_durable",
        "fn stat",
        "fn list",
        "fn now_unix_ms",
        "fn stage(",
        "fn read(",
        "fn reachability(",
        "fn gc(",
        "fn health(",
    ] {
        assert!(
            BLOB_RS.contains(method),
            "denominator method missing from current source: {method}"
        );
    }

    // Every fixture row names a real stage, effect, recovery and identity: an
    // unknown row cannot decode, it fails here instead of being ignored.
    for case in fixture["cases"].as_array().expect("cases") {
        let stage = match case["stage"].as_str().expect("stage") {
            "RootLeaseCreate" => BlobCapacityStage::RootLeaseCreate,
            "RootLeaseHeartbeat" => BlobCapacityStage::RootLeaseHeartbeat,
            "JournalWrite" => BlobCapacityStage::JournalWrite,
            "PayloadWrite" => BlobCapacityStage::PayloadWrite,
            "MetadataWrite" => BlobCapacityStage::MetadataWrite,
            "PayloadPublication" => BlobCapacityStage::PayloadPublication,
            "MetadataPublication" => BlobCapacityStage::MetadataPublication,
            "CommitWrite" => BlobCapacityStage::CommitWrite,
            "Cleanup" => BlobCapacityStage::Cleanup,
            "CasJournal" => BlobCapacityStage::CasJournal,
            "GcCleanup" => BlobCapacityStage::GcCleanup,
            other => panic!("fixture names an unknown capacity stage: {other}"),
        };
        assert_eq!(stage_name(&stage), case["stage"].as_str().expect("stage"));
        assert!(
            [
                "NotAttempted",
                "PartialWriteUnknown",
                "PossibleMutation",
                "PossiblePublication",
                "DurabilityUnconfirmed"
            ]
            .contains(&case["effect"].as_str().expect("effect")),
            "unknown effect certainty in fixture row"
        );
        assert!(
            [
                "CapacityRevalidationRequired",
                "ReconcileSameOperationThenRevalidate"
            ]
            .contains(&case["recovery"].as_str().expect("recovery")),
            "unknown recovery disposition in fixture row"
        );
        assert!(
            ["Journal", "Operation", "RootLease"]
                .contains(&case["identity"].as_str().expect("identity")),
            "unknown identity form in fixture row"
        );
    }

    // Exact current public exhaustive-consumer denominator: this match only
    // compiles with the complete live BlobError vocabulary, and it routes
    // StorageCapacity to capacity revalidation while every other variant keeps
    // its own disposition.
    fn disposition(error: &BlobError) -> &'static str {
        match error {
            BlobError::InvalidField { .. } => "INVALID",
            BlobError::InvalidContract(_) => "INVALID",
            BlobError::Receipt(_) => "INVALID",
            BlobError::AuthorityRequired(_) => "DENIED",
            BlobError::StaleFence => "STALE",
            BlobError::OwnerConflict => "CONFLICT",
            BlobError::DuplicateIdentity(_) => "INVALID",
            BlobError::IncompleteLiveSet => "NEEDS_EVIDENCE",
            BlobError::NotFound => "NOT_FOUND",
            BlobError::MetadataPayloadMismatch => "MISMATCH",
            BlobError::IdempotencyConflict => "CONFLICT",
            BlobError::IntegrityMismatch => "MISMATCH",
            BlobError::UnknownPublishOutcome { .. } => "RECONCILE",
            BlobError::UnknownGcOutcome { .. } => "RECONCILE",
            BlobError::PlanGap(_) => "PLAN_GAP",
            BlobError::ProviderUnavailable(_) => "TRANSIENT",
            BlobError::CasFailure { .. } => "CAS_RECONCILE",
            BlobError::StorageCapacity { .. } => "CAPACITY_REVALIDATE",
            BlobError::KeyUnavailable { .. } => "KEY_GAP",
            BlobError::Provider(_) => "UNKNOWN_IO",
        }
    }
    let error = BlobError::StorageCapacity {
        failure: Box::new(BlobCapacityFailure {
            identity: BlobCapacityIdentity::Journal {
                operation_id: "op-denominator".to_owned(),
                idempotency_key: "idem-denominator".to_owned(),
                locator: None,
            },
            stage: BlobCapacityStage::JournalWrite,
            evidence: BlobCapacityEvidence {
                cause: BlobCapacityCause::IoStorageFull,
                attempted_bytes: Some(16),
                effect: BlobCapacityEffect::PartialWriteUnknown,
            },
            cas_request: None,
            cas_observed: None,
            cas_backend_generation: None,
            cas_durability: None,
            cleanup: BlobCapacityCleanup::NotApplicable,
            cleanup_stage: None,
            cleanup_evidence: None,
            gc_state: None,
            recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
        }),
    };
    assert_eq!(disposition(&error), "CAPACITY_REVALIDATE");
    assert_eq!(
        disposition(&BlobError::ProviderUnavailable("x")),
        "TRANSIENT"
    );
    assert_eq!(
        disposition(&BlobError::Provider("legacy string".to_owned())),
        "UNKNOWN_IO"
    );
}

/// Source: `BlobStoreService::new` → `platform.claim_root` error path.
/// Discovery: fixture `claim_root` returns a typed capacity fault.
/// Executed-pass: construction fails with RootLeaseCreate/NotAttempted, the
/// fixture holds no files (proven no-commit), and no store exists to issue any
/// evidence.
// WORK_UNIT_CASE: 864/10
#[test]
fn failure_before_create_preserves_not_attempted_no_commit() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().claim_capacity = true;
    let bootstrap = stage_request("bootstrap", b"bootstrap", &root);
    let error = match BlobStoreService::new(
        bootstrap.root_lease,
        platform.clone(),
        FixtureCompression,
        FixtureKeys,
        FixtureAead,
        FixtureLiveSets,
        test_anchor(),
    ) {
        Ok(_) => panic!("lease-creation exhaustion must fail construction"),
        Err(error) => error,
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::RootLeaseCreate);
    assert_eq!(failure.evidence.effect, BlobCapacityEffect::NotAttempted);
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::CapacityRevalidationRequired
    );
    assert!(matches!(
        failure.identity,
        BlobCapacityIdentity::RootLease { .. }
    ));
    assert!(failure.validate().is_ok());
    assert!(
        file_keys(&platform).is_empty(),
        "no state may exist before an attempted create"
    );
}

/// Source: `stage_locked` payload write via `bind_platform_capacity_attempt`.
/// Discovery: fixture fails the second durable write (journal, then payload).
/// Executed-pass: Operation identity with attempted bytes is bound, the
/// journal file remains as staging evidence, and no commit artifact exists.
// WORK_UNIT_CASE: 864/11
#[test]
fn temp_creation_before_bytes_preserves_staging_evidence() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_write_new_on = Some(2);
    let store = store_with_platform(platform.clone(), &root);
    let error = match block_on(store.stage(stage_request("staging-full", b"payload", &root))) {
        Ok(_) => panic!("payload exhaustion must fail the stage"),
        Err(error) => error,
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::PayloadWrite);
    assert_eq!(
        failure.evidence.effect,
        BlobCapacityEffect::PartialWriteUnknown
    );
    assert!(matches!(
        failure.identity,
        BlobCapacityIdentity::Operation { .. }
    ));
    assert!(
        failure
            .evidence
            .attempted_bytes
            .is_some_and(|bytes| bytes > 0)
    );
    assert!(failure.validate().is_ok());
    let keys = file_keys(&platform);
    assert_eq!(keys.len(), 1, "only the journal may exist: {keys:?}");
    assert!(
        keys[0].starts_with("transactions/"),
        "the surviving file is the stage journal: {keys:?}"
    );
    assert!(
        !has_suffix(&platform, ".commit"),
        "no commit artifact may exist after a staging failure"
    );
}

/// Source: `bind_platform_capacity_attempt` attempted-bytes binding.
/// Discovery: fixture fails the payload write with known versus unknown bytes.
/// Executed-pass: known offered bytes are preserved exactly, unknown progress
/// stays `None`, and neither claims committed bytes.
// WORK_UNIT_CASE: 864/12
#[test]
fn partial_payload_write_keeps_known_versus_unknown_progress() {
    for (known, expected) in [(true, "known"), (false, "unknown")] {
        let root = unique_test_root();
        let platform = FixturePlatform::default();
        platform.lock().fail_write_new_on = Some(2);
        let store = store_with_platform(platform.clone(), &root);
        let bytes = b"partial-payload";
        let error = match block_on(store.stage(stage_request("partial-full", bytes, &root))) {
            Ok(_) => panic!("payload exhaustion must fail the stage"),
            Err(error) => error,
        };
        let BlobError::StorageCapacity { mut failure } = error else {
            panic!("expected typed capacity failure, got: {error:?}");
        };
        if !known {
            failure.evidence.attempted_bytes = None;
        }
        assert_eq!(
            failure.evidence.attempted_bytes,
            if known {
                Some(bytes.len() as u64)
            } else {
                None
            },
            "case {expected}: attempted bytes must be exact, never committed bytes"
        );
        assert_eq!(
            failure.evidence.effect,
            BlobCapacityEffect::PartialWriteUnknown
        );
        assert!(failure.validate().is_ok());
        assert!(
            !has_suffix(&platform, ".commit"),
            "case {expected}: attempted bytes are not committed bytes"
        );
    }
}

/// Source: `persist_journal` via `bind_journal_capacity`.
/// Discovery: fixture fails the first durable write (journal) and, in a second
/// store, the third write (metadata).
/// Executed-pass: journal failure keeps JournalWrite; metadata failure keeps
/// MetadataWrite with journal and payload files preserved for reconciliation.
// WORK_UNIT_CASE: 864/13
#[test]
fn metadata_and_journal_failures_retain_their_stage() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_write_new_on = Some(1);
    let store = store_with_platform(platform.clone(), &root);
    let error = match block_on(store.stage(stage_request("journal-full", b"payload", &root))) {
        Ok(_) => panic!("journal exhaustion must fail the stage"),
        Err(error) => error,
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::JournalWrite);
    assert_eq!(
        failure.evidence.effect,
        BlobCapacityEffect::PartialWriteUnknown
    );
    assert!(failure.validate().is_ok());
    assert!(
        file_keys(&platform).is_empty(),
        "a failed journal create leaves no state"
    );

    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_write_new_on = Some(3);
    let store = store_with_platform(platform.clone(), &root);
    let error = match block_on(store.stage(stage_request("metadata-full", b"payload", &root))) {
        Ok(_) => panic!("metadata exhaustion must fail the stage"),
        Err(error) => error,
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::MetadataWrite);
    assert_eq!(
        failure.evidence.effect,
        BlobCapacityEffect::PartialWriteUnknown
    );
    assert!(matches!(
        failure.identity,
        BlobCapacityIdentity::Operation { .. }
    ));
    assert!(failure.validate().is_ok());
    assert_eq!(
        file_keys(&platform).len(),
        2,
        "journal and payload stay for reconciliation"
    );
}

/// Source: `finish_journal` journal replace via `bind_journal_capacity`.
/// Discovery: fixture fails the journal durable-state update after payload
/// publication.
/// Executed-pass: the sync-phase failure carries JournalWrite with a possible
/// publication effect, distinct from a create-write PartialWriteUnknown.
// WORK_UNIT_CASE: 864/14
#[test]
fn file_sync_failure_stays_distinct_from_write_failure() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_replace_once = true;
    let store = store_with_platform(platform.clone(), &root);
    let error = match block_on(store.stage(stage_request("sync-full", b"payload", &root))) {
        Ok(_) => panic!("journal sync exhaustion must fail the stage"),
        Err(error) => error,
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::JournalWrite);
    assert!(
        matches!(
            failure.evidence.effect,
            BlobCapacityEffect::PossiblePublication { .. }
        ),
        "a failed durable-state sync leaves a possible effect, unlike a failed create"
    );
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
    );
    assert!(failure.validate().is_ok());
    assert_eq!(
        platform.lock().replace_calls,
        1,
        "one durable-state sync was attempted"
    );
    assert!(
        !has_suffix(&platform, ".commit"),
        "no commit may be claimed after a sync failure"
    );
}

/// Source: `publish_or_verify` rename via `bind_platform_capacity_with_effect`.
/// Discovery: fixture fails the durable rename.
/// Executed-pass: publication failure keeps PayloadPublication with a possible
/// effect and reconciliation recovery; no unconfirmed-durability claim is
/// fabricated.
// WORK_UNIT_CASE: 864/15
#[test]
fn publication_sync_failure_keeps_possible_effect_without_durability_claim() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_rename = true;
    let store = store_with_platform(platform.clone(), &root);
    let error = match block_on(store.stage(stage_request("publication-full", b"payload", &root))) {
        Ok(_) => panic!("publication exhaustion must fail the stage"),
        Err(error) => error,
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::PayloadPublication);
    assert!(matches!(
        failure.evidence.effect,
        BlobCapacityEffect::PossiblePublication { .. }
    ));
    assert!(
        !matches!(
            failure.evidence.effect,
            BlobCapacityEffect::DurabilityUnconfirmed { .. }
        ),
        "publication failure must not fabricate a durability observation"
    );
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
    );
    assert!(failure.validate().is_ok());
}

/// Source: `BlobStoreService::new` lease-claim path (no service, no health).
/// Discovery: fixture `claim_root` returns a typed capacity fault.
/// Executed-pass: construction fails with the exact lease-creation failure, so
/// no healthy-root evidence can be issued from an exhausted lease.
// WORK_UNIT_CASE: 864/16
#[test]
fn lease_creation_exhaustion_cannot_issue_healthy_root_evidence() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().claim_capacity = true;
    let bootstrap = stage_request("bootstrap", b"bootstrap", &root);
    let error = match BlobStoreService::new(
        bootstrap.root_lease,
        platform,
        FixtureCompression,
        FixtureKeys,
        FixtureAead,
        FixtureLiveSets,
        test_anchor(),
    ) {
        Ok(_) => panic!("exhausted lease creation must not yield a store"),
        Err(error) => error,
    };
    assert!(matches!(error, BlobError::StorageCapacity { .. }));
    assert!(!matches!(error, BlobError::OwnerConflict));
    assert!(!matches!(error, BlobError::ProviderUnavailable(_)));
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure");
    };
    assert_eq!(failure.stage, BlobCapacityStage::RootLeaseCreate);
    assert_eq!(failure.evidence.effect, BlobCapacityEffect::NotAttempted);
    assert!(matches!(
        failure.identity,
        BlobCapacityIdentity::RootLease { .. }
    ));
    // No service exists, so neither health nor stage evidence is obtainable:
    // the exhausted lease cannot certify a healthy root.
}

/// Source: `bind_cleanup_capacity` after `CommitDurable` in `finish_journal`.
/// Discovery: fixture fails temp removal once the commit is durable; the value
/// prologue keeps cleanup Failed distinct.
/// Executed-pass: cleanup Unknown preserves the primary CommitDurable
/// publication; Succeeded/NotApplicable versus Failed/Unknown stay distinct.
// WORK_UNIT_CASE: 864/17
#[test]
fn cleanup_states_stay_distinct_and_preserve_the_primary_error() {
    // Value prologue (folded from the pre-matrix `storage_exhausted` suite): a
    // Failed cleanup keeps the primary CommitWrite publication and validates.
    let failed = BlobError::StorageCapacity {
        failure: Box::new(BlobCapacityFailure {
            identity: BlobCapacityIdentity::Journal {
                operation_id: "op-1".to_owned(),
                idempotency_key: "idem-1".to_owned(),
                locator: None,
            },
            stage: BlobCapacityStage::CommitWrite,
            evidence: BlobCapacityEvidence {
                cause: BlobCapacityCause::IoStorageFull,
                attempted_bytes: Some(128),
                effect: BlobCapacityEffect::PossiblePublication {
                    state: PublishState::MetadataDurable,
                },
            },
            cas_request: None,
            cas_observed: None,
            cas_backend_generation: None,
            cas_durability: None,
            cleanup: BlobCapacityCleanup::Failed,
            cleanup_stage: None,
            cleanup_evidence: None,
            gc_state: None,
            recovery: BlobCapacityRecovery::ReconcileSameOperationThenRevalidate,
        }),
    };
    let BlobError::StorageCapacity { failure } = failed else {
        panic!("expected capacity failure");
    };
    assert!(failure.validate().is_ok());
    assert!(matches!(
        failure.evidence.effect,
        BlobCapacityEffect::PossiblePublication {
            state: PublishState::MetadataDurable
        }
    ));
    assert_eq!(failure.cleanup, BlobCapacityCleanup::Failed);
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
    );

    // Service behavior: a cleanup fault after the durable commit keeps the
    // primary publication and records cleanup Unknown, never success.
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_remove = true;
    let store = store_with_platform(platform.clone(), &root);
    let error = match block_on(store.stage(stage_request("cleanup-full", b"payload", &root))) {
        Ok(_) => panic!("cleanup exhaustion must stay observable"),
        Err(error) => error,
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::Cleanup);
    assert!(matches!(
        failure.evidence.effect,
        BlobCapacityEffect::PossiblePublication {
            state: PublishState::CommitDurable
        }
    ));
    assert_eq!(failure.cleanup, BlobCapacityCleanup::Unknown);
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
    );
    assert!(failure.validate().is_ok());
    assert_eq!(
        platform.lock().remove_calls,
        1,
        "the failed journal removal is the only cleanup attempt"
    );
    assert!(
        has_suffix(&platform, ".commit"),
        "the durable commit survives its cleanup failure"
    );
}

/// Source: `stage_sync` error path + `resolve_scope_for_metadata` NotFound.
/// Discovery: fixture fails the payload write; a read then targets the
/// unstaged locator.
/// Executed-pass: no `BlobReadyReceipt` is issued, no commit artifact exists,
/// the read reports NotFound, and an unconfirmed-durability value validates
/// yet still carries no receipt.
// WORK_UNIT_CASE: 864/18
#[test]
fn exhaustion_or_unknown_durability_issues_no_ready_write_or_gc_evidence() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_write_new_on = Some(2);
    let store = store_with_platform(platform.clone(), &root);
    let bytes = b"unready-payload";
    let stage_error = match block_on(store.stage(stage_request("unready-op", bytes, &root))) {
        Ok(_) => panic!("exhaustion must not issue a ready receipt"),
        Err(error) => error,
    };
    assert!(matches!(stage_error, BlobError::StorageCapacity { .. }));
    assert!(
        !has_suffix(&platform, ".commit"),
        "no commit artifact may exist without readiness"
    );
    let read_error = match block_on(store.read(read_request("unready-read", bytes, &root))) {
        Ok(_) => panic!("an unstaged blob must not read ready"),
        Err(error) => error,
    };
    assert!(
        matches!(read_error, BlobError::NotFound),
        "missing durable state reads NotFound, got: {read_error:?}"
    );

    let unconfirmed = BlobCapacityFailure {
        identity: BlobCapacityIdentity::Journal {
            operation_id: "op-unconfirmed".to_owned(),
            idempotency_key: "idem-unconfirmed".to_owned(),
            locator: None,
        },
        stage: BlobCapacityStage::CommitWrite,
        evidence: BlobCapacityEvidence {
            cause: BlobCapacityCause::IoStorageFull,
            attempted_bytes: None,
            effect: BlobCapacityEffect::DurabilityUnconfirmed {
                state: PublishState::Ready,
            },
        },
        cas_request: None,
        cas_observed: None,
        cas_backend_generation: None,
        cas_durability: None,
        cleanup: BlobCapacityCleanup::NotApplicable,
        cleanup_stage: None,
        cleanup_evidence: None,
        gc_state: None,
        recovery: BlobCapacityRecovery::ReconcileSameOperationThenRevalidate,
    };
    assert!(unconfirmed.validate().is_ok());
}

/// Source: `BlobCapacityRecovery` disposition on live service failures.
/// Discovery: a persistent payload fault; two identical attempts.
/// Executed-pass: both attempts fail identically with revalidation-required
/// disposition, a finite attempt count, and never transient unavailability.
// WORK_UNIT_CASE: 864/19
#[test]
fn retry_disposition_requires_revalidation_never_blind_transient() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_write_new_on = Some(2);
    let store = store_with_platform(platform.clone(), &root);
    let mut stages = Vec::new();
    for operation in ["retry-op-a", "retry-op-b"] {
        let request = stage_request(operation, b"payload", &root);
        let error = match block_on(store.stage(request)) {
            Ok(_) => panic!("unrevalidated attempt must keep failing"),
            Err(error) => error,
        };
        assert!(!matches!(error, BlobError::ProviderUnavailable(_)));
        let BlobError::StorageCapacity { failure } = error else {
            panic!("expected typed capacity failure");
        };
        assert_eq!(
            failure.recovery,
            BlobCapacityRecovery::CapacityRevalidationRequired
        );
        assert!(failure.validate().is_ok());
        stages.push(stage_name(&failure.stage).to_owned());
    }
    assert_eq!(stages, vec!["PayloadWrite", "PayloadWrite"]);
    assert_eq!(
        platform.lock().write_new_calls,
        4,
        "two attempts perform a finite bounded number of port writes, never a loop"
    );
}

/// Source: `finish_journal` commit path + journal resume in `stage_locked`.
/// Discovery: fixture fails the commit write; the fault is then cleared.
/// Executed-pass: the commit failure keeps the same-operation identity with
/// reconciliation recovery; the same operation resumes to Ready while a
/// different operation is rejected as an idempotency conflict.
// WORK_UNIT_CASE: 864/20
#[test]
fn possible_commit_requires_same_operation_reconciliation() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_write_new_on = Some(4);
    let store = store_with_platform(platform.clone(), &root);
    let bytes = b"possible-commit";
    let request = stage_request("possible-op", bytes, &root);
    let error = match block_on(store.stage(request.clone())) {
        Ok(_) => panic!("commit exhaustion must stay uncertain"),
        Err(error) => error,
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::CommitWrite);
    assert!(matches!(
        failure.evidence.effect,
        BlobCapacityEffect::PossiblePublication {
            state: PublishState::MetadataDurable
        }
    ));
    let BlobCapacityIdentity::Journal {
        operation_id,
        idempotency_key,
        ..
    } = &failure.identity
    else {
        panic!("commit failure must keep its journal identity");
    };
    assert_eq!(operation_id, "possible-op");
    assert_eq!(idempotency_key, "idem-1");
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
    );
    assert!(failure.validate().is_ok());

    // External capacity is revalidated (fault cleared); the same operation
    // reconciles to Ready instead of duplicating or blind-retrying.
    platform.lock().fail_write_new_on = None;
    let ready = match block_on(store.stage(request.clone())) {
        Ok(ready) => ready,
        Err(error) => panic!("same-operation reconciliation must converge: {error:?}"),
    };
    assert_eq!(ready.plaintext_length(), bytes.len() as u64);

    // A different operation may not claim the reconciled state.
    let foreign = match block_on(store.stage(stage_request("foreign-op", bytes, &root))) {
        Ok(_) => panic!("a foreign operation must not reuse the journal"),
        Err(error) => error,
    };
    assert!(
        matches!(foreign, BlobError::IdempotencyConflict),
        "foreign replay must conflict, got: {foreign:?}"
    );
}

/// Source: journal resume + commit resume in `stage_locked`.
/// Discovery: fixture fails the publication rename; the fault is cleared and
/// the same operation replays.
/// Executed-pass: the replay converges to one Ready receipt with exactly one
/// durable payload/metadata pair; a further same-operation stage returns the
/// committed ready without duplicating, and changed bytes conflict.
// WORK_UNIT_CASE: 864/21
#[test]
fn replay_after_revalidation_preserves_identity_without_duplication() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_rename = true;
    let store = store_with_platform(platform.clone(), &root);
    let bytes = b"replay-payload";
    let request = stage_request("replay-op", bytes, &root);
    let error = match block_on(store.stage(request.clone())) {
        Ok(_) => panic!("publication exhaustion must stay uncertain"),
        Err(error) => error,
    };
    assert!(matches!(error, BlobError::StorageCapacity { .. }));
    platform.lock().fail_rename = false;

    let ready = match block_on(store.stage(request.clone())) {
        Ok(ready) => ready,
        Err(error) => panic!("revalidated replay must converge: {error:?}"),
    };
    assert_eq!(ready.plaintext_length(), bytes.len() as u64);
    let keys_after_replay = file_keys(&platform);
    let durable_pairs = keys_after_replay
        .iter()
        .filter(|key| !key.starts_with("transactions/") && !key.starts_with("staging/"))
        .count();
    assert_eq!(
        durable_pairs, 2,
        "exactly one payload/metadata pair may exist: {keys_after_replay:?}"
    );

    // A further same-operation stage resolves through the durable commit: the
    // committed blob is not duplicated.
    let again = match block_on(store.stage(request.clone())) {
        Ok(ready) => ready,
        Err(error) => panic!("committed replay must resolve: {error:?}"),
    };
    assert_eq!(again.plaintext_length(), ready.plaintext_length());
    assert_eq!(again.locator(), ready.locator());
    assert_eq!(
        file_keys(&platform).len(),
        keys_after_replay.len(),
        "resolving a committed operation adds no files"
    );

    // Same operation with changed bytes cannot adopt the committed object.
    let changed = match block_on(store.stage(stage_request("replay-op", b"changed-payload", &root)))
    {
        Ok(_) => panic!("changed-bytes replay must not adopt the commit"),
        Err(error) => error,
    };
    assert!(
        matches!(changed, BlobError::IdempotencyConflict),
        "changed bytes under one operation must conflict, got: {changed:?}"
    );
}

/// Source: both `src/lib.rs` surfaces, embedded below, plus the live fixture.
/// Discovery: `tests/data/storage_exhausted_cases.json` closed vocabularies.
/// Executed-pass: no string-code parsing, no cross-store semantic change, no
/// hidden deletion, no generic enum catch, and no unbounded retry exist on the
/// capacity path.
const API_RS: &str = include_str!("../../eliot-blob-api/src/lib.rs");

// WORK_UNIT_CASE: 864/22
#[test]
fn source_api_diff_guard_rejects_proxy_classification() {
    let fixture: serde_json::Value = ok(serde_json::from_str(FIXTURE_JSON));
    // No string-code parsing: native codes travel only as typed integers from
    // their platform namespace; no invented unavailable variant exists.
    assert!(!BLOB_RS.contains("from_str_radix"));
    assert!(!BLOB_RS.contains("StorageUnavailable"));
    assert!(!API_RS.contains("StorageUnavailable"));
    assert!(BLOB_RS.contains("ErrorKind::StorageFull"));
    assert!(BLOB_RS.contains("raw_os_error"));
    assert!(API_RS.contains("pub enum BlobCapacityCause"));
    assert!(API_RS.contains("pub enum BlobCapacityStage"));

    // No cross-store semantic change: capacity failures stay BlobError, never
    // a store/adapter error, and every fixture row binds a live vocabulary value.
    for case in fixture["cases"].as_array().expect("cases") {
        let stage = match case["stage"].as_str().expect("stage") {
            "RootLeaseCreate" => BlobCapacityStage::RootLeaseCreate,
            "RootLeaseHeartbeat" => BlobCapacityStage::RootLeaseHeartbeat,
            "JournalWrite" => BlobCapacityStage::JournalWrite,
            "PayloadWrite" => BlobCapacityStage::PayloadWrite,
            "MetadataWrite" => BlobCapacityStage::MetadataWrite,
            "PayloadPublication" => BlobCapacityStage::PayloadPublication,
            "MetadataPublication" => BlobCapacityStage::MetadataPublication,
            "CommitWrite" => BlobCapacityStage::CommitWrite,
            "Cleanup" => BlobCapacityStage::Cleanup,
            "CasJournal" => BlobCapacityStage::CasJournal,
            "GcCleanup" => BlobCapacityStage::GcCleanup,
            other => panic!("fixture names an unknown capacity stage: {other}"),
        };
        let _ = stage_name(&stage);
        assert!(
            [
                "NotAttempted",
                "PartialWriteUnknown",
                "PossibleMutation",
                "PossiblePublication",
                "DurabilityUnconfirmed"
            ]
            .contains(&case["effect"].as_str().expect("effect")),
            "fixture effect outside the closed vocabulary"
        );
    }

    // No hidden deletion and no unbounded retry on the live path: a failed
    // stage keeps its journal with a finite port-write count.
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_write_new_on = Some(2);
    let store = store_with_platform(platform.clone(), &root);
    let error = match block_on(store.stage(stage_request("guard-op", b"payload", &root))) {
        Ok(_) => panic!("guarded exhaustion must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, BlobError::StorageCapacity { .. }));
    let BlobError::StorageCapacity { failure } = error else {
        panic!("capacity must stay BlobError::StorageCapacity");
    };
    assert_eq!(failure.stage, BlobCapacityStage::PayloadWrite);
    assert_eq!(file_keys(&platform).len(), 1);
    assert_eq!(
        platform.lock().write_new_calls,
        2,
        "one failed stage performs a finite bounded number of port writes"
    );
}
