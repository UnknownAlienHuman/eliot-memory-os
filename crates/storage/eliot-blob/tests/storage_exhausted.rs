//! Durable `BlobStore` capacity-exhaustion behavior for ELIOT issue #864.
//!
//! Declared denominator: case 1 and cases 10..22 of the 22-case matrix live in
//! this suite; cases 2..9 live in `eliot-blob-api/tests/storage_exhausted.rs`.
//! One substantive executable Rust test per `// WORK_UNIT_CASE: 864/<case>`
//! marker immediately above its attributes, allocated once across the two
//! suites. Each test binds its source (the `eliot-blob` service and port surface
//! as they stand in this working tree -- the #864 delta, not `main`), its
//! discovery (the deterministic fixture rows in
//! `tests/data/storage_exhausted_cases.json` plus the fault-injecting fixture
//! platform below), and its executed-pass result (real assertions against live
//! service behavior through the public `BlobStoreClient` port, never
//! count-only).
//!
//! Citations into `src/lib.rs` and into `eliot-blob-api/src/lib.rs` name
//! SYMBOLS, never line numbers. Those two files are still being rewritten
//! underneath this suite, and a raw line pointer here goes stale on its own;
//! a named symbol does not.
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

/// The root generation every root lease in this suite is minted with.
///
/// `lease_for` is the ONE place that mints it, and `stage_locked` reads the
/// generation straight off the request's lease (`root_generation:
/// request.root_lease.root_generation`), so a locator built from this constant
/// carries the generation a live stage actually settles rather than a
/// restatement of it. The lease's own fence binding is `context.request`, whose
/// `state_fence` carries the same `resource_generation: 7` (`context_json`, this
/// file), so the lease and its fence binding cannot disagree about which
/// generation is in force.
const ROOT_GENERATION: u64 = 7;

/// The `BlobLocator` `stage_locked` derives for `bytes` under this suite's root
/// and path generations.
///
/// Both generations are the ones the service itself uses: `root_generation` is
/// [`ROOT_GENERATION`], read back off the lease by `stage_locked`, and
/// `path_generation` is `PATH_GENERATION`. Neither is chosen here.
fn locator_for(bytes: &[u8]) -> BlobLocator {
    let (hash, residency_key) = residency(bytes);
    BlobLocator {
        hash,
        residency: residency_key,
        root_generation: ROOT_GENERATION,
        path_generation: 1,
    }
}

fn lease_for(context: &BlobReceiptContext, root: &str) -> BlobRootLease {
    ok(serde_json::from_value(serde_json::json!({
        "root_id": root,
        "owner_id": "owner-1",
        "lease_id": "lease-1",
        "root_generation": ROOT_GENERATION,
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
    BlobReadRequest {
        root_lease: lease_for(&context, root),
        context,
        locator: locator_for(bytes),
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

/// Which durable-write fault the fixture currently arms, if any.
///
/// `fail_write_new_on` stays a separate one-shot CALL ORDINAL -- it names the
/// Nth `write_new_durable` call and self-clears -- so it cannot express the
/// persistent fault case 19 states in its own doc comment ("a persistent
/// payload fault; two identical attempts"): attempt two would issue writes
/// 3..6 and meet no fault at all. The standing fault below is keyed on the
/// DESTINATION IDENTITY instead, exactly like `is_metadata_destination`, so it
/// can only ever fire on the payload leg: the journal and the commit record
/// both live under `transactions/`, the metadata leg is `staging/...metadata`,
/// and the two final publications are installed by
/// `rename_no_replace_durable`, never by this method. Naive call-order
/// stickiness would re-fire on the second attempt's JOURNAL write and report
/// `JournalWrite` where the test asserts `PayloadWrite`.
///
/// Default off, and `fail_write_new_on` keeps its one-shot semantics, so the
/// cases that share `write_new_durable` and do not opt in are byte-identical
/// to before. The armed fault itself is the condition: there is no retry
/// budget, counter or timer behind it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum WriteFault {
    /// No write fault armed.
    #[default]
    None,
    /// Every durable write to the staged PAYLOAD envelope fails, for as long
    /// as this fault is armed.
    PayloadWhileFull,
    /// The commit create installs its actual bytes, then its directory-flush
    /// boundary reports unconfirmed durability and only then marks the volume
    /// full for all following journal replacements.
    ///
    /// This destination-keyed seam cannot fire on the earlier payload,
    /// metadata, or journal writes. It therefore lets both publication
    /// checkpoints succeed before the commit boundary arms the standing
    /// journal-replace fault.
    CommitAfterInstallWhileFull,
}

/// Which journal durable-state replace fault the fixture currently arms, if any.
///
/// `Once` models exactly one failed sync and self-clears; capacity that has
/// not been freed yet is a standing condition, not a single attempt, so
/// `WhileFull` keeps every journal durable-state replace failing across every
/// call until it is cleared. The armed fault itself is the condition -- there
/// is no retry budget, counter or timer behind either variant.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ReplaceFault {
    /// No replace fault armed.
    #[default]
    None,
    /// Exactly one failed journal replace, then self-clears.
    Once,
    /// The volume is still full: every journal durable-state replace fails
    /// until this fault is cleared. This is what makes "space freed"
    /// observable to the service: nothing else changes and the same operation
    /// simply keeps meeting the same boundary.
    WhileFull,
}

/// Which publication-rename fault the fixture currently arms, if any.
///
/// The install-then-flush seams are keyed on the publication's final identity:
/// s-04.12 lays the two publications out under disjoint filename kinds --
/// `...{hash}.r{residency}.p{gen}` for the payload and
/// `...{hash}.r{residency}.m{gen}` for the metadata -- and the service reads
/// exactly that distinction back in `parse_scoped_path`. Keying on the
/// destination identity is what makes the metadata phase reachable. This is
/// NOT a call ordinal, a counter, a retry budget or a timer: the armed fault
/// is the condition itself. Default off, so the cases that do not opt in keep
/// byte-identical behaviour.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum RenameFault {
    /// No rename fault armed.
    #[default]
    None,
    /// The rename fails before anything is installed. It names no durability
    /// boundary of its own.
    BeforeInstall,
    /// The rename installs the final destination bytes and only THEN fails at
    /// the port's own directory-flush durability boundary.
    ///
    /// This is the only seam that produces "destination bytes visible, durable
    /// rename unconfirmed".
    AfterInstallPayload,
    /// The same install-then-flush seam, keyed on the METADATA publication's
    /// final identity instead of the payload's, so the metadata publication
    /// phase is reachable too.
    AfterInstallMetadata,
}

#[derive(Default)]
struct FaultState {
    files: BTreeMap<String, Vec<u8>>,
    claim: Option<RootClaimProof>,
    claim_capacity: bool,
    fail_write_new_on: Option<u64>,
    write_fault: WriteFault,
    replace_fault: ReplaceFault,
    rename_fault: RenameFault,
    fail_remove: bool,
    write_new_calls: u64,
    replace_calls: u64,
    /// Every identity `replace_durable` actually installed, in call order.
    ///
    /// `replace_calls` counts durable writes but cannot say WHICH boundary the
    /// owner was asked to re-establish, and that is precisely what separates a
    /// real same-identity durable re-establishment from a bare byte-equality
    /// promotion: both reach a ready receipt, but only the first asks the owner
    /// to write the destination again. Recorded so that distinction can be
    /// asserted on a named path rather than on a magic total.
    replace_targets: Vec<String>,
    /// Every `rename_no_replace_durable` attempt, including a failed one.
    ///
    /// Same-operation replay must add no rename after the commit checkpoint is
    /// durable, so a file snapshot alone is not enough to prove that the owner
    /// was left untouched.
    rename_calls: u64,
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
            Err(error) => panic!("fixture platform lock poisoned: {error:?}"),
        }
    }

    /// A typed capacity failure as this port's owner reports it.
    ///
    /// `recovery` is left at the non-reconciling default on purpose. The
    /// service recomputes the disposition from the bound effect inside
    /// `bind_platform_capacity_with_effect` and never reads the one a port wrote,
    /// so stating a reconciling disposition here would assert an invariant nothing
    /// checks.
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

    /// Whether `destination` is the metadata publication's final identity.
    ///
    /// s-04.12 lays the two publications out under disjoint filename kinds --
    /// `...{hash}.r{residency}.p{gen}` for the payload and
    /// `...{hash}.r{residency}.m{gen}` for the metadata -- and the service reads
    /// that same distinction back in `parse_scoped_path`, which parses kind `p`
    /// versus kind `m`. The residency digest ahead of the kind marker is exactly
    /// 64 hex characters, so the marker cannot be mistaken for part of a digest,
    /// and `PATH_GENERATION` is `1`, the generation every scoped placement in
    /// this suite carries.
    fn is_metadata_destination(destination: &WorkScopePath) -> bool {
        has_file_extension(destination.normalized_identity(), "m1")
    }

    /// Whether `destination` is the staged PAYLOAD envelope, i.e. the one
    /// `write_new_durable` call that is the payload leg of a stage.
    ///
    /// `temp_path` lays the two staged objects out as `staging/<hash>.payload`
    /// and `staging/<hash>.metadata`, while the journal and the commit record are
    /// both `transactions/<hash>.stage` and `transactions/<hash>.commit`, per
    /// `operation_path_from`. The namespace and the suffix are disjoint, so this
    /// predicate can never select a journal write. That is the whole point: a
    /// payload fault that also fired on the journal would report the wrong phase
    /// for the operation it belongs to.
    fn is_payload_temp_destination(destination: &WorkScopePath) -> bool {
        let identity = destination.normalized_identity();
        identity.starts_with("staging/") && identity.ends_with(".payload")
    }

    /// Whether `destination` is this operation's commit-marker create.
    fn is_commit_destination(destination: &WorkScopePath) -> bool {
        destination
            .normalized_identity()
            .starts_with("transactions/")
            && destination.normalized_identity().ends_with(".commit")
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
        if state.fail_write_new_on == Some(state.write_new_calls)
            || (state.write_fault == WriteFault::PayloadWhileFull
                && Self::is_payload_temp_destination(path))
        {
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
        if state.write_fault == WriteFault::CommitAfterInstallWhileFull
            && Self::is_commit_destination(path)
        {
            // The bytes are installed before the owner reports its own
            // directory-flush boundary. The volume becomes full only at this
            // commit boundary, after payload and metadata journal checkpoints
            // have already succeeded.
            state.replace_fault = ReplaceFault::WhileFull;
            return Err(Self::port_capacity(
                BlobCapacityStage::DirectoryFlush,
                BlobCapacityEffect::DurabilityUnconfirmed {
                    state: PublishState::MetadataDurable,
                    possible_effect: true,
                },
                None,
            ));
        }
        Ok(())
    }

    fn replace_durable(&mut self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
        let mut state = self.lock();
        state.replace_calls += 1;
        if state.replace_fault == ReplaceFault::WhileFull {
            // The volume is still full, so every journal durable-state replace
            // fails until the fault is cleared. This is what makes "space
            // freed" observable to the service: nothing else changes and the
            // same operation simply keeps meeting the same boundary.
            return Err(Self::port_capacity(
                BlobCapacityStage::JournalWrite,
                BlobCapacityEffect::PartialWriteUnknown,
                Some(bytes.len() as u64),
            ));
        }
        if state.replace_fault == ReplaceFault::Once {
            state.replace_fault = ReplaceFault::None;
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
        state
            .replace_targets
            .push(path.normalized_identity().to_owned());
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
        state.rename_calls += 1;
        if state.rename_fault == RenameFault::BeforeInstall {
            // The WRAPPED port's own label, deliberately different from the
            // caller's. A rename port cannot know which Blob object the service
            // asked it to publish, so it states the object-level phase label it
            // does know -- the case `bind_platform_capacity_with_effect`'s own doc
            // calls "an internal phase label of one port call" -- while the
            // service's caller states `PayloadPublication` for this leg. Reporting
            // the caller's value here would make "the caller's stage wins" and "the
            // port's stage wins" indistinguishable and would leave that doc's
            // stage-collision rule unexercised. It names no durability boundary of
            // its own, which is what makes this the losing side of the rule.
            return Err(Self::port_capacity(
                BlobCapacityStage::PayloadWrite,
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
        let metadata_leg = Self::is_metadata_destination(destination);
        if state.rename_fault == RenameFault::AfterInstallPayload
            || (state.rename_fault == RenameFault::AfterInstallMetadata && metadata_leg)
        {
            // The final name is now visible in its directory; only the port's own
            // `fsync` of that directory fails. I5.12 makes durable rename a
            // precondition of the receipt, so this is "published, durability
            // unconfirmed" -- a state `BeforeInstall` can never reach, because it
            // fails before a single byte is installed.
            //
            // `DirectoryFlush` is a durability boundary, so
            // `bind_platform_capacity_with_effect`'s stage-collision row keeps this
            // stage verbatim where the caller would have stated its own
            // `PayloadPublication`/`MetadataPublication`. That collision is real and
            // observable: those are different values.
            //
            // The EFFECT axis cannot be read the same way. Because the port named a
            // boundary, the caller's override is declined, so this value survives --
            // but it is byte-identical to what the caller would have supplied for
            // the same boundary, so an assertion on it proves only that no phase
            // was promoted, never which side supplied it. The origin proof is the
            // identity, which the service rewrites and this port cannot. The effect
            // does state what the boundary produced: the payload leg runs while the
            // journal is `JournalPrepared`, and the metadata leg runs only after
            // `finish_journal` persisted `PayloadDurable` between the two calls.
            return Err(Self::port_capacity(
                BlobCapacityStage::DirectoryFlush,
                BlobCapacityEffect::DurabilityUnconfirmed {
                    state: if metadata_leg {
                        PublishState::PayloadDurable
                    } else {
                        PublishState::JournalPrepared
                    },
                    possible_effect: true,
                },
                None,
            ));
        }
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

impl FixtureAead {
    /// The single envelope-marker byte this port's AEAD prepends to every
    /// sealed payload.
    ///
    /// It is a named constant rather than an inline `0x01` so that a test which
    /// must state a length at the native write boundary derives it from `seal`
    /// itself instead of restating it. `stage_locked` seals and then writes the
    /// SEALED buffer (`&sealed`) to the payload temp path, so the bytes offered to
    /// `write_new_durable` are the plaintext length plus this marker -- the
    /// plaintext never reaches the boundary at all.
    const ENVELOPE_MARKER: [u8; 1] = [0x01];
}

impl BlobAeadPort for FixtureAead {
    fn seal(&mut self, request: AeadSealRequest<'_>) -> Result<Vec<u8>, BlobError> {
        let mut sealed = Self::ENVELOPE_MARKER.to_vec();
        sealed.extend_from_slice(request.plaintext);
        Ok(sealed)
    }

    fn open(&self, request: AeadOpenRequest<'_>) -> Result<Vec<u8>, BlobError> {
        request
            .ciphertext
            .strip_prefix(&Self::ENVELOPE_MARKER)
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

/// Whether the normalized identity's FILE EXTENSION is `extension`, compared
/// case-insensitively.
///
/// s-04.12 puts the publication kind in the filename's extension: the payload is
/// `{hash}.r{residency}.p{gen}` (`scoped_payload_path`) and the metadata is
/// `{hash}.r{residency}.m{gen}` (`scoped_metadata_path`), so on the generation
/// this suite uses (`PATH_GENERATION` = 1) `Path::extension` yields exactly `p1`
/// and `m1`. Comparing the EXTENSION rather than a string suffix is what keeps
/// the two kinds disjoint: `eq_ignore_ascii_case("m1")` is false for `p1`, so a
/// payload destination can never satisfy the metadata predicate, and the
/// residency digest ahead of the kind marker is irrelevant to the split.
fn has_file_extension(identity: &str, extension: &str) -> bool {
    std::path::Path::new(identity)
        .extension()
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(extension))
}

/// Which publication phase the install-then-flush seam fires on.
///
/// `platform_rename` is DEFINED once and CALLED once: its single call site is in
/// `publish_or_verify`, which both `settle_publication` invocations reach. The two
/// publication destinations are disjoint by filename kind, so those phases are
/// selected by destination identity. Commit uses the separate durable-create
/// boundary and has its own destination-keyed flag. No seam is a call ordinal.
#[derive(Clone, Copy, Eq, PartialEq)]
enum SeamPhase {
    /// `finish_journal`'s first `settle_publication` call: destination
    /// `...{hash}.r{residency}.p1`, journal state `JournalPrepared`.
    Payload,
    /// `finish_journal`'s second `settle_publication` call: destination
    /// `...{hash}.r{residency}.m1`. The payload leg already persisted
    /// `PayloadDurable` in the `persist_journal` between the two calls, so that is
    /// the state this boundary fails after.
    Metadata,
    /// `finish_journal`'s commit-marker create: `.commit` receives real bytes
    /// after the metadata checkpoint, then its directory-flush boundary fails
    /// with `MetadataDurable` as the last proven state.
    Commit,
}

impl SeamPhase {
    /// Arms the fixture flag this phase's seam is keyed on.
    ///
    /// The metadata seam sits behind two preconditions, so both are refused HERE,
    /// where the combination is still visible, instead of degrading the run into
    /// the payload phase and failing later on a state mismatch that names the
    /// symptom rather than the cause:
    ///
    /// * the payload leg's own seam must be off, or the FIRST rename fails and the
    ///   run never reaches the metadata leg at all;
    /// * the journal durable-state replace must not still be failing, because
    ///   `finish_journal` performs that `persist_journal` BETWEEN the two
    ///   publications and propagates its error, so no amount of re-clearing the
    ///   rename flag would ever reach the metadata boundary.
    fn arm(self, state: &mut FaultState) {
        match self {
            Self::Payload => state.rename_fault = RenameFault::AfterInstallPayload,
            Self::Metadata => {
                assert!(
                    state.rename_fault != RenameFault::AfterInstallPayload,
                    "the payload seam must be off to reach the metadata publication phase: with \
                     both armed the first rename fails and this run silently becomes the payload \
                     phase"
                );
                assert!(
                    state.replace_fault != ReplaceFault::WhileFull,
                    "the payload leg's journal durable-state replace runs between the two \
                     publications in finish_journal and propagates, so the metadata boundary is \
                     unreachable while the volume is still full"
                );
                state.rename_fault = RenameFault::AfterInstallMetadata;
            }
            Self::Commit => {
                assert!(
                    state.replace_fault != ReplaceFault::WhileFull,
                    "the standing-full journal fault is armed only after actual commit bytes are installed"
                );
                state.write_fault = WriteFault::CommitAfterInstallWhileFull;
            }
        }
    }

    /// The installed destination identity this phase publishes.
    fn installed_suffix(self) -> &'static str {
        match self {
            Self::Payload => ".p1",
            Self::Metadata => ".m1",
            Self::Commit => ".commit",
        }
    }

    /// The state the operation had durably reached before this boundary.
    fn state_before(self) -> PublishState {
        match self {
            Self::Payload => PublishState::JournalPrepared,
            Self::Metadata => PublishState::PayloadDurable,
            Self::Commit => PublishState::MetadataDurable,
        }
    }
}

/// Drives the "effect installed, durability unconfirmed" seam against the live
/// service for one publication or commit phase and asserts what the SERVICE bound.
///
/// The fixture installs the destination bytes and only THEN returns storage-full
/// at its own directory-flush boundary. For `Commit`, the `.commit` bytes are
/// real and the full-volume journal-replace fault is armed only after that write,
/// so the earlier payload and metadata checkpoints run normally.
///
/// Two axes of the bound record, and they are NOT equally informative:
///
/// * `stage` is a real collision the assertions can see. The port says
///   `DirectoryFlush`; rename callers say `PayloadPublication` or
///   `MetadataPublication`, while the commit caller says `CommitWrite`. Those
///   differ, so
///   `assert_eq!(failure.stage, DirectoryFlush)` proves the port's boundary
///   survived verbatim under `bind_platform_capacity_with_effect`'s collision rule.
/// * `effect` is NOT a collision. Because the port named a boundary, the
///   caller's override is declined, so the port's value survives -- but it is
///   byte-identical to what the caller would have supplied for the same boundary.
///   An assertion on it proves only that no phase was promoted to a durable
///   publication, and would stay green if production never bound the port error at
///   all. Nothing here claims otherwise.
///
/// The axis that does prove the service bound this record is `identity`: this
/// file's port contributes `provider-operation`/`provider-idempotency` and no
/// locator, while the bound failure carries the operation's own journal identity
/// and the storage identity that settled -- `publish_or_verify` states both for
/// rename phases, and the commit create binds that identity directly.
fn assert_service_bound_unconfirmed_durability(phase: SeamPhase) {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    {
        let mut state = platform.lock();
        phase.arm(&mut state);
    }
    let store = store_with_platform(platform.clone(), &root);
    let bytes = b"unconfirmed-durability-payload";
    let request = stage_request("unconfirmed-durability-op", bytes, &root);
    let Err(error) = block_on(store.stage(request)) else {
        panic!("an unconfirmed durability boundary must not issue a ready receipt");
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::DirectoryFlush);
    // Not the service-origin proof, and deliberately not dressed up as one: this
    // value is byte-identical to the caller's own override for the same boundary,
    // so it can only show that no phase was promoted. The identity assertions
    // below are the origin proof.
    assert_eq!(
        failure.evidence.effect,
        BlobCapacityEffect::DurabilityUnconfirmed {
            state: phase.state_before(),
            possible_effect: true,
        },
        "a failed durability boundary never promotes a phase to a durable publication"
    );
    let BlobCapacityIdentity::Journal {
        operation_id,
        idempotency_key,
        locator,
    } = &failure.identity
    else {
        panic!("the bound failure must carry the operation's own journal identity");
    };
    assert_eq!(
        operation_id, "unconfirmed-durability-op",
        "the bound record names the operation, never the port's own placeholder"
    );
    assert_eq!(idempotency_key, "idem-1");
    assert_eq!(
        locator.as_ref(),
        Some(&locator_for(bytes)),
        "the bound record names this exact storage identity, never the port's empty one"
    );
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
    );
    assert!(failure.validate().is_ok());
    let keys = file_keys(&platform);
    assert!(
        keys.iter()
            .any(|key| key.ends_with(phase.installed_suffix())),
        "the destination bytes are visible; only their durability is unconfirmed: {keys:?}"
    );
    if phase == SeamPhase::Metadata {
        assert!(
            keys.iter().any(|key| has_file_extension(key, "p1")),
            "the payload leg completed and persisted before this metadata boundary: {keys:?}"
        );
    }
    if phase == SeamPhase::Commit {
        assert_commit_and_journal_identity(
            &platform,
            "unconfirmed-durability-op",
            "idem-1",
            bytes,
            "METADATA_DURABLE",
        );
    } else {
        assert!(
            !keys.iter().any(|key| key.ends_with(".commit")),
            "an unconfirmed publication boundary must not reach the commit marker: {keys:?}"
        );
        assert!(
            keys.iter().any(|key| has_file_extension(key, "stage")),
            "the journal is retained under the original operation: {keys:?}"
        );
    }
}

/// Proves that a commit-path durability refusal left the real commit bytes and
/// the matching journal on the fixture volume under one exact operation.
fn assert_commit_and_journal_identity(
    platform: &FixturePlatform,
    operation: &str,
    idempotency_key: &str,
    bytes: &[u8],
    expected_journal_state: &str,
) -> (String, String) {
    let state = platform.lock();
    let Some((commit_path, commit_bytes)) = state
        .files
        .iter()
        .find(|(path, _)| has_file_extension(path, "commit"))
        .map(|(path, bytes)| (path.clone(), bytes.clone()))
    else {
        panic!("the commit seam installs a real commit record before failing");
    };
    assert!(
        !commit_bytes.is_empty(),
        "the installed commit bytes are real"
    );
    let commit: serde_json::Value = ok(serde_json::from_slice(&commit_bytes));
    assert_eq!(commit["operation_id"], serde_json::json!(operation));
    assert_eq!(
        commit["idempotency_key"],
        serde_json::json!(idempotency_key)
    );
    assert_eq!(
        commit["locator"],
        ok(serde_json::to_value(locator_for(bytes)))
    );

    let Some((journal_path, journal_bytes)) = state
        .files
        .iter()
        .find(|(path, _)| has_file_extension(path, "stage"))
        .map(|(path, bytes)| (path.clone(), bytes.clone()))
    else {
        panic!("the unresolved operation retains its stage journal");
    };
    let journal: serde_json::Value = ok(serde_json::from_slice(&journal_bytes));
    assert_eq!(journal["operation_id"], serde_json::json!(operation));
    assert_eq!(
        journal["idempotency_key"],
        serde_json::json!(idempotency_key)
    );
    assert_eq!(
        journal["locator"],
        ok(serde_json::to_value(locator_for(bytes)))
    );
    assert_eq!(journal["state"], serde_json::json!(expected_journal_state));
    (commit_path, journal_path)
}

/// The card's negative clause, asserted against the live service: replaying the
/// SAME operation after the volume is revalidated still yields a typed
/// unresolved capacity outcome under the original operation identity, never a
/// ready receipt.
///
/// The boundary is named by the obligation the journal still carries, and
/// `stage`/`publish_state` are exactly what that obligation recorded. The refusal is
/// `fenced_publication_error`: the retained cause, an unknown attempted-byte
/// observation (never restated from the bytes this test knows), and
/// `DurabilityUnconfirmed { possible_effect: true }` under
/// `ReconcileSameOperationThenRevalidate`.
fn assert_replay_stays_typed_unresolved(
    store: &FixtureStore,
    request: &BlobStageRequest,
    stage: BlobCapacityStage,
    publish_state: PublishState,
    operation: &str,
) {
    let Err(error) = block_on(store.stage(request.clone())) else {
        panic!("a revalidated replay must not settle an unproven publication");
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("the unresolved replay must stay capacity-typed, got: {error:?}");
    };
    assert_eq!(failure.stage, stage);
    assert_eq!(
        failure.evidence.effect,
        BlobCapacityEffect::DurabilityUnconfirmed {
            state: publish_state,
            possible_effect: true,
        },
        "the fence reports unconfirmed durability, never a durable publication"
    );
    // The cause observed at the boundary is carried into the durable obligation
    // by `publication_fence` and restated verbatim by `fenced_publication_error`;
    // it is never reclassified or dropped on the way out.
    assert_eq!(
        failure.evidence.cause,
        BlobCapacityCause::IoStorageFull,
        "the retained capacity cause survives the fence unchanged"
    );
    // The progress the boundary left behind was never observed by the port, so it
    // stays unknown. Restating it from the bytes this fixture happens to know
    // would turn an unobserved observation into a byte count, which
    // `fenced_publication_error` explicitly refuses to do.
    assert!(
        failure.evidence.attempted_bytes.is_none(),
        "unobserved progress stays unknown, never restated from the bytes this test knows"
    );
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
    );
    assert!(failure.validate().is_ok());
    let BlobCapacityIdentity::Journal {
        operation_id,
        idempotency_key,
        ..
    } = &failure.identity
    else {
        panic!("the fenced replay must stay bound to its journal identity");
    };
    assert_eq!(
        operation_id, operation,
        "reconciliation stays same-operation"
    );
    assert_eq!(idempotency_key, "idem-1");
}

/// The operation identity and bytes the positive half below drives, so every
/// caller replays exactly the same settled operation.
const REESTABLISH_OPERATION: &str = "reestablish-op";

const REESTABLISH_BYTES: &[u8] = b"same-identity-reestablishment";

/// The positive half of #864's integration clause, driven against the live
/// service: a real same-identity durable re-establishment is what finally lets
/// one operation settle.
///
/// The platform installs the final path and then fails only its own durability
/// boundary, while the journal durable-state replace also fails because the
/// volume is still full. Nothing durable then carries the obligation, so the
/// service retains it instead (`record_publication_obligation`) and re-binds that
/// retained record on the next entry (`settle_retained_publications`). Capacity is
/// then revalidated — nothing about the operation changes, only the volume — and
/// the same operation settles exactly once.
///
/// It can only do so because the owner performed the durable write itself, on the
/// exact bounded bytes, at the boundary the obligation names:
/// `reestablish_publication_durability` is reached from `settle_pending_publication`
/// for the retained obligation and from `settle_publication` for a destination
/// whose bytes already match. Matching bytes alone never promote a phase, and the
/// assertions below are written so that re-introducing that promotion turns them
/// red rather than merely changing a number.
///
/// This is the only thing that distinguishes the new behavior from a permanent
/// lockout, so it also pins identity preservation: a further same-operation
/// stage resolves through the durable commit and adds no file, and changed
/// bytes under that same operation conflict.
fn assert_same_identity_reestablishment_settles_once() -> FixturePlatform {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    {
        let mut state = platform.lock();
        state.rename_fault = RenameFault::AfterInstallPayload;
        state.replace_fault = ReplaceFault::WhileFull;
    }
    let store = store_with_platform(platform.clone(), &root);
    let request = stage_request(REESTABLISH_OPERATION, REESTABLISH_BYTES, &root);
    let Err(error) = block_on(store.stage(request.clone())) else {
        panic!("an unconfirmed durability boundary must not issue a ready receipt");
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::DirectoryFlush);
    assert_eq!(
        failure.evidence.effect,
        BlobCapacityEffect::DurabilityUnconfirmed {
            state: PublishState::JournalPrepared,
            possible_effect: true,
        }
    );
    assert!(
        platform.lock().replace_calls >= 1,
        "the obligation's own journal durable-state replace met the still-full volume"
    );
    assert!(
        has_suffix(&platform, ".p1"),
        "the boundary the obligation names is installed; only its durability is unconfirmed"
    );
    assert!(
        !has_suffix(&platform, ".commit"),
        "an unconfirmed durability boundary must never reach the commit marker"
    );
    // The exact identity the retained obligation names: the destination the port
    // installed before its own directory flush failed. Counting owner replaces ON
    // THIS PATH is what separates a real re-establishment from a byte-equality
    // promotion -- a total replace count cannot, because settlement also persists
    // the journal several times and those persists are unrelated to the bug.
    let Some(obligation_destination) = file_keys(&platform)
        .into_iter()
        .find(|key| has_file_extension(key, "p1"))
    else {
        panic!("the seam must have installed the obligation's destination");
    };

    // Capacity is revalidated: both conditions clear and nothing else changes.
    let replaces_before = platform.lock().replace_calls;
    let targets_before = platform.lock().replace_targets.len();
    {
        let mut state = platform.lock();
        state.rename_fault = RenameFault::None;
        state.replace_fault = ReplaceFault::None;
    }
    let ready = match block_on(store.stage(request.clone())) {
        Ok(ready) => ready,
        Err(error) => panic!("a real same-identity re-establishment must settle: {error:?}"),
    };
    assert_eq!(ready.plaintext_length(), REESTABLISH_BYTES.len() as u64);
    let replaces_after = platform.lock().replace_calls;
    assert!(
        replaces_after >= replaces_before + 2,
        "settlement costs the owner several durable writes rather than none: \
         {replaces_before} -> {replaces_after}"
    );
    // Traced on the settling replay, on the obligation's destination itself:
    //
    //   1. the retained obligation is re-established under this identity
    //      (`settle_retained_publications` -> `settle_pending_publication` ->
    //      `reestablish_publication_durability`);
    //   2. the journal's phase advance reaches `settle_publication` with that same
    //      payload already matching, and re-establishes the boundary instead of
    //      returning on a bare byte match;
    //   plus the journal persists, which are not on this path and are counted only
    //   by the total above.
    //
    // Re-introducing the byte-equality promotion removes exactly step 2, leaving
    // ONE owner replace on this destination. Two is therefore the discriminating
    // threshold, and the total-count assertion above is not: the promotion still
    // leaves four total replaces.
    let destination_replacements = {
        let state = platform.lock();
        state.replace_targets[targets_before..]
            .iter()
            .filter(|target| **target == obligation_destination)
            .count()
    };
    assert!(
        destination_replacements >= 2,
        "the owner must be asked to durably write the obligation's own destination again, \
         once to discharge the retained obligation and once for the matching destination it \
         re-establishes; a byte-equality promotion would skip the second and leave only one: \
         {destination_replacements} replace(s) on {obligation_destination}, total \
         {replaces_before} -> {replaces_after}"
    );
    assert!(has_suffix(&platform, ".commit"));
    assert_settled_operation_is_inert(&platform, &store, &request, &root, ready.locator());
    platform
}

/// Replays an installed-but-unconfirmed commit across a service restart.
///
/// The first service installs the real commit bytes and only then arms the
/// standing journal-replace capacity fault. A second service, with empty
/// process-local retention but the same fixture volume, must ask the owner to
/// replace that exact commit record and remain unresolved while the owner still
/// reports full. After clearing the fault, one successful same-identity owner
/// replacement checkpoints `CommitDurable`; all later replay is inert.
#[allow(
    clippy::too_many_lines,
    reason = "the commit restart, refusal, settlement and inert replay are one recovery proof"
)]
fn assert_same_commit_identity_reestablishment_settles_once() {
    const OPERATION: &str = "commit-reestablish-op";
    const BYTES: &[u8] = b"same-commit-identity-reestablishment";

    let root = unique_test_root();
    let platform = FixturePlatform::default();
    {
        let mut state = platform.lock();
        assert_ne!(state.replace_fault, ReplaceFault::WhileFull);
        state.write_fault = WriteFault::CommitAfterInstallWhileFull;
    }
    let first_store = store_with_platform(platform.clone(), &root);
    let request = stage_request(OPERATION, BYTES, &root);
    let Err(error) = block_on(first_store.stage(request.clone())) else {
        panic!("an unconfirmed commit durability boundary must not issue Ready");
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed commit durability failure, got: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::DirectoryFlush);
    assert_eq!(
        failure.evidence.effect,
        BlobCapacityEffect::DurabilityUnconfirmed {
            state: PublishState::MetadataDurable,
            possible_effect: true,
        }
    );
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
    );
    let expected_locator = locator_for(BYTES);
    let BlobCapacityIdentity::Journal {
        operation_id,
        idempotency_key,
        locator,
    } = &failure.identity
    else {
        panic!("the commit boundary must bind the journal identity");
    };
    assert_eq!(operation_id, OPERATION);
    assert_eq!(idempotency_key, "idem-1");
    assert_eq!(locator.as_ref(), Some(&expected_locator));
    assert!(failure.validate().is_ok());
    assert!(
        file_keys(&platform)
            .iter()
            .any(|path| has_file_extension(path, "p1")),
        "the payload checkpoint completed before the commit boundary"
    );
    assert!(
        file_keys(&platform)
            .iter()
            .any(|path| has_file_extension(path, "m1")),
        "the metadata checkpoint completed before the commit boundary"
    );
    let (commit_path, journal_path) = assert_commit_and_journal_identity(
        &platform,
        OPERATION,
        "idem-1",
        BYTES,
        "METADATA_DURABLE",
    );
    {
        let state = platform.lock();
        assert_eq!(state.replace_fault, ReplaceFault::WhileFull);
        assert_eq!(
            state
                .replace_targets
                .iter()
                .filter(|target| target.as_str() == journal_path.as_str())
                .count(),
            2,
            "payload and metadata journal checkpoints succeeded before the commit fault armed"
        );
        assert!(
            !state
                .replace_targets
                .iter()
                .any(|target| target.as_str() == commit_path.as_str()),
            "the installed commit has not yet had a successful owner replace"
        );
    }
    drop(first_store);

    // A new service shares the exact files and owner but starts with no retained
    // in-memory obligation from the first service.
    let restarted_store = store_with_platform(platform.clone(), &root);
    let files_before_refusal = file_keys(&platform);
    let Err(error) = block_on(restarted_store.stage(request.clone())) else {
        panic!("the still-full volume must keep commit replay unresolved");
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("the direct commit re-establishment must stay capacity-typed: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::CommitWrite);
    assert_eq!(
        failure.evidence.effect,
        BlobCapacityEffect::DurabilityUnconfirmed {
            state: PublishState::MetadataDurable,
            possible_effect: true,
        }
    );
    assert_eq!(failure.evidence.cause, BlobCapacityCause::IoStorageFull);
    assert_eq!(
        failure.evidence.attempted_bytes,
        Some(platform.lock().files[&commit_path].len() as u64),
        "the direct owner replace retains the bytes actually offered"
    );
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
    );
    let BlobCapacityIdentity::Journal {
        operation_id,
        idempotency_key,
        locator,
    } = &failure.identity
    else {
        panic!("the restart refusal must keep the journal identity");
    };
    assert_eq!(operation_id, OPERATION);
    assert_eq!(idempotency_key, "idem-1");
    assert_eq!(locator.as_ref(), Some(&expected_locator));
    assert!(failure.validate().is_ok());
    assert_eq!(file_keys(&platform), files_before_refusal);
    assert_commit_and_journal_identity(&platform, OPERATION, "idem-1", BYTES, "METADATA_DURABLE");

    // Capacity is revalidated. The same service now settles its retained
    // obligation with one successful owner replace on the exact commit path.
    {
        let mut state = platform.lock();
        state.replace_fault = ReplaceFault::None;
        state.write_fault = WriteFault::None;
    }
    let ready = match block_on(restarted_store.stage(request.clone())) {
        Ok(ready) => ready,
        Err(error) => panic!("the owner replace should settle commit durability: {error:?}"),
    };
    assert_eq!(ready.locator(), &expected_locator);
    let (committed_path, committed_journal) =
        assert_commit_and_journal_identity(&platform, OPERATION, "idem-1", BYTES, "COMMIT_DURABLE");
    assert_eq!(committed_path, commit_path);
    assert_eq!(committed_journal, journal_path);
    let settled_journal: serde_json::Value = {
        let state = platform.lock();
        ok(serde_json::from_slice(&state.files[&journal_path]))
    };
    assert!(
        settled_journal["pending_publication"].is_null(),
        "the obligation is cleared in the same persisted CommitDurable checkpoint"
    );
    {
        let state = platform.lock();
        assert_eq!(
            state
                .replace_targets
                .iter()
                .filter(|target| target.as_str() == commit_path.as_str())
                .count(),
            1,
            "the commit durability boundary is re-established by one owner replace"
        );
    }

    let settled_files = file_keys(&platform);
    let before_replay = {
        let state = platform.lock();
        (
            state.write_new_calls,
            state.replace_calls,
            state.rename_calls,
        )
    };
    let replay = match block_on(restarted_store.stage(request.clone())) {
        Ok(ready) => ready,
        Err(error) => {
            panic!("CommitDurable replay must resolve without another owner write: {error:?}")
        }
    };
    assert_eq!(replay.locator(), &expected_locator);
    assert_eq!(file_keys(&platform), settled_files);
    let after_replay = {
        let state = platform.lock();
        (
            state.write_new_calls,
            state.replace_calls,
            state.rename_calls,
        )
    };
    assert_eq!(after_replay, before_replay);

    let Err(changed) =
        block_on(restarted_store.stage(stage_request(OPERATION, b"changed-commit-payload", &root)))
    else {
        panic!("changed bytes under the committed operation must conflict");
    };
    assert!(
        matches!(changed, BlobError::IdempotencyConflict),
        "changed bytes under one operation must conflict, got: {changed:?}"
    );
    let after_conflict = {
        let state = platform.lock();
        (
            state.write_new_calls,
            state.replace_calls,
            state.rename_calls,
        )
    };
    assert_eq!(after_conflict, before_replay);
}

/// The observable tail of a settled operation: once a genuine same-identity
/// durable re-establishment has issued the receipt, the operation is inert.
///
/// A further same-operation stage resolves through the durable commit and
/// publishes and writes nothing again, and the same operation under changed bytes
/// cannot adopt the committed object. Together those are what "settles exactly
/// once" has to mean on a surface a test can read.
fn assert_settled_operation_is_inert(
    platform: &FixturePlatform,
    store: &FixtureStore,
    request: &BlobStageRequest,
    root: &str,
    settled_locator: &BlobLocator,
) {
    // Settled once: a further same-operation stage resolves through the durable
    // commit without publishing or writing anything again.
    let settled_keys = file_keys(platform);
    let again = match block_on(store.stage(request.clone())) {
        Ok(ready) => ready,
        Err(error) => panic!("a committed replay must resolve: {error:?}"),
    };
    assert_eq!(again.locator(), settled_locator);
    assert_eq!(
        file_keys(platform),
        settled_keys,
        "resolving a committed operation adds no files"
    );
    // Same operation with changed bytes cannot adopt the committed object.
    let Err(changed) = block_on(store.stage(stage_request(
        REESTABLISH_OPERATION,
        b"changed-payload",
        root,
    ))) else {
        panic!("changed-bytes replay must not adopt the commit")
    };
    assert!(
        matches!(changed, BlobError::IdempotencyConflict),
        "changed bytes under one operation must conflict, got: {changed:?}"
    );
}

fn stage_name(stage: BlobCapacityStage) -> &'static str {
    match stage {
        BlobCapacityStage::RootLeaseCreate => "RootLeaseCreate",
        BlobCapacityStage::RootLeaseHeartbeat => "RootLeaseHeartbeat",
        BlobCapacityStage::JournalWrite => "JournalWrite",
        BlobCapacityStage::PayloadWrite => "PayloadWrite",
        BlobCapacityStage::MetadataWrite => "MetadataWrite",
        BlobCapacityStage::FileFlush => "FileFlush",
        BlobCapacityStage::DirectoryFlush => "DirectoryFlush",
        BlobCapacityStage::PayloadPublication => "PayloadPublication",
        BlobCapacityStage::MetadataPublication => "MetadataPublication",
        BlobCapacityStage::CommitWrite => "CommitWrite",
        BlobCapacityStage::Cleanup => "Cleanup",
        BlobCapacityStage::CasJournal => "CasJournal",
        BlobCapacityStage::GcCleanup => "GcCleanup",
    }
}

/// The rows of the closed fixture denominator both case 1 and the case-22
/// guard decode, so an unknown row fails in one place instead of being
/// ignored in two.
fn fixture_cases(fixture: &serde_json::Value) -> &[serde_json::Value] {
    let Some(cases) = fixture["cases"].as_array() else {
        panic!("the fixture must carry a cases array");
    };
    cases
}

/// One closed-vocabulary text field of a fixture row.
fn fixture_text<'a>(case: &'a serde_json::Value, field: &str) -> &'a str {
    let Some(text) = case[field].as_str() else {
        panic!("every fixture row must carry {field}");
    };
    text
}

/// The live capacity stage a fixture row names. An unknown row cannot decode,
/// it fails here instead of being ignored.
fn fixture_capacity_stage(case: &serde_json::Value) -> BlobCapacityStage {
    match fixture_text(case, "stage") {
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
    }
}

/// Sorted distinct stages the fixture baseline covers. Compared as an exact
/// list by the case-22 guard, so a dropped or renamed fixture row fails
/// instead of silently shrinking the denominator.
fn fixture_stage_baseline(fixture: &serde_json::Value) -> Vec<&str> {
    let mut stages: Vec<&str> = Vec::new();
    for case in fixture_cases(fixture) {
        let stage = fixture_text(case, "stage");
        if !stages.contains(&stage) {
            stages.push(stage);
        }
    }
    stages.sort_unstable();
    stages
}

/// Every fixture row names a real stage, effect, recovery and identity from
/// the closed vocabularies.
fn assert_fixture_rows_bind_live_vocabulary(fixture: &serde_json::Value) {
    for case in fixture_cases(fixture) {
        let stage = fixture_capacity_stage(case);
        assert_eq!(stage_name(stage), fixture_text(case, "stage"));
        assert!(
            [
                "NotAttempted",
                "PartialWriteUnknown",
                "PossibleMutation",
                "PossiblePublication",
                "DurabilityUnconfirmed"
            ]
            .contains(&fixture_text(case, "effect")),
            "unknown effect certainty in fixture row"
        );
        assert!(
            [
                "CapacityRevalidationRequired",
                "ReconcileSameOperationThenRevalidate"
            ]
            .contains(&fixture_text(case, "recovery")),
            "unknown recovery disposition in fixture row"
        );
        assert!(
            ["Journal", "Operation", "RootLease"].contains(&fixture_text(case, "identity")),
            "unknown identity form in fixture row"
        );
    }
}

/// Exact current durable-operation denominator, derived from the live API
/// surface rather than a local guess: the 15 `BlobPlatformPort` methods
/// (`src/lib.rs:1369`, implemented by the service's platform legs) plus the 6
/// `BlobStoreClient` operations (declared in
/// `crates/storage/eliot-blob-api/src/lib.rs:3608`, implemented by
/// `impl BlobStoreClient for BlobStoreService` in `src/lib.rs:5596` — the
/// production path). `read_sealed` (api lib.rs:3616) is a full member: equal
/// bytes under different obligations stay distinct objects, and the sealed
/// read path carries the same capacity evidence as `read`.
const PORT_METHOD_DENOMINATOR: &[&str] = &[
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
];

/// The 6 public client operations of the live `BlobStoreClient` surface.
/// Checked against both the trait declaration (`API_RS`) and the service
/// implementation (`BLOB_RS`), so a removed or renamed operation fails here
/// instead of silently leaving the denominator.
const CLIENT_METHOD_DENOMINATOR: &[&str] = &[
    "fn stage(",
    "fn read(",
    "fn read_sealed(",
    "fn reachability(",
    "fn gc(",
    "fn health(",
];

/// Every denominator method exists in current source: port methods in the
/// service source, client operations in both the trait declaration and the
/// service implementation. Counts are exact, so an added surface method
/// without denominator coverage fails here.
fn assert_port_method_denominator() {
    assert_eq!(
        PORT_METHOD_DENOMINATOR.len(),
        15,
        "the port surface holds exactly its 15 declared methods"
    );
    assert_eq!(
        CLIENT_METHOD_DENOMINATOR.len(),
        6,
        "the client surface holds exactly its 6 declared operations"
    );
    for method in PORT_METHOD_DENOMINATOR.iter().copied() {
        assert!(
            BLOB_RS.contains(method),
            "denominator method missing from current source: {method}"
        );
    }
    for method in CLIENT_METHOD_DENOMINATOR.iter().copied() {
        assert!(
            API_RS.contains(method),
            "client operation missing from the live trait surface: {method}"
        );
        assert!(
            BLOB_RS.contains(method),
            "client operation missing from the service implementation: {method}"
        );
    }
}

/// The disposition an exhaustive public consumer gives one `BlobError`.
///
/// This match only compiles with the complete live vocabulary, and it routes
/// `StorageCapacity` to capacity revalidation while every other variant keeps
/// its own disposition.
fn error_disposition(error: &BlobError) -> &'static str {
    match error {
        BlobError::InvalidField { .. }
        | BlobError::InvalidContract(_)
        | BlobError::Receipt(_)
        | BlobError::DuplicateIdentity(_) => "INVALID",
        BlobError::AuthorityRequired(_) => "DENIED",
        BlobError::StaleFence => "STALE",
        BlobError::OwnerConflict | BlobError::IdempotencyConflict => "CONFLICT",
        BlobError::IncompleteLiveSet => "NEEDS_EVIDENCE",
        BlobError::NotFound => "NOT_FOUND",
        BlobError::MetadataPayloadMismatch | BlobError::IntegrityMismatch => "MISMATCH",
        BlobError::UnknownPublishOutcome { .. } | BlobError::UnknownGcOutcome { .. } => "RECONCILE",
        BlobError::PlanGap(_) => "PLAN_GAP",
        BlobError::ProviderUnavailable(_) => "TRANSIENT",
        BlobError::CasFailure { .. } => "CAS_RECONCILE",
        BlobError::StorageCapacity { .. } => "CAPACITY_REVALIDATE",
        BlobError::KeyUnavailable { .. } => "KEY_GAP",
        BlobError::Provider(_) => "UNKNOWN_IO",
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

/// The subsequent downstream consumer of `BlobError`: `eliot-backup`
/// converts it with `impl From<BlobError> for BackupError`
/// (`crates/storage/eliot-backup/src/lib.rs:3080`, string conversion). It is
/// accounted here by shape only — this leaf never changes it, and the local
/// exhaustive `error_disposition` below proves this crate's own routing, not
/// the downstream conversion.
const BACKUP_RS: &str = include_str!("../../eliot-backup/src/lib.rs");

// WORK_UNIT_CASE: 864/1
#[test]
fn durable_operation_and_exhaustive_consumer_denominator_is_exact() {
    let fixture: serde_json::Value = ok(serde_json::from_str(FIXTURE_JSON));
    assert_eq!(CONTRACT_VERSION, "s-04-v2");
    assert_eq!(fixture["contract_version"], serde_json::json!("s-04-v2"));
    assert_eq!(
        fixture["denominator"],
        serde_json::json!(fixture_cases(&fixture).len())
    );
    assert_eq!(fixture["denominator"], serde_json::json!(14));

    assert_port_method_denominator();
    assert_fixture_rows_bind_live_vocabulary(&fixture);
    assert!(
        BACKUP_RS.contains("impl From<BlobError> for BackupError"),
        "the downstream backup consumer conversion must stay accounted"
    );

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
    assert_eq!(error_disposition(&error), "CAPACITY_REVALIDATE");
    assert_eq!(
        error_disposition(&BlobError::ProviderUnavailable("x")),
        "TRANSIENT"
    );
    assert_eq!(
        error_disposition(&BlobError::Provider("legacy string".to_owned())),
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
    let Err(error) = BlobStoreService::new(
        bootstrap.root_lease,
        platform.clone(),
        FixtureCompression,
        FixtureKeys,
        FixtureAead,
        FixtureLiveSets,
        test_anchor(),
    ) else {
        panic!("lease-creation exhaustion must fail construction")
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
    let Err(error) = block_on(store.stage(stage_request("staging-full", b"payload", &root))) else {
        panic!("payload exhaustion must fail the stage")
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
/// Discovery: fixture fails the payload write with known bytes offered.
/// Executed-pass: the observed offered bytes are preserved exactly as the sealed
/// envelope length -- offered, never committed -- and the operation never reaches
/// a commit record.
///
/// The UNKNOWN-progress half of this contract is not asserted here, and cannot
/// be: no service path yields an unknown attempted-byte observation for a
/// payload write. `bind_platform_capacity_attempt` fills the field from the
/// caller's offered length whenever the port leaves it empty, so every payload
/// write that reaches the port is a KNOWN-progress observation. This case
/// previously carried a second iteration that set `attempted_bytes` to `None`
/// itself and then asserted it was `None`, which no production behaviour could
/// turn red; it is deleted rather than restated. The unknown-progress guarantee
/// is asserted for real where production actually produces it: a re-established
/// obligation's refusal in `fenced_publication_error`, driven through the live
/// service by `assert_replay_stays_typed_unresolved` at cases 864/20 and 864/21.
// WORK_UNIT_CASE: 864/12
#[test]
fn partial_payload_write_keeps_known_versus_unknown_progress() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_write_new_on = Some(2);
    let store = store_with_platform(platform.clone(), &root);
    let bytes = b"partial-payload";
    let Err(error) = block_on(store.stage(stage_request("partial-full", bytes, &root))) else {
        panic!("payload exhaustion must fail the stage")
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    // The buffer that reaches the native write boundary is the SEALED envelope,
    // never the plaintext: `stage_locked` seals and writes `&sealed` to the
    // payload temp path, so the plaintext never reaches `write_new_durable` at
    // all. This port's AEAD prepends exactly one envelope-marker byte, so the
    // offered length is the plaintext length plus that marker.
    // `BlobCapacityEvidence::attempted_bytes` is defined as "Bytes offered to the
    // native write boundary, not bytes proven written, committed, or durable after
    // the failure", and `bind_platform_capacity_attempt` says the same of its own
    // default: "The offered buffer length is only what reached the native write
    // boundary".
    let offered_bytes = bytes.len() as u64 + FixtureAead::ENVELOPE_MARKER.len() as u64;
    // The envelope must differ from the plaintext, or the equality below would
    // hold for a port that was handed the caller's bytes.
    assert_ne!(
        offered_bytes,
        bytes.len() as u64,
        "the sealed envelope must be longer than the plaintext for this case to prove anything"
    );
    assert_eq!(
        failure.evidence.attempted_bytes,
        Some(offered_bytes),
        "attempted bytes are the sealed envelope actually offered to the write boundary, \
         never the plaintext length and never committed bytes"
    );
    assert_eq!(
        failure.evidence.effect,
        BlobCapacityEffect::PartialWriteUnknown
    );
    assert!(failure.validate().is_ok());
    assert!(
        !has_suffix(&platform, ".commit"),
        "the operation never reached a commit record"
    );
}

/// Source: `persist_journal` via `bind_journal_capacity`.
/// Discovery: fixture fails the first durable write (journal) and, in a second
/// store, the third write (metadata).
/// Executed-pass: journal failure keeps `JournalWrite`; metadata failure keeps
/// `MetadataWrite` with journal and payload files preserved for reconciliation.
// WORK_UNIT_CASE: 864/13
#[test]
fn metadata_and_journal_failures_retain_their_stage() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_write_new_on = Some(1);
    let store = store_with_platform(platform.clone(), &root);
    let Err(error) = block_on(store.stage(stage_request("journal-full", b"payload", &root))) else {
        panic!("journal exhaustion must fail the stage")
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
    let Err(error) = block_on(store.stage(stage_request("metadata-full", b"payload", &root)))
    else {
        panic!("metadata exhaustion must fail the stage")
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
/// Executed-pass: the sync-phase failure carries `JournalWrite` with a possible
/// publication effect, distinct from a create-write `PartialWriteUnknown`.
// WORK_UNIT_CASE: 864/14
#[test]
fn file_sync_failure_stays_distinct_from_write_failure() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().replace_fault = ReplaceFault::Once;
    let store = store_with_platform(platform.clone(), &root);
    let Err(error) = block_on(store.stage(stage_request("sync-full", b"payload", &root))) else {
        panic!("journal sync exhaustion must fail the stage")
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

/// Source: `publish_or_verify` rename via `bind_platform_capacity_with_effect`
/// on a port that reported no durability boundary of its own.
/// Discovery: fixture fails the durable rename before installing anything, and
/// reports its own wrapped-port label `PayloadWrite` rather than the caller's
/// `PayloadPublication`, so the stage collision is real rather than assumed.
/// Executed-pass: the caller's `PayloadPublication` stage wins over the port's
/// `PayloadWrite` and the caller's own unconfirmed-durability effect applies — a
/// possible installed effect that is never promoted to a durable phase — with
/// reconciliation recovery; no destination byte is installed and no receipt
/// follows.
// WORK_UNIT_CASE: 864/15
#[test]
fn publication_failure_without_port_boundary_reports_unconfirmed_durability() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().rename_fault = RenameFault::BeforeInstall;
    let store = store_with_platform(platform.clone(), &root);
    let Err(error) = block_on(store.stage(stage_request("publication-full", b"payload", &root)))
    else {
        panic!("publication exhaustion must fail the stage")
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    // A real stage collision, and the assertion can see it: the port reported the
    // wrapped-port label `PayloadWrite` (see the `BeforeInstall` arm) while the
    // caller's stage for this leg is `PayloadPublication`. `PayloadWrite` names no
    // durability boundary of its own, so the caller's stage stands. Had the rule
    // instead let the port's stage win, this would read `PayloadWrite`.
    assert_eq!(failure.stage, BlobCapacityStage::PayloadPublication);
    // The port could only say `PossiblePublication`; the caller's effect
    // applies, because a failed publication may have installed a destination
    // whose durability is unconfirmed. This is the service's own statement, not
    // a durable phase and not a receipt.
    assert_eq!(
        failure.evidence.effect,
        BlobCapacityEffect::DurabilityUnconfirmed {
            state: PublishState::JournalPrepared,
            possible_effect: true,
        }
    );
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
    );
    assert!(failure.validate().is_ok());
    // This rename failed before installing a single byte, so the obligation it
    // leaves behind names a destination that does not exist: nothing durable
    // exists and the unconfirmed claim is never settled by the failing rename.
    let keys = file_keys(&platform);
    assert!(
        !keys.iter().any(|key| has_file_extension(key, "p1")),
        "the failed rename installed no destination bytes: {keys:?}"
    );
    assert!(
        !keys.iter().any(|key| key.ends_with(".commit")),
        "an unconfirmed publication must never reach the commit marker: {keys:?}"
    );
}

/// Source: `BlobStoreService::new` lease-claim path (no service, no health),
/// and the root-claim proof the healthy-root evidence would rest on.
/// Discovery: fixture `claim_root` returns a typed capacity fault.
/// Executed-pass: construction fails with the exact lease-creation failure, and
/// the owner never obtains a `RootClaimProof` -- so the root-inspection surface
/// cannot confirm the root either, which is the evidence a healthy-root report
/// would rest on. The failure is neither an ownership conflict nor a transient
/// provider-unavailable signal, so exhaustion is never degraded into one.
// WORK_UNIT_CASE: 864/16
#[test]
fn lease_creation_exhaustion_cannot_issue_healthy_root_evidence() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().claim_capacity = true;
    let bootstrap = stage_request("bootstrap", b"bootstrap", &root);
    let lease = bootstrap.root_lease.clone();
    let Err(error) = BlobStoreService::new(
        bootstrap.root_lease,
        platform.clone(),
        FixtureCompression,
        FixtureKeys,
        FixtureAead,
        FixtureLiveSets,
        test_anchor(),
    ) else {
        panic!("exhausted lease creation must not yield a store")
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
    assert!(failure.validate().is_ok());
    // What makes this distinct from case 864/10, which asserts the same failure
    // record: 864/10 proves no FILE was created. This proves no CLAIM PROOF was
    // issued either. `claim_root` returns the capacity failure before it would
    // store a proof, so the owner holds nothing a healthy-root report could rest
    // on and the root cannot be inspected as healthy.
    assert!(
        platform.lock().claim.is_none(),
        "an exhausted claim must not leave a root claim proof behind"
    );
    assert!(
        matches!(platform.inspect_root(&lease), Err(BlobError::OwnerConflict)),
        "the root-inspection surface cannot confirm a root whose claim was never proven"
    );
}

/// Source: `bind_cleanup_capacity` after `CommitDurable` in `finish_journal`.
/// Discovery: fixture fails temp removal once the commit is durable; the value
/// prologue keeps cleanup Failed distinct.
/// Executed-pass: a `Failed` cleanup preserves the primary `CommitDurable`
/// publication and retains the typed cleanup observation beside that verdict;
/// the SAME retained observation is rejected by `BlobCapacityFailure::validate`
/// when the verdict is restated as `Succeeded` or `NotApplicable`, so those rows
/// are separated by the production validator rather than by name alone; and the
/// live cleanup fault is reported `Failed` rather than `Unknown` because
/// `remove_durable` provably did not complete.
// WORK_UNIT_CASE: 864/17
#[test]
fn cleanup_states_stay_distinct_and_preserve_the_primary_error() {
    // `CommitWrite` is an object-level stage, so the api crate's
    // `capacity_stage_requires_locator` rejects a `None` locator: recovery for a
    // stage whose physical effect is a named storage object is meaningless
    // without the identity it settled, and every production site supplies one.
    let settled = locator_for(b"payload");
    // Value prologue (folded from the pre-matrix suite): a Failed cleanup keeps
    // the primary CommitWrite publication and validates.
    let failed = BlobError::StorageCapacity {
        failure: Box::new(BlobCapacityFailure {
            identity: BlobCapacityIdentity::Journal {
                operation_id: "op-1".to_owned(),
                idempotency_key: "idem-1".to_owned(),
                locator: Some(settled),
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
    // primary publication and records cleanup Failed, never success and never
    // Unknown, and retains the cleanup observation beside that verdict.
    assert_failed_cleanup_retains_its_observation();
}

/// The live half of case 17: a cleanup fault after the durable commit keeps the
/// primary publication, reports the cleanup as `Failed`, and retains the typed
/// cleanup observation beside that verdict.
///
/// `remove_durable` returned an error, so that removal provably did not durably
/// complete. `bind_cleanup_capacity` copies the CLEANUP record's own evidence
/// into the retained slot (`failure.cleanup_evidence = Some(failure.evidence)`)
/// and settles the verdict on `Failed` -- the row `retain_cleanup_evidence` calls
/// "the honest row".
///
/// What the retained row therefore carries is the CLEANUP observation, not the
/// primary publication's: `bind_platform_capacity_with_effect` copies the port's
/// evidence and overwrites only `effect`, so the typed cause survives verbatim,
/// `attempted_bytes` stays `None` (a removal offers no bytes to any write boundary
/// and this port observed none -- and `bind_cleanup_capacity` takes no
/// `attempted_bytes` argument to restate), and the effect is the CALLER's
/// `PossiblePublication` over the durable commit.
///
/// The `Failed` row is then distinguished from `Succeeded` and `NotApplicable` by
/// the api crate's `validate_capacity_cleanup`, not by this file's naming: the
/// same record with either of those verdicts is rejected outright, because
/// cleanup evidence cannot accompany an inapplicable or successful result.
fn assert_failed_cleanup_retains_its_observation() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_remove = true;
    let store = store_with_platform(platform.clone(), &root);
    let Err(error) = block_on(store.stage(stage_request("cleanup-full", b"payload", &root))) else {
        panic!("cleanup exhaustion must stay observable")
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
    assert_eq!(
        failure.cleanup,
        BlobCapacityCleanup::Failed,
        "a removal that returned an error is Failed, not Unknown"
    );
    assert_eq!(failure.cleanup_stage, Some(BlobCapacityStage::Cleanup));
    assert_eq!(
        failure.cleanup_evidence,
        Some(BlobCapacityEvidence {
            cause: BlobCapacityCause::IoStorageFull,
            attempted_bytes: None,
            effect: BlobCapacityEffect::PossiblePublication {
                state: PublishState::CommitDurable,
            },
        }),
        "the Failed verdict retains the cleanup observation itself, byte for byte"
    );
    // Distinctness, proved by the production validator rather than by name: the
    // SAME retained evidence, re-verdicted as `Succeeded` or `NotApplicable`, is
    // rejected outright (`validate_capacity_cleanup`: "cleanup evidence cannot
    // accompany an inapplicable or successful result"). Before this the three
    // cleanup rows were only ever named, never compared.
    for verdict in [
        BlobCapacityCleanup::Succeeded,
        BlobCapacityCleanup::NotApplicable,
    ] {
        let mut collapsed = (*failure).clone();
        collapsed.cleanup = verdict;
        assert!(
            matches!(collapsed.validate(), Err(BlobError::InvalidField { .. })),
            "the retained cleanup observation must be rejected beside a {verdict:?} verdict: \
             the Failed/Succeeded/NotApplicable rows are separated by the validator, not by \
             this file's naming"
        );
    }
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

/// Source: `stage_sync` error path + `resolve_scope_for_metadata` `NotFound`,
/// and both `settle_publication` → `publish_or_verify` →
/// `bind_platform_capacity_with_effect` calls on a port-reported durability
/// boundary.
/// Discovery: the fixture fails the payload write, installs payload and metadata
/// on separate runs before their directory flushes fail, then installs actual
/// commit bytes before the commit directory-flush failure arms the standing-full
/// journal-replace fault; a read targets the unstaged locator.
/// Executed-pass: no `BlobReadyReceipt` is issued for any phase. Publication
/// refusals have no commit marker; the commit refusal has its actual commit bytes
/// and matching retained journal, both under the original identity. The read
/// reports `NotFound`, the port's own durability-boundary stage survives verbatim,
/// and the bound record names the operation and exact settled storage identity.
// WORK_UNIT_CASE: 864/18
#[test]
fn exhaustion_or_unknown_durability_issues_no_ready_write_or_gc_evidence() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_write_new_on = Some(2);
    let store = store_with_platform(platform.clone(), &root);
    let bytes = b"unready-payload";
    let Err(stage_error) = block_on(store.stage(stage_request("unready-op", bytes, &root))) else {
        panic!("exhaustion must not issue a ready receipt")
    };
    assert!(matches!(stage_error, BlobError::StorageCapacity { .. }));
    assert!(
        !has_suffix(&platform, ".commit"),
        "no commit artifact may exist without readiness"
    );
    let Err(read_error) = block_on(store.read(read_request("unready-read", bytes, &root))) else {
        panic!("an unstaged blob must not read ready")
    };
    assert!(
        matches!(read_error, BlobError::NotFound),
        "missing durable state reads NotFound, got: {read_error:?}"
    );

    // The durability-unconfirmed effect used to be hand-written here, which made
    // case 18 a self-consistency check on a value the test itself authored. It is
    // now obtained from the live service through the install-then-directory-flush
    // seam, once for each publication phase, and still carries no ready/write/GC
    // evidence. Each run is its own store with its own root, so every phase
    // starts from a clean volume rather than inheriting another run's files.
    assert_service_bound_unconfirmed_durability(SeamPhase::Payload);
    assert_service_bound_unconfirmed_durability(SeamPhase::Metadata);
    assert_service_bound_unconfirmed_durability(SeamPhase::Commit);
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
    // The volume is still full on the payload leg for the whole test, which is
    // what "a persistent payload fault; two identical attempts" means. A
    // one-shot call ordinal cannot express it: armed with `Some(2)`, the
    // one-shot flag would clear after the first attempt and the second would run
    // `write_new_durable` calls 3..6 to completion and succeed.
    platform.lock().write_fault = WriteFault::PayloadWhileFull;
    let store = store_with_platform(platform.clone(), &root);
    let mut stages = Vec::new();
    for operation in ["retry-op-a", "retry-op-b"] {
        let request = stage_request(operation, b"payload", &root);
        let Err(error) = block_on(store.stage(request)) else {
            panic!("unrevalidated attempt must keep failing")
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
        stages.push(stage_name(failure.stage).to_owned());
    }
    assert_eq!(stages, vec!["PayloadWrite", "PayloadWrite"]);
    // The loop above is a two-element array literal with no range and no repeat,
    // and its body stages once per iteration (`request` is moved, never cloned),
    // so exactly two attempts reach the service and each produces one
    // `PayloadWrite` -- the port names `PayloadWrite`, which is not a durability
    // boundary, so the caller's stage in `stage_locked`'s payload arm stands.
    //
    // Writes per attempt, on this one store instance: #1 journal
    // `transactions/...stage` (the `persist_journal` create), #2 staged payload
    // `staging/...payload` which FAILS and returns the capacity error straight out
    // of `stage_locked`. The two attempts are independent because
    // `operation_path_from`/`temp_path` hash operation_id with idempotency_key, so
    // `retry-op-b` owns none of `retry-op-a`'s paths and repeats the same two
    // writes and the same single failure. The staged metadata, both publications
    // and the commit record are never reached by either attempt.
    assert_eq!(
        platform.lock().write_new_calls,
        4,
        "two attempts perform a finite bounded number of port writes, never a loop"
    );
}

/// Source: `finish_journal` commit creation, the commit-present recovery in
/// `stage_locked`, and `reestablish_publication_durability` through the owner's
/// existing `replace_durable` operation.
/// Discovery: one fixture fault fails the commit create before installing it;
/// a second installs real `.commit` bytes and only then reports `DirectoryFlush`
/// unconfirmed while arming the standing journal-replace fault. A new service
/// with the same files fails its same-identity owner replace until the fault
/// clears.
/// Executed-pass: the pre-create path leaves no commit record and stays typed
/// unresolved on replay. The installed-commit path retains exact operation,
/// idempotency key and locator across both refusals; after capacity is
/// revalidated, one real owner replace persists `CommitDurable`. Same-identity
/// replay then performs no writes or renames, and changed bytes conflict.
// WORK_UNIT_CASE: 864/20
#[test]
fn possible_commit_requires_same_operation_reconciliation() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_write_new_on = Some(4);
    let store = store_with_platform(platform.clone(), &root);
    let bytes = b"possible-commit";
    let request = stage_request("possible-op", bytes, &root);
    let Err(error) = block_on(store.stage(request.clone())) else {
        panic!("commit exhaustion must stay uncertain")
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected typed capacity failure, got: {error:?}");
    };
    assert_eq!(failure.stage, BlobCapacityStage::CommitWrite);
    assert_eq!(
        failure.evidence.effect,
        BlobCapacityEffect::DurabilityUnconfirmed {
            state: PublishState::MetadataDurable,
            possible_effect: true,
        }
    );
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
    assert!(
        !has_suffix(&platform, ".commit"),
        "the failed commit create installed no commit record"
    );

    // This is the already-present negative replay row: clearing a capacity
    // fault cannot re-establish a commit destination that was never installed.
    platform.lock().fail_write_new_on = None;
    assert_replay_stays_typed_unresolved(
        &store,
        &request,
        BlobCapacityStage::CommitWrite,
        PublishState::MetadataDurable,
        "possible-op",
    );
    assert!(
        !has_suffix(&platform, ".commit"),
        "an unresolved pre-create failure still has no commit record"
    );

    let Err(foreign) = block_on(store.stage(stage_request("foreign-op", bytes, &root))) else {
        panic!("a foreign operation must not reuse the committed scope")
    };
    assert!(
        matches!(foreign, BlobError::IdempotencyConflict),
        "a foreign operation must conflict with the retained commit-stage work: {foreign:?}"
    );

    // Extend case 20 over the distinct commit-present path: real commit bytes,
    // a restart with empty in-memory retention, a failed owner replace, then
    // one same-identity replacement and an inert CommitDurable replay.
    assert_same_commit_identity_reestablishment_settles_once();
}

/// Source: journal resume + the publication-obligation guard in
/// `stage_locked`/`finish_journal` on re-entry, and `reestablish_publication_durability`
/// as the only settlement of a carried obligation.
/// Discovery: fixture fails the publication rename before installing anything;
/// the fault is cleared and the same operation replays.
/// Executed-pass: the replay stays a typed unresolved capacity outcome under the
/// original operation identity and never issues a ready receipt, because the
/// destination bytes the obligation names were never installed and the owner
/// cannot re-establish a boundary it never installed. Identity is still
/// preserved: a foreign operation conflicts, and a genuine same-identity durable
/// re-establishment elsewhere settles such an operation exactly once, with one
/// durable payload/metadata pair and no duplication.
// WORK_UNIT_CASE: 864/21
#[test]
fn replay_after_revalidation_preserves_identity_without_duplication() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().rename_fault = RenameFault::BeforeInstall;
    let store = store_with_platform(platform.clone(), &root);
    let bytes = b"replay-payload";
    let request = stage_request("replay-op", bytes, &root);
    let Err(error) = block_on(store.stage(request.clone())) else {
        panic!("publication exhaustion must stay uncertain")
    };
    assert!(matches!(error, BlobError::StorageCapacity { .. }));
    platform.lock().rename_fault = RenameFault::None;

    // Capacity is revalidated and the SAME operation replays, but it must not
    // converge to Ready. This rename failed before installing a single byte, so
    // the obligation this journal durably carries names a destination that does
    // not exist: the guard's re-establishment cannot restore it and the
    // operation stays unresolved rather than being promoted on byte equality.
    assert_replay_stays_typed_unresolved(
        &store,
        &request,
        BlobCapacityStage::PayloadPublication,
        PublishState::JournalPrepared,
        "replay-op",
    );
    let keys_after_replay = file_keys(&platform);
    assert!(
        !keys_after_replay
            .iter()
            .any(|key| has_file_extension(key, "p1")),
        "the never-installed destination is still absent: {keys_after_replay:?}"
    );
    assert!(
        !keys_after_replay.iter().any(|key| key.ends_with(".commit")),
        "an unresolved publication must never reach the commit marker: {keys_after_replay:?}"
    );

    // The journal and its two staged objects survive the fence, so a later
    // entry still has the exact evidence a real re-establishment would need.
    assert!(
        keys_after_replay
            .iter()
            .any(|key| key.starts_with("transactions/")),
        "the journal survives an unresolved publication: {keys_after_replay:?}"
    );
    assert!(
        keys_after_replay
            .iter()
            .any(|key| key.starts_with("staging/")),
        "the staged payload and metadata survive for reconciliation: {keys_after_replay:?}"
    );

    // The positive half the card requires: the fence is not a permanent
    // lockout. Once the owner performs a real same-identity durable write on the
    // exact bounded bytes of the boundary the obligation names, the same
    // operation settles — once, with exactly one durable payload/metadata pair,
    // a further same-operation stage resolving through the durable commit
    // without duplicating, and changed bytes still conflicting.
    let settled_platform = assert_same_identity_reestablishment_settles_once();
    let settled_keys = file_keys(&settled_platform);
    let durable_pairs = settled_keys
        .iter()
        .filter(|key| !key.starts_with("transactions/") && !key.starts_with("staging/"))
        .count();
    assert_eq!(
        durable_pairs, 2,
        "exactly one payload/metadata pair may exist: {settled_keys:?}"
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

    // Baseline diff: the fixture denominator still covers exactly the live
    // stage baseline — every baseline stage decodes through the same helper
    // case 1 uses, and every baseline stage names a live source variant, so
    // drift on either side fails here instead of silently shrinking coverage.
    assert_fixture_rows_bind_live_vocabulary(&fixture);
    let baseline = fixture_stage_baseline(&fixture);
    assert_eq!(
        baseline,
        [
            "CasJournal",
            "Cleanup",
            "CommitWrite",
            "GcCleanup",
            "JournalWrite",
            "MetadataPublication",
            "MetadataWrite",
            "PayloadPublication",
            "PayloadWrite",
            "RootLeaseCreate",
            "RootLeaseHeartbeat",
        ],
        "fixture stage baseline changed: {baseline:?}"
    );
    for stage in baseline {
        assert!(
            BLOB_RS.contains(&format!("BlobCapacityStage::{stage}")),
            "baseline stage missing from live source: {stage}"
        );
    }

    // No cross-store semantic change: capacity failures stay BlobError, never
    // a store/adapter error type, and the service-produced observation is a
    // valid typed record rather than a catch-all bucket.
    assert!(!BLOB_RS.contains("StoreError"));
    assert!(!BLOB_RS.contains("AdapterError"));
    assert!(!API_RS.contains("StoreError"));
    assert!(!API_RS.contains("AdapterError"));

    // No generic enum catch: well-formed non-capacity errors keep their own
    // dispositions through the exhaustive consumer — no catch-all arm merges
    // them into one bucket, and capacity keeps its own.
    assert_eq!(error_disposition(&BlobError::NotFound), "NOT_FOUND");
    assert_eq!(error_disposition(&BlobError::StaleFence), "STALE");
    assert_eq!(error_disposition(&BlobError::OwnerConflict), "CONFLICT");
    assert!(
        BLOB_RS.contains("other => other"),
        "the error mappers must keep an explicit pass-through arm"
    );

    // No hidden deletion and no unbounded retry on the live path: a failed
    // stage keeps its journal with a finite port-write count.
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    platform.lock().fail_write_new_on = Some(2);
    let store = store_with_platform(platform.clone(), &root);
    let Err(error) = block_on(store.stage(stage_request("guard-op", b"payload", &root))) else {
        panic!("guarded exhaustion must fail")
    };
    assert!(matches!(error, BlobError::StorageCapacity { .. }));
    let BlobError::StorageCapacity { failure } = error else {
        panic!("capacity must stay BlobError::StorageCapacity");
    };
    assert_eq!(failure.stage, BlobCapacityStage::PayloadWrite);
    assert!(failure.validate().is_ok());
    let keys = file_keys(&platform);
    assert_eq!(keys.len(), 1, "only the journal may exist: {keys:?}");
    assert!(
        keys[0].starts_with("transactions/"),
        "the surviving file is the stage journal: {keys:?}"
    );
    assert_eq!(
        platform.lock().write_new_calls,
        2,
        "one failed stage performs a finite bounded number of port writes"
    );
}
