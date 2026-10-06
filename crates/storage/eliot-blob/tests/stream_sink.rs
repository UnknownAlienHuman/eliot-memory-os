//! Durable process-stream sink behavior for ELIOT issue #297.
//!
//! One substantive executable Rust test per `// WORK_UNIT_CASE: 297/<case>`
//! marker immediately above its attributes. Case 297/A1 drives the exact #296
//! sink port (`ProcessStreamSinkClient`) implemented by `BlobStoreStreamSink`
//! in `crates/storage/eliot-blob/src/stream_sink.rs` against the `eliot-blob`
//! service as it stands in this working tree -- the #297 delta, not `main`.
//!
//! The fixture harness below is MIRRORED verbatim from
//! `crates/storage/eliot-blob/tests/storage_exhausted.rs`: the `ok` and
//! `block_on` helpers and the `Fixture*` fakes keep their names and their exact
//! fake semantics, and nothing is redesigned. WHY `block_on`: like its sibling
//! suite this target declares no async runtime. The harness builds ONE store,
//! ONE `BlobStreamSinkStoreBinding` and ONE `BlobStoreStreamSink`; the adapter
//! is handed a `.clone()` of the shared service handle because it holds the
//! handle without claiming any root -- a second `BlobStoreService::new` on the
//! same root would raise `OwnerConflict` (A8) and must never appear here. That
//! construction is why the four stateless port fakes additionally carry
//! `Clone`: `BlobStoreService` derives `Clone` over all five of its port
//! parameters. No fake method, name or semantic changed to get there.
//!
//! Citations into `src/stream_sink.rs` and into
//! `eliot-process/src/stream_sink/{port,requests}.rs` name SYMBOLS, never line
//! numbers. Those files are still being rewritten underneath this suite, so a
//! raw line pointer here goes stale on its own; a named symbol does not.
//!
//! Governing fragments: I10.8.5 (append-only temporary raw evidence object; a
//! zero-byte source still publishes and verifies as a real immutable object),
//! I5.12 (one active root owner; blob durability proves bytes only).
//!
//! No test here fills a real disk or performs live recovery: every durable
//! write goes through the existing `BlobPlatformPort` seam held in memory by
//! `FixturePlatform`.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::task::{Context, Poll, Waker};

use sha2::{Digest, Sha256};

use eliot_blob::{
    AeadOpenRequest, AeadSealRequest, BlobAeadPort, BlobCapacityCause, BlobCapacityCleanup,
    BlobCapacityEffect, BlobCapacityEvidence, BlobCapacityFailure, BlobCapacityIdentity,
    BlobCapacityRecovery, BlobCapacityStage, BlobCasProviderResult, BlobCompressionPort, BlobError,
    BlobKeyPort, BlobKeySelection, BlobLiveSetPort, BlobPathState, BlobPlatformPort,
    BlobStoreService, BlobStoreStreamSink, BlobStreamPublication, BlobStreamSinkStoreBinding,
    BlobStreamUnavailableReason, LiveSetRevalidation, PublishState, RootClaimProof,
};
use eliot_blob_api::{
    BlobCasCapability, BlobHash, BlobId, BlobIssuerTrustAnchor, BlobPolicyBinding, BlobReadRequest,
    BlobReceiptContext, BlobRootLease, BlobStageRequest, BlobStoreClient, CompressionDescriptor,
    CryptoDescriptor, ObjectResidencyKey, RetentionClass, VersionedContentDigest,
};
use eliot_platform::{PlatformHandle, WorkScopePath};
use eliot_process::{
    DurableStreamLocatorKind, DurableStreamRepresentation, ProcessExecutionBinding,
    ProcessStreamDigestAlgorithm, ProcessStreamKind, ProcessStreamPolicyBinding,
    ProcessStreamPrefixPreview, ProcessStreamSinkAbortReason, ProcessStreamSinkAbortRequest,
    ProcessStreamSinkAppend, ProcessStreamSinkAppendDisposition, ProcessStreamSinkClient,
    ProcessStreamSinkError, ProcessStreamSinkFinalizeRequest, ProcessStreamSinkLimits,
    ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback, ProcessStreamSinkSession,
    ProcessStreamSinkSessionId, ProcessStreamSinkSourceId, ProcessStreamSinkState,
    ProcessStreamSinkTerminalId, ProcessStreamSinkUnknownOutcome, StreamEvidenceGap,
    StreamPersistenceStatus, StreamTransportStatus,
};
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
    /// A standing payload-write capacity fault: every durable write to the
    /// staged PAYLOAD envelope fails, for as long as this condition holds.
    ///
    /// `fail_write_new_on` is a one-shot CALL ORDINAL -- it names the Nth
    /// `write_new_durable` call and self-clears -- so it cannot express the
    /// persistent fault case 19 states in its own doc comment ("a persistent
    /// payload fault; two identical attempts"): attempt two would issue writes
    /// 3..6 and meet no fault at all. This flag is keyed on the DESTINATION
    /// IDENTITY instead, exactly like `is_metadata_destination`, so it can only
    /// ever fire on the payload leg: the journal and the commit record both
    /// live under `transactions/`, the metadata leg is `staging/...metadata`,
    /// and the two final publications are installed by
    /// `rename_no_replace_durable`, never by this method. Naive call-order
    /// stickiness would re-fire on the second attempt's JOURNAL write and report
    /// `JournalWrite` where the test asserts `PayloadWrite`.
    ///
    /// Default off, and `fail_write_new_on` keeps its one-shot semantics, so the
    /// cases that share `write_new_durable` and do not opt in are
    /// byte-identical to before.
    ///
    /// The flag itself is the condition: there is no retry budget, counter or
    /// timer behind it.
    fail_payload_write_while_full: bool,
    /// The commit create installs its actual bytes, then its directory-flush
    /// boundary reports unconfirmed durability and only then marks the volume
    /// full for all following journal replacements.
    ///
    /// This destination-keyed seam cannot fire on the earlier payload,
    /// metadata, or journal writes. It therefore lets both publication
    /// checkpoints succeed before the commit boundary arms
    /// `fail_replace_while_full`.
    fail_commit_write_after_install_while_full: bool,
    fail_replace_once: bool,
    /// The volume is still full: the journal durable-state replace keeps
    /// failing for as long as this condition holds, across every call.
    ///
    /// `fail_replace_once` models exactly one failed sync and self-clears;
    /// capacity that has not been freed yet is a standing condition, not a
    /// single attempt, so it needs its own flag. The flag itself is the
    /// condition -- there is no retry budget, counter or timer behind it.
    fail_replace_while_full: bool,
    fail_rename: bool,
    /// The rename installs the final destination bytes and only THEN fails at
    /// the port's own directory-flush durability boundary.
    ///
    /// This is the only seam that produces "destination bytes visible, durable
    /// rename unconfirmed": `fail_rename` fails before anything is installed.
    fail_rename_after_install: bool,
    /// The same install-then-flush seam, keyed on the METADATA publication's
    /// final identity instead of the payload's, so the metadata publication
    /// phase is reachable too.
    ///
    /// s-04.12 lays the two publications out under disjoint filename kinds --
    /// `...{hash}.r{residency}.p{gen}` for the payload and
    /// `...{hash}.r{residency}.m{gen}` for the metadata -- and the service reads
    /// exactly that distinction back in `parse_scoped_path`. Keying on the
    /// destination identity is what makes the second phase reachable with one
    /// boolean. This is NOT a call ordinal, a counter, a retry budget or a timer:
    /// the flag is the condition itself, and the flag is what is armed. Default
    /// off, so the payload seam and every case that does not opt in keep
    /// byte-identical behaviour.
    fail_metadata_rename_after_install: bool,
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
            Err(_) => panic!("fixture platform lock poisoned"),
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
            || (state.fail_payload_write_while_full && Self::is_payload_temp_destination(path))
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
        if state.fail_commit_write_after_install_while_full && Self::is_commit_destination(path) {
            // The bytes are installed before the owner reports its own
            // directory-flush boundary. The volume becomes full only at this
            // commit boundary, after payload and metadata journal checkpoints
            // have already succeeded.
            state.fail_replace_while_full = true;
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
        if state.fail_replace_while_full {
            // The volume is still full, so every journal durable-state replace
            // fails until the condition is cleared. This is what makes "space
            // freed" observable to the service: nothing else changes and the
            // same operation simply keeps meeting the same boundary.
            return Err(Self::port_capacity(
                BlobCapacityStage::JournalWrite,
                BlobCapacityEffect::PartialWriteUnknown,
                Some(bytes.len() as u64),
            ));
        }
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
        if state.fail_rename {
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
        if state.fail_rename_after_install
            || (state.fail_metadata_rename_after_install && metadata_leg)
        {
            // The final name is now visible in its directory; only the port's own
            // `fsync` of that directory fails. I5.12 makes durable rename a
            // precondition of the receipt, so this is "published, durability
            // unconfirmed" -- a state `fail_rename` can never reach, because it
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

/// A `BlobPlatformPort` over a real temp directory: every durable byte the
/// service hands down reaches the filesystem, so a stage leaves observable
/// files and a read returns them. Conditional recovery stays a declared gap
/// (`PlanGap` from `compare_and_replace_durable`, like the capacity
/// fixture): this platform covers the stage/read path, never the CAS path.
/// Clones share one root path and one claim slot, like the memory fixture.
#[derive(Clone)]
struct DirPlatform {
    root: std::path::PathBuf,
    claim: Arc<Mutex<Option<RootClaimProof>>>,
}

impl DirPlatform {
    fn platform_error(context: &str, error: std::io::Error) -> BlobError {
        BlobError::InvalidContract(format!("dir platform {context}: {error}"))
    }

    fn resolve(&self, path: &WorkScopePath) -> Result<std::path::PathBuf, BlobError> {
        let identity = path.normalized_identity();
        if identity.split('/').any(|component| {
            component == ".." || component.contains('\\') || component.contains(':')
        }) {
            return Err(BlobError::InvalidContract(
                "dir platform refuses non-contained path".to_owned(),
            ));
        }
        Ok(self.root.join(identity))
    }

    /// Collects every file under `dir`, expressed relative to `dir`. The
    /// service-side scope prefix applies at the caller (`list` retains only
    /// the wanted scope), so the walk itself takes no prefix.
    fn list_recursive(
        root: &std::path::Path,
        dir: &std::path::Path,
        out: &mut Vec<WorkScopePath>,
    ) -> Result<(), BlobError> {
        let entries =
            std::fs::read_dir(dir).map_err(|error| Self::platform_error("list", error))?;
        for entry in entries {
            let entry = entry.map_err(|error| Self::platform_error("list", error))?;
            let path = entry.path();
            if path.is_dir() {
                Self::list_recursive(root, &path, out)?;
                continue;
            }
            let Some(identity) = path
                .strip_prefix(root)
                .ok()
                .and_then(|relative| relative.to_str())
            else {
                continue;
            };
            out.push(
                WorkScopePath::new(identity.replace('\\', "/"))
                    .map_err(|error| BlobError::InvalidContract(error.to_string()))?,
            );
        }
        Ok(())
    }
}

impl BlobPlatformPort for DirPlatform {
    fn claim_root(&mut self, lease: &BlobRootLease) -> Result<RootClaimProof, BlobError> {
        std::fs::create_dir_all(&self.root)
            .map_err(|error| Self::platform_error("claim root", error))?;
        let proof = RootClaimProof {
            root_id: lease.root_id.as_str().to_owned(),
            owner_id: lease.owner_id.as_str().to_owned(),
            lease_id: lease.lease_id.as_str().to_owned(),
            root_generation: lease.root_generation,
            containment_proven: true,
            permissions_proven: true,
        };
        match self.claim.lock() {
            Ok(mut slot) => {
                *slot = Some(proof.clone());
                Ok(proof)
            }
            Err(_) => panic!("dir platform lock poisoned"),
        }
    }

    fn inspect_root(&self, _lease: &BlobRootLease) -> Result<RootClaimProof, BlobError> {
        match self.claim.lock() {
            Ok(slot) => slot.clone().ok_or(BlobError::OwnerConflict),
            Err(_) => panic!("dir platform lock poisoned"),
        }
    }

    fn prove_contained(
        &self,
        _lease: &BlobRootLease,
        path: &WorkScopePath,
    ) -> Result<(), BlobError> {
        self.resolve(path).map(|_| ())
    }

    fn read_bounded(&self, path: &WorkScopePath, max_bytes: u64) -> Result<Vec<u8>, BlobError> {
        let resolved = self.resolve(path)?;
        let bytes = std::fs::read(&resolved).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                BlobError::NotFound
            } else {
                Self::platform_error("read", error)
            }
        })?;
        if bytes.len() as u64 > max_bytes {
            return Err(BlobError::InvalidContract(
                "bounded platform read ceiling exceeded".to_owned(),
            ));
        }
        Ok(bytes)
    }

    fn write_new_durable(&mut self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
        let resolved = self.resolve(path)?;
        if let Some(parent) = resolved.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| Self::platform_error("write parent", error))?;
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&resolved)
        {
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(bytes)
                    .map_err(|error| Self::platform_error("write", error))
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(BlobError::IdempotencyConflict)
            }
            Err(error) => Err(Self::platform_error("write", error)),
        }
    }

    fn replace_durable(&mut self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
        let resolved = self.resolve(path)?;
        if !resolved.exists() {
            return Err(BlobError::NotFound);
        }
        std::fs::write(&resolved, bytes).map_err(|error| Self::platform_error("replace", error))
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
            "dir platform performs no conditional mutation".to_owned(),
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
        let from = self.resolve(source)?;
        let to = self.resolve(destination)?;
        if to.exists() {
            return Err(BlobError::IdempotencyConflict);
        }
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| Self::platform_error("rename parent", error))?;
        }
        std::fs::rename(&from, &to).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                BlobError::NotFound
            } else {
                Self::platform_error("rename", error)
            }
        })
    }

    fn remove_durable(&mut self, path: &WorkScopePath) -> Result<(), BlobError> {
        let resolved = self.resolve(path)?;
        match std::fs::remove_file(&resolved) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Self::platform_error("remove", error)),
        }
    }

    fn stat(&self, path: &WorkScopePath) -> Result<BlobPathState, BlobError> {
        let resolved = self.resolve(path)?;
        match std::fs::metadata(&resolved) {
            Ok(metadata) => Ok(BlobPathState::File {
                length: metadata.len(),
                modified_unix_ms: 0,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(BlobPathState::Missing)
            }
            Err(error) => Err(Self::platform_error("stat", error)),
        }
    }

    fn list(&self, prefix: &WorkScopePath) -> Result<Vec<WorkScopePath>, BlobError> {
        let mut out = Vec::new();
        if self.root.exists() {
            Self::list_recursive(&self.root, &self.root, &mut out)?;
        }
        let wanted = prefix.normalized_identity().to_owned();
        out.retain(|path| path.normalized_identity().starts_with(&wanted));
        Ok(out)
    }

    fn now_unix_ms(&mut self) -> Result<u64, BlobError> {
        Ok(0)
    }
}

// `BlobStoreService` derives `Clone` over ALL FIVE port parameters, so the
// shared-handle construction the sink requires (`store.clone()`: the adapter
// holds the one owner without claiming a root, and a second
// `BlobStoreService::new` on the same root would raise `OwnerConflict`, A8)
// needs every injected port to be `Clone`. `FixturePlatform` already is; the
// other four gain the derive here. That changes no fake behaviour: all four are
// stateless unit types whose every method is unchanged.
#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone, Default)]
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

/// Source: `BlobStreamSinkStoreBinding::new` + `BlobStoreStreamSink::new`
/// (`src/stream_sink.rs`), and `ProcessStreamSinkClient::open`/`finalize`/
/// `readback` (`eliot-process/src/stream_sink/port.rs`) with
/// `ProcessStreamSinkOpenRequest`/`ProcessStreamSinkFinalizeRequest` from
/// `eliot-process/src/stream_sink/requests.rs`.
/// Discovery: the W7 zero-byte contract stated on
/// `BlobStreamPublication::Complete`, on `complete_source` and on
/// `verify_readback` -- a zero-byte source publishes and verifies as a real
/// immutable object and is never reported as "no source".
/// Executed-pass: the live service is opened over the port, given ZERO appended
/// chunks and one complete-source finalize, and the assertions below are real
/// ones against the settled terminal, the owner-backed publication and the
/// durable source identity -- never count-only.
// WORK_UNIT_CASE: 297/A1-empty
#[allow(
    clippy::too_many_lines,
    reason = "the open, zero-chunk publish, owner readback and publication proof is one case"
)]
#[test]
fn empty_source_publishes_and_verifies_as_real_object() {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    // The ONE active root owner of this case. The sink below receives a clone of
    // this shared handle, never a second construction on the same root: that
    // would raise `OwnerConflict` (A8) and is exactly what must not appear here.
    let store = store_with_platform(platform, &root);

    // The five store-side identities `BlobStreamSinkStoreBinding::new`
    // validates. The residency template's content digest is a placeholder only:
    // `stage_request` replaces it with the BLAKE3 of the exact staged bytes, so
    // no byte of this case is described by the template itself.
    let stage_context = receipt_context("sink-empty-stage");
    let read_context: BlobReceiptContext = ok(serde_json::from_str(&context_json(
        "READ",
        "sink-empty-read",
        "request-sink-empty-read",
    )));
    let root_lease = lease_for(&stage_context, &root);
    let (_, residency_template) = residency(b"");
    let binding = ok(BlobStreamSinkStoreBinding::new(
        root_lease,
        stage_context,
        read_context,
        policy(),
        residency_template,
    ));
    let sink = BlobStoreStreamSink::new(store.clone(), binding);

    let binding_json = ok(serde_json::from_value::<ProcessExecutionBinding>(
        serde_json::json!({
            "operation_id": "operation-1",
            "process_tree_id": "tree-1",
            "job_id": "job-1",
            "image_id": "image-1",
            "session_id": "session-1",
            "generation": 3,
            "action_lease_ref": "lease-1",
            "authority_id": "authority-1",
            "authority_epoch": {
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 7
            },
            "state_fence": {
                "authority_epoch": {
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 7
                },
                "generation": 3,
                "nonce": "fence-1"
            },
            "request_digest": "a".repeat(64),
            "permit_digest": "b".repeat(64),
            "effect_digest": "c".repeat(64),
            "validation_revision": 2
        }),
    ));
    let stream_policy = ok(ProcessStreamPolicyBinding::new(
        "policy:sink-empty",
        "privacy:project",
        "visibility:owner",
        "retention:task",
        "redaction:exact-v1",
    ));
    let open = ok(ProcessStreamSinkOpenRequest::new(
        ok(ProcessStreamSinkSessionId::new("sink-empty-session")),
        ok(ProcessStreamSinkSourceId::new("source:sink-empty-session")),
        ok(ProcessStreamSinkTerminalId::new(
            "terminal:sink-empty-session",
        )),
        binding_json,
        ProcessStreamKind::Stdout,
        stream_policy,
        ok(ProcessStreamSinkLimits::new(4, 16, 4, 8, 2, 8, 10, 20, 20)),
        ProcessStreamDigestAlgorithm::Sha256,
        ProcessStreamDigestAlgorithm::Sha256,
    ));
    let session = ok(block_on(sink.open(open)));

    // ZERO appends. The admitted transport stream is empty, so the admitted
    // digest and count are the empty ones and the bounded preview retains and
    // represents nothing: no byte was ever handed to the adapter.
    let empty_sha256 = format!("{:x}", Sha256::digest(b""));
    let request = ok(ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        0,
        0,
        10,
        StreamTransportStatus::Complete,
        empty_sha256.clone(),
        0,
        ok(ProcessStreamPrefixPreview::from_transport_prefix(
            Vec::new(),
            0,
        )),
        None,
        Vec::new(),
    ));
    // A complete, gap-free, transport-complete source with no declared
    // transformation is the ONLY shape that reaches `publish_reserved`, so this
    // call is what hands zero bytes to the one blob owner under the bound stage
    // operation identity.
    let terminal = ok(block_on(sink.finalize(session.clone(), request)));

    // The terminal is a complete source, not a withheld one: `complete_source`
    // ran, so a real ready receipt existed and `verify_readback` had already read
    // that very object back and matched its byte commitment. Nothing else can
    // mint this state.
    assert!(terminal.validate().is_ok());
    assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);
    assert_eq!(terminal.final_sequence(), 0);
    assert_eq!(terminal.final_offset(), 0);
    assert_eq!(terminal.admitted_chunks(), 0);
    assert_eq!(terminal.admitted_bytes(), 0);
    assert_eq!(terminal.admitted_sha256(), empty_sha256);

    let evidence = terminal.evidence();
    assert_eq!(evidence.transport(), StreamTransportStatus::Complete);
    assert_eq!(
        evidence.persistence(),
        StreamPersistenceStatus::CompleteSource
    );
    assert!(evidence.gaps().is_empty());
    assert_eq!(evidence.observed_bytes(), 0);
    assert_eq!(evidence.observed_sha256(), empty_sha256);
    let Some(source) = evidence.source() else {
        panic!("a complete source terminal must carry its durable expansion source");
    };
    // The durable source names a real object, not "no source": the locator hash
    // is the empty-content digest and it still resolves through its own
    // owner-issued ready receipt.
    assert_eq!(source.kind(), DurableStreamLocatorKind::Blob);
    assert_eq!(
        source.representation(),
        DurableStreamRepresentation::ExactTransportBytes
    );
    assert_eq!(
        source.byte_length(),
        0,
        "the readback this terminal rests on returned zero bytes"
    );
    assert_eq!(source.sha256(), empty_sha256);
    assert_eq!(
        source.locator(),
        format!("blob:{}", blake3::hash(b"").to_hex()),
        "the published object is addressed by the empty-content identity, never by a restated locator"
    );
    assert!(
        !source.ready_receipt_ref().is_empty(),
        "a complete source is resolvable only through an owner-issued receipt reference"
    );
    assert!(
        source.transformation().is_none(),
        "this adapter stages exact transport bytes and records no transformation output"
    );

    // The recorded publication is the same proven object: `Complete` is set only
    // from a real owner receipt whose readback matched, and never from a
    // nonempty locator alone.
    let Some(BlobStreamPublication::Complete(complete)) = sink.publication() else {
        panic!("a verified zero-byte source must record a real object, never `Unavailable`");
    };
    assert_eq!(complete.locator, source.locator());
    assert_eq!(complete.ready_receipt_ref, source.ready_receipt_ref());
    assert_eq!(complete.byte_length, 0);
    assert_eq!(complete.sha256, empty_sha256);
    assert_eq!(complete.measures.transport.byte_count, 0);
    assert_eq!(complete.measures.transport.sha256, empty_sha256);
    assert_eq!(complete.measures.admissible_source.byte_count, 0);
    assert_eq!(
        complete.measures.bounded_preview.retained_byte_count, 0,
        "an empty stream retains no inline preview bytes"
    );
    assert_eq!(
        complete.measures.bounded_preview.represented_byte_count, 0,
        "an empty stream is fully represented by its empty preview, so it omits nothing"
    );
    assert!(complete.measures.bounded_preview.omitted_ranges.is_empty());

    // The settled session reads back the ONE recorded terminal under the same
    // command identity: no second object, no bare session view and no unknown
    // outcome once the publication is proven.
    let ProcessStreamSinkReadback::Terminal { terminal: recorded } =
        ok(block_on(sink.readback(session.clone())))
    else {
        panic!("a proven publication reads back as its terminal");
    };
    assert_eq!(recorded, terminal);
}

/// The session limits the replay cases below open with.
///
/// WHY these ceilings and not the ones case 297/A1 states: `append_locked`
/// charges every arriving chunk against `max_in_flight_bytes` at its
/// SERIALIZATION size, and `PersistenceQueueBound::record_bytes` charges four
/// `u64` slots plus the digest's 64 hex characters plus the payload. A charged
/// chunk is therefore 96 bytes or more, so A1's eight-byte in-flight ceiling --
/// correct for a case that appends nothing -- would shed every chunk here as
/// `Backpressured` before the replay-identity comparison is ever reached.
/// `max_in_flight_bytes` must also not exceed `max_total_admitted_bytes`.
fn replay_limits() -> ProcessStreamSinkLimits {
    ok(ProcessStreamSinkLimits::new(
        64, 4096, 8, 4096, 8, 4096, 10, 20, 20,
    ))
}

/// The store, binding, sink and open request the replay cases share.
///
/// Every value here is the one case 297/A1 states -- the same five store-side
/// identities, the same `ProcessExecutionBinding`, the same digest algorithms --
/// so this states no new contract; it exists so the three replay cases drive
/// ONE `ProcessStreamSinkClient` shape instead of restating the construction
/// three times. Only the labels differ, so each case owns a disjoint root and a
/// disjoint session/source/terminal identity.
fn open_replay_sink(case: &str) -> (BlobStoreStreamSink<FixtureStore>, ProcessStreamSinkSession) {
    let (_, _, sink, session) = open_observed_sink(case);
    (sink, session)
}

/// The store, binding, sink and open request the replay cases share, plus the
/// platform and store handles behind the sink.
///
/// `FixturePlatform` clones over one shared `Arc<Mutex<FaultState>>`, so the
/// returned handle observes every durable write the sink's store performs —
/// including writes the sink was never supposed to make. The store handle
/// lets a case attach a SECOND adapter to the same owner (a restart without
/// retained proof), which `open_replay_sink` cannot express. Both helpers
/// build on `open_sink_on_store`, so no case restates the construction.
fn open_observed_sink(
    case: &str,
) -> (
    FixturePlatform,
    FixtureStore,
    BlobStoreStreamSink<FixtureStore>,
    ProcessStreamSinkSession,
) {
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    let platform_handle = platform.clone();
    // The ONE active root owner of this case; every sink below receives a
    // clone of this shared handle, never a second construction on the same
    // root.
    let store = store_with_platform(platform, &root);
    let (sink, session) = open_sink_on_store(case, &root, store.clone());
    (platform_handle, store, sink, session)
}

/// Binds one sink session to an existing store and opens it.
///
/// The binding lease names the store's own root, so a second adapter on the
/// same store observes the same owner without claiming the root twice. Only
/// the labels differ per `case`, so each session owns disjoint identities.
fn open_sink_on_store(
    case: &str,
    root: &str,
    store: FixtureStore,
) -> (BlobStoreStreamSink<FixtureStore>, ProcessStreamSinkSession) {
    open_sink_on_store_with_limits(case, root, store, replay_limits())
}

/// Binds and opens one sink session under caller-chosen session limits.
///
/// Only the pressure case needs this: every other case shares
/// `replay_limits`. The limits travel into the open request the session
/// pins, so the ceilings a case probes are the ceilings the session states.
fn open_sink_on_store_with_limits(
    case: &str,
    root: &str,
    store: FixtureStore,
    limits: ProcessStreamSinkLimits,
) -> (BlobStoreStreamSink<FixtureStore>, ProcessStreamSinkSession) {
    let stage_context = receipt_context(&format!("sink-{case}-stage"));
    let read_context: BlobReceiptContext = ok(serde_json::from_str(&context_json(
        "READ",
        &format!("sink-{case}-read"),
        &format!("request-sink-{case}-read"),
    )));
    let root_lease = lease_for(&stage_context, root);
    let (_, residency_template) = residency(b"");
    let binding = ok(BlobStreamSinkStoreBinding::new(
        root_lease,
        stage_context,
        read_context,
        policy(),
        residency_template,
    ));
    let sink = BlobStoreStreamSink::new(store.clone(), binding);

    let binding_json = ok(serde_json::from_value::<ProcessExecutionBinding>(
        serde_json::json!({
            "operation_id": "operation-1",
            "process_tree_id": "tree-1",
            "job_id": "job-1",
            "image_id": "image-1",
            "session_id": "session-1",
            "generation": 3,
            "action_lease_ref": "lease-1",
            "authority_id": "authority-1",
            "authority_epoch": {
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 7
            },
            "state_fence": {
                "authority_epoch": {
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 7
                },
                "generation": 3,
                "nonce": "fence-1"
            },
            "request_digest": "a".repeat(64),
            "permit_digest": "b".repeat(64),
            "effect_digest": "c".repeat(64),
            "validation_revision": 2
        }),
    ));
    let stream_policy = ok(ProcessStreamPolicyBinding::new(
        format!("policy:sink-{case}"),
        "privacy:project",
        "visibility:owner",
        "retention:task",
        "redaction:exact-v1",
    ));
    let open = ok(ProcessStreamSinkOpenRequest::new(
        ok(ProcessStreamSinkSessionId::new(format!(
            "sink-{case}-session"
        ))),
        ok(ProcessStreamSinkSourceId::new(format!(
            "source:sink-{case}-session"
        ))),
        ok(ProcessStreamSinkTerminalId::new(format!(
            "terminal:sink-{case}-session"
        ))),
        binding_json,
        ProcessStreamKind::Stdout,
        stream_policy,
        limits,
        ProcessStreamDigestAlgorithm::Sha256,
        ProcessStreamDigestAlgorithm::Sha256,
    ));
    let session = ok(block_on(sink.open(open)));
    (sink, session)
}

/// Counts every durable write the platform has performed.
///
/// A stage is never a pure-memory act: it issues `write_new_durable` calls
/// for the payload, the metadata, the journal and the commit record. Any
/// `stage` call therefore moves these counters, so equal counters across a
/// terminal command prove no stage ran — without naming any file layout.
fn durable_write_counts(platform: &FixturePlatform) -> (u64, u64, usize) {
    let state = platform
        .state
        .lock()
        .expect("fixture platform state is observable");
    (
        state.write_new_calls,
        state.replace_calls,
        state.files.len(),
    )
}

/// Appends one chunk at explicit coordinates through the port.
///
/// `ProcessStreamSinkAppend::from_bytes` computes the chunk's own SHA-256, so
/// the digest in every request is the real digest of the bytes sent and a
/// refused case can vary the BYTES, LENGTH or OFFSET without ever tripping the
/// request's own digest validation first.
fn append_chunk(
    sink: &BlobStoreStreamSink<FixtureStore>,
    session: &ProcessStreamSinkSession,
    sequence: u64,
    offset: u64,
    bytes: &[u8],
) -> Result<ProcessStreamSinkAppendDisposition, ProcessStreamSinkError> {
    let request = ProcessStreamSinkAppend::from_bytes(sequence, offset, bytes.to_vec(), 10);
    block_on(sink.append(session.clone(), request))
}

/// Asserts that a disposition is exactly `Accepted`/`Replayed` at these
/// coordinates, by name, rather than by count.
fn assert_disposition(
    disposition: ProcessStreamSinkAppendDisposition,
    expected: ProcessStreamSinkAppendDisposition,
) {
    assert_eq!(disposition, expected);
}

/// Source: the chunk-replay identity block in `src/stream_sink.rs`
/// (`append_locked`): an append whose `sequence` is BELOW `next_sequence` is a
/// replay candidate, and it is accepted only when the recorded
/// `AdmittedChunk` metadata AND the admitted bytes at that chunk's coordinates
/// both match -- otherwise `MismatchedReplay`. An append AHEAD of
/// `next_sequence` is a `SequenceGap` with the exact expected/observed
/// coordinates.
/// Discovery: a transport that re-sends a chunk after a dropped reply must not
/// publish a second object, so the exact replay settles as `Replayed` and the
/// final publication carries `C+E` exactly.
/// Executed-pass: chunk `C` (nonempty) and empty chunk `E` are appended, then
/// BOTH are re-appended with identical sequence/offset/length/sha256; the
/// dispositions and the published object's length and digest are the assertions,
/// never a count.
/// I10.8.5: the append-only temporary raw evidence object grows once, by the
/// admitted bytes, no matter how many times a chunk is re-sent.
// WORK_UNIT_CASE: 297/A3-replay
#[test]
fn exact_replay_is_accepted_including_empty_chunk() {
    const C: &[u8] = b"chunk-c";
    const E: &[u8] = b"";
    let (sink, session) = open_replay_sink("replay");

    // The admitted stream is `C` then an EMPTY chunk. The empty chunk is a real
    // admitted chunk with its own sequence, offset and SHA-256 of the empty
    // byte string, so it must be replayable by the same arms as a nonempty one.
    assert_disposition(
        ok(append_chunk(&sink, &session, 0, 0, C)),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 1,
            next_offset: C.len() as u64,
        },
    );
    assert_disposition(
        ok(append_chunk(&sink, &session, 1, C.len() as u64, E)),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 2,
            next_offset: C.len() as u64,
        },
    );

    // The exact replay of `C`, and then of the empty chunk `E`. Both are
    // admitted chunks already, so both settle as `Replayed` and both report the
    // UNCHANGED cursors: a replay advances neither the sequence nor the offset.
    assert_disposition(
        ok(append_chunk(&sink, &session, 0, 0, C)),
        ProcessStreamSinkAppendDisposition::Replayed {
            next_sequence: 2,
            next_offset: C.len() as u64,
        },
    );
    assert_disposition(
        ok(append_chunk(&sink, &session, 1, C.len() as u64, E)),
        ProcessStreamSinkAppendDisposition::Replayed {
            next_sequence: 2,
            next_offset: C.len() as u64,
        },
    );

    // Two replays admitted nothing: the session still counts two chunks and
    // `C.len()` bytes.
    let ProcessStreamSinkReadback::Session { view } = ok(block_on(sink.readback(session.clone())))
    else {
        panic!("an unfinalized session reads back as its session view");
    };
    assert_eq!(view.admitted_chunks(), 2);
    assert_eq!(view.admitted_bytes(), C.len() as u64);

    let expected_sha256 = format!("{:x}", Sha256::digest(C));
    let request = ok(ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        2,
        C.len() as u64,
        20,
        StreamTransportStatus::Complete,
        expected_sha256.clone(),
        C.len() as u64,
        ok(ProcessStreamPrefixPreview::from_transport_prefix(
            C.to_vec(),
            C.len() as u64,
        )),
        None,
        Vec::new(),
    ));
    let terminal = ok(block_on(sink.finalize(session.clone(), request)));

    assert!(terminal.validate().is_ok());
    assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);
    assert_eq!(terminal.admitted_chunks(), 2);
    assert_eq!(terminal.admitted_bytes(), C.len() as u64);
    assert_eq!(terminal.admitted_sha256(), expected_sha256);

    // The ONE published object is exactly `C+E`. Its length and digest are the
    // proof that the two replays minted no second object and appended no second
    // byte: a duplicate append would have published `C+E+C+E`.
    let Some(BlobStreamPublication::Complete(complete)) = sink.publication() else {
        panic!("a complete source must record a real object, never `Unavailable`");
    };
    assert_eq!(complete.byte_length, C.len() as u64);
    assert_eq!(complete.sha256, expected_sha256);
    assert_eq!(
        complete.locator,
        format!("blob:{}", blake3::hash(C).to_hex()),
        "the replayed stream published the content it actually admitted"
    );
    let Some(source) = terminal.evidence().source() else {
        panic!("a complete source terminal must carry its durable expansion source");
    };
    assert_eq!(source.byte_length(), C.len() as u64);
    assert_eq!(source.sha256(), expected_sha256);
}

/// Source: the same `append_locked` replay-identity block cited by case
/// 297/A3-replay, and specifically its `MismatchedReplay` arm.
/// Discovery: a replay is accepted only when the sequence, offset, length,
/// sha256 AND the bytes at that offset ALL match the recorded
/// `AdmittedChunk`; any disagreement is a mismatched replay, and a mismatched
/// replay is refused BEFORE the persistence-queue charge and before `staged`
/// is extended.
/// Executed-pass: three refusals against one admitted chunk -- same sequence
/// with changed bytes, with a short length, and with a wrong offset -- and then
/// a finalize whose published object is the ORIGINAL chunk.
/// I10.8.5: a refused replay never reaches the append-only evidence object, so
/// the published bytes stay the bytes the transport actually sent.
// WORK_UNIT_CASE: 297/A3-changed
#[allow(
    clippy::too_many_lines,
    reason = "three refusal sub-cases and the finalization proof are one case"
)]
#[test]
fn changed_replay_leaves_state_unchanged() {
    const C: &[u8] = b"chunk-c-original";
    let (sink, session) = open_replay_sink("changed");

    assert_disposition(
        ok(append_chunk(&sink, &session, 0, 0, C)),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 1,
            next_offset: C.len() as u64,
        },
    );

    // (a) The same sequence and coordinates with DIFFERENT BYTES. The length and
    // the offset agree, so this is refused on the byte comparison alone.
    assert_eq!(
        append_chunk(&sink, &session, 0, 0, b"chunk-c-changed!"),
        Err(ProcessStreamSinkError::MismatchedReplay),
        "a replay whose bytes differ from the admitted chunk is not the same chunk"
    );

    // (b) The same sequence and offset with a SHORT LENGTH: a prefix of the
    // admitted chunk. Its digest is a real digest of the bytes it carries, so
    // the refusal is the length/metadata arm and not a request digest failure.
    assert_eq!(
        append_chunk(&sink, &session, 0, 0, &C[..C.len() - 1]),
        Err(ProcessStreamSinkError::MismatchedReplay),
        "a replay that carries fewer bytes than the admitted chunk is not the same chunk"
    );

    // (c) The same sequence and bytes at a WRONG OFFSET. The offset arm runs
    // before the length and digest arms, so this isolates it.
    assert_eq!(
        append_chunk(&sink, &session, 0, 1, C),
        Err(ProcessStreamSinkError::MismatchedReplay),
        "a replay at an offset the admitted chunk never occupied is not the same chunk"
    );

    // None of the three refusals advanced a cursor or admitted a byte: the
    // session still counts exactly the one original chunk.
    let ProcessStreamSinkReadback::Session { view } = ok(block_on(sink.readback(session.clone())))
    else {
        panic!("an unfinalized session reads back as its session view");
    };
    assert_eq!(view.admitted_chunks(), 1);
    assert_eq!(view.admitted_bytes(), C.len() as u64);
    assert_eq!(view.next_sequence(), 1);
    assert_eq!(view.next_offset(), C.len() as u64);

    let expected_sha256 = format!("{:x}", Sha256::digest(C));
    let request = ok(ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        1,
        C.len() as u64,
        20,
        StreamTransportStatus::Complete,
        expected_sha256.clone(),
        C.len() as u64,
        ok(ProcessStreamPrefixPreview::from_transport_prefix(
            C.to_vec(),
            C.len() as u64,
        )),
        None,
        Vec::new(),
    ));
    let terminal = ok(block_on(sink.finalize(session.clone(), request)));

    assert!(terminal.validate().is_ok());
    assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);
    assert_eq!(terminal.admitted_chunks(), 1);

    // The published object is the ORIGINAL `C`: had any refused replay reached
    // the staged plaintext, the length or the digest below would differ.
    let Some(BlobStreamPublication::Complete(complete)) = sink.publication() else {
        panic!("a complete source must record a real object, never `Unavailable`");
    };
    assert_eq!(complete.byte_length, C.len() as u64);
    assert_eq!(complete.sha256, expected_sha256);
    assert_eq!(
        complete.locator,
        format!("blob:{}", blake3::hash(C).to_hex())
    );
}

/// Source: the same `append_locked` replay-identity block cited by case
/// 297/A3-replay and 297/A3-changed, and specifically the LENGTH arm of the
/// `matches_admitted_chunk` conjunction: a replay is accepted only when the
/// recorded `AdmittedChunk` metadata AND the admitted bytes at that chunk's
/// coordinates ALL match, and a disagreement on any one of them is
/// `MismatchedReplay`.
/// Discovery: a transport may re-send a chunk with EXTRA BYTES APPENDED -- the
/// same sequence and offset, but STRICTLY LONGER than what was admitted. Such a
/// replay STARTS WITH the admitted bytes, so it is not a changed chunk, yet it is
/// not the same chunk either: the length arm fails before the byte comparison,
/// so it is refused as `MismatchedReplay` and the append-only evidence object is
/// never silently extended by the extra byte.
/// Executed-pass: one chunk `C` is admitted, then the LONGER `b"chunk-c!"` is
/// offered at the same sequence and offset; the refusal is the exact
/// `MismatchedReplay`, the session view shows both cursors unmoved, and the
/// finalized publication is the ORIGINAL `C`.
/// I10.8.5: the append-only temporary raw evidence object grows once, by the
/// admitted bytes -- an overlapping replay admits no byte of its extra tail.
// WORK_UNIT_CASE: 297/A3-overlap
#[test]
fn overlapping_replay_leaves_state_unchanged() {
    const C: &[u8] = b"chunk-c";
    let (sink, session) = open_replay_sink("overlap");

    assert_disposition(
        ok(append_chunk(&sink, &session, 0, 0, C)),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 1,
            next_offset: C.len() as u64,
        },
    );

    // The same sequence and offset with EXTRA BYTES APPENDED: `b"chunk-c!"` is
    // one byte longer than the admitted `C` and begins with it. The admitted
    // length arm of the replay identity fails on the longer payload, so this is
    // `MismatchedReplay` rather than a silent extension of the evidence object.
    // `replay_limits()` leaves every ceiling far above eight bytes, so the
    // refusal is the replay-identity arm and not a byte-limit arm.
    assert_eq!(
        append_chunk(&sink, &session, 0, 0, b"chunk-c!"),
        Err(ProcessStreamSinkError::MismatchedReplay),
        "a replay that carries more bytes than the admitted chunk is not the same chunk, even when it begins with the admitted bytes"
    );

    // The refused overlap admitted nothing and moved no cursor: the session still
    // counts exactly the one original chunk at its original extent.
    let ProcessStreamSinkReadback::Session { view } = ok(block_on(sink.readback(session.clone())))
    else {
        panic!("an unfinalized session reads back as its session view");
    };
    assert_eq!(view.admitted_chunks(), 1);
    assert_eq!(view.admitted_bytes(), C.len() as u64);
    assert_eq!(view.next_sequence(), 1);
    assert_eq!(view.next_offset(), C.len() as u64);

    let expected_sha256 = format!("{:x}", Sha256::digest(C));
    let request = ok(ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        1,
        C.len() as u64,
        20,
        StreamTransportStatus::Complete,
        expected_sha256.clone(),
        C.len() as u64,
        ok(ProcessStreamPrefixPreview::from_transport_prefix(
            C.to_vec(),
            C.len() as u64,
        )),
        None,
        Vec::new(),
    ));
    let terminal = ok(block_on(sink.finalize(session.clone(), request)));

    assert!(terminal.validate().is_ok());
    assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);
    assert_eq!(terminal.admitted_chunks(), 1);

    // The published object is the ORIGINAL `C`, without the replayed `!`: had the
    // overlapping tail reached the staged plaintext, the length or the digest
    // below would differ.
    let Some(BlobStreamPublication::Complete(complete)) = sink.publication() else {
        panic!("a complete source must record a real object, never `Unavailable`");
    };
    assert_eq!(complete.byte_length, C.len() as u64);
    assert_eq!(complete.sha256, expected_sha256);
    assert_eq!(
        complete.locator,
        format!("blob:{}", blake3::hash(C).to_hex())
    );
}

/// Source: the `SequenceGap` arm of `append_locked`: an append whose sequence
/// is ABOVE `next_sequence` names the exact expected and observed cursors and
/// is refused before any byte is admitted.
/// Discovery: a caller that skips a sequence would otherwise leave a hole in
/// the append-only evidence object that no later append could fill, so the gap
/// is refused with the cursor it expected and the one it saw.
/// Executed-pass: sequence 0 is admitted, then a chunk at sequence 2 is offered
/// -- skipping sequence 1 -- and the error names both cursors; the session view
/// then shows the gap admitted nothing.
// WORK_UNIT_CASE: 297/A3-gap
#[test]
fn sequence_gap_is_refused() {
    const C: &[u8] = b"chunk-c";
    let (sink, session) = open_replay_sink("gap");

    assert_disposition(
        ok(append_chunk(&sink, &session, 0, 0, C)),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 1,
            next_offset: C.len() as u64,
        },
    );

    // Sequence 2 with sequence 1 never admitted. The refusal names the cursor
    // the sink expected (1) and the one the caller offered (2).
    assert_eq!(
        append_chunk(&sink, &session, 2, C.len() as u64, b"chunk-d"),
        Err(ProcessStreamSinkError::SequenceGap {
            expected: 1,
            observed: 2,
        }),
        "a chunk that skips a sequence would leave an unfillable hole in the evidence object"
    );

    // The refused gap admitted nothing and left the cursor where it was, so the
    // skipped sequence is still the next one a caller may append.
    let ProcessStreamSinkReadback::Session { view } = ok(block_on(sink.readback(session.clone())))
    else {
        panic!("an unfinalized session reads back as its session view");
    };
    assert_eq!(view.admitted_chunks(), 1);
    assert_eq!(view.admitted_bytes(), C.len() as u64);
    assert_eq!(view.next_sequence(), 1);
    assert_eq!(view.next_offset(), C.len() as u64);
}

/// Source: `BlobStoreService::new` joins the process-local single-owner registry
/// above `BlobStoreCore::claim`, so a second service on the same root fails with
/// `BlobError::OwnerConflict`.
/// Discovery: the sink harness holds one owner through a cloned handle because
/// a second owner on that root would be refused; here the first service stays
/// bound while the second is refused, never admitted alongside it.
/// Executed-pass: a first service is opened on a unique root and kept alive by
/// `_first`, then a second `BlobStoreService::new` over the same live lease
/// returns exactly `Err(BlobError::OwnerConflict)`.
/// I05-12: vendor-neutral CAS, one active root owner.
// WORK_UNIT_CASE: 297/A8
#[test]
fn second_service_on_same_root_fails_with_owner_conflict() {
    let root = unique_test_root();
    let first_req = stage_request("bootstrap", b"bootstrap", &root);
    // The clone keeps the FIRST service the registry's owner across the second
    // construction below; dropping it would release the root and prove nothing.
    let _first = ok(BlobStoreService::new(
        first_req.root_lease.clone(),
        FixturePlatform::default(),
        FixtureCompression,
        FixtureKeys,
        FixtureAead,
        FixtureLiveSets,
        test_anchor(),
    ));

    // WHY the destructuring rather than `assert_eq!` on the whole `Result`:
    // `BlobStoreService` derives `Clone` only -- no `PartialEq`, no `Debug` -- so
    // the service value is not comparable. The ERROR is (`BlobError` derives
    // `Eq`/`PartialEq`), so the exact refusal is still asserted by value, not by
    // "the call did not succeed".
    let Err(second_error) = BlobStoreService::new(
        first_req.root_lease,
        FixturePlatform::default(),
        FixtureCompression,
        FixtureKeys,
        FixtureAead,
        FixtureLiveSets,
        test_anchor(),
    ) else {
        panic!(
            "a second service owner on the same root is refused, never admitted alongside the first"
        );
    };
    assert_eq!(
        second_error,
        BlobError::OwnerConflict,
        "a second service owner on the same root is refused, never admitted alongside the first"
    );
}

/// Source: `bounded_preview_measure` and `check_preview` in
/// `crates/storage/eliot-blob/src/stream_sink.rs`, and the `max_preview_bytes`
/// ceiling of `ProcessStreamSinkLimits::new` (`types.rs:127`).
/// Discovery: the A5 preview item has two halves and only the EMPTY half was
/// proved, by `empty_source_publishes_and_verifies_as_real_object`. A nonempty
/// source whose bounded preview retains EVERY admitted byte was unproved, so a
/// measure that silently dropped or mis-stated the whole preview would still
/// pass every existing case. This is the COMPLETE-preview half: the session
/// ceiling holds all seven bytes, so no truncation arm is reached and
/// `omitted_ranges` must be empty — a truncated preview may never read as a
/// complete one.
/// Executed-pass: `ALL` (7 bytes) is admitted in TWO chunks, so exactness is
/// proved over a multi-chunk stream rather than a single write; the finalize
/// carries the full retained prefix, and the assertions are the publication's
/// locator, digest, byte count AND the exact bounded-preview measure — never
/// only that `finalize` returned `Ok`.
/// I05-12: vendor-neutral CAS, one active root owner. Blob durability proves
/// bytes only.
// WORK_UNIT_CASE: 297/A5-preview
#[test]
fn nonempty_source_with_complete_preview_publishes_exact_measures() {
    const ALL: &[u8] = b"0123456";
    // `preview-full` yields exactly this case's own disjoint session, source and
    // terminal identities and the `policy:sink-preview-full` binding, over a
    // `unique_test_root` this case owns alone.
    let (sink, session) = open_replay_sink("preview-full");

    // WHY two chunks: a single write would make the incremental preview
    // accumulation and the transport measure trivially equal to the one append,
    // so the exactness below would never be proved ACROSS chunk boundaries.
    assert_disposition(
        ok(append_chunk(&sink, &session, 0, 0, &ALL[..4])),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 1,
            next_offset: 4,
        },
    );
    assert_disposition(
        ok(append_chunk(&sink, &session, 1, 4, &ALL[4..])),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 2,
            next_offset: 7,
        },
    );

    let expected_sha256 = format!("{:x}", Sha256::digest(ALL));
    let request = ok(ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        2,
        ALL.len() as u64,
        20,
        StreamTransportStatus::Complete,
        expected_sha256.clone(),
        ALL.len() as u64,
        // The FULL retained prefix: the session ceiling holds every byte, so
        // this request preview matches the adapter's own incremental
        // accumulation exactly and `check_preview` passes.
        ok(ProcessStreamPrefixPreview::from_transport_prefix(
            ALL.to_vec(),
            ALL.len() as u64,
        )),
        None,
        Vec::new(),
    ));
    let terminal = ok(block_on(sink.finalize(session.clone(), request)));

    assert!(terminal.validate().is_ok());
    assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);
    assert_eq!(terminal.admitted_chunks(), 2);
    assert_eq!(terminal.admitted_bytes(), 7);
    assert_eq!(terminal.admitted_sha256(), expected_sha256);

    // The published object is exactly `ALL`, so the two-chunk admission minted
    // ONE object carrying the whole source and not a per-chunk object.
    let Some(BlobStreamPublication::Complete(complete)) = sink.publication() else {
        panic!("a complete source must record a real object, never `Unavailable`");
    };
    assert_eq!(complete.byte_length, 7);
    assert_eq!(complete.sha256, expected_sha256);
    assert_eq!(
        complete.locator,
        format!("blob:{}", blake3::hash(ALL).to_hex()),
        "the published locator is the content hash of the bytes this case admitted"
    );

    // The measure itself, not merely a successful finalize: the preview retains
    // all seven bytes, represents all seven bytes, omits nothing, and its
    // TransportBytes digest covers exactly the retained bytes.
    assert_eq!(complete.measures.bounded_preview.retained_byte_count, 7);
    assert_eq!(complete.measures.bounded_preview.represented_byte_count, 7);
    assert!(
        complete.measures.bounded_preview.omitted_ranges.is_empty(),
        "a preview that retains every admitted byte omits nothing, so a truncated \
         preview can never read as a complete one: {:?}",
        complete.measures.bounded_preview.omitted_ranges
    );
    assert_eq!(complete.measures.bounded_preview.sha256, expected_sha256);
}

/// Source: the #297 append-only staged-object path (`abort_async` /
/// `retain_aborted_prefix` in `src/stream_sink.rs`): a cancellation,
/// caller-shutdown or transport-failure abort with a nonempty admitted prefix
/// stages the exact prefix through the owner under the bound root lease, reads
/// it back, and mints `PartialSource` with its locator, length and digest —
/// never a memory buffer relabelled as durable.
/// Discovery: before this path the adapter minted no partial-durable-prefix
/// value at all, so an aborted stream's admitted bytes survived only in the
/// dying process. A locator that named no owner-staged object would be exactly
/// the "locator substitutes for owner evidence" defect the audit rejects, so
/// the locator, length and digest are asserted against the owner-backed
/// publication AND the terminal evidence, never only that `abort` returned
/// `Ok`.
/// Executed-pass: two chunks (17 bytes) are admitted, then a `Cancellation`
/// abort naming the `CancelledBeforeEof` coverage gap keeps the admitted
/// prefix: the terminal state, counters, evidence source and recorded
/// publication below all name the same retained object.
/// I10-08-05: the append-only temporary raw evidence object outlives the
/// aborted session as a real immutable object.
// WORK_UNIT_CASE: 297/W3
#[test]
fn cancelled_abort_retains_admitted_prefix_as_durable_partial_source() {
    const PREFIX: &[u8] = b"abort-partial-297";
    let prefix_len = PREFIX.len() as u64;
    let (sink, session) = open_replay_sink("abort-partial");

    assert_disposition(
        ok(append_chunk(&sink, &session, 0, 0, &PREFIX[..8])),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 1,
            next_offset: 8,
        },
    );
    assert_disposition(
        ok(append_chunk(&sink, &session, 1, 8, &PREFIX[8..])),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 2,
            next_offset: prefix_len,
        },
    );

    let expected_sha256 = format!("{:x}", Sha256::digest(PREFIX));
    let request = ok(ProcessStreamSinkAbortRequest::new(
        session.terminal_id().clone(),
        ProcessStreamSinkAbortReason::Cancellation,
        2,
        prefix_len,
        10,
        StreamTransportStatus::CancelledBeforeEof,
        expected_sha256.clone(),
        prefix_len,
        ok(ProcessStreamPrefixPreview::from_transport_prefix(
            PREFIX.to_vec(),
            prefix_len,
        )),
        None,
        vec![StreamEvidenceGap::CancelledBeforeEof],
    ));
    let terminal = ok(block_on(sink.abort(session.clone(), request)));

    assert!(terminal.validate().is_ok());
    assert_eq!(terminal.state(), ProcessStreamSinkState::PartialSource);
    assert_eq!(terminal.admitted_bytes(), prefix_len);
    assert_eq!(terminal.admitted_sha256(), expected_sha256);

    // The locator names the owner-staged object: the blob content hash of the
    // exact admitted bytes, with the same length and digest the terminal
    // carries. The evidence source and the recorded publication must agree —
    // either one alone could be an unbacked claim.
    let expected_locator = format!("blob:{}", blake3::hash(PREFIX).to_hex());
    let source = terminal
        .evidence()
        .source()
        .expect("a partial terminal keeps its retained source");
    assert_eq!(source.locator(), expected_locator);
    assert_eq!(source.sha256(), expected_sha256);
    assert_eq!(source.byte_length(), prefix_len);
    let Some(BlobStreamPublication::Partial(partial)) = sink.publication() else {
        panic!("a retaining abort must record a real prefix object, never `Unavailable`");
    };
    assert_eq!(partial.locator, expected_locator);
    assert_eq!(partial.byte_length, prefix_len);
    assert_eq!(partial.sha256, expected_sha256);
}

/// Source: `withheld_plan` (`src/stream_sink.rs:1683`) and the no-retention
/// abort arm: a gapped, policy-prohibited or failed-redaction finalize mints
/// a withheld terminal, and a prohibition/redaction abort mints its terminal
/// — in NEITHER case may a stage call run, so no raw bytes reach the owner.
/// Discovery: the W3 retention path stages on purpose, which makes the
/// negative proof load-bearing rather than vacuous: the same adapter that
/// retains a cancelled prefix must still stage NOTHING for a prohibited one,
/// and "no stage ran" is observed on the platform write counters, not
/// inferred from the terminal state.
/// Executed-pass: two sessions admit the same bytes; a `PolicyProhibited`
/// finalize and a `RedactionFailure` abort each land their exact terminal and
/// reason, and the durable write counters do not move across either command.
/// I05-12: one active root owner; prohibition is enforced before any effect.
// WORK_UNIT_CASE: 297/A6
#[test]
fn prohibition_and_redaction_failure_stage_nothing() {
    const SECRET: &[u8] = b"must-never-stage";
    let secret_len = SECRET.len() as u64;
    let expected_sha256 = format!("{:x}", Sha256::digest(SECRET));

    // Finalize half: a policy-prohibited finalize withholds, never publishes.
    let (platform, _, sink, session) = open_observed_sink("policy-deny");
    assert_disposition(
        ok(append_chunk(&sink, &session, 0, 0, &SECRET[..8])),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 1,
            next_offset: 8,
        },
    );
    assert_disposition(
        ok(append_chunk(&sink, &session, 1, 8, &SECRET[8..])),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 2,
            next_offset: secret_len,
        },
    );
    let before = durable_write_counts(&platform);
    let finalize = ok(ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        2,
        secret_len,
        10,
        StreamTransportStatus::Complete,
        expected_sha256.clone(),
        secret_len,
        ProcessStreamPrefixPreview::withheld_by_policy(),
        None,
        vec![StreamEvidenceGap::PolicyProhibited],
    ));
    let terminal = ok(block_on(sink.finalize(session.clone(), finalize)));
    assert!(terminal.validate().is_ok());
    assert_eq!(terminal.state(), ProcessStreamSinkState::PolicyProhibited);
    assert_eq!(
        sink.publication(),
        Some(BlobStreamPublication::Unavailable {
            reason: BlobStreamUnavailableReason::PolicyProhibited,
        }),
        "a prohibited finalize records no object, only its cause"
    );
    assert_eq!(
        durable_write_counts(&platform),
        before,
        "a prohibited finalize issues no durable write: no stage ran"
    );

    // Abort half: a failed-redaction abort mints its terminal, stages nothing.
    let (platform, _, sink, session) = open_observed_sink("redaction-deny");
    assert_disposition(
        ok(append_chunk(&sink, &session, 0, 0, SECRET)),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 1,
            next_offset: secret_len,
        },
    );
    let before = durable_write_counts(&platform);
    // Transport is `Complete`: every byte arrived and the failure is the
    // redaction step, not the pipe. A transport gap here would contradict the
    // declared `RedactionFailed` coverage gap (each non-complete transport
    // status demands its own gap).
    let abort = ok(ProcessStreamSinkAbortRequest::new(
        session.terminal_id().clone(),
        ProcessStreamSinkAbortReason::RedactionFailure,
        1,
        secret_len,
        10,
        StreamTransportStatus::Complete,
        expected_sha256.clone(),
        secret_len,
        ProcessStreamPrefixPreview::withheld_by_policy(),
        None,
        vec![StreamEvidenceGap::RedactionFailed],
    ));
    let terminal = ok(block_on(sink.abort(session.clone(), abort)));
    assert!(terminal.validate().is_ok());
    assert_eq!(terminal.state(), ProcessStreamSinkState::RedactionFailed);
    assert_eq!(
        sink.publication(),
        Some(BlobStreamPublication::Unavailable {
            reason: BlobStreamUnavailableReason::RedactionFailed,
        }),
        "a failed-redaction abort records no object, only its cause"
    );
    assert_eq!(
        durable_write_counts(&platform),
        before,
        "a failed-redaction abort issues no durable write: no stage ran"
    );
}

/// Source: `reconcile_async` + `record_locked` (`src/stream_sink.rs`): a
/// same-identity finalize replay resolves the recorded terminal instead of
/// minting a second object, and a reconcile without the retained reservation
/// proof refuses instead of inventing a terminal.
/// Discovery: after an interruption the only honest resume is the retained
/// command re-driven against the retained proof. Re-running the same finalize
/// must therefore settle on the SAME object (same locator, same terminal
/// digest, no second stage), while a brand-new adapter — same owner, same
/// store, but no reservation and no uncertainty proof — must never answer
/// `COMPLETE_SOURCE`: its readback is a session view and its reconcile is a
/// refusal.
/// Executed-pass: one session publishes, then finalizes the identical request
/// again (same terminal, same locator, no new durable write); a second
/// adapter on the same store then opens a fresh session, reads back a bare
/// session view, and fails a fabricated-uncertainty reconcile with
/// `ProviderUnavailable`.
/// I05-12: one active root owner; the owner still holds the object, but the
/// adapter claims only what it retained.
// WORK_UNIT_CASE: 297/A7
#[test]
fn repeat_finalize_reuses_object_and_fresh_adapter_holds_no_proof() {
    const ALL: &[u8] = b"a7-restart";
    let all_len = ALL.len() as u64;
    let expected_sha256 = format!("{:x}", Sha256::digest(ALL));

    // Half one: publish through the first adapter on its own owner.
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    let platform_handle = platform.clone();
    let store = store_with_platform(platform, &root);
    let (sink, session) = open_sink_on_store("restart-pub", &root, store.clone());
    assert_disposition(
        ok(append_chunk(&sink, &session, 0, 0, &ALL[..4])),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 1,
            next_offset: 4,
        },
    );
    assert_disposition(
        ok(append_chunk(&sink, &session, 1, 4, &ALL[4..])),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 2,
            next_offset: all_len,
        },
    );
    let finalize = || {
        ok(ProcessStreamSinkFinalizeRequest::new(
            session.terminal_id().clone(),
            2,
            all_len,
            10,
            StreamTransportStatus::Complete,
            expected_sha256.clone(),
            all_len,
            ok(ProcessStreamPrefixPreview::from_transport_prefix(
                ALL.to_vec(),
                all_len,
            )),
            None,
            Vec::new(),
        ))
    };
    let first = ok(block_on(sink.finalize(session.clone(), finalize())));
    assert_eq!(first.state(), ProcessStreamSinkState::CompleteSource);
    let locator = match sink.publication() {
        Some(BlobStreamPublication::Complete(complete)) => complete.locator.clone(),
        other => panic!("a published source records its object, got {other:?}"),
    };

    // The identical finalize replays the recorded terminal: same digest, same
    // locator, and — observed on the shared platform — no second stage.
    let before = durable_write_counts(&platform_handle);
    let second = ok(block_on(sink.finalize(session.clone(), finalize())));
    assert_eq!(
        durable_write_counts(&platform_handle),
        before,
        "a same-identity replay stages nothing: the object already exists"
    );
    assert_eq!(
        second.terminal_sha256(),
        first.terminal_sha256(),
        "a same-identity finalize replay resolves the recorded terminal"
    );
    match sink.publication() {
        Some(BlobStreamPublication::Complete(complete)) => assert_eq!(
            complete.locator, locator,
            "the replay reuses the one published object, never a second one"
        ),
        other => panic!("the publication still names its object, got {other:?}"),
    }

    // Half two: a brand-new adapter on the SAME store holds no proof. Its
    // session is bare, its readback is a session view, and a reconcile
    // carrying a fabricated uncertainty — well-formed and bound to this
    // session, but never issued by any reservation — is refused instead of
    // inventing a `COMPLETE_SOURCE` terminal.
    let (fresh_sink, fresh_session) = open_sink_on_store("restart-clean", &root, store.clone());
    assert!(
        fresh_sink.publication().is_none(),
        "a new adapter retains no publication outcome"
    );
    let ProcessStreamSinkReadback::Session { view } =
        ok(block_on(fresh_sink.readback(fresh_session.clone())))
    else {
        panic!("a proof-less session reads back as its session view, never a terminal");
    };
    assert_eq!(view.admitted_bytes(), 0);
    let fabricated = ok(ProcessStreamSinkUnknownOutcome::new(
        fresh_session.session_id().clone(),
        fresh_session.terminal_id().clone(),
        fresh_session.open_request_sha256().to_owned(),
        "e".repeat(64),
    ));
    assert_eq!(
        block_on(fresh_sink.reconcile(fresh_session.clone(), fabricated)),
        Err(ProcessStreamSinkError::ProviderUnavailable),
        "no retained reservation means no reconcile, never a synthesized terminal"
    );
}

/// Source: `PersistenceQueueBound` + the latched overflow (`src/stream_sink.rs`)
/// and the terminal-identity fencing in `abort_snapshot`/`record_locked`: a
/// full persistence queue REFUSES the append with `Backpressured` instead of
/// blocking, sheds every later append too, stages nothing, and a terminal
/// command that arrives after the terminal recorded conflicts instead of
/// minting a second outcome.
/// Discovery: without the latch a fast producer could grind through a full
/// queue by retrying and stall the drain; without the fencing a late abort
/// could rename the recorded outcome. The shed bytes must therefore be absent
/// from the published object (not merely refused at the door), and the late
/// abort must leave the recorded publication, terminal and platform exactly
/// as they were.
/// Executed-pass: under a two-chunk / 250-byte in-flight ceiling two chunks
/// are accepted, the third and fourth shed with `retry_after_ms: 0`, the
/// cursor never moves past the admitted two, and the finalize publishes
/// exactly those two chunks. A `Cancellation` abort naming the recorded
/// terminal id then conflicts, and nothing — publication, terminal digest,
/// platform writes — moves.
/// I05-12: one active root owner; pressure is refused, never queued.
// WORK_UNIT_CASE: 297/A4
#[test]
fn pressure_sheds_without_stalling_and_late_abort_conflicts() {
    const KEPT: &[u8] = b"kept-297-16-bytes!";
    const SHED: &[u8] = b"shed-297-16-bytes!";
    assert_eq!(KEPT.len(), 18);
    assert_eq!(SHED.len(), 18);
    // Two 9-byte chunks charge 2 * (32 + 64 + 9) = 210 bytes against the
    // 250-byte in-flight ceiling, so both fit; the third would reach 315 and
    // sheds. KEPT is exactly the two admitted chunks.
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    let platform_handle = platform.clone();
    let store = store_with_platform(platform, &root);
    let limits = ok(ProcessStreamSinkLimits::new(
        64, 4096, 8, 4096, 2, 250, 10, 20, 20,
    ));
    let (sink, session) = open_sink_on_store_with_limits("pressure", &root, store, limits);

    assert_disposition(
        ok(append_chunk(&sink, &session, 0, 0, &KEPT[..9])),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 1,
            next_offset: 9,
        },
    );
    assert_disposition(
        ok(append_chunk(&sink, &session, 1, 9, &KEPT[9..])),
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 2,
            next_offset: 18,
        },
    );
    // The queue is full: this append and every retry at the live cursor shed
    // with a zero hint — a refusal per chunk, never a block (the latch, not
    // the sequence check, sheds them: coordinates stay at the live cursor, so
    // no `SequenceGap` fires first). The cursor stays where the admitted
    // bytes left it.
    for _ in 0..3 {
        assert_eq!(
            append_chunk(&sink, &session, 2, 18, SHED),
            Ok(ProcessStreamSinkAppendDisposition::Backpressured { retry_after_ms: 0 }),
            "a full queue refuses without blocking and without advancing"
        );
    }
    let ProcessStreamSinkReadback::Session { view } = ok(block_on(sink.readback(session.clone())))
    else {
        panic!("an unfinalized pressured session reads back as its session view");
    };
    assert_eq!(view.admitted_chunks(), 2);
    assert_eq!(view.admitted_bytes(), 18);
    assert_eq!(view.next_sequence(), 2);
    assert_eq!(view.next_offset(), 18);

    // The finalize publishes exactly the admitted prefix: the shed bytes are
    // absent from the object, not merely refused at the door.
    let expected_sha256 = format!("{:x}", Sha256::digest(KEPT));
    let finalize = ok(ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        2,
        18,
        10,
        StreamTransportStatus::Complete,
        expected_sha256.clone(),
        18,
        ok(ProcessStreamPrefixPreview::from_transport_prefix(
            KEPT.to_vec(),
            18,
        )),
        None,
        Vec::new(),
    ));
    let terminal = ok(block_on(sink.finalize(session.clone(), finalize)));
    assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);
    match sink.publication() {
        Some(BlobStreamPublication::Complete(complete)) => {
            assert_eq!(complete.byte_length, 18);
            assert_eq!(complete.sha256, expected_sha256);
        }
        other => panic!("pressure must not lose the admitted prefix, got {other:?}"),
    }
    let recorded = terminal.terminal_sha256().to_owned();
    let before = durable_write_counts(&platform_handle);

    // Race half: a `Cancellation` abort that arrives after the terminal
    // recorded names the same terminal id with a different command kind, so
    // it conflicts — and moves nothing behind it.
    let abort = ok(ProcessStreamSinkAbortRequest::new(
        session.terminal_id().clone(),
        ProcessStreamSinkAbortReason::Cancellation,
        2,
        18,
        10,
        StreamTransportStatus::CancelledBeforeEof,
        expected_sha256.clone(),
        18,
        ok(ProcessStreamPrefixPreview::from_transport_prefix(
            KEPT.to_vec(),
            18,
        )),
        None,
        vec![StreamEvidenceGap::CancelledBeforeEof],
    ));
    assert_eq!(
        block_on(sink.abort(session.clone(), abort)),
        Err(ProcessStreamSinkError::TerminalIdentityConflict),
        "a terminal command after the recorded one conflicts, never renames it"
    );
    assert_eq!(
        terminal.terminal_sha256(),
        recorded,
        "the recorded terminal is untouched by the late abort"
    );
    assert_eq!(
        durable_write_counts(&platform_handle),
        before,
        "a conflicted abort stages nothing behind the recorded terminal"
    );
}

/// Source: the four injected seams (`BlobCompressionPort`, `BlobKeyPort`,
/// `BlobAeadPort`, `BlobPlatformPort`) driven through `BlobStoreService::new`
/// (`src/lib.rs`), with the platform leg on a real temp directory
/// (`DirPlatform`, this file).
/// Discovery: every sink case above runs all five seams, but always the same
/// single fake behaviour behind each one — one codec identity, one key
/// generation, one envelope, one memory platform. A seam that is never varied
/// is a seam the suite assumes rather than proves, and a platform that never
/// touches a disk proves nothing about the bytes' durable form. So this case
/// varies each seam across at least two behaviours AND puts the platform leg
/// on real files: the codec roundtrips, the key port pins generation 3 as
/// current and echoes generation 9 on resolve, the AEAD seals (marker +
/// plaintext, never plaintext) and rejects unmarked bytes, and the same bytes
/// staged through the memory platform and through the directory platform
/// settle the same content digest.
/// Executed-pass: port-level pins for codec/keys/AEAD, then one stage of the
/// same bytes on each platform; the directory leg asserts the sealed payload
/// file exists on disk (marker-prefixed, never plaintext), the owner read
/// returns exactly the staged bytes, and both legs agree on the digest.
/// I05-12: one active root owner per store; the directory root is a unique
/// temp case root removed at the end.
// WORK_UNIT_CASE: 297/A2
#[test]
fn seam_matrix_stages_and_reads_through_a_real_directory() {
    const BYTES: &[u8] = b"a2-matrix-real-fs-297";
    let byte_len = BYTES.len() as u64;
    let expected_sha256 = format!("{:x}", Sha256::digest(BYTES));

    // Codec seam: identity roundtrip under its named algorithm.
    let mut codec = FixtureCompression;
    let descriptor = ok(codec.descriptor());
    assert_eq!(ok(codec.compress(BYTES)), BYTES);
    assert_eq!(
        ok(codec.decompress_bounded(&descriptor, BYTES, 1024)),
        BYTES
    );

    // Key seam: generation 3 is current; resolve echoes any generation with
    // the same lineage, so rotation changes the selection, never the shape.
    let mut keys = FixtureKeys;
    let current = ok(keys.current());
    assert_eq!(current.crypto.key_generation, 3);
    let rotated = ok(keys.resolve(&CryptoDescriptor {
        algorithm: ok(BlobId::new("test-only-authenticated-envelope")),
        version: 1,
        key_lineage: ok(BlobId::new("test-lineage")),
        key_generation: 9,
    }));
    assert_eq!(rotated.crypto.key_generation, 9);
    assert_eq!(rotated.crypto.key_lineage, current.crypto.key_lineage);

    // AEAD seam: seal prepends the marker (never plaintext on the wire) and
    // unmarked bytes fail to open.
    let mut aead = FixtureAead;
    let sealed = ok(aead.seal(AeadSealRequest {
        key: &current,
        nonce_context: b"a2-matrix",
        associated_data: b"a2-matrix",
        plaintext: BYTES,
    }));
    assert_ne!(sealed, BYTES, "sealed bytes are never the plaintext");
    assert_eq!(&sealed[..1], &[0x01], "the envelope marker leads");
    assert_eq!(
        ok(aead.open(AeadOpenRequest {
            key: &current,
            nonce_context: b"a2-matrix",
            associated_data: b"a2-matrix",
            ciphertext: &sealed,
        })),
        BYTES
    );
    assert_eq!(
        aead.open(AeadOpenRequest {
            key: &current,
            nonce_context: b"a2-matrix",
            associated_data: b"a2-matrix",
            ciphertext: BYTES,
        }),
        Err(BlobError::IntegrityMismatch),
        "unmarked bytes never open as an envelope"
    );

    // Platform seam, memory leg: the same bytes through the memory platform.
    let root = unique_test_root();
    let mem_store = store_with_platform(FixturePlatform::default(), &root);
    let mem_ready = ok(block_on(mem_store.stage(stage_request(
        "a2-matrix",
        BYTES,
        &root,
    ))));

    // Platform seam, directory leg: a second store on the same seams except
    // the platform, whose root is a real temp directory.
    let dir = std::env::temp_dir().join(format!(
        "eliot-297-a2-{}-{}",
        std::process::id(),
        TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    // A second store on the same root would raise `OwnerConflict` (A8): the
    // directory leg owns a sibling root with its own lease.
    let dir_root = format!("{root}-dir");
    let bootstrap = stage_request("bootstrap", b"bootstrap", &dir_root);
    let store = ok(BlobStoreService::new(
        bootstrap.root_lease,
        DirPlatform {
            root: dir.clone(),
            claim: Arc::new(Mutex::new(None)),
        },
        FixtureCompression,
        FixtureKeys,
        FixtureAead,
        FixtureLiveSets,
        test_anchor(),
    ));
    let ready = ok(block_on(store.stage(stage_request(
        "a2-realfs",
        BYTES,
        &dir_root,
    ))));
    assert_eq!(ready.plaintext_sha256(), expected_sha256);
    assert_eq!(ready.plaintext_length(), byte_len);
    assert_eq!(
        ready.locator(),
        mem_ready.locator(),
        "content identity does not depend on the platform behind the store"
    );

    // The sealed payload reached real files: some file under the case root
    // holds exactly marker + plaintext, and NO file holds the plaintext.
    let mut sealed_on_disk = false;
    let mut plaintext_on_disk = false;
    let mut pending = vec![dir.clone()];
    while let Some(next) = pending.pop() {
        for entry in ok(std::fs::read_dir(&next)) {
            let entry = ok(entry);
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let bytes = ok(std::fs::read(&path));
            sealed_on_disk = sealed_on_disk || bytes == sealed;
            plaintext_on_disk = plaintext_on_disk || bytes == BYTES;
        }
    }
    assert!(
        sealed_on_disk,
        "the staged payload reached the directory sealed, marker first"
    );
    assert!(
        !plaintext_on_disk,
        "the plaintext itself never reaches the directory"
    );

    // Owner readback through the directory platform returns exactly the
    // staged bytes.
    let read_context: BlobReceiptContext = ok(serde_json::from_str(&context_json(
        "READ",
        "sink-a2-read",
        "request-sink-a2-read",
    )));
    let chunk = ok(block_on(store.read(BlobReadRequest {
        context: read_context,
        root_lease: lease_for(&receipt_context("sink-a2-read"), &dir_root),
        locator: ready.locator().clone(),
        expected_metadata_sha256: ready.metadata_sha256().to_owned(),
        expected_ready_receipt_id: ready.receipt().identity.receipt_id.to_string(),
        max_bytes: byte_len,
    })));
    assert!(chunk.validate().is_ok());
    assert_eq!(chunk.bytes(), BYTES);

    ok(std::fs::remove_dir_all(&dir));
}

/// Source: `BoundedPreviewDigest::absorb` + `check_preview`
/// (`src/stream_sink.rs`): a source longer than the session preview ceiling
/// finalizes with an HONEST truncated preview — the retained head window the
/// accumulator kept, the full represented length, and the explicit omitted
/// suffix range — never a refused finalize and never a preview that claims
/// bytes it does not hold.
/// Discovery: the accumulator used to release the retained bytes the moment
/// the ceiling was hit while its digest kept growing over everything, so the
/// only preview that could ever finalize was the complete one — and any
/// source longer than the ceiling (which `max_total_admitted_bytes` allows to
/// be far longer than `max_preview_bytes`) was unfinalizable. The port model
/// already describes exactly this shape (`omitted_suffix`: retained head plus
/// an explicit omitted suffix), so the adapter keeps the head window and its
/// digest covers exactly that window; `check_preview` then matches the
/// request against the kept window, and the measures state the omission
/// instead of hiding it.
/// Executed-pass: 64 bytes are admitted under a 16-byte preview ceiling, then
/// finalized with the 16-byte head preview for all 64: the terminal is
/// `CompleteSource`, the measures retain 16, represent 64, omit exactly
/// `[16, 64)`, and digest exactly the retained head — while the transport and
/// the published object still cover all 64.
/// I05-12: one active root owner; the ceiling comes from the pinned session
/// limits, so the window the caller must present is the window the session
/// states.
// WORK_UNIT_CASE: 297/A5
#[test]
fn truncated_preview_finalizes_with_honest_omitted_suffix() {
    const ALL: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert_eq!(ALL.len(), 64);
    const HEAD: usize = 16;
    let root = unique_test_root();
    let platform = FixturePlatform::default();
    let store = store_with_platform(platform, &root);
    let limits = ok(ProcessStreamSinkLimits::new(
        64, 8192, 256, 16, 8, 8192, 10, 20, 20,
    ));
    let (sink, session) = open_sink_on_store_with_limits("truncated-preview", &root, store, limits);
    for sequence in 0..8 {
        let start = (sequence * 8) as usize;
        assert_disposition(
            ok(append_chunk(
                &sink,
                &session,
                sequence as u64,
                (start) as u64,
                &ALL[start..start + 8],
            )),
            ProcessStreamSinkAppendDisposition::Accepted {
                next_sequence: sequence as u64 + 1,
                next_offset: (start + 8) as u64,
            },
        );
    }

    let expected_sha256 = format!("{:x}", Sha256::digest(ALL));
    let expected_head_sha256 = format!("{:x}", Sha256::digest(&ALL[..HEAD]));
    let finalize = ok(ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        8,
        64,
        10,
        StreamTransportStatus::Complete,
        expected_sha256.clone(),
        64,
        ok(ProcessStreamPrefixPreview::from_transport_prefix(
            ALL[..HEAD].to_vec(),
            64,
        )),
        None,
        Vec::new(),
    ));
    let terminal = ok(block_on(sink.finalize(session.clone(), finalize)));
    assert!(terminal.validate().is_ok());
    assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);

    // The published object still covers all 64 admitted bytes: truncation
    // touches the preview measures only, never the source.
    let complete = match sink.publication() {
        Some(BlobStreamPublication::Complete(complete)) => complete,
        other => panic!("a truncated preview still publishes its source, got {other:?}"),
    };
    assert_eq!(complete.byte_length, 64);
    assert_eq!(complete.sha256, expected_sha256);
    assert_eq!(
        complete.locator,
        format!("blob:{}", blake3::hash(ALL).to_hex()),
        "the published locator is the content hash of all admitted bytes"
    );

    // The measures state the omission instead of hiding it: 16 retained of 64
    // represented, exactly the suffix [16, 64) omitted, digested over exactly
    // the retained head.
    assert_eq!(complete.measures.bounded_preview.retained_byte_count, 16);
    assert_eq!(complete.measures.bounded_preview.represented_byte_count, 64);
    assert_eq!(complete.measures.bounded_preview.omitted_ranges.len(), 1);
    assert_eq!(
        complete.measures.bounded_preview.omitted_ranges[0].start(),
        16
    );
    assert_eq!(
        complete.measures.bounded_preview.omitted_ranges[0].end_exclusive(),
        64
    );
    assert_eq!(
        complete.measures.bounded_preview.sha256,
        expected_head_sha256
    );
}
