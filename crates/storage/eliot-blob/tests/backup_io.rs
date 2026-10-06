//! Sealed-blob backup and restore behavior for ELIOT issue #956.
//!
//! Declared denominator: the F5/F6 integration file the audit requires —
//! twenty substantive executable cases T1-T20 plus the `tests/data/backup-io`
//! manifest fixtures. One test per audit item; each test binds its source
//! (the `eliot-blob`/`eliot-blob-api` backup seam as it stands in this
//! working tree), its discovery (deterministic in-memory owner ports and the
//! manifest fixtures below), and its executed-pass result (real assertions
//! against live seam behavior through the public port traits, never
//! count-only).
//!
//! Item map (audit `issues/956/ISSUE-AUDIT.md`, norm
//! `docs/architecture/I05-13-backup-and-restore.md:42` — equal bytes under
//! different obligations remain distinct logical objects):
//! T1 canonical capture denominator | T2 cross-domain separation |
//! T3 generation-mismatch refusal | T4 lease/path guards |
//! T5 source replacement mid-run | T6 contiguous page cover |
//! T7 envelope bindings | T8 unavailable key vs auth failure |
//! T9 no plaintext in diagnostics | T10 bounds, one-over, truncation |
//! T11 foreign destination refusal | T12 no post-purge resurrect |
//! T13 conditional publication | T14 replay and conflict |
//! T15 same-operation reconciliation | T16 typed member states |
//! T17 prefix and resume index | T18 owned cleanup |
//! T19 filesystem fixture round-trip | T20 second-owner guard.
//!
//! Production path: the Blob owner's sealed-read entry
//! (`BlobStoreService::read_sealed` -> `SealedBlobRead::from_verified`,
//! `crates/storage/eliot-blob/src/lib.rs`) is the live export half; the
//! capture driver here (`run_capture`) seals through the same real key/AEAD
//! owner ports and hands per-residency evidence to the F restore lane
//! (`bins/eliot-kernel/src/backup_restore.rs`, issue #959, downstream
//! consumer — not a block). No test touches another owner's modules.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use eliot_blob::{
    AeadOpenRequest, AeadSealRequest, BackupCleanupPort, BackupMemberState, BackupPlaintextSource,
    BackupSealedSink, BlobAeadPort, BlobError, BlobKeyPort, BlobKeySelection, CaptureOutcome,
    CapturePorts, DispositionCleanup, DispositionDurability, DispositionValidation, ExportedPage,
    MemberDisposition, ResidencyDisposition, RestoreBinding, SealedMember, bind_restore_set,
    complete_export, export_page, open_member, run_capture, seal_associated_data, seal_member,
    seal_nonce_context, verify_destination_scope,
};
use eliot_blob_api::{
    BlobBackupCompletionReceipt, BlobBackupFence, BlobBackupPage, BlobBackupPartial,
    BlobBackupScope, BlobHash, BlobId, BlobLocator, BlobReceiptContext, BlobRootLease,
    CryptoDescriptor, ObjectResidencyKey, PageCompletion, SealedBlobCaptureRecord,
    VersionedContentDigest,
};
use sha2::{Digest, Sha256};

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn sha_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// The root generation every lease and locator in this suite is minted with.
const ROOT_GENERATION: u64 = 7;
/// The key lineage the fake owner holds and every test residency admits.
const LINEAGE: &str = "test-lineage";

fn context_json(operation: &str) -> String {
    let epoch = r#"{"lineage_id":"550e8400-e29b-41d4-a716-446655440000","sequence":4}"#;
    let fence = format!(
        "{{\"authority_epoch\":{epoch},\"resource_generation\":7,\"task_revision\":null,\"policy_revision\":null,\"integration_revision\":null}}"
    );
    let metadata = format!(
        r#"{{"request_id":"request-{operation}","session_id":null,"task_id":null,"product_id":"product-1","source_id":"source-1","state_fence":{fence},"clock":{{"valid_time_ms":1,"known_time_ms":1,"transaction_sequence":null,"monotonic_ns":1}}}}"#
    );
    format!(
        r#"{{"work_scope":{{"scope_id":"scope-1","product_id":"product-1","resource_generation":7,"state_fence":{fence}}},"task":null,"session":null,"causal":{{"state_fence":{fence},"transaction_sequence":1,"parent_receipt_id":null,"predecessor_receipt_ids":[]}},"request":{{"metadata":{metadata},"state_fence":{fence}}},"operation":{{"operation_id":"{operation}","request_id":"request-{operation}","idempotency_key":"idem-1","operation_kind":"blob-backup-test","effect":"REVERSIBLE_MUTATION","state_fence":{fence}}},"authority":{{"authority_id":"authority-1","authority_owner":"test-owner","authority_epoch":{epoch},"state_fence":{fence},"allowed_effect":"REVERSIBLE_MUTATION","proof_ceiling":"OBSERVED_EXTERNAL_EFFECT"}}}}"#
    )
}

fn receipt_context(operation: &str) -> BlobReceiptContext {
    ok(serde_json::from_str(&context_json(operation)))
}

fn lease_for(context: &BlobReceiptContext, root: &str, owner: &str) -> BlobRootLease {
    ok(serde_json::from_value(serde_json::json!({
        "root_id": root,
        "owner_id": owner,
        "lease_id": "lease-1",
        "root_generation": ROOT_GENERATION,
        "fence_binding": context.request,
    })))
}

fn residency_for(content: &[u8], scope_domain: &str) -> (BlobHash, ObjectResidencyKey) {
    let hash = ok(BlobHash::new(blake3::hash(content).to_hex().to_string()));
    let key = ObjectResidencyKey {
        scope_domain_id: ok(BlobId::new(scope_domain)),
        access_domain_id: ok(BlobId::new("access-test")),
        confidentiality_domain_id: ok(BlobId::new("conf-test")),
        encryption_key_domain_id: ok(BlobId::new(LINEAGE)),
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

fn locator_for(content: &[u8], scope_domain: &str) -> BlobLocator {
    let (hash, residency) = residency_for(content, scope_domain);
    BlobLocator {
        hash,
        residency,
        root_generation: ROOT_GENERATION,
        path_generation: 1,
    }
}

fn test_crypto() -> CryptoDescriptor {
    CryptoDescriptor {
        algorithm: ok(BlobId::new("seal-alg")),
        version: 1,
        key_lineage: ok(BlobId::new(LINEAGE)),
        key_generation: 3,
    }
}

/// The single destination admission every happy-path run stages into.
struct Admission {
    source_lease: BlobRootLease,
    lease: BlobRootLease,
    crypto: CryptoDescriptor,
    residency: ObjectResidencyKey,
    scope: BlobBackupScope,
}

fn admission() -> Admission {
    let context = receipt_context("backup-op-1");
    let source_lease = lease_for(&context, "root-source", "owner-1");
    let lease = lease_for(&context, "root-dest", "owner-1");
    let crypto = test_crypto();
    let (_, residency) = residency_for(b"dest-marker", "scope-dest");
    let scope = ok(BlobBackupScope::issue(&lease, &crypto, &residency));
    Admission {
        source_lease,
        lease,
        crypto,
        residency,
        scope,
    }
}

/// Fake key owner: holds exactly one lineage; foreign or refused lineages
/// fail with `ProviderUnavailable` — never invented success.
struct FakeKeyPort {
    lineage: String,
    refuse_current: bool,
    refuse_resolve: bool,
}

impl FakeKeyPort {
    fn holder() -> Self {
        Self {
            lineage: LINEAGE.to_owned(),
            refuse_current: false,
            refuse_resolve: false,
        }
    }

    fn selection(&self, generation: u64) -> Result<BlobKeySelection, BlobError> {
        Ok(BlobKeySelection {
            key_ref: BlobId::new(format!("test-key-{generation}"))?,
            crypto: CryptoDescriptor {
                algorithm: ok(BlobId::new("seal-alg")),
                version: 1,
                key_lineage: ok(BlobId::new(&self.lineage)),
                key_generation: generation,
            },
        })
    }
}

impl BlobKeyPort for FakeKeyPort {
    fn current(&mut self) -> Result<BlobKeySelection, BlobError> {
        if self.refuse_current {
            return Err(BlobError::ProviderUnavailable("backup-test-key"));
        }
        self.selection(3)
    }

    fn resolve(&self, descriptor: &CryptoDescriptor) -> Result<BlobKeySelection, BlobError> {
        if self.refuse_resolve {
            return Err(BlobError::ProviderUnavailable("backup-test-key"));
        }
        if descriptor.key_lineage.as_str() != self.lineage {
            return Err(BlobError::ProviderUnavailable("backup-test-key"));
        }
        self.selection(descriptor.key_generation)
    }
}

/// Deterministic test envelope: 32-byte tag over associated data, nonce,
/// plaintext, and key reference, then the plaintext. Tag mismatch refuses;
/// short input refuses; anything else opens.
struct FakeAead;

fn envelope_tag(key_ref: &str, associated_data: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(associated_data);
    input.extend_from_slice(nonce);
    input.extend_from_slice(plaintext);
    input.extend_from_slice(key_ref.as_bytes());
    sha_hex(&input).into_bytes()
}

impl BlobAeadPort for FakeAead {
    fn seal(&mut self, request: AeadSealRequest<'_>) -> Result<Vec<u8>, BlobError> {
        let mut sealed = envelope_tag(
            request.key.key_ref.as_str(),
            request.associated_data,
            request.nonce_context,
            request.plaintext,
        );
        sealed.extend_from_slice(request.plaintext);
        Ok(sealed)
    }

    fn open(&self, request: AeadOpenRequest<'_>) -> Result<Vec<u8>, BlobError> {
        if request.ciphertext.len() < 64 {
            return Err(BlobError::IntegrityMismatch);
        }
        let plaintext = request.ciphertext[64..].to_vec();
        let expected = envelope_tag(
            request.key.key_ref.as_str(),
            request.associated_data,
            request.nonce_context,
            &plaintext,
        );
        if request.ciphertext[..64] != expected[..] {
            return Err(BlobError::IntegrityMismatch);
        }
        Ok(plaintext)
    }
}

/// In-memory admitted source: serves exact bytes per locator hash under the
/// retained lease generation; a moved generation refuses as stale instead of
/// serving bytes the fence never covered.
struct MemSource {
    served_generation: u64,
    bytes: HashMap<String, Vec<u8>>,
    fetch_count: usize,
    fail_at: Option<usize>,
    fail_with: Option<BlobError>,
}

impl MemSource {
    fn serving(contents: &[(&[u8], &str)], served_generation: u64) -> Self {
        let mut bytes = HashMap::new();
        for (content, scope) in contents {
            let locator = locator_for(content, scope);
            bytes.insert(locator.hash.as_str().to_owned(), content.to_vec());
        }
        Self {
            served_generation,
            bytes,
            fetch_count: 0,
            fail_at: None,
            fail_with: None,
        }
    }
}

impl BackupPlaintextSource for MemSource {
    fn fetch(
        &mut self,
        lease: &BlobRootLease,
        locator: &BlobLocator,
    ) -> Result<Vec<u8>, BlobError> {
        if lease.root_generation != self.served_generation {
            return Err(BlobError::StaleFence);
        }
        locator.validate()?;
        let count = self.fetch_count;
        self.fetch_count += 1;
        if self.fail_at == Some(count) {
            return Err(self.fail_with.clone().unwrap_or(BlobError::NotFound));
        }
        match self.bytes.get(locator.hash.as_str()) {
            Some(content) => Ok(content.clone()),
            None => Err(BlobError::NotFound),
        }
    }
}

/// In-memory admitted sink: stages only under the admitted scope residency
/// and publishes the completion receipt at most once per completed run.
struct MemSink {
    staged: Vec<(RestoreBinding, Vec<u8>)>,
    published: Vec<String>,
    fail_stage_at: Option<usize>,
    fail_publish: bool,
}

impl MemSink {
    fn new() -> Self {
        Self {
            staged: Vec::new(),
            published: Vec::new(),
            fail_stage_at: None,
            fail_publish: false,
        }
    }
}

impl BackupSealedSink for MemSink {
    fn stage(
        &mut self,
        scope: &BlobBackupScope,
        binding: &RestoreBinding,
        sealed: &[u8],
    ) -> Result<(), BlobError> {
        if binding.residency_digest() != scope.residency_digest() {
            return Err(BlobError::IntegrityMismatch);
        }
        if self.fail_stage_at == Some(self.staged.len()) {
            return Err(BlobError::Provider("backup-test-sink".to_owned()));
        }
        self.staged.push((binding.clone(), sealed.to_vec()));
        Ok(())
    }

    fn publish_completion(
        &mut self,
        scope: &BlobBackupScope,
        receipt: &BlobBackupCompletionReceipt,
    ) -> Result<(), BlobError> {
        if receipt.scope_residency_digest() != scope.residency_digest() {
            return Err(BlobError::IntegrityMismatch);
        }
        if self.fail_publish {
            return Err(BlobError::Provider("backup-test-publish".to_owned()));
        }
        self.published.push(receipt.manifest_sha256().to_owned());
        Ok(())
    }
}

/// In-memory cleanup port: retains every discarded unverified envelope.
struct MemCleanup {
    discarded: Vec<Vec<u8>>,
}

impl MemCleanup {
    fn new() -> Self {
        Self {
            discarded: Vec::new(),
        }
    }
}

impl BackupCleanupPort for MemCleanup {
    fn discard_unverified(&mut self, sealed: &[u8]) -> Result<(), BlobError> {
        self.discarded.push(sealed.to_vec());
        Ok(())
    }
}

/// Run fate knobs: every refusal the driver must survive, in one place.
struct Fate {
    fail_fetch_at: Option<usize>,
    fetch_error: Option<BlobError>,
    fail_stage_at: Option<usize>,
    fail_publish: bool,
    served_generation: u64,
    max_per_page: u32,
    max_member_bytes: u64,
    max_total_bytes: u64,
}

impl Default for Fate {
    fn default() -> Self {
        Self {
            fail_fetch_at: None,
            fetch_error: None,
            fail_stage_at: None,
            fail_publish: false,
            served_generation: ROOT_GENERATION,
            max_per_page: 8,
            max_member_bytes: 1 << 20,
            max_total_bytes: 1 << 30,
        }
    }
}

struct LivePorts {
    keys: FakeKeyPort,
    aead: FakeAead,
}

/// End-to-end capture over `contents` under the standard admission.
/// Returns the outcome plus the sink and cleanup evidence for assertions.
fn capture(
    contents: &[(&[u8], &str)],
    fate: &Fate,
    admission: &Admission,
) -> (CaptureOutcome, MemSink, MemCleanup) {
    let mut live = LivePorts {
        keys: FakeKeyPort::holder(),
        aead: FakeAead,
    };
    let members: Vec<BlobLocator> = contents
        .iter()
        .map(|(content, scope)| locator_for(content, scope))
        .collect();
    let fence = ok(BlobBackupFence::fence(
        "backup-op-1".to_owned(),
        ROOT_GENERATION,
        members,
        fate.max_per_page,
        fate.max_member_bytes,
        fate.max_total_bytes,
    ));
    let mut source = MemSource::serving(contents, fate.served_generation);
    source.fail_at = fate.fail_fetch_at;
    source.fail_with.clone_from(&fate.fetch_error);
    let mut sink = MemSink::new();
    sink.fail_stage_at = fate.fail_stage_at;
    sink.fail_publish = fate.fail_publish;
    let mut cleanup = MemCleanup::new();
    let mut ports = CapturePorts {
        key_port: &mut live.keys,
        aead: &mut live.aead,
    };
    let outcome = run_capture(
        &mut ports,
        &fence,
        &admission.source_lease,
        &admission.scope,
        &admission.lease,
        &admission.crypto,
        &admission.residency,
        &mut source,
        &mut sink,
        &mut cleanup,
    );
    (outcome, sink, cleanup)
}

fn must_complete(outcome: CaptureOutcome) -> Vec<ResidencyDisposition> {
    match outcome {
        CaptureOutcome::Completed {
            dispositions,
            staged_members,
            staged_bytes,
            ..
        } => {
            assert!(staged_members > 0, "completed run stages members");
            assert!(staged_bytes > 0, "completed run stages bytes");
            dispositions
        }
        CaptureOutcome::Interrupted { cause, .. } => {
            panic!("capture must complete, interrupted with {cause:?}")
        }
    }
}

fn must_interrupt(
    outcome: CaptureOutcome,
) -> (BlobError, u32, usize, u64, u64, Vec<ResidencyDisposition>) {
    match outcome {
        CaptureOutcome::Completed { .. } => panic!("capture must interrupt"),
        CaptureOutcome::Interrupted {
            cause,
            failed_page_index,
            failed_fence_index,
            staged_members,
            staged_bytes,
            dispositions,
            ..
        } => (
            cause,
            failed_page_index,
            failed_fence_index,
            staged_members,
            staged_bytes,
            dispositions,
        ),
    }
}

fn locator_for_path(content: &[u8], scope_domain: &str, path_generation: u32) -> BlobLocator {
    let (hash, residency) = residency_for(content, scope_domain);
    BlobLocator {
        hash,
        residency,
        root_generation: ROOT_GENERATION,
        path_generation,
    }
}

/// End-to-end capture of `member_count` same-residency members (path
/// generations 1..=n) under a fresh standard admission. Same content and
/// domain keep one residency digest, so the run can complete.
fn capture_same(member_count: u32, fate: &Fate) -> (CaptureOutcome, MemSink, MemCleanup) {
    let admission = admission();
    let mut live = LivePorts {
        keys: FakeKeyPort::holder(),
        aead: FakeAead,
    };
    let mut members = Vec::new();
    let mut index = 0;
    while index < member_count {
        members.push(locator_for_path(b"dest-marker", "scope-dest", index + 1));
        index += 1;
    }
    let fence = ok(BlobBackupFence::fence(
        "backup-op-1".to_owned(),
        ROOT_GENERATION,
        members,
        fate.max_per_page,
        fate.max_member_bytes,
        fate.max_total_bytes,
    ));
    let mut source = MemSource::serving(
        &[(b"dest-marker".as_slice(), "scope-dest")],
        fate.served_generation,
    );
    source.fail_at = fate.fail_fetch_at;
    source.fail_with.clone_from(&fate.fetch_error);
    let mut sink = MemSink::new();
    sink.fail_stage_at = fate.fail_stage_at;
    sink.fail_publish = fate.fail_publish;
    let mut cleanup = MemCleanup::new();
    let mut ports = CapturePorts {
        key_port: &mut live.keys,
        aead: &mut live.aead,
    };
    let outcome = run_capture(
        &mut ports,
        &fence,
        &admission.source_lease,
        &admission.scope,
        &admission.lease,
        &admission.crypto,
        &admission.residency,
        &mut source,
        &mut sink,
        &mut cleanup,
    );
    (outcome, sink, cleanup)
}

/// One manually driven page step: opens the exact window over the fence and
/// exports it through the admitted source port.
#[derive(Clone, Copy)]
struct PageCursor {
    page_index: u32,
    start: usize,
    len: usize,
}

fn drive_page(
    ports: &mut CapturePorts<'_>,
    fence: &BlobBackupFence,
    lease: &BlobRootLease,
    source: &mut MemSource,
    cursor: PageCursor,
    predecessor: String,
    cumulative: (u64, u64),
) -> ExportedPage {
    let page = ok(BlobBackupPage::open(
        fence,
        cursor.page_index,
        cursor.start,
        cursor.len,
        predecessor,
        cumulative.0,
        cumulative.1,
    ));
    ok(export_page(ports, fence, lease, &page, source))
}

fn seal_with(
    keys: &mut FakeKeyPort,
    locator: &BlobLocator,
    operation: &str,
    page_index: u32,
    member_index: usize,
    plaintext: &[u8],
) -> SealedMember {
    ok(seal_member(
        keys,
        &mut FakeAead,
        locator,
        &seal_nonce_context(operation, page_index, member_index),
        &seal_associated_data(operation, locator),
        plaintext,
    ))
}

// WORK_UNIT_CASE: 956/T1 — exact finite denominator from canonical capture.
#[test]
fn t01_canonical_capture_denominator_is_exact() {
    let mut keys = FakeKeyPort::holder();
    let first = locator_for(b"member-zero", "scope-a");
    let second = locator_for(b"member-one", "scope-a");
    let record_one = seal_with(&mut keys, &first, "backup-op-1", 0, 0, b"member-zero");
    let record_two = seal_with(&mut keys, &second, "backup-op-1", 0, 1, b"member-one");
    let records = vec![record_one.record().clone(), record_two.record().clone()];
    let fence = ok(BlobBackupFence::fence_from_capture(
        "backup-op-1".to_owned(),
        ROOT_GENERATION,
        &records,
        8,
        1 << 20,
        1 << 30,
    ));
    assert_eq!(fence.member_count(), 2);
    assert_eq!(fence.members(), &[first, second]);
    let again = ok(BlobBackupFence::fence_from_capture(
        "backup-op-1".to_owned(),
        ROOT_GENERATION,
        &records,
        8,
        1 << 20,
        1 << 30,
    ));
    assert_eq!(ok(fence.canonical_digest()), ok(again.canonical_digest()));
    let empty = ok(BlobBackupFence::fence_from_capture(
        "backup-op-1".to_owned(),
        ROOT_GENERATION,
        &[],
        8,
        1 << 20,
        1 << 30,
    ));
    assert_eq!(empty.member_count(), 0);
}

// WORK_UNIT_CASE: 956/T2 — equal bytes under different obligations stay distinct.
#[test]
fn t02_equal_bytes_across_domains_stay_distinct() {
    let content = b"shared-bytes";
    let left = locator_for(content, "scope-a");
    let right = locator_for(content, "scope-b");
    assert_eq!(left.hash, right.hash);
    let left_digest = ok(left.residency_key_digest());
    let right_digest = ok(right.residency_key_digest());
    assert_ne!(left_digest, right_digest);
    let mut keys = FakeKeyPort::holder();
    let sealed_left = seal_with(&mut keys, &left, "backup-op-1", 0, 0, content);
    let sealed_right = seal_with(&mut keys, &right, "backup-op-1", 0, 1, content);
    assert_ne!(
        sealed_left.sealed_bytes(),
        sealed_right.sealed_bytes(),
        "associated data binds the residency domain"
    );
    let admission = admission();
    let scope_left = ok(BlobBackupScope::issue(
        &admission.lease,
        &admission.crypto,
        &left.residency,
    ));
    let bindings = ok(bind_restore_set(
        &keys,
        &scope_left,
        &admission.lease,
        &admission.crypto,
        &left.residency,
        std::slice::from_ref(sealed_left.record()),
    ));
    assert_eq!(bindings.len(), 1);
    assert_eq!(
        bindings[0].residency_digest(),
        scope_left.residency_digest()
    );
    let Err(BlobError::IntegrityMismatch) = bind_restore_set(
        &keys,
        &scope_left,
        &admission.lease,
        &admission.crypto,
        &left.residency,
        std::slice::from_ref(sealed_right.record()),
    ) else {
        panic!("a foreign-domain record must fail the set closed")
    };
}

// WORK_UNIT_CASE: 956/T3 — member generation must equal the fenced source generation.
#[test]
fn t03_fence_refuses_generation_mismatch() {
    let mut keys = FakeKeyPort::holder();
    let current = locator_for(b"member-zero", "scope-a");
    let mut drifted = locator_for(b"member-one", "scope-a");
    drifted.root_generation = ROOT_GENERATION + 1;
    let record_current = seal_with(&mut keys, &current, "backup-op-1", 0, 0, b"member-zero");
    let record_drifted = seal_with(&mut keys, &drifted, "backup-op-1", 0, 1, b"member-one");
    let Err(BlobError::InvalidField { field, .. }) = BlobBackupFence::fence_from_capture(
        "backup-op-1".to_owned(),
        ROOT_GENERATION,
        &[
            record_current.record().clone(),
            record_drifted.record().clone(),
        ],
        8,
        1 << 20,
        1 << 30,
    ) else {
        panic!("a foreign-generation capture record must refuse")
    };
    assert_eq!(field, "backup_fence.member.root_generation");
}

// WORK_UNIT_CASE: 956/T4 — lease, identity, and path-shape guards.
#[test]
fn t04_lease_and_path_guards_hold() {
    // An incoherent fence binding never parses: the receipt contract
    // rejects it at the wire boundary, before any lease exists.
    let mut value: serde_json::Value = ok(serde_json::from_str(&context_json("backup-op-9")));
    value["request"]["metadata"]["state_fence"]["resource_generation"] = serde_json::json!(8);
    assert!(
        serde_json::from_value::<BlobReceiptContext>(value).is_err(),
        "an incoherent fence binding must not parse"
    );
    // A drifted lease generation reads stale through the owner contract.
    let mut lease = lease_for(&receipt_context("backup-op-9"), "root-x", "owner-1");
    lease.root_generation = ROOT_GENERATION + 1;
    assert!(
        matches!(lease.validate(), Err(BlobError::StaleFence)),
        "a drifted lease generation must read stale"
    );
    for candidate in ["../escape", "a/b", "..", "a\\b"] {
        assert!(
            BlobId::new(candidate).is_err(),
            "path-shaped identity {candidate:?} must refuse"
        );
    }
}

// WORK_UNIT_CASE: 956/T5 — source replacement refuses mid-run with the prefix preserved.
#[test]
fn t05_source_replacement_refuses_mid_run() {
    let fate = Fate {
        max_per_page: 1,
        fail_fetch_at: Some(1),
        fetch_error: Some(BlobError::StaleFence),
        ..Fate::default()
    };
    let (outcome, sink, cleanup) = capture_same(3, &fate);
    let (cause, failed_page, failed_index, staged_members, staged_bytes, _) =
        must_interrupt(outcome);
    assert!(matches!(cause, BlobError::StaleFence));
    assert_eq!(failed_page, 1);
    assert_eq!(failed_index, 1);
    assert_eq!(staged_members, 1);
    assert!(staged_bytes > 0);
    assert_eq!(sink.staged.len(), 1);
    assert!(sink.published.is_empty(), "interrupted runs never publish");
    assert!(cleanup.discarded.is_empty());
    let skewed = Fate {
        served_generation: ROOT_GENERATION + 1,
        ..Fate::default()
    };
    let (skewed_outcome, _, _) = capture_same(2, &skewed);
    let (skewed_cause, skewed_page, skewed_index, skewed_staged, _, _) =
        must_interrupt(skewed_outcome);
    assert!(matches!(skewed_cause, BlobError::StaleFence));
    assert_eq!((skewed_page, skewed_index, skewed_staged), (0, 0, 0));
}

// WORK_UNIT_CASE: 956/T6 — pages form one contiguous chain over the full denominator.
#[test]
fn t06_pages_form_contiguous_full_cover() {
    let admission = admission();
    let members: Vec<BlobLocator> = [1, 2, 3, 4, 5]
        .iter()
        .map(|path| locator_for_path(b"dest-marker", "scope-dest", *path))
        .collect();
    let fence = ok(BlobBackupFence::fence(
        "backup-op-1".to_owned(),
        ROOT_GENERATION,
        members,
        2,
        1 << 20,
        1 << 30,
    ));
    let mut live = LivePorts {
        keys: FakeKeyPort::holder(),
        aead: FakeAead,
    };
    let mut source = MemSource::serving(
        &[(b"dest-marker".as_slice(), "scope-dest")],
        ROOT_GENERATION,
    );
    let mut ports = CapturePorts {
        key_port: &mut live.keys,
        aead: &mut live.aead,
    };
    let exported_zero = drive_page(
        &mut ports,
        &fence,
        &admission.source_lease,
        &mut source,
        PageCursor {
            page_index: 0,
            start: 0,
            len: 2,
        },
        eliot_blob_api::BLOB_BACKUP_GENESIS.to_owned(),
        (0, 0),
    );
    let bytes_zero = exported_zero.total_sealed_bytes();
    let exported_one = drive_page(
        &mut ports,
        &fence,
        &admission.source_lease,
        &mut source,
        PageCursor {
            page_index: 1,
            start: 2,
            len: 2,
        },
        exported_zero.page_digest().to_owned(),
        (2, bytes_zero),
    );
    let exported_two = drive_page(
        &mut ports,
        &fence,
        &admission.source_lease,
        &mut source,
        PageCursor {
            page_index: 2,
            start: 4,
            len: 1,
        },
        exported_one.page_digest().to_owned(),
        (4, bytes_zero + exported_one.total_sealed_bytes()),
    );
    let pages = [exported_zero, exported_one, exported_two];
    let records: Vec<SealedBlobCaptureRecord> = pages
        .iter()
        .flat_map(|page| page.members().iter().map(|member| member.record().clone()))
        .collect();
    let completions: Vec<PageCompletion> =
        pages.iter().map(|page| page.completion().clone()).collect();
    assert_eq!(records.len(), 5);
    let receipt = ok(BlobBackupCompletionReceipt::complete(
        &fence,
        &records,
        &completions,
        &admission.scope,
    ));
    assert_eq!(receipt.member_count(), 5);
    let gapped = vec![completions[0].clone(), completions[2].clone()];
    assert!(
        BlobBackupCompletionReceipt::complete(&fence, &records, &gapped, &admission.scope).is_err(),
        "a gapped page chain must refuse"
    );
    let partial_cover = vec![completions[0].clone(), completions[1].clone()];
    assert!(
        matches!(
            BlobBackupCompletionReceipt::complete(
                &fence,
                &records,
                &partial_cover,
                &admission.scope
            ),
            Err(BlobError::PlanGap(_))
        ),
        "a partial page cover must refuse as a denominator gap"
    );
}

// WORK_UNIT_CASE: 956/T7 — envelope, descriptor, AAD, and source bindings travel together.
#[test]
fn t07_envelope_bindings_travel_together() {
    let mut keys = FakeKeyPort::holder();
    let locator = locator_for(b"bound-member", "scope-a");
    let sealed = seal_with(&mut keys, &locator, "backup-op-1", 0, 0, b"bound-member");
    let opened = ok(open_member(
        &keys,
        &FakeAead,
        "backup-op-1",
        0,
        0,
        sealed.record(),
        sealed.sealed_bytes(),
    ));
    assert_eq!(opened, b"bound-member");
    assert!(
        open_member(
            &keys,
            &FakeAead,
            "backup-op-other",
            0,
            0,
            sealed.record(),
            sealed.sealed_bytes(),
        )
        .is_err(),
        "a foreign operation must not open the envelope"
    );
    let rebound = ok(SealedBlobCaptureRecord::capture(
        locator.clone(),
        "c".repeat(64),
        sealed.record().plaintext_sha256().to_owned(),
        test_crypto(),
    ));
    assert!(
        matches!(
            open_member(
                &keys,
                &FakeAead,
                "backup-op-1",
                0,
                0,
                &rebound,
                sealed.sealed_bytes(),
            ),
            Err(BlobError::IntegrityMismatch)
        ),
        "bytes that are not the recorded ones must refuse"
    );
    let rotated_crypto = CryptoDescriptor {
        algorithm: ok(BlobId::new("seal-alg")),
        version: 1,
        key_lineage: ok(BlobId::new(LINEAGE)),
        key_generation: 4,
    };
    let rotated = ok(SealedBlobCaptureRecord::capture(
        locator,
        sealed.record().sealed_sha256().to_owned(),
        sealed.record().plaintext_sha256().to_owned(),
        rotated_crypto,
    ));
    assert!(
        open_member(
            &keys,
            &FakeAead,
            "backup-op-1",
            0,
            0,
            &rotated,
            sealed.sealed_bytes(),
        )
        .is_err(),
        "a rotated descriptor must not open the old envelope"
    );
}

// WORK_UNIT_CASE: 956/T8 — unavailable keys refuse distinctly from auth failures.
#[test]
fn t08_unavailable_key_is_not_auth_failure() {
    let mut keys = FakeKeyPort::holder();
    let locator = locator_for(b"keyed-member", "scope-a");
    let sealed = seal_with(&mut keys, &locator, "backup-op-1", 0, 0, b"keyed-member");
    let mut blind = FakeKeyPort::holder();
    blind.refuse_resolve = true;
    assert!(
        matches!(
            open_member(
                &blind,
                &FakeAead,
                "backup-op-1",
                0,
                0,
                sealed.record(),
                sealed.sealed_bytes(),
            ),
            Err(BlobError::ProviderUnavailable(_))
        ),
        "an unheld lineage refuses as unavailable"
    );
    let admission = admission();
    assert!(
        matches!(
            verify_destination_scope(
                &blind,
                &admission.scope,
                &admission.lease,
                &admission.crypto,
                &admission.residency,
            ),
            Err(BlobError::ProviderUnavailable(_))
        ),
        "scope verification proves live lineage possession"
    );
    let mut tampered = sealed.sealed_bytes().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        matches!(
            open_member(
                &keys,
                &FakeAead,
                "backup-op-1",
                0,
                0,
                sealed.record(),
                &tampered,
            ),
            Err(BlobError::IntegrityMismatch)
        ),
        "validly-held keys fail tampered envelopes as integrity errors"
    );
}

// WORK_UNIT_CASE: 956/T9 — diagnostics never carry plaintext.
#[test]
fn t09_diagnostics_carry_no_plaintext() {
    let marker = b"SECRET-PLAINTEXT-XYZ-9";
    let mut foreign = FakeKeyPort {
        lineage: "foreign-lineage".to_owned(),
        refuse_current: false,
        refuse_resolve: false,
    };
    let locator = locator_for(marker, "scope-a");
    let mut source = MemSource::serving(&[(marker.as_slice(), "scope-a")], ROOT_GENERATION);
    let fence = ok(BlobBackupFence::fence(
        "backup-op-1".to_owned(),
        ROOT_GENERATION,
        vec![locator],
        8,
        1 << 20,
        1 << 30,
    ));
    let admission = admission();
    let page = ok(BlobBackupPage::open(
        &fence,
        0,
        0,
        1,
        eliot_blob_api::BLOB_BACKUP_GENESIS.to_owned(),
        0,
        0,
    ));
    let mut ports = CapturePorts {
        key_port: &mut foreign,
        aead: &mut FakeAead,
    };
    let Err(interrupt) = export_page(
        &mut ports,
        &fence,
        &admission.source_lease,
        &page,
        &mut source,
    ) else {
        panic!("a foreign lineage must not seal")
    };
    let shown = format!("{interrupt}");
    let shown_debug = format!("{interrupt:?}");
    assert!(
        !shown.contains("SECRET-PLAINTEXT-XYZ-9"),
        "Display diagnostics must not carry plaintext: {shown}"
    );
    assert!(
        !shown_debug.contains("SECRET-PLAINTEXT-XYZ-9"),
        "Debug diagnostics must not carry plaintext"
    );
    assert!(interrupt.completed().is_empty());
}

// WORK_UNIT_CASE: 956/T10 — aggregate and per-member bounds, one-over, truncation.
#[test]
fn t10_bounds_refuse_one_over_and_truncated() {
    let locator = locator_for(b"bounded-member", "scope-a");
    assert!(
        BlobBackupFence::fence(
            "backup-op-1".to_owned(),
            ROOT_GENERATION,
            vec![locator.clone()],
            0,
            1 << 20,
            1 << 30,
        )
        .is_err(),
        "a zero page bound must refuse at fence time"
    );
    let plaintext = b"bounded-member";
    let tight = Fate {
        max_member_bytes: u64::try_from(plaintext.len()).unwrap_or(0) - 1,
        ..Fate::default()
    };
    let admission = admission();
    let (tight_outcome, _, _) = capture(&[(plaintext.as_slice(), "scope-a")], &tight, &admission);
    let (tight_cause, _, _, _, _, _) = must_interrupt(tight_outcome);
    assert!(
        matches!(
            tight_cause,
            BlobError::InvalidField {
                field: "capture.plaintext",
                ..
            }
        ),
        "one byte over the member bound refuses, got {tight_cause:?}"
    );
    let exact = Fate {
        max_member_bytes: u64::try_from(plaintext.len()).unwrap_or(0),
        ..Fate::default()
    };
    let (exact_outcome, _, _) = capture(&[(plaintext.as_slice(), "scope-a")], &exact, &admission);
    assert!(
        matches!(exact_outcome, CaptureOutcome::Interrupted { .. }),
        "a single foreign-residency member cannot complete under the dest scope"
    );
    let mut keys = FakeKeyPort::holder();
    let fenced = locator_for_path(b"dest-marker", "scope-dest", 1);
    let sealed = seal_with(&mut keys, &fenced, "backup-op-1", 0, 0, b"dest-marker");
    let mut cut = sealed.sealed_bytes().to_vec();
    cut.truncate(cut.len() / 2);
    assert!(
        matches!(
            open_member(&keys, &FakeAead, "backup-op-1", 0, 0, sealed.record(), &cut,),
            Err(BlobError::IntegrityMismatch)
        ),
        "truncated input refuses at open"
    );
    let starved = Fate {
        max_total_bytes: 1,
        ..Fate::default()
    };
    let (starved_outcome, _, _) = capture_same(1, &starved);
    let (starved_cause, _, _, _, _, _) = must_interrupt(starved_outcome);
    assert!(
        matches!(
            starved_cause,
            BlobError::InvalidField {
                field: "backup_page.bounds",
                ..
            }
        ),
        "a total-bytes overrun refuses, got {starved_cause:?}"
    );
}

// WORK_UNIT_CASE: 956/T11 — source, active-unadmitted, and foreign destinations refuse.
#[test]
fn t11_foreign_destination_refused() {
    let admission = admission();
    let mut drifted = lease_for(&receipt_context("backup-op-1"), "root-dest", "owner-1");
    drifted.root_generation = ROOT_GENERATION + 1;
    assert!(
        matches!(
            verify_destination_scope(
                &FakeKeyPort::holder(),
                &admission.scope,
                &drifted,
                &admission.crypto,
                &admission.residency,
            ),
            Err(BlobError::StaleFence)
        ),
        "a drifted destination lease refuses"
    );
    let foreign_crypto = CryptoDescriptor {
        algorithm: ok(BlobId::new("seal-alg")),
        version: 1,
        key_lineage: ok(BlobId::new("foreign-lineage")),
        key_generation: 3,
    };
    assert!(
        matches!(
            verify_destination_scope(
                &FakeKeyPort::holder(),
                &admission.scope,
                &admission.lease,
                &foreign_crypto,
                &admission.residency,
            ),
            Err(BlobError::InvalidField {
                field: "backup_scope.crypto",
                ..
            })
        ),
        "a rotated destination key binding refuses"
    );
    let foreign_scope = ok(BlobBackupScope::issue(
        &admission.lease,
        &foreign_crypto,
        &admission.residency,
    ));
    assert!(
        matches!(
            verify_destination_scope(
                &FakeKeyPort::holder(),
                &foreign_scope,
                &admission.lease,
                &foreign_crypto,
                &admission.residency,
            ),
            Err(BlobError::ProviderUnavailable(_))
        ),
        "an unheld destination lineage refuses without invented success"
    );
    assert!(
        BlobBackupScope::issue(&drifted, &admission.crypto, &admission.residency).is_err(),
        "no scope issues without a valid destination lease"
    );
}

// WORK_UNIT_CASE: 956/T12 — purged residency evidence cannot resurrect under a new scope.
#[test]
fn t12_purged_residency_cannot_resurrect() {
    let mut keys = FakeKeyPort::holder();
    let old = locator_for(b"purged-member", "scope-old");
    let sealed_old = seal_with(&mut keys, &old, "backup-op-1", 0, 0, b"purged-member");
    let admission = admission();
    let Err(BlobError::IntegrityMismatch) = bind_restore_set(
        &keys,
        &admission.scope,
        &admission.lease,
        &admission.crypto,
        &admission.residency,
        std::slice::from_ref(sealed_old.record()),
    ) else {
        panic!("pre-purge evidence must not enter the post-purge scope")
    };
    let scope_old = ok(BlobBackupScope::issue(
        &admission.lease,
        &admission.crypto,
        &old.residency,
    ));
    let fence_old = ok(BlobBackupFence::fence(
        "backup-op-1".to_owned(),
        ROOT_GENERATION,
        vec![old],
        8,
        1 << 20,
        1 << 30,
    ));
    let page_old = ok(BlobBackupPage::open(
        &fence_old,
        0,
        0,
        1,
        eliot_blob_api::BLOB_BACKUP_GENESIS.to_owned(),
        0,
        0,
    ));
    let mut source = MemSource::serving(
        &[(b"purged-member".as_slice(), "scope-old")],
        ROOT_GENERATION,
    );
    let mut ports = CapturePorts {
        key_port: &mut keys,
        aead: &mut FakeAead,
    };
    let exported = ok(export_page(
        &mut ports,
        &fence_old,
        &admission.source_lease,
        &page_old,
        &mut source,
    ));
    let prior = ok(BlobBackupCompletionReceipt::complete(
        &fence_old,
        std::slice::from_ref(sealed_old.record()),
        std::slice::from_ref(exported.completion()),
        &scope_old,
    ));
    assert!(
        BlobBackupCompletionReceipt::reconcile_same_operation(
            &prior,
            &fence_old,
            std::slice::from_ref(sealed_old.record()),
            std::slice::from_ref(exported.completion()),
            &admission.scope,
        )
        .is_err(),
        "a stale receipt cannot reconcile under the post-purge scope"
    );
}

// WORK_UNIT_CASE: 956/T13 — durable publication happens only on the completed path.
#[test]
fn t13_publish_only_on_complete() {
    let (outcome, sink, _) = capture_same(2, &Fate::default());
    let _ = must_complete(outcome);
    assert_eq!(sink.staged.len(), 2);
    assert_eq!(sink.published.len(), 1);
    assert_eq!(sink.published[0].len(), 64);
    let fate = Fate {
        max_per_page: 1,
        fail_fetch_at: Some(1),
        fetch_error: Some(BlobError::NotFound),
        ..Fate::default()
    };
    let (broken, broken_sink, _) = capture_same(2, &fate);
    let _ = must_interrupt(broken);
    assert_eq!(broken_sink.staged.len(), 1);
    assert!(
        broken_sink.published.is_empty(),
        "interrupted runs never publish"
    );
}

// WORK_UNIT_CASE: 956/T14 — same-operation replay re-issues; changed input conflicts.
#[test]
fn t14_replay_and_changed_input_conflict() {
    let admission = admission();
    let members: Vec<BlobLocator> = [1, 2]
        .iter()
        .map(|path| locator_for_path(b"dest-marker", "scope-dest", *path))
        .collect();
    let fence = ok(BlobBackupFence::fence(
        "backup-op-1".to_owned(),
        ROOT_GENERATION,
        members.clone(),
        8,
        1 << 20,
        1 << 30,
    ));
    let mut live = LivePorts {
        keys: FakeKeyPort::holder(),
        aead: FakeAead,
    };
    let mut source = MemSource::serving(
        &[(b"dest-marker".as_slice(), "scope-dest")],
        ROOT_GENERATION,
    );
    let mut ports = CapturePorts {
        key_port: &mut live.keys,
        aead: &mut live.aead,
    };
    let page = ok(BlobBackupPage::open(
        &fence,
        0,
        0,
        2,
        eliot_blob_api::BLOB_BACKUP_GENESIS.to_owned(),
        0,
        0,
    ));
    let exported = ok(export_page(
        &mut ports,
        &fence,
        &admission.source_lease,
        &page,
        &mut source,
    ));
    let records: Vec<SealedBlobCaptureRecord> = exported
        .members()
        .iter()
        .map(|member| member.record().clone())
        .collect();
    let completions = vec![exported.completion().clone()];
    let prior = ok(BlobBackupCompletionReceipt::complete(
        &fence,
        &records,
        &completions,
        &admission.scope,
    ));
    let replay = ok(BlobBackupCompletionReceipt::reconcile_same_operation(
        &prior,
        &fence,
        &records,
        &completions,
        &admission.scope,
    ));
    assert_eq!(replay, prior);
    let changed_record = ok(SealedBlobCaptureRecord::capture(
        members[0].clone(),
        "d".repeat(64),
        records[0].plaintext_sha256().to_owned(),
        test_crypto(),
    ));
    let changed = vec![changed_record, records[1].clone()];
    assert!(
        matches!(
            BlobBackupCompletionReceipt::reconcile_same_operation(
                &prior,
                &fence,
                &changed,
                &completions,
                &admission.scope,
            ),
            Err(BlobError::IdempotencyConflict)
        ),
        "changed inputs under one operation identity conflict"
    );
}

// WORK_UNIT_CASE: 956/T15 — the same operation reconciles after a possible publication.
#[test]
fn t15_same_operation_reconciles_after_publish() {
    let (first, sink_one, _) = capture_same(2, &Fate::default());
    let (second, sink_two, _) = capture_same(2, &Fate::default());
    let CaptureOutcome::Completed {
        receipt: receipt_one,
        ..
    } = first
    else {
        panic!("the first run must complete")
    };
    let CaptureOutcome::Completed {
        receipt: receipt_two,
        ..
    } = second
    else {
        panic!("the second run must complete")
    };
    assert_eq!(receipt_one, receipt_two);
    assert_eq!(sink_one.staged.len(), sink_two.staged.len());
    let bytes_one: Vec<&[u8]> = sink_one
        .staged
        .iter()
        .map(|(_, bytes)| bytes.as_slice())
        .collect();
    let bytes_two: Vec<&[u8]> = sink_two
        .staged
        .iter()
        .map(|(_, bytes)| bytes.as_slice())
        .collect();
    assert_eq!(bytes_one, bytes_two);
}

// WORK_UNIT_CASE: 956/T16 — staged, unknown, and not-attempted members are typed.
#[test]
fn t16_typed_member_states() {
    let fate = Fate {
        max_per_page: 1,
        fail_stage_at: Some(1),
        ..Fate::default()
    };
    let (outcome, _, _) = capture_same(3, &fate);
    let (cause, failed_page, failed_index, _, _, dispositions) = must_interrupt(outcome);
    assert!(matches!(cause, BlobError::Provider(_)));
    assert_eq!((failed_page, failed_index), (1, 1));
    assert_eq!(dispositions.len(), 1);
    let group = &dispositions[0];
    assert_eq!(group.members().len(), 3);
    assert_eq!(group.staged_members(), 1);
    assert_eq!(group.operation_id(), "backup-op-1");
    assert!(!group.residency_digest().is_empty());
    let states: Vec<BackupMemberState> = group
        .members()
        .iter()
        .map(MemberDisposition::state)
        .collect();
    assert_eq!(
        states,
        vec![
            BackupMemberState::Staged,
            BackupMemberState::Unknown,
            BackupMemberState::NotAttempted,
        ]
    );
    assert_eq!(
        group.members()[0].durability(),
        DispositionDurability::StagedDurable
    );
    assert_eq!(
        group.members()[0].validation(),
        DispositionValidation::OpenVerified
    );
    assert_eq!(group.members()[0].cleanup(), DispositionCleanup::Retained);
    assert_eq!(
        group.members()[1].cleanup(),
        DispositionCleanup::DiscardedUnverified
    );
    assert_eq!(group.members()[2].cleanup(), DispositionCleanup::Untouched);
    let (whole, _, _) = capture_same(2, &Fate::default());
    let groups = must_complete(whole);
    assert!(
        groups
            .iter()
            .flat_map(ResidencyDisposition::members)
            .all(|member| member.state() == BackupMemberState::Staged)
    );
}

// WORK_UNIT_CASE: 956/T17 — the verified prefix and the exact resume index survive.
#[test]
fn t17_prefix_and_resume_index() {
    let admission = admission();
    let members: Vec<BlobLocator> = [1, 2, 3, 4]
        .iter()
        .map(|path| locator_for_path(b"dest-marker", "scope-dest", *path))
        .collect();
    let fence = ok(BlobBackupFence::fence(
        "backup-op-1".to_owned(),
        ROOT_GENERATION,
        members,
        2,
        1 << 20,
        1 << 30,
    ));
    let mut live = LivePorts {
        keys: FakeKeyPort::holder(),
        aead: FakeAead,
    };
    let mut source = MemSource::serving(
        &[(b"dest-marker".as_slice(), "scope-dest")],
        ROOT_GENERATION,
    );
    let mut ports = CapturePorts {
        key_port: &mut live.keys,
        aead: &mut live.aead,
    };
    let exported_head = drive_page(
        &mut ports,
        &fence,
        &admission.source_lease,
        &mut source,
        PageCursor {
            page_index: 0,
            start: 0,
            len: 2,
        },
        eliot_blob_api::BLOB_BACKUP_GENESIS.to_owned(),
        (0, 0),
    );
    let bytes_head = exported_head.total_sealed_bytes();
    let exported_next = drive_page(
        &mut ports,
        &fence,
        &admission.source_lease,
        &mut source,
        PageCursor {
            page_index: 1,
            start: 2,
            len: 2,
        },
        exported_head.page_digest().to_owned(),
        (2, bytes_head),
    );
    let first = exported_head.completion().clone();
    let second = exported_next.completion().clone();
    let partial = ok(BlobBackupPartial::cancel_after(&fence, vec![first.clone()]));
    assert_eq!(partial.completed_members(), 2);
    assert_eq!(partial.next_start_index(), 2);
    assert_eq!(partial.fence_member_count(), 4);
    assert!(
        BlobBackupPartial::cancel_after(&fence, vec![second.clone()]).is_err(),
        "a chain that does not start at genesis refuses"
    );
    let exported_tail = drive_page(
        &mut ports,
        &fence,
        &admission.source_lease,
        &mut source,
        PageCursor {
            page_index: 1,
            start: partial.next_start_index(),
            len: 2,
        },
        first.page_digest().to_owned(),
        (2, bytes_head),
    );
    let receipt = ok(complete_export(
        &fence,
        &[exported_head, exported_tail],
        &admission.scope,
    ));
    assert_eq!(receipt.member_count(), 4);
}

// WORK_UNIT_CASE: 956/T18 — owned cleanup discards only unverified bytes.
#[test]
fn t18_cleanup_discards_only_unverified() {
    let fate = Fate {
        fail_stage_at: Some(1),
        ..Fate::default()
    };
    let (outcome, sink, cleanup) = capture_same(3, &fate);
    let (cause, _, failed_index, _, _, dispositions) = must_interrupt(outcome);
    assert!(matches!(cause, BlobError::Provider(_)));
    assert_eq!(failed_index, 1);
    assert_eq!(sink.staged.len(), 1, "the verified prefix stays staged");
    assert_eq!(
        cleanup.discarded.len(),
        2,
        "only sealed-but-unverified members are discarded"
    );
    for discarded in &cleanup.discarded {
        assert_ne!(
            discarded, &sink.staged[0].1,
            "staged bytes never enter cleanup"
        );
    }
    let states: Vec<BackupMemberState> = dispositions[0]
        .members()
        .iter()
        .map(MemberDisposition::state)
        .collect();
    assert_eq!(
        states,
        vec![
            BackupMemberState::Staged,
            BackupMemberState::Unknown,
            BackupMemberState::Unknown,
        ]
    );
}

/// Isolated filesystem sink: stages sealed members as exact manifest-named
/// files under one retained root and publishes the receipt beside them.
/// Every name stays inside the root; anything else refuses.
struct FsSink {
    root: PathBuf,
    names: HashMap<String, String>,
    published: Vec<String>,
}

impl FsSink {
    fn stage_file(&mut self, name: &str, bytes: &[u8]) -> Result<(), BlobError> {
        if name.is_empty()
            || name.contains(['/', '\\'])
            || name.starts_with('.')
            || PathBuf::from(name).is_absolute()
        {
            return Err(BlobError::InvalidField {
                field: "backup_sink.path",
                reason: "staged names stay inside the isolated root",
            });
        }
        let path = self.root.join(name);
        if !path.starts_with(&self.root) {
            return Err(BlobError::InvalidField {
                field: "backup_sink.path",
                reason: "staged paths never escape the isolated root",
            });
        }
        fs::write(&path, bytes).map_err(|error| BlobError::Provider(error.to_string()))?;
        Ok(())
    }
}

impl BackupSealedSink for FsSink {
    fn stage(
        &mut self,
        scope: &BlobBackupScope,
        binding: &RestoreBinding,
        sealed: &[u8],
    ) -> Result<(), BlobError> {
        if binding.residency_digest() != scope.residency_digest() {
            return Err(BlobError::IntegrityMismatch);
        }
        let name = match self.names.get(binding.blob_hash()) {
            Some(name) => name.clone(),
            None => {
                return Err(BlobError::InvalidField {
                    field: "backup_sink.binding",
                    reason: "staged bindings name manifest members",
                });
            }
        };
        self.stage_file(&name, sealed)?;
        Ok(())
    }

    fn publish_completion(
        &mut self,
        scope: &BlobBackupScope,
        receipt: &BlobBackupCompletionReceipt,
    ) -> Result<(), BlobError> {
        if receipt.scope_residency_digest() != scope.residency_digest() {
            return Err(BlobError::IntegrityMismatch);
        }
        let digest = receipt.manifest_sha256().to_owned();
        self.stage_file("receipt.json", digest.as_bytes())?;
        self.published.push(digest);
        Ok(())
    }
}

fn read_manifest(dir: &std::path::Path) -> Vec<(Vec<u8>, String, String)> {
    let text = ok(fs::read_to_string(dir.join("manifest.json")));
    let value: serde_json::Value = ok(serde_json::from_str(&text));
    let Some(members) = value["members"].as_array() else {
        panic!("the backup-io manifest must list members")
    };
    let mut listed = Vec::new();
    for member in members {
        let Some(plaintext) = member["plaintext"].as_str() else {
            panic!("every manifest member names its plaintext")
        };
        let Some(staged) = member["staged"].as_str() else {
            panic!("every manifest member names its staged file")
        };
        let Some(scope) = member["scope_domain"].as_str() else {
            panic!("every manifest member names its scope domain")
        };
        listed.push((
            ok(fs::read(dir.join(plaintext))),
            staged.to_owned(),
            scope.to_owned(),
        ));
    }
    listed
}

// WORK_UNIT_CASE: 956/T19 — the manifest fixtures stage, reopen, and clean up on real files.
#[test]
fn t19_filesystem_fixture_roundtrip() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/backup-io");
    let listed = read_manifest(&dir);
    assert_eq!(listed.len(), 3);
    let root = std::env::temp_dir().join(format!("eliot-956-t19-{}", std::process::id()));
    if root.exists() {
        ok(fs::remove_dir_all(&root));
    }
    ok(fs::create_dir_all(&root));
    let admission = admission();
    let mut names = HashMap::new();
    for (content, staged, scope) in &listed {
        names.insert(
            locator_for(content, scope).hash.as_str().to_owned(),
            staged.clone(),
        );
    }
    let mut sink = FsSink {
        root: root.clone(),
        names,
        published: Vec::new(),
    };
    let mut witnessed = Vec::new();
    for (content, staged, scope) in &listed {
        let locator = locator_for(content, scope);
        let mut keys = FakeKeyPort::holder();
        let sealed = seal_with(&mut keys, &locator, "backup-op-1", 0, 0, content);
        let record = sealed.record().clone();
        let fence = ok(BlobBackupFence::fence_from_capture(
            "backup-op-1".to_owned(),
            ROOT_GENERATION,
            std::slice::from_ref(&record),
            8,
            1 << 20,
            1 << 30,
        ));
        let destination = ok(BlobBackupScope::issue(
            &admission.lease,
            &admission.crypto,
            &locator.residency,
        ));
        let mut source =
            MemSource::serving(&[(content.as_slice(), scope.as_str())], ROOT_GENERATION);
        let mut cleanup = MemCleanup::new();
        let mut ports = CapturePorts {
            key_port: &mut keys,
            aead: &mut FakeAead,
        };
        let outcome = run_capture(
            &mut ports,
            &fence,
            &admission.source_lease,
            &destination,
            &admission.lease,
            &admission.crypto,
            &locator.residency,
            &mut source,
            &mut sink,
            &mut cleanup,
        );
        let _ = must_complete(outcome);
        witnessed.push((staged.clone(), record, sealed.sealed_bytes().to_vec()));
    }
    assert_eq!(sink.published.len(), 3);
    for (staged, record, bytes) in &witnessed {
        let back = ok(fs::read(root.join(staged)));
        assert_eq!(&back, bytes, "{staged} reopens with exact bytes");
        assert_eq!(sha_hex(&back), record.sealed_sha256());
    }
    ok(fs::remove_dir_all(&root));
    assert!(!root.exists(), "cleanup removes the isolated root");
}

// WORK_UNIT_CASE: 956/T20 — no second owner, no arbitrary filesystem, no unblocking.
#[test]
fn t20_second_owner_and_arbitrary_fs_refused() {
    let admission = admission();
    // The guard keys on the owner identity, not on unblockable labels: the
    // second lease below is minted from a different operation context, yet
    // the refusal is identical.
    let other_lease = lease_for(&receipt_context("backup-op-2"), "root-dest", "owner-2");
    assert!(
        matches!(
            admission
                .scope
                .verify_against(&other_lease, &admission.crypto, &admission.residency,),
            Err(BlobError::OwnerConflict)
        ),
        "a second owner cannot present the scope"
    );
    assert!(
        admission
            .scope
            .verify_against(&admission.lease, &admission.crypto, &admission.residency)
            .is_ok(),
        "the issuing owner still admits"
    );
    let root = std::env::temp_dir().join(format!("eliot-956-t20-{}", std::process::id()));
    if root.exists() {
        ok(fs::remove_dir_all(&root));
    }
    ok(fs::create_dir_all(&root));
    let mut sink = FsSink {
        root: root.clone(),
        names: HashMap::new(),
        published: Vec::new(),
    };
    for hostile in [
        "../escape.sealed",
        "/absolute.sealed",
        "sub\\escape.sealed",
        "",
        ".hidden.sealed",
    ] {
        assert!(
            sink.stage_file(hostile, b"bytes").is_err(),
            "{hostile:?} must stay outside the isolated root"
        );
    }
    assert!(ok(root.read_dir()).next().is_none());
    ok(fs::remove_dir_all(&root));
}
