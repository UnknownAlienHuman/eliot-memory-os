//! Owner-side verification for sealed-blob backup scope and capture evidence
//! (issue #956, slice 1).
//!
//! This module performs no staging, no reads, and mints no receipts. It
//! verifies presentation against owner-held truth only:
//! [`verify_destination_scope`] re-checks the provider-neutral scope bindings
//! and then resolves the destination descriptor through the real injected
//! [`BlobKeyPort`], proving the destination owner actually holds the admitted
//! key lineage (a foreign lineage refuses with `ProviderUnavailable`, never
//! invented success); [`verify_capture_record`] re-validates recorded capture
//! evidence through the owner contracts. Decryptability and key availability
//! stay attested by the envelope/key owners — ciphertext presence here is
//! never plaintext authentication or key possession.

use std::task::{Context, Poll, Waker};

use eliot_blob_api::{
    BlobBackupCompletionReceipt, BlobBackupFence, BlobBackupPage, BlobBackupPartial,
    BlobBackupScope, BlobError, BlobFuture, BlobId, BlobLocator, BlobReadChunk, BlobReadRequest,
    BlobReceiptContext, BlobRootLease, BlobStoreClient, CryptoDescriptor, FencedBlobMember,
    ObjectResidencyKey, PageCompletion, SealedBlobCaptureRecord, BLOB_BACKUP_GENESIS,
};
use eliot_platform::WorkScopePath;
use eliot_receipts::EffectClass;

use super::{
    AeadOpenRequest, AeadSealRequest, BlobAeadPort, BlobKeyPort, BlobKeySelection, BlobPlatformPort,
    BlobRootOwner,
};
use sha2::{Digest, Sha256};

/// Verifies an admitted destination scope against live owner state.
///
/// Re-validates the scope bindings against the presented destination lease,
/// crypto descriptor, and residency identity, then resolves the descriptor
/// through `key_port`. Success returns the owner-issued key selection the
/// restore path must seal under; any refusal fails the import closed.
///
/// # Errors
///
/// Returns binding, fence, integrity, or provider errors: stale/drifted scope
/// bindings, or [`BlobError::ProviderUnavailable`] when the destination owner
/// does not hold the admitted lineage.
pub fn verify_destination_scope(
    key_port: &dyn BlobKeyPort,
    scope: &BlobBackupScope,
    lease: &BlobRootLease,
    crypto: &CryptoDescriptor,
    residency: &ObjectResidencyKey,
) -> Result<BlobKeySelection, BlobError> {
    scope.verify_against(lease, crypto, residency)?;
    key_port.resolve(crypto)
}

/// Re-validates recorded sealed capture evidence through the owner contracts.
///
/// # Errors
///
/// Returns locator, crypto, lineage-binding, digest, or integrity errors when
/// the record no longer describes one coherent sealed member.
pub fn verify_capture_record(record: &SealedBlobCaptureRecord) -> Result<(), BlobError> {
    record.validate()
}

/// Plaintext byte ceiling for one backup member. Mirrors the service staging
/// ceiling: backup capture never admits a member the store itself would
/// refuse to stage.
pub const BACKUP_MAX_PLAINTEXT_BYTES: u64 = 32 * 1024 * 1024;

/// Nonce-context derivation for backup seals. Binds the envelope to one
/// operation, page, and fence member; the restore side recomputes the same
/// bytes through this function instead of accepting caller text.
#[must_use]
pub fn seal_nonce_context(operation_id: &str, page_index: u32, member_index: usize) -> Vec<u8> {
    format!("backup-seal:{operation_id}:{page_index}:{member_index}").into_bytes()
}

/// Associated-data derivation for backup seals. Binds the envelope to the
/// operation plus the exact locator hash and residency digest; equal bytes
/// under different obligations seal under different associated data.
#[must_use]
pub fn seal_associated_data(operation_id: &str, locator: &BlobLocator) -> Vec<u8> {
    // Fence members are validated at fence time and re-validated before any
    // seal consumes this context, so the fallback below is unreachable on the
    // honest path; it exists only to keep associated-data derivation total.
    let residency = locator
        .residency_key_digest()
        .unwrap_or_else(|_| "invalid-residency".to_owned());
    format!(
        "backup-ad:{operation_id}:{}:{residency}",
        locator.hash.as_str()
    )
    .into_bytes()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// One sealed member: the owner-computed capture record plus the sealed
/// envelope bytes it describes. Plaintext is never retained here.
#[derive(Clone, Debug)]
pub struct SealedMember {
    record: SealedBlobCaptureRecord,
    sealed_bytes: Vec<u8>,
}

impl SealedMember {
    /// Capture record with digests computed over the actual bytes.
    #[must_use]
    pub fn record(&self) -> &SealedBlobCaptureRecord {
        &self.record
    }

    /// Sealed envelope bytes described by the record.
    #[must_use]
    pub fn sealed_bytes(&self) -> &[u8] {
        &self.sealed_bytes
    }
}

/// Seals one fenced member through the real key and AEAD owners.
///
/// Resolves the current key selection from `key_port` (proving the owner
/// holds a live lineage), requires that lineage to serve the locator's
/// residency key-lineage domain, seals the actual plaintext bytes through
/// `aead`, and computes both digests over the actual bytes. No digest text
/// is accepted from any caller: the record carries only computed values and
/// owner-issued crypto.
///
/// # Errors
///
/// Returns locator, bound, key-lineage, provider, or framing errors. An
/// unheld lineage refuses; it never seals under a substitute.
pub fn seal_member(
    key_port: &mut dyn BlobKeyPort,
    aead: &mut dyn BlobAeadPort,
    locator: &BlobLocator,
    nonce_context: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<SealedMember, BlobError> {
    locator.validate()?;
    if plaintext.is_empty() {
        return Err(BlobError::InvalidField {
            field: "capture.plaintext",
            reason: "cannot seal empty plaintext",
        });
    }
    if plaintext.len() as u64 > BACKUP_MAX_PLAINTEXT_BYTES {
        return Err(BlobError::InvalidField {
            field: "capture.plaintext",
            reason: "member exceeds the backup plaintext ceiling",
        });
    }
    if nonce_context.is_empty() || associated_data.is_empty() {
        return Err(BlobError::InvalidField {
            field: "capture.context",
            reason: "seal context must bind operation and member",
        });
    }
    let selection = key_port.current()?;
    if selection.crypto.key_lineage != locator.residency.encryption_key_domain_id {
        return Err(BlobError::InvalidField {
            field: "capture.key_lineage",
            reason: "owner key lineage does not serve the fenced residency domain",
        });
    }
    let sealed_bytes = aead.seal(AeadSealRequest {
        key: &selection,
        nonce_context,
        associated_data,
        plaintext,
    })?;
    let record = SealedBlobCaptureRecord::capture(
        locator.clone(),
        sha256_hex(&sealed_bytes),
        sha256_hex(plaintext),
        selection.crypto.clone(),
    )?;
    Ok(SealedMember {
        record,
        sealed_bytes,
    })
}

/// Opens one sealed member through the real key and AEAD owners.
///
/// Re-validates the record, proves the sealed bytes still match the recorded
/// digest, resolves the recorded descriptor through `key_port` (an unheld or
/// foreign lineage refuses here, distinctly from valid ciphertext), opens
/// through `aead`, and proves the opened bytes still match the recorded
/// plaintext digest. The returned plaintext is owned by the caller — the
/// isolated-destination stager — and is retained nowhere here.
///
/// # Errors
///
/// Returns record, digest-mismatch, key-availability, or authentication
/// errors. Ciphertext equality alone never substitutes for a successful open.
pub fn open_member(
    key_port: &dyn BlobKeyPort,
    aead: &dyn BlobAeadPort,
    record: &SealedBlobCaptureRecord,
    sealed_bytes: &[u8],
    nonce_context: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, BlobError> {
    record.validate()?;
    if sealed_bytes.is_empty() {
        return Err(BlobError::InvalidField {
            field: "capture.sealed_bytes",
            reason: "sealed envelope cannot be empty",
        });
    }
    if sha256_hex(sealed_bytes) != record.sealed_sha256() {
        return Err(BlobError::IntegrityMismatch);
    }
    let selection = key_port.resolve(record.crypto())?;
    let opened = aead.open(AeadOpenRequest {
        key: &selection,
        nonce_context,
        associated_data,
        ciphertext: sealed_bytes,
    })?;
    if sha256_hex(&opened) != record.plaintext_sha256() {
        return Err(BlobError::IntegrityMismatch);
    }
    Ok(opened)
}

/// Production plaintext read half: resolves one fenced locator to its bytes.
pub type PlaintextFetch = dyn FnMut(&BlobLocator) -> Result<Vec<u8>, BlobError>;
/// Isolated-destination stager: persists one verified sealed member.
pub type SealedStage = dyn FnMut(&RestoreBinding, &[u8]) -> Result<(), BlobError>;

/// Live owner ports for one capture run.
pub struct CapturePorts<'a> {
    /// Destination key-lineage owner proving live lineage possession.
    pub key_port: &'a mut dyn BlobKeyPort,
    /// Envelope seal/open owner proving key possession per member.
    pub aead: &'a mut dyn BlobAeadPort,
}

/// Mid-page interruption: the completed member prefix is preserved with the
/// exact failed index and cause. This is evidence, never a completion: the
/// failed member and every later member of the page remain unsealed.
#[derive(Debug)]
pub struct PageInterrupt {
    completed: Vec<SealedMember>,
    failed_index: usize,
    cause: BlobError,
}

impl PageInterrupt {
    /// Members sealed before the interruption, in fence order.
    #[must_use]
    pub fn completed(&self) -> &[SealedMember] {
        &self.completed
    }

    /// Fence index that refused.
    #[must_use]
    pub fn failed_index(&self) -> usize {
        self.failed_index
    }

    /// Typed refusal that stopped the page.
    #[must_use]
    pub fn cause(&self) -> &BlobError {
        &self.cause
    }
}

impl std::fmt::Display for PageInterrupt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "backup page interrupted at fence index {} after {} sealed members: {}",
            self.failed_index,
            self.completed.len(),
            self.cause
        )
    }
}

impl std::error::Error for PageInterrupt {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// One executed page: the sealed members in fence order plus the observed
/// page completion built from the real fence at export time.
#[derive(Clone, Debug)]
pub struct ExportedPage {
    page: BlobBackupPage,
    members: Vec<SealedMember>,
    completion: PageCompletion,
}

impl ExportedPage {
    /// Executed page window.
    #[must_use]
    pub fn page(&self) -> &BlobBackupPage {
        &self.page
    }

    /// Sealed members in fence order.
    #[must_use]
    pub fn members(&self) -> &[SealedMember] {
        &self.members
    }

    /// Owner-recomputed page digest chained by the next page.
    #[must_use]
    pub fn page_digest(&self) -> &str {
        self.completion.page_digest()
    }

    /// Sealed bytes produced by this page.
    #[must_use]
    pub fn total_sealed_bytes(&self) -> u64 {
        self.completion.sealed_bytes()
    }

    /// Observed page completion for denominator accounting.
    #[must_use]
    pub fn completion(&self) -> &PageCompletion {
        &self.completion
    }
}

/// Exports one bounded page through the real Blob owners.
///
/// Reads each covered member's plaintext through `fetch` — the production
/// read half owned by the caller — seals it through the real key/AEAD ports
/// with operation-bound derived seal context, and accounts exact cumulative
/// totals against the fence. A refusal at any member stops the page and
/// preserves the sealed prefix as [`PageInterrupt`] evidence; the failed
/// member and every later member stay unsealed and unclaimed.
///
/// # Errors
///
/// Returns [`PageInterrupt`] carrying the completed prefix, the exact failed
/// fence index, and the typed cause.
fn seal_fetched_member(
    key_port: &mut dyn BlobKeyPort,
    aead: &mut dyn BlobAeadPort,
    fence: &BlobBackupFence,
    page: &BlobBackupPage,
    locator: &BlobLocator,
    member_index: usize,
    plaintext: &[u8],
) -> Result<SealedMember, BlobError> {
    let Ok(plaintext_len) = u64::try_from(plaintext.len()) else {
        return Err(BlobError::InvalidField {
            field: "capture.plaintext",
            reason: "member length overflows",
        });
    };
    if plaintext_len > fence.max_bytes_per_member() {
        return Err(BlobError::InvalidField {
            field: "capture.plaintext",
            reason: "member exceeds the fenced per-member bound",
        });
    }
    seal_member(
        key_port,
        aead,
        locator,
        &seal_nonce_context(fence.operation_id(), page.page_index(), member_index),
        &seal_associated_data(fence.operation_id(), locator),
        plaintext,
    )
}

fn add_sealed_total(
    running: u64,
    sealed_len: u64,
    ceiling: u64,
) -> Result<u64, BlobError> {
    let running = running.checked_add(sealed_len).ok_or(BlobError::InvalidField {
        field: "backup_page.bounds",
        reason: "sealed byte totals overflow",
    })?;
    if running > ceiling {
        return Err(BlobError::InvalidField {
            field: "backup_page.bounds",
            reason: "page exceeds the fenced total byte bound",
        });
    }
    Ok(running)
}

pub fn export_page(
    key_port: &mut dyn BlobKeyPort,
    aead: &mut dyn BlobAeadPort,
    fence: &BlobBackupFence,
    page: &BlobBackupPage,
    fetch: &mut PlaintextFetch,
) -> Result<ExportedPage, PageInterrupt> {
    let interrupt = |completed: Vec<SealedMember>, failed_index: usize, cause: BlobError| {
        PageInterrupt {
            completed,
            failed_index,
            cause,
        }
    };
    let expected_digest = page
        .page_digest(fence)
        .map_err(|cause| interrupt(Vec::new(), page.start_index(), cause))?;
    let mut members = Vec::with_capacity(page.member_count());
    let mut sealed_running = page.cumulative_bytes_before();
    for (position, index) in page.member_indexes().iter().enumerate() {
        let member_position = page.start_index() + position;
        let Some(fenced) = fence.member(*index) else {
            return Err(interrupt(
                members,
                member_position,
                BlobError::InvalidField {
                    field: "backup_page.window",
                    reason: "page window escapes the fenced denominator",
                },
            ));
        };
        let locator = fenced.locator();
        let plaintext = fetch(locator).map_err(|cause| {
            interrupt(std::mem::take(&mut members), member_position, cause)
        })?;
        let sealed = match seal_fetched_member(
            key_port,
            aead,
            fence,
            page,
            locator,
            *index,
            &plaintext,
        ) {
            Ok(sealed) => sealed,
            Err(cause) => return Err(interrupt(members, member_position, cause)),
        };
        match add_sealed_total(
            sealed_running,
            sealed.sealed_bytes().len() as u64,
            fence.max_total_sealed_bytes(),
        ) {
            Ok(total) => sealed_running = total,
            Err(cause) => return Err(interrupt(members, member_position, cause)),
        }
        members.push(sealed);
    }
    let total_sealed_bytes = sealed_running - page.cumulative_bytes_before();
    let completion = PageCompletion::for_page(page, fence, total_sealed_bytes).map_err(
        |cause| interrupt(std::mem::take(&mut members), page.end_index(), cause),
    )?;
    debug_assert_eq!(completion.page_digest(), expected_digest.as_str());
    Ok(ExportedPage {
        page: page.clone(),
        members,
        completion,
    })
}

/// Completes one export over fully-verified pages.
///
/// Gathers every page record and completion and issues the contract receipt
/// through [`BlobBackupCompletionReceipt::complete`], which re-verifies full
/// denominator coverage, record validity, page-chain continuity, and the
/// single-residency scope binding. Anything short of the full verified set
/// refuses here; cancellation evidence stays a [`PageInterrupt`]/partial,
/// never a receipt.
///
/// # Errors
///
/// Returns denominator-coverage, record-validity, chain, scope-binding, or
/// bound errors.
pub fn complete_export(
    fence: &BlobBackupFence,
    pages: &[ExportedPage],
    scope: &BlobBackupScope,
) -> Result<BlobBackupCompletionReceipt, BlobError> {
    let records: Vec<SealedBlobCaptureRecord> = pages
        .iter()
        .flat_map(|page| page.members.iter().map(|member| member.record.clone()))
        .collect();
    let completions: Vec<PageCompletion> = pages
        .iter()
        .map(|page| page.completion.clone())
        .collect();
    BlobBackupCompletionReceipt::complete(fence, &records, &completions, scope)
}

/// Restore binding for one sealed member: exactly the lookup keys the F
/// restore blob channel consumes.
///
/// Consumer wiring (read-only reference, F lane frozen branch
/// `work/960-kernel-restore-adapter`, files not edited here):
/// `bins/eliot-kernel/src/backup_restore.rs:239` declares
/// `BlobOwnerClient` holding backup-bound restoration receipts, the admitted
/// key manifest, and `&DestinationScope`; `bind` refuses a missing scope
/// with `BLOB_SCOPE_BINDING` (`backup_restore.rs:245-268`); `restore_blob`
/// locates the receipt by `receipt.blob_hash == blob.locator.hash` and calls
/// `DestinationRestoreAdapter::restore_blob_sealed`. This binding carries
/// that lookup key (`blob_hash`), the envelope/plaintext digests the adapter
/// re-verifies, the crypto descriptor bound to the residency key lineage,
/// and the residency digest pinned to the admitted destination scope. The
/// field correspondence to `DestinationScope` is structural and documented:
/// `dest_key_lineage`/`dest_key_generation` name the same destination key
/// binding; no second scope type is introduced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreBinding {
    blob_hash: String,
    sealed_sha256: String,
    plaintext_sha256: String,
    crypto: CryptoDescriptor,
    residency_digest: String,
}

impl RestoreBinding {
    /// Receipt-lookup key: the captured locator hash.
    #[must_use]
    pub fn blob_hash(&self) -> &str {
        &self.blob_hash
    }

    /// Sealed-envelope digest the restore adapter re-verifies.
    #[must_use]
    pub fn sealed_sha256(&self) -> &str {
        &self.sealed_sha256
    }

    /// Plaintext digest the restore adapter re-verifies after open.
    #[must_use]
    pub fn plaintext_sha256(&self) -> &str {
        &self.plaintext_sha256
    }

    /// Envelope crypto descriptor bound to the residency key lineage.
    #[must_use]
    pub fn crypto(&self) -> &CryptoDescriptor {
        &self.crypto
    }

    /// Residency digest pinned to the admitted destination scope.
    #[must_use]
    pub fn residency_digest(&self) -> &str {
        &self.residency_digest
    }
}

/// Binds verified capture records to the admitted destination scope for the
/// F restore blob channel.
///
/// Re-verifies the scope against the live lease/crypto/residency through the
/// real key port (proving the destination owner holds the admitted lineage),
/// then verifies every record and requires each one to sit under the scope's
/// residency domain. A foreign-domain record fails the set closed — it is
/// never silently dropped and never smuggled into another scope.
///
/// # Errors
///
/// Returns scope, record-validity, or domain-binding errors.
pub fn bind_restore_set(
    key_port: &dyn BlobKeyPort,
    scope: &BlobBackupScope,
    lease: &BlobRootLease,
    crypto: &CryptoDescriptor,
    residency: &ObjectResidencyKey,
    records: &[SealedBlobCaptureRecord],
) -> Result<Vec<RestoreBinding>, BlobError> {
    let selection = verify_destination_scope(key_port, scope, lease, crypto, residency)?;
    if selection.crypto != *crypto {
        return Err(BlobError::IntegrityMismatch);
    }
    let mut bindings = Vec::with_capacity(records.len());
    for record in records {
        record.validate()?;
        if record.residency_digest() != scope.residency_digest() {
            return Err(BlobError::IntegrityMismatch);
        }
        bindings.push(RestoreBinding {
            blob_hash: record.locator().hash.as_str().to_owned(),
            sealed_sha256: record.sealed_sha256().to_owned(),
            plaintext_sha256: record.plaintext_sha256().to_owned(),
            crypto: record.crypto().clone(),
            residency_digest: record.residency_digest().to_owned(),
        });
    }
    Ok(bindings)
}

/// Consumer evidence pack: everything the F restore blob channel needs from
/// one completed capture, assembled and verified on the owner side.
///
/// Field contract verified read-only against the frozen F lane
/// (`work/960-kernel-restore-adapter`, files not edited here):
///   - `bindings[].blob_hash` feeds `BlobOwnerClient::restore_blob`
///     (`backup_restore.rs:245-283`) receipt lookup
///     (`receipt.blob_hash == blob.locator.hash`);
///   - `bindings[].crypto.key_lineage` feeds both `BackupBlob.key_lineage`
///     (`eliot-backup/src/lib.rs:316`, validated `crypto.key_lineage ==
///     key_lineage`) and `BlobRestorationReceipt.key_lineage`
///     (`portable_recovery.rs`, checked equal to the blob lineage before
///     open);
///   - `bindings[].sealed_sha256` / `.plaintext_sha256` feed the digests
///     `DestinationRestoreAdapter::restore_blob_sealed` re-verifies
///     (`owner_adapters.rs:338`);
///   - `dest_key_lineage` / `dest_key_generation` name the exact
///     `DestinationScope` binding (`owner_adapters.rs:61`) whose absence F
///     refuses with `BLOB_SCOPE_BINDING`; `scope_residency_digest` pins every
///     binding to that scope's residency domain.
///
/// Archive-format framing (`BackupBlob.format`/`format_version`,
/// `compression`) is owned by the #948 bundle layer, not the blob capture
/// owner: the pack hands the bundle builder locator, envelope bytes,
/// digests, and lineage-bound crypto, and the bundle layer adds its own
/// format envelope. The future #975 Store wire wraps this pack as its
/// backend response: operation id, per-residency dispositions
/// (bytes/digest/domain), completion receipt, and scope binding travel in
/// the wire; the wire adds transport identity and never re-derives a digest.
///
/// Wire handoff (read-only reference, wire branch `work/950-975-store-wire`,
/// tip `5b6877b4`, files not edited here): the store channel carries its own
/// `StoreEvidencePack` (`eliot-store-api/src/backup_io.rs`) mirroring this
/// pack's shape in store-neutral vocabulary — receipt, bindings,
/// destination installation/store ids, scope residency digest — over
/// store-canonical members, while this pack serves the sealed-blob channel
/// over envelope members. The two channels share no code dependency
/// (`eliot-store-api` does not depend on `eliot-blob-api`) and meet only at
/// the Kernel capture coordinator: the blob pack's `blob_hash`,
/// `sealed_sha256`, `plaintext_sha256`, lineage-bound `crypto`, and
/// `scope_residency_digest` correspond to the store pack's member digest,
/// content digest, and residency digest slots with envelope semantics
/// preserved, and destination installation/store identity stays with the
/// wire/coordinator owners on both sides.
#[derive(Clone, Debug)]
pub struct ConsumerEvidencePack {
    receipt: BlobBackupCompletionReceipt,
    bindings: Vec<RestoreBinding>,
    dest_key_lineage: BlobId,
    dest_key_generation: u64,
    dest_root_generation: u64,
    scope_residency_digest: String,
}

impl ConsumerEvidencePack {
    /// Assembles the pack from a completed export. Re-checks receipt↔binding
    /// consistency here: member counts match, every binding sits under the
    /// scope residency digest named by the receipt, and the destination key
    /// binding equals the scope the receipt was completed against.
    pub fn assemble(
        receipt: BlobBackupCompletionReceipt,
        bindings: Vec<RestoreBinding>,
        scope: &BlobBackupScope,
    ) -> Result<Self, BlobError> {
        if receipt.member_count() != bindings.len() {
            return Err(BlobError::IntegrityMismatch);
        }
        if receipt.scope_residency_digest() != scope.residency_digest() {
            return Err(BlobError::IntegrityMismatch);
        }
        for binding in &bindings {
            if binding.residency_digest() != scope.residency_digest() {
                return Err(BlobError::IntegrityMismatch);
            }
        }
        Ok(Self {
            receipt,
            bindings,
            dest_key_lineage: scope.dest_key_lineage().clone(),
            dest_key_generation: scope.dest_key_generation(),
            dest_root_generation: scope.dest_root_generation(),
            scope_residency_digest: scope.residency_digest().to_owned(),
        })
    }

    /// Completion receipt over the fully-verified export.
    #[must_use]
    pub fn receipt(&self) -> &BlobBackupCompletionReceipt {
        &self.receipt
    }

    /// Per-member restore bindings in fence order.
    #[must_use]
    pub fn bindings(&self) -> &[RestoreBinding] {
        &self.bindings
    }

    /// Destination key lineage the consumer's `DestinationScope` must carry.
    #[must_use]
    pub fn dest_key_lineage(&self) -> &BlobId {
        &self.dest_key_lineage
    }

    /// Destination key generation the consumer's `DestinationScope` must carry.
    #[must_use]
    pub fn dest_key_generation(&self) -> u64 {
        self.dest_key_generation
    }

    /// Destination root generation the scope was issued against.
    #[must_use]
    pub fn dest_root_generation(&self) -> u64 {
        self.dest_root_generation
    }

    /// Residency domain every binding is pinned to.
    #[must_use]
    pub fn scope_residency_digest(&self) -> &str {
        &self.scope_residency_digest
    }
}

/// Terminal outcome of one bounded capture run.
///
/// `Completed` carries only fully-verified evidence: the chained completion
/// receipt plus the consumer pack. `Interrupted` carries cancellation
/// evidence — the verified page prefix as a partial, observed staging
/// totals, and the exact failure point — and no receipt. A stage refusal
/// after bytes left the owner is reported with the staged totals observed so
/// far; transport delivery is never presented as durable success.
#[derive(Debug)]
pub enum CaptureOutcome {
    Completed {
        receipt: BlobBackupCompletionReceipt,
        evidence: ConsumerEvidencePack,
        staged_members: u64,
        staged_bytes: u64,
    },
    Interrupted {
        partial: BlobBackupPartial,
        staged_members: u64,
        staged_bytes: u64,
        failed_page_index: u32,
        failed_fence_index: usize,
        cause: BlobError,
    },
}

fn mint_run_trust(
    ports: &mut CapturePorts<'_>,
    fence: &BlobBackupFence,
    scope: &BlobBackupScope,
    lease: &BlobRootLease,
    owner: Option<&BlobRootOwner>,
) -> Result<CaptureTrustRoot, BlobError> {
    let selection = ports.key_port.current()?;
    CaptureTrustRoot::mint(fence.operation_id(), &selection, owner, lease, scope)
}

fn interrupt_outcome(
    fence: &BlobBackupFence,
    done: &[ExportedPage],
    staged_members: u64,
    staged_bytes: u64,
    failed_page_index: u32,
    failed_fence_index: usize,
    cause: BlobError,
) -> CaptureOutcome {
    let completions: Vec<PageCompletion> =
        done.iter().map(|page| page.completion().clone()).collect();
    // Executed pages chain by construction, so the full prefix always
    // cancels; the empty fallback covers only the impossible contradiction.
    #[allow(
        clippy::expect_used,
        reason = "empty page prefix chains trivially; reached only if executed pages contradict their own digests"
    )]
    let partial = BlobBackupPartial::cancel_after(fence, completions).unwrap_or_else(|_| {
        BlobBackupPartial::cancel_after(fence, Vec::new()).expect("empty prefix always cancels")
    });
    CaptureOutcome::Interrupted {
        partial,
        staged_members,
        staged_bytes,
        failed_page_index,
        failed_fence_index,
        cause,
    }
}

struct PageProgress {
    staged_members: u64,
    staged_bytes: u64,
}

fn verify_and_stage_page(
    ports: &mut CapturePorts<'_>,
    fence: &BlobBackupFence,
    scope: &BlobBackupScope,
    page: &BlobBackupPage,
    exported: &ExportedPage,
    stage: &mut SealedStage,
    progress: &mut PageProgress,
) -> Result<(), (usize, BlobError)> {
    for (position, member) in exported.members().iter().enumerate() {
        let fence_index = page.start_index() + position;
        let opened = open_member(
            &*ports.key_port,
            &*ports.aead,
            member.record(),
            member.sealed_bytes(),
            &seal_nonce_context(fence.operation_id(), page.page_index(), fence_index),
            &seal_associated_data(fence.operation_id(), member.record().locator()),
        )
        .map_err(|cause| (fence_index, cause))?;
        drop(opened);
        let binding = RestoreBinding {
            blob_hash: member.record().locator().hash.as_str().to_owned(),
            sealed_sha256: member.record().sealed_sha256().to_owned(),
            plaintext_sha256: member.record().plaintext_sha256().to_owned(),
            crypto: member.record().crypto().clone(),
            residency_digest: member.record().residency_digest().to_owned(),
        };
        if binding.residency_digest() != scope.residency_digest() {
            return Err((fence_index, BlobError::IntegrityMismatch));
        }
        stage(&binding, member.sealed_bytes()).map_err(|cause| (fence_index, cause))?;
        progress.staged_members += 1;
        progress.staged_bytes += member.sealed_bytes().len() as u64;
    }
    Ok(())
}

fn export_run_page(
    ports: &mut CapturePorts<'_>,
    fence: &BlobBackupFence,
    done: &[ExportedPage],
    page_index: u32,
    start: usize,
    window: usize,
    fetch: &mut PlaintextFetch,
) -> Result<ExportedPage, (u32, usize, BlobError)> {
    let predecessor = done
        .last()
        .map_or(BLOB_BACKUP_GENESIS.to_owned(), |page| {
            page.page_digest().to_owned()
        });
    let cumulative_members: u64 = done.iter().map(|page| page.members().len() as u64).sum();
    let cumulative_bytes: u64 = done.iter().map(ExportedPage::total_sealed_bytes).sum();
    let page = match BlobBackupPage::open(
        fence,
        page_index,
        start,
        window,
        predecessor,
        cumulative_members,
        cumulative_bytes,
    ) {
        Ok(page) => page,
        Err(cause) => return Err((page_index, start, cause)),
    };
    match export_page(
        &mut *ports.key_port,
        &mut *ports.aead,
        fence,
        &page,
        fetch,
    ) {
        Ok(exported) => Ok(exported),
        Err(interrupt) => Err((
            page_index,
            interrupt.failed_index(),
            interrupt.cause().clone(),
        )),
    }
}

fn finalize_capture(
    key_port: &dyn BlobKeyPort,
    fence: &BlobBackupFence,
    scope: &BlobBackupScope,
    lease: &BlobRootLease,
    crypto: &CryptoDescriptor,
    residency: &ObjectResidencyKey,
    done: &[ExportedPage],
) -> Result<(BlobBackupCompletionReceipt, ConsumerEvidencePack), BlobError> {
    let receipt = complete_export(fence, done, scope)?;
    let records: Vec<SealedBlobCaptureRecord> = done
        .iter()
        .flat_map(|page| {
            page.members()
                .iter()
                .map(|member| member.record().clone())
        })
        .collect();
    let bindings = bind_restore_set(key_port, scope, lease, crypto, residency, &records)?;
    let evidence = ConsumerEvidencePack::assemble(receipt.clone(), bindings, scope)?;
    Ok((receipt, evidence))
}

/// Drives one owner future to completion on the calling task.
///
/// The current owner futures (`BlobStoreService` stage/read/reachability)
/// wrap synchronous core transitions and never yield, so they complete on
/// immediate polls. The loop still bounds polls with cooperative yields: a
/// future that ever stays `Pending` refuses with a typed provider error
/// instead of parking the task or inventing readiness. No executor, no
/// thread blocking, no second completion story.
///
/// # Errors
///
/// Returns the owner's own failure, or [`BlobError::Provider`] when the
/// future yields and therefore requires the composition executor.
pub fn drive_owner<T>(future: BlobFuture<'_, T>) -> Result<T, BlobError> {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = future;
    for _ in 0..16 {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
    Err(BlobError::Provider(
        "owner future yielded; composition executor required".to_owned(),
    ))
}

/// Production plaintext fetch owner: reads fenced members through the real
/// source `BlobStore` client.
///
/// Holds the admitted run-scoped read context and source root lease
/// (composition-minted, caller-held; validated here before any byte moves)
/// plus the live client handle. Each fetch builds the exact validated owner
/// read request from the fenced member's durable metadata binding, drives it
/// through the real client, and verifies the returned chunk through the
/// owner contract — including the chunk's receipt/byte integrity proof.
/// A replaced or drifted payload refuses at the service binding, never
/// seals under the stale fenced identity.
pub struct ServiceFetch<'c> {
    client: &'c dyn BlobStoreClient,
    context: BlobReceiptContext,
    lease: BlobRootLease,
    max_bytes: u64,
}

impl<'c> ServiceFetch<'c> {
    /// Binds the fetch owner. Admission is checked now: the context must
    /// authorize reads, the lease must validate, and the byte bound must be
    /// non-zero — before any member is touched.
    pub fn bind(
        client: &'c dyn BlobStoreClient,
        context: BlobReceiptContext,
        lease: BlobRootLease,
        max_bytes: u64,
    ) -> Result<Self, BlobError> {
        context.validate_for(EffectClass::Read)?;
        lease.validate_context(&context)?;
        lease.validate()?;
        if max_bytes == 0 {
            return Err(BlobError::InvalidField {
                field: "capture_fetch.max_bytes",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            client,
            context,
            lease,
            max_bytes,
        })
    }

    /// Reads one fenced member's plaintext through the real source client.
    /// The returned bytes are caller-owned plaintext for the seal step and
    /// are retained nowhere here.
    pub fn fetch(&self, member: &FencedBlobMember) -> Result<Vec<u8>, BlobError> {
        let request = BlobReadRequest {
            context: self.context.clone(),
            root_lease: self.lease.clone(),
            locator: member.locator().clone(),
            expected_metadata_sha256: member.expected_metadata_sha256().to_owned(),
            expected_ready_receipt_id: member.expected_ready_receipt_id().to_owned(),
            max_bytes: self.max_bytes,
        };
        request.validate()?;
        let chunk: BlobReadChunk = drive_owner(self.client.read(request))?;
        chunk.validate()?;
        if !chunk.is_complete() {
            return Err(BlobError::IntegrityMismatch);
        }
        Ok(chunk.bytes().to_vec())
    }
}

/// Production isolated-destination stager: persists verified sealed members
/// through the real destination platform port.
///
/// Holds the admitted destination root lease (caller-held; validated here)
/// plus the live platform handle and a backup-operation namespace. Each
/// store re-proves the sealed digest over the actual bytes, derives the
/// owner-contained path from the member hash, proves containment against
/// the admitted lease, creates the envelope with the no-replace durable
/// primitive (a replayed member refuses instead of overwriting — the caller
/// reconciles by read-back), and verifies by reading the bytes back and
/// re-proving the digest. Plaintext never reaches this owner: only sealed
/// envelopes plus their digests.
pub struct SubstrateStage<'p, P: BlobPlatformPort + ?Sized> {
    platform: &'p mut P,
    lease: BlobRootLease,
    namespace: String,
    max_bytes: u64,
}

impl<'p, P: BlobPlatformPort + ?Sized> SubstrateStage<'p, P> {
    /// Binds the stager. The lease validates now and the namespace must be
    /// non-blank path-safe text; the platform handle stays borrowed from
    /// the composition owner for the run.
    pub fn bind(
        platform: &'p mut P,
        lease: BlobRootLease,
        namespace: String,
        max_bytes: u64,
    ) -> Result<Self, BlobError> {
        lease.validate()?;
        if namespace.trim().is_empty()
            || namespace.chars().any(char::is_control)
            || namespace.contains(['/', '\\', '.'])
        {
            return Err(BlobError::InvalidField {
                field: "capture_stage.namespace",
                reason: "must be non-blank and free of separators",
            });
        }
        if max_bytes == 0 {
            return Err(BlobError::InvalidField {
                field: "capture_stage.max_bytes",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            platform,
            lease,
            namespace,
            max_bytes,
        })
    }

    fn envelope_path(&self, binding: &RestoreBinding) -> Result<WorkScopePath, BlobError> {
        let path = WorkScopePath::new(format!(
            "backup-export/{}/{}.sealed",
            self.namespace,
            binding.blob_hash()
        ))
        .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        self.platform.prove_contained(&self.lease, &path)?;
        Ok(path)
    }

    /// Stages one verified sealed member to the isolated destination and
    /// proves the write by read-back. Refusals leave prior members intact
    /// and report the exact member; a replayed path refuses at the
    /// no-replace primitive for caller reconciliation.
    pub fn store(
        &mut self,
        binding: &RestoreBinding,
        sealed_bytes: &[u8],
    ) -> Result<(), BlobError> {
        if sealed_bytes.is_empty() {
            return Err(BlobError::InvalidField {
                field: "capture.sealed_bytes",
                reason: "sealed envelope cannot be empty",
            });
        }
        if sealed_bytes.len() as u64 > self.max_bytes {
            return Err(BlobError::InvalidField {
                field: "capture.sealed_bytes",
                reason: "member exceeds the stager byte bound",
            });
        }
        if sha256_hex(sealed_bytes) != binding.sealed_sha256() {
            return Err(BlobError::IntegrityMismatch);
        }
        let path = self.envelope_path(binding)?;
        self.platform.write_new_durable(&path, sealed_bytes)?;
        let stored = self.platform.read_bounded(&path, self.max_bytes)?;
        if sha256_hex(&stored) != binding.sealed_sha256() {
            return Err(BlobError::IntegrityMismatch);
        }
        Ok(())
    }
}

/// First-mint trust root for one capture run (P3a/P3b binding).
///
/// Pins, at run start and from live owner readback only: the operation id,
/// the admitted scope digest, the lease root/lease identities and
/// generation, the CURRENT key selection (fresh `current()` read — never
/// caller text, never invented crypto), and the OS root claim identity read
/// from the live `BlobRootOwner` when one is held. Every later page
/// re-checks currency against the pinned root through the same live
/// handles: a key-lineage rotation, lease drift, heartbeat failure, or root
/// identity change refuses with fence/owner errors instead of mixing
/// generations into one receipt. Same-lineage generation advance stays
/// admissible, and historical envelopes keep resolving through `resolve` —
/// historical key possession is honored for opens while only the pinned
/// current lineage admits new seals.
#[derive(Clone, Debug)]
pub struct CaptureTrustRoot {
    operation_id: String,
    scope_digest: String,
    lease_root_id: String,
    lease_id: String,
    lease_generation: u64,
    key_lineage: BlobId,
    key_generation: u64,
    root_id: Option<String>,
}

impl CaptureTrustRoot {
    /// Mints the trust root from live readback. The key selection must come
    /// from a fresh `current()` call on the run's key port; the owner, when
    /// held, must show no heartbeat failure and must own the presented
    /// lease root. Without a held owner, root-liveness readback is
    /// unavailable and the run carries that ceiling explicitly
    /// (`root_id` stays `None`): composition proof, not a silent pass.
    pub fn mint(
        operation_id: &str,
        selection: &BlobKeySelection,
        owner: Option<&BlobRootOwner>,
        lease: &BlobRootLease,
        scope: &BlobBackupScope,
    ) -> Result<Self, BlobError> {
        valid_operation_text(operation_id, "capture_trust.operation_id")?;
        lease.validate()?;
        selection.crypto.validate()?;
        let root_id = if let Some(owner) = owner {
            if let Some(failure) = owner.heartbeat_failure() {
                return Err(failure);
            }
            if !owner.owns_service_root(lease.root_id.as_str()) {
                return Err(BlobError::OwnerConflict);
            }
            Some(owner.root_id().to_owned())
        } else {
            None
        };
        Ok(Self {
            operation_id: operation_id.to_owned(),
            scope_digest: scope.residency_digest().to_owned(),
            lease_root_id: lease.root_id.as_str().to_owned(),
            lease_id: lease.lease_id.as_str().to_owned(),
            lease_generation: lease.root_generation,
            key_lineage: selection.crypto.key_lineage.clone(),
            key_generation: selection.crypto.key_generation,
            root_id,
        })
    }

    /// Re-checks currency against the pinned root through the live handles.
    /// Lineage rotation, lease drift, heartbeat failure, or a changed root
    /// identity refuses; same-lineage generation advance passes.
    pub fn recheck(
        &self,
        key_port: &mut dyn BlobKeyPort,
        owner: Option<&BlobRootOwner>,
        lease: &BlobRootLease,
    ) -> Result<(), BlobError> {
        lease.validate()?;
        if lease.root_id.as_str() != self.lease_root_id
            || lease.lease_id.as_str() != self.lease_id
            || lease.root_generation != self.lease_generation
        {
            return Err(BlobError::StaleFence);
        }
        if let Some(owner) = owner {
            if let Some(failure) = owner.heartbeat_failure() {
                return Err(failure);
            }
            if !owner.owns_service_root(lease.root_id.as_str()) {
                return Err(BlobError::OwnerConflict);
            }
            if self.root_id.as_deref() != Some(owner.root_id()) {
                return Err(BlobError::StaleFence);
            }
        }
        let current = key_port.current()?;
        if current.crypto.key_lineage != self.key_lineage {
            return Err(BlobError::StaleFence);
        }
        Ok(())
    }

    /// Operation this trust root pins.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Admitted scope digest pinned at mint.
    #[must_use]
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    /// Key lineage pinned at mint; rotations refuse.
    #[must_use]
    pub fn key_lineage(&self) -> &BlobId {
        &self.key_lineage
    }

    /// Key generation observed at mint; advance stays admissible.
    #[must_use]
    pub fn key_generation(&self) -> u64 {
        self.key_generation
    }
}

fn valid_operation_text(value: &str, field: &'static str) -> Result<(), BlobError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(BlobError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        })
    } else {
        Ok(())
    }
}

/// Production capture caller: binds the real owner handles once and runs
/// the bounded driver with first-mint trust.
///
/// This is the in-copy caller side of the backup flow: composition claims
/// the OS root owner, constructs the real key/AEAD ports, admits the
/// lease/crypto/residency bindings, and calls [`ProductionCapture::run`]
/// with the real [`ServiceFetch`]/[`SubstrateStage`] owners behind the
/// fetch/stage seams. The Kernel coordinator (#959) drives this caller;
/// this struct never mints admission itself — every binding validates here
/// before any byte moves.
pub struct ProductionCapture<'a> {
    ports: CapturePorts<'a>,
    owner: Option<&'a BlobRootOwner>,
    lease: BlobRootLease,
    crypto: CryptoDescriptor,
    residency: ObjectResidencyKey,
}

impl<'a> ProductionCapture<'a> {
    /// Binds the production caller. The lease, destination crypto, and
    /// residency validate now; the held OS owner, when present, must show
    /// no heartbeat failure and must own the presented lease root — a
    /// second owner fails fast with `OwnerConflict` before any byte moves.
    /// The lease stays caller-held and prevalidated: this validates, never
    /// mints.
    pub fn bind(
        ports: CapturePorts<'a>,
        owner: Option<&'a BlobRootOwner>,
        lease: BlobRootLease,
        crypto: CryptoDescriptor,
        residency: ObjectResidencyKey,
    ) -> Result<Self, BlobError> {
        lease.validate()?;
        crypto.validate()?;
        residency.validate()?;
        if let Some(owner) = owner {
            if let Some(failure) = owner.heartbeat_failure() {
                return Err(failure);
            }
            if !owner.owns_service_root(lease.root_id.as_str()) {
                return Err(BlobError::OwnerConflict);
            }
        }
        Ok(Self {
            ports,
            owner,
            lease,
            crypto,
            residency,
        })
    }

    /// Runs one bounded capture over the fenced denominator under the
    /// admitted scope, reading through `fetch` and staging through `stage`.
    /// Production callers back those seams with [`ServiceFetch::fetch`] and
    /// [`SubstrateStage::store`]; the trust root mints from a fresh key-port
    /// readback at start and re-checks currency every page.
    pub fn run(
        &mut self,
        fence: &BlobBackupFence,
        scope: &BlobBackupScope,
        fetch: &mut PlaintextFetch,
        stage: &mut SealedStage,
    ) -> CaptureOutcome {
        run_capture(
            &mut self.ports,
            fence,
            scope,
            &self.lease,
            &self.crypto,
            &self.residency,
            self.owner,
            fetch,
            stage,
        )
    }
}

/// Bounded capture driver: walks the fenced denominator page by page through
/// export, import-verification, and destination staging.
///
/// For every page, in order: seal each member through the real key/AEAD
/// owners (`export_page`); import-verify each sealed member by opening it
/// through the real owners with recomputed seal context and proving the
/// plaintext digest (`open_member`); stage each verified member to the
/// isolated destination through `stage`. After the last page, issue the
/// chained completion receipt (`complete_export`), bind the restore set
/// against the admitted scope (`bind_restore_set`), and assemble the
/// consumer pack. Any refusal at any step ends the run as
/// [`CaptureOutcome::Interrupted`] with the verified prefix preserved — the
/// failed page's sealed-but-unverified members are discarded, never staged,
/// never receipted.
///
/// `fetch` is the production plaintext read half owned by the caller;
/// `stage` is the isolated-destination stager owned by the caller (the F
/// lane stages re-sealed bytes into its isolated substrate). `owner`, when
/// held, supplies live root readback: the trust root mints from a fresh
/// key-port selection at start and re-checks lineage, lease, heartbeat, and
/// root identity every page. This driver owns the denominator walk, the
/// seal/verify round-trip, and the evidence — never the live store and
/// never cutover.
#[allow(clippy::too_many_arguments)]
pub fn run_capture(
    ports: &mut CapturePorts<'_>,
    fence: &BlobBackupFence,
    scope: &BlobBackupScope,
    lease: &BlobRootLease,
    crypto: &CryptoDescriptor,
    residency: &ObjectResidencyKey,
    owner: Option<&BlobRootOwner>,
    fetch: &mut PlaintextFetch,
    stage: &mut SealedStage,
) -> CaptureOutcome {
    if let Err(cause) = scope.verify_against(lease, crypto, residency) {
        return interrupt_outcome(fence, &[], 0, 0, 0, 0, cause);
    }
    let trust = match mint_run_trust(ports, fence, scope, lease, owner) {
        Ok(trust) => trust,
        Err(cause) => return interrupt_outcome(fence, &[], 0, 0, 0, 0, cause),
    };
    let mut done: Vec<ExportedPage> = Vec::new();
    let mut staged_members: u64 = 0;
    let mut staged_bytes: u64 = 0;
    let mut start = 0usize;
    let mut page_index = 0u32;
    while start < fence.member_count() {
        if let Err(cause) = trust.recheck(&mut *ports.key_port, owner, lease) {
            return interrupt_outcome(
                fence,
                &done,
                staged_members,
                staged_bytes,
                page_index,
                start,
                cause,
            );
        }
        let remaining = fence.member_count() - start;
        let window = usize::try_from(fence.max_members_per_page())
            .unwrap_or(usize::MAX)
            .min(remaining);
        let exported = match export_run_page(
            ports, fence, &done, page_index, start, window, fetch,
        ) {
            Ok(exported) => exported,
            Err((failed_page, failed_index, cause)) => {
                return interrupt_outcome(
                    fence,
                    &done,
                    staged_members,
                    staged_bytes,
                    failed_page,
                    failed_index,
                    cause,
                );
            }
        };
        let page = exported.page().clone();
        let mut progress = PageProgress {
            staged_members,
            staged_bytes,
        };
        if let Err((fence_index, cause)) =
            verify_and_stage_page(ports, fence, scope, &page, &exported, stage, &mut progress)
        {
            return interrupt_outcome(
                fence,
                &done,
                progress.staged_members,
                progress.staged_bytes,
                page.page_index(),
                fence_index,
                cause,
            );
        }
        staged_members = progress.staged_members;
        staged_bytes = progress.staged_bytes;
        start = page.end_index();
        page_index += 1;
        done.push(exported);
    }
    match finalize_capture(
        &*ports.key_port,
        fence,
        scope,
        lease,
        crypto,
        residency,
        &done,
    ) {
        Ok((receipt, evidence)) => CaptureOutcome::Completed {
            receipt,
            evidence,
            staged_members,
            staged_bytes,
        },
        Err(cause) => interrupt_outcome(
            fence,
            &done,
            staged_members,
            staged_bytes,
            page_index,
            fence.member_count(),
            cause,
        ),
    }
}
