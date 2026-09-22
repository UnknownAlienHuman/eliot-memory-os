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

use eliot_blob_api::{
    BlobError, BlobLocator, BlobRootLease, CryptoDescriptor, ObjectResidencyKey,
    backup_io::{
        BlobBackupCompletionReceipt, BlobBackupFence, BlobBackupPage, BlobBackupScope,
        PageCompletion, SealedBlobCaptureRecord,
    },
};

use super::{AeadOpenRequest, AeadSealRequest, BlobAeadPort, BlobKeyPort, BlobKeySelection};
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
    fetch: &mut dyn FnMut(&BlobLocator) -> Result<Vec<u8>, BlobError>,
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
        let Some(locator) = fence.member(*index) else {
            return Err(interrupt(
                members,
                member_position,
                BlobError::InvalidField {
                    field: "backup_page.window",
                    reason: "page window escapes the fenced denominator",
                },
            ));
        };
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
