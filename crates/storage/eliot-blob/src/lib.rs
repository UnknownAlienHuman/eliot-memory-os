//! C3 S-04 blob implementation over injected platform, codec, key, AEAD and
//! canonical-live-set ports.
//!
//! This crate intentionally contains no direct filesystem or cryptographic
//! implementation. The current P-01 filesystem surface cannot express
//! durable create/replace/no-replace rename plus Windows reparse containment,
//! so those exact obligations are represented by [`BlobPlatformPort`]. A
//! composition lacking that adapter receives a typed `PLAN_GAP`.
//!
//! # Ownership and concurrency
//!
//! [`BlobStoreService`] claims the root exactly once at construction and holds
//! the immutable [`RootOwner`] claim behind one `Arc`. Cloned handles never
//! re-claim a root and never create a second receipt issuer. There is no global
//! state lock: reads overlap through shared platform/codec/key/AEAD locks, and
//! same-content or same-operation identities serialize through striped shard
//! locks. The only process-global lock is the bounded startup root-claim
//! registry; it is not on the blob operation hot path. Blocking
//! filesystem/codec work still executes on the calling task until the P-11
//! task API is admitted (documented blocker).

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use eliot_blob_api::{
    BlobError, BlobFuture, BlobGcReceipt, BlobGcRequest, BlobHash, BlobHealth, BlobId,
    BlobIssuerTrustAnchor, BlobKeyOperation, BlobKeyRecoveryCeiling, BlobLiveSetProof, BlobLocator,
    BlobPolicyBinding, BlobReachabilityRequest, BlobReachabilityView, BlobReadChunk,
    BlobReadRequest, BlobReadyReceipt, BlobReceiptBinding, BlobReceiptContext,
    BlobReferenceObservation, BlobReferenceRequest, BlobRootLease, BlobStageRequest,
    BlobStoreClient, CompressionDescriptor, CryptoDescriptor, GcState, PublishState,
    SignedBlobReceiptWire, VerifiedBlobReceipt, metadata_path, payload_path, verify_receipt,
};
use eliot_platform::WorkScopePath;
use eliot_receipts::{
    ArtifactBinding, ProofCeiling, Receipt, ReceiptCore, ReceiptDisposition, ReceiptKind,
    contract_identity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const FORMAT_ID: &str = "eliot-blob-envelope";
const FORMAT_VERSION: u32 = 1;
const PATH_GENERATION: u32 = 1;
const MAX_BLOB_ENVELOPE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BLOB_PLAINTEXT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 64 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024;
const SHARD_COUNT: usize = 64;
const ROOT_LEASE_FILE: &str = ".eliot-root.lock";
const ROOT_LEASE_VERSION: u32 = 1;
const ROOT_LEASE_HEARTBEAT_MS: u64 = 1_000;
#[cfg(windows)]
const WINDOWS_REPARSE_POINT: u32 = 0x400;
#[cfg(windows)]
const WINDOWS_FILE_SHARE_READ: u32 = 0x0000_0001;

static ROOT_LEASE_TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

/// The process-owned S-04 root claim used by composition roots that do not
/// expose a second Blob service seam. The claim is backed by an OS-visible
/// lease file in the canonical root, so a second process cannot silently own
/// the same root. The owner holds the OS file handle for its full lifetime; a
/// crashed process releases that authority when the OS closes the handle.
/// The process-local set below is only a secondary same-process defense.
#[derive(Clone)]
pub struct BlobRootOwner {
    root_id: String,
    owner_id: BlobId,
    process_id: u32,
    claim_id: String,
    lease: Arc<RootLeaseState>,
}

static PROCESS_ROOT_CLAIMS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

#[derive(Debug, Deserialize, Serialize)]
struct RootLeaseRecord {
    version: u32,
    token: String,
    root_id: String,
    process_id: u32,
    heartbeat_unix_ms: u64,
}

struct RootLeaseState {
    root_id: String,
    lock_path: PathBuf,
    token: String,
    process_id: u32,
    lock_file: Mutex<Option<fs::File>>,
    stop: Arc<AtomicBool>,
    heartbeat: Mutex<Option<JoinHandle<()>>>,
}

#[allow(
    clippy::missing_fields_in_debug,
    reason = "lease authority and synchronization internals must remain absent from Debug output"
)]
impl fmt::Debug for RootLeaseState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootLeaseState")
            .field("root_id", &self.root_id)
            .field("lock_path", &self.lock_path)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RootLeaseState {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(mut heartbeat) = self.heartbeat.lock()
            && let Some(handle) = heartbeat.take()
            && handle.thread().id() != thread::current().id()
        {
            let _ = handle.join();
        }
        // The OS handle is the authority. Dropping it releases the claim;
        // never unlink the lock path, which would reintroduce an unlink race.
        remove_process_claim(&self.root_id);
    }
}

impl fmt::Debug for BlobRootOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlobRootOwner")
            .field("root_id", &self.root_id)
            .field("owner_id", &self.owner_id)
            .field("process_id", &self.process_id)
            .field("claim_id", &self.claim_id)
            .field("lease", &self.lease)
            .finish()
    }
}

impl PartialEq for BlobRootOwner {
    fn eq(&self, other: &Self) -> bool {
        self.root_id == other.root_id
            && self.owner_id == other.owner_id
            && self.process_id == other.process_id
            && self.claim_id == other.claim_id
    }
}

impl Eq for BlobRootOwner {}

impl BlobRootOwner {
    /// Claims exactly one process/root identity. Physical path containment,
    /// encryption and durable publication remain owned by the concrete
    /// `BlobStoreService` platform ports; this identity is not a semantic
    /// write authority.
    pub fn claim(
        root_id: impl Into<String>,
        owner_id: impl Into<String>,
        process_id: u32,
    ) -> Result<Self, BlobError> {
        let configured_root = root_id.into();
        if configured_root.trim().is_empty()
            || configured_root.chars().any(char::is_control)
            || process_id == 0
        {
            return Err(BlobError::InvalidContract(
                "Blob root claim requires a non-blank root and process identity".to_owned(),
            ));
        }
        let owner_id = BlobId::new(owner_id)?;
        let (canonical_path, root_claim_key) = canonical_root(&configured_root)?;
        let (lock_path, token, lock_file) =
            acquire_root_lease(&canonical_path, &root_claim_key, process_id)?;
        let claims = PROCESS_ROOT_CLAIMS.get_or_init(|| Mutex::new(BTreeSet::new()));
        let Ok(mut claims) = claims.lock() else {
            return Err(BlobError::Provider(
                "Blob root claim lock poisoned".to_owned(),
            ));
        };
        if !claims.insert(root_claim_key.clone()) {
            return Err(BlobError::OwnerConflict);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let lease = Arc::new(RootLeaseState {
            root_id: root_claim_key.clone(),
            lock_path,
            token: token.clone(),
            process_id,
            lock_file: Mutex::new(Some(lock_file)),
            stop: Arc::clone(&stop),
            heartbeat: Mutex::new(None),
        });
        let heartbeat_lease = Arc::downgrade(&lease);
        let heartbeat_stop = Arc::clone(&stop);
        let heartbeat = match thread::Builder::new()
            .name("eliot-blob-root-lease".to_owned())
            .spawn(move || heartbeat_root_lease(&heartbeat_lease, &heartbeat_stop))
        {
            Ok(handle) => handle,
            Err(error) => {
                claims.remove(&root_claim_key);
                return Err(BlobError::Provider(format!(
                    "start Blob root lease heartbeat: {error}"
                )));
            }
        };
        let Ok(mut heartbeat_slot) = lease.heartbeat.lock() else {
            claims.remove(&root_claim_key);
            drop(heartbeat);
            return Err(BlobError::Provider(
                "Blob root lease heartbeat lock poisoned".to_owned(),
            ));
        };
        heartbeat_slot.replace(heartbeat);
        drop(heartbeat_slot);
        drop(claims);

        let claim_id =
            format!("process:{process_id}:root:{root_claim_key}:owner:{owner_id}:lease:{token}");
        Ok(Self {
            root_id: root_claim_key.clone(),
            owner_id,
            process_id,
            claim_id,
            lease,
        })
    }

    #[must_use]
    pub fn root_id(&self) -> &str {
        &self.root_id
    }

    #[must_use]
    pub fn owner_id(&self) -> &BlobId {
        &self.owner_id
    }

    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    #[must_use]
    pub fn claim_id(&self) -> &str {
        &self.claim_id
    }
}

fn canonical_root(configured_root: &str) -> Result<(PathBuf, String), BlobError> {
    let configured = PathBuf::from(configured_root);
    reject_reparse_components(&configured)?;
    fs::create_dir_all(&configured).map_err(|error| {
        BlobError::Provider(format!(
            "create configured Blob root {}: {error}",
            configured.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(&configured).map_err(|error| {
        BlobError::Provider(format!(
            "inspect configured Blob root {}: {error}",
            configured.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(BlobError::InvalidContract(
            "Blob root must resolve to a directory".to_owned(),
        ));
    }
    if is_reparse_point(&metadata) {
        return Err(BlobError::InvalidContract(
            "Blob root reparse points are not permitted".to_owned(),
        ));
    }
    let canonical = fs::canonicalize(&configured).map_err(|error| {
        BlobError::Provider(format!(
            "canonicalize configured Blob root {}: {error}",
            configured.display()
        ))
    })?;
    reject_reparse_components(&canonical)?;
    let identity = canonical_identity(&canonical);
    Ok((canonical, identity))
}

fn canonical_identity(path: &Path) -> String {
    let mut identity = path.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        identity.make_ascii_lowercase();
    }
    identity
}

fn reject_reparse_components(path: &Path) -> Result<(), BlobError> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if let Ok(metadata) = fs::symlink_metadata(candidate)
            && is_reparse_point(&metadata)
        {
            return Err(BlobError::InvalidContract(format!(
                "Blob root contains reparse component {}",
                candidate.display()
            )));
        }
        current = candidate.parent();
    }
    Ok(())
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        metadata.file_attributes() & WINDOWS_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn lease_token(process_id: u32) -> String {
    let sequence = ROOT_LEASE_TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{process_id}-{}-{sequence}", now_unix_ms())
}

fn acquire_root_lease(
    root: &Path,
    root_id: &str,
    process_id: u32,
) -> Result<(PathBuf, String, fs::File), BlobError> {
    let lock_path = root.join(ROOT_LEASE_FILE);
    ensure_lock_path_not_reparse(&lock_path)?;
    let token = lease_token(process_id);
    let mut file = open_owned_root_lease(&lock_path)?;
    let record = RootLeaseRecord {
        version: ROOT_LEASE_VERSION,
        token: token.clone(),
        root_id: root_id.to_owned(),
        process_id,
        heartbeat_unix_ms: now_unix_ms(),
    };
    write_lease_record(&mut file, &record).map_err(|error| {
        BlobError::Provider(format!(
            "write Blob root lease {}: {error}",
            lock_path.display()
        ))
    })?;
    Ok((lock_path, token, file))
}

fn ensure_lock_path_not_reparse(lock_path: &Path) -> Result<(), BlobError> {
    match fs::symlink_metadata(lock_path) {
        Ok(metadata) if is_reparse_point(&metadata) => Err(BlobError::InvalidContract(
            "Blob root lease reparse points are not permitted".to_owned(),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BlobError::Provider(format!(
            "inspect Blob root lease {}: {error}",
            lock_path.display()
        ))),
    }
}

#[cfg(windows)]
fn open_owned_root_lease(lock_path: &Path) -> Result<fs::File, BlobError> {
    use std::os::windows::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .create_new(true)
        .read(true)
        .write(true)
        .share_mode(WINDOWS_FILE_SHARE_READ);
    match options.open(lock_path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // A crashed owner leaves the record but not the handle. Opening
            // the existing path read+write with FILE_SHARE_READ transfers
            // ownership; a live owner denies this open.
            let mut existing = OpenOptions::new();
            existing
                .read(true)
                .write(true)
                .share_mode(WINDOWS_FILE_SHARE_READ);
            existing.open(lock_path).map_err(|error| {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::WouldBlock
                ) {
                    BlobError::OwnerConflict
                } else {
                    BlobError::Provider(format!(
                        "open existing Blob root lease {}: {error}",
                        lock_path.display()
                    ))
                }
            })
        }
        Err(error) => Err(BlobError::Provider(format!(
            "create Blob root lease {}: {error}",
            lock_path.display()
        ))),
    }
}

#[cfg(not(windows))]
fn open_owned_root_lease(lock_path: &Path) -> Result<fs::File, BlobError> {
    // The production runtime is native Windows. On other targets, fail closed
    // on an existing path rather than pretending std::fs provides equivalent
    // cross-process write/delete exclusion.
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                BlobError::OwnerConflict
            } else {
                BlobError::Provider(format!(
                    "create Blob root lease {}: {error}",
                    lock_path.display()
                ))
            }
        })
}

fn write_lease_record(file: &mut fs::File, record: &RootLeaseRecord) -> std::io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    serde_json::to_writer(&mut *file, record).map_err(std::io::Error::other)?;
    file.sync_all()
}

fn heartbeat_root_lease(lease: &Weak<RootLeaseState>, stop: &Arc<AtomicBool>) {
    while !stop.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(ROOT_LEASE_HEARTBEAT_MS));
        if stop.load(Ordering::Acquire) {
            break;
        }
        let Some(lease) = lease.upgrade() else {
            break;
        };
        let Ok(mut lock_file) = lease.lock_file.lock() else {
            break;
        };
        let Some(file) = lock_file.as_mut() else {
            break;
        };
        let record = RootLeaseRecord {
            version: ROOT_LEASE_VERSION,
            token: lease.token.clone(),
            root_id: lease.root_id.clone(),
            process_id: lease.process_id,
            heartbeat_unix_ms: now_unix_ms(),
        };
        if write_lease_record(file, &record).is_err() {
            break;
        }
    }
}

fn remove_process_claim(root_id: &str) {
    let Some(claims) = PROCESS_ROOT_CLAIMS.get() else {
        return;
    };
    if let Ok(mut claims) = claims.lock() {
        claims.remove(root_id);
    }
}

/// Proof returned only after the adapter has exclusively claimed a root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootClaimProof {
    pub root_id: String,
    pub owner_id: String,
    pub lease_id: String,
    pub root_generation: u64,
    pub containment_proven: bool,
    pub permissions_proven: bool,
}

impl RootClaimProof {
    fn validate(&self, lease: &BlobRootLease) -> Result<(), BlobError> {
        if self.root_id != lease.root_id.as_str()
            || self.owner_id != lease.owner_id.as_str()
            || self.lease_id != lease.lease_id.as_str()
            || self.root_generation != lease.root_generation
        {
            return Err(BlobError::OwnerConflict);
        }
        if !self.containment_proven || !self.permissions_proven {
            return Err(BlobError::PlanGap(
                "P-01/P-02 root containment or permission proof unavailable".to_owned(),
            ));
        }
        Ok(())
    }
}

/// File state observed through the pinned root handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobPathState {
    Missing,
    File { length: u64, modified_unix_ms: u64 },
    Directory,
    ReparsePoint,
    Other,
}

/// Platform-neutral extension required until P-01 exposes the complete blob
/// durability and reparse-safe publication surface.
pub trait BlobPlatformPort: Send + Sync {
    fn claim_root(&mut self, lease: &BlobRootLease) -> Result<RootClaimProof, BlobError>;
    fn inspect_root(&self, lease: &BlobRootLease) -> Result<RootClaimProof, BlobError>;
    fn prove_contained(&self, lease: &BlobRootLease, path: &WorkScopePath)
    -> Result<(), BlobError>;
    /// Reads at most `max_bytes`; implementations must reject before allocating
    /// or returning byte `max_bytes + 1`.
    fn read_bounded(&self, path: &WorkScopePath, max_bytes: u64) -> Result<Vec<u8>, BlobError>;
    fn write_new_durable(&mut self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError>;
    fn replace_durable(&mut self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError>;
    /// Replaces one durable record only when its exact prior bytes still have
    /// the supplied digest. Providers with an atomic CAS should override this
    /// default; the fallback remains fail-closed on a stale observed digest.
    fn compare_and_replace_durable(
        &mut self,
        path: &WorkScopePath,
        expected_sha256: &str,
        bytes: &[u8],
    ) -> Result<(), BlobError> {
        let current = self.read_bounded(path, MAX_JOURNAL_BYTES)?;
        if sha256_hex(&current) != expected_sha256 {
            return Err(BlobError::PlanGap(
                "durable blob journal CAS revision is stale".to_owned(),
            ));
        }
        self.replace_durable(path, bytes)
    }
    fn rename_no_replace_durable(
        &mut self,
        source: &WorkScopePath,
        destination: &WorkScopePath,
    ) -> Result<(), BlobError>;
    fn remove_durable(&mut self, path: &WorkScopePath) -> Result<(), BlobError>;
    fn stat(&self, path: &WorkScopePath) -> Result<BlobPathState, BlobError>;
    fn list(&self, prefix: &WorkScopePath) -> Result<Vec<WorkScopePath>, BlobError>;
    fn now_unix_ms(&mut self) -> Result<u64, BlobError>;
}

/// Compression provider. `BlobStore` never treats compression as encryption.
pub trait BlobCompressionPort: Send + Sync {
    fn descriptor(&mut self) -> Result<CompressionDescriptor, BlobError>;
    fn compress(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, BlobError>;
    /// Incrementally decodes and aborts before producing `max_output_bytes + 1`.
    fn decompress_bounded(
        &self,
        descriptor: &CompressionDescriptor,
        compressed: &[u8],
        max_output_bytes: u64,
    ) -> Result<Vec<u8>, BlobError>;
}

/// Opaque key selection result. Key bytes are not representable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobKeySelection {
    pub key_ref: BlobId,
    pub crypto: CryptoDescriptor,
}

/// Exact injected key-lineage/rotation port.
pub trait BlobKeyPort: Send + Sync {
    fn current(&mut self) -> Result<BlobKeySelection, BlobError>;
    fn resolve(&self, descriptor: &CryptoDescriptor) -> Result<BlobKeySelection, BlobError>;
}

/// Versioned authenticated-encryption input.
pub struct AeadSealRequest<'a> {
    pub key: &'a BlobKeySelection,
    pub nonce_context: &'a [u8],
    pub associated_data: &'a [u8],
    pub plaintext: &'a [u8],
}

/// Versioned authenticated-decryption input.
pub struct AeadOpenRequest<'a> {
    pub key: &'a BlobKeySelection,
    pub nonce_context: &'a [u8],
    pub associated_data: &'a [u8],
    pub ciphertext: &'a [u8],
}

/// AEAD provider. There is deliberately no plaintext fallback.
pub trait BlobAeadPort: Send + Sync {
    fn seal(&mut self, request: AeadSealRequest<'_>) -> Result<Vec<u8>, BlobError>;
    fn open(&self, request: AeadOpenRequest<'_>) -> Result<Vec<u8>, BlobError>;
}

/// Canonical-owner revalidation result immediately before destructive GC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveSetRevalidation {
    pub proof_id: BlobId,
    pub snapshot_sha256: String,
    pub revision: u64,
    pub still_complete_and_current: bool,
}

/// Provider-observed result of one exact GC deletion effect. The
/// coordinator validates this identity before advancing the durable tombstone;
/// it never constructs a successful effect receipt itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobDeletionReceipt {
    pub operation_id: String,
    pub proof_id: BlobId,
    pub snapshot_sha256: String,
    pub revision: u64,
    pub locator: BlobLocator,
    pub path_digest_sha256: String,
    pub payload_deleted: bool,
    pub metadata_deleted: bool,
}

/// Reconciliation result for a durable GC intent. Unknown never authorizes a
/// blind retry of the physical deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobDeletionReconciliation {
    Applied(BlobDeletionReceipt),
    NotApplied,
    Unknown,
}

/// Runtime port to G-04/S-01 authority. `BlobStore` cannot self-certify reachability.
pub trait BlobLiveSetPort: Send + Sync {
    fn revalidate(&mut self, proof: &BlobLiveSetProof) -> Result<LiveSetRevalidation, BlobError>;

    /// Reconciles an existing deletion intent against the provider target.
    /// Implementations must return `Unknown` when they cannot prove the exact
    /// effect identity and must not perform a blind retry.
    fn reconcile_delete(
        &mut self,
        _operation_id: &str,
        _proof: &BlobLiveSetProof,
        _locator: &BlobLocator,
        _intent_revision: u64,
    ) -> Result<BlobDeletionReconciliation, BlobError> {
        Ok(BlobDeletionReconciliation::Unknown)
    }

    /// Applies one deletion effect while the canonical
    /// compare-and-delete guard is held, returning a target-observed receipt.
    /// The legacy `compare_and_delete` seam remains available, but is not
    /// accepted by the production GC coordinator.
    fn compare_and_delete_observed(
        &mut self,
        _operation_id: &str,
        _proof: &BlobLiveSetProof,
        _locator: &BlobLocator,
        _intent_revision: u64,
        _delete: &mut dyn FnMut() -> Result<(), BlobError>,
    ) -> Result<BlobDeletionReconciliation, BlobError> {
        Err(BlobError::PlanGap(
            "GC target-observed deletion receipt is required".to_owned(),
        ))
    }

    /// Serializes canonical-reference creation against physical deletion and
    /// invokes `delete` while the same compare-and-delete guard is held.
    fn compare_and_delete(
        &mut self,
        _proof: &BlobLiveSetProof,
        _locator: &BlobLocator,
        _delete: &mut dyn FnMut() -> Result<(), BlobError>,
    ) -> Result<ConditionalDeleteOutcome, BlobError> {
        Err(BlobError::PlanGap(
            "legacy GC deletion seam is not accepted without a target receipt".to_owned(),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConditionalDeleteOutcome {
    Deleted,
    RetainedLive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredMetadata {
    receipt: Receipt,
    /// Exact immutable receipt envelope bytes approved by the service verifier.
    receipt_bytes: Vec<u8>,
    locator: BlobLocator,
    plaintext_length: u64,
    stored_length: u64,
    envelope_length: u64,
    plaintext_sha256: String,
    sealed_sha256: String,
    receipt_binding_sha256: String,
    format: BlobId,
    format_version: u32,
    compression: CompressionDescriptor,
    crypto: CryptoDescriptor,
    policy: BlobPolicyBinding,
    operation_id: String,
    idempotency_key: String,
}

impl StoredMetadata {
    fn validate(&self) -> Result<(), BlobError> {
        self.receipt
            .validate()
            .map_err(|error| BlobError::Receipt(error.to_string()))?;
        let signed_wire: SignedBlobReceiptWire = serde_json::from_slice(&self.receipt_bytes)
            .map_err(|error| {
                BlobError::Receipt(format!("stored receipt wire decode failed: {error}"))
            })?;
        let canonical_receipt_bytes = serde_json::to_vec(&signed_wire)
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        if canonical_receipt_bytes != self.receipt_bytes || signed_wire.receipt != self.receipt {
            return Err(BlobError::Receipt(
                "stored receipt bytes do not match the immutable envelope".to_owned(),
            ));
        }
        self.locator.validate()?;
        validate_sha256(&self.plaintext_sha256, "plaintext_sha256")?;
        validate_sha256(&self.sealed_sha256, "sealed_sha256")?;
        validate_sha256(&self.receipt_binding_sha256, "receipt_binding_sha256")?;
        if self.stored_length == 0 || self.stored_length != self.envelope_length {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        if self.plaintext_length > MAX_BLOB_PLAINTEXT_BYTES
            || self.stored_length > MAX_BLOB_ENVELOPE_BYTES
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        if self.format.as_str() != FORMAT_ID || self.format_version != FORMAT_VERSION {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        self.compression.validate()?;
        self.crypto.validate()?;
        self.policy.validate()?;
        let expected = eliot_blob_api::receipt_binding_sha256(
            &self.format,
            self.format_version,
            &self.locator,
            self.plaintext_length,
            self.stored_length,
            &self.plaintext_sha256,
            &self.sealed_sha256,
            &self.compression,
            &self.crypto,
            &self.policy,
        )?;
        if expected != self.receipt_binding_sha256
            || self.receipt.core.artifacts.len() != 2
            || self.receipt.core.artifacts[0].sha256 != self.plaintext_sha256
            || self.receipt.core.artifacts[1].sha256 != self.receipt_binding_sha256
            || self.receipt.core.operation.operation_id.as_str() != self.operation_id.as_str()
            || self.receipt.core.operation.idempotency_key != self.idempotency_key
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        Ok(())
    }

    fn ready(
        &self,
        verified: VerifiedBlobReceipt,
        expected_anchor: &BlobIssuerTrustAnchor,
        metadata_sha256: String,
    ) -> Result<BlobReadyReceipt, BlobError> {
        BlobReadyReceipt::from_verified(
            verified,
            expected_anchor,
            self.locator.clone(),
            self.plaintext_length,
            self.stored_length,
            self.plaintext_sha256.clone(),
            self.sealed_sha256.clone(),
            self.receipt_binding_sha256.clone(),
            metadata_sha256,
            self.format.clone(),
            self.format_version,
            self.compression.clone(),
            self.crypto.clone(),
            self.policy.clone(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageJournal {
    operation_id: String,
    idempotency_key: String,
    state: PublishState,
    temp_payload: WorkScopePath,
    temp_metadata: WorkScopePath,
    final_payload: WorkScopePath,
    final_metadata: WorkScopePath,
    expected_payload_sha256: String,
    expected_metadata_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationCommit {
    operation_id: String,
    idempotency_key: String,
    locator: BlobLocator,
    metadata_sha256: String,
}

impl OperationCommit {
    fn validate(&self) -> Result<(), BlobError> {
        valid_operation_text(&self.operation_id, "commit.operation_id")?;
        valid_operation_text(&self.idempotency_key, "commit.idempotency_key")?;
        self.locator.validate()?;
        validate_sha256(&self.metadata_sha256, "commit.metadata_sha256")
    }
}

impl StageJournal {
    fn validate(&self) -> Result<(), BlobError> {
        valid_operation_text(&self.operation_id, "journal.operation_id")?;
        valid_operation_text(&self.idempotency_key, "journal.idempotency_key")?;
        validate_sha256(&self.expected_payload_sha256, "journal.payload_sha256")?;
        validate_sha256(&self.expected_metadata_sha256, "journal.metadata_sha256")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tombstone {
    operation_id: String,
    revision: u64,
    intent_revision: u64,
    proof_id: BlobId,
    proof_snapshot_sha256: String,
    locator: BlobLocator,
    live_set: BlobLiveSetProof,
    payload: WorkScopePath,
    metadata: WorkScopePath,
    state: GcState,
    receipt: Option<BlobDeletionReceipt>,
}

impl Tombstone {
    fn validate(&self) -> Result<(), BlobError> {
        valid_operation_text(&self.operation_id, "tombstone.operation_id")?;
        if self.revision == 0 || self.intent_revision == 0 || self.intent_revision > self.revision {
            return Err(BlobError::PlanGap(
                "GC tombstone revision is missing".to_owned(),
            ));
        }
        validate_sha256(&self.proof_snapshot_sha256, "tombstone.snapshot_sha256")?;
        self.locator.validate()?;
        self.live_set.validate_complete()?;
        if self.live_set.proof_id != self.proof_id
            || self.live_set.snapshot_sha256 != self.proof_snapshot_sha256
        {
            return Err(BlobError::IncompleteLiveSet);
        }
        if matches!(self.state, GcState::TombstoneCleaned) != self.receipt.is_some() {
            return Err(BlobError::PlanGap(
                "GC tombstone state/receipt mismatch".to_owned(),
            ));
        }
        if let Some(receipt) = &self.receipt {
            validate_deletion_receipt(receipt, self)?;
        }
        Ok(())
    }
}

fn deletion_path_digest(payload: &WorkScopePath, metadata: &WorkScopePath) -> String {
    sha256_hex(format!("{}\n{}", payload.as_str(), metadata.as_str()).as_bytes())
}

fn validate_deletion_receipt(
    receipt: &BlobDeletionReceipt,
    tombstone: &Tombstone,
) -> Result<(), BlobError> {
    valid_operation_text(&receipt.operation_id, "deletion_receipt.operation_id")?;
    validate_sha256(&receipt.snapshot_sha256, "deletion_receipt.snapshot_sha256")?;
    validate_sha256(
        &receipt.path_digest_sha256,
        "deletion_receipt.path_digest_sha256",
    )?;
    receipt.locator.validate()?;
    if receipt.operation_id != tombstone.operation_id
        || receipt.proof_id != tombstone.proof_id
        || receipt.snapshot_sha256 != tombstone.proof_snapshot_sha256
        || receipt.revision != tombstone.intent_revision
        || receipt.locator != tombstone.locator
        || receipt.path_digest_sha256
            != deletion_path_digest(&tombstone.payload, &tombstone.metadata)
        || !receipt.payload_deleted
        || !receipt.metadata_deleted
    {
        return Err(BlobError::MetadataPayloadMismatch);
    }
    Ok(())
}

/// Immutable claimed-root state shared by every cloned service handle.
struct RootOwner {
    lease: BlobRootLease,
    claim: RootClaimProof,
}

/// Striped per-content/per-operation serialization locks. There is no single
/// global mutex; independent identities contend only on their own stripe.
struct ShardLocks {
    locks: [Mutex<()>; SHARD_COUNT],
}

impl ShardLocks {
    fn new() -> Self {
        Self {
            locks: std::array::from_fn(|_| Mutex::new(())),
        }
    }
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn content_shard(hash: &BlobHash) -> usize {
    let bytes = hash.as_str().as_bytes();
    let hi = usize::from(hex_nibble(bytes[0]));
    let lo = usize::from(hex_nibble(bytes[1]));
    (hi * 16 + lo) % SHARD_COUNT
}

fn operation_shard(operation_id: &str, idempotency_key: &str) -> usize {
    let mut hasher = Hasher::new();
    hasher.update(operation_id.as_bytes());
    hasher.update(idempotency_key.as_bytes());
    let bytes = hasher.finalize();
    let hi = usize::from(bytes.as_bytes()[0]);
    let lo = usize::from(bytes.as_bytes()[1]);
    (hi * 16 + lo) % SHARD_COUNT
}

struct BlobStoreCore<P, C, K, A, L> {
    owner: RootOwner,
    platform: RwLock<P>,
    compression: RwLock<C>,
    keys: RwLock<K>,
    aead: RwLock<A>,
    live_sets: Mutex<L>,
    shards: ShardLocks,
    issuer_anchor: BlobIssuerTrustAnchor,
}

impl<P, C, K, A, L> BlobStoreCore<P, C, K, A, L>
where
    P: BlobPlatformPort,
    C: BlobCompressionPort,
    K: BlobKeyPort,
    A: BlobAeadPort,
    L: BlobLiveSetPort,
{
    fn claim(
        lease: BlobRootLease,
        mut platform: P,
        compression: C,
        keys: K,
        aead: A,
        live_sets: L,
        issuer_anchor: BlobIssuerTrustAnchor,
    ) -> Result<Self, BlobError> {
        lease.validate()?;
        let claim = platform.claim_root(&lease)?;
        claim.validate(&lease)?;
        Ok(Self {
            owner: RootOwner { lease, claim },
            platform: RwLock::new(platform),
            compression: RwLock::new(compression),
            keys: RwLock::new(keys),
            aead: RwLock::new(aead),
            live_sets: Mutex::new(live_sets),
            shards: ShardLocks::new(),
            issuer_anchor,
        })
    }

    fn lock_shards(&self, indices: &[usize]) -> Result<Vec<MutexGuard<'_, ()>>, BlobError> {
        let mut unique = indices.to_vec();
        unique.sort_unstable();
        unique.dedup();
        unique
            .into_iter()
            .map(|index| {
                self.shards.locks[index]
                    .lock()
                    .map_err(|_| BlobError::Provider("blob shard lock poisoned".to_owned()))
            })
            .collect()
    }

    fn platform_read(&self) -> Result<RwLockReadGuard<'_, P>, BlobError> {
        self.platform
            .read()
            .map_err(|_| BlobError::Provider("blob platform lock poisoned".to_owned()))
    }

    fn platform_write(&self) -> Result<RwLockWriteGuard<'_, P>, BlobError> {
        self.platform
            .write()
            .map_err(|_| BlobError::Provider("blob platform lock poisoned".to_owned()))
    }

    fn platform_stat(&self, path: &WorkScopePath) -> Result<BlobPathState, BlobError> {
        self.platform_read()?.stat(path)
    }

    fn platform_read_bounded(
        &self,
        path: &WorkScopePath,
        max_bytes: u64,
    ) -> Result<Vec<u8>, BlobError> {
        self.platform_read()?.read_bounded(path, max_bytes)
    }

    fn platform_list(&self, prefix: &WorkScopePath) -> Result<Vec<WorkScopePath>, BlobError> {
        self.platform_read()?.list(prefix)
    }

    fn platform_write_new(&self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
        self.platform_write()?.write_new_durable(path, bytes)
    }

    fn platform_replace(&self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
        self.platform_write()?.replace_durable(path, bytes)
    }

    fn platform_compare_and_replace(
        &self,
        path: &WorkScopePath,
        expected_sha256: &str,
        bytes: &[u8],
    ) -> Result<(), BlobError> {
        self.platform_write()?
            .compare_and_replace_durable(path, expected_sha256, bytes)
    }

    fn platform_rename(
        &self,
        source: &WorkScopePath,
        destination: &WorkScopePath,
    ) -> Result<(), BlobError> {
        self.platform_write()?
            .rename_no_replace_durable(source, destination)
    }

    fn platform_remove(&self, path: &WorkScopePath) -> Result<(), BlobError> {
        self.platform_write()?.remove_durable(path)
    }

    fn platform_now_ms(&self) -> Result<u64, BlobError> {
        self.platform_write()?.now_unix_ms()
    }

    fn compression_descriptor(&self) -> Result<CompressionDescriptor, BlobError> {
        self.compression
            .write()
            .map_err(|_| BlobError::Provider("blob compression lock poisoned".to_owned()))?
            .descriptor()
    }

    fn compression_compress(&self, plaintext: &[u8]) -> Result<Vec<u8>, BlobError> {
        self.compression
            .write()
            .map_err(|_| BlobError::Provider("blob compression lock poisoned".to_owned()))?
            .compress(plaintext)
    }

    fn compression_decompress(
        &self,
        descriptor: &CompressionDescriptor,
        compressed: &[u8],
        max_output_bytes: u64,
    ) -> Result<Vec<u8>, BlobError> {
        self.compression
            .read()
            .map_err(|_| BlobError::Provider("blob compression lock poisoned".to_owned()))?
            .decompress_bounded(descriptor, compressed, max_output_bytes)
    }

    fn keys_current(&self) -> Result<BlobKeySelection, BlobError> {
        self.keys
            .write()
            .map_err(|_| BlobError::Provider("blob key lock poisoned".to_owned()))?
            .current()
    }

    fn keys_resolve(&self, descriptor: &CryptoDescriptor) -> Result<BlobKeySelection, BlobError> {
        self.keys
            .read()
            .map_err(|_| BlobError::Provider("blob key lock poisoned".to_owned()))?
            .resolve(descriptor)
    }

    fn aead_seal(&self, request: AeadSealRequest<'_>) -> Result<Vec<u8>, BlobError> {
        self.aead
            .write()
            .map_err(|_| BlobError::Provider("blob AEAD lock poisoned".to_owned()))?
            .seal(request)
    }

    fn aead_open(&self, request: AeadOpenRequest<'_>) -> Result<Vec<u8>, BlobError> {
        self.aead
            .read()
            .map_err(|_| BlobError::Provider("blob AEAD lock poisoned".to_owned()))?
            .open(request)
    }

    fn live_sets_revalidate(
        &self,
        proof: &BlobLiveSetProof,
    ) -> Result<LiveSetRevalidation, BlobError> {
        self.live_sets
            .lock()
            .map_err(|_| BlobError::Provider("blob live-set lock poisoned".to_owned()))?
            .revalidate(proof)
    }

    fn live_sets_reconcile_delete(
        &self,
        operation_id: &str,
        proof: &BlobLiveSetProof,
        locator: &BlobLocator,
        intent_revision: u64,
    ) -> Result<BlobDeletionReconciliation, BlobError> {
        self.live_sets
            .lock()
            .map_err(|_| BlobError::Provider("blob live-set lock poisoned".to_owned()))?
            .reconcile_delete(operation_id, proof, locator, intent_revision)
    }

    fn live_sets_compare_and_delete_observed(
        &self,
        operation_id: &str,
        proof: &BlobLiveSetProof,
        locator: &BlobLocator,
        intent_revision: u64,
        delete: &mut dyn FnMut() -> Result<(), BlobError>,
    ) -> Result<BlobDeletionReconciliation, BlobError> {
        self.live_sets
            .lock()
            .map_err(|_| BlobError::Provider("blob live-set lock poisoned".to_owned()))?
            .compare_and_delete_observed(operation_id, proof, locator, intent_revision, delete)
    }

    fn ensure_lease(&self, lease: &BlobRootLease) -> Result<(), BlobError> {
        lease.validate()?;
        if lease.root_id != self.owner.lease.root_id
            || lease.owner_id != self.owner.lease.owner_id
            || lease.lease_id != self.owner.lease.lease_id
            || lease.root_generation != self.owner.lease.root_generation
            || lease.fence_binding.state_fence != self.owner.lease.fence_binding.state_fence
        {
            return Err(BlobError::StaleFence);
        }
        let observed = self.platform_read()?.inspect_root(lease)?;
        observed.validate(lease)?;
        if observed != self.owner.claim {
            return Err(BlobError::OwnerConflict);
        }
        Ok(())
    }

    fn contained(&self, path: &WorkScopePath) -> Result<(), BlobError> {
        if path.adapter_input().normalized_identity != path.normalized_identity() {
            return Err(BlobError::InvalidContract(
                "P-01 canonical path identity changed".to_owned(),
            ));
        }
        self.platform_read()?
            .prove_contained(&self.owner.lease, path)
    }

    fn read_bounded_file(
        &self,
        path: &WorkScopePath,
        hard_ceiling: u64,
    ) -> Result<Vec<u8>, BlobError> {
        self.contained(path)?;
        let BlobPathState::File { length, .. } = self.platform_stat(path)? else {
            return Err(BlobError::NotFound);
        };
        if length > hard_ceiling {
            return Err(BlobError::InvalidContract(format!(
                "{} exceeds canonical {} byte ceiling",
                path.normalized_identity(),
                hard_ceiling
            )));
        }
        let bytes = self.platform_read_bounded(path, hard_ceiling)?;
        if bytes.len() as u64 != length || bytes.len() as u64 > hard_ceiling {
            return Err(BlobError::IntegrityMismatch);
        }
        Ok(bytes)
    }

    fn load_metadata(&self, locator: &BlobLocator) -> Result<(StoredMetadata, Vec<u8>), BlobError> {
        let path = metadata_path(locator)?;
        self.contained(&path)?;
        let bytes = self.read_bounded_file(&path, MAX_METADATA_BYTES)?;
        let metadata: StoredMetadata =
            serde_json::from_slice(&bytes).map_err(|_| BlobError::MetadataPayloadMismatch)?;
        metadata.validate()?;
        if metadata.locator != *locator {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        Ok((metadata, bytes))
    }

    fn verify_metadata_receipt(
        &self,
        metadata: &StoredMetadata,
    ) -> Result<VerifiedBlobReceipt, BlobError> {
        let context = context_from_receipt(&metadata.receipt);
        let binding = BlobReceiptBinding::for_blob(&context, &metadata.locator)?;
        verify_receipt(&self.issuer_anchor, &metadata.receipt_bytes, binding)
    }

    fn exact_bytes_at(
        &self,
        path: &WorkScopePath,
        expected_sha256: &str,
        hard_ceiling: u64,
    ) -> Result<bool, BlobError> {
        self.contained(path)?;
        match self.platform_stat(path)? {
            BlobPathState::File { .. } => {
                Ok(sha256_hex(&self.read_bounded_file(path, hard_ceiling)?) == expected_sha256)
            }
            BlobPathState::Missing => Ok(false),
            BlobPathState::ReparsePoint => Err(BlobError::PlanGap(
                "P-02 reparse-safe containment proof rejected a blob component".to_owned(),
            )),
            BlobPathState::Directory | BlobPathState::Other => {
                Err(BlobError::MetadataPayloadMismatch)
            }
        }
    }

    fn publish_or_verify(
        &self,
        source: &WorkScopePath,
        destination: &WorkScopePath,
        expected_sha256: &str,
        hard_ceiling: u64,
        operation_id: &str,
        state_before: PublishState,
    ) -> Result<(), BlobError> {
        self.contained(source)?;
        self.contained(destination)?;
        match self.platform_rename(source, destination) {
            Ok(()) => {
                if self.exact_bytes_at(destination, expected_sha256, hard_ceiling)? {
                    Ok(())
                } else {
                    Err(BlobError::UnknownPublishOutcome {
                        operation_id: operation_id.to_owned(),
                        state: state_before,
                    })
                }
            }
            Err(_) if self.exact_bytes_at(destination, expected_sha256, hard_ceiling)? => Ok(()),
            Err(_) => Err(BlobError::UnknownPublishOutcome {
                operation_id: operation_id.to_owned(),
                state: state_before,
            }),
        }
    }

    fn persist_journal(
        &self,
        path: &WorkScopePath,
        journal: &StageJournal,
        replace: bool,
    ) -> Result<(), BlobError> {
        journal.validate()?;
        self.contained(path)?;
        let bytes = serde_json::to_vec(journal)
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        if replace {
            self.platform_replace(path, &bytes)
        } else {
            self.platform_write_new(path, &bytes)
        }
    }

    fn persist_tombstone(
        &self,
        path: &WorkScopePath,
        tombstone: &Tombstone,
        expected_revision: Option<u64>,
    ) -> Result<(), BlobError> {
        tombstone.validate()?;
        self.contained(path)?;
        let current_digest = if let Some(expected) = expected_revision {
            let current_bytes = self.read_bounded_file(path, MAX_JOURNAL_BYTES)?;
            let current: Tombstone = serde_json::from_slice(&current_bytes)
                .map_err(|_| BlobError::MetadataPayloadMismatch)?;
            current.validate()?;
            if current.revision != expected {
                return Err(BlobError::PlanGap(
                    "GC tombstone CAS revision is stale".to_owned(),
                ));
            }
            Some(sha256_hex(&current_bytes))
        } else {
            None
        };
        let bytes = serde_json::to_vec(tombstone)
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        if let Some(current_digest) = current_digest {
            self.platform_compare_and_replace(path, &current_digest, &bytes)
        } else {
            self.platform_write_new(path, &bytes)
        }
    }

    #[allow(clippy::too_many_lines)]
    fn finish_journal(
        &self,
        journal_path: &WorkScopePath,
        journal: &mut StageJournal,
    ) -> Result<(), BlobError> {
        if !self.exact_bytes_at(
            &journal.final_payload,
            &journal.expected_payload_sha256,
            MAX_BLOB_ENVELOPE_BYTES,
        )? {
            if !self.exact_bytes_at(
                &journal.temp_payload,
                &journal.expected_payload_sha256,
                MAX_BLOB_ENVELOPE_BYTES,
            )? {
                return Err(BlobError::UnknownPublishOutcome {
                    operation_id: journal.operation_id.clone(),
                    state: journal.state,
                });
            }
            self.publish_or_verify(
                &journal.temp_payload,
                &journal.final_payload,
                &journal.expected_payload_sha256,
                MAX_BLOB_ENVELOPE_BYTES,
                &journal.operation_id,
                journal.state,
            )?;
        }
        journal.state = PublishState::PayloadDurable;
        self.persist_journal(journal_path, journal, true)?;

        if !self.exact_bytes_at(
            &journal.final_metadata,
            &journal.expected_metadata_sha256,
            MAX_METADATA_BYTES,
        )? {
            if !self.exact_bytes_at(
                &journal.temp_metadata,
                &journal.expected_metadata_sha256,
                MAX_METADATA_BYTES,
            )? {
                return Err(BlobError::UnknownPublishOutcome {
                    operation_id: journal.operation_id.clone(),
                    state: journal.state,
                });
            }
            self.publish_or_verify(
                &journal.temp_metadata,
                &journal.final_metadata,
                &journal.expected_metadata_sha256,
                MAX_METADATA_BYTES,
                &journal.operation_id,
                journal.state,
            )?;
        }
        journal.state = PublishState::MetadataDurable;
        self.persist_journal(journal_path, journal, true)?;
        if !self.exact_bytes_at(
            &journal.final_payload,
            &journal.expected_payload_sha256,
            MAX_BLOB_ENVELOPE_BYTES,
        )? || !self.exact_bytes_at(
            &journal.final_metadata,
            &journal.expected_metadata_sha256,
            MAX_METADATA_BYTES,
        )? {
            return Err(BlobError::UnknownPublishOutcome {
                operation_id: journal.operation_id.clone(),
                state: PublishState::MetadataDurable,
            });
        }
        let metadata_bytes = self.read_bounded_file(&journal.final_metadata, MAX_METADATA_BYTES)?;
        let metadata: StoredMetadata = serde_json::from_slice(&metadata_bytes)
            .map_err(|_| BlobError::MetadataPayloadMismatch)?;
        metadata.validate()?;
        if sha256_hex(&metadata_bytes) != journal.expected_metadata_sha256
            || metadata.operation_id != journal.operation_id
            || metadata.idempotency_key != journal.idempotency_key
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        let commit = OperationCommit {
            operation_id: journal.operation_id.clone(),
            idempotency_key: journal.idempotency_key.clone(),
            locator: metadata.locator,
            metadata_sha256: journal.expected_metadata_sha256.clone(),
        };
        commit.validate()?;
        let commit_path =
            Self::operation_path_from(&journal.operation_id, &journal.idempotency_key, "commit")?;
        let commit_bytes = serde_json::to_vec(&commit)
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        self.contained(&commit_path)?;
        match self.platform_write_new(&commit_path, &commit_bytes) {
            Ok(()) => {}
            Err(_)
                if self.exact_bytes_at(
                    &commit_path,
                    &sha256_hex(&commit_bytes),
                    MAX_JOURNAL_BYTES,
                )? => {}
            Err(_) => {
                return Err(BlobError::UnknownPublishOutcome {
                    operation_id: journal.operation_id.clone(),
                    state: PublishState::MetadataDurable,
                });
            }
        }
        journal.state = PublishState::CommitDurable;
        self.remove_if_present(&journal.temp_payload)?;
        self.remove_if_present(&journal.temp_metadata)?;
        self.remove_if_present(journal_path)?;
        journal.state = PublishState::Cleaned;
        Ok(())
    }

    fn remove_if_present(&self, path: &WorkScopePath) -> Result<(), BlobError> {
        self.contained(path)?;
        if self.platform_stat(path)? == BlobPathState::Missing {
            return Ok(());
        }
        self.platform_remove(path)
    }

    fn reconcile_stage_path(&self, path: &WorkScopePath) -> Result<(), BlobError> {
        self.contained(path)?;
        let bytes = self.read_bounded_file(path, MAX_JOURNAL_BYTES)?;
        let mut journal: StageJournal =
            serde_json::from_slice(&bytes).map_err(|_| BlobError::MetadataPayloadMismatch)?;
        journal.validate()?;
        self.finish_journal(path, &mut journal)
    }

    #[allow(clippy::too_many_lines)]
    fn reconcile_tombstone_path(
        &self,
        path: &WorkScopePath,
    ) -> Result<ConditionalDeleteOutcome, BlobError> {
        self.contained(path)?;
        let bytes = self.read_bounded_file(path, MAX_JOURNAL_BYTES)?;
        let mut tombstone: Tombstone =
            serde_json::from_slice(&bytes).map_err(|_| BlobError::MetadataPayloadMismatch)?;
        tombstone.validate()?;
        if let Some(receipt) = &tombstone.receipt {
            validate_deletion_receipt(receipt, &tombstone)?;
            return Ok(ConditionalDeleteOutcome::Deleted);
        }
        // The live-set authority holds its compare-and-delete guard across the
        // physical effects. Reference creation cannot race between a check and
        // the remove calls.
        if matches!(tombstone.state, GcState::TombstoneDurable) {
            let observed = self.live_sets_revalidate(&tombstone.live_set)?;
            Self::validate_live_set_revalidation(&tombstone.live_set, &observed)?;
            let previous_revision = tombstone.revision;
            tombstone.revision = previous_revision
                .checked_add(1)
                .ok_or_else(|| BlobError::PlanGap("GC tombstone revision overflow".to_owned()))?;
            tombstone.intent_revision = tombstone.revision;
            tombstone.state = GcState::LiveSetRevalidated;
            self.persist_tombstone(path, &tombstone, Some(previous_revision))?;
        }

        let payload = tombstone.payload.clone();
        let metadata = tombstone.metadata.clone();
        let operation_id = tombstone.operation_id.clone();
        let live_set = tombstone.live_set.clone();
        let locator = tombstone.locator.clone();
        let intent_revision = tombstone.intent_revision;
        let mut delete = || -> Result<(), BlobError> {
            for (target, state) in [
                (&payload, GcState::PayloadDeleteAttempt),
                (&metadata, GcState::MetadataDeleteAttempt),
            ] {
                self.contained(target)?;
                match self.platform_stat(target)? {
                    BlobPathState::Missing => {}
                    BlobPathState::File { .. } => {
                        let previous_revision = tombstone.revision;
                        tombstone.revision = previous_revision.checked_add(1).ok_or_else(|| {
                            BlobError::PlanGap("GC tombstone revision overflow".to_owned())
                        })?;
                        tombstone.state = state;
                        self.persist_tombstone(path, &tombstone, Some(previous_revision))?;
                        self.platform_remove(target)
                            .map_err(|_| BlobError::UnknownGcOutcome {
                                operation_id: operation_id.clone(),
                                state,
                            })?;
                    }
                    BlobPathState::ReparsePoint => {
                        return Err(BlobError::PlanGap(
                            "P-02 rejected a reparse point during GC deletion".to_owned(),
                        ));
                    }
                    BlobPathState::Directory | BlobPathState::Other => {
                        return Err(BlobError::MetadataPayloadMismatch);
                    }
                }
            }
            Ok(())
        };
        let reconciliation =
            self.live_sets_reconcile_delete(&operation_id, &live_set, &locator, intent_revision)?;
        let applied = match reconciliation {
            BlobDeletionReconciliation::Applied(receipt) => receipt,
            BlobDeletionReconciliation::NotApplied => {
                match self.live_sets_compare_and_delete_observed(
                    &operation_id,
                    &live_set,
                    &locator,
                    intent_revision,
                    &mut delete,
                )? {
                    BlobDeletionReconciliation::Applied(receipt) => receipt,
                    BlobDeletionReconciliation::NotApplied
                    | BlobDeletionReconciliation::Unknown => {
                        return Err(BlobError::UnknownGcOutcome {
                            operation_id,
                            state: GcState::LiveSetRevalidated,
                        });
                    }
                }
            }
            BlobDeletionReconciliation::Unknown => {
                return Err(BlobError::UnknownGcOutcome {
                    operation_id,
                    state: GcState::LiveSetRevalidated,
                });
            }
        };
        validate_deletion_receipt(&applied, &tombstone)?;
        for target in [&tombstone.payload, &tombstone.metadata] {
            match self.platform_stat(target)? {
                BlobPathState::Missing => {}
                BlobPathState::ReparsePoint => {
                    return Err(BlobError::PlanGap(
                        "P-02 rejected a reparse point while confirming GC receipt".to_owned(),
                    ));
                }
                BlobPathState::File { .. } | BlobPathState::Directory | BlobPathState::Other => {
                    return Err(BlobError::MetadataPayloadMismatch);
                }
            }
        }
        let previous_revision = tombstone.revision;
        tombstone.revision = previous_revision
            .checked_add(1)
            .ok_or_else(|| BlobError::PlanGap("GC tombstone revision overflow".to_owned()))?;
        tombstone.state = GcState::TombstoneCleaned;
        tombstone.receipt = Some(applied);
        self.persist_tombstone(path, &tombstone, Some(previous_revision))?;
        Ok(ConditionalDeleteOutcome::Deleted)
    }

    fn ensure_not_revoked(&self, locator: &BlobLocator) -> Result<(), BlobError> {
        let tombstones = WorkScopePath::new("tombstones")
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        self.contained(&tombstones)?;
        for path in self.platform_list(&tombstones)? {
            let bytes = self.read_bounded_file(&path, MAX_JOURNAL_BYTES)?;
            let tombstone: Tombstone =
                serde_json::from_slice(&bytes).map_err(|_| BlobError::MetadataPayloadMismatch)?;
            tombstone.validate()?;
            if tombstone.locator == *locator {
                return Err(BlobError::PlanGap(
                    "purged or quarantined blob content cannot be re-admitted".to_owned(),
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn stage_locked(
        &self,
        request: BlobStageRequest,
        hash: BlobHash,
    ) -> Result<BlobReadyReceipt, BlobError> {
        let locator = BlobLocator {
            hash,
            root_generation: request.root_lease.root_generation,
            path_generation: PATH_GENERATION,
        };
        let payload = payload_path(&locator)?;
        let metadata_path_value = metadata_path(&locator)?;
        self.contained(&payload)?;
        self.contained(&metadata_path_value)?;
        self.ensure_not_revoked(&locator)?;

        let journal_path = Self::operation_path(&request.context, "stage")?;
        let commit_path = Self::operation_path(&request.context, "commit")?;
        self.contained(&commit_path)?;
        if self.platform_stat(&commit_path)? != BlobPathState::Missing {
            let bytes = self.read_bounded_file(&commit_path, MAX_JOURNAL_BYTES)?;
            let commit: OperationCommit =
                serde_json::from_slice(&bytes).map_err(|_| BlobError::MetadataPayloadMismatch)?;
            commit.validate()?;
            if commit.operation_id != request.context.operation.operation_id.as_str()
                || commit.idempotency_key != request.context.operation.idempotency_key
                || commit.locator != locator
            {
                return Err(BlobError::IdempotencyConflict);
            }
            let (stored, metadata_bytes) = self.load_metadata(&commit.locator)?;
            if sha256_hex(&metadata_bytes) != commit.metadata_sha256
                || stored.policy != request.policy
                || stored.plaintext_sha256 != sha256_hex(&request.bytes)
            {
                return Err(BlobError::IdempotencyConflict);
            }
            let verified = self.verify_metadata_receipt(&stored)?;
            let ready = stored.ready(verified, &self.issuer_anchor, commit.metadata_sha256)?;
            self.verify_payload(&ready, &request.bytes)?;
            return Ok(ready);
        }
        if self.platform_stat(&journal_path)? != BlobPathState::Missing {
            self.reconcile_stage_path(&journal_path)?;
        }
        let payload_state = self.platform_stat(&payload)?;
        let metadata_state = self.platform_stat(&metadata_path_value)?;
        if payload_state != BlobPathState::Missing || metadata_state != BlobPathState::Missing {
            if !matches!(payload_state, BlobPathState::File { .. })
                || !matches!(metadata_state, BlobPathState::File { .. })
            {
                return Err(BlobError::MetadataPayloadMismatch);
            }
            let (stored, metadata_bytes) = self.load_metadata(&locator)?;
            if stored.operation_id != request.context.operation.operation_id.as_str()
                || stored.idempotency_key != request.context.operation.idempotency_key
                || stored.policy != request.policy
                || stored.plaintext_length != request.bytes.len() as u64
                || stored.plaintext_sha256 != sha256_hex(&request.bytes)
            {
                return Err(BlobError::IdempotencyConflict);
            }
            let verified = self.verify_metadata_receipt(&stored)?;
            let ready = stored.ready(verified, &self.issuer_anchor, sha256_hex(&metadata_bytes))?;
            self.verify_payload(&ready, &request.bytes)?;
            return Ok(ready);
        }

        let compression = self.compression_descriptor()?;
        compression.validate()?;
        let compressed = self.compression_compress(&request.bytes)?;
        if compressed.len() as u64 > MAX_BLOB_ENVELOPE_BYTES {
            return Err(BlobError::InvalidContract(
                "compressed blob exceeds canonical envelope ceiling".to_owned(),
            ));
        }
        let key = self.keys_current().map_err(|error| match error {
            BlobError::ProviderUnavailable(_) | BlobError::NotFound => BlobError::KeyUnavailable {
                operation: BlobKeyOperation::Stage,
                key_lineage: None,
                key_generation: None,
                recovery: BlobKeyRecoveryCeiling::PlanGap,
            },
            other => other,
        })?;
        key.crypto.validate()?;
        let plaintext_sha256 = sha256_hex(&request.bytes);
        let aad = serde_json::to_vec(&(
            eliot_blob_api::CONTRACT_VERSION,
            &locator,
            &request.policy,
            &compression,
            &key.crypto,
            request.context.request.metadata.request_id.as_str(),
        ))
        .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        let sealed = self.aead_seal(AeadSealRequest {
            key: &key,
            nonce_context: locator.hash.as_str().as_bytes(),
            associated_data: &aad,
            plaintext: &compressed,
        })?;
        if sealed.is_empty() {
            return Err(BlobError::ProviderUnavailable(
                "AEAD provider returned no envelope",
            ));
        }
        if sealed.len() as u64 > MAX_BLOB_ENVELOPE_BYTES {
            return Err(BlobError::InvalidContract(
                "sealed blob exceeds canonical envelope ceiling".to_owned(),
            ));
        }

        let sealed_sha256 = sha256_hex(&sealed);
        let format = BlobId::new(FORMAT_ID)?;
        let receipt_binding_sha256 = eliot_blob_api::receipt_binding_sha256(
            &format,
            FORMAT_VERSION,
            &locator,
            request.bytes.len() as u64,
            sealed.len() as u64,
            &plaintext_sha256,
            &sealed_sha256,
            &compression,
            &key.crypto,
            &request.policy,
        )?;
        let content_artifact = ArtifactBinding {
            artifact_id: format!("blob-content-{}", locator.hash)
                .parse()
                .map_err(|error| BlobError::InvalidContract(format!("{error}")))?,
            sha256: plaintext_sha256.clone(),
            role: ReceiptKind::Artifact,
            source_revision: Some(format!(
                "root-generation:{};path-generation:{}",
                locator.root_generation, locator.path_generation
            )),
        };
        let envelope_artifact = ArtifactBinding {
            artifact_id: format!("blob-envelope-{}", locator.hash)
                .parse()
                .map_err(|error| BlobError::InvalidContract(format!("{error}")))?,
            sha256: receipt_binding_sha256.clone(),
            role: ReceiptKind::Artifact,
            source_revision: Some(format!(
                "{};format-version:{};stored-length:{};sealed-sha256:{}",
                eliot_blob_api::CONTRACT_VERSION,
                FORMAT_VERSION,
                sealed.len(),
                sealed_sha256
            )),
        };
        let verified_receipt = self.issue_receipt(
            &request.context,
            vec![content_artifact, envelope_artifact],
            ReceiptKind::Artifact,
            ReceiptDisposition::Success {
                proof: ProofCeiling::ObservedExternalEffect,
            },
            BlobReceiptBinding::for_blob(&request.context, &locator)?,
        )?;
        let metadata = StoredMetadata {
            receipt: verified_receipt.receipt().clone(),
            receipt_bytes: verified_receipt.receipt_bytes().to_vec(),
            locator: locator.clone(),
            plaintext_length: request.bytes.len() as u64,
            stored_length: sealed.len() as u64,
            envelope_length: sealed.len() as u64,
            plaintext_sha256,
            sealed_sha256,
            receipt_binding_sha256,
            format,
            format_version: FORMAT_VERSION,
            compression,
            crypto: key.crypto,
            policy: request.policy,
            operation_id: request.context.operation.operation_id.to_string(),
            idempotency_key: request.context.operation.idempotency_key.clone(),
        };
        let metadata_bytes = Self::metadata_bytes(&metadata)?;
        let metadata_sha256 = sha256_hex(&metadata_bytes);
        let temp_payload = Self::temp_path(&request.context, "payload")?;
        let temp_metadata = Self::temp_path(&request.context, "metadata")?;
        let mut journal = StageJournal {
            operation_id: request.context.operation.operation_id.to_string(),
            idempotency_key: request.context.operation.idempotency_key,
            state: PublishState::JournalPrepared,
            temp_payload: temp_payload.clone(),
            temp_metadata: temp_metadata.clone(),
            final_payload: payload,
            final_metadata: metadata_path_value,
            expected_payload_sha256: sha256_hex(&sealed),
            expected_metadata_sha256: metadata_sha256.clone(),
        };
        self.persist_journal(&journal_path, &journal, false)?;
        self.contained(&temp_payload)?;
        self.contained(&temp_metadata)?;
        if let Err(error) = self.platform_write_new(&temp_payload, &sealed) {
            let _ = self.remove_if_present(&journal_path);
            return Err(error);
        }
        if let Err(error) = self.platform_write_new(&temp_metadata, &metadata_bytes) {
            let _ = self.remove_if_present(&temp_payload);
            let _ = self.remove_if_present(&journal_path);
            return Err(error);
        }
        self.finish_journal(&journal_path, &mut journal)?;
        let verified = self.verify_metadata_receipt(&metadata)?;
        metadata.ready(verified, &self.issuer_anchor, metadata_sha256)
    }

    fn verify_payload(
        &self,
        ready: &BlobReadyReceipt,
        expected_plaintext: &[u8],
    ) -> Result<(), BlobError> {
        let path = payload_path(ready.locator())?;
        self.contained(&path)?;
        let sealed = self.read_bounded_file(&path, MAX_BLOB_ENVELOPE_BYTES)?;
        if sha256_hex(&sealed) != self.load_metadata(ready.locator())?.0.sealed_sha256 {
            return Err(BlobError::IntegrityMismatch);
        }
        let key = self.keys_resolve(ready.crypto()).map_err(|error| {
            map_resolve_key_error(error, ready.crypto(), BlobKeyOperation::Recovery)
        })?;
        if key.crypto != *ready.crypto() {
            return Err(BlobError::IntegrityMismatch);
        }
        let aad = serde_json::to_vec(&(
            eliot_blob_api::CONTRACT_VERSION,
            ready.locator(),
            ready.policy(),
            ready.compression(),
            ready.crypto(),
            ready.receipt().core.request.metadata.request_id.as_str(),
        ))
        .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        let compressed = self.aead_open(AeadOpenRequest {
            key: &key,
            nonce_context: ready.locator().hash.as_str().as_bytes(),
            associated_data: &aad,
            ciphertext: &sealed,
        })?;
        let plaintext = self.compression_decompress(
            ready.compression(),
            &compressed,
            MAX_BLOB_PLAINTEXT_BYTES,
        )?;
        if plaintext != expected_plaintext
            || blake3::hash(&plaintext).to_hex().as_str() != ready.locator().hash.as_str()
            || sha256_hex(&plaintext) != ready.plaintext_sha256()
        {
            return Err(BlobError::IntegrityMismatch);
        }
        Ok(())
    }

    fn read_verified(
        &self,
        request: &BlobReadRequest,
    ) -> Result<(BlobReadyReceipt, Vec<u8>), BlobError> {
        request.validate()?;
        self.ensure_lease(&request.root_lease)?;
        let (metadata, metadata_bytes) = self.load_metadata(&request.locator)?;
        let metadata_sha256 = sha256_hex(&metadata_bytes);
        if metadata_sha256 != request.expected_metadata_sha256
            || metadata.receipt.identity.receipt_id.as_str() != request.expected_ready_receipt_id
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        let verified = self.verify_metadata_receipt(&metadata)?;
        let ready = metadata.ready(verified, &self.issuer_anchor, metadata_sha256)?;
        let path = payload_path(&request.locator)?;
        self.contained(&path)?;
        let decode_ceiling = request.max_bytes.min(MAX_BLOB_PLAINTEXT_BYTES);
        if request.max_bytes > MAX_BLOB_PLAINTEXT_BYTES {
            return Err(BlobError::InvalidContract(
                "read max_bytes exceeds canonical hard ceiling".to_owned(),
            ));
        }
        if metadata.plaintext_length > decode_ceiling {
            return Err(BlobError::InvalidContract(
                "blob plaintext exceeds requested max_bytes".to_owned(),
            ));
        }
        let stored_state = self.platform_stat(&path)?;
        let BlobPathState::File { length, .. } = stored_state else {
            return Err(BlobError::NotFound);
        };
        if length != metadata.stored_length || length != metadata.envelope_length {
            return Err(BlobError::IntegrityMismatch);
        }
        if length > MAX_BLOB_ENVELOPE_BYTES {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        let sealed = self.read_bounded_file(&path, MAX_BLOB_ENVELOPE_BYTES)?;
        if sha256_hex(&sealed) != metadata.sealed_sha256 {
            return Err(BlobError::IntegrityMismatch);
        }
        let key = self.keys_resolve(&metadata.crypto).map_err(|error| {
            map_resolve_key_error(error, &metadata.crypto, BlobKeyOperation::Read)
        })?;
        if key.crypto != metadata.crypto {
            return Err(BlobError::IntegrityMismatch);
        }
        let aad = serde_json::to_vec(&(
            eliot_blob_api::CONTRACT_VERSION,
            &metadata.locator,
            &metadata.policy,
            &metadata.compression,
            &metadata.crypto,
            metadata.receipt.core.request.metadata.request_id.as_str(),
        ))
        .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        let compressed = self.aead_open(AeadOpenRequest {
            key: &key,
            nonce_context: request.locator.hash.as_str().as_bytes(),
            associated_data: &aad,
            ciphertext: &sealed,
        })?;
        let plaintext =
            self.compression_decompress(&metadata.compression, &compressed, decode_ceiling)?;
        if plaintext.len() as u64 != metadata.plaintext_length
            || plaintext.len() as u64 > request.max_bytes
            || sha256_hex(&plaintext) != metadata.plaintext_sha256
            || blake3::hash(&plaintext).to_hex().as_str() != request.locator.hash.as_str()
        {
            return Err(BlobError::IntegrityMismatch);
        }
        Ok((ready, plaintext))
    }

    fn stage_sync(&self, request: BlobStageRequest) -> Result<BlobReadyReceipt, BlobError> {
        request.validate()?;
        if request.bytes.len() as u64 > MAX_BLOB_PLAINTEXT_BYTES {
            return Err(BlobError::InvalidContract(
                "blob plaintext exceeds canonical hard ceiling".to_owned(),
            ));
        }
        self.ensure_lease(&request.root_lease)?;
        let hash = BlobHash::new(blake3::hash(&request.bytes).to_hex().to_string())?;
        let content_idx = content_shard(&hash);
        let op_idx = operation_shard(
            request.context.operation.operation_id.as_str(),
            &request.context.operation.idempotency_key,
        );
        let _guards = self.lock_shards(&[content_idx, op_idx])?;
        self.stage_locked(request, hash)
    }

    fn read_sync(&self, request: &BlobReadRequest) -> Result<BlobReadChunk, BlobError> {
        let content_idx = content_shard(&request.locator.hash);
        let _guard = self.lock_shards(&[content_idx])?;
        let (ready, bytes) = self.read_verified(request)?;
        let artifact = ArtifactBinding {
            artifact_id: format!("blob-read-{}", request.locator.hash)
                .parse()
                .map_err(|error| BlobError::InvalidContract(format!("{error}")))?,
            sha256: ready.plaintext_sha256().to_owned(),
            role: ReceiptKind::Artifact,
            source_revision: Some(format!(
                "{};root-generation:{};path-generation:{}",
                ready.metadata_sha256(),
                ready.root_generation(),
                ready.path_generation()
            )),
        };
        let verified_receipt = self.issue_receipt(
            &request.context,
            vec![artifact],
            ReceiptKind::Operation,
            ReceiptDisposition::Success {
                proof: ProofCeiling::ScopedVerification,
            },
            BlobReceiptBinding::for_blob(&request.context, &request.locator)?,
        )?;
        BlobReadChunk::from_verified(verified_receipt, &self.issuer_anchor, ready, bytes)
    }

    fn reference(
        &self,
        request: BlobReferenceRequest,
    ) -> Result<BlobReferenceObservation, BlobError> {
        request.validate()?;
        self.ensure_lease(&request.root_lease)?;
        let (metadata, bytes) = self.load_metadata(&request.locator)?;
        let metadata_sha256 = sha256_hex(&bytes);
        if metadata_sha256 != request.expected_metadata_sha256 {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        let payload = payload_path(&request.locator)?;
        let present =
            self.exact_bytes_at(&payload, &metadata.sealed_sha256, MAX_BLOB_ENVELOPE_BYTES)?;
        let receipt = self.issue_receipt(
            &request.context,
            Vec::new(),
            ReceiptKind::Operation,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            BlobReceiptBinding::for_blob(&request.context, &request.locator)?,
        )?;
        Ok(BlobReferenceObservation {
            receipt: receipt.receipt().clone(),
            locator: request.locator,
            metadata_sha256,
            present_and_integral: present,
        })
    }

    fn reachability(
        &self,
        request: BlobReachabilityRequest,
    ) -> Result<BlobReachabilityView, BlobError> {
        request.validate()?;
        self.ensure_lease(&request.root_lease)?;
        let mut present = Vec::new();
        let mut missing = Vec::new();
        for locator in &request.live_set.live {
            let payload = payload_path(locator)?;
            let metadata = metadata_path(locator)?;
            let payload_state = self.platform_stat(&payload)?;
            let metadata_state = self.platform_stat(&metadata)?;
            if matches!(payload_state, BlobPathState::File { .. })
                && matches!(metadata_state, BlobPathState::File { .. })
            {
                present.push(locator.clone());
            } else {
                missing.push(locator.clone());
            }
        }
        let receipt = self.issue_receipt(
            &request.context,
            Vec::new(),
            ReceiptKind::Operation,
            ReceiptDisposition::Success {
                proof: ProofCeiling::Observation,
            },
            BlobReceiptBinding::for_operation(
                &request.context,
                request.root_lease.root_generation,
                None,
                Some(&request.live_set.proof_id),
            )?,
        )?;
        Ok(BlobReachabilityView {
            receipt: receipt.receipt().clone(),
            proof_id: request.live_set.proof_id,
            present,
            missing,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn gc(&self, request: BlobGcRequest) -> Result<BlobGcReceipt, BlobError> {
        request.validate()?;
        self.ensure_lease(&request.root_lease)?;
        let observed = self.live_sets_revalidate(&request.live_set)?;
        Self::validate_revalidation(&request, &observed)?;
        let now = self.platform_now_ms()?;
        let mut deleted = Vec::new();
        let mut retained = Vec::new();
        for locator in &request.candidates {
            if request.live_set.contains(locator) {
                retained.push(locator.clone());
                continue;
            }
            let content_idx = content_shard(&locator.hash);
            let _guard = self.lock_shards(&[content_idx])?;
            let payload = payload_path(locator)?;
            let metadata = metadata_path(locator)?;
            let tombstone_path = WorkScopePath::new(format!(
                "tombstones/{}-{}.json",
                request.context.operation.operation_id.as_str(),
                locator.hash
            ))
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
            self.contained(&tombstone_path)?;
            if self.platform_stat(&tombstone_path)? != BlobPathState::Missing {
                let bytes = self.read_bounded_file(&tombstone_path, MAX_JOURNAL_BYTES)?;
                let tombstone: Tombstone = serde_json::from_slice(&bytes)
                    .map_err(|_| BlobError::MetadataPayloadMismatch)?;
                tombstone.validate()?;
                if tombstone.locator != *locator
                    || tombstone.proof_id != request.live_set.proof_id
                    || tombstone.proof_snapshot_sha256 != request.live_set.snapshot_sha256
                {
                    return Err(BlobError::PlanGap(
                        "GC tombstone identity does not match the exact request".to_owned(),
                    ));
                }
                match self.reconcile_tombstone_path(&tombstone_path)? {
                    ConditionalDeleteOutcome::Deleted => deleted.push(locator.clone()),
                    ConditionalDeleteOutcome::RetainedLive => retained.push(locator.clone()),
                }
                continue;
            }
            let modified = match self.platform_stat(&payload)? {
                BlobPathState::File {
                    modified_unix_ms, ..
                } => modified_unix_ms,
                BlobPathState::Missing => {
                    retained.push(locator.clone());
                    continue;
                }
                BlobPathState::ReparsePoint => {
                    return Err(BlobError::PlanGap(
                        "P-02 rejected a reparse point during GC".to_owned(),
                    ));
                }
                BlobPathState::Directory | BlobPathState::Other => {
                    return Err(BlobError::MetadataPayloadMismatch);
                }
            };
            match self.platform_stat(&metadata)? {
                BlobPathState::File { .. } => {}
                BlobPathState::Missing => return Err(BlobError::MetadataPayloadMismatch),
                BlobPathState::ReparsePoint => {
                    return Err(BlobError::PlanGap(
                        "P-02 rejected a metadata reparse point during GC".to_owned(),
                    ));
                }
                BlobPathState::Directory | BlobPathState::Other => {
                    return Err(BlobError::MetadataPayloadMismatch);
                }
            }
            if now.saturating_sub(modified) < request.grace_period_seconds.saturating_mul(1_000) {
                retained.push(locator.clone());
                continue;
            }
            // Revalidate at each destructive boundary, not once per batch.
            let current = self.live_sets_revalidate(&request.live_set)?;
            Self::validate_revalidation(&request, &current)?;
            let tombstone = Tombstone {
                operation_id: request.context.operation.operation_id.to_string(),
                revision: 1,
                intent_revision: 1,
                proof_id: request.live_set.proof_id.clone(),
                proof_snapshot_sha256: request.live_set.snapshot_sha256.clone(),
                locator: locator.clone(),
                live_set: request.live_set.clone(),
                payload,
                metadata,
                state: GcState::TombstoneDurable,
                receipt: None,
            };
            self.persist_tombstone(&tombstone_path, &tombstone, None)?;
            match self.reconcile_tombstone_path(&tombstone_path)? {
                ConditionalDeleteOutcome::Deleted => deleted.push(locator.clone()),
                ConditionalDeleteOutcome::RetainedLive => retained.push(locator.clone()),
            }
        }
        let verified_receipt = self.issue_receipt(
            &request.context,
            Vec::new(),
            ReceiptKind::Operation,
            ReceiptDisposition::Success {
                proof: ProofCeiling::ObservedExternalEffect,
            },
            BlobReceiptBinding::for_operation(
                &request.context,
                request.root_lease.root_generation,
                None,
                Some(&request.live_set.proof_id),
            )?,
        )?;
        BlobGcReceipt::from_verified(
            verified_receipt,
            &self.issuer_anchor,
            request.live_set.proof_id,
            deleted,
            retained,
        )
    }

    fn reconcile(&self, lease: &BlobRootLease) -> Result<(), BlobError> {
        self.ensure_lease(lease)?;
        let transactions = WorkScopePath::new("transactions")
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        self.contained(&transactions)?;
        for path in self.platform_list(&transactions)? {
            if is_stage_path(&path) {
                self.reconcile_stage_path(&path)?;
            }
        }
        let tombstones = WorkScopePath::new("tombstones")
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        self.contained(&tombstones)?;
        for path in self.platform_list(&tombstones)? {
            let _ = self.reconcile_tombstone_path(&path)?;
        }
        Ok(())
    }

    fn tombstones_recovery_clean(
        &self,
        tombstones: &WorkScopePath,
        degraded: &mut Vec<String>,
    ) -> bool {
        let paths = match self.platform_list(tombstones) {
            Ok(paths) => paths,
            Err(error) => {
                degraded.push(format!("tombstone scan failed: {error}"));
                return false;
            }
        };
        let mut clean = true;
        for path in paths {
            let result = (|| -> Result<(), BlobError> {
                let bytes = self.read_bounded_file(&path, MAX_JOURNAL_BYTES)?;
                let tombstone: Tombstone = serde_json::from_slice(&bytes)
                    .map_err(|_| BlobError::MetadataPayloadMismatch)?;
                tombstone.validate()?;
                if !matches!(tombstone.state, GcState::TombstoneCleaned)
                    || tombstone.receipt.is_none()
                {
                    return Err(BlobError::UnknownGcOutcome {
                        operation_id: tombstone.operation_id,
                        state: tombstone.state,
                    });
                }
                for target in [&tombstone.payload, &tombstone.metadata] {
                    if !matches!(self.platform_stat(target)?, BlobPathState::Missing) {
                        return Err(BlobError::MetadataPayloadMismatch);
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                clean = false;
                degraded.push(format!("tombstone recovery validation failed: {error}"));
            }
        }
        clean
    }

    fn health(&self) -> Result<BlobHealth, BlobError> {
        let mut degraded = Vec::new();
        let (owner_matches, containment_proven, permissions_proven) = match self
            .platform_read()
            .and_then(|guard| guard.inspect_root(&self.owner.lease))
        {
            Ok(proof) => {
                let matches =
                    proof.validate(&self.owner.lease).is_ok() && proof == self.owner.claim;
                if !matches {
                    degraded.push("root owner/lease mismatch".to_owned());
                }
                (matches, proof.containment_proven, proof.permissions_proven)
            }
            Err(error) => {
                degraded.push(format!("root inspection failed: {error}"));
                (false, false, false)
            }
        };
        let transactions = WorkScopePath::new("transactions")
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        let tombstones = WorkScopePath::new("tombstones")
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        let recovery_clean = self.platform_list(&transactions).map_or_else(
            |error| {
                degraded.push(format!("transaction scan failed: {error}"));
                false
            },
            |items| !items.iter().any(is_stage_path),
        ) && self.tombstones_recovery_clean(&tombstones, &mut degraded);
        if !recovery_clean {
            degraded.push("pending recovery journal or tombstone".to_owned());
        }
        let active_key_available = self.keys_current().map_or_else(
            |error| {
                degraded.push(format!("active key unavailable: {error}"));
                false
            },
            |key| key.crypto.validate().is_ok(),
        );
        let ready = owner_matches
            && containment_proven
            && permissions_proven
            && recovery_clean
            && active_key_available
            && degraded.is_empty();
        let health = BlobHealth {
            ready,
            owner_matches,
            containment_proven,
            permissions_proven,
            recovery_clean,
            active_key_available,
            root_generation: self.owner.lease.root_generation,
            degraded,
        };
        health.validate()?;
        Ok(health)
    }

    fn operation_path(
        context: &BlobReceiptContext,
        suffix: &str,
    ) -> Result<WorkScopePath, BlobError> {
        Self::operation_path_from(
            context.operation.operation_id.as_str(),
            &context.operation.idempotency_key,
            suffix,
        )
    }

    fn operation_path_from(
        operation_id: &str,
        idempotency_key: &str,
        suffix: &str,
    ) -> Result<WorkScopePath, BlobError> {
        let mut hasher = Hasher::new();
        hasher.update(operation_id.as_bytes());
        hasher.update(idempotency_key.as_bytes());
        WorkScopePath::new(format!(
            "transactions/{}.{}",
            hasher.finalize().to_hex(),
            suffix
        ))
        .map_err(|error| BlobError::InvalidContract(error.to_string()))
    }

    fn temp_path(context: &BlobReceiptContext, suffix: &str) -> Result<WorkScopePath, BlobError> {
        let mut hasher = Hasher::new();
        hasher.update(context.operation.operation_id.as_str().as_bytes());
        hasher.update(context.operation.idempotency_key.as_bytes());
        WorkScopePath::new(format!("staging/{}.{}", hasher.finalize().to_hex(), suffix))
            .map_err(|error| BlobError::InvalidContract(error.to_string()))
    }

    fn metadata_bytes(metadata: &StoredMetadata) -> Result<Vec<u8>, BlobError> {
        metadata.validate()?;
        serde_json::to_vec(metadata).map_err(|error| BlobError::InvalidContract(error.to_string()))
    }

    fn validate_revalidation(
        request: &BlobGcRequest,
        observed: &LiveSetRevalidation,
    ) -> Result<(), BlobError> {
        Self::validate_live_set_revalidation(&request.live_set, observed)
    }

    fn validate_live_set_revalidation(
        live_set: &BlobLiveSetProof,
        observed: &LiveSetRevalidation,
    ) -> Result<(), BlobError> {
        if !observed.still_complete_and_current
            || observed.proof_id != live_set.proof_id
            || observed.snapshot_sha256 != live_set.snapshot_sha256
            || observed.revision != live_set.revision
        {
            return Err(BlobError::IncompleteLiveSet);
        }
        Ok(())
    }

    fn issue_receipt(
        &self,
        context: &BlobReceiptContext,
        artifacts: Vec<ArtifactBinding>,
        kind: ReceiptKind,
        disposition: ReceiptDisposition,
        binding: BlobReceiptBinding,
    ) -> Result<VerifiedBlobReceipt, BlobError> {
        // `Receipt::issue` creates only an untrusted candidate envelope. The
        // capability boundary is the independent verifier over the exact
        // serialized bytes below.
        let receipt = Receipt::issue(ReceiptCore {
            contract: contract_identity().map_err(|error| BlobError::Receipt(error.to_string()))?,
            kind,
            work_scope: context.work_scope.clone(),
            task: context.task.clone(),
            session: context.session.clone(),
            causal: context.causal.clone(),
            request: context.request.clone(),
            operation: context.operation.clone(),
            authority: context.authority.clone(),
            artifacts,
            verifier: None,
            problem: None,
            coordination: None,
            disposition,
        })
        .map_err(|error| BlobError::Receipt(error.to_string()))?;
        let receipt_bytes = self.issuer_anchor.sign_receipt(&receipt)?;
        verify_receipt(&self.issuer_anchor, &receipt_bytes, binding)
    }
}

/// One claimed-root S-04 owner. Cloning shares the immutable [`RootOwner`] and
/// the port state; it never re-claims the root and never creates a second
/// receipt issuer.
#[derive(Clone)]
pub struct BlobStoreService<P, C, K, A, L> {
    core: Arc<BlobStoreCore<P, C, K, A, L>>,
}

impl<P, C, K, A, L> BlobStoreService<P, C, K, A, L>
where
    P: BlobPlatformPort,
    C: BlobCompressionPort,
    K: BlobKeyPort,
    A: BlobAeadPort,
    L: BlobLiveSetPort,
{
    pub fn new(
        lease: BlobRootLease,
        platform: P,
        compression: C,
        keys: K,
        aead: A,
        live_sets: L,
        issuer_anchor: BlobIssuerTrustAnchor,
    ) -> Result<Self, BlobError> {
        Ok(Self {
            core: Arc::new(BlobStoreCore::claim(
                lease,
                platform,
                compression,
                keys,
                aead,
                live_sets,
                issuer_anchor,
            )?),
        })
    }

    /// Typed constructor error for a composition missing the required
    /// Windows atomic/reparse-safe adapter.
    #[must_use]
    pub fn platform_plan_gap() -> BlobError {
        BlobError::PlanGap(
            "S-04 requires an injected P-01/P-02 durable no-replace and reparse-safe blob platform port"
                .to_owned(),
        )
    }

    /// Non-canonical observation helper retained for storage diagnostics.
    pub fn reference(
        &self,
        request: BlobReferenceRequest,
    ) -> Result<BlobReferenceObservation, BlobError> {
        self.core.reference(request)
    }

    /// Startup recovery helper; it is not part of the public `BlobStoreClient` contract.
    pub fn reconcile(&self, lease: &BlobRootLease) -> Result<(), BlobError> {
        self.core.reconcile(lease)
    }
}

impl<P, C, K, A, L> BlobStoreClient for BlobStoreService<P, C, K, A, L>
where
    P: BlobPlatformPort,
    C: BlobCompressionPort,
    K: BlobKeyPort,
    A: BlobAeadPort,
    L: BlobLiveSetPort,
{
    fn stage(&self, request: BlobStageRequest) -> BlobFuture<'_, BlobReadyReceipt> {
        let core = Arc::clone(&self.core);
        Box::pin(async move { core.stage_sync(request) })
    }

    fn read(&self, request: BlobReadRequest) -> BlobFuture<'_, BlobReadChunk> {
        let core = Arc::clone(&self.core);
        Box::pin(async move { core.read_sync(&request) })
    }

    fn reachability(
        &self,
        request: BlobReachabilityRequest,
    ) -> BlobFuture<'_, BlobReachabilityView> {
        let core = Arc::clone(&self.core);
        Box::pin(async move { core.reachability(request) })
    }

    fn gc(&self, request: BlobGcRequest) -> BlobFuture<'_, BlobGcReceipt> {
        let core = Arc::clone(&self.core);
        Box::pin(async move { core.gc(request) })
    }

    fn health(&self) -> BlobFuture<'_, BlobHealth> {
        let core = Arc::clone(&self.core);
        Box::pin(async move { core.health() })
    }
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), BlobError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(BlobError::InvalidField {
            field,
            reason: "must be lowercase SHA-256 hex",
        })
    }
}

fn context_from_receipt(receipt: &Receipt) -> BlobReceiptContext {
    BlobReceiptContext {
        work_scope: receipt.core.work_scope.clone(),
        task: receipt.core.task.clone(),
        session: receipt.core.session.clone(),
        causal: receipt.core.causal.clone(),
        request: receipt.core.request.clone(),
        operation: receipt.core.operation.clone(),
        authority: receipt.core.authority.clone(),
    }
}

fn is_stage_path(path: &WorkScopePath) -> bool {
    std::path::Path::new(path.normalized_identity())
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("stage"))
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

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn map_resolve_key_error(
    error: BlobError,
    descriptor: &CryptoDescriptor,
    operation: BlobKeyOperation,
) -> BlobError {
    match error {
        BlobError::ProviderUnavailable(_) | BlobError::NotFound => BlobError::KeyUnavailable {
            operation,
            key_lineage: Some(descriptor.key_lineage.clone()),
            key_generation: Some(descriptor.key_generation),
            recovery: BlobKeyRecoveryCeiling::Unavailable,
        },
        other => other,
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "test fixtures use expect to make violated setup invariants fail immediately"
)]
mod tests {
    use super::*;
    use eliot_blob_api::LiveSetCompleteness;
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

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

    fn test_anchor() -> BlobIssuerTrustAnchor {
        BlobIssuerTrustAnchor::new("s04-test-issuer", "s04-test-key-v1", vec![0x42; 32])
            .expect("test anchor")
    }

    #[derive(Default)]
    struct MemoryPlatform {
        files: BTreeMap<String, (Vec<u8>, u64)>,
        claim: Option<RootClaimProof>,
        now: u64,
    }

    impl BlobPlatformPort for MemoryPlatform {
        fn claim_root(&mut self, lease: &BlobRootLease) -> Result<RootClaimProof, BlobError> {
            let requested = RootClaimProof {
                root_id: lease.root_id.as_str().to_owned(),
                owner_id: lease.owner_id.to_string(),
                lease_id: lease.lease_id.to_string(),
                root_generation: lease.root_generation,
                containment_proven: true,
                permissions_proven: true,
            };
            if self.claim.as_ref().is_some_and(|claim| claim != &requested) {
                return Err(BlobError::OwnerConflict);
            }
            self.claim = Some(requested.clone());
            Ok(requested)
        }

        fn inspect_root(&self, _lease: &BlobRootLease) -> Result<RootClaimProof, BlobError> {
            self.claim.clone().ok_or(BlobError::OwnerConflict)
        }

        fn prove_contained(
            &self,
            _lease: &BlobRootLease,
            _path: &WorkScopePath,
        ) -> Result<(), BlobError> {
            Ok(())
        }

        fn read_bounded(&self, path: &WorkScopePath, max_bytes: u64) -> Result<Vec<u8>, BlobError> {
            let bytes = self
                .files
                .get(path.normalized_identity())
                .map(|(bytes, _)| bytes.clone())
                .ok_or(BlobError::NotFound)?;
            if bytes.len() as u64 > max_bytes {
                return Err(BlobError::InvalidContract(
                    "bounded platform read ceiling exceeded".to_owned(),
                ));
            }
            Ok(bytes)
        }

        fn write_new_durable(
            &mut self,
            path: &WorkScopePath,
            bytes: &[u8],
        ) -> Result<(), BlobError> {
            if self.files.contains_key(path.normalized_identity()) {
                return Err(BlobError::IdempotencyConflict);
            }
            self.files.insert(
                path.normalized_identity().to_owned(),
                (bytes.to_vec(), self.now),
            );
            Ok(())
        }

        fn replace_durable(&mut self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
            if !self.files.contains_key(path.normalized_identity()) {
                return Err(BlobError::NotFound);
            }
            self.files.insert(
                path.normalized_identity().to_owned(),
                (bytes.to_vec(), self.now),
            );
            Ok(())
        }

        fn rename_no_replace_durable(
            &mut self,
            source: &WorkScopePath,
            destination: &WorkScopePath,
        ) -> Result<(), BlobError> {
            if self.files.contains_key(destination.normalized_identity()) {
                return Err(BlobError::IdempotencyConflict);
            }
            let value = self
                .files
                .remove(source.normalized_identity())
                .ok_or(BlobError::NotFound)?;
            self.files
                .insert(destination.normalized_identity().to_owned(), value);
            Ok(())
        }

        fn remove_durable(&mut self, path: &WorkScopePath) -> Result<(), BlobError> {
            self.files.remove(path.normalized_identity());
            Ok(())
        }

        fn stat(&self, path: &WorkScopePath) -> Result<BlobPathState, BlobError> {
            Ok(self.files.get(path.normalized_identity()).map_or(
                BlobPathState::Missing,
                |(bytes, modified)| BlobPathState::File {
                    length: bytes.len() as u64,
                    modified_unix_ms: *modified,
                },
            ))
        }

        fn list(&self, prefix: &WorkScopePath) -> Result<Vec<WorkScopePath>, BlobError> {
            self.files
                .keys()
                .filter(|path| path.starts_with(prefix.normalized_identity()))
                .map(|path| {
                    WorkScopePath::new(path.clone())
                        .map_err(|error| BlobError::InvalidContract(error.to_string()))
                })
                .collect()
        }

        fn now_unix_ms(&mut self) -> Result<u64, BlobError> {
            Ok(self.now)
        }
    }

    struct TestCompression;

    impl BlobCompressionPort for TestCompression {
        fn descriptor(&mut self) -> Result<CompressionDescriptor, BlobError> {
            Ok(CompressionDescriptor {
                algorithm: BlobId::new("test-identity-codec")?,
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

    struct TestKeys;

    impl BlobKeyPort for TestKeys {
        fn current(&mut self) -> Result<BlobKeySelection, BlobError> {
            Ok(test_key(3))
        }

        fn resolve(&self, descriptor: &CryptoDescriptor) -> Result<BlobKeySelection, BlobError> {
            Ok(BlobKeySelection {
                key_ref: BlobId::new(format!("test-key-{}", descriptor.key_generation))?,
                crypto: descriptor.clone(),
            })
        }
    }

    fn test_key(generation: u64) -> BlobKeySelection {
        BlobKeySelection {
            key_ref: BlobId::new(format!("test-key-{generation}")).expect("key ref"),
            crypto: CryptoDescriptor {
                algorithm: BlobId::new("test-only-authenticated-envelope").expect("algorithm"),
                version: 1,
                key_lineage: BlobId::new("test-lineage").expect("lineage"),
                key_generation: generation,
            },
        }
    }

    struct TestAead;

    impl BlobAeadPort for TestAead {
        fn seal(&mut self, request: AeadSealRequest<'_>) -> Result<Vec<u8>, BlobError> {
            let mut result = sha256_hex(
                &[
                    request.associated_data,
                    request.nonce_context,
                    request.plaintext,
                    request.key.key_ref.as_str().as_bytes(),
                ]
                .concat(),
            )
            .into_bytes();
            result.extend_from_slice(request.plaintext);
            Ok(result)
        }

        fn open(&self, request: AeadOpenRequest<'_>) -> Result<Vec<u8>, BlobError> {
            if request.ciphertext.len() < 64 {
                return Err(BlobError::IntegrityMismatch);
            }
            let plaintext = &request.ciphertext[64..];
            let expected = sha256_hex(
                &[
                    request.associated_data,
                    request.nonce_context,
                    plaintext,
                    request.key.key_ref.as_str().as_bytes(),
                ]
                .concat(),
            );
            if request.ciphertext[..64] != *expected.as_bytes() {
                return Err(BlobError::IntegrityMismatch);
            }
            Ok(plaintext.to_vec())
        }
    }

    #[derive(Clone, Copy, Default)]
    enum TestGcMode {
        #[default]
        Unknown,
        NotApplied,
        Applied,
    }

    #[derive(Default)]
    struct TestLiveSets {
        mode: TestGcMode,
        stale: bool,
        tamper_receipt: bool,
        delete_calls: usize,
    }

    impl BlobLiveSetPort for TestLiveSets {
        fn revalidate(
            &mut self,
            proof: &BlobLiveSetProof,
        ) -> Result<LiveSetRevalidation, BlobError> {
            Ok(LiveSetRevalidation {
                proof_id: proof.proof_id.clone(),
                snapshot_sha256: proof.snapshot_sha256.clone(),
                revision: if self.stale {
                    proof.revision.saturating_add(1)
                } else {
                    proof.revision
                },
                still_complete_and_current: !self.stale,
            })
        }

        fn reconcile_delete(
            &mut self,
            operation_id: &str,
            proof: &BlobLiveSetProof,
            locator: &BlobLocator,
            intent_revision: u64,
        ) -> Result<BlobDeletionReconciliation, BlobError> {
            match self.mode {
                TestGcMode::Applied => Ok(BlobDeletionReconciliation::Applied(deletion_receipt(
                    operation_id,
                    proof,
                    locator,
                    intent_revision,
                ))),
                TestGcMode::NotApplied => Ok(BlobDeletionReconciliation::NotApplied),
                TestGcMode::Unknown => Ok(BlobDeletionReconciliation::Unknown),
            }
        }

        fn compare_and_delete_observed(
            &mut self,
            operation_id: &str,
            proof: &BlobLiveSetProof,
            locator: &BlobLocator,
            intent_revision: u64,
            delete: &mut dyn FnMut() -> Result<(), BlobError>,
        ) -> Result<BlobDeletionReconciliation, BlobError> {
            if self.stale {
                return Err(BlobError::IncompleteLiveSet);
            }
            delete()?;
            self.delete_calls = self.delete_calls.saturating_add(1);
            let mut receipt = deletion_receipt(operation_id, proof, locator, intent_revision);
            if self.tamper_receipt {
                receipt.path_digest_sha256 = sha256_hex(b"wrong-path");
            }
            Ok(BlobDeletionReconciliation::Applied(receipt))
        }

        fn compare_and_delete(
            &mut self,
            proof: &BlobLiveSetProof,
            _locator: &BlobLocator,
            delete: &mut dyn FnMut() -> Result<(), BlobError>,
        ) -> Result<ConditionalDeleteOutcome, BlobError> {
            let observed = self.revalidate(proof)?;
            if !observed.still_complete_and_current {
                return Err(BlobError::IncompleteLiveSet);
            }
            delete()?;
            Ok(ConditionalDeleteOutcome::Deleted)
        }
    }

    fn deletion_receipt(
        operation_id: &str,
        proof: &BlobLiveSetProof,
        locator: &BlobLocator,
        intent_revision: u64,
    ) -> BlobDeletionReceipt {
        let payload = payload_path(locator).expect("payload path");
        let metadata = metadata_path(locator).expect("metadata path");
        BlobDeletionReceipt {
            operation_id: operation_id.to_owned(),
            proof_id: proof.proof_id.clone(),
            snapshot_sha256: proof.snapshot_sha256.clone(),
            revision: intent_revision,
            locator: locator.clone(),
            path_digest_sha256: deletion_path_digest(&payload, &metadata),
            payload_deleted: true,
            metadata_deleted: true,
        }
    }

    fn context_json(effect: &str, operation: &str, request: &str) -> String {
        let fence = r#"{"authority_epoch":4,"resource_generation":7,"task_revision":null,"policy_revision":null,"integration_revision":null}"#;
        let metadata = format!(
            r#"{{"request_id":"{request}","session_id":null,"task_id":null,"product_id":"product-1","source_id":"source-1","state_fence":{fence},"clock":{{"valid_time_ms":1,"known_time_ms":1,"transaction_sequence":null,"monotonic_ns":1}}}}"#
        );
        format!(
            r#"{{"work_scope":{{"scope_id":"scope-1","product_id":"product-1","resource_generation":7,"state_fence":{fence}}},"task":null,"session":null,"causal":{{"state_fence":{fence},"transaction_sequence":1,"parent_receipt_id":null,"predecessor_receipt_ids":[]}},"request":{{"metadata":{metadata},"state_fence":{fence}}},"operation":{{"operation_id":"{operation}","request_id":"{request}","idempotency_key":"idem-1","operation_kind":"blob-test","effect":"{effect}","state_fence":{fence}}},"authority":{{"authority_id":"authority-1","authority_owner":"test-owner","authority_epoch":4,"state_fence":{fence},"allowed_effect":"{effect}","proof_ceiling":"OBSERVED_EXTERNAL_EFFECT"}}}}"#
        )
    }

    fn lease(context: &BlobReceiptContext) -> BlobRootLease {
        serde_json::from_value(serde_json::json!({
            "root_id": "root-1",
            "owner_id": "owner-1",
            "lease_id": "lease-1",
            "root_generation": 7,
            "fence_binding": context.request,
        }))
        .expect("lease")
    }

    fn stage_request(operation: &str, bytes: &[u8]) -> BlobStageRequest {
        let context: BlobReceiptContext = serde_json::from_str(&context_json(
            "REVERSIBLE_MUTATION",
            operation,
            &format!("request-{operation}"),
        ))
        .expect("context");
        BlobStageRequest {
            root_lease: lease(&context),
            context,
            bytes: bytes.to_vec(),
            policy: BlobPolicyBinding {
                privacy_class: eliot_security_contracts::PrivacyClass::Private,
                retention_class: eliot_blob_api::RetentionClass::Task,
                policy_ref: eliot_platform::PlatformHandle::new("policy-1").expect("policy"),
                instruction_taint: eliot_security_contracts::InstructionTaint::DataOnly,
                effect_ceiling: eliot_security_contracts::EffectCeiling::CandidateOnly,
            },
        }
    }

    fn store() -> BlobStoreService<MemoryPlatform, TestCompression, TestKeys, TestAead, TestLiveSets>
    {
        let request = stage_request("bootstrap", b"");
        BlobStoreService::new(
            request.root_lease,
            MemoryPlatform::default(),
            TestCompression,
            TestKeys,
            TestAead,
            TestLiveSets::default(),
            test_anchor(),
        )
        .expect("store")
    }

    fn gc_store(
        mode: TestGcMode,
        stale: bool,
    ) -> BlobStoreService<MemoryPlatform, TestCompression, TestKeys, TestAead, TestLiveSets> {
        let request = stage_request("bootstrap", b"");
        BlobStoreService::new(
            request.root_lease,
            MemoryPlatform::default(),
            TestCompression,
            TestKeys,
            TestAead,
            TestLiveSets {
                mode,
                stale,
                tamper_receipt: false,
                delete_calls: 0,
            },
            test_anchor(),
        )
        .expect("store")
    }

    fn gc_request(live: Vec<BlobLocator>, candidates: Vec<BlobLocator>) -> BlobGcRequest {
        let context: BlobReceiptContext = serde_json::from_str(&context_json(
            "REVERSIBLE_MUTATION",
            "gc-operation",
            "request-gc-operation",
        ))
        .expect("context");
        let live_set = BlobLiveSetProof {
            proof_id: BlobId::new("proof-gc").expect("proof id"),
            canonical_owner_ref: BlobId::new("canonical-owner").expect("owner ref"),
            completeness: LiveSetCompleteness::Complete,
            snapshot_sha256: sha256_hex(b"live-set-snapshot"),
            revision: 1,
            fence_binding: context.request.clone(),
            live,
            receipt_refs: vec!["receipt-gc".to_owned()],
        };
        BlobGcRequest {
            root_lease: lease(&context),
            context,
            live_set,
            candidates,
            grace_period_seconds: 0,
        }
    }

    fn read_request(ready: &BlobReadyReceipt, operation: &str) -> BlobReadRequest {
        let context: BlobReceiptContext = serde_json::from_str(&context_json(
            "READ",
            operation,
            &format!("request-{operation}"),
        ))
        .expect("context");
        BlobReadRequest {
            root_lease: lease(&context),
            context,
            locator: ready.locator().clone(),
            expected_metadata_sha256: ready.metadata_sha256().to_owned(),
            expected_ready_receipt_id: ready.receipt().identity.receipt_id.to_string(),
            max_bytes: 1024,
        }
    }

    #[test]
    fn object_safe_stage_read_roundtrip() {
        let store = store();
        let client: &dyn BlobStoreClient = &store;
        let ready = block_on(client.stage(stage_request("roundtrip", b"payload"))).expect("stage");
        let expected_anchor = test_anchor();
        assert_eq!(ready.anchor_fingerprint(), expected_anchor.fingerprint());
        assert_eq!(ready.plaintext_length(), 7);
        let chunk = block_on(client.read(read_request(&ready, "roundtrip-read"))).expect("read");
        assert_eq!(chunk.bytes(), b"payload");
        assert_eq!(chunk.anchor_fingerprint(), expected_anchor.fingerprint());
        assert!(chunk.is_complete());
        assert!(block_on(client.health()).expect("health").ready);
    }

    #[test]
    fn idempotent_replay_is_exact_and_conflict_never_succeeds() {
        let store = store();
        let request = stage_request("idem", b"payload");
        let first = block_on(store.stage(request.clone())).expect("stage");
        let replay = block_on(store.stage(request)).expect("replay");
        assert_eq!(first, replay);
        let conflict = block_on(store.stage(stage_request("idem", b"different")));
        assert_eq!(conflict, Err(BlobError::IdempotencyConflict));
    }

    #[test]
    fn gc_retains_live_and_removes_unreachable_once() {
        let store = gc_store(TestGcMode::NotApplied, false);
        let live = block_on(store.stage(stage_request("live", b"live-payload"))).expect("live");
        let unreachable =
            block_on(store.stage(stage_request("orphan", b"orphan-payload"))).expect("orphan");
        let request = gc_request(
            vec![live.locator().clone()],
            vec![live.locator().clone(), unreachable.locator().clone()],
        );
        let receipt = block_on(store.gc(request.clone())).expect("gc");
        assert!(receipt.deleted().contains(unreachable.locator()));
        assert!(receipt.retained().contains(live.locator()));
        assert!(matches!(
            block_on(store.read(read_request(&unreachable, "orphan-read"))),
            Err(BlobError::NotFound)
        ));
        assert_eq!(
            block_on(store.stage(stage_request("orphan-replay", b"orphan-payload"))),
            Err(BlobError::PlanGap(
                "purged or quarantined blob content cannot be re-admitted".to_owned()
            ))
        );
        let health = block_on(store.health()).expect("health");
        assert!(health.ready);
        assert!(health.recovery_clean);
        let replay = block_on(store.gc(request)).expect("exact gc replay");
        assert_eq!(replay, receipt);
    }

    #[test]
    fn stale_reachability_plan_is_rejected_before_tombstone() {
        let store = gc_store(TestGcMode::NotApplied, true);
        let orphan =
            block_on(store.stage(stage_request("stale-orphan", b"payload"))).expect("orphan");
        let request = gc_request(Vec::new(), vec![orphan.locator().clone()]);
        assert_eq!(
            block_on(store.gc(request)),
            Err(BlobError::IncompleteLiveSet)
        );
        assert!(block_on(store.read(read_request(&orphan, "stale-read"))).is_ok());
    }

    #[test]
    fn target_receipt_path_digest_mismatch_is_rejected() {
        let store = gc_store(TestGcMode::NotApplied, false);
        store
            .core
            .live_sets
            .lock()
            .expect("live-set lock")
            .tamper_receipt = true;
        let orphan =
            block_on(store.stage(stage_request("bad-receipt", b"payload"))).expect("orphan");
        let request = gc_request(Vec::new(), vec![orphan.locator().clone()]);
        assert_eq!(
            block_on(store.gc(request)),
            Err(BlobError::MetadataPayloadMismatch)
        );
    }

    #[test]
    fn applied_receipt_with_live_targets_is_rejected() {
        let store = gc_store(TestGcMode::Applied, false);
        let orphan = block_on(store.stage(stage_request("live-target-receipt", b"payload")))
            .expect("orphan");
        let request = gc_request(Vec::new(), vec![orphan.locator().clone()]);
        assert_eq!(
            block_on(store.gc(request)),
            Err(BlobError::MetadataPayloadMismatch)
        );
        assert!(block_on(store.read(read_request(&orphan, "live-target-read"))).is_ok());
    }

    #[test]
    fn unknown_gc_outcome_is_durable_and_not_blindly_retried() {
        let store = gc_store(TestGcMode::Unknown, false);
        let orphan =
            block_on(store.stage(stage_request("unknown-orphan", b"payload"))).expect("orphan");
        let request = gc_request(Vec::new(), vec![orphan.locator().clone()]);
        assert!(matches!(
            block_on(store.gc(request.clone())),
            Err(BlobError::UnknownGcOutcome { .. })
        ));
        assert!(block_on(store.read(read_request(&orphan, "unknown-read"))).is_ok());
        let health = block_on(store.health()).expect("health");
        assert!(!health.ready);
        assert!(!health.recovery_clean);
        assert_eq!(
            block_on(store.gc(request)),
            Err(BlobError::UnknownGcOutcome {
                operation_id: "gc-operation".to_owned(),
                state: GcState::LiveSetRevalidated,
            })
        );
        assert!(block_on(store.read(read_request(&orphan, "unknown-read-2"))).is_ok());
    }

    #[test]
    fn applied_reconciliation_after_effect_does_not_delete_again() {
        let store = gc_store(TestGcMode::Unknown, false);
        let orphan =
            block_on(store.stage(stage_request("crash-orphan", b"payload"))).expect("orphan");
        let request = gc_request(Vec::new(), vec![orphan.locator().clone()]);
        assert!(matches!(
            block_on(store.gc(request.clone())),
            Err(BlobError::UnknownGcOutcome { .. })
        ));

        let payload = payload_path(orphan.locator()).expect("payload path");
        let metadata = metadata_path(orphan.locator()).expect("metadata path");
        store
            .core
            .platform
            .write()
            .expect("platform lock")
            .remove_durable(&payload)
            .expect("payload effect");
        store
            .core
            .platform
            .write()
            .expect("platform lock")
            .remove_durable(&metadata)
            .expect("metadata effect");
        store.core.live_sets.lock().expect("live-set lock").mode = TestGcMode::Applied;

        let receipt = block_on(store.gc(request)).expect("applied reconcile");
        assert!(receipt.deleted().contains(orphan.locator()));
        assert_eq!(
            store
                .core
                .live_sets
                .lock()
                .expect("live-set lock")
                .delete_calls,
            0
        );
        assert!(matches!(
            block_on(store.read(read_request(&orphan, "crash-read"))),
            Err(BlobError::NotFound)
        ));
    }
}
