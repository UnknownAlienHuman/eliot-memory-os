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
//! re-claim a root and never create a second receipt issuer. The owner-bound
//! constructor binds that claim to the OS [`BlobRootOwner`] lease through one
//! process-local single-owner registry, so a root reserved through either
//! seam rejects a second service owner with `OwnerConflict`. There is no global
//! state lock: reads overlap through shared platform/codec/key/AEAD locks, and
//! same-content or same-operation identities serialize through striped shard
//! locks. The only process-global lock is the bounded startup root-claim
//! registry; it is not on the blob operation hot path. Blocking
//! filesystem/codec work still executes on the calling task until the P-11
//! task API is admitted (documented blocker).

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake3::Hasher;
pub use eliot_blob_api::{
    BlobCapacityCause, BlobCapacityCleanup, BlobCapacityEffect, BlobCapacityEvidence,
    BlobCapacityFailure, BlobCapacityIdentity, BlobCapacityRecovery, BlobCapacityStage, BlobError,
    BlobPublicationFence, BlobPublicationObligation, PublishState,
};
pub mod backup_io;
pub use backup_io::{
    BACKUP_MAX_PLAINTEXT_BYTES, BackupCleanupPort, BackupMemberState, BackupPlaintextSource,
    BackupSealedSink, CaptureOutcome, CapturePorts, ConsumerEvidencePack, DispositionCleanup,
    DispositionDurability, DispositionValidation, ExportedPage, MemberDisposition, PageInterrupt,
    ResidencyDisposition, RestoreBinding, SealedMember, bind_restore_set, complete_export,
    export_page, open_member, run_capture, seal_associated_data, seal_member, seal_nonce_context,
    verify_capture_record, verify_destination_scope,
};
pub mod demand;
pub mod key_ports;
pub mod publication_owner;
pub mod stream_sink;
pub use demand::{
    ApprovedBlobView, BlobGenerationProbe, BlobProbeError, StoreBlobDemand,
    classify_capture_payload, garbage_collection_demand, probe_blob_generation,
    staged_recovery_demand,
};
use eliot_blob_api::{
    BlobCasCapability, BlobCasDurability, BlobCasFailure, BlobCasOutcome, BlobCasReceipt,
    BlobCasRequest, BlobCasState, BlobCasSuccessKind, BlobFuture, BlobGcReceipt, BlobGcRequest,
    BlobHash, BlobHealth, BlobId, BlobIssuerTrustAnchor, BlobKeyOperation, BlobKeyRecoveryCeiling,
    BlobLiveSetProof, BlobLocator, BlobPolicyBinding, BlobReachabilityRequest,
    BlobReachabilityView, BlobReadChunk, BlobReadRequest, BlobReadyReceipt, BlobReceiptBinding,
    BlobReceiptContext, BlobReferenceObservation, BlobReferenceRequest, BlobRootLease,
    BlobStageRequest, BlobStoreClient, CompressionDescriptor, CryptoDescriptor, GcState,
    SealedBlobRead, SignedBlobReceiptWire, VerifiedBlobReceipt, metadata_path, payload_path,
    verify_receipt,
};
use eliot_platform::WorkScopePath;
use eliot_receipts::{
    ArtifactBinding, OperationId, ProofCeiling, Receipt, ReceiptCore, ReceiptDisposition,
    ReceiptKind, contract_identity,
};
pub use key_ports::{DpapiUserAeadPort, DpapiUserKeyPort, KEY_PORT_ALGORITHM, KEY_PORT_VERSION};
pub use publication_owner::{BlobArchivePublicationBinding, BlobArchivePublicationOwner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub use stream_sink::{
    BlobStoreStreamSink, BlobStreamPartialPrefix, BlobStreamPublication,
    BlobStreamSinkStoreBinding, BlobStreamUnavailableReason,
};

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
#[cfg(target_os = "linux")]
const LINUX_ENOSPC: i32 = 28;

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
    /// Normalized configured-root key shared with the service claim path.
    /// [`owns_service_root`] is the only public comparison over it.
    registry_key: String,
    lease: Arc<RootLeaseState>,
}

static PROCESS_ROOT_CLAIMS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

/// Process-wide single-owner registry shared by the OS [`BlobRootOwner`] claim
/// path and the [`BlobStoreService`] claim path (T3-B, issue #19).
///
/// The two paths historically reserved different identities (an OS lease file
/// plus `PROCESS_ROOT_CLAIMS` versus the platform port `claim_root`), so a
/// root reserved through one seam could still admit a second service owner
/// through the other. Both paths now reserve one normalized key here:
/// any live entry — OS owner or service — rejects a newcomer with
/// `OwnerConflict`. An OS owner entry is replaced by exactly one service entry
/// when [`BlobStoreService::new_with_owner`] binds to it, and restored when
/// that service drops. This registry is a same-process defense only;
/// cross-process exclusion remains the OS lease file retained by the owner
/// handle (plus the platform adapter proof for ownerless compositions).
#[derive(Clone, Debug, Eq, PartialEq)]
enum RootClaimKind {
    OsOwner { token: String },
    Service,
}

static ROOT_OWNERSHIP: OnceLock<Mutex<BTreeMap<String, RootClaimKind>>> = OnceLock::new();

/// Normalizes one configured root identity for the process-local single-owner
/// registry. Filesystem canonicalization (symlinks, relative-vs-absolute)
/// stays with [`canonical_root`]; this key only aligns the two claim paths
/// that were given the same configured string.
fn ownership_key(raw_root_id: &str) -> String {
    let mut key = raw_root_id.replace('\\', "/");
    if cfg!(windows) {
        key.make_ascii_lowercase();
    }
    key
}

fn is_ownership_reserved(key: &str) -> bool {
    ROOT_OWNERSHIP
        .get()
        .and_then(|registry| registry.lock().ok())
        .is_some_and(|registry| registry.contains_key(key))
}

fn reserve_ownership(key: &str, kind: RootClaimKind) -> Result<(), BlobError> {
    let registry = ROOT_OWNERSHIP.get_or_init(|| Mutex::new(BTreeMap::new()));
    let Ok(mut registry) = registry.lock() else {
        return Err(BlobError::Provider(
            "Blob root ownership lock poisoned".to_owned(),
        ));
    };
    if registry.contains_key(key) {
        return Err(BlobError::OwnerConflict);
    }
    registry.insert(key.to_owned(), kind);
    Ok(())
}

/// Binds one live service to the OS owner that reserved `key`. The presenting
/// owner must be the reserver (token equality); the entry becomes `Service`
/// so no second service — even with the same handle — can bind afterwards.
fn bind_service_to_owner(key: &str, token: &str) -> Result<(), BlobError> {
    let registry = ROOT_OWNERSHIP.get_or_init(|| Mutex::new(BTreeMap::new()));
    let Ok(mut registry) = registry.lock() else {
        return Err(BlobError::Provider(
            "Blob root ownership lock poisoned".to_owned(),
        ));
    };
    let bound = matches!(
        registry.get(key),
        Some(RootClaimKind::OsOwner { token: expected }) if expected == token
    );
    if !bound {
        return Err(BlobError::OwnerConflict);
    }
    registry.insert(key.to_owned(), RootClaimKind::Service);
    Ok(())
}

/// Restores the OS owner entry after its bound service goes away (drop or
/// failed construction). Only a `Service` entry is replaced; any other state
/// is left untouched so a release can never evict a newcomer.
fn restore_os_owner(key: &str, token: &str) {
    let Some(registry) = ROOT_OWNERSHIP.get() else {
        return;
    };
    if let Ok(mut registry) = registry.lock()
        && matches!(registry.get(key), Some(RootClaimKind::Service))
    {
        registry.insert(
            key.to_owned(),
            RootClaimKind::OsOwner {
                token: token.to_owned(),
            },
        );
    }
}

fn release_os_owner_key(key: &str, token: &str) {
    let Some(registry) = ROOT_OWNERSHIP.get() else {
        return;
    };
    if let Ok(mut registry) = registry.lock()
        && matches!(
            registry.get(key),
            Some(RootClaimKind::OsOwner { token: expected }) if expected == token
        )
    {
        registry.remove(key);
    }
}

fn release_service_key(key: &str) {
    let Some(registry) = ROOT_OWNERSHIP.get() else {
        return;
    };
    if let Ok(mut registry) = registry.lock()
        && matches!(registry.get(key), Some(RootClaimKind::Service))
    {
        registry.remove(key);
    }
}

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
    registry_key: String,
    lock_path: PathBuf,
    token: String,
    process_id: u32,
    lock_file: Mutex<Option<fs::File>>,
    stop: Arc<AtomicBool>,
    heartbeat: Mutex<Option<JoinHandle<()>>>,
    heartbeat_failure: Mutex<Option<BlobError>>,
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
        // Release the unified single-owner entry only while it still names
        // this exact claim; a bound service replaces the entry and restores
        // it on drop, so this must never evict the service entry.
        release_os_owner_key(&self.registry_key, &self.token);
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
            .field("registry_key", &self.registry_key)
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
        // Fail fast before touching the filesystem when the unified
        // single-owner registry already names a live OS owner or service for
        // this configured root. The post-acquire reservation below closes the
        // residual race; both report the same typed conflict.
        let registry_key = ownership_key(&configured_root);
        if is_ownership_reserved(&registry_key) {
            return Err(BlobError::OwnerConflict);
        }
        let (canonical_path, root_claim_key) = canonical_root(&configured_root)?;
        let (lock_path, token, lock_file) =
            acquire_root_lease(&canonical_path, &root_claim_key, process_id)?;
        reserve_ownership(
            &registry_key,
            RootClaimKind::OsOwner {
                token: token.clone(),
            },
        )?;
        let claims = PROCESS_ROOT_CLAIMS.get_or_init(|| Mutex::new(BTreeSet::new()));
        let Ok(mut claims) = claims.lock() else {
            release_os_owner_key(&registry_key, &token);
            return Err(BlobError::Provider(
                "Blob root claim lock poisoned".to_owned(),
            ));
        };
        if !claims.insert(root_claim_key.clone()) {
            drop(claims);
            release_os_owner_key(&registry_key, &token);
            return Err(BlobError::OwnerConflict);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let lease = Arc::new(RootLeaseState {
            root_id: root_claim_key.clone(),
            registry_key: registry_key.clone(),
            lock_path,
            token: token.clone(),
            process_id,
            lock_file: Mutex::new(Some(lock_file)),
            stop: Arc::clone(&stop),
            heartbeat: Mutex::new(None),
            heartbeat_failure: Mutex::new(None),
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
                drop(claims);
                release_os_owner_key(&registry_key, &token);
                return Err(BlobError::Provider(format!(
                    "start Blob root lease heartbeat: {error}"
                )));
            }
        };
        let Ok(mut heartbeat_slot) = lease.heartbeat.lock() else {
            claims.remove(&root_claim_key);
            drop(claims);
            release_os_owner_key(&registry_key, &token);
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
            registry_key,
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

    /// Returns true when `lease_root_id` names the same configured root this
    /// owner was claimed for. A service lease binds to this OS claim only
    /// through this comparison ([`BlobStoreService::new_with_owner`]); the
    /// composition root (C3) must therefore pass the exact configured
    /// blob-root string as the service lease `root_id`. Anything else is a
    /// second owner and is rejected with `OwnerConflict`.
    #[must_use]
    pub fn owns_service_root(&self, lease_root_id: &str) -> bool {
        ownership_key(lease_root_id) == self.registry_key
    }

    /// Returns the last bounded heartbeat failure observed by the native lease
    /// thread, if any. This is an owner observation; it does not claim that an
    /// injected service health port has observed the same failure.
    pub fn heartbeat_failure(&self) -> Option<BlobError> {
        self.lease
            .heartbeat_failure
            .lock()
            .ok()
            .and_then(|failure| failure.clone())
    }
}

fn redacted_root_id(root_id: &str) -> String {
    format!("root:{}", sha256_hex(root_id.as_bytes()))
}

fn canonical_root(configured_root: &str) -> Result<(PathBuf, String), BlobError> {
    let configured = PathBuf::from(configured_root);
    reject_reparse_components(&configured)?;
    fs::create_dir_all(&configured).map_err(|error| {
        native_capacity_error(
            &error,
            BlobCapacityStage::RootLeaseCreate,
            BlobCapacityIdentity::RootLease {
                root_id: redacted_root_id(configured_root),
                lease_id: None,
            },
            None,
            BlobCapacityEffect::PartialWriteUnknown,
        )
        .unwrap_or_else(|| BlobError::Provider("create configured Blob root failed".to_owned()))
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
        native_capacity_error(
            &error,
            BlobCapacityStage::RootLeaseCreate,
            BlobCapacityIdentity::RootLease {
                root_id: redacted_root_id(configured_root),
                lease_id: None,
            },
            None,
            BlobCapacityEffect::PartialWriteUnknown,
        )
        .unwrap_or_else(|| {
            BlobError::Provider("canonicalize configured Blob root failed".to_owned())
        })
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
    ensure_lock_path_not_reparse(&lock_path, root_id)?;
    let token = lease_token(process_id);
    let mut file = open_owned_root_lease(&lock_path, root_id, Some(&token))?;
    let record = RootLeaseRecord {
        version: ROOT_LEASE_VERSION,
        token: token.clone(),
        root_id: root_id.to_owned(),
        process_id,
        heartbeat_unix_ms: now_unix_ms(),
    };
    write_lease_record(&mut file, &record).map_err(|failure| {
        lease_record_capacity_error(
            &failure,
            BlobCapacityStage::RootLeaseCreate,
            root_id,
            Some(&token),
        )
        .unwrap_or_else(|| BlobError::Provider("write Blob root lease failed".to_owned()))
    })?;
    Ok((lock_path, token, file))
}

fn ensure_lock_path_not_reparse(lock_path: &Path, root_id: &str) -> Result<(), BlobError> {
    match fs::symlink_metadata(lock_path) {
        Ok(metadata) if is_reparse_point(&metadata) => Err(BlobError::InvalidContract(
            "Blob root lease reparse points are not permitted".to_owned(),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(native_capacity_error(
            &error,
            BlobCapacityStage::RootLeaseCreate,
            BlobCapacityIdentity::RootLease {
                root_id: redacted_root_id(root_id),
                lease_id: None,
            },
            None,
            BlobCapacityEffect::NotAttempted,
        )
        .unwrap_or_else(|| BlobError::Provider("inspect Blob root lease failed".to_owned()))),
    }
}

#[cfg(windows)]
fn open_owned_root_lease(
    lock_path: &Path,
    root_id: &str,
    lease_id: Option<&str>,
) -> Result<fs::File, BlobError> {
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
                    native_capacity_error(
                        &error,
                        BlobCapacityStage::RootLeaseCreate,
                        BlobCapacityIdentity::RootLease {
                            root_id: redacted_root_id(root_id),
                            lease_id: lease_id.map(redacted_root_id),
                        },
                        None,
                        BlobCapacityEffect::PartialWriteUnknown,
                    )
                    .unwrap_or_else(|| {
                        BlobError::Provider("open existing Blob root lease failed".to_owned())
                    })
                }
            })
        }
        Err(error) => Err(native_capacity_error(
            &error,
            BlobCapacityStage::RootLeaseCreate,
            BlobCapacityIdentity::RootLease {
                root_id: redacted_root_id(root_id),
                lease_id: lease_id.map(redacted_root_id),
            },
            None,
            BlobCapacityEffect::PartialWriteUnknown,
        )
        .unwrap_or_else(|| BlobError::Provider("create Blob root lease failed".to_owned()))),
    }
}

#[cfg(not(windows))]
fn open_owned_root_lease(
    lock_path: &Path,
    root_id: &str,
    lease_id: Option<&str>,
) -> Result<fs::File, BlobError> {
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
                native_capacity_error(
                    &error,
                    BlobCapacityStage::RootLeaseCreate,
                    BlobCapacityIdentity::RootLease {
                        root_id: redacted_root_id(root_id),
                        lease_id: lease_id.map(redacted_root_id),
                    },
                    None,
                    BlobCapacityEffect::PartialWriteUnknown,
                )
                .unwrap_or_else(|| BlobError::Provider("create Blob root lease failed".to_owned()))
            }
        })
}

/// Which physical phase of one native lease-record write failed.
///
/// I5.12 orders "flush and fsync ciphertext plus metadata" as a step of its own,
/// *before* the atomic rename, so a native `fsync` failure and a native write
/// failure are two different observations carrying two different certainties.
/// `std::io::Error` erases that distinction, so it is recovered here — at the
/// only place in this crate that performs a native file sync itself. Every
/// other durability boundary is owned by a platform port, which reports its own
/// stage through the wrapped-port rule in
/// [`bind_platform_capacity_with_effect`]. Issue #864: "file sync failure
/// remains distinct from write failure".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseRecordPhase {
    /// The record did not provably reach the file in full.
    Write,
    /// Every byte reached the file; only the file's own durability boundary
    /// (`File::sync_all`) failed.
    FileSync,
}

/// One failed lease-record write, retaining the phase that failed beside the
/// untouched `std::io::Error` so [`native_capacity_cause`] still reads the
/// typed `raw_os_error` from its proper target namespace and no diagnostic
/// string is ever parsed for a code.
struct LeaseRecordFailure {
    phase: LeaseRecordPhase,
    error: std::io::Error,
}

fn write_lease_record(
    file: &mut fs::File,
    record: &RootLeaseRecord,
) -> Result<(), LeaseRecordFailure> {
    let bytes = serde_json::to_vec(record).map_err(|error| LeaseRecordFailure {
        phase: LeaseRecordPhase::Write,
        error: std::io::Error::other(error),
    })?;
    let mut write = || -> std::io::Result<()> {
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        Ok(())
    };
    write().map_err(|error| LeaseRecordFailure {
        phase: LeaseRecordPhase::Write,
        error,
    })?;
    file.sync_all().map_err(|error| LeaseRecordFailure {
        phase: LeaseRecordPhase::FileSync,
        error,
    })
}

/// Maps one failed native lease-record write onto the capacity evidence its
/// phase actually supports.
///
/// A `Write` failure may have left a partial record staged, so the byte
/// progress stays unknown — it is never restated as the encoded length, which
/// would read as committed bytes. A `FileSync` failure happened *after* every
/// byte was written: the record is staged and may already be durable, so the
/// observation is a possible mutation of the lease rather than a partial write,
/// and the two certainties stay on independent axes (issue #864: "failure
/// cause and effect certainty are independent"). Neither phase is a directory
/// or publication flush: the containing-directory entry was installed by the
/// earlier exclusive `create_new` in [`open_owned_root_lease`], not by this
/// record write, so `DirectoryFlush` is never asserted here.
fn lease_record_capacity_error(
    failure: &LeaseRecordFailure,
    stage: BlobCapacityStage,
    root_id: &str,
    lease_id: Option<&str>,
) -> Option<BlobError> {
    let (stage, effect) = match failure.phase {
        LeaseRecordPhase::Write => (stage, BlobCapacityEffect::PartialWriteUnknown),
        LeaseRecordPhase::FileSync => (
            BlobCapacityStage::FileFlush,
            BlobCapacityEffect::PossibleMutation,
        ),
    };
    native_capacity_error(
        &failure.error,
        stage,
        BlobCapacityIdentity::RootLease {
            root_id: redacted_root_id(root_id),
            lease_id: lease_id.map(redacted_root_id),
        },
        None,
        effect,
    )
}

fn native_capacity_cause(error: &std::io::Error) -> Option<BlobCapacityCause> {
    #[cfg(windows)]
    if error.kind() == std::io::ErrorKind::StorageFull
        && let Some(code) = error.raw_os_error()
    {
        match code {
            112 => return Some(BlobCapacityCause::WindowsErrorDiskFull { code: 112 }),
            39 => return Some(BlobCapacityCause::WindowsErrorHandleDiskFull { code: 39 }),
            _ => {}
        }
    }
    #[cfg(target_os = "linux")]
    if error.kind() == std::io::ErrorKind::StorageFull && error.raw_os_error() == Some(LINUX_ENOSPC)
    {
        return Some(BlobCapacityCause::PosixEnospc { code: LINUX_ENOSPC });
    }
    (error.kind() == std::io::ErrorKind::StorageFull).then_some(BlobCapacityCause::IoStorageFull)
}

fn native_capacity_error(
    error: &std::io::Error,
    stage: BlobCapacityStage,
    identity: BlobCapacityIdentity,
    attempted_bytes: Option<u64>,
    effect: BlobCapacityEffect,
) -> Option<BlobError> {
    let cause = native_capacity_cause(error)?;
    Some(BlobError::StorageCapacity {
        failure: Box::new(BlobCapacityFailure {
            identity,
            stage,
            evidence: BlobCapacityEvidence {
                cause,
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
            recovery: match effect {
                BlobCapacityEffect::PossiblePublication { .. }
                | BlobCapacityEffect::DurabilityUnconfirmed { .. }
                | BlobCapacityEffect::PossibleMutation => {
                    BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
                }
                BlobCapacityEffect::NotAttempted | BlobCapacityEffect::PartialWriteUnknown => {
                    BlobCapacityRecovery::CapacityRevalidationRequired
                }
            },
        }),
    })
}

#[derive(Clone, Copy, Debug)]
struct InvalidCapacityEvidence;

/// Whether an effect demands reconciliation of the *same* operation before any
/// new attempt may be issued.
///
/// This is the same split `BlobCapacityFailure::validate` enforces when it
/// rejects a `recovery` that does not match effect certainty, restated here so
/// the binding rule below and the contract the bound record must satisfy cannot
/// disagree.
fn effect_requires_reconciliation(effect: BlobCapacityEffect) -> bool {
    matches!(
        effect,
        BlobCapacityEffect::PossibleMutation
            | BlobCapacityEffect::PossiblePublication { .. }
            | BlobCapacityEffect::DurabilityUnconfirmed { .. }
    )
}

fn bind_platform_capacity_attempt(
    error: BlobError,
    stage: BlobCapacityStage,
    identity: BlobCapacityIdentity,
    attempted_bytes: u64,
) -> Result<BlobError, InvalidCapacityEvidence> {
    let error = bind_platform_capacity_with_effect(
        error,
        stage,
        identity,
        Some(BlobCapacityEffect::PartialWriteUnknown),
    )?;
    let BlobError::StorageCapacity { mut failure } = error else {
        return Ok(error);
    };
    // The offered buffer length is only what reached the native write
    // boundary. A port that observed its own progress keeps that observation;
    // an unknown partial write stays unknown and is never restated as the full
    // buffer, which would read as committed bytes.
    failure.evidence.attempted_bytes = failure.evidence.attempted_bytes.or(Some(attempted_bytes));
    Ok(BlobError::StorageCapacity { failure })
}

/// Binds a durable journal create/replace failure to the operation that owns the
/// journal.
///
/// The caller states `JournalWrite` because the *journal* is the object being
/// written; whether the port failed while writing the journal or while flushing
/// it is the port's own observation, and both the stage and the effect that
/// observation carries are preserved by
/// [`bind_platform_capacity_with_effect`]'s boundary rules (issue #864: "Wrapped
/// ports must preserve typed cause/code and stage"). The serialized buffer
/// length is likewise only a caller-side default, so a port that observed its
/// own progress keeps that observation rather than having it restated as the
/// whole buffer.
fn bind_journal_capacity(
    error: BlobError,
    journal: &StageJournal,
    attempted_bytes: u64,
) -> Result<BlobError, InvalidCapacityEvidence> {
    let effect = if journal.state == PublishState::JournalPrepared {
        BlobCapacityEffect::PartialWriteUnknown
    } else {
        BlobCapacityEffect::PossiblePublication {
            state: journal.state,
        }
    };
    let error = bind_platform_capacity_with_effect(
        error,
        BlobCapacityStage::JournalWrite,
        BlobCapacityIdentity::Journal {
            operation_id: journal.operation_id.clone(),
            idempotency_key: journal.idempotency_key.clone(),
            locator: None,
        },
        Some(effect),
    )?;
    let BlobError::StorageCapacity { mut failure } = error else {
        return Ok(error);
    };
    // A port that observed its own partial progress keeps that observation. The
    // encoded journal length is only what reached the native write boundary, so
    // it fills in an unobserved value and never overwrites a real one, which
    // would read as committed bytes.
    failure.evidence.attempted_bytes = failure.evidence.attempted_bytes.or(Some(attempted_bytes));
    Ok(BlobError::StorageCapacity { failure })
}

/// Binds a wrapped port's typed capacity failure to this service's own
/// operation/stage identity.
///
/// Stage collision rule (issue #864, "Wrapped ports must preserve typed
/// cause/code and stage before conversion to text"):
///
/// ```text
/// port reported a durability boundary (FileFlush | DirectoryFlush)
///   → the port's stage wins, verbatim;
/// port reported any other stage
///   → the caller's stage wins.
/// ```
///
/// The asymmetry is not arbitrary. A `BlobPlatformPort` method such as
/// `write_new_durable` or `replace_durable` is structurally unable to know
/// which Blob object the service asked it to write, so a stage it reports there
/// is an internal phase label of one port call and the caller's stage is the
/// more precise statement about *which* object failed. The two boundary rows are
/// the opposite case: only the port performed the `fsync`, and only the port can
/// distinguish its own file flush from its own directory flush — the service sees
/// one failed call and cannot express that difference at all. Overwriting those
/// two with the caller's stage is the exact information loss issue #864 names.
///
/// Root-lease create versus heartbeat is not a collision: the heartbeat path
/// writes the lease file directly and never reaches a port, so the only port
/// that can author a root-lease stage is `claim_root`, whose stage the caller
/// states identically.
///
/// The same asymmetry decides the *effect*, but only in the direction that can
/// lose information. A caller states the effect of the operation it asked for;
/// it cannot state what its bytes or its directory entry became inside a port
/// call, and `BlobCapacityEffect` is defined as the owner's own observation
/// ("whether the owner also left a possible physical effect"). A caller-side
/// default must therefore never *overwrite* a port observation; the rule below
/// only ever declines to overwrite:
///
/// ```text
/// port reported a durability boundary (FileFlush | DirectoryFlush),
///   and the caller's default requires same-operation reconciliation,
///   and the port's own effect does not
///   → the caller's effect stands; the port's weaker statement is not
///     substituted for it.
/// otherwise
///   → the caller's effect applies, exactly as before.
/// ```
///
/// The first row is the loss issue #864 names. A directory/publication sync
/// failure the owner reports at its own `FileFlush`/`DirectoryFlush` boundary
/// carries the effect that boundary actually produced — typically
/// `DurabilityUnconfirmed { possible_effect: true }`, a possible installed effect
/// whose durability is unconfirmed. Restating that as the caller's
/// `NotAttempted` or `PartialWriteUnknown` default would drop the possible effect
/// *and* its unconfirmed-durability axis, and would downgrade the recovery
/// disposition from same-operation reconciliation to a bare capacity
/// revalidation — exactly the blind new attempt the issue forbids ("if commit is
/// possible, reconcile that same operation first even after space is freed").
///
/// The rule is deliberately one-directional. A port whose own boundary
/// observation is the *stronger* one is never overwritten either, so the
/// preserved `DurabilityUnconfirmed`/`PossibleMutation` statements survive; and a
/// port observation is never promoted or reinterpreted, because the owner is the
/// only party that can know what its own flush did. Only the one substitution
/// that would destroy the caller's stronger reconciliation claim is declined.
///
/// Nothing else is dropped: the port's cause, native code and attempted-byte
/// observation are carried through untouched in every case, and
/// [`effect_requires_reconciliation`] is the same effect/recovery split
/// `BlobCapacityFailure::validate` enforces on the bound record, so the two
/// cannot disagree.
fn bind_platform_capacity_with_effect(
    error: BlobError,
    stage: BlobCapacityStage,
    identity: BlobCapacityIdentity,
    effect_override: Option<BlobCapacityEffect>,
) -> Result<BlobError, InvalidCapacityEvidence> {
    let BlobError::StorageCapacity { failure } = error else {
        return Ok(error);
    };
    let mut evidence = failure.evidence;
    let port_reported_durability_boundary = failure.stage.reports_durability_boundary();
    if let Some(effect) = effect_override
        && !port_reported_durability_boundary
    {
        evidence.effect = effect;
    }
    let recovery = if effect_requires_reconciliation(evidence.effect) {
        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
    } else {
        match evidence.effect {
            BlobCapacityEffect::NotAttempted | BlobCapacityEffect::PartialWriteUnknown => {
                BlobCapacityRecovery::CapacityRevalidationRequired
            }
            // Unreachable by construction: the predicate above already selected
            // every reconciling effect, and the vocabulary is closed. Spelled
            // out rather than left implicit so an added variant cannot silently
            // become a capacity revalidation while its own predicate says it
            // needs reconciliation.
            BlobCapacityEffect::PossibleMutation
            | BlobCapacityEffect::PossiblePublication { .. }
            | BlobCapacityEffect::DurabilityUnconfirmed { .. } => {
                BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
            }
        }
    };
    let stage = if port_reported_durability_boundary {
        failure.stage
    } else {
        stage
    };
    let bound = BlobError::StorageCapacity {
        failure: Box::new(BlobCapacityFailure {
            identity,
            stage,
            evidence,
            cas_request: failure.cas_request,
            cas_observed: failure.cas_observed,
            cas_backend_generation: failure.cas_backend_generation,
            cas_durability: failure.cas_durability,
            cleanup: failure.cleanup,
            cleanup_stage: failure.cleanup_stage,
            cleanup_evidence: failure.cleanup_evidence,
            gc_state: failure.gc_state,
            recovery,
        }),
    };
    if matches!(&bound, BlobError::StorageCapacity { failure } if failure.validate().is_err()) {
        Err(InvalidCapacityEvidence)
    } else {
        Ok(bound)
    }
}

/// Binds a conditional-mutation capacity failure to its exact CAS request.
///
/// `CasJournal` is stated by the caller rather than deferred to a port-reported
/// stage because the capacity validators make that stage the *only* stage that
/// may carry `cas_request`/`cas_observed`/`cas_backend_generation`/
/// `cas_durability`: preserving any other port stage here would make
/// `BlobCapacityFailure::validate` reject the record and downgrade typed
/// capacity evidence to an unknown outcome. The reconciliation frame the caller
/// owns is therefore the stage of record, and the port's typed cause, native
/// code and effect evidence are carried through unchanged.
fn bind_capacity_cas(
    error: BlobError,
    request: &BlobCasRequest,
) -> Result<BlobError, InvalidCapacityEvidence> {
    let BlobError::StorageCapacity { failure } = error else {
        return Ok(error);
    };
    let mut failure = *failure;
    let observations_match = failure
        .cas_request
        .as_deref()
        .is_some_and(|candidate| candidate == request);
    if failure.cas_request.is_none()
        && (failure.cas_observed.is_some()
            || failure.cas_backend_generation.is_some()
            || failure.cas_durability.is_some())
    {
        return Err(InvalidCapacityEvidence);
    }
    failure.identity = BlobCapacityIdentity::Operation {
        context: Box::new(request.context.clone()),
        locator: None,
    };
    failure.stage = BlobCapacityStage::CasJournal;
    failure.evidence.effect = BlobCapacityEffect::PossibleMutation;
    failure.cas_request = Some(Box::new(request.clone()));
    if !observations_match {
        failure.cas_observed = None;
        failure.cas_backend_generation = None;
        failure.cas_durability = None;
    }
    failure.recovery = BlobCapacityRecovery::ReconcileSameOperationThenRevalidate;
    if failure.validate().is_err() {
        return Err(InvalidCapacityEvidence);
    }
    Ok(BlobError::StorageCapacity {
        failure: Box::new(failure),
    })
}

fn retain_capacity_gc_state(error: BlobError, gc_phase: GcState) -> BlobError {
    let BlobError::StorageCapacity { mut failure } = error else {
        return error;
    };
    failure.gc_state = Some(gc_phase);
    BlobError::StorageCapacity { failure }
}

/// Records a secondary cleanup observation beside the primary capacity
/// failure it followed.
///
/// Cleanup is additional evidence: it never replaces the primary error, and
/// the primary error's own identity, stage and cause are preserved verbatim.
fn retain_cleanup_evidence(cleanup_error: BlobError, primary: BlobError) -> BlobError {
    let BlobError::StorageCapacity {
        failure: mut primary,
    } = primary
    else {
        // A non-capacity primary error is already complete evidence; the
        // cleanup observation is only retained beside a capacity failure,
        // which is the family that carries a cleanup slot.
        return primary;
    };
    let BlobError::StorageCapacity { failure } = cleanup_error else {
        // The cleanup demonstrably failed; it simply did not fail on capacity,
        // so it carries no capacity evidence to retain. Leaving the slot at its
        // `NotApplicable` default would report a cleanup that provably did not
        // happen as one that never applied, collapsing the success/failure/
        // unknown distinction issue #864 requires. `Failed` without evidence is
        // the honest row and already validates (`validate_capacity_cleanup`
        // only requires stage and evidence to be supplied together).
        if primary.cleanup == BlobCapacityCleanup::NotApplicable {
            primary.cleanup = BlobCapacityCleanup::Failed;
        }
        return BlobError::StorageCapacity { failure: primary };
    };
    primary.cleanup = BlobCapacityCleanup::Unknown;
    primary.cleanup_stage = Some(BlobCapacityStage::Cleanup);
    primary.cleanup_evidence = Some(failure.evidence);
    if primary.validate().is_err() {
        // Rejecting the composite must not discard the primary evidence; the
        // cleanup observation is dropped instead.
        primary.cleanup_stage = None;
        primary.cleanup_evidence = None;
        primary.cleanup = BlobCapacityCleanup::NotApplicable;
    }
    BlobError::StorageCapacity { failure: primary }
}

fn bind_cleanup_capacity(
    error: BlobError,
    operation_id: &str,
    idempotency_key: &str,
    locator: &BlobLocator,
    state: PublishState,
) -> BlobError {
    match error {
        BlobError::StorageCapacity { .. } => {
            let error = match bind_platform_capacity_with_effect(
                error,
                BlobCapacityStage::Cleanup,
                BlobCapacityIdentity::Journal {
                    operation_id: operation_id.to_owned(),
                    idempotency_key: idempotency_key.to_owned(),
                    locator: Some(locator.clone()),
                },
                Some(BlobCapacityEffect::PossiblePublication { state }),
            ) {
                Ok(error) => error,
                Err(InvalidCapacityEvidence) => {
                    return BlobError::UnknownPublishOutcome {
                        operation_id: operation_id.to_owned(),
                        state,
                    };
                }
            };
            let BlobError::StorageCapacity { mut failure } = error else {
                return error;
            };
            // The last durable phase is known, but a cleanup error cannot
            // prove whether this individual removal took effect. The typed
            // evidence the port reported is retained beside that verdict so
            // recovery sees the cleanup cause and phase, not just `Unknown`.
            failure.cleanup = BlobCapacityCleanup::Unknown;
            failure.cleanup_stage = Some(BlobCapacityStage::Cleanup);
            failure.cleanup_evidence = Some(failure.evidence);
            failure.cleanup = BlobCapacityCleanup::Failed;
            if failure.validate().is_err() {
                failure.cleanup_stage = None;
                failure.cleanup_evidence = None;
                failure.cleanup = BlobCapacityCleanup::Unknown;
            }
            BlobError::StorageCapacity { failure }
        }
        other => other,
    }
}

fn bind_platform_capacity_gc(
    error: BlobError,
    stage: BlobCapacityStage,
    identity: BlobCapacityIdentity,
    gc_phase: GcState,
) -> BlobError {
    let operation_id = match &identity {
        BlobCapacityIdentity::Journal { operation_id, .. } => operation_id.clone(),
        BlobCapacityIdentity::Operation { context, .. } => {
            context.operation.operation_id.to_string()
        }
        BlobCapacityIdentity::RootLease { root_id, .. } => root_id.clone(),
    };
    let error = match bind_platform_capacity_with_effect(
        error,
        stage,
        identity,
        Some(BlobCapacityEffect::PossibleMutation),
    ) {
        Ok(error) => error,
        Err(InvalidCapacityEvidence) => {
            return BlobError::UnknownGcOutcome {
                operation_id,
                state: gc_phase,
            };
        }
    };
    let BlobError::StorageCapacity { mut failure } = error else {
        return error;
    };
    failure.gc_state = Some(gc_phase);
    BlobError::StorageCapacity { failure }
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
        if let Err(write_failure) = write_lease_record(file, &record) {
            let failure = lease_record_capacity_error(
                &write_failure,
                BlobCapacityStage::RootLeaseHeartbeat,
                &lease.root_id,
                Some(&lease.token),
            )
            .unwrap_or_else(|| {
                BlobError::Provider(format!(
                    "Blob root lease heartbeat write failed: kind={:?};raw_os_error={:?}",
                    write_failure.error.kind(),
                    write_failure.error.raw_os_error()
                ))
            });
            if let Ok(mut retained) = lease.heartbeat_failure.lock() {
                *retained = Some(failure);
            }
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
    /// Replaces one durable journal record through the provider's conditional
    /// primitive. Implementations must compare and install while their stable
    /// serialization boundary remains held; a read/compare/replace fallback is
    /// not a valid implementation.
    fn cas_capability(&self) -> BlobCasCapability;
    fn compare_and_replace_durable(
        &mut self,
        request: &BlobCasRequest,
        bytes: &[u8],
    ) -> Result<BlobCasProviderResult, BlobError>;
    /// Returns retained operation-bound evidence for a prior CAS step. A
    /// provider that cannot retain this status must return `Ok(None)`; the
    /// service then stops recovery with an unknown outcome.
    fn cas_status(&self, operation_id: &str) -> Result<Option<BlobCasProviderResult>, BlobError>;
    /// Provider generation used to fence a conditional operation. It must be
    /// stable for the provider instance and change whenever its authority view
    /// changes.
    fn backend_generation(&self) -> Result<u64, BlobError>;
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

/// Provider evidence for one conditional journal operation. The service binds
/// this physical result to the authority-issued request and receipt before it
/// exposes success to its caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobCasProviderResult {
    pub operation_id: String,
    pub request_commitment_sha256: String,
    pub observed: BlobCasState,
    pub replacement_sha256: String,
    pub replacement_length: u64,
    pub backend_generation: u64,
    pub observed_durability: BlobCasDurability,
    pub success: BlobCasSuccessKind,
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
    Applied(Box<BlobDeletionReceipt>),
    NotApplied,
    Unknown,
}

/// Runtime port to G-04/S-01 authority. `BlobStore` cannot self-certify reachability.
pub trait BlobLiveSetPort: Send + Sync {
    fn revalidate(&mut self, proof: &BlobLiveSetProof) -> Result<LiveSetRevalidation, BlobError>;

    /// Reconciles an existing deletion intent against the provider target.
    /// Implementations must return `Unknown` when they cannot prove the exact
    /// effect identity and must not perform a blind retry. The receipt for an
    /// `Applied` outcome must cover the residency-scoped object named by
    /// (`locator`, `residency_sha256`): the service validates the receipt
    /// path digest against the derived scope paths and then requires both
    /// files to be absent.
    fn reconcile_delete(
        &mut self,
        _operation_id: &str,
        _proof: &BlobLiveSetProof,
        _locator: &BlobLocator,
        _intent_revision: u64,
        _residency_sha256: &str,
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
        _residency_sha256: &str,
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
    /// T3-B residency digest (I05-12 scope identity shim). Recomputed from
    /// the stored locator/policy/crypto on every load; a mismatch proves the
    /// metadata was transplanted across residency domains.
    residency_sha256: String,
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
        validate_sha256(&self.residency_sha256, "residency_sha256")?;
        // The residency binding is recomputed from the stored fields, never
        // trusted from the stored digest alone: equal bytes under a different
        // policy or key lineage must not validate against this object.
        let bound = residency_scope(&self.locator, &self.policy, &self.crypto)?;
        if bound.digest != self.residency_sha256 {
            return Err(BlobError::MetadataPayloadMismatch);
        }
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
    /// Storage identity this operation settles. Recovery needs it to bind a
    /// publication capacity observation to the object it published; a journal
    /// written before this binding keeps `None` and stays fenced.
    #[serde(default)]
    locator: Option<BlobLocator>,
    /// A publication/durability boundary the platform owner has not proven for
    /// this operation. While it is set, recovery must not promote any durable
    /// phase and must not delete this journal: content equality proves
    /// identity, never commit or durability.
    #[serde(default)]
    pending_publication: Option<BlobPublicationObligation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationCommit {
    operation_id: String,
    idempotency_key: String,
    locator: BlobLocator,
    /// Residency scope the operation converged to. A same-operation replay
    /// under a rotated key resolves to this committed scope (operation
    /// identity wins); it never silently adopts a second scope.
    residency_sha256: String,
    metadata_sha256: String,
}

impl OperationCommit {
    fn validate(&self) -> Result<(), BlobError> {
        valid_operation_text(&self.operation_id, "commit.operation_id")?;
        valid_operation_text(&self.idempotency_key, "commit.idempotency_key")?;
        self.locator.validate()?;
        validate_sha256(&self.residency_sha256, "commit.residency_sha256")?;
        validate_sha256(&self.metadata_sha256, "commit.metadata_sha256")
    }
}

/// Decodes an operation commit with an explicit legacy disposition: commits
/// written before the T3-B residency binding carry no scope and are rejected
/// instead of being matched to a caller-supplied locator alone.
fn decode_commit(bytes: &[u8]) -> Result<OperationCommit, BlobError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| BlobError::MetadataPayloadMismatch)?;
    if value.get("residency_sha256").is_none() {
        return Err(BlobError::PlanGap(
            "legacy operation commit predates T3-B residency binding; reconcile through the original stage journal or re-stage from source — never adopt by locator alone".to_owned(),
        ));
    }
    let commit: OperationCommit =
        serde_json::from_value(value).map_err(|_| BlobError::MetadataPayloadMismatch)?;
    commit.validate()?;
    Ok(commit)
}

impl StageJournal {
    fn validate(&self) -> Result<(), BlobError> {
        valid_operation_text(&self.operation_id, "journal.operation_id")?;
        valid_operation_text(&self.idempotency_key, "journal.idempotency_key")?;
        validate_sha256(&self.expected_payload_sha256, "journal.payload_sha256")?;
        validate_sha256(&self.expected_metadata_sha256, "journal.metadata_sha256")?;
        if let Some(obligation) = &self.pending_publication {
            obligation.validate()?;
            // The obligation is only meaningful while it is still owed by *this*
            // operation at one of this journal's own publication targets. A
            // decoded journal that pairs an obligation with another operation or
            // an unrelated destination is a corrupt recovery record, not a
            // licence to advance.
            let journal_destinations = [
                self.final_payload.normalized_identity(),
                self.final_metadata.normalized_identity(),
                self.temp_payload.normalized_identity(),
                self.temp_metadata.normalized_identity(),
            ];
            let destination_is_ours = journal_destinations
                .iter()
                .any(|candidate| *candidate == obligation.destination)
                // The commit marker is derived from this operation's own
                // identity inside the transactions namespace; the journal keeps
                // it as a stable derived identity rather than a caller path.
                || (obligation.stage == BlobCapacityStage::CommitWrite
                    && obligation.destination.starts_with("transactions/"));
            if obligation.operation_id != self.operation_id
                || obligation.idempotency_key != self.idempotency_key
                || !destination_is_ours
            {
                return Err(BlobError::PlanGap(
                    "stage journal obligation does not belong to this operation".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TombstoneCas {
    /// Tombstone journal wire revision. Revision 2 requires the full CAS block.
    version: u32,
    context: BlobReceiptContext,
    root_lease: BlobRootLease,
    target: WorkScopePath,
    expected: BlobCasState,
    expected_backend_generation: u64,
    requested_durability: BlobCasDurability,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tombstone {
    operation_id: String,
    parent_idempotency_key: String,
    revision: u64,
    intent_revision: u64,
    proof_id: BlobId,
    proof_snapshot_sha256: String,
    locator: BlobLocator,
    /// Residency scope this tombstone purges. GC is per scope: purging one
    /// domain never disturbs equal bytes in another domain.
    residency_sha256: String,
    live_set: BlobLiveSetProof,
    payload: WorkScopePath,
    metadata: WorkScopePath,
    state: GcState,
    receipt: Option<BlobDeletionReceipt>,
    /// Versioned exact CAS authority and target context. `None` is used only
    /// while a new record is being assembled; legacy decoded records fail closed.
    cas: Option<TombstoneCas>,
}

impl Tombstone {
    fn validate_base(&self) -> Result<(), BlobError> {
        valid_operation_text(&self.operation_id, "tombstone.operation_id")?;
        valid_operation_text(
            &self.parent_idempotency_key,
            "tombstone.parent_idempotency_key",
        )?;
        if self.revision == 0 || self.intent_revision == 0 || self.intent_revision > self.revision {
            return Err(BlobError::PlanGap(
                "GC tombstone revision is missing".to_owned(),
            ));
        }
        validate_sha256(&self.proof_snapshot_sha256, "tombstone.snapshot_sha256")?;
        self.locator.validate()?;
        validate_sha256(&self.residency_sha256, "tombstone.residency_sha256")?;
        self.live_set.validate_complete()?;
        // The tombstone paths must be exactly the derived placement for
        // (locator, residency). A transplanted tombstone (right locator,
        // wrong scope paths) can never authorize a deletion.
        let scope = ResidencyScope {
            digest: self.residency_sha256.clone(),
        };
        if scoped_payload_path(&self.locator, &scope)?.normalized_identity()
            != self.payload.normalized_identity()
            || scoped_metadata_path(&self.locator, &scope)?.normalized_identity()
                != self.metadata.normalized_identity()
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
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

    fn validate(&self) -> Result<(), BlobError> {
        self.validate_base()?;
        let Some(cas) = &self.cas else {
            return Err(BlobError::PlanGap(
                "legacy GC tombstone is missing exact CAS authority context".to_owned(),
            ));
        };
        if cas.version != 2 {
            return Err(BlobError::PlanGap(
                "GC tombstone CAS wire version is unsupported".to_owned(),
            ));
        }
        cas.context
            .validate_for(eliot_receipts::EffectClass::ReversibleMutation)?;
        cas.root_lease.validate_context(&cas.context)?;
        cas.expected.validate()?;
        if cas.target.normalized_identity().is_empty()
            || !cas.target.normalized_identity().starts_with("tombstones/")
        {
            return Err(BlobError::PlanGap(
                "GC tombstone CAS target is outside its journal namespace".to_owned(),
            ));
        }
        if cas.context.operation.operation_id.to_string() == self.operation_id {
            return Err(BlobError::PlanGap(
                "GC tombstone CAS step identity must differ from its parent operation".to_owned(),
            ));
        }
        let expected_step_identity =
            tombstone_cas_step_identity(&self.operation_id, &cas.target, self.revision);
        if cas.context.operation.operation_id.as_str() != expected_step_identity
            || cas.context.operation.idempotency_key != expected_step_identity
            || cas.context.operation.operation_kind != "blob-tombstone-cas"
        {
            return Err(BlobError::PlanGap(
                "GC tombstone CAS step identity does not match its parent, target, and revision"
                    .to_owned(),
            ));
        }
        if cas.expected_backend_generation == 0 {
            return Err(BlobError::PlanGap(
                "GC tombstone CAS backend generation is missing".to_owned(),
            ));
        }
        if !matches!(
            cas.requested_durability,
            BlobCasDurability::NotRequested | BlobCasDurability::Requested
        ) {
            return Err(BlobError::PlanGap(
                "GC tombstone CAS durability request is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Decodes stored blob metadata with an explicit migration disposition:
/// metadata written before the T3-B residency binding carries no scope and is
/// rejected instead of being matched to a caller-supplied locator alone.
/// Recovery is an explicit re-stage from source (re-encrypt-copy) with a new
/// receipt — never a silent adoption under a default domain.
fn decode_metadata(bytes: &[u8]) -> Result<StoredMetadata, BlobError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| BlobError::MetadataPayloadMismatch)?;
    if value.get("residency_sha256").is_none() {
        return Err(BlobError::PlanGap(
            "stored blob metadata predates T3-B residency binding; re-stage from source as an explicit re-encrypt-copy with a new receipt — legacy objects are never silently adopted".to_owned(),
        ));
    }
    let metadata: StoredMetadata =
        serde_json::from_value(value).map_err(|_| BlobError::MetadataPayloadMismatch)?;
    metadata.validate()?;
    Ok(metadata)
}

fn decode_tombstone(bytes: &[u8]) -> Result<Tombstone, BlobError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| BlobError::MetadataPayloadMismatch)?;
    if value.get("cas").is_none() {
        return Err(BlobError::PlanGap(
            "legacy GC tombstone is missing versioned CAS authority context".to_owned(),
        ));
    }
    if value.get("residency_sha256").is_none() {
        return Err(BlobError::PlanGap(
            "legacy GC tombstone predates T3-B residency binding; it cannot authorize a scope-blind deletion — quiesce, reconcile, and re-issue GC under the current live set".to_owned(),
        ));
    }
    serde_json::from_value(value).map_err(|_| BlobError::MetadataPayloadMismatch)
}

fn tombstone_cas_step_identity(
    parent_operation_id: &str,
    target: &WorkScopePath,
    revision: u64,
) -> String {
    format!(
        "{parent_operation_id}:tombstone-cas:target={}:revision={revision}",
        target.normalized_identity()
    )
}

fn cas_unknown(
    request: &BlobCasRequest,
    observed: Option<BlobCasState>,
    backend_generation: Option<u64>,
    durability: BlobCasDurability,
) -> BlobError {
    BlobError::CasFailure {
        failure: Box::new(BlobCasFailure::UnknownOutcome {
            request: Box::new(request.clone()),
            observed,
            observed_backend_generation: backend_generation,
            observed_durability: durability,
        }),
    }
}

fn cas_failure_is_bound(failure: &BlobCasFailure, request: &BlobCasRequest) -> bool {
    let candidate = match failure {
        BlobCasFailure::ExpectedStateConflict { request, .. }
        | BlobCasFailure::IdentityConflict { request }
        | BlobCasFailure::NotFound { request }
        | BlobCasFailure::NotAttempted { request }
        | BlobCasFailure::UnsupportedAtomicCas { request }
        | BlobCasFailure::UnknownOutcome { request, .. }
        | BlobCasFailure::DurabilityUnconfirmed { request, .. }
        | BlobCasFailure::Internal { request, .. }
        | BlobCasFailure::SuccessKindMismatch { request } => request,
    };
    let Ok(candidate_commitment) = candidate.request_commitment_sha256() else {
        return false;
    };
    let Ok(request_commitment) = request.request_commitment_sha256() else {
        return false;
    };
    candidate.context.operation.operation_id == request.context.operation.operation_id
        && candidate.context.operation.idempotency_key == request.context.operation.idempotency_key
        && candidate_commitment == request_commitment
}

fn validate_retained_cas_status(
    request: &BlobCasRequest,
    status: &BlobCasProviderResult,
) -> Result<(), BlobError> {
    let expected_success = if request.expected.sha256() == Some(request.replacement_sha256.as_str())
    {
        BlobCasSuccessKind::NoOp
    } else {
        BlobCasSuccessKind::Applied
    };
    if status.operation_id != request.context.operation.operation_id.to_string()
        || status.request_commitment_sha256 != request.request_commitment_sha256()?
        || status.observed != request.expected
        || status.replacement_sha256 != request.replacement_sha256
        || status.replacement_length != request.replacement_length
        || status.backend_generation != request.expected_backend_generation
        || status.observed_durability != BlobCasDurability::Confirmed
        || status.success != expected_success
    {
        return Err(cas_unknown(
            request,
            Some(status.observed.clone()),
            Some(status.backend_generation),
            status.observed_durability,
        ));
    }
    Ok(())
}

fn cas_durability_unconfirmed(
    request: &BlobCasRequest,
    observed: Option<BlobCasState>,
    backend_generation: Option<u64>,
) -> BlobError {
    BlobError::CasFailure {
        failure: Box::new(BlobCasFailure::DurabilityUnconfirmed {
            request: Box::new(request.clone()),
            observed,
            observed_backend_generation: backend_generation,
        }),
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

/// T3-B residency scope (I05-12 `ObjectResidencyKey`, s-04-v2 integrated).
///
/// The scope digest is the canonical [`ObjectResidencyKey::key_digest`] carried
/// by the locator itself. The on-disk `residency_sha256` field keeps its meaning
/// (the residency digest); s-04-v2 only changes its computation from the former
/// (locator, policy, crypto) shim to the versioned contract key. No default
/// domain is ever substituted: a locator without a well-formed residency key is
/// rejected by [`BlobLocator::validate`].
///
/// The caller-supplied policy and the converged service key are still validated
/// at every call site, and the key lineage must equal the residency
/// `encryption_key_domain_id` (the permitted key-lineage binding). Policy and
/// residency travel together via
/// [`BlobPolicyBinding::validate_for_residency`]; their cryptographic linkage
/// lives in the API receipt binding, not in this path digest.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ResidencyScope {
    digest: String,
}

fn residency_scope(
    locator: &BlobLocator,
    policy: &BlobPolicyBinding,
    crypto: &CryptoDescriptor,
) -> Result<ResidencyScope, BlobError> {
    locator.validate()?;
    policy.validate_for_residency(locator.residency())?;
    crypto.validate()?;
    if crypto.key_lineage != locator.residency().encryption_key_domain_id {
        return Err(BlobError::InvalidField {
            field: "crypto.key_lineage",
            reason: "must equal residency encryption_key_domain_id",
        });
    }
    let digest = locator.residency_key_digest()?;
    Ok(ResidencyScope { digest })
}

/// Residency-scoped payload path. Equal bytes in different residency domains
/// MUST yield different physical objects, so the residency digest is part of
/// the file identity — never just the directory name. The derivation starts
/// from the canonical API path (no second path scheme) and inserts the
/// digest before the generation suffix.
fn scoped_payload_path(
    locator: &BlobLocator,
    scope: &ResidencyScope,
) -> Result<WorkScopePath, BlobError> {
    validate_sha256(&scope.digest, "residency_sha256")?;
    let base = payload_path(locator)?;
    let suffix = format!(".p{}", locator.path_generation);
    let stem = base
        .normalized_identity()
        .strip_suffix(suffix.as_str())
        .ok_or(BlobError::MetadataPayloadMismatch)?;
    WorkScopePath::new(format!(
        "{stem}.r{}.p{}",
        scope.digest, locator.path_generation
    ))
    .map_err(|error| BlobError::InvalidContract(error.to_string()))
}

/// Residency-scoped metadata path (same construction as the payload path).
fn scoped_metadata_path(
    locator: &BlobLocator,
    scope: &ResidencyScope,
) -> Result<WorkScopePath, BlobError> {
    validate_sha256(&scope.digest, "residency_sha256")?;
    let base = metadata_path(locator)?;
    let suffix = format!(".m{}", locator.path_generation);
    let stem = base
        .normalized_identity()
        .strip_suffix(suffix.as_str())
        .ok_or(BlobError::MetadataPayloadMismatch)?;
    WorkScopePath::new(format!(
        "{stem}.r{}.m{}",
        scope.digest, locator.path_generation
    ))
    .map_err(|error| BlobError::InvalidContract(error.to_string()))
}

/// Prefix that enumerates every residency scope stored for one locator.
///
/// s-04-v2 places objects under residency-scoped directories
/// (`objects/g{R}/{rd[..2]}/{rd}/`), so scopes for one content hash spread
/// across residency dirs. Enumeration lists the whole generation root and lets
/// [`parse_scoped_path`] admit only byte-exact placements for the locator.
/// Enumeration is physical scope discovery for a caller-supplied locator; it
/// is never semantic-root discovery (liveness still comes only from the
/// caller-supplied live-set union).
fn scope_list_prefix(locator: &BlobLocator) -> Result<WorkScopePath, BlobError> {
    locator.validate()?;
    WorkScopePath::new(format!("objects/g{}/", locator.root_generation))
        .map_err(|error| BlobError::InvalidContract(error.to_string()))
}

/// One durably stored residency scope of a locator: both files exist as a
/// complete pair.
struct ScopedObject {
    scope: ResidencyScope,
    payload: WorkScopePath,
    metadata: WorkScopePath,
}

/// Parses the residency digest out of a scoped path and proves the path is
/// exactly the derived placement for `(locator, digest)`. A transplanted
/// path (right digest, wrong directory, or hand-built name) is rejected.
///
/// s-04-v2 layout: `objects/g{R}/{rd[..2]}/{rd}/{hash}.r{digest}.{p|m}{gen}`.
/// The digest in the filename must reproduce the exact canonical path when
/// rebuilt; anything else is not an object of this locator in that scope.
fn parse_scoped_path(
    path: &WorkScopePath,
    locator: &BlobLocator,
    kind: char,
) -> Result<ResidencyScope, BlobError> {
    let hash = locator.hash.as_str();
    let root_prefix = format!("objects/g{}/", locator.root_generation);
    let rest = path
        .normalized_identity()
        .strip_prefix(root_prefix.as_str())
        .ok_or(BlobError::MetadataPayloadMismatch)?;
    let mut parts = rest.splitn(3, '/');
    let shard = parts.next().ok_or(BlobError::MetadataPayloadMismatch)?;
    let residency_dir = parts.next().ok_or(BlobError::MetadataPayloadMismatch)?;
    let file = parts.next().ok_or(BlobError::MetadataPayloadMismatch)?;
    if shard.len() != 2 || residency_dir.len() != 64 {
        return Err(BlobError::MetadataPayloadMismatch);
    }
    validate_sha256(residency_dir, "residency_sha256")?;
    let stem = file
        .strip_prefix(format!("{hash}.r").as_str())
        .ok_or(BlobError::MetadataPayloadMismatch)?;
    if stem.len() < 64 {
        return Err(BlobError::MetadataPayloadMismatch);
    }
    let (digest, suffix) = stem.split_at(64);
    validate_sha256(digest, "residency_sha256")?;
    let expected_suffix = format!(".{kind}{}", locator.path_generation);
    if suffix != expected_suffix {
        return Err(BlobError::MetadataPayloadMismatch);
    }
    let scope = ResidencyScope {
        digest: digest.to_owned(),
    };
    let rebuilt = match kind {
        'p' => scoped_payload_path(locator, &scope)?,
        _ => scoped_metadata_path(locator, &scope)?,
    };
    if rebuilt.normalized_identity() != path.normalized_identity() {
        return Err(BlobError::MetadataPayloadMismatch);
    }
    Ok(scope)
}

/// Scope-bound AEAD nonce context: `"<content-hash>:<residency-digest>"`.
/// Equal bytes in different domains must never reuse a nonce under one key.
fn scope_nonce(locator: &BlobLocator, scope: &ResidencyScope) -> String {
    format!("{}:{}", locator.hash.as_str(), scope.digest)
}

/// Per-scope GC tombstone path. Tombstones are per residency scope (not per
/// locator) so purging one domain never disturbs another.
fn tombstone_scope_path(
    operation_id: &str,
    locator: &BlobLocator,
    scope: &ResidencyScope,
) -> Result<WorkScopePath, BlobError> {
    validate_sha256(&scope.digest, "residency_sha256")?;
    WorkScopePath::new(format!(
        "tombstones/{}-{}-r{}.json",
        operation_id,
        locator.hash.as_str(),
        scope.digest
    ))
    .map_err(|error| BlobError::InvalidContract(error.to_string()))
}

/// Immutable claimed-root state shared by every cloned service handle.
/// `os_owner` retains the OS lease behind the service claim for the full
/// service lifetime when the owner-bound constructor was used; it is `None`
/// for the ownerless unit/reference contour.
struct RootOwner {
    lease: BlobRootLease,
    claim: RootClaimProof,
    os_owner: Option<BlobRootOwner>,
    service_key: String,
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

impl<P, C, K, A, L> BlobStoreCore<P, C, K, A, L> {
    /// Releases a construction-time reservation after a failed claim. A bound
    /// service restores the reserver's OS owner entry; an ownerless attempt
    /// only drops its own service entry.
    fn release_construction_claim(service_key: &str, os_owner: Option<&BlobRootOwner>) {
        if let Some(owner) = os_owner {
            restore_os_owner(service_key, &owner.lease.token);
        } else {
            release_service_key(service_key);
        }
    }
}

impl<P, C, K, A, L> Drop for BlobStoreCore<P, C, K, A, L> {
    fn drop(&mut self) {
        // The core lives behind one `Arc` shared by every cloned handle, so
        // this runs exactly once when the last handle drops. A bound service
        // restores its reserver's OS owner entry; an ownerless service only
        // releases its own entry and never evicts a newcomer.
        Self::release_construction_claim(&self.owner.service_key, self.owner.os_owner.as_ref());
    }
}

struct BlobStoreCore<P, C, K, A, L> {
    owner: RootOwner,
    platform: RwLock<P>,
    compression: RwLock<C>,
    keys: RwLock<K>,
    aead: RwLock<A>,
    live_sets: Mutex<L>,
    shards: ShardLocks,
    /// Publication obligations whose durable journal record this service could
    /// not write. The volume rejected the journal replace, so the record a
    /// later re-entry decodes carries no obligation; retention here is what
    /// keeps the boundary in front of the next attempt.
    ///
    /// The lifecycle, stated as it actually is rather than as a bound it does not
    /// have. An entry is dropped when its own boundary is settled through
    /// [`BlobStoreCore::forget_unrecorded_publication`], and it is inserted at
    /// most once per `(operation_id, idempotency_key, destination)` triple. There
    /// is no cap, no eviction heuristic and no sweep, so the honest bound is:
    ///
    /// * one operation may hold up to three entries — its payload, its metadata
    ///   and its commit destination;
    /// * an operation that records an obligation and is never re-entered keeps
    ///   its entry for the life of this `BlobStoreCore`, and the set therefore
    ///   grows monotonically with the number of operations that recorded an
    ///   unpersistable obligation and were then abandoned.
    ///
    /// That is deliberate: an entry only ever causes an owner to be asked about a
    /// boundary again, and dropping one on a heuristic could release an operation
    /// whose boundary nobody has proven.
    unrecorded_publications: Mutex<Vec<BlobPublicationObligation>>,
    issuer_anchor: BlobIssuerTrustAnchor,
}

struct PublishVerification<'a> {
    source: &'a WorkScopePath,
    destination: &'a WorkScopePath,
    expected_sha256: &'a str,
    hard_ceiling: u64,
    operation_id: &'a str,
    idempotency_key: &'a str,
    /// Storage identity this publication settles; every publication stage
    /// requires it so recovery never reports an anonymous exhaustion.
    locator: &'a BlobLocator,
    state_before: PublishState,
    stage: BlobCapacityStage,
}

/// One publication attempt's durability verdict. See
/// [`BlobStoreCore::publish_or_verify`].
enum PublicationOutcome {
    /// The owner reported the publication and its durability boundary.
    ConfirmedDurable,
    /// The destination may already hold the exact bytes, but the owner did not
    /// prove the durability boundary. The retained error is returned unchanged
    /// and the obligation is recorded against the original operation.
    InstalledUnproven {
        error: BlobError,
        fence: BlobPublicationFence,
    },
}

/// Retains the owner-reported capacity cause for a fenced publication so a
/// later re-entry can re-emit the same typed evidence instead of inventing
/// one. A non-capacity failure keeps the obligation unconfirmed.
fn publication_fence(error: &BlobError) -> BlobPublicationFence {
    match error {
        BlobError::StorageCapacity { failure } => BlobPublicationFence::Capacity {
            cause: failure.evidence.cause,
        },
        _ => BlobPublicationFence::Unconfirmed,
    }
}

/// Storage identity one publication obligation must bind to.
///
/// A journal written before the storage-identity binding carries none and can
/// neither settle a publication nor produce an obligation for it.
fn publication_locator(journal: &StageJournal) -> Result<BlobLocator, BlobError> {
    journal.locator.clone().ok_or_else(|| {
        BlobError::PlanGap(
            "stage journal predates the storage identity a publication obligation requires"
                .to_owned(),
        )
    })
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
        os_owner: Option<BlobRootOwner>,
        ports: BlobServicePorts<P, C, K, A, L>,
    ) -> Result<Self, BlobError> {
        let BlobServicePorts {
            mut platform,
            compression,
            keys,
            aead,
            live_sets,
            issuer_anchor,
        } = ports;
        lease.validate()?;
        // Single-owner composition (T3-B): the service claim and the OS
        // `BlobRootOwner` claim reserve one process-local key. A root
        // reserved through either seam rejects a second service owner here
        // with `OwnerConflict` — the dual-claim gap this closes. An
        // owner-bound service additionally proves it presents the reserver
        // (token equality) and retains the OS handle, so cross-process
        // exclusion holds for the full service lifetime.
        let service_key = ownership_key(lease.root_id.as_str());
        if let Some(owner) = &os_owner {
            if !owner.owns_service_root(lease.root_id.as_str()) {
                return Err(BlobError::OwnerConflict);
            }
            bind_service_to_owner(&service_key, &owner.lease.token)?;
        } else {
            reserve_ownership(&service_key, RootClaimKind::Service)?;
        }
        let claim = match platform.claim_root(&lease) {
            Ok(claim) => claim,
            Err(error) => {
                Self::release_construction_claim(&service_key, os_owner.as_ref());
                // Lease creation is the one platform call the service never
                // binds. Binding it here keeps the typed cause, native code and
                // stage the port actually reported, names the owner-issued
                // root/lease identity the service holds, and redacts it exactly
                // as the native lease path does so no host path travels inside
                // a capacity record (issue #864: "no raw sensitive filesystem
                // path"; "wrapped ports must preserve typed cause/code and
                // stage before conversion to text"). The effect is NOT
                // overridden: only the port observed whether the lease file
                // exists. A composite that cannot validate falls back to the
                // port's own error rather than discarding it, and construction
                // still fails, so an exhausted lease can never issue healthy
                // root, ready, write or GC evidence.
                let bound = bind_platform_capacity_with_effect(
                    error.clone(),
                    BlobCapacityStage::RootLeaseCreate,
                    BlobCapacityIdentity::RootLease {
                        root_id: redacted_root_id(lease.root_id.as_str()),
                        lease_id: Some(redacted_root_id(lease.lease_id.as_str())),
                    },
                    None,
                );
                return Err(match bound {
                    Ok(bound) => bound,
                    Err(InvalidCapacityEvidence) => error,
                });
            }
        };
        if let Err(error) = claim.validate(&lease) {
            Self::release_construction_claim(&service_key, os_owner.as_ref());
            return Err(error);
        }
        Ok(Self {
            owner: RootOwner {
                lease,
                claim,
                os_owner,
                service_key,
            },
            platform: RwLock::new(platform),
            compression: RwLock::new(compression),
            keys: RwLock::new(keys),
            aead: RwLock::new(aead),
            live_sets: Mutex::new(live_sets),
            shards: ShardLocks::new(),
            unrecorded_publications: Mutex::new(Vec::new()),
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

    #[allow(
        clippy::too_many_lines,
        reason = "CAS receipt validation keeps the provider-to-authority boundary in one path"
    )]
    fn platform_compare_and_replace(
        &self,
        request: &BlobCasRequest,
        bytes: &[u8],
    ) -> Result<(), BlobError> {
        request.validate()?;
        if bytes.len() as u64 != request.replacement_length
            || sha256_hex(bytes) != request.replacement_sha256
        {
            return Err(BlobError::CasFailure {
                failure: Box::new(BlobCasFailure::Internal {
                    request: Box::new(request.clone()),
                    reason: eliot_blob_api::BlobCasInternalReason::CommitmentMismatch,
                }),
            });
        }
        if self.platform_read()?.cas_capability() != BlobCasCapability::AtomicCompareAndReplace {
            return Err(BlobError::CasFailure {
                failure: Box::new(BlobCasFailure::UnsupportedAtomicCas {
                    request: Box::new(request.clone()),
                }),
            });
        }
        let physical = match self
            .platform_write()
            .and_then(|mut platform| platform.compare_and_replace_durable(request, bytes))
        {
            Ok(physical) => physical,
            Err(BlobError::CasFailure { failure }) if cas_failure_is_bound(&failure, request) => {
                return Err(BlobError::CasFailure { failure });
            }
            Err(error @ BlobError::StorageCapacity { .. }) => {
                return Err(match bind_capacity_cas(error, request) {
                    Ok(bound) => bound,
                    Err(InvalidCapacityEvidence) => {
                        cas_unknown(request, None, None, BlobCasDurability::Unconfirmed)
                    }
                });
            }
            Err(_) => {
                return Err(cas_unknown(
                    request,
                    None,
                    None,
                    BlobCasDurability::Unconfirmed,
                ));
            }
        };
        let expected_commitment = request.request_commitment_sha256()?;
        let expected_success =
            if request.expected.sha256() == Some(request.replacement_sha256.as_str()) {
                BlobCasSuccessKind::NoOp
            } else {
                BlobCasSuccessKind::Applied
            };
        if physical.observed_durability != BlobCasDurability::Confirmed {
            return Err(cas_durability_unconfirmed(
                request,
                Some(physical.observed),
                Some(physical.backend_generation),
            ));
        }
        if physical.operation_id != request.context.operation.operation_id.to_string()
            || physical.request_commitment_sha256 != expected_commitment
            || physical.observed != request.expected
            || physical.replacement_sha256 != request.replacement_sha256
            || physical.replacement_length != request.replacement_length
            || physical.backend_generation != request.expected_backend_generation
            || physical.observed_durability != BlobCasDurability::Confirmed
            || physical.success != expected_success
        {
            return Err(cas_unknown(
                request,
                Some(physical.observed),
                Some(physical.backend_generation),
                physical.observed_durability,
            ));
        }
        let success = physical.success;
        let request_commitment_sha256 = expected_commitment;
        let physical_observed = physical.observed.clone();
        let receipt_result = (|| -> Result<BlobCasReceipt, BlobError> {
            let effect_commitment_sha256 = request.effect_commitment_sha256(
                request.expected_backend_generation,
                BlobCasDurability::Confirmed,
                success,
            )?;
            let request_artifact = ArtifactBinding {
                artifact_id: request
                    .request_artifact_id()?
                    .parse()
                    .map_err(|error| BlobError::InvalidContract(format!("{error}")))?,
                sha256: request_commitment_sha256,
                role: ReceiptKind::Artifact,
                source_revision: Some(format!(
                    "backend-generation:{};target:{}",
                    request.expected_backend_generation,
                    request.target.normalized_identity()
                )),
            };
            let effect_artifact = ArtifactBinding {
                artifact_id: request
                    .effect_artifact_id(
                        request.expected_backend_generation,
                        BlobCasDurability::Confirmed,
                        success,
                    )?
                    .parse()
                    .map_err(|error| BlobError::InvalidContract(format!("{error}")))?,
                sha256: effect_commitment_sha256,
                role: ReceiptKind::Artifact,
                source_revision: Some(format!(
                    "backend-generation:{};durability:CONFIRMED",
                    request.expected_backend_generation
                )),
            };
            let proof_id = request.receipt_proof_id()?;
            let binding = BlobReceiptBinding::for_operation(
                &request.context,
                request.root_lease.root_generation,
                None,
                Some(&proof_id),
            )?;
            let verified = self.issue_receipt(
                &request.context,
                vec![request_artifact, effect_artifact],
                ReceiptKind::Operation,
                ReceiptDisposition::Success {
                    proof: ProofCeiling::ObservedExternalEffect,
                },
                binding,
            )?;
            BlobCasReceipt::from_verified(
                &verified,
                &self.issuer_anchor,
                request,
                request.expected_backend_generation,
                BlobCasDurability::Confirmed,
                success,
            )
        })();
        let receipt = match receipt_result {
            Ok(receipt) => receipt,
            Err(BlobError::CasFailure { failure }) if cas_failure_is_bound(&failure, request) => {
                return Err(BlobError::CasFailure { failure });
            }
            Err(_) => {
                return Err(cas_unknown(
                    request,
                    Some(physical_observed),
                    Some(physical.backend_generation),
                    physical.observed_durability,
                ));
            }
        };
        let outcome = if success == BlobCasSuccessKind::Applied {
            BlobCasOutcome::Applied { receipt }
        } else {
            BlobCasOutcome::NoOp { receipt }
        };
        match outcome.into_blob_result()? {
            BlobCasOutcome::Applied { .. } | BlobCasOutcome::NoOp { .. } => Ok(()),
            _ => Err(BlobError::CasFailure {
                failure: Box::new(BlobCasFailure::Internal {
                    request: Box::new(request.clone()),
                    reason: eliot_blob_api::BlobCasInternalReason::SuccessKindMismatch,
                }),
            }),
        }
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

    fn platform_backend_generation(&self) -> Result<u64, BlobError> {
        self.platform_read()?.backend_generation()
    }

    fn tombstone_cas_request(
        tombstone: &Tombstone,
        bytes: &[u8],
    ) -> Result<BlobCasRequest, BlobError> {
        let cas = tombstone.cas.as_ref().ok_or_else(|| {
            BlobError::PlanGap("GC tombstone is missing exact CAS authority context".to_owned())
        })?;
        BlobCasRequest::new(
            cas.context.clone(),
            cas.root_lease.clone(),
            eliot_blob_api::BlobCasNamespace::Tombstone,
            cas.target.clone(),
            cas.expected.clone(),
            sha256_hex(bytes),
            bytes.len() as u64,
            cas.expected_backend_generation,
            cas.requested_durability,
        )
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
        residency_sha256: &str,
    ) -> Result<BlobDeletionReconciliation, BlobError> {
        self.live_sets
            .lock()
            .map_err(|_| BlobError::Provider("blob live-set lock poisoned".to_owned()))?
            .reconcile_delete(
                operation_id,
                proof,
                locator,
                intent_revision,
                residency_sha256,
            )
    }

    fn live_sets_compare_and_delete_observed(
        &self,
        operation_id: &str,
        proof: &BlobLiveSetProof,
        locator: &BlobLocator,
        intent_revision: u64,
        residency_sha256: &str,
        delete: &mut dyn FnMut() -> Result<(), BlobError>,
    ) -> Result<BlobDeletionReconciliation, BlobError> {
        self.live_sets
            .lock()
            .map_err(|_| BlobError::Provider("blob live-set lock poisoned".to_owned()))?
            .compare_and_delete_observed(
                operation_id,
                proof,
                locator,
                intent_revision,
                residency_sha256,
                delete,
            )
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

    /// Enumerates every complete residency scope durably stored for one
    /// locator. A scope is a complete payload/metadata pair whose names are
    /// exactly the derived placement for `(locator, digest)`. Half-published
    /// pairs and foreign names fail closed: silently skipping them could hide
    /// live data from a later coherence scan. Callers needing liveness still
    /// consult only the caller-supplied live-set union; this enumerates
    /// physical scopes, never semantic roots.
    fn enumerate_scopes(&self, locator: &BlobLocator) -> Result<Vec<ScopedObject>, BlobError> {
        let prefix = scope_list_prefix(locator)?;
        self.contained(&prefix)?;
        // s-04-v2 generation-wide listing also returns other hashes' objects.
        // Only filenames of this content hash can belong to this locator;
        // anything else is skipped before the strict placement proof below.
        // A same-hash file that fails the proof is still a hard error.
        let file_marker = format!("/{}.r", locator.hash.as_str());
        // s-04-v2: the locator pins one residency key, so only its own digest
        // can yield a scope here. Same-hash files of other domains are other
        // objects, not errors; a same-digest file at a non-canonical placement
        // still fails the strict proof inside parse_scoped_path.
        let own_digest = locator.residency_key_digest()?;
        let mut payloads: BTreeMap<String, WorkScopePath> = BTreeMap::new();
        let mut metadatas: BTreeMap<String, WorkScopePath> = BTreeMap::new();
        for path in self.platform_list(&prefix)? {
            let identity = path.normalized_identity().to_owned();
            if !identity.contains(&file_marker) {
                continue;
            }
            if !identity.contains(own_digest.as_str()) {
                // Same content hash, another residency domain: another object,
                // not an error. Only our own digest admits the strict proof.
                continue;
            }
            // Claims our scope: strict placement proof, so a transplanted
            // same-digest file is a hard error, never a silent skip.
            let scope = parse_scoped_path(&path, locator, 'p')
                .or_else(|_| parse_scoped_path(&path, locator, 'm'))
                .map_err(|_| BlobError::MetadataPayloadMismatch)?;
            if scope.digest != own_digest {
                return Err(BlobError::MetadataPayloadMismatch);
            }
            let rebuilt_payload = scoped_payload_path(locator, &scope)?;
            let rebuilt_metadata = scoped_metadata_path(locator, &scope)?;
            if path.normalized_identity() == rebuilt_payload.normalized_identity() {
                if payloads.insert(scope.digest.clone(), path).is_some() {
                    return Err(BlobError::MetadataPayloadMismatch);
                }
            } else if path.normalized_identity() == rebuilt_metadata.normalized_identity() {
                if metadatas.insert(scope.digest.clone(), path).is_some() {
                    return Err(BlobError::MetadataPayloadMismatch);
                }
            } else {
                return Err(BlobError::MetadataPayloadMismatch);
            }
        }
        let mut scopes: Vec<ScopedObject> = Vec::new();
        for (digest, payload) in &payloads {
            let Some(metadata) = metadatas.remove(digest) else {
                return Err(BlobError::MetadataPayloadMismatch);
            };
            scopes.push(ScopedObject {
                scope: ResidencyScope {
                    digest: digest.clone(),
                },
                payload: payload.clone(),
                metadata,
            });
        }
        if !metadatas.is_empty() {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        Ok(scopes)
    }

    /// Resolves the one residency scope a locator-bound read/reference means.
    /// The request carries no policy, so the caller proves the intended scope
    /// with the exact durable metadata digest it already holds
    /// (`expected_metadata_sha256`): the match is byte-exact, never a
    /// default-domain guess. Zero scopes is `NotFound`; no digest match is
    /// `MetadataPayloadMismatch`. Only the matched scope's metadata is
    /// validated here; coherence scans validate every scope explicitly.
    fn resolve_scope_for_metadata(
        &self,
        locator: &BlobLocator,
        expected_metadata_sha256: &str,
    ) -> Result<(ScopedObject, StoredMetadata, Vec<u8>), BlobError> {
        let scopes = self.enumerate_scopes(locator)?;
        if scopes.is_empty() {
            return Err(BlobError::NotFound);
        }
        for scoped in scopes {
            let path = scoped.metadata.clone();
            self.contained(&path)?;
            let bytes = self.read_bounded_file(&path, MAX_METADATA_BYTES)?;
            if sha256_hex(&bytes) != expected_metadata_sha256 {
                continue;
            }
            let metadata = decode_metadata(&bytes)?;
            if metadata.locator != *locator || metadata.residency_sha256 != scoped.scope.digest {
                return Err(BlobError::MetadataPayloadMismatch);
            }
            let resolved = ScopedObject {
                scope: scoped.scope,
                payload: scoped.payload,
                metadata: path,
            };
            return Ok((resolved, metadata, bytes));
        }
        Err(BlobError::MetadataPayloadMismatch)
    }

    fn load_metadata(
        &self,
        locator: &BlobLocator,
        scope: &ResidencyScope,
    ) -> Result<(StoredMetadata, Vec<u8>), BlobError> {
        let path = scoped_metadata_path(locator, scope)?;
        self.contained(&path)?;
        let bytes = self.read_bounded_file(&path, MAX_METADATA_BYTES)?;
        let metadata = decode_metadata(&bytes)?;
        if metadata.locator != *locator || metadata.residency_sha256 != scope.digest {
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

    /// One publication attempt's durability verdict.
    ///
    /// `ConfirmedDurable` is produced only when the platform owner itself
    /// reported the publication and its durability boundary succeeded.
    /// `InstalledUnproven` retains the underlying failure for a destination
    /// whose bytes match: the effect may be installed, but nothing the caller
    /// can read back proves the boundary was crossed.
    fn publish_or_verify(
        &self,
        verification: &PublishVerification<'_>,
    ) -> Result<PublicationOutcome, BlobError> {
        self.contained(verification.source)?;
        self.contained(verification.destination)?;
        match self.platform_rename(verification.source, verification.destination) {
            Ok(()) => {
                if self.exact_bytes_at(
                    verification.destination,
                    verification.expected_sha256,
                    verification.hard_ceiling,
                )? {
                    Ok(PublicationOutcome::ConfirmedDurable)
                } else {
                    Err(BlobError::UnknownPublishOutcome {
                        operation_id: verification.operation_id.to_owned(),
                        state: verification.state_before,
                    })
                }
            }
            Err(error @ BlobError::StorageCapacity { .. }) => {
                // The rename reached its durability boundary and the owner
                // reported exhaustion there: the publication may already be
                // installed AND its durability is unconfirmed. Both axes are
                // retained; neither is promoted to a durable phase.
                match bind_platform_capacity_with_effect(
                    error,
                    verification.stage,
                    BlobCapacityIdentity::Journal {
                        operation_id: verification.operation_id.to_owned(),
                        idempotency_key: verification.idempotency_key.to_owned(),
                        locator: Some(verification.locator.clone()),
                    },
                    Some(BlobCapacityEffect::DurabilityUnconfirmed {
                        state: verification.state_before,
                        possible_effect: true,
                    }),
                ) {
                    Ok(bound) => {
                        let fence = publication_fence(&bound);
                        Ok(PublicationOutcome::InstalledUnproven {
                            error: bound,
                            fence,
                        })
                    }
                    Err(InvalidCapacityEvidence) => Err(BlobError::UnknownPublishOutcome {
                        operation_id: verification.operation_id.to_owned(),
                        state: verification.state_before,
                    }),
                }
            }
            Err(error)
                if self.exact_bytes_at(
                    verification.destination,
                    verification.expected_sha256,
                    verification.hard_ceiling,
                )? =>
            {
                // Matching destination bytes establish identity and integrity
                // only. The owner's non-capacity failure still leaves the
                // durability boundary unproven, so the obligation is fenced
                // instead of being reported as a completed publication.
                Ok(PublicationOutcome::InstalledUnproven {
                    fence: BlobPublicationFence::Unconfirmed,
                    error,
                })
            }
            Err(_) => Err(BlobError::UnknownPublishOutcome {
                operation_id: verification.operation_id.to_owned(),
                state: verification.state_before,
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
        if !path.normalized_identity().starts_with("transactions/") {
            return Err(BlobError::PlanGap(
                "stage journal replacement is restricted to transactions namespace".to_owned(),
            ));
        }
        self.contained(path)?;
        let bytes = serde_json::to_vec(journal)
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        let result = if replace {
            self.platform_replace(path, &bytes)
        } else {
            self.platform_write_new(path, &bytes)
        };
        result.map_err(|error| {
            let bound = bind_journal_capacity(error, journal, bytes.len() as u64);
            match bound {
                Ok(bound) => bound,
                Err(InvalidCapacityEvidence) => BlobError::UnknownPublishOutcome {
                    operation_id: journal.operation_id.clone(),
                    state: journal.state,
                },
            }
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "journal preparation and conditional publication share one linearization path"
    )]
    fn persist_tombstone(
        &self,
        path: &WorkScopePath,
        tombstone: &Tombstone,
        expected_revision: Option<(u64, BlobCasState)>,
    ) -> Result<BlobCasState, BlobError> {
        tombstone.validate_base()?;
        self.contained(path)?;
        let (expected_state, observed_state, conflict_observed) =
            if let Some((expected, frozen)) = expected_revision {
                let current_bytes = self.read_bounded_file(path, MAX_JOURNAL_BYTES)?;
                let current = decode_tombstone(&current_bytes)?;
                current.validate()?;
                let observed = BlobCasState::Digest(sha256_hex(&current_bytes));
                let conflict = current.revision != expected || frozen != observed;
                (frozen, observed, conflict)
            } else {
                (BlobCasState::Missing, BlobCasState::Missing, false)
            };
        let backend_generation = self.platform_backend_generation()?;
        if backend_generation == 0 {
            return Err(BlobError::PlanGap(
                "blob platform returned an invalid backend generation".to_owned(),
            ));
        }
        let mut candidate = tombstone.clone();
        let context = candidate
            .cas
            .as_ref()
            .map(|cas| cas.context.clone())
            .ok_or_else(|| {
                BlobError::PlanGap(
                    "new GC tombstone is missing owner-issued CAS step context".to_owned(),
                )
            })?;
        let context = Self::tombstone_cas_context(
            &context,
            &candidate.operation_id,
            path,
            candidate.revision,
        )?;
        candidate.cas = Some(TombstoneCas {
            version: 2,
            context,
            root_lease: self.owner.lease.clone(),
            target: path.clone(),
            expected: expected_state.clone(),
            expected_backend_generation: backend_generation,
            requested_durability: BlobCasDurability::Requested,
        });
        let context = candidate
            .cas
            .as_ref()
            .map(|cas| cas.context.clone())
            .ok_or_else(|| {
                BlobError::PlanGap("CAS context disappeared during preparation".to_owned())
            })?;
        let bytes = serde_json::to_vec(&candidate)
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        let request = BlobCasRequest::new(
            context,
            self.owner.lease.clone(),
            eliot_blob_api::BlobCasNamespace::Tombstone,
            path.clone(),
            expected_state,
            sha256_hex(&bytes),
            bytes.len() as u64,
            backend_generation,
            BlobCasDurability::Requested,
        )?;
        if conflict_observed {
            return Err(BlobError::CasFailure {
                failure: Box::new(BlobCasFailure::ExpectedStateConflict {
                    request: Box::new(request),
                    observed: observed_state,
                }),
            });
        }
        self.platform_compare_and_replace(&request, &bytes)
            .map_err(|error| retain_capacity_gc_state(error, candidate.state))?;
        Ok(BlobCasState::Digest(sha256_hex(&bytes)))
    }

    /// Fences an operation whose publication/durability boundary the platform
    /// owner has not proven.
    ///
    /// The obligation is durable and bound to the original operation, so every
    /// re-entry re-observes it and refuses to advance. Only the owner can
    /// settle it, either through an exact operation-bound publication/durability
    /// reconciliation or by the existing durable replace on the exact
    /// destination under this same identity. A failed replace leaves this
    /// obligation unresolved instead of letting the caller certify it. See
    /// #730/#946.
    fn fenced_publication_error(
        journal: &StageJournal,
        obligation: &BlobPublicationObligation,
    ) -> BlobError {
        let BlobPublicationFence::Capacity { cause } = obligation.fence else {
            return BlobError::UnknownPublishOutcome {
                operation_id: obligation.operation_id.clone(),
                state: obligation.state_before,
            };
        };
        let Some(locator) = obligation.locator.clone() else {
            return BlobError::UnknownPublishOutcome {
                operation_id: obligation.operation_id.clone(),
                state: obligation.state_before,
            };
        };
        let bound = BlobError::StorageCapacity {
            failure: Box::new(BlobCapacityFailure {
                identity: BlobCapacityIdentity::Journal {
                    operation_id: obligation.operation_id.clone(),
                    idempotency_key: obligation.idempotency_key.clone(),
                    locator: Some(locator),
                },
                stage: obligation.stage,
                evidence: BlobCapacityEvidence {
                    cause,
                    // The retained cause was observed at the boundary; the
                    // progress it left behind was never observed, so it stays
                    // unknown rather than being restated as a byte count.
                    attempted_bytes: None,
                    effect: BlobCapacityEffect::DurabilityUnconfirmed {
                        state: obligation.state_before,
                        possible_effect: true,
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
            }),
        };
        match bound {
            BlobError::StorageCapacity { failure } if failure.validate().is_err() => {
                BlobError::UnknownPublishOutcome {
                    operation_id: journal.operation_id.clone(),
                    state: obligation.state_before,
                }
            }
            other => other,
        }
    }

    /// Records one unresolved publication obligation under the operation's own
    /// journal and returns the error the caller must surface.
    ///
    /// The primary failure is never replaced: if persisting the obligation also
    /// fails, that failure is retained as additional cleanup evidence beside
    /// the original error, and that composite may drop the cleanup observation
    /// again when it does not validate. Losing the record must not silently
    /// release the operation, so an obligation this journal could not persist is
    /// retained in this service process under the same operation identity, and it
    /// can only be discharged by an owner `platform_replace` that returns
    /// success. Three re-entry shapes bind and settle what was retained — the
    /// commit-record branch, the journal-reload branch and the `reconcile` sweep.
    /// The other two receipt shapes, the within-scope dedup branch and the fresh
    /// publish, only refuse: they have no journal to bind it to, so an obligation
    /// there is re-observed as a refusal rather than settled. The retention is
    /// dropped once that boundary is settled.
    ///
    /// The retention is process-local, and the scope of the guarantee is exactly
    /// as wide as that. Within this service the obligation is re-observed and
    /// cannot be discharged without the owner performing the durable write. It
    /// does not survive a restart, because the volume rejected the very write
    /// that would have carried it. After a restart the journal on the volume
    /// still reads `pending_publication: None` and the retention is empty, so a
    /// payload or metadata boundary is re-derived from the journal and the
    /// matching destination is routed through the same owner re-establishment.
    /// An owner refusal re-records the obligation durably when possible; if that
    /// write is also refused, process-local retention keeps it in front of the
    /// next same-service entry.
    ///
    /// A `CommitWrite` boundary is different because a commit record can already
    /// exist after its create reports an unconfirmed durability result. On replay,
    /// the commit-present branch first proves the journal's operation identity,
    /// settles any recorded or retained obligation, and—unless the journal
    /// already carries `CommitDurable`, `Ready`, or `Cleaned`—asks the owner to
    /// replace the exact bounded commit bytes under that same identity. Success
    /// advances an earlier journal checkpoint to `CommitDurable` and persists it
    /// before a receipt can be returned; an existing later checkpoint is
    /// preserved. Refusal remains unresolved and preserves the journal. If the
    /// obligation never reached the volume and the service restarted, this
    /// checkpoint makes the existing commit record recoverable without treating
    /// its mere presence or byte equality as durability evidence.
    ///
    /// The refusal is not one uniform error class, and the difference is whether
    /// a replacement obligation could be written. An owner refusal of the durable
    /// write records one first, carrying the owner's newest fence, and that error
    /// is what reaches the caller. An attempt that fails before that — a locator
    /// the journal predates, or a destination that was never installed — records
    /// nothing, so the obligation already in hand is still the durable record and
    /// the refusal is rebuilt from it, capacity-typed. The two receipt shapes that
    /// have no journal at all report `UnknownPublishOutcome` instead, because
    /// they have no obligation fence to build a capacity failure from; that is the
    /// card's other typed unresolved outcome, not a weakening.
    fn record_publication_obligation(
        &self,
        journal_path: &WorkScopePath,
        journal: &mut StageJournal,
        obligation: &BlobPublicationObligation,
        primary: BlobError,
    ) -> BlobError {
        journal.pending_publication = Some(obligation.clone());
        match self.persist_journal(journal_path, journal, true) {
            Ok(()) => primary,
            Err(persist_error) => {
                // The journal replace failed, so nothing durable carries this
                // obligation and the journal a later re-entry decodes would walk
                // straight past the fence. Retention is what keeps the boundary
                // in front of the next attempt, and it is observed before the
                // composite is built and never read from it, because that
                // composite may drop the cleanup observation and revert to a
                // plain capacity failure that fences nothing.
                //
                // A poisoned retention lock is deliberately not branched on: it
                // must not degrade the primary capacity failure into a generic
                // provider error, and it must not discard the journal persist
                // failure either. Both are retained below and returned as the
                // composite, which is this caller's refusal. What that refusal
                // still guarantees is narrower than "cannot be released": without
                // the retained entry, the operation can be released once some
                // re-entry actually re-establishes the boundary through a
                // successful owner `platform_replace`. It cannot be released
                // *without* one, because the journal record on the volume is
                // untouched and every re-entry reaches the same publication and
                // asks the owner about the same boundary.
                let _retention = self.retain_unrecorded_publication(obligation);
                retain_cleanup_evidence(persist_error, primary)
            }
        }
    }

    /// Retains an obligation whose durable journal record could not be written.
    ///
    /// Retention is bound to the obligation's own operation identity, so
    /// re-entering the same operation re-observes the refusal instead of
    /// resolving it, and it is dropped again by
    /// [`BlobStoreCore::forget_unrecorded_publication`] once the owner has
    /// settled that boundary.
    fn retain_unrecorded_publication(
        &self,
        obligation: &BlobPublicationObligation,
    ) -> Result<(), BlobError> {
        let Ok(mut retained) = self.unrecorded_publications.lock() else {
            return Err(BlobError::Provider(
                "blob publication retention lock poisoned".to_owned(),
            ));
        };
        let known = retained.iter().any(|candidate| {
            candidate.operation_id == obligation.operation_id
                && candidate.idempotency_key == obligation.idempotency_key
                && candidate.destination == obligation.destination
        });
        if known {
            return Ok(());
        }
        retained.push(obligation.clone());
        Ok(())
    }

    /// Every obligation this service retained for one operation identity.
    ///
    /// Retrieval covers the whole insertion key, not just the operation: an
    /// insertion is keyed by `(operation_id, idempotency_key, destination)`, so
    /// every retained obligation is returned and every one of them is re-bound
    /// on re-entry. A poisoned lock reports an error rather than an empty set:
    /// it must never be read as "nothing is owed" and release the operation.
    fn retained_publications(
        &self,
        operation_id: &str,
        idempotency_key: &str,
    ) -> Result<Vec<BlobPublicationObligation>, BlobError> {
        let Ok(retained) = self.unrecorded_publications.lock() else {
            return Err(BlobError::Provider(
                "blob publication retention lock poisoned".to_owned(),
            ));
        };
        Ok(retained
            .iter()
            .filter(|candidate| {
                candidate.operation_id == operation_id
                    && candidate.idempotency_key == idempotency_key
            })
            .cloned()
            .collect())
    }

    /// Drops one obligation from the retained set once the owner has settled it
    /// and the cleared journal is already durable.
    ///
    /// Retention exists only to carry an obligation the volume never let the
    /// journal record. A settled obligation must not outlive its settlement, or
    /// every later re-entry would re-bind a discharged boundary and discharge it
    /// again with an extra durable write of an already-durable destination.
    fn forget_unrecorded_publication(
        &self,
        obligation: &BlobPublicationObligation,
    ) -> Result<(), BlobError> {
        let Ok(mut retained) = self.unrecorded_publications.lock() else {
            return Err(BlobError::Provider(
                "blob publication retention lock poisoned".to_owned(),
            ));
        };
        retained.retain(|candidate| {
            !(candidate.operation_id == obligation.operation_id
                && candidate.idempotency_key == obligation.idempotency_key
                && candidate.destination == obligation.destination)
        });
        Ok(())
    }

    /// Advances one publication phase. An obligation this journal still carries
    /// outranks everything below — but that ordering is a property of the call
    /// site, not of this function: nothing here reads `journal.pending_publication`,
    /// and every caller settles or refuses an outstanding obligation through
    /// `settle_pending_publication` before reaching this. Matching destination
    /// bytes establish identity and integrity only: they are never promoted to a
    /// durable phase, and are settled either by an owner verdict — which the
    /// current platform port exposes no method for, so that path stays
    /// unavailable rather than being invented — or by re-establishing that
    /// destination's durability boundary under the same operation identity.
    #[allow(clippy::too_many_arguments)]
    fn settle_publication(
        &self,
        journal_path: &WorkScopePath,
        journal: &mut StageJournal,
        source: &WorkScopePath,
        destination: &WorkScopePath,
        expected_sha256: &str,
        hard_ceiling: u64,
        stage: BlobCapacityStage,
    ) -> Result<(), BlobError> {
        if self.exact_bytes_at(destination, expected_sha256, hard_ceiling)? {
            return self.reestablish_publication_durability(
                journal_path,
                journal,
                destination,
                expected_sha256,
                hard_ceiling,
                stage,
            );
        }
        if !self.exact_bytes_at(source, expected_sha256, hard_ceiling)? {
            return Err(BlobError::UnknownPublishOutcome {
                operation_id: journal.operation_id.clone(),
                state: journal.state,
            });
        }
        let locator = publication_locator(journal)?;
        match self.publish_or_verify(&PublishVerification {
            source,
            destination,
            expected_sha256,
            hard_ceiling,
            operation_id: &journal.operation_id,
            idempotency_key: &journal.idempotency_key,
            locator: &locator,
            state_before: journal.state,
            stage,
        })? {
            PublicationOutcome::ConfirmedDurable => Ok(()),
            PublicationOutcome::InstalledUnproven { error, fence } => {
                let obligation = BlobPublicationObligation {
                    operation_id: journal.operation_id.clone(),
                    idempotency_key: journal.idempotency_key.clone(),
                    locator: Some(locator),
                    stage,
                    destination: destination.normalized_identity().to_owned(),
                    expected_sha256: expected_sha256.to_owned(),
                    state_before: journal.state,
                    fence,
                };
                obligation.validate()?;
                Err(self.record_publication_obligation(journal_path, journal, &obligation, error))
            }
        }
    }

    /// Re-establishes one destination's durability boundary under the same
    /// operation identity.
    ///
    /// This is the only settlement a matching destination admits. The bytes are
    /// read back from the destination, confirmed to be the exact bytes the
    /// operation expects, and installed again through the platform's existing
    /// durable replace, so the owner performs the durable write for this
    /// destination under this identity instead of being assumed to have done so
    /// already. A failed re-establishment is the same fenced outcome an
    /// unproven publication is: the obligation is recorded under the original
    /// identity and the phase is not advanced.
    fn reestablish_publication_durability(
        &self,
        journal_path: &WorkScopePath,
        journal: &mut StageJournal,
        destination: &WorkScopePath,
        expected_sha256: &str,
        hard_ceiling: u64,
        stage: BlobCapacityStage,
    ) -> Result<(), BlobError> {
        let locator = publication_locator(journal)?;
        let bytes = self.read_bounded_file(destination, hard_ceiling)?;
        if sha256_hex(&bytes) != expected_sha256 {
            // The destination stopped being this operation's object between the
            // identity check and the re-establishment; nothing is installed.
            return Err(BlobError::UnknownPublishOutcome {
                operation_id: journal.operation_id.clone(),
                state: journal.state,
            });
        }
        if let Err(error) = self.platform_replace(destination, &bytes) {
            let identity = BlobCapacityIdentity::Journal {
                operation_id: journal.operation_id.clone(),
                idempotency_key: journal.idempotency_key.clone(),
                locator: Some(locator.clone()),
            };
            let (primary, fence) = match bind_platform_capacity_with_effect(
                error,
                stage,
                identity,
                Some(BlobCapacityEffect::DurabilityUnconfirmed {
                    state: journal.state,
                    possible_effect: true,
                }),
            ) {
                Ok(bound) => {
                    let fence = publication_fence(&bound);
                    (bound, fence)
                }
                Err(InvalidCapacityEvidence) => (
                    BlobError::UnknownPublishOutcome {
                        operation_id: journal.operation_id.clone(),
                        state: journal.state,
                    },
                    BlobPublicationFence::Unconfirmed,
                ),
            };
            let obligation = BlobPublicationObligation {
                operation_id: journal.operation_id.clone(),
                idempotency_key: journal.idempotency_key.clone(),
                locator: Some(locator),
                stage,
                destination: destination.normalized_identity().to_owned(),
                expected_sha256: expected_sha256.to_owned(),
                state_before: journal.state,
                fence,
            };
            obligation.validate()?;
            return Err(self.record_publication_obligation(
                journal_path,
                journal,
                &obligation,
                primary,
            ));
        }
        if stage == BlobCapacityStage::CommitWrite {
            match journal.state {
                PublishState::JournalPrepared
                | PublishState::PayloadDurable
                | PublishState::MetadataDurable => {
                    journal.state = PublishState::CommitDurable;
                }
                // Preserve a later checkpoint if a caller has already advanced
                // it; re-establishing this boundary must never regress state.
                PublishState::CommitDurable | PublishState::Ready | PublishState::Cleaned => {}
            }
        }
        Ok(())
    }

    /// The exact destination and bounded ceiling one recorded obligation names.
    ///
    /// An obligation carries a normalized in-root identity rather than a typed
    /// path, so the pair is resolved from the identities this journal and its own
    /// operation already establish: its two publication targets and its own
    /// derived commit record, each read under the same ceiling the phase that
    /// published it used. Stage and destination are cross-checked together, so an
    /// obligation naming one phase's stage with another phase's destination
    /// resolves to nothing and is refused instead of being discharged by a write
    /// to a boundary it never named. An unresolved obligation is not given an
    /// invented bound; the caller refuses it.
    fn obligation_target(
        journal: &StageJournal,
        obligation: &BlobPublicationObligation,
    ) -> Option<(WorkScopePath, u64)> {
        let payload = (journal.final_payload.clone(), MAX_BLOB_ENVELOPE_BYTES);
        let metadata = (journal.final_metadata.clone(), MAX_METADATA_BYTES);
        let commit =
            Self::operation_path_from(&journal.operation_id, &journal.idempotency_key, "commit")
                .ok()
                .map(|path| ((path, MAX_JOURNAL_BYTES), BlobCapacityStage::CommitWrite));
        [
            Some((payload, BlobCapacityStage::PayloadPublication)),
            Some((metadata, BlobCapacityStage::MetadataPublication)),
            commit,
        ]
        .into_iter()
        .flatten()
        .find(|((path, _), stage)| {
            *stage == obligation.stage && path.normalized_identity() == obligation.destination
        })
        .map(|((path, ceiling), _)| (path, ceiling))
    }

    /// Settles every publication obligation this operation still carries.
    ///
    /// A carried obligation names exactly one boundary that is still owed, and it
    /// is a question to settle rather than a permanent wall. The owner is asked
    /// about that one boundary first, under this operation identity and only for
    /// the destination *and* stage the obligation itself names: matching bytes
    /// never settle it, the settlement is the owner's own replace returning
    /// success, and a failure to re-establish it is exactly the fenced outcome the
    /// obligation describes — in one of two classes, split by whether a
    /// replacement obligation could be recorded at all. Each settlement clears the
    /// journal's single slot and
    /// persists that clearance before the next one is bound, so only the boundary
    /// still owed is ever in flight and a journal that still names a boundary
    /// stays fenced on re-entry.
    fn settle_pending_publication(
        &self,
        journal_path: &WorkScopePath,
        journal: &mut StageJournal,
    ) -> Result<(), BlobError> {
        while let Some(obligation) = journal.pending_publication.clone() {
            let Some((destination, hard_ceiling)) = Self::obligation_target(journal, &obligation)
            else {
                return Err(Self::fenced_publication_error(journal, &obligation));
            };
            // A failed re-establishment is always a fenced refusal, but the error
            // class differs with how far the attempt got, and the difference is
            // whether a replacement obligation could be written at all.
            //
            // The three preconditions the callee needs — a storage identity this
            // journal carries, a destination that exists, and those bytes being
            // this operation's own — are checked here first. If one fails,
            // nothing was recorded and the obligation still in hand is the durable
            // record, so the refusal is rebuilt from it and stays capacity-typed.
            // Matching the callee's error variants instead would not work: a
            // `platform_replace` refusal can itself be `NotFound` or `PlanGap`.
            //
            // Otherwise the callee's only remaining exit is an owner refusal of the
            // durable write, and that attempt records a replacement obligation
            // before it returns — carrying the owner's newest fence, including any
            // file/directory-flush refinement it reported this time. That error is
            // passed through unchanged, so the caller sees the same evidence as the
            // record just written.
            let Ok(destination_bytes) = self.read_bounded_file(&destination, hard_ceiling) else {
                return Err(Self::fenced_publication_error(journal, &obligation));
            };
            if publication_locator(journal).is_err()
                || sha256_hex(&destination_bytes) != obligation.expected_sha256
            {
                return Err(Self::fenced_publication_error(journal, &obligation));
            }
            self.reestablish_publication_durability(
                journal_path,
                journal,
                &destination,
                &obligation.expected_sha256,
                hard_ceiling,
                obligation.stage,
            )?;
            // The owner performed the durable write for that boundary, so the
            // obligation is settled. The clearance is persisted before the next
            // boundary is considered: a journal that still names one stays fenced.
            journal.pending_publication = None;
            self.persist_journal(journal_path, journal, true)?;
            // Only now is the retained copy dischargeable: the journal on the
            // volume is durable and no longer names this boundary.
            self.forget_unrecorded_publication(&obligation)?;
        }
        Ok(())
    }

    /// Settles everything this operation still owes before any phase advances.
    ///
    /// Two sources, in order. First the journal's own durable obligation, if the
    /// record on the volume carries one — that is the obligation this service
    /// wrote and owes, and it is discharged before anything else is considered.
    /// Then the obligations this service retained for the operation because the
    /// volume never let their journal record be written; each is bound in turn,
    /// because the journal carries a single slot and one durable settlement
    /// happens between bindings.
    ///
    /// Every binding, from either source, passes the same obligation-ownership
    /// check a durable record passes, and every discharge is the owner's own
    /// `platform_replace` returning success. Callers must have proven that
    /// `journal` belongs to the operation they are recovering before calling
    /// this: settling performs durable writes and overwrites the journal.
    fn settle_retained_publications(
        &self,
        journal_path: &WorkScopePath,
        journal: &mut StageJournal,
    ) -> Result<(), BlobError> {
        self.settle_pending_publication(journal_path, journal)?;
        let retained = self.retained_publications(
            journal.operation_id.as_str(),
            journal.idempotency_key.as_str(),
        )?;
        for obligation in retained {
            journal.pending_publication = Some(obligation);
            journal.validate()?;
            self.settle_pending_publication(journal_path, journal)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn finish_journal(
        &self,
        journal_path: &WorkScopePath,
        journal: &mut StageJournal,
    ) -> Result<(), BlobError> {
        self.settle_pending_publication(journal_path, journal)?;
        let temp_payload = journal.temp_payload.clone();
        let final_payload = journal.final_payload.clone();
        let expected_payload_sha256 = journal.expected_payload_sha256.clone();
        self.settle_publication(
            journal_path,
            journal,
            &temp_payload,
            &final_payload,
            &expected_payload_sha256,
            MAX_BLOB_ENVELOPE_BYTES,
            BlobCapacityStage::PayloadPublication,
        )?;
        journal.state = PublishState::PayloadDurable;
        self.persist_journal(journal_path, journal, true)?;

        let temp_metadata = journal.temp_metadata.clone();
        let final_metadata = journal.final_metadata.clone();
        let expected_metadata_sha256 = journal.expected_metadata_sha256.clone();
        self.settle_publication(
            journal_path,
            journal,
            &temp_metadata,
            &final_metadata,
            &expected_metadata_sha256,
            MAX_METADATA_BYTES,
            BlobCapacityStage::MetadataPublication,
        )?;
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
            locator: metadata.locator.clone(),
            residency_sha256: metadata.residency_sha256.clone(),
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
            Err(error @ BlobError::StorageCapacity { .. }) => {
                let bound = bind_platform_capacity_with_effect(
                    error,
                    BlobCapacityStage::CommitWrite,
                    BlobCapacityIdentity::Journal {
                        operation_id: journal.operation_id.clone(),
                        idempotency_key: journal.idempotency_key.clone(),
                        locator: Some(metadata.locator.clone()),
                    },
                    Some(BlobCapacityEffect::DurabilityUnconfirmed {
                        state: PublishState::MetadataDurable,
                        possible_effect: true,
                    }),
                );
                let bound = match bound {
                    Ok(bound) => bound,
                    Err(InvalidCapacityEvidence) => {
                        return Err(BlobError::UnknownPublishOutcome {
                            operation_id: journal.operation_id.clone(),
                            state: PublishState::MetadataDurable,
                        });
                    }
                };
                let fence = publication_fence(&bound);
                let obligation = BlobPublicationObligation {
                    operation_id: journal.operation_id.clone(),
                    idempotency_key: journal.idempotency_key.clone(),
                    locator: Some(metadata.locator.clone()),
                    stage: BlobCapacityStage::CommitWrite,
                    destination: commit_path.normalized_identity().to_owned(),
                    expected_sha256: sha256_hex(&commit_bytes),
                    state_before: PublishState::MetadataDurable,
                    fence,
                };
                obligation.validate()?;
                return Err(self.record_publication_obligation(
                    journal_path,
                    journal,
                    &obligation,
                    bound,
                ));
            }
            Err(error)
                if self.exact_bytes_at(
                    &commit_path,
                    &sha256_hex(&commit_bytes),
                    MAX_JOURNAL_BYTES,
                )? =>
            {
                // An already-existing commit record proves identity, not that
                // this operation's create completed its durability boundary.
                // The obligation is fenced under the original identity instead
                // of being promoted to `CommitDurable`.
                let obligation = BlobPublicationObligation {
                    operation_id: journal.operation_id.clone(),
                    idempotency_key: journal.idempotency_key.clone(),
                    locator: Some(metadata.locator.clone()),
                    stage: BlobCapacityStage::CommitWrite,
                    destination: commit_path.normalized_identity().to_owned(),
                    expected_sha256: sha256_hex(&commit_bytes),
                    state_before: PublishState::MetadataDurable,
                    fence: BlobPublicationFence::Unconfirmed,
                };
                obligation.validate()?;
                return Err(self.record_publication_obligation(
                    journal_path,
                    journal,
                    &obligation,
                    error,
                ));
            }
            Err(_) => {
                return Err(BlobError::UnknownPublishOutcome {
                    operation_id: journal.operation_id.clone(),
                    state: PublishState::MetadataDurable,
                });
            }
        }
        journal.state = PublishState::CommitDurable;
        self.remove_if_present(&journal.temp_payload)
            .map_err(|error| {
                bind_cleanup_capacity(
                    error,
                    &journal.operation_id,
                    &journal.idempotency_key,
                    &metadata.locator,
                    PublishState::CommitDurable,
                )
            })?;
        self.remove_if_present(&journal.temp_metadata)
            .map_err(|error| {
                bind_cleanup_capacity(
                    error,
                    &journal.operation_id,
                    &journal.idempotency_key,
                    &metadata.locator,
                    PublishState::CommitDurable,
                )
            })?;
        self.remove_if_present(journal_path).map_err(|error| {
            bind_cleanup_capacity(
                error,
                &journal.operation_id,
                &journal.idempotency_key,
                &metadata.locator,
                PublishState::CommitDurable,
            )
        })?;
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
        // The sweep is a second entry into the same operation, so an obligation
        // whose durable journal record could not be written must be settled here
        // exactly as it is on the `stage` path. Without this the sweep would ask
        // the owner about a boundary this journal still owes and could release an
        // operation the volume never let it record.
        self.settle_retained_publications(path, &mut journal)?;
        self.finish_journal(path, &mut journal)
    }

    #[allow(clippy::too_many_lines)]
    fn reconcile_tombstone_path(
        &self,
        path: &WorkScopePath,
    ) -> Result<ConditionalDeleteOutcome, BlobError> {
        self.contained(path)?;
        let bytes = self.read_bounded_file(path, MAX_JOURNAL_BYTES)?;
        let mut tombstone = decode_tombstone(&bytes)?;
        tombstone.validate()?;
        let cas = tombstone.cas.as_ref().ok_or_else(|| {
            BlobError::PlanGap("legacy GC tombstone is missing exact CAS context".to_owned())
        })?;
        if cas.target.normalized_identity() != path.normalized_identity() {
            return Err(BlobError::PlanGap(
                "GC tombstone CAS target does not match its journal path".to_owned(),
            ));
        }
        if cas.root_lease != self.owner.lease {
            return Err(BlobError::StaleFence);
        }
        // A persisted tombstone is not evidence that its preceding CAS
        // completed. Reconstruct the exact request from the protected v2
        // context and recorded bytes, then require the provider's retained
        // operation-bound result. Byte equality alone never settles recovery.
        let request = Self::tombstone_cas_request(&tombstone, &bytes)?;
        let Ok(Some(status)) = self.platform_read().and_then(|platform| {
            platform.cas_status(request.context.operation.operation_id.as_str())
        }) else {
            return Err(cas_unknown(
                &request,
                None,
                None,
                BlobCasDurability::Unconfirmed,
            ));
        };
        validate_retained_cas_status(&request, &status)?;
        let mut frozen_cas_state = BlobCasState::Digest(sha256_hex(&bytes));
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
            frozen_cas_state = self.persist_tombstone(
                path,
                &tombstone,
                Some((previous_revision, frozen_cas_state.clone())),
            )?;
        }

        let payload = tombstone.payload.clone();
        let metadata = tombstone.metadata.clone();
        let operation_id = tombstone.operation_id.clone();
        let live_set = tombstone.live_set.clone();
        let locator = tombstone.locator.clone();
        let intent_revision = tombstone.intent_revision;
        // Hoisted before the `delete` closure borrows `tombstone` mutably:
        // the scope identity never changes across tombstone revisions.
        let tombstone_residency = tombstone.residency_sha256.clone();
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
                        frozen_cas_state = self.persist_tombstone(
                            path,
                            &tombstone,
                            Some((previous_revision, frozen_cas_state.clone())),
                        )?;
                        self.platform_remove(target).map_err(|error| {
                            if matches!(error, BlobError::StorageCapacity { .. }) {
                                bind_platform_capacity_gc(
                                    error,
                                    BlobCapacityStage::GcCleanup,
                                    BlobCapacityIdentity::Journal {
                                        operation_id: operation_id.clone(),
                                        idempotency_key: tombstone.parent_idempotency_key.clone(),
                                        locator: Some(locator.clone()),
                                    },
                                    state,
                                )
                            } else {
                                BlobError::UnknownGcOutcome {
                                    operation_id: operation_id.clone(),
                                    state,
                                }
                            }
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
        let reconciliation = self.live_sets_reconcile_delete(
            &operation_id,
            &live_set,
            &locator,
            intent_revision,
            &tombstone_residency,
        )?;
        let applied = match reconciliation {
            BlobDeletionReconciliation::Applied(receipt) => *receipt,
            BlobDeletionReconciliation::NotApplied => {
                match self.live_sets_compare_and_delete_observed(
                    &operation_id,
                    &live_set,
                    &locator,
                    intent_revision,
                    &tombstone_residency,
                    &mut delete,
                )? {
                    BlobDeletionReconciliation::Applied(receipt) => *receipt,
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
        let _ = self.persist_tombstone(
            path,
            &tombstone,
            Some((previous_revision, frozen_cas_state)),
        )?;
        Ok(ConditionalDeleteOutcome::Deleted)
    }

    /// Rejects re-admission of a purged object in the SAME residency scope.
    /// Purge is domain-scoped: a tombstone for equal bytes in another scope
    /// never blocks this scope, and this scope never revives another scope's
    /// purge. Legacy tombstones fail closed through [`decode_tombstone`].
    fn ensure_not_revoked(
        &self,
        locator: &BlobLocator,
        scope: &ResidencyScope,
    ) -> Result<(), BlobError> {
        let tombstones = WorkScopePath::new("tombstones")
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        self.contained(&tombstones)?;
        for path in self.platform_list(&tombstones)? {
            let bytes = self.read_bounded_file(&path, MAX_JOURNAL_BYTES)?;
            let tombstone = decode_tombstone(&bytes)?;
            tombstone.validate()?;
            if tombstone.locator == *locator && tombstone.residency_sha256 == scope.digest {
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
            residency: request.residency.clone(),
            root_generation: request.root_lease.root_generation,
            path_generation: PATH_GENERATION,
        };
        locator.validate()?;
        // One key observation per stage call. The residency scope — and with
        // it the physical object identity — is the s-04-v2 contract key carried
        // by the request. No default domain is ever invented; a rotated key
        // lineage that disagrees with the residency encryption domain is
        // rejected, while a converged operation below resolves to its committed
        // scope.
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
        let scope = residency_scope(&locator, &request.policy, &key.crypto)?;
        let payload = scoped_payload_path(&locator, &scope)?;
        let metadata_path_value = scoped_metadata_path(&locator, &scope)?;
        self.contained(&payload)?;
        self.contained(&metadata_path_value)?;
        self.ensure_not_revoked(&locator, &scope)?;

        let journal_path = Self::operation_path(&request.context, "stage")?;
        let commit_path = Self::operation_path(&request.context, "commit")?;
        self.contained(&commit_path)?;
        if self.platform_stat(&commit_path)? != BlobPathState::Missing {
            let bytes = self.read_bounded_file(&commit_path, MAX_JOURNAL_BYTES)?;
            let commit = decode_commit(&bytes)?;
            if commit.operation_id != request.context.operation.operation_id.as_str()
                || commit.idempotency_key != request.context.operation.idempotency_key
                || commit.locator != locator
            {
                return Err(BlobError::IdempotencyConflict);
            }
            // A commit record on disk does not prove this operation's create
            // completed its durability boundary: the journal that owes that
            // boundary is still the authority, and it outranks the record.
            //
            // `stage_locked` has four sites that issue a receipt, and they do not
            // all have the same power. Two of them settle: this branch, and the
            // journal-reload branch below, both through
            // `settle_retained_publications`. Two of them can only refuse: the
            // within-scope dedup branch and the fresh-publish branch further
            // down, because neither can settle a boundary it has no journal for
            // or no prior record of. The `reconcile` sweep is a third settler.
            //
            // Where this branch has no journal at all it relies on a precondition
            // rather than proving it: a retained obligation means the journal that
            // would carry it is still on the volume, because the journal is
            // deleted only after a fully settled commit. That is why this check
            // refuses instead of settling, and why the two refuse-only sites
            // restate it as a refusal rather than assume it.
            if self.platform_stat(&journal_path)? != BlobPathState::Missing {
                let journal_bytes = self.read_bounded_file(&journal_path, MAX_JOURNAL_BYTES)?;
                let mut journal: StageJournal = serde_json::from_slice(&journal_bytes)
                    .map_err(|_| BlobError::MetadataPayloadMismatch)?;
                journal.validate()?;
                // Prove this journal belongs to *this* request before settling
                // anything. Settling performs durable owner writes, overwrites the
                // journal on the volume and evicts retention entries, all keyed by
                // the journal's own identity — so acting on an unproven journal
                // would mutate a different operation. `journal_path` is derived
                // from this request's context, so identity equality already proves
                // ownership; `StageJournal::validate` above proved only that the
                // record is self-consistent. The sibling journal-reload branch
                // rejects the same mismatch with the same reason.
                if journal.operation_id != request.context.operation.operation_id.as_str()
                    || journal.idempotency_key != request.context.operation.idempotency_key
                {
                    return Err(BlobError::IdempotencyConflict);
                }
                self.settle_retained_publications(&journal_path, &mut journal)?;
                if !matches!(
                    journal.state,
                    PublishState::CommitDurable | PublishState::Ready | PublishState::Cleaned
                ) {
                    self.reestablish_publication_durability(
                        &journal_path,
                        &mut journal,
                        &commit_path,
                        &sha256_hex(&bytes),
                        MAX_JOURNAL_BYTES,
                        BlobCapacityStage::CommitWrite,
                    )?;
                    self.persist_journal(&journal_path, &journal, true)?;
                }
            } else if let Some(obligation) = self
                .retained_publications(
                    request.context.operation.operation_id.as_str(),
                    request.context.operation.idempotency_key.as_str(),
                )?
                .into_iter()
                .next()
            {
                // A boundary this operation still owes outlived the journal that
                // recorded it. The recovery state is unrecoverable, so the
                // operation stays unreleasable instead of being released on a
                // commit record that cannot answer for that boundary.
                return Err(BlobError::UnknownPublishOutcome {
                    operation_id: obligation.operation_id,
                    state: obligation.state_before,
                });
            }
            // Operation identity wins over a rotated request scope: the
            // committed scope is authoritative for this operation.
            let commit_scope = ResidencyScope {
                digest: commit.residency_sha256.clone(),
            };
            let (stored, metadata_bytes) = self.load_metadata(&commit.locator, &commit_scope)?;
            if sha256_hex(&metadata_bytes) != commit.metadata_sha256
                || stored.policy != request.policy
                || stored.plaintext_sha256 != sha256_hex(&request.bytes)
            {
                return Err(BlobError::IdempotencyConflict);
            }
            let verified = self.verify_metadata_receipt(&stored)?;
            let ready = stored.ready(verified, &self.issuer_anchor, commit.metadata_sha256)?;
            self.verify_payload(&ready, &request.bytes, &commit_scope)?;
            return Ok(ready);
        }
        if self.platform_stat(&journal_path)? != BlobPathState::Missing {
            let journal_bytes = self.read_bounded_file(&journal_path, MAX_JOURNAL_BYTES)?;
            let mut journal: StageJournal = serde_json::from_slice(&journal_bytes)
                .map_err(|_| BlobError::MetadataPayloadMismatch)?;
            journal.validate()?;
            // Check the persisted operation and all deterministic artifact
            // paths before allowing recovery to perform any publication. A
            // reused operation with a different locator must not advance the
            // old journal and discover the mismatch only after mutation.
            // The journal scope is parsed out of the persisted final paths
            // and proven against the request locator: a same-operation replay
            // under a rotated key or a changed policy recovers the journal's
            // own scope (the post-recovery metadata binding still rejects a
            // policy mismatch before readiness), while a different-bytes
            // replay cannot even parse and is an idempotency conflict.
            // The persisted journal has no policy commitment, so an otherwise
            // identical content/locator replay with a changed policy remains
            // an explicitly documented reconciliation limitation; final
            // metadata binding still rejects the mismatch before readiness.
            let journal_scope = parse_scoped_path(&journal.final_payload, &locator, 'p')
                .map_err(|_| BlobError::IdempotencyConflict)?;
            let journal_metadata_scope = parse_scoped_path(&journal.final_metadata, &locator, 'm')
                .map_err(|_| BlobError::IdempotencyConflict)?;
            if journal.operation_id != request.context.operation.operation_id.as_str()
                || journal.idempotency_key != request.context.operation.idempotency_key
                || journal.temp_payload != Self::temp_path(&request.context, "payload")?
                || journal.temp_metadata != Self::temp_path(&request.context, "metadata")?
                || journal_metadata_scope != journal_scope
            {
                return Err(BlobError::IdempotencyConflict);
            }
            // A publication obligation whose durable journal record could not be
            // written never reached the volume, so the journal decoded above
            // carries none and recovery would walk straight past the fence.
            // Settle what this service retained for this proven operation
            // identity first; each binding passes the obligation-ownership check a
            // durable record passes, and the same settlement-or-refusal route then
            // governs this and every later re-entry.
            self.settle_retained_publications(&journal_path, &mut journal)?;
            self.finish_journal(&journal_path, &mut journal)?;
            // Converge to the journal's own scope: a same-operation replay
            // under a rotated key recovers the already-published object
            // instead of publishing a second one for one operation.
            let (stored, metadata_bytes) = self.load_metadata(&locator, &journal_scope)?;
            if stored.policy != request.policy
                || stored.plaintext_length != request.bytes.len() as u64
                || stored.plaintext_sha256 != sha256_hex(&request.bytes)
            {
                return Err(BlobError::IdempotencyConflict);
            }
            let verified = self.verify_metadata_receipt(&stored)?;
            let ready = stored.ready(verified, &self.issuer_anchor, sha256_hex(&metadata_bytes))?;
            self.verify_payload(&ready, &request.bytes, &journal_scope)?;
            return Ok(ready);
        }
        // Within-scope dedup only: these paths already carry the request
        // scope, so equal bytes in another residency domain are invisible
        // here and always proceed to their own object below. Sharing one
        // physical object across domains by digest alone is rejected by
        // construction, not by comparison.
        let payload_state = self.platform_stat(&payload)?;
        let metadata_state = self.platform_stat(&metadata_path_value)?;
        if payload_state != BlobPathState::Missing || metadata_state != BlobPathState::Missing {
            if !matches!(payload_state, BlobPathState::File { .. })
                || !matches!(metadata_state, BlobPathState::File { .. })
            {
                return Err(BlobError::MetadataPayloadMismatch);
            }
            let (stored, metadata_bytes) = self.load_metadata(&locator, &scope)?;
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
            self.verify_payload(&ready, &request.bytes, &scope)?;
            // This branch never recovers a journal, so it cannot settle what this
            // service retained for the operation. A retained obligation means a
            // boundary is still owed, and no owner write has been performed for it
            // here, so the operation stays unreleasable rather than being released
            // on a matching object. Reported with the obligation's own recorded
            // state, because this site has no journal to bound.
            if let Some(obligation) = self
                .retained_publications(
                    request.context.operation.operation_id.as_str(),
                    request.context.operation.idempotency_key.as_str(),
                )?
                .into_iter()
                .next()
            {
                return Err(BlobError::UnknownPublishOutcome {
                    operation_id: obligation.operation_id,
                    state: obligation.state_before,
                });
            }
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
        // The nonce binds the residency scope, not just the content hash:
        // equal bytes in different domains must never reuse a nonce under one
        // key. (The AAD already covers the full residency inputs through the
        // locator/policy/crypto triple.) Envelopes sealed before this binding
        // fail authentication-closed on open — never plaintext fallback — and
        // recover by explicit re-stage from source.
        let seal_nonce = scope_nonce(&locator, &scope);
        let sealed = self.aead_seal(AeadSealRequest {
            key: &key,
            nonce_context: seal_nonce.as_bytes(),
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
        let residency_digest = locator.residency_key_digest()?;
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
                "{};format-version:{};stored-length:{};sealed-sha256:{};residency:{}",
                eliot_blob_api::CONTRACT_VERSION,
                FORMAT_VERSION,
                sealed.len(),
                sealed_sha256,
                residency_digest
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
            residency_sha256: scope.digest.clone(),
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
            idempotency_key: request.context.operation.idempotency_key.clone(),
            state: PublishState::JournalPrepared,
            temp_payload: temp_payload.clone(),
            temp_metadata: temp_metadata.clone(),
            final_payload: payload,
            final_metadata: metadata_path_value,
            expected_payload_sha256: sha256_hex(&sealed),
            expected_metadata_sha256: metadata_sha256.clone(),
            locator: Some(locator.clone()),
            pending_publication: None,
        };
        self.persist_journal(&journal_path, &journal, false)?;
        self.contained(&temp_payload)?;
        self.contained(&temp_metadata)?;
        if let Err(error) = self.platform_write_new(&temp_payload, &sealed) {
            let error = bind_platform_capacity_attempt(
                error,
                BlobCapacityStage::PayloadWrite,
                BlobCapacityIdentity::Operation {
                    context: Box::new(request.context.clone()),
                    locator: Some(locator.clone()),
                },
                sealed.len() as u64,
            );
            let error = match error {
                Ok(error) => error,
                Err(InvalidCapacityEvidence) => {
                    return Err(BlobError::UnknownPublishOutcome {
                        operation_id: journal.operation_id.clone(),
                        state: journal.state,
                    });
                }
            };
            // Keep the journal as the sole same-operation recovery record;
            // a capacity failure may have partially written the temp payload.
            if matches!(error, BlobError::StorageCapacity { .. }) {
                return Err(error);
            }
            let _ = self.remove_if_present(&journal_path);
            return Err(error);
        }
        if let Err(error) = self.platform_write_new(&temp_metadata, &metadata_bytes) {
            let error = bind_platform_capacity_attempt(
                error,
                BlobCapacityStage::MetadataWrite,
                BlobCapacityIdentity::Operation {
                    context: Box::new(request.context.clone()),
                    locator: Some(locator.clone()),
                },
                metadata_bytes.len() as u64,
            );
            let error = match error {
                Ok(error) => error,
                Err(InvalidCapacityEvidence) => {
                    return Err(BlobError::UnknownPublishOutcome {
                        operation_id: journal.operation_id.clone(),
                        state: journal.state,
                    });
                }
            };
            // Preserve both the journal and payload for reconciliation.  The
            // metadata write may have left a partial artifact as well.
            if matches!(error, BlobError::StorageCapacity { .. }) {
                return Err(error);
            }
            let _ = self.remove_if_present(&temp_payload);
            let _ = self.remove_if_present(&journal_path);
            return Err(error);
        }
        self.finish_journal(&journal_path, &mut journal)?;
        let verified = self.verify_metadata_receipt(&metadata)?;
        let ready = metadata.ready(verified, &self.issuer_anchor, metadata_sha256)?;
        self.verify_payload(&ready, &request.bytes, &scope)?;
        // Fourth receipt site, and the only one that publishes rather than
        // recovers: it built this operation's journal in this call, so the
        // journal carries no obligation to settle. A retained obligation for the
        // same identity would mean an earlier attempt left a boundary unproven and
        // nothing has discharged it since, so refuse rather than release. Same
        // refusal as the within-scope dedup branch, for the same reason.
        if let Some(obligation) = self
            .retained_publications(
                request.context.operation.operation_id.as_str(),
                request.context.operation.idempotency_key.as_str(),
            )?
            .into_iter()
            .next()
        {
            return Err(BlobError::UnknownPublishOutcome {
                operation_id: obligation.operation_id,
                state: obligation.state_before,
            });
        }
        Ok(ready)
    }

    fn verify_payload(
        &self,
        ready: &BlobReadyReceipt,
        expected_plaintext: &[u8],
        scope: &ResidencyScope,
    ) -> Result<(), BlobError> {
        // The receipt binds the full (locator, policy, crypto) triple, so the
        // scope it claims is exact. A caller-supplied scope for another
        // domain can never verify against this object.
        let bound = residency_scope(ready.locator(), ready.policy(), ready.crypto())?;
        if bound.digest != scope.digest {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        let path = scoped_payload_path(ready.locator(), scope)?;
        self.contained(&path)?;
        let sealed = self.read_bounded_file(&path, MAX_BLOB_ENVELOPE_BYTES)?;
        let (stored, _) = self.load_metadata(ready.locator(), scope)?;
        if sha256_hex(&sealed) != stored.sealed_sha256 {
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
        let open_nonce = scope_nonce(ready.locator(), scope);
        let compressed = self.aead_open(AeadOpenRequest {
            key: &key,
            nonce_context: open_nonce.as_bytes(),
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
    ) -> Result<(BlobReadyReceipt, Vec<u8>, Vec<u8>), BlobError> {
        request.validate()?;
        self.ensure_lease(&request.root_lease)?;
        // The request names a locator but no residency scope; the caller
        // proves the intended scope with the exact metadata digest it holds.
        // Resolution is byte-exact across every stored scope — never a
        // default-domain guess.
        let (resolved, metadata, metadata_bytes) =
            self.resolve_scope_for_metadata(&request.locator, &request.expected_metadata_sha256)?;
        let scope = resolved.scope;
        let metadata_sha256 = sha256_hex(&metadata_bytes);
        if metadata_sha256 != request.expected_metadata_sha256
            || metadata.receipt.identity.receipt_id.as_str() != request.expected_ready_receipt_id
        {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        let verified = self.verify_metadata_receipt(&metadata)?;
        let ready = metadata.ready(verified, &self.issuer_anchor, metadata_sha256)?;
        let path = scoped_payload_path(&request.locator, &scope)?;
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
        let open_nonce = scope_nonce(&request.locator, &scope);
        let compressed = self.aead_open(AeadOpenRequest {
            key: &key,
            nonce_context: open_nonce.as_bytes(),
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
        Ok((ready, plaintext, sealed))
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
        let (ready, bytes, _sealed_bytes) = self.read_verified(request)?;
        let read_residency_digest = request.locator.residency_key_digest()?;
        let artifact = ArtifactBinding {
            artifact_id: format!("blob-read-{}", request.locator.hash)
                .parse()
                .map_err(|error| BlobError::InvalidContract(format!("{error}")))?,
            sha256: ready.plaintext_sha256().to_owned(),
            role: ReceiptKind::Artifact,
            source_revision: Some(format!(
                "{};root-generation:{};path-generation:{};residency:{}",
                ready.metadata_sha256(),
                ready.root_generation(),
                ready.path_generation(),
                read_residency_digest
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

    fn read_sealed_sync(&self, request: &BlobReadRequest) -> Result<SealedBlobRead, BlobError> {
        let content_idx = content_shard(&request.locator.hash);
        let _guard = self.lock_shards(&[content_idx])?;
        let (ready, _plaintext, sealed_bytes) = self.read_verified(request)?;
        SealedBlobRead::from_verified(ready, sealed_bytes)
    }

    fn reference(
        &self,
        request: BlobReferenceRequest,
    ) -> Result<BlobReferenceObservation, BlobError> {
        request.validate()?;
        self.ensure_lease(&request.root_lease)?;
        let (resolved, metadata, bytes) =
            self.resolve_scope_for_metadata(&request.locator, &request.expected_metadata_sha256)?;
        let scope = resolved.scope;
        let metadata_sha256 = sha256_hex(&bytes);
        if metadata_sha256 != request.expected_metadata_sha256 {
            return Err(BlobError::MetadataPayloadMismatch);
        }
        let payload = scoped_payload_path(&request.locator, &scope)?;
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
        // Coherent reachability (T3-B): the view is bound to a freshly
        // revalidated complete live set. A stale or partial source blocks the
        // view instead of reporting reachability against a superseded union.
        // Liveness itself still comes only from the caller-supplied union —
        // the service never discovers semantic roots; per-locator scope
        // enumeration below resolves physical placements, not liveness.
        let observed = self.live_sets_revalidate(&request.live_set)?;
        Self::validate_live_set_revalidation(&request.live_set, &observed)?;
        let mut present = Vec::new();
        let mut missing = Vec::new();
        for locator in &request.live_set.live {
            // A locator is present only when at least one residency scope
            // exists and every stored scope is a complete, residency-bound
            // pair. Any gap — no scopes, a half-published pair, or a metadata
            // whose stored binding does not match its placement — reports the
            // locator missing rather than claiming a coherent view.
            let scopes = self.enumerate_scopes(locator)?;
            let mut complete = !scopes.is_empty();
            for scoped in &scopes {
                let (metadata, _) = self.load_metadata(locator, &scoped.scope)?;
                let payload_state = self.platform_stat(&scoped.payload)?;
                let metadata_state = self.platform_stat(&scoped.metadata)?;
                if !matches!(payload_state, BlobPathState::File { .. })
                    || !matches!(metadata_state, BlobPathState::File { .. })
                    || metadata.locator != *locator
                {
                    complete = false;
                    break;
                }
            }
            if complete {
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

    /// Lists durable per-scope tombstone paths for one operation and locator.
    /// The prefix binds the operation and the content hash; every match is
    /// still fully validated on load — the listing never authorizes anything.
    fn scope_tombstone_paths(
        &self,
        operation_id: &str,
        locator: &BlobLocator,
    ) -> Result<Vec<WorkScopePath>, BlobError> {
        let prefix = WorkScopePath::new(format!(
            "tombstones/{}-{}-r",
            operation_id,
            locator.hash.as_str()
        ))
        .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        self.contained(&prefix)?;
        self.platform_list(&prefix)
    }

    /// Resumes one durable per-scope tombstone against the exact request.
    /// Locator, residency placement, proof, snapshot, revision, and parent
    /// idempotency must all match; anything else fails closed instead of
    /// deleting under a superseded intent.
    fn resume_scope_tombstone(
        &self,
        request: &BlobGcRequest,
        locator: &BlobLocator,
        tombstone_path: &WorkScopePath,
    ) -> Result<ConditionalDeleteOutcome, BlobError> {
        self.contained(tombstone_path)?;
        let bytes = self.read_bounded_file(tombstone_path, MAX_JOURNAL_BYTES)?;
        let tombstone = decode_tombstone(&bytes)?;
        tombstone.validate()?;
        if tombstone.locator != *locator
            || tombstone.operation_id != request.context.operation.operation_id.as_str()
            || tombstone.proof_id != request.live_set.proof_id
            || tombstone.proof_snapshot_sha256 != request.live_set.snapshot_sha256
            || tombstone.live_set.revision != request.live_set.revision
        {
            return Err(BlobError::PlanGap(
                "GC tombstone identity does not match the exact request".to_owned(),
            ));
        }
        // The loaded tombstone must live exactly at the derived placement
        // for its own (locator, residency): a transplanted record can never
        // authorize this path's deletion.
        let loaded_scope = ResidencyScope {
            digest: tombstone.residency_sha256.clone(),
        };
        if tombstone_scope_path(&tombstone.operation_id, &tombstone.locator, &loaded_scope)?
            .normalized_identity()
            != tombstone_path.normalized_identity()
        {
            return Err(BlobError::PlanGap(
                "GC tombstone identity does not match the exact request".to_owned(),
            ));
        }
        if tombstone.parent_idempotency_key != request.context.operation.idempotency_key {
            return Err(BlobError::IdempotencyConflict);
        }
        self.reconcile_tombstone_path(tombstone_path)
    }

    /// Collects one residency scope of an unreachable candidate: resumes an
    /// existing per-scope tombstone or, after grace and a fresh
    /// destructive-boundary revalidation, persists one and reconciles it to
    /// deletion. A resumed tombstone must match the exact request —
    /// locator, residency scope, proof, snapshot, revision, and parent
    /// idempotency — or the run fails closed instead of deleting under a
    /// superseded intent.
    #[allow(clippy::too_many_lines)]
    fn gc_scope(
        &self,
        request: &BlobGcRequest,
        locator: &BlobLocator,
        scoped: &ScopedObject,
        now: u64,
    ) -> Result<ConditionalDeleteOutcome, BlobError> {
        let operation_id = request.context.operation.operation_id.to_string();
        let tombstone_path = tombstone_scope_path(&operation_id, locator, &scoped.scope)?;
        self.contained(&tombstone_path)?;
        if self.platform_stat(&tombstone_path)? != BlobPathState::Missing {
            return self.resume_scope_tombstone(request, locator, &tombstone_path);
        }
        let modified = match self.platform_stat(&scoped.payload)? {
            BlobPathState::File {
                modified_unix_ms, ..
            } => modified_unix_ms,
            BlobPathState::Missing => {
                return Ok(ConditionalDeleteOutcome::RetainedLive);
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
        match self.platform_stat(&scoped.metadata)? {
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
            return Ok(ConditionalDeleteOutcome::RetainedLive);
        }
        // Revalidate at each destructive boundary, not once per batch.
        let current = self.live_sets_revalidate(&request.live_set)?;
        Self::validate_revalidation(request, &current)?;
        let tombstone = Tombstone {
            operation_id,
            parent_idempotency_key: request.context.operation.idempotency_key.clone(),
            revision: 1,
            intent_revision: 1,
            proof_id: request.live_set.proof_id.clone(),
            proof_snapshot_sha256: request.live_set.snapshot_sha256.clone(),
            locator: locator.clone(),
            residency_sha256: scoped.scope.digest.clone(),
            live_set: request.live_set.clone(),
            payload: scoped.payload.clone(),
            metadata: scoped.metadata.clone(),
            state: GcState::TombstoneDurable,
            receipt: None,
            cas: Some(TombstoneCas {
                version: 2,
                context: Self::tombstone_cas_context(
                    &request.context,
                    request.context.operation.operation_id.as_str(),
                    &tombstone_path,
                    1,
                )?,
                root_lease: self.owner.lease.clone(),
                target: tombstone_path.clone(),
                expected: BlobCasState::Missing,
                expected_backend_generation: self.platform_backend_generation()?,
                requested_durability: BlobCasDurability::Requested,
            }),
        };
        self.persist_tombstone(&tombstone_path, &tombstone, None)?;
        self.reconcile_tombstone_path(&tombstone_path)
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
            // Residency-scoped collection: every stored scope of an
            // unreachable locator is collected independently, each with its
            // own tombstone, grace check, and destructive-boundary
            // revalidation. Liveness stays locator-level and conservative — a
            // live locator retains all of its scopes — while deletion is per
            // scope so purging one domain never disturbs equal bytes in
            // another.
            let scopes = self.enumerate_scopes(locator)?;
            if scopes.is_empty() {
                // No complete scope pairs remain: either nothing was ever
                // published, or a prior run already deleted every scope and
                // left only durable tombstones. Resume this operation's
                // tombstones so an exact GC replay converges to the same
                // receipt; anything else retains (never error, never delete
                // blind).
                let operation_id = request.context.operation.operation_id.to_string();
                let mut replayed_deleted = false;
                let mut replayed_retained = false;
                for tombstone_path in self.scope_tombstone_paths(&operation_id, locator)? {
                    if self.platform_stat(&tombstone_path)? == BlobPathState::Missing {
                        continue;
                    }
                    match self.resume_scope_tombstone(&request, locator, &tombstone_path)? {
                        ConditionalDeleteOutcome::Deleted => {
                            replayed_deleted = true;
                        }
                        ConditionalDeleteOutcome::RetainedLive => {
                            replayed_retained = true;
                        }
                    }
                }
                if replayed_deleted && !replayed_retained {
                    deleted.push(locator.clone());
                } else {
                    retained.push(locator.clone());
                }
                continue;
            }
            let mut scopes_deleted = 0_usize;
            let mut scopes_retained = 0_usize;
            for scoped in &scopes {
                match self.gc_scope(&request, locator, scoped, now)? {
                    ConditionalDeleteOutcome::Deleted => {
                        scopes_deleted = scopes_deleted.saturating_add(1);
                    }
                    ConditionalDeleteOutcome::RetainedLive => {
                        scopes_retained = scopes_retained.saturating_add(1);
                    }
                }
            }
            // The locator-level receipt vocabulary cannot express a split
            // scope outcome: any retained scope retains the locator.
            if scopes_deleted > 0 && scopes_retained == 0 {
                deleted.push(locator.clone());
            } else {
                retained.push(locator.clone());
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
                let tombstone = decode_tombstone(&bytes)?;
                tombstone.validate()?;
                let cas = tombstone.cas.as_ref().ok_or_else(|| {
                    BlobError::PlanGap(
                        "GC tombstone is missing exact CAS authority context".to_owned(),
                    )
                })?;
                if cas.target.normalized_identity() != path.normalized_identity() {
                    return Err(BlobError::PlanGap(
                        "GC tombstone CAS target does not match its scanned path".to_owned(),
                    ));
                }
                if cas.root_lease != self.owner.lease {
                    return Err(BlobError::StaleFence);
                }
                let request = Self::tombstone_cas_request(&tombstone, &bytes)?;
                let Ok(Some(status)) = self.platform_read().and_then(|platform| {
                    platform.cas_status(request.context.operation.operation_id.as_str())
                }) else {
                    return Err(cas_unknown(
                        &request,
                        None,
                        None,
                        BlobCasDurability::Unconfirmed,
                    ));
                };
                validate_retained_cas_status(&request, &status)?;
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
        // An unresolved required capacity failure on the root lease is an owner
        // observation, not a diagnostic detail: while the heartbeat has not
        // been re-established, this root may not report healthy evidence.
        if let Some(heartbeat) = self
            .owner
            .os_owner
            .as_ref()
            .and_then(BlobRootOwner::heartbeat_failure)
        {
            degraded.push(format!("root lease heartbeat unresolved: {heartbeat}"));
        }
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

    fn tombstone_cas_context(
        context: &BlobReceiptContext,
        parent_operation_id: &str,
        target: &WorkScopePath,
        revision: u64,
    ) -> Result<BlobReceiptContext, BlobError> {
        let mut cas = context.clone();
        let step_identity = tombstone_cas_step_identity(parent_operation_id, target, revision);
        cas.operation.operation_id = OperationId::new(step_identity.clone())
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        step_identity.clone_into(&mut cas.operation.idempotency_key);
        "blob-tombstone-cas".clone_into(&mut cas.operation.operation_kind);
        Ok(cas)
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

/// Construction bundle for [`BlobStoreService`] (T3-B): the six injected
/// dependencies travel as one value so constructors stay within the argument
/// ceiling without hiding any dependency. Every field is still supplied by
/// the composition owner (C3 wiring for production).
pub struct BlobServicePorts<P, C, K, A, L> {
    /// Durable no-replace platform adapter (P-01/P-02).
    pub platform: P,
    /// Compression provider (never encryption).
    pub compression: C,
    /// Key lineage provider.
    pub keys: K,
    /// Authenticated-envelope provider.
    pub aead: A,
    /// Caller-owned live-set union provider.
    pub live_sets: L,
    /// Independently pinned receipt issuer anchor.
    pub issuer_anchor: BlobIssuerTrustAnchor,
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
        // Ownerless contour for unit/reference compositions. It still joins
        // the process-local single-owner registry (a second service on the
        // same root fails with `OwnerConflict`), but without a retained OS
        // owner handle its cross-process exclusion rests on the platform
        // adapter's `claim_root` proof. Production compositions must use
        // `new_with_owner`; the real P-01/P-02 adapter that would carry the
        // cross-process proof is an honest gap (see `platform_plan_gap`).
        Ok(Self {
            core: Arc::new(BlobStoreCore::claim(
                lease,
                None,
                BlobServicePorts {
                    platform,
                    compression,
                    keys,
                    aead,
                    live_sets,
                    issuer_anchor,
                },
            )?),
        })
    }

    /// Owner-bound constructor: the single-owner composition (T3-B, issue
    /// #19). The service claim binds to the presenting OS `owner` claim —
    /// `owns_service_root` plus reserver-token equality — so a root reserved
    /// by one claim can never admit a second service owner in the same or
    /// another process. The OS lease handle is retained inside the shared
    /// core for the full service lifetime; cloned handles share it and never
    /// re-claim. The C3 bridge wiring owns calling this with the retained
    /// composition owner.
    pub fn new_with_owner(
        owner: &BlobRootOwner,
        lease: BlobRootLease,
        ports: BlobServicePorts<P, C, K, A, L>,
    ) -> Result<Self, BlobError> {
        Ok(Self {
            core: Arc::new(BlobStoreCore::claim(lease, Some(owner.clone()), ports)?),
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

    fn read_sealed(&self, request: BlobReadRequest) -> BlobFuture<'_, SealedBlobRead> {
        let core = Arc::clone(&self.core);
        Box::pin(async move { core.read_sealed_sync(&request) })
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
    use eliot_blob_api::{ObjectResidencyKey, VersionedContentDigest};
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

    fn test_capacity_error(
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
                recovery: match effect {
                    BlobCapacityEffect::NotAttempted | BlobCapacityEffect::PartialWriteUnknown => {
                        BlobCapacityRecovery::CapacityRevalidationRequired
                    }
                    BlobCapacityEffect::PossibleMutation
                    | BlobCapacityEffect::PossiblePublication { .. }
                    | BlobCapacityEffect::DurabilityUnconfirmed { .. } => {
                        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
                    }
                },
            }),
        }
    }

    struct MemoryPlatform {
        files: BTreeMap<String, (Vec<u8>, u64)>,
        cas_requests: BTreeMap<String, BlobCasRequest>,
        cas_statuses: BTreeMap<String, BlobCasProviderResult>,
        claim: Option<RootClaimProof>,
        now: u64,
        backend_generation: u64,
        fail_write: Option<BlobCapacityStage>,
        fail_rename: bool,
        fail_remove: bool,
    }

    impl Default for MemoryPlatform {
        fn default() -> Self {
            Self {
                files: BTreeMap::new(),
                cas_requests: BTreeMap::new(),
                cas_statuses: BTreeMap::new(),
                claim: None,
                now: 0,
                backend_generation: 1,
                fail_write: None,
                fail_rename: false,
                fail_remove: false,
            }
        }
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
            if let Some(stage) = self.fail_write.take() {
                return Err(test_capacity_error(
                    stage,
                    BlobCapacityEffect::PartialWriteUnknown,
                    Some(bytes.len() as u64),
                ));
            }
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

        fn compare_and_replace_durable(
            &mut self,
            request: &BlobCasRequest,
            bytes: &[u8],
        ) -> Result<BlobCasProviderResult, BlobError> {
            request.validate()?;
            let operation_id = request.context.operation.operation_id.to_string();
            if self.cas_capability() != BlobCasCapability::AtomicCompareAndReplace {
                return Err(BlobError::CasFailure {
                    failure: Box::new(BlobCasFailure::UnsupportedAtomicCas {
                        request: Box::new(request.clone()),
                    }),
                });
            }
            if let Some(previous) = self.cas_requests.get(&operation_id) {
                if previous.context.operation.idempotency_key
                    != request.context.operation.idempotency_key
                    || previous.request_commitment_sha256()?
                        != request.request_commitment_sha256()?
                {
                    return Err(BlobError::CasFailure {
                        failure: Box::new(BlobCasFailure::IdentityConflict {
                            request: Box::new(request.clone()),
                        }),
                    });
                }
                return self
                    .cas_statuses
                    .get(&operation_id)
                    .cloned()
                    .ok_or_else(|| {
                        cas_unknown(request, None, None, BlobCasDurability::Unconfirmed)
                    });
            }
            if self.backend_generation != request.expected_backend_generation {
                return Err(BlobError::CasFailure {
                    failure: Box::new(BlobCasFailure::Internal {
                        request: Box::new(request.clone()),
                        reason: eliot_blob_api::BlobCasInternalReason::BackendGenerationMismatch,
                    }),
                });
            }
            if bytes.len() as u64 != request.replacement_length
                || sha256_hex(bytes) != request.replacement_sha256
            {
                return Err(BlobError::CasFailure {
                    failure: Box::new(BlobCasFailure::Internal {
                        request: Box::new(request.clone()),
                        reason: eliot_blob_api::BlobCasInternalReason::CommitmentMismatch,
                    }),
                });
            }
            let observed = self
                .files
                .get(request.target.normalized_identity())
                .map_or(BlobCasState::Missing, |(current, _)| {
                    BlobCasState::Digest(sha256_hex(current))
                });
            if observed != request.expected {
                return Err(BlobError::CasFailure {
                    failure: Box::new(BlobCasFailure::ExpectedStateConflict {
                        request: Box::new(request.clone()),
                        observed,
                    }),
                });
            }
            if request.expected.sha256() != Some(request.replacement_sha256.as_str()) {
                self.files.insert(
                    request.target.normalized_identity().to_owned(),
                    (bytes.to_vec(), self.now),
                );
            }
            let result = BlobCasProviderResult {
                operation_id: operation_id.clone(),
                request_commitment_sha256: request.request_commitment_sha256()?,
                observed: request.expected.clone(),
                replacement_sha256: request.replacement_sha256.clone(),
                replacement_length: request.replacement_length,
                backend_generation: self.backend_generation,
                observed_durability: BlobCasDurability::Confirmed,
                success: if request.expected.sha256() == Some(request.replacement_sha256.as_str()) {
                    BlobCasSuccessKind::NoOp
                } else {
                    BlobCasSuccessKind::Applied
                },
            };
            self.cas_requests
                .insert(operation_id.clone(), request.clone());
            self.cas_statuses.insert(operation_id, result.clone());
            Ok(result)
        }

        fn cas_status(
            &self,
            operation_id: &str,
        ) -> Result<Option<BlobCasProviderResult>, BlobError> {
            Ok(self.cas_statuses.get(operation_id).cloned())
        }

        fn cas_capability(&self) -> BlobCasCapability {
            BlobCasCapability::AtomicCompareAndReplace
        }

        fn backend_generation(&self) -> Result<u64, BlobError> {
            Ok(self.backend_generation)
        }

        fn rename_no_replace_durable(
            &mut self,
            source: &WorkScopePath,
            destination: &WorkScopePath,
        ) -> Result<(), BlobError> {
            if self.fail_rename {
                return Err(test_capacity_error(
                    BlobCapacityStage::PayloadPublication,
                    BlobCapacityEffect::PossiblePublication {
                        state: PublishState::JournalPrepared,
                    },
                    None,
                ));
            }
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
            if self.fail_remove {
                return Err(test_capacity_error(
                    BlobCapacityStage::Cleanup,
                    BlobCapacityEffect::PossiblePublication {
                        state: PublishState::CommitDurable,
                    },
                    None,
                ));
            }
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
            residency_sha256: &str,
        ) -> Result<BlobDeletionReconciliation, BlobError> {
            match self.mode {
                TestGcMode::Applied => Ok(BlobDeletionReconciliation::Applied(Box::new(
                    deletion_receipt(
                        operation_id,
                        proof,
                        locator,
                        intent_revision,
                        residency_sha256,
                    ),
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
            residency_sha256: &str,
            delete: &mut dyn FnMut() -> Result<(), BlobError>,
        ) -> Result<BlobDeletionReconciliation, BlobError> {
            if self.stale {
                return Err(BlobError::IncompleteLiveSet);
            }
            delete()?;
            self.delete_calls = self.delete_calls.saturating_add(1);
            let mut receipt = deletion_receipt(
                operation_id,
                proof,
                locator,
                intent_revision,
                residency_sha256,
            );
            if self.tamper_receipt {
                receipt.path_digest_sha256 = sha256_hex(b"wrong-path");
            }
            Ok(BlobDeletionReconciliation::Applied(Box::new(receipt)))
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
        residency_sha256: &str,
    ) -> BlobDeletionReceipt {
        // The port re-derives the residency-scoped placement from the digest
        // the service passes, exactly like the service does; the service then
        // validates the receipt path digest and requires both files absent.
        let scope = ResidencyScope {
            digest: residency_sha256.to_owned(),
        };
        let payload = scoped_payload_path(locator, &scope).expect("payload path");
        let metadata = scoped_metadata_path(locator, &scope).expect("metadata path");
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
        // Epoch wire shape follows the current contract: EpochId is the exact
        // (lineage_id, sequence) tuple, never a scalar. Fence and authority
        // epochs match (AuthorityBinding::validate enforces sameness).
        let epoch = r#"{"lineage_id":"550e8400-e29b-41d4-a716-446655440000","sequence":4}"#;
        let fence = format!(
            "{{\"authority_epoch\":{epoch},\"resource_generation\":7,\"task_revision\":null,\"policy_revision\":null,\"integration_revision\":null}}"
        );
        let metadata = format!(
            r#"{{"request_id":"{request}","session_id":null,"task_id":null,"product_id":"product-1","source_id":"source-1","state_fence":{fence},"clock":{{"valid_time_ms":1,"known_time_ms":1,"transaction_sequence":null,"monotonic_ns":1}}}}"#
        );
        format!(
            r#"{{"work_scope":{{"scope_id":"scope-1","product_id":"product-1","resource_generation":7,"state_fence":{fence}}},"task":null,"session":null,"causal":{{"state_fence":{fence},"transaction_sequence":1,"parent_receipt_id":null,"predecessor_receipt_ids":[]}},"request":{{"metadata":{metadata},"state_fence":{fence}}},"operation":{{"operation_id":"{operation}","request_id":"{request}","idempotency_key":"idem-1","operation_kind":"blob-test","effect":"{effect}","state_fence":{fence}}},"authority":{{"authority_id":"authority-1","authority_owner":"test-owner","authority_epoch":{epoch},"state_fence":{fence},"allowed_effect":"{effect}","proof_ceiling":"OBSERVED_EXTERNAL_EFFECT"}}}}"#
        )
    }

    static TEST_ROOT_COUNTER: AtomicU64 = AtomicU64::new(1);

    /// Fresh root identity per test store. Stores share one process, and the
    /// T3-B single-owner registry rejects a second service on a live root —
    /// so every store under test needs its own root.
    fn unique_test_root() -> String {
        let sequence = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("root-test-{sequence}")
    }

    fn lease(context: &BlobReceiptContext) -> BlobRootLease {
        lease_on(context, "root-1")
    }

    fn lease_on(context: &BlobReceiptContext, root_id: &str) -> BlobRootLease {
        serde_json::from_value(serde_json::json!({
            "root_id": root_id,
            "owner_id": "owner-1",
            "lease_id": "lease-1",
            "root_generation": 7,
            "fence_binding": context.request,
        }))
        .expect("lease")
    }

    fn stage_request(operation: &str, bytes: &[u8], root: &str) -> BlobStageRequest {
        stage_request_with_policy(operation, bytes, root, "policy-1")
    }

    fn stage_request_with_policy(
        operation: &str,
        bytes: &[u8],
        root: &str,
        policy_ref: &str,
    ) -> BlobStageRequest {
        stage_request_with_scope(operation, bytes, root, policy_ref, "scope-test")
    }

    fn stage_request_with_scope(
        operation: &str,
        bytes: &[u8],
        root: &str,
        policy_ref: &str,
        scope_domain: &str,
    ) -> BlobStageRequest {
        let context: BlobReceiptContext = serde_json::from_str(&context_json(
            "REVERSIBLE_MUTATION",
            operation,
            &format!("request-{operation}"),
        ))
        .expect("context");
        // s-04-v2: the request carries the full residency key whose content
        // digest must equal BLAKE3(bytes). Test lineage matches TestKeys.
        let digest = BlobHash::new(blake3::hash(bytes).to_hex().to_string()).expect("hash");
        let residency = ObjectResidencyKey {
            scope_domain_id: BlobId::new(scope_domain).expect("scope domain"),
            access_domain_id: BlobId::new("access-test").expect("access domain"),
            confidentiality_domain_id: BlobId::new("conf-test").expect("conf domain"),
            encryption_key_domain_id: BlobId::new("test-lineage").expect("key domain"),
            retention_domain_id: BlobId::new("retention-test").expect("retention domain"),
            erasure_domain_id: BlobId::new("erasure-test").expect("erasure domain"),
            content_digest: VersionedContentDigest {
                algorithm: BlobId::new("blake3").expect("algorithm"),
                version: 1,
                digest,
            },
        };
        residency.validate().expect("residency");
        BlobStageRequest {
            root_lease: lease_on(&context, root),
            context,
            bytes: bytes.to_vec(),
            policy: BlobPolicyBinding {
                privacy_class: eliot_security_contracts::PrivacyClass::Private,
                retention_class: eliot_blob_api::RetentionClass::Task,
                policy_ref: eliot_platform::PlatformHandle::new(policy_ref).expect("policy"),
                instruction_taint: eliot_security_contracts::InstructionTaint::DataOnly,
                effect_ceiling: eliot_security_contracts::EffectCeiling::CandidateOnly,
            },
            residency,
        }
    }

    fn store_with_platform(
        platform: MemoryPlatform,
        root: &str,
    ) -> BlobStoreService<MemoryPlatform, TestCompression, TestKeys, TestAead, TestLiveSets> {
        let request = stage_request("bootstrap", b"", root);
        BlobStoreService::new(
            request.root_lease,
            platform,
            TestCompression,
            TestKeys,
            TestAead,
            TestLiveSets::default(),
            test_anchor(),
        )
        .expect("store")
    }

    fn store_on(
        root: &str,
    ) -> BlobStoreService<MemoryPlatform, TestCompression, TestKeys, TestAead, TestLiveSets> {
        store_with_platform(MemoryPlatform::default(), root)
    }

    fn gc_store(
        mode: TestGcMode,
        stale: bool,
        root: &str,
    ) -> BlobStoreService<MemoryPlatform, TestCompression, TestKeys, TestAead, TestLiveSets> {
        let request = stage_request("bootstrap", b"", root);
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

    fn gc_request(
        live: Vec<BlobLocator>,
        candidates: Vec<BlobLocator>,
        root: &str,
    ) -> BlobGcRequest {
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
            root_lease: lease_on(&context, root),
            context,
            live_set,
            candidates,
            grace_period_seconds: 0,
        }
    }

    fn reachability_request(live: Vec<BlobLocator>, root: &str) -> BlobReachabilityRequest {
        let context: BlobReceiptContext = serde_json::from_str(&context_json(
            "READ",
            "reachability-operation",
            "request-reachability-operation",
        ))
        .expect("context");
        let live_set = BlobLiveSetProof {
            proof_id: BlobId::new("proof-reachability").expect("proof id"),
            canonical_owner_ref: BlobId::new("canonical-owner").expect("owner ref"),
            completeness: LiveSetCompleteness::Complete,
            snapshot_sha256: sha256_hex(b"live-set-snapshot"),
            revision: 1,
            fence_binding: context.request.clone(),
            live,
            receipt_refs: vec!["receipt-reachability".to_owned()],
        };
        BlobReachabilityRequest {
            root_lease: lease_on(&context, root),
            context,
            live_set,
        }
    }

    fn read_request(ready: &BlobReadyReceipt, operation: &str, root: &str) -> BlobReadRequest {
        let context: BlobReceiptContext = serde_json::from_str(&context_json(
            "READ",
            operation,
            &format!("request-{operation}"),
        ))
        .expect("context");
        BlobReadRequest {
            root_lease: lease_on(&context, root),
            context,
            locator: ready.locator().clone(),
            expected_metadata_sha256: ready.metadata_sha256().to_owned(),
            expected_ready_receipt_id: ready.receipt().identity.receipt_id.to_string(),
            max_bytes: 1024,
        }
    }

    #[test]
    fn object_safe_stage_read_roundtrip() {
        let root = unique_test_root();
        let store = store_on(&root);
        let client: &dyn BlobStoreClient = &store;
        let ready =
            block_on(client.stage(stage_request("roundtrip", b"payload", &root))).expect("stage");
        let expected_anchor = test_anchor();
        assert_eq!(ready.anchor_fingerprint(), expected_anchor.fingerprint());
        assert_eq!(ready.plaintext_length(), 7);
        let chunk =
            block_on(client.read(read_request(&ready, "roundtrip-read", &root))).expect("read");
        assert_eq!(chunk.bytes(), b"payload");
        assert_eq!(chunk.anchor_fingerprint(), expected_anchor.fingerprint());
        assert!(chunk.is_complete());
        assert!(block_on(client.health()).expect("health").ready);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_user_ports_drive_stage_read_roundtrip() {
        use crate::key_ports::{DpapiUserAeadPort, DpapiUserKeyPort};

        let root = unique_test_root();
        let platform_root = std::env::temp_dir().join(format!("eliot-1873k-svc-{root}"));
        std::fs::create_dir_all(&platform_root).expect("isolated platform root");
        let platform =
            eliot_platform_windows::WindowsPlatform::new(platform_root.clone()).expect("platform");
        let lineage = BlobId::new("dpapi-user-1873k-svc").expect("lineage");
        let bootstrap = stage_request("bootstrap", b"", &root);
        let store = BlobStoreService::new(
            bootstrap.root_lease,
            MemoryPlatform::default(),
            TestCompression,
            DpapiUserKeyPort::new(lineage, 5).expect("key port"),
            DpapiUserAeadPort::new(platform),
            TestLiveSets::default(),
            test_anchor(),
        )
        .expect("store");
        let client: &dyn BlobStoreClient = &store;
        let mut request = stage_request("dpapi-roundtrip", b"payload-1873k", &root);
        request.residency.encryption_key_domain_id =
            BlobId::new("dpapi-user-1873k-svc").expect("key domain");
        let ready = block_on(client.stage(request)).expect("stage");
        assert_eq!(ready.plaintext_length(), 13);
        let chunk = block_on(client.read(read_request(&ready, "dpapi-read", &root))).expect("read");
        assert_eq!(chunk.bytes(), b"payload-1873k");
        assert!(chunk.is_complete());
        std::fs::remove_dir_all(&platform_root).ok();
    }

    #[test]
    fn idempotent_replay_is_exact_and_conflict_never_succeeds() {
        let root = unique_test_root();
        let store = store_on(&root);
        let request = stage_request("idem", b"payload", &root);
        let first = block_on(store.stage(request.clone())).expect("stage");
        let replay = block_on(store.stage(request)).expect("replay");
        assert_eq!(first, replay);
        let conflict = block_on(store.stage(stage_request("idem", b"different", &root)));
        assert_eq!(conflict, Err(BlobError::IdempotencyConflict));
    }

    #[test]
    fn gc_retains_live_and_removes_unreachable_once() {
        let root = unique_test_root();
        let store = gc_store(TestGcMode::NotApplied, false, &root);
        let live =
            block_on(store.stage(stage_request("live", b"live-payload", &root))).expect("live");
        let unreachable = block_on(store.stage(stage_request("orphan", b"orphan-payload", &root)))
            .expect("orphan");
        let request = gc_request(
            vec![live.locator().clone()],
            vec![live.locator().clone(), unreachable.locator().clone()],
            &root,
        );
        let receipt = block_on(store.gc(request.clone())).expect("gc");
        assert!(receipt.deleted().contains(unreachable.locator()));
        assert!(receipt.retained().contains(live.locator()));
        assert!(matches!(
            block_on(store.read(read_request(&unreachable, "orphan-read", &root))),
            Err(BlobError::NotFound)
        ));
        assert_eq!(
            block_on(store.stage(stage_request("orphan-replay", b"orphan-payload", &root))),
            Err(BlobError::PlanGap(
                "purged or quarantined blob content cannot be re-admitted".to_owned()
            ))
        );
        let health = block_on(store.health()).expect("health");
        assert!(health.ready);
        assert!(health.recovery_clean);
        let mut changed_parent = request.clone();
        changed_parent.context.operation.idempotency_key = "gc-operation-changed".to_owned();
        assert_eq!(
            block_on(store.gc(changed_parent)),
            Err(BlobError::IdempotencyConflict)
        );
        let replay = block_on(store.gc(request)).expect("exact gc replay");
        assert_eq!(replay, receipt);
    }

    #[test]
    fn stale_reachability_plan_is_rejected_before_tombstone() {
        let root = unique_test_root();
        let store = gc_store(TestGcMode::NotApplied, true, &root);
        let orphan = block_on(store.stage(stage_request("stale-orphan", b"payload", &root)))
            .expect("orphan");
        let request = gc_request(Vec::new(), vec![orphan.locator().clone()], &root);
        assert_eq!(
            block_on(store.gc(request)),
            Err(BlobError::IncompleteLiveSet)
        );
        assert!(block_on(store.read(read_request(&orphan, "stale-read", &root))).is_ok());
    }

    #[test]
    fn target_receipt_path_digest_mismatch_is_rejected() {
        let root = unique_test_root();
        let store = gc_store(TestGcMode::NotApplied, false, &root);
        store
            .core
            .live_sets
            .lock()
            .expect("live-set lock")
            .tamper_receipt = true;
        let orphan =
            block_on(store.stage(stage_request("bad-receipt", b"payload", &root))).expect("orphan");
        let request = gc_request(Vec::new(), vec![orphan.locator().clone()], &root);
        assert_eq!(
            block_on(store.gc(request)),
            Err(BlobError::MetadataPayloadMismatch)
        );
    }

    #[test]
    fn applied_receipt_with_live_targets_is_rejected() {
        let root = unique_test_root();
        let store = gc_store(TestGcMode::Applied, false, &root);
        let orphan = block_on(store.stage(stage_request("live-target-receipt", b"payload", &root)))
            .expect("orphan");
        let request = gc_request(Vec::new(), vec![orphan.locator().clone()], &root);
        assert_eq!(
            block_on(store.gc(request)),
            Err(BlobError::MetadataPayloadMismatch)
        );
        assert!(block_on(store.read(read_request(&orphan, "live-target-read", &root))).is_ok());
    }

    #[test]
    fn unknown_gc_outcome_is_durable_and_not_blindly_retried() {
        let root = unique_test_root();
        let store = gc_store(TestGcMode::Unknown, false, &root);
        let orphan = block_on(store.stage(stage_request("unknown-orphan", b"payload", &root)))
            .expect("orphan");
        let request = gc_request(Vec::new(), vec![orphan.locator().clone()], &root);
        assert!(matches!(
            block_on(store.gc(request.clone())),
            Err(BlobError::UnknownGcOutcome { .. })
        ));
        let tombstones = WorkScopePath::new("tombstones").expect("tombstones path");
        let tombstone_path = store
            .core
            .platform
            .read()
            .expect("platform lock")
            .list(&tombstones)
            .expect("tombstone list")
            .into_iter()
            .next()
            .expect("durable tombstone");
        let current_bytes = store
            .core
            .platform
            .read()
            .expect("platform lock")
            .read_bounded(&tombstone_path, MAX_JOURNAL_BYTES)
            .expect("tombstone bytes");
        let current = decode_tombstone(&current_bytes).expect("tombstone");
        let revision_one_id =
            tombstone_cas_step_identity(&current.operation_id, &tombstone_path, 1);
        let revision_one_status = store
            .core
            .platform
            .read()
            .expect("platform lock")
            .cas_status(&revision_one_id)
            .expect("retained status")
            .expect("revision one status");
        let revision_one_expected = revision_one_status.replacement_sha256.clone();
        let mut stale = current.clone();
        stale.revision = current.revision.saturating_add(1);
        let stale_error = store.core.persist_tombstone(
            &tombstone_path,
            &stale,
            Some((1, BlobCasState::Digest(revision_one_expected.clone()))),
        );
        assert!(matches!(
            stale_error,
                Err(BlobError::CasFailure { failure })
                    if matches!(&*failure, BlobCasFailure::ExpectedStateConflict { request, .. }
                    if request.expected == BlobCasState::Digest(revision_one_expected.clone()))
        ));
        assert!(block_on(store.read(read_request(&orphan, "unknown-read", &root))).is_ok());
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
        assert!(block_on(store.read(read_request(&orphan, "unknown-read-2", &root))).is_ok());
    }

    #[test]
    fn applied_reconciliation_after_effect_does_not_delete_again() {
        let root = unique_test_root();
        let store = gc_store(TestGcMode::Unknown, false, &root);
        let orphan = block_on(store.stage(stage_request("crash-orphan", b"payload", &root)))
            .expect("orphan");
        let request = gc_request(Vec::new(), vec![orphan.locator().clone()], &root);
        assert!(matches!(
            block_on(store.gc(request.clone())),
            Err(BlobError::UnknownGcOutcome { .. })
        ));

        // Resolve the residency-scoped placement through the service's own
        // enumeration: the test never guesses the physical layout.
        let scoped = store
            .core
            .enumerate_scopes(orphan.locator())
            .expect("enumerate scopes")
            .into_iter()
            .next()
            .expect("one scope");
        let payload = scoped.payload;
        let metadata = scoped.metadata;
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
            block_on(store.read(read_request(&orphan, "crash-read", &root))),
            Err(BlobError::NotFound)
        ));
    }

    #[test]
    fn memory_cas_compares_and_installs_under_one_provider_boundary() {
        let context: BlobReceiptContext = serde_json::from_str(&context_json(
            "REVERSIBLE_MUTATION",
            "cas-apply",
            "request-cas-apply",
        ))
        .expect("context");
        let lease = lease(&context);
        let target = WorkScopePath::new("tombstones/cas-apply.json").expect("target");
        let bytes = b"replacement";
        let request = BlobCasRequest::new(
            context,
            lease.clone(),
            eliot_blob_api::BlobCasNamespace::Tombstone,
            target.clone(),
            BlobCasState::Missing,
            sha256_hex(bytes),
            bytes.len() as u64,
            1,
            BlobCasDurability::Requested,
        )
        .expect("request");
        let mut platform = MemoryPlatform::default();
        platform.claim_root(&lease).expect("claim");
        assert_eq!(
            platform.cas_capability(),
            BlobCasCapability::AtomicCompareAndReplace
        );
        let applied = platform
            .compare_and_replace_durable(&request, bytes)
            .expect("first CAS");
        assert_eq!(applied.success, BlobCasSuccessKind::Applied);
        assert_eq!(applied.observed, BlobCasState::Missing);
        let replay = platform
            .compare_and_replace_durable(&request, bytes)
            .expect("exact CAS replay");
        assert_eq!(replay, applied);
        assert_eq!(
            platform
                .cas_status(request.context.operation.operation_id.as_str())
                .expect("retained status"),
            Some(applied.clone())
        );
        let mut changed = request.clone();
        changed.replacement_sha256 = sha256_hex(b"changed");
        changed.replacement_length = 7;
        let conflict = platform.compare_and_replace_durable(&changed, b"changed");
        assert!(matches!(
            conflict,
            Err(BlobError::CasFailure { failure })
                if matches!(*failure, BlobCasFailure::IdentityConflict { .. })
        ));
        assert_eq!(platform.read_bounded(&target, 1024).expect("read"), bytes);

        let target_b = WorkScopePath::new("tombstones/cas-apply-other.json").expect("target");
        let step_a_r1 = BlobStoreCore::<
            MemoryPlatform,
            TestCompression,
            TestKeys,
            TestAead,
            TestLiveSets,
        >::tombstone_cas_context(&request.context, "cas-parent", &target, 1)
        .expect("step identity");
        let step_other_target = BlobStoreCore::<
            MemoryPlatform,
            TestCompression,
            TestKeys,
            TestAead,
            TestLiveSets,
        >::tombstone_cas_context(
            &request.context, "cas-parent", &target_b, 1
        )
        .expect("step identity");
        let step_a_r2 = BlobStoreCore::<
            MemoryPlatform,
            TestCompression,
            TestKeys,
            TestAead,
            TestLiveSets,
        >::tombstone_cas_context(&request.context, "cas-parent", &target, 2)
        .expect("step identity");
        assert_ne!(
            step_a_r1.operation.operation_id,
            step_other_target.operation.operation_id
        );
        assert_ne!(
            step_a_r1.operation.operation_id,
            step_a_r2.operation.operation_id
        );
        assert_ne!(
            step_other_target.operation.idempotency_key,
            step_a_r2.operation.idempotency_key
        );
    }

    #[test]
    fn memory_cas_reports_exact_equal_replacement_as_noop() {
        let context: BlobReceiptContext = serde_json::from_str(&context_json(
            "REVERSIBLE_MUTATION",
            "cas-noop",
            "request-cas-noop",
        ))
        .expect("context");
        let lease = lease(&context);
        let target = WorkScopePath::new("tombstones/cas-noop.json").expect("target");
        let bytes = b"same";
        let mut platform = MemoryPlatform::default();
        platform.claim_root(&lease).expect("claim");
        platform.write_new_durable(&target, bytes).expect("seed");
        let request = BlobCasRequest::new(
            context,
            lease,
            eliot_blob_api::BlobCasNamespace::Tombstone,
            target.clone(),
            BlobCasState::Digest(sha256_hex(bytes)),
            sha256_hex(bytes),
            bytes.len() as u64,
            1,
            BlobCasDurability::Requested,
        )
        .expect("request");
        let result = platform
            .compare_and_replace_durable(&request, bytes)
            .expect("no-op CAS");
        assert_eq!(result.success, BlobCasSuccessKind::NoOp);
        assert_eq!(platform.read_bounded(&target, 1024).expect("read"), bytes);
    }

    #[test]
    fn legacy_tombstone_without_cas_context_stops_before_mutation() {
        let error = decode_tombstone(br#"{"operation_id":"legacy"}"#)
            .expect_err("legacy tombstone must not be admitted");
        assert!(matches!(error, BlobError::PlanGap(message) if message.contains("legacy")));
    }

    #[test]
    fn native_storage_full_mapping_keeps_unknown_partial_progress() {
        let io_error = std::io::Error::new(std::io::ErrorKind::StorageFull, "full");
        let error = native_capacity_error(
            &io_error,
            BlobCapacityStage::PayloadWrite,
            BlobCapacityIdentity::Journal {
                operation_id: "op-native".to_owned(),
                idempotency_key: "idem-native".to_owned(),
                locator: None,
            },
            Some(64),
            BlobCapacityEffect::PartialWriteUnknown,
        )
        .expect("StorageFull must classify");
        let BlobError::StorageCapacity { failure } = error else {
            panic!("expected storage capacity");
        };
        assert_eq!(failure.evidence.attempted_bytes, Some(64));
        assert_eq!(
            failure.evidence.effect,
            BlobCapacityEffect::PartialWriteUnknown
        );
        assert_eq!(failure.cleanup, BlobCapacityCleanup::NotApplicable);
    }

    #[test]
    fn stage_journal_capacity_retains_operation_and_attempted_bytes() {
        let root = unique_test_root();
        let platform = MemoryPlatform {
            fail_write: Some(BlobCapacityStage::JournalWrite),
            ..MemoryPlatform::default()
        };
        let error = block_on(store_with_platform(platform, &root).stage(stage_request(
            "journal-full",
            b"payload",
            &root,
        )))
        .expect_err("journal capacity must be surfaced");
        let BlobError::StorageCapacity { failure } = error else {
            panic!("expected typed journal capacity failure");
        };
        assert_eq!(failure.stage, BlobCapacityStage::JournalWrite);
        assert_eq!(
            failure.evidence.effect,
            BlobCapacityEffect::PartialWriteUnknown
        );
        assert!(
            failure
                .evidence
                .attempted_bytes
                .is_some_and(|bytes| bytes > 0)
        );
        assert!(matches!(
            failure.identity,
            BlobCapacityIdentity::Journal { .. }
        ));
    }

    /// Discovery: `MemoryPlatform::rename_no_replace_durable` fails and reports
    /// `PayloadPublication`. That stage names no durability boundary of its own,
    /// so `bind_platform_capacity_with_effect` applies the caller's effect for
    /// this publication leg instead of the port's weaker statement.
    #[test]
    fn publication_failure_without_port_boundary_reports_unconfirmed_durability() {
        let root = unique_test_root();
        let platform = MemoryPlatform {
            fail_rename: true,
            ..MemoryPlatform::default()
        };
        let error = block_on(store_with_platform(platform, &root).stage(stage_request(
            "publication-full",
            b"payload",
            &root,
        )))
        .expect_err("publication capacity must remain uncertain");
        let BlobError::StorageCapacity { failure } = error else {
            panic!("expected typed publication capacity failure");
        };
        // `PayloadPublication` names no durability boundary, so the caller's stage
        // for this leg stands rather than the port's.
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
    }

    /// Discovery: `MemoryPlatform::remove_durable` fails at the cleanup leg, after
    /// the commit marker is already durable. `bind_cleanup_capacity` retains the
    /// port's typed evidence and states the honest row: the removal was observed
    /// and did not report success, so the result is `Failed` with its evidence
    /// attached — not `Unknown`, which would claim nobody observed it at all.
    #[test]
    fn cleanup_capacity_retains_last_durable_phase_and_failed_cleanup() {
        let root = unique_test_root();
        let platform = MemoryPlatform {
            fail_remove: true,
            ..MemoryPlatform::default()
        };
        let error = block_on(store_with_platform(platform, &root).stage(stage_request(
            "cleanup-full",
            b"payload",
            &root,
        )))
        .expect_err("cleanup capacity must remain observable");
        let BlobError::StorageCapacity { failure } = error else {
            panic!("expected typed cleanup capacity failure");
        };
        assert_eq!(failure.stage, BlobCapacityStage::Cleanup);
        assert!(matches!(
            failure.evidence.effect,
            BlobCapacityEffect::PossiblePublication {
                state: PublishState::CommitDurable
            }
        ));
        // Pinned as the whole row, not just the verdict: `Failed` at the `Cleanup`
        // stage, carrying the evidence the port actually reported. `Unknown` would
        // assert that the removal's outcome was unobserved, which this failure did
        // observe.
        assert_eq!(failure.cleanup, BlobCapacityCleanup::Failed);
        assert_eq!(failure.cleanup_stage, Some(BlobCapacityStage::Cleanup));
        let cleanup_evidence = failure
            .cleanup_evidence
            .expect("a failed cleanup must retain the port's typed evidence");
        assert_eq!(
            cleanup_evidence.effect,
            BlobCapacityEffect::PossiblePublication {
                state: PublishState::CommitDurable
            }
        );
        assert_eq!(
            failure.recovery,
            BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
        );
    }

    /// Fresh OS-claim root under the system temp dir. Callers drop the store
    /// and the owner before removing the directory.
    fn unique_owner_root() -> PathBuf {
        let sequence = TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("eliot-t3b-owner-{}-{sequence}", std::process::id()))
    }

    fn owner_test_store(
        owner: &BlobRootOwner,
        lease: BlobRootLease,
    ) -> BlobStoreService<MemoryPlatform, TestCompression, TestKeys, TestAead, TestLiveSets> {
        BlobStoreService::new_with_owner(
            owner,
            lease,
            BlobServicePorts {
                platform: MemoryPlatform::default(),
                compression: TestCompression,
                keys: TestKeys,
                aead: TestAead,
                live_sets: TestLiveSets::default(),
                issuer_anchor: test_anchor(),
            },
        )
        .expect("owner-bound store")
    }

    #[test]
    fn owner_bound_stage_read_roundtrip() {
        let dir = unique_owner_root();
        let root = dir.to_string_lossy().into_owned();
        let owner =
            BlobRootOwner::claim(root.clone(), "t3b-owner", std::process::id()).expect("claim");
        let lease = stage_request("owner-bootstrap", b"", &root).root_lease;
        let store = owner_test_store(&owner, lease);
        let ready =
            block_on(store.stage(stage_request("owner-roundtrip", b"owner-payload", &root)))
                .expect("stage");
        assert_eq!(ready.plaintext_length(), 13);
        let chunk = block_on(store.read(read_request(&ready, "owner-read", &root))).expect("read");
        assert_eq!(chunk.bytes(), b"owner-payload");
        assert_eq!(chunk.anchor_fingerprint(), test_anchor().fingerprint());
        assert!(block_on(store.health()).expect("health").ready);
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(&dir).expect("cleanup owner root");
    }

    #[test]
    fn second_service_owner_on_same_root_is_rejected() {
        let root = unique_test_root();
        let first_lease = stage_request("bootstrap-first", b"", &root).root_lease;
        let _first = BlobStoreService::new(
            first_lease,
            MemoryPlatform::default(),
            TestCompression,
            TestKeys,
            TestAead,
            TestLiveSets::default(),
            test_anchor(),
        )
        .expect("first service");
        // A second service on the same live root is a second owner.
        let second_lease = stage_request("bootstrap-second", b"", &root).root_lease;
        assert_eq!(
            BlobStoreService::new(
                second_lease,
                MemoryPlatform::default(),
                TestCompression,
                TestKeys,
                TestAead,
                TestLiveSets::default(),
                test_anchor(),
            )
            .map(|_| ()),
            Err(BlobError::OwnerConflict)
        );
        // So is an OS claim on a service-held root — rejected before any
        // filesystem work by the same unified registry.
        assert_eq!(
            BlobRootOwner::claim(root.clone(), "t3b-owner-late", std::process::id()).map(|_| ()),
            Err(BlobError::OwnerConflict)
        );
    }

    #[test]
    fn owner_reserved_root_rejects_ownerless_service_but_admits_bound_service() {
        let dir = unique_owner_root();
        let root = dir.to_string_lossy().into_owned();
        let owner =
            BlobRootOwner::claim(root.clone(), "t3b-owner", std::process::id()).expect("claim");
        // A root reserved by the OS claim can never admit an ownerless
        // service as a second owner.
        let probe = stage_request("bootstrap-probe", b"", &root).root_lease;
        assert_eq!(
            BlobStoreService::new(
                probe,
                MemoryPlatform::default(),
                TestCompression,
                TestKeys,
                TestAead,
                TestLiveSets::default(),
                test_anchor(),
            )
            .map(|_| ()),
            Err(BlobError::OwnerConflict)
        );
        // The bound service presenting the reserver is admitted exactly once.
        let bound_lease = stage_request("bootstrap-bound", b"", &root).root_lease;
        let bound = owner_test_store(&owner, bound_lease);
        let again_lease = stage_request("bootstrap-again", b"", &root).root_lease;
        assert_eq!(
            BlobStoreService::new_with_owner(
                &owner,
                again_lease,
                BlobServicePorts {
                    platform: MemoryPlatform::default(),
                    compression: TestCompression,
                    keys: TestKeys,
                    aead: TestAead,
                    live_sets: TestLiveSets::default(),
                    issuer_anchor: test_anchor(),
                },
            )
            .map(|_| ()),
            Err(BlobError::OwnerConflict)
        );
        // A lease for a different root never binds to this owner.
        let foreign_root = unique_test_root();
        let foreign_lease = stage_request("bootstrap-foreign", b"", &foreign_root).root_lease;
        assert_eq!(
            BlobStoreService::new_with_owner(
                &owner,
                foreign_lease,
                BlobServicePorts {
                    platform: MemoryPlatform::default(),
                    compression: TestCompression,
                    keys: TestKeys,
                    aead: TestAead,
                    live_sets: TestLiveSets::default(),
                    issuer_anchor: test_anchor(),
                },
            )
            .map(|_| ()),
            Err(BlobError::OwnerConflict)
        );
        // A second OS claim on the owner-held root is rejected as well.
        assert_eq!(
            BlobRootOwner::claim(root.clone(), "t3b-owner-second", std::process::id()).map(|_| ()),
            Err(BlobError::OwnerConflict)
        );
        drop(bound);
        drop(owner);
        std::fs::remove_dir_all(&dir).expect("cleanup owner root");
    }

    #[test]
    fn same_bytes_in_different_residency_domains_never_share_an_object() {
        let root = unique_test_root();
        let store = gc_store(TestGcMode::NotApplied, false, &root);
        let bytes = b"shared-bytes-across-domains";
        // s-04-v2: residency is caller-supplied contract identity. Same bytes
        // under the same policy but different scope domains are different
        // locators and different physical objects by construction.
        let first = block_on(store.stage(stage_request_with_scope(
            "xdom-a",
            bytes,
            &root,
            "policy-xdom",
            "scope-a",
        )))
        .expect("domain a");
        let second = block_on(store.stage(stage_request_with_scope(
            "xdom-b",
            bytes,
            &root,
            "policy-xdom",
            "scope-b",
        )))
        .expect("domain b");
        assert_ne!(first.locator(), second.locator());
        assert_ne!(
            first.locator().residency_key_digest(),
            second.locator().residency_key_digest()
        );
        assert_ne!(first.metadata_sha256(), second.metadata_sha256());
        // One physical scope per locator at distinct placements — never one
        // shared object.
        for ready in [&first, &second] {
            let scopes = store
                .core
                .enumerate_scopes(ready.locator())
                .expect("enumerate scopes");
            assert_eq!(scopes.len(), 1);
        }
        let scopes_a = store
            .core
            .enumerate_scopes(first.locator())
            .expect("enumerate a");
        let scopes_b = store
            .core
            .enumerate_scopes(second.locator())
            .expect("enumerate b");
        assert_ne!(
            scopes_a[0].payload.normalized_identity(),
            scopes_b[0].payload.normalized_identity()
        );
        assert_ne!(
            scopes_a[0].metadata.normalized_identity(),
            scopes_b[0].metadata.normalized_identity()
        );
        // Both domains read back their exact bytes under their own receipts.
        let chunk_a =
            block_on(store.read(read_request(&first, "xdom-read-a", &root))).expect("read a");
        let chunk_b =
            block_on(store.read(read_request(&second, "xdom-read-b", &root))).expect("read b");
        assert_eq!(chunk_a.bytes(), bytes);
        assert_eq!(chunk_b.bytes(), bytes);
        // GC collects both scopes independently through both locators.
        let receipt = block_on(store.gc(gc_request(
            Vec::new(),
            vec![first.locator().clone(), second.locator().clone()],
            &root,
        )))
        .expect("gc both scopes");
        assert!(receipt.deleted().contains(first.locator()));
        assert!(receipt.deleted().contains(second.locator()));
        assert!(matches!(
            block_on(store.read(read_request(&first, "xdom-read-a2", &root))),
            Err(BlobError::NotFound)
        ));
        assert!(matches!(
            block_on(store.read(read_request(&second, "xdom-read-b2", &root))),
            Err(BlobError::NotFound)
        ));
    }

    #[test]
    fn partial_live_set_blocks_gc_before_any_effect() {
        let root = unique_test_root();
        let store = gc_store(TestGcMode::NotApplied, false, &root);
        let orphan = block_on(store.stage(stage_request("partial-orphan", b"payload", &root)))
            .expect("orphan");
        let mut request = gc_request(Vec::new(), vec![orphan.locator().clone()], &root);
        request.live_set.completeness = LiveSetCompleteness::Partial;
        assert_eq!(
            block_on(store.gc(request)),
            Err(BlobError::IncompleteLiveSet)
        );
        // Blocked before any tombstone effect; the object still reads.
        let tombstones = WorkScopePath::new("tombstones").expect("tombstones");
        let listed = store
            .core
            .platform
            .read()
            .expect("platform lock")
            .list(&tombstones)
            .expect("tombstone list");
        assert!(listed.is_empty());
        assert!(block_on(store.read(read_request(&orphan, "partial-read", &root))).is_ok());
    }

    #[test]
    fn coherent_reachability_reports_scopes_and_rejects_stale_sources() {
        let root = unique_test_root();
        let store = gc_store(TestGcMode::NotApplied, false, &root);
        let live =
            block_on(store.stage(stage_request("reach-live", b"live", &root))).expect("live");
        let view =
            block_on(store.reachability(reachability_request(vec![live.locator().clone()], &root)))
                .expect("reachability view");
        assert!(view.present.contains(live.locator()));
        assert!(view.missing.is_empty());
        // A locator with no stored scope reports missing without failing.
        let absent = BlobLocator {
            hash: BlobHash::new("b".repeat(64)).expect("hash"),
            residency: ObjectResidencyKey {
                scope_domain_id: BlobId::new("scope-absent").expect("scope domain"),
                access_domain_id: BlobId::new("access-absent").expect("access domain"),
                confidentiality_domain_id: BlobId::new("conf-absent").expect("conf domain"),
                encryption_key_domain_id: BlobId::new("test-lineage").expect("key domain"),
                retention_domain_id: BlobId::new("retention-absent").expect("retention domain"),
                erasure_domain_id: BlobId::new("erasure-absent").expect("erasure domain"),
                content_digest: VersionedContentDigest {
                    algorithm: BlobId::new("blake3").expect("algorithm"),
                    version: 1,
                    digest: BlobHash::new("b".repeat(64)).expect("hash"),
                },
            },
            root_generation: 7,
            path_generation: 1,
        };
        let absent_view =
            block_on(store.reachability(reachability_request(vec![absent.clone()], &root)))
                .expect("absent view");
        assert!(absent_view.missing.contains(&absent));
        assert!(absent_view.present.is_empty());
        // A stale live-set source blocks the view instead of reporting
        // reachability against a superseded union.
        let stale_root = unique_test_root();
        let stale_store = gc_store(TestGcMode::NotApplied, true, &stale_root);
        let staged =
            block_on(stale_store.stage(stage_request("reach-stale", b"stale", &stale_root)))
                .expect("staged");
        assert_eq!(
            block_on(stale_store.reachability(reachability_request(
                vec![staged.locator().clone()],
                &stale_root,
            ))),
            Err(BlobError::IncompleteLiveSet)
        );
    }
}
