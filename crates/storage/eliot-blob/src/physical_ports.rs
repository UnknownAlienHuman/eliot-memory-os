//! Production filesystem and compression providers for the S-04 Blob owner.
//!
//! The Windows file store owns physical path effects; this module binds them
//! to the live `BlobRootOwner` lease and the Blob service's existing typed
//! receipts. Zstandard is a real versioned codec with bounded streaming decode.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_blob_api::{
    BlobCasCapability, BlobCasDurability, BlobCasFailure, BlobCasRequest, BlobCasState,
    BlobCasSuccessKind, BlobError, BlobId, BlobIssuerTrustAnchor, BlobRootLease,
    CompressionDescriptor,
};
use eliot_platform::WorkScopePath;
use eliot_platform_windows::blob_file_store::{BlobFilePathState, BlobFileStore, BlobFileStoreError};

use crate::{
    BlobCasProviderResult, BlobCompressionPort, BlobPathState, BlobPlatformPort, BlobRootOwner,
    RootClaimProof,
};

const ZSTD_ALGORITHM: &str = "zstd";
const ZSTD_VERSION: u32 = 1;

/// Real Zstandard compression provider with a bounded streaming decoder.
#[derive(Clone, Copy, Debug)]
pub struct ZstdBlobCompression {
    level: i32,
}

impl Default for ZstdBlobCompression {
    fn default() -> Self {
        Self { level: 3 }
    }
}

impl ZstdBlobCompression {
    /// Selects the standard production compression level.
    #[must_use]
    pub const fn new(level: i32) -> Self {
        Self { level }
    }
}

impl BlobCompressionPort for ZstdBlobCompression {
    fn descriptor(&mut self) -> Result<CompressionDescriptor, BlobError> {
        Ok(CompressionDescriptor {
            algorithm: BlobId::new(ZSTD_ALGORITHM)?,
            version: ZSTD_VERSION,
        })
    }

    fn compress(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, BlobError> {
        if plaintext.len() as u64 > crate::MAX_BLOB_PLAINTEXT_BYTES {
            return Err(BlobError::InvalidContract(
                "Blob plaintext exceeds the canonical compression bound".to_owned(),
            ));
        }
        let limit = usize::try_from(crate::MAX_BLOB_ENVELOPE_BYTES).unwrap_or(usize::MAX);
        let writer = BoundedCodecOutput {
            bytes: Vec::new(),
            limit,
        };
        let mut encoder = zstd::stream::write::Encoder::new(writer, self.level)
            .map_err(|error| BlobError::Provider(format!("Zstandard encoder refused: {error}")))?;
        encoder
            .write_all(plaintext)
            .map_err(|error| BlobError::Provider(format!("Zstandard compression failed: {error}")))?;
        let output = encoder
            .finish()
            .map_err(|error| BlobError::Provider(format!("Zstandard finalization failed: {error}")))?;
        Ok(output.bytes)
    }

    fn decompress_bounded(
        &self,
        descriptor: &CompressionDescriptor,
        compressed: &[u8],
        max_output_bytes: u64,
    ) -> Result<Vec<u8>, BlobError> {
        descriptor.validate()?;
        if descriptor.algorithm.as_str() != ZSTD_ALGORITHM
            || descriptor.version != ZSTD_VERSION
        {
            return Err(BlobError::ProviderUnavailable(
                "zstd-v1 compression profile",
            ));
        }
        if compressed.len() as u64 > crate::MAX_BLOB_ENVELOPE_BYTES
            || max_output_bytes > crate::MAX_BLOB_PLAINTEXT_BYTES
        {
            return Err(BlobError::InvalidContract(
                "Zstandard input or output exceeds the canonical Blob bound".to_owned(),
            ));
        }
        let read_limit = max_output_bytes
            .checked_add(1)
            .ok_or(BlobError::InvalidField {
                field: "compression.max_output_bytes",
                reason: "bounded decode limit overflows",
            })?;
        let decoder = zstd::stream::read::Decoder::new(Cursor::new(compressed))
            .map_err(|error| BlobError::Provider(format!("Zstandard decoder refused: {error}")))?;
        let mut output = Vec::new();
        decoder
            .take(read_limit)
            .read_to_end(&mut output)
            .map_err(|error| BlobError::Provider(format!("Zstandard decode failed: {error}")))?;
        if output.len() as u64 > max_output_bytes {
            return Err(BlobError::InvalidContract(
                "decompressed Blob payload exceeds its declared bound".to_owned(),
            ));
        }
        Ok(output)
    }
}

struct BoundedCodecOutput {
    bytes: Vec<u8>,
    limit: usize,
}

impl std::io::Write for BoundedCodecOutput {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "compressed Blob output exceeds its bound",
            ));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Blob platform bound to one retained OS root owner.
///
/// Mutable journal CAS is serialized by the Blob core's exclusive platform
/// guard while this adapter is borrowed mutably. The retained `BlobRootOwner`
/// excludes another production service process from the same root; the
/// compare and install therefore remain under one stable owner boundary.
pub struct WindowsBlobPlatform {
    owner: BlobRootOwner,
    files: BlobFileStore,
    claimed_lease: Option<BlobRootLease>,
    backend_generation: u64,
    cas_statuses: Mutex<BTreeMap<String, (String, BlobCasProviderResult)>>,
}

impl std::fmt::Debug for WindowsBlobPlatform {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsBlobPlatform")
            .field("root_identity", &self.files.root_identity())
            .field("backend_generation", &self.backend_generation)
            .field("claimed", &self.claimed_lease.is_some())
            .finish_non_exhaustive()
    }
}

impl WindowsBlobPlatform {
    /// Retains the original OS owner claim and pins the same canonical root.
    pub fn new(owner: BlobRootOwner) -> Result<Self, BlobError> {
        if owner.heartbeat_failure().is_some() {
            return Err(BlobError::OwnerConflict);
        }
        let root = PathBuf::from(owner.root_id());
        let files = BlobFileStore::new(root).map_err(map_file_error)?;
        files.validate_root().map_err(map_file_error)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BlobError::Provider("system clock is before Unix epoch".to_owned()))?
            .as_nanos();
        let now = u64::try_from(now).map_err(|_| {
            BlobError::Provider("physical Blob provider generation could not be established".to_owned())
        })?;
        let sequence = PHYSICAL_PROVIDER_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let backend_generation = now
            ^ (u64::from(owner.process_id()) << 32)
            ^ sequence;
        if backend_generation == 0 {
            return Err(BlobError::Provider(
                "physical Blob provider generation could not be established".to_owned(),
            ));
        }
        Ok(Self {
            owner,
            files,
            claimed_lease: None,
            backend_generation,
            cas_statuses: Mutex::new(BTreeMap::new()),
        })
    }

    /// Loads the receipt issuer anchor from the DPAPI-protected key owned by
    /// this exact Store Blob-root claim. The anchor is not globally trusted by
    /// construction; downstream owners still pin and compare its fingerprint.
    pub fn receipt_issuer_anchor(&self) -> Result<BlobIssuerTrustAnchor, BlobError> {
        if self.owner.heartbeat_failure().is_some() {
            return Err(BlobError::OwnerConflict);
        }
        let key = self
            .files
            .load_or_create_receipt_issuer_key(self.owner.owner_id().as_str())
            .map_err(map_file_error)?;
        BlobIssuerTrustAnchor::new(
            format!("store-blob-receipt-issuer:{}", self.owner.owner_id()),
            "dpapi-user-store-blob-receipt-key-v1",
            key.expose().to_vec(),
        )
    }

    fn validate_lease(&self, lease: &BlobRootLease) -> Result<(), BlobError> {
        lease.validate()?;
        if self.owner.heartbeat_failure().is_some()
            || !self.owner.owns_service_root(lease.root_id.as_str())
            || lease.owner_id != *self.owner.owner_id()
        {
            return Err(BlobError::OwnerConflict);
        }
        self.files.validate_root().map_err(map_file_error)
    }

    fn require_claim(&self) -> Result<&BlobRootLease, BlobError> {
        let lease = self.claimed_lease.as_ref().ok_or(BlobError::OwnerConflict)?;
        self.validate_lease(lease)?;
        Ok(lease)
    }

    fn probe_permission_proof(&self) -> Result<(), BlobError> {
        self.files.prove_root_permissions().map_err(map_file_error)
    }

    fn previous_cas_result(
        &self,
        request: &BlobCasRequest,
        operation_id: &str,
        commitment: &str,
    ) -> Result<Option<BlobCasProviderResult>, BlobError> {
        let previous = self
            .cas_statuses
            .lock()
            .map_err(|_| BlobError::Provider("Blob CAS status lock poisoned".to_owned()))?
            .get(operation_id)
            .cloned();
        let Some((previous_commitment, previous_result)) = previous else {
            return Ok(None);
        };
        if previous_commitment.as_str() != commitment {
            return Err(BlobError::CasFailure {
                failure: Box::new(BlobCasFailure::IdentityConflict {
                    request: Box::new(request.clone()),
                }),
            });
        }
        Ok(Some(previous_result))
    }
}

static PHYSICAL_PROVIDER_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

impl BlobPlatformPort for WindowsBlobPlatform {
    fn claim_root(&mut self, lease: &BlobRootLease) -> Result<RootClaimProof, BlobError> {
        self.validate_lease(lease)?;
        if self.claimed_lease.as_ref().is_some_and(|claimed| claimed != lease) {
            return Err(BlobError::OwnerConflict);
        }
        self.probe_permission_proof()?;
        self.claimed_lease = Some(lease.clone());
        Ok(RootClaimProof {
            root_id: lease.root_id.as_str().to_owned(),
            owner_id: lease.owner_id.to_string(),
            lease_id: lease.lease_id.to_string(),
            root_generation: lease.root_generation,
            containment_proven: true,
            permissions_proven: true,
        })
    }

    fn inspect_root(&self, lease: &BlobRootLease) -> Result<RootClaimProof, BlobError> {
        self.validate_lease(lease)?;
        if self.claimed_lease.as_ref() != Some(lease) {
            return Err(BlobError::OwnerConflict);
        }
        self.probe_permission_proof()?;
        Ok(RootClaimProof {
            root_id: lease.root_id.as_str().to_owned(),
            owner_id: lease.owner_id.to_string(),
            lease_id: lease.lease_id.to_string(),
            root_generation: lease.root_generation,
            containment_proven: true,
            permissions_proven: true,
        })
    }

    fn prove_contained(&self, lease: &BlobRootLease, path: &WorkScopePath) -> Result<(), BlobError> {
        self.validate_lease(lease)?;
        if self.claimed_lease.as_ref() != Some(lease) {
            return Err(BlobError::OwnerConflict);
        }
        self.files.prove_contained(path).map_err(map_file_error)
    }

    fn read_bounded(&self, path: &WorkScopePath, max_bytes: u64) -> Result<Vec<u8>, BlobError> {
        self.require_claim()?;
        self.files.read_bounded(path, max_bytes).map_err(map_file_error)
    }

    fn write_new_durable(&mut self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
        self.require_claim()?;
        self.files.create_new_durable(path, bytes).map_err(map_file_error)
    }

    fn replace_durable(&mut self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
        self.require_claim()?;
        self.files.replace_durable(path, bytes).map_err(map_file_error)
    }

    fn cas_capability(&self) -> BlobCasCapability {
        BlobCasCapability::AtomicCompareAndReplace
    }

    fn compare_and_replace_durable(
        &mut self,
        request: &BlobCasRequest,
        bytes: &[u8],
    ) -> Result<BlobCasProviderResult, BlobError> {
        request.validate()?;
        self.validate_lease(&request.root_lease)?;
        if self.claimed_lease.as_ref() != Some(&request.root_lease) {
            return Err(BlobError::OwnerConflict);
        }
        if request.expected_backend_generation != self.backend_generation {
            return Err(BlobError::StaleFence);
        }
        if bytes.len() as u64 != request.replacement_length
            || crate::sha256_hex(bytes) != request.replacement_sha256
        {
            return Err(BlobError::CasFailure {
                failure: Box::new(BlobCasFailure::Internal {
                    request: Box::new(request.clone()),
                    reason: eliot_blob_api::BlobCasInternalReason::CommitmentMismatch,
                }),
            });
        }
        let operation_id = request.context.operation.operation_id.as_str().to_owned();
        let commitment = request.request_commitment_sha256()?;
        if let Some(previous_result) =
            self.previous_cas_result(request, &operation_id, &commitment)?
        {
            return Ok(previous_result);
        }
        let observed_bytes = match self
            .files
            .read_bounded_with_identity(&request.target, 64 * 1024)
        {
            Ok(observed) => Some(observed),
            Err(BlobFileStoreError::NotFound) => None,
            Err(error) => return Err(map_file_error(error)),
        };
        let observed = observed_bytes
            .as_ref()
            .map_or(BlobCasState::Missing, |(current, _)| {
                BlobCasState::Digest(crate::sha256_hex(current))
            });
        if observed != request.expected {
            return Err(BlobError::CasFailure {
                failure: Box::new(BlobCasFailure::ExpectedStateConflict {
                    request: Box::new(request.clone()),
                    observed,
                }),
            });
        }
        let success = if request.expected.sha256() == Some(request.replacement_sha256.as_str()) {
            BlobCasSuccessKind::NoOp
        } else {
            match observed_bytes {
                Some((_, observed_identity)) => {
                    let expected_sha256 = request.expected.sha256().ok_or_else(|| {
                        BlobError::CasFailure {
                            failure: Box::new(BlobCasFailure::Internal {
                                request: Box::new(request.clone()),
                                reason: eliot_blob_api::BlobCasInternalReason::InvalidRequest,
                            }),
                        }
                    })?;
                    match self.files.replace_durable_if_matches(
                        &request.target,
                        observed_identity,
                        expected_sha256,
                        bytes,
                    ) {
                        Ok(()) => Ok(()),
                        Err(BlobFileStoreError::PreconditionFailed) => {
                            Err(BlobError::CasFailure {
                                failure: Box::new(BlobCasFailure::ExpectedStateConflict {
                                    request: Box::new(request.clone()),
                                    observed: observed.clone(),
                                }),
                            })
                        }
                        Err(error) => Err(map_file_error(error)),
                    }
                }
                None => self
                    .files
                    .create_new_durable(&request.target, bytes)
                    .map_err(map_file_error),
            }
            ?;
            BlobCasSuccessKind::Applied
        };
        let result = BlobCasProviderResult {
            operation_id: operation_id.clone(),
            request_commitment_sha256: commitment.clone(),
            observed: request.expected.clone(),
            replacement_sha256: request.replacement_sha256.clone(),
            replacement_length: request.replacement_length,
            backend_generation: self.backend_generation,
            observed_durability: BlobCasDurability::Confirmed,
            success,
        };
        self.cas_statuses
            .lock()
            .map_err(|_| BlobError::Provider("Blob CAS status lock poisoned".to_owned()))?
            .insert(operation_id, (commitment, result.clone()));
        Ok(result)
    }

    fn cas_status(&self, operation_id: &str) -> Result<Option<BlobCasProviderResult>, BlobError> {
        self.require_claim()?;
        Ok(self
            .cas_statuses
            .lock()
            .map_err(|_| BlobError::Provider("Blob CAS status lock poisoned".to_owned()))?
            .get(operation_id)
            .map(|(_, result)| result.clone()))
    }

    fn backend_generation(&self) -> Result<u64, BlobError> {
        self.require_claim()?;
        Ok(self.backend_generation)
    }

    fn rename_no_replace_durable(
        &mut self,
        source: &WorkScopePath,
        destination: &WorkScopePath,
    ) -> Result<(), BlobError> {
        self.require_claim()?;
        self.files
            .rename_no_replace_durable(source, destination)
            .map_err(map_file_error)
    }

    fn remove_durable(&mut self, path: &WorkScopePath) -> Result<(), BlobError> {
        self.require_claim()?;
        self.files.remove_durable(path).map_err(map_file_error)
    }

    fn stat(&self, path: &WorkScopePath) -> Result<BlobPathState, BlobError> {
        self.require_claim()?;
        self.files.stat(path).map(map_path_state).map_err(map_file_error)
    }

    fn list(&self, prefix: &WorkScopePath) -> Result<Vec<WorkScopePath>, BlobError> {
        self.require_claim()?;
        self.files.list(prefix).map_err(map_file_error)
    }

    fn now_unix_ms(&mut self) -> Result<u64, BlobError> {
        self.require_claim()?;
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
            .map_err(|_| BlobError::Provider("system clock is before Unix epoch".to_owned()))
    }
}

fn map_path_state(state: BlobFilePathState) -> BlobPathState {
    match state {
        BlobFilePathState::Missing => BlobPathState::Missing,
        BlobFilePathState::File {
            length,
            modified_unix_ms,
        } => BlobPathState::File {
            length,
            modified_unix_ms,
        },
        BlobFilePathState::Directory => BlobPathState::Directory,
        BlobFilePathState::ReparsePoint => BlobPathState::ReparsePoint,
        BlobFilePathState::Other => BlobPathState::Other,
    }
}

fn map_file_error(error: BlobFileStoreError) -> BlobError {
    match error {
        BlobFileStoreError::NotFound => BlobError::NotFound,
        BlobFileStoreError::AlreadyExists => BlobError::IdempotencyConflict,
        BlobFileStoreError::UnsupportedPlatform => BlobError::ProviderUnavailable(
            "Windows reparse-safe Blob filesystem provider",
        ),
        BlobFileStoreError::Platform(source) => BlobError::Provider(source.to_string()),
        BlobFileStoreError::InvalidPath | BlobFileStoreError::ReparsePoint => {
            BlobError::InvalidContract(error.to_string())
        }
        BlobFileStoreError::PreconditionFailed => BlobError::Provider(
            "Blob compare-and-replace precondition changed before installation".to_owned(),
        ),
        BlobFileStoreError::UnknownPublication => BlobError::Provider(
            "Blob atomic replacement outcome is unknown; reconcile the original operation"
                .to_owned(),
        ),
        BlobFileStoreError::Io(reason) => BlobError::Provider(reason),
    }
}
