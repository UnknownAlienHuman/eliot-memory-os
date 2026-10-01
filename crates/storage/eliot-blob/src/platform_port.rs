//! Production BlobPlatformPort over the retained-root Windows filesystem
//! primitives. The OS root lease is held by `BlobRootOwner`; CAS comparison
//! and install are serialized under that single-owner boundary and a local
//! mutex. Every operation record is persisted before and after its possible
//! effect so a crash in the middle remains `Unknown` on restart.

use std::collections::BTreeMap;
use std::sync::Mutex;

use eliot_blob_api::{
    BlobCapacityCause, BlobCapacityCleanup, BlobCapacityEffect, BlobCapacityEvidence,
    BlobCapacityFailure, BlobCapacityIdentity, BlobCapacityRecovery, BlobCapacityStage,
    BlobCasCapability, BlobCasDurability, BlobCasFailure, BlobCasProviderResult, BlobCasRequest,
    BlobCasState, BlobCasSuccessKind, BlobError, BlobIssuerTrustAnchor, BlobRootLease,
};
use eliot_platform::{PortError, ProviderErrorCode, WorkScopePath};
use eliot_platform_windows::{
    WindowsBlobPathState, WindowsBlobPublicationReconciliation, WindowsBlobStorePlatform,
};
use serde::{Deserialize, Serialize};

use crate::{
    BlobPathState, BlobPlatformPort, BlobPublicationReconciliation, RootClaimProof, cas_unknown,
    sha256_hex,
};

const CAS_STATUS_DIR: &str = ".eliot-cas-status";
const CAS_STATUS_MAX_BYTES: u64 = 16 * 1024;
const CAS_NAMESPACE_MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CasStatusRecord {
    version: u32,
    operation_id: String,
    request_commitment_sha256: String,
    result: Option<BlobCasProviderResult>,
}

/// Real filesystem implementation for the single Store-owned Blob root.
pub struct WindowsBlobPlatformPort {
    filesystem: WindowsBlobStorePlatform,
    root_identity: String,
    root_claim: Mutex<Option<RootClaimProof>>,
    active_lease: Mutex<Option<BlobRootLease>>,
    cas_serialization: Mutex<()>,
    backend_generation: u64,
    /// Bounded same-process cache; durable operation records remain the source
    /// of truth after restart.
    cas_statuses: Mutex<BTreeMap<String, CasStatusRecord>>,
}

impl std::fmt::Debug for WindowsBlobPlatformPort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsBlobPlatformPort")
            .field("root_identity", &"[REDACTED]")
            .field("backend_generation", &self.backend_generation)
            .finish_non_exhaustive()
    }
}

impl WindowsBlobPlatformPort {
    /// Binds the concrete no-follow durable filesystem surface to one root.
    pub fn new(root: impl Into<std::path::PathBuf>) -> Result<Self, BlobError> {
        let filesystem = WindowsBlobStorePlatform::new(root)
            .map_err(|error| BlobError::Provider(format!("bind Blob root: {error}")))?;
        let root_identity = filesystem
            .root_identity()
            .map_err(|error| BlobError::Provider(format!("identify Blob root: {error}")))?;
        let backend_generation = filesystem.root_generation().map_err(|error| {
            BlobError::Provider(format!("identify Blob root generation: {error}"))
        })?;
        Ok(Self {
            filesystem,
            root_identity,
            root_claim: Mutex::new(None),
            active_lease: Mutex::new(None),
            cas_serialization: Mutex::new(()),
            backend_generation,
            cas_statuses: Mutex::new(BTreeMap::new()),
        })
    }

    /// Loads the root's stable receipt-issuer anchor or creates it exactly
    /// once from Windows CSPRNG output protected by current-user DPAPI. A
    /// corrupt/partial key is never replaced because doing so would make
    /// previously issued receipts unverifiable.
    pub fn load_or_create_issuer_anchor(&self) -> Result<BlobIssuerTrustAnchor, BlobError> {
        let path = WorkScopePath::new(".eliot-blob-issuer.dpapi")
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        let secret = match self.filesystem.stat(&path) {
            Ok(WindowsBlobPathState::Missing) => {
                let generated = self.filesystem.random_secret_bytes(32).map_err(|_| {
                    BlobError::Provider("Windows Blob issuer entropy unavailable".to_owned())
                })?;
                let protected = self
                    .filesystem
                    .protect_secret_bytes(&generated)
                    .map_err(|_| {
                        BlobError::Provider("DPAPI could not protect Blob issuer key".to_owned())
                    })?;
                self.filesystem
                    .write_new_durable(&path, &protected)
                    .map_err(|_| {
                        BlobError::Provider("durable Blob issuer key creation failed".to_owned())
                    })?;
                let persisted = self
                    .filesystem
                    .read_bounded(&path, 16 * 1024)
                    .map_err(|_| {
                        BlobError::Provider("Blob issuer key readback failed".to_owned())
                    })?;
                if persisted != protected {
                    return Err(BlobError::IntegrityMismatch);
                }
                let unprotected =
                    self.filesystem
                        .unprotect_secret_bytes(&persisted)
                        .map_err(|_| {
                            BlobError::Provider("DPAPI could not verify Blob issuer key".to_owned())
                        })?;
                if unprotected != generated {
                    return Err(BlobError::IntegrityMismatch);
                }
                unprotected
            }
            Ok(WindowsBlobPathState::File { .. }) => {
                let protected = self
                    .filesystem
                    .read_bounded(&path, 16 * 1024)
                    .map_err(|_| BlobError::Provider("Blob issuer key read failed".to_owned()))?;
                self.filesystem
                    .unprotect_secret_bytes(&protected)
                    .map_err(|_| {
                        BlobError::Provider("DPAPI could not open Blob issuer key".to_owned())
                    })?
            }
            Ok(_) => {
                return Err(BlobError::InvalidContract(
                    "Blob issuer key path is not a regular file".to_owned(),
                ));
            }
            Err(_) => {
                return Err(BlobError::Provider(
                    "Blob issuer key state unavailable".to_owned(),
                ));
            }
        };
        if secret.len() < 32 {
            return Err(BlobError::IntegrityMismatch);
        }
        let key_id = format!(
            "s04-issuer-{}",
            &sha256_hex(self.root_identity.as_bytes())[..16]
        );
        BlobIssuerTrustAnchor::new("eliot-s04-store", key_id, secret)
    }

    fn require_root(&self, lease: &BlobRootLease) -> Result<(), BlobError> {
        lease.validate()?;
        if lease.root_id.as_str() != self.root_identity {
            return Err(BlobError::OwnerConflict);
        }
        let claim = self
            .root_claim
            .lock()
            .map_err(|_| BlobError::Provider("Blob platform claim lock poisoned".to_owned()))?;
        let Some(claim) = claim.as_ref() else {
            return Err(BlobError::OwnerConflict);
        };
        if claim.root_id != lease.root_id.as_str()
            || claim.owner_id != lease.owner_id.as_str()
            || claim.lease_id != lease.lease_id.as_str()
            || claim.root_generation != lease.root_generation
        {
            return Err(BlobError::OwnerConflict);
        }
        let active = self
            .active_lease
            .lock()
            .map_err(|_| BlobError::Provider("Blob active lease lock poisoned".to_owned()))?;
        let is_active_fence = active.as_ref().is_some_and(|current| {
            current.root_id == lease.root_id
                && current.owner_id == lease.owner_id
                && current.lease_id == lease.lease_id
                && current.root_generation == lease.root_generation
                && current.fence_binding.state_fence == lease.fence_binding.state_fence
        });
        if !is_active_fence {
            return Err(BlobError::StaleFence);
        }
        Ok(())
    }

    fn cas_record_path(operation_id: &str) -> Result<WorkScopePath, BlobError> {
        WorkScopePath::new(format!(
            "{CAS_STATUS_DIR}/{}.json",
            sha256_hex(operation_id.as_bytes())
        ))
        .map_err(|error| BlobError::InvalidContract(error.to_string()))
    }

    fn read_cas_record(&self, operation_id: &str) -> Result<Option<CasStatusRecord>, BlobError> {
        let path = Self::cas_record_path(operation_id)?;
        let bytes = match self.filesystem.read_bounded(&path, CAS_STATUS_MAX_BYTES) {
            Ok(bytes) => bytes,
            Err(eliot_platform::PortError::Provider(error))
                if error.code == eliot_platform::ProviderErrorCode::Failed =>
            {
                // The Windows adapter maps an absent file to the provider's
                // stable not-found class; inspect metadata to distinguish it.
                if self.filesystem.stat(&path).ok() == Some(WindowsBlobPathState::Missing) {
                    return Ok(None);
                }
                return Err(BlobError::Provider(
                    "read Blob CAS status failed".to_owned(),
                ));
            }
            Err(error) => return Err(BlobError::Provider(error.to_string())),
        };
        let record: CasStatusRecord =
            serde_json::from_slice(&bytes).map_err(|_| BlobError::IntegrityMismatch)?;
        if record.version != 1 || record.operation_id != operation_id {
            return Err(BlobError::IntegrityMismatch);
        }
        Ok(Some(record))
    }

    fn write_cas_record(&self, record: &CasStatusRecord, create: bool) -> Result<(), PortError> {
        let bytes = serde_json::to_vec(record).map_err(|_| PortError::InvalidPath)?;
        let path =
            Self::cas_record_path(&record.operation_id).map_err(|_| PortError::InvalidPath)?;
        if create {
            self.filesystem.write_new_durable(&path, &bytes)
        } else {
            self.filesystem.replace_durable(&path, &bytes)
        }
    }

    fn cas_journal_capacity(
        request: &BlobCasRequest,
        error: &PortError,
        effect: BlobCapacityEffect,
        observed: Option<BlobCasState>,
    ) -> Option<BlobError> {
        if !matches!(error, PortError::Provider(provider) if provider.code == ProviderErrorCode::StorageFull)
        {
            return None;
        }
        Some(BlobError::StorageCapacity {
            failure: Box::new(BlobCapacityFailure {
                identity: BlobCapacityIdentity::Operation {
                    context: Box::new(request.context.clone()),
                    locator: None,
                },
                stage: BlobCapacityStage::CasJournal,
                evidence: BlobCapacityEvidence {
                    cause: BlobCapacityCause::IoStorageFull,
                    attempted_bytes: None,
                    effect,
                },
                cas_request: Some(Box::new(request.clone())),
                cas_observed: observed,
                cas_backend_generation: Some(request.expected_backend_generation),
                cas_durability: Some(BlobCasDurability::Unconfirmed),
                cleanup: BlobCapacityCleanup::NotApplicable,
                cleanup_stage: None,
                cleanup_evidence: None,
                gc_state: None,
                recovery: if matches!(effect, BlobCapacityEffect::NotAttempted) {
                    BlobCapacityRecovery::CapacityRevalidationRequired
                } else {
                    BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
                },
            }),
        })
    }

    fn observe_cas_state(&self, request: &BlobCasRequest) -> Result<BlobCasState, BlobError> {
        self.prove_contained(&request.root_lease, &request.target)?;
        match self
            .filesystem
            .read_bounded(&request.target, CAS_NAMESPACE_MAX_BYTES)
        {
            Ok(bytes) => Ok(BlobCasState::Digest(sha256_hex(&bytes))),
            Err(eliot_platform::PortError::Provider(error))
                if error.code == eliot_platform::ProviderErrorCode::Failed
                    && self.filesystem.stat(&request.target).ok()
                        == Some(WindowsBlobPathState::Missing) =>
            {
                Ok(BlobCasState::Missing)
            }
            Err(error) => Err(BlobError::Provider(error.to_string())),
        }
    }
}

impl BlobPlatformPort for WindowsBlobPlatformPort {
    fn claim_root(&mut self, lease: &BlobRootLease) -> Result<RootClaimProof, BlobError> {
        lease.validate()?;
        if lease.root_id.as_str() != self.root_identity {
            return Err(BlobError::OwnerConflict);
        }
        self.filesystem.prove_root_writable().map_err(|error| {
            BlobError::Provider(format!("prove Blob root permissions: {error}"))
        })?;
        let proof = RootClaimProof {
            root_id: self.root_identity.clone(),
            owner_id: lease.owner_id.to_string(),
            lease_id: lease.lease_id.to_string(),
            root_generation: lease.root_generation,
            containment_proven: true,
            permissions_proven: true,
        };
        let mut retained = self
            .root_claim
            .lock()
            .map_err(|_| BlobError::Provider("Blob platform claim lock poisoned".to_owned()))?;
        if retained.as_ref().is_some_and(|current| current != &proof) {
            return Err(BlobError::OwnerConflict);
        }
        let mut active = self
            .active_lease
            .lock()
            .map_err(|_| BlobError::Provider("Blob active lease lock poisoned".to_owned()))?;
        if active.as_ref().is_some_and(|current| current != lease) {
            return Err(BlobError::StaleFence);
        }
        *active = Some(lease.clone());
        *retained = Some(proof.clone());
        Ok(proof)
    }

    fn inspect_root(&self, lease: &BlobRootLease) -> Result<RootClaimProof, BlobError> {
        self.require_root(lease)?;
        self.root_claim
            .lock()
            .map_err(|_| BlobError::Provider("Blob platform claim lock poisoned".to_owned()))?
            .clone()
            .ok_or(BlobError::OwnerConflict)
    }

    fn prove_contained(
        &self,
        lease: &BlobRootLease,
        path: &WorkScopePath,
    ) -> Result<(), BlobError> {
        self.require_root(lease)?;
        self.filesystem
            .prove_contained(path)
            .map_err(|error| BlobError::InvalidContract(error.to_string()))
    }

    fn read_bounded(&self, path: &WorkScopePath, max_bytes: u64) -> Result<Vec<u8>, BlobError> {
        self.filesystem
            .read_bounded(path, max_bytes)
            .map_err(|error| match error {
                eliot_platform::PortError::Provider(_)
                    if self.filesystem.stat(path).ok() == Some(WindowsBlobPathState::Missing) =>
                {
                    BlobError::NotFound
                }
                other => BlobError::Provider(other.to_string()),
            })
    }

    fn write_new_durable(&mut self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
        self.filesystem
            .write_new_durable(path, bytes)
            .map_err(|error| match error {
                eliot_platform::PortError::Provider(_)
                    if self.filesystem.stat(path).ok() != Some(WindowsBlobPathState::Missing) =>
                {
                    BlobError::IdempotencyConflict
                }
                other => BlobError::Provider(other.to_string()),
            })
    }

    fn replace_durable(&mut self, path: &WorkScopePath, bytes: &[u8]) -> Result<(), BlobError> {
        self.filesystem
            .replace_durable(path, bytes)
            .map_err(|error| BlobError::Provider(error.to_string()))
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
        self.require_root(&request.root_lease)?;
        let _serial = self
            .cas_serialization
            .lock()
            .map_err(|_| BlobError::Provider("Blob CAS serialization lock poisoned".to_owned()))?;
        let operation_id = request.context.operation.operation_id.to_string();
        let request_commitment_sha256 = request.request_commitment_sha256()?;
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
        if let Some(previous) = self.read_cas_record(&operation_id)? {
            if previous.request_commitment_sha256 != request_commitment_sha256 {
                return Err(BlobError::CasFailure {
                    failure: Box::new(BlobCasFailure::IdentityConflict {
                        request: Box::new(request.clone()),
                    }),
                });
            }
            if let Some(result) = previous.result {
                return Ok(result);
            }
            return Err(cas_unknown(
                request,
                None,
                Some(self.backend_generation),
                BlobCasDurability::Unconfirmed,
            ));
        }
        if self.backend_generation != request.expected_backend_generation {
            return Err(BlobError::CasFailure {
                failure: Box::new(BlobCasFailure::Internal {
                    request: Box::new(request.clone()),
                    reason: eliot_blob_api::BlobCasInternalReason::BackendGenerationMismatch,
                }),
            });
        }
        let observed = self.observe_cas_state(request)?;
        if observed != request.expected {
            return Err(BlobError::CasFailure {
                failure: Box::new(BlobCasFailure::ExpectedStateConflict {
                    request: Box::new(request.clone()),
                    observed,
                }),
            });
        }
        let pending = CasStatusRecord {
            version: 1,
            operation_id: operation_id.clone(),
            request_commitment_sha256: request_commitment_sha256.clone(),
            result: None,
        };
        if let Err(error) = self.write_cas_record(&pending, true) {
            return Err(Self::cas_journal_capacity(
                request,
                &error,
                BlobCapacityEffect::PartialWriteUnknown,
                None,
            )
            .unwrap_or_else(|| BlobError::Provider(error.to_string())));
        }
        let no_op = request.expected.sha256() == Some(request.replacement_sha256.as_str());
        let install = if no_op {
            Ok(())
        } else {
            match observed {
                BlobCasState::Missing => self.filesystem.write_new_durable(&request.target, bytes),
                BlobCasState::Digest(_) => self.filesystem.replace_durable(&request.target, bytes),
            }
        };
        if install.is_err() {
            return Err(cas_unknown(
                request,
                self.observe_cas_state(request).ok(),
                Some(self.backend_generation),
                BlobCasDurability::Unconfirmed,
            ));
        }
        let result = BlobCasProviderResult {
            operation_id: operation_id.clone(),
            request_commitment_sha256: request_commitment_sha256.clone(),
            observed,
            replacement_sha256: request.replacement_sha256.clone(),
            replacement_length: request.replacement_length,
            backend_generation: self.backend_generation,
            observed_durability: BlobCasDurability::Confirmed,
            success: if no_op {
                BlobCasSuccessKind::NoOp
            } else {
                BlobCasSuccessKind::Applied
            },
        };
        let complete = CasStatusRecord {
            version: 1,
            operation_id: operation_id.clone(),
            request_commitment_sha256,
            result: Some(result.clone()),
        };
        if let Err(error) = self.write_cas_record(&complete, false) {
            if let Some(capacity) = Self::cas_journal_capacity(
                request,
                &error,
                BlobCapacityEffect::PossibleMutation,
                Some(BlobCasState::Digest(request.replacement_sha256.clone())),
            ) {
                return Err(capacity);
            }
            return Err(cas_unknown(
                request,
                Some(BlobCasState::Digest(request.replacement_sha256.clone())),
                Some(self.backend_generation),
                BlobCasDurability::Unconfirmed,
            ));
        }
        self.cas_statuses
            .lock()
            .map_err(|_| BlobError::Provider("Blob CAS status cache poisoned".to_owned()))?
            .insert(operation_id, complete);
        Ok(result)
    }

    fn cas_status(&self, operation_id: &str) -> Result<Option<BlobCasProviderResult>, BlobError> {
        if let Some(record) = self
            .cas_statuses
            .lock()
            .map_err(|_| BlobError::Provider("Blob CAS status cache poisoned".to_owned()))?
            .get(operation_id)
            .cloned()
        {
            return Ok(record.result);
        }
        let Some(record) = self.read_cas_record(operation_id)? else {
            return Ok(None);
        };
        let result = record.result.clone();
        self.cas_statuses
            .lock()
            .map_err(|_| BlobError::Provider("Blob CAS status cache poisoned".to_owned()))?
            .insert(operation_id.to_owned(), record);
        Ok(result)
    }

    fn backend_generation(&self) -> Result<u64, BlobError> {
        Ok(self.backend_generation)
    }

    fn rename_no_replace_durable(
        &mut self,
        source: &WorkScopePath,
        destination: &WorkScopePath,
    ) -> Result<(), BlobError> {
        self.filesystem
            .rename_no_replace_durable(source, destination)
            .map_err(|error| BlobError::Provider(error.to_string()))
    }

    fn reconcile_rename_publication(
        &mut self,
        operation_id: &str,
        idempotency_key: &str,
        source: &WorkScopePath,
        destination: &WorkScopePath,
        expected_sha256: &str,
        hard_ceiling: u64,
    ) -> Result<BlobPublicationReconciliation, BlobError> {
        self.filesystem
            .reconcile_rename_publication(
                operation_id,
                idempotency_key,
                source,
                destination,
                expected_sha256,
                hard_ceiling,
            )
            .map(|result| match result {
                WindowsBlobPublicationReconciliation::ConfirmedDurable => {
                    BlobPublicationReconciliation::ConfirmedDurable
                }
                WindowsBlobPublicationReconciliation::KnownAbsent => {
                    BlobPublicationReconciliation::KnownAbsent
                }
            })
            .map_err(|error| BlobError::Provider(error.to_string()))
    }

    fn reconcile_create_publication(
        &mut self,
        operation_id: &str,
        idempotency_key: &str,
        destination: &WorkScopePath,
        expected_sha256: &str,
        bytes: &[u8],
        hard_ceiling: u64,
    ) -> Result<BlobPublicationReconciliation, BlobError> {
        self.filesystem
            .reconcile_create_publication(
                operation_id,
                idempotency_key,
                destination,
                expected_sha256,
                bytes,
                hard_ceiling,
            )
            .map(|result| match result {
                WindowsBlobPublicationReconciliation::ConfirmedDurable => {
                    BlobPublicationReconciliation::ConfirmedDurable
                }
                WindowsBlobPublicationReconciliation::KnownAbsent => {
                    BlobPublicationReconciliation::KnownAbsent
                }
            })
            .map_err(|error| BlobError::Provider(error.to_string()))
    }

    fn remove_durable(&mut self, path: &WorkScopePath) -> Result<(), BlobError> {
        self.filesystem
            .remove_durable(path)
            .map_err(|error| BlobError::Provider(error.to_string()))
    }

    fn stat(&self, path: &WorkScopePath) -> Result<BlobPathState, BlobError> {
        self.filesystem
            .stat(path)
            .map(|state| match state {
                WindowsBlobPathState::Missing => BlobPathState::Missing,
                WindowsBlobPathState::File {
                    length,
                    modified_unix_ms,
                } => BlobPathState::File {
                    length,
                    modified_unix_ms,
                },
                WindowsBlobPathState::Directory => BlobPathState::Directory,
                WindowsBlobPathState::ReparsePoint => BlobPathState::ReparsePoint,
                WindowsBlobPathState::Other => BlobPathState::Other,
            })
            .map_err(|error| BlobError::Provider(error.to_string()))
    }

    fn list(&self, prefix: &WorkScopePath) -> Result<Vec<WorkScopePath>, BlobError> {
        self.filesystem
            .list(prefix)
            .map_err(|error| BlobError::Provider(error.to_string()))
    }

    fn now_unix_ms(&mut self) -> Result<u64, BlobError> {
        self.filesystem
            .now_unix_ms()
            .map_err(|error| BlobError::Provider(error.to_string()))
    }
}
