//! Governed ECXF/1 logical backup and isolated restore.
//!
//! This crate owns the exchange-format boundary, not a database connection or
//! a filesystem root. Exporters provide already-fenced canonical records and
//! sealed blob envelopes; this package validates their identities, computes one
//! deterministic manifest, and exposes an explicit restore plan.
//!
//! No operation restores an active session, lease, broker registration,
//! authority, or route continuation. Restore is isolated and leaves cutover to
//! the owning Kernel/Human authority.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_blob_api::{
    BlobError, BlobHash, BlobId, BlobLocator, CompressionDescriptor, CryptoDescriptor,
};
use eliot_contracts::{EpochId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::{OrderingHead, RevisionHead, ScopeId, StoreError, WriteReceipt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Stable identity of the exchange-format contract.
pub const CONTRACT_NAME: &str = "eliot.storage.backup";
/// Current logical exchange format.
pub const FORMAT_VERSION: &str = "ECXF/1";
/// Maximum one canonical record accepted by an export.
pub const MAX_RECORD_BYTES: usize = 32 * 1024 * 1024;
/// Maximum one sealed blob envelope accepted by an export.
pub const MAX_SEALED_BLOB_BYTES: usize = 512 * 1024 * 1024;

fn text(value: &str, field: &'static str) -> Result<(), BackupError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(BackupError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn sha256<T: Serialize>(value: &T) -> Result<String, BackupError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| BackupError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn bytes_sha256(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

fn digest(value: &str, field: &'static str) -> Result<(), BackupError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(BackupError::InvalidField {
            field,
            reason: "must be lowercase SHA-256 hex",
        });
    }
    Ok(())
}

fn unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<(), BackupError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(BackupError::Duplicate { field });
    }
    Ok(())
}

/// Explicit backup class from I5.13.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupClass {
    FullRecovery,
    CanonicalOnlyDegraded,
    ScopeExport,
}

impl BackupClass {
    #[must_use]
    pub const fn is_full_recovery(self) -> bool {
        matches!(self, Self::FullRecovery)
    }
}

/// Event interval captured by one consistent export fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRange {
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub count: u64,
}

impl EventRange {
    pub fn validate(&self) -> Result<(), BackupError> {
        match (self.first_sequence, self.last_sequence, self.count) {
            (None, None, 0) => Ok(()),
            (Some(first), Some(last), count) if first <= last && count > 0 => {
                if last.saturating_sub(first).saturating_add(1) < count {
                    return Err(BackupError::InvalidField {
                        field: "event_range.count",
                        reason: "cannot exceed the declared sequence interval",
                    });
                }
                Ok(())
            }
            _ => Err(BackupError::InvalidField {
                field: "event_range",
                reason: "empty and non-empty ranges must use matching bounds",
            }),
        }
    }
}

/// The coherent logical boundary of an ECXF export.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportFence {
    pub export_id: String,
    pub store_generation: String,
    pub state_fence: StateFence,
    pub scope_id: Option<ScopeId>,
    pub revision_heads: Vec<RevisionHead>,
    pub ordering_heads: Vec<OrderingHead>,
    pub event_range: EventRange,
    pub blob_reachability_manifest: Vec<BlobHash>,
    /// False means the exporter did not prove one coherent boundary.
    pub consistent: bool,
}

impl ExportFence {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.export_id, "export_fence.export_id")?;
        text(&self.store_generation, "export_fence.store_generation")?;
        self.state_fence
            .validate()
            .map_err(|error| BackupError::Foundation(error.to_string()))?;
        if !self.consistent {
            return Err(BackupError::InconsistentBoundary);
        }
        self.event_range.validate()?;
        unique(
            self.revision_heads.iter().map(|head| head.key.clone()),
            "revision_heads",
        )?;
        for head in &self.revision_heads {
            head.validate().map_err(BackupError::Store)?;
        }
        unique(
            self.ordering_heads.iter().map(|head| head.scope.clone()),
            "ordering_heads",
        )?;
        for head in &self.ordering_heads {
            head.validate().map_err(BackupError::Store)?;
        }
        unique(
            self.blob_reachability_manifest.iter().cloned(),
            "blob_reachability_manifest",
        )?;
        Ok(())
    }
}

/// One canonical logical record in an ECXF section.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRecord {
    pub record_type: String,
    pub record_id: String,
    pub payload: Value,
    pub sha256: String,
}

impl CanonicalRecord {
    pub fn new(
        record_type: impl Into<String>,
        record_id: impl Into<String>,
        payload: Value,
    ) -> Result<Self, BackupError> {
        let record_type = record_type.into();
        let record_id = record_id.into();
        text(&record_type, "record_type")?;
        text(&record_id, "record_id")?;
        if !payload.is_object() {
            return Err(BackupError::InvalidField {
                field: "payload",
                reason: "canonical records require an object payload",
            });
        }
        let record = Self {
            record_type,
            record_id,
            sha256: sha256(&payload)?,
            payload,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.record_type, "record_type")?;
        text(&self.record_id, "record_id")?;
        if !self.payload.is_object() {
            return Err(BackupError::InvalidField {
                field: "payload",
                reason: "canonical records require an object payload",
            });
        }
        digest(&self.sha256, "record.sha256")?;
        if sha256(&self.payload)? != self.sha256 {
            return Err(BackupError::IntegrityMismatch {
                subject: self.record_id.clone(),
            });
        }
        let size = canonical_json_bytes(&self.payload)
            .map_err(|error| BackupError::Serialization(error.to_string()))?
            .len();
        if size > MAX_RECORD_BYTES {
            return Err(BackupError::LimitExceeded {
                field: "record",
                limit: MAX_RECORD_BYTES,
            });
        }
        Ok(())
    }
}

/// A sealed blob envelope transported by ECXF. Plaintext never appears here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupBlob {
    pub locator: BlobLocator,
    pub sealed_bytes: Vec<u8>,
    pub sealed_sha256: String,
    pub plaintext_sha256: String,
    pub key_lineage: BlobId,
    pub format: BlobId,
    pub format_version: u32,
    pub compression: CompressionDescriptor,
    pub crypto: CryptoDescriptor,
}

impl BackupBlob {
    pub fn validate(&self) -> Result<(), BackupError> {
        self.locator.validate()?;
        if self.sealed_bytes.is_empty() {
            return Err(BackupError::InvalidField {
                field: "blob.sealed_bytes",
                reason: "sealed envelope cannot be empty",
            });
        }
        if self.sealed_bytes.len() > MAX_SEALED_BLOB_BYTES {
            return Err(BackupError::LimitExceeded {
                field: "blob.sealed_bytes",
                limit: MAX_SEALED_BLOB_BYTES,
            });
        }
        digest(&self.sealed_sha256, "blob.sealed_sha256")?;
        if bytes_sha256(&self.sealed_bytes) != self.sealed_sha256 {
            return Err(BackupError::IntegrityMismatch {
                subject: format!("sealed blob {}", self.locator.hash),
            });
        }
        digest(&self.plaintext_sha256, "blob.plaintext_sha256")?;
        text(self.key_lineage.as_str(), "blob.key_lineage")?;
        text(self.format.as_str(), "blob.format")?;
        if self.format_version == 0 {
            return Err(BackupError::InvalidField {
                field: "blob.format_version",
                reason: "must be greater than zero",
            });
        }
        self.compression.validate()?;
        self.crypto.validate()?;
        Ok(())
    }
}

/// A checksummed config, policy, module, or approved build manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupArtifact {
    pub kind: String,
    pub artifact_id: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

impl BackupArtifact {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.kind, "artifact.kind")?;
        text(&self.artifact_id, "artifact.artifact_id")?;
        digest(&self.sha256, "artifact.sha256")?;
        if self.bytes.is_empty() {
            return Err(BackupError::InvalidField {
                field: "artifact.bytes",
                reason: "manifest artifact cannot be empty",
            });
        }
        if self.bytes.len() > MAX_RECORD_BYTES {
            return Err(BackupError::LimitExceeded {
                field: "artifact.bytes",
                limit: MAX_RECORD_BYTES,
            });
        }
        if bytes_sha256(&self.bytes) != self.sha256 {
            return Err(BackupError::IntegrityMismatch {
                subject: self.artifact_id.clone(),
            });
        }
        Ok(())
    }
}

/// Logical ORS boundary. It is historical input to recovery, never active
/// authority in the restored root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrsSnapshotFence {
    pub snapshot_id: String,
    pub authority_epoch: EpochId,
    pub resource_generation: ResourceGeneration,
    pub last_receipt_cursor: u64,
    pub last_event_cursor: u64,
    pub last_outbox_cursor: u64,
    pub pending_operation_ids: Vec<String>,
    pub job_checkpoint_ids: Vec<String>,
    pub generation_cutover_ids: Vec<String>,
    pub state_fence: StateFence,
    pub active_authority_restored: bool,
}

impl OrsSnapshotFence {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.snapshot_id, "ors.snapshot_id")?;
        self.state_fence
            .validate()
            .map_err(|error| BackupError::Foundation(error.to_string()))?;
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
            || self.resource_generation != self.state_fence.resource_generation
        {
            return Err(BackupError::FenceMismatch {
                subject: "ors snapshot".to_owned(),
            });
        }
        if self.active_authority_restored {
            return Err(BackupError::ActiveAuthorityInBackup);
        }
        unique(
            self.pending_operation_ids.iter().cloned(),
            "ors.pending_operation_ids",
        )?;
        for id in self
            .pending_operation_ids
            .iter()
            .chain(self.job_checkpoint_ids.iter())
            .chain(self.generation_cutover_ids.iter())
        {
            text(id, "ors.identity")?;
        }
        Ok(())
    }
}

/// Bounded unresolved Watchdog spool boundary required by full recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogSpoolFence {
    pub fence_id: String,
    pub unresolved_signal_digests: Vec<String>,
    pub state_fence: StateFence,
    pub bounded: bool,
}

impl WatchdogSpoolFence {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.fence_id, "watchdog.fence_id")?;
        self.state_fence
            .validate()
            .map_err(|error| BackupError::Foundation(error.to_string()))?;
        if !self.bounded {
            return Err(BackupError::UnboundedWatchdogSpool);
        }
        for signal in &self.unresolved_signal_digests {
            digest(signal, "watchdog.signal_digest")?;
        }
        unique(
            self.unresolved_signal_digests.iter().cloned(),
            "watchdog.unresolved_signal_digests",
        )?;
        Ok(())
    }
}

/// Optional forensic host audit. It cannot authorize restored operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStateAuditFence {
    pub audit_id: String,
    pub lineage_digest: String,
    pub observed_dispositions: Vec<String>,
    pub active_authority_restored: bool,
}

impl HostStateAuditFence {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.audit_id, "host_audit.audit_id")?;
        digest(&self.lineage_digest, "host_audit.lineage_digest")?;
        for disposition in &self.observed_dispositions {
            text(disposition, "host_audit.observed_disposition")?;
        }
        if self.active_authority_restored {
            return Err(BackupError::ActiveAuthorityInBackup);
        }
        Ok(())
    }
}

/// Explicit encryption declaration in the ECXF manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionSummary {
    pub envelope: String,
    pub key_lineages: Vec<String>,
    pub plaintext_keys_present: bool,
}

impl EncryptionSummary {
    fn validate(&self) -> Result<(), BackupError> {
        text(&self.envelope, "manifest.encryption.envelope")?;
        if self.plaintext_keys_present {
            return Err(BackupError::PlaintextKeyMaterial);
        }
        for lineage in &self.key_lineages {
            text(lineage, "manifest.encryption.key_lineage")?;
        }
        unique(
            self.key_lineages.iter().cloned(),
            "manifest.encryption.key_lineages",
        )?;
        Ok(())
    }
}

/// ECXF manifest. Section checksums and `integrity_sha256` bind the export.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxfManifest {
    pub format: String,
    pub backup_id: String,
    pub class: BackupClass,
    pub source_adapter: String,
    pub schema_generation: String,
    pub export_fence_sha256: String,
    pub sections: BTreeMap<String, String>,
    pub missing_features: Vec<String>,
    pub purge_ledger_revision: u64,
    pub encryption: EncryptionSummary,
    pub integrity_sha256: String,
}

impl EcxfManifest {
    fn validate_shape(&self) -> Result<(), BackupError> {
        if self.format != FORMAT_VERSION {
            return Err(BackupError::UnsupportedFormat(self.format.clone()));
        }
        text(&self.backup_id, "manifest.backup_id")?;
        text(&self.source_adapter, "manifest.source_adapter")?;
        text(&self.schema_generation, "manifest.schema_generation")?;
        digest(&self.export_fence_sha256, "manifest.export_fence_sha256")?;
        digest(&self.integrity_sha256, "manifest.integrity_sha256")?;
        self.encryption.validate()?;
        for (section, checksum) in &self.sections {
            text(section, "manifest.section")?;
            digest(checksum, "manifest.section_checksum")?;
        }
        for feature in &self.missing_features {
            text(feature, "manifest.missing_feature")?;
        }
        Ok(())
    }
}

/// Input supplied by a canonical exporter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupInput {
    pub backup_id: String,
    pub class: BackupClass,
    pub source_adapter: String,
    pub schema_generation: String,
    pub export_fence: ExportFence,
    pub canonical_events: Vec<CanonicalRecord>,
    pub projections: Vec<CanonicalRecord>,
    pub receipts: Vec<WriteReceipt>,
    pub blobs: Vec<BackupBlob>,
    pub purge_ledger: Vec<PurgeLedgerEntry>,
    pub ors_snapshot: Option<OrsSnapshotFence>,
    pub artifacts: Vec<BackupArtifact>,
    pub watchdog_spool: Option<WatchdogSpoolFence>,
    pub host_audit: Option<HostStateAuditFence>,
    pub missing_features: Vec<String>,
    pub purge_ledger_revision: u64,
}

/// Immutable logical ECXF bundle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupBundle {
    pub manifest: EcxfManifest,
    pub export_fence: ExportFence,
    pub canonical_events: Vec<CanonicalRecord>,
    pub projections: Vec<CanonicalRecord>,
    pub receipts: Vec<WriteReceipt>,
    pub blobs: Vec<BackupBlob>,
    pub purge_ledger: Vec<PurgeLedgerEntry>,
    pub ors_snapshot: Option<OrsSnapshotFence>,
    pub artifacts: Vec<BackupArtifact>,
    pub watchdog_spool: Option<WatchdogSpoolFence>,
    pub host_audit: Option<HostStateAuditFence>,
}

impl BackupBundle {
    /// Builds, hashes, and validates one complete logical export.
    pub fn build(input: BackupInput) -> Result<Self, BackupError> {
        let mut bundle = Self {
            manifest: EcxfManifest {
                format: FORMAT_VERSION.to_owned(),
                backup_id: input.backup_id,
                class: input.class,
                source_adapter: input.source_adapter,
                schema_generation: input.schema_generation,
                export_fence_sha256: sha256(&input.export_fence)?,
                sections: BTreeMap::new(),
                missing_features: input.missing_features,
                purge_ledger_revision: input.purge_ledger_revision,
                encryption: EncryptionSummary {
                    envelope: "sealed-blob-envelope-v1".to_owned(),
                    key_lineages: Vec::new(),
                    plaintext_keys_present: false,
                },
                integrity_sha256: "0".repeat(64),
            },
            export_fence: input.export_fence,
            canonical_events: input.canonical_events,
            projections: input.projections,
            receipts: input.receipts,
            blobs: input.blobs,
            purge_ledger: input.purge_ledger,
            ors_snapshot: input.ors_snapshot,
            artifacts: input.artifacts,
            watchdog_spool: input.watchdog_spool,
            host_audit: input.host_audit,
        };
        normalize_bundle(&mut bundle);
        bundle.manifest.encryption.key_lineages = bundle
            .blobs
            .iter()
            .map(|blob| blob.key_lineage.as_str().to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        bundle.manifest.sections = bundle.section_checksums()?;
        bundle.manifest.integrity_sha256 = bundle.manifest_integrity_digest()?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Revalidates all integrity, fence, class, purge, and manifest rules.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), BackupError> {
        self.manifest.validate_shape()?;
        self.export_fence.validate()?;
        if sha256(&self.export_fence)? != self.manifest.export_fence_sha256 {
            return Err(BackupError::IntegrityMismatch {
                subject: "export fence".to_owned(),
            });
        }
        if self.manifest.class == BackupClass::ScopeExport && self.export_fence.scope_id.is_none() {
            return Err(BackupError::ScopeRequired);
        }
        if self.manifest.class != BackupClass::ScopeExport && self.export_fence.scope_id.is_some() {
            return Err(BackupError::ScopeUnexpected);
        }
        for record in self.canonical_events.iter().chain(self.projections.iter()) {
            record.validate()?;
        }
        unique(
            self.canonical_events
                .iter()
                .map(|record| record.record_id.clone()),
            "canonical_events",
        )?;
        unique(
            self.projections
                .iter()
                .map(|record| record.record_id.clone()),
            "projections",
        )?;
        if self.export_fence.event_range.count != self.canonical_events.len() as u64 {
            return Err(BackupError::FenceMismatch {
                subject: "event range count".to_owned(),
            });
        }
        validate_receipts(
            &self.receipts,
            &self.canonical_events,
            &self.export_fence.state_fence,
        )?;
        unique(
            self.blobs.iter().map(|blob| blob.locator.hash.clone()),
            "blobs",
        )?;
        let expected_blobs = self
            .export_fence
            .blob_reachability_manifest
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for blob in &self.blobs {
            blob.validate()?;
            if !expected_blobs.contains(&blob.locator.hash) {
                return Err(BackupError::UnreferencedBlob {
                    hash: blob.locator.hash.to_string(),
                });
            }
        }
        if expected_blobs.len() != self.blobs.len() {
            return Err(BackupError::MissingBlob);
        }
        unique(
            self.purge_ledger.iter().map(|entry| entry.purge_id.clone()),
            "purge_ledger",
        )?;
        for entry in &self.purge_ledger {
            entry
                .validate()
                .map_err(|error| BackupError::Security(error.to_string()))?;
            if !entry
                .state_fence
                .is_compatible_with(&self.export_fence.state_fence)
            {
                return Err(BackupError::FenceMismatch {
                    subject: format!("purge {}", entry.purge_id),
                });
            }
        }
        unique(
            self.artifacts
                .iter()
                .map(|artifact| artifact.artifact_id.clone()),
            "artifacts",
        )?;
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        if let Some(ors) = &self.ors_snapshot {
            ors.validate()?;
            if ors.state_fence != self.export_fence.state_fence {
                return Err(BackupError::FenceMismatch {
                    subject: "ors/export fence".to_owned(),
                });
            }
        }
        if let Some(watchdog) = &self.watchdog_spool {
            watchdog.validate()?;
            if watchdog.state_fence != self.export_fence.state_fence {
                return Err(BackupError::FenceMismatch {
                    subject: "watchdog/export fence".to_owned(),
                });
            }
        }
        if let Some(host_audit) = &self.host_audit {
            host_audit.validate()?;
        }
        validate_class_requirements(self)?;
        if self.section_checksums()? != self.manifest.sections {
            return Err(BackupError::IntegrityMismatch {
                subject: "manifest sections".to_owned(),
            });
        }
        if self.manifest_integrity_digest()? != self.manifest.integrity_sha256 {
            return Err(BackupError::IntegrityMismatch {
                subject: "manifest".to_owned(),
            });
        }
        Ok(())
    }

    fn section_checksums(&self) -> Result<BTreeMap<String, String>, BackupError> {
        let mut sections = BTreeMap::new();
        sections.insert(
            "canonical_events".to_owned(),
            sha256(&self.canonical_events)?,
        );
        sections.insert("projections".to_owned(), sha256(&self.projections)?);
        sections.insert("receipts".to_owned(), sha256(&self.receipts)?);
        sections.insert("blobs".to_owned(), sha256(&self.blobs)?);
        sections.insert("purge_ledger".to_owned(), sha256(&self.purge_ledger)?);
        sections.insert("ors_snapshot".to_owned(), sha256(&self.ors_snapshot)?);
        sections.insert("artifacts".to_owned(), sha256(&self.artifacts)?);
        sections.insert("watchdog_spool".to_owned(), sha256(&self.watchdog_spool)?);
        sections.insert("host_audit".to_owned(), sha256(&self.host_audit)?);
        Ok(sections)
    }

    fn manifest_integrity_digest(&self) -> Result<String, BackupError> {
        let mut manifest = self.manifest.clone();
        manifest.integrity_sha256 = "0".repeat(64);
        sha256(&manifest)
    }

    /// Returns the deterministic complete-bundle digest.
    pub fn bundle_sha256(&self) -> Result<String, BackupError> {
        self.validate()?;
        sha256(self)
    }

    /// Encodes the logical bundle with the canonical object-key ordering used
    /// by ECXF integrity records.
    pub fn encode(&self) -> Result<Vec<u8>, BackupError> {
        self.validate()?;
        canonical_json_bytes(self).map_err(|error| BackupError::Serialization(error.to_string()))
    }

    /// Decodes and fully validates one logical ECXF bundle before use.
    pub fn decode(bytes: &[u8]) -> Result<Self, BackupError> {
        let bundle: Self = serde_json::from_slice(bytes)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        bundle.validate()?;
        Ok(bundle)
    }
}

fn normalize_bundle(bundle: &mut BackupBundle) {
    bundle
        .canonical_events
        .sort_by(|left, right| left.record_id.cmp(&right.record_id));
    bundle
        .projections
        .sort_by(|left, right| left.record_id.cmp(&right.record_id));
    bundle.receipts.sort_by(|left, right| {
        left.operation_id
            .to_string()
            .cmp(&right.operation_id.to_string())
    });
    bundle
        .blobs
        .sort_by(|left, right| left.locator.hash.cmp(&right.locator.hash));
    bundle
        .purge_ledger
        .sort_by(|left, right| left.purge_id.cmp(&right.purge_id));
    bundle
        .artifacts
        .sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
}

fn validate_receipts(
    receipts: &[WriteReceipt],
    events: &[CanonicalRecord],
    export_fence: &StateFence,
) -> Result<(), BackupError> {
    unique(
        receipts
            .iter()
            .map(|receipt| receipt.operation_id.to_string()),
        "receipts.operation_id",
    )?;
    let event_ids = events
        .iter()
        .map(|event| event.record_id.as_str())
        .collect::<BTreeSet<_>>();
    for receipt in receipts {
        receipt.validate().map_err(BackupError::Store)?;
        if !receipt.state_fence.is_compatible_with(export_fence) {
            return Err(BackupError::FenceMismatch {
                subject: format!("receipt {}", receipt.operation_id),
            });
        }
        for event_id in &receipt.emitted_event_ids {
            if !event_ids.contains(event_id.as_str()) {
                return Err(BackupError::ReceiptChainGap {
                    event_id: event_id.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn validate_class_requirements(bundle: &BackupBundle) -> Result<(), BackupError> {
    const REQUIRED: [&str; 4] = ["config", "policy", "module", "host_dependency_build"];
    match bundle.manifest.class {
        BackupClass::FullRecovery => {
            if bundle.ors_snapshot.is_none() {
                return Err(BackupError::MissingRecoveryComponent("ors_snapshot"));
            }
            if bundle.watchdog_spool.is_none() {
                return Err(BackupError::MissingRecoveryComponent("watchdog_spool"));
            }
            for required in REQUIRED {
                if !bundle
                    .artifacts
                    .iter()
                    .any(|artifact| artifact.kind == required)
                {
                    return Err(BackupError::MissingRecoveryComponent(required));
                }
            }
            if !bundle.manifest.missing_features.is_empty() {
                return Err(BackupError::FullRecoveryHasGaps);
            }
        }
        BackupClass::CanonicalOnlyDegraded | BackupClass::ScopeExport => {
            if bundle.ors_snapshot.is_some() {
                return Err(BackupError::UnexpectedRecoveryComponent("ors_snapshot"));
            }
        }
    }
    Ok(())
}

/// Context for compiling an isolated restore plan.
///
/// `target_authority_epoch`/`target_resource_generation` are caller-proposed
/// planning inputs only. They are not accepted owner-issued authority: the
/// caller cannot mint authority by incrementing an integer. `RestorePlan::compile`
/// and `RestoredFence::validate` check that the proposal advances the observed
/// source lineage under the lineage-aware rule (same lineage must advance;
/// a new lineage must be genesis at sequence 1 with a newer generation), and
/// production composition must attach exact owner-issued lineage evidence
/// (see [`RestoreOwnerEpoch`]/[`ObservedLineageLimit`]) before cutover.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreContext {
    pub target_id: String,
    pub target_authority_epoch: EpochId,
    pub target_resource_generation: ResourceGeneration,
}

impl RestoreContext {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.target_id, "restore.target_id")
    }
}

/// New lineage assigned to the isolated restored root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoredFence {
    pub source_state_fence: StateFence,
    pub authority_epoch: EpochId,
    pub resource_generation: ResourceGeneration,
}

impl RestoredFence {
    pub fn validate(&self) -> Result<(), BackupError> {
        self.source_state_fence
            .validate()
            .map_err(|error| BackupError::Foundation(error.to_string()))?;
        // Lineage-aware restore ordering (Implements #64): sequence is
        // compared only when lineage_id is exactly equal (contract
        // types.EpochId). Same-lineage restore must advance; a new lineage
        // restore must be genesis (sequence 1, contract types.EpochTransition).
        // Cross-lineage non-genesis never advances.
        let target = &self.authority_epoch;
        let source = &self.source_state_fence.authority_epoch;
        let epoch_advances = if target.lineage_id == source.lineage_id {
            target.sequence.get() > source.sequence.get()
        } else {
            target.sequence.get() == 1
        };
        if !epoch_advances
            || self.resource_generation <= self.source_state_fence.resource_generation
        {
            return Err(BackupError::StaleRestoreLineage);
        }
        Ok(())
    }
}

/// Deterministic restore execution ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreStep {
    PrepareIsolatedRoot,
    ApplyPurgeLedger,
    ImportSealedBlobs,
    ImportCanonicalEvents,
    ImportReceipts,
    ImportProjections,
    SuspendOrsOperations,
    RebuildProjections,
    VerifyReceiptEventChain,
    FinalizeIsolatedRoot,
}

/// Stable identity for one recoverable restore transaction. The identity is
/// bound to the exact bundle, compiled plan and target context; none of these
/// values may drift while a journaled restore is resumed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreTransaction {
    pub transaction_id: String,
    pub bundle_sha256: String,
    pub plan_sha256: String,
    pub context_sha256: String,
}

/// One externally visible restore boundary. Item identities are stable and do
/// not rely on vector positions, so replay remains exact after restart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestorePhase {
    Pending,
    PrepareIsolatedRoot,
    ApplyPurgeLedger,
    ImportSealedBlob { hash: String },
    ImportCanonicalEvent { record_id: String },
    ImportReceipt { operation_id: String },
    ImportProjection { record_id: String },
    SuspendOrsOperations,
    RebuildProjections,
    VerifyReceiptEventChain,
    FinalizeIsolatedRoot,
}

/// Journal state is deliberately narrower than a provider's internal state.
/// An intent without a durable receipt is never treated as success.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreJournalState {
    Ready,
    IntentPersisted,
    ReceiptPersisted,
    Completed,
    RollbackRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreIntent {
    pub transaction_id: String,
    pub phase: RestorePhase,
    pub input_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreEffectReceipt {
    pub transaction_id: String,
    pub phase: RestorePhase,
    pub input_digest: String,
    pub external_identity_sha256: String,
    pub evidence_sha256: String,
}

/// Target-owned observation of one applied restore effect. The coordinator
/// never constructs this value; it only validates and journals it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreAppliedEffect {
    pub receipt: RestoreEffectReceipt,
    pub final_evidence: Option<RestoreEvidence>,
}

/// Result of reconciling an intent whose effect may have happened before a
/// process restart. Only an exact applied receipt may resume the transaction.
/// `Unknown` (the fail-closed default) and `NotApplied` carry no payload by
/// construction: an unknown possible effect stays unknown and is distinct
/// from not-attempted and success.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum RestoreReconciliation {
    Applied(RestoreAppliedEffect),
    NotApplied,
    Unknown,
}

/// Durable journal row. Implementations persist this record in their own
/// governed substrate; this crate does not create a second store or fallback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalRecord {
    pub journal_key: String,
    pub transaction: RestoreTransaction,
    pub revision: u64,
    pub completed_phases: u64,
    pub phase: RestorePhase,
    pub state: RestoreJournalState,
    pub intent: Option<RestoreIntent>,
    pub receipt: Option<RestoreEffectReceipt>,
    pub final_receipt: Option<RestoreReceipt>,
}

/// Durable restore journal seam. `compare_and_swap` must reject any stale
/// expected revision and must durably commit the complete next record.
pub trait RestoreJournalPort {
    fn load(&mut self, journal_key: &str) -> Result<Option<RestoreJournalRecord>, BackupError>;
    fn compare_and_swap(
        &mut self,
        journal_key: &str,
        expected_revision: u64,
        next: RestoreJournalRecord,
    ) -> Result<(), BackupError>;
}

/// A validated isolated restore plan. It never performs cutover.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePlan {
    pub plan_id: String,
    pub bundle_sha256: String,
    pub target: RestoreContext,
    pub restored_fence: RestoredFence,
    pub steps: Vec<RestoreStep>,
}

impl RestorePlan {
    pub fn compile(bundle: &BackupBundle, target: RestoreContext) -> Result<Self, BackupError> {
        bundle.validate()?;
        target.validate()?;
        let source = &bundle.export_fence.state_fence;
        let ors_epoch = bundle
            .ors_snapshot
            .as_ref()
            .map_or(source.authority_epoch.clone(), |ors| {
                ors.authority_epoch.clone()
            });
        let ors_generation = bundle
            .ors_snapshot
            .as_ref()
            .map_or(source.resource_generation, |ors| ors.resource_generation);
        // Lineage-aware restore ordering (Implements #64): same-lineage must
        // advance; new-lineage must be genesis (sequence 1).
        let epoch_advances = if target.target_authority_epoch.lineage_id == ors_epoch.lineage_id {
            target.target_authority_epoch.sequence.get() > ors_epoch.sequence.get()
        } else {
            target.target_authority_epoch.sequence.get() == 1
        };
        if !epoch_advances || target.target_resource_generation <= ors_generation {
            return Err(BackupError::StaleRestoreLineage);
        }
        let restored_fence = RestoredFence {
            source_state_fence: source.clone(),
            authority_epoch: target.target_authority_epoch.clone(),
            resource_generation: target.target_resource_generation,
        };
        restored_fence.validate()?;
        let steps = expected_restore_steps(bundle);
        Ok(Self {
            plan_id: format!("restore-plan-{}", bundle.manifest.backup_id),
            bundle_sha256: bundle.bundle_sha256()?,
            target,
            restored_fence,
            steps,
        })
    }

    /// Derives the stable transaction identity for this exact plan/context.
    pub fn transaction(&self) -> Result<RestoreTransaction, BackupError> {
        let bundle_sha256 = self.bundle_sha256.clone();
        digest(&bundle_sha256, "restore.transaction.bundle_sha256")?;
        let plan_sha256 = sha256(self)?;
        let context_sha256 = sha256(&self.target)?;
        let transaction_material = (
            self.plan_id.as_str(),
            bundle_sha256.as_str(),
            plan_sha256.as_str(),
            context_sha256.as_str(),
        );
        let transaction_id = format!("restore-transaction-{}", sha256(&transaction_material)?);
        Ok(RestoreTransaction {
            transaction_id,
            bundle_sha256,
            plan_sha256,
            context_sha256,
        })
    }

    fn journal_key(&self) -> Result<String, BackupError> {
        sha256(&(self.plan_id.as_str(), self.bundle_sha256.as_str()))
    }

    /// Executes the plan against a provider-owned isolated target.
    pub fn execute<T: RestoreTarget>(
        &self,
        bundle: &BackupBundle,
        target: &mut T,
    ) -> Result<RestoreReceipt, BackupError> {
        let _ = (bundle, target);
        Err(BackupError::RestoreJournalRequired)
    }

    /// Executes or resumes an isolated restore through an injected durable
    /// journal. Every target effect is preceded by an intent CAS and followed
    /// by a typed receipt CAS. No active cutover is performed here.
    #[allow(
        clippy::too_many_lines,
        reason = "the coordinator keeps the journal state machine and its CAS boundaries together"
    )]
    pub fn execute_with_journal<T: RestoreTarget, J: RestoreJournalPort>(
        &self,
        bundle: &BackupBundle,
        target: &mut T,
        journal: &mut J,
    ) -> Result<RestoreReceipt, BackupError> {
        bundle.validate()?;
        if bundle.bundle_sha256()? != self.bundle_sha256 {
            return Err(BackupError::PlanMismatch);
        }
        if self.steps != expected_restore_steps(bundle)
            || self.restored_fence.source_state_fence != bundle.export_fence.state_fence
            || self.target.validate().is_err()
            || self.restored_fence.validate().is_err()
        {
            return Err(BackupError::PlanMismatch);
        }
        let transaction = self.transaction()?;
        let journal_key = self.journal_key()?;
        let phases = restore_phases(bundle);
        let mut record = if let Some(record) = journal.load(&journal_key)? {
            record
        } else {
            let initial = RestoreJournalRecord {
                journal_key: journal_key.clone(),
                transaction: transaction.clone(),
                revision: 0,
                completed_phases: 0,
                phase: RestorePhase::Pending,
                state: RestoreJournalState::Ready,
                intent: None,
                receipt: None,
                final_receipt: None,
            };
            journal.compare_and_swap(&journal_key, 0, initial.clone())?;
            initial
        };
        validate_journal_record(&record, &journal_key, &transaction, &phases)?;

        loop {
            validate_journal_record(&record, &journal_key, &transaction, &phases)?;
            match record.state {
                RestoreJournalState::Completed => {
                    return record
                        .final_receipt
                        .clone()
                        .ok_or(BackupError::RestoreJournalCorrupt);
                }
                RestoreJournalState::IntentPersisted => {
                    let intent = record
                        .intent
                        .as_ref()
                        .ok_or(BackupError::RestoreJournalCorrupt)?;
                    match target.reconcile_restore_effect(intent)? {
                        RestoreReconciliation::Applied(applied) => {
                            let final_receipt = validate_applied_effect(
                                self,
                                bundle,
                                &transaction,
                                intent,
                                &applied,
                            )?;
                            let mut observed = record.clone();
                            observed.revision = next_revision(record.revision)?;
                            observed.state = RestoreJournalState::ReceiptPersisted;
                            observed.receipt = Some(applied.receipt);
                            observed.final_receipt = final_receipt;
                            journal.compare_and_swap(
                                &journal_key,
                                record.revision,
                                observed.clone(),
                            )?;
                            record = observed;
                        }
                        RestoreReconciliation::NotApplied => {
                            let applied = apply_restore_phase(self, bundle, target, intent)?;
                            let final_receipt = validate_applied_effect(
                                self,
                                bundle,
                                &transaction,
                                intent,
                                &applied,
                            )?;
                            let mut observed = record.clone();
                            observed.revision = next_revision(record.revision)?;
                            observed.state = RestoreJournalState::ReceiptPersisted;
                            observed.receipt = Some(applied.receipt);
                            observed.final_receipt = final_receipt;
                            journal.compare_and_swap(
                                &journal_key,
                                record.revision,
                                observed.clone(),
                            )?;
                            record = observed;
                        }
                        RestoreReconciliation::Unknown => {
                            let mut rollback = record.clone();
                            rollback.revision = next_revision(record.revision)?;
                            rollback.state = RestoreJournalState::RollbackRequired;
                            journal.compare_and_swap(&journal_key, record.revision, rollback)?;
                            return Err(BackupError::RestoreRollbackRequired);
                        }
                    }
                }
                RestoreJournalState::RollbackRequired => {
                    return Err(BackupError::RestoreRollbackRequired);
                }
                RestoreJournalState::ReceiptPersisted => {
                    let index = phase_index(&phases, &record.phase)?;
                    if index + 1 == phases.len() {
                        let mut completed = record.clone();
                        completed.revision = next_revision(record.revision)?;
                        completed.completed_phases = phases.len() as u64;
                        completed.state = RestoreJournalState::Completed;
                        journal.compare_and_swap(
                            &journal_key,
                            record.revision,
                            completed.clone(),
                        )?;
                        record = completed;
                    } else {
                        let mut advanced = record.clone();
                        advanced.revision = next_revision(record.revision)?;
                        advanced.completed_phases = (index + 1) as u64;
                        advanced.phase = phases[index + 1].clone();
                        advanced.state = RestoreJournalState::Ready;
                        advanced.intent = None;
                        advanced.receipt = None;
                        journal.compare_and_swap(
                            &journal_key,
                            record.revision,
                            advanced.clone(),
                        )?;
                        record = advanced;
                    }
                }
                RestoreJournalState::Ready => {
                    if matches!(record.phase, RestorePhase::Pending) {
                        if phases.is_empty() {
                            return Err(BackupError::RestoreJournalCorrupt);
                        }
                        let mut advanced = record.clone();
                        advanced.revision = next_revision(record.revision)?;
                        advanced.phase = phases[0].clone();
                        journal.compare_and_swap(
                            &journal_key,
                            record.revision,
                            advanced.clone(),
                        )?;
                        record = advanced;
                        continue;
                    }
                    let intent = restore_intent(&transaction, &record.phase)?;
                    let mut intent_record = record.clone();
                    intent_record.revision = next_revision(record.revision)?;
                    intent_record.state = RestoreJournalState::IntentPersisted;
                    intent_record.intent = Some(intent.clone());
                    intent_record.receipt = None;
                    journal.compare_and_swap(
                        &journal_key,
                        record.revision,
                        intent_record.clone(),
                    )?;
                    record = intent_record;

                    let applied = apply_restore_phase(self, bundle, target, &intent)?;
                    let final_receipt =
                        validate_applied_effect(self, bundle, &transaction, &intent, &applied)?;
                    let mut observed = record.clone();
                    observed.revision = next_revision(record.revision)?;
                    observed.state = RestoreJournalState::ReceiptPersisted;
                    observed.receipt = Some(applied.receipt);
                    observed.final_receipt = final_receipt;
                    journal.compare_and_swap(&journal_key, record.revision, observed.clone())?;
                    record = observed;
                }
            }
        }
    }
}

fn expected_restore_steps(bundle: &BackupBundle) -> Vec<RestoreStep> {
    let mut steps = vec![
        RestoreStep::PrepareIsolatedRoot,
        RestoreStep::ApplyPurgeLedger,
        RestoreStep::ImportSealedBlobs,
        RestoreStep::ImportCanonicalEvents,
        RestoreStep::ImportReceipts,
        RestoreStep::ImportProjections,
    ];
    if bundle.ors_snapshot.is_some() {
        steps.push(RestoreStep::SuspendOrsOperations);
    }
    steps.extend([
        RestoreStep::RebuildProjections,
        RestoreStep::VerifyReceiptEventChain,
        RestoreStep::FinalizeIsolatedRoot,
    ]);
    steps
}

fn restore_phases(bundle: &BackupBundle) -> Vec<RestorePhase> {
    let mut phases = vec![
        RestorePhase::PrepareIsolatedRoot,
        RestorePhase::ApplyPurgeLedger,
    ];
    phases.extend(
        bundle
            .blobs
            .iter()
            .map(|blob| RestorePhase::ImportSealedBlob {
                hash: blob.locator.hash.to_string(),
            }),
    );
    phases.extend(bundle.canonical_events.iter().map(|record| {
        RestorePhase::ImportCanonicalEvent {
            record_id: record.record_id.clone(),
        }
    }));
    phases.extend(
        bundle
            .receipts
            .iter()
            .map(|receipt| RestorePhase::ImportReceipt {
                operation_id: receipt.operation_id.to_string(),
            }),
    );
    phases.extend(
        bundle
            .projections
            .iter()
            .map(|record| RestorePhase::ImportProjection {
                record_id: record.record_id.clone(),
            }),
    );
    if bundle.ors_snapshot.is_some() {
        phases.push(RestorePhase::SuspendOrsOperations);
    }
    phases.extend([
        RestorePhase::RebuildProjections,
        RestorePhase::VerifyReceiptEventChain,
        RestorePhase::FinalizeIsolatedRoot,
    ]);
    phases
}

fn phase_index(phases: &[RestorePhase], phase: &RestorePhase) -> Result<usize, BackupError> {
    phases
        .iter()
        .position(|candidate| candidate == phase)
        .ok_or(BackupError::RestorePhaseMismatch)
}

fn next_revision(revision: u64) -> Result<u64, BackupError> {
    revision
        .checked_add(1)
        .ok_or(BackupError::RestoreJournalCorrupt)
}

fn validate_journal_record(
    record: &RestoreJournalRecord,
    journal_key: &str,
    transaction: &RestoreTransaction,
    phases: &[RestorePhase],
) -> Result<(), BackupError> {
    if record.journal_key != journal_key || record.transaction != *transaction {
        return Err(BackupError::RestoreJournalMismatch);
    }
    let completed_phases =
        usize::try_from(record.completed_phases).map_err(|_| BackupError::RestorePhaseMismatch)?;
    if completed_phases > phases.len() {
        return Err(BackupError::RestorePhaseMismatch);
    }
    if matches!(record.phase, RestorePhase::Pending) {
        if completed_phases != 0 || !matches!(record.state, RestoreJournalState::Ready) {
            return Err(BackupError::RestorePhaseMismatch);
        }
    } else if !matches!(record.state, RestoreJournalState::Completed) {
        let index = phase_index(phases, &record.phase)?;
        if index != completed_phases {
            return Err(BackupError::RestorePhaseMismatch);
        }
    }
    match record.state {
        RestoreJournalState::Ready => {
            if record.intent.is_some() || record.receipt.is_some() || record.final_receipt.is_some()
            {
                return Err(BackupError::RestoreJournalCorrupt);
            }
        }
        RestoreJournalState::IntentPersisted => {
            let intent = record
                .intent
                .as_ref()
                .ok_or(BackupError::RestoreJournalCorrupt)?;
            if intent.transaction_id != transaction.transaction_id
                || intent.phase != record.phase
                || record.receipt.is_some()
                || intent.input_digest
                    != sha256(&(transaction.transaction_id.as_str(), &record.phase))?
            {
                return Err(BackupError::RestoreJournalCorrupt);
            }
        }
        RestoreJournalState::ReceiptPersisted => {
            let intent = record
                .intent
                .as_ref()
                .ok_or(BackupError::RestoreJournalCorrupt)?;
            let receipt = record
                .receipt
                .as_ref()
                .ok_or(BackupError::RestoreJournalCorrupt)?;
            if intent.transaction_id != transaction.transaction_id
                || intent.phase != record.phase
                || receipt.transaction_id != transaction.transaction_id
                || receipt.phase != record.phase
                || (matches!(record.phase, RestorePhase::FinalizeIsolatedRoot)
                    != record.final_receipt.is_some())
            {
                return Err(BackupError::RestoreJournalCorrupt);
            }
            validate_effect_receipt(intent, receipt)?;
            if matches!(record.phase, RestorePhase::FinalizeIsolatedRoot)
                && record.final_receipt.is_none()
            {
                return Err(BackupError::RestoreJournalCorrupt);
            }
        }
        RestoreJournalState::Completed => {
            if completed_phases != phases.len()
                || !matches!(record.phase, RestorePhase::FinalizeIsolatedRoot)
                || record.final_receipt.is_none()
            {
                return Err(BackupError::RestoreJournalCorrupt);
            }
            let final_receipt = record
                .final_receipt
                .as_ref()
                .ok_or(BackupError::RestoreJournalCorrupt)?;
            if final_receipt.bundle_sha256 != transaction.bundle_sha256 {
                return Err(BackupError::RestoreJournalMismatch);
            }
            let effect_receipt = record
                .receipt
                .as_ref()
                .ok_or(BackupError::RestoreJournalCorrupt)?;
            let intent = record
                .intent
                .as_ref()
                .ok_or(BackupError::RestoreJournalCorrupt)?;
            validate_effect_receipt(intent, effect_receipt)?;
            if final_receipt.effect_receipt_sha256 != sha256(effect_receipt)? {
                return Err(BackupError::RestoreJournalCorrupt);
            }
        }
        RestoreJournalState::RollbackRequired => {
            if record.intent.is_none() || record.receipt.is_some() || record.final_receipt.is_some()
            {
                return Err(BackupError::RestoreJournalCorrupt);
            }
        }
    }
    Ok(())
}

fn restore_intent(
    transaction: &RestoreTransaction,
    phase: &RestorePhase,
) -> Result<RestoreIntent, BackupError> {
    let input_digest = sha256(&(transaction.transaction_id.as_str(), phase))?;
    Ok(RestoreIntent {
        transaction_id: transaction.transaction_id.clone(),
        phase: phase.clone(),
        input_digest,
    })
}

fn validate_effect_receipt(
    intent: &RestoreIntent,
    receipt: &RestoreEffectReceipt,
) -> Result<(), BackupError> {
    if receipt.transaction_id != intent.transaction_id
        || receipt.phase != intent.phase
        || receipt.input_digest != intent.input_digest
    {
        return Err(BackupError::RestoreJournalCorrupt);
    }
    digest(
        &receipt.external_identity_sha256,
        "restore.external_identity_sha256",
    )
    .map_err(|_| BackupError::RestoreJournalCorrupt)?;
    digest(&receipt.evidence_sha256, "restore.evidence_sha256")
        .map_err(|_| BackupError::RestoreJournalCorrupt)?;
    Ok(())
}

fn apply_restore_phase<T: RestoreTarget>(
    plan: &RestorePlan,
    bundle: &BackupBundle,
    target: &mut T,
    intent: &RestoreIntent,
) -> Result<RestoreAppliedEffect, BackupError> {
    if matches!(intent.phase, RestorePhase::Pending) {
        return Err(BackupError::RestorePhaseMismatch);
    }
    target.apply_restore_effect(plan, bundle, intent)
}

fn validate_applied_effect(
    plan: &RestorePlan,
    bundle: &BackupBundle,
    transaction: &RestoreTransaction,
    intent: &RestoreIntent,
    applied: &RestoreAppliedEffect,
) -> Result<Option<RestoreReceipt>, BackupError> {
    validate_effect_receipt(intent, &applied.receipt)?;
    let is_final = matches!(intent.phase, RestorePhase::FinalizeIsolatedRoot);
    if !is_final {
        if applied.final_evidence.is_some() {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        return Ok(None);
    }
    let evidence = applied
        .final_evidence
        .as_ref()
        .ok_or(BackupError::RestoreEvidenceIncomplete)?;
    evidence.validate()?;
    let expected_level = RestoreEvidenceLevel::for_class(bundle.manifest.class);
    if evidence.evidence_level() != expected_level {
        return Err(BackupError::RestoreEvidenceLevelMismatch);
    }
    if sha256(evidence)? != applied.receipt.evidence_sha256 {
        return Err(BackupError::FinalizeEvidenceMismatch);
    }
    evidence.validate_against_plan(plan, bundle)?;
    Ok(Some(RestoreReceipt {
        receipt_id: format!("restore-receipt-{}", plan.plan_id),
        plan_id: plan.plan_id.clone(),
        bundle_sha256: transaction.bundle_sha256.clone(),
        target_id: plan.target.target_id.clone(),
        restored_fence: plan.restored_fence.clone(),
        effect_receipt_sha256: sha256(&applied.receipt)?,
        evidence_level: RestoreEvidenceLevel::for_class(bundle.manifest.class),
        canonical_only: bundle.manifest.class != BackupClass::FullRecovery,
        operational_recovery_ready: false,
        cutover_performed: false,
    }))
}

/// Distinct restore proof ceilings. Archive class validity, isolated import,
/// effect reconciliation, operational validation, and cutover are different
/// evidence levels; no later level is inferred from an enum class or Boolean.
///
/// - `ArchiveValid`: the bundle passed archive/build verification only.
/// - `IsolatedImportComplete`: the isolated root imported bytes, purge,
///   receipts, and projections with no active authority.
/// - `ReconciliationRequired`: import is staged but external effects remain
///   unresolved; operational claims and cutover are forbidden.
/// - `OperationallyValidated`: the exact owner issued bounded validation
///   evidence for the isolated root (outside this library).
/// - `Cutover`: a separate Human/System Owner authorization (outside this
///   library; this library never emits it).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreEvidenceLevel {
    ArchiveValid,
    IsolatedImportComplete,
    ReconciliationRequired,
    OperationallyValidated,
    Cutover,
}

impl RestoreEvidenceLevel {
    /// Returns the highest level this library may certify for one class.
    #[must_use]
    pub const fn for_class(class: BackupClass) -> Self {
        match class {
            // A full archive can be valid while its isolated import still
            // requires effect reconciliation (I5.13/ORS suspension rule); a
            // scope transfer can never report installation recovery.
            BackupClass::FullRecovery => Self::ReconciliationRequired,
            BackupClass::CanonicalOnlyDegraded | BackupClass::ScopeExport => {
                Self::IsolatedImportComplete
            }
        }
    }

    /// Returns whether this level may assert operational recovery readiness.
    ///
    /// Only owner-issued [`OperationalValidationEvidence`] at
    /// `OperationallyValidated` (and a separate cutover authority at
    /// `Cutover`) may do so; the levels this library emits never qualify.
    #[must_use]
    pub const fn permits_operational_readiness(self) -> bool {
        match self {
            Self::ArchiveValid | Self::IsolatedImportComplete | Self::ReconciliationRequired => {
                false
            }
            Self::OperationallyValidated | Self::Cutover => true,
        }
    }
}

/// Exact trust binding under which an owner identity was authenticated.
///
/// The binding is the minimal composition-boundary receipt reference (owner
/// identity plus the transport/session/key material that authenticated it);
/// arbitrary decoded data never certifies itself through a local hash.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerTrustBinding {
    pub owner_id: String,
    pub trust_binding_ref: String,
}

impl OwnerTrustBinding {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.owner_id, "owner.owner_id")?;
        text(&self.trust_binding_ref, "owner.trust_binding_ref")?;
        Ok(())
    }
}

/// One attributable owner obligation for a restore evidence bundle.
///
/// Each applicable obligation is represented either by the minimal exact
/// existing owner receipt/reference (an opaque, owner-issued, authenticated
/// string whose issuer is named in `owner_id`) or by an explicit
/// [`RestoreObligationState::MissingCapability`]. Execution of unresolved
/// obligations belongs to the real owner integration (#960/#961); its absence
/// must not be hidden as successful library execution. UI/broker invalidation
/// belongs to the real runtime owner when that integration is present.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreOwnerObligation {
    pub owner_id: String,
    pub evidence_ref: String,
    pub state: RestoreObligationState,
}

/// Attributable state of one owner obligation.
///
/// `Satisfied` carries no payload beyond the owner-issued reference on the
/// enclosing obligation: the reference itself is the minimal exact owner
/// receipt. `NotAttempted`/`Unknown` preserve the class/capability/identity
/// distinction required by diagnostics; unknown possible effect stays unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreObligationState {
    Satisfied,
    NotAttempted,
    Unknown,
    MissingCapability,
}

/// Observed lineage ceiling bound by the exact owner contract.
///
/// The library validates candidate epochs against every relevant observed
/// limit; it never mints authority by incrementing an integer. New epochs must
/// exceed all relevant observed authority lineages under their owner's
/// contract before the owner issues [`RestoreOwnerEpoch`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedLineageLimit {
    pub owner_id: String,
    pub observed_epoch: EpochId,
    pub observed_generation: ResourceGeneration,
}

impl ObservedLineageLimit {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.owner_id, "lineage_limit.owner_id")?;
        Ok(())
    }
}

/// Exact owner-issued new-epoch evidence.
///
/// Authenticated at the real owner/composition boundary. A caller-proposed
/// target epoch (see [`RestoreContext`]) is planning input, not accepted
/// authority; only this owner-issued value may support cutover, and cutover
/// itself remains a separate authorization (#961) outside this library.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreOwnerEpoch {
    pub owner: OwnerTrustBinding,
    pub new_epoch: EpochId,
    pub new_generation: ResourceGeneration,
    pub supersedes: Vec<ObservedLineageLimit>,
}

impl RestoreOwnerEpoch {
    pub fn validate(&self) -> Result<(), BackupError> {
        self.owner.validate()?;
        if self.supersedes.is_empty() {
            return Err(BackupError::RestoreEvidenceIncomplete);
        }
        for limit in &self.supersedes {
            limit.validate()?;
            let same_lineage = self.new_epoch.lineage_id == limit.observed_epoch.lineage_id;
            let advances = if same_lineage {
                self.new_epoch.sequence.get() > limit.observed_epoch.sequence.get()
            } else {
                self.new_epoch.sequence.get() == 1
            };
            if !advances || self.new_generation <= limit.observed_generation {
                return Err(BackupError::StaleRestoreLineage);
            }
        }
        // The exact-tuple rule (`EpochId::is_same_authority`): equal sequences
        // from different lineages are unrelated and never authorize, so a
        // candidate that reuses an observed sequence under a different lineage
        // with a non-genesis sequence is rejected above.
        Ok(())
    }
}

/// Bounded owner-issued validation evidence for an isolated root.
///
/// Transport acknowledgement, content equality, checksum validity, a phase
/// count, or a self-asserted `active_authority_restored = false` is
/// insufficient operational proof. Only the exact owner named in `owner` may
/// issue this evidence, and only for the exact isolated destination named in
/// `target_ref`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalValidationEvidence {
    pub owner: OwnerTrustBinding,
    pub target_ref: String,
    pub validation_digest: String,
    pub observed_at_state_fence: StateFence,
}

impl OperationalValidationEvidence {
    pub fn validate(&self) -> Result<(), BackupError> {
        self.owner.validate()?;
        text(&self.target_ref, "operational.target_ref")?;
        digest(&self.validation_digest, "operational.validation_digest")?;
        self.observed_at_state_fence
            .validate()
            .map_err(|error| BackupError::Foundation(error.to_string()))?;
        Ok(())
    }
}

/// Complete current owner-issued denominator for a known-zero unresolved
/// count.
///
/// A complete known-zero unresolved count requires a complete current
/// owner-issued denominator: `expected_total` is the exact owner-issued count
/// of known reconciliation items and `reconciled_refs` names each reconciled
/// item. Suspension is not resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationDenominator {
    pub owner_id: String,
    pub denominator_ref: String,
    pub expected_total: u64,
    pub reconciled_refs: Vec<String>,
}

impl ReconciliationDenominator {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.owner_id, "reconciliation.owner_id")?;
        text(&self.denominator_ref, "reconciliation.denominator_ref")?;
        unique(
            self.reconciled_refs.iter().cloned(),
            "reconciliation.reconciled_refs",
        )?;
        for reference in &self.reconciled_refs {
            text(reference, "reconciliation.reconciled_ref")?;
        }
        if self.reconciled_refs.len() as u64 != self.expected_total {
            return Err(BackupError::RestoreEvidenceIncomplete);
        }
        Ok(())
    }

    /// Returns whether the denominator proves known-zero unresolved work.
    #[must_use]
    pub fn is_known_zero(&self) -> bool {
        // `validate` already enforces `reconciled == expected_total`; a
        // zero total with zero reconciled refs is the only known-zero shape.
        self.expected_total == 0 && self.reconciled_refs.is_empty()
    }
}

/// Separately attributable owner obligations bound to one restore.
///
/// Every field is load-bearing: each applicable obligation carries the minimal
/// exact existing owner receipt/reference or an explicit missing capability.
/// `watchdog_spool`/`external_source`/`ui_broker` default to
/// `MissingCapability` so absent evidence fails closed instead of reading as
/// success; `MissingCapability` is a typed explicit state, not success.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreObligations {
    pub purge: RestoreOwnerObligation,
    pub canonical_validation: RestoreOwnerObligation,
    pub reference_validation: RestoreOwnerObligation,
    pub blob_validation: RestoreOwnerObligation,
    pub ors_suspension: RestoreOwnerObligation,
    pub unresolved_effect_reconciliation: RestoreOwnerObligation,
    pub watchdog_signals: RestoreOwnerObligation,
    pub external_source_revalidation: RestoreOwnerObligation,
    pub runtime_invalidation: RestoreOwnerObligation,
    pub session_invalidation: RestoreOwnerObligation,
    pub lease_invalidation: RestoreOwnerObligation,
    pub route_invalidation: RestoreOwnerObligation,
    pub user_broker_invalidation: RestoreOwnerObligation,
}

impl RestoreObligations {
    pub fn validate(&self) -> Result<(), BackupError> {
        for obligation in self.all() {
            text(&obligation.owner_id, "obligation.owner_id")?;
            text(&obligation.evidence_ref, "obligation.evidence_ref")?;
            // `MissingCapability` and `NotAttempted`/`Unknown` are explicit
            // typed states; only structurally invalid identities fail here.
            // Unsatisfied applicable obligations gate readiness in
            // `RestoreEvidence::operationally_validated_by_owner`.
        }
        Ok(())
    }

    fn all(&self) -> [&RestoreOwnerObligation; 13] {
        [
            &self.purge,
            &self.canonical_validation,
            &self.reference_validation,
            &self.blob_validation,
            &self.ors_suspension,
            &self.unresolved_effect_reconciliation,
            &self.watchdog_signals,
            &self.external_source_revalidation,
            &self.runtime_invalidation,
            &self.session_invalidation,
            &self.lease_invalidation,
            &self.route_invalidation,
            &self.user_broker_invalidation,
        ]
    }

    /// Returns whether every obligation is satisfied by its exact owner.
    #[must_use]
    pub fn all_satisfied(&self) -> bool {
        self.all()
            .iter()
            .all(|obligation| obligation.state == RestoreObligationState::Satisfied)
    }
}

/// Full provenance and identity binding for one isolated restore.
///
/// Binds transaction/phase/operation identity, source archive/class/digest,
/// source and isolated destination, expected predecessor, current
/// schema/build/purge revision, owner identity/trust binding,
/// generation/epoch, and bounded validation evidence. A supplied journal
/// object is not automatically an admitted durable journal: production
/// composition must bind the current persistent owner, exact
/// database/installation/generation, journal identity, and receipt
/// (see [`RestoreJournalAdmission`]).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreProvenance {
    pub transaction_id: String,
    pub plan_id: String,
    pub operation_id: String,
    pub phase: RestorePhase,
    pub source_archive_id: String,
    pub source_class: BackupClass,
    pub source_digest: String,
    pub source_endpoint_ref: String,
    pub isolated_destination_ref: String,
    pub expected_predecessor_ref: String,
    pub schema_revision: String,
    pub build_manifest_digest: String,
    pub purge_ledger_revision: u64,
    pub owner: OwnerTrustBinding,
    pub observed_generation: ResourceGeneration,
    pub observed_epoch: EpochId,
    pub validation_digest: String,
}

impl RestoreProvenance {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.transaction_id, "provenance.transaction_id")?;
        text(&self.plan_id, "provenance.plan_id")?;
        text(&self.operation_id, "provenance.operation_id")?;
        text(&self.source_archive_id, "provenance.source_archive_id")?;
        digest(&self.source_digest, "provenance.source_digest")?;
        text(&self.source_endpoint_ref, "provenance.source_endpoint_ref")?;
        text(
            &self.isolated_destination_ref,
            "provenance.isolated_destination_ref",
        )?;
        text(
            &self.expected_predecessor_ref,
            "provenance.expected_predecessor_ref",
        )?;
        text(&self.schema_revision, "provenance.schema_revision")?;
        digest(
            &self.build_manifest_digest,
            "provenance.build_manifest_digest",
        )?;
        digest(&self.validation_digest, "provenance.validation_digest")?;
        self.owner.validate()?;
        Ok(())
    }
}

/// Production admission binding for the durable journal behind a restore.
///
/// An in-memory fixture has only fixture proof; a supplied journal object is
/// not automatically an admitted durable journal. Production composition must
/// bind the current persistent owner, exact database/installation/generation,
/// journal identity, and receipt. There is no no-op production fallback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournalAdmission {
    pub persistent_owner: OwnerTrustBinding,
    pub database_ref: String,
    pub installation_ref: String,
    pub generation: ResourceGeneration,
    pub journal_identity_ref: String,
    pub admission_receipt_ref: String,
    pub fixture_proof_only: bool,
}

impl RestoreJournalAdmission {
    pub fn validate(&self) -> Result<(), BackupError> {
        self.persistent_owner.validate()?;
        text(&self.database_ref, "journal.database_ref")?;
        text(&self.installation_ref, "journal.installation_ref")?;
        text(&self.journal_identity_ref, "journal.journal_identity_ref")?;
        text(&self.admission_receipt_ref, "journal.admission_receipt_ref")?;
        Ok(())
    }

    /// Returns whether this admission may back a production
    /// durable-recovery claim. Fixture-only journals never qualify.
    #[must_use]
    pub const fn admits_production_durable_recovery(&self) -> bool {
        !self.fixture_proof_only
    }
}

/// Evidence returned by the isolated target after all restore steps complete.
///
/// Boolean import claims alone are not proof of reconciliation, operational
/// readiness, or cutover. Every evidence value carries:
///
/// - [`RestoreProvenance`]: transaction/phase/operation identity, source
///   archive/class/digest, source and isolated destination, expected
///   predecessor, schema/build/purge revision, owner identity/trust binding,
///   generation/epoch, and bounded validation evidence;
/// - [`RestoreObligations`]: separately attributable owner obligations (purge,
///   canonical/reference/blob validation, ORS suspension, unresolved-effect
///   reconciliation, Watchdog signals, external-source revalidation,
///   runtime/session/lease/route/UserBroker invalidation), each as the minimal
///   exact owner receipt/reference or an explicit missing capability;
/// - [`ObservedLineageLimit`]s plus optional owner-issued
///   [`RestoreOwnerEpoch`]: proposal-vs-authority separation for epochs (this
///   library validates, never mints);
/// - optional [`ReconciliationDenominator`]: the complete current
///   owner-issued denominator required for a known-zero unresolved count
///   (suspension is not resolution);
/// - optional [`OperationalValidationEvidence`]: bounded owner-issued
///   validation evidence for the isolated root (only the exact named owner
///   may issue it).
///
/// Old sessions/leases/routes/epochs are preserved only as
/// historical/suspended evidence (see
/// [`RestoreHistoricalAuthority`]); no library output activates them,
/// unblocks effects, performs cutover, or retires the source. Closed current
/// schemas reject unknown/duplicate fields; valid historical archives are
/// preserved through explicit compatibility/disposition
/// ([`RestoreArchiveDisposition`]), not silent reinterpretation.
//
// The six import-claim booleans are a fixed wire-compatibility surface, not a
// fungible flag bag: each names one distinct isolated-import gate checked in
// `validate`, and collapsing them would break the frozen archive/evidence
// shape. They never assert reconciliation, readiness, or cutover on their own.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RestoreEvidence {
    pub target_id: String,
    pub isolated_root: bool,
    pub purge_applied: bool,
    pub blobs_imported: bool,
    pub projections_rebuilt: bool,
    pub receipt_event_chain_verified: bool,
    pub ors_suspended: bool,
    pub active_authority_restored: bool,
    pub authority_epoch: EpochId,
    pub resource_generation: ResourceGeneration,
    pub provenance: RestoreProvenance,
    pub obligations: RestoreObligations,
    pub observed_lineage_limits: Vec<ObservedLineageLimit>,
    pub owner_epoch: Option<RestoreOwnerEpoch>,
    pub reconciliation_denominator: Option<ReconciliationDenominator>,
    pub operational_validation: Option<OperationalValidationEvidence>,
    pub historical_authority: Vec<RestoreHistoricalAuthority>,
    pub archive_disposition: RestoreArchiveDisposition,
}

impl RestoreEvidence {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.target_id, "restore.evidence.target_id")?;
        if !self.isolated_root
            || !self.purge_applied
            || !self.blobs_imported
            || !self.projections_rebuilt
            || !self.receipt_event_chain_verified
            || self.active_authority_restored
        {
            return Err(BackupError::RestoreEvidenceIncomplete);
        }
        self.provenance.validate()?;
        if self.provenance.observed_epoch.lineage_id != self.authority_epoch.lineage_id
            || self.provenance.observed_epoch.sequence != self.authority_epoch.sequence
            || self.provenance.observed_generation != self.resource_generation
            || self.provenance.isolated_destination_ref != self.target_id
        {
            return Err(BackupError::FinalizeEvidenceMismatch);
        }
        self.provenance.owner.validate()?;
        self.obligations.validate()?;
        if self.observed_lineage_limits.is_empty() {
            return Err(BackupError::RestoreEvidenceIncomplete);
        }
        for limit in &self.observed_lineage_limits {
            limit.validate()?;
        }
        unique(
            self.observed_lineage_limits
                .iter()
                .map(|limit| limit.owner_id.clone()),
            "evidence.observed_lineage_limits",
        )?;
        if let Some(owner_epoch) = &self.owner_epoch {
            owner_epoch.validate()?;
        }
        if let Some(denominator) = &self.reconciliation_denominator {
            denominator.validate()?;
        }
        if let Some(operational) = &self.operational_validation {
            operational.validate()?;
            if operational.target_ref != self.target_id {
                return Err(BackupError::FinalizeEvidenceMismatch);
            }
        }
        for historical in &self.historical_authority {
            historical.validate()?;
        }
        self.archive_disposition.validate()?;
        Ok(())
    }

    /// Returns the highest proof level this library may certify from the
    /// archive class carried in provenance. Never inferred from a Boolean.
    #[must_use]
    pub fn evidence_level(&self) -> RestoreEvidenceLevel {
        RestoreEvidenceLevel::for_class(self.provenance.source_class)
    }

    /// Validates identity bindings against the compiled plan and bundle.
    pub fn validate_against_plan(
        &self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
    ) -> Result<(), BackupError> {
        if self.target_id != plan.target.target_id
            || !self
                .authority_epoch
                .is_same_authority(&plan.restored_fence.authority_epoch)
            || self.resource_generation != plan.restored_fence.resource_generation
        {
            return Err(BackupError::FinalizeEvidenceMismatch);
        }
        if self.provenance.plan_id != plan.plan_id
            || self.provenance.source_archive_id != bundle.manifest.backup_id
            || self.provenance.source_class != bundle.manifest.class
            || self.provenance.source_digest != bundle.bundle_sha256()?
            || self.provenance.purge_ledger_revision != bundle.manifest.purge_ledger_revision
            || self.provenance.schema_revision != bundle.manifest.schema_generation
        {
            return Err(BackupError::FinalizeEvidenceMismatch);
        }
        if bundle.ors_snapshot.is_some()
            && (!self.ors_suspended
                || self.obligations.ors_suspension.state != RestoreObligationState::Satisfied)
        {
            return Err(BackupError::RestoreEvidenceIncomplete);
        }
        Ok(())
    }

    /// Returns owner-issued operational validation only when every gate holds:
    /// isolated root with no active authority, all obligations satisfied by
    /// their exact owners, a complete current denominator proving known-zero
    /// unresolved work, and bounded validation evidence from the exact owner
    /// for this exact isolated destination. Otherwise returns
    /// [`BackupError::RestoreEvidenceIncomplete`] (fail-closed); absence of
    /// evidence is never success.
    pub fn operationally_validated_by_owner(
        &self,
    ) -> Result<&OperationalValidationEvidence, BackupError> {
        let operational = self
            .operational_validation
            .as_ref()
            .ok_or(BackupError::RestoreEvidenceIncomplete)?;
        if !self.isolated_root || self.active_authority_restored {
            return Err(BackupError::RestoreEvidenceIncomplete);
        }
        if !self.obligations.all_satisfied() {
            return Err(BackupError::RestoreEvidenceIncomplete);
        }
        match &self.reconciliation_denominator {
            Some(denominator) if denominator.is_known_zero() => {}
            _ => return Err(BackupError::RestoreEvidenceIncomplete),
        }
        operational.validate()?;
        if operational.target_ref != self.target_id {
            return Err(BackupError::FinalizeEvidenceMismatch);
        }
        Ok(operational)
    }
}

/// Historical/suspended authority preserved as evidence only.
///
/// Old sessions, leases, routes, broker registrations, and epochs return only
/// in this shape. No library output may activate them, unblock effects,
/// perform cutover, or retire the source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreHistoricalAuthority {
    pub kind: RestoreHistoricalKind,
    pub historical_ref: String,
    pub suspended: bool,
}

impl RestoreHistoricalAuthority {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.historical_ref, "historical.historical_ref")?;
        if !self.suspended {
            return Err(BackupError::HistoricalAuthorityActivated);
        }
        Ok(())
    }
}

/// Closed kind vocabulary for preserved historical authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreHistoricalKind {
    Session,
    Lease,
    Route,
    UserBrokerRegistration,
    AuthorityEpoch,
    OrsOperation,
    WatchdogSignal,
}

/// Explicit compatibility/disposition for the source archive.
///
/// Valid historical archives are preserved through this explicit disposition,
/// never through silent reinterpretation or fabricated missing evidence.
/// Closed current schemas reject unknown/duplicate fields at the byte
/// boundary (all evidence structs use `deny_unknown_fields`); legacy bytes
/// decode only into this dispositional envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreArchiveDisposition {
    pub disposition: RestoreArchiveDispositionKind,
    pub compatibility_ref: String,
}

impl RestoreArchiveDisposition {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(
            &self.compatibility_ref,
            "archive_disposition.compatibility_ref",
        )?;
        Ok(())
    }
}

/// Closed disposition vocabulary for source archives.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreArchiveDispositionKind {
    Current,
    HistoricalPreserved,
    Rejected,
}

/// Immutable receipt of an isolated restore. It is not a cutover receipt.
///
/// `operational_recovery_ready` is always `false` from this library: only the
/// exact owner named in [`OperationalValidationEvidence`] may assert
/// operational readiness (at [`RestoreEvidenceLevel::OperationallyValidated`])
/// for the exact isolated destination, and cutover requires a separate
/// Human/System Owner authorization (at [`RestoreEvidenceLevel::Cutover`]).
/// `cutover_performed` is always `false` here. `canonical_only` distinguishes
/// degraded/scope imports from full archives without upgrading them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReceipt {
    pub receipt_id: String,
    pub plan_id: String,
    pub bundle_sha256: String,
    pub target_id: String,
    pub restored_fence: RestoredFence,
    pub effect_receipt_sha256: String,
    pub evidence_level: RestoreEvidenceLevel,
    pub canonical_only: bool,
    pub operational_recovery_ready: bool,
    pub cutover_performed: bool,
}

impl RestoreReceipt {
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.receipt_id, "restore.receipt.receipt_id")?;
        text(&self.plan_id, "restore.receipt.plan_id")?;
        digest(&self.bundle_sha256, "restore.receipt.bundle_sha256")?;
        text(&self.target_id, "restore.receipt.target_id")?;
        self.restored_fence
            .validate()
            .map_err(|_| BackupError::RestoreEvidenceIncomplete)?;
        digest(
            &self.effect_receipt_sha256,
            "restore.receipt.effect_receipt_sha256",
        )?;
        if self.cutover_performed {
            return Err(BackupError::CutoverNotAuthorized);
        }
        if self.operational_recovery_ready {
            if self.evidence_level != RestoreEvidenceLevel::OperationallyValidated {
                return Err(BackupError::RestoreEvidenceLevelMismatch);
            }
        } else if self.evidence_level.permits_operational_readiness() {
            return Err(BackupError::RestoreEvidenceLevelMismatch);
        }
        Ok(())
    }
}

/// Provider-owned isolated restore target. Implementations must not make the
/// target current authority as part of any method in this trait.
///
/// The historical per-step methods below (`prepare_isolated`,
/// `apply_purge_ledger`, `import_sealed_blob`, `import_canonical_event`,
/// `import_receipt`, `import_projection`, `suspend_ors_operations`,
/// `rebuild_projections`, `verify_receipt_event_chain`, `finalize_isolated`)
/// are the exact historical seam retained for owner adapters (#960/#961); no
/// new per-obligation target methods are invented here. Each applicable owner
/// obligation (purge, canonical/reference/blob validation, ORS suspension,
/// unresolved-effect reconciliation, Watchdog signals, external-source
/// revalidation, runtime/session/lease/route/UserBroker invalidation) is
/// represented in [`RestoreEvidence`] by the minimal exact existing owner
/// receipt/reference or an explicit missing capability.
pub trait RestoreTarget {
    /// Applies one exact intent and returns a target-observed receipt. The
    /// default is fail-closed so legacy targets cannot mint coordinator-side
    /// success without migrating to this receipt-bearing seam.
    fn apply_restore_effect(
        &mut self,
        _plan: &RestorePlan,
        _bundle: &BackupBundle,
        _intent: &RestoreIntent,
    ) -> Result<RestoreAppliedEffect, BackupError> {
        Err(BackupError::RestoreTargetReceiptRequired)
    }

    /// Reconciles an intent left durable by a prior process. The default is
    /// deliberately unknown, forcing rollback/escalation rather than guessing.
    fn reconcile_restore_effect(
        &mut self,
        _intent: &RestoreIntent,
    ) -> Result<RestoreReconciliation, BackupError> {
        Ok(RestoreReconciliation::Unknown)
    }

    fn prepare_isolated(
        &mut self,
        context: &RestoreContext,
        restored_fence: &RestoredFence,
    ) -> Result<(), BackupError>;
    fn apply_purge_ledger(&mut self, entries: &[PurgeLedgerEntry]) -> Result<(), BackupError>;
    fn import_sealed_blob(&mut self, blob: &BackupBlob) -> Result<(), BackupError>;
    fn import_canonical_event(&mut self, record: &CanonicalRecord) -> Result<(), BackupError>;
    fn import_receipt(&mut self, receipt: &WriteReceipt) -> Result<(), BackupError>;
    fn import_projection(&mut self, record: &CanonicalRecord) -> Result<(), BackupError>;
    fn suspend_ors_operations(&mut self, snapshot: &OrsSnapshotFence) -> Result<(), BackupError>;
    fn rebuild_projections(&mut self, restored_fence: &RestoredFence) -> Result<(), BackupError>;
    fn verify_receipt_event_chain(
        &mut self,
        receipts: &[WriteReceipt],
        events: &[CanonicalRecord],
    ) -> Result<(), BackupError>;
    fn finalize_isolated(
        &mut self,
        restored_fence: &RestoredFence,
    ) -> Result<RestoreEvidence, BackupError>;
}

/// Typed failures that preserve integrity and recovery boundaries.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum BackupError {
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("duplicate values in {field}")]
    Duplicate { field: &'static str },
    #[error("inconsistent export boundary")]
    InconsistentBoundary,
    #[error("unsupported exchange format {0}")]
    UnsupportedFormat(String),
    #[error("integrity mismatch for {subject}")]
    IntegrityMismatch { subject: String },
    #[error("fence mismatch for {subject}")]
    FenceMismatch { subject: String },
    #[error("receipt/event chain gap for event {event_id}")]
    ReceiptChainGap { event_id: String },
    #[error("missing referenced blob")]
    MissingBlob,
    #[error("unreferenced blob {hash}")]
    UnreferencedBlob { hash: String },
    #[error("missing full-recovery component {0}")]
    MissingRecoveryComponent(&'static str),
    #[error("full-recovery export contains declared gaps")]
    FullRecoveryHasGaps,
    #[error("unexpected recovery component {0}")]
    UnexpectedRecoveryComponent(&'static str),
    #[error("scope export requires one declared scope")]
    ScopeRequired,
    #[error("non-scope export cannot carry a scope")]
    ScopeUnexpected,
    #[error("active authority cannot be present in backup or restore")]
    ActiveAuthorityInBackup,
    #[error("watchdog spool must be bounded")]
    UnboundedWatchdogSpool,
    #[error("plaintext key material is forbidden in ECXF")]
    PlaintextKeyMaterial,
    #[error("restore lineage must be newer than every observed source lineage")]
    StaleRestoreLineage,
    #[error("restore plan does not match the supplied bundle")]
    PlanMismatch,
    #[error("restore journal is required for recoverable execution")]
    RestoreJournalRequired,
    #[error("restore journal transaction does not match the exact plan/context identity")]
    RestoreJournalMismatch,
    #[error("restore journal has an invalid phase/state transition")]
    RestorePhaseMismatch,
    #[error("restore journal record is corrupt or incomplete")]
    RestoreJournalCorrupt,
    #[error("restore journal CAS revision is stale")]
    RestoreJournalCasConflict,
    #[error("restore target must return an observed effect receipt")]
    RestoreTargetReceiptRequired,
    #[error("ROLLBACK_REQUIRED: restore effect outcome is not durably reconciled")]
    RestoreRollbackRequired,
    #[error("restore target returned incomplete evidence")]
    RestoreEvidenceIncomplete,
    #[error("restore target evidence does not match the plan")]
    FinalizeEvidenceMismatch,
    #[error("restore evidence level does not match the archive class ceiling")]
    RestoreEvidenceLevelMismatch,
    #[error("required class capability is absent before target dispatch")]
    RestoreCapabilityUnsupported { capability: &'static str },
    #[error("required class capability was not attempted")]
    RestoreCapabilityNotAttempted { capability: &'static str },
    #[error("historical authority must remain suspended and never activate")]
    HistoricalAuthorityActivated,
    #[error("cutover requires a separate Human/System Owner authorization")]
    CutoverNotAuthorized,
    #[error("record or artifact exceeds the {field} limit of {limit} bytes")]
    LimitExceeded { field: &'static str, limit: usize },
    #[error("foundation contract: {0}")]
    Foundation(String),
    #[error("security contract: {0}")]
    Security(String),
    #[error("blob contract: {0}")]
    Blob(String),
    #[error("store contract: {0}")]
    Store(StoreError),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("restore target failed: {0}")]
    Target(String),
}

impl From<BlobError> for BackupError {
    fn from(error: BlobError) -> Self {
        Self::Blob(error.to_string())
    }
}

#[cfg(test)]
mod restore_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_epoch_in(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_owner(owner_id: &str) -> OwnerTrustBinding {
        OwnerTrustBinding {
            owner_id: owner_id.to_owned(),
            trust_binding_ref: format!("trust-binding-{owner_id}-session-1"),
        }
    }

    fn test_obligation(owner_id: &str, state: RestoreObligationState) -> RestoreOwnerObligation {
        RestoreOwnerObligation {
            owner_id: owner_id.to_owned(),
            evidence_ref: format!("receipt-{owner_id}-1"),
            state,
        }
    }

    fn test_obligations(
        ors: RestoreObligationState,
        unresolved: RestoreObligationState,
        broker: RestoreObligationState,
    ) -> RestoreObligations {
        RestoreObligations {
            purge: test_obligation("purge-owner", RestoreObligationState::Satisfied),
            canonical_validation: test_obligation(
                "canonical-owner",
                RestoreObligationState::Satisfied,
            ),
            reference_validation: test_obligation(
                "reference-owner",
                RestoreObligationState::Satisfied,
            ),
            blob_validation: test_obligation("blob-owner", RestoreObligationState::Satisfied),
            ors_suspension: test_obligation("ors-owner", ors),
            unresolved_effect_reconciliation: test_obligation("reconciliation-owner", unresolved),
            watchdog_signals: test_obligation("watchdog-owner", RestoreObligationState::Satisfied),
            external_source_revalidation: test_obligation(
                "external-source-owner",
                RestoreObligationState::Satisfied,
            ),
            runtime_invalidation: test_obligation(
                "runtime-owner",
                RestoreObligationState::Satisfied,
            ),
            session_invalidation: test_obligation(
                "session-owner",
                RestoreObligationState::Satisfied,
            ),
            lease_invalidation: test_obligation("lease-owner", RestoreObligationState::Satisfied),
            route_invalidation: test_obligation("route-owner", RestoreObligationState::Satisfied),
            user_broker_invalidation: test_obligation("user-broker-owner", broker),
        }
    }

    fn test_provenance(bundle: &BackupBundle, plan: &RestorePlan) -> RestoreProvenance {
        RestoreProvenance {
            transaction_id: plan.transaction().expect("transaction").transaction_id,
            plan_id: plan.plan_id.clone(),
            operation_id: "restore-operation-1".to_owned(),
            phase: RestorePhase::FinalizeIsolatedRoot,
            source_archive_id: bundle.manifest.backup_id.clone(),
            source_class: bundle.manifest.class,
            source_digest: bundle.bundle_sha256().expect("bundle digest"),
            source_endpoint_ref: "source-adapter-test".to_owned(),
            isolated_destination_ref: plan.target.target_id.clone(),
            expected_predecessor_ref: "predecessor-receipt-0".to_owned(),
            schema_revision: bundle.manifest.schema_generation.clone(),
            build_manifest_digest: sha256_hex(b"test-build-manifest"),
            purge_ledger_revision: bundle.manifest.purge_ledger_revision,
            owner: test_owner("restore-owner"),
            observed_generation: plan.restored_fence.resource_generation,
            observed_epoch: plan.restored_fence.authority_epoch.clone(),
            validation_digest: sha256_hex(b"bounded-validation-evidence"),
        }
    }

    fn test_evidence(bundle: &BackupBundle, plan: &RestorePlan) -> RestoreEvidence {
        RestoreEvidence {
            target_id: plan.target.target_id.clone(),
            isolated_root: true,
            purge_applied: true,
            blobs_imported: true,
            projections_rebuilt: true,
            receipt_event_chain_verified: true,
            ors_suspended: false,
            active_authority_restored: false,
            authority_epoch: plan.restored_fence.authority_epoch.clone(),
            resource_generation: plan.restored_fence.resource_generation,
            provenance: test_provenance(bundle, plan),
            obligations: test_obligations(
                RestoreObligationState::NotAttempted,
                RestoreObligationState::Unknown,
                RestoreObligationState::MissingCapability,
            ),
            observed_lineage_limits: vec![ObservedLineageLimit {
                owner_id: "restore-owner".to_owned(),
                observed_epoch: plan
                    .restored_fence
                    .source_state_fence
                    .authority_epoch
                    .clone(),
                observed_generation: plan.restored_fence.source_state_fence.resource_generation,
            }],
            owner_epoch: None,
            reconciliation_denominator: None,
            operational_validation: None,
            historical_authority: Vec::new(),
            archive_disposition: RestoreArchiveDisposition {
                disposition: RestoreArchiveDispositionKind::Current,
                compatibility_ref: "ecxf-1-current".to_owned(),
            },
        }
    }

    #[derive(Default)]
    struct TestJournal {
        record: Option<RestoreJournalRecord>,
        fail_receipt_cas: bool,
    }

    impl RestoreJournalPort for TestJournal {
        fn load(&mut self, journal_key: &str) -> Result<Option<RestoreJournalRecord>, BackupError> {
            Ok(self
                .record
                .clone()
                .filter(|record| record.journal_key == journal_key))
        }

        fn compare_and_swap(
            &mut self,
            journal_key: &str,
            expected_revision: u64,
            next: RestoreJournalRecord,
        ) -> Result<(), BackupError> {
            if next.journal_key != journal_key
                || self.record.as_ref().map_or(0, |record| record.revision) != expected_revision
            {
                return Err(BackupError::RestoreJournalCasConflict);
            }
            if self.fail_receipt_cas && next.state == RestoreJournalState::ReceiptPersisted {
                self.fail_receipt_cas = false;
                return Err(BackupError::RestoreJournalCasConflict);
            }
            self.record = Some(next);
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestTarget {
        calls: Vec<&'static str>,
        fail_rebuild: bool,
        bad_receipt: bool,
        reconcile_mode: ReconcileMode,
    }

    #[derive(Default)]
    enum ReconcileMode {
        #[default]
        Unknown,
        NotApplied,
        Applied,
    }

    impl RestoreTarget for TestTarget {
        fn apply_restore_effect(
            &mut self,
            _plan: &RestorePlan,
            _bundle: &BackupBundle,
            intent: &RestoreIntent,
        ) -> Result<RestoreAppliedEffect, BackupError> {
            self.calls.push(phase_call_name(&intent.phase));
            if self.fail_rebuild && matches!(intent.phase, RestorePhase::RebuildProjections) {
                return Err(BackupError::Target("simulated process loss".to_owned()));
            }
            let mut applied = applied_effect(intent);
            if self.bad_receipt {
                applied.receipt.input_digest = "0".repeat(64);
            }
            Ok(applied)
        }

        fn reconcile_restore_effect(
            &mut self,
            intent: &RestoreIntent,
        ) -> Result<RestoreReconciliation, BackupError> {
            match self.reconcile_mode {
                ReconcileMode::Unknown => Ok(RestoreReconciliation::Unknown),
                ReconcileMode::NotApplied => Ok(RestoreReconciliation::NotApplied),
                ReconcileMode::Applied => {
                    Ok(RestoreReconciliation::Applied(applied_effect(intent)))
                }
            }
        }

        fn prepare_isolated(
            &mut self,
            _context: &RestoreContext,
            _restored_fence: &RestoredFence,
        ) -> Result<(), BackupError> {
            self.calls.push("prepare");
            Ok(())
        }

        fn apply_purge_ledger(&mut self, _entries: &[PurgeLedgerEntry]) -> Result<(), BackupError> {
            self.calls.push("purge");
            Ok(())
        }

        fn import_sealed_blob(&mut self, _blob: &BackupBlob) -> Result<(), BackupError> {
            self.calls.push("blob");
            Ok(())
        }

        fn import_canonical_event(&mut self, _record: &CanonicalRecord) -> Result<(), BackupError> {
            self.calls.push("event");
            Ok(())
        }

        fn import_receipt(&mut self, _receipt: &WriteReceipt) -> Result<(), BackupError> {
            self.calls.push("receipt");
            Ok(())
        }

        fn import_projection(&mut self, _record: &CanonicalRecord) -> Result<(), BackupError> {
            self.calls.push("projection");
            Ok(())
        }

        fn suspend_ors_operations(
            &mut self,
            _snapshot: &OrsSnapshotFence,
        ) -> Result<(), BackupError> {
            self.calls.push("ors");
            Ok(())
        }

        fn rebuild_projections(
            &mut self,
            _restored_fence: &RestoredFence,
        ) -> Result<(), BackupError> {
            self.calls.push("rebuild");
            if self.fail_rebuild {
                return Err(BackupError::Target("simulated process loss".to_owned()));
            }
            Ok(())
        }

        fn verify_receipt_event_chain(
            &mut self,
            _receipts: &[WriteReceipt],
            _events: &[CanonicalRecord],
        ) -> Result<(), BackupError> {
            self.calls.push("verify");
            Ok(())
        }

        fn finalize_isolated(
            &mut self,
            _restored_fence: &RestoredFence,
        ) -> Result<RestoreEvidence, BackupError> {
            self.calls.push("finalize");
            Err(BackupError::RestoreTargetReceiptRequired)
        }
    }

    fn phase_call_name(phase: &RestorePhase) -> &'static str {
        match phase {
            RestorePhase::PrepareIsolatedRoot => "prepare",
            RestorePhase::ApplyPurgeLedger => "purge",
            RestorePhase::RebuildProjections => "rebuild",
            RestorePhase::VerifyReceiptEventChain => "verify",
            RestorePhase::FinalizeIsolatedRoot => "finalize",
            _ => "other",
        }
    }

    fn applied_effect(intent: &RestoreIntent) -> RestoreAppliedEffect {
        // `plan()` always builds the same canonical-degraded bundle/context, so
        // the finalize evidence can be reconstructed deterministically here.
        let final_evidence = if matches!(intent.phase, RestorePhase::FinalizeIsolatedRoot) {
            let plan = plan();
            let bundle = bundle_for(&plan);
            Some(test_evidence(&bundle, &plan))
        } else {
            None
        };
        let evidence_sha256 = final_evidence.as_ref().map_or_else(
            || sha256_hex(b"target-observed-effect"),
            |evidence| sha256(evidence).expect("evidence digest"),
        );
        RestoreAppliedEffect {
            receipt: RestoreEffectReceipt {
                transaction_id: intent.transaction_id.clone(),
                phase: intent.phase.clone(),
                input_digest: intent.input_digest.clone(),
                external_identity_sha256: sha256(&intent.phase).expect("phase digest"),
                evidence_sha256,
            },
            final_evidence,
        }
    }

    fn plan() -> RestorePlan {
        let source_fence = StateFence::new(test_epoch(1), ResourceGeneration::genesis());
        let bundle = BackupBundle::build(BackupInput {
            backup_id: "backup".to_owned(),
            class: BackupClass::CanonicalOnlyDegraded,
            source_adapter: "test".to_owned(),
            schema_generation: "1".to_owned(),
            export_fence: ExportFence {
                export_id: "export".to_owned(),
                store_generation: "store".to_owned(),
                state_fence: source_fence,
                scope_id: None,
                revision_heads: Vec::new(),
                ordering_heads: Vec::new(),
                event_range: EventRange {
                    first_sequence: None,
                    last_sequence: None,
                    count: 0,
                },
                blob_reachability_manifest: Vec::new(),
                consistent: true,
            },
            canonical_events: Vec::new(),
            projections: Vec::new(),
            receipts: Vec::new(),
            blobs: Vec::new(),
            purge_ledger: Vec::new(),
            ors_snapshot: None,
            artifacts: Vec::new(),
            watchdog_spool: None,
            host_audit: None,
            missing_features: Vec::new(),
            purge_ledger_revision: 1,
        })
        .expect("bundle");
        RestorePlan::compile(
            &bundle,
            RestoreContext {
                target_id: "target".to_owned(),
                target_authority_epoch: test_epoch(2),
                target_resource_generation: ResourceGeneration::new(2).expect("generation"),
            },
        )
        .expect("plan")
    }

    fn bundle_for(plan: &RestorePlan) -> BackupBundle {
        let source_fence = plan.restored_fence.source_state_fence.clone();
        BackupBundle::build(BackupInput {
            backup_id: "backup".to_owned(),
            class: BackupClass::CanonicalOnlyDegraded,
            source_adapter: "test".to_owned(),
            schema_generation: "1".to_owned(),
            export_fence: ExportFence {
                export_id: "export".to_owned(),
                store_generation: "store".to_owned(),
                state_fence: source_fence,
                scope_id: None,
                revision_heads: Vec::new(),
                ordering_heads: Vec::new(),
                event_range: EventRange {
                    first_sequence: None,
                    last_sequence: None,
                    count: 0,
                },
                blob_reachability_manifest: Vec::new(),
                consistent: true,
            },
            canonical_events: Vec::new(),
            projections: Vec::new(),
            receipts: Vec::new(),
            blobs: Vec::new(),
            purge_ledger: Vec::new(),
            ors_snapshot: None,
            artifacts: Vec::new(),
            watchdog_spool: None,
            host_audit: None,
            missing_features: Vec::new(),
            purge_ledger_revision: 1,
        })
        .expect("bundle")
    }

    #[test]
    fn purge_is_the_first_external_restore_boundary() {
        let plan = plan();
        let bundle = bundle_for(&plan);
        let mut journal = TestJournal::default();
        let mut target = TestTarget::default();

        let receipt = plan
            .execute_with_journal(&bundle, &mut target, &mut journal)
            .expect("restore");
        assert!(!receipt.cutover_performed);
        assert!(!receipt.operational_recovery_ready);
        assert_eq!(
            receipt.evidence_level,
            RestoreEvidenceLevel::IsolatedImportComplete
        );
        assert!(receipt.canonical_only);
        receipt.validate().expect("receipt validates");
        assert_eq!(&target.calls[..2], &["prepare", "purge"]);
    }

    #[test]
    fn exact_replay_returns_durable_receipt_without_target_effects() {
        let plan = plan();
        let bundle = bundle_for(&plan);
        let mut journal = TestJournal::default();
        let mut first_target = TestTarget::default();
        let first = plan
            .execute_with_journal(&bundle, &mut first_target, &mut journal)
            .expect("first restore");
        let mut replay_target = TestTarget::default();
        let replay = plan
            .execute_with_journal(&bundle, &mut replay_target, &mut journal)
            .expect("replay");

        assert_eq!(first, replay);
        assert!(replay_target.calls.is_empty());
        assert_eq!(
            journal.record.as_ref().expect("journal").state,
            RestoreJournalState::Completed
        );
    }

    #[test]
    fn crash_after_two_boundaries_requires_rollback_on_resume() {
        let plan = plan();
        let bundle = bundle_for(&plan);
        let mut journal = TestJournal::default();
        let mut target = TestTarget {
            fail_rebuild: true,
            ..TestTarget::default()
        };
        assert!(matches!(
            plan.execute_with_journal(&bundle, &mut target, &mut journal),
            Err(BackupError::Target(_))
        ));
        assert_eq!(
            journal.record.as_ref().expect("intent").state,
            RestoreJournalState::IntentPersisted
        );
        let mut resumed_target = TestTarget::default();
        assert_eq!(
            plan.execute_with_journal(&bundle, &mut resumed_target, &mut journal),
            Err(BackupError::RestoreRollbackRequired)
        );
        assert!(resumed_target.calls.is_empty());
        assert_eq!(
            journal.record.as_ref().expect("rollback record").state,
            RestoreJournalState::RollbackRequired
        );
        let mut replay_target = TestTarget::default();
        assert_eq!(
            plan.execute_with_journal(&bundle, &mut replay_target, &mut journal),
            Err(BackupError::RestoreRollbackRequired)
        );
        assert!(replay_target.calls.is_empty());
    }

    #[test]
    fn target_mismatched_receipt_is_rejected_without_success() {
        let plan = plan();
        let bundle = bundle_for(&plan);
        let mut journal = TestJournal::default();
        let mut target = TestTarget {
            bad_receipt: true,
            ..TestTarget::default()
        };

        assert_eq!(
            plan.execute_with_journal(&bundle, &mut target, &mut journal),
            Err(BackupError::RestoreJournalCorrupt)
        );
        let record = journal.record.as_ref().expect("intent record");
        assert_eq!(record.state, RestoreJournalState::IntentPersisted);
        assert!(record.receipt.is_none());
    }

    #[test]
    fn crash_after_effect_before_receipt_cas_reconciles_without_duplicate_effect() {
        let plan = plan();
        let bundle = bundle_for(&plan);
        let mut journal = TestJournal {
            fail_receipt_cas: true,
            ..TestJournal::default()
        };
        let mut first_target = TestTarget::default();
        assert_eq!(
            plan.execute_with_journal(&bundle, &mut first_target, &mut journal),
            Err(BackupError::RestoreJournalCasConflict)
        );
        assert_eq!(first_target.calls, vec!["prepare"]);

        let mut resumed_target = TestTarget {
            reconcile_mode: ReconcileMode::Applied,
            ..TestTarget::default()
        };
        plan.execute_with_journal(&bundle, &mut resumed_target, &mut journal)
            .expect("reconcile and continue");
        assert!(!resumed_target.calls.contains(&"prepare"));
        assert_eq!(
            resumed_target.calls,
            vec!["purge", "rebuild", "verify", "finalize"]
        );
    }

    #[test]
    fn not_applied_replays_existing_intent_exactly_once() {
        let plan = plan();
        let bundle = bundle_for(&plan);
        let mut journal = TestJournal::default();
        let mut first_target = TestTarget {
            fail_rebuild: true,
            ..TestTarget::default()
        };
        assert!(matches!(
            plan.execute_with_journal(&bundle, &mut first_target, &mut journal),
            Err(BackupError::Target(_))
        ));

        let mut resumed_target = TestTarget {
            reconcile_mode: ReconcileMode::NotApplied,
            ..TestTarget::default()
        };
        plan.execute_with_journal(&bundle, &mut resumed_target, &mut journal)
            .expect("apply persisted intent");
        assert_eq!(resumed_target.calls, vec!["rebuild", "verify", "finalize"]);
    }

    #[test]
    fn context_digest_drift_is_rejected_by_existing_transaction() {
        let plan = plan();
        let bundle = bundle_for(&plan);
        let mut journal = TestJournal::default();
        let mut target = TestTarget::default();
        plan.execute_with_journal(&bundle, &mut target, &mut journal)
            .expect("restore");

        let mut changed = plan.clone();
        changed.target.target_id = "other-target".to_owned();
        assert_ne!(
            plan.transaction().expect("transaction").transaction_id,
            changed.transaction().expect("transaction").transaction_id
        );
        let mut changed_target = TestTarget::default();
        assert_eq!(
            changed.execute_with_journal(&bundle, &mut changed_target, &mut journal),
            Err(BackupError::RestoreJournalMismatch)
        );
    }

    #[test]
    fn plan_digest_drift_is_rejected_by_existing_transaction() {
        let plan = plan();
        let bundle = bundle_for(&plan);
        let mut journal = TestJournal::default();
        let mut target = TestTarget::default();
        plan.execute_with_journal(&bundle, &mut target, &mut journal)
            .expect("restore");

        let mut changed = plan.clone();
        changed.steps.reverse();
        assert_ne!(
            plan.transaction().expect("transaction").transaction_id,
            changed.transaction().expect("transaction").transaction_id
        );
        let mut changed_target = TestTarget::default();
        assert_eq!(
            changed.execute_with_journal(&bundle, &mut changed_target, &mut journal),
            Err(BackupError::PlanMismatch)
        );
    }

    #[test]
    fn stale_cas_is_rejected() {
        let plan = plan();
        let journal_key = plan.journal_key().expect("journal key");
        let transaction = plan.transaction().expect("transaction");
        let mut journal = TestJournal::default();
        let record = RestoreJournalRecord {
            journal_key: journal_key.clone(),
            transaction,
            revision: 0,
            completed_phases: 0,
            phase: RestorePhase::Pending,
            state: RestoreJournalState::Ready,
            intent: None,
            receipt: None,
            final_receipt: None,
        };
        journal
            .compare_and_swap(&journal_key, 0, record.clone())
            .expect("create");
        assert_eq!(
            journal.compare_and_swap(&journal_key, 999, record),
            Err(BackupError::RestoreJournalCasConflict)
        );
    }

    #[test]
    fn phase_skip_is_rejected_fail_closed() {
        let plan = plan();
        let journal_key = plan.journal_key().expect("journal key");
        let transaction = plan.transaction().expect("transaction");
        let phases = restore_phases(&bundle_for(&plan));
        let record = RestoreJournalRecord {
            journal_key,
            transaction: transaction.clone(),
            revision: 1,
            completed_phases: 0,
            phase: RestorePhase::FinalizeIsolatedRoot,
            state: RestoreJournalState::Ready,
            intent: None,
            receipt: None,
            final_receipt: None,
        };
        assert_eq!(
            validate_journal_record(&record, &record.journal_key, &transaction, &phases),
            Err(BackupError::RestorePhaseMismatch)
        );
    }

    #[test]
    fn evidence_levels_are_distinct_per_class_without_operational_inference() {
        assert_eq!(
            RestoreEvidenceLevel::for_class(BackupClass::FullRecovery),
            RestoreEvidenceLevel::ReconciliationRequired
        );
        assert_eq!(
            RestoreEvidenceLevel::for_class(BackupClass::CanonicalOnlyDegraded),
            RestoreEvidenceLevel::IsolatedImportComplete
        );
        assert_eq!(
            RestoreEvidenceLevel::for_class(BackupClass::ScopeExport),
            RestoreEvidenceLevel::IsolatedImportComplete
        );
        assert_ne!(
            RestoreEvidenceLevel::for_class(BackupClass::FullRecovery),
            RestoreEvidenceLevel::for_class(BackupClass::CanonicalOnlyDegraded)
        );
        for level in [
            RestoreEvidenceLevel::ArchiveValid,
            RestoreEvidenceLevel::IsolatedImportComplete,
            RestoreEvidenceLevel::ReconciliationRequired,
        ] {
            assert!(!level.permits_operational_readiness());
        }
    }

    #[test]
    fn known_zero_requires_complete_current_denominator() {
        let complete = ReconciliationDenominator {
            owner_id: "reconciliation-owner".to_owned(),
            denominator_ref: "denominator-current-1".to_owned(),
            expected_total: 0,
            reconciled_refs: Vec::new(),
        };
        complete.validate().expect("complete denominator");
        assert!(complete.is_known_zero());
        let partial = ReconciliationDenominator {
            owner_id: "reconciliation-owner".to_owned(),
            denominator_ref: "denominator-current-1".to_owned(),
            expected_total: 2,
            reconciled_refs: vec!["item-1".to_owned()],
        };
        assert_eq!(
            partial.validate(),
            Err(BackupError::RestoreEvidenceIncomplete)
        );
        assert!(!partial.is_known_zero());
    }

    #[test]
    fn owner_epoch_validates_lineage_authority_without_minting() {
        let candidate = RestoreOwnerEpoch {
            owner: test_owner("epoch-owner"),
            new_epoch: test_epoch(2),
            new_generation: ResourceGeneration::new(2).expect("generation"),
            supersedes: vec![ObservedLineageLimit {
                owner_id: "epoch-owner".to_owned(),
                observed_epoch: test_epoch(1),
                observed_generation: ResourceGeneration::genesis(),
            }],
        };
        candidate.validate().expect("advancing epoch");
        // Cross-lineage reuse of an observed non-genesis sequence is not newer.
        let cross_lineage = RestoreOwnerEpoch {
            owner: test_owner("epoch-owner"),
            new_epoch: test_epoch_in(TEST_LINEAGE_B, 2),
            new_generation: ResourceGeneration::new(2).expect("generation"),
            supersedes: vec![ObservedLineageLimit {
                owner_id: "epoch-owner".to_owned(),
                observed_epoch: test_epoch(1),
                observed_generation: ResourceGeneration::genesis(),
            }],
        };
        assert_eq!(
            cross_lineage.validate(),
            Err(BackupError::StaleRestoreLineage)
        );
    }

    #[test]
    fn journal_admission_separates_fixture_proof_from_production() {
        let fixture = RestoreJournalAdmission {
            persistent_owner: test_owner("journal-owner"),
            database_ref: "memory-fixture".to_owned(),
            installation_ref: "installation-fixture".to_owned(),
            generation: ResourceGeneration::genesis(),
            journal_identity_ref: "journal-fixture-1".to_owned(),
            admission_receipt_ref: "admission-fixture-1".to_owned(),
            fixture_proof_only: true,
        };
        fixture.validate().expect("fixture admission");
        assert!(!fixture.admits_production_durable_recovery());
    }

    #[test]
    fn closed_evidence_rejects_unknown_fields_at_decode() {
        let plan = plan();
        let bundle = bundle_for(&plan);
        let evidence = test_evidence(&bundle, &plan);
        let mut wire = serde_json::to_value(&evidence).expect("encode");
        wire["unknown_future_field"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RestoreEvidence>(wire).is_err());
    }
}
