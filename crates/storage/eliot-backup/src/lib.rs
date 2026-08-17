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
use eliot_contracts::{
    AuthorityEpoch, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
};
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
    pub authority_epoch: AuthorityEpoch,
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
        if self.authority_epoch != self.state_fence.authority_epoch
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreContext {
    pub target_id: String,
    pub target_authority_epoch: AuthorityEpoch,
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
    pub authority_epoch: AuthorityEpoch,
    pub resource_generation: ResourceGeneration,
}

impl RestoredFence {
    pub fn validate(&self) -> Result<(), BackupError> {
        self.source_state_fence
            .validate()
            .map_err(|error| BackupError::Foundation(error.to_string()))?;
        if self.authority_epoch <= self.source_state_fence.authority_epoch
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
            .map_or(source.authority_epoch, |ors| ors.authority_epoch);
        let ors_generation = bundle
            .ors_snapshot
            .as_ref()
            .map_or(source.resource_generation, |ors| ors.resource_generation);
        if target.target_authority_epoch <= ors_epoch
            || target.target_resource_generation <= ors_generation
        {
            return Err(BackupError::StaleRestoreLineage);
        }
        let restored_fence = RestoredFence {
            source_state_fence: source.clone(),
            authority_epoch: target.target_authority_epoch,
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
    if sha256(evidence)? != applied.receipt.evidence_sha256 {
        return Err(BackupError::FinalizeEvidenceMismatch);
    }
    if bundle.ors_snapshot.is_some() && !evidence.ors_suspended {
        return Err(BackupError::RestoreEvidenceIncomplete);
    }
    if evidence.target_id != plan.target.target_id
        || evidence.authority_epoch != plan.restored_fence.authority_epoch
        || evidence.resource_generation != plan.restored_fence.resource_generation
    {
        return Err(BackupError::FinalizeEvidenceMismatch);
    }
    Ok(Some(RestoreReceipt {
        receipt_id: format!("restore-receipt-{}", plan.plan_id),
        plan_id: plan.plan_id.clone(),
        bundle_sha256: transaction.bundle_sha256.clone(),
        target_id: plan.target.target_id.clone(),
        restored_fence: plan.restored_fence.clone(),
        effect_receipt_sha256: sha256(&applied.receipt)?,
        canonical_only: bundle.manifest.class != BackupClass::FullRecovery,
        operational_recovery_ready: bundle.manifest.class == BackupClass::FullRecovery,
        cutover_performed: false,
    }))
}

/// Evidence returned by the isolated target after all restore steps complete.
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
    pub authority_epoch: AuthorityEpoch,
    pub resource_generation: ResourceGeneration,
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
        Ok(())
    }
}

/// Immutable receipt of an isolated restore. It is not a cutover receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReceipt {
    pub receipt_id: String,
    pub plan_id: String,
    pub bundle_sha256: String,
    pub target_id: String,
    pub restored_fence: RestoredFence,
    pub effect_receipt_sha256: String,
    pub canonical_only: bool,
    pub operational_recovery_ready: bool,
    pub cutover_performed: bool,
}

/// Provider-owned isolated restore target. Implementations must not make the
/// target current authority as part of any method in this trait.
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
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};

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
            Ok(RestoreEvidence {
                target_id: "target".to_owned(),
                isolated_root: true,
                purge_applied: true,
                blobs_imported: true,
                projections_rebuilt: true,
                receipt_event_chain_verified: true,
                ors_suspended: false,
                active_authority_restored: false,
                authority_epoch: AuthorityEpoch::new(2).expect("epoch"),
                resource_generation: ResourceGeneration::new(2).expect("generation"),
            })
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
        let final_evidence = if matches!(intent.phase, RestorePhase::FinalizeIsolatedRoot) {
            Some(RestoreEvidence {
                target_id: "target".to_owned(),
                isolated_root: true,
                purge_applied: true,
                blobs_imported: true,
                projections_rebuilt: true,
                receipt_event_chain_verified: true,
                ors_suspended: false,
                active_authority_restored: false,
                authority_epoch: AuthorityEpoch::new(2).expect("epoch"),
                resource_generation: ResourceGeneration::new(2).expect("generation"),
            })
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
        let source_fence =
            StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
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
                target_authority_epoch: AuthorityEpoch::new(2).expect("epoch"),
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
}
