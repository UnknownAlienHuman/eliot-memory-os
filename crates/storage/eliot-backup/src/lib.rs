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
            head.validate()?;
        }
        unique(
            self.ordering_heads.iter().map(|head| head.scope.clone()),
            "ordering_heads",
        )?;
        for head in &self.ordering_heads {
            head.validate()?;
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

/// ECXF manifest. Section checksums and integrity_sha256 bind the export.
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
        for record in self
            .canonical_events
            .iter()
            .chain(self.projections.iter())
        {
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
        validate_receipts(&self.receipts, &self.canonical_events, &self.export_fence.state_fence)?;
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
        sections.insert("canonical_events".to_owned(), sha256(&self.canonical_events)?);
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
        canonical_json_bytes(self)
            .map_err(|error| BackupError::Serialization(error.to_string()))
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
    bundle
        .receipts
        .sort_by(|left, right| left.operation_id.to_string().cmp(&right.operation_id.to_string()));
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
    match bundle.manifest.class {
        BackupClass::FullRecovery => {
            if bundle.ors_snapshot.is_none() {
                return Err(BackupError::MissingRecoveryComponent("ors_snapshot"));
            }
            if bundle.watchdog_spool.is_none() {
                return Err(BackupError::MissingRecoveryComponent("watchdog_spool"));
            }
            const REQUIRED: [&str; 4] = ["config", "policy", "module", "host_dependency_build"];
            for required in REQUIRED {
                if !bundle.artifacts.iter().any(|artifact| artifact.kind == required) {
                    return Err(BackupError::MissingRecoveryComponent(required));
                }
            }
            if !bundle.manifest.missing_features.is_empty() {
                return Err(BackupError::FullRecoveryHasGaps);
            }
        }
        BackupClass::CanonicalOnlyDegraded => {
            if bundle.ors_snapshot.is_some() {
                return Err(BackupError::UnexpectedRecoveryComponent("ors_snapshot"));
            }
        }
        BackupClass::ScopeExport => {
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
        Ok(Self {
            plan_id: format!("restore-plan-{}", bundle.manifest.backup_id),
            bundle_sha256: bundle.bundle_sha256()?,
            target,
            restored_fence,
            steps,
        })
    }

    /// Executes the plan against a provider-owned isolated target.
    pub fn execute<T: RestoreTarget>(
        &self,
        bundle: &BackupBundle,
        target: &mut T,
    ) -> Result<RestoreReceipt, BackupError> {
        bundle.validate()?;
        if bundle.bundle_sha256()? != self.bundle_sha256 {
            return Err(BackupError::PlanMismatch);
        }
        target.prepare_isolated(&self.target, &self.restored_fence)?;
        target.apply_purge_ledger(&bundle.purge_ledger)?;
        for blob in &bundle.blobs {
            target.import_sealed_blob(blob)?;
        }
        for event in &bundle.canonical_events {
            target.import_canonical_event(event)?;
        }
        for receipt in &bundle.receipts {
            target.import_receipt(receipt)?;
        }
        for projection in &bundle.projections {
            target.import_projection(projection)?;
        }
        if let Some(ors) = &bundle.ors_snapshot {
            target.suspend_ors_operations(ors)?;
        }
        target.rebuild_projections(&self.restored_fence)?;
        target.verify_receipt_event_chain(&bundle.receipts, &bundle.canonical_events)?;
        let evidence = target.finalize_isolated(&self.restored_fence)?;
        evidence.validate()?;
        if bundle.ors_snapshot.is_some() && !evidence.ors_suspended {
            return Err(BackupError::RestoreEvidenceIncomplete);
        }
        if evidence.target_id != self.target.target_id
            || evidence.authority_epoch != self.restored_fence.authority_epoch
            || evidence.resource_generation != self.restored_fence.resource_generation
        {
            return Err(BackupError::FinalizeEvidenceMismatch);
        }
        Ok(RestoreReceipt {
            receipt_id: format!("restore-receipt-{}", self.plan_id),
            plan_id: self.plan_id.clone(),
            bundle_sha256: self.bundle_sha256.clone(),
            target_id: self.target.target_id.clone(),
            restored_fence: self.restored_fence.clone(),
            canonical_only: bundle.manifest.class != BackupClass::FullRecovery,
            operational_recovery_ready: bundle.manifest.class == BackupClass::FullRecovery,
            cutover_performed: false,
        })
    }
}

/// Evidence returned by the isolated target after all restore steps complete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub canonical_only: bool,
    pub operational_recovery_ready: bool,
    pub cutover_performed: bool,
}

/// Provider-owned isolated restore target. Implementations must not make the
/// target current authority as part of any method in this trait.
pub trait RestoreTarget {
    fn prepare_isolated(
        &mut self,
        context: &RestoreContext,
        restored_fence: &RestoredFence,
    ) -> Result<(), BackupError>;
    fn apply_purge_ledger(
        &mut self,
        entries: &[PurgeLedgerEntry],
    ) -> Result<(), BackupError>;
    fn import_sealed_blob(&mut self, blob: &BackupBlob) -> Result<(), BackupError>;
    fn import_canonical_event(&mut self, record: &CanonicalRecord) -> Result<(), BackupError>;
    fn import_receipt(&mut self, receipt: &WriteReceipt) -> Result<(), BackupError>;
    fn import_projection(&mut self, record: &CanonicalRecord) -> Result<(), BackupError>;
    fn suspend_ors_operations(
        &mut self,
        snapshot: &OrsSnapshotFence,
    ) -> Result<(), BackupError>;
    fn rebuild_projections(
        &mut self,
        restored_fence: &RestoredFence,
    ) -> Result<(), BackupError>;
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
