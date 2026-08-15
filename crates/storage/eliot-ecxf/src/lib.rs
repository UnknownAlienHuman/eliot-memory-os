//! Canonical ECXF/1 interchange source for ELIOT storage.
//!
//! ECXF is a logical, vendor-neutral representation of a fenced canonical
//! store. This crate deliberately does not open a database or a filesystem.
//! A store bridge supplies already-fenced records and completed blob receipts;
//! this crate validates their relationship, computes deterministic digests, and
//! exposes a layout writer for an injected section codec.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_blob_api::{BlobHash, BlobLocator, BlobReadyReceipt};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::{OrderingHead, RevisionHead, ScopeId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.storage.ecxf";
pub const FORMAT_VERSION: &str = "ECXF/1";
pub const MAX_RECORD_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_SECTION_BYTES: usize = 1024 * 1024 * 1024;

fn text(value: &str, field: &'static str) -> Result<(), EcxfError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(EcxfError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), EcxfError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(EcxfError::InvalidField {
            field,
            reason: "must be lowercase SHA-256 hex",
        });
    }
    Ok(())
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, EcxfError> {
    canonical_json_bytes(value).map_err(|error| EcxfError::Serialization(error.to_string()))
}

fn value_digest(value: &Value) -> Result<String, EcxfError> {
    Ok(sha256_hex(&canonical(value)?))
}

fn unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<(), EcxfError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(EcxfError::Duplicate { field });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum EcxfError {
    #[error("invalid ECXF field {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("duplicate ECXF value in {field}")]
    Duplicate { field: &'static str },
    #[error("ECXF export fence is not coherent")]
    InconsistentBoundary,
    #[error("ECXF digest mismatch for {subject}")]
    DigestMismatch { subject: String },
    #[error("ECXF serialization failed: {0}")]
    Serialization(String),
    #[error("ECXF codec failed: {0}")]
    Codec(String),
    #[error("ECXF blob contract failed: {0}")]
    Blob(String),
    #[error("ECXF store contract failed: {0}")]
    Store(String),
    #[error("ECXF security contract failed: {0}")]
    Security(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRange {
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub count: u64,
}

impl EventRange {
    pub fn validate(&self) -> Result<(), EcxfError> {
        match (self.first_sequence, self.last_sequence, self.count) {
            (None, None, 0) => Ok(()),
            (Some(first), Some(last), count)
                if first <= last && count > 0 && count <= last - first + 1 =>
            {
                Ok(())
            }
            _ => Err(EcxfError::InvalidField {
                field: "event_range",
                reason: "bounds and count do not describe one interval",
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportFence {
    pub export_id: String,
    pub schema_generation: String,
    pub store_generation: String,
    pub state_fence: StateFence,
    pub scope_id: Option<ScopeId>,
    pub revision_heads: Vec<RevisionHead>,
    pub ordering_heads: Vec<OrderingHead>,
    pub event_range: EventRange,
    pub blob_reachability_manifest: Vec<BlobHash>,
    pub consistent: bool,
}

impl ExportFence {
    pub fn validate(&self) -> Result<(), EcxfError> {
        text(&self.export_id, "export_id")?;
        text(&self.schema_generation, "schema_generation")?;
        text(&self.store_generation, "store_generation")?;
        self.state_fence
            .validate()
            .map_err(|error| EcxfError::Store(error.to_string()))?;
        if !self.consistent {
            return Err(EcxfError::InconsistentBoundary);
        }
        self.event_range.validate()?;
        unique(
            self.revision_heads.iter().map(|head| head.key.clone()),
            "revision_heads",
        )?;
        for head in &self.revision_heads {
            head.validate()
                .map_err(|error| EcxfError::Store(error.to_string()))?;
            if head.state_fence != self.state_fence {
                return Err(EcxfError::InconsistentBoundary);
            }
        }
        unique(
            self.ordering_heads.iter().map(|head| head.scope.clone()),
            "ordering_heads",
        )?;
        for head in &self.ordering_heads {
            head.validate()
                .map_err(|error| EcxfError::Store(error.to_string()))?;
            if head.state_fence != self.state_fence {
                return Err(EcxfError::InconsistentBoundary);
            }
        }
        unique(
            self.blob_reachability_manifest.iter().cloned(),
            "blob_reachability_manifest",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxfRecord {
    pub record_type: String,
    pub record_id: String,
    pub payload: Value,
    pub sha256: String,
}

impl EcxfRecord {
    pub fn new(
        record_type: impl Into<String>,
        record_id: impl Into<String>,
        payload: Value,
    ) -> Result<Self, EcxfError> {
        let value = Self {
            record_type: record_type.into(),
            record_id: record_id.into(),
            sha256: value_digest(&payload)?,
            payload,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), EcxfError> {
        text(&self.record_type, "record_type")?;
        text(&self.record_id, "record_id")?;
        if !self.payload.is_object() {
            return Err(EcxfError::InvalidField {
                field: "payload",
                reason: "canonical ECXF records require an object",
            });
        }
        digest(&self.sha256, "record.sha256")?;
        if value_digest(&self.payload)? != self.sha256 {
            return Err(EcxfError::DigestMismatch {
                subject: self.record_id.clone(),
            });
        }
        if canonical(&self.payload)?.len() > MAX_RECORD_BYTES {
            return Err(EcxfError::InvalidField {
                field: "payload",
                reason: "record exceeds MAX_RECORD_BYTES",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionKind {
    Events,
    Projections,
    Receipts,
}

impl SectionKind {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Events => "events",
            Self::Projections => "projections",
            Self::Receipts => "receipts",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSection {
    pub kind: SectionKind,
    pub records: Vec<EcxfRecord>,
    pub record_count: u64,
    pub canonical_sha256: String,
}

impl CanonicalSection {
    pub fn new(kind: SectionKind, records: Vec<EcxfRecord>) -> Result<Self, EcxfError> {
        let mut value = Self {
            kind,
            record_count: records.len() as u64,
            records,
            canonical_sha256: String::new(),
        };
        value.canonical_sha256 = sha256_hex(&value.ndjson_bytes()?);
        value.validate()?;
        Ok(value)
    }

    pub fn ndjson_bytes(&self) -> Result<Vec<u8>, EcxfError> {
        let mut bytes = Vec::new();
        for record in &self.records {
            bytes.extend(canonical(record)?);
            bytes.push(b'\n');
        }
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), EcxfError> {
        if self.record_count != self.records.len() as u64 {
            return Err(EcxfError::InvalidField {
                field: "record_count",
                reason: "does not match records",
            });
        }
        unique(
            self.records.iter().map(|record| record.record_id.clone()),
            "section.record_id",
        )?;
        for record in &self.records {
            record.validate()?;
        }
        digest(&self.canonical_sha256, "canonical_sha256")?;
        if sha256_hex(&self.ndjson_bytes()?) != self.canonical_sha256 {
            return Err(EcxfError::DigestMismatch {
                subject: self.kind.wire_name().to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EcxfBlob {
    pub locator: BlobLocator,
    pub sealed_bytes: Vec<u8>,
    pub sealed_sha256: String,
    pub ready_receipt: BlobReadyReceipt,
}

impl EcxfBlob {
    pub fn validate(&self) -> Result<(), EcxfError> {
        self.locator
            .validate()
            .map_err(|error| EcxfError::Blob(error.to_string()))?;
        self.ready_receipt
            .validate()
            .map_err(|error| EcxfError::Blob(error.to_string()))?;
        if self.ready_receipt.locator() != &self.locator
            || self.ready_receipt.sealed_sha256() != self.sealed_sha256
        {
            return Err(EcxfError::DigestMismatch {
                subject: format!("blob receipt {}", self.locator.hash),
            });
        }
        if self.sealed_bytes.is_empty() || sha256_hex(&self.sealed_bytes) != self.sealed_sha256 {
            return Err(EcxfError::DigestMismatch {
                subject: format!("blob {}", self.locator.hash),
            });
        }
        digest(&self.sealed_sha256, "sealed_sha256")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxfManifest {
    pub format: String,
    pub source_adapter: String,
    pub source_adapter_version: String,
    pub architecture_source_digest: String,
    pub normative_pair_identity_receipt_digest: String,
    pub scope_id: Option<ScopeId>,
    pub revision_start: Option<u64>,
    pub revision_end: Option<u64>,
    pub checksums: BTreeMap<String, String>,
    pub compression: CompressionProfile,
    pub encryption: EncryptionProfile,
    pub missing_features: Vec<String>,
    pub purge_state: PurgeExportState,
    pub export_receipt: String,
}

impl EcxfManifest {
    pub fn validate(&self) -> Result<(), EcxfError> {
        if self.format != FORMAT_VERSION {
            return Err(EcxfError::InvalidField {
                field: "format",
                reason: "unsupported ECXF format",
            });
        }
        text(&self.source_adapter, "source_adapter")?;
        text(&self.source_adapter_version, "source_adapter_version")?;
        digest(&self.architecture_source_digest, "architecture_source_digest")?;
        digest(
            &self.normative_pair_identity_receipt_digest,
            "normative_pair_identity_receipt_digest",
        )?;
        if let (Some(start), Some(end)) = (self.revision_start, self.revision_end)
            && start > end
        {
            return Err(EcxfError::InvalidField {
                field: "revision_range",
                reason: "start is greater than end",
            });
        }
        for (name, checksum) in &self.checksums {
            text(name, "checksums.name")?;
            digest(checksum, "checksums.value")?;
        }
        self.compression.validate()?;
        self.encryption.validate()?;
        unique(self.missing_features.iter().cloned(), "missing_features")?;
        for feature in &self.missing_features {
            text(feature, "missing_features.value")?;
        }
        text(&self.export_receipt, "export_receipt")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionProfile {
    pub algorithm: String,
    pub version: u32,
}

impl CompressionProfile {
    pub fn validate(&self) -> Result<(), EcxfError> {
        text(&self.algorithm, "compression.algorithm")?;
        if self.version == 0 {
            return Err(EcxfError::InvalidField {
                field: "compression.version",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionProfile {
    pub algorithm: String,
    pub version: u32,
    pub key_lineage: Option<String>,
    pub plaintext_keys_present: bool,
}

impl EncryptionProfile {
    pub fn validate(&self) -> Result<(), EcxfError> {
        text(&self.algorithm, "encryption.algorithm")?;
        if self.version == 0 || self.plaintext_keys_present {
            return Err(EcxfError::InvalidField {
                field: "encryption",
                reason: "version must be nonzero and plaintext keys are forbidden",
            });
        }
        if let Some(lineage) = &self.key_lineage {
            text(lineage, "encryption.key_lineage")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurgeExportState {
    Applied,
    IncludedLedger,
    NoEntries,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityManifest {
    pub manifest_sha256: String,
    pub section_sha256: BTreeMap<String, String>,
    pub blob_sha256: BTreeMap<String, String>,
    pub purge_ledger_sha256: String,
    pub archive_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EcxfArchive {
    pub manifest: EcxfManifest,
    pub export_fence: ExportFence,
    pub sections: BTreeMap<SectionKind, CanonicalSection>,
    pub blobs: Vec<EcxfBlob>,
    pub privacy_purge_ledger: Vec<PurgeLedgerEntry>,
    pub integrity: IntegrityManifest,
}

pub struct EcxfExportInput {
    pub manifest: EcxfManifest,
    pub export_fence: ExportFence,
    pub sections: Vec<CanonicalSection>,
    pub blobs: Vec<EcxfBlob>,
    pub privacy_purge_ledger: Vec<PurgeLedgerEntry>,
}

impl EcxfArchive {
    pub fn build(input: EcxfExportInput) -> Result<Self, EcxfError> {
        input.export_fence.validate()?;
        input.manifest.validate()?;
        if input.manifest.scope_id != input.export_fence.scope_id {
            return Err(EcxfError::InconsistentBoundary);
        }
        let mut sections = BTreeMap::new();
        for section in input.sections {
            section.validate()?;
            if sections.insert(section.kind, section).is_some() {
                return Err(EcxfError::Duplicate { field: "sections.kind" });
            }
        }
        for blob in &input.blobs {
            blob.validate()?;
        }
        unique(
            input.blobs.iter().map(|blob| blob.locator.hash.clone()),
            "blobs.hash",
        )?;
        let expected_blobs: BTreeSet<_> = input
            .export_fence
            .blob_reachability_manifest
            .iter()
            .cloned()
            .collect();
        let actual_blobs: BTreeSet<_> = input
            .blobs
            .iter()
            .map(|blob| blob.locator.hash.clone())
            .collect();
        if expected_blobs != actual_blobs {
            return Err(EcxfError::InconsistentBoundary);
        }
        unique(
            input
                .privacy_purge_ledger
                .iter()
                .map(|entry| entry.purge_id.clone()),
            "privacy_purge_ledger.purge_id",
        )?;
        for entry in &input.privacy_purge_ledger {
            entry
                .validate()
                .map_err(|error| EcxfError::Security(error.to_string()))?;
            if entry.state_fence != input.export_fence.state_fence {
                return Err(EcxfError::InconsistentBoundary);
            }
        }
        let mut manifest = input.manifest;
        manifest.checksums = sections
            .iter()
            .map(|(kind, section)| {
                (format!("{}/records", kind.wire_name()), section.canonical_sha256.clone())
            })
            .collect();
        manifest.checksums.extend(
            input
                .blobs
                .iter()
                .map(|blob| (format!("blobs/{}", blob.locator.hash), blob.sealed_sha256.clone())),
        );
        manifest.checksums.insert(
            "privacy-purge-ledger".to_owned(),
            sha256_hex(&canonical(&input.privacy_purge_ledger)?),
        );
        manifest.validate()?;
        let mut archive = Self {
            manifest,
            export_fence: input.export_fence,
            sections,
            blobs: input.blobs,
            privacy_purge_ledger: input.privacy_purge_ledger,
            integrity: IntegrityManifest {
                manifest_sha256: String::new(),
                section_sha256: BTreeMap::new(),
                blob_sha256: BTreeMap::new(),
                purge_ledger_sha256: String::new(),
                archive_sha256: String::new(),
            },
        };
        archive.recompute_integrity()?;
        archive.validate()?;
        Ok(archive)
    }

    fn manifest_digest(&self) -> Result<String, EcxfError> {
        Ok(sha256_hex(&canonical(&self.manifest)?))
    }

    fn purge_digest(&self) -> Result<String, EcxfError> {
        Ok(sha256_hex(&canonical(&self.privacy_purge_ledger)?))
    }

    fn archive_digest(&self) -> Result<String, EcxfError> {
        let mut copy = self.clone();
        copy.integrity.archive_sha256.clear();
        Ok(sha256_hex(&canonical(&copy)?))
    }

    fn recompute_integrity(&mut self) -> Result<(), EcxfError> {
        self.integrity.manifest_sha256 = self.manifest_digest()?;
        self.integrity.section_sha256 = self
            .sections
            .iter()
            .map(|(kind, section)| {
                (kind.wire_name().to_owned(), section.canonical_sha256.clone())
            })
            .collect();
        self.integrity.blob_sha256 = self
            .blobs
            .iter()
            .map(|blob| (blob.locator.hash.to_string(), blob.sealed_sha256.clone()))
            .collect();
        self.integrity.purge_ledger_sha256 = self.purge_digest()?;
        self.integrity.archive_sha256.clear();
        self.integrity.archive_sha256 = self.archive_digest()?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), EcxfError> {
        self.manifest.validate()?;
        self.export_fence.validate()?;
        for section in self.sections.values() {
            section.validate()?;
        }
        for blob in &self.blobs {
            blob.validate()?;
        }
        let expected_sections: BTreeMap<_, _> = self
            .sections
            .iter()
            .map(|(kind, section)| (kind.wire_name().to_owned(), section.canonical_sha256.clone()))
            .collect();
        let mut expected_checksums = expected_sections
            .iter()
            .map(|(name, checksum)| (format!("{name}/records"), checksum.clone()))
            .collect::<BTreeMap<_, _>>();
        expected_checksums.extend(
            self.blobs
                .iter()
                .map(|blob| (format!("blobs/{}", blob.locator.hash), blob.sealed_sha256.clone())),
        );
        expected_checksums.insert("privacy-purge-ledger".to_owned(), self.purge_digest()?);
        if self.manifest.checksums != expected_checksums {
            return Err(EcxfError::DigestMismatch {
                subject: "manifest checksums".to_owned(),
            });
        }
        if self.integrity.section_sha256 != expected_sections
            || self.integrity.manifest_sha256 != self.manifest_digest()?
            || self.integrity.purge_ledger_sha256 != self.purge_digest()?
        {
            return Err(EcxfError::DigestMismatch {
                subject: "integrity manifest".to_owned(),
            });
        }
        let expected_blobs: BTreeMap<_, _> = self
            .blobs
            .iter()
            .map(|blob| (blob.locator.hash.to_string(), blob.sealed_sha256.clone()))
            .collect();
        if self.integrity.blob_sha256 != expected_blobs
            || self.integrity.archive_sha256 != self.archive_digest()?
        {
            return Err(EcxfError::DigestMismatch {
                subject: "archive".to_owned(),
            });
        }
        Ok(())
    }

    pub fn manifest_json(&self) -> Result<Vec<u8>, EcxfError> {
        canonical(&self.manifest)
    }

    pub fn integrity_json(&self) -> Result<Vec<u8>, EcxfError> {
        canonical(&self.integrity)
    }

    pub fn section_ndjson(&self, kind: SectionKind) -> Result<Vec<u8>, EcxfError> {
        self.sections
            .get(&kind)
            .ok_or(EcxfError::InvalidField {
                field: "section",
                reason: "requested section is absent",
            })?
            .ndjson_bytes()
    }

    pub fn layout(&self, codec: &dyn SectionCodec) -> Result<BTreeMap<String, Vec<u8>>, EcxfError> {
        self.validate()?;
        let mut files = BTreeMap::new();
        files.insert("manifest.json".to_owned(), self.manifest_json()?);
        files.insert(
            "schema/ecxf-1.json".to_owned(),
            canonical(&serde_json::json!({
                "format": FORMAT_VERSION,
                "contract": CONTRACT_NAME,
                "sections": ["events", "projections", "receipts"],
            }))?,
        );
        for kind in [SectionKind::Events, SectionKind::Projections, SectionKind::Receipts] {
            if let Some(section) = self.sections.get(&kind) {
                let encoded = codec.encode(&section.ndjson_bytes()?)?;
                if encoded.len() > MAX_SECTION_BYTES {
                    return Err(EcxfError::Codec("encoded section exceeds limit".to_owned()));
                }
                files.insert(
                    format!("{}/records.ndjson{}", kind.wire_name(), codec.suffix()),
                    encoded,
                );
            }
        }
        for blob in &self.blobs {
            files.insert(
                format!("blobs/{}.blob", blob.locator.hash),
                blob.sealed_bytes.clone(),
            );
        }
        files.insert("integrity.json".to_owned(), self.integrity_json()?);
        files.insert(
            "privacy-purge-ledger.json".to_owned(),
            canonical(&self.privacy_purge_ledger)?,
        );
        Ok(files)
    }
}

pub trait SectionCodec: Send + Sync {
    fn suffix(&self) -> &'static str;
    fn encode(&self, canonical_ndjson: &[u8]) -> Result<Vec<u8>, EcxfError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IdentitySectionCodec;

impl SectionCodec for IdentitySectionCodec {
    fn suffix(&self) -> &'static str {
        ""
    }

    fn encode(&self, canonical_ndjson: &[u8]) -> Result<Vec<u8>, EcxfError> {
        Ok(canonical_ndjson.to_vec())
    }
}
