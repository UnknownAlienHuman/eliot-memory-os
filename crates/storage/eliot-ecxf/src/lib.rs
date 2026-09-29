//! Canonical ECXF/1 interchange source for ELIOT storage.
//!
//! ECXF is a logical, vendor-neutral representation of a fenced canonical
//! store. This crate deliberately does not open a database or a filesystem.
//! A store bridge supplies already-fenced records and completed blob receipts;
//! this crate validates their relationship, computes deterministic digests, and
//! exposes a layout writer for an injected section codec.
//!
//! The exchange has both halves. [`EcxfArchive::build`] and
//! [`EcxfArchive::layout`] write one package, and [`import_ecxf_package`] reads
//! one back, checking every member against the digest the package itself
//! recorded. Neither half is a backup or a restore decision: this crate decides
//! nothing about cutover, revocation or the current Store generation.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_blob_api::{BlobId, BlobLocator, BlobReadyReceipt, VersionedContentDigest};
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

/// Emitted package member names, owned here so the writer in [`EcxfArchive::layout`]
/// and the reader in [`admit_ecxf_import`] cannot drift apart.
const MANIFEST_FILE: &str = "manifest.json";
const INTEGRITY_FILE: &str = "integrity.json";
const PURGE_LEDGER_FILE: &str = "privacy-purge-ledger.json";
const SCHEMA_FILE: &str = "schema/ecxf-1.json";
/// Section members are `<kind>/records.ndjson<codec-suffix>` (I05-10 layout).
const SECTION_MEMBER_PREFIX: &str = "/records.ndjson";
/// Blob members are the residency-keyed entry path plus this suffix.
const BLOB_MEMBER_SUFFIX: &str = ".blob";

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
                if last
                    .checked_sub(first)
                    .and_then(|width| width.checked_add(1))
                    == Some(count) =>
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
    /// Opaque residency-key digests of every reachable exported blob
    /// (issue #1871, D1: I05-13 forbids merging records whose content digests
    /// match, so reachability is keyed on residency and not on content).
    // ASSUMPTION: the fence keeps one opaque residency-key digest per reachable
    // blob instead of a full residency record. I05-10 only calls this a "blob
    // residency/reachability manifest" and I05-13 requires the full residency
    // tuple per *entry*, which `EcxfBlobResidency` carries in the manifest. A
    // fence is a set identity, so a digest per residency key is the smallest
    // change that makes a set comparison against the source store meaningful
    // when equal bytes exist in two domains.
    pub blob_reachability_manifest: Vec<String>,
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
        for entry in &self.blob_reachability_manifest {
            digest(entry, "blob_reachability_manifest.value")?;
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
    /// Returns the opaque I05-12 residency-key digest of this blob
    /// (issue #1871, D1: blob identity is residency-keyed, never the content
    /// digest alone, because I05-13 forbids merging equal bytes that carry
    /// different obligations).
    ///
    /// The value is the normative derivation of
    /// `ObjectResidencyKey::key_digest`; this crate never re-hashes or
    /// re-serializes the residency key itself.
    // ASSUMPTION: the residency-key digest source is the existing
    // `BlobLocator::residency_key_digest()` (which delegates to
    // `ObjectResidencyKey::key_digest`). I05-12 requires the physical path to
    // be derived from the full residency identity and I05-13 forbids merging on
    // content digest, but neither document names the digest bytes or the
    // algorithm, so this crate reuses the single existing normative derivation
    // and adds no second hash algorithm of its own.
    pub fn residency_key_digest(&self) -> Result<String, EcxfError> {
        self.locator
            .residency_key_digest()
            .map_err(|error| EcxfError::Blob(error.to_string()))
    }

    /// Returns the logical `ECXF/1` path of this blob entry
    /// (I05-10 `blobs/<residency-key-digest>/<content-digest>.blob`; issue
    /// #1871, D1). The emitted file appends the `.blob` suffix, and the
    /// manifest checksum key omits it exactly like the extension-less
    /// `events/records` section keys.
    pub fn entry_path(&self) -> Result<String, EcxfError> {
        Ok(blob_entry_path(
            &self.residency_key_digest()?,
            &self.locator.residency().content_digest.digest.to_string(),
        ))
    }

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

/// Builds the residency-keyed logical path of one blob entry
/// (I05-10 `blobs/<residency-key-digest>/<content-digest>.blob`, issue #1871).
fn blob_entry_path(residency_key_digest: &str, content_digest: &str) -> String {
    format!("blobs/{residency_key_digest}/{content_digest}")
}

/// Logical package member name of one blob entry (issue #1141: the writer and
/// the importer derive it from one function so they cannot drift).
fn blob_member_name(entry_path: &str) -> String {
    format!("{entry_path}{BLOB_MEMBER_SUFFIX}")
}

/// Logical package member name of one section (issue #1141).
fn section_member_name(wire_name: &str, codec_suffix: &str) -> String {
    format!("{wire_name}{SECTION_MEMBER_PREFIX}{codec_suffix}")
}

/// Manifest-side residency entry for one exported blob (issue #1871, D2).
///
/// I05-13 requires that every export entry preserve the opaque residency-key
/// digest, the versioned content digest, the retention and erasure domains and
/// the purge-ledger revision, and that export never merges blob records solely
/// because their content digests match. [`BlobReadyReceipt`] already binds
/// every one of those values, but it is a serialize-only capability whose
/// residency domains are checked in memory and never reach the wire, so the
/// already-bound values are projected here into the emitted manifest instead of
/// being re-derived, re-serialized or re-hashed by this crate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxfBlobResidency {
    /// Opaque residency-key digest from `BlobLocator::residency_key_digest`.
    pub residency_key_digest: String,
    /// Versioned content digest carried inside the residency key (I05-12).
    pub content_digest: VersionedContentDigest,
    /// Retention/lifecycle domain identity of the residency key.
    pub retention_domain_id: BlobId,
    /// Erasure/purge-closure domain identity of the residency key.
    pub erasure_domain_id: BlobId,
    /// Key lineage bound by the `BlobReadyReceipt` crypto descriptor (I05-13:
    /// the export carries key lineage and format metadata, never key bytes).
    pub key_lineage: BlobId,
}

impl EcxfBlobResidency {
    /// Projects one already-bound `BlobReadyReceipt` onto its manifest entry
    /// (issue #1871, D2: every value is read from the receipt's existing
    /// accessors, so the entry cannot drift from the durable blob record).
    pub fn from_ready_receipt(receipt: &BlobReadyReceipt) -> Result<Self, EcxfError> {
        let residency = receipt.locator().residency();
        let value = Self {
            residency_key_digest: receipt
                .locator()
                .residency_key_digest()
                .map_err(|error| EcxfError::Blob(error.to_string()))?,
            content_digest: residency.content_digest.clone(),
            retention_domain_id: residency.retention_domain_id.clone(),
            erasure_domain_id: residency.erasure_domain_id.clone(),
            key_lineage: receipt.crypto().key_lineage.clone(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the shape of one manifest residency entry using the same local
    /// helpers as the rest of the manifest (issue #1871, D2).
    pub fn validate(&self) -> Result<(), EcxfError> {
        digest(
            &self.residency_key_digest,
            "blob_residency.residency_key_digest",
        )?;
        self.content_digest
            .validate()
            .map_err(|error| EcxfError::Blob(error.to_string()))?;
        text(
            self.retention_domain_id.as_str(),
            "blob_residency.retention_domain_id",
        )?;
        text(
            self.erasure_domain_id.as_str(),
            "blob_residency.erasure_domain_id",
        )?;
        text(self.key_lineage.as_str(), "blob_residency.key_lineage")?;
        Ok(())
    }
}

/// Returns the purge-ledger revision recorded for the carried entries
/// (I05-13 binds every export entry to a purge-ledger revision; issue #1871,
/// D2). The revision of a non-empty ledger is the highest
/// `PurgeLedgerEntry::revision` it carries. An empty ledger has no revision.
fn derived_purge_ledger_revision(ledger: &[PurgeLedgerEntry]) -> Result<Option<u64>, EcxfError> {
    let mut revision: Option<u64> = None;
    for entry in ledger {
        entry
            .validate()
            .map_err(|error| EcxfError::Security(error.to_string()))?;
        revision = match revision {
            Some(seen) => Some(seen.max(entry.revision)),
            None => Some(entry.revision),
        };
    }
    Ok(revision)
}

/// Binds the manifest's declared purge state to the ledger the package
/// actually carries (issue #1141, A2/W3).
///
/// I5.13 binds every export entry to "retention/erasure domains and
/// purge-ledger revision", and A2 requires the erasure identity to be a
/// recorded one rather than a claim. The manifest's `purge_state` is one
/// recorded position; the carried `privacy-purge-ledger.json` member is a
/// second, independent one. This function compares them in both directions, so
/// neither can be edited without the other:
///
/// * a manifest that declares a carried ledger while the package carries an
///   empty one is refused, because its erasure claim has no ledger behind it;
/// * a manifest that declares no entries while the package carries a ledger is
///   refused, because the package would ship purge evidence the manifest does
///   not acknowledge.
///
/// `PurgeExportState::Applied` is deliberately left unbound here. It asserts
/// that the *source* already removed the purged content, which nothing in this
/// package can observe, so this crate has no second recorded position to
/// compare it against and no rule may be invented for one.
///
/// It re-uses `derived_purge_ledger_revision` and the existing
/// `PurgeLedgerEntry::validate`, so this is a comparison between two recorded
/// sets and not a second definition of either. The check runs where the ledger
/// is known — `EcxfArchive::validate` and `import_ecxf_package` — and never
/// from `EcxfManifest::validate`, which has no ledger to compare against.
fn check_purge_claim(
    manifest: &EcxfManifest,
    ledger: &[PurgeLedgerEntry],
) -> Result<(), EcxfError> {
    let carried = !ledger.is_empty();
    if carried != (manifest.purge_state == PurgeExportState::IncludedLedger) {
        return Err(EcxfError::InconsistentBoundary);
    }
    if manifest.purge_ledger_revision != derived_purge_ledger_revision(ledger)? {
        return Err(EcxfError::DigestMismatch {
            subject: "purge ledger revision".to_owned(),
        });
    }
    Ok(())
}

/// Binds the export fence's declared canonical event interval to the events the
/// package actually carries (issue #1141, A3).
///
/// I5.10 requires the export fence to carry "the canonical event range" and
/// forbids "mixing unrelated table moments into one 'backup'". A package whose
/// fence declares `count` events while carrying a different number of event
/// records spans a moment its own boundary does not describe: either the
/// interval was narrowed after the events were read, or records were dropped
/// from under a recorded range. Neither is visible by examining the section
/// alone, because a truncated section is internally self-consistent and
/// re-digests cleanly — which is exactly why the recorded digests are not
/// sufficient evidence here.
///
/// The two sides come from different recorded positions — the fence is written
/// by the export boundary, the section is written by the record stream — so
/// this compares against an independent expected count rather than a value with
/// its own twin. An empty export stays representable: a fence with no interval
/// declares `count == 0`, and that is a real recorded count, not a synthesized
/// bound.
fn check_event_coverage(
    export_fence: &ExportFence,
    sections: &BTreeMap<SectionKind, CanonicalSection>,
) -> Result<(), EcxfError> {
    let carried = sections
        .get(&SectionKind::Events)
        .map_or(0_u64, |section| section.record_count);
    if carried != export_fence.event_range.count {
        return Err(EcxfError::InconsistentBoundary);
    }
    Ok(())
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
    /// Highest carried `PurgeLedgerEntry::revision`; `None` when the archive
    /// carries no purge-ledger entry (I05-13 purge-ledger revision; issue
    /// #1871, D2).
    // ASSUMPTION: an absent revision is represented by `None` rather than a
    // sentinel integer, because I05-13 ties the revision to the carried ledger
    // and `PurgeExportState::NoEntries` legitimately has no ledger to carry a
    // revision. A magic `0` would fabricate a revision and a magic `u64::MAX`
    // would fabricate a revision order, so the typed absence is the only
    // representation that cannot be mistaken for a real one.
    pub purge_ledger_revision: Option<u64>,
    /// Per-blob residency, retention and erasure entries (I05-10 "opaque blob
    /// residency identities plus retention/erasure domains"; issue #1871, D2).
    pub blob_residency: Vec<EcxfBlobResidency>,
    /// The export fence, recoverable from the emitted `manifest.json`
    /// (I05-10 "consistent export boundary"; issue #1871, D3).
    // ASSUMPTION: the fence is nested in the manifest rather than emitted as a
    // separate `export_fence.json`, because the issue acceptance names the
    // manifest as the artifact that must contain it. The digest chain stays
    // acyclic: the fence references no archive digest, `manifest_sha256` in
    // `integrity.json` covers the fence transitively, and `archive_digest`
    // only clears `archive_sha256` when cloning, so no value is hashed into
    // itself. Keeping a second sibling copy of the fence on `EcxfArchive`
    // would create two sources of truth that could disagree, so the manifest
    // entry is the only owner.
    pub export_fence: ExportFence,
    pub export_receipt: String,
}

impl EcxfManifest {
    /// Validates the emitted manifest, including the nested export fence, the
    /// per-blob residency entries and the purge-ledger revision (issue #1871,
    /// D2 and D3; I05-10 manifest contents, I05-13 retention/erasure domains).
    pub fn validate(&self) -> Result<(), EcxfError> {
        if self.format != FORMAT_VERSION {
            return Err(EcxfError::InvalidField {
                field: "format",
                reason: "unsupported ECXF format",
            });
        }
        text(&self.source_adapter, "source_adapter")?;
        text(&self.source_adapter_version, "source_adapter_version")?;
        digest(
            &self.architecture_source_digest,
            "architecture_source_digest",
        )?;
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
        // Issue #1141, W3: the manifest is what travels, and on import it is
        // validated on its own before any payload is looked at, when there is
        // no archive and no delivered blob to check it against. So the two
        // coherence checks a package must satisfy before a byte of it is read
        // belong here.
        //
        // The fence's blob reachability set is deliberately NOT compared to
        // `blob_residency` here: `EcxfArchive::build` validates the
        // caller-assembled manifest before it derives the residency entries, so
        // at that point the residency set is legitimately still empty. That
        // comparison belongs where the delivered blobs are known, which is
        // `check_reachability` and `EcxfArchive::validate`; the importer
        // repeats it against the members it actually received.
        let head_span =
            self.export_fence
                .revision_heads
                .iter()
                .fold(None::<(u64, u64)>, |span, head| {
                    Some(match span {
                        Some((start, end)) => (start.min(head.revision), end.max(head.revision)),
                        None => (head.revision, head.revision),
                    })
                });
        if head_span != self.revision_start.zip(self.revision_end) {
            return Err(EcxfError::InconsistentBoundary);
        }
        // The manifest and the fence it carries describe one export scope. A
        // package whose two records disagree is incoherent, not a choice the
        // importer may resolve by picking one.
        if self.scope_id != self.export_fence.scope_id {
            return Err(EcxfError::InconsistentBoundary);
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
        if self.purge_state == PurgeExportState::NoEntries && self.purge_ledger_revision.is_some() {
            return Err(EcxfError::InvalidField {
                field: "purge_ledger_revision",
                reason: "must be absent when the export declares no purge entries",
            });
        }
        unique(
            self.blob_residency
                .iter()
                .map(|entry| entry.residency_key_digest.clone()),
            "blob_residency.residency_key_digest",
        )?;
        for entry in &self.blob_residency {
            entry.validate()?;
        }
        self.export_fence.validate()?;
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

impl IntegrityManifest {
    /// Every recorded digest must be a lowercase SHA-256 hex value, so a
    /// corrupt or absent `integrity.json` cannot be read back as an empty
    /// successful export (issue #1141, A2/A5).
    pub fn validate(&self) -> Result<(), EcxfError> {
        digest(&self.manifest_sha256, "integrity.manifest_sha256")?;
        digest(&self.purge_ledger_sha256, "integrity.purge_ledger_sha256")?;
        digest(&self.archive_sha256, "integrity.archive_sha256")?;
        for (name, checksum) in &self.section_sha256 {
            text(name, "integrity.section_sha256.name")?;
            digest(checksum, "integrity.section_sha256.value")?;
        }
        for (name, checksum) in &self.blob_sha256 {
            text(name, "integrity.blob_sha256.name")?;
            digest(checksum, "integrity.blob_sha256.value")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EcxfArchive {
    /// The emitted manifest. It owns the `ExportFence` (issue #1871, D3), the
    /// per-blob residency entries and the purge-ledger revision (issue #1871,
    /// D2), so `manifest.json` alone is enough to recover and re-check the
    /// whole export boundary against the source store.
    pub manifest: EcxfManifest,
    pub sections: BTreeMap<SectionKind, CanonicalSection>,
    pub blobs: Vec<EcxfBlob>,
    pub privacy_purge_ledger: Vec<PurgeLedgerEntry>,
    pub integrity: IntegrityManifest,
}

pub struct EcxfExportInput {
    /// Caller-assembled manifest. Its `export_fence` is validated here and is
    /// not replaced; `blob_residency`, `purge_ledger_revision` and `checksums`
    /// are derived from the supplied blobs, ledger and sections.
    pub manifest: EcxfManifest,
    pub sections: Vec<CanonicalSection>,
    pub blobs: Vec<EcxfBlob>,
    pub privacy_purge_ledger: Vec<PurgeLedgerEntry>,
}

/// Compares the fence reachability set with the exported residency keys
/// (issue #1871, D1: both sides are residency-keyed, so equal bytes in two
/// domains stay two distinct reachable objects per I05-13).
fn check_reachability(export_fence: &ExportFence, blobs: &[EcxfBlob]) -> Result<(), EcxfError> {
    let expected: BTreeSet<_> = export_fence
        .blob_reachability_manifest
        .iter()
        .cloned()
        .collect();
    let mut actual = BTreeSet::new();
    for blob in blobs {
        actual.insert(blob.residency_key_digest()?);
    }
    if expected != actual || expected.len() != blobs.len() {
        return Err(EcxfError::InconsistentBoundary);
    }
    Ok(())
}

impl EcxfArchive {
    /// Assembles one coherent `ECXF/1` export (I05-10 "consistent export
    /// boundary"; issue #1871). Blob identity, reachability, checksums and
    /// integrity entries are residency-keyed (D1), the residency, retention,
    /// erasure and purge-ledger-revision metadata is projected into the
    /// manifest from the already-bound blob receipts (D2), and the export fence
    /// is carried inside the manifest it is emitted in (D3).
    pub fn build(input: EcxfExportInput) -> Result<Self, EcxfError> {
        let export_fence = input.manifest.export_fence.clone();
        input.manifest.validate()?;
        if input.manifest.scope_id != export_fence.scope_id {
            return Err(EcxfError::InconsistentBoundary);
        }
        let mut sections = BTreeMap::new();
        for section in input.sections {
            section.validate()?;
            if sections.insert(section.kind, section).is_some() {
                return Err(EcxfError::Duplicate {
                    field: "sections.kind",
                });
            }
        }
        let mut residency_keys = BTreeSet::new();
        for blob in &input.blobs {
            blob.validate()?;
            if !residency_keys.insert(blob.residency_key_digest()?) {
                return Err(EcxfError::Duplicate {
                    field: "blobs.residency_key_digest",
                });
            }
        }
        check_reachability(&export_fence, &input.blobs)?;
        unique(
            input
                .privacy_purge_ledger
                .iter()
                .map(|entry| entry.purge_id.clone()),
            "privacy_purge_ledger.purge_id",
        )?;
        for entry in &input.privacy_purge_ledger {
            if entry.state_fence != export_fence.state_fence {
                return Err(EcxfError::InconsistentBoundary);
            }
        }
        let purge_ledger_revision = derived_purge_ledger_revision(&input.privacy_purge_ledger)?;
        let mut manifest = input.manifest;
        manifest.checksums = sections
            .iter()
            .map(|(kind, section)| {
                (
                    format!("{}/records", kind.wire_name()),
                    section.canonical_sha256.clone(),
                )
            })
            .collect();
        for blob in &input.blobs {
            manifest
                .checksums
                .insert(blob.entry_path()?, blob.sealed_sha256.clone());
        }
        manifest.checksums.insert(
            "privacy-purge-ledger".to_owned(),
            sha256_hex(&canonical(&input.privacy_purge_ledger)?),
        );
        manifest.purge_ledger_revision = purge_ledger_revision;
        // Issue #1871, D2: the residency entries are emitted in residency-key
        // digest order so the manifest bytes do not depend on input blob order.
        manifest.blob_residency = input
            .blobs
            .iter()
            .map(|blob| EcxfBlobResidency::from_ready_receipt(&blob.ready_receipt))
            .collect::<Result<Vec<_>, EcxfError>>()?;
        manifest
            .blob_residency
            .sort_by(|left, right| left.residency_key_digest.cmp(&right.residency_key_digest));
        // Issue #1141, A3: the fence declares the canonical event interval and
        // the caller supplies the events. Refuse a view whose two disagree
        // before the manifest is accepted, so `EcxfManifest::validate` is never
        // reached with a fence that over- or under-declares its own range.
        check_event_coverage(&export_fence, &sections)?;
        manifest.validate()?;
        let mut archive = Self {
            manifest,
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

    /// Recomputes every integrity digest, keyed by the residency-keyed blob
    /// entry path (issue #1871, D1). No digest covers itself: the archive digest
    /// is computed on a clone whose own `archive_sha256` is cleared.
    fn recompute_integrity(&mut self) -> Result<(), EcxfError> {
        self.integrity.manifest_sha256 = self.manifest_digest()?;
        self.integrity.section_sha256 = self
            .sections
            .iter()
            .map(|(kind, section)| {
                (
                    kind.wire_name().to_owned(),
                    section.canonical_sha256.clone(),
                )
            })
            .collect();
        self.integrity.blob_sha256 = self
            .blobs
            .iter()
            .map(|blob| Ok((blob.entry_path()?, blob.sealed_sha256.clone())))
            .collect::<Result<BTreeMap<_, _>, EcxfError>>()?;
        self.integrity.purge_ledger_sha256 = self.purge_digest()?;
        self.integrity.archive_sha256.clear();
        self.integrity.archive_sha256 = self.archive_digest()?;
        Ok(())
    }

    /// Re-checks the whole export against its own emitted bytes: manifest
    /// residency and purge-ledger revision, fence reachability, checksums and
    /// integrity digests (issue #1871, D1 to D3).
    pub fn validate(&self) -> Result<(), EcxfError> {
        self.manifest.validate()?;
        for section in self.sections.values() {
            section.validate()?;
        }
        for blob in &self.blobs {
            blob.validate()?;
        }
        check_reachability(&self.manifest.export_fence, &self.blobs)?;
        // Issue #1141, A2/A3: the two recorded positions that only disagree in
        // one direction each. `check_purge_claim` re-derives the revision from
        // the carried ledger and compares it in both directions against the
        // declared purge state; `check_event_coverage` compares the fence's
        // declared interval against the events the archive actually holds.
        // Both run before any caller can act on the archive.
        check_purge_claim(&self.manifest, &self.privacy_purge_ledger)?;
        check_event_coverage(&self.manifest.export_fence, &self.sections)?;
        let expected_residency: BTreeMap<_, _> = self
            .blobs
            .iter()
            .map(|blob| {
                Ok((
                    blob.residency_key_digest()?,
                    EcxfBlobResidency::from_ready_receipt(&blob.ready_receipt)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, EcxfError>>()?;
        let actual_residency: BTreeMap<_, _> = self
            .manifest
            .blob_residency
            .iter()
            .map(|entry| (entry.residency_key_digest.clone(), entry.clone()))
            .collect();
        if actual_residency != expected_residency {
            return Err(EcxfError::DigestMismatch {
                subject: "manifest blob residency".to_owned(),
            });
        }
        let expected_sections: BTreeMap<_, _> = self
            .sections
            .iter()
            .map(|(kind, section)| {
                (
                    kind.wire_name().to_owned(),
                    section.canonical_sha256.clone(),
                )
            })
            .collect();
        let mut expected_checksums = expected_sections
            .iter()
            .map(|(name, checksum)| (format!("{name}/records"), checksum.clone()))
            .collect::<BTreeMap<_, _>>();
        for blob in &self.blobs {
            expected_checksums.insert(blob.entry_path()?, blob.sealed_sha256.clone());
        }
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
            .map(|blob| Ok((blob.entry_path()?, blob.sealed_sha256.clone())))
            .collect::<Result<BTreeMap<_, _>, EcxfError>>()?;
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

    /// Emits the `ECXF/1` directory contents (I05-10 layout; issue #1871):
    /// residency-keyed `blobs/<residency-key-digest>/<content-digest>.blob`
    /// entries (D1) and a `manifest.json` that carries the recoverable export
    /// fence (D3).
    pub fn layout(&self, codec: &dyn SectionCodec) -> Result<BTreeMap<String, Vec<u8>>, EcxfError> {
        self.validate()?;
        let mut files = BTreeMap::new();
        files.insert(MANIFEST_FILE.to_owned(), self.manifest_json()?);
        files.insert(
            SCHEMA_FILE.to_owned(),
            canonical(&serde_json::json!({
                "format": FORMAT_VERSION,
                "contract": CONTRACT_NAME,
                "sections": ["events", "projections", "receipts"],
            }))?,
        );
        for kind in [
            SectionKind::Events,
            SectionKind::Projections,
            SectionKind::Receipts,
        ] {
            if let Some(section) = self.sections.get(&kind) {
                let encoded = codec.encode(&section.ndjson_bytes()?)?;
                if encoded.len() > MAX_SECTION_BYTES {
                    return Err(EcxfError::Codec("encoded section exceeds limit".to_owned()));
                }
                files.insert(
                    section_member_name(kind.wire_name(), codec.suffix()),
                    encoded,
                );
            }
        }
        for blob in &self.blobs {
            files.insert(
                blob_member_name(&blob.entry_path()?),
                blob.sealed_bytes.clone(),
            );
        }
        files.insert(INTEGRITY_FILE.to_owned(), self.integrity_json()?);
        files.insert(
            PURGE_LEDGER_FILE.to_owned(),
            canonical(&self.privacy_purge_ledger)?,
        );
        // Issue #1871, D3: no separate fence artifact is emitted. The fence is
        // inside `manifest.json`, so the recoverable `manifest_sha256` in
        // `integrity.json` covers it and a consumer can re-check the fence
        // against the source store from the produced directory alone.
        Ok(files)
    }
}

pub trait SectionCodec: Send + Sync {
    fn suffix(&self) -> &'static str;
    fn encode(&self, canonical_ndjson: &[u8]) -> Result<Vec<u8>, EcxfError>;
    /// Restores the canonical NDJSON bytes of one encoded section member.
    ///
    /// Issue #1141: the import side must re-check a recorded section digest
    /// against the emitted member, and the recorded digest covers the canonical
    /// NDJSON. A codec that can encode but not decode leaves that digest
    /// unverifiable, so decoding is part of the same closed port as encoding
    /// rather than a separate capability the importer has to assume.
    fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>, EcxfError>;
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

    fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>, EcxfError> {
        Ok(encoded.to_vec())
    }
}

/// One blob member of an imported package.
///
/// Issue #1141: the import side cannot rebuild [`EcxfBlob`], because
/// [`BlobReadyReceipt`] is a serialize-only capability with no public
/// constructor and no `Deserialize` impl. Reconstructing one here would
/// fabricate the exact receipt the export bound, so the import returns the
/// sealed bytes plus the residency identity the manifest recorded, and leaves
/// the receipt reconstruction to the owner that holds the blob service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedBlob {
    /// Residency-keyed logical entry path, without the member suffix.
    pub entry_path: String,
    pub sealed_bytes: Vec<u8>,
    /// The digest the manifest and the integrity manifest both recorded.
    pub sealed_sha256: String,
    /// The residency, retention, erasure and key-lineage identity the manifest
    /// recorded for this entry.
    pub residency: EcxfBlobResidency,
}

/// An `ECXF/1` package admitted for restore.
///
/// Every field here was recovered from the emitted package and re-checked
/// against a digest the package itself recorded at export time. Nothing is
/// recomputed from a value the importer supplied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcxfImport {
    pub manifest: EcxfManifest,
    /// Carried through unchanged. `archive_sha256` covers the export-time
    /// `EcxfArchive`, whose `BlobReadyReceipt` values are serialize-only and
    /// therefore not reconstructible here, so that one digest is NOT
    /// independently verified by this import. Every manifest, section and blob
    /// digest below it is.
    pub integrity: IntegrityManifest,
    pub sections: BTreeMap<SectionKind, CanonicalSection>,
    pub blobs: Vec<ImportedBlob>,
    pub privacy_purge_ledger: Vec<PurgeLedgerEntry>,
}

impl EcxfImport {
    /// The recorded blob digests, keyed by residency-keyed entry path.
    ///
    /// Issue #1141: the restore owner needs the sealed identity of each
    /// admitted blob without re-deriving it, and this map is built from the
    /// digests the package recorded rather than from anything the caller
    /// supplied.
    pub fn blob_digests(&self) -> BTreeMap<&str, &str> {
        self.blobs
            .iter()
            .map(|blob| (blob.entry_path.as_str(), blob.sealed_sha256.as_str()))
            .collect()
    }
}

/// Resolves one recorded section wire name back to its [`SectionKind`].
fn section_kind_from_wire_name(wire_name: &str) -> Result<SectionKind, EcxfError> {
    match wire_name {
        "events" => Ok(SectionKind::Events),
        "projections" => Ok(SectionKind::Projections),
        "receipts" => Ok(SectionKind::Receipts),
        _ => Err(EcxfError::InvalidField {
            field: "integrity.section_sha256.name",
            reason: "recorded section name is not an ECXF/1 section",
        }),
    }
}

/// Reads back and admits one emitted `ECXF/1` package for restore.
///
/// This is the import half of the exchange format (issue #1141, W3 and A2): the
/// crate only ever offered `build` and `layout`, so an emitted package had no
/// path back to a validated value. It takes the package members as they were
/// read from the published artifact and, for every member, checks the bytes
/// against the digest the package recorded for that member.
///
/// The order is deliberate and every refusal happens before any caller can act
/// on the result:
///
/// ```text
/// manifest/integrity/ledger/schema members present and well formed
///   → the manifest's own `validate()` runs on the recorded values
///   → the recorded manifest digest is checked against the manifest bytes
///   → the recorded purge-ledger digest is checked against the ledger bytes,
///     and the ledger's own validation, purge revision and state fence
///   → the recorded purge state is compared against the carried ledger in both
///     directions, and the fence's event interval against the delivered events
///   → the recorded schema declaration is checked against this crate's format
///   → every recorded section member is decoded and checked against its digest
///   → every recorded blob member is checked against its digest
///   → the member set is compared in both directions, so a missing member and
///     an unrecorded member are both explicit
/// ```
///
/// This function is deliberately NOT a restore: it reads no database and no
/// filesystem, and it decides nothing about cutover, revocation or the current
/// Store generation. It returns a validated artifact; the owner that admitted
/// the export decides whether it may become current state.
#[allow(
    clippy::too_many_lines,
    reason = "one linear admission path: members, recorded digests, ledger, schema, sections, blobs, completeness"
)]
pub fn import_ecxf_package(
    files: &BTreeMap<String, Vec<u8>>,
    codec: &dyn SectionCodec,
) -> Result<EcxfImport, EcxfError> {
    // Fixed package members. These four names are static, so each refusal
    // names the member it is about.
    let manifest_bytes = files.get(MANIFEST_FILE).ok_or(EcxfError::InvalidField {
        field: MANIFEST_FILE,
        reason: "package member is absent",
    })?;
    let integrity_bytes = files.get(INTEGRITY_FILE).ok_or(EcxfError::InvalidField {
        field: INTEGRITY_FILE,
        reason: "package member is absent",
    })?;
    let ledger_bytes = files
        .get(PURGE_LEDGER_FILE)
        .ok_or(EcxfError::InvalidField {
            field: PURGE_LEDGER_FILE,
            reason: "package member is absent",
        })?;
    let schema_bytes = files.get(SCHEMA_FILE).ok_or(EcxfError::InvalidField {
        field: SCHEMA_FILE,
        reason: "package member is absent",
    })?;

    // Parse the recorded artifacts and run their own existing validators, so
    // this function never becomes a second validator for a type it did not
    // write.
    let manifest: EcxfManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| EcxfError::Serialization(error.to_string()))?;
    manifest.validate()?;
    let integrity: IntegrityManifest = serde_json::from_slice(integrity_bytes)
        .map_err(|error| EcxfError::Serialization(error.to_string()))?;
    integrity.validate()?;
    let privacy_purge_ledger: Vec<PurgeLedgerEntry> = serde_json::from_slice(ledger_bytes)
        .map_err(|error| EcxfError::Serialization(error.to_string()))?;

    // The recorded digests, checked against the bytes as emitted. These are the
    // values the export recorded in `integrity.json`; recomputing them from the
    // manifest and calling that a proof would only prove the manifest hashes to
    // itself.
    if integrity.manifest_sha256 != sha256_hex(manifest_bytes) {
        return Err(EcxfError::DigestMismatch {
            subject: MANIFEST_FILE.to_owned(),
        });
    }
    if integrity.purge_ledger_sha256 != sha256_hex(ledger_bytes) {
        return Err(EcxfError::DigestMismatch {
            subject: PURGE_LEDGER_FILE.to_owned(),
        });
    }
    let recorded_ledger_digest =
        manifest
            .checksums
            .get("privacy-purge-ledger")
            .ok_or(EcxfError::InvalidField {
                field: "checksums.privacy-purge-ledger",
                reason: "manifest does not record the purge-ledger member",
            })?;
    if recorded_ledger_digest != &integrity.purge_ledger_sha256 {
        return Err(EcxfError::DigestMismatch {
            subject: "privacy-purge-ledger".to_owned(),
        });
    }

    // The ledger the package carries must be the ledger the manifest describes:
    // valid entries, the recorded purge revision, and one state fence with the
    // export fence. A ledger from another epoch cannot be admitted as this
    // export's erasure evidence.
    unique(
        privacy_purge_ledger
            .iter()
            .map(|entry| entry.purge_id.clone()),
        "privacy_purge_ledger.purge_id",
    )?;
    for entry in &privacy_purge_ledger {
        entry
            .validate()
            .map_err(|error| EcxfError::Security(error.to_string()))?;
        if entry.state_fence != manifest.export_fence.state_fence {
            return Err(EcxfError::InconsistentBoundary);
        }
    }
    // Issue #1141, A2: the declared purge state is compared against the ledger
    // the package actually carries, in both directions, so a manifest that
    // claims a carried ledger with an empty member — or acknowledges no entries
    // while shipping one — cannot be admitted. This REPLACES the one-directional
    // revision comparison that stood here alone: the revision on its own could
    // not tell an empty ledger from a ledger that merely declares no revision,
    // because `derived_purge_ledger_revision` answers `None` for both. It runs
    // on the recorded manifest and the recorded ledger member, before any
    // section or blob is decoded, and re-uses the entry validation and revision
    // derivation above, so it is a comparison between two recorded positions
    // and not a second definition of either.
    check_purge_claim(&manifest, &privacy_purge_ledger)?;

    // The recorded schema declaration must be this crate's format and contract,
    // so a package that declares another format cannot be read as ECXF/1.
    let schema: Value = serde_json::from_slice(schema_bytes)
        .map_err(|error| EcxfError::Serialization(error.to_string()))?;
    if schema.get("format").and_then(Value::as_str) != Some(FORMAT_VERSION)
        || schema.get("contract").and_then(Value::as_str) != Some(CONTRACT_NAME)
    {
        return Err(EcxfError::InvalidField {
            field: SCHEMA_FILE,
            reason: "recorded schema declaration is not this ECXF/1 contract",
        });
    }

    // Every recorded section member. The expected set is the section names the
    // integrity manifest recorded; the actual set is the decoded member bytes,
    // and the two must agree before any record is returned.
    let mut sections = BTreeMap::new();
    for (wire_name, recorded_digest) in &integrity.section_sha256 {
        let kind = section_kind_from_wire_name(wire_name)?;
        let member = section_member_name(wire_name, codec.suffix());
        let encoded = files.get(&member).ok_or_else(|| {
            EcxfError::Codec(format!("recorded section member {member} is absent"))
        })?;
        if encoded.len() > MAX_SECTION_BYTES {
            return Err(EcxfError::Codec(format!(
                "section member {member} exceeds MAX_SECTION_BYTES"
            )));
        }
        // Bounding the encoded member is not enough: a codec that expands its
        // input must not be able to hand back an unbounded buffer either, so
        // the decoded canonical bytes are bounded by the same limit. Archive
        // extraction stays bounded (issue #1141, mutable scope).
        let canonical_ndjson = codec.decode(encoded)?;
        if canonical_ndjson.len() > MAX_SECTION_BYTES {
            return Err(EcxfError::Codec(format!(
                "decoded section member {member} exceeds MAX_SECTION_BYTES"
            )));
        }
        if sha256_hex(&canonical_ndjson) != *recorded_digest {
            return Err(EcxfError::DigestMismatch {
                subject: member.clone(),
            });
        }
        // The manifest records the same section checksum under its
        // `<name>/records` key; a manifest that disagrees with the integrity
        // manifest about a section is a corrupt package, not a choice.
        if manifest.checksums.get(&format!("{wire_name}/records")) != Some(recorded_digest) {
            return Err(EcxfError::DigestMismatch {
                subject: format!("{wire_name}/records"),
            });
        }
        // A section member is NDJSON: one canonical record object per line.
        // Each record carries its own payload digest, so a corrupted or
        // reordered line is refused by the record and section validators rather
        // than reassembled into a section that merely hashes the same.
        let mut records = Vec::new();
        for line in canonical_ndjson.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let record: EcxfRecord = serde_json::from_slice(line)
                .map_err(|error| EcxfError::Serialization(error.to_string()))?;
            records.push(record);
        }
        let section = CanonicalSection::new(kind, records)?;
        if section.canonical_sha256 != *recorded_digest {
            return Err(EcxfError::DigestMismatch {
                subject: format!("{wire_name}/records"),
            });
        }
        if sections.insert(kind, section).is_some() {
            return Err(EcxfError::Duplicate {
                field: "sections.kind",
            });
        }
    }
    // Issue #1141, A3: the fence's recorded canonical event interval against
    // the events this package actually delivered. The interval was written by
    // the export boundary and the events by the record stream, so this is a
    // comparison between two independent recorded positions. A package whose
    // event stream was truncated under a recorded range is refused here even
    // though every delivered section still hashes to its recorded digest.
    check_event_coverage(&manifest.export_fence, &sections)?;

    // Every recorded blob member. The expected set is derived from the
    // residency entries the manifest recorded, so a member dropped from the
    // package is detected against a set the importer never chose.
    let mut recorded_reachability: BTreeSet<String> = BTreeSet::new();
    let mut blobs = Vec::new();
    for residency in &manifest.blob_residency {
        if !recorded_reachability.insert(residency.residency_key_digest.clone()) {
            return Err(EcxfError::Duplicate {
                field: "blob_residency.residency_key_digest",
            });
        }
        let entry_path = blob_entry_path(
            &residency.residency_key_digest,
            &residency.content_digest.digest.to_string(),
        );
        let member = blob_member_name(&entry_path);
        let sealed_bytes = files
            .get(&member)
            .ok_or_else(|| EcxfError::Blob(format!("recorded blob member {member} is absent")))?
            .clone();
        let recorded_digest = manifest.checksums.get(&entry_path).ok_or_else(|| {
            EcxfError::Blob(format!("manifest does not record blob {entry_path}"))
        })?;
        if integrity.blob_sha256.get(&entry_path) != Some(recorded_digest) {
            return Err(EcxfError::DigestMismatch {
                subject: format!("integrity blob {entry_path}"),
            });
        }
        if sha256_hex(&sealed_bytes) != *recorded_digest {
            return Err(EcxfError::DigestMismatch { subject: member });
        }
        blobs.push(ImportedBlob {
            entry_path,
            sealed_bytes,
            sealed_sha256: recorded_digest.clone(),
            residency: residency.clone(),
        });
    }
    // The export fence's reachability set and the manifest's projected
    // residency set are recorded by different steps of the export; a
    // disagreement means one of them lost a reachable blob. This is a
    // coherence check between two recorded sets, not the completeness check
    // above, which compares a recorded set against the actual member bytes.
    if recorded_reachability
        != manifest
            .export_fence
            .blob_reachability_manifest
            .iter()
            .cloned()
            .collect()
    {
        return Err(EcxfError::InconsistentBoundary);
    }

    // Completeness in both directions. The expected member set is built from
    // the recorded artifacts above; the actual set is the package. An extra
    // member is refused rather than ignored, so nothing rides into a restore
    // that the export did not record.
    let mut expected = BTreeSet::new();
    expected.insert(MANIFEST_FILE.to_owned());
    expected.insert(INTEGRITY_FILE.to_owned());
    expected.insert(PURGE_LEDGER_FILE.to_owned());
    expected.insert(SCHEMA_FILE.to_owned());
    for wire_name in integrity.section_sha256.keys() {
        expected.insert(section_member_name(wire_name, codec.suffix()));
    }
    for blob in &blobs {
        expected.insert(blob_member_name(&blob.entry_path));
    }
    if files.keys().any(|name| !expected.contains(name)) {
        // The offending member name is a dynamic package path and
        // `EcxfError::InvalidField` carries a static field, so the class of the
        // refusal is named here and the caller identifies the member from its
        // own member set. The refusal itself is unconditional: an unrecorded
        // member never rides into a restore unnoticed.
        return Err(EcxfError::InvalidField {
            field: "package_members",
            reason: "package carries a member no recorded artifact names",
        });
    }

    Ok(EcxfImport {
        manifest,
        integrity,
        sections,
        blobs,
        privacy_purge_ledger,
    })
}
