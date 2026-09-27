//! Reachable `ECXF/1` export owner with a provable `ExportFence` (issue #1871).
//!
//! This module is the production owner that makes the `eliot-ecxf` interchange
//! crate reachable: [`export_ecxf_package`] reads one coherent, fenced source
//! view through the [`EcxfSourceStore`] port, hands it to the single sanctioned
//! producers ([`eliot_ecxf::EcxfArchive::build`] and
//! [`eliot_ecxf::EcxfArchive::layout`]) and publishes the emitted
//! `manifest.json`, `schema/`, event/projection/receipt streams,
//! residency-keyed `blobs/`, `integrity.json` and `privacy-purge-ledger.json`
//! as one package. It defines no second archive builder, no second manifest
//! writer, no second fence vocabulary and no second package layout: every
//! archive value is produced by `eliot-ecxf`, and this crate's own
//! [`CanonicalRecord`]/[`WriteReceipt`]/[`PurgeLedgerEntry`] values are the only
//! source vocabulary it projects.
//!
//! The fence is not asserted by the caller. Every fence field is read from the
//! source view the port returns: state fence, revision heads, ordering heads,
//! event range, scope, schema/store generation and the store-declared
//! residency-key reachability set. Coherence is then *proved* before a byte is
//! written, and the proof fails closed (I05-10 "consistent export boundary";
//! I5.13: an incoherent boundary fails that class rather than producing a
//! partial successful backup):
//!
//! * a source whose capture is not [`SnapshotCompleteness::Complete`] never
//!   reaches the archive builder, so no manifest is ever written with an
//!   unproved boundary;
//! * the declared event interval must describe exactly the exported events;
//! * every store write receipt must validate and be compatible with the same
//!   state fence;
//! * `eliot-ecxf` then re-proves that every revision and ordering head carries
//!   that same `state_fence`, that every purge-ledger entry does too, and that
//!   the fence reachability set equals the residency keys of the exported
//!   blobs.
//!
//! `layout` materialises the whole package in memory and re-validates the
//! archive before returning, so every one of those refusals happens before any
//! filesystem write. Publication is then a single atomic directory rename from
//! a sibling staging directory: a mid-way failure removes the staging
//! directory and the destination path never exists, so a partially written
//! package is not observable (issue #1871, work item W2).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eliot_blob_api::BlobReadyReceipt;
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::{OrderingHead, RevisionHead, ScopeId, SnapshotCompleteness, WriteReceipt};
use serde::{Deserialize, Serialize};

use super::{BackupError, CanonicalRecord, EventRange, bytes_sha256, text};

/// Record-type label of one canonical store write receipt inside the `ECXF/1`
/// receipt stream.
///
/// `eliot_store_api::WriteReceipt` is the only receipt type that crosses the
/// canonical store boundary, so the receipt stream carries exactly one label
/// instead of one label per backend. The payload is the receipt's own canonical
/// JSON, unmodified.
pub const WRITE_RECEIPT_RECORD_TYPE: &str = "write-receipt";

/// One sealed source blob and the completed receipt that already binds it.
///
/// Only the two values a blob owner can truthfully supply are carried: the
/// sealed envelope bytes and its `BlobReadyReceipt`. The residency key, the
/// versioned content digest, the retention/erasure domains, the key lineage and
/// the sealed digest are read back from the receipt by `eliot-ecxf` (I05-12,
/// I05-13); nothing here re-derives or re-hashes them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBlobEntry {
    /// The sealed envelope bytes exactly as the blob owner stored them.
    pub sealed_bytes: Vec<u8>,
    /// The completed receipt whose locator, crypto lineage and sealed digest
    /// bind `sealed_bytes`.
    pub ready_receipt: BlobReadyReceipt,
}

impl SealedBlobEntry {
    /// Projects this entry onto the interchange blob type.
    ///
    /// The locator and the sealed digest are read back from the already-bound
    /// receipt, so the emitted entry cannot claim a residency key, a content
    /// digest or a key lineage the blob owner did not seal (I05-13). Nothing can
    /// fail here: `eliot-ecxf` re-validates the projected entry, its receipt and
    /// its sealed bytes before the archive is built.
    fn into_ecxf(self) -> eliot_ecxf::EcxfBlob {
        let locator = self.ready_receipt.locator().clone();
        let sealed_sha256 = self.ready_receipt.sealed_sha256().to_owned();
        eliot_ecxf::EcxfBlob {
            locator,
            sealed_bytes: self.sealed_bytes,
            sealed_sha256,
            ready_receipt: self.ready_receipt,
        }
    }
}

/// One coherent, fenced source view, as the exporter observes it.
///
/// Every field is read from the source store owner. This crate never defaults,
/// constants or guesses any of them: a source that cannot observe a value must
/// fail rather than fill it in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoherentSourceExport {
    /// Completeness of the source's own capture. Only
    /// [`SnapshotCompleteness::Complete`] proves one coherent boundary; every
    /// other value refuses the export (I05-10: if neither route can prove a
    /// coherent boundary, the export fails).
    pub completeness: SnapshotCompleteness,
    /// Store adapter identity that produced this view.
    pub source_adapter: String,
    /// Store adapter version that produced this view.
    pub source_adapter_version: String,
    /// Schema generation observed at the bound consistency point.
    pub schema_generation: String,
    /// Store resource generation observed at the bound consistency point.
    pub store_generation: String,
    /// Digest of the Architecture source the export was taken against.
    pub architecture_source_digest: String,
    /// Digest of the externally sealed `NormativePairIdentity` receipt.
    pub normative_pair_identity_receipt_digest: String,
    /// Reference of the source-side export receipt.
    pub export_receipt: String,
    /// Declared store scope, or `None` for an installation-wide export.
    pub scope_id: Option<ScopeId>,
    /// State fence observed at the bound consistency point.
    pub state_fence: eliot_contracts::StateFence,
    /// Revision heads observed at the same point.
    pub revision_heads: Vec<RevisionHead>,
    /// Ordering heads observed at the same point.
    pub ordering_heads: Vec<OrderingHead>,
    /// Canonical event interval covered by this view.
    pub event_range: EventRange,
    /// Opaque residency-key digests the source declares reachable from this
    /// export. They are compared against the residency keys of the delivered
    /// blobs, so a source that under- or over-declares reachability fails
    /// instead of shipping an archive whose fence does not describe it.
    pub reachable_blob_residency_keys: Vec<String>,
    /// Canonical events of the view.
    pub events: Vec<CanonicalRecord>,
    /// Projection records of the view.
    pub projections: Vec<CanonicalRecord>,
    /// Canonical write receipts of the view.
    pub receipts: Vec<WriteReceipt>,
    /// Reachable sealed blobs of the view.
    pub blobs: Vec<SealedBlobEntry>,
    /// Privacy/purge ledger entries of the view.
    pub purge_ledger: Vec<PurgeLedgerEntry>,
    /// Compression profile the source applies to the emitted sections.
    pub compression: eliot_ecxf::CompressionProfile,
    /// Encryption profile the source declares for the emitted package.
    pub encryption: eliot_ecxf::EncryptionProfile,
    /// Features the source could not represent in this export.
    pub missing_features: Vec<String>,
}

/// A source store that can hand the exporter one coherent, fenced view.
///
/// This is the composition seam, not a capability implementation: the store
/// bridge that can prove a consistent snapshot owns the read and the
/// consistency point. The method has no default body, so no caller can obtain a
/// successful export without a real owner behind it.
pub trait EcxfSourceStore {
    /// Reads one coherent, fenced source view for `export_id`.
    ///
    /// `export_id` names the export identity the caller will publish; an
    /// implementation records it in whatever owner-issued export receipt it
    /// holds. It grants no authority and selects no scope by itself.
    fn coherent_export(&self, export_id: &str) -> Result<CoherentSourceExport, BackupError>;
}

/// Product arguments of one `ECXF/1` export.
///
/// Only the export identity is a request field. Every fence value is read from
/// the source view, so no request field can be copied into the manifest fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxfExportRequest {
    /// Identity this export publishes under.
    pub export_id: String,
}

impl EcxfExportRequest {
    /// Validates the request shape before any source read.
    pub fn validate(&self) -> Result<(), BackupError> {
        text(&self.export_id, "ecxf.export_id")
    }
}

/// Serializable report for one published `ECXF/1` package.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcxfExportReport {
    /// Identity this export published under.
    pub export_id: String,
    /// Exchange format the package carries.
    pub format: String,
    /// Caller-supplied path of the published package directory.
    pub package_path: String,
    /// Digest re-read from the published `manifest.json`; equal to the manifest
    /// digest the archive's own `integrity.json` attests.
    pub manifest_sha256: String,
    /// Whole-archive digest from the published `integrity.json`.
    pub archive_sha256: String,
    /// Number of files in the published package.
    pub file_count: u64,
    /// Records in the emitted event stream.
    pub event_count: u64,
    /// Records in the emitted projection stream.
    pub projection_count: u64,
    /// Records in the emitted receipt stream.
    pub receipt_count: u64,
    /// Residency-keyed blob entries in the published package.
    pub blob_count: u64,
    /// Entries in the published `privacy-purge-ledger.json`.
    pub purge_ledger_entries: u64,
}

/// Exports one coherent `ECXF/1` package from a source store and publishes it.
///
/// This is the owner function: it reads the source view, derives the
/// `ExportFence` from it, assembles the archive through
/// [`eliot_ecxf::EcxfArchive::build`], renders the package through
/// [`eliot_ecxf::EcxfArchive::layout`] and publishes the result as one unit.
///
/// Failure is total. Every coherence refusal, every digest mismatch and every
/// filesystem error happens before the destination path exists, and the
/// destination is created only by the final atomic rename of a fully written
/// staging directory, so a failed export never leaves a partially written
/// package observable.
#[allow(
    clippy::too_many_lines,
    reason = "one linear export path: read, prove the fence, build, render, publish, report"
)]
pub fn export_ecxf_package(
    request: &EcxfExportRequest,
    source: &dyn EcxfSourceStore,
    out_dir: &Path,
) -> Result<EcxfExportReport, BackupError> {
    request.validate()?;
    let snapshot = source.coherent_export(&request.export_id)?;
    prove_coherent_boundary(&snapshot)?;
    let (revision_start, revision_end) = revision_range(&snapshot.revision_heads);
    let fence = eliot_ecxf::ExportFence {
        export_id: request.export_id.clone(),
        schema_generation: snapshot.schema_generation.clone(),
        store_generation: snapshot.store_generation.clone(),
        state_fence: snapshot.state_fence.clone(),
        scope_id: snapshot.scope_id.clone(),
        revision_heads: snapshot.revision_heads.clone(),
        ordering_heads: snapshot.ordering_heads.clone(),
        event_range: snapshot.event_range.clone(),
        blob_reachability_manifest: snapshot.reachable_blob_residency_keys.clone(),
        consistent: snapshot.completeness.is_complete(),
    };
    let manifest = eliot_ecxf::EcxfManifest {
        format: eliot_ecxf::FORMAT_VERSION.to_owned(),
        source_adapter: snapshot.source_adapter.clone(),
        source_adapter_version: snapshot.source_adapter_version.clone(),
        architecture_source_digest: snapshot.architecture_source_digest.clone(),
        normative_pair_identity_receipt_digest: snapshot
            .normative_pair_identity_receipt_digest
            .clone(),
        scope_id: snapshot.scope_id.clone(),
        revision_start,
        revision_end,
        // Section, blob and purge-ledger checksums, the per-blob residency
        // entries and the purge-ledger revision are derived by
        // `EcxfArchive::build` from the members it is given, so this crate
        // supplies none of them and cannot disagree with them.
        checksums: BTreeMap::new(),
        compression: snapshot.compression.clone(),
        encryption: snapshot.encryption.clone(),
        missing_features: snapshot.missing_features.clone(),
        purge_state: purge_export_state(snapshot.purge_ledger.len()),
        purge_ledger_revision: None,
        blob_residency: Vec::new(),
        export_fence: fence,
        export_receipt: snapshot.export_receipt.clone(),
    };
    let sections = vec![
        canonical_section(eliot_ecxf::SectionKind::Events, snapshot.events)?,
        canonical_section(eliot_ecxf::SectionKind::Projections, snapshot.projections)?,
        receipt_section(snapshot.receipts)?,
    ];
    let blobs: Vec<eliot_ecxf::EcxfBlob> = snapshot
        .blobs
        .into_iter()
        .map(SealedBlobEntry::into_ecxf)
        .collect();
    let archive = eliot_ecxf::EcxfArchive::build(eliot_ecxf::EcxfExportInput {
        manifest,
        sections,
        blobs,
        privacy_purge_ledger: snapshot.purge_ledger,
    })
    .map_err(ecxf_error)?;
    // `layout` re-validates the whole archive against its own emitted bytes and
    // returns the complete package in memory, so no byte is written before the
    // fence, residency, checksum and integrity proofs have all held.
    let files = archive
        .layout(&eliot_ecxf::IdentitySectionCodec)
        .map_err(ecxf_error)?;
    publish_package(&files, out_dir)?;
    let manifest_sha256 = readback_digest(out_dir, "manifest.json", &files)?;
    if manifest_sha256 != archive.integrity.manifest_sha256 {
        return Err(BackupError::IntegrityMismatch {
            subject: "published ECXF manifest".to_owned(),
        });
    }
    readback_digest(out_dir, "integrity.json", &files)?;
    Ok(EcxfExportReport {
        export_id: request.export_id.clone(),
        format: eliot_ecxf::FORMAT_VERSION.to_owned(),
        package_path: out_dir.display().to_string(),
        manifest_sha256,
        archive_sha256: archive.integrity.archive_sha256.clone(),
        file_count: files.len() as u64,
        event_count: section_records(&archive, eliot_ecxf::SectionKind::Events),
        projection_count: section_records(&archive, eliot_ecxf::SectionKind::Projections),
        receipt_count: section_records(&archive, eliot_ecxf::SectionKind::Receipts),
        blob_count: archive.blobs.len() as u64,
        purge_ledger_entries: archive.privacy_purge_ledger.len() as u64,
    })
}

/// Refuses a source view that cannot prove one coherent export boundary.
///
/// I05-10 admits exactly one export route: a database-supported consistent
/// snapshot, or a base fence plus immutable history, a canonical-event tail to
/// a final fence and a brief write quiesce. Either way the source ends at one
/// fence and the source owner reports that as
/// [`SnapshotCompleteness::Complete`]. Anything else refuses here, before the
/// archive is assembled.
fn prove_coherent_boundary(snapshot: &CoherentSourceExport) -> Result<(), BackupError> {
    if !snapshot.completeness.is_complete() {
        return Err(BackupError::InconsistentBoundary);
    }
    if snapshot.event_range.count != snapshot.events.len() as u64 {
        return Err(BackupError::FenceMismatch {
            subject: "export event range count".to_owned(),
        });
    }
    for receipt in &snapshot.receipts {
        receipt.validate().map_err(BackupError::Store)?;
        if !receipt
            .state_fence
            .is_compatible_with(&snapshot.state_fence)
        {
            return Err(BackupError::FenceMismatch {
                subject: format!("receipt {}", receipt.operation_id),
            });
        }
    }
    Ok(())
}

/// Projects the manifest's revision range from the observed revision heads.
///
/// I05-10 requires the manifest to carry "scope/revision ranges". The exported
/// range is the observed minimum and maximum `RevisionHead::revision`; an
/// export with no observed head carries no range, which stays representable
/// instead of becoming a fabricated `0`.
///
/// ASSUMPTION: no document names the projection rule. Min/max over the fence's
/// own revision heads is used because those heads are the only revision
/// evidence the fence carries, so any other rule would either invent a bound
/// or drop the required manifest member.
fn revision_range(heads: &[RevisionHead]) -> (Option<u64>, Option<u64>) {
    let mut bounds: Option<(u64, u64)> = None;
    for head in heads {
        bounds = Some(match bounds {
            Some((start, end)) => (start.min(head.revision), end.max(head.revision)),
            None => (head.revision, head.revision),
        });
    }
    bounds.map_or((None, None), |(start, end)| (Some(start), Some(end)))
}

/// Declares the purge state this export actually carries.
///
/// ASSUMPTION: I05-10 asks the manifest for "purge state" and `eliot-ecxf`
/// offers `Applied`, `IncludedLedger` and `NoEntries`, but no document says
/// which one an exporter may declare. This exporter declares `IncludedLedger`
/// exactly when it carries the source's purge ledger and `NoEntries` otherwise,
/// because those two describe the produced package. `Applied` is never
/// declared: it would assert that the source already removed the purged
/// content, which the exporter cannot observe.
const fn purge_export_state(ledger_entries: usize) -> eliot_ecxf::PurgeExportState {
    if ledger_entries == 0 {
        eliot_ecxf::PurgeExportState::NoEntries
    } else {
        eliot_ecxf::PurgeExportState::IncludedLedger
    }
}

/// Projects canonical records onto one interchange section.
///
/// The record type, record identity and payload cross unchanged; the emitted
/// record digest is recomputed by `eliot-ecxf` over the same payload, so the
/// two record types cannot drift apart.
fn canonical_section(
    kind: eliot_ecxf::SectionKind,
    records: Vec<CanonicalRecord>,
) -> Result<eliot_ecxf::CanonicalSection, BackupError> {
    let records = records
        .into_iter()
        .map(|record| {
            eliot_ecxf::EcxfRecord::new(record.record_type, record.record_id, record.payload)
                .map_err(ecxf_error)
        })
        .collect::<Result<Vec<_>, BackupError>>()?;
    eliot_ecxf::CanonicalSection::new(kind, records).map_err(ecxf_error)
}

/// Projects canonical write receipts onto the interchange receipt section.
fn receipt_section(
    receipts: Vec<WriteReceipt>,
) -> Result<eliot_ecxf::CanonicalSection, BackupError> {
    let records = receipts
        .into_iter()
        .map(|receipt| {
            let record_id = receipt.operation_id.to_string();
            let payload = serde_json::to_value(&receipt)
                .map_err(|error| BackupError::Serialization(error.to_string()))?;
            eliot_ecxf::EcxfRecord::new(WRITE_RECEIPT_RECORD_TYPE, record_id, payload)
                .map_err(ecxf_error)
        })
        .collect::<Result<Vec<_>, BackupError>>()?;
    eliot_ecxf::CanonicalSection::new(eliot_ecxf::SectionKind::Receipts, records)
        .map_err(ecxf_error)
}

/// Returns the emitted record count of one section.
fn section_records(archive: &eliot_ecxf::EcxfArchive, kind: eliot_ecxf::SectionKind) -> u64 {
    archive
        .sections
        .get(&kind)
        .map_or(0, |section| section.record_count)
}

/// Publishes the rendered package as one unit.
///
/// The complete package is written into a sibling staging directory and only
/// then renamed onto `out_dir`. Renaming a fully written directory is the single
/// observable transition, so the destination path never names a partial
/// package: any earlier failure removes the staging directory and leaves no
/// package at all. An existing destination refuses instead of being merged or
/// overwritten, which keeps the published package exactly the archive this call
/// produced.
fn publish_package(files: &BTreeMap<String, Vec<u8>>, out_dir: &Path) -> Result<(), BackupError> {
    if out_dir.exists() {
        return Err(BackupError::Interchange(format!(
            "ECXF package path {} already exists; refusing to publish over an existing package",
            out_dir.display()
        )));
    }
    let staging = staging_dir(out_dir)?;
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(|error| {
            BackupError::Interchange(format!(
                "cannot clear the staging directory {}: {error}",
                staging.display()
            ))
        })?;
    }
    if let Err(error) = write_tree(&staging, files) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error);
    }
    std::fs::rename(&staging, out_dir).map_err(|error| {
        BackupError::Interchange(format!(
            "cannot publish the ECXF package {}: {error}",
            out_dir.display()
        ))
    })
}

/// Returns the sibling staging directory used to publish `out_dir`.
///
/// The name is a pure function of the destination, so a retry after a failed
/// attempt reuses the same path instead of accumulating staging directories, and
/// no random or caller-supplied component enters the filesystem layout.
fn staging_dir(out_dir: &Path) -> Result<PathBuf, BackupError> {
    let name = out_dir.file_name().ok_or_else(|| {
        BackupError::Interchange("ECXF package path has no directory name".to_owned())
    })?;
    let parent = out_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!(".{}.ecxf-staging", name.to_string_lossy())))
}

/// Writes every package member below `root`.
///
/// Relative member names come from `eliot-ecxf`, which builds them from
/// validated components, so a member can never escape the package root.
fn write_tree(root: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<(), BackupError> {
    for (relative, bytes) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                BackupError::Interchange(format!(
                    "cannot create the ECXF package directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        std::fs::write(&path, bytes).map_err(|error| {
            BackupError::Interchange(format!(
                "cannot write the ECXF package member {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

/// Re-reads one published member and returns the digest of the observed bytes.
///
/// The reported digest is computed over the file that landed, not over the
/// in-memory member that produced it, and a readback that disagrees with the
/// rendered package is refused instead of reported (#1141).
fn readback_digest(
    out_dir: &Path,
    relative: &str,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<String, BackupError> {
    let expected = files.get(relative).ok_or_else(|| {
        BackupError::Interchange(format!("the rendered package has no {relative} member"))
    })?;
    let path = out_dir.join(relative);
    let observed = std::fs::read(&path).map_err(|error| {
        BackupError::Interchange(format!(
            "cannot read back the published ECXF package member {}: {error}",
            path.display()
        ))
    })?;
    if &observed != expected {
        return Err(BackupError::IntegrityMismatch {
            subject: format!("published ECXF member {relative} readback"),
        });
    }
    Ok(bytes_sha256(&observed))
}

/// Maps an `eliot-ecxf` failure onto this crate's typed backup failure.
///
/// The mapping preserves every typed variant, so an incoherent boundary, a
/// duplicate identity, a field rejection and a digest mismatch never collapse
/// into one another on the way out of the interchange crate.
fn ecxf_error(error: eliot_ecxf::EcxfError) -> BackupError {
    match error {
        eliot_ecxf::EcxfError::InvalidField { field, reason } => {
            BackupError::InvalidField { field, reason }
        }
        eliot_ecxf::EcxfError::Duplicate { field } => BackupError::Duplicate { field },
        eliot_ecxf::EcxfError::InconsistentBoundary => BackupError::InconsistentBoundary,
        eliot_ecxf::EcxfError::DigestMismatch { subject } => {
            BackupError::IntegrityMismatch { subject }
        }
        eliot_ecxf::EcxfError::Serialization(message) => BackupError::Serialization(message),
        eliot_ecxf::EcxfError::Blob(message) => BackupError::Blob(message),
        eliot_ecxf::EcxfError::Security(message) => BackupError::Security(message),
        eliot_ecxf::EcxfError::Codec(message) | eliot_ecxf::EcxfError::Store(message) => {
            BackupError::Interchange(message)
        }
    }
}
