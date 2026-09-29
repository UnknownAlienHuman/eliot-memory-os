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
//! source view the port returns: the installation identity the owner observed,
//! state fence, revision heads, ordering heads, event range, scope, schema/store
//! generation and the store-declared residency-key reachability set. Coherence
//! is then *proved* before a byte is written, and the proof fails closed
//! (I05-10 "consistent export boundary"; I5.13: an incoherent boundary fails
//! that class rather than producing a partial successful backup):
//!
//! * a source whose capture is not [`SnapshotCompleteness::Complete`] never
//!   reaches the archive builder, so no manifest is ever written with an
//!   unproved boundary;
//! * the declared event interval must describe exactly the exported events;
//! * every store write receipt must validate and be compatible with the same
//!   state fence;
//! * every source event and projection record validates its own recorded
//!   checksum against its payload before it is destructured, so a source whose
//!   retained checksum does not describe its payload is refused instead of
//!   being re-digested into an internally consistent package that no longer
//!   preserves the source's integrity claim;
//! * `eliot-ecxf` then re-proves that every revision and ordering head carries
//!   that same `state_fence`, that every purge-ledger entry does too, and that
//!   the fence reachability set equals the residency keys of the exported
//!   blobs.
//!
//! `layout` materialises the whole package in memory and re-validates the
//! archive before returning, so every one of those refusals happens before any
//! filesystem write. Publication then claims a sibling staging area
//! exclusively — an exclusive create plus an owner record naming this export
//! identity and this attempt incarnation — writes the rendered package inside
//! the claim, and renames the claimed package root onto the destination. The
//! claim, not the directory name, is the ownership boundary: an occupied or
//! concurrently claimed path is refused and left untouched, and cleanup removes
//! only the tree whose owner record still names this invocation (issue #1871,
//! work item W2).
//!
//! The destination comes into existence at that rename, which precedes the
//! manifest/integrity readback, so publication is not all-or-nothing. A
//! readback failure after the rename is reported as the typed
//! [`BackupError::PublishReconciliationRequired`] outcome carrying the export
//! identity and the published package path, never as proof that nothing was
//! published.
//!
//! This module is a port, not a reachable edge. [`EcxfSourceStore`] has no
//! implementor in the workspace and [`export_ecxf_package`] has no caller, so
//! no process currently produces an `ECXF/1` package. Nothing here stands in
//! for that edge: a source that returns nothing would make an export look real.
//! I5.1 puts the coherent read behind the store bridge, and this crate depends
//! on the neutral store contracts only, so the implementor belongs on the
//! bridge that already owns the admitted coherent-capture port
//! (`CanonicalSnapshotPort for SurrealStoreAdapter`,
//! `crates/storage/eliot-store-surreal-adapter/src/lib.rs`) and the composition
//! call site to the process that owns the export request. Two facts bound that
//! implementor: the neutral `SnapshotSourceIdentity::installation_id` is a
//! request field and the neutral snapshot receipts echo no installation
//! identity, so the source view's `installation_id` must come from the bridge's
//! own durable state; and the comparison the bridge does perform today,
//! `check_active_source_identity` in
//! `crates/storage/eliot-store-surreal-adapter/src/backup_snapshot.rs`, refuses
//! a foreign source against `active_store_identity`, which is derived from
//! `SurrealAdapterConfig::installation_id` — a name the adapter was configured
//! with, not an observation of the installation that owns the data.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eliot_blob_api::BlobReadyReceipt;
use eliot_security_contracts::PurgeLedgerEntry;
pub use eliot_store_api::{EcxfExportReport, EcxfExportRequest};
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
    /// Installation identity the source owner observed at the bound
    /// consistency point.
    ///
    /// This is the owner's own durable state, read through the port at export
    /// time. A caller string, a configuration value or a request field is not
    /// an installation identity — a predictable name is not ownership — so a
    /// source that cannot observe this value leaves it blank and is refused by
    /// `prove_coherent_boundary` before the archive is assembled, instead of
    /// filling it in. An export that cannot be attributed to one installation
    /// produces a package nobody can hold responsible for it.
    ///
    /// BLOCKED-BY `crates/storage/eliot-ecxf/src/lib.rs`: neither
    /// `eliot_ecxf::ExportFence` nor `eliot_ecxf::EcxfManifest` (distinct from
    /// this crate's own `eliot_backup::EcxfManifest`, which the backup bundle
    /// carries) has an installation identity member, so the value bound here
    /// cannot yet be carried into the emitted `manifest.json`. The binding is
    /// proved at the port and reaches the package when that struct gains the
    /// member; it is never derived from the exporter, a config value or the
    /// request.
    pub installation_id: String,
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
#[allow(async_fn_in_trait)]
pub trait EcxfSourceStore: Send + Sync {
    /// Reads one coherent, fenced source view for the authenticated operation
    /// and its required scope. Implementations obtain every fence value from
    /// the source owner; request fields do not become source evidence.
    async fn coherent_export(
        &self,
        request: &EcxfExportRequest,
    ) -> Result<CoherentSourceExport, BackupError>;
}

/// Exports one coherent `ECXF/1` package from a source store and publishes it.
///
/// This is the owner function: it reads the source view, derives the
/// `ExportFence` from it, assembles the archive through
/// [`eliot_ecxf::EcxfArchive::build`], renders the package through
/// [`eliot_ecxf::EcxfArchive::layout`] and publishes the result as one unit.
///
/// Every coherence refusal, every source checksum mismatch and every staging
/// ownership refusal happens before the destination path exists, and the
/// destination is created only by the final atomic rename of a fully written,
/// exclusively claimed staging tree, so a failed export never leaves a
/// partially written package observable.
///
/// Publication is not total-failure-only. The manifest and integrity readback
/// runs after that rename, so a failure there is reported as the typed
/// [`BackupError::PublishReconciliationRequired`] outcome, which carries this
/// export identity and the published package path. The caller therefore always
/// learns whether a package exists; an error is never read as proof that
/// nothing was published.
#[allow(
    clippy::too_many_lines,
    reason = "one linear export path: read, prove the fence, build, render, publish, report"
)]
pub async fn export_ecxf_package<S: EcxfSourceStore + ?Sized>(
    request: &EcxfExportRequest,
    source: &S,
    out_dir: &Path,
) -> Result<EcxfExportReport, BackupError> {
    request.validate().map_err(BackupError::Store)?;
    let export_id = request.identity.operation_id.to_string();
    let snapshot = source.coherent_export(request).await?;
    prove_coherent_boundary(&snapshot, request)?;
    let (revision_start, revision_end) = revision_range(&snapshot.revision_heads);
    let fence = eliot_ecxf::ExportFence {
        export_id: export_id.clone(),
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
    publish_package(&files, out_dir, &export_id)?;
    // The rename has already made the destination exist, so every refusal from
    // here on is a publication/reconciliation outcome carrying the published
    // identity and path, never a claim that nothing was written.
    let manifest_sha256 = readback_digest(out_dir, "manifest.json", &files, &export_id)?;
    if manifest_sha256 != archive.integrity.manifest_sha256 {
        return Err(BackupError::PublishReconciliationRequired {
            export_id: export_id.clone(),
            package_path: out_dir.display().to_string(),
            reason:
                "the published manifest digest disagrees with the archive integrity attestation"
                    .to_owned(),
        });
    }
    readback_digest(out_dir, "integrity.json", &files, &export_id)?;
    let report = EcxfExportReport {
        export_id,
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
    };
    report
        .validate()
        .map_err(|error| BackupError::PublishReconciliationRequired {
            export_id: report.export_id.clone(),
            package_path: report.package_path.clone(),
            reason: error.to_string(),
        })?;
    Ok(report)
}

/// Refuses a source view that cannot prove one coherent export boundary.
///
/// I05-10 admits exactly one export route: a database-supported consistent
/// snapshot, or a base fence plus immutable history, a canonical-event tail to
/// a final fence and a brief write quiesce. Either way the source ends at one
/// fence and the source owner reports that as
/// [`SnapshotCompleteness::Complete`]. Anything else refuses here, before the
/// archive is assembled.
///
/// The source must also have observed its own installation identity at that
/// point. It is the one fence input the exporter cannot derive from anything it
/// already holds, so it is required rather than defaulted: a source view that
/// leaves it blank is refused here rather than exported under a name the
/// exporter chose.
fn prove_coherent_boundary(
    snapshot: &CoherentSourceExport,
    request: &EcxfExportRequest,
) -> Result<(), BackupError> {
    if !snapshot.completeness.is_complete() {
        return Err(BackupError::InconsistentBoundary);
    }
    text(&snapshot.installation_id, "ecxf.installation_id")?;
    if snapshot.scope_id.as_ref() != Some(&request.scope_id) {
        return Err(BackupError::FenceMismatch {
            subject: "export scope".to_owned(),
        });
    }
    if snapshot.state_fence != request.context.state_fence {
        return Err(BackupError::FenceMismatch {
            subject: "authenticated request state fence".to_owned(),
        });
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
///
/// The source's own recorded checksum is validated first, against the source's
/// own payload, by the existing [`CanonicalRecord::validate`]. Recomputing a
/// digest over the payload is not a substitute for that: a source record whose
/// payload was replaced while its checksum was retained would otherwise leave
/// this function with a freshly valid digest and an export that is internally
/// consistent while no longer carrying the source's integrity claim. The
/// refusal happens here, before any filesystem work, and the record type, id
/// and payload are projected only after the source claim is proven.
fn canonical_section(
    kind: eliot_ecxf::SectionKind,
    records: Vec<CanonicalRecord>,
) -> Result<eliot_ecxf::CanonicalSection, BackupError> {
    let records = records
        .into_iter()
        .map(|record| {
            record.validate()?;
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
/// The complete package is written into a staging area this call claimed
/// exclusively, and only the package root inside that claim is renamed onto
/// `out_dir`. Renaming a fully written directory is the single observable
/// transition, so the destination path never names a partial package.
///
/// Ownership of the staging area is the exclusive create plus the owner record
/// [`StagingClaim::acquire`] writes into it, bound to this export identity and
/// this attempt incarnation. An occupied path is refused and left untouched —
/// never erased because its name matches — and cleanup removes only a tree
/// whose owner record still names this invocation, so a concurrent or
/// unrelated staging tree can neither be deleted nor overwritten. An existing
/// destination refuses instead of being merged or overwritten, which keeps the
/// published package exactly the archive this call produced.
///
/// From the rename onwards the package exists on disk, so a claim that cannot
/// be retired is reported as [`BackupError::PublishReconciliationRequired`]:
/// the publication happened, the caller's reconciliation is outstanding, and
/// the error is not a claim that nothing was published.
fn publish_package(
    files: &BTreeMap<String, Vec<u8>>,
    out_dir: &Path,
    export_id: &str,
) -> Result<(), BackupError> {
    if out_dir.exists() {
        return Err(BackupError::Interchange(format!(
            "ECXF package path {} already exists; refusing to publish over an existing package",
            out_dir.display()
        )));
    }
    let claim = StagingClaim::acquire(out_dir, export_id)?;
    if let Err(error) = write_tree(&claim.package_root(), files) {
        return Err(keep_cleanup_failure(error, claim.release()));
    }
    // Only the package root is renamed. The claim directory keeps the owner
    // record, so the published members are exactly the ones `eliot-ecxf`
    // rendered — no claim member is ever shipped — while cleanup still has a
    // record to re-verify before it removes anything.
    if let Err(error) = std::fs::rename(claim.package_root(), out_dir) {
        let publish_error = BackupError::Interchange(format!(
            "cannot publish the ECXF package {}: {error}",
            out_dir.display()
        ));
        return Err(keep_cleanup_failure(publish_error, claim.release()));
    }
    claim
        .release()
        .map_err(|error| BackupError::PublishReconciliationRequired {
            export_id: export_id.to_owned(),
            package_path: out_dir.display().to_string(),
            reason: error.to_string(),
        })
}

/// Name of the directory inside a claimed staging area that holds the rendered
/// package members. It is the rename source, so the claim directory itself is
/// never published.
const STAGING_PACKAGE_DIR: &str = "package";

/// Name of the owner record inside a claimed staging area. The name is outside
/// the published layout because the record lives in the claim directory, not in
/// the package root that gets renamed.
const STAGING_OWNER_FILE: &str = ".ecxf-staging-owner.json";

/// Owner record written into a claimed staging area.
///
/// The record is the proof that the directory belongs to one export operation
/// and one attempt incarnation of it. A record that is absent, unreadable, or
/// naming a different owner is never treated as ownership by anyone (issue
/// #1871).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingOwnerRecord {
    /// Export identity that claimed the staging area.
    export_id: String,
    /// Attempt incarnation of that export which claimed it.
    attempt: String,
}

/// One staging area claimed exclusively by a single export attempt.
///
/// A deterministic directory name is not ownership: two exports to the same
/// destination would share it, and a pre-existing unrelated directory of the
/// same name would be indistinguishable from a retry. This claim therefore
/// combines an exclusive create (the crate's existing ownership boundary, as in
/// [`isolated_restore`](super::isolated_restore)) with an owner record naming
/// this export identity and a fresh attempt incarnation, and it re-reads that
/// record before removing anything.
#[derive(Debug)]
struct StagingClaim {
    /// Claimed directory, created exclusively by this invocation.
    root: PathBuf,
    /// Export identity recorded in the owner record.
    export_id: String,
    /// Attempt incarnation recorded in the owner record.
    attempt: String,
}

impl StagingClaim {
    /// Claims the sibling staging area of `out_dir` for this export attempt.
    ///
    /// `std::fs::create_dir` is the ownership boundary: it fails when the path
    /// already exists, so an occupied staging path is neither adopted nor
    /// erased, whatever its name or contents say. The refusal names the
    /// occupied path so the owner can reconcile it. This includes a path left
    /// behind by an earlier attempt: a deterministic name is not evidence that
    /// its previous owner is gone, so a leftover claim is refused rather than
    /// reclaimed.
    fn acquire(out_dir: &Path, export_id: &str) -> Result<Self, BackupError> {
        let claim = Self {
            root: staging_dir(out_dir)?,
            export_id: export_id.to_owned(),
            attempt: fresh_attempt_incarnation()?,
        };
        std::fs::create_dir(&claim.root).map_err(|error| {
            BackupError::Interchange(format!(
                "cannot claim the ECXF staging directory {}: {error}; the existing path is left untouched",
                claim.root.display()
            ))
        })?;
        let record = StagingOwnerRecord {
            export_id: claim.export_id.clone(),
            attempt: claim.attempt.clone(),
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        // A claim that cannot record its owner is not a claim this invocation
        // can later prove, so the directory stays in place and the error names
        // it rather than deleting an unproven tree.
        std::fs::write(claim.owner_record_path(), bytes).map_err(|error| {
            BackupError::Interchange(format!(
                "cannot record the ECXF staging owner in {}: {error}; the claimed directory is left untouched",
                claim.root.display()
            ))
        })?;
        Ok(claim)
    }

    /// Returns the directory inside the claim that receives the package members.
    fn package_root(&self) -> PathBuf {
        self.root.join(STAGING_PACKAGE_DIR)
    }

    /// Returns the path of this claim's owner record.
    fn owner_record_path(&self) -> PathBuf {
        self.root.join(STAGING_OWNER_FILE)
    }

    /// Removes the claimed tree, but only after re-proving this invocation owns it.
    ///
    /// The owner record is re-read from disk and compared against this claim's
    /// export identity and attempt incarnation. A record that cannot be read,
    /// or that names another owner, makes this a refusal instead of a deletion:
    /// cleanup may remove only the caller's own staging resources.
    fn release(&self) -> Result<(), BackupError> {
        let record_path = self.owner_record_path();
        let bytes = std::fs::read(&record_path).map_err(|error| {
            BackupError::Interchange(format!(
                "cannot read the ECXF staging owner record {}: {error}; the directory is left untouched",
                record_path.display()
            ))
        })?;
        let record: StagingOwnerRecord = serde_json::from_slice(&bytes).map_err(|error| {
            BackupError::Interchange(format!(
                "cannot parse the ECXF staging owner record {}: {error}; the directory is left untouched",
                record_path.display()
            ))
        })?;
        if record.export_id != self.export_id || record.attempt != self.attempt {
            return Err(BackupError::Interchange(format!(
                "ECXF staging directory {} is claimed by export {} attempt {}; refusing to remove a tree this attempt does not own",
                self.root.display(),
                record.export_id,
                record.attempt
            )));
        }
        std::fs::remove_dir_all(&self.root).map_err(|error| {
            BackupError::Interchange(format!(
                "cannot remove the owned ECXF staging directory {}: {error}",
                self.root.display()
            ))
        })
    }
}

/// Mints the fresh local attempt incarnation that identifies one export attempt.
///
/// The incarnation must never repeat across attempts, including attempts of the
/// same export identity by another process, because it is the second half of
/// the staging ownership proof. It is therefore derived from 128 bits of
/// process-local randomness rather than from the destination path, the export
/// identity, a counter or the clock, none of which distinguishes a new attempt
/// from a dead one that reused the same staging path.
fn fresh_attempt_incarnation() -> Result<String, BackupError> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|error| {
        BackupError::Interchange(format!(
            "cannot mint an ECXF export attempt incarnation: {error}"
        ))
    })?;
    Ok(bytes_sha256(&nonce))
}

/// Keeps a staging cleanup failure visible beside the primary failure it followed.
///
/// A cleanup failure is never discarded and never replaces the primary
/// outcome; it is reported next to it. Both primary failures on this path are
/// `Interchange` filesystem refusals from `write_tree` or the rename, so
/// folding the cleanup note into that variant keeps the primary's variant and
/// message intact and adds the cleanup failure to it.
fn keep_cleanup_failure(primary: BackupError, cleanup: Result<(), BackupError>) -> BackupError {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup_error) => BackupError::Interchange(format!("{primary}; {cleanup_error}")),
    }
}

/// Returns the sibling staging path this export claims for `out_dir`.
///
/// The name stays a pure function of the destination — no random or
/// caller-supplied component enters the filesystem layout — so two exports to
/// the same destination contend for exactly one path and the second is refused
/// rather than sharing it. The name is not ownership: ownership is the
/// exclusive create plus the owner record [`StagingClaim::acquire`] writes into
/// that path, so a path that merely carries the expected name is never
/// reclaimed or erased.
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

/// Re-reads one published member and reports this publication's outcome.
///
/// The readback runs after the destination exists, so its refusals are
/// publication/reconciliation outcomes rather than evidence that nothing was
/// published: every failure becomes [`BackupError::PublishReconciliationRequired`]
/// carrying the export identity and the published package path, with the exact
/// readback failure as the reason. The precise typed reason is preserved in that
/// message instead of being reported as a total failure.
fn readback_digest(
    out_dir: &Path,
    relative: &str,
    files: &BTreeMap<String, Vec<u8>>,
    export_id: &str,
) -> Result<String, BackupError> {
    observed_member_digest(out_dir, relative, files).map_err(|error| {
        BackupError::PublishReconciliationRequired {
            export_id: export_id.to_owned(),
            package_path: out_dir.display().to_string(),
            reason: error.to_string(),
        }
    })
}

/// Re-reads one published member and returns the digest of the observed bytes.
///
/// The reported digest is computed over the file that landed, not over the
/// in-memory member that produced it, and a readback that disagrees with the
/// rendered package is refused instead of reported (#1141).
fn observed_member_digest(
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
