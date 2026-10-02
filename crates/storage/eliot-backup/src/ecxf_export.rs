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
//! * the declared event interval must equal the store-issued `event_ordinal`
//!   interval observed on the source's own `CanonicalEvent` records, and every
//!   ordering position those events consumed must sit at or below the declared
//!   Ordering Heads — so the fence's event range and ordering heads are checked
//!   against the source Store's own rows rather than against the export's own
//!   record list, which would only compare a value with its own shadow;
//! * the observed revision and ordering heads are re-checked through the store
//!   port's own [`ScopeRevisionView::validate`], so a view assembled from two
//!   moments, or carrying a duplicate head key, is refused (issue #1141, A3
//!   mixed-revision);
//! * every store write receipt must validate, be compatible with the same
//!   state fence, and sit at or below the ordering and revision heads the owner
//!   declared for this view — a receipt past a declared head is a stale or mixed
//!   capture (issue #1141, A3 stale);
//! * every emitted event identity a receipt claims must be present in the
//!   exported event stream, so a view whose receipt/event chain cannot be
//!   closed is refused before it becomes a section record (issue #1141, A3
//!   unverifiable);
//! * every source event and projection record validates its own recorded
//!   checksum against its payload before it is destructured, so a source whose
//!   retained checksum does not describe its payload is refused instead of
//!   being re-digested into an internally consistent package that no longer
//!   preserves the source's integrity claim;
//! * `eliot-ecxf` then re-proves that every revision and ordering head carries
//!   that same `state_fence`, that every purge-ledger entry does too, that the
//!   fence reachability set equals the residency keys of the exported blobs,
//!   that the fence's declared event interval equals the delivered event count,
//!   and that the manifest's declared purge state equals the ledger the package
//!   actually carries.
//!
//! Issue #1871, A2 additionally requires the two fence values that no admitted
//! column supplies — the schema generation and the reachable blob residency set
//! — to be falsifiable rather than merely well-shaped. They are therefore
//! carried as [`eliot_ecxf::SchemaGenerationObservation`] and
//! [`eliot_ecxf::BlobReachabilityObservation`], each naming the adapter that
//! read it and the state fence it was read at. An owner that observed neither is
//! refused here with [`BackupError::UnobservedSourceMember`] before a fence is
//! assembled, and an owner whose stamped observer or point disagrees with this
//! view's own already-observed identity is refused with
//! [`BackupError::FenceMismatch`]. Neither value can be satisfied by an empty
//! string or an empty vector, because an absent observation is not the same
//! record as an observed empty one.
//!
//! # There is no live-DB-file backup path (issue #1141, W4)
//!
//! I05-10 states the export "is independent of `SurrealQL`" and I05-13 states the
//! ORS fence "is a logical Kernel export, not a copy of a live redb file".
//! `crates/storage/AGENTS.md` carries the same rule: "Live DB file copying is
//! not a supported backup contract."
//!
//! That is not only a claim about this function; it is measurable in the crate,
//! and the measurement is recorded here so a later reader can repeat it:
//!
//! * a sweep of `crates/storage/eliot-backup/src` and
//!   `crates/storage/eliot-ecxf/src` for `fs::copy`, `hard_link`, `copy_dir`,
//!   `copy(`, `fs_extra` and `walkdir` returns no match: no byte of any
//!   pre-existing file is ever duplicated into a package;
//! * a case-insensitive sweep of the same two directories for `surrealdb`,
//!   `surrealkv`, `surreal::`, `Db::`, `rocksdb` and `*.db` returns no match:
//!   the crate holds no vendor type, no database handle and no data-file path;
//! * the crate's every `std::fs` call site is accounted for above and below —
//!   `ecxf_export.rs` writes only package members it rendered itself, into a
//!   staging tree it claimed exclusively, and reads back only those same
//!   members;
//!   `isolated_restore.rs` creates and removes only its own temp-dir root;
//!   `product_run.rs` and `restore_runner.rs` write and read only bundle and
//!   journal bytes they serialized themselves.
//!
//! The consequence is that a backup artifact can only exist if a source owner
//! produced a coherent view through [`EcxfSourceStore`]. There is no code path
//! that produces a package from files found on disk.
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use eliot_blob_api::BlobReadyReceipt;
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::{
    CanonicalEvent, OrderingHead, OrderingScopeId, RevisionHead, RevisionKey, ScopeId,
    ScopeRevisionView, SnapshotCompleteness, WriteReceipt,
};
pub use eliot_store_api::{EcxfExportReport, EcxfExportRequest};
use serde::{Deserialize, Serialize};

use super::{BackupError, CanonicalRecord, EventRange, bytes_sha256, digest, text};

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
    /// Schema generation observed at the bound consistency point, with the
    /// source that observed it.
    ///
    /// `None` when the owner observed no generation. That is the typed absence
    /// and it refuses the export: an owner that has not read a generation cannot
    /// hand one over, and an empty string would be a shape that looks observed
    /// while naming nothing (issue #1871, A2).
    pub schema_generation: Option<eliot_ecxf::SchemaGenerationObservation>,
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
    /// export, with the source that declared them. They are compared against the
    /// residency keys of the delivered blobs, so a source that under- or
    /// over-declares reachability fails instead of shipping an archive whose
    /// fence does not describe it.
    ///
    /// `None` when the owner declared no live set. It refuses the export: an
    /// owner with no reachable-set observation has not established that the
    /// package is complete, and an empty vector would assert exactly that
    /// completeness without having observed anything (issue #1871, A2). An empty
    /// vector *inside* an observation stays available and means the store read a
    /// live set that was empty.
    pub reachable_blob_residency_keys: Option<eliot_ecxf::BlobReachabilityObservation>,
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
/// The four named refusals of issue #1141 item A3 map onto checks that read
/// two *independently recorded* positions rather than re-deriving one from the
/// other:
///
/// * **partial** — the owner's own completeness discriminator, and the declared
///   event interval against the events actually delivered;
/// * **stale** — the observed fence against the authenticated request's fence,
///   and every receipt's own ordering/revision positions against the heads the
///   owner declared for this view;
/// * **mixed-revision** — [`ScopeRevisionView::validate`], the store port's own
///   coherence contract, run over the observed heads so a view assembled from
///   two different moments (or with a duplicate head key) never reaches the
///   archive builder;
/// * **unverifiable** — every receipt's emitted-event identities against the
///   exported event stream, and every source adapter / generation identity
///   against its own shape, so a view that cannot be re-checked by the
///   `eliot-ecxf` manifest validator is refused here first.
///
/// The heads are looked up in maps built once, so the membership test is
/// "does the owner declare this position" and not a search of a caller-chosen
/// list.
/// The owner-declared identities that travel into `manifest.json`, checked for
/// shape at the export boundary rather than by the interchange crate's own
/// `text`/`digest` helpers further down.
///
/// This is a shape requirement, not an authenticity proof: the authenticity
/// obligation is the importer's, which checks the recorded values against what
/// it holds.
fn require_exported_identity_shape(snapshot: &CoherentSourceExport) -> Result<(), BackupError> {
    text(&snapshot.source_adapter, "ecxf.source_adapter")?;
    text(
        &snapshot.source_adapter_version,
        "ecxf.source_adapter_version",
    )?;
    text(&snapshot.store_generation, "ecxf.store_generation")?;
    text(&snapshot.export_receipt, "ecxf.export_receipt")?;
    digest(
        &snapshot.architecture_source_digest,
        "ecxf.architecture_source_digest",
    )?;
    digest(
        &snapshot.normative_pair_identity_receipt_digest,
        "ecxf.normative_pair_identity_receipt_digest",
    )?;
    Ok(())
}

/// Refuses a source view whose fence values no source store observed.
///
/// Issue #1871, A2 requires the fence's schema generation and blob
/// reachability to be *checkable against the source Store*. A view that carries
/// neither names no observation at all, so it is refused here instead of being
/// projected onto a fence member that has only its shape — an absent generation
/// and an absent live set are both the absence of an observation, and neither is
/// readable as an empty one.
///
/// When both observations are present, the provenance on them is compared
/// against this view's own already-observed identity: the adapter that read the
/// values must be the adapter this view declares, and the boundary it read them
/// at must be the boundary this view observed. An owner that stamped a foreign
/// observer or a foreign point onto its own observation is refused, so the fence
/// can only carry provenance the source view already proved.
fn require_observed_fence_sources(snapshot: &CoherentSourceExport) -> Result<(), BackupError> {
    let Some(generation) = snapshot.schema_generation.as_ref() else {
        return Err(BackupError::UnobservedSourceMember {
            member: "schema_generation",
        });
    };
    text(&generation.generation, "ecxf.schema_generation")?;
    let Some(reachability) = snapshot.reachable_blob_residency_keys.as_ref() else {
        return Err(BackupError::UnobservedSourceMember {
            member: "reachable_blob_residency_keys",
        });
    };
    for (member, observation) in [
        ("schema_generation", &generation.observation),
        ("reachable_blob_residency_keys", &reachability.observation),
    ] {
        if observation.observed_by != snapshot.source_adapter {
            return Err(BackupError::FenceMismatch {
                subject: format!(
                    "{member} observed by {} but the source view declares adapter {}",
                    observation.observed_by, snapshot.source_adapter
                ),
            });
        }
        if observation.observed_at != snapshot.state_fence {
            return Err(BackupError::FenceMismatch {
                subject: format!("{member} observed state fence"),
            });
        }
    }
    Ok(())
}

fn prove_coherent_boundary(
    snapshot: &CoherentSourceExport,
    request: &EcxfExportRequest,
) -> Result<(), BackupError> {
    if !snapshot.completeness.is_complete() {
        return Err(BackupError::InconsistentBoundary);
    }
    require_exported_identity_shape(snapshot)?;
    require_observed_fence_sources(snapshot)?;
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
    // Issue #1141, A3 (mixed-revision): the store port already owns the
    // coherent-view contract, so the observed heads are re-checked through
    // `ScopeRevisionView::validate` instead of a second head-checking loop
    // here. It refuses a duplicate revision key, a duplicate ordering scope and
    // any head whose fence differs from the view fence — the three ways a view
    // can describe more than one moment. `eliot-ecxf` checks the same
    // relationship again on the fence it emits; that is a coherence check
    // between two recorded positions, this one is the port contract.
    let scope_view = ScopeRevisionView {
        scope_id: request.scope_id.clone(),
        revision_heads: snapshot.revision_heads.clone(),
        ordering_heads: snapshot.ordering_heads.clone(),
        state_fence: snapshot.state_fence.clone(),
    };
    scope_view.validate().map_err(BackupError::Store)?;
    let revisions: BTreeMap<&RevisionKey, u64> = snapshot
        .revision_heads
        .iter()
        .map(|head| (&head.key, head.revision))
        .collect();
    let orderings: BTreeMap<&OrderingScopeId, u64> = snapshot
        .ordering_heads
        .iter()
        .map(|head| (&head.scope, head.sequence))
        .collect();
    let events: BTreeSet<&str> = snapshot
        .events
        .iter()
        .map(|record| record.record_id.as_str())
        .collect();
    prove_event_range_against_store(snapshot, &orderings)?;
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
        // Issue #1141, A3 (stale): a receipt records the ordering position and
        // the revision advance its transition consumed. If either is past the
        // head the owner declared for this view, the view spans a moment later
        // than its own fence — a mixed or stale capture, refused here rather
        // than emitted as a coherent export.
        for head in &receipt.ordering_sequences {
            let Some(observed) = orderings.get(&head.scope) else {
                return Err(BackupError::FenceMismatch {
                    subject: format!(
                        "receipt {} ordering scope {} absent from the declared ordering heads",
                        receipt.operation_id, head.scope
                    ),
                });
            };
            if head.sequence > *observed {
                return Err(BackupError::FenceMismatch {
                    subject: format!(
                        "receipt {} ordering head {}",
                        receipt.operation_id, head.scope
                    ),
                });
            }
        }
        for delta in &receipt.revision_before_after {
            let Some(observed) = revisions.get(&delta.key) else {
                return Err(BackupError::FenceMismatch {
                    subject: format!(
                        "receipt {} revision key {} absent from the declared revision heads",
                        receipt.operation_id, delta.key
                    ),
                });
            };
            if delta.after > *observed {
                return Err(BackupError::FenceMismatch {
                    subject: format!(
                        "receipt {} revision head {}",
                        receipt.operation_id, delta.key
                    ),
                });
            }
        }
        // Issue #1141, A3 (unverifiable): the receipt/event chain is closed
        // against the exported stream, so a receipt citing an event this view
        // does not deliver is refused before it becomes a section record. The
        // expected set is the delivered event identities, which this crate
        // never chooses.
        for event_id in &receipt.emitted_event_ids {
            if !events.contains(event_id.as_str()) {
                return Err(BackupError::FenceMismatch {
                    subject: format!(
                        "receipt {} emitted event {} absent from the exported event stream",
                        receipt.operation_id, event_id
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Proves the declared `ExportFence` event range and ordering heads against the
/// source Store's own canonical event records.
///
/// I05-10 "Consistent export boundary" ties an export to an `ExportFence` that
/// carries the Ordering Heads and the canonical event range, and issue #1871
/// item A2 requires those values to be *checkable against the source Store*.
/// Comparing the declared range with the number of records this crate is about
/// to write would compare a value with its own shadow and prove nothing about
/// the source, so the expected interval is read from the other side: the
/// store-issued monotonic `event_ordinal` on the source's own `CanonicalEvent`
/// records, and the ordering positions those same records consumed.
///
/// Two independently recorded positions meet here. The declared side comes from
/// the source's `ordering_head` rows and its declared interval; the expected side
/// comes from the `canonical_event` rows of the same capture. Neither is derived
/// from the other, so a source that declares a range or a head its own events
/// contradict is refused before an archive is assembled.
///
/// Each record is decoded as the store owner's [`CanonicalEvent`] and run
/// through that owner's existing `validate`, which re-proves every ordering-link
/// hash over the event's own payload digest and ordinal. Nothing is recomputed
/// here to stand in for owner-issued material: a record that does not carry the
/// store's own canonical event cannot be evidence for the fence at all, so it
/// refuses rather than being read for an ordinal.
fn prove_event_range_against_store(
    snapshot: &CoherentSourceExport,
    orderings: &BTreeMap<&OrderingScopeId, u64>,
) -> Result<(), BackupError> {
    let mut observed: Option<(u64, u64)> = None;
    for record in &snapshot.events {
        let Ok(event) = serde_json::from_value::<CanonicalEvent>(record.payload.clone()) else {
            return Err(BackupError::InvalidField {
                field: "ecxf.event_record",
                reason: "event record does not carry the source store's own canonical event",
            });
        };
        event.validate().map_err(BackupError::Store)?;
        if !event.state_fence.is_compatible_with(&snapshot.state_fence) {
            return Err(BackupError::FenceMismatch {
                subject: format!("event {} state fence", event.event_id.as_str()),
            });
        }
        // A canonical event records the ordering position its own transition
        // consumed. If that position is past the head the source declared for
        // this view, the declared Ordering Head does not describe the events the
        // export delivers, so the view spans a moment later than its own fence.
        for link in &event.ordering_links {
            let Some(declared) = orderings.get(&link.ordering_scope) else {
                return Err(BackupError::FenceMismatch {
                    subject: format!(
                        "event {} ordering scope {} absent from the declared ordering heads",
                        event.event_id.as_str(),
                        link.ordering_scope.as_str()
                    ),
                });
            };
            if link.ordering_sequence > *declared {
                return Err(BackupError::FenceMismatch {
                    subject: format!(
                        "event {} ordering head {}",
                        event.event_id.as_str(),
                        link.ordering_scope.as_str()
                    ),
                });
            }
        }
        observed = Some(match observed {
            Some((first, last)) => (
                first.min(event.event_ordinal),
                last.max(event.event_ordinal),
            ),
            None => (event.event_ordinal, event.event_ordinal),
        });
    }
    // An export that observes no event declares no interval, which stays
    // representable instead of becoming a fabricated bound.
    if snapshot.event_range.first_sequence != observed.map(|(first, _)| first) {
        return Err(BackupError::FenceMismatch {
            subject: "export event range first sequence".to_owned(),
        });
    }
    if snapshot.event_range.last_sequence != observed.map(|(_, last)| last) {
        return Err(BackupError::FenceMismatch {
            subject: "export event range last sequence".to_owned(),
        });
    }
    if snapshot.event_range.count != snapshot.events.len() as u64 {
        return Err(BackupError::FenceMismatch {
            subject: "export event range count".to_owned(),
        });
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
        // An absent observation keeps its own typed variant instead of being
        // folded into a boundary incoherence: "the source store said nothing
        // about this member" and "the source store contradicted itself" are
        // different reasons, and only the source owner can tell them apart.
        eliot_ecxf::EcxfError::UnobservedSourceMember { member } => {
            BackupError::UnobservedSourceMember { member }
        }
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

// ---------------------------------------------------------------------------
// Kernel-fence projection (issue #2569, package BK)
//
// `eliot_ecxf::ExportFence` (`crates/storage/eliot-ecxf/src/lib.rs:217-243`) and
// this crate's own `ExportFence` (`crates/storage/eliot-backup/src/lib.rs:206`)
// are two fences that share a name and are not the same object. Nine members
// have identical types on both sides (`export_id`, `schema_generation` -- the
// very same `eliot_ecxf::SchemaGenerationObservation`, re-exported at
// `lib.rs:201` -- `store_generation`, `state_fence`, `scope_id`,
// `revision_heads`, `ordering_heads`, `event_range`, which is the very same
// `eliot_ecxf::EventRange` re-exported at `lib.rs:189`, and `consistent`), so
// those carry the source value verbatim. Nothing is flattened on the way: the
// source's schema generation crosses as the owner's own observation, naming the
// adapter that read it and the state fence it read it at, so a kernel fence
// states the same checkable provenance the interchange fence states rather than a
// bare generation string or a digest of one.
//
// The two fences now differ in exactly one place, and that difference is the
// refusal below rather than a conversion:
//
// * the interchange fence's `blob_reachability_manifest` is an OBSERVATION whose
//   declared set holds RESIDENCY-key digests (`eliot-ecxf/src/lib.rs:198-215`
//   and `:231-241`: issue #1871 D1 -- reachability is keyed on residency and
//   not on content, because I05-13 forbids merging records whose content
//   digests match). The kernel fence's member is a `Vec<BlobHash>` that its
//   consumers read as a bijection over CONTENT digests:
//   `lib.rs:796` requires every `blob.locator.hash` to be in that set,
//   `lib.rs:802` requires its length to equal the carried blob count, and
//   `bins/eliot-kernel/src/backup_capture.rs:1818` states that explicitly ("the
//   fence bijection is still over CONTENT digests"). Re-parsing a residency key
//   through `BlobHash::new` would type-check and would still assert a content
//   identity that no owner ever proved, so it refuses.
//
// Issue #1871, A2 made both fenced source values observations, so an absent
// observation is a state this projection can see. It refuses that state by name
// instead of reading it as an empty member: an empty kernel member would be
// indistinguishable from an owner-issued bijection over zero blobs, which is
// precisely the fabrication this projection exists to prevent. An observed but
// EMPTY live set remains a store statement about zero blobs and is carried as
// the empty list it is.
//
// Nothing is synthesized, defaulted or dropped: a member that cannot be carried
// ends the conversion with a named refusal instead of a plausible value.

use eliot_blob_api::BlobHash;

/// Why one `eliot_ecxf::ExportFence` member could not be carried onto the
/// kernel [`ExportFence`](super::ExportFence).
///
/// The first refusal in source-member order is returned, matching the
/// single-variant shape of this crate's other boundary mappings
/// ([`ecxf_error`], and `unobserved_member` in
/// `bins/eliot-store-surreal/src/ecxf_export.rs:170`).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FenceBridgeRefusal {
    /// The source member carries no source-store observation at all.
    ///
    /// Issue #1871, A2: `schema_generation` and `blob_reachability_manifest`
    /// are observations rather than bare values, so an absent observation is
    /// representable and is never the same record as an observed empty one.
    /// Reading it as an empty member here would fabricate exactly the silence
    /// this projection exists to refuse, so it is refused by name instead.
    #[error("ecxf export fence {member:?} carries no source-store observation")]
    SourceMemberAbsent {
        /// The static name of the source member that carries no observation.
        member: &'static str,
    },
    /// A source manifest entry is not a canonical digest at all.
    #[error(
        "ecxf export fence blob_reachability_manifest entry {entry:?} is not a canonical digest: {reason}"
    )]
    MalformedResidencyKey {
        /// The offending source entry, carried verbatim so the refusal names it.
        entry: String,
        /// The owning constructor's own reason for refusing it.
        reason: String,
    },
    /// The source member holds residency identities where the kernel member is
    /// read as a content-digest bijection.
    #[error(
        "ecxf export fence blob_reachability_manifest holds residency-key digests, not the content digests the kernel ExportFence binds to BackupBlob::locator.hash"
    )]
    ResidencyKeyIsNotContentIdentity,
    /// The carried ORIGINAL recorded values were refused by the kernel validator.
    #[error("the carried fence was refused by the kernel ExportFence::validate: {reason}")]
    CarriedFenceRefused {
        /// The kernel validator's own refusal, carried verbatim.
        reason: String,
    },
}

impl TryFrom<&eliot_ecxf::ExportFence> for super::ExportFence {
    type Error = FenceBridgeRefusal;

    /// Carries every member the two fences hold in common, by value.
    ///
    /// The ORIGINAL recorded values are carried and then proved by this crate's
    /// own [`ExportFence::validate`](super::ExportFence::validate). No digest is
    /// recomputed here and no stored digest is replaced by a fresh one.
    fn try_from(source: &eliot_ecxf::ExportFence) -> Result<Self, Self::Error> {
        // Issue #1871, A2: `schema_generation` is an observation now, so "nobody
        // read a generation" is a state distinct from "the owner read an empty
        // one". An absent observation is refused by name here rather than read as
        // an empty generation, because an empty generation reads exactly like an
        // observed value that names nothing. An owner-issued fence always carries
        // one -- `eliot_ecxf::ExportFence::validate` refuses a fence that
        // carries none -- so this refusal is reachable only for a fence the
        // interchange owner would itself refuse.
        if source.schema_generation.is_none() {
            return Err(FenceBridgeRefusal::SourceMemberAbsent {
                member: "schema_generation",
            });
        }
        // Issue #1871, A2: `blob_reachability_manifest` is an observation too, so
        // "nobody declared a live set" is a state distinct from "the owner
        // declared an empty one". An absent observation is refused by name here
        // rather than read as an empty member, because an empty kernel member is
        // exactly the fabrication this bridge exists to refuse. An observed but
        // EMPTY live set stays convertible below, and that is a store statement
        // about zero blobs rather than a silence.
        let Some(reachability) = source.blob_reachability_manifest.as_ref() else {
            return Err(FenceBridgeRefusal::SourceMemberAbsent {
                member: "blob_reachability_manifest",
            });
        };
        // Shape gate over the source's own observed list: every entry is parsed by
        // the existing `BlobHash` constructor, so a malformed entry is refused by
        // the owner that defines the digest rather than by a local re-check of it.
        let mut blob_reachability_manifest =
            Vec::with_capacity(reachability.residency_key_digests.len());
        for entry in &reachability.residency_key_digests {
            blob_reachability_manifest.push(BlobHash::new(entry.clone()).map_err(|error| {
                FenceBridgeRefusal::MalformedResidencyKey {
                    entry: entry.clone(),
                    reason: error.to_string(),
                }
            })?);
        }
        // The observed reachability set holds residency-key digests and the kernel
        // member is read as a content bijection, so a populated source list
        // refuses instead of being re-typed as content identity.
        if !blob_reachability_manifest.is_empty() {
            return Err(FenceBridgeRefusal::ResidencyKeyIsNotContentIdentity);
        }
        // The source fence carries `schema_generation` as the source store's own
        // observation and the kernel fence has a member for exactly that value,
        // so it crosses verbatim below: the generation string, the adapter that
        // read it and the state fence it was read at. This bridge never supplies
        // a generation of its own in either state and never flattens the
        // observation into a bare string or a digest of one.
        let fence = Self {
            export_id: source.export_id.clone(),
            schema_generation: source.schema_generation.clone(),
            store_generation: source.store_generation.clone(),
            state_fence: source.state_fence.clone(),
            scope_id: source.scope_id.clone(),
            revision_heads: source.revision_heads.clone(),
            ordering_heads: source.ordering_heads.clone(),
            event_range: source.event_range.clone(),
            blob_reachability_manifest,
            consistent: source.consistent,
        };
        // The carried ORIGINAL recorded values are proved by the existing
        // validator. It is not weakened, bypassed or re-implemented here.
        fence
            .validate()
            .map_err(|error| FenceBridgeRefusal::CarriedFenceRefused {
                reason: error.to_string(),
            })?;
        Ok(fence)
    }
}
