//! The production [`EcxfSourceStore`] composition for `ECXF/1` export (issue #1871).
//!
//! The `ecxf_export` module owns the archive, the manifest and the
//! `ExportFence`, but until now it had no implementor: `EcxfSourceStore` had
//! zero implementors and `export_ecxf_package` had zero call sites, so no
//! production process could produce an `ECXF/1` package at all. This module is
//! that missing half. It supplies one [`EcxfSourceOwners`] port for the owners
//! that actually hold the source evidence, and [`CoherentEcxfSource`] reads
//! through that port to assemble the [`CoherentSourceExport`] the exporter
//! consumes. It derives no `ExportFence`, builds no archive, writes no manifest
//! and defines no second fence or manifest vocabulary.
//!
//! # The coherence route
//!
//! I5.10 "Consistent export boundary" admits two routes: "The bridge uses a
//! database-supported consistent snapshot/transaction when available. Otherwise
//! it records a base fence, exports immutable history/projections, tails
//! canonical events to a final fence and briefly quiesces affected writes for
//! final reconciliation."
//!
//! The deployed canonical Store provides the first route, so that is the only
//! route modelled here. [`EcxfSourceOwners::capture_source`] is the
//! database-supported consistent snapshot: the store owner reads its admitted
//! member classes and the state fence observed *beside them in the same
//! transaction*, and returns both together. The single observation of rows and
//! fence at one consistency point is the whole proof — there is no second read
//! to reconcile against, no base fence, no event tail and no write quiesce
//! anywhere in this module. `EcxfSourceOwners::capture_source` has no default
//! body, so a source with no real store owner behind it cannot reach the
//! exporter at all.
//!
//! The rows and the fence therefore travel in one value ([`SourceCapture`]) and
//! cannot be read at two different moments. The composition adds no fence
//! evidence of its own and never re-reads the store: it asks once, and the
//! coherent boundary is the one that observation already proved.
//!
//! # Fail-closed completeness
//!
//! I5.10: "If neither route can prove a coherent boundary, the export fails;
//! mixing unrelated table moments into one 'backup' is forbidden."
//!
//! The store owner alone cannot prove the whole view. It reads canonical rows
//! and its own fence, so it honestly reports itself
//! [`SnapshotCompleteness::Partial`] and names the evidence it cannot observe
//! ([`SourceEvidenceGap`]). Those declarations are neither refusals nor
//! bookkeeping: every declared gap is closed only by positive evidence this
//! call actually obtained, and a gap with no such evidence refuses the export.
//! A gap is never closed by the absence of the work that would have closed it,
//! and never by a value that merely has the right shape.
//!
//! * [`SourceEvidenceGap::RequestedScopeClosureUnproven`] is refused before any
//!   owner is read, because it is the one gap only the canonical store can hold:
//!   no other owner has the scope-to-record closure. An unproven scope closure is
//!   exactly the "mixing unrelated table moments into one 'backup'" that I05.10
//!   forbids, and deciding it here costs no blob or ledger work.
//! * [`SourceEvidenceGap::SourcePurgeLedgerUnavailable`] is closed only by a
//!   ledger this call obtained that carries entries. An owner that returns an
//!   empty ledger under a declared gap has not observed the ledger:
//!   `eliot-ecxf` would render that emptiness faithfully into
//!   `privacy-purge-ledger.json`, and nothing downstream could tell it apart
//!   from a source that genuinely holds no purge entries.
//! * [`SourceEvidenceGap::BlobStoreEvidenceUnavailable`] is closed only when the
//!   store declared at least one reachable residency identity and every one of
//!   them came back sealed and revalidated. A store that declared the gap *and*
//!   declared no locators produced the absence of the work, not its result.
//! * [`SourceEvidenceGap::ExternalSourceIdentityEvidenceUnavailable`] and
//!   [`SourceEvidenceGap::SourceExportReceiptUnavailable`] are refused. The
//!   owner port returns a digest and a reference, which is exactly what the
//!   manifest needs and nothing more, so shape is all that can be checked and
//!   existence is not derivable from it. Assuming closure would let a store that
//!   observed neither receipt ship a manifest attesting to both.
//! * A capture that reports itself non-`Complete` while naming no gap is
//!   refused too: an unnamed incompleteness names no evidence another owner
//!   could supply.
//!
//! [`SnapshotCompleteness::Complete`] is therefore reachable only when the
//! export is either gap-free, because the store attested to its own completeness
//! and named nothing it could not observe, or every gap it named is closed by
//! positive evidence obtained in this same call. Nothing here is defaulted, and
//! the exporter's own `prove_coherent_boundary` refusal is left in place and
//! unreached by any composition value this module can build.
//!
//! # Every value comes from an owner
//!
//! No field of [`CoherentSourceExport`] is synthesised here. The state fence,
//! schema generation, store generation, adapter identity, scope, revision heads,
//! ordering heads, event range, events, projections, receipts and the declared
//! reachable residency locators are copied from the store owner's single
//! snapshot. The Architecture source digest and the sealed
//! `NormativePairIdentity` receipt digest come from the external source-identity
//! owner. The source-side export receipt reference comes from the export-receipt
//! owner. The compression, encryption and unsupported-feature declarations come
//! from the export-profile owner. The privacy/purge ledger comes from the
//! privacy owner. The sealed blob bytes and their completed receipts come from
//! the `BlobStore` owner, and the fence's residency reachability set is derived
//! through the owner's own accessor
//! [`BlobLocator::residency_key_digest`], never through a look-alike digest and
//! never from a content digest: I05.13 "Export and backup never merge blob
//! records solely because their content digests match."
//!
//! No provider query text, table name or SurrealQL appears here. The composition
//! is store-neutral: it names a port, never a schema (I05.10 "Export is
//! independent of SurrealQL"; `crates/storage/AGENTS.md` "No raw SurrealQL,
//! generic query/upsert").
//!
//! # Judgement calls
//!
//! ASSUMPTION: the two gaps whose evidence this port cannot observe, the
//! externally sealed identity pair and the source-side export receipt, are
//! refused rather than assumed closed. No document settles it. I05.10 requires
//! the manifest to carry both a `NormativePairIdentity` receipt digest and an
//! export receipt and requires a coherence proof, but the values this port
//! returns are precisely the values the manifest needs: a digest string and a
//! reference. Checking their shape admits them; it does not establish that
//! either receipt exists, and this crate never recomputes a digest an owner
//! already recorded, so there is no owner-issued material here a digest could be
//! tied to. Assuming closure would let a store that observed neither receipt ship
//! a manifest attesting to both, which is the failure I05.10 forbids. Refusing
//! is the safe reading; widening the port to carry the sealed receipt material is
//! a change to this seam, not a judgement this module may make for it.

use eliot_blob_api::{BlobLocator, SealedBlobRead};
use eliot_contracts::StateFence;
use eliot_ecxf::{CompressionProfile, EncryptionProfile};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::{
    EcxfExportRequest, OrderingHead, RevisionHead, ScopeId, SnapshotCompleteness, WriteReceipt,
};

use super::{
    BackupError, CanonicalRecord, CoherentSourceExport, EcxfSourceStore, EventRange, SealedBlobEntry,
    digest, text,
};

/// Evidence the canonical store owner declares it cannot observe by itself.
///
/// A gap is a declaration by the store owner about its own view, not a failure.
/// It names the evidence that is missing, and this composition closes it only
/// when this call actually obtained that evidence; otherwise the export is
/// refused. The five cases are the store owner's own closed vocabulary, restated
/// here because this crate may not depend on the admitted store adapter — the
/// composition root maps the adapter's capture onto [`SourceCapture`], and a gap
/// it cannot map is a gap it never reports, not a gap it may drop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceEvidenceGap {
    /// The store returned rows without proving they cover the requested scope.
    ///
    /// Only the canonical store can close this: no other owner holds the
    /// scope-to-record closure, so it refuses the export outright.
    RequestedScopeClosureUnproven,
    /// The admitted schema does not carry the source erasure/purge ledger.
    ///
    /// Closed by [`EcxfSourceOwners::purge_ledger`] returning a ledger that
    /// carries entries. An empty ledger leaves the gap standing.
    SourcePurgeLedgerUnavailable,
    /// The store is not the `BlobStore` owner and read no sealed bytes.
    ///
    /// Closed by [`EcxfSourceOwners::sealed_blob`] answering for every residency
    /// identity the store declared reachable, of which there must be at least
    /// one. Declaring no reachable identity leaves the gap standing.
    BlobStoreEvidenceUnavailable,
    /// Architecture and `NormativePair` identity receipts are sealed elsewhere.
    ///
    /// Refused: [`EcxfSourceOwners::source_identity`] returns the manifest's
    /// digest, so its shape cannot distinguish an owner that holds the sealed
    /// receipt from one that does not.
    ExternalSourceIdentityEvidenceUnavailable,
    /// The store holds no durable source-side ECXF export receipt.
    ///
    /// Refused: [`EcxfSourceOwners::source_export_receipt`] returns the
    /// manifest's receipt reference, so its shape cannot distinguish a durable
    /// receipt from a placeholder.
    SourceExportReceiptUnavailable,
}

impl SourceEvidenceGap {
    /// The typed refusal this gap produces up front, or `None` when this call
    /// must still read an owner before it can judge the gap.
    ///
    /// Only the scope closure is refused before any owner is read, because it is
    /// the only gap no other owner can hold. It is refused as
    /// [`BackupError::InconsistentBoundary`] because an unproven scope closure
    /// is exactly the "mixing unrelated table moments into one 'backup'" that
    /// I05.10 forbids, and deciding it here costs no blob or ledger work.
    ///
    /// A `None` is not closure. It means the gap is decided later, against the
    /// evidence this call actually obtained.
    const fn refusal(self) -> Option<BackupError> {
        match self {
            Self::RequestedScopeClosureUnproven => Some(BackupError::InconsistentBoundary),
            Self::SourcePurgeLedgerUnavailable
            | Self::BlobStoreEvidenceUnavailable
            | Self::ExternalSourceIdentityEvidenceUnavailable
            | Self::SourceExportReceiptUnavailable => None,
        }
    }
}

/// One database-supported consistent snapshot of the canonical source store.
///
/// The store owner fills this from a single observation: the admitted member
/// classes and the state fence, schema generation and resource generation
/// observed beside them inside the same transaction. Rows and fence cannot be
/// read at two different moments, because the store owner obtained both at one
/// consistency point and this module never re-reads the store.
///
/// `completeness` and `missing_evidence` are the store owner's honest account
/// of *its own* view. A capture that names no gap and reports itself
/// `Complete` is the store's own attestation and is taken as such. A capture
/// that names gaps is not complete until each named gap is closed by positive
/// evidence this composition obtained; see the module header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCapture {
    /// Completeness of the store owner's own capture.
    pub completeness: SnapshotCompleteness,
    /// Evidence the store owner declares it cannot observe by itself.
    pub missing_evidence: Vec<SourceEvidenceGap>,
    /// Store adapter identity that produced this snapshot.
    pub source_adapter: String,
    /// Store adapter version that produced this snapshot.
    pub source_adapter_version: String,
    /// Schema generation observed at the bound consistency point.
    pub schema_generation: String,
    /// Store resource generation observed at the bound consistency point.
    pub store_generation: String,
    /// Scope the store owner read.
    pub scope_id: ScopeId,
    /// State fence observed in the same transaction as the rows.
    pub state_fence: StateFence,
    /// Revision heads observed in the same transaction.
    pub revision_heads: Vec<RevisionHead>,
    /// Ordering heads observed in the same transaction.
    pub ordering_heads: Vec<OrderingHead>,
    /// Canonical event interval this snapshot covers.
    pub event_range: EventRange,
    /// Canonical events observed at the bound consistency point.
    pub events: Vec<CanonicalRecord>,
    /// Projection records observed at the bound consistency point.
    pub projections: Vec<CanonicalRecord>,
    /// Canonical write receipts observed at the bound consistency point.
    pub receipts: Vec<WriteReceipt>,
    /// Residency identities the store declares reachable from this view.
    ///
    /// Each is a full residency identity, not a digest, because that is the
    /// only form the `BlobStore` owner can be addressed with. The fence's
    /// reachability set is derived from these, and `eliot-ecxf` then proves it
    /// equals the residency keys of the blobs that were actually delivered, so
    /// a blob owner that returns a different object is refused instead of
    /// silently redefining what the fence declared.
    pub reachable_blobs: Vec<BlobLocator>,
}

/// The externally sealed identity pair the manifest must carry.
///
/// I5.10 requires "Architecture source digest plus externally sealed
/// `NormativePairIdentity` receipt". Both are sealed outside the canonical
/// store, so the store cannot observe them and never guesses them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceIdentity {
    /// Digest of the Architecture source the export was taken against.
    pub architecture_source_digest: String,
    /// Digest of the externally sealed `NormativePairIdentity` receipt.
    pub normative_pair_identity_receipt_digest: String,
}

/// The profile the source declares for the package it emits.
///
/// These are the source's own declarations, not exporter choices: the exporter
/// copies them into the manifest and `eliot-ecxf` revalidates them, so a source
/// that cannot declare them cannot export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceExportProfile {
    /// Compression profile applied to the emitted sections.
    pub compression: CompressionProfile,
    /// Encryption profile declared for the emitted package.
    pub encryption: EncryptionProfile,
    /// Features the source could not represent in this export.
    ///
    /// An empty list is the owner's declaration that it represented every
    /// feature, not a stand-in for missing evidence: every evidence gap is
    /// carried by [`SourceCapture::missing_evidence`] instead.
    pub missing_features: Vec<String>,
}

/// The owners that together hold every value an `ECXF/1` export needs.
///
/// This is the composition seam, not a capability implementation. It is the
/// single port the composition root binds to the real owners: the canonical
/// store adapter, the `BlobStore` owner, the privacy/purge-ledger owner, the
/// external source-identity owner, the source export-receipt owner and the
/// export-profile owner. Every method has no default body, so a bundle with no
/// real owner behind it cannot produce an export, and no method may return a
/// synthesised stand-in for an owner value — an owner that cannot answer
/// returns its own typed [`BackupError`] and the export never completes.
///
/// Every method takes the export request (or the snapshot it was read from)
/// so the owner can bind its answer to one operation, and none of them takes a
/// caller-presented fence, generation or digest.
#[allow(async_fn_in_trait)]
pub trait EcxfSourceOwners: Send + Sync {
    /// Reads the one database-supported consistent snapshot of the canonical
    /// source store for this export operation.
    ///
    /// This is the I5.10 snapshot route. The returned [`SourceCapture`] carries
    /// the canonical rows and the state fence observed in the same transaction,
    /// so the coherence proof is that single observation.
    ///
    /// # Errors
    ///
    /// Returns the store owner's own typed [`BackupError`] when the consistency
    /// point cannot be opened, when the request does not validate, or when the
    /// store owner holds no such snapshot. It never reports a partial read as a
    /// complete one.
    async fn capture_source(
        &self,
        request: &EcxfExportRequest,
    ) -> Result<SourceCapture, BackupError>;

    /// Reads one declared reachable residency identity back as sealed bytes
    /// together with the receipt that already binds them.
    ///
    /// The owner returns the `BlobStore`'s own validated pair; this composition
    /// revalidates that pair and never seals, re-hashes or re-receipts a
    /// payload (I05.12: a `BlobReadyReceipt` is returned "only after durable
    /// rename and metadata commit", and it "proves durable payload
    /// availability only").
    ///
    /// # Errors
    ///
    /// Returns the blob owner's typed [`BackupError`] when the residency
    /// identity is unknown, not durable, not readable, or not bound to the
    /// receipt it is returned with. Absence is never reported as an empty blob.
    ///
    /// Answering is what closes [`SourceEvidenceGap::BlobStoreEvidenceUnavailable`],
    /// and only for a residency identity the store actually declared reachable;
    /// a store that declared the gap and declared none leaves it standing.
    async fn sealed_blob(&self, locator: &BlobLocator) -> Result<SealedBlobRead, BackupError>;

    /// Reads the source privacy/purge ledger for the scope and fence of
    /// `capture`.
    ///
    /// The ledger is read for the snapshot, not for the request, so every entry
    /// is one the same consistency point can be held against. Entries that do
    /// not carry that fence are refused by the archive build, which checks each
    /// one against the export fence.
    ///
    /// Returning an empty ledger is a claim that the source holds no purge
    /// entries. It closes
    /// [`SourceEvidenceGap::SourcePurgeLedgerUnavailable`] only if the store did
    /// not declare that gap; under a declared gap an empty ledger is the gap
    /// still standing and refuses the export.
    ///
    /// # Errors
    ///
    /// Returns the privacy owner's typed [`BackupError`] when the ledger cannot
    /// be read at that fence. An unreadable ledger is never reported as an empty
    /// one, because an empty ledger is a claim that nothing was ever purged
    /// (I05.13 restore "appl[ies] privacy purge ledger").
    async fn purge_ledger(
        &self,
        capture: &SourceCapture,
    ) -> Result<Vec<PurgeLedgerEntry>, BackupError>;

    /// Reads the externally sealed Architecture source and
    /// `NormativePairIdentity` receipts for this installation.
    ///
    /// The returned digests are the manifest's own values, so a well-formed one
    /// is admitted into the export; it is not proof that the sealed receipt
    /// exists, and it does not close
    /// [`SourceEvidenceGap::ExternalSourceIdentityEvidenceUnavailable`].
    ///
    /// # Errors
    ///
    /// Returns the identity owner's typed [`BackupError`] when either receipt is
    /// absent or unreadable. A missing receipt is never replaced by a digest
    /// this module could compute.
    async fn source_identity(&self) -> Result<SourceIdentity, BackupError>;

    /// Reads the reference of the source-side export receipt already issued for
    /// this export operation.
    ///
    /// The returned reference is the manifest's own value, so a non-blank one is
    /// admitted into the export; it is not proof that a durable receipt exists,
    /// and it does not close [`SourceEvidenceGap::SourceExportReceiptUnavailable`].
    ///
    /// # Errors
    ///
    /// Returns the export-receipt owner's typed [`BackupError`] when no durable
    /// receipt exists for this operation. The reference is never minted here:
    /// I05.10 requires the manifest to carry an export receipt, and a receipt
    /// this module invented would attest to nothing.
    async fn source_export_receipt(
        &self,
        request: &EcxfExportRequest,
    ) -> Result<String, BackupError>;

    /// Reads the compression, encryption and unsupported-feature profile the
    /// source declares for the package it emits.
    ///
    /// # Errors
    ///
    /// Returns the profile owner's typed [`BackupError`] when the installation
    /// declares no export profile. No default profile is substituted, because a
    /// guessed profile would be an unbacked claim about the emitted bytes.
    fn export_profile(&self) -> Result<SourceExportProfile, BackupError>;
}

/// The production [`EcxfSourceStore`] over one [`EcxfSourceOwners`] bundle.
///
/// Construct it with [`CoherentEcxfSource::new`] around the real owner handles
/// and hand it to [`export_ecxf_package`](super::export_ecxf_package). It holds
/// no fence, no archive and no filesystem state: every value it returns was read
/// from the owner bundle it wraps.
pub struct CoherentEcxfSource<O: ?Sized> {
    owners: O,
}

impl<O> CoherentEcxfSource<O> {
    /// Binds this composition to the real owners of one source.
    pub fn new(owners: O) -> Self {
        Self { owners }
    }
}

impl<O: EcxfSourceOwners + ?Sized> EcxfSourceStore for CoherentEcxfSource<O> {
    /// Reads one coherent, fenced view of the source through the owner bundle.
    ///
    /// The order is the order of the proof. The store's one consistent snapshot
    /// comes first, and a gap no other owner can close refuses the export there
    /// and then, before any blob or ledger work. Every other declared gap is
    /// decided afterwards against the evidence this call actually obtained, so a
    /// gap the owners could not evidence refuses the export here rather than
    /// being marked closed. The view is returned only when no declared gap is
    /// still standing.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::InconsistentBoundary`] when the store declares an
    /// unclosable scope closure, reports itself non-`Complete` without naming a
    /// gap, or names a gap this call obtained no positive evidence for;
    /// [`BackupError::InvalidField`] when a sealed identity digest or the
    /// export-receipt reference is not the shape the manifest requires, which
    /// admits the value into the export without establishing that the receipt
    /// behind it exists; and the owning component's own typed [`BackupError`]
    /// whenever a store, blob, privacy, identity, export-receipt or profile owner
    /// cannot answer. No failure is collapsed into a synthesised value.
    async fn coherent_export(
        &self,
        request: &EcxfExportRequest,
    ) -> Result<CoherentSourceExport, BackupError> {
        let capture = self.owners.capture_source(request).await?;
        prove_capture_is_closable(&capture)?;
        let identity = self.owners.source_identity().await?;
        digest(
            &identity.architecture_source_digest,
            "architecture_source_digest",
        )?;
        digest(
            &identity.normative_pair_identity_receipt_digest,
            "normative_pair_identity_receipt_digest",
        )?;
        let export_receipt = self.owners.source_export_receipt(request).await?;
        text(&export_receipt, "export_receipt")?;
        let purge_ledger = self.owners.purge_ledger(&capture).await?;
        let profile = self.owners.export_profile()?;
        let (reachable_blob_residency_keys, blobs) = self.seal_reachable_blobs(&capture).await?;
        prove_every_declared_gap_is_closed(&capture, &purge_ledger, &blobs)?;
        Ok(CoherentSourceExport {
            // Reachable only because the call above refused every declared gap
            // this composition could not evidence: either the store attested to
            // its own completeness and named no gap, or every gap it named is
            // closed by evidence obtained in this same call. A gap that is still
            // standing never reaches this line.
            completeness: SnapshotCompleteness::Complete,
            source_adapter: capture.source_adapter,
            source_adapter_version: capture.source_adapter_version,
            schema_generation: capture.schema_generation,
            store_generation: capture.store_generation,
            architecture_source_digest: identity.architecture_source_digest,
            normative_pair_identity_receipt_digest: identity
                .normative_pair_identity_receipt_digest,
            export_receipt,
            // The scope is the one the store read, not the one the request
            // asked for; the exporter proves the two agree.
            scope_id: Some(capture.scope_id),
            state_fence: capture.state_fence,
            revision_heads: capture.revision_heads,
            ordering_heads: capture.ordering_heads,
            event_range: capture.event_range,
            reachable_blob_residency_keys,
            events: capture.events,
            projections: capture.projections,
            receipts: capture.receipts,
            blobs,
            purge_ledger,
            compression: profile.compression,
            encryption: profile.encryption,
            missing_features: profile.missing_features,
        })
    }
}

impl<O: EcxfSourceOwners + ?Sized> CoherentEcxfSource<O> {
    /// Seals every residency identity the store declared reachable.
    ///
    /// The reachability set is derived from the store's declaration through the
    /// owner's own [`BlobLocator::residency_key_digest`] accessor and returned
    /// alongside the delivered blobs, so `eliot-ecxf` can prove that the fence
    /// describes exactly what the export carries. The content digest is never
    /// used for this: I5.13 "Export and backup never merge blob records solely
    /// because their content digests match", so equal bytes under different
    /// obligations stay two distinct reachable objects.
    ///
    /// Each sealed read is revalidated before its bytes are taken, and the pair
    /// is moved through the owner's own `into_parts` accessor, so a receipt and
    /// a payload that were not issued together can never reach the exporter.
    ///
    /// The returned pairs are the positive evidence for
    /// [`SourceEvidenceGap::BlobStoreEvidenceUnavailable`]: reaching this return
    /// means every declared locator produced a validated pair, and the caller
    /// still requires at least one declared locator for the gap to count as
    /// closed.
    async fn seal_reachable_blobs(
        &self,
        capture: &SourceCapture,
    ) -> Result<(Vec<String>, Vec<SealedBlobEntry>), BackupError> {
        let mut reachable_blob_residency_keys = Vec::with_capacity(capture.reachable_blobs.len());
        let mut blobs = Vec::with_capacity(capture.reachable_blobs.len());
        for locator in &capture.reachable_blobs {
            reachable_blob_residency_keys.push(locator.residency_key_digest()?);
            let read = self.owners.sealed_blob(locator).await?;
            read.validate()?;
            let (ready_receipt, sealed_bytes) = read.into_parts();
            blobs.push(SealedBlobEntry {
                sealed_bytes,
                ready_receipt,
            });
        }
        Ok((reachable_blob_residency_keys, blobs))
    }
}

/// Refuses a capture whose coherence this composition cannot finish.
///
/// An unclosable declared gap, or an incompleteness that names nothing, is the
/// I5.10 refusal: the export fails rather than mixing whatever moments were
/// available into one package. This is the pre-read half of that decision; the
/// gaps it lets through are judged later, against the evidence this call
/// obtained, by [`prove_every_declared_gap_is_closed`].
fn prove_capture_is_closable(capture: &SourceCapture) -> Result<(), BackupError> {
    if let Some(refusal) = capture
        .missing_evidence
        .iter()
        .copied()
        .find_map(SourceEvidenceGap::refusal)
    {
        return Err(refusal);
    }
    if !capture.completeness.is_complete() && capture.missing_evidence.is_empty() {
        return Err(BackupError::InconsistentBoundary);
    }
    Ok(())
}

/// Refuses an export whose declared gaps are not all closed by real evidence.
///
/// Any declared gap that no evidence obtained in this call closes refuses the
/// export. A gap is never closed by the absence of the work that would have
/// closed it, and never by a value that only has the right shape. The arms below
/// say when a gap is still standing, one per gap, and each is the strongest
/// evidence available rather than the weakest that would pass:
///
/// * the scope closure, the externally sealed identity pair and the source-side
///   export receipt have no evidence available on this port. The scope closure
///   is the pre-read refusal; the other two return only the manifest's own
///   digest and reference, so all that can be checked there is shape, and shape
///   is not existence. Assuming closure would let a store that observed neither
///   receipt ship a manifest attesting to both.
/// * the purge ledger is closed by entries this call obtained, because a ledger
///   with no entries is a claim about the source rather than evidence of one,
///   and under a declared gap `eliot-ecxf` would render that claim into the
///   package indistinguishable from a source that really holds none.
/// * blob evidence is closed by a non-empty declared reachability set whose every
///   member was sealed and revalidated, because a store that declared the gap
///   and declared no locators produced the absence of the work rather than its
///   result.
///
/// The refusal is [`BackupError::InconsistentBoundary`], the same typed variant
/// [`export_ecxf_package`](super::export_ecxf_package) already uses for a source
/// that cannot prove one coherent boundary, so the two layers cannot disagree
/// about what a coherent export is. It names the boundary rather than the gap
/// because this crate's failure type carries no payload for the gap.
fn prove_every_declared_gap_is_closed(
    capture: &SourceCapture,
    purge_ledger: &[PurgeLedgerEntry],
    blobs: &[SealedBlobEntry],
) -> Result<(), BackupError> {
    let still_standing = capture.missing_evidence.iter().any(|gap| match gap {
        SourceEvidenceGap::RequestedScopeClosureUnproven
        | SourceEvidenceGap::ExternalSourceIdentityEvidenceUnavailable
        | SourceEvidenceGap::SourceExportReceiptUnavailable => true,
        SourceEvidenceGap::SourcePurgeLedgerUnavailable => purge_ledger.is_empty(),
        SourceEvidenceGap::BlobStoreEvidenceUnavailable => {
            capture.reachable_blobs.is_empty() || blobs.len() != capture.reachable_blobs.len()
        }
    });
    if still_standing {
        return Err(BackupError::InconsistentBoundary);
    }
    Ok(())
}
