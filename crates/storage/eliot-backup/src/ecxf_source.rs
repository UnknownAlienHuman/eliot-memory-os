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
//! ([`SourceEvidenceGap`]). Those declarations are not refusals: each one names
//! the owner that can actually close it, and this composition closes it by
//! reading that owner.
//!
//! * [`SourceEvidenceGap::RequestedScopeClosureUnproven`] is the one gap no
//!   other owner can close — only the canonical store can prove that the rows it
//!   returned cover the requested scope — so it is refused here with
//!   [`BackupError::InconsistentBoundary`] before any owner is read.
//! * The other four gaps name owners this composition does read, so each is
//!   closed only if that owner's read actually succeeds. A purge-ledger owner
//!   that cannot answer, a blob owner that cannot seal a declared residency key,
//!   an identity owner with no sealed receipt and an export-receipt owner with no
//!   durable receipt each return their own typed failure, which propagates.
//! * A capture that reports itself non-`Complete` while naming no gap is
//!   refused too: an unnamed incompleteness is not something another owner can
//!   close, and this module never guesses which gap it stands for.
//!
//! [`SnapshotCompleteness::Complete`] is therefore returned only when every
//! declared gap is closed by a real owner value this composition actually
//! holds. Nothing here is defaulted, and the exporter's own
//! `prove_coherent_boundary` refusal is left in place and unreached by any
//! composition value this module can build.
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
//! ASSUMPTION: the source's *store* completeness and this composition's *view*
//! completeness are different claims, so the composition derives the view's
//! value instead of copying the store's. I05.10 requires a coherence *proof*,
//! and the store owner can only attest to what it read. When the store names the
//! exact gaps it cannot observe, this composition either closes each one with a
//! real owner value or refuses, which is the only reading under which the
//! database-supported snapshot route can ever succeed against a real store. An
//! unnamed non-`Complete` claim is still refused, because nothing in it
//! identifies evidence another owner could supply.

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
/// It names the owner that can actually close it, and this composition closes
/// each one by reading that owner; only a gap with no other owner is a refusal.
/// The five cases are the store owner's own closed vocabulary, restated here
/// because this crate may not depend on the admitted store adapter — the
/// composition root maps the adapter's capture onto [`SourceCapture`], and a
/// gap it cannot map is a gap it never reports, not a gap it may drop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceEvidenceGap {
    /// The store returned rows without proving they cover the requested scope.
    ///
    /// Only the canonical store can close this: no other owner holds the
    /// scope-to-record closure, so it refuses the export outright.
    RequestedScopeClosureUnproven,
    /// The admitted schema does not carry the source erasure/purge ledger.
    ///
    /// Closed by [`EcxfSourceOwners::purge_ledger`], the privacy owner.
    SourcePurgeLedgerUnavailable,
    /// The store is not the `BlobStore` owner and read no sealed bytes.
    ///
    /// Closed by [`EcxfSourceOwners::sealed_blob`], the `BlobStore` owner.
    BlobStoreEvidenceUnavailable,
    /// Architecture and `NormativePair` identity receipts are sealed elsewhere.
    ///
    /// Closed by [`EcxfSourceOwners::source_identity`], the external identity
    /// owner.
    ExternalSourceIdentityEvidenceUnavailable,
    /// The store holds no durable source-side ECXF export receipt.
    ///
    /// Closed by [`EcxfSourceOwners::source_export_receipt`], the export-receipt
    /// owner.
    SourceExportReceiptUnavailable,
}

impl SourceEvidenceGap {
    /// The typed refusal this gap produces, or `None` when another owner in the
    /// bundle can close it.
    ///
    /// Only the scope closure is refused here, because it is the only gap whose
    /// evidence no other owner holds. It is refused as
    /// [`BackupError::InconsistentBoundary`] because an unproven scope closure
    /// is exactly the "mixing unrelated table moments into one 'backup'" that
    /// I05.10 forbids, and it is decided before any other owner is read so a
    /// hopeless export costs no blob or ledger work.
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
/// of *its own* view. The view this composition exports is complete only when
/// every declared gap is closed by a real owner value; see the module header.
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
    async fn sealed_blob(&self, locator: &BlobLocator) -> Result<SealedBlobRead, BackupError>;

    /// Reads the source privacy/purge ledger for the scope and fence of
    /// `capture`.
    ///
    /// The ledger is read for the snapshot, not for the request, so every entry
    /// is one the same consistency point can be held against. Entries that do
    /// not carry that fence are refused by the archive build, which checks each
    /// one against the export fence.
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
    /// # Errors
    ///
    /// Returns the identity owner's typed [`BackupError`] when either receipt is
    /// absent or unreadable. A missing receipt is never replaced by a digest
    /// this module could compute.
    async fn source_identity(&self) -> Result<SourceIdentity, BackupError>;

    /// Reads the reference of the source-side export receipt already issued for
    /// this export operation.
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
    /// The order is the order of the proof: the store's one consistent snapshot
    /// first, because an unprovable boundary must cost nothing else; then each
    /// remaining owner's evidence, so a gap the store declared is closed by a
    /// real owner or refuses the export. The result is returned only when every
    /// declared gap is closed.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::InconsistentBoundary`] when the store declares an
    /// unclosable scope closure, or reports itself non-`Complete` without naming
    /// a gap; [`BackupError::InvalidField`] when a sealed identity digest or the
    /// export-receipt reference is not the shape the manifest requires; and the
    /// owning component's own typed [`BackupError`] whenever a store, blob,
    /// privacy, identity, export-receipt or profile owner cannot answer. No
    /// failure is collapsed into a synthesised value.
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
        Ok(CoherentSourceExport {
            // Derived, never copied: `capture.completeness` describes what the
            // store alone could attest to, and the view exported here is complete
            // only because every gap it declared has now been closed by an owner
            // value this call actually holds.
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
/// available into one package. Every other declared gap is closable and is
/// closed by reading its owner, so it is not a refusal here.
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
