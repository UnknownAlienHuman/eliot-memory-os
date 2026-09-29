//! Owner-issued archive provenance for the read-only `backup.verify` route
//! (issue #2862, queue items I2, I3, I4, I5; I10 and I11 preserved).
//!
//! # WHAT THIS FILE IS
//!
//! One closed value — [`OwnerProvenanceEvidence`] — that holds what an ADMITTED
//! retained-archive owner issued for the archive a single `backup.verify`
//! operation is about, plus the two operations the route needs on it:
//!
//! - [`OwnerProvenanceEvidence::bind_into`], the EXHAUSTIVE CHECKED ADAPTER from
//!   the owner's recorded values into the three #2862 fields of
//!   `eliot_ors::BackupVerifyRequestIdentity` (`archive_handle`,
//!   `capture_receipt_digest`, `validity_attestation_digest`). Every field is
//!   mapped, nothing is defaulted, and nothing is dropped. I2 asks for the
//!   protocol request shape to be admitted rather than a parallel one; the
//!   mapping therefore goes from the EXISTING protocol owner types
//!   ([`BackupArtifactHandle`], [`BackupCaptureReceipt`],
//!   [`BackupArchiveValidityAttestation`]) with their fields reused verbatim.
//!   None of them is redefined, re-spelled or re-digested here.
//! - [`check_provenance_binding`], the PRE-VERDICT GATE (I4). It validates the
//!   ORIGINAL RECORDED values with the protocol's OWN `validate()` and then
//!   binds each of them to this operation's exact archive, class, fence and
//!   owner. A receipt for another archive, class, source, fence, owner or
//!   revision is refused here, BEFORE any verdict is produced, so a
//!   provenance-qualified verdict is structurally unreachable for it.
//!
//! # WHAT THE THREE FACTS STAY (I5)
//!
//! Structural validation, provenance validation and class qualification remain
//! three SEPARATE typed facts and this file never merges them. Concretely:
//!
//! - STRUCTURAL validation is the capture owner's own
//!   `CaptureEvidenceLevel::StructurallyValidCandidate` and the archive
//!   format's re-derived checks. This file neither reads nor changes it.
//! - PROVENANCE validation is the owner-issued handle + capture receipt chain,
//!   validated here.
//! - CLASS QUALIFICATION is the owner's `class_ceiling`. This file never reads
//!   it, never raises it, and never substitutes a digest for it. I5.13 keeps
//!   "Backup existence is not recovery proof", and a ceiling is raised by an
//!   owner-issued attestation alone — never by matching text or a matching
//!   digest. A recorded digest in the request identity is a REFERENCE that
//!   makes a changed receipt an I5.27 conflict; it is not evidence, and it is
//!   not a ceiling.
//!
//! # THE HONEST ANSWER ON THIS TREE (I3)
//!
//! There is NO admitted owner that can resolve a
//! [`BackupArtifactHandle`] for a backup archive, and this file does not invent
//! one. Measured on this base:
//!
//! 1. `BackupArtifactHandle` requires an `eliot_contracts::ArtifactId`, and the
//!    ECXF manifest (`eliot_backup::EcxfManifest`) carries no artifact identity
//!    at all — only `backup_id`, `source_adapter` and `export_fence_sha256`.
//!    There is no value anywhere in the repository that could be that
//!    `artifact_id` for a whole archive.
//! 2. `backup_capture_ports::PublicationPort` — the admitted artifact/publication
//!    seam — has NO production `impl`. The only implementation is `MemPublisher`
//!    inside `bins/eliot-kernel/tests/backup_capture.rs`.
//! 3. `eliot-blob-api::backup_io` DOES own real retained-artifact evidence
//!    (`BlobBackupFence`, `SealedBlobCaptureRecord`, `BlobBackupScope`,
//!    `BlobBackupCompletionReceipt`, `SealedBlobRead`), but that owner retains
//!    PER-MEMBER SEALED BLOB ENVELOPES under a destination residency scope, not
//!    a backup archive, and none of its receipts carries an `ArtifactId`, a
//!    `ContractIdentity` or a class. It is therefore not a backup-archive
//!    retention owner and is not bound here.
//! 4. `bins/eliot-kernel/src/backup_owner_clients.rs` binds the two real owner
//!    CHANNELS, and its Watchdog accepted table carries `VerifyArchive`, but the
//!    Watchdog channel's authenticated protocol role is `BackupRole::SpoolOwner`
//!    (read `OwnerRole::protocol_role`), and `SpoolOwner`'s closed capability
//!    projection does not carry `BackupCapability::VerifyArchive`. So that
//!    channel cannot carry a verify effect, and in particular
//!    `BackupRole::Verifier` — the only role whose
//!    `BackupArchiveValidityAttestation::validate_against` accepts — is bound to
//!    no channel on this product.
//!
//! Consequently the production answer is
//! [`OwnerProvenanceEvidence::unissued`]: the three #2862 identity fields stay
//! `None`, no receipt is validated because none exists, and no attestation is
//! produced because no verifier session issues one. `None` there is the OWNER'S
//! OWN ANSWER — the same absence `capture_receipt` and `target_compatibility`
//! already record on this row — and never a placeholder, a synthesised digest
//! or an empty-string stand-in.
//!
//! # WHAT IS DELIBERATELY NOT HERE
//!
//! - No `BackupArchiveVerification` is constructed. Building one needs a
//!   protocol `BackupRole`, a protocol `RequestIdentity` and a
//!   `BackupAdmissionRef` (an `AuthorityBinding`, a `WorkScopeBinding` and an
//!   owner-issued `ReceiptId`). None of those exists on the verify frame, and
//!   inventing any of them would fabricate authority. I2's "admit the protocol
//!   request" is therefore implemented as the adapter INTO the existing
//!   `BackupVerifyRequestIdentity` profile, which is the request identity this
//!   route really holds.
//! - `BackupCaptureReceipt::validate_against` and
//!   `BackupArchiveValidityAttestation::validate_against` are NOT called: both
//!   take a `&BackupRequestIdentity` and an AUTHENTICATED `BackupRole`, and
//!   this frame holds neither. The relations those two functions would check
//!   against a request identity (archive id, archive digest, class, fence) are
//!   checked here against the capture owner's OWN recorded archive facts
//!   instead, which is the same relation stated against values this route
//!   really holds. The authenticated-ROLE check is the one term left open, and
//!   it is left open by naming it, not by assuming it.
//! - `successor_of` is untouched. It stays caller-presented, stays a POINTER
//!   that only selects which durable row is read, and stays at its current
//!   fail-closed / lower-ceiling behaviour. Nothing here grants cross-principal
//!   read authority from matching text digests (I10).
//! - This file writes nothing. Verification's only durable effect remains the
//!   single request/result/receipt row staged by the route (I11): no restore,
//!   no decryption proof, no key-availability proof, no activation, no epoch
//!   change, no import, no cutover, no Product-readiness transition.
//!
//! Capability cell: Kernel read-only backup verification provenance (owner
//! evidence binding and pre-verdict refusal only). Forbidden authority: no
//! retention or publication effect, no capture, no restore, no cutover, no
//! readiness transition, no second retention/lease/digest scheme.

use eliot_backup::BackupClass;
use eliot_ors::{BackupVerifyArchiveHandleRef, BackupVerifyRequestIdentity, OrsError};
use eliot_protocol::backup::{
    BackupArchiveValidityAttestation, BackupArtifactHandle, BackupCaptureReceipt, BackupClassWire,
    BackupError,
};

use super::backup_capture::{CaptureReport, archived_state_fence_digest};

/// Field path the retained archive handle is validated under on this route.
///
/// `BackupArtifactHandle::validate` takes the caller's field path so a refusal
/// names WHERE the handle came from rather than the type that happened to
/// reject it. One constant, one call site per validation, so the path cannot be
/// re-spelled between the gate and the adapter.
const ARCHIVE_HANDLE_FIELD: &str = "backup_verify.archive_handle";
/// Field path the capture receipt is validated under on this route.
const CAPTURE_RECEIPT_FIELD: &str = "backup_verify.capture_receipt";
/// Field path the archive validity attestation is validated under on this route.
const VALIDITY_ATTESTATION_FIELD: &str = "backup_verify.validity_attestation";

/// Typed fail-closed refusals from the archive-provenance chain (issue #2862).
///
/// Every variant refuses. None fabricates success, none substitutes a digest
/// for a validation, and none is collapsed into a free string: the typed
/// protocol and store sources are carried as typed values so the route renders
/// them exactly once, at the existing dispatch seam that already takes `&str`.
///
/// A receipt that does not belong to this operation's archive is
/// [`Self::NotBound`], and it is returned BEFORE any verdict exists — see
/// [`check_provenance_binding`].
///
/// `Debug` only, deliberately: `OrsError` is neither `Clone` nor comparable, so
/// deriving more would mean dropping the typed store refusal this enum exists to
/// preserve.
#[derive(Debug)]
pub(crate) enum BackupProvenanceError {
    /// An owner-issued value is not bound to the archive, class, fence, owner
    /// or bytes this verify operation is about. `field` is the stable protocol
    /// field path that diverged.
    NotBound {
        /// Stable field path that diverged from this operation's archive.
        field: &'static str,
    },
    /// The protocol's own `validate()` refused an owner-issued value. The typed
    /// refusal is preserved: it is never re-spelled as a string here, and a
    /// recomputed digest is never substituted for validating the value the
    /// owner actually recorded.
    OwnerValueInvalid {
        /// Stable field path the protocol refused.
        field: &'static str,
        /// The protocol's own typed refusal, preserved verbatim.
        source: BackupError,
    },
    /// The ORS store's own validator refused the durable handle projection
    /// this adapter produced. Carried typed so the adapter never projects a
    /// value the store would fail to read back.
    ProjectionRefused {
        /// Stable field path the ORS store refused.
        field: &'static str,
        /// The store's own typed refusal, preserved verbatim.
        source: OrsError,
    },
    /// The archive's own recorded `StateFence` value could not be re-encoded,
    /// so the fence relation between an owner-issued value and the archive
    /// could not be decided. Fails closed: an undecidable relation is a
    /// refusal, never a match.
    ArchiveFenceUndecidable,
}

impl BackupProvenanceError {
    /// Stable field path this refusal names.
    #[must_use]
    pub(crate) const fn field(&self) -> &'static str {
        match self {
            Self::NotBound { field }
            | Self::OwnerValueInvalid { field, .. }
            | Self::ProjectionRefused { field, .. } => field,
            Self::ArchiveFenceUndecidable => CAPTURE_RECEIPT_FIELD,
        }
    }

    /// Stable bounded reason this refusal names.
    ///
    /// The only place a typed refusal becomes text, and it is reached solely
    /// from the route's existing `invalid_reply` seam, which already takes a
    /// reason string. `NotBound` states the one relation that failed without
    /// naming any archive content, and the typed protocol refusals keep the
    /// protocol's own bounded vocabulary.
    #[must_use]
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::NotBound { .. } => {
                "owner-issued evidence is not bound to this verification's archive".to_owned()
            }
            Self::OwnerValueInvalid { field, source } => format!("{field}: {source}"),
            Self::ProjectionRefused { field, source } => format!("{field}: {source}"),
            Self::ArchiveFenceUndecidable => {
                "the archive's own recorded state fence could not be re-encoded".to_owned()
            }
        }
    }
}

/// The owner-issued provenance evidence held for EXACTLY ONE `backup.verify`
/// operation (issue #2862, item I3).
///
/// The three values it carries are the EXISTING protocol owner types, reused
/// verbatim: [`BackupArtifactHandle`] for the retained archive,
/// [`BackupCaptureReceipt`] for the capture, and
/// [`BackupArchiveValidityAttestation`] for the verifier's validity verdict. No
/// field of any of them is redefined, renamed, re-spelled or re-digested here,
/// and no second retention, lease or digest scheme is introduced. What this
/// value adds is the BOUND: which one operation and which one archive these
/// three belong to, which is exactly the relation item I4 requires and which no
/// individual owner value carries on its own.
///
/// Every field is `Option`, and every `None` is the OWNER'S OWN ANSWER on a
/// path where the owner issued nothing. That is the same reading
/// `eliot_ors::BackupVerifyRequestIdentity` already gives its three #2862
/// fields, and it is deliberately not a placeholder: see
/// [`Self::unissued`] for what is absent today and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnerProvenanceEvidence {
    /// The retained immutable artifact handle the admitted archive owner
    /// resolved for the exact bytes this operation is about. A path, a URL or
    /// an inline `bundle_hex` is not a handle and is never admitted as one.
    pub(crate) archive_handle: Option<BackupArtifactHandle>,
    /// The receipt the `BackupRole::CaptureOwner` session issued for THAT
    /// handle, in the protocol's own `BackupCaptureReceipt` shape. A receipt
    /// for another archive, class, source, fence, owner or revision is refused
    /// by [`check_provenance_binding`] before any verdict.
    pub(crate) capture_receipt: Option<BackupCaptureReceipt>,
    /// The validity attestation the `BackupRole::Verifier` session issued for
    /// THAT archive under the exact observed fence. It is the ONLY thing that
    /// may raise a proof ceiling on this route, and it is never synthesised
    /// here.
    pub(crate) validity_attestation: Option<BackupArchiveValidityAttestation>,
}

impl OwnerProvenanceEvidence {
    /// The owner's own answer on a path where no admitted owner issued
    /// provenance evidence for the presented archive (issue #2862, item I3).
    ///
    /// This is a TYPED REFUSAL, not an empty default and not a stand-in. On
    /// this tree it is also the production answer, and the measured reasons are
    /// enumerated in the module docs: a `BackupArtifactHandle` needs an
    /// `ArtifactId` that no backup-archive owner issues, `PublicationPort` has
    /// no production implementation, `eliot-blob-api::backup_io` retains
    /// per-member sealed blob envelopes rather than a backup archive, and
    /// `BackupRole::Verifier` is bound to no owner channel.
    ///
    /// What it means concretely: the presented archive is caller-presented
    /// inline bytes and nothing more. The route therefore records all three
    /// #2862 identity fields as absent, validates no receipt because none
    /// exists, issues no attestation because no verifier issues one, and keeps
    /// answering at the capture owner's own
    /// `StructurallyValidCandidate` level with its class ceiling unchanged.
    #[must_use]
    pub(crate) const fn unissued() -> Self {
        Self {
            archive_handle: None,
            capture_receipt: None,
            validity_attestation: None,
        }
    }

    /// Binds this owner evidence into the #2862 fields of the accepted ORS
    /// request identity (issue #2862, item I2) — the exhaustive checked adapter.
    ///
    /// Exactly three fields are written, one per owner-issued commitment, and
    /// the mapping is total over the evidence: a present handle becomes the
    /// durable projection of that recorded handle, and an absent one becomes
    /// `None`; a present receipt becomes the RECORDED `receipt_digest` the
    /// owner wrote on it, and an absent one becomes `None`; a present
    /// attestation becomes the RECORDED `attestation_digest`, and an absent one
    /// becomes `None`. There is no `Default`, no `..rest`, no silently dropped
    /// field and no field invented here, so a field added to the ORS identity is
    /// a compile error at this constructor rather than a silent omission
    /// (I5.27: a field affecting authority, scope, ordering, privacy or effect
    /// cannot be omitted or defaulted silently).
    ///
    /// The two digests are the owner's OWN RECORDED strings, read off the
    /// validated owner value. They are NOT recomputed here and never stand in
    /// for validating what the owner recorded: [`check_provenance_binding`]
    /// runs first and calls each value's own `validate()`, which is what proves
    /// the recorded digest is the digest of that recorded value. I5.27's
    /// `canonical_request_hash` then binds all three fields, so a different
    /// handle, receipt or attestation under one operation identity is the
    /// identity conflict acceptance clause 3 names, not a second answer.
    ///
    /// The projected [`BackupVerifyArchiveHandleRef`] is shape-checked through
    /// its own ORS `validate()` before it is written, so the adapter never
    /// projects a value the store would refuse to read back.
    pub(crate) fn bind_into(
        &self,
        identity: &mut BackupVerifyRequestIdentity,
    ) -> Result<(), BackupProvenanceError> {
        identity.archive_handle = match &self.archive_handle {
            Some(handle) => Some(BackupVerifyArchiveHandleRef {
                artifact_id: handle.artifact_id.as_str().to_owned(),
                owner_contract: handle.contract.name.as_str().to_owned(),
                source_revision: handle.source_revision.clone(),
                content_sha256: handle.content_sha256.clone(),
                byte_length: handle.byte_length,
            }),
            None => None,
        };
        identity.capture_receipt_digest = self
            .capture_receipt
            .as_ref()
            .map(|receipt| receipt.receipt_digest.clone());
        identity.validity_attestation_digest = self
            .validity_attestation
            .as_ref()
            .map(|attestation| attestation.attestation_digest.clone());
        if let Some(handle) = &identity.archive_handle {
            handle
                .validate()
                .map_err(|source| BackupProvenanceError::ProjectionRefused {
                    field: ARCHIVE_HANDLE_FIELD,
                    source,
                })?;
        }
        Ok(())
    }
}

/// Binds every owner-issued value in one provenance answer to the archive this
/// `backup.verify` operation is about, and refuses before any verdict
/// (issue #2862, item I4).
///
/// `report` is the capture owner's OWN record of the decoded archive, and
/// `presented_bytes` is the exact byte sequence the caller presented and the
/// owner re-decoded. Both are owner/admission facts, never caller spelling.
///
/// The ORDER is the point. Every binding check runs here, before the route
/// computes a request identity, projects an answer, or stages its single
/// durable row, so a mismatched receipt is structurally unable to reach a
/// provenance-qualified verdict: the route calls this first and turns a typed
/// refusal into the same `invalid_reply` an archive-invalid frame already gets,
/// which is a structural refusal carrying no ceiling and no class claim.
///
/// Each present owner value is validated as the ORIGINAL RECORDED value through
/// the protocol's OWN `validate()` — never a recomputed copy validated against
/// itself, and never a digest recomputed to substitute for the validation.
/// An absent value contributes no relation and no verdict: it is the owner's own
/// answer, and this function then says nothing about provenance either way.
///
/// The exact relations checked, and the owner-issued fact each is checked
/// against:
///
/// - handle → bytes: `content_sha256` equals the archive digest the capture
///   owner recomputed from the decoded bundle, and `byte_length` equals the
///   presented byte length. A handle for other content, or for other bytes of
///   the same content, refuses.
/// - handle → owner: the handle's owner `ContractId` equals the capture/owner
///   contract the archive DECLARES about itself in its producing
///   `source_adapter`.
///   ASSUMPTION: a retained-archive owner records its contract name in the same
///   text the archive declares as its `source_adapter`. Nothing in the
///   repository proves that today, because no such owner exists; if a future
///   owner records a different spelling, this comparison fails closed for every
///   receipt, which is the safe direction, and this line is the single place
///   that binding is stated.
/// - receipt → archive: `archive_id` equals the archive identity the owner
///   reported. A receipt for another archive refuses.
/// - receipt → class: the protocol's own
///   [`BackupClassWire::validate_transition`] compares the class the owner
///   evidenced from the decoded archive with the class the receipt attests, so
///   any change, downgrade or upgrade refuses. I5.13: a degraded or scope class
///   can never satisfy a `full_recovery` claim by being relabelled.
/// - receipt → fence: the receipt's `StateFence` re-encodes to the same
///   complete-fence digest the owner computed from the fence it decoded out of
///   THIS archive. A receipt observed under another fence refuses.
/// - receipt → owner: the receipt's `attesting_owner` equals the owner contract
///   the archive declares. A receipt issued by another owner refuses.
/// - attestation → archive/fence: the verifier's attested `archive_id`,
///   `archive_digest` and `StateFence` equal the same three owner facts. An
///   attestation about other content, or observed under another fence, refuses.
///
/// The `source_revision` term of I4 is the one I4 term with no owner-issued
/// counterpart on this path: nothing the capture owner reports names an owner
/// revision of a retained artifact, and inventing one would be a free string.
/// It is bound structurally instead, by `BackupArtifactHandle::validate`'s bound
/// plus the fact that the handle is DIGEST-BOUND into the I5.27 request hash —
/// so a different `source_revision` under one operation identity is an identity
/// conflict rather than a silently accepted answer.
pub(crate) fn check_provenance_binding(
    evidence: &OwnerProvenanceEvidence,
    report: &CaptureReport,
    presented_bytes: &[u8],
) -> Result<(), BackupProvenanceError> {
    if let Some(handle) = &evidence.archive_handle {
        handle
            .validate(ARCHIVE_HANDLE_FIELD)
            .map_err(|source| BackupProvenanceError::OwnerValueInvalid {
                field: ARCHIVE_HANDLE_FIELD,
                source,
            })?;
        if handle.content_sha256 != report.archive_sha256 {
            return Err(BackupProvenanceError::NotBound {
                field: "backup_verify.archive_handle.content_sha256",
            });
        }
        if handle.byte_length != presented_bytes.len() as u64 {
            return Err(BackupProvenanceError::NotBound {
                field: "backup_verify.archive_handle.byte_length",
            });
        }
        if handle.contract.name.as_str() != report.owner_contract {
            return Err(BackupProvenanceError::NotBound {
                field: "backup_verify.archive_handle.contract",
            });
        }
    }
    if let Some(receipt) = &evidence.capture_receipt {
        receipt
            .validate()
            .map_err(|source| BackupProvenanceError::OwnerValueInvalid {
                field: CAPTURE_RECEIPT_FIELD,
                source,
            })?;
        if receipt.archive_id != report.backup_id {
            return Err(BackupProvenanceError::NotBound {
                field: "backup_verify.capture_receipt.archive_id",
            });
        }
        BackupClassWire::validate_transition(wire_class(report.class), receipt.class)
            .map_err(|source| BackupProvenanceError::OwnerValueInvalid {
                field: "backup_verify.capture_receipt.class",
                source,
            })?;
        if archived_state_fence_digest(&receipt.fence)
            .map_err(|_| BackupProvenanceError::ArchiveFenceUndecidable)?
            != report.archived_state_fence_digest
        {
            return Err(BackupProvenanceError::NotBound {
                field: "backup_verify.capture_receipt.fence",
            });
        }
        if receipt.attesting_owner != report.owner_contract {
            return Err(BackupProvenanceError::NotBound {
                field: "backup_verify.capture_receipt.attesting_owner",
            });
        }
    }
    if let Some(attestation) = &evidence.validity_attestation {
        attestation
            .validate()
            .map_err(|source| BackupProvenanceError::OwnerValueInvalid {
                field: VALIDITY_ATTESTATION_FIELD,
                source,
            })?;
        if attestation.archive_id != report.backup_id
            || attestation.archive_digest != report.archive_sha256
        {
            return Err(BackupProvenanceError::NotBound {
                field: "backup_verify.validity_attestation.archive",
            });
        }
        if archived_state_fence_digest(&attestation.fence)
            .map_err(|_| BackupProvenanceError::ArchiveFenceUndecidable)?
            != report.archived_state_fence_digest
        {
            return Err(BackupProvenanceError::NotBound {
                field: "backup_verify.validity_attestation.fence",
            });
        }
    }
    Ok(())
}

/// Projects the capture owner's typed class onto the protocol's closed wire
/// class, exhaustively over all three variants.
///
/// This is the ONE place the two closed class spellings meet: the route's
/// operator spelling is `backup_capture::class_name` (`full_recovery` /
/// `canonical_only_degraded` / `scope_export`), and the protocol's is
/// `BackupClassWire` (`SCREAMING_SNAKE_CASE`). Reading the protocol's own serde
/// spelling instead would be a string round-trip, and re-deriving the class
/// from the archive would be a second classification. A class the owner did not
/// report cannot occur here: `BackupClass` is a closed three-variant enum, so
/// this match is total by construction and cannot fall through to a default.
///
/// ASSUMPTION: this inverse belongs beside `backup_capture::class_name` rather
/// than here, because both spellings are the capture owner's vocabulary. It is
/// kept in this file only because this lane does not own `backup_capture.rs`;
/// it should move to the owner when that file is next owned, and there is then
/// exactly one place where the two spellings are related.
const fn wire_class(class: BackupClass) -> BackupClassWire {
    match class {
        BackupClass::FullRecovery => BackupClassWire::FullRecovery,
        BackupClass::CanonicalOnlyDegraded => BackupClassWire::CanonicalOnlyDegraded,
        BackupClass::ScopeExport => BackupClassWire::ScopeExport,
    }
}
