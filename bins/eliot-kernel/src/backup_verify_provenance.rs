//! Owner-issued archive provenance for the read-only `backup.verify` route
//! (issue #2862, queue items I2, I3, I4, I5; I10 and I11 preserved).
//!
//! # WHAT THIS FILE IS
//!
//! One closed value — [`OwnerProvenanceEvidence`] — that holds what an ADMITTED
//! retained-archive owner issued for the archive a single `backup.verify`
//! operation is about, plus the two operations the route needs on it:
//!
//! - [`OwnerProvenanceEvidence::bind_into`] and [`bind_protocol_request`], the
//!   EXHAUSTIVE CHECKED ADAPTERS from the owner's recorded values and from the
//!   EXISTING protocol request into the #2862 fields of
//!   `eliot_ors::BackupVerifyRequestIdentity` (`archive_handle`,
//!   `capture_receipt_digest`, `validity_attestation_digest`) and the whole
//!   accepted request identity. Every field of the protocol request is accounted
//!   for and an unknown field is refused; no field of it is redefined,
//!   re-spelled or re-digested here. [`BackupVerifyAdmittedRequest`] is the ONE
//!   closed wrapper the production payload of the retained-archive arm is decoded
//!   into, and it embeds `BackupArchiveVerification` verbatim.
//! - [`check_provenance_binding`], the PRE-VERDICT GATE (I4). It validates the
//!   ORIGINAL RECORDED values with the protocol's OWN `validate()` — including
//!   `BackupCaptureReceipt::validate_against` and
//!   `BackupArchiveValidityAttestation::validate_against`, with the
//!   authenticated owner roles as the protocol requires them, passed separately —
//!   and then binds each of them to this operation's exact archive, class, fence
//!   and owner. A receipt for another archive, class, source, fence, owner or
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
//! 2. `backup_capture_ports::PublicationPort` — the admitted
//!    artifact/publication seam — DOES have a production implementation, and it
//!    is stated here precisely because an earlier version of this file claimed
//!    otherwise and was wrong: `eliot_blob::BlobArchivePublicationOwner`
//!    (`crates/storage/eliot-blob/src/publication_owner.rs`,
//!    `impl PublicationPort for BlobArchivePublicationOwner`).
//!    But that implementation cannot resolve an ARCHIVE HANDLE, and the reason is
//!    the trait's own shape, not a missing file: `PublicationPort` has exactly
//!    two methods, `publish_once(operation_id, idempotency_key, bytes)` and
//!    `reconcile(operation_id)`. Both are WRITE-SIDE or BY-OPERATION queries.
//!    Neither accepts a `BackupArtifactHandle`, neither returns bytes, and
//!    neither returns an `ArtifactId`: the only thing either can hand back is a
//!    `PublicationReceipt { operation_id, archive_sha256, durable }`. So there is
//!    no argument this route could pass a handle to and no value it could read
//!    bytes out of. Binding it is a second, independent blocker — it needs an
//!    `eliot_blob::BlobStoreService`, and every construction of that type in the
//!    repository (`BlobStoreService::new`, `BlobStoreService::new_with_owner` in
//!    `crates/storage/eliot-blob/src/lib.rs`) sits inside the `#[cfg(test)] mod
//!    tests` that begins at line 5173 of that file, so no production code
//!    constructs one — but the trait shape alone already decides it.
//! 3. `eliot-blob-api::backup_io` DOES own real retained-artifact evidence
//!    (`BlobBackupFence`, `SealedBlobCaptureRecord`, `BlobBackupScope`,
//!    `BlobBackupCompletionReceipt`, `SealedBlobRead`), and its one read path,
//!    `BlobReadRequest` → `read_sealed` → `SealedBlobRead`, is a genuine
//!    owner-issued-bytes read. But that owner retains PER-MEMBER SEALED BLOB
//!    ENVELOPES under a destination residency scope, not a backup archive, and
//!    none of its receipts carries an `ArtifactId`, a `ContractIdentity` or a
//!    class. Its own read request is addressed by `BlobLocator` plus
//!    `expected_metadata_sha256` and `expected_ready_receipt_id` — a locator, not
//!    a `BackupArtifactHandle`. It is therefore not a backup-archive retention
//!    owner and is not bound here.
//! 4. `bins/eliot-kernel/src/backup_owner_clients.rs` binds the two real owner
//!    CHANNELS, and its Watchdog accepted table carries `VerifyArchive`
//!    (`WATCHDOG_SUPPORTED_OPS`), but that is a RECOGNITION set and the
//!    executable set is narrower: `WATCHDOG_EXECUTABLE_CONTOURS` is
//!    `[ReadSnapshotPage, ReconcileRestore]`, so `VerifyArchive` is registered
//!    precisely so an absent owner method answers with an explicit typed
//!    refusal instead of vanishing. The Watchdog's own endpoint says the same
//!    thing about itself in `bins/eliot-watchdog/src/backup_control.rs`: it
//!    "holds no archive verifier and never interprets archive bytes". Separately,
//!    `BackupRole::Verifier` — the only role whose
//!    `BackupArchiveValidityAttestation::validate_against` accepts
//!    (`eliot-protocol/src/backup.rs`) — is bound to no channel: the closed
//!    `OwnerRole` enum carries only `InstallationAuthority` (Host) and
//!    `CaptureOwner`/`SpoolOwner` (Watchdog), and `Verifier` appears in no
//!    `protocol_roles()` table. So no channel on this product can issue a
//!    validity attestation at all. The Watchdog DOES hold
//!    `BackupRole::CaptureOwner`, so a capture receipt is role-plausible on its
//!    own; it is still unreachable, for two independent reasons:
//!    `RequestCapture` is outside that owner's registered operation table, and
//!    the verify route contacts no owner client at all.
//!
//! Consequently the production answer is
//! [`OwnerProvenanceEvidence::unissued`]: the three #2862 identity fields stay
//! `None`, no receipt is validated because none exists, and no attestation is
//! produced because no verifier session issues one. `None` there is the OWNER'S
//! OWN ANSWER — the same absence `capture_receipt` and `target_compatibility`
//! already record on this row — and never a placeholder, a synthesised digest
//! or an empty-string stand-in.
//!
//! # WHAT THAT MEANS FOR ITEM A1, STATED PLAINLY
//!
//! A1 asks that a retained archive handle with a matching owner-issued capture
//! receipt verifies through the existing ORS operation and returns a typed
//! validity attestation. On this tree that does NOT happen, and this delivery
//! does not make it happen. [`bind_protocol_request`] and
//! [`check_provenance_binding`] — including their genuine calls to
//! `BackupCaptureReceipt::validate_against` and
//! `BackupArchiveValidityAttestation::validate_against` — are unreachable from
//! a PASSING frame, because the arm that would carry them is refused before it
//! can reach the capture owner. So A1 stays PARTIAL, and the honest delivery for
//! it is that refusal being VISIBLE and correctly typed, not a green route.
//!
//! What a caller actually sees for the protocol arm is a `refused` /
//! `plan_gap` answer naming `backup-retained-archive-owner (#2862)`
//! (`request_dispatch.rs::BACKUP_VERIFY_MISSING_OWNER`), produced by
//! `request_dispatch.rs::admit_verify_bundle` and rendered by
//! `request_dispatch.rs::VerifyAdmissionRefusal::into_reply`. It is deliberately
//! NOT an `invalid` field: the caller's protocol request passed the protocol's
//! own `validate()`, so reporting a field would blame the caller for an owner
//! that is absent. The operator surface already projects exactly this shape
//! (`eliot_cli::backup::backup_verify`'s `BACKUP_STATE_REFUSED` arm reads `code`,
//! `missing_owner` and `reason`), so the refusal uses the vocabulary that
//! already exists instead of inventing one.
//!
//! # WHAT IS DELIBERATELY NOT HERE
//!
//! - No `BackupArchiveVerification` is CONSTRUCTED here, and this route is still
//!   the READER of the protocol request rather than its author: the frame admits
//!   the caller's value and the protocol's own `validate()` decides whether it is
//!   well-formed. Building one here would need a protocol `BackupRole`, a
//!   protocol `RequestIdentity`, an archive-side `ContractIdentity` and the
//!   archive's `schema_digest`/`build_digest`/`snapshot_digest`/
//!   `member_digest`/`dest_installation`, and none of those has an owner value on
//!   this product — the ECXF manifest carries only `backup_id`, `class`,
//!   `source_adapter`, `schema_generation` and `export_fence_sha256`
//!   (`crates/storage/eliot-backup/src/lib.rs:543`), and `BackupArtifactHandle`
//!   needs an `ArtifactId` no backup-archive owner issues. Filling them in would
//!   fabricate authority, so they are not filled in.
//!
//!   ONE PART OF THAT LIST IS NO LONGER TRUE, and the correction belongs here
//!   rather than in the new file: the owner-issued `ReceiptId` in
//!   `BackupAdmissionRef` DOES now have a producer. This Kernel front door is the
//!   authority boundary that admits this route
//!   (`request_dispatch::admit_backup_caller`), and
//!   `elipt_receipts::ReceiptEnvelope::issue` is the repository's one `ReceiptId`
//!   issuer, so [`super::backup_verify_admission`] issues the admission receipt
//!   for a presented request from the live module scope, fence and authenticated
//!   principal, and `request_dispatch::check_admission_binding` requires the
//!   presented reference to BE that receipt. Before that, `admission_receipt` was
//!   free text any caller could satisfy, which is the same "parallel shape with
//!   no owner behind it" defect one level below the payload.
//!
//!   I2 is therefore implemented in the direction the issue names: the production
//!   payload of the retained-archive arm IS the existing
//!   `BackupArchiveVerification`, admitted verbatim through one closed wrapper
//!   ([`BackupVerifyAdmittedRequest`]), its admission reference bound to this
//!   boundary's own issued receipt, and mapped into the existing
//!   `BackupVerifyRequestIdentity` by the exhaustive checked adapter
//!   [`bind_protocol_request`].
//! - No `BackupRole` is invented. The protocol states as its own invariant that
//!   the authenticated role always travels as a separate function argument and
//!   never as a payload claim, so the two role-bearing values here —
//!   [`CaptureOwnerAttestation`] and [`VerifierAttestation`] — are SEPARATE
//!   values that exist only to be handed to the protocol's own
//!   `validate_against` calls as those separate arguments. They are supplied by
//!   an owner channel, and the frame holds none: which is why
//!   `OwnerProvenanceEvidence::unissued` is the production answer below and why
//!   the retained-archive arm fails closed today rather than assuming a role.
//!   This file's measured reasons for that absence are unchanged; what changed is
//!   that the receipt and attestation validators are now genuinely CALLED on the
//!   path where an owner does supply them, instead of a hand-written subset of
//!   their relations being spelled out beside them.
//! - `successor_of` is untouched in meaning. It stays caller-presented, stays a
//!   POINTER that only selects which durable row is read, and stays at its
//!   current fail-closed / lower-ceiling behaviour. Only its owning TYPE moved
//!   here, so the two arms of the admitted payload are described by one closed
//!   type each. Nothing here grants cross-principal read authority from matching
//!   text digests (I10).
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
use eliot_contracts::StateFence;
use eliot_ors::{BackupVerifyArchiveHandleRef, BackupVerifyRequestIdentity, OrsError};
use eliot_protocol::backup::{
    BackupArchiveValidityAttestation, BackupArchiveVerification, BackupArtifactHandle,
    BackupCaptureReceipt, BackupCaptureRequest, BackupClassWire, BackupError, BackupOperationKind,
    BackupRequestIdentity, BackupRole,
};
use serde::{Deserialize, Serialize};

use super::backup_capture::{CaptureReport, archived_state_fence_digest, class_name};

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
/// Field path the admitted protocol verification request is validated under.
const ARCHIVE_VERIFICATION_FIELD: &str = "backup_verify.verification";
/// Field path the owner-issued capture operation is validated under.
const CAPTURE_OPERATION_FIELD: &str = "backup_verify.capture_operation";

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
    /// The presented admission reference is not the one THIS admission boundary
    /// issues for this request under this admitted session (issue #2862, item
    /// I2).
    ///
    /// It is a separate variant rather than a fourth use of [`Self::NotBound`]
    /// because the bounded reasons are different facts: `NotBound` says owner
    /// evidence does not name THIS verification's archive, and this one says the
    /// authority-bearing admission receipt is not a receipt this boundary
    /// issued. Collapsing them would put a sentence on the wire that is wrong
    /// for one of the two.
    AdmissionNotBound {
        /// Stable field path of the admission reference that diverged.
        field: &'static str,
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
            | Self::ProjectionRefused { field, .. }
            | Self::AdmissionNotBound { field } => field,
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
            Self::AdmissionNotBound { .. } => {
                "the admission receipt is not one this boundary issued for this request".to_owned()
            }
            Self::OwnerValueInvalid { field, source } => format!("{field}: {source}"),
            Self::ProjectionRefused { field, source } => format!("{field}: {source}"),
            Self::ArchiveFenceUndecidable => {
                "the archive's own recorded state fence could not be re-encoded".to_owned()
            }
        }
    }
}

/// The ONE admitted `backup.verify` request for the retained-archive arm
/// (issue #2862, item I2).
///
/// # WHY THIS EXISTS AND WHAT IT IS NOT
///
/// I2 asks for the EXISTING protocol request to be admitted rather than a
/// parallel shape, and permits "one closed wrapper that embeds it and the
/// current front-door/session facts without redefining its fields". This is
/// that wrapper, and it is deliberately as thin as the permission allows:
///
/// - `verification` is [`BackupArchiveVerification`] BY VALUE. Not a copy of
///   its shape, not a re-spelling, not a projection with renamed members. Its
///   fields are read off the value the protocol owner defined, and the protocol
///   owner's own `validate()` is the only thing that decides whether it is
///   well-formed.
/// - `successor_of` is the current front-door succession pointer, moved here
///   from the route so the two arms of the admitted payload are described by
///   ONE type each rather than by two hand-written key lists that could drift.
///   It is a POINTER that selects which durable row is read; it is not part of
///   the request and is not digested into it.
///
/// There is no third member and no `Default`: a frame that presents a protocol
/// request presents all of it, and a frame that presents only inline bytes is
/// the OTHER arm of the same closed admission and never reaches this type.
///
/// # CLOSED, NOT PERMISSIVE
///
/// `deny_unknown_fields` here, and on every embedded type, is what makes the
/// admission closed. An unknown key at this level is refused; an unknown key
/// inside `verification` is refused by the protocol type's own
/// `deny_unknown_fields`; an unknown key inside the succession pointer is
/// refused by its own. Nothing is defaulted and nothing is dropped: a
/// `Verification` absent here is a shape refusal at the route's existing
/// admission seam, not a `None` this type tolerates.
///
/// # WHY THE INLINE ARM STILL EXISTS, AND WHY BYTES STAY BESIDE THE HANDLE
///
/// Acceptance requires that a self-consistent inline bundle WITHOUT retained
/// publication or capture evidence stays a durably replayable structural
/// candidate, and the operator surface still presents exactly that. So the
/// payload is a CLOSED TWO-ARM UNION keyed on whether the protocol request is
/// present: `{bundle_hex}` / `{bundle_hex, successor_of}` is the inline arm and
/// never reaches this type, and `{bundle_hex, verification}` /
/// `{bundle_hex, successor_of, verification}` is this one.
///
/// The bytes stay beside the handle rather than being resolved through an owner,
/// and that is the honest arrangement rather than a shortcut. `bundle_hex` is
/// read at the route's EXISTING bounded-lowercase-hex seam with its existing
/// bound, so nothing about the wire spelling changes; and a frame that presents
/// bytes beside a handle gains nothing it did not already have, because the
/// adapter requires the request's `handle.content_sha256` and
/// `handle.byte_length` to BE exactly the presented archive and the pre-verdict
/// gate then requires the OWNER to have issued that same handle together with
/// the capture operation, the receipt and both authenticated roles. A request
/// whose handle is for other content, other bytes, another archive identity,
/// another class, another source, another owner contract or another authority
/// fence refuses, and a request with no owner evidence behind it refuses too — so
/// a handle can never be decorative and caller bytes can never stand in for one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupVerifyAdmittedRequest {
    /// The EXISTING protocol archive-verification request, embedded verbatim.
    /// Required: this type exists to admit it, and a frame that does not
    /// present one is the inline arm instead of a partial instance of this one.
    pub(crate) verification: BackupArchiveVerification,
    /// The current front-door succession pointer, or `None` for a fresh
    /// verification. Same wire keys, same two digests, same exact-key admission
    /// the route has always applied — only the owner of the shape moved.
    pub(crate) successor_of: Option<BackupVerifySuccessorPointer>,
}

/// The succession pointer exactly as the front door has always read it.
///
/// Two 64-hex digests and nothing else, which is what makes it a POINTER rather
/// than an authorization: the predecessor's namespace key and its
/// accepted-identity digest. It was moved out of `request_dispatch.rs` so the
/// admitted payload has one closed type per arm; the field names, the shape
/// check and every use are unchanged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupVerifySuccessorPointer {
    /// The predecessor operation's durable namespace key.
    pub(crate) predecessor_namespace_digest: String,
    /// The predecessor operation's full accepted-identity digest.
    pub(crate) predecessor_identity_digest: String,
}

/// The owner channel's own evidence for the CAPTURE operation a receipt belongs
/// to (issue #2862, item I4).
///
/// # WHY THE ROLE AND THE OPERATION TRAVEL TOGETHER
///
/// [`BackupCaptureReceipt::validate_against`] takes a `&BackupRequestIdentity`
/// and an AUTHENTICATED [`BackupRole`] as SEPARATE arguments, because a value in
/// a payload never grants a role (the protocol module states this as its own
/// invariant). That signature is the reason these two facts are one value here:
/// the receipt cannot be validated at all unless BOTH the capture operation it
/// was issued under and the role its issuing channel authenticated as are
/// present, and [`check_provenance_binding`] refuses a receipt that arrives
/// without them rather than falling back to a subset of the checks.
///
/// `operation` is the EXISTING [`BackupCaptureRequest`], carried whole, so the
/// capture operation's own `validate()` decides its wire identity, its
/// `RequestCapture` operation binding, its `BackupRequestIdentity` and its
/// canonical request digest. Nothing about the capture operation is re-derived
/// or re-spelled here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CaptureOwnerAttestation {
    /// The EXACT protocol role the issuing owner channel authenticated as.
    /// Read from the owner channel, never from a payload and never from this
    /// route's front-door capability, and compared by
    /// [`BackupCaptureReceipt::validate_against`] against the capture request
    /// identity's own `principal.role`.
    pub(crate) authenticated_role: BackupRole,
    /// The capture operation the receipt belongs to, in the protocol's own shape.
    pub(crate) operation: BackupCaptureRequest,
}

/// The owner channel's own evidence for the VERIFIER that issued an archive
/// validity attestation (issue #2862, items I4 and A1).
///
/// [`BackupArchiveValidityAttestation::validate_against`] takes the
/// authenticated [`BackupRole::Verifier`] as a separate argument for the same
/// reason, and the route holds no other source for it. It is a distinct value
/// from [`CaptureOwnerAttestation`] rather than a field on it because the two
/// roles are different closed protocol values attesting different lifecycle
/// stages (`Captured` and `Verified`), and collapsing them would let a capture
/// owner's role be read as a verifier's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VerifierAttestation {
    /// The EXACT protocol role the attesting verifier channel authenticated as.
    pub(crate) authenticated_role: BackupRole,
}

/// The owner-issued provenance evidence held for EXACTLY ONE `backup.verify`
/// operation (issue #2862, item I3).
///
/// The three owner-ISSUED values it carries are the EXISTING protocol owner
/// types, reused verbatim: [`BackupArtifactHandle`] for the retained archive,
/// [`BackupCaptureReceipt`] for the capture, and
/// [`BackupArchiveValidityAttestation`] for the verifier's validity verdict. No
/// field of any of them is redefined, renamed, re-spelled or re-digested here,
/// and no second retention, lease or digest scheme is introduced. The remaining
/// two fields are not evidence at all: they are the CAPTURE OPERATION the
/// receipt was issued under and the two AUTHENTICATED ROLES, which exist
/// because the protocol's own validators take the role as a separate argument
/// and would otherwise be replaced by a hand-written subset of their relations.
/// What this value adds is the BOUND: which one operation and which one archive
/// these belong to, which is exactly the relation item I4 requires and which no
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
    /// The capture OPERATION the receipt above was issued under, together with
    /// the authenticated capture-owner role its issuing channel proved. It is
    /// not optional bookkeeping: without it the receipt's snapshot and member
    /// digests, its capture operation and its role cannot be decided at all, so
    /// a receipt present without it is REFUSED rather than partially checked.
    /// See [`check_provenance_binding`].
    pub(crate) capture_owner: Option<CaptureOwnerAttestation>,
    /// The validity attestation the `BackupRole::Verifier` session issued for
    /// THAT archive under the exact observed fence. It is the ONLY thing that
    /// may raise a proof ceiling on this route, and it is never synthesised
    /// here.
    pub(crate) validity_attestation: Option<BackupArchiveValidityAttestation>,
    /// The authenticated verifier role the attestation above was issued under.
    /// Required whenever the attestation is present, for the same reason the
    /// capture owner's role is: the protocol's own validator takes the
    /// authenticated role as a separate argument and a payload never grants it.
    pub(crate) verifier: Option<VerifierAttestation>,
}

impl OwnerProvenanceEvidence {
    /// The owner's own answer on a path where no admitted owner issued
    /// provenance evidence for the presented archive (issue #2862, item I3).
    ///
    /// This is a TYPED REFUSAL, not an empty default and not a stand-in. On
    /// this tree it is also the production answer, and the measured reasons are
    /// enumerated in the module docs: a `BackupArtifactHandle` needs an
    /// `ArtifactId` that no backup-archive owner issues; the production
    /// `PublicationPort` impl #959 added
    /// (`eliot_blob::BlobArchivePublicationOwner`) has NO METHOD THAT ACCEPTS A
    /// HANDLE AND NO METHOD THAT RETURNS BYTES — its `reconcile` returns only a
    /// `PublicationReceipt { operation_id, archive_sha256, durable }` — and it
    /// additionally could not be bound without a production
    /// `eliot_blob::BlobStoreService`, which does not exist;
    /// `eliot-blob-api::backup_io` retains per-member sealed blob envelopes
    /// addressed by `BlobLocator` rather than a backup archive; and
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
            capture_owner: None,
            validity_attestation: None,
            verifier: None,
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
    /// field and no field invented here, so every one of the identity's owner-
    /// evidence fields is written here deliberately.
    ///
    /// Be precise about what that buys. It IS total over the evidence as it
    /// stands: each present owner value is projected and each absent one is
    /// explicitly `None`. It is NOT a compile-time exhaustive guard — this is a
    /// field-by-field assignment, not a struct literal, so adding a fourth
    /// owner-evidence field to the ORS identity would NOT be a compile error
    /// here; the struct-literal site that IS exhaustive is
    /// `backup_verify_admitted_identity`, one layer up, and the I5.27
    /// `BackupVerifyIdentityPreimage` is likewise a struct literal. The property
    /// that would make it mechanical — one test that perturbs each owner-evidence
    /// field and asserts the request digest moves — is deferred to the test phase
    /// (I5.27: a field affecting authority, scope, ordering, privacy or effect
    /// cannot be omitted or defaulted silently).
    ///
    /// The two digests are the owner's OWN RECORDED strings, read off the
    /// validated owner value. They are NOT recomputed here and never stand in
    /// for validating what the owner recorded: [`check_provenance_binding`]
    /// runs first and calls each value's own `validate()`, which is what proves
    /// the recorded digest is the digest of that recorded value. That proof is
    /// carried by call order, not by the type — neither digest gets an ORS shape
    /// check of its own here — so the two must not be reordered past each other.
    /// I5.27's `canonical_request_hash` then binds all three fields, so a
    /// different handle, receipt or attestation under one operation identity is
    /// the identity conflict acceptance clause 3 names, not a second answer.
    ///
    /// The projected [`BackupVerifyArchiveHandleRef`] is shape-checked through
    /// its own ORS `validate()` before it is written, so the adapter never
    /// projects a value the store would refuse to read back.
    pub(crate) fn bind_into(
        &self,
        identity: &mut BackupVerifyRequestIdentity,
    ) -> Result<(), BackupProvenanceError> {
        identity.archive_handle =
            self.archive_handle
                .as_ref()
                .map(|handle| BackupVerifyArchiveHandleRef {
                    artifact_id: handle.artifact_id.as_str().to_owned(),
                    owner_contract: handle.contract.name.as_str().to_owned(),
                    source_revision: handle.source_revision.clone(),
                    content_sha256: handle.content_sha256.clone(),
                    byte_length: handle.byte_length,
                });
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

/// Binds the EXISTING protocol verification request for this operation into the
/// accepted ORS request identity (issue #2862, item I2) — the exhaustive
/// CHECKED ADAPTER.
///
/// # WHAT "EXHAUSTIVE" IS HERE, PRECISELY
///
/// Not a struct update, not a `..rest`, and not a permissive `if let Some(..)`
/// walk over the protocol request. Every field of [`BackupArchiveVerification`]
/// and every field of [`BackupRequestIdentity`] is accounted for below in one of
/// exactly three ways, and which way is stated rather than left to a reader:
///
/// 1. JOINED, by exact equality, against a value THIS operation really holds.
///    Divergence is a typed refusal, so a changed input under one operation
///    identity is the I5.27 conflict and never a second answer.
/// 2. VALIDATED by the protocol's OWN `validate()`, which runs FIRST on the
///    ORIGINAL RECORDED value and decides the wire identity, the
///    `VerifyArchive` operation binding, every digest shape, the
///    source/destination isolation, the fence and transport-correlation join,
///    the admission bindings and BOTH canonical digests. Those fields are not
///    re-checked here: re-deriving a digest to compare against this route's own
///    re-derivation is precisely the substitution the issue forbids.
/// 3. PROJECTED into the ORS identity, so the operation's own I5.27 preimage
///    commits to it.
///
/// # WHY THE REQUEST IS ABOUT THIS OPERATION AND NOT MERELY WELL-FORMED
///
/// A [`BackupArchiveVerification`] that passes its own `validate()` proves it is
/// internally consistent and nothing more — a caller can mint one for an archive
/// it never presented. The joins are therefore the load-bearing half:
///
/// - operation: `operation` and `identity.mutation.operation` are
///   `VerifyArchive`, and `wire_id` is the value the protocol's own total
///   [`BackupOperationKind::wire_id`] table returns for that operation, so a
///   capture request re-spelled as a verification cannot pass.
/// - caller: `identity.request.idempotency_key`,
///   `identity.principal.principal`, `identity.principal.session_id` and
///   `identity.principal.authority_epoch` equal the accepted ORS identity's own
///   `operation_id`, `principal`, `session_id` and `authority_epoch`. The first
///   three are the platform adapter's proved peer identity; the fourth is the
///   admitted session's epoch. A request minted for another principal, another
///   session, another epoch or another idempotency key refuses.
/// - fence: `identity.fence` is the admitted session's live `StateFence`. The
///   protocol already requires it to equal the request's own transport
///   `state_fence`; binding it to the live fence is what stops a request being
///   carried into a different authority.
/// - archive: `identity.archive_id`, `identity.archive_digest`,
///   `believed_archive_digest`, `handle.content_sha256` and `handle.byte_length`
///   are the archive the capture owner just decoded from the presented bytes,
///   and `identity.archive_contract.name` / `identity.owner_contract.name` are
///   the contract the archive declares in its producing `source_adapter`. A
///   handle for other content, for other bytes of the same content, or for an
///   archive this operation did not present, refuses.
/// - class: `identity.class` is the class the capture owner evidenced from the
///   decoded archive, compared through the protocol's own
///   [`BackupClassWire::validate_transition`], and it is the same class the ORS
///   identity already recorded as `evidenced_class`. I5.13: a degraded or scope
///   class can never satisfy a `full_recovery` claim by being relabelled.
///
/// # TERMS DELIBERATELY NOT JOINED, AND WHY
///
/// `identity.admission.capability` is NOT compared with the ORS identity's
/// `capability`: those are two different closed vocabularies (the protocol admits
/// a backup capability token, this frame holds the transport's `daemon`
/// front-door capability), so an equality test would invent a spelling relation
/// no owner states. The protocol's own `BackupAdmissionRef::validate` still
/// checks the admission's authority/scope/epoch bindings, and the ORS identity
/// separately records and shape-checks the capability that actually gated this
/// call. `admission.admission_receipt`, `schema_digest`, `build_digest`,
/// `max_page_members`, `max_payload_bytes`, `deadline_unix_ms`,
/// `cancellation_id`, `dest_installation`, `identity_digest` and
/// `request_digest` are all decided by the protocol's own `validate()` on the
/// original recorded value.
pub(crate) fn bind_protocol_request(
    verification: &BackupArchiveVerification,
    identity: &mut BackupVerifyRequestIdentity,
    session_fence: &StateFence,
    report: &CaptureReport,
    presented_bytes: &[u8],
) -> Result<(), BackupProvenanceError> {
    // The ORIGINAL RECORDED protocol request through the protocol's OWN
    // validator. This is what proves the two canonical digests, and it runs
    // before any join below so a self-consistent forgery is refused on its own
    // terms first.
    verification
        .validate()
        .map_err(|source| BackupProvenanceError::OwnerValueInvalid {
            field: ARCHIVE_VERIFICATION_FIELD,
            source,
        })?;
    let request: &BackupRequestIdentity = &verification.identity;

    // The operation, read against the protocol's own total operation-to-wire
    // table rather than a copied literal.
    if verification.operation != BackupOperationKind::VerifyArchive
        || request.mutation.operation != BackupOperationKind::VerifyArchive
        || verification.operation.wire_id() != verification.wire_id
    {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.operation",
        });
    }

    // THE CALLER AND THE OPERATION.
    if request.request.idempotency_key != identity.operation_id {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.identity.request.idempotency_key",
        });
    }
    if request.principal.principal != identity.principal {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.identity.principal.principal",
        });
    }
    if request.principal.session_id != identity.session_id {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.identity.principal.session_id",
        });
    }
    if request.principal.authority_epoch != identity.authority_epoch {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.identity.principal.authority_epoch",
        });
    }
    if &request.fence != session_fence {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.identity.fence",
        });
    }

    // The archive leg is its own function so this one keeps the operation and
    // caller joins together with the projection that follows them.
    check_protocol_archive_binding(verification, request, identity, report, presented_bytes)?;

    // The PROJECTION. The protocol request's handle is the handle reference this
    // operation vouches for, so it is what the ORS identity carries. The
    // owner-issued handle is projected by `bind_into`; requiring the two to be
    // the SAME value is what stops either from silently winning, and that
    // equality is enforced in `check_provenance_binding`.
    let projection = BackupVerifyArchiveHandleRef {
        artifact_id: verification.handle.artifact_id.as_str().to_owned(),
        owner_contract: verification.handle.contract.name.as_str().to_owned(),
        source_revision: verification.handle.source_revision.clone(),
        content_sha256: verification.handle.content_sha256.clone(),
        byte_length: verification.handle.byte_length,
    };
    projection
        .validate()
        .map_err(|source| BackupProvenanceError::ProjectionRefused {
            field: ARCHIVE_HANDLE_FIELD,
            source,
        })?;
    identity.archive_handle = Some(projection);
    Ok(())
}

/// Joins the admitted protocol request's ARCHIVE half to the archive this
/// operation actually presented (issue #2862, item I2).
///
/// This is the third of the three joins [`bind_protocol_request`] makes, split
/// out because the archive join is the largest of them and the two together no
/// longer fit one function. It takes the three values it compares against —
/// `report` (the capture owner's own record of the decoded archive),
/// `presented_bytes` (the exact sequence it decoded) and `identity` (for the
/// evidenced class the ORS identity already recorded) — so nothing is read from
/// a sibling field of the value being written and no argument is carried that
/// the body does not use.
///
/// Every comparison below is EXACT EQUALITY against a value this operation
/// really holds. Nothing here is a second validation: the protocol's own
/// `validate()` has already decided the wire identity, the digest shapes and both
/// canonical digests, and this function decides only whether the request is about
/// the archive in hand.
fn check_protocol_archive_binding(
    verification: &BackupArchiveVerification,
    request: &BackupRequestIdentity,
    identity: &BackupVerifyRequestIdentity,
    report: &CaptureReport,
    presented_bytes: &[u8],
) -> Result<(), BackupProvenanceError> {
    if request.archive_id != report.backup_id {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.identity.archive_id",
        });
    }
    if request.archive_digest != report.archive_sha256 {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.identity.archive_digest",
        });
    }
    if verification.believed_archive_digest != report.archive_sha256 {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.believed_archive_digest",
        });
    }
    if verification.handle.content_sha256 != report.archive_sha256 {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.handle.content_sha256",
        });
    }
    if verification.handle.byte_length != presented_bytes.len() as u64 {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.handle.byte_length",
        });
    }
    if request.archive_contract.name.as_str() != report.owner_contract
        || request.owner_contract.name.as_str() != report.owner_contract
    {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.identity.archive_contract",
        });
    }
    if request.source_installation != report.source_installation {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.identity.source_installation",
        });
    }
    BackupClassWire::validate_transition(wire_class(report.class), request.class).map_err(
        |source| BackupProvenanceError::OwnerValueInvalid {
            field: "backup_verify.verification.identity.class",
            source,
        },
    )?;
    if identity.evidenced_class != class_name(report.class) {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.verification.identity.evidenced_class",
        });
    }
    Ok(())
}

/// Binds every owner-issued value in one provenance answer, and the admitted
/// protocol request, to the archive this `backup.verify` operation is about, and
/// refuses before any verdict (issue #2862, items I4 and A1).
///
/// `report` is the capture owner's OWN record of the decoded archive, and
/// `presented_bytes` is the exact byte sequence the caller presented and the
/// owner re-decoded. Both are owner/admission facts, never caller spelling.
/// `request` is the admitted protocol request, or `None` on the inline-bytes arm
/// where the caller presented bytes and no protocol request exists.
///
/// The ORDER is the point. Every binding check runs here, before the route
/// computes a request identity, projects an answer, or stages its single
/// durable row, so a mismatched receipt is structurally unable to reach a
/// provenance-qualified verdict: the route calls this first and turns a typed
/// refusal into the same `invalid_reply` an archive-invalid frame already gets,
/// which is a structural refusal carrying no ceiling and no class claim.
///
/// # WHAT I4 ADDS ON TOP OF THE PREVIOUS VERSION
///
/// The previous version compared the receipt's archive id, class, fence and
/// attesting owner against the presented archive and stopped there. That proved
/// the receipt is CONSISTENT WITH the archive; it did not prove the receipt is
/// bound to an OPERATION, which is what I4 asks for. Three terms are added, and
/// all three come from the protocol's OWN validators rather than from a second
/// comparison spelled here:
///
/// - the CAPTURE OPERATION the receipt was issued under, carried whole as
///   [`BackupCaptureRequest`] and validated by its own `validate()`;
/// - the AUTHENTICATED capture-owner role, carried as a separate value and passed
///   to [`BackupCaptureReceipt::validate_against`] as its separate argument,
///   because a value in a payload never grants a role;
/// - the ARCHIVE/SNAPSHOT/MEMBER digest join, which `validate_against` states
///   between the receipt and the capture operation, and which the joins below
///   state between the capture operation and the verification request that IS
///   this operation. Two different records on each side, so neither leg is a
///   self-comparison.
///
/// # THE TWO FACTS THAT TRAVEL TOGETHER, AND WHY A PARTIAL PAIR REFUSES
///
/// A receipt without its capture operation and role cannot be checked against
/// either, so it is REFUSED — not partially checked, not defaulted, and not
/// treated as absent. The same holds for the validity attestation and the
/// authenticated verifier role. The rule is one `is_some() != is_some()` per
/// pair, so "some evidence arrived" can never mean "less was checked".
///
/// # THE RELATIONS, AND THE OWNER FACT EACH IS CHECKED AGAINST
///
/// - handle ↔ protocol request: the owner-issued handle and the handle the
///   admitted protocol request names are the SAME value. One without the other
///   refuses: a handle with no request has no operation to belong to, and a
///   request with no handle has no retained bytes behind it.
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
/// - receipt → capture operation → archive: `validate_against` compares the
///   receipt's `archive_id`, `snapshot_digest`, `member_digest`, class, fence
///   and currency against the capture request identity; the joins below then
///   compare the capture operation's `archive_id`, `archive_digest`,
///   `owner_contract` and `source_installation` against the archive the capture
///   owner just decoded, and its `StateFence` against the COMPLETE archived
///   fence this archive was exported under. A receipt for another archive,
///   another snapshot, another membership, another class, another fence or
///   another source refuses here, before any verdict.
/// - receipt → owner: the receipt's `attesting_owner` equals the owner contract
///   the archive declares. A receipt issued by another owner refuses, and so
///   does one whose channel never authenticated as the capture owner.
/// - attestation → this operation: the EXISTING
///   [`BackupArchiveValidityAttestation::validate_against`] is called with the
///   admitted protocol request identity and the authenticated verifier role, so
///   the attested archive id, archive digest, exact fence and currency are
///   compared against THIS operation's own request, and only
///   `BackupRole::Verifier` is accepted. The verifier's `attesting_owner` and
///   attested archive id/digest are additionally compared against the presented
///   archive's own answers.
/// - NOTE ON THE ATTESTATION'S FENCE, which changed: the previous version
///   required the attestation's `StateFence` to re-encode to the ARCHIVE's
///   complete fence digest. That was the wrong relation and is gone. A validity
///   attestation says the archive is valid AS OBSERVED NOW, so the protocol
///   binds it to the request's CURRENT fence, and the archive's own historical
///   fence is the separate archived-fence relation the capture owner already
///   reports. Requiring the two to be one value would make the relation
///   unsatisfiable by construction.
///
/// # THE TWO TERMS WITH NO OWNER-ISSUED COUNTERPART, STATED RATHER THAN INVENTED
///
/// `snapshot_digest` and `member_digest` exist only on the protocol request
/// identity: the ECXF archive format carries no snapshot digest and no member
/// digest, so there is no archive-side value to compare them against and
/// deriving one here would be a second digest scheme over the same content. They
/// are bound by the two-record join described above instead. `source_revision` is
/// the same case: nothing the capture owner reports names an owner revision of a
/// retained artifact, so it is bound by `BackupArtifactHandle::validate`'s bound
/// plus being DIGEST-BOUND into the I5.27 request hash — a different
/// `source_revision` under one operation identity is an identity conflict rather
/// than a silently accepted answer.
pub(crate) fn check_provenance_binding(
    evidence: &OwnerProvenanceEvidence,
    request: Option<&BackupVerifyAdmittedRequest>,
    report: &CaptureReport,
    presented_bytes: &[u8],
) -> Result<(), BackupProvenanceError> {
    check_handle_binding(evidence, request, report, presented_bytes)?;
    // The two pairs that must not be split. See the type doc.
    if evidence.capture_receipt.is_some() != evidence.capture_owner.is_some() {
        return Err(BackupProvenanceError::NotBound {
            field: CAPTURE_OPERATION_FIELD,
        });
    }
    if evidence.validity_attestation.is_some() != evidence.verifier.is_some() {
        return Err(BackupProvenanceError::NotBound {
            field: VALIDITY_ATTESTATION_FIELD,
        });
    }
    if let (Some(receipt), Some(capture_owner)) =
        (&evidence.capture_receipt, &evidence.capture_owner)
    {
        check_capture_receipt_against_operation(receipt, capture_owner)?;
        // The capture operation → THIS archive and THIS operation.
        check_capture_operation_binding(capture_owner, request, report)?;
        if receipt.archive_id != report.backup_id {
            return Err(BackupProvenanceError::NotBound {
                field: "backup_verify.capture_receipt.archive_id",
            });
        }
        if receipt.attesting_owner != report.owner_contract {
            return Err(BackupProvenanceError::NotBound {
                field: "backup_verify.capture_receipt.attesting_owner",
            });
        }
    }
    if let (Some(attestation), Some(verifier)) =
        (&evidence.validity_attestation, &evidence.verifier)
    {
        check_validity_attestation_binding(attestation, *verifier, request, report)?;
    }
    Ok(())
}

/// Leg one: the retained handle, bound to the bytes in hand and to the protocol
/// request that names it (issue #2862, items I2 and I4).
///
/// Two relations live here because they are the same fact seen from two sides,
/// and the ORDER matters: the handle and the protocol request must first be the
/// SAME value, and only then is either of them compared against the archive.
/// A protocol request whose handle is for other content, or an owner-issued
/// handle with no protocol request behind it, has no operation to belong to and
/// refuses before any archive comparison is attempted.
fn check_handle_binding(
    evidence: &OwnerProvenanceEvidence,
    request: Option<&BackupVerifyAdmittedRequest>,
    report: &CaptureReport,
    presented_bytes: &[u8],
) -> Result<(), BackupProvenanceError> {
    // The retained handle and the admitted protocol request are the SAME fact.
    match (evidence.archive_handle.as_ref(), request) {
        (Some(_), None) => {
            return Err(BackupProvenanceError::NotBound {
                field: ARCHIVE_VERIFICATION_FIELD,
            });
        }
        (None, Some(_)) => {
            return Err(BackupProvenanceError::NotBound {
                field: ARCHIVE_HANDLE_FIELD,
            });
        }
        (Some(handle), Some(admitted)) => {
            if handle != &admitted.verification.handle {
                return Err(BackupProvenanceError::NotBound {
                    field: ARCHIVE_HANDLE_FIELD,
                });
            }
        }
        (None, None) => {}
    }
    let Some(handle) = &evidence.archive_handle else {
        return Ok(());
    };
    handle.validate(ARCHIVE_HANDLE_FIELD).map_err(|source| {
        BackupProvenanceError::OwnerValueInvalid {
            field: ARCHIVE_HANDLE_FIELD,
            source,
        }
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
    Ok(())
}

/// Leg two: the capture receipt against the CAPTURE OPERATION it was issued
/// under, with the authenticated capture-owner role (issue #2862, item I4).
///
/// This leg is the one that makes the receipt bound to an OPERATION rather than
/// merely consistent with an archive, and it is stated entirely through the
/// protocol's own validators:
///
/// - both values are validated as the ORIGINAL RECORDED values through their own
///   `validate()`, so a recomputed digest never stands in for the check;
/// - [`BackupCaptureReceipt::validate_against`] is then called with the capture
///   request identity and the authenticated role as SEPARATE arguments, because a
///   value in a payload never grants a role. It requires the role to equal the
///   capture request identity's own `principal.role` AND to be
///   `BackupRole::CaptureOwner`, and it compares the receipt's archive id,
///   snapshot digest, member digest, class, exact fence and evidence currency
///   against that operation.
///
/// A receipt for another archive, another snapshot, another membership, another
/// class, another fence, or one that no capture owner channel authenticated,
/// refuses HERE — before any verdict exists, and before the archive this
/// operation presented is consulted at all.
fn check_capture_receipt_against_operation(
    receipt: &BackupCaptureReceipt,
    capture_owner: &CaptureOwnerAttestation,
) -> Result<(), BackupProvenanceError> {
    receipt
        .validate()
        .map_err(|source| BackupProvenanceError::OwnerValueInvalid {
            field: CAPTURE_RECEIPT_FIELD,
            source,
        })?;
    capture_owner.operation.validate().map_err(|source| {
        BackupProvenanceError::OwnerValueInvalid {
            field: CAPTURE_OPERATION_FIELD,
            source,
        }
    })?;
    receipt
        .validate_against(
            &capture_owner.operation.identity,
            capture_owner.authenticated_role,
        )
        .map_err(|source| BackupProvenanceError::OwnerValueInvalid {
            field: CAPTURE_RECEIPT_FIELD,
            source,
        })
}

/// Leg three: the capture operation against THIS archive and THIS verification
/// operation (issue #2862, item I4).
///
/// Leg two tied the receipt to the capture operation; this leg ties that
/// operation to the thing actually in hand, and every term is exact equality
/// against a value this operation really holds. `request` is the admitted
/// protocol request, and it is `None` only on the inline arm, where the two
/// digest joins below are not applicable because no protocol request exists to
/// join them to.
fn check_capture_operation_binding(
    capture_owner: &CaptureOwnerAttestation,
    request: Option<&BackupVerifyAdmittedRequest>,
    report: &CaptureReport,
) -> Result<(), BackupProvenanceError> {
    // The capture operation → THIS archive.
    if capture_owner.operation.identity.archive_id != report.backup_id {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.capture_operation.archive_id",
        });
    }
    if capture_owner.operation.identity.archive_digest != report.archive_sha256 {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.capture_operation.archive_digest",
        });
    }
    if capture_owner
        .operation
        .identity
        .owner_contract
        .name
        .as_str()
        != report.owner_contract
    {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.capture_operation.owner_contract",
        });
    }
    if capture_owner.operation.identity.source_installation != report.source_installation {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.capture_operation.source_installation",
        });
    }
    // The receipt's fence is tied BY VALUE to the capture operation's fence by
    // leg two, so the complete-fence digest below is taken over the fence the
    // receipt was actually issued under rather than over the receipt's own copy.
    if archived_state_fence_digest(&capture_owner.operation.identity.fence)
        .map_err(|_| BackupProvenanceError::ArchiveFenceUndecidable)?
        != report.archived_state_fence_digest
    {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.capture_operation.fence",
        });
    }
    // The evidenced class the capture operation declared, against the class the
    // capture owner read out of the decoded archive.
    BackupClassWire::validate_transition(
        wire_class(report.class),
        capture_owner.operation.identity.class,
    )
    .map_err(|source| BackupProvenanceError::OwnerValueInvalid {
        field: "backup_verify.capture_operation.class",
        source,
    })?;
    // The capture operation → THIS operation, for the two digests the archive
    // format does not carry. Leg two tied the receipt's copies to the capture
    // operation's; these tie the capture operation's to the verification request
    // that IS this operation, so the snapshot and membership the receipt attests
    // are the ones this verification asked about.
    let Some(admitted) = request else {
        return Ok(());
    };
    if capture_owner.operation.identity.snapshot_digest
        != admitted.verification.identity.snapshot_digest
    {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.capture_operation.snapshot_digest",
        });
    }
    if capture_owner.operation.identity.member_digest
        != admitted.verification.identity.member_digest
    {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.capture_operation.member_digest",
        });
    }
    Ok(())
}

/// Leg four: the verifier's archive validity attestation against THIS operation
/// (issue #2862, items I4 and A1).
///
/// The typed attestation is checked by the protocol's own
/// [`BackupArchiveValidityAttestation::validate_against`] with the admitted
/// protocol request identity and the authenticated verifier role as separate
/// arguments. Only `BackupRole::Verifier` is accepted there, and the role must
/// equal the request identity's own `principal.role` — so the verdict is never
/// creditable to a role the payload merely names.
///
/// An attestation with no protocol request behind it has no operation to be
/// valid FOR, so it refuses rather than being compared against the archive
/// alone. Note that the attested fence is deliberately NOT compared against the
/// archive's historical fence: a validity attestation states the archive is valid
/// as observed NOW, so the protocol binds it to the request's current fence, and
/// the archive's own historical fence is the separate archived-fence relation
/// the capture owner already reports.
fn check_validity_attestation_binding(
    attestation: &BackupArchiveValidityAttestation,
    // BY VALUE because the type is `Copy` — it is a single closed protocol role,
    // and passing a reference to it would be a needless borrow.
    verifier: VerifierAttestation,
    request: Option<&BackupVerifyAdmittedRequest>,
    report: &CaptureReport,
) -> Result<(), BackupProvenanceError> {
    let Some(admitted) = request else {
        return Err(BackupProvenanceError::NotBound {
            field: ARCHIVE_VERIFICATION_FIELD,
        });
    };
    attestation
        .validate_against(&admitted.verification.identity, verifier.authenticated_role)
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
    if attestation.attesting_owner != report.owner_contract {
        return Err(BackupProvenanceError::NotBound {
            field: "backup_verify.validity_attestation.attesting_owner",
        });
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
