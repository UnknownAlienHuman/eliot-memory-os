//! Kernel-owned cross-owner backup capture coordinator (issue #959).
//!
//! Architecture: I5.13 backup classes (full denominator, degraded ceiling,
//! key-material rule); A13.6 Operational Recovery State (only identities,
//! opaque envelopes, epochs, suspended leases, checkpoints, intents, manifests,
//! anchors — never semantic claims); I14.21 unknown-commit recovery (reconcile
//! by identity, never blind retry); I14.3 Control Reserve (bounded capture
//! work; no unbounded waits inside a held transaction); I7.20 agent-facing
//! error contract (typed refusals with exact reason, never silence or
//! fabricated success).
//!
//! I5.13 sentences this coordinator is bound by:
//!
//! - The ORS and canonical export are not one cross-store transaction: the
//!   manifest records their relation, and every ORS item restores as
//!   `suspended_recovery`. No global-transaction type exists anywhere in this
//!   file; per-owner snapshots stay independent and only their recorded
//!   `SnapshotRelation` is validated.
//! - A legitimate independent snapshot with bounded unresolved operations may
//!   form a `full_recovery` archive when all required material and coherent
//!   relations are preserved; those operations restore suspended and are
//!   reconciled before replay. Unresolved operations are not archive
//!   corruption, and archive validity is not completed effect reconciliation.
//! - An optional forensic `HostStateAuditFence` is never restored as active
//!   authority and never satisfies a class denominator.
//! - The backup contains key lineage and format metadata, never plaintext
//!   master or data keys; equal bytes under different obligations remain
//!   distinct logical objects.
//!
//! What this file owns: the thin `KernelBackupCapture` execution body that
//! admits, freezes, gates, relates, bounds, builds, verifies, and publishes
//! exactly once. Build and verification run through the existing accepted
//! `BackupBundle` API (`build` / `validate` / `encode` / `decode` /
//! `bundle_sha256`); validation may repeat freely — one admitted
//! capture/publication operation is the identity boundary, never a once-only
//! validation guard. Publication reconciles a lost response by operation
//! identity through `PublicationPort::reconcile`, never by byte-equality or
//! process exit. Verification-only decodes and validates with zero restore
//! calls and zero installation mutation.
//!
//! Proof levels this coordinator reports (issue #2802):
//!
//! - Every result names its own evidence level ([`CaptureEvidenceLevel`]) and
//!   its exact class ceiling (`BackupClass::evidence_level`): I5.13 keeps
//!   `canonical_only_degraded` "preserves semantic data only and is never
//!   advertised as operational recovery" and `scope_export` "not an
//!   installation backup", and states "Backup existence is not recovery
//!   proof", so a degraded class reports its own lower ceiling instead of
//!   being promoted to recovery or collapsed into corruption.
//! - The archived fence is validated internally and related to the live session
//!   fence as one closed STRUCTURAL relation over the COMPLETE fence value
//!   ([`ArchiveFenceRelation`]), while PROVENANCE stays a separate axis
//!   ([`ArchiveFenceProof`]): a restart, generation change, or epoch rotation
//!   must not make a genuine earlier archive unverifiable, and
//!   current-target compatibility plus epoch monotonicity stay with the isolated
//!   restore/cutover owners (A13.7 "Cutover requires separate authority").
//! - The reported operation identity is only ever the identity the admitted
//!   caller bound: I5.27 defines idempotency over canonical bytes, "not over
//!   caller spelling or an unversioned hash", so this owner never mints one.
//!
//! Capability cell: Kernel capture ownership (cross-owner capture execution).
//! Forbidden authority: no ORS row reinterpretation, no epoch minting, no
//! cutover, no activation/retirement of any installation, no second archive
//! format, no invented restore or target methods, and no recovered, activated,
//! cut-over, or finished claims.

use std::path::{Path, PathBuf};

use eliot_backup::{
    BackupArtifact, BackupBlob, BackupBundle, BackupClass, BackupInput, CanonicalRecord,
    ExportFence, HostStateAuditFence, OrsSnapshotFence, RestoreEvidenceLevel, WatchdogSpoolFence,
};
use eliot_contracts::{EpochRelation, StateFence, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::WriteReceipt;

use super::backup_capture_ports::{
    CaptureBudgets, CaptureCallerAuth, CapturePorts, FrozenCapturePlan, KernelCaptureError,
    PublicationPort, PublishedArchive, SnapshotRelation, owner_fence_dispositions,
    owner_residency_key_digest, owner_suspended_recovery_refs, require_capture_admitted,
};

/// Owner order for per-owner budget accounting: canonical, blob, purge, ORS,
/// watchdog, host.
const OWNER_COUNT: usize = 6;

/// One capture request: the admitted caller, the frozen plan, and owned clones
/// of the already-accepted owner evidence.
///
/// A single struct with owned vectors and options keeps test construction
/// direct: no live owner handle, database read path, or snapshot service
/// travels here.
#[derive(Clone, Debug, PartialEq)]
pub struct CaptureRequest {
    /// Admitted caller authentication behind the capture.
    pub caller: CaptureCallerAuth,
    /// Frozen class, scope, source, schema, build, policy, and budgets.
    pub plan: FrozenCapturePlan,
    /// Coherent canonical export fence binding the capture.
    pub export_fence: ExportFence,
    /// The Kernel's live authority fence the evidence was admitted under.
    pub kernel_fence: StateFence,
    /// Canonical event records carried by the capture.
    pub canonical_events: Vec<CanonicalRecord>,
    /// Canonical projection records carried by the capture.
    pub projections: Vec<CanonicalRecord>,
    /// Canonical write receipts carried by the capture.
    pub receipts: Vec<WriteReceipt>,
    /// Sealed blob envelopes carried by the capture (never plaintext).
    pub blobs: Vec<BackupBlob>,
    /// Purge ledger entries carried by the capture.
    pub purge_ledger: Vec<PurgeLedgerEntry>,
    /// Logical ORS snapshot fence, when the class carries one.
    pub ors_snapshot: Option<OrsSnapshotFence>,
    /// Count of suspended recovery entries derived from the ORS snapshot.
    ///
    /// This is the PRODUCER'S CLAIM, never this owner's authority. The
    /// unresolved-effect frontier that decides the capture state and the
    /// suspended marker is read from the ORS owner's own
    /// `ors_snapshot.pending_operation_ids` (see `observed_unresolved_frontier`);
    /// this field only has to agree with that evidence, and a disagreement
    /// refuses the capture instead of silently preferring one of the two.
    pub suspended_count: u64,
    /// Checksummed config, policy, module, and build manifest artifacts.
    pub artifacts: Vec<BackupArtifact>,
    /// Bounded Watchdog spool fence, when the class carries one.
    pub watchdog_spool: Option<WatchdogSpoolFence>,
    /// Optional forensic Host audit fence (never active authority).
    pub host_audit: Option<HostStateAuditFence>,
}

/// Builds one owned capture request from the validated per-execution port
/// bundle plus the frozen plan: the production caller validates owner-evidence
/// shapes through the bundle, then crosses the owned request into `capture`.
/// This keeps the ref-borrowed adapter (`CapturePorts`) on the production
/// path instead of beside it.
pub fn request_from_ports(
    ports: &CapturePorts<'_>,
    plan: FrozenCapturePlan,
    suspended_count: u64,
) -> Result<CaptureRequest, KernelCaptureError> {
    ports.validate_shapes()?;
    Ok(CaptureRequest {
        caller: ports.caller.clone(),
        plan,
        export_fence: ports.export_fence.clone(),
        kernel_fence: ports.kernel_fence.clone(),
        canonical_events: ports.canonical_events.to_vec(),
        projections: ports.projections.to_vec(),
        receipts: ports.receipts.to_vec(),
        blobs: ports.blobs.to_vec(),
        purge_ledger: ports.purge_ledger.to_vec(),
        ors_snapshot: ports.ors_snapshot.cloned(),
        suspended_count,
        artifacts: ports.artifacts.to_vec(),
        watchdog_spool: ports.watchdog_spool.cloned(),
        host_audit: ports.host_audit.cloned(),
    })
}
/// Terminal state of one capture or verification.
///
/// Capture reports completeness only: it never claims recovered, activated,
/// cut-over, or finished — no such variant or string exists here.
#[derive(Clone, Debug, PartialEq)]
pub enum CaptureState {
    /// The archive built, validated, encoded, and published completely.
    Complete,
    /// The archive is structurally valid but cannot claim completeness.
    Incomplete { reason: String },
    /// A required capability is explicitly unsupported here.
    Unsupported { reason: String },
    /// The capture was cancelled before completion.
    Cancelled,
    /// The capture outcome could not be decided from observed evidence.
    Unknown { reason: String },
}

/// The closed evidence level this owner actually proved for one result
/// (issue #2802 instruction 1).
///
/// The level is the owner's own answer about what it did, never a value a
/// caller infers from the reply shape: `verification_level` on the wire is
/// exactly the spelling `as_wire_name` returns here. I5.13 keeps "Backup
/// existence is not recovery proof", so the three levels below are separated
/// rather than collapsed into one Boolean-like "verified" claim.
///
/// The fourth level of #2802 instruction 1 — restore rehearsal / readiness —
/// is deliberately NOT represented here and remains outside this command: it
/// needs the isolated restore and cutover owners, and this owner performs no
/// restore call and mutates nothing.
///
/// A [`StructurallyValidCandidate`] is never promoted to
/// [`ProvenanceBoundCapture`] by this owner, because no retained-artifact owner
/// exists in the repository today: there is no production
/// `impl PublicationPort` (the only implementation is `MemPublisher` inside
/// `bins/eliot-kernel/tests/backup_capture.rs`), and
/// `KernelBackupCapture::capture` / `request_from_ports` have zero production
/// callers. Nothing here may invent a capture receipt to cross that gap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureEvidenceLevel {
    /// Bytes that decode and validate internally; carries no retained capture
    /// receipt, so it is an untrusted candidate.
    StructurallyValidCandidate,
    /// Bound to a retained capture artifact handle plus its owner-issued
    /// publication receipt.
    ProvenanceBoundCapture,
    /// Provenance-bound AND class/compatibility qualified.
    ClassQualified,
}

impl CaptureEvidenceLevel {
    /// Stable operator/wire spelling of this owner's evidence level.
    ///
    /// The front-door projection reads this one value instead of restating a
    /// level literal, so renaming a level changes exactly one place.
    #[must_use]
    pub const fn as_wire_name(self) -> &'static str {
        match self {
            Self::StructurallyValidCandidate => "structurally-valid-candidate",
            Self::ProvenanceBoundCapture => "provenance-bound-capture",
            Self::ClassQualified => "class-qualified",
        }
    }
}

/// Contract version of the closed archived-fence relation vocabulary and of the
/// classifier that produces it (issue #2863).
///
/// It is bound into every verification answer, in the durable result row and in
/// the wire body, and it is the ONE place a change to that vocabulary has to be
/// made. I5.27 requires a versioned canonical encoding, so a vocabulary whose
/// meaning changed cannot be read back under the new meaning: a consumer that
/// sees a version it does not know fails closed rather than coercing an
/// unrecognized value into "current" or "invalid".
pub const ARCHIVE_FENCE_RELATION_CONTRACT_VERSION: u16 = 1;

/// The closed STRUCTURAL relation between the archive's own COMPLETE
/// `StateFence` and the live session fence (issue #2863, superseding #2802
/// instruction 4).
///
/// This is ONE axis and it answers ONE question: how the archived fence VALUE
/// stands to the current fence value. It is not archive validity — that is
/// [`CaptureState`] plus the owner's own `ArchiveInvalid` refusals, and a
/// malformed archive or fence is a separate result, never one of these variants.
/// It is not provenance — that is [`ArchiveFenceProof`]. It is not target
/// compatibility, which is absent from this owner entirely because A13.7 keeps
/// schema/build/key/purge/import/epoch compatibility and cutover with the
/// isolated restore owner.
///
/// # WHY THE PREVIOUS TWO-VALUE CLASSIFIER WAS REPLACED
///
/// The former `ArchivedFenceRelation::{CurrentSession, HistoricalAuthority}`
/// classifier consulted only `EpochId::relation_to` on the authority epoch, so
/// `EpochRelation::Same` became `current-session` even when the resource
/// generation or the optional task/policy/integration revisions disagreed, and
/// an older epoch became `historical-authority` without proving that any other
/// comparable field was coherent. An old epoch with a numerically HIGHER
/// generation was reported as this installation's own accepted history. Those
/// are three different facts, and none of them is "this installation's history".
///
/// # WHAT IS AND IS NOT ORDERED HERE
///
/// Only [`EpochRelation`] orders anything, and only the authority epoch's
/// `(lineage_id, sequence)` tuple. `ResourceGeneration` and the three optional
/// revision counters are separate contracts with no cross-counter order, so
/// this owner NEVER compares them to each other or to the epoch sequence, and
/// never combines them into a total history order. That is why a differing
/// generation is [`Self::SameAuthorityDivergent`] rather than
/// [`Self::SameAuthorityOlder`]: the contracts do not say which is later, so this
/// owner says "these two values contradict or cannot be reconciled", and the
/// isolated restore owner — which holds the transition evidence — decides
/// whether a legal transition exists. Inventing an order here would be a
/// fabricated authority claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveFenceRelation {
    /// EVERY `StateFence` field is equal: authority epoch, resource generation,
    /// and all three optional revisions. This is the ONLY value that may be
    /// described as the current fence value, and reaching it requires complete
    /// equality — `EpochRelation::Same` on its own is never sufficient.
    ExactFenceValue,
    /// The archived authority epoch is older on this installation's own lineage
    /// (`EpochRelation::DirectParent` / `SameLineageOlder`) AND every other
    /// comparable field is coherent: the resource generation is equal and each
    /// optional revision either matches or is absent on both sides. The archived
    /// value therefore differs from the current one in the authority epoch and
    /// in nothing else, which is the one "earlier, same shape" statement the
    /// contracts actually support.
    SameAuthorityOlder,
    /// The archived authority epoch is AHEAD of the live session epoch
    /// (`EpochRelation::DirectChild` / `SameLineageNewer`). An ahead archive is
    /// not this installation's history and this command does not judge its
    /// monotonicity, so it is reported as its own relation rather than refused.
    /// The remaining fields are deliberately NOT consulted for this variant: the
    /// authority relation alone already establishes that the archive is not
    /// behind the current authority, and no other field can make it so.
    SameAuthorityNewer,
    /// The authority epochs are the same or on one lineage, but the remaining
    /// fields do not reconcile: the resource generation differs, or a
    /// task/policy/integration revision is present on BOTH sides with DIFFERENT
    /// values. That is a contradiction, or at minimum an ordering the owning
    /// contracts do not define. It is neither historical success and not archive
    /// corruption, and it is never reported as the current value.
    SameAuthorityDivergent,
    /// The authority lineages differ (`EpochRelation::UnrelatedLineage`). The
    /// archive is a structurally valid candidate from a different authority
    /// lineage — not corrupt, and not refused as though it were malformed.
    UnrelatedLineage,
    /// The complete fence values cannot be compared at all: at least one
    /// optional revision is present on exactly ONE side, so neither value claims
    /// the revision and there is nothing to compare. This is deliberately NOT
    /// merged into [`Self::SameAuthorityDivergent`], because a one-sided revision
    /// is an absence of comparable evidence and not a contradiction; reporting it
    /// as divergent would over-claim a conflict that was never observed.
    IncomparableOrUnknown,
}

impl ArchiveFenceRelation {
    /// Stable operator/wire spelling of the archived-fence relation.
    ///
    /// Bound in one place beside the classification so the front door and the
    /// operator surface never restate the relation as its own literal. These
    /// are the exact tokens the durable result row stores and the CLI decodes.
    #[must_use]
    pub const fn as_wire_name(self) -> &'static str {
        match self {
            Self::ExactFenceValue => "exact-fence-value",
            Self::SameAuthorityOlder => "same-authority-older",
            Self::SameAuthorityNewer => "same-authority-newer",
            Self::SameAuthorityDivergent => "same-authority-divergent",
            Self::UnrelatedLineage => "unrelated-lineage",
            Self::IncomparableOrUnknown => "incomparable-or-unknown",
        }
    }
}

/// The closed PROOF qualifier for one archived-fence relation (issue #2863).
///
/// This is the second axis and it is deliberately independent of
/// [`ArchiveFenceRelation`]. A relation is a statement about VALUES; a proof
/// qualifier is a statement about where those values came from. An
/// [`Self::StructuralOnly`] relation may be exact, older, ahead, divergent,
/// foreign or incomparable and is still only untrusted caller-presented
/// evidence, because nothing on this path authenticates the archive as produced
/// by THIS installation.
///
/// Only [`Self::CaptureOwnerProven`] may be described to an operator as this
/// installation's own capture, and it REQUIRES the owner-issued receipt
/// reference: the variant carries the field, so it cannot be constructed without
/// naming what proved it. That is the whole mechanism, and it is why the
/// qualifier is an enum rather than a flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchiveFenceProof {
    /// The relation was computed from archive bytes this owner decoded and
    /// validated, with no retained-capture provenance behind it. Structural
    /// validity plus a relation is still an untrusted candidate (I5.13: "Backup
    /// existence is not recovery proof"), and this variant is the ONLY value a
    /// `verify_only` answer can carry today, because no production
    /// `impl PublicationPort` issues a capture receipt on that path.
    StructuralOnly,
    /// Bound to the owner-issued publication receipt identity that proves this
    /// installation produced the archive. Only this variant licenses the words
    /// "this installation's capture"; [`Self::StructuralOnly`] never does.
    CaptureOwnerProven { capture_receipt: String },
}

impl ArchiveFenceProof {
    /// Stable operator/wire spelling of the proof qualifier.
    ///
    /// The receipt reference itself is NOT part of this token: it travels in its
    /// own field so a qualifier can be closed-checked without parsing a receipt
    /// identity out of a composite string.
    #[must_use]
    pub const fn as_wire_name(&self) -> &'static str {
        match self {
            Self::StructuralOnly => "structural-only",
            Self::CaptureOwnerProven { .. } => "capture-owner-proven",
        }
    }

    /// The owner-issued receipt reference backing this qualifier, if any.
    ///
    /// `None` is the owner's own answer on a path where no retained-artifact
    /// owner issues a receipt; it is never replaced by a placeholder identity.
    #[must_use]
    pub fn capture_receipt(&self) -> Option<&str> {
        match self {
            Self::StructuralOnly => None,
            Self::CaptureOwnerProven { capture_receipt } => Some(capture_receipt.as_str()),
        }
    }
}

/// Bounded restriction tokens that travel beside every archived-fence relation
/// and proof qualifier (issue #2863).
///
/// These are the claims the result explicitly does NOT make, as closed tokens
/// rather than prose, so the Kernel projection and the operator surface report
/// the same ceiling from the same owner instead of each restating it. Every
/// token is a refusal of a specific over-claim, and none of them is a repair
/// instruction or a compatibility verdict.
pub fn archive_fence_restrictions(
    relation: ArchiveFenceRelation,
    proof: &ArchiveFenceProof,
) -> Vec<&'static str> {
    let mut restrictions = Vec::new();
    // No schema/build/key/purge/import/epoch compatibility check ran on this
    // path, so the absence is stated on EVERY result rather than only on the
    // ones where a reader might assume it.
    restrictions.push("target-compatibility-not-evaluated");
    // Structural relation is never restore readiness, for any variant.
    restrictions.push("not-restore-readiness");
    if !matches!(relation, ArchiveFenceRelation::ExactFenceValue) {
        restrictions.push("not-current-fence-value");
    }
    if matches!(proof, ArchiveFenceProof::StructuralOnly) {
        restrictions.push("origin-unproven");
    }
    restrictions
}

/// Digest binding the COMPLETE archived `StateFence` value (issue #2863).
///
/// This is a dedicated digest over the canonical encoding of the fence value
/// itself. It is deliberately NOT the manifest's `export_fence_sha256`, which the
/// archive format computes over the whole export fence and re-binds on every
/// decode, and it is NOT a manifest, plan or approval digest: reusing one of
/// those as a fence identity would make an unrelated contract's change move this
/// identity. It exists because the relation is now a statement about a complete
/// fence value, so a complete fence value has to be commitable on its own terms.
pub fn archived_state_fence_digest(fence: &StateFence) -> Result<String, KernelCaptureError> {
    let bytes = canonical_json_bytes(fence).map_err(|_| {
        KernelCaptureError::OwnerEvidenceInvalid("state fence is not serializable".to_owned())
    })?;
    Ok(sha256_hex(&bytes))
}

/// Outcome of one capture or verification: the requested class, exact
/// source and archive identities, evidence level, class ceiling, archived-fence
/// relation, member dispositions, terminal state, and the archive's own
/// source/provenance commitments.
///
/// The three source/provenance commitments
/// ([`source_installation`](Self::source_installation),
/// [`owner_contract`](Self::owner_contract) and
/// [`export_fence_digest`](Self::export_fence_digest)) are the archive's own
/// declared source and provenance, not recovery evidence. Be precise about the
/// word "declared": on the verify path the result is a
/// [`CaptureEvidenceLevel::StructurallyValidCandidate`], so these are text the
/// ARCHIVE declares about itself and this owner re-validates for internal
/// consistency — the export fence is re-checked by the bundle's own `validate`,
/// and the manifest's digest binding is re-computed — but they are NOT proved
/// against a capture owner, because none exists on this path. Equal bytes
/// exported by a different owner, from a different installation, or under a
/// different export fence are therefore a different request (I5.27: "archive
/// SHA-256 alone is content integrity, not the source/capture operation
/// identity"), not a contradiction this route can detect.
#[derive(Clone, Debug, PartialEq)]
pub struct CaptureReport {
    /// Archive backup identity bound at build.
    pub backup_id: String,
    /// Requested backup class.
    pub class: BackupClass,
    /// Deterministic digest of the complete encoded archive.
    pub archive_sha256: String,
    /// The archive's own source installation identity, as declared in the export
    /// fence (`ExportFence::export_id`) this owner already treats as the
    /// archive's source installation in [`SnapshotRelation::installation_id`].
    /// Read from the decoded archive, never inferred from the verifying session
    /// or a local path, and NOT proved against a capture owner.
    pub source_installation: String,
    /// The archive's own capture/owner contract identity, read from the decoded
    /// manifest's `source_adapter` — the producer identity the archive declares.
    /// The `EcxfManifest` carries no separate owner-contract field beyond the
    /// producing `source_adapter`, `backup_id` and class, so that is the one real
    /// owner-identity value available and no second spelling of it is invented
    /// here. It is declared by the archive and re-validated for internal
    /// consistency only, NOT proved against a capture owner.
    pub owner_contract: String,
    /// The archive's own export-fence digest, taken from the manifest's
    /// `export_fence_sha256`. This one IS re-derived rather than merely declared:
    /// the archive format computes it at build and `BackupBundle::validate`
    /// recomputes it from the decoded fence and re-checks the manifest binding on
    /// every decode, so a mismatch is refused before this value is read. The
    /// owner value is used as-is; the digest formula is not recomputed in a second
    /// place. It is historical fence evidence: it says what fence the export
    /// happened under, which is not the same fact as the verifying session's
    /// current authority.
    pub export_fence_digest: String,
    /// Operation identity of this result. Capture mints it once at the single
    /// publication; verification only reports back the identity its admitted
    /// caller bound, because I5.27 defines idempotency over canonical bytes and
    /// not over caller spelling, so this owner never invents one.
    pub operation_id: String,
    /// Terminal capture state (never recovered, activated, cut-over, or
    /// finished).
    pub state: CaptureState,
    /// Evidence level this owner proved, from
    /// [`CaptureEvidenceLevel`]: the owner's own answer, never a value a
    /// caller infers.
    pub evidence_level: CaptureEvidenceLevel,
    /// Exact class-specific restore proof ceiling for this archive's class,
    /// read from [`BackupClass::evidence_level`]. I5.13 keeps a degraded class
    /// from ever being advertised as operational recovery, so the ceiling is
    /// reported beside the state rather than encoded into it.
    pub class_ceiling: RestoreEvidenceLevel,
    /// STRUCTURAL relation of the archive's COMPLETE fence to the live session
    /// fence; see [`ArchiveFenceRelation`]. This is not validity, not provenance
    /// and not target compatibility, and it is deliberately reported for a
    /// foreign, ahead or divergent archive instead of refusing one.
    pub archived_fence_relation: ArchiveFenceRelation,
    /// PROVENANCE qualifier for [`Self::archived_fence_relation`]; see
    /// [`ArchiveFenceProof`]. Independent of the relation: a structurally exact
    /// or same-lineage value is still unproven origin without an owner receipt.
    pub archived_fence_proof: ArchiveFenceProof,
    /// Bounded tokens naming the claims this result does not make, from
    /// [`archive_fence_restrictions`]. Reported beside the relation so a reader
    /// cannot take a relation as compatibility, currentness or readiness.
    pub archived_fence_restrictions: Vec<&'static str>,
    /// Contract version of the relation vocabulary and classifier that produced
    /// [`Self::archived_fence_relation`]; see
    /// [`ARCHIVE_FENCE_RELATION_CONTRACT_VERSION`].
    pub archived_fence_relation_contract_version: u16,
    /// Digest of the COMPLETE archived `StateFence` value this report related,
    /// from [`archived_state_fence_digest`]. Commits the exact value the
    /// relation was computed from, and is distinct from
    /// [`Self::export_fence_digest`], which is the archive format's own
    /// manifest-bound digest over the whole export fence.
    pub archived_state_fence_digest: String,
    /// Exactly one disposition per expected source member.
    pub member_dispositions: Vec<(String, String)>,
    /// Publication receipt identity, or the suspended-operations marker. It is
    /// absent on the verification-only path because no retained-artifact owner
    /// issues a receipt there, and absence stays explicit rather than inferred.
    pub receipt_identity: Option<String>,
}

/// Kernel-owned cross-owner backup capture coordinator.
///
/// Binds the Kernel work root the capture operates under. The coordinator
/// owns no live owner channel: every capture consumes already-accepted owner
/// evidence through `CaptureRequest`, builds and verifies through the accepted
/// `BackupBundle` API, and publishes once through the admitted `PublicationPort`.
pub struct KernelBackupCapture {
    work_root: PathBuf,
}

impl KernelBackupCapture {
    /// Binds the capture owner to the Kernel work root.
    pub fn bind(work_root: PathBuf) -> Self {
        Self { work_root }
    }

    /// Returns the bound work root.
    #[must_use]
    pub fn work_root(&self) -> &Path {
        &self.work_root
    }

    /// Executes one admitted capture: admit, freeze, gate, relate, bound,
    /// build, verify, publish exactly once.
    ///
    /// Order: (a) caller admission and frozen-plan validation before touching
    /// evidence; (b) class capability gate with no silent downgrade;
    /// (c) snapshot-relation build and validation; (d) complete-denominator
    /// check; (e) per-owner and cumulative budget check; (f) exact
    /// `BackupBundle` build, repeated validation, and encoding; (g) a single
    /// `publish_once` under the operation identity and idempotency key, with a
    /// lost response reconciled by identity through `reconcile` (never a
    /// second publish). Bounded unresolved operations are not corruption: a
    /// `full_recovery` capture with suspended entries still completes and
    /// records the suspended marker as its receipt identity.
    ///
    /// The frozen `max_duration_ms` is enforced as a real bound at every stage
    /// boundary. A capture that spends its admitted duration before publication
    /// has a real, validated archive and no owner receipt, so it is reported as
    /// [`CaptureState::Cancelled`] at the structurally-valid evidence level
    /// rather than published past its budget or discarded silently.
    ///
    /// A wrong source or fence is refused BEFORE any protected read, and before
    /// any owner evidence is used. The presented export fence is compared for
    /// COMPLETE equality against the Kernel's own live authority fence — not
    /// through `StateFence::is_compatible_with`, whose one-directional `None`
    /// wildcards would let an absent revision match. I15-02 keeps "Principal
    /// identity is issued by Kernel, never self-declared", and I5.6 requires
    /// admission to "verify State Fence, authority and expected current
    /// revisions": the Kernel's own fence is therefore the only acceptable
    /// authority for the evidence it admits, and a presented fence that is not
    /// it is not a proof of anything this owner is willing to act on.
    #[allow(
        clippy::unused_self,
        reason = "governed owner seam keeps &self receivers; the work root binds composition"
    )]
    pub fn capture(
        &self,
        request: &CaptureRequest,
        publisher: &mut impl PublicationPort,
    ) -> Result<CaptureReport, KernelCaptureError> {
        require_capture_admitted(&request.caller)?;
        request.plan.validate()?;
        // Kernel authority fence first: a wrong fence is refused before evidence.
        gate_kernel_authority_fence(request)?;
        let duration = CaptureDuration::start(request.plan.budgets);
        gate_class_capability(request)?;
        gate_approved_manifest_digests(request)?;
        // The ORS owner's own pending-operation identities are the frontier.
        let unresolved_count = observed_unresolved_frontier(request)?.len() as u64;
        require_suspended_claim_matches_frontier(request, unresolved_count)?;
        let relation = snapshot_relation(&SnapshotEvidence::from_request(request))?;
        Self::validate_snapshot_relation(&relation)?;
        duration.check()?;
        let member_dispositions = check_denominator(request)?;
        check_budgets(request)?;
        duration.check()?;
        let bundle = BackupBundle::build(assemble_input(request))
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        duration.check()?;
        bundle
            .validate()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        let bytes = bundle
            .encode()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        duration.check()?;
        let archive_sha256 = bundle
            .bundle_sha256()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        let identities = ArchiveIdentities::from_bundle(&bundle, archive_sha256);
        let operation_id = format!("capture-publish-{}", identities.backup_id);
        let idempotency_key = format!("{}:{}", identities.backup_id, identities.archive_sha256);
        // The last point at which no owner effect has happened. A capture that
        // is already over its admitted duration here produced real bytes and
        // owns no publication receipt, so the honest terminal state is a
        // cancelled one: publishing anyway would exceed the authorisation the
        // caller granted, and dropping the bytes would hide that a validated
        // archive exists.
        if duration.is_spent() {
            return cancelled_report(
                &identities,
                request.plan.class,
                operation_id,
                member_dispositions,
                &bundle.export_fence.state_fence,
            );
        }
        let receipt = match publisher.publish_once(&operation_id, &idempotency_key, &bytes) {
            Ok(receipt) => receipt,
            Err(KernelCaptureError::PublicationUnknown(_)) => publisher.reconcile(&operation_id)?,
            Err(other) => return Err(other),
        };
        let archive = PublishedArchive {
            backup_id: identities.backup_id.clone(),
            archive_sha256: identities.archive_sha256.clone(),
            operation_id: operation_id.clone(),
            idempotency_key,
        };
        if receipt.operation_id != archive.operation_id
            || receipt.archive_sha256 != archive.archive_sha256
            || !receipt.durable
        {
            return Err(KernelCaptureError::PublicationUnknown(operation_id));
        }
        // The frontier is the OBSERVED unresolved-effect count read from the ORS
        // owner's own pending-operation identities, cross-checked against the
        // producer's claim above. A caller-asserted integer never decides this.
        let (state, receipt_identity) =
            terminal_capture_decision(request, unresolved_count, &operation_id);
        // The provenance qualifier is bound to the OWNER-ISSUED receipt, never to
        // the report's `receipt_identity`. That field is documented as "publication
        // receipt identity, or the suspended-operations marker", so on a capture
        // with an unresolved frontier it holds a coordinator-computed
        // `suspended:<count>` string. Naming the qualifier from it would let a
        // string this owner invented stand in for an owner receipt, which is
        // precisely the substitution `ArchiveFenceProof::CaptureOwnerProven` is
        // supposed to make impossible. The value bound here is the operation
        // identity the OWNER returned, and the two comparisons above already
        // proved it equals this operation's identity AND that the same receipt
        // names this operation's archive digest, so the receipt is bound to this
        // operation's content and not merely to a predictable name.
        let archived_fence_proof = ArchiveFenceProof::CaptureOwnerProven {
            capture_receipt: receipt.operation_id.clone(),
        };
        // The report's own `receipt_identity` keeps its documented two-way
        // meaning (the operation identity, or the suspended-operations marker
        // when the archive carries a bounded unresolved frontier), so a reader of
        // the report can tell which of the two it is looking at. It is NOT what
        // the provenance qualifier is named from, for the reason above.
        Ok(CaptureReport {
            backup_id: identities.backup_id,
            class: request.plan.class,
            archive_sha256: identities.archive_sha256,
            // The producing owner is this very operation, so the archive's own
            // source installation and owner contract are the frozen plan's and
            // the export fence's own declared values, and the fence digest is
            // the one the bundle format computed and validated at build.
            source_installation: identities.source_installation,
            owner_contract: identities.owner_contract,
            export_fence_digest: identities.export_fence_digest,
            operation_id,
            state,
            // The capture really did build, validate and publish once through
            // the admitted port, so it is the class/compatibility qualified
            // level; the class ceiling still bounds what the archive may claim.
            evidence_level: CaptureEvidenceLevel::ClassQualified,
            class_ceiling: identities.class_ceiling,
            // The producing operation is this owner, so the published fence IS
            // the frozen export fence of the operation in flight: the relation is
            // exact over the complete value, and provenance is owner-proven
            // because this operation is the one that durably published those
            // bytes. The verify path is where a carried archive carries an
            // earlier value's fence and no provenance.
            archived_fence_relation: ArchiveFenceRelation::ExactFenceValue,
            archived_fence_restrictions: archive_fence_restrictions(
                ArchiveFenceRelation::ExactFenceValue,
                &archived_fence_proof,
            ),
            archived_fence_relation_contract_version: ARCHIVE_FENCE_RELATION_CONTRACT_VERSION,
            archived_state_fence_digest: archived_state_fence_digest(
                &bundle.export_fence.state_fence,
            )?,
            member_dispositions,
            receipt_identity,
            archived_fence_proof,
        })
    }

    /// Verifies one archive without restoration effects or installation
    /// mutation: admitted gate, `BackupBundle::decode` plus repeated
    /// validation, and the structural relation between the archive's COMPLETE
    /// fence and the live session fence. No publication happens here and nothing
    /// is mutated (`&self` only); the report state follows class completeness.
    ///
    /// A structurally valid FOREIGN, AHEAD or DIVERGENT archive is answered here,
    /// as a candidate carrying its exact [`ArchiveFenceRelation`] and its
    /// [`archive_fence_restrictions`] tokens. It is not refused and not reported
    /// as `invalid`, because nothing about it fails the archive/fence contract;
    /// the relation is what tells the restore owner it is not this installation's
    /// current history. This is the #2863 change from the previous authority-epoch
    /// -only classifier, which refused those archives.
    ///
    /// The proof qualifier is [`ArchiveFenceProof::StructuralOnly`] on every
    /// answer this path can produce today. Equal fence values, an exact match, or
    /// a same-lineage older value are NOT evidence that this installation produced
    /// the bytes: nothing on this path authenticates origin, so the relation is
    /// structural caller-supplied evidence until #2862 supplies owner provenance.
    ///
    /// `operation_id` is the identity the admitted caller already bound. This
    /// owner reports it back and never mints one: I5.27 defines idempotency
    /// over canonical bytes, "not over caller spelling or an unversioned hash",
    /// so a fabricated `verify-only-{backup_id}` would be a spelling, not an
    /// operation identity.
    ///
    /// The report also carries the archive's own source/provenance commitments
    /// (`source_installation`, `owner_contract`, `export_fence_digest`), read
    /// out of the decoded `export_fence` and `manifest`. A caller that keeps
    /// them in its canonical request digest is what makes "the same bytes,
    /// exported by a different owner or from a different installation" a
    /// different operation rather than a replay (#2883 instruction 6); reading
    /// them here is a decode, not a second validation, so no check is duplicated
    /// and none is weakened.
    ///
    /// The decoded archive's own cross-owner snapshot relation is built and
    /// validated here too, through the same implementation the capture contour
    /// uses. A structurally decodable archive whose carried owner evidence does
    /// not form a coherent relation — empty cursors, incompatible owner fences,
    /// a foreign installation or lineage — is not a verifiable capture, and
    /// reporting it as one would let a caller substitute a self-consistent
    /// decode for the owner-relation proof I5.16 requires.
    ///
    /// This contour reads no `FrozenCapturePlan`, so it enforces no duration
    /// budget and produces no cancellation: there is no admitted operation
    /// whose authorisation could be spent, and no publication happens here.
    #[allow(
        clippy::unused_self,
        reason = "governed owner seam keeps &self receivers; the work root binds composition"
    )]
    pub fn verify_only(
        &self,
        bytes: &[u8],
        caller: &CaptureCallerAuth,
        kernel_fence: &StateFence,
        operation_id: &str,
    ) -> Result<CaptureReport, KernelCaptureError> {
        require_capture_admitted(caller)?;
        let bundle = BackupBundle::decode(bytes)
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        bundle
            .validate()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        // The cross-owner snapshot relation is built and validated first, exactly
        // as on the capture contour: a structurally decodable archive whose
        // carried owner evidence does not form a coherent relation is not a
        // verifiable capture.
        let relation = snapshot_relation(&SnapshotEvidence::from_bundle(&bundle))?;
        Self::validate_snapshot_relation(&relation)?;
        // The relation is TOTAL over the archived complete fence value: a
        // foreign, ahead or divergent archive is a structural candidate carrying
        // its exact relation, not a refusal. `invalid` is reserved for a failure
        // of the archive/fence contract itself, which `decode`/`validate` above
        // already decided.
        let archived_fence_relation =
            classify_archived_fence(&bundle.export_fence.state_fence, kernel_fence);
        // Nothing on this path authenticates the archive as produced by THIS
        // installation: no retained-artifact owner issues a capture receipt here
        // (there is no production `impl PublicationPort`), so a relation computed
        // from caller-presented bytes is unproven structural evidence whatever
        // the relation is. #2862 owns the producer that will change this.
        let archived_fence_proof = ArchiveFenceProof::StructuralOnly;
        let archive_sha256 = bundle
            .bundle_sha256()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        let backup_id = bundle.manifest.backup_id.clone();
        let class = bundle.manifest.class;
        // The archive's own source and provenance, read out of the decoded fence
        // and manifest rather than from the verifying session. I5.27 requires
        // them in the canonical request digest because archive SHA-256 alone is
        // content integrity, not the source/capture operation identity. Two are
        // the archive's own declared text (`export_fence.export_id`,
        // `manifest.source_adapter`); the fence digest is the manifest's
        // precomputed `export_fence_sha256`, which `BackupBundle::validate` has
        // already recomputed and re-bound on this decode, so it is never a digest
        // recomputed here.
        let source_installation = bundle.export_fence.export_id.clone();
        let owner_contract = bundle.manifest.source_adapter.clone();
        let export_fence_digest = bundle.manifest.export_fence_sha256.clone();
        let mut member_dispositions = member_disposition_list(
            &bundle.canonical_events,
            &bundle.projections,
            &bundle.receipts,
            &bundle.blobs,
            &bundle.purge_ledger,
            &bundle.artifacts,
        )?;
        // The archive's OWN owner-declared members are retained beside its carried
        // content, through the same adapter the capture contour uses, so a decoded
        // archive reports the same one-disposition-per-member set the capture
        // contour produced.
        let owner_declared = owner_fence_dispositions(
            &bundle.export_fence,
            bundle.ors_snapshot.as_ref(),
            bundle.watchdog_spool.as_ref(),
            bundle.host_audit.as_ref(),
        )?;
        member_dispositions.extend(owner_declared);
        let state = if class == BackupClass::FullRecovery {
            CaptureState::Complete
        } else {
            CaptureState::Incomplete {
                reason: "degraded class; operational recovery unavailable".to_owned(),
            }
        };
        Ok(CaptureReport {
            operation_id: operation_id.to_owned(),
            backup_id,
            class,
            archive_sha256,
            source_installation,
            owner_contract,
            export_fence_digest,
            state,
            // Decoding, validating and relating bytes is the whole of this
            // path: no retained capture artifact is looked up, so the result
            // is a structurally valid candidate and never a provenance-bound
            // or class-qualified archive.
            evidence_level: CaptureEvidenceLevel::StructurallyValidCandidate,
            // A valid `canonical_only_degraded` or `scope_export` reports its
            // exact lower ceiling from the archive's own class instead of
            // inheriting the collapsed degraded-class reason as its only
            // answer.
            class_ceiling: class.evidence_level(),
            archived_fence_relation,
            archived_fence_restrictions: archive_fence_restrictions(
                archived_fence_relation,
                &archived_fence_proof,
            ),
            archived_fence_relation_contract_version: ARCHIVE_FENCE_RELATION_CONTRACT_VERSION,
            // Commits the exact COMPLETE fence value the relation above was
            // computed from. It is a dedicated digest over that value's canonical
            // encoding, not the manifest's `export_fence_sha256` and not any plan
            // or approval digest.
            archived_state_fence_digest: archived_state_fence_digest(
                &bundle.export_fence.state_fence,
            )?,
            member_dispositions,
            receipt_identity: None,
            archived_fence_proof,
        })
    }

    /// Returns the archive format's own content digest of the PRESENTED bytes, or
    /// `None` when those bytes are not a decodable, internally valid ECXF bundle.
    ///
    /// This exists for one caller: `request_dispatch.rs` must decide whether bytes
    /// presented under an already-bound verification key are the archive that key is
    /// bound to (#2802 Work 3, "changed bytes under the same identity conflict"), and
    /// on the path where [`Self::verify_only`] returns `Err` there is no
    /// [`CaptureReport`] to read an `archive_sha256` from. The digest is computed HERE
    /// rather than in the route because this module is the one that owns the
    /// `BackupBundle` API; the route holds presented bytes and nothing else.
    ///
    /// It is the decoded bundle's digest, never a digest of the presented bytes, and
    /// that is load-bearing: a durable row stores `BackupBundle::bundle_sha256`, which
    /// is a digest of the canonical encoding of the DECODED bundle, so comparing
    /// caller bytes would refuse a re-spelled copy of the very archive the key is
    /// bound to. The route must be able to say "same archive" as well as "changed
    /// archive", and only the format's own digest can say it.
    ///
    /// `None` is the honest answer for bytes that are not an archive at all: there is
    /// no canonical archive identity to compare, and inventing a raw-bytes digest
    /// domain here would create a second, caller-movable notion of archive identity.
    /// The caller keeps its own structural refusal on that path.
    pub fn presented_archive_digest(bytes: &[u8]) -> Option<String> {
        let bundle = BackupBundle::decode(bytes).ok()?;
        bundle.bundle_sha256().ok()
    }

    /// Validates one recorded snapshot relation for tests and the coordinator:
    /// timestamps alone fail, and empty cursors or lineage refuse as
    /// incoherent. No global transaction is assumed.
    pub fn validate_snapshot_relation(
        relation: &SnapshotRelation,
    ) -> Result<(), KernelCaptureError> {
        relation.validate_relation()
    }
}

/// Classifies one archived `StateFence` against the live session fence.
///
/// The archived fence is already validated internally by the bundle, so this
/// function decides ONLY the structural relation and is TOTAL: every pair of
/// well-formed fences maps to exactly one [`ArchiveFenceRelation`], and no
/// relation value is ever a refusal. That is the point of #2863. The previous
/// classifier returned `Err(RelationIncoherent)` for a foreign lineage or an
/// ahead epoch, which the front door then rendered as `invalid` — collapsing
/// "structurally valid archive whose fence is not ours" into "this archive is
/// malformed". A valid foreign, ahead or divergent archive is a structural
/// CANDIDATE carrying its exact relation and its restrictions; only a failure of
/// the archive/fence contract itself is `invalid`, and that is decided before
/// this function is reached.
///
/// Complete equality is checked FIRST and over EVERY field, so
/// [`ArchiveFenceRelation::ExactFenceValue`] requires full `StateFence`
/// equality. `EpochRelation::Same` alone is never sufficient, and differing
/// optional revisions can never produce an exact-current statement.
///
/// No ordering is invented. Only [`EpochRelation`] orders, and only the
/// authority epoch's `(lineage_id, sequence)` tuple. Resource generations and
/// the optional revision counters are separate owner contracts with no
/// cross-counter order, so an older epoch with a numerically higher generation
/// is [`ArchiveFenceRelation::SameAuthorityDivergent`] — neither this
/// installation's history and not archive corruption — and a one-sided optional
/// revision, which cannot be compared at all, is
/// [`ArchiveFenceRelation::IncomparableOrUnknown`] rather than an invented
/// contradiction. `StateFence::is_compatible_with` is deliberately not consulted
/// for the same reason as before: its one-directional `None` wildcards would
/// turn an absent revision into a match.
fn classify_archived_fence(archived: &StateFence, current: &StateFence) -> ArchiveFenceRelation {
    // Complete equality over every field, checked before anything else so no
    // partial match can ever be reported as the current fence value.
    if archived == current {
        return ArchiveFenceRelation::ExactFenceValue;
    }
    match archived
        .authority_epoch
        .relation_to(&current.authority_epoch)
    {
        EpochRelation::UnrelatedLineage => ArchiveFenceRelation::UnrelatedLineage,
        // Same authority epoch but different values: the generation or a
        // revision disagrees, so the two fences contradict and neither is the
        // other. Never the current value.
        EpochRelation::Same => ArchiveFenceRelation::SameAuthorityDivergent,
        // Ahead of the live authority. Established by the epoch relation alone;
        // no other field can make an ahead archive current or historical.
        EpochRelation::DirectChild | EpochRelation::SameLineageNewer => {
            ArchiveFenceRelation::SameAuthorityNewer
        }
        EpochRelation::DirectParent | EpochRelation::SameLineageOlder => {
            if fence_body_coherent(archived, current) {
                ArchiveFenceRelation::SameAuthorityOlder
            } else if optional_revision_one_sided(archived, current) {
                ArchiveFenceRelation::IncomparableOrUnknown
            } else {
                ArchiveFenceRelation::SameAuthorityDivergent
            }
        }
    }
}

/// Returns whether everything outside the authority epoch reconciles between an
/// older archived fence and the current one.
///
/// "Reconciles" is deliberately weak and contract-respecting: equal resource
/// generation, and every optional revision either equal on both sides or absent
/// on both sides. It does NOT order the generation or the revisions, so a
/// differing generation is incoherent rather than newer or older.
fn fence_body_coherent(archived: &StateFence, current: &StateFence) -> bool {
    archived.resource_generation == current.resource_generation
        && optional_revision_agrees(
            archived.task_revision.as_ref(),
            current.task_revision.as_ref(),
        )
        && optional_revision_agrees(
            archived.policy_revision.as_ref(),
            current.policy_revision.as_ref(),
        )
        && optional_revision_agrees(
            archived.integration_revision.as_ref(),
            current.integration_revision.as_ref(),
        )
}

/// Returns whether two optional revisions are comparable, and equal when they
/// are. `None` on both sides is agreement — neither fence claims a revision.
/// Anything else unequal, including one side claiming a revision the other does
/// not, is NOT agreement.
fn optional_revision_agrees<T: PartialEq>(archived: Option<&T>, current: Option<&T>) -> bool {
    archived == current
}

/// Returns whether any of the three optional revisions is claimed by exactly one
/// of the two fences, which is what makes a fence pair incomparable rather than
/// contradictory.
fn optional_revision_one_sided(archived: &StateFence, current: &StateFence) -> bool {
    fn one_sided<T: PartialEq>(left: Option<&T>, right: Option<&T>) -> bool {
        left.is_some() != right.is_some()
    }
    one_sided(
        archived.task_revision.as_ref(),
        current.task_revision.as_ref(),
    ) || one_sided(
        archived.policy_revision.as_ref(),
        current.policy_revision.as_ref(),
    ) || one_sided(
        archived.integration_revision.as_ref(),
        current.integration_revision.as_ref(),
    )
}

/// Stable class name for capability refusals and the front-door projection.
///
/// The front-door backup route reports the owner's evidenced class under this
/// exact spelling, so the closed operator/wire vocabulary stays bound in one
/// place instead of being restated in a caller.
pub(crate) fn class_name(class: BackupClass) -> &'static str {
    match class {
        BackupClass::FullRecovery => "full_recovery",
        BackupClass::CanonicalOnlyDegraded => "canonical_only_degraded",
        BackupClass::ScopeExport => "scope_export",
    }
}

/// Closed obligation-domain prefixes carried by every member disposition.
///
/// The front-door verify projection counts these domains for the operator, so
/// the prefixes are named here, beside the dispositions that emit them, rather
/// than restated as string literals in a caller. Renaming a prefix therefore
/// changes exactly one place.
pub(crate) const MEMBER_DOMAIN_CANONICAL: &str = "canonical:";
/// Receipt obligation domain prefix (see [`MEMBER_DOMAIN_CANONICAL`]).
pub(crate) const MEMBER_DOMAIN_RECEIPT: &str = "receipt:";
/// Sealed-blob obligation domain prefix (see [`MEMBER_DOMAIN_CANONICAL`]).
pub(crate) const MEMBER_DOMAIN_BLOB: &str = "blob:";

/// Counts one obligation domain inside this owner's own member dispositions.
///
/// This reads the owner's report; it never re-decodes the archive and never
/// re-derives the capture-path denominator.
pub(crate) fn member_domain_count(report: &CaptureReport, domain: &str) -> u64 {
    u64::try_from(
        report
            .member_dispositions
            .iter()
            .filter(|(member, _)| member.starts_with(domain))
            .count(),
    )
    .unwrap_or(u64::MAX)
}

/// Enforces the class capability gate: `full_recovery` requires the ORS
/// snapshot, the Watchdog spool, and manifest artifacts, refusing without
/// silent downgrade; `scope_export` requires the frozen scope to match the
/// export evidence exactly. Degraded classes carry no installation recovery
/// and are bounded by bundle validation instead.
fn gate_class_capability(request: &CaptureRequest) -> Result<(), KernelCaptureError> {
    if request.plan.class == BackupClass::FullRecovery {
        if request.ors_snapshot.is_none() {
            return Err(KernelCaptureError::ClassCapabilityUnsupported {
                class: class_name(request.plan.class),
                capability: "ors_snapshot",
            });
        }
        if request.watchdog_spool.is_none() {
            return Err(KernelCaptureError::ClassCapabilityUnsupported {
                class: class_name(request.plan.class),
                capability: "watchdog_spool",
            });
        }
        if request.artifacts.is_empty() {
            return Err(KernelCaptureError::ClassCapabilityUnsupported {
                class: class_name(request.plan.class),
                capability: "config_policy_module_build_manifests",
            });
        }
    }
    if request.plan.class == BackupClass::ScopeExport {
        let frozen = request.plan.scope_id.as_deref();
        let observed = request
            .export_fence
            .scope_id
            .as_ref()
            .map(eliot_store_api::ScopeId::as_str);
        if frozen != observed {
            return Err(KernelCaptureError::RelationIncoherent(
                "scope mismatch between frozen plan and export fence".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Refuses evidence presented under anything but the Kernel's own live
/// authority fence.
///
/// `CapturePorts::kernel_fence` is the Kernel's own authority, and I15-02 keeps
/// "Principal identity is issued by Kernel, never self-declared": the same
/// reasoning applies to the fence the export was admitted under, and I5.6
/// requires admission to "verify State Fence, authority and expected current
/// revisions" before any source is read. A `CaptureRequest` that carried no
/// Kernel fence at all made that verification impossible — the presented fence
/// would have been checked against nothing.
///
/// The comparison is COMPLETE `StateFence` equality. `is_compatible_with` is
/// deliberately not used: its one-directional `None` wildcards would let an
/// absent optional revision pass as a match, which is exactly the
/// validated-then-discarded guarantee this gate closes.
fn gate_kernel_authority_fence(request: &CaptureRequest) -> Result<(), KernelCaptureError> {
    if request.export_fence.state_fence != request.kernel_fence {
        return Err(KernelCaptureError::RelationIncoherent(
            "export fence does not match the Kernel authority fence it was admitted under"
                .to_owned(),
        ));
    }
    Ok(())
}

/// The exact artifact kinds the archive format's own class gate requires
/// (`eliot-backup`'s `validate_class_requirements` `REQUIRED` set), spelled
/// once here so this owner refuses an unknown kind with the same vocabulary the
/// bundle would later refuse it with.
const REQUIRED_ARTIFACT_KINDS: [&str; 4] = ["config", "policy", "module", "host_dependency_build"];

/// Binds the frozen plan's approved digests to the artifacts actually carried.
///
/// `FrozenCapturePlan::build_digest` and `.policy_digest` are otherwise only
/// SHAPE-validated 64-hex strings: nothing would ever compare them to the
/// package actually being used, which is exactly the guarantee I00-14 requires
/// ("manifest/package digest equality for the package actually being used").
/// A 64-hex value that is never compared is a claim, not a binding.
///
/// The check is deliberately over each artifact's OWN recorded `sha256` rather
/// than a checksum recomputed here. `BackupArtifact::validate` already re-derives
/// the digest from the carried bytes and the bundle re-validates every artifact,
/// so the recorded field is the original recorded value: recomputing over the
/// bytes in hand would REPLACE the proof instead of checking it.
///
/// That also closes the substitution hole: an artifact whose `kind` is one of
/// the four approved names can only satisfy the plan if its recorded digest IS
/// the approved digest, so a key file, a credential or a live database
/// presented under an approved `kind` cannot be laundered into a full-recovery
/// archive.
fn gate_approved_manifest_digests(request: &CaptureRequest) -> Result<(), KernelCaptureError> {
    if request.artifacts.is_empty() {
        return Ok(());
    }
    for artifact in &request.artifacts {
        if !REQUIRED_ARTIFACT_KINDS.contains(&artifact.kind.as_str()) {
            return Err(KernelCaptureError::OwnerEvidenceInvalid(format!(
                "artifact.kind {} is not one of the four class-gate manifest kinds",
                artifact.kind
            )));
        }
    }
    if !request
        .artifacts
        .iter()
        .any(|artifact| artifact.kind == "policy" && artifact.sha256 == request.plan.policy_digest)
    {
        return Err(KernelCaptureError::OwnerEvidenceInvalid(
            "artifact kind policy is not bound to the frozen plan field policy_digest".to_owned(),
        ));
    }
    if !request.artifacts.iter().any(|artifact| {
        artifact.kind == "host_dependency_build" && artifact.sha256 == request.plan.build_digest
    }) {
        return Err(KernelCaptureError::OwnerEvidenceInvalid(
            "artifact kind host_dependency_build is not bound to the frozen plan field build_digest"
                .to_owned(),
        ));
    }
    Ok(())
}

/// The unresolved-effect frontier this owner observes, read from the ORS
/// owner's own evidence rather than from a caller's arithmetic.
///
/// I5.13 requires the `OrsSnapshotFence` to record "pending-operation identities
/// and hashes", and the identities it records ARE the frontier: a capture that
/// reports completeness against an independently supplied integer could claim a
/// clean frontier while the ORS owner recorded unresolved operations. An absent
/// ORS snapshot is an empty frontier, never a default of "none claimed".
///
/// The identities are read through the archive owner's own suspended derivation
/// (`owner_suspended_recovery_refs`), which validates the fence before counting
/// it. A raw read of `pending_operation_ids` would count rows the archive owner
/// itself refuses.
fn observed_unresolved_frontier(
    request: &CaptureRequest,
) -> Result<Vec<String>, KernelCaptureError> {
    request
        .ors_snapshot
        .as_ref()
        .map_or(Ok(Vec::new()), owner_suspended_recovery_refs)
}

/// Refuses a producer whose asserted suspended count disagrees with the ORS
/// owner's own pending-operation identities.
///
/// The observed frontier is authoritative (I5.13 requires the ORS snapshot to
/// record "pending-operation identities and hashes"), but silently preferring
/// the owner's count over the producer's would hide that the two disagree, so
/// the disagreement itself is the refusal: a caller cannot mark a capture
/// `Complete` by asserting a count the ORS owner contradicts.
fn require_suspended_claim_matches_frontier(
    request: &CaptureRequest,
    observed: u64,
) -> Result<(), KernelCaptureError> {
    if request.suspended_count != observed {
        return Err(KernelCaptureError::OwnerEvidenceInvalid(
            "capture.suspended_count does not match the observed ORS pending-operation frontier"
                .to_owned(),
        ));
    }
    Ok(())
}

/// The terminal state and the report's receipt identity, decided from the
/// OBSERVED unresolved-effect frontier.
///
/// A bounded frontier is not corruption: a `full_recovery` capture with
/// suspended operations still completes and records the suspended marker as its
/// receipt identity, which is what I5.13 requires for a legitimate independent
/// snapshot with bounded unresolved operations. A degraded class that cannot
/// carry them reports an explicit incomplete result instead of over-claiming,
/// and an empty frontier reports the publication operation identity.
///
/// `unresolved_count` is the observed frontier length, already cross-checked
/// against the producer's claim; nothing here reads `CaptureRequest::
/// suspended_count`.
fn terminal_capture_decision(
    request: &CaptureRequest,
    unresolved_count: u64,
    operation_id: &str,
) -> (CaptureState, Option<String>) {
    let state = if unresolved_count > 0 && request.plan.class != BackupClass::FullRecovery {
        CaptureState::Incomplete {
            reason: "bounded suspended operations exceed degraded class ceiling".to_owned(),
        }
    } else {
        CaptureState::Complete
    };
    let receipt_identity = if unresolved_count > 0 {
        Some(format!("suspended:{unresolved_count}"))
    } else {
        Some(operation_id.to_owned())
    };
    (state, receipt_identity)
}

/// The exact per-owner evidence one snapshot relation is derived from.
///
/// `capture` reads it from the admitted [`CaptureRequest`]; `verify_only` reads
/// the same fields out of the archive it just decoded. Both contours therefore
/// derive the relation through one implementation and cannot drift into two
/// definitions of what a coherent relation is.
struct SnapshotEvidence<'a> {
    /// Coherent canonical export fence binding the evidence.
    export_fence: &'a ExportFence,
    /// Canonical event records covered by the evidence.
    canonical_events: &'a [CanonicalRecord],
    /// Canonical write receipts covered by the evidence.
    receipts: &'a [WriteReceipt],
    /// Purge ledger entries covered by the evidence.
    purge_ledger: &'a [PurgeLedgerEntry],
    /// Logical ORS snapshot fence, when the class carries one.
    ors_snapshot: Option<&'a OrsSnapshotFence>,
    /// Bounded Watchdog spool fence, when the class carries one.
    watchdog_spool: Option<&'a WatchdogSpoolFence>,
}

impl<'a> SnapshotEvidence<'a> {
    /// Reads the relation-bearing evidence out of one admitted request.
    fn from_request(request: &'a CaptureRequest) -> Self {
        Self {
            export_fence: &request.export_fence,
            canonical_events: &request.canonical_events,
            receipts: &request.receipts,
            purge_ledger: &request.purge_ledger,
            ors_snapshot: request.ors_snapshot.as_ref(),
            watchdog_spool: request.watchdog_spool.as_ref(),
        }
    }

    /// Reads the same evidence out of one decoded archive.
    fn from_bundle(bundle: &'a BackupBundle) -> Self {
        Self {
            export_fence: &bundle.export_fence,
            canonical_events: &bundle.canonical_events,
            receipts: &bundle.receipts,
            purge_ledger: &bundle.purge_ledger,
            ors_snapshot: bundle.ors_snapshot.as_ref(),
            watchdog_spool: bundle.watchdog_spool.as_ref(),
        }
    }
}

/// The archive-derived identities every capture report carries.
///
/// They are read out of the bundle this owner built, validated and encoded, so
/// a report can never mix the archive's own commitments with the verifying
/// session's. I5.27 requires the source installation and the owner contract in
/// the canonical request digest, because an archive SHA-256 alone is content
/// integrity and not the source/capture operation identity. `export_fence_digest`
/// is the manifest's own precomputed `export_fence_sha256`, which
/// `BackupBundle::validate` has already recomputed and re-bound on this bundle —
/// it is never a digest recomputed here.
struct ArchiveIdentities {
    /// The archive's own declared backup identity.
    backup_id: String,
    /// This bundle's own content digest.
    archive_sha256: String,
    /// The archive's own declared source installation.
    source_installation: String,
    /// The archive's own declared owner contract.
    owner_contract: String,
    /// The manifest's precomputed export-fence digest.
    export_fence_digest: String,
    /// The exact restore proof ceiling the archive's own class permits.
    class_ceiling: RestoreEvidenceLevel,
}

impl ArchiveIdentities {
    /// Reads the identities out of one already-validated bundle and its content
    /// digest.
    fn from_bundle(bundle: &BackupBundle, archive_sha256: String) -> Self {
        Self {
            backup_id: bundle.manifest.backup_id.clone(),
            archive_sha256,
            source_installation: bundle.export_fence.export_id.clone(),
            owner_contract: bundle.manifest.source_adapter.clone(),
            export_fence_digest: bundle.manifest.export_fence_sha256.clone(),
            class_ceiling: bundle.manifest.class.evidence_level(),
        }
    }
}

/// Builds the terminal report for a capture that spent its admitted duration
/// before publication.
///
/// Such a capture owns real, built and validated bytes and no owner-issued
/// publication receipt, so its terminal state is
/// [`CaptureState::Cancelled`] at the structurally-valid evidence level.
/// Reporting `Complete` would claim a receipt that does not exist; reporting
/// the qualified level would claim a provenance binding that was never
/// obtained; discarding the bytes silently would hide that a validated archive
/// exists at all. I5.13 keeps backup existence from being recovery proof, which
/// is exactly why a cancelled capture is not a completed one.
///
/// The archived fence VALUE is real — it is the frozen export fence of the
/// operation in flight — so the structural relation is exact over the complete
/// value. Its proof stays [`ArchiveFenceProof::StructuralOnly`]: publication
/// never happened, so no owner issued a receipt for those bytes and this owner
/// cannot claim more than structural evidence.
fn cancelled_report(
    identities: &ArchiveIdentities,
    class: BackupClass,
    operation_id: String,
    member_dispositions: Vec<(String, String)>,
    archived_fence: &StateFence,
) -> Result<CaptureReport, KernelCaptureError> {
    let archived_fence_proof = ArchiveFenceProof::StructuralOnly;
    let archived_fence_restrictions =
        archive_fence_restrictions(ArchiveFenceRelation::ExactFenceValue, &archived_fence_proof);
    Ok(CaptureReport {
        backup_id: identities.backup_id.clone(),
        class,
        archive_sha256: identities.archive_sha256.clone(),
        source_installation: identities.source_installation.clone(),
        owner_contract: identities.owner_contract.clone(),
        export_fence_digest: identities.export_fence_digest.clone(),
        operation_id,
        state: CaptureState::Cancelled,
        evidence_level: CaptureEvidenceLevel::StructurallyValidCandidate,
        class_ceiling: identities.class_ceiling,
        archived_fence_relation: ArchiveFenceRelation::ExactFenceValue,
        archived_fence_proof,
        archived_fence_restrictions,
        archived_fence_relation_contract_version: ARCHIVE_FENCE_RELATION_CONTRACT_VERSION,
        archived_state_fence_digest: archived_state_fence_digest(archived_fence)?,
        member_dispositions,
        receipt_identity: None,
    })
}

/// One admitted capture operation's monotonic duration budget.
///
/// `max_duration_ms` is a ceiling on the authorisation the caller granted, so
/// it needs a real clock: this owner reads `std::time::Instant`, which is
/// monotonic, and therefore a wall-clock adjustment can neither extend nor
/// shrink an admitted duration. There is deliberately no injected clock and no
/// waiting observer — a capture that would have to wait for a cancellation
/// signal or a globally quiet instant is exactly the unbounded wait the frozen
/// budgets exist to refuse (I14.3 keeps recovery inside protected capacity).
///
/// The budget is consulted at every stage boundary rather than only at the end,
/// so an over-long capture stops as soon as it is observably over its ceiling
/// instead of running to completion and reporting afterwards.
struct CaptureDuration {
    /// Monotonic instant at which the admitted operation started.
    started: std::time::Instant,
    /// The frozen ceiling from the admitted plan.
    budgets: CaptureBudgets,
}

impl CaptureDuration {
    /// Starts the budget at the moment the operation is admitted.
    fn start(budgets: CaptureBudgets) -> Self {
        Self {
            started: std::time::Instant::now(),
            budgets,
        }
    }

    /// Whole milliseconds elapsed since the operation was admitted.
    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Whether the frozen ceiling is already spent.
    fn is_spent(&self) -> bool {
        self.elapsed_ms() > self.budgets.max_duration_ms
    }

    /// Refuses the operation once its admitted duration is spent.
    fn check(&self) -> Result<(), KernelCaptureError> {
        self.budgets.check_duration(self.elapsed_ms())
    }
}

/// Builds the exact cross-owner snapshot relation from validated request
/// evidence: cursors from the ORS snapshot when present, otherwise from the
/// observed canonical coverage; lineage from the export state fence;
/// checkpoints, cutovers, and spool signals from their owners. Capture times
/// stay empty here: every accepted owner-neutral type hands this owner
/// already-acquired evidence and none reports the instant it was acquired, so
/// there is no per-owner clock to record, and times alone never satisfy the
/// relation anyway.
///
/// The pending-operation identities come from the archive owner's own suspended
/// derivation, so an ORS fence the owner refuses refuses the relation instead of
/// yielding a shortened frontier.
fn snapshot_relation(
    evidence: &SnapshotEvidence<'_>,
) -> Result<SnapshotRelation, KernelCaptureError> {
    let export_fence = evidence.export_fence;
    let receipt_cursor = evidence
        .ors_snapshot
        .map_or(evidence.receipts.len() as u64, |snapshot| {
            snapshot.last_receipt_cursor
        });
    let event_cursor = evidence
        .ors_snapshot
        .map_or(evidence.canonical_events.len() as u64, |snapshot| {
            snapshot.last_event_cursor
        });
    let outbox_cursor = evidence
        .ors_snapshot
        .map_or(0, |snapshot| snapshot.last_outbox_cursor);
    let ors_compatible = evidence
        .ors_snapshot
        .is_none_or(|snapshot| snapshot.state_fence == export_fence.state_fence);
    let watchdog_compatible = evidence
        .watchdog_spool
        .is_none_or(|spool| spool.state_fence == export_fence.state_fence);
    let purge_compatible = evidence.purge_ledger.iter().all(|entry| {
        entry
            .state_fence
            .is_compatible_with(&export_fence.state_fence)
    });
    let receipt_compatible = evidence.receipts.iter().all(|receipt| {
        receipt
            .state_fence
            .is_compatible_with(&export_fence.state_fence)
    });
    Ok(SnapshotRelation {
        installation_id: export_fence.export_id.clone(),
        store_generation: export_fence.store_generation.clone(),
        authority_lineage: export_fence
            .state_fence
            .authority_epoch
            .lineage_id
            .as_str()
            .to_owned(),
        receipt_cursor,
        event_cursor,
        outbox_cursor,
        pending_operation_ids: match evidence.ors_snapshot {
            Some(snapshot) => owner_suspended_recovery_refs(snapshot)?,
            None => Vec::new(),
        },
        // Unreportable dimensions, not empty claims: see the field docs on
        // `SnapshotRelation` in `backup_capture_ports.rs`.
        pending_operation_hashes: Vec::new(),
        checkpoint_ids: evidence
            .ors_snapshot
            .map(|snapshot| snapshot.job_checkpoint_ids.clone())
            .unwrap_or_default(),
        cutover_ids: evidence
            .ors_snapshot
            .map(|snapshot| snapshot.generation_cutover_ids.clone())
            .unwrap_or_default(),
        spool_signal_digests: evidence
            .watchdog_spool
            .map(|spool| spool.unresolved_signal_digests.clone())
            .unwrap_or_default(),
        spool_gaps: Vec::new(),
        capture_time_ms_per_owner: Vec::new(),
        fence_compatible: ors_compatible
            && watchdog_compatible
            && purge_compatible
            && receipt_compatible,
        timestamps_only: false,
    })
}

/// Builds exactly one `captured` disposition per carried source member.
/// Domain prefixes keep obligation domains disjoint so equal bytes under
/// different obligations never coalesce into one logical object, and each blob
/// is keyed by the blob owner's own full residency identity (see
/// [`owner_residency_key_digest`]) for the same reason: the content digest
/// alone is not a logical object.
///
/// The members an OWNER declared rather than carried are emitted separately by
/// [`owner_fence_dispositions`], and the denominator joins the two halves into
/// the one disposition list it is checked against.
fn member_disposition_list(
    events: &[CanonicalRecord],
    projections: &[CanonicalRecord],
    receipts: &[WriteReceipt],
    blobs: &[BackupBlob],
    purge_ledger: &[PurgeLedgerEntry],
    artifacts: &[BackupArtifact],
) -> Result<Vec<(String, String)>, KernelCaptureError> {
    let mut dispositions = Vec::new();
    for event in events {
        dispositions.push((
            format!("{}{}", MEMBER_DOMAIN_CANONICAL, event.record_id),
            "captured".to_owned(),
        ));
    }
    for projection in projections {
        dispositions.push((
            format!("projection:{}", projection.record_id),
            "captured".to_owned(),
        ));
    }
    for receipt in receipts {
        dispositions.push((
            format!("{}{}", MEMBER_DOMAIN_RECEIPT, receipt.operation_id),
            "captured".to_owned(),
        ));
    }
    for blob in blobs {
        dispositions.push((
            format!(
                "{}{}",
                MEMBER_DOMAIN_BLOB,
                owner_residency_key_digest(blob)?
            ),
            "captured".to_owned(),
        ));
    }
    for entry in purge_ledger {
        dispositions.push((format!("purge:{}", entry.purge_id), "captured".to_owned()));
    }
    for artifact in artifacts {
        dispositions.push((
            format!("artifact:{}", artifact.artifact_id),
            "captured".to_owned(),
        ));
    }
    Ok(dispositions)
}

/// Checks the complete reconciliation denominator: a consistent export fence,
/// exactly one blob per reachability hash and no unreferenced blob, an event
/// range matching the carried canonical events, and exactly one disposition
/// per expected member — carried members AND the members each owner declared in
/// its own fence. Expired or mixed-generation evidence (an inconsistent fence)
/// cannot stitch into a complete result.
///
/// The export fence's own `blob_reachability_manifest` is a `Vec<BlobHash>`, so
/// the fence bijection is still over CONTENT digests — that is the fence's own
/// element type and changing it is not this owner's to do. The per-member
/// "exactly one" count and the duplicate check, however, are over the
/// disposition list, whose blob keys are residency identities: two blobs with
/// equal content under different obligations are two distinct logical objects
/// (I5.13: "equal bytes under different obligations remain distinct logical
/// objects"), while one blob under one obligation appearing twice is a real
/// duplicate and refuses.
fn check_denominator(
    request: &CaptureRequest,
) -> Result<Vec<(String, String)>, KernelCaptureError> {
    if !request.export_fence.consistent {
        return Err(KernelCaptureError::RelationIncoherent(
            "export fence is not consistent".to_owned(),
        ));
    }
    // REACHABILITY IS COVERAGE, NOT MULTIPLICITY. The manifest is a `Vec<BlobHash>`
    // — a set of content digests that must be reachable — so the obligation it
    // states is "every reachable content digest is carried", not "carried exactly
    // once". I5.13:42 keeps "equal bytes under different obligations ... distinct
    // logical objects", so two carried blobs sharing a content digest under two
    // different residency identities is a LEGITIMATE set that this check must not
    // reject. Multiplicity is not dropped by making this a coverage check: the
    // same logical object appearing twice is still refused, by the residency-keyed
    // duplicate check below, which is strictly finer than a content-hash one.
    for hash in &request.export_fence.blob_reachability_manifest {
        let count = request
            .blobs
            .iter()
            .filter(|blob| blob.locator.hash == *hash)
            .count();
        if count == 0 {
            return Err(KernelCaptureError::DenominatorIncomplete(format!(
                "reachable blob {} is not carried by this capture",
                hash.as_str()
            )));
        }
    }
    for blob in &request.blobs {
        if !request
            .export_fence
            .blob_reachability_manifest
            .contains(&blob.locator.hash)
        {
            return Err(KernelCaptureError::DenominatorIncomplete(format!(
                "blob {} is not referenced by the export fence",
                blob.locator.hash.as_str()
            )));
        }
    }
    if request.export_fence.event_range.count != request.canonical_events.len() as u64 {
        return Err(KernelCaptureError::DenominatorIncomplete(format!(
            "event range count {} does not match {} canonical events",
            request.export_fence.event_range.count,
            request.canonical_events.len()
        )));
    }
    // The SECOND, independent expected set. Everything above enumerates members
    // from the caller's carried CONTENT lists; the members each OWNER declared
    // are enumerated here straight from that owner's own fence — the canonical
    // owner's order/history heads, the ORS owner's pending operations,
    // checkpoints and cutovers, the Watchdog owner's unresolved signals, and the
    // optional forensic Host audit's own dispositions. A16 requires every
    // expected source/member to have exactly one disposition, and an expected
    // set taken from the carried content alone cannot state that about a member
    // the owner declared and the capture never enumerated: the two copies of one
    // caller-supplied list would agree with each other whatever the owner said.
    //
    // What this cannot do, and does not claim: it cannot detect a member an
    // owner dropped from its OWN fence before this owner saw it. The fences are
    // the owner's declaration; a fence that under-declares is the owner's
    // evidence gap, not one this owner can detect from inside the capture.
    let owner_declared = owner_fence_dispositions(
        &request.export_fence,
        request.ors_snapshot.as_ref(),
        request.watchdog_spool.as_ref(),
        request.host_audit.as_ref(),
    )?;
    let mut dispositions = member_disposition_list(
        &request.canonical_events,
        &request.projections,
        &request.receipts,
        &request.blobs,
        &request.purge_ledger,
        &request.artifacts,
    )?;
    dispositions.extend(owner_declared.iter().cloned());
    for event in &request.canonical_events {
        let want = format!("canonical:{}", event.record_id);
        let count = dispositions.iter().filter(|entry| entry.0 == want).count();
        if count != 1 {
            return Err(KernelCaptureError::DenominatorIncomplete(format!(
                "canonical event {} has {count} dispositions, want exactly one",
                event.record_id
            )));
        }
    }
    for (declared, _) in &owner_declared {
        let count = dispositions
            .iter()
            .filter(|entry| &entry.0 == declared)
            .count();
        if count != 1 {
            return Err(KernelCaptureError::DenominatorIncomplete(format!(
                "owner-declared member {declared} has {count} dispositions, want exactly one"
            )));
        }
    }
    let mut seen = Vec::with_capacity(dispositions.len());
    for entry in &dispositions {
        if seen.contains(entry) {
            return Err(KernelCaptureError::DenominatorIncomplete(format!(
                "member {} has a duplicate disposition",
                entry.0
            )));
        }
        seen.push(entry.clone());
    }
    Ok(dispositions)
}

/// Serialized byte length of one evidence value for budget accounting.
fn json_len(value: &impl serde::Serialize) -> Result<u64, KernelCaptureError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len() as u64)
        .map_err(|_| KernelCaptureError::ArchiveInvalid("evidence serialization failed".to_owned()))
}

/// Per-owner evidence byte and item counts in `OWNER_COUNT` order for budget
/// accounting. Blob bytes are exact sealed-envelope lengths; every other owner
/// is measured over its canonical JSON encoding.
fn evidence_counts(
    request: &CaptureRequest,
) -> Result<([u64; OWNER_COUNT], [u64; OWNER_COUNT]), KernelCaptureError> {
    let mut canonical_bytes: u64 = 0;
    for record in request
        .canonical_events
        .iter()
        .chain(request.projections.iter())
    {
        canonical_bytes = canonical_bytes.saturating_add(json_len(record)?);
    }
    for receipt in &request.receipts {
        canonical_bytes = canonical_bytes.saturating_add(json_len(receipt)?);
    }
    let mut blob_bytes: u64 = 0;
    for blob in &request.blobs {
        blob_bytes = blob_bytes.saturating_add(blob.sealed_bytes.len() as u64);
    }
    let mut purge_bytes: u64 = 0;
    for entry in &request.purge_ledger {
        purge_bytes = purge_bytes.saturating_add(json_len(entry)?);
    }
    let mut ors_bytes: u64 = 0;
    let mut ors_items: u64 = 0;
    if let Some(snapshot) = request.ors_snapshot.as_ref() {
        ors_bytes = json_len(snapshot)?;
        ors_items = snapshot.pending_operation_ids.len() as u64;
    }
    let mut watchdog_bytes: u64 = 0;
    let mut watchdog_items: u64 = 0;
    if let Some(spool) = request.watchdog_spool.as_ref() {
        watchdog_bytes = json_len(spool)?;
        watchdog_items = spool.unresolved_signal_digests.len() as u64;
    }
    let mut host_bytes: u64 = 0;
    for artifact in &request.artifacts {
        host_bytes = host_bytes.saturating_add(artifact.bytes.len() as u64);
    }
    let mut host_items: u64 = request.artifacts.len() as u64;
    if let Some(audit) = request.host_audit.as_ref() {
        host_bytes = host_bytes.saturating_add(json_len(audit)?);
        host_items = host_items.saturating_add(1);
    }
    let bytes = [
        canonical_bytes,
        blob_bytes,
        purge_bytes,
        ors_bytes,
        watchdog_bytes,
        host_bytes,
    ];
    let items = [
        request.canonical_events.len() as u64
            + request.projections.len() as u64
            + request.receipts.len() as u64,
        request.blobs.len() as u64,
        request.purge_ledger.len() as u64,
        ors_items,
        watchdog_items,
        host_items,
    ];
    Ok((bytes, items))
}

/// Enforces the frozen budgets over per-owner and cumulative byte and work
/// counts before any archive build work begins.
fn check_budgets(request: &CaptureRequest) -> Result<(), KernelCaptureError> {
    let (bytes, items) = evidence_counts(request)?;
    request.plan.budgets.check_cumulative(&bytes)?;
    request.plan.budgets.check_work_items(&items)?;
    Ok(())
}

/// Assembles the exact `BackupInput` from validated request fields: the
/// archive identity binds the canonical export identity (nothing invented),
/// class, source, and schema come from the frozen plan, and every evidence
/// section crosses byte-identical. The purge revision binds the carried
/// ledger: zero with an empty ledger, the entry count otherwise.
///
/// ASSUMPTION (purge-ledger revision). I5.13:44 requires the manifest to bind
/// the "purge-ledger revision", and `eliot-backup` leaves that value to the
/// producer: it only refuses a nonzero revision with no ledger and a zero
/// revision with a non-empty one (`BackupBundle::validate`, "the purge revision
/// binds the purge ledger carried here"). No accepted owner-neutral purge API
/// reachable from this owner publishes a ledger-wide revision — the closest
/// thing, Host's `BackupConfigProjection::purge_ledger_revision`, lives in
/// `bins/eliot-host`, which this composition root may not depend on. The
/// carried entry count is therefore used as the binding over the ledger this
/// owner actually validated, and it is stated here rather than presented as the
/// purge owner's own declared revision.
fn assemble_input(request: &CaptureRequest) -> BackupInput {
    BackupInput {
        backup_id: request.export_fence.export_id.clone(),
        class: request.plan.class,
        source_adapter: request.plan.source_adapter.clone(),
        schema_generation: request.plan.schema_generation.clone(),
        export_fence: request.export_fence.clone(),
        canonical_events: request.canonical_events.clone(),
        projections: request.projections.clone(),
        receipts: request.receipts.clone(),
        blobs: request.blobs.clone(),
        purge_ledger: request.purge_ledger.clone(),
        ors_snapshot: request.ors_snapshot.clone(),
        artifacts: request.artifacts.clone(),
        watchdog_spool: request.watchdog_spool.clone(),
        host_audit: request.host_audit.clone(),
        missing_features: Vec::new(),
        purge_ledger_revision: if request.purge_ledger.is_empty() {
            0
        } else {
            request.purge_ledger.len() as u64
        },
    }
}
