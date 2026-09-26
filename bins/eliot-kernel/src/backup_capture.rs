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
//!   fence as current or historical ([`ArchivedFenceRelation`]): a restart,
//!   generation change, or epoch rotation must not make a genuine earlier
//!   archive unverifiable, and current-target compatibility plus epoch
//!   monotonicity stay with the isolated restore/cutover owners (A13.7
//!   "Cutover requires separate authority").
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
use eliot_contracts::{EpochRelation, StateFence};
use eliot_security_contracts::PurgeLedgerEntry;
use eliot_store_api::WriteReceipt;

use super::backup_capture_ports::{
    CaptureCallerAuth, CapturePorts, FrozenCapturePlan, KernelCaptureError, PublicationPort,
    PublishedArchive, SnapshotRelation, require_capture_admitted,
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

/// The closed relation between an archive's own fence and the live session
/// fence (issue #2802 instruction 4).
///
/// The archived fence is validated internally — `BackupBundle::validate`
/// already calls `ExportFence::validate` (which validates
/// `state_fence.validate()` and `consistent`) and already binds the fence to
/// the archive's own manifest through `export_fence_sha256` — and this relation
/// adds no weakening of either check. It records only whether the archive is
/// the current fence or this installation's own earlier authority.
///
/// Current-target compatibility and epoch monotonicity are separate decisions
/// owned by the isolated restore/cutover owners, because A13.7 states "Cutover
/// requires separate authority" and old sessions, leases, approvals, and epochs
/// do not revive. A stale or foreign archive may therefore be incompatible for
/// this target without being structurally corrupt, and this command reports
/// that honestly instead of refusing the archive or promoting it to recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchivedFenceRelation {
    /// The archived fence is the live fence of the operation: either it equals
    /// the session fence the route supplied, or this owner is the producer and
    /// published it from its own frozen export fence in the same operation.
    CurrentSession,
    /// The archived fence is an older epoch on this installation's own
    /// authority lineage: this installation's history, accepted rather than
    /// refused.
    HistoricalAuthority,
}

impl ArchivedFenceRelation {
    /// Stable operator/wire spelling of the archived-fence relation.
    ///
    /// Bound in one place beside the classification so the front door never
    /// restates the relation as its own literal.
    #[must_use]
    pub const fn as_wire_name(self) -> &'static str {
        match self {
            Self::CurrentSession => "current-session",
            Self::HistoricalAuthority => "historical-authority",
        }
    }
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
    /// Whether the archive's fence is the current session fence or this
    /// installation's own earlier authority; see [`ArchivedFenceRelation`].
    pub archived_fence_relation: ArchivedFenceRelation,
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
        gate_class_capability(request)?;
        let relation = snapshot_relation(request);
        Self::validate_snapshot_relation(&relation)?;
        let member_dispositions = check_denominator(request)?;
        check_budgets(request)?;
        let bundle = BackupBundle::build(assemble_input(request))
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        bundle
            .validate()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        let bytes = bundle
            .encode()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        let archive_sha256 = bundle
            .bundle_sha256()
            .map_err(|error| KernelCaptureError::ArchiveInvalid(error.to_string()))?;
        let backup_id = bundle.manifest.backup_id.clone();
        let operation_id = format!("capture-publish-{backup_id}");
        let idempotency_key = format!("{backup_id}:{archive_sha256}");
        let receipt = match publisher.publish_once(&operation_id, &idempotency_key, &bytes) {
            Ok(receipt) => receipt,
            Err(KernelCaptureError::PublicationUnknown(_)) => publisher.reconcile(&operation_id)?,
            Err(other) => return Err(other),
        };
        let archive = PublishedArchive {
            backup_id: backup_id.clone(),
            archive_sha256: archive_sha256.clone(),
            operation_id: operation_id.clone(),
            idempotency_key,
            durability_note: "owner-durable".to_owned(),
        };
        if receipt.operation_id != archive.operation_id
            || receipt.archive_sha256 != archive.archive_sha256
            || !receipt.durable
        {
            return Err(KernelCaptureError::PublicationUnknown(operation_id));
        }
        let state =
            if request.suspended_count > 0 && request.plan.class != BackupClass::FullRecovery {
                CaptureState::Incomplete {
                    reason: "bounded suspended operations exceed degraded class ceiling".to_owned(),
                }
            } else {
                CaptureState::Complete
            };
        let receipt_identity = if request.suspended_count > 0 {
            Some(format!("suspended:{}", request.suspended_count))
        } else {
            Some(operation_id.clone())
        };
        Ok(CaptureReport {
            backup_id,
            class: request.plan.class,
            archive_sha256,
            // The producing owner is this very operation, so the archive's own
            // source installation and owner contract are the frozen plan's and
            // the export fence's own declared values, and the fence digest is
            // the one the bundle format computed and validated at build.
            source_installation: bundle.export_fence.export_id.clone(),
            owner_contract: bundle.manifest.source_adapter.clone(),
            export_fence_digest: bundle.manifest.export_fence_sha256.clone(),
            operation_id,
            state,
            // The capture really did build, validate and publish once through
            // the admitted port, so it is the class/compatibility qualified
            // level; the class ceiling still bounds what the archive may claim.
            evidence_level: CaptureEvidenceLevel::ClassQualified,
            class_ceiling: bundle.manifest.class.evidence_level(),
            // The producing operation is this owner: the published fence is the
            // frozen export fence of the operation in flight, so no historical
            // relation applies. The verify path is where a carried archive
            // carries an earlier generation's fence.
            archived_fence_relation: ArchivedFenceRelation::CurrentSession,
            member_dispositions,
            receipt_identity,
        })
    }

    /// Verifies one archive without restoration effects or installation
    /// mutation: admitted gate, `BackupBundle::decode` plus repeated
    /// validation, and a historical relation between the archived fence and the
    /// live session fence. No publication happens here and nothing is mutated
    /// (`&self` only); the report state follows class completeness.
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
        let archived_fence_relation =
            classify_archived_fence(&bundle.export_fence.state_fence, kernel_fence)?;
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
        let member_dispositions = member_disposition_list(
            &bundle.canonical_events,
            &bundle.projections,
            &bundle.receipts,
            &bundle.blobs,
            &bundle.purge_ledger,
            &bundle.artifacts,
        );
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
            member_dispositions,
            receipt_identity: None,
        })
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
/// The archived fence is already validated internally by the bundle; this
/// decides only the relation, and it replaces the exact-equality gate that made
/// a genuine earlier-generation archive unverifiable after a restart, a
/// generation change, or an epoch rotation.
///
/// The decision uses `EpochId::relation_to` on the authority epoch only.
/// `StateFence::is_compatible_with` is deliberately not the gate: it also
/// requires `resource_generation` equality, so it refuses every archive after
/// any generation change — the defect this replaces — and A13.7's
/// schema/format compatibility and Authority Epoch monotonicity checks belong
/// to the isolated restore, not to a read-only verify.
///
/// An older epoch on the same lineage is this installation's own history and is
/// accepted as [`ArchivedFenceRelation::HistoricalAuthority`]. A foreign
/// lineage is not this installation's history and refuses; so does an epoch
/// ahead of the live session, which is not a historical archive and whose
/// monotonicity this command does not judge.
fn classify_archived_fence(
    archived: &StateFence,
    current: &StateFence,
) -> Result<ArchivedFenceRelation, KernelCaptureError> {
    match archived
        .authority_epoch
        .relation_to(&current.authority_epoch)
    {
        EpochRelation::Same => Ok(ArchivedFenceRelation::CurrentSession),
        EpochRelation::DirectParent | EpochRelation::SameLineageOlder => {
            Ok(ArchivedFenceRelation::HistoricalAuthority)
        }
        EpochRelation::DirectChild | EpochRelation::SameLineageNewer => {
            Err(KernelCaptureError::RelationIncoherent(
                "archive authority epoch is ahead of the current session epoch".to_owned(),
            ))
        }
        EpochRelation::UnrelatedLineage => Err(KernelCaptureError::RelationIncoherent(
            "archive authority lineage is not this installation's lineage".to_owned(),
        )),
    }
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

/// Builds the exact cross-owner snapshot relation from validated request
/// evidence: cursors from the ORS snapshot when present, otherwise from the
/// observed canonical coverage; lineage from the export state fence;
/// checkpoints, cutovers, and spool signals from their owners. Capture times
/// stay empty here: production composition records per-owner capture times,
/// and times alone never satisfy the relation.
fn snapshot_relation(request: &CaptureRequest) -> SnapshotRelation {
    let receipt_cursor = request
        .ors_snapshot
        .as_ref()
        .map_or(request.receipts.len() as u64, |snapshot| {
            snapshot.last_receipt_cursor
        });
    let event_cursor = request
        .ors_snapshot
        .as_ref()
        .map_or(request.canonical_events.len() as u64, |snapshot| {
            snapshot.last_event_cursor
        });
    let outbox_cursor = request
        .ors_snapshot
        .as_ref()
        .map_or(0, |snapshot| snapshot.last_outbox_cursor);
    let ors_compatible = request
        .ors_snapshot
        .as_ref()
        .is_none_or(|snapshot| snapshot.state_fence == request.export_fence.state_fence);
    let watchdog_compatible = request
        .watchdog_spool
        .as_ref()
        .is_none_or(|spool| spool.state_fence == request.export_fence.state_fence);
    let purge_compatible = request.purge_ledger.iter().all(|entry| {
        entry
            .state_fence
            .is_compatible_with(&request.export_fence.state_fence)
    });
    let receipt_compatible = request.receipts.iter().all(|receipt| {
        receipt
            .state_fence
            .is_compatible_with(&request.export_fence.state_fence)
    });
    SnapshotRelation {
        installation_id: request.export_fence.export_id.clone(),
        store_generation: request.export_fence.store_generation.clone(),
        authority_lineage: request
            .export_fence
            .state_fence
            .authority_epoch
            .lineage_id
            .as_str()
            .to_owned(),
        receipt_cursor,
        event_cursor,
        outbox_cursor,
        pending_operation_ids: request
            .ors_snapshot
            .as_ref()
            .map(|snapshot| snapshot.pending_operation_ids.clone())
            .unwrap_or_default(),
        pending_operation_hashes: Vec::new(),
        checkpoint_ids: request
            .ors_snapshot
            .as_ref()
            .map(|snapshot| snapshot.job_checkpoint_ids.clone())
            .unwrap_or_default(),
        cutover_ids: request
            .ors_snapshot
            .as_ref()
            .map(|snapshot| snapshot.generation_cutover_ids.clone())
            .unwrap_or_default(),
        spool_signal_digests: request
            .watchdog_spool
            .as_ref()
            .map(|spool| spool.unresolved_signal_digests.clone())
            .unwrap_or_default(),
        spool_gaps: Vec::new(),
        capture_time_ms_per_owner: Vec::new(),
        fence_compatible: ors_compatible
            && watchdog_compatible
            && purge_compatible
            && receipt_compatible,
        timestamps_only: false,
    }
}

/// Builds exactly one `captured` disposition per expected source member.
/// Domain prefixes keep obligation domains disjoint so equal bytes under
/// different obligations never coalesce into one logical object.
fn member_disposition_list(
    events: &[CanonicalRecord],
    projections: &[CanonicalRecord],
    receipts: &[WriteReceipt],
    blobs: &[BackupBlob],
    purge_ledger: &[PurgeLedgerEntry],
    artifacts: &[BackupArtifact],
) -> Vec<(String, String)> {
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
            format!("{}{}", MEMBER_DOMAIN_BLOB, blob.locator.hash.as_str()),
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
    dispositions
}

/// Checks the complete reconciliation denominator: a consistent export fence,
/// exactly one blob per reachability hash and no unreferenced blob, an event
/// range matching the carried canonical events, and exactly one disposition
/// per expected member. Expired or mixed-generation evidence (an inconsistent
/// fence) cannot stitch into a complete result.
fn check_denominator(
    request: &CaptureRequest,
) -> Result<Vec<(String, String)>, KernelCaptureError> {
    if !request.export_fence.consistent {
        return Err(KernelCaptureError::RelationIncoherent(
            "export fence is not consistent".to_owned(),
        ));
    }
    for hash in &request.export_fence.blob_reachability_manifest {
        let count = request
            .blobs
            .iter()
            .filter(|blob| blob.locator.hash == *hash)
            .count();
        if count != 1 {
            return Err(KernelCaptureError::DenominatorIncomplete(format!(
                "blob {} has {count} members, want exactly one",
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
    let dispositions = member_disposition_list(
        &request.canonical_events,
        &request.projections,
        &request.receipts,
        &request.blobs,
        &request.purge_ledger,
        &request.artifacts,
    );
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
