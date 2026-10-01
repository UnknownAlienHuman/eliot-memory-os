//! Bounded logical ORS backup-snapshot contracts (issue #953).
//!
//! I05-13: logical export only. Pages carry record digests, never raw payload
//! bytes; the snapshot is `suspended_recovery` material and never runnable
//! authority. It never copies a live `redb` file, mutates durable state, or
//! advances a canonical ordering head.
//! I05-27: canonical identity is bound at import. Source-equals-destination,
//! missing admission, or unbound evidence is rejected, never relabelled.
//! I14-21: unknown stays reconciling. Import receipts keep an explicit
//! per-entry outcome including `Unresolved`; callers attest full validation
//! via [`OrsBackupImportReceipt::known_zero_unresolved`], which since issue
//! #953/A17 requires a [`CurrentOwnerValidation`] — a record of what the
//! CURRENT owner was asked about the receipt's members and what it answered,
//! observed from the store's own live recovery rows — and compares that
//! record's asked-about roster against the receipt's members in both
//! directions. A zero `unresolved_count` is not a zero somebody validated, so
//! it is not trusted. No blind retry.
//!
//! The same issue then found the denominator itself was the vector it checked:
//! both the record's roster and the receipt's member set were projections of the
//! one caller-supplied `per_entry` vector, so a missing import member compared
//! equal and the gate could not fire. The expected set is now
//! [`OrsBackupSnapshot::expected_member_roster`] — the member identities the
//! validated archive itself declares, with family plus record identity — and
//! [`OrsBackupImportReceipt::owner_validation_is_complete`] requires the
//! expected members, the provided outcomes and the consulted roster to be three
//! rosters that agree. `unresolved_count` is derived from the outcomes inside
//! [`OrsBackupImportReceipt::new`] rather than asserted beside them.
//!
//! Issue #2884 adds the typed row-family cursor. A family that has no canonical
//! operation order cannot share the operational `after_order` window, so it is
//! paged by its own total order through [`OrsFamilyCursor`]: an owner-issued
//! [`OrsFamilySnapshotIdentity`] freezes the family's durable revision and
//! streamed content root, and the cursor names the exact durable-key prefix the
//! owner already emitted. [`OrsFamilyRowChain`] is the one hash-chain
//! construction behind both, so a continuation can extend a proved prefix
//! without re-reading it while a verifier re-derives the same prefix from
//! durable state alone. [`RowFamilyKind::uses_family_cursor`] is the closed
//! discriminator. The family snapshot identity and the outstanding next cursor
//! are part of [`OrsBackupSnapshot::snapshot_digest`], and a snapshot that
//! declares no family denominator can never validate as `Complete`.
//!
//! Issue #1971 makes that machinery serve a SECOND family. The versioned-artifact
//! family is cursor-paged for the same reason
//! [`RowFamilyKind::uses_family_cursor`] already names it: its rows carry no
//! operation order. Each paged family keeps its OWN named request cursor, page
//! continuation and snapshot identity rather than sharing one slot, because each
//! of those slots refuses a cursor frozen for a different family — sharing one
//! would let one family's table be paged under another family's denominator. A
//! `Complete` snapshot therefore requires a frozen identity for every cursor-
//! paged family, and a page is final only when the operational window AND every
//! paged family are closed.
//!
//! Issue #953 binds the capture to ONE owner-established read consistency
//! point and rebinds every page digest to its own token. Three contract changes
//! carry that:
//! - [`OrsBackupPage`] is now self-describing: it carries the
//!   [`OrsBackupPage::fence_token`] the store derived from the state it actually
//!   observed through the capture transaction, plus the creation/expiry pair that
//!   bounds how long the page stays triageable. A page that does not state its own
//!   token cannot have its digest recomputed, which is why the digest used to be
//!   shape-checked only and independently sourced pages could be mixed.
//! - [`OrsBackupPage::expected_page_digest`] is the ONE digest derivation over a
//!   page. The store produces the page with it and the validators re-derive it
//!   from the page's own bytes, so a page that does not hash to its declared
//!   digest is refused instead of being trusted on shape.
//! - [`OrsBackupRequest::observed_fence_token`] folds the owner-observed
//!   high-water order and family revision into the page token, so the token binds
//!   owner-established state and not only caller-asserted fields.
//!
//! The same issue closes the DENOMINATOR, which the page binding above left
//! open: a snapshot's `denominator_digest` used to be shape-checked and nothing
//! recomputed it, so a caller could declare any well-formed digest and be
//! admitted as a complete capture of a denominator that was never measured.
//! Three contract changes carry that:
//! - [`OrsBackupSnapshot::snapshot_digest`] stays the ONE derivation of the
//!   denominator and is now re-derived by [`OrsBackupSnapshot::validate`], so a
//!   declared denominator that does not hash to the snapshot's own contents is
//!   [`OrsError::PayloadIntegrityMismatch`] rather than accepted on shape.
//! - [`OrsBackupEntry::payload_state`] states, per member, whether its opaque
//!   payload was obtained at all. Without it "this row's bytes were never
//!   available" had no representation, and a `Complete` snapshot could contain
//!   such a row without anything noticing.
//! - `Complete` is additionally withheld from a member roster that is not a
//!   roster. [`check_observed_members`] refuses a member identity repeated across
//!   pages, `member_roster_refused` separates a plain duplicate
//!   ([`OrsError::DuplicateConflict`]) from one whose facts disagree
//!   ([`OrsError::IntegrityProblem`]), [`check_declared_members`] refuses a
//!   declared frozen-family row count the pages do not carry, and
//!   [`check_member_payload_states`] refuses an unavailable member inside a
//!   `Complete` snapshot. Four distinct typed outcomes, because the operator
//!   action differs in each case and one generic failure would hide that.
//!
//! The same issue then found the EXHAUSTED axis, which the contracts above left
//! unrepresentable. Both continuations carried `next: Option<Cursor>`, and `None`
//! said only "this page is done with the axis"; it did not carry the axis's
//! terminal boundary, so a page that followed to carry another axis had to be
//! built under a boundary reconstructed somewhere else — and reconstructing it
//! from the axis's own pre-page cursor RE-READ the axis, emitting its rows a
//! second time while every digest in the archive still agreed. Three contract
//! changes carry the repair:
//! - [`OrsAxisState`] replaces the option on both continuations. `Open` names the
//!   cursor a following page resumes from; `Exhausted` names the walk's FINAL
//!   frontier, which the pages after it carry unchanged while emitting nothing
//!   further for that axis. The INCOMING cursor stays a separate field, because a
//!   page's own boundary and the boundary it hands on are two different facts.
//! - The state and its frontier are folded into the page digest and the
//!   denominator under their own names, so an exhausted axis can never hash like
//!   an open one and a changed terminal boundary moves the value.
//! - [`check_operational_pages`] and the new [`check_family_pages`] validate the
//!   two transitions separately. `Open` must advance to the exact next cursor;
//!   `Exhausted` may be followed only by pages that carry the same final
//!   frontier, stay exhausted, and emit zero further rows for that axis. Refusing
//!   exhausted-to-open, a changed terminal boundary, a repeated row and a skipped
//!   prefix are what make an exhausted axis inert rather than restarted. The
//!   families previously had NO cross-page chain at all — only the last page's
//!   declared state was compared with the snapshot's own fields — which is
//!   precisely the "last-page equality alone" the audit names.
//!
//! Storage-free: no `redb`, no filesystem, no `eliot-backup` dependency.
//! Distinct from `snapshot_model`; every new name starts `OrsBackup`/`Backup`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::OrsError;

/// Schema version of the backup-snapshot wire shape.
///
/// Issue #953 bumps this from `1` to `2` because the v1 wire shape cannot express
/// the property the issue requires: a v1 [`OrsBackupPage`] carries neither a fence
/// token nor a capture window, so its `page_digest` is not recomputable from the
/// page and two independently sourced pages are indistinguishable from one
/// snapshot. The bump is a WIRE constant, not durable schema: no table, column or
/// row changes, nothing is rewritten, and no migration is introduced. The existing
/// refusal mechanism covers it unchanged — [`OrsBackupSourceIdentity::new`]
/// already returns [`OrsError::MigrationRequired`] for any schema other than this
/// constant, so a v1 request or snapshot is rejected at construction and at import
/// rather than being silently reinterpreted. I05-22 keeps migration IDs and
/// checksums immutable after release, which is why this is a version bump with no
/// migration rather than an in-place widening of v1.
///
/// Issue #1971 bumps this from `2` to `3` because #1971 registers a SECOND
/// cursor-paged row family and the v2 wire shape has exactly ONE family slot on
/// each of its three carriers: [`OrsBackupRequest`] carries one
/// `process_stream_recovery_cursor`, [`OrsBackupPage`] one
/// `family_continuation`, and [`OrsBackupSnapshot`] one frozen family identity
/// plus one outstanding next cursor. A v2 shape cannot state the
/// versioned-artifact family's frozen identity at all, so a v2 page cannot carry
/// that family's entries, its continuation or its movement refusal, and a v2
/// snapshot cannot fold it into [`OrsBackupSnapshot::snapshot_digest`] or require
/// it for `Complete`. The bump is a WIRE constant again, not durable schema: no
/// table, column or row changes, nothing is rewritten, and no migration is
/// introduced. The existing refusal mechanism covers it unchanged —
/// [`OrsBackupSourceIdentity::new`] already returns [`OrsError::MigrationRequired`]
/// for any schema other than this constant, so a v1 or v2 request or snapshot is
/// rejected at construction and at import rather than being silently
/// reinterpreted. For the same I05-22 reason this is a version bump with no
/// migration rather than an in-place widening of v2.
///
/// Issue #953 bumps this from `3` to `4` because `OrsBackupEntry` gains
/// [`payload_state`](OrsBackupEntry::payload_state) and the declared
/// `denominator_digest` becomes a proved value instead of a shape-checked one.
/// A v3 shape cannot say whether a member's opaque payload was obtained, so a v3
/// archive cannot distinguish a member it read from a member whose ciphertext it
/// never obtained, and `Complete` could not be withheld for the second case. The
/// bump is a WIRE constant again, not durable schema: no table, column or row
/// changes, nothing is rewritten, and no migration is introduced — the existing
/// [`OrsError::MigrationRequired`] refusal in
/// [`OrsBackupSourceIdentity::new`] covers it exactly as it covered v2 and v3.
///
/// Issue #2967 bumps this from `4` to `5` because the v4 wire shape has NO
/// operational continuation at all, and the property this issue requires cannot be
/// stated without one. A v4 [`OrsBackupRequest`] carries only `after_order: u64`,
/// so the only boundary a v4 page could name was `after_order + page_entries *
/// page_index` — count arithmetic over a SPARSE order domain (I05-7: one ORS
/// coordinator allocates `NEXT_GLOBAL_ORDER` for reservation bookkeeping and for
/// operational rows alike, so the orders that reach `OPERATIONAL_HISTORY` contain
/// arbitrary gaps). Orders `1, 3, 5` with `page_entries = 2` therefore emitted
/// `[1, 3]`, then `[3, 5]`, then `[5]`: row 3 twice and row 5 twice. A v4 page also
/// carries no upper bound on its window, so a stable row above the declared
/// `high_water_order` was emitted under the older fence, and no v4 field lets a
/// validator refuse either fact. v5 adds [`OrsOperationalSnapshotIdentity`],
/// [`OrsOperationalCursor`] and [`OrsOperationalContinuation`] to all three carriers
/// (request, page, snapshot) and folds them into the page digest and the
/// denominator, which is the same wire-version change #2884 and #1971 each made for
/// their own cursor. The bump is a WIRE constant, not durable schema: no table,
/// column or row changes, nothing is rewritten, and no migration is introduced.
/// A v4 snapshot is therefore NEVER silently promoted to the operational-coverage
/// claim: the existing [`OrsError::MigrationRequired`] refusal in
/// [`OrsBackupSourceIdentity::new`] rejects it at construction and at import, and
/// [`OrsBackupSnapshot::validate`] additionally requires an operational identity and
/// no outstanding operational continuation for `Complete`, which a v4 value cannot
/// express in the first place.
///
/// Issue #953 bumps this from `5` to `6` because the v5 continuation contract
/// cannot express the EXHAUSTED state. Both [`OrsOperationalContinuation`] and
/// [`OrsFamilyContinuation`] carried `next: Option<Cursor>`, and `None` said only
/// "this page is done with the axis" — it did not carry the axis's terminal
/// boundary, so a page that followed to carry another axis had to be built under a
/// boundary reconstructed elsewhere, and reconstructing it from the axis's own
/// pre-page cursor RE-READ the axis. A v5 value therefore has no way to say "this
/// axis is finished, at this exact frontier, and owes nothing more", which is the
/// one fact a cross-page validator needs to tell an exhausted axis from an axis
/// that merely has not been paged yet. v6 replaces the option with
/// [`OrsAxisState`], whose `Exhausted` arm carries that frontier and is folded
/// into the page digest and the denominator under its own name. The bump is a WIRE
/// constant, not durable schema: no table, column or row changes, nothing is
/// rewritten, and no migration is introduced. A v5 request or snapshot is refused
/// at construction and at import by the unchanged
/// [`OrsError::MigrationRequired`] refusal, and is never reinterpreted as a v6
/// value that claims an exhausted axis it never measured.
pub const BACKUP_SNAPSHOT_SCHEMA_VERSION: u16 = 6;
/// Hard ceiling for entries in one backup page (mirrors `MAX_RECOVERY_PAGE`).
pub const MAX_BACKUP_PAGE_ENTRIES: u16 = 256;
/// Hard ceiling for pages in one backup snapshot.
pub const MAX_BACKUP_PAGES: u16 = 256;
/// Hard ceiling for the declared byte budget of one backup request.
pub const MAX_BACKUP_BYTES: u64 = 16 * 1024 * 1024;
/// Hard ceiling for installation/admission identifier length.
pub const MAX_BACKUP_ID_LEN: usize = 256;
/// Hard ceiling for the capture window a page may declare (issue #953).
///
/// The issue requires "bounded pages/bytes/work/lifetime", and an unbounded
/// capture window is how a page outlives the state it claims: a page exported
/// under a fence would stay triageable indefinitely while the store moved on. One
/// hour is the ceiling, not the stamped value, so a caller cannot buy a longer
/// window by asking for it. Reuses the crate's existing expiry convention
/// (I05-2: `expires_at` is a cleanup horizon, never an automatic deletion), so
/// this bounds triage eligibility and deletes nothing.
pub const MAX_BACKUP_PAGE_LIFETIME_MS: i64 = 60 * 60 * 1000;
/// Version tag of the typed row-family cursor contract (issue #2884).
pub const ORS_FAMILY_CURSOR_VERSION: u16 = 1;
/// Version tag of the typed operational-history continuation contract (#2967).
///
/// Its own tag, separate from [`ORS_FAMILY_CURSOR_VERSION`] and separate from
/// [`BACKUP_SNAPSHOT_SCHEMA_VERSION`], because the two continuation domains have
/// different owners, different orders and different wire carriers. A cursor that
/// carried the family tag could not be told apart from a family cursor by version
/// alone.
pub const ORS_OPERATIONAL_CURSOR_VERSION: u16 = 1;
/// Lowercase 64-hex digest shape check (local copy: `model` is private).
fn require_digest(value: &str, field: &'static str) -> Result<(), OrsError> {
    let ok = value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    if ok {
        Ok(())
    } else {
        Err(OrsError::InvalidField {
            field,
            reason: "digest must be 64 lowercase hex characters",
        })
    }
}
/// SHA-256 hex helper local to this module.
fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
/// Bounded installation identifier check shared by source and destination.
fn require_installation_id(value: &str, field: &'static str) -> Result<(), OrsError> {
    if value.is_empty() || value.len() > MAX_BACKUP_ID_LEN {
        return Err(OrsError::InvalidField {
            field,
            reason: "installation id must be non-empty and bounded",
        });
    }
    Ok(())
}
/// Source identity bound into every backup request and snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OrsBackupSourceIdentity {
    pub installation_id: String,
    pub ors_generation: u64,
    /// Must equal [`BACKUP_SNAPSHOT_SCHEMA_VERSION`].
    pub schema_version: u16,
}
impl OrsBackupSourceIdentity {
    /// Validate and bind a backup source identity.
    pub fn new(
        installation_id: String,
        ors_generation: u64,
        schema_version: u16,
    ) -> Result<Self, OrsError> {
        require_installation_id(&installation_id, "source_installation_id")?;
        if schema_version != BACKUP_SNAPSHOT_SCHEMA_VERSION {
            return Err(OrsError::MigrationRequired {
                reason: format!(
                    "backup schema {schema_version} unsupported, expected {BACKUP_SNAPSHOT_SCHEMA_VERSION}"
                ),
            });
        }
        Ok(Self {
            installation_id,
            ors_generation,
            schema_version,
        })
    }
}
/// Fence binding captured with a backup request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsBackupFence {
    pub fence_digest: String,
    pub high_water_order: u64,
    pub captured_at_ms: i64,
}
impl OrsBackupFence {
    /// Validate and bind a backup fence.
    pub fn new(
        fence_digest: String,
        high_water_order: u64,
        captured_at_ms: i64,
    ) -> Result<Self, OrsError> {
        require_digest(&fence_digest, "backup_fence_digest")?;
        Ok(Self {
            fence_digest,
            high_water_order,
            captured_at_ms,
        })
    }
}
/// Every durable ORS row family classifiable for backup disposition.
///
/// `Ord`/`PartialOrd`/`Hash` are derived for the admission census in
/// `check_observed_members`, which has to key observed members by
/// `(family, record_id)` to tell a repeat of one identity from two different
/// rows. They are the only reason those derives exist: a string key built from
/// `{:?}` would alias two members onto one whenever a record id contained the
/// separator, which is exactly the silent-collapse failure the census exists to
/// prevent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RowFamilyKind {
    OperationalHistory,
    OperationalCurrent,
    Reservations,
    ReservationOrders,
    Envelopes,
    ScopeHeads,
    ScopeTerminals,
    RecoveryInbox,
    RecoveryInboxHistory,
    ProcessStartReplay,
    AuthorityHandoffs,
    /// Observation-only process-evidence rows (issue #269, A1).
    ///
    /// A row of this family may be a pre-#269 row that still holds the accepted
    /// `ProcessEvidence` value inline, bounded preview bytes included, so the
    /// family carries payload a restore must never receive as an answer. It is
    /// `ForensicOnly`: an exported row lands as forensics and never as an
    /// importable observation.
    ProcessEvidence,
    /// Immutable process-stream recovery projections (issue #269): one durable
    /// row per `(operation_id, stream)` identity, carrying only the locator,
    /// coverage, typed transport/persistence state and reconciliation owner.
    ///
    /// `Restorable` means eligible for the existing
    /// `import_process_stream_recovery_suspended` quarantine only. It never
    /// means a restored projection can revive process, session or authority
    /// state: the import path discards the incoming activation and always
    /// writes `Suspended` (or keeps an already `Retired` row `Retired`).
    ProcessStreamRecovery,
    SupervisionLeaseStaged,
    SupervisionLeaseCurrent,
    SupervisionLeaseHistory,
    SupervisionLeaseResults,
    SupervisionStageResolutions,
    StoreRebindReplay,
    StoreFailureRetention,
    UnknownCommitRecovery,
    CutoverOwnership,
    /// Versioned-artifact registry metadata is installation-bound generation
    /// authority. A restored installation must not reactivate its old paths.
    VersionedArtifacts,
    HostRequests,
    ActivationLifecycle,
    ActivationResultRetention,
    NativeWorkerClaims,
    ReplayStreams,
    ReplayRequests,
    ReplayEvents,
    ReplayAcks,
    DoctorAttempts,
    DoctorEffects,
    DoctorBudgets,
    RecoveryProblems,
    GrantClosureCurrent,
    GrantGraphRevisionCurrent,
    RestoreJournalIntents,
    RestoreJournalResults,
    RestoreJournalMeta,
    /// Durable scan disclosure receipts (issue #2900): one row per
    /// `scan-disclosure:<installation>:<operation>` identity. Evidence, not
    /// live state: backup/export preserves the family under policy, import
    /// never restores scan state.
    ScanDisclosure,
    /// Durable cold-start leases and immutable readiness receipts (issue
    /// #1790). These rows are bound to one installation and exact workspace,
    /// privacy, source generation and state fence. Backup restore must never
    /// revive their prior lease or readiness decision.
    ColdStartReadiness,
    /// Durable owner-backed `backup.verify` results (issue #2883): one row per
    /// distinct `(principal, authority lineage, operation id)` within one
    /// installation's ORS file — the exact tuple the durable key is scoped to, and
    /// structural rather than an in-band installation field, because a row is only
    /// ever read out of the file that owns it — holding the accepted request
    /// identity and the archive's own declared answers and nothing else.
    ///
    /// The family is now DECLARED in the EXISTING ORS operational retention/export
    /// contract whose [`RowFamilyKind::disposition`] this enum already is, and
    /// that contract is the existing owner of its lifecycle. Be precise about what
    /// the declaration is worth: the denominator function that carries it has NO
    /// production reader in this tree, so nothing yet COUNTS the family and nothing
    /// bounds it. The real cardinality is one row per distinct
    /// `(principal, authority lineage, operation id)` within one installation's ORS
    /// file, plus one quarantined row per pre-#2883 caller key. #2883 therefore
    /// adds no deletion, no eviction, no TTL and no cap here; the bounded-retirement
    /// work stays with the separate ORS retention owner, and a second retention
    /// rule beside that contract is exactly the unbounded growth instruction 10
    /// forbids.
    ///
    /// The disposition follows the [`RowFamilyKind::UnknownCommitRecovery`]
    /// sibling, i.e. `ForensicOnly`, not the
    /// [`RowFamilyKind::ProcessStreamRecovery`] sibling's `Restorable`.
    /// `Restorable` means "eligible for the family's own quarantined
    /// `import_*_suspended` path", and that premise is false here: this family
    /// has no import path at all, so `Restorable` would advertise a durable
    /// re-import that does not exist. `ForensicOnly`'s premise is exactly the one
    /// that holds — an owner-backed read-only result is evidence, never
    /// authority — so an exported row lands as forensics and no restored
    /// installation can read a prior installation's verification answer back as
    /// its own.
    BackupVerificationResults,
}
/// Backup disposition of one row family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RowDisposition {
    /// Restores into a live ORS.
    Restorable,
    /// Historical; never restores.
    NonrestorableHistorical,
    /// Forensic-only (I14-21: unknown stays reconciling).
    ForensicOnly,
}
impl RowFamilyKind {
    /// Static disposition policy for one row family.
    pub const fn disposition(self) -> RowDisposition {
        match self {
            // `BackupVerificationResults` is listed EXPLICITLY on the
            // `ForensicOnly` arm, not left to the wildcard. It has no
            // `import_*_suspended` path at all, so `Restorable` would advertise a
            // durable re-import that does not exist; `ForensicOnly`'s premise —
            // evidence, never authority — is the one that actually holds for a
            // read-only owner-backed verification result. Listing it explicitly is
            // what makes that true rather than merely stated: a new trailing
            // variant would otherwise silently fall through to `Restorable`.
            Self::StoreRebindReplay
            | Self::StoreFailureRetention
            | Self::BackupVerificationResults
            // `ProcessEvidence` (issue #269, A1) is listed EXPLICITLY for the
            // same reason `BackupVerificationResults` is. The family has no
            // `import_*_suspended` path at all, so `Restorable` would advertise
            // a durable re-import that does not exist; and a row of it may be a
            // pre-#269 row that still holds the inline stdout/stderr payload, so
            // an imported copy of that row would be raw stream payload crossing
            // a restore boundary. `ForensicOnly`'s premise — evidence, never
            // authority — is the one that actually holds. Listing it explicitly
            // is what makes that true rather than merely stated: a new trailing
            // variant would otherwise silently fall through to `Restorable`.
            | Self::ProcessEvidence => RowDisposition::ForensicOnly,
            Self::AuthorityHandoffs
            | Self::HostRequests
            | Self::ActivationLifecycle
            | Self::ActivationResultRetention
            | Self::NativeWorkerClaims
            | Self::CutoverOwnership
            | Self::VersionedArtifacts
            | Self::ScanDisclosure
            | Self::ColdStartReadiness => RowDisposition::NonrestorableHistorical,
            // Everything else, including the #269 process-stream recovery
            // family, is `Restorable`. That word only means eligible for the
            // family's own quarantined import: the sole durable import for a
            // process-stream recovery row is
            // `RedbRecoveryStore::import_process_stream_recovery_suspended`,
            // which always writes suspended recovery evidence and never
            // revives process, session or authority state.
            _ => RowDisposition::Restorable,
        }
    }
}
/// Disposition binding for one row family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RowFamilyDisposition {
    pub kind: RowFamilyKind,
    pub disposition: RowDisposition,
}
impl RowFamilyDisposition {
    /// Bind a family to its static disposition policy.
    pub const fn of(kind: RowFamilyKind) -> Self {
        Self {
            kind,
            disposition: kind.disposition(),
        }
    }
}
impl RowFamilyKind {
    /// Reports whether the family is paged through its own typed family cursor
    /// instead of the shared `after_order` operational window.
    ///
    /// A family qualifies only when it has its own total order. The
    /// process-stream recovery family has no canonical operation order, so
    /// selecting it by observation time silently drops or duplicates rows
    /// whenever two rows share a millisecond or a row lands between two pages.
    /// Its entry `order` stays a reporting value; selection is always by the
    /// family's own durable-key order through [`OrsFamilyCursor`]. The
    /// versioned-artifact family (issue #1971) qualifies for the same reason:
    /// its rows carry no operation order at all, so selection is always by the
    /// family's own durable-key order and the entry `order` reports the
    /// generation as a reporting value only.
    pub const fn uses_family_cursor(self) -> bool {
        matches!(self, Self::ProcessStreamRecovery | Self::VersionedArtifacts)
    }
}

/// One link of a row-family hash chain (issue #2884).
///
/// The chain is a real hash chain, not a stream digest: each link absorbs the
/// previous link, so a link can be resumed from a previously observed value
/// without re-reading what came before it. That is what lets a continuation
/// extend the emitted prefix it already proved, and what lets a verifier
/// re-derive the same prefix from durable state alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrsFamilyRowChain {
    /// Lowercase hex digest of the previous link; the empty family is the
    /// family-scoped seed.
    link: String,
}
impl OrsFamilyRowChain {
    /// Starts a chain scoped to one row family.
    ///
    /// The seed carries the family name, so a link is never transferable
    /// between families.
    #[must_use]
    pub fn start(family: RowFamilyKind) -> Self {
        Self {
            link: sha256_hex(format!("eliot.ors.family_chain.v1|{family:?}|").as_bytes()),
        }
    }
    /// Resumes a chain from a link a prior verified step already observed.
    ///
    /// Only the owner may resume: a resumed chain is trusted because the
    /// cursor it came from was proved against durable state, never because the
    /// presented link looked well formed.
    #[must_use]
    pub fn resume(link: String) -> Self {
        Self { link }
    }
    /// Absorbs one durable key only, for an emitted-prefix witness.
    pub fn advance_key(&mut self, key: &str) {
        self.link = sha256_hex(format!("{}|{key}|", self.link).as_bytes());
    }
    /// Absorbs one durable row: its key and the digest of its encoded bytes.
    pub fn advance_row(&mut self, key: &str, encoded_digest: &str) {
        self.link = sha256_hex(format!("{}|{key}|{encoded_digest}|", self.link).as_bytes());
    }
    /// Returns the current lowercase hex link.
    #[must_use]
    pub fn link(&self) -> &str {
        &self.link
    }
}

/// Frozen owner identity of one paged row family (issue #2884).
///
/// Both fields are owner state, never caller input.
/// `family_revision` is the durable monotone revision that the family's single
/// write path advances inside the same transaction as every insert, evidence
/// advance and retirement, so any movement of the family moves it.
/// `family_root_digest` is the streamed content root over the family's durable
/// keys and encoded row bytes, so it also binds a store whose revision counter
/// never ran. Together they name the one family snapshot every page of a
/// multi-page export must keep observing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsFamilySnapshotIdentity {
    /// Family this identity freezes.
    pub family: RowFamilyKind,
    /// Durable monotone family revision observed when the identity was frozen.
    pub family_revision: u64,
    /// Streamed content root over the family at that revision.
    pub family_root_digest: String,
    /// Retained rows in the frozen family.
    pub family_row_count: u64,
    /// Summed encoded bytes of the frozen family.
    pub family_total_bytes: u64,
}
impl OrsFamilySnapshotIdentity {
    /// Validate and bind one frozen family identity.
    ///
    /// Only a family with its own total order may carry one: a family paged on
    /// the shared `after_order` window has no separate snapshot to freeze.
    pub fn new(
        family: RowFamilyKind,
        family_revision: u64,
        family_root_digest: String,
        family_row_count: u64,
        family_total_bytes: u64,
    ) -> Result<Self, OrsError> {
        if !family.uses_family_cursor() {
            return Err(OrsError::InvalidField {
                field: "backup.family",
                reason: "only a family with its own total order carries a family snapshot identity",
            });
        }
        require_digest(&family_root_digest, "backup_family_root_digest")?;
        Ok(Self {
            family,
            family_revision,
            family_root_digest,
            family_row_count,
            family_total_bytes,
        })
    }
    /// Deterministic binding token for the frozen family snapshot.
    ///
    /// This token is folded into every family page digest and into the
    /// snapshot denominator, so the family snapshot identity is bound by the
    /// page token and the denominator and not only by the request.
    #[must_use]
    pub fn fence_token(&self) -> String {
        sha256_hex(
            format!(
                "{:?}|{}|{}|{}|{}",
                self.family,
                self.family_revision,
                self.family_root_digest,
                self.family_row_count,
                self.family_total_bytes
            )
            .as_bytes(),
        )
    }
}
/// Typed continuation cursor for one paged row family (issue #2884).
///
/// The cursor names a frozen family snapshot plus the exact durable-key prefix
/// the owner already emitted for it. Its boundary is not self-authenticating:
/// `emitted_prefix_digest` is a hash chain over the family's own ordered keys,
/// and the export re-derives that chain from durable state and refuses any
/// cursor whose `after_key` is not the key at `emitted_rows`. A caller
/// therefore cannot choose which family rows a page covers, and no row can be
/// skipped out of the denominator by presenting a different offset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsFamilyCursor {
    /// Cursor contract version. A snapshot produced before this cursor existed
    /// declares no family denominator and is legacy/partial evidence.
    pub version: u16,
    /// The one frozen family snapshot every page must still observe.
    pub identity: OrsFamilySnapshotIdentity,
    /// Exclusive durable-key bound; empty at the start of the family.
    pub after_key: String,
    /// Rows the owner has already emitted for this family.
    pub emitted_rows: u64,
    /// Summed encoded bytes the owner has already emitted for this family.
    pub emitted_bytes: u64,
    /// Chained digest of the emitted durable-key prefix.
    pub emitted_prefix_digest: String,
}
impl OrsFamilyCursor {
    /// Opens the first family cursor for one frozen family identity.
    pub fn start(identity: OrsFamilySnapshotIdentity) -> Result<Self, OrsError> {
        let emitted_prefix_digest = OrsFamilyRowChain::start(identity.family).link().to_owned();
        let cursor = Self {
            version: ORS_FAMILY_CURSOR_VERSION,
            identity,
            after_key: String::new(),
            emitted_rows: 0,
            emitted_bytes: 0,
            emitted_prefix_digest,
        };
        cursor.validate()?;
        Ok(cursor)
    }
    /// Exact deterministic identity of this cursor, including the frozen family
    /// snapshot and the emitted prefix.
    #[must_use]
    pub fn fence_token(&self) -> String {
        sha256_hex(
            format!(
                "{}|{}|{}|{}|{}|{}",
                self.version,
                self.identity.fence_token(),
                self.after_key,
                self.emitted_rows,
                self.emitted_bytes,
                self.emitted_prefix_digest
            )
            .as_bytes(),
        )
    }
    /// Validate the cursor's version, family identity and prefix shape.
    ///
    /// This is a shape gate only. It proves the cursor is well formed, never
    /// that its boundary is the owner's: only the export, by re-deriving the
    /// prefix chain from durable state, can bind the boundary.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.version != ORS_FAMILY_CURSOR_VERSION {
            return Err(OrsError::MigrationRequired {
                reason: format!(
                    "backup family cursor {} unsupported, expected {ORS_FAMILY_CURSOR_VERSION}",
                    self.version
                ),
            });
        }
        if !self.identity.family.uses_family_cursor() {
            return Err(OrsError::InvalidField {
                field: "backup_family_cursor",
                reason: "family is not paged through a typed family cursor",
            });
        }
        require_digest(
            &self.emitted_prefix_digest,
            "backup_family_emitted_prefix_digest",
        )?;
        if self.after_key.is_empty() != (self.emitted_rows == 0) {
            return Err(OrsError::InvalidField {
                field: "backup_family_cursor",
                reason: "an emitted family prefix must name its last durable key",
            });
        }
        if self.emitted_rows > self.identity.family_row_count {
            return Err(OrsError::InvalidField {
                field: "backup_family_cursor",
                reason: "emitted family rows exceed the frozen family row count",
            });
        }
        Ok(())
    }
}

/// Frozen owner identity of the operational-history axis of one backup
/// (issue #2967).
///
/// The operational twin of [`OrsFamilySnapshotIdentity`], and the same three
/// questions answered for the axis that used to have none:
///
/// - `high_water_order` is the exact ordering head the owner observed when the
///   identity was frozen. It is the UPPER bound of the walk, and it is the value
///   [`OrsBackupFence::high_water_order`] claims. A row above it is not a member of
///   this snapshot; it belongs to a successor snapshot even when it already existed
///   and was stable when the export began.
/// - `operational_root_digest`, `operational_row_count` and
///   `operational_total_bytes` are the streamed content root, the eligible row
///   count and the bounded encoded-byte denominator measured by the OWNER over the
///   window `(lower_order_bound, high_water_order]`. They are the denominator the
///   pages are counted against, exactly as `family_row_count` is the denominator
///   [`check_declared_members`] counts a family's members against, so a `Complete`
///   snapshot is a measurement rather than a claim.
/// - `lower_order_bound` is the walk's declared exclusive start. It is part of the
///   identity rather than of the cursor because it is what makes the denominator
///   mean something: "every operational row above order N and at or below the
///   high-water" is a statement, while "every operational row" is not what a
///   windowed export measured.
///
/// `source_installation_id`, `ors_generation` and `schema_version` are folded in so
/// the identity is bound to the source it was read from and to the wire contract
/// under which it is meaningful; a cursor minted for one source is refused for
/// another because the whole identity differs, not because a field was edited.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsOperationalSnapshotIdentity {
    /// Installation the walk was read from.
    pub source_installation_id: String,
    /// ORS generation the walk was read from.
    pub ors_generation: u64,
    /// Backup-snapshot wire contract this identity belongs to.
    pub schema_version: u16,
    /// Inclusive upper order bound of the walk, as the owner observed it.
    pub high_water_order: u64,
    /// Exclusive lower order bound the walk was declared to start above.
    pub lower_order_bound: u64,
    /// Streamed content root over the window at that high-water.
    pub operational_root_digest: String,
    /// Eligible operational rows in the window.
    pub operational_row_count: u64,
    /// Summed encoded bytes of the window.
    pub operational_total_bytes: u64,
}
impl OrsOperationalSnapshotIdentity {
    /// Validate and bind one frozen operational identity.
    ///
    /// The only structural rule the identity itself must satisfy is that the
    /// declared window is non-empty as an interval: a lower bound above the
    /// high-water would declare a denominator of negative width, and every count
    /// taken from it would be meaningless. The CONTENT is the owner's business and
    /// is re-derived from durable state by the store before the identity is used;
    /// see `check_operational_identity_frozen`.
    pub fn new(
        source: &OrsBackupSourceIdentity,
        high_water_order: u64,
        lower_order_bound: u64,
        operational_root_digest: String,
        operational_row_count: u64,
        operational_total_bytes: u64,
    ) -> Result<Self, OrsError> {
        require_installation_id(
            &source.installation_id,
            "operational_source_installation_id",
        )?;
        if source.schema_version != BACKUP_SNAPSHOT_SCHEMA_VERSION {
            return Err(OrsError::MigrationRequired {
                reason: format!(
                    "backup schema {} unsupported, expected {BACKUP_SNAPSHOT_SCHEMA_VERSION}",
                    source.schema_version
                ),
            });
        }
        if lower_order_bound > high_water_order {
            return Err(OrsError::InvalidField {
                field: "backup_operational_lower_order_bound",
                reason: "the declared walk window must not start above the high-water order",
            });
        }
        require_digest(&operational_root_digest, "backup_operational_root_digest")?;
        Ok(Self {
            source_installation_id: source.installation_id.clone(),
            ors_generation: source.ors_generation,
            schema_version: source.schema_version,
            high_water_order,
            lower_order_bound,
            operational_root_digest,
            operational_row_count,
            operational_total_bytes,
        })
    }
    /// Deterministic binding token for the frozen operational snapshot.
    ///
    /// Folded into every operational page digest (through
    /// [`OrsOperationalCursor::fence_token`]) and into
    /// [`OrsBackupSnapshot::snapshot_digest`], so the frozen operational identity is
    /// bound by the page token and the denominator and not only by the request. A
    /// page emitted under a different high-water, a different denominator or a
    /// different source cannot hash to the same value.
    #[must_use]
    pub fn fence_token(&self) -> String {
        sha256_hex(
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}",
                self.source_installation_id,
                self.ors_generation,
                self.schema_version,
                self.high_water_order,
                self.lower_order_bound,
                self.operational_root_digest,
                self.operational_row_count,
                self.operational_total_bytes
            )
            .as_bytes(),
        )
    }
}

/// Typed continuation cursor for the operational-history axis (issue #2967).
///
/// The operational twin of [`OrsFamilyCursor`], and it exists for the reason
/// #2967 names: `after_order + page_entries * page_index` is count arithmetic over a
/// sparse order domain, so it is not a continuation. A count stride re-selects rows
/// the previous page already emitted whenever the domain is sparse, and it skips
/// rows whenever the domain is dense enough to hide the defect; with orders
/// `1, 3, 5` and `page_entries = 2` it emits `[1, 3]`, `[3, 5]`, `[5]`. This cursor
/// instead names the frozen operational identity plus the exact durable row the
/// owner last emitted, so the next page starts strictly after the previous page's
/// real tail and a sparse order can neither repeat nor be skipped.
///
/// Its boundary is not self-authenticating, for exactly the reason
/// [`OrsFamilyCursor`]'s is not: every field of a presented cursor is observable.
/// `emitted_prefix_digest` is a hash chain over the emitted prefix's durable keys
/// (the same [`OrsFamilyRowChain`] construction, seeded for the operational family),
/// and the store re-derives that chain from durable state and refuses any cursor
/// whose `after_order`/`after_key` is not the row at `emitted_rows`. A caller
/// therefore cannot choose which operational rows a page covers, and cannot present
/// a later boundary under an earlier offset to drop the rows in between out of the
/// denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsOperationalCursor {
    /// Cursor contract version. A snapshot produced before this cursor existed
    /// declares no operational denominator and is legacy/partial evidence.
    pub version: u16,
    /// The one frozen operational snapshot every page must still observe.
    pub identity: OrsOperationalSnapshotIdentity,
    /// Exclusive `operation_order` bound; the identity's `lower_order_bound` at the
    /// start of the walk.
    pub after_order: u64,
    /// Exclusive durable-key bound; empty at the start of the walk.
    pub after_key: String,
    /// Operational rows the owner has already emitted for this walk.
    pub emitted_rows: u64,
    /// Summed encoded bytes the owner has already emitted for this walk.
    pub emitted_bytes: u64,
    /// Chained digest of the emitted operational durable-key prefix.
    pub emitted_prefix_digest: String,
}
impl OrsOperationalCursor {
    /// Opens the first operational cursor for one frozen operational identity.
    pub fn start(identity: OrsOperationalSnapshotIdentity) -> Result<Self, OrsError> {
        let emitted_prefix_digest = OrsFamilyRowChain::start(RowFamilyKind::OperationalHistory)
            .link()
            .to_owned();
        // The walk's declared start IS the start cursor's exclusive bound: a cursor
        // that had emitted nothing but named any other boundary would be a caller
        // choosing where the walk begins, which `validate` refuses below.
        let after_order = identity.lower_order_bound;
        let cursor = Self {
            version: ORS_OPERATIONAL_CURSOR_VERSION,
            identity,
            after_order,
            after_key: String::new(),
            emitted_rows: 0,
            emitted_bytes: 0,
            emitted_prefix_digest,
        };
        cursor.validate()?;
        Ok(cursor)
    }
    /// Exact deterministic identity of this cursor, including the frozen
    /// operational snapshot and the emitted prefix.
    #[must_use]
    pub fn fence_token(&self) -> String {
        sha256_hex(
            format!(
                "{}|{}|{}|{}|{}|{}|{}",
                self.version,
                self.identity.fence_token(),
                self.after_order,
                self.after_key,
                self.emitted_rows,
                self.emitted_bytes,
                self.emitted_prefix_digest
            )
            .as_bytes(),
        )
    }
    /// Validate the cursor's version, identity, prefix and window shape.
    ///
    /// This is a shape gate only, in the same sense and for the same reason as
    /// [`OrsFamilyCursor::validate`]: it proves the cursor is well formed, never
    /// that its boundary is the owner's. Only the store, by re-deriving the prefix
    /// chain from durable state, can bind the boundary. A cursor that passed this
    /// gate alone would prove nothing, which is why the store's re-derivation is a
    /// separate, mandatory step and not a refinement of this one.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.version != ORS_OPERATIONAL_CURSOR_VERSION {
            return Err(OrsError::MigrationRequired {
                reason: format!(
                    "backup operational cursor {} unsupported, expected {ORS_OPERATIONAL_CURSOR_VERSION}",
                    self.version
                ),
            });
        }
        if self.identity.schema_version != BACKUP_SNAPSHOT_SCHEMA_VERSION {
            return Err(OrsError::MigrationRequired {
                reason: format!(
                    "backup operational identity schema {} unsupported, expected {BACKUP_SNAPSHOT_SCHEMA_VERSION}",
                    self.identity.schema_version
                ),
            });
        }
        require_digest(
            &self.emitted_prefix_digest,
            "backup_operational_emitted_prefix_digest",
        )?;
        if self.after_key.is_empty() != (self.emitted_rows == 0) {
            return Err(OrsError::InvalidField {
                field: "backup_operational_cursor",
                reason: "an emitted operational prefix must name its last durable key",
            });
        }
        if self.emitted_rows == 0 {
            // A start cursor carries no emitted row, so its only legal boundary is
            // the walk's declared start. Any other value would be a caller choosing
            // where the walk begins while claiming nothing had been emitted.
            if self.after_order != self.identity.lower_order_bound {
                return Err(OrsError::InvalidField {
                    field: "backup_operational_cursor",
                    reason: "a start cursor must begin at the frozen walk's lower order bound",
                });
            }
        }
        if self.emitted_rows > self.identity.operational_row_count {
            return Err(OrsError::InvalidField {
                field: "backup_operational_cursor",
                reason: "emitted operational rows exceed the frozen operational row count",
            });
        }
        if self.after_order > self.identity.high_water_order {
            return Err(OrsError::InvalidField {
                field: "backup_operational_cursor",
                reason: "an emitted operational prefix cannot reach above the frozen high-water order",
            });
        }
        Ok(())
    }
}

/// The outgoing state of one backup axis after a page (issue #953).
///
/// ONE continuation contract for both the operational axis and the two
/// cursor-paged family axes, parameterised by the axis's own cursor type. It
/// exists because `Option<Cursor>` cannot say three different things.
///
/// `None` meant "this page is finished with the axis", and the producer that
/// wrote it had to reconstruct the axis's real outgoing boundary from somewhere
/// else to build the next page — which is how an exhausted axis got RE-STARTED:
/// the page that follows was built under the axis's pre-page cursor, re-emitted
/// the axis's rows, and a family whose `next` was `None` silently kept its old
/// request cursor while a later family continued. The restart was invisible to
/// every page digest, because nothing in the page said which state the axis was
/// in, only that a cursor was missing.
///
/// Two named states say it instead, and each carries the boundary it names:
///
/// - [`Self::Open`] — the axis still owes rows, and the cursor is the exact one a
///   following page must be read under.
/// - [`Self::Exhausted`] — the axis reached the frozen denominator it was opened
///   with, and the cursor is its FINAL frontier: the exact durable-key/order
///   boundary the walk actually reached. It is retained rather than discarded
///   because a page that follows to carry another axis must still be read under
///   this boundary, and because the terminal commitment must come from the walk
///   that emitted the rows rather than from a guess.
///
/// The INCOMING cursor stays a separate field on each continuation. Substituting
/// it for the outgoing one would invalidate what the current page says it read:
/// a page's own boundary and the boundary it hands on are two different facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrsAxisState<C> {
    /// The axis still owes rows; this is the exact cursor a following page is
    /// read under.
    Open(C),
    /// The axis reached its frozen denominator; this is its final frontier and
    /// every later page of the same frozen snapshot carries it unchanged while
    /// emitting nothing further for the axis.
    Exhausted(C),
}
impl<C> OrsAxisState<C> {
    /// The exact cursor a following page is read under, on both arms: the open
    /// cursor while the axis owes rows, and the retained final frontier once it
    /// does not. This is the ONE read point the page loop uses, so a producer
    /// cannot advance one arm and drop the other.
    #[must_use]
    pub fn frontier(&self) -> &C {
        match self {
            Self::Open(cursor) | Self::Exhausted(cursor) => cursor,
        }
    }
    /// The outstanding cursor while the axis is open, and `None` once it is
    /// exhausted. This is the outstanding-cursor projection a snapshot publishes:
    /// a limit that stopped the walk retains the exact open frontier, and an
    /// exhausted axis publishes nothing.
    #[must_use]
    pub fn open_cursor(&self) -> Option<&C> {
        match self {
            Self::Open(cursor) => Some(cursor),
            Self::Exhausted(_) => None,
        }
    }
    /// Whether the axis still owes rows.
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open(_))
    }
    /// Whether the axis is explicitly exhausted, and the terminal frontier if it
    /// is.
    #[must_use]
    pub fn exhausted_cursor(&self) -> Option<&C> {
        match self {
            Self::Exhausted(cursor) => Some(cursor),
            Self::Open(_) => None,
        }
    }
}

/// Per-page operational continuation state (issue #2967, extended by #953).
///
/// The operational twin of [`OrsFamilyContinuation`], and deliberately a separate
/// type with a separate field on the page: operational rows are ordered by
/// `operation_order` under the store's ordering high-water, while each paged family
/// is ordered by its own durable key under its own frozen revision. One cursor can
/// never stand in for the other, so neither the wire nor the digest can either.
///
/// `state` is the ONE outgoing state of the axis, and it names its own boundary
/// (see [`OrsAxisState`]). The boundary is the page's ACTUAL last emitted row, so
/// a sparse order domain neither duplicates nor skips rows across pages, and an
/// axis that reached its frozen denominator keeps that final frontier instead of
/// handing the next page its own start.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsOperationalContinuation {
    /// Cursor in force for this page.
    pub cursor: OrsOperationalCursor,
    /// The axis's exact outgoing state and its boundary.
    pub state: OrsAxisState<OrsOperationalCursor>,
}
impl OrsOperationalContinuation {
    /// Reports whether the operational walk still has rows behind its frontier.
    #[must_use]
    pub fn operational_open(&self) -> bool {
        self.state.is_open()
    }
    /// The axis's exact outgoing boundary, open or exhausted.
    #[must_use]
    pub fn frontier(&self) -> &OrsOperationalCursor {
        self.state.frontier()
    }
    /// The outstanding cursor while the axis is open, and `None` once it is
    /// explicitly exhausted (issue #953).
    #[must_use]
    pub fn open_cursor(&self) -> Option<&OrsOperationalCursor> {
        self.state.open_cursor()
    }
    /// The retained terminal frontier while the axis is explicitly exhausted, and
    /// `None` while it is still open (issue #953).
    #[must_use]
    pub fn exhausted_cursor(&self) -> Option<&OrsOperationalCursor> {
        self.state.exhausted_cursor()
    }
    /// The axis's digest material: the state NAME plus the exact boundary it
    /// names, so a page that flipped from open to exhausted, or moved its
    /// terminal boundary, moves its digest. Folded into both the page digest and
    /// the snapshot denominator.
    #[must_use]
    pub fn state_material(&self) -> String {
        axis_state_material(&self.state, OrsOperationalCursor::fence_token)
    }
    /// Validate the in-force cursor and the outgoing state.
    ///
    /// Both arms check the same two cross-cursor facts — the outgoing cursor must
    /// stay inside the same frozen operational identity and must not reset the
    /// emitted prefix — and the `Exhausted` arm adds the one that is specific to
    /// it: the final frontier must account for exactly the frozen denominator,
    /// so "exhausted" can only ever be the truthful statement that the walk
    /// finished and never a way to stop early. A page or byte LIMIT is the `Open`
    /// arm, which retains the exact frontier to resume from.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.cursor.validate()?;
        let frontier = self.state.frontier();
        frontier.validate()?;
        if frontier.identity != self.cursor.identity {
            return Err(OrsError::InvalidField {
                field: "backup_operational_continuation",
                reason: "the outgoing operational cursor left the frozen operational snapshot",
            });
        }
        if frontier.emitted_rows < self.cursor.emitted_rows {
            return Err(OrsError::InvalidField {
                field: "backup_operational_continuation",
                reason: "operational continuation must not reset its emitted prefix",
            });
        }
        if let Some(final_cursor) = self.state.exhausted_cursor()
            && final_cursor.emitted_rows != self.cursor.identity.operational_row_count
        {
            return Err(OrsError::InvalidField {
                field: "backup_operational_continuation",
                reason: "an exhausted operational walk must account for exactly the frozen operational denominator",
            });
        }
        Ok(())
    }
}

/// The digest material of one axis state: the state name and the fence token of
/// the exact boundary it names (issue #953).
///
/// ONE derivation for all three axes, so a producer and a validator cannot
/// disagree about one axis's fold while agreeing about another's, and the label
/// keeps an exhausted frontier from ever hashing like an open one.
fn axis_state_material<C, T>(state: &OrsAxisState<C>, token: T) -> String
where
    T: Fn(&C) -> String,
{
    match state {
        OrsAxisState::Open(cursor) => format!("open:{}", token(cursor)),
        OrsAxisState::Exhausted(cursor) => format!("exhausted:{}", token(cursor)),
    }
}
/// Stored effect class per backup entry (bytes stay in the store).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredEffectClass {
    /// Staged but not committed.
    Staged,
    /// Possibly committed, unresolved.
    Possible,
    /// Unknown; remains reconciling (I14-21).
    Unknown,
    /// Terminal effect.
    Terminal,
}
/// Bounded logical backup export request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsBackupRequest {
    pub source: OrsBackupSourceIdentity,
    pub fence: OrsBackupFence,
    /// Exclusive lower order bound for pagination: the start of the WHOLE walk.
    ///
    /// This is a subsetting declaration, not a continuation, and that is the whole
    /// reason it is still here while `page_index` arithmetic is gone. It names where
    /// the owner-issued walk begins; it can never name a page boundary inside the
    /// walk, because every boundary after the first is
    /// [`Self::operational_cursor`]. The denominator the walk declares is measured
    /// from it, so a caller that starts late gets a snapshot that is complete over
    /// the window it asked for and is not thereby complete over the whole history.
    pub after_order: u64,
    /// Entries per page, `1..=MAX_BACKUP_PAGE_ENTRIES`.
    pub page_entries: u16,
    /// Declared byte budget, `1..=MAX_BACKUP_BYTES`.
    pub max_bytes: u64,
    /// Page budget, `1..=MAX_BACKUP_PAGES`.
    pub max_pages: u16,
    /// Typed continuation for the operational-history axis (issue #2967), or `None`
    /// for the FIRST page of a walk.
    ///
    /// A THIRD named slot, never a widened `after_order`. The operational axis has
    /// its own total order (the store's `operation_order` allocator) and its own
    /// frozen identity, so it is paged the way each cursor-paged family is: by an
    /// owner-issued cursor whose boundary is re-derived from durable state, not by
    /// `after_order + page_entries * page_index`. `None` means "this is the first
    /// page of the walk declared by `after_order`" and is the only case in which the
    /// store mints the operational cursor itself, from the high-water, content root
    /// and denominator it observes.
    ///
    /// The slot is never reused for a family cursor and a family slot is never
    /// reused for it: `OrsOperationalCursor::validate` refuses a family identity by
    /// construction, and a family cursor cannot be constructed in this slot.
    pub operational_cursor: Option<OrsOperationalCursor>,
    /// Typed continuation for the paged process-stream recovery family
    /// (issue #2884), or `None` when the caller declared no family
    /// continuation.
    ///
    /// `None` is not an empty family. A snapshot exported without one carries
    /// no family denominator at all and is therefore legacy/partial evidence
    /// (see [`OrsBackupSnapshot::validate`]); it can never certify that the
    /// family was fully retained. The operational `after_order` window is never
    /// reused for this family: observation time is not a total order.
    pub process_stream_recovery_cursor: Option<OrsFamilyCursor>,
    /// Typed continuation for the paged versioned-artifact family (issue
    /// #1971), or `None` when the caller declared no continuation for it.
    ///
    /// A SECOND symmetric slot rather than a widened first one, and the reason is
    /// that widening would destroy the property the first slot exists for:
    /// [`Self::with_process_stream_recovery_cursor`] refuses a cursor frozen for
    /// any other family, precisely so one family's table can never be paged
    /// under another family's denominator. One named slot per family keeps that
    /// refusal exact and keeps the digest folds in
    /// [`OrsBackupPage::expected_page_digest`] and
    /// [`OrsBackupSnapshot::snapshot_digest`] positionally unambiguous, where a
    /// map keyed by family would make the fold order a serde detail. A general
    /// per-family map would additionally need `RowFamilyKind: Ord` plus a string
    /// map key, which is more new surface than a second field.
    ///
    /// The versioned-artifact family's rows carry no operation order at all, so
    /// the operational `after_order` window is never reused for it either.
    pub versioned_artifact_cursor: Option<OrsFamilyCursor>,
}
impl OrsBackupRequest {
    /// The exact family continuation this request declares for `family`, or
    /// `None` when it declares none.
    ///
    /// One read point for both slots so the export loop cannot read the wrong
    /// family's cursor: the discriminator is the caller's `family`, not a guess
    /// made where the cursor is consumed.
    #[must_use]
    pub fn family_cursor(&self, family: RowFamilyKind) -> Option<&OrsFamilyCursor> {
        match family {
            RowFamilyKind::ProcessStreamRecovery => self.process_stream_recovery_cursor.as_ref(),
            RowFamilyKind::VersionedArtifacts => self.versioned_artifact_cursor.as_ref(),
            _ => None,
        }
    }
}
impl OrsBackupRequest {
    /// Validate and bind a backup request.
    pub fn new(
        source: OrsBackupSourceIdentity,
        fence: OrsBackupFence,
        after_order: u64,
        page_entries: u16,
        max_bytes: u64,
        max_pages: u16,
    ) -> Result<Self, OrsError> {
        if page_entries == 0 || page_entries > MAX_BACKUP_PAGE_ENTRIES {
            return Err(OrsError::InvalidCursorLimit);
        }
        if max_bytes == 0 || max_bytes > MAX_BACKUP_BYTES {
            return Err(OrsError::InvalidField {
                field: "backup_max_bytes",
                reason: "byte budget must be within 1 and MAX_BACKUP_BYTES",
            });
        }
        if max_pages == 0 || max_pages > MAX_BACKUP_PAGES {
            return Err(OrsError::InvalidField {
                field: "backup_max_pages",
                reason: "page budget must be within 1 and MAX_BACKUP_PAGES",
            });
        }
        Ok(Self {
            source,
            fence,
            after_order,
            page_entries,
            max_bytes,
            max_pages,
            operational_cursor: None,
            process_stream_recovery_cursor: None,
            versioned_artifact_cursor: None,
        })
    }
    /// Binds one typed operational continuation to this request (issue #2967).
    ///
    /// The cursor comes from the store's operational-snapshot opener or from the
    /// `next_operational_cursor` an earlier partial snapshot published, never from
    /// a boundary the caller computed: it names a frozen high-water, a frozen
    /// content root and the operational durable-key prefix the owner already
    /// emitted, and the store re-derives that prefix from durable state before it
    /// reads a single row (see `check_operational_cursor_boundary`). A caller that
    /// echoes the exact cursor back resumes; a caller that edits the boundary, the
    /// offset, the prefix commitment, the high-water or the source is refused before
    /// any suffix read.
    ///
    /// A request carrying this cursor is paged from the cursor's own boundary, not
    /// from `after_order`: `after_order` remains the walk's declared start and the
    /// frozen identity carries it, so a cursor whose identity disagrees with this
    /// request's `after_order` is refused rather than silently restarting the walk
    /// at a different window.
    pub fn with_operational_cursor(
        mut self,
        cursor: OrsOperationalCursor,
    ) -> Result<Self, OrsError> {
        cursor.validate()?;
        if cursor.identity.lower_order_bound != self.after_order {
            return Err(OrsError::InvalidField {
                field: "backup_operational_cursor",
                reason: "the operational cursor is frozen for a different walk start than this request declares",
            });
        }
        self.operational_cursor = Some(cursor);
        Ok(self)
    }
    /// Binds one typed family continuation to this request (issue #2884).
    ///
    /// The cursor comes from the store's family-snapshot opener, never from the
    /// caller: it names a frozen durable family revision and the durable-key
    /// prefix the owner already emitted. Attaching it here is what makes the
    /// family part of the exported denominator instead of an implicit
    /// side-effect of the final operational page. The cursor must name the
    /// process-stream recovery family (issue #1971 registers a second
    /// cursor-paged family, so the slot refuses a cursor frozen for any other
    /// family rather than paging one family's table under another family's
    /// denominator).
    pub fn with_process_stream_recovery_cursor(
        mut self,
        cursor: OrsFamilyCursor,
    ) -> Result<Self, OrsError> {
        cursor.validate()?;
        if cursor.identity.family != RowFamilyKind::ProcessStreamRecovery {
            return Err(OrsError::InvalidField {
                field: "backup_process_stream_recovery_cursor",
                reason: "cursor names a different row family",
            });
        }
        self.process_stream_recovery_cursor = Some(cursor);
        Ok(self)
    }
    /// Binds one typed versioned-artifact family continuation to this request
    /// (issue #1971).
    ///
    /// The exact mirror of [`Self::with_process_stream_recovery_cursor`], and it
    /// refuses the same way for the same reason: the slot names ONE family, so a
    /// cursor frozen for any other family is refused here rather than paging one
    /// family's table under another family's denominator. The cursor still comes
    /// only from the store's family-snapshot opener
    /// (`RedbRecoveryStore::open_backup_versioned_artifact_family`), never from
    /// the caller.
    ///
    /// Attaching a cursor for a family whose disposition is
    /// [`RowDisposition::NonrestorableHistorical`] grants no restore path: it
    /// puts those rows inside the exported denominator, where quarantine triage
    /// lands them `Forensic` (I05-27 / ARCH-RES-03). It never reactivates a prior
    /// installation's generation authority.
    pub fn with_versioned_artifact_cursor(
        mut self,
        cursor: OrsFamilyCursor,
    ) -> Result<Self, OrsError> {
        cursor.validate()?;
        if cursor.identity.family != RowFamilyKind::VersionedArtifacts {
            return Err(OrsError::InvalidField {
                field: "backup_versioned_artifact_cursor",
                reason: "cursor names a different row family",
            });
        }
        self.versioned_artifact_cursor = Some(cursor);
        Ok(self)
    }
    /// Deterministic binding token for source, fence, and page cursor.
    ///
    /// Neither cursor is deliberately folded in: an operational or family
    /// continuation advances by exactly one owner-issued cursor per page, so the
    /// store-wide token has to stay stable across a whole snapshot while those
    /// tokens move. Each frozen snapshot identity reaches the page through its own
    /// cursor's `fence_token` instead, which
    /// [`OrsBackupPage::expected_page_digest`] folds in.
    pub fn page_fence_token(&self) -> String {
        sha256_hex(
            format!(
                "{}:{}:{}:{}:{}",
                self.source.installation_id,
                self.source.ors_generation,
                self.fence.fence_digest,
                self.fence.high_water_order,
                self.after_order
            )
            .as_bytes(),
        )
    }
    /// Deterministic page token for a capture taken through one
    /// owner-established read consistency point (issue #953).
    ///
    /// [`OrsBackupRequest::page_fence_token`] is computed purely from
    /// caller-asserted fields, so on its own it binds a claim and not a fact: two
    /// requests that assert the same fence are indistinguishable from two requests
    /// read at two different moments. This folds the two store-wide values the
    /// capture transaction actually observed into the token, so a page states the
    /// owner-established high-water order and family revision it was read under
    /// and a page token can no longer be minted from caller input alone.
    ///
    /// The owner is the only producer of the observation arguments, so the token
    /// cannot be retargeted by the caller. The observation is taken once per
    /// capture and threaded through every page, which is what makes "one
    /// consistency point" observable in the exported bytes: every page of one
    /// snapshot carries the same owner-observed values by construction.
    #[must_use]
    pub fn observed_fence_token(
        &self,
        observed_high_water_order: u64,
        observed_family_revision: u64,
    ) -> String {
        sha256_hex(
            format!(
                "{}|{}|{}",
                self.page_fence_token(),
                observed_high_water_order,
                observed_family_revision
            )
            .as_bytes(),
        )
    }
}
/// Whether one member's opaque payload was actually obtained from the source
/// (issue #953, A6).
///
/// This is the only way a snapshot can say "a member of this denominator exists
/// and I could not read its bytes" without inventing a digest for bytes nobody
/// read. A digest for an unavailable payload would be a fabricated proof, and a
/// sentinel string in `payload_digest` would be indistinguishable from a real
/// row whose payload digest happens to be that value, so the statement is a
/// two-valued typed field on the member instead.
///
/// It is folded into both the page digest and the snapshot denominator, so a
/// member cannot be flipped between the two states without moving the digest
/// that proves it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RowPayloadState {
    /// The member's opaque payload was read from the source and hashed.
    Obtained,
    /// The member's opaque payload could not be obtained. The entry names the
    /// member and carries no payload digest.
    Unavailable,
}
/// One backup entry: digests only, never raw payload (redaction).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsBackupEntry {
    pub record_id: String,
    pub family: RowFamilyKind,
    pub order: u64,
    /// Digest of the opaque payload held by the store. Empty exactly when
    /// `payload_state` is [`RowPayloadState::Unavailable`], which
    /// [`OrsBackupSnapshot::validate`] enforces in both directions.
    pub payload_digest: String,
    pub effect_class: StoredEffectClass,
    /// Whether this member's payload was obtained (issue #953, A6).
    pub payload_state: RowPayloadState,
}
/// Per-page family continuation state (issue #2884, extended by #1971 and #953).
///
/// `cursor` is the family cursor the page was read under, so a page always
/// states which frozen family snapshot and which emitted prefix produced it, and
/// it stays the INCOMING boundary: a page that carried the family's final segment
/// still says which prefix it was read under, which the outgoing frontier is not.
/// `state` is the ONE outgoing state of the family, and it names its own boundary
/// (see [`OrsAxisState`]), so a family that closed on this page hands the next
/// page its terminal frontier rather than leaving its own pre-page cursor in
/// force. Operational-history paging and family paging never share a cursor: the
/// operational walk is bounded by its own frozen high-water under
/// [`OrsOperationalContinuation`] and each family keeps its own durable-key bound.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsFamilyContinuation {
    /// Cursor in force for this page.
    pub cursor: OrsFamilyCursor,
    /// The family's exact outgoing state and its boundary.
    pub state: OrsAxisState<OrsFamilyCursor>,
}
impl OrsFamilyContinuation {
    /// Reports whether the family still has rows behind its frontier.
    #[must_use]
    pub fn family_open(&self) -> bool {
        self.state.is_open()
    }
    /// The family's exact outgoing boundary, open or exhausted.
    #[must_use]
    pub fn frontier(&self) -> &OrsFamilyCursor {
        self.state.frontier()
    }
    /// The outstanding cursor while the family is open, and `None` once it is
    /// explicitly exhausted (issue #953).
    #[must_use]
    pub fn open_cursor(&self) -> Option<&OrsFamilyCursor> {
        self.state.open_cursor()
    }
    /// The retained terminal frontier while the family is explicitly exhausted,
    /// and `None` while it is still open (issue #953).
    #[must_use]
    pub fn exhausted_cursor(&self) -> Option<&OrsFamilyCursor> {
        self.state.exhausted_cursor()
    }
    /// The family's digest material: the state name plus the exact boundary it
    /// names. One derivation, shared with the operational axis through
    /// [`axis_state_material`], so a family that flipped from open to exhausted
    /// moves its digest and cannot be laundered into the other.
    #[must_use]
    pub fn state_material(&self) -> String {
        axis_state_material(&self.state, OrsFamilyCursor::fence_token)
    }
    /// Validate the in-force cursor and the outgoing state.
    ///
    /// The operational twin of the same rule, and for the same reason: the
    /// `Exhausted` arm requires the final frontier to account for exactly the
    /// frozen `family_row_count`, so only an owner-established terminal frontier
    /// can close the axis and a limit that merely spent the page budget cannot.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.cursor.validate()?;
        let frontier = self.state.frontier();
        frontier.validate()?;
        if frontier.identity != self.cursor.identity {
            return Err(OrsError::InvalidField {
                field: "backup_family_continuation",
                reason: "the outgoing family cursor left the frozen family snapshot",
            });
        }
        if frontier.emitted_rows < self.cursor.emitted_rows {
            return Err(OrsError::InvalidField {
                field: "backup_family_continuation",
                reason: "family continuation must not reset its emitted prefix",
            });
        }
        if let Some(final_cursor) = self.state.exhausted_cursor()
            && final_cursor.emitted_rows != self.cursor.identity.family_row_count
        {
            return Err(OrsError::InvalidField {
                field: "backup_family_continuation",
                reason: "an exhausted family walk must account for exactly the frozen family denominator",
            });
        }
        Ok(())
    }
}
/// One page of a backup snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsBackupPage {
    /// Zero-based page index; pages must be continuous.
    pub page_index: u32,
    pub entries: Vec<OrsBackupEntry>,
    /// Token this page's capture was read under (issue #953).
    ///
    /// Owner-derived from the store-wide high-water order and process-stream
    /// recovery family revision the capture transaction actually observed, via
    /// [`OrsBackupRequest::observed_fence_token`]. It is the field that makes the
    /// page self-describing: without it the page cannot state which
    /// owner-established consistency point produced it, so its digest cannot be
    /// recomputed and an independently sourced page is indistinguishable from one
    /// of this snapshot.
    pub fence_token: String,
    /// When the store stamped this page, in Unix milliseconds (issue #953).
    ///
    /// Stamped by the store through its own clock at capture, never supplied by
    /// the caller, and paired with [`OrsBackupPage::expires_at_ms`] under the
    /// crate's existing ordered-positive-pair rule (the same
    /// `expires_at_ms <= created_at_ms` refusal as `ReservationRequest`).
    pub created_at_ms: i64,
    /// Capture-window end in Unix milliseconds (issue #953).
    ///
    /// A refusal horizon for triage eligibility only, never an automatic deletion
    /// and never a claim that the state behind the page still exists (I05-2).
    pub expires_at_ms: i64,
    /// Digest binding this page, recomputable through
    /// [`OrsBackupPage::expected_page_digest`].
    pub page_digest: String,
    /// True only on the final page.
    ///
    /// Unambiguous by construction (issue #2884, extended by #1971 and by #2967):
    /// it is the conjunction of the operational walk having no continuation left and
    /// EVERY paged family having no continuation left. A page that still owes rows
    /// to the operational walk, to the process-stream recovery family or to the
    /// versioned-artifact family is never `is_last` even when its own segment
    /// ended, so page continuity can never hide an unemitted tail behind a final
    /// page. Since #2967 the operational half is derived from the frozen
    /// denominator rather than from a scan that returned fewer rows than the page
    /// size, so a page can no longer claim finality by having found nothing this
    /// time.
    pub is_last: bool,
    /// Operational-history continuation this page was read under (issue #2967).
    ///
    /// Present on every page and never shared with a family continuation: the two
    /// axes have different owners, different total orders and different frozen
    /// identities, so a page states the operational boundary in its own field. The
    /// frozen operational identity and the page's actual last emitted row both
    /// reach [`Self::page_digest`] through it, which is what makes a page that was
    /// stitched from two operational windows detectable.
    pub operational_continuation: OrsOperationalContinuation,
    /// Process-stream recovery family continuation this page was read under, or
    /// `None` when the request declared no continuation for that family.
    pub family_continuation: Option<OrsFamilyContinuation>,
    /// Versioned-artifact family continuation this page was read under, or `None`
    /// when the request declared no continuation for that family (issue #1971).
    ///
    /// Never shares a cursor with [`Self::family_continuation`]: the two families
    /// have independent durable-key orders and independent frozen identities, so
    /// one field per family is what keeps a page from carrying a continuation
    /// under the wrong family's denominator.
    pub versioned_artifact_continuation: Option<OrsFamilyContinuation>,
}
impl OrsBackupPage {
    /// The one digest derivation over a page's own content (issue #953).
    ///
    /// Single derivation, two callers: the store builds a page and assigns
    /// `page.expected_page_digest()` to `page_digest`, and
    /// [`OrsBackupPage::validate_binding`] re-derives the same value from the page
    /// a caller presented. There is deliberately no second implementation, because
    /// two implementations would let a producer and a validator disagree about
    /// what a page binds, which is exactly the gap issue #953 closes: "Independent
    /// per-page read transactions with a reused timestamp are not one snapshot"
    /// and a shape-checked digest bound nothing at all.
    ///
    /// Binds, in order: the capture token, the page index, finality, the whole
    /// capture window, the entry count, the operational continuation in force and
    /// its exact next cursor (issue #2967), the process-stream recovery family
    /// continuation in force and its exact next cursor, then the SAME four family
    /// facts for the versioned-artifact family (issue #1971), then one 64-hex
    /// digest per entry. All three continuation segments are folded in a FIXED
    /// order with a literal label in front of each, so a page that carried only one
    /// axis cannot produce the same material as a page that carried another. Every
    /// contribution is
    /// either a fixed-width digest or a delimiter-separated decimal/bool field, so
    /// the concatenation is length-delimited by construction and an embedded
    /// separator inside a `record_id` cannot make two different pages produce the
    /// same material.
    ///
    /// Since issue #953 each entry's material also folds the entry's
    /// [`RowPayloadState`], so the page digest moves when a member's payload
    /// availability moves and an unavailable member can never be laundered into
    /// an available one behind an unchanged digest. The `v2`→`v3` label change
    /// is that addition, issue #2967's `v3` to `v4` label change is the
    /// operational segment, and the `v4` to `v5` label change is issue #953's
    /// EXPLICIT EXHAUSTED axis state: each continuation segment now folds the
    /// state NAME together with the exact boundary it names, replacing the
    /// `no-next` / `no-next-operational` sentinels a page used to carry when an
    /// axis simply had no cursor to hand on. Each is a wire constant, not durable
    /// schema, and the pre-existing [`OrsError::MigrationRequired`] refusal is the
    /// migration story.
    #[must_use]
    pub fn expected_page_digest(&self) -> String {
        let mut material = format!(
            "eliot.ors.backup_page.v5|{}|{}|{}|{}|{}|{}|",
            self.fence_token,
            self.page_index,
            self.is_last,
            self.created_at_ms,
            self.expires_at_ms,
            self.entries.len()
        );
        material.push_str("operational-axis=");
        material.push_str(&self.operational_continuation.cursor.fence_token());
        material.push(':');
        material.push_str(&self.operational_continuation.state_material());
        material.push(':');
        push_family_continuation_material(
            &mut material,
            "recovery-family",
            self.family_continuation.as_ref(),
        );
        push_family_continuation_material(
            &mut material,
            "artifact-family",
            self.versioned_artifact_continuation.as_ref(),
        );
        material.push(':');
        for entry in &self.entries {
            // Fixed-width per entry, so a record id containing the delimiter
            // cannot shift a field boundary and alias one entry set onto another.
            material.push_str(&sha256_hex(
                format!(
                    "eliot.ors.backup_entry.v4|{}|{:?}|{}|{}|{:?}|{:?}",
                    entry.record_id,
                    entry.family,
                    entry.order,
                    entry.payload_digest,
                    entry.effect_class,
                    entry.payload_state
                )
                .as_bytes(),
            ));
            material.push(':');
        }
        sha256_hex(material.as_bytes())
    }
    /// Recompute and compare everything this page claims about itself
    /// (issue #953).
    ///
    /// The page no longer validates on shape alone: a well-formed 64-hex
    /// `page_digest` that does not hash to the page's own content is
    /// [`OrsError::PayloadIntegrityMismatch`], the crate's existing typed
    /// content/digest disagreement, so a page assembled from more than one source
    /// cannot pass as one snapshot. `fence_token` is shape-checked as a digest
    /// because its value is only meaningful next to the store that minted it, and
    /// the capture window is checked as the crate's existing ordered-positive pair
    /// bounded by [`MAX_BACKUP_PAGE_LIFETIME_MS`]; whether that window has actually
    /// elapsed needs a clock and is the store's check, not this pure one.
    ///
    /// Single-page entrypoint for quarantined import triage, which receives one
    /// page out of a snapshot and therefore cannot apply the continuity rules of
    /// [`OrsBackupSnapshot::validate`]. Shared with `check_page_shape`, so both
    /// paths judge a page by the same function.
    pub fn validate_binding(&self) -> Result<(), OrsError> {
        require_digest(&self.fence_token, "backup_page_fence_token")?;
        require_digest(&self.page_digest, "backup_page_digest")?;
        if self.entries.len() > usize::from(MAX_BACKUP_PAGE_ENTRIES) {
            return Err(OrsError::InvalidCursorLimit);
        }
        if self.expires_at_ms <= self.created_at_ms {
            return Err(OrsError::InvalidExpiry);
        }
        if self.expires_at_ms - self.created_at_ms > MAX_BACKUP_PAGE_LIFETIME_MS {
            return Err(OrsError::InvalidExpiry);
        }
        self.operational_continuation.validate()?;
        if let Some(continuation) = &self.family_continuation {
            continuation.validate()?;
        }
        if let Some(continuation) = &self.versioned_artifact_continuation {
            continuation.validate()?;
        }
        if self.expected_page_digest() != self.page_digest {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        Ok(())
    }
}

/// Folds one family's in-force and next cursors into a page's digest material.
///
/// ONE derivation for both paged families (issue #1971), with `label` naming
/// which family the following four fields belong to. Sharing it is what makes
/// "one derivation over a page" stay one derivation after the second family was
/// added: a producer and a validator cannot disagree about one family's fold
/// while agreeing about the other's.
fn push_family_continuation_material(
    material: &mut String,
    label: &str,
    continuation: Option<&OrsFamilyContinuation>,
) {
    material.push_str(label);
    material.push('=');
    if let Some(continuation) = continuation {
        material.push_str(&continuation.cursor.fence_token());
        material.push(':');
        material.push_str(&continuation.state_material());
    } else {
        material.push_str("no-family");
    }
    material.push(':');
}
/// Typed reason a snapshot is partial (issue #2967).
///
/// A reason STRING is not a disposition: it cannot be matched on, so a caller that
/// must "distinguish operational partial, family partial, moved snapshot, malformed
/// continuation and complete export" (the issue's W13) had nothing to match on and
/// every partial read as the same undifferentiated fact. Each variant names the AXIS
/// that is unfinished and carries the exact outstanding boundary, so the caller's
/// next action — resume the operational walk with this cursor, resume that family
/// with that key, or re-open the snapshot because the store moved — is a decision
/// the value makes and not a substring the caller has to parse.
///
/// A moved snapshot and a malformed continuation are NOT variants here on purpose:
/// both are refusals, not dispositions, and they arrive as typed [`OrsError`]
/// values instead. Putting them here would turn a refusal into a report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupPartialReason {
    /// The operational walk still owes rows and the exact next cursor is
    /// published on the snapshot as `next_operational_cursor`.
    OperationalContinuationOutstanding {
        /// Frozen high-water the walk is still under.
        high_water_order: u64,
        /// Rows already emitted under that frozen identity.
        emitted_rows: u64,
        /// Rows the frozen denominator still owes.
        remaining_rows: u64,
    },
    /// A cursor-paged row family still owes rows; the exact next cursor is
    /// published on the snapshot in that family's own slot.
    FamilyContinuationOutstanding {
        /// The family that is unfinished.
        family: RowFamilyKind,
        /// Rows already emitted for that family.
        emitted_rows: u64,
        /// Rows that family's frozen denominator still owes.
        remaining_rows: u64,
    },
    /// The request declared no denominator for a cursor-paged family, so the
    /// snapshot cannot distinguish "no rows were retained" from "this exporter
    /// never looked at the family" (I05-16: absence of a closure or coverage
    /// record means `unknown`, not unrestricted/complete).
    NoFamilyDenominator {
        /// The family with no declared denominator.
        family: RowFamilyKind,
    },
    /// The declared denominator is empty, so there is nothing to certify.
    EmptyDenominator,
}
/// Completeness of a backup snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupCompleteness {
    /// Every bound page present.
    Complete,
    /// Truncated but usable with a typed reason.
    Partial {
        /// Which axis is unfinished, and the exact boundary it is unfinished at.
        reason: BackupPartialReason,
    },
    /// Unusable as an export; retained for forensics.
    Incomplete {
        /// Why the snapshot is incomplete.
        reason: String,
    },
}
/// Bounded logical backup snapshot: digest-bound pages, never authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsBackupSnapshot {
    pub source: OrsBackupSourceIdentity,
    pub fence: OrsBackupFence,
    /// Ordered pages starting at index zero.
    pub pages: Vec<OrsBackupPage>,
    /// Denominator digest binding all pages.
    pub denominator_digest: String,
    pub entry_count: u64,
    pub total_bytes: u64,
    pub completeness: BackupCompleteness,
    /// Frozen operational-history snapshot every page of this snapshot was read
    /// under (issue #2967).
    ///
    /// Not optional, and that is the point. The operational axis is the axis that
    /// was previously unaccounted for: its pages could repeat and skip rows and
    /// could carry rows above the declared high-water while every digest in the
    /// archive still agreed, because nothing stated what the operational walk was
    /// supposed to cover. Carrying the frozen identity here makes the denominator
    /// and the pages two statements about the same window, and
    /// [`Self::validate`] requires every page's in-force cursor to be this
    /// identity.
    pub operational_history: OrsOperationalSnapshotIdentity,
    /// Exact continuation that resumes an unfinished operational walk, or `None`
    /// when the walk reached the frozen denominator.
    ///
    /// Page-budget or byte exhaustion leaves a resumable typed partial disposition
    /// carrying this cursor, never a permanent all-or-nothing failure and never a
    /// fabricated finality. It is the operational twin of
    /// [`Self::next_process_stream_recovery_cursor`] and is independent of it: a
    /// snapshot may carry both, either, or neither, and one never stands in for the
    /// other.
    pub next_operational_cursor: Option<OrsOperationalCursor>,
    /// Frozen process-stream recovery family snapshot this snapshot exported,
    /// or `None` when the request declared no family continuation.
    ///
    /// A missing family denominator is legacy/partial evidence, never an empty
    /// complete family (issue #2884): a snapshot produced before the family
    /// cursor existed cannot distinguish "no rows were retained" from "this
    /// exporter never looked at the family", so it may not certify `Complete`.
    pub process_stream_recovery_family: Option<OrsFamilySnapshotIdentity>,
    /// Exact continuation that resumes an incomplete family export, or `None`
    /// when no family continuation is outstanding.
    ///
    /// `max_pages` or byte exhaustion leaves a resumable partial disposition
    /// carrying this cursor, never a permanent all-or-nothing failure.
    pub next_process_stream_recovery_cursor: Option<OrsFamilyCursor>,
    /// Frozen versioned-artifact family snapshot this snapshot exported, or `None`
    /// when the request declared no continuation for that family (issue #1971).
    ///
    /// A missing family denominator is legacy/partial evidence, never an empty
    /// complete family, for the same reason the process-stream recovery family's
    /// is: a snapshot that declares no denominator cannot distinguish "no
    /// generations were retained" from "this exporter never looked at the
    /// family", so it may not certify `Complete`.
    pub versioned_artifact_family: Option<OrsFamilySnapshotIdentity>,
    /// Exact versioned-artifact continuation that resumes an incomplete family
    /// export, or `None` when no such continuation is outstanding.
    pub next_versioned_artifact_cursor: Option<OrsFamilyCursor>,
}
impl OrsBackupSnapshot {
    /// Recompute the denominator digest over source, fence, family and page
    /// digests.
    ///
    /// Every frozen family snapshot identity, every page's in-force and next
    /// family cursors and every outstanding next cursor are all folded in, so the
    /// denominator certifies the composite snapshot and not just one table's pages
    /// (issue #2884, extended to the second paged family by #1971). The two
    /// families are folded in a FIXED order and each under its own label, so a
    /// snapshot cannot present a versioned-artifact denominator as a
    /// process-stream recovery one or omit one of them from the digest without
    /// changing the value.
    ///
    /// Since issue #953 the denominator also transitively binds each page's
    /// capture token and capture window, because it folds `page_digest` and
    /// `page_digest` is recomputable from those fields by
    /// [`OrsBackupPage::expected_page_digest`].
    ///
    /// This is the ONE derivation of the denominator, and since issue #953 it is
    /// not decorative: [`OrsBackupSnapshot::validate`] recomputes it and refuses
    /// a snapshot whose declared `denominator_digest` does not equal it. A
    /// well-formed 64-hex declared denominator that does not hash to this
    /// snapshot's own contents used to pass validation on shape alone, which
    /// meant any caller could declare any denominator and be admitted. There is
    /// still exactly one implementation — a second derivation here would let a
    /// producer and a validator disagree about what the denominator binds, which
    /// is the defect in its original form.
    pub fn snapshot_digest(&self) -> String {
        let mut material = format!(
            "{}:{}:{}:{}:",
            self.source.installation_id,
            self.source.ors_generation,
            self.fence.fence_digest,
            self.fence.high_water_order
        );
        // The operational axis is folded FIRST and under its own label, because it
        // is the axis the high-water above only ever claimed: the fence digest and
        // the declared high-water are caller-asserted fields until the frozen
        // operational identity beside them binds a measured content root, row count
        // and byte denominator to them (issue #2967). The outstanding operational
        // cursor is folded with it, so a snapshot that stops early and one that
        // finished cannot share a denominator.
        material.push_str("operational:");
        material.push_str(&self.operational_history.fence_token());
        material.push(':');
        match &self.next_operational_cursor {
            Some(next) => {
                material.push_str("operational_next:");
                material.push_str(&next.fence_token());
                material.push(':');
            }
            None => material.push_str("operational_next:none:"),
        }
        match &self.process_stream_recovery_family {
            Some(identity) => {
                material.push_str("family:");
                material.push_str(&identity.fence_token());
                material.push(':');
            }
            None => material.push_str("family:none:"),
        }
        match &self.next_process_stream_recovery_cursor {
            Some(next) => {
                material.push_str("next:");
                material.push_str(&next.fence_token());
                material.push(':');
            }
            None => material.push_str("next:none:"),
        }
        match &self.versioned_artifact_family {
            Some(identity) => {
                material.push_str("artifact_family:");
                material.push_str(&identity.fence_token());
                material.push(':');
            }
            None => material.push_str("artifact_family:none:"),
        }
        match &self.next_versioned_artifact_cursor {
            Some(next) => {
                material.push_str("artifact_next:");
                material.push_str(&next.fence_token());
                material.push(':');
            }
            None => material.push_str("artifact_next:none:"),
        }
        for page in &self.pages {
            material.push_str(&page.page_digest);
            material.push(':');
            // The page's own operational boundary is folded here as well as inside
            // `page_digest`. That is not redundancy: `page_digest` proves the page
            // agrees with itself, and this is what lets the denominator prove the
            // pages form one walk in one order — a page whose outgoing operational
            // cursor is not the next page's incoming cursor moves this value even
            // when every individual page re-derives its own digest.
            material.push_str("operational-axis=");
            material.push_str(&page.operational_continuation.cursor.fence_token());
            material.push(':');
            material.push_str(&page.operational_continuation.state_material());
            material.push(':');
            push_family_continuation_material(
                &mut material,
                "recovery-family",
                page.family_continuation.as_ref(),
            );
            push_family_continuation_material(
                &mut material,
                "artifact-family",
                page.versioned_artifact_continuation.as_ref(),
            );
            for entry in &page.entries {
                material.push_str(&entry.payload_digest);
                // The availability state is folded beside the digest it qualifies,
                // so a member whose payload was never obtained and a member whose
                // payload was obtained but hashed to something can never produce
                // the same denominator contribution.
                material.push(':');
                material.push_str(match entry.payload_state {
                    RowPayloadState::Obtained => "obtained",
                    RowPayloadState::Unavailable => "unavailable",
                });
                material.push(':');
            }
        }
        sha256_hex(material.as_bytes())
    }
    /// Validate digest shapes, page continuity and finality, denominator, and completeness.
    ///
    /// A `Complete` snapshot must carry a frozen family identity for BOTH paged
    /// families and no outstanding continuation for either. That is the
    /// compatibility rule for snapshots produced before a family cursor existed:
    /// they declare no family denominator, so they stay `Partial` and can never be
    /// read as a proven complete family. It is also why #1971, which adds a second
    /// cursor-paged family, is a wire-shape change: a snapshot that declared only
    /// the process-stream recovery denominator is no longer able to certify that
    /// the versioned-artifact family was fully retained, and the requirement stays
    /// exact rather than being relaxed for the new slot.
    pub fn validate(&self) -> Result<(), OrsError> {
        require_digest(&self.fence.fence_digest, "backup_fence_digest")?;
        require_digest(&self.denominator_digest, "backup_denominator_digest")?;
        let last_page = self.pages.last();
        // The OPERATIONAL axis is checked independently of both family axes (issue
        // #2967). It is the axis a v4 snapshot could not state at all: there was no
        // frozen identity, no continuation and no upper bound, so a snapshot could
        // repeat a row across pages, skip rows between pages, or carry a row above
        // its own declared high-water and still be internally self-digesting. The
        // field-level rules run below, next to the family rules they are independent
        // of; this one needs no page and so runs here.
        if matches!(self.completeness, BackupCompleteness::Complete)
            && self.next_operational_cursor.is_some()
        {
            return Err(OrsError::InvalidField {
                field: "backup_completeness",
                reason: "a complete snapshot must have no outstanding operational continuation",
            });
        }
        let last_recovery = last_page.and_then(|page| page.family_continuation.as_ref());
        let last_artifact =
            last_page.and_then(|page| page.versioned_artifact_continuation.as_ref());
        // The declared family state must be the state the last page actually
        // reported, for EACH family independently, so a snapshot cannot claim an
        // outstanding continuation the pages do not carry, nor a finished family
        // whose last page still owes one, nor swap one family's declared state
        // onto the other family's page.
        check_declared_family(
            RowFamilyKind::ProcessStreamRecovery,
            self.process_stream_recovery_family.as_ref(),
            self.next_process_stream_recovery_cursor.as_ref(),
            last_recovery,
            "backup_process_stream_recovery_family",
            "backup_next_process_stream_recovery_cursor",
        )?;
        check_declared_family(
            RowFamilyKind::VersionedArtifacts,
            self.versioned_artifact_family.as_ref(),
            self.next_versioned_artifact_cursor.as_ref(),
            last_artifact,
            "backup_versioned_artifact_family",
            "backup_next_versioned_artifact_cursor",
        )?;
        if matches!(self.completeness, BackupCompleteness::Complete) {
            check_complete_denominators(self)?;
        }
        if self.pages.is_empty() {
            return Err(OrsError::InvalidField {
                field: "backup_pages",
                reason: "snapshot must carry at least one page",
            });
        }
        if self.pages.len() > usize::from(MAX_BACKUP_PAGES) {
            return Err(OrsError::InvalidField {
                field: "backup_max_pages",
                reason: "snapshot exceeds MAX_BACKUP_PAGES",
            });
        }
        // The declared operational state against the last page's own continuation,
        // after the empty-page refusal so an empty snapshot is named as one.
        check_declared_operational(
            &self.fence,
            &self.operational_history,
            self.next_operational_cursor.as_ref(),
            last_page.map(|page| &page.operational_continuation),
        )?;
        let mut counted: u64 = 0;
        let mut previous_page_was_final = false;
        for (index, page) in self.pages.iter().enumerate() {
            check_page_shape(page, index, previous_page_was_final)?;
            previous_page_was_final = page.is_last;
            counted =
                counted
                    .checked_add(page.entries.len() as u64)
                    .ok_or(OrsError::InvalidField {
                        field: "backup_entry_count",
                        reason: "entry count overflow",
                    })?;
        }
        // Cross-page operational continuity, over the whole page sequence. It runs
        // on BOTH completeness arms, not only on `Complete`: a truncated snapshot
        // is still a statement about which rows it walked and in what order, and a
        // repeated or out-of-window row is a contradiction on either arm. Each
        // cursor-paged family gets the SAME treatment on its own axis (issue #953),
        // because comparing only the last page's declared family state is exactly
        // "last-page equality alone" and let a middle page re-read a family or flip
        // it back to open without anything noticing. The three domains stay
        // independent: each is checked against its own frozen identity and its own
        // entries.
        check_operational_pages(&self.pages, &self.operational_history)?;
        check_family_pages(
            &self.pages,
            RowFamilyKind::ProcessStreamRecovery,
            self.process_stream_recovery_family.as_ref(),
        )?;
        check_family_pages(
            &self.pages,
            RowFamilyKind::VersionedArtifacts,
            self.versioned_artifact_family.as_ref(),
        )?;
        if counted != self.entry_count {
            return Err(OrsError::InvalidField {
                field: "backup_entry_count",
                reason: "declared entry count does not match pages",
            });
        }
        // THE denominator proof (issue #953, A6). `denominator_digest` is not
        // shape-checked and left there: it is recomputed from this snapshot's own
        // contents through the ONE existing derivation, `snapshot_digest`, and a
        // declared value that does not equal it is refused. The shape check above
        // stays because it is what names the field in the refusal for a
        // non-digest; the comparison here is what makes a well-formed digest
        // prove anything at all. Same variant as the page binding
        // (`OrsBackupPage::validate_binding`), because it is the same defect: a
        // declared digest that disagrees with the content it claims to describe.
        if self.denominator_digest != self.snapshot_digest() {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        check_completeness(
            &self.completeness,
            counted,
            &self.pages,
            &self.operational_history,
            self.process_stream_recovery_family.as_ref(),
            self.versioned_artifact_family.as_ref(),
        )
    }
    /// The member identities this snapshot's own pages declare, as the expected
    /// denominator of a quarantined import (issue #953 import-denominator repair).
    ///
    /// This is the INDEPENDENT expected set the import reconciliation gate
    /// compares against. It is derived from the snapshot, which is a value the
    /// archive itself carries and which [`Self::validate`] has already proved
    /// against its own contents, and from nothing else: no outcome vector, no
    /// caller-supplied roster and no live read takes part in it. A caller that
    /// wants a global known-zero result therefore has to present a snapshot whose
    /// pages really are its whole denominator, or be refused.
    ///
    /// Two dispositions are accepted and no others, and the difference is the
    /// whole point of the check (I05-13: "an incoherent ORS fence fails that class
    /// rather than producing a partial 'successful' backup"; I05-16: absence of a
    /// coverage record means `unknown`, not unrestricted/complete):
    ///
    /// - [`BackupCompleteness::Complete`], where every axis is exhausted and
    ///   every declared denominator was counted against the pages.
    /// - [`BackupCompleteness::Partial`] with
    ///   [`BackupPartialReason::EmptyDenominator`], which is how a genuinely
    ///   EMPTY but fully verified snapshot is representable: no axis owes a row,
    ///   and an empty roster is a measured fact rather than a missing one. This is
    ///   the case that keeps a real empty import representable, so the gate is not
    ///   satisfied by a shortcut that refuses every empty snapshot.
    ///
    /// A snapshot that is `Partial` because an axis still owes rows, `Partial`
    /// because a cursor-paged family was never given a denominator at all, or
    /// `Incomplete` for any reason, cannot establish a global result: its pages
    /// are not the whole denominator, so a roster read off them is a roster of
    /// what the archive happened to carry. Those are
    /// [`OrsError::ReconciliationMismatch`] — unknown stays reconciling
    /// (I14-21), never a zero.
    ///
    /// [`check_observed_members`] runs before the roster is set, on both accepted
    /// dispositions, because a repeated or self-contradicted member must be
    /// refused rather than collapsed into one apparently-covered identity. On the
    /// `Complete` arm `validate` has already run it; running it again is what
    /// makes the `EmptyDenominator` arm equally safe.
    pub fn expected_member_roster(&self) -> Result<Vec<(RowFamilyKind, String)>, OrsError> {
        match &self.completeness {
            BackupCompleteness::Complete
            | BackupCompleteness::Partial {
                reason: BackupPartialReason::EmptyDenominator,
            } => {}
            BackupCompleteness::Partial { .. } | BackupCompleteness::Incomplete { .. } => {
                return Err(OrsError::ReconciliationMismatch);
            }
        }
        check_observed_members(&self.pages)?;
        let mut roster: BTreeSet<(RowFamilyKind, String)> = BTreeSet::new();
        for page in &self.pages {
            for entry in &page.entries {
                roster.insert((entry.family, entry.record_id.clone()));
            }
        }
        Ok(roster.into_iter().collect())
    }
}

/// Requires a `Complete` snapshot to declare every family denominator and to owe
/// nothing on either family axis (issue #2967, W8).
///
/// Since issue #953 "owes nothing" is EXPLICIT: with the last page's declared
/// outstanding cursor required to equal that page's own open frontier
/// ([`check_declared_family`]), an absent cursor means the last page stated
/// [`OrsAxisState::Exhausted`] — and
/// [`OrsFamilyContinuation::validate`], run on every page by
/// `check_page_shape`, has already required that terminal frontier to account for
/// exactly the frozen `family_row_count`. So the denominator a `Complete` snapshot
/// certifies is the same one the axis was opened with, and a family the exporter
/// never looked at still cannot certify completeness.
///
/// Each missing denominator is refused by its own name, because the reason they are
/// required is a compatibility rule and the operator needs to know WHICH family the
/// snapshot never looked at: a snapshot exported before a family cursor existed
/// declares no denominator for that family, so it stays `Partial`, can never be
/// read as a proven complete family, and can never be silently promoted to the
/// operational-coverage claim either (I05-16: absent coverage means unknown, not
/// complete).
fn check_complete_denominators(snapshot: &OrsBackupSnapshot) -> Result<(), OrsError> {
    if snapshot.process_stream_recovery_family.is_none() {
        return Err(OrsError::InvalidField {
            field: "backup_completeness",
            reason: "a complete snapshot must carry a process-stream recovery family denominator",
        });
    }
    if snapshot.versioned_artifact_family.is_none() {
        return Err(OrsError::InvalidField {
            field: "backup_completeness",
            reason: "a complete snapshot must carry a versioned-artifact family denominator",
        });
    }
    if snapshot.next_process_stream_recovery_cursor.is_some()
        || snapshot.next_versioned_artifact_cursor.is_some()
    {
        return Err(OrsError::InvalidField {
            field: "backup_completeness",
            reason: "a complete snapshot must have no outstanding family continuation",
        });
    }
    Ok(())
}

/// Checks the declared operational snapshot state against the last page's own
/// operational continuation (issue #2967).
///
/// The operational twin of [`check_declared_family`], and the same three questions
/// asked of the same three facts: does the declared frozen identity name the
/// identity the last page was actually read under, does the declared outstanding
/// cursor equal the last page's own next cursor, and can the declared identity
/// disagree with the request's own high-water?
///
/// The third question has no family analogue and is the A5 rule. `fence` is
/// caller-asserted input, and `OrsBackupFence::high_water_order` was never compared
/// with anything that could refuse it, so a snapshot could declare one high-water
/// at the top and freeze its operational window at another. Here the declared
/// identity's high-water must equal the fence's, and it is the identity — a value
/// the store measured — that the pages are then counted against.
fn check_declared_operational(
    fence: &OrsBackupFence,
    identity: &OrsOperationalSnapshotIdentity,
    declared_next: Option<&OrsOperationalCursor>,
    last: Option<&OrsOperationalContinuation>,
) -> Result<(), OrsError> {
    if identity.schema_version != BACKUP_SNAPSHOT_SCHEMA_VERSION {
        return Err(OrsError::MigrationRequired {
            reason: format!(
                "backup operational identity schema {} unsupported, expected {BACKUP_SNAPSHOT_SCHEMA_VERSION}",
                identity.schema_version
            ),
        });
    }
    // A5, at the snapshot boundary. The store already refuses a request whose
    // declared high-water is not the one it observed (`check_export_fence`), so a
    // store-produced snapshot always agrees here; the rule exists for a RECEIVED
    // snapshot, where the fence is a bare field and the pages are somebody else's
    // bytes. Without it a snapshot could declare one high-water at the top and
    // freeze its window at another, and the A5 bound the pages are counted under
    // would be the one the sender chose rather than the one the fence claims.
    if identity.high_water_order != fence.high_water_order {
        return Err(OrsError::InvalidField {
            field: "backup_operational_history",
            reason: "the declared operational window is frozen at a different high-water order than the snapshot's own fence claims",
        });
    }
    if identity.lower_order_bound > identity.high_water_order {
        return Err(OrsError::InvalidField {
            field: "backup_operational_lower_order_bound",
            reason: "the declared walk window must not start above the high-water order",
        });
    }
    require_digest(
        &identity.operational_root_digest,
        "backup_operational_root_digest",
    )?;
    if let Some(next) = declared_next {
        next.validate()?;
    }
    let Some(last) = last else {
        return Err(OrsError::InvalidField {
            field: "backup_operational_continuation",
            reason: "a snapshot must carry an operational continuation on its last page",
        });
    };
    if last.cursor.identity != *identity {
        return Err(OrsError::InvalidField {
            field: "backup_operational_history",
            reason: "declared operational denominator is not the frozen operational snapshot the last page was read under",
        });
    }
    // The declared outstanding cursor is the last page's OPEN frontier, so an
    // exhausted last page (issue #953) publishes nothing and an open one publishes
    // exactly the frontier the page itself carries. A byte or page LIMIT is the open
    // arm and is never converted to exhausted.
    if last.open_cursor() != declared_next {
        return Err(OrsError::InvalidField {
            field: "backup_next_operational_cursor",
            reason: "declared operational continuation does not match the last page",
        });
    }
    Ok(())
}

/// What one page's own entries say about the operational walk (issue #2967).
///
/// The three facts the page's continuation rules and the cross-page chain rule are
/// both decided from, measured once so that neither has to re-walk the entries.
/// [`Self::last_order`] is the cursor's own bound when the page emitted no
/// operational row, which is what makes "did this page move the walk" a question
/// about [`Self::emitted`] alone.
struct OperationalPageTail {
    /// Operational rows this page emitted.
    emitted: u64,
    /// Order of this page's last emitted operational row, or the incoming cursor's
    /// own bound when the page emitted none.
    last_order: u64,
    /// The incoming cursor's row count plus this page's emitted rows.
    walked: u64,
}

/// Measures one page's operational tail from its own entries (issue #2967).
///
/// Per entry, in one pass and no sort: the operational rows must strictly increase
/// and follow the incoming cursor's exclusive bound, and none may sit above the
/// frozen high-water. The high-water half is A5 — a row above it belongs to a
/// successor snapshot and cannot appear under the older fence even though it may
/// have been durable and stable before the export began — and the ordering half is
/// what makes a repeated or reordered row a refusal rather than a member.
fn measure_operational_tail(
    page: &OrsBackupPage,
    identity: &OrsOperationalSnapshotIdentity,
) -> Result<OperationalPageTail, OrsError> {
    let continuation = &page.operational_continuation;
    let mut last_order = continuation.cursor.after_order;
    let mut emitted: u64 = 0;
    for entry in &page.entries {
        if entry.family != RowFamilyKind::OperationalHistory {
            continue;
        }
        emitted = emitted.checked_add(1).ok_or(OrsError::InvalidField {
            field: "backup_operational_entry",
            reason: "operational entry count overflow",
        })?;
        if entry.order <= last_order {
            return Err(OrsError::InvalidField {
                field: "backup_operational_entry",
                reason: "operational entries must strictly increase and follow the incoming cursor; a repeated or reordered row is a duplicated or out-of-order member",
            });
        }
        if entry.order > identity.high_water_order {
            return Err(OrsError::InvalidField {
                field: "backup_operational_entry",
                reason: "an operational entry is above the frozen high-water order and belongs to a successor snapshot",
            });
        }
        last_order = entry.order;
    }
    let walked = continuation
        .cursor
        .emitted_rows
        .checked_add(emitted)
        .ok_or(OrsError::InvalidField {
            field: "backup_operational_cursor",
            reason: "emitted operational row count overflow",
        })?;
    Ok(OperationalPageTail {
        emitted,
        last_order,
        walked,
    })
}

/// Checks a page's OWN operational continuation against the tail its entries
/// measured (issue #2967, extended by #953).
///
/// A page that leaves the walk OPEN must have moved it — otherwise the page
/// budget would be spent without the walk ever moving — and its frontier must be
/// derived from the page's exact emitted tail, in both its order and its row
/// count. A page that leaves it EXHAUSTED must instead have consumed the frozen
/// denominator exactly, and must say so with the frontier the walk actually
/// reached, so "exhausted" is only ever the truthful statement that the walk
/// finished and never a way to stop early.
///
/// Both arms additionally require the frontier to BE the page's tail. That is the
/// fact the previous shape could not state: with `next: Option<Cursor>` a page
/// that emitted the last operational row had nothing to hand on, and the only
/// boundary a following page could be built under was the axis's own pre-page
/// cursor — which re-read the whole walk.
fn check_operational_continuation(
    continuation: &OrsOperationalContinuation,
    tail: &OperationalPageTail,
    identity: &OrsOperationalSnapshotIdentity,
) -> Result<(), OrsError> {
    let refused = |reason: &'static str| -> OrsError {
        OrsError::InvalidField {
            field: "backup_operational_continuation",
            reason,
        }
    };
    let frontier = continuation.frontier();
    if frontier.after_order != tail.last_order {
        return Err(refused(
            "the outgoing operational cursor is not derived from the page's last operational member",
        ));
    }
    if frontier.emitted_rows != tail.walked {
        return Err(refused(
            "the outgoing operational cursor does not account for exactly the rows this page emitted",
        ));
    }
    match &continuation.state {
        OrsAxisState::Open(_) => {
            if tail.emitted == 0 {
                return Err(refused(
                    "a page must not declare an operational continuation without emitting an operational row",
                ));
            }
            Ok(())
        }
        OrsAxisState::Exhausted(_) => {
            if tail.walked != identity.operational_row_count {
                return Err(refused(
                    "the walk declared itself exhausted before the frozen operational denominator was reached",
                ));
            }
            Ok(())
        }
    }
}

/// Requires the page that follows `page` to have been read under the boundary `page`
/// actually reached (issue #2967, W6/A2; split by explicit state in #953).
///
/// The arm is chosen by what `page` OWES, not by how many rows it happened to emit,
/// and the two are not the same question:
///
/// - `page` leaves the axis OPEN, so the successor must present exactly the frontier
///   `page` named, and its refusal is the truncation refusal.
/// - `page` leaves it EXHAUSTED, and "declares itself exhausted" is a PROOF of
///   that, not an assumption: [`check_operational_continuation`]'s exhausted arm has
///   already established `walked == identity.operational_row_count`. The successor
///   must then present the SAME final frontier, must itself still be exhausted, and
///   must emit ZERO further operational rows. Those three obligations together are
///   what make an exhausted axis inert: a successor that resumed the walk, that
///   re-opened it, or that read it again is refused.
///
/// The exhausted arm is therefore not "no requirement". The successor must carry
/// the walk's real TAIL and nothing else, and the two differ exactly when the walk
/// finished early: a start cursor is what the previous incarnation of the exporter
/// carried, and it re-read the frozen lower bound and re-emitted every operational
/// row the snapshot had already exported. The chain is the structural defence
/// against that, because [`check_observed_members`] — which refuses a member
/// observed twice — runs on the `Complete` arm only, so on a `Partial` snapshot
/// nothing else would. The frontier is checked on the two bounds a pure validator
/// can re-derive from the pages themselves; the durable key and the prefix
/// commitment stay out of scope for the same reason they are out of scope in
/// [`check_operational_pages`], and are proved at the read boundary instead.
fn check_operational_successor(
    continuation: &OrsOperationalContinuation,
    next_page: &OrsBackupPage,
    next_tail: &OperationalPageTail,
) -> Result<(), OrsError> {
    let refused = |reason: &'static str| -> OrsError {
        OrsError::InvalidField {
            field: "backup_operational_continuation",
            reason,
        }
    };
    let successor = &next_page.operational_continuation;
    if successor.cursor != *continuation.frontier() {
        return Err(match &continuation.state {
            OrsAxisState::Open(_) => refused(
                "the next page did not continue from this page's exact emitted operational tail",
            ),
            OrsAxisState::Exhausted(_) => refused(
                "a page after the exhausted operational walk did not resume from the walk's exact final frontier",
            ),
        });
    }
    if let OrsAxisState::Exhausted(_) = &continuation.state {
        if successor.state.is_open() {
            return Err(refused(
                "an exhausted operational walk may not become open again",
            ));
        }
        if next_tail.emitted != 0 {
            return Err(refused(
                "an exhausted operational walk must emit no further operational rows",
            ));
        }
    }
    Ok(())
}

/// Proves cross-page operational continuity independently of the family axes
/// (issue #2967, A11/A12; explicit open/exhausted split in #953).
///
/// Every page is checked against the SAME frozen identity, and the pages must form
/// ONE exact chain:
///
/// - Every page is bound to the page that follows it by
///   [`check_operational_successor`], which is what makes duplication and skipping
///   structurally impossible rather than merely unlikely: page N+1 cannot re-read
///   anything page N emitted, and cannot start anywhere other than where page N
///   actually stopped, because the boundary it must present IS page N's emitted
///   tail. Its two arms are the OPEN and EXHAUSTED states, and the exhausted one
///   additionally forbids re-opening the axis or emitting into it again.
/// - The first page starts the walk: its in-force cursor must have emitted nothing.
///   A chain that is exact from page 1 onward can still under-report coverage if
///   page 0 opens in the middle, which is the same defect as a stride window with a
///   large offset. A cursor that emitted nothing is already forced to name the
///   frozen window's lower bound by [`OrsOperationalCursor::validate`], so this is
///   the whole opening-boundary rule.
/// - Within a page, operational orders strictly increase, stay above the incoming
///   cursor's exclusive bound, and never exceed the frozen high-water. The last rule
///   is A5: a row above the high-water belongs to a successor snapshot and cannot
///   appear under the older fence even though it may have been durable and stable
///   before the export began.
/// - A page that declares the walk exhausted must have exactly consumed the frozen
///   denominator, and a page that leaves it open must have made strict progress.
///   Without the progress rule a page could emit no operational rows at all while
///   pointing at the same boundary, and the page budget would be spent without the
///   walk ever moving.
///
/// The one thing deliberately NOT checked here is the outgoing cursor's durable key
/// and prefix chain: an entry carries the operation's `record_id` and its digest,
/// not the durable history key the owner walked under or the chained commitment
/// over the emitted prefix, so a pure validator cannot re-derive them. They are
/// proved at the READ boundary instead, where the store re-derives the chain from
/// durable state against the next page's in-force cursor — the same division of
/// labour the family axis already uses.
fn check_operational_pages(
    pages: &[OrsBackupPage],
    identity: &OrsOperationalSnapshotIdentity,
) -> Result<(), OrsError> {
    // Measured once for the whole sequence, because the successor rule needs the
    // NEXT page's tail as well as this page's: "an exhausted axis emits nothing
    // further" is a statement about the successor's entries.
    let tails: Vec<OperationalPageTail> = pages
        .iter()
        .map(|page| measure_operational_tail(page, identity))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, page) in pages.iter().enumerate() {
        let continuation = &page.operational_continuation;
        if continuation.cursor.identity != *identity {
            return Err(OrsError::InvalidField {
                field: "backup_operational_continuation",
                reason: "a page was read under a different frozen operational snapshot than the snapshot declares",
            });
        }
        if index == 0 && continuation.cursor.emitted_rows != 0 {
            // The first page of a walk is the walk's start. Without this, an archive
            // could open mid-walk and still chain every later page correctly: the
            // chain would be exact and the coverage would silently start in the
            // middle, which is the same defect as a stride window with a large
            // offset.
            return Err(OrsError::InvalidField {
                field: "backup_operational_continuation",
                reason: "the first page must start the walk, not continue one that is already under way",
            });
        }
        let tail = &tails[index];
        check_operational_continuation(continuation, tail, identity)?;
        if let Some(next_page) = pages.get(index + 1) {
            check_operational_successor(continuation, next_page, &tails[index + 1])?;
        }
    }
    Ok(())
}

/// What one page's own entries say about one cursor-paged family's walk
/// (issue #953).
///
/// The family twin of [`OperationalPageTail`], and the same measurement rather
/// than a trust: the declared side is the frozen `family_row_count` the owner
/// measured when it opened the family, and the observed side is what this page
/// actually carries for that family. A family row's `order` is a reporting value
/// (its observation time, or its artifact generation) and carries no order
/// information, so only the COUNT is re-derivable from a page — which is exactly
/// what the cross-page chain needs, since the boundary itself is proved at the
/// read boundary by `check_family_cursor_boundary`.
struct FamilyPageTail {
    /// Rows of this family this page emitted.
    emitted: u64,
    /// The in-force cursor's row count plus this page's emitted rows.
    walked: u64,
}
/// Measures one page's family tail from its own entries.
fn measure_family_tail(
    page: &OrsBackupPage,
    family: RowFamilyKind,
) -> Result<FamilyPageTail, OrsError> {
    let emitted: u64 = page
        .entries
        .iter()
        .filter(|entry| entry.family == family)
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    let base = page_family_continuation(page, family)
        .map_or(0, |continuation| continuation.cursor.emitted_rows);
    let walked = base.checked_add(emitted).ok_or(OrsError::InvalidField {
        field: "backup_family_continuation",
        reason: "emitted family row count overflow",
    })?;
    Ok(FamilyPageTail { emitted, walked })
}
/// The one page's continuation for `family`, or `None` when the page declares no
/// denominator for it.
fn page_family_continuation(
    page: &OrsBackupPage,
    family: RowFamilyKind,
) -> Option<&OrsFamilyContinuation> {
    match family {
        RowFamilyKind::ProcessStreamRecovery => page.family_continuation.as_ref(),
        RowFamilyKind::VersionedArtifacts => page.versioned_artifact_continuation.as_ref(),
        _ => None,
    }
}
/// Checks one page's OWN family continuation against the tail its entries measured
/// (issue #953).
///
/// The family twin of [`check_operational_continuation`]. The OPEN arm requires
/// the frontier to account for exactly the rows this page emitted, so a page
/// cannot claim to owe a boundary it did not reach; the EXHAUSTED arm requires it
/// to account for exactly those rows AND for the frozen `family_row_count`, so
/// only an owner-established terminal frontier can close the axis.
///
/// Unlike the operational axis there is deliberately NO progress requirement on
/// the open arm. A family that shares a page with an open operational walk whose
/// segment already spent the whole row budget emits nothing and legitimately owes
/// the same boundary, and refusing that would make a family unpaginable whenever
/// the operational walk is the longer of the two.
fn check_family_continuation(
    family: RowFamilyKind,
    continuation: &OrsFamilyContinuation,
    tail: &FamilyPageTail,
    identity: &OrsFamilySnapshotIdentity,
) -> Result<(), OrsError> {
    let field = family_continuation_field(family);
    let frontier = continuation.frontier();
    if frontier.emitted_rows != tail.walked {
        return Err(OrsError::InvalidField {
            field,
            reason: "the outgoing family cursor does not account for exactly the rows this page emitted",
        });
    }
    if let Some(final_cursor) = continuation.state.exhausted_cursor()
        && final_cursor.emitted_rows != identity.family_row_count
    {
        return Err(OrsError::InvalidField {
            field,
            reason: "the family declared itself exhausted before the frozen family denominator was reached",
        });
    }
    Ok(())
}
/// Requires the page that follows `page` to have been read under the boundary
/// `page` actually reached, on one family axis (issue #953).
///
/// The exact family twin of [`check_operational_successor`], on the same
/// cross-page chain the operational axis has always had. Before this the families
/// had NO cross-page chain at all: only the LAST page's declared state was compared
/// with the snapshot's own fields, which is exactly "last-page equality alone",
/// so a middle page could re-read a family's rows, skip a durable-key prefix, or
/// flip a family from exhausted back to open and nothing in the validator noticed.
fn check_family_successor(
    family: RowFamilyKind,
    continuation: &OrsFamilyContinuation,
    next_page: &OrsBackupPage,
    next_tail: &FamilyPageTail,
) -> Result<(), OrsError> {
    let field = family_continuation_field(family);
    let refused = |reason: &'static str| -> OrsError { OrsError::InvalidField { field, reason } };
    let Some(successor) = page_family_continuation(next_page, family) else {
        return Err(refused(
            "a page after a declared cursor-paged family must carry that family's continuation",
        ));
    };
    if successor.cursor != *continuation.frontier() {
        return Err(match &continuation.state {
            OrsAxisState::Open(_) => {
                refused("the next page did not continue from this page's exact emitted family tail")
            }
            OrsAxisState::Exhausted(_) => refused(
                "a page after an exhausted family did not resume from the family's exact final frontier",
            ),
        });
    }
    if let OrsAxisState::Exhausted(_) = &continuation.state {
        if successor.state.is_open() {
            return Err(refused(
                "an exhausted family axis may not become open again",
            ));
        }
        if next_tail.emitted != 0 {
            return Err(refused(
                "an exhausted family axis must emit no further rows",
            ));
        }
    }
    Ok(())
}
/// The field name one family's continuation is refused under, so no two axes'
/// refusals read alike.
fn family_continuation_field(family: RowFamilyKind) -> &'static str {
    match family {
        RowFamilyKind::VersionedArtifacts => "backup_versioned_artifact_family_continuation",
        _ => "backup_family_continuation",
    }
}
/// Proves cross-page continuity for ONE cursor-paged family independently of the
/// operational axis and of the other family (issue #953).
///
/// A snapshot that declares no denominator for `family` has nothing to prove here:
/// the third condition — a family the request never asked about — is UNKNOWN
/// COVERAGE, not an exhausted axis, and it is [`check_declared_family`] and
/// [`check_complete_denominators`] that keep it from reading as one. A snapshot
/// that DOES declare the denominator must carry that family's continuation on
/// EVERY page, must run it under the one declared frozen identity, and must form
/// the same exact chain the operational axis forms.
///
/// The opening-boundary rule the operational axis has is deliberately absent here,
/// and the asymmetry is a real difference rather than an omission: a snapshot
/// publishes a family's outstanding cursor precisely so a caller can RESUME a
/// truncated family export, while the operational walk is explicitly re-opened as
/// a new window instead (`export_page_in` refuses a page 0 with a non-start
/// operational cursor). Resuming a family mid-way is therefore representable here
/// and is bounded instead by [`check_declared_members`], which counts a `Complete`
/// snapshot's family rows against the frozen `family_row_count` and so cannot be
/// satisfied by a suffix.
fn check_family_pages(
    pages: &[OrsBackupPage],
    family: RowFamilyKind,
    declared: Option<&OrsFamilySnapshotIdentity>,
) -> Result<(), OrsError> {
    let Some(identity) = declared else {
        return Ok(());
    };
    let field = family_continuation_field(family);
    let tails: Vec<FamilyPageTail> = pages
        .iter()
        .map(|page| measure_family_tail(page, family))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, page) in pages.iter().enumerate() {
        let Some(continuation) = page_family_continuation(page, family) else {
            return Err(OrsError::InvalidField {
                field,
                reason: "a declared cursor-paged family must carry its continuation on every page",
            });
        };
        if continuation.cursor.identity != *identity {
            return Err(OrsError::InvalidField {
                field,
                reason: "a page was read under a different frozen family snapshot than the snapshot declares",
            });
        }
        let tail = &tails[index];
        check_family_continuation(family, continuation, tail, identity)?;
        if let Some(next_page) = pages.get(index + 1) {
            check_family_successor(family, continuation, next_page, &tails[index + 1])?;
        }
    }
    Ok(())
}

/// Checks one paged family's declared snapshot state against the last page's
/// continuation for that SAME family (issue #2884, extended to the second
/// cursor-paged family by #1971).
///
/// The four arguments are the family's own three declared fields and the
/// continuation the last page reported FOR THAT FAMILY, so a snapshot cannot
/// present one family's page as the other's denominator. `identity_field` and
/// `next_field` are the caller's own field names, which keeps the refusal
/// pointing at the slot that is actually wrong.
fn check_declared_family(
    family: RowFamilyKind,
    identity: Option<&OrsFamilySnapshotIdentity>,
    declared_next: Option<&OrsFamilyCursor>,
    last: Option<&OrsFamilyContinuation>,
    identity_field: &'static str,
    next_field: &'static str,
) -> Result<(), OrsError> {
    if let Some(identity) = identity {
        if identity.family != family {
            return Err(OrsError::InvalidField {
                field: identity_field,
                reason: "declared family denominator names a different row family",
            });
        }
        if !identity.family.uses_family_cursor() {
            return Err(OrsError::InvalidField {
                field: identity_field,
                reason: "family is not paged through a typed family cursor",
            });
        }
        require_digest(&identity.family_root_digest, "backup_family_root_digest")?;
    }
    if let Some(next) = declared_next {
        next.validate()?;
    }
    if identity.is_some() && last.is_none() {
        return Err(OrsError::InvalidField {
            field: identity_field,
            reason: "a declared family denominator requires a family continuation on the last page",
        });
    }
    // The declared frozen identity must be the identity the last page was
    // actually read under, not merely a well-formed identity of the right
    // family. Without this the declaration and the pages were two independent
    // statements: a snapshot could name one frozen family snapshot at the top
    // and carry pages read under a different one, and the declared row count
    // that `check_observed_members` later counts against would describe rows
    // that are not in these pages at all.
    if let (Some(identity), Some(continuation)) = (identity, last)
        && continuation.cursor.identity != *identity
    {
        return Err(OrsError::InvalidField {
            field: identity_field,
            reason: "declared family denominator is not the frozen family the last page was read under",
        });
    }
    if let Some(continuation) = last
        && continuation.open_cursor() != declared_next
    {
        return Err(OrsError::InvalidField {
            field: next_field,
            reason: "declared family continuation does not match the last page",
        });
    }
    Ok(())
}

/// Validate one page's index continuity, finality, self-binding and entry bound.
///
/// The self-binding half is [`OrsBackupPage::validate_binding`] and is NOT
/// duplicated here: shape alone is not evidence of anything, and a validator
/// that re-derives the page digest differently from the producer is the defect
/// issue #953 names. This function only adds what a single page in isolation
/// cannot know: that the pages before it were not final and that this page's index
/// is the one the sequence demands.
fn check_page_shape(
    page: &OrsBackupPage,
    index: usize,
    previous_page_was_final: bool,
) -> Result<(), OrsError> {
    if previous_page_was_final {
        return Err(OrsError::InvalidField {
            field: "backup_page_is_last",
            reason: "a page must not follow an earlier final page",
        });
    }
    let expected = u32::try_from(index).map_err(|_| OrsError::InvalidField {
        field: "backup_page_index",
        reason: "page index exceeds u32 range",
    })?;
    if page.page_index != expected {
        return Err(OrsError::InvalidField {
            field: "backup_page_index",
            reason: "pages must be continuous from zero",
        });
    }
    page.validate_binding()?;
    // A final page must leave NO continuation open on ANY axis. All three are
    // checked because `is_last` is the conjunction over all of them, so a producer
    // that computed finality from only the operational walk or only the families
    // would be caught here (issue #1971, extended by #2967). This is what makes
    // finality AUTHORITATIVE: it cannot be asserted while any axis still owes rows.
    let operational_open = page.operational_continuation.operational_open();
    let family_open = page
        .family_continuation
        .as_ref()
        .is_some_and(OrsFamilyContinuation::family_open)
        || page
            .versioned_artifact_continuation
            .as_ref()
            .is_some_and(OrsFamilyContinuation::family_open);
    if page.is_last && (operational_open || family_open) {
        return Err(OrsError::InvalidField {
            field: "backup_page_is_last",
            reason: "a final page must not leave an open operational or family continuation",
        });
    }
    Ok(())
}
/// Enforce completeness rules: `Complete` needs entries, valid digests, a final
/// last page, and members that agree with the declared denominator.
///
/// The member census ([`check_observed_members`], [`check_declared_members`]) is
/// the A6 half and runs only on the `Complete` arm, which is exactly the claim
/// it has to police: a `Partial` or `Incomplete` snapshot is by definition not
/// asserting a proven denominator, so an unavailable member there is a stated
/// reason rather than a contradiction. Nothing here downgrades a `Complete`
/// declaration to `Partial` silently — a snapshot that contradicts its own
/// contents is malformed, and every other violation in this validator is a
/// refusal, so this one is too.
fn check_completeness(
    completeness: &BackupCompleteness,
    counted: u64,
    pages: &[OrsBackupPage],
    operational_history: &OrsOperationalSnapshotIdentity,
    recovery_family: Option<&OrsFamilySnapshotIdentity>,
    artifact_family: Option<&OrsFamilySnapshotIdentity>,
) -> Result<(), OrsError> {
    match completeness {
        BackupCompleteness::Complete => {
            if counted == 0 {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "complete snapshot must carry entries",
                });
            }
            if !matches!(pages.last(), Some(page) if page.is_last) {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "complete snapshot must end with a final page",
                });
            }
            for page in pages {
                require_digest(&page.page_digest, "backup_page_digest")?;
            }
            check_member_payload_states(pages, true)?;
            check_observed_members(pages)?;
            // The operational denominator is counted exactly like each family
            // denominator, and for the same reason: `Complete` is a claim that the
            // declared walk was walked, and a claim is proved by the members the
            // pages carry rather than by a number the snapshot declared. A
            // non-empty denominator is a precondition for `Complete` for the same
            // reason it is for the families (I05-16: absent coverage means unknown,
            // not complete), and it is checked on the identity rather than inferred
            // from row presence.
            if operational_history.operational_row_count == 0 {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "a complete snapshot must declare a non-empty operational denominator; an empty declared window is unknown coverage, not complete coverage",
                });
            }
            check_declared_operational_members(operational_history, pages)?;
            check_declared_members(RowFamilyKind::ProcessStreamRecovery, recovery_family, pages)?;
            check_declared_members(RowFamilyKind::VersionedArtifacts, artifact_family, pages)?;
            // Digest shapes are required only now, and only for members whose
            // payload was actually obtained. A member that declares its payload
            // unavailable carries no digest at all, so demanding a 64-hex value
            // there would demand a digest of bytes nobody read; demanding a
            // non-empty one on an unavailable member is refused by
            // `check_observed_members` as a fabricated proof.
            for page in pages {
                for entry in &page.entries {
                    if entry.payload_state == RowPayloadState::Obtained {
                        require_digest(&entry.payload_digest, "backup_payload_digest")?;
                    }
                }
            }
            Ok(())
        }
        BackupCompleteness::Partial { reason } => {
            // A typed reason needs no emptiness check: every
            // `BackupPartialReason` variant carries the axis and the exact
            // outstanding boundary, so there is no way to state "partial" without
            // saying which axis is unfinished. That is the whole reason the string
            // was replaced (issue #2967, W13).
            if let BackupPartialReason::FamilyContinuationOutstanding { family, .. } = reason
                && !family.uses_family_cursor()
            {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "a partial family continuation must name a cursor-paged row family",
                });
            }
            check_member_payload_states(pages, false)?;
            Ok(())
        }
        BackupCompleteness::Incomplete { reason } => {
            if reason.is_empty() {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "an incomplete snapshot must state a reason",
                });
            }
            check_member_payload_states(pages, false)?;
            Ok(())
        }
    }
}

/// Requires every member's payload-availability claim to be self-consistent, and
/// — when `requires_obtained` — requires every member's payload to have been
/// obtained at all.
///
/// Two rules, and they are different rules:
///
/// - ALWAYS: a member that says its payload is unavailable must carry no payload
///   digest. A digest there is a hash of bytes the same entry says were never
///   read, so it is a fabricated proof, and it is refused as the opaque-payload
///   outcome rather than as a shape problem because the availability claim is
///   what is wrong.
/// - `Complete` ONLY: no member may be unavailable at all. A `Complete` snapshot
///   is a claim that the whole denominator is in evidence, so a member whose
///   ciphertext was never obtained contradicts that claim outright. Inside a
///   `Partial` or `Incomplete` snapshot the same member is the stated reason
///   rather than a contradiction, which is why the rule is scoped and not
///   unconditional.
///
/// This runs on both arms while the duplicate and conflict census below runs on
/// the `Complete` arm only: an unavailable member is a legitimate partial, but a
/// member whose availability claim contradicts its own digest never is.
fn check_member_payload_states(
    pages: &[OrsBackupPage],
    requires_obtained: bool,
) -> Result<(), OrsError> {
    for page in pages {
        for entry in &page.entries {
            let unavailable = entry.payload_state == RowPayloadState::Unavailable;
            if unavailable && !entry.payload_digest.is_empty() {
                return Err(OrsError::IntegrityProblem {
                    record_type: "backup_opaque_payload",
                    reason: format!(
                        "member {:?} of family {:?} declares its payload unavailable and also carries a payload digest",
                        entry.record_id, entry.family
                    ),
                });
            }
            if unavailable && requires_obtained {
                return Err(OrsError::IntegrityProblem {
                    record_type: "backup_opaque_payload",
                    reason: format!(
                        "member {:?} of family {:?} has no obtainable payload, so this snapshot cannot be complete",
                        entry.record_id, entry.family
                    ),
                });
            }
        }
    }
    Ok(())
}

/// What one member identity was first observed to say, so a later occurrence of
/// the same identity can be told apart from a genuinely different row.
#[derive(Clone, Copy, Eq, PartialEq)]
struct ObservedMember {
    order: u64,
    effect_class: StoredEffectClass,
    payload_state: RowPayloadState,
    has_payload_digest: bool,
}

/// The two identity-level refusals a `Complete` snapshot can earn, kept apart on
/// purpose.
///
/// A repeat of one identity with the SAME facts is a duplicate: the denominator
/// counts the member twice while the frozen family counted it once, so the
/// snapshot is internally inconsistent even though no single row lies. A repeat
/// with DIFFERENT facts is a conflict: two members claim one identity and
/// disagree about what it is, which is the shape a forged or spliced archive
/// takes. Collapsing them into one error would make the operator unable to tell
/// a double-counted row from a row that was rewritten, which is the difference
/// between re-running the capture and investigating the archive.
#[derive(Clone, Copy)]
enum MemberRoster {
    Duplicate,
    Conflicting,
}

/// Keys the members the pages observed and refuses a `Complete` snapshot whose
/// roster is not a roster: a repeated member identity, and a member that
/// conflicts with its own first observation.
///
/// The opaque-payload rule is [`check_member_payload_states`], not this
/// function: availability is a per-member claim that holds on a partial
/// snapshot too, while a doubled or contradicted member only contradicts a
/// completeness claim.
///
/// This is the ONE place member identity is resolved, and it is deliberately
/// exhaustive over the pages rather than over one page: a member identity that
/// repeats only ACROSS pages is invisible to any per-page check, and the whole
/// point of a denominator is that it spans pages. The key is the typed
/// `(RowFamilyKind, String)` pair, not a formatted string, so no `record_id` can
/// alias two members onto one.
///
/// ONE family is the exception, and it is an exact exception rather than a
/// relaxation. Operational history is append-only by construction: every phase
/// transition of one operation allocates a NEW `operation_order` and inserts a NEW
/// history row carrying the same `record_id`, so a single operation legitimately
/// appears once per phase it passed through, each at its own order with its own
/// effect class. A repeated `record_id` at a DIFFERENT order is therefore a
/// revision, not a duplicate, and a repeated `(record_id, order)` is a duplicate
/// even though its facts differ — one operation order is one durable revision, so
/// two entries claiming it are two claims about one row. Every other family keeps
/// the stricter one-observation-per-identity rule, and the operational exception is
/// scoped to the one family whose durable write path actually produces revisions;
/// it is not a general weakening of the census.
fn check_observed_members(pages: &[OrsBackupPage]) -> Result<(), OrsError> {
    let mut roster: BTreeMap<(RowFamilyKind, &str), Vec<ObservedMember>> = BTreeMap::new();
    for page in pages {
        for entry in &page.entries {
            let key = (entry.family, entry.record_id.as_str());
            let observed = ObservedMember {
                order: entry.order,
                effect_class: entry.effect_class,
                payload_state: entry.payload_state,
                has_payload_digest: !entry.payload_digest.is_empty(),
            };
            match roster.get_mut(&key) {
                None => {
                    roster.insert(key, vec![observed]);
                }
                Some(history) => {
                    if history.contains(&observed) {
                        return Err(member_roster_refused(MemberRoster::Duplicate, entry));
                    }
                    if entry.family == RowFamilyKind::OperationalHistory
                        && !history.iter().any(|first| first.order == observed.order)
                    {
                        // A later phase of the same operation: a distinct durable
                        // revision at its own order, which is what append-only
                        // operational history looks like.
                        history.push(observed);
                        continue;
                    }
                    return Err(member_roster_refused(MemberRoster::Conflicting, entry));
                }
            }
        }
    }
    Ok(())
}

/// The distinct typed refusal for each way a member roster can be wrong.
///
/// Two different `OrsError` variants, not one variant with two reasons: the
/// operator action differs (re-run the bounded capture versus treat the archive
/// as untrustworthy) and a caller matching on the variant must be able to tell
/// them apart without parsing a message.
fn member_roster_refused(roster: MemberRoster, entry: &OrsBackupEntry) -> OrsError {
    match roster {
        MemberRoster::Duplicate => OrsError::DuplicateConflict,
        MemberRoster::Conflicting => OrsError::IntegrityProblem {
            record_type: "backup_member_roster",
            reason: format!(
                "member {:?} of family {:?} is observed more than once with disagreeing facts",
                entry.record_id, entry.family
            ),
        },
    }
}

/// Requires the operational rows a `Complete` snapshot declares in its frozen
/// window to be the operational rows its pages actually carry (issue #2967).
///
/// The same measurement, not a trust, that
/// [`check_declared_members`] performs for each cursor-paged family. The declared
/// side is `operational_row_count`, taken by the owner from a streaming pass over
/// the operational history in `(lower_order_bound, high_water_order]`; the observed
/// side is the count of this snapshot's operational entries. When the two disagree
/// the snapshot claims a walk it did not perform.
///
/// Both directions are refused. A shortfall means rows left the denominator, which
/// is the A4 starvation case; an excess means the pages carry a row the frozen
/// window never contained, which is either an above-high-water row or a page from a
/// different walk. The exact continuation chain in [`check_operational_pages`]
/// already makes duplication structurally impossible, so the excess arm is the
/// measurement that catches a window the pages were not read under at all.
fn check_declared_operational_members(
    declared: &OrsOperationalSnapshotIdentity,
    pages: &[OrsBackupPage],
) -> Result<(), OrsError> {
    let observed: u64 = pages
        .iter()
        .flat_map(|page| &page.entries)
        .filter(|entry| entry.family == RowFamilyKind::OperationalHistory)
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    if observed != declared.operational_row_count {
        return Err(OrsError::IntegrityProblem {
            record_type: "backup_operational_denominator",
            reason: format!(
                "declared operational window ({}, {}] counts {} row(s) but the pages carry {observed}",
                declared.lower_order_bound,
                declared.high_water_order,
                declared.operational_row_count
            ),
        });
    }
    Ok(())
}

/// Requires the members a `Complete` snapshot declares for one cursor-paged
/// family to be the members its pages actually carry.
///
/// The declared denominator is the frozen family's `family_row_count`, taken by
/// the owner from a streaming pass over that family's durable rows, and the
/// observed side is the count of this family's entries across every page. When
/// the two disagree, the snapshot is claiming a completeness it did not observe,
/// which is the A6 "missing row prevents complete" case: a family with rows the
/// pages did not carry can be certified `Complete` only by trusting a declared
/// number instead of the members, and the issue forbids exactly that
/// ("never complete from reference count alone").
///
/// Extra members are refused too, not only missing ones: an observed member the
/// frozen family never counted means the pages were not read under the declared
/// family at all, and `check_declared_family` already refuses that on the last
/// page's in-force identity. Refusing both directions here is what makes the
/// comparison exact rather than a one-sided lower bound.
fn check_declared_members(
    family: RowFamilyKind,
    declared: Option<&OrsFamilySnapshotIdentity>,
    pages: &[OrsBackupPage],
) -> Result<(), OrsError> {
    let Some(declared) = declared else {
        // `validate` already refuses `Complete` without both family
        // denominators, so this arm is unreachable for a `Complete` snapshot and
        // returns the same field-named refusal rather than a new one.
        return Err(OrsError::InvalidField {
            field: "backup_completeness",
            reason: "a complete snapshot must carry a family denominator to count members against",
        });
    };
    let observed: u64 = pages
        .iter()
        .flat_map(|page| &page.entries)
        .filter(|entry| entry.family == family)
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    if observed != declared.family_row_count {
        return Err(OrsError::IntegrityProblem {
            record_type: "backup_member_denominator",
            reason: format!(
                "declared row family {family:?} denominator counts {} member(s) but the pages carry {observed}",
                declared.family_row_count
            ),
        });
    }
    Ok(())
}
/// Destination identity for a backup import.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OrsBackupDestination {
    pub installation_id: String,
    /// Admission receipt authorising the import.
    pub admission_receipt: String,
    /// Whether canonical evidence is bound (checked at import, not here).
    pub evidence_bound: bool,
}
impl OrsBackupDestination {
    /// Validate identifier shapes; evidence binding is checked at import.
    pub fn new(
        installation_id: String,
        admission_receipt: String,
        evidence_bound: bool,
    ) -> Result<Self, OrsError> {
        require_installation_id(&installation_id, "destination_installation_id")?;
        if admission_receipt.is_empty() || admission_receipt.len() > MAX_BACKUP_ID_LEN {
            return Err(OrsError::InvalidField {
                field: "backup_admission_receipt",
                reason: "admission receipt must be non-empty and bounded",
            });
        }
        Ok(Self {
            installation_id,
            admission_receipt,
            evidence_bound,
        })
    }
}
/// Explicit import input: the only struct here that accepts deserialization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OrsBackupImportRequest {
    /// Denominator digest of the snapshot under import.
    pub snapshot_digest: String,
    pub source: OrsBackupSourceIdentity,
    pub destination: OrsBackupDestination,
}
/// Per-entry import outcome; unknown stays reconciling, never retried blindly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PerEntryOutcome {
    /// Entry imported.
    Imported,
    /// Entry rejected with a stated reason.
    Rejected {
        /// Why the entry was rejected.
        reason: String,
    },
    /// Entry retained for forensics only.
    Forensic {
        /// Why the entry is forensic-only.
        reason: String,
    },
    /// Entry blocked (fence/authority) with a stated reason.
    Blocked {
        /// Why the entry was blocked.
        reason: String,
    },
    /// Entry unresolved; remains reconciling (I14-21).
    Unresolved {
        /// Why the entry is unresolved.
        reason: String,
    },
}
/// What one current owner was asked about a backup import's members, and what it
/// answered (issue #953, A17).
///
/// This is a RECORD of one consultation, not a claim: nothing here is trusted
/// because it is well formed, and nothing here is recomputed by
/// [`OrsBackupImportReceipt::known_zero_unresolved`]. The record exists so the
/// two halves of the guarantee are separately checkable — that the current owner
/// was asked (which members, which live families, at which instant) and what it
/// answered (whether it still holds any of them unresolved).
///
/// The current owner of ORS recovery effects is the ORS store itself, observed
/// through its own live durable rows. The producer is the store: it opens
/// [`RowFamilyKind::RecoveryInbox`] and [`RowFamilyKind::RecoveryProblems`]
/// inside the read transaction the import already holds, and decides per member
/// whether the current owner still holds it unresolved. A caller that never read
/// that live state has no validation to present, which is why
/// [`Self::consulted_families`] is part of the record and part of the gate.
///
/// [`Self::validated_record_ids`] stores the identifiers rather than only a
/// count, so COMPLETENESS is a comparison against the receipt's own member set
/// and not a number the validation declared about itself. A validation that
/// covered fewer members, more members, or different members than the receipt
/// carries is refused, which is the property a count could never express.
///
/// Since the issue #953 import-denominator repair the roster is NOT built from the
/// import outcome vector any more. It is built from the SNAPSHOT's own declared
/// member identities, established by the store before a single outcome is read,
/// and reaches this record as a parameter. The previous derivation cloned, sorted
/// and de-duplicated the very `per_entry` vector the record was supposed to police,
/// so the completeness comparison in [`OrsBackupImportReceipt::known_zero_unresolved`]
/// set-compared two projections of one caller-supplied list and could not observe a
/// missing import member at all. The record now states which members the owner was
/// asked about because an INDEPENDENT roster said they existed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CurrentOwnerValidation {
    /// Snapshot denominator digest this validation covers.
    ///
    /// Bound to the operation, not merely well formed: a validation of a
    /// different snapshot answers a different question, so the gate refuses a
    /// validation whose digest is not this receipt's.
    pub snapshot_digest: String,
    /// The COMPLETE set of record ids the current owner was asked about, taken
    /// from the snapshot's declared member roster.
    pub validated_record_ids: Vec<String>,
    /// Identities the current owner still holds unresolved.
    pub unresolved_effect_identities: Vec<String>,
    /// The live row families actually read to reach that answer.
    pub consulted_families: Vec<RowFamilyKind>,
    /// When the current owner was consulted, in Unix milliseconds.
    pub validated_at_ms: i64,
}
impl CurrentOwnerValidation {
    /// Shape-checks every field of the record.
    ///
    /// Reuses this module's existing validators and rules; it adds none of its
    /// own. [`require_digest`] covers the snapshot binding,
    /// [`require_installation_id`] is this module's single bounded-identifier
    /// shape check and covers each member and each still-unresolved identity,
    /// and the positive-stamp half of the module's existing
    /// `expires_at_ms > created_at_ms` rule (`OrsBackupPage::validate_binding`)
    /// covers the consultation instant. A family roster additionally may not be
    /// empty and may not repeat a family, because a roster that padded itself
    /// with a repeat would satisfy the gate's "both families were consulted"
    /// test without having read both.
    ///
    /// Shape is necessary and not sufficient: every obligation
    /// [`OrsBackupImportReceipt::known_zero_unresolved`] adds on top is a
    /// relation to the receipt, and none of them is implied here.
    pub fn validate(&self) -> Result<(), OrsError> {
        require_digest(&self.snapshot_digest, "backup_owner_validation_digest")?;
        if self.consulted_families.is_empty() {
            return Err(OrsError::InvalidField {
                field: "backup_owner_consulted_families",
                reason: "a current owner validation must name the live families it read",
            });
        }
        let mut families: BTreeSet<RowFamilyKind> = BTreeSet::new();
        for family in &self.consulted_families {
            if !families.insert(*family) {
                return Err(OrsError::InvalidField {
                    field: "backup_owner_consulted_families",
                    reason: "a current owner validation must not list one consulted family twice",
                });
            }
        }
        // The complete asked-about roster. Each identifier takes the module's
        // existing bounded-identifier check, and a repeat is refused: a roster
        // that asked the same member twice is not a roster, and comparing it as
        // a SET against the receipt's members would let a repeated ask stand in
        // for a member that was never asked about.
        let mut asked: BTreeSet<&str> = BTreeSet::new();
        for record_id in &self.validated_record_ids {
            require_installation_id(record_id, "backup_owner_validated_record_id")?;
            if !asked.insert(record_id.as_str()) {
                return Err(OrsError::InvalidField {
                    field: "backup_owner_validated_record_id",
                    reason: "a current owner validation must ask about each record id at most once",
                });
            }
        }
        for identity in &self.unresolved_effect_identities {
            require_installation_id(identity, "backup_owner_unresolved_effect_identity")?;
        }
        if self.validated_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "backup_owner_validated_at_ms",
                reason: "current owner validation must carry a positive unix millisecond stamp",
            });
        }
        Ok(())
    }
}
/// Typed verdict of the known-zero-unresolved gate for one import receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KnownZeroVerdict {
    /// A complete current-owner validation covered every member of this receipt
    /// and the current owner holds none of them unresolved.
    Satisfied,
    /// The gate refused; `reason` states which obligation was unmet.
    ///
    /// A reason STRING is a report, never the decision: the decision is this
    /// enum's variant, and [`OrsBackupImportReceipt::known_zero_unresolved`]
    /// re-derives it from the recorded validation rather than reading this
    /// field, so a stale or wrong record cannot become a satisfied gate.
    Refused {
        /// Why the gate refused.
        reason: String,
    },
}
/// Import receipt with explicit per-entry outcomes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsBackupImportReceipt {
    /// Snapshot denominator digest this receipt binds.
    pub snapshot_digest: String,
    pub source_installation: String,
    pub destination_installation: String,
    /// The snapshot's OWN member roster, established independently of every
    /// outcome below (issue #953 import-denominator repair).
    ///
    /// This is the expected set the completeness comparison is made against, and
    /// it is recorded on the receipt rather than recomputed from `per_entry` for
    /// exactly the reason the previous projection could not fire: a roster cloned
    /// out of the outcome vector always agrees with the outcome vector, so an
    /// import member that was never covered was invisible. The member identity is
    /// the pair `(row family, record id)`, because the snapshot's record ids are
    /// family-scoped and two families may legitimately carry the same id.
    pub expected_members: Vec<(RowFamilyKind, String)>,
    /// Per-entry outcomes keyed by record id.
    pub per_entry: Vec<(String, PerEntryOutcome)>,
    pub unresolved_count: u64,
    pub import_at_ms: i64,
    /// The live current-owner validation this receipt's members were checked
    /// against (issue #953, A17).
    ///
    /// Recorded, not recomputed: it is what makes the gate observable on the
    /// receipt, and it is what a replayed receipt re-evaluates from instead of
    /// carrying a verdict forward.
    pub current_owner_validation: CurrentOwnerValidation,
    /// Typed verdict of [`Self::known_zero_unresolved`] for
    /// [`Self::current_owner_validation`].
    pub known_zero_verdict: KnownZeroVerdict,
}
impl OrsBackupImportReceipt {
    /// Validate and bind an import receipt.
    ///
    /// The known-zero verdict is COMPUTED here, by invoking
    /// [`Self::known_zero_unresolved`] against the supplied validation. It is
    /// not a parameter, and that is deliberate on both sides: a verdict a caller
    /// asserted would be a claim with nothing behind it, and a verdict left to a
    /// later step would mean a receipt exists whose recorded gate was never run.
    /// A gate refusal is a verdict, not a construction failure, so it is
    /// recorded on the receipt and does not fail `new` — the caller reads the
    /// verdict and the standalone gate.
    ///
    /// `expected_members` replaces the `unresolved_count` parameter of the
    /// previous signature. `unresolved_count` is now DERIVED here, in this one
    /// place, from the validated `per_entry` vector: it used to be an independent
    /// caller-supplied number, so a receipt could declare `0` beside a vector
    /// full of [`PerEntryOutcome::Unresolved`] and the gate's last conjunct was
    /// the only thing standing between the two facts and a false zero. The
    /// denominator is now supplied instead of the count, because a completeness
    /// check needs an independent EXPECTED set to compare against and a count can
    /// never be one.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_digest: String,
        source_installation: String,
        destination_installation: String,
        expected_members: Vec<(RowFamilyKind, String)>,
        per_entry: Vec<(String, PerEntryOutcome)>,
        import_at_ms: i64,
        current_owner_validation: CurrentOwnerValidation,
    ) -> Result<Self, OrsError> {
        require_digest(&snapshot_digest, "backup_snapshot_digest")?;
        require_installation_id(&source_installation, "source_installation_id")?;
        require_installation_id(&destination_installation, "destination_installation_id")?;
        // ONE derivation of the unresolved count, from the outcomes themselves.
        let unresolved_count = per_entry
            .iter()
            .filter(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. }))
            .count();
        let unresolved_count =
            u64::try_from(unresolved_count).map_err(|_| OrsError::ProjectionLimitExceeded)?;
        let mut receipt = Self {
            snapshot_digest,
            source_installation,
            destination_installation,
            expected_members,
            per_entry,
            unresolved_count,
            import_at_ms,
            current_owner_validation,
            known_zero_verdict: KnownZeroVerdict::Refused {
                reason: "the known-zero gate has not been evaluated for this receipt".to_owned(),
            },
        };
        // ONE evaluation, and the recorded verdict is its result. Assigning from
        // the gate's own answer (rather than hard-coding either arm) is what
        // keeps the receipt and the gate the same judgement.
        receipt.known_zero_verdict =
            match receipt.known_zero_unresolved(&receipt.current_owner_validation) {
                Ok(()) => KnownZeroVerdict::Satisfied,
                Err(error) => KnownZeroVerdict::Refused {
                    reason: error.to_string(),
                },
            };
        Ok(receipt)
    }
    /// The known-zero gate: succeeds only when this receipt's members are
    /// completely covered by a current-owner validation that found nothing
    /// unresolved (issue #953, A17).
    ///
    /// A zero `unresolved_count` says only that no imported member came back
    /// `Unresolved`. It says nothing about whether the CURRENT owner still holds
    /// an effect for any of them, because a brand-new empty destination has no
    /// row to collide with and therefore triages every entry as a fresh
    /// quarantined candidate. Trusting that zero is exactly the claim this gate
    /// now refuses to make on its own, so it takes the current owner's answer as
    /// an input and refuses unless ALL of the following hold:
    ///
    /// 1. the validation's own recorded shape passes
    ///    ([`CurrentOwnerValidation::validate`]), checked on the ORIGINAL
    ///    recorded value and never recomputed from live state;
    /// 2. `owner.snapshot_digest == self.snapshot_digest` — bound to THIS
    ///    operation, so a well-formed validation of a different snapshot cannot
    ///    vouch for this one;
    /// 3. FULL COVERAGE of the snapshot's own member roster. This is the
    ///    prerequisite of `Satisfied`, and it is a comparison against an
    ///    INDEPENDENT expected set: the receipt's [`Self::expected_members`],
    ///    which the store established from the validated snapshot before it read
    ///    a single outcome. Three sets must agree —
    ///    [`Self::expected_members`] (what the snapshot declares),
    ///    `self.per_entry` (what the caller actually triaged) and
    ///    `owner.validated_record_ids` (what the current owner was asked about) —
    ///    and every one of them must be a roster, with a duplicate outcome
    ///    refused rather than collapsed. Fewer members, more members, different
    ///    members or a repeated outcome are all refused; a count equality could
    ///    not distinguish any of them, and neither could a comparison of two
    ///    projections of the caller's own outcome vector, which is what this
    ///    check used to be;
    /// 4. `owner.unresolved_effect_identities` is empty — the current owner
    ///    still holds nothing unresolved for what it was asked about;
    /// 5. `owner.consulted_families` contains BOTH
    ///    [`RowFamilyKind::RecoveryInbox`] and
    ///    [`RowFamilyKind::RecoveryProblems`] — a validation that did not read
    ///    the current owner's live recovery state proves nothing about it;
    /// 6. `unresolved_count == 0` and no `per_entry` outcome is
    ///    [`PerEntryOutcome::Unresolved`]. `unresolved_count` is no longer an
    ///    independently supplied number: it is derived from `per_entry` inside
    ///    [`Self::new`], so it is a restatement of the facts rather than a
    ///    second claim about them.
    ///
    /// Every refusal is a TYPED variant, not one blanket error: a DUPLICATE
    /// outcome or a doubled member is [`OrsError::DuplicateConflict`] (one durable
    /// identity claimed twice — the caller triaged one member twice, and its
    /// operator action is to re-run the triage), and every other unmet obligation is
    /// [`OrsError::ReconciliationMismatch`] — I14-21: unknown stays reconciling, and
    /// a zero that nobody validated is unknown, not resolved. Nothing here retries,
    /// replays or repairs; it refuses.
    pub fn known_zero_unresolved(&self, owner: &CurrentOwnerValidation) -> Result<(), OrsError> {
        owner.validate()?;
        if owner.snapshot_digest != self.snapshot_digest {
            return Err(OrsError::ReconciliationMismatch);
        }
        // The coverage check REPORTS its own refusal: it returns the typed variant
        // for the failure it found, so a duplicate outcome stays distinguishable
        // from a member nobody triaged instead of both collapsing into one
        // undifferentiated mismatch.
        self.owner_validation_is_complete(owner)?;
        if !owner.unresolved_effect_identities.is_empty() {
            return Err(OrsError::ReconciliationMismatch);
        }
        if !owner
            .consulted_families
            .contains(&RowFamilyKind::RecoveryInbox)
            || !owner
                .consulted_families
                .contains(&RowFamilyKind::RecoveryProblems)
        {
            return Err(OrsError::ReconciliationMismatch);
        }
        let any_unresolved = self
            .per_entry
            .iter()
            .any(|(_, outcome)| matches!(outcome, PerEntryOutcome::Unresolved { .. }));
        if self.unresolved_count == 0 && !any_unresolved {
            Ok(())
        } else {
            Err(OrsError::ReconciliationMismatch)
        }
    }
    /// Requires FULL COVERAGE of the snapshot's own member roster by the
    /// provided outcomes and by the roster the current owner was consulted about.
    ///
    /// This is the owner's rule-10(d) check, and its whole content is that the
    /// expected set is INDEPENDENT of the thing being checked.
    /// [`Self::expected_members`] is the member roster the validated snapshot
    /// declares; `self.per_entry` is what the caller actually triaged; and
    /// `owner.validated_record_ids` is what the current owner was asked about.
    /// The previous implementation compared the last two only, and both were
    /// projections of the SAME caller-supplied `per_entry` vector, so a missing
    /// import member, a subset, a foreign outcome and a duplicated outcome all
    /// compared equal and the gate could never fire.
    ///
    /// Five distinct failures, none reachable from another, each of which the
    /// import is refused for, and each of which is now REPORTED rather than
    /// collapsed:
    ///
    /// 1. the expected roster repeats a member identity — it is not a roster;
    /// 2. two DIFFERENT expected members share one record id. The outcome
    ///    vocabulary is record-id keyed, so one id under two families cannot be
    ///    covered by two outcomes and is refused rather than half-covered;
    /// 3. the provided outcomes repeat a record id — a duplicate outcome is
    ///    contradictory evidence, not a second member, and is refused rather
    ///    than de-duplicated into apparent success;
    /// 4. the provided outcomes and the expected roster differ in either
    ///    direction: a subset leaves a member nobody triaged, a foreign or
    ///    superset answers a question this receipt is not;
    /// 5. the consulted roster and the expected roster differ in either
    ///    direction, so the current owner was never asked about some member, or
    ///    was asked about one this receipt does not carry.
    ///
    /// Sets rather than lengths, because a length cannot tell a subset from a
    /// superset from a different set of the same size.
    ///
    /// WHY THIS RETURNS `Result` RATHER THAN `bool` (issue #953): while this was
    /// one predicate every failure above collapsed into the same `false`, and
    /// [`Self::known_zero_unresolved`] mapped that single `false` to one
    /// [`OrsError::ReconciliationMismatch`]. A caller triaging the same record id
    /// twice — which the audit names as its own discriminator, because two
    /// contradictory outcomes for one member is a caller bug with an operator
    /// action, not an unknown effect — was therefore indistinguishable at the error
    /// site from a member nobody triaged at all. The rejection was real but it was
    /// not ADDRESSABLE. Each failure now names itself; a DUPLICATE reports
    /// [`OrsError::DuplicateConflict`], the crate's existing typed refusal for one
    /// durable identity claimed twice and the same variant [`member_roster_refused`]
    /// already returns for a repeated member of a page roster, while the coverage
    /// failures keep [`OrsError::ReconciliationMismatch`] (I14-21: unknown stays
    /// reconciling). Failures 1–3 are [`check_outcome_identities`]'s, which the store
    /// also runs BEFORE it builds a validation, so a duplicate is refused as a typed
    /// `Err` at the boundary instead of only as a verdict string on a receipt;
    /// failure 4 is [`expected_member_ids`]'s and stays a verdict, so the per-member
    /// outcome vector survives for the caller to route.
    /// The REACHABILITY of [`KnownZeroVerdict::Satisfied`] is unchanged: a full
    /// checked roster with exact per-member outcomes still returns `Ok(())`.
    fn owner_validation_is_complete(&self, owner: &CurrentOwnerValidation) -> Result<(), OrsError> {
        // The expected/provided half of the coverage rule: repeats are refused by
        // `check_outcome_identities`, and this adds the set equality in both
        // directions, judged against the halves RECORDED on the receipt.
        let expected_ids = expected_member_ids(&self.expected_members, &self.per_entry)?;
        // Failure 5: the consulted roster must equal the expected roster, so the
        // current owner was asked about every member and about nothing else.
        let mut consulted: BTreeSet<&str> = BTreeSet::new();
        for record_id in &owner.validated_record_ids {
            if !consulted.insert(record_id.as_str()) {
                return Err(OrsError::DuplicateConflict);
            }
        }
        let covered = consulted.len() == expected_ids.len()
            && expected_ids
                .iter()
                .all(|record_id| consulted.contains(record_id.as_str()));
        if !covered {
            return Err(OrsError::ReconciliationMismatch);
        }
        Ok(())
    }
}

/// Requires that no identity in the expected roster or the outcome vector is
/// claimed TWICE (issue #953; external audit 5868369939, step 2).
///
/// This is the boundary half of the coverage rule, and it is deliberately
/// IDENTITY-ONLY: it refuses a repeat, and nothing else. A missing or extra member
/// is NOT refused here — that refusal is
/// [`KnownZeroVerdict::Refused`] on a receipt the caller can read, and failing it
/// here would destroy the per-member outcome vector that says WHICH members went
/// untriaged, which is the artifact the caller needs to route reconciliation. So the
/// two halves refuse different things at different places: a contradiction in the
/// input is a typed `Err` at the boundary, while an incomplete coverage report is a
/// verdict on the receipt.
///
/// Three typed refusals:
///
/// - the expected roster repeats one member identity — [`OrsError::DuplicateConflict`];
/// - one record id appears under two row families — [`OrsError::ReconciliationMismatch`],
///   because the identity was declared once per family while the outcome vocabulary is
///   record-id keyed, so it cannot be covered by two outcomes and is half-covered by
///   one;
/// - the outcomes repeat one record id — [`OrsError::DuplicateConflict`], the audit's
///   named case: two outcomes for one member are contradictory evidence about a single
///   member, never a second member, and de-duplicating them into apparent success is
///   the defect.
///
/// Pure and total: it reads no table and writes none, so it can run before any
/// observation is made.
pub fn check_outcome_identities(
    expected_members: &[(RowFamilyKind, String)],
    per_entry: &[(String, PerEntryOutcome)],
) -> Result<(), OrsError> {
    let mut expected: BTreeSet<(RowFamilyKind, &str)> = BTreeSet::new();
    for (family, record_id) in expected_members {
        if !expected.insert((*family, record_id.as_str())) {
            return Err(OrsError::DuplicateConflict);
        }
    }
    let expected_ids: BTreeSet<&str> = expected.iter().map(|(_, record_id)| *record_id).collect();
    if expected_ids.len() != expected.len() {
        return Err(OrsError::ReconciliationMismatch);
    }
    let mut provided: BTreeSet<&str> = BTreeSet::new();
    for (record_id, _) in per_entry {
        if !provided.insert(record_id.as_str()) {
            return Err(OrsError::DuplicateConflict);
        }
    }
    Ok(())
}

/// Requires the provided outcomes to cover the expected roster EXACTLY, once each
/// (issue #953; external audit 5868369939, step 2).
///
/// The coverage half, run by [`OrsBackupImportReceipt::new`]'s gate against the
/// values RECORDED on the receipt — so it also judges a hand-assembled or replayed
/// receipt that claims coverage it does not have, which the boundary
/// [`check_outcome_identities`] cannot see. Its repeats are already
/// [`check_outcome_identities`]'s job; what it adds is the set equality in both
/// directions: a subset leaves a member nobody triaged and a superset answers a
/// question this receipt is not. Returns the expected record-id SET (owned, so it
/// outlives both borrowed inputs) so the caller compares the consulted roster
/// against the same set rather than rebuilding it.
fn expected_member_ids(
    expected_members: &[(RowFamilyKind, String)],
    per_entry: &[(String, PerEntryOutcome)],
) -> Result<BTreeSet<String>, OrsError> {
    check_outcome_identities(expected_members, per_entry)?;
    let expected_ids: BTreeSet<String> = expected_members
        .iter()
        .map(|(_, record_id)| record_id.clone())
        .collect();
    let provided: BTreeSet<&str> = per_entry
        .iter()
        .map(|(record_id, _)| record_id.as_str())
        .collect();
    let covered = provided.len() == expected_ids.len()
        && expected_ids
            .iter()
            .all(|record_id| provided.contains(record_id.as_str()));
    if !covered {
        return Err(OrsError::ReconciliationMismatch);
    }
    Ok(expected_ids)
}
/// Reject imports that relabel identity or arrive without bound evidence.
pub fn validate_import_binding(
    source: &OrsBackupSourceIdentity,
    dest: &OrsBackupDestination,
) -> Result<(), OrsError> {
    if source.installation_id == dest.installation_id {
        return Err(OrsError::InvalidField {
            field: "source_installation_id",
            reason: "source and destination installations must differ",
        });
    }
    if dest.admission_receipt.is_empty() {
        return Err(OrsError::CanonicalEvidence(
            "backup import lacks an admission receipt".to_owned(),
        ));
    }
    if !dest.evidence_bound {
        return Err(OrsError::CanonicalEvidence(
            "backup import lacks bound canonical evidence".to_owned(),
        ));
    }
    Ok(())
}
/// Freeze check: any canonical head advance across import is rejected.
pub fn check_canonical_frozen(pre: &str, post: &str) -> Result<(), OrsError> {
    require_digest(pre, "backup_canonical_pre")?;
    require_digest(post, "backup_canonical_post")?;
    if pre == post {
        Ok(())
    } else {
        Err(OrsError::OrderingHeadMismatch)
    }
}
