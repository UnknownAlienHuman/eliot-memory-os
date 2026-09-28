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
//! via [`OrsBackupImportReceipt::known_zero_unresolved`]. No blind retry.
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
//! Storage-free: no `redb`, no filesystem, no `eliot-backup` dependency.
//! Distinct from `snapshot_model`; every new name starts `OrsBackup`/`Backup`.

use std::collections::BTreeMap;
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
pub const BACKUP_SNAPSHOT_SCHEMA_VERSION: u16 = 4;
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
            | Self::ScanDisclosure => RowDisposition::NonrestorableHistorical,
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
    /// Exclusive lower order bound for pagination.
    pub after_order: u64,
    /// Entries per page, `1..=MAX_BACKUP_PAGE_ENTRIES`.
    pub page_entries: u16,
    /// Declared byte budget, `1..=MAX_BACKUP_BYTES`.
    pub max_bytes: u64,
    /// Page budget, `1..=MAX_BACKUP_PAGES`.
    pub max_pages: u16,
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
            process_stream_recovery_cursor: None,
            versioned_artifact_cursor: None,
        })
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
    /// The family cursor is deliberately not folded in: a family continuation
    /// advances by exactly one owner-issued cursor per family page, so the
    /// operational fence token has to stay stable across a whole snapshot
    /// while the family token moves. The family snapshot identity reaches the
    /// page token through [`OrsFamilyCursor::fence_token`] instead.
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
/// Per-page family continuation state (issue #2884).
///
/// `cursor` is the family cursor the page was read under, so a page always
/// states which frozen family snapshot and which emitted prefix produced it.
/// `next` is the exact cursor for the next family page and is `None` only when
/// this page carried the family's final segment. Operational-history paging and
/// family paging therefore never share a cursor: the operational window stays
/// `page_index * page_entries` and the family keeps its own durable-key bound.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsFamilyContinuation {
    /// Cursor in force for this page.
    pub cursor: OrsFamilyCursor,
    /// Exact next family cursor; `None` when the family is exhausted here.
    pub next: Option<OrsFamilyCursor>,
}
impl OrsFamilyContinuation {
    /// Reports whether the family still has rows behind `next`.
    #[must_use]
    pub fn family_open(&self) -> bool {
        self.next.is_some()
    }
    /// Validate the in-force cursor and the next cursor.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.cursor.validate()?;
        match &self.next {
            Some(next) => {
                next.validate()?;
                if next.identity != self.cursor.identity {
                    return Err(OrsError::InvalidField {
                        field: "backup_family_continuation",
                        reason: "next family cursor left the frozen family snapshot",
                    });
                }
                if next.emitted_rows < self.cursor.emitted_rows {
                    return Err(OrsError::InvalidField {
                        field: "backup_family_continuation",
                        reason: "family continuation must not reset its emitted prefix",
                    });
                }
                Ok(())
            }
            None => Ok(()),
        }
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
    /// Unambiguous by construction (issue #2884, extended by #1971): it is the
    /// conjunction of the operational window being exhausted and EVERY paged
    /// family having no continuation left. A page that still owes rows to
    /// either the process-stream recovery family or the versioned-artifact family
    /// is never `is_last` even when its operational segment ended, so page
    /// continuity can never hide an unemitted family tail behind a final page.
    pub is_last: bool,
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
    /// capture window, the entry count, the process-stream recovery family
    /// continuation in force and its exact next cursor, then the SAME four family
    /// facts for the versioned-artifact family (issue #1971), then one 64-hex
    /// digest per entry. Both family segments are folded in a FIXED order with a
    /// literal label in front of each, so a page that carried only the
    /// versioned-artifact family cannot produce the same material as a page that
    /// carried only the process-stream recovery family. Every contribution is
    /// either a fixed-width digest or a delimiter-separated decimal/bool field, so
    /// the concatenation is length-delimited by construction and an embedded
    /// separator inside a `record_id` cannot make two different pages produce the
    /// same material.
    ///
    /// Since issue #953 each entry's material also folds the entry's
    /// [`RowPayloadState`], so the page digest moves when a member's payload
    /// availability moves and an unavailable member can never be laundered into
    /// an available one behind an unchanged digest. The `v2`→`v3` label change
    /// is that addition; it is a wire constant, not durable schema, and the
    /// pre-existing [`OrsError::MigrationRequired`] refusal is the migration
    /// story.
    #[must_use]
    pub fn expected_page_digest(&self) -> String {
        let mut material = format!(
            "eliot.ors.backup_page.v3|{}|{}|{}|{}|{}|{}|",
            self.fence_token,
            self.page_index,
            self.is_last,
            self.created_at_ms,
            self.expires_at_ms,
            self.entries.len()
        );
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
                    "eliot.ors.backup_entry.v3|{}|{:?}|{}|{}|{:?}|{:?}",
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
        match &continuation.next {
            Some(next) => material.push_str(&next.fence_token()),
            None => material.push_str("no-next"),
        }
    } else {
        material.push_str("no-family");
    }
    material.push(':');
}
/// Completeness of a backup snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupCompleteness {
    /// Every bound page present.
    Complete,
    /// Truncated but usable with a stated reason.
    Partial {
        /// Why the snapshot is partial.
        reason: String,
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
            if self.process_stream_recovery_family.is_none() {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "a complete snapshot must carry a process-stream recovery family denominator",
                });
            }
            if self.versioned_artifact_family.is_none() {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "a complete snapshot must carry a versioned-artifact family denominator",
                });
            }
            if self.next_process_stream_recovery_cursor.is_some()
                || self.next_versioned_artifact_cursor.is_some()
            {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "a complete snapshot must have no outstanding family continuation",
                });
            }
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
            self.process_stream_recovery_family.as_ref(),
            self.versioned_artifact_family.as_ref(),
        )
    }
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
        && continuation.next.as_ref() != declared_next
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
    // A final page must leave NO paged family open. Both continuations are
    // checked because `is_last` is the conjunction over both of them, so a
    // producer that computed finality from only one family would be caught here
    // (issue #1971).
    let family_open = page
        .family_continuation
        .as_ref()
        .is_some_and(OrsFamilyContinuation::family_open)
        || page
            .versioned_artifact_continuation
            .as_ref()
            .is_some_and(OrsFamilyContinuation::family_open);
    if page.is_last && family_open {
        return Err(OrsError::InvalidField {
            field: "backup_page_is_last",
            reason: "a final page must not leave an open family continuation",
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
        BackupCompleteness::Partial { reason } | BackupCompleteness::Incomplete { reason } => {
            if reason.is_empty() {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "partial snapshots must state a reason",
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
#[derive(Clone, Copy)]
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
fn check_observed_members(pages: &[OrsBackupPage]) -> Result<(), OrsError> {
    let mut roster: BTreeMap<(RowFamilyKind, &str), ObservedMember> = BTreeMap::new();
    for page in pages {
        for entry in &page.entries {
            let key = (entry.family, entry.record_id.as_str());
            let observed = ObservedMember {
                order: entry.order,
                effect_class: entry.effect_class,
                payload_state: entry.payload_state,
                has_payload_digest: !entry.payload_digest.is_empty(),
            };
            match roster.get(&key) {
                None => {
                    roster.insert(key, observed);
                }
                Some(first) => {
                    if first.order == observed.order
                        && first.effect_class == observed.effect_class
                        && first.payload_state == observed.payload_state
                        && first.has_payload_digest == observed.has_payload_digest
                    {
                        return Err(member_roster_refused(MemberRoster::Duplicate, entry));
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
/// Import receipt with explicit per-entry outcomes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsBackupImportReceipt {
    /// Snapshot denominator digest this receipt binds.
    pub snapshot_digest: String,
    pub source_installation: String,
    pub destination_installation: String,
    /// Per-entry outcomes keyed by record id.
    pub per_entry: Vec<(String, PerEntryOutcome)>,
    pub unresolved_count: u64,
    pub import_at_ms: i64,
}
impl OrsBackupImportReceipt {
    /// Validate and bind an import receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_digest: String,
        source_installation: String,
        destination_installation: String,
        per_entry: Vec<(String, PerEntryOutcome)>,
        unresolved_count: u64,
        import_at_ms: i64,
    ) -> Result<Self, OrsError> {
        require_digest(&snapshot_digest, "backup_snapshot_digest")?;
        require_installation_id(&source_installation, "source_installation_id")?;
        require_installation_id(&destination_installation, "destination_installation_id")?;
        Ok(Self {
            snapshot_digest,
            source_installation,
            destination_installation,
            per_entry,
            unresolved_count,
            import_at_ms,
        })
    }
    /// Explicit gate: succeeds only when no entry remains unresolved.
    pub fn known_zero_unresolved(&self) -> Result<(), OrsError> {
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
