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
//! Storage-free: no `redb`, no filesystem, no `eliot-backup` dependency.
//! Distinct from `snapshot_model`; every new name starts `OrsBackup`/`Backup`.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::OrsError;

/// Schema version of the backup-snapshot wire shape.
pub const BACKUP_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
/// Hard ceiling for entries in one backup page (mirrors `MAX_RECOVERY_PAGE`).
pub const MAX_BACKUP_PAGE_ENTRIES: u16 = 256;
/// Hard ceiling for pages in one backup snapshot.
pub const MAX_BACKUP_PAGES: u16 = 256;
/// Hard ceiling for the declared byte budget of one backup request.
pub const MAX_BACKUP_BYTES: u64 = 16 * 1024 * 1024;
/// Hard ceiling for installation/admission identifier length.
pub const MAX_BACKUP_ID_LEN: usize = 256;
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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
            Self::StoreRebindReplay | Self::StoreFailureRetention => RowDisposition::ForensicOnly,
            Self::AuthorityHandoffs
            | Self::HostRequests
            | Self::ActivationLifecycle
            | Self::ActivationResultRetention
            | Self::NativeWorkerClaims
            | Self::CutoverOwnership => RowDisposition::NonrestorableHistorical,
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
    /// family's own durable-key order through [`OrsFamilyCursor`].
    pub const fn uses_family_cursor(self) -> bool {
        matches!(self, Self::ProcessStreamRecovery)
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
        })
    }
    /// Binds one typed family continuation to this request (issue #2884).
    ///
    /// The cursor comes from the store's family-snapshot opener, never from the
    /// caller: it names a frozen durable family revision and the durable-key
    /// prefix the owner already emitted. Attaching it here is what makes the
    /// family part of the exported denominator instead of an implicit
    /// side-effect of the final operational page.
    pub fn with_process_stream_recovery_cursor(
        mut self,
        cursor: OrsFamilyCursor,
    ) -> Result<Self, OrsError> {
        cursor.validate()?;
        self.process_stream_recovery_cursor = Some(cursor);
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
}
/// One backup entry: digests only, never raw payload (redaction).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsBackupEntry {
    pub record_id: String,
    pub family: RowFamilyKind,
    pub order: u64,
    /// Digest of the opaque payload held by the store.
    pub payload_digest: String,
    pub effect_class: StoredEffectClass,
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
    /// Digest binding this page.
    pub page_digest: String,
    /// True only on the final page.
    ///
    /// Unambiguous by construction (issue #2884): it is the conjunction of the
    /// operational window being exhausted and the paged family having no
    /// continuation left. A page that still owes family rows is never `is_last`
    /// even when its operational segment ended, so page continuity can never
    /// hide an unemitted family tail behind a final page.
    pub is_last: bool,
    /// Family continuation this page was read under, or `None` when the request
    /// declared no family continuation.
    pub family_continuation: Option<OrsFamilyContinuation>,
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
}
impl OrsBackupSnapshot {
    /// Recompute the denominator digest over source, fence, family and page
    /// digests.
    ///
    /// The frozen family snapshot identity, every page's family cursor and the
    /// outstanding next cursor are all folded in, so the denominator certifies
    /// the composite snapshot and not just one table's pages (issue #2884).
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
        for page in &self.pages {
            material.push_str(&page.page_digest);
            material.push(':');
            match &page.family_continuation {
                Some(continuation) => {
                    material.push_str(&continuation.cursor.fence_token());
                    if let Some(next) = &continuation.next {
                        material.push('|');
                        material.push_str(&next.fence_token());
                    }
                    material.push(':');
                }
                None => material.push_str("no-family:"),
            }
            for entry in &page.entries {
                material.push_str(&entry.payload_digest);
                material.push(':');
            }
        }
        sha256_hex(material.as_bytes())
    }
    /// Validate digest shapes, page continuity, denominator, and completeness.
    ///
    /// A `Complete` snapshot must carry a frozen process-stream recovery family
    /// identity and no outstanding continuation. That is the compatibility rule
    /// for snapshots produced before the family cursor existed: they declare no
    /// family denominator, so they stay `Partial` and can never be read as a
    /// proven complete family.
    pub fn validate(&self) -> Result<(), OrsError> {
        require_digest(&self.fence.fence_digest, "backup_fence_digest")?;
        require_digest(&self.denominator_digest, "backup_denominator_digest")?;
        if let Some(identity) = &self.process_stream_recovery_family {
            if !identity.family.uses_family_cursor() {
                return Err(OrsError::InvalidField {
                    field: "backup_process_stream_recovery_family",
                    reason: "family is not paged through a typed family cursor",
                });
            }
            require_digest(&identity.family_root_digest, "backup_family_root_digest")?;
        }
        if let Some(next) = &self.next_process_stream_recovery_cursor {
            next.validate()?;
        }
        // The declared family state must be the state the last page actually
        // reported, so a snapshot cannot claim an outstanding continuation the
        // pages do not carry, nor a finished family whose last page still owes
        // one.
        let last_continuation = self
            .pages
            .last()
            .and_then(|page| page.family_continuation.as_ref());
        if self.process_stream_recovery_family.is_some() && last_continuation.is_none() {
            return Err(OrsError::InvalidField {
                field: "backup_process_stream_recovery_family",
                reason: "a declared family denominator requires a family continuation on the last page",
            });
        }
        if let Some(continuation) = last_continuation
            && continuation.next != self.next_process_stream_recovery_cursor
        {
            return Err(OrsError::InvalidField {
                field: "backup_next_process_stream_recovery_cursor",
                reason: "declared family continuation does not match the last page",
            });
        }
        if matches!(self.completeness, BackupCompleteness::Complete) {
            if self.process_stream_recovery_family.is_none() {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "a complete snapshot must carry a process-stream recovery family denominator",
                });
            }
            if self.next_process_stream_recovery_cursor.is_some() {
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
        for (index, page) in self.pages.iter().enumerate() {
            check_page_shape(page, index)?;
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
        check_completeness(&self.completeness, counted, &self.pages)
    }
}
/// Validate one page's index continuity, digest, entry bound, and family
/// continuation.
fn check_page_shape(page: &OrsBackupPage, index: usize) -> Result<(), OrsError> {
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
    require_digest(&page.page_digest, "backup_page_digest")?;
    if page.entries.len() > usize::from(MAX_BACKUP_PAGE_ENTRIES) {
        return Err(OrsError::InvalidCursorLimit);
    }
    if let Some(continuation) = &page.family_continuation {
        continuation.validate()?;
        if page.is_last && continuation.family_open() {
            return Err(OrsError::InvalidField {
                field: "backup_page_is_last",
                reason: "a final page must not leave an open family continuation",
            });
        }
    }
    Ok(())
}
/// Enforce completeness rules: `Complete` needs entries and valid digests.
fn check_completeness(
    completeness: &BackupCompleteness,
    counted: u64,
    pages: &[OrsBackupPage],
) -> Result<(), OrsError> {
    match completeness {
        BackupCompleteness::Complete => {
            if counted == 0 {
                return Err(OrsError::InvalidField {
                    field: "backup_completeness",
                    reason: "complete snapshot must carry entries",
                });
            }
            for page in pages {
                require_digest(&page.page_digest, "backup_page_digest")?;
                for entry in &page.entries {
                    require_digest(&entry.payload_digest, "backup_payload_digest")?;
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
            Ok(())
        }
    }
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
