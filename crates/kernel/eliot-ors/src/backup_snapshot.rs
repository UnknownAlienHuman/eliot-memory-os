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
            | Self::ActivationResultRetention
            | Self::NativeWorkerClaims
            | Self::CutoverOwnership => RowDisposition::NonrestorableHistorical,
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
        })
    }
    /// Deterministic binding token for source, fence, and page cursor.
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
/// One page of a backup snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsBackupPage {
    /// Zero-based page index; pages must be continuous.
    pub page_index: u32,
    pub entries: Vec<OrsBackupEntry>,
    /// Digest binding this page.
    pub page_digest: String,
    /// True only on the final page.
    pub is_last: bool,
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
}
impl OrsBackupSnapshot {
    /// Recompute the denominator digest over source, fence, and page digests.
    pub fn snapshot_digest(&self) -> String {
        let mut material = format!(
            "{}:{}:{}:{}:",
            self.source.installation_id,
            self.source.ors_generation,
            self.fence.fence_digest,
            self.fence.high_water_order
        );
        for page in &self.pages {
            material.push_str(&page.page_digest);
            material.push(':');
            for entry in &page.entries {
                material.push_str(&entry.payload_digest);
                material.push(':');
            }
        }
        sha256_hex(material.as_bytes())
    }
    /// Validate digest shapes, page continuity, denominator, and completeness.
    pub fn validate(&self) -> Result<(), OrsError> {
        require_digest(&self.fence.fence_digest, "backup_fence_digest")?;
        require_digest(&self.denominator_digest, "backup_denominator_digest")?;
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
/// Validate one page's index continuity, digest, and entry bound.
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
