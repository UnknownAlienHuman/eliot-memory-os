//! Kernel-owned audit-fallback interface (issue #1840; I16.10, I16.11).
//!
//! This module closes the I16.11 cascade the #1837 chain left open: when the
//! normal audit write fails, the failed draft is retained in the
//! independently persisted audit spool, else the last-resort channel, else
//! the visible control-loss state. Stage order is exactly I16.11:
//!
//! ```text
//! normal audit write (`KernelAuditChain::append`);
//! if unavailable → audit spool record (stage 2, ORS/Watchdog-spool leg);
//! if unavailable → last-resort channel (stage 3: control slot, or the
//!   Windows Event Log in the `system_service` profile);
//! if all unavailable → visible control-loss state when next channel returns.
//! ```
//!
//! Reuse boundary, stated exactly. The cascade reuses the existing
//! observability-runtime machinery where it covers this path: the
//! [`CriticalPath`](eliot_observability_runtime::CriticalPath) control-loss
//! hold/replay machine with its monotone counters, the
//! [`EventLogReport`](eliot_observability_runtime::EventLogReport)
//! last-resort sink, the [`RuntimeProfile`](eliot_observability_runtime::config::RuntimeProfile)
//! profile rule, and the `SinkStatus`/`UnavailableReason` vocabulary. What
//! already exists is not duplicated: reconciliation appends through the one
//! [`KernelAuditChain::append`], anchors keep flowing through the one anchor
//! sink, and no second chain, second anchor scheme, or alternate transport
//! is introduced. The spool record store itself is new because the
//! operational [`CriticalEventRecord`](eliot_observability_runtime::CriticalEventRecord)
//! is by design never canonical audit proof (I16.1) and carries no draft,
//! sequence, hash, retry, or disposition fields; threading audit payloads
//! through it would cross the owner boundary I2.23 forbids.
//!
//! Lock order: the composition always locks `kernel_audit` before
//! `audit_fallback`, both here and at reconcile time. The fallback never
//! acquires another Kernel lock.
//!
//! Protection rule: spool files live in the profile-appropriate contour —
//! the installer `ProgramData` contour for `system_service`, the
//! current-user contour for `user_mode` and portable — and the contour
//! proof outcome is recorded in every spool record. A failed proof degrades
//! the record to `Unverified`, never to silence and never to a loosened
//! file: spool files are created with plain inheriting opens and no access
//! is ever widened. Refusal is the failure posture everywhere: a saturated
//! spool, an occupied last-resort slot, or an unparseable store refuses the
//! new write instead of overwriting retained evidence.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use eliot_contracts::canonical_json_bytes;
use eliot_observability_runtime::{
    CriticalEventRecord, CriticalEventSinks, CriticalEventState, CriticalPath, EventLogReport,
    RuntimeProfile,
};
use eliot_platform_windows::{ProtectedPathError, UserOwnedRootLease, prepare_protected_directory};
use serde::{Deserialize, Serialize};

use super::kernel_audit::{
    AuditAssuranceClass, AuditEventDraft, AuditEventKind, AuditLineage, AuditRecord,
    KernelAuditChain, KernelAuditError, blake3_hex, kernel_audit_dir,
};

/// Spool record/receipt/slot format version.
pub const AUDIT_SPOOL_FORMAT_VERSION: u16 = 1;
/// Spool directory name below the Kernel audit directory.
pub const AUDIT_SPOOL_DIR_NAME: &str = "audit-spool";
/// Independently persisted spool record file (one JSON line per record).
pub const AUDIT_SPOOL_FILE_NAME: &str = "spool-events.jsonl";
/// Append-only reconciliation receipt file (one JSON line per receipt).
pub const AUDIT_SPOOL_RECEIPT_FILE_NAME: &str = "spool-receipts.jsonl";
/// Last-resort control slot document for `user_mode`/portable profiles.
pub const AUDIT_SPOOL_SLOT_FILE_NAME: &str = "control-slot.json";
/// Staging suffix for atomic spool/slot rewrites.
const AUDIT_SPOOL_STAGING_SUFFIX: &str = ".staging";
/// Retained spool records ceiling; beyond it the spool stage refuses.
pub const AUDIT_SPOOL_MAX_RECORDS: usize = 4096;
/// Largest accepted single spool line, in bytes.
pub const AUDIT_SPOOL_MAX_LINE_BYTES: u64 = 64 * 1024;
/// Largest spool/receipt file read in one pass, in bytes.
const AUDIT_SPOOL_MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Largest accepted control-slot document, in bytes.
const AUDIT_SPOOL_SLOT_MAX_BYTES: u64 = 128 * 1024;
/// Stable terminal code emitted when a failed draft is spool-retained.
pub const KERNEL_AUDIT_SPOOL_RETAINED_CODE: &str = "KERNEL_AUDIT_SPOOL_RETAINED";
/// Stable terminal code emitted when a failed draft reaches last-resort.
pub const KERNEL_AUDIT_LAST_RESORT_RETAINED_CODE: &str = "KERNEL_AUDIT_LAST_RESORT_RETAINED";
/// Stable terminal code emitted when every stage fails (control loss).
pub const KERNEL_AUDIT_CONTROL_LOSS_CODE: &str = "KERNEL_AUDIT_CONTROL_LOSS";
/// Bounded event name carried by fallback control projections.
const AUDIT_FALLBACK_EVENT_NAME: &str = "audit.fallback.last_resort";

/// Resolves the default audit-spool directory below the work root.
#[must_use]
pub fn audit_spool_dir(work_root: &Path) -> PathBuf {
    kernel_audit_dir(work_root).join(AUDIT_SPOOL_DIR_NAME)
}

/// Host-injected audit-spool directory binding.
///
/// Mirrors [`AuditAnchorBinding`](super::kernel_audit::AuditAnchorBinding):
/// an absolute, already existing directory outside the canonical chain
/// file's failure leg where the Kernel persists spool records. `None` keeps
/// the default directory below the Kernel work root; the Kernel never
/// creates the foreign directory, it only appends inside it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditSpoolBinding {
    dir: PathBuf,
}

impl AuditSpoolBinding {
    /// Binds an absolute spool directory.
    ///
    /// # Errors
    ///
    /// Returns [`KernelAuditError::NotAbsoluteRoot`] when `dir` is not
    /// absolute, or [`KernelAuditError::NotDirectory`] when it does not
    /// exist. The Kernel never creates the foreign directory.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, KernelAuditError> {
        let dir = dir.into();
        if !dir.is_absolute() {
            return Err(KernelAuditError::NotAbsoluteRoot);
        }
        if !dir.is_dir() {
            return Err(KernelAuditError::NotDirectory);
        }
        Ok(Self { dir })
    }

    /// Returns the bound spool directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Redaction status carried by one spool record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuditSpoolRedaction {
    /// The body carries digests/identities only, per the #1837
    /// digest/identity-only draft-body contract (I15.4: no content).
    #[serde(rename = "DIGEST_IDENTITY_ONLY")]
    DigestIdentityOnly,
    /// Reserved for a future body classifier; never minted today.
    #[serde(rename = "NOT_ASSESSED")]
    NotAssessed,
}

/// Profile-appropriate contour proof recorded in one spool record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSpoolProtection {
    /// Whether the spool-contour access proof held at fallback open.
    pub verified: bool,
    /// Proven contour: `program_data` or `user_owned`.
    pub contour: String,
    /// Stable proof-failure code when `verified` is false.
    pub reason: Option<String>,
}

impl AuditSpoolProtection {
    /// Returns the spool contour name for one installation profile.
    fn contour_for(profile: RuntimeProfile) -> &'static str {
        match profile {
            RuntimeProfile::SystemService => "program_data",
            RuntimeProfile::UserMode | RuntimeProfile::Portable => "user_owned",
        }
    }

    /// Returns the stable code for one contour-proof failure.
    fn proof_code(error: ProtectedPathError) -> &'static str {
        match error {
            ProtectedPathError::InvalidRoot => "invalid_root",
            ProtectedPathError::InvalidPath => "invalid_path",
            ProtectedPathError::ReparsePoint => "reparse_point",
            ProtectedPathError::AclMismatch => "acl_mismatch",
            ProtectedPathError::Io => "contour_io",
            ProtectedPathError::IdentityMismatch => "identity_mismatch",
            ProtectedPathError::Win32 { .. } => "win32",
            ProtectedPathError::SizeExceeded => "size_exceeded",
            ProtectedPathError::UnsupportedPlatform => "unsupported_platform",
        }
    }

    /// Records a held contour proof.
    fn verified(contour: &'static str) -> Self {
        Self {
            verified: true,
            contour: contour.to_owned(),
            reason: None,
        }
    }

    /// Records a failed contour proof without loosening any access.
    fn unverified(contour: &'static str, reason: &'static str) -> Self {
        Self {
            verified: false,
            contour: contour.to_owned(),
            reason: Some(reason.to_owned()),
        }
    }
}

/// Recovery disposition carried by one spool record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuditSpoolDisposition {
    /// Spooled and awaiting reconciliation.
    #[serde(rename = "UNRECONCILED")]
    Unreconciled,
    /// Retained only by the last-resort slot (the spool stage failed).
    #[serde(rename = "LAST_RESORT_RETAINED")]
    LastResortRetained,
    /// Canonically appended; the receipt links spool to canonical record.
    #[serde(rename = "RECONCILED")]
    Reconciled,
    /// A canonical carrier already held the event; the receipt links it.
    #[serde(rename = "DUPLICATE_MERGED")]
    DuplicateMerged,
    /// Commit state unresolvable this run; retained for retry, never dropped.
    #[serde(rename = "UNKNOWN_COMMIT")]
    UnknownCommit,
}

impl AuditSpoolDisposition {
    /// Whether reconciliation is finished for this disposition.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Reconciled | Self::DuplicateMerged)
    }
}

/// One independently persisted audit spool record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSpoolRecord {
    /// Spool format version.
    pub format_version: u16,
    /// Stable spool identity: BLAKE3 over kind, draft hash, intended seq.
    pub spool_id: String,
    /// Closed canonical event kind (or the retained unknown kind).
    pub kind: String,
    /// Pre-finalize lineage: source process/module generation included.
    pub lineage: AuditLineage,
    /// Digest/identity-only event body.
    pub body: serde_json::Value,
    /// I16.9 assurance class derived from the kind.
    pub assurance: AuditAssuranceClass,
    /// Wall-clock milliseconds of the original boundary attempt.
    pub emitted_at_ms: u64,
    /// Wall-clock milliseconds when the record was spooled.
    pub spooled_at_ms: u64,
    /// Chain sequence the draft would have taken (`head + 1` at spool time).
    pub intended_seq: u64,
    /// BLAKE3 over the canonical draft bytes (kind, lineage, body).
    pub draft_hash: String,
    /// Source process identity (`process_identity`, or `kernel`).
    pub source_process: String,
    /// Source module/process generation text, when the lineage carries it.
    pub source_module_generation: Option<String>,
    /// Redaction status of the retained body.
    pub redaction: AuditSpoolRedaction,
    /// Contour proof recorded when the record was spooled.
    pub protection: AuditSpoolProtection,
    /// Reconcile attempts so far.
    pub retry_count: u32,
    /// Wall-clock milliseconds of the latest reconcile attempt.
    pub last_attempt_at_ms: Option<u64>,
    /// Current recovery disposition.
    pub disposition: AuditSpoolDisposition,
    /// BLAKE3 over the canonical bytes of every field above.
    pub record_hash: String,
}

/// Hash-covered spool record view: every field except `record_hash`.
#[derive(Serialize)]
struct AuditSpoolRecordHashView<'a> {
    format_version: u16,
    spool_id: &'a str,
    kind: &'a str,
    lineage: &'a AuditLineage,
    body: &'a serde_json::Value,
    assurance: AuditAssuranceClass,
    emitted_at_ms: u64,
    spooled_at_ms: u64,
    intended_seq: u64,
    draft_hash: &'a str,
    source_process: &'a str,
    source_module_generation: &'a Option<String>,
    redaction: AuditSpoolRedaction,
    protection: &'a AuditSpoolProtection,
    retry_count: u32,
    last_attempt_at_ms: &'a Option<u64>,
    disposition: AuditSpoolDisposition,
}

/// Canonical draft bytes covered by [`AuditSpoolRecord::draft_hash`].
#[derive(Serialize)]
struct AuditDraftHashView<'a> {
    kind: &'a str,
    lineage: &'a AuditLineage,
    body: &'a serde_json::Value,
}

/// Stable lineage identity compared by duplicate detection.
type AuditLineageKey = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

impl AuditSpoolRecord {
    /// Retains one failed draft as a spool record.
    ///
    /// The identity is deterministic in (kind, lineage, body, intended
    /// sequence): the same observation retried at the same head reuses its
    /// record instead of duplicating retained evidence, while any moved
    /// head or changed byte mints a distinct record.
    pub(crate) fn from_draft(
        draft: &AuditEventDraft,
        intended_seq: u64,
        emitted_at_ms: u64,
        spooled_at_ms: u64,
        protection: AuditSpoolProtection,
    ) -> Result<Self, KernelAuditError> {
        let view = AuditDraftHashView {
            kind: draft.kind(),
            lineage: draft.lineage(),
            body: draft.body(),
        };
        let draft_bytes = canonical_json_bytes(&view)
            .map_err(|error| KernelAuditError::Serialization(error.to_string()))?;
        let draft_hash = blake3_hex(&draft_bytes);
        let spool_id =
            blake3_hex(format!("{}:{draft_hash}:{intended_seq}", draft.kind()).as_bytes());
        let mut record = Self {
            format_version: AUDIT_SPOOL_FORMAT_VERSION,
            spool_id,
            kind: draft.kind().to_owned(),
            lineage: draft.lineage().clone(),
            body: draft.body().clone(),
            assurance: AuditEventKind::assurance_class(draft.kind()),
            emitted_at_ms,
            spooled_at_ms,
            intended_seq,
            draft_hash,
            source_process: draft
                .lineage()
                .process_identity
                .clone()
                .unwrap_or_else(|| "kernel".to_owned()),
            source_module_generation: draft.lineage().module_generation.clone(),
            redaction: AuditSpoolRedaction::DigestIdentityOnly,
            protection,
            retry_count: 0,
            last_attempt_at_ms: None,
            disposition: AuditSpoolDisposition::Unreconciled,
            record_hash: String::new(),
        };
        record.record_hash = record.recomputed_hash()?;
        Ok(record)
    }

    /// Returns the canonical bytes covered by `record_hash`.
    fn signing_bytes(&self) -> Result<Vec<u8>, KernelAuditError> {
        let view = AuditSpoolRecordHashView {
            format_version: self.format_version,
            spool_id: &self.spool_id,
            kind: &self.kind,
            lineage: &self.lineage,
            body: &self.body,
            assurance: self.assurance,
            emitted_at_ms: self.emitted_at_ms,
            spooled_at_ms: self.spooled_at_ms,
            intended_seq: self.intended_seq,
            draft_hash: &self.draft_hash,
            source_process: &self.source_process,
            source_module_generation: &self.source_module_generation,
            redaction: self.redaction,
            protection: &self.protection,
            retry_count: self.retry_count,
            last_attempt_at_ms: &self.last_attempt_at_ms,
            disposition: self.disposition,
        };
        canonical_json_bytes(&view)
            .map_err(|error| KernelAuditError::Serialization(error.to_string()))
    }

    /// Recomputes the record hash from the record's own fields.
    fn recomputed_hash(&self) -> Result<String, KernelAuditError> {
        Ok(blake3_hex(&self.signing_bytes()?))
    }

    /// Records one reconcile attempt, resealing the record hash.
    ///
    /// Atomic: the retry state changes only when the reseal succeeds.
    fn note_attempt(&mut self, now: u64) -> Result<(), KernelAuditError> {
        let mut next = self.clone();
        next.retry_count = next.retry_count.saturating_add(1);
        next.last_attempt_at_ms = Some(now);
        next.record_hash = next.recomputed_hash()?;
        *self = next;
        Ok(())
    }

    /// Moves the record to one disposition, resealing the record hash.
    ///
    /// Atomic: the disposition changes only when the reseal succeeds.
    fn set_disposition(
        &mut self,
        disposition: AuditSpoolDisposition,
    ) -> Result<(), KernelAuditError> {
        let mut next = self.clone();
        next.disposition = disposition;
        next.record_hash = next.recomputed_hash()?;
        *self = next;
        Ok(())
    }

    /// Returns the chain-style event digest of the retained body.
    fn event_digest(&self) -> Result<String, KernelAuditError> {
        let body_bytes = canonical_json_bytes(&self.body)
            .map_err(|error| KernelAuditError::Serialization(error.to_string()))?;
        Ok(blake3_hex(&body_bytes))
    }
}

/// Returns the stable lineage identity compared by duplicate detection.
fn lineage_key(lineage: &AuditLineage) -> AuditLineageKey {
    (
        lineage.trace_id.clone(),
        lineage.operation_id.clone(),
        lineage.attempt_id.clone(),
        lineage.job_id.clone(),
    )
}

/// Reconciliation disposition carried by one receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuditReconcileDisposition {
    /// The spooled draft appended canonically.
    #[serde(rename = "APPENDED")]
    Appended,
    /// A canonical carrier already held the event; no second append.
    #[serde(rename = "DUPLICATE_MERGED")]
    DuplicateMerged,
    /// A receipted-but-missing carrier was re-appended as a new record.
    #[serde(rename = "UNKNOWN_COMMIT_RESOLVED")]
    UnknownCommitResolved,
    /// The spooled kind is outside the closed set; evidence retained.
    #[serde(rename = "UNKNOWN_KIND_RETAINED")]
    UnknownKindRetained,
    /// A held control-loss projection was carried by a returning channel.
    #[serde(rename = "CONTROL_LOSS_REPLAYED")]
    ControlLossReplayed,
}

impl AuditReconcileDisposition {
    /// Returns the stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Appended => "APPENDED",
            Self::DuplicateMerged => "DUPLICATE_MERGED",
            Self::UnknownCommitResolved => "UNKNOWN_COMMIT_RESOLVED",
            Self::UnknownKindRetained => "UNKNOWN_KIND_RETAINED",
            Self::ControlLossReplayed => "CONTROL_LOSS_REPLAYED",
        }
    }
}

/// One reconciliation receipt linking spool evidence to a canonical append.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReconcileReceipt {
    /// Spool format version.
    pub format_version: u16,
    /// Stable receipt identity.
    pub receipt_id: String,
    /// Spooled record (or replayed projection) this receipt settles.
    pub spool_id: String,
    /// Record hash of the settled spool evidence (or of the replayed
    /// projection for [`AuditReconcileDisposition::ControlLossReplayed`]).
    pub spool_hash: String,
    /// Chain identity that carried or was searched for the event.
    pub chain_id: String,
    /// Canonical sequence carrying the event, when one does.
    pub canonical_seq: Option<u64>,
    /// Canonical current hash carrying the event, when one does.
    pub canonical_hash: Option<String>,
    /// How the spooled evidence settled.
    pub disposition: AuditReconcileDisposition,
    /// Superseded receipt identity for unknown-commit re-appends.
    pub prior_receipt_id: Option<String>,
    /// Wall-clock milliseconds when the receipt minted.
    pub reconciled_at_ms: u64,
    /// BLAKE3 over the canonical bytes of every field above.
    pub receipt_hash: String,
}

/// Hash-covered receipt view: every field except `receipt_hash`.
#[derive(Serialize)]
struct AuditReconcileReceiptHashView<'a> {
    format_version: u16,
    receipt_id: &'a str,
    spool_id: &'a str,
    spool_hash: &'a str,
    chain_id: &'a str,
    canonical_seq: &'a Option<u64>,
    canonical_hash: &'a Option<String>,
    disposition: AuditReconcileDisposition,
    prior_receipt_id: &'a Option<String>,
    reconciled_at_ms: u64,
}

/// Receipt mint inputs.
struct ReceiptMint<'a> {
    spool_id: &'a str,
    spool_hash: &'a str,
    chain_id: &'a str,
    canonical_seq: Option<u64>,
    canonical_hash: Option<&'a str>,
    disposition: AuditReconcileDisposition,
    prior_receipt_id: Option<&'a str>,
    reconciled_at_ms: u64,
}

impl AuditReconcileReceipt {
    /// Mints one receipt for settled spool evidence.
    fn mint(mint: &ReceiptMint<'_>) -> Result<Self, KernelAuditError> {
        let receipt_id = blake3_hex(
            format!(
                "{}:{}:{}:{}",
                mint.spool_id,
                mint.canonical_seq
                    .map_or_else(|| "-".to_owned(), |seq| seq.to_string()),
                mint.disposition.as_str(),
                mint.reconciled_at_ms,
            )
            .as_bytes(),
        );
        let mut receipt = Self {
            format_version: AUDIT_SPOOL_FORMAT_VERSION,
            receipt_id,
            spool_id: mint.spool_id.to_owned(),
            spool_hash: mint.spool_hash.to_owned(),
            chain_id: mint.chain_id.to_owned(),
            canonical_seq: mint.canonical_seq,
            canonical_hash: mint.canonical_hash.map(str::to_owned),
            disposition: mint.disposition,
            prior_receipt_id: mint.prior_receipt_id.map(str::to_owned),
            reconciled_at_ms: mint.reconciled_at_ms,
            receipt_hash: String::new(),
        };
        receipt.receipt_hash = receipt.recomputed_hash()?;
        Ok(receipt)
    }

    /// Returns the canonical bytes covered by `receipt_hash`.
    fn signing_bytes(&self) -> Result<Vec<u8>, KernelAuditError> {
        let view = AuditReconcileReceiptHashView {
            format_version: self.format_version,
            receipt_id: &self.receipt_id,
            spool_id: &self.spool_id,
            spool_hash: &self.spool_hash,
            chain_id: &self.chain_id,
            canonical_seq: &self.canonical_seq,
            canonical_hash: &self.canonical_hash,
            disposition: self.disposition,
            prior_receipt_id: &self.prior_receipt_id,
            reconciled_at_ms: self.reconciled_at_ms,
        };
        canonical_json_bytes(&view)
            .map_err(|error| KernelAuditError::Serialization(error.to_string()))
    }

    /// Recomputes the receipt hash from the receipt's own fields.
    fn recomputed_hash(&self) -> Result<String, KernelAuditError> {
        Ok(blake3_hex(&self.signing_bytes()?))
    }
}

/// Last-resort control-slot document (single bounded record).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlSlotDoc {
    format_version: u16,
    occupied: Option<AuditSpoolRecord>,
    last_cleared: Option<SlotClearance>,
}

/// Tombstone proving which settled record left the control slot.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotClearance {
    spool_id: String,
    receipt_id: String,
    cleared_at_ms: u64,
}

/// Last-resort channel that carried one record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditLastResortChannel {
    /// The Windows Event Log (`system_service` profile).
    EventLog,
    /// The bounded control-slot document (`user_mode`/portable).
    ControlSlot,
}

/// Terminal outcome of one fallback observation.
#[derive(Clone, Debug)]
pub enum AuditFallbackOutcome {
    /// Stage 1 carried the draft.
    Appended(AuditRecord),
    /// Stage 2 retained the draft in the audit spool.
    Spooled {
        /// The retained spool record.
        record: AuditSpoolRecord,
    },
    /// Stage 3 retained the draft in the last-resort channel.
    LastResort {
        /// The retained spool record.
        record: AuditSpoolRecord,
        /// The channel that carried it.
        via: AuditLastResortChannel,
    },
    /// Every stage failed; the projection is held in the visible
    /// control-loss state with its real stage reasons.
    ControlLoss {
        /// The unretained spool record (in-memory only).
        record: AuditSpoolRecord,
        /// The control-loss state holding its projection.
        state: CriticalEventState,
    },
    /// The draft could not even be hashed for retention; only the bounded
    /// projection entered the control-loss machine.
    Unretainable {
        /// Synthetic projection identity.
        event_id: String,
        /// Stable failure code.
        reason: &'static str,
        /// The control-loss state holding its projection.
        state: CriticalEventState,
    },
}

impl AuditFallbackOutcome {
    /// Returns the cascade terminal code for a degraded outcome.
    #[must_use]
    pub const fn retention_code(&self) -> Option<&'static str> {
        match self {
            Self::Appended(_) => None,
            Self::Spooled { .. } => Some(KERNEL_AUDIT_SPOOL_RETAINED_CODE),
            Self::LastResort { .. } => Some(KERNEL_AUDIT_LAST_RESORT_RETAINED_CODE),
            Self::ControlLoss { .. } | Self::Unretainable { .. } => {
                Some(KERNEL_AUDIT_CONTROL_LOSS_CODE)
            }
        }
    }
}

/// One per-record reconcile failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditReconcileFailure {
    /// Spooled record that could not settle this run.
    pub spool_id: String,
    /// Stable failure code.
    pub reason: &'static str,
}

/// Terminal report of one reconcile run.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the reconcile report is a flat terminal tally; grouping its independent run flags into sub-structs would obscure the bounded summary"
)]
pub struct AuditReconcileReport {
    /// Wall-clock milliseconds when the run started.
    pub ran_at_ms: u64,
    /// Whether the canonical chain was readable.
    pub chain_available: bool,
    /// Stable chain-read failure code when unavailable.
    pub chain_error: Option<&'static str>,
    /// Spool records examined.
    pub spool_examined: u64,
    /// Drafts canonically appended.
    pub appended: u64,
    /// Events merged onto an existing canonical carrier.
    pub duplicates_merged: u64,
    /// Records already settled by a retained receipt.
    pub already_receipted: u64,
    /// Receipted-but-missing carriers re-appended.
    pub unknown_commits_resolved: u64,
    /// Unknown-kind records retained without an append.
    pub unknown_kind_retained: u64,
    /// Per-record failures, each retained for a later run.
    pub failed: Vec<AuditReconcileFailure>,
    /// 1-based spool line numbers that did not parse or verify.
    pub unparseable_spool_lines: Vec<u64>,
    /// Spool lines beyond the retention ceiling (counted, not read).
    pub spool_lines_beyond_cap: u64,
    /// Receipt lines that did not parse or verify.
    pub unparseable_receipt_lines: u64,
    /// Whether the receipt append failed (nothing else persisted).
    pub receipt_append_failed: bool,
    /// Whether the spool disposition rewrite failed.
    pub spool_rewrite_failed: bool,
    /// Whether the control slot held a record this run.
    pub slot_examined: bool,
    /// Whether the control slot was cleared with a tombstone.
    pub slot_cleared: bool,
    /// Whether the control-slot clearance write failed.
    pub slot_clear_failed: bool,
    /// Whether the control slot could not be read.
    pub slot_unparseable: bool,
    /// Held control-loss projections carried by a returning channel.
    pub control_loss_replayed: u64,
    /// Replayed projections that could not be receipted.
    pub control_loss_unhashable: u64,
}

impl AuditReconcileReport {
    /// Starts an empty report for one run.
    fn new(ran_at_ms: u64) -> Self {
        Self {
            ran_at_ms,
            chain_available: true,
            chain_error: None,
            spool_examined: 0,
            appended: 0,
            duplicates_merged: 0,
            already_receipted: 0,
            unknown_commits_resolved: 0,
            unknown_kind_retained: 0,
            failed: Vec::new(),
            unparseable_spool_lines: Vec::new(),
            spool_lines_beyond_cap: 0,
            unparseable_receipt_lines: 0,
            receipt_append_failed: false,
            spool_rewrite_failed: false,
            slot_examined: false,
            slot_cleared: false,
            slot_clear_failed: false,
            slot_unparseable: false,
            control_loss_replayed: 0,
            control_loss_unhashable: 0,
        }
    }

    /// Returns the bounded single-line run summary for diagnostics.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "kernel.audit.spool_reconciled chain={} examined={} appended={} dup={} receipted={} unknown={} unkind={} failed={} bad_lines={} slot_cleared={} replayed={}",
            self.chain_available,
            self.spool_examined,
            self.appended,
            self.duplicates_merged,
            self.already_receipted,
            self.unknown_commits_resolved,
            self.unknown_kind_retained,
            self.failed.len(),
            self.unparseable_spool_lines.len(),
            self.slot_cleared,
            self.control_loss_replayed,
        )
    }
}

/// Returns the stable code for one chain failure (caller-visible only).
fn audit_error_code(error: &KernelAuditError) -> &'static str {
    match error {
        KernelAuditError::NotAbsoluteRoot => "not_absolute_root",
        KernelAuditError::NotDirectory => "not_directory",
        KernelAuditError::Io { .. } => "io",
        KernelAuditError::ChainCorrupt { .. } => "chain_corrupt",
        KernelAuditError::UnknownEventKind(_) => "unknown_event_kind",
        KernelAuditError::AnchorMismatch { .. } => "anchor_mismatch",
        KernelAuditError::EmptyChain => "empty_chain",
        KernelAuditError::Serialization(_) => "serialization",
        KernelAuditError::LockPoisoned => "lock_poisoned",
    }
}

/// The single Kernel-owned audit-fallback handle.
///
/// Owns the I16.11 stage 2-4 cascade for audit drafts: the independently
/// persisted spool record store, the last-resort channel, and the terminal
/// control-loss machine. Exactly one handle exists per composition; it is
/// locked after `kernel_audit` and never acquires another Kernel lock.
pub struct KernelAuditFallback {
    spool_dir: PathBuf,
    spool_path: PathBuf,
    receipt_path: PathBuf,
    slot_path: PathBuf,
    profile: RuntimeProfile,
    protection: AuditSpoolProtection,
    spool_available: bool,
    control: CriticalPath,
}

impl KernelAuditFallback {
    /// Opens the fallback over one spool directory.
    ///
    /// This never fails: an unusable directory degrades the spool stage to
    /// unavailable (last-resort and control-loss stay live) instead of
    /// failing composition boot over a fallback-path problem. The contour
    /// proof outcome is recorded for every spooled record.
    #[must_use]
    pub fn open(spool_dir: &Path, profile: RuntimeProfile) -> Self {
        let spool_available = spool_dir.is_absolute()
            && std::fs::create_dir_all(spool_dir).is_ok()
            && spool_dir.is_dir();
        let contour = AuditSpoolProtection::contour_for(profile);
        let protection = if spool_available {
            prove_spool_contour(spool_dir, profile, contour)
        } else {
            AuditSpoolProtection::unverified(contour, "spool_dir_unusable")
        };
        let last_resort = match profile {
            RuntimeProfile::SystemService => Some(EventLogReport),
            RuntimeProfile::UserMode | RuntimeProfile::Portable => None,
        };
        Self {
            spool_dir: spool_dir.to_path_buf(),
            spool_path: spool_dir.join(AUDIT_SPOOL_FILE_NAME),
            receipt_path: spool_dir.join(AUDIT_SPOOL_RECEIPT_FILE_NAME),
            slot_path: spool_dir.join(AUDIT_SPOOL_SLOT_FILE_NAME),
            profile,
            protection,
            spool_available,
            control: CriticalPath::new(CriticalEventSinks {
                normal: None,
                spool: None,
                last_resort,
            }),
        }
    }

    /// Returns the spool directory.
    #[must_use]
    pub fn spool_dir(&self) -> &Path {
        &self.spool_dir
    }

    /// Returns the installation profile driving the last-resort rule.
    #[must_use]
    pub const fn profile(&self) -> RuntimeProfile {
        self.profile
    }

    /// Returns the contour proof recorded at open.
    #[must_use]
    pub fn protection(&self) -> &AuditSpoolProtection {
        &self.protection
    }

    /// Whether the spool stage can persist records.
    #[must_use]
    pub const fn spool_available(&self) -> bool {
        self.spool_available
    }

    /// Monotone count of records that entered the control-loss state.
    #[must_use]
    pub fn control_loss_total(&self) -> u64 {
        self.control.control_loss_total()
    }

    /// Number of projections currently held in the control-loss state.
    #[must_use]
    pub fn held_control_loss(&self) -> usize {
        self.control.held_control_loss()
    }

    /// Counts spool records still awaiting reconciliation.
    #[must_use]
    pub fn pending_spool_records(&self) -> u64 {
        let (records, _, _) = self.read_spool_records();
        u64::try_from(
            records
                .iter()
                .filter(|record| !record.disposition.is_terminal())
                .count(),
        )
        .unwrap_or(u64::MAX)
    }
}

/// Proves the profile-appropriate spool contour without changing access.
fn prove_spool_contour(
    spool_dir: &Path,
    profile: RuntimeProfile,
    contour: &'static str,
) -> AuditSpoolProtection {
    match profile {
        RuntimeProfile::SystemService => match prepare_protected_directory(spool_dir) {
            Ok(()) => AuditSpoolProtection::verified(contour),
            Err(error) => {
                AuditSpoolProtection::unverified(contour, AuditSpoolProtection::proof_code(error))
            }
        },
        RuntimeProfile::UserMode | RuntimeProfile::Portable => {
            match UserOwnedRootLease::open_existing(spool_dir) {
                Ok(_lease) => AuditSpoolProtection::verified(contour),
                Err(error) => AuditSpoolProtection::unverified(
                    contour,
                    AuditSpoolProtection::proof_code(error),
                ),
            }
        }
    }
}

/// Appends one line plus newline with an fsync, reporting persistence.
fn append_line_sync(path: &Path, line: &str) -> bool {
    let opened = OpenOptions::new().create(true).append(true).open(path);
    let Ok(mut file) = opened else {
        return false;
    };
    file.write_all(line.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .is_ok()
}

/// Replaces one file atomically (staging write, fsync, rename).
fn write_sync_replace(path: &Path, bytes: &[u8]) -> bool {
    let staging = path.with_extension(AUDIT_SPOOL_STAGING_SUFFIX);
    let opened = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&staging);
    let Ok(mut file) = opened else {
        return false;
    };
    if file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        return false;
    }
    drop(file);
    std::fs::rename(&staging, path).is_ok()
}

/// Outcome of one spool-stage attempt.
enum SpoolAttempt {
    /// The record is retained (newly written or already present).
    Retained(Box<AuditSpoolRecord>),
    /// The stage refused with a stable code.
    Unavailable(&'static str),
}

/// Control-slot read state.
enum SlotState {
    /// No record is retained.
    Empty,
    /// One record is retained.
    Occupied(Box<AuditSpoolRecord>),
    /// The slot could not be read or verified.
    Unreadable,
}

impl KernelAuditFallback {
    /// Observes one draft through the I16.11 stage order.
    ///
    /// Stage 1 appends to the canonical chain. On failure the draft is
    /// retained in the audit spool (stage 2), else the last-resort channel
    /// (stage 3), else the visible control-loss state. No outcome is a
    /// silent success: degraded outcomes carry their retention proof or
    /// their held control-loss state.
    pub fn observe(
        &mut self,
        chain: &mut KernelAuditChain,
        draft: AuditEventDraft,
        now: u64,
    ) -> AuditFallbackOutcome {
        let retained = draft.clone();
        let chain_code = match chain.append(draft, now) {
            Ok(record) => return AuditFallbackOutcome::Appended(record),
            Err(error) => audit_error_code(&error),
        };
        let Some(intended_seq) = chain.head_seq().checked_add(1) else {
            return self.unretainable("sequence_overflow", chain_code, now);
        };
        let Ok(record) = AuditSpoolRecord::from_draft(
            &retained,
            intended_seq,
            now,
            now,
            self.protection.clone(),
        ) else {
            return self.unretainable("spool_record_unhashable", chain_code, now);
        };
        let (spool_code, spooled) = match self.try_spool(&record) {
            SpoolAttempt::Retained(stored) => {
                return AuditFallbackOutcome::Spooled { record: *stored };
            }
            SpoolAttempt::Unavailable(code) => (code, record),
        };
        self.last_resort(spooled, chain_code, spool_code)
    }

    /// Attempts the spool stage, refusing instead of overwriting evidence.
    fn try_spool(&self, record: &AuditSpoolRecord) -> SpoolAttempt {
        if !self.spool_available {
            return SpoolAttempt::Unavailable("spool_unavailable");
        }
        let (retained, _, _) = self.read_spool_records();
        if retained.len() >= AUDIT_SPOOL_MAX_RECORDS {
            return SpoolAttempt::Unavailable("spool_saturated");
        }
        if let Some(existing) = retained
            .iter()
            .find(|stored| stored.spool_id == record.spool_id)
        {
            return SpoolAttempt::Retained(Box::new(existing.clone()));
        }
        let Ok(line) = serde_json::to_string(record) else {
            return SpoolAttempt::Unavailable("spool_serialization");
        };
        if u64::try_from(line.len()).unwrap_or(u64::MAX) > AUDIT_SPOOL_MAX_LINE_BYTES {
            return SpoolAttempt::Unavailable("spool_record_overbound");
        }
        if append_line_sync(&self.spool_path, &line) {
            SpoolAttempt::Retained(Box::new(record.clone()))
        } else {
            SpoolAttempt::Unavailable("spool_io")
        }
    }

    /// Attempts the last-resort stage, else the visible control-loss state.
    fn last_resort(
        &mut self,
        record: AuditSpoolRecord,
        chain_code: &'static str,
        spool_code: &'static str,
    ) -> AuditFallbackOutcome {
        if matches!(self.profile, RuntimeProfile::SystemService) {
            return self.last_resort_event_log(record, chain_code, spool_code);
        }
        let mut stored = record.clone();
        if stored
            .set_disposition(AuditSpoolDisposition::LastResortRetained)
            .is_ok()
            && self.try_control_slot(&stored)
        {
            return AuditFallbackOutcome::LastResort {
                record: stored,
                via: AuditLastResortChannel::ControlSlot,
            };
        }
        let state = self.hold_control_loss(
            &record.spool_id,
            &record.kind,
            record.intended_seq,
            &[chain_code, spool_code, "slot_unavailable"],
        );
        AuditFallbackOutcome::ControlLoss { record, state }
    }

    /// Attempts the `system_service` last-resort stage through the machine.
    fn last_resort_event_log(
        &mut self,
        record: AuditSpoolRecord,
        chain_code: &'static str,
        spool_code: &'static str,
    ) -> AuditFallbackOutcome {
        let state = self.hold_control_loss(
            &record.spool_id,
            &record.kind,
            record.intended_seq,
            &[chain_code, spool_code, "event_log"],
        );
        match state {
            CriticalEventState::Delivered { .. } => AuditFallbackOutcome::LastResort {
                record,
                via: AuditLastResortChannel::EventLog,
            },
            state @ CriticalEventState::ControlLoss { .. } => {
                AuditFallbackOutcome::ControlLoss { record, state }
            }
        }
    }

    /// Holds one bounded projection in the control-loss machine.
    ///
    /// The projection detail carries the real audit stage codes; the
    /// returned state is the machine's honest terminal for the projection.
    fn hold_control_loss(
        &mut self,
        spool_id: &str,
        kind: &str,
        intended_seq: u64,
        stages: &[&str],
    ) -> CriticalEventState {
        let detail = format!(
            "kind={} seq={intended_seq} stages={}",
            bounded_token(kind, 64),
            stages.join("/"),
        );
        let projection = CriticalEventRecord::new(
            spool_id,
            AUDIT_FALLBACK_EVENT_NAME,
            self.profile.as_str(),
            &detail,
        );
        match projection {
            Ok(projection) => self.control.submit(projection).state,
            Err(_) => CriticalEventState::ControlLoss {
                attempts: Vec::new(),
            },
        }
    }

    /// Handles a draft that cannot be hashed for retention.
    fn unretainable(
        &mut self,
        reason: &'static str,
        chain_code: &'static str,
        now: u64,
    ) -> AuditFallbackOutcome {
        let event_id = format!("unretainable-{now}-{reason}");
        let detail = format!("stages={chain_code}/unhashable/unattempted");
        let state = match CriticalEventRecord::new(
            &event_id,
            AUDIT_FALLBACK_EVENT_NAME,
            self.profile.as_str(),
            &detail,
        ) {
            Ok(projection) => self.control.submit(projection).state,
            Err(_) => CriticalEventState::ControlLoss {
                attempts: Vec::new(),
            },
        };
        AuditFallbackOutcome::Unretainable {
            event_id,
            reason,
            state,
        }
    }

    /// Attempts the control-slot write, refusing an occupied slot.
    fn try_control_slot(&self, record: &AuditSpoolRecord) -> bool {
        if !self.spool_available {
            return false;
        }
        if !matches!(self.read_slot_state(), SlotState::Empty) {
            return false;
        }
        self.write_slot_doc(&ControlSlotDoc {
            format_version: AUDIT_SPOOL_FORMAT_VERSION,
            occupied: Some(record.clone()),
            last_cleared: self.last_slot_clearance(),
        })
    }

    /// Returns the retained slot tombstone, if any.
    fn last_slot_clearance(&self) -> Option<SlotClearance> {
        if !self.slot_path.exists() {
            return None;
        }
        let bytes = std::fs::read(&self.slot_path).ok()?;
        serde_json::from_slice::<ControlSlotDoc>(&bytes)
            .ok()
            .and_then(|doc| doc.last_cleared)
    }

    /// Writes one slot document atomically.
    fn write_slot_doc(&self, doc: &ControlSlotDoc) -> bool {
        let Ok(bytes) = serde_json::to_vec(doc) else {
            return false;
        };
        write_sync_replace(&self.slot_path, &bytes)
    }

    /// Reads the control-slot state, verifying any retained record.
    fn read_slot_state(&self) -> SlotState {
        if !self.spool_available || !self.slot_path.exists() {
            return SlotState::Empty;
        }
        let Ok(bytes) = std::fs::read(&self.slot_path) else {
            return SlotState::Unreadable;
        };
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > AUDIT_SPOOL_SLOT_MAX_BYTES {
            return SlotState::Unreadable;
        }
        let doc: ControlSlotDoc = match serde_json::from_slice(&bytes) {
            Ok(doc) => doc,
            Err(_) => return SlotState::Unreadable,
        };
        if doc.format_version != AUDIT_SPOOL_FORMAT_VERSION {
            return SlotState::Unreadable;
        }
        match doc.occupied {
            None => SlotState::Empty,
            Some(record) => {
                if record.format_version != AUDIT_SPOOL_FORMAT_VERSION {
                    return SlotState::Unreadable;
                }
                match record.recomputed_hash() {
                    Ok(hash) if hash == record.record_hash => SlotState::Occupied(Box::new(record)),
                    _ => SlotState::Unreadable,
                }
            }
        }
    }
}

/// Returns the first `max` non-control characters of one token.
fn bounded_token(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(max)
        .collect()
}

/// Canonical carrier index: (kind, event digest, lineage key) to the first
/// canonical (sequence, current hash) holding the event.
type CanonicalIndex = HashMap<(String, String, AuditLineageKey), (u64, String)>;

/// Builds the canonical carrier index over retained chain records.
fn canonical_index(records: &[AuditRecord]) -> CanonicalIndex {
    let mut index = HashMap::new();
    for record in records {
        index
            .entry((
                record.kind.clone(),
                record.event_digest.clone(),
                lineage_key(&record.lineage),
            ))
            .or_insert((record.seq, record.current_hash.clone()));
    }
    index
}

/// Shared inputs of one per-record reconcile step.
struct SpoolReconcileCtx<'a> {
    chain: &'a mut KernelAuditChain,
    chain_records: &'a [AuditRecord],
    index: &'a mut CanonicalIndex,
    receipts: &'a mut HashMap<String, AuditReconcileReceipt>,
    now: u64,
    report: &'a mut AuditReconcileReport,
    new_receipts: &'a mut Vec<AuditReconcileReceipt>,
}

/// Control-slot reconcile outcome.
enum SlotOutcome {
    /// The slot held no record.
    Empty,
    /// The slot still holds its record.
    KeptOccupied,
    /// The slot was cleared for one settled record.
    Cleared {
        /// Settled spool identity.
        spool_id: String,
        /// Receipt settling it.
        receipt_id: String,
    },
}

impl KernelAuditFallback {
    /// Reconciles spooled records into canonical audit state.
    ///
    /// Runs once storage is readable (composition startup calls this after
    /// the chain opens). Every spooled record settles exactly once: it
    /// appends canonically, merges onto an existing canonical carrier, or
    /// stays retained with its failure visible in the report. Duplicates
    /// and unknown-commit cases always mint a receipt; nothing is silently
    /// dropped. Receipts persist before spool dispositions rewrite, so a
    /// crash between the two self-heals through the receipt-wins path.
    pub fn reconcile(&mut self, chain: &mut KernelAuditChain, now: u64) -> AuditReconcileReport {
        let mut report = AuditReconcileReport::new(now);
        let chain_records = match chain.records() {
            Ok(records) => records,
            Err(error) => {
                report.chain_available = false;
                report.chain_error = Some(audit_error_code(&error));
                return report;
            }
        };
        let mut index = canonical_index(&chain_records);
        let (mut spool_records, unparseable, beyond_cap) = self.read_spool_records();
        report.unparseable_spool_lines = unparseable;
        report.spool_lines_beyond_cap = beyond_cap;
        let (mut receipts, bad_receipts) = self.read_receipts();
        report.unparseable_receipt_lines = bad_receipts;
        let mut new_receipts = Vec::new();
        let mut spool_mutated = false;
        let slot_outcome = {
            let mut ctx = SpoolReconcileCtx {
                chain,
                chain_records: &chain_records,
                index: &mut index,
                receipts: &mut receipts,
                now,
                report: &mut report,
                new_receipts: &mut new_receipts,
            };
            for record in &mut spool_records {
                ctx.report.spool_examined += 1;
                spool_mutated |= reconcile_spool_record(&mut ctx, record);
            }
            let slot_state = self.read_slot_state();
            if matches!(slot_state, SlotState::Empty) {
                SlotOutcome::Empty
            } else {
                ctx.report.slot_examined = true;
                reconcile_slot(&mut ctx, slot_state)
            }
        };
        if self.append_receipts(&new_receipts) {
            if spool_mutated && !self.rewrite_spool_file(&spool_records) {
                report.spool_rewrite_failed = true;
            }
            self.apply_slot_outcome(&slot_outcome, &mut report);
        } else {
            report.receipt_append_failed = true;
        }
        self.reconcile_control_loss(
            now,
            chain.chain_id(),
            &mut receipts,
            &mut new_receipts,
            &mut report,
        );
        let replayed_only: Vec<AuditReconcileReceipt> = new_receipts
            .iter()
            .filter(|receipt| receipt.disposition == AuditReconcileDisposition::ControlLossReplayed)
            .cloned()
            .collect();
        if !replayed_only.is_empty() && !self.append_receipts(&replayed_only) {
            report.receipt_append_failed = true;
        }
        report
    }

    /// Applies one slot outcome after its receipts persisted.
    fn apply_slot_outcome(&self, outcome: &SlotOutcome, report: &mut AuditReconcileReport) {
        if let SlotOutcome::Cleared {
            spool_id,
            receipt_id,
        } = outcome
        {
            if self.clear_slot(spool_id, receipt_id, report.ran_at_ms) {
                report.slot_cleared = true;
            } else {
                report.slot_clear_failed = true;
            }
        }
    }

    /// Receipts control-loss projections carried by a returning channel.
    fn reconcile_control_loss(
        &mut self,
        now: u64,
        chain_id: &str,
        receipts: &mut HashMap<String, AuditReconcileReceipt>,
        new_receipts: &mut Vec<AuditReconcileReceipt>,
        report: &mut AuditReconcileReport,
    ) {
        let replayed = self.control.release_control_loss();
        report.control_loss_replayed = u64::try_from(replayed.len()).unwrap_or(u64::MAX);
        for projection in &replayed {
            if receipts.contains_key(&projection.event_id) {
                continue;
            }
            let Ok(digest_bytes) = canonical_json_bytes(projection) else {
                report.control_loss_unhashable += 1;
                continue;
            };
            let digest = blake3_hex(&digest_bytes);
            let receipt = AuditReconcileReceipt::mint(&ReceiptMint {
                spool_id: &projection.event_id,
                spool_hash: &digest,
                chain_id,
                canonical_seq: None,
                canonical_hash: None,
                disposition: AuditReconcileDisposition::ControlLossReplayed,
                prior_receipt_id: None,
                reconciled_at_ms: now,
            });
            match receipt {
                Ok(receipt) => {
                    receipts.insert(projection.event_id.clone(), receipt.clone());
                    new_receipts.push(receipt);
                }
                Err(_) => {
                    report.control_loss_unhashable += 1;
                }
            }
        }
    }

    /// Reads and verifies retained spool records with their bad-line report.
    fn read_spool_records(&self) -> (Vec<AuditSpoolRecord>, Vec<u64>, u64) {
        let mut records = Vec::new();
        let mut unparseable = Vec::new();
        let mut beyond_cap = 0_u64;
        if !self.spool_available || !self.spool_path.exists() {
            return (records, unparseable, beyond_cap);
        }
        let Ok(file) = OpenOptions::new().read(true).open(&self.spool_path) else {
            return (records, unparseable, beyond_cap);
        };
        let mut bytes_read = 0_u64;
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line_number = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
            let Ok(line) = line else {
                unparseable.push(line_number);
                continue;
            };
            bytes_read = bytes_read.saturating_add(
                u64::try_from(line.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            );
            if bytes_read > AUDIT_SPOOL_MAX_FILE_BYTES
                || records.len() + unparseable.len() >= AUDIT_SPOOL_MAX_RECORDS
            {
                beyond_cap += 1;
                continue;
            }
            match parse_spool_line(&line) {
                Some(record) => records.push(record),
                None => unparseable.push(line_number),
            }
        }
        (records, unparseable, beyond_cap)
    }

    /// Reads retained receipts into a last-wins map with a bad-line count.
    fn read_receipts(&self) -> (HashMap<String, AuditReconcileReceipt>, u64) {
        let mut receipts = HashMap::new();
        let mut unparseable = 0_u64;
        if !self.spool_available || !self.receipt_path.exists() {
            return (receipts, unparseable);
        }
        let Ok(file) = OpenOptions::new().read(true).open(&self.receipt_path) else {
            return (receipts, unparseable);
        };
        let mut bytes_read = 0_u64;
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else {
                unparseable += 1;
                continue;
            };
            bytes_read = bytes_read.saturating_add(
                u64::try_from(line.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            );
            if bytes_read > AUDIT_SPOOL_MAX_FILE_BYTES {
                unparseable += 1;
                continue;
            }
            match parse_receipt_line(&line) {
                Some(receipt) => {
                    receipts.insert(receipt.spool_id.clone(), receipt);
                }
                None => unparseable += 1,
            }
        }
        (receipts, unparseable)
    }

    /// Rewrites the spool file with current dispositions, atomically.
    fn rewrite_spool_file(&self, records: &[AuditSpoolRecord]) -> bool {
        let mut bytes = Vec::new();
        for record in records {
            let Ok(line) = serde_json::to_string(record) else {
                return false;
            };
            bytes.extend_from_slice(line.as_bytes());
            bytes.push(b'\n');
        }
        write_sync_replace(&self.spool_path, &bytes)
    }

    /// Appends one run's receipts with a single fsync.
    fn append_receipts(&self, receipts: &[AuditReconcileReceipt]) -> bool {
        if receipts.is_empty() {
            return true;
        }
        if !self.spool_available {
            return false;
        }
        let mut bytes = Vec::new();
        for receipt in receipts {
            let Ok(line) = serde_json::to_string(receipt) else {
                return false;
            };
            bytes.extend_from_slice(line.as_bytes());
            bytes.push(b'\n');
        }
        let opened = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.receipt_path);
        let Ok(mut file) = opened else {
            return false;
        };
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .is_ok()
    }

    /// Clears the control slot with a tombstone for one settled record.
    fn clear_slot(&self, spool_id: &str, receipt_id: &str, now: u64) -> bool {
        let occupied_id = match self.read_slot_state() {
            SlotState::Occupied(record) => Some(record.spool_id),
            _ => None,
        };
        if occupied_id.as_deref() != Some(spool_id) {
            return false;
        }
        self.write_slot_doc(&ControlSlotDoc {
            format_version: AUDIT_SPOOL_FORMAT_VERSION,
            occupied: None,
            last_cleared: Some(SlotClearance {
                spool_id: spool_id.to_owned(),
                receipt_id: receipt_id.to_owned(),
                cleared_at_ms: now,
            }),
        })
    }
}

/// Parses and verifies one spool line.
fn parse_spool_line(line: &str) -> Option<AuditSpoolRecord> {
    if line.trim().is_empty() {
        return None;
    }
    let record: AuditSpoolRecord = serde_json::from_str(line).ok()?;
    if record.format_version != AUDIT_SPOOL_FORMAT_VERSION {
        return None;
    }
    let hash = record.recomputed_hash().ok()?;
    if hash != record.record_hash {
        return None;
    }
    Some(record)
}

/// Parses and verifies one receipt line.
fn parse_receipt_line(line: &str) -> Option<AuditReconcileReceipt> {
    if line.trim().is_empty() {
        return None;
    }
    let receipt: AuditReconcileReceipt = serde_json::from_str(line).ok()?;
    if receipt.format_version != AUDIT_SPOOL_FORMAT_VERSION {
        return None;
    }
    let hash = receipt.recomputed_hash().ok()?;
    if hash != receipt.receipt_hash {
        return None;
    }
    Some(receipt)
}

/// Settles one spool record, returning whether its persisted state changed.
fn reconcile_spool_record(ctx: &mut SpoolReconcileCtx<'_>, record: &mut AuditSpoolRecord) -> bool {
    if record.disposition.is_terminal() {
        return false;
    }
    if record.note_attempt(ctx.now).is_err() {
        ctx.report.failed.push(AuditReconcileFailure {
            spool_id: record.spool_id.clone(),
            reason: "spool_record_unhashable",
        });
        return false;
    }
    if let Some(receipt) = ctx.receipts.get(&record.spool_id).cloned() {
        return reconcile_receipted_record(ctx, record, &receipt);
    }
    settle_unreceipted_record(ctx, record, None)
}

/// Settles one record that already holds a receipt (receipt-wins path).
fn reconcile_receipted_record(
    ctx: &mut SpoolReconcileCtx<'_>,
    record: &mut AuditSpoolRecord,
    receipt: &AuditReconcileReceipt,
) -> bool {
    match receipt.disposition {
        AuditReconcileDisposition::Appended
        | AuditReconcileDisposition::DuplicateMerged
        | AuditReconcileDisposition::UnknownCommitResolved => {
            if carrier_verifies(
                ctx.chain_records,
                receipt.canonical_seq,
                receipt.canonical_hash.as_deref(),
            ) {
                ctx.report.already_receipted += 1;
                let disposition = match receipt.disposition {
                    AuditReconcileDisposition::DuplicateMerged => {
                        AuditSpoolDisposition::DuplicateMerged
                    }
                    _ => AuditSpoolDisposition::Reconciled,
                };
                if record.disposition == disposition {
                    return true;
                }
                record.set_disposition(disposition).is_ok()
            } else {
                resolve_unknown_commit(ctx, record, receipt)
            }
        }
        AuditReconcileDisposition::UnknownKindRetained => {
            if AuditEventKind::canonical(&record.kind).is_some() {
                settle_unreceipted_record(ctx, record, Some(receipt.receipt_id.as_str()))
            } else {
                ctx.report.already_receipted += 1;
                true
            }
        }
        AuditReconcileDisposition::ControlLossReplayed => {
            settle_unreceipted_record(ctx, record, Some(receipt.receipt_id.as_str()))
        }
    }
}

/// Settles one record with no usable receipt: merge, append, or retain.
fn settle_unreceipted_record(
    ctx: &mut SpoolReconcileCtx<'_>,
    record: &mut AuditSpoolRecord,
    prior_receipt_id: Option<&str>,
) -> bool {
    let Some(kind) = AuditEventKind::canonical(&record.kind) else {
        if mint_settlement(
            ctx,
            record,
            AuditReconcileDisposition::UnknownKindRetained,
            None,
            prior_receipt_id,
        ) {
            ctx.report.unknown_kind_retained += 1;
        }
        return true;
    };
    let Ok(digest) = record.event_digest() else {
        ctx.report.failed.push(AuditReconcileFailure {
            spool_id: record.spool_id.clone(),
            reason: "spool_record_unhashable",
        });
        return true;
    };
    let key = (record.kind.clone(), digest, lineage_key(&record.lineage));
    if let Some((seq, hash)) = ctx.index.get(&key).cloned() {
        if mint_settlement(
            ctx,
            record,
            AuditReconcileDisposition::DuplicateMerged,
            Some((seq, hash.as_str())),
            prior_receipt_id,
        ) {
            ctx.report.duplicates_merged += 1;
            return record
                .set_disposition(AuditSpoolDisposition::DuplicateMerged)
                .is_ok();
        }
        return true;
    }
    let draft = AuditEventDraft::from_parts(kind, record.lineage.clone(), record.body.clone());
    match ctx.chain.append(draft, ctx.now) {
        Ok(canonical) => {
            ctx.index
                .entry(key)
                .or_insert((canonical.seq, canonical.current_hash.clone()));
            if mint_settlement(
                ctx,
                record,
                AuditReconcileDisposition::Appended,
                Some((canonical.seq, canonical.current_hash.as_str())),
                prior_receipt_id,
            ) {
                ctx.report.appended += 1;
                return record
                    .set_disposition(AuditSpoolDisposition::Reconciled)
                    .is_ok();
            }
            true
        }
        Err(error) => {
            ctx.report.failed.push(AuditReconcileFailure {
                spool_id: record.spool_id.clone(),
                reason: audit_error_code(&error),
            });
            true
        }
    }
}

/// Re-appends one receipted-but-missing carrier with a superseding receipt.
fn resolve_unknown_commit(
    ctx: &mut SpoolReconcileCtx<'_>,
    record: &mut AuditSpoolRecord,
    receipt: &AuditReconcileReceipt,
) -> bool {
    let Some(kind) = AuditEventKind::canonical(&record.kind) else {
        let _ = record.set_disposition(AuditSpoolDisposition::UnknownCommit);
        ctx.report.failed.push(AuditReconcileFailure {
            spool_id: record.spool_id.clone(),
            reason: "unknown_commit_unresolvable",
        });
        return true;
    };
    let draft = AuditEventDraft::from_parts(kind, record.lineage.clone(), record.body.clone());
    match ctx.chain.append(draft, ctx.now) {
        Ok(canonical) => {
            ctx.index
                .entry((
                    record.kind.clone(),
                    canonical.event_digest.clone(),
                    lineage_key(&record.lineage),
                ))
                .or_insert((canonical.seq, canonical.current_hash.clone()));
            if mint_settlement(
                ctx,
                record,
                AuditReconcileDisposition::UnknownCommitResolved,
                Some((canonical.seq, canonical.current_hash.as_str())),
                Some(receipt.receipt_id.as_str()),
            ) {
                ctx.report.unknown_commits_resolved += 1;
                return record
                    .set_disposition(AuditSpoolDisposition::Reconciled)
                    .is_ok();
            }
            true
        }
        Err(error) => {
            let _ = record.set_disposition(AuditSpoolDisposition::UnknownCommit);
            ctx.report.failed.push(AuditReconcileFailure {
                spool_id: record.spool_id.clone(),
                reason: audit_error_code(&error),
            });
            true
        }
    }
}

/// Mints one settlement receipt, recording it for this run.
fn mint_settlement(
    ctx: &mut SpoolReconcileCtx<'_>,
    record: &AuditSpoolRecord,
    disposition: AuditReconcileDisposition,
    canonical: Option<(u64, &str)>,
    prior_receipt_id: Option<&str>,
) -> bool {
    let chain_id = ctx.chain.chain_id().to_owned();
    let (canonical_seq, canonical_hash) = match canonical {
        Some((seq, hash)) => (Some(seq), Some(hash)),
        None => (None, None),
    };
    let receipt = AuditReconcileReceipt::mint(&ReceiptMint {
        spool_id: &record.spool_id,
        spool_hash: &record.record_hash,
        chain_id: &chain_id,
        canonical_seq,
        canonical_hash,
        disposition,
        prior_receipt_id,
        reconciled_at_ms: ctx.now,
    });
    let Ok(receipt) = receipt else {
        ctx.report.failed.push(AuditReconcileFailure {
            spool_id: record.spool_id.clone(),
            reason: "receipt_unhashable",
        });
        return false;
    };
    ctx.receipts
        .insert(record.spool_id.clone(), receipt.clone());
    ctx.new_receipts.push(receipt);
    true
}

/// Returns whether one receipted carrier still verifies in retained history.
fn carrier_verifies(records: &[AuditRecord], seq: Option<u64>, hash: Option<&str>) -> bool {
    let (Some(seq), Some(hash)) = (seq, hash) else {
        return false;
    };
    let Ok(index) = usize::try_from(seq.saturating_sub(1)) else {
        return false;
    };
    records
        .get(index)
        .is_some_and(|record| record.seq == seq && record.current_hash == hash)
}

/// Reconciles the control-slot record, if any.
fn reconcile_slot(ctx: &mut SpoolReconcileCtx<'_>, slot: SlotState) -> SlotOutcome {
    let mut record = match slot {
        SlotState::Empty => return SlotOutcome::Empty,
        SlotState::Unreadable => {
            ctx.report.slot_unparseable = true;
            return SlotOutcome::KeptOccupied;
        }
        SlotState::Occupied(record) => *record,
    };
    if record.disposition.is_terminal()
        && !ctx.receipts.contains_key(&record.spool_id)
        && record
            .set_disposition(AuditSpoolDisposition::Unreconciled)
            .is_err()
    {
        ctx.report.failed.push(AuditReconcileFailure {
            spool_id: record.spool_id.clone(),
            reason: "spool_record_unhashable",
        });
        return SlotOutcome::KeptOccupied;
    }
    reconcile_spool_record(ctx, &mut record);
    if !record.disposition.is_terminal() {
        return SlotOutcome::KeptOccupied;
    }
    if let Some(receipt) = ctx.receipts.get(&record.spool_id) {
        SlotOutcome::Cleared {
            spool_id: record.spool_id.clone(),
            receipt_id: receipt.receipt_id.clone(),
        }
    } else {
        ctx.report.failed.push(AuditReconcileFailure {
            spool_id: record.spool_id.clone(),
            reason: "slot_receipt_missing",
        });
        SlotOutcome::KeptOccupied
    }
}
