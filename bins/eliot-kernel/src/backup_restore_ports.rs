//! Kernel-owned restore ports: durable journal, isolated destination, effect fence
//! (issue #960, lane F first production slice).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (restore executes in
//! an isolated area; cutover needs separate authority; old sessions, leases,
//! approvals, and epochs do not revive); A13.6 Operational Recovery State
//! (only identities, opaque envelopes, epochs, suspended leases, checkpoints,
//! intents, manifests, anchors — never semantic claims); I5.13 backup classes
//! and purge-first isolated restore; I14.21 unknown-commit recovery (reconcile
//! by identity, never blind retry); A12.3 one governed write path (no second
//! writer, no database-protocol bypass).
//! Implementation: I5.16 common durable fields (explicit identity, fence,
//! schema, digests); I5.19 intent-before-effect ordering (every target effect
//! is preceded by a journaled intent); I5.27 canonical operation identity
//! (idempotency over canonical bytes; database idempotency and external-effect
//! idempotency stay separate).
//!
//! What this file owns: the Kernel-owned durable [`KernelRestoreJournal`]
//! implementing the accepted [`RestoreJournalPort`] seam with revision-checked
//! compare-and-swap, the constructed (never accepted)
//! [`KernelIsolatedDestination`], and the [`check_kernel_effect_fence`] gate.
//! The journal substrate here is a single-writer file below the canonical work
//! root (atomic temp-write + rename + fsync), following the established
//! Kernel-owned owner pattern (`doctor_recovery_ledger.rs` over a separate
//! store file with exactly one writer).
//!
//! Binding to the durable ORS journal surface (#957, E-owned): the accepted
//! [`RestoreJournalPort::compare_and_swap`] expected revision is propagated
//! losslessly to the substrate check — exact equality, genesis exactly at
//! zero, strictly monotone `+1` advance, per-key transaction continuity — so
//! no success is reconstructed from counts and no blind retry is possible.
//! The stream-binding vocabulary this journal enforces per key (transaction,
//! source archive, class, destination, writer fence) maps field-for-field to
//! the E-owned ORS surface (donor PR2375 SHA
//! `48d50308c2f5dac4f67bc25e10df048866ad8e8c`, read-only reference:
//! `crates/kernel/eliot-ors/src/restore_journal.rs`
//! `RestoreJournalStreamBinding { transaction_id, source_archive_id,
//! archive_class, destination_ref, writer_id, writer_fence_digest }` and
//! `store/restore_journal.rs` exact-predecessor compare-and-append on
//! `RedbRecoveryStore`). That surface does not exist at this lane's base and
//! is owned by the E child: this file neither imports it nor duplicates it.
//! The #962 turn binds the actual ORS-backed port over these same values
//! (transaction from [`eliot_backup::RestoreTransaction`], source archive and
//! class from the bundle manifest, destination from [`eliot_backup::RestoreContext`],
//! writer fence digest from the admitted [`StateFence`]); until then the
//! production gate ([`KernelRestoreJournal::require_production_admitted`])
//! refuses fixture-flagged admission and there is no in-memory substitute.
//!
//! Capability cell: Kernel restore ownership (durable intent journal,
//! isolated destination admission, effect-fence gating). Read through the
//! restore receipt and evidence vocabulary.
//! Forbidden authority: no ORS row reinterpretation, no second database, no
//! backup phase rules, no epoch minting, no cutover, no activation/retirement
//! of any installation, no in-memory/no-op journal substitute in production
//! paths.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_backup::{
    BackupBundle, BackupError, RestoreJournalAdmission, RestoreJournalPort, RestoreJournalRecord,
};
use eliot_contracts::StateFence;

/// Directory below `<work_root>/.eliot` holding the Kernel restore journal.
pub const RESTORE_JOURNAL_DIR_NAME: &str = "kernel-restore-journal";
/// Journal file holding every `journal_key -> record` row.
pub const RESTORE_JOURNAL_FILE_NAME: &str = "journal.json";
/// Stable identity of this journal for admission bindings.
pub const RESTORE_JOURNAL_IDENTITY: &str = "kernel-restore-journal-v1";
/// Owner identity naming the Kernel restore journal.
pub const RESTORE_JOURNAL_OWNER_ID: &str = "kernel-restore-owner";
/// Isolated-restore area below `<work_root>/.eliot`.
pub const RESTORE_ISOLATED_AREA: &str = "restore-isolated";

/// Typed fail-closed errors for the Kernel restore owner.
///
/// Every variant refuses an effect or an admission; none fabricates success.
/// The primary cause is preserved: coordinator failures cross the seam typed
/// in [`KernelRestoreError::TargetFailed`], never flattened before the owner
/// can attribute them.
#[derive(Clone, Debug, PartialEq)]
pub enum KernelRestoreError {
    /// A caller-supplied field is malformed.
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    /// The durable journal could not be read or written.
    JournalIo(String),
    /// No admitted journal is bound, or the bound admission is fixture-only;
    /// effects are refused, never substituted.
    JournalNotAdmitted,
    /// A journal row or file is corrupt or incomplete.
    JournalCorrupt,
    /// The isolated destination is invalid or escapes the work root.
    DestinationInvalid(String),
    /// The Kernel fence does not admit this archive.
    FenceMismatch(String),
    /// The archive or its class denominator is invalid.
    ArchiveInvalid(String),
    /// A required owner capability is absent; the effect is refused.
    CapabilityMissing { capability: &'static str },
    /// Owner-issued evidence is invalid or does not advance observed lineage.
    OwnerEvidenceInvalid(String),
    /// The journaled restore engine reported a typed failure.
    TargetFailed(BackupError),
}

impl std::fmt::Display for KernelRestoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::JournalIo(detail) => write!(formatter, "restore journal io: {detail}"),
            Self::JournalNotAdmitted => {
                write!(
                    formatter,
                    "restore journal is not admitted for production; effects refused"
                )
            }
            Self::JournalCorrupt => write!(formatter, "restore journal record is corrupt"),
            Self::DestinationInvalid(detail) => {
                write!(formatter, "isolated destination invalid: {detail}")
            }
            Self::FenceMismatch(detail) => {
                write!(formatter, "kernel fence does not admit archive: {detail}")
            }
            Self::ArchiveInvalid(detail) => {
                write!(formatter, "restore archive invalid: {detail}")
            }
            Self::CapabilityMissing { capability } => {
                write!(formatter, "required owner capability absent: {capability}")
            }
            Self::OwnerEvidenceInvalid(detail) => {
                write!(formatter, "owner-issued restore evidence invalid: {detail}")
            }
            Self::TargetFailed(error) => write!(formatter, "restore target failed: {error}"),
        }
    }
}

impl std::error::Error for KernelRestoreError {}

fn non_blank(value: &str, field: &'static str) -> Result<(), KernelRestoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(KernelRestoreError::InvalidInput {
            field,
            reason: "must be non-blank with no control characters",
        });
    }
    Ok(())
}

/// Requires the archive fence to be compatible with the Kernel effect fence
/// before any restore effect.
///
/// Compatibility is the accepted [`StateFence::is_compatible_with`] exact
/// `(lineage_id, sequence)` tuple plus generation equality: equal sequences
/// from different lineages are unrelated and refuse, and a rotated live fence
/// never admits effects under a stale restore authority. The production
/// caller supplies the live fence; this gate performs no caller arithmetic.
pub fn check_kernel_effect_fence(
    kernel_fence: &StateFence,
    bundle: &BackupBundle,
) -> Result<(), BackupError> {
    if bundle
        .export_fence
        .state_fence
        .is_compatible_with(kernel_fence)
    {
        Ok(())
    } else {
        Err(BackupError::FenceMismatch {
            subject: "kernel effect fence".to_owned(),
        })
    }
}

/// Kernel-owned durable restore journal.
///
/// Owns one journal file below the canonical work root and implements the
/// accepted [`RestoreJournalPort`] seam with atomic temp-write + rename +
/// fsync persistence and lossless revision-checked compare-and-swap. Single
/// writer: the Kernel restore coordinator is the only writer; the handle
/// keeps no process-local row cache, so reopening observes durable state.
/// There is no `Default`, no in-memory substitute, and no production
/// fallback: an unadmitted or fixture-flagged journal refuses effects
/// ([`JournalNotAdmitted`](KernelRestoreError::JournalNotAdmitted)) instead
/// of standing in for durability.
///
/// Compare-and-swap binds, losslessly, the exact expected predecessor the
/// coordinator observed: the stored revision must equal the expected
/// revision, the stored transaction must equal the incoming transaction
/// (cross-transaction clobbering through one handle refuses as a journal
/// mismatch), and the incoming revision must advance exactly `+1`. Genesis
/// binds exactly at revision zero.
#[derive(Debug)]
pub struct KernelRestoreJournal {
    dir: PathBuf,
    file: PathBuf,
    admission: Option<RestoreJournalAdmission>,
}

static JOURNAL_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl KernelRestoreJournal {
    /// Opens (or creates) the Kernel restore journal below `work_root`.
    ///
    /// `work_root` is the canonical absolute Kernel work root from the
    /// authenticated Host launch contour (same pattern as the doctor recovery
    /// ledger), never a request value. The journal starts unadmitted:
    /// [`admit`](Self::admit) must bind owner admission before any restore
    /// executes against it.
    pub fn open(work_root: &Path) -> Result<Self, KernelRestoreError> {
        if !work_root.is_absolute() {
            return Err(KernelRestoreError::InvalidInput {
                field: "restore.work_root",
                reason: "the restore journal root must be absolute",
            });
        }
        if !work_root.is_dir() {
            return Err(KernelRestoreError::InvalidInput {
                field: "restore.work_root",
                reason: "the restore journal root must be an existing directory",
            });
        }
        let dir = work_root.join(".eliot").join(RESTORE_JOURNAL_DIR_NAME);
        std::fs::create_dir_all(&dir)
            .map_err(|error| KernelRestoreError::JournalIo(error.to_string()))?;
        Ok(Self {
            file: dir.join(RESTORE_JOURNAL_FILE_NAME),
            dir,
            admission: None,
        })
    }

    /// Binds owner admission to this journal handle.
    ///
    /// Accepts any structurally valid admission, fixture-flagged included;
    /// production versus rehearsal is decided at execution by
    /// [`require_production_admitted`](Self::require_production_admitted)
    /// through [`RestoreJournalAdmission::admits_production_durable_recovery`].
    /// The admission value is owner-supplied, never minted here.
    pub fn admit(&mut self, admission: RestoreJournalAdmission) -> Result<(), KernelRestoreError> {
        admission
            .validate()
            .map_err(|error| KernelRestoreError::OwnerEvidenceInvalid(error.to_string()))?;
        self.admission = Some(admission);
        Ok(())
    }

    /// Returns whether owner admission is bound.
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        self.admission.is_some()
    }

    /// Returns the bound admission, if any.
    #[must_use]
    pub fn admission(&self) -> Option<&RestoreJournalAdmission> {
        self.admission.as_ref()
    }

    /// Requires production-grade admission before an effect.
    ///
    /// Refuses both the unadmitted handle and a fixture-flagged admission:
    /// a fixture proves adapter mapping only and never backs a production
    /// durable-recovery claim.
    pub fn require_production_admitted(&self) -> Result<(), KernelRestoreError> {
        match self.admission.as_ref() {
            Some(admission) if admission.admits_production_durable_recovery() => Ok(()),
            _ => Err(KernelRestoreError::JournalNotAdmitted),
        }
    }

    /// Stable journal file path (evidence + diagnostics reference).
    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.file
    }

    fn read_all(&self) -> Result<BTreeMap<String, RestoreJournalRecord>, KernelRestoreError> {
        if !self.file.exists() {
            return Ok(BTreeMap::new());
        }
        let bytes = std::fs::read(&self.file)
            .map_err(|error| KernelRestoreError::JournalIo(error.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|_| KernelRestoreError::JournalCorrupt)
    }

    fn write_all(
        &self,
        map: &BTreeMap<String, RestoreJournalRecord>,
    ) -> Result<(), KernelRestoreError> {
        let bytes = serde_json::to_vec(map)
            .map_err(|error| KernelRestoreError::JournalIo(error.to_string()))?;
        let counter = JOURNAL_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = self.dir.join(format!(
            ".journal.json.tmp-{}-{counter}",
            std::process::id()
        ));
        std::fs::write(&tmp, &bytes)
            .map_err(|error| KernelRestoreError::JournalIo(error.to_string()))?;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&tmp)
            .and_then(|file| file.sync_all())
            .map_err(|error| KernelRestoreError::JournalIo(error.to_string()))?;
        std::fs::rename(&tmp, &self.file)
            .map_err(|error| KernelRestoreError::JournalIo(error.to_string()))?;
        Ok(())
    }
}

impl RestoreJournalPort for KernelRestoreJournal {
    fn load(&mut self, journal_key: &str) -> Result<Option<RestoreJournalRecord>, BackupError> {
        // Error type is fixed by the accepted seam; map without losing the
        // primary cause so resume decisions stay exact.
        let map = self
            .read_all()
            .map_err(|error| BackupError::Target(error.to_string()))?;
        Ok(map.get(journal_key).cloned())
    }

    fn compare_and_swap(
        &mut self,
        journal_key: &str,
        expected_revision: u64,
        next: RestoreJournalRecord,
    ) -> Result<(), BackupError> {
        if next.journal_key != journal_key {
            return Err(BackupError::RestoreJournalMismatch);
        }
        let Some(next_revision) = expected_revision.checked_add(1) else {
            return Err(BackupError::RestoreJournalCorrupt);
        };
        if next.revision != next_revision {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        let mut map = self
            .read_all()
            .map_err(|error| BackupError::Target(error.to_string()))?;
        match map.get(journal_key) {
            Some(current) => {
                if current.revision != expected_revision {
                    return Err(BackupError::RestoreJournalCasConflict);
                }
                if current.transaction != next.transaction {
                    return Err(BackupError::RestoreJournalMismatch);
                }
            }
            None => {
                if expected_revision != 0 {
                    return Err(BackupError::RestoreJournalCasConflict);
                }
            }
        }
        map.insert(journal_key.to_owned(), next);
        self.write_all(&map)
            .map_err(|error| BackupError::Target(error.to_string()))
    }
}

/// Kernel-owned isolated restore destination.
///
/// The root is CONSTRUCTED below the canonical work root
/// (`<work_root>/.eliot/restore-isolated/<label>`), never accepted as an
/// arbitrary path, so it cannot escape to production state by construction.
/// Labels are restricted to ASCII alphanumeric/dash/underscore. Operational
/// store files live outside the restore area, and the destination carries no
/// live authority: it starts empty (fresh) or resumes an admitted restore.
#[derive(Clone, Debug)]
pub struct KernelIsolatedDestination {
    root: PathBuf,
    label: String,
}

impl KernelIsolatedDestination {
    /// Opens (creating) the isolated destination for `label`.
    pub fn open(work_root: &Path, label: &str) -> Result<Self, KernelRestoreError> {
        Self::validate_work_root(work_root)?;
        Self::validate_label(label)?;
        let root = work_root
            .join(".eliot")
            .join(RESTORE_ISOLATED_AREA)
            .join(label);
        if !root.starts_with(work_root) {
            return Err(KernelRestoreError::DestinationInvalid(
                "isolated destination escapes the work root".to_owned(),
            ));
        }
        std::fs::create_dir_all(&root)
            .map_err(|error| KernelRestoreError::DestinationInvalid(error.to_string()))?;
        Ok(Self {
            root,
            label: label.to_owned(),
        })
    }

    /// Opens an existing isolated destination for resume.
    pub fn open_existing(root: PathBuf, work_root: &Path) -> Result<Self, KernelRestoreError> {
        Self::validate_work_root(work_root)?;
        if !root.starts_with(work_root.join(".eliot").join(RESTORE_ISOLATED_AREA)) {
            return Err(KernelRestoreError::DestinationInvalid(
                "resume root is outside the isolated restore area".to_owned(),
            ));
        }
        if !root.is_dir() {
            return Err(KernelRestoreError::DestinationInvalid(
                "resume root must be an existing directory".to_owned(),
            ));
        }
        let label = root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                KernelRestoreError::DestinationInvalid("resume label is not valid".to_owned())
            })?
            .to_owned();
        Self::validate_label(&label)?;
        Ok(Self { root, label })
    }

    fn validate_work_root(work_root: &Path) -> Result<(), KernelRestoreError> {
        if !work_root.is_absolute() {
            return Err(KernelRestoreError::InvalidInput {
                field: "restore.work_root",
                reason: "the work root must be absolute",
            });
        }
        if !work_root.is_dir() {
            return Err(KernelRestoreError::InvalidInput {
                field: "restore.work_root",
                reason: "the work root must be an existing directory",
            });
        }
        Ok(())
    }

    fn validate_label(label: &str) -> Result<(), KernelRestoreError> {
        if label.is_empty()
            || label.len() > 64
            || label
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        {
            return Err(KernelRestoreError::InvalidInput {
                field: "restore.destination_label",
                reason: "label must be 1-64 ASCII alphanumeric, dash, or underscore",
            });
        }
        non_blank(label, "restore.destination_label")
    }

    /// Destination root path.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Destination label; restore binds it to the plan target id.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}
