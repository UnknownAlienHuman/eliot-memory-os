//! Kernel-owned durable restore journal and isolated destination (issue #960).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (restore executes in
//! an isolated area; cutover needs separate authority; old sessions, leases,
//! approvals, and epochs do not revive); A13.6 Operational Recovery State
//! (only operation identity, opaque envelopes, epochs, suspended leases,
//! checkpoints, intents, manifests, anchors may be stored); I5.13 backup
//! classes and purge-first isolated restore; I14.21 unknown-commit recovery
//! (no blind duplicate effect — reconcile by identity).
//! Implementation: single-writer file-durable CAS journal below the Kernel
//! work root (atomic temp-write + rename + fsync; revision-checked
//! compare-and-swap); temp-dir restores stay in the rehearsal runner.
//! Health reading: journal/destination open failures surface as typed errors
//! and degrade only the restore capability, never unrelated Kernel work.
//! Failure containment: I14.24 (a broken journal refuses effects, it never
//! fabricates success or falls back to memory).
//!
//! Capability cell: Kernel restore ownership (durable intent/result journal,
//! isolated destination admission). Read through the restore receipt and
//! evidence vocabulary. Forbidden authority: no ORS row reinterpretation, no
//! second database, no backup phase rules, no epoch minting, no cutover,
//! no in-memory/no-op journal substitute in production paths.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_backup::{
    BackupError, RestoreJournalAdmission, RestoreJournalPort, RestoreJournalRecord,
};

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelRestoreError {
    /// A caller-supplied field is malformed.
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    /// The durable journal could not be read or written.
    JournalIo(String),
    /// A journal compare-and-swap lost to a newer revision.
    JournalConflict,
    /// No admitted journal is bound; effects are refused, never substituted.
    JournalNotAdmitted,
    /// A journal row or file is corrupt or incomplete.
    JournalCorrupt,
    /// The isolated destination is invalid or escapes the work root.
    DestinationInvalid(String),
    /// The destination does not belong to this restore target.
    DestinationMismatch,
    /// The Kernel fence does not admit this archive.
    FenceMismatch(String),
    /// The archive or its class denominator is invalid.
    ArchiveInvalid(String),
    /// A required owner capability is absent; the effect is refused.
    CapabilityMissing { capability: &'static str },
    /// Owner-issued evidence is invalid or does not advance observed lineage.
    OwnerEvidenceInvalid(String),
    /// The isolated target failed an effect.
    TargetFailed(String),
    /// Plan, bundle, journal, or destination identity drifted mid-restore.
    PlanMismatch,
}

impl std::fmt::Display for KernelRestoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::JournalIo(detail) => write!(formatter, "restore journal io: {detail}"),
            Self::JournalConflict => write!(formatter, "restore journal CAS revision is stale"),
            Self::JournalNotAdmitted => {
                write!(
                    formatter,
                    "restore journal is not admitted; effects refused"
                )
            }
            Self::JournalCorrupt => write!(formatter, "restore journal record is corrupt"),
            Self::DestinationInvalid(detail) => {
                write!(formatter, "isolated destination invalid: {detail}")
            }
            Self::DestinationMismatch => {
                write!(
                    formatter,
                    "isolated destination does not belong to this target"
                )
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
            Self::TargetFailed(detail) => write!(formatter, "restore target failed: {detail}"),
            Self::PlanMismatch => write!(formatter, "restore plan does not match bundle"),
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

/// Kernel-owned durable restore journal.
///
/// Owns one journal file below the canonical work root and implements the
/// accepted [`RestoreJournalPort`] seam with atomic temp-write + rename +
/// fsync persistence and revision-checked compare-and-swap. Single writer:
/// the Kernel restore coordinator is the only writer; the handle keeps no
/// process-local row cache, so reopening observes durable state. There is no
/// `Default`, no in-memory substitute, and no production fallback: an
/// unadmitted journal refuses effects (`JournalNotAdmitted`) instead of
/// standing in for durability.
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
    /// callers distinguish rehearsal from production through
    /// [`RestoreJournalAdmission::admits_production_durable_recovery`]. The
    /// admission value is owner-supplied, never minted here.
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

    /// Requires bound admission before an effect; refuses otherwise.
    pub fn require_admitted(&self) -> Result<(), KernelRestoreError> {
        if self.is_admitted() {
            Ok(())
        } else {
            Err(KernelRestoreError::JournalNotAdmitted)
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
        let mut map = self
            .read_all()
            .map_err(|error| BackupError::Target(error.to_string()))?;
        match map.get(journal_key) {
            Some(current) if current.revision != expected_revision => {
                return Err(BackupError::RestoreJournalCasConflict);
            }
            None if expected_revision != 0 => {
                return Err(BackupError::RestoreJournalCasConflict);
            }
            _ => {}
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
