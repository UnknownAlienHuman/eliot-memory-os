//! Kernel-owned restore ports: durable ORS journal, isolated destination,
//! effect fence (issue #960, lane F).
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
//! implementing the accepted [`RestoreJournalPort`] seam over the committed
//! E-owned ORS journal surface (#957: `RedbRecoveryStore` exact-predecessor
//! compare-and-append plus idempotent replay, merged into this lane from the
//! M2 candidate), the constructed (never accepted)
//! [`KernelIsolatedDestination`], and the [`check_kernel_effect_fence`] gate.
//! There is no filesystem, in-memory, or no-op journal path here: the journal
//! substrate is a Kernel-owned separate redb file
//! (`kernel-restore-journal.redb`, mirroring the established
//! `doctor_recovery_ledger.rs` pattern) driven exclusively through the E
//! owner's committed row/table logic, so restore rows keep exactly one writer
//! and never share a handle with the operational store.
//!
//! Stream binding (lossless transaction/source/class/destination/fence
//! binding): one ORS stream per restore transaction (the stream key is the
//! accepted [`RestoreTransaction`](eliot_backup::RestoreTransaction)
//! identity, a pure function of plan, bundle, and context, hence stable
//! across resume). [`bind_plan_stream`](KernelRestoreJournal::bind_plan_stream)
//! binds the exact [`RestoreJournalStreamBinding`](eliot_ors::RestoreJournalStreamBinding)
//! once per transaction — identical rebinding replays, a conflicting rebinding
//! (notably a rotated writer fence) refuses instead of continuing the old
//! transaction under new authority. Every compare-and-swap appends one intent
//! row carrying the exact observed predecessor (or genesis `None`), then its
//! paired result row, then prunes resolved pairs to a small keep count so the
//! bounded ORS readback stays exact for arbitrarily large archives; the
//! coordinator's own revision still advances strictly `+1` per swap and the
//! per-key transaction never drifts. No success is reconstructed from counts
//! and no blind retry is possible.
//!
//! Capability cell: Kernel restore ownership (durable intent journal,
//! isolated destination admission, effect-fence gating). Read through the
//! restore receipt and evidence vocabulary.
//! Forbidden authority: no ORS row reinterpretation, no second database, no
//! backup phase rules, no epoch minting, no cutover, no activation/retirement
//! of any installation, no in-memory/no-op journal substitute in any path.

use std::path::{Path, PathBuf};

use eliot_backup::{
    BackupBundle, BackupClass, BackupError, RestoreJournalAdmission, RestoreJournalPort,
    RestoreJournalRecord, RestoreJournalState, RestorePhase, RestorePlan,
};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_ors::{
    JournalPredecessor, MAX_JOURNAL_PAGE_ENTRIES, MAX_JOURNAL_PAYLOAD_BYTES,
    RESTORE_JOURNAL_RECORD_SCHEMA, OrsError, RedbRecoveryStore, RestoreJournalArchiveClass,
    RestoreJournalOperation, RestoreJournalResult, RestoreJournalStreamBinding,
};

/// File name of the Kernel-owned durable restore journal below the canonical
/// work root. A separate database file from the operational ORS store, so
/// restore rows keep exactly one writer.
pub const RESTORE_JOURNAL_FILE_NAME: &str = "kernel-restore-journal.redb";
/// Stable identity of this journal for admission bindings. Composition must
/// place this identity in the admission it issues for this journal.
pub const RESTORE_JOURNAL_IDENTITY: &str = "kernel-restore-journal-v1";
/// Isolated-restore area below `<work_root>/.eliot`.
pub const RESTORE_ISOLATED_AREA: &str = "restore-isolated";
/// Resolved intent/result pairs retained per stream by pruning. The bounded
/// ORS readback only ever needs the tail; the pruned-prefix marker keeps
/// chain validation exact.
pub const RESTORE_JOURNAL_KEEP_RESOLVED: usize = 8;

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
    /// The durable journal could not be opened or written at the owner layer.
    JournalIo(String),
    /// No admitted journal is bound, or the bound admission is fixture-only;
    /// effects are refused, never substituted.
    JournalNotAdmitted,
    /// A journal row, binding, or file is corrupt, foreign, or incomplete.
    JournalCorrupt,
    /// The journal stream is already bound to a different transaction or
    /// binding; the old transaction never continues under new authority.
    JournalBindingConflict,
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
            Self::JournalBindingConflict => write!(
                formatter,
                "restore journal stream is bound to a different transaction or binding"
            ),
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

fn map_archive_class(class: BackupClass) -> RestoreJournalArchiveClass {
    match class {
        BackupClass::FullRecovery => RestoreJournalArchiveClass::FullRecovery,
        BackupClass::CanonicalOnlyDegraded => {
            RestoreJournalArchiveClass::CanonicalOnlyDegraded
        }
        BackupClass::ScopeExport => RestoreJournalArchiveClass::ScopeExport,
    }
}

fn journal_state_name(state: &RestoreJournalState) -> &'static str {
    match state {
        RestoreJournalState::Ready => "ready",
        RestoreJournalState::IntentPersisted => "intent-persisted",
        RestoreJournalState::ReceiptPersisted => "receipt-persisted",
        RestoreJournalState::Completed => "completed",
        RestoreJournalState::RollbackRequired => "rollback-required",
    }
}

/// Maps an owner-layer journal failure to the accepted seam error without
/// losing the causal class.
///
/// A predecessor mismatch means a foreign writer advanced the stream under
/// this adapter: the swap lost the race and reports a CAS conflict, never a
/// blind retry. A conflicting stream binding means a different transaction or
/// authority claims this stream: a journal mismatch, never a silent rebind.
/// Any other restore-journal integrity break is corruption; substrate
/// failures stay opaque transport errors.
fn map_ors_to_backup(error: OrsError) -> BackupError {
    match &error {
        OrsError::IntegrityProblem {
            record_type,
            reason,
        } if record_type.starts_with("restore_journal") && reason.contains("predecessor") => {
            BackupError::RestoreJournalCasConflict
        }
        OrsError::IntegrityProblem {
            record_type,
            reason,
        } if *record_type == "restore_journal_binding" || reason.contains("binding") => {
            BackupError::RestoreJournalMismatch
        }
        OrsError::IntegrityProblem { record_type, .. }
            if record_type.starts_with("restore_journal") =>
        {
            BackupError::RestoreJournalCorrupt
        }
        _ => BackupError::Target(error.to_string()),
    }
}

fn map_ors_to_kernel(error: OrsError) -> KernelRestoreError {
    match &error {
        OrsError::IntegrityProblem { .. } => KernelRestoreError::JournalCorrupt,
        _ => KernelRestoreError::JournalIo(error.to_string()),
    }
}

fn backup_to_kernel(error: BackupError) -> KernelRestoreError {
    match error {
        BackupError::RestoreJournalMismatch => KernelRestoreError::JournalBindingConflict,
        BackupError::RestoreJournalCorrupt => KernelRestoreError::JournalCorrupt,
        _ => KernelRestoreError::JournalIo(error.to_string()),
    }
}

fn kernel_to_backup(error: KernelRestoreError) -> BackupError {    match error {
        KernelRestoreError::JournalNotAdmitted | KernelRestoreError::JournalBindingConflict => {
            BackupError::RestoreJournalMismatch
        }
        KernelRestoreError::JournalCorrupt => BackupError::RestoreJournalCorrupt,
        KernelRestoreError::JournalIo(detail) => BackupError::Target(detail),
        KernelRestoreError::InvalidInput { field, reason } => {
            BackupError::InvalidField { field, reason }
        }
        KernelRestoreError::TargetFailed(inner) => inner,
        KernelRestoreError::DestinationInvalid(_)
        | KernelRestoreError::FenceMismatch(_)
        | KernelRestoreError::ArchiveInvalid(_)
        | KernelRestoreError::CapabilityMissing { .. }
        | KernelRestoreError::OwnerEvidenceInvalid(_) => {
            BackupError::Target(error.to_string())
        }
    }
}

/// One bound ORS stream: the stable stream key plus the exact binding every
/// append on it carries.
#[derive(Clone, Debug)]
struct BoundStream {
    stream: String,
    binding: RestoreJournalStreamBinding,
}

/// Kernel-owned durable restore journal over the committed ORS journal port.
///
/// Owns the separate redb file below the canonical work root and implements
/// the accepted [`RestoreJournalPort`] seam exclusively through the E-owned
/// row/table logic (`bind` / exact-predecessor `append` with idempotent
/// replay / bounded chain-validated `load` / paired `result` / `prune`).
/// Single writer: the Kernel restore coordinator is the only writer of this
/// file; the in-memory head is a lossy accelerator only — every swap
/// re-derives continuity from the durable tail when the cache is cold, and a
/// lost predecessor race reports [`RestoreJournalCasConflict`](BackupError::RestoreJournalCasConflict)
/// instead of retrying blindly. There is no `Default`, no in-memory
/// substitute, and no filesystem/JSON journal path: an unadmitted,
/// fixture-flagged, or unbound journal refuses effects
/// ([`JournalNotAdmitted`](KernelRestoreError::JournalNotAdmitted)) instead
/// of standing in for durability.
pub struct KernelRestoreJournal {
    store: RedbRecoveryStore,
    file: PathBuf,
    admission: Option<RestoreJournalAdmission>,
    bound: Option<BoundStream>,
    head: Option<(u64, String)>,
    head_record: Option<RestoreJournalRecord>,
}

impl std::fmt::Debug for KernelRestoreJournal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KernelRestoreJournal")
            .field("file", &self.file)
            .field("admission", &self.admission)
            .field("bound", &self.bound)
            .field("head", &self.head)
            .finish()
    }
}

impl KernelRestoreJournal {
    /// Opens (or creates) the Kernel-owned durable restore journal below
    /// `work_root` and ensures the versioned ORS journal schema.
    ///
    /// `work_root` is the canonical absolute Kernel work root from the
    /// authenticated Host launch contour (same pattern as the doctor recovery
    /// ledger), never a request value. A foreign schema identity refuses
    /// here so an old empty/incomplete journal can never read as complete.
    /// The journal starts unadmitted and unbound: [`admit`](Self::admit) must
    /// bind owner admission and
    /// [`bind_plan_stream`](Self::bind_plan_stream) the transaction stream
    /// before any restore executes against it.
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
        let file = work_root.join(RESTORE_JOURNAL_FILE_NAME);
        let store =
            RedbRecoveryStore::open(&file).map_err(|error| match &error {
                OrsError::IntegrityProblem { .. } => KernelRestoreError::JournalCorrupt,
                _ => KernelRestoreError::JournalIo(error.to_string()),
            })?;
        store
            .ensure_restore_journal_schema()
            .map_err(map_ors_to_kernel)?;
        Ok(Self {
            store,
            file,
            admission: None,
            bound: None,
            head: None,
            head_record: None,
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

    /// Binds one restore transaction stream with its exact ORS stream binding.
    ///
    /// Derives the stable stream key from the accepted transaction identity
    /// and the binding from the compiled plan, the validated bundle, the
    /// admitted writer, and the live writer fence. Binding is idempotent for
    /// the identical transaction context (resume replays it); a conflicting
    /// binding — including a rotated writer fence — refuses with
    /// [`JournalBindingConflict`](KernelRestoreError::JournalBindingConflict)
    /// so the old transaction never continues under new authority. Refreshes
    /// the head from the durable tail, so a resumed process observes the
    /// exact predecessor chain before its first swap.
    pub fn bind_plan_stream(
        &mut self,
        plan: &RestorePlan,
        bundle: &BackupBundle,
        writer_fence: &StateFence,
    ) -> Result<String, KernelRestoreError> {
        let admission = self
            .admission
            .as_ref()
            .ok_or(KernelRestoreError::JournalNotAdmitted)?;
        let transaction = plan
            .transaction()
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        let fence_bytes = canonical_json_bytes(writer_fence)
            .map_err(|error| KernelRestoreError::ArchiveInvalid(error.to_string()))?;
        let binding = RestoreJournalStreamBinding {
            transaction_id: transaction.transaction_id.clone(),
            source_archive_id: bundle.manifest.backup_id.clone(),
            archive_class: map_archive_class(bundle.manifest.class),
            destination_ref: plan.target.target_id.clone(),
            writer_id: admission.persistent_owner.owner_id.clone(),
            writer_fence_digest: sha256_hex(&fence_bytes),
        };
        binding
            .validate()
            .map_err(|error| KernelRestoreError::OwnerEvidenceInvalid(error.to_string()))?;
        let stream = transaction.transaction_id.clone();
        self.store
            .bind_restore_journal_stream(&stream, &binding)
            .map_err(|error| match &error {
                OrsError::IntegrityProblem { .. } => {
                    KernelRestoreError::JournalBindingConflict
                }
                _ => KernelRestoreError::JournalIo(error.to_string()),
            })?;
        self.bound = Some(BoundStream {
            stream: stream.clone(),
            binding,
        });
        self.refresh_head().map_err(backup_to_kernel)?;
        Ok(stream)
    }

    /// Stable journal file path (evidence + diagnostics reference).
    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.file
    }

    /// Returns the bound stream key, if bound.
    #[must_use]
    pub fn bound_stream(&self) -> Option<&str> {
        self.bound.as_ref().map(|bound| bound.stream.as_str())
    }

    /// Re-derives the head (sequence, digest) and cached tail record from
    /// the durable stream. Empty (bound, never swapped) streams clear the
    /// cache; the tail payload must decode as the accepted journal record or
    /// the stream is corrupt.
    fn refresh_head(&mut self) -> Result<(), BackupError> {
        let stream = self
            .bound
            .as_ref()
            .map(|bound| bound.stream.clone())
            .ok_or(BackupError::RestoreJournalRequired)?;
        let binding = self
            .store
            .load_restore_journal_binding(&stream)
            .map_err(map_ors_to_backup)?;
        match binding {
            None => {
                self.head = None;
                self.head_record = None;
                Ok(())
            }
            Some(stored) => {
                let expected = self
                    .bound
                    .as_ref()
                    .map(|bound| &bound.binding)
                    .ok_or(BackupError::RestoreJournalRequired)?;
                if stored != *expected {
                    return Err(BackupError::RestoreJournalMismatch);
                }
                let rows = self
                    .store
                    .load_restore_journal_stream(&stream, MAX_JOURNAL_PAGE_ENTRIES)
                    .map_err(map_ors_to_backup)?;
                match rows.last() {
                    None => {
                        self.head = None;
                        self.head_record = None;
                        Ok(())
                    }
                    Some(tail) => {
                        let record: RestoreJournalRecord =
                            serde_json::from_str(&tail.payload)
                                .map_err(|_| BackupError::RestoreJournalCorrupt)?;
                        let digest = tail.digest().map_err(map_ors_to_backup)?;
                        self.head = Some((tail.sequence, digest));
                        self.head_record = Some(record);
                        Ok(())
                    }
                }
            }
        }
    }

    fn phase_operation(state: &RestoreJournalState, phase: &RestorePhase) -> Result<String, BackupError> {
        let phase_bytes = canonical_json_bytes(phase)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        Ok(format!(
            "restore-{}-{}",
            journal_state_name(state),
            sha256_hex(&phase_bytes)
        ))
    }

    /// Appends one coordinator swap as an intent/result pair and prunes.
    ///
    /// The intent carries the exact observed predecessor (genesis `None`
    /// exactly for an empty stream), the lossless stream binding, and the
    /// request/body digests binding this exact swap; the paired result row
    /// answers it so pruning can compact resolved pairs while the
    /// pruned-prefix marker keeps readback linkage exact. An idempotent
    /// replay of the identical operation succeeds with the persisted receipt
    /// instead of duplicating.
    fn append_swap(
        &mut self,
        journal_key: &str,
        expected_revision: u64,
        next: &RestoreJournalRecord,
    ) -> Result<(), BackupError> {
        let (stream, binding) = self
            .bound
            .as_ref()
            .map(|bound| (bound.stream.clone(), bound.binding.clone()))
            .ok_or(BackupError::RestoreJournalRequired)?;
        if self.head.is_none() && self.head_record.is_none() {
            self.refresh_head()?;
        }
        match self.head_record.as_ref() {
            None => {
                if expected_revision != 0 {
                    return Err(BackupError::RestoreJournalCasConflict);
                }
            }
            Some(current) => {
                if current.revision != expected_revision {
                    return Err(BackupError::RestoreJournalCasConflict);
                }
                if current.transaction != next.transaction {
                    return Err(BackupError::RestoreJournalMismatch);
                }
            }
        }
        let predecessor = self.head.clone().map(|(sequence, digest)| JournalPredecessor {
            sequence,
            digest,
        });
        let payload_bytes = canonical_json_bytes(next)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let payload = String::from_utf8(payload_bytes.clone())
            .map_err(|_| BackupError::Serialization("restore journal payload is not UTF-8".to_owned()))?;
        if payload.len() > MAX_JOURNAL_PAYLOAD_BYTES {
            return Err(BackupError::LimitExceeded {
                field: "restore.journal_payload",
                limit: MAX_JOURNAL_PAYLOAD_BYTES,
            });
        }
        let payload_sha256 = sha256_hex(&payload_bytes);
        let phase_operation = Self::phase_operation(&next.state, &next.phase)?;
        let request_bytes = canonical_json_bytes(&(
            journal_key,
            expected_revision,
            next.revision,
            next.transaction.transaction_id.as_str(),
        ))
        .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let operation = RestoreJournalOperation {
            transaction_id: next.transaction.transaction_id.clone(),
            source_archive_id: binding.source_archive_id.clone(),
            archive_class: binding.archive_class,
            destination_ref: binding.destination_ref.clone(),
            writer_id: binding.writer_id.clone(),
            writer_fence_digest: binding.writer_fence_digest.clone(),
            record_schema: RESTORE_JOURNAL_RECORD_SCHEMA.to_owned(),
            phase_operation: phase_operation.clone(),
            request_digest: sha256_hex(&request_bytes),
            body_digest: payload_sha256.clone(),
            expected_predecessor: predecessor,
            payload_handle: format!("restore-row:{journal_key}:{expected_revision}"),
        };
        let receipt = self
            .store
            .append_restore_journal_intent(&stream, &operation, &payload_sha256, &payload)
            .map_err(map_ors_to_backup)?;
        let result = RestoreJournalResult {
            transaction_id: operation.transaction_id.clone(),
            phase_operation,
            intent_sequence: receipt.sequence,
            receipt_sha256: payload_sha256,
            receipt: payload,
        };
        self.store
            .append_restore_journal_result(&stream, &result)
            .map_err(map_ors_to_backup)?;
        self.store
            .prune_restore_journal(&stream, RESTORE_JOURNAL_KEEP_RESOLVED)
            .map_err(map_ors_to_backup)?;
        self.head = Some((receipt.sequence, receipt.record_digest));
        self.head_record = Some(next.clone());
        Ok(())
    }
}

impl RestoreJournalPort for KernelRestoreJournal {
    fn load(&mut self, journal_key: &str) -> Result<Option<RestoreJournalRecord>, BackupError> {
        let _ = journal_key;
        if self.bound.is_none() {
            return Ok(None);
        }
        self.refresh_head()?;
        Ok(self.head_record.clone())
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
        if self.bound.is_none() {
            return Err(kernel_to_backup(KernelRestoreError::JournalNotAdmitted));
        }
        self.append_swap(journal_key, expected_revision, &next)
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
