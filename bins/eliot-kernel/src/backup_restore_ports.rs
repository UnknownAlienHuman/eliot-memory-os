//! Kernel-owned restore ports: durable-journal admission, isolated destination,
//! effect fence (issue #960).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (restore executes in
//! an isolated area; cutover needs separate authority; old sessions, leases,
//! approvals, and epochs do not revive); A13.6 Operational Recovery State
//! (only identities, opaque envelopes, epochs, suspended leases, checkpoints,
//! intents, manifests, anchors — never semantic claims); I5.13 backup classes
//! and purge-first isolated restore; I14.21 unknown-commit recovery (reconcile
//! by identity, never blind retry); A12.3 one governed write path (no second
//! writer, no database-protocol bypass); I14.3 Control Reserve (recovery lanes
//! keep bounded budgets; restore work is bounded and never consumes the
//! control reserve silently).
//! Implementation: I5.16 common durable fields (explicit identity, fence,
//! schema, digests); I5.19 intent-before-effect ordering (every target effect
//! is preceded by a journaled intent); I5.27 canonical operation identity
//! (idempotency over canonical bytes; database idempotency and external-effect
//! idempotency stay separate); I7.20 agent-facing error contract (typed
//! refusals with exact reason, never silence or fabricated success).
//!
//! What this file owns: the journal-admission gate
//! ([`require_production_admitted`]), the per-execution port bundle
//! ([`RestorePorts`]), the constructed (never accepted)
//! [`KernelIsolatedDestination`], the pinned destination admission record,
//! the [`check_kernel_effect_fence`] gate, and the fail-closed
//! [`KernelRestoreError`] vocabulary with lossless mapping to the accepted
//! [`BackupError`](eliot_backup::BackupError) seam.
//!
//! What this file deliberately does NOT own: a journal implementation. There
//! is no in-memory, filesystem-JSON, or no-op journal here. It owns only the
//! **adapter** onto the one admitted persistent owner: [`OrsRestoreJournal`]
//! maps the accepted `load`/`compare_and_swap` seam onto #957's durable ORS
//! restore journal ([`RedbRecoveryStore`]) and owns no ORS row meaning, no
//! second database, and no journal state machine. The coordinator
//! ([`KernelBackupRestore`](super::backup_restore::KernelBackupRestore),
//! registered by the #959 turn) still takes the journal as a required
//! parameter with no `Default` and no fallback constructor, so production
//! cannot introduce a substitute by construction: an unadmitted or
//! fixture-flagged admission refuses effects
//! ([`JournalNotAdmitted`](KernelRestoreError::JournalNotAdmitted)) instead of
//! standing in for durability.
//!
//! The adapter is the seam #960 contributes and #957 depends on. `eliot-ors`
//! must not depend on `eliot-backup` (the ORS-to-backup edge is forbidden), so
//! `impl RestoreJournalPort for RedbRecoveryStore` cannot live in `eliot-ors`.
//! `eliot-kernel` depends on both owners, so the mapping lives here, in the
//! file the issue scopes to "minimal adapters to the accepted
//! RestoreTarget/RestoreJournalPort only".
//!
//! Capability cell: Kernel restore ownership (journal admission, isolated
//! destination admission, effect-fence gating). Read through the restore
//! receipt and evidence vocabulary.
//! Forbidden authority: no ORS row interpretation, no second database, no
//! backup phase rules, no epoch minting, no cutover, no activation/retirement
//! of any installation, no in-memory/no-op journal substitute in any path.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_backup::{
    BackupBundle, BackupError, RestoreJournalAdmission, RestoreJournalPort, RestoreJournalRecord,
    RestoreJournalState,
};
use eliot_contracts::{StateFence, sha256_hex};
use eliot_ors::{
    EpochIdentity, EpochLineage, JournalPredecessor, MAX_JOURNAL_PAGE_ENTRIES,
    MAX_JOURNAL_PAYLOAD_BYTES, MAX_JOURNAL_STREAM_KEY_BYTES, OpaqueLabel, OrsError,
    RESTORE_JOURNAL_RECORD_SCHEMA, RecoveryAccessClass, RecoveryEnvelopeContext,
    RecoveryPayloadEnvelope, RedbRecoveryStore, RestoreJournalArchiveClass, RestoreJournalEntry,
    RestoreJournalOperation, RestoreJournalResult, RestoreJournalStreamBinding, StateFenceSnapshot,
};
use eliot_platform::PlatformHandle;
use eliot_security_contracts::PrivacyClass;

/// Stable identity of the restore-journal stream namespace for admission
/// bindings. Composition must place this identity in the admission it issues
/// for the restore streams owned by the operational ORS database (#957).
pub const RESTORE_JOURNAL_IDENTITY: &str = "kernel-restore-journal-v1";
/// Owner label identifying the operational ORS database behind restore
/// streams (evidence + diagnostics reference). The rows live in the
/// Kernel-owned operational ORS file; this label names that owner, never a
/// second database.
pub const RESTORE_JOURNAL_OWNER_LABEL: &str = "kernel-operational-ors";
/// Isolated-restore area below `<work_root>/.eliot`.
pub const RESTORE_ISOLATED_AREA: &str = "restore-isolated";
/// Content-addressed sealed journal-payload area below `<work_root>/.eliot`.
///
/// The ORS journal rows carry a locator into this area rather than the
/// journaled record body. ORS deliberately does not fetch or hash a locator
/// target, so [`OrsRestoreJournal`] verifies the declared length and SHA-256
/// on every read before the bytes are parsed.
pub const RESTORE_JOURNAL_PAYLOAD_AREA: &str = "restore-journal-payloads";
/// File name of the pinned destination admission inside the isolated root.
pub const DESTINATION_ADMISSION_FILE: &str = "destination-admission.json";
/// File name of the finalized restore evidence inside the isolated root.
pub const RESTORE_EVIDENCE_FILE: &str = "evidence.json";
/// Maximum destination label length (bounded identities, I14.3).
pub const MAX_DESTINATION_LABEL_LEN: usize = 64;

/// Kernel-side destination manifest evidence: the digest projection of the
/// Host-issued owner binding every isolated destination must carry.
///
/// The issuing owner is the Host-side manifest binding (#958): the active
/// manifest's config digest, the digest of the manifest-bound runtime roots,
/// and the registry revision observed at inspection time. The Host roots type
/// itself stays untouchable here: this struct carries only the verifiable
/// projection — the two digests, the revision, and the Kernel work root the
/// destination must live under — and never the Host roots type. This is not
/// a competing binding struct: it names the Host binding as its issuer and
/// cannot substitute for it.
///
/// Binding rule enforced by the restore owner: digests must be 64-hex; the
/// admitted work root must canonicalize-equal the Kernel's own work root
/// (never caller text); when the archive carries a `config` artifact, the
/// admitted manifest digest must equal that artifact's digest; the admitted
/// values pin to [`DESTINATION_ADMISSION_FILE`] at prepare and any drift
/// refuses later effects. Rehearsal without Host admission carries `None`
/// instead: isolated import still runs, but cutover refuses without a
/// pinned owner-approved admission.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationManifestEvidence {
    /// Owner config digest of the active manifest (hex64).
    pub manifest_digest: String,
    /// Digest of the manifest-bound runtime roots (hex64).
    pub roots_digest: String,
    /// Registry revision observed at inspection time.
    pub registry_revision: u64,
    /// Kernel work root the destination must live under.
    pub kernel_work_root: PathBuf,
}

impl DestinationManifestEvidence {
    /// Validates shapes and the admitted root. Cross-checks against the
    /// Kernel-owned work root and the archive happen at restore entry, not
    /// here: this validates the evidence itself.
    pub fn validate(&self) -> Result<(), KernelRestoreError> {
        if !is_hex64(&self.manifest_digest) {
            return Err(KernelRestoreError::InvalidInput {
                field: "restore.manifest_digest",
                reason: "must be a 64-hex digest",
            });
        }
        if !is_hex64(&self.roots_digest) {
            return Err(KernelRestoreError::InvalidInput {
                field: "restore.roots_digest",
                reason: "must be a 64-hex digest",
            });
        }
        if !self.kernel_work_root.is_absolute() {
            return Err(KernelRestoreError::InvalidInput {
                field: "restore.kernel_work_root",
                reason: "the admitted work root must be absolute",
            });
        }
        if !self.kernel_work_root.is_dir() {
            return Err(KernelRestoreError::InvalidInput {
                field: "restore.kernel_work_root",
                reason: "the admitted work root must be an existing directory",
            });
        }
        Ok(())
    }
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

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
    /// Cutover requires a separate Human/System Owner authorization, which
    /// was absent. Rehearsal never activates or retires.
    CutoverNotAuthorized,
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
            Self::CutoverNotAuthorized => write!(
                formatter,
                "cutover requires a separate Human/System Owner authorization"
            ),
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

/// Maps an accepted seam failure to the Kernel owner vocabulary without
/// losing the causal class.
///
/// A journal mismatch means a different transaction or authority claims the
/// stream: a binding conflict, never a silent rebind. Corruption stays
/// corruption; every other engine failure crosses typed as
/// [`KernelRestoreError::TargetFailed`] with its primary cause preserved.
pub fn backup_to_kernel(error: BackupError) -> KernelRestoreError {
    match error {
        BackupError::RestoreJournalMismatch => KernelRestoreError::JournalBindingConflict,
        BackupError::RestoreJournalCorrupt => KernelRestoreError::JournalCorrupt,
        _ => KernelRestoreError::TargetFailed(error),
    }
}

/// Maps a Kernel owner refusal onto the accepted seam for journal-adjacent
/// callers. Owner refusals that name an exact accepted variant keep it;
/// admission, destination, fence, archive, capability, and evidence refusals
/// cross as typed target failures with their exact reason preserved.
pub fn kernel_to_backup(error: KernelRestoreError) -> BackupError {
    match error {
        KernelRestoreError::JournalNotAdmitted | KernelRestoreError::JournalBindingConflict => {
            BackupError::RestoreJournalMismatch
        }
        KernelRestoreError::JournalCorrupt => BackupError::RestoreJournalCorrupt,
        KernelRestoreError::JournalIo(detail) => BackupError::Target(detail),
        KernelRestoreError::InvalidInput { field, reason } => {
            BackupError::InvalidField { field, reason }
        }
        KernelRestoreError::TargetFailed(inner) => inner,
        KernelRestoreError::CutoverNotAuthorized => BackupError::CutoverNotAuthorized,
        KernelRestoreError::DestinationInvalid(_)
        | KernelRestoreError::FenceMismatch(_)
        | KernelRestoreError::ArchiveInvalid(_)
        | KernelRestoreError::CapabilityMissing { .. }
        | KernelRestoreError::OwnerEvidenceInvalid(_) => BackupError::Target(error.to_string()),
    }
}

/// Requires production-grade journal admission before an effect.
///
/// Accepts only a structurally valid admission that
/// [`admits_production_durable_recovery`](eliot_backup::RestoreJournalAdmission::admits_production_durable_recovery):
/// an unadmitted handle and a fixture-flagged admission both refuse with
/// [`JournalNotAdmitted`](KernelRestoreError::JournalNotAdmitted). A fixture
/// proves adapter mapping only and never backs a production
/// durable-recovery claim. The admission value is owner-supplied, never
/// minted here.
pub fn require_production_admitted(
    admission: &RestoreJournalAdmission,
) -> Result<(), KernelRestoreError> {
    admission
        .validate()
        .map_err(|error| KernelRestoreError::OwnerEvidenceInvalid(error.to_string()))?;
    if admission.admits_production_durable_recovery() {
        Ok(())
    } else {
        Err(KernelRestoreError::JournalNotAdmitted)
    }
}

/// Per-execution restore port bundle: the admitted journal description, the
/// live Kernel effect fence, the blob/key bindings, and the owner-approved
/// destination evidence.
///
/// Every reference is caller-supplied owner evidence, validated here and
/// re-checked at each phase boundary by the target. The durable journal
/// itself is NOT carried here: it is injected as `J: RestoreJournalPort`
/// (see [`require_production_admitted`]) so no substitute can hide inside
/// this bundle. Owner channels that bind later (#962: canonical Store #952,
/// ORS recovery #953, Watchdog spool #955, Blob #956, installation #958)
/// arrive as evidence obligations in the finalized receipt, never as live
/// handles in this struct.
pub struct RestorePorts<'a> {
    /// Owner-issued journal admission for the injected durable journal.
    pub journal_admission: &'a RestoreJournalAdmission,
    /// The Kernel's current authority fence (never caller arithmetic).
    pub kernel_fence: &'a StateFence,
    /// Admitted wrapped-key manifest for blob-carrying archives.
    pub keys: Option<&'a eliot_backup::WrappedKeyManifest>,
    /// Destination blob scope for destination-owned re-sealing.
    pub blob_scope: Option<&'a eliot_backup::DestinationScope>,
    /// Owner-approved destination manifest evidence (#958 issuer).
    pub manifest_evidence: Option<DestinationManifestEvidence>,
    /// Rehearsal mode: isolated import runs, but cutover refuses and no
    /// activation, retirement, or effect unblocking exists on any path.
    pub rehearsal: bool,
}

impl RestorePorts<'_> {
    /// Validates the structural shape of every carried evidence value.
    /// Production-vs-rehearsal admission is decided at execution by the
    /// coordinator, not here.
    pub fn validate(&self) -> Result<(), KernelRestoreError> {
        self.journal_admission
            .validate()
            .map_err(|error| KernelRestoreError::OwnerEvidenceInvalid(error.to_string()))?;
        if let Some(evidence) = self.manifest_evidence.as_ref() {
            evidence.validate()?;
        }
        Ok(())
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
            || label.len() > MAX_DESTINATION_LABEL_LEN
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

/// Pinned destination admission: the owner-approved manifest evidence bound
/// to one restore transaction and target. Written once at prepare,
/// re-verified before later effects and at cutover qualification; any drift
/// refuses.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedDestinationAdmission {
    /// Accepted transaction identity pinned at prepare.
    pub transaction_id: String,
    /// Plan target id pinned at prepare.
    pub target_id: String,
    /// Owner-approved manifest evidence pinned at prepare.
    pub evidence: DestinationManifestEvidence,
}

// ---------------------------------------------------------------------------
// Issue #960: the ORS-backed durable journal adapter.
//
// This is the seam issue #957 names as its blocker. `eliot-ors` must not
// depend on `eliot-backup` (the ORS-to-backup edge is forbidden by the
// architecture boundary audit), so `impl RestoreJournalPort` cannot live in
// `eliot-ors`. `eliot-kernel` depends on both owners, so the mapping lives in
// the file issue #960 scopes to "minimal adapters to the accepted
// RestoreTarget/RestoreJournalPort only".
//
// What this adapter is: a lossless translation of the two accepted seam
// methods onto #957's durable ORS restore journal.
//
// What this adapter is NOT: a journal. It keeps no restore state machine, no
// phase rules, and no in-memory substitute. The engine remains
// `RestorePlan::execute_with_journal`; the durability remains the ORS
// `RedbRecoveryStore` that production composition already owns.
// ---------------------------------------------------------------------------

/// Owner-derived identity of one ORS restore-journal stream family.
///
/// Every field is an exact owner fact taken from live composition. The adapter
/// never derives, defaults, or guesses any of them, and a blank or malformed
/// value refuses at construction instead of being replaced with a placeholder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrsRestoreBinding {
    /// Exact source archive identity under restore.
    pub source_archive_id: String,
    /// Exact archive class of that source. A class is never silently changed
    /// to make an effect admissible.
    pub archive_class: RestoreJournalArchiveClass,
    /// Exact isolated destination identity (owner-issued by #958).
    pub destination_ref: String,
    /// Exact Kernel writer identity that owns the stream.
    pub writer_id: String,
}

impl OrsRestoreBinding {
    fn stream_binding(
        &self,
        transaction_id: &str,
        writer_fence_digest: &str,
    ) -> RestoreJournalStreamBinding {
        RestoreJournalStreamBinding {
            transaction_id: transaction_id.to_owned(),
            source_archive_id: self.source_archive_id.clone(),
            archive_class: self.archive_class,
            destination_ref: self.destination_ref.clone(),
            writer_id: self.writer_id.clone(),
            writer_fence_digest: writer_fence_digest.to_owned(),
        }
    }
}

/// Adapter from the accepted [`RestoreJournalPort`] seam onto the durable ORS
/// restore journal owned by production composition (#957).
///
/// ## Lossless mapping
///
/// One eliot-backup `compare_and_swap` is one immutable ORS *append*; nothing
/// is ever mutated in place. The ORS stream is the eliot-backup `journal_key`,
/// so every stream row is bound to the exact source archive, archive class,
/// destination, writer identity and writer fence through
/// [`RestoreJournalStreamBinding`], and every row is chained to its exact
/// durable predecessor through `expected_predecessor`.
///
/// The ORS phase slot is `(stream, transaction, phase_operation)`, and
/// `phase_operation` is derived from the record's own revision and phase
/// digest. Every compare-and-swap therefore owns a distinct slot, so a resumed
/// transaction re-drives the same revisions and lands on the same slots, where
/// the ORS owner recognises the exact replay instead of appending twice.
///
/// A CAS whose state is terminal for its slot (`ReceiptPersisted`, `Completed`,
/// `RollbackRequired`) additionally appends the ORS *result* row for that same
/// slot, so the post-effect receipt is a first-class durable owner row rather
/// than an inferred fact.
///
/// ## Payload medium
///
/// The journaled record is sealed as an `ImmutableLocator` envelope whose
/// locator names one content-addressed file under the Kernel-owned payload
/// root. The ORS owner deliberately does not fetch or hash a locator target,
/// so this adapter verifies the declared length and SHA-256 on every read
/// before the bytes are parsed. A record is journal state, not plaintext key
/// material, and no key or secret provider is invented for it.
///
/// ## Bounded work
///
/// Reads are bounded by the ORS page ceiling. A stream that outgrows one page
/// fails closed through the owner rather than being silently truncated, so a
/// restore never resumes from a partial view of its own history.
pub struct OrsRestoreJournal {
    store: Arc<RedbRecoveryStore>,
    binding: OrsRestoreBinding,
    writer_fence_digest: String,
    epoch: EpochIdentity,
    fence_snapshot: StateFenceSnapshot,
    sealed_root: PathBuf,
    /// Canonical form of the payload root, resolved once at construction. A
    /// lexical prefix check cannot see a link or junction planted inside the
    /// root, so every read re-checks the resolved path against this value.
    sealed_root_canonical: Option<PathBuf>,
    heads: BTreeMap<String, JournalPredecessor>,
}

impl OrsRestoreJournal {
    /// Binds the adapter to the composition-owned durable ORS owner.
    ///
    /// The writer fence and the authority epoch are taken from the Kernel's
    /// own live effect fence, never from the journaled record: a caller cannot
    /// name its own writer authority. The `sealed_root` is the Kernel-owned
    /// payload root under the work root.
    pub fn production(
        store: Arc<RedbRecoveryStore>,
        kernel_fence: &StateFence,
        binding: OrsRestoreBinding,
        sealed_root: PathBuf,
    ) -> Result<Self, KernelRestoreError> {
        for (value, field) in [
            (
                binding.source_archive_id.as_str(),
                "restore.journal.source_archive_id",
            ),
            (
                binding.destination_ref.as_str(),
                "restore.journal.destination_ref",
            ),
            (binding.writer_id.as_str(), "restore.journal.writer_id"),
        ] {
            non_blank(value, field)?;
        }
        if !sealed_root.is_absolute() {
            return Err(KernelRestoreError::InvalidInput {
                field: "restore.journal.sealed_root",
                reason: "the sealed payload root must be absolute",
            });
        }
        let sequence = kernel_fence.authority_epoch.sequence.get();
        let epoch = EpochIdentity {
            lineage_id: OpaqueLabel::new(kernel_fence.authority_epoch.lineage_id.as_str())
                .map_err(|error| KernelRestoreError::OwnerEvidenceInvalid(error.to_string()))?,
            epoch: sequence,
        };
        // The captured snapshot's own digest is the exact writer fence digest
        // the ORS owner binds: the envelope fence and the operation fence are
        // then the same value by construction, not by agreement.
        let fence_snapshot = StateFenceSnapshot::capture(kernel_fence, sequence)
            .map_err(|error| KernelRestoreError::FenceMismatch(error.to_string()))?;
        Ok(Self {
            store,
            binding,
            writer_fence_digest: fence_snapshot.sha256.clone(),
            epoch,
            fence_snapshot,
            // The root may not exist yet on a first restore; it is created by
            // the first seal, and the canonical form is resolved then.
            sealed_root_canonical: std::fs::canonicalize(&sealed_root).ok(),
            sealed_root,
            heads: BTreeMap::new(),
        })
    }

    /// Returns the exact writer fence digest the ORS owner binds for every row.
    #[must_use]
    pub fn writer_fence_digest(&self) -> &str {
        &self.writer_fence_digest
    }

    /// Returns the Kernel-owned content-addressed payload root.
    #[must_use]
    pub fn sealed_root(&self) -> &Path {
        &self.sealed_root
    }

    /// Ensures the stream carries the exact immutable owner binding.
    ///
    /// A stream already bound to another transaction, source, class,
    /// destination, writer or fence is left bound: the ORS owner refuses the
    /// rebind, and the old transaction never continues under new authority.
    fn ensure_bound(&self, stream: &str, transaction_id: &str) -> Result<(), BackupError> {
        let binding = self
            .binding
            .stream_binding(transaction_id, &self.writer_fence_digest);
        match self.store.load_restore_journal_binding(stream) {
            Ok(Some(existing)) if existing == binding => Ok(()),
            Ok(Some(_)) => Err(BackupError::RestoreJournalMismatch),
            Ok(None) => self
                .store
                .bind_restore_journal_stream(stream, &binding)
                .map_err(ors_to_backup),
            Err(error) => Err(ors_to_backup(error)),
        }
    }

    /// Reads the newest durably appended record and the durable head of one
    /// stream.
    ///
    /// An **unbound** stream is an exact new stream: the ORS owner reports it
    /// as a missing binding, not as corruption, so it reads as empty and the
    /// engine's genesis compare-and-swap can bind it. Reading it as an error
    /// would strand every fresh transaction before its first append.
    ///
    /// The head is **derived from the retained rows** when nothing was pruned,
    /// because the ORS owner installs `history_fence` only when a prune retired
    /// a slot, so a populated unpruned stream still reports no fence. Once a
    /// prune has run, the fence predecessor *is* the durable head and sits
    /// beyond the retained suffix, so it is used verbatim.
    ///
    /// The newest record is the newest retained row in both cases. A prune
    /// retires the oldest rows and keeps the newest, so a retained suffix still
    /// carries the exact latest record and a resume reads the true journal
    /// state rather than a truncated guess.
    fn read_state(
        &mut self,
        stream: &str,
    ) -> Result<(Option<RestoreJournalRecord>, Option<JournalPredecessor>), BackupError> {
        let expected = self.binding.stream_binding("", &self.writer_fence_digest);
        match self
            .store
            .load_restore_journal_binding(stream)
            .map_err(ors_to_backup)?
        {
            // An unbound stream is an exact new stream: the ORS owner reports a
            // missing binding as absent, not as corruption, so it reads as
            // empty and the engine's genesis compare-and-swap can bind it.
            None => return Ok((None, None)),
            Some(existing) => {
                // A stream already bound to another source, class, destination,
                // writer, fence or transaction is refused on READ, not only on
                // append. Checking it later would let the engine reconcile or
                // apply a target effect under a foreign binding before the
                // conflict surfaced.
                if existing.transaction_id != expected.transaction_id
                    || !matches_stream(&self.binding, &existing, &self.writer_fence_digest)
                {
                    return Err(BackupError::RestoreJournalMismatch);
                }
            }
        }
        let (entries, fence_head) = self
            .store
            .load_restore_journal_readback(stream, MAX_JOURNAL_PAGE_ENTRIES)
            .map_err(ors_to_backup)?;
        let latest = entries.iter().max_by_key(|entry| entry.sequence);
        // The head is the newest RETAINED row, always. The readback fence
        // argument is the prune boundary (the predecessor of the first retained
        // row), not the head, so trusting it would submit a stale predecessor
        // after any prune. A prune retires the oldest rows and leaves the head
        // in place, so the newest retained row is the head in both cases.
        let Some(latest) = latest else {
            if fence_head.is_some() {
                return Err(BackupError::IntegrityMismatch {
                    subject: "restore journal head has no retained record row".to_owned(),
                });
            }
            return Ok((None, None));
        };
        // The head digest is the owner's canonical digest of exactly this row,
        // so a row that does not hash to its own head is corruption rather
        // than a resume point.
        let head = JournalPredecessor {
            sequence: latest.sequence,
            digest: sha256_hex(
                serde_json::to_string(latest)
                    .map_err(|error| BackupError::Serialization(error.to_string()))?
                    .as_bytes(),
            ),
        };
        self.heads.insert(stream.to_owned(), head.clone());
        let record = self.open_bound_sealed(latest)?;
        Ok((Some(record), Some(head)))
    }

    /// Returns the durable head this adapter must chain its next append to.
    fn durable_head(&mut self, stream: &str) -> Result<Option<JournalPredecessor>, BackupError> {
        if let Some(head) = self.heads.get(stream) {
            return Ok(Some(head.clone()));
        }
        Ok(self.read_state(stream)?.1)
    }

    /// Reads the newest durably appended record for one stream.
    fn read_record(&mut self, stream: &str) -> Result<Option<RestoreJournalRecord>, BackupError> {
        Ok(self.read_state(stream)?.0)
    }

    /// Seals one record into the content-addressed payload root.
    ///
    /// Returns `(locator, sha256, length)`. The write is temp-file plus
    /// atomic rename, so a reader never observes a partial body.
    fn seal(&self, record: &RestoreJournalRecord) -> Result<(String, String, u64), BackupError> {
        let bytes = serde_json::to_vec(record)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        if bytes.len() > MAX_JOURNAL_PAYLOAD_BYTES {
            return Err(BackupError::LimitExceeded {
                field: "restore.journal_payload",
                limit: MAX_JOURNAL_PAYLOAD_BYTES,
            });
        }
        let digest = sha256_hex(&bytes);
        let locator = format!("{}/{}", &digest[..2], digest);
        let length = u64::try_from(bytes.len()).map_err(|_| BackupError::IntegrityMismatch {
            subject: "restore journal payload length".to_owned(),
        })?;
        let path = self.sealed_path(&locator)?;
        // An existing target is never trusted on its path alone. Content
        // addressing makes the name a claim, not a guarantee, so bytes already
        // on disk are verified against the digest this record actually
        // produced. Accepting a foreign body would let ORS commit a locator
        // that every later read refuses.
        if path.is_file() {
            let existing =
                std::fs::read(&path).map_err(|error| BackupError::Target(error.to_string()))?;
            if sha256_hex(&existing) != digest {
                return Err(BackupError::IntegrityMismatch {
                    subject: "restore journal sealed payload address collision".to_owned(),
                });
            }
            return Ok((locator, digest, length));
        }
        let parent = path.parent().ok_or(BackupError::RestoreJournalCorrupt)?;
        std::fs::create_dir_all(parent).map_err(|error| BackupError::Target(error.to_string()))?;
        let mut temporary = path.clone();
        temporary.set_extension("json.partial");
        // A stale partial from an interrupted write is replaced, never appended
        // to, so a crash can never splice two bodies together.
        if temporary.exists() {
            std::fs::remove_file(&temporary)
                .map_err(|error| BackupError::Target(error.to_string()))?;
        }
        std::fs::write(&temporary, &bytes)
            .map_err(|error| BackupError::Target(error.to_string()))?;
        // The body is made durable BEFORE the ORS row that names it is
        // committed, and a failed sync is a refusal rather than a silent
        // success: a recovered row must never point at a target that power
        // loss could still remove.
        std::fs::File::open(&temporary)
            .and_then(|file| file.sync_all())
            .map_err(|error| BackupError::Target(error.to_string()))?;
        std::fs::rename(&temporary, &path)
            .map_err(|error| BackupError::Target(error.to_string()))?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| BackupError::Target(error.to_string()))?;
        Ok((locator, digest, length))
    }

    /// Resolves one locator inside the payload root, refusing any other shape.
    ///
    /// The shard must be two hex characters and the name a 64-hex digest, so a
    /// `..` segment or any other traversal spelling is rejected before a path
    /// is built. The resolved path is then re-checked against the root, so a
    /// link or junction cannot move the read outside the payload area either.
    fn sealed_path(&self, locator: &str) -> Result<PathBuf, BackupError> {
        let mut parts = locator.split('/');
        let (Some(shard), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(BackupError::RestoreJournalCorrupt);
        };
        if shard.len() != 2 || !shard.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        if name.len() != 64 || !is_hex64(name) {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        let path = self.sealed_root.join(shard).join(format!("{name}.json"));
        if path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
            || !path.starts_with(&self.sealed_root)
        {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        Ok(path)
    }

    /// Opens the sealed record body of one persisted entry.
    ///
    /// Three independent things are proved before the bytes are parsed: the
    /// entry's envelope, locator and digest agree with its own operation; the
    /// resolved path is still inside the payload root once links are resolved;
    /// and the body matches the declared length and SHA-256. The read is size
    /// bounded first, so a committed locator cannot force an unbounded
    /// allocation.
    fn open_bound_sealed(
        &self,
        entry: &RestoreJournalEntry,
    ) -> Result<RestoreJournalRecord, BackupError> {
        check_entry_body_binding(entry)?;
        let envelope: RecoveryPayloadEnvelope =
            serde_json::from_str(&entry.payload).map_err(|_| BackupError::RestoreJournalCorrupt)?;
        let RecoveryPayloadBinding { locator, .. } = read_payload_binding(&envelope)?;
        let path = self.sealed_path(&locator)?;
        let resolved =
            std::fs::canonicalize(&path).map_err(|error| BackupError::Target(error.to_string()))?;
        let root = self
            .sealed_root_canonical
            .as_ref()
            .ok_or(BackupError::RestoreJournalCorrupt)?;
        if !resolved.starts_with(root) {
            return Err(BackupError::RestoreJournalCorrupt);
        }
        let length = resolved
            .metadata()
            .map_err(|error| BackupError::Target(error.to_string()))?
            .len();
        if length > MAX_JOURNAL_PAYLOAD_BYTES as u64 || length != envelope.payload_length {
            return Err(BackupError::LimitExceeded {
                field: "restore.journal_payload",
                limit: MAX_JOURNAL_PAYLOAD_BYTES,
            });
        }
        let bytes = std::fs::read(&path).map_err(|error| BackupError::Target(error.to_string()))?;
        if u64::try_from(bytes.len()).ok() != Some(length)
            || sha256_hex(&bytes) != envelope.payload_sha256
        {
            return Err(BackupError::IntegrityMismatch {
                subject: "restore journal sealed payload".to_owned(),
            });
        }
        serde_json::from_slice(&bytes).map_err(|_| BackupError::RestoreJournalCorrupt)
    }

    /// Builds the exact ORS operation identity for one compare-and-swap.
    fn operation(
        &self,
        record: &RestoreJournalRecord,
        body_digest: &str,
        payload_handle: &str,
        expected_predecessor: Option<JournalPredecessor>,
    ) -> Result<RestoreJournalOperation, BackupError> {
        Ok(RestoreJournalOperation {
            transaction_id: record.transaction.transaction_id.clone(),
            source_archive_id: self.binding.source_archive_id.clone(),
            archive_class: self.binding.archive_class,
            destination_ref: self.binding.destination_ref.clone(),
            writer_id: self.binding.writer_id.clone(),
            writer_fence_digest: self.writer_fence_digest.clone(),
            record_schema: RESTORE_JOURNAL_RECORD_SCHEMA.to_owned(),
            phase_operation: phase_operation(record)?,
            request_digest: request_digest(record)?,
            body_digest: body_digest.to_owned(),
            expected_predecessor,
            payload_handle: payload_handle.to_owned(),
        })
    }

    /// Builds the versioned ORS payload envelope for one sealed record.
    fn envelope(
        &self,
        operation: &RestoreJournalOperation,
        stream: &str,
        digest: &str,
        length: u64,
    ) -> Result<RecoveryPayloadEnvelope, BackupError> {
        let identity = operation.identity(stream).map_err(ors_to_backup)?;
        let context = RecoveryEnvelopeContext {
            operation_or_checkpoint_id: OpaqueLabel::new(identity).map_err(|_error| {
                BackupError::InvalidField {
                    field: "restore.journal_operation_identity",
                    reason: leak_free(),
                }
            })?,
            privacy_and_visibility_class: RecoveryAccessClass {
                privacy: PrivacyClass::Private,
                visibility: OpaqueLabel::new(RESTORE_JOURNAL_IDENTITY).map_err(|_error| {
                    BackupError::InvalidField {
                        field: "restore.journal_visibility",
                        reason: leak_free(),
                    }
                })?,
            },
            authority_epoch: EpochLineage {
                current: self.epoch.clone(),
                predecessor: None,
            },
            state_fence: self.fence_snapshot.clone(),
            created_at_ms: 0,
            known_at_ms: 0,
            // An unresolved restore journal row must never expire: an expired
            // intent is not reconcilable.
            expires_at_ms: None,
        };
        let locator = PlatformHandle::new(operation.payload_handle.clone()).map_err(|_error| {
            BackupError::InvalidField {
                field: "restore.journal_payload_locator",
                reason: leak_free(),
            }
        })?;
        RecoveryPayloadEnvelope::immutable_locator(context, locator, digest.to_owned(), length)
            .map_err(ors_to_backup)
    }
}

/// Maps a typed ORS owner failure onto the accepted seam without losing its
/// causal class.
///
/// Rules held here:
///
/// - No typed cause is flattened into an opaque code. Each ORS failure class
///   keeps a semantically exact [`BackupError`] variant, and the ORS record
///   type, reason or operation identity travels in the variant's own subject
///   field rather than being discarded.
/// - `IntegrityProblem` is subdivided by its `record_type` because the ORS
///   owner uses one variant for four genuinely different journal refusals: a
///   binding mismatch, a rewritten operation in an occupied phase slot, a
///   stale expected predecessor, and index/closure corruption. Collapsing them
///   would turn "retry against the durable head" and "this journal is
///   unreadable" into the same answer.
/// - ORS variants outside the journal vocabulary (supervision leases, worker
///   replay, versioned artifacts, activation and reservation state) cannot be
///   raised by a journal append. They are still mapped, per cause class, to a
///   typed seam variant instead of being gathered into one catch-all, so a
///   future ORS call that can reach them still reports a real class.
#[allow(
    clippy::too_many_lines,
    reason = "an exhaustive 55-variant owner mapping stays readable as one reviewed table"
)]
pub fn ors_to_backup(error: OrsError) -> BackupError {
    match error {
        OrsError::InvalidField { field, reason } => BackupError::InvalidField { field, reason },
        OrsError::FenceMismatch => BackupError::FenceMismatch {
            subject: "restore journal writer fence".to_owned(),
        },
        OrsError::EpochMismatch => BackupError::FenceMismatch {
            subject: "restore journal authority epoch".to_owned(),
        },
        OrsError::InvalidEpochLineage => BackupError::StaleRestoreLineage,
        OrsError::PayloadIntegrityMismatch => BackupError::IntegrityMismatch {
            subject: "restore journal payload".to_owned(),
        },
        OrsError::PayloadTooLarge => BackupError::LimitExceeded {
            field: "restore.journal_payload",
            limit: MAX_JOURNAL_PAYLOAD_BYTES,
        },
        OrsError::ProjectionLimitExceeded => BackupError::LimitExceeded {
            field: "restore.journal_page",
            limit: MAX_JOURNAL_PAGE_ENTRIES,
        },
        OrsError::UnsupportedContractVersion(version) => BackupError::UnsupportedFormat(format!(
            "restore journal envelope contract version {version}"
        )),
        OrsError::InvalidExpiry => BackupError::InvalidField {
            field: "restore.journal_expiry",
            reason: "an unresolved journal row must not expire",
        },
        OrsError::MigrationRequired { reason } => {
            BackupError::UnsupportedFormat(format!("restore journal migration: {reason}"))
        }
        OrsError::Encoding(detail) => BackupError::Serialization(detail),
        OrsError::Storage(_) => {
            BackupError::Target("restore journal owner storage failure".to_owned())
        }
        OrsError::CanonicalEvidence(detail) => BackupError::Target(detail),
        OrsError::DuplicateConflict
        | OrsError::HostRequestIdentityConflict { .. }
        | OrsError::ActivationResultRetentionIdentityConflict { .. }
        | OrsError::NativeWorkerClaimIdentityConflict { .. }
        | OrsError::WorkerReplayIdentityConflict { .. }
        | OrsError::WorkerReplayStaleStream { .. } => BackupError::Duplicate {
            field: "restore.journal",
        },
        OrsError::IntegrityProblem {
            record_type,
            reason,
        } => match record_type {
            "restore_journal_binding" | "restore_journal_operation" => {
                BackupError::RestoreJournalMismatch
            }
            // ORS emits `restore_journal_entry` for a stale expected
            // predecessor AND for malformed rows, sequence/key mismatch,
            // duplicate slots, broken predecessor linkage and sequence
            // exhaustion. Corruption is the far more likely cause, and
            // `RestoreJournalCasConflict` reads as a retryable stale
            // revision, so the unresolvable class wins: a corrupt journal
            // must be refused, not retried.
            "restore_journal_entry" => BackupError::RestoreJournalCorrupt,
            other => BackupError::IntegrityMismatch {
                subject: format!("restore journal {other}: {reason}"),
            },
        },
        OrsError::Contract(detail) => BackupError::Foundation(detail),
        OrsError::AuthorityHandoffNotFresh
        | OrsError::StaleWriterEpoch
        | OrsError::RecoveryOwnerMismatch => BackupError::FenceMismatch {
            subject: "restore journal writer authority".to_owned(),
        },
        OrsError::AuthoritySnapshotUnavailable | OrsError::RecoveryProblemRetained { .. } => {
            BackupError::RestoreEvidenceIncomplete
        }
        OrsError::OrderingHeadMismatch | OrsError::ReconciliationMismatch => {
            BackupError::ReceiptChainGap {
                event_id: "restore journal ordering head".to_owned(),
            }
        }
        OrsError::InboxIntegrityMismatch => BackupError::IntegrityMismatch {
            subject: "restore journal inbox binding".to_owned(),
        },
        OrsError::UnknownReceiptCannotResolve
        | OrsError::ReservationNotFound
        | OrsError::PredecessorPending
        | OrsError::StagingNotDurable(_) => BackupError::RestoreRollbackRequired,
        OrsError::EmptyScopeSet | OrsError::DuplicateScope => {
            BackupError::MissingRecoveryComponent("restore journal ordering scope set")
        }
        OrsError::InvalidCursorLimit | OrsError::InvalidSupervisionLeaseHistoryLimit => {
            BackupError::InvalidField {
                field: "restore.journal_page_limit",
                reason: "must be a supported bounded page",
            }
        }
        OrsError::InvalidTransition | OrsError::ScopeRecoveryRequired | OrsError::UnsafeExpiry => {
            BackupError::RestorePhaseMismatch
        }
        OrsError::ActiveExecutableReplacement
        | OrsError::IncompatibleArtifact
        | OrsError::VersionedArtifactConflict
        | OrsError::VersionedArtifactNotFound
        | OrsError::VersionedArtifactNotDrained => BackupError::IntegrityMismatch {
            subject: "restore journal versioned artifact".to_owned(),
        },
        OrsError::WorkerReplayAckMismatch { .. } | OrsError::WorkerReplayIncomplete { .. } => {
            BackupError::RestoreJournalCorrupt
        }
        OrsError::SupervisionLeaseStaleRevision | OrsError::SupervisionLeaseTicketConflict => {
            BackupError::FenceMismatch {
                subject: "restore journal supervision lease".to_owned(),
            }
        }
        OrsError::SupervisionLeaseBindingMismatch
        | OrsError::SupervisionLeaseTicketNotStaged
        | OrsError::SupervisionLeaseTicketResolved
        | OrsError::SupervisionLeaseTicketNotExpired
        | OrsError::SupervisionLeaseTicketExpired
        | OrsError::SupervisionLeaseTicketAlreadyCommitted => BackupError::IntegrityMismatch {
            subject: "restore journal supervision ticket".to_owned(),
        },
    }
}

/// Maps a rejected opaque label onto a static seam reason. The owner error is
/// deliberately not interpolated: journal labels are bounded opaque identities,
/// never free text a diagnostic should echo back.
fn leak_free() -> &'static str {
    "must be a bounded opaque journal label"
}

/// Reports whether a persisted stream binding is exactly this adapter's own
/// binding. The transaction is compared separately, because the adapter learns
/// the transaction identity from the journaled record rather than owning it.
fn matches_stream(
    binding: &OrsRestoreBinding,
    existing: &RestoreJournalStreamBinding,
    writer_fence_digest: &str,
) -> bool {
    existing.source_archive_id == binding.source_archive_id
        && existing.archive_class == binding.archive_class
        && existing.destination_ref == binding.destination_ref
        && existing.writer_id == binding.writer_id
        && existing.writer_fence_digest == writer_fence_digest
}

/// Checks that a persisted entry and the record body it names agree.
///
/// The ORS owner checks the envelope against the operation's identity and
/// writer fence, but it deliberately does not fetch a locator target, so
/// nothing else proves that the locator the envelope names is the body the
/// operation committed. This adapter re-derives both bindings from the entry
/// it is about to trust, so a row whose envelope points at a different valid
/// content-addressed body is refused rather than replayed.
fn check_entry_body_binding(entry: &RestoreJournalEntry) -> Result<(), BackupError> {
    let envelope: RecoveryPayloadEnvelope =
        serde_json::from_str(&entry.payload).map_err(|_| BackupError::RestoreJournalCorrupt)?;
    let RecoveryPayloadBinding {
        locator,
        payload_sha256,
        payload_length,
    } = read_payload_binding(&envelope)?;
    if locator != entry.operation.payload_handle
        || payload_sha256 != entry.payload_sha256
        || payload_sha256 != entry.operation.body_digest
    {
        return Err(BackupError::RestoreJournalMismatch);
    }
    let expected =
        u64::try_from(entry.payload.len()).map_err(|_| BackupError::RestoreJournalCorrupt)?;
    if payload_length != expected {
        return Err(BackupError::IntegrityMismatch {
            subject: "restore journal envelope payload length".to_owned(),
        });
    }
    Ok(())
}

/// The three fields this adapter relies on from a sealed envelope.
struct RecoveryPayloadBinding {
    locator: String,
    payload_sha256: String,
    payload_length: u64,
}

/// Extracts the sealed-payload binding, refusing any other payload variant.
///
/// An `Encrypted` payload is refused rather than read: this adapter only ever
/// writes the locator variant, so an encrypted row was not produced by it and
/// must not be silently interpreted.
fn read_payload_binding(
    envelope: &RecoveryPayloadEnvelope,
) -> Result<RecoveryPayloadBinding, BackupError> {
    let eliot_ors::RecoveryPayload::ImmutableLocator { locator } = &envelope.payload else {
        return Err(BackupError::RestoreJournalCorrupt);
    };
    Ok(RecoveryPayloadBinding {
        locator: locator.as_str().to_owned(),
        payload_sha256: envelope.payload_sha256.clone(),
        payload_length: envelope.payload_length,
    })
}

/// The ORS phase slot for one compare-and-swap: its exact revision plus its
/// exact phase digest, so every CAS owns a distinct durable slot and an exact
/// resume re-lands on the same one.
///
/// A phase that cannot be encoded is a refusal, never a fallback digest: a
/// zeroed digest would let two different phases share one durable slot.
fn phase_operation(record: &RestoreJournalRecord) -> Result<String, BackupError> {
    let phase = sha256_hex(
        serde_json::to_string(&record.phase)
            .map_err(|error| BackupError::Serialization(error.to_string()))?
            .as_bytes(),
    );
    Ok(format!(
        "restore-cas-revision-{:020}-{phase}",
        record.revision
    ))
}

/// Digest of the exact requested effect for this CAS, or of the exact
/// phase/state advance when the record carries no intent.
///
/// An unencodable request is a refusal rather than the digest of empty bytes,
/// because `request_digest` is what the ORS owner compares to detect a
/// rewritten request in an occupied phase slot.
fn request_digest(record: &RestoreJournalRecord) -> Result<String, BackupError> {
    let encoded = match &record.intent {
        Some(intent) => serde_json::to_string(intent),
        None => serde_json::to_string(&(&record.phase, record.state)),
    }
    .map_err(|error| BackupError::Serialization(error.to_string()))?;
    Ok(sha256_hex(encoded.as_bytes()))
}

impl RestoreJournalPort for OrsRestoreJournal {
    fn load(&mut self, journal_key: &str) -> Result<Option<RestoreJournalRecord>, BackupError> {
        if journal_key.is_empty() || journal_key.len() > MAX_JOURNAL_STREAM_KEY_BYTES {
            return Err(BackupError::RestoreJournalMismatch);
        }
        self.read_record(journal_key)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the CAS keeps the revision gate, the binding, the seal, the append and the owner readback together"
    )]
    fn compare_and_swap(
        &mut self,
        journal_key: &str,
        expected_revision: u64,
        next: RestoreJournalRecord,
    ) -> Result<(), BackupError> {
        if journal_key.is_empty() || journal_key.len() > MAX_JOURNAL_STREAM_KEY_BYTES {
            return Err(BackupError::RestoreJournalMismatch);
        }
        if next.journal_key != journal_key {
            return Err(BackupError::RestoreJournalMismatch);
        }
        let current = self.read_record(journal_key)?;
        match (&current, expected_revision) {
            (Some(record), expected) if record.revision != expected => {
                return Err(BackupError::RestoreJournalCasConflict);
            }
            (None, expected) if expected != 0 => {
                return Err(BackupError::RestoreJournalCasConflict);
            }
            _ => {}
        }
        // The engine's genesis record is written at revision 0 with an expected
        // revision of 0, so genesis is the one case where the next revision
        // does NOT advance. Every later compare-and-swap advances by exactly
        // one. The increment is checked, so a saturated `u64::MAX` cannot wrap a
        // later append back to revision 0 and reverse the durable revision
        // ordering.
        let required_revision = match &current {
            None => 0,
            Some(_) => expected_revision
                .checked_add(1)
                .ok_or(BackupError::RestoreJournalCorrupt)?,
        };
        if next.revision != required_revision {
            return Err(BackupError::RestoreJournalMismatch);
        }
        self.ensure_bound(journal_key, &next.transaction.transaction_id)?;

        let (locator, body_digest, length) = self.seal(&next)?;
        let head = self.durable_head(journal_key)?;
        let operation = self.operation(&next, &body_digest, &locator, head)?;
        let envelope = self.envelope(&operation, journal_key, &body_digest, length)?;
        let payload = serde_json::to_string(&envelope)
            .map_err(|error| BackupError::Serialization(error.to_string()))?;
        let payload_sha256 = sha256_hex(payload.as_bytes());
        let receipt = self
            .store
            .append_restore_journal_intent(journal_key, &operation, &payload_sha256, &payload)
            .map_err(ors_to_backup)?;
        self.store
            .verify_restore_journal_receipt(journal_key, &receipt)
            .map_err(ors_to_backup)?;
        self.heads.insert(
            journal_key.to_owned(),
            JournalPredecessor {
                sequence: receipt.sequence,
                digest: receipt.record_digest.clone(),
            },
        );

        if matches!(
            next.state,
            RestoreJournalState::ReceiptPersisted
                | RestoreJournalState::Completed
                | RestoreJournalState::RollbackRequired
        ) {
            let result = RestoreJournalResult {
                transaction_id: operation.transaction_id.clone(),
                phase_operation: operation.phase_operation.clone(),
                intent_sequence: receipt.sequence,
                receipt_sha256: payload_sha256.clone(),
                receipt: payload,
            };
            let result_receipt = self
                .store
                .append_restore_journal_result(journal_key, &result)
                .map_err(ors_to_backup)?;
            self.store
                .verify_restore_journal_receipt(journal_key, &result_receipt)
                .map_err(ors_to_backup)?;
        }
        Ok(())
    }
}
