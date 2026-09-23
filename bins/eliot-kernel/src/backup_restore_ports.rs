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
//! What this file deliberately does NOT own: any journal implementation.
//! There is no in-memory, filesystem-JSON, or no-op journal here. The durable
//! journal is always an injected `J: RestoreJournalPort` supplied by
//! production composition (the admitted persistent owner is #957's ORS
//! journal, bound by the #962 composition turn through the accepted
//! [`RestoreJournalAdmission`](eliot_backup::RestoreJournalAdmission)).
//! The coordinator ([`KernelBackupRestore`](super::backup_restore::KernelBackupRestore),
//! registered by the #959 turn) takes the journal as a required parameter
//! with no `Default` and no fallback constructor, so production cannot
//! introduce a substitute by construction: an unadmitted or fixture-flagged
//! admission refuses effects ([`JournalNotAdmitted`](KernelRestoreError::JournalNotAdmitted))
//! instead of standing in for durability.
//!
//! Capability cell: Kernel restore ownership (journal admission, isolated
//! destination admission, effect-fence gating). Read through the restore
//! receipt and evidence vocabulary.
//! Forbidden authority: no ORS row interpretation, no second database, no
//! backup phase rules, no epoch minting, no cutover, no activation/retirement
//! of any installation, no in-memory/no-op journal substitute in any path.

use std::path::{Path, PathBuf};

use eliot_backup::{BackupBundle, BackupError, RestoreJournalAdmission};
use eliot_contracts::StateFence;

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
        | KernelRestoreError::OwnerEvidenceInvalid(_) => {
            BackupError::Target(error.to_string())
        }
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
