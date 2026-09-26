//! Host-owned isolated destination preparation for backup (issue #958).
//!
//! Pure admission, verification, and filesystem-effect logic over explicitly
//! supplied evidence. The caller (`HostComposition` at delegation; fixtures in
//! tests) provides the admission, the source root, the explicitly admitted
//! staging parent, authority values, and a [`PreparationJournal`] sink. This
//! module mints no authority of its own: fresh destination identities derive
//! deterministically from the operation identity under a domain separator, so
//! they are never archive copies or caller-chosen increments — while true
//! owner epoch assignment stays with the later cutover child.
//!
//! Effects are exactly: create one destination directory under the admitted
//! parent, pin its OS identity, and record intent/result through the journal
//! sink. No launch, no readiness probing, no effect-authority activation, no
//! source shutdown, no SCM contact, no registry writes, no archive import, no
//! cutover. Launch/readiness/effect authority have no representation here by
//! construction (see case 958/10).
//!
//! # Configuration projection
//!
//! Preparation is gated by the bounded owner-issued configuration projection
//! in [`crate::backup_config_projection`], not by a caller assertion.
//! [`DelegatedPreparation::prepare`] runs
//! [`OwnerEvidence::project_backup_configuration`] first; its
//! [`BackupConfigProjection::manifest_digest`] becomes the admitted owner
//! configuration digest and its [`BackupConfigProjection::projection_digest`]
//! becomes the admitted [`DestinationAdmission::config_projection_digest`], so
//! the prepared-destination receipt binds the exact configuration evidence that
//! was proved. The same step renders the optional forensic audit note through
//! [`describe_audit_fence`] into
//! [`DestinationAdmission::audit_fence_note`]; the note stays evidence text
//! with its non-authoritative ceiling and is never a lease, grant, or
//! current-state assertion.
//!
//! # Staging parent, generation and sweep bounds
//!
//! Three admissions carry the guarantees issue #958 requires, and each one is
//! decided before any effect:
//!
//! - **The staging parent is owner-proved, never client-named.**
//!   [`admit_staging_parent`] keeps its structural checks and then proves the
//!   parent through [`verify_staging_parent_lease`], which
//!   containment-checks it against the real ELIOT protected contour and pins
//!   the directory chain by retained handle. A client-supplied arbitrary path
//!   is refused with [`PreparationError::ArbitraryPath`], and the parent this
//!   module proceeds with is the owner-resolved canonical path rather than a
//!   name-based canonicalise. That is also what makes removal reachable:
//!   [`reverify_recorded_destination`] requires the same containment, so a
//!   root created here is by construction one whose removal path
//!   ([`remove_reverified_destination`]) can be reached. The proof is taken at
//!   admission; the recorded root is proved again through the same owner
//!   immediately before any removal, and preserved when that proof fails.
//! - **The generation comparison is an owner comparison on the delegated
//!   path.**
//!   [`DelegatedPreparation::prepare`] sources
//!   [`DestinationAdmission::authority_generation`] from the committed
//!   activation fence ([`OwnerEvidence::authority_generation`]) and never from
//!   the presented request, so the `approved_generation != authority_generation`
//!   arm in [`validate_admission`] compares a caller-presented value against
//!   owner-issued evidence instead of comparing two values the same caller
//!   supplied. A caller can no longer make the pair agree by agreement **through
//!   this path**. It is stated at the narrower scope the code actually has:
//!   [`prepare_isolated_destination`] and [`DestinationAdmission`] remain
//!   `pub` with all-public fields, so a caller that builds an admission itself can
//!   still present two agreeing values, and the arm cannot tell. The
//!   owner-sourced construction is what makes the check real, and only
//!   `DelegatedPreparation::prepare` performs it.
//! - **The cleanup sweep is budgeted.** [`cleanup_preparations`] is bounded by
//!   [`MAX_CLEANUP_REQUESTED_IDS`], [`MAX_CLEANUP_SWEEP_OPERATIONS`] and
//!   [`CLEANUP_SWEEP_BUDGET`], and refuses with
//!   [`PreparationError::SweepBudget`] instead of letting an unbounded journal
//!   drive unbounded reconciles and `remove_dir_all` calls (A13.9: a Durable
//!   Job carries a budget).
//!
//! # Target build and profile are presented scope, not approved names
//!
//! [`DestinationAdmission::target_build`] and
//! [`DestinationAdmission::target_profile`] stay caller-presented bounded text,
//! and are hashed into the admission digest as exactly that. The owner records
//! reachable from this module ([`OwnerEvidence`], [`ApprovedBuildBinding`])
//! carry approved artifact *digests* plus a generation handle, and have no
//! build-name or profile-name field, so no owner source exists here against
//! which a presented name could be approved; no name-level approval list and
//! no always-passing comparison is invented in its place. The owner-approval
//! check that genuinely exists is the presented `build_digests` subset check
//! against the owner artifact set, in
//! [`DelegatedPreparation::prepare`] and again in
//! [`OwnerEvidence::project_backup_configuration`]. Nothing here claims more:
//! the owner-issued facts in the receipt are the manifest digest and the
//! configuration projection digest, and the build/profile strings are scope
//! text the owner has not approved by name.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::backup_config_projection::{
    ApprovedBuildBinding, AuditFenceNote, BackupConfigProjection, BackupConfigRequest,
    ProjectionError, bind_approved_build, describe_audit_fence, hash_field,
    project_backup_config_owner_bound,
};
use eliot_installation::{
    ActivationCommitFence, ApprovedGeneration, ApprovedGenerationRegistry,
    RedbInstallationRegistry, RuntimeStateRoots,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    FileIdentity, HostOwnerLease, ProtectedPathError, ProtectedRootLease, windows_paths_equal,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Preparation format version pinned into digests and receipts.
pub const PREPARATION_VERSION: u32 = 1;
/// Maximum length of one bounded identity string.
pub const MAX_IDENTITY_LEN: usize = 256;
/// Maximum length of the rendered forensic audit note carried in an admission.
///
/// A receipt-size bound, not an authority bound: the note has no authority to
/// check because it can never be a lease, grant, or current-state assertion.
///
/// Sized so it can always hold the largest note the projector admits — 64
/// dispositions of 256 bytes each, their separators, the 64-character note
/// digest, and the fixed ceiling wording (16 615 bytes). A smaller bound would
/// let preparation refuse a note the projector had already accepted, which
/// would report a receipt-size limit as an evidence failure.
pub const MAX_AUDIT_NOTE_LEN: usize = 16615;
/// Maximum number of caller-presented operation ids one cleanup sweep may be
/// narrowed to.
///
/// The narrowing list is caller input, so it is bounded before the sweep does
/// any work: the membership test against the journal-owned set is quadratic in
/// the two list lengths, and an unbounded presented list would make one cleanup
/// call cost more than the sweep it narrows. 256 is two orders of magnitude
/// above any plausible single narrowing request (a cancel batch, one
/// maintenance pass) while still refusing a list that is trying to be a dump.
pub const MAX_CLEANUP_REQUESTED_IDS: usize = 256;
/// Maximum number of journal-owned operations one cleanup sweep may sweep.
///
/// Each swept operation costs one journal load, one protected-root lease open
/// (which pins the whole directory contour by retained handle) and at most one
/// `remove_dir_all`, so the swept key set is the sweep's real work bound. 256
/// covers every realistic leftover of one Host's preparation history while
/// staying far below the handle and time pressure of an unbounded journal; a
/// larger set is refused whole and swept in bounded passes, never truncated
/// silently (truncation would hide owned roots that still exist).
///
/// The bound applies to the set the call will actually sweep — the journal's own
/// operations intersected with the caller's narrowing list, or the whole owned
/// set when no list is given. It deliberately does NOT bound the journal's total
/// history: a journal grows by one operation per preparation, so bounding the
/// owned set would refuse every later cleanup forever, including a caller that
/// named one specific operation, and there would be no way to make progress
/// again. A non-empty narrowing list is separately capped by
/// [`MAX_CLEANUP_REQUESTED_IDS`].
pub const MAX_CLEANUP_SWEEP_OPERATIONS: usize = 256;
/// Wall-clock budget for one cleanup sweep (A13.9: a Durable Job has a
/// budget).
///
/// The clock starts before the owned set is listed and is checked after the
/// listing returns and again before every swept operation, so the bound caps the
/// number of *subsequent* reconciles and removals rather than interrupting one in
/// flight (`remove_dir_all` cannot be cancelled once issued) and the listing's
/// own unbounded cost still falls inside the window even though the call itself
/// cannot be interrupted. 30 s is generous headroom for 256 individually
/// re-proven owned roots on a loaded volume and still far below any caller wait
/// that a runaway sweep could justify; exhaustion refuses with
/// [`PreparationError::SweepBudget`], names any roots already removed in the same
/// call, and preserves everything not yet swept.
pub const CLEANUP_SWEEP_BUDGET: Duration = Duration::from_secs(30);
/// Domain separator for owner-minted destination identities.
pub const DESTINATION_ID_DOMAIN: &str = "eliot.backup.destination.v1";

/// Errors for isolated destination preparation (issue #958).
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum PreparationError {
    /// Malformed request shape (empty/overlong/control-carrying identity, bad digest).
    #[error("invalid request field {field}: {reason}")]
    InvalidRequest { field: &'static str, reason: String },
    /// Approved generation disagrees with the authority generation input.
    #[error("unapproved generation: approved {approved} != authority {authority}")]
    UnapprovedGeneration { approved: u64, authority: u64 },
    /// Staging parent is the source, nested under it, missing, not a directory,
    /// or outside the ELIOT protected contour (cases 958/5-6, 958/7).
    #[error("staging parent not admitted: {reason}")]
    ArbitraryPath { reason: String },
    /// The active/source installation itself was targeted.
    #[error("source installation is active and can never be a destination")]
    SourceIsActive,
    /// Preexisting foreign content sits at the exact destination path.
    #[error("preexisting foreign content at {path}: refusing to adopt or overwrite")]
    ForeignContent { path: String },
    /// Reparse point / alias substitution detected on the admitted path.
    #[error("alias substitution refused at {path}: reparse points are not admitted")]
    AliasSubstitution { path: String },
    /// Recorded OS identity no longer matches (replaced root).
    #[error("root identity mismatch for {operation}: recorded {recorded} != observed {observed}")]
    IdentityConflict {
        operation: String,
        recorded: String,
        observed: String,
    },
    /// Same operation with changed input; names the first differing field.
    #[error("changed same-operation input in field {field}: reconcile, do not blindly retry")]
    ConflictField { field: &'static str },
    /// State cannot be established (missing journal slots, unverifiable root).
    #[error("unknown state for {operation}: {reason}; preserved, never deleted")]
    UnknownState { operation: String, reason: String },
    /// Journal sink failure (message only, never secret material).
    #[error("journal fault: {0}")]
    JournalFault(String),
    /// Platform lacks the OS identity primitive (non-Windows builds).
    /// Unconstructible on Windows by design (identity always available);
    /// allowed dead on this contour with the reason recorded here.
    #[error("platform unsupported: OS root identity requires Windows")]
    #[allow(dead_code, reason = "constructed only on non-Windows contours")]
    PlatformUnsupported,
    /// Filesystem effect failed after admission (message only).
    #[error("filesystem effect failed at {path}: {reason}")]
    FilesystemEffect { path: String, reason: String },
    /// The cleanup sweep exceeded its explicit count or time budget
    /// (case 958/16).
    ///
    /// A refused sweep stops before the next operation: nothing further is
    /// deleted and nothing is deleted by truncation, so every root this module
    /// created stays individually re-provable on the next bounded pass. When
    /// the refusal follows removals already performed in the same call, `reason`
    /// additionally names those completed operation ids — a budget error raised
    /// after an irreversible effect must never hide which effects occurred.
    #[error("cleanup sweep budget exceeded on {field}: {reason}")]
    SweepBudget { field: &'static str, reason: String },
}

impl PreparationError {
    /// Names the operations this call already removed, so a refusal raised after
    /// an irreversible effect still carries the evidence of that effect.
    ///
    /// Appended to the static reason, never replacing it, and bounded to the
    /// number of ids the sweep can have completed under
    /// [`MAX_CLEANUP_SWEEP_OPERATIONS`]. An empty set leaves the reason exactly
    /// as it was.
    fn with_removed(self, removed: &[String]) -> Self {
        if removed.is_empty() {
            return self;
        }
        match self {
            Self::SweepBudget { field, reason } => Self::SweepBudget {
                field,
                reason: format!("{reason}; already removed in this call: {removed:?}"),
            },
            other => other,
        }
    }
}

// F-LOG-HOST-8 (#983) backup preparation diagnostics: observation-only helpers.
//
// Through the #889 facade's target and bounded-field helpers only, on the
// existing subscriber; the Event Log seam stays typed-Unavailable (never
// implemented here, #984 still open). `EntrypointStage` describes process
// startup/shutdown, not backup phases, so these observations carry local event
// names and never reuse that enum.
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static tokens or validated numeric facts
// (generations, owner-minted destination epochs); never operation/installation
// strings, paths, digests, nonces, reasons, `redacted_debug()` text, or
// arbitrary error `Debug`/`Display` (a canary stays absent even inside an
// alleged identity string). Truncation bounds size, never sensitivity. Before
// validation only the static attempt record fires. Macro arguments are
// precomputed pure values; sink outcome never alters call counts, order,
// results, receipts, rollback, or cleanup, and stdout framing is untouched
// (facade stderr subscriber). No owner reads, effects, hashing, retries, or
// mutation are added for logging.
//
// Terminal ownership (W4): the leaf emits nonterminal phase/refusal evidence
// only, with no dedup cache. Child phase records may remain beneath one
// caller-level record. The single terminal record per failed operation belongs
// to the outer caller boundary, which owns the one `observe_terminal_error`
// call. Handoff (caller-owned, not applied here): `prepare_backup_destination`
// / `backup_dispatch_prepare` and the reconcile/cancel/cleanup holders arm one
// terminal guard each with a frozen `host-backup-prepare-failed` code;
// operation failure stays distinct from any process shutdown failure.
//
// Explicit no-event list: `DelegatedPreparation::{reconcile, cancel, cleanup}`
// (pure passthroughs; the inner operation owns the record),
// `OwnerEvidence::approved_binding` (mapping adapter covered by the inner bind
// and outer delegate records), `BackupCallerAuth::{check_shapes, authenticate}`
// (the former surfaces through `authenticate_for_owner`; the latter is the
// pending-#954 always-refuse stub with no production path),
// `conflict_field`/`admission_digest`/`derive_*`/`hash_path`/`capture_identity`
// /`reject_reparse`/`reverify_recorded_destination`/`protected_path_to_preparation`
// /`projection_to_preparation`/`intent_json`/`result_json`/`destination_from_result`
// (private steps whose outcome surfaces with its exact category at the owning
// boundary). No record asserts destination readiness, source retirement, or
// activation: `destination_epoch` is preparation scope, never authority.

/// Operation tokens for preparation diagnostics (stable, static only).
const OP_PREPARE: &str = "prepare";
const OP_RECONCILE: &str = "reconcile";
const OP_CANCEL: &str = "cancel";
const OP_CLEANUP: &str = "cleanup";
const OP_DELEGATE: &str = "delegate_prepare";
const OP_OWNER_EVIDENCE: &str = "owner_evidence";
const OP_SOURCE_ROOT: &str = "source_root";
const OP_STAGING_LEASE: &str = "staging_lease";
const OP_CALLER_AUTH: &str = "caller_auth";

/// Notes the facade's actual Event Log seam status (typed-unavailable).
fn backup_prepare_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

/// Projects one [`PreparationError`] to its stable diagnostic category plus a
/// static facet. Pure and exhaustive; carries no paths, reasons, or
/// operation/installation strings.
#[must_use]
fn preparation_error_category(error: &PreparationError) -> (&'static str, &'static str) {
    match *error {
        PreparationError::InvalidRequest { field, .. } => ("invalid_request", field),
        PreparationError::UnapprovedGeneration { .. } => ("unapproved_generation", "generation"),
        PreparationError::ArbitraryPath { .. } => ("arbitrary_path", "path"),
        PreparationError::SourceIsActive => ("source_is_active", "source_root"),
        PreparationError::ForeignContent { .. } => ("foreign_content", "destination_root"),
        PreparationError::AliasSubstitution { .. } => ("alias_substitution", "path"),
        PreparationError::IdentityConflict { .. } => ("identity_conflict", "root_identity"),
        PreparationError::ConflictField { field } => ("conflict_field", field),
        PreparationError::UnknownState { .. } => ("unknown_state", "operation"),
        PreparationError::JournalFault(_) => ("journal_fault", "journal"),
        PreparationError::PlatformUnsupported => ("platform_unsupported", "platform"),
        PreparationError::FilesystemEffect { .. } => ("filesystem_effect", "path"),
        PreparationError::SweepBudget { field, .. } => ("sweep_budget", field),
    }
}

/// Observes one nonterminal preparation phase outcome after the decision
/// exists. `approved_generation` is carried only once validated (else 0), and
/// `destination_epoch` only from a produced destination (else 0); 0 marks a
/// fact this boundary does not carry, never a real epoch.
fn observe_prepare_progress(
    op: &'static str,
    phase: &'static str,
    outcome: &'static str,
    approved_generation: u64,
    destination_epoch: u64,
) {
    backup_prepare_note_event_log_unavailable();
    let op = crate::host_diagnostics::bound_field(op);
    let phase = crate::host_diagnostics::bound_field(phase);
    let outcome = crate::host_diagnostics::bound_field(outcome);
    tracing::info!(
        target: crate::host_diagnostics::HOST_DIAGNOSTICS_TARGET,
        event = "host.backup.prepare_phase",
        op = op.text(),
        phase = phase.text(),
        outcome = outcome.text(),
        approved_generation = approved_generation,
        destination_epoch = destination_epoch,
        "host backup preparation phase observed"
    );
}

/// Observes one typed preparation refusal after the decision exists, then hands
/// the unchanged error back. Terminal ownership stays with the outer caller.
fn note_prepare_error(
    op: &'static str,
    phase: &'static str,
    error: PreparationError,
    approved_generation: u64,
) -> PreparationError {
    backup_prepare_note_event_log_unavailable();
    let (category, field) = preparation_error_category(&error);
    let op = crate::host_diagnostics::bound_field(op);
    let phase = crate::host_diagnostics::bound_field(phase);
    let category = crate::host_diagnostics::bound_field(category);
    let field = crate::host_diagnostics::bound_field(field);
    tracing::warn!(
        target: crate::host_diagnostics::HOST_DIAGNOSTICS_TARGET,
        event = "host.backup.prepare_refusal",
        op = op.text(),
        phase = phase.text(),
        category = category.text(),
        field = field.text(),
        approved_generation = approved_generation,
        "host backup preparation refused"
    );
    error
}

/// Closed preparation class set (issue #958, case 958/18 guard).
///
/// There is deliberately NO cutover/activation variant: preparation produces
/// fenced destinations only. A later dedicated cutover child owns activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationClass {
    /// Isolated restore rehearsal destination (fenced, no effects).
    IsolatedRestoreRehearsal,
}

impl PreparationClass {
    /// Canonical class token bound into the admission digest.
    ///
    /// The admission digest must discriminate the class, so the token is a
    /// closed `&'static str` rather than a `Debug` rendering: adding a variant
    /// forces a decision here instead of silently changing the digest input.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IsolatedRestoreRehearsal => "isolated_restore_rehearsal",
        }
    }
}

/// Destination admission: explicit, fully-bound request (issue #958, cases 958/5-7, 958/9).
///
/// Every authority input is presented evidence. `staging_parent` is an
/// explicitly admitted isolated-prep parent directory — never the source, never
/// an arbitrary client path (verified by the protected-root owner, not
/// trusted), and never outside the ELIOT protected contour.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DestinationAdmission {
    /// Operation identity (bounded text, unique per preparation).
    pub operation_id: String,
    /// Closed preparation class.
    pub class: PreparationClass,
    /// Source installation identity (bounded text; its root is never targeted).
    pub source_installation_id: String,
    /// Source installation root (observed read-only; never modified).
    pub source_root: PathBuf,
    /// Explicitly admitted staging parent (must exist, be a directory, not be
    /// or contain the source, be reparse-free, and lie inside the ELIOT
    /// protected contour; verified by the protected-root owner, never
    /// trusted as a name).
    pub staging_parent: PathBuf,
    /// Target build identity for the destination (bounded caller-presented
    /// text).
    ///
    /// Not owner-approved by name: the owner records reachable here carry
    /// approved artifact digests and no build-name field, so this stays the
    /// presented scope of the operation and is hashed into the admission
    /// digest as such. What is genuinely owner-approved for the build is the
    /// presented `build_digests` subset check against the owner artifact set.
    pub target_build: String,
    /// Target profile for the destination (bounded caller-presented text).
    ///
    /// Not owner-approved by name, for the same reason as
    /// [`DestinationAdmission::target_build`]: no owner source carries a
    /// profile name, and none is invented here.
    pub target_profile: String,
    /// Generation the caller claims as approved for the destination.
    pub approved_generation: u64,
    /// Authority generation the admission is checked against; must equal
    /// `approved_generation`.
    ///
    /// Owner-issued on the production path:
    /// [`DelegatedPreparation::prepare`] fills it from the committed
    /// activation fence ([`OwnerEvidence::authority_generation`]), so the
    /// comparison is against owner evidence rather than against a second
    /// value the same caller presented.
    pub authority_generation: u64,
    /// Config manifest digest the destination must match (hex64). On the
    /// delegated path this is the projected owner-issued configuration digest,
    /// never a caller-presented one.
    pub manifest_digest: String,
    /// Owner-issued configuration projection digest proved for this request
    /// (hex64). It binds the owner lease reference, approved generation,
    /// purge-ledger revision, owner authority state fence, owner-issued
    /// configuration/build digests and the optional forensic note, so the
    /// prepared-destination receipt names the exact configuration evidence
    /// that was proved.
    pub config_projection_digest: String,
    /// Optional rendered forensic audit note, with its non-authoritative
    /// ceiling stated by [`describe_audit_fence`]. It is carried as evidence
    /// text only and can never act as a lease, grant, or current-state
    /// assertion; no API converts it into one.
    pub audit_fence_note: Option<String>,
    /// Opaque owner-issued entropy for fresh identity derivation (bounded text).
    pub authority_nonce: String,
    /// Caller-observed state fence bound into the receipt.
    pub state_fence_digest: String,
}

impl DestinationAdmission {
    /// Redacted debug: digests truncated, never full values in logs (case 958/16).
    pub fn redacted_debug(&self) -> String {
        format!(
            "DestinationAdmission {{ operation_id: {}, class: {:?}, installation: {}, \
             target: {}:{}, generation: {}, manifest: {}.., config_projection: {}.., \
             audit_note: {}, nonce_len: {} }}",
            self.operation_id,
            self.class,
            self.source_installation_id,
            self.target_build,
            self.target_profile,
            self.approved_generation,
            self.manifest_digest.chars().take(16).collect::<String>(),
            self.config_projection_digest
                .chars()
                .take(16)
                .collect::<String>(),
            self.audit_fence_note.is_some(),
            self.authority_nonce.len(),
        )
    }
}

/// OS-pinned identity of a prepared root (volume + file index on Windows).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RootIdentity {
    /// Opaque OS identity text (`volume:index` on Windows).
    pub identity: String,
}

/// Prepared isolated destination: the only success output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedDestination {
    /// Operation identity that produced it.
    pub operation_id: String,
    /// Created destination root (under the admitted staging parent).
    pub root: PathBuf,
    /// Pinned OS identity captured at creation.
    pub root_identity: RootIdentity,
    /// Owner-minted destination identity (deterministic, never archive/caller copy).
    pub destination_id: String,
    /// Destination epoch minted for preparation scope (distinct from owner epochs).
    pub destination_epoch: u64,
    /// Admission receipt digest binding the admitted inputs.
    pub admission_digest: String,
    /// Owner-issued configuration projection digest this destination was
    /// admitted under (hex64). Present so the prepared-destination receipt
    /// states the proved configuration evidence directly instead of only
    /// through [`PreparedDestination::admission_digest`].
    pub config_projection_digest: String,
    /// Optional rendered forensic audit note, with its non-authoritative
    /// ceiling stated. Evidence text only; never a lease, grant, or
    /// current-state assertion.
    pub audit_fence_note: Option<String>,
}

/// Reconcile disposition for one operation (issue #958, cases 958/12, 958/14).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileDisposition {
    /// No intent recorded: safe to prepare (or absent entirely).
    Absent,
    /// Recorded result re-verified against the live root: reuse, do not duplicate.
    Current(PreparedDestination),
    /// State cannot be established: preserved as-is, never deleted, never retried blindly.
    Uncertain { reason: String },
}

/// Cleanup report: removed owned-unactivated roots vs preserved unknowns.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CleanupReport {
    /// Operation ids whose owned roots were removed.
    pub removed: Vec<String>,
    /// Operation ids preserved with reasons (unknown/foreign/mismatch).
    pub preserved: Vec<(String, String)>,
}

/// Durable intent/result sink port (issue #958).
///
/// Implemented by `HostComposition` over the installation/Host journal at
/// delegation; tests use an in-memory sink. Synchronous narrow port: record
/// intent before effects, result after; load-before-act for idempotency.
pub trait PreparationJournal {
    /// Records the preparation intent (admission digest + derived root).
    fn record_intent(
        &mut self,
        operation_id: &str,
        intent: &serde_json::Value,
    ) -> Result<(), PreparationError>;
    /// Records the preparation result (receipt).
    fn record_result(
        &mut self,
        operation_id: &str,
        result: &serde_json::Value,
    ) -> Result<(), PreparationError>;
    /// Loads `(intent, Option<result>)` for one operation.
    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<(serde_json::Value, Option<serde_json::Value>)>, PreparationError>;
    /// Lists known operation ids for sweeps.
    fn list_operations(&self) -> Result<Vec<String>, PreparationError>;
}

fn check_identity(value: &str, field: &'static str) -> Result<(), PreparationError> {
    if value.is_empty() || value.len() > MAX_IDENTITY_LEN || value.chars().any(char::is_control) {
        return Err(PreparationError::InvalidRequest {
            field,
            reason: "bounded printable text required".to_owned(),
        });
    }
    Ok(())
}

fn check_digest(value: &str, field: &'static str) -> Result<(), PreparationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(PreparationError::InvalidRequest {
            field,
            reason: "64 lowercase hex chars required".to_owned(),
        });
    }
    Ok(())
}

/// Bounds the rendered forensic audit note carried in an admission (case 958/3).
///
/// The note text is produced by
/// [`describe_audit_fence`](crate::backup_config_projection::describe_audit_fence)
/// from already-validated note fields, so this is purely a receipt-size and
/// printable-text bound. There is deliberately no authority check here because
/// the note can never be a lease, grant, or current-state assertion.
fn check_audit_note(note: &str) -> Result<(), PreparationError> {
    if note.is_empty() || note.len() > MAX_AUDIT_NOTE_LEN || note.chars().any(char::is_control) {
        return Err(PreparationError::InvalidRequest {
            field: "audit_fence_note",
            reason: "bounded printable forensic note text required".to_owned(),
        });
    }
    Ok(())
}

fn sha_hex(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    format!("{:x}", hasher.finalize())
}

/// Owner-minted destination identity (issue #958, case 958/9).
///
/// Deterministic domain-separated derivation from the operation identity plus
/// owner nonce: fresh per operation, stable across repeats, and never equal
/// to archive-supplied or caller-chosen values (which live outside this domain).
#[must_use]
pub fn derive_destination_id(operation_id: &str, authority_nonce: &str) -> String {
    sha_hex(&[
        DESTINATION_ID_DOMAIN.as_bytes(),
        b"\0identity\0",
        operation_id.as_bytes(),
        b"\0",
        authority_nonce.as_bytes(),
    ])
}

/// Owner-minted preparation epoch (same properties as the destination identity).
#[must_use]
pub fn derive_destination_epoch(operation_id: &str, authority_nonce: &str) -> u64 {
    let digest = sha_hex(&[
        DESTINATION_ID_DOMAIN.as_bytes(),
        b"\0epoch\0",
        operation_id.as_bytes(),
        b"\0",
        authority_nonce.as_bytes(),
    ]);
    u64::from_le_bytes(digest.as_bytes()[..8].try_into().unwrap_or([0; 8])).max(1)
}

/// Hashes a path through its lossless platform byte encoding.
///
/// `Path::to_string_lossy` maps unpaired surrogates to U+FFFD, so two distinct
/// roots can share one digest. The admission digest exists to discriminate the
/// admitted inputs (I5.27), so the raw OS bytes are hashed instead and a
/// substituted root can never reuse a recorded digest.
#[cfg(windows)]
fn hash_path(hasher: &mut Sha256, label: &[u8], path: &Path) {
    use std::os::windows::ffi::OsStrExt as _;
    let units: Vec<u8> = path
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect();
    hash_field(hasher, label, &units);
}

#[cfg(not(windows))]
fn hash_path(hasher: &mut Sha256, label: &[u8], path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    hash_field(hasher, label, path.as_os_str().as_bytes());
}

/// Admission digest binding every admitted input (idempotency key).
///
/// v1 left `class`, `source_root` and `authority_generation` out of the hashed
/// set while `conflict_field` did compare `class`. The two lists disagreed, and
/// the disagreement was exploitable rather than cosmetic: `prepare_isolated_destination`
/// compares the recorded digest first and returns the recorded destination
/// without re-running [`admit_staging_parent`] when it matches, so re-presenting
/// a recorded `operation_id` with a different `class` or a different
/// `source_root` — including the live source installation root — hashed
/// identically, took the "same inputs" branch, and returned `Ok` with no
/// conflict, no naming, and no re-admission. I5.27: a field affecting authority
/// or scope cannot be omitted silently, and reusing an idempotency key with a
/// different canonical request hash must conflict.
///
/// v2 hashes every field of [`DestinationAdmission`], length-prefixed and
/// domain-separated, with paths encoded losslessly.
///
/// v3 adds the two configuration-projection fields. Leaving them out while
/// [`conflict_field`] compared them would recreate exactly the v2 defect one
/// level up: the delegated path proves the owner-issued configuration
/// projection and then carries `config_projection_digest` and
/// `audit_fence_note`, so an admission digest that hashed neither would let
/// two different proved configuration projections reuse one idempotency key
/// and return the same recorded destination.
fn admission_digest(admission: &DestinationAdmission) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"eliot.backup.destination-admission.v3\0");
    hasher.update(PREPARATION_VERSION.to_le_bytes());
    hash_field(
        &mut hasher,
        b"operation_id",
        admission.operation_id.as_bytes(),
    );
    hash_field(&mut hasher, b"class", admission.class.as_str().as_bytes());
    hash_field(
        &mut hasher,
        b"source_installation_id",
        admission.source_installation_id.as_bytes(),
    );
    hash_path(&mut hasher, b"source_root", &admission.source_root);
    hash_path(&mut hasher, b"staging_parent", &admission.staging_parent);
    hash_field(
        &mut hasher,
        b"target_build",
        admission.target_build.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"target_profile",
        admission.target_profile.as_bytes(),
    );
    hasher.update(b"approved_generation\0");
    hasher.update(admission.approved_generation.to_le_bytes());
    hasher.update(b"authority_generation\0");
    hasher.update(admission.authority_generation.to_le_bytes());
    hash_field(
        &mut hasher,
        b"manifest_digest",
        admission.manifest_digest.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"config_projection_digest",
        admission.config_projection_digest.as_bytes(),
    );
    match &admission.audit_fence_note {
        Some(note) => {
            hash_field(&mut hasher, b"audit_fence_note", b"present");
            hash_field(&mut hasher, b"audit_fence_note.text", note.as_bytes());
        }
        None => hash_field(&mut hasher, b"audit_fence_note", b"absent"),
    }
    hash_field(
        &mut hasher,
        b"authority_nonce",
        admission.authority_nonce.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"state_fence_digest",
        admission.state_fence_digest.as_bytes(),
    );
    format!("{:x}", hasher.finalize())
}

/// Reparse-point attribute test (case 958/8): the exact bit the OS check enforces.
#[must_use]
pub fn is_reparse_attributes(attributes: u32) -> bool {
    attributes & REPARSE_POINT_ATTRIBUTE != 0
}

/// Windows `FILE_ATTRIBUTE_REPARSE_POINT` value, named for the check above.
pub const REPARSE_POINT_ATTRIBUTE: u32 = 0x400;

/// Rejects reparse points / alias substitution on an admitted path (case 958/8).
#[cfg(windows)]
fn reject_reparse(path: &Path) -> Result<(), PreparationError> {
    use std::os::windows::fs::MetadataExt as _;

    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| PreparationError::FilesystemEffect {
            path: path.to_string_lossy().into_owned(),
            reason: format!("cannot stat admitted path: {error}"),
        })?;
    if metadata.file_type().is_symlink() {
        return Err(PreparationError::AliasSubstitution {
            path: path.to_string_lossy().into_owned(),
        });
    }
    if is_reparse_attributes(metadata.file_attributes()) {
        return Err(PreparationError::AliasSubstitution {
            path: path.to_string_lossy().into_owned(),
        });
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_reparse(_path: &Path) -> Result<(), PreparationError> {
    Err(PreparationError::PlatformUnsupported)
}

/// Captures the OS identity of a root (volume + file index on Windows).
///
/// Identity observation belongs to the platform-windows owner: this calls
/// [`eliot_platform_windows::directory_identity_for_path`], which opens the
/// directory without following reparse points and reads the stable identity
/// from the opened handle. Host only formats the observed identity into the
/// preparation receipt and never touches a raw handle, so this module stays
/// under the crate's `#![forbid(unsafe_code)]`.
#[cfg(windows)]
fn capture_identity(path: &Path) -> Result<RootIdentity, PreparationError> {
    eliot_platform_windows::directory_identity_for_path(path)
        .map(|identity| RootIdentity {
            identity: file_identity_text(identity),
        })
        .map_err(|error| PreparationError::FilesystemEffect {
            path: path.to_string_lossy().into_owned(),
            reason: format!("root identity query failed: {error}"),
        })
}

#[cfg(not(windows))]
fn capture_identity(_path: &Path) -> Result<RootIdentity, PreparationError> {
    Err(PreparationError::PlatformUnsupported)
}

/// Renders one observed [`FileIdentity`] as the receipt identity text.
///
/// One canonical rendering is shared by creation-time capture and by every
/// later re-verification, so a recorded identity and a freshly observed one
/// are always compared as the same encoding instead of two independently
/// maintained formats that can drift into a false conflict.
fn file_identity_text(identity: FileIdentity) -> String {
    format!("{}:{}", identity.volume_serial_number, identity.file_index)
}

/// Maps protected-path owner failures to the typed preparation failure that
/// fits, following the [`projection_to_preparation`] precedent.
///
/// Every owner variant maps to an existing [`PreparationError`]; none is
/// stringified into a generic code and no variant is invented. Owner internals
/// are not echoed: each reason is a static sentence naming the refused
/// property. Both protected-root callers share this mapping — the recorded
/// destination re-proof ([`reverify_recorded_destination`]) and the presented
/// staging parent ([`verify_staging_parent_lease`]) — so the sentences are
/// worded for a path rather than for a recorded one.
fn protected_path_to_preparation(
    operation_id: &str,
    path: &Path,
    error: ProtectedPathError,
) -> PreparationError {
    let refused = path.to_string_lossy().into_owned();
    match error {
        ProtectedPathError::InvalidRoot => PreparationError::ArbitraryPath {
            reason: "protected contour root is not resolvable".to_owned(),
        },
        ProtectedPathError::InvalidPath => PreparationError::ArbitraryPath {
            reason: "path is outside the protected contour".to_owned(),
        },
        ProtectedPathError::ReparsePoint => PreparationError::AliasSubstitution { path: refused },
        ProtectedPathError::AclMismatch => PreparationError::FilesystemEffect {
            path: refused,
            reason: "protected root ACL does not match owner policy".to_owned(),
        },
        ProtectedPathError::Io => PreparationError::FilesystemEffect {
            path: refused,
            reason: "protected root I/O failed".to_owned(),
        },
        ProtectedPathError::IdentityMismatch => PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason: "protected root identity changed under the retained handle".to_owned(),
        },
        ProtectedPathError::Win32 { .. } => PreparationError::FilesystemEffect {
            path: refused,
            reason: "protected root owner call failed".to_owned(),
        },
        ProtectedPathError::SizeExceeded => PreparationError::ArbitraryPath {
            reason: "protected root exceeded its bounded limit".to_owned(),
        },
        ProtectedPathError::UnsupportedPlatform => PreparationError::PlatformUnsupported,
    }
}

/// Re-proves one recorded destination through the real protected-root owner.
///
/// A recorded receipt is evidence of a past effect, not proof of a live root.
/// Before a recorded destination is reused ([`reconcile_preparation`]) or
/// removed ([`cleanup_preparations`]), the recorded root is re-opened through
/// [`ProtectedRootLease::open_existing`] — the owner that containment-checks
/// the path and pins the whole directory contour by retained handle — and only
/// then are the canonical path, the retained-handle alias defence
/// ([`ProtectedRootLease::verify_stable_identity`]) and the owner-observed
/// [`FileIdentity`] compared against the recorded values. Any failure is a
/// typed [`PreparationError`]: the recorded root is no longer an owned
/// protected object, and the caller preserves it rather than acting on a name.
fn reverify_recorded_destination(
    operation_id: &str,
    destination: &PreparedDestination,
) -> Result<(), PreparationError> {
    let recorded = &destination.root;
    let lease = ProtectedRootLease::open_existing(recorded)
        .map_err(|error| protected_path_to_preparation(operation_id, recorded, error))?;
    let canonical = lease
        .canonical_path()
        .map_err(|error| protected_path_to_preparation(operation_id, recorded, error))?;
    if !windows_paths_equal(&canonical, recorded) {
        return Err(PreparationError::ArbitraryPath {
            reason: "recorded root differs from the retained protected-root identity".to_owned(),
        });
    }
    lease
        .verify_stable_identity()
        .map_err(|error| protected_path_to_preparation(operation_id, recorded, error))?;
    let observed = file_identity_text(lease.identity());
    if observed != destination.root_identity.identity {
        return Err(PreparationError::IdentityConflict {
            operation: operation_id.to_owned(),
            recorded: destination.root_identity.identity.clone(),
            observed,
        });
    }
    Ok(())
}

/// Validates one admission without effects (cases 958/5-7).
///
/// The generation arm compares [`DestinationAdmission::approved_generation`]
/// against [`DestinationAdmission::authority_generation`], and that is only a
/// real check when the second value came from owner evidence:
/// [`DelegatedPreparation::prepare`] fills it from
/// [`OwnerEvidence::authority_generation`], so the production path refuses an
/// unapproved generation (case 958/7). The shape checks here are unchanged and
/// stay shape checks: `target_build` and `target_profile` are bounded text with
/// no name-level owner approval, and the presented `build_digests` subset check
/// is what approves a build (see the module documentation).
fn validate_admission(admission: &DestinationAdmission) -> Result<(), PreparationError> {
    check_identity(&admission.operation_id, "operation_id")?;
    check_identity(&admission.source_installation_id, "source_installation_id")?;
    check_identity(&admission.target_build, "target_build")?;
    check_identity(&admission.target_profile, "target_profile")?;
    check_digest(&admission.manifest_digest, "manifest_digest")?;
    check_digest(
        &admission.config_projection_digest,
        "config_projection_digest",
    )?;
    if let Some(note) = &admission.audit_fence_note {
        check_audit_note(note)?;
    }
    check_digest(&admission.state_fence_digest, "state_fence_digest")?;
    check_identity(&admission.authority_nonce, "authority_nonce")?;
    if admission.approved_generation == 0 {
        return Err(PreparationError::InvalidRequest {
            field: "approved_generation",
            reason: "generation must be nonzero".to_owned(),
        });
    }
    if admission.approved_generation != admission.authority_generation {
        return Err(PreparationError::UnapprovedGeneration {
            approved: admission.approved_generation,
            authority: admission.authority_generation,
        });
    }
    Ok(())
}

/// Admits a staging parent: exists, directory, reparse-free, neither the
/// source root nor nested under it, and proved by the protected-root owner
/// (cases 958/5-6, 958/7, 958/8).
///
/// The structural checks alone admit any existing unrelated directory, so they
/// are not the whole admission. After they pass, the parent is proved through
/// [`verify_staging_parent_lease`]: the real
/// [`ProtectedRootLease::open_existing`] containment-checks it against the
/// ELIOT protected contour and pins the whole directory chain by retained
/// handle, and the returned parent is that owner-resolved canonical path. A
/// client-supplied arbitrary path is therefore refused (case 958/7) instead of
/// becoming a destination parent, and the parent every root is created under
/// is one that [`reverify_recorded_destination`] can re-prove before removal, so
/// the cleanup removal path is reachable for every root created here (case
/// 958/15).
fn admit_staging_parent(admission: &DestinationAdmission) -> Result<PathBuf, PreparationError> {
    let parent = &admission.staging_parent;
    let metadata =
        std::fs::symlink_metadata(parent).map_err(|_| PreparationError::ArbitraryPath {
            reason: "staging parent must exist before admission".to_owned(),
        })?;
    if !metadata.is_dir() {
        return Err(PreparationError::ArbitraryPath {
            reason: "staging parent must be a directory".to_owned(),
        });
    }
    reject_reparse(parent)?;
    let canonical_parent =
        std::fs::canonicalize(parent).map_err(|error| PreparationError::FilesystemEffect {
            path: parent.to_string_lossy().into_owned(),
            reason: format!("cannot canonicalize staging parent: {error}"),
        })?;
    let canonical_source = std::fs::canonicalize(&admission.source_root).map_err(|error| {
        PreparationError::FilesystemEffect {
            path: admission.source_root.to_string_lossy().into_owned(),
            reason: format!("cannot canonicalize source root: {error}"),
        }
    })?;
    if canonical_parent == canonical_source {
        return Err(PreparationError::SourceIsActive);
    }
    if canonical_parent.starts_with(&canonical_source) {
        return Err(PreparationError::ArbitraryPath {
            reason: "staging parent nested under the active source is refused".to_owned(),
        });
    }
    // Owner proof last, so the structural refusals above keep their exact
    // category and a name that never resolved the protected contour is refused
    // as the arbitrary path it is.
    verify_staging_parent_lease(&admission.operation_id, parent)
}

fn intent_json(admission: &DestinationAdmission, digest: &str, root: &Path) -> serde_json::Value {
    serde_json::json!({
        "version": PREPARATION_VERSION,
        "operation_id": admission.operation_id,
        "admission_digest": digest,
        "admission": admission,
        "root": root.to_string_lossy(),
    })
}

/// Names the first differing admission field between the recorded intent and
/// a changed re-presentation (case 958/13).
///
/// The compared list mirrors the v3 [`admission_digest`] hashed set exactly.
/// `source_root` was missing here while being the field that decides which
/// installation is the live source, so a conflict could never name it.
fn conflict_field(intent: &serde_json::Value, admission: &DestinationAdmission) -> &'static str {
    let recorded = intent.get("admission");
    let current = serde_json::to_value(admission).unwrap_or(serde_json::Value::Null);
    for field in [
        "class",
        "source_installation_id",
        "source_root",
        "staging_parent",
        "target_build",
        "target_profile",
        "approved_generation",
        "authority_generation",
        "manifest_digest",
        "config_projection_digest",
        "audit_fence_note",
        "authority_nonce",
        "state_fence_digest",
    ] {
        if recorded.and_then(|value| value.get(field)) != current.get(field) {
            return field;
        }
    }
    "admission"
}

fn result_json(destination: &PreparedDestination) -> serde_json::Value {
    serde_json::json!({
        "version": PREPARATION_VERSION,
        "operation_id": destination.operation_id,
        "root": destination.root.to_string_lossy(),
        "root_identity": destination.root_identity.identity,
        "destination_id": destination.destination_id,
        "destination_epoch": destination.destination_epoch,
        "admission_digest": destination.admission_digest,
        "config_projection_digest": destination.config_projection_digest,
        "audit_fence_note": destination.audit_fence_note,
    })
}

fn destination_from_result(
    operation_id: &str,
    result: &serde_json::Value,
) -> Option<PreparedDestination> {
    let audit_fence_note = match result.get("audit_fence_note") {
        Some(serde_json::Value::String(text)) => Some(text.clone()),
        Some(serde_json::Value::Null) | None => None,
        // A present but wrong-typed note is a malformed record, not an absent
        // one: treating it as absent would let a tampered result round-trip.
        Some(_) => return None,
    };
    Some(PreparedDestination {
        operation_id: operation_id.to_owned(),
        root: PathBuf::from(result.get("root")?.as_str()?),
        root_identity: RootIdentity {
            identity: result.get("root_identity")?.as_str()?.to_owned(),
        },
        destination_id: result.get("destination_id")?.as_str()?.to_owned(),
        destination_epoch: result.get("destination_epoch")?.as_u64()?,
        admission_digest: result.get("admission_digest")?.as_str()?.to_owned(),
        config_projection_digest: result.get("config_projection_digest")?.as_str()?.to_owned(),
        audit_fence_note,
    })
}

/// Prepares one isolated destination (issue #958, cases 958/5-7, 958/9, 958/12).
///
/// Order: validate → ledger/journal idempotency (same inputs return the
/// recorded destination; changed inputs conflict by field) → record intent →
/// admit parent → create root → pin identity → record result. The source root
/// is only ever read for comparison, never modified.
#[allow(
    clippy::too_many_lines,
    reason = "the preparation order (validate, replay, intent, admit, effect, identity, result) stays in one boundary so no phase observation can be skipped between neighbors"
)]
pub fn prepare_isolated_destination<J: PreparationJournal>(
    journal: &mut J,
    admission: &DestinationAdmission,
) -> Result<PreparedDestination, PreparationError> {
    // Static attempt record before validation; the operation id is unvalidated
    // caller text here and is never logged.
    observe_prepare_progress(OP_PREPARE, "attempt", "attempted", 0, 0);
    validate_admission(admission)
        .map_err(|error| note_prepare_error(OP_PREPARE, "validate", error, 0))?;
    let generation = admission.approved_generation;
    let digest = admission_digest(admission);
    let recorded_entry = journal
        .load(&admission.operation_id)
        .map_err(|error| note_prepare_error(OP_PREPARE, "replay_check", error, generation))?;
    if let Some((intent, result)) = recorded_entry {
        let recorded = intent
            .get("admission_digest")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if recorded != digest {
            return Err(note_prepare_error(
                OP_PREPARE,
                "replay_check",
                PreparationError::ConflictField {
                    field: conflict_field(&intent, admission),
                },
                generation,
            ));
        }
        if let Some(result) = result {
            if let Some(destination) = destination_from_result(&admission.operation_id, &result) {
                let live = capture_identity(&destination.root)
                    .map_err(|_| PreparationError::UnknownState {
                        operation: admission.operation_id.clone(),
                        reason: "recorded root no longer observable; preserved".to_owned(),
                    })
                    .map_err(|error| {
                        note_prepare_error(OP_PREPARE, "replay_check", error, generation)
                    })?;
                if live != destination.root_identity {
                    return Err(note_prepare_error(
                        OP_PREPARE,
                        "replay_check",
                        PreparationError::IdentityConflict {
                            operation: admission.operation_id.clone(),
                            recorded: destination.root_identity.identity.clone(),
                            observed: live.identity.clone(),
                        },
                        generation,
                    ));
                }
                // Observed replay, not a second effect: the recorded
                // destination is re-verified and reused unchanged.
                observe_prepare_progress(
                    OP_PREPARE,
                    "replay_check",
                    "replay_observed",
                    generation,
                    destination.destination_epoch,
                );
                return Ok(destination);
            }
            return Err(note_prepare_error(
                OP_PREPARE,
                "replay_check",
                PreparationError::UnknownState {
                    operation: admission.operation_id.clone(),
                    reason: "result record malformed; preserved for inspection".to_owned(),
                },
                generation,
            ));
        }
        // Intent without result: a crash between intent and result recording.
        // Root absent means nothing exists: fall through and prepare fresh
        // (the intent is overwritten below). Root present means unverified
        // effects: refuse here; reconcile first.
        let intent_root = intent
            .get("root")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if !intent_root.is_empty() && Path::new(intent_root).exists() {
            return Err(note_prepare_error(
                OP_PREPARE,
                "replay_check",
                PreparationError::UnknownState {
                    operation: admission.operation_id.clone(),
                    reason:
                        "intent without verifiable result and root present; reconcile before retry"
                            .to_owned(),
                },
                generation,
            ));
        }
    }
    let canonical_parent = admit_staging_parent(admission)
        .map_err(|error| note_prepare_error(OP_PREPARE, "admit_parent", error, generation))?;
    let destination_id = derive_destination_id(&admission.operation_id, &admission.authority_nonce);
    let root = canonical_parent.join(format!("dest-{destination_id}"));
    if root.exists() {
        return Err(note_prepare_error(
            OP_PREPARE,
            "create_root",
            PreparationError::ForeignContent {
                path: root.to_string_lossy().into_owned(),
            },
            generation,
        ));
    }
    journal
        .record_intent(
            &admission.operation_id,
            &intent_json(admission, &digest, &root),
        )
        .map_err(|error| note_prepare_error(OP_PREPARE, "record_intent", error, generation))?;
    std::fs::create_dir(&root)
        .map_err(|error| PreparationError::FilesystemEffect {
            path: root.to_string_lossy().into_owned(),
            reason: format!("destination creation failed: {error}"),
        })
        .map_err(|error| note_prepare_error(OP_PREPARE, "create_root", error, generation))?;
    let identity = capture_identity(&root)
        .map_err(|error| note_prepare_error(OP_PREPARE, "capture_identity", error, generation))?;
    let destination = PreparedDestination {
        operation_id: admission.operation_id.clone(),
        root: root.clone(),
        root_identity: identity,
        destination_id,
        destination_epoch: derive_destination_epoch(
            &admission.operation_id,
            &admission.authority_nonce,
        ),
        admission_digest: digest,
        config_projection_digest: admission.config_projection_digest.clone(),
        audit_fence_note: admission.audit_fence_note.clone(),
    };
    journal
        .record_result(&admission.operation_id, &result_json(&destination))
        .map_err(|error| note_prepare_error(OP_PREPARE, "record_result", error, generation))?;
    // Fresh preparation observed; this asserts a fenced destination only,
    // never readiness, retirement, or activation.
    observe_prepare_progress(
        OP_PREPARE,
        "complete",
        "prepared_fresh",
        generation,
        destination.destination_epoch,
    );
    Ok(destination)
}

/// Reconciles one operation without duplicating effects (cases 958/12, 958/14).
///
/// Absent (no intent, or intent whose root never materialized) → `Absent` and
/// retry may proceed. Intent + verifiable result → `Current`, and only after
/// the recorded root is re-proved through the real protected-root owner
/// ([`reverify_recorded_destination`]): a receipt alone is not a live root.
/// Anything else → `Uncertain`: preserved as-is, never deleted, never blindly
/// retried. Reconciliation never deletes.
pub fn reconcile_preparation<J: PreparationJournal>(
    journal: &J,
    operation_id: &str,
) -> Result<ReconcileDisposition, PreparationError> {
    check_identity(operation_id, "operation_id")
        .map_err(|error| note_prepare_error(OP_RECONCILE, "validate", error, 0))?;
    // Intent proves the operation was admitted; its digest binds the inputs.
    let recorded = journal
        .load(operation_id)
        .map_err(|error| note_prepare_error(OP_RECONCILE, "load", error, 0))?;
    let Some((intent, result)) = recorded else {
        observe_prepare_progress(OP_RECONCILE, "outcome", "absent", 0, 0);
        return Ok(ReconcileDisposition::Absent);
    };
    let Some(result) = result else {
        // Intent without result: a crash between intent recording and effect
        // completion. Root absent means nothing exists (a fresh prepare may
        // proceed and overwrites the intent); root present means unverified
        // effects (preserve, never duplicate).
        let root_absent = intent
            .get("root")
            .and_then(|value| value.as_str())
            .is_none_or(|root| !Path::new(root).exists());
        if root_absent {
            observe_prepare_progress(OP_RECONCILE, "outcome", "absent", 0, 0);
            return Ok(ReconcileDisposition::Absent);
        }
        observe_prepare_progress(OP_RECONCILE, "outcome", "uncertain", 0, 0);
        return Ok(ReconcileDisposition::Uncertain {
            reason: "intent recorded without result and root present; effects unverified"
                .to_owned(),
        });
    };
    let Some(destination) = destination_from_result(operation_id, &result) else {
        observe_prepare_progress(OP_RECONCILE, "outcome", "uncertain", 0, 0);
        return Ok(ReconcileDisposition::Uncertain {
            reason: "result record malformed; preserved for inspection".to_owned(),
        });
    };
    match reverify_recorded_destination(operation_id, &destination) {
        Ok(()) => {
            observe_prepare_progress(
                OP_RECONCILE,
                "outcome",
                "current",
                0,
                destination.destination_epoch,
            );
            Ok(ReconcileDisposition::Current(destination))
        }
        Err(error) => {
            // The failure text names recorded paths; only the uncertain
            // outcome is observed, never the error content.
            observe_prepare_progress(OP_RECONCILE, "outcome", "uncertain", 0, 0);
            Ok(ReconcileDisposition::Uncertain {
                reason: error.to_string(),
            })
        }
    }
}

/// Cancels one prepared operation (case 958/15).
///
/// Only a currently `Current` preparation may cancel; the cancel envelope
/// embeds the prior receipt so no evidence is destroyed. Absent operations
/// cannot be cancelled; uncertain ones must reconcile first.
pub fn cancel_preparation<J: PreparationJournal>(
    journal: &mut J,
    operation_id: &str,
) -> Result<(), PreparationError> {
    match reconcile_preparation(journal, operation_id)
        .map_err(|error| note_prepare_error(OP_CANCEL, "reconcile", error, 0))?
    {
        ReconcileDisposition::Current(destination) => {
            let mut envelope = result_json(&destination);
            envelope["status"] = serde_json::Value::String("cancelled".to_owned());
            envelope["prior_receipt"] = result_json(&destination);
            journal
                .record_result(operation_id, &envelope)
                .map_err(|error| note_prepare_error(OP_CANCEL, "record_result", error, 0))?;
            observe_prepare_progress(OP_CANCEL, "outcome", "cancelled", 0, 0);
            Ok(())
        }
        ReconcileDisposition::Absent => Err(note_prepare_error(
            OP_CANCEL,
            "outcome",
            PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "nothing recorded; nothing to cancel".to_owned(),
            },
            0,
        )),
        ReconcileDisposition::Uncertain { reason } => Err(note_prepare_error(
            OP_CANCEL,
            "outcome",
            PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: format!("reconcile first: {reason}"),
            },
            0,
        )),
    }
}

/// Cleans up owned unactivated destinations (case 958/15).
///
/// The sweep set comes from the journal's own operation list — the journal
/// owns its key set — and an explicitly requested id narrows that set instead
/// of extending it. A requested id the journal does not own is refused into
/// [`CleanupReport::preserved`]; a caller can never nominate a deletion.
///
/// Removal happens only for a reconciled `Current` destination whose recorded
/// root is re-proved through the real protected-root owner immediately before
/// the irreversible delete ([`reverify_recorded_destination`], applied again
/// here so the proof is adjacent to the effect, not merely somewhere earlier
/// in the reconcile). Anything uncertain, foreign, mismatched, unleased, or
/// source-related is preserved with its reason. Never deletes by bare path
/// name: every removal is keyed by operation id through the journal, and
/// `ARCH-RES-03` (A13.7) holds — recovery preserves what it cannot prove it
/// owns. That removal is reachable at all because
/// [`admit_staging_parent`] proved every parent through the same protected
/// contour this re-proof requires.
///
/// The sweep is budgeted (case 958/16, A13.9): the presented narrowing list is
/// bounded by [`MAX_CLEANUP_REQUESTED_IDS`], the journal-owned set by
/// [`MAX_CLEANUP_SWEEP_OPERATIONS`], and elapsed time by
/// [`CLEANUP_SWEEP_BUDGET`]. A bound that is reached refuses the sweep with
/// [`PreparationError::SweepBudget`] — it never truncates the set, because a
/// silent truncation would report a partial sweep as complete and strand owned
/// roots that still exist. Every operation already swept in that call had been
/// individually re-proven owned before its removal, and the remainder stays
/// reconcilable by the next bounded pass.
pub fn cleanup_preparations<J: PreparationJournal>(
    journal: &J,
    operation_ids: &[String],
) -> Result<CleanupReport, PreparationError> {
    let budget_start = Instant::now();
    if operation_ids.len() > MAX_CLEANUP_REQUESTED_IDS {
        return Err(sweep_budget_refusal(
            "requested_operation_ids",
            "presented narrowing list exceeds the bounded sweep size",
        ));
    }
    let mut report = CleanupReport::default();
    let owned = journal
        .list_operations()
        .map_err(|error| note_prepare_error(OP_CLEANUP, "list", error, 0))?;
    // The count bound applies to the set this call will actually SWEEP, not to
    // the journal's whole history. A journal grows by one operation per
    // preparation, so bounding the full owned set would refuse every future
    // cleanup once the count was passed — including a caller that named one
    // specific operation — with no way to make progress again. A non-empty
    // narrowing list is already capped by MAX_CLEANUP_REQUESTED_IDS above, so
    // the effective set needs no second bound.
    let effective = if operation_ids.is_empty() {
        owned.len()
    } else {
        owned
            .iter()
            .filter(|operation_id| operation_ids.contains(operation_id))
            .count()
    };
    if effective > MAX_CLEANUP_SWEEP_OPERATIONS {
        return Err(sweep_budget_refusal(
            "swept_operations",
            "the effective sweep set exceeds the bounded sweep size",
        ));
    }
    // The clock starts before the owned set is listed, because that listing is
    // the journal's own cost and an implementor's is unbounded; the first check
    // is after it returns, since the call itself cannot be interrupted.
    if budget_start.elapsed() >= CLEANUP_SWEEP_BUDGET {
        return Err(sweep_budget_refusal(
            "sweep_elapsed",
            "sweep budget exhausted before any operation was swept",
        ));
    }
    for requested in operation_ids {
        if !owned.contains(requested) {
            // Refused, never deleted: a caller can never nominate a deletion.
            // The requested id itself is unowned caller text and is not logged.
            observe_prepare_progress(OP_CLEANUP, "sweep", "refused_not_owned", 0, 0);
            report.preserved.push((
                requested.clone(),
                "operation is not owned by this journal; refused, never deleted".to_owned(),
            ));
        }
    }
    for operation_id in &owned {
        if !operation_ids.is_empty() && !operation_ids.contains(operation_id) {
            continue;
        }
        if budget_start.elapsed() >= CLEANUP_SWEEP_BUDGET {
            // Removals already performed in THIS call are named in the refusal.
            // Returning a bare error here would discard the only record of roots
            // this module already deleted, which is evidence loss immediately
            // after an irreversible effect.
            return Err(sweep_budget_refusal(
                "sweep_elapsed",
                "sweep budget exhausted; the remainder is preserved for a later pass",
            )
            .with_removed(&report.removed));
        }
        match reconcile_preparation(journal, operation_id)
            .map_err(|error| note_prepare_error(OP_CLEANUP, "reconcile", error, 0))?
        {
            ReconcileDisposition::Current(destination) => {
                remove_reverified_destination(operation_id, &destination, &mut report);
            }
            ReconcileDisposition::Absent => {
                observe_prepare_progress(OP_CLEANUP, "sweep", "absent", 0, 0);
                report
                    .preserved
                    .push((operation_id.clone(), "nothing recorded".to_owned()));
            }
            ReconcileDisposition::Uncertain { reason } => {
                observe_prepare_progress(OP_CLEANUP, "sweep", "preserved", 0, 0);
                report.preserved.push((operation_id.clone(), reason));
            }
        }
    }
    Ok(report)
}

/// One typed refusal for a cleanup sweep that reached an explicit bound.
///
/// Bound exhaustion is a refusal, not a partial success: the sweep stops, the
/// operation after the last completed one is never reconciled or removed, and
/// the static reason names the bound without naming a path, identity, or count.
/// The budget facts are not observed numerically because the observation
/// contract admits only validated generation/epoch facts, so a count or a
/// duration is reported as this stable category plus its static field only.
///
/// When the refusal follows removals that already happened in the same call, the
/// caller appends those operation ids to the reason through `with_removed`. A
/// budget error that arrived after irreversible effects must never hide which
/// effects occurred, so the removed set travels with the refusal instead of
/// being dropped with the local report.
fn sweep_budget_refusal(field: &'static str, reason: &'static str) -> PreparationError {
    note_prepare_error(
        OP_CLEANUP,
        "budget",
        PreparationError::SweepBudget {
            field,
            reason: reason.to_owned(),
        },
        0,
    )
}

/// Removes one re-proven owned root, or preserves it with the reason.
///
/// The protected-root proof is repeated here, immediately before the
/// irreversible effect: [`reconcile_preparation`] proves the recorded root at
/// reconcile time, and this is the last chance to notice that the object at
/// that path is no longer the one this lane created.
fn remove_reverified_destination(
    operation_id: &str,
    destination: &PreparedDestination,
    report: &mut CleanupReport,
) {
    if let Err(error) = reverify_recorded_destination(operation_id, destination) {
        observe_prepare_progress(OP_CLEANUP, "remove", "preserved", 0, 0);
        report
            .preserved
            .push((operation_id.to_owned(), error.to_string()));
        return;
    }
    match std::fs::remove_dir_all(&destination.root) {
        Ok(()) => {
            observe_prepare_progress(OP_CLEANUP, "remove", "removed", 0, 0);
            report.removed.push(operation_id.to_owned());
        }
        Err(error) => {
            observe_prepare_progress(OP_CLEANUP, "remove", "preserved", 0, 0);
            report.preserved.push((
                operation_id.to_owned(),
                format!("removal failed, preserved: {error}"),
            ));
        }
    }
}

/// Resolves the source installation root from manifest-bound owner runtime
/// roots: validates the owner topology, then returns the canonical
/// installation root that preparation must treat as the active source. The
/// source is observed read-only for comparison and never modified.
///
/// Fail-closed with static reasons: a topology violation yields
/// [`PreparationError::InvalidRequest`], a non-directory yields
/// [`PreparationError::ArbitraryPath`], and an unresolvable root yields
/// [`PreparationError::FilesystemEffect`]. Owner error internals are never
/// echoed. Staging admission, generation/lease authority, and journal
/// binding stay with [`prepare_isolated_destination`] and HostComposition
/// delegation.
pub fn resolve_owner_source_root(roots: &RuntimeStateRoots) -> Result<PathBuf, PreparationError> {
    roots
        .validate()
        .map_err(|_| PreparationError::InvalidRequest {
            field: "source_roots",
            reason: "owner runtime roots violate topology".to_owned(),
        })
        .map_err(|error| note_prepare_error(OP_SOURCE_ROOT, "resolve", error, 0))?;
    let canonical = std::fs::canonicalize(roots.installation_root.as_str())
        .map_err(|error| PreparationError::FilesystemEffect {
            path: roots.installation_root.as_str().to_owned(),
            reason: format!("cannot canonicalize owner installation root: {error}"),
        })
        .map_err(|error| note_prepare_error(OP_SOURCE_ROOT, "resolve", error, 0))?;
    if !canonical.is_dir() {
        return Err(note_prepare_error(
            OP_SOURCE_ROOT,
            "resolve",
            PreparationError::ArbitraryPath {
                reason: "owner installation root is not a directory".to_owned(),
            },
            0,
        ));
    }
    observe_prepare_progress(OP_SOURCE_ROOT, "resolve", "resolved", 0, 0);
    Ok(canonical)
}

/// Caller-presented preparation fields for one delegated operation.
///
/// The configuration manifest digest is deliberately absent: the manifest
/// always comes from the owner-bound [`ApprovedBuildBinding`] through the
/// configuration projection, so a caller can never assert a competing
/// manifest. Presented build digests are subset-checked against the owner
/// artifact set by that same projection. Numeric generation, lease, purge, and
/// target build/profile stay caller-presented pending #954 control contracts
/// and `HostComposition` delegation, which authenticate the caller; the
/// projection binds them and never invents currency for them. The one
/// presented generation that is nevertheless decided against owner evidence is
/// `approved_generation`, compared by
/// [`DelegatedPreparation::prepare`] against
/// [`OwnerEvidence::authority_generation`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PresentedPreparationRequest {
    /// Operation identity (bounded text, unique per preparation).
    pub operation_id: String,
    /// Closed preparation class.
    pub class: PreparationClass,
    /// Source installation identity (bounded text).
    pub source_installation_id: String,
    /// Explicitly admitted staging parent (verified through the
    /// protected-root owner, never trusted as a name).
    pub staging_parent: PathBuf,
    /// Target build identity for the destination (bounded presented text; not
    /// owner-approved by name, see
    /// [`DestinationAdmission::target_build`]).
    pub target_build: String,
    /// Target profile for the destination (bounded presented text; not
    /// owner-approved by name, see
    /// [`DestinationAdmission::target_profile`]).
    pub target_profile: String,
    /// Generation the caller claims as approved (presented, and checked
    /// against owner-issued authority evidence).
    pub approved_generation: u64,
    /// Authority generation the caller presents (presented evidence only).
    ///
    /// Deliberately not an input to the generation decision:
    /// [`DelegatedPreparation::prepare`] admits
    /// [`OwnerEvidence::authority_generation`] instead, so this value cannot
    /// make an unapproved generation pass. It is read nowhere on this path —
    /// the #954 control contract presents it and this lane grants it nothing —
    /// and it is not the value bound into the admission digest, which carries
    /// the owner-issued one. It is kept on the request rather than deleted
    /// because it is part of the presented contract surface, and removing a
    /// contract field from under #954 is not this lane's decision.
    pub authority_generation: u64,
    /// Owner lease reference the requester presents (bounded text; projected
    /// and bound into the projection digest, never a secret value).
    pub owner_lease_ref: String,
    /// Purge-ledger revision the requester presents (projected and bound into
    /// the projection digest; owner issuance belongs to #954).
    pub purge_ledger_revision: u64,
    /// Presented build digests, each verified against owner artifacts by the
    /// configuration projection.
    pub build_digests: Vec<String>,
    /// Optional forensic Host state audit note. It is validated, bound into
    /// the projection digest, and rendered with its non-authoritative ceiling
    /// into the prepared-destination receipt; it is never a lease, grant, or
    /// current-state assertion.
    pub audit_fence_note: Option<AuditFenceNote>,
    /// Opaque owner-issued entropy for fresh identity derivation.
    pub authority_nonce: String,
    /// Caller-observed state fence bound into the receipt.
    pub state_fence_digest: String,
}

/// HostComposition-side delegation handle for isolated destination
/// preparation (issue #958).
///
/// This is the exact sink interface the HostComposition owner binds: it owns
/// the installation/Host journal sink (`J`), takes inspected owner evidence
/// ([`OwnerEvidence`]) plus one presented request, and runs the full
/// owner-bound preparation lifecycle. Caller authentication stays
/// parameterized pending #954; every owner or presented-evidence failure
/// maps to a static fail-closed [`PreparationError`] without echoing owner
/// internals.
pub struct DelegatedPreparation<J: PreparationJournal> {
    journal: J,
}

impl<J: PreparationJournal> DelegatedPreparation<J> {
    /// Binds one journal sink for the preparation lifecycle.
    pub fn new(journal: J) -> Self {
        Self { journal }
    }

    /// Prepares one isolated destination from owner evidence plus one
    /// presented request.
    ///
    /// Order: bind the active approved generation from the inspected
    /// evidence, project the bounded owner-issued configuration evidence
    /// through the owner-bound projector, resolve the manifest-bound owner
    /// source root, then admit and prepare idempotently. The projection is a
    /// precondition, not an observation: a stale or mixed lease, generation,
    /// configuration/build digest, purge revision or forensic note is refused
    /// before any filesystem observation, and the projected owner
    /// configuration digest plus the projection digest are admitted so the
    /// prepared-destination receipt binds the exact configuration evidence
    /// that was proved. The caller never chooses the manifest digest, the
    /// projection digest, or the owner lease.
    ///
    /// The admitted `authority_generation` is the owner-issued one from
    /// [`OwnerEvidence::authority_generation`], so the presented
    /// `approved_generation` is admitted only if it matches committed owner
    /// evidence, and the presented `request.authority_generation` is not an
    /// input to that decision at all. The presented `staging_parent` is proved
    /// by the protected-root owner inside the preparation, so a
    /// client-supplied arbitrary path is refused. Target build and profile
    /// stay presented text with no name-level owner approval: see the module
    /// documentation.
    pub fn prepare(
        &mut self,
        evidence: &OwnerEvidence,
        request: &PresentedPreparationRequest,
    ) -> Result<PreparedDestination, PreparationError> {
        let binding: ApprovedBuildBinding = evidence
            .approved_binding()
            .map_err(|error| note_prepare_error(OP_DELEGATE, "bind_build", error, 0))?;
        let source_root = resolve_owner_source_root(evidence.runtime_roots())
            .map_err(|error| note_prepare_error(OP_DELEGATE, "resolve_source", error, 0))?;
        for digest in &request.build_digests {
            check_digest(digest, "build_digests")
                .map_err(|error| note_prepare_error(OP_DELEGATE, "check_build", error, 0))?;
            if !binding
                .artifact_digests
                .iter()
                .any(|artifact| artifact == digest)
            {
                return Err(note_prepare_error(
                    OP_DELEGATE,
                    "check_build",
                    PreparationError::InvalidRequest {
                        field: "build_digests",
                        reason: "build digest is not an owner-approved artifact".to_owned(),
                    },
                    0,
                ));
            }
        }
        // The owner-issued configuration projection runs AFTER the checks above
        // so #983's per-step diagnostics keep their existing precedence, and
        // BEFORE the admission is built so a stale or mixed lease, generation,
        // configuration/build digest, purge revision or forensic note is refused
        // before any effect. The projector re-checks the presented build digests
        // against the owner-issued artifact set, so the loop above is a first
        // cheap refusal and this is the authoritative one.
        let projection: BackupConfigProjection = evidence
            .project_backup_configuration(request, &binding)
            .map_err(|error| note_prepare_error(OP_DELEGATE, "project_config", error, 0))?;
        let admission = DestinationAdmission {
            operation_id: request.operation_id.clone(),
            class: request.class,
            source_installation_id: request.source_installation_id.clone(),
            source_root,
            staging_parent: request.staging_parent.clone(),
            target_build: request.target_build.clone(),
            target_profile: request.target_profile.clone(),
            approved_generation: request.approved_generation,
            // Owner-issued, never presented: the presented
            // `request.authority_generation` is deliberately NOT used here.
            // It was two caller values compared against each other, so any
            // caller could satisfy it by making its two values agree; sourcing
            // it from the committed activation fence makes
            // `validate_admission` compare the caller-presented approved
            // generation against owner-issued evidence, and an unapproved
            // generation is refused before any effect (case 958/7).
            authority_generation: evidence.authority_generation(),
            manifest_digest: projection.manifest_digest.clone(),
            config_projection_digest: projection.projection_digest.clone(),
            // The forensic note reaches the receipt only as rendered evidence
            // text carrying its own non-authoritative ceiling. There is no
            // constructor that turns it into a lease, grant, or current-state
            // assertion, and none is added here.
            audit_fence_note: request.audit_fence_note.as_ref().map(describe_audit_fence),
            authority_nonce: request.authority_nonce.clone(),
            state_fence_digest: request.state_fence_digest.clone(),
        };
        // The inner preparation owns its phase records; this notes only the
        // propagation of its failure to the delegation boundary.
        prepare_isolated_destination(&mut self.journal, &admission)
            .map_err(|error| note_prepare_error(OP_DELEGATE, "prepare", error, 0))
    }

    /// Reconciles one operation without duplicating effects.
    pub fn reconcile(&self, operation_id: &str) -> Result<ReconcileDisposition, PreparationError> {
        reconcile_preparation(&self.journal, operation_id)
    }

    /// Cancels one prepared operation, preserving its prior receipt.
    pub fn cancel(&mut self, operation_id: &str) -> Result<(), PreparationError> {
        cancel_preparation(&mut self.journal, operation_id)
    }

    /// Cleans up owned unactivated destinations, preserving unknowns.
    ///
    /// The swept set is this sink's own journal operation list; a presented id
    /// narrows that set and is refused when the journal does not own it.
    pub fn cleanup(&self, operation_ids: &[String]) -> Result<CleanupReport, PreparationError> {
        cleanup_preparations(&self.journal, operation_ids)
    }
}

/// Maps owner-binding projection failures to static fail-closed preparation
/// errors, preserving the offending field name without echoing owner
/// internals.
fn projection_to_preparation(error: ProjectionError) -> PreparationError {
    match error {
        ProjectionError::InvalidDigest { field } => PreparationError::InvalidRequest {
            field,
            reason: "digest shape required".to_owned(),
        },
        ProjectionError::InvalidIdentity { field } => PreparationError::InvalidRequest {
            field,
            reason: "bounded printable text required".to_owned(),
        },
        ProjectionError::BoundsExceeded { field } => PreparationError::InvalidRequest {
            field,
            reason: "bounded collection exceeded".to_owned(),
        },
        ProjectionError::StaleEvidence { field } => PreparationError::InvalidRequest {
            field,
            reason: "evidence is not current owner evidence".to_owned(),
        },
    }
}

/// Registry-committed owner evidence for one protected Host root.
///
/// This is the delegation-time read bundle preparation consumes: the
/// installation registry projection is inspected through the existing
/// read-only owner query
/// ([`RedbInstallationRegistry::inspect_existing_at`], A13.9 short-lived
/// poll read — no writer is acquired and no registry mutation is possible
/// here), and only the fully bound chain below is returned: lease-verified
/// caller root equal to the manifest root, validated registry, active
/// approved generation, validated manifest, topology-validated
/// manifest-bound runtime roots, committed fence, and fence↔manifest
/// agreement. The bundle owns every record it serves, so evidence cannot
/// outlive its read and no caller input enters it.
pub struct OwnerEvidence {
    registry: ApprovedGenerationRegistry,
    approved: ApprovedGeneration,
    fence: ActivationCommitFence,
    canonical_host_root: PathBuf,
    root_identity: FileIdentity,
}

impl OwnerEvidence {
    /// Inspects and binds the committed owner evidence below one protected
    /// Host root.
    ///
    /// Order, mirroring the `load_manifest_bound_canary_binding` precedent:
    /// absolute-path gate, protected-root lease, canonical path,
    /// stable-identity proof, caller-root equality, read-only registry
    /// inspection, registry validation, active generation, manifest
    /// validation, manifest/profile agreement with the bound runtime roots,
    /// manifest-root equality, committed fence, fence validation, and
    /// fence↔manifest agreement. Any step fails closed with a static
    /// [`PreparationError`]; owner error internals are never echoed.
    /// Absence of proof is never treated as proof of absence.
    ///
    /// The outcome is observed once: the static field in each refusal already
    /// names the failed inspection step, and no path or owner text is logged.
    pub fn inspect(host_state_root: &Path) -> Result<Self, PreparationError> {
        match Self::inspect_inner(host_state_root) {
            Ok(evidence) => {
                observe_prepare_progress(OP_OWNER_EVIDENCE, "inspect", "inspected", 0, 0);
                Ok(evidence)
            }
            Err(error) => Err(note_prepare_error(OP_OWNER_EVIDENCE, "inspect", error, 0)),
        }
    }

    /// Inspection body behind the outcome observation.
    #[allow(
        clippy::too_many_lines,
        reason = "the ordered inspection chain stays in one boundary; the wrapper only observes the outcome"
    )]
    fn inspect_inner(host_state_root: &Path) -> Result<Self, PreparationError> {
        if !host_state_root.is_absolute() {
            return Err(PreparationError::InvalidRequest {
                field: "host_state_root",
                reason: "absolute protected root required".to_owned(),
            });
        }
        let lease = ProtectedRootLease::open_existing(host_state_root).map_err(|error| {
            PreparationError::FilesystemEffect {
                path: host_state_root.to_string_lossy().into_owned(),
                reason: format!("protected source root unavailable: {error}"),
            }
        })?;
        let root_identity = lease.identity();
        let canonical =
            lease
                .canonical_path()
                .map_err(|error| PreparationError::FilesystemEffect {
                    path: host_state_root.to_string_lossy().into_owned(),
                    reason: format!("resolve source root: {error}"),
                })?;
        lease
            .verify_stable_identity()
            .map_err(|error| PreparationError::FilesystemEffect {
                path: host_state_root.to_string_lossy().into_owned(),
                reason: format!("verify source root identity: {error}"),
            })?;
        if !windows_paths_equal(host_state_root, &canonical) {
            return Err(PreparationError::InvalidRequest {
                field: "host_state_root",
                reason: "caller root differs from retained OS identity".to_owned(),
            });
        }
        let registry = RedbInstallationRegistry::inspect_existing_at(lease).map_err(|_| {
            PreparationError::InvalidRequest {
                field: "source_registry",
                reason: "owner registry inspection withheld".to_owned(),
            }
        })?;
        let Some(registry) = registry else {
            return Err(PreparationError::InvalidRequest {
                field: "source_registry",
                reason: "no committed installation registry under the protected root".to_owned(),
            });
        };
        registry
            .validate()
            .map_err(|_| PreparationError::InvalidRequest {
                field: "source_registry",
                reason: "owner registry projection invalid".to_owned(),
            })?;
        let approved = registry
            .active()
            .cloned()
            .ok_or(PreparationError::InvalidRequest {
                field: "approved_generation",
                reason: "no active approved generation committed".to_owned(),
            })?;
        approved
            .manifest
            .validate()
            .map_err(|_| PreparationError::InvalidRequest {
                field: "approved_generation",
                reason: "active candidate manifest invalid".to_owned(),
            })?;
        let roots = &approved.manifest.runtime_launch.runtime_state_roots;
        roots
            .validate()
            .map_err(|_| PreparationError::InvalidRequest {
                field: "source_roots",
                reason: "owner runtime roots violate topology".to_owned(),
            })?;
        if approved.manifest.runtime_launch.profile != roots.profile {
            return Err(PreparationError::InvalidRequest {
                field: "source_roots",
                reason: "manifest profile disagrees with bound runtime roots".to_owned(),
            });
        }
        if !windows_paths_equal(Path::new(roots.host_state_root.as_str()), &canonical) {
            return Err(PreparationError::InvalidRequest {
                field: "host_state_root",
                reason: "active manifest root differs from retained root".to_owned(),
            });
        }
        let fence = registry.last_committed_activation_fence().cloned().ok_or(
            PreparationError::InvalidRequest {
                field: "commit_fence",
                reason: "no committed activation fence".to_owned(),
            },
        )?;
        fence
            .validate()
            .map_err(|_| PreparationError::InvalidRequest {
                field: "commit_fence",
                reason: "committed activation fence invalid".to_owned(),
            })?;
        if fence.generation != approved.manifest.generation
            || fence.config_digest != approved.manifest.config_digest
            || fence.authority_generation != approved.manifest.runtime_launch.authority_generation
        {
            return Err(PreparationError::InvalidRequest {
                field: "commit_fence",
                reason: "fence and manifest disagree".to_owned(),
            });
        }
        Ok(Self {
            registry,
            approved,
            fence,
            canonical_host_root: canonical,
            root_identity,
        })
    }

    /// Returns the validated active approved generation.
    pub fn approved(&self) -> &ApprovedGeneration {
        &self.approved
    }

    /// Returns the validated committed activation fence agreed with the
    /// manifest.
    pub fn fence(&self) -> &ActivationCommitFence {
        &self.fence
    }

    /// Returns the lease-verified canonical Host root, equal to the manifest
    /// Host state root.
    pub fn canonical_host_root(&self) -> &Path {
        &self.canonical_host_root
    }

    /// Returns the pinned OS identity observed at inspection time.
    pub fn root_identity(&self) -> FileIdentity {
        self.root_identity
    }

    /// Returns the topology-validated manifest-bound runtime roots.
    pub fn runtime_roots(&self) -> &RuntimeStateRoots {
        &self.approved.manifest.runtime_launch.runtime_state_roots
    }

    /// Binds the active generation to owner-verified build facts.
    ///
    /// The record is already validated by [`OwnerEvidence::inspect`];
    /// [`bind_approved_build`] re-verifies it here so the binding never
    /// depends on inspection-time state alone.
    pub fn approved_binding(&self) -> Result<ApprovedBuildBinding, PreparationError> {
        bind_approved_build(&self.approved).map_err(projection_to_preparation)
    }

    /// Projects the bounded owner-issued configuration evidence for one
    /// presented preparation request (issue #958, cases 958/1-4, 958/16).
    ///
    /// This is the production construction of the owner-bound projection. The
    /// owner supplies three of its inputs and the request supplies only
    /// presented evidence:
    ///
    /// - the manifest digest is the owner-issued configuration digest from
    ///   `binding`, so a caller can never present a competing manifest;
    /// - the projection fence is the committed activation fence's authority
    ///   state fence, so a caller cannot choose the fence its evidence is bound
    ///   to;
    /// - the generation handle is bound inside the projector from the same
    ///   owner record.
    ///
    /// Installation identity, owner lease reference, numeric generation,
    /// purge-ledger revision, presented build digests and the optional
    /// forensic note are caller-presented and shape-checked here, then bound
    /// into the returned [`BackupConfigProjection`]. The projector verifies
    /// presented-vs-owner equality where the owner has evidence and never
    /// invents currency where it does not: the installation registry, the
    /// approved generation and the activation commit fence carry no
    /// owner-issued lease reference and no purge-ledger revision, so those two
    /// stay presented until #954 control contracts land. No secret-typed field
    /// exists on this path, and a credential-shaped value fails digest or
    /// identity shape rather than being projected.
    ///
    /// `manifest_digest` is the one field that is NOT caller-presented on this
    /// path, and it is stated here rather than left to look like a check: the
    /// presented request carries no configuration digest of its own, so the
    /// value handed to the projector is the owner-issued
    /// `binding.config_digest` and the projector's `manifest_digest` arm
    /// compares the owner against itself. That arm is retained because the
    /// projector's contract is presented-vs-owner and other callers may supply
    /// a presented digest, but on THIS path it is a shape guard, not evidence.
    /// The configuration binding that is real evidence here comes from
    /// `bind_approved_build` over an owner-validated record plus the presented
    /// `build_digests` subset check, both of which compare against owner-issued
    /// values. Nothing downstream may cite the `manifest_digest` comparison as
    /// an owner proof for a production preparation.
    pub fn project_backup_configuration(
        &self,
        request: &PresentedPreparationRequest,
        binding: &ApprovedBuildBinding,
    ) -> Result<BackupConfigProjection, PreparationError> {
        let config = BackupConfigRequest {
            installation_id: request.source_installation_id.clone(),
            owner_lease_ref: request.owner_lease_ref.clone(),
            generation: request.approved_generation,
            // Owner-issued, not presented: see the note above.
            manifest_digest: binding.config_digest.clone(),
            build_digests: request.build_digests.clone(),
            purge_ledger_revision: request.purge_ledger_revision,
            audit: request.audit_fence_note.clone(),
        };
        project_backup_config_owner_bound(&config, binding, &self.fence.authority_state_fence)
            .map_err(projection_to_preparation)
    }

    /// Returns the registry CAS revision observed at inspection time.
    ///
    /// Binds "current": HostComposition compares revisions to detect
    /// registry movement between inspection and preparation. This is the
    /// registry revision, not the purge-ledger revision, whose authority
    /// belongs to the backup domain.
    pub fn revision(&self) -> u64 {
        self.registry.revision()
    }

    /// Returns the owner-issued runtime authority resource generation.
    ///
    /// This is the value [`ActivationCommitFence::authority_generation`] the
    /// committed activation fence carries, and it is the only numeric
    /// generation the owner record exposes. It was already proved against the
    /// active manifest during [`OwnerEvidence::inspect`] (the fence's
    /// authority generation must equal the manifest runtime launch's, the fence
    /// itself must validate, and a zero authority generation is rejected), so
    /// this is owner-issued, non-zero and manifest-agreed by construction.
    ///
    /// [`DelegatedPreparation::prepare`] admits it as
    /// [`DestinationAdmission::authority_generation`], which is what turns
    /// `validate_admission`'s generation comparison into a comparison against
    /// owner evidence rather than between two values the same caller presented.
    /// The approved generation identity itself is a
    /// [`crate::backup_config_projection::ApprovedBuildBinding::generation_handle`]
    /// and is not numeric, so no numeric owner handle is invented here.
    pub fn authority_generation(&self) -> u64 {
        self.fence.authority_generation.value()
    }
}

/// Verifies one staging parent against the protected-root owner.
///
/// Opens the existing protected-root lease — which containment-checks the path
/// against the real ELIOT protected contour, rejects a reparse chain, and pins
/// the whole directory chain plus its identity by retained handle — proves that
/// retained identity is still stable, and returns the owner-resolved canonical
/// path. This is the production protected-root gate for destination
/// preparation: [`admit_staging_parent`] calls it for every prepared
/// destination, so no caller-nominated path outside the contour is ever used as
/// a destination parent (case 958/7) and every root created is inside the
/// contour [`reverify_recorded_destination`] re-proves before removal (case
/// 958/15). There is no bypass: an unproved parent is refused.
///
/// Fail-closed and static: every owner failure maps through
/// [`protected_path_to_preparation`] to a typed [`PreparationError`] with a
/// static reason, and owner internals are never echoed into it.
pub fn verify_staging_parent_lease(
    operation_id: &str,
    parent: &Path,
) -> Result<PathBuf, PreparationError> {
    let lease = ProtectedRootLease::open_existing(parent)
        .map_err(|error| protected_path_to_preparation(operation_id, parent, error))
        .map_err(|error| note_prepare_error(OP_STAGING_LEASE, "verify", error, 0))?;
    lease
        .verify_stable_identity()
        .map_err(|error| protected_path_to_preparation(operation_id, parent, error))
        .map_err(|error| note_prepare_error(OP_STAGING_LEASE, "verify", error, 0))?;
    let verified = lease
        .canonical_path()
        .map_err(|error| protected_path_to_preparation(operation_id, parent, error))
        .map_err(|error| note_prepare_error(OP_STAGING_LEASE, "verify", error, 0))?;
    observe_prepare_progress(OP_STAGING_LEASE, "verify", "verified", 0, 0);
    Ok(verified)
}

/// Authenticated caller control for one delegated preparation (issue #958).
///
/// Shape carries the owner-issued caller lease digest and the caller fence
/// digest so refusals and (later) admissions bind them into the audit trail.
/// Caller authentication itself is pending #954 role-bound control: until
/// the #954 owner port lands, [`BackupCallerAuth::authenticate`] fails
/// closed and no destination effect is reachable through delegation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupCallerAuth {
    /// Owner-issued caller lease digest (hex64; shape-checked only).
    pub lease_digest: String,
    /// Caller-observed fence digest bound into the receipt (hex64).
    pub fence_digest: String,
}

impl BackupCallerAuth {
    /// Shape-checks the presented caller digests without granting authority.
    pub fn check_shapes(&self) -> Result<(), PreparationError> {
        check_digest(&self.lease_digest, "caller_lease_digest")?;
        check_digest(&self.fence_digest, "caller_fence_digest")?;
        Ok(())
    }

    /// Authenticates the caller against owner-issued control evidence.
    ///
    /// Fail-closed pending the #954 caller-control port: there is currently
    /// no owner-issued caller token to verify against, so every caller is
    /// refused here before any destination effect. The #954 implementation
    /// fills this method without changing its signature or callers.
    pub fn authenticate(&self) -> Result<(), PreparationError> {
        Err(PreparationError::InvalidRequest {
            field: "caller_auth",
            reason:
                "authenticated caller control pending #954; unauthenticated preparation refused"
                    .to_owned(),
        })
    }

    /// Authenticates the caller against held owner facts without minting
    /// authority.
    ///
    /// Verifies digest shapes, then requires the held owner lease to cover
    /// the launch installation and the presented source to equal it. The
    /// lease/fence digests stay shape-checked audit-trail evidence: no owner
    /// digest scheme binds them yet, so they grant nothing here.
    /// Caller-channel (control-plane principal) authentication awaits the
    /// #954 role-bound port and is reported as backlog, not assumed.
    pub fn authenticate_for_owner(
        &self,
        lease: &HostOwnerLease,
        installation: &PlatformHandle,
        source_installation_id: &str,
    ) -> Result<(), PreparationError> {
        self.check_shapes()
            .map_err(|error| note_prepare_error(OP_CALLER_AUTH, "authenticate", error, 0))?;
        if !lease.is_for_installation(installation) {
            return Err(note_prepare_error(
                OP_CALLER_AUTH,
                "authenticate",
                PreparationError::InvalidRequest {
                    field: "caller_auth",
                    reason: "held owner lease does not cover the launch installation".to_owned(),
                },
                0,
            ));
        }
        if source_installation_id != installation.as_str() {
            return Err(note_prepare_error(
                OP_CALLER_AUTH,
                "authenticate",
                PreparationError::InvalidRequest {
                    field: "caller_auth",
                    reason: "presented source differs from the lease-bound installation".to_owned(),
                },
                0,
            ));
        }
        observe_prepare_progress(OP_CALLER_AUTH, "authenticate", "authenticated", 0, 0);
        Ok(())
    }
}
