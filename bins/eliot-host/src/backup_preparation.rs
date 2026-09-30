//! Host-owned isolated destination preparation for backup (issue #958).
//!
//! Pure admission, verification, and filesystem-effect logic over explicitly
//! supplied evidence. The caller (`HostComposition` at delegation; fixtures in
//! tests) provides the admission, the source root, the explicitly admitted
//! staging parent, authority values, and a [`PreparationJournal`] sink. This
//! module mints no authority of its own: the fresh destination identity binds
//! owner-issued evidence under a domain separator and never any caller-chosen
//! material, so it is neither an archive copy nor a value a caller can select.
//!
//! Effects are exactly: create one destination directory under the admitted
//! parent, pin its OS identity, and record intent/result through the journal
//! sink. No launch, no readiness probing, no effect-authority activation, no
//! source shutdown, no SCM contact, no registry writes, no archive import, no
//! cutover. Launch/readiness/effect authority have no representation here by
//! construction (see case 958/10).
//!
//! # Durable intent and result
//!
//! [`HostStatePreparationJournal`] is the production [`PreparationJournal`]
//! sink. It writes the owner's [`BackupPreparationRecord`] into the same
//! `HostStateJournalService` this crate's other durable records use, through the
//! same single-writer reconcile choke, and it is constructed by
//! `HostComposition::prepare_backup_destination` from the composition's own
//! journal rather than supplied by a caller. Intent and result therefore survive
//! a process restart and a Host restart, which is what makes A4's repeated-request
//! rule real rather than only as durable as an in-memory map.
//!
//! The record is the owner's (#961, `c8b6bf64`), not a second registry and not a
//! reuse of an unrelated record: `Pending` is written before the root is created
//! and proves only that the operation was admitted, and `Prepared` is written
//! after the root exists and its identity was pinned and is the sole proof that
//! this operation created that exact directory. Nothing here reads a `Pending`
//! record as proof that a root does or does not exist, and nothing treats it as
//! permission to prepare a second destination.
//!
//! The created directory is **not** an installation allocated through the
//! installation authority: `ApprovedGenerationRegistry` exposes no public
//! mutation seam (every mutator is `pub(crate)`), so the created root has no
//! `ApprovedGeneration` row, no registry CAS and no activation fence of its
//! own. It is a fenced empty root under a protected staging parent. Allocating
//! a real new installation is an owner correction in
//! `crates/kernel/eliot-installation`, outside this module.
//!
//! # Destination identity and epoch
//!
//! [`derive_destination_id`] and [`derive_destination_epoch`] bind
//! owner-issued evidence only: the owner-issued authority generation, the
//! owner-proved configuration projection digest, the **owner-resolved** staging
//! parent returned by the protected-root owner, and the operation identity.
//! [`DestinationAdmission::authority_nonce`] is deliberately NOT an input: a
//! caller that could choose the nonce could choose the identity and the epoch,
//! and an archive-supplied nonce would make both archive-determined.
//!
//! The resulting `destination_epoch` is a preparation-scope lineage marker
//! bound to that evidence. It is **not** an Authority Epoch and no Authority
//! Epoch is issued here: I5.13/A13.7 require a new Authority Epoch lineage
//! strictly above every observed epoch, and the only owner that could allocate
//! one is the cutover child, which is a separate issue. A preparation receipt
//! must therefore never be read as epoch authority, and nothing in this module
//! consumes `destination_epoch` as one.
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
//! was proved.
//!
//! The projection is **owner-issued**: the owner lease reference comes from
//! [`OwnerEvidence::owner_lease_ref`], which re-proves the retained
//! protected-root lease (identity plus the object's current final path) at the
//! moment the projection consumes it and refuses typed if the source root is no
//! longer the object the evidence chain admitted; the configuration and
//! generation values come from the validated approved generation, its committed
//! activation fence and any completed Phase-B rebind; and the fence is the
//! committed fence's authority state fence. A presented owner lease reference is
//! a *claim* checked against that owner value and refused as
//! [`PreparationError::InvalidRequest`] with the `owner_lease_ref` field when it
//! differs, so a stale or foreign lease cannot reach a receipt.
//!
//! The purge-ledger revision is **owner-issued** too, and now read rather than
//! refused: [`OwnerEvidence::owner_purge_ledger_revision`] opens the
//! approved-manifest-selected ORS child through
//! [`ProtectedRuntimePathLease`], re-proves the retained identity and path
//! identity on both sides of the read, and hands the value to
//! [`crate::backup_config_projection::project_backup_config_owner_bound`],
//! where a presented revision is a *claim* checked against that owner value.
//! That read does NOT make this composition root a second *mutable* root owner
//! (`crates/storage/AGENTS.md`): it is a `ReadOnlyDatabase` read with no write
//! transaction, no retained store handle and no ORS lease held past the call,
//! so the module still holds no registry writer, no store handle and no ORS
//! lease of its own. The producer stays
//! `RedbRecoveryStore::purge_ledger_revision`; this module observes it.
//!
//! The forensic audit note is no longer refused, because it no longer has to be:
//! [`OwnerEvidence::owner_audit_note`] derives it from the validated
//! installation lineage this owner actually read, so a presented note is a
//! **claim** checked against the owner's rather than the only candidate, and
//! caller-authored disposition text cannot reach a receipt. The owner-issued
//! note is bound into the projection digest only; this module passes the
//! presented value through so the comparison is real, and it never renders a
//! forensic note into a receipt:
//! [`DestinationAdmission::audit_fence_note`] and
//! [`PreparedDestination::audit_fence_note`] are therefore always absent here.
//! I5.13 keeps the HostStateAuditFence forensic and optional for exactly this
//! reason. No
//! credential or secret material is read or projected: the committed fence's
//! `credential_receipt_digest` and `host_process_nonce_digest` are visible on a
//! record this module reads and are deliberately not extracted.
//!
//! # Source and API guard
//!
//! The source-identity proof is real and lives at its owner:
//! `HostComposition::prepare_backup_destination` calls
//! [`BackupCallerAuth::authenticate_for_owner`] with the held owner lease and
//! the launch installation handle before any preparation runs, so the presented
//! source installation identity is compared against owner-issued evidence
//! there. The delegated port itself is owner-bound too: [`OwnerEvidence`] has
//! all-private fields and only [`OwnerEvidence::inspect`] can build one, so
//! [`DelegatedPreparation::prepare`] cannot be entered without a real
//! protected root and a committed registry behind it.
//!
//! What is NOT proved here: [`prepare_isolated_destination`] and
//! [`DestinationAdmission`] are `pub` with all-public fields, so a caller that
//! bypasses the delegated port can reach the effect step with a fabricated
//! source root and staging parent. Narrowing that port means making it
//! crate-private, which the declared 958 suite calls directly, and the
//! authenticated-caller control itself has no Host-side port
//! ([`BackupCallerAuth::authenticate`] fails closed against it). The module
//! holds no registry writer, no archive import, no store-recovery rewrite and
//! no cutover arm, so the closed [`PreparationClass`] set plus those absences
//! are what exclude a second installer/registry, same-installation
//! Store-recovery rewrite, archive restore and cutover today.
//!
//! # One versioned lifecycle record, decoded once
//!
//! Every read of a persisted preparation goes through one decoder,
//! [`decode_preparation_record`], and one join,
//! [`validate_recorded_binding`]. A record is a **typed lifecycle state**, not an
//! object that happens to carry destination fields:
//!
//! - [`PreparationLifecycleState`] is a closed four-state set — `prepared`,
//!   `cancelled`, `cleanup_pending`, `reclaimed` — spelled exactly as the durable
//!   [`BackupPreparationState`] variants are, so the in-memory frame and the
//!   owner's record cannot disagree about what a state is called.
//! - An unsupported `version`, an absent or unrecognized `state`, a malformed
//!   field, a `transition` block that contradicts the frame's own state, or a
//!   stored `operation_id` that differs from the lookup key is **refused**. None
//!   of them is read as `prepared`, and the stored operation identity is never
//!   overwritten with the requested one.
//! - Only [`PreparationLifecycle::usable_destination`] yields a
//!   [`PreparedDestination`], and it returns `None` for all three terminal
//!   states. A cancelled, cleanup-pending or reclaimed operation therefore
//!   reconciles as preserved and replays as a refusal, never as a usable
//!   destination, and it creates no root.
//! - `prior_receipt` is decoded as history and shape-checked, never as current
//!   preparation authority. Cancellation alone is never proof that a populated
//!   root is safe to destroy.
//!
//! The join is what makes a recorded result usable at all. It re-derives the
//! admission digest from the recorded admission, re-derives `destination_id` and
//! `destination_epoch` from the **same recorded** owner evidence through
//! [`owner_identity_evidence`], [`derive_destination_id`] and
//! [`derive_destination_epoch`], and compares every one of them against the
//! recorded value. Both read paths use it, so the exact prepare replay and
//! reconciliation cannot disagree about whether a root is still this
//! operation's.
//!
//! # Lossless paths
//!
//! A path is persisted only through its own lossless text
//! ([`persistable_path_text`]); a path with no lossless text form is refused
//! before any intent or effect rather than recorded through replacement
//! characters. `to_string_lossy` is no longer on any persistence path, which is
//! what keeps it in agreement with [`hash_path`]: the digest is over the raw
//! platform bytes, and the record is over the text that maps back to exactly
//! those bytes, or the path never reaches a record. The in-memory sink and
//! [`HostStatePreparationJournal`] therefore produce byte-identical frames for
//! the same record.
//!
//! # Cleanup ownership, custody and retirement state
//!
//! A preparation receipt proves that this operation once created that exact
//! directory. It does not prove that the directory is still empty, that no
//! restore has populated it, or that no other owner has adopted or activated it,
//! so a reconciled `Current` destination is a *candidate* for reclamation and
//! never a sufficient reason for one. [`cleanup_preparations`] decides four
//! further questions before anything is destroyed, in this order:
//!
//! - **Ownership, carried into the effect.** [`reverify_recorded_destination`]
//!   returns the retained [`ProtectedRootLease`] instead of `Ok(())`, and the
//!   reclamation hands that lease straight to
//!   [`ProtectedRootLease::into_removal_proof`]. The irreversible operation is
//!   applied to the retained `DELETE` handle the proof pinned, so there is no
//!   longer a window in which a proved root is re-resolved by name and deleted
//!   through a reopened, unprotected path. This is the same conclusion the
//!   platform owner already reached for itself: recursive deletion "cannot be
//!   made identity-bound by checking a pathname, closing the check handle, and
//!   then calling `remove_dir_all`"
//!   (`crates/kernel/eliot-platform-windows/src/directory_publication.rs`), so
//!   the removal lives beside that capability as
//!   [`ProtectedRootRemovalProof`] rather than being re-implemented here.
//! - **A bounded empty-root effect.** There is no recursive sweep on this path
//!   at all. [`ProtectedRootRemovalProof::remove_if_empty`] observes one entry
//!   and then applies one handle-bound delete disposition, so a root that a
//!   restore populated, or that another owner adopted, is reported as preserved
//!   for the owning cleanup protocol instead of being destroyed. A count or byte
//!   bound is not a substitute for that disposition and none is invented here.
//! - **Current destination and custody disposition.**
//!   [`PreparationJournal::destination_custody`] must read
//!   [`DestinationCustody::Released`] — a retained cutover intent claiming this
//!   exact destination, or a sink that cannot read the custody records at all,
//!   preserves the root. Cancellation is a separate transition and is never
//!   read as proof that a populated root is safe to destroy.
//! - **An owner-authorized cleanup transition.**
//!   [`CleanupTransitionState::CleanupPending`] is retained through the journal
//!   *before* the effect and [`CleanupTransitionState::Reclaimed`] only *after*
//!   the absence has been observed. A sink that refuses the transition has not
//!   authorized the reclamation, so the root is preserved. An operation whose
//!   `Reclaimed` retention is refused is reported as preserved rather than
//!   removed, so [`CleanupReport`] never claims a durable lifecycle state this
//!   module could not write.
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
//!   name-based canonicalise. That is also what makes reclamation reachable:
//!   [`reverify_recorded_destination`] requires the same containment, so a
//!   root created here is by construction one whose reclamation path
//!   ([`remove_reverified_destination`]) can be reached. The proof is taken at
//!   admission; the recorded root is proved again through the same owner
//!   immediately before any reclamation, and preserved when that proof fails.
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
//!   drive unbounded reconciles and reclamations (A13.9: a Durable Job carries
//!   a budget). The bound is a work bound only: it is never read as an ownership
//!   or emptiness decision, and once the first reclamation has happened the
//!   sweep reports through [`CleanupReport`] rather than through an error, so a
//!   later stop can never discard the record of an effect that already occurred.
//!
//! # Target build and profile are owner-approved identities
//!
//! [`DelegatedPreparation::prepare`] refuses a presented
//! [`DestinationAdmission::target_build`] that is not the owner-issued
//! approved-generation handle, and a presented
//! [`DestinationAdmission::target_profile`] that is not the owner-issued
//! approved profile token of the same validated record. Both come from the
//! owner record through [`bind_approved_build`], so no approval list, no
//! synthetic table and no always-passing comparison is invented: a name the
//! owner has not approved is refused, not accepted. The shape half stays in
//! [`validate_admission`], which can only check bounded printable text because
//! the low-level port has no owner evidence.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::backup_config_projection::{
    ApprovedBuildBinding, AuditFenceNote, BackupConfigProjection, BackupConfigRequest,
    ProjectionError, bind_approved_build, hash_field, project_backup_config_owner_bound,
};
use eliot_host_state::{
    BackupPreparationRecord, BackupPreparationState, HostState, HostStateRecord,
    IdempotencyIdentity, ProductionHostStateJournal, RecordFence,
};
use eliot_installation::{
    ActivationCommitFence, ApprovedGeneration, ApprovedGenerationRegistry,
    RedbInstallationRegistry, RuntimeStateRoots,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    FileIdentity, HostOwnerLease, ProtectedPathError, ProtectedRootLease,
    ProtectedRootRemovalOutcome, ProtectedRootRemovalProof, ProtectedRuntimePathLease,
    windows_paths_equal,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Preparation format version pinned into digests and receipts.
///
/// **v1** carried an arbitrary result object: a frame with the right field
/// names decoded as a usable [`PreparedDestination`] whatever it actually said,
/// and the root was persisted with `to_string_lossy`, so two distinct Windows
/// roots could share one record.
///
/// **v2** makes the persisted frame a **versioned, typed lifecycle record**:
///
/// - the result carries an explicit `state` (`prepared`, `cancelled`,
///   `cleanup_pending`, `reclaimed`), and a frame whose state is unknown,
///   missing or not a string is REFUSED rather than read as `prepared`;
/// - the intent carries the canonical parent and an explicit `admission_binding`
///   discriminator, so the recorded-result join reads a declared admission
///   encoding instead of guessing one from a decode that happened to succeed;
/// - a path is persisted only through its lossless text form: a path with no
///   lossless text representation is REFUSED before any intent or effect, and
///   `to_string_lossy` is no longer on any persistence path.
///
/// The version is an input to [`admission_digest`] and to
/// [`owner_identity_evidence`], so bumping it re-cuts both digests: a record
/// admitted under v1 is not readable as a v2 record, and it is refused and
/// preserved rather than re-decoded under rules it was never written for
/// (I5.27 canonical encoding is versioned; A13.7 `ARCH-RES-03`).
pub const PREPARATION_VERSION: u32 = 2;
/// Maximum length of one bounded identity string.
pub const MAX_IDENTITY_LEN: usize = 256;
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
/// bounded empty-root reclamation, so the swept key set is the sweep's real work
/// bound. 256
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
/// number of *subsequent* reconciles and reclamations rather than interrupting
/// one in flight (a delete disposition cannot be cancelled once issued) and the
/// listing's own unbounded cost still falls inside the window even though the
/// call itself cannot be interrupted. 30 s is generous headroom for 256
/// individually re-proven owned roots on a loaded volume and still far below any
/// caller wait that a runaway sweep could justify. Exhaustion before the first
/// reclamation refuses with [`PreparationError::SweepBudget`]; exhaustion after
/// one reports through [`CleanupReport`], so the roots already reclaimed in the
/// same call and every operation not yet swept both stay visible.
pub const CLEANUP_SWEEP_BUDGET: Duration = Duration::from_secs(30);
/// Domain separator for owner-evidence-bound destination identities.
pub const DESTINATION_ID_DOMAIN: &str = "eliot.backup.destination.v1";

/// Stable marker recorded in [`BackupPreparationRecord::source_archive`] when an
/// isolated preparation admitted no source archive.
///
/// The owner's record carries a mandatory source-archive field, and this
/// preparation genuinely binds no archive: it creates a fenced empty root and
/// stops (see the module documentation), and the restore that would consume an
/// archive is a separate owner with its own admission. The field is therefore
/// filled with an explicit, static, truthful **absence** marker rather than an
/// invented archive identity, which would let a reader believe a specific
/// archive had been proved. This is the same "record the absence" treatment the
/// owner-issued configuration projection still applies to the forensic audit
/// note, and the marker is part of the
/// record's exact-binding transition, so it cannot vary between one
/// preparation's admission and its result.
pub const PREPARATION_NO_SOURCE_ARCHIVE: &str = "eliot.backup.preparation.no-source-archive.v1";

/// Errors for isolated destination preparation (issue #958).
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum PreparationError {
    /// Malformed request shape (empty/overlong/control-carrying identity, bad digest).
    #[error("invalid request field {field}: {reason}")]
    InvalidRequest { field: &'static str, reason: String },
    /// Approved generation disagrees with the authority generation input.
    #[error("unapproved generation: approved {approved} != authority {authority}")]
    UnapprovedGeneration { approved: u64, authority: u64 },
    /// A presented target build/profile is not the owner-approved identity.
    #[error(
        "unapproved target {field}: presented {presented} is not the owner-approved {approved}"
    )]
    UnapprovedTarget {
        field: &'static str,
        presented: String,
        approved: String,
    },
    /// No owner issues the value the request presented for this field.
    ///
    /// The fail-closed alternative to copying an uncorroborated caller claim
    /// into an owner-issued receipt. `obligation` names the exact owner that
    /// must issue it and is a static sentence; no caller value is echoed.
    #[error("no owner-issued evidence for field {field}: {obligation}")]
    OwnerEvidenceUnavailable {
        field: &'static str,
        obligation: &'static str,
    },
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
    /// created stays individually re-provable on the next bounded pass. This
    /// variant is therefore only ever raised **before** the first irreversible
    /// effect of the call: once a root has been reclaimed, the sweep returns its
    /// [`CleanupReport`] instead, so the record of what was already removed can
    /// never be discarded by a later refusal.
    #[error("cleanup sweep budget exceeded on {field}: {reason}")]
    SweepBudget { field: &'static str, reason: String },
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
// (generations, owner-evidence-bound preparation-scope lineage markers); never
// operation/installation
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
// call. Handoff (caller-owned, APPLIED for the admitted preparation port under
// #983 W4): `HostComposition::backup_dispatch_prepare` arms one
// `HostTerminalGuard` with the frozen `host-backup-prepare-failed` code and
// disarms only on its success return, so a failed preparation operation
// produces exactly one terminal record here while the leaf's phase/refusal
// records stay nonterminal beneath it; operation failure stays distinct from
// any process shutdown failure. STILL PENDING, and deliberately not claimed:
// the reconcile/cancel/cleanup holders named below are `DelegatedPreparation`
// passthroughs reached by the caller of the returned handle rather than by this
// port, and this issue arms no second guard for them.
//
// Explicit no-event list: `DelegatedPreparation::{reconcile, cancel, cleanup}`
// (pure passthroughs; the inner operation owns the record),
// `OwnerEvidence::approved_binding` (mapping adapter covered by the inner bind
// and outer delegate records), `BackupCallerAuth::{check_shapes, authenticate}`
// (the former surfaces through `authenticate_for_owner`; the latter is the
// always-refuse stub with no production path),
// `conflict_field`/`admission_digest`/`derive_*`/`hash_path`/`capture_identity`
// /`reject_reparse`/`reverify_recorded_destination`/`protected_path_to_preparation`
// /`projection_to_preparation`/`intent_json`/`result_json`/`cleanup_transition_json`
// /`owner_identity_evidence`/`reject_audit_note`/`persistable_path_text`
// /`check_persistable_path`/`recorded_text`/`recorded_u64`
// /`decode_preparation_record`/`decode_recorded_destination`
// /`check_recorded_destination_shapes`/`validate_recorded_binding`
// /`recorded_complete_admission`/`recorded_owner_projection_evidence`
// /`state_is_cleanup`/`cleanup_transition_lifecycle`
// (private steps whose outcome surfaces with its exact category at the owning
// boundary). The durable sink adds only the same shape of step:
// `HostStatePreparationJournal::{snapshot, record_fence, retained, append,
// destination_custody}` and
// `preparation_handle`/`preparation_mutation`/`preparation_state_spelling` are
// private steps whose outcome surfaces with its exact category at the owning
// boundary; `HostStatePreparationJournal::{record_intent, record_result, load,
// list_operations}` are the `PreparationJournal` port itself, whose refusals
// propagate through the existing `record_intent`/`record_result` phase records
// of `prepare_isolated_destination`, and `load`/`list_operations`/
// `destination_custody` are read-only projections that observe no phase. The
// cleanup path adds `remove_reverified_destination` and `record_sweep_stop` as
// owning boundaries of their own, so every reclamation refusal surfaces there
// with its exact category and no second terminal record is produced. No record
// asserts destination readiness,
// source retirement, or activation: `destination_epoch` is preparation scope,
// never authority.

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
/// The durable Host-state journal sink this module writes intent/result through.
const OP_JOURNAL_SINK: &str = "journal_sink";

/// The ORS file name the kernel operational-record state root's own child
/// carries.
///
/// The owner of this name is
/// `bins/eliot-host/src/watchdog_publication.rs:58`
/// (`read_manifest_current_supervision_lease` reads the same file through the
/// same retained runtime-path lease), and the two declarations MUST agree: the
/// watchdog module is declared `mod watchdog_publication;` (private) in
/// `bins/eliot-host/src/lib.rs`, so its constant is not reachable from here and
/// this one is declared beside its use rather than by refactoring the crate root
/// to share it. If the ORS file name ever changes, both sites change together —
/// a copy that drifts would make this module read a different file than the
/// owner it claims to observe.
const KERNEL_ORS_FILE_NAME: &str = "kernel-ors.redb";

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
        PreparationError::UnapprovedTarget { field, .. } => ("unapproved_target", field),
        PreparationError::OwnerEvidenceUnavailable { field, .. } => {
            ("owner_evidence_unavailable", field)
        }
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
    crate::host_diagnostics::info!(
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
    crate::host_diagnostics::warn!(
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
/// Mixed by construction, and the docs name which is which. `staging_parent` is
/// an explicitly admitted isolated-prep parent directory — never the source,
/// never an arbitrary client path (verified by the protected-root owner, not
/// trusted), and never outside the ELIOT protected contour. On the delegated
/// path `authority_generation`, `manifest_digest` and
/// `config_projection_digest` are owner-issued or owner-proved, and
/// `target_build`/`target_profile` are approved against the owner record there;
/// every remaining text field is presented evidence, and a presented forensic
/// note is refused.
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
    /// Target build identity for the destination (bounded text).
    ///
    /// Owner-approved on the delegated path: the value must equal the
    /// owner-issued approved-generation handle of the validated approved
    /// record ([`ApprovedBuildBinding::generation_handle`]), otherwise
    /// [`DelegatedPreparation::prepare`] refuses with
    /// [`PreparationError::UnapprovedTarget`]. No broader build-name catalogue
    /// exists on this path, so a name outside the approved generation is refused
    /// rather than accepted. What is additionally owner-approved for the build is
    /// the presented `build_digests` subset check against the owner artifact
    /// set.
    pub target_build: String,
    /// Target profile for the destination (bounded text).
    ///
    /// Owner-approved on the delegated path: the value must equal the
    /// owner-issued approved profile token of the same validated record
    /// ([`ApprovedBuildBinding::approved_profile`]), otherwise
    /// [`DelegatedPreparation::prepare`] refuses with
    /// [`PreparationError::UnapprovedTarget`]. No local spelling or fallback
    /// list is used for that token.
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
    /// (hex64). It binds the owner-approved generation, the owner authority
    /// state fence, the owner-issued template and retained (materialized Phase-B)
    /// configuration digests, the complete owner-issued approved build digest
    /// set, the owner-approved profile token and the owner-issued lease
    /// reference, and states the absence of a purge-ledger revision and an audit
    /// note, so the prepared-destination receipt names the exact configuration
    /// evidence that was proved.
    pub config_projection_digest: String,
    /// Optional rendered forensic audit note.
    ///
    /// Always `None` on every path this module owns: a presented note is
    /// refused, by the owner-bound configuration projection as
    /// [`ProjectionError::OwnerEvidenceUnavailable`] and independently by
    /// [`validate_admission`] as [`PreparationError::OwnerEvidenceUnavailable`],
    /// because no owner reachable from Host issues or corroborates such a note.
    /// The field is kept so the receipt shape is unchanged, and so a tampered
    /// record that carries one is detected rather than silently reinterpreted.
    /// It can never act as a lease, grant, or current-state assertion; no API
    /// converts it into one.
    pub audit_fence_note: Option<String>,
    /// Opaque caller-presented entropy text.
    ///
    /// Deliberately NOT an input to the destination identity or the preparation
    /// epoch: [`derive_destination_id`] and [`derive_destination_epoch`] bind
    /// owner-issued evidence instead, so a caller cannot select either by
    /// choosing this value and an archive-supplied value cannot determine
    /// either. It stays part of the presented contract surface and remains
    /// hashed into the admission digest, so rotating it is still a changed
    /// idempotency input.
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
///
/// It is a fenced empty root under a protected staging parent, **not** an
/// installation allocated through the installation authority: no
/// `ApprovedGeneration` row, registry CAS or activation fence is created for
/// it, because the registry exposes no public mutation seam. Nothing here is
/// restored, launched, activated or retired.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedDestination {
    /// Operation identity that produced it.
    pub operation_id: String,
    /// Created destination root (under the admitted staging parent).
    pub root: PathBuf,
    /// Pinned OS identity captured at creation.
    pub root_identity: RootIdentity,
    /// Destination identity bound to owner-issued evidence (never an archive or
    /// caller copy, and never caller-selectable).
    pub destination_id: String,
    /// Preparation-scope lineage marker bound to the same owner-issued
    /// evidence as [`PreparedDestination::destination_id`].
    ///
    /// **Not** an Authority Epoch: no Authority Epoch is issued by this module
    /// (see the module documentation), and nothing here consumes this value as
    /// one. A preparation receipt must never be read as epoch authority.
    pub destination_epoch: u64,
    /// Admission receipt digest binding the admitted inputs.
    pub admission_digest: String,
    /// Owner-issued configuration projection digest this destination was
    /// admitted under (hex64). Present so the prepared-destination receipt
    /// states the proved configuration evidence directly instead of only
    /// through [`PreparedDestination::admission_digest`].
    pub config_projection_digest: String,
    /// Optional rendered forensic audit note.
    ///
    /// Always `None` on every path this module owns; a presented note is
    /// refused, never rendered into a receipt. See
    /// [`DestinationAdmission::audit_fence_note`].
    pub audit_fence_note: Option<String>,
}

/// Reconcile disposition for one operation (issue #958, cases 958/12, 958/14).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileDisposition {
    /// No intent recorded: safe to prepare (or absent entirely).
    ///
    /// Reachable ONLY when the journal holds no record for the operation. A
    /// recorded intent is never reported as `Absent`, whatever the state of its
    /// root: the operation was admitted, and `Absent` is a claim that it never
    /// was.
    Absent,
    /// Recorded result re-verified against the live root: reuse, do not duplicate.
    Current(PreparedDestination),
    /// Intent is durable but no result was ever recorded, and the derived root
    /// is not observable: the operation is admitted and its outcome is UNKNOWN.
    ///
    /// This is deliberately distinct from both [`Self::Absent`] and
    /// [`Self::Uncertain`]. It is not absent because the intent proves the
    /// operation was admitted; it is not `Uncertain` because no receipt exists to
    /// be uncertain *about* — there is no recorded outcome at all, only a
    /// recorded admission whose effect may or may not have happened before the
    /// process stopped. I14.21 requires an unknown to pause the Ordering Scope
    /// and preserve the operation; reporting it as absent would let a second
    /// preparation run under the same operation id and overwrite the recorded
    /// intent, destroying the only evidence that the first one was admitted.
    AdmittedWithoutResult {
        /// The admission digest the durable intent binds, carried so the recorded
        /// operation identity survives reconciliation instead of being discarded
        /// as "nothing happened". A caller may compare it against its own
        /// admission to prove it is retrying the same operation, never to adopt
        /// a destination from it.
        admission_digest: String,
    },
    /// State cannot be established: preserved as-is, never deleted, never retried blindly.
    Uncertain { reason: String },
}

/// Cleanup report: reclaimed owned-unactivated roots vs preserved unknowns.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CleanupReport {
    /// Operation ids whose owned roots were reclaimed.
    ///
    /// Only an operation whose whole protocol completed is listed here: the
    /// ownership proof, the custody disposition, the retained `CleanupPending`
    /// transition, the bounded empty-root removal AND the retained `Reclaimed`
    /// transition. A root that was removed but whose `Reclaimed` retention was
    /// refused is reported under [`Self::preserved`] instead, so `removed` is
    /// never a claim about a durable state this module could not write.
    pub removed: Vec<String>,
    /// Operation ids preserved with reasons (unknown/foreign/mismatch/populated/
    /// unauthorized). An operation the sweep stopped before is preserved here
    /// too, so a partial sweep is always visible in the returned report.
    pub preserved: Vec<(String, String)>,
}

/// Current disposition of any unresolved restore/cutover custody claim over one
/// destination root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DestinationCustody {
    /// The owners this sink reads retain no unresolved custody claim over this
    /// exact destination.
    Released,
    /// Custody is unresolved, or this sink cannot observe the records that
    /// would settle it. The destination is preserved, never reclaimed.
    ///
    /// Absence of proof is never proof of absence: a sink that cannot see the
    /// custody records must never be read as "no custody", so the port default
    /// is this variant and only an owner that actually reads them may report
    /// [`Self::Released`].
    Unresolved(String),
}

/// Durable intent/result sink port (issue #958).
///
/// **The production sink is [`HostStatePreparationJournal`].** It writes the
/// owner's [`BackupPreparationRecord`] through the same `HostStateRecord`
/// variant, the same `HostStateJournalService`, the same single-writer
/// reconcile choke every other Host journal write uses, and the same
/// `backup_preparations` projection — one record store, one writer, no second
/// registry. `HostComposition::prepare_backup_destination` constructs it from
/// its own `ProductionHostStateJournal`, so the composition port no longer
/// accepts a caller-supplied sink and the durable path is the only production
/// one. The in-memory `MemJournal` in
/// `bins/eliot-host/tests/backup_preparation.rs` remains a second
/// implementation of the same port for the declared suite.
///
/// A4's semantics — a repeated request returns the same verified destination or
/// a typed conflict, never a second installation, and reconciliation preserves
/// an unknown rather than retrying it — are implemented once, above this port,
/// and are therefore exactly as durable as the sink bound to it.
///
/// The owner's record variant was delivered by #961 (`c8b6bf64`, PR #3893) and
/// is deliberately not a stand-in for anything else: a preparation record is
/// distinguishable from a `CutoverIntentRecord` because a preparation creates a
/// fenced destination and stops, while a cutover activates an approved
/// installation generation. Nothing here reuses an unrelated record's semantics
/// (a preparation intent is never written as a `ReactiveContext` or
/// `Observation` record), and the installation registry is not used as a
/// substitute: an unactivated destination is not an approved generation.
///
/// # What the four states mean here
///
/// The sink writes `Pending` **before** the destination root is created and
/// `Prepared` **after** the root exists and its OS identity was pinned, then
/// `CleanupPending` **before** an owner-authorized reclamation effect and
/// `Reclaimed` only **after** its absence was observed. A
/// `Pending` frame therefore proves only that the operation was admitted, which
/// is what I5.6's `ACCEPTED_PENDING` means and what I5.27 requires: a committed
/// canonical intent never proves an external effect occurred. It cannot
/// distinguish "the root was never created" from "created but not pinned", does
/// not try, and is never treated as permission to prepare a second destination
/// under the same operation identity. `Prepared` is the proof that this
/// operation — and no other — created that exact directory; a `Pending` root is
/// reconciled and preserved, never deleted by path name.
///
/// `Reclaimed` is terminal and every successor out of it is refused: a record
/// that says the root was observed gone cannot become authority that it exists.
/// The pinned identity is carried forward through both cleanup states rather
/// than dropped when the root goes away, because that identity is the whole
/// authorization for the reclamation.
///
/// # Cancellation
///
/// Cancellation is **not a state of this record**: the owner's transition law
/// admits exactly `Pending -> Prepared -> CleanupPending -> Reclaimed`.
/// [`cancel_preparation`] over this sink therefore refuses with a typed
/// [`PreparationError`] naming that boundary, and preserves the prepared root for
/// the owner-governed [`cleanup_preparations`] sweep. The in-memory sink keeps
/// cancellation as a lifecycle state of its own
/// ([`PreparationLifecycleState::Cancelled`]); what is refused here is writing it
/// into a record that has no such state, because mapping it onto a cleanup state
/// would assert an observed absence nobody looked for. Cancellation alone is
/// never proof that a populated root is safe to destroy.
///
/// Synchronous narrow port: record intent before effects, result after;
/// load-before-act for idempotency.
pub trait PreparationJournal {
    /// Records the preparation intent (admission digest + derived root).
    fn record_intent(
        &mut self,
        operation_id: &str,
        intent: &serde_json::Value,
    ) -> Result<(), PreparationError>;
    /// Records the preparation result (receipt).
    ///
    /// The same port carries the owner-authorized **cleanup transition**
    /// ([`cleanup_transition_json`]): a sink that accepts the transition has
    /// authorized the reclamation, and a sink that refuses it has not, so the
    /// sweep preserves the destination rather than deleting on a receipt alone.
    /// Cancellation and cleanup stay separate transitions and neither is proof
    /// that a populated root is safe to destroy.
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
    /// Current disposition of unresolved restore/cutover custody over one
    /// destination root.
    ///
    /// Defaults to [`DestinationCustody::Unresolved`] because a sink that does
    /// not read the custody records cannot prove they are clear: the default is
    /// the fail-closed answer, not a permissive stub, and a reclamation is
    /// refused unless an implementation that actually reads the owners reports
    /// [`DestinationCustody::Released`].
    fn destination_custody(&self, _root: &Path) -> DestinationCustody {
        DestinationCustody::Unresolved(
            "this sink observes no restore/cutover custody records; an unobservable claim is \
             unresolved, not absent"
                .to_owned(),
        )
    }
}

/// Durable [`PreparationJournal`] over the owner's Host state journal.
///
/// This is the production sink for issue #958's A4. It holds a borrow of the
/// composition's own [`ProductionHostStateJournal`] and writes the owner's
/// [`BackupPreparationRecord`] through `crate::journal_append::append_reconciled`
/// — the single reconcile-decision choke every `ProductionHostStateJournal`
/// write in this crate already goes through, so an unknown append outcome is
/// reconciled under one policy rather than forked here.
///
/// It adds no storage, no writer and no lifecycle of its own: the record type,
/// its state law, its fence, its idempotency keying and its `backup_preparations`
/// projection are all the Host journal owner's. Two things are decided here
/// rather than delegated, and both are decisions about *this* operation's
/// effect identity, which the durable record is the only place to express:
///
/// - the per-outcome journal mutation identity `<operation>:<state>`, so the
///   admission and its result are two mutations and a retry of the *same*
///   outcome replays byte-identically;
/// - the transition from the retained `Pending` frame to the `Prepared` frame,
///   which is built by **carrying the retained record's own binding forward**
///   and changing only the state and the pinned identity. The owner-issued
///   authority generation, class, source installation, proposed destination,
///   admission digest and destination identity are therefore read back from the
///   durable record, never reconstructed from the presented request, and the
///   owner's own `backup_preparation_transition` independently re-checks that
///   the successor agrees with the frame it replaces.
///
/// # Reads
///
/// [`PreparationJournal::load`] projects a retained record back into the same
/// JSON shape the in-memory sink stores, from the fields the record actually
/// retains. It does not invent the fields the record does not carry (the
/// presented `source_root`, `staging_parent`, build/profile names, nonce and
/// state fence), so `conflict_field` is documented to skip absent recorded
/// fields rather than blame one. The admission digest - which is what actually
/// decides a repeated request - is retained in full, and a repeat is compared
/// against that **recorded** value, never against a freshly recomputed one.
pub struct HostStatePreparationJournal<'a> {
    journal: &'a ProductionHostStateJournal,
}

impl<'a> HostStatePreparationJournal<'a> {
    /// Binds the composition's own Host state journal as the durable sink.
    pub fn new(journal: &'a ProductionHostStateJournal) -> Self {
        Self { journal }
    }

    /// Reads the journal snapshot this sink projects and appends through.
    fn snapshot(&self) -> Result<HostState, PreparationError> {
        self.journal
            .snapshot()
            .map_err(|error| PreparationError::JournalFault(error.to_string()))
    }

    /// Returns the fence every preparation record is written under.
    ///
    /// Taken from the **current owner-issued activation record's own fence**,
    /// never from a caller or from a presented value: `RecordFence` requires
    /// every record in one activation generation to carry the same identity, and
    /// the reducer re-establishes that binding against the activation
    /// projection on append. Using the activation record's fence verbatim is
    /// what makes the binding agree by construction instead of by a second
    /// caller-supplied copy.
    ///
    /// A journal with no current activation is refused rather than given an
    /// invented one: there is no activation generation to bind a durable record
    /// to, and absence of proof is never proof of absence.
    fn record_fence(&self) -> Result<RecordFence, PreparationError> {
        let state = self.snapshot()?;
        state
            .activation
            .as_ref()
            .map(|activation| activation.fence.clone())
            .ok_or_else(|| {
                note_prepare_error(
                    OP_JOURNAL_SINK,
                    "record_fence",
                    PreparationError::InvalidRequest {
                        field: "activation_fence",
                        reason: "no current activation record; a durable preparation cannot be \
                                 bound to an activation generation"
                            .to_owned(),
                    },
                    0,
                )
            })
    }

    /// Returns the retained record for one admitted preparation operation, if any.
    ///
    /// The `backup_preparations` projection is indexed by the admitted
    /// preparation operation identity, so this is the owner's own key: there is
    /// no second lookup index here and no way to address a preparation by any
    /// other name.
    fn retained(
        &self,
        operation_id: &str,
    ) -> Result<Option<BackupPreparationRecord>, PreparationError> {
        Ok(self
            .snapshot()?
            .backup_preparations
            .into_iter()
            .find(|record| record.preparation_operation.as_str() == operation_id))
    }

    /// Appends one record through the composition's single journal write choke.
    ///
    /// The owner error is preserved as this module's own journal-fault variant
    /// rather than being collapsed further: it is the narrow port's declared
    /// sink-fault type, and it carries the owner's message, never a caller value.
    fn append(&self, record: BackupPreparationRecord) -> Result<(), PreparationError> {
        crate::journal_append::append_reconciled(
            self.journal,
            HostStateRecord::BackupPreparation(record),
        )
        .map(|_receipt| ())
        .map_err(|error| {
            note_prepare_error(
                OP_JOURNAL_SINK,
                "append",
                PreparationError::JournalFault(error.to_string()),
                0,
            )
        })
    }
}

/// Builds one validated handle, or the typed refusal that replaces an
/// unbuildable one.
///
/// The owner's record validates every handle it carries, so a value that cannot
/// become a handle is refused here with the module's own typed
/// [`PreparationError::InvalidRequest`] naming the field, rather than being
/// substituted with a placeholder that would put an invented identity into a
/// durable record.
fn preparation_handle(
    value: &str,
    field: &'static str,
) -> Result<PlatformHandle, PreparationError> {
    PlatformHandle::new(value.to_owned()).map_err(|_| PreparationError::InvalidRequest {
        field,
        reason: "value is not a valid journal handle".to_owned(),
    })
}

/// Stable wire spelling of one preparation state, used to derive the per-outcome
/// journal mutation identity. Kept in lockstep with
/// [`BackupPreparationState`]'s `SCREAMING_SNAKE_CASE` serde, and with
/// [`PreparationLifecycleState::spelling`], which spells the same four states
/// the same way so one record cannot be spelled two ways.
const fn preparation_state_spelling(state: BackupPreparationState) -> &'static str {
    match state {
        BackupPreparationState::Pending => "pending",
        BackupPreparationState::Prepared => "prepared",
        BackupPreparationState::CleanupPending => "cleanup_pending",
        BackupPreparationState::Reclaimed => "reclaimed",
    }
}

/// Builds one journal mutation identity for a single outcome of a preparation.
///
/// One identity per outcome, because the journal keys `applied_operations` on it:
/// reusing one for the admission and its result would be a checksum conflict
/// rather than a second mutation. Replaying the *same* outcome reuses the same
/// identity and therefore reproduces byte for byte. The base is the admitted
/// operation identity, never a presented string, and the key is the canonical
/// admission digest - the I5.27 `canonical_request_hash` for this operation.
fn preparation_mutation(
    operation_id: &str,
    state: BackupPreparationState,
    admission_digest: &str,
) -> Result<IdempotencyIdentity, PreparationError> {
    let mutation = format!("{operation_id}:{}", preparation_state_spelling(state));
    Ok(IdempotencyIdentity {
        operation_id: preparation_handle(&mutation, "preparation_operation")?,
        idempotency_key: preparation_handle(admission_digest, "admission_digest")?,
    })
}

impl PreparationJournal for HostStatePreparationJournal<'_> {
    /// Writes the durable `Pending` admission, before any destination effect.
    ///
    /// The admitted binding is read back out of the intent this module itself
    /// produced, so the record carries the operation's own owner-issued
    /// authority generation, configuration projection digest and destination
    /// lineage marker rather than anything reconstructed at the sink.
    fn record_intent(
        &mut self,
        operation_id: &str,
        intent: &serde_json::Value,
    ) -> Result<(), PreparationError> {
        let admission: DestinationAdmission =
            serde_json::from_value(intent.get("admission").cloned().ok_or(
                PreparationError::InvalidRequest {
                    field: "admission",
                    reason: "intent frame carries no admission".to_owned(),
                },
            )?)
            .map_err(|_| PreparationError::InvalidRequest {
                field: "admission",
                reason: "intent admission is not a decodable admission".to_owned(),
            })?;
        let root = intent
            .get("root")
            .and_then(serde_json::Value::as_str)
            .ok_or(PreparationError::InvalidRequest {
                field: "root",
                reason: "intent frame carries no proposed destination".to_owned(),
            })?;
        let destination_id = intent
            .get("destination_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(PreparationError::InvalidRequest {
                field: "destination_id",
                reason: "intent frame carries no owner-issued destination identity".to_owned(),
            })?;
        let destination_epoch = intent
            .get("destination_epoch")
            .and_then(serde_json::Value::as_u64)
            .ok_or(PreparationError::InvalidRequest {
                field: "destination_epoch",
                reason: "intent frame carries no destination lineage marker".to_owned(),
            })?;
        let admission_digest = intent
            .get("admission_digest")
            .and_then(serde_json::Value::as_str)
            .ok_or(PreparationError::InvalidRequest {
                field: "admission_digest",
                reason: "intent frame carries no admission digest".to_owned(),
            })?;
        let record = BackupPreparationRecord {
            fence: self.record_fence()?,
            operation: preparation_mutation(
                operation_id,
                BackupPreparationState::Pending,
                admission_digest,
            )?,
            preparation_operation: preparation_handle(operation_id, "preparation_operation")?,
            class: preparation_handle(admission.class.as_str(), "class")?,
            source_installation: preparation_handle(
                &admission.source_installation_id,
                "source_installation",
            )?,
            // See `PREPARATION_NO_SOURCE_ARCHIVE`: preparation binds no archive,
            // and the absence is recorded explicitly rather than filled with an
            // invented identity.
            source_archive: preparation_handle(PREPARATION_NO_SOURCE_ARCHIVE, "source_archive")?,
            admission_digest: preparation_handle(admission_digest, "admission_digest")?,
            // The proposed destination, recorded before any effect. It is a
            // name, not ownership: only a `Prepared` frame's pinned identity
            // authorises deleting anything at this path.
            destination_root: preparation_handle(root, "destination_root")?,
            destination_id: preparation_handle(destination_id, "destination_id")?,
            config_projection_digest: preparation_handle(
                &admission.config_projection_digest,
                "config_projection_digest",
            )?,
            authority_generation: admission.authority_generation,
            destination_epoch,
            // `Pending` proves admission only, so it must not claim an effect.
            destination_root_identity: None,
            // The evidence an unsettled admission retains: the canonical request
            // hash it was admitted under and the owner-issued destination
            // identity it proposed. Both are digests, so no path or caller text
            // enters the evidence list, and the frame is never evidence-free.
            retained_evidence_refs: vec![
                preparation_handle(admission_digest, "admission_digest")?,
                preparation_handle(destination_id, "destination_id")?,
            ],
            state: BackupPreparationState::Pending,
        };
        self.append(record)
    }

    /// Writes the durable outcome, after the root exists and is pinned or after an
    /// owner-authorized reclamation has been decided.
    ///
    /// The frame is built by carrying the **retained** record's own binding forward
    /// and changing only the state and the pinned identity. That is what makes a
    /// successor of the exact admission rather than a fresh claim: the owner-issued
    /// authority generation and the rest of the binding are read from the durable
    /// record, and the owner's `backup_preparation_transition` re-checks the
    /// agreement. A frame whose own values disagree with the retained frame is
    /// refused here as a typed conflict before any append, so a mismatched result
    /// never reaches the journal as a re-scoped preparation.
    ///
    /// **The frame's own lifecycle state chooses the durable state**, through
    /// [`PreparationLifecycleState::durable_state`]. That mapping is what makes
    /// reclamation reachable at all: the frame a caller retains before an effect
    /// is `cleanup_pending` and the one it retains after observing the absence is
    /// `reclaimed`, so the durable record follows the effect rather than always
    /// claiming `Prepared`. `Cancelled` has no durable state and is refused -
    /// cancellation is not a state of this record, and it is never proof that a
    /// populated root is safe to destroy.
    ///
    /// The pinned identity is carried forward through the cleanup states because
    /// the owner's record validation requires it there and because it is the whole
    /// authorization for a reclamation: a `Reclaimed` frame that could not re-pin
    /// the root would be asserting a deletion nothing proved this operation was
    /// entitled to perform. A cleanup frame that disagrees with the retained
    /// identity is refused rather than allowed to overwrite it.
    ///
    /// The frame is read back through [`decode_preparation_record`], the one reader
    /// every read path in this module uses, so this sink cannot accept a frame
    /// shape the rest of the lifecycle would refuse.
    fn record_result(
        &mut self,
        operation_id: &str,
        result: &serde_json::Value,
    ) -> Result<(), PreparationError> {
        let Some(retained) = self.retained(operation_id)? else {
            return Err(PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "no durable admission for this operation; a result may not be recorded \
                         before its intent"
                    .to_owned(),
            });
        };
        let lifecycle = decode_preparation_record(operation_id, result)?;
        let Some(state) = lifecycle.state().durable_state() else {
            // `Cancelled` reaches this port: a cancellation is not a durable
            // preparation state, and mapping it onto `Reclaimed` would assert an
            // observed absence nobody looked for.
            return Err(PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "cancellation is not a state of this durable preparation record; the \
                         prepared destination is preserved for the owner-governed cleanup sweep"
                    .to_owned(),
            });
        };
        if retained.state == BackupPreparationState::Reclaimed {
            // `Reclaimed` is terminal in the owner's transition law. Nothing can
            // succeed it: not a cancellation, not a second reclamation, and not a
            // fresh preparation, because a terminal record that says the root was
            // observed gone cannot become authority that it exists.
            return Err(PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "the durable preparation record is terminal; its reclamation was observed \
                         and no successor state is admitted"
                    .to_owned(),
            });
        }
        if retained.state == state {
            // A repeat of the outcome already recorded. It is refused here rather
            // than re-appended: the owner's transition law admits exactly one step
            // forward per effect and refuses a self-transition, and this record's
            // state is already the one the caller asked to write.
            return Err(PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "the durable preparation record already carries this outcome; the \
                         transition is idempotent by record identity and is not re-appended"
                    .to_owned(),
            });
        }
        let destination = lifecycle.preserved_receipt();
        let pinned = destination.root_identity.identity.as_str();
        // The result must describe the very root and identity the durable
        // admission proposed, or it is not this operation's result. Every
        // comparison is against the RETAINED value, never a recomputation.
        if !windows_paths_equal(
            &destination.root,
            Path::new(retained.destination_root.as_str()),
        ) || destination.destination_id != retained.destination_id.as_str()
            || destination.admission_digest != retained.admission_digest.as_str()
            || destination.config_projection_digest != retained.config_projection_digest.as_str()
            || destination.destination_epoch != retained.destination_epoch
        {
            return Err(PreparationError::ConflictField {
                field: "destination",
            });
        }
        // A cleanup state carries the identity forward from the record it
        // succeeds; a frame that names a different one is not this operation's
        // reclamation.
        // A retained record that pinned no identity cannot be advanced into a
        // cleanup state: the pinned identity is the SOLE proof that this
        // operation created that exact root, and a cleanup frame that carried
        // none would authorise a deletion nothing proved. The owner's own
        // record validation refuses such a frame too; refusing here names the
        // operation instead of surfacing it as a journal fault.
        if retained
            .destination_root_identity
            .as_ref()
            .is_some_and(|retained_identity| retained_identity.as_str() != pinned)
        {
            return Err(PreparationError::ConflictField {
                field: "destination_root_identity",
            });
        }
        if retained.destination_root_identity.is_none() {
            return Err(PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "the retained record pinned no destination identity, so this operation \
                         cannot prove it created the root it would reclaim"
                    .to_owned(),
            });
        }
        let record = BackupPreparationRecord {
            fence: retained.fence.clone(),
            // One mutation identity per outcome, so a repeat of the SAME state
            // reproduces byte for byte and a different state is a distinct
            // mutation rather than a checksum conflict.
            operation: preparation_mutation(
                operation_id,
                state,
                retained.admission_digest.as_str(),
            )?,
            preparation_operation: retained.preparation_operation.clone(),
            class: retained.class.clone(),
            source_installation: retained.source_installation.clone(),
            source_archive: retained.source_archive.clone(),
            admission_digest: retained.admission_digest.clone(),
            destination_root: retained.destination_root.clone(),
            destination_id: retained.destination_id.clone(),
            config_projection_digest: retained.config_projection_digest.clone(),
            authority_generation: retained.authority_generation,
            destination_epoch: retained.destination_epoch,
            destination_root_identity: Some(preparation_handle(
                pinned,
                "destination_root_identity",
            )?),
            // An outcome necessarily carries evidence a `Pending` admission
            // cannot: that this operation created the root and pinned its
            // identity. The list is digests and handles only, and the owner's
            // transition law deliberately does not require it to equal the
            // admission's - the cleanup states carry the same proof forward,
            // because it is still the proof that authorizes the reclamation.
            retained_evidence_refs: vec![
                retained.admission_digest.clone(),
                retained.destination_id.clone(),
                preparation_handle(pinned, "destination_root_identity")?,
            ],
            state,
        };
        self.append(record)
    }

    /// Projects one retained record back into the `(intent, result)` JSON shape
    /// the preparation lifecycle reads.
    ///
    /// The intent is reconstructed from exactly the fields the durable record
    /// retains, and declares
    /// [`RecordedAdmissionBinding::OwnerProjection`] so
    /// [`validate_recorded_binding`] reads it as the owner's retained binding
    /// instead of guessing from a decode that happened to fail. The canonical
    /// parent is the recorded destination root's own parent: the root was created
    /// as `<canonical parent>/dest-<destination id>`, so it is a structural fact
    /// of the retained record rather than a re-observation of the registry, and
    /// the join re-checks that the two agree.
    ///
    /// The result exists only for a record that has a recorded outcome. `Pending`
    /// has none and projecting one would be the fabrication this module exists to
    /// prevent. A `CleanupPending` or `Reclaimed` record projects its own state,
    /// so a read-back yields that terminal disposition rather than a usable
    /// destination.
    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<(serde_json::Value, Option<serde_json::Value>)>, PreparationError> {
        let Some(record) = self.retained(operation_id)? else {
            return Ok(None);
        };
        // `audit_fence_note` is never carried: a caller-authored forensic note
        // is refused before it can reach a receipt on this path, and the durable
        // record deliberately has nowhere to put one. Projecting `None` states
        // that absence truthfully rather than dropping the field.
        let canonical_parent = Path::new(record.destination_root.as_str())
            .parent()
            .ok_or_else(|| PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "retained destination root names no parent directory".to_owned(),
            })?
            .to_path_buf();
        check_persistable_path(&canonical_parent, "canonical_parent")?;
        check_persistable_path(
            Path::new(record.destination_root.as_str()),
            "destination_root",
        )?;
        let intent = serde_json::json!({
            "version": PREPARATION_VERSION,
            "operation_id": operation_id,
            "admission_digest": record.admission_digest,
            "admission_binding": RecordedAdmissionBinding::OwnerProjection.spelling(),
            "admission": {
                "class": record.class,
                "source_installation_id": record.source_installation,
                "authority_generation": record.authority_generation,
                "config_projection_digest": record.config_projection_digest,
            },
            "canonical_parent": persistable_path_text(&canonical_parent, "canonical_parent")?,
            "root": record.destination_root,
            "destination_id": record.destination_id,
            "destination_epoch": record.destination_epoch,
        });
        // The pinned identity exists in every state except `Pending`; the owner's
        // record validation refuses the other combinations, so the two impossible
        // arms are refused here rather than treated as "no recorded result" - a
        // record that does have an outcome must not be projected as one that does
        // not.
        let result = match (record.state, &record.destination_root_identity) {
            (BackupPreparationState::Pending, _) => None,
            (_, Some(identity)) => {
                let destination = PreparedDestination {
                    operation_id: operation_id.to_owned(),
                    root: PathBuf::from(record.destination_root.as_str()),
                    root_identity: RootIdentity {
                        identity: identity.as_str().to_owned(),
                    },
                    destination_id: record.destination_id.as_str().to_owned(),
                    destination_epoch: record.destination_epoch,
                    admission_digest: record.admission_digest.as_str().to_owned(),
                    config_projection_digest: record.config_projection_digest.as_str().to_owned(),
                    audit_fence_note: None,
                };
                let frame = match record.state {
                    BackupPreparationState::Pending => {
                        return Err(PreparationError::UnknownState {
                            operation: operation_id.to_owned(),
                            reason: "an unsettled preparation cannot carry a pinned identity"
                                .to_owned(),
                        });
                    }
                    BackupPreparationState::Prepared => {
                        result_json(&destination, PreparationLifecycleState::Prepared)
                    }
                    BackupPreparationState::CleanupPending => cleanup_transition_json(
                        &destination,
                        CleanupTransitionState::CleanupPending,
                    ),
                    BackupPreparationState::Reclaimed => {
                        cleanup_transition_json(&destination, CleanupTransitionState::Reclaimed)
                    }
                }?;
                Some(frame)
            }
            (_, None) => {
                return Err(PreparationError::UnknownState {
                    operation: operation_id.to_owned(),
                    reason: "retained preparation outcome carries no pinned destination identity"
                        .to_owned(),
                });
            }
        };
        Ok(Some((intent, result)))
    }

    /// Lists the operation identities the durable projection owns.
    ///
    /// This is the journal's own key set, which is what makes the cleanup sweep's
    /// "owned" test real: a caller can narrow the set but never extend it, and a
    /// requested id this journal does not own is refused by
    /// [`cleanup_preparations`] rather than deleted.
    fn list_operations(&self) -> Result<Vec<String>, PreparationError> {
        Ok(self
            .snapshot()?
            .backup_preparations
            .iter()
            .map(|record| record.preparation_operation.as_str().to_owned())
            .collect())
    }

    /// Reads the durable restore/cutover custody records this journal owns.
    ///
    /// The join is deliberately narrow and exact: the retained cutover intent
    /// must name the **same destination identity** the durable preparation
    /// record holds for this exact root. `HostState::pending_cutover` is a
    /// single slot, so a claim over some other installation says nothing about
    /// this root and is not custody of it; a claim over this destination — at
    /// any disposition, because an intent that already committed is an
    /// *adopted* destination, not an unactivated preparation root — leaves the
    /// root unresolved and therefore unreclaimable.
    ///
    /// An unreadable snapshot is `Unresolved` for the same reason the port
    /// default is: absence of proof is never proof of absence.
    fn destination_custody(&self, root: &Path) -> DestinationCustody {
        let state = match self.snapshot() {
            Ok(state) => state,
            Err(error) => {
                return DestinationCustody::Unresolved(format!(
                    "durable custody records are unavailable: {error}"
                ));
            }
        };
        let Some(intent) = state.pending_cutover.as_ref() else {
            return DestinationCustody::Released;
        };
        let claimed = state.backup_preparations.iter().any(|record| {
            windows_paths_equal(Path::new(record.destination_root.as_str()), root)
                && intent.installation == record.destination_id
        });
        if claimed {
            return DestinationCustody::Unresolved(
                "a retained cutover intent claims this exact destination; an unactivated \
                 preparation root is never reclaimed while restore/cutover custody over it is \
                 unresolved or has already activated it"
                    .to_owned(),
            );
        }
        DestinationCustody::Released
    }
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

/// Refuses a rendered forensic audit note carried in an admission (case 958/3).
///
/// The note would be caller-authored: nothing in this module compares its digest
/// or its observed dispositions to Host state, so a receipt carrying it would
/// publish unverified disposition claims under a forensic label. I5.13 keeps the
/// `HostStateAuditFence` optional, so refusing it is a complete answer rather
/// than a gap, and no note-size bound is needed because no note is ever carried.
///
/// This is the strongest of the two refusals A1's optional audit fence admits.
/// The note's own typed non-authoritative ceiling is enforced where a note is
/// admissible at all
/// (`crate::backup_config_projection::AuditFenceNote::validate`, refusing
/// `ProjectionError::ActiveAuthorityInAuditFence`); refusing every note here is
/// stronger still, because no owner corroborates the note's lineage in the
/// first place, so a lease/grant/current-state assertion is unreachable rather
/// than merely bounded.
fn reject_audit_note(note: Option<&String>) -> Result<(), PreparationError> {
    if note.is_some() {
        return Err(PreparationError::OwnerEvidenceUnavailable {
            field: "audit_fence_note",
            obligation: "a HostStateAuditFence must be issued or corroborated by the owner that observed \
                 the installation lineage; preparation admits no caller-authored forensic note",
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

/// Summarizes the owner-issued evidence a destination identity binds.
///
/// Three owner-issued facts and nothing else: the authority generation carried
/// by the committed activation fence, the configuration projection digest the
/// owner-bound projector proved, and the **owner-resolved** staging parent
/// returned by the protected-root owner (not the caller's path name). Together
/// with the operation identity and the preparation version they form the input
/// to [`derive_destination_id`] and [`derive_destination_epoch`].
///
/// The caller-presented [`DestinationAdmission::authority_nonce`] is excluded on
/// purpose. With it in the derivation, a caller could enumerate values until it
/// liked the produced identity, and an archive-supplied value would make the
/// identity archive-determined.
///
/// The three owner-issued inputs are named rather than taken from the whole
/// admission so that the one caller that re-derives the identity from a
/// **retained record** — [`validate_recorded_binding`] — feeds this function the
/// same owner-issued facts a fresh preparation feeds it. The hashed input set is
/// identical either way; nothing about the derivation is re-implemented for the
/// read-back path.
fn owner_identity_evidence(
    authority_generation: u64,
    config_projection_digest: &str,
    owner_resolved_parent: &Path,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"eliot.backup.destination.owner-identity-evidence.v1\0");
    hasher.update(PREPARATION_VERSION.to_le_bytes());
    hash_field(
        &mut hasher,
        b"authority_generation",
        &authority_generation.to_le_bytes(),
    );
    hash_field(
        &mut hasher,
        b"config_projection_digest",
        config_projection_digest.as_bytes(),
    );
    hash_path(&mut hasher, b"owner_resolved_parent", owner_resolved_parent);
    format!("{:x}", hasher.finalize())
}

/// Destination identity bound to owner-issued evidence (issue #958, case
/// 958/9).
///
/// Deterministic, domain-separated derivation from the operation identity plus
/// the owner-evidence summary produced by [`owner_identity_evidence`]: fresh per
/// operation, stable across repeats, and never equal to archive-supplied or
/// caller-chosen values. The caller cannot select it: no presented field, and in
/// particular not `authority_nonce`, is an input, and the path component is the
/// owner-resolved parent rather than a name the caller chose.
#[must_use]
pub fn derive_destination_id(operation_id: &str, owner_evidence: &str) -> String {
    sha_hex(&[
        DESTINATION_ID_DOMAIN.as_bytes(),
        b"\0identity\0",
        operation_id.as_bytes(),
        b"\0",
        owner_evidence.as_bytes(),
    ])
}

/// Preparation-scope lineage marker bound to the same owner-issued evidence
/// (see [`derive_destination_id`]).
///
/// It is **not** an Authority Epoch and no Authority Epoch is issued here: a new
/// Authority Epoch lineage strictly above every observed epoch is the cutover
/// child's owner obligation (I5.13, A13.7), and the installation authority
/// exposes no epoch-allocating seam to this module. Nothing in this module
/// consumes the returned value as an epoch; it only discriminates one fenced
/// preparation from another under identical owner evidence.
#[must_use]
pub fn derive_destination_epoch(operation_id: &str, owner_evidence: &str) -> u64 {
    let digest = sha_hex(&[
        DESTINATION_ID_DOMAIN.as_bytes(),
        b"\0epoch\0",
        operation_id.as_bytes(),
        b"\0",
        owner_evidence.as_bytes(),
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

/// Renders one path into its persisted text, or refuses it.
///
/// `Path::to_str` yields `None` on Windows exactly when the `OsString` holds an
/// unpaired surrogate, i.e. when `to_string_lossy` would write U+FFFD and two
/// different roots could come back as one name. Such a path is refused rather
/// than recorded lossily, because `hash_path` above deliberately digests the
/// RAW bytes: a record whose text cannot reproduce those bytes would carry a
/// digest over one path and a name over another.
///
/// This runs on the admission, before any intent or effect
/// ([`validate_admission`]), and again on every path this module constructs, so
/// a path that cannot round-trip never reaches a durable record. It also keeps
/// both `hash_path` variants in agreement with the persisted encoding: the
/// digest is over raw bytes and the record is over the text that maps back to
/// exactly those bytes, or the path is refused.
///
/// One function so there is one refusal and one rendering: no writer on the
/// persistence path can reintroduce a lossy conversion behind its back.
fn persistable_path_text<'a>(
    path: &'a Path,
    field: &'static str,
) -> Result<&'a str, PreparationError> {
    path.to_str()
        .ok_or_else(|| PreparationError::InvalidRequest {
            field,
            reason:
                "path has no lossless text form on this platform; refusing before any intent or \
                 effect rather than recording replacement characters"
                    .to_owned(),
        })
}

/// Shape-only wrapper over [`persistable_path_text`] for the places that only
/// need the refusal, not the text.
fn check_persistable_path(path: &Path, field: &'static str) -> Result<(), PreparationError> {
    persistable_path_text(path, field).map(|_text| ())
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
/// and return the same recorded destination. The audit-note arm is now
/// unreachable on every path this module owns — a presented note is refused —
/// but it stays in the hashed set so the digest remains a faithful encoding of
/// the whole struct and a record that somehow carries one is detected.
///
/// v4 changes no field of the hashed set. The record version itself moved to 2
/// (see [`PREPARATION_VERSION`]: an explicit lifecycle state, a retained
/// canonical parent, and a lossless path encoding), and the version is an input
/// here, so a v4 digest is a v2-canonical-encoding digest. The domain separator
/// moves with it: the digest is versioned by its own separator as well as by the
/// record version, so a digest written under the v1 record version can never be
/// compared as if it were written under v2 and vice versa (I5.27: canonical
/// encoding is deterministic and versioned).
fn admission_digest(admission: &DestinationAdmission) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"eliot.backup.destination-admission.v4\0");
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

/// Re-proves one recorded destination through the real protected-root owner and
/// **returns the retained proof**, never `Ok(())`.
///
/// A recorded receipt is evidence of a past effect, not proof of a live root.
/// Before a recorded destination is reused ([`reconcile_preparation`]) or
/// reclaimed ([`cleanup_preparations`]), the recorded root is re-opened through
/// [`ProtectedRootLease::open_existing`] — the owner that containment-checks
/// the path and pins the whole directory contour by retained handle — and only
/// then are the canonical path, the retained-handle alias defence
/// ([`ProtectedRootLease::verify_stable_identity`]) and the owner-observed
/// [`FileIdentity`] compared against the recorded values. Any failure is a
/// typed [`PreparationError`]: the recorded root is no longer an owned
/// protected object, and the caller preserves it rather than acting on a name.
///
/// The return value is the point. The lease owns the pinned directory contour
/// and dies at `return`, so a caller that received only `Ok(())` would have to
/// re-resolve the pathname to act on it, and between the proof and that
/// re-resolution the name can be rebound to a different object. Handing the
/// lease back instead makes the caller either use it (as
/// [`ProtectedRootLease::into_removal_proof`] does) or drop it, and there is no
/// longer a shape in which a proved-then-reopened deletion can be written.
fn reverify_recorded_destination(
    operation_id: &str,
    destination: &PreparedDestination,
) -> Result<ProtectedRootLease, PreparationError> {
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
    Ok(lease)
}

/// Validates one admission without effects (cases 958/5-7).
///
/// The generation arm compares [`DestinationAdmission::approved_generation`]
/// against [`DestinationAdmission::authority_generation`], and that is only a
/// real check when the second value came from owner evidence:
/// [`DelegatedPreparation::prepare`] fills it from
/// [`OwnerEvidence::authority_generation`], so the production path refuses an
/// unapproved generation (case 958/7). The shape checks here stay shape checks:
/// `target_build` and `target_profile` are bounded text here, and the owner
/// comparison that approves them by name is in
/// [`DelegatedPreparation::prepare`], where the owner record is in hand.
///
/// A presented forensic audit note is refused here, before any effect and
/// independently of the configuration projection, so no caller-authored
/// disposition claim can enter a receipt through this port either.
fn validate_admission(admission: &DestinationAdmission) -> Result<(), PreparationError> {
    check_identity(&admission.operation_id, "operation_id")?;
    // The admission's two paths are hashed RAW into the admission digest (see
    // `hash_path`) and persisted into the durable intent. A path with no
    // lossless text form would therefore be hashed as one path and recorded as
    // another: two distinct Windows roots could share one admission digest, and
    // a record could round-trip a name the digest never covered. Refusing here
    // is before any intent and before any filesystem observation, which is the
    // only place a refusal still costs nothing.
    check_persistable_path(&admission.source_root, "source_root")?;
    check_persistable_path(&admission.staging_parent, "staging_parent")?;
    check_identity(&admission.source_installation_id, "source_installation_id")?;
    check_identity(&admission.target_build, "target_build")?;
    check_identity(&admission.target_profile, "target_profile")?;
    check_digest(&admission.manifest_digest, "manifest_digest")?;
    check_digest(
        &admission.config_projection_digest,
        "config_projection_digest",
    )?;
    reject_audit_note(admission.audit_fence_note.as_ref())?;
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

/// How a recorded intent carries its admission, declared in the record itself.
///
/// The join in [`validate_recorded_binding`] re-derives the admission digest, and
/// re-deriving it requires the *whole* [`DestinationAdmission`]. A durable
/// [`BackupPreparationRecord`] retains the owner-issued binding and the canonical
/// admission digest but not every presented field, so
/// [`HostStatePreparationJournal::load`] cannot reproduce the admitted request
/// byte for byte - and it must not fabricate the missing fields to pretend it
/// can. Declaring which encoding an intent actually carries turns that difference
/// into a typed, per-record fact instead of a decode that quietly succeeded.
///
/// The alternative - probing with `serde_json::from_value` and treating a failure
/// as "it must have been a projection" - is exactly the permissive reader this
/// record version exists to remove: a tampered full admission would fail to
/// decode and be reclassified as a projection, skipping the recomputation. So the
/// discriminator is written by the writer and read by the reader, and a value
/// outside this closed set is refused rather than guessed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordedAdmissionBinding {
    /// The intent carries the complete admitted request; the digest is
    /// recomputed from it and compared against the recorded value.
    Complete,
    /// The intent carries only the owner's retained binding; the recorded
    /// admission digest is the owner's own canonical value and is joined
    /// against the result, never recomputed over fields that were not retained.
    OwnerProjection,
}

impl RecordedAdmissionBinding {
    /// Stable wire spelling of one admission binding.
    const fn spelling(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::OwnerProjection => "owner_projection",
        }
    }

    /// Parses one wire spelling, refusing anything outside the closed set.
    fn from_spelling(value: &str) -> Option<Self> {
        match value {
            "complete" => Some(Self::Complete),
            "owner_projection" => Some(Self::OwnerProjection),
            _ => None,
        }
    }
}

/// Builds the durable intent frame for one admitted preparation.
///
/// `destination_id` and `destination_epoch` are carried here because the
/// durable sink writes them into [`BackupPreparationRecord`], and the owner's
/// record requires both: the identity as a digest and the lineage marker as a
/// non-zero value. Neither is recoverable from the proposed root alone - the
/// epoch is not encoded in the path name - so re-deriving them at the sink from
/// what the sink holds would mean recomputing an owner-issued value instead of
/// recording the one this operation was admitted under. They are the exact
/// values `prepare_isolated_destination` just derived from owner evidence and
/// passes to the record, not a second derivation.
///
/// `canonical_parent` is the owner-resolved parent the destination was created
/// under, retained here so [`validate_recorded_binding`] can re-derive
/// `destination_id` and `destination_epoch` from the SAME recorded owner
/// evidence a read-back sees. Re-observing the registry to learn "current"
/// evidence instead would compare this operation's recorded identities against a
/// world that has since moved, which is precisely the reconstructed history this
/// frame exists to make unnecessary.
///
/// The root and the parent are rendered through [`persistable_path_text`]: a path
/// that cannot be written without changing is refused here, before the intent
/// exists, rather than persisted through replacement characters.
fn intent_json(
    admission: &DestinationAdmission,
    digest: &str,
    canonical_parent: &Path,
    root: &Path,
    destination_id: &str,
    destination_epoch: u64,
) -> Result<serde_json::Value, PreparationError> {
    Ok(serde_json::json!({
        "version": PREPARATION_VERSION,
        "operation_id": admission.operation_id,
        "admission_digest": digest,
        "admission": admission,
        "admission_binding": RecordedAdmissionBinding::Complete.spelling(),
        "canonical_parent": persistable_path_text(canonical_parent, "canonical_parent")?,
        "root": persistable_path_text(root, "root")?,
        "destination_id": destination_id,
        "destination_epoch": destination_epoch,
    }))
}

/// Names the first differing admission field between the recorded intent and
/// a changed re-presentation (case 958/13).
///
/// The compared list mirrors the v3 [`admission_digest`] hashed set exactly.
/// `source_root` was missing here while being the field that decides which
/// installation is the live source, so a conflict could never name it.
///
/// A field the recorded intent does not carry is **skipped**, not reported as a
/// difference. [`HostStatePreparationJournal`] reconstructs the recorded
/// admission from the durable [`BackupPreparationRecord`], which retains the
/// owner-issued binding but not every presented field; comparing an absent
/// recorded value against a present current one would name the first
/// non-retained field for *every* conflict, blaming a field that did not
/// change. Skipping keeps the diagnostic honest: the fields this can name are
/// exactly the ones both sides hold, and a conflict only in non-retained fields
/// falls through to the `"admission"` digest-level name. The refusal itself is
/// unaffected - it is raised from the admission digest comparison, not from
/// this naming.
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
        // Absent from the recorded admission: this sink cannot compare it, so
        // it must not be named.
        if recorded.and_then(|value| value.get(field)).is_none() {
            continue;
        }
        if recorded.and_then(|value| value.get(field)) != current.get(field) {
            return field;
        }
    }
    "admission"
}

/// Renders the durable result frame for one prepared destination.
///
/// `state` is the lifecycle state the frame declares, and it is written here
/// rather than inferred on read: before v2 a frame carried no state at all and
/// any object with the right field names decoded as a usable destination, which
/// is what let a cancelled or reclaimed operation replay as `Prepared`.
///
/// The root is rendered through [`persistable_path_text`], so a path with no
/// lossless text form is refused at write time instead of being recorded through
/// replacement characters.
fn result_json(
    destination: &PreparedDestination,
    state: PreparationLifecycleState,
) -> Result<serde_json::Value, PreparationError> {
    Ok(serde_json::json!({
        "version": PREPARATION_VERSION,
        "state": state.spelling(),
        "operation_id": destination.operation_id,
        "root": persistable_path_text(&destination.root, "root")?,
        "root_identity": destination.root_identity.identity,
        "destination_id": destination.destination_id,
        "destination_epoch": destination.destination_epoch,
        "admission_digest": destination.admission_digest,
        "config_projection_digest": destination.config_projection_digest,
        "audit_fence_note": destination.audit_fence_note,
    }))
}

/// Version of the owner-authorized cleanup transition block (issue #958, A4).
///
/// Distinct from [`PREPARATION_VERSION`], which versions the whole preparation
/// record. The cleanup transition is a separate owner decision with its own
/// authorization, and reusing the record version would make a reclaimed root
/// indistinguishable from a prepared one in the same frame.
pub const CLEANUP_TRANSITION_VERSION: u32 = 1;

/// The two states of the owner-authorized cleanup transition.
///
/// `CleanupPending` is retained **before** the reclamation effect and `Reclaimed`
/// only **after** the effect has been observed, so a crash between them leaves a
/// durable "may have been reclaimed" record rather than a receipt that claims a
/// root is gone when nobody looked.
///
/// This is deliberately not a second preparation lifecycle: it is the reclamation
/// half of the one closed set in [`PreparationLifecycleState`], and
/// [`cleanup_transition_lifecycle`] is the single mapping between them so a
/// transition can never be written under one spelling and read under another.
/// Cancellation is a third, separate thing entirely: none of these states is proof
/// that a populated root is safe to destroy, and a `Cancelled` record in
/// particular says only that the operation was withdrawn, not that its root is
/// empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupTransitionState {
    /// Reclamation is authorized and about to be attempted.
    CleanupPending,
    /// The reclamation was attempted and its absence was observed.
    Reclaimed,
}

impl CleanupTransitionState {
    /// Stable wire spelling of one cleanup transition state.
    const fn spelling(self) -> &'static str {
        match self {
            Self::CleanupPending => "cleanup_pending",
            Self::Reclaimed => "reclaimed",
        }
    }
}

/// Maps one cleanup transition state onto its lifecycle state.
///
/// The one place the two closed sets meet, so [`cleanup_transition_json`] and
/// [`decode_preparation_record`] cannot disagree about what a transition means on
/// the wire.
const fn cleanup_transition_lifecycle(state: CleanupTransitionState) -> PreparationLifecycleState {
    match state {
        CleanupTransitionState::CleanupPending => PreparationLifecycleState::CleanupPending,
        CleanupTransitionState::Reclaimed => PreparationLifecycleState::Reclaimed,
    }
}

/// The closed set of states one persisted preparation record may declare.
///
/// These are **states of the record**, not of the filesystem. A record's state
/// and what is on disk are different questions, and only `Prepared` may ever be
/// read as "this operation produced a usable destination":
///
/// - `Prepared` — this operation exclusively created the recorded root and its
///   identity was pinned. It is the only state from which a caller may reuse a
///   [`PreparedDestination`].
/// - `Cancelled` — the operation was withdrawn. The preserved receipt is
///   historical evidence of what once existed; it is never current preparation
///   authority, and a cancelled record is never proof that its root is empty.
/// - `CleanupPending` — an owner-authorized reclamation is durable and its
///   effect is **not** observed. Whether the root survives is unknown, so the
///   record authorizes observation, not reuse.
/// - `Reclaimed` — the reclamation was attempted and the absence was observed.
///   Terminal, and in particular never a claim that the root exists.
///
/// The spellings are the same ones [`preparation_state_spelling`] gives the
/// durable [`BackupPreparationState`] variants, so one record cannot be written
/// under one spelling and read under another.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationLifecycleState {
    /// The destination was created and its OS identity pinned.
    Prepared,
    /// The operation was withdrawn; the prior receipt is preserved as evidence.
    Cancelled,
    /// A reclamation is authorized and about to be attempted, not yet observed.
    CleanupPending,
    /// The reclamation was attempted and the absence was actually observed.
    Reclaimed,
}

impl PreparationLifecycleState {
    /// Stable wire spelling of one lifecycle state.
    const fn spelling(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Cancelled => "cancelled",
            Self::CleanupPending => "cleanup_pending",
            Self::Reclaimed => "reclaimed",
        }
    }

    /// Parses one wire spelling.
    ///
    /// `None` for anything outside the closed set, including a state a future
    /// version adds: an unrecognized state is refused and preserved, never read
    /// as the nearest known one.
    fn from_spelling(value: &str) -> Option<Self> {
        match value {
            "prepared" => Some(Self::Prepared),
            "cancelled" => Some(Self::Cancelled),
            "cleanup_pending" => Some(Self::CleanupPending),
            "reclaimed" => Some(Self::Reclaimed),
            _ => None,
        }
    }

    /// The durable owner state this lifecycle state is written as, if any.
    ///
    /// [`Self::Cancelled`] has none: cancellation is **not** a state of
    /// [`BackupPreparationRecord`], so a cancel envelope can never become a
    /// durable preparation outcome. Returning `None` here is what keeps
    /// cancellation from being smuggled into the owner's state law as a
    /// reclaimed-looking record.
    const fn durable_state(self) -> Option<BackupPreparationState> {
        match self {
            Self::Prepared => Some(BackupPreparationState::Prepared),
            Self::CleanupPending => Some(BackupPreparationState::CleanupPending),
            Self::Reclaimed => Some(BackupPreparationState::Reclaimed),
            Self::Cancelled => None,
        }
    }
}

/// One decoded preparation lifecycle record.
///
/// This is the only shape any read path in this module produces. A caller that
/// wants a [`PreparedDestination`] must go through
/// [`PreparationLifecycle::usable_destination`], which exists so that "is this
/// record still usable" is a property of the decoded record and not of a
/// caller's willingness to read fields off an arbitrary object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparationLifecycle {
    /// Usable: this operation created the recorded root and it is still a
    /// candidate destination. The only state that yields a destination.
    Prepared(PreparedDestination),
    /// Withdrawn. `prior_receipt` is the receipt preserved as history.
    Cancelled {
        /// Historical evidence only. Never current preparation authority, and
        /// never proof that the root is empty.
        prior_receipt: PreparedDestination,
    },
    /// Reclamation authorized, effect not observed.
    CleanupPending {
        /// Historical evidence only, as for [`Self::Cancelled`].
        prior_receipt: PreparedDestination,
    },
    /// Reclamation attempted and its absence observed. Terminal.
    Reclaimed {
        /// Historical evidence only, as for [`Self::Cancelled`].
        prior_receipt: PreparedDestination,
    },
}

impl PreparationLifecycle {
    /// The decoded lifecycle state of this record.
    #[must_use]
    pub fn state(&self) -> PreparationLifecycleState {
        match self {
            Self::Prepared(_) => PreparationLifecycleState::Prepared,
            Self::Cancelled { .. } => PreparationLifecycleState::Cancelled,
            Self::CleanupPending { .. } => PreparationLifecycleState::CleanupPending,
            Self::Reclaimed { .. } => PreparationLifecycleState::Reclaimed,
        }
    }

    /// The usable destination, or `None` for every non-`Prepared` state.
    ///
    /// The one accessor a caller may use to obtain a [`PreparedDestination`]
    /// from a decoded record. Cancellation, a pending reclamation and a
    /// completed one all return `None`, so no read path can resurrect `Prepared`
    /// from a terminal record even if it wants to.
    #[must_use]
    pub fn usable_destination(&self) -> Option<&PreparedDestination> {
        match self {
            Self::Prepared(destination) => Some(destination),
            Self::Cancelled { .. } | Self::CleanupPending { .. } | Self::Reclaimed { .. } => None,
        }
    }

    /// The record's preserved receipt, whether it is still usable or historical.
    ///
    /// For the three terminal states this is evidence and nothing more; it is
    /// what a reclamation candidate is checked against, and it is never returned
    /// as a destination a caller may work with.
    #[must_use]
    pub fn preserved_receipt(&self) -> &PreparedDestination {
        match self {
            Self::Prepared(destination) => destination,
            Self::Cancelled { prior_receipt }
            | Self::CleanupPending { prior_receipt }
            | Self::Reclaimed { prior_receipt } => prior_receipt,
        }
    }
}

/// Reads one required text field from a recorded frame.
///
/// Refuses an absent field and a wrong-typed one with the same typed error: a
/// field that is not the shape this module writes is a malformed record, and
/// defaulting it (to empty, or to the lookup key) is how a partial object became
/// a usable destination in the first place.
fn recorded_text<'a>(
    frame: &'a serde_json::Value,
    field: &'static str,
    operation_id: &str,
) -> Result<&'a str, PreparationError> {
    frame
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason: format!("recorded record carries no readable {field} field"),
        })
}

/// Reads one required unsigned field from a recorded frame, refusing zero.
fn recorded_u64(
    frame: &serde_json::Value,
    field: &'static str,
    operation_id: &str,
) -> Result<u64, PreparationError> {
    let value = frame
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(|| PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason: format!("recorded record carries no readable nonzero {field} field"),
        })?;
    Ok(value)
}

/// Renders one owner-authorized cleanup transition frame.
///
/// The frame carries the exact binding the reclamation is authorized against —
/// the operation identity, the owner-issued destination identity and lineage
/// marker, the admission digest and the pinned OS identity — so a retained
/// transition names *this* destination and can never be read as authorization
/// for a different one. The prior receipt is preserved beside it, exactly as
/// [`cancel_preparation`] preserves its own, so no evidence is destroyed by
/// moving the operation into cleanup.
///
/// The frame's own `state` is the cleanup state, and the nested `transition`
/// block repeats it under its own version. The decoder requires the two to
/// agree, so a frame cannot declare `cleanup_pending` at the top and carry a
/// `reclaimed` transition underneath it and still be read.
fn cleanup_transition_json(
    destination: &PreparedDestination,
    state: CleanupTransitionState,
) -> Result<serde_json::Value, PreparationError> {
    let prior_receipt = result_json(destination, PreparationLifecycleState::Prepared)?;
    let mut frame = result_json(destination, cleanup_transition_lifecycle(state))?;
    frame["transition"] = serde_json::json!({
        "version": CLEANUP_TRANSITION_VERSION,
        "operation_id": destination.operation_id,
        "state": state.spelling(),
        "destination_id": destination.destination_id,
        "destination_epoch": destination.destination_epoch,
        "admission_digest": destination.admission_digest,
        "root_identity": destination.root_identity.identity,
    });
    frame["prior_receipt"] = prior_receipt;
    Ok(frame)
}

/// The one decoder for a persisted preparation lifecycle record.
///
/// Every read path in this module goes through it: the exact prepare replay,
/// reconciliation, cancellation and the cleanup sweep. There is no second
/// reader of these frames anywhere in this file, so a frame is interpreted the
/// same way no matter which operation observes it.
///
/// What it refuses, and why each refusal is not a default:
///
/// - an unsupported `version`, on the intent, the result or the nested
///   transition block — the record was written under rules this decoder does not
///   implement, and re-interpreting it under different rules is how a reclaimed
///   root becomes a prepared one;
/// - a missing, wrong-typed or unrecognized `state` — `None` is never mapped
///   onto `Prepared`, because "I do not know what this is" and "this is usable"
///   are different facts and only one of them may produce a destination;
/// - a `transition` block that disagrees with the frame's own `state`, or names
///   a different operation, destination, epoch, digest or pinned identity — a
///   contradictory binding is evidence of a record that cannot be trusted, not a
///   field to prefer one reading of;
/// - a frame whose stored `operation_id` differs from the lookup key — refused,
///   never overwritten with the requested identity;
/// - a malformed or wrongly-typed destination field.
///
/// `prior_receipt` is decoded as history and never as the frame's current state:
/// for the three terminal states it is the receipt that once existed, and
/// [`PreparationLifecycle::usable_destination`] returns `None` regardless of
/// what it says.
#[allow(
    clippy::too_many_lines,
    reason = "the decoder's refusals stay in one function so no version, state or transition check can be skipped between its neighbours; splitting them would put the ordering back under the caller's discretion"
)]
fn decode_preparation_record(
    operation_id: &str,
    result: &serde_json::Value,
) -> Result<PreparationLifecycle, PreparationError> {
    if result.get("version").and_then(serde_json::Value::as_u64)
        != Some(u64::from(PREPARATION_VERSION))
    {
        return Err(PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason:
                "recorded record carries a version this decoder does not implement; preserved, \
                     never re-interpreted"
                    .to_owned(),
        });
    }
    // The stored operation identity is the record's own. A frame naming a
    // different operation is refused here; substituting the lookup key would
    // reattribute a foreign record to this operation.
    let stored_operation_id = recorded_text(result, "operation_id", operation_id)?;
    if stored_operation_id != operation_id {
        return Err(PreparationError::IdentityConflict {
            operation: operation_id.to_owned(),
            recorded: stored_operation_id.to_owned(),
            observed: operation_id.to_owned(),
        });
    }
    let state_text = result
        .get("state")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason: "recorded record declares no lifecycle state; preserved, never read as \
                     prepared"
                .to_owned(),
        })?;
    let Some(state) = PreparationLifecycleState::from_spelling(state_text) else {
        return Err(PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason: "recorded record declares an unrecognized lifecycle state; preserved, never \
                     read as prepared"
                .to_owned(),
        });
    };
    let receipt = decode_recorded_destination(operation_id, result)?;
    // A lifecycle state and the transition block that authorizes it are two
    // statements of the same fact, so they must agree. A frame that claims a
    // cleanup state with no transition block, or with one naming a different
    // state, is a contradictory binding rather than a partially-written frame.
    match result.get("transition") {
        Some(transition) => {
            let transition_state = transition
                .get("state")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| PreparationError::UnknownState {
                    operation: operation_id.to_owned(),
                    reason: "cleanup transition block declares no state; preserved".to_owned(),
                })?;
            if transition
                .get("version")
                .and_then(serde_json::Value::as_u64)
                != Some(u64::from(CLEANUP_TRANSITION_VERSION))
                || state.spelling() != transition_state
                || !state_is_cleanup(state)
                || transition
                    .get("operation_id")
                    .and_then(serde_json::Value::as_str)
                    != Some(operation_id)
                || transition
                    .get("destination_id")
                    .and_then(serde_json::Value::as_str)
                    != Some(receipt.destination_id.as_str())
                || transition
                    .get("destination_epoch")
                    .and_then(serde_json::Value::as_u64)
                    != Some(receipt.destination_epoch)
                || transition
                    .get("admission_digest")
                    .and_then(serde_json::Value::as_str)
                    != Some(receipt.admission_digest.as_str())
                || transition
                    .get("root_identity")
                    .and_then(serde_json::Value::as_str)
                    != Some(receipt.root_identity.identity.as_str())
            {
                return Err(PreparationError::ConflictField {
                    field: "transition",
                });
            }
        }
        None if state_is_cleanup(state) => {
            return Err(PreparationError::ConflictField {
                field: "transition",
            });
        }
        None => {}
    }
    // A prepared or cancelled frame carrying a cleanup transition would claim a
    // reclamation that its own state denies; refuse it rather than prefer one.
    if !state_is_cleanup(state) && result.get("transition").is_some() {
        return Err(PreparationError::ConflictField {
            field: "transition",
        });
    }
    match state {
        PreparationLifecycleState::Prepared => Ok(PreparationLifecycle::Prepared(receipt)),
        terminal => {
            // The preserved receipt is history, decoded for evidence and shape
            // only. It is never read as the frame's current preparation state.
            let prior_receipt = match result.get("prior_receipt") {
                Some(prior) => decode_recorded_destination(operation_id, prior)?,
                None => receipt.clone(),
            };
            Ok(match terminal {
                PreparationLifecycleState::Cancelled => {
                    PreparationLifecycle::Cancelled { prior_receipt }
                }
                PreparationLifecycleState::CleanupPending => {
                    PreparationLifecycle::CleanupPending { prior_receipt }
                }
                PreparationLifecycleState::Reclaimed => {
                    PreparationLifecycle::Reclaimed { prior_receipt }
                }
                // `Prepared` is handled above and never reaches this arm.
                PreparationLifecycleState::Prepared => {
                    return Err(PreparationError::UnknownState {
                        operation: operation_id.to_owned(),
                        reason: "prepared state reached the terminal branch".to_owned(),
                    });
                }
            })
        }
    }
}

/// Whether one lifecycle state is a cleanup transition state.
///
/// A `Prepared` or `Cancelled` frame that carries a transition block, or a
/// cleanup state that carries none, is a contradictory record; both directions
/// are refused by the decoder, and this predicate is the single place that
/// decides which direction a state belongs to.
const fn state_is_cleanup(state: PreparationLifecycleState) -> bool {
    matches!(
        state,
        PreparationLifecycleState::CleanupPending | PreparationLifecycleState::Reclaimed
    )
}

/// Decodes the destination fields shared by every lifecycle state.
///
/// Strictly typed: every field is required, `audit_fence_note` is required to be
/// absent, and each identity is shape-checked with this module's existing rules.
/// Nothing here takes the operation identity from the caller — it reads the
/// frame's own — so a decoded record always names the operation it belongs to.
fn decode_recorded_destination(
    operation_id: &str,
    frame: &serde_json::Value,
) -> Result<PreparedDestination, PreparationError> {
    let stored_operation_id = recorded_text(frame, "operation_id", operation_id)?;
    if stored_operation_id != operation_id {
        return Err(PreparationError::IdentityConflict {
            operation: operation_id.to_owned(),
            recorded: stored_operation_id.to_owned(),
            observed: operation_id.to_owned(),
        });
    }
    let audit_fence_note = match frame.get("audit_fence_note") {
        Some(serde_json::Value::String(text)) => Some(text.clone()),
        Some(serde_json::Value::Null) | None => None,
        // A present but wrong-typed note is a malformed record, not an absent
        // one: treating it as absent would let a tampered result round-trip.
        Some(_) => {
            return Err(PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "recorded record carries a forensic audit note of the wrong shape"
                    .to_owned(),
            });
        }
    };
    let destination = PreparedDestination {
        operation_id: stored_operation_id.to_owned(),
        root: PathBuf::from(recorded_text(frame, "root", operation_id)?),
        root_identity: RootIdentity {
            identity: recorded_text(frame, "root_identity", operation_id)?.to_owned(),
        },
        destination_id: recorded_text(frame, "destination_id", operation_id)?.to_owned(),
        destination_epoch: recorded_u64(frame, "destination_epoch", operation_id)?,
        admission_digest: recorded_text(frame, "admission_digest", operation_id)?.to_owned(),
        config_projection_digest: recorded_text(frame, "config_projection_digest", operation_id)?
            .to_owned(),
        audit_fence_note,
    };
    check_recorded_destination_shapes(operation_id, &destination)?;
    Ok(destination)
}

/// The required identity shapes of a decoded destination.
///
/// Applied to every decoded record, terminal states included: a malformed
/// preserved receipt is still a malformed record, and shape-checking only the
/// usable state would let a terminal frame carry an unbounded or control-
/// carrying identity into a preserved report.
fn check_recorded_destination_shapes(
    operation_id: &str,
    destination: &PreparedDestination,
) -> Result<(), PreparationError> {
    check_persistable_path(&destination.root, "root").map_err(|error| {
        // Re-raise under the operation being read so the typed error names the
        // operation whose record was unreadable.
        PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason: error.to_string(),
        }
    })?;
    check_identity(&destination.operation_id, "operation_id")?;
    check_identity(&destination.root_identity.identity, "root_identity")?;
    check_digest(&destination.destination_id, "destination_id")?;
    check_digest(&destination.admission_digest, "admission_digest")?;
    check_digest(
        &destination.config_projection_digest,
        "config_projection_digest",
    )?;
    // A presented forensic note is never admissible in a receipt, so a decoded
    // one is a record that was tampered with or written under other rules.
    reject_audit_note(destination.audit_fence_note.as_ref())?;
    Ok(())
}

/// The one record validator, consumed by BOTH the prepare replay and
/// reconciliation.
///
/// The bug it replaces: the prepare replay compared only the intent digest and
/// then the result root's *file identity*, and reconciliation did not join the
/// result to its intent at all. A result could therefore name a root, an
/// identity and a destination identity that the recorded admission never
/// admitted, and reconciliation would report it `Current`.
///
/// What it checks, in order, all against **recorded** values:
///
/// 1. supported record version, on the intent and the result;
/// 2. the STORED operation identity on both frames against the lookup key —
///    refused on mismatch, never overwritten with the requested id;
/// 3. the recorded admission, decoded according to the intent's own declared
///    [`RecordedAdmissionBinding`], and the RECOMPUTED admission digest
///    ([`admission_digest`], not re-implemented) compared against the recorded
///    one;
/// 4. the result's admission digest and `config_projection_digest` against that
///    admission;
/// 5. the retained canonical parent and the exact root derived from it;
/// 6. `destination_id` and `destination_epoch` RE-DERIVED from the same recorded
///    owner evidence through [`owner_identity_evidence`],
///    [`derive_destination_id`] and [`derive_destination_epoch`] — compared
///    against the recorded values, never substituted with the re-derived ones;
/// 7. permitted audit-note absence and the required identity shapes, applied by
///    [`decode_recorded_destination`].
///
/// Point 5 is why the intent retains `canonical_parent`: re-observing the
/// registry to learn "current" evidence would compare this operation's recorded
/// identities against a world that has since moved, which is the reconstructed
/// history this check exists to avoid.
///
/// Returns the decoded lifecycle record. Callers that want a destination use
/// [`PreparationLifecycle::usable_destination`], so a terminal record cannot be
/// turned into one here.
#[allow(
    clippy::too_many_lines,
    reason = "the join's checks stay in one ordered function so no identity re-derivation can be reached before the record version, the stored operation id and the recorded admission have all been checked"
)]
fn validate_recorded_binding(
    operation_id: &str,
    intent: &serde_json::Value,
    result: &serde_json::Value,
) -> Result<PreparationLifecycle, PreparationError> {
    for frame in [intent, result] {
        if frame.get("version").and_then(serde_json::Value::as_u64)
            != Some(u64::from(PREPARATION_VERSION))
        {
            return Err(PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "recorded record carries a version this module does not implement; \
                         preserved, never re-interpreted"
                    .to_owned(),
            });
        }
        if recorded_text(frame, "operation_id", operation_id)? != operation_id {
            return Err(PreparationError::IdentityConflict {
                operation: operation_id.to_owned(),
                recorded: recorded_text(frame, "operation_id", operation_id)?.to_owned(),
                observed: operation_id.to_owned(),
            });
        }
    }
    let lifecycle = decode_preparation_record(operation_id, result)?;
    let receipt = lifecycle.preserved_receipt();
    // The result's own binding against the recorded intent's, before any
    // filesystem is observed.
    let recorded_digest = recorded_text(intent, "admission_digest", operation_id)?;
    if receipt.admission_digest != recorded_digest {
        return Err(PreparationError::ConflictField {
            field: "admission_digest",
        });
    }
    let binding_text = recorded_text(intent, "admission_binding", operation_id)?;
    let Some(binding) = RecordedAdmissionBinding::from_spelling(binding_text) else {
        return Err(PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason: "recorded intent declares an unrecognized admission binding; preserved, never \
                     guessed"
                .to_owned(),
        });
    };
    let admission_frame =
        intent
            .get("admission")
            .ok_or_else(|| PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "recorded intent carries no admission".to_owned(),
            })?;
    let owner_evidence = match binding {
        RecordedAdmissionBinding::Complete => {
            let admission = recorded_complete_admission(admission_frame, operation_id)?;
            // Recomputed from the recorded admission and compared against the
            // recorded digest: this is the I5.27 canonical request hash check, and
            // the two sides are independent.
            if admission_digest(&admission) != recorded_digest {
                return Err(PreparationError::ConflictField {
                    field: "admission_digest",
                });
            }
            RecordedOwnerEvidence {
                authority_generation: admission.authority_generation,
                config_projection_digest: admission.config_projection_digest,
            }
        }
        RecordedAdmissionBinding::OwnerProjection => {
            // The durable record does not retain every presented field, so the
            // admitted request cannot be rebuilt and this module does not invent
            // the missing ones to pretend otherwise. The recorded admission digest
            // is the owner's own canonical value and was joined against the result
            // above; what is re-derived here is the owner-issued binding the record
            // does retain.
            recorded_owner_projection_evidence(admission_frame, operation_id)?
        }
    };
    if receipt.config_projection_digest != owner_evidence.config_projection_digest {
        return Err(PreparationError::ConflictField {
            field: "config_projection_digest",
        });
    }
    let canonical_parent = PathBuf::from(recorded_text(intent, "canonical_parent", operation_id)?);
    check_persistable_path(&canonical_parent, "canonical_parent")?;
    if intent.get("root").and_then(serde_json::Value::as_str)
        != Some(persistable_path_text(&receipt.root, "root")?)
    {
        return Err(PreparationError::ConflictField {
            field: "destination_root",
        });
    }
    if recorded_text(intent, "destination_id", operation_id)? != receipt.destination_id
        || recorded_u64(intent, "destination_epoch", operation_id)? != receipt.destination_epoch
    {
        return Err(PreparationError::ConflictField {
            field: "destination",
        });
    }
    // Re-derived from the SAME recorded owner evidence, and compared against the
    // recorded values: a substituted value would pass by construction.
    let evidence = owner_identity_evidence(
        owner_evidence.authority_generation,
        &owner_evidence.config_projection_digest,
        &canonical_parent,
    );
    if derive_destination_id(operation_id, &evidence) != receipt.destination_id {
        return Err(PreparationError::ConflictField {
            field: "destination_id",
        });
    }
    if derive_destination_epoch(operation_id, &evidence) != receipt.destination_epoch {
        return Err(PreparationError::ConflictField {
            field: "destination_epoch",
        });
    }
    Ok(lifecycle)
}

/// The owner-issued facts every recorded-result identity is re-derived from.
///
/// Read out of the recorded admission under either
/// [`RecordedAdmissionBinding`], so the re-derivation below has one input shape
/// and never depends on which encoding the record happens to carry.
struct RecordedOwnerEvidence {
    /// Owner-issued authority generation the admission was admitted against.
    authority_generation: u64,
    /// Owner-issued configuration projection digest proved for the admission.
    config_projection_digest: String,
}

/// Decodes a recorded admission that declares itself complete.
///
/// Strictly typed and shape-checked exactly like a live admission
/// ([`validate_admission`]), so a record whose admission is well-formed JSON but
/// not a decodable admission, or is an admission for another operation, is
/// refused rather than partially believed.
fn recorded_complete_admission(
    recorded: &serde_json::Value,
    operation_id: &str,
) -> Result<DestinationAdmission, PreparationError> {
    let admission: DestinationAdmission =
        serde_json::from_value(recorded.clone()).map_err(|_| PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason: "recorded intent declares a complete admission that is not a decodable \
                     admission"
                .to_owned(),
        })?;
    if admission.operation_id != operation_id {
        return Err(PreparationError::IdentityConflict {
            operation: operation_id.to_owned(),
            recorded: admission.operation_id.clone(),
            observed: operation_id.to_owned(),
        });
    }
    validate_admission(&admission)?;
    Ok(admission)
}

/// Reads the owner-issued binding an `owner_projection` intent retains.
///
/// This is a narrow, explicit read of exactly the two fields the durable
/// [`BackupPreparationRecord`] keeps and this module re-derives from. It is not a
/// relaxed decode of a [`DestinationAdmission`]: no presented path, build, profile,
/// nonce or fence is substituted here, because the record does not carry them and
/// inventing them would put a value nobody admitted into a digest comparison.
fn recorded_owner_projection_evidence(
    recorded: &serde_json::Value,
    operation_id: &str,
) -> Result<RecordedOwnerEvidence, PreparationError> {
    let authority_generation = recorded
        .get("authority_generation")
        .and_then(serde_json::Value::as_u64)
        .filter(|generation| *generation != 0)
        .ok_or_else(|| PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason: "recorded owner projection carries no nonzero authority generation".to_owned(),
        })?;
    let config_projection_digest = recorded
        .get("config_projection_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason: "recorded owner projection carries no configuration projection digest"
                .to_owned(),
        })?
        .to_owned();
    check_digest(&config_projection_digest, "config_projection_digest")?;
    Ok(RecordedOwnerEvidence {
        authority_generation,
        config_projection_digest,
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
            // The SAME join reconciliation performs, and the same decoder. The
            // replay path previously checked only the intent digest and then the
            // result root's *file identity*, so a result naming a root, an
            // identity and a destination identity the recorded admission never
            // admitted replayed as a usable destination.
            let lifecycle = validate_recorded_binding(&admission.operation_id, &intent, &result)
                .map_err(|error| {
                    note_prepare_error(OP_PREPARE, "replay_check", error, generation)
                })?;
            // A cancelled, cleanup-pending or reclaimed record is terminal. An
            // exact replay returns that terminal disposition — never a usable
            // destination — and creates no root: cancellation replays as
            // cancellation, and a reclamation is never walked back.
            let Some(destination) = lifecycle.usable_destination() else {
                return Err(note_prepare_error(
                    OP_PREPARE,
                    "replay_check",
                    PreparationError::UnknownState {
                        operation: admission.operation_id.clone(),
                        reason: format!(
                            "recorded preparation lifecycle is {}; it is terminal, so this exact \
                             replay yields no destination and creates no root",
                            lifecycle.state().spelling()
                        ),
                    },
                    generation,
                ));
            };
            // The protected-root re-proof reconciliation uses, replacing the
            // weaker `capture_identity`-only check this path used. A recorded
            // receipt is evidence of a past effect, not proof of a live root, so
            // both replay paths now re-open the recorded root through the owner
            // that containment-checks and pins it.
            let lease = reverify_recorded_destination(&admission.operation_id, destination)
                .map_err(|error| {
                    note_prepare_error(OP_PREPARE, "replay_check", error, generation)
                })?;
            // Observed replay, not a second effect: the recorded destination is
            // re-verified and reused unchanged. The retained lease is dropped on
            // purpose — deciding a destination is reusable is not a reason to hold
            // delete authority over it; the reclamation path takes its own proof
            // immediately before its effect.
            drop(lease);
            observe_prepare_progress(
                OP_PREPARE,
                "replay_check",
                "replay_observed",
                generation,
                destination.destination_epoch,
            );
            return Ok(destination.clone());
        }
        // Intent without result: a crash between intent and result recording.
        // The operation was already admitted under this id, and the digest
        // above proved the retry carries identical inputs — so proceeding would
        // not be a first attempt, it would be a SECOND preparation under the
        // same operation id that overwrites the recorded intent and loses the
        // original one. A4 requires a repeated request to return the same
        // verified destination or a conflict, never another installation, and
        // I14.21 requires an unknown to pause rather than retry. Root present
        // additionally means unverified effects exist. Both cases therefore
        // refuse and preserve, whatever the root shows; the way out is the
        // owner-governed cancel/cleanup path, not a blind retry.
        let intent_root = intent
            .get("root")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let root_present = !intent_root.is_empty() && Path::new(intent_root).exists();
        return Err(note_prepare_error(
            OP_PREPARE,
            "replay_check",
            PreparationError::UnknownState {
                operation: admission.operation_id.clone(),
                reason: if root_present {
                    "intent without verifiable result and root present; reconcile before retry"
                        .to_owned()
                } else {
                    "intent recorded without result and root unobservable; the outcome is \
                     unknown, so the recorded intent is preserved rather than overwritten"
                        .to_owned()
                },
            },
            generation,
        ));
    }
    let canonical_parent = admit_staging_parent(admission)
        .map_err(|error| note_prepare_error(OP_PREPARE, "admit_parent", error, generation))?;
    // Identity and preparation-scope lineage bind owner-issued evidence and the
    // owner-resolved parent, never a presented field: see
    // `owner_identity_evidence`.
    let identity_evidence = owner_identity_evidence(
        admission.authority_generation,
        &admission.config_projection_digest,
        &canonical_parent,
    );
    let destination_id = derive_destination_id(&admission.operation_id, &identity_evidence);
    let root = canonical_parent.join(format!("dest-{destination_id}"));
    // The two owner-issued facts and the owner-resolved parent are what the
    // recorded-result join re-derives the destination identity from, so the
    // intent retains the parent rather than a read-back having to re-observe the
    // registry and compare this operation against a world that has since moved.
    check_persistable_path(&root, "root")
        .map_err(|error| note_prepare_error(OP_PREPARE, "record_intent", error, generation))?;
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
    let destination_epoch = derive_destination_epoch(&admission.operation_id, &identity_evidence);
    let intent = intent_json(
        admission,
        &digest,
        &canonical_parent,
        &root,
        &destination_id,
        destination_epoch,
    )
    .map_err(|error| note_prepare_error(OP_PREPARE, "record_intent", error, generation))?;
    journal
        .record_intent(&admission.operation_id, &intent)
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
        destination_epoch,
        admission_digest: digest,
        config_projection_digest: admission.config_projection_digest.clone(),
        audit_fence_note: admission.audit_fence_note.clone(),
    };
    let result = result_json(&destination, PreparationLifecycleState::Prepared)
        .map_err(|error| note_prepare_error(OP_PREPARE, "record_result", error, generation))?;
    journal
        .record_result(&admission.operation_id, &result)
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
/// No intent at all → `Absent` and retry may proceed. Intent + verifiable result
/// → `Current`, and only after the recorded root is re-proved through the real
/// protected-root owner ([`reverify_recorded_destination`]): a receipt alone is
/// not a live root. Intent without a result → `AdmittedWithoutResult` when the
/// root is unobservable and `Uncertain` when it is present, because the
/// operation was admitted either way and only a recorded result may be
/// reconciled into a destination. A result that cannot be re-proved → `Uncertain`.
///
/// `Absent` is reachable only when the journal holds no record. Reporting a
/// recorded intent as absent would let a second preparation run under the same
/// operation id and overwrite the recorded intent, which I14.21 forbids
/// ("unknown → pause Ordering Scope, preserve operation, open Problem State")
/// and which A4's own repeated-request rule forbids ("the same verified
/// destination or a conflict, not another installation"). Reconciliation never
/// deletes.
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
        // completion. The operation WAS admitted — the durable intent is the
        // proof — so it is never reported as absent, whatever the root shows.
        // Root present means unverified effects (preserve, never duplicate);
        // root absent means the outcome is simply unknown, because a root that
        // never materialized and a root that was created and later removed are
        // indistinguishable from here. I14.21: an unknown pauses the Ordering
        // Scope and preserves the operation; it is not an absence.
        let root_present = intent
            .get("root")
            .and_then(|value| value.as_str())
            .is_some_and(|root| Path::new(root).exists());
        if root_present {
            observe_prepare_progress(OP_RECONCILE, "outcome", "uncertain", 0, 0);
            return Ok(ReconcileDisposition::Uncertain {
                reason: "intent recorded without result and root present; effects unverified"
                    .to_owned(),
            });
        }
        observe_prepare_progress(OP_RECONCILE, "outcome", "admitted_unknown", 0, 0);
        return Ok(ReconcileDisposition::AdmittedWithoutResult {
            admission_digest: intent
                .get("admission_digest")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned(),
        });
    };
    // The SAME decoder and the SAME record-intent join the prepare replay uses.
    // Reconciliation previously decoded the result with a field-name reader and
    // did not join it to its intent at all, so a record whose result named a
    // root, an identity and a destination identity the recorded admission never
    // admitted reconciled as `Current`.
    let Ok(lifecycle) = validate_recorded_binding(operation_id, &intent, &result) else {
        observe_prepare_progress(OP_RECONCILE, "outcome", "uncertain", 0, 0);
        return Ok(ReconcileDisposition::Uncertain {
            // The specific refusal is deliberately not echoed: it names
            // recorded paths and digests. What matters to a reader is that
            // the outcome is unestablished and preserved.
            reason:
                "recorded result does not join its own recorded intent; preserved for inspection"
                    .to_owned(),
        });
    };
    // Only a `Prepared` record may reconcile into a usable destination. A
    // cancelled, cleanup-pending or reclaimed record is terminal or unsettled,
    // and reporting it `Current` is exactly the resurrection A13.7 `ARCH-RES-03`
    // forbids: a cancelled operation with an observable root used to reconcile as
    // `Current` and replay as a prepared destination.
    let Some(destination) = lifecycle.usable_destination() else {
        observe_prepare_progress(OP_RECONCILE, "outcome", "terminal", 0, 0);
        return Ok(ReconcileDisposition::Uncertain {
            reason: format!(
                "recorded preparation lifecycle is {}; it is not a usable destination and is \
                 preserved",
                lifecycle.state().spelling()
            ),
        });
    };
    match reverify_recorded_destination(operation_id, destination) {
        // The retained lease is dropped here on purpose: reconciliation only
        // needs to decide whether the recorded root is still the owned object,
        // and a decision is not a reason to hold delete authority over it. The
        // reclamation path takes its own proof immediately before its effect.
        Ok(_lease) => {
            observe_prepare_progress(
                OP_RECONCILE,
                "outcome",
                "current",
                0,
                destination.destination_epoch,
            );
            Ok(ReconcileDisposition::Current(destination.clone()))
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
/// cannot be cancelled; uncertain ones must reconcile first, and so must
/// admitted-but-unrecorded ones, which have no receipt to embed and are
/// preserved rather than released.
///
/// **Cancellation replays idempotently as cancellation.** This decodes the record
/// itself rather than going through [`reconcile_preparation`], because a cancelled
/// record reconciles as a preserved terminal disposition and never as `Current`;
/// routing cancellation through reconcile would make a repeated cancellation a
/// refusal ("reconcile first") instead of the same outcome. An operation already
/// cancelled therefore returns `Ok` again, and a `CleanupPending` or `Reclaimed`
/// record is refused because a reclamation is not a cancellation and cannot be
/// walked back.
pub fn cancel_preparation<J: PreparationJournal>(
    journal: &mut J,
    operation_id: &str,
) -> Result<(), PreparationError> {
    check_identity(operation_id, "operation_id")
        .map_err(|error| note_prepare_error(OP_CANCEL, "validate", error, 0))?;
    let recorded = journal
        .load(operation_id)
        .map_err(|error| note_prepare_error(OP_CANCEL, "load", error, 0))?;
    let Some((intent, result)) = recorded else {
        return Err(note_prepare_error(
            OP_CANCEL,
            "outcome",
            PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "nothing recorded; nothing to cancel".to_owned(),
            },
            0,
        ));
    };
    let Some(result) = result else {
        return Err(note_prepare_error(
            OP_CANCEL,
            "outcome",
            PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "admitted without a recorded result; there is no receipt to embed, so the \
                          operation is preserved for inspection"
                    .to_owned(),
            },
            0,
        ));
    };
    // The same decoder and the same intent join every other read path uses.
    let lifecycle = validate_recorded_binding(operation_id, &intent, &result)
        .map_err(|error| note_prepare_error(OP_CANCEL, "record_result", error, 0))?;
    match lifecycle {
        PreparationLifecycle::Prepared(destination) => {
            // Only a still-prepared operation is cancellable, and only after its
            // root is re-proved: a receipt alone is not proof that what is on
            // disk is still the object this operation created.
            reverify_recorded_destination(operation_id, &destination)
                .map_err(|error| note_prepare_error(OP_CANCEL, "reconcile", error, 0))?;
            let prior_receipt = result_json(&destination, PreparationLifecycleState::Prepared)
                .map_err(|error| note_prepare_error(OP_CANCEL, "record_result", error, 0))?;
            let mut envelope = result_json(&destination, PreparationLifecycleState::Cancelled)
                .map_err(|error| note_prepare_error(OP_CANCEL, "record_result", error, 0))?;
            envelope["prior_receipt"] = prior_receipt;
            journal
                .record_result(operation_id, &envelope)
                .map_err(|error| note_prepare_error(OP_CANCEL, "record_result", error, 0))?;
            observe_prepare_progress(OP_CANCEL, "outcome", "cancelled", 0, 0);
            Ok(())
        }
        PreparationLifecycle::Cancelled { .. } => {
            // Idempotent replay: the operation is already withdrawn, so it is
            // already cancelled. Re-recording would be a second terminal write
            // for one withdrawal, and the envelope is unchanged.
            observe_prepare_progress(OP_CANCEL, "outcome", "already_cancelled", 0, 0);
            Ok(())
        }
        PreparationLifecycle::CleanupPending { .. } => Err(note_prepare_error(
            OP_CANCEL,
            "outcome",
            PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason:
                    "an authorized reclamation is already pending and its effect is unobserved; \
                          cancellation is a different transition and cannot reverse it"
                        .to_owned(),
            },
            0,
        )),
        PreparationLifecycle::Reclaimed { .. } => Err(note_prepare_error(
            OP_CANCEL,
            "outcome",
            PreparationError::UnknownState {
                operation: operation_id.to_owned(),
                reason: "the destination was already reclaimed and its absence observed; there is \
                          nothing left to cancel"
                    .to_owned(),
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
/// Anything uncertain, foreign, mismatched, unleased, or source-related is
/// preserved with its reason. Reclamation is reachable at all because
/// [`admit_staging_parent`] proved every parent through the same protected
/// contour the re-proof requires, and `ARCH-RES-03` (A13.7) holds throughout:
/// recovery preserves what it cannot prove it owns.
///
/// The sweep is budgeted (case 958/16, A13.9): the presented narrowing list is
/// bounded by [`MAX_CLEANUP_REQUESTED_IDS`], the journal-owned set by
/// [`MAX_CLEANUP_SWEEP_OPERATIONS`], and elapsed time by
/// [`CLEANUP_SWEEP_BUDGET`]. A bound reached *before* the first irreversible
/// effect refuses the sweep with [`PreparationError::SweepBudget`] — it never
/// truncates the set, because a silent truncation would report a partial sweep
/// as complete and strand owned roots that still exist. A bound reached
/// *after* a reclamation reports through [`CleanupReport`] instead
/// ([`record_sweep_stop`]), so the roots this call already reclaimed and the
/// operations it never reached both survive the stop.
///
/// Reclamation of a `Current` destination is not a consequence of being
/// `Current`. A preparation receipt proves that this operation once created that
/// exact directory; it does not prove that the directory is still empty, that no
/// restore has populated it, and that no other owner has adopted or activated
/// it. A reconciled `Current` destination is therefore only a *candidate*, and
/// the candidate must clear four further conditions before anything is
/// destroyed, in this order:
///
/// 1. **Ownership, carried into the effect.**
///    [`reverify_recorded_destination`] returns the retained
///    [`ProtectedRootLease`], and that lease is handed straight to
///    [`ProtectedRootLease::into_removal_proof`]. The removal is then applied to
///    the retained `DELETE` handle, never to a reopened name.
/// 2. **Current custody disposition.**
///    [`PreparationJournal::destination_custody`] must read
///    [`DestinationCustody::Released`]; unresolved restore/cutover custody, or a
///    sink that cannot read it, preserves the root.
/// 3. **An owner-authorized cleanup transition.**
///    [`CleanupTransitionState::CleanupPending`] is retained through the journal
///    *before* the effect. A sink that refuses the transition has not authorized
///    the reclamation, and the root is preserved.
/// 4. **An empty root.**
///    [`ProtectedRootRemovalProof::remove_if_empty`] is bounded to one empty
///    directory applied to the retained handle. A populated root is reported as
///    preserved and needs the owning cleanup protocol, not a recursive sweep.
///
/// [`CleanupTransitionState::Reclaimed`] is retained only after the absence has
/// actually been observed, and an operation whose `Reclaimed` retention is
/// refused is reported as preserved rather than removed, so [`CleanupReport`]
/// never claims a durable state this module could not write.
///
/// # Which lifecycle states are candidates
///
/// The sweep classifies through [`validate_recorded_binding`] — the same decoder
/// and the same intent join every read path uses — and not through
/// [`reconcile_preparation`]'s disposition. Reconciliation reports a cancelled
/// record as a preserved terminal state, which is right for a caller asking "is
/// this destination still usable" and wrong for a sweep asking "is this root
/// still an owned unactivated preparation I may reclaim": routing the sweep
/// through reconcile would strand every cancelled root from every later pass.
///
/// `Prepared` and `Cancelled` are therefore both candidates, and both must clear
/// all four conditions above. A `CleanupPending` record carries an authorized
/// reclamation whose effect was never observed, so it is completed forward
/// through the same removal proof with **no second transition write**: the
/// transition is already the authorization, and re-writing it would be
/// re-authorizing an effect this operation has already recorded as possibly
/// applied. A `Reclaimed` record is preserved: its absence was observed, and a
/// second reclamation of a root nobody proved still exists is not a cleanup.
#[allow(
    clippy::too_many_lines,
    reason = "the sweep's budget stops, classification and per-state disposition stay in one boundary so no swept operation can skip the bound check or the decoder between neighbours"
)]
pub fn cleanup_preparations<J: PreparationJournal>(
    journal: &mut J,
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
    let swept = owned
        .iter()
        .filter(|operation_id| operation_ids.is_empty() || operation_ids.contains(operation_id))
        .cloned()
        .collect::<Vec<String>>();
    for (index, operation_id) in swept.iter().enumerate() {
        if budget_start.elapsed() >= CLEANUP_SWEEP_BUDGET {
            // Post-effect stop. Every bound that is still reachable here is
            // reported through the report, never through a bare `Err`: once a
            // root has been reclaimed in this call, the record of that effect
            // must survive whatever happens to the operations after it, and the
            // unprocessed remainder has to be visible with it.
            record_sweep_stop(
                &mut report,
                &swept[index..],
                "sweep budget exhausted; the remainder is preserved for a later bounded pass",
            );
            return Ok(report);
        }
        // The sweep classifies through the SAME decoder every other read path uses,
        // through [`validate_recorded_binding`] rather than through
        // [`reconcile_preparation`]'s disposition: a cancelled record reconciles as
        // a preserved terminal disposition, yet its root is still an owned
        // unactivated preparation this sweep may reclaim once it clears the same
        // four conditions every other candidate must clear. Routing the sweep
        // through reconcile would drop exactly those roots from the sweep forever
        // — a second, quieter resurrection problem in the opposite direction,
        // since a cancellation is not proof that a populated root is empty
        // ([`cleanup_preparations`] conditions 2-4 still decide that).
        let recorded = match journal.load(operation_id) {
            Ok(recorded) => recorded,
            Err(error) => {
                // A journal fault is a failure of the record this sweep is
                // authorised by, not of one root. Roots already reclaimed in this
                // call stay in the report and the unprocessed remainder is
                // preserved with it, so no post-effect failure can discard the
                // evidence of an irreversible effect.
                let reason = note_prepare_error(OP_CLEANUP, "reconcile", error, 0).to_string();
                record_sweep_stop(&mut report, &swept[index..], &reason);
                return Ok(report);
            }
        };
        let Some((intent, result)) = recorded else {
            observe_prepare_progress(OP_CLEANUP, "sweep", "absent", 0, 0);
            report
                .preserved
                .push((operation_id.to_owned(), "nothing recorded".to_owned()));
            continue;
        };
        let Some(result) = result else {
            // Intent without result: nothing may be deleted by inference, and the
            // digest travels with the reason so the owner can prove which recorded
            // admission is unresolved.
            observe_prepare_progress(OP_CLEANUP, "sweep", "preserved", 0, 0);
            report.preserved.push((
                operation_id.to_owned(),
                format!(
                    "admitted without a recorded result; outcome unknown, intent preserved \
                     (admission digest {})",
                    intent
                        .get("admission_digest")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unreadable")
                ),
            ));
            continue;
        };
        let lifecycle = match validate_recorded_binding(operation_id, &intent, &result) {
            Ok(lifecycle) => lifecycle,
            Err(error) => {
                // The refusal is reduced to its stable category: the typed text
                // names recorded paths and digests.
                observe_prepare_progress(OP_CLEANUP, "sweep", "preserved", 0, 0);
                report.preserved.push((
                    operation_id.to_owned(),
                    format!("record does not join its own intent: {error}"),
                ));
                continue;
            }
        };
        // The receipt the record preserves, taken before the match consumes the
        // lifecycle. For `Prepared` it is the usable destination; for the three
        // terminal states it is the preserved prior receipt, which is what a
        // reclamation candidate is checked against and never what a caller may
        // work with.
        let receipt = lifecycle.preserved_receipt().clone();
        match lifecycle {
            // A `Reclaimed` record already observed the absence; re-attempting
            // would be a second reclamation of a root nobody proved still exists.
            PreparationLifecycle::Reclaimed { .. } => {
                observe_prepare_progress(OP_CLEANUP, "sweep", "preserved", 0, 0);
                report.preserved.push((
                    operation_id.to_owned(),
                    "reclamation already completed and its absence observed".to_owned(),
                ));
            }
            // A `CleanupPending` record has an authorized reclamation whose
            // effect was never observed. The sweep may complete it, but it must
            // not re-authorize: the transition is already durable, so this goes
            // straight to the same removal proof with no second transition write.
            PreparationLifecycle::CleanupPending { .. } => {
                remove_reverified_destination(journal, operation_id, &receipt, false, &mut report);
            }
            // `Prepared` and `Cancelled` are both reclamation candidates. A
            // cancellation withdrew the operation, not the root; what authorizes
            // deleting it is still the ownership proof, the custody disposition,
            // the owner-authorized transition and an observed empty root, in that
            // order, below.
            PreparationLifecycle::Prepared(_) | PreparationLifecycle::Cancelled { .. } => {
                remove_reverified_destination(journal, operation_id, &receipt, true, &mut report);
            }
        }
    }
    Ok(report)
}

/// Records a stopped sweep: the operation the stop happened on keeps the stop
/// reason, and every operation after it is preserved with one static sentence,
/// so a partial sweep is never reported as a complete one.
fn record_sweep_stop(report: &mut CleanupReport, remaining: &[String], reason: &str) {
    observe_prepare_progress(OP_CLEANUP, "sweep", "stopped", 0, 0);
    for (position, operation_id) in remaining.iter().enumerate() {
        let recorded = if position == 0 {
            reason.to_owned()
        } else {
            "sweep stopped before this operation; preserved for a later bounded pass".to_owned()
        };
        report.preserved.push((operation_id.clone(), recorded));
    }
}

/// One typed refusal for a cleanup sweep that reached an explicit bound.
///
/// Bound exhaustion is a refusal, not a partial success: the sweep stops before
/// the first irreversible effect, the operation after the last completed one is
/// never reconciled or removed, and the static reason names the bound without
/// naming a path, identity, or count. The budget facts are not observed
/// numerically because the observation contract admits only validated
/// generation/epoch facts, so a count or a duration is reported as this stable
/// category plus its static field only.
///
/// This is only ever produced while [`CleanupReport::removed`] is still empty.
/// A bound reached after a reclamation is reported through the report instead
/// ([`record_sweep_stop`]), so a refusal can never hide an effect that already
/// happened.
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

/// Reclaims one candidate destination, or preserves it with the reason.
///
/// The four conditions in [`cleanup_preparations`] are decided here, in order,
/// and each refusal is a preserved entry rather than a silent skip. The
/// protected-root proof is taken here rather than reused from
/// [`reconcile_preparation`], so the handle the removal is applied to is the one
/// that was just proved.
///
/// `authorize` says whether this call must first retain a fresh
/// [`CleanupTransitionState::CleanupPending`] transition. It is `true` for a
/// `Prepared` or `Cancelled` record and `false` for a record that already carries
/// a durable `CleanupPending` whose effect was never observed: that transition is
/// already the authorization, and writing it again would re-authorize an effect
/// this operation has already recorded as possibly applied — which the owner's
/// transition law refuses, and which would make the record claim two
/// authorizations for one reclamation. Either way the effect happens after the
/// authorization exists, and `Reclaimed` is retained only after the absence is
/// observed.
fn remove_reverified_destination<J: PreparationJournal>(
    journal: &mut J,
    operation_id: &str,
    destination: &PreparedDestination,
    authorize: bool,
    report: &mut CleanupReport,
) {
    let lease = match reverify_recorded_destination(operation_id, destination) {
        Ok(lease) => lease,
        Err(error) => {
            observe_prepare_progress(OP_CLEANUP, "remove", "preserved", 0, 0);
            report
                .preserved
                .push((operation_id.to_owned(), error.to_string()));
            return;
        }
    };
    // The retained proof is carried into the removal: this is the only step
    // where an ownership proof becomes a destructive capability, and it happens
    // without releasing a single ancestor pin or resolving the leaf by name.
    let proof: ProtectedRootRemovalProof = match lease.into_removal_proof() {
        Ok(proof) => proof,
        Err(error) => {
            observe_prepare_progress(OP_CLEANUP, "remove", "preserved", 0, 0);
            let refused = protected_path_to_preparation(operation_id, &destination.root, error);
            report
                .preserved
                .push((operation_id.to_owned(), refused.to_string()));
            return;
        }
    };
    if let DestinationCustody::Unresolved(reason) = journal.destination_custody(&destination.root) {
        observe_prepare_progress(OP_CLEANUP, "custody", "preserved", 0, 0);
        report.preserved.push((operation_id.to_owned(), reason));
        return;
    }
    if authorize {
        // `CleanupPending` is retained BEFORE the effect, through the journal. A
        // sink that refuses it has not authorized the reclamation, so the root is
        // preserved and nothing is destroyed.
        let transition =
            match cleanup_transition_json(destination, CleanupTransitionState::CleanupPending) {
                Ok(transition) => transition,
                Err(error) => {
                    observe_prepare_progress(OP_CLEANUP, "transition", "preserved", 0, 0);
                    report.preserved.push((
                        operation_id.to_owned(),
                        format!("cleanup transition could not be rendered: {error}"),
                    ));
                    return;
                }
            };
        if let Err(error) = journal.record_result(operation_id, &transition) {
            observe_prepare_progress(OP_CLEANUP, "transition", "preserved", 0, 0);
            report.preserved.push((
                operation_id.to_owned(),
                format!("no owner-authorized cleanup transition: {error}"),
            ));
            return;
        }
    }
    // `authorize` false means the record already carries a durable
    // `CleanupPending` transition whose effect was never observed. Re-authorizing
    // would be re-writing a transition this operation has already recorded as
    // authorized and possibly applied, and the owner's transition law refuses
    // exactly that; completing it forward is the correct resolution.
    match proof.remove_if_empty() {
        Ok(ProtectedRootRemovalOutcome::Removed) => {
            let reclaimed =
                match cleanup_transition_json(destination, CleanupTransitionState::Reclaimed) {
                    Ok(reclaimed) => reclaimed,
                    Err(error) => {
                        observe_prepare_progress(OP_CLEANUP, "transition", "preserved", 0, 0);
                        report.preserved.push((
                            operation_id.to_owned(),
                            format!("reclaimed transition could not be rendered: {error}"),
                        ));
                        return;
                    }
                };
            if let Err(error) = journal.record_result(operation_id, &reclaimed) {
                // The effect is real and observed, but the durable record of it
                // could not be written. Reporting it as removed would claim a
                // reclaimed lifecycle state that does not exist, so it is
                // preserved with the exact gap and stays reconcilable.
                observe_prepare_progress(OP_CLEANUP, "transition", "preserved", 0, 0);
                report.preserved.push((
                    operation_id.to_owned(),
                    format!("absence observed but the reclaimed transition was refused: {error}"),
                ));
                return;
            }
            observe_prepare_progress(OP_CLEANUP, "remove", "removed", 0, 0);
            report.removed.push(operation_id.to_owned());
        }
        Ok(ProtectedRootRemovalOutcome::NotEmpty) => {
            observe_prepare_progress(OP_CLEANUP, "remove", "preserved", 0, 0);
            report.preserved.push((
                operation_id.to_owned(),
                "destination is populated; only an empty preparation root may be reclaimed, and a \
                 populated one needs the owning cleanup protocol"
                    .to_owned(),
            ));
        }
        Ok(ProtectedRootRemovalOutcome::CommittedUnconfirmed) => {
            observe_prepare_progress(OP_CLEANUP, "remove", "preserved", 0, 0);
            report.preserved.push((
                operation_id.to_owned(),
                "a delete disposition committed but the final absence could not be confirmed; \
                 preserved and never reported as removed"
                    .to_owned(),
            ));
        }
        Err(error) => {
            observe_prepare_progress(OP_CLEANUP, "remove", "preserved", 0, 0);
            let refused = protected_path_to_preparation(operation_id, &destination.root, error);
            report
                .preserved
                .push((operation_id.to_owned(), refused.to_string()));
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
/// echoed. Staging admission and generation authority stay with
/// [`prepare_isolated_destination`] and HostComposition delegation, and the
/// owner lease reference a caller may present is a claim checked against
/// [`OwnerEvidence::owner_lease_ref`] by the configuration projection rather
/// than bound from the request.
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
/// artifact set by that same projection.
///
/// The remaining fields are presented and are treated as follows. The
/// presented `approved_generation` is decided against owner evidence
/// ([`DelegatedPreparation::prepare`] against
/// [`OwnerEvidence::authority_generation`]); `target_build` and
/// `target_profile` must equal the owner-approved generation handle and
/// profile token or the preparation is refused. A presented owner lease
/// reference is a claim that must equal [`OwnerEvidence::owner_lease_ref`] or
/// the preparation is refused as stale evidence; the projected lease reference
/// is always the owner-issued one. A presented purge-ledger revision is
/// **refused outright**, because no owner reachable from Host issues one —
/// purge-ledger authority belongs to the ORS purge-ledger owner, which this
/// module does not open — and #954 (merged, `5e71386a`) supplies neither an
/// owner lease nor a purge revision: its `BackupAdmissionRef` is a
/// per-operation admission reference, not a standing owner lease. A presented
/// forensic audit note is a **claim** that must equal
/// [`OwnerEvidence::owner_audit_note`] or the preparation is refused as stale
/// evidence, and the owner-issued note is what the projection digest binds. The
/// presented
/// `authority_generation` is read nowhere on this path: this lane grants it
/// nothing, and the admission carries the owner-issued one instead.
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
    /// Target build identity for the destination (bounded text).
    ///
    /// Must equal the owner-issued approved-generation handle on the delegated
    /// path, or [`DelegatedPreparation::prepare`] refuses with
    /// [`PreparationError::UnapprovedTarget`]; see
    /// [`DestinationAdmission::target_build`].
    pub target_build: String,
    /// Target profile for the destination (bounded text).
    ///
    /// Must equal the owner-issued approved profile token on the delegated path,
    /// or [`DelegatedPreparation::prepare`] refuses with
    /// [`PreparationError::UnapprovedTarget`]; see
    /// [`DestinationAdmission::target_profile`].
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
    /// Owner lease reference the requester presents (bounded text).
    ///
    /// A **claim** about the owner's lease, never a source of one. On the
    /// delegated path it is checked against [`OwnerEvidence::owner_lease_ref`]:
    /// empty (no claim) is admitted, and a value that differs from the
    /// owner-issued reference is refused as stale evidence. The projection's own
    /// `owner_lease_ref` is always the owner-issued side, so nothing a caller
    /// writes here reaches the record. The field stays on the presented contract
    /// surface because removing a #954 contract field is not this lane's
    /// decision.
    pub owner_lease_ref: String,
    /// Purge-ledger revision the requester presents.
    ///
    /// Presenting a nonzero value is still **refused** by the owner-bound
    /// configuration projection: the revision is owner-issued by the ORS owner
    /// and Host backup preparation opens no ORS store, so no owner observed
    /// here issues one and the projection records the absence instead. This
    /// refusal is unchanged by the owner-lease work — a lease is not purge-ledger
    /// authority, and holding one does not make a caller-asserted purge revision
    /// corroborable.
    pub purge_ledger_revision: u64,
    /// Presented build digests, each verified against owner artifacts by the
    /// configuration projection.
    pub build_digests: Vec<String>,
    /// Optional forensic Host state audit note.
    ///
    /// A **claim** on the delegated path, never the source of the note: the
    /// owner-bound configuration projection compares it against
    /// [`OwnerEvidence::owner_audit_note`] and refuses a note that differs from
    /// the owner's as stale evidence, so caller-authored disposition text can
    /// never reach a receipt. It is still never *rendered* into a
    /// prepared-destination receipt — the owner-issued note is bound into the
    /// projection digest only — and I5.13's ceiling that the fence is forensic
    /// and never a lease, grant or current-state assertion is enforced on both
    /// sides by
    /// `crate::backup_config_projection::AuditFenceNote::validate`.
    pub audit_fence_note: Option<AuditFenceNote>,
    /// Opaque caller-presented entropy text.
    ///
    /// Not an input to the destination identity or the preparation-scope epoch:
    /// both bind owner-issued evidence instead, so a caller cannot select either
    /// and an archive-supplied value cannot determine either. It remains hashed
    /// into the admission digest, so rotating it is a changed idempotency input.
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
/// owner-bound preparation lifecycle. [`OwnerEvidence`] has all-private fields
/// and only [`OwnerEvidence::inspect`] can build one, so this port cannot be
/// entered without a real protected root and a committed registry behind it.
/// The caller-role half of authentication has no Host-side port and stays a
/// real fail-closed refusal ([`BackupCallerAuth::authenticate`]), while the
/// source-identity half is proved by
/// [`BackupCallerAuth::authenticate_for_owner`] at the composition port. Every
/// owner or presented-evidence failure maps to a typed [`PreparationError`]
/// without echoing owner internals.
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
    /// evidence, approve the presented target build and profile against that
    /// owner record, project the bounded owner-issued configuration evidence
    /// through the owner-bound projector, resolve the manifest-bound owner
    /// source root, then admit and prepare idempotently. The projection is a
    /// precondition, not an observation: a presented purge-ledger revision or
    /// forensic note is refused outright, a presented owner lease reference that
    /// is not the owner-issued one is refused as stale, and a stale or mixed
    /// generation or configuration/build digest is refused, all before any
    /// filesystem observation. The projected owner configuration digest plus the
    /// projection digest are admitted so the prepared-destination receipt binds
    /// the exact configuration evidence that was proved. The caller never
    /// chooses the manifest digest, the projection digest, the owner lease
    /// reference, or the approved-build digest set.
    ///
    /// The admitted `authority_generation` is the owner-issued one from
    /// [`OwnerEvidence::authority_generation`], so the presented
    /// `approved_generation` is admitted only if it matches committed owner
    /// evidence, and the presented `request.authority_generation` is not an
    /// input to that decision at all. The presented `staging_parent` is proved
    /// by the protected-root owner inside the preparation, so a
    /// client-supplied arbitrary path is refused. The presented target build
    /// and profile are compared against the owner-issued approved-generation
    /// handle and approved profile token of the same validated record, so a
    /// build or profile the owner has not approved is refused rather than
    /// accepted.
    pub fn prepare(
        &mut self,
        evidence: &OwnerEvidence,
        request: &PresentedPreparationRequest,
    ) -> Result<PreparedDestination, PreparationError> {
        let binding: ApprovedBuildBinding = evidence
            .approved_binding()
            .map_err(|error| note_prepare_error(OP_DELEGATE, "bind_build", error, 0))?;
        // The presented target build and profile are approved by NAME against
        // the owner record bound above, not merely shape-checked. The two
        // owner-issued names are the approved-generation handle and the
        // approved profile token; no approval list, synthetic table or
        // always-passing comparison is involved, and a name the owner has not
        // approved is refused before any effect (case 958/7).
        if request.target_build != binding.generation_handle {
            return Err(note_prepare_error(
                OP_DELEGATE,
                "check_target",
                PreparationError::UnapprovedTarget {
                    field: "target_build",
                    presented: request.target_build.clone(),
                    approved: binding.generation_handle.clone(),
                },
                0,
            ));
        }
        if request.target_profile != binding.approved_profile {
            return Err(note_prepare_error(
                OP_DELEGATE,
                "check_target",
                PreparationError::UnapprovedTarget {
                    field: "target_profile",
                    presented: request.target_profile.clone(),
                    approved: binding.approved_profile.clone(),
                },
                0,
            ));
        }
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
        // BEFORE the admission is built so a presented purge revision or forensic
        // note, a presented owner lease reference that is not the owner-issued
        // one, and any stale or mixed generation or configuration/build digest
        // is refused before any effect. The projector re-checks the presented
        // build digests against the owner-issued artifact set, so the loop above
        // is a first cheap refusal and this is the authoritative one.
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
            // Still no forensic note in a receipt. The projection bound an
            // OWNER-ISSUED note into `config_projection_digest`, but its text is
            // not restated here, and a presented note that differed from the
            // owner's was already refused by the projection above;
            // `validate_admission` refuses one independently.
            // `describe_audit_fence` is therefore not called from this path — a
            // digest commits to the note without publishing its wording, which
            // is what keeps forensic text out of a receipt and out of the log.
            audit_fence_note: None,
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
    ///
    /// Takes the sink mutably because reclamation retains an owner-authorized
    /// cleanup transition around the effect; a sweep that could not write one
    /// has no authorization to destroy anything.
    pub fn cleanup(&mut self, operation_ids: &[String]) -> Result<CleanupReport, PreparationError> {
        cleanup_preparations(&mut self.journal, operation_ids)
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
        ProjectionError::OwnerEvidenceUnavailable { field, obligation } => {
            PreparationError::OwnerEvidenceUnavailable { field, obligation }
        }
        ProjectionError::ActiveAuthorityInAuditFence { field } => {
            PreparationError::InvalidRequest {
                field,
                reason: "forensic audit note asserts restored active authority; a \
                         HostStateAuditFence is forensic only and never a lease, grant, or \
                         current-state assertion"
                    .to_owned(),
            }
        }
    }
}

/// The **owner-issued** projection of the active manifest binding, in the shape
/// the Kernel's `DestinationManifestEvidence` producer consumes (issue #962,
/// AUDIT-7).
///
/// This is a *projection of owner records*, not a second binding. The Host
/// binding itself is the [`ApprovedGenerationRegistry`] plus the
/// [`ApprovedGeneration`] it committed; every field below is copied out of a
/// record that [`OwnerEvidence::inspect`] already validated, and no field is a
/// copy of a caller value, a recomputed digest, or a default. The Kernel-side
/// consumer names this owner as its issuer and cannot substitute for the Host
/// binding: the two registry records stay in this crate, and a projection of
/// three validated values is not the registry.
///
/// Deliberately three values and a counter. The Host roots type
/// ([`RuntimeStateRoots`]) is never carried: the roots digest is what a restore
/// can verify, and shipping the roots themselves would create a second readable
/// copy of the mutable root topology on a boundary that has no other reason to
/// hold it.
///
/// No credential-typed or secret-typed value is read to build it. The committed
/// fence's `credential_receipt_digest` and `host_process_nonce_digest` are
/// visible on a record this owner reads and are, as everywhere else in this
/// module, deliberately not extracted (I5.13).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostManifestBinding {
    /// The active approved manifest's own configuration digest.
    pub manifest_digest: String,
    /// The manifest-bound runtime roots' own digest.
    pub roots_digest: String,
    /// The registry CAS revision observed at inspection time.
    pub registry_revision: u64,
}

impl HostManifestBinding {
    /// Shape-checks the two owner-issued digests with this module's existing
    /// 64-lowercase-hex rule.
    ///
    /// This is a guard on owner-issued content, exactly like
    /// [`AuditFenceNote::validate`] inside [`OwnerEvidence::owner_audit_note`]:
    /// the values are owner records, so a shape failure is a broken owner record
    /// rather than an expected outcome, and it must fail here at the owner
    /// boundary instead of after being carried into a restore. It is not a
    /// substitute for the consumer's own comparison of these values.
    ///
    /// # Errors
    ///
    /// [`PreparationError::InvalidRequest`] naming the offending field, with the
    /// module's static reason. The owner's own error text is never echoed.
    pub fn validate(&self) -> Result<(), PreparationError> {
        check_digest(&self.manifest_digest, "owner_manifest_digest")?;
        check_digest(&self.roots_digest, "owner_roots_digest")?;
        Ok(())
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
///
/// It is also the owner of the **owner lease reference** the configuration
/// projection binds ([`OwnerEvidence::owner_lease_ref`]). The `root_lease`
/// field is a real retained [`ProtectedRootLease`] over the canonical source
/// Host state root, held for the whole life of the bundle — the registry read
/// gets a second, short-lived lease because
/// [`RedbInstallationRegistry::inspect_existing_at`] consumes the one it is
/// handed. Because the handle is retained, [`OwnerEvidence::owner_lease_ref`]
/// can re-derive the object's current final path from that handle at
/// projection time and refuse unless it still resolves to
/// `canonical_host_root`; that is the property a backup manifest needs from a
/// lease reference, and it is a decision the code makes rather than a claim
/// about a lease it no longer holds.
///
/// It is also the source of the owner-issued **purge-ledger revision** the
/// configuration projection binds
/// ([`OwnerEvidence::owner_purge_ledger_revision`]). That one value is *not*
/// retained in the bundle: the counter belongs to the ORS owner and is read from
/// it, read-only and through a short-lived retained lease, at the moment the
/// projection consumes it — the same "take it at use" discipline the lease
/// reference follows, for the same reason.
pub struct OwnerEvidence {
    registry: ApprovedGenerationRegistry,
    approved: ApprovedGeneration,
    fence: ActivationCommitFence,
    canonical_host_root: PathBuf,
    root_identity: FileIdentity,
    /// Retained source-root lease. Never read except through
    /// [`OwnerEvidence::owner_lease_ref`], which re-proves it first.
    root_lease: ProtectedRootLease,
}

impl OwnerEvidence {
    /// Inspects and binds the committed owner evidence below one protected
    /// Host root.
    ///
    /// Order, mirroring the `load_manifest_bound_canary_binding` precedent:
    /// absolute-path gate, protected-root lease, canonical path,
    /// stable-identity proof, caller-root equality, second lease for the
    /// registry read pinned to the same object, read-only registry
    /// inspection, registry validation, active generation, manifest
    /// validation, manifest/profile agreement with the bound runtime roots,
    /// manifest-root equality, committed fence, fence validation, and
    /// fence↔manifest agreement. Any step fails closed with a static
    /// [`PreparationError`]; owner error internals are never echoed.
    /// Absence of proof is never treated as proof of absence.
    ///
    /// The first lease is the one RETAINED in the bundle; the registry read
    /// consumes the second one, because
    /// [`RedbInstallationRegistry::inspect_existing_at`] takes its lease by
    /// value. See the `root_lease` field docs.
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
        // The registry read below CONSUMES the lease it is handed (A13.9 keeps
        // the containment proof alive only for the duration of that read and
        // returns the projection, not the store), so the registry read gets its
        // own second lease while this one is RETAINED in the bundle. The two
        // leases must pin the same object: without that equality the read could
        // have happened against a different directory than the one whose
        // identity and canonical path the rest of this chain just admitted, and
        // the retained lease would be pinning something nobody inspected.
        let read_lease = ProtectedRootLease::open_existing(host_state_root).map_err(|error| {
            PreparationError::FilesystemEffect {
                path: host_state_root.to_string_lossy().into_owned(),
                reason: format!("protected source root unavailable for registry read: {error}"),
            }
        })?;
        if read_lease.identity() != root_identity {
            return Err(PreparationError::IdentityConflict {
                operation: OP_OWNER_EVIDENCE.to_owned(),
                recorded: file_identity_text(root_identity),
                observed: file_identity_text(read_lease.identity()),
            });
        }
        let registry = RedbInstallationRegistry::inspect_existing_at(read_lease).map_err(|_| {
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
            // The retained lease outlives the registry read on purpose: it is
            // the only thing that can still prove, at projection time, that the
            // source root is the same object this chain admitted.
            root_lease: lease,
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
    /// [`bind_approved_build`] re-verifies it here — the approved generation and
    /// the committed activation fence together, including their agreement on
    /// generation, configuration digest and authority generation — so the
    /// binding never depends on inspection-time state alone and the retained
    /// Phase-B configuration identity is read from the same activation the
    /// template digest came from.
    ///
    /// The registry's completed Phase-B rebind is passed through so
    /// [`ApprovedBuildBinding::retained_config_digest`] names the rebind's
    /// config readback when one exists; see
    /// [`ApprovedGenerationRegistry::active_phase_b_rebind`]. The registry
    /// itself already prefers the rebind over the committed fence for the live
    /// Phase-B supervision authority, and the retained config identity is read
    /// the same way rather than from the older committed fence alone.
    pub fn approved_binding(&self) -> Result<ApprovedBuildBinding, PreparationError> {
        bind_approved_build(
            &self.approved,
            &self.fence,
            self.registry.active_phase_b_rebind(),
        )
        .map_err(projection_to_preparation)
    }

    /// Returns the **owner-issued** lease reference for this source, re-proving
    /// the retained lease first.
    ///
    /// The value is the pinned OS file identity (volume serial + file index) of
    /// the retained `root_lease`, rendered through the same `file_identity_text`
    /// encoding the preparation receipts already use and prefixed so a reader
    /// cannot mistake it for a path. It is opaque, non-secret, bounded text.
    ///
    /// # The retention and stability this actually provides
    ///
    /// [`OwnerEvidence::inspect`] retains the `ProtectedRootLease` in
    /// `root_lease` for the whole life of the bundle and proves the identity
    /// once, at inspection. That single inspection-time proof is **not** enough
    /// to call the reference current, so this method re-proves it here, at the
    /// moment the projection consumes it, and refuses rather than returning a
    /// reference that is no longer true:
    ///
    /// - [`ProtectedRootLease::verify_stable_identity`] re-reads the identity
    ///   from the retained handle and compares it with the one pinned at
    ///   inspection, and
    /// - [`ProtectedRootLease::canonical_path`] re-derives the object's
    ///   **current** final path from that same handle and requires it still to
    ///   equal `canonical_host_root`.
    ///
    /// The second check is the defence in depth behind the handle itself. The
    /// lease's directory handle is opened with `FILE_SHARE_READ | FILE_SHARE_WRITE`
    /// and **without** `FILE_SHARE_DELETE`
    /// (`crates/kernel/eliot-platform-windows/src/protected_path.rs`), so while
    /// this bundle holds it, Windows sharing rules do not admit a rename or
    /// delete of the pinned directory at all. The re-derivation above therefore
    /// confirms the object and its path rather than being the only barrier: a
    /// handle's own file identity never changes, so an identity check alone could
    /// not distinguish "still the admitted object" from "the admitted object,
    /// moved". Both failures are typed [`PreparationError`]s and are observed once
    /// at this owner boundary.
    ///
    /// What this does **not** claim: it does not prove the source tree's
    /// *contents* are unchanged — files inside the pinned directory are opened
    /// independently of this lease and are not covered by the share mode above.
    /// It proves that, at the instant of this call, the retained lease still pins
    /// the same object at the same path the rest of the evidence chain was
    /// admitted against, and it keeps that object pinned for as long as this
    /// bundle is alive.
    ///
    /// The retention has a consequence worth stating rather than discovering: an
    /// operation that legitimately renames or replaces a directory inside the
    /// protected contour can now meet a sharing violation while a preparation is
    /// in flight, where before the lease was dropped immediately after the
    /// registry read. That is the cost of a reference that cannot go stale, and
    /// it is the reason the lease is retained for the whole bundle instead of
    /// only for the read that needed it.
    ///
    /// This is deliberately **not** the installation-wide
    /// `eliot_platform_windows::HostOwnerLease` mutex name. That lease is held by
    /// `HostComposition` for the process lifetime and
    /// `HostOwnerLease::acquire` refuses to observe an existing object — it
    /// would also *create* one if none existed, which no backup read may do — so
    /// this contour cannot read that name at all. Recomputing it from a
    /// caller-supplied installation path would name a lease nobody proved was
    /// held, which is the fabrication I5.13 forbids; naming the lease this owner
    /// demonstrably holds and demonstrably still holds is the honest binding.
    /// #954 merged (`5e71386a`, PR #2572) and does not close that gap either:
    /// its `BackupAdmissionRef` is a per-operation admission reference,
    /// documented never to grant a role on its own, so substituting it here
    /// would put a different object under the name of the guarantee A1
    /// requires.
    ///
    /// ASSUMPTION: the issue's "owner lease" is read as the lease the owner
    /// holds over the source being captured, not specifically the
    /// installation-wide admission mutex, because only the former is observable
    /// from the owner that already exists on this path. If the intended guarantee
    /// is the admission mutex specifically, this reference must be replaced by
    /// one read from the composition-held `HostOwnerLease` at the port that
    /// already holds it (`HostComposition::prepare_backup_destination` passes it
    /// to `authenticate_for_owner`) — which is a change outside this file.
    pub fn owner_lease_ref(&self) -> Result<String, PreparationError> {
        let reverified = self
            .root_lease
            .verify_stable_identity()
            .and_then(|()| self.root_lease.canonical_path())
            .map_err(|error| {
                protected_path_to_preparation(OP_OWNER_EVIDENCE, &self.canonical_host_root, error)
            })
            .and_then(|current| {
                if windows_paths_equal(&current, &self.canonical_host_root) {
                    Ok(current)
                } else {
                    Err(PreparationError::UnknownState {
                        operation: OP_OWNER_EVIDENCE.to_owned(),
                        reason: "retained source lease moved off the inspected root".to_owned(),
                    })
                }
            });
        match reverified {
            Ok(_) => Ok(format!(
                "protected-root-lease:{}",
                file_identity_text(self.root_identity)
            )),
            Err(error) => Err(note_prepare_error(OP_OWNER_EVIDENCE, "lease_ref", error, 0)),
        }
    }

    /// Returns the **owner-issued** forensic audit note for this installation
    /// lineage (I5.13:44, A13.7).
    ///
    /// The note is derived here, at issue time, from the records this bundle
    /// already holds and proved: the registry projection read through the
    /// read-only owner query, its active approved generation, the committed
    /// activation fence, and the registry CAS revision
    /// ([`OwnerEvidence::revision`]). Every one of those is owner-observed
    /// durable state, so the note **describes** owner evidence instead of
    /// claiming it — which is the distinction that was missing when this
    /// function did not exist and every presented note had to be refused.
    ///
    /// Deliberately NOT `eliot_backup::HostStateAuditFence`: that type and
    /// `eliot_protocol::backup::HostAuditRef` are built only in `#[cfg(test)]`
    /// fixtures, and in production that fence is a caller-presented optional
    /// field of `eliot_kernel::backup_capture::CaptureRequest`. Copying its
    /// shape here would reproduce a caller-authored note under an owner-issued
    /// name, which is the fabrication I5.13 forbids. The lineage digest below
    /// is a **new** domain-separated digest over owner-observed facts, not a
    /// value copied from any record, and nothing here recomputes a digest an
    /// owner recorded: each fact is either a handle the registry validated or a
    /// counter it maintains.
    ///
    /// That digest is not an added layer. `AuditFenceNote::note_digest` is an
    /// existing required field of the existing note type, so a note cannot exist
    /// without a value in it, and the three choices are "caller's text", "a
    /// constant", or "a digest over what the owner read". This is the third, and
    /// it is built with the module's existing `hash_field` canonical encoding and
    /// its own disjoint domain separator, so no new hashing scheme, key, MAC or
    /// nonce is introduced and no existing one is reused for a second purpose.
    ///
    /// The observed dispositions are bounded, non-secret descriptions of what
    /// the registry actually shows. They are labels over owner-read facts, not
    /// claims a reader must trust: the note carries no lease, grant, generation,
    /// epoch or state field, so it cannot be read as one.
    /// [`AuditFenceNote::active_authority_restored`] is left `false`, which is
    /// the ceiling I5.13 requires and the value
    /// [`AuditFenceNote::validate`] requires for an admissible note; the
    /// projector re-validates it, so this cannot be relaxed here.
    ///
    /// What this does **not** claim: the note is a snapshot of the lineage as
    /// observed at inspection. It is not re-read at projection time, so it does
    /// not prove the lineage is unmoved between the two — the registry revision
    /// comparison at `HostComposition` is what covers that window, exactly as it
    /// does for every other fact in this bundle.
    ///
    /// # Errors
    ///
    /// Returns [`PreparationError::InvalidRequest`] if the derived note fails
    /// [`AuditFenceNote::validate`] — a disposition this function composed that
    /// is not bounded printable text. It cannot happen for the committed
    /// lineage (every disposition is built from a registry handle or a counter
    /// the registry validated), so the arm is a fail-closed guard rather than an
    /// expected outcome; a note that failed shape must not reach a projection,
    /// and this is the owner boundary where that is decided.
    pub fn owner_audit_note(&self) -> Result<AuditFenceNote, PreparationError> {
        let mut dispositions = Vec::new();
        if let Some(active) = self.registry.active_generation() {
            dispositions.push(format!("active_generation:{}", active.as_str()));
        }
        if let Some(last_known_good) = self.registry.last_known_good_generation() {
            dispositions.push(format!(
                "last_known_good_generation:{}",
                last_known_good.as_str()
            ));
        }
        dispositions.push(format!("registry_revision:{}", self.registry.revision()));
        dispositions.push(format!(
            "committed_generation:{}",
            self.approved.manifest.generation.as_str()
        ));
        dispositions.push(format!(
            "authority_generation:{}",
            self.fence.authority_generation.value()
        ));
        dispositions.push(format!(
            "config_digest:{}",
            self.fence.config_digest.as_str()
        ));
        let mut hasher = Sha256::new();
        // A new domain separator, disjoint from every other digest in this
        // module and from the projection digest's own `v6` separator, so a
        // lineage digest can never be read as a projection digest.
        hasher.update(b"eliot.backup.host-audit-lineage.v1\0");
        hash_field(
            &mut hasher,
            b"registry_wire_version",
            self.registry.registry_wire_version().as_string().as_bytes(),
        );
        hash_field(
            &mut hasher,
            b"registry_revision",
            &self.registry.revision().to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            b"active_generation",
            self.registry
                .active_generation()
                .map_or("", |handle| handle.as_str())
                .as_bytes(),
        );
        hash_field(
            &mut hasher,
            b"last_known_good_generation",
            self.registry
                .last_known_good_generation()
                .map_or("", |handle| handle.as_str())
                .as_bytes(),
        );
        hash_field(
            &mut hasher,
            b"committed_generation",
            self.approved.manifest.generation.as_str().as_bytes(),
        );
        hash_field(
            &mut hasher,
            b"authority_generation",
            &self.fence.authority_generation.value().to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            b"config_digest",
            self.fence.config_digest.as_str().as_bytes(),
        );
        // The retained (materialized Phase-B) configuration identity is NOT
        // re-derived here: `bind_approved_build` already extracts it from the
        // committed fence or the registry's completed rebind and the projector
        // binds it, so naming it here would be a second copy of that rule in a
        // place with no way to keep the two in step.
        let note = AuditFenceNote {
            note_digest: format!("{:x}", hasher.finalize()),
            observed_dispositions: dispositions,
            // The ceiling I5.13 requires of a `HostStateAuditFence`, and the
            // only value `AuditFenceNote::validate` admits.
            active_authority_restored: false,
        };
        // Shape-checked here as well as in the projector, so an owner that
        // produced an unbounded disposition fails at the owner boundary rather
        // than after being carried into a projection. This is a shape guard on
        // owner-issued content, never a substitute for the projector's
        // presented-versus-owner comparison.
        note.validate().map_err(projection_to_preparation)?;
        Ok(note)
    }

    /// Returns the **owner-issued** durable purge-ledger revision (issue #958
    /// A1; I5.13:44, A13.7).
    ///
    /// The value is the ORS owner's own durable counter, read READ-ONLY through
    /// a retained [`ProtectedRuntimePathLease`] and handed to
    /// [`crate::backup_config_projection::project_backup_config_owner_bound`],
    /// where a presented revision is a *claim* checked against this one exactly
    /// as the owner lease reference and the audit note already are. It is never
    /// recomputed here, never taken from
    /// [`PresentedPreparationRequest::purge_ledger_revision`], and never derived
    /// from a caller-supplied path: `RedbRecoveryStore::purge_ledger_revision`
    /// is the producer, and this function only observes what that owner
    /// durably wrote.
    ///
    /// The location is OWNER-ISSUED. `kernel_ors_root` is read from the approved
    /// manifest this bundle already validated during [`OwnerEvidence::inspect`]
    /// — an active approved generation, a validated manifest and topology-
    /// validated manifest-bound runtime roots — and only the file name beside it
    /// is contributed here. No caller value reaches this path.
    ///
    /// The read discipline is the `read_manifest_current_supervision_lease`
    /// precedent in `bins/eliot-host/src/watchdog_publication.rs`: the ORS child
    /// is opened through the installer-provisioned runtime contour (which proves
    /// the immutable `BA+LS+SY` file DACL and never asks the caller for
    /// `WRITE_DAC`), the retained handle's current final path is compared with
    /// the approved manifest's selection, and the retained identity plus the path
    /// identity are re-proved BOTH BEFORE the read and AGAIN AFTER it, so the
    /// read is bracketed by the same identity pair on both sides and a path
    /// that moved across the read refuses instead of returning a value read
    /// from somewhere else. That is a time-bracket over the read, not a proof
    /// of file identity — the read itself is a fresh open by path — and it is
    /// exactly the guarantee the `watchdog_publication.rs` precedent offers.
    ///
    /// **This does not make this composition root a store owner.** The read is a
    /// `ReadOnlyDatabase` transaction: no write transaction, no store handle
    /// retained, no table written, and the lease is dropped on return.
    /// `crates/storage/AGENTS.md` stops at "a request needs … a second mutable
    /// root owner"; a read-only observation of a counter the ORS owner already
    /// maintains is not that, and the module continues to hold no registry
    /// writer, no store handle and no ORS lease of its own.
    ///
    /// The `Ok(None)` answer is refused, not turned into a zero. The owner's own
    /// rule — `RedbRecoveryStore::purge_ledger_revision_in` and
    /// `store.rs:427`, "An absent counter means no purge was ever applied, which
    /// is revision zero and NOT AN UNKNOWN ANSWER" — governs a counter key inside
    /// an initialised store, and `eliot_ors::read_purge_ledger_revision_read_only`
    /// MUST answer `Some(0)` for that case: it is a requirement of consuming
    /// this reader, not a courtesy it may withdraw. `Ok(None)` therefore covers
    /// exactly one thing, a database holding **no tables at all** — an
    /// uninitialised or empty ORS file — which is a broken installation rather
    /// than an unknowable state, and is refused as such with
    /// [`PreparationError::FilesystemEffect`] naming the file. Substituting `0`
    /// would state the owner's answer on its behalf, and
    /// [`PreparationError::UnknownState`] would erase the operator's ability to
    /// tell "Host cannot know" apart from "the ORS on disk is empty". This
    /// module's standing rule applies: absence of proof is never treated as
    /// proof of absence. A store that has never purged says so with a real zero.
    ///
    /// What is NOT proved: the revision is a point-in-time observation of a
    /// counter, not a fence, so the owner can advance it the instant after this
    /// returns and nothing downstream may treat the bound value as "the revision
    /// during restore"; and the retained handle proves the file's identity, not
    /// its CONTENTS — the revision is trusted because the ORS owner produced it
    /// from a schema-checked read of that exact file, not because this module
    /// inspected any record inside it.
    ///
    /// I5.13 forbids replaying a raw credential reference in a backup manifest.
    /// `credential_receipt_digest` and `host_process_nonce_digest` are visible
    /// on the committed fence this bundle holds ([`OwnerEvidence::inspect`]
    /// proves and stores it) — they sit on the Host Phase-B prepared
    /// materialization its `phase_b_live_binding` carries — and are deliberately
    /// NOT extracted here, exactly as they are not extracted for the audit note:
    /// a digest of a credential receipt is not a credential reference, and
    /// nothing in this value path reads credential material or a secret-typed
    /// field.
    ///
    /// # Errors
    ///
    /// Fails closed with a static [`PreparationError`] at every step: the ORS
    /// open is mapped through the existing [`protected_path_to_preparation`]
    /// helper, a selection or identity disagreement is
    /// [`PreparationError::UnknownState`], an owner read that produced no
    /// revision is [`PreparationError::UnknownState`] with a static reason, an
    /// owner read that answered `Ok(None)` — the empty-database case — is
    /// [`PreparationError::FilesystemEffect`] carrying the ORS path and a
    /// static reason, and the owner's own error text is never echoed.
    pub fn owner_purge_ledger_revision(&self) -> Result<u64, PreparationError> {
        // The approved manifest's own ORS root, never a request field. Built
        // before the observation so the refusal below names the same path the
        // read would have used.
        let ors_path = PathBuf::from(
            self.approved
                .manifest
                .runtime_launch
                .runtime_state_roots
                .kernel_ors_root
                .as_str(),
        )
        .join(KERNEL_ORS_FILE_NAME);
        let read = (|| -> Result<u64, PreparationError> {
            let retained =
                ProtectedRuntimePathLease::open_existing_absolute(&ors_path).map_err(|error| {
                    protected_path_to_preparation(OP_OWNER_EVIDENCE, &ors_path, error)
                })?;
            if !windows_paths_equal(retained.path(), &ors_path) {
                return Err(PreparationError::UnknownState {
                    operation: OP_OWNER_EVIDENCE.to_owned(),
                    reason: "retained ORS lease is not the approved manifest's ORS child"
                        .to_owned(),
                });
            }
            retained
                .verify_stable_identity()
                .and_then(|()| retained.verify_path_identity())
                .map_err(|error| {
                    protected_path_to_preparation(OP_OWNER_EVIDENCE, &ors_path, error)
                })?;
            let revision = eliot_ors::read_purge_ledger_revision_read_only(retained.path())
                // The owner's error internals are never echoed; the static
                // reason names the refused property only.
                .map_err(|_| PreparationError::UnknownState {
                    operation: OP_OWNER_EVIDENCE.to_owned(),
                    reason: "owner purge-ledger read did not produce a revision".to_owned(),
                })?
                // `Ok(None)` covers exactly one case now that the reader
                // answers `Some(0)` for an absent counter inside an
                // initialised store: a database holding NO TABLES AT ALL, i.e.
                // an uninitialised or empty ORS file. That is a broken
                // installation, not an unknowable state, so it is refused as a
                // filesystem effect naming the file rather than through this
                // module's `UnknownState` catch-all, which would erase the
                // operator's ability to tell "Host cannot know" apart from
                // "the ORS on disk is empty". The reason is static; the
                // owner's own error text is never echoed.
                .ok_or_else(|| PreparationError::FilesystemEffect {
                    path: ors_path.to_string_lossy().into_owned(),
                    reason:
                        "owner ORS database holds no tables, so no ORS was initialised here and \
                         its state cannot be established"
                            .to_owned(),
                })?;
            // The same identity pair brackets the read: it is re-proved on both
            // sides, so a handle that no longer resolves to the approved
            // selection refuses rather than yielding a revision read from
            // somewhere else. A time-bracket, not proof of file identity.
            retained
                .verify_stable_identity()
                .and_then(|()| retained.verify_path_identity())
                .map_err(|error| {
                    protected_path_to_preparation(OP_OWNER_EVIDENCE, &ors_path, error)
                })?;
            if !windows_paths_equal(retained.path(), &ors_path) {
                return Err(PreparationError::UnknownState {
                    operation: OP_OWNER_EVIDENCE.to_owned(),
                    reason: "retained ORS lease moved off the approved manifest's ORS child"
                        .to_owned(),
                });
            }
            Ok(revision)
        })();
        match read {
            Ok(revision) => Ok(revision),
            Err(error) => Err(note_prepare_error(
                OP_OWNER_EVIDENCE,
                "purge_revision",
                error,
                0,
            )),
        }
    }

    /// Returns the **owner-issued** active-manifest binding projection the
    /// Kernel's `DestinationManifestEvidence` is built from (issue #962,
    /// AUDIT-7; I5.13 `full_recovery` manifest; A13.7 provenance/integrity).
    ///
    /// Three owner records, one value each, and no fourth:
    ///
    /// - `manifest_digest` is the ACTIVE approved generation's own manifest
    ///   `config_digest` — the manifest [`OwnerEvidence::inspect`] already
    ///   validated through its own `validate`, which proves it is a 64-hex
    ///   digest, binds `runtime_state_roots_digest` to the launch roots, and
    ///   agrees with the committed activation fence on generation, configuration
    ///   digest and authority generation. It is the same value
    ///   [`OwnerEvidence::project_backup_configuration`] hands the configuration
    ///   projector as `binding.config_digest`, read from the same record, so a
    ///   caller cannot present a competing configuration digest and this method
    ///   does not re-derive one.
    /// - `roots_digest` is the manifest-bound runtime roots' OWN `roots_digest`
    ///   field. It is not an owner-computed summary: `RuntimeStateRoots::validate`,
    ///   which [`OwnerEvidence::inspect`] ran on these exact roots, recomputes it
    ///   from the nine root fields and refuses a mismatch, and the manifest's own
    ///   `validate` independently requires
    ///   `runtime_state_roots_digest == runtime_launch.runtime_state_roots.roots_digest`.
    ///   So the value read here is a digest the owner proved against the roots
    ///   it committed. The roots THEMSELVES are not carried: this projection
    ///   crosses into a restore, and a restore needs to verify the digest, not
    ///   to re-read the Host's mutable root topology.
    /// - `registry_revision` is [`OwnerEvidence::revision`], the registry CAS
    ///   revision observed at inspection time — the same observation
    ///   `HostComposition` already compares to detect registry movement between
    ///   inspection and use. It is deliberately NOT the purge-ledger revision,
    ///   whose authority belongs to the backup domain and whose counter belongs
    ///   to the ORS owner ([`OwnerEvidence::owner_purge_ledger_revision`]).
    ///
    /// The retained protected-root lease is **re-proved here**, not at
    /// inspection only, by calling [`OwnerEvidence::owner_lease_ref`] and
    /// requiring it to succeed: the same identity-plus-current-final-path proof
    /// that accessor performs is reused rather than duplicated, so there is one
    /// implementation of "the retained lease still pins the inspected source
    /// root" in this module. A source root that moved or was replaced refuses
    /// typed here rather than yielding a manifest binding read from a lineage
    /// the rest of this chain no longer admits.
    ///
    /// ## What this proves, and what it does not
    ///
    /// PROVED: the three values are the ones this owner validated and still
    /// holds; the retained lease still pins the same source object at the same
    /// path; the roots digest is the digest of the roots the active manifest
    /// binds; and the revision is a real observed registry revision, not a
    /// placeholder.
    ///
    /// NOT PROVED, and deliberately not claimed:
    ///
    /// - the registry is NOT re-read at issue time. `OwnerEvidence::inspect`
    ///   observed it once; this projection is a snapshot of that read, exactly
    ///   like the audit note's. The window between inspection and issue is
    ///   covered by the caller's own revision comparison, the same way it is for
    ///   every other fact in this bundle — not by anything here.
    /// - the digests are NOT recomputed. A fresh checksum here would replace the
    ///   owner's proof with a local one, so both are read from records the
    ///   owner's own validators checked.
    /// - nothing about the CURRENT contents of the roots. `roots_digest` binds
    ///   the approved root TOPOLOGY, not the bytes under those roots; a tree
    ///   that changed under an unchanged topology leaves this value untouched.
    /// - no destination readiness, no archive integrity, no cutover authority,
    ///   and no restore effect of any kind.
    ///
    /// # Errors
    ///
    /// Fails closed with a static [`PreparationError`]: a stale or moved retained
    /// lease is whatever typed error [`OwnerEvidence::owner_lease_ref`] reports
    /// (re-proved, never re-derived here), and a digest that is not 64 lowercase
    /// hex is [`PreparationError::InvalidRequest`] from
    /// [`HostManifestBinding::validate`]. The outcome is observed once through
    /// `note_prepare_error`, and no owner error text, path or record body is
    /// echoed.
    pub fn owner_manifest_binding(&self) -> Result<HostManifestBinding, PreparationError> {
        let issued = (|| -> Result<HostManifestBinding, PreparationError> {
            // The retained lease is re-proved at issue time, through the one
            // accessor that already implements that proof. Its value is not part
            // of this projection; the refusal it raises is the point.
            self.owner_lease_ref()?;
            let binding = HostManifestBinding {
                manifest_digest: self.approved.manifest.config_digest.as_str().to_owned(),
                roots_digest: self.runtime_roots().roots_digest.as_str().to_owned(),
                registry_revision: self.revision(),
            };
            binding.validate()?;
            Ok(binding)
        })();
        match issued {
            Ok(binding) => Ok(binding),
            Err(error) => Err(note_prepare_error(
                OP_OWNER_EVIDENCE,
                "manifest_binding",
                error,
                0,
            )),
        }
    }

    /// Projects the bounded owner-issued configuration evidence for one
    /// presented preparation request (issue #958, cases 958/1-4, 958/16).
    ///
    /// This is the production construction of the owner-bound projection. The
    /// owner supplies five of its inputs and the request supplies only
    /// presented evidence:
    ///
    /// - the manifest digest is the owner-issued configuration digest from
    ///   `binding`, so a caller can never present a competing manifest;
    /// - the projection fence is the committed activation fence's authority
    ///   state fence, so a caller cannot choose the fence its evidence is bound
    ///   to;
    /// - the owner lease reference is [`OwnerEvidence::owner_lease_ref`], which
    ///   re-proves the retained protected-root lease immediately before this
    ///   method uses it, so the record names the lease this owner still holds
    ///   over the source rather than anything the requester wrote;
    /// - the purge-ledger revision is
    ///   [`OwnerEvidence::owner_purge_ledger_revision`], read read-only from
    ///   the ORS owner through a retained protected runtime-path lease that is
    ///   re-proved on both sides of the read, so the record binds the owner's
    ///   own counter rather than a requester-supplied number;
    /// - the generation handle, profile token, retained Phase-B configuration
    ///   digest and the complete approved artifact digest set are bound inside
    ///   the projector from the same owner records.
    ///
    /// The presented owner lease reference is still passed through unchanged,
    /// but its role changed: it is now a **claim** the projector checks against
    /// the owner-issued reference, and a claim that differs is refused with
    /// [`ProjectionError::StaleEvidence`] rather than
    /// [`ProjectionError::OwnerEvidenceUnavailable`]. Nothing about the check
    /// itself weakened — before this change any non-empty claim was refused, and
    /// now a claim is refused unless it equals owner evidence.
    ///
    /// The purge-ledger revision is now **owner-issued** rather than refused.
    /// [`OwnerEvidence::owner_purge_ledger_revision`] reads it read-only from
    /// the ORS owner through a retained protected runtime-path lease and hands
    /// it to the projector beside the other owner values, so the presented
    /// revision is a **claim** the projector compares against owner evidence
    /// rather than a number this method passes through on the caller's behalf.
    /// Before this change the projector refused every presented revision
    /// outright; it now has an owner-issued value to compare one against. The
    /// value is neither a copied caller field nor a recomputed counter, and the
    /// read that produces it leaves no store handle, no write transaction and no
    /// retained lease behind, so it does not make this composition root a second
    /// mutable root owner.
    ///
    /// The presented forensic note is passed through unchanged too, but its role
    /// is now a **claim**: the projector compares it against
    /// [`OwnerEvidence::owner_audit_note`], the note this owner derives from the
    /// same validated lineage, and refuses a claim that differs as stale
    /// evidence. So no caller-authored disposition text reaches the record,
    /// while the projection digest does bind a real owner-observed lineage note.
    /// No secret-typed field exists on this path and no credential-typed value is
    /// read: the committed fence's `credential_receipt_digest` and
    /// `host_process_nonce_digest` are not extracted, because I5.13 forbids
    /// replaying a raw credential reference in a backup manifest. A
    /// credential-shaped value presented by a caller fails digest or identity
    /// shape rather than being projected.
    ///
    /// Installation identity, numeric generation and presented build digests
    /// remain caller-presented and shape-checked here, then bound into the
    /// returned record. The install identity's only owner corroboration is
    /// `BackupCallerAuth::authenticate_for_owner` at
    /// `HostComposition::prepare_backup_destination`, which compares it against
    /// the owner-issued launch installation handle before this method runs; the
    /// numeric generation, the lease reference and the build digests are
    /// compared against owner-issued values inside the projector. The returned
    /// record's `build_digests` is the complete owner-issued artifact set, not
    /// the presented subset.
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
    /// `bind_approved_build` over an owner-validated approved generation and its
    /// committed fence, the presented `build_digests` subset check against the
    /// owner-issued approved artifact set, and the projection digest's binding of
    /// the owner-issued retained Phase-B configuration digest. Nothing
    /// downstream may cite the `manifest_digest` comparison as an owner proof
    /// for a production preparation.
    ///
    /// That `manifest_digest` arm cannot be made a real presented-vs-owner
    /// comparison from this lane, and the reason is scope rather than design.
    /// [`PresentedPreparationRequest`] is the presented contract surface and it
    /// carries no config/policy/module manifest digest field, so there is no
    /// presented value to compare: feeding the owner value in as the presented
    /// side is precisely the self-comparison above. Adding the field is the
    /// correct fix, but `bins/eliot-host/tests/backup_preparation.rs` — outside
    /// this issue's Exclusive mutable scope — constructs
    /// [`PresentedPreparationRequest`] as an exhaustive struct literal, so a
    /// field added here would not compile that suite. Until the presented
    /// surface carries a configuration digest, T2's config-digest arm is
    /// refused-as-evidence rather than claimed. The owner comparisons that ARE
    /// real on this path are the numeric `generation` arm (presented
    /// `approved_generation` against the owner-issued authority generation), the
    /// `owner_lease_ref` arm (a presented reference against
    /// [`OwnerEvidence::owner_lease_ref`]) and the `build_digests` subset arm
    /// (each presented digest against the owner-issued approved artifact set).
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
        // The owner-issued lease reference is re-proved here, at the moment the
        // projection consumes it, and refuses typed if the retained lease no
        // longer pins the inspected source root. Taken BEFORE the projection so
        // a lease that went stale is a named owner refusal rather than a
        // projection digest naming an object that is no longer at the path.
        let owner_lease_ref = self.owner_lease_ref()?;
        // The owner-issued forensic audit note, derived from the same validated
        // lineage the rest of this bundle carries. Taken before the projection
        // for the same reason: a note that cannot be shaped must be a named
        // owner refusal, not a projection digest over it.
        let owner_audit = self.owner_audit_note()?;
        // The owner-issued purge-ledger revision, observed read-only from the ORS
        // owner through a retained protected runtime-path lease. Taken before
        // the projection for the same reason as the two values above: a stale,
        // unreadable or counter-less owner revision must be a named owner
        // refusal, not a projection digest that silently binds a zero nobody
        // issued.
        let owner_purge_ledger_revision = self.owner_purge_ledger_revision()?;
        project_backup_config_owner_bound(
            &config,
            binding,
            &owner_lease_ref,
            &owner_purge_ledger_revision,
            &owner_audit,
            &self.fence.authority_state_fence,
        )
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
/// Caller authentication itself has no Host-side verification to run against:
/// [`BackupCallerAuth::authenticate`] fails closed, and no destination effect
/// is reachable through it. #954 is not the open item — it merged
/// (`5e71386a`, PR #2572) and defines the role/operation contract in
/// `crates/foundation/eliot-protocol/src/backup.rs`, but that contract carries
/// no caller credential or token this contour can verify a lease or fence
/// digest against, and its own doc states that a payload value never grants a
/// role.
///
/// The live source-identity proof is
/// [`BackupCallerAuth::authenticate_for_owner`], which
/// `HostComposition::prepare_backup_destination` runs before any preparation
/// and which compares the presented source installation identity against the
/// owner-issued launch installation handle covered by the held owner lease. See
/// the module documentation for exactly what is proved there and what is not.
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
    /// Fail-closed because there is no owner-issued caller token to verify
    /// against: no installation record, approved generation, commit fence,
    /// owner lease or host-state record reachable from this contour carries a
    /// caller credential, so every caller is refused here before any
    /// destination effect. This is a real refusal, not a placeholder for a
    /// passing check: no destination can be prepared through the
    /// authenticated-caller path until such an owner exists, and no code path
    /// relaxes it. The implementation that fills it must not change this
    /// method's signature or callers.
    ///
    /// #954 is NOT the missing owner. It merged (`5e71386a`, PR #2572) and
    /// supplies the role/operation *contract* in
    /// `crates/foundation/eliot-protocol/src/backup.rs`; what it does not
    /// supply is a credential this contour can verify, and its own doc states
    /// that validators always compare a presented value against a separately
    /// passed role argument because a payload value never grants a role.
    ///
    /// The owner-issued source-identity proof that does exist today is
    /// [`BackupCallerAuth::authenticate_for_owner`]; this method covers the
    /// caller-role/credential half, which no owner issues.
    pub fn authenticate(&self) -> Result<(), PreparationError> {
        Err(PreparationError::InvalidRequest {
            field: "caller_auth",
            reason: "no owner-issued caller credential exists on this contour; unauthenticated \
                     preparation refused"
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
    /// Caller-channel (control-plane principal) authentication has no owner on
    /// this contour and is reported as backlog, not assumed; see
    /// [`BackupCallerAuth::authenticate`].
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
