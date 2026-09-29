//! Bounded owner-issued configuration evidence projection for backup (issue #958).
//!
//! Pure logical projection over explicitly supplied evidence: approved
//! generation, manifest/build digests, the owner state fence, and the
//! presented request. No I/O, no registry reads, no secret material. Every
//! digest is shape-checked lowercase hex; every identity is bounded text. Stale
//! or mixed evidence is rejected with the exact field named; nothing is ever
//! silently refreshed.
//!
//! # What the owner actually proves
//!
//! On the production path the owner proves seven things, and each reaches the
//! record as an owner-issued value rather than as a copied claim:
//!
//! - the **owner lease reference**, issued by `OwnerEvidence` from the
//!   protected-root lease it retains over the canonical source Host state root
//!   for the whole life of the evidence bundle and re-proves — pinned identity
//!   and the object's current final path — at the moment the projection uses it;
//! - the numeric **authority generation** and the **approved generation
//!   identity handle**, extracted from the owner-validated [`ApprovedGeneration`]
//!   and the committed activation fence;
//! - the **configuration digest** (the approved candidate template digest) and
//!   the **retained configuration digest** (the most recent owner-issued digest
//!   of the materialized Phase-B Store config bytes, which a completed Phase-B
//!   rebind supersedes), both from the same validated records;
//! - the **full owner-issued approved artifact digest set**, in manifest order,
//! rather than whichever subset a caller happened to name;
//! - the **approved profile token**, compared against the same validated
//!   approved record inside
//!   `crate::backup_preparation::DelegatedPreparation::prepare`;
//! - the **purge-ledger revision**, the owner-issued counter from the ORS owner
//!   read through the read-only, schema-checked purge-ledger reader published
//!   beside `eliot_ors::read_current_supervision_lease_read_only`
//!   (`crates/kernel/eliot-ors/src/status.rs:657`) and handed to the projector
//!   as `owner_purge_ledger_revision`;
//! - the **state fence**, which is the committed activation fence's authority
//!   state fence.
//!
//! The generation, configuration digest, artifact digest, purge-ledger and
//! owner-lease comparisons are presented-vs-owner: a caller that names a
//! different value is refused with [`ProjectionError::StaleEvidence`] naming the
//! exact field, so a stale or mixed claim cannot reach the record. The record
//! itself is filled from the owner side of each comparison, never from the
//! presented side.
//!
//! The purge-ledger revision is **owner-issued** on the production path, and the
//! seam that made that possible is named here so the boundary stays visible:
//!
//! - The purge-ledger revision is owner-issued by the ORS owner
//!   (`RedbRecoveryStore::purge_ledger_revision`, and its historical
//!   `backup_verification_purge_ledger_revision` binding). **This contour holds
//!   no ORS store handle beyond the single short-lived read-only observation
//!   `OwnerEvidence::owner_purge_ledger_revision` performs, and is not a store
//!   owner, and must not become one**: `crates/storage/AGENTS.md` forbids a
//!   **second mutable** root owner,
//!   and a Host-side read of the ORS `META` counter would additionally be a
//!   second copy of the owner's own rule (`META` and
//!   `PURGE_LEDGER_REVISION_KEY` are private to
//!   `crates/kernel/eliot-ors/src/store.rs`). What it consumes instead is the
//!   owner's own reading, published as a short-lived, read-only,
//!   schema-checked purge-ledger reader beside
//!   `eliot_ors::read_current_supervision_lease_read_only`
//!   (`crates/kernel/eliot-ors/src/status.rs:657`), the same retained-lease shape
//!   this bin already consumes read-only in `crate::watchdog_publication`
//!   (`watchdog_publication.rs:170`). The number reaching this projector is
//!   therefore the owner's, observed by the owner, and this function only
//!   compares against it; it never reads, opens or owns a store to obtain it.
//! - The forensic audit note is **owner-issued**, from the owner that did
//!   observe the installation lineage: `OwnerEvidence` holds the validated
//!   registry projection, its active approved generation and its committed
//!   activation fence, so it derives the note from those records at issue time
//!   (`OwnerEvidence::owner_audit_note`). It is not the kernel's
//!   `eliot_backup::HostStateAuditFence` — that type and its wire form
//!   `eliot_protocol::backup::HostAuditRef` are constructed only in
//!   `#[cfg(test)]` fixtures, and in production that fence is a caller-presented
//!   optional field of `eliot_kernel::backup_capture::CaptureRequest` — because a
//!   caller-presented note carries disposition claims nothing here corroborates.
//!   The note that reaches this projector is the owner's description of what it
//!   read, a presented one is a claim checked against it, and the typed
//!   non-authoritative ceiling (`active_authority_restored`) is enforced by
//!   [`AuditFenceNote::validate`] before anything is hashed. I5.13 keeps the
//!   fence forensic and never restored as active authority, and that ceiling is
//!   unchanged.
//!
//! A presented purge-ledger revision is a **claim**, checked against the
//! owner-issued one and refused with [`ProjectionError::StaleEvidence`] when it
//! differs, exactly like the lease-reference and audit-note arms. Because the
//! field is a `u64` with no distinct absent value, **zero is the "no claim"
//! reading** — the same admission the empty lease reference gets — and the
//! owner-issued value is what the record and the digest carry in either case.
//! I5.27 is honoured in both directions: the field is never silently omitted or
//! defaulted to an absent marker, and it is never defaulted to a presented
//! value.
//!
//! The presented source installation identity is bounded presented text. The
//! only owner-issued installation identity on this contour is the launch
//! installation handle, and it is proved against the presented value by
//! `BackupCallerAuth::authenticate_for_owner` at
//! `HostComposition::prepare_backup_destination` before any projection runs.
//! The projector itself performs no installation-identity comparison, and the
//! source root bound next to it in the prepared-destination receipt is the
//! owner-issued manifest-bound installation root, not presented text.
//!
//! # What is never projected
//!
//! No credential or secret material is read, referenced or carried:
//! `PhaseBLiveBinding::credential_receipt_digest` and
//! `PhaseBLiveBinding::host_process_nonce_digest` are visible on the committed
//! fence this module reads, and neither is extracted, because I5.13 forbids
//! replaying a raw credential reference and the projection's own purpose is
//! configuration evidence. No live Host-state database is copied either: the
//! only Host-state-derived value here is one OS file identity read from a
//! retained directory handle, which is an opaque volume/file-index pair, not
//! database content.
//!
//! No secret-typed field exists anywhere in this module: the rebind receipt read
//! here carries a `host_process_nonce_digest` and the rebind's prepared record
//! carries a `credential_receipt_digest`, and neither is extracted — only
//! `config_file_digest`, a public readback digest, is read.
//!
//! # Production caller
//!
//! [`project_backup_config_owner_bound`] is the production entry point. It is
//! invoked by `OwnerEvidence::project_backup_configuration` in
//! `crate::backup_preparation`, which
//! `crate::backup_preparation::DelegatedPreparation::prepare` runs for every
//! delegated preparation, so its [`BackupConfigProjection`] is the evidence the
//! prepared-destination receipt binds. That projector binds an **owner-issued**
//! forensic note (never a presented one), but it binds the note only inside the
//! projection digest: [`describe_audit_fence`] still renders no forensic text on
//! the production path and the prepared-destination receipt still carries no
//! audit claim at all, because its text is not restated into a receipt.
//!
//! [`project_backup_config`] is the current-authority-snapshot variant. It has
//! no production caller, and deliberately so: its [`AuthoritySnapshot`] has no
//! production constructor, so nothing in production assembles the whole set it
//! compares against. See [`project_backup_config_owner_bound`] for the
//! production comparison it stands in for.

use eliot_contracts::{ResourceGeneration, StateFence};
use eliot_installation::{ActivationCommitFence, ActivePhaseBRebind, ApprovedGeneration};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Projection format version pinned into every projection.
pub const CONFIG_PROJECTION_VERSION: u32 = 1;
/// Maximum digests carried in one request (bounds, case 958/16).
pub const MAX_DIGESTS: usize = 64;
/// Maximum length of one bounded identity string (bounds, case 958/16).
pub const MAX_IDENTITY_LEN: usize = 256;
/// Exact length of a lowercase hex SHA-256 digest string.
pub const DIGEST_HEX_LEN: usize = 64;

/// Errors for configuration projection (issue #958, cases 958/1-4, 958/16).
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ProjectionError {
    /// A digest field is not lowercase hex of the digest length.
    #[error("invalid digest in field {field}: expected 64 lowercase hex chars")]
    InvalidDigest { field: &'static str },
    /// A bounded identity string is empty, overlong, or carries controls.
    #[error("invalid identity in field {field}: bounded printable text required")]
    InvalidIdentity { field: &'static str },
    /// A bounded collection exceeds [`MAX_DIGESTS`].
    #[error("too many entries in field {field}: bound is 64")]
    BoundsExceeded { field: &'static str },
    /// Presented evidence disagrees with current authority evidence.
    #[error("stale evidence in field {field}: presented value differs from current authority")]
    StaleEvidence { field: &'static str },
    /// The owner issues no evidence for a field the request presents.
    ///
    /// Issued instead of copying an uncorroborated caller claim into an
    /// owner-issued record. `obligation` names the exact owner that must issue
    /// the value before such a request can be admitted; it is a static sentence
    /// and never echoes the presented value.
    #[error("no owner-issued evidence for field {field}: {obligation}")]
    OwnerEvidenceUnavailable {
        field: &'static str,
        obligation: &'static str,
    },
    /// A forensic audit note claims restored active authority (case 958/3).
    ///
    /// The typed non-authoritative ceiling. A `HostStateAuditFence` is forensic
    /// evidence and nothing else, so a note asserting that active authority was
    /// restored is exactly the claim I5.13 forbids the fence from carrying. The
    /// refusal is a distinct typed variant rather than a digest/identity shape
    /// error, because the offending value is a well-formed `true` and only the
    /// ceiling rejects it: collapsing it into [`Self::InvalidDigest`] or
    /// [`Self::InvalidIdentity`] would hide which guarantee failed.
    #[error(
        "forensic audit note in field {field} asserts restored active authority: a \
             HostStateAuditFence is forensic only and never a lease, grant, or current-state \
             assertion"
    )]
    ActiveAuthorityInAuditFence { field: &'static str },
}

// F-LOG-HOST-8 (#983) backup configuration diagnostics: observation-only helpers.
//
// Through the #889 facade's target and bounded-field helpers only, on the
// existing subscriber; the Event Log seam stays typed-Unavailable (never
// implemented here, #984 still open). `EntrypointStage` describes process
// startup/shutdown, not backup phases, so these observations carry local event
// names and never reuse that enum.
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static tokens, validated numeric facts, or
// counts; never identity/digest/nonce/config/archive/user strings (a canary
// stays absent even inside an alleged identity string), never
// `describe_audit_fence()` text, never arbitrary error `Debug`/`Display`.
// Truncation bounds size, never sensitivity. Macro arguments are precomputed
// pure values; sink outcome never alters results/order/receipts/rollback/
// cleanup, and stdout framing is untouched (facade stderr subscriber).
// Projection performs no owner query and these helpers add none.
//
// Terminal ownership (W4): the leaf emits nonterminal phase/refusal evidence
// only, with no dedup cache. The single terminal record per failed operation
// belongs to the outer caller boundary, which owns the one
// `observe_terminal_error` call. Handoff (caller-owned, APPLIED for the
// admitted preparation port under #983 W4): the production path is
// `project_backup_config_owner_bound`, invoked by
// `crate::backup_preparation::OwnerEvidence::project_backup_configuration`
// from the delegated preparation owner path, so a projection refusal here is a
// failed PREPARATION operation, not an operation of its own. That one terminal
// record is already owned by `HostComposition::backup_dispatch_prepare`
// through the crate's own `HostTerminalGuard` and the frozen
// `host-backup-prepare-failed` code; these leaf records correlate beneath that
// record by emission order. This leaf therefore deliberately arms no guard: a
// second terminal for the same failed operation would break "exactly one
// terminal emitter per failed operation". STILL PENDING, and deliberately not
// claimed: the snapshot variant `project_backup_config` has no production
// caller anywhere in the repository (only this crate's own
// `tests/backup_preparation.rs` reaches it) and its `AuthoritySnapshot` has no
// production constructor, which is why the owner-bound variant is the only
// production projector. No wrapper and no new terminal code were invented to
// close that gap.
//
// Explicit no-event list: `describe_audit_fence` (pure renderer, not an
// observation point; its forensic text must never be logged),
// `hash_state_fence`/`hash_audit_note`/`check_*` (private steps whose refusal
// surfaces with its exact static field at the projecting boundary).

/// Notes the facade's actual Event Log seam status (typed-unavailable).
fn backup_config_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

/// Counts bounded collections as a log-safe `u64` without truncation casts.
fn backup_config_count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Projects one [`ProjectionError`] to its stable diagnostic category plus the
/// static field it names. Pure and exhaustive; carries no caller content.
#[must_use]
fn projection_error_category(error: &ProjectionError) -> (&'static str, &'static str) {
    match *error {
        ProjectionError::InvalidDigest { field } => ("invalid_digest", field),
        ProjectionError::InvalidIdentity { field } => ("invalid_identity", field),
        ProjectionError::BoundsExceeded { field } => ("bounds_exceeded", field),
        ProjectionError::StaleEvidence { field } => ("stale_evidence", field),
        ProjectionError::OwnerEvidenceUnavailable { field, .. } => {
            ("owner_evidence_unavailable", field)
        }
        ProjectionError::ActiveAuthorityInAuditFence { field } => {
            ("active_authority_in_audit_fence", field)
        }
    }
}

/// Observes one nonterminal projection outcome after the decision exists.
/// Numerics come from the produced projection; `audit_present` names only
/// whether the forensic note was bound, never its content (non-authoritative).
fn observe_config_progress(
    op: &'static str,
    outcome: &'static str,
    generation: u64,
    purge_revision: u64,
    build_count: u64,
    audit_present: bool,
) {
    backup_config_note_event_log_unavailable();
    let op = crate::host_diagnostics::bound_field(op);
    let outcome = crate::host_diagnostics::bound_field(outcome);
    crate::host_diagnostics::info!(
        target: crate::host_diagnostics::HOST_DIAGNOSTICS_TARGET,
        event = "host.backup.config_phase",
        op = op.text(),
        outcome = outcome.text(),
        generation = generation,
        purge_revision = purge_revision,
        build_count = build_count,
        audit_present = audit_present,
        "host backup configuration projection observed"
    );
}

/// Observes one owner-build binding outcome after the decision exists.
fn observe_bind_progress(outcome: &'static str, artifact_count: u64) {
    backup_config_note_event_log_unavailable();
    let outcome = crate::host_diagnostics::bound_field(outcome);
    crate::host_diagnostics::info!(
        target: crate::host_diagnostics::HOST_DIAGNOSTICS_TARGET,
        event = "host.backup.config_phase",
        op = "bind_build",
        outcome = outcome.text(),
        artifact_count = artifact_count,
        "host backup owner-build binding observed"
    );
}

/// Observes one typed projection refusal after the decision exists, then hands
/// the unchanged error back. Terminal ownership stays with the outer caller.
fn note_config_error(op: &'static str, error: ProjectionError) -> ProjectionError {
    backup_config_note_event_log_unavailable();
    let (category, field) = projection_error_category(&error);
    let op = crate::host_diagnostics::bound_field(op);
    let category = crate::host_diagnostics::bound_field(category);
    let field = crate::host_diagnostics::bound_field(field);
    crate::host_diagnostics::warn!(
        target: crate::host_diagnostics::HOST_DIAGNOSTICS_TARGET,
        event = "host.backup.config_refusal",
        op = op.text(),
        category = category.text(),
        field = field.text(),
        "host backup configuration projection refused"
    );
    error
}

/// A complete owner-authority comparison set supplied as a whole value.
///
/// **This type has no production constructor.** The only construction anywhere
/// is the `authority_from_valid` test fixture helper in
/// `bins/eliot-host/tests/backup_preparation.rs`, and the only function that
/// consumes it, [`project_backup_config`], therefore has no production caller
/// either. That remains true for a reason that is no longer about the purge
/// ledger: no production code assembles this **whole** set, because no single
/// owner-issued read produces all five fields at once — the lease reference, the
/// approved record and the purge counter are three separate owner reads. The
/// purge counter in particular is no longer an obstacle, because the owner-issued
/// value now reaches the production projection as the
/// `owner_purge_ledger_revision` argument of
/// [`project_backup_config_owner_bound`] rather than through this struct. No
/// production constructor was invented for it here.
///
/// The production path is [`project_backup_config_owner_bound`]. It compares
/// every field this struct carries, each against a separately owner-issued
/// value, and **refuses** a presented `purge_ledger_revision` that differs from
/// the owner-issued one with [`ProjectionError::StaleEvidence`], rather than
/// comparing it against a value the same caller supplied. This struct is
/// retained as the snapshot-shaped comparison set for that variant; it is not,
/// and must not be read as, a description of evidence a production caller
/// supplies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthoritySnapshot {
    /// Owner lease reference (opaque bounded text, never a secret value).
    pub owner_lease_ref: String,
    /// Approved generation number.
    pub generation: u64,
    /// Config/policy/module manifest digest (lowercase hex 64).
    pub manifest_digest: String,
    /// Approved Host/dependency build digests (each lowercase hex 64).
    pub build_digests: Vec<String>,
    /// Purge-ledger revision.
    pub purge_ledger_revision: u64,
}

/// Backup configuration evidence request (issue #958, case 958/1).
///
/// Every field is presented evidence; the projector never invents currency for
/// any of them. Where the owner issues a value for a field, the projector
/// refuses a mismatch and fills the record from the owner side; where the owner
/// issues nothing and the field is not part of the record the receipt may carry,
/// the projector refuses the presented value itself with
/// [`ProjectionError::OwnerEvidenceUnavailable`].
/// [`project_backup_config_owner_bound`] compares `owner_lease_ref`,
/// `manifest_digest`, `build_digests`, `generation`, `purge_ledger_revision`
/// and `audit` against owner-issued values; [`project_backup_config`] compares
/// all six against an [`AuthoritySnapshot`] that has no production constructor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupConfigRequest {
    /// Source installation identity (bounded text).
    ///
    /// Presented. The only owner-issued installation identity on this contour is
    /// the launch installation handle, proved against the presented value at
    /// `HostComposition::prepare_backup_destination` before the delegated
    /// projection runs; the projector itself makes no such comparison.
    pub installation_id: String,
    /// Owner lease reference the requester claims.
    ///
    /// On the owner-bound production path this is a *claim* about the owner's
    /// lease, never the source of one: a non-empty value must equal the
    /// owner-issued lease reference
    /// `crate::backup_preparation::OwnerEvidence::owner_lease_ref`, or the
    /// projector refuses with [`ProjectionError::StaleEvidence`]. An empty
    /// value is "no claim", and the record then carries the owner-issued
    /// reference anyway. The snapshot variant still compares it against its
    /// [`AuthoritySnapshot`].
    pub owner_lease_ref: String,
    /// Generation the requester claims as approved. On the owner-bound
    /// production path this is refused unless it equals the owner-issued
    /// authority generation of the approved record.
    pub generation: u64,
    /// Config/policy/module manifest digest claimed.
    pub manifest_digest: String,
    /// Approved build digests claimed.
    ///
    /// On the owner-bound production path these are a *subset claim* against the
    /// owner-issued approved artifact digest set: every entry must be a member
    /// of that set, and the record carries the **full** owner-issued set rather
    /// than whichever subset was named, so the projection states the exact
    /// approved Host/dependency build identity (T1) instead of a caller's
    /// selection from it.
    pub build_digests: Vec<String>,
    /// Purge-ledger revision claimed.
    ///
    /// On the owner-bound production path this is a *claim* about the owner's
    /// revision, never the source of one, and it is checked exactly like the
    /// lease reference: because the field is a `u64` with no distinct absent
    /// value, **zero is the "no claim" reading** and is admitted, and any other
    /// presented value must equal the owner-issued revision the projector was
    /// handed, or it is refused with [`ProjectionError::StaleEvidence`]. The
    /// record and the projection digest carry the **owner-issued** revision in
    /// either case, so a claim can never become the evidence. I5.27 forbids
    /// silently omitting or defaulting this field in either direction, and
    /// neither happens: an absent claim is visible as the owner's own number,
    /// not as a substituted zero. The owner-issued value comes from the ORS
    /// owner's read-only, schema-checked purge-ledger reader, observed by the
    /// owner; this composition holds no ORS store handle beyond the single
    /// short-lived read-only observation
    /// `crate::backup_preparation::OwnerEvidence::owner_purge_ledger_revision`
    /// performs, and is not a store owner (`crates/storage/AGENTS.md` forbids a
    /// second **mutable** root owner). The snapshot variant still compares it
    /// against its [`AuthoritySnapshot`].
    pub purge_ledger_revision: u64,
    /// Optional forensic audit note; never authority (case 958/3).
    ///
    /// A **claim** on the owner-bound production path, not the source of the
    /// note: the projector holds the owner-issued note
    /// `crate::backup_preparation::OwnerEvidence::owner_audit_note` and refuses
    /// a presented one that differs from it with [`ProjectionError::StaleEvidence`],
    /// so a caller cannot substitute its own disposition claims for the ones the
    /// owner observed. Absent means "no claim" and is admitted; the projection
    /// digest binds the owner's note either way. The snapshot variant accepts it
    /// as presented content, and on both paths [`AuditFenceNote::validate`]
    /// enforces the typed non-authoritative ceiling before anything is hashed: a
    /// note claiming restored active authority is refused with
    /// [`ProjectionError::ActiveAuthorityInAuditFence`].
    pub audit: Option<AuditFenceNote>,
}

/// Forensic audit note with a typed non-authoritative ceiling (case 958/3).
///
/// Carries a digest, observed dispositions, and the one flag that states the
/// ceiling. There is deliberately NO constructor, conversion, or method that
/// turns this into a lease, grant, or current-state assertion;
/// [`describe_audit_fence`] renders the note with its ceiling stated, and
/// [`AuditFenceNote::validate`] ENFORCES that ceiling rather than only
/// describing it. No field here can be read as authority: the note has no
/// lease, grant, generation, epoch or state field to populate.
///
/// [`active_authority_restored`] is the ceiling made representable. Before it
/// existed, a note had no field in which a restored-authority claim could even
/// be stated, so the "never a lease, grant, or current-state assertion"
/// guarantee was documentation rather than a decision any code made. The same
/// flag exists on the owner's own fence type
/// (`eliot_backup::HostStateAuditFence::active_authority_restored`), so this
/// note is the projection of that recorded value and not a local invention;
/// the field defaults to `false` on read because a note that omits the claim
/// makes no restored-authority assertion.
///
/// On the owner-bound production path this note is **owner-issued**:
/// `crate::backup_preparation::OwnerEvidence::owner_audit_note` derives it from
/// the validated installation lineage that owner read (the registry projection,
/// its active approved generation, and the committed activation fence) at issue
/// time, and [`project_backup_config_owner_bound`] binds that value — never a
/// presented one — into the projection digest. A presented note is a claim
/// checked against the owner's and refused with
/// [`ProjectionError::StaleEvidence`] when it differs, which replaces a refusal
/// that rejected every presented note; no guarantee is weakened, because before
/// this change no presented note could reach the record at all. The
/// owner-issued note is still bound under this same typed ceiling, and the
/// prepared-destination receipt still never carries forensic text: it records
/// only that the note was bound, never what it said.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditFenceNote {
    /// Digest of the observed installation lineage/dispositions.
    pub note_digest: String,
    /// Observed dispositions (bounded text each).
    pub observed_dispositions: Vec<String>,
    /// Typed non-authoritative ceiling: whether this note claims active
    /// authority was restored. Always `false` for an admissible note.
    ///
    /// `#[serde(default)]` is not a default grant: `false` is the absence of a
    /// restored-authority *claim*, and a note that states the claim is refused
    /// by [`AuditFenceNote::validate`] with
    /// [`ProjectionError::ActiveAuthorityInAuditFence`].
    #[serde(default)]
    pub active_authority_restored: bool,
}

impl AuditFenceNote {
    /// Enforces the note's shape and its typed non-authoritative ceiling.
    ///
    /// Order is the ceiling first, then shape. A note that both claims
    /// restored active authority and carries a malformed digest is a ceiling
    /// violation, and reporting the digest instead would let the authority
    /// claim be "fixed" by re-digesting the note.
    ///
    /// This is a complete gate for one note: there is no shape check for an
    /// audit note anywhere else in this module, so a note that reaches
    /// [`BackupConfigProjection::projection_digest`] has passed the ceiling.
    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self.active_authority_restored {
            return Err(ProjectionError::ActiveAuthorityInAuditFence {
                field: "audit.active_authority_restored",
            });
        }
        check_digest(&self.note_digest, "audit.note_digest")
            .map_err(|error| note_config_error("audit", error))?;
        check_bounded_list(&self.observed_dispositions, "audit.observed_dispositions")
            .map_err(|error| note_config_error("audit", error))?;
        for disposition in &self.observed_dispositions {
            check_identity(disposition, "audit.observed_dispositions[]")
                .map_err(|error| note_config_error("audit", error))?;
        }
        Ok(())
    }
}

/// Bounded owner-issued logical projection of backup configuration evidence.
///
/// The field docs below describe the production owner-bound path reached from
/// `crate::backup_preparation::OwnerEvidence::project_backup_configuration`,
/// which is the only path a receipt is built from. A field is called verified
/// only when the projector compared the presented value against a value the
/// owner issued; a field the owner cannot issue says so, and a presented value
/// for such a field is refused rather than copied.
/// [`project_backup_config`] produces the same record from an
/// [`AuthoritySnapshot`] that has no production constructor, and is documented
/// at that function as not being on the production path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupConfigProjection {
    /// Projection format version ([`CONFIG_PROJECTION_VERSION`]).
    pub version: u32,
    /// Source installation identity, as presented by the requester and
    /// shape-checked. The projector makes no installation-identity comparison
    /// of its own: the installation registry is not consulted here, and the one
    /// owner-issued installation identity on this contour (the launch
    /// installation handle) is proved against the presented value at
    /// `HostComposition::prepare_backup_destination` before the delegated
    /// projection runs. Bounded text only; the source root itself is never
    /// carried here.
    pub installation_id: String,
    /// Owner lease reference, **owner-issued** on the production path.
    ///
    /// The value is whatever the owner issued as the lease reference for this
    /// preparation, never a presented string: on the delegated path that is
    /// `crate::backup_preparation::OwnerEvidence::owner_lease_ref`, which
    /// re-proves the retained protected-root lease (pinned identity AND the
    /// object's current final path) at the moment the projection consumes it and
    /// refuses typed if the source root is no longer the object the evidence
    /// chain admitted. A presented `owner_lease_ref` is a claim about that
    /// lease, not a source of one: it must be empty (no claim) or equal the
    /// owner-issued value, and a different one is refused with
    /// [`ProjectionError::StaleEvidence`] naming the field, so a stale or mixed
    /// lease cannot reach the record.
    ///
    /// This is deliberately **not** the installation-wide
    /// `eliot_platform_windows::HostOwnerLease` mutex name. That lease is held
    /// by `HostComposition` for the process lifetime, `HostOwnerLease::acquire`
    /// refuses to re-observe an existing object (and would *create* one if it
    /// were absent), and no installation record, approved generation or commit
    /// fence carries its name — so there is no way for this contour to observe
    /// it, and deriving one from a caller-chosen path would be fabrication. The
    /// lease the owner demonstrably holds and demonstrably retains for the life
    /// of this evidence bundle is the protected-root lease, and naming that is
    /// the honest binding. #954 merged (`5e71386a`, PR #2572) and still does not
    /// supply one: its `BackupAdmissionRef` is a per-operation admission
    /// reference, never a standing owner lease. The snapshot variant fills this
    /// from its [`AuthoritySnapshot`].
    pub owner_lease_ref: String,
    /// Approved generation, refused unless it equals the owner-issued
    /// authority generation of the active approved record on the production
    /// path, and refused unless it equals the supplied [`AuthoritySnapshot`] on
    /// the snapshot variant.
    pub generation: u64,
    /// Configuration digest of the approved record. It equals the owner-issued
    /// configuration digest whenever the projector was given a presented digest
    /// to check. On the production path the presented request carries no digest
    /// of its own and the projector is handed the owner's own value, so this
    /// field is owner-derived there and the projector's comparison is a shape
    /// guard rather than evidence — see
    /// `OwnerEvidence::project_backup_configuration`, which states this at the
    /// call site. Do not cite this field as an owner proof on that path.
    ///
    /// This is the approved candidate **template** digest. The **retained**
    /// configuration identity — the most recent owner-issued physical digest of
    /// the materialized Phase-B Store config bytes for this activation, which a
    /// completed Phase-B rebind supersedes — is a deliberately different fact
    /// and is bound in [`Self::projection_digest`] under its own label from
    /// [`ApprovedBuildBinding::retained_config_digest`], the same way
    /// `authority_generation`, `generation_handle` and `approved_profile` are
    /// bound without being separate record fields.
    pub manifest_digest: String,
    /// The **complete** owner-issued approved artifact digest set, in manifest
    /// order, on the owner-bound production path.
    ///
    /// A presented `build_digests` entry is a membership claim that must be
    /// satisfied by this set, but the record carries the whole set rather than
    /// the caller's subset: T1 asks for the *exact* owner-issued
    /// Host/dependency build projection, and a caller-narrowed list would let a
    /// record say "one approved artifact" about an installation with eight.
    /// The snapshot variant copies the presented list, because its
    /// [`AuthoritySnapshot`] comparison is equality against a caller-built
    /// value and narrowing it would weaken that arm.
    pub build_digests: Vec<String>,
    /// Purge-ledger revision, **owner-issued** on the production path.
    ///
    /// The value is the revision the ORS owner read through its read-only,
    /// schema-checked purge-ledger reader, never a presented number. A presented
    /// `purge_ledger_revision` is a claim about it: zero is "no claim" and is
    /// admitted, and any other value must equal the owner-issued revision or it
    /// is refused with [`ProjectionError::StaleEvidence`]. The record carries
    /// the owner-issued side either way, which is what a backup receipt has to
    /// bind so a restore compares against the ledger that actually held the
    /// purged data rather than against a number a caller supplied. The snapshot
    /// variant fills this from its [`AuthoritySnapshot`].
    pub purge_ledger_revision: u64,
    /// State fence bound at projection time.
    ///
    /// On the owner-bound production path this is the committed activation
    /// fence's authority state fence, so it is owner-issued; on the snapshot
    /// variant it is the fence the caller handed over.
    pub state_fence: StateFence,
    /// Projection digest binding every field above (domain-separated SHA-256).
    ///
    /// On the owner-bound production path it additionally binds the
    /// owner-issued facts that are not separate record fields: the authority
    /// generation, the approved generation handle, the approved profile token,
    /// the retained (materialized Phase-B) configuration digest, the
    /// **owner-issued forensic audit note**, and the complete owner-issued
    /// artifact digest set. A receipt therefore cannot be replayed across
    /// installations, authority generations, retained config byte sets or
    /// installation lineages. The note is bound here rather than carried as a
    /// record field so the serialized record shape — and therefore
    /// [`CONFIG_PROJECTION_VERSION`] — does not change; only the digest
    /// revision does.
    pub projection_digest: String,
}

/// Canonical length-prefixed field hashing shared by every #958 digest.
///
/// Both the label and the value are length-prefixed, so no two `(label, value)`
/// sequences — and no field boundary inside one — can produce the same byte
/// stream. I5.27 requires a deterministic, versioned canonical encoding; an
/// unprefixed concatenation does not give one.
pub(crate) fn hash_field(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    hasher.update((label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

/// Binds the caller-observed state fence into a projection digest.
///
/// `BackupConfigProjection::projection_digest` is documented to bind every field
/// above it, and `state_fence` is one of those fields, but the v1 digest was
/// computed without it: two projections differing only in the lineage-aware
/// authority epoch, resource generation or task/policy/integration revision
/// hashed identically. `StateFence` is a required durable field (I5.16) and the
/// fence is what carries authority, so omitting it from the binding is exactly
/// the silent omission I5.27 forbids.
///
/// The fence is encoded through its own derived `Serialize` implementation
/// (declaration-ordered, no maps), length-prefixed by [`hash_field`], so the
/// bytes are deterministic for this pinned fence type.
fn hash_state_fence(hasher: &mut Sha256, fence: &StateFence) -> Result<(), ProjectionError> {
    let encoded = serde_json::to_vec(fence).map_err(|_| ProjectionError::InvalidDigest {
        field: "state_fence",
    })?;
    hash_field(hasher, b"state_fence", &encoded);
    Ok(())
}

/// Binds the optional forensic audit note into a projection digest.
///
/// The note is validated request content that never reached the v1 digest, so
/// two requests differing only in the note produced byte-identical projections
/// and the receipt could not say which evidence was presented. The note keeps
/// its forensic ceiling — it is still never a lease, grant or current-state
/// assertion — binding it only discriminates the request it belongs to.
///
/// Both projectors reach this with a present note. The snapshot variant binds
/// the presented one it validated against its [`AuthoritySnapshot`]; the
/// owner-bound production path binds the **owner-issued** note
/// `crate::backup_preparation::OwnerEvidence::owner_audit_note` produced, and
/// only after its presented-versus-owner arm forced any claim to equal it, so
/// what the digest commits to is always the owner's side of the lineage.
fn hash_audit_note(hasher: &mut Sha256, audit: Option<&AuditFenceNote>) {
    let Some(note) = audit else {
        hash_field(hasher, b"audit", b"absent");
        return;
    };
    hash_field(hasher, b"audit", b"present");
    // The ceiling flag is bound as its enforced value, not omitted. I5.27
    // forbids silently omitting a field that affects authority in either
    // direction, and this one decides whether a note may be a current-state
    // assertion at all. `AuditFenceNote::validate` has already refused any
    // `true`, so the byte written here is the ceiling that was proved, and a
    // future relaxation of that gate is visible as a digest change rather
    // than as two byte-identical digests over different ceilings.
    hash_field(
        hasher,
        b"audit.active_authority_restored",
        &(u8::from(note.active_authority_restored)).to_le_bytes(),
    );
    hash_field(
        hasher,
        b"audit.disposition_count",
        &(note.observed_dispositions.len() as u64).to_le_bytes(),
    );
    hash_field(hasher, b"audit.note_digest", note.note_digest.as_bytes());
    for disposition in &note.observed_dispositions {
        hash_field(
            hasher,
            b"audit.observed_dispositions",
            disposition.as_bytes(),
        );
    }
}

fn check_digest(value: &str, field: &'static str) -> Result<(), ProjectionError> {
    if value.len() != DIGEST_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProjectionError::InvalidDigest { field });
    }
    Ok(())
}

fn check_identity(value: &str, field: &'static str) -> Result<(), ProjectionError> {
    if value.is_empty() || value.len() > MAX_IDENTITY_LEN || value.chars().any(char::is_control) {
        return Err(ProjectionError::InvalidIdentity { field });
    }
    Ok(())
}

fn check_bounded_list(values: &[String], field: &'static str) -> Result<(), ProjectionError> {
    if values.len() > MAX_DIGESTS {
        return Err(ProjectionError::BoundsExceeded { field });
    }
    Ok(())
}

/// Renders the forensic audit note with its non-authoritative ceiling stated
/// (case 958/3). The returned text is evidence only and can never act as a
/// lease, grant, or current-state assertion.
///
/// The ceiling is not only stated here, it is enforced: a note whose
/// [`AuditFenceNote::active_authority_restored`] is set is refused by
/// [`AuditFenceNote::validate`] with
/// [`ProjectionError::ActiveAuthorityInAuditFence`] before any projection is
/// built, so no rendered text can describe a note that claims restored active
/// authority.
///
/// This renderer is deliberately **not reached** from
/// `crate::backup_preparation` on either path. The owner-bound projector binds
/// its owner-issued note into the projection *digest* only, and a digest commits
/// to the note without restating its text, so no prepared-destination receipt
/// carries forensic prose — which is also why a note's dispositions must never
/// be logged. It remains the only place the ceiling wording exists, for the
/// snapshot variant and for the declared case 958/3 proof.
#[must_use]
pub fn describe_audit_fence(note: &AuditFenceNote) -> String {
    format!(
        "forensic audit note {} (non-authoritative: not a lease, grant, or current-state \
         assertion; active_authority_restored={}; dispositions: {})",
        note.note_digest,
        note.active_authority_restored,
        note.observed_dispositions.join(",")
    )
}

/// Projects bounded backup configuration evidence against a complete
/// authority snapshot (issue #958, cases 958/1-2, 958/4, 958/16).
///
/// **This is not the production projector and has no production caller.** Every
/// call site is in `bins/eliot-host/tests/backup_preparation.rs`; the only
/// producer of the [`AuthoritySnapshot`] it needs is that suite's
/// `authority_from_valid` fixture helper. It is retained as the whole-snapshot
/// comparison shape, for the case where one owner-issued value is available for
/// every field at once. A snapshot assembled from the very request it checks
/// compares only with itself, which is why its purge-ledger arm is unreachable
/// from any production path today and why the production projector takes the
/// revision from its own owner-issued argument instead.
///
/// The production path is [`project_backup_config_owner_bound`], which compares
/// against the owner-issued lease reference, generation, configuration digest,
/// artifact digests, purge-ledger revision and forensic note. Its digest domain
/// separator is therefore distinct from this function's, because the two
/// constructions bind different fields: this path is `snapshot.v3`, the
/// owner-bound path is `v7`.
///
/// Validates shapes and bounds, then requires field-for-field equality with
/// the supplied snapshot. Any stale or mixed field fails with
/// [`ProjectionError::StaleEvidence`] naming it. Credential-shaped values
/// fail digest shape and are never accepted; no secret-typed field exists.
#[allow(
    clippy::too_many_lines,
    reason = "the shape/staleness gate set stays in one boundary so no refusal observation can be skipped between neighbors"
)]
pub fn project_backup_config(
    request: &BackupConfigRequest,
    current: &AuthoritySnapshot,
    fence: &StateFence,
) -> Result<BackupConfigProjection, ProjectionError> {
    check_identity(&request.installation_id, "installation_id")
        .map_err(|error| note_config_error("project", error))?;
    check_identity(&request.owner_lease_ref, "owner_lease_ref")
        .map_err(|error| note_config_error("project", error))?;
    check_digest(&request.manifest_digest, "manifest_digest")
        .map_err(|error| note_config_error("project", error))?;
    check_bounded_list(&request.build_digests, "build_digests")
        .map_err(|error| note_config_error("project", error))?;
    for digest in &request.build_digests {
        check_digest(digest, "build_digests[]")
            .map_err(|error| note_config_error("project", error))?;
    }
    if let Some(audit) = &request.audit {
        // The complete gate for the note, including its typed
        // non-authoritative ceiling. The snapshot variant is the only
        // projector that admits a note at all, so this is the only place a
        // ceiling can be enforced for a note that reaches a projection digest.
        audit
            .validate()
            .map_err(|error| note_config_error("project", error))?;
    }
    if request.owner_lease_ref != current.owner_lease_ref {
        return Err(note_config_error(
            "project",
            ProjectionError::StaleEvidence {
                field: "owner_lease_ref",
            },
        ));
    }
    if request.generation != current.generation {
        return Err(note_config_error(
            "project",
            ProjectionError::StaleEvidence {
                field: "generation",
            },
        ));
    }
    if request.manifest_digest != current.manifest_digest {
        return Err(note_config_error(
            "project",
            ProjectionError::StaleEvidence {
                field: "manifest_digest",
            },
        ));
    }
    if request.build_digests != current.build_digests {
        return Err(note_config_error(
            "project",
            ProjectionError::StaleEvidence {
                field: "build_digests",
            },
        ));
    }
    if request.purge_ledger_revision != current.purge_ledger_revision {
        return Err(note_config_error(
            "project",
            ProjectionError::StaleEvidence {
                field: "purge_ledger_revision",
            },
        ));
    }
    let mut hasher = Sha256::new();
    // `snapshot.v3`, not the earlier `v2`: v2 did not bind the forensic note's
    // typed non-authoritative ceiling, so a stored v2 digest must not silently
    // match a digest over a note whose ceiling is now a proved field (I5.27).
    // The `snapshot.` infix also keeps this path's revision sequence disjoint
    // from the owner-bound path's (there `v3`, `v4`, `v5` and `v6` are retired
    // and `v7` is current): the two paths bind different fields and must never
    // be read as one revision series.
    hasher.update(b"eliot.backup.config-projection.snapshot.v3\0");
    hasher.update(CONFIG_PROJECTION_VERSION.to_le_bytes());
    hash_field(
        &mut hasher,
        b"installation_id",
        request.installation_id.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"owner_lease_ref",
        request.owner_lease_ref.as_bytes(),
    );
    hasher.update(b"generation\0");
    hasher.update(request.generation.to_le_bytes());
    hash_field(
        &mut hasher,
        b"manifest_digest",
        request.manifest_digest.as_bytes(),
    );
    for digest in &request.build_digests {
        hash_field(&mut hasher, b"build_digest", digest.as_bytes());
    }
    hasher.update(b"purge_ledger_revision\0");
    hasher.update(request.purge_ledger_revision.to_le_bytes());
    hash_state_fence(&mut hasher, fence).map_err(|error| note_config_error("project", error))?;
    hash_audit_note(&mut hasher, request.audit.as_ref());
    let projection_digest = format!("{:x}", hasher.finalize());
    // Observed projection only: numerics from the produced value, never
    // authority. The bound forensic note stays non-authoritative.
    observe_config_progress(
        "project",
        "projected",
        request.generation,
        request.purge_ledger_revision,
        backup_config_count(request.build_digests.len()),
        request.audit.is_some(),
    );
    Ok(BackupConfigProjection {
        version: CONFIG_PROJECTION_VERSION,
        installation_id: request.installation_id.clone(),
        owner_lease_ref: request.owner_lease_ref.clone(),
        generation: request.generation,
        manifest_digest: request.manifest_digest.clone(),
        build_digests: request.build_digests.clone(),
        purge_ledger_revision: request.purge_ledger_revision,
        state_fence: fence.clone(),
        projection_digest,
    })
}

/// Owner-verified build/config facts extracted from one validated
/// [`ApprovedGeneration`] installation record, the committed
/// [`ActivationCommitFence`] that activated it, and the registry's completed
/// Phase-B rebind when one exists.
///
/// Every value below is owner-issued and owner-validated. The configuration
/// digest is the candidate configuration digest, the retained configuration
/// digest is the most recent owner-issued physical digest of the materialized
/// Phase-B Store config bytes for this activation, and the build digests are the
/// eight approved artifact digests in manifest order, all shape-enforced by
/// [`ApprovedGeneration::validate`], [`ActivationCommitFence::validate`] and —
/// for the rebind — `ActivePhaseBRebind::validate` before extraction. The
/// generation handle is the owner-issued generation identity text, never a
/// caller-chosen string, and [`ApprovedBuildBinding::authority_generation`] is
/// the owner-issued numeric authority generation of the same record, never a
/// caller-chosen number.
///
/// The lease reference, the installation identity and the target build/profile
/// comparison itself stay outside this record: the lease reference is issued
/// separately by the owner that holds the lease (see
/// `crate::backup_preparation::OwnerEvidence::owner_lease_ref`), the
/// installation identity is compared at
/// `HostComposition::prepare_backup_destination`, and the last is compared in
/// `crate::backup_preparation::DelegatedPreparation::prepare` against
/// [`ApprovedBuildBinding::generation_handle`] and
/// [`ApprovedBuildBinding::approved_profile`], the two owner-issued names a
/// presented target may equal. The purge-ledger revision is owner-issued too,
/// but from a different owner over a different read, so it is not a field of
/// this struct either: it reaches the projection as the separate
/// `owner_purge_ledger_revision` argument of
/// [`project_backup_config_owner_bound`].
///
/// **Provenance is a property of the constructor, not of the type.** Every field
/// is `pub` and the type is not `#[non_exhaustive]`, so a caller can construct
/// one directly and every value in it becomes caller-declared — which would turn
/// the `generation` comparison in [`project_backup_config_owner_bound`] back into
/// the self-comparison it exists to remove. The owner-issuedness of each field
/// below holds for the [`bind_approved_build`] product only, exactly as
/// [`AuthoritySnapshot`] has no production constructor at all. Any future caller
/// that builds this value another way must not describe it as owner-issued.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedBuildBinding {
    /// Owner-issued generation identity handle text.
    ///
    /// This is the owner-issued approved build identity of the destination
    /// contour: the only build identity the installation authority names. A
    /// presented target build may equal it and nothing else, because no
    /// broader build-name catalogue exists on this path.
    pub generation_handle: String,
    /// Owner-issued numeric authority generation of the approved record.
    ///
    /// Extracted from the candidate manifest's
    /// `runtime_launch.authority_generation` only after
    /// [`ApprovedGeneration::validate`] has proved it equals the activation
    /// approval's authority generation. The commit fence then copies this same
    /// manifest value into `ActivationCommitFence::authority_generation`, so
    /// this is the same owner-issued quantity the committed fence carries. It
    /// is a [`ResourceGeneration`], so it cannot be zero or absent.
    pub authority_generation: ResourceGeneration,
    /// Owner-issued candidate configuration digest (lowercase hex 64).
    pub config_digest: String,
    /// Owner-issued **retained** configuration digest (lowercase hex 64).
    ///
    /// The most recent owner-issued physical SHA-256 of the materialized Host
    /// Phase-B Store config bytes for this activation, which is what a backup
    /// manifest has to name: the Phase-A template digest in [`Self::config_digest`]
    /// is a different fact, and binding only that left two different retained
    /// configurations projecting to one byte-identical digest.
    ///
    /// Two owner records can carry it, and the most recent one wins — see
    /// [`bind_approved_build`]:
    ///
    /// - a **completed** Phase-B rebind's `ActivePhaseBRebindReceipt::config_file_digest`,
    ///   which is the exact Store config readback of the latest materialization.
    ///   The registry keeps `active_phase_b_rebind` after the commit and clears
    ///   it only when a new generation is staged, and
    ///   `ApprovedGenerationRegistry::provisioned_supervision_authority_for_generation`
    ///   already prefers the completed rebind over the committed activation's
    ///   authority, so reading the committed fence alone here would have named a
    ///   pre-rebind digest for an installation whose config bytes were rebound;
    /// - otherwise `ActivationCommitFence::materialized_config_digest`, the
    ///   committed-activation readback. That field is documented as distinct from
    ///   the Phase-A template digest and from Store's semantic approved-config
    ///   hash, and [`ActivationCommitFence::validate`] proves it equals the
    ///   Phase-B live binding's `config_file_digest`.
    ///
    /// An *incomplete* rebind (one with no receipt) has published nothing, so the
    /// committed-activation value is still the live one and the rebind is not
    /// consulted for it.
    ///
    /// Neither source is read off an unvalidated record: [`bind_approved_build`]
    /// re-runs the fence validation, the rebind validation, and
    /// `ActivePhaseBRebindIntent::validate_against_prior_binding` against the
    /// committed Phase-B live binding, so a rebind belonging to a different
    /// activation is refused rather than mixed in.
    pub retained_config_digest: String,
    /// Owner-issued approved artifact digests in manifest order.
    pub artifact_digests: Vec<String>,
    /// Owner-issued installation profile token (lowercase `snake_case`).
    ///
    /// The approved record's own canonical serialization of
    /// `runtime_launch.profile`, read through the owner type's derived
    /// `Serialize`, so the spelling is the owner's and not a local table. A
    /// presented target profile may equal this and nothing else.
    pub approved_profile: String,
}

/// Binds the exact active approved generation to its owner-issued facts.
///
/// Takes the committed [`ActivationCommitFence`] as well as the approved
/// generation because the retained (materialized Phase-B) configuration
/// identity lives on the fence, not on the manifest, and the registry's
/// `Option<&ActivePhaseBRebind>` because a completed rebind is a LATER
/// materialization of the same activation's config bytes and outranks the
/// committed fence's readback. The records are proved to describe the same
/// activation here — owner validation of each, the generation / configuration
/// digest / authority generation agreement between the approved record and the
/// fence, and
/// `ActivePhaseBRebindIntent::validate_against_prior_binding` between the
/// rebind intent and the committed Phase-B live binding — so this constructor
/// never mixes one activation's facts with another's and the caller is not
/// asked to have done that check.
///
/// Fails closed with [`ProjectionError::StaleEvidence`] naming
/// `approved_generation` when the record is not active or its owner
/// validation rejects it, `commit_fence` when the fence fails validation or
/// disagrees with the approved record about the generation, configuration digest
/// or authority generation, and `phase_b_rebind` when a completed rebind fails
/// its own validation or is not bound to this activation's committed Phase-B
/// live binding. Owner error internals are never echoed: a record that fails
/// owner validation cannot be treated as current authority.
///
/// `None` for the rebind is a real "no rebind has completed", not an absence of
/// evidence, and a rebind with no receipt is treated the same way because it has
/// published nothing. In both cases the committed fence's readback is the live
/// one.
///
/// Owner validation is also what makes the numeric extraction sound: it rejects
/// a record whose manifest runtime launch descriptor disagrees with the
/// activation approval about the authority generation, so
/// [`ApprovedBuildBinding::authority_generation`] can only ever be read off a
/// record whose manifest and approval agree on it. The profile token is read
/// through the owner type's own serialization and fails closed rather than
/// falling back to a local spelling.
#[allow(
    clippy::too_many_lines,
    reason = "one linear owner-validation chain: each refusal names its own record and none may be reordered past a neighbour"
)]
pub fn bind_approved_build(
    approved: &ApprovedGeneration,
    fence: &ActivationCommitFence,
    rebind: Option<&ActivePhaseBRebind>,
) -> Result<ApprovedBuildBinding, ProjectionError> {
    if !approved.active {
        return Err(note_config_error(
            "bind_build",
            ProjectionError::StaleEvidence {
                field: "approved_generation",
            },
        ));
    }
    approved.validate().map_err(|_| {
        note_config_error(
            "bind_build",
            ProjectionError::StaleEvidence {
                field: "approved_generation",
            },
        )
    })?;
    let manifest = &approved.manifest;
    // The committed fence is the second owner record this binding reads, and it
    // is proved to describe the SAME activation as the approved generation
    // before any of its values are extracted. A fence from another activation
    // would otherwise put one generation's retained config bytes next to
    // another generation's template digest, which is exactly the mixing T2
    // refuses.
    fence.validate().map_err(|_| {
        note_config_error(
            "bind_build",
            ProjectionError::StaleEvidence {
                field: "commit_fence",
            },
        )
    })?;
    if fence.generation != manifest.generation
        || fence.config_digest != manifest.config_digest
        || fence.authority_generation != manifest.runtime_launch.authority_generation
    {
        return Err(note_config_error(
            "bind_build",
            ProjectionError::StaleEvidence {
                field: "commit_fence",
            },
        ));
    }
    // The retained configuration identity: the MOST RECENT owner-issued config
    // readback for this activation. A completed Phase-B rebind is a later
    // materialization of the same config bytes and outranks the committed
    // fence's readback — the registry keeps `active_phase_b_rebind` after the
    // commit, clears it only when a new generation is staged, and already
    // prefers the rebind for the live Phase-B supervision authority. Reading
    // the fence alone would name a pre-rebind digest for a rebound
    // installation, which is exactly the stale config digest T2 exists to
    // reject. A rebind with no receipt has published nothing, so it is the same
    // as no rebind here.
    let committed_phase_b = fence.phase_b_live_binding.as_ref().ok_or_else(|| {
        note_config_error(
            "bind_build",
            ProjectionError::StaleEvidence {
                field: "commit_fence",
            },
        )
    })?;
    let retained_config_digest =
        match rebind.and_then(|rebind| rebind.receipt.as_ref().map(|receipt| (rebind, receipt))) {
            None => fence.materialized_config_digest.as_str().to_owned(),
            Some((rebind, receipt)) => {
                // Bound to THIS activation before its readback is used: the
                // rebind's own validation, then its intent against the committed
                // Phase-B live binding (manifest digest, prior public receipt
                // digest, prior Host epoch lineage/sequence, nonce, owner epoch
                // and process identity). A rebind that cannot be tied to this
                // activation's committed binding is refused, not mixed in.
                rebind.validate().map_err(|_| {
                    note_config_error(
                        "bind_build",
                        ProjectionError::StaleEvidence {
                            field: "phase_b_rebind",
                        },
                    )
                })?;
                rebind
                    .intent
                    .validate_against_prior_binding(committed_phase_b)
                    .map_err(|_| {
                        note_config_error(
                            "bind_build",
                            ProjectionError::StaleEvidence {
                                field: "phase_b_rebind",
                            },
                        )
                    })?;
                receipt.config_file_digest.as_str().to_owned()
            }
        };
    let approved_profile = serde_json::to_value(manifest.runtime_launch.profile)
        .ok()
        .and_then(|profile| profile.as_str().map(str::to_owned))
        .ok_or_else(|| {
            note_config_error(
                "bind_build",
                ProjectionError::OwnerEvidenceUnavailable {
                    field: "approved_profile",
                    obligation:
                        "the approved record must carry a serializable installation profile",
                },
            )
        })?;
    let binding = ApprovedBuildBinding {
        generation_handle: manifest.generation.as_str().to_owned(),
        authority_generation: manifest.runtime_launch.authority_generation,
        config_digest: manifest.config_digest.as_str().to_owned(),
        retained_config_digest,
        artifact_digests: vec![
            manifest.kernel_artifact_digest.as_str().to_owned(),
            manifest.store_bridge_artifact_digest.as_str().to_owned(),
            manifest.canonical_store_artifact_digest.as_str().to_owned(),
            manifest.host_artifact_digest.as_str().to_owned(),
            manifest.doctor_artifact_digest.as_str().to_owned(),
            manifest.testd_artifact_digest.as_str().to_owned(),
            manifest.native_worker_artifact_digest.as_str().to_owned(),
            manifest.wasm_host_artifact_digest.as_str().to_owned(),
        ],
        approved_profile,
    };
    // Owner-issued facts only; the count observes the binding, never values.
    observe_bind_progress("bound", backup_config_count(binding.artifact_digests.len()));
    Ok(binding)
}

/// Projects backup configuration evidence against the owner-bound approved
/// record (issue #958, cases 958/1-2, 958/4, 958/16 with owner binding).
///
/// Shapes and bounds are checked as in [`project_backup_config`], plus the same
/// checks on the OWNER side: the owner-issued lease reference, retained
/// configuration digest and the complete approved artifact digest set are
/// `check_identity`/`check_digest`/`check_bounded_list` guarded before they can
/// reach the record or the digest, because [`ApprovedBuildBinding`] is a plain
/// public struct and a directly-constructed one would otherwise carry arbitrary
/// text into an owner-issued record. One difference from the snapshot variant is
/// deliberate: an EMPTY presented `owner_lease_ref` is legal here and means "no
/// claim", where the snapshot variant treats empty as an invalid identity.
///
/// Then five presented fields must agree with owner-issued ones, each failing
/// with [`ProjectionError::StaleEvidence`] naming the exact field:
///
/// - `owner_lease_ref`, when presented, must be bounded text and must equal the
///   `owner_lease_ref` argument — the reference the owner issued for the lease
///   it holds over the source. An empty presented value is "no claim", not "no
///   evidence", and the record carries the owner-issued reference either way;
/// - `generation` must equal [`ApprovedBuildBinding::authority_generation`],
///   the owner-issued numeric authority generation of the approved record;
/// - `manifest_digest` must equal the owner-issued configuration digest;
/// - every presented `build_digests` entry must be one of the owner-issued
///   artifact digests;
/// - `purge_ledger_revision`, when non-zero, must equal the
///   `owner_purge_ledger_revision` argument. Zero is "no claim" — the `u64` has
///   no distinct absent value — and the record carries the owner-issued revision
///   either way.
///
/// The generation arm runs before the configuration and artifact comparisons on
/// purpose: it is the scope the other approved-record owner facts belong to, so a
/// request that mixes one generation's digest into another generation's claim is
/// refused as a generation mismatch rather than as a digest mismatch. The
/// lease-reference and purge-ledger arms run ahead of it because each has its own
/// "no claim" admission that must be settled first; they compare against owner
/// reads from a different owner and are not scoped by the approved generation.
///
/// The record is then filled from the **owner side** of every comparison:
/// `owner_lease_ref` is the owner-issued reference, `purge_ledger_revision` is
/// the owner-issued revision, `generation` and
/// `manifest_digest` are the owner-issued values the comparisons just forced to
/// agree, and `build_digests` is the complete owner-issued approved artifact
/// set rather than the presented subset. So the projection states the exact
/// owner-issued config/policy/module/approved-build evidence (T1) and a
/// caller's narrowing of that evidence can neither become the record nor change
/// the digest.
///
/// # The purge-ledger revision is compared, not refused
///
/// The purge-ledger revision is **owner-issued**: the ORS owner issues it
/// (`RedbRecoveryStore::purge_ledger_revision`, with its historical
/// `backup_verification_purge_ledger_revision` binding), and this bin obtains
/// that value from the read-only, schema-checked purge-ledger reader published
/// beside `eliot_ors::read_current_supervision_lease_read_only`
/// (`crates/kernel/eliot-ors/src/status.rs:657`) and receives it as the
/// `owner_purge_ledger_revision` argument. So a presented revision is a
/// presented-versus-owner **claim**, refused with
/// [`ProjectionError::StaleEvidence`] when it differs — the same shape as the
/// lease reference and the forensic note.
///
/// This composition holds no ORS store handle beyond the single short-lived
/// read-only observation `OwnerEvidence::owner_purge_ledger_revision` performs,
/// and is not a store owner, and it must not open a retained one:
/// `crates/storage/AGENTS.md` forbids a **second mutable** root owner, so
/// reading the ORS `META` counter here would be a second copy of the owner's own
/// rule rather than evidence. What it consumes is the owner's reading over a
/// short-lived read, the same retained-lease shape `crate::watchdog_publication`
/// already consumes for the supervision lease.
///
/// The refusal that stood here previously is gone, and nothing is weakened by
/// its removal: before, a presented revision could never reach the record, and
/// the record stated the absence; now a revision reaches the record only when it
/// equals the owner-issued one, and what reaches it is always the **owner's**
/// number rather than the presented one. A no-claim request produces exactly
/// the record the refusal produced, except that the owner-issued revision is
/// stated instead of an absence.
///
/// The forensic audit note is no longer in that category: it is **owner-issued**,
/// from `owner_audit`, which is
/// `crate::backup_preparation::OwnerEvidence::owner_audit_note` — derived from
/// the validated installation lineage that owner actually read (the registry
/// projection, its active approved generation, and the committed activation
/// fence) at issue time. That is deliberately NOT the kernel's
/// `eliot_backup::HostStateAuditFence`, which is constructed only in
/// `#[cfg(test)]` fixtures and arrives in production as a caller-presented
/// optional field of `eliot_kernel::backup_capture::CaptureRequest`; a presented
/// note of that kind carries disposition claims nothing here corroborates. So a
/// presented note is now a **claim** checked against the owner's and refused
/// with [`ProjectionError::StaleEvidence`] when it differs. That replaces a
/// refusal which rejected every presented note, so nothing is weakened: before,
/// no presented note could reach the record at all; now only one equal to owner
/// evidence can. Both the owner's note and any presented one pass
/// [`AuditFenceNote::validate`] before anything is hashed, so the typed
/// non-authoritative ceiling is enforced on the owner's side too and the digest
/// can only ever commit to a note that passed it. I5.13's ceiling — forensic
/// evidence, never a lease, grant, or current-state assertion — is unchanged.
///
/// The projection digest binds the owner-issued generation handle, the
/// owner-issued authority generation, the owner-issued approved profile token,
/// the owner-issued template configuration digest, the owner-issued **retained**
/// (materialized Phase-B) configuration digest, the owner-issued lease
/// reference, the owner-issued forensic note and the complete owner-issued
/// artifact digest set, in addition to the presented fields, so a receipt cannot
/// migrate across installations, authority generations, retained configuration
/// byte sets or installation lineages. Its domain separator is `v7`, distinct
/// from [`project_backup_config`]'s `snapshot.v3` and from this path's earlier
/// `v3`, `v4`, `v5` and `v6`: `v3` hashed the caller's lease reference and
/// purge-ledger revision as if they were evidence, `v4` bound an *absent* lease
/// reference plus only the caller's chosen subset of the approved artifacts, `v5`
/// bound an *absent* forensic note, and `v6` bound an *absent* purge-ledger
/// revision, so a stored receipt under any of them must not silently match a
/// `v7` digest over the same logical input (I5.27). `v5` and `v6` **have**
/// shipped on `main`, so this binding genuinely changes what a digest commits
/// to: under `v5` two preparations whose installation lineage differed hashed
/// identically, and under `v6` a digest said nothing whatsoever about the purge
/// ledger, so neither a stored `v5` nor a stored `v6` receipt may be accepted
/// as evidence about either fact.
///
/// `CONFIG_PROJECTION_VERSION` is the serialized record schema version, not the
/// digest revision, and does not move: the record shape is unchanged, because
/// the owner-issued note is bound in the digest and is deliberately not a new
/// record field (adding one would change what a serialized projection means,
/// which is a schema change and not a digest revision). That asymmetry — digest
/// revision moves, schema version does not — is the existing rule applied, not
/// a new one. The set of bound fields and their order is otherwise unchanged.
///
/// The installation identity stays presented here and is compared by its real
/// owner at `HostComposition::prepare_backup_destination`, not by this
/// function. No secret-typed field exists here, and no credential-typed field is
/// read: the committed fence's `credential_receipt_digest` and
/// `host_process_nonce_digest`, and the rebind receipt's
/// `host_process_nonce_digest`, are deliberately not extracted, because I5.13
/// forbids replaying a raw credential reference in a backup manifest.
///
/// This is the production projector. Its caller is
/// `crate::backup_preparation::OwnerEvidence::project_backup_configuration`,
/// reached from `crate::backup_preparation::DelegatedPreparation::prepare` on
/// every delegated preparation; the returned
/// [`BackupConfigProjection::projection_digest`] is what the prepared
/// destination receipt binds.
///
/// The refusals below are owner comparisons only when `binding` came from
/// [`bind_approved_build`], `owner_lease_ref` came from the owner and
/// `owner_purge_ledger_revision` came from the owner. All three are plain public
/// values, so a caller that constructs them directly supplies the values the
/// refusals are measured against; on that path the arms degrade to shape guards.
/// The one production caller obtains its binding from `bind_approved_build` over
/// an owner-validated [`ApprovedGeneration`] and its committed
/// [`ActivationCommitFence`], its lease reference and purge-ledger revision from
/// `OwnerEvidence`, whose fields are all private and constructible only by
/// `OwnerEvidence::inspect`. The delegated path is therefore the owner
/// comparison these arms are written for.
#[allow(
    clippy::too_many_lines,
    reason = "the shape/staleness gate set stays in one boundary so no refusal observation can be skipped between neighbors"
)]
pub fn project_backup_config_owner_bound(
    request: &BackupConfigRequest,
    binding: &ApprovedBuildBinding,
    owner_lease_ref: &str,
    owner_purge_ledger_revision: &u64,
    owner_audit: &AuditFenceNote,
    fence: &StateFence,
) -> Result<BackupConfigProjection, ProjectionError> {
    check_identity(&request.installation_id, "installation_id")
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    check_digest(&request.manifest_digest, "manifest_digest")
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    check_bounded_list(&request.build_digests, "build_digests")
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    for digest in &request.build_digests {
        check_digest(digest, "build_digests[]")
            .map_err(|error| note_config_error("project_owner_bound", error))?;
    }
    // The owner-issued lease reference is evidence, so it is shape-checked on
    // the owner's side exactly like a presented one: an owner that produced
    // unbounded or control-bearing text fails closed here instead of putting it
    // in a receipt.
    check_identity(owner_lease_ref, "owner_lease_ref")
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    // The presented claim is bounded like every other presented field. The
    // snapshot variant always checked it; this arm did not need to while it
    // refused every non-empty value, and now that a non-empty claim can be
    // admitted, an unbounded one is a typed refusal again instead of a
    // multi-kilobyte string compared against a 40-byte owner value. Empty stays
    // legal here and means "no claim" — that is the one deliberate difference
    // from the snapshot variant, where empty is simply an invalid identity.
    if !request.owner_lease_ref.is_empty() {
        check_identity(&request.owner_lease_ref, "owner_lease_ref")
            .map_err(|error| note_config_error("project_owner_bound", error))?;
    }
    // The owner-issued config and build identities are shape-checked here for
    // the same reason. On the production path they come from an owner-validated
    // `CandidateManifest` and fence, but `ApprovedBuildBinding` is a plain
    // public struct, so a directly-constructed one could otherwise put
    // arbitrary text into both the record and the digest on the strength of a
    // guard that only ever covered the caller's narrower list.
    check_digest(&binding.retained_config_digest, "retained_config_digest")
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    check_bounded_list(&binding.artifact_digests, "approved_artifact_digests")
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    for digest in &binding.artifact_digests {
        check_digest(digest, "approved_artifact_digests[]")
            .map_err(|error| note_config_error("project_owner_bound", error))?;
    }
    // The forensic audit note is OWNER-ISSUED here, not refused and not
    // caller-authored. The note this function was handed is the one
    // `crate::backup_preparation::OwnerEvidence::owner_audit_note` derived from
    // the validated registry lineage at issue time, so its content is a
    // description of owner-observed state rather than a claim about it.
    //
    // The owner side is shape- and ceiling-checked exactly like every other
    // owner-issued value, because `AuditFenceNote` is a plain public struct: a
    // directly-constructed note would otherwise put arbitrary text into an
    // owner-issued record. `validate()` enforces the typed non-authoritative
    // ceiling (a note asserting restored active authority is refused with
    // `ActiveAuthorityInAuditFence`) before any byte is hashed, so the digest
    // can only ever commit to a note that passed the ceiling.
    owner_audit
        .validate()
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    // A presented note is now a CLAIM, not the source of the note, and it is
    // checked against the owner's — the same presented-versus-owner shape as
    // the lease reference below. Empty is "no claim" and is admitted; a note
    // that differs from the owner's is refused naming the exact field, so a
    // caller cannot substitute its own disposition claims for the observed
    // ones. This replaces a refusal that rejected every presented note, so no
    // guarantee is weakened: before, no presented note could reach the record;
    // now only one that equals owner evidence can.
    if let Some(presented) = request.audit.as_ref() {
        presented
            .validate()
            .map_err(|error| note_config_error("project_owner_bound", error))?;
        if presented != owner_audit {
            return Err(note_config_error(
                "project_owner_bound",
                ProjectionError::StaleEvidence { field: "audit" },
            ));
        }
    }
    // Owner-issued lease reference, refused before any digest is named. The
    // owner issued this text from the lease it holds over the source (see
    // `crate::backup_preparation::OwnerEvidence::owner_lease_ref`), so a
    // presented value that differs is a stale or foreign lease, not a naming
    // preference. Absence of a presented claim is admitted and is not evidence
    // of absence: the record below carries the owner-issued reference.
    if !request.owner_lease_ref.is_empty() && request.owner_lease_ref != owner_lease_ref {
        return Err(note_config_error(
            "project_owner_bound",
            ProjectionError::StaleEvidence {
                field: "owner_lease_ref",
            },
        ));
    }
    // Owner-issued purge-ledger revision, refused before any digest is named.
    // The revision this function was handed is the ORS owner's own reading,
    // obtained by `OwnerEvidence` through the read-only, schema-checked
    // purge-ledger reader published beside
    // `eliot_ors::read_current_supervision_lease_read_only`. This contour holds
    // no ORS store handle and is not a store owner: it compares against the
    // owner's number, it never reads the ORS `META` counter itself, because
    // `crates/storage/AGENTS.md` forbids a second mutable root owner.
    //
    // A presented revision is a CLAIM, not the source, exactly like the lease
    // reference above. There is no shape check to add on either side because the
    // owner-issued value is a plain number, not text: there is nothing to
    // length-prefix-validate, and no ceiling or "must be non-zero" rule is
    // invented here, because the owner states no such bound and this function
    // must not invent authority it was not given.
    //
    // NO-CLAIM RULE, chosen deliberately: **zero is "no claim" and is admitted**,
    // mirroring the empty lease reference and the `None` audit note, and
    // mirroring the fact that zero was previously this path's by-construction
    // value. The field is a `u64` with no distinct absent marker, so a request
    // that observed nothing about the purge ledger has no other way to say so;
    // requiring every presented value to equal the owner's would make "I have
    // no claim" inexpressible and would force a caller to echo a number it cannot
    // observe. This rule cannot let an uncorroborated value reach the record or
    // the digest: the record and the digest below carry
    // `*owner_purge_ledger_revision` unconditionally, so an admitted zero
    // changes only whether a claim was *checked*, never what is *recorded*. A
    // non-zero claim that is not the owner's is refused naming the exact field,
    // so a caller can never substitute its own revision for the observed one —
    // and, because the owner's number is bound either way, the projection can
    // never claim a revision weaker than the one the owner actually read.
    if request.purge_ledger_revision != 0
        && request.purge_ledger_revision != *owner_purge_ledger_revision
    {
        return Err(note_config_error(
            "project_owner_bound",
            ProjectionError::StaleEvidence {
                field: "purge_ledger_revision",
            },
        ));
    }
    // Owner-issued numeric authority generation, refused before any digest is
    // named. `DestinationAdmission` in `crate::backup_preparation` already
    // requires the presented `approved_generation` to equal the presented
    // `authority_generation`, and `bind_approved_build` extracts the owner
    // value from a record whose manifest and activation approval owner
    // validation has already proved agree on it, so this compares two readings
    // of one quantity: the request's claim against the owner's. It is not a
    // self-comparison of two caller values, and a zero or absent owner value is
    // unrepresentable because the owner value is a `ResourceGeneration`.
    if request.generation != binding.authority_generation.value() {
        return Err(note_config_error(
            "project_owner_bound",
            ProjectionError::StaleEvidence {
                field: "generation",
            },
        ));
    }
    if request.manifest_digest != binding.config_digest {
        return Err(note_config_error(
            "project_owner_bound",
            ProjectionError::StaleEvidence {
                field: "manifest_digest",
            },
        ));
    }
    for digest in &request.build_digests {
        if !binding
            .artifact_digests
            .iter()
            .any(|artifact| artifact == digest)
        {
            return Err(note_config_error(
                "project_owner_bound",
                ProjectionError::StaleEvidence {
                    field: "build_digests",
                },
            ));
        }
    }
    // Every arm above runs before any digest is computed, so nothing that
    // reaches this point carries a caller-declared purge-ledger revision, lease
    // reference or audit note that the owner did not first corroborate. A
    // caller-declared lease reference and revision *can* reach the record, but
    // only after their arms above proved them equal to the owner-issued values,
    // and the digest below binds the owner-issued side regardless.
    let mut hasher = Sha256::new();
    // v7 on this path only. The retired revisions, each named so a stored
    // receipt over the same logical request cannot silently match a later
    // digest (I5.27): v3 hashed the presented lease reference and purge-ledger
    // revision as if they were evidence; v4 bound an *absent* lease reference
    // plus only the caller's chosen subset of the approved artifacts; v5 bound
    // an *absent* forensic note, because at that revision nothing on this path
    // could observe the installation lineage; and v6 bound the literal
    // `absent` for the purge-ledger revision, a field the owner had not yet
    // issued. v6 therefore says NOTHING about the purge ledger, so a stored v6
    // receipt over the same logical request must not be accepted as evidence
    // about one — v7 binds the owner-issued number instead. This is a real
    // change in what a digest commits to, not a cosmetic bump: under v6 two
    // preparations whose purge ledger differed hashed identically, and under v7
    // they do not.
    // `CONFIG_PROJECTION_VERSION` is the serialized record schema version, not
    // the digest revision, and does not move: the record shape is unchanged
    // (the owner-issued note is bound in the digest, and is not a new record
    // field; the purge-ledger revision was already a record field and is filled
    // with the owner-issued value instead of an absence).
    // See [`project_backup_config`] for the snapshot variant, whose coverage is
    // unchanged and whose separator is untouched at `snapshot.v3`.
    hasher.update(b"eliot.backup.config-projection.v7\0");
    hasher.update(CONFIG_PROJECTION_VERSION.to_le_bytes());
    hash_field(
        &mut hasher,
        b"installation_id",
        request.installation_id.as_bytes(),
    );
    // The OWNER-issued lease reference, never the presented string. The refusal
    // above already forces the two equal when a claim was made, so binding this
    // is what makes the digest say which side supplied the reference and keeps
    // that true if that refusal is ever reordered or weakened.
    hash_field(&mut hasher, b"owner_lease_ref", owner_lease_ref.as_bytes());
    hasher.update(b"generation\0");
    hasher.update(request.generation.to_le_bytes());
    // Owner-issued authority generation, bound under its own label rather than
    // only through the presented value. The refusal above already forces the
    // two equal, so this is not what makes the check happen; it is what makes
    // the digest say which side of the comparison supplied the number, and it
    // keeps that true if the refusal is ever reordered or weakened.
    hash_field(
        &mut hasher,
        b"authority_generation",
        &binding.authority_generation.value().to_le_bytes(),
    );
    hash_field(
        &mut hasher,
        b"generation_handle",
        binding.generation_handle.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"approved_profile",
        binding.approved_profile.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"manifest_digest",
        binding.config_digest.as_bytes(),
    );
    // The retained (materialized Phase-B) configuration identity, bound
    // separately from the approved template digest above. Without it, two
    // installations whose approved template digest agrees but whose materialized
    // Store config bytes differ would project to one byte-identical digest, so
    // the retained identity I5.13 asks a backup manifest to name was in fact
    // unnamed (I5.27).
    hash_field(
        &mut hasher,
        b"retained_config_digest",
        binding.retained_config_digest.as_bytes(),
    );
    // The COMPLETE owner-issued approved artifact digest set, in manifest order.
    // The presented subset is a membership claim checked above; binding it here
    // would bind a caller's narrowing of the owner's evidence rather than the
    // approved Host/dependency build identity itself, and two requests naming
    // different valid subsets of one approved build are one and the same owner
    // fact (T1).
    for digest in &binding.artifact_digests {
        hash_field(&mut hasher, b"approved_artifact_digest", digest.as_bytes());
    }
    // The OWNER-ISSUED purge-ledger revision, hashed as a number under the
    // same label and in the same position the absent marker used to occupy, so
    // the field order is byte-identical and only its meaning changes. v6 bound
    // the literal `absent` here; v7 commits to the revision the ORS owner
    // actually read. The arm above refused any non-zero presented value that
    // differs from it, so binding this is what makes the digest say which side
    // supplied the number and keeps that true if that arm is ever reordered or
    // weakened. It is the owner-issued value even when no claim was presented.
    hash_field(
        &mut hasher,
        b"purge_ledger_revision",
        &owner_purge_ledger_revision.to_le_bytes(),
    );
    hash_state_fence(&mut hasher, fence)
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    // The OWNER-ISSUED forensic note, never the presented one. The arm above
    // refused any presented note that differs from it, so binding this is what
    // makes the digest say which side supplied the note and keeps that true if
    // that arm is ever reordered or weakened.
    hash_audit_note(&mut hasher, Some(owner_audit));
    let projection_digest = format!("{:x}", hasher.finalize());
    // Observed owner-bound projection only, never authority. Numeric facts
    // come from the produced value, and the purge revision observed here is the
    // owner-issued one — a caller-presented number is never reported as an
    // observation. A refused projection carries no numeric observation at all,
    // because every arm above returns before this point.
    // `audit_present` names only that the owner-issued note was BOUND, never
    // its content: it is forensic text that must never be logged.
    observe_config_progress(
        "project_owner_bound",
        "projected_owner_bound",
        request.generation,
        *owner_purge_ledger_revision,
        backup_config_count(binding.artifact_digests.len()),
        true,
    );
    Ok(BackupConfigProjection {
        version: CONFIG_PROJECTION_VERSION,
        installation_id: request.installation_id.clone(),
        // The owner-issued reference, never the presented string: the arm above
        // refused any presented value that differs from it.
        owner_lease_ref: owner_lease_ref.to_owned(),
        generation: request.generation,
        manifest_digest: binding.config_digest.clone(),
        // The complete owner-issued approved artifact set, never the caller's
        // subset of it.
        build_digests: binding.artifact_digests.clone(),
        // The owner-issued revision, never the presented number: the arm above
        // refused any non-zero presented value that differs from it.
        purge_ledger_revision: *owner_purge_ledger_revision,
        state_fence: fence.clone(),
        projection_digest,
    })
}
