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
//! On the production path the owner proves exactly three things, and each is
//! compared field-for-field against presented evidence: the numeric
//! authority generation, the configuration digest and the approved artifact
//! digest set. The owner-issued approved build identity and profile token are
//! compared against the same validated approved record inside
//! `crate::backup_preparation::DelegatedPreparation::prepare`.
//!
//! For three further fields this path has no owner evidence at all: an owner
//! lease reference, a purge-ledger revision, and a forensic audit note. The
//! installation registry, the [`ApprovedGeneration`] record, the activation
//! commit fence and the host-state records observed here carry none of them, so
//! a presented value could not be corroborated by anything. Such a value is
//! therefore **refused** with [`ProjectionError::OwnerEvidenceUnavailable`],
//! which names the missing owner obligation, instead of being copied into an
//! owner-issued projection and its digest. With no claim presented the record
//! carries the absence and the digest binds that absence explicitly: I5.27
//! forbids silently omitting or defaulting a field that affects authority, in
//! either direction.
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
//! # Production caller
//!
//! [`project_backup_config_owner_bound`] is the production entry point. It is
//! invoked by `OwnerEvidence::project_backup_configuration` in
//! `crate::backup_preparation`, which
//! `crate::backup_preparation::DelegatedPreparation::prepare` runs for every
//! delegated preparation, so its [`BackupConfigProjection`] is the evidence the
//! prepared-destination receipt binds. Because that projector refuses a
//! presented audit note, [`describe_audit_fence`] renders no caller-authored
//! forensic text on the production path and the prepared-destination receipt
//! carries no audit claim at all.
//!
//! [`project_backup_config`] is the current-authority-snapshot variant. It has
//! no production caller, and deliberately so: its [`AuthoritySnapshot`] needs
//! an owner-issued lease reference and a purge-ledger revision, and the
//! installation registry, [`ApprovedGeneration`] and the activation commit
//! fence carry neither. See [`project_backup_config_owner_bound`] for the
//! refusals that replace those two comparisons on the production path.

use eliot_contracts::{ResourceGeneration, StateFence};
use eliot_installation::ApprovedGeneration;
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
// `observe_terminal_error` call. Handoff (caller-owned, not applied here):
// when HostComposition delegation lands, its dispatch wrapper arms one
// terminal guard with a frozen `host-backup-config-failed` code; these leaf
// records correlate beneath it by emission order.
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
    tracing::info!(
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
    tracing::info!(
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
    tracing::warn!(
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
/// either. Nothing in the installation registry, [`ApprovedGeneration`] or the
/// activation commit fence carries `owner_lease_ref` or
/// `purge_ledger_revision`, so producing this struct from a production path
/// would mean copying both values out of the request being checked, which
/// would turn the comparison into a self-comparison that can never fail.
///
/// The production path is [`project_backup_config_owner_bound`], which compares
/// the three fields the owner really does issue and **refuses** a presented
/// lease reference or purge-ledger revision with
/// [`ProjectionError::OwnerEvidenceUnavailable`] instead of comparing them
/// against a value the same caller supplied. This struct is retained as the
/// snapshot-shaped comparison set for that variant; it is not, and must not be
/// read as, a description of evidence a production caller supplies.
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
/// refuses a mismatch; where the owner issues nothing and the field is not part
/// of the record the receipt may carry, the projector refuses the presented
/// value itself with [`ProjectionError::OwnerEvidenceUnavailable`].
/// [`project_backup_config_owner_bound`] compares `manifest_digest`,
/// `build_digests` and `generation` against owner-issued values and refuses a
/// presented `owner_lease_ref`, `purge_ledger_revision` or `audit`;
/// [`project_backup_config`] compares all five against an
/// [`AuthoritySnapshot`] that has no production constructor.
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
    /// Refused on the owner-bound production path: no owner here issues a lease
    /// reference, so any presented value is uncorroborated. Lease issuance
    /// belongs to the #954 control contracts, which are open. The snapshot
    /// variant still compares it against its [`AuthoritySnapshot`].
    pub owner_lease_ref: String,
    /// Generation the requester claims as approved. On the owner-bound
    /// production path this is refused unless it equals the owner-issued
    /// authority generation of the approved record.
    pub generation: u64,
    /// Config/policy/module manifest digest claimed.
    pub manifest_digest: String,
    /// Approved build digests claimed.
    pub build_digests: Vec<String>,
    /// Purge-ledger revision claimed.
    ///
    /// Refused on the owner-bound production path: purge-ledger authority is
    /// owned outside Host backup preparation and no owner here observes a
    /// revision, so any presented value is uncorroborated. The snapshot variant
    /// still compares it against its [`AuthoritySnapshot`].
    pub purge_ledger_revision: u64,
    /// Optional forensic audit note; never authority (case 958/3).
    ///
    /// Refused on the owner-bound production path: the note is caller-authored
    /// and nothing here compares its digest or its observed dispositions to Host
    /// state, so carrying it would put unverified claims into an owner-issued
    /// record. The snapshot variant accepts it and keeps its forensic ceiling.
    pub audit: Option<AuditFenceNote>,
}

/// Forensic audit note with a typed non-authoritative ceiling (case 958/3).
///
/// Carries a digest plus observed dispositions only. There is deliberately NO
/// constructor, conversion, or method that turns this into a lease, grant,
/// or current-state assertion; [`describe_audit_fence`] renders the note
/// with its ceiling stated.
///
/// Nothing on the owner-bound production path issues or corroborates such a
/// note, so [`project_backup_config_owner_bound`] refuses a presented one and
/// the prepared-destination receipt never carries one. I5.13 keeps the
/// `HostStateAuditFence` optional for exactly this reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditFenceNote {
    /// Digest of the observed installation lineage/dispositions.
    pub note_digest: String,
    /// Observed dispositions (bounded text each).
    pub observed_dispositions: Vec<String>,
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
    /// Owner lease reference. Always **empty** on the owner-bound production
    /// path: no owner issues a lease reference there, so a presented one is
    /// refused with [`ProjectionError::OwnerEvidenceUnavailable`] rather than
    /// copied, and the record states the absence instead. Lease issuance
    /// belongs to the #954 control contracts, which are open. The snapshot
    /// variant fills this from its [`AuthoritySnapshot`].
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
    pub manifest_digest: String,
    /// Build digests, each verified to be a member of the owner-issued
    /// approved artifact digest set.
    pub build_digests: Vec<String>,
    /// Purge-ledger revision. Always **zero** on the owner-bound production
    /// path: purge-ledger authority is owned outside Host backup preparation
    /// and no owner observed here issues a revision, so a presented one is
    /// refused with [`ProjectionError::OwnerEvidenceUnavailable`] and the
    /// record states the absence. The snapshot variant fills this from its
    /// [`AuthoritySnapshot`].
    pub purge_ledger_revision: u64,
    /// State fence bound at projection time.
    ///
    /// On the owner-bound production path this is the committed activation
    /// fence's authority state fence, so it is owner-issued; on the snapshot
    /// variant it is the fence the caller handed over.
    pub state_fence: StateFence,
    /// Projection digest binding every field above (domain-separated SHA-256).
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
/// Only [`project_backup_config`] can reach this with a present note:
/// [`project_backup_config_owner_bound`] refuses a presented note outright, so
/// on the production path this binds the observed absence.
fn hash_audit_note(hasher: &mut Sha256, audit: Option<&AuditFenceNote>) {
    let Some(note) = audit else {
        hash_field(hasher, b"audit", b"absent");
        return;
    };
    hash_field(hasher, b"audit", b"present");
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
/// The note it renders is **caller-authored**, and the owner-bound production
/// path therefore refuses a presented note
/// ([`project_backup_config_owner_bound`]): no owner here compares the note
/// digest or its observed dispositions to Host state, so this renderer is
/// deliberately not reached from `crate::backup_preparation` and no
/// prepared-destination receipt carries such text. It remains the only place
/// the ceiling wording exists, for the snapshot variant and for the declared
/// case 958/3 proof.
#[must_use]
pub fn describe_audit_fence(note: &AuditFenceNote) -> String {
    format!(
        "forensic audit note {} (non-authoritative: not a lease, grant, or current-state assertion; dispositions: {})",
        note.note_digest,
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
/// compares only with itself, which is why its lease and purge-ledger arms are
/// unreachable from any production path today and why the production projector
/// refuses those two fields instead of comparing them.
///
/// The production path is [`project_backup_config_owner_bound`], which compares
/// against the owner-issued generation, configuration digest and artifact
/// digests of the active approved record. Its digest domain separator is
/// therefore distinct from this function's, because the two constructions bind
/// different fields.
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
        check_digest(&audit.note_digest, "audit.note_digest")
            .map_err(|error| note_config_error("project", error))?;
        check_bounded_list(&audit.observed_dispositions, "audit.observed_dispositions")
            .map_err(|error| note_config_error("project", error))?;
        for disposition in &audit.observed_dispositions {
            check_identity(disposition, "audit.observed_dispositions[]")
                .map_err(|error| note_config_error("project", error))?;
        }
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
    hasher.update(b"eliot.backup.config-projection.v2\0");
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
/// [`ApprovedGeneration`] installation record.
///
/// Every value below is owner-issued and owner-validated. The configuration
/// digest is the candidate configuration digest and the build digests are the
/// eight approved artifact digests in manifest order, all shape-enforced by
/// [`ApprovedGeneration::validate`] before extraction. The generation handle is
/// the owner-issued generation identity text, never a caller-chosen string, and
/// [`ApprovedBuildBinding::authority_generation`] is the owner-issued numeric
/// authority generation of the same record, never a caller-chosen number.
///
/// The lease reference, the installation identity, the purge-ledger revision and
/// the target build/profile comparison itself stay outside this record: the
/// first three are refused by [`project_backup_config_owner_bound`] because no
/// owner here issues them, and the last is compared in
/// `crate::backup_preparation::DelegatedPreparation::prepare` against
/// [`ApprovedBuildBinding::generation_handle`] and
/// [`ApprovedBuildBinding::approved_profile`], the two owner-issued names a
/// presented target may equal.
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
/// Fails closed with [`ProjectionError::StaleEvidence`] naming
/// `approved_generation` when the record is not active or its owner
/// validation rejects it. Owner error internals are never echoed: a record
/// that fails owner validation cannot be treated as current authority.
///
/// Owner validation is also what makes the numeric extraction sound: it rejects
/// a record whose manifest runtime launch descriptor disagrees with the
/// activation approval about the authority generation, so
/// [`ApprovedBuildBinding::authority_generation`] can only ever be read off a
/// record whose manifest and approval agree on it. The profile token is read
/// through the owner type's own serialization and fails closed rather than
/// falling back to a local spelling.
pub fn bind_approved_build(
    approved: &ApprovedGeneration,
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
/// Shapes and bounds are checked exactly as in [`project_backup_config`], then
/// three presented fields must equal owner-issued ones, each failing with
/// [`ProjectionError::StaleEvidence`] naming the exact field:
///
/// - `generation` must equal [`ApprovedBuildBinding::authority_generation`],
///   the owner-issued numeric authority generation of the approved record;
/// - `manifest_digest` must equal the owner-issued configuration digest;
/// - every presented `build_digests` entry must be one of the owner-issued
///   artifact digests.
///
/// The generation arm runs first among the owner comparisons on purpose: it is
/// the scope every other owner-issued fact belongs to, so a request that mixes
/// one generation's digest into another generation's claim is refused as a
/// generation mismatch rather than as a digest mismatch. The uncorroborable-field
/// refusals above run before all of them, because a value nothing can check is
/// not evidence in any generation.
///
/// # Fields the owner cannot issue are refused, not copied
///
/// Three presented fields have no owner evidence anywhere on this path, so a
/// presented value is refused with
/// [`ProjectionError::OwnerEvidenceUnavailable`] rather than compared against
/// the caller's own value or carried into an owner-issued record:
///
/// - a non-empty `owner_lease_ref` — lease issuance belongs to the #954
///   control contracts, which are open;
/// - a non-zero `purge_ledger_revision` — purge-ledger authority is owned
///   outside Host backup preparation and no owner observed here issues one;
/// - any `audit` note — the note is caller-authored and nothing here compares
///   its digest or observed dispositions to Host state, so binding it would
///   carry unverified disposition claims into an owner-issued receipt.
///
/// Each refusal names the exact owner obligation that is missing. With no claim
/// presented, the record states the absence and the digest binds that absence
/// explicitly, so an absent owner value is as visible as a present one.
///
/// The projection digest binds the owner-issued generation handle, the
/// owner-issued authority generation and the owner-issued configuration digest
/// in addition to the presented fields, so a receipt cannot migrate across
/// authority generations. Its domain separator is `v4`, distinct from
/// [`project_backup_config`]'s `v2` and from this path's own earlier `v3`:
/// `v3` still hashed the caller's lease reference and purge-ledger revision as
/// if they were evidence, and a stored `v3` receipt must not silently match a
/// `v4` digest over the same logical input (I5.27). `CONFIG_PROJECTION_VERSION`
/// is the serialized record schema version, not the digest revision, and does
/// not move: the record shape is unchanged.
///
/// The installation identity stays presented here and is compared by its real
/// owner at `HostComposition::prepare_backup_destination`, not by this
/// function. No secret-typed field exists here.
///
/// This is the production projector. Its caller is
/// `crate::backup_preparation::OwnerEvidence::project_backup_configuration`,
/// reached from `crate::backup_preparation::DelegatedPreparation::prepare` on
/// every delegated preparation; the returned
/// [`BackupConfigProjection::projection_digest`] is what the prepared
/// destination receipt binds.
///
/// The `generation` refusal below is an owner comparison only when `binding`
/// came from [`bind_approved_build`]. `ApprovedBuildBinding` is a plain public
/// struct, so a caller that constructs one directly supplies the value the
/// refusal is measured against; on that path the arm degrades to a shape guard.
/// The one production caller obtains its binding from `bind_approved_build`
/// over an owner-validated [`ApprovedGeneration`], and
/// `OwnerEvidence` has all-private fields, so the delegated path is the owner
/// comparison this arm is written for.
#[allow(
    clippy::too_many_lines,
    reason = "the shape/staleness gate set stays in one boundary so no refusal observation can be skipped between neighbors"
)]
pub fn project_backup_config_owner_bound(
    request: &BackupConfigRequest,
    binding: &ApprovedBuildBinding,
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
    // Uncorroborable presented claims, refused before any owner comparison runs.
    // Each names the exact owner obligation that is missing. Nothing here can
    // compare these three against owner evidence, so the alternatives would be a
    // self-comparison against the caller's own value or an owner field invented
    // only to make a check pass; both are refused by design.
    if !request.owner_lease_ref.is_empty() {
        return Err(note_config_error(
            "project_owner_bound",
            ProjectionError::OwnerEvidenceUnavailable {
                field: "owner_lease_ref",
                obligation: "an owner-issued lease reference must come from the #954 caller-control \
                     contracts, which are open; no installation record observed here issues one",
            },
        ));
    }
    if request.purge_ledger_revision != 0 {
        return Err(note_config_error(
            "project_owner_bound",
            ProjectionError::OwnerEvidenceUnavailable {
                field: "purge_ledger_revision",
                obligation: "the purge-ledger owner must issue the revision observed by Host backup \
                     preparation; no registry, approved-generation, commit-fence or host-state \
                     record observed here carries one",
            },
        ));
    }
    if request.audit.is_some() {
        return Err(note_config_error(
            "project_owner_bound",
            ProjectionError::OwnerEvidenceUnavailable {
                field: "audit",
                obligation: "a HostStateAuditFence must be issued or corroborated by the owner that \
                     observed the installation lineage; a caller-authored note is not evidence \
                     and I5.13 keeps that fence optional",
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
    // The three refusals above run before any digest is computed: nothing that
    // reaches this point carries a caller-declared lease reference, purge-ledger
    // revision or audit note, so none of them can reach the record below.
    let mut hasher = Sha256::new();
    // v4 on this path only: v3 still hashed the presented lease reference and
    // purge-ledger revision as if they were evidence, so a stored v3 receipt
    // must not silently match a v4 digest over the same logical request. Naming
    // the revision in the domain separator is what makes that mismatch legible
    // instead of silent (I5.27). `CONFIG_PROJECTION_VERSION` is the serialized
    // record schema version, not the digest revision, and does not move: the
    // record shape is unchanged. See [`project_backup_config`] for the snapshot
    // variant, whose coverage is unchanged and which stays at v2.
    hasher.update(b"eliot.backup.config-projection.v4\0");
    hasher.update(CONFIG_PROJECTION_VERSION.to_le_bytes());
    hash_field(
        &mut hasher,
        b"installation_id",
        request.installation_id.as_bytes(),
    );
    // The absence is bound explicitly, never an empty caller string that could
    // be read as "an empty lease reference was presented and accepted".
    hash_field(&mut hasher, b"owner_lease_ref", b"absent");
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
    for digest in &request.build_digests {
        hash_field(&mut hasher, b"build_digest", digest.as_bytes());
    }
    hash_field(&mut hasher, b"purge_ledger_revision", b"absent");
    hash_state_fence(&mut hasher, fence)
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    // No audit note can be present here, so this binds the observed absence.
    hash_audit_note(&mut hasher, None);
    let projection_digest = format!("{:x}", hasher.finalize());
    // Observed owner-bound projection only, never authority. Numeric facts
    // come from the produced value; the refused fields carry no observation.
    observe_config_progress(
        "project_owner_bound",
        "projected_owner_bound",
        request.generation,
        0,
        backup_config_count(request.build_digests.len()),
        false,
    );
    Ok(BackupConfigProjection {
        version: CONFIG_PROJECTION_VERSION,
        installation_id: request.installation_id.clone(),
        // Empty and zero by construction: a presented value was refused above.
        owner_lease_ref: String::new(),
        generation: request.generation,
        manifest_digest: binding.config_digest.clone(),
        build_digests: request.build_digests.clone(),
        purge_ledger_revision: 0,
        state_fence: fence.clone(),
        projection_digest,
    })
}
