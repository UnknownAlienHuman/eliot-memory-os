//! Bounded owner-issued configuration evidence projection for backup (issue #958).
//!
//! Pure logical projection over explicitly supplied evidence: owner lease
//! reference, approved generation, manifest/build digests, purge-ledger
//! revision, and the caller-observed [`StateFence`]. No I/O, no registry
//! reads, no secret material. Every digest is shape-checked lowercase hex;
//! every identity is bounded text. Stale or mixed evidence is rejected with
//! the exact field named; nothing is ever silently refreshed.
//!
//! The optional [`AuditFenceNote`] is forensic only: [`describe_audit_fence`]
//! renders a non-authoritative note, and no API converts it into a lease,
//! grant, or current-state assertion.

use eliot_contracts::StateFence;
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

/// Current authority evidence supplied by the caller (`HostComposition` at
/// delegation; fixtures in tests). Compared field-for-field against the
/// request; never refreshed or defaulted here.
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
/// All authority inputs are presented evidence; the projector compares them
/// against [`AuthoritySnapshot`] and never invents currency.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupConfigRequest {
    /// Source installation identity (bounded text).
    pub installation_id: String,
    /// Owner lease reference the requester claims.
    pub owner_lease_ref: String,
    /// Generation the requester claims as approved.
    pub generation: u64,
    /// Config/policy/module manifest digest claimed.
    pub manifest_digest: String,
    /// Approved build digests claimed.
    pub build_digests: Vec<String>,
    /// Purge-ledger revision claimed.
    pub purge_ledger_revision: u64,
    /// Optional forensic audit note; never authority (case 958/3).
    pub audit: Option<AuditFenceNote>,
}

/// Forensic audit note with a typed non-authoritative ceiling (case 958/3).
///
/// Carries a digest plus observed dispositions only. There is deliberately NO
/// constructor, conversion, or method that turns this into a lease, grant,
/// or current-state assertion; [`describe_audit_fence`] renders the note
/// with its ceiling stated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditFenceNote {
    /// Digest of the observed installation lineage/dispositions.
    pub note_digest: String,
    /// Observed dispositions (bounded text each).
    pub observed_dispositions: Vec<String>,
}

/// Bounded owner-issued logical projection of backup configuration evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupConfigProjection {
    /// Projection format version ([`CONFIG_PROJECTION_VERSION`]).
    pub version: u32,
    /// Source installation identity, as verified.
    pub installation_id: String,
    /// Owner lease reference, verified equal to current authority.
    pub owner_lease_ref: String,
    /// Approved generation, verified equal to current authority.
    pub generation: u64,
    /// Manifest digest, verified equal to current authority.
    pub manifest_digest: String,
    /// Build digests, verified equal to current authority.
    pub build_digests: Vec<String>,
    /// Purge-ledger revision, verified equal to current authority.
    pub purge_ledger_revision: u64,
    /// State fence bound at projection time (caller-observed evidence).
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
#[must_use]
pub fn describe_audit_fence(note: &AuditFenceNote) -> String {
    format!(
        "forensic audit note {} (non-authoritative: not a lease, grant, or current-state assertion; dispositions: {})",
        note.note_digest,
        note.observed_dispositions.join(",")
    )
}

/// Projects bounded backup configuration evidence (issue #958, cases 958/1-2, 958/4, 958/16).
///
/// Validates shapes and bounds, then requires field-for-field equality with
/// current authority evidence. Any stale or mixed field fails with
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
/// Every digest below is owner-issued: the configuration digest is the
/// candidate configuration digest and the build digests are the eight
/// approved artifact digests in manifest order, all shape-enforced by
/// [`ApprovedGeneration::validate`] before extraction. The generation handle
/// is the owner-issued generation identity text, never a caller-chosen
/// number: numeric generation, lease, purge, and target build/profile
/// evidence stays caller-presented until #954 control contracts and
/// HostComposition delegation land, and is documented as such at
/// [`project_backup_config_owner_bound`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedBuildBinding {
    /// Owner-issued generation identity handle text.
    pub generation_handle: String,
    /// Owner-issued candidate configuration digest (lowercase hex 64).
    pub config_digest: String,
    /// Owner-issued approved artifact digests in manifest order.
    pub artifact_digests: Vec<String>,
}

/// Binds presented evidence to the exact active approved generation.
///
/// Fails closed with [`ProjectionError::StaleEvidence`] naming
/// `approved_generation` when the record is not active or its owner
/// validation rejects it. Owner error internals are never echoed: a record
/// that fails owner validation cannot be treated as current authority.
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
    let binding = ApprovedBuildBinding {
        generation_handle: manifest.generation.as_str().to_owned(),
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
    };
    // Owner-issued facts only; the count observes the binding, never values.
    observe_bind_progress("bound", backup_config_count(binding.artifact_digests.len()));
    Ok(binding)
}

/// Projects backup configuration evidence against the owner-bound build
/// (issue #958, cases 958/1-2, 958/4, 958/16 with owner binding).
///
/// Shapes and bounds are checked exactly as in [`project_backup_config`].
/// The presented manifest digest must equal the owner-issued configuration
/// digest and every presented build digest must be one of the owner-issued
/// artifact digests; anything else fails with
/// [`ProjectionError::StaleEvidence`] naming the field. The projection
/// digest additionally binds the owner-issued generation handle, so a
/// receipt can never migrate across generations.
///
/// Owner binding covers manifest and builds only. Installation identity,
/// lease reference, numeric generation, purge-ledger revision, and target
/// build/profile stay caller-presented: lease issuance and purge-ledger
/// authority belong to #954 control contracts and HostComposition
/// delegation, which are open. No secret-typed field exists here.
pub fn project_backup_config_owner_bound(
    request: &BackupConfigRequest,
    binding: &ApprovedBuildBinding,
    fence: &StateFence,
) -> Result<BackupConfigProjection, ProjectionError> {
    check_identity(&request.installation_id, "installation_id")
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    check_identity(&request.owner_lease_ref, "owner_lease_ref")
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    check_digest(&request.manifest_digest, "manifest_digest")
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    check_bounded_list(&request.build_digests, "build_digests")
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    for digest in &request.build_digests {
        check_digest(digest, "build_digests[]")
            .map_err(|error| note_config_error("project_owner_bound", error))?;
    }
    if let Some(audit) = &request.audit {
        check_digest(&audit.note_digest, "audit.note_digest")
            .map_err(|error| note_config_error("project_owner_bound", error))?;
        check_bounded_list(&audit.observed_dispositions, "audit.observed_dispositions")
            .map_err(|error| note_config_error("project_owner_bound", error))?;
        for disposition in &audit.observed_dispositions {
            check_identity(disposition, "audit.observed_dispositions[]")
                .map_err(|error| note_config_error("project_owner_bound", error))?;
        }
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
        b"generation_handle",
        binding.generation_handle.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"manifest_digest",
        binding.config_digest.as_bytes(),
    );
    for digest in &request.build_digests {
        hash_field(&mut hasher, b"build_digest", digest.as_bytes());
    }
    hasher.update(b"purge_ledger_revision\0");
    hasher.update(request.purge_ledger_revision.to_le_bytes());
    hash_state_fence(&mut hasher, fence)
        .map_err(|error| note_config_error("project_owner_bound", error))?;
    hash_audit_note(&mut hasher, request.audit.as_ref());
    let projection_digest = format!("{:x}", hasher.finalize());
    // Observed owner-bound projection only, never authority. Numeric facts
    // come from the produced value; the forensic note stays non-authoritative.
    observe_config_progress(
        "project_owner_bound",
        "projected_owner_bound",
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
        manifest_digest: binding.config_digest.clone(),
        build_digests: request.build_digests.clone(),
        purge_ledger_revision: request.purge_ledger_revision,
        state_fence: fence.clone(),
        projection_digest,
    })
}
