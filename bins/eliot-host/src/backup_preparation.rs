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

use std::path::{Path, PathBuf};

use crate::HostComposition;
use crate::backup_config_projection::{
    ApprovedBuildBinding, ProjectionError, bind_approved_build,
};
use eliot_installation::{
    ApprovedGeneration, ApprovedGenerationRegistry, InstallationProfile, InstallationRoots,
    RedbInstallationRegistry, RuntimeStateRoots,
};
use eliot_platform_windows::{ProtectedRootLease, windows_paths_equal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Preparation format version pinned into digests and receipts.
pub const PREPARATION_VERSION: u32 = 1;
/// Maximum length of one bounded identity string.
pub const MAX_IDENTITY_LEN: usize = 256;
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
    /// Staging parent is the source, nested under it, missing, or not a directory.
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

/// Destination admission: explicit, fully-bound request (issue #958, cases 958/5-7, 958/9).
///
/// Every authority input is presented evidence. `staging_parent` is an
/// explicitly admitted isolated-prep parent directory — never the source, never
/// an arbitrary client path (verified, not trusted).
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
    /// Explicitly admitted staging parent (must exist, be a directory, and not
    /// be or contain the source; reparse-free).
    pub staging_parent: PathBuf,
    /// Approved target build identity (bounded text).
    pub target_build: String,
    /// Approved target profile (bounded text).
    pub target_profile: String,
    /// Generation approved for the destination.
    pub approved_generation: u64,
    /// Live authority generation presented by the caller; must equal approved.
    pub authority_generation: u64,
    /// Config manifest digest the destination must match (hex64).
    pub manifest_digest: String,
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
             target: {}:{}, generation: {}, manifest: {}.., nonce_len: {} }}",
            self.operation_id,
            self.class,
            self.source_installation_id,
            self.target_build,
            self.target_profile,
            self.approved_generation,
            self.manifest_digest.chars().take(16).collect::<String>(),
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

/// Admission digest binding every admitted input (idempotency key).
fn admission_digest(admission: &DestinationAdmission) -> String {
    sha_hex(&[
        b"eliot.backup.destination-admission.v1\0",
        admission.operation_id.as_bytes(),
        b"\0",
        admission.source_installation_id.as_bytes(),
        b"\0",
        admission.staging_parent.to_string_lossy().as_bytes(),
        b"\0",
        admission.target_build.as_bytes(),
        b"\0",
        admission.target_profile.as_bytes(),
        b"\0",
        &admission.approved_generation.to_le_bytes(),
        admission.manifest_digest.as_bytes(),
        admission.authority_nonce.as_bytes(),
        admission.state_fence_digest.as_bytes(),
    ])
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
            identity: format!(
                "{}:{}",
                identity.volume_serial_number, identity.file_index
            ),
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

/// Validates one admission without effects (cases 958/5-7).
fn validate_admission(admission: &DestinationAdmission) -> Result<(), PreparationError> {
    check_identity(&admission.operation_id, "operation_id")?;
    check_identity(&admission.source_installation_id, "source_installation_id")?;
    check_identity(&admission.target_build, "target_build")?;
    check_identity(&admission.target_profile, "target_profile")?;
    check_digest(&admission.manifest_digest, "manifest_digest")?;
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

/// Admits a staging parent: exists, directory, reparse-free, and neither the
/// source root nor nested under it (cases 958/5-6, 958/8).
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
    Ok(canonical_parent)
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
fn conflict_field(intent: &serde_json::Value, admission: &DestinationAdmission) -> &'static str {
    let recorded = intent.get("admission");
    let current = serde_json::to_value(admission).unwrap_or(serde_json::Value::Null);
    for field in [
        "source_installation_id",
        "staging_parent",
        "target_build",
        "target_profile",
        "approved_generation",
        "authority_generation",
        "manifest_digest",
        "authority_nonce",
        "state_fence_digest",
        "class",
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
    })
}

fn destination_from_result(
    operation_id: &str,
    result: &serde_json::Value,
) -> Option<PreparedDestination> {
    Some(PreparedDestination {
        operation_id: operation_id.to_owned(),
        root: PathBuf::from(result.get("root")?.as_str()?),
        root_identity: RootIdentity {
            identity: result.get("root_identity")?.as_str()?.to_owned(),
        },
        destination_id: result.get("destination_id")?.as_str()?.to_owned(),
        destination_epoch: result.get("destination_epoch")?.as_u64()?,
        admission_digest: result.get("admission_digest")?.as_str()?.to_owned(),
    })
}

/// Prepares one isolated destination (issue #958, cases 958/5-7, 958/9, 958/12).
///
/// Order: validate → ledger/journal idempotency (same inputs return the
/// recorded destination; changed inputs conflict by field) → record intent →
/// admit parent → create root → pin identity → record result. The source root
/// is only ever read for comparison, never modified.
pub fn prepare_isolated_destination<J: PreparationJournal>(
    journal: &mut J,
    admission: &DestinationAdmission,
) -> Result<PreparedDestination, PreparationError> {
    validate_admission(admission)?;
    let digest = admission_digest(admission);
    if let Some((intent, result)) = journal.load(&admission.operation_id)? {
        let recorded = intent
            .get("admission_digest")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if recorded != digest {
            return Err(PreparationError::ConflictField {
                field: conflict_field(&intent, admission),
            });
        }
        if let Some(result) = result {
            if let Some(destination) = destination_from_result(&admission.operation_id, &result) {
                let live = capture_identity(&destination.root).map_err(|_| {
                    PreparationError::UnknownState {
                        operation: admission.operation_id.clone(),
                        reason: "recorded root no longer observable; preserved".to_owned(),
                    }
                })?;
                if live != destination.root_identity {
                    return Err(PreparationError::IdentityConflict {
                        operation: admission.operation_id.clone(),
                        recorded: destination.root_identity.identity.clone(),
                        observed: live.identity.clone(),
                    });
                }
                return Ok(destination);
            }
            return Err(PreparationError::UnknownState {
                operation: admission.operation_id.clone(),
                reason: "result record malformed; preserved for inspection".to_owned(),
            });
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
            return Err(PreparationError::UnknownState {
                operation: admission.operation_id.clone(),
                reason: "intent without verifiable result and root present; reconcile before retry"
                    .to_owned(),
            });
        }
    }
    let canonical_parent = admit_staging_parent(admission)?;
    let destination_id = derive_destination_id(&admission.operation_id, &admission.authority_nonce);
    let root = canonical_parent.join(format!("dest-{destination_id}"));
    if root.exists() {
        return Err(PreparationError::ForeignContent {
            path: root.to_string_lossy().into_owned(),
        });
    }
    journal.record_intent(
        &admission.operation_id,
        &intent_json(admission, &digest, &root),
    )?;
    std::fs::create_dir(&root).map_err(|error| PreparationError::FilesystemEffect {
        path: root.to_string_lossy().into_owned(),
        reason: format!("destination creation failed: {error}"),
    })?;
    let identity = capture_identity(&root)?;
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
    };
    journal.record_result(&admission.operation_id, &result_json(&destination))?;
    Ok(destination)
}

/// Reconciles one operation without duplicating effects (cases 958/12, 958/14).
///
/// Absent (no intent, or intent whose root never materialized) → `Absent` and
/// retry may proceed. Intent + verifiable result → `Current` (same destination,
/// no second creation). Anything else → `Uncertain`: preserved as-is, never
/// deleted, never blindly retried.
pub fn reconcile_preparation<J: PreparationJournal>(
    journal: &J,
    operation_id: &str,
) -> Result<ReconcileDisposition, PreparationError> {
    check_identity(operation_id, "operation_id")?;
    // Intent proves the operation was admitted; its digest binds the inputs.
    let Some((intent, result)) = journal.load(operation_id)? else {
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
            return Ok(ReconcileDisposition::Absent);
        }
        return Ok(ReconcileDisposition::Uncertain {
            reason: "intent recorded without result and root present; effects unverified"
                .to_owned(),
        });
    };
    let Some(destination) = destination_from_result(operation_id, &result) else {
        return Ok(ReconcileDisposition::Uncertain {
            reason: "result record malformed; preserved for inspection".to_owned(),
        });
    };
    match capture_identity(&destination.root) {
        Ok(live) if live == destination.root_identity => {
            Ok(ReconcileDisposition::Current(destination))
        }
        Ok(live) => Ok(ReconcileDisposition::Uncertain {
            reason: format!(
                "root identity changed (recorded {} != observed {})",
                destination.root_identity.identity, live.identity
            ),
        }),
        Err(_) => Ok(ReconcileDisposition::Uncertain {
            reason: "recorded root no longer observable".to_owned(),
        }),
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
    match reconcile_preparation(journal, operation_id)? {
        ReconcileDisposition::Current(destination) => {
            let mut envelope = result_json(&destination);
            envelope["status"] = serde_json::Value::String("cancelled".to_owned());
            envelope["prior_receipt"] = result_json(&destination);
            journal.record_result(operation_id, &envelope)?;
            Ok(())
        }
        ReconcileDisposition::Absent => Err(PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason: "nothing recorded; nothing to cancel".to_owned(),
        }),
        ReconcileDisposition::Uncertain { reason } => Err(PreparationError::UnknownState {
            operation: operation_id.to_owned(),
            reason: format!("reconcile first: {reason}"),
        }),
    }
}

/// Cleans up owned unactivated destinations (case 958/15).
///
/// Removes ONLY roots whose recorded identity re-verifies against the live
/// root (proving this lane created and still owns them) and whose journal
/// shows no launched/effect state. Anything uncertain, foreign, mismatched,
/// or source-related is preserved with its reason. Never deletes by bare
/// path name: every removal is keyed by operation id through the journal.
pub fn cleanup_preparations<J: PreparationJournal>(
    journal: &J,
    operation_ids: &[String],
) -> Result<CleanupReport, PreparationError> {
    let mut report = CleanupReport::default();
    for operation_id in operation_ids {
        match reconcile_preparation(journal, operation_id)? {
            ReconcileDisposition::Current(destination) => {
                match std::fs::remove_dir_all(&destination.root) {
                    Ok(()) => report.removed.push(operation_id.clone()),
                    Err(error) => report.preserved.push((
                        operation_id.clone(),
                        format!("removal failed, preserved: {error}"),
                    )),
                }
            }
            ReconcileDisposition::Absent => {
                report
                    .preserved
                    .push((operation_id.clone(), "nothing recorded".to_owned()));
            }
            ReconcileDisposition::Uncertain { reason } => {
                report.preserved.push((operation_id.clone(), reason));
            }
        }
    }
    Ok(report)
}

/// Resolves the source installation root from owner-issued installation
/// roots: validates the root set for the Host profile, then returns the
/// canonical durable-data root that preparation must treat as the active
/// source. The source is observed read-only for comparison and never
/// modified.
///
/// Fail-closed with static reasons: a root-set violation yields
/// [`PreparationError::InvalidRequest`], a non-directory yields
/// [`PreparationError::ArbitraryPath`], and an unresolvable root yields
/// [`PreparationError::FilesystemEffect`]. Owner error internals are never
/// echoed. Staging admission, generation/lease authority, and journal
/// binding stay with [`prepare_isolated_destination`] and HostComposition
/// delegation.
pub fn resolve_source_root(
    roots: &InstallationRoots,
    profile: InstallationProfile,
) -> Result<PathBuf, PreparationError> {
    roots
        .validate(profile)
        .map_err(|_| PreparationError::InvalidRequest {
            field: "source_roots",
            reason: "owner installation roots violate the Host profile".to_owned(),
        })?;
    let canonical = std::fs::canonicalize(&roots.durable_data).map_err(|error| {
        PreparationError::FilesystemEffect {
            path: roots.durable_data.clone(),
            reason: format!("cannot canonicalize owner durable-data root: {error}"),
        }
    })?;
    if !canonical.is_dir() {
        return Err(PreparationError::ArbitraryPath {
            reason: "owner durable-data root is not a directory".to_owned(),
        });
    }
    Ok(canonical)
}

/// Caller-presented preparation fields for one delegated operation.
///
/// The configuration manifest digest is deliberately absent: the manifest
/// always comes from the owner-bound [`ApprovedBuildBinding`], so a caller
/// can never assert a competing manifest. Presented build digests are
/// subset-checked against the owner artifact set at preparation time.
/// Numeric generation, lease, purge, and target build/profile stay
/// caller-presented pending #954 control contracts and HostComposition
/// delegation, which authenticate the caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PresentedPreparationRequest {
    /// Operation identity (bounded text, unique per preparation).
    pub operation_id: String,
    /// Closed preparation class.
    pub class: PreparationClass,
    /// Source installation identity (bounded text).
    pub source_installation_id: String,
    /// Explicitly admitted staging parent (verified, never trusted).
    pub staging_parent: PathBuf,
    /// Approved target build identity (bounded text).
    pub target_build: String,
    /// Approved target profile (bounded text).
    pub target_profile: String,
    /// Generation approved for the destination (presented).
    pub approved_generation: u64,
    /// Live authority generation presented by the caller (presented).
    pub authority_generation: u64,
    /// Presented build digests, each verified against owner artifacts.
    pub build_digests: Vec<String>,
    /// Opaque owner-issued entropy for fresh identity derivation.
    pub authority_nonce: String,
    /// Caller-observed state fence bound into the receipt.
    pub state_fence_digest: String,
}

/// HostComposition-side delegation handle for isolated destination
/// preparation (issue #958).
///
/// This is the exact sink interface the HostComposition owner binds: it owns
/// the installation/Host journal sink (`J`), takes the owner records it
/// holds ([`ApprovedGeneration`], [`InstallationRoots`]) plus one presented
/// request, and runs the full owner-bound preparation lifecycle. Caller
/// authentication stays parameterized pending #954; every owner or
/// presented-evidence failure maps to a static fail-closed
/// [`PreparationError`] without echoing owner internals.
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
    /// Order: bind the active approved generation, resolve the owner source
    /// root, subset-check presented builds against owner artifacts, admit,
    /// then prepare idempotently. The manifest digest is always the owner
    /// configuration digest; generation/lease/purge/target evidence stays
    /// presented as documented at [`PresentedPreparationRequest`].
    pub fn prepare(
        &mut self,
        approved: &ApprovedGeneration,
        roots: &InstallationRoots,
        profile: InstallationProfile,
        request: &PresentedPreparationRequest,
    ) -> Result<PreparedDestination, PreparationError> {
        let binding: ApprovedBuildBinding =
            bind_approved_build(approved).map_err(projection_to_preparation)?;
        let source_root = resolve_source_root(roots, profile)?;
        prepare_admitted(&mut self.journal, &binding, source_root, request)
    }

    /// Reconciles one operation without duplicating effects.
    pub fn reconcile(
        &self,
        operation_id: &str,
    ) -> Result<ReconcileDisposition, PreparationError> {
        reconcile_preparation(&self.journal, operation_id)
    }

    /// Cancels one prepared operation, preserving its prior receipt.
    pub fn cancel(&mut self, operation_id: &str) -> Result<(), PreparationError> {
        cancel_preparation(&mut self.journal, operation_id)
    }

    /// Cleans up owned unactivated destinations, preserving unknowns.
    pub fn cleanup(
        &self,
        operation_ids: &[String],
    ) -> Result<CleanupReport, PreparationError> {
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

/// Read-only owner registry evidence for one protected Host root.
///
/// This is the delegation-time read bundle HostComposition holds while
/// preparing: the installation registry projection is inspected through the
/// existing read-only owner query
/// ([`RedbInstallationRegistry::inspect_existing_at`], A13.9 short-lived
/// poll read — no writer is acquired and no registry mutation is possible
/// here), so the active generation served below is registry-committed owner
/// state, never a caller assertion. The bundle owns the projection; every
/// accessor borrows from it, so evidence cannot outlive its read.
pub struct OwnerRegistryEvidence {
    registry: ApprovedGenerationRegistry,
}

impl OwnerRegistryEvidence {
    /// Inspects the committed installation registry below one protected Host
    /// root without acquiring a writer.
    ///
    /// Fail-closed: an unprotectable root yields
    /// [`PreparationError::FilesystemEffect`], a withheld inspection yields
    /// [`PreparationError::InvalidRequest`] naming `source_registry`, and an
    /// absent registry file yields the same with a distinct reason — absence
    /// of proof is never treated as proof of absence.
    pub fn inspect(host_state_root: &Path) -> Result<Self, PreparationError> {
        let lease = ProtectedRootLease::open_existing(host_state_root).map_err(|error| {
            PreparationError::FilesystemEffect {
                path: host_state_root.to_string_lossy().into_owned(),
                reason: format!("protected source root unavailable: {error}"),
            }
        })?;
        let registry =
            RedbInstallationRegistry::inspect_existing_at(lease).map_err(|_| {
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
        Ok(Self { registry })
    }

    /// Returns the currently active approved generation, if the registry
    /// carries a committed active record.
    ///
    /// `None` means no active generation is committed — callers withhold
    /// preparation rather than substituting any other record.
    pub fn active_generation(&self) -> Option<&ApprovedGeneration> {
        self.registry.active()
    }

    /// Binds the active generation to owner-verified build facts.
    ///
    /// Combines [`OwnerRegistryEvidence::active_generation`] with
    /// [`bind_approved_build`]: absent, inactive, or owner-invalid records
    /// fail closed before any destination effect.
    pub fn approved_binding(&self) -> Result<ApprovedBuildBinding, PreparationError> {
        let Some(approved) = self.active_generation() else {
            return Err(PreparationError::InvalidRequest {
                field: "approved_generation",
                reason: "no active approved generation committed".to_owned(),
            });
        };
        bind_approved_build(approved).map_err(projection_to_preparation)
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
}

/// Verifies one staging parent against the protected-root owner.
///
/// Opens the existing protected-root lease (containment-checked,
/// identity-pinned) and returns the re-verified canonical path. This is the
/// production-only lease gate: fixture or explicitly admitted non-protected
/// parents bypass it by not calling it, while [`prepare_isolated_destination`]
/// always re-applies the structural admission checks. Fail-closed with
/// static reasons; lease error internals are echoed only inside
/// [`PreparationError::FilesystemEffect`], matching file precedent.
pub fn verify_staging_parent_lease(parent: &Path) -> Result<PathBuf, PreparationError> {
    let lease = ProtectedRootLease::open_existing(parent).map_err(|error| {
        PreparationError::FilesystemEffect {
            path: parent.to_string_lossy().into_owned(),
            reason: format!("staging parent is not a protected root: {error}"),
        }
    })?;
    lease.canonical_path().map_err(|error| {
        PreparationError::FilesystemEffect {
            path: parent.to_string_lossy().into_owned(),
            reason: format!("staging parent identity changed during admission: {error}"),
        }
    })
}

/// Owner-bound manifest roots for one inspected registry (issue #958).
///
/// Unlike [`InstallationRoots`] (the root-composition contract with no live
/// readers), these roots come from the registry-committed active candidate
/// manifest: `ApprovedGeneration.manifest.runtime_launch.runtime_state_roots`.
/// The manifest digest is the owner `config_digest`; the registry revision
/// binds "current" for movement detection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestRootsBinding {
    /// Manifest-bound runtime roots of the active generation.
    pub roots: RuntimeStateRoots,
    /// Owner configuration digest of the active manifest.
    pub manifest_digest: String,
    /// Registry CAS revision observed at inspection time.
    pub registry_revision: u64,
}

/// Resolves the source installation root from manifest-bound owner roots.
///
/// This is the live preparation path: it validates the owner
/// [`RuntimeStateRoots`] (profile binding, topology, roots digest) and
/// returns the canonical durable installation root as the read-only source.
/// The legacy [`resolve_source_root`] ([`InstallationRoots`]) seam stays for
/// the existing fixture-driven proof; production delegation uses this
/// function exclusively.
pub fn resolve_manifest_source_root(
    roots: &RuntimeStateRoots,
) -> Result<PathBuf, PreparationError> {
    roots
        .validate()
        .map_err(|_| PreparationError::InvalidRequest {
            field: "manifest_roots",
            reason: "owner runtime roots violate the installation profile".to_owned(),
        })?;
    let canonical =
        std::fs::canonicalize(roots.installation_root.as_str()).map_err(|error| {
            PreparationError::FilesystemEffect {
                path: roots.installation_root.as_str().to_owned(),
                reason: format!("cannot canonicalize owner installation root: {error}"),
            }
        })?;
    if !canonical.is_dir() {
        return Err(PreparationError::ArbitraryPath {
            reason: "owner installation root is not a directory".to_owned(),
        });
    }
    Ok(canonical)
}

impl OwnerRegistryEvidence {
    /// Binds the active manifest roots against the retained caller root.
    ///
    /// Mirrors the `load_manifest_bound_canary_binding` owner pattern
    /// (`bins/eliot/src/main.rs`): the active manifest is owner-validated,
    /// its roots are owner-validated, and the manifest's
    /// `runtime_state_roots.host_state_root` must equal the retained caller
    /// root (OS-identity comparison, never bare path text). A foreign,
    /// stale, or missing manifest withholds preparation; it never falls
    /// back to caller-supplied roots.
    pub fn manifest_roots_against(
        &self,
        host_state_root: &Path,
    ) -> Result<ManifestRootsBinding, PreparationError> {
        let Some(active) = self.active_generation() else {
            return Err(PreparationError::InvalidRequest {
                field: "approved_generation",
                reason: "no active approved generation committed".to_owned(),
            });
        };
        let manifest = active.manifest.clone();
        manifest
            .validate()
            .map_err(|_| PreparationError::InvalidRequest {
                field: "manifest",
                reason: "active candidate manifest is not owner-valid".to_owned(),
            })?;
        let roots = manifest.runtime_launch.runtime_state_roots.clone();
        roots
            .validate()
            .map_err(|_| PreparationError::InvalidRequest {
                field: "manifest_roots",
                reason: "active manifest roots are not owner-valid".to_owned(),
            })?;
        let retained = ProtectedRootLease::open_existing(host_state_root).map_err(|error| {
            PreparationError::FilesystemEffect {
                path: host_state_root.to_string_lossy().into_owned(),
                reason: format!("protected source root unavailable: {error}"),
            }
        })?;
        let canonical = retained.canonical_path().map_err(|error| {
            PreparationError::FilesystemEffect {
                path: host_state_root.to_string_lossy().into_owned(),
                reason: format!("source root identity changed during binding: {error}"),
            }
        })?;
        if !windows_paths_equal(Path::new(roots.host_state_root.as_str()), &canonical) {
            return Err(PreparationError::InvalidRequest {
                field: "manifest_roots",
                reason: "active manifest Host state root does not equal the retained caller root"
                    .to_owned(),
            });
        }
        Ok(ManifestRootsBinding {
            roots,
            manifest_digest: manifest.config_digest.as_str().to_owned(),
            registry_revision: self.revision(),
        })
    }
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
            reason: "authenticated caller control pending #954; unauthenticated preparation refused"
                .to_owned(),
        })
    }
}

/// Durable preparation journal directory name under the Host state root.
pub const PREPARATION_JOURNAL_SUBDIR: &str = "backup-preparation-journal";
/// Maximum bytes of one journal record (intent or result).
pub const MAX_JOURNAL_RECORD_BYTES: u64 = 1 << 20;
/// Maximum journal files swept by one listing.
pub const MAX_JOURNAL_SWEEP_ENTRIES: usize = 4096;

/// Durable file-backed [`PreparationJournal`] sink owned by HostComposition.
///
/// Lives under the identity-pinned Host state root
/// (`PREPARATION_JOURNAL_SUBDIR`): one `<sha(operation)>.intent.json` and one
/// `<sha(operation)>.result.json` per operation, written atomically through a
/// temp file plus rename. Intent is recorded before effects, result after;
/// load-before-act gives the same idempotency as the tested in-memory sink.
/// Filenames are operation-digest derived so no caller text becomes a path.
/// This sink survives restarts; the semantic `HostStateJournal` is untouched
/// (backup intents are not canonical transitions).
#[derive(Clone, Debug)]
pub struct DirPreparationJournal {
    dir: PathBuf,
    identity: String,
}

fn journal_record_path(dir: &Path, operation_id: &str, kind: &str) -> PathBuf {
    dir.join(format!(
        "{}-{}.json",
        kind,
        sha_hex(&[operation_id.as_bytes()])
    ))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, PreparationError> {
    let metadata =
        std::fs::metadata(path).map_err(|error| PreparationError::JournalFault(format!(
            "journal record unreadable {}: {error}",
            path.to_string_lossy()
        )))?;
    if metadata.len() > MAX_JOURNAL_RECORD_BYTES {
        return Err(PreparationError::JournalFault(format!(
            "journal record oversize {}",
            path.to_string_lossy()
        )));
    }
    std::fs::read(path).map_err(|error| PreparationError::JournalFault(format!(
        "journal record unreadable {}: {error}",
        path.to_string_lossy()
    )))
}

impl DirPreparationJournal {
    /// Opens (creating) the durable journal below one protected Host root.
    ///
    /// Pins the root OS identity first, then the journal directory identity;
    /// both are re-verifiable by the caller through [`Self::identity`].
    /// Fail-closed with static reasons; no registry or journal writes occur
    /// here beyond creating the owned directory.
    pub fn open_at(host_state_root: &Path) -> Result<Self, PreparationError> {
        let lease = ProtectedRootLease::open_existing(host_state_root).map_err(|error| {
            PreparationError::FilesystemEffect {
                path: host_state_root.to_string_lossy().into_owned(),
                reason: format!("protected Host root unavailable: {error}"),
            }
        })?;
        let canonical = lease.canonical_path().map_err(|error| {
            PreparationError::FilesystemEffect {
                path: host_state_root.to_string_lossy().into_owned(),
                reason: format!("Host root identity changed during journal open: {error}"),
            }
        })?;
        let dir = canonical.join(PREPARATION_JOURNAL_SUBDIR);
        std::fs::create_dir_all(&dir).map_err(|error| PreparationError::FilesystemEffect {
            path: dir.to_string_lossy().into_owned(),
            reason: format!("preparation journal directory unavailable: {error}"),
        })?;
        let identity = capture_identity(&dir).map_err(|error| PreparationError::JournalFault(
            format!("journal identity unobservable: {error:?}"),
        ))?;
        Ok(Self {
            dir,
            identity: identity.identity,
        })
    }

    /// Pinned OS identity of the journal directory, captured at open.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    fn store_record(
        &self,
        operation_id: &str,
        kind: &str,
        value: &serde_json::Value,
    ) -> Result<(), PreparationError> {
        check_identity(operation_id, "operation_id")?;
        let bytes = serde_json::to_vec(value).map_err(|error| {
            PreparationError::JournalFault(format!("journal record unserializable: {error}"))
        })?;
        if bytes.len() as u64 > MAX_JOURNAL_RECORD_BYTES {
            return Err(PreparationError::JournalFault(
                "journal record oversize".to_owned(),
            ));
        }
        let target = journal_record_path(&self.dir, operation_id, kind);
        let temp = target.with_extension(format!(
            "tmp-{}",
            std::process::id()
        ));
        std::fs::write(&temp, &bytes).map_err(|error| PreparationError::JournalFault(format!(
            "journal staging write failed {}: {error}",
            temp.to_string_lossy()
        )))?;
        std::fs::rename(&temp, &target).map_err(|error| {
            let _ = std::fs::remove_file(&temp);
            PreparationError::JournalFault(format!(
                "journal commit failed {}: {error}",
                target.to_string_lossy()
            ))
        })?;
        Ok(())
    }
}

impl PreparationJournal for DirPreparationJournal {
    fn record_intent(
        &mut self,
        operation_id: &str,
        intent: &serde_json::Value,
    ) -> Result<(), PreparationError> {
        self.store_record(operation_id, "intent", intent)
    }

    fn record_result(
        &mut self,
        operation_id: &str,
        result: &serde_json::Value,
    ) -> Result<(), PreparationError> {
        self.store_record(operation_id, "result", result)
    }

    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<(serde_json::Value, Option<serde_json::Value>)>, PreparationError> {
        check_identity(operation_id, "operation_id")?;
        let intent_path = journal_record_path(&self.dir, operation_id, "intent");
        if !intent_path.exists() {
            return Ok(None);
        }
        let intent: serde_json::Value =
            serde_json::from_slice(&read_bounded(&intent_path)?).map_err(|error| {
                PreparationError::JournalFault(format!(
                    "journal intent malformed {}: {error}",
                    intent_path.to_string_lossy()
                ))
            })?;
        let result_path = journal_record_path(&self.dir, operation_id, "result");
        let result = if result_path.exists() {
            Some(
                serde_json::from_slice(&read_bounded(&result_path)?).map_err(|error| {
                    PreparationError::JournalFault(format!(
                        "journal result malformed {}: {error}",
                        result_path.to_string_lossy()
                    ))
                })?,
            )
        } else {
            None
        };
        Ok(Some((intent, result)))
    }

    fn list_operations(&self) -> Result<Vec<String>, PreparationError> {
        let mut operations = Vec::new();
        let entries =
            std::fs::read_dir(&self.dir).map_err(|error| PreparationError::JournalFault(format!(
                "journal sweep failed {}: {error}",
                self.dir.to_string_lossy()
            )))?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                PreparationError::JournalFault(format!("journal sweep failed: {error}"))
            })?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("intent-") || !name.ends_with(".json") {
                continue;
            }
            let intent: serde_json::Value =
                serde_json::from_slice(&read_bounded(&entry.path())?).map_err(|error| {
                    PreparationError::JournalFault(format!(
                        "journal intent malformed {}: {error}",
                        entry.path().to_string_lossy()
                    ))
                })?;
            if let Some(operation) = intent.get("operation_id").and_then(|v| v.as_str()) {
                operations.push(operation.to_owned());
            }
            if operations.len() >= MAX_JOURNAL_SWEEP_ENTRIES {
                break;
            }
        }
        Ok(operations)
    }
}

impl<J: PreparationJournal> DelegatedPreparation<J> {
    /// Prepares one isolated destination from registry-committed manifest
    /// roots plus one presented request (production path).
    ///
    /// The manifest digest is always the owner `config_digest` from
    /// [`ManifestRootsBinding`]; it is cross-checked against the active
    /// generation binding so two owner derivations cannot disagree silently.
    /// The source root comes from [`resolve_manifest_source_root`], never
    /// from caller text. Generation/lease/purge/target evidence stays
    /// presented pending #954, exactly as in [`DelegatedPreparation::prepare`].
    pub fn prepare_from_evidence(
        &mut self,
        evidence: &OwnerRegistryEvidence,
        manifest: &ManifestRootsBinding,
        request: &PresentedPreparationRequest,
    ) -> Result<PreparedDestination, PreparationError> {
        let binding = evidence.approved_binding()?;
        if binding.config_digest != manifest.manifest_digest {
            return Err(PreparationError::InvalidRequest {
                field: "manifest",
                reason: "active generation binding disagrees with manifest roots binding"
                    .to_owned(),
            });
        }
        let source_root = resolve_manifest_source_root(&manifest.roots)?;
        prepare_admitted(&mut self.journal, &binding, source_root, request)
    }
}

/// Shared admission tail: subset-check presented builds against owner
/// artifacts, bind the owner manifest digest into the admission, and prepare
/// idempotently through the journal.
fn prepare_admitted<J: PreparationJournal>(
    journal: &mut J,
    binding: &ApprovedBuildBinding,
    source_root: PathBuf,
    request: &PresentedPreparationRequest,
) -> Result<PreparedDestination, PreparationError> {
    for digest in &request.build_digests {
        check_digest(digest, "build_digests")?;
        if !binding
            .artifact_digests
            .iter()
            .any(|artifact| artifact == digest)
        {
            return Err(PreparationError::InvalidRequest {
                field: "build_digests",
                reason: "build digest is not an owner-approved artifact".to_owned(),
            });
        }
    }
    let admission = DestinationAdmission {
        operation_id: request.operation_id.clone(),
        class: request.class,
        source_installation_id: request.source_installation_id.clone(),
        source_root,
        staging_parent: request.staging_parent.clone(),
        target_build: request.target_build.clone(),
        target_profile: request.target_profile.clone(),
        approved_generation: request.approved_generation,
        authority_generation: request.authority_generation,
        manifest_digest: binding.config_digest.clone(),
        authority_nonce: request.authority_nonce.clone(),
        state_fence_digest: request.state_fence_digest.clone(),
    };
    prepare_isolated_destination(journal, &admission)
}

/// HostComposition live call path for isolated backup preparation.
///
/// Binds, in order: caller shapes → durable journal below the retained Host
/// root → read-only registry evidence → manifest roots bound against the
/// retained root → cached-registry movement check → caller authentication
/// (fail-closed pending #954) → owner-bound preparation. Every failure is a
/// static [`PreparationError`]; owner internals are never echoed and no
/// destination effect precedes authentication.
impl HostComposition {
    /// Prepares one isolated backup destination through real owner authority.
    pub fn prepare_isolated_backup_destination(
        &mut self,
        caller: &BackupCallerAuth,
        request: &PresentedPreparationRequest,
    ) -> Result<PreparedDestination, PreparationError> {
        caller.check_shapes()?;
        let journal = DirPreparationJournal::open_at(&self.registry_host_root)?;
        let evidence = OwnerRegistryEvidence::inspect(&self.registry_host_root)?;
        if self.registry.revision() != evidence.revision() {
            return Err(PreparationError::InvalidRequest {
                field: "source_registry",
                reason: "installation registry moved during delegation; retry from a fresh read"
                    .to_owned(),
            });
        }
        let manifest = evidence.manifest_roots_against(&self.registry_host_root)?;
        caller.authenticate()?;
        let mut delegation = DelegatedPreparation::new(journal);
        delegation.prepare_from_evidence(&evidence, &manifest, request)
    }
}
