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
#[cfg(windows)]
fn capture_identity(path: &Path) -> Result<RootIdentity, PreparationError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle,
    };

    // Directories open for identity reads only with backup semantics.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|error| PreparationError::FilesystemEffect {
            path: path.to_string_lossy().into_owned(),
            reason: format!("cannot open prepared root for identity: {error}"),
        })?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let ok = unsafe {
        // SAFETY: the file handle is live for this statement and `information`
        // is valid zeroed output storage (installer precedent:
        // `file_identity_from_handle_staged`).
        GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &raw mut information)
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(PreparationError::FilesystemEffect {
            path: path.to_string_lossy().into_owned(),
            reason: format!("root identity query failed (win32 {code})"),
        });
    }
    Ok(RootIdentity {
        identity: format!(
            "{}:{}",
            information.dwVolumeSerialNumber,
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow)
        ),
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
