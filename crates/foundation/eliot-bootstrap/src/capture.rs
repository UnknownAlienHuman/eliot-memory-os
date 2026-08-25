//! Narrow D0 capture adapters for the pure bootstrap compilers.
//!
//! The compiler in `lib.rs` remains pure.  This module is the intentionally
//! small execution boundary used by `eliot system snapshot`: it takes an
//! explicit repository root, reads only Git evidence from that root, and
//! supplies unavailable runtime/store/integration domains as attributed
//! observations rather than inventing support.

#![forbid(unsafe_code)]

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CurrentSystemEvidenceCompiler, CurrentSystemEvidenceSnapshot, CurrentSystemEvidenceSource,
    EvidenceEvaluation, EvidenceRecord, NormativePair, SourceProjection,
};

const SNAPSHOT_TEMP_CREATE_ATTEMPTS: usize = 128;
static SNAPSHOT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Returns the normative pair used by the current Architecture 4.5 /
/// Implementation 0.29 working line. These are identities, not completion
/// evidence.
pub fn current_normative_pair() -> NormativePair {
    NormativePair {
        architecture_sha256: "58e71a2bdb10925c63d85a708ed768aee8617bed0fb52eb044478ec20ab439d8"
            .to_owned(),
        implementation_sha256: "c216fb7f6fdbc62d108c748be6f61ca7ef9e5d24e5bb13af2677c31a58460c0b"
            .to_owned(),
    }
}

/// Immutable receipt proving which snapshot was emitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotExecutionReceipt {
    /// Receipt schema identity.
    pub schema_version: String,
    /// Snapshot digest covered by this receipt.
    pub snapshot_sha256: String,
    /// Canonical repository root used for Git capture.
    pub repository_root: String,
    /// Git source head captured from the explicit root.
    pub source_head: String,
    /// Dirty-tree binding, when the worktree was not clean.
    pub dirty_delta_artifact_ref: Option<String>,
    /// Content digest of this receipt with this field empty.
    pub receipt_sha256: String,
}

impl SnapshotExecutionReceipt {
    fn new(snapshot: &CurrentSystemEvidenceSnapshot) -> Result<Self, CaptureError> {
        let mut receipt = Self {
            schema_version: "eliot-current-system-evidence-receipt-v2".to_owned(),
            snapshot_sha256: snapshot.snapshot_sha256.clone(),
            repository_root: snapshot.selected_repository_root.clone(),
            source_head: snapshot.selected_source_head.clone(),
            dirty_delta_artifact_ref: snapshot.dirty_delta_artifact_ref.clone(),
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = sha256_hex(
            &canonical_json_bytes(&receipt)
                .map_err(|error| CaptureError::Serialization(error.to_string()))?,
        );
        Ok(receipt)
    }

    fn validate(&self, snapshot: &CurrentSystemEvidenceSnapshot) -> Result<(), CaptureError> {
        if self.snapshot_sha256 != snapshot.snapshot_sha256
            || self.repository_root != snapshot.selected_repository_root
            || self.source_head != snapshot.selected_source_head
            || self.dirty_delta_artifact_ref != snapshot.dirty_delta_artifact_ref
        {
            return Err(CaptureError::ReceiptMismatch);
        }
        let mut unsigned = self.clone();
        unsigned.receipt_sha256.clear();
        if self.receipt_sha256
            != sha256_hex(
                &canonical_json_bytes(&unsigned)
                    .map_err(|error| CaptureError::Serialization(error.to_string()))?,
            )
        {
            return Err(CaptureError::ReceiptDigestMismatch);
        }
        Ok(())
    }
}

/// JSON artifact emitted by `eliot system snapshot`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotExecutionArtifact {
    /// Immutable source/runtime/data snapshot.
    pub snapshot: CurrentSystemEvidenceSnapshot,
    /// Receipt bound to the snapshot digest and source identity.
    pub receipt: SnapshotExecutionReceipt,
}

impl SnapshotExecutionArtifact {
    /// Validates the snapshot and its receipt binding.
    pub fn validate(&self) -> Result<(), CaptureError> {
        self.snapshot
            .validate()
            .map_err(|error| CaptureError::SnapshotValidation(error.to_string()))?;
        self.receipt.validate(&self.snapshot)
    }
}

/// Capture failures at the narrow filesystem/Git boundary.
#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("repository root must be an absolute path: {0}")]
    RepositoryRootNotAbsolute(PathBuf),
    #[error("repository root does not exist: {0}")]
    RepositoryRootMissing(PathBuf),
    #[error("repository root is not the Git root: requested {requested}, discovered {discovered}")]
    RepositoryRootMismatch {
        requested: PathBuf,
        discovered: PathBuf,
    },
    #[error("snapshot output must be an absolute path: {0}")]
    OutputPathNotAbsolute(PathBuf),
    #[error("git command failed ({command}): {detail}")]
    Git { command: String, detail: String },
    #[error("capture I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("snapshot validation failed: {0}")]
    SnapshotValidation(String),
    #[error("snapshot receipt does not match its snapshot")]
    ReceiptMismatch,
    #[error("snapshot receipt digest is invalid")]
    ReceiptDigestMismatch,
    #[error("snapshot serialization failed: {0}")]
    Serialization(String),
}

/// Capture and compile one immutable snapshot from an explicit repository root.
pub fn capture_snapshot(repository_root: &Path) -> Result<SnapshotExecutionArtifact, CaptureError> {
    if !repository_root.is_absolute() {
        return Err(CaptureError::RepositoryRootNotAbsolute(
            repository_root.to_owned(),
        ));
    }
    if !repository_root.is_dir() {
        return Err(CaptureError::RepositoryRootMissing(
            repository_root.to_owned(),
        ));
    }

    let requested_root = fs::canonicalize(repository_root)?;
    let discovered_root = git_output(&requested_root, ["rev-parse", "--show-toplevel"])?;
    let discovered_root = fs::canonicalize(PathBuf::from(discovered_root.trim()))?;
    if !same_path(&requested_root, &discovered_root) {
        return Err(CaptureError::RepositoryRootMismatch {
            requested: requested_root,
            discovered: discovered_root,
        });
    }

    let source_head = git_output(&discovered_root, ["rev-parse", "HEAD"])?
        .trim()
        .to_owned();
    let dirty_delta_artifact_ref = dirty_delta_binding(&discovered_root)?;
    let dirty_delta_value = dirty_delta_artifact_ref
        .as_deref()
        .unwrap_or("CLEAN")
        .to_owned();

    let records = vec![
        evidence(
            "source.repository_root",
            discovered_root.display().to_string(),
            "git:rev-parse",
            EvidenceEvaluation::VerifierBacked,
        ),
        evidence(
            "source.head",
            source_head.clone(),
            "git:rev-parse",
            EvidenceEvaluation::VerifierBacked,
        ),
        evidence(
            "source.dirty_delta",
            dirty_delta_value,
            "git:status+diff",
            EvidenceEvaluation::Screened,
        ),
        evidence(
            "build.status",
            "UNKNOWN".to_owned(),
            "capture:unavailable",
            EvidenceEvaluation::Unknown,
        ),
        evidence(
            "runtime.status",
            "NOT_RUNNING".to_owned(),
            "capture:unavailable",
            EvidenceEvaluation::Unavailable,
        ),
        evidence(
            "store.status",
            "UNKNOWN".to_owned(),
            "capture:unavailable",
            EvidenceEvaluation::Unknown,
        ),
        evidence(
            "integrations.status",
            "UNKNOWN".to_owned(),
            "capture:unavailable",
            EvidenceEvaluation::Unknown,
        ),
    ];
    let source = SourceProjection::complete(
        "current-system",
        source_head.clone(),
        CurrentSystemEvidenceSource {
            normative_pair: current_normative_pair(),
            selected_repository_root: discovered_root.display().to_string(),
            selected_source_head: source_head,
            dirty_delta_artifact_ref,
            external_state_root: "UNKNOWN".to_owned(),
            records,
            unavailable_domains: vec![
                "build".to_owned(),
                "integrations".to_owned(),
                "runtime".to_owned(),
                "store".to_owned(),
            ],
        },
    );
    let snapshot = CurrentSystemEvidenceCompiler::compile(source)
        .map_err(|error| CaptureError::SnapshotValidation(error.to_string()))?;
    let receipt = SnapshotExecutionReceipt::new(&snapshot)?;
    let artifact = SnapshotExecutionArtifact { snapshot, receipt };
    artifact.validate()?;
    Ok(artifact)
}

/// Write an artifact once. Existing files are never overwritten.
pub fn write_snapshot_artifact(
    artifact: &SnapshotExecutionArtifact,
    output_path: &Path,
) -> Result<(), CaptureError> {
    if !output_path.is_absolute() {
        return Err(CaptureError::OutputPathNotAbsolute(output_path.to_owned()));
    }
    artifact.validate()?;
    let mut bytes = serde_json::to_vec_pretty(artifact)
        .map_err(|error| CaptureError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    StagedSnapshotArtifact::create(output_path, &bytes)?.publish()?;
    Ok(())
}

struct StagedSnapshotArtifact {
    temporary: PathBuf,
    destination: PathBuf,
    directory: PathBuf,
    owns_temporary: bool,
}

impl StagedSnapshotArtifact {
    fn create(destination: &Path, bytes: &[u8]) -> io::Result<Self> {
        let directory = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snapshot output must have a parent directory",
                )
            })?
            .to_owned();
        let (temporary, mut file) = create_unique_snapshot_temp(destination, &directory)?;
        let staged = Self {
            temporary,
            destination: destination.to_owned(),
            directory,
            owns_temporary: true,
        };
        let write_result = (|| {
            file.write_all(bytes)?;
            file.sync_all()
        })();
        drop(file);
        write_result?;
        Ok(staged)
    }

    fn publish(mut self) -> io::Result<()> {
        // Hard-link publication exposes the fully synced file in one step and
        // fails when the destination already exists. Unlike rename, this is a
        // no-clobber primitive on both Windows and Unix.
        fs::hard_link(&self.temporary, &self.destination)?;
        sync_parent_directory(&self.directory)?;
        self.remove_temporary()?;
        sync_parent_directory(&self.directory)
    }

    fn remove_temporary(&mut self) -> io::Result<()> {
        if !self.owns_temporary {
            return Ok(());
        }
        match fs::remove_file(&self.temporary) {
            Ok(()) => {
                self.owns_temporary = false;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.owns_temporary = false;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for StagedSnapshotArtifact {
    fn drop(&mut self) {
        if self.owns_temporary {
            let _ = fs::remove_file(&self.temporary);
        }
    }
}

fn create_unique_snapshot_temp(
    destination: &Path,
    directory: &Path,
) -> io::Result<(PathBuf, fs::File)> {
    let destination_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot output must name a file",
        )
    })?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    for _ in 0..SNAPSHOT_TEMP_CREATE_ATTEMPTS {
        let sequence = SNAPSHOT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(destination_name);
        temporary_name.push(format!(
            ".eliot-snapshot-{}-{nonce}-{sequence}.tmp",
            std::process::id()
        ));
        let temporary = directory.join(temporary_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not reserve a unique snapshot temporary file",
    ))
}

#[cfg(unix)]
fn sync_parent_directory(directory: &Path) -> io::Result<()> {
    fs::File::open(directory)?.sync_all()
}

#[cfg(windows)]
fn sync_parent_directory(directory: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory)
        .and_then(|handle| handle.sync_all())
        .or_else(|error| match error.kind() {
            io::ErrorKind::InvalidInput
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::Unsupported => Ok(()),
            _ => Err(error),
        })
}

#[cfg(not(any(unix, windows)))]
fn sync_parent_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

fn evidence(
    key: &str,
    value: String,
    evidence_ref: &str,
    evaluation: EvidenceEvaluation,
) -> EvidenceRecord {
    EvidenceRecord {
        key: key.to_owned(),
        value,
        evidence_ref: evidence_ref.to_owned(),
        evaluation,
    }
}

fn git_output<const N: usize>(
    repository_root: &Path,
    args: [&str; N],
) -> Result<String, CaptureError> {
    let command = format!("git -C {} {}", repository_root.display(), args.join(" "));
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(args)
        .output()
        .map_err(CaptureError::Io)?;
    if !output.status.success() {
        return Err(CaptureError::Git {
            command,
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn dirty_delta_binding(repository_root: &Path) -> Result<Option<String>, CaptureError> {
    // Candidate drafts are outputs of the bootstrap compiler. Feeding those
    // bytes back into its source snapshot would make repeated compilation
    // self-referential and would hide tampering behind a new content address.
    const DRAFT_EXCLUDE: &str = ":(exclude).eliot/evidence/bootstrap-drafts/**";
    let status = git_output(
        repository_root,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            ".",
            DRAFT_EXCLUDE,
        ],
    )?;
    let diff = git_output(
        repository_root,
        ["diff", "--binary", "HEAD", "--", ".", DRAFT_EXCLUDE],
    )?;
    let untracked_paths = git_output(
        repository_root,
        [
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            ".",
            DRAFT_EXCLUDE,
        ],
    )?;
    if status.is_empty() && diff.is_empty() && untracked_paths.is_empty() {
        return Ok(None);
    }

    let mut binding = Vec::new();
    binding.extend_from_slice(b"status\0");
    binding.extend_from_slice(status.as_bytes());
    binding.extend_from_slice(b"\0diff\0");
    binding.extend_from_slice(diff.as_bytes());
    binding.extend_from_slice(b"\0untracked\0");
    for relative in untracked_paths.split('\0').filter(|path| !path.is_empty()) {
        let path = repository_root.join(relative);
        binding.extend_from_slice(relative.replace('\\', "/").as_bytes());
        binding.push(0);
        binding.extend_from_slice(&fs::read(path)?);
        binding.push(0);
    }
    Ok(Some(format!("sha256:{}", sha256_hex(&binding))))
}

fn same_path(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_normative_pair_contains_only_architecture_and_implementation()
    -> Result<(), Box<dyn std::error::Error>> {
        let pair = current_normative_pair();
        assert_eq!(
            pair.architecture_sha256,
            "58e71a2bdb10925c63d85a708ed768aee8617bed0fb52eb044478ec20ab439d8"
        );
        assert_eq!(
            pair.implementation_sha256,
            "c216fb7f6fdbc62d108c748be6f61ca7ef9e5d24e5bb13af2677c31a58460c0b"
        );
        let value = serde_json::to_value(&pair)?;
        let object = value.as_object().ok_or("normative pair is not an object")?;
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, ["architecture_sha256", "implementation_sha256"]);
        Ok(())
    }

    fn git(repo: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "git {:?}: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn capture_requires_absolute_repository_root() {
        assert!(matches!(
            capture_snapshot(Path::new("relative-repo")),
            Err(CaptureError::RepositoryRootNotAbsolute(_))
        ));
    }

    fn output_directory(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "eliot-snapshot-publication-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn staged_snapshot_is_not_visible_at_final_path() -> Result<(), Box<dyn std::error::Error>> {
        let directory = output_directory("atomic");
        fs::create_dir_all(&directory)?;
        let destination = directory.join("snapshot.json");
        let bytes = b"complete snapshot bytes\n";

        let staged = StagedSnapshotArtifact::create(&destination, bytes)?;
        assert_eq!(staged.temporary.parent(), Some(directory.as_path()));
        assert!(!destination.exists());
        assert_eq!(fs::read(&staged.temporary)?, bytes);

        staged.publish()?;
        assert_eq!(fs::read(&destination)?, bytes);
        let entries = fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(entries.len(), 1);
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn snapshot_publication_never_overwrites_final() -> Result<(), Box<dyn std::error::Error>> {
        let directory = output_directory("no-clobber");
        fs::create_dir_all(&directory)?;
        let destination = directory.join("snapshot.json");
        fs::write(&destination, b"existing snapshot\n")?;

        let staged = StagedSnapshotArtifact::create(&destination, b"replacement snapshot\n")?;
        let result = staged.publish();
        assert!(matches!(
            result,
            Err(ref error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert_eq!(fs::read(&destination)?, b"existing snapshot\n");
        let entries = fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(entries.len(), 1);
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn capture_is_deterministic_and_binds_dirty_state() -> Result<(), Box<dyn std::error::Error>> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let repository_root = std::env::temp_dir().join(format!(
            "eliot-snapshot-capture-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&repository_root)?;
        git(&repository_root, &["init", "-q"])?;
        git(&repository_root, &["config", "user.name", "eliot-test"])?;
        git(
            &repository_root,
            &["config", "user.email", "eliot-test@example.invalid"],
        )?;
        fs::write(repository_root.join("tracked.txt"), "initial\n")?;
        git(&repository_root, &["add", "tracked.txt"])?;
        git(
            &repository_root,
            &["-c", "commit.gpgSign=false", "commit", "-qm", "initial"],
        )?;
        fs::write(repository_root.join("tracked.txt"), "dirty\n")?;
        fs::write(repository_root.join("untracked.txt"), "untracked\n")?;

        let first = capture_snapshot(&repository_root)?;
        let second = capture_snapshot(&repository_root)?;
        assert_eq!(first, second);
        assert_eq!(first.snapshot.selected_source_head.len(), 40);
        assert!(first.snapshot.dirty_delta_artifact_ref.is_some());
        first.validate()?;
        let _ = fs::remove_dir_all(repository_root);
        Ok(())
    }

    #[test]
    fn bootstrap_draft_outputs_do_not_feed_back_into_source_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let repository_root = std::env::temp_dir().join(format!(
            "eliot-snapshot-output-exclusion-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&repository_root)?;
        git(&repository_root, &["init", "-q"])?;
        git(&repository_root, &["config", "user.name", "eliot-test"])?;
        git(
            &repository_root,
            &["config", "user.email", "eliot-test@example.invalid"],
        )?;
        fs::write(repository_root.join("tracked.txt"), "source\n")?;
        git(&repository_root, &["add", "tracked.txt"])?;
        git(
            &repository_root,
            &["-c", "commit.gpgSign=false", "commit", "-qm", "initial"],
        )?;

        let before = capture_snapshot(&repository_root)?;
        let drafts = repository_root.join(".eliot/evidence/bootstrap-drafts");
        fs::create_dir_all(&drafts)?;
        fs::write(drafts.join("candidate.json"), "{\"candidate\":true}\n")?;
        let after = capture_snapshot(&repository_root)?;
        assert_eq!(before.snapshot, after.snapshot);
        assert_eq!(before.receipt.dirty_delta_artifact_ref, None);
        assert_eq!(after.receipt.dirty_delta_artifact_ref, None);
        let _ = fs::remove_dir_all(repository_root);
        Ok(())
    }
}
