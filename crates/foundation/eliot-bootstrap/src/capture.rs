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
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CONFORMANCE_CONTRACT_VERSION, CurrentSystemEvidenceCompiler, CurrentSystemEvidenceSnapshot,
    CurrentSystemEvidenceSource, DomainCoverage, EvidenceDomain, EvidenceEvaluation,
    EvidenceRecord, NormativePair, SourceProjection, SupportObservationState,
    normative::{self, parse_normative_pair_receipt},
};

const SNAPSHOT_TEMP_CREATE_ATTEMPTS: usize = 128;
static SNAPSHOT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

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
    #[error("normative pair receipt is unavailable at {path}: {detail}")]
    NormativePairReceipt { path: PathBuf, detail: String },
}

/// Read and parse the accepted normative pair from an explicit repository root.
pub fn load_normative_pair(repository_root: &Path) -> Result<NormativePair, CaptureError> {
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
    let canonical_root =
        fs::canonicalize(repository_root).map_err(|error| CaptureError::NormativePairReceipt {
            path: repository_root.to_owned(),
            detail: error.to_string(),
        })?;
    let path = canonical_root.join("docs/normative-pair.toml");
    let canonical_path =
        fs::canonicalize(&path).map_err(|error| CaptureError::NormativePairReceipt {
            path: path.clone(),
            detail: error.to_string(),
        })?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(CaptureError::NormativePairReceipt {
            path: canonical_path,
            detail: "receipt resolves outside the canonical repository root".to_owned(),
        });
    }
    let mut bytes = Vec::with_capacity(normative::MAX_RECEIPT_BYTES + 1);
    File::open(&canonical_path)
        .map_err(|error| CaptureError::NormativePairReceipt {
            path: canonical_path.clone(),
            detail: error.to_string(),
        })?
        .take((normative::MAX_RECEIPT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| CaptureError::NormativePairReceipt {
            path: canonical_path.clone(),
            detail: error.to_string(),
        })?;
    parse_normative_pair_receipt(&bytes).map_err(|error| CaptureError::NormativePairReceipt {
        path: canonical_path,
        detail: error.to_string(),
    })
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
    let normative_pair = load_normative_pair(&discovered_root)?;

    let source_head = git_output(&discovered_root, ["rev-parse", "HEAD"])?
        .trim()
        .to_owned();
    let dirty_delta_artifact_ref = dirty_delta_binding(&discovered_root)?;
    let dirty_delta_value = dirty_delta_artifact_ref
        .as_deref()
        .unwrap_or("CLEAN")
        .to_owned();
    // Anchor every coverage row to the exact HEAD commit time: the
    // deterministic evidence moment bound to the captured source identity.
    // Capture owns no wall-clock observation of build, runtime, store, or
    // integrations, so only source is OBSERVED; the rest stay explicit
    // UNKNOWN, except runtime which is explicitly NOT_RUNNING. The adapter
    // supplies these attributed observations and never decides support.
    let observed_at_ms = git_head_time_ms(&discovered_root)?;
    let domain_coverage = capture_domain_coverage(&source_head, observed_at_ms);

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
            normative_pair,
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
            domain_coverage,
            support_rows: Vec::new(),
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

fn coverage_row(
    domain: EvidenceDomain,
    state: SupportObservationState,
    source_handle: &str,
    evidence_refs: Vec<String>,
    observed_at_ms: Option<u64>,
    invalidation_set: Vec<String>,
) -> DomainCoverage {
    DomainCoverage {
        contract_version: CONFORMANCE_CONTRACT_VERSION,
        domain,
        state,
        source_handles: vec![source_handle.to_owned()],
        evidence_refs,
        blind_boundaries: Vec::new(),
        observed_at_ms,
        expires_at_ms: None,
        invalidation_set,
    }
}

/// Builds the exact five-domain observation set for one captured source head.
///
/// Source is `OBSERVED` through the Git capture routes; build, store, and
/// integrations are explicitly `UNKNOWN`; runtime is explicitly `NOT_RUNNING`.
/// Every non-source row carries the `capture:unavailable` route attribution.
/// No support row is minted here: the adapter cannot decide support.
fn capture_domain_coverage(source_head: &str, observed_at_ms: u64) -> Vec<DomainCoverage> {
    let head_binding = format!("git:head:{source_head}");
    vec![
        coverage_row(
            EvidenceDomain::Source,
            SupportObservationState::Observed,
            "git:rev-parse",
            vec![head_binding.clone()],
            Some(observed_at_ms),
            vec![head_binding.clone()],
        ),
        coverage_row(
            EvidenceDomain::Build,
            SupportObservationState::Unknown,
            "capture:unavailable",
            Vec::new(),
            None,
            Vec::new(),
        ),
        coverage_row(
            EvidenceDomain::Runtime,
            SupportObservationState::NotRunning,
            "capture:unavailable",
            Vec::new(),
            Some(observed_at_ms),
            vec![head_binding.clone()],
        ),
        coverage_row(
            EvidenceDomain::Store,
            SupportObservationState::Unknown,
            "capture:unavailable",
            Vec::new(),
            None,
            Vec::new(),
        ),
        coverage_row(
            EvidenceDomain::Integrations,
            SupportObservationState::Unknown,
            "capture:unavailable",
            Vec::new(),
            None,
            Vec::new(),
        ),
    ]
}

fn git_head_time_ms(repository_root: &Path) -> Result<u64, CaptureError> {
    let seconds = git_output(repository_root, ["log", "-1", "--format=%ct", "HEAD"])?
        .trim()
        .parse::<u64>()
        .map_err(|_| CaptureError::Git {
            command: "git log -1 --format=%ct HEAD".to_owned(),
            detail: "HEAD commit time is not a Unix timestamp".to_owned(),
        })?;
    Ok(seconds.saturating_mul(1_000))
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

/// Mechanical workspace-instance facts for `WorkScope` identity (issue #1787).
///
/// Source data only, never policy: the exact canonical root, VCS common-dir
/// and worktree identities, head branch/commit evidence, a dirty-file count,
/// root-level manifest names, and `.eliot` marker presence. Consumers derive
/// identity from these facts; display names, manifest names, copied markers,
/// and remote URLs stay supporting evidence there and never identity here.
/// Unobservable values stay `None`/empty rather than defaulted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceInstanceFacts {
    /// Canonicalized requested root; equals the worktree toplevel when Git is present.
    pub canonical_root: String,
    /// Whether a `.git` marker (dir or worktree file) was observed.
    pub has_git: bool,
    /// Canonical worktree git dir; distinct per worktree.
    pub git_dir: Option<String>,
    /// Canonical VCS common dir (shared object store); equal across worktrees of one lineage.
    pub common_dir: Option<String>,
    /// Head branch short name; `None` when detached or unobserved.
    pub head_branch: Option<String>,
    /// Head commit object id; present whenever Git evidence was read.
    pub head_commit: Option<String>,
    /// First root commit object id; present whenever Git evidence was read.
    pub root_commit: Option<String>,
    /// `origin` remote URL; `None` when no remote is configured.
    pub remote_url: Option<String>,
    /// Non-empty `git status --porcelain` line count; zero when clean.
    pub dirty_files: u64,
    /// Manifest file names present at the root only; no traversal.
    pub manifest_names: Vec<String>,
    /// Whether a `.eliot` marker entry exists at the root.
    pub eliot_marker_present: bool,
}

/// Root-level manifest names admitted as supporting evidence only.
const WORKSPACE_MANIFEST_NAMES: [&str; 8] = [
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "package-lock.json",
    "go.mod",
    "pyproject.toml",
    "pom.xml",
    "CMakeLists.txt",
];

impl WorkspaceInstanceFacts {
    /// Validates observed facts without interpreting them.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::Git`] when the canonical root is blank or Git
    /// presence disagrees with the observed VCS evidence.
    pub fn validate(&self) -> Result<(), CaptureError> {
        if self.canonical_root.trim().is_empty() {
            return Err(CaptureError::Git {
                command: "observe_workspace_instance".to_owned(),
                detail: "canonical root is blank".to_owned(),
            });
        }
        let vcs_complete = self.git_dir.is_some()
            && self.common_dir.is_some()
            && self.head_commit.is_some()
            && self.root_commit.is_some();
        if self.has_git != vcs_complete {
            return Err(CaptureError::Git {
                command: "observe_workspace_instance".to_owned(),
                detail: "git marker presence disagrees with observed VCS evidence".to_owned(),
            });
        }
        for manifest in &self.manifest_names {
            if manifest.trim().is_empty() {
                return Err(CaptureError::Git {
                    command: "observe_workspace_instance".to_owned(),
                    detail: "manifest name is blank".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Observes one workspace root mechanically from an explicit absolute path.
///
/// Mirrors the snapshot capture discipline: the requested root must exist,
/// canonicalize, and — when Git is present — equal the discovered worktree
/// toplevel. A missing remote stays `None`; a detached head stays `None` for
/// the branch; a non-Git directory yields directory facts with no VCS
/// evidence. Nothing is inferred, defaulted, or scanned beyond the root.
///
/// # Errors
///
/// Returns [`CaptureError`] when the root is not absolute, missing, or not
/// the worktree toplevel, or when a required Git read fails.
pub fn observe_workspace_instance(root: &Path) -> Result<WorkspaceInstanceFacts, CaptureError> {
    if !root.is_absolute() {
        return Err(CaptureError::RepositoryRootNotAbsolute(root.to_owned()));
    }
    if !root.is_dir() {
        return Err(CaptureError::RepositoryRootMissing(root.to_owned()));
    }
    let canonical_root = fs::canonicalize(root)?;
    let has_git = fs::symlink_metadata(canonical_root.join(".git")).is_ok();
    let mut manifest_names = Vec::new();
    for manifest in WORKSPACE_MANIFEST_NAMES {
        if canonical_root.join(manifest).is_file() {
            manifest_names.push(manifest.to_owned());
        }
    }
    let eliot_marker_present = canonical_root.join(".eliot").exists();
    if !has_git {
        let facts = WorkspaceInstanceFacts {
            canonical_root: canonical_root.display().to_string(),
            has_git: false,
            git_dir: None,
            common_dir: None,
            head_branch: None,
            head_commit: None,
            root_commit: None,
            remote_url: None,
            dirty_files: 0,
            manifest_names,
            eliot_marker_present,
        };
        facts.validate()?;
        return Ok(facts);
    }
    let discovered = git_output(&canonical_root, ["rev-parse", "--show-toplevel"])?;
    let discovered = fs::canonicalize(PathBuf::from(discovered.trim()))?;
    if !same_path(&canonical_root, &discovered) {
        return Err(CaptureError::RepositoryRootMismatch {
            requested: canonical_root,
            discovered,
        });
    }
    let git_dir = canonicalize_git_path(&canonical_root, ["rev-parse", "--git-dir"])?;
    let common_dir = canonicalize_git_path(&canonical_root, ["rev-parse", "--git-common-dir"])?;
    let head_commit = nonempty_git_output(&canonical_root, ["rev-parse", "HEAD"])?;
    let root_commit = git_output(&canonical_root, ["rev-list", "--max-parents=0", "HEAD"])?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .next()
        .filter(|line| !line.is_empty());
    let root_commit = root_commit.ok_or_else(|| CaptureError::Git {
        command: "git rev-list --max-parents=0 HEAD".to_owned(),
        detail: "no root commit observed".to_owned(),
    })?;
    let head_branch = fs::read_to_string(PathBuf::from(&git_dir).join("HEAD"))
        .ok()
        .and_then(|head| head.strip_prefix("ref: refs/heads/").map(str::trim).map(str::to_owned))
        .filter(|branch| !branch.is_empty() && !branch.contains(char::is_control));
    let remote_url = git_output(&canonical_root, ["remote", "get-url", "origin"])
        .map(|url| url.trim().to_owned())
        .ok()
        .filter(|url| !url.is_empty());
    let dirty_files = git_output(
        &canonical_root,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            ".",
        ],
    )?
    .lines()
    .filter(|line| !line.trim().is_empty())
    .count() as u64;
    let facts = WorkspaceInstanceFacts {
        canonical_root: canonical_root.display().to_string(),
        has_git: true,
        git_dir: Some(git_dir),
        common_dir: Some(common_dir),
        head_branch,
        head_commit: Some(head_commit),
        root_commit: Some(root_commit),
        remote_url,
        dirty_files,
        manifest_names,
        eliot_marker_present,
    };
    facts.validate()?;
    Ok(facts)
}

fn canonicalize_git_path<const N: usize>(
    repository_root: &Path,
    args: [&str; N],
) -> Result<String, CaptureError> {
    let raw = git_output(repository_root, args)?.trim().to_owned();
    if raw.is_empty() {
        return Err(CaptureError::Git {
            command: format!("git -C {} <identity>", repository_root.display()),
            detail: "git identity output is empty".to_owned(),
        });
    }
    let path = PathBuf::from(&raw);
    let joined = if path.is_absolute() {
        path
    } else {
        repository_root.join(path)
    };
    Ok(fs::canonicalize(joined)?.display().to_string())
}

fn nonempty_git_output<const N: usize>(
    repository_root: &Path,
    args: [&str; N],
) -> Result<String, CaptureError> {
    let value = git_output(repository_root, args)?.trim().to_owned();
    if value.is_empty() {
        return Err(CaptureError::Git {
            command: format!("git -C {} <identity>", repository_root.display()),
            detail: "git identity output is empty".to_owned(),
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
    }

    fn copy_normative_pair_receipt(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let destination = root.join("docs/normative-pair.toml");
        fs::create_dir_all(destination.parent().ok_or("receipt has no parent")?)?;
        fs::copy(
            repository_root().join("docs/normative-pair.toml"),
            destination,
        )?;
        Ok(())
    }

    #[test]
    fn canonical_normative_pair_contains_only_architecture_and_implementation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = repository_root();
        let receipt = fs::read(root.join("docs/normative-pair.toml"))?;
        let parsed: toml::Value = toml::from_str(std::str::from_utf8(&receipt)?)?;
        let pair = load_normative_pair(&root)?;
        assert_eq!(
            pair.architecture_sha256,
            parsed
                .get("architecture_sha256")
                .and_then(toml::Value::as_str)
                .ok_or("architecture digest missing")?
        );
        assert_eq!(
            pair.implementation_sha256,
            parsed
                .get("implementation_sha256")
                .and_then(toml::Value::as_str)
                .ok_or("implementation digest missing")?
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
        copy_normative_pair_receipt(&repository_root)?;
        git(&repository_root, &["config", "user.name", "eliot-test"])?;
        git(
            &repository_root,
            &["config", "user.email", "eliot-test@example.invalid"],
        )?;
        fs::write(repository_root.join("tracked.txt"), "initial\n")?;
        git(
            &repository_root,
            &["add", "tracked.txt", "docs/normative-pair.toml"],
        )?;
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
        copy_normative_pair_receipt(&repository_root)?;
        git(&repository_root, &["config", "user.name", "eliot-test"])?;
        git(
            &repository_root,
            &["config", "user.email", "eliot-test@example.invalid"],
        )?;
        fs::write(repository_root.join("tracked.txt"), "source\n")?;
        git(
            &repository_root,
            &["add", "tracked.txt", "docs/normative-pair.toml"],
        )?;
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
