//! Immutable readback of the selected Git workspace and its worktree overlay.

use crate::{
    AsyncProcessRunner, BridgeError, GitProcessProfile, ProcessOutcome, ProcessRunner, RepoRoot,
};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static INDEX_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Typed failures while capturing or revalidating an immutable source tree.
#[derive(Debug)]
pub enum GitSnapshotError {
    /// The selected path could not be resolved to an existing directory.
    WorkspaceUnavailable(PathBuf),
    /// Git resolved a different repository root than the selected workspace.
    WorkspaceRootMismatch { selected: PathBuf, resolved: PathBuf },
    /// A process port rejected an invocation or could not return complete data.
    Process { operation: &'static str, detail: String },
    /// Git completed with a nonzero exit status while reading the source tree.
    ProcessExit {
        operation: &'static str,
        exit_code: i32,
        stderr: Vec<u8>,
    },
    /// The original Kernel owner rejected a source readback invocation.
    OwnerRejected {
        operation: &'static str,
        code: String,
        detail: String,
    },
    /// Git returned output outside the admitted source snapshot shape.
    InvalidGitOutput { operation: &'static str, detail: String },
    /// A complete tree could not be archived with every referenced blob.
    IncompleteArchive { path: String },
    /// The selected workspace changed while the capture was in progress.
    WorkspaceChanged,
    /// The captured source archive exceeded the admitted byte ceiling.
    ArchiveTooLarge { max_bytes: u64 },
    /// The filesystem refused creation or cleanup of an operation-owned index.
    IndexDirectory { path: PathBuf, detail: String },
}

impl fmt::Display for GitSnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceUnavailable(path) => {
                write!(f, "source workspace is unavailable: {}", path.display())
            }
            Self::WorkspaceRootMismatch { selected, resolved } => write!(
                f,
                "Git workspace root {} does not match selected root {}",
                resolved.display(),
                selected.display()
            ),
            Self::Process { operation, detail } => {
                write!(f, "Git source {operation} failed: {detail}")
            }
            Self::ProcessExit {
                operation,
                exit_code,
                stderr,
            } => write!(
                f,
                "Git source {operation} exited with {exit_code}: {}",
                String::from_utf8_lossy(stderr)
            ),
            Self::OwnerRejected { operation, code, detail } => write!(
                f,
                "Git source {operation} was rejected by its original owner ({code}): {detail}"
            ),
            Self::InvalidGitOutput { operation, detail } => {
                write!(f, "Git source {operation} returned invalid output: {detail}")
            }
            Self::IncompleteArchive { path } => {
                write!(f, "Git archive omitted or changed source entry {path}")
            }
            Self::WorkspaceChanged => {
                f.write_str("selected workspace changed during source capture")
            }
            Self::ArchiveTooLarge { max_bytes } => write!(
                f,
                "source archive exceeds the admitted {max_bytes}-byte ceiling"
            ),
            Self::IndexDirectory { path, detail } => write!(
                f,
                "operation-owned Git index directory {} failed: {detail}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for GitSnapshotError {}

impl From<BridgeError> for GitSnapshotError {
    fn from(error: BridgeError) -> Self {
        Self::Process {
            operation: "bridge admission",
            detail: error.to_string(),
        }
    }
}

/// Captured source bytes for one exact selected workspace, including tracked
/// edits, tracked deletions, and untracked files, including ignored files that
/// remain readable inputs to tools operating on the selected workspace.
///
/// This value is deliberately neither serializable nor caller-constructible.
/// The Git tree ID is supplemental correlation; the archive bytes and their
/// subsequent Artifact/S-04 readback establish source content identity.
#[derive(Debug, Eq, PartialEq)]
pub struct SourceTreeSnapshot {
    workspace_root: PathBuf,
    tree_id: String,
    archive_bytes: Vec<u8>,
    max_archive_bytes: u64,
}

impl SourceTreeSnapshot {
    /// Captures the complete selected workspace and confirms a second
    /// independent isolated-index capture has the same tree and archive bytes.
    pub fn capture_current(
        root: &RepoRoot,
        runner: &dyn ProcessRunner,
        max_archive_bytes: u64,
    ) -> Result<Self, GitSnapshotError> {
        if max_archive_bytes == 0 {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "archive bound",
                detail: "admitted source archive ceiling must be nonzero".to_owned(),
            });
        }
        let before = capture_once(root, runner, max_archive_bytes)?;
        let after = capture_once(root, runner, max_archive_bytes)?;
        if !before.same_source(&after) {
            return Err(GitSnapshotError::WorkspaceChanged);
        }
        Ok(after)
    }

    /// Captures and double-checks the complete selected workspace through the
    /// asynchronous original-owner process port.
    pub async fn capture_current_async(
        root: &RepoRoot,
        runner: &dyn AsyncProcessRunner,
        max_archive_bytes: u64,
    ) -> Result<Self, GitSnapshotError> {
        if max_archive_bytes == 0 {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "archive bound",
                detail: "admitted source archive ceiling must be nonzero".to_owned(),
            });
        }
        let before = capture_once_async(root, runner, max_archive_bytes).await?;
        let after = capture_once_async(root, runner, max_archive_bytes).await?;
        if !before.same_source(&after) {
            return Err(GitSnapshotError::WorkspaceChanged);
        }
        Ok(after)
    }

    /// Re-captures the selected workspace under the same admitted byte ceiling
    /// and returns that new owner readback only when it matches this capture.
    /// A changed source invalidates currentness.
    pub fn revalidate_current(
        &self,
        root: &RepoRoot,
        runner: &dyn ProcessRunner,
    ) -> Result<Self, GitSnapshotError> {
        let current = Self::capture_current(root, runner, self.max_archive_bytes)?;
        if self.same_source(&current) {
            Ok(current)
        } else {
            Err(GitSnapshotError::WorkspaceChanged)
        }
    }

    /// Re-captures through the same asynchronous original owner and returns
    /// the new owner readback only when every source byte still matches.
    pub async fn revalidate_current_async(
        &self,
        root: &RepoRoot,
        runner: &dyn AsyncProcessRunner,
    ) -> Result<Self, GitSnapshotError> {
        let current = Self::capture_current_async(root, runner, self.max_archive_bytes).await?;
        if self.same_source(&current) {
            Ok(current)
        } else {
            Err(GitSnapshotError::WorkspaceChanged)
        }
    }

    /// Checks whether a request-selected workspace resolves to this exact
    /// canonical source root.
    pub fn validates_workspace_root(&self, path: &Path) -> Result<bool, GitSnapshotError> {
        let resolved = fs::canonicalize(path)
            .map_err(|_| GitSnapshotError::WorkspaceUnavailable(path.to_path_buf()))?;
        Ok(resolved == self.workspace_root)
    }

    /// Returns the canonical selected Git workspace root.
    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Returns the Git tree object ID as supplemental identity only.
    #[must_use]
    pub fn tree_id(&self) -> &str {
        &self.tree_id
    }

    /// Returns the complete Git archive bytes to bind through the existing
    /// ArtifactIdentity content address and S-04 read receipt.
    #[must_use]
    pub fn archive_bytes(&self) -> &[u8] {
        &self.archive_bytes
    }

    /// Returns the admitted byte ceiling used by this capture and its
    /// subsequent fresh revalidations.
    #[must_use]
    pub const fn max_archive_bytes(&self) -> u64 {
        self.max_archive_bytes
    }

    /// Compares canonical root, tree object and the complete archive payload.
    #[must_use]
    pub fn same_source(&self, other: &Self) -> bool {
        self.workspace_root == other.workspace_root
            && self.tree_id == other.tree_id
            && self.archive_bytes == other.archive_bytes
    }
}

fn capture_once(
    root: &RepoRoot,
    runner: &dyn ProcessRunner,
    max_archive_bytes: u64,
) -> Result<SourceTreeSnapshot, GitSnapshotError> {
    let requested = root.path();
    let workspace_root = fs::canonicalize(requested)
        .map_err(|_| GitSnapshotError::WorkspaceUnavailable(requested.to_path_buf()))?;
    if !workspace_root.is_dir() {
        return Err(GitSnapshotError::WorkspaceUnavailable(workspace_root));
    }
    let index = OwnedGitIndex::create()?;
    let profile = GitProcessProfile::isolated_index(index.index_path())
        .map_err(|detail| GitSnapshotError::IndexDirectory {
            path: index.directory.clone(),
            detail,
        })?;

    let resolved = run_git(runner, &workspace_root, &profile, "workspace root", &["rev-parse", "--show-toplevel"], &[])?;
    let git_root = parse_line(&resolved.stdout, "workspace root")?;
    let git_root = fs::canonicalize(PathBuf::from(git_root)).map_err(|error| {
        GitSnapshotError::InvalidGitOutput {
            operation: "workspace root",
            detail: format!("Git root could not be resolved: {error}"),
        }
    })?;
    if git_root != workspace_root {
        return Err(GitSnapshotError::WorkspaceRootMismatch {
            selected: workspace_root,
            resolved: git_root,
        });
    }

    run_git(runner, &workspace_root, &profile, "index initialization", &["read-tree", "HEAD"], &[])?;
    run_git(
        runner,
        &workspace_root,
        &profile,
        "overlay capture",
        &["add", "--all", "--force"],
        &[],
    )?;
    let tree = run_git(runner, &workspace_root, &profile, "tree write", &["write-tree"], &[])?;
    let tree_id = parse_line(&tree.stdout, "tree write")?.to_owned();
    if !matches!(tree_id.len(), 40 | 64) || !tree_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GitSnapshotError::InvalidGitOutput {
            operation: "tree write",
            detail: "Git did not return a full object ID".to_owned(),
        });
    }

    let listing = run_git(
        runner,
        &workspace_root,
        &profile,
        "tree enumeration",
        &["ls-tree", "-r", "-z", &tree_id],
        &[],
    )?;
    if listing.stdout.len() as u64 > max_archive_bytes {
        return Err(GitSnapshotError::ArchiveTooLarge {
            max_bytes: max_archive_bytes,
        });
    }
    let blobs = read_all_blobs(
        runner,
        &workspace_root,
        &profile,
        &listing.stdout,
        max_archive_bytes,
    )?;
    let archive = run_git(
        runner,
        &workspace_root,
        &profile,
        "tree archive",
        &["archive", "--format=tar", &tree_id],
        &[],
    )?;
    if archive.stdout.len() as u64 > max_archive_bytes {
        return Err(GitSnapshotError::ArchiveTooLarge {
            max_bytes: max_archive_bytes,
        });
    }
    verify_archive(&archive.stdout, &blobs)?;
    let workspace_after = fs::canonicalize(requested)
        .map_err(|_| GitSnapshotError::WorkspaceUnavailable(requested.to_path_buf()))?;
    if workspace_after != workspace_root {
        return Err(GitSnapshotError::WorkspaceChanged);
    }
    drop(index);

    Ok(SourceTreeSnapshot {
        workspace_root,
        tree_id,
        archive_bytes: archive.stdout,
        max_archive_bytes,
    })
}

async fn capture_once_async(
    root: &RepoRoot,
    runner: &dyn AsyncProcessRunner,
    max_archive_bytes: u64,
) -> Result<SourceTreeSnapshot, GitSnapshotError> {
    let requested = root.path();
    let workspace_root = fs::canonicalize(requested)
        .map_err(|_| GitSnapshotError::WorkspaceUnavailable(requested.to_path_buf()))?;
    if !workspace_root.is_dir() {
        return Err(GitSnapshotError::WorkspaceUnavailable(workspace_root));
    }
    let index = OwnedGitIndex::create()?;
    let profile = GitProcessProfile::isolated_index(index.index_path())
        .map_err(|detail| GitSnapshotError::IndexDirectory {
            path: index.directory.clone(),
            detail,
        })?;

    let resolved = run_git_async(
        runner,
        &workspace_root,
        &profile,
        "workspace root",
        &["rev-parse", "--show-toplevel"],
        &[],
    )
    .await?;
    let git_root = parse_line(&resolved.stdout, "workspace root")?;
    let git_root = fs::canonicalize(PathBuf::from(git_root)).map_err(|error| {
        GitSnapshotError::InvalidGitOutput {
            operation: "workspace root",
            detail: format!("Git root could not be resolved: {error}"),
        }
    })?;
    if git_root != workspace_root {
        return Err(GitSnapshotError::WorkspaceRootMismatch {
            selected: workspace_root,
            resolved: git_root,
        });
    }

    run_git_async(
        runner,
        &workspace_root,
        &profile,
        "index initialization",
        &["read-tree", "HEAD"],
        &[],
    )
    .await?;
    run_git_async(
        runner,
        &workspace_root,
        &profile,
        "overlay capture",
        &["add", "--all", "--force"],
        &[],
    )
    .await?;
    let tree = run_git_async(
        runner,
        &workspace_root,
        &profile,
        "tree write",
        &["write-tree"],
        &[],
    )
    .await?;
    let tree_id = parse_line(&tree.stdout, "tree write")?.to_owned();
    if !matches!(tree_id.len(), 40 | 64) || !tree_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GitSnapshotError::InvalidGitOutput {
            operation: "tree write",
            detail: "Git did not return a full object ID".to_owned(),
        });
    }

    let listing = run_git_async(
        runner,
        &workspace_root,
        &profile,
        "tree enumeration",
        &["ls-tree", "-r", "-z", &tree_id],
        &[],
    )
    .await?;
    if listing.stdout.len() as u64 > max_archive_bytes {
        return Err(GitSnapshotError::ArchiveTooLarge {
            max_bytes: max_archive_bytes,
        });
    }
    let blobs = read_all_blobs_async(
        runner,
        &workspace_root,
        &profile,
        &listing.stdout,
        max_archive_bytes,
    )
    .await?;
    let archive = run_git_async(
        runner,
        &workspace_root,
        &profile,
        "tree archive",
        &["archive", "--format=tar", &tree_id],
        &[],
    )
    .await?;
    if archive.stdout.len() as u64 > max_archive_bytes {
        return Err(GitSnapshotError::ArchiveTooLarge {
            max_bytes: max_archive_bytes,
        });
    }
    verify_archive(&archive.stdout, &blobs)?;
    let workspace_after = fs::canonicalize(requested)
        .map_err(|_| GitSnapshotError::WorkspaceUnavailable(requested.to_path_buf()))?;
    if workspace_after != workspace_root {
        return Err(GitSnapshotError::WorkspaceChanged);
    }
    drop(index);

    Ok(SourceTreeSnapshot {
        workspace_root,
        tree_id,
        archive_bytes: archive.stdout,
        max_archive_bytes,
    })
}

struct OwnedGitIndex {
    directory: PathBuf,
}

impl OwnedGitIndex {
    fn create() -> Result<Self, GitSnapshotError> {
        let temp_root = std::env::temp_dir();
        for _ in 0..64 {
            let sequence = INDEX_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let directory = temp_root.join(format!(
                "eliot-git-index-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&directory) {
                Ok(()) => return Ok(Self { directory }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(GitSnapshotError::IndexDirectory {
                        path: directory,
                        detail: error.to_string(),
                    });
                }
            }
        }
        Err(GitSnapshotError::IndexDirectory {
            path: temp_root,
            detail: "no unique operation-owned index directory was available".to_owned(),
        })
    }

    fn index_path(&self) -> PathBuf {
        self.directory.join("index")
    }
}

impl Drop for OwnedGitIndex {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.directory) else {
            return;
        };
        if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}

struct SourceBlob {
    path: Vec<u8>,
    mode: String,
    bytes: Vec<u8>,
}

fn read_all_blobs(
    runner: &dyn ProcessRunner,
    cwd: &Path,
    profile: &GitProcessProfile,
    listing: &[u8],
    max_archive_bytes: u64,
) -> Result<BTreeMap<Vec<u8>, SourceBlob>, GitSnapshotError> {
    let mut blobs = BTreeMap::new();
    let mut total_bytes = 0u64;
    if listing.is_empty() {
        return Ok(blobs);
    }
    for row in listing.split(|byte| *byte == 0).filter(|row| !row.is_empty()) {
        let (metadata, path) = row.split_once(|byte| *byte == b'\t').ok_or_else(|| {
            GitSnapshotError::InvalidGitOutput {
                operation: "tree enumeration",
                detail: "tree row omitted its path separator".to_owned(),
            }
        })?;
        let fields: Vec<&[u8]> = metadata
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty())
            .collect();
        if fields.len() != 3 {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "tree enumeration",
                detail: "tree row did not contain mode, type and object ID".to_owned(),
            });
        }
        if fields[1] != b"blob" || fields[0] == b"160000" {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "tree enumeration",
                detail: "source tree contains an entry without captured blob bytes".to_owned(),
            });
        }
        let mode = std::str::from_utf8(fields[0]).map_err(|_| GitSnapshotError::InvalidGitOutput {
            operation: "tree enumeration",
            detail: "tree mode is not ASCII".to_owned(),
        })?.to_owned();
        if !matches!(mode.as_str(), "100644" | "100755" | "120000") {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "tree enumeration",
                detail: format!("unsupported Git blob mode {mode}"),
            });
        }
        let object_id = std::str::from_utf8(fields[2]).map_err(|_| GitSnapshotError::InvalidGitOutput {
            operation: "tree enumeration",
            detail: "blob object ID is not ASCII".to_owned(),
        })?;
        let outcome = run_git(
            runner,
            cwd,
            profile,
            "blob readback",
            &["cat-file", "blob", object_id],
            &[],
        )?;
        total_bytes = total_bytes
            .checked_add(outcome.stdout.len() as u64)
            .ok_or(GitSnapshotError::ArchiveTooLarge {
                max_bytes: max_archive_bytes,
            })?;
        if total_bytes > max_archive_bytes {
            return Err(GitSnapshotError::ArchiveTooLarge {
                max_bytes: max_archive_bytes,
            });
        }
        let blob = SourceBlob {
            path: path.to_vec(),
            mode,
            bytes: outcome.stdout,
        };
        if blobs.insert(path.to_vec(), blob).is_some() {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "tree enumeration",
                detail: "tree repeated a source path".to_owned(),
            });
        }
    }
    Ok(blobs)
}

async fn read_all_blobs_async(
    runner: &dyn AsyncProcessRunner,
    cwd: &Path,
    profile: &GitProcessProfile,
    listing: &[u8],
    max_archive_bytes: u64,
) -> Result<BTreeMap<Vec<u8>, SourceBlob>, GitSnapshotError> {
    let mut blobs = BTreeMap::new();
    let mut total_bytes = 0u64;
    if listing.is_empty() {
        return Ok(blobs);
    }
    for row in listing.split(|byte| *byte == 0).filter(|row| !row.is_empty()) {
        let (metadata, path) = row.split_once(|byte| *byte == b'\t').ok_or_else(|| {
            GitSnapshotError::InvalidGitOutput {
                operation: "tree enumeration",
                detail: "tree row omitted its path separator".to_owned(),
            }
        })?;
        let fields: Vec<&[u8]> = metadata
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty())
            .collect();
        if fields.len() != 3 {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "tree enumeration",
                detail: "tree row did not contain mode, type and object ID".to_owned(),
            });
        }
        if fields[1] != b"blob" || fields[0] == b"160000" {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "tree enumeration",
                detail: "source tree contains an entry without captured blob bytes".to_owned(),
            });
        }
        let mode = std::str::from_utf8(fields[0])
            .map_err(|_| GitSnapshotError::InvalidGitOutput {
                operation: "tree enumeration",
                detail: "tree mode is not ASCII".to_owned(),
            })?
            .to_owned();
        if !matches!(mode.as_str(), "100644" | "100755" | "120000") {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "tree enumeration",
                detail: format!("unsupported Git blob mode {mode}"),
            });
        }
        let object_id = std::str::from_utf8(fields[2]).map_err(|_| {
            GitSnapshotError::InvalidGitOutput {
                operation: "tree enumeration",
                detail: "blob object ID is not ASCII".to_owned(),
            }
        })?;
        let outcome = run_git_async(
            runner,
            cwd,
            profile,
            "blob readback",
            &["cat-file", "blob", object_id],
            &[],
        )
        .await?;
        total_bytes = total_bytes
            .checked_add(outcome.stdout.len() as u64)
            .ok_or(GitSnapshotError::ArchiveTooLarge {
                max_bytes: max_archive_bytes,
            })?;
        if total_bytes > max_archive_bytes {
            return Err(GitSnapshotError::ArchiveTooLarge {
                max_bytes: max_archive_bytes,
            });
        }
        let blob = SourceBlob {
            path: path.to_vec(),
            mode,
            bytes: outcome.stdout,
        };
        if blobs.insert(path.to_vec(), blob).is_some() {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "tree enumeration",
                detail: "tree repeated a source path".to_owned(),
            });
        }
    }
    Ok(blobs)
}

fn verify_archive(
    archive: &[u8],
    expected: &BTreeMap<Vec<u8>, SourceBlob>,
) -> Result<(), GitSnapshotError> {
    if archive.len() % 512 != 0 {
        return Err(GitSnapshotError::InvalidGitOutput {
            operation: "tree archive",
            detail: "tar length is not block aligned".to_owned(),
        });
    }
    let mut offset = 0usize;
    let mut actual = BTreeMap::<Vec<u8>, (String, Vec<u8>)>::new();
    let mut extended_path: Option<Vec<u8>> = None;
    let mut ended = false;
    while offset + 512 <= archive.len() {
        let header = &archive[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            if archive[offset..].iter().any(|byte| *byte != 0) {
                return Err(GitSnapshotError::InvalidGitOutput {
                    operation: "tree archive",
                    detail: "nonzero bytes follow the tar end marker".to_owned(),
                });
            }
            ended = true;
            break;
        }
        let size = tar_octal(&header[124..136]).ok_or_else(|| GitSnapshotError::InvalidGitOutput {
            operation: "tree archive",
            detail: "tar entry has an invalid size".to_owned(),
        })?;
        let size = usize::try_from(size).map_err(|_| GitSnapshotError::InvalidGitOutput {
            operation: "tree archive",
            detail: "tar entry size does not fit this process".to_owned(),
        })?;
        let data_start = offset + 512;
        let data_end = data_start.checked_add(size).ok_or_else(|| GitSnapshotError::InvalidGitOutput {
            operation: "tree archive",
            detail: "tar entry size overflow".to_owned(),
        })?;
        if data_end > archive.len() {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "tree archive",
                detail: "tar entry exceeds archive length".to_owned(),
            });
        }
        let kind = header[156];
        if kind == b'x' {
            let payload = pax_path(&archive[data_start..data_end]).ok_or_else(|| {
                GitSnapshotError::InvalidGitOutput {
                    operation: "tree archive",
                    detail: "tar extended header is malformed".to_owned(),
                }
            })?;
            extended_path = payload;
        } else if kind == b'g' {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "tree archive",
                detail: "global tar headers are outside the admitted archive shape".to_owned(),
            });
        } else if kind == 0 || kind == b'0' || kind == b'2' {
            let path = extended_path.take().unwrap_or_else(|| tar_path(header));
            let mode_num = tar_octal(&header[100..108]).unwrap_or_default();
            let mode = if kind == b'2' {
                "120000"
            } else if mode_num & 0o111 != 0 {
                "100755"
            } else {
                "100644"
            };
            let bytes = if kind == b'2' {
                tar_field_bytes(&header[157..257])
            } else {
                archive[data_start..data_end].to_vec()
            };
            if actual.insert(path, (mode.to_owned(), bytes)).is_some() {
                return Err(GitSnapshotError::InvalidGitOutput {
                    operation: "tree archive",
                    detail: "tar repeated a source path".to_owned(),
                });
            }
        } else if kind == b'5' {
            let directory = extended_path.take().unwrap_or_else(|| tar_path(header));
            let directory = directory.strip_suffix(b"/").unwrap_or(&directory);
            let prefix = [directory, &b"/"[..]].concat();
            if directory.is_empty()
                || !expected.keys().any(|path| path.starts_with(&prefix))
            {
                return Err(GitSnapshotError::InvalidGitOutput {
                    operation: "tree archive",
                    detail: "archive contains a directory outside the source tree".to_owned(),
                });
            }
        } else {
            return Err(GitSnapshotError::InvalidGitOutput {
                operation: "tree archive",
                detail: format!("unsupported tar entry type {}", kind as char),
            });
        }
        let padded = size.checked_add(511).ok_or_else(|| GitSnapshotError::InvalidGitOutput {
            operation: "tree archive",
            detail: "tar padding overflow".to_owned(),
        })? / 512 * 512;
        offset = data_start.checked_add(padded).ok_or_else(|| GitSnapshotError::InvalidGitOutput {
            operation: "tree archive",
            detail: "tar offset overflow".to_owned(),
        })?;
    }
    if !ended || extended_path.is_some() || actual.len() != expected.len() {
        return Err(GitSnapshotError::InvalidGitOutput {
            operation: "tree archive",
            detail: "archive did not terminate or omit/duplicate source entries".to_owned(),
        });
    }
    for (path, blob) in expected {
        let matches = actual
            .get(path)
            .is_some_and(|(mode, bytes)| mode == &blob.mode && bytes == &blob.bytes);
        if !matches {
            return Err(GitSnapshotError::IncompleteArchive {
                path: String::from_utf8_lossy(&blob.path).into_owned(),
            });
        }
    }
    Ok(())
}

fn pax_path(payload: &[u8]) -> Option<Option<Vec<u8>>> {
    let mut rest = payload;
    let mut path = None;
    while !rest.is_empty() {
        let separator = rest.iter().position(|byte| *byte == b' ')?;
        let length = std::str::from_utf8(&rest[..separator]).ok()?.parse::<usize>().ok()?;
        if length <= separator + 1 || length > rest.len() {
            return None;
        }
        let record = &rest[separator + 1..length];
        if record.last() != Some(&b'\n') {
            return None;
        }
        if let Some(value) = record.strip_prefix(b"path=") {
            path = Some(value.strip_suffix(b"\n").unwrap_or(value).to_vec());
        }
        rest = &rest[length..];
    }
    Some(path)
}

fn tar_path(header: &[u8]) -> Vec<u8> {
    let name = tar_field_bytes(&header[..100]);
    let prefix = tar_field_bytes(&header[345..500]);
    if prefix.is_empty() {
        name
    } else {
        [prefix, vec![b'/'], name].concat()
    }
}

fn tar_field_bytes(bytes: &[u8]) -> Vec<u8> {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    bytes[..end].to_vec()
}

fn tar_octal(bytes: &[u8]) -> Option<u64> {
    let value = bytes
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0 || *byte == b' ')
        .take_while(|byte| *byte != 0 && *byte != b' ')
        .collect::<Vec<_>>();
    if value.is_empty() {
        return Some(0);
    }
    let text = std::str::from_utf8(&value).ok()?;
    u64::from_str_radix(text, 8).ok()
}

fn parse_line<'a>(bytes: &'a [u8], operation: &'static str) -> Result<&'a str, GitSnapshotError> {
    let trimmed = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
    std::str::from_utf8(trimmed)
        .ok()
        .filter(|line| !line.is_empty())
        .ok_or_else(|| GitSnapshotError::InvalidGitOutput {
            operation,
            detail: "expected one non-empty UTF-8 line".to_owned(),
        })
}

fn run_git(
    runner: &dyn ProcessRunner,
    cwd: &Path,
    profile: &GitProcessProfile,
    operation: &'static str,
    args: &[&str],
    stdin: &[u8],
) -> Result<ProcessOutcome, GitSnapshotError> {
    let outcome = runner
        .run_profiled("git", args, cwd, stdin, profile)
        .map_err(|detail| GitSnapshotError::Process { operation, detail })?;
    if outcome.code != 0 {
        return Err(GitSnapshotError::ProcessExit {
            operation,
            exit_code: outcome.code,
            stderr: outcome.stderr,
        });
    }
    Ok(outcome)
}

async fn run_git_async(
    runner: &dyn AsyncProcessRunner,
    cwd: &Path,
    profile: &GitProcessProfile,
    operation: &'static str,
    args: &[&str],
    stdin: &[u8],
) -> Result<ProcessOutcome, GitSnapshotError> {
    let outcome = runner
        .run_profiled("git", args, cwd, stdin, profile)
        .await
        .map_err(|error| GitSnapshotError::OwnerRejected {
            operation,
            code: error.code,
            detail: error.detail,
        })?;
    if outcome.code != 0 {
        return Err(GitSnapshotError::ProcessExit {
            operation,
            exit_code: outcome.code,
            stderr: outcome.stderr,
        });
    }
    Ok(outcome)
}
