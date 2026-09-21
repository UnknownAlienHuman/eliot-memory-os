//! Typed Git bridge without destructive worktree handling (issue #1830).
//!
//! Implements the I10.9 Git bridge contract: typed operations for
//! `status` / `branch` / `commit` (read-only inspection) / `diff`,
//! worktree create / remove, patch `check` (non-mutating preflight) versus
//! patch `apply` (guarded mutation), `blame` / `log` / co-change mining,
//! change manifests, and base drift.
//!
//! Design rules enforced here:
//!
//! * Every operation runs through the injected [`ProcessRunner`] port. The
//!   production binding of this port is the shared `ProcessExecutor`; this
//!   crate never spawns private launch/retry semantics and never shells out
//!   except through the port. [`StdProcessRunner`] is the local
//!   `std::process`-backed port implementation used by tests and standalone
//!   hosts.
//! * Every request carries a declared execution identity ([`ExecutionIdentity`]
//!   / SID) and a resource root ([`RepoRoot`]). User-owned roots are served
//!   only through a broker-launched scoped [`Lease`] unless an explicit
//!   [`AclAdmission`] admits the service identity.
//! * Dirty-state detection runs before worktree and patch operations. The
//!   bridge records the dirty fact in every receipt and refuses clean-gated
//!   work when the source tree is dirty. It never issues `git reset --hard`
//!   (or any equivalent destructive invocation); [`validate_invocation`]
//!   rejects such invocations fail-closed.
//! * Patch checking (`apply --check`) is a separate operation from patch
//!   application and never mutates the repository.
//! * Worktree removal is lease-aware and never uses `--force`.
//! * Every receipt carries the SID, resolved root, worktree path, lease,
//!   executable invocation, exit disposition, and bounded command-output
//!   handles.
//!
//! Documentation routing: route `generic-source`,
//! read receipt `sha256:83d4af5fa39d53bf3036ba8e12598d95535a49acc4ea1b3ed1279a840b5301e4`,
//! bundle `a579537df8b05287562cd597032ad0a2810dfd3512a804b604d94e6f345c9518`
//! (23 required items read before mutation; I10.9 Git bridge fragment,
//! dependency policy, and workspace crate instructions applied).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Identity, ownership, leases
// ---------------------------------------------------------------------------

/// Declared execution identity every bridge call runs under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionIdentity {
    sid: String,
}

impl ExecutionIdentity {
    /// Declares the execution identity. Empty/blank SIDs are rejected.
    pub fn new(sid: impl Into<String>) -> Result<Self, BridgeError> {
        let sid = sid.into();
        if sid.trim().is_empty() {
            return Err(BridgeError::EmptySid);
        }
        Ok(Self { sid })
    }

    /// Returns the declared SID.
    pub fn sid(&self) -> &str {
        &self.sid
    }
}

/// Ownership of a repository root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerKind {
    /// Service-owned root: the bridge identity may act directly.
    Service,
    /// User-owned root: requires a broker-launched scoped adapter unless an
    /// explicit ACL admission is present.
    User,
}

/// A repository resource root plus its declared ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepoRoot {
    path: PathBuf,
    owner: OwnerKind,
}

impl RepoRoot {
    /// Declares a resource root. The path must be absolute.
    pub fn new(path: impl Into<PathBuf>, owner: OwnerKind) -> Result<Self, BridgeError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(BridgeError::RootNotAbsolute(path));
        }
        Ok(Self { path, owner })
    }

    /// Returns the declared root path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the declared ownership.
    pub fn owner(&self) -> OwnerKind {
        self.owner
    }
}

/// Explicit ACL admission of the service identity on a user-owned root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AclAdmission {
    /// When true, the service identity is admitted without a broker lease.
    pub admits_service_identity: bool,
}

/// Broker-launched scoped lease binding one SID to one root (and, for
/// worktree operations, one worktree path).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    id: String,
    sid: String,
    scope_root: PathBuf,
    worktree: Option<PathBuf>,
    issued_by: String,
}

impl Lease {
    /// Returns the lease identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the SID this lease was issued to.
    pub fn sid(&self) -> &str {
        &self.sid
    }

    /// Returns the root this lease is scoped to.
    pub fn scope_root(&self) -> &Path {
        &self.scope_root
    }

    /// Returns the worktree path this lease is scoped to, if any.
    pub fn worktree(&self) -> Option<&Path> {
        self.worktree.as_deref()
    }

    /// Returns the lease issuer label.
    pub fn issued_by(&self) -> &str {
        &self.issued_by
    }
}

/// Broker that launches scoped adapters by minting [`Lease`] values.
#[derive(Debug, Default)]
pub struct Broker {
    sequence: AtomicU64,
}

impl Broker {
    /// Creates a broker with a zeroed lease sequence.
    pub fn new() -> Self {
        Self {
            sequence: AtomicU64::new(1),
        }
    }

    /// Issues a scoped worktree lease for one SID on one root.
    pub fn issue_worktree_lease(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        worktree: impl Into<PathBuf>,
    ) -> Lease {
        let n = self.sequence.fetch_add(1, Ordering::SeqCst);
        Lease {
            id: format!("wt-lease-{n}-{}", identity.sid()),
            sid: identity.sid().to_owned(),
            scope_root: root.path.clone(),
            worktree: Some(worktree.into()),
            issued_by: "broker".to_owned(),
        }
    }

    /// Issues a scoped repository lease (no worktree) for one SID on one root.
    pub fn issue_repo_lease(&self, identity: &ExecutionIdentity, root: &RepoRoot) -> Lease {
        let n = self.sequence.fetch_add(1, Ordering::SeqCst);
        Lease {
            id: format!("repo-lease-{n}-{}", identity.sid()),
            sid: identity.sid().to_owned(),
            scope_root: root.path.clone(),
            worktree: None,
            issued_by: "broker".to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Process port (shared ProcessExecutor binding surface)
// ---------------------------------------------------------------------------

/// Raw outcome of one port invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutcome {
    /// Process exit code (`-1` when the platform reports no code).
    pub code: i32,
    /// Captured stdout bytes.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes.
    pub stderr: Vec<u8>,
}

/// Read-only process-launch port this bridge consumes.
///
/// The production binding is the shared `ProcessExecutor`; this trait is the
/// narrow seam the bridge is allowed to touch. It carries no authority, no
/// retry, and no shell semantics — one executable, explicit argv, explicit
/// cwd, explicit stdin bytes.
pub trait ProcessRunner: Send + Sync {
    /// Runs `exe` with `args` in `cwd`, feeding `stdin` to the child.
    ///
    /// # Errors
    /// Returns a message when the child cannot be launched or its streams
    /// cannot be drained.
    fn run(
        &self,
        exe: &str,
        args: &[&str],
        cwd: &Path,
        stdin: &[u8],
    ) -> Result<ProcessOutcome, String>;
}

/// Local `std::process`-backed [`ProcessRunner`] for tests/standalone hosts.
#[derive(Clone, Copy, Debug, Default)]
pub struct StdProcessRunner;

impl ProcessRunner for StdProcessRunner {
    fn run(
        &self,
        exe: &str,
        args: &[&str],
        cwd: &Path,
        stdin: &[u8],
    ) -> Result<ProcessOutcome, String> {
        validate_invocation(exe, args).map_err(|e| e.to_string())?;
        let mut child = Command::new(exe)
            .args(args)
            .current_dir(cwd)
            .stdin(if stdin.is_empty() {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {exe}: {e}"))?;
        if !stdin.is_empty() {
            child
                .stdin
                .take()
                .ok_or_else(|| format!("spawn {exe}: stdin unavailable"))?
                .write_all(stdin)
                .map_err(|e| format!("write stdin {exe}: {e}"))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|e| format!("wait {exe}: {e}"))?;
        Ok(ProcessOutcome {
            code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

// ---------------------------------------------------------------------------
// Invocation guard: no hidden destructive path
// ---------------------------------------------------------------------------

/// Rejects destructive git invocations fail-closed.
///
/// The bridge only ever constructs fixed, reviewed argv vectors, so this
/// validator is defense in depth: `reset` in any form, `checkout`, `clean`,
/// forced worktree removal, forced branch deletion, forced push, and stash
/// destruction are all refused. There is no code path in this crate that
/// needs them.
pub fn validate_invocation(exe: &str, args: &[&str]) -> Result<(), BridgeError> {
    if exe.trim().is_empty() {
        return Err(BridgeError::DestructiveOpRejected("empty executable"));
    }
    let has = |flag: &str| args.contains(&flag);
    let subcommand = args.first().copied().unwrap_or("");
    // Any reset is destructive to human dirty state: never allowed.
    if subcommand == "reset" || args.contains(&"reset") {
        return Err(BridgeError::DestructiveOpRejected(
            "git reset is not admitted by the bridge",
        ));
    }
    // Checkout / clean rewrite or delete working-tree state.
    if subcommand == "checkout" || subcommand == "clean" {
        return Err(BridgeError::DestructiveOpRejected(
            "git checkout/clean are not admitted by the bridge",
        ));
    }
    // Forced worktree removal can destroy uncommitted work in the worktree.
    if subcommand == "worktree" && (has("--force") || has("-f")) {
        return Err(BridgeError::DestructiveOpRejected(
            "forced worktree removal is not admitted by the bridge",
        ));
    }
    // Forced branch deletion and forced pushes destroy reachable history.
    if subcommand == "branch" && has("-D") {
        return Err(BridgeError::DestructiveOpRejected(
            "forced branch deletion is not admitted by the bridge",
        ));
    }
    if subcommand == "push" && (has("--force") || has("-f") || has("--delete")) {
        return Err(BridgeError::DestructiveOpRejected(
            "forced push / remote deletion is not admitted by the bridge",
        ));
    }
    if subcommand == "stash" && (has("drop") || has("clear")) {
        return Err(BridgeError::DestructiveOpRejected(
            "stash destruction is not admitted by the bridge",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed bridge failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeError {
    /// No execution identity was declared.
    EmptySid,
    /// The resource root is not absolute.
    RootNotAbsolute(PathBuf),
    /// The resource root could not be resolved for execution.
    RootNotFound(PathBuf),
    /// A user-owned root needs a broker lease (no ACL admission present).
    BrokerLeaseRequired,
    /// The presented lease does not cover this SID/root/worktree.
    LeaseScopeMismatch(String),
    /// The source tree is dirty and the request requires a clean tree.
    DirtyWorktree(String),
    /// Patch preflight (`apply --check`) reports the patch as inapplicable.
    PatchCheckFailed(String),
    /// Git ran but reported failure.
    GitFailed {
        invocation: String,
        code: i32,
        stderr: String,
    },
    /// A destructive invocation was requested or constructed.
    DestructiveOpRejected(&'static str),
    /// The process port failed.
    Runner(String),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySid => write!(f, "execution identity SID must not be empty"),
            Self::RootNotAbsolute(p) => {
                write!(f, "resource root must be absolute: {}", p.display())
            }
            Self::RootNotFound(p) => {
                write!(f, "resource root not found: {}", p.display())
            }
            Self::BrokerLeaseRequired => write!(
                f,
                "user-owned root requires a broker-launched scoped lease or ACL admission"
            ),
            Self::LeaseScopeMismatch(detail) => {
                write!(f, "lease scope mismatch: {detail}")
            }
            Self::DirtyWorktree(detail) => write!(f, "dirty worktree guard: {detail}"),
            Self::PatchCheckFailed(detail) => write!(f, "patch check failed: {detail}"),
            Self::GitFailed {
                invocation,
                code,
                stderr,
            } => write!(f, "git failed ({invocation}, exit {code}): {stderr}"),
            Self::DestructiveOpRejected(reason) => {
                write!(f, "destructive operation rejected: {reason}")
            }
            Self::Runner(detail) => write!(f, "process runner failed: {detail}"),
        }
    }
}

impl std::error::Error for BridgeError {}

// ---------------------------------------------------------------------------
// Receipt primitives
// ---------------------------------------------------------------------------

/// Bounded preview ceiling for output handles (bytes).
pub const OUTPUT_PREVIEW_CEILING: usize = 4096;

/// The exact executable invocation behind a receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    /// Executable name (`git` for every operation in this bridge).
    pub exe: String,
    /// Exact argv.
    pub args: Vec<String>,
    /// Working directory the child ran in.
    pub cwd: PathBuf,
}

impl Invocation {
    fn describe(&self) -> String {
        let mut s = self.exe.clone();
        for a in &self.args {
            s.push(' ');
            s.push_str(a);
        }
        s
    }
}

/// Typed exit disposition of one invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitDisposition {
    /// Process exit code.
    pub code: i32,
    /// Whether the code reports success (zero).
    pub success: bool,
}

/// Bounded handle to one captured command-output stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputHandle {
    /// Total bytes observed (including bytes beyond the preview).
    pub total_bytes: u64,
    /// SHA-256 over the full observed bytes, hex-encoded.
    pub sha256: String,
    /// Bounded lossy preview (first [`OUTPUT_PREVIEW_CEILING`] bytes).
    pub preview: String,
    /// Whether bytes beyond the preview were observed.
    pub truncated: bool,
}

impl OutputHandle {
    /// Captures a bounded handle over observed bytes.
    pub fn capture(bytes: &[u8]) -> Self {
        let preview_bytes = bytes.len().min(OUTPUT_PREVIEW_CEILING);
        Self {
            total_bytes: bytes.len() as u64,
            sha256: sha256_hex(bytes),
            preview: String::from_utf8_lossy(&bytes[..preview_bytes]).into_owned(),
            truncated: bytes.len() > OUTPUT_PREVIEW_CEILING,
        }
    }
}

/// Receipt fields shared by every operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommonReceipt {
    /// Declared execution identity (SID).
    pub sid: String,
    /// Resolved repository root the operation ran against.
    pub root: PathBuf,
    /// Worktree path the operation targeted, when applicable.
    pub worktree: Option<PathBuf>,
    /// Lease the operation ran under, when applicable.
    pub lease: Option<Lease>,
    /// Exact executable invocation.
    pub invocation: Invocation,
    /// Exit disposition.
    pub exit: ExitDisposition,
    /// Captured stdout handle.
    pub stdout: OutputHandle,
    /// Captured stderr handle.
    pub stderr: OutputHandle,
    /// Dirty-state preflight observation of the source tree.
    pub source_dirty: bool,
}

// ---------------------------------------------------------------------------
// Typed operation payloads
// ---------------------------------------------------------------------------

/// One `status --porcelain` entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusEntry {
    /// Two-letter index/worktree status.
    pub xy: String,
    /// Path as reported by git.
    pub path: String,
}

/// Typed `status` receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusReceipt {
    /// Shared receipt fields (SID, root, invocation, exit, handles, ...).
    pub common: CommonReceipt,
    /// Current branch line (`## ...`), when reported.
    pub branch_line: Option<String>,
    /// Whether the tree holds uncommitted changes.
    pub dirty: bool,
    /// Parsed porcelain entries.
    pub entries: Vec<StatusEntry>,
}

/// Typed `branch` receipt (read-only listing).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchReceipt {
    /// Shared receipt fields.
    pub common: CommonReceipt,
    /// Current branch name, when determinable.
    pub current: Option<String>,
    /// Branch names listed.
    pub branches: Vec<String>,
    /// Whether HEAD is detached.
    pub detached: bool,
}

/// Typed `commit` receipt: read-only inspection of one revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    /// Shared receipt fields.
    pub common: CommonReceipt,
    /// Inspected revision (as requested).
    pub rev: String,
    /// Full commit hash.
    pub hash: String,
    /// Author name.
    pub author: String,
    /// Author date (ISO-8601 when available).
    pub date: String,
    /// Subject line.
    pub subject: String,
}

/// Typed `diff` receipt (read-only).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffReceipt {
    /// Shared receipt fields.
    pub common: CommonReceipt,
    /// Files reported by `diff --name-status`.
    pub files: Vec<DiffFile>,
}

/// One file row of a diff name-status listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffFile {
    /// Single-letter status (`M`, `A`, `D`, `R`, ...).
    pub status: String,
    /// Path as reported by git.
    pub path: String,
}

/// Typed worktree-create receipt: carries the scoped lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorktreeCreateReceipt {
    /// Shared receipt fields.
    pub common: CommonReceipt,
    /// Path of the created worktree.
    pub worktree_path: PathBuf,
    /// Revision the worktree was attached at.
    pub rev: String,
    /// Scoped lease covering this worktree.
    pub lease: Lease,
}

/// Typed lease-aware worktree-remove receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorktreeRemoveReceipt {
    /// Shared receipt fields.
    pub common: CommonReceipt,
    /// Path of the removed worktree.
    pub worktree_path: PathBuf,
}

/// Typed patch-check receipt: applicability without mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchCheckReceipt {
    /// Shared receipt fields.
    pub common: CommonReceipt,
    /// Whether `git apply --check` accepted the patch.
    pub applicable: bool,
}

/// Typed patch-apply receipt (guarded mutation, never destructive).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchApplyReceipt {
    /// Shared receipt fields.
    pub common: CommonReceipt,
    /// Patch bytes digest (SHA-256 hex) that were applied.
    pub patch_sha256: String,
}

/// One blamed line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlameLine {
    /// Commit hash owning the line.
    pub rev: String,
    /// 1-based line number.
    pub line_no: u64,
    /// Line content (without trailing newline).
    pub content: String,
}

/// Typed `blame` receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlameReceipt {
    /// Shared receipt fields.
    pub common: CommonReceipt,
    /// Blamed path.
    pub path: String,
    /// Blamed lines in order.
    pub lines: Vec<BlameLine>,
}

/// One log entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogEntry {
    /// Full commit hash.
    pub rev: String,
    /// Author date (ISO-8601 when available).
    pub date: String,
    /// Author name.
    pub author: String,
    /// Subject line.
    pub subject: String,
}

/// Typed `log` receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogReceipt {
    /// Shared receipt fields.
    pub common: CommonReceipt,
    /// Newest-first entries (bounded by the request limit).
    pub entries: Vec<LogEntry>,
}

/// Typed co-change mining receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CochangeReceipt {
    /// Shared receipt fields.
    pub common: CommonReceipt,
    /// Mined path.
    pub path: String,
    /// `(path, commit-count)` pairs sorted by count descending.
    pub cochanged: Vec<(String, u64)>,
}

/// One change-manifest row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestEntry {
    /// Path as reported by git.
    pub path: String,
    /// Porcelain index/worktree status.
    pub xy: String,
    /// Added lines (`diff --numstat`), when measurable.
    pub added: Option<u64>,
    /// Removed lines (`diff --numstat`), when measurable.
    pub removed: Option<u64>,
}

/// Typed change-manifest receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeManifestReceipt {
    /// Shared receipt fields.
    pub common: CommonReceipt,
    /// Whether the tree holds uncommitted changes.
    pub dirty: bool,
    /// Manifest rows.
    pub entries: Vec<ManifestEntry>,
}

/// Typed base-drift receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaseDriftReceipt {
    /// Shared receipt fields.
    pub common: CommonReceipt,
    /// Inspected base revision.
    pub base: String,
    /// Inspected head revision.
    pub head: String,
    /// Merge base of `base` and `head`, when resolvable.
    pub merge_base: Option<String>,
    /// Commits reachable only from `head`.
    pub ahead: u64,
    /// Commits reachable only from `base`.
    pub behind: u64,
}

// ---------------------------------------------------------------------------
// Bridge
// ---------------------------------------------------------------------------

/// Typed Git bridge.
///
/// Owns no process mechanics: every git invocation goes through the injected
/// [`ProcessRunner`] port (production: the shared `ProcessExecutor`).
#[derive(Debug)]
pub struct GitBridge<R> {
    runner: R,
    sequence: AtomicU64,
}

impl<R: ProcessRunner> GitBridge<R> {
    /// Binds the bridge to a process-runner port.
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            sequence: AtomicU64::new(1),
        }
    }

    /// Returns the bound runner port.
    pub fn runner(&self) -> &R {
        &self.runner
    }

    // -- internals ---------------------------------------------------------

    fn resolve_root(&self, root: &RepoRoot) -> Result<PathBuf, BridgeError> {
        match std::fs::canonicalize(&root.path) {
            Ok(p) => Ok(p),
            Err(e) if root.path.exists() => Err(BridgeError::Runner(format!(
                "resolve root {}: {e}",
                root.path.display()
            ))),
            // Nonexistent paths (e.g. scripted fakes) resolve to themselves;
            // the runner owns launch failure for genuinely missing roots.
            Err(_) => Ok(root.path.clone()),
        }
    }

    /// Enforces identity + root + broker-lease routing for one call.
    ///
    /// Returns the resolved root and the lease the receipt must carry.
    fn admit(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
        worktree: Option<&Path>,
    ) -> Result<(PathBuf, Option<Lease>), BridgeError> {
        let resolved = self.resolve_root(root)?;
        if !resolved.exists() {
            return Err(BridgeError::RootNotFound(resolved));
        }
        let admitted = admission
            .map(|a| a.admits_service_identity)
            .unwrap_or(false);
        if root.owner == OwnerKind::User && !admitted {
            let lease = lease.ok_or(BridgeError::BrokerLeaseRequired)?;
            if lease.sid() != identity.sid() {
                return Err(BridgeError::LeaseScopeMismatch(format!(
                    "lease {} is issued to '{}', request runs as '{}'",
                    lease.id(),
                    lease.sid(),
                    identity.sid()
                )));
            }
            let lease_root = best_effort_canonical(lease.scope_root());
            if lease_root != best_effort_canonical(&resolved) {
                return Err(BridgeError::LeaseScopeMismatch(format!(
                    "lease {} scopes '{}', request targets '{}'",
                    lease.id(),
                    lease.scope_root().display(),
                    resolved.display()
                )));
            }
            if let Some(worktree) = worktree {
                match lease.worktree() {
                    Some(scoped)
                        if best_effort_canonical(scoped) == best_effort_canonical(worktree) =>
                    {
                        // scoped correctly
                    }
                    _ => {
                        return Err(BridgeError::LeaseScopeMismatch(format!(
                            "lease {} does not scope worktree '{}'",
                            lease.id(),
                            worktree.display()
                        )));
                    }
                }
            }
            Ok((resolved, Some(lease.clone())))
        } else {
            // A presented lease is receipt identity: it must belong to the
            // requesting SID even where no broker lease is required.
            if let Some(lease) = lease {
                if lease.sid() != identity.sid() {
                    return Err(BridgeError::LeaseScopeMismatch(format!(
                        "lease {} is issued to '{}', request runs as '{}'",
                        lease.id(),
                        lease.sid(),
                        identity.sid()
                    )));
                }
            }
            Ok((resolved, lease.cloned()))
        }
    }

    fn exec(
        &self,
        args: Vec<String>,
        cwd: &Path,
    ) -> Result<(ProcessOutcome, Invocation, ExitDisposition), BridgeError> {
        let invocation = Invocation {
            exe: "git".to_owned(),
            args,
            cwd: cwd.to_owned(),
        };
        let argv: Vec<&str> = invocation.args.iter().map(String::as_str).collect();
        validate_invocation(&invocation.exe, &argv)?;
        let outcome = self
            .runner
            .run(
                &invocation.exe,
                &argv,
                &invocation.cwd,
                // stdin is supplied via exec_stdin; plain exec sends none.
                &[],
            )
            .map_err(BridgeError::Runner)?;
        let exit = ExitDisposition {
            code: outcome.code,
            success: outcome.code == 0,
        };
        Ok((outcome, invocation, exit))
    }

    fn exec_stdin(
        &self,
        args: Vec<String>,
        cwd: &Path,
        stdin: &[u8],
    ) -> Result<(ProcessOutcome, Invocation, ExitDisposition), BridgeError> {
        let invocation = Invocation {
            exe: "git".to_owned(),
            args,
            cwd: cwd.to_owned(),
        };
        let argv: Vec<&str> = invocation.args.iter().map(String::as_str).collect();
        validate_invocation(&invocation.exe, &argv)?;
        let outcome = self
            .runner
            .run(&invocation.exe, &argv, &invocation.cwd, stdin)
            .map_err(BridgeError::Runner)?;
        let exit = ExitDisposition {
            code: outcome.code,
            success: outcome.code == 0,
        };
        Ok((outcome, invocation, exit))
    }

    #[allow(clippy::too_many_arguments)]
    fn common(
        &self,
        identity: &ExecutionIdentity,
        root: PathBuf,
        worktree: Option<PathBuf>,
        lease: Option<Lease>,
        invocation: Invocation,
        exit: ExitDisposition,
        outcome: &ProcessOutcome,
        source_dirty: bool,
    ) -> CommonReceipt {
        CommonReceipt {
            sid: identity.sid().to_owned(),
            root,
            worktree,
            lease,
            invocation,
            exit,
            stdout: OutputHandle::capture(&outcome.stdout),
            stderr: OutputHandle::capture(&outcome.stderr),
            source_dirty,
        }
    }

    fn check_success(
        &self,
        outcome: &ProcessOutcome,
        invocation: &Invocation,
    ) -> Result<(), BridgeError> {
        if outcome.code == 0 {
            return Ok(());
        }
        Err(BridgeError::GitFailed {
            invocation: invocation.describe(),
            code: outcome.code,
            stderr: String::from_utf8_lossy(&outcome.stderr).into_owned(),
        })
    }

    /// Dirty-state preflight: true when `git status --porcelain` is non-empty.
    fn is_dirty(&self, cwd: &Path) -> Result<bool, BridgeError> {
        let args = vec![
            "status".to_owned(),
            "--porcelain=v1".to_owned(),
            "--untracked-files=normal".to_owned(),
        ];
        let (outcome, invocation, _) = self.exec(args, cwd)?;
        self.check_success(&outcome, &invocation)?;
        Ok(!outcome.stdout.iter().all(|b| b.is_ascii_whitespace()))
    }

    // -- typed operations --------------------------------------------------

    /// Typed `status`: dirty-state, branch line, and porcelain entries.
    ///
    /// # Errors
    /// Identity/root/lease failures, runner failures, or git failures.
    pub fn status(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<StatusReceipt, BridgeError> {
        let (resolved, lease) = self.admit(identity, root, admission, lease, None)?;
        let args = vec![
            "status".to_owned(),
            "--porcelain=v1".to_owned(),
            "-b".to_owned(),
            "--untracked-files=normal".to_owned(),
        ];
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        self.check_success(&outcome, &invocation)?;
        let text = String::from_utf8_lossy(&outcome.stdout);
        let mut branch_line = None;
        let mut entries = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if index == 0 && line.starts_with("## ") {
                branch_line = Some(line.to_owned());
                continue;
            }
            if line.len() < 4 {
                continue;
            }
            entries.push(StatusEntry {
                xy: line[..2].to_owned(),
                path: line[3..].to_owned(),
            });
        }
        let dirty = !entries.is_empty();
        let common = self.common(
            identity, resolved, None, lease, invocation, exit, &outcome, dirty,
        );
        Ok(StatusReceipt {
            common,
            branch_line,
            dirty,
            entries,
        })
    }

    /// Typed `branch`: read-only current-branch and listing.
    ///
    /// # Errors
    /// Identity/root/lease failures, runner failures, or git failures.
    pub fn branch(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<BranchReceipt, BridgeError> {
        let (resolved, lease) = self.admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let args = vec![
            "branch".to_owned(),
            "--list".to_owned(),
            "--no-color".to_owned(),
        ];
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        self.check_success(&outcome, &invocation)?;
        let text = String::from_utf8_lossy(&outcome.stdout);
        let mut current = None;
        let mut branches = Vec::new();
        let mut detached = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(name) = trimmed.strip_prefix("* ") {
                if name == "(HEAD detached at" || trimmed.starts_with("* (HEAD") {
                    detached = true;
                } else {
                    current = Some(name.to_owned());
                    branches.push(name.to_owned());
                }
            } else {
                branches.push(trimmed.to_owned());
            }
        }
        let common = self.common(
            identity, resolved, None, lease, invocation, exit, &outcome, dirty,
        );
        Ok(BranchReceipt {
            common,
            current,
            branches,
            detached,
        })
    }

    /// Typed `commit`: read-only inspection of one revision (never creates one).
    ///
    /// # Errors
    /// Identity/root/lease failures, runner failures, or git failures.
    pub fn inspect_commit(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        rev: &str,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<CommitReceipt, BridgeError> {
        let (resolved, lease) = self.admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let args = vec![
            "show".to_owned(),
            "-s".to_owned(),
            "--no-color".to_owned(),
            "--format=%H%n%an%n%aI%n%s".to_owned(),
            rev.to_owned(),
        ];
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        self.check_success(&outcome, &invocation)?;
        let text = String::from_utf8_lossy(&outcome.stdout);
        let mut lines = text.lines();
        let hash = lines.next().unwrap_or("").to_owned();
        let author = lines.next().unwrap_or("").to_owned();
        let date = lines.next().unwrap_or("").to_owned();
        let subject = lines.next().unwrap_or("").to_owned();
        let common = self.common(
            identity, resolved, None, lease, invocation, exit, &outcome, dirty,
        );
        Ok(CommitReceipt {
            common,
            rev: rev.to_owned(),
            hash,
            author,
            date,
            subject,
        })
    }

    /// Typed `diff`: read-only name-status listing, optionally for a range.
    ///
    /// # Errors
    /// Identity/root/lease failures, runner failures, or git failures.
    pub fn diff(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        rev_range: Option<&str>,
        paths: &[&str],
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<DiffReceipt, BridgeError> {
        let (resolved, lease) = self.admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let mut args = vec![
            "diff".to_owned(),
            "--no-color".to_owned(),
            "--name-status".to_owned(),
        ];
        if let Some(range) = rev_range {
            args.push(range.to_owned());
        }
        if !paths.is_empty() {
            args.push("--".to_owned());
            for p in paths {
                args.push((*p).to_owned());
            }
        }
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        self.check_success(&outcome, &invocation)?;
        let text = String::from_utf8_lossy(&outcome.stdout);
        let mut files = Vec::new();
        for line in text.lines() {
            let mut parts = line.splitn(2, '\t');
            let (Some(status), Some(path)) = (parts.next(), parts.next()) else {
                continue;
            };
            files.push(DiffFile {
                status: status.to_owned(),
                path: path.to_owned(),
            });
        }
        let common = self.common(
            identity, resolved, None, lease, invocation, exit, &outcome, dirty,
        );
        Ok(DiffReceipt { common, files })
    }

    /// Typed worktree create: isolated, non-destructive, lease-scoped.
    ///
    /// Runs a dirty-state preflight (recorded on the receipt; `require_clean`
    /// turns a dirty source into a refusal) and then
    /// `git worktree add --detach <path> <rev>`. The worktree path must be
    /// absolute. User-owned roots require a broker lease scoping this exact
    /// worktree path.
    ///
    /// # Errors
    /// Identity/root/lease failures, dirty-guard refusals, runner failures,
    /// or git failures.
    #[allow(clippy::too_many_arguments)]
    pub fn worktree_create(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        worktree_path: &Path,
        rev: &str,
        require_clean: bool,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<WorktreeCreateReceipt, BridgeError> {
        if !worktree_path.is_absolute() {
            return Err(BridgeError::RootNotAbsolute(worktree_path.to_owned()));
        }
        let (resolved, lease) =
            self.admit(identity, root, admission, lease, Some(worktree_path))?;
        let dirty = self.is_dirty(&resolved)?;
        if dirty && require_clean {
            return Err(BridgeError::DirtyWorktree(format!(
                "refusing worktree create on dirty root {}",
                resolved.display()
            )));
        }
        let args = vec![
            "worktree".to_owned(),
            "add".to_owned(),
            "--detach".to_owned(),
            worktree_path.to_string_lossy().into_owned(),
            rev.to_owned(),
        ];
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        self.check_success(&outcome, &invocation)?;
        let Some(lease) = lease else {
            // Service-owned roots without a presented lease still receive a
            // receipt-bound scope record minted locally (never broker-forged:
            // the issuer label names the bridge, not the broker). The bridge
            // sequence keeps each minted record unique per bridge instance.
            let n = self.sequence.fetch_add(1, Ordering::SeqCst);
            let local = Lease {
                id: format!("local-{n}-{}-worktree", identity.sid()),
                sid: identity.sid().to_owned(),
                scope_root: resolved.clone(),
                worktree: Some(worktree_path.to_owned()),
                issued_by: "bridge-local".to_owned(),
            };
            let common = self.common(
                identity,
                resolved,
                Some(worktree_path.to_owned()),
                Some(local.clone()),
                invocation,
                exit,
                &outcome,
                dirty,
            );
            return Ok(WorktreeCreateReceipt {
                common,
                worktree_path: worktree_path.to_owned(),
                rev: rev.to_owned(),
                lease: local,
            });
        };
        let common = self.common(
            identity,
            resolved,
            Some(worktree_path.to_owned()),
            Some(lease.clone()),
            invocation,
            exit,
            &outcome,
            dirty,
        );
        Ok(WorktreeCreateReceipt {
            common,
            worktree_path: worktree_path.to_owned(),
            rev: rev.to_owned(),
            lease,
        })
    }

    /// Typed lease-aware worktree remove: never uses `--force`.
    ///
    /// The presented lease must scope the exact worktree path. Removal runs
    /// plain `git worktree remove <path>`; a dirty/locked worktree fails the
    /// operation instead of being destroyed.
    ///
    /// # Errors
    /// Identity/root/lease failures, runner failures, or git failures.
    pub fn worktree_remove(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        worktree_path: &Path,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<WorktreeRemoveReceipt, BridgeError> {
        let (resolved, lease) =
            self.admit(identity, root, admission, lease, Some(worktree_path))?;
        // Removal is always lease-aware: without a validated lease covering
        // this exact worktree there is no receipt to carry, so refuse — even
        // for service-owned roots.
        let lease = lease.ok_or(BridgeError::BrokerLeaseRequired)?;
        let dirty = self.is_dirty(&resolved)?;
        let args = vec![
            "worktree".to_owned(),
            "remove".to_owned(),
            worktree_path.to_string_lossy().into_owned(),
        ];
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        self.check_success(&outcome, &invocation)?;
        let common = self.common(
            identity,
            resolved,
            Some(worktree_path.to_owned()),
            Some(lease),
            invocation,
            exit,
            &outcome,
            dirty,
        );
        Ok(WorktreeRemoveReceipt {
            common,
            worktree_path: worktree_path.to_owned(),
        })
    }

    /// Typed patch check: reports applicability without modifying the repo.
    ///
    /// Runs `git apply --check -v` with the patch on stdin. A non-zero exit
    /// is reported as `applicable == false` on the receipt (not an error);
    /// only identity/root/lease, runner, or invocation failures error.
    ///
    /// # Errors
    /// Identity/root/lease failures, runner failures, or invocation failures.
    pub fn patch_check(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        patch: &[u8],
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<PatchCheckReceipt, BridgeError> {
        let (resolved, lease) = self.admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let args = vec!["apply".to_owned(), "--check".to_owned(), "-v".to_owned()];
        let (outcome, invocation, exit) = self.exec_stdin(args, &resolved, patch)?;
        let applicable = outcome.code == 0;
        let common = self.common(
            identity, resolved, None, lease, invocation, exit, &outcome, dirty,
        );
        Ok(PatchCheckReceipt { common, applicable })
    }

    /// Typed patch apply: guarded mutation, never destructive.
    ///
    /// Runs the dirty-state preflight (refusing when `require_clean` and the
    /// tree is dirty), then re-runs the non-mutating check fail-fast
    /// ([`BridgeError::PatchCheckFailed`]), and finally `git apply -v` with
    /// the patch on stdin. No reset, checkout, or clean is ever issued.
    ///
    /// # Errors
    /// Identity/root/lease failures, dirty-guard refusals, inapplicable
    /// patches, runner failures, or git failures.
    pub fn patch_apply(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        patch: &[u8],
        require_clean: bool,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<PatchApplyReceipt, BridgeError> {
        let (resolved, lease) = self.admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        if dirty && require_clean {
            return Err(BridgeError::DirtyWorktree(format!(
                "refusing patch apply on dirty root {}",
                resolved.display()
            )));
        }
        let check_args = vec!["apply".to_owned(), "--check".to_owned(), "-v".to_owned()];
        let (check_outcome, _, _) = self.exec_stdin(check_args, &resolved, patch)?;
        if check_outcome.code != 0 {
            return Err(BridgeError::PatchCheckFailed(
                String::from_utf8_lossy(&check_outcome.stderr).into_owned(),
            ));
        }
        let args = vec!["apply".to_owned(), "-v".to_owned()];
        let (outcome, invocation, exit) = self.exec_stdin(args, &resolved, patch)?;
        self.check_success(&outcome, &invocation)?;
        let common = self.common(
            identity, resolved, None, lease, invocation, exit, &outcome, dirty,
        );
        Ok(PatchApplyReceipt {
            common,
            patch_sha256: sha256_hex(patch),
        })
    }

    /// Typed `blame` (read-only line ownership).
    ///
    /// # Errors
    /// Identity/root/lease failures, runner failures, or git failures.
    pub fn blame(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        path: &str,
        rev: Option<&str>,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<BlameReceipt, BridgeError> {
        let (resolved, lease) = self.admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let mut args = vec!["blame".to_owned(), "--line-porcelain".to_owned()];
        if let Some(rev) = rev {
            args.push(rev.to_owned());
        }
        args.push("--".to_owned());
        args.push(path.to_owned());
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        self.check_success(&outcome, &invocation)?;
        let text = String::from_utf8_lossy(&outcome.stdout);
        let mut lines = Vec::new();
        let mut current_rev = String::new();
        let mut line_no: u64 = 0;
        for raw in text.lines() {
            if let Some(rest) = raw.strip_prefix('\t') {
                line_no += 1;
                lines.push(BlameLine {
                    rev: current_rev.clone(),
                    line_no,
                    content: rest.to_owned(),
                });
            } else if is_hex_prefix(raw) {
                current_rev = raw.split_whitespace().next().unwrap_or("").to_owned();
            }
        }
        let common = self.common(
            identity, resolved, None, lease, invocation, exit, &outcome, dirty,
        );
        Ok(BlameReceipt {
            common,
            path: path.to_owned(),
            lines,
        })
    }

    /// Typed `log` (read-only history, newest first, bounded by `limit`).
    ///
    /// # Errors
    /// Identity/root/lease failures, runner failures, or git failures.
    pub fn log(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        limit: u32,
        path: Option<&str>,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<LogReceipt, BridgeError> {
        let (resolved, lease) = self.admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let mut args = vec![
            "log".to_owned(),
            "--no-color".to_owned(),
            "--format=%H%x1f%aI%x1f%an%x1f%s%x1e".to_owned(),
            format!("-n{limit}"),
        ];
        if let Some(path) = path {
            args.push("--".to_owned());
            args.push(path.to_owned());
        }
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        self.check_success(&outcome, &invocation)?;
        let text = String::from_utf8_lossy(&outcome.stdout);
        let mut entries = Vec::new();
        for record in text.split('\x1e') {
            let record = record.trim_start_matches('\n');
            if record.trim().is_empty() {
                continue;
            }
            let mut fields = record.splitn(4, '\x1f');
            let (Some(rev), Some(date), Some(author), Some(subject)) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            entries.push(LogEntry {
                rev: rev.trim().to_owned(),
                date: date.to_owned(),
                author: author.to_owned(),
                subject: subject.trim_end().to_owned(),
            });
        }
        let common = self.common(
            identity, resolved, None, lease, invocation, exit, &outcome, dirty,
        );
        Ok(LogReceipt { common, entries })
    }

    /// Typed co-change mining over `git log --name-only` (read-only).
    ///
    /// Counts files committed alongside `path` in the last `limit` commits
    /// touching it, sorted by count descending.
    ///
    /// # Errors
    /// Identity/root/lease failures, runner failures, or git failures.
    pub fn cochange(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        path: &str,
        limit: u32,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<CochangeReceipt, BridgeError> {
        let (resolved, lease) = self.admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let args = vec![
            "log".to_owned(),
            "--no-color".to_owned(),
            "--format=COMMIT:%H".to_owned(),
            "--name-only".to_owned(),
            format!("-n{limit}"),
            "--".to_owned(),
            path.to_owned(),
        ];
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        self.check_success(&outcome, &invocation)?;
        let text = String::from_utf8_lossy(&outcome.stdout);
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut current_files: Vec<String> = Vec::new();
        let mut touched_target = false;
        let flush = |files: &[String], touched: bool, counts: &mut BTreeMap<String, u64>| {
            if !touched {
                return;
            }
            for f in files {
                if f != path {
                    *counts.entry(f.clone()).or_insert(0) += 1;
                }
            }
        };
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("COMMIT:") {
                flush(&current_files, touched_target, &mut counts);
                current_files.clear();
                touched_target = false;
            } else if line.is_empty() {
                continue;
            } else {
                if line == path {
                    touched_target = true;
                }
                current_files.push(line.to_owned());
            }
        }
        flush(&current_files, touched_target, &mut counts);
        let mut cochanged: Vec<(String, u64)> = counts.into_iter().collect();
        cochanged.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        cochanged.truncate(16);
        let common = self.common(
            identity, resolved, None, lease, invocation, exit, &outcome, dirty,
        );
        Ok(CochangeReceipt {
            common,
            path: path.to_owned(),
            cochanged,
        })
    }

    /// Typed change manifest: status entries joined with `diff --numstat`.
    ///
    /// # Errors
    /// Identity/root/lease failures, runner failures, or git failures.
    pub fn change_manifest(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<ChangeManifestReceipt, BridgeError> {
        let (resolved, lease) = self.admit(identity, root, admission, lease, None)?;
        // Single status probe serves both parsing and the receipt invocation,
        // so the receipt cannot disagree with the parsed entries. A failed
        // probe is a git failure like every other typed operation.
        let status_args = vec![
            "status".to_owned(),
            "--porcelain=v1".to_owned(),
            "--untracked-files=normal".to_owned(),
        ];
        let (outcome, invocation, exit) = self.exec(status_args, &resolved)?;
        self.check_success(&outcome, &invocation)?;
        let numstat_args = vec![
            "diff".to_owned(),
            "--no-color".to_owned(),
            "--numstat".to_owned(),
            "HEAD".to_owned(),
            "--".to_owned(),
        ];
        // numstat against HEAD can fail on unborn HEAD; treat as empty.
        let numstat = match self.exec(numstat_args, &resolved) {
            Ok((outcome, invocation, _)) if outcome.code == 0 => {
                let _ = invocation;
                String::from_utf8_lossy(&outcome.stdout).into_owned()
            }
            Ok(_) | Err(_) => String::new(),
        };
        let mut stats: BTreeMap<String, (Option<u64>, Option<u64>)> = BTreeMap::new();
        for line in numstat.lines() {
            let mut parts = line.splitn(3, '\t');
            let (Some(added), Some(removed), Some(path)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            stats.insert(path.to_owned(), (added.parse().ok(), removed.parse().ok()));
        }
        let status_text = String::from_utf8_lossy(&outcome.stdout);
        let mut entries = Vec::new();
        for line in status_text.lines() {
            if line.len() < 4 {
                continue;
            }
            let path = line[3..].to_owned();
            let (added, removed) = stats.remove(&path).unwrap_or((None, None));
            entries.push(ManifestEntry {
                path,
                xy: line[..2].to_owned(),
                added,
                removed,
            });
        }
        let dirty = !entries.is_empty();
        let common = self.common(
            identity, resolved, None, lease, invocation, exit, &outcome, dirty,
        );
        Ok(ChangeManifestReceipt {
            common,
            dirty,
            entries,
        })
    }

    /// Typed base drift: merge base plus ahead/behind counts (read-only).
    ///
    /// # Errors
    /// Identity/root/lease failures, runner failures, or git failures.
    pub fn base_drift(
        &self,
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        base: &str,
        head: &str,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
    ) -> Result<BaseDriftReceipt, BridgeError> {
        let (resolved, lease) = self.admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let mb_args = vec!["merge-base".to_owned(), base.to_owned(), head.to_owned()];
        let (mb_outcome, _, _) = self.exec(mb_args, &resolved)?;
        let merge_base = if mb_outcome.code == 0 {
            let s = String::from_utf8_lossy(&mb_outcome.stdout)
                .trim()
                .to_owned();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        };
        let count_args = vec![
            "rev-list".to_owned(),
            "--left-right".to_owned(),
            "--count".to_owned(),
            format!("{base}...{head}"),
        ];
        let (outcome, invocation, exit) = self.exec(count_args, &resolved)?;
        self.check_success(&outcome, &invocation)?;
        let text = String::from_utf8_lossy(&outcome.stdout);
        let mut parts = text.split_whitespace();
        let behind = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let ahead = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let common = self.common(
            identity, resolved, None, lease, invocation, exit, &outcome, dirty,
        );
        Ok(BaseDriftReceipt {
            common,
            base: base.to_owned(),
            head: head.to_owned(),
            merge_base,
            ahead,
            behind,
        })
    }
}

// ---------------------------------------------------------------------------
// Small helpers (dependency-free)
// ---------------------------------------------------------------------------

fn best_effort_canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned())
}

fn is_hex_prefix(line: &str) -> bool {
    let head = line.split_whitespace().next().unwrap_or("");
    head.len() >= 7 && head.chars().all(|c| c.is_ascii_hexdigit())
}

fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = String::with_capacity(64);
    for word in h {
        out.push_str(&format!("{word:08x}"));
    }
    out
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use std::sync::Mutex;

    /// Scripted fake port: canned outputs per subcommand, records invocations.
    pub struct FakeRunner {
        pub invocations: Mutex<Vec<Vec<String>>>,
        pub status_porcelain: String,
        pub fail_check: bool,
        pub fail_status: bool,
    }

    impl FakeRunner {
        pub fn new(status_porcelain: &str) -> Self {
            Self {
                invocations: Mutex::new(Vec::new()),
                status_porcelain: status_porcelain.to_owned(),
                fail_check: false,
                fail_status: false,
            }
        }

        fn record(&self, exe: &str, args: &[&str]) {
            let mut argv = vec![exe.to_owned()];
            argv.extend(args.iter().map(ToString::to_string));
            self.invocations.lock().expect("lock").push(argv);
        }
    }

    impl ProcessRunner for FakeRunner {
        fn run(
            &self,
            exe: &str,
            args: &[&str],
            _cwd: &Path,
            _stdin: &[u8],
        ) -> Result<ProcessOutcome, String> {
            self.record(exe, args);
            let stdout = if args.first() == Some(&"status") {
                if self.fail_status {
                    return Ok(ProcessOutcome {
                        code: 128,
                        stdout: Vec::new(),
                        stderr: b"fatal: not a git repository\n".to_vec(),
                    });
                }
                self.status_porcelain.clone().into_bytes()
            } else if args == ["apply", "--check", "-v"] {
                if self.fail_check {
                    return Ok(ProcessOutcome {
                        code: 1,
                        stdout: Vec::new(),
                        stderr: b"error: patch failed\n".to_vec(),
                    });
                }
                b"Checking patch...\n".to_vec()
            } else if args.first() == Some(&"branch") {
                b"* main\n  feature\n".to_vec()
            } else if args.first() == Some(&"rev-list") {
                b"2\t5\n".to_vec()
            } else if args.first() == Some(&"merge-base") {
                b"abc123\n".to_vec()
            } else {
                Vec::new()
            };
            Ok(ProcessOutcome {
                code: 0,
                stdout,
                stderr: Vec::new(),
            })
        }
    }

    #[test]
    fn sha256_matches_empty_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn destructive_invocations_are_rejected() {
        assert!(validate_invocation("git", &["reset", "--hard"]).is_err());
        assert!(validate_invocation("git", &["reset"]).is_err());
        assert!(validate_invocation("git", &["checkout", "--", "."]).is_err());
        assert!(validate_invocation("git", &["clean", "-fd"]).is_err());
        assert!(validate_invocation("git", &["worktree", "remove", "--force", "p"]).is_err());
        assert!(validate_invocation("git", &["branch", "-D", "x"]).is_err());
        assert!(validate_invocation("git", &["push", "--force"]).is_err());
        // Ordinary read / guarded-write argv stays admitted.
        assert!(validate_invocation("git", &["status", "--porcelain=v1"]).is_ok());
        assert!(validate_invocation("git", &["apply", "--check", "-v"]).is_ok());
        assert!(validate_invocation("git", &["worktree", "remove", "p"]).is_ok());
    }

    #[test]
    fn user_root_without_lease_is_refused() {
        let tmp = std::env::temp_dir();
        let bridge = GitBridge::new(FakeRunner::new(""));
        let id = ExecutionIdentity::new("sid-user").expect("sid");
        let root = RepoRoot::new(tmp, OwnerKind::User).expect("root");
        let err = bridge.status(&id, &root, None, None).expect_err("lease");
        assert_eq!(err, BridgeError::BrokerLeaseRequired);
    }

    #[test]
    fn lease_scope_mismatch_is_refused() {
        let tmp = std::env::temp_dir();
        let bridge = GitBridge::new(FakeRunner::new(""));
        let id = ExecutionIdentity::new("sid-a").expect("sid");
        let root = RepoRoot::new(tmp.clone(), OwnerKind::User).expect("root");
        let other = ExecutionIdentity::new("sid-b").expect("sid");
        let broker = Broker::new();
        let lease = broker.issue_repo_lease(&other, &root);
        let err = bridge
            .status(&id, &root, None, Some(&lease))
            .expect_err("scope");
        assert!(matches!(err, BridgeError::LeaseScopeMismatch(_)));
    }

    #[test]
    fn patch_apply_refuses_dirty_when_clean_required() {
        let tmp = std::env::temp_dir();
        let bridge = GitBridge::new(FakeRunner::new(" M dirty.txt\n"));
        let id = ExecutionIdentity::new("sid-svc").expect("sid");
        let root = RepoRoot::new(tmp, OwnerKind::Service).expect("root");
        let err = bridge
            .patch_apply(&id, &root, b"patch", true, None, None)
            .expect_err("dirty");
        assert!(matches!(err, BridgeError::DirtyWorktree(_)));
    }

    #[test]
    fn patch_apply_refuses_inapplicable_patch() {
        let tmp = std::env::temp_dir();
        let mut runner = FakeRunner::new("");
        runner.fail_check = true;
        let bridge = GitBridge::new(runner);
        let id = ExecutionIdentity::new("sid-svc").expect("sid");
        let root = RepoRoot::new(tmp, OwnerKind::Service).expect("root");
        let err = bridge
            .patch_apply(&id, &root, b"bogus", false, None, None)
            .expect_err("check");
        assert!(matches!(err, BridgeError::PatchCheckFailed(_)));
    }

    #[test]
    fn change_manifest_reports_git_failure() {
        let tmp = std::env::temp_dir();
        let mut runner = FakeRunner::new("");
        runner.fail_status = true;
        let bridge = GitBridge::new(runner);
        let id = ExecutionIdentity::new("sid-svc").expect("sid");
        let root = RepoRoot::new(tmp, OwnerKind::Service).expect("root");
        let err = bridge
            .change_manifest(&id, &root, None, None)
            .expect_err("status failure must error");
        assert!(matches!(err, BridgeError::GitFailed { .. }));
    }

    #[test]
    fn local_worktree_leases_are_unique_per_create() {
        let tmp = std::env::temp_dir();
        let bridge = GitBridge::new(FakeRunner::new(""));
        let id = ExecutionIdentity::new("sid-svc").expect("sid");
        let root = RepoRoot::new(tmp.clone(), OwnerKind::Service).expect("root");
        let first_path = tmp.join("eliot-1830-local-a");
        let second_path = tmp.join("eliot-1830-local-b");
        let first = bridge
            .worktree_create(&id, &root, &first_path, "HEAD", false, None, None)
            .expect("first create");
        let second = bridge
            .worktree_create(&id, &root, &second_path, "HEAD", false, None, None)
            .expect("second create");
        assert_ne!(
            first.lease.id(),
            second.lease.id(),
            "each minted scope record must be unique"
        );
        assert_eq!(first.lease.worktree(), Some(first_path.as_path()));
        assert_eq!(second.lease.worktree(), Some(second_path.as_path()));
        assert_eq!(
            first.common.lease.as_ref().map(Lease::id),
            Some(first.lease.id())
        );
    }

    #[test]
    fn service_root_rejects_cross_sid_lease() {
        let tmp = std::env::temp_dir();
        let bridge = GitBridge::new(FakeRunner::new(""));
        let id = ExecutionIdentity::new("sid-a").expect("sid");
        let root = RepoRoot::new(tmp.clone(), OwnerKind::Service).expect("root");
        let other = ExecutionIdentity::new("sid-b").expect("sid");
        let broker = Broker::new();
        let lease = broker.issue_repo_lease(&other, &root);
        let err = bridge
            .status(&id, &root, None, Some(&lease))
            .expect_err("cross-SID lease");
        assert!(matches!(err, BridgeError::LeaseScopeMismatch(_)));
    }
}
