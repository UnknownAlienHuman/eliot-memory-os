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
//!   production binding is [`ExecutorRunner`]: the shared governed executor
//!   (`WindowsProcessExecutor`, the sole P-04 implementation of the
//!   `ProcessExecutor` contract) behind per-call authorized requests minted
//!   by the composition root through [`ExecutorRequestPort`]. This crate
//!   never mints dispatch authority, never spawns private launch/retry
//!   semantics, and never shells out except through the port.
//!   [`StdProcessRunner`] is the local `std::process`-backed port
//!   implementation used by tests, standalone hosts, and the stdin-fed patch
//!   path (P-03 carries no stdin channel, so patch check/apply stay local).
//!   Exact exit codes of completed bound runs are recovered through the
//!   serialized exit observation, following the established `successful_exit`
//!   precedent in `eliot-instrument-runner`.
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
use std::future::Future;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use eliot_process::{
    ExitDisposition as KernelExitDisposition, ExitStatus, ProcessEvidenceSink, ProcessExecutor,
    ProcessRequest,
};
use eliot_process_executor::{CapturedStream, WindowsProcessExecutor};

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

/// Process-wide monotonic broker generation.
///
/// Minted once per [`Broker::new()`] call, so every broker instance holds a
/// distinct generation for as long as leases are in memory. Wrapping on
/// `u64::MAX` is the only reuse path and is practically unreachable
/// (2^64 broker constructions in one process lifetime).
static BROKER_INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Broker that launches scoped adapters by minting [`Lease`] values.
///
/// Each broker owns a per-instance identity domain bound into every lease ID
/// it mints, so leases from separate broker instances never collide even for
/// the same SID and sequence position. The domain is a process-local
/// monotonic generation minted from [`BROKER_INSTANCE_COUNTER`]: an
/// established owner-ID mechanism whose lifetime matches these in-memory
/// leases exactly. Leases die with the process — no cross-process or
/// persistence guarantee is claimed or needed.
#[derive(Debug)]
pub struct Broker {
    sequence: AtomicU64,
    domain: u64,
}

impl Broker {
    /// Creates a broker with a fresh identity domain and lease sequence.
    pub fn new() -> Self {
        Self {
            sequence: AtomicU64::new(1),
            domain: BROKER_INSTANCE_COUNTER.fetch_add(1, Ordering::SeqCst),
        }
    }

    /// Returns this broker's identity domain (bound into minted lease IDs).
    pub fn domain(&self) -> u64 {
        self.domain
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
            id: format!("wt-lease-{:016x}-{n}-{}", self.domain, identity.sid()),
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
            id: format!("repo-lease-{:016x}-{n}-{}", self.domain, identity.sid()),
            sid: identity.sid().to_owned(),
            scope_root: root.path.clone(),
            worktree: None,
            issued_by: "broker".to_owned(),
        }
    }
}

impl Default for Broker {
    /// Creates a broker exactly as [`Broker::new`] does (fresh domain).
    fn default() -> Self {
        Self::new()
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
// Executor binding: shared ProcessExecutor behind the ProcessRunner port
// ---------------------------------------------------------------------------

/// Compile-time proof that the bound executor implements the shared
/// [`ProcessExecutor`] contract: if P-04 ever stops implementing P-03, the
/// binding fails to build instead of silently targeting a fork.
const _: fn() = || {
    fn requires_shared_contract<E: ProcessExecutor>() {}
    requires_shared_contract::<WindowsProcessExecutor>();
};

/// Composition-root seam minting authorized [`ProcessRequest`] values.
///
/// Mirrors `InstrumentRequestPort` in `eliot-instrument-runner`: dispatch
/// permits are Kernel-issued authority, so the bridge never mints requests
/// itself. The production implementation belongs to the runtime composition
/// root; tests play that role with test authority.
pub trait ExecutorRequestPort: Send + Sync {
    /// Binds one invocation to exactly one authorized process request.
    ///
    /// # Errors
    /// Returns a message when the request cannot be minted for this call.
    fn bind(&self, exe: &str, args: &[&str], cwd: &Path) -> Result<ProcessRequest, String>;
}

/// Default bound for the terminal-lifecycle wait (matches the `s04` executor
/// test precedent of a 30-second horizon with 25 ms polls).
pub const BOUND_RUN_DEADLINE: Duration = Duration::from_secs(30);
/// Poll interval for the terminal-lifecycle wait.
const BOUND_RUN_POLL: Duration = Duration::from_millis(25);

/// [`ProcessRunner`] implemented by the shared governed executor.
///
/// The runner is deliberately concrete over [`WindowsProcessExecutor`], the
/// sole physical P-04 implementation: the provider-neutral [`ProcessExecutor`]
/// trait carries launch/inspect/cancel/reconcile but no output readback, so a
/// generic binding could not preserve command-output handles without
/// inventing a shadow seam. Construction mirrors
/// `InstrumentRunner::new`: the composition root supplies the executor, the
/// request-minting port, and the evidence sink; the runner owns no authority.
///
/// Boundaries (fail-closed, documented):
///
/// * P-03 carries no stdin channel, so stdin-fed invocations (patch check /
///   apply) are refused here; those operations stay on the local port.
/// * Truncated or incomplete stream captures are refused: typed parsing needs
///   full streams, and a partial parse must never pose as complete.
/// * Non-completed terminal dispositions, missing exit observations, and
///   deadline overruns surface as runner errors naming the disposition;
///   no synthetic exit code is ever fabricated.
/// * Exact numeric codes of completed exits are recovered through the
///   serialized `code` field, following the established `successful_exit`
///   precedent in `eliot-instrument-runner`.
pub struct ExecutorRunner {
    executor: Arc<WindowsProcessExecutor>,
    port: Arc<dyn ExecutorRequestPort>,
    sink: Arc<dyn ProcessEvidenceSink>,
    deadline: Duration,
}

impl ExecutorRunner {
    /// Binds the runner to a shared executor, a request-minting port, and an
    /// evidence sink.
    pub fn new(
        executor: Arc<WindowsProcessExecutor>,
        port: Arc<dyn ExecutorRequestPort>,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Self {
        Self {
            executor,
            port,
            sink,
            deadline: BOUND_RUN_DEADLINE,
        }
    }

    /// Overrides the terminal-lifecycle wait bound.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Returns the bound shared executor.
    pub fn executor(&self) -> &Arc<WindowsProcessExecutor> {
        &self.executor
    }
}

impl std::fmt::Debug for ExecutorRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutorRunner")
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl ExecutorRunner {
    fn run_via_executor(
        &self,
        exe: &str,
        args: &[&str],
        cwd: &Path,
    ) -> Result<ProcessOutcome, String> {
        let request = self
            .port
            .bind(exe, args, cwd)
            .map_err(|e| format!("executor request binding failed: {e}"))?;
        request
            .validate()
            .map_err(|e| format!("bound request failed validation: {e}"))?;
        let operation = request.operation_id().clone();
        let digest = request.invocation_digest().to_owned();
        let generation = request.generation().get();
        let receipt = block_on(self.executor.start(request, self.sink.clone()))
            .map_err(|e| format!("executor start failed: {e}"))?;
        if receipt.operation_id() != &operation
            || receipt.request_digest() != digest
            || receipt.accepted_generation().get() != generation
        {
            return Err("executor start receipt does not preserve the bound request".to_owned());
        }
        let started = Instant::now();
        let view = loop {
            let view = block_on(self.executor.inspect(operation.clone()))
                .map_err(|e| format!("executor inspect failed: {e}"))?;
            if view.operation_id() != &operation || view.request_digest() != digest {
                return Err("executor observation does not preserve the bound request".to_owned());
            }
            if view.lifecycle().is_terminal() {
                break view;
            }
            if started.elapsed() >= self.deadline {
                return Err(format!(
                    "executor run timed out after {}s waiting for terminal lifecycle",
                    self.deadline.as_secs()
                ));
            }
            std::thread::sleep(BOUND_RUN_POLL);
        };
        let exit = view.exit().ok_or_else(|| {
            "executor reported a terminal lifecycle without an exit observation".to_owned()
        })?;
        let code = exit_code_of(exit)?;
        let (stdout, stderr) = self
            .executor
            .captured_output(&operation)
            .map_err(|e| format!("executor stream readback failed: {e}"))?;
        Ok(ProcessOutcome {
            code,
            stdout: captured_bytes(stdout, "stdout")?,
            stderr: captured_bytes(stderr, "stderr")?,
        })
    }
}

impl ProcessRunner for ExecutorRunner {
    fn run(
        &self,
        exe: &str,
        args: &[&str],
        cwd: &Path,
        stdin: &[u8],
    ) -> Result<ProcessOutcome, String> {
        validate_invocation(exe, args).map_err(|e| e.to_string())?;
        if !stdin.is_empty() {
            return Err("executor binding refuses stdin-fed invocations: P-03 carries no stdin channel; patch operations stay on the local port"
                .to_owned());
        }
        self.run_via_executor(exe, args, cwd)
    }
}

/// Recovers the exact numeric exit code of a completed exit.
///
/// Follows the established `successful_exit` precedent in
/// `eliot-instrument-runner`: the code is read from the serialized exit
/// observation because the typed contract exposes only the coarse
/// disposition. Anything but `Completed` has no meaningful git exit code
/// and is refused fail-closed with the disposition named.
fn exit_code_of(exit: &ExitStatus) -> Result<i32, String> {
    if !matches!(exit.disposition(), KernelExitDisposition::Completed) {
        return Err(format!(
            "executor reports a non-completed exit disposition: {:?}",
            exit.disposition()
        ));
    }
    serde_json::to_value(exit)
        .ok()
        .and_then(|value| value.get("code").and_then(serde_json::Value::as_i64))
        .and_then(|code| i32::try_from(code).ok())
        .ok_or_else(|| "executor completed exit carries no numeric code".to_owned())
}

/// Extracts full stream bytes, refusing partial captures fail-closed.
fn captured_bytes(stream: CapturedStream, name: &'static str) -> Result<Vec<u8>, String> {
    if !stream.captured {
        return Err(format!("executor captured no {name} handle"));
    }
    if !stream.complete {
        return Err(format!("executor {name} capture ended before EOF"));
    }
    if stream.truncated {
        return Err(format!(
            "executor {name} output exceeded the capture ceiling"
        ));
    }
    Ok(stream.bytes)
}

/// Drives one executor future to completion on the calling thread.
///
/// Established precedent: the production `block_on_sink` drain path and the
/// `block_on` test driver in `eliot-process-executor` spin a noop waker with
/// `yield_now`. P-04 futures complete without a reactor; this performs no
/// sleeping, no retry, and no I/O of its own.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
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
    /// A caller-supplied revision or range is option-like and refused before
    /// any process is launched (flag-injection guard).
    InvalidArgument(String),
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
            Self::InvalidArgument(detail) => write!(f, "invalid argument: {detail}"),
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

    fn resolve_root(root: &RepoRoot) -> Result<PathBuf, BridgeError> {
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
        identity: &ExecutionIdentity,
        root: &RepoRoot,
        admission: Option<AclAdmission>,
        lease: Option<&Lease>,
        worktree: Option<&Path>,
    ) -> Result<(PathBuf, Option<Lease>), BridgeError> {
        let resolved = Self::resolve_root(root)?;
        if !resolved.exists() {
            return Err(BridgeError::RootNotFound(resolved));
        }
        let admitted = admission.is_some_and(|a| a.admits_service_identity);
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
            if let Some(lease) = lease
                && lease.sid() != identity.sid()
            {
                return Err(BridgeError::LeaseScopeMismatch(format!(
                    "lease {} is issued to '{}', request runs as '{}'",
                    lease.id(),
                    lease.sid(),
                    identity.sid()
                )));
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
        let arg_slices: Vec<&str> = invocation.args.iter().map(String::as_str).collect();
        validate_invocation(&invocation.exe, &arg_slices)?;
        let outcome = self
            .runner
            .run(
                &invocation.exe,
                &arg_slices,
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
        let arg_slices: Vec<&str> = invocation.args.iter().map(String::as_str).collect();
        validate_invocation(&invocation.exe, &arg_slices)?;
        let outcome = self
            .runner
            .run(&invocation.exe, &arg_slices, &invocation.cwd, stdin)
            .map_err(BridgeError::Runner)?;
        let exit = ExitDisposition {
            code: outcome.code,
            success: outcome.code == 0,
        };
        Ok((outcome, invocation, exit))
    }

    #[allow(clippy::too_many_arguments)]
    fn common(
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

    fn check_success(outcome: &ProcessOutcome, invocation: &Invocation) -> Result<(), BridgeError> {
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
        Self::check_success(&outcome, &invocation)?;
        Ok(!outcome.stdout.iter().all(u8::is_ascii_whitespace))
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
        let (resolved, lease) = Self::admit(identity, root, admission, lease, None)?;
        let args = vec![
            "status".to_owned(),
            "--porcelain=v1".to_owned(),
            "-b".to_owned(),
            "--untracked-files=normal".to_owned(),
        ];
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        Self::check_success(&outcome, &invocation)?;
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
        let common = Self::common(
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
        let (resolved, lease) = Self::admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let args = vec![
            "branch".to_owned(),
            "--list".to_owned(),
            "--no-color".to_owned(),
        ];
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        Self::check_success(&outcome, &invocation)?;
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
        let common = Self::common(
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
        reject_option_like(rev, "rev")?;
        let (resolved, lease) = Self::admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let args = vec![
            "show".to_owned(),
            "-s".to_owned(),
            "--no-color".to_owned(),
            "--format=%H%n%an%n%aI%n%s".to_owned(),
            rev.to_owned(),
        ];
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        Self::check_success(&outcome, &invocation)?;
        let text = String::from_utf8_lossy(&outcome.stdout);
        let mut lines = text.lines();
        let hash = lines.next().unwrap_or("").to_owned();
        let author = lines.next().unwrap_or("").to_owned();
        let date = lines.next().unwrap_or("").to_owned();
        let subject = lines.next().unwrap_or("").to_owned();
        let common = Self::common(
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
        if let Some(range) = rev_range {
            reject_option_like(range, "rev_range")?;
        }
        let (resolved, lease) = Self::admit(identity, root, admission, lease, None)?;
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
        Self::check_success(&outcome, &invocation)?;
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
        let common = Self::common(
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
        reject_option_like(rev, "rev")?;
        let (resolved, lease) = Self::admit(identity, root, admission, lease, Some(worktree_path))?;
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
        Self::check_success(&outcome, &invocation)?;
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
            let common = Self::common(
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
        let common = Self::common(
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
        let (resolved, lease) = Self::admit(identity, root, admission, lease, Some(worktree_path))?;
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
        Self::check_success(&outcome, &invocation)?;
        let common = Self::common(
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
        let (resolved, lease) = Self::admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let args = vec!["apply".to_owned(), "--check".to_owned(), "-v".to_owned()];
        let (outcome, invocation, exit) = self.exec_stdin(args, &resolved, patch)?;
        let applicable = outcome.code == 0;
        let common = Self::common(
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
        let (resolved, lease) = Self::admit(identity, root, admission, lease, None)?;
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
        Self::check_success(&outcome, &invocation)?;
        let common = Self::common(
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
        if let Some(rev) = rev {
            reject_option_like(rev, "rev")?;
        }
        let (resolved, lease) = Self::admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let mut args = vec!["blame".to_owned(), "--line-porcelain".to_owned()];
        if let Some(rev) = rev {
            args.push(rev.to_owned());
        }
        args.push("--".to_owned());
        args.push(path.to_owned());
        let (outcome, invocation, exit) = self.exec(args, &resolved)?;
        Self::check_success(&outcome, &invocation)?;
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
                raw.split_whitespace()
                    .next()
                    .unwrap_or("")
                    .clone_into(&mut current_rev);
            }
        }
        let common = Self::common(
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
        let (resolved, lease) = Self::admit(identity, root, admission, lease, None)?;
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
        Self::check_success(&outcome, &invocation)?;
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
        let common = Self::common(
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
        let (resolved, lease) = Self::admit(identity, root, admission, lease, None)?;
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
        Self::check_success(&outcome, &invocation)?;
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
            } else if !line.is_empty() {
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
        let common = Self::common(
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
        let (resolved, lease) = Self::admit(identity, root, admission, lease, None)?;
        // Single status probe serves both parsing and the receipt invocation,
        // so the receipt cannot disagree with the parsed entries. A failed
        // probe is a git failure like every other typed operation.
        let status_args = vec![
            "status".to_owned(),
            "--porcelain=v1".to_owned(),
            "--untracked-files=normal".to_owned(),
        ];
        let (outcome, invocation, exit) = self.exec(status_args, &resolved)?;
        Self::check_success(&outcome, &invocation)?;
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
        let common = Self::common(
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
        reject_option_like(base, "base")?;
        reject_option_like(head, "head")?;
        let (resolved, lease) = Self::admit(identity, root, admission, lease, None)?;
        let dirty = self.is_dirty(&resolved)?;
        let mb_args = vec!["merge-base".to_owned(), base.to_owned(), head.to_owned()];
        let (mb_outcome, _, _) = self.exec(mb_args, &resolved)?;
        let merge_base = if mb_outcome.code == 0 {
            let s = String::from_utf8_lossy(&mb_outcome.stdout)
                .trim()
                .to_owned();
            if s.is_empty() { None } else { Some(s) }
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
        Self::check_success(&outcome, &invocation)?;
        let text = String::from_utf8_lossy(&outcome.stdout);
        let mut parts = text.split_whitespace();
        let behind = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let ahead = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let common = Self::common(
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

/// Rejects option-like caller input before it can reach git argv.
///
/// Revision-position values (`rev`, ranges, `base`/`head`) cannot be fenced
/// with end-of-options `--` (git would read them as paths), so any value
/// starting with `-` is refused fail-closed here. Path-position values are
/// instead safely separated: every operation places caller paths after an
/// explicit `--`, so git always reads them as pathspecs. [`validate_invocation`]
/// remains the backstop for anything constructed downstream.
fn reject_option_like(value: &str, what: &'static str) -> Result<(), BridgeError> {
    if value.starts_with('-') {
        return Err(BridgeError::InvalidArgument(format!(
            "{what} must not be option-like: {value:?}"
        )));
    }
    Ok(())
}

fn best_effort_canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned())
}

fn is_hex_prefix(line: &str) -> bool {
    let head = line.split_whitespace().next().unwrap_or("");
    head.len() >= 7 && head.chars().all(|c| c.is_ascii_hexdigit())
}

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn sha256_pad(data: &[u8]) -> Vec<u8> {
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    msg
}

fn sha256_compress(digest: &mut [u32; 8], chunk: &[u8]) {
    let mut sched = [0u32; 64];
    for round in 0..16 {
        sched[round] = u32::from_be_bytes([
            chunk[4 * round],
            chunk[4 * round + 1],
            chunk[4 * round + 2],
            chunk[4 * round + 3],
        ]);
    }
    for round in 16..64 {
        let s0 = sched[round - 15].rotate_right(7)
            ^ sched[round - 15].rotate_right(18)
            ^ (sched[round - 15] >> 3);
        let s1 = sched[round - 2].rotate_right(17)
            ^ sched[round - 2].rotate_right(19)
            ^ (sched[round - 2] >> 10);
        sched[round] = sched[round - 16]
            .wrapping_add(s0)
            .wrapping_add(sched[round - 7])
            .wrapping_add(s1);
    }
    let (mut h0, mut h1, mut h2, mut h3, mut h4, mut h5, mut h6, mut h7) = (
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    );
    for round in 0..64 {
        let s1 = h4.rotate_right(6) ^ h4.rotate_right(11) ^ h4.rotate_right(25);
        let ch = (h4 & h5) ^ ((!h4) & h6);
        let t1 = h7
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[round])
            .wrapping_add(sched[round]);
        let s0 = h0.rotate_right(2) ^ h0.rotate_right(13) ^ h0.rotate_right(22);
        let maj = (h0 & h1) ^ (h0 & h2) ^ (h1 & h2);
        let t2 = s0.wrapping_add(maj);
        h7 = h6;
        h6 = h5;
        h5 = h4;
        h4 = h3.wrapping_add(t1);
        h3 = h2;
        h2 = h1;
        h1 = h0;
        h0 = t1.wrapping_add(t2);
    }
    digest[0] = digest[0].wrapping_add(h0);
    digest[1] = digest[1].wrapping_add(h1);
    digest[2] = digest[2].wrapping_add(h2);
    digest[3] = digest[3].wrapping_add(h3);
    digest[4] = digest[4].wrapping_add(h4);
    digest[5] = digest[5].wrapping_add(h5);
    digest[6] = digest[6].wrapping_add(h6);
    digest[7] = digest[7].wrapping_add(h7);
}

fn sha256_hex(data: &[u8]) -> String {
    let mut digest: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let msg = sha256_pad(data);
    for chunk in msg.chunks_exact(64) {
        sha256_compress(&mut digest, chunk);
    }
    let mut out = String::with_capacity(64);
    for word in digest {
        use std::fmt::Write as _;
        // Appending hex into a `String` cannot fail short of allocation
        // failure; the result is intentionally unchecked.
        let _ = write!(out, "{word:08x}");
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
            let mut command = vec![exe.to_owned()];
            command.extend(args.iter().map(ToString::to_string));
            let Ok(mut invocations) = self.invocations.lock() else {
                panic!("invocations lock poisoned");
            };
            invocations.push(command);
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
        let Ok(id) = ExecutionIdentity::new("sid-user") else {
            panic!("sid")
        };
        let Ok(root) = RepoRoot::new(tmp, OwnerKind::User) else {
            panic!("root")
        };
        let Err(err) = bridge.status(&id, &root, None, None) else {
            panic!("lease")
        };
        assert_eq!(err, BridgeError::BrokerLeaseRequired);
    }

    #[test]
    fn lease_scope_mismatch_is_refused() {
        let tmp = std::env::temp_dir();
        let bridge = GitBridge::new(FakeRunner::new(""));
        let Ok(id) = ExecutionIdentity::new("sid-a") else {
            panic!("sid")
        };
        let Ok(root) = RepoRoot::new(tmp.clone(), OwnerKind::User) else {
            panic!("root")
        };
        let Ok(other) = ExecutionIdentity::new("sid-b") else {
            panic!("sid")
        };
        let broker = Broker::new();
        let lease = broker.issue_repo_lease(&other, &root);
        let Err(err) = bridge.status(&id, &root, None, Some(&lease)) else {
            panic!("scope")
        };
        assert!(matches!(err, BridgeError::LeaseScopeMismatch(_)));
    }

    #[test]
    fn patch_apply_refuses_dirty_when_clean_required() {
        let tmp = std::env::temp_dir();
        let bridge = GitBridge::new(FakeRunner::new(" M dirty.txt\n"));
        let Ok(id) = ExecutionIdentity::new("sid-svc") else {
            panic!("sid")
        };
        let Ok(root) = RepoRoot::new(tmp, OwnerKind::Service) else {
            panic!("root")
        };
        let Err(err) = bridge.patch_apply(&id, &root, b"patch", true, None, None) else {
            panic!("dirty")
        };
        assert!(matches!(err, BridgeError::DirtyWorktree(_)));
    }

    #[test]
    fn patch_apply_refuses_inapplicable_patch() {
        let tmp = std::env::temp_dir();
        let mut runner = FakeRunner::new("");
        runner.fail_check = true;
        let bridge = GitBridge::new(runner);
        let Ok(id) = ExecutionIdentity::new("sid-svc") else {
            panic!("sid")
        };
        let Ok(root) = RepoRoot::new(tmp, OwnerKind::Service) else {
            panic!("root")
        };
        let Err(err) = bridge.patch_apply(&id, &root, b"bogus", false, None, None) else {
            panic!("check")
        };
        assert!(matches!(err, BridgeError::PatchCheckFailed(_)));
    }

    #[test]
    fn change_manifest_reports_git_failure() {
        let tmp = std::env::temp_dir();
        let mut runner = FakeRunner::new("");
        runner.fail_status = true;
        let bridge = GitBridge::new(runner);
        let Ok(id) = ExecutionIdentity::new("sid-svc") else {
            panic!("sid")
        };
        let Ok(root) = RepoRoot::new(tmp, OwnerKind::Service) else {
            panic!("root")
        };
        let Err(err) = bridge.change_manifest(&id, &root, None, None) else {
            panic!("status failure must error")
        };
        assert!(matches!(err, BridgeError::GitFailed { .. }));
    }

    #[test]
    fn local_worktree_leases_are_unique_per_create() {
        let tmp = std::env::temp_dir();
        let bridge = GitBridge::new(FakeRunner::new(""));
        let Ok(id) = ExecutionIdentity::new("sid-svc") else {
            panic!("sid")
        };
        let Ok(root) = RepoRoot::new(tmp.clone(), OwnerKind::Service) else {
            panic!("root")
        };
        let first_path = tmp.join("eliot-1830-local-a");
        let second_path = tmp.join("eliot-1830-local-b");
        let Ok(first) = bridge.worktree_create(&id, &root, &first_path, "HEAD", false, None, None)
        else {
            panic!("first create")
        };
        let Ok(second) =
            bridge.worktree_create(&id, &root, &second_path, "HEAD", false, None, None)
        else {
            panic!("second create")
        };
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
        let Ok(id) = ExecutionIdentity::new("sid-a") else {
            panic!("sid")
        };
        let Ok(root) = RepoRoot::new(tmp.clone(), OwnerKind::Service) else {
            panic!("root")
        };
        let Ok(other) = ExecutionIdentity::new("sid-b") else {
            panic!("sid")
        };
        let broker = Broker::new();
        let lease = broker.issue_repo_lease(&other, &root);
        let Err(err) = bridge.status(&id, &root, None, Some(&lease)) else {
            panic!("cross-SID lease")
        };
        assert!(matches!(err, BridgeError::LeaseScopeMismatch(_)));
    }

    #[test]
    fn option_like_revisions_are_refused_before_exec() {
        let tmp = std::env::temp_dir();
        let bridge = GitBridge::new(FakeRunner::new(""));
        let Ok(id) = ExecutionIdentity::new("sid-svc") else {
            panic!("sid")
        };
        let Ok(root) = RepoRoot::new(tmp.clone(), OwnerKind::Service) else {
            panic!("root")
        };
        let Err(err) = bridge.inspect_commit(&id, &root, "--all", None, None) else {
            panic!("rev")
        };
        assert!(matches!(err, BridgeError::InvalidArgument(_)));
        let Err(err) = bridge.diff(&id, &root, Some("--no-index"), &[], None, None) else {
            panic!("range")
        };
        assert!(matches!(err, BridgeError::InvalidArgument(_)));
        let Err(err) = bridge.blame(&id, &root, "a.txt", Some("--all"), None, None) else {
            panic!("blame rev")
        };
        assert!(matches!(err, BridgeError::InvalidArgument(_)));
        let Err(err) = bridge.base_drift(&id, &root, "--all", "HEAD", None, None) else {
            panic!("base")
        };
        assert!(matches!(err, BridgeError::InvalidArgument(_)));
        let Err(err) = bridge.base_drift(&id, &root, "HEAD", "--all", None, None) else {
            panic!("head")
        };
        assert!(matches!(err, BridgeError::InvalidArgument(_)));
        let Err(err) =
            bridge.worktree_create(&id, &root, &tmp.join("wt"), "--force", false, None, None)
        else {
            panic!("worktree rev")
        };
        assert!(matches!(err, BridgeError::InvalidArgument(_)));
        // Refusal happens before admission and launch: no git invocation ran.
        let Ok(invocations) = bridge.runner().invocations.lock() else {
            panic!("invocations lock poisoned");
        };
        assert!(invocations.is_empty());
    }

    #[test]
    fn broker_instances_never_collide_on_lease_identity() {
        let tmp = std::env::temp_dir();
        let Ok(id) = ExecutionIdentity::new("sid-shared") else {
            panic!("sid")
        };
        let Ok(root) = RepoRoot::new(tmp, OwnerKind::Service) else {
            panic!("root")
        };
        let first = Broker::new();
        let second = Broker::new();
        assert_ne!(first.domain(), second.domain());
        // Same SID, same sequence position, different brokers: IDs differ.
        let first_lease = first.issue_repo_lease(&id, &root);
        let second_lease = second.issue_repo_lease(&id, &root);
        assert_ne!(first_lease.id(), second_lease.id());
        let third_lease = first.issue_worktree_lease(&id, &root, "C:/wt-a");
        let fourth_lease = second.issue_worktree_lease(&id, &root, "C:/wt-b");
        assert_ne!(third_lease.id(), fourth_lease.id());
        // A default-constructed broker gets a fresh domain, not a constant.
        let third = Broker::default();
        let fifth_lease = third.issue_repo_lease(&id, &root);
        assert_ne!(fifth_lease.id(), first_lease.id());
        assert_ne!(fifth_lease.id(), second_lease.id());
        // Many rapidly created instances (wall clock and PID effectively
        // constant across the loop) still hold pairwise-distinct domains,
        // proving the mechanism is monotonic generation, not time/PID-derived.
        let mut domains = std::collections::BTreeSet::new();
        let mut lease_ids = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let broker = Broker::new();
            assert!(domains.insert(broker.domain()));
            let lease = broker.issue_repo_lease(&id, &root);
            assert!(lease_ids.insert(lease.id().to_owned()));
        }
        assert!(domains.insert(Broker::default().domain()));
    }

    #[test]
    fn bound_exit_codes_follow_completed_disposition() {
        let Ok(ok) = ExitStatus::new(KernelExitDisposition::Completed, Some(0), None, 1) else {
            panic!("exit")
        };
        assert_eq!(exit_code_of(&ok), Ok(0));
        let Ok(diff) = ExitStatus::new(KernelExitDisposition::Completed, Some(1), None, 1) else {
            panic!("exit")
        };
        assert_eq!(exit_code_of(&diff), Ok(1));
        let Ok(failed) = ExitStatus::new(KernelExitDisposition::Completed, Some(128), None, 1)
        else {
            panic!("exit")
        };
        assert_eq!(exit_code_of(&failed), Ok(128));
        for disposition in [
            KernelExitDisposition::Cancelled,
            KernelExitDisposition::ResourceLimit,
            KernelExitDisposition::Unknown,
        ] {
            let Ok(exit) = ExitStatus::new(disposition, None, None, 1) else {
                panic!("exit")
            };
            assert!(
                exit_code_of(&exit).is_err(),
                "non-completed exits have no git exit code"
            );
        }
        let Ok(signalled) = ExitStatus::new(KernelExitDisposition::Signalled, None, Some(15), 1)
        else {
            panic!("exit")
        };
        assert!(exit_code_of(&signalled).is_err());
    }

    /// Authority port that must never be contacted: every test below fails
    /// before the executor is reached, so any call is a test failure.
    struct UnreachedPort;

    impl eliot_process_executor::DispatchValidationPort for UnreachedPort {
        fn validate_and_consume(
            &self,
            _request: ProcessRequest,
            _observed: eliot_process::SuspendedProcessIdentity,
        ) -> Result<eliot_process::ValidatedDispatch, eliot_process::ProcessExecutionError>
        {
            panic!("bound refusal tests must not reach the executor");
        }
    }

    /// Evidence sink that accepts and drops everything.
    #[derive(Default)]
    struct DropSink;

    impl ProcessEvidenceSink for DropSink {
        fn record(
            &self,
            _evidence: eliot_process::ProcessEvidence,
        ) -> Result<(), eliot_process::EvidenceSinkError> {
            Ok(())
        }
    }

    /// Request port that refuses every binding.
    struct RefusingPort(&'static str);

    impl ExecutorRequestPort for RefusingPort {
        fn bind(&self, _exe: &str, _args: &[&str], _cwd: &Path) -> Result<ProcessRequest, String> {
            Err(self.0.to_owned())
        }
    }

    fn unreached_runner(port: RefusingPort) -> ExecutorRunner {
        let executor = Arc::new(WindowsProcessExecutor::new(Arc::new(UnreachedPort)));
        ExecutorRunner::new(executor, Arc::new(port), Arc::new(DropSink))
    }

    #[test]
    fn bound_runner_refuses_stdin_before_executor_contact() {
        let tmp = std::env::temp_dir();
        let runner = unreached_runner(RefusingPort("unused"));
        let Err(err) = runner.run("git", &["apply", "--check", "-v"], &tmp, b"patch") else {
            panic!("stdin")
        };
        assert!(
            err.contains("stdin"),
            "refusal must name the stdin boundary: {err}"
        );
    }

    #[test]
    fn bound_runner_keeps_the_invocation_guard() {
        let tmp = std::env::temp_dir();
        let runner = unreached_runner(RefusingPort("unused"));
        let Err(err) = runner.run("git", &["reset", "--hard"], &tmp, &[]) else {
            panic!("reset")
        };
        assert!(err.contains("destructive operation rejected"));
    }

    #[test]
    fn bound_runner_maps_bind_failures() {
        let tmp = std::env::temp_dir();
        let runner = unreached_runner(RefusingPort("no authority in unit scope"));
        let Err(err) = runner.run("git", &["status", "--porcelain=v1"], &tmp, &[]) else {
            panic!("bind")
        };
        assert!(err.contains("binding failed"));
    }
}
