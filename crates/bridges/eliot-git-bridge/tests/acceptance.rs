//! Acceptance proof for issue #1830 (I10.9 Git bridge).
//!
//! Minimal by owner order: exactly the acceptance criteria.
//!
//! 1. On a user-owned repo with uncommitted changes, a typed status request
//!    returns a receipt containing the declared SID and root.
//! 2. A worktree request receives a scoped lease.
//! 3. Patch checking reports applicability without modifying the repository.
//! 4. No bridge operation accepts or performs hidden destructive reset
//!    behavior.

use eliot_git_bridge::{
    AclAdmission, BridgeError, ExecutionIdentity, ExecutorRequestPort, ExecutorRunner, GitBridge,
    Lease, OwnerKind, ProcessOutcome, ProcessRunner, RepoRoot, StdProcessRunner,
};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Scripted fake port with canned outputs; records every invocation.
struct FakeRunner {
    invocations: Mutex<Vec<Vec<String>>>,
    status_porcelain: String,
}

impl FakeRunner {
    fn new(status_porcelain: &str) -> Self {
        Self {
            invocations: Mutex::new(Vec::new()),
            status_porcelain: status_porcelain.to_owned(),
        }
    }

    fn argv(&self) -> Vec<Vec<String>> {
        self.invocations.lock().expect("lock").clone()
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
        let mut argv = vec![exe.to_owned()];
        argv.extend(args.iter().map(ToString::to_string));
        self.invocations.lock().expect("lock").push(argv);
        let stdout = if args.first() == Some(&"status") {
            self.status_porcelain.clone().into_bytes()
        } else if args.first() == Some(&"branch") {
            b"* main\n  feature\n".to_vec()
        } else if args.first() == Some(&"rev-list") {
            b"2\t5\n".to_vec()
        } else if args.first() == Some(&"merge-base") {
            b"abc123\n".to_vec()
        } else if args.first() == Some(&"log") {
            b"abc123\x1f2026-01-01\x1fAda\x1finit\x1e".to_vec()
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

fn user_root(path: &Path) -> RepoRoot {
    RepoRoot::new(path, OwnerKind::User).expect("root")
}

#[test]
fn status_receipt_carries_sid_and_root_on_dirty_user_repo() {
    let dir = std::env::temp_dir();
    let bridge = GitBridge::new(FakeRunner::new("## main...origin/main\n M dirty.txt\n"));
    let id = ExecutionIdentity::new("sid-1830-status").expect("sid");
    let root = user_root(&dir);
    let broker = eliot_git_bridge::Broker::new();
    let lease: Lease = broker.issue_repo_lease(&id, &root);

    let receipt = bridge
        .status(&id, &root, None, Some(&lease))
        .expect("status");

    assert_eq!(receipt.common.sid, "sid-1830-status");
    assert!(receipt.common.root.exists());
    assert!(receipt.dirty);
    assert_eq!(receipt.entries.len(), 1);
    assert_eq!(receipt.entries[0].path, "dirty.txt");
    assert!(receipt.common.exit.success);
    assert_eq!(receipt.common.invocation.exe, "git");
}

#[test]
fn worktree_request_receives_scoped_lease_and_requires_one() {
    let dir = std::env::temp_dir();
    let runner = FakeRunner::new("");
    let bridge = GitBridge::new(runner);
    let id = ExecutionIdentity::new("sid-1830-wt").expect("sid");
    let root = user_root(&dir);
    let wt = dir.join("eliot-1830-wt-probe");

    // Without a lease the user-owned worktree request is refused.
    let err = bridge
        .worktree_create(&id, &root, &wt, "HEAD", false, None, None)
        .expect_err("must require lease");
    assert_eq!(err, BridgeError::BrokerLeaseRequired);

    // With a broker lease the request succeeds and the receipt carries it.
    let broker = eliot_git_bridge::Broker::new();
    let lease = broker.issue_worktree_lease(&id, &root, &wt);
    let receipt = bridge
        .worktree_create(&id, &root, &wt, "HEAD", false, None, Some(&lease))
        .expect("worktree create");
    assert_eq!(receipt.lease.id(), lease.id());
    assert_eq!(receipt.lease.sid(), "sid-1830-wt");
    assert_eq!(receipt.common.sid, "sid-1830-wt");

    // Removal is lease-aware: a mismatched worktree is refused.
    let elsewhere = dir.join("eliot-1830-elsewhere");
    let err = bridge
        .worktree_remove(&id, &root, &elsewhere, None, Some(&lease))
        .expect_err("must enforce lease scope");
    assert!(matches!(err, BridgeError::LeaseScopeMismatch(_)));

    let removed = bridge
        .worktree_remove(&id, &root, &wt, None, Some(&lease))
        .expect("worktree remove");
    assert_eq!(removed.worktree_path, wt);
}

// ---------------------------------------------------------------------------
// Real-git proof: patch check is non-mutating on a dirty user-owned repo.
// ---------------------------------------------------------------------------

fn unique_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "eliot-git-bridge-{}-{}-{}",
        tag,
        std::process::id(),
        nanos
    ))
}

fn git(cwd: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn patch_check_is_non_mutating_on_dirty_user_repo() {
    let dir = unique_dir("accept");
    std::fs::create_dir_all(&dir).expect("mkdir");
    git(&dir, &["init"]);
    git(&dir, &["config", "user.name", "t"]);
    git(&dir, &["config", "user.email", "t@t"]);
    git(&dir, &["config", "commit.gpgsign", "false"]);
    std::fs::write(dir.join("file.txt"), "hello\n").expect("write");
    std::fs::write(dir.join("second.txt"), "two\n").expect("write");
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "init"]);

    // Uncommitted user change: the acceptance precondition.
    std::fs::write(dir.join("file.txt"), "hello dirty\n").expect("dirty");

    let bridge = GitBridge::new(StdProcessRunner);
    let id = ExecutionIdentity::new("sid-1830-real").expect("sid");
    let root = user_root(&dir);
    let admission = Some(AclAdmission {
        admits_service_identity: true,
    });

    let status = bridge.status(&id, &root, admission, None).expect("status");
    assert_eq!(status.common.sid, "sid-1830-real");
    assert!(status.common.root.exists());
    assert!(status.dirty, "precondition: repo is dirty");

    let before = std::fs::read(dir.join("second.txt")).expect("read");
    let patch = b"diff --git a/second.txt b/second.txt\n--- a/second.txt\n+++ b/second.txt\n@@ -1 +1 @@\n-two\n+two-patched\n";
    let check = bridge
        .patch_check(&id, &root, patch, admission, None)
        .expect("patch check");
    assert!(check.applicable, "patch must apply cleanly");
    assert!(
        check.common.invocation.args.contains(&"--check".to_owned()),
        "check must run apply --check"
    );
    let after = std::fs::read(dir.join("second.txt")).expect("read");
    assert_eq!(before, after, "patch check must not mutate the repo");
    let dirty_after = std::fs::read(dir.join("file.txt")).expect("read");
    assert_eq!(dirty_after, b"hello dirty\n");

    // Worktree isolation on the real repo: scoped lease in, lease out.
    let broker = eliot_git_bridge::Broker::new();
    let wt = unique_dir("worktree");
    let lease = broker.issue_worktree_lease(&id, &root, &wt);
    let created = bridge
        .worktree_create(&id, &root, &wt, "HEAD", false, None, Some(&lease))
        .expect("worktree create");
    assert_eq!(created.lease.id(), lease.id());
    assert!(wt.join("file.txt").exists());
    bridge
        .worktree_remove(&id, &root, &wt, None, Some(&lease))
        .expect("worktree remove");

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&wt).ok();
}

#[test]
fn no_hidden_destructive_reset_path_exists() {
    let dir = std::env::temp_dir();
    let runner = FakeRunner::new(" M a.txt\n");
    let bridge = GitBridge::new(runner);
    let id = ExecutionIdentity::new("sid-1830-scan").expect("sid");
    let root = RepoRoot::new(&dir, OwnerKind::Service).expect("root");
    let broker = eliot_git_bridge::Broker::new();
    let lease = broker.issue_repo_lease(&id, &root);

    // Exercise every read path plus the guarded write paths.
    let _ = bridge.status(&id, &root, None, Some(&lease)).expect("s");
    let _ = bridge.branch(&id, &root, None, Some(&lease)).expect("b");
    let _ = bridge
        .inspect_commit(&id, &root, "HEAD", None, Some(&lease))
        .expect("c");
    let _ = bridge
        .diff(&id, &root, None, &[], None, Some(&lease))
        .expect("d");
    let _ = bridge
        .blame(&id, &root, "a.txt", None, None, Some(&lease))
        .expect("bl");
    let _ = bridge
        .log(&id, &root, 5, None, None, Some(&lease))
        .expect("l");
    let _ = bridge
        .cochange(&id, &root, "a.txt", 5, None, Some(&lease))
        .expect("cc");
    let _ = bridge
        .change_manifest(&id, &root, None, Some(&lease))
        .expect("m");
    let _ = bridge
        .base_drift(&id, &root, "main", "HEAD", None, Some(&lease))
        .expect("bd");
    let patch = b"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n";
    let _ = bridge
        .patch_check(&id, &root, patch, None, Some(&lease))
        .expect("pc");
    let _ = bridge
        .patch_apply(&id, &root, patch, false, None, Some(&lease))
        .expect("pa");

    for argv in bridge.runner().argv() {
        for token in &argv {
            assert_ne!(token, "reset", "hidden destructive path: {argv:?}");
            assert_ne!(token, "--hard", "hidden destructive path: {argv:?}");
            assert_ne!(
                token, "--force",
                "forced invocation has no place in this bridge: {argv:?}"
            );
        }
    }

    // The guard itself refuses destructive construction.
    assert!(matches!(
        eliot_git_bridge::validate_invocation("git", &["reset", "--hard"]),
        Err(BridgeError::DestructiveOpRejected(_))
    ));
}

#[test]
fn option_like_inputs_are_refused_or_safely_separated_on_real_repo() {
    let dir = unique_dir("optlike");
    std::fs::create_dir_all(&dir).expect("mkdir");
    git(&dir, &["init"]);
    git(&dir, &["config", "user.name", "t"]);
    git(&dir, &["config", "user.email", "t@t"]);
    git(&dir, &["config", "commit.gpgsign", "false"]);
    // Witness file plus a legitimately option-like tracked path.
    std::fs::write(dir.join("witness.txt"), "witness\n").expect("write");
    std::fs::write(dir.join("--tricky.txt"), "tricky\n").expect("write");
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "init"]);

    let bridge = GitBridge::new(StdProcessRunner);
    let id = ExecutionIdentity::new("sid-1830-opt").expect("sid");
    let root = user_root(&dir);
    let admission = Some(AclAdmission {
        admits_service_identity: true,
    });

    // Revision-position input is refused before any process launches.
    let err = bridge
        .inspect_commit(&id, &root, "--all", admission, None)
        .expect_err("rev");
    assert!(matches!(err, BridgeError::InvalidArgument(_)));

    // Path-position input travels after `--`: the option-like path is read
    // as a pathspec, never parsed as a flag.
    let blamed = bridge
        .blame(&id, &root, "--tricky.txt", None, admission, None)
        .expect("blame");
    assert_eq!(blamed.lines.len(), 1);
    assert_eq!(blamed.lines[0].content, "tricky");

    // Nothing was created, removed, or rewritten.
    assert_eq!(
        std::fs::read(dir.join("witness.txt")).expect("read"),
        b"witness\n"
    );
    assert_eq!(
        std::fs::read(dir.join("--tricky.txt")).expect("read"),
        b"tricky\n"
    );
    let status = bridge.status(&id, &root, admission, None).expect("status");
    assert!(!status.dirty);

    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Bound-executor proof: real git through the shared P-04 executor under test
// authority. The composition root plays the authority role here exactly as
// the `s04` executor tests do (one shared authority contour, per-request
// permits); production replaces this scaffolding with the P-07 composition.
// ---------------------------------------------------------------------------

/// Resolves `git` through `PATH` (the harness already requires git).
fn where_git() -> String {
    let out = std::process::Command::new("where")
        .arg("git")
        .output()
        .expect("spawn where");
    assert!(out.status.success(), "git must be on PATH");
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next().expect("where output").trim().to_owned();
    assert!(!first.is_empty(), "where git returned nothing");
    first
}

/// SHA-256 of a file (P-04 verifies the executable digest at launch).
fn sha256_file_hex(path: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let bytes = std::fs::read(path).expect("read executable");
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
#[cfg(windows)]
fn bound_executor_drives_status_and_guarded_worktree() {
    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_platform::ClockObservation;
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
        EnvironmentProjection, EvidenceSinkError, FencingToken, Generation, ImageId, JobId,
        KernelDispatchKey, OperationId, PermitIssuance, ProcessEvidence, ProcessEvidenceSink,
        ProcessExecutionError, ProcessIntent, ProcessRequest, ProcessTreeId, ResourceLimits,
        SessionId, SuspendedProcessIdentity, ValidatedDispatch,
    };
    use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    /// Test composition root: one shared authority contour, per-request
    /// permits, and the request-minting port the bound runner consumes.
    struct TestRoot {
        authority: Mutex<DispatchPermitAuthority>,
        context: DispatchValidationContext,
        fence: FencingToken,
        git_exe: String,
        git_sha: String,
        seq: AtomicU64,
    }

    impl DispatchValidationPort for TestRoot {
        fn validate_and_consume(
            &self,
            request: ProcessRequest,
            observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            let mut authority = self.authority.lock().expect("authority lock");
            authority
                .validate_and_consume(request, observed, &self.context)
                .map_err(Into::into)
        }
    }

    impl ExecutorRequestPort for TestRoot {
        fn bind(&self, exe: &str, args: &[&str], cwd: &Path) -> Result<ProcessRequest, String> {
            assert_eq!(exe, "git", "test root only launches git");
            let n = self.seq.fetch_add(1, Ordering::SeqCst);
            let generation = Generation::new(1).map_err(|e| e.to_string())?;
            let intent = ProcessIntent::new(
                OperationId::new(format!("op-git-bound-{n}")).map_err(|e| e.to_string())?,
                ProcessTreeId::new(format!("tree-git-bound-{n}")).map_err(|e| e.to_string())?,
                JobId::new(format!("job-git-bound-{n}")).map_err(|e| e.to_string())?,
                ImageId::new(format!("image-git-bound-{n}")).map_err(|e| e.to_string())?,
                SessionId::new(format!("session-git-bound-{n}")).map_err(|e| e.to_string())?,
                generation,
                self.git_exe.clone(),
                self.git_sha.clone(),
                args.iter().map(ToString::to_string).collect(),
                cwd.to_string_lossy().into_owned(),
                EnvironmentProjection::default(),
                ResourceLimits::new(
                    30_000,
                    Some(10_000),
                    Some(512_000_000),
                    1u64 << 20,
                    1u64 << 20,
                    16u32,
                )
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let mut authority = self.authority.lock().expect("authority lock");
            let permit = authority
                .issue(
                    &intent,
                    PermitIssuance::new(
                        ActionLeaseRef::new(format!("lease-git-bound-{n}"))
                            .map_err(|e| e.to_string())?,
                        self.fence.clone(),
                        BTreeMap::from([
                            ("authority".to_owned(), "a".repeat(64)),
                            ("state".to_owned(), "b".repeat(64)),
                        ]),
                        100,
                        10_000,
                        format!("nonce-git-bound-{n}"),
                    )
                    .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
            ProcessRequest::new(intent, permit).map_err(|e| e.to_string())
        }
    }

    #[derive(Default)]
    struct TestSink {
        evidence: Mutex<Vec<ProcessEvidence>>,
    }

    impl ProcessEvidenceSink for TestSink {
        fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
            self.evidence.lock().expect("sink lock").push(evidence);
            Ok(())
        }
    }

    fn test_epoch() -> EpochId {
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("test lineage");
        EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("test epoch")
    }

    // Repository fixture with an uncommitted change.
    let dir = unique_dir("bound");
    std::fs::create_dir_all(&dir).expect("mkdir");
    git(&dir, &["init"]);
    git(&dir, &["config", "user.name", "t"]);
    git(&dir, &["config", "user.email", "t@t"]);
    git(&dir, &["config", "commit.gpgsign", "false"]);
    std::fs::write(dir.join("file.txt"), "hello\n").expect("write");
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "init"]);
    std::fs::write(dir.join("file.txt"), "hello dirty\n").expect("dirty");

    // Test authority contour (mirrors the `s04` executor precedent).
    let git_exe = where_git();
    let git_sha = sha256_file_hex(&git_exe);
    let generation = Generation::new(1).expect("generation");
    let fence = FencingToken::new(test_epoch(), generation, "fence-git-bound").expect("fence");
    let authority = DispatchPermitAuthority::activate(
        DispatchAuthorityId::new("auth-git-bound").expect("authority id"),
        KernelDispatchKey::from_secret_bytes([0x5a; 32]).expect("test key"),
    );
    let context = DispatchValidationContext::new(
        ClockObservation {
            valid_time_ms: Some(150),
            known_time_ms: Some(150),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        },
        fence.clone(),
        test_epoch(),
        BTreeMap::from([
            ("authority".to_owned(), "a".repeat(64)),
            ("state".to_owned(), "b".repeat(64)),
        ]),
        41,
    )
    .expect("context");
    let root = Arc::new(TestRoot {
        authority: Mutex::new(authority),
        context,
        fence,
        git_exe,
        git_sha,
        seq: AtomicU64::new(1),
    });
    let sink = Arc::new(TestSink::default());
    let executor = Arc::new(WindowsProcessExecutor::new(root.clone()));
    let runner = ExecutorRunner::new(executor, root, sink.clone());

    // Real git, real executor, real receipts.
    let bridge = GitBridge::new(runner);
    let id = ExecutionIdentity::new("sid-1830-bound").expect("sid");
    let repo = user_root(&dir);
    let admission = Some(AclAdmission {
        admits_service_identity: true,
    });

    let status = bridge
        .status(&id, &repo, admission, None)
        .expect("bound status");
    assert_eq!(status.common.sid, "sid-1830-bound");
    assert!(status.common.root.exists());
    assert!(status.dirty, "precondition: repo is dirty");
    assert_eq!(status.entries.len(), 1);
    assert_eq!(status.entries[0].path, "file.txt");
    assert!(status.common.exit.success);
    assert!(!status.common.stdout.preview.is_empty());

    // Bound mutating-guarded op: worktree create/remove under a broker lease.
    let broker = eliot_git_bridge::Broker::new();
    let wt = unique_dir("bound-wt");
    let lease = broker.issue_worktree_lease(&id, &repo, &wt);
    let created = bridge
        .worktree_create(&id, &repo, &wt, "HEAD", false, None, Some(&lease))
        .expect("bound worktree create");
    assert_eq!(created.lease.id(), lease.id());
    assert!(wt.join("file.txt").exists());
    bridge
        .worktree_remove(&id, &repo, &wt, None, Some(&lease))
        .expect("bound worktree remove");

    // The stdin boundary holds on the bound path: patch preflight cannot run
    // without a stdin channel and fails closed instead of silently dropping
    // the patch.
    let patch = b"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n";
    let err = bridge
        .patch_check(&id, &repo, patch, admission, None)
        .expect_err("stdin");
    assert!(matches!(err, BridgeError::Runner(_)));

    // Evidence flowed through the sink on every bound launch.
    assert!(
        !sink.evidence.lock().expect("lock").is_empty(),
        "bound launches must record evidence"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&wt).ok();
}
