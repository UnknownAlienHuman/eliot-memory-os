#!/usr/bin/env python3
"""Apply the bounded #83 deadline-watcher ownership/fail-closed patch.

The script is intentionally bound to the exact main-branch Git blob observed on
2026-08-29. It refuses to edit any other source revision and removes no code
outside the process-executor owner.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path

EXPECTED_GIT_BLOB_SHA1 = "3825051a4e89b9d40e70a0ed3c68dfd047c7f8ac"
TARGET = Path("crates/instrument/eliot-process-executor/src/lib.rs")
CARGO = Path("crates/instrument/eliot-process-executor/Cargo.toml")


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact match, found {count}")
    return source.replace(old, new, 1)


def apply(source: str) -> str:
    source = replace_once(
        source,
        """enum CaptureFailureDisposition {
    SpawnFailed,
    Timeout,
    Panicked,
    Incomplete,
    ReadFailed,
}

#[cfg(windows)]
struct Operation {
""",
        """enum CaptureFailureDisposition {
    SpawnFailed,
    Timeout,
    Panicked,
    Incomplete,
    ReadFailed,
}

#[cfg(windows)]
struct DeadlineWatcher {
    thread_id: String,
    thread: Option<JoinHandle<()>>,
}

#[cfg(windows)]
impl DeadlineWatcher {
    fn from_thread(thread: JoinHandle<()>) -> Self {
        Self {
            thread_id: format!("{:?}", thread.thread().id()),
            thread: Some(thread),
        }
    }

    fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }

    fn join(mut self) -> Result<(), ProcessExecutionError> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread.join().map_err(|_| {
            unavailable(format!(
                "deadline watcher {} panicked before ownership release",
                self.thread_id
            ))
        })
    }
}

#[cfg(windows)]
struct Operation {
""",
        "deadline watcher identity and owner",
    )

    source = replace_once(
        source,
        """    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    deadline: Instant,
""",
        """    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    deadline_watcher: Option<DeadlineWatcher>,
    deadline: Instant,
""",
        "operation owns deadline watcher",
    )

    source = replace_once(
        source,
        """                if !join_streams(&mut guard) {
                    poison_operation(&mut guard, &self.poisoned);
                    cleanup_unknown = true;
                    continue;
                }
                ids.push(id.clone());
""",
        """                if !join_streams(&mut guard) {
                    poison_operation(&mut guard, &self.poisoned);
                    cleanup_unknown = true;
                    continue;
                }
                match join_finished_deadline_watcher(&mut guard) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(_) => {
                        quarantine_operation(&mut guard);
                        cleanup_unknown = true;
                        continue;
                    }
                }
                ids.push(id.clone());
""",
        "cleanup retains watcher ownership until join",
    )

    source = replace_once(
        source,
        """            if !retain_cleanup_owners {
                operations.clear();
""",
        """            for operation in operations.values() {
                match join_deadline_watcher_bounded(operation) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => {
                        let mut guard = operation
                            .lock()
                            .map_err(|_| unavailable("operation lock poisoned"))?;
                        quarantine_operation(&mut guard);
                        retain_cleanup_owners = true;
                    }
                }
            }
            if !retain_cleanup_owners {
                operations.clear();
""",
        "shutdown joins deadline watchers",
    )

    source = replace_once(
        source,
        """                stdout_thread,
                stderr_thread,
                deadline,
""",
        """                stdout_thread,
                stderr_thread,
                deadline_watcher: None,
                deadline,
""",
        "initialize watcher owner",
    )

    source = replace_once(
        source,
        """            spawn_deadline_watcher(operation, Arc::clone(&self.poisoned));
            Ok(receipt)
""",
        """            let deadline_watcher = match spawn_deadline_watcher(Arc::clone(&operation)) {
                Ok(watcher) => watcher,
                Err(_) => {
                    let mut guard = operation.lock().map_err(|_| {
                        self.poisoned.store(true, Ordering::Release);
                        ProcessExecutionError::UnknownOutcome
                    })?;
                    if finalize_operation(&mut guard, ExitDisposition::Unknown, false).is_err() {
                        quarantine_operation(&mut guard);
                    }
                    return Err(ProcessExecutionError::UnknownOutcome);
                }
            };
            let mut guard = operation.lock().map_err(|_| {
                self.poisoned.store(true, Ordering::Release);
                ProcessExecutionError::UnknownOutcome
            })?;
            guard.deadline_watcher = Some(deadline_watcher);
            if guard.cleanup_required
                || guard.state.view().lifecycle() == ProcessLifecycle::UnknownOutcome
            {
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            drop(guard);
            Ok(receipt)
""",
        "deadline spawn failure contains resumed child",
    )

    source = replace_once(
        source,
        """fn refresh_operation(operation: &mut Operation) -> Result<(), ProcessExecutionError> {
    if operation.state.view().lifecycle().is_terminal() {
        return Ok(());
    }
""",
        """fn refresh_operation(operation: &mut Operation) -> Result<(), ProcessExecutionError> {
    let lifecycle = operation.state.view().lifecycle();
    if lifecycle.is_terminal() || lifecycle == ProcessLifecycle::UnknownOutcome {
        return Ok(());
    }
""",
        "unknown outcome remains reconcilable",
    )

    source = replace_once(
        source,
        """#[cfg(windows)]
fn poison_operation(operation: &mut Operation, poisoned: &AtomicBool) {
    operation.cleanup_required = true;
    poisoned.store(true, Ordering::Release);
    let _ = fence_unknown(operation);
}

#[cfg(windows)]
fn spawn_deadline_watcher(operation: Arc<Mutex<Operation>>, poisoned: Arc<AtomicBool>) {
    let _ = thread::Builder::new()
        .name("eliot-p04-deadline".to_owned())
        .spawn(move || {
            loop {
                thread::sleep(WATCH_INTERVAL);
                let Ok(mut guard) = operation.lock() else {
                    return;
                };
                if guard.state.view().lifecycle().is_terminal() {
                    return;
                }
                if refresh_operation(&mut guard).is_err() {
                    // A failed observation is an external-state gap, not a
                    // reason to detach the Job.  Fence the operation as
                    // unknown and retain it for explicit reconciliation or
                    // final shutdown cleanup.
                    poison_operation(&mut guard, &poisoned);
                    return;
                }
            }
        });
}

#[cfg(windows)]
fn join_streams(operation: &mut Operation) -> bool {
""",
        """#[cfg(windows)]
fn quarantine_operation(operation: &mut Operation) {
    operation.cleanup_required = true;
    let _ = fence_unknown(operation);
}

#[cfg(windows)]
fn poison_operation(operation: &mut Operation, poisoned: &AtomicBool) {
    quarantine_operation(operation);
    poisoned.store(true, Ordering::Release);
}

#[cfg(all(test, windows))]
static FAIL_NEXT_DEADLINE_WATCHER_SPAWN: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
fn spawn_deadline_watcher(
    operation: Arc<Mutex<Operation>>,
) -> Result<DeadlineWatcher, ProcessExecutionError> {
    #[cfg(test)]
    if FAIL_NEXT_DEADLINE_WATCHER_SPAWN.swap(false, Ordering::AcqRel) {
        return Err(unavailable("injected deadline watcher spawn failure"));
    }
    let thread = spawn_named_thread("eliot-p04-deadline", move || {
        loop {
            thread::sleep(WATCH_INTERVAL);
            let Ok(mut guard) = operation.lock() else {
                return;
            };
            let lifecycle = guard.state.view().lifecycle();
            if lifecycle.is_terminal()
                || lifecycle == ProcessLifecycle::UnknownOutcome
                || guard.child.is_none()
            {
                return;
            }
            if refresh_operation(&mut guard).is_err() {
                // An operation-local observation gap retains the exact Job and
                // evidence owner. It does not disable unrelated operations.
                quarantine_operation(&mut guard);
                return;
            }
        }
    })?;
    Ok(DeadlineWatcher::from_thread(thread))
}

fn spawn_named_thread<F>(
    name: &'static str,
    task: F,
) -> Result<JoinHandle<()>, ProcessExecutionError>
where
    F: FnOnce() + Send + 'static,
{
    spawn_named_thread_with(name, task, |builder, task| builder.spawn(task))
}

fn spawn_named_thread_with<F, S>(
    name: &'static str,
    task: F,
    spawner: S,
) -> Result<JoinHandle<()>, ProcessExecutionError>
where
    F: FnOnce() + Send + 'static,
    S: FnOnce(thread::Builder, F) -> std::io::Result<JoinHandle<()>>,
{
    spawner(thread::Builder::new().name(name.to_owned()), task)
        .map_err(|error| unavailable(format!("{name} spawn failed: {error}")))
}

#[cfg(windows)]
fn join_finished_deadline_watcher(
    operation: &mut Operation,
) -> Result<bool, ProcessExecutionError> {
    let Some(watcher) = operation.deadline_watcher.as_ref() else {
        return Ok(true);
    };
    if !watcher.is_finished() {
        return Ok(false);
    }
    let Some(watcher) = operation.deadline_watcher.take() else {
        return Ok(true);
    };
    watcher.join()?;
    Ok(true)
}

#[cfg(windows)]
fn join_deadline_watcher_bounded(
    operation: &Arc<Mutex<Operation>>,
) -> Result<bool, ProcessExecutionError> {
    let deadline = Instant::now()
        .checked_add(STREAM_JOIN_TIMEOUT)
        .unwrap_or_else(Instant::now);
    loop {
        let joined = {
            let mut guard = operation
                .lock()
                .map_err(|_| unavailable("operation lock poisoned"))?;
            join_finished_deadline_watcher(&mut guard)?
        };
        if joined {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(STREAM_JOIN_POLL);
    }
}

#[cfg(windows)]
fn join_streams(operation: &mut Operation) -> bool {
""",
        "watcher spawn and ownership helpers",
    )

    source = replace_once(
        source,
        """fn unavailable(error: impl std::fmt::Display) -> ProcessExecutionError {
    ProcessExecutionError::Unavailable(error.to_string())
}
""",
        """fn unavailable(error: impl std::fmt::Display) -> ProcessExecutionError {
    ProcessExecutionError::Unavailable(error.to_string())
}

#[cfg(test)]
mod tests;
""",
        "register process-executor fault tests",
    )

    return source


def apply_cargo(source: str) -> str:
    return replace_once(
        source,
        """[lints]
workspace = true
""",
        """[dev-dependencies]
eliot-platform.workspace = true

[lints]
workspace = true
""",
        "test-only platform clock dependency",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", type=Path, nargs="?", default=Path.cwd())
    parser.add_argument("--skip-blob-check", action="store_true")
    parser.add_argument("--no-format", action="store_true")
    args = parser.parse_args()

    target = args.repo / TARGET
    data = target.read_bytes()
    observed = git_blob_sha1(data)
    if not args.skip_blob_check and observed != EXPECTED_GIT_BLOB_SHA1:
        raise RuntimeError(
            f"refusing stale edit: {TARGET} blob is {observed}, expected {EXPECTED_GIT_BLOB_SHA1}"
        )

    target.write_text(apply(data.decode("utf-8")), encoding="utf-8", newline="\n")

    cargo = args.repo / CARGO
    cargo.write_text(apply_cargo(cargo.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")

    if not args.no_format:
        subprocess.run(["cargo", "fmt", "--all"], cwd=args.repo, check=True)

    print(f"patched {TARGET} and {CARGO}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
