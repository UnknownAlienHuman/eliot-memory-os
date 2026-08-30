#!/usr/bin/env python3
"""Source-shape discriminator for the ProcessExecutor deadline owner.

This verifier is deliberately narrow. It rejects the confirmed #83 failure
shape in which a resumed process can receive a successful start receipt while
`thread::Builder::spawn` for the autonomous wall-deadline owner is ignored.

A PASS proves only that the expected ownership/control shape is present in the
reviewed source. It does not prove Windows process containment, Job emptiness,
wall-time enforcement, or package correctness; those require Rust package and
real Windows Edge Proof.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

TARGET = Path("crates/instrument/eliot-process-executor/src/lib.rs")


class VerificationError(RuntimeError):
    """A stable source-shape verification failure."""


@dataclass(frozen=True)
class CheckResult:
    name: str
    detail: str


def fail(message: str) -> None:
    raise VerificationError(f"PROCESS_DEADLINE_OWNER_FAIL: {message}")


def extract_braced_item(source: str, pattern: str, label: str) -> str:
    match = re.search(pattern, source, flags=re.MULTILINE)
    if match is None:
        fail(f"missing {label}")

    brace = source.find("{", match.start())
    if brace < 0:
        fail(f"missing opening brace for {label}")

    depth = 0
    in_string = False
    escaped = False
    index = brace
    while index < len(source):
        char = source[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        else:
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[match.start() : index + 1]
        index += 1

    fail(f"unterminated {label}")


def require_contains(text: str, fragments: Iterable[str], label: str) -> None:
    missing = [fragment for fragment in fragments if fragment not in text]
    if missing:
        fail(f"{label} is missing: {', '.join(missing)}")


def verify_source(source: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    operation = extract_braced_item(
        source,
        r"^(?:pub\s+)?struct\s+Operation\s*\{",
        "Operation owner",
    )
    if not re.search(
        r"\bdeadline_watcher\s*:\s*Option\s*<\s*DeadlineWatcher\s*>",
        operation,
    ):
        fail("Operation does not retain an optional DeadlineWatcher owner")
    results.append(
        CheckResult("operation_owner", "Operation retains the watcher handle")
    )

    watcher = extract_braced_item(
        source,
        r"^fn\s+spawn_deadline_watcher\s*\(",
        "spawn_deadline_watcher",
    )
    signature = watcher[: watcher.find("{")]
    if not re.search(
        r"->\s*Result\s*<\s*DeadlineWatcher\s*,\s*ProcessExecutionError\s*>",
        signature,
        flags=re.DOTALL,
    ):
        fail("spawn_deadline_watcher is not a fallible DeadlineWatcher constructor")
    if re.search(
        r"let\s+_\s*=\s*thread::Builder::new\s*\(\s*\).*?\.spawn\s*\(",
        watcher,
        flags=re.DOTALL,
    ):
        fail("deadline watcher spawn result is still discarded")
    require_contains(
        watcher,
        ("refresh_operation", "quarantine_operation"),
        "deadline watcher loop",
    )
    results.append(
        CheckResult("fallible_spawn", "watcher creation returns an owned result")
    )

    start = extract_braced_item(
        source,
        r"^\s*async\s+fn\s+start\s*\(",
        "ProcessExecutor::start",
    )
    spawn_index = start.find("spawn_deadline_watcher")
    attach_match = re.search(
        r"\.deadline_watcher\s*=\s*Some\s*\(",
        start,
    )
    success_index = start.rfind("Ok(receipt)")
    if spawn_index < 0 or attach_match is None or success_index < 0:
        fail("start lacks watcher creation, attachment, or success receipt")
    if not spawn_index < attach_match.start() < success_index:
        fail("start can publish ProcessStartReceipt before watcher ownership is attached")

    spawn_window = start[spawn_index:attach_match.start()]
    if "UnknownOutcome" not in spawn_window:
        fail("watcher setup failure does not expose an unknown process outcome")
    if not any(
        marker in spawn_window
        for marker in (
            "contain_failed_start",
            "finalize_operation",
            "terminate_in_place",
            "quarantine_operation",
        )
    ):
        fail("watcher setup failure has no visible containment/recovery path")
    results.append(
        CheckResult(
            "receipt_order",
            "successful start is ordered after watcher attachment",
        )
    )

    cleanup = extract_braced_item(
        source,
        r"^\s*pub\s+fn\s+cleanup_finished\s*\(",
        "cleanup_finished",
    )
    shutdown = extract_braced_item(
        source,
        r"^\s*pub\s+fn\s+shutdown\s*\(",
        "shutdown",
    )
    join_markers = (
        "join_finished_deadline_watcher",
        "join_deadline_watcher_bounded",
        "join_deadline_watcher",
    )
    if not any(marker in cleanup for marker in join_markers):
        fail("cleanup_finished does not retain/join the deadline owner")
    if not any(marker in shutdown for marker in join_markers):
        fail("shutdown does not retain/join the deadline owner")
    results.append(
        CheckResult("owner_release", "cleanup and shutdown release watcher ownership")
    )

    if "FAIL_NEXT_DEADLINE_WATCHER_SPAWN" not in source and not re.search(
        r"spawn_deadline_watcher_with\s*<|DeadlineWatcherSpawner",
        source,
    ):
        fail("no deterministic watcher-spawn fault-injection seam is present")
    results.append(
        CheckResult("fault_injection", "watcher spawn failure is injectable")
    )

    production = source.split("#[cfg(test)]", maxsplit=1)[0]
    old_poison_field = "poisoned: Arc<AtomicBool>"
    if old_poison_field in production:
        fail("operation-local watcher failure can still poison the whole executor")
    results.append(
        CheckResult("local_failure", "watcher failure is not executor-global poison")
    )

    return results


def self_test() -> None:
    failing = r'''
struct Operation {
    deadline: Instant,
}
fn spawn_deadline_watcher(operation: Arc<Mutex<Operation>>) {
    let _ = thread::Builder::new().spawn(move || refresh_operation(&mut operation));
}
async fn start() {
    spawn_deadline_watcher(operation);
    Ok(receipt)
}
pub fn cleanup_finished() {}
pub fn shutdown() {}
'''
    try:
        verify_source(failing)
    except VerificationError:
        pass
    else:
        fail("self-test accepted the confirmed discarded-watcher failure shape")

    passing = r'''
struct Operation {
    deadline_watcher: Option<DeadlineWatcher>,
}
fn spawn_deadline_watcher(
    operation: Arc<Mutex<Operation>>,
) -> Result<DeadlineWatcher, ProcessExecutionError> {
    if FAIL_NEXT_DEADLINE_WATCHER_SPAWN.swap(false, Ordering::AcqRel) {
        return Err(unavailable("injected"));
    }
    let _ = refresh_operation;
    let _ = quarantine_operation;
    Ok(DeadlineWatcher::new(operation))
}
async fn start() {
    let deadline_watcher = match spawn_deadline_watcher(operation) {
        Ok(owner) => owner,
        Err(_) => {
            contain_failed_start();
            return Err(ProcessExecutionError::UnknownOutcome);
        }
    };
    guard.deadline_watcher = Some(deadline_watcher);
    Ok(receipt)
}
pub fn cleanup_finished() { join_finished_deadline_watcher(); }
pub fn shutdown() { join_deadline_watcher_bounded(); }
#[cfg(all(test, windows))]
static FAIL_NEXT_DEADLINE_WATCHER_SPAWN: AtomicBool = AtomicBool::new(false);
'''
    results = verify_source(passing)
    if len(results) != 6:
        fail(f"self-test expected 6 checks, observed {len(results)}")

    print("PROCESS_DEADLINE_OWNER_SELF_TEST: PASS cases=2 checks=6")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    target = args.repo / TARGET
    if not target.is_file():
        fail(f"required source is missing: {TARGET}")

    source = target.read_text(encoding="utf-8")
    results = verify_source(source)
    for result in results:
        print(f"PASS {result.name}: {result.detail}")
    print(
        "PROCESS_DEADLINE_OWNER_VERIFY: PASS "
        f"checks={len(results)} proof_ceiling=SOURCE_SHAPE_ONLY"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(error)
        raise SystemExit(1)
