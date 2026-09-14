#!/usr/bin/env python3
"""Run the gate for every crate that is deliberately outside the workspace.

A crate carrying its own `[workspace]` table is invisible to
`cargo check --locked --workspace --all-targets`, so nothing in `just verify`
or CI covers it. `crates/foundation/eliot-conformance-contracts` is such a
crate: its `[package.metadata.eliot].workspace_admission` records that joining
the workspace is *forbidden* until its admission conditions are met, yet it
ships 1 424 lines and 16 passing tests that no gate runs.

It also compile-checks the test targets of every package listed in the root
workspace `exclude` (Cargo.toml:139-185), which no workspace-wide `cargo test`
reaches, with a locked no-run build per package when `<crate>/Cargo.lock`
exists and an offline no-run build otherwise (lockless libraries).

This verifier discovers those crates from the tree rather than a hand-written
list, and runs fmt, clippy and the tests for each one. It does not admit any
crate to the workspace and does not change any admission decision.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from pathlib import Path

STEPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("fmt", ("cargo", "fmt", "--manifest-path", "{manifest}", "--", "--check")),
    ("clippy", ("cargo", "clippy", "--manifest-path", "{manifest}", "--all-targets", "--", "-D", "warnings")),
    ("test", ("cargo", "test", "--manifest-path", "{manifest}", "--all-targets")),
)

def exclude_norun_steps(crate: Path) -> tuple[tuple[str, tuple[str, ...]], ...]:
    # Runtime flag selection per package (never a hardcoded per-package list):
    # - `cargo test --help` documents `--locked` as
    #   "Assert that `Cargo.lock` will remain unchanged", `--offline` as
    #   "Run without accessing the network", and `--frozen` as
    #   "Equivalent to specifying both --locked and --offline".
    # - For lockless packages `--locked` fails before compiling with
    #   "cannot create the lock file ... because --locked was passed" plus
    #   "help: ... remove the --locked flag and use --offline instead", so the
    #   lockless cohort uses `--offline` (documented equivalent per that help;
    #   compiles all targets without network using the cached registry).
    # - If `<crate>/Cargo.lock` exists, keep `--locked` (locked-cargo
    #   convention scripts/verify.ps1:291); the 45 root workspace.exclude
    #   packages are lockless libraries (no committed Cargo.lock;
    #   crates/*/*/Cargo.lock gitignored per .gitignore:77), so they take the
    #   `--offline` branch. A generated Cargo.lock is gitignored build output
    #   (harmless, matches existing STEPS test behavior which also creates
    #   them). `--all-targets` matches the existing test step scope
    #   (scripts/verify-standalone-crates.py:31); `--no-run` compiles without
    #   executing.
    if (crate / "Cargo.lock").is_file():
        return (("test-no-run", ("cargo", "test", "--manifest-path", "{manifest}", "--locked", "--no-run", "--all-targets")),)
    return (("test-no-run", ("cargo", "test", "--manifest-path", "{manifest}", "--offline", "--no-run", "--all-targets")),)


def workspace_paths(root: Path) -> tuple[set[str], set[str]]:
    data = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    return set(data.get("members", [])), set(data.get("exclude", []))


def standalone_crates(root: Path) -> list[Path]:
    """Crates outside every gate: own `[workspace]`, not a member, not excluded.

    A crate listed in `workspace.exclude` is an unadmitted capability cell whose
    own work unit owns its gate, so it is not the repository gate's business.
    What is left is a crate no gate covers at all.
    """
    members, exclude = workspace_paths(root)
    found: list[Path] = []
    ignored_parts = {"target", "testdata", "fixtures"}
    for manifest in sorted(root.rglob("Cargo.toml")):
        if any(part in ignored_parts for part in manifest.parts) or manifest == root / "Cargo.toml":
            continue
        text = manifest.read_text(encoding="utf-8")
        if "[workspace]" not in text:
            continue
        relative = manifest.parent.relative_to(root).as_posix()
        if relative in members or relative in exclude:
            continue
        data = tomllib.loads(text)
        if "package" not in data:
            continue
        found.append(manifest.parent)
    return found


def exclude_crates(root: Path) -> list[Path]:
    # Discovered at runtime from `workspace.exclude` in the root Cargo.toml
    # (scripts/verify-standalone-crates.py:42-44); never a hardcoded list.
    _, exclude = workspace_paths(root)
    found: list[Path] = []
    for relative in sorted(exclude):
        manifest = root / relative / "Cargo.toml"
        if not manifest.is_file():
            continue
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        if "package" not in data:
            continue
        found.append(manifest.parent)
    return found


def run_crate_steps(root: Path, crate: Path, steps: tuple[tuple[str, tuple[str, ...]], ...]) -> list[str]:
    relative = crate.relative_to(root).as_posix()
    manifest = str(crate / "Cargo.toml")
    failures: list[str] = []
    for label, template in steps:
        command = [part.format(manifest=manifest) for part in template]
        completed = subprocess.run(command, cwd=root, capture_output=True, text=True)
        if completed.returncode != 0:
            failures.append(f"{relative}: {label}")
            tail = (completed.stderr or completed.stdout or "").strip().splitlines()[-8:]
            print(f"STANDALONE_CRATE_FAIL: {relative} step={label}")
            for line in tail:
                print(f"    {line}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--list", action="store_true", help="print the discovered crates and exit")
    args = parser.parse_args()
    root = args.root.resolve()

    crates = standalone_crates(root)
    excluded = exclude_crates(root)
    if args.list:
        for path in crates:
            print(path.relative_to(root).as_posix())
        for path in excluded:
            print(f"exclude: {path.relative_to(root).as_posix()}")
        return 0
    if not crates and not excluded:
        print("STANDALONE_CRATES: PASS crates=0")
        return 0

    failures: list[str] = []
    for crate in crates:
        failures.extend(run_crate_steps(root, crate, STEPS))
    for crate in excluded:
        failures.extend(run_crate_steps(root, crate, exclude_norun_steps(crate)))

    total = len(crates) + len(excluded)
    if failures:
        print(f"STANDALONE_CRATES: FAIL crates={total} failures={len(failures)}")
        return 1
    print(f"STANDALONE_CRATES: PASS crates={total} steps={len(STEPS)} exclude_norun={len(excluded)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
