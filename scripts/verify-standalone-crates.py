#!/usr/bin/env python3
"""Run the gate for every crate that is deliberately outside the workspace.

A crate carrying its own `[workspace]` table is invisible to
`cargo check --locked --workspace --all-targets`, so nothing in `just verify`
or CI covers it. `crates/foundation/eliot-conformance-contracts` is such a
crate: its `[package.metadata.eliot].workspace_admission` records that joining
the workspace is *forbidden* until its admission conditions are met, yet it
ships 1 424 lines and 16 passing tests that no gate runs.

It also compile-checks the test targets of every package listed in the root
workspace `exclude` (Cargo.toml:216), which no workspace-wide `cargo test`
reaches, with a locked no-run build per package when `<crate>/Cargo.lock`
exists and an offline no-run build otherwise (lockless libraries).

That excluded cohort is currently EMPTY: the root `exclude` list measures
`exclude = []` with 188 members. So the excluded-capability-cell leg below
covers zero crates today, and `--list` reports `exclude:` for none of them.
This is recorded as a measured value, not as an assumed one: an empty
exclusion set is not evidence that every unadmitted crate is admitted. The
discovery is tree-derived and the count is printed, so the denominator can
never again be stated here as a number the code does not produce.

This verifier discovers those crates from the tree rather than a hand-written
list, and runs fmt, clippy and the tests for each one. It does not admit any
crate to the workspace and does not change any admission decision.

It also proves that the workspace member set and the standalone-crate set are
one consistent pair, which discovery alone cannot do. `standalone_crates`
subtracts the member set, so a crate that is simultaneously a member and a
declared standalone crate would simply vanish from its output; the consistency
check therefore compares three INDEPENDENT sources instead of re-checking one
of them against itself:

- the workspace member set as Cargo itself resolves it
  (`cargo metadata --locked --no-deps`), which is the one existing owner of
  `[workspace] members`, compared against the root manifest's own array;
- the standalone-crate set declared in
  `workstreams/security/standalone-crate-dispositions.toml`, the checked-in
  disposition set that already owns these crates;
- the standalone-crate set discovered from the tree by the rule above.

Each non-member crate's resolver identity is bound to what its own resolver will
act on: `[package] name` and `version` read from that crate's own manifest and
cross-checked against its declared row. The crate is additionally required to be
absent from the root `Cargo.lock`, which is the root resolver's identity set.
Nothing here adds a second member registry, a second lock or a second owner:
crate identity stays Cargo's, and the standalone disposition stays owned by the
disposition file.

Closed `--mode compile` (accepted issue #3004, selected only by the
`MergeCompile` verification profile) keeps the same runtime discovery but
compiles every discovered target without executing any test binary: fmt check,
bounded clippy with normal warning semantics (no `-D warnings` oracle), and
`cargo test --no-run --all-targets` with the existing locked/offline per-crate
distinction. A mode named compile never calls the execution path.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

# The one existing owner of the standalone-crate disposition set. This gate
# reads it to CHECK consistency; it never discovers from it and never writes it.
DISPOSITIONS_REL = Path("workstreams/security/standalone-crate-dispositions.toml")
LOCK_REL = Path("Cargo.lock")
# `cargo metadata --locked --no-deps` resolves the workspace without building
# anything and without touching the network: `--locked` refuses a lockfile that
# would change and `--no-deps` resolves workspace members only.
CARGO_METADATA = ("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1")

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
    #   convention scripts/verify.ps1:291); the root workspace.exclude
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


def compile_steps(crate: Path) -> tuple[tuple[str, tuple[str, ...]], ...]:
    # Compile-only cohort for `--mode compile` (issue #3004): same runtime
    # discovery as the normal path, but fmt check, bounded clippy with normal
    # warning semantics (deliberately no `-D warnings` Review oracle), and a
    # no-run test-target build. The locked/offline flag keeps the existing
    # per-crate rule from exclude_norun_steps (Cargo.lock present -> --locked,
    # lockless library -> --offline). No step here executes a test binary.
    flag = "--locked" if (crate / "Cargo.lock").is_file() else "--offline"
    return (
        ("fmt", ("cargo", "fmt", "--manifest-path", "{manifest}", "--", "--check")),
        ("clippy", ("cargo", "clippy", "--manifest-path", "{manifest}", flag, "--all-targets", "--no-deps")),
        ("test-no-run", ("cargo", "test", "--manifest-path", "{manifest}", flag, "--no-run", "--all-targets")),
    )


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
    # Every declared entry must resolve to exactly one readable package
    # manifest. A missing, malformed, or package-less manifest fails loudly
    # instead of vanishing from `--list`, so the MergeCompile denominator
    # receipt (issue #3004 W4) accounts for every declared excluded input.
    _, exclude = workspace_paths(root)
    found: list[Path] = []
    for relative in sorted(exclude):
        manifest = root / relative / "Cargo.toml"
        if not manifest.is_file():
            raise SystemExit(
                f"STANDALONE_CRATES: FAIL declared-but-missing excluded manifest: {relative}/Cargo.toml"
            )
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise SystemExit(
                f"STANDALONE_CRATES: FAIL malformed excluded manifest: {relative}/Cargo.toml ({exc})"
            ) from exc
        if "package" not in data:
            raise SystemExit(
                f"STANDALONE_CRATES: FAIL excluded manifest without [package]: {relative}/Cargo.toml"
            )
        found.append(manifest.parent)
    return found


def cargo_resolved_members(root: Path) -> set[str]:
    """The workspace member set exactly as Cargo itself resolves it.

    Cargo is the one existing owner of `[workspace] members`; this gate reads its
    resolution instead of re-deriving the array, so the comparison below never
    checks the root manifest against itself (A0.3: a second ungoverned canonical
    owner is a hard boundary). A resolution failure is a failure, never an
    empty set.
    """
    completed = subprocess.run(
        list(CARGO_METADATA), cwd=root, capture_output=True, text=True
    )
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout or "").strip().splitlines()[-8:]
        raise SystemExit(
            "STANDALONE_CRATES: FAIL cargo could not resolve the workspace member "
            "set: " + " | ".join(tail)
        )
    members: set[str] = set()
    for package in json.loads(completed.stdout)["packages"]:
        directory = Path(package["manifest_path"]).resolve().parent
        try:
            members.add(directory.relative_to(root).as_posix())
        except ValueError as error:
            raise SystemExit(
                "STANDALONE_CRATES: FAIL cargo resolved a member outside the "
                f"repository: {package['manifest_path']}"
            ) from error
    return members


def declared_standalone_rows(root: Path) -> dict[str, dict]:
    """The declared standalone-crate set, read from its one owning record."""
    path = root / DISPOSITIONS_REL
    if not path.is_file():
        raise SystemExit(
            f"STANDALONE_CRATES: FAIL missing {DISPOSITIONS_REL.as_posix()}, the "
            "one owning record of the standalone-crate set"
        )
    rows = tomllib.loads(path.read_text(encoding="utf-8")).get("crate", [])
    return {str(row.get("path")): row for row in rows if isinstance(row, dict)}


def root_locked_packages(root: Path) -> set[str]:
    """Package identities the ROOT resolver locked, read from the root lockfile."""
    lock = root / LOCK_REL
    if not lock.is_file():
        return set()
    return set(re.findall(r'name\s*=\s*"([^"]+)"', lock.read_text(encoding="utf-8")))


def set_consistency_failures(root: Path, crates: list[Path], excluded: list[Path]) -> list[str]:
    """The member set and the standalone set, compared as independent sets.

    `crates` is derived by subtracting the member set, so it cannot detect a
    crate that is in both. This compares the Cargo-resolved member set, the root
    manifest's own member array, the declared disposition set and the discovered
    set against one another, and binds each non-member crate's resolver identity
    to its own manifest.
    """
    failures: list[str] = []
    resolved_members = cargo_resolved_members(root)
    declared_members, declared_exclude = workspace_paths(root)
    rows = declared_standalone_rows(root)

    # The member set: Cargo's resolution against the declared array.
    unresolved = sorted(declared_members - resolved_members)
    undeclared = sorted(resolved_members - declared_members)
    if unresolved:
        failures.append(f"declared workspace members Cargo does not resolve: {unresolved}")
    if undeclared:
        failures.append(f"Cargo resolves members the root manifest does not declare: {undeclared}")

    # The standalone-crate set: the declared record against tree discovery.
    discovered = {crate.relative_to(root).as_posix() for crate in crates}
    declared = set(rows)
    missing = sorted(discovered - declared)
    stale = sorted(declared - discovered)
    if missing:
        failures.append(f"discovered standalone crates without a declared row: {missing}")
    if stale:
        failures.append(f"declared standalone rows that are not standalone crates: {stale}")

    # Disjointness, in both directions against both member-side sets.
    for relative in sorted(declared & (resolved_members | declared_members | declared_exclude)):
        failures.append(
            f"{relative}: declared standalone crate is also an admitted or excluded "
            "workspace input"
        )
    for relative in sorted(discovered & (resolved_members | declared_members)):
        failures.append(
            f"{relative}: discovered standalone crate is also a workspace member"
        )

    # Resolver identity: bound to the crate's own manifest, and absent from the
    # root resolver's identity set.
    locked = root_locked_packages(root)
    for relative in sorted(discovered | set(c for c in declared_exclude)):
        manifest = root / relative / "Cargo.toml"
        if not manifest.is_file():
            failures.append(f"{relative}: no readable Cargo.toml for its resolver identity")
            continue
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        package = data.get("package")
        if not isinstance(package, dict):
            failures.append(f"{relative}: manifest carries no [package] to bind an identity")
            continue
        name = str(package.get("name", ""))
        version = str(package.get("version", ""))
        if not name or not version:
            failures.append(f"{relative}: resolver identity needs [package] name and version")
            continue
        if "workspace" not in data:
            failures.append(
                f"{relative}: a non-member crate must carry its own [workspace] table so "
                "the root resolver does not own it"
            )
        if name in locked:
            failures.append(
                f"{relative}: {name} is in the root Cargo.lock, so the root resolver "
                "owns an identity this gate treats as non-member"
            )
        row = rows.get(relative)
        if row is not None and str(row.get("package", "")) != name:
            failures.append(
                f"{relative}: declared package {row.get('package')!r} disagrees with the "
                f"crate's own manifest name {name!r}"
            )
    return failures


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
    parser.add_argument(
        "--mode",
        choices=("full", "compile"),
        default="full",
        help="full: fmt, clippy -D warnings and executed tests (default); "
        "compile: closed compile-only mode for the MergeCompile profile, never executes a test binary",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    crates = standalone_crates(root)
    excluded = exclude_crates(root)
    # Fail closed before anything is reported or run: a `--list` printed from an
    # inconsistent pair is exactly the denominator receipt this issue's
    # consistency property exists to keep honest.
    consistency = set_consistency_failures(root, crates, excluded)
    if consistency:
        print(
            f"STANDALONE_CRATES: FAIL set-consistency issues={len(consistency)} "
            f"crates={len(crates)} excluded={len(excluded)}"
        )
        for failure in consistency:
            print(f"  - {failure}")
        return 1
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
    if args.mode == "compile":
        for crate in crates:
            failures.extend(run_crate_steps(root, crate, compile_steps(crate)))
        for crate in excluded:
            failures.extend(run_crate_steps(root, crate, exclude_norun_steps(crate)))
    else:
        for crate in crates:
            failures.extend(run_crate_steps(root, crate, STEPS))
        for crate in excluded:
            failures.extend(run_crate_steps(root, crate, exclude_norun_steps(crate)))

    total = len(crates) + len(excluded)
    if failures:
        print(f"STANDALONE_CRATES: FAIL crates={total} mode={args.mode} failures={len(failures)}")
        return 1
    print(f"STANDALONE_CRATES: PASS crates={total} mode={args.mode} steps={len(STEPS)} exclude_norun={len(excluded)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
