#!/usr/bin/env python3
"""Run the gate for every crate that is deliberately outside the workspace.

A crate carrying its own `[workspace]` table is invisible to
`cargo check --locked --workspace --all-targets`, so nothing in `just verify`
or CI covers it. `crates/foundation/eliot-conformance-contracts` is such a
crate: its `[package.metadata.eliot].workspace_admission` records that joining
the workspace is *forbidden* until its admission conditions are met, yet it
ships 1 424 lines and 16 passing tests that no gate runs.

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
    for manifest in sorted(root.rglob("Cargo.toml")):
        if "target" in manifest.parts or manifest == root / "Cargo.toml":
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--list", action="store_true", help="print the discovered crates and exit")
    args = parser.parse_args()
    root = args.root.resolve()

    crates = standalone_crates(root)
    if args.list:
        for path in crates:
            print(path.relative_to(root).as_posix())
        return 0
    if not crates:
        print("STANDALONE_CRATES: PASS crates=0")
        return 0

    failures: list[str] = []
    for crate in crates:
        relative = crate.relative_to(root).as_posix()
        manifest = str(crate / "Cargo.toml")
        for label, template in STEPS:
            command = [part.format(manifest=manifest) for part in template]
            completed = subprocess.run(command, cwd=root, capture_output=True, text=True)
            if completed.returncode != 0:
                failures.append(f"{relative}: {label}")
                tail = (completed.stderr or completed.stdout or "").strip().splitlines()[-8:]
                print(f"STANDALONE_CRATE_FAIL: {relative} step={label}")
                for line in tail:
                    print(f"    {line}")

    if failures:
        print(f"STANDALONE_CRATES: FAIL crates={len(crates)} failures={len(failures)}")
        return 1
    print(f"STANDALONE_CRATES: PASS crates={len(crates)} steps={len(STEPS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
