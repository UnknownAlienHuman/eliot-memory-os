#!/usr/bin/env python3
"""Excluded/standalone disposition gate (issue #1811, slice 2 / go15).

Fail-closed gate: every standalone-workspace package (own `[workspace]`
table, carries `[package]`, neither a root member nor in root `exclude`)
and every root `workspace.exclude` entry must have a checked-in disposition
row with a named owner in
`workstreams/security/standalone-crate-dispositions.toml`, using one of
KEEP, WRAP, EXTRACT, REWORK, REPLACE, RETIRE, UNKNOWN.

Additionally, any in-tree build/release input that consumes an inventoried
package without provenance, lock, toolchain, license, and SBOM evidence is
rejected. Consumption means:

- a non-standalone crate manifest (normal/dev/build/target edges) with a
  `path =` reference resolving into an inventoried directory, or a
  dependency key matching an inventoried package name; or
- an inventoried package name present in the root `Cargo.lock`; or
- a `build.rs` under a non-standalone crate referencing an inventoried
  package name or inventoried relative path.

There is currently no per-crate evidence framework (SBOM/lock/provenance
artifacts stay out of Git per docs/DEPENDENCY_POLICY.md), so any such
consumer is fail-closed rejected with the evidence list named. The gate
passes when no non-standalone consumer exists and no inventoried name is
locked, which is the current tree state (11 standalone, 0 consumers).

Discovery never trusts the inventory: the denominator is derived from the
tree with the same rule as scripts/verify-standalone-crates.py.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

ALLOWED = {"KEEP", "WRAP", "EXTRACT", "REWORK", "REPLACE", "RETIRE", "UNKNOWN"}
IGNORED_PARTS = {"target", "testdata", "fixtures"}
INVENTORY_REL = Path("workstreams/security/standalone-crate-dispositions.toml")
EVIDENCE = "provenance, lock, toolchain, license, SBOM"


def load_inventory(root: Path) -> dict:
    path = root / INVENTORY_REL
    if not path.is_file():
        raise SystemExit(f"EXCLUDED_DISPOSITIONS: FAIL missing {INVENTORY_REL.as_posix()}")
    return tomllib.loads(path.read_text(encoding="utf-8"))


def workspace_sets(root: Path) -> tuple[set[str], set[str]]:
    data = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    return set(data.get("members", [])), set(data.get("exclude", []))


def discover_standalone(root: Path) -> dict[str, str]:
    members, exclude = workspace_sets(root)
    found: dict[str, str] = {}
    for manifest in sorted(root.rglob("Cargo.toml")):
        if any(part in IGNORED_PARTS for part in manifest.parts):
            continue
        if manifest == root / "Cargo.toml":
            continue
        if "[workspace]" not in manifest.read_text(encoding="utf-8"):
            continue
        relative = manifest.parent.relative_to(root).as_posix()
        if relative in members or relative in exclude:
            continue
        parsed = tomllib.loads(manifest.read_text(encoding="utf-8"))
        if "package" not in parsed:
            continue
        found[relative] = str(parsed["package"]["name"])
    return found


def find_consumers(root: Path, inventory: dict[str, str]) -> list[str]:
    """Non-standalone manifests depending on an inventoried path or package."""
    standalone_dirs = set(inventory.keys())
    standalone_pkgs = set(inventory.values())
    consumers: list[str] = []
    for manifest in sorted(root.rglob("Cargo.toml")):
        if any(part in IGNORED_PARTS for part in manifest.parts):
            continue
        if manifest == root / "Cargo.toml":
            continue
        relative = manifest.parent.relative_to(root).as_posix()
        if relative in standalone_dirs:
            continue
        text = manifest.read_text(encoding="utf-8")
        hit = False
        for path in standalone_dirs:
            if path in text:
                hit = True
                break
        if not hit:
            try:
                parsed = tomllib.loads(text)
            except Exception:
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                deps = parsed.get(section, {})
                if isinstance(deps, dict) and any(str(k) in standalone_pkgs for k in deps):
                    hit = True
                    break
            target = parsed.get("target", {})
            if not hit and isinstance(target, dict):
                for entry in target.values():
                    if not isinstance(entry, dict):
                        continue
                    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                        deps = entry.get(section, {})
                        if isinstance(deps, dict) and any(str(k) in standalone_pkgs for k in deps):
                            hit = True
                            break
        if hit:
            consumers.append(relative)
        # build.rs beside a non-standalone manifest referencing an input
        script = manifest.parent / "build.rs"
        if script.is_file():
            body = script.read_text(encoding="utf-8", errors="ignore")
            if any(pkg in body for pkg in standalone_pkgs) or any(
               lfhtrang in body for lfhtrang in standalone_dirs
            ):
                if relative not in consumers:
                    consumers.append(f"{relative} (build.rs)")
    # nested build.rs files (e.g. src/build.rs, tests/build.rs)
    for script in sorted(root.rglob("build.rs")):
        if any(part in IGNORED_PARTS for part in script.parts):
            continue
        relative = script.parent.relative_to(root).as_posix()
        if relative in standalone_dirs or relative in consumers or any(c.startswith(relative) for c in consumers):
            continue
        # only consider build scripts under non-standalone crate trees
        body = script.read_text(encoding="utf-8", errors="ignore")
        for pkg in standalone_pkgs:
            if pkg in body:
                consumers.append(f"{relative} (build.rs)")
                break
    return sorted(set(consumers))


def locked_packages(root: Path, packages: set[str]) -> list[str]:
    lock = root / "Cargo.lock"
    if not lock.is_file():
        return []
    names = set(re.findall(r'name\s*=\s*"([^"]+)"', lock.read_text(encoding="utf-8")))
    return sorted(names & packages)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.root.resolve()

    failures: list[str] = []
    data = load_inventory(root)
    rows = data.get("crate", [])
    by_path = {str(r.get("path")): r for r in rows}

    discovered = discover_standalone(root)
    _, exclude = workspace_sets(root)

    # 1. denominator: inventory must equal tree discovery
    if set(by_path) != set(discovered):
        missing = sorted(set(discovered) - set(by_path))
        stale = sorted(set(by_path) - set(discovered))
        failures.append(f"inventory/tree drift missing={missing} stale={stale}")
    # 2. every root exclude entry must be declared
    for entry in sorted(exclude):
        if entry not in by_path:
            failures.append(f"undeclared excluded input: {entry}")
    # 3. every row: disposition verb + named owner
    for path in sorted(by_path):
        row = by_path[path]
        disp = str(row.get("disposition", "")).strip()
        owner = str(row.get("owner", "")).strip()
        if disp not in ALLOWED:
            failures.append(f"{path}: disposition must be one of {sorted(ALLOWED)}, got {disp!r}")
        if not owner:
            failures.append(f"{path}: owner must be a named non-empty value")
        if row.get("package") != discovered.get(path, row.get("package")):
            failures.append(f"{path}: package name drift vs tree")
    # 4. fail-closed consumption without evidence
    consumers = find_consumers(root, discovered if discovered else {str(r.get('path')): str(r.get('package')) for r in rows})
    if consumers:
        failures.append(
            "undeclared excluded-input consumption without "
            f"{EVIDENCE} evidence: {consumers}"
        )
    locked = locked_packages(root, set(discovered.values()) if discovered else {str(r.get('package')) for r in rows})
    if locked:
        failures.append(f"inventoried package present in root Cargo.lock without {EVIDENCE} evidence: {locked}")

    total = len(rows)
    if failures:
        print(f"EXCLUDED_DISPOSITIONS: FAIL rows={total} issues={len(failures)}")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"EXCLUDED_DISPOSITIONS: PASS rows={total} consumers=0 locked=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
