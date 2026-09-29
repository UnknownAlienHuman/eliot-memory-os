#!/usr/bin/env python3
"""Excluded/standalone disposition gate (issue #1811, slices 2-4).

Fail-closed gate: every standalone-workspace package (own `[workspace]`
table, carries `[package]`, neither a root member nor in root `exclude`)
and every root `workspace.exclude` entry must have a checked-in disposition
row with a named owner in
`workstreams/security/standalone-crate-dispositions.toml`, using one of
KEEP, WRAP, EXTRACT, REWORK, REPLACE, RETIRE, UNKNOWN, and must declare the
gate's own supply-chain admission state in `supply_chain_admission`, read from
the admission vocabulary the inventory itself declares.

Additionally, any real build or release input that consumes an inventoried
package is rejected. The product-input closure is derived structurally, not
by substring:

- a non-standalone Cargo manifest edge whose resolved path or aliased package
  identity lands on an inventoried package (normal/dev/build/target sections
  plus `[workspace.dependencies]` inheritance), carrying the host/dev/build/
  proc-macro versus target/runtime role of the edge;
- a `cargo` invocation carrying `--manifest-path`/`-p`/`--package` that names an
  inventoried package, or a script that enters an inventoried package directory
  and then runs `cargo`;
- a byte-moving construct (copy/archive/packaging helper, `include!`/
  `include_str!`/`include_bytes!`) whose path operand resolves into an
  inventoried package: a release copy, bundle, installer or source-bundle
  reference. A path token is an edge only as an operand of such a construct, so
  prose, docstrings, comments and documentation text are not edges;
- any `build.rs` under a real input path (build-output directories excluded,
  never `testdata`/`fixtures`), or an inventoried package name present in the
  root `Cargo.lock`.

The role label distinguishes host/build/proc-macro from target/runtime; the
admission decision does not. Each row declares one state of the inventory's
admission vocabulary in `supply_chain_admission`:

- `deny-all` is the deny marker. The package is not a product input, so every
  role fails closed with the evidence list named. Every row carries it today.
- `evidence-qualified` is the single admitted route for an intentionally
  consumed separate package. It is declared in the inventory and unexercised:
  zero rows carry it, so the live policy stays deny-all and no placeholder
  evidence record is invented. A row qualifies only when its
  `[crate.supply_chain_evidence]` table binds every element the governing
  documents name, with an explicit bound state and an exact binding value, and
  only when its disposition is not UNKNOWN/REPLACE/RETIRE. A KEEP/WRAP/EXTRACT
  row is not sufficient without that evidence and is never a promotion claim
  by itself. A missing, unbound, empty or out-of-taxonomy element refuses the
  row, and a nonproduction admitted use is refused because the I15.9 evidence
  set is a production-artifact requirement set.

A qualified row reached by a real edge is the only case in which an edge onto an
inventoried package is admitted; every other edge, and any inventoried package
present in the root `Cargo.lock`, still fails closed — membership in the root
workspace deletes the row instead of qualifying it.

Discovery never trusts the inventory. The denominator is not re-derived here: it
is read from the accepted Cargo/package discovery owner
`scripts/verify-standalone-crates.py`, whose `workspace_paths` and
`standalone_crates` own root workspace members, root excludes and the
independently rooted package set. An owner that is missing, unloadable or
API-changed refuses the gate, because an empty denominator reads as "no
standalone packages" and is a false proof. The declared
`standalone_package_count` is checked against both the unique inventory rows
and the discovered set, so a stale count fails closed instead of passing
silently.

The decision is emitted as a retained, versioned receipt
(`--receipt-out`, default `.eliot/excluded-dispositions/gate-receipt.json`,
a gitignored output path) naming the exact denominator (package and path, with
the count the gate computed), the admission vocabulary with its admitted set, and
the source/build identity it decided against: source commit and repository, root
manifest, Cargo.lock, build toolchain, inventory and verifier digests,
per-package byte digests, every resolved consumer edge, the I15.9
production-artifact evidence names with a computed per-element state, and the
result. `--receipt` re-validates a retained receipt against the current identity
at the owned pre-publication boundary: a changed source commit, lock, toolchain,
inventory, verifier, trust class, package byte, admission state or admitted set
invalidates it, and a receipt whose cache namespace crosses trust classes is
refused.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

ALLOWED = {"KEEP", "WRAP", "EXTRACT", "REWORK", "REPLACE", "RETIRE", "UNKNOWN"}
# Consumer-scan manifest enumeration only. The DENOMINATOR is no longer derived
# from a local re-parse of these parts: it is read from the accepted discovery
# owner (see `owner_denominator`).
IGNORED_PARTS = {"target", "testdata", "fixtures"}
# The consumer scan never skips test/fixture inputs on principle: a real build
# can run a build script or a packaging script from either location. Only
# build-output and VCS directories are excluded.
SCAN_SKIP_PARTS = {"target", ".git", "node_modules"}
SCRIPT_SUFFIXES = {".ps1", ".psm1", ".py", ".cmd", ".bat", ".sh", ".yml", ".yaml"}
DOCUMENTATION_SUFFIXES = {".md", ".txt", ".rst", ".adoc"}
INVENTORY_REL = Path("workstreams/security/standalone-crate-dispositions.toml")
GATE_REL = Path("scripts/verify-excluded-dispositions-1811.py")
DISCOVERY_OWNER_REL = Path("scripts/verify-standalone-crates.py")
# The exact owner entry points the denominator is read through: root workspace
# members/excludes, and the independently rooted package set. Their absence is a
# refusal, never a locally recomputed fallback.
DISCOVERY_OWNER_SYMBOLS = ("workspace_paths", "standalone_crates")
ROOT_MANIFEST_REL = Path("Cargo.toml")
LOCK_REL = Path("Cargo.lock")
TOOLCHAIN_REL = Path("rust-toolchain.toml")
RECEIPT_SCHEMA = "eliot.excluded-disposition-gate-receipt.v1"
RECEIPT_OUT_REL = Path(".eliot/excluded-dispositions/gate-receipt.json")
RECEIPT_RECHECK_REL = Path(".eliot/excluded-dispositions/gate-recheck-receipt.json")
EVIDENCE = "provenance, lock, toolchain, license, SBOM"
# Supply-chain admission vocabulary (issue #1811, item A4). The vocabulary lives
# in the inventory and is re-read from it on every run, so the inventory, this
# gate and the release seam cannot disagree about which admission states exist.
# `deny-all` is the deny marker; `evidence-qualified` is the one admitted route
# for an intentionally consumed separate package. No row is admitted today, so
# the live policy is the deny marker and nothing here invents an evidence record
# for a package that has none.
DENY_MARKER = "deny-all"
EVIDENCE_ADMISSION = "evidence-qualified"
ADMISSION_STATES_KEY = "allowed_admission_states"
ADMISSION_EVIDENCE_STATE_KEY = "evidence_qualified_state"
ADMISSION_EVIDENCE_COUNT_KEY = "evidence_qualified_package_count"
SUPPLY_CHAIN_ADMISSION_KEY = "supply_chain_admission"
SUPPLY_CHAIN_EVIDENCE_KEY = "supply_chain_evidence"
# The admitted-value a deny-state row's `evidence_reference` must still carry:
# the same declaration as `supply_chain_admission`, kept as its own key.
EVIDENCE_REFERENCE = "deny-all"
# I15.9's evidence set is a *production* artifact requirement set, so an admitted
# row must declare a production use; a fixture, documentation or tool-only use
# cannot be qualified by it.
EVIDENCE_BOUND = "bound"
EVIDENCE_ADMITTED_USES = ("production",)
# UNKNOWN/REPLACE/RETIRE are never a production input (issue #1811 acceptance),
# whatever evidence a row presents.
NON_PRODUCTION_DISPOSITIONS = frozenset({"UNKNOWN", "REPLACE", "RETIRE"})
# Every element an evidence-qualified row must bind, with the governing source
# for each. I15.9 names the production-artifact evidence set; I15.17 adds the
# exact build inputs and the trust/cache identity; I2.18 defines the
# BuildFingerprint; I15.19 requires authenticated origin rather than a digest
# alone. Each must be present as a table with `state = "bound"` and an exact
# binding value.
REQUIRED_EVIDENCE = (
    "source_identity",  # repository, commit and source tree (I15.9, I15.19)
    "independent_lock",  # the package's own lockfile, not the root one (I15.9)
    "build_fingerprint",  # toolchain, target, profile, features (I15.17, I2.18)
    "license",  # license report and decision (I15.9)
    "advisory",  # known vulnerabilities and exceptions (I15.9)
    "sbom",  # SBOM (I15.9)
    "artifact_hash",  # artifact hash (I15.9)
    "artifact_signature",  # artifact signature / origin attestation (I15.9, I15.19)
    "test_canary",  # test and canary receipts (I15.9, I2.18)
    "owner",  # named owner (I15.9)
    "rollback",  # rollback / owner-approved removal boundary (I15.9)
    "trust_class",  # I15.17 build trust class
    "cache_namespace",  # I15.17 dedicated target/cache namespace
    "admitted_use",  # the admitted use class; only a production use qualifies
)
# How each required element maps onto the I15.9 production-artifact evidence
# names the receipt already carries, and who owns the elements this gate does not
# itself produce.
EVIDENCE_TO_I15_9 = {
    "source_identity": "source_commit_and_repository",
    "independent_lock": "cargo_lock_and_build_toolchain",
    "build_fingerprint": "cargo_lock_and_build_toolchain",
    "license": "license_report",
    "advisory": "known_vulnerabilities_and_exceptions",
    "sbom": "sbom",
    "artifact_hash": "artifact_hash_and_signature",
    "artifact_signature": "artifact_hash_and_signature",
    "test_canary": "test_canary_receipts",
    "owner": "owner",
    "rollback": "rollback",
}
I15_9_EVIDENCE_ORDER = (
    "source_commit_and_repository",
    "cargo_lock_and_build_toolchain",
    "license_report",
    "sbom",
    "artifact_hash_and_signature",
    "module_manifest",
    "test_canary_receipts",
    "known_vulnerabilities_and_exceptions",
    "owner",
    "rollback",
)
I15_9_ELEMENT_OWNERS = {
    "license_report": "scripts/verify-dependency-policy.py",
    "sbom": (
        "release build plan; generated SBOM stays out of Git per "
        "docs/DEPENDENCY_POLICY.md"
    ),
    "artifact_hash_and_signature": (
        "scripts/build-eliot-windows-x64-release.ps1 (RELEASE.json, SHA256SUMS.json)"
    ),
    "module_manifest": "per-crate module.toml manifests",
    "test_canary_receipts": "crates/instrument/eliot-build-test-graph (BuildTestGraph, I2.18)",
    "known_vulnerabilities_and_exceptions": "scripts/verify-dependency-policy.py advisory snapshot",
}
# The two computed per-element states: what this decision actually bound itself,
# and an element this gate only routes to its owner. Neither is a placeholder
# record for evidence the gate does not hold.
EVIDENCE_STATE_BOUND = "bound-by-this-gate"
EVIDENCE_STATE_OWNER = "named-owner-not-verified-by-this-gate"
ROLLBACK_DECLARATION = (
    "a package leaves this receipt by moving into the root workspace "
    "(its [[crate]] row is deleted in the same change) or by an "
    "owner-approved removal; an inventory row is never a package deletion"
)
# I15.17 build trust classes. The receipt binds a trust class because I15.17
# requires that "cache identity includes trust class and source/lock/toolchain
# fingerprints" and that "artifact reuse across trust classes or mismatched
# BuildFingerprint is forbidden".
#
# The three values are the DOCUMENT'S OWN taxonomy, quoted from
# docs/architecture/I15-17-agent-generated-rust-build-threat-model.md
# ("Build trust classes:"):
#   T0 known first-party change
#   T1 agent-generated change on admitted dependencies
#   T2 new/untrusted dependency, build script, proc macro or foreign native code
# They are not an invented ladder, and restricting the CLI to one of them would
# make the cross-trust refusal in `recheck_receipt` unreachable: a T0 receipt can
# never disagree with another T0 receipt, so "cross-trust cache reuse refused"
# could never fire. Issue #1811's acceptance requires that cross-trust cache
# reuse IS refused, which needs more than one class to exist.
#
# The DEFAULT is the one value this gate's own caller is: the release seam runs
# the gate on a pinned, clean, isolated first-party source commit with a
# dedicated target root, which is I15.17's T0 ("disposable worktree, dedicated
# target, no user secrets, Job Object limits"). No document names which class
# applies to this gate, hence the derivation above.
TRUST_CLASSES = ("T0", "T1", "T2")
DEFAULT_TRUST_CLASS = "T0"
DEPENDENCY_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")
SECTION_ROLES = {
    "dependencies": "target-runtime",
    "dev-dependencies": "host-dev",
    "build-dependencies": "host-build",
}

CARGO_INVOCATION = re.compile(r"(?:^|[\s;&|(])cargo(?:\.exe)?(?:\s|$)", re.MULTILINE)
MANIFEST_PATH_ARG = re.compile(r"--manifest-path[=\s]+(\S+)")
PACKAGE_SELECTOR_ARG = re.compile(r"(?:^|\s)(?:-p|--package)[=\s]+(\S+)")
LOCATION_CHANGE = re.compile(
    r"(?:Push-Location|Set-Location|pushd|cd|os\.chdir)\b[^\n]*?([^\s;|)]+)"
)
BYTE_MOVING_CONSTRUCT = re.compile(
    r"\b(?:Copy-Item|Copy-PinnedSourceFile|Copy-TrackedTree|Copy-OperatorPayload"
    r"|Copy-VerifiedResidentFile|Write-VerifiedResidentFile|robocopy|xcopy"
    r"|Compress-Archive|make_archive|copyfile|copytree|copy2|shutil\.copy\w*)\b"
)
RUST_INCLUDE = re.compile(r"\b(?:include!|include_str!|include_bytes!)\s*\(\s*(\S+?)\s*[,)]")
PATH_TOKEN = re.compile(r"[A-Za-z0-9_.\-]+(?:[/\\][A-Za-z0-9_.\-]+)+[/\\]?")
QUOTED_TOKEN = re.compile(r"'([^']*)'|\"([^\"]*)\"")
COMMENT_REM = re.compile(r"^\s*(?:REM|rem)\b", re.IGNORECASE)


def load_inventory(root: Path) -> dict:
    path = root / INVENTORY_REL
    if not path.is_file():
        raise SystemExit(f"EXCLUDED_DISPOSITIONS: FAIL missing {INVENTORY_REL.as_posix()}")
    return tomllib.loads(path.read_text(encoding="utf-8"))


def load_discovery_owner(root: Path) -> Any:
    """The accepted Cargo/package discovery owner, loaded or refused.

    `scripts/verify-standalone-crates.py` is the one accepted owner of root
    workspace members, root `workspace.exclude` and the tree-derived
    independently rooted package set (its own docstring names Cargo the owner of
    `[workspace] members` and refuses an empty set when Cargo cannot resolve it).
    This gate reads the denominator from that owner instead of re-parsing the root
    manifest here, because a second in-tool re-parse is a denominator that can
    silently disagree with the owner it claims to reflect.

    A missing, unloadable or API-changed owner is a refusal, never an empty set:
    an empty denominator reads as "there are no standalone packages", which is a
    false proof, not a measurement.
    """
    script = root / DISCOVERY_OWNER_REL
    if not script.is_file():
        raise SystemExit(
            "EXCLUDED_DISPOSITIONS: FAIL missing the Cargo/package discovery owner "
            f"{DISCOVERY_OWNER_REL.as_posix()}; the denominator cannot be derived"
        )
    spec = importlib.util.spec_from_file_location(
        "verify_standalone_crates", script
    )
    if spec is None or spec.loader is None:
        raise SystemExit(
            "EXCLUDED_DISPOSITIONS: FAIL discovery owner "
            f"{DISCOVERY_OWNER_REL.as_posix()} is not importable; the denominator "
            "cannot be derived"
        )
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:  # a broken owner is a refusal, not an empty set
        raise SystemExit(
            "EXCLUDED_DISPOSITIONS: FAIL discovery owner "
            f"{DISCOVERY_OWNER_REL.as_posix()} failed to load ({error}); the "
            "denominator cannot be derived"
        ) from error
    for symbol in DISCOVERY_OWNER_SYMBOLS:
        if not callable(getattr(module, symbol, None)):
            raise SystemExit(
                "EXCLUDED_DISPOSITIONS: FAIL discovery owner "
                f"{DISCOVERY_OWNER_REL.as_posix()} exposes no callable "
                f"{symbol}(root); the denominator cannot be derived"
            )
    return module


def owner_denominator(root: Path) -> tuple[set[str], set[str], dict[str, str]]:
    """The one current denominator, read from the accepted discovery owner.

    Root workspace members and root `workspace.exclude` come from the owner's
    `workspace_paths`, and the independently rooted package set comes from its
    `standalone_crates`. The package NAME of each selected crate is then read from
    that crate's own manifest, because the owner returns crate directories and a
    package identity is a property of the package, not of this gate.
    """
    owner = load_discovery_owner(root)
    members, exclude = owner.workspace_paths(root)
    discovered: dict[str, str] = {}
    for crate in owner.standalone_crates(root):
        relative = crate.relative_to(root).as_posix()
        manifest = crate / ROOT_MANIFEST_REL.name
        try:
            parsed = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise SystemExit(
                "EXCLUDED_DISPOSITIONS: FAIL discovery owner selected "
                f"{relative} but its own manifest is unreadable ({error}); the "
                "denominator cannot be derived"
            ) from error
        package = parsed.get("package")
        if not isinstance(package, dict) or not str(package.get("name", "")).strip():
            raise SystemExit(
                "EXCLUDED_DISPOSITIONS: FAIL discovery owner selected "
                f"{relative} but its own manifest declares no package name; the "
                "denominator cannot be derived"
            )
        discovered[relative] = str(package["name"])
    return set(members), set(exclude), discovered


def is_proc_macro(root: Path, rel_dir: str) -> bool:
    try:
        parsed = tomllib.loads((root / rel_dir / ROOT_MANIFEST_REL.name).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return False
    return bool(parsed.get("lib", {}).get("proc-macro", False))


def resolve_reference(root: Path, base: Path, token: str) -> list[str]:
    """Canonically resolve a path reference to repo-relative candidates.

    Resolution is positional, not textual: a token is resolved against the
    referring file's directory and against the repository root, then normalised
    and required to stay inside the tree. A wildcard, interpolation or
    out-of-tree token yields no candidate.
    """
    cleaned = token.strip().strip("'\"`,")
    if not cleaned or cleaned.startswith(("#", "http")) or re.match(r"^[A-Za-z]:", cleaned):
        return []
    if any(char in cleaned for char in "*?<>|$%&;\n\r\t"):
        return []
    normalized = cleaned.replace("\\", "/")
    if normalized.startswith("/"):
        return []
    candidates: list[str] = []
    for anchor in (base, root):
        try:
            resolved = Path(os.path.normpath(str(anchor / normalized)))
            relative = resolved.relative_to(root).as_posix()
        except ValueError:
            continue
        if relative not in candidates:
            candidates.append(relative)
    return candidates


def standalone_hit(candidates: list[str], inventory: dict[str, str]) -> str | None:
    for candidate in candidates:
        for path in inventory:
            if candidate == path or candidate.startswith(path + "/"):
                return path
    return None


def owning_package(relative: Path, inventory: dict[str, str]) -> str | None:
    """The inventoried package a referencing file itself belongs to, if any."""
    for path in inventory:
        if relative == Path(path) or relative.as_posix().startswith(path + "/"):
            return path
    return None


def dependency_edges(
    root: Path,
    inventory: dict[str, str],
    packages: dict[str, str],
    manifest: Path,
    parsed: dict,
    sections: list[tuple[str, str]],
    workspace_dependencies: dict,
) -> list[dict]:
    """Resolved Cargo edges of one manifest, with the edge role preserved."""
    relative = manifest.parent.relative_to(root).as_posix()
    edges: list[dict] = []
    for section, role in sections:
        deps = parsed.get(section, {})
        if not isinstance(deps, dict):
            continue
        for key, value in deps.items():
            if not isinstance(value, dict):
                continue
            entry = value
            if value.get("workspace") is True:
                inherited = workspace_dependencies.get(key)
                if not isinstance(inherited, dict):
                    continue
                entry = inherited
            # An aliased edge names the real package in `package =`; the key
            # may be any alias, so both identities are checked.
            names = {str(key)}
            if "package" in entry:
                names.add(str(entry["package"]))
            hit_package = next((n for n in sorted(names) if n in packages.values()), None)
            hit_path = None
            if isinstance(entry.get("path"), str):
                hit_path = standalone_hit(
                    resolve_reference(root, manifest.parent, str(entry["path"])), inventory
                )
            if hit_path is None and hit_package is None:
                continue
            landed = hit_path or next(
                path for path, name in packages.items() if name == hit_package
            )
            effective_role = "host-proc-macro" if is_proc_macro(root, landed) else role
            detail = f"{key} -> {landed}"
            if "package" in entry:
                detail += f" (package = {entry['package']})"
            if isinstance(entry.get("path"), str):
                detail += f" (path = {entry['path']})"
            edges.append(
                {
                    "kind": "cargo-manifest",
                    "role": effective_role,
                    "source": f"{relative}/{ROOT_MANIFEST_REL.name}",
                    "section": section,
                    "package": packages[landed],
                    "package_path": landed,
                    "detail": detail,
                }
            )
    return edges


def find_consumers(root: Path, inventory: dict[str, str]) -> list[dict]:
    """Every real build or release input edge onto an inventoried package."""
    packages = dict(inventory)
    edges: list[dict] = []
    root_manifest = root / ROOT_MANIFEST_REL
    workspace_dependencies = tomllib.loads(root_manifest.read_text(encoding="utf-8"))[
        "workspace"
    ].get("dependencies", {})
    if not isinstance(workspace_dependencies, dict):
        workspace_dependencies = {}

    # 1. Cargo manifest edges, including root [workspace.dependencies] entries
    #    that members inherit through `workspace = true`.
    for manifest in sorted(root.rglob(ROOT_MANIFEST_REL.name)):
        if any(part in IGNORED_PARTS for part in manifest.parts):
            continue
        if manifest == root_manifest:
            continue
        relative = manifest.parent.relative_to(root).as_posix()
        if relative in packages:
            continue
        try:
            parsed = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            continue
        sections = [(section, SECTION_ROLES[section]) for section in DEPENDENCY_SECTIONS]
        target = parsed.get("target", {})
        if isinstance(target, dict):
            for condition, entry in target.items():
                if not isinstance(entry, dict):
                    continue
                for section in DEPENDENCY_SECTIONS:
                    if section in entry:
                        sections.append((f"target.{condition}.{section}", SECTION_ROLES[section]))
        edges.extend(
            dependency_edges(
                root, inventory, packages, manifest, parsed, sections, workspace_dependencies
            )
        )
    for key, value in sorted(workspace_dependencies.items()):
        if not isinstance(value, dict):
            continue
        names = {str(key)} | ({str(value["package"])} if "package" in value else set())
        hit_package = next((n for n in sorted(names) if n in packages.values()), None)
        hit_path = None
        if isinstance(value.get("path"), str):
            hit_path = standalone_hit(
                resolve_reference(root, root, str(value["path"])), inventory
            )
        if hit_path is None and hit_package is None:
            continue
        landed = hit_path or next(path for path, name in packages.items() if name == hit_package)
        edges.append(
            {
                "kind": "cargo-workspace-dependency",
                "role": "target-runtime" if not is_proc_macro(root, landed) else "host-proc-macro",
                "source": ROOT_MANIFEST_REL.as_posix(),
                "section": "workspace.dependencies",
                "package": packages[landed],
                "package_path": landed,
                "detail": f"{key} -> {landed}",
            }
        )

    # 2. Build scripts and Rust codegen inputs at any real input path. A file
    #    inside an inventoried package may build itself; a reference onto a
    #    different inventoried package is still a cross-package edge.
    for script in sorted(root.rglob("build.rs")):
        if any(part in SCAN_SKIP_PARTS for part in script.parts):
            continue
        relative = script.relative_to(root)
        owner = owning_package(relative, inventory)
        body = script.read_text(encoding="utf-8", errors="ignore")
        for line in code_lines(body, ".rs"):
            hit = standalone_hit(
                [
                    candidate
                    for token in line_tokens(line)
                    for candidate in resolve_reference(root, script.parent, token)
                ],
                inventory,
            )
            if hit is None or hit == owner:
                continue
            hit_name = next((name for name in packages.values() if name in line), None)
            edges.append(
                {
                    "kind": "build-script",
                    "role": "host-build",
                    "source": relative.as_posix(),
                    "section": "build.rs",
                    "package": packages[hit],
                    "package_path": hit,
                    "detail": f"build script input -> {hit}"
                    + (f" (names {hit_name})" if hit_name else ""),
                }
            )
    for source in sorted(root.rglob("*.rs")):
        if any(part in SCAN_SKIP_PARTS for part in source.parts):
            continue
        if source.name == "build.rs":
            continue
        relative = source.relative_to(root)
        owner = owning_package(relative, inventory)
        for match in RUST_INCLUDE.finditer(source.read_text(encoding="utf-8", errors="ignore")):
            hit = standalone_hit(resolve_reference(root, source.parent, match.group(1)), inventory)
            if hit is None or hit == owner:
                continue
            edges.append(
                {
                    "kind": "rust-include-input",
                    "role": "target-runtime",
                    "source": relative.as_posix(),
                    "section": "include!",
                    "package": packages[hit],
                    "package_path": hit,
                    "detail": f"compiled include -> {hit}",
                }
            )

    # 3. Scripted build, packaging and release inputs.
    for script in sorted(root.rglob("*")):
        if not script.is_file() or script.suffix.lower() not in SCRIPT_SUFFIXES:
            continue
        if any(part in SCAN_SKIP_PARTS for part in script.parts):
            continue
        if script.suffix.lower() in DOCUMENTATION_SUFFIXES:
            continue
        relative = script.relative_to(root).as_posix()
        owner = owning_package(script.relative_to(root), inventory)
        body = script.read_text(encoding="utf-8", errors="ignore")
        lines = code_lines(body, script.suffix)
        has_cargo = any(CARGO_INVOCATION.search(line) for line in lines)
        entered: set[str] = set()
        for line in lines:
            for match in MANIFEST_PATH_ARG.finditer(line):
                hit = standalone_hit(resolve_reference(root, script.parent, match.group(1)), inventory)
                if hit is not None and hit != owner:
                    edges.append(
                        script_edge(
                            "cargo-manifest-path",
                            "host-build",
                            relative,
                            hit,
                            packages,
                            f"cargo --manifest-path {match.group(1)}",
                        )
                    )
            for match in PACKAGE_SELECTOR_ARG.finditer(line):
                name = match.group(1).strip("'\"")
                selected = next((p for p, n in packages.items() if n == name), None)
                if selected is None or selected == owner:
                    continue
                edges.append(
                    script_edge(
                        "cargo-package-selector",
                        "host-build",
                        relative,
                        selected,
                        packages,
                        f"cargo package selector {name}",
                    )
                )
            if has_cargo:
                for match in LOCATION_CHANGE.finditer(line):
                    hit = standalone_hit(
                        resolve_reference(root, script.parent, match.group(1)), inventory
                    )
                    if hit is not None and hit != owner:
                        entered.add(hit)
            if BYTE_MOVING_CONSTRUCT.search(line):
                for token in line_tokens(line):
                    hit = standalone_hit(resolve_reference(root, script.parent, token), inventory)
                    if hit is None or hit == owner:
                        continue
                    edges.append(
                        script_edge(
                            "byte-moving-copy",
                            "host-build",
                            relative,
                            hit,
                            packages,
                            f"copied/staged path operand {token}",
                        )
                    )
        for hit in sorted(entered):
            edges.append(
                script_edge(
                    "script-entry-into-package",
                    "host-build",
                    relative,
                    hit,
                    packages,
                    "script enters the package directory and runs cargo",
                )
            )
    return sorted(
        {
            (
                edge["source"],
                edge["kind"],
                edge["package_path"],
                edge["role"],
                edge["detail"],
            ): edge
            for edge in edges
        }.values(),
        key=lambda edge: (edge["source"], edge["kind"], edge["package_path"]),
    )


def script_edge(kind: str, role: str, source: str, hit: str, packages: dict[str, str], detail: str) -> dict:
    return {
        "kind": kind,
        "role": role,
        "source": source,
        "section": kind,
        "package": packages[hit],
        "package_path": hit,
        "detail": detail,
    }


def code_lines(body: str, suffix: str) -> list[str]:
    """Executable lines only: a comment never carries a product-input edge."""
    comment_prefixes = ("#", "//") if suffix.lower() == ".rs" else ("#",)
    lines = []
    for line in body.splitlines():
        if suffix.lower() in {".rs", ".ps1", ".psm1", ".py", ".cmd", ".bat", ".sh"}:
            stripped = line.strip()
            if stripped.startswith(comment_prefixes) or COMMENT_REM.match(line):
                continue
        lines.append(line)
    return lines


def line_tokens(line: str) -> list[str]:
    tokens: list[str] = []
    for match in QUOTED_TOKEN.finditer(line):
        tokens.append(match.group(1) or match.group(2) or "")
    for match in PATH_TOKEN.finditer(line):
        tokens.append(match.group(0))
    return [token for token in tokens if token]


def read_admission_vocabulary(data: dict, failures: list[str]) -> tuple[list[str], str]:
    """The admission states the inventory itself declares.

    The inventory is the owner of the vocabulary, not this gate: reading it back
    means a row cannot claim a state the inventory never declared, and a
    vocabulary that loses either the deny marker or the evidence-qualified state
    fails closed instead of silently admitting whatever remains.
    """
    states = data.get(ADMISSION_STATES_KEY)
    if (
        not isinstance(states, list)
        or not states
        or not all(isinstance(state, str) and state.strip() for state in states)
    ):
        failures.append(
            f"{ADMISSION_STATES_KEY} must be a non-empty list of admission state "
            f"names, got {states!r}"
        )
        return [], EVIDENCE_ADMISSION
    normalized = [str(state).strip() for state in states]
    if len(set(normalized)) != len(normalized):
        failures.append(f"duplicate admission states: {normalized}")
    if DENY_MARKER not in normalized:
        failures.append(
            f"the admission vocabulary must declare the deny marker "
            f"{DENY_MARKER!r}: {normalized}"
        )
    evidence_state = str(data.get(ADMISSION_EVIDENCE_STATE_KEY, "")).strip()
    if evidence_state not in normalized:
        failures.append(
            f"{ADMISSION_EVIDENCE_STATE_KEY} {evidence_state!r} is not one of the "
            f"declared admission states {normalized}"
        )
    return normalized, evidence_state or EVIDENCE_ADMISSION


def qualify_evidence(path: str, row: dict, evidence_state: str) -> tuple[list[str], dict[str, str]]:
    """Check one evidence-qualified row's evidence table element by element.

    Returns the refusals and the bindings the row actually presented. A row is
    not qualified by the presence of the table: every element must be present,
    bound, and bound to an exact value, and a trust class outside I15.17's own
    taxonomy or an admitted use that is not a production use refuses the row.
    """
    table = row.get(SUPPLY_CHAIN_EVIDENCE_KEY)
    if not isinstance(table, dict):
        return (
            [
                f"{path}: supply_chain_admission {evidence_state!r} requires a "
                f"[crate.{SUPPLY_CHAIN_EVIDENCE_KEY}] table binding every element "
                f"{list(REQUIRED_EVIDENCE)}"
            ],
            {},
        )
    refusals: list[str] = []
    bindings: dict[str, str] = {}
    for element in REQUIRED_EVIDENCE:
        entry = table.get(element)
        if not isinstance(entry, dict):
            refusals.append(f"{path}: evidence element {element!r} is missing or is not a table")
            continue
        state = str(entry.get("state", "")).strip()
        binding = str(entry.get("binding", "")).strip()
        if state != EVIDENCE_BOUND:
            refusals.append(
                f"{path}: evidence element {element!r} must be {EVIDENCE_BOUND!r}, got {state!r}"
            )
        elif not binding:
            refusals.append(
                f"{path}: evidence element {element!r} is {EVIDENCE_BOUND!r} with no binding value"
            )
        elif element == "trust_class" and binding not in TRUST_CLASSES:
            refusals.append(
                f"{path}: evidence element 'trust_class' binds {binding!r}, which is not an "
                f"I15.17 build trust class {list(TRUST_CLASSES)}"
            )
        elif element == "admitted_use" and binding not in EVIDENCE_ADMITTED_USES:
            refusals.append(
                f"{path}: evidence element 'admitted_use' binds {binding!r}, which is not a "
                f"production use {list(EVIDENCE_ADMITTED_USES)}"
            )
        else:
            bindings[element] = binding
    undeclared = sorted(set(table) - set(REQUIRED_EVIDENCE))
    if undeclared:
        refusals.append(
            f"{path}: evidence table names elements this gate neither requires nor binds: "
            f"{undeclared}"
        )
    return refusals, bindings


def admission_decision(
    path: str,
    row: dict,
    states: list[str],
    evidence_state: str,
) -> tuple[dict, list[str]]:
    """The gate's own supply-chain admission decision for one inventoried row.

    The deny marker is a decision, not a failure: a package declared deny-all is
    simply not a product input, and the consumer/lock checks below refuse any
    edge that contradicts that. Only a row that claims the evidence-qualified
    state, or that claims a state the inventory never declared, can fail here.
    """
    package = str(row.get("package", ""))
    state = str(row.get(SUPPLY_CHAIN_ADMISSION_KEY, "")).strip()
    reference = str(row.get("evidence_reference", "")).strip()
    decision = {
        "path": path,
        "package": package,
        "state": state,
        "decision": "denied",
        "evidence": {},
        "required_elements": list(REQUIRED_EVIDENCE),
        "unbound_elements": list(REQUIRED_EVIDENCE),
        "reasons": [],
    }
    if state == DENY_MARKER:
        # `evidence_reference` stays the same declaration for a deny-state row:
        # a row that claims anything else is refused rather than implying an
        # evidence record that does not exist.
        if reference != EVIDENCE_REFERENCE:
            decision["reasons"] = [
                f"supply_chain_admission {DENY_MARKER!r} requires "
                f"evidence_reference {EVIDENCE_REFERENCE!r}, got {reference!r}"
            ]
            return decision, [f"{path}: {decision['reasons'][0]}"]
        decision["reasons"] = [
            f"supply_chain_admission {DENY_MARKER!r}: not an admitted separate-package input"
        ]
        return decision, []
    if state != evidence_state:
        return decision, [
            f"{path}: supply_chain_admission {state!r} is not a declared admission state "
            f"{states}"
        ]
    refusals, bindings = qualify_evidence(path, row, evidence_state)
    disposition = str(row.get("disposition", "")).strip()
    if disposition in NON_PRODUCTION_DISPOSITIONS:
        refusals.append(
            f"{path}: disposition {disposition} is never admissible as a production input"
        )
    if not reference or reference == EVIDENCE_REFERENCE:
        refusals.append(
            f"{path}: supply_chain_admission {evidence_state!r} requires an "
            f"evidence_reference naming the qualifying evidence record, got {reference!r}"
        )
    unbound = [element for element in REQUIRED_EVIDENCE if element not in bindings]
    decision["unbound_elements"] = unbound
    decision["evidence"] = bindings
    if refusals:
        decision["reasons"] = refusals
        return decision, refusals
    decision["decision"] = "admitted"
    decision["reasons"] = [
        f"supply_chain_admission {evidence_state!r}: every required element is bound"
    ]
    return decision, []


def locked_packages(root: Path, package_names: set[str]) -> list[str]:
    lock = root / LOCK_REL
    if not lock.is_file():
        return []
    names = set(re.findall(r'name\s*=\s*"([^"]+)"', lock.read_text(encoding="utf-8")))
    return sorted(names & package_names)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 16), b""):
            digest.update(block)
    return digest.hexdigest()


def file_evidence(root: Path, relative: Path) -> dict:
    path = root / relative
    if not path.is_file():
        return {"path": relative.as_posix(), "sha256": None, "state": "absent"}
    return {"path": relative.as_posix(), "sha256": sha256_file(path), "state": "present"}


def package_bytes_digest(root: Path, rel_dir: str) -> str:
    """Content identity of the package bytes a receipt must bind."""
    base = root / rel_dir
    entries = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(base)
        if any(part in SCAN_SKIP_PARTS for part in relative.parts):
            continue
        entries.append(f"{relative.as_posix()} {sha256_file(path)}")
    if not entries:
        return hashlib.sha256(b"").hexdigest()
    return hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()


def git_output(root: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def source_identity(root: Path) -> dict:
    commit = git_output(root, "rev-parse", "HEAD")
    repository = git_output(root, "config", "--get", "remote.origin.url")
    status = git_output(root, "status", "--porcelain", "--untracked-files=all")
    if status is None:
        tree_state = "unavailable"
    elif status:
        tree_state = "dirty"
    else:
        tree_state = "clean"
    return {
        "repository": repository or "unavailable",
        "commit": commit or "unavailable",
        "tree_state": tree_state,
    }


def build_admission_block(
    states: list[str],
    evidence_state: str,
    decisions: list[dict],
) -> dict:
    """The admission decision the receipt carries and the cache namespace binds.

    `qualified` holds one decision per row that claimed the evidence-qualified
    state, whether or not it qualified, so a refused row is retained as a
    refusal rather than disappearing. `admitted_packages` is the set a release
    build is allowed to treat as an intentionally consumed separate package; it
    is empty unless a row presented a complete, bound evidence table.
    """
    qualified = [decision for decision in decisions if decision["state"] == evidence_state]
    admitted = sorted(
        decision["package"] for decision in qualified if decision["decision"] == "admitted"
    )
    return {
        "deny_marker": DENY_MARKER,
        "declared_states": list(states),
        "evidence_qualified_state": evidence_state,
        "required_evidence_elements": list(REQUIRED_EVIDENCE),
        "policy": EVIDENCE_ADMISSION if admitted else DENY_MARKER,
        "admitted_packages": admitted,
        "qualified": qualified,
        "denied_packages": sorted(
            decision["package"] for decision in decisions if decision["decision"] == "denied"
        ),
    }


def production_artifact_evidence(admission: dict) -> dict:
    """I15.9's production-artifact evidence with a computed per-element state.

    An element is `bound-by-this-gate` only when this decision really holds a
    binding for it: the gate's own computed inputs, or a binding an
    evidence-qualified row presented and this gate checked element by element. An
    element the gate merely routes to its owner is reported as that owner's
    evidence, so the receipt never presents a record it did not produce.
    """
    bound: dict[str, str] = {
        "source_commit_and_repository": "inputs.source",
        "cargo_lock_and_build_toolchain": "inputs.cargo_lock, inputs.rust_toolchain",
        "owner": "denominator.packages[].owner",
    }
    for decision in admission.get("qualified", []):
        for element, binding in sorted(decision.get("evidence", {}).items()):
            name = EVIDENCE_TO_I15_9.get(element)
            if name is not None:
                bound.setdefault(
                    name, f"admission.qualified[{decision['package']}].{element} = {binding}"
                )
    block: dict[str, dict] = {}
    for name in I15_9_EVIDENCE_ORDER:
        if name in bound:
            block[name] = {"state": EVIDENCE_STATE_BOUND, "binding": bound[name]}
        elif name == "rollback":
            block[name] = {"state": "declared", "value": ROLLBACK_DECLARATION}
        else:
            block[name] = {"state": EVIDENCE_STATE_OWNER, "owner": I15_9_ELEMENT_OWNERS[name]}
    return block


def build_receipt(
    root: Path,
    data: dict,
    inventory: dict[str, str],
    edges: list[dict],
    locked: list[str],
    trust_class: str,
    states: list[str],
    evidence_state: str,
    decisions: list[dict],
    members: set[str],
    exclude: set[str],
) -> dict:
    rows = {str(row.get("path")): row for row in data.get("crate", [])}
    packages = [
        {
            "path": path,
            "package": inventory[path],
            "package_bytes_sha256": package_bytes_digest(root, path),
            "disposition": str(rows.get(path, {}).get("disposition", "")),
            "owner": str(rows.get(path, {}).get("owner", "")),
            "evidence_reference": str(rows.get(path, {}).get("evidence_reference", "")),
            "supply_chain_admission": str(
                rows.get(path, {}).get(SUPPLY_CHAIN_ADMISSION_KEY, "")
            ),
        }
        for path in sorted(inventory)
    ]
    admission = build_admission_block(states, evidence_state, decisions)
    inputs = {
        "source": source_identity(root),
        "root_manifest": file_evidence(root, ROOT_MANIFEST_REL),
        "cargo_lock": file_evidence(root, LOCK_REL),
        "rust_toolchain": file_evidence(root, TOOLCHAIN_REL),
        "inventory": file_evidence(root, INVENTORY_REL),
        "verifier": file_evidence(root, GATE_REL),
        "discovery_owner": file_evidence(root, DISCOVERY_OWNER_REL),
    }
    identity = json.dumps(
        {
            "trust_class": trust_class,
            "inputs": inputs,
            "denominator": {
                "standalone_package_count": len(packages),
                "workspace_member_count": len(members),
                "root_exclude_count": len(exclude),
                "packages": packages,
            },
            "consumer_edges": edges,
            "locked_standalone_packages": locked,
            # The admission decision is inside the hashed identity, so flipping a
            # row's admission state, dropping a binding or changing the admitted
            # set invalidates the retained receipt instead of reusing it.
            "admission": admission,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "schema": RECEIPT_SCHEMA,
        "component": "eliot_excluded_disposition_gate_receipt",
        "issue": 1811,
        "generator": GATE_REL.as_posix(),
        "trust_class": trust_class,
        "admission_policy": admission["policy"],
        "admission": admission,
        "inputs": inputs,
        "denominator": {
            "rule": (
                "own [workspace] [package] manifest, neither a root workspace member "
                "nor a root workspace.exclude entry"
            ),
            "discovery_owner": DISCOVERY_OWNER_REL.as_posix(),
            "discovery_owner_symbols": list(DISCOVERY_OWNER_SYMBOLS),
            "standalone_package_count": len(packages),
            "workspace_member_count": len(members),
            "root_exclude_count": len(exclude),
            "packages": packages,
        },
        "consumer_edges": edges,
        "locked_standalone_packages": locked,
        "coverage": {
            "scanned": [
                "non-standalone Cargo manifests (dependencies, dev-dependencies, "
                "build-dependencies, target.* and [workspace.dependencies] inheritance)",
                "build.rs at every real input path, Rust include!/include_str!/include_bytes! inputs",
                "PowerShell/Python/cmd/batch/shell/CI invocations: cargo --manifest-path, "
                "cargo -p/--package, package-directory entry followed by cargo",
                "byte-moving copy/archive/packaging path operands in those scripts",
                "root Cargo.lock package identities",
            ],
            "omitted": [
                "documentation text (.md/.txt/.rst/.adoc), comments, docstrings and prose "
                "fields: a documented name is not an invocation or byte-producing edge",
                "fixture and testdata Cargo manifests: excluded from the denominator by the "
                "accepted discovery owner, so they are not package inputs either",
            ],
            "unknown": [
                "a build input produced entirely outside the tracked tree cannot be "
                "discovered by a tree scan; the release runtime artifact manifest binds "
                "downloaded bytes instead"
            ],
        },
        "production_artifact_evidence": {
            "required_by": (
                "docs/architecture/I15-09-source-admission-and-executable-supply-chain.md"
                "#executable-module-supply-chain"
            ),
            **production_artifact_evidence(admission),
        },
        "cache_namespace": "sha256:" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
    }


def summarize_admission_field(value) -> str:
    """A short description of one admission field for a refusal message."""
    if isinstance(value, list):
        if value and isinstance(value[0], dict):
            names = sorted(str(item.get("package", "")) for item in value)
            return f"{len(value)} decision(s) for {names}"
        return f"{len(value)} entr{'y' if len(value) == 1 else 'ies'}: {value}"
    return repr(value)


def recheck_receipt(root: Path, prior_path: Path, receipt: dict, failures: list[str]) -> None:
    """Refuse a retained receipt that no longer binds this exact identity."""
    if not prior_path.is_file():
        failures.append(f"retained gate receipt is missing: {prior_path.as_posix()}")
        return
    try:
        prior = json.loads(prior_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        failures.append(f"retained gate receipt is unreadable: {prior_path.as_posix()} ({error})")
        return
    if prior.get("schema") != RECEIPT_SCHEMA:
        failures.append(
            f"retained gate receipt schema {prior.get('schema')!r} is not {RECEIPT_SCHEMA}"
        )
        return
    if prior.get("result") != "PASS":
        failures.append("retained gate receipt does not record a PASS decision")
    if prior.get("trust_class") != receipt["trust_class"]:
        failures.append(
            "cross-trust cache reuse refused: retained receipt trust class "
            f"{prior.get('trust_class')!r} differs from {receipt['trust_class']!r}"
        )
    if prior.get("cache_namespace") != receipt["cache_namespace"]:
        failures.append(
            "retained gate receipt is invalidated by a changed source, lock, toolchain, "
            "inventory, verifier, trust class or package byte identity "
            f"(retained {prior.get('cache_namespace')} vs current {receipt['cache_namespace']})"
        )
    # The admission decision is refused explicitly as well as through the cache
    # namespace: a receipt that admitted a separate package under one evidence
    # binding must not authorise a build whose row, bindings or admitted set
    # differ.
    if prior.get("admission_policy") != receipt["admission_policy"]:
        failures.append(
            "retained gate receipt admission policy differs from the current decision "
            f"(retained {prior.get('admission_policy')!r} vs current {receipt['admission_policy']!r})"
        )
    prior_admission = prior.get("admission") if isinstance(prior.get("admission"), dict) else {}
    for field in ("declared_states", "admitted_packages", "qualified", "denied_packages"):
        if prior_admission.get(field) != receipt["admission"][field]:
            failures.append(
                f"retained gate receipt admission.{field} differs from the current decision "
                f"(retained {summarize_admission_field(prior_admission.get(field))} vs current "
                f"{summarize_admission_field(receipt['admission'][field])})"
            )
    for field in ("inputs", "denominator", "consumer_edges", "locked_standalone_packages"):
        if prior.get(field) != receipt[field]:
            failures.append(f"retained gate receipt {field} differs from the current decision")
    if failures:
        failures.append(
            "current excluded-disposition decision is FAIL, so no retained receipt can "
            "authorise publication"
        )


def write_receipt(path: Path, receipt: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(receipt, indent=2, sort_keys=False) + "\n"
    path.write_text(payload, encoding="utf-8")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Excluded/standalone disposition gate (#1811).")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--trust-class",
        default=DEFAULT_TRUST_CLASS,
        # The document's own taxonomy; an unrecognised class is refused rather
        # than written into a supply-chain receipt.
        choices=TRUST_CLASSES,
        help="I15.17 build trust class of the decision being made",
    )
    parser.add_argument(
        "--receipt-out",
        type=Path,
        default=None,
        help=f"retained receipt output (default {RECEIPT_OUT_REL.as_posix()})",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        default=None,
        help="re-check a retained receipt against the current decision identity",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    receipt_out = args.receipt_out or (root / (RECEIPT_RECHECK_REL if args.receipt else RECEIPT_OUT_REL))

    failures: list[str] = []
    data = load_inventory(root)
    rows = data.get("crate", [])
    by_path = {str(r.get("path")): r for r in rows}
    declared_paths = [str(r.get("path")) for r in rows]
    declared_names = [str(r.get("package")) for r in rows]
    if len(by_path) != len(rows):
        failures.append(
            f"duplicate inventory rows: {sorted({p for p in declared_paths if declared_paths.count(p) > 1})}"
        )
    if len(set(declared_names)) != len(declared_names):
        failures.append(
            f"duplicate inventory package identities: {sorted({n for n in declared_names if declared_names.count(n) > 1})}"
        )

    members, exclude, discovered = owner_denominator(root)

    # 1. denominator: inventory must equal tree discovery
    if set(by_path) != set(discovered):
        missing = sorted(set(discovered) - set(by_path))
        stale = sorted(set(by_path) - set(discovered))
        failures.append(f"inventory/tree drift missing={missing} stale={stale}")
    for path in sorted(set(by_path) & set(members)):
        failures.append(f"inventory row is a root workspace member: {path}")
    # 2. every root exclude entry must be declared
    for entry in sorted(exclude):
        if entry not in by_path:
            failures.append(f"undeclared excluded input: {entry}")
    # 2b. declared count must equal the unique current rows and tree discovery
    declared_count = data.get("standalone_package_count")
    if isinstance(declared_count, bool) or not isinstance(declared_count, int):
        failures.append(
            "standalone_package_count must be an integer, got "
            f"{declared_count!r}"
        )
    else:
        if declared_count != len(by_path):
            failures.append(
                "standalone_package_count drift: declared "
                f"{declared_count} vs {len(by_path)} unique inventory rows"
            )
        if declared_count != len(discovered):
            failures.append(
                "standalone_package_count drift: declared "
                f"{declared_count} vs {len(discovered)} discovered standalone packages"
            )
    # 2c. the declared evidence-qualified row count, and the admission
    #     vocabulary the rows are read against.
    states, evidence_state = read_admission_vocabulary(data, failures)
    declared_evidence_rows = data.get(ADMISSION_EVIDENCE_COUNT_KEY)
    evidence_rows = [
        path
        for path, row in by_path.items()
        if str(row.get(SUPPLY_CHAIN_ADMISSION_KEY, "")).strip() == evidence_state
    ]
    if isinstance(declared_evidence_rows, bool) or not isinstance(declared_evidence_rows, int):
        failures.append(
            f"{ADMISSION_EVIDENCE_COUNT_KEY} must be an integer, got "
            f"{declared_evidence_rows!r}"
        )
    elif declared_evidence_rows != len(evidence_rows):
        failures.append(
            f"{ADMISSION_EVIDENCE_COUNT_KEY} drift: declared "
            f"{declared_evidence_rows} vs {len(evidence_rows)} rows declaring "
            f"supply_chain_admission {evidence_state!r}"
        )
    # 3. every row: disposition verb + named owner + its admission decision
    decisions: list[dict] = []
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
        decision, refusals = admission_decision(path, row, states, evidence_state)
        decisions.append(decision)
        failures.extend(refusals)
    # 4. fail-closed consumption without evidence. A qualified row is the only
    #    package an edge may reach; every other edge still fails closed.
    inventory = discovered or {str(r.get("path")): str(r.get("package")) for r in rows}
    edges = find_consumers(root, inventory)
    admitted_paths = {
        decision["path"] for decision in decisions if decision["decision"] == "admitted"
    }
    unevidenced_edges = [edge for edge in edges if edge["package_path"] not in admitted_paths]
    if unevidenced_edges:
        failures.append(
            "undeclared excluded-input consumption without "
            f"{EVIDENCE} evidence: "
            + "; ".join(
                f"{edge['source']} {edge['kind']} [{edge['role']}] -> {edge['package']} ({edge['detail']})"
                for edge in unevidenced_edges
            )
        )
    locked = locked_packages(root, set(inventory.values()))
    if locked:
        failures.append(f"inventoried package present in root Cargo.lock without {EVIDENCE} evidence: {locked}")

    receipt = build_receipt(
        root,
        data,
        inventory,
        edges,
        locked,
        args.trust_class,
        states,
        evidence_state,
        decisions,
        members,
        exclude,
    )
    if args.receipt is not None:
        recheck_receipt(root, args.receipt, receipt, failures)
        receipt["recheck_of"] = args.receipt.as_posix()
    receipt["result"] = "PASS" if not failures else "FAIL"
    receipt["failures"] = list(failures)
    receipt_sha256 = write_receipt(receipt_out, receipt)

    total = len(rows)
    if failures:
        print(f"EXCLUDED_DISPOSITIONS: FAIL rows={total} issues={len(failures)}")
        for failure in failures:
            print(f"  - {failure}")
        print(f"  receipt={receipt_out.as_posix()} sha256={receipt_sha256} trust_class={args.trust_class}")
        return 1
    print(
        f"EXCLUDED_DISPOSITIONS: PASS rows={total} consumers={len(edges)} "
        f"locked={len(locked)} "
        f"admitted_separate_packages={len(receipt['admission']['admitted_packages'])} "
        f"admission_policy={receipt['admission_policy']}"
    )
    print(
        f"  receipt={receipt_out.as_posix()} sha256={receipt_sha256} "
        f"schema={RECEIPT_SCHEMA} trust_class={args.trust_class} "
        f"cache_namespace={receipt['cache_namespace']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
