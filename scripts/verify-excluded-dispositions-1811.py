#!/usr/bin/env python3
"""Excluded/standalone disposition gate (issue #1811, slices 2-4).

Fail-closed gate: every standalone-workspace package (own `[workspace]`
table, carries `[package]`, neither a root member nor in root `exclude`)
and every root `workspace.exclude` entry must have a checked-in disposition
row with a named owner in
`workstreams/security/standalone-crate-dispositions.toml`, using one of
KEEP, WRAP, EXTRACT, REWORK, REPLACE, RETIRE, UNKNOWN, and must declare the
gate's own admission state in `evidence_reference`.

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
admission decision does not: there is no evidence-qualified separate-package
route, so every role fails closed with the evidence list named. That deny-all
posture is declared per row (`evidence_reference = "deny-all"`) and re-asserted
in the receipt instead of inventing an empty evidence record.

Discovery never trusts the inventory: the denominator is derived from the tree
with the same rule as scripts/verify-standalone-crates.py. The declared
`standalone_package_count` is checked against both the unique inventory rows
and the discovered set, so a stale count fails closed instead of passing
silently.

The decision is emitted as a retained, versioned receipt
(`--receipt-out`, default `.eliot/excluded-dispositions/gate-receipt.json`,
a gitignored output path) naming the exact denominator (package and path, with
the count the gate computed) and the source/build identity it decided against:
source commit and repository, root manifest, Cargo.lock, build toolchain,
inventory and verifier digests, per-package byte digests, every resolved
consumer edge, the I15.9 production-artifact evidence names, and the result.
`--receipt` re-validates a retained receipt against the current identity at the
owned pre-publication boundary: a changed source commit, lock, toolchain,
inventory, verifier, trust class or package byte invalidates it, and a receipt
whose cache namespace crosses trust classes is refused.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ALLOWED = {"KEEP", "WRAP", "EXTRACT", "REWORK", "REPLACE", "RETIRE", "UNKNOWN"}
# Denominator discovery, identical to scripts/verify-standalone-crates.py.
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
ROOT_MANIFEST_REL = Path("Cargo.toml")
LOCK_REL = Path("Cargo.lock")
TOOLCHAIN_REL = Path("rust-toolchain.toml")
RECEIPT_SCHEMA = "eliot.excluded-disposition-gate-receipt.v1"
RECEIPT_OUT_REL = Path(".eliot/excluded-dispositions/gate-receipt.json")
RECEIPT_RECHECK_REL = Path(".eliot/excluded-dispositions/gate-recheck-receipt.json")
EVIDENCE = "provenance, lock, toolchain, license, SBOM"
ADMISSION_POLICY = "deny-all"
EVIDENCE_REFERENCE = "deny-all"
# I15.17 build trust class. The receipt must bind a trust class, because
# I15.17 requires that "cache identity includes trust class and
# source/lock/toolchain fingerprints" and that "artifact reuse across trust
# classes or mismatched BuildFingerprint is forbidden".
#
# No document names a trust-class value, and no trust-class taxonomy exists
# anywhere in this repository, so exactly one class is defined rather than an
# invented ladder: this gate runs inside a governed release build, so its
# single class is the governed build. Tiers with no defined meaning are NOT
# offered, because a selectable label nobody can interpret would let a caller
# write a meaningless trust class into a supply-chain receipt and have it
# revalidated as authoritative. The anti-reuse guarantee comes from the input
# digests and the cache namespace derived from them, not from the label.
GOVERNED_BUILD_TRUST_CLASS = "T0"
DEFAULT_TRUST_CLASS = GOVERNED_BUILD_TRUST_CLASS
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


def workspace_sets(root: Path) -> tuple[set[str], set[str]]:
    data = tomllib.loads((root / ROOT_MANIFEST_REL).read_text(encoding="utf-8"))["workspace"]
    return set(data.get("members", [])), set(data.get("exclude", []))


def discover_standalone(root: Path) -> dict[str, str]:
    """Tree-derived denominator, identical to scripts/verify-standalone-crates.py."""
    members, exclude = workspace_sets(root)
    found: dict[str, str] = {}
    for manifest in sorted(root.rglob(ROOT_MANIFEST_REL.name)):
        if any(part in IGNORED_PARTS for part in manifest.parts):
            continue
        if manifest == root / ROOT_MANIFEST_REL:
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


def build_receipt(
    root: Path,
    data: dict,
    inventory: dict[str, str],
    edges: list[dict],
    locked: list[str],
    trust_class: str,
) -> dict:
    members, exclude = workspace_sets(root)
    rows = {str(row.get("path")): row for row in data.get("crate", [])}
    packages = [
        {
            "path": path,
            "package": inventory[path],
            "package_bytes_sha256": package_bytes_digest(root, path),
            "disposition": str(rows.get(path, {}).get("disposition", "")),
            "owner": str(rows.get(path, {}).get("owner", "")),
            "evidence_reference": str(rows.get(path, {}).get("evidence_reference", "")),
        }
        for path in sorted(inventory)
    ]
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
        "admission_policy": ADMISSION_POLICY,
        "inputs": inputs,
        "denominator": {
            "rule": (
                "own [workspace] [package] manifest, neither a root workspace member "
                "nor a root workspace.exclude entry"
            ),
            "discovery_owner": DISCOVERY_OWNER_REL.as_posix(),
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
            "source_commit_and_repository": {"state": "bound", "binding": "inputs.source"},
            "cargo_lock_and_build_toolchain": {
                "state": "bound",
                "binding": "inputs.cargo_lock, inputs.rust_toolchain",
            },
            "license_report": {
                "state": "not-produced-by-this-gate",
                "owner": "scripts/verify-dependency-policy.py",
            },
            "sbom": {
                "state": "not-produced-by-this-gate",
                "owner": "release build plan; generated SBOM stays out of Git per docs/DEPENDENCY_POLICY.md",
            },
            "artifact_hash_and_signature": {
                "state": "not-produced-by-this-gate",
                "owner": "scripts/build-eliot-windows-x64-release.ps1 (RELEASE.json, SHA256SUMS.json)",
            },
            "module_manifest": {
                "state": "not-produced-by-this-gate",
                "owner": "per-crate module.toml manifests",
            },
            "test_canary_receipts": {
                "state": "not-produced-by-this-gate",
                "owner": "crates/instrument/eliot-build-test-graph (BuildTestGraph, I2.18)",
            },
            "known_vulnerabilities_and_exceptions": {
                "state": "not-produced-by-this-gate",
                "owner": "scripts/verify-dependency-policy.py advisory snapshot",
            },
            "owner": {"state": "bound", "binding": "denominator.packages[].owner"},
            "rollback": {
                "state": "declared",
                "value": (
                    "a package leaves this receipt by moving into the root workspace "
                    "(its [[crate]] row is deleted in the same change) or by an "
                    "owner-approved removal; an inventory row is never a package deletion"
                ),
            },
        },
        "cache_namespace": "sha256:" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
    }


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
        # No invented ladder: see GOVERNED_BUILD_TRUST_CLASS. A caller that
        # declares a different class is refusing this gate's own class, which
        # fails closed rather than minting an uninterpretable receipt.
        choices=(GOVERNED_BUILD_TRUST_CLASS,),
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

    discovered = discover_standalone(root)
    members, exclude = workspace_sets(root)

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
    # 3. every row: disposition verb + named owner + declared admission state
    for path in sorted(by_path):
        row = by_path[path]
        disp = str(row.get("disposition", "")).strip()
        owner = str(row.get("owner", "")).strip()
        evidence = str(row.get("evidence_reference", "")).strip()
        if disp not in ALLOWED:
            failures.append(f"{path}: disposition must be one of {sorted(ALLOWED)}, got {disp!r}")
        if not owner:
            failures.append(f"{path}: owner must be a named non-empty value")
        if evidence != EVIDENCE_REFERENCE:
            failures.append(
                f"{path}: evidence_reference {evidence!r} is not the admitted "
                f"{EVIDENCE_REFERENCE!r} state; this gate admits no evidence-qualified "
                "separate-package route"
            )
        if row.get("package") != discovered.get(path, row.get("package")):
            failures.append(f"{path}: package name drift vs tree")
    # 4. fail-closed consumption without evidence
    inventory = discovered or {str(r.get("path")): str(r.get("package")) for r in rows}
    edges = find_consumers(root, inventory)
    if edges:
        failures.append(
            "undeclared excluded-input consumption without "
            f"{EVIDENCE} evidence: "
            + "; ".join(
                f"{edge['source']} {edge['kind']} [{edge['role']}] -> {edge['package']} ({edge['detail']})"
                for edge in edges
            )
        )
    locked = locked_packages(root, set(inventory.values()))
    if locked:
        failures.append(f"inventoried package present in root Cargo.lock without {EVIDENCE} evidence: {locked}")

    receipt = build_receipt(root, data, inventory, edges, locked, args.trust_class)
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
    print(f"EXCLUDED_DISPOSITIONS: PASS rows={total} consumers=0 locked=0")
    print(
        f"  receipt={receipt_out.as_posix()} sha256={receipt_sha256} "
        f"schema={RECEIPT_SCHEMA} trust_class={args.trust_class} "
        f"cache_namespace={receipt['cache_namespace']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
