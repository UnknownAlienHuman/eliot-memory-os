#!/usr/bin/env python3
"""Multi-ecosystem dependency admission policy verifier (issue #1229).

Executes and verifies the documented dependency admission policy:
- Pinned scanner identity (cargo-deny) outside legacy engine;
- Complete direct dependency inventory accounting (consumer, owner, reason, features, removal);
- Cross-ecosystem lockfile integrity (Rust Cargo.lock, NuGet packages.lock.json, Python hash-locked requirements);
- External executable inventory (SurrealDB);
- Distinct verification profiles: offline-source vs current-advisories;
- Structured expiring exceptions;
- Deterministic canonical receipt generation.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    line: int
    detail: str


STATUS_PASS = "PASS"
STATUS_FINDINGS = "FINDINGS"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
STATUS_ADVISORY_SOURCE_UNAVAILABLE = "ADVISORY_SOURCE_UNAVAILABLE"
STATUS_STALE = "STALE"
STATUS_CONFLICTED = "CONFLICTED"
STATUS_NOT_EXECUTED = "NOT_EXECUTED"

SCANNER_IDENTITY_FINDING = "DEP-011"
SCANNER_OUTPUT_FINDING = "DEP-012"
RECEIPT_PROVENANCE_FINDING = "DEP-013"
IDENTITY_BINDING_FINDING = "DEP-014"
NODE_ECOSYSTEM_FINDING = "DEP-015"

_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_TARGET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_SCANNER_RECORD_TYPES = {"diagnostic", "summary"}
_DIAGNOSTIC_SEVERITIES = {"error", "warning", "note", "help"}
_SUMMARY_CHECKS = {"advisories", "bans", "licenses", "sources"}
_SUMMARY_COUNTERS = {"errors", "warnings", "notes", "helps"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _validate_rust_policy_config(config: dict | None, *, require_fields: bool = False) -> list[str]:
    """Return configuration errors without silently changing cargo-deny's profile."""

    if not isinstance(config, dict):
        return ["[ecosystems.rust] must be a table"]

    errors: list[str] = []
    for field in ("manifest", "lockfile", "policy_file"):
        value = config.get(field)
        if value is None and not require_fields:
            continue
        if not isinstance(value, str) or not value.strip():
            errors.append(f"[ecosystems.rust] {field} must be a non-empty relative path")
        elif Path(value).is_absolute() or ".." in Path(value).parts:
            errors.append(f"[ecosystems.rust] {field} must stay within the repository")

    targets = config.get("targets")
    if targets is None and not require_fields:
        pass
    elif not isinstance(targets, list) or not targets:
        errors.append("[ecosystems.rust].targets must be a non-empty list")
    else:
        for target in targets:
            if not isinstance(target, str) or not _TARGET_NAME.fullmatch(target):
                errors.append(f"[ecosystems.rust].targets contains unsupported target {target!r}")

    features = config.get("features")
    if features is None and not require_fields:
        pass
    elif features == "all":
        pass
    elif not isinstance(features, list) or not features or any(
        not isinstance(feature, str) or not feature.strip() for feature in features
    ):
        errors.append("[ecosystems.rust].features must be 'all' or a non-empty list of feature names")

    return errors


def check_policy_manifest(root: Path) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    manifest_path = root / "config" / "dependency-policy.toml"
    rel_path = "config/dependency-policy.toml"

    if not manifest_path.is_file():
        findings.append(Finding("DEP-002", rel_path, 0, "missing required config/dependency-policy.toml manifest"))
        return findings, {}

    try:
        data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append(Finding("DEP-002", rel_path, 1, f"failed to parse config/dependency-policy.toml: {exc}"))
        return findings, {}

    if data.get("schema") != "eliot.dependency-policy.v1":
        findings.append(Finding("DEP-002", rel_path, 1, "schema must be 'eliot.dependency-policy.v1'"))

    scanner = data.get("scanner", {})
    if not isinstance(scanner, dict):
        findings.append(Finding("DEP-002", rel_path, 1, "[scanner] must be a table"))
        scanner = {}

    for field in ("tool", "version", "executable", "sha256", "advisory_owner", "checks"):
        if field not in scanner or scanner[field] in (None, "", []):
            findings.append(Finding("DEP-002", rel_path, 1, f"missing [scanner] {field} declaration"))

    if scanner.get("tool") != "cargo-deny":
        findings.append(Finding("DEP-002", rel_path, 1, "[scanner].tool must be 'cargo-deny'"))

    scanner_digest = scanner.get("sha256", "")
    if scanner_digest and not re.fullmatch(r"[0-9a-fA-F]{64}", str(scanner_digest)):
        findings.append(Finding("DEP-002", rel_path, 1, "[scanner].sha256 must be a 64-character hexadecimal digest"))

    scanner_checks = scanner.get("checks", [])
    if not isinstance(scanner_checks, list) or not {"advisories", "bans", "licenses", "sources"}.issubset(scanner_checks):
        findings.append(
            Finding(
                "DEP-002",
                rel_path,
                1,
                "[scanner].checks must include advisories, bans, licenses and sources",
            )
        )

    ecosystems = data.get("ecosystems", {})
    if not isinstance(ecosystems, dict):
        findings.append(Finding("DEP-002", rel_path, 1, "[ecosystems] must be a table"))
        ecosystems = {}
    rust_policy = ecosystems.get("rust", {})
    if not isinstance(rust_policy, dict):
        findings.append(Finding("DEP-002", rel_path, 1, "[ecosystems.rust] must be a table"))
        rust_policy = {}
    for field in ("manifest", "lockfile", "policy_file", "targets", "features"):
        if field not in rust_policy or rust_policy[field] in (None, "", []):
            findings.append(Finding("DEP-002", rel_path, 1, f"missing [ecosystems.rust] {field} declaration"))
    for detail in _validate_rust_policy_config(rust_policy):
        findings.append(Finding("DEP-002", rel_path, 1, detail))

    nuget_policy = ecosystems.get("nuget", {})
    if not isinstance(nuget_policy, dict):
        findings.append(Finding("DEP-002", rel_path, 1, "[ecosystems.nuget] must be a table"))
    else:
        for field in ("project", "lockfile", "target_framework"):
            value = nuget_policy.get(field)
            if not isinstance(value, str) or not value.strip():
                findings.append(
                    Finding("DEP-002", rel_path, 1, f"missing or invalid [ecosystems.nuget] {field} declaration")
                )
            elif field != "target_framework" and (
                Path(value).is_absolute() or ".." in Path(value).parts
            ):
                findings.append(
                    Finding("DEP-002", rel_path, 1, f"[ecosystems.nuget] {field} must stay within the repository")
                )

    node_policy = ecosystems.get("node", {})
    if not isinstance(node_policy, dict):
        findings.append(Finding("DEP-002", rel_path, 1, "[ecosystems.node] must be a table"))
    else:
        for field in ("contract", "manifest"):
            value = node_policy.get(field)
            if not isinstance(value, str) or not value.strip():
                findings.append(
                    Finding("DEP-002", rel_path, 1, f"missing or invalid [ecosystems.node] {field} declaration")
                )
            elif Path(value).is_absolute() or ".." in Path(value).parts:
                findings.append(
                    Finding("DEP-002", rel_path, 1, f"[ecosystems.node] {field} must stay within the repository")
                )

    deny_path = root / "deny.toml"
    if not deny_path.is_file():
        findings.append(Finding("DEP-002", "deny.toml", 0, "missing required deny.toml policy configuration"))
    else:
        try:
            deny_data = tomllib.loads(deny_path.read_text(encoding="utf-8"))
            for section in ("advisories", "licenses", "bans", "sources"):
                if section not in deny_data:
                    findings.append(Finding("DEP-002", "deny.toml", 1, f"missing required section [{section}] in deny.toml"))
        except Exception as exc:
            findings.append(Finding("DEP-002", "deny.toml", 1, f"failed to parse deny.toml: {exc}"))

    return findings, data


def collect_direct_rust_dependencies(root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    direct_deps: set[str] = set()
    internal_crates: set[str] = set()

    cargo_root = root / "Cargo.toml"
    if not cargo_root.is_file():
        findings.append(Finding("DEP-003", "Cargo.toml", 0, "root Cargo.toml is missing"))
        return findings, direct_deps

    try:
        root_data = tomllib.loads(cargo_root.read_text(encoding="utf-8"))
        ws_deps = root_data.get("workspace", {}).get("dependencies", {})
        if isinstance(ws_deps, dict):
            for name, spec in ws_deps.items():
                if isinstance(spec, dict) and "path" in spec:
                    internal_crates.add(name)
    except Exception as exc:
        findings.append(Finding("DEP-003", "Cargo.toml", 1, f"failed to parse root Cargo.toml: {exc}"))

    cargo_files = [cargo_root]
    for sub in ("crates", "bins", "apps", "workspace/tools"):
        sub_dir = root / sub
        if sub_dir.is_dir():
            cargo_files.extend(sub_dir.rglob("Cargo.toml"))

    for cpath in cargo_files:
        try:
            data = tomllib.loads(cpath.read_text(encoding="utf-8"))
            pkg_name = data.get("package", {}).get("name")
            if pkg_name:
                internal_crates.add(pkg_name)
        except Exception:
            pass

    for cpath in cargo_files:
        try:
            data = tomllib.loads(cpath.read_text(encoding="utf-8"))
        except Exception as exc:
            rel = str(cpath.relative_to(root)).replace("\\", "/")
            findings.append(Finding("DEP-003", rel, 1, f"failed to parse Cargo.toml: {exc}"))
            continue

        for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
            deps = data.get(sec, {})
            if isinstance(deps, dict):
                for name, spec in deps.items():
                    if name in internal_crates or name.startswith("eliot"):
                        continue
                    if isinstance(spec, dict) and "path" in spec:
                        continue
                    direct_deps.add(name)

        ws_deps = data.get("workspace", {}).get("dependencies", {})
        if isinstance(ws_deps, dict):
            for name, spec in ws_deps.items():
                if name in internal_crates or name.startswith("eliot"):
                    continue
                if isinstance(spec, dict) and "path" in spec:
                    continue
                direct_deps.add(name)

    return findings, direct_deps


def check_cargo_inventory(manifest_data: dict, direct_deps: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    inventory = manifest_data.get("direct_dependencies", {})
    required_fields = ("consumer", "owner", "reason", "features", "public_exposure", "removal_plan")

    for dep in sorted(direct_deps):
        if dep not in inventory:
            findings.append(
                Finding("DEP-003", "config/dependency-policy.toml", 1, f"direct dependency '{dep}' is missing from inventory")
            )
            continue

        entry = inventory[dep]
        if not isinstance(entry, dict):
            findings.append(
                Finding("DEP-003", "config/dependency-policy.toml", 1, f"inventory entry for '{dep}' must be a table")
            )
            continue

        for field in required_fields:
            if field not in entry:
                findings.append(
                    Finding(
                        "DEP-003",
                        "config/dependency-policy.toml",
                        1,
                        f"dependency '{dep}' is missing required field '{field}' in inventory",
                    )
                )

    return findings


def check_exceptions(manifest_data: dict, now_dt: datetime | None = None) -> list[Finding]:
    findings: list[Finding] = []
    exceptions = manifest_data.get("exceptions", [])
    if not isinstance(exceptions, list):
        findings.append(Finding("DEP-010", "config/dependency-policy.toml", 1, "'exceptions' must be a list"))
        return findings

    if now_dt is None:
        now_dt = datetime.now(timezone.utc)

    for exc_entry in exceptions:
        if not isinstance(exc_entry, dict):
            findings.append(Finding("DEP-010", "config/dependency-policy.toml", 1, "each exception must be a table"))
            continue

        for req in ("package", "version", "advisory", "owner", "compensating_control", "expires_at", "removal_condition"):
            if req not in exc_entry:
                findings.append(
                    Finding("DEP-010", "config/dependency-policy.toml", 1, f"exception missing required field '{req}'")
                )

        exp_str = exc_entry.get("expires_at", "")
        if exp_str:
            try:
                exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                if exp_dt < now_dt:
                    pkg = exc_entry.get("package", "unknown")
                    adv = exc_entry.get("advisory", "unknown")
                    findings.append(
                        Finding(
                            "DEP-010",
                            "config/dependency-policy.toml",
                            1,
                            f"exception for package '{pkg}' advisory '{adv}' expired on {exp_str}",
                        )
                    )
            except Exception as e:
                findings.append(
                    Finding("DEP-010", "config/dependency-policy.toml", 1, f"invalid expires_at format '{exp_str}': {e}")
                )

    return findings


def _configured_repo_path(root: Path, raw_value: object, label: str, code: str) -> tuple[Path | None, list[Finding]]:
    if not isinstance(raw_value, str) or not raw_value.strip():
        return None, [Finding(code, "config/dependency-policy.toml", 1, f"{label} must be a non-empty path")]
    path = Path(raw_value)
    if path.is_absolute() or ".." in path.parts:
        return None, [Finding(code, "config/dependency-policy.toml", 1, f"{label} must stay within the repository")]
    return root / path, []


def check_nuget_ecosystem(root: Path, nuget_policy: dict | None = None) -> list[Finding]:
    findings: list[Finding] = []
    policy = nuget_policy if isinstance(nuget_policy, dict) else {}
    csproj_path, path_findings = _configured_repo_path(
        root, policy.get("project"), "[ecosystems.nuget].project", "DEP-007"
    )
    findings.extend(path_findings)
    lock_path, path_findings = _configured_repo_path(
        root, policy.get("lockfile"), "[ecosystems.nuget].lockfile", "DEP-007"
    )
    findings.extend(path_findings)
    if csproj_path is None or lock_path is None:
        return findings

    rel_csproj = str(csproj_path.relative_to(root)).replace("\\", "/")
    rel_lock = str(lock_path.relative_to(root)).replace("\\", "/")

    if not csproj_path.is_file():
        findings.append(Finding("DEP-007", rel_csproj, 0, "configured NuGet project is missing"))
    else:
        try:
            content = csproj_path.read_text(encoding="utf-8")
        except OSError as exc:
            findings.append(Finding("DEP-007", rel_csproj, 1, f"cannot read configured NuGet project: {exc}"))
        else:
            if "<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>" not in content:
                findings.append(
                    Finding(
                        "DEP-007",
                        rel_csproj,
                        1,
                        "missing <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>",
                    )
                )

    if not lock_path.is_file():
        findings.append(Finding("DEP-007", rel_lock, 0, "configured NuGet packages.lock.json is missing"))
    else:
        try:
            lock_data = json.loads(lock_path.read_text(encoding="utf-8"))
            if not isinstance(lock_data, dict) or not lock_data.get("dependencies"):
                findings.append(Finding("DEP-007", rel_lock, 1, "packages.lock.json has empty dependencies"))
        except Exception as exc:
            findings.append(Finding("DEP-007", rel_lock, 1, f"malformed packages.lock.json: {exc}"))

    return findings


def collect_locked_dependency_identity(
    root: Path, direct_deps: set[str], lockfile: object
) -> tuple[list[Finding], dict[str, list[dict]]]:
    """Bind every direct registry dependency to the exact Cargo.lock identity."""

    findings: list[Finding] = []
    identities: dict[str, list[dict]] = {}
    if not isinstance(lockfile, str) or not lockfile.strip() or Path(lockfile).is_absolute() or ".." in Path(lockfile).parts:
        findings.append(Finding(IDENTITY_BINDING_FINDING, "config/dependency-policy.toml", 1, "Rust lockfile path is invalid for identity binding"))
        return findings, identities

    lock_path = root / lockfile
    rel_lock = str(lock_path.relative_to(root)).replace("\\", "/")
    if not lock_path.is_file():
        findings.append(Finding(IDENTITY_BINDING_FINDING, rel_lock, 0, "Cargo.lock is missing for direct dependency identity binding"))
        return findings, identities
    try:
        lock_data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        findings.append(Finding(IDENTITY_BINDING_FINDING, rel_lock, 1, f"Cargo.lock cannot be parsed for identity binding: {exc}"))
        return findings, identities

    packages = lock_data.get("package")
    if not isinstance(packages, list):
        findings.append(Finding(IDENTITY_BINDING_FINDING, rel_lock, 1, "Cargo.lock package table is missing or malformed"))
        return findings, identities

    for dep in sorted(direct_deps):
        matches = [package for package in packages if isinstance(package, dict) and package.get("name") == dep]
        if not matches:
            findings.append(Finding(IDENTITY_BINDING_FINDING, rel_lock, 1, f"direct dependency '{dep}' has no Cargo.lock identity"))
            continue
        entries: list[dict] = []
        for package in matches:
            version = package.get("version")
            source = package.get("source")
            checksum = package.get("checksum")
            entry = {"version": version, "source": source, "checksum": checksum}
            entries.append(entry)
            if not isinstance(version, str) or not version.strip():
                findings.append(Finding(IDENTITY_BINDING_FINDING, rel_lock, 1, f"direct dependency '{dep}' has an invalid locked version"))
            if not isinstance(source, str) or not source.strip():
                findings.append(Finding(IDENTITY_BINDING_FINDING, rel_lock, 1, f"direct dependency '{dep}' lacks an exact locked source"))
            if not isinstance(checksum, str) or not _HEX64.fullmatch(checksum):
                findings.append(Finding(IDENTITY_BINDING_FINDING, rel_lock, 1, f"direct dependency '{dep}' lacks an exact 64-character registry checksum"))
        identities[dep] = entries

    return findings, identities


def _validated_node_input(
    root: Path, raw_value: object, label: str
) -> tuple[Path | None, str | None]:
    path, _ = _configured_repo_path(root, raw_value, label, NODE_ECOSYSTEM_FINDING)
    if path is None:
        return None, None
    try:
        resolved_path = path.resolve()
        relative_path = resolved_path.relative_to(root.resolve())
    except (OSError, ValueError):
        return None, None
    relative = str(relative_path).replace("\\", "/")
    if not relative or relative == ".":
        return None, None
    return resolved_path, relative


def _node_input_paths(root: Path, node_policy: dict | None) -> list[str]:
    policy = node_policy if isinstance(node_policy, dict) else {}
    paths: list[str] = []

    contract_path, contract_relative = _validated_node_input(
        root, policy.get("contract"), "[ecosystems.node].contract"
    )
    if contract_relative:
        paths.append(contract_relative)

    if contract_path is not None:
        try:
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            contract = {}
        surface = contract.get("surface") if isinstance(contract, dict) else None
        if isinstance(surface, str) and surface.strip():
            _, surface_relative = _validated_node_input(root, surface, "Node contract surface")
            if surface_relative:
                paths.append(surface_relative)

    manifest_path, manifest_relative = _validated_node_input(
        root, policy.get("manifest"), "[ecosystems.node].manifest"
    )
    if manifest_relative:
        paths.append(manifest_relative)

    if manifest_path is not None:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            manifest = {}
        instructions = manifest.get("instructions", []) if isinstance(manifest, dict) else []
        if isinstance(instructions, list):
            for instruction in instructions:
                if isinstance(instruction, str) and instruction.strip():
                    instruction_path = (manifest_path.parent / instruction).resolve()
                    try:
                        relative_instruction = instruction_path.relative_to(root.resolve())
                    except ValueError:
                        continue
                    _, instruction_relative = _validated_node_input(
                        root, str(relative_instruction), "Node manifest instruction"
                    )
                    if instruction_relative:
                        paths.append(instruction_relative)
    return list(dict.fromkeys(paths))


def check_node_ecosystem(root: Path, node_policy: dict | None = None) -> list[Finding]:
    findings: list[Finding] = []
    policy = node_policy if isinstance(node_policy, dict) else {}
    contract_path, path_findings = _configured_repo_path(
        root, policy.get("contract"), "[ecosystems.node].contract", NODE_ECOSYSTEM_FINDING
    )
    findings.extend(path_findings)
    manifest_path, path_findings = _configured_repo_path(
        root, policy.get("manifest"), "[ecosystems.node].manifest", NODE_ECOSYSTEM_FINDING
    )
    findings.extend(path_findings)
    if contract_path is None or manifest_path is None:
        return findings

    contract: dict = {}
    if not contract_path.is_file():
        findings.append(
            Finding(NODE_ECOSYSTEM_FINDING, str(contract_path.relative_to(root)).replace("\\", "/"), 0, "configured Node contract is missing")
        )
    else:
        try:
            value = json.loads(contract_path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("top-level value must be an object")
            contract = value
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            findings.append(
                Finding(
                    NODE_ECOSYSTEM_FINDING,
                    str(contract_path.relative_to(root)).replace("\\", "/"),
                    1,
                    f"malformed configured Node contract: {exc}",
                )
            )
        else:
            for field in ("schema_version", "surface", "authority_ceiling", "tool_identity"):
                if field not in contract:
                    findings.append(Finding(NODE_ECOSYSTEM_FINDING, "config/dependency-policy.toml", 1, f"Node contract missing '{field}'"))
            surface = contract.get("surface")
            if isinstance(surface, str) and surface.strip():
                surface_path, surface_findings = _configured_repo_path(
                    root, surface, "Node contract surface", NODE_ECOSYSTEM_FINDING
                )
                findings.extend(surface_findings)
                if surface_path is not None and not surface_path.is_file():
                    findings.append(
                        Finding(NODE_ECOSYSTEM_FINDING, surface.replace("\\", "/"), 0, "Node contract surface is missing")
                    )

    if not manifest_path.is_file():
        findings.append(
            Finding(NODE_ECOSYSTEM_FINDING, str(manifest_path.relative_to(root)).replace("\\", "/"), 0, "configured Node manifest is missing")
        )
    else:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("top-level value must be an object")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            findings.append(
                Finding(
                    NODE_ECOSYSTEM_FINDING,
                    str(manifest_path.relative_to(root)).replace("\\", "/"),
                    1,
                    f"malformed configured Node manifest: {exc}",
                )
            )
        else:
            instructions = manifest.get("instructions")
            if not isinstance(instructions, list) or not instructions:
                findings.append(Finding(NODE_ECOSYSTEM_FINDING, "config/dependency-policy.toml", 1, "Node manifest instructions must be a non-empty list"))
            else:
                for instruction in instructions:
                    if not isinstance(instruction, str) or not instruction.strip():
                        findings.append(Finding(NODE_ECOSYSTEM_FINDING, "config/dependency-policy.toml", 1, "Node manifest instruction path must be a string"))
                        continue
                    instruction_path = (manifest_path.parent / instruction).resolve()
                    try:
                        instruction_path.relative_to(root.resolve())
                    except ValueError:
                        findings.append(Finding(NODE_ECOSYSTEM_FINDING, "config/dependency-policy.toml", 1, f"Node instruction escapes repository: {instruction}"))
                    else:
                        if not instruction_path.is_file():
                            findings.append(Finding(NODE_ECOSYSTEM_FINDING, instruction.replace("\\", "/"), 0, "Node manifest instruction is missing"))

            mcp = manifest.get("mcp")
            eliot = mcp.get("eliot") if isinstance(mcp, dict) else None
            command = eliot.get("command") if isinstance(eliot, dict) else None
            if not isinstance(command, list) or not command or any(not isinstance(part, str) or not part for part in command):
                findings.append(Finding(NODE_ECOSYSTEM_FINDING, "config/dependency-policy.toml", 1, "Node manifest ELIOT MCP command is malformed"))
            if not isinstance(eliot, dict) or not isinstance(eliot.get("enabled"), bool):
                findings.append(Finding(NODE_ECOSYSTEM_FINDING, "config/dependency-policy.toml", 1, "Node manifest ELIOT MCP enabled flag is malformed"))
            timeout = eliot.get("timeout") if isinstance(eliot, dict) else None
            if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
                findings.append(Finding(NODE_ECOSYSTEM_FINDING, "config/dependency-policy.toml", 1, "Node manifest ELIOT MCP timeout must be a positive integer"))

    return findings


def check_python_ecosystem(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    req_path = root / "scripts" / "requirements-verification.txt"
    rel_req = "scripts/requirements-verification.txt"

    if not req_path.is_file():
        findings.append(Finding("DEP-008", rel_req, 0, "missing requirements-verification.txt"))
        return findings

    lines = req_path.read_text(encoding="utf-8").splitlines()
    current_package = None
    has_hash = False

    for line_no, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("--hash="):
            if not re.fullmatch(r"--hash=sha256:[0-9a-fA-F]{64}\s*\\?", stripped):
                findings.append(Finding("DEP-008", rel_req, line_no, f"invalid hash format: {stripped}"))
            else:
                has_hash = True
            continue

        if current_package and not has_hash:
            findings.append(
                Finding("DEP-008", rel_req, line_no - 1, f"package '{current_package}' is missing --hash=sha256")
            )

        pkg_part = stripped.rstrip("\\").strip()
        if "==" not in pkg_part:
            findings.append(
                Finding("DEP-008", rel_req, line_no, f"requirement '{pkg_part}' is not exact version-pinned with ==")
            )
        current_package = pkg_part
        has_hash = False

    if current_package and not has_hash:
        findings.append(
            Finding("DEP-008", rel_req, len(lines), f"package '{current_package}' is missing --hash=sha256")
        )

    return findings


def check_external_executables(manifest_data: dict) -> list[Finding]:
    findings: list[Finding] = []
    externals = manifest_data.get("external_executables", {})
    if not externals or "surrealdb" not in externals:
        findings.append(
            Finding("DEP-009", "config/dependency-policy.toml", 1, "missing 'surrealdb' in [external_executables]")
        )
        return findings

    surreal = externals["surrealdb"]
    for req in ("name", "version", "license", "consumer", "trust_model", "removal_boundary", "sha256", "advisory_digest"):
        if req not in surreal:
            findings.append(
                Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb external executable missing '{req}'")
            )

    if "sha256" in surreal and not _HEX64.fullmatch(str(surreal.get("sha256", ""))):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb sha256 must be a 64-character hexadecimal digest"))
    if "advisory_digest" in surreal and not _HEX64.fullmatch(str(surreal.get("advisory_digest", ""))):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_digest must be a 64-character hexadecimal digest"))

    return findings


def _scanner_version(raw_output: str) -> str | None:
    match = re.search(r"\bcargo-deny(?:\.exe)?\s+(\d+\.\d+\.\d+)\b", raw_output, re.IGNORECASE)
    return match.group(1) if match else None


def _rust_policy_options(root: Path, rust_policy: dict | None) -> tuple[list[str], dict, list[str]]:
    config = rust_policy if isinstance(rust_policy, dict) else {}
    config_errors = _validate_rust_policy_config(config, require_fields=True)
    manifest = str(config.get("manifest", "Cargo.toml"))
    lockfile = str(config.get("lockfile", "Cargo.lock"))
    policy_file = str(config.get("policy_file", "deny.toml"))
    targets = config.get("targets", [])
    if isinstance(targets, str):
        targets = [targets]
    targets = [str(target) for target in targets]

    features = config.get("features", "all")
    options = [
        "--manifest-path",
        manifest,
        "--config",
        policy_file,
        "--workspace",
        "--locked",
    ]
    if features == "all":
        options.append("--all-features")
    elif isinstance(features, list) and features:
        options.extend(["--features", ",".join(str(feature) for feature in features)])
    for target in targets:
        options.extend(["--target", target])

    return options, {
        "manifest": manifest,
        "lockfile": lockfile,
        "policy_file": policy_file,
        "targets": targets,
        "features": features,
        "workspace": True,
        "locked": True,
        "config_valid": not config_errors,
        "config_errors": config_errors,
    }, config_errors


def _finding_code_for_scanner_diagnostic(code: str, message: str) -> str:
    lower_code = code.lower()
    lower_message = message.lower()
    if "source" in lower_code or "registry" in lower_code or "registry" in lower_message:
        return "DEP-005"
    if "advisory" in lower_code or "rustsec" in lower_code or "rustsec" in lower_message:
        return "DEP-006"
    return "DEP-004"


def _parse_scanner_stream(
    stream: str,
    stream_name: str,
    findings: list[Finding],
    summary: dict,
    seen_findings: set[tuple[str, str]],
) -> dict:
    result = {
        "json_records": 0,
        "diagnostic_records": 0,
        "summary_records": 0,
        "non_json": [],
        "parse_errors": [],
        "severity_counts": {},
    }

    def schema_error(line_no: int, detail: str) -> None:
        bounded = detail if len(detail) <= 240 else detail[:237] + "..."
        result["parse_errors"].append(bounded)
        findings.append(
            Finding(
                SCANNER_OUTPUT_FINDING,
                "deny.toml",
                1,
                f"cargo-deny {stream_name}:{line_no} has invalid JSON evidence: {bounded}",
            )
        )

    def add_summary(check_name: str, check_summary: dict, line_no: int) -> None:
        prior = summary.get(check_name)
        if prior is not None and prior != check_summary:
            schema_error(line_no, f"conflicting summary for check '{check_name}'")
            return
        summary[check_name] = check_summary

    for line_no, raw_line in enumerate(stream.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            result["non_json"].append(line)
            schema_error(line_no, "non-JSON output line")
            continue

        if not isinstance(entry, dict):
            schema_error(line_no, "top-level record must be an object")
            continue

        if set(entry) != {"type", "fields"}:
            unknown = sorted(set(entry) - {"type", "fields"})
            missing = sorted({"type", "fields"} - set(entry))
            pieces = []
            if missing:
                pieces.append(f"missing keys {missing}")
            if unknown:
                pieces.append(f"unsupported keys {unknown}")
            schema_error(line_no, "; ".join(pieces))
            continue

        entry_type = entry.get("type")
        if not isinstance(entry_type, str) or entry_type not in _SCANNER_RECORD_TYPES:
            schema_error(line_no, f"unsupported record type {entry_type!r}")
            continue

        fields = entry.get("fields")
        if not isinstance(fields, dict):
            schema_error(line_no, "fields must be an object")
            continue

        if entry_type == "summary":
            valid = True
            for check_name, check_summary in fields.items():
                if check_name not in _SUMMARY_CHECKS:
                    schema_error(line_no, f"unsupported summary check {check_name!r}")
                    valid = False
                    continue
                if not isinstance(check_summary, dict):
                    schema_error(line_no, f"summary for '{check_name}' must be an object")
                    valid = False
                    continue
                if set(check_summary) != _SUMMARY_COUNTERS:
                    schema_error(
                        line_no,
                        f"summary for '{check_name}' must contain exactly {sorted(_SUMMARY_COUNTERS)}",
                    )
                    valid = False
                    continue
                if any(
                    isinstance(check_summary[key], bool)
                    or not isinstance(check_summary[key], int)
                    or check_summary[key] < 0
                    for key in _SUMMARY_COUNTERS
                ):
                    schema_error(line_no, f"summary counters for '{check_name}' must be non-negative integers")
                    valid = False
                    continue
                add_summary(check_name, check_summary, line_no)
            if valid:
                result["json_records"] += 1
                result["summary_records"] += 1
            continue

        allowed_fields = {"code", "graphs", "labels", "message", "severity"}
        valid = True
        unknown_fields = sorted(set(fields) - allowed_fields)
        if unknown_fields:
            schema_error(line_no, f"unsupported diagnostic fields {unknown_fields}")
            valid = False
        required_fields = ("severity", "code", "message")
        for field in required_fields:
            if field not in fields:
                schema_error(line_no, f"diagnostic is missing '{field}'")
                valid = False
        severity = fields.get("severity")
        code = fields.get("code")
        message = fields.get("message")
        if not isinstance(severity, str) or severity not in _DIAGNOSTIC_SEVERITIES:
            schema_error(line_no, f"diagnostic severity must be one of {sorted(_DIAGNOSTIC_SEVERITIES)}")
            valid = False
        if not isinstance(code, str) or not code.strip():
            schema_error(line_no, "diagnostic code must be a non-empty string")
            valid = False
        if not isinstance(message, str) or not message.strip():
            schema_error(line_no, "diagnostic message must be a non-empty string")
            valid = False
        for field in ("graphs", "labels"):
            if field in fields and not isinstance(fields[field], list):
                schema_error(line_no, f"diagnostic '{field}' must be an array")
                valid = False
        if not valid:
            continue

        result["json_records"] += 1
        result["diagnostic_records"] += 1
        severity_counts = result["severity_counts"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        if severity != "error":
            continue
        finding_key = (code, message)
        if finding_key in seen_findings:
            continue
        seen_findings.add(finding_key)
        finding_code = _finding_code_for_scanner_diagnostic(code, message)
        findings.append(
            Finding(
                finding_code,
                "deny.toml",
                1,
                f"cargo-deny error ({stream_name}:{line_no}): [{code}] {message}",
            )
        )

    return result


def _summary_error_count(summary: dict) -> int:
    total = 0
    for value in summary.values():
        if isinstance(value, dict):
            try:
                total += int(value.get("errors", 0) or 0)
            except (TypeError, ValueError):
                continue
    return total


def _canonical_digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _git_source_provenance(root: Path) -> tuple[str, dict, Finding | None]:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        detail = f"cannot establish git source provenance: {exc}"
        return "unknown", {"status": "unavailable", "error": detail}, Finding(
            RECEIPT_PROVENANCE_FINDING, "git", 1, detail
        )

    source_sha = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-fA-F]{40,64}", source_sha):
        stderr = result.stderr.strip().replace("\n", " ")
        detail = f"git source provenance unavailable (exit={result.returncode}, stderr={stderr[:240]})"
        return "unknown", {"status": "unavailable", "error": detail, "exit_code": result.returncode}, Finding(
            RECEIPT_PROVENANCE_FINDING, "git", 1, detail
        )
    return source_sha, {"status": "verified", "command": ["git", "rev-parse", "--verify", "HEAD"]}, None


def _receipt_input_paths(root: Path, manifest_data: dict) -> list[str]:
    paths = {
        "Cargo.toml",
        "Cargo.lock",
        "deny.toml",
        "config/dependency-policy.toml",
        "scripts/verify-dependency-policy.py",
        "scripts/requirements-verification.txt",
    }
    ecosystems = manifest_data.get("ecosystems", {})
    if isinstance(ecosystems, dict):
        rust = ecosystems.get("rust", {})
        if isinstance(rust, dict):
            for key in ("manifest", "lockfile", "policy_file"):
                value = rust.get(key)
                if isinstance(value, str) and value.strip() and not Path(value).is_absolute() and ".." not in Path(value).parts:
                    paths.add(value.replace("\\", "/"))
        nuget = ecosystems.get("nuget", {})
        if isinstance(nuget, dict):
            for key in ("project", "lockfile"):
                value = nuget.get(key)
                if isinstance(value, str) and value.strip() and not Path(value).is_absolute() and ".." not in Path(value).parts:
                    paths.add(value.replace("\\", "/"))
        node = ecosystems.get("node", {})
        paths.update(_node_input_paths(root, node))
    return sorted(paths)


def _external_receipt_evidence(root: Path, manifest_data: dict) -> dict:
    externals = manifest_data.get("external_executables", {})
    if not isinstance(externals, dict):
        return {}
    evidence: dict = {}
    for name, config in externals.items():
        if not isinstance(config, dict):
            evidence[str(name)] = {"status": "invalid_configuration"}
            continue
        configured_name = config.get("name", name)
        observed_path = shutil.which(str(configured_name)) if configured_name else None
        observed_digest = None
        if observed_path:
            try:
                observed_digest = sha256_file(Path(observed_path))
            except OSError:
                observed_digest = None
        evidence[str(name)] = {
            "configured": config,
            "observed_executable": str(Path(observed_path).resolve()) if observed_path else None,
            "observed_sha256": observed_digest,
            "status": "observed" if observed_path and observed_digest else "not_observed",
        }
    return evidence


def run_cargo_deny(
    root: Path,
    profile: str,
    scanner_info: dict,
    rust_policy: dict | None = None,
) -> tuple[list[Finding], str, dict]:
    """Run the configured cargo-deny identity and return findings plus evidence.

    cargo-deny emits JSON diagnostics on stderr for this version. Both output
    streams are parsed so a policy failure cannot be mistaken for an unusable
    scanner merely because stdout is empty.
    """

    findings: list[Finding] = []
    executable_name = str(scanner_info.get("executable", "cargo-deny"))
    exec_path = shutil.which(executable_name)
    execution: dict = {
        "configured_executable": executable_name,
        "configured_version": scanner_info.get("version"),
        "configured_sha256": scanner_info.get("sha256"),
        "profile": profile,
        "identity_verified": False,
    }

    if not exec_path:
        findings.append(Finding("DEP-001", "deny.toml", 1, f"scanner tool '{executable_name}' not found on PATH"))
        execution["status"] = STATUS_TOOL_UNAVAILABLE
        return findings, STATUS_TOOL_UNAVAILABLE, {"_execution": execution}

    try:
        observed_digest = sha256_file(Path(exec_path)).lower()
    except OSError as exc:
        findings.append(Finding("DEP-001", "deny.toml", 1, f"cannot read scanner executable '{exec_path}': {exc}"))
        execution["status"] = STATUS_TOOL_UNAVAILABLE
        return findings, STATUS_TOOL_UNAVAILABLE, {"_execution": execution}

    try:
        version_proc = subprocess.run(
            [exec_path, "--version"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        findings.append(Finding("DEP-001", "deny.toml", 1, f"cannot execute scanner identity probe: {exc}"))
        execution["observed_sha256"] = observed_digest
        execution["status"] = STATUS_TOOL_UNAVAILABLE
        return findings, STATUS_TOOL_UNAVAILABLE, {"_execution": execution}

    version_output = "\n".join(part for part in (version_proc.stdout, version_proc.stderr) if part)
    observed_version = _scanner_version(version_output)
    execution.update(
        {
            "executable": str(Path(exec_path).resolve()),
            "observed_version": observed_version,
            "observed_sha256": observed_digest,
            "version_probe_exit_code": version_proc.returncode,
        }
    )

    expected_version = str(scanner_info.get("version", ""))
    expected_digest = str(scanner_info.get("sha256", "")).lower()
    if version_proc.returncode != 0 or not observed_version:
        findings.append(
            Finding(
                SCANNER_IDENTITY_FINDING,
                "config/dependency-policy.toml",
                1,
                f"scanner identity probe did not report cargo-deny version (exit={version_proc.returncode})",
            )
        )
    elif expected_version and observed_version != expected_version:
        findings.append(
            Finding(
                SCANNER_IDENTITY_FINDING,
                "config/dependency-policy.toml",
                1,
                f"scanner version mismatch: configured {expected_version}, observed {observed_version}",
            )
        )

    if expected_digest and observed_digest != expected_digest:
        findings.append(
            Finding(
                SCANNER_IDENTITY_FINDING,
                "config/dependency-policy.toml",
                1,
                f"scanner executable SHA-256 mismatch: configured {expected_digest}, observed {observed_digest}",
            )
        )

    if findings:
        execution["status"] = STATUS_CONFLICTED
        return findings, STATUS_CONFLICTED, {"_execution": execution}

    execution["identity_verified"] = True
    option_args, option_evidence, config_errors = _rust_policy_options(root, rust_policy)
    execution.update(option_evidence)
    if config_errors:
        for detail in config_errors:
            findings.append(Finding("DEP-002", "config/dependency-policy.toml", 1, detail))
        execution["status"] = STATUS_CONFLICTED
        return findings, STATUS_CONFLICTED, {"_execution": execution}

    checks = ["bans", "licenses", "sources"]
    if profile == "current-advisories":
        checks.insert(0, "advisories")
    if profile == "offline-source":
        option_args.append("--offline")

    cmd = [exec_path, "--format", "json", "--color", "never"] + option_args + ["check"] + checks
    execution["checks"] = checks
    execution["offline"] = profile == "offline-source"
    execution["command"] = [str(arg) for arg in cmd]

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        findings.append(Finding("DEP-001", "deny.toml", 1, "cargo-deny execution timed out after 180s"))
        execution["status"] = STATUS_TOOL_UNAVAILABLE
        return findings, STATUS_TOOL_UNAVAILABLE, {"_execution": execution}
    except OSError as exc:
        findings.append(Finding("DEP-001", "deny.toml", 1, f"cargo-deny execution error: {exc}"))
        execution["status"] = STATUS_TOOL_UNAVAILABLE
        return findings, STATUS_TOOL_UNAVAILABLE, {"_execution": execution}

    execution["exit_code"] = proc.returncode
    summary: dict = {}
    seen_findings: set[tuple[str, str]] = set()
    stdout_result = _parse_scanner_stream(
        proc.stdout, "stdout", findings, summary, seen_findings
    )
    stderr_result = _parse_scanner_stream(
        proc.stderr, "stderr", findings, summary, seen_findings
    )
    severity_counts: dict[str, int] = {}
    for result in (stdout_result, stderr_result):
        for severity, count in result["severity_counts"].items():
            severity_counts[severity] = severity_counts.get(severity, 0) + count
    parse_errors = stdout_result["parse_errors"] + stderr_result["parse_errors"]
    non_json = stdout_result["non_json"] + stderr_result["non_json"]
    parsed_records = stdout_result["json_records"] + stderr_result["json_records"]
    diagnostic_records = stdout_result["diagnostic_records"] + stderr_result["diagnostic_records"]
    summary_records = stdout_result["summary_records"] + stderr_result["summary_records"]
    execution.update(
        {
            "stdout_json_records": stdout_result["json_records"],
            "stderr_json_records": stderr_result["json_records"],
            "stdout_diagnostic_records": stdout_result["diagnostic_records"],
            "stderr_diagnostic_records": stderr_result["diagnostic_records"],
            "summary_records": summary_records,
            "non_json_output_lines": len(non_json),
            "scanner_parse_errors": len(parse_errors),
            "scanner_parse_error_details": parse_errors[:20],
            "diagnostic_severity_counts": severity_counts,
        }
    )

    expected_checks = set(checks)
    actual_checks = set(summary)
    if summary_records == 0:
        findings.append(
            Finding(
                SCANNER_OUTPUT_FINDING,
                "deny.toml",
                1,
                f"cargo-deny emitted no valid summary record for checks {sorted(expected_checks)}",
            )
        )
    elif actual_checks != expected_checks:
        missing_checks = sorted(expected_checks - actual_checks)
        unexpected_checks = sorted(actual_checks - expected_checks)
        findings.append(
            Finding(
                SCANNER_OUTPUT_FINDING,
                "deny.toml",
                1,
                f"cargo-deny summary checks are inconsistent (missing={missing_checks}, unexpected={unexpected_checks})",
            )
        )

    summary_errors = _summary_error_count(summary)
    observed_errors = severity_counts.get("error", 0)
    if summary_errors != observed_errors:
        findings.append(
            Finding(
                SCANNER_OUTPUT_FINDING,
                "deny.toml",
                1,
                f"cargo-deny summary error count {summary_errors} does not match {observed_errors} parsed error diagnostics",
            )
        )

    summary_warnings = sum(
        int(value.get("warnings", 0))
        for value in summary.values()
        if isinstance(value, dict) and isinstance(value.get("warnings"), int)
    )
    observed_warnings = severity_counts.get("warning", 0)
    if summary_warnings != observed_warnings:
        findings.append(
            Finding(
                SCANNER_OUTPUT_FINDING,
                "deny.toml",
                1,
                f"cargo-deny summary warning count {summary_warnings} does not match {observed_warnings} parsed warning diagnostics",
            )
        )

    combined_output = f"{proc.stdout}\n{proc.stderr}".lower()
    advisory_policy_finding = any(
        f.code == "DEP-006" and re.search(r"rustsec-\d{4}-\d+", f.detail, re.IGNORECASE) for f in findings
    )
    if profile == "current-advisories" and proc.returncode != 0 and not advisory_policy_finding:
        advisory_unavailable_markers = (
            "advisory database",
            "failed to fetch",
            "could not fetch",
            "unable to fetch",
            "network",
        )
        if any(marker in combined_output for marker in advisory_unavailable_markers):
            if not any(f.code == "DEP-006" for f in findings):
                findings.append(
                    Finding(
                        "DEP-006",
                        "deny.toml",
                        1,
                        "cargo-deny could not establish the current advisory database evidence",
                    )
                )
            execution["status"] = STATUS_ADVISORY_SOURCE_UNAVAILABLE
            return findings, STATUS_ADVISORY_SOURCE_UNAVAILABLE, {**summary, "_execution": execution}

        stale_markers = ("stale", "out of date", "older than")
        if any(marker in combined_output for marker in stale_markers):
            if not any(f.code == "DEP-006" for f in findings):
                findings.append(
                    Finding(
                        "DEP-006",
                        "deny.toml",
                        1,
                        "cargo-deny advisory evidence is stale and cannot support current-advisory proof",
                    )
                )
            execution["status"] = STATUS_STALE
            return findings, STATUS_STALE, {**summary, "_execution": execution}

    if proc.returncode != 0 and not findings:
        detail = (proc.stderr or proc.stdout).strip().replace("\n", " ")
        if len(detail) > 400:
            detail = detail[:400] + "..."
        findings.append(
            Finding(
                SCANNER_OUTPUT_FINDING,
                "deny.toml",
                1,
                f"cargo-deny exited nonzero ({proc.returncode}) without a parsed policy diagnostic: {detail}",
            )
        )

    if proc.returncode == 0 and parsed_records == 0:
        findings.append(
            Finding(
                SCANNER_OUTPUT_FINDING,
                "deny.toml",
                1,
                "cargo-deny returned success without machine-readable JSON evidence",
            )
        )

    status = STATUS_PASS if not findings else STATUS_FINDINGS
    execution["status"] = status
    return findings, status, {**summary, "_execution": execution}


def build_receipt(
    root: Path,
    profile: str,
    status: str,
    findings: list[Finding],
    manifest_data: dict,
    cargo_summary: dict,
    direct_deps: set[str] | int,
) -> dict:
    source_sha, source_provenance, source_finding = _git_source_provenance(root)
    if source_finding is not None:
        findings.append(source_finding)

    input_paths = _receipt_input_paths(root, manifest_data)
    digests = {}
    missing_inputs = []
    for relative_path in input_paths:
        fp = root / relative_path
        if fp.is_file():
            digests[relative_path] = sha256_file(fp)
        else:
            missing_inputs.append(relative_path)

    scanner = manifest_data.get("scanner", {})
    if not isinstance(scanner, dict):
        scanner = {}
    scanner_execution = cargo_summary.get("_execution", {}) if isinstance(cargo_summary, dict) else {}
    scanner_summary = (
        {key: value for key, value in cargo_summary.items() if key != "_execution"}
        if isinstance(cargo_summary, dict)
        else {}
    )
    ecosystems = manifest_data.get("ecosystems", {})
    rust_policy = ecosystems.get("rust", {}) if isinstance(ecosystems, dict) else {}
    if not isinstance(rust_policy, dict):
        rust_policy = {}
    nuget_policy = ecosystems.get("nuget", {}) if isinstance(ecosystems, dict) else {}
    if not isinstance(nuget_policy, dict):
        nuget_policy = {}
    node_policy = ecosystems.get("node", {}) if isinstance(ecosystems, dict) else {}
    if not isinstance(node_policy, dict):
        node_policy = {}
    if isinstance(direct_deps, set):
        direct_dependency_names = sorted(direct_deps)
        direct_dependency_count = len(direct_deps)
    else:
        direct_dependency_names = []
        direct_dependency_count = int(direct_deps)
    effective_status = STATUS_FINDINGS if status == STATUS_PASS and findings else status
    ceiling = (
        "DEPENDENCY_ADMISSION_AND_ADVISORY_EVIDENCE_CANDIDATE"
        if profile == "current-advisories"
        else "OFFLINE_SOURCE_EVIDENCE_ONLY"
    )

    receipt = {
        "schema": "eliot.dependency-policy-receipt.v1",
        "profile": profile,
        "proof_ceiling": ceiling,
        "status": effective_status,
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_sha": source_sha,
        "source_provenance": source_provenance,
        "scanner": {
            "tool": scanner.get("tool", "cargo-deny"),
            "version": scanner.get("version", "0.20.2"),
            "executable_sha256": scanner.get("sha256", ""),
            "advisory_owner": scanner.get("advisory_owner", "cargo-deny"),
            "observed_version": scanner_execution.get("observed_version"),
            "observed_executable_sha256": scanner_execution.get("observed_sha256"),
            "identity_verified": scanner_execution.get("identity_verified", False),
        },
        "ecosystem_denominator": {
            "rust": {
                "direct_dependencies_count": direct_dependency_count,
                "direct_dependencies": direct_dependency_names,
                "manifest": rust_policy.get("manifest", "Cargo.toml"),
                "lockfile": rust_policy.get("lockfile", "Cargo.lock"),
                "policy_file": rust_policy.get("policy_file", "deny.toml"),
                "workspace": True,
                "locked": True,
                "targets": rust_policy.get("targets", []),
                "features": rust_policy.get("features", "all"),
            },
            "nuget": {
                "project": nuget_policy.get("project"),
                "lock_mode": "RestorePackagesWithLockFile",
                "lockfile": nuget_policy.get("lockfile"),
                "target_framework": nuget_policy.get("target_framework"),
            },
            "python": {
                "manifest": (ecosystems.get("python", {}) if isinstance(ecosystems.get("python", {}), dict) else {}).get(
                    "manifest", "scripts/requirements-verification.txt"
                ),
                "hash_locked": True,
            },
            "node": {
                "contract": node_policy.get("contract"),
                "manifest": node_policy.get("manifest"),
                "inputs": _node_input_paths(root, node_policy),
            },
            "external_executables": list(manifest_data.get("external_executables", {}).keys()),
        },
        "input_digests": digests,
        "missing_inputs": missing_inputs,
        "exceptions": manifest_data.get("exceptions", []),
        "exceptions_digest": _canonical_digest(manifest_data.get("exceptions", [])),
        "direct_dependency_identity": cargo_summary.get("_direct_dependency_identity", {})
        if isinstance(cargo_summary, dict)
        else {},
        "external_executable_evidence": _external_receipt_evidence(root, manifest_data),
        "scanner_summary": scanner_summary,
        "scanner_execution": scanner_execution,
        "findings_count": len(findings),
        "findings": [
            {"code": f.code, "path": f.path, "line": f.line, "detail": f.detail} for f in findings
        ],
    }

    if profile == "current-advisories":
        if effective_status == STATUS_ADVISORY_SOURCE_UNAVAILABLE:
            advisory_status = "unavailable"
        elif effective_status in (STATUS_CONFLICTED, STATUS_TOOL_UNAVAILABLE, STATUS_NOT_EXECUTED, STATUS_STALE):
            advisory_status = "not_established"
        elif any(f.code == "DEP-006" for f in findings):
            advisory_status = "findings"
        else:
            advisory_status = "ok"
        receipt["advisory_snapshot"] = {
            "source": "https://github.com/rustsec/advisory-db",
            "evaluated_at_utc": receipt["timestamp_utc"],
            "status": advisory_status,
            "digest": None,
            "digest_status": "not_bound_by_cargo-deny_receipt",
        }

    return receipt


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.code, finding.path, finding.line, finding.detail)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def _derive_overall_status(scanner_status: str, findings: list[Finding]) -> str:
    if scanner_status == STATUS_TOOL_UNAVAILABLE or any(f.code == "DEP-001" for f in findings):
        return STATUS_TOOL_UNAVAILABLE
    if scanner_status == STATUS_ADVISORY_SOURCE_UNAVAILABLE:
        return STATUS_ADVISORY_SOURCE_UNAVAILABLE
    if scanner_status in (STATUS_STALE, STATUS_CONFLICTED, STATUS_NOT_EXECUTED):
        return scanner_status
    if any(f.code in ("DEP-002", "DEP-003", RECEIPT_PROVENANCE_FINDING, IDENTITY_BINDING_FINDING, NODE_ECOSYSTEM_FINDING) for f in findings):
        return STATUS_INCOMPLETE
    if any(f.code == "DEP-006" for f in findings):
        return STATUS_FINDINGS
    return STATUS_FINDINGS if findings else STATUS_PASS


def verify_all(root: Path, profile: str) -> tuple[list[Finding], str, dict, dict, int]:
    all_findings: list[Finding] = []

    # 1. Check policy manifest
    m_findings, manifest_data = check_policy_manifest(root)
    all_findings.extend(m_findings)

    # 2. Check Rust direct dependencies & inventory
    d_findings, direct_deps = collect_direct_rust_dependencies(root)
    all_findings.extend(d_findings)
    inv_findings = check_cargo_inventory(manifest_data, direct_deps)
    all_findings.extend(inv_findings)

    ecosystems = manifest_data.get("ecosystems", {})
    rust_policy = ecosystems.get("rust", {}) if isinstance(ecosystems, dict) else {}
    rust_policy = rust_policy if isinstance(rust_policy, dict) else {}
    identity_findings, direct_dependency_identity = collect_locked_dependency_identity(
        root, direct_deps, rust_policy.get("lockfile")
    )
    all_findings.extend(identity_findings)

    # 3. Check exceptions
    exc_findings = check_exceptions(manifest_data)
    all_findings.extend(exc_findings)

    # 4. Check NuGet
    nuget_policy = ecosystems.get("nuget", {}) if isinstance(ecosystems, dict) else {}
    nu_findings = check_nuget_ecosystem(root, nuget_policy if isinstance(nuget_policy, dict) else {})
    all_findings.extend(nu_findings)

    # 5. Check Python requirements
    py_findings = check_python_ecosystem(root)
    all_findings.extend(py_findings)

    # 6. Check configured Node ecosystem inputs
    node_policy = ecosystems.get("node", {}) if isinstance(ecosystems, dict) else {}
    node_findings = check_node_ecosystem(root, node_policy if isinstance(node_policy, dict) else {})
    all_findings.extend(node_findings)

    # 7. Check external executables
    ext_findings = check_external_executables(manifest_data)
    all_findings.extend(ext_findings)

    # 8. Run cargo deny scanner
    scanner_info = manifest_data.get("scanner", {})
    if not isinstance(scanner_info, dict):
        scanner_info = {}
    scanner_findings, scanner_status, cargo_summary = run_cargo_deny(
        root,
        profile,
        scanner_info,
        rust_policy if isinstance(rust_policy, dict) else {},
    )
    all_findings.extend(scanner_findings)
    if isinstance(cargo_summary, dict):
        cargo_summary["_direct_dependency_identity"] = direct_dependency_identity
    if profile == "current-advisories":
        all_findings.append(
            Finding(
                IDENTITY_BINDING_FINDING,
                "config/dependency-policy.toml",
                1,
                "current advisory evidence has no content digest binding in cargo-deny's receipt",
            )
        )

    all_findings = _deduplicate_findings(all_findings)
    overall_status = _derive_overall_status(scanner_status, all_findings)

    receipt = build_receipt(
        root, profile, overall_status, all_findings, manifest_data, cargo_summary, direct_deps
    )
    all_findings = _deduplicate_findings(all_findings)
    overall_status = _derive_overall_status(scanner_status, all_findings)
    receipt["status"] = overall_status
    receipt["findings_count"] = len(all_findings)
    receipt["findings"] = [
        {"code": f.code, "path": f.path, "line": f.line, "detail": f.detail} for f in all_findings
    ]

    return all_findings, overall_status, receipt, manifest_data, len(direct_deps)


def run_self_tests() -> int:
    import tempfile

    print("Running verify-dependency-policy self-tests...")

    # Case 1: missing manifest
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        findings, data = check_policy_manifest(root)
        if not any(f.code == "DEP-002" for f in findings):
            print("SELF_TEST_FAILURE: expected DEP-002 for missing manifest", file=sys.stderr)
            return 1

    # Case 2: missing dependency in inventory
    manifest_fixture = {
        "schema": "eliot.dependency-policy.v1",
        "scanner": {"tool": "cargo-deny"},
        "direct_dependencies": {
            "dep1": {
                "consumer": "test",
                "owner": "test",
                "reason": "test",
                "features": [],
                "public_exposure": "none",
                "removal_plan": "none",
            }
        },
    }
    findings = check_cargo_inventory(manifest_fixture, {"dep1", "dep_unaccounted"})
    if not any(f.code == "DEP-003" and "dep_unaccounted" in f.detail for f in findings):
        print("SELF_TEST_FAILURE: expected DEP-003 for missing inventory item", file=sys.stderr)
        return 1

    # Case 3: expired exception
    manifest_exc = {
        "exceptions": [
            {
                "package": "vuln-pkg",
                "version": "1.0.0",
                "advisory": "RUSTSEC-2020-0001",
                "owner": "security",
                "compensating_control": "isolated",
                "expires_at": "2020-01-01T00:00:00Z",
                "removal_condition": "replace",
            }
        ]
    }
    findings = check_exceptions(manifest_exc, now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc))
    if not any(f.code == "DEP-010" and "expired on 2020-01-01" in f.detail for f in findings):
        print("SELF_TEST_FAILURE: expected DEP-010 for expired exception", file=sys.stderr)
        return 1

    # Case 4: unhashed python requirement
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sdir = root / "scripts"
        sdir.mkdir(parents=True)
        (sdir / "requirements-verification.txt").write_text("jsonschema==4.25.1\n", encoding="utf-8")
        findings = check_python_ecosystem(root)
        if not any(f.code == "DEP-008" for f in findings):
            print("SELF_TEST_FAILURE: expected DEP-008 for unhashed python requirement", file=sys.stderr)
            return 1

    # Case 5: missing nuget lockfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        op_dir = root / "apps" / "Eliot.Operator"
        op_dir.mkdir(parents=True)
        (op_dir / "Eliot.Operator.csproj").write_text(
            "<Project><PropertyGroup><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup></Project>",
            encoding="utf-8",
        )
        findings = check_nuget_ecosystem(root)
        if not any(f.code == "DEP-007" and "missing" in f.detail for f in findings):
            print("SELF_TEST_FAILURE: expected DEP-007 for missing nuget packages.lock.json", file=sys.stderr)
            return 1

    # Case 6: missing external executable inventory
    findings = check_external_executables({})
    if not any(f.code == "DEP-009" and "surrealdb" in f.detail for f in findings):
        print("SELF_TEST_FAILURE: expected DEP-009 for missing external executable", file=sys.stderr)
        return 1

    # Case 7: scanner tool missing
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        scanner_info = {"executable": "nonexistent-scanner-tool-12345"}
        findings, status, _ = run_cargo_deny(root, "offline-source", scanner_info)
        if status != STATUS_TOOL_UNAVAILABLE or not any(f.code == "DEP-001" for f in findings):
            print("SELF_TEST_FAILURE: expected TOOL_UNAVAILABLE for missing scanner", file=sys.stderr)
            return 1

    # Case 8: receipt generation structure
    receipt = build_receipt(
        Path("."),
        "current-advisories",
        STATUS_PASS,
        [],
        manifest_fixture,
        {"bans": {"errors": 0}},
        1,
    )
    if receipt.get("proof_ceiling") != "DEPENDENCY_ADMISSION_AND_ADVISORY_EVIDENCE_CANDIDATE":
        print("SELF_TEST_FAILURE: expected candidate proof ceiling in receipt", file=sys.stderr)
        return 1
    if "advisory_snapshot" not in receipt:
        print("SELF_TEST_FAILURE: expected advisory_snapshot in current-advisories receipt", file=sys.stderr)
        return 1

    print("DEPENDENCY_POLICY_SELF_TEST: PASS (8/8 cases verified)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify multi-ecosystem dependency admission policy.")
    parser.add_argument("--root", default=".", help="Repository root directory")
    parser.add_argument(
        "--profile",
        choices=["offline-source", "current-advisories"],
        default="offline-source",
        help="Verification profile to execute",
    )
    parser.add_argument("--json-out", help="Write findings to JSON output file")
    parser.add_argument("--receipt-out", help="Write canonical receipt to JSON output file")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests")
    args = parser.parse_args()

    if args.self_test:
        return run_self_tests()

    root = Path(args.root).resolve()
    findings, status, receipt, _, _ = verify_all(root, args.profile)

    if args.json_out:
        out_p = Path(args.json_out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "status": status,
            "profile": args.profile,
            "findings_count": len(findings),
            "findings": [
                {"code": f.code, "path": f.path, "line": f.line, "detail": f.detail} for f in findings
            ],
        }
        out_p.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.receipt_out:
        rec_p = Path(args.receipt_out)
        rec_p.parent.mkdir(parents=True, exist_ok=True)
        rec_p.write_text(json.dumps(receipt, indent=2), encoding="utf-8")

    print(f"VERIFY_DEPENDENCY_POLICY: {status} (profile={args.profile}, findings={len(findings)})")
    for f in findings:
        print(f"  [{f.code}] {f.path}:{f.line}: {f.detail}")

    return 0 if status == STATUS_PASS else 1


if __name__ == "__main__":
    sys.exit(main())
