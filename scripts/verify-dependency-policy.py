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
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
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
_HEX40 = re.compile(r"[0-9a-fA-F]{40}")
_GHSA_ID = re.compile(r"GHSA-[0-9A-Za-z]+-[0-9A-Za-z]+-[0-9A-Za-z]+$")
_TARGET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_SEMVER = re.compile(r"(\d+)\.(\d+)\.(\d+)$")
_SCANNER_RECORD_TYPES = {"diagnostic", "summary"}
_DIAGNOSTIC_SEVERITIES = {"error", "warning", "note", "help"}
_SUMMARY_CHECKS = {"advisories", "bans", "licenses", "sources"}
_SUMMARY_COUNTERS = {"errors", "warnings", "notes", "helps"}
_REPARSE_POINT = 0x400


def _stable_file_identity(stat_result: os.stat_result) -> tuple[object, ...]:
    return (
        getattr(stat_result, "st_dev", None),
        getattr(stat_result, "st_ino", None),
        getattr(stat_result, "st_size", None),
        getattr(stat_result, "st_mtime_ns", None),
    )


def _assert_no_reparse_parents(path: Path) -> None:
    current = path
    while True:
        stat_result = current.lstat()
        attributes = getattr(stat_result, "st_file_attributes", 0)
        if current.is_symlink() or attributes & _REPARSE_POINT:
            raise OSError(f"path contains a symlink or reparse component: {current}")
        parent = current.parent
        if parent == current:
            break
        current = parent


def _open_nofollow_read_handle(path: Path) -> int:
    """Open a resident file while denying replacement during the read."""

    if os.name == "nt":
        import ctypes
        import msvcrt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        handle = kernel32.CreateFileW(
            str(path),
            0x80000000,  # GENERIC_READ
            0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE; deny delete/rename
            None,
            3,  # OPEN_EXISTING
            0x00000080 | 0x00200000,  # FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle == invalid:
            error = ctypes.get_last_error()
            raise OSError(error, f"CreateFileW failed for {path}")
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))

    return os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))


def _read_stable_file_bytes(path: Path, label: str) -> tuple[bytes, tuple[object, ...]]:
    """Read and hash one path through a no-follow handle and identity fence."""

    _assert_no_reparse_parents(path)
    fd: int | None = None
    try:
        fd = _open_nofollow_read_handle(path)
        before = os.fstat(fd)
        if getattr(before, "st_file_attributes", 0) & _REPARSE_POINT:
            raise OSError(f"{label} opened as a reparse point: {path}")
        chunks: list[bytes] = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(fd)
        if getattr(after, "st_file_attributes", 0) & _REPARSE_POINT:
            raise OSError(f"{label} became a reparse point while being read: {path}")
    finally:
        if fd is not None:
            os.close(fd)
    if _stable_file_identity(before) != _stable_file_identity(after):
        raise OSError(f"{label} changed while being read: {path}")
    _assert_no_reparse_parents(path)
    return b"".join(chunks), _stable_file_identity(after)


def _pe_machine(payload: bytes) -> int | None:
    """Return the PE machine value only when the payload is a well-formed PE."""

    if len(payload) < 0x40 or payload[:2] != b"MZ":
        return None
    pe_offset = int.from_bytes(payload[0x3C:0x40], "little")
    if pe_offset < 0 or pe_offset + 6 > len(payload) or payload[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None
    return int.from_bytes(payload[pe_offset + 4 : pe_offset + 6], "little")


def sha256_file(path: Path) -> str:
    payload, _ = _read_stable_file_bytes(path, "file")
    h = hashlib.sha256()
    h.update(payload)
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
    root: Path,
    raw_value: object,
    label: str,
    findings: list[Finding] | None = None,
    finding_code: str = NODE_ECOSYSTEM_FINDING,
) -> tuple[Path | None, str | None]:
    path, path_findings = _configured_repo_path(root, raw_value, label, finding_code)
    if findings is not None:
        findings.extend(path_findings)
    if path is None:
        return None, None

    def fail(detail: str) -> tuple[Path | None, str | None]:
        if findings is not None:
            findings.append(Finding(finding_code, "config/dependency-policy.toml", 1, detail))
        return None, None

    try:
        root_resolved = root.resolve(strict=True)
        lexical_path = root_resolved / Path(raw_value)
        lexical_relative = lexical_path.relative_to(root_resolved)
    except (OSError, TypeError, ValueError):
        return fail(f"{label} must resolve within the repository")

    # Resolve and inspect every existing component.  Path.resolve() alone is
    # insufficient for the receipt boundary: a symlink/junction can change
    # between the textual path check and the later read/hash operation.  Node
    # inputs are metadata, so rejecting all reparse components is the safe
    # policy even when the target would resolve back inside the repository.
    current = root_resolved
    for component in lexical_relative.parts:
        current = current / component
        try:
            attributes = getattr(current.lstat(), "st_file_attributes", 0)
        except FileNotFoundError:
            continue
        except OSError as exc:
            return fail(f"{label} cannot inspect repository path component {current}: {exc}")
        if current.is_symlink() or attributes & 0x400:
            return fail(f"{label} contains a symlink or reparse-point component: {current}")

    try:
        resolved_path = lexical_path.resolve(strict=False)
        relative_path = resolved_path.relative_to(root_resolved)
    except (OSError, ValueError):
        return fail(f"{label} must resolve within the repository")
    relative = str(relative_path).replace("\\", "/")
    if not relative or relative == ".":
        return fail(f"{label} must resolve to a non-root repository path")
    return resolved_path, relative


def _open_node_read_handle(path: Path) -> int:
    """Open one Node input without following its final reparse component."""

    if os.name == "nt":
        import ctypes
        import msvcrt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        handle = kernel32.CreateFileW(
            str(path),
            0x80000000,  # GENERIC_READ
            0x00000001 | 0x00000002,  # share read/write; deny delete/rename
            None,
            3,  # OPEN_EXISTING
            0x00000080 | 0x00200000,  # FILE_ATTRIBUTE_NORMAL | OPEN_REPARSE_POINT
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle == invalid:
            error = ctypes.get_last_error()
            raise OSError(error, f"CreateFileW failed for {path}")
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags)


def _node_stat_identity(stat_result: os.stat_result) -> tuple[object, ...]:
    return (
        getattr(stat_result, "st_dev", None),
        getattr(stat_result, "st_ino", None),
        getattr(stat_result, "st_size", None),
        getattr(stat_result, "st_mtime_ns", None),
    )


def _read_validated_repo_bytes(
    root: Path,
    raw_path: object,
    label: str,
    findings: list[Finding] | None = None,
    finding_code: str = NODE_ECOSYSTEM_FINDING,
) -> tuple[Path | None, str | None, bytes | None, tuple[object, ...] | None]:
    """Read one repository file through a contained, no-follow identity fence.

    The returned bytes and identity are bound to
    the same handle, and the path is revalidated after the handle is closed.
    """

    path, relative = _validated_node_input(root, raw_path, label, findings, finding_code)
    if path is None or relative is None:
        return None, None, None, None

    fd: int | None = None
    try:
        fd = _open_node_read_handle(path)
        before = os.fstat(fd)
        if getattr(before, "st_file_attributes", 0) & _REPARSE_POINT:
            raise OSError(f"{label} opened as a reparse point: {path}")
        chunks: list[bytes] = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(fd)
    except (OSError, ValueError) as exc:
        if findings is not None:
            findings.append(Finding(finding_code, relative, 0, f"{label} cannot be read through a safe handle: {exc}"))
        return path, relative, None, None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    if getattr(after, "st_file_attributes", 0) & _REPARSE_POINT:
        if findings is not None:
            findings.append(Finding(finding_code, relative, 0, f"{label} became a reparse point while being read"))
        return path, relative, None, None
    if _node_stat_identity(before) != _node_stat_identity(after):
        if findings is not None:
            findings.append(Finding(finding_code, relative, 0, f"{label} changed while it was being read"))
        return path, relative, None, None

    revalidated, revalidated_relative = _validated_node_input(root, relative, label, findings, finding_code)
    if revalidated is None or revalidated_relative != relative:
        if findings is not None:
            findings.append(Finding(finding_code, relative, 0, f"{label} failed repository revalidation after read"))
        return path, relative, None, None
    try:
        path_stat = revalidated.stat()
    except OSError as exc:
        if findings is not None:
            findings.append(Finding(finding_code, relative, 0, f"{label} cannot be re-stat'ed after read: {exc}"))
        return path, relative, None, None
    if _node_stat_identity(after) != _node_stat_identity(path_stat):
        if findings is not None:
            findings.append(Finding(finding_code, relative, 0, f"{label} path identity changed during read/hash"))
        return path, relative, None, None
    return path, relative, b"".join(chunks), _node_stat_identity(after)


def _read_validated_node_bytes(
    root: Path,
    relative_path: str,
    label: str,
    findings: list[Finding] | None = None,
) -> bytes | None:
    """Read Node input through the shared no-follow/revalidation boundary."""

    _, _, payload, _ = _read_validated_repo_bytes(root, relative_path, label, findings)
    return payload


def _node_input_paths(
    root: Path, node_policy: dict | None, findings: list[Finding] | None = None
) -> list[str]:
    policy = node_policy if isinstance(node_policy, dict) else {}
    paths: list[str] = []

    contract_path, contract_relative = _validated_node_input(
        root, policy.get("contract"), "[ecosystems.node].contract"
    )
    if contract_relative:
        paths.append(contract_relative)

    if contract_path is not None and contract_relative:
        contract_bytes = _read_validated_node_bytes(
            root, contract_relative, "Node contract", findings
        )
        try:
            contract = json.loads(contract_bytes.decode("utf-8")) if contract_bytes is not None else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            contract = {}
        surface = contract.get("surface") if isinstance(contract, dict) else None
        if isinstance(surface, str) and surface.strip():
            _, surface_relative = _validated_node_input(
                root, surface, "Node contract surface", findings
            )
            if surface_relative:
                paths.append(surface_relative)

    manifest_path, manifest_relative = _validated_node_input(
        root, policy.get("manifest"), "[ecosystems.node].manifest"
    )
    if manifest_relative:
        paths.append(manifest_relative)

    if manifest_path is not None and manifest_relative:
        manifest_bytes = _read_validated_node_bytes(
            root, manifest_relative, "Node manifest", findings
        )
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8")) if manifest_bytes is not None else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            manifest = {}
        instructions = manifest.get("instructions", []) if isinstance(manifest, dict) else []
        if isinstance(instructions, list):
            for instruction in instructions:
                if isinstance(instruction, str) and instruction.strip():
                    try:
                        relative_instruction = (manifest_path.parent / instruction).relative_to(root.resolve())
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
    contract_path, contract_relative = _validated_node_input(
        root,
        policy.get("contract"),
        "[ecosystems.node].contract",
        findings,
    )
    manifest_path, manifest_relative = _validated_node_input(
        root,
        policy.get("manifest"),
        "[ecosystems.node].manifest",
        findings,
    )
    if contract_path is None or manifest_path is None:
        return findings

    contract: dict = {}
    contract_bytes = (
        _read_validated_node_bytes(root, contract_relative, "Node contract", findings)
        if contract_relative
        else None
    )
    if contract_bytes is None:
        findings.append(
            Finding(NODE_ECOSYSTEM_FINDING, contract_relative or "config/dependency-policy.toml", 0, "configured Node contract is missing")
        )
    else:
        try:
            value = json.loads(contract_bytes.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("top-level value must be an object")
            contract = value
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            findings.append(
                Finding(
                    NODE_ECOSYSTEM_FINDING,
                    contract_relative or "config/dependency-policy.toml",
                    1,
                    f"malformed configured Node contract: {exc}",
                )
            )
        else:
            for field in ("schema_version", "surface", "authority_ceiling", "tool_identity"):
                if field not in contract:
                    findings.append(Finding(NODE_ECOSYSTEM_FINDING, "config/dependency-policy.toml", 1, f"Node contract missing '{field}'"))
            surface = contract.get("surface")
            if not isinstance(surface, str) or not surface.strip():
                findings.append(
                    Finding(
                        NODE_ECOSYSTEM_FINDING,
                        contract_relative or "config/dependency-policy.toml",
                        1,
                        "Node contract surface must be a non-empty string",
                    )
                )
            else:
                surface_path, surface_relative = _validated_node_input(
                    root, surface, "Node contract surface", findings
                )
                surface_bytes = (
                    _read_validated_node_bytes(root, surface_relative, "Node contract surface", findings)
                    if surface_relative
                    else None
                )
                if surface_path is not None and surface_bytes is None:
                    findings.append(
                        Finding(
                            NODE_ECOSYSTEM_FINDING,
                            surface_relative or "config/dependency-policy.toml",
                            0,
                            "Node contract surface is missing",
                        )
                    )

    manifest_bytes = (
        _read_validated_node_bytes(root, manifest_relative, "Node manifest", findings)
        if manifest_relative
        else None
    )
    if manifest_bytes is None:
        findings.append(
            Finding(NODE_ECOSYSTEM_FINDING, manifest_relative or "config/dependency-policy.toml", 0, "configured Node manifest is missing")
        )
    else:
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("top-level value must be an object")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            findings.append(
                Finding(
                    NODE_ECOSYSTEM_FINDING,
                    manifest_relative or "config/dependency-policy.toml",
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
                    try:
                        relative_instruction = (manifest_path.parent / instruction).relative_to(root.resolve())
                    except ValueError:
                        findings.append(Finding(NODE_ECOSYSTEM_FINDING, "config/dependency-policy.toml", 1, f"Node instruction escapes repository: {instruction}"))
                    else:
                        instruction_path, instruction_relative = _validated_node_input(
                            root, str(relative_instruction), "Node manifest instruction", findings
                        )
                        instruction_bytes = (
                            _read_validated_node_bytes(
                                root,
                                instruction_relative,
                                "Node manifest instruction",
                                findings,
                            )
                            if instruction_relative
                            else None
                        )
                        if instruction_path is not None and instruction_bytes is None:
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


def _extract_external_version(output: str) -> str | None:
    match = re.search(r"(?<!\d)(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)(?!\d)", output)
    return match.group(1) if match else None


def _release_version(value: object) -> tuple[int, int, int] | None:
    match = _SEMVER.fullmatch(str(value))
    return tuple(int(part) for part in match.groups()) if match else None


def _read_external_evidence_file(
    root: Path,
    raw_value: object,
    label: str,
    findings: list[Finding],
) -> tuple[Path | None, bytes | None]:
    path, relative, payload, _ = _read_validated_repo_bytes(
        root,
        raw_value,
        label,
        findings,
        RECEIPT_PROVENANCE_FINDING,
    )
    if path is None or relative is None:
        return None, None
    if not relative.startswith(".eliot/dependency-policy/surrealdb/"):
        findings.append(Finding("DEP-009", relative, 1, f"{label} must be a project-local provisioner artifact"))
        return None, None
    if payload is None:
        return path, None
    return path, payload


@contextmanager
def _verified_private_executable(payload: bytes, label: str):
    """Expose exactly the bytes already verified to an external version probe.

    The probe never reopens the evidence path.  A private, create-new copy is
    written and read back through the same no-follow identity fence before it
    is executed; the temporary directory remains private for the lifetime of
    the child process.
    """

    with tempfile.TemporaryDirectory(prefix="eliot-verified-executable-") as temporary:
        private_path = Path(temporary) / "verified.exe"
        write_fd: int | None = None
        try:
            write_fd = os.open(
                private_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o700,
            )
            view = memoryview(payload)
            while view:
                written = os.write(write_fd, view)
                if written <= 0:
                    raise OSError(f"{label} private copy made no progress")
                view = view[written:]
            os.fsync(write_fd)
        finally:
            if write_fd is not None:
                os.close(write_fd)

        if os.name != "nt":
            private_path.chmod(0o700)

        # Keep the same no-follow handle open for the complete child lifetime.
        # On Windows the handle denies delete/rename; on other platforms the
        # post-exec identity and byte checks close the remaining replacement
        # window.  The subprocess still receives the verified private path,
        # never the evidence path that was originally inspected.
        verify_fd: int | None = None
        try:
            verify_fd = _open_nofollow_read_handle(private_path)
            before = os.fstat(verify_fd)
            if getattr(before, "st_file_attributes", 0) & _REPARSE_POINT:
                raise OSError(f"{label} private copy opened as a reparse point")
            os.lseek(verify_fd, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            while chunk := os.read(verify_fd, 1024 * 1024):
                chunks.append(chunk)
            after = os.fstat(verify_fd)
            if getattr(after, "st_file_attributes", 0) & _REPARSE_POINT:
                raise OSError(f"{label} private copy became a reparse point")
            observed = b"".join(chunks)
            if _stable_file_identity(before) != _stable_file_identity(after) or observed != payload:
                raise OSError(f"{label} private copy changed before execution")
            yield private_path

            # Re-read the held handle after the child exits.  This catches a
            # replacement or in-place mutation even where the host does not
            # enforce delete sharing for the temporary file.
            after_exec = os.fstat(verify_fd)
            os.lseek(verify_fd, 0, os.SEEK_SET)
            post_chunks: list[bytes] = []
            while chunk := os.read(verify_fd, 1024 * 1024):
                post_chunks.append(chunk)
            final = os.fstat(verify_fd)
            if (
                _stable_file_identity(before) != _stable_file_identity(after_exec)
                or _stable_file_identity(after_exec) != _stable_file_identity(final)
                or b"".join(post_chunks) != payload
            ):
                raise OSError(f"{label} private copy changed during execution")
        finally:
            if verify_fd is not None:
                os.close(verify_fd)


def _run_verified_executable(payload: bytes, args: list[str], root: Path, label: str) -> subprocess.CompletedProcess:
    with _verified_private_executable(payload, label) as private_path:
        return subprocess.run(
            [str(private_path), *args],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )


_SURREAL_REPOSITORY = "https://github.com/surrealdb/surrealdb"
_SURREAL_API_REPOSITORY = "https://api.github.com/repos/surrealdb/surrealdb"
_OSV_ENDPOINT = "https://api.osv.dev/v1/query"
_PROVISIONING_RECEIPT_RELATIVE = ".eliot/dependency-policy/surrealdb/provisioning-receipt.json"


def _canonical_surreal_evidence_records(surreal: dict, candidate: dict) -> list[dict]:
    """Derive evidence subjects and URLs from the official source contract.

    Configured URL strings are checked against these derived values; they do
    not establish the source on their own.
    """

    records: list[dict] = []

    def add(subject: str, relative_path: object, url: str, expected_sha: object = None, expected_bytes: object = None) -> None:
        if isinstance(relative_path, str) and relative_path.strip():
            records.append(
                {
                    "subject": subject,
                    "relative_path": relative_path.replace("\\", "/"),
                    "url": url,
                    "expected_sha256": str(expected_sha).lower() if isinstance(expected_sha, str) else None,
                    "expected_bytes": expected_bytes if isinstance(expected_bytes, int) and not isinstance(expected_bytes, bool) else None,
                }
            )

    candidate_tag = candidate.get("source_tag") if isinstance(candidate, dict) else None
    candidate_version = candidate.get("version") if isinstance(candidate, dict) else None
    if isinstance(candidate_tag, str) and isinstance(candidate_version, str):
        add(
            f"surrealdb.release-asset.{candidate_tag}",
            candidate.get("artifact_path"),
            f"{_SURREAL_REPOSITORY}/releases/download/{candidate_tag}/surreal-{candidate_tag}.windows-amd64.exe",
            candidate.get("sha256"),
            candidate.get("artifact_size"),
        )
        add(
            f"surrealdb.source-archive.{candidate_tag}",
            candidate.get("source_archive_path"),
            f"{_SURREAL_REPOSITORY}/archive/refs/tags/{candidate_tag}.tar.gz",
            candidate.get("source_archive_sha256"),
        )
        add(
            f"surrealdb.release-metadata.{candidate_tag}",
            candidate.get("release_metadata_path"),
            f"{_SURREAL_API_REPOSITORY}/releases/tags/{candidate_tag}",
        )
        add(
            f"surrealdb.tag-ref.{candidate_tag}",
            candidate.get("source_tag_ref_path"),
            f"{_SURREAL_API_REPOSITORY}/git/ref/tags/{candidate_tag}",
        )

    vulnerable = surreal.get("distributed_binary_evidence") if isinstance(surreal, dict) else None
    if isinstance(vulnerable, dict):
        vulnerable_tag = vulnerable.get("source_tag")
        if isinstance(vulnerable_tag, str):
            add(
                f"surrealdb.source-archive.{vulnerable_tag}",
                vulnerable.get("source_archive_path"),
                f"{_SURREAL_REPOSITORY}/archive/refs/tags/{vulnerable_tag}.tar.gz",
                vulnerable.get("source_archive_sha256"),
            )
            add(
                f"surrealdb.tag-ref.{vulnerable_tag}",
                vulnerable.get("source_tag_ref_path"),
                f"{_SURREAL_API_REPOSITORY}/git/ref/tags/{vulnerable_tag}",
            )

    add("osv.query.surrealdb", surreal.get("advisory_query_path"), _OSV_ENDPOINT, surreal.get("advisory_query_sha256"))
    add("osv.response.surrealdb", surreal.get("advisory_response_path"), _OSV_ENDPOINT, surreal.get("advisory_response_digest"))
    return records


def _validate_provisioning_receipt(
    root: Path,
    surreal: dict,
    candidate: dict,
    findings: list[Finding],
) -> dict:
    """Consume the provisioner's canonical URL/path/bytes/digest binding."""

    old_tag = surreal.get("source_tag")
    old_version = surreal.get("version")
    expected_old_release_source = f"{_SURREAL_REPOSITORY}/releases/tag/{old_tag}"
    expected_old_release_asset = f"{_SURREAL_REPOSITORY}/releases/download/{old_tag}/surreal-{old_tag}.windows-amd64.exe"
    if surreal.get("release_source") != expected_old_release_source or surreal.get("release_asset") != expected_old_release_asset:
        findings.append(Finding(RECEIPT_PROVENANCE_FINDING, "config/dependency-policy.toml", 1, "installed SurrealDB release URLs are not the derived official release subject"))
    if surreal.get("advisory_source") != _OSV_ENDPOINT:
        findings.append(Finding(RECEIPT_PROVENANCE_FINDING, "config/dependency-policy.toml", 1, "SurrealDB advisory_source is not the derived official OSV subject"))
    if isinstance(candidate, dict):
        candidate_tag = candidate.get("source_tag")
        candidate_version = candidate.get("version")
        expected_candidate_source = f"{_SURREAL_REPOSITORY}/releases/tag/{candidate_tag}"
        expected_candidate_asset = f"{_SURREAL_REPOSITORY}/releases/download/{candidate_tag}/surreal-{candidate_tag}.windows-amd64.exe"
        if candidate.get("release_source") != expected_candidate_source or candidate.get("release_asset") != expected_candidate_asset:
            findings.append(Finding(RECEIPT_PROVENANCE_FINDING, "config/dependency-policy.toml", 1, "patched candidate release URLs are not the derived official release subject"))

    receipt_path, receipt_bytes = _read_external_evidence_file(
        root,
        _PROVISIONING_RECEIPT_RELATIVE,
        "SurrealDB project-local provisioning receipt",
        findings,
    )
    if receipt_path is None or receipt_bytes is None:
        findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 0, "project-local provisioning receipt is unavailable"))
        return {"status": "missing", "path": _PROVISIONING_RECEIPT_RELATIVE}

    try:
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 1, f"project-local provisioning receipt is not valid JSON: {exc}"))
        return {"status": "invalid", "path": _PROVISIONING_RECEIPT_RELATIVE}

    if not isinstance(receipt, dict) or receipt.get("schema") != "eliot.surrealdb-project-local-provisioning.v2":
        findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 1, "project-local provisioning receipt schema is not the canonical v2 binding"))
        return {"status": "invalid", "path": _PROVISIONING_RECEIPT_RELATIVE}
    if receipt.get("repository") != _SURREAL_REPOSITORY or receipt.get("shared_installation_touched") is not False:
        findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 1, "project-local provisioning receipt does not bind the official repository and no-shared-installation boundary"))

    expected_records = _canonical_surreal_evidence_records(surreal, candidate)
    actual_records = receipt.get("records")
    if not isinstance(actual_records, list):
        findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 1, "project-local provisioning receipt records must be a list"))
        return {"status": "invalid", "path": _PROVISIONING_RECEIPT_RELATIVE}

    receipt_by_subject: dict[str, list[dict]] = {}
    for record in actual_records:
        if isinstance(record, dict) and isinstance(record.get("subject"), str):
            receipt_by_subject.setdefault(record["subject"], []).append(record)

    verified: list[dict] = []
    expected_subjects = {item["subject"] for item in expected_records}
    if set(receipt_by_subject) != expected_subjects:
        findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 1, "project-local provisioning receipt subjects do not exactly cover the canonical evidence set"))

    for expected in expected_records:
        matches = receipt_by_subject.get(expected["subject"], [])
        if len(matches) != 1:
            findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 1, f"provisioning receipt must contain exactly one record for {expected['subject']}"))
            continue
        record = matches[0]
        relative = record.get("relative_path")
        if relative != expected["relative_path"] or record.get("url") != expected["url"]:
            findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 1, f"provisioning receipt record {expected['subject']} has non-canonical URL or path"))
        if record.get("path") != relative:
            findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 1, f"provisioning receipt record {expected['subject']} path must equal its repository-relative path"))
        if not isinstance(record.get("sha256"), str) or not _HEX64.fullmatch(record["sha256"]):
            findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 1, f"provisioning receipt record {expected['subject']} lacks a valid SHA-256"))
        if not isinstance(record.get("bytes"), int) or isinstance(record.get("bytes"), bool) or record["bytes"] < 0:
            findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 1, f"provisioning receipt record {expected['subject']} lacks a valid byte length"))
        expected_sha = expected.get("expected_sha256")
        if expected_sha and record.get("sha256", "").lower() != expected_sha:
            findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 1, f"provisioning receipt record {expected['subject']} does not match the locked digest"))
        expected_bytes = expected.get("expected_bytes")
        if expected_bytes is not None and record.get("bytes") != expected_bytes:
            findings.append(Finding(RECEIPT_PROVENANCE_FINDING, _PROVISIONING_RECEIPT_RELATIVE, 1, f"provisioning receipt record {expected['subject']} does not match the locked byte length"))
        if isinstance(relative, str):
            _, actual_relative, payload, _ = _read_validated_repo_bytes(
                root,
                relative,
                f"provisioned evidence {expected['subject']}",
                findings,
                RECEIPT_PROVENANCE_FINDING,
            )
            actual_sha = hashlib.sha256(payload).hexdigest() if payload is not None else None
            if actual_relative != relative or payload is None or actual_sha != str(record.get("sha256", "")).lower() or len(payload) != record.get("bytes"):
                findings.append(Finding(RECEIPT_PROVENANCE_FINDING, relative, 1, f"provisioning receipt record {expected['subject']} does not match the safely read bytes"))
            else:
                verified.append({**expected, "sha256": actual_sha, "bytes": len(payload)})

    return {
        "status": "verified" if len(verified) == len(expected_records) and not any(
            finding.code == RECEIPT_PROVENANCE_FINDING for finding in findings
        ) else "findings",
        "path": _PROVISIONING_RECEIPT_RELATIVE,
        "sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "bytes": len(receipt_bytes),
        "records": verified,
    }


def _parse_external_json(
    root: Path,
    raw_value: object,
    label: str,
    findings: list[Finding],
) -> tuple[Path | None, bytes | None, object | None]:
    path, payload = _read_external_evidence_file(root, raw_value, label, findings)
    if path is None or payload is None:
        return path, payload, None
    try:
        return path, payload, json.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        findings.append(Finding("DEP-009", str(path.relative_to(root)).replace("\\", "/"), 1, f"{label} is not valid JSON: {exc}"))
        return path, payload, None


def _validate_source_archive(
    root: Path,
    archive_path_value: object,
    archive_sha256: object,
    source_paths: object,
    label: str,
    findings: list[Finding],
) -> dict:
    path, payload = _read_external_evidence_file(root, archive_path_value, label, findings)
    if path is None or payload is None:
        return {"status": "missing", "path": archive_path_value}
    relative = str(path.relative_to(root)).replace("\\", "/")
    actual_sha = hashlib.sha256(payload).hexdigest()
    expected_sha = str(archive_sha256).lower()
    if not _HEX64.fullmatch(expected_sha) or actual_sha != expected_sha:
        findings.append(Finding("DEP-009", relative, 1, f"{label} bytes do not match the configured SHA-256"))
    if not isinstance(source_paths, list) or not source_paths or any(
        not isinstance(source_path, str) or not source_path.strip() or Path(source_path).is_absolute() or ".." in Path(source_path).parts
        for source_path in source_paths
    ):
        findings.append(Finding("DEP-009", relative, 1, f"{label} source_paths are missing or unsafe"))
        source_paths = []

    present_paths: set[str] = set()
    archive_prefix = None
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            names = {name.replace("\\", "/").lstrip("./") for name in archive.getnames()}
        prefixes = {name.split("/", 1)[0] for name in names if "/" in name}
        if len(prefixes) == 1:
            archive_prefix = next(iter(prefixes))
        if archive_prefix:
            for source_path in source_paths:
                candidate = f"{archive_prefix}/{source_path}"
                if candidate in names:
                    present_paths.add(source_path)
                else:
                    findings.append(Finding("DEP-009", relative, 1, f"{label} does not contain {source_path}"))
        else:
            findings.append(Finding("DEP-009", relative, 1, f"{label} has no single source-tree root"))
    except (OSError, tarfile.TarError) as exc:
        findings.append(Finding("DEP-009", relative, 1, f"{label} is not a readable gzip source archive: {exc}"))

    return {
        "status": "verified" if len(present_paths) == len(source_paths) and actual_sha == expected_sha else "findings",
        "path": relative,
        "sha256": actual_sha,
        "bytes": len(payload),
        "archive_root": archive_prefix,
        "source_paths": sorted(present_paths),
    }


def _validate_osv_snapshot(
    root: Path,
    surreal: dict,
    advisory_findings: list[str],
    fixes: dict,
    conditions: dict,
    advisory_paths: dict,
    source_archive: dict,
    findings: list[Finding],
) -> dict:
    query_path, query_bytes, query_data = _parse_external_json(
        root, surreal.get("advisory_query_path"), "SurrealDB OSV query evidence", findings
    )
    response_path, response_bytes, response_data = _parse_external_json(
        root, surreal.get("advisory_response_path"), "SurrealDB OSV response evidence", findings
    )
    query_sha = hashlib.sha256(query_bytes).hexdigest() if query_bytes is not None else None
    response_sha = hashlib.sha256(response_bytes).hexdigest() if response_bytes is not None else None
    if query_sha != str(surreal.get("advisory_query_sha256", "")).lower():
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "SurrealDB OSV query bytes do not match advisory_query_sha256"))
    if response_sha != str(surreal.get("advisory_response_digest", "")).lower():
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "SurrealDB OSV response bytes do not match advisory_response_digest"))
    canonical_response_sha = _canonical_digest(response_data) if response_data is not None else None
    if canonical_response_sha != str(surreal.get("advisory_digest", "")).lower():
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "SurrealDB OSV response canonical bytes do not match advisory_digest"))

    expected_query = None
    try:
        expected_query = json.loads(str(surreal.get("advisory_query", "")))
    except json.JSONDecodeError:
        pass
    if query_data != expected_query:
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "saved SurrealDB OSV query does not equal the configured query"))

    observed: dict[str, dict] = {}
    if isinstance(response_data, dict) and isinstance(response_data.get("vulns"), list):
        for vulnerability in response_data["vulns"]:
            if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str):
                findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "saved SurrealDB OSV response contains a malformed vulnerability record"))
                continue
            observed[vulnerability["id"]] = vulnerability
    if set(observed) != set(advisory_findings):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "saved SurrealDB OSV response IDs do not equal advisory_findings"))

    source_present = set(source_archive.get("source_paths", []))
    for advisory_id in sorted(advisory_findings):
        vulnerability = observed.get(advisory_id)
        if not isinstance(vulnerability, dict):
            continue
        affected = vulnerability.get("affected")
        if not isinstance(affected, list) or not any(
            isinstance(item, dict)
            and isinstance(item.get("package"), dict)
            and item["package"].get("ecosystem") == surreal.get("advisory_ecosystem")
            and item["package"].get("name") == surreal.get("advisory_package")
            for item in affected
        ):
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"saved OSV record {advisory_id} is not for the configured package/ecosystem"))
        observed_fixed: set[str] = set()
        for affected_item in affected if isinstance(affected, list) else []:
            for range_item in affected_item.get("ranges", []) if isinstance(affected_item, dict) else []:
                for event in range_item.get("events", []) if isinstance(range_item, dict) else []:
                    if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                        observed_fixed.add(event["fixed"])
        configured_fixed = fixes.get(advisory_id) if isinstance(fixes, dict) else None
        if observed_fixed != {configured_fixed}:
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"OSV fixed versions for {advisory_id} do not match the configured fix version"))
        configured_paths = advisory_paths.get(advisory_id) if isinstance(advisory_paths, dict) else None
        if not isinstance(configured_paths, list) or not set(configured_paths).issubset(source_present):
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"source archive does not contain every advisory path for {advisory_id}"))
        condition = conditions.get(advisory_id) if isinstance(conditions, dict) else None
        details = vulnerability.get("details", "")
        tokens = {token for token in re.findall(r"[a-z0-9]+", str(condition).lower()) if len(token) >= 4}
        detail_tokens = set(re.findall(r"[a-z0-9]+", str(details).lower()))
        if not isinstance(condition, str) or not condition.strip() or len(tokens & detail_tokens) < max(2, len(tokens) // 4):
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"configured advisory condition for {advisory_id} is not bound to saved OSV details"))

    return {
        "status": "verified" if not any(
            finding.path == "config/dependency-policy.toml" and "OSV" in finding.detail
            for finding in findings
        ) else "findings",
        "query_path": str(query_path.relative_to(root)).replace("\\", "/") if query_path else None,
        "query_sha256": query_sha,
        "response_path": str(response_path.relative_to(root)).replace("\\", "/") if response_path else None,
        "response_sha256": response_sha,
        "canonical_response_sha256": canonical_response_sha,
        "ids": sorted(observed),
        "fixed_versions": {key: sorted(
            {
                event["fixed"]
                for affected in observed[key].get("affected", [])
                if isinstance(affected, dict)
                for range_item in affected.get("ranges", [])
                if isinstance(range_item, dict)
                for event in range_item.get("events", [])
                if isinstance(event, dict) and isinstance(event.get("fixed"), str)
            }
        ) for key in sorted(observed)},
        "condition_binding_digest": _canonical_digest({
            key: {"condition": conditions.get(key), "fix_version": fixes.get(key), "source_paths": advisory_paths.get(key)}
            for key in sorted(advisory_findings)
        }),
    }


def _validate_surreal_binary_evidence(
    root: Path, surreal: dict, advisory_findings: list[str], findings: list[Finding]
) -> dict:
    """Consume source/advisory bytes without upgrading crate evidence to binary proof."""

    evidence = surreal.get("distributed_binary_evidence")
    if not isinstance(evidence, dict):
        findings.append(
            Finding(
                "DEP-009",
                "config/dependency-policy.toml",
                1,
                "surrealdb distributed_binary_evidence must be a source/advisory evidence table",
            )
        )
        return {}

    expected_command = (
        "cargo build --no-default-features --features default "
        "--features storage-tikv,jwks,ml --locked --target x86_64-pc-windows-msvc"
    )
    if evidence.get("status") != "source-and-advisory-verified":
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary evidence status must be source-and-advisory-verified"))
    if evidence.get("build_status") != "not_executed":
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary applicability cannot be established without an observed source build"))
    if evidence.get("source_repository") != "https://github.com/surrealdb/surrealdb":
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary evidence must name the official source repository"))
    if evidence.get("source_tag") != surreal.get("source_tag"):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary evidence source_tag must match the pinned release artifact"))
    source_commit = evidence.get("source_commit")
    if not isinstance(source_commit, str) or not _HEX40.fullmatch(source_commit):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary evidence source_commit must be a 40-character source tag commit"))
    if evidence.get("build_target") != "x86_64-pc-windows-msvc":
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary evidence build_target must be x86_64-pc-windows-msvc"))
    if evidence.get("build_command") != expected_command:
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary evidence build_command does not match the official Windows action"))

    build_features = evidence.get("build_features")
    required_features = {"default", "storage-tikv", "jwks", "ml"}
    if not isinstance(build_features, list) or any(not isinstance(feature, str) for feature in build_features):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary evidence build_features must be a string list"))
        build_features = []
    if not required_features.issubset(set(build_features)):
        missing = sorted(required_features - set(build_features))
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb binary evidence is missing official build features: {', '.join(missing)}"))

    source_paths = evidence.get("source_paths")
    if not isinstance(source_paths, list) or not source_paths or any(
        not isinstance(path, str) or not path.strip() or Path(path).is_absolute() or ".." in Path(path).parts
        for path in source_paths
    ):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary evidence source_paths must be non-empty safe upstream-relative paths"))
        source_paths = []

    source_archive = _validate_source_archive(
        root,
        evidence.get("source_archive_path"),
        evidence.get("source_archive_sha256"),
        source_paths,
        "SurrealDB vulnerable-release source archive",
        findings,
    )
    tag_path, tag_payload, tag_ref = _parse_external_json(
        root, evidence.get("source_tag_ref_path"), "SurrealDB vulnerable-release tag evidence", findings
    )
    if not isinstance(tag_ref, dict):
        tag_ref = {}
    tag_object = tag_ref.get("object") if isinstance(tag_ref.get("object"), dict) else {}
    if tag_ref.get("ref") != f"refs/tags/{evidence.get('source_tag')}":
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "saved source tag evidence does not match source_tag"))
    if tag_object.get("type") != "commit" or tag_object.get("sha") != source_commit:
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "saved source tag evidence does not bind source_commit"))

    fixes = evidence.get("advisory_fix_versions")
    conditions = evidence.get("advisory_conditions")
    advisory_paths = evidence.get("advisory_source_paths")
    advisory_features = evidence.get("advisory_features")
    if not isinstance(fixes, dict) or set(fixes) != set(advisory_findings):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary evidence advisory_fix_versions must cover exactly every recorded GHSA"))
        fixes = {}
    if not isinstance(conditions, dict) or set(conditions) != set(advisory_findings):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary evidence advisory_conditions must cover exactly every recorded GHSA"))
        conditions = {}
    if not isinstance(advisory_paths, dict) or set(advisory_paths) != set(advisory_findings):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary evidence advisory_source_paths must cover exactly every recorded GHSA"))
        advisory_paths = {}
    if not isinstance(advisory_features, dict) or set(advisory_features) != set(advisory_findings):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb binary evidence advisory_features must cover exactly every recorded GHSA"))
        advisory_features = {}

    configured_version = _release_version(surreal.get("version"))
    for advisory_id in sorted(advisory_findings):
        fixed_version = _release_version(fixes.get(advisory_id)) if isinstance(fixes, dict) else None
        if fixed_version is None or (configured_version is not None and fixed_version <= configured_version):
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb binary evidence fixed version for {advisory_id} must be newer than the pinned vulnerable artifact"))
        condition = conditions.get(advisory_id) if isinstance(conditions, dict) else None
        if not isinstance(condition, str) or not condition.strip():
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb binary evidence condition for {advisory_id} is missing"))
        paths = advisory_paths.get(advisory_id) if isinstance(advisory_paths, dict) else None
        if not isinstance(paths, list) or not paths or any(
            not isinstance(path, str) or not path.strip() or Path(path).is_absolute() or ".." in Path(path).parts
            for path in paths
        ):
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb binary evidence source path for {advisory_id} is missing or unsafe"))
        features = advisory_features.get(advisory_id) if isinstance(advisory_features, dict) else None
        if not isinstance(features, list) or not features or any(
            not isinstance(feature, str) or feature not in build_features for feature in features
        ):
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb binary evidence features for {advisory_id} are missing or outside the official build"))

    advisory_snapshot = _validate_osv_snapshot(
        root,
        surreal,
        advisory_findings,
        fixes,
        conditions,
        advisory_paths,
        source_archive,
        findings,
    )

    return {
        "status": evidence.get("status"),
        "source_repository": evidence.get("source_repository"),
        "source_tag": evidence.get("source_tag"),
        "source_commit": source_commit,
        "build_target": evidence.get("build_target"),
        "build_features": build_features,
        "build_command": evidence.get("build_command"),
        "source_paths": source_paths,
        "advisory_fix_versions": fixes,
        "advisory_conditions": conditions,
        "advisory_source_paths": advisory_paths,
        "advisory_features": advisory_features,
        "build_status": evidence.get("build_status"),
        "source_archive": source_archive,
        "source_tag_ref": {
            "status": "verified" if tag_path and tag_object.get("sha") == source_commit else "findings",
            "path": str(tag_path.relative_to(root)).replace("\\", "/") if tag_path else None,
            "sha256": hashlib.sha256(tag_payload).hexdigest() if tag_payload is not None else None,
        },
        "advisory_snapshot": advisory_snapshot,
    }


def _validate_patched_candidate(
    root: Path, surreal: dict, catalog: dict, advisory_fix_versions: dict, findings: list[Finding]
) -> dict:
    """Validate the project-local release bytes selected by the release lock."""

    candidate = surreal.get("patched_candidate")
    required = (
        "status",
        "name",
        "version",
        "architecture",
        "pe_machine",
        "sha256",
        "release_source",
        "release_asset",
        "source_tag",
        "source_commit",
        "build_target",
        "build_features",
        "build_command",
        "provisioning",
        "installation_approval",
        "artifact_path",
        "artifact_size",
        "source_archive_path",
        "source_archive_sha256",
        "source_paths",
        "source_tag_ref_path",
        "release_metadata_path",
        "advisory_query_path",
        "advisory_response_path",
    )
    if not isinstance(candidate, dict):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate must be a project-local release lock table"))
        return {}
    candidate_config_start = len(findings)
    for field in required:
        if field not in candidate:
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb patched_candidate missing '{field}'"))

    if candidate.get("status") not in {"project_local_artifact_required", "project_local_artifact_verified"}:
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate status must describe project-local artifact provisioning"))
    if candidate.get("provisioning") != "project_local_provisioner":
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate must use the project-local provisioner"))
    if candidate.get("name") != surreal.get("name"):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate name must match the external executable"))
    if candidate.get("architecture") != "windows-x64" or candidate.get("pe_machine") != "8664":
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate must pin the Windows x64 PE identity"))
    candidate_sha = str(candidate.get("sha256", "")).lower()
    if not _HEX64.fullmatch(candidate_sha):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate sha256 must be a 64-character hexadecimal digest"))
    candidate_version = _release_version(candidate.get("version"))
    current_version = _release_version(surreal.get("version"))
    if candidate_version is None or current_version is None or candidate_version <= current_version:
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate version must be newer than the installed/pinned vulnerable version"))
    if isinstance(advisory_fix_versions, dict):
        fixed_versions = [_release_version(value) for value in advisory_fix_versions.values()]
        fixed_versions = [value for value in fixed_versions if value is not None]
        if candidate_version is None or (fixed_versions and candidate_version < max(fixed_versions)):
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate version does not cover every recorded advisory fix version"))

    for field in ("release_source", "release_asset"):
        value = candidate.get(field)
        if not isinstance(value, str) or not value.startswith("https://"):
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb patched_candidate {field} must be an HTTPS URL"))
    if candidate.get("source_tag") != f"v{candidate.get('version')}":
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate source_tag must identify its release version"))
    if not isinstance(candidate.get("source_commit"), str) or not _HEX40.fullmatch(candidate.get("source_commit", "")):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate source_commit must be a 40-character source tag commit"))
    if candidate.get("build_target") != "x86_64-pc-windows-msvc":
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate build_target must be x86_64-pc-windows-msvc"))
    build_features = candidate.get("build_features")
    required_features = {"default", "storage-tikv", "jwks", "ml"}
    if not isinstance(build_features, list) or not required_features.issubset(set(build_features)):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate build_features must include default, storage-tikv, jwks and ml"))
    expected_command = (
        "cargo build --no-default-features --features default "
        "--features storage-tikv,jwks,ml --locked --target x86_64-pc-windows-msvc"
    )
    if candidate.get("build_command") != expected_command:
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched_candidate build_command does not match the official Windows action"))

    candidate_config_valid = len(findings) == candidate_config_start
    artifact_execution_valid = candidate_config_valid
    artifact_path, artifact_bytes = _read_external_evidence_file(
        root, candidate.get("artifact_path"), "SurrealDB patched candidate artifact", findings
    )
    artifact_sha = hashlib.sha256(artifact_bytes).hexdigest() if artifact_bytes is not None else None
    if artifact_bytes is None:
        artifact_execution_valid = False
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched candidate artifact has not been provisioned locally"))
    else:
        if artifact_sha != candidate_sha:
            artifact_execution_valid = False
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched candidate bytes do not match the pinned SHA-256"))
        if candidate.get("artifact_size") != len(artifact_bytes):
            artifact_execution_valid = False
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched candidate byte length does not match the release asset"))
        machine = _pe_machine(artifact_bytes)
        if machine is None:
            artifact_execution_valid = False
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched candidate is not a Windows PE artifact"))
        elif machine != 0x8664:
            artifact_execution_valid = False
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched candidate PE machine is not x86_64"))
        if artifact_execution_valid and artifact_path is not None:
            try:
                proc = _run_verified_executable(
                    artifact_bytes,
                    ["version"],
                    root,
                    "SurrealDB patched candidate artifact",
                )
                combined = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
                observed_candidate_version = _extract_external_version(combined)
                if proc.returncode != 0 or observed_candidate_version != str(candidate.get("version")):
                    artifact_execution_valid = False
                    findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb patched candidate version probe does not match the pinned release"))
            except (OSError, subprocess.TimeoutExpired) as exc:
                artifact_execution_valid = False
                findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb patched candidate version probe failed: {exc}"))

    release_path, _, release_data = _parse_external_json(
        root, candidate.get("release_metadata_path"), "SurrealDB patched candidate release metadata", findings
    )
    if not isinstance(release_data, dict) or release_data.get("tag_name") != candidate.get("source_tag"):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "saved release metadata does not bind the candidate source tag"))
    release_assets = release_data.get("assets", []) if isinstance(release_data, dict) else []
    matching_assets = [
        asset for asset in release_assets
        if isinstance(asset, dict) and asset.get("name") == Path(str(candidate.get("release_asset", ""))).name
    ]
    if not matching_assets or not any(
        asset.get("browser_download_url") == candidate.get("release_asset")
        and asset.get("size") == candidate.get("artifact_size")
        and asset.get("digest") == f"sha256:{candidate_sha}"
        for asset in matching_assets
    ):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "saved release metadata does not bind the candidate URL, size and digest"))

    tag_path, tag_payload, tag_data = _parse_external_json(
        root, candidate.get("source_tag_ref_path"), "SurrealDB patched candidate tag evidence", findings
    )
    tag_object = tag_data.get("object", {}) if isinstance(tag_data, dict) else {}
    if not isinstance(tag_object, dict) or tag_data.get("ref") != f"refs/tags/{candidate.get('source_tag')}" or tag_object.get("type") != "commit" or tag_object.get("sha") != candidate.get("source_commit"):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "saved candidate tag evidence does not bind source_commit"))

    candidate_source_archive = _validate_source_archive(
        root,
        candidate.get("source_archive_path"),
        candidate.get("source_archive_sha256"),
        candidate.get("source_paths"),
        "SurrealDB patched candidate source archive",
        findings,
    )
    if candidate.get("advisory_query_path") != surreal.get("advisory_query_path") or candidate.get("advisory_response_path") != surreal.get("advisory_response_path"):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "patched candidate advisory evidence must use the actual configured OSV snapshot"))

    catalog_candidate = catalog.get("patched_candidate") if isinstance(catalog, dict) else None
    if not isinstance(catalog_candidate, dict):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb catalog is missing the patched_candidate release lock"))
    else:
        for field in required:
            if catalog_candidate.get(field) != candidate.get(field):
                findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb catalog patched_candidate differs from configured field '{field}'"))

    return {
        "status": candidate.get("status"),
        "name": candidate.get("name"),
        "version": candidate.get("version"),
        "architecture": candidate.get("architecture"),
        "pe_machine": candidate.get("pe_machine"),
        "sha256": candidate_sha,
        "release_source": candidate.get("release_source"),
        "release_asset": candidate.get("release_asset"),
        "source_tag": candidate.get("source_tag"),
        "source_commit": candidate.get("source_commit"),
        "build_target": candidate.get("build_target"),
        "build_features": candidate.get("build_features"),
        "build_command": candidate.get("build_command"),
        "provisioning": candidate.get("provisioning"),
        "installation_approval": candidate.get("installation_approval"),
        "artifact": {
            "status": "verified" if artifact_bytes is not None and artifact_execution_valid else "findings",
            "path": str(artifact_path.relative_to(root)).replace("\\", "/") if artifact_path else None,
            "sha256": artifact_sha,
            "bytes": len(artifact_bytes) if artifact_bytes is not None else None,
        },
        "release_metadata": {
            "status": "observed" if release_path and isinstance(release_data, dict) else "missing",
            "path": str(release_path.relative_to(root)).replace("\\", "/") if release_path else None,
        },
        "tag_ref": {
            "status": "verified" if tag_path and isinstance(tag_data, dict) and tag_object.get("sha") == candidate.get("source_commit") else "findings",
            "path": str(tag_path.relative_to(root)).replace("\\", "/") if tag_path else None,
            "sha256": hashlib.sha256(tag_payload).hexdigest() if tag_payload is not None else None,
        },
        "source_archive": candidate_source_archive,
    }


def _collect_external_evidence(root: Path, manifest_data: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    evidence: dict = {}
    externals = manifest_data.get("external_executables", {})
    if not isinstance(externals, dict) or "surrealdb" not in externals:
        findings.append(
            Finding("DEP-009", "config/dependency-policy.toml", 1, "missing 'surrealdb' in [external_executables]")
        )
        return findings, evidence

    surreal = externals["surrealdb"]
    name = "surrealdb"
    if not isinstance(surreal, dict):
        finding = Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb external executable configuration must be a table")
        return [finding], {name: {"status": "invalid_configuration"}}

    required = (
        "name",
        "version",
        "license",
        "consumer",
        "trust_model",
        "removal_boundary",
        "sha256",
        "catalog",
        "observed_path",
        "version_args",
        "release_source",
        "release_asset",
        "source_tag",
        "advisory_package",
        "advisory_ecosystem",
        "advisory_scope",
        "distributed_binary_applicability",
        "distributed_binary_evidence",
        "patched_candidate",
        "advisory_source",
        "advisory_query",
        "advisory_checked_at",
        "advisory_digest",
        "advisory_response_digest",
        "advisory_query_sha256",
        "advisory_query_path",
        "advisory_response_path",
        "advisory_status",
        "advisory_findings",
    )
    for req in required:
        if req not in surreal:
            findings.append(
                Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb external executable missing '{req}'")
            )

    configured_sha = str(surreal.get("sha256", "")).lower()
    if not _HEX64.fullmatch(configured_sha):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb sha256 must be a 64-character hexadecimal digest"))

    advisory_digest = str(surreal.get("advisory_digest", "")).lower()
    if not _HEX64.fullmatch(advisory_digest):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_digest must be a 64-character hexadecimal digest"))

    advisory_response_digest = str(surreal.get("advisory_response_digest", "")).lower()
    if not _HEX64.fullmatch(advisory_response_digest):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_response_digest must be a 64-character hexadecimal digest"))

    release_source = surreal.get("release_source")
    release_asset = surreal.get("release_asset")
    source_tag = surreal.get("source_tag")
    if not isinstance(release_source, str) or not release_source.startswith("https://"):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb release_source must be an HTTPS URL"))
    if not isinstance(release_asset, str) or not release_asset.startswith("https://"):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb release_asset must be an HTTPS URL"))
    if not isinstance(source_tag, str) or not source_tag.strip() or source_tag.removeprefix("v") != str(surreal.get("version", "")):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb source_tag must identify the configured release version"))

    advisory_package = surreal.get("advisory_package")
    advisory_ecosystem = surreal.get("advisory_ecosystem")
    advisory_scope = surreal.get("advisory_scope")
    binary_applicability = surreal.get("distributed_binary_applicability")
    if advisory_package != "surrealdb" or advisory_ecosystem != "crates.io":
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory evidence must target crates.io package surrealdb"))
    if advisory_scope != "rust-crate":
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_scope must be rust-crate"))
    if binary_applicability not in {"unestablished", "established"}:
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb distributed_binary_applicability is unsupported"))
    elif binary_applicability != "established":
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb distributed binary applicability remains unestablished: no observed source build is bound to the installed 3.1.4 binary"))

    advisory_query = surreal.get("advisory_query")
    if not isinstance(advisory_query, str) or not advisory_query.strip():
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_query must be a non-empty JSON request body"))
    else:
        try:
            query_data = json.loads(advisory_query)
            expected_query = {
                "package": {"ecosystem": advisory_ecosystem, "name": advisory_package},
                "version": surreal.get("version"),
            }
            if query_data != expected_query:
                findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_query does not bind the configured package, ecosystem and version"))
        except (TypeError, json.JSONDecodeError) as exc:
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb advisory_query is not valid JSON: {exc}"))

    advisory_source = surreal.get("advisory_source")
    if not isinstance(advisory_source, str) or not advisory_source.startswith("https://"):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_source must be an HTTPS URL"))

    advisory_checked_at = surreal.get("advisory_checked_at")
    if not isinstance(advisory_checked_at, str):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_checked_at must be an RFC3339 timestamp"))
    else:
        try:
            parsed_at = datetime.fromisoformat(advisory_checked_at.replace("Z", "+00:00"))
            if parsed_at.tzinfo is None:
                raise ValueError("timestamp has no timezone")
        except ValueError as exc:
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb advisory_checked_at is invalid: {exc}"))

    advisory_findings = surreal.get("advisory_findings")
    if not isinstance(advisory_findings, list) or any(not isinstance(item, str) or not item.strip() for item in advisory_findings):
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_findings must be a list of advisory identifiers"))
        advisory_findings = []
    else:
        invalid_advisories = [item for item in advisory_findings if not _GHSA_ID.fullmatch(item)]
        if invalid_advisories:
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb advisory_findings contains invalid identifiers: {', '.join(invalid_advisories)}"))
        if len(set(advisory_findings)) != len(advisory_findings):
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_findings contains duplicate identifiers"))
    advisory_status = surreal.get("advisory_status")
    if advisory_status not in {"findings", "no_known_vulnerabilities", "unavailable"}:
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_status is unsupported"))
    elif advisory_status == "findings" and not advisory_findings:
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_status=findings requires advisory_findings"))
    elif advisory_status == "no_known_vulnerabilities" and advisory_findings:
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb advisory_status=no_known_vulnerabilities conflicts with advisory_findings"))
    if advisory_status == "findings" and advisory_findings:
        for advisory_id in sorted(advisory_findings):
            findings.append(
                Finding(
                    "DEP-009",
                    "config/dependency-policy.toml",
                    1,
                    "surrealdb Rust-crate advisory "
                    f"{advisory_id} affects {advisory_ecosystem}/{advisory_package} "
                    f"{surreal.get('version', 'unknown')}; distributed binary applicability="
                    f"{binary_applicability}",
                )
            )

    binary_evidence = _validate_surreal_binary_evidence(root, surreal, advisory_findings, findings)

    observed_path_value = surreal.get("observed_path")
    observed_path: Path | None = None
    observed_sha = None
    observed_version = None
    observed_payload: bytes | None = None
    version_probe: dict = {"status": "not_executed"}
    observed_execution_valid = _HEX64.fullmatch(configured_sha) is not None
    if not isinstance(observed_path_value, str) or not Path(observed_path_value).is_absolute():
        observed_execution_valid = False
        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb observed_path must be an absolute path"))
    else:
        observed_path = Path(observed_path_value)
        if observed_path.name.lower() != str(surreal.get("name", "")).lower():
            observed_execution_valid = False
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb observed_path filename does not match configured executable name"))
        if not observed_path.is_file() or observed_path.is_symlink():
            observed_execution_valid = False
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb observed executable is not a regular file: {observed_path}"))
        else:
            try:
                observed_payload, _ = _read_stable_file_bytes(observed_path, "observed surrealdb executable")
                observed_sha = hashlib.sha256(observed_payload).hexdigest().lower()
            except OSError as exc:
                observed_execution_valid = False
                findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"cannot hash observed surrealdb executable: {exc}"))
            if observed_sha and _HEX64.fullmatch(configured_sha) and observed_sha != configured_sha:
                observed_execution_valid = False
                findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb observed SHA-256 {observed_sha} differs from pinned {configured_sha}"))
            if observed_payload is not None and not observed_payload:
                observed_execution_valid = False
                findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb observed executable is empty"))
            if observed_payload is not None:
                machine = _pe_machine(observed_payload)
                if machine is None:
                    observed_execution_valid = False
                    findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb observed executable is not a Windows PE artifact"))
                elif machine != 0x8664:
                    observed_execution_valid = False
                    findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb observed executable PE machine is not x86_64"))

            version_args = surreal.get("version_args")
            if not isinstance(version_args, list) or any(not isinstance(arg, str) or not arg for arg in version_args):
                observed_execution_valid = False
                findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb version_args must be a non-empty string list"))
                version_args = []
            if observed_execution_valid and observed_payload is not None and version_args:
                command = [str(observed_path), *version_args]
                version_probe = {"command": command, "execution": "verified_private_copy"}
                try:
                    proc = _run_verified_executable(
                        observed_payload,
                        version_args,
                        root,
                        "observed surrealdb executable",
                    )
                    combined = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
                    observed_version = _extract_external_version(combined)
                    version_probe.update(
                        {
                            "status": "observed" if proc.returncode == 0 and observed_version else "invalid",
                            "exit_code": proc.returncode,
                            "observed_version": observed_version,
                            "output_sha256": hashlib.sha256(combined.encode("utf-8")).hexdigest(),
                        }
                    )
                    if proc.returncode != 0 or not observed_version:
                        observed_execution_valid = False
                        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb version probe did not produce a version"))
                    elif observed_version != str(surreal.get("version", "")):
                        observed_execution_valid = False
                        findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb observed version {observed_version} differs from pinned {surreal.get('version')}"))
                except (OSError, subprocess.TimeoutExpired) as exc:
                    observed_execution_valid = False
                    version_probe = {"status": "unavailable", "error": str(exc), "command": command}
                    findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"surrealdb version probe failed: {exc}"))

    catalog_path, catalog_rel, catalog_bytes, _ = _read_validated_repo_bytes(
        root,
        surreal.get("catalog"),
        "SurrealDB catalog",
        findings,
        RECEIPT_PROVENANCE_FINDING,
    )
    catalog_evidence: dict = {"status": "not_observed"}
    catalog: dict = {}
    if catalog_path is not None:
        try:
            catalog = json.loads(catalog_bytes.decode("utf-8")) if catalog_bytes is not None else {}
            catalog_sha = hashlib.sha256(catalog_bytes).hexdigest().lower() if catalog_bytes is not None else None
            catalog_evidence = {
                "status": "observed",
                "path": catalog_rel,
                "sha256": catalog_sha,
                "artifact": catalog.get("artifact"),
                "version": catalog.get("version"),
                "sha256_pin": catalog.get("sha256"),
                "architecture": catalog.get("architecture"),
                "patched_candidate": catalog.get("patched_candidate"),
            }
            if catalog.get("artifact") != str(surreal.get("name", "")):
                findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb catalog artifact does not match executable name"))
            if catalog.get("version") != surreal.get("version") or str(catalog.get("sha256", "")).lower() != configured_sha:
                findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, "surrealdb catalog identity differs from configured version/SHA-256 pin"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            catalog_evidence = {"status": "invalid", "path": catalog_rel}
            findings.append(Finding("DEP-009", "config/dependency-policy.toml", 1, f"malformed surrealdb catalog: {exc}"))

    candidate_evidence = _validate_patched_candidate(
        root,
        surreal,
        catalog,
        binary_evidence.get("advisory_fix_versions", {}),
        findings,
    )
    provisioning_receipt = _validate_provisioning_receipt(
        root,
        surreal,
        surreal.get("patched_candidate") if isinstance(surreal.get("patched_candidate"), dict) else {},
        findings,
    )

    evidence[name] = {
        "status": "findings" if findings else "observed",
        "configured": surreal,
        "pinned_artifact": {
            "version": surreal.get("version"),
            "sha256": configured_sha,
            "catalog": catalog_evidence,
            "patched_candidate": candidate_evidence,
        },
        "provisioning_receipt": provisioning_receipt,
        "observed_installed": {
            "path": str(observed_path.resolve()) if observed_path else None,
            "version": observed_version,
            "sha256": observed_sha,
            "version_probe": version_probe,
        },
        "advisory_snapshot": {
            "source": advisory_source,
            "query": surreal.get("advisory_query"),
            "package": advisory_package,
            "ecosystem": advisory_ecosystem,
            "scope": advisory_scope,
            "checked_at": advisory_checked_at,
            "digest": advisory_digest,
            "response_digest": advisory_response_digest,
            "status": advisory_status,
            "findings": sorted(advisory_findings),
            "distributed_binary_applicability": binary_applicability,
            "distributed_binary_evidence": binary_evidence,
            "release_source": release_source,
            "release_asset": release_asset,
            "source_tag": source_tag,
        },
    }
    return findings, evidence


def check_external_executables(
    root: Path | dict, manifest_data: dict | None = None
) -> list[Finding]:
    # Keep the one-argument helper form compatible with the existing focused
    # verifier tests while allowing the real run to probe from its repository root.
    if manifest_data is None:
        manifest_data = root if isinstance(root, dict) else {}
        root = Path(".")
    findings, _ = _collect_external_evidence(root, manifest_data)
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


def _scanner_input_snapshot(
    root: Path,
    rust_policy: dict | None,
    findings: list[Finding] | None = None,
) -> dict:
    policy = rust_policy if isinstance(rust_policy, dict) else {}
    snapshot: dict[str, dict] = {}
    for key, default in (
        ("manifest", "Cargo.toml"),
        ("lockfile", "Cargo.lock"),
        ("policy_file", "deny.toml"),
    ):
        raw_path = policy.get(key, default)
        if not isinstance(raw_path, str) or not raw_path.strip():
            snapshot[key] = {"status": "invalid", "path": None}
            continue
        path, relative, payload, identity = _read_validated_repo_bytes(
            root,
            raw_path,
            f"cargo-deny input {key}",
            findings,
            IDENTITY_BINDING_FINDING,
        )
        snapshot[key] = {
            "status": "verified" if payload is not None else "unavailable",
            "path": relative,
            "sha256": hashlib.sha256(payload).hexdigest() if payload is not None else None,
            "bytes": len(payload) if payload is not None else None,
            "identity": list(identity) if identity is not None else None,
        }
    return snapshot


def _scanner_advisory_binding_digest(execution: dict) -> str:
    return _canonical_digest(
        {
            "profile": execution.get("profile"),
            "checks": execution.get("checks"),
            "command": execution.get("command"),
            "input_snapshot_before_digest": execution.get("input_snapshot_before_digest"),
            "input_snapshot_after_digest": execution.get("input_snapshot_after_digest"),
            "input_snapshot_digest": execution.get("input_snapshot_digest"),
            "input_snapshot_equal": execution.get("input_snapshot_equal"),
            "advisory_content_digest": execution.get("advisory_content_digest"),
            "scanner_identity": execution.get("scanner_identity"),
            "scanner_identity_after": execution.get("scanner_identity_after"),
            "parser_status": execution.get("parser_status"),
            "parser_complete": execution.get("parser_complete"),
            "summary_consistent": execution.get("summary_consistent"),
            "parsed_records": execution.get("parsed_records"),
            "summary_records": execution.get("summary_records"),
            "scanner_exit_accepted": execution.get("scanner_exit_accepted"),
        }
    )


def _scanner_advisory_binding_is_valid(cargo_summary: dict) -> bool:
    execution = cargo_summary.get("_execution") if isinstance(cargo_summary, dict) else None
    if not isinstance(execution, dict):
        return False
    required = (
        "advisory_content_digest",
        "input_snapshot_digest",
        "input_snapshot_before_digest",
        "input_snapshot_after_digest",
        "advisory_binding_digest",
    )
    if any(not isinstance(execution.get(key), str) or not execution[key] for key in required):
        return False
    if execution.get("input_snapshot_equal") is not True:
        return False
    if execution.get("parser_status") != "complete" or execution.get("parser_complete") is not True:
        return False
    if execution.get("summary_consistent") is not True:
        return False
    if not isinstance(execution.get("parsed_records"), int) or execution["parsed_records"] <= 0:
        return False
    if not isinstance(execution.get("summary_records"), int) or execution["summary_records"] <= 0:
        return False
    if execution.get("scanner_exit_accepted") is not True:
        return False
    before = execution.get("input_snapshot_before")
    after = execution.get("input_snapshot_after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    expected_before_digest = _canonical_digest(before)
    expected_after_digest = _canonical_digest(after)
    expected_snapshot_digest = _canonical_digest(
        {
            "before": before,
            "after": after,
            "equal": before == after,
        }
    )
    if execution.get("input_snapshot_before_digest") != expected_before_digest:
        return False
    if execution.get("input_snapshot_after_digest") != expected_after_digest:
        return False
    if execution.get("input_snapshot_digest") != expected_snapshot_digest:
        return False
    if execution.get("input_snapshot_equal") is not (before == after):
        return False
    if any(
        not isinstance(snapshot, dict) or snapshot.get("status") != "verified"
        for snapshot in (*before.values(), *after.values())
    ):
        return False
    if not execution.get("identity_verified") or execution.get("scanner_identity_stable") is not True:
        return False
    return execution.get("advisory_binding_digest") == _scanner_advisory_binding_digest(execution)


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


def _node_surface_observation(
    root: Path, node_policy: dict | None, findings: list[Finding] | None = None
) -> dict:
    policy = node_policy if isinstance(node_policy, dict) else {}
    _, contract_relative = _validated_node_input(
        root, policy.get("contract"), "[ecosystems.node].contract", findings
    )
    if not contract_relative:
        return {"status": "missing", "surface": None}
    contract_bytes = _read_validated_node_bytes(root, contract_relative, "Node contract", findings)
    if contract_bytes is None:
        return {"status": "unreadable", "surface": None}
    try:
        contract = json.loads(contract_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"status": "malformed", "surface": None}
    if not isinstance(contract, dict):
        return {"status": "malformed", "surface": None}
    surface = contract.get("surface")
    return {
        "status": "observed",
        "surface": surface,
        "surface_type": type(surface).__name__,
    }


def _receipt_input_paths(
    root: Path, manifest_data: dict, findings: list[Finding] | None = None
) -> list[str]:
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
        paths.update(_node_input_paths(root, node, findings))
    externals = manifest_data.get("external_executables", {})
    if isinstance(externals, dict):
        for config in externals.values():
            if not isinstance(config, dict):
                continue
            paths.add(_PROVISIONING_RECEIPT_RELATIVE)
            catalog_path, _ = _configured_repo_path(
                root, config.get("catalog"), "external executable catalog", "DEP-009"
            )
            if catalog_path is not None:
                try:
                    paths.add(str(catalog_path.relative_to(root)).replace("\\", "/"))
                except ValueError:
                    continue
    return sorted(paths)


def _external_receipt_evidence(root: Path, manifest_data: dict) -> dict:
    _, evidence = _collect_external_evidence(root, manifest_data)
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

    expected_version = str(scanner_info.get("version", ""))
    expected_digest = str(scanner_info.get("sha256", "")).lower()
    scanner_config_errors: list[str] = []
    if scanner_info.get("tool") != "cargo-deny":
        scanner_config_errors.append("[scanner].tool must be cargo-deny")
    if executable_name not in {"cargo-deny", "cargo-deny.exe"}:
        scanner_config_errors.append("[scanner].executable must identify cargo-deny")
    if not _SEMVER.fullmatch(expected_version):
        scanner_config_errors.append("[scanner].version must be an exact semantic version")
    if not _HEX64.fullmatch(expected_digest):
        scanner_config_errors.append("[scanner].sha256 must be a 64-character hexadecimal digest")
    configured_checks = scanner_info.get("checks")
    required_checks = {"advisories", "bans", "licenses", "sources"}
    if (
        not isinstance(configured_checks, list)
        or any(not isinstance(check, str) for check in configured_checks)
        or set(configured_checks) != required_checks
    ):
        scanner_config_errors.append("[scanner].checks must contain advisories, bans, licenses and sources exactly once")

    option_args, option_evidence, config_errors = _rust_policy_options(root, rust_policy)
    execution.update(option_evidence)
    for detail in scanner_config_errors:
        findings.append(Finding(SCANNER_IDENTITY_FINDING, "config/dependency-policy.toml", 1, detail))
    for detail in config_errors:
        findings.append(Finding("DEP-002", "config/dependency-policy.toml", 1, detail))
    if findings:
        execution["status"] = STATUS_CONFLICTED
        return findings, STATUS_CONFLICTED, {"_execution": execution}

    scanner_payload: bytes | None = None
    try:
        scanner_payload, _ = _read_stable_file_bytes(Path(exec_path), "cargo-deny scanner")
        observed_digest = hashlib.sha256(scanner_payload).hexdigest().lower()
    except OSError as exc:
        findings.append(Finding("DEP-001", "deny.toml", 1, f"cannot read scanner executable '{exec_path}': {exc}"))
        execution["status"] = STATUS_TOOL_UNAVAILABLE
        return findings, STATUS_TOOL_UNAVAILABLE, {"_execution": execution}

    scanner_identity_valid = True
    if not scanner_payload:
        scanner_identity_valid = False
        findings.append(Finding(SCANNER_IDENTITY_FINDING, "config/dependency-policy.toml", 1, "cargo-deny scanner executable is empty"))
    scanner_machine = _pe_machine(scanner_payload) if scanner_payload is not None else None
    if scanner_machine is None:
        scanner_identity_valid = False
        findings.append(Finding(SCANNER_IDENTITY_FINDING, "config/dependency-policy.toml", 1, "cargo-deny scanner is not a Windows PE artifact"))
    elif scanner_machine != 0x8664:
        scanner_identity_valid = False
        findings.append(Finding(SCANNER_IDENTITY_FINDING, "config/dependency-policy.toml", 1, "cargo-deny scanner PE machine is not x86_64"))
    if observed_digest != expected_digest:
        scanner_identity_valid = False
        findings.append(
            Finding(
                SCANNER_IDENTITY_FINDING,
                "config/dependency-policy.toml",
                1,
                f"scanner executable SHA-256 mismatch: configured {expected_digest}, observed {observed_digest}",
            )
        )
    execution.update(
        {
            "executable": str(Path(exec_path).resolve()),
            "observed_sha256": observed_digest,
            "observed_size": len(scanner_payload) if scanner_payload is not None else None,
            "scanner_identity": {
                "executable": str(Path(exec_path).resolve()),
                "version": None,
                "sha256": observed_digest,
                "size": len(scanner_payload) if scanner_payload is not None else None,
                "configured_version": expected_version,
                "configured_sha256": expected_digest,
            },
            "scanner_identity_stable": False,
            "execution_transport": "verified_private_copy",
        }
    )
    if not scanner_identity_valid or scanner_payload is None:
        execution["status"] = STATUS_CONFLICTED
        return findings, STATUS_CONFLICTED, {"_execution": execution}

    try:
        version_proc = _run_verified_executable(
            scanner_payload,
            ["--version"],
            root,
            "cargo-deny scanner",
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
            "observed_version": observed_version,
            "version_probe_exit_code": version_proc.returncode,
            "scanner_identity": {
                "executable": str(Path(exec_path).resolve()),
                "version": observed_version,
                "sha256": observed_digest,
                "configured_version": scanner_info.get("version"),
                "configured_sha256": scanner_info.get("sha256"),
            },
            "scanner_identity_stable": False,
        }
    )

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

    if findings:
        execution["status"] = STATUS_CONFLICTED
        return findings, STATUS_CONFLICTED, {"_execution": execution}

    execution["identity_verified"] = True
    try:
        scanner_pre_policy_payload, _ = _read_stable_file_bytes(Path(exec_path), "cargo-deny scanner before policy execution")
        scanner_pre_policy_sha = hashlib.sha256(scanner_pre_policy_payload).hexdigest().lower()
    except OSError as exc:
        findings.append(Finding(SCANNER_IDENTITY_FINDING, "deny.toml", 1, f"cannot re-read scanner identity before policy execution: {exc}"))
        execution["status"] = STATUS_CONFLICTED
        return findings, STATUS_CONFLICTED, {"_execution": execution}
    if scanner_pre_policy_sha != observed_digest:
        findings.append(Finding(SCANNER_IDENTITY_FINDING, "deny.toml", 1, "scanner executable identity changed before cargo-deny policy execution"))
        execution["status"] = STATUS_CONFLICTED
        return findings, STATUS_CONFLICTED, {"_execution": execution}

    checks = ["bans", "licenses", "sources"]
    if profile == "current-advisories":
        checks.insert(0, "advisories")
    if profile == "offline-source":
        option_args.append("--offline")

    policy_args = ["--format", "json", "--color", "never"] + option_args + ["check"] + checks
    execution["checks"] = checks
    execution["offline"] = profile == "offline-source"
    execution["command"] = [str(Path(exec_path).resolve()), *[str(arg) for arg in policy_args]]
    snapshot_start = len(findings)
    input_snapshot_before = _scanner_input_snapshot(root, rust_policy, findings)
    execution["input_snapshot_before"] = input_snapshot_before
    execution["input_snapshot_before_digest"] = _canonical_digest(input_snapshot_before)
    if len(findings) != snapshot_start or any(
        not isinstance(snapshot, dict) or snapshot.get("status") != "verified"
        for snapshot in input_snapshot_before.values()
    ):
        execution["status"] = STATUS_CONFLICTED
        return findings, STATUS_CONFLICTED, {"_execution": execution}

    try:
        proc = _run_verified_executable(
            scanner_payload,
            policy_args,
            root,
            "cargo-deny scanner",
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
    stdout_bytes = proc.stdout or b""
    stderr_bytes = proc.stderr or b""
    stdout_text = stdout_bytes.decode("utf-8", errors="replace")
    stderr_text = stderr_bytes.decode("utf-8", errors="replace")
    execution["advisory_content_digest"] = hashlib.sha256(
        stdout_bytes + b"\n" + stderr_bytes
    ).hexdigest()
    input_snapshot_after = _scanner_input_snapshot(root, rust_policy, findings)
    execution["input_snapshot_after"] = input_snapshot_after
    execution["input_snapshot_after_digest"] = _canonical_digest(input_snapshot_after)
    execution["input_snapshot_equal"] = input_snapshot_before == input_snapshot_after
    execution["input_snapshot_digest"] = _canonical_digest(
        {
            "before": input_snapshot_before,
            "after": input_snapshot_after,
            "equal": execution["input_snapshot_equal"],
        }
    )
    try:
        scanner_after_payload, _ = _read_stable_file_bytes(Path(exec_path), "cargo-deny scanner after policy execution")
        scanner_after_sha = hashlib.sha256(scanner_after_payload).hexdigest().lower()
    except OSError as exc:
        scanner_after_sha = None
        findings.append(Finding(SCANNER_IDENTITY_FINDING, "deny.toml", 1, f"cannot re-read scanner identity after execution: {exc}"))
    execution["scanner_identity_after"] = {
        "executable": str(Path(exec_path).resolve()),
        "version": observed_version,
        "sha256": scanner_after_sha,
    }
    execution["scanner_identity_stable"] = scanner_after_sha == observed_digest
    if not execution["scanner_identity_stable"]:
        findings.append(Finding(SCANNER_IDENTITY_FINDING, "deny.toml", 1, "scanner executable identity changed during cargo-deny execution"))
    if not execution["input_snapshot_equal"]:
        findings.append(Finding(IDENTITY_BINDING_FINDING, "config/dependency-policy.toml", 1, "cargo-deny input files changed between the safe pre-run and post-run snapshots"))
    execution["advisory_binding_digest"] = _scanner_advisory_binding_digest(execution)
    summary: dict = {}
    seen_findings: set[tuple[str, str]] = set()
    stdout_result = _parse_scanner_stream(
        stdout_text, "stdout", findings, summary, seen_findings
    )
    stderr_result = _parse_scanner_stream(
        stderr_text, "stderr", findings, summary, seen_findings
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
    summary_consistent = True
    if summary_records == 0:
        summary_consistent = False
        findings.append(
            Finding(
                SCANNER_OUTPUT_FINDING,
                "deny.toml",
                1,
                f"cargo-deny emitted no valid summary record for checks {sorted(expected_checks)}",
            )
        )
    elif actual_checks != expected_checks:
        summary_consistent = False
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
        summary_consistent = False
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
        summary_consistent = False
        findings.append(
            Finding(
                SCANNER_OUTPUT_FINDING,
                "deny.toml",
                1,
                f"cargo-deny summary warning count {summary_warnings} does not match {observed_warnings} parsed warning diagnostics",
            )
        )

    # cargo-deny summary ``helps`` is check-specific metadata (the observed
    # licenses summary carries 390 of them) rather than one diagnostic with
    # severity=help; only errors and warnings have the cross-record meaning
    # that can be compared to parsed diagnostic severities here.
    parser_complete = (
        not parse_errors
        and not non_json
        and parsed_records > 0
        and summary_records > 0
        and summary_consistent
    )
    execution.update(
        {
            "summary_consistent": summary_consistent,
            "parser_complete": parser_complete,
            "parser_status": "complete" if parser_complete else "incomplete",
            "parsed_records": parsed_records,
        }
    )

    combined_output = f"{stdout_text}\n{stderr_text}".lower()
    advisory_policy_finding = any(
        f.code == "DEP-006" and re.search(r"rustsec-\d{4}-\d+", f.detail, re.IGNORECASE) for f in findings
    )
    execution["scanner_exit_accepted"] = proc.returncode == 0 or advisory_policy_finding
    execution["advisory_binding_digest"] = _scanner_advisory_binding_digest(execution)
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
    external_evidence: dict | None = None,
) -> dict:
    source_sha, source_provenance, source_finding = _git_source_provenance(root)
    if source_finding is not None:
        findings.append(source_finding)

    ecosystems = manifest_data.get("ecosystems", {})
    node_policy = ecosystems.get("node", {}) if isinstance(ecosystems, dict) else {}
    if not isinstance(node_policy, dict):
        node_policy = {}
    node_input_paths = set(_node_input_paths(root, node_policy, findings))
    input_paths = _receipt_input_paths(root, manifest_data, findings)
    digests = {}
    missing_inputs = []
    for relative_path in input_paths:
        if relative_path in node_input_paths:
            payload = _read_validated_node_bytes(root, relative_path, f"Node receipt input {relative_path}", findings)
            if payload is not None:
                digests[relative_path] = hashlib.sha256(payload).hexdigest()
            else:
                missing_inputs.append(relative_path)
        else:
            _, validated_relative, payload, _ = _read_validated_repo_bytes(
                root,
                relative_path,
                f"Receipt input {relative_path}",
                findings,
                RECEIPT_PROVENANCE_FINDING,
            )
            if validated_relative == relative_path and payload is not None:
                digests[relative_path] = hashlib.sha256(payload).hexdigest()
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
            "advisory_content_digest": scanner_execution.get("advisory_content_digest"),
            "input_snapshot_digest": scanner_execution.get("input_snapshot_digest"),
            "input_snapshot_before_digest": scanner_execution.get("input_snapshot_before_digest"),
            "input_snapshot_after_digest": scanner_execution.get("input_snapshot_after_digest"),
            "input_snapshot_equal": scanner_execution.get("input_snapshot_equal"),
            "scanner_identity": scanner_execution.get("scanner_identity"),
            "scanner_identity_after": scanner_execution.get("scanner_identity_after"),
            "scanner_identity_stable": scanner_execution.get("scanner_identity_stable"),
            "parser_status": scanner_execution.get("parser_status"),
            "parser_complete": scanner_execution.get("parser_complete"),
            "summary_consistent": scanner_execution.get("summary_consistent"),
            "parsed_records": scanner_execution.get("parsed_records"),
            "summary_records": scanner_execution.get("summary_records"),
            "scanner_exit_accepted": scanner_execution.get("scanner_exit_accepted"),
            "advisory_binding_digest": scanner_execution.get("advisory_binding_digest"),
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
            "surface_observation": _node_surface_observation(root, node_policy, findings),
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
        "external_executable_evidence": external_evidence
        if external_evidence is not None
        else _external_receipt_evidence(root, manifest_data),
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
        elif not _scanner_advisory_binding_is_valid(cargo_summary):
            advisory_status = "not_established"
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
            "digest": scanner_execution.get("advisory_content_digest"),
            "input_snapshot_digest": scanner_execution.get("input_snapshot_digest"),
            "binding_digest": scanner_execution.get("advisory_binding_digest"),
            "parser_status": scanner_execution.get("parser_status"),
            "parser_complete": scanner_execution.get("parser_complete"),
            "summary_consistent": scanner_execution.get("summary_consistent"),
            "digest_status": (
                "bound_to_observed_cargo_deny_output_and_inputs"
                if _scanner_advisory_binding_is_valid(cargo_summary)
                else "not_bound"
            ),
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

    # 7. Check external executables and retain the exact observation for the receipt.
    ext_findings, external_evidence = _collect_external_evidence(root, manifest_data)
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
    if profile == "current-advisories" and not _scanner_advisory_binding_is_valid(cargo_summary):
        all_findings.append(
            Finding(
                IDENTITY_BINDING_FINDING,
                "config/dependency-policy.toml",
                1,
                "current advisory evidence lacks a verified cargo-deny content/input snapshot binding",
            )
        )

    all_findings = _deduplicate_findings(all_findings)
    overall_status = _derive_overall_status(scanner_status, all_findings)

    receipt = build_receipt(
        root,
        profile,
        overall_status,
        all_findings,
        manifest_data,
        cargo_summary,
        direct_deps,
        external_evidence=external_evidence,
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
    findings = check_external_executables(Path("."), {})
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
