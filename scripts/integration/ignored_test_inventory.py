#!/usr/bin/env python3
"""Derive a bounded source/compiled inventory of ignored Rust tests.

Issue #905 owns the complete 28-case acceptance contract.  This module is the
real implementation entrypoint, not a reservation marker.  It performs no test
execution and provisions no Store, Runtime, Git, credential, or network state.
It builds the locked test graph, asks each produced libtest binary to list only
ignored tests, scans admitted Rust source with a small bounded lexer, reconciles
the two denominators, and writes canonical JSON to an explicit `.eliot` path.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any, Final

SCHEMA: Final = "eliot.integration.ignored-test-inventory.v1"
TOOL_VERSION: Final = "0.1.0"
OUTPUT_ROOT: Final = ".eliot"


class InventoryError(RuntimeError):
    """Stable public failure with a machine-readable reason code."""

    def __init__(self, code: str, detail: str, owner: str = "build-test-graph-owner") -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.owner = owner


@dataclasses.dataclass(frozen=True)
class Bounds:
    max_source_files: int = 20_000
    max_source_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 4 * 1024 * 1024
    max_attribute_bytes: int = 64 * 1024
    max_attributes_per_item: int = 256
    max_attribute_set_bytes: int = 256 * 1024
    max_tokens_per_file: int = 1_000_000
    max_module_depth: int = 256
    max_source_tests: int = 100_000
    max_test_binaries: int = 10_000
    max_compiled_tests: int = 100_000
    max_executable_bytes: int = 1024 * 1024 * 1024
    max_command_output_bytes: int = 256 * 1024 * 1024
    max_inventory_bytes: int = 256 * 1024 * 1024
    command_timeout_seconds: int = 3_600


BOUNDS: Final = Bounds()


class RowState(str, enum.Enum):
    CLASSIFIED = "CLASSIFIED"
    UNCLASSIFIED = "UNCLASSIFIED"
    SOURCE_ONLY = "SOURCE_ONLY"
    COMPILED_ONLY = "COMPILED_ONLY"
    DUPLICATE = "DUPLICATE"
    COMPILED_GRAPH_UNAVAILABLE = "COMPILED_GRAPH_UNAVAILABLE"


class Requirement(str, enum.Enum):
    STORE = "STORE"
    RUNTIME = "RUNTIME"
    GIT = "GIT"
    EXTERNAL_CREDENTIALED_MANUAL_ONLY = "EXTERNAL_CREDENTIALED_MANUAL_ONLY"
    UNKNOWN = "UNKNOWN"


DEFAULT_REMEDIATION_OWNERS: Final = {
    RowState.CLASSIFIED: "declared-environment-owner",
    RowState.UNCLASSIFIED: "test-declaration-owner",
    RowState.SOURCE_ONLY: "test-target-owner",
    RowState.COMPILED_ONLY: "build-test-graph-owner",
    RowState.DUPLICATE: "test-source-owner",
    RowState.COMPILED_GRAPH_UNAVAILABLE: "build-test-graph-owner",
}


@dataclasses.dataclass(frozen=True)
class Token:
    kind: str
    value: str
    start: int
    end: int
    line: int


@dataclasses.dataclass(frozen=True)
class SourceTest:
    package_id: str
    package_name: str
    target_name: str
    target_kind: str
    test_name: str
    source_path: str
    line: int
    attribute_text: str
    attribute_digest: str
    reason: str | None
    cfg_evidence: tuple[str, ...]
    requirements: tuple[str, ...]
    source_digest: str

    def identity(self) -> tuple[str, str, str, str]:
        return (self.package_id, self.target_kind, self.target_name, self.test_name)


@dataclasses.dataclass(frozen=True)
class CompiledTest:
    package_id: str
    package_name: str
    target_name: str
    target_kind: str
    executable: str
    executable_digest: str
    test_name: str

    def identity(self) -> tuple[str, str, str, str]:
        return (self.package_id, self.target_kind, self.target_name, self.test_name)


@dataclasses.dataclass(frozen=True)
class InventoryRow:
    state: str
    package_id: str
    package_name: str
    target_name: str
    target_kind: str
    test_name: str
    source_path: str | None
    source_line: int | None
    source_digest: str | None
    attribute_text: str | None
    attribute_digest: str | None
    ignore_reason: str | None
    cfg_evidence: tuple[str, ...]
    requirements: tuple[str, ...]
    executable: str | None
    executable_digest: str | None
    remediation_owner: str
    row_digest: str


@dataclasses.dataclass(frozen=True)
class PackageTarget:
    package_id: str
    package_name: str
    manifest_dir: Path
    target_name: str
    target_kind: str
    src_path: Path
    test: bool = True
    harness: bool | None = None
    required_features: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class Artifact:
    package_id: str
    target_name: str
    target_kind: str
    executable: Path


@dataclasses.dataclass(frozen=True)
class ModuleSource:
    path: Path
    module_prefix: tuple[str, ...]
    module_dir: Path


@dataclasses.dataclass(frozen=True)
class ModuleDeclaration:
    name: str
    path: str | None
    module_prefix: tuple[str, ...]
    module_dir: Path
    line: int


@dataclasses.dataclass(frozen=True)
class CommandResult:
    stdout: bytes
    stderr: bytes


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _repo_path(root: Path, path: Path) -> Path:
    try:
        resolved_root = root.resolve(strict=True)
        candidate = path if path.is_absolute() else root / path
        _reject_reparse_components(resolved_root, candidate)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise InventoryError("PATH_ESCAPE", f"path is outside repository root: {path}") from exc
    return resolved


def _reject_reparse_components(root: Path, path: Path, *, allow_missing: bool = False) -> None:
    """Reject symlinks/junctions below root before resolving a path through them."""
    try:
        absolute = Path(os.path.abspath(path))
        relative = absolute.relative_to(root)
    except ValueError as exc:
        raise InventoryError("PATH_ESCAPE", f"path is outside repository root: {path}") from exc
    current = root
    missing = False
    for part in relative.parts:
        current = current / part
        if missing:
            continue
        try:
            info = current.lstat()
        except FileNotFoundError:
            if allow_missing:
                missing = True
                continue
            raise
        except OSError as exc:
            raise InventoryError("PATH_INVALID", f"cannot inspect path component: {current}") from exc
        attributes = getattr(info, "st_file_attributes", 0)
        if stat.S_ISLNK(info.st_mode) or attributes & 0x400:
            raise InventoryError("PATH_REPARSE_POINT", f"reparse path component is not allowed: {current}")


def _relative(root: Path, path: Path) -> str:
    return _repo_path(root, path).relative_to(root.resolve(strict=True)).as_posix()


def _safe_output(root: Path, output: Path, overwrite: bool = False) -> Path:
    root = root.resolve(strict=True)
    candidate = output if output.is_absolute() else root / output
    try:
        _reject_reparse_components(root, candidate, allow_missing=True)
        resolved_candidate = candidate.resolve(strict=False)
        relative = resolved_candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise InventoryError("UNSAFE_OUTPUT", f"output parent is outside repository root: {output}") from exc
    if len(relative.parts) < 2 or relative.parts[0].casefold() != OUTPUT_ROOT:
        raise InventoryError("UNSAFE_OUTPUT", "output must be below the repository .eliot directory")
    if resolved_candidate.exists() and not overwrite:
        raise InventoryError("OUTPUT_EXISTS", f"refusing to overwrite {candidate}")
    return resolved_candidate


def _bounded_read(path: Path) -> bytes:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise InventoryError("PATH_REPARSE_POINT", f"reparse file is not allowed: {path}")
        if not stat.S_ISREG(info.st_mode):
            raise InventoryError("SOURCE_FILE_INVALID", f"input is not a regular file: {path}")
        if info.st_size > BOUNDS.max_file_bytes:
            raise InventoryError("SOURCE_FILE_TOO_LARGE", f"{path} exceeds {BOUNDS.max_file_bytes} bytes")
        with path.open("rb") as handle:
            data = handle.read(BOUNDS.max_file_bytes + 1)
    except InventoryError:
        raise
    except OSError as exc:
        raise InventoryError("SOURCE_FILE_UNREADABLE", f"cannot read bounded input: {path}: {exc}") from exc
    if len(data) > BOUNDS.max_file_bytes:
        raise InventoryError("SOURCE_FILE_TOO_LARGE", f"{path} exceeds {BOUNDS.max_file_bytes} bytes")
    return data


def _validate_command(argv: Sequence[str]) -> None:
    if not argv:
        raise InventoryError("COMMAND_NOT_ALLOWED", "empty command is not allowed")
    t = tuple(argv)
    if t in {
        ("cargo", "metadata", "--locked", "--format-version", "1"),
        ("cargo", "test", "--workspace", "--all-targets", "--locked", "--no-run", "--message-format=json"),
        ("git", "rev-parse", "HEAD"),
        ("git", "status", "--porcelain=v1", "--untracked-files=no"),
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
    }:
        return
    if len(argv) == 5 and tuple(argv[1:]) == ("--list", "--ignored", "--format", "terse"):
        if argv[0] and not argv[0].startswith("-"):
            return
    raise InventoryError("COMMAND_NOT_ALLOWED", f"command is not fixed/allowed: {argv!r}")


def _run_fixed(root: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
    _validate_command(argv)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "USERPROFILE": os.environ.get("USERPROFILE", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "WINDIR": os.environ.get("WINDIR", ""),
        "TEMP": os.environ.get("TEMP", os.environ.get("TMP", "")),
        "TMP": os.environ.get("TMP", os.environ.get("TEMP", "")),
        "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", ""),
        "CARGO_HOME": os.environ.get("CARGO_HOME", ""),
        "CARGO_TARGET_DIR": os.environ.get("CARGO_TARGET_DIR", ""),
        "CARGO_TERM_COLOR": "never",
        "RUST_BACKTRACE": "0",
    }
    env = {key: value for key, value in env.items() if value}
    try:
        completed = subprocess.run(
            list(argv),
            cwd=root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout or BOUNDS.command_timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", f"fixed command failed: {argv[0]}: {exc}") from exc
    total = len(completed.stdout) + len(completed.stderr)
    if total > BOUNDS.max_command_output_bytes:
        raise InventoryError("COMMAND_OUTPUT_TOO_LARGE", f"fixed command output exceeds {BOUNDS.max_command_output_bytes} bytes")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")[-4096:]
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", f"fixed command exited {completed.returncode}: {detail}")
    return CommandResult(completed.stdout, completed.stderr)


def _run_cmd(runner: Any, root: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
    if runner is not None:
        try:
            result = runner(root, argv, timeout=timeout)
        except TypeError:
            result = runner(root, argv)
    else:
        result = _run_fixed(root, argv, timeout=timeout)
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise InventoryError("COMMAND_RESULT_INVALID", "fixed command result must contain byte stdout and stderr")
    if len(stdout) + len(stderr) > BOUNDS.max_command_output_bytes:
        raise InventoryError("COMMAND_OUTPUT_TOO_LARGE", f"fixed command output exceeds {BOUNDS.max_command_output_bytes} bytes")
    return CommandResult(stdout, stderr)


def _locked_graph_digest(metadata: dict[str, Any]) -> str:
    packages = metadata.get("packages")
    workspace_members = metadata.get("workspace_members")
    resolve = metadata.get("resolve")
    if not isinstance(packages, list) or not isinstance(workspace_members, list) or not isinstance(resolve, dict):
        raise InventoryError("LOCKED_GRAPH_INVALID", "cargo metadata lacks a resolved locked dependency graph")
    package_ids = [item.get("id") for item in packages if isinstance(item, dict)]
    if len(package_ids) != len(packages) or any(not isinstance(item, str) or not item for item in package_ids):
        raise InventoryError("LOCKED_GRAPH_INVALID", "cargo metadata contains a package without an identity")
    if len(set(package_ids)) != len(package_ids):
        raise InventoryError("LOCKED_GRAPH_INVALID", "cargo metadata repeats a package identity")
    if any(not isinstance(item, str) or not item for item in workspace_members) or len(set(workspace_members)) != len(workspace_members):
        raise InventoryError("LOCKED_GRAPH_INVALID", "cargo metadata workspace membership is malformed")
    if not set(workspace_members).issubset(package_ids):
        raise InventoryError("LOCKED_GRAPH_INVALID", "workspace member is absent from cargo metadata packages")
    raw_nodes = resolve.get("nodes")
    if not isinstance(raw_nodes, list):
        raise InventoryError("LOCKED_GRAPH_INVALID", "cargo metadata resolved nodes are malformed")
    normalized_nodes: list[dict[str, Any]] = []
    node_ids: set[str] = set()
    for node in raw_nodes:
        if not isinstance(node, dict):
            raise InventoryError("LOCKED_GRAPH_INVALID", "cargo metadata contains a malformed resolve node")
        package_id = node.get("id")
        dependencies = node.get("dependencies")
        detailed = node.get("deps", [])
        features = node.get("features")
        if not isinstance(package_id, str) or package_id not in package_ids or package_id in node_ids:
            raise InventoryError("LOCKED_GRAPH_INVALID", "cargo metadata resolve node identity is missing or duplicated")
        if not isinstance(dependencies, list) or any(not isinstance(item, str) or item not in package_ids for item in dependencies):
            raise InventoryError("LOCKED_GRAPH_INVALID", f"cargo resolve edges are malformed for {package_id}")
        if not isinstance(features, list) or any(not isinstance(item, str) or not item for item in features) or len(set(features)) != len(features):
            raise InventoryError("LOCKED_GRAPH_INVALID", f"cargo resolved features are malformed for {package_id}")
        if not isinstance(detailed, list):
            raise InventoryError("LOCKED_GRAPH_INVALID", f"cargo detailed dependencies are malformed for {package_id}")
        normalized_details: list[dict[str, Any]] = []
        for edge in detailed:
            if not isinstance(edge, dict) or not isinstance(edge.get("pkg"), str) or edge["pkg"] not in package_ids:
                raise InventoryError("LOCKED_GRAPH_INVALID", f"cargo detailed dependency identity is malformed for {package_id}")
            if not isinstance(edge.get("name"), str) or not isinstance(edge.get("dep_kinds", []), list):
                raise InventoryError("LOCKED_GRAPH_INVALID", f"cargo detailed dependency metadata is malformed for {package_id}")
            if any(
                not isinstance(kind, dict)
                or kind.get("kind") not in {None, "normal", "dev", "build"}
                or (kind.get("target") is not None and not isinstance(kind.get("target"), str))
                for kind in edge.get("dep_kinds", [])
            ):
                raise InventoryError("LOCKED_GRAPH_INVALID", f"cargo dependency kind metadata is malformed for {package_id}")
            normalized_details.append(edge)
        node_ids.add(package_id)
        normalized_nodes.append(
            {
                "id": package_id,
                "features": sorted(features),
                "dependencies": sorted(dependencies),
                "deps": sorted(normalized_details, key=_canonical_bytes),
            }
        )
    if not set(workspace_members).issubset(node_ids):
        raise InventoryError("LOCKED_GRAPH_INVALID", "resolved graph does not cover every workspace member")
    graph = {
        "package_ids": sorted(package_ids),
        "workspace_members": sorted(workspace_members),
        "nodes": sorted(normalized_nodes, key=lambda item: item["id"]),
    }
    return _sha256(_canonical_bytes(graph))


def _cargo_metadata(root: Path, runner: Any = None) -> dict[str, Any]:
    result = _run_cmd(runner, root, ("cargo", "metadata", "--locked", "--format-version", "1"))
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata returned malformed JSON") from exc
    if not isinstance(value, dict) or not isinstance(value.get("packages"), list):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata shape is invalid")
    value["_eliot_locked_graph_sha256"] = _locked_graph_digest(value)
    value["_eliot_resolved_features"] = {
        node["id"]: sorted(node.get("features", []))
        for node in value["resolve"]["nodes"]
    }
    return value


def _targets(root: Path, metadata: dict[str, Any]) -> list[PackageTarget]:
    workspace_values = metadata.get("workspace_members")
    if not isinstance(workspace_values, list) or any(not isinstance(item, str) for item in workspace_values):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo workspace membership is invalid")
    workspace = set(workspace_values)
    resolved_features = metadata.get("_eliot_resolved_features")
    if not isinstance(resolved_features, dict):
        raise InventoryError("LOCKED_GRAPH_INVALID", "cargo resolved feature identities are unavailable")
    result: list[PackageTarget] = []
    for package in metadata["packages"]:
        if not isinstance(package, dict):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo package metadata entry is malformed")
        package_id = package.get("id")
        if package_id not in workspace:
            continue
        name = package.get("name")
        manifest = package.get("manifest_path")
        targets = package.get("targets")
        if not isinstance(package_id, str) or not isinstance(name, str) or not isinstance(manifest, str) or not isinstance(targets, list):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo package metadata is incomplete")
        manifest_path = _repo_path(root, Path(manifest))
        active_features_raw = resolved_features.get(package_id)
        if not isinstance(active_features_raw, list) or any(not isinstance(item, str) for item in active_features_raw):
            raise InventoryError("LOCKED_GRAPH_INVALID", f"resolved workspace features are absent for {package_id}")
        active_features = set(active_features_raw)
        for target in targets:
            if not isinstance(target, dict):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target metadata entry is malformed")
            kinds = target.get("kind")
            src_path = target.get("src_path")
            target_name = target.get("name")
            is_test = target.get("test")
            harness = target.get("harness")
            required_features = target.get("required-features")
            if (
                not isinstance(kinds, list)
                or not kinds
                or any(not isinstance(kind, str) or not kind for kind in kinds)
                or len(set(kinds)) != len(kinds)
                or not isinstance(src_path, str)
                or not isinstance(target_name, str)
                or not target_name
                or not isinstance(is_test, bool)
                or (harness is not None and not isinstance(harness, bool))
                or not isinstance(required_features, list)
                or any(not isinstance(feature, str) or not feature for feature in required_features)
                or len(set(required_features)) != len(required_features)
            ):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target metadata is incomplete")
            if not is_test or not set(required_features).issubset(active_features):
                continue
            target_kind = "+".join(sorted(kinds))
            result.append(
                PackageTarget(
                    package_id=package_id,
                    package_name=name,
                    manifest_dir=manifest_path.parent,
                    target_name=target_name,
                    target_kind=target_kind,
                    src_path=_repo_path(root, Path(src_path)),
                    test=is_test,
                    harness=harness,
                    required_features=tuple(sorted(required_features)),
                )
            )
    keys = [(item.package_id, item.target_kind, item.target_name) for item in result]
    if len(keys) != len(set(keys)):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata repeats a test target identity")
    return sorted(result, key=lambda item: (item.package_id, item.target_kind, item.target_name))


def _lex_rust(text: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    line = 1
    length = len(text)

    def advance(segment: str) -> None:
        nonlocal line
        line += segment.count("\n")

    while index < length:
        if len(tokens) >= BOUNDS.max_tokens_per_file:
            raise InventoryError("SOURCE_TOKEN_LIMIT", "Rust source exceeds configured token bound")
        char = text[index]
        if char.isspace():
            end = index + 1
            while end < length and text[end].isspace():
                end += 1
            advance(text[index:end])
            index = end
            continue
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                break
            advance(text[index : end + 1])
            index = end + 1
            continue
        if text.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < length and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise InventoryError("MALFORMED_SOURCE", "unterminated block comment")
            advance(text[index:end])
            index = end
            continue
        if char == '"' or (char in {"b", "c"} and index + 1 < length and text[index + 1] == '"'):
            start = index
            if char in {"b", "c"}:
                index += 1
            quote = index
            index += 1
            escaped = False
            while index < length:
                current = text[index]
                if current == "\n" and not escaped:
                    raise InventoryError("MALFORMED_SOURCE", "newline in cooked string literal")
                index += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    break
            else:
                raise InventoryError("MALFORMED_SOURCE", "unterminated string or character literal")
            raw = text[start:index]
            tokens.append(Token("string", raw, start, index, line))
            advance(raw)
            continue
        if char == "'" or (char == "b" and index + 1 < length and text[index + 1] == "'"):
            start = index
            quote = index + 1 if char == "b" else index
            cursor = quote + 1
            if cursor < length and text[cursor] == "\\":
                cursor += 1
                if cursor < length and text[cursor] == "x":
                    cursor += 3
                elif cursor < length and text[cursor] == "u" and cursor + 1 < length and text[cursor + 1] == "{":
                    end = text.find("}", cursor + 2)
                    cursor = end + 1 if end >= 0 else length
                else:
                    cursor += 1
            elif cursor < length and text[cursor] not in {"'", "\n", "\\"}:
                cursor += 1
            found_end = cursor < length and text[cursor] == "'"
            if found_end:
                cursor += 1
                raw = text[start:cursor]
                tokens.append(Token("string", raw, start, cursor, line))
                index = cursor
                advance(raw)
            else:
                # A quote without a same-line terminator begins a Rust lifetime,
                # not a character literal. Keep it as punctuation for the parser.
                tokens.append(Token("punct", "'", index, index + 1, line))
                index += 1
            continue
        raw_match = re.match(r'(?:b|c)?r(#{0,255})"', text[index:])
        if raw_match:
            start = index
            hashes = raw_match.group(1)
            index += raw_match.end()
            terminator = '"' + hashes
            end = text.find(terminator, index)
            if end < 0:
                raise InventoryError("MALFORMED_SOURCE", "unterminated raw string literal")
            index = end + len(terminator)
            raw = text[start:index]
            tokens.append(Token("string", raw, start, index, line))
            advance(raw)
            continue
        if char == "r" and index + 2 < length and text[index + 1] == "#" and (text[index + 2].isalpha() or text[index + 2] == "_"):
            start = index
            end = index + 3
            while end < length and (text[end].isalnum() or text[end] == "_"):
                end += 1
            tokens.append(Token("ident", text[index + 2 : end], start, end, line))
            index = end
            continue
        if char.isalpha() or char == "_":
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] == "_"):
                end += 1
            tokens.append(Token("ident", text[index:end], index, end, line))
            index = end
            continue
        if char.isdigit():
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] in r"_\."):
                end += 1
            tokens.append(Token("number", text[index:end], index, end, line))
            index = end
            continue
        if text.startswith("::", index) or text.startswith("->", index) or text.startswith("=>", index):
            tokens.append(Token("punct", text[index : index + 2], index, index + 2, line))
            index += 2
            continue
        tokens.append(Token("punct", char, index, index + 1, line))
        index += 1
        if len(tokens) > BOUNDS.max_tokens_per_file:
            raise InventoryError("SOURCE_TOKEN_LIMIT", "Rust source exceeds configured token bound")
    if len(tokens) > BOUNDS.max_tokens_per_file:
        raise InventoryError("SOURCE_TOKEN_LIMIT", "Rust source exceeds configured token bound")
    return tokens


def _matching_group(tokens: Sequence[Token], start: int) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    first = tokens[start].value
    if first not in pairs:
        raise InventoryError("MALFORMED_SOURCE", "expected a Rust token-group opener")
    stack = [pairs[first]]
    for index in range(start + 1, len(tokens)):
        value = tokens[index].value
        if value in pairs:
            stack.append(pairs[value])
        elif value in {")", "]", "}"}:
            if not stack or value != stack[-1]:
                raise InventoryError("MALFORMED_SOURCE", "mismatched Rust token-group delimiter")
            stack.pop()
            if not stack:
                return index
    raise InventoryError("MALFORMED_SOURCE", "unterminated Rust token group")


def _split_top_level(tokens: Sequence[Token]) -> list[Sequence[Token]]:
    result: list[Sequence[Token]] = []
    start = 0
    index = 0
    while index < len(tokens):
        if tokens[index].value in {"(", "[", "{"}:
            index = _matching_group(tokens, index) + 1
            continue
        if tokens[index].value == ",":
            result.append(tokens[start:index])
            start = index + 1
        index += 1
    result.append(tokens[start:])
    return result


def _parse_meta(tokens: Sequence[Token]) -> tuple[str, Sequence[Token], Sequence[Token] | None] | None:
    if not tokens or tokens[0].kind != "ident":
        return None
    pieces = [tokens[0].value]
    index = 1
    while index + 1 < len(tokens) and tokens[index].value == "::" and tokens[index + 1].kind == "ident":
        pieces.append(tokens[index + 1].value)
        index += 2
    path = "::".join(pieces)
    if index == len(tokens):
        return path, (), None
    if tokens[index].value == "=":
        return path, tokens[index + 1 :], None
    if tokens[index].value == "(" and _matching_group(tokens, index) == len(tokens) - 1:
        return path, (), tokens[index + 1 : -1]
    return path, tokens[index:], None


def _rust_string_value(token: Token) -> str | None:
    raw = token.value
    raw_match = re.fullmatch(r"(?:b|c)?r(#{0,255})\"(.*)\"\1", raw, re.DOTALL)
    if raw_match:
        return raw_match.group(2)
    cooked = re.fullmatch(r'(?:b|c)?"((?:\\.|[^"\\])*)"', raw, re.DOTALL)
    if cooked is None:
        return None
    body = cooked.group(1)
    output: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        index += 1
        if char != "\\":
            output.append(char)
            continue
        if index >= len(body):
            return None
        escape = body[index]
        index += 1
        simple = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", '"': '"', "'": "'"}
        if escape in simple:
            output.append(simple[escape])
        elif escape == "x" and index + 2 <= len(body):
            digits = body[index : index + 2]
            if not re.fullmatch(r"[0-9a-fA-F]{2}", digits):
                return None
            value = int(digits, 16)
            if value > 0x7F:
                return None
            output.append(chr(value))
            index += 2
        elif escape == "u" and index < len(body) and body[index] == "{":
            end = body.find("}", index + 1)
            if end < 0:
                return None
            digits = body[index + 1 : end].replace("_", "").strip()
            try:
                value = int(digits, 16)
                output.append(chr(value))
            except (ValueError, OverflowError):
                return None
            index = end + 1
        elif escape == "\n":
            while index < len(body) and body[index].isspace():
                index += 1
        else:
            return None
    return "".join(output)


def _meta_reason(meta: tuple[str, Sequence[Token], Sequence[Token] | None]) -> str | None:
    _, value, arguments = meta
    if len(value) == 1 and value[0].kind == "string":
        decoded = _rust_string_value(value[0])
        return decoded.strip()[:1024] if decoded and decoded.strip() else None
    if arguments is not None:
        for item in _split_top_level(arguments):
            child = _parse_meta(item)
            if child and child[0] in {"reason", "note"} and len(child[1]) == 1 and child[1][0].kind == "string":
                decoded = _rust_string_value(child[1][0])
                if decoded and decoded.strip():
                    return decoded.strip()[:1024]
    return None


def _attribute_effects(raw: str) -> tuple[bool, bool, bool, str | None, bool]:
    tokens = _lex_rust(raw)
    if len(tokens) < 3 or tokens[0].value != "#":
        return False, False, False, None, False
    index = 1
    inner = index < len(tokens) and tokens[index].value == "!"
    if inner:
        index += 1
    if index >= len(tokens) or tokens[index].value != "[":
        return False, False, False, None, False
    close = _matching_group(tokens, index)
    if close != len(tokens) - 1:
        raise InventoryError("MALFORMED_ATTRIBUTE", "attribute contains trailing tokens")
    root = _parse_meta(tokens[index + 1 : close])
    if root is None:
        return False, False, False, None, False
    is_test = False
    is_ignored = False
    conditional_ignore = False
    has_cfg = False
    reason: str | None = None
    depth = 0

    def visit(meta: tuple[str, Sequence[Token], Sequence[Token] | None], conditional: bool) -> None:
        nonlocal is_test, is_ignored, conditional_ignore, has_cfg, reason, depth
        depth += 1
        if depth > BOUNDS.max_module_depth:
            raise InventoryError("ATTRIBUTE_NESTING_LIMIT", "attribute nesting exceeds configured bound")
        path, _, arguments = meta
        if path == "cfg":
            has_cfg = True
        if path == "cfg_attr":
            has_cfg = True
            if arguments is not None:
                children = _split_top_level(arguments)
                for child_tokens in children[1:]:
                    child = _parse_meta(child_tokens)
                    if child is not None:
                        visit(child, True)
        elif path in {"test", "tokio::test", "async_std::test"}:
            is_test = True
        elif path in {"ignore", "disabled_test", "eliot_disabled_test", "test_disabled"}:
            is_ignored = True
            if path != "ignore":
                is_test = True
            conditional_ignore = conditional_ignore or conditional or path != "ignore"
            if reason is None:
                reason = _meta_reason(meta)
        depth -= 1

    if not inner:
        visit(root, False)
    return is_test, is_ignored, conditional_ignore, reason, has_cfg


def _decode_reason(raw: str) -> str | None:
    return _attribute_effects(raw)[3]


def _attribute_flags(raw: str) -> tuple[bool, bool, bool, str | None, str | None]:
    tokens = _lex_rust(raw)
    is_test = False
    is_ignored = False
    conditional = False
    reason: str | None = None
    has_cfg = False
    index = 0
    count = 0
    while index < len(tokens):
        if tokens[index].value != "#":
            raise InventoryError("MALFORMED_ATTRIBUTE", "unexpected tokens between Rust attributes")
        attr_start = tokens[index].start
        attr_index = index + 1 + int(index + 1 < len(tokens) and tokens[index + 1].value == "!")
        if attr_index >= len(tokens) or tokens[attr_index].value != "[":
            raise InventoryError("MALFORMED_ATTRIBUTE", "attribute opener is malformed")
        close = _matching_group(tokens, attr_index)
        attr_end = tokens[close].end
        one_test, one_ignored, one_conditional, one_reason, one_cfg = _attribute_effects(raw[attr_start:attr_end])
        is_test = is_test or one_test
        is_ignored = is_ignored or one_ignored
        conditional = conditional or one_conditional
        has_cfg = has_cfg or one_cfg
        if reason is None:
            reason = one_reason
        index = close + 1
        count += 1
    return is_test, is_ignored, conditional, reason, raw if has_cfg and count else None


def _file_module_prefix(target: PackageTarget, path: Path) -> tuple[str, ...]:
    path = path.resolve(strict=True)
    src = target.src_path.resolve(strict=True)
    if path == src:
        return ()
    try:
        relative = path.relative_to(src.parent)
    except ValueError:
        return ()
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "mod":
        parts.pop()
    return tuple(part for part in parts if part not in {"lib", "main"})


def _attribute_tokens(raw: str) -> Sequence[Token] | None:
    tokens = _lex_rust(raw)
    if len(tokens) < 3 or tokens[0].value != "#":
        return None
    index = 1 + int(tokens[1].value == "!")
    if index >= len(tokens) or tokens[index].value != "[":
        return None
    close = _matching_group(tokens, index)
    if close != len(tokens) - 1:
        raise InventoryError("MALFORMED_ATTRIBUTE", "attribute contains trailing tokens")
    return tokens[index + 1 : close]


def _module_path_attribute(attributes: Sequence[str]) -> str | None:
    values: list[str] = []
    for raw in attributes:
        contents = _attribute_tokens(raw)
        if contents is None:
            continue
        meta = _parse_meta(contents)
        if meta is not None and meta[0] == "path":
            if meta[2] is not None or len(meta[1]) != 1 or meta[1][0].kind != "string":
                raise InventoryError("MODULE_PATH_INVALID", "path attribute must contain one string literal")
            value = _rust_string_value(meta[1][0])
            if value is None or not value or "\0" in value:
                raise InventoryError("MODULE_PATH_INVALID", "path attribute string is invalid")
            values.append(value)
        elif meta is not None and meta[0] == "cfg_attr" and meta[2] is not None:
            for child_tokens in _split_top_level(meta[2])[1:]:
                child = _parse_meta(child_tokens)
                if child is not None and child[0] == "path":
                    raise InventoryError("CONDITIONAL_MODULE_PATH_UNSUPPORTED", "conditional path attributes cannot be resolved as one source graph")
    if len(values) > 1:
        raise InventoryError("MODULE_PATH_INVALID", "module declares more than one path attribute")
    return values[0] if values else None


def _consume_item_end(tokens: Sequence[Token], start: int) -> int:
    index = start
    angle_depth = 0
    while index < len(tokens):
        value = tokens[index].value
        if value in {"(", "[", "{"}:
            end = _matching_group(tokens, index)
            if value == "{" and angle_depth == 0:
                return end + 1
            index = end + 1
            continue
        if value == "<":
            angle_depth += 1
        elif value == ">" and angle_depth:
            angle_depth -= 1
        elif value == ";" and angle_depth == 0:
            return index + 1
        index += 1
    raise InventoryError("MALFORMED_SOURCE", "Rust item has no terminating body or semicolon")


def _item_modifiers(tokens: Sequence[Token], index: int) -> int:
    while index < len(tokens):
        token = tokens[index]
        if token.value == "pub":
            index += 1
            if index < len(tokens) and tokens[index].value == "(":
                index = _matching_group(tokens, index) + 1
        elif token.value in {"async", "unsafe", "const", "default"}:
            index += 1
        elif token.value == "extern":
            index += 1
            if index < len(tokens) and tokens[index].kind == "string":
                index += 1
        else:
            break
    return index


def _scan_scope(
    root: Path,
    target: PackageTarget,
    path: Path,
    text: str,
    tokens: Sequence[Token],
    module_prefix: tuple[str, ...],
    module_dir: Path,
    depth: int = 0,
) -> tuple[list[SourceTest], list[ModuleDeclaration]]:
    if depth > BOUNDS.max_module_depth:
        raise InventoryError("MODULE_DEPTH_LIMIT", "Rust inline module nesting exceeds configured bound")
    results: list[SourceTest] = []
    declarations: list[ModuleDeclaration] = []
    index = 0
    while index < len(tokens):
        attributes: list[str] = []
        while index + 1 < len(tokens) and tokens[index].value == "#":
            attr_start = index
            attr_index = index + 1
            inner = tokens[attr_index].value == "!"
            if inner:
                attr_index += 1
            if attr_index >= len(tokens) or tokens[attr_index].value != "[":
                break
            close = _matching_group(tokens, attr_index)
            if tokens[close].end - tokens[attr_start].start > BOUNDS.max_attribute_bytes:
                raise InventoryError("ATTRIBUTE_TOO_LARGE", f"attribute exceeds bound in {path}")
            if not inner:
                attributes.append(text[tokens[attr_start].start : tokens[close].end])
                if len(attributes) > BOUNDS.max_attributes_per_item:
                    raise InventoryError("ATTRIBUTE_COUNT_LIMIT", f"too many attributes on one Rust item in {path}")
                if sum(len(item.encode("utf-8")) for item in attributes) > BOUNDS.max_attribute_set_bytes:
                    raise InventoryError("ATTRIBUTE_SET_TOO_LARGE", f"attribute set exceeds bound in {path}")
            index = close + 1
        item_index = _item_modifiers(tokens, index)
        if item_index >= len(tokens):
            break
        token = tokens[item_index]
        if token.value == "mod" and item_index + 1 < len(tokens) and tokens[item_index + 1].kind == "ident":
            name_token = tokens[item_index + 1]
            after_name = item_index + 2
            path_attr = _module_path_attribute(attributes)
            if after_name < len(tokens) and tokens[after_name].value == ";":
                declarations.append(
                    ModuleDeclaration(
                        name=name_token.value,
                        path=path_attr,
                        module_prefix=module_prefix + (name_token.value,),
                        module_dir=module_dir,
                        line=name_token.line,
                    )
                )
                index = after_name + 1
            elif after_name < len(tokens) and tokens[after_name].value == "{":
                if path_attr is not None:
                    raise InventoryError("MODULE_PATH_INVALID", "path attribute cannot be combined with an inline module body")
                close = _matching_group(tokens, after_name)
                nested_tests, nested_declarations = _scan_scope(
                    root,
                    target,
                    path,
                    text,
                    tokens[after_name + 1 : close],
                    module_prefix + (name_token.value,),
                    module_dir / name_token.value,
                    depth + 1,
                )
                results.extend(nested_tests)
                declarations.extend(nested_declarations)
                index = close + 1
            else:
                raise InventoryError("MALFORMED_SOURCE", f"module declaration is malformed in {path}")
            continue
        if token.value == "fn" and item_index + 1 < len(tokens) and tokens[item_index + 1].kind == "ident":
            name_token = tokens[item_index + 1]
            flags = [_attribute_flags(raw) for raw in attributes]
            is_test = any(item[0] for item in flags)
            is_ignored = any(item[1] for item in flags)
            if is_test and is_ignored:
                test_name = "::".join((*module_prefix, name_token.value)) if module_prefix else name_token.value
                reason = next((item[3] for item in flags if item[3]), None)
                cfg = tuple(item[4] for item in flags if item[4])
                attribute_text = "\n".join(attributes)
                requirements = _requirements(attribute_text + "\n" + (reason or ""))
                relative = _relative(root, path)
                source_identity = {
                    "path": relative,
                    "line": name_token.line,
                    "test_name": test_name,
                    "attributes": attribute_text,
                }
                results.append(
                    SourceTest(
                        package_id=target.package_id,
                        package_name=target.package_name,
                        target_name=target.target_name,
                        target_kind=target.target_kind,
                        test_name=test_name,
                        source_path=relative,
                        line=name_token.line,
                        attribute_text=attribute_text,
                        attribute_digest=_sha256(attribute_text.encode("utf-8")),
                        reason=reason,
                        cfg_evidence=cfg,
                        requirements=requirements,
                        source_digest=_sha256(_canonical_bytes(source_identity)),
                    )
                )
            index = _consume_item_end(tokens, item_index + 2)
            continue
        index = _consume_item_end(tokens, item_index)
    return results, declarations


def _scan_file(
    root: Path,
    target: PackageTarget,
    path: Path,
    module_prefix: tuple[str, ...] | None = None,
    module_dir: Path | None = None,
) -> list[SourceTest]:
    data = _bounded_read(path)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InventoryError("INVALID_SOURCE_ENCODING", f"Rust source is not UTF-8: {path}") from exc
    tokens = _lex_rust(text)
    prefix = module_prefix if module_prefix is not None else _file_module_prefix(target, path)
    found, _ = _scan_scope(root, target, path, text, tokens, prefix, module_dir or path.parent)
    return found


def _resolve_module_source(root: Path, declaration: ModuleDeclaration) -> ModuleSource:
    if declaration.path is None:
        candidates = (declaration.module_dir / f"{declaration.name}.rs", declaration.module_dir / declaration.name / "mod.rs")
        existing: list[Path] = []
        for candidate in candidates:
            try:
                _reject_reparse_components(root.resolve(strict=True), candidate)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise InventoryError("MODULE_SOURCE_INVALID", f"cannot inspect declared module source: {candidate}") from exc
            if candidate.is_file():
                existing.append(candidate)
        if len(existing) != 1:
            code = "MODULE_SOURCE_MISSING" if not existing else "MODULE_SOURCE_AMBIGUOUS"
            raise InventoryError(code, f"module {declaration.name} must resolve to exactly one Rust source file")
        candidate = existing[0]
    else:
        authored = Path(declaration.path)
        if authored.is_absolute() or authored.drive or "\0" in declaration.path:
            raise InventoryError("MODULE_PATH_ESCAPE", f"module path must be repository-relative: {declaration.path}")
        candidate = declaration.module_dir / authored
    resolved = _repo_path(root, candidate)
    if resolved.suffix.casefold() != ".rs" or not resolved.is_file():
        raise InventoryError("MODULE_SOURCE_INVALID", f"declared module is not a Rust source file: {resolved}")
    child_dir = declaration.module_dir / declaration.name if declaration.path is None else resolved.parent / declaration.name
    return ModuleSource(resolved, declaration.module_prefix, child_dir)


def _reachable_source_graph(root: Path, target: PackageTarget) -> tuple[list[SourceTest], list[tuple[ModuleSource, str, int]]]:
    root_file = _repo_path(root, target.src_path)
    active: set[Path] = set()
    visited: list[tuple[ModuleSource, str, int]] = []
    tests: list[SourceTest] = []

    def visit(current: ModuleSource, depth: int) -> None:
        if depth > BOUNDS.max_module_depth:
            raise InventoryError("MODULE_DEPTH_LIMIT", "Rust external module nesting exceeds configured bound")
        if current.path in active:
            raise InventoryError("MODULE_CYCLE", f"Rust module path cycles through {current.path}")
        active.add(current.path)
        data = _bounded_read(current.path)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError("INVALID_SOURCE_ENCODING", f"Rust source is not UTF-8: {current.path}") from exc
        tokens = _lex_rust(text)
        source_tests, declarations = _scan_scope(root, target, current.path, text, tokens, current.module_prefix, current.module_dir)
        tests.extend(source_tests)
        visited.append((current, _sha256(data), len(data)))
        if len(visited) > BOUNDS.max_source_files:
            raise InventoryError("SOURCE_FILE_LIMIT", "reachable Rust module graph exceeds configured file bound")
        for declaration in reversed(declarations):
            child = _resolve_module_source(root, declaration)
            visit(child, depth + 1)
        active.remove(current.path)
    visit(ModuleSource(root_file, (), root_file.parent), 0)
    return tests, visited


def _candidate_source_files(root: Path, target: PackageTarget) -> list[Path]:
    _, visits = _reachable_source_graph(root, target)
    return sorted(item[0].path for item in visits)


def _requirements(text: str) -> tuple[str, ...]:
    words = tuple(re.findall(r"[a-z0-9]+", text.casefold()))

    def contains(phrase: str) -> bool:
        wanted = tuple(phrase.split())
        width = len(wanted)
        return any(words[index : index + width] == wanted for index in range(len(words) - width + 1))

    vocabulary = {
        Requirement.STORE: (
            "surreal", "surrealdb", "store", "database", "schema migration", "authenticated db",
        ),
        Requirement.RUNTIME: (
            "kernel", "governor", "host", "watchdog", "agent bridge", "named pipe", "windows pipe",
            "pipe", "acl", "session", "installation", "configuration", "config",
            "eliot governor config", "windows runtime",
        ),
        Requirement.GIT: ("git", "repository", "worktree", "commit identity"),
        Requirement.EXTERNAL_CREDENTIALED_MANUAL_ONLY: (
            "personal credential", "external credential", "credential", "paid", "api key", "oauth",
            "manual only",
        ),
    }
    result = {kind for kind, phrases in vocabulary.items() if any(contains(phrase) for phrase in phrases)}
    if not result:
        result.add(Requirement.UNKNOWN)
    return tuple(sorted(item.value for item in result))


def discover_source(root: Path, targets: Sequence[PackageTarget], evidence: dict[str, Any] | None = None) -> list[SourceTest]:
    result: list[SourceTest] = []
    total_bytes = 0
    source_inputs: list[dict[str, Any]] = []
    for target in targets:
        source_tests, visits = _reachable_source_graph(root, target)
        result.extend(source_tests)
        for module, digest, size in visits:
            total_bytes += size
            if total_bytes > BOUNDS.max_source_bytes:
                raise InventoryError("SOURCE_BYTE_LIMIT", "source denominator exceeds configured byte bound")
            source_inputs.append(
                {
                    "package_id": target.package_id,
                    "target_kind": target.target_kind,
                    "target_name": target.target_name,
                    "module_prefix": module.module_prefix,
                    "path": _relative(root, module.path),
                    "sha256": digest,
                    "bytes": size,
                }
            )
            if len(source_inputs) > BOUNDS.max_source_files:
                raise InventoryError("SOURCE_FILE_LIMIT", "source denominator exceeds configured file bound")
        if len(result) > BOUNDS.max_source_tests:
            raise InventoryError("SOURCE_TEST_LIMIT", "source test denominator exceeds configured bound")
    source_inputs.sort(key=lambda item: (item["package_id"], item["target_kind"], item["target_name"], item["module_prefix"], item["path"], item["sha256"]))
    if evidence is not None:
        evidence.update(
            {
                "source_file_count": len(source_inputs),
                "source_bytes": total_bytes,
                "source_graph_sha256": _sha256(_canonical_bytes(source_inputs)),
            }
        )
    return sorted(result, key=lambda item: item.identity() + (item.source_path, item.line))


def _target_directory(root: Path, metadata: dict[str, Any] | None = None) -> Path:
    raw = metadata.get("target_directory") if metadata is not None else None
    if raw is None:
        configured = os.environ.get("CARGO_TARGET_DIR")
        candidate = Path(configured) if configured else root / "target"
        if not candidate.is_absolute():
            candidate = root / candidate
    elif isinstance(raw, str) and raw:
        candidate = Path(raw)
    else:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata target_directory is invalid")
    if not candidate.is_absolute():
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target_directory must be absolute")
    if len(str(candidate)) > 32_000:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target_directory exceeds the path bound")
    return candidate


def _artifact_executable(raw: str, target_directory: Path) -> Path:
    authored = Path(raw)
    if not authored.is_absolute():
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo emitted a non-absolute test executable path")
    try:
        target_root = target_directory.resolve(strict=True)
        if not target_root.is_dir():
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target_directory is not a directory")
        _reject_reparse_components(target_root, authored)
        executable = authored.resolve(strict=True)
        executable.relative_to(target_root)
        info = executable.lstat()
    except (OSError, ValueError) as exc:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", f"test executable escapes or is absent from cargo target_directory: {raw}") from exc
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400 or not stat.S_ISREG(info.st_mode):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", f"test executable is not a regular non-reparse file: {raw}")
    if info.st_size > BOUNDS.max_executable_bytes:
        raise InventoryError("EXECUTABLE_TOO_LARGE", f"test executable exceeds {BOUNDS.max_executable_bytes} bytes")
    return executable


def _digest_executable(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                total += len(chunk)
                if total > BOUNDS.max_executable_bytes:
                    raise InventoryError("EXECUTABLE_TOO_LARGE", f"test executable exceeds {BOUNDS.max_executable_bytes} bytes")
                digest.update(chunk)
    except InventoryError:
        raise
    except OSError as exc:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", f"cannot hash compiled test binary: {path}") from exc
    return digest.hexdigest()


def _build_test_artifacts(
    root: Path,
    runner: Any = None,
    expected_targets: Sequence[PackageTarget] | None = None,
    target_directory: Path | None = None,
) -> list[Artifact]:
    argv = (
        "cargo",
        "test",
        "--workspace",
        "--all-targets",
        "--locked",
        "--no-run",
        "--message-format=json",
    )
    result = _run_cmd(runner, root, argv)
    artifacts: list[Artifact] = []
    expected = {
        (item.package_id, item.target_kind, item.target_name)
        for item in expected_targets or ()
    }
    target_root = target_directory or _target_directory(root)
    seen_targets: set[tuple[str, str, str]] = set()
    build_finished = 0
    for line_number, raw_line in enumerate(result.stdout.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            value = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InventoryError("CARGO_MESSAGE_MALFORMED", f"cargo emitted malformed JSON on stdout line {line_number}") from exc
        if not isinstance(value, dict) or not isinstance(value.get("reason"), str):
            raise InventoryError("CARGO_MESSAGE_MALFORMED", f"cargo emitted an invalid message on stdout line {line_number}")
        reason = value["reason"]
        if reason == "build-finished":
            build_finished += 1
            if not isinstance(value.get("success"), bool) or not value["success"] or build_finished > 1:
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo build-finished message is failed or duplicated")
            continue
        if reason not in {"compiler-artifact", "compiler-message", "build-script-executed", "future-incompat-report"}:
            raise InventoryError("CARGO_MESSAGE_UNSUPPORTED", f"unsupported cargo message reason: {reason}")
        if reason != "compiler-artifact":
            continue
        profile = value.get("profile")
        if not isinstance(profile, dict) or not isinstance(profile.get("test"), bool):
            raise InventoryError("CARGO_ARTIFACT_MALFORMED", "cargo compiler-artifact profile is malformed")
        target = value.get("target")
        package_id = value.get("package_id")
        if not isinstance(target, dict) or not isinstance(package_id, str) or not package_id:
            raise InventoryError("CARGO_ARTIFACT_MALFORMED", "cargo compiler-artifact identity is malformed")
        target_name = target.get("name")
        kinds = target.get("kind")
        if (
            not isinstance(target_name, str)
            or not target_name
            or not isinstance(kinds, list)
            or not kinds
            or any(not isinstance(kind, str) or not kind for kind in kinds)
            or len(set(kinds)) != len(kinds)
        ):
            raise InventoryError("CARGO_ARTIFACT_MALFORMED", "cargo compiler-artifact target is malformed")
        target_kind = "+".join(sorted(kinds))
        key = (package_id, target_kind, target_name)
        if not profile["test"]:
            continue
        if expected_targets is not None and key not in expected:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", f"test artifact has no exact metadata target identity: {key}")
        if key in seen_targets:
            raise InventoryError("DUPLICATE_ARTIFACT", f"cargo repeated a test artifact identity: {key}")
        seen_targets.add(key)
        executable = value.get("executable")
        if not isinstance(executable, str) or not executable:
            raise InventoryError("CARGO_ARTIFACT_MALFORMED", "test compiler-artifact lacks an executable path")
        executable_path = _artifact_executable(executable, target_root)
        artifacts.append(
            Artifact(
                package_id=package_id,
                target_name=target_name,
                target_kind=target_kind,
                executable=executable_path,
            )
        )
        if len(artifacts) > BOUNDS.max_test_binaries:
            raise InventoryError("TEST_BINARY_LIMIT", "compiled test binary denominator exceeds bound")
    if expected_targets is not None and seen_targets != expected:
        missing = sorted(expected - seen_targets)
        raise InventoryError("COMPILED_GRAPH_INCOMPLETE", f"locked build omitted test target artifacts: {missing[:20]}")
    return sorted(artifacts, key=lambda item: (item.package_id, item.target_kind, item.target_name, str(item.executable)))


def discover_compiled(
    root: Path,
    targets: Sequence[PackageTarget],
    runner: Any = None,
    target_directory: Path | None = None,
) -> list[CompiledTest]:
    target_map = {(item.package_id, item.target_kind, item.target_name): item for item in targets}
    if len(target_map) != len(targets):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "target metadata contains duplicate identities")
    result: list[CompiledTest] = []
    for artifact in _build_test_artifacts(root, runner=runner, expected_targets=targets, target_directory=target_directory):
        target = target_map.get((artifact.package_id, artifact.target_kind, artifact.target_name))
        if target is None:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", f"compiled artifact has no metadata target: {artifact}")
        if target.harness is False:
            raise InventoryError("NON_LIBTEST_HARNESS", f"target cannot be classified through the libtest listing interface: {target.target_name}")
        executable_digest = _digest_executable(artifact.executable)
        listing = _run_cmd(
            runner,
            root,
            (str(artifact.executable), "--list", "--ignored", "--format", "terse"),
        )
        try:
            text = listing.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", f"invalid test listing encoding: {artifact.executable}") from exc
        listing_entries: list[tuple[str, str]] = []
        summary_counts: tuple[int, int] | None = None
        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            match = re.fullmatch(r"(.+?):\s+(test|benchmark)", stripped)
            if match is not None:
                if summary_counts is not None:
                    raise InventoryError("LIBTEST_LIST_MALFORMED", "libtest emitted a test after its summary")
                listing_entries.append((match.group(1), match.group(2)))
                continue
            summary = re.fullmatch(r"(\d+) tests?, (\d+) benchmarks?(?: \(filtered out\))?", stripped)
            if summary is not None:
                if summary_counts is not None:
                    raise InventoryError("LIBTEST_LIST_MALFORMED", "libtest emitted more than one listing summary")
                summary_counts = (int(summary.group(1)), int(summary.group(2)))
                continue
            raise InventoryError("LIBTEST_LIST_MALFORMED", f"unsupported libtest output on line {line_number}: {stripped[:160]}")
        if summary_counts is None:
            raise InventoryError("LIBTEST_LIST_MALFORMED", "libtest listing omitted its completeness summary")
        actual_counts = (
            sum(kind == "test" for _, kind in listing_entries),
            sum(kind == "benchmark" for _, kind in listing_entries),
        )
        if actual_counts != summary_counts:
            raise InventoryError("LIBTEST_LIST_INCOMPLETE", f"libtest summary {summary_counts} does not match listed names {actual_counts}")
        if len(listing_entries) > BOUNDS.max_compiled_tests:
            raise InventoryError("COMPILED_TEST_LIMIT", "compiled ignored-test listing exceeds configured bound")
        for name, _kind in listing_entries:
            if not name or any(ord(char) < 32 for char in name):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "compiled test name is invalid")
            result.append(
                CompiledTest(
                    package_id=artifact.package_id,
                    package_name=target.package_name,
                    target_name=artifact.target_name,
                    target_kind=artifact.target_kind,
                    executable=_relative(root, artifact.executable) if artifact.executable.is_relative_to(root.resolve(strict=True)) else str(artifact.executable),
                    executable_digest=executable_digest,
                    test_name=name,
                )
            )
            if len(result) > BOUNDS.max_compiled_tests:
                raise InventoryError("COMPILED_TEST_LIMIT", "compiled ignored-test denominator exceeds bound")
    return sorted(result, key=lambda item: item.identity() + (item.executable,))


def _row(source: SourceTest | None, compiled: CompiledTest | None, state: RowState, owner: str) -> InventoryRow:
    item = source or compiled
    assert item is not None
    payload = {
        "state": state.value,
        "package_id": item.package_id,
        "package_name": item.package_name,
        "target_name": item.target_name,
        "target_kind": item.target_kind,
        "test_name": item.test_name,
        "source_path": source.source_path if source else None,
        "source_line": source.line if source else None,
        "source_digest": source.source_digest if source else None,
        "attribute_text": source.attribute_text if source else None,
        "attribute_digest": source.attribute_digest if source else None,
        "ignore_reason": source.reason if source else None,
        "cfg_evidence": source.cfg_evidence if source else (),
        "requirements": source.requirements if source else (Requirement.UNKNOWN.value,),
        "executable": compiled.executable if compiled else None,
        "executable_digest": compiled.executable_digest if compiled else None,
        "remediation_owner": owner,
    }
    return InventoryRow(**payload, row_digest=_sha256(_canonical_bytes(payload)))


def reconcile(source: Sequence[SourceTest], compiled: Sequence[CompiledTest]) -> list[InventoryRow]:
    source_map: dict[tuple[str, str, str, str], list[SourceTest]] = {}
    compiled_map: dict[tuple[str, str, str, str], list[CompiledTest]] = {}
    for item in source:
        source_map.setdefault(item.identity(), []).append(item)
    for item in compiled:
        compiled_map.setdefault(item.identity(), []).append(item)
    rows: list[InventoryRow] = []
    for identity in sorted(set(source_map) | set(compiled_map)):
        sources = source_map.get(identity, [])
        binaries = compiled_map.get(identity, [])
        if len(sources) > 1 or len(binaries) > 1:
            owner = "test-source-owner" if len(sources) > 1 else "build-test-graph-owner"
            rows.extend(_row(source_item, None, RowState.DUPLICATE, owner) for source_item in sources)
            rows.extend(_row(None, compiled_item, RowState.DUPLICATE, owner) for compiled_item in binaries)
            continue
        source_item = sources[0] if sources else None
        compiled_item = binaries[0] if binaries else None
        if source_item is None:
            rows.append(_row(None, compiled_item, RowState.COMPILED_ONLY, "build-test-graph-owner"))
        elif compiled_item is None:
            rows.append(_row(source_item, None, RowState.SOURCE_ONLY, "test-target-owner"))
        elif source_item.reason is None or Requirement.UNKNOWN.value in source_item.requirements:
            rows.append(_row(source_item, compiled_item, RowState.UNCLASSIFIED, "test-declaration-owner"))
        else:
            rows.append(_row(source_item, compiled_item, RowState.CLASSIFIED, "declared-environment-owner"))
    return sorted(rows, key=lambda item: (item.package_id, item.target_kind, item.target_name, item.test_name, item.row_digest))


def _git_identity(root: Path, runner: Any = None) -> dict[str, Any]:
    head = _run_cmd(runner, root, ("git", "rev-parse", "HEAD")).stdout.decode("ascii", errors="strict").strip()
    status = _run_cmd(runner, root, ("git", "status", "--porcelain=v1", "--untracked-files=all")).stdout
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise InventoryError("SOURCE_IDENTITY_INVALID", "git HEAD is not a SHA-1 commit identity")
    clean = not bool(status)
    return {"head": head, "tracked_tree_clean": clean, "working_tree_clean": clean}


def build_inventory(root: Path, runner: Any = None) -> dict[str, Any]:
    metadata = _cargo_metadata(root, runner=runner)
    targets = _targets(root, metadata)
    source_evidence: dict[str, Any] = {}
    source = discover_source(root, targets, evidence=source_evidence)
    target_directory = _target_directory(root, metadata)
    compiled = discover_compiled(root, targets, runner=runner, target_directory=target_directory)
    rows = reconcile(source, compiled)
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.state] = counts.get(row.state, 0) + 1
    denominator = [dataclasses.asdict(row) for row in rows]
    lock_file = root / "Cargo.lock"
    if not lock_file.is_file():
        raise InventoryError("LOCKFILE_MISSING", "locked dependency inventory requires Cargo.lock")
    cargo_lock_sha256 = _sha256(_bounded_read(_repo_path(root, lock_file)))
    target_identity = [
        {
            "package_id": item.package_id,
            "target_kind": item.target_kind,
            "target_name": item.target_name,
            "src_path": _relative(root, item.src_path),
            "test": item.test,
            "harness": item.harness,
        }
        for item in targets
    ]
    header = {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "source_identity": _git_identity(root, runner=runner),
        "cargo_lock_sha256": cargo_lock_sha256,
        "locked_graph_sha256": metadata["_eliot_locked_graph_sha256"],
        "target_graph_sha256": _sha256(_canonical_bytes(target_identity)),
        "cargo_target_directory": str(target_directory.resolve(strict=False)),
        **source_evidence,
        "source_count": len(source),
        "compiled_count": len(compiled),
        "row_count": len(rows),
        "counts_by_state": dict(sorted(counts.items())),
        "proof_ceiling": "IGNORED_TEST_IDENTITY_AND_ENVIRONMENT_CLASSIFICATION_ONLY",
        "complete": all(row.state == RowState.CLASSIFIED.value for row in rows),
    }
    aggregate_input = {"header": header, "rows": denominator}
    header["aggregate_sha256"] = _sha256(_canonical_bytes(aggregate_input))
    return {"header": header, "rows": denominator}


def self_test() -> None:
    """Run internal unit self-tests without requiring external tools or repository mutations."""
    # 1. Canonical bytes deterministic sorting
    c1 = _canonical_bytes({"b": 1, "a": [2, 3]})
    c2 = _canonical_bytes({"a": [2, 3], "b": 1})
    assert c1 == c2, "canonical bytes must sort keys deterministically"
    assert _sha256(c1) == _sha256(c2)

    # 2. Command validation
    _validate_command(("cargo", "metadata", "--locked", "--format-version", "1"))
    _validate_command(("cargo", "test", "--workspace", "--all-targets", "--locked", "--no-run", "--message-format=json"))
    _validate_command(("git", "rev-parse", "HEAD"))
    _validate_command(("git", "status", "--porcelain=v1", "--untracked-files=no"))
    _validate_command(("target/debug/deps/test.exe", "--list", "--ignored", "--format", "terse"))
    try:
        _validate_command(("cargo", "run"))
        assert False, "arbitrary command must be rejected"
    except InventoryError as exc:
        assert exc.code == "COMMAND_NOT_ALLOWED"

    # 3. Attribute flags & reason decoding
    is_t, is_i, is_cfg, reason, cfg = _attribute_flags('#[test]\n#[ignore = "requires store database"]')
    assert is_t and is_i and not is_cfg and reason == "requires store database" and cfg is None

    is_t, is_i, is_cfg, reason, cfg = _attribute_flags('#[tokio::test]\n#[ignore = r#"requires "raw" host"#]')
    assert is_t and is_i and not is_cfg and reason == 'requires "raw" host' and cfg is None

    is_t, is_i, is_cfg, reason, cfg = _attribute_flags('#[disabled_test = "requires kernel"]')
    assert is_t and is_i and is_cfg and reason == "requires kernel"

    is_t, is_i, is_cfg, reason, cfg = _attribute_flags('#[cfg_attr(windows, ignore = "requires windows pipe")]')
    assert not is_t and is_i and is_cfg and reason == "requires windows pipe" and cfg is not None

    # 4. Reason unescaping
    assert _decode_reason(r'#[ignore = "foo \"bar\" baz"]') == 'foo "bar" baz'
    assert _decode_reason(r'#[ignore = r#"raw "quotes" inside"#]') == 'raw "quotes" inside'

    # 5. Requirements mapping and composition
    assert _requirements("requires local authenticated surrealdb") == (Requirement.STORE.value,)
    assert _requirements("governor host runtime") == (Requirement.RUNTIME.value,)
    assert _requirements("windows pipe acl session") == (Requirement.RUNTIME.value,)
    assert _requirements("git repository worktree") == (Requirement.GIT.value,)
    assert _requirements("external personal credential api key") == (Requirement.EXTERNAL_CREDENTIALED_MANUAL_ONLY.value,)
    assert _requirements("requires local surrealdb and governor runtime") == (Requirement.RUNTIME.value, Requirement.STORE.value)
    assert _requirements("just a random test failure") == (Requirement.UNKNOWN.value,)

    # 6. Safe output validation
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        troot = Path(td).resolve()
        (troot / ".eliot").mkdir()
        safe_candidate = troot / ".eliot" / "sub" / "inventory.json"
        assert _safe_output(troot, safe_candidate) == safe_candidate

        try:
            _safe_output(troot, troot / "unsafe.json")
            assert False, "output outside .eliot must fail"
        except InventoryError as exc:
            assert exc.code == "UNSAFE_OUTPUT"

        existing = troot / ".eliot" / "existing.json"
        existing.write_bytes(b"{}")
        try:
            _safe_output(troot, existing, overwrite=False)
            assert False, "existing output without overwrite must fail"
        except InventoryError as exc:
            assert exc.code == "OUTPUT_EXISTS"
        assert _safe_output(troot, existing, overwrite=True) == existing

    # 7. Reconciliation state logic
    s1 = SourceTest("p1", "pname", "tname", "lib", "test_one", "src/lib.rs", 10, "#[test]", "h1", "requires store", (), ("STORE",), "sd1")
    c1 = CompiledTest("p1", "pname", "tname", "lib", "bin/test.exe", "ed1", "test_one")
    rows = reconcile([s1], [c1])
    assert len(rows) == 1 and rows[0].state == RowState.CLASSIFIED.value and rows[0].remediation_owner == "declared-environment-owner"

    rows_s = reconcile([s1], [])
    assert len(rows_s) == 1 and rows_s[0].state == RowState.SOURCE_ONLY.value and rows_s[0].remediation_owner == "test-target-owner"

    rows_c = reconcile([], [c1])
    assert len(rows_c) == 1 and rows_c[0].state == RowState.COMPILED_ONLY.value and rows_c[0].remediation_owner == "build-test-graph-owner"

    s_dup = SourceTest("p1", "pname", "tname", "lib", "test_one", "src/lib.rs", 20, "#[test]", "h2", "requires store", (), ("STORE",), "sd2")
    rows_dup = reconcile([s1, s_dup], [c1])
    assert all(r.state == RowState.DUPLICATE.value for r in rows_dup)


def run_self_tests() -> int:
    try:
        self_test()
    except Exception as exc:
        print(f"FAIL: ignored_test_inventory self-tests failed: {exc}", file=sys.stderr)
        return 1
    print("PASS: ignored_test_inventory self-tests passed")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=None, help="Path to repository root")
    parser.add_argument("--output", type=Path, default=None, help="Path to output JSON file (must be under .eliot)")
    parser.add_argument("--overwrite", action="store_true", help="Allow overwriting existing output")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests and exit")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        return run_self_tests()
    if args.repo_root is None or args.output is None:
        print(
            json.dumps(
                {"status": "error", "code": "INVALID_ARGUMENTS", "detail": "--repo-root and --output are required when not running --self-test"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    try:
        root = args.repo_root.resolve(strict=True)
        output = _safe_output(root, args.output, overwrite=args.overwrite)
        inventory = build_inventory(root)
        serialized = _canonical_bytes(inventory) + b"\n"
        if len(serialized) > BOUNDS.max_inventory_bytes:
            raise InventoryError("INVENTORY_TOO_LARGE", f"inventory exceeds {BOUNDS.max_inventory_bytes} bytes")
        output.parent.mkdir(parents=True, exist_ok=True)
        output = _safe_output(root, output, overwrite=args.overwrite)
        if args.overwrite and output.exists():
            output.unlink()
        with output.open("xb") as handle:
            handle.write(serialized)
    except InventoryError as exc:
        payload = {"status": "error", "code": exc.code, "detail": exc.detail}
        if hasattr(exc, "owner") and exc.owner:
            payload["owner"] = exc.owner
        print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        return 2
    except OSError as exc:
        print(json.dumps({"status": "error", "code": "INVENTORY_IO_ERROR", "detail": str(exc)[:1024}, sort_keys=True), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "ok",
                "output": str(output),
                "rows": inventory["header"]["row_count"],
                "complete": inventory["header"]["complete"],
                "aggregate_sha256": inventory["header"]["aggregate_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0 if inventory["header"]["complete"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
