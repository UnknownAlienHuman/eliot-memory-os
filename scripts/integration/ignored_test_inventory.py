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
import subprocess
import sys
import time
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any, Final

SCHEMA: Final = "eliot.integration.ignored-test-inventory.v1"
TOOL_VERSION: Final = "0.1.0"
OUTPUT_ROOT: Final = ".eliot"


class InventoryError(RuntimeError):
    """Stable public failure with a machine-readable reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class Bounds:
    max_source_files: int = 20_000
    max_source_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 4 * 1024 * 1024
    max_attribute_bytes: int = 64 * 1024
    max_source_tests: int = 100_000
    max_test_binaries: int = 10_000
    max_compiled_tests: int = 100_000
    max_command_output_bytes: int = 256 * 1024 * 1024
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


@dataclasses.dataclass(frozen=True)
class Artifact:
    package_id: str
    target_name: str
    target_kind: str
    executable: Path


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
        resolved = path.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise InventoryError("PATH_ESCAPE", f"path is outside repository root: {path}") from exc
    return resolved


def _relative(root: Path, path: Path) -> str:
    return _repo_path(root, path).relative_to(root.resolve(strict=True)).as_posix()


def _safe_output(root: Path, output: Path) -> Path:
    root = root.resolve(strict=True)
    candidate = output if output.is_absolute() else root / output
    parent = candidate.parent.resolve(strict=True)
    try:
        relative = parent.relative_to(root)
    except ValueError as exc:
        raise InventoryError("UNSAFE_OUTPUT", "output parent is outside repository root") from exc
    if not relative.parts or relative.parts[0] != OUTPUT_ROOT:
        raise InventoryError("UNSAFE_OUTPUT", "output must be below the repository .eliot directory")
    if candidate.exists():
        raise InventoryError("OUTPUT_EXISTS", f"refusing to overwrite {candidate}")
    return candidate


def _bounded_read(path: Path) -> bytes:
    size = path.stat().st_size
    if size > BOUNDS.max_file_bytes:
        raise InventoryError("SOURCE_FILE_TOO_LARGE", f"{path} exceeds {BOUNDS.max_file_bytes} bytes")
    return path.read_bytes()


def _run_fixed(root: Path, argv: Sequence[str], timeout: int | None = None) -> CommandResult:
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


def _cargo_metadata(root: Path) -> dict[str, Any]:
    result = _run_fixed(root, ("cargo", "metadata", "--locked", "--format-version", "1"))
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata returned malformed JSON") from exc
    if not isinstance(value, dict) or not isinstance(value.get("packages"), list):
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo metadata shape is invalid")
    return value


def _targets(root: Path, metadata: dict[str, Any]) -> list[PackageTarget]:
    workspace = set(metadata.get("workspace_members", []))
    result: list[PackageTarget] = []
    for package in metadata["packages"]:
        package_id = package.get("id")
        if package_id not in workspace:
            continue
        name = package.get("name")
        manifest = package.get("manifest_path")
        targets = package.get("targets")
        if not isinstance(package_id, str) or not isinstance(name, str) or not isinstance(manifest, str) or not isinstance(targets, list):
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo package metadata is incomplete")
        manifest_path = _repo_path(root, Path(manifest))
        for target in targets:
            kinds = target.get("kind")
            src_path = target.get("src_path")
            target_name = target.get("name")
            if not isinstance(kinds, list) or not kinds or not isinstance(src_path, str) or not isinstance(target_name, str):
                raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "cargo target metadata is incomplete")
            target_kind = "+".join(sorted(str(item) for item in kinds))
            result.append(
                PackageTarget(
                    package_id=package_id,
                    package_name=name,
                    manifest_dir=manifest_path.parent,
                    target_name=target_name,
                    target_kind=target_kind,
                    src_path=_repo_path(root, Path(src_path)),
                )
            )
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
        if char in {'"', "'"} or (char in {"b", "c"} and index + 1 < length and text[index + 1] in {'"', "'"}):
            start = index
            if char in {"b", "c"}:
                index += 1
                char = text[index]
            index += 1
            escaped = False
            while index < length:
                current = text[index]
                index += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == char:
                    break
            else:
                raise InventoryError("MALFORMED_SOURCE", "unterminated string or character literal")
            raw = text[start:index]
            tokens.append(Token("string", raw, start, index, line))
            advance(raw)
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
        if char.isalpha() or char == "_":
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] == "_"):
                end += 1
            tokens.append(Token("ident", text[index:end], index, end, line))
            index = end
            continue
        if char.isdigit():
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] in "_\."):
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
    return tokens


def _decode_reason(raw: str) -> str | None:
    matches = re.findall(r'(?:b|c)?r#{0,16}"(.*?)"#{0,16}|(?:b|c)?"((?:\\.|[^"\\])*)"', raw, re.DOTALL)
    for raw_value, escaped_value in matches:
        value = raw_value or escaped_value
        if value.strip():
            return value.strip()[:1024]
    return None


def _attribute_flags(raw: str) -> tuple[bool, bool, bool, str | None, str | None]:
    compact = re.sub(r"\s+", "", raw)
    is_test = bool(re.search(r"(?:^|[:\[,])(?:test|tokio::test|async_std::test)(?:$|[\],(])", compact))
    direct_ignore = bool(re.search(r"(?:^|[:\[,])ignore(?:=|$|[\],(])", compact))
    cfg_ignore = "cfg_attr" in compact and "ignore" in compact
    disabled = any(marker in compact for marker in ("disabled_test", "eliot_disabled_test", "test_disabled"))
    cfg = raw if "cfg" in compact else None
    return is_test, direct_ignore or cfg_ignore or disabled, cfg_ignore or disabled, _decode_reason(raw), cfg


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


def _candidate_source_files(root: Path, target: PackageTarget) -> list[Path]:
    files: set[Path] = {target.src_path}
    manifest = target.manifest_dir
    for directory in (manifest / "src", manifest / "tests", manifest / "benches", manifest / "examples"):
        if not directory.exists():
            continue
        for path in directory.rglob("*.rs"):
            files.add(_repo_path(root, path))
            if len(files) > BOUNDS.max_source_files:
                raise InventoryError("SOURCE_FILE_LIMIT", "source file denominator exceeds configured bound")
    return sorted(files)


def _scan_file(root: Path, target: PackageTarget, path: Path) -> list[SourceTest]:
    data = _bounded_read(path)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InventoryError("INVALID_SOURCE_ENCODING", f"Rust source is not UTF-8: {path}") from exc
    tokens = _lex_rust(text)
    module_stack: list[tuple[str, int]] = [(part, 0) for part in _file_module_prefix(target, path)]
    brace_depth = 0
    pending_attributes: list[str] = []
    pending_module: str | None = None
    results: list[SourceTest] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.value == "#" and index + 1 < len(tokens) and tokens[index + 1].value == "[":
            start = token.start
            depth = 0
            cursor = index + 1
            while cursor < len(tokens):
                value = tokens[cursor].value
                if value == "[":
                    depth += 1
                elif value == "]":
                    depth -= 1
                    if depth == 0:
                        end = tokens[cursor].end
                        break
                cursor += 1
            else:
                raise InventoryError("MALFORMED_SOURCE", f"unterminated attribute in {path}")
            if end - start > BOUNDS.max_attribute_bytes:
                raise InventoryError("ATTRIBUTE_TOO_LARGE", f"attribute exceeds bound in {path}")
            pending_attributes.append(text[start:end])
            index = cursor + 1
            continue
        if token.value == "mod" and index + 1 < len(tokens) and tokens[index + 1].kind == "ident":
            pending_module = tokens[index + 1].value
        elif token.value == "fn" and index + 1 < len(tokens) and tokens[index + 1].kind == "ident":
            name_token = tokens[index + 1]
            flags = [_attribute_flags(raw) for raw in pending_attributes]
            is_test = any(item[0] for item in flags)
            is_ignored = any(item[1] for item in flags)
            if is_test and is_ignored:
                modules = [name for name, _ in module_stack]
                test_name = "::".join((*modules, name_token.value)) if modules else name_token.value
                reason = next((item[3] for item in flags if item[3]), None)
                cfg = tuple(item[4] for item in flags if item[4])
                attributes = "\n".join(pending_attributes)
                requirements = _requirements(attributes + "\n" + (reason or ""))
                relative = _relative(root, path)
                source_identity = {
                    "path": relative,
                    "line": name_token.line,
                    "test_name": test_name,
                    "attributes": attributes,
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
                        attribute_text=attributes,
                        attribute_digest=_sha256(attributes.encode("utf-8")),
                        reason=reason,
                        cfg_evidence=cfg,
                        requirements=requirements,
                        source_digest=_sha256(_canonical_bytes(source_identity)),
                    )
                )
            pending_attributes.clear()
        elif token.value == "{":
            brace_depth += 1
            if pending_module is not None:
                module_stack.append((pending_module, brace_depth))
                pending_module = None
            pending_attributes.clear()
        elif token.value == "}":
            while module_stack and module_stack[-1][1] == brace_depth:
                module_stack.pop()
            brace_depth = max(0, brace_depth - 1)
            pending_attributes.clear()
            pending_module = None
        elif token.value == ";":
            pending_attributes.clear()
            pending_module = None
        elif token.kind == "ident" and token.value not in {"pub", "async", "unsafe", "const", "extern", "crate", "self", "super"}:
            if token.value not in {"fn", "mod"} and pending_module is None:
                # Keep attributes while traversing visibility/qualifier tokens,
                # but discard them when another item begins.
                if token.value in {"struct", "enum", "trait", "impl", "type", "static", "use", "macro_rules"}:
                    pending_attributes.clear()
        index += 1
    return results


def _requirements(text: str) -> tuple[str, ...]:
    value = text.casefold()
    result: set[Requirement] = set()
    if any(token in value for token in ("surreal", "store", "database", "schema migration", "authenticated db")):
        result.add(Requirement.STORE)
    if any(token in value for token in ("kernel", "governor", "host", "watchdog", "agent bridge", "named pipe", "acl", "session", "installation", "eliot_governor_config", "windows runtime")):
        result.add(Requirement.RUNTIME)
    if any(token in value for token in ("git", "repository", "worktree", "commit identity")):
        result.add(Requirement.GIT)
    if any(token in value for token in ("personal credential", "paid", "external credential", "api key", "oauth")):
        result.add(Requirement.EXTERNAL_CREDENTIALED_MANUAL_ONLY)
    if not result:
        result.add(Requirement.UNKNOWN)
    return tuple(sorted(item.value for item in result))


def discover_source(root: Path, targets: Sequence[PackageTarget]) -> list[SourceTest]:
    result: list[SourceTest] = []
    seen_files: set[tuple[str, Path]] = set()
    total_bytes = 0
    for target in targets:
        for path in _candidate_source_files(root, target):
            key = (target.package_id, path)
            if key in seen_files:
                continue
            seen_files.add(key)
            total_bytes += path.stat().st_size
            if total_bytes > BOUNDS.max_source_bytes:
                raise InventoryError("SOURCE_BYTE_LIMIT", "source denominator exceeds configured byte bound")
            result.extend(_scan_file(root, target, path))
            if len(result) > BOUNDS.max_source_tests:
                raise InventoryError("SOURCE_TEST_LIMIT", "source test denominator exceeds configured bound")
    return sorted(result, key=lambda item: item.identity() + (item.source_path, item.line))


def _build_test_artifacts(root: Path) -> list[Artifact]:
    argv = (
        "cargo",
        "test",
        "--workspace",
        "--all-targets",
        "--locked",
        "--no-run",
        "--message-format=json",
    )
    result = _run_fixed(root, argv)
    artifacts: list[Artifact] = []
    for raw_line in result.stdout.splitlines():
        if not raw_line.strip():
            continue
        try:
            value = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if value.get("reason") != "compiler-artifact" or not value.get("profile", {}).get("test"):
            continue
        executable = value.get("executable")
        target = value.get("target", {})
        package_id = value.get("package_id")
        if not isinstance(executable, str) or not isinstance(package_id, str):
            continue
        target_name = target.get("name")
        kinds = target.get("kind")
        if not isinstance(target_name, str) or not isinstance(kinds, list) or not kinds:
            continue
        executable_path = Path(executable).resolve(strict=True)
        artifacts.append(
            Artifact(
                package_id=package_id,
                target_name=target_name,
                target_kind="+".join(sorted(str(item) for item in kinds)),
                executable=executable_path,
            )
        )
        if len(artifacts) > BOUNDS.max_test_binaries:
            raise InventoryError("TEST_BINARY_LIMIT", "compiled test binary denominator exceeds bound")
    unique = {(item.package_id, item.target_kind, item.target_name, str(item.executable)): item for item in artifacts}
    if not unique:
        raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", "locked build produced no test executables")
    return sorted(unique.values(), key=lambda item: (item.package_id, item.target_kind, item.target_name, str(item.executable)))


def discover_compiled(root: Path, targets: Sequence[PackageTarget]) -> list[CompiledTest]:
    target_map = {(item.package_id, item.target_kind, item.target_name): item for item in targets}
    result: list[CompiledTest] = []
    for artifact in _build_test_artifacts(root):
        target = target_map.get((artifact.package_id, artifact.target_kind, artifact.target_name))
        if target is None:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", f"compiled artifact has no metadata target: {artifact}")
        executable_digest = _sha256(artifact.executable.read_bytes())
        listing = _run_fixed(
            root,
            (str(artifact.executable), "--list", "--ignored", "--format", "terse"),
        )
        try:
            text = listing.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError("COMPILED_GRAPH_UNAVAILABLE", f"invalid test listing encoding: {artifact.executable}") from exc
        for line in text.splitlines():
            match = re.fullmatch(r"(.+?):\s+(?:test|benchmark)", line.strip())
            if match is None:
                continue
            name = match.group(1)
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
            for source_item in sources or [None]:
                for compiled_item in binaries or [None]:
                    rows.append(_row(source_item, compiled_item, RowState.DUPLICATE, "test-source-owner"))
            continue
        source_item = sources[0] if sources else None
        compiled_item = binaries[0] if binaries else None
        if source_item is None:
            rows.append(_row(None, compiled_item, RowState.COMPILED_ONLY, "build-test-graph-owner"))
        elif compiled_item is None:
            rows.append(_row(source_item, None, RowState.SOURCE_ONLY, "test-target-owner"))
        elif source_item.reason is None or source_item.requirements == (Requirement.UNKNOWN.value,):
            rows.append(_row(source_item, compiled_item, RowState.UNCLASSIFIED, "test-declaration-owner"))
        else:
            rows.append(_row(source_item, compiled_item, RowState.CLASSIFIED, "declared-environment-owner"))
    return sorted(rows, key=lambda item: (item.package_id, item.target_kind, item.target_name, item.test_name, item.row_digest))


def _git_identity(root: Path) -> dict[str, Any]:
    head = _run_fixed(root, ("git", "rev-parse", "HEAD")).stdout.decode("ascii", errors="strict").strip()
    status = _run_fixed(root, ("git", "status", "--porcelain=v1", "--untracked-files=no")).stdout
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise InventoryError("SOURCE_IDENTITY_INVALID", "git HEAD is not a SHA-1 commit identity")
    return {"head": head, "tracked_tree_clean": not bool(status)}


def build_inventory(root: Path) -> dict[str, Any]:
    started = time.monotonic()
    metadata = _cargo_metadata(root)
    targets = _targets(root, metadata)
    source = discover_source(root, targets)
    compiled = discover_compiled(root, targets)
    rows = reconcile(source, compiled)
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.state] = counts.get(row.state, 0) + 1
    denominator = [dataclasses.asdict(row) for row in rows]
    header = {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "source_identity": _git_identity(root),
        "cargo_lock_sha256": _sha256(_bounded_read(root / "Cargo.lock")),
        "source_count": len(source),
        "compiled_count": len(compiled),
        "row_count": len(rows),
        "counts_by_state": dict(sorted(counts.items())),
        "proof_ceiling": "IGNORED_TEST_IDENTITY_AND_ENVIRONMENT_CLASSIFICATION_ONLY",
        "complete": all(row.state == RowState.CLASSIFIED.value for row in rows),
    }
    aggregate_input = {"header": header, "rows": denominator}
    header["aggregate_sha256"] = _sha256(_canonical_bytes(aggregate_input))
    header["duration_observation_ms"] = int((time.monotonic() - started) * 1000)
    return {"header": header, "rows": denominator}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        root = args.repo_root.resolve(strict=True)
        output = _safe_output(root, args.output)
        inventory = build_inventory(root)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as handle:
            handle.write(_canonical_bytes(inventory))
            handle.write(b"\n")
    except InventoryError as exc:
        print(json.dumps({"status": "error", "code": exc.code, "detail": exc.detail}, sort_keys=True), file=sys.stderr)
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
