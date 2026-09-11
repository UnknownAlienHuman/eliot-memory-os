#!/usr/bin/env python3
"""Generate a deterministic support-neutral Cargo package reachability inventory.

The inventory is evidence, not authority. It never builds or runs repository
code, mutates Issues, or promotes package presence to implementation/runtime
support. It executes only fixed Git/Cargo/toolchain identity commands and reads
tracked manifests and bounded Rust source below one repository root.

Issue: https://github.com/UnknownAlienHuman/eliot-memory-os/issues/1133
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tomllib
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final, Protocol

SCHEMA: Final = "eliot.crate-reachability-inventory.v1"
TOOL_VERSION: Final = "0.1.0"
OUTPUT_ROOT: Final = ".eliot"


class InventoryError(RuntimeError):
    """Stable fail-closed error carrying a machine-readable reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class Bounds:
    max_manifests: int = 2_000
    max_metadata_graphs: int = 512
    max_command_output_bytes: int = 128 * 1024 * 1024
    command_timeout_seconds: int = 900
    max_source_files: int = 30_000
    max_source_bytes: int = 768 * 1024 * 1024
    max_source_file_bytes: int = 8 * 1024 * 1024
    max_findings: int = 250_000
    max_source_consumers_per_package: int = 2_000


BOUNDS: Final = Bounds()


class ManifestClass(str, enum.Enum):
    WORKSPACE_ROOT = "WORKSPACE_ROOT"
    WORKSPACE_MEMBER = "WORKSPACE_MEMBER"
    LOCAL_NON_MEMBER_DEPENDENCY = "LOCAL_NON_MEMBER_DEPENDENCY"
    EXCLUDED_PACKAGE = "EXCLUDED_PACKAGE"
    STANDALONE_PACKAGE = "STANDALONE_PACKAGE"


class Reachability(str, enum.Enum):
    BINARY_ENTRYPOINT = "BINARY_ENTRYPOINT"
    PRODUCTION_CONSUMER = "PRODUCTION_CONSUMER"
    BUILD_ONLY = "BUILD_ONLY"
    TEST_ONLY = "TEST_ONLY"
    UNRESOLVED_DYNAMIC = "UNRESOLVED_DYNAMIC"
    NO_CONSUMER = "NO_CONSUMER"


class SourceScope(str, enum.Enum):
    PRODUCTION = "PRODUCTION"
    BUILD = "BUILD"
    TEST = "TEST"
    EXAMPLE = "EXAMPLE"
    BENCH = "BENCH"
    UNKNOWN = "UNKNOWN"


class Runner(Protocol):
    def run(self, root: Path, argv: Sequence[str]) -> bytes:
        """Run one internally fixed command and return bounded stdout."""


@dataclasses.dataclass(frozen=True)
class SubprocessRunner:
    bounds: Bounds = BOUNDS

    def run(self, root: Path, argv: Sequence[str]) -> bytes:
        allowed = {
            ("git", "ls-files"),
            ("git", "rev-parse"),
            ("git", "status"),
            ("cargo", "metadata"),
            ("cargo", "-Vv"),
            ("rustc", "-Vv"),
        }
        prefix = tuple(argv[:2])
        if prefix not in allowed:
            raise InventoryError("COMMAND_NOT_ALLOWED", f"command is not fixed/allowed: {argv!r}")
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
                timeout=self.bounds.command_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InventoryError("COMMAND_FAILED", f"{argv[0]} could not run: {exc}") from exc
        total = len(completed.stdout) + len(completed.stderr)
        if total > self.bounds.max_command_output_bytes:
            raise InventoryError(
                "COMMAND_OUTPUT_TOO_LARGE",
                f"command output exceeded {self.bounds.max_command_output_bytes} bytes: {argv!r}",
            )
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace")[-4096:]
            raise InventoryError(
                "COMMAND_FAILED",
                f"command exited {completed.returncode}: {argv!r}: {detail}",
            )
        return completed.stdout


@dataclasses.dataclass(frozen=True)
class MetadataGraph:
    graph_id: str
    manifest_path: str
    workspace_root: str
    workspace_members: tuple[str, ...]
    workspace_default_members: tuple[str, ...]
    packages: tuple[Mapping[str, Any], ...]
    resolve: Mapping[str, Any] | None


@dataclasses.dataclass(frozen=True)
class SourceFileEvidence:
    package_key: str
    package_name: str
    path: str
    scope: str
    sha256: str
    nonblank_loc: int
    public_items: int
    test_attributes: int
    identifiers: tuple[str, ...]


TEXT_INDICATORS: Final[tuple[tuple[str, str], ...]] = (
    ("NOT_IMPLEMENTED", "NOT_IMPLEMENTED_MARKER"),
    ("KERNEL_ADMISSION_REQUIRED", "FAIL_CLOSED_ADMISSION_MARKER"),
    ("PLAN_GAP", "PLAN_GAP_MARKER"),
    ("placeholder", "PLACEHOLDER_LANGUAGE"),
    ("skeleton", "SKELETON_LANGUAGE"),
    ("contract-only", "CONTRACT_ONLY_LANGUAGE"),
    ("not yet implemented", "NOT_IMPLEMENTED_LANGUAGE"),
)

CODE_INDICATORS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (re.compile(r"\btodo\s*!\s*\("), "TODO_MACRO"),
    (re.compile(r"\bunimplemented\s*!\s*\("), "UNIMPLEMENTED_MACRO"),
    (re.compile(r"\b(?:std\s*::\s*process\s*::\s*)?Command\s*::\s*new\s*\("), "DIRECT_PROCESS_COMMAND"),
    (re.compile(r"\bunsafe\b"), "UNSAFE_CODE"),
    (re.compile(r"#!?\s*\[\s*allow\s*\(\s*dead_code\s*\)\s*\]"), "DEAD_CODE_ALLOW"),
    (re.compile(r"\bserde_json\s*::\s*Value\b"), "GENERIC_JSON_VALUE"),
    (re.compile(r"\boperation\s*:\s*String\b"), "GENERIC_STRING_OPERATION"),
    (re.compile(r"\bprocess\s*::\s*exit\s*\(\s*78\s*\)"), "EXPLICIT_ADMISSION_EXIT"),
)

PUBLIC_ITEM_RE: Final = re.compile(
    r"\bpub(?:\s*\([^)]*\))?\s+(?:async\s+|unsafe\s+|const\s+)*"
    r"(?:struct|enum|trait|fn|type|const|static|mod)\b"
)
TEST_ATTRIBUTE_RE: Final = re.compile(r"#\s*\[\s*(?:tokio\s*::\s*)?test(?:\s*\([^]]*\))?\s*\]")
IDENTIFIER_RE: Final = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _bounded_text(value: Any, limit: int = 4096) -> str:
    text = str(value).replace("\x00", "\\0")
    return text if len(text) <= limit else text[:limit] + "…"


def _root(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise InventoryError("REPOSITORY_UNAVAILABLE", f"repository root is unavailable: {path}") from exc
    if not (resolved / "Cargo.toml").is_file() or not (resolved / ".git").exists():
        raise InventoryError("NOT_A_REPOSITORY", f"expected Git/Cargo repository root: {resolved}")
    return resolved


def _inside(root: Path, path: Path, *, must_exist: bool = True) -> Path:
    try:
        resolved = path.resolve(strict=must_exist)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise InventoryError("PATH_ESCAPE", f"path is outside repository root: {path}") from exc
    return resolved


def _relative(root: Path, path: Path) -> str:
    return _inside(root, path).relative_to(root).as_posix()


def _safe_output(root: Path, output: Path) -> Path:
    candidate = output if output.is_absolute() else root / output
    parent = _inside(root, candidate.parent, must_exist=True)
    relative = parent.relative_to(root)
    if not relative.parts or relative.parts[0] != OUTPUT_ROOT:
        raise InventoryError("UNSAFE_OUTPUT", "output must be below the repository .eliot directory")
    if candidate.exists():
        raise InventoryError("OUTPUT_EXISTS", f"refusing to overwrite existing output: {candidate}")
    return candidate


def _read_bytes(root: Path, path: Path, *, max_bytes: int) -> bytes:
    resolved = _inside(root, path)
    if resolved.is_symlink() or not resolved.is_file():
        raise InventoryError("SOURCE_NOT_REGULAR_FILE", f"expected a regular non-symlink file: {resolved}")
    size = resolved.stat().st_size
    if size > max_bytes:
        raise InventoryError("SOURCE_FILE_TOO_LARGE", f"{_relative(root, resolved)} exceeds {max_bytes} bytes")
    return resolved.read_bytes()


def _json_object(raw: bytes, *, source: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("MALFORMED_JSON", f"malformed JSON from {source}") from exc
    if not isinstance(value, dict):
        raise InventoryError("MALFORMED_JSON", f"expected JSON object from {source}")
    return value


def _tracked_manifests(root: Path, runner: Runner) -> tuple[str, ...]:
    raw = runner.run(root, ("git", "ls-files", "-z", "--", "Cargo.toml", ":(glob)**/Cargo.toml"))
    paths: list[str] = []
    for item in raw.split(b"\x00"):
        if not item:
            continue
        try:
            relative = item.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError("INVALID_GIT_PATH", "tracked manifest path is not UTF-8") from exc
        path = _inside(root, root / relative)
        if path.name != "Cargo.toml":
            raise InventoryError("INVALID_MANIFEST_PATH", f"unexpected manifest path: {relative}")
        paths.append(path.relative_to(root).as_posix())
    unique = tuple(sorted(set(paths)))
    if "Cargo.toml" not in unique:
        raise InventoryError("ROOT_MANIFEST_MISSING", "tracked root Cargo.toml is missing")
    if len(unique) > BOUNDS.max_manifests:
        raise InventoryError("MANIFEST_LIMIT", f"manifest denominator exceeds {BOUNDS.max_manifests}")
    return unique


def _metadata(root: Path, runner: Runner, manifest: str | None = None) -> MetadataGraph:
    argv: list[str] = ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"]
    if manifest is not None:
        argv.extend(("--manifest-path", manifest))
    raw = runner.run(root, tuple(argv))
    value = _json_object(raw, source="cargo metadata")
    packages = value.get("packages")
    members = value.get("workspace_members")
    defaults = value.get("workspace_default_members", [])
    workspace_root = value.get("workspace_root")
    if not isinstance(packages, list) or not isinstance(members, list) or not isinstance(defaults, list):
        raise InventoryError("MALFORMED_METADATA", "cargo metadata package/member arrays are missing")
    if not isinstance(workspace_root, str):
        raise InventoryError("MALFORMED_METADATA", "cargo metadata workspace_root is missing")
    graph_manifest = manifest or "Cargo.toml"
    return MetadataGraph(
        graph_id=_sha256(_canonical_bytes({"manifest": graph_manifest, "workspace_root": workspace_root})),
        manifest_path=graph_manifest.replace("\\", "/"),
        workspace_root=workspace_root,
        workspace_members=tuple(str(item) for item in members),
        workspace_default_members=tuple(str(item) for item in defaults),
        packages=tuple(item for item in packages if isinstance(item, dict)),
        resolve=value.get("resolve") if isinstance(value.get("resolve"), dict) else None,
    )


def _load_root_workspace(root: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    raw = _read_bytes(root, root / "Cargo.toml", max_bytes=BOUNDS.max_source_file_bytes)
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise InventoryError("MALFORMED_MANIFEST", "root Cargo.toml is malformed") from exc
    workspace = value.get("workspace", {})
    if not isinstance(workspace, dict):
        return (), ()
    members = workspace.get("members", [])
    exclude = workspace.get("exclude", [])
    if not isinstance(members, list) or not isinstance(exclude, list):
        raise InventoryError("MALFORMED_MANIFEST", "workspace members/exclude must be arrays")
    return tuple(str(item) for item in members), tuple(str(item) for item in exclude)


def _matches_pattern(manifest: str, patterns: Sequence[str]) -> bool:
    package_dir = str(Path(manifest).parent).replace("\\", "/")
    for pattern in patterns:
        normalized = pattern.rstrip("/")
        if fnmatch.fnmatchcase(package_dir, normalized) or fnmatch.fnmatchcase(manifest, normalized):
            return True
        if normalized and fnmatch.fnmatchcase(package_dir + "/", normalized.rstrip("/") + "/"):
            return True
    return False


def _manifest_paths_from_graph(root: Path, graph: MetadataGraph) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for package in graph.packages:
        manifest_path = package.get("manifest_path")
        package_id = package.get("id")
        if not isinstance(manifest_path, str) or not isinstance(package_id, str):
            raise InventoryError("MALFORMED_METADATA", "package id/manifest_path is missing")
        path = Path(manifest_path)
        try:
            relative = _inside(root, path).relative_to(root).as_posix()
        except InventoryError:
            continue
        if relative in result:
            raise InventoryError("DUPLICATE_MANIFEST_IDENTITY", f"duplicate package manifest: {relative}")
        result[relative] = package
    return result


def _collect_graphs(root: Path, runner: Runner, manifests: Sequence[str]) -> tuple[MetadataGraph, ...]:
    graphs: list[MetadataGraph] = []
    covered: set[str] = set()
    root_graph = _metadata(root, runner)
    graphs.append(root_graph)
    covered.update(_manifest_paths_from_graph(root, root_graph))
    for manifest in manifests:
        if manifest == "Cargo.toml" or manifest in covered:
            continue
        if len(graphs) >= BOUNDS.max_metadata_graphs:
            raise InventoryError("METADATA_GRAPH_LIMIT", f"metadata graph count exceeds {BOUNDS.max_metadata_graphs}")
        graph = _metadata(root, runner, manifest)
        graph_paths = _manifest_paths_from_graph(root, graph)
        if manifest not in graph_paths:
            raise InventoryError("UNACCOUNTED_MANIFEST", f"metadata graph did not account for {manifest}")
        graphs.append(graph)
        covered.update(graph_paths)
    missing = sorted(set(manifests) - covered - {"Cargo.toml"})
    if missing:
        raise InventoryError("UNACCOUNTED_MANIFEST", f"tracked manifests absent from metadata graphs: {missing[:20]}")
    return tuple(graphs)


def _package_key(graph: MetadataGraph, package_id: str) -> str:
    return f"{graph.graph_id}:{package_id}"


def _dependency_edges(graph: MetadataGraph) -> list[dict[str, Any]]:
    if graph.resolve is None:
        return []
    nodes = graph.resolve.get("nodes")
    if not isinstance(nodes, list):
        raise InventoryError("MALFORMED_METADATA", "resolve.nodes is missing")
    edges: list[dict[str, Any]] = []
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise InventoryError("MALFORMED_METADATA", "resolve node id is missing")
        source_id = node["id"]
        deps = node.get("deps", [])
        if not isinstance(deps, list):
            raise InventoryError("MALFORMED_METADATA", "resolve node deps is malformed")
        for dep in deps:
            if not isinstance(dep, dict) or not isinstance(dep.get("pkg"), str):
                raise InventoryError("MALFORMED_METADATA", "resolve dependency package is missing")
            dep_kinds = dep.get("dep_kinds", [])
            if not isinstance(dep_kinds, list) or not dep_kinds:
                dep_kinds = [{"kind": None, "target": None}]
            for dep_kind in dep_kinds:
                if not isinstance(dep_kind, dict):
                    raise InventoryError("MALFORMED_METADATA", "dependency kind is malformed")
                kind = dep_kind.get("kind") or "normal"
                target = dep_kind.get("target")
                edges.append(
                    {
                        "graph_id": graph.graph_id,
                        "from_package": _package_key(graph, source_id),
                        "to_package": _package_key(graph, dep["pkg"]),
                        "dependency_name": _bounded_text(dep.get("name", ""), 256),
                        "kind": str(kind),
                        "target": str(target) if target is not None else None,
                    }
                )
    return sorted(
        edges,
        key=lambda item: (
            item["from_package"],
            item["to_package"],
            item["kind"],
            item["target"] or "",
            item["dependency_name"],
        ),
    )


def _source_scope(manifest_dir: Path, path: Path) -> SourceScope:
    relative = path.relative_to(manifest_dir).as_posix()
    if relative == "build.rs":
        return SourceScope.BUILD
    if relative.startswith("tests/"):
        return SourceScope.TEST
    if relative.startswith("benches/"):
        return SourceScope.BENCH
    if relative.startswith("examples/"):
        return SourceScope.EXAMPLE
    if relative.startswith("src/"):
        return SourceScope.PRODUCTION
    return SourceScope.UNKNOWN


def _mask_rust(text: str) -> str:
    """Replace Rust comments and literal bodies with spaces while preserving lines."""

    chars = list(text)
    length = len(chars)
    index = 0

    def blank(start: int, end: int) -> None:
        for pos in range(start, end):
            if chars[pos] not in "\r\n":
                chars[pos] = " "

    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                end = length
            blank(index, end)
            index = end
            continue
        if text.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if text.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif text.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if depth:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unterminated block comment")
            blank(index, cursor)
            index = cursor
            continue
        raw_match = re.match(r'(?:b|c)?r(#{0,255})"', text[index:])
        if raw_match:
            hashes = raw_match.group(1)
            body_start = index + raw_match.end()
            terminator = '"' + hashes
            end = text.find(terminator, body_start)
            if end < 0:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unterminated raw string")
            end += len(terminator)
            blank(index, end)
            index = end
            continue
        prefix = 1 if text[index:index + 1] in {"b", "c"} and text[index + 1:index + 2] in {'"', "'"} else 0
        quote_pos = index + prefix
        if quote_pos < length and text[quote_pos] in {'"', "'"}:
            quote = text[quote_pos]
            cursor = quote_pos + 1
            escaped = False
            while cursor < length:
                current = text[cursor]
                cursor += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    break
            else:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unterminated string/character literal")
            blank(index, cursor)
            index = cursor
            continue
        index += 1
    return "".join(chars)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _line_excerpt(text: str, line: int) -> str:
    lines = text.splitlines()
    if line < 1 or line > len(lines):
        return ""
    return _bounded_text(lines[line - 1].strip(), 320)


def _nearest_instructions(root: Path, manifest_dir: Path) -> str | None:
    current = manifest_dir
    while True:
        candidate = current / "AGENTS.md"
        if candidate.is_file() and not candidate.is_symlink():
            return candidate.relative_to(root).as_posix()
        if current == root:
            return None
        try:
            current = current.parent
            current.relative_to(root)
        except ValueError:
            return None


def _owner_issues(root: Path, manifest_dir: Path) -> tuple[int, ...]:
    instructions = _nearest_instructions(root, manifest_dir)
    if instructions is None:
        return ()
    raw = _read_bytes(root, root / instructions, max_bytes=BOUNDS.max_source_file_bytes)
    text = raw.decode("utf-8", errors="replace")
    return tuple(sorted({int(value) for value in re.findall(r"(?:issues/|#)(\d{1,7})", text)}))


def _scan_sources(
    root: Path,
    package_key: str,
    package_name: str,
    manifest_dir: Path,
) -> tuple[list[SourceFileEvidence], list[dict[str, Any]]]:
    files: list[Path] = []
    for relative in ("src", "tests", "examples", "benches"):
        directory = manifest_dir / relative
        if not directory.exists():
            continue
        for path in directory.rglob("*.rs"):
            resolved = _inside(root, path)
            if resolved.is_symlink() or not resolved.is_file():
                continue
            files.append(resolved)
    build_rs = manifest_dir / "build.rs"
    if build_rs.is_file() and not build_rs.is_symlink():
        files.append(_inside(root, build_rs))
    files = sorted(set(files))
    if len(files) > BOUNDS.max_source_files:
        raise InventoryError("SOURCE_FILE_LIMIT", f"source file count exceeds {BOUNDS.max_source_files}")

    total_bytes = 0
    evidence: list[SourceFileEvidence] = []
    findings: list[dict[str, Any]] = []
    for path in files:
        raw = _read_bytes(root, path, max_bytes=BOUNDS.max_source_file_bytes)
        total_bytes += len(raw)
        if total_bytes > BOUNDS.max_source_bytes:
            raise InventoryError("SOURCE_BYTE_LIMIT", f"source bytes exceed {BOUNDS.max_source_bytes}")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError("INVALID_RUST_ENCODING", f"Rust source is not UTF-8: {_relative(root, path)}") from exc
        try:
            masked = _mask_rust(text)
        except InventoryError as exc:
            raise InventoryError(exc.code, f"{_relative(root, path)}: {exc.detail}") from exc
        scope = _source_scope(manifest_dir, path)
        identifiers = tuple(sorted(set(IDENTIFIER_RE.findall(masked))))
        evidence.append(
            SourceFileEvidence(
                package_key=package_key,
                package_name=package_name,
                path=_relative(root, path),
                scope=scope.value,
                sha256=_sha256(raw),
                nonblank_loc=sum(1 for line in text.splitlines() if line.strip()),
                public_items=len(PUBLIC_ITEM_RE.findall(masked)),
                test_attributes=len(TEST_ATTRIBUTE_RE.findall(masked)),
                identifiers=identifiers,
            )
        )
        for token, category in TEXT_INDICATORS:
            start = 0
            lowered = text.casefold()
            needle = token.casefold()
            while True:
                index = lowered.find(needle, start)
                if index < 0:
                    break
                line = _line_number(text, index)
                findings.append(
                    {
                        "package_key": package_key,
                        "path": _relative(root, path),
                        "line": line,
                        "scope": scope.value,
                        "category": category,
                        "token": token,
                        "excerpt": _line_excerpt(text, line),
                        "source_sha256": _sha256(raw),
                        "contextual_disposition": "REVIEW_REQUIRED",
                    }
                )
                start = index + len(needle)
        for pattern, category in CODE_INDICATORS:
            for match in pattern.finditer(masked):
                line = _line_number(masked, match.start())
                findings.append(
                    {
                        "package_key": package_key,
                        "path": _relative(root, path),
                        "line": line,
                        "scope": scope.value,
                        "category": category,
                        "token": _bounded_text(match.group(0), 128),
                        "excerpt": _line_excerpt(text, line),
                        "source_sha256": _sha256(raw),
                        "contextual_disposition": "REVIEW_REQUIRED",
                    }
                )
        if len(findings) > BOUNDS.max_findings:
            raise InventoryError("FINDING_LIMIT", f"finding count exceeds {BOUNDS.max_findings}")
    return evidence, findings


def _package_rows(
    root: Path,
    graphs: Sequence[MetadataGraph],
    tracked_manifests: Sequence[str],
    excluded_patterns: Sequence[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[SourceFileEvidence], list[dict[str, Any]]]:
    root_graph = graphs[0]
    root_member_ids = set(root_graph.workspace_members)
    root_default_ids = set(root_graph.workspace_default_members)
    root_packages_by_manifest = _manifest_paths_from_graph(root, root_graph)
    root_package_ids = {str(package.get("id")) for package in root_packages_by_manifest.values()}

    manifest_class: dict[str, ManifestClass] = {"Cargo.toml": ManifestClass.WORKSPACE_ROOT}
    for manifest, package in root_packages_by_manifest.items():
        package_id = str(package.get("id"))
        manifest_class[manifest] = (
            ManifestClass.WORKSPACE_MEMBER
            if package_id in root_member_ids
            else ManifestClass.LOCAL_NON_MEMBER_DEPENDENCY
        )
    for manifest in tracked_manifests:
        if manifest in manifest_class:
            continue
        manifest_class[manifest] = (
            ManifestClass.EXCLUDED_PACKAGE
            if _matches_pattern(manifest, excluded_patterns)
            else ManifestClass.STANDALONE_PACKAGE
        )

    rows: list[dict[str, Any]] = []
    all_edges: list[dict[str, Any]] = []
    source_files: list[SourceFileEvidence] = []
    findings: list[dict[str, Any]] = []
    package_by_key: dict[str, Mapping[str, Any]] = {}
    graph_by_key: dict[str, MetadataGraph] = {}
    manifest_by_key: dict[str, str] = {}

    for graph in graphs:
        all_edges.extend(_dependency_edges(graph))
        for package in graph.packages:
            package_id = package.get("id")
            manifest_path = package.get("manifest_path")
            if not isinstance(package_id, str) or not isinstance(manifest_path, str):
                raise InventoryError("MALFORMED_METADATA", "package identity is incomplete")
            try:
                manifest = _inside(root, Path(manifest_path)).relative_to(root).as_posix()
            except InventoryError:
                continue
            key = _package_key(graph, package_id)
            if key in package_by_key:
                raise InventoryError("DUPLICATE_PACKAGE_KEY", f"duplicate package key: {key}")
            package_by_key[key] = package
            graph_by_key[key] = graph
            manifest_by_key[key] = manifest

    reverse_edges: dict[str, list[dict[str, Any]]] = defaultdict(list)
    forward_edges: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in all_edges:
        reverse_edges[edge["to_package"]].append(edge)
        forward_edges[edge["from_package"]].append(edge)

    token_consumers: dict[str, set[tuple[str, str]]] = defaultdict(set)
    source_by_package: dict[str, list[SourceFileEvidence]] = defaultdict(list)
    findings_by_package: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for key, package in package_by_key.items():
        manifest_dir = (root / manifest_by_key[key]).parent
        package_name = str(package.get("name", ""))
        evidence, package_findings = _scan_sources(root, key, package_name, manifest_dir)
        source_files.extend(evidence)
        findings.extend(package_findings)
        source_by_package[key].extend(evidence)
        findings_by_package[key].extend(package_findings)
        for file in evidence:
            if file.scope not in {SourceScope.PRODUCTION.value, SourceScope.BUILD.value}:
                continue
            for identifier in file.identifiers:
                token_consumers[identifier].add((key, file.scope))

    for key, package in sorted(package_by_key.items()):
        graph = graph_by_key[key]
        manifest = manifest_by_key[key]
        package_name = str(package.get("name", ""))
        crate_identifier = package_name.replace("-", "_")
        source_consumers: list[dict[str, str]] = []
        for consumer_key, scope in sorted(token_consumers.get(crate_identifier, set())):
            if consumer_key == key:
                continue
            source_consumers.append({"package_key": consumer_key, "scope": scope})
            if len(source_consumers) > BOUNDS.max_source_consumers_per_package:
                raise InventoryError(
                    "SOURCE_CONSUMER_LIMIT",
                    f"source consumer count exceeds {BOUNDS.max_source_consumers_per_package}: {package_name}",
                )
        rev = sorted(
            reverse_edges.get(key, []),
            key=lambda item: (item["from_package"], item["kind"], item["target"] or ""),
        )
        targets_raw = package.get("targets", [])
        if not isinstance(targets_raw, list):
            raise InventoryError("MALFORMED_METADATA", f"targets are malformed: {package_name}")
        targets: list[dict[str, Any]] = []
        has_binary = False
        for target in targets_raw:
            if not isinstance(target, dict):
                raise InventoryError("MALFORMED_METADATA", f"target is malformed: {package_name}")
            kinds = target.get("kind", [])
            crate_types = target.get("crate_types", [])
            if not isinstance(kinds, list) or not isinstance(crate_types, list):
                raise InventoryError("MALFORMED_METADATA", f"target kind is malformed: {package_name}")
            has_binary = has_binary or "bin" in kinds
            src_path = target.get("src_path")
            relative_src: str | None = None
            if isinstance(src_path, str):
                try:
                    relative_src = _inside(root, Path(src_path)).relative_to(root).as_posix()
                except InventoryError:
                    relative_src = None
            targets.append(
                {
                    "name": _bounded_text(target.get("name", ""), 256),
                    "kind": tuple(sorted(str(item) for item in kinds)),
                    "crate_types": tuple(sorted(str(item) for item in crate_types)),
                    "edition": _bounded_text(target.get("edition", ""), 32),
                    "src_path": relative_src,
                    "required_features": tuple(sorted(str(item) for item in target.get("required-features", []) or [])),
                    "doctest": bool(target.get("doctest", False)),
                    "test": bool(target.get("test", False)),
                    "bench": bool(target.get("bench", False)),
                }
            )
        dependency_kinds = {edge["kind"] for edge in rev}
        source_prod_consumers = [item for item in source_consumers if item["scope"] == SourceScope.PRODUCTION.value]
        source_build_consumers = [item for item in source_consumers if item["scope"] == SourceScope.BUILD.value]
        normal_consumers = [edge for edge in rev if edge["kind"] == "normal"]
        build_consumers = [edge for edge in rev if edge["kind"] == "build"]
        dev_consumers = [edge for edge in rev if edge["kind"] == "dev"]
        if has_binary:
            reachability = Reachability.BINARY_ENTRYPOINT
        elif normal_consumers or source_prod_consumers:
            reachability = Reachability.PRODUCTION_CONSUMER
        elif build_consumers or source_build_consumers:
            reachability = Reachability.BUILD_ONLY
        elif dev_consumers:
            reachability = Reachability.TEST_ONLY
        elif package.get("links") or package.get("metadata", {}).get("eliot", {}).get("dynamic_registration"):
            reachability = Reachability.UNRESOLVED_DYNAMIC
        else:
            reachability = Reachability.NO_CONSUMER

        files = source_by_package.get(key, [])
        package_findings = findings_by_package.get(key, [])
        manifest_dir = (root / manifest).parent
        instructions = _nearest_instructions(root, manifest_dir)
        owner_issues = _owner_issues(root, manifest_dir)
        row = {
            "package_key": key,
            "graph_id": graph.graph_id,
            "package_id": str(package.get("id")),
            "name": package_name,
            "version": _bounded_text(package.get("version", ""), 128),
            "source": package.get("source"),
            "manifest_path": manifest,
            "manifest_class": manifest_class.get(manifest, ManifestClass.STANDALONE_PACKAGE).value,
            "workspace_member": str(package.get("id")) in root_member_ids,
            "workspace_default_member": str(package.get("id")) in root_default_ids,
            "targets": sorted(targets, key=lambda item: (item["name"], item["kind"], item["src_path"] or "")),
            "dependency_edges": sorted(
                forward_edges.get(key, []),
                key=lambda item: (item["to_package"], item["kind"], item["target"] or ""),
            ),
            "reverse_dependency_edges": rev,
            "source_consumers": source_consumers,
            "reachability": reachability.value,
            "source_summary": {
                "files": len(files),
                "nonblank_loc": sum(file.nonblank_loc for file in files),
                "public_items": sum(file.public_items for file in files),
                "owned_test_attributes": sum(file.test_attributes for file in files),
                "production_files": sum(file.scope == SourceScope.PRODUCTION.value for file in files),
                "build_files": sum(file.scope == SourceScope.BUILD.value for file in files),
                "test_files": sum(file.scope == SourceScope.TEST.value for file in files),
                "example_files": sum(file.scope == SourceScope.EXAMPLE.value for file in files),
                "bench_files": sum(file.scope == SourceScope.BENCH.value for file in files),
            },
            "finding_counts": dict(
                sorted(
                    (
                        category,
                        sum(item["category"] == category for item in package_findings),
                    )
                    for category in {item["category"] for item in package_findings}
                )
            ),
            "nearest_instructions": instructions,
            "owner_issue_refs_from_instructions": owner_issues,
            "support_axes": {
                "contract_maturity": "UNKNOWN_FROM_THIS_INVENTORY",
                "implementation_support": "SOURCE_SHAPE_OBSERVED_ONLY",
                "evidence_execution_status": "NOT_EXECUTED_BY_THIS_INVENTORY",
                "runtime_support": "UNKNOWN_FROM_THIS_INVENTORY",
                "product_support": "UNKNOWN_FROM_THIS_INVENTORY",
            },
            "review_state": (
                "REVIEW_REQUIRED"
                if reachability in {Reachability.NO_CONSUMER, Reachability.UNRESOLVED_DYNAMIC}
                or package_findings
                else "NO_STATIC_GAP_DETECTED"
            ),
            "blind_boundaries": (
                "dynamic registration, generated code, runtime feature selection, and platform-only construction are not proven by static token evidence",
            ),
        }
        row["row_sha256"] = _sha256(_canonical_bytes(row))
        rows.append(row)

    manifest_rows = [
        {
            "manifest_path": manifest,
            "class": manifest_class[manifest].value,
            "sha256": _sha256(_read_bytes(root, root / manifest, max_bytes=BOUNDS.max_source_file_bytes)),
        }
        for manifest in sorted(manifest_class)
    ]
    return (
        sorted(rows, key=lambda item: (item["manifest_path"], item["package_id"], item["graph_id"])),
        manifest_rows,
        sorted(source_files, key=lambda item: (item.package_key, item.scope, item.path)),
        sorted(findings, key=lambda item: (item["package_key"], item["path"], item["line"], item["category"])),
    )


def build_inventory(root: Path, runner: Runner | None = None) -> dict[str, Any]:
    root = _root(root)
    runner = runner or SubprocessRunner()
    started = time.monotonic()
    tracked_manifests = _tracked_manifests(root, runner)
    _, excluded_patterns = _load_root_workspace(root)
    graphs = _collect_graphs(root, runner, tracked_manifests)
    packages, manifests, source_files, findings = _package_rows(
        root,
        graphs,
        tracked_manifests,
        excluded_patterns,
    )
    head = runner.run(root, ("git", "rev-parse", "HEAD")).decode("ascii", errors="strict").strip()
    status = runner.run(root, ("git", "status", "--porcelain=v1", "--untracked-files=no"))
    cargo_version = runner.run(root, ("cargo", "-Vv")).decode("utf-8", errors="replace").strip()
    rustc_version = runner.run(root, ("rustc", "-Vv")).decode("utf-8", errors="replace").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", head):
        raise InventoryError("INVALID_SOURCE_IDENTITY", "git HEAD is not a full commit identity")
    lock_path = root / "Cargo.lock"
    lock_sha = _sha256(_read_bytes(root, lock_path, max_bytes=128 * 1024 * 1024)) if lock_path.is_file() else None
    semantic = {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "source_identity": {
            "git_head": head.lower(),
            "tracked_tree_clean": not bool(status),
            "cargo_lock_sha256": lock_sha,
            "cargo_version": cargo_version,
            "rustc_version": rustc_version,
        },
        "bounds": dataclasses.asdict(BOUNDS),
        "manifest_rows": manifests,
        "metadata_graphs": [
            {
                "graph_id": graph.graph_id,
                "manifest_path": graph.manifest_path,
                "workspace_root": graph.workspace_root,
                "workspace_members": graph.workspace_members,
                "workspace_default_members": graph.workspace_default_members,
            }
            for graph in sorted(graphs, key=lambda item: (item.manifest_path, item.graph_id))
        ],
        "packages": packages,
        "source_files": [dataclasses.asdict(item) for item in source_files],
        "findings": findings,
        "summary": {
            "tracked_manifests": len(manifests),
            "metadata_graphs": len(graphs),
            "packages": len(packages),
            "source_files": len(source_files),
            "findings": len(findings),
            "packages_without_consumer": sum(item["reachability"] == Reachability.NO_CONSUMER.value for item in packages),
            "packages_with_binary_entrypoint": sum(item["reachability"] == Reachability.BINARY_ENTRYPOINT.value for item in packages),
            "packages_requiring_review": sum(item["review_state"] == "REVIEW_REQUIRED" for item in packages),
            "complete_denominator": True,
            "proof_ceiling": "CRATE_REACHABILITY_AND_SOURCE_SHAPE_EVIDENCE_ONLY",
        },
    }
    semantic["aggregate_sha256"] = _sha256(_canonical_bytes(semantic))
    semantic["observation"] = {
        "duration_ms": int((time.monotonic() - started) * 1000),
        "note": "duration is excluded from aggregate_sha256 and is not support evidence",
    }
    return semantic


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        root = _root(args.repo_root)
        output = _safe_output(root, args.output)
        inventory = build_inventory(root)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as handle:
            handle.write(_canonical_bytes(inventory))
            handle.write(b"\n")
    except InventoryError as exc:
        print(
            json.dumps(
                {"status": "error", "code": exc.code, "detail": exc.detail},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "status": "ok",
                "output": str(output),
                "packages": inventory["summary"]["packages"],
                "manifests": inventory["summary"]["tracked_manifests"],
                "findings": inventory["summary"]["findings"],
                "aggregate_sha256": inventory["aggregate_sha256"],
                "proof_ceiling": inventory["summary"]["proof_ceiling"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
