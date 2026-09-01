#!/usr/bin/env python3
"""Independent closure audit for ELIOT's sharded normative documentation.

This is an audit harness, not a normative source or generator. It validates the
current checkout against Git history, generated indexes, repository routing,
and issue-state connections. It deliberately does not trust the compatibility
facades or a single generated projection as its only source of evidence.
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
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

PAIR_PATH = Path("docs/normative-pair.toml")
MANIFEST_PATHS = {
    "architecture": Path("docs/architecture/architecture/manifest.json"),
    "implementation": Path("docs/architecture/implementation/manifest.json"),
}
LEGACY_PATHS = {
    "architecture": Path("docs/architecture/ELIOT_ARCHITECTURE.md"),
    "implementation": Path("docs/architecture/ELIOT_IMPLEMENTATION.md"),
}
HANDLE_INDEX_PATH = Path("docs/architecture/handle-index.json")
ANCHOR_SOURCE_PATH = Path("docs/architecture/A16-01-decision-anchors.md")
ANCHOR_INDEX_PATH = Path("docs/architecture/decision-anchor-index.json")
ANCHOR_INDEX_MD_PATH = Path("docs/architecture/DECISION_ANCHOR_INDEX.md")
PAIR_SCHEMA = "eliot-normative-pair-v2-sharded"
MANIFEST_SCHEMA = "eliot-doc-shards-v1"
HANDLE_SCHEMA = "eliot-handle-index-v1"
ANCHOR_SCHEMA = "eliot-decision-anchor-index-v1"

TEXT_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cs", ".css", ".go", ".h", ".hpp", ".html",
    ".js", ".json", ".jsx", ".md", ".mjs", ".ps1", ".py", ".rs",
    ".sh", ".toml", ".ts", ".tsx", ".txt", ".xaml", ".xml", ".yaml",
    ".yml",
}
SKIP_PARTS = {
    ".git", ".eliot", ".eliot-docs", ".codebase-memory", "target",
    "dist", "node_modules", "bin", "obj", "__pycache__",
}
EXACT_HANDLE = re.compile(r"^(?:[AI]\d+(?:\.\d+)*|APPENDIX-[A-Z])$")
RANGE_HANDLE = re.compile(
    r"^((?:[AI]\d+(?:\.\d+)*|APPENDIX-[A-Z]))\.\."
    r"((?:[AI]\d+(?:\.\d+)*|APPENDIX-[A-Z]))$"
)
WILDCARD_HANDLE = re.compile(r"^([AI]\d+(?:\.\d+)*)\.\*$")
ANCHOR_ID = re.compile(r"\bARCH-[A-Z0-9]+(?:-[A-Z0-9]+)+\b")
CODE_SPAN = re.compile(r"`([^`\r\n]+)`")
PATH_HANDLE = re.compile(
    r"(?:ELIOT_(?:ARCHITECTURE|IMPLEMENTATION)\.md|docs/architecture/[^\s:`]+)"
    r"[:#]((?:[AI]\d+(?:\.\d+)*|APPENDIX-[A-Z]))\b"
)
BARE_HANDLE = re.compile(r"(?<![A-Za-z0-9_.-])(?:[AI]\d+(?:\.\d+)+|APPENDIX-[A-Z])(?![A-Za-z0-9_.-])")
NEGATIVE_FIXTURE_HINTS = (
    "fake", "unknown", "invalid", "missing", "reject", "negative fixture",
    "self-test", "self_test", "must fail", "nonexistent",
)


class AuditFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class Finding:
    severity: str
    finding_id: str
    message: str
    path: str | None = None
    line: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "severity": self.severity,
            "id": self.finding_id,
            "message": self.message,
        }
        if self.path is not None:
            value["path"] = self.path
        if self.line is not None:
            value["line"] = self.line
        if self.detail:
            value["detail"] = self.detail
        return value


@dataclass
class Audit:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)

    def add(
        self,
        severity: str,
        finding_id: str,
        message: str,
        *,
        path: str | Path | None = None,
        line: int | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        normalized = None
        if path is not None:
            candidate = Path(path)
            try:
                normalized = candidate.resolve().relative_to(self.root).as_posix()
            except (OSError, ValueError):
                normalized = candidate.as_posix()
        self.findings.append(
            Finding(severity, finding_id, message, normalized, line, detail or {})
        )

    def error(self, finding_id: str, message: str, **kwargs: Any) -> None:
        self.add("error", finding_id, message, **kwargs)

    def warning(self, finding_id: str, message: str, **kwargs: Any) -> None:
        self.add("warning", finding_id, message, **kwargs)

    def info(self, finding_id: str, message: str, **kwargs: Any) -> None:
        self.add("info", finding_id, message, **kwargs)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pair_key(architecture_hash: str, implementation_hash: str) -> str:
    payload = (
        b"eliot-normative-pair-v1\x00"
        + architecture_hash.encode("ascii")
        + b"\x00"
        + implementation_hash.encode("ascii")
        + b"\x00"
    )
    return "sha256:" + sha256(payload)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AuditFailure(f"JSON root is not an object: {path}")
    return value


def read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        value = tomllib.load(stream)
    if not isinstance(value, dict):
        raise AuditFailure(f"TOML root is not a table: {path}")
    return value


def git(root: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise AuditFailure(f"git {' '.join(args)} failed: {stderr}")
    return completed.stdout


def git_blob_id(root: Path, data: bytes) -> str:
    return git(root, "hash-object", "--stdin", input_bytes=data).decode("ascii").strip()


def reverse_rewrites(
    rendered: str,
    raw_records: Any,
    *,
    path: str,
    audit: Audit,
) -> str:
    if raw_records is None:
        raw_records = []
    if not isinstance(raw_records, list):
        audit.error("DOC-REWRITE-SHAPE", "navigation_rewrites is not an array", path=path)
        return rendered

    records: list[tuple[int, int, str, str]] = []
    for index, raw in enumerate(raw_records):
        if not isinstance(raw, dict):
            audit.error(
                "DOC-REWRITE-SHAPE",
                f"rewrite record {index} is not an object",
                path=path,
            )
            continue
        try:
            start = int(raw["rendered_start"])
            end = int(raw["rendered_end"])
            original = str(raw["original"])
            replacement = str(raw["replacement"])
        except (KeyError, TypeError, ValueError) as exc:
            audit.error(
                "DOC-REWRITE-FIELDS",
                f"rewrite record {index} has invalid fields: {exc}",
                path=path,
            )
            continue
        records.append((start, end, original, replacement))

    previous_end = -1
    for start, end, _original, replacement in sorted(records):
        if start < 0 or end < start or end > len(rendered):
            audit.error(
                "DOC-REWRITE-RANGE",
                f"invalid rewrite range {start}:{end}",
                path=path,
            )
            continue
        if start < previous_end:
            audit.error("DOC-REWRITE-OVERLAP", "rewrite ranges overlap", path=path)
        previous_end = max(previous_end, end)
        if rendered[start:end] != replacement:
            audit.error(
                "DOC-REWRITE-TARGET",
                f"rewrite target differs at {start}:{end}",
                path=path,
                detail={"expected": replacement, "actual": rendered[start:end]},
            )

    result = rendered
    for start, end, original, replacement in sorted(records, reverse=True):
        if 0 <= start <= end <= len(result) and result[start:end] == replacement:
            result = result[:start] + original + result[end:]
    return result


def validate_pair(audit: Audit) -> dict[str, Any]:
    path = audit.root / PAIR_PATH
    try:
        pair = read_toml(path)
    except (OSError, tomllib.TOMLDecodeError, AuditFailure) as exc:
        audit.error("DOC-PAIR-READ", str(exc), path=path)
        return {}

    if pair.get("schema_version") != PAIR_SCHEMA:
        audit.error(
            "DOC-PAIR-SCHEMA",
            f"expected {PAIR_SCHEMA}, found {pair.get('schema_version')!r}",
            path=path,
        )
    if pair.get("status") != "accepted":
        audit.error("DOC-PAIR-STATUS", "normative pair is not accepted", path=path)
    if pair.get("repository_authority_branch") != "main":
        audit.error("DOC-PAIR-AUTHORITY", "authority branch is not main", path=path)

    architecture_hash = str(pair.get("architecture_sha256", ""))
    implementation_hash = str(pair.get("implementation_sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", architecture_hash):
        audit.error("DOC-PAIR-HASH", "architecture_sha256 is invalid", path=path)
    if not re.fullmatch(r"[0-9a-f]{64}", implementation_hash):
        audit.error("DOC-PAIR-HASH", "implementation_sha256 is invalid", path=path)
    if re.fullmatch(r"[0-9a-f]{64}", architecture_hash) and re.fullmatch(
        r"[0-9a-f]{64}", implementation_hash
    ):
        expected = pair_key(architecture_hash, implementation_hash)
        if pair.get("pair_key") != expected:
            audit.error(
                "DOC-PAIR-KEY",
                "pair_key does not match the two adopted document digests",
                path=path,
                detail={"expected": expected, "actual": pair.get("pair_key")},
            )
    audit.evidence["pair"] = pair
    return pair


def validate_manifest(
    audit: Audit,
    key: str,
    manifest_path: Path,
) -> tuple[dict[str, Any], bytes]:
    path = audit.root / manifest_path
    try:
        manifest = read_json(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, AuditFailure) as exc:
        audit.error("DOC-MANIFEST-READ", str(exc), path=path)
        return {}, b""

    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        audit.error("DOC-MANIFEST-SCHEMA", "manifest schema mismatch", path=path)
    if manifest.get("source_key") != key:
        audit.error("DOC-MANIFEST-SOURCE", "manifest source_key mismatch", path=path)

    fragments = manifest.get("fragments")
    if not isinstance(fragments, list) or not fragments:
        audit.error("DOC-MANIFEST-FRAGMENTS", "manifest has no fragment array", path=path)
        return manifest, b""
    if manifest.get("fragment_count") != len(fragments):
        audit.error(
            "DOC-MANIFEST-COUNT",
            "fragment_count differs from the array length",
            path=path,
        )

    chunks: list[str] = []
    expected_order = 0
    expected_start = 0
    seen_paths: set[str] = set()
    fragment_records: list[dict[str, Any]] = []
    for raw in fragments:
        if not isinstance(raw, dict):
            audit.error("DOC-FRAGMENT-SHAPE", "fragment entry is not an object", path=path)
            continue
        fragment_records.append(raw)
        fragment_path = str(raw.get("path", ""))
        order = int(raw.get("order", -1))
        start = int(raw.get("source_start_char", -1))
        end = int(raw.get("source_end_char", -1))
        if order != expected_order:
            audit.error(
                "DOC-FRAGMENT-ORDER",
                f"expected order {expected_order}, found {order}",
                path=fragment_path or path,
            )
        expected_order += 1
        if start != expected_start or end < start:
            audit.error(
                "DOC-FRAGMENT-RANGE",
                f"expected source start {expected_start}, found {start}:{end}",
                path=fragment_path or path,
            )
        expected_start = max(expected_start, end)
        if not fragment_path or fragment_path in seen_paths:
            audit.error(
                "DOC-FRAGMENT-PATH",
                "fragment path is blank or duplicated",
                path=fragment_path or path,
            )
        seen_paths.add(fragment_path)

        target = audit.root / fragment_path
        if not target.is_file() or target.is_symlink():
            audit.error(
                "DOC-FRAGMENT-MISSING",
                "fragment is missing or symlinked",
                path=target,
            )
            continue
        rendered_bytes = target.read_bytes()
        expected_rendered_hash = str(raw.get("rendered_sha256", ""))
        expected_rendered_bytes = int(raw.get("rendered_bytes", -1))
        if sha256(rendered_bytes) != expected_rendered_hash:
            audit.error("DOC-FRAGMENT-RENDERED-HASH", "rendered hash mismatch", path=target)
        if len(rendered_bytes) != expected_rendered_bytes:
            audit.error("DOC-FRAGMENT-RENDERED-BYTES", "rendered byte count mismatch", path=target)
        try:
            rendered = rendered_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            audit.error("DOC-FRAGMENT-UTF8", str(exc), path=target)
            continue
        source = reverse_rewrites(
            rendered,
            raw.get("navigation_rewrites"),
            path=fragment_path,
            audit=audit,
        )
        source_bytes = source.encode("utf-8")
        if sha256(source_bytes) != str(raw.get("source_sha256", "")):
            audit.error("DOC-FRAGMENT-SOURCE-HASH", "source hash mismatch", path=target)
        if len(source_bytes) != int(raw.get("source_bytes", -1)):
            audit.error("DOC-FRAGMENT-SOURCE-BYTES", "source byte count mismatch", path=target)
        if len(source) != end - start:
            audit.error(
                "DOC-FRAGMENT-SOURCE-CHARS",
                "source character length differs from manifest range",
                path=target,
                detail={"characters": len(source), "range": end - start},
            )
        chunks.append(source)

    text = "".join(chunks)
    data = text.encode("utf-8")
    if expected_start != len(text):
        audit.error(
            "DOC-MANIFEST-FINAL-RANGE",
            "final source range differs from reconstructed character count",
            path=path,
        )
    checks = {
        "source_sha256": sha256(data),
        "source_bytes": len(data),
        "source_characters": len(text),
        "source_lines": text.count("\n") + (0 if text.endswith("\n") else 1),
    }
    for field_name, actual in checks.items():
        if manifest.get(field_name) != actual:
            audit.error(
                "DOC-MANIFEST-RECONSTRUCTION",
                f"{field_name} mismatch: expected {manifest.get(field_name)!r}, actual {actual!r}",
                path=path,
            )

    for raw in fragment_records:
        start = int(raw.get("source_start_char", 0))
        end = int(raw.get("source_end_char", 0))
        expected_start_line = text.count("\n", 0, start) + 1
        expected_end_line = text.count("\n", 0, end) + 1
        if int(raw.get("source_start_line", -1)) != expected_start_line:
            audit.error(
                "DOC-FRAGMENT-START-LINE",
                "source_start_line does not match reconstructed source",
                path=str(raw.get("path", path)),
            )
        if int(raw.get("source_end_line", -1)) != expected_end_line:
            audit.error(
                "DOC-FRAGMENT-END-LINE",
                "source_end_line does not match reconstructed source",
                path=str(raw.get("path", path)),
            )

    audit.metrics[f"{key}_fragments"] = len(fragments)
    audit.metrics[f"{key}_bytes"] = len(data)
    audit.metrics[f"{key}_sha256"] = sha256(data)
    return manifest, data


def history_matches(root: Path, path: Path, expected_sha256: str) -> list[dict[str, str]]:
    commits = git(root, "log", "--format=%H", "--all", "--", path.as_posix()).decode(
        "ascii", errors="replace"
    ).splitlines()
    matches: list[dict[str, str]] = []
    for commit in commits:
        completed = subprocess.run(
            ["git", "-C", str(root), "show", f"{commit}:{path.as_posix()}"],
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            continue
        if sha256(completed.stdout) == expected_sha256:
            matches.append(
                {
                    "commit": commit,
                    "blob": git(root, "rev-parse", f"{commit}:{path.as_posix()}")
                    .decode("ascii")
                    .strip(),
                }
            )
    return matches


def validate_originals(
    audit: Audit,
    reconstructed: dict[str, bytes],
) -> None:
    matches_by_key: dict[str, list[dict[str, str]]] = {}
    for key, data in reconstructed.items():
        if not data:
            continue
        path = LEGACY_PATHS[key]
        matches = history_matches(audit.root, path, sha256(data))
        matches_by_key[key] = matches
        if not matches:
            audit.error(
                "DOC-ORIGINAL-NOT-FOUND",
                "no Git-history version of the monolith matches reconstructed bytes",
                path=path,
                detail={"reconstructed_sha256": sha256(data)},
            )
            continue
        reconstructed_blob = git_blob_id(audit.root, data)
        if reconstructed_blob not in {record["blob"] for record in matches}:
            audit.error(
                "DOC-ORIGINAL-BLOB",
                "reconstructed Git blob ID differs from all matching history blobs",
                path=path,
            )
        audit.evidence[f"{key}_original_matches"] = matches
        audit.evidence[f"{key}_reconstructed_blob"] = reconstructed_blob

    if set(matches_by_key) == {"architecture", "implementation"}:
        architecture_commits = {item["commit"] for item in matches_by_key["architecture"]}
        implementation_commits = {item["commit"] for item in matches_by_key["implementation"]}
        common = sorted(architecture_commits & implementation_commits)
        if not common:
            audit.error(
                "DOC-ORIGINAL-PAIR-COMMIT",
                "Architecture and Implementation do not share a Git commit with both adopted byte streams",
            )
        else:
            audit.evidence["common_original_commits"] = common
            audit.metrics["common_original_commit_count"] = len(common)


def expected_handle_index(manifests: Iterable[dict[str, Any]], audit: Audit) -> dict[str, Any]:
    handles: dict[str, dict[str, Any]] = {}
    headings: list[dict[str, Any]] = []
    for manifest in manifests:
        for fragment in manifest.get("fragments", []):
            if not isinstance(fragment, dict):
                continue
            for heading in fragment.get("headings", []):
                if not isinstance(heading, dict):
                    audit.error(
                        "DOC-HEADING-SHAPE",
                        "manifest heading is not an object",
                        path=str(fragment.get("path", "")),
                    )
                    continue
                record = {
                    "source": manifest.get("source_key"),
                    "title": heading.get("title"),
                    "level": heading.get("level"),
                    "path": fragment.get("path"),
                    "anchor": heading.get("fragment_anchor"),
                    "source_anchor": heading.get("source_anchor"),
                    "source_line": heading.get("source_line"),
                    "fragment_sha256": fragment.get("rendered_sha256"),
                    "fragment_bytes": fragment.get("rendered_bytes"),
                }
                headings.append(record)
                handle = heading.get("handle")
                if handle:
                    handle = str(handle)
                    if handle in handles:
                        audit.error(
                            "DOC-HANDLE-DUPLICATE",
                            f"duplicate normative handle {handle}",
                            path=str(fragment.get("path", "")),
                        )
                    handles[handle] = record
    return {"schema_version": HANDLE_SCHEMA, "handles": handles, "headings": headings}


def validate_handle_index(
    audit: Audit,
    manifests: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    path = audit.root / HANDLE_INDEX_PATH
    try:
        actual = read_json(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, AuditFailure) as exc:
        audit.error("DOC-HANDLE-INDEX-READ", str(exc), path=path)
        return {}
    expected = expected_handle_index(manifests.values(), audit)
    if actual != expected:
        audit.error(
            "DOC-HANDLE-INDEX-DRIFT",
            "handle-index.json differs from the exact two shard manifests",
            path=path,
        )
    handles = actual.get("handles")
    if not isinstance(handles, dict) or not handles:
        audit.error("DOC-HANDLE-INDEX-EMPTY", "handle index has no handles", path=path)
        return {}
    audit.metrics["numeric_handles"] = len(handles)
    return handles


def parse_decision_anchors(audit: Audit) -> dict[str, dict[str, Any]]:
    path = audit.root / ANCHOR_SOURCE_PATH
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        audit.error("DOC-ANCHOR-SOURCE-READ", str(exc), path=path)
        return {}

    in_section = False
    in_table = False
    anchors: dict[str, dict[str, Any]] = {}
    row_pattern = re.compile(
        r"^\|\s*`(ARCH-[A-Z0-9]+(?:-[A-Z0-9]+)+)`\s*\|\s*"
        r"(Invariant|Contract)\s*\|\s*(.*?)\s*\|\s*$"
    )
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped == "## A16.1. Decision Anchors":
            if in_section:
                audit.error("DOC-ANCHOR-HEADING-DUPLICATE", "duplicate A16.1 heading", path=path, line=line_number)
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if not in_section:
            continue
        if stripped == "| ID | Class | Decision |":
            in_table = True
            continue
        if not in_table or not stripped.startswith("|") or re.fullmatch(r"\|[-|\s]+\|", stripped):
            continue
        match = row_pattern.match(line)
        if not match:
            audit.error(
                "DOC-ANCHOR-ROW",
                "malformed Decision Anchor table row",
                path=path,
                line=line_number,
            )
            continue
        anchor, anchor_class, decision = match.groups()
        if anchor in anchors:
            audit.error(
                "DOC-ANCHOR-DUPLICATE",
                f"duplicate Decision Anchor {anchor}",
                path=path,
                line=line_number,
            )
            continue
        if not decision.strip():
            audit.error(
                "DOC-ANCHOR-BLANK",
                f"blank Decision Anchor decision for {anchor}",
                path=path,
                line=line_number,
            )
        anchors[anchor] = {
            "class": anchor_class,
            "decision": decision.strip(),
            "fragment_line": line_number,
        }
    if not in_section or not in_table or not anchors:
        audit.error("DOC-ANCHOR-TABLE", "A16.1 Decision Anchor table is missing or empty", path=path)
    audit.metrics["decision_anchors"] = len(anchors)
    return anchors


def validate_anchor_index(
    audit: Audit,
    anchors: dict[str, dict[str, Any]],
    pair: dict[str, Any],
    handles: dict[str, dict[str, Any]],
) -> None:
    json_path = audit.root / ANCHOR_INDEX_PATH
    md_path = audit.root / ANCHOR_INDEX_MD_PATH
    if not json_path.is_file():
        audit.error(
            "DOC-ANCHOR-INDEX-MISSING",
            "Decision Anchors have no generated machine-readable index",
            path=json_path,
        )
        return
    try:
        value = read_json(json_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, AuditFailure) as exc:
        audit.error("DOC-ANCHOR-INDEX-READ", str(exc), path=json_path)
        return
    if value.get("schema_version") != ANCHOR_SCHEMA:
        audit.error("DOC-ANCHOR-INDEX-SCHEMA", "Decision Anchor index schema mismatch", path=json_path)
    if value.get("normative_pair_key") != pair.get("pair_key"):
        audit.error("DOC-ANCHOR-INDEX-PAIR", "Decision Anchor index is not bound to the current pair", path=json_path)
    indexed = value.get("anchors")
    if not isinstance(indexed, dict) or set(indexed) != set(anchors):
        audit.error("DOC-ANCHOR-INDEX-DRIFT", "Decision Anchor index IDs differ from A16.1", path=json_path)
    else:
        for anchor_id, record in anchors.items():
            indexed_record = indexed.get(anchor_id)
            if not isinstance(indexed_record, dict):
                continue
            if indexed_record.get("class") != record["class"] or indexed_record.get("decision") != record["decision"]:
                audit.error(
                    "DOC-ANCHOR-INDEX-DRIFT",
                    f"Decision Anchor index content differs for {anchor_id}",
                    path=json_path,
                )
    section = handles.get("A16.1")
    source = value.get("source")
    if not isinstance(section, dict) or not isinstance(source, dict):
        audit.error("DOC-ANCHOR-INDEX-SOURCE", "A16.1 source binding is missing", path=json_path)
    else:
        source_path = audit.root / ANCHOR_SOURCE_PATH
        data = source_path.read_bytes()
        expected_source = {
            "path": ANCHOR_SOURCE_PATH.as_posix(),
            "section_handle": "A16.1",
            "anchor": section.get("anchor"),
            "sha256": sha256(data),
            "git_blob_sha1": git_blob_id(audit.root, data),
            "bytes": len(data),
        }
        if source != expected_source:
            audit.error("DOC-ANCHOR-INDEX-SOURCE", "Decision Anchor source binding differs from A16.1", path=json_path)
    if not md_path.is_file():
        audit.warning("DOC-ANCHOR-MD-MISSING", "human-readable Decision Anchor index is missing", path=md_path)


def tracked_text_files(root: Path) -> list[Path]:
    raw = git(root, "ls-files", "-z")
    files: list[Path] = []
    for item in raw.split(b"\x00"):
        if not item:
            continue
        relative = Path(item.decode("utf-8"))
        if any(part in SKIP_PARTS for part in relative.parts):
            continue
        target = root / relative
        if not target.is_file() or target.is_symlink():
            continue
        if target.suffix.casefold() in TEXT_SUFFIXES or target.name in {"Justfile", "Dockerfile", "LICENSE"}:
            files.append(target)
    return files


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def validate_selector(
    selector: str,
    handles: set[str],
) -> tuple[bool, str | None]:
    selector = selector.strip()
    if EXACT_HANDLE.fullmatch(selector):
        return selector in handles, None if selector in handles else f"unknown exact handle {selector}"
    range_match = RANGE_HANDLE.fullmatch(selector)
    if range_match:
        start, end = range_match.groups()
        missing = [value for value in (start, end) if value not in handles]
        if missing:
            return False, f"unknown range endpoint(s): {', '.join(missing)}"
        if start[0] != end[0]:
            return False, "cross-book range"
        return True, None
    wildcard_match = WILDCARD_HANDLE.fullmatch(selector)
    if wildcard_match:
        prefix = wildcard_match.group(1)
        if any(value == prefix or value.startswith(prefix + ".") for value in handles):
            return True, None
        return False, f"wildcard resolves to no handle: {selector}"
    return True, None


def likely_negative_fixture(path: Path, line: str) -> bool:
    folded = line.casefold()
    return "scripts" in path.parts and any(hint in folded for hint in NEGATIVE_FIXTURE_HINTS)


def scan_references(
    audit: Audit,
    handles: dict[str, dict[str, Any]],
    anchors: dict[str, dict[str, Any]],
) -> None:
    known_handles = set(handles)
    known_anchors = set(anchors)
    strict_selectors = 0
    bare_candidates = 0
    anchor_refs = 0
    legacy_hits: list[dict[str, Any]] = []

    for path in tracked_text_files(audit.root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        relative = path.relative_to(audit.root).as_posix()
        lines = text.splitlines()

        for match in CODE_SPAN.finditer(text):
            content = match.group(1).strip()
            candidates = [content]
            if "," in content or ";" in content:
                candidates.extend(part.strip() for part in re.split(r"[,;]", content))
            for candidate in candidates:
                if not (
                    EXACT_HANDLE.fullmatch(candidate)
                    or RANGE_HANDLE.fullmatch(candidate)
                    or WILDCARD_HANDLE.fullmatch(candidate)
                ):
                    continue
                strict_selectors += 1
                valid, reason = validate_selector(candidate, known_handles)
                if not valid:
                    current_line = lines[line_number(text, match.start()) - 1] if lines else ""
                    if likely_negative_fixture(path, current_line):
                        audit.info(
                            "DOC-HANDLE-NEGATIVE-FIXTURE",
                            reason or "intentional invalid handle fixture",
                            path=path,
                            line=line_number(text, match.start()),
                            detail={"selector": candidate},
                        )
                    else:
                        audit.error(
                            "DOC-HANDLE-UNKNOWN",
                            reason or "unknown handle selector",
                            path=path,
                            line=line_number(text, match.start()),
                            detail={"selector": candidate},
                        )

        for match in PATH_HANDLE.finditer(text):
            selector = match.group(1)
            strict_selectors += 1
            if selector not in known_handles:
                audit.error(
                    "DOC-HANDLE-UNKNOWN",
                    f"path-qualified reference uses unknown handle {selector}",
                    path=path,
                    line=line_number(text, match.start()),
                )

        for match in BARE_HANDLE.finditer(text):
            selector = match.group(0)
            bare_candidates += 1
            if selector in known_handles:
                continue
            current_line = lines[line_number(text, match.start()) - 1] if lines else ""
            if likely_negative_fixture(path, current_line):
                continue
            context_folded = current_line.casefold()
            if any(
                token in context_folded
                for token in (
                    "architecture", "implementation", "normative", "handle",
                    "docs/architecture", "eliot_", "contract", "source",
                )
            ):
                audit.warning(
                    "DOC-HANDLE-BARE-UNKNOWN",
                    f"possible unresolved bare normative handle {selector}",
                    path=path,
                    line=line_number(text, match.start()),
                    detail={"line": current_line.strip()},
                )

        for match in ANCHOR_ID.finditer(text):
            anchor_refs += 1
            anchor = match.group(0)
            if anchor in known_anchors:
                continue
            current_line = lines[line_number(text, match.start()) - 1] if lines else ""
            if likely_negative_fixture(path, current_line):
                audit.info(
                    "DOC-ANCHOR-NEGATIVE-FIXTURE",
                    f"intentional unknown Decision Anchor fixture {anchor}",
                    path=path,
                    line=line_number(text, match.start()),
                )
            else:
                audit.error(
                    "DOC-ANCHOR-UNKNOWN",
                    f"unknown Decision Anchor {anchor}",
                    path=path,
                    line=line_number(text, match.start()),
                    detail={"line": current_line.strip()},
                )

        for pattern in (
            "docs/normative/",
            "ELIOT_ARCHITECTURE_ENGLISH_FINAL_2026-08-28.md",
            "ELIOT_IMPLEMENTATION_ENGLISH_FINAL_2026-08-28.md",
        ):
            start = 0
            while True:
                offset = text.find(pattern, start)
                if offset < 0:
                    break
                legacy_hits.append(
                    {
                        "path": relative,
                        "line": line_number(text, offset),
                        "pattern": pattern,
                    }
                )
                start = offset + len(pattern)

    for hit in legacy_hits:
        path = Path(hit["path"])
        if path.as_posix() in {
            ".github/workflows/repository-policy.yml",
            "scripts/docs_closure_audit.py",
        }:
            continue
        audit.error(
            "DOC-RETIRED-REFERENCE",
            f"retired authority reference remains: {hit['pattern']}",
            path=audit.root / path,
            line=int(hit["line"]),
        )

    audit.metrics["strict_handle_selectors_scanned"] = strict_selectors
    audit.metrics["bare_handle_candidates_scanned"] = bare_candidates
    audit.metrics["decision_anchor_references_scanned"] = anchor_refs


def validate_fragment_inventory(
    audit: Audit,
    manifests: dict[str, dict[str, Any]],
) -> None:
    expected: set[str] = set()
    for manifest in manifests.values():
        for fragment in manifest.get("fragments", []):
            if isinstance(fragment, dict):
                expected.add(str(fragment.get("path", "")))
    tracked = {
        path.relative_to(audit.root).as_posix()
        for path in (audit.root / "docs/architecture").glob("*.md")
        if re.fullmatch(r"(?:A|I)(?:-|\d).+\.md", path.name)
        and path.name not in {"ELIOT_ARCHITECTURE.md", "ELIOT_IMPLEMENTATION.md"}
    }
    missing = sorted(expected - tracked)
    orphaned = sorted(tracked - expected)
    for relative in missing:
        audit.error("DOC-FRAGMENT-INVENTORY", "manifest fragment is absent from inventory", path=audit.root / relative)
    for relative in orphaned:
        audit.error("DOC-FRAGMENT-ORPHAN", "normative-looking fragment is absent from both manifests", path=audit.root / relative)
    audit.metrics["manifest_fragment_paths"] = len(expected)
    audit.metrics["tracked_fragment_paths"] = len(tracked)


def validate_gate_wiring(audit: Audit) -> None:
    justfile = audit.root / "Justfile"
    verify = audit.root / "scripts/verify.ps1"
    readme = audit.root / "scripts/README.md"
    try:
        just_text = justfile.read_text(encoding="utf-8")
        verify_text = verify.read_text(encoding="utf-8")
        readme_text = readme.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        audit.error("DOC-GATE-READ", str(exc))
        return

    quick_match = re.search(r"(?m)^quick:\s*(.+)$", just_text)
    quick = quick_match.group(1) if quick_match else ""
    for target in ("doc-code-conformance-self-test", "doc-code-conformance"):
        if target not in quick:
            audit.error(
                "DOC-GATE-JUST",
                f"just quick does not depend on {target}",
                path=justfile,
            )
    for marker in ("doc-code-conformance-self-test", "doc-code-conformance"):
        if marker not in verify_text:
            audit.error(
                "DOC-GATE-POWERSHELL",
                f"scripts/verify.ps1 does not invoke {marker}",
                path=verify,
            )
    if "verify-doc-code-conformance.py" not in readme_text:
        audit.error(
            "DOC-GATE-README",
            "scripts/README.md does not document the conformance verifier",
            path=readme,
        )


def github_issue(
    repository: str,
    number: int,
    token: str,
) -> dict[str, Any]:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/issues/{number}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "eliot-docs-closure-audit",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise AuditFailure(f"issue #{number} response is not an object")
    return value


def validate_workstream_issue_states(
    audit: Audit,
    repository: str | None,
    token: str | None,
) -> None:
    path = audit.root / "workstreams/ACTIVE.toml"
    try:
        active = read_toml(path)
    except (OSError, tomllib.TOMLDecodeError, AuditFailure) as exc:
        audit.error("DOC-WORKSTREAM-READ", str(exc), path=path)
        return
    workstreams = active.get("workstream")
    if not isinstance(workstreams, list):
        audit.error("DOC-WORKSTREAM-SHAPE", "ACTIVE.toml has no [[workstream]] array", path=path)
        return

    semantics = {
        "issue_refs": "open",
        "confirmed_open_defect_refs": "open",
        "cross_cutting_follow_up_issue_refs": "open",
        "merged_source_fix_refs": "closed",
        "completed_baseline_issue_refs": "closed",
    }
    references: dict[int, list[tuple[str, str, str]]] = {}
    for raw in workstreams:
        if not isinstance(raw, dict):
            continue
        workstream_id = str(raw.get("id", "<unknown>"))
        for field_name, expected_state in semantics.items():
            values = raw.get(field_name, [])
            if values is None:
                continue
            if not isinstance(values, list) or not all(isinstance(value, int) for value in values):
                audit.error(
                    "DOC-WORKSTREAM-REF-SHAPE",
                    f"{workstream_id}.{field_name} must be an integer array",
                    path=path,
                )
                continue
            if values != sorted(set(values)):
                audit.error(
                    "DOC-WORKSTREAM-REF-ORDER",
                    f"{workstream_id}.{field_name} is not sorted and duplicate-free",
                    path=path,
                )
            for number in values:
                references.setdefault(number, []).append((workstream_id, field_name, expected_state))

    if not repository or not token:
        audit.warning(
            "DOC-WORKSTREAM-STATE-UNVERIFIED",
            "GitHub repository/token unavailable; issue-state parity was not checked",
            path=path,
        )
        return

    checked = 0
    for number, bindings in sorted(references.items()):
        try:
            issue = github_issue(repository, number, token)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, AuditFailure) as exc:
            audit.error(
                "DOC-WORKSTREAM-ISSUE-READ",
                f"cannot read issue #{number}: {exc}",
                path=path,
            )
            continue
        checked += 1
        if "pull_request" in issue:
            audit.error(
                "DOC-WORKSTREAM-PR-AS-ISSUE",
                f"#{number} is a pull request, not an owning issue",
                path=path,
            )
        state = str(issue.get("state", ""))
        for workstream_id, field_name, expected_state in bindings:
            if state != expected_state:
                audit.error(
                    "DOC-WORKSTREAM-ISSUE-STATE",
                    f"{workstream_id}.{field_name} lists #{number} as {expected_state}, GitHub reports {state}",
                    path=path,
                    detail={"issue": number, "title": issue.get("title")},
                )
    audit.metrics["workstream_issues_checked"] = checked


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# ELIOT documentation closure audit",
        "",
        f"- Commit: `{payload['commit']}`",
        f"- Errors: **{payload['summary']['errors']}**",
        f"- Warnings: **{payload['summary']['warnings']}**",
        f"- Informational findings: **{payload['summary']['info']}**",
        "",
        "## Reconstruction and identity",
        "",
    ]
    evidence = payload.get("evidence", {})
    for key in ("architecture", "implementation"):
        matches = evidence.get(f"{key}_original_matches", [])
        lines.append(
            f"- {key}: reconstructed blob `{evidence.get(f'{key}_reconstructed_blob', 'UNKNOWN')}`; "
            f"matching historical versions: {len(matches)}."
        )
    common = evidence.get("common_original_commits", [])
    lines.append(f"- Common exact original commits: {', '.join(f'`{value}`' for value in common) or 'none' }.")
    lines += ["", "## Metrics", "", "| Metric | Value |", "|---|---:|"]
    for key, value in sorted(payload.get("metrics", {}).items()):
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, sort_keys=True)
        lines.append(f"| `{key}` | {value} |")
    lines += ["", "## Findings", ""]
    if not payload["findings"]:
        lines.append("No findings.")
    else:
        for finding in payload["findings"]:
            location = ""
            if finding.get("path"):
                location = f" — `{finding['path']}"
                if finding.get("line"):
                    location += f":{finding['line']}"
                location += "`"
            lines.append(
                f"- **{finding['severity'].upper()} {finding['id']}**: "
                f"{finding['message']}{location}"
            )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--report-dir", type=Path, default=Path(".eliot/docs-closure-audit"))
    parser.add_argument("--github-repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--github-token-env", default="GITHUB_TOKEN")
    parser.add_argument("--warnings-as-errors", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = args.root.resolve()
    audit = Audit(root)

    try:
        commit = git(root, "rev-parse", "HEAD").decode("ascii").strip()
    except AuditFailure as exc:
        print(f"DOC_CLOSURE_AUDIT_FAIL: {exc}", file=sys.stderr)
        return 2

    pair = validate_pair(audit)
    manifests: dict[str, dict[str, Any]] = {}
    reconstructed: dict[str, bytes] = {}
    for key, manifest_path in MANIFEST_PATHS.items():
        manifest, data = validate_manifest(audit, key, manifest_path)
        manifests[key] = manifest
        reconstructed[key] = data
        if pair:
            if pair.get(f"{key}_path") != manifest_path.as_posix():
                audit.error(
                    "DOC-PAIR-MANIFEST-PATH",
                    f"{key}_path does not identify the canonical manifest",
                    path=PAIR_PATH,
                )
            if manifest and pair.get(f"{key}_sha256") != manifest.get("source_sha256"):
                audit.error(
                    "DOC-PAIR-MANIFEST-HASH",
                    f"{key} pair digest differs from the manifest source digest",
                    path=PAIR_PATH,
                )

    validate_originals(audit, reconstructed)
    handles = validate_handle_index(audit, manifests)
    anchors = parse_decision_anchors(audit)
    validate_anchor_index(audit, anchors, pair, handles)
    validate_fragment_inventory(audit, manifests)
    scan_references(audit, handles, anchors)
    validate_gate_wiring(audit)
    validate_workstream_issue_states(
        audit,
        args.github_repository,
        os.environ.get(args.github_token_env),
    )

    severity_order = {"error": 0, "warning": 1, "info": 2}
    audit.findings.sort(
        key=lambda item: (
            severity_order.get(item.severity, 9),
            item.finding_id,
            item.path or "",
            item.line or 0,
            item.message,
        )
    )
    errors = sum(item.severity == "error" for item in audit.findings)
    warnings = sum(item.severity == "warning" for item in audit.findings)
    info = sum(item.severity == "info" for item in audit.findings)
    payload = {
        "schema_version": "eliot-doc-closure-audit-v1",
        "commit": commit,
        "summary": {"errors": errors, "warnings": warnings, "info": info},
        "metrics": audit.metrics,
        "evidence": audit.evidence,
        "findings": [item.as_dict() for item in audit.findings],
    }

    report_dir = args.report_dir if args.report_dir.is_absolute() else root / args.report_dir
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "audit.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (report_dir / "audit.md").write_text(render_markdown(payload), encoding="utf-8")

    print(
        "DOC_CLOSURE_AUDIT: "
        f"errors={errors} warnings={warnings} info={info} "
        f"report={report_dir.relative_to(root).as_posix()}"
    )
    if errors or (args.warnings_as_errors and warnings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
