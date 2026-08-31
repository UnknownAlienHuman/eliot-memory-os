#!/usr/bin/env python3
"""Detect drift between operational documentation and current repository source."""

from __future__ import annotations

import argparse
import fnmatch
import html
import json
import re
import sys
import tempfile
import textwrap
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

SCHEMA = "eliot-doc-code-conformance-v1"
ROUTING_START = "<!-- eliot-doc-routing:start -->"
ROUTING_END = "<!-- eliot-doc-routing:end -->"
SKIP = {
    ".git",
    ".idea",
    ".vscode",
    ".eliot",
    ".codebase-memory",
    "__pycache__",
    "target",
    "dist",
    "node_modules",
    "obj",
}
DOC_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?P<path>docs/[A-Za-z0-9_.\-/]+\."
    r"(?:md|markdown|toml|json|ya?ml|txt))"
    r"(?P<handle>:(?:[AI]\d+(?:\.\d+)*|APPENDIX-[A-Z]))?"
)


class AuditError(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class Finding:
    finding_id: str
    path: str
    line: int
    message: str


def norm(value: str) -> str:
    value = re.sub(r"/+", "/", value.strip().replace("\\", "/"))
    while value.startswith("./"):
        value = value[2:]
    if value in {"", "."}:
        return "."
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or re.match(r"^[A-Za-z]:", value):
        raise AuditError(f"path must be repository-relative: {value!r}")
    return path.as_posix()


def rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise AuditError(f"path escapes repository root: {path}") from exc


def text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise AuditError(f"cannot read UTF-8 text {path}: {exc}") from exc


def toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise AuditError(f"cannot read TOML {path}: {exc}") from exc


def json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(text(path))
    except json.JSONDecodeError as exc:
        raise AuditError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AuditError(f"JSON root must be an object: {path}")
    return value


def strings(value: Any, field: str, *, allow_empty: bool = False) -> list[str]:
    if value is None and allow_empty:
        return []
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise AuditError(f"{field} must be an array of non-empty strings")
    return [item.strip() for item in value]


def files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and not any(part in SKIP for part in path.parts):
            yield path


def line_no(value: str, offset: int) -> int:
    return value.count("\n", 0, offset) + 1


def routing_block(value: str) -> str | None:
    start = value.find(ROUTING_START)
    end = value.find(ROUTING_END)
    if start < 0 or end < start:
        return None
    return value[start : end + len(ROUTING_END)]


def missing_terms(value: str, terms: Sequence[str]) -> list[str]:
    folded = value.casefold()
    return [term for term in terms if term.casefold() not in folded]


def bounded_scope(value: str, start: str, end: str, field: str) -> str:
    first = value.find(start)
    if first < 0:
        raise AuditError(f"{field} start marker is absent: {start!r}")
    last = value.find(end, first + len(start))
    if last < 0:
        raise AuditError(f"{field} end marker is absent: {end!r}")
    return value[first:last]


def reader_findings(
    root: Path, cfg: dict[str, Any]
) -> tuple[list[Finding], dict[str, int]]:
    section = cfg["documentation_reader"]
    terms = [
        str(section["command"]).strip(),
        *strings(section["required_terms"], "documentation_reader.required_terms"),
    ]
    surfaces = {
        norm(item)
        for item in strings(
            section["surfaces"], "documentation_reader.surfaces"
        )
    }
    if section.get("scan_all_agent_files") is True:
        surfaces |= {rel(root, path) for path in files(root) if path.name == "AGENTS.md"}

    findings: list[Finding] = []
    for relative in sorted(surfaces):
        path = root / relative
        if not path.is_file():
            findings.append(
                Finding(
                    "DCC-001",
                    relative,
                    0,
                    "documentation-reading surface is missing",
                )
            )
            continue
        value = text(path)
        inspected = routing_block(value) or value
        missing = missing_terms(inspected, terms)
        if missing:
            findings.append(
                Finding(
                    "DCC-001",
                    relative,
                    1,
                    "reader contract is incomplete; missing: " + ", ".join(missing),
                )
            )

    scopes = section.get("generator_scope", [])
    if not isinstance(scopes, list) or not scopes:
        raise AuditError("documentation_reader.generator_scope must be non-empty")
    for index, item in enumerate(scopes):
        if not isinstance(item, dict):
            raise AuditError(f"documentation_reader.generator_scope[{index}] must be a table")
        relative = norm(str(item["path"]))
        path = root / relative
        if not path.is_file():
            findings.append(
                Finding("DCC-001", relative, 0, "documentation generator is missing")
            )
            continue
        try:
            inspected = bounded_scope(
                text(path),
                str(item["start"]),
                str(item["end"]),
                f"generator scope {relative}",
            )
        except AuditError as exc:
            findings.append(Finding("DCC-001", relative, 1, str(exc)))
            continue
        missing = missing_terms(inspected, terms)
        if missing:
            findings.append(
                Finding(
                    "DCC-001",
                    relative,
                    1,
                    "generator scope cannot reproduce reader contract; missing: "
                    + ", ".join(missing),
                )
            )
    return findings, {
        "reader_surfaces": len(surfaces),
        "reader_generator_scopes": len(scopes),
    }


def workflow_events(value: str) -> set[str]:
    lines = value.splitlines()
    for index, line in enumerate(lines):
        if not re.fullmatch(r"on:\s*.*", line):
            continue
        tail = line.split(":", 1)[1].strip()
        if tail.startswith("[") and tail.endswith("]"):
            return {
                item.strip(" '\"")
                for item in tail[1:-1].split(",")
                if item.strip()
            }
        if tail:
            return {tail.strip("'\"")}
        events: set[str] = set()
        for candidate in lines[index + 1 :]:
            if not candidate.strip() or candidate.lstrip().startswith("#"):
                continue
            if candidate == candidate.lstrip():
                break
            match = re.match(r"^  ([A-Za-z_][A-Za-z0-9_-]*):", candidate)
            if match:
                events.add(match.group(1))
        return events
    return set()


def workflow_findings(
    root: Path, cfg: dict[str, Any]
) -> tuple[list[Finding], dict[str, int]]:
    section = cfg["workflows"]
    directory = root / norm(str(section["directory"]))
    allowed = set(strings(section["allowed_events"], "workflows.allowed_events"))
    workflows = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    findings: list[Finding] = []
    for path in workflows:
        events = workflow_events(text(path))
        if events != allowed:
            findings.append(
                Finding(
                    "DCC-002",
                    rel(root, path),
                    1,
                    f"workflow events differ from policy: actual={sorted(events)} "
                    f"allowed={sorted(allowed)}",
                )
            )

    doc_relative = norm(str(section["documentation"]))
    doc = root / doc_relative
    if not doc.is_file():
        findings.append(
            Finding("DCC-002", doc_relative, 0, "workflow documentation is missing")
        )
    else:
        value = text(doc)
        for term in strings(
            section["required_documentation_terms"],
            "workflows.required_documentation_terms",
        ):
            if term.casefold() not in value.casefold():
                findings.append(
                    Finding(
                        "DCC-002",
                        doc_relative,
                        1,
                        f"manual-trigger documentation term is absent: {term}",
                    )
                )
        for term in strings(
            section["forbidden_documentation_terms"],
            "workflows.forbidden_documentation_terms",
        ):
            offset = value.casefold().find(term.casefold())
            if offset >= 0:
                findings.append(
                    Finding(
                        "DCC-002",
                        doc_relative,
                        line_no(value, offset),
                        f"workflow documentation contradicts source: {term}",
                    )
                )
        if section.get("require_workflow_filenames") is True:
            for path in workflows:
                if f"`{path.name}`" not in value:
                    findings.append(
                        Finding(
                            "DCC-002",
                            doc_relative,
                            1,
                            f"workflow file is absent from documentation: {path.name}",
                        )
                    )
    return findings, {"workflow_files": len(workflows)}


def selected_files(root: Path, roots: Sequence[str]) -> Iterable[Path]:
    seen: set[Path] = set()
    for raw in roots:
        candidate = root / norm(raw)
        if candidate.is_file():
            candidates: Iterable[Path] = [candidate]
        elif candidate.is_dir():
            candidates = files(candidate)
        else:
            candidates = []
        for path in candidates:
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                yield path


def retired_reference_findings(
    root: Path, cfg: dict[str, Any]
) -> tuple[list[Finding], dict[str, int]]:
    section = cfg["retired_references"]
    roots = strings(section["scan_roots"], "retired_references.scan_roots")
    tokens = strings(section["tokens"], "retired_references.tokens")
    extensions = set(strings(section["extensions"], "retired_references.extensions"))
    ignores = strings(
        section.get("ignore_globs", []),
        "retired_references.ignore_globs",
        allow_empty=True,
    )
    allow = {
        (norm(str(item["path"])), str(item["token"]))
        for item in section.get("allow", [])
        if isinstance(item, dict) and str(item.get("reason", "")).strip()
    }
    regex = re.compile(str(section["unstable_line_reference_regex"]))
    findings: list[Finding] = []
    scanned = 0
    for path in selected_files(root, roots):
        relative = rel(root, path)
        if path.suffix.lower() not in extensions or any(
            fnmatch.fnmatchcase(relative, pattern) for pattern in ignores
        ):
            continue
        value = text(path)
        scanned += 1
        for token in tokens:
            if (relative, token) in allow:
                continue
            for match in re.finditer(re.escape(token), value):
                findings.append(
                    Finding(
                        "DCC-003",
                        relative,
                        line_no(value, match.start()),
                        f"retired repository path reference remains: {token}",
                    )
                )
        for match in regex.finditer(value):
            findings.append(
                Finding(
                    "DCC-003",
                    relative,
                    line_no(value, match.start()),
                    "unstable line-number authority reference remains: "
                    + match.group(0),
                )
            )
    return findings, {"reference_files": scanned}


def script_findings(
    root: Path, cfg: dict[str, Any]
) -> tuple[list[Finding], dict[str, int]]:
    section = cfg["script_inventory"]
    directory = root / norm(str(section["directory"]))
    doc_relative = norm(str(section["documentation"]))
    doc = root / doc_relative
    if not doc.is_file():
        return [Finding("DCC-004", doc_relative, 0, "script documentation is missing")], {
            "scripts": 0
        }
    value = text(doc)
    extensions = set(strings(section["extensions"], "script_inventory.extensions"))
    excluded = set(
        strings(
            section.get("exclude", []),
            "script_inventory.exclude",
            allow_empty=True,
        )
    )
    names = sorted(
        path.name
        for path in directory.iterdir()
        if path.is_file()
        and path.suffix.lower() in extensions
        and path.name not in excluded
    )
    findings = [
        Finding(
            "DCC-004",
            doc_relative,
            1,
            f"top-level script/helper is absent from the supported-script map: {name}",
        )
        for name in names
        if name not in value
    ]
    return findings, {"scripts": len(names)}


def binary_findings(
    root: Path, cfg: dict[str, Any]
) -> tuple[list[Finding], dict[str, int]]:
    section = cfg["binary_inventory"]
    workspace = toml(root / norm(str(section["workspace_manifest"]))).get(
        "workspace", {}
    )
    members = workspace.get("members")
    if not isinstance(members, list):
        raise AuditError("workspace.members is missing")
    prefix = norm(str(section["member_prefix"])).rstrip("/") + "/"
    selected = sorted(
        norm(str(item))
        for item in members
        if str(item).replace("\\", "/").startswith(prefix)
    )
    doc_relative = norm(str(section["documentation"]))
    doc = root / doc_relative
    if not doc.is_file():
        return [Finding("DCC-005", doc_relative, 0, "project map is missing")], {
            "binary_packages": len(selected)
        }
    value = text(doc)
    findings: list[Finding] = []
    for member in selected:
        manifest = root / member / "Cargo.toml"
        package = toml(manifest).get("package", {}) if manifest.is_file() else {}
        name = str(package.get("name", "")).strip()
        if not name:
            findings.append(
                Finding(
                    "DCC-005",
                    member,
                    0,
                    "binary package manifest/name is missing",
                )
            )
        elif f"`{member}`" not in value and f"`{name}.exe`" not in value:
            findings.append(
                Finding(
                    "DCC-005",
                    doc_relative,
                    1,
                    f"composition root is not named exactly: {member} ({name}.exe)",
                )
            )
    return findings, {"binary_packages": len(selected)}


def owner_findings(
    root: Path, cfg: dict[str, Any]
) -> tuple[list[Finding], dict[str, int]]:
    bindings = cfg.get("owner_binding", [])
    if not isinstance(bindings, list):
        raise AuditError("owner_binding must be an array of tables")
    findings: list[Finding] = []
    for item in bindings:
        if not isinstance(item, dict):
            raise AuditError("owner_binding entry must be a table")
        relative = norm(str(item["path"]))
        path = root / relative
        if not path.is_file():
            findings.append(
                Finding("DCC-006", relative, 0, "configured owner surface is missing")
            )
            continue
        value = text(path)
        folded = value.casefold()
        for phrase in strings(
            item["required_phrases"],
            f"owner_binding {relative}.required_phrases",
        ):
            if phrase.casefold() not in folded:
                findings.append(
                    Finding(
                        "DCC-006",
                        relative,
                        1,
                        f"current owner/work reference is absent: {phrase}",
                    )
                )
        for phrase in strings(
            item["forbidden_current_phrases"],
            f"owner_binding {relative}.forbidden_current_phrases",
        ):
            offset = folded.find(phrase.casefold())
            if offset >= 0:
                findings.append(
                    Finding(
                        "DCC-006",
                        relative,
                        line_no(value, offset),
                        f"completed/stale work is described as current: {phrase}",
                    )
                )
    return findings, {"owner_bindings": len(bindings)}


def repository_path_findings(
    root: Path, cfg: dict[str, Any]
) -> tuple[list[Finding], dict[str, int]]:
    section = cfg["repository_paths"]
    scan_roots = strings(section["scan_roots"], "repository_paths.scan_roots")
    extensions = set(strings(section["extensions"], "repository_paths.extensions"))
    ignores = strings(
        section.get("ignore_globs", []),
        "repository_paths.ignore_globs",
        allow_empty=True,
    )
    allowed_missing = {
        (norm(str(item["source"])), norm(str(item["path"])))
        for item in section.get("allow_missing", [])
        if isinstance(item, dict) and str(item.get("reason", "")).strip()
    }

    exact_paths = {rel(root, path) for path in files(root)}
    by_casefold: dict[str, list[str]] = {}
    for relative in exact_paths:
        by_casefold.setdefault(relative.casefold(), []).append(relative)

    handle_index_path = root / norm(
        str(section.get("handle_index", "docs/architecture/handle-index.json"))
    )
    handles: set[str] = set()
    if handle_index_path.is_file():
        payload = json_object(handle_index_path)
        raw_handles = payload.get("handles")
        if isinstance(raw_handles, dict):
            handles = {str(item) for item in raw_handles}

    findings: list[Finding] = []
    references = 0
    unique: set[str] = set()
    for path in selected_files(root, scan_roots):
        relative = rel(root, path)
        if path.suffix.lower() not in extensions or any(
            fnmatch.fnmatchcase(relative, pattern) for pattern in ignores
        ):
            continue
        value = text(path)
        for match in DOC_PATH_RE.finditer(value):
            candidate = norm(html.unescape(match.group("path")))
            handle = match.group("handle")
            references += 1
            unique.add(candidate)
            if (relative, candidate) in allowed_missing:
                continue
            if candidate not in exact_paths:
                case_matches = sorted(by_casefold.get(candidate.casefold(), []))
                if case_matches:
                    message = (
                        f"repository path has incorrect case: {candidate}; "
                        f"actual={case_matches}"
                    )
                else:
                    message = f"repository path does not exist: {candidate}"
                findings.append(
                    Finding(
                        "DCC-007",
                        relative,
                        line_no(value, match.start()),
                        message,
                    )
                )
                continue
            if handle:
                handle_value = handle[1:]
                if handles and handle_value not in handles:
                    findings.append(
                        Finding(
                            "DCC-007",
                            relative,
                            line_no(value, match.start()),
                            f"normative handle is absent from handle index: {handle_value}",
                        )
                    )
    return findings, {
        "repository_path_references": references,
        "repository_paths_unique": len(unique),
    }


def audit(root: Path, cfg: dict[str, Any]) -> tuple[list[Finding], dict[str, int]]:
    if cfg.get("schema_version") != SCHEMA:
        raise AuditError(f"unsupported schema: {cfg.get('schema_version')!r}")
    findings: list[Finding] = []
    metrics: dict[str, int] = {}
    for checker in (
        reader_findings,
        workflow_findings,
        retired_reference_findings,
        script_findings,
        binary_findings,
        owner_findings,
        repository_path_findings,
    ):
        current, values = checker(root, cfg)
        findings.extend(current)
        metrics.update(values)
    return sorted(set(findings)), metrics


def route_fixture() -> str:
    return textwrap.dedent(
        f"""
        {ROUTING_START}
        python scripts/docs_read.py read --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
        route alone is navigation, not reading evidence; open the verified bundle and record the read receipt.
        {ROUTING_END}
        """
    ).lstrip()


def fixture_config() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA,
        "documentation_reader": {
            "command": "python scripts/docs_read.py read",
            "required_terms": [
                "docs-read-bundle.md",
                "docs-read-receipt.json",
                "route alone",
                "verified bundle",
                "read receipt",
            ],
            "surfaces": [
                "AGENTS.md",
                "WORKFLOW.md",
                "docs/architecture/READING_PROTOCOL.md",
                "docs/architecture/README.md",
            ],
            "scan_all_agent_files": True,
            "generator_scope": [
                {
                    "path": "scripts/docs_shards.py",
                    "start": "def routing_block",
                    "end": "def end_routing_block",
                }
            ],
        },
        "workflows": {
            "directory": ".github/workflows",
            "documentation": ".github/README.md",
            "allowed_events": ["workflow_dispatch"],
            "required_documentation_terms": ["`workflow_dispatch` only"],
            "forbidden_documentation_terms": ["Runs on every branch push"],
            "require_workflow_filenames": True,
        },
        "retired_references": {
            "scan_roots": ["crates", ".github"],
            "tokens": ["docs/normative/"],
            "extensions": [".rs", ".yml"],
            "ignore_globs": [],
            "unstable_line_reference_regex": r"docs/(?:normative|architecture)/ELIOT_(?:ARCHITECTURE|IMPLEMENTATION)\.md:\d+",
            "allow": [
                {
                    "path": ".github/workflows/policy.yml",
                    "token": "docs/normative/",
                    "reason": "negative fixture",
                }
            ],
        },
        "script_inventory": {
            "directory": "scripts",
            "documentation": "scripts/README.md",
            "extensions": [".py"],
            "exclude": [],
        },
        "binary_inventory": {
            "workspace_manifest": "Cargo.toml",
            "documentation": "docs/PROJECT_MAP.md",
            "member_prefix": "bins/",
        },
        "owner_binding": [
            {
                "path": "crates/owner/AGENTS.md",
                "required_phrases": ["#265"],
                "forbidden_current_phrases": ["Issue #224 owns current"],
            }
        ],
        "repository_paths": {
            "scan_roots": ["crates", "scripts", ".github"],
            "extensions": [".rs", ".py", ".yml"],
            "ignore_globs": [],
            "handle_index": "docs/architecture/handle-index.json",
            "allow_missing": [
                {
                    "source": ".github/workflows/policy.yml",
                    "path": "docs/retired.md",
                    "reason": "negative fixture",
                }
            ],
        },
    }


def write_fixture(root: Path) -> None:
    for relative in [
        "crates/x/src",
        "crates/owner",
        "bins/tool/src",
        "docs/architecture",
        "scripts",
        ".github/workflows",
    ]:
        (root / relative).mkdir(parents=True, exist_ok=True)
    for relative in [
        "AGENTS.md",
        "WORKFLOW.md",
        "crates/x/AGENTS.md",
        "docs/architecture/READING_PROTOCOL.md",
        "docs/architecture/README.md",
    ]:
        (root / relative).write_text(route_fixture(), encoding="utf-8")
    (root / "crates/owner/AGENTS.md").write_text(
        route_fixture() + "Current owner: #265.\n", encoding="utf-8"
    )
    (root / "scripts/docs_read.py").write_text("# reader\n", encoding="utf-8")
    (root / "scripts/docs_shards.py").write_text(
        "def routing_block():\n" + textwrap.indent(route_fixture(), "    # ")
        + "def end_routing_block():\n    pass\n",
        encoding="utf-8",
    )
    (root / "scripts/README.md").write_text(
        "`docs_read.py` `docs_shards.py`\n", encoding="utf-8"
    )
    (root / ".github/workflows/ci.yml").write_text(
        "on:\n  workflow_dispatch:\n", encoding="utf-8"
    )
    (root / ".github/workflows/policy.yml").write_text(
        "on:\n  workflow_dispatch:\n# reject docs/normative/ and docs/retired.md\n",
        encoding="utf-8",
    )
    (root / ".github/README.md").write_text(
        "`ci.yml` and `policy.yml` use `workflow_dispatch` only.\n",
        encoding="utf-8",
    )
    (root / "docs/current.md").write_text("# Current\n", encoding="utf-8")
    (root / "crates/x/src/lib.rs").write_text(
        "//! docs/current.md:A1.1\npub fn ok() {}\n", encoding="utf-8"
    )
    (root / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["bins/tool"]\n', encoding="utf-8"
    )
    (root / "bins/tool/Cargo.toml").write_text(
        '[package]\nname = "tool"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    (root / "bins/tool/src/main.rs").write_text("fn main() {}\n", encoding="utf-8")
    (root / "docs/PROJECT_MAP.md").write_text("`tool.exe`\n", encoding="utf-8")
    (root / "docs/architecture/handle-index.json").write_text(
        json.dumps({"handles": {"A1.1": {"path": "docs/current.md"}}}),
        encoding="utf-8",
    )


def expect(root: Path, cfg: dict[str, Any], finding_id: str) -> None:
    ids = {item.finding_id for item in audit(root, cfg)[0]}
    if finding_id not in ids:
        raise AuditError(f"self-test expected {finding_id}, got {sorted(ids)}")


def self_test() -> None:
    cfg = fixture_config()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_fixture(root)
        clean_findings = audit(root, cfg)[0]
        if clean_findings:
            raise AuditError(f"clean self-test fixture failed: {clean_findings}")

        nested = root / "crates/x/AGENTS.md"
        nested.write_text("router only\n", encoding="utf-8")
        expect(root, cfg, "DCC-001")
        nested.write_text(route_fixture(), encoding="utf-8")

        generator = root / "scripts/docs_shards.py"
        original_generator = text(generator)
        generator.write_text(
            "def routing_block():\n    # docs_read.py mentioned elsewhere only\ndef end_routing_block():\n    pass\n",
            encoding="utf-8",
        )
        expect(root, cfg, "DCC-001")
        generator.write_text(original_generator, encoding="utf-8")

        workflow_doc = root / ".github/README.md"
        workflow_doc.write_text(
            "`ci.yml` `policy.yml` use `workflow_dispatch` only. Runs on every branch push\n",
            encoding="utf-8",
        )
        expect(root, cfg, "DCC-002")
        workflow_doc.write_text(
            "`ci.yml` and `policy.yml` use `workflow_dispatch` only.\n",
            encoding="utf-8",
        )

        source = root / "crates/x/src/lib.rs"
        source.write_text(
            "//! docs/normative/ELIOT_ARCHITECTURE.md:42\n", encoding="utf-8"
        )
        expect(root, cfg, "DCC-003")
        source.write_text("//! docs/current.md:A1.1\n", encoding="utf-8")

        extra = root / "scripts/new_helper.py"
        extra.write_text("# helper\n", encoding="utf-8")
        expect(root, cfg, "DCC-004")
        extra.unlink()

        project_map = root / "docs/PROJECT_MAP.md"
        project_map.write_text("no exact binary\n", encoding="utf-8")
        expect(root, cfg, "DCC-005")
        project_map.write_text("`tool.exe`\n", encoding="utf-8")

        owner = root / "crates/owner/AGENTS.md"
        owner.write_text(
            route_fixture() + "Issue #224 owns current work.\n", encoding="utf-8"
        )
        expect(root, cfg, "DCC-006")
        owner.write_text(route_fixture() + "Current owner: #265.\n", encoding="utf-8")

        source.write_text("//! docs/missing.md\n", encoding="utf-8")
        expect(root, cfg, "DCC-007")
        source.write_text("//! docs/Current.md\n", encoding="utf-8")
        expect(root, cfg, "DCC-007")
        source.write_text("//! docs/current.md:A9.9\n", encoding="utf-8")
        expect(root, cfg, "DCC-007")

    print("DOC_CODE_CONFORMANCE_SELF_TEST: PASS cases=11")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/doc-code-conformance.toml"),
    )
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.self_test:
            self_test()
            return 0
        root = args.root.resolve()
        config_path = args.config if args.config.is_absolute() else root / args.config
        findings, metrics = audit(root, toml(config_path))
        payload = {
            "schema_version": SCHEMA,
            "status": "PASS" if not findings else "FAIL",
            "metrics": metrics,
            "findings": [asdict(item) for item in findings],
        }
        if args.json_out:
            output = args.json_out if args.json_out.is_absolute() else root / args.json_out
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        if findings:
            for item in findings:
                location = item.path + (f":{item.line}" if item.line else "")
                print(
                    f"{item.finding_id} {location}: {item.message}", file=sys.stderr
                )
            print(
                f"DOC_CODE_CONFORMANCE: FAIL findings={len(findings)}",
                file=sys.stderr,
            )
            return 1
        print(
            "DOC_CODE_CONFORMANCE: PASS "
            + " ".join(f"{key}={value}" for key, value in sorted(metrics.items()))
        )
        return 0
    except (AuditError, KeyError, TypeError, ValueError) as exc:
        print(f"DOC_CODE_CONFORMANCE_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
