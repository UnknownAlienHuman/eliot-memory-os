#!/usr/bin/env python3
"""Route agents to exact normative sections and materialize lossless slices.

The accepted ELIOT Architecture/Implementation books remain immutable canonical
sources.  This tool parses their stable section handles, selects the minimum
mandatory set for a task/path scope, and writes byte-exact section files plus a
content-addressed reading receipt.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover - Python < 3.11
    raise SystemExit("docs_router.py requires Python 3.11 or newer") from exc

SCHEMA_VERSION = "eliot-doc-router-v1"
RECEIPT_SCHEMA_VERSION = "eliot-doc-reading-receipt-v1"
DOMAIN = b"eliot-doc-reading-receipt-v1\0"
DEFAULT_MAP = Path("docs/architecture/reading-map.toml")
DEFAULT_RECEIPT = Path("docs/normative-pair.toml")
FENCE_RE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")
HEADING_RE = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*$")
HTML_TAG_RE = re.compile(r"<[^>]+>")
LINK_RE = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
ARCHITECTURE_HANDLE_RE = re.compile(
    r"^(?P<handle>A\d+(?:\.\d+)*)(?=$|[\s.:;,)—–-])",
    re.IGNORECASE,
)
IMPLEMENTATION_HANDLE_RE = re.compile(
    r"^(?P<handle>I\d+(?:\.(?:\d+|[A-Z]))*|I-[A-Z](?:\.\d+)*)"
    r"(?=$|[\s.:;,)—–-])",
    re.IGNORECASE,
)
IMPLEMENTATION_APPENDIX_RE = re.compile(
    r"^appendix\s+(?P<letter>[A-Z])(?:\.(?P<number>\d+))?"
    r"(?=$|[\s.:;,)—–-])",
    re.IGNORECASE,
)
IMPLEMENTATION_APPENDIX_CHILD_RE = re.compile(
    r"^(?P<letter>[A-Z])\.(?P<number>\d+(?:\.\d+)*)"
    r"(?=$|[\s.:;,)—–-])",
    re.IGNORECASE,
)
ROOT_HANDLE_RE = re.compile(r"^(?:A\d+|I\d+|I-[A-Z])$")


class RouterError(RuntimeError):
    """Expected, actionable documentation-routing failure."""


@dataclasses.dataclass(frozen=True)
class Heading:
    level: int
    title: str
    handle: str | None
    line: int
    start: int


@dataclasses.dataclass(frozen=True)
class Section:
    source_id: str
    source_path: Path
    handle: str
    title: str
    level: int
    start_line: int
    end_line: int
    start: int
    end: int

    @property
    def byte_count(self) -> int:
        return self.end - self.start


@dataclasses.dataclass(frozen=True)
class Slice:
    source_id: str
    source_path: Path
    selectors: tuple[str, ...]
    handles: tuple[str, ...]
    start_line: int
    end_line: int
    start: int
    end: int

    @property
    def byte_count(self) -> int:
        return self.end - self.start


@dataclasses.dataclass(frozen=True)
class SourceDocument:
    source_id: str
    path: Path
    data: bytes
    sha256: str
    headings: tuple[Heading, ...]
    sections: tuple[Section, ...]

    @property
    def by_handle(self) -> dict[str, Section]:
        return {section.handle: section for section in self.sections}


@dataclasses.dataclass(frozen=True)
class Route:
    route_id: str
    description: str
    priority: int
    paths: tuple[str, ...]
    tasks: tuple[str, ...]
    required: tuple[str, ...]
    optional: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class Selection:
    routes: tuple[Route, ...]
    required_selectors: tuple[str, ...]
    optional_selectors: tuple[str, ...]
    unknown_paths: tuple[str, ...]
    unknown_tasks: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class RouterConfig:
    path: Path
    schema_version: str
    base_required: tuple[str, ...]
    base_optional: tuple[str, ...]
    routes: tuple[Route, ...]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def normalize_repo_path(raw: str) -> str:
    value = raw.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    value = str(PurePosixPath(value))
    if value in {"", "."} or value.startswith("../") or value == "..":
        raise RouterError(f"invalid repository path: {raw!r}")
    return value


def clean_heading_title(raw: str) -> str:
    value = raw.strip()
    value = re.sub(r"\s+#+\s*$", "", value)
    value = HTML_TAG_RE.sub("", value)
    value = LINK_RE.sub(lambda match: match.group(1), value)
    value = value.replace("`", "")
    value = value.replace("**", "").replace("__", "")
    value = value.strip("*_~ ")
    return value


def normalize_handle(raw: str) -> str:
    return raw.upper()


def extract_handle(source_id: str, title: str) -> str | None:
    if source_id == "architecture":
        match = ARCHITECTURE_HANDLE_RE.match(title)
        return normalize_handle(match.group("handle")) if match else None
    match = IMPLEMENTATION_HANDLE_RE.match(title)
    if match:
        return normalize_handle(match.group("handle"))
    match = IMPLEMENTATION_APPENDIX_RE.match(title)
    if match:
        suffix = f".{match.group('number')}" if match.group("number") else ""
        return f"I-{match.group('letter').upper()}{suffix}"
    match = IMPLEMENTATION_APPENDIX_CHILD_RE.match(title)
    if match:
        return f"I-{match.group('letter').upper()}.{match.group('number')}"
    return None


def handle_depth(handle: str) -> int:
    if handle.startswith("I-"):
        suffix = handle[3:]
        return 1 + (suffix.count(".") if suffix else 0)
    return 1 + handle.count(".")


def parse_document(
    source_id: str,
    absolute_path: Path,
    source_path: Path,
    expected_sha256: str,
) -> SourceDocument:
    path = absolute_path
    if not path.is_file():
        raise RouterError(f"canonical source is missing: {path.as_posix()}")
    data = path.read_bytes()
    actual_sha = sha256_bytes(data)
    if actual_sha != expected_sha256:
        raise RouterError(
            f"{source_id} digest mismatch: expected {expected_sha256}, actual {actual_sha}"
        )
    try:
        text_lines = data.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise RouterError(f"{path.as_posix()} is not valid UTF-8: {exc}") from exc

    headings: list[Heading] = []
    offset = 0
    fence_marker: str | None = None
    fence_len = 0

    for line_number, line in enumerate(text_lines, start=1):
        logical_line = line.rstrip("\r\n")
        fence = FENCE_RE.match(logical_line)
        if fence:
            marker = fence.group(1)
            if fence_marker is None:
                fence_marker = marker[0]
                fence_len = len(marker)
            elif marker[0] == fence_marker and len(marker) >= fence_len:
                fence_marker = None
                fence_len = 0
            offset += len(line.encode("utf-8"))
            continue
        if fence_marker is not None:
            offset += len(line.encode("utf-8"))
            continue

        heading_match = HEADING_RE.match(logical_line)
        if heading_match:
            title = clean_heading_title(heading_match.group(2))
            handle = extract_handle(source_id, title)
            headings.append(
                Heading(
                    level=len(heading_match.group(1)),
                    title=title,
                    handle=handle,
                    line=line_number,
                    start=offset,
                )
            )
        offset += len(line.encode("utf-8"))

    if fence_marker is not None:
        raise RouterError(f"unterminated Markdown fence in {path.as_posix()}")

    sections: list[Section] = []
    seen: dict[str, Heading] = {}
    for index, heading in enumerate(headings):
        if heading.handle is None:
            continue
        if heading.handle in seen:
            previous = seen[heading.handle]
            raise RouterError(
                f"duplicate handle {heading.handle} in {path.as_posix()} "
                f"at lines {previous.line} and {heading.line}"
            )
        seen[heading.handle] = heading
        end = len(data)
        end_line = len(text_lines)
        for next_heading in headings[index + 1 :]:
            if next_heading.level <= heading.level:
                end = next_heading.start
                end_line = next_heading.line - 1
                break
        sections.append(
            Section(
                source_id=source_id,
                source_path=source_path,
                handle=heading.handle,
                title=heading.title,
                level=heading.level,
                start_line=heading.line,
                end_line=end_line,
                start=heading.start,
                end=end,
            )
        )

    if not sections:
        raise RouterError(f"no stable A/I section handles found in {path.as_posix()}")
    return SourceDocument(
        source_id=source_id,
        path=source_path,
        data=data,
        sha256=actual_sha,
        headings=tuple(headings),
        sections=tuple(sections),
    )


def load_normative_pair(repo_root: Path, receipt_path: Path) -> tuple[dict[str, Any], dict[str, SourceDocument]]:
    absolute_receipt = repo_root / receipt_path
    if not absolute_receipt.is_file():
        raise RouterError(f"normative-pair receipt is missing: {receipt_path.as_posix()}")
    with absolute_receipt.open("rb") as stream:
        receipt = tomllib.load(stream)
    required = (
        "schema_version",
        "status",
        "pair_key",
        "architecture_path",
        "architecture_sha256",
        "implementation_path",
        "implementation_sha256",
    )
    missing = [key for key in required if not receipt.get(key)]
    if missing:
        raise RouterError(f"normative-pair receipt is missing keys: {', '.join(missing)}")
    if receipt["status"] != "accepted":
        raise RouterError("normative pair is not accepted")

    documents = {
        "architecture": parse_document(
            "architecture",
            repo_root / str(receipt["architecture_path"]),
            Path(str(receipt["architecture_path"])),
            str(receipt["architecture_sha256"]),
        ),
        "implementation": parse_document(
            "implementation",
            repo_root / str(receipt["implementation_path"]),
            Path(str(receipt["implementation_path"])),
            str(receipt["implementation_sha256"]),
        ),
    }
    return receipt, documents


def string_tuple(value: Any, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RouterError(f"{field} must be an array of strings")
    return tuple(item.strip() for item in value if item.strip())


def load_config(repo_root: Path, map_path: Path) -> RouterConfig:
    absolute_path = repo_root / map_path
    if not absolute_path.is_file():
        raise RouterError(f"reading map is missing: {map_path.as_posix()}")
    with absolute_path.open("rb") as stream:
        raw = tomllib.load(stream)
    schema = raw.get("schema_version")
    if schema != SCHEMA_VERSION:
        raise RouterError(f"unsupported reading-map schema: {schema!r}")
    base = raw.get("base", {})
    if not isinstance(base, dict):
        raise RouterError("[base] must be a TOML table")
    routes: list[Route] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw.get("route", [])):
        if not isinstance(item, dict):
            raise RouterError(f"route[{index}] must be a TOML table")
        route_id = str(item.get("id", "")).strip()
        if not route_id:
            raise RouterError(f"route[{index}] is missing id")
        if route_id in seen_ids:
            raise RouterError(f"duplicate route id: {route_id}")
        seen_ids.add(route_id)
        paths = string_tuple(item.get("paths"), f"route {route_id}.paths")
        tasks = tuple(task.lower() for task in string_tuple(item.get("tasks"), f"route {route_id}.tasks"))
        if not paths and not tasks:
            raise RouterError(f"route {route_id} has neither paths nor tasks")
        routes.append(
            Route(
                route_id=route_id,
                description=str(item.get("description", "")).strip(),
                priority=int(item.get("priority", 0)),
                paths=paths,
                tasks=tasks,
                required=string_tuple(item.get("required"), f"route {route_id}.required"),
                optional=string_tuple(item.get("optional"), f"route {route_id}.optional"),
            )
        )
    return RouterConfig(
        path=map_path,
        schema_version=schema,
        base_required=string_tuple(base.get("required"), "base.required"),
        base_optional=string_tuple(base.get("optional"), "base.optional"),
        routes=tuple(routes),
    )


def matches_path(path: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(path, pattern)


def stable_unique(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = value.upper() if value[:1].upper() in {"A", "I"} else value
        if key not in seen:
            seen.add(key)
            result.append(value)
    return tuple(result)


def select_routes(
    config: RouterConfig,
    paths: Sequence[str],
    tasks: Sequence[str],
    allow_fallback: bool,
) -> Selection:
    selected: dict[str, Route] = {}
    unknown_paths: list[str] = []
    unknown_tasks: list[str] = []

    for raw_path in paths:
        path = normalize_repo_path(raw_path)
        matches = [route for route in config.routes if any(matches_path(path, pattern) for pattern in route.paths)]
        if not matches:
            unknown_paths.append(path)
            continue
        max_priority = max(route.priority for route in matches)
        for route in matches:
            if route.priority == max_priority:
                selected[route.route_id] = route

    for raw_task in tasks:
        task = raw_task.strip().lower()
        matches = [route for route in config.routes if task in route.tasks]
        if not matches:
            unknown_tasks.append(task)
            continue
        max_priority = max(route.priority for route in matches)
        for route in matches:
            if route.priority == max_priority:
                selected[route.route_id] = route

    if (unknown_paths or unknown_tasks) and not allow_fallback:
        details: list[str] = []
        if unknown_paths:
            details.append("unmapped paths=" + ",".join(unknown_paths))
        if unknown_tasks:
            details.append("unmapped tasks=" + ",".join(unknown_tasks))
        raise RouterError(
            "documentation route is incomplete (" + "; ".join(details) + "). "
            "Add an explicit reading-map route or rerun with --allow-fallback "
            "and record the cross-cutting fallback in the receipt."
        )

    selected_routes = list(selected.values())
    if allow_fallback and (unknown_paths or unknown_tasks):
        fallback = next((route for route in config.routes if route.route_id == "cross-cutting-fallback"), None)
        if fallback is None:
            raise RouterError("reading map has no cross-cutting-fallback route")
        selected[fallback.route_id] = fallback
        selected_routes = list(selected.values())

    selected_routes.sort(key=lambda route: (-route.priority, route.route_id))
    required = stable_unique(
        [*config.base_required, *(selector for route in selected_routes for selector in route.required)]
    )
    optional = stable_unique(
        [*config.base_optional, *(selector for route in selected_routes for selector in route.optional)]
    )
    return Selection(
        routes=tuple(selected_routes),
        required_selectors=required,
        optional_selectors=optional,
        unknown_paths=tuple(unknown_paths),
        unknown_tasks=tuple(unknown_tasks),
    )

