#!/usr/bin/env python3
"""Resolve ELIOT documentation fragments for one bounded causal work unit.

The router is deliberately deterministic. It maps repository paths and a short
causal-property description to required/optional normative handles, resolves
those handles through the generated shard index, and emits a content-addressed
read receipt. It never treats a legacy compatibility map as task context.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Sequence

SCHEMA = "eliot-doc-routes-v1"
INDEX_SCHEMA = "eliot-handle-index-v1"
GENERATED_MARKER = "<!-- generated: eliot-doc-routes-v1 -->"
DEFAULT_CONFIG = "docs/architecture/route-rules.toml"
DEFAULT_INDEX = "docs/architecture/handle-index.json"
DEFAULT_RECEIPT = "docs/normative-pair.toml"
DEFAULT_ROUTES_MD = "docs/architecture/ROUTES.md"
LEGACY_BOOKS = {
    "docs/architecture/ELIOT_ARCHITECTURE.md",
    "docs/architecture/ELIOT_IMPLEMENTATION.md",
}
SKIP_PARTS = {".git", "target", ".idea", ".vscode", "node_modules", "bin", "obj"}
COVERAGE_KEYS = ("path", "topic", "expect_routes", "expect_required_handles", "expect_absent_routes")
# Topic text is matched as whole alphanumeric tokens, never as an arbitrary
# substring. Punctuation, whitespace, and symbol boundaries all separate
# tokens, so a multiword keyword such as "source code" matches "source-code",
# "source_code", and "source code" alike (#4606).
TOPIC_TOKEN_RE = re.compile(r"[a-z0-9]+")
# An Issue declares its own reading under one of these headings (#5320).
ISSUE_READING_HEADINGS = ("read", "читать")
HANDLE_SELECTOR_RE = re.compile(
    r"(?:APPENDIX-[A-Z](?:\.\.APPENDIX-[A-Z])?"
    r"|[AI]\d+(?:\.\d+)*(?:\.\*|\.\.[AI]\d+(?:\.\d+)*)?)"
)


class RouteError(RuntimeError):
    pass


@dataclass(frozen=True)
class RouteRule:
    route_id: str
    description: str
    path_globs: tuple[str, ...]
    topic_keywords: tuple[str, ...]
    required_handles: tuple[str, ...]
    optional_handles: tuple[str, ...]
    required_files: tuple[str, ...]
    optional_files: tuple[str, ...]
    max_required_bytes: int | None


@dataclass(frozen=True)
class DeclaredReading:
    """The reading an Issue declares in its `## Read` section (#5320)."""

    source: str
    body_sha256: str
    handles: tuple[str, ...]
    files: tuple[str, ...]


@dataclass(frozen=True)
class Config:
    pair_schema: str
    baseline_handles: tuple[str, ...]
    baseline_files: tuple[str, ...]
    baseline_optional_handles: tuple[str, ...]
    baseline_optional_files: tuple[str, ...]
    max_required_bytes: int
    routes: tuple[RouteRule, ...]
    examples: tuple[dict[str, Any], ...]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RouteError(f"cannot read JSON {path}: {exc}") from exc


def read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise RouteError(f"cannot read TOML {path}: {exc}") from exc


def normalize_repo_path(value: str) -> str:
    value = value.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    value = re.sub(r"/+", "/", value)
    if value in ("", "."):
        return "."
    pure = PurePosixPath(value)
    if pure.is_absolute() or PureWindowsPath(value).drive or ".." in pure.parts or any(ord(char) < 32 for char in value):
        raise RouteError(f"path must be repository-relative and non-traversing: {value!r}")
    return pure.as_posix()


def string_tuple(value: Any, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise RouteError(f"{field} must be an array of non-empty strings")
    return tuple(item.strip() for item in value)


def load_config(root: Path, relative: str = DEFAULT_CONFIG) -> Config:
    payload = read_toml(root / relative)
    if payload.get("schema_version") != SCHEMA:
        raise RouteError(f"unsupported route schema in {relative}")
    baseline = payload.get("baseline")
    if not isinstance(baseline, dict):
        raise RouteError("route config is missing [baseline]")
    max_required = baseline.get("max_required_bytes", 262_144)
    if not isinstance(max_required, int) or max_required <= 0:
        raise RouteError("baseline.max_required_bytes must be a positive integer")

    raw_routes = payload.get("route")
    if not isinstance(raw_routes, list) or not raw_routes:
        raise RouteError("route config requires at least one [[route]]")
    routes: list[RouteRule] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_routes):
        if not isinstance(raw, dict):
            raise RouteError(f"route[{index}] must be a table")
        route_id = str(raw.get("id", "")).strip()
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", route_id):
            raise RouteError(f"invalid route id: {route_id!r}")
        if route_id in seen:
            raise RouteError(f"duplicate route id: {route_id}")
        seen.add(route_id)
        description = str(raw.get("description", "")).strip()
        if not description:
            raise RouteError(f"route {route_id} has no description")
        path_globs = string_tuple(raw.get("path_globs"), f"route {route_id}.path_globs")
        topic_keywords = tuple(
            item.casefold()
            for item in string_tuple(raw.get("topic_keywords"), f"route {route_id}.topic_keywords")
        )
        if not path_globs and not topic_keywords:
            raise RouteError(f"route {route_id} has no match conditions")
        route_max = raw.get("max_required_bytes")
        if route_max is not None and (not isinstance(route_max, int) or route_max <= 0):
            raise RouteError(f"route {route_id}.max_required_bytes must be positive")
        routes.append(
            RouteRule(
                route_id=route_id,
                description=description,
                path_globs=path_globs,
                topic_keywords=topic_keywords,
                required_handles=string_tuple(raw.get("required_handles"), f"route {route_id}.required_handles"),
                optional_handles=string_tuple(raw.get("optional_handles"), f"route {route_id}.optional_handles"),
                required_files=string_tuple(raw.get("required_files"), f"route {route_id}.required_files"),
                optional_files=string_tuple(raw.get("optional_files"), f"route {route_id}.optional_files"),
                max_required_bytes=route_max,
            )
        )

    raw_examples = payload.get("coverage", {}).get("example", []) if isinstance(payload.get("coverage"), dict) else []
    if raw_examples is None:
        raw_examples = []
    if not isinstance(raw_examples, list):
        raise RouteError("coverage.example must be an array of tables")
    examples: list[dict[str, Any]] = []
    for raw in raw_examples:
        if not isinstance(raw, dict):
            raise RouteError("coverage example must be a table")
        unsupported = sorted(set(raw) - set(COVERAGE_KEYS))
        if unsupported:
            raise RouteError(
                f"coverage example has unsupported key(s) {unsupported}; "
                f"supported keys are {list(COVERAGE_KEYS)}"
            )
        path = normalize_repo_path(str(raw.get("path", "")))
        expected = string_tuple(raw.get("expect_routes"), f"coverage example {path}.expect_routes")
        examples.append(
            {
                "path": path,
                "topic": str(raw.get("topic", "")),
                "expect_routes": expected,
                "expect_required_handles": string_tuple(
                    raw.get("expect_required_handles"),
                    f"coverage example {path}.expect_required_handles",
                ),
                "expect_absent_routes": string_tuple(
                    raw.get("expect_absent_routes"),
                    f"coverage example {path}.expect_absent_routes",
                ),
            }
        )

    return Config(
        pair_schema=str(payload.get("pair_schema", "")),
        baseline_handles=string_tuple(baseline.get("required_handles"), "baseline.required_handles"),
        baseline_files=string_tuple(baseline.get("required_files"), "baseline.required_files"),
        baseline_optional_handles=string_tuple(baseline.get("optional_handles"), "baseline.optional_handles"),
        baseline_optional_files=string_tuple(baseline.get("optional_files"), "baseline.optional_files"),
        max_required_bytes=max_required,
        routes=tuple(routes),
        examples=tuple(examples),
    )


def handle_key(handle: str) -> tuple[Any, ...]:
    appendix = re.fullmatch(r"APPENDIX-([A-Z])", handle)
    if appendix:
        return (2, ord(appendix.group(1)))
    match = re.fullmatch(r"([AI])(\d+(?:\.\d+)*)", handle)
    if not match:
        return (9, handle)
    return (0 if match.group(1) == "A" else 1, *(int(piece) for piece in match.group(2).split(".")))


def expand_selector(selector: str, handles: dict[str, dict[str, Any]]) -> list[str]:
    selector = selector.strip()
    if not selector:
        raise RouteError("empty handle selector")
    if selector.endswith(".*"):
        prefix = selector[:-2]
        matched = [handle for handle in handles if handle == prefix or handle.startswith(prefix + ".")]
    elif ".." in selector:
        start, end = (part.strip() for part in selector.split("..", 1))
        if start not in handles or end not in handles:
            missing = [item for item in (start, end) if item not in handles]
            raise RouteError(f"range selector {selector!r} has unknown endpoint(s): {', '.join(missing)}")
        start_key, end_key = handle_key(start), handle_key(end)
        if start_key > end_key:
            raise RouteError(f"reversed handle range: {selector}")
        family = start.split(".", 1)[0][0]
        if end.split(".", 1)[0][0] != family:
            raise RouteError(f"cross-book range is prohibited: {selector}")
        matched = [
            handle for handle in handles
            if handle.startswith(family) and start_key <= handle_key(handle) <= end_key
        ]
    else:
        matched = [selector] if selector in handles else []
    if not matched:
        raise RouteError(f"handle selector resolves to nothing: {selector}")
    return sorted(set(matched), key=handle_key)


def expand_selectors(selectors: Iterable[str], handles: dict[str, dict[str, Any]]) -> list[str]:
    values: set[str] = set()
    for selector in selectors:
        values.update(expand_selector(selector, handles))
    return sorted(values, key=handle_key)


# A normative fragment is titled `<handle>. <prose title>` (or
# `<handle> <prose title>`). The handle token itself never participates in
# topic matching: routing is chosen by the prose title the writer described the
# work with, never by the identifier they happened to grep for.
FRAGMENT_TITLE_PREFIX_RE = re.compile(r"^(?:APPENDIX-[A-Z]|[AI]\d+(?:\.\d+)*)[.]?[ \t]+")


def fragment_title_tokens(title: str) -> list[str]:
    """Tokenize a fragment's prose title, dropping its leading handle token."""
    return topic_tokens(FRAGMENT_TITLE_PREFIX_RE.sub("", title, count=1))


def governing_handles(
    handles: dict[str, dict[str, Any]], topic: str
) -> list[str]:
    """Handles whose prose title the causal property names directly.

    A writer states the causal property in prose ("oracle ownership and test
    change governance"). When that prose names a fragment's own title, that
    fragment governs the work regardless of which path globs or route keywords
    happen to match, so it is a required read. Only a full contiguous coverage
    of the fragment's complete title qualifies, which keeps the result small
    and evidence-bearing rather than a fuzzy keyword expansion.
    """
    wanted = topic_tokens(topic)
    if not wanted:
        return []
    selected: list[str] = []
    for handle in sorted(handles):
        title = str(handles[handle].get("title", ""))
        if not title:
            continue
        title_wanted = fragment_title_tokens(title)
        if not title_wanted or len(title_wanted) > len(wanted):
            continue
        if any(
            list(wanted[offset:offset + len(title_wanted)]) == title_wanted
            for offset in range(len(wanted) - len(title_wanted) + 1)
        ):
            selected.append(handle)
    return sorted(selected, key=handle_key)


def path_matches(path: str, pattern: str) -> bool:
    path = normalize_repo_path(path)
    pattern = normalize_repo_path(pattern)
    if fnmatch.fnmatchcase(path, pattern):
        return True
    # Make `dir/**` include the directory itself and `**/name` include root name.
    if pattern.endswith("/**") and path == pattern[:-3].rstrip("/"):
        return True
    if pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:]):
        return True
    return False


def topic_tokens(text: str) -> list[str]:
    """Split topic text into case-insensitive alphanumeric tokens."""
    return TOPIC_TOKEN_RE.findall(text.casefold())


def keyword_token_hit(topic_token_list: Sequence[str], keyword: str) -> bool:
    """Match one casefolded keyword against tokenized topic text.

    A single-word keyword matches only a whole topic token; a multiword
    keyword matches only a contiguous token run. Fragments inside a longer
    token (``ors`` in ``errors``, ``cli`` in ``clippy``) never match.
    Legitimate inflections must be listed as explicit keyword variants in
    the route configuration.
    """
    wanted = TOPIC_TOKEN_RE.findall(keyword)
    if not wanted:
        return False
    width = len(wanted)
    return any(
        list(topic_token_list[offset:offset + width]) == wanted
        for offset in range(len(topic_token_list) - width + 1)
    )


def matched_routes(config: Config, paths: Sequence[str], topic: str) -> list[RouteRule]:
    normalized = tuple(normalize_repo_path(path) for path in paths)
    tokens = topic_tokens(topic)
    matched: list[RouteRule] = []
    for route in config.routes:
        path_hit = any(
            path_matches(path, pattern)
            for path in normalized
            for pattern in route.path_globs
        )
        topic_hit = bool(tokens) and any(
            keyword_token_hit(tokens, keyword) for keyword in route.topic_keywords
        )
        if path_hit or topic_hit:
            matched.append(route)
    return matched


def git_changed_paths(root: Path, changed_from: str) -> list[str]:
    if not changed_from.strip():
        raise RouteError("--changed-from cannot be empty")
    command = ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMRTUXB", f"{changed_from}...HEAD"]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RouteError(f"git diff failed for {changed_from}: {completed.stderr.strip()}")
    paths = [normalize_repo_path(line) for line in completed.stdout.splitlines() if line.strip()]
    if not paths:
        raise RouteError(f"no changed paths found from {changed_from} to HEAD")
    return sorted(set(paths))


def _reading_item_token(text: str) -> str:
    """Return the selector or path an Issue reading list item names."""
    text = text.strip()
    link = re.match(r"\[[^\]]*\]\(([^)\s]+)\)", text)
    if link:
        return link.group(1)
    code = re.match(r"`([^`]+)`", text)
    if code:
        return code.group(1).strip()
    return text.split()[0].rstrip(",;:") if text.split() else ""


def parse_issue_reading(body: str) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Parse the `## Read` / `## Читать` section of an Issue body.

    Each list item names one handle selector (`I5.19`, `I1.1..I1.8`, `A4.*`,
    `APPENDIX-L`) or one repository file as its first token, optionally in
    backticks or as a Markdown link; the rest of the line is a free comment.
    Returns ``None`` when the body has no such section. An invalid item fails
    closed in parsing or repository resolution instead of being skipped. Fenced code
    blocks are tracked explicitly: list items and headings inside a
    fence are ignored, and a fence closes only with a run of the
    same character at least as long as the opening run. A second
    real `## Read` section is ambiguous and rejected instead of
    silently shadowed.
    """
    handles: list[str] = []
    files: list[str] = []
    fence: tuple[str, int] | None = None
    found = False
    in_section = False
    level = 0
    in_comment = False
    list_indent: int | None = None
    for line in body.replace("\r\n", "\n").split("\n"):
        # The declaration grammar is a visible ATX heading and flat list, not
        # list-shaped examples inside fenced/indented code or HTML comments.
        if fence is not None:
            closed = re.fullmatch(r" {0,3}(`{3,}|~{3,})[ \t]*", line)
            if closed and closed[1][0] == fence[0] and len(closed[1]) >= fence[1]:
                fence = None
            continue
        if not in_comment:
            if line.startswith("    ") or line.startswith("\t"):
                continue
            opened = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", line)
            if opened and not (opened[1][0] == "`" and "`" in opened[2]):
                fence = (opened[1][0], len(opened[1]))
                continue
        # Comments may begin after prose, not only at column zero. Preserve
        # visible columns so removing a comment cannot manufacture a heading.
        visible: list[str] = []
        offset = 0
        code_spans = [match.span() for match in re.finditer(r"(?<!`)(`+)(?!`)(.*?)\1(?!`)", line)]
        while offset < len(line):
            if in_comment:
                end = line.find("-->", offset)
                stop = len(line) if end < 0 else end + 3
                visible.append(" " * (stop - offset))
                offset = stop
                in_comment = end < 0
            else:
                start = line.find("<!--", offset)
                for first, last in code_spans:
                    if first <= start < last:
                        start = line.find("<!--", last)
                if start < 0:
                    visible.append(line[offset:])
                    break
                visible.append(line[offset:start])
                offset = start
                in_comment = True
        line = "".join(visible)
        if line.startswith("    ") or line.startswith("\t"):
            continue
        heading = re.fullmatch(r" {0,3}(#{1,6})[ \t]+(.*?)[ \t]*", line)
        if heading:
            title = re.sub(r"[ \t]+#+[ \t]*$", "", heading[2]).casefold()
            is_read = len(heading[1]) == 2 and title in ISSUE_READING_HEADINGS
            if is_read:
                if found:
                    raise RouteError("ambiguous duplicate `## Read` section; keep exactly one")
                found, in_section, level = True, True, len(heading[1])
            elif in_section and len(heading[1]) <= level:
                in_section = False
            continue
        if not in_section:
            continue
        item = re.match(r" {0,3}(?:[-*+]|\d+[.)])[ \t]+(.*)$", line)
        if not item:
            continue
        indent = len(line) - len(line.lstrip(" "))
        if list_indent is None:
            list_indent = indent
        elif indent != list_indent:
            raise RouteError("Issue reading list must be flat; nested items are ambiguous")
        token = _reading_item_token(item.group(1))
        if not token:
            raise RouteError("empty Issue reading list item")
        if HANDLE_SELECTOR_RE.fullmatch(token):
            handles.append(token)
            continue
        if "://" in token:
            raise RouteError(f"Issue reading item must be a handle or repository file, not a URL: {token}")
        path = normalize_repo_path(token.split("#", 1)[0])
        # Repository resolution, not punctuation, decides whether this is a
        # file. Root files such as LICENSE and Justfile have no extension.
        files.append(path)
    if not found:
        return None
    if not handles and not files:
        raise RouteError("the Issue `## Read` section lists no handles or files")
    return tuple(dict.fromkeys(handles)), tuple(dict.fromkeys(files))


def declared_reading_from_body(body: str, source: str) -> DeclaredReading:
    parsed = parse_issue_reading(body)
    if parsed is None:
        raise RouteError(
            f"{source} has no `## Read` section; list the handles and files the change "
            "needs there (draft one with `docs_router.py route --path ... --format issue`)"
        )
    handles, files = parsed
    return DeclaredReading(
        source=source,
        body_sha256=sha256_bytes(body.encode("utf-8")),
        handles=handles,
        files=files,
    )


def fetch_issue_body(root: Path, issue: str) -> str:
    """Return the live Issue body with its exact bytes.

    `gh --jq .body` prints the body with an appended formatting
    newline, which would change `body_sha256` for every Issue. The
    reader requests the raw JSON document instead and decodes the
    `body` field verbatim, so the receipt hashes the exact Issue
    body bytes with no remapping. The authoritative `number` field
    must identify the requested Issue; anything else fails closed.
    An offline `--issue-body` file keeps its own provenance and is
    never labeled as the live Issue.
    """
    number = issue.strip().lstrip("#")
    if not number.isdigit():
        raise RouteError(f"--issue expects an Issue number: {issue!r}")
    command = ["gh", "issue", "view", number, "--json", "body,number"]
    try:
        completed = subprocess.run(
            command, cwd=root, capture_output=True, text=True, encoding="utf-8", check=False
        )
    except OSError as exc:
        raise RouteError(f"cannot run gh for Issue #{number}: {exc}; use --issue-body <file>") from exc
    if completed.returncode != 0:
        raise RouteError(
            f"gh issue view {number} failed: {completed.stderr.strip()}; use --issue-body <file>"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RouteError(
            f"gh returned a non-JSON Issue document for #{number}: {exc}; use --issue-body <file>"
        ) from exc
    if not isinstance(payload, dict) or type(payload.get("number")) is not int or payload["number"] != int(number):
        raise RouteError(f"gh response does not identify the requested Issue #{number}")
    body = payload.get("body")
    if not isinstance(body, str):
        raise RouteError(f"gh returned no body for Issue #{number}; use --issue-body <file>")
    return body


def load_declared_reading(root: Path, issue: str | None, issue_body: Path | None) -> DeclaredReading | None:
    if issue and issue_body:
        raise RouteError("use either --issue or --issue-body, not both")
    if issue:
        number = issue.strip().lstrip("#")
        return declared_reading_from_body(fetch_issue_body(root, number), f"Issue #{number}")
    if issue_body:
        # Read the capture as raw bytes and decode UTF-8 explicitly:
        # a text-mode read would universal-newline-normalize CRLF away
        # before hashing, so a verbatim offline capture would not hash
        # identically to the live JSON body. The final newline is part
        # of the capture and is never stripped, and the offline source
        # label stays distinct from the live Issue provenance.
        try:
            raw = issue_body.read_bytes()
        except OSError as exc:
            raise RouteError(f"cannot read Issue body file {issue_body}: {exc}") from exc
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RouteError(f"Issue body file {issue_body} is not UTF-8: {exc}") from exc
        return declared_reading_from_body(text, f"Issue body file {issue_body.name}")
    return None


def ancestor_agent_files(root: Path, paths: Sequence[str]) -> list[str]:
    found = {"AGENTS.md"} if (root / "AGENTS.md").is_file() else set()
    for raw in paths:
        path = PurePosixPath(normalize_repo_path(raw))
        parts = path.parts[:-1] if (root / path).suffix else path.parts
        for end in range(1, len(parts) + 1):
            candidate = PurePosixPath(*parts[:end], "AGENTS.md").as_posix()
            if (root / candidate).is_file():
                found.add(candidate)
    return sorted(found)


def repository_file(root: Path, relative: str, role: str) -> Path:
    """Resolve a reading file without granting external path authority."""
    relative = normalize_repo_path(relative)
    if relative in LEGACY_BOOKS:
        raise RouteError(f"legacy compatibility map cannot be routed as {role}: {relative}")
    path = root / relative
    try:
        if not path.resolve().is_relative_to(root.resolve()):
            raise RouteError(f"routed {role} file escapes repository: {relative}")
    except (OSError, ValueError) as exc:
        raise RouteError(f"invalid routed {role} file: {relative}") from exc
    if not path.is_file():
        raise RouteError(f"routed {role} file does not exist: {relative}")
    return path


def file_record(root: Path, relative: str, role: str) -> dict[str, Any]:
    relative = normalize_repo_path(relative)
    path = repository_file(root, relative, role)
    return {
        "kind": "file",
        "role": role,
        "path": relative,
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def fragment_records(
    handles_selected: Sequence[str],
    handles: dict[str, dict[str, Any]],
    role: str,
    *,
    root: Path,
) -> list[dict[str, Any]]:
    by_path: dict[str, dict[str, Any]] = {}
    for handle in handles_selected:
        record = handles[handle]
        path = str(record["path"])
        repository_file(root, path, role)
        target = by_path.setdefault(
            path,
            {
                "kind": "fragment",
                "role": role,
                "path": path,
                "sha256": str(record["fragment_sha256"]),
                "bytes": int(record["fragment_bytes"]),
                "handles": [],
                "anchors": [],
            },
        )
        if target["sha256"] != str(record["fragment_sha256"]):
            raise RouteError(f"fragment hash disagreement in handle index: {path}")
        target["handles"].append(handle)
        target["anchors"].append(str(record["anchor"]))
    return sorted(by_path.values(), key=lambda item: item["path"])


def coalesce_records(items: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """One verified payload per path, retaining every indexed handle."""
    by_path: dict[str, dict[str, Any]] = {}
    for item in items:
        path = str(item["path"])
        previous = by_path.get(path)
        if previous is None:
            by_path[path] = dict(item)
            continue
        if (previous["sha256"], previous["bytes"]) != (item["sha256"], item["bytes"]):
            raise RouteError(f"reading item identity disagreement: {path}")
        if item["kind"] == "fragment":
            previous["kind"] = "fragment"
        for field in ("handles", "anchors"):
            values = set(previous.get(field, ())) | set(item.get(field, ()))
            if values:
                previous[field] = sorted(values, key=handle_key) if field == "handles" else sorted(values)
    return list(by_path.values())


def route_payload(
    root: Path,
    config: Config,
    paths: Sequence[str],
    topic: str,
    declared: DeclaredReading | None = None,
) -> dict[str, Any]:
    normalized_paths = sorted(set(normalize_repo_path(path) for path in paths))
    if not normalized_paths and declared is None:
        raise RouteError("at least one --path, --changed-from result or --issue is required")
    index = read_json(root / DEFAULT_INDEX)
    if index.get("schema_version") != INDEX_SCHEMA:
        raise RouteError("unsupported handle index schema")
    handles = index.get("handles")
    if not isinstance(handles, dict) or not handles:
        raise RouteError("handle index has no handles")
    receipt = read_toml(root / DEFAULT_RECEIPT)
    if config.pair_schema and receipt.get("schema_version") != config.pair_schema:
        raise RouteError(
            f"route config expects pair schema {config.pair_schema}, found {receipt.get('schema_version')}"
        )
    pair_key = str(receipt.get("pair_key", ""))
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", pair_key):
        raise RouteError("normative pair receipt has no valid pair key")

    routes = matched_routes(config, normalized_paths, topic)
    if not routes and declared is None:
        raise RouteError(
            "no non-baseline documentation route matched; add a route before mutating this scope"
        )

    limits = [config.max_required_bytes]
    if declared is None:
        required_selectors = list(config.baseline_handles)
        optional_selectors = list(config.baseline_optional_handles)
        required_files = list(config.baseline_files)
        optional_files = list(config.baseline_optional_files)
        for route in routes:
            required_selectors.extend(route.required_handles)
            optional_selectors.extend(route.optional_handles)
            required_files.extend(route.required_files)
            optional_files.extend(route.optional_files)
            if route.max_required_bytes is not None:
                limits.append(route.max_required_bytes)
    else:
        # The Issue names what the change needs (#5320). Only the Decision
        # Safety Floor, the declared items and the nearest AGENTS.md files are
        # required; everything the path routes would add stays as optional
        # pointers that are opened only when the work crosses their boundary.
        required_selectors = [*config.baseline_handles, *declared.handles]
        required_files = list(declared.files)
        optional_selectors = list(config.baseline_optional_handles)
        optional_files = [*config.baseline_files, *config.baseline_optional_files]
        for route in routes:
            optional_selectors.extend(route.required_handles)
            optional_selectors.extend(route.optional_handles)
            optional_files.extend(route.required_files)
            optional_files.extend(route.optional_files)
    agent_scope = [*normalized_paths, *(declared.files if declared is not None else ())]
    required_files.extend(ancestor_agent_files(root, agent_scope))

    # The causal property names its own governing fragment; a route table gap
    # must not silently demote it to one-hop optional material (#929, #958,
    # #1730, #2970). Resolved from the prose title, so it names the governing
    # fragment without widening any glob, keyword, or required byte ceiling.
    governing = governing_handles(handles, topic)
    selected_handles = set(expand_selectors(required_selectors, handles))
    if declared is not None:
        absent = set(governing) - selected_handles
        if absent:
            raise RouteError(
                "the topic names governing handles absent from the Issue `## Read`: "
                + ", ".join(sorted(absent, key=handle_key))
                + "; declare them explicitly rather than silently expanding the context"
            )
    else:
        selected_handles.update(governing)
    required_handles = sorted(selected_handles, key=handle_key)
    optional_handles = [
        handle for handle in expand_selectors(optional_selectors, handles)
        if handle not in set(required_handles)
    ]
    required_items = fragment_records(required_handles, handles, "required", root=root)
    optional_items = fragment_records(optional_handles, handles, "optional", root=root)
    required_fragment_paths = {item["path"] for item in required_items}
    optional_items = [item for item in optional_items if item["path"] not in required_fragment_paths]

    for relative in sorted(set(required_files)):
        required_items.append(file_record(root, relative, "required"))
    for relative in sorted(set(optional_files) - set(required_files)):
        optional_items.append(file_record(root, relative, "optional"))

    required_items = coalesce_records(required_items)
    required_paths = {item["path"] for item in required_items}
    optional_items = coalesce_records([item for item in optional_items if item["path"] not in required_paths])

    required_items.sort(key=lambda item: (0 if item["kind"] == "file" else 1, item["path"]))
    optional_items.sort(key=lambda item: (0 if item["kind"] == "file" else 1, item["path"]))
    required_bytes = sum(int(item["bytes"]) for item in required_items)
    required_limit = max(limits)
    if required_bytes > required_limit:
        raise RouteError(
            f"required route payload is {required_bytes} bytes, above limit {required_limit}; "
            "split the route or move one-hop material to optional"
        )

    core = {
        "schema_version": SCHEMA,
        "pair_key": pair_key,
        "paths": normalized_paths,
        "topic": topic.strip(),
        "matched_routes": [route.route_id for route in routes],
        "governing_handles": governing,
        "required": required_items,
        "optional": optional_items,
        "required_bytes": required_bytes,
        "required_limit_bytes": required_limit,
    }
    if declared is not None:
        core["declared_reading"] = {
            "source": declared.source,
            "body_sha256": declared.body_sha256,
            "handles": list(declared.handles),
            "files": list(declared.files),
        }
    canonical = json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    core["receipt_id"] = "sha256:" + sha256_bytes(canonical)
    return core


def assert_required_handles(
    root: Path,
    handles: dict[str, dict[str, Any]],
    payload: dict[str, Any],
    expected: Sequence[str],
    label: str,
) -> None:
    """Prove each expected handle is a REQUIRED fragment at its indexed path and current hash.

    A route name match, an ``optional`` entry, or a textual link is not evidence: the
    handle must resolve through the handle index to a required fragment whose recorded
    SHA-256 still equals the fragment bytes on disk.
    """
    required_fragments = {
        str(item["path"]): item
        for item in payload["required"]
        if item.get("kind") == "fragment"
    }
    optional_paths = {
        str(item["path"]) for item in payload["optional"] if item.get("kind") == "fragment"
    }
    for handle in expected:
        record = handles.get(handle)
        if record is None:
            raise RouteError(f"{label} expects handle {handle} which the index does not define")
        index_path = str(record["path"])
        index_sha = str(record["fragment_sha256"])
        item = required_fragments.get(index_path)
        if item is None:
            if index_path in optional_paths:
                raise RouteError(
                    f"{label}: handle {handle} resolves to {index_path} only as optional; "
                    "it must be a required read"
                )
            raise RouteError(
                f"{label}: required payload has no fragment {index_path} for handle {handle}; "
                f"required={sorted(required_fragments)}"
            )
        if handle not in item.get("handles", ()):
            raise RouteError(
                f"{label}: required fragment {index_path} does not carry handle {handle}; "
                f"handles={item.get('handles', [])}"
            )
        if str(item["sha256"]) != index_sha:
            raise RouteError(
                f"{label}: required fragment {index_path} hash {item['sha256']} "
                f"differs from the handle index {index_sha}"
            )
        current = sha256_file(repository_file(root, index_path, "required fragment"))
        if current != index_sha:
            raise RouteError(
                f"{label}: required fragment {index_path} is stale upstream; "
                f"indexed={index_sha} on-disk={current}"
            )


def render_route(payload: dict[str, Any], *, full_pointers: bool = False) -> str:
    lines = [
        "# Documentation read route",
        "",
        f"Receipt: `{payload['receipt_id']}`",
        f"Normative pair: `{payload['pair_key']}`",
        f"Matched routes: `{', '.join(payload['matched_routes'])}`",
        f"Required payload: `{payload['required_bytes']}` / `{payload['required_limit_bytes']}` bytes",
        "",
        "## Scope",
        "",
    ]
    for path in payload["paths"]:
        lines.append(f"- `{path}`")
    if payload["topic"]:
        lines.append(f"- Causal property: {payload['topic']}")
    declared = payload.get("declared_reading")
    if declared:
        lines.append(
            f"- Declared reading: {declared['source']} — "
            f"{len(declared['handles'])} handle selector(s), {len(declared['files'])} file(s)"
        )
    lines.extend(["", "## Required — read all before mutation", ""])
    for item in payload["required"]:
        handles = f" — handles `{', '.join(item['handles'])}`" if item.get("handles") else ""
        lines.append(
            f"- `{item['path']}`{handles} — `{item['bytes']}` bytes — SHA-256 `{item['sha256']}`"
        )
    lines.extend(["", "## Optional one-hop expansion", ""])
    if payload["optional"]:
        if full_pointers:
            for item in payload["optional"]:
                handles = f" — handles `{', '.join(item['handles'])}`" if item.get("handles") else ""
                lines.append(
                    f"- `{item['path']}`{handles} — `{item['bytes']}` bytes — SHA-256 `{item['sha256']}`"
                )
        else:
            lines.append(f"- {len(payload['optional'])} optional pointers; no optional content is included.")
            lines.append("- Inspect them only at a boundary crossing with `--full-pointers` or `--format json`.")
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "Re-run the router when the path set, causal property, authority boundary, or evidence scope expands.",
            "The two `ELIOT_*` compatibility maps do not satisfy this receipt.",
            "",
        ]
    )
    return "\n".join(lines)


def render_issue_reading_draft(root: Path, config: Config, payload: dict[str, Any]) -> str:
    """Draft an Issue `## Read` section from a path route for the author to trim.

    The Decision Safety Floor and the nearest AGENTS.md files are always added
    by the reader, so the draft lists only the route-specific handles and files.
    """
    index = read_json(root / DEFAULT_INDEX).get("handles", {})
    floor = set(expand_selectors(config.baseline_handles, index))
    lines = [
        "## Read",
        "",
        f"<!-- Drafted by docs_router.py from routes {', '.join(payload['matched_routes'])}. "
        "Keep only what this change needs. The Decision Safety Floor and the nearest "
        "AGENTS.md files are added automatically. -->",
    ]
    for item in payload["required"]:
        if item["kind"] == "fragment":
            for handle in item["handles"]:
                if handle in floor:
                    continue
                title = FRAGMENT_TITLE_PREFIX_RE.sub("", str(index.get(handle, {}).get("title", "")), count=1)
                lines.append(f"- `{handle}` — {title} ({item['bytes']} B)")
        elif item["path"] not in config.baseline_files and not item["path"].endswith("AGENTS.md"):
            lines.append(f"- `{item['path']}` ({item['bytes']} B)")
    return "\n".join(lines) + "\n"


def render_routes_markdown(config: Config) -> str:
    lines = [
        GENERATED_MARKER,
        "# Task and path documentation routes",
        "",
        "This is a human-readable projection of [`route-rules.toml`](route-rules.toml).",
        "The executable source is the TOML file plus [`scripts/docs_router.py`](../../scripts/docs_router.py).",
        "",
        "For an owning Issue:",
        "",
        "```text",
        "python scripts/docs_router.py route --issue <number> --path <repository/path>",
        "```",
        "",
        "Required reading is the Issue's `## Read` list, the Decision Safety Floor and applicable `AGENTS.md` files.",
        "The path matrix below supplies optional pointers in Issue mode. Human output summarizes them by default;",
        "inspect `--full-pointers` or `--format json` only when crossing an optional boundary.",
        "",
        "Without an Issue, use `route --path <repository/path> --topic \"<causal property>\"`.",
        "Path mode requires the global baseline and all matching specialized routes; a path may match several routes.",
        "Draft a new Issue reading list with `route --path <repository/path> --format issue`, then trim it to the change.",
        "",
        "## Global required baseline",
        "",
        "- Handles: " + ", ".join(f"`{item}`" for item in config.baseline_handles),
        "- Files: " + ", ".join(f"`{item}`" for item in config.baseline_files),
        f"- Default maximum required payload: `{config.max_required_bytes}` bytes",
        "",
        "## Route matrix",
        "",
        "| Route | Purpose | Path patterns | Topic keywords | Required selectors | Optional selectors |",
        "|---|---|---|---|---|---|",
    ]
    for route in config.routes:
        paths = "<br>".join(f"`{item}`" for item in route.path_globs) or "—"
        topics = "<br>".join(f"`{item}`" for item in route.topic_keywords) or "—"
        required = "<br>".join(f"`{item}`" for item in route.required_handles) or "—"
        optional = "<br>".join(f"`{item}`" for item in route.optional_handles) or "—"
        lines.append(
            f"| `{route.route_id}` | {route.description} | {paths} | {topics} | {required} | {optional} |"
        )
    lines.extend(
        [
            "",
            "## Enforcement",
            "",
            "`python scripts/docs_router.py check --root .` validates selectors, files,",
            "route membership plus per-example merged payloads, expected required handles",
            "at their indexed fragment path and current hash, routes a path must not gain,",
            "tracked-path coverage, route-size ceilings, and this generated projection.",
            "Unknown material paths fail closed.",
            "",
        ]
    )
    return "\n".join(lines)


def tracked_files(root: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=False,
    )
    if completed.returncode == 0 and completed.stdout:
        return sorted(
            normalize_repo_path(raw.decode("utf-8"))
            for raw in completed.stdout.split(b"\x00")
            if raw
        )
    values: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.relative_to(root).parts):
            continue
        values.append(path.relative_to(root).as_posix())
    return sorted(values)


def coverage_exempt(path: str) -> bool:
    if path in LEGACY_BOOKS:
        return True
    if path.startswith("docs/architecture/") and (
        path.endswith("/manifest.json")
        or "/sections/" in path
        or re.fullmatch(r"docs/architecture/(?:A|I|APPENDIX)-.+\.md", path)
        or path in {
            "docs/architecture/HANDLE_INDEX.md",
            "docs/architecture/handle-index.json",
            "docs/architecture/ROUTES.md",
            "docs/architecture/SPLIT_REPORT.md",
            "docs/architecture/READING_PROTOCOL.md",
            "docs/architecture/architecture/README.md",
            "docs/architecture/implementation/README.md",
        }
    ):
        return True
    return False


def check(root: Path, config_relative: str = DEFAULT_CONFIG) -> dict[str, Any]:
    root = root.resolve()
    config = load_config(root, config_relative)
    index = read_json(root / DEFAULT_INDEX)
    if index.get("schema_version") != INDEX_SCHEMA:
        raise RouteError("unsupported handle index schema")
    handles = index.get("handles")
    if not isinstance(handles, dict) or not handles:
        raise RouteError("handle index has no handles")

    selector_count = 0
    for selector in (
        *config.baseline_handles,
        *config.baseline_optional_handles,
        *(selector for route in config.routes for selector in route.required_handles),
        *(selector for route in config.routes for selector in route.optional_handles),
    ):
        expand_selector(selector, handles)
        selector_count += 1

    files_to_check = set(config.baseline_files) | set(config.baseline_optional_files)
    for route in config.routes:
        files_to_check.update(route.required_files)
        files_to_check.update(route.optional_files)
    for relative in sorted(files_to_check):
        if relative in LEGACY_BOOKS:
            raise RouteError(f"route config references a legacy compatibility map: {relative}")
        if not (root / normalize_repo_path(relative)).is_file():
            raise RouteError(f"route config references missing file: {relative}")

    examples_checked = 0
    route_ids = {route.route_id for route in config.routes}
    for example in config.examples:
        actual = {route.route_id for route in matched_routes(config, [example["path"]], example["topic"])}
        missing = set(example["expect_routes"]) - actual
        unknown = set(example["expect_routes"]) - route_ids
        if unknown:
            raise RouteError(f"coverage example names unknown routes: {sorted(unknown)}")
        if missing:
            raise RouteError(
                f"coverage example {example['path']} missed routes {sorted(missing)}; actual={sorted(actual)}"
            )
        examples_checked += 1

    # Exercise every example's merged payload on its own and prove the expected
    # handles are required fragments at the indexed path and current hash. Route
    # name membership above cannot see a handle demoted to `optional`.
    example_payloads_checked = 0
    required_handle_expectations = 0
    for example in config.examples:
        label = f"coverage example {example['path']}"
        absent = set(example["expect_absent_routes"]) - route_ids
        if absent:
            raise RouteError(f"{label} names unknown routes in expect_absent_routes: {sorted(absent)}")
        if not (root / example["path"]).exists():
            raise RouteError(f"{label} does not exist: {example['path']}")
        actual_ids = {route.route_id for route in matched_routes(config, [example["path"]], example["topic"])}
        gained = sorted(actual_ids & set(example["expect_absent_routes"]))
        if gained:
            raise RouteError(
                f"{label} matched routes it must not gain by proximity: {gained}; "
                f"actual={sorted(actual_ids)}"
            )
        payload = route_payload(root, config, [example["path"]], example["topic"])
        assert_required_handles(
            root, handles, payload, example["expect_required_handles"], label
        )
        required_handle_expectations += len(example["expect_required_handles"])
        example_payloads_checked += 1

    uncovered: list[str] = []
    tracked = tracked_files(root)
    for path in tracked:
        if coverage_exempt(path):
            continue
        if not matched_routes(config, [path], ""):
            uncovered.append(path)
    if uncovered:
        preview = "\n".join(f"  - {path}" for path in uncovered[:100])
        more = "" if len(uncovered) <= 100 else f"\n  ... {len(uncovered) - 100} more"
        raise RouteError(f"tracked material paths without a documentation route ({len(uncovered)}):\n{preview}{more}")

    # Exercise each route with one matching path or keyword and enforce the actual payload ceiling.
    route_payloads_checked = 0
    for route in config.routes:
        candidate = next((example for example in config.examples if route.route_id in example["expect_routes"]), None)
        if candidate is not None:
            path, topic = candidate["path"], candidate["topic"]
        elif route.path_globs:
            # Config validation still checks selectors; no synthetic filesystem path is invented here.
            continue
        elif route.topic_keywords:
            path, topic = "README.md", route.topic_keywords[0]
        else:
            continue
        if (root / path).exists():
            payload = route_payload(root, config, [path], topic)
            if route.route_id not in payload["matched_routes"]:
                raise RouteError(f"route payload exercise failed for {route.route_id}")
            route_payloads_checked += 1

    expected_routes = render_routes_markdown(config)
    routes_path = root / DEFAULT_ROUTES_MD
    if not routes_path.is_file() or routes_path.read_text(encoding="utf-8") != expected_routes:
        raise RouteError(
            f"stale {DEFAULT_ROUTES_MD}; run docs_router.py sync --root ."
        )

    result = {
        "routes": len(config.routes),
        "selectors": selector_count,
        "examples": examples_checked,
        "tracked_files": len(tracked),
        "payloads_checked": route_payloads_checked,
        "example_payloads": example_payloads_checked,
        "required_handles": required_handle_expectations,
    }
    print(
        "DOC_ROUTER_CHECK: PASS "
        + " ".join(f"{key}={value}" for key, value in result.items())
    )
    return result


def sync(root: Path, config_relative: str = DEFAULT_CONFIG) -> None:
    root = root.resolve()
    config = load_config(root, config_relative)
    target = root / DEFAULT_ROUTES_MD
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_routes_markdown(config), encoding="utf-8", newline="")
    print(f"DOC_ROUTER_SYNC: PASS path={DEFAULT_ROUTES_MD} routes={len(config.routes)}")


def self_test() -> None:
    handles = {
        "A0.1": {},
        "A0.2": {},
        "A0.3": {},
        "I1": {},
        "I1.1": {},
        "I1.2": {},
        "I2": {},
    }
    if expand_selector("A0.1..A0.3", handles) != ["A0.1", "A0.2", "A0.3"]:
        raise RouteError("range expansion self-test failed")
    if expand_selector("I1.*", handles) != ["I1", "I1.1", "I1.2"]:
        raise RouteError("prefix expansion self-test failed")
    if not path_matches("bins/eliot-host/src/main.rs", "bins/eliot-host/**"):
        raise RouteError("path glob self-test failed")
    core = {"a": 1, "b": [2, 3]}
    if sha256_bytes(json.dumps(core, sort_keys=True).encode()) != sha256_bytes(json.dumps(core, sort_keys=True).encode()):
        raise RouteError("receipt determinism self-test failed")
    try:
        normalize_repo_path("../escape")
    except RouteError:
        pass
    else:
        raise RouteError("path traversal self-test failed")

    body = (
        "## Problem\n\nText.\n\n```text\n## Read\n- `I9.9`\n```\n\n"
        "## Читать\n\n- `I1.1..I1.8` — process topology\n- A4.*\n"
        "- [policy](docs/DEPENDENCY_POLICY.md#admission)\n- `I1.1..I1.8` duplicate\n\n"
        "## Done when\n\n- `I7.7` is not reading\n"
    )
    if parse_issue_reading(body) != (("I1.1..I1.8", "A4.*"), ("docs/DEPENDENCY_POLICY.md",)):
        raise RouteError("Issue reading section self-test failed")
    if parse_issue_reading("## Problem\n\nNo reading.\n") is not None:
        raise RouteError("missing Issue reading section self-test failed")
    if parse_issue_reading("## Read\n- LICENSE\n") != ((), ("LICENSE",)):
        raise RouteError("extensionless Issue reading file self-test failed")
    for bad in ("## Read\n\n- ../outside\n", "## Read\n\n- https://example.com/doc\n", "## Read\n\nnone\n"):
        try:
            parse_issue_reading(bad)
        except RouteError:
            pass
        else:
            raise RouteError(f"unrecognized Issue reading item was accepted: {bad!r}")
    print("DOC_ROUTER_SELF_TEST: PASS cases=8")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    route_parser = sub.add_parser("route")
    route_parser.add_argument("--root", type=Path, default=Path("."))
    route_parser.add_argument("--path", action="append", default=[])
    route_parser.add_argument("--changed-from")
    route_parser.add_argument("--topic", default="")
    route_parser.add_argument("--issue", help="Issue number whose `## Read` section declares the reading")
    route_parser.add_argument("--issue-body", type=Path, help="Issue body file (offline alternative to --issue)")
    route_parser.add_argument("--format", choices=("markdown", "json", "issue"), default="markdown")
    route_parser.add_argument("--full-pointers", action="store_true", help="Include the full optional pointer inventory in human output")
    route_parser.add_argument("--output", type=Path)

    check_parser = sub.add_parser("check")
    check_parser.add_argument("--root", type=Path, default=Path("."))
    check_parser.add_argument("--config", default=DEFAULT_CONFIG)

    sync_parser = sub.add_parser("sync")
    sync_parser.add_argument("--root", type=Path, default=Path("."))
    sync_parser.add_argument("--config", default=DEFAULT_CONFIG)

    sub.add_parser("self-test")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "self-test":
            self_test()
        elif args.command == "sync":
            sync(args.root, args.config)
        elif args.command == "check":
            check(args.root, args.config)
        elif args.command == "route":
            root = args.root.resolve()
            paths = list(args.path)
            if args.changed_from:
                paths.extend(git_changed_paths(root, args.changed_from))
            config = load_config(root)
            declared = load_declared_reading(root, args.issue, args.issue_body)
            payload = route_payload(root, config, paths, args.topic, declared)
            if args.format == "json":
                rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
            elif args.format == "issue":
                rendered = render_issue_reading_draft(root, config, payload)
            else:
                rendered = render_route(payload, full_pointers=args.full_pointers)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(rendered, encoding="utf-8", newline="")
            else:
                sys.stdout.write(rendered)
        else:
            raise RouteError(f"unknown command: {args.command}")
        return 0
    except RouteError as exc:
        print(f"DOC_ROUTER_FAIL: {exc}", file=sys.stderr)
        return 1
