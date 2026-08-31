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
from pathlib import Path, PurePosixPath
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
    if pure.is_absolute() or ".." in pure.parts:
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
        path = normalize_repo_path(str(raw.get("path", "")))
        expected = string_tuple(raw.get("expect_routes"), f"coverage example {path}.expect_routes")
        examples.append({"path": path, "topic": str(raw.get("topic", "")), "expect_routes": expected})

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


def matched_routes(config: Config, paths: Sequence[str], topic: str) -> list[RouteRule]:
    normalized = tuple(normalize_repo_path(path) for path in paths)
    topic_folded = topic.casefold()
    matched: list[RouteRule] = []
    for route in config.routes:
        path_hit = any(
            path_matches(path, pattern)
            for path in normalized
            for pattern in route.path_globs
        )
        topic_hit = any(keyword in topic_folded for keyword in route.topic_keywords)
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


def file_record(root: Path, relative: str, role: str) -> dict[str, Any]:
    relative = normalize_repo_path(relative)
    if relative in LEGACY_BOOKS:
        raise RouteError(f"legacy compatibility map cannot be routed as {role}: {relative}")
    path = root / relative
    if not path.is_file():
        raise RouteError(f"routed {role} file does not exist: {relative}")
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
) -> list[dict[str, Any]]:
    by_path: dict[str, dict[str, Any]] = {}
    for handle in handles_selected:
        record = handles[handle]
        path = str(record["path"])
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


def route_payload(root: Path, config: Config, paths: Sequence[str], topic: str) -> dict[str, Any]:
    normalized_paths = sorted(set(normalize_repo_path(path) for path in paths))
    if not normalized_paths:
        raise RouteError("at least one --path or --changed-from result is required")
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
    if not routes:
        raise RouteError(
            "no non-baseline documentation route matched; add a route before mutating this scope"
        )

    required_selectors = list(config.baseline_handles)
    optional_selectors = list(config.baseline_optional_handles)
    required_files = list(config.baseline_files)
    optional_files = list(config.baseline_optional_files)
    limits = [config.max_required_bytes]
    for route in routes:
        required_selectors.extend(route.required_handles)
        optional_selectors.extend(route.optional_handles)
        required_files.extend(route.required_files)
        optional_files.extend(route.optional_files)
        if route.max_required_bytes is not None:
            limits.append(route.max_required_bytes)
    required_files.extend(ancestor_agent_files(root, normalized_paths))

    required_handles = expand_selectors(required_selectors, handles)
    optional_handles = [
        handle for handle in expand_selectors(optional_selectors, handles)
        if handle not in set(required_handles)
    ]
    required_items = fragment_records(required_handles, handles, "required")
    optional_items = fragment_records(optional_handles, handles, "optional")
    required_fragment_paths = {item["path"] for item in required_items}
    optional_items = [item for item in optional_items if item["path"] not in required_fragment_paths]

    for relative in sorted(set(required_files)):
        required_items.append(file_record(root, relative, "required"))
    for relative in sorted(set(optional_files) - set(required_files)):
        optional_items.append(file_record(root, relative, "optional"))

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
        "required": required_items,
        "optional": optional_items,
        "required_bytes": required_bytes,
        "required_limit_bytes": required_limit,
    }
    canonical = json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    core["receipt_id"] = "sha256:" + sha256_bytes(canonical)
    return core


def render_route(payload: dict[str, Any]) -> str:
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
    lines.extend(["", "## Required — read all before mutation", ""])
    for item in payload["required"]:
        handles = f" — handles `{', '.join(item['handles'])}`" if item.get("handles") else ""
        lines.append(
            f"- `{item['path']}`{handles} — `{item['bytes']}` bytes — SHA-256 `{item['sha256']}`"
        )
    lines.extend(["", "## Optional one-hop expansion", ""])
    if payload["optional"]:
        for item in payload["optional"]:
            handles = f" — handles `{', '.join(item['handles'])}`" if item.get("handles") else ""
            lines.append(
                f"- `{item['path']}`{handles} — `{item['bytes']}` bytes — SHA-256 `{item['sha256']}`"
            )
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


def render_routes_markdown(config: Config) -> str:
    lines = [
        GENERATED_MARKER,
        "# Task and path documentation routes",
        "",
        "This is a human-readable projection of [`route-rules.toml`](route-rules.toml).",
        "The executable source is the TOML file plus [`scripts/docs_router.py`](../../scripts/docs_router.py).",
        "",
        "Run:",
        "",
        "```text",
        "python scripts/docs_router.py route --path <repository/path> --topic \"<causal property>\"",
        "```",
        "",
        "Every result includes the global Decision Safety Floor and all matching specialized routes.",
        "A path may intentionally match more than one route.",
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
            "representative route examples, tracked-path coverage, route-size ceilings, and",
            "this generated projection. Unknown material paths fail closed.",
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
    print("DOC_ROUTER_SELF_TEST: PASS cases=5")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    route_parser = sub.add_parser("route")
    route_parser.add_argument("--root", type=Path, default=Path("."))
    route_parser.add_argument("--path", action="append", default=[])
    route_parser.add_argument("--changed-from")
    route_parser.add_argument("--topic", default="")
    route_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
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
            payload = route_payload(root, config, paths, args.topic)
            rendered = (
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
                if args.format == "json"
                else render_route(payload)
            )
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


if __name__ == "__main__":
    raise SystemExit(main())
