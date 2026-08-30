"""Path routing, human/machine rendering, and deterministic validation."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

from .blocks import load_docs_router
from .cargo import nearest_agents
from .common import NavigationError, SCHEMA, normalize_repo_path, path_matches
from .registry import build_registry, matching_package
from .rust import module_locator


def route_payload(root: Path, path: str, topic: str | None = None) -> dict[str, Any]:
    registry = build_registry(root)
    path = normalize_repo_path(path)
    package = matching_package(registry, path)
    blocks = [
        block
        for block in registry["logical_blocks"]
        if any(path_matches(path, pattern) for pattern in block["path_globs"])
    ]
    effective_topic = topic or " ".join(
        block["route_topic"] for block in blocks
    ) or "repository source ownership and change impact"

    docs_router = load_docs_router(root)
    docs_config = docs_router.load_config(root)
    routes = docs_router.matched_routes(docs_config, [path], effective_topic)

    module = None
    if package and path.endswith(".rs"):
        package_relative = PurePosixPath(path).relative_to(package["root_path"]).as_posix()
        module = {"path": path, **module_locator(package["name"], package_relative)}

    package_view = None
    if package:
        package_view = {
            key: package[key]
            for key in (
                "name",
                "root_path",
                "manifest_path",
                "workspace_member",
                "default_member",
                "layer",
                "purpose",
                "source_maintenance_owner",
                "functional_cell_refs",
                "contract_refs",
                "targets",
                "logical_blocks",
            )
        }
        package_view["local_dependencies"] = [
            {
                "package": dependency["package"],
                "root_path": dependency["local_package_root"],
                "kind": dependency["kind"],
            }
            for dependency in package["dependencies"]
            if dependency["local_package_root"]
        ]
        package_view["reverse_dependencies"] = package["reverse_dependencies"]

    graph_intents = [
        {
            "stage": "pre-edit",
            "intent": "project, index status/schema, architecture, and symbol ownership",
            "suggested_tools": ["list_projects", "index_status", "get_graph_schema", "get_architecture", "search_graph"],
        },
        {
            "stage": "pre-edit",
            "intent": "inbound/outbound call and reference closure",
            "suggested_tools": ["trace_path", "query_graph"],
        },
        {
            "stage": "pre-edit",
            "intent": "index coverage for every cited or negatively searched path",
            "suggested_tools": ["check_index_coverage"],
        },
        {
            "stage": "post-edit",
            "intent": "map the exact diff to affected symbols and tests, then re-check coverage",
            "suggested_tools": ["detect_changes", "check_index_coverage"],
        },
    ]

    return {
        "schema_version": SCHEMA,
        "path": path,
        "topic": effective_topic,
        "nearest_agents": nearest_agents(root, path),
        "package": package_view,
        "module": module,
        "logical_blocks": [
            {
                "id": block["id"],
                "title": block["title"],
                "responsibility": block["responsibility"],
                "documentation_handles": block["documentation_handles"],
                "documentation_route_ids": block["documentation_route_ids"],
            }
            for block in blocks
        ],
        "documentation_route_ids": [route.route_id for route in routes],
        "documentation_router_command": (
            f'python scripts/docs_router.py route --path "{path}" '
            f'--topic "{effective_topic}"'
        ),
        "documentation_reader_command": (
            f'python scripts/docs_read.py read --path "{path}" '
            f'--topic "{effective_topic}" '
            '--output .eliot/docs-read-bundle.md '
            '--receipt-out .eliot/docs-read-receipt.json'
        ),
        "code_graph": {
            "adapter": "CodeBase Memory MCP",
            "required_assurance": "Verify tier for mutation; Auditor tier for exhaustive/negative claims",
            "query_intents": graph_intents,
            "hard_boundaries": [
                "graph output is derived navigation evidence, not source or semantic authority",
                "record project/index generation and coverage for every cited path",
                "stale, partial, ambiguous, skipped, or unknown coverage cannot prove absence, non-impact, dead code, or safe deletion",
                "read exact source and run owning verifiers before completion",
                "do not commit .codebase-memory or create a second watcher for the repository root",
            ],
        },
    }


def render_crates(registry: dict[str, Any]) -> str:
    lines = [
        "| Package | Path | Admission | Layer | Logical blocks |",
        "|---|---|---|---|---|",
    ]
    for package in registry["packages"]:
        admission = (
            "default"
            if package["default_member"]
            else "workspace"
            if package["workspace_member"]
            else "nonmember"
        )
        lines.append(
            f"| `{package['name']}` | `{package['root_path']}` | {admission} | "
            f"`{package['layer'] or '-'}` | "
            f"{', '.join(f'`{item}`' for item in package['logical_blocks']) or '-'} |"
        )
    return "\n".join(lines)


def render_modules(registry: dict[str, Any]) -> str:
    lines = [
        "| Module locator | File | Package | Role |",
        "|---|---|---|---|",
    ]
    for package in registry["packages"]:
        for module in package["rust_files"]:
            lines.append(
                f"| `{module['module_locator']}` | `{module['path']}` | "
                f"`{package['name']}` | {module['role']} |"
            )
    return "\n".join(lines)


def render_blocks(registry: dict[str, Any]) -> str:
    lines = [
        "| Logical block | Responsibility | Paths | Docs routes | Handles |",
        "|---|---|---|---|---|",
    ]
    for block in registry["logical_blocks"]:
        lines.append(
            f"| `{block['id']}` | {block['responsibility']} | "
            f"{'<br>'.join(f'`{item}`' for item in block['path_globs'])} | "
            f"{', '.join(f'`{item}`' for item in block['documentation_route_ids'])} | "
            f"{', '.join(f'`{item}`' for item in block['documentation_handles']) or '-'} |"
        )
    return "\n".join(lines)


def render_route(payload: dict[str, Any]) -> str:
    lines = [
        f"# Code navigation for `{payload['path']}`",
        "",
        f"- Documentation navigation: `{payload['documentation_router_command']}`",
        f"- Verified documentation read: `{payload['documentation_reader_command']}`",
        "- Documentation routes: "
        + (", ".join(f"`{item}`" for item in payload["documentation_route_ids"]) or "none"),
        "- Nearest agent contracts: "
        + (", ".join(f"`{item}`" for item in payload["nearest_agents"]) or "none"),
    ]
    package = payload.get("package")
    if package:
        admission = (
            "default"
            if package["default_member"]
            else "workspace"
            if package["workspace_member"]
            else "nonmember"
        )
        lines.extend(
            [
                f"- Package: `{package['name']}` at `{package['root_path']}` ({admission})",
                "- Local dependencies: "
                + (
                    ", ".join(
                        f"`{item['package']}` (`{item['root_path']}`)"
                        for item in package["local_dependencies"]
                    )
                    or "none"
                ),
                "- Reverse dependencies: "
                + (
                    ", ".join(
                        f"`{item['name']}` (`{item['root_path']}`)"
                        for item in package["reverse_dependencies"]
                    )
                    or "none"
                ),
            ]
        )
    else:
        lines.append("- Package: none")
    module = payload.get("module")
    if module:
        lines.append(
            f"- Filesystem module locator: `{module['module_locator']}` ({module['role']}; "
            "verify declaration/reachability in Code Graph and exact source)"
        )
    lines.append(
        "- Logical blocks: "
        + (
            ", ".join(f"`{item['id']}`" for item in payload["logical_blocks"])
            or "none"
        )
    )
    lines.extend(
        [
            "",
            "## Mandatory Code Graph loop",
            "",
            "1. Confirm the current project/index generation and run `get_graph_schema`.",
            "2. Use `get_architecture`/`search_graph`, then `trace_path` or read-only `query_graph` for the bounded symbol closure.",
            "3. Run `check_index_coverage` for every cited path and before any negative/exhaustive claim.",
            "4. Read exact source/contracts/tests and execute the owning verifier.",
            "5. After editing, run `detect_changes`, refresh/requery the graph, and repeat coverage checks.",
        ]
    )
    return "\n".join(lines)


def check(root: Path) -> None:
    first = build_registry(root)
    second = build_registry(root)
    if json.dumps(first, sort_keys=True) != json.dumps(second, sort_keys=True):
        raise NavigationError("code navigation registry is not deterministic")
    counts = first["counts"]
    print(
        "CODE_NAVIGATION_CHECK: PASS "
        f"workspace_members={counts['workspace_members']} "
        f"default_members={counts['default_members']} "
        f"nonmember_packages={counts['nonmember_packages']} "
        f"rust_files={counts['rust_files']} "
        f"logical_blocks={counts['logical_blocks']}"
    )
