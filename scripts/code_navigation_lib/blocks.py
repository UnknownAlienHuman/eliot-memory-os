"""Logical responsibility blocks and documentation-router integration."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from typing import Any

from .common import (
    DEFAULT_BLOCKS,
    DEFAULT_DOC_ROUTER,
    NavigationError,
    SCHEMA,
    normalize_repo_path,
    read_toml,
)


class _RouteBoundBlock(dict[str, Any]):
    """Keep configured route IDs authoritative over sample-path projections."""

    def __init__(self, values: dict[str, Any], declared_routes: list[str]) -> None:
        super().__init__(values)
        dict.__setitem__(self, "documentation_route_ids", declared_routes)

    def __setitem__(self, key: str, value: Any) -> None:
        if key != "documentation_route_ids" or key not in self:
            super().__setitem__(key, value)
            return

        if not isinstance(value, list):
            raise NavigationError(
                f"logical block {self.get('id')} produced invalid sample route IDs"
            )
        sample_routes = [str(item).strip() for item in value if str(item).strip()]
        declared = list(dict.__getitem__(self, key))
        missing = [route_id for route_id in declared if route_id not in sample_routes]
        if missing:
            raise NavigationError(
                f"logical block {self.get('id')} sample path omits declared "
                f"documentation routes: {', '.join(missing)}"
            )
        # The sample is only a consistency probe. Preserve the configured
        # denominator rather than replacing it with sample-specific extras.


def _unique_strings(
    value: Any,
    field: str,
    *,
    path_values: bool = False,
) -> list[str]:
    if not isinstance(value, list) or not value:
        raise NavigationError(f"{field} must be a non-empty array")
    normalized: list[str] = []
    for item in value:
        text = str(item).strip()
        if not text:
            raise NavigationError(f"{field} contains an empty value")
        normalized.append(normalize_repo_path(text) if path_values else text)
    if len(normalized) != len(set(normalized)):
        raise NavigationError(f"{field} contains duplicate values")
    return normalized


def load_blocks(root: Path, relative: str = DEFAULT_BLOCKS) -> list[dict[str, Any]]:
    payload = read_toml(root / relative)
    if payload.get("schema_version") != SCHEMA:
        raise NavigationError(f"unsupported logical-block schema in {relative}")
    raw_blocks = payload.get("block")
    if not isinstance(raw_blocks, list) or not raw_blocks:
        raise NavigationError("logical block config requires at least one [[block]]")

    blocks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_blocks):
        if not isinstance(raw, dict):
            raise NavigationError(f"block[{index}] must be a table")
        block_id = str(raw.get("id", "")).strip()
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", block_id):
            raise NavigationError(f"invalid logical block id: {block_id!r}")
        if block_id in seen:
            raise NavigationError(f"duplicate logical block id: {block_id}")
        seen.add(block_id)

        title = str(raw.get("title", "")).strip()
        responsibility = str(raw.get("responsibility", "")).strip()
        route_topic = str(raw.get("route_topic", "")).strip()
        if not title or not responsibility or not route_topic:
            raise NavigationError(f"block {block_id} has an empty required field")

        globs = _unique_strings(
            raw.get("path_globs"),
            f"block {block_id}.path_globs",
            path_values=True,
        )
        handles = _unique_strings(
            raw.get("documentation_handles"),
            f"block {block_id}.documentation_handles",
        )
        routes = _unique_strings(
            raw.get("documentation_route_ids"),
            f"block {block_id}.documentation_route_ids",
        )
        invalid_routes = [
            route_id
            for route_id in routes
            if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", route_id)
        ]
        if invalid_routes:
            raise NavigationError(
                f"block {block_id} has invalid documentation route IDs: "
                + ", ".join(invalid_routes)
            )

        blocks.append(
            _RouteBoundBlock(
                {
                    "id": block_id,
                    "title": title,
                    "responsibility": responsibility,
                    "route_topic": route_topic,
                    "path_globs": globs,
                    "documentation_handles": handles,
                },
                routes,
            )
        )
    return blocks


def load_docs_router(root: Path) -> Any:
    path = root / DEFAULT_DOC_ROUTER
    if not path.is_file():
        raise NavigationError(f"documentation router is missing: {DEFAULT_DOC_ROUTER}")
    spec = importlib.util.spec_from_file_location("eliot_docs_router", path)
    if spec is None or spec.loader is None:
        raise NavigationError("cannot load documentation router")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - preserve router failure context
        raise NavigationError(f"cannot import documentation router: {exc}") from exc
    return module
