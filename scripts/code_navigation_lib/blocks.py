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
        globs = raw.get("path_globs")
        handles = raw.get("documentation_handles", [])
        if not title or not responsibility or not route_topic:
            raise NavigationError(f"block {block_id} has an empty required field")
        if not isinstance(globs, list) or not globs:
            raise NavigationError(f"block {block_id}.path_globs must be non-empty")
        if not isinstance(handles, list):
            raise NavigationError(f"block {block_id}.documentation_handles must be an array")
        normalized_globs = [normalize_repo_path(str(item)) for item in globs]
        normalized_handles = [str(item).strip() for item in handles if str(item).strip()]
        blocks.append(
            {
                "id": block_id,
                "title": title,
                "responsibility": responsibility,
                "route_topic": route_topic,
                "path_globs": normalized_globs,
                "documentation_handles": normalized_handles,
            }
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
