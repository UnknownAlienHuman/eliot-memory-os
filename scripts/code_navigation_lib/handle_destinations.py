"""Canonical handle-to-fragment and anchor resolution for code navigation."""

from __future__ import annotations

import json
import posixpath
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .common import (
    DEFAULT_HANDLE_INDEX,
    NavigationError,
    normalize_repo_path,
    read_json,
)

SCHEMA = "eliot-handle-destinations-v1"


def natural_handle_key(handle: str) -> tuple[Any, ...]:
    if handle.startswith("APPENDIX-"):
        return (9, handle)
    match = re.fullmatch(r"([AI])(\d+(?:\.\d+)*)", handle)
    if not match:
        return (8, handle)
    prefix_order = 0 if match.group(1) == "A" else 1
    numbers = tuple(int(piece) for piece in match.group(2).split("."))
    return (prefix_order, *numbers)


def _markdown_anchors(text: str) -> set[str]:
    counts: dict[str, int] = {}
    anchors: set[str] = set()
    fenced = False
    for line in text.splitlines():
        fence = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if fence:
            fenced = not fenced
            continue
        if fenced:
            continue
        heading = re.match(r"^\s{0,3}#{1,6}[ \t]+(.+?)[ \t]*#*[ \t]*$", line)
        if not heading:
            continue
        title = heading.group(1).strip()
        base = re.sub(r"<[^>]+>", "", title.lower())
        base = re.sub(r"[^\w\-\s]", "", base, flags=re.UNICODE)
        base = re.sub(r"\s", "-", base)
        count = counts.get(base, 0)
        anchor = base if count == 0 else f"{base}-{count}"
        counts[base] = count + 1
        anchors.add(anchor)
    return anchors


class DestinationResolver:
    """Resolve documentation handles to immutable canonical fragment destinations."""

    def __init__(self, root: Path, handle_index_relative: str = DEFAULT_HANDLE_INDEX) -> None:
        self.root = root.resolve()
        self.handle_index_path = self.root / handle_index_relative
        if not self.handle_index_path.is_file():
            raise NavigationError(
                f"canonical handle index is missing: {handle_index_relative}"
            )
        payload = read_json(self.handle_index_path)
        if payload.get("schema_version") != "eliot-handle-index-v1":
            raise NavigationError(
                f"unsupported handle index schema in {handle_index_relative}"
            )
        raw_handles = payload.get("handles")
        if not isinstance(raw_handles, dict) or not raw_handles:
            raise NavigationError(
                f"canonical handle index has no handle entries: {handle_index_relative}"
            )
        self._handles: dict[str, dict[str, Any]] = {}
        self._load_and_validate(raw_handles)

    def _load_and_validate(self, raw_handles: dict[str, Any]) -> None:
        for raw_handle, record in raw_handles.items():
            handle = str(raw_handle).strip()
            if not handle:
                raise NavigationError("handle index contains an empty handle")
            if not isinstance(record, dict):
                raise NavigationError(f"handle {handle} is not a valid record")
            required = ("source", "title", "path", "anchor")
            for key in required:
                if key not in record or not str(record[key]).strip():
                    raise NavigationError(f"handle {handle} is missing required field: {key}")
            raw_path = record["path"]
            normalized_path = normalize_repo_path(str(raw_path))
            if normalized_path != raw_path:
                raise NavigationError(f"handle {handle} path is not canonical: {raw_path!r}")
            fragment_file = self.root / PurePosixPath(normalized_path)
            if not fragment_file.is_file():
                raise NavigationError(
                    f"canonical fragment for handle {handle} is missing: {normalized_path}"
                )
            anchor = str(record["anchor"]).strip()
            if not anchor:
                raise NavigationError(f"handle {handle} has an empty anchor")
            self._handles[handle] = {
                "handle": handle,
                "title": str(record["title"]).strip(),
                "path": normalized_path,
                "anchor": anchor,
                "source": str(record["source"]).strip(),
                "direct_destination": f"{normalized_path}#{anchor}",
            }

    def resolve(self, handle: str) -> dict[str, Any]:
        val = str(handle).strip()
        if not val:
            raise NavigationError("cannot resolve empty documentation handle")
        if "HANDLE_INDEX" in val:
            raise NavigationError(f"generic HANDLE_INDEX destination is rejected: {handle}")
        record = self._handles.get(val)
        if record is None:
            raise NavigationError(f"unknown documentation handle: {val}")
        return dict(record)

    def relative_link(self, from_doc: str, handle: str) -> str:
        record = self.resolve(handle)
        from_dir = str(PurePosixPath(normalize_repo_path(from_doc)).parent)
        rel_path = posixpath.relpath(record["path"], start=from_dir)
        return f"{rel_path}#{record['anchor']}"

    def all_handles(self) -> dict[str, dict[str, Any]]:
        return dict(self._handles)


_cached_resolvers: dict[Path, DestinationResolver] = {}


def get_resolver(root: Path) -> DestinationResolver:
    resolved_root = root.resolve()
    resolver = _cached_resolvers.get(resolved_root)
    if resolver is None:
        resolver = DestinationResolver(resolved_root)
        _cached_resolvers[resolved_root] = resolver
    return resolver


def clear_cache() -> None:
    _cached_resolvers.clear()
