"""Canonical handle-to-fragment and anchor resolution for code navigation."""

from __future__ import annotations

import posixpath
import re
from pathlib import Path, PurePosixPath
from typing import Any

import docs_shards as links

from .common import (
    DEFAULT_HANDLE_INDEX,
    NavigationError,
    normalize_repo_path,
    read_json,
    sha256_file,
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


def resolve_repository_ref(root: Path, ref: str) -> dict[str, Any]:
    """Resolve a canonical repository file, optionally with a Markdown anchor."""
    root = root.resolve()
    path, separator, anchor = ref.partition("#")
    if (not path or normalize_repo_path(path) != path or ":" in path
            or "?" in path or "%" in ref or (separator and not anchor)):
        raise NavigationError(f"non-canonical repository contract reference: {ref!r}")
    status, target = links._case_resolution(root, root / path)
    if status != "exact" or target is None:
        raise NavigationError(f"contract reference {status}: {ref}")
    if any((root / Path(*target.relative_to(root).parts[:index])).is_symlink()
           for index in range(1, len(target.relative_to(root).parts) + 1)):
        raise NavigationError(f"symlinked contract reference: {ref}")
    if not target.is_file():
        raise NavigationError(f"contract reference is not a file: {ref}")
    if anchor:
        if target.suffix.lower() not in (".md", ".markdown"):
            raise NavigationError(f"contract anchor requires Markdown: {ref}")
        try:
            anchors = links.markdown_anchors(target.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            raise NavigationError(f"cannot read contract reference {ref}: {exc}") from exc
        if anchor not in anchors:
            raise NavigationError(f"contract anchor is absent: {ref}")
    return {"path": path, "anchor": anchor, "sha256": sha256_file(target)}


class DestinationResolver:
    """Resolve current file references and lazily loaded retained V2 handles."""

    def __init__(self, root: Path, handle_index_relative: str = DEFAULT_HANDLE_INDEX) -> None:
        self.root = root.resolve()
        self.handle_index_path = self.root / handle_index_relative
        self._handles: dict[str, dict[str, Any]] | None = None
        self._owners: dict[str, str] = {}

    @property
    def uses_legacy_index(self) -> bool:
        return self._handles is not None

    def _load(self) -> None:
        if self._handles is not None:
            return
        handle_index_relative = self.handle_index_path.relative_to(self.root).as_posix()
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
        self._handles = {}
        try:
            self._load_and_validate(raw_handles)
        except NavigationError:
            self._handles = None
            self._owners.clear()
            raise

    def _load_and_validate(self, raw_handles: dict[str, Any]) -> None:
        for raw_handle, record in raw_handles.items():
            handle = str(raw_handle).strip()
            if not handle:
                raise NavigationError("handle index contains an empty handle")
            if handle in self._handles:
                raise NavigationError(
                    f"handle index declares a duplicate handle identity: {handle}"
                )
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
            destination = f"{normalized_path}#{anchor}"
            owner = self._owners.get(destination)
            if owner is not None:
                raise NavigationError(
                    f"handle index declares an ambiguous destination claimed by both "
                    f"{owner} and {handle}: {destination}"
                )
            self._owners[destination] = handle
            self._handles[handle] = {
                "handle": handle,
                "title": str(record["title"]).strip(),
                "path": normalized_path,
                "anchor": anchor,
                "source": str(record["source"]).strip(),
                "direct_destination": destination,
            }

    def resolve(self, handle: str) -> dict[str, Any]:
        val = str(handle).strip()
        if not val:
            raise NavigationError("cannot resolve empty documentation handle")
        if "HANDLE_INDEX" in val:
            raise NavigationError(f"generic HANDLE_INDEX destination is rejected: {handle}")
        if "/" in val or "#" in val or val.endswith((".md", ".markdown", ".toml")):
            record = resolve_repository_ref(self.root, val)
            return {**record, "handle": val, "title": val,
                    "source": "repository_file", "direct_destination": val}
        self._load()
        key = val.partition(":")[2] if val.startswith("ELIOT_") else val
        record = self._handles.get(key)
        if record is None:
            raise NavigationError(f"unknown documentation handle: {val}")
        if val.startswith("ELIOT_"):
            source = {"ELIOT_ARCHITECTURE": "architecture",
                      "ELIOT_IMPLEMENTATION": "implementation"}.get(val.partition(":")[0])
            if source is None or record["source"] != source:
                raise NavigationError(f"documentation prefix disagrees with source: {val}")
        return {**record, "sha256": sha256_file(self.root / record["path"])}

    def relative_link(self, from_doc: str, handle: str) -> str:
        record = self.resolve(handle)
        from_dir = str(PurePosixPath(normalize_repo_path(from_doc)).parent)
        rel_path = posixpath.relpath(record["path"], start=from_dir)
        return rel_path + (f"#{record['anchor']}" if record["anchor"] else "")

    def all_handles(self) -> dict[str, dict[str, Any]]:
        self._load()
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
