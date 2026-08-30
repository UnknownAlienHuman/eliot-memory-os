"""Section selection, byte ranges, and content-addressed receipts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Sequence

from docs_router_core import (
    DOMAIN,
    RECEIPT_SCHEMA_VERSION,
    ROOT_HANDLE_RE,
    RouterConfig,
    RouterError,
    Selection,
    Slice,
    SourceDocument,
    canonical_json,
    normalize_repo_path,
    sha256_bytes,
    stable_unique,
)


def split_selector(selector: str) -> tuple[str, str | None]:
    normalized = selector.strip().upper().replace("–", "..").replace("—", "..")
    if ".." in normalized:
        start, end = normalized.split("..", 1)
        if not start or not end:
            raise RouterError(f"invalid section range: {selector}")
        return start, end
    return normalized, None


def document_for_handle(documents: dict[str, SourceDocument], handle: str) -> SourceDocument:
    if handle.startswith("A"):
        return documents["architecture"]
    if handle.startswith("I"):
        return documents["implementation"]
    raise RouterError(f"selector does not start with A or I: {handle}")


def resolve_selector(documents: dict[str, SourceDocument], selector: str) -> Slice:
    start_handle, end_handle = split_selector(selector)
    document = document_for_handle(documents, start_handle)
    by_handle = document.by_handle
    start_section = by_handle.get(start_handle)
    if start_section is None:
        raise RouterError(f"unknown section handle: {start_handle}")
    if end_handle is None:
        return Slice(
            source_id=document.source_id,
            source_path=document.path,
            selectors=(selector,),
            handles=(start_handle,),
            start_line=start_section.start_line,
            end_line=start_section.end_line,
            start=start_section.start,
            end=start_section.end,
        )
    end_document = document_for_handle(documents, end_handle)
    if end_document.source_id != document.source_id:
        raise RouterError(f"cross-document section range is not allowed: {selector}")
    end_section = by_handle.get(end_handle)
    if end_section is None:
        raise RouterError(f"unknown section handle: {end_handle}")
    if end_section.start < start_section.start:
        raise RouterError(f"reversed section range: {selector}")
    ordered_handles = tuple(
        section.handle
        for section in document.sections
        if start_section.start <= section.start <= end_section.start
    )
    return Slice(
        source_id=document.source_id,
        source_path=document.path,
        selectors=(selector,),
        handles=ordered_handles,
        start_line=start_section.start_line,
        end_line=end_section.end_line,
        start=start_section.start,
        end=end_section.end,
    )


def coalesce_slices(slices: Sequence[Slice]) -> tuple[Slice, ...]:
    ordered = sorted(slices, key=lambda item: (item.source_id, item.start, item.end))
    merged: list[Slice] = []
    for current in ordered:
        if not merged:
            merged.append(current)
            continue
        previous = merged[-1]
        if previous.source_id == current.source_id and current.start <= previous.end:
            merged[-1] = Slice(
                source_id=previous.source_id,
                source_path=previous.source_path,
                selectors=stable_unique((*previous.selectors, *current.selectors)),
                handles=stable_unique((*previous.handles, *current.handles)),
                start_line=min(previous.start_line, current.start_line),
                end_line=max(previous.end_line, current.end_line),
                start=min(previous.start, current.start),
                end=max(previous.end, current.end),
            )
        else:
            merged.append(current)
    return tuple(merged)


def resolve_selection(
    documents: dict[str, SourceDocument],
    selection: Selection,
    include_optional: bool,
) -> tuple[Slice, ...]:
    selectors = list(selection.required_selectors)
    if include_optional:
        selectors.extend(selection.optional_selectors)
    return coalesce_slices([resolve_selector(documents, selector) for selector in selectors])


def root_partition(document: SourceDocument) -> tuple[Slice, ...]:
    roots = [section for section in document.sections if ROOT_HANDLE_RE.fullmatch(section.handle)]
    roots.sort(key=lambda section: section.start)
    if not roots:
        raise RouterError(f"no root section handles in {document.path.as_posix()}")
    blocks: list[Slice] = []
    if roots[0].start > 0:
        blocks.append(
            Slice(
                source_id=document.source_id,
                source_path=document.path,
                selectors=("PREAMBLE",),
                handles=(),
                start_line=1,
                end_line=roots[0].start_line - 1,
                start=0,
                end=roots[0].start,
            )
        )
    for index, section in enumerate(roots):
        end = roots[index + 1].start if index + 1 < len(roots) else len(document.data)
        end_line = (
            roots[index + 1].start_line - 1
            if index + 1 < len(roots)
            else document.data.count(b"\n") + 1
        )
        blocks.append(
            Slice(
                source_id=document.source_id,
                source_path=document.path,
                selectors=(section.handle,),
                handles=(section.handle,),
                start_line=section.start_line,
                end_line=end_line,
                start=section.start,
                end=end,
            )
        )
    reconstructed = b"".join(document.data[block.start : block.end] for block in blocks)
    if reconstructed != document.data:
        raise RouterError(f"lossless root partition failed for {document.path.as_posix()}")
    return tuple(blocks)


def safe_name(value: str) -> str:
    value = value.replace("..", "-through-")
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")
    return value or "slice"


def relative_to_root(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def slice_record(item: Slice, document: SourceDocument) -> dict[str, Any]:
    data = document.data[item.start : item.end]
    return {
        "source": item.source_id,
        "source_path": item.source_path.as_posix(),
        "selectors": list(item.selectors),
        "handles": list(item.handles),
        "start_line": item.start_line,
        "end_line": item.end_line,
        "byte_count": len(data),
        "sha256": sha256_bytes(data),
    }


def build_receipt(
    repo_root: Path,
    pair: dict[str, Any],
    config: RouterConfig,
    documents: dict[str, SourceDocument],
    selection: Selection,
    slices: Sequence[Slice],
    paths: Sequence[str],
    tasks: Sequence[str],
    include_optional: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "pair_key": pair["pair_key"],
        "reading_map_path": config.path.as_posix(),
        "reading_map_sha256": sha256_bytes((repo_root / config.path).read_bytes()),
        "sources": {
            source_id: {
                "path": relative_to_root(document.path, repo_root),
                "sha256": document.sha256,
            }
            for source_id, document in sorted(documents.items())
        },
        "input": {
            "paths": [normalize_repo_path(path) for path in paths],
            "tasks": [task.strip().lower() for task in tasks],
            "include_optional": include_optional,
            "fallback_used": bool(selection.unknown_paths or selection.unknown_tasks),
            "unknown_paths": list(selection.unknown_paths),
            "unknown_tasks": list(selection.unknown_tasks),
        },
        "routes": [
            {
                "id": route.route_id,
                "description": route.description,
                "priority": route.priority,
            }
            for route in selection.routes
        ],
        "required_selectors": list(selection.required_selectors),
        "optional_selectors": list(selection.optional_selectors),
        "resolved_slices": [
            slice_record(item, documents[item.source_id]) for item in slices
        ],
    }
    payload["receipt_sha256"] = sha256_bytes(DOMAIN + canonical_json(payload))
    return payload

