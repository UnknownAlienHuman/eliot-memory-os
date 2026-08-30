"""Rendering, materialization, catalog, and corpus verification."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

from docs_router_core import (
    DOMAIN,
    RouterConfig,
    RouterError,
    Selection,
    Slice,
    SourceDocument,
    canonical_json,
    sha256_bytes,
    stable_unique,
)
from docs_router_select import (
    build_receipt,
    resolve_selector,
    root_partition,
    safe_name,
    slice_record,
)


def render_route_markdown(receipt: dict[str, Any]) -> str:
    lines = [
        "# Mandatory documentation reading set",
        "",
        f"Normative pair: `{receipt['pair_key']}`",
        f"Reading map: `{receipt['reading_map_path']}` (`{receipt['reading_map_sha256']}`)",
        "",
        "## Matched routes",
        "",
    ]
    routes = receipt["routes"]
    if routes:
        for route in routes:
            description = f" — {route['description']}" if route["description"] else ""
            lines.append(f"- `{route['id']}`{description}")
    else:
        lines.append("- Base reading set only.")
    lines.extend(["", "## Read every slice below", ""])
    for index, item in enumerate(receipt["resolved_slices"], start=1):
        selectors = ", ".join(f"`{value}`" for value in item["selectors"])
        lines.append(
            f"{index}. {selectors} — `{item['source_path']}` lines "
            f"{item['start_line']}–{item['end_line']}; "
            f"{item['byte_count']} bytes; SHA-256 `{item['sha256']}`."
        )
    lines.extend(
        [
            "",
            "Do not begin implementation until every listed slice has been read. "
            "Rerun routing whenever the changed-path set or task scope expands.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
        + b"\n"
    )


def materialize_selected(
    output: Path,
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
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    receipt = build_receipt(
        repo_root,
        pair,
        config,
        documents,
        selection,
        slices,
        paths,
        tasks,
        include_optional,
    )
    materialized: list[dict[str, Any]] = []
    for index, item in enumerate(slices, start=1):
        document = documents[item.source_id]
        data = document.data[item.start : item.end]
        label = (
            item.selectors[0]
            if len(item.selectors) == 1
            else f"{item.selectors[0]}--{item.selectors[-1]}"
        )
        filename = f"{index:03d}-{item.source_id}-{safe_name(label)}.md"
        target = output / filename
        target.write_bytes(data)
        materialized.append({"file": filename, **slice_record(item, document)})
    receipt["materialized_files"] = materialized
    receipt_without_hash = dict(receipt)
    receipt_without_hash.pop("receipt_sha256", None)
    receipt["receipt_sha256"] = sha256_bytes(
        DOMAIN + canonical_json(receipt_without_hash)
    )
    write_json(output / "reading-receipt.json", receipt)
    (output / "README.md").write_text(
        render_route_markdown(receipt), encoding="utf-8", newline="\n"
    )
    return receipt


def materialize_all(
    output: Path,
    pair: dict[str, Any],
    documents: dict[str, SourceDocument],
) -> dict[str, Any]:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    manifest: dict[str, Any] = {
        "schema_version": "eliot-lossless-doc-sections-v1",
        "pair_key": pair["pair_key"],
        "sources": {},
    }
    for source_id, document in sorted(documents.items()):
        directory = output / source_id
        directory.mkdir()
        blocks = root_partition(document)
        records: list[dict[str, Any]] = []
        for index, block in enumerate(blocks):
            label = block.selectors[0]
            filename = f"{index:02d}-{safe_name(label)}.md"
            data = document.data[block.start : block.end]
            (directory / filename).write_bytes(data)
            records.append(
                {
                    "file": f"{source_id}/{filename}",
                    **slice_record(block, document),
                }
            )
        reconstructed = b"".join(
            (output / record["file"]).read_bytes() for record in records
        )
        if reconstructed != document.data:
            raise RouterError(f"materialized corpus does not reconstruct {source_id}")
        manifest["sources"][source_id] = {
            "canonical_path": document.path.as_posix(),
            "canonical_sha256": document.sha256,
            "materialized_sha256": sha256_bytes(reconstructed),
            "blocks": records,
        }
    manifest_without_hash = dict(manifest)
    manifest["manifest_sha256"] = sha256_bytes(
        canonical_json(manifest_without_hash)
    )
    write_json(output / "manifest.json", manifest)
    return manifest


def validate_config_selectors(
    config: RouterConfig,
    documents: dict[str, SourceDocument],
) -> int:
    selectors = [*config.base_required, *config.base_optional]
    for route in config.routes:
        selectors.extend(route.required)
        selectors.extend(route.optional)
    count = 0
    for selector in stable_unique(selectors):
        resolve_selector(documents, selector)
        count += 1
    return count


def check_all(
    repo_root: Path,
    pair: dict[str, Any],
    config: RouterConfig,
    documents: dict[str, SourceDocument],
) -> dict[str, Any]:
    selector_count = validate_config_selectors(config, documents)
    partition_summary: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="eliot-doc-sections-") as temporary:
        manifest = materialize_all(Path(temporary), pair, documents)
        for source_id, source in manifest["sources"].items():
            if source["canonical_sha256"] != source["materialized_sha256"]:
                raise RouterError(
                    f"lossless reconstruction digest mismatch for {source_id}"
                )
            partition_summary[source_id] = {
                "sha256": source["canonical_sha256"],
                "blocks": len(source["blocks"]),
                "handles": len(documents[source_id].sections),
            }
    return {
        "status": "PASS",
        "pair_key": pair["pair_key"],
        "reading_map": config.path.as_posix(),
        "routes": len(config.routes),
        "validated_selectors": selector_count,
        "sources": partition_summary,
    }


def print_catalog(
    documents: dict[str, SourceDocument], output_format: str
) -> None:
    if output_format == "json":
        value = {
            source_id: [
                {
                    "handle": section.handle,
                    "title": section.title,
                    "start_line": section.start_line,
                    "end_line": section.end_line,
                    "byte_count": section.byte_count,
                }
                for section in document.sections
            ]
            for source_id, document in sorted(documents.items())
        }
        print(json.dumps(value, indent=2, ensure_ascii=False))
        return
    for source_id, document in sorted(documents.items()):
        print(f"# {source_id.title()} section catalog\n")
        print(f"Source: `{document.path.as_posix()}`  ")
        print(f"SHA-256: `{document.sha256}`\n")
        print("| Handle | Lines | Bytes | Title |")
        print("|---|---:|---:|---|")
        for section in document.sections:
            escaped_title = section.title.replace("|", "\\|")
            print(
                f"| `{section.handle}` | {section.start_line}–{section.end_line} | "
                f"{section.byte_count} | {escaped_title} |"
            )
        print()


def emit_content(
    slices: Sequence[Slice],
    documents: dict[str, SourceDocument],
    exact: bool,
) -> None:
    output = sys.stdout.buffer
    for index, item in enumerate(slices):
        document = documents[item.source_id]
        data = document.data[item.start : item.end]
        if not exact:
            if index:
                output.write(b"\n")
            selectors = ", ".join(item.selectors)
            marker = (
                f"<!-- ELIOT-DOC-SLICE source={item.source_id} selectors={selectors} "
                f"lines={item.start_line}-{item.end_line} "
                f"sha256={sha256_bytes(data)} -->\n"
            ).encode("utf-8")
            output.write(marker)
        output.write(data)

