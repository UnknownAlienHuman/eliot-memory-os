#!/usr/bin/env python3
"""Shard ELIOT's normative books without losing canonical source bytes.

The migration keeps the two historical entry paths as compact compatibility maps.
Canonical content lives in small Markdown fragments. A manifest records fragment
order, navigation-only link rewrites, and the original SHA-256 so verification can
reconstruct the exact adopted byte stream.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import html
import json
import posixpath
import re
import shutil
import sys
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

SCHEMA = "eliot-doc-shards-v1"
PAIR_SCHEMA = "eliot-normative-pair-v2-sharded"
GENERATED_MARKER = "<!-- generated: eliot-doc-shards-v1 -->"
ROUTING_START = "<!-- eliot-doc-routing:start -->"
ROUTING_END = "<!-- eliot-doc-routing:end -->"

SOURCE_SPECS = (
    {
        "key": "architecture",
        "legacy": "docs/architecture/ELIOT_ARCHITECTURE.md",
        "manifest": "docs/architecture/architecture/manifest.json",
        "entry": "docs/architecture/architecture/README.md",
        "prefix": "A",
        "label": "Architecture",
    },
    {
        "key": "implementation",
        "legacy": "docs/architecture/ELIOT_IMPLEMENTATION.md",
        "manifest": "docs/architecture/implementation/manifest.json",
        "entry": "docs/architecture/implementation/README.md",
        "prefix": "I",
        "label": "Implementation",
    },
)


class DocsError(RuntimeError):
    pass


@dataclass(frozen=True)
class Heading:
    level: int
    title: str
    char_start: int
    line: int
    handle: str | None
    source_anchor: str


@dataclass
class Fragment:
    index: int
    source_start: int
    source_end: int
    source_start_line: int
    source_end_line: int
    path: str
    text: str
    rendered_text: str
    rewrites: list[dict[str, Any]]
    headings: list[dict[str, Any]]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def repo_path(root: Path, relative: str) -> Path:
    return root / Path(relative)


def read_utf8(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise DocsError(f"expected UTF-8 text: {path}") from exc


def write_utf8(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


def github_slug_base(title: str) -> str:
    value = html.unescape(title).strip().lower()
    value = re.sub(r"<[^>]+>", "", value)
    value = re.sub(r"[^\w\-\s]", "", value, flags=re.UNICODE)
    value = re.sub(r"\s", "-", value, flags=re.UNICODE)
    return value


def assign_anchors(titles: Iterable[str]) -> list[str]:
    counts: dict[str, int] = {}
    anchors: list[str] = []
    for title in titles:
        base = github_slug_base(title)
        count = counts.get(base, 0)
        anchors.append(base if count == 0 else f"{base}-{count}")
        counts[base] = count + 1
    return anchors


def extract_handle(title: str) -> str | None:
    match = re.match(r"^([AI]\d+(?:\.\d+)*)(?=$|[\s.:;,\-–—])", title.strip())
    if match:
        return match.group(1)
    match = re.match(r"^Appendix\s+([A-Z])(?=$|[\s.:;,\-–—])", title.strip(), re.I)
    if match:
        return f"APPENDIX-{match.group(1).upper()}"
    return None


def iter_lines_with_offsets(text: str) -> Iterator[tuple[int, int, str]]:
    offset = 0
    for line_no, line in enumerate(text.splitlines(keepends=True), 1):
        yield line_no, offset, line
        offset += len(line)


def parse_headings(text: str) -> list[Heading]:
    raw: list[tuple[int, str, int, int]] = []
    fence_char: str | None = None
    fence_len = 0
    previous_plain: tuple[int, int, str] | None = None

    for line_no, offset, line in iter_lines_with_offsets(text):
        logical = line.rstrip("\r\n")
        fence_match = re.match(r"^\s{0,3}(`{3,}|~{3,})", logical)
        if fence_match:
            marker = fence_match.group(1)
            if fence_char is None:
                fence_char = marker[0]
                fence_len = len(marker)
            elif marker[0] == fence_char and len(marker) >= fence_len:
                fence_char = None
                fence_len = 0
            previous_plain = None
            continue
        if fence_char is not None:
            previous_plain = None
            continue

        atx = re.match(r"^\s{0,3}(#{1,6})[ \t]+(.+?)[ \t]*$", logical)
        if atx:
            title = re.sub(r"[ \t]+#+[ \t]*$", "", atx.group(2)).strip()
            if title:
                raw.append((len(atx.group(1)), title, offset, line_no))
            previous_plain = None
            continue

        setext = re.match(r"^\s{0,3}(=+|-+)[ \t]*$", logical)
        if setext and previous_plain is not None:
            prev_line_no, prev_offset, prev_text = previous_plain
            title = prev_text.strip()
            if title:
                raw.append((1 if setext.group(1)[0] == "=" else 2, title, prev_offset, prev_line_no))
            previous_plain = None
            continue

        if logical.strip() and not logical.lstrip().startswith(("<", "[", "|", ">")):
            previous_plain = (line_no, offset, logical)
        else:
            previous_plain = None

    raw.sort(key=lambda item: item[2])
    anchors = assign_anchors(item[1] for item in raw)
    return [
        Heading(
            level=level,
            title=title,
            char_start=offset,
            line=line_no,
            handle=extract_handle(title),
            source_anchor=anchor,
        )
        for (level, title, offset, line_no), anchor in zip(raw, anchors, strict=True)
    ]


def source_line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def choose_cuts(text: str, headings: Sequence[Heading]) -> list[int]:
    cuts = {0, len(text)}
    for heading in headings:
        if heading.level == 1 or heading.handle is not None:
            cuts.add(heading.char_start)

    for max_level, threshold in ((2, 48_000), (3, 64_000), (4, 80_000), (6, 120_000)):
        changed = True
        while changed:
            changed = False
            ordered = sorted(cuts)
            for start, end in zip(ordered, ordered[1:], strict=False):
                if len(text[start:end].encode("utf-8")) <= threshold:
                    continue
                candidates = [
                    h.char_start
                    for h in headings
                    if start < h.char_start < end and h.level <= max_level
                ]
                if candidates:
                    cuts.update(candidates)
                    changed = True
            if not changed:
                break
    return sorted(cuts)


def title_without_handle(title: str) -> str:
    value = re.sub(
        r"^(?:[AI]\d+(?:\.\d+)*|Appendix\s+[A-Z])(?:[.\s:;\-–—]+)?",
        "",
        title.strip(),
        flags=re.I,
    )
    return value or title


def safe_stem(value: str, limit: int = 72) -> str:
    stem = github_slug_base(value)
    stem = re.sub(r"-+", "-", stem).strip("-_")
    stem = stem[:limit].rstrip("-_")
    return stem or "section"


def normalized_handle_stem(handle: str) -> str:
    if handle.startswith("APPENDIX-"):
        return handle.upper()
    match = re.fullmatch(r"([AI])(\d+)((?:\.\d+)*)", handle)
    if not match:
        return safe_stem(handle)
    parts = [match.group(1).upper() + f"{int(match.group(2)):02d}"]
    if match.group(3):
        parts.extend(f"{int(piece):02d}" for piece in match.group(3).split(".") if piece)
    return "-".join(parts)


def derive_fragment_paths(
    spec: dict[str, str],
    headings: Sequence[Heading],
    cuts: Sequence[int],
) -> list[str]:
    used: set[str] = set()
    paths: list[str] = []
    top_level: Heading | None = None
    heading_offsets = [h.char_start for h in headings]
    preface_seq = 0
    extra_seq: dict[str, int] = {}

    for start in cuts[:-1]:
        prior_index = bisect.bisect_right(heading_offsets, start) - 1
        primary = headings[prior_index] if prior_index >= 0 and headings[prior_index].char_start == start else None

        for candidate in headings:
            if candidate.char_start > start:
                break
            if candidate.level == 1:
                top_level = candidate

        handle = primary.handle if primary and primary.handle else None
        if handle:
            base = normalized_handle_stem(handle)
            tail = safe_stem(title_without_handle(primary.title))
            filename = f"{base}-{tail}.md"
        elif primary and primary.level == 1:
            preface_seq += 1
            tail = safe_stem(primary.title)
            filename = f"{spec['prefix']}-PREFACE-{preface_seq:02d}-{tail}.md"
        else:
            section = top_level.handle if top_level and top_level.handle else f"{spec['prefix']}-PREFACE"
            extra_seq[section] = extra_seq.get(section, 0) + 1
            title = primary.title if primary else "preamble"
            filename = (
                f"{normalized_handle_stem(section)}-"
                f"EXTRA-{extra_seq[section]:02d}-{safe_stem(title)}.md"
            )

        relative = f"docs/architecture/{filename}"
        candidate_path = relative
        suffix = 2
        while candidate_path in used:
            candidate_path = relative[:-3] + f"-{suffix}.md"
            suffix += 1
        used.add(candidate_path)
        paths.append(candidate_path)
    return paths


def headings_by_fragment(
    headings: Sequence[Heading],
    cuts: Sequence[int],
) -> list[list[dict[str, Any]]]:
    result: list[list[dict[str, Any]]] = [[] for _ in cuts[:-1]]
    per_fragment_titles: list[list[str]] = [[] for _ in cuts[:-1]]
    heading_fragment_indices: list[int] = []

    for heading in headings:
        index = bisect.bisect_right(cuts, heading.char_start) - 1
        index = min(index, len(result) - 1)
        heading_fragment_indices.append(index)
        per_fragment_titles[index].append(heading.title)

    fragment_anchors = [assign_anchors(titles) for titles in per_fragment_titles]
    fragment_anchor_offsets = [0 for _ in result]

    for heading, index in zip(headings, heading_fragment_indices, strict=True):
        local = fragment_anchor_offsets[index]
        fragment_anchor_offsets[index] += 1
        result[index].append(
            {
                "level": heading.level,
                "title": heading.title,
                "handle": heading.handle,
                "source_line": heading.line,
                "source_anchor": heading.source_anchor,
                "fragment_anchor": fragment_anchors[index][local],
            }
        )
    return result


INLINE_LINK_RE = re.compile(
    r"(?P<prefix>\]\(\s*)(?P<dest><[^>\r\n]+>|[^)\s\r\n]+)(?P<suffix>(?:\s+[\"'][^\"'\r\n]*[\"'])?\s*\))"
)
REFERENCE_LINK_RE = re.compile(
    r"(?P<prefix>^\s{0,3}\[[^\]]+\]:\s*)(?P<dest><[^>\r\n]+>|\S+)",
    re.MULTILINE,
)


def outside_fence_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    fence_char: str | None = None
    fence_len = 0
    active_start = 0
    offset = 0
    for line in text.splitlines(keepends=True):
        logical = line.rstrip("\r\n")
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})", logical)
        if match:
            marker = match.group(1)
            if fence_char is None:
                if active_start < offset:
                    spans.append((active_start, offset))
                fence_char = marker[0]
                fence_len = len(marker)
            elif marker[0] == fence_char and len(marker) >= fence_len:
                fence_char = None
                fence_len = 0
                active_start = offset + len(line)
        offset += len(line)
    if fence_char is None and active_start < len(text):
        spans.append((active_start, len(text)))
    return spans


def find_link_destinations(text: str) -> list[tuple[int, int, str]]:
    found: list[tuple[int, int, str]] = []
    for span_start, span_end in outside_fence_spans(text):
        segment = text[span_start:span_end]
        for regex in (INLINE_LINK_RE, REFERENCE_LINK_RE):
            for match in regex.finditer(segment):
                start = span_start + match.start("dest")
                end = span_start + match.end("dest")
                found.append((start, end, match.group("dest")))
    found.sort()
    dedup: list[tuple[int, int, str]] = []
    for item in found:
        if dedup and item[:2] == dedup[-1][:2]:
            continue
        dedup.append(item)
    return dedup


def unwrap_destination(destination: str) -> tuple[str, bool]:
    if destination.startswith("<") and destination.endswith(">"):
        return destination[1:-1], True
    return destination, False


def rewrite_cross_fragment_links(
    original: str,
    current_path: str,
    legacy_filename: str,
    anchor_targets: dict[str, tuple[str, str]],
) -> tuple[str, list[dict[str, Any]]]:
    replacements: list[tuple[int, int, str, str]] = []
    current_name = Path(current_path).name

    for start, end, raw_dest in find_link_destinations(original):
        dest, angled = unwrap_destination(raw_dest)
        parsed = urllib.parse.urlsplit(dest)
        if parsed.scheme or parsed.netloc or not parsed.fragment:
            continue

        path_part = urllib.parse.unquote(parsed.path)
        same_document = path_part in (
            "", ".", f"./{legacy_filename}", legacy_filename,
            current_name, f"./{current_name}",
        )
        if not same_document:
            continue

        anchor = urllib.parse.unquote(parsed.fragment)
        target = anchor_targets.get(anchor)
        if target is None:
            continue
        target_path, target_anchor = target
        if target_path == current_path:
            new_dest = f"#{target_anchor}"
        else:
            new_dest = f"{Path(target_path).name}#{target_anchor}"
        if parsed.query:
            if "#" in new_dest:
                base, fragment = new_dest.split("#", 1)
                new_dest = f"{base}?{parsed.query}#{fragment}"
            else:
                new_dest = f"{new_dest}?{parsed.query}"
        if angled:
            new_dest = f"<{new_dest}>"
        if new_dest != raw_dest:
            replacements.append((start, end, raw_dest, new_dest))

    if not replacements:
        return original, []

    output: list[str] = []
    rewrites: list[dict[str, Any]] = []
    cursor = 0
    rendered_length = 0
    for start, end, old, new in replacements:
        prefix = original[cursor:start]
        output.append(prefix)
        rendered_length += len(prefix)
        rendered_start = rendered_length
        output.append(new)
        rendered_length += len(new)
        rewrites.append(
            {
                "rendered_start": rendered_start,
                "rendered_end": rendered_length,
                "original": old,
                "replacement": new,
            }
        )
        cursor = end
    output.append(original[cursor:])
    return "".join(output), rewrites


def reverse_rewrites(rendered: str, rewrites: Sequence[dict[str, Any]]) -> str:
    value = rendered
    for rewrite in sorted(rewrites, key=lambda item: int(item["rendered_start"]), reverse=True):
        start = int(rewrite["rendered_start"])
        end = int(rewrite["rendered_end"])
        replacement = str(rewrite["replacement"])
        if value[start:end] != replacement:
            raise DocsError(
                "navigation rewrite drift at "
                f"{start}:{end}; expected {replacement!r}, found {value[start:end]!r}"
            )
        value = value[:start] + str(rewrite["original"]) + value[end:]
    return value


def build_fragments(spec: dict[str, str], source_text: str) -> tuple[list[Fragment], list[Heading]]:
    headings = parse_headings(source_text)
    if not headings:
        raise DocsError(f"{spec['label']} has no Markdown headings")
    cuts = choose_cuts(source_text, headings)
    paths = derive_fragment_paths(spec, headings, cuts)
    fragment_heading_records = headings_by_fragment(headings, cuts)

    anchor_targets: dict[str, tuple[str, str]] = {}
    for path, records in zip(paths, fragment_heading_records, strict=True):
        for record in records:
            source_anchor = str(record["source_anchor"])
            if source_anchor in anchor_targets:
                raise DocsError(f"duplicate source anchor after GitHub slugging: {source_anchor}")
            anchor_targets[source_anchor] = (path, str(record["fragment_anchor"]))

    fragments: list[Fragment] = []
    legacy_filename = Path(spec["legacy"]).name
    for index, (start, end, path, records) in enumerate(
        zip(cuts[:-1], cuts[1:], paths, fragment_heading_records, strict=True)
    ):
        original = source_text[start:end]
        rendered, rewrites = rewrite_cross_fragment_links(
            original,
            path,
            legacy_filename,
            anchor_targets,
        )
        fragments.append(
            Fragment(
                index=index,
                source_start=start,
                source_end=end,
                source_start_line=source_line_for_offset(source_text, start),
                source_end_line=source_line_for_offset(source_text, end),
                path=path,
                text=original,
                rendered_text=rendered,
                rewrites=rewrites,
                headings=records,
            )
        )
    return fragments, headings


def manifest_from_fragments(
    spec: dict[str, str],
    source_text: str,
    fragments: Sequence[Fragment],
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for fragment in fragments:
        records.append(
            {
                "order": fragment.index,
                "path": fragment.path,
                "source_start_char": fragment.source_start,
                "source_end_char": fragment.source_end,
                "source_start_line": fragment.source_start_line,
                "source_end_line": fragment.source_end_line,
                "source_sha256": sha256_text(fragment.text),
                "rendered_sha256": sha256_text(fragment.rendered_text),
                "source_bytes": len(fragment.text.encode("utf-8")),
                "rendered_bytes": len(fragment.rendered_text.encode("utf-8")),
                "navigation_rewrites": fragment.rewrites,
                "headings": fragment.headings,
            }
        )
    return {
        "schema_version": SCHEMA,
        "source_key": spec["key"],
        "label": spec["label"],
        "legacy_compatibility_path": spec["legacy"],
        "entry_path": spec["entry"],
        "source_sha256": sha256_text(source_text),
        "source_bytes": len(source_text.encode("utf-8")),
        "source_characters": len(source_text),
        "source_lines": source_text.count("\n") + (0 if source_text.endswith("\n") else 1),
        "fragment_count": len(records),
        "fragments": records,
    }


def relative_markdown_link(from_path: str, to_path: str) -> str:
    start = str(Path(from_path).parent).replace("\\", "/")
    return posixpath.relpath(to_path, start=start)


def render_compatibility_map(
    spec: dict[str, str],
    manifest: dict[str, Any],
) -> str:
    lines = [GENERATED_MARKER]
    lines.append(
        "<!-- Compatibility facade: headings intentionally preserve historical GitHub anchors. -->"
    )
    first = True
    for fragment in manifest["fragments"]:
        fragment_path = str(fragment["path"])
        link_path = relative_markdown_link(spec["legacy"], fragment_path)
        for heading in fragment["headings"]:
            level = int(heading["level"])
            title = str(heading["title"])
            target_anchor = str(heading["fragment_anchor"])
            lines.append(f"{'#' * level} {title}")
            if first:
                lines.extend(
                    [
                        "",
                        "> This stable path is a compatibility map, not the full normative book.",
                        "> Agents must use the [reading protocol](READING_PROTOCOL.md),",
                        "> [route table](ROUTES.md), or [handle index](HANDLE_INDEX.md)",
                        "> and open only the returned canonical fragments.",
                        "",
                    ]
                )
                first = False
            lines.append(
                f"_Canonical content: [{Path(fragment_path).name}]"
                f"({link_path}#{target_anchor})._"
            )
            lines.append("")
    if first:
        raise DocsError(f"cannot render empty compatibility map for {spec['key']}")
    return "\n".join(lines).rstrip() + "\n"


def group_key_for_fragment(fragment: dict[str, Any], prefix: str) -> str:
    handles = [str(h["handle"]) for h in fragment["headings"] if h.get("handle")]
    if handles:
        handle = handles[0]
        if handle.startswith("APPENDIX-"):
            return handle
        match = re.match(rf"^({re.escape(prefix)}\d+)", handle)
        if match:
            return match.group(1)
    return "PREFACE"


def render_source_readme(
    spec: dict[str, str],
    manifest: dict[str, Any],
) -> str:
    groups: dict[str, list[dict[str, Any]]] = {}
    for fragment in manifest["fragments"]:
        groups.setdefault(group_key_for_fragment(fragment, spec["prefix"]), []).append(fragment)

    lines = [
        GENERATED_MARKER,
        f"# {spec['label']} fragment index",
        "",
        f"The adopted `{spec['label']}` byte stream is split into "
        f"{manifest['fragment_count']} bounded Markdown fragments.",
        "",
        f"- Original SHA-256: `{manifest['source_sha256']}`",
        f"- Original bytes: `{manifest['source_bytes']}`",
        f"- Manifest: [`manifest.json`](manifest.json)",
        f"- Stable compatibility path: [`../{Path(spec['legacy']).name}`]"
        f"(../{Path(spec['legacy']).name})",
        "- Do not read this entire index as task context. Resolve a route first.",
        "",
        "Use [`../READING_PROTOCOL.md`](../READING_PROTOCOL.md), "
        "[`../ROUTES.md`](../ROUTES.md), or "
        "[`../HANDLE_INDEX.md`](../HANDLE_INDEX.md).",
        "",
    ]
    for group, fragments in groups.items():
        lines.append(f"## {group}")
        lines.append("")
        for fragment in fragments:
            records = fragment["headings"]
            title = records[0]["title"] if records else Path(fragment["path"]).stem
            anchor = records[0]["fragment_anchor"] if records else ""
            link = relative_markdown_link(spec["entry"], fragment["path"])
            if anchor:
                link += f"#{anchor}"
            handles = ", ".join(
                str(record["handle"]) for record in records if record.get("handle")
            )
            handle_note = f" — `{handles}`" if handles else ""
            lines.append(
                f"- [{title}]({link}){handle_note} "
                f"({fragment['rendered_bytes']} bytes)"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_group_readmes(root: Path, spec: dict[str, str], manifest: dict[str, Any]) -> None:
    entry_dir = repo_path(root, spec["entry"]).parent
    groups: dict[str, list[dict[str, Any]]] = {}
    for fragment in manifest["fragments"]:
        groups.setdefault(group_key_for_fragment(fragment, spec["prefix"]), []).append(fragment)
    groups_dir = entry_dir / "sections"
    if groups_dir.exists():
        shutil.rmtree(groups_dir)
    groups_dir.mkdir(parents=True, exist_ok=True)
    for group, fragments in groups.items():
        target_path = groups_dir / f"{safe_stem(group)}.md"
        target_relative = str(target_path.relative_to(root)).replace("\\", "/")
        lines = [
            GENERATED_MARKER,
            f"# {spec['label']} — {group}",
            "",
            "Read only the fragments returned by the documentation router.",
            "",
        ]
        for fragment in fragments:
            records = fragment["headings"]
            title = records[0]["title"] if records else Path(fragment["path"]).stem
            anchor = records[0]["fragment_anchor"] if records else ""
            link = relative_markdown_link(target_relative, fragment["path"])
            if anchor:
                link += f"#{anchor}"
            handles = ", ".join(
                str(record["handle"]) for record in records if record.get("handle")
            )
            lines.append(f"- [{title}]({link})" + (f" — `{handles}`" if handles else ""))
        write_utf8(target_path, "\n".join(lines).rstrip() + "\n")


def natural_handle_key(handle: str) -> tuple[Any, ...]:
    if handle.startswith("APPENDIX-"):
        return (9, handle)
    match = re.fullmatch(r"([AI])(\d+(?:\.\d+)*)", handle)
    if not match:
        return (8, handle)
    prefix_order = 0 if match.group(1) == "A" else 1
    numbers = tuple(int(piece) for piece in match.group(2).split("."))
    return (prefix_order, *numbers)


def build_handle_index(manifests: Sequence[dict[str, Any]]) -> tuple[dict[str, Any], str]:
    handles: dict[str, dict[str, Any]] = {}
    headings: list[dict[str, Any]] = []
    for manifest in manifests:
        for fragment in manifest["fragments"]:
            for heading in fragment["headings"]:
                record = {
                    "source": manifest["source_key"],
                    "title": heading["title"],
                    "level": heading["level"],
                    "path": fragment["path"],
                    "anchor": heading["fragment_anchor"],
                    "source_anchor": heading["source_anchor"],
                    "source_line": heading["source_line"],
                    "fragment_sha256": fragment["rendered_sha256"],
                    "fragment_bytes": fragment["rendered_bytes"],
                }
                headings.append(record)
                handle = heading.get("handle")
                if handle:
                    if handle in handles:
                        raise DocsError(f"duplicate normative handle: {handle}")
                    handles[str(handle)] = record

    payload = {
        "schema_version": "eliot-handle-index-v1",
        "handles": dict(sorted(handles.items(), key=lambda item: natural_handle_key(item[0]))),
        "headings": headings,
    }

    lines = [
        GENERATED_MARKER,
        "# Canonical handle index",
        "",
        "Resolve task-specific documentation through [`ROUTES.md`](ROUTES.md). "
        "Use this index for exact handle lookup.",
        "",
        "| Handle | Canonical fragment | Source line | Bytes |",
        "|---|---|---:|---:|",
    ]
    for handle, record in payload["handles"].items():
        link = f"{Path(record['path']).name}#{record['anchor']}"
        lines.append(
            f"| `{handle}` | [{record['title']}]({link}) | "
            f"{record['source_line']} | {record['fragment_bytes']} |"
        )
    return payload, "\n".join(lines).rstrip() + "\n"


def load_simple_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        return tomllib.load(stream)


def render_pair_receipt(old: dict[str, Any], manifests: dict[str, dict[str, Any]]) -> str:
    architecture = manifests["architecture"]
    implementation = manifests["implementation"]
    required_equal = {
        "architecture_sha256": architecture["source_sha256"],
        "implementation_sha256": implementation["source_sha256"],
    }
    for key, value in required_equal.items():
        if str(old.get(key, "")) != value:
            raise DocsError(
                f"refusing layout migration because {key} does not match source: "
                f"receipt={old.get(key)!r} source={value!r}"
            )

    values = dict(old)
    values["schema_version"] = PAIR_SCHEMA
    values["content_layout"] = SCHEMA
    values["architecture_path"] = SOURCE_SPECS[0]["manifest"]
    values["architecture_entry_path"] = SOURCE_SPECS[0]["entry"]
    values["architecture_compatibility_path"] = SOURCE_SPECS[0]["legacy"]
    values["implementation_path"] = SOURCE_SPECS[1]["manifest"]
    values["implementation_entry_path"] = SOURCE_SPECS[1]["entry"]
    values["implementation_compatibility_path"] = SOURCE_SPECS[1]["legacy"]

    ordered_keys = [
        "schema_version", "status", "adopted_at", "decision_ref",
        "repository_authority_branch", "historical_material_location",
        "content_layout",
        "pair_key_algorithm", "pair_key_input", "pair_key",
        "architecture_path", "architecture_entry_path",
        "architecture_compatibility_path", "architecture_revision",
        "architecture_edition", "architecture_sha256",
        "implementation_path", "implementation_entry_path",
        "implementation_compatibility_path", "implementation_revision",
        "implementation_edition", "implementation_sha256",
        "supersedes_architecture_sha256", "supersedes_implementation_sha256",
    ]
    lines: list[str] = []
    section_breaks = {
        "content_layout", "pair_key_algorithm", "architecture_path",
        "implementation_path", "supersedes_architecture_sha256",
    }
    for key in ordered_keys:
        if key not in values:
            continue
        if key in section_breaks and lines and lines[-1] != "":
            lines.append("")
        value = str(values[key]).replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{key} = "{value}"')
    return "\n".join(lines).rstrip() + "\n"


def pair_key(architecture_hash: str, implementation_hash: str) -> str:
    payload = (
        b"eliot-normative-pair-v1\x00"
        + architecture_hash.encode("ascii")
        + b"\x00"
        + implementation_hash.encode("ascii")
        + b"\x00"
    )
    return "sha256:" + sha256_bytes(payload)


def render_architecture_contract(old_text: str, pair: dict[str, Any]) -> str:
    lines = [
        "# Architecture authority",
        "",
        "This file is the repository authority and navigation contract. It is not a",
        "third normative book.",
        "",
        "## Accepted sharded normative pair",
        "",
        "The 2026-08-28 adopted semantic byte streams are unchanged. Only their",
        "repository layout changed: each stream is reconstructed deterministically",
        "from ordered fragments and verified against the original SHA-256.",
        "",
        "| Authority | Canonical manifest and entry | Revision | Edition | Reconstructed SHA-256 |",
        "|---|---|---|---|---|",
        f"| Intent, theory, invariants, and Hard Boundaries | "
        f"[`{pair['architecture_path']}`](architecture/architecture/manifest.json) · "
        f"[bounded index](architecture/architecture/README.md) | "
        f"`{pair['architecture_revision']}` | `{pair['architecture_edition']}` | "
        f"`{str(pair['architecture_sha256']).upper()}` |",
        f"| Target owners, contracts, defaults, failure behavior, and migration | "
        f"[`{pair['implementation_path']}`](architecture/implementation/manifest.json) · "
        f"[bounded index](architecture/implementation/README.md) | "
        f"`{pair['implementation_revision']}` | `{pair['implementation_edition']}` | "
        f"`{str(pair['implementation_sha256']).upper()}` |",
        "",
        f"The machine-bindable adoption receipt is "
        f"[`docs/normative-pair.toml`](normative-pair.toml). Its pair key remains "
        f"`{pair['pair_key']}` because the reconstructed canonical bytes are unchanged.",
        "",
        "The historical paths "
        "[`docs/architecture/ELIOT_ARCHITECTURE.md`](architecture/ELIOT_ARCHITECTURE.md) "
        "and "
        "[`docs/architecture/ELIOT_IMPLEMENTATION.md`](architecture/ELIOT_IMPLEMENTATION.md) "
        "are compact compatibility maps. They preserve incoming file and heading links,",
        "but agents must not load them as the documentation payload.",
        "",
        "Use [`docs/architecture/READING_PROTOCOL.md`](architecture/READING_PROTOCOL.md),",
        "[`docs/architecture/ROUTES.md`](architecture/ROUTES.md), and",
        "[`docs/architecture/HANDLE_INDEX.md`](architecture/HANDLE_INDEX.md) for bounded routing.",
        "",
        "Architecture still prevails over Implementation on semantic conflict. A layout",
        "migration does not promote target behavior to current support; product status",
        "remains `NOT_ACCEPTED / UNVERIFIED` until exact Product Proof exists.",
        "",
        "## Preserved pre-sharding authority contract",
        "",
        "> The following text is retained as migration evidence. Where it calls the",
        "> two former monolith paths canonical files, the sharded authority section",
        "> above supersedes only that repository-layout statement.",
        "",
        old_text.rstrip(),
        "",
    ]
    return "\n".join(lines)


def insert_or_replace_block(text: str, block: str, *, after_first_heading: bool = True) -> str:
    wrapped = f"{ROUTING_START}\n{block.rstrip()}\n{ROUTING_END}"
    pattern = re.compile(
        re.escape(ROUTING_START) + r".*?" + re.escape(ROUTING_END),
        re.DOTALL,
    )
    if pattern.search(text):
        return pattern.sub(wrapped, text)
    if after_first_heading:
        match = re.search(r"^#{1,6}\s+.+(?:\r?\n)", text, re.MULTILINE)
        if match:
            return text[:match.end()] + "\n" + wrapped + "\n\n" + text[match.end():]
    return wrapped + "\n\n" + text


def routing_block(relative_protocol: str = "docs/architecture/READING_PROTOCOL.md") -> str:
    return f"""## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_router.py route --path <repository/path> --topic "<causal property>"
```

Read every fragment marked **required**, then record the emitted receipt in the
work unit or pull request. Optional fragments are loaded only when the current
decision crosses their stated boundary. A legacy `ELIOT_*` compatibility map is
never an acceptable reading receipt.

If no non-baseline route matches, stop the mutation and add or obtain a route;
silence is not permission. See [`{relative_protocol}`]({relative_protocol})."""


def patch_navigation_surfaces(root: Path) -> None:
    architecture_dir = root / "docs/architecture"
    history_dir = architecture_dir / "navigation-history"
    history_dir.mkdir(parents=True, exist_ok=True)
    for name in ("README.md", "INDEX.md"):
        source = architecture_dir / name
        if source.exists() and GENERATED_MARKER not in read_utf8(source):
            write_utf8(history_dir / f"{source.stem}.pre-sharding.txt", read_utf8(source))

    for agents_path in sorted(root.rglob("AGENTS.md")):
        relative_protocol = posixpath.relpath(
            "docs/architecture/READING_PROTOCOL.md",
            start=str(agents_path.parent.relative_to(root)).replace("\\", "/") or ".",
        )
        write_utf8(
            agents_path,
            insert_or_replace_block(
                read_utf8(agents_path),
                routing_block(relative_protocol),
            ),
        )

    workflow = root / "WORKFLOW.md"
    if workflow.exists():
        write_utf8(
            workflow,
            insert_or_replace_block(
                read_utf8(workflow),
                routing_block("docs/architecture/READING_PROTOCOL.md"),
            ),
        )

    for relative, protocol in (
        ("README.md", "docs/architecture/READING_PROTOCOL.md"),
        ("docs/README.md", "architecture/READING_PROTOCOL.md"),
        ("docs/PROJECT_MAP.md", "architecture/READING_PROTOCOL.md"),
    ):
        path = root / relative
        if path.exists():
            block = (
                "## Documentation entry point\n\n"
                f"Start with the [mandatory reading protocol]({protocol}), then use "
                "the generated route for the exact files and causal property being changed. "
                "The stable `ELIOT_*` files are compatibility maps, not task prompts."
            )
            write_utf8(path, insert_or_replace_block(read_utf8(path), block))

    pr_template = root / ".github/pull_request_template.md"
    if pr_template.exists():
        block = """## Documentation read receipt

- Router command:
- Matched route IDs:
- Required handles and fragment SHAs read:
- Receipt ID:
- Optional expansions opened and reason:
"""
        write_utf8(
            pr_template,
            insert_or_replace_block(read_utf8(pr_template), block, after_first_heading=False),
        )


def render_reading_protocol(pair_key_value: str) -> str:
    return f"""{GENERATED_MARKER}
# Mandatory agent documentation protocol

The documentation is a routed contract graph, not a book-shaped prompt.

## Required sequence

1. Resolve current repository authority through `AGENTS.md`, `WORKFLOW.md`, and
   `workstreams/ACTIVE.toml`.
2. Run `python scripts/docs_router.py route --path <path> --topic "<intent>"`.
3. Read every **required** fragment exactly as emitted.
4. Inspect optional one-hop fragments only when the current decision crosses
   their boundary.
5. Record the router receipt ID, matched routes, handles, fragment paths, and
   fragment SHA-256 values in the work unit or pull request.
6. Re-run the route when the changed path, causal property, authority boundary,
   or evidence scope expands.

Current normative pair: `{pair_key_value}`.

## Fail-closed cases

Do not mutate the repository when:

- no non-baseline route matches a material path;
- a required handle cannot be resolved;
- a fragment hash differs from the route receipt;
- the shard manifest cannot reconstruct the adopted source hash;
- an incoming legacy anchor resolves only to a compatibility map and the
  canonical fragment was not opened;
- the task expands beyond the routed causal property without a new route.

## Context discipline

The router returns decision-sufficient fragments, not every related section.
The compatibility maps, full handle index, and assembled books are navigation or
audit surfaces. They are prohibited as default agent context.

To inspect all changed paths at once:

```text
python scripts/docs_router.py route --changed-from origin/main --topic "<intent>"
```

To verify the documentation graph:

```text
python scripts/docs_shards.py verify --root .
python scripts/docs_router.py check --root .
```
"""


def render_architecture_readme(pair_key_value: str) -> str:
    return f"""{GENERATED_MARKER}
# ELIOT documentation router

Do not open the former monoliths as task context.

1. Read [`READING_PROTOCOL.md`](READING_PROTOCOL.md).
2. Run `python scripts/docs_router.py route ...`.
3. Open every required fragment returned by the command.
4. Record the generated receipt.

## Navigation

- [Task/path route matrix](ROUTES.md)
- [Exact handle index](HANDLE_INDEX.md)
- [Architecture bounded index](architecture/README.md)
- [Implementation bounded index](implementation/README.md)
- [Architecture authority](../ARCHITECTURE_CONTRACT.md)
- [Dependency policy](../DEPENDENCY_POLICY.md)
- [Pre-sharding navigation snapshots](navigation-history/)

Normative pair: `{pair_key_value}`.

`ELIOT_ARCHITECTURE.md` and `ELIOT_IMPLEMENTATION.md` remain only to preserve
incoming file and heading links. Their canonical content has moved to fragments.
"""


def render_topic_index(old_index: str) -> str:
    return f"""{GENERATED_MARKER}
# ELIOT canonical topic index

For executable routing, use [`ROUTES.md`](ROUTES.md). For an exact section
handle, use [`HANDLE_INDEX.md`](HANDLE_INDEX.md). The table below preserves the
pre-sharding topic map; each handle now resolves to a bounded fragment.

## Preserved topic map

{old_index.rstrip()}
"""


def render_split_report(manifests: Sequence[dict[str, Any]], pair_key_value: str) -> str:
    lines = [
        GENERATED_MARKER,
        "# Documentation sharding integrity report",
        "",
        "This report records the deterministic layout migration. It does not add a",
        "third normative source.",
        "",
        f"- Normative pair key: `{pair_key_value}`",
        "- Canonical semantic byte streams changed: **no**",
        "- Legacy file paths retained as compatibility maps: **yes**",
        "- Cross-fragment self-links rewritten only as navigation metadata: **yes**",
        "",
        "| Source | Original bytes | Fragments | Largest rendered fragment | Reconstructed SHA-256 |",
        "|---|---:|---:|---:|---|",
    ]
    for manifest in manifests:
        largest = max(int(item["rendered_bytes"]) for item in manifest["fragments"])
        lines.append(
            f"| {manifest['label']} | {manifest['source_bytes']} | "
            f"{manifest['fragment_count']} | {largest} | "
            f"`{manifest['source_sha256']}` |"
        )
    lines.extend(
        [
            "",
            "Verification reconstructs each source by reversing only recorded link-target",
            "rewrites and concatenating fragments in manifest order. Any missing byte,",
            "reordered fragment, stale index, stale compatibility anchor, or changed",
            "fragment hash fails closed.",
            "",
        ]
    )
    return "\n".join(lines)


def replace_normative_verifier(root: Path) -> None:
    content = r"""[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$verifier = Join-Path $PSScriptRoot 'docs_shards.py'

python $verifier self-test
if ($LASTEXITCODE -ne 0) {
    throw "VERIFY_NORMATIVE_FAIL: documentation verifier self-test failed"
}

python $verifier verify --root $repoRoot --normative-only
if ($LASTEXITCODE -ne 0) {
    throw "VERIFY_NORMATIVE_FAIL: sharded normative pair verification failed"
}

Write-Output 'NORMATIVE_VERIFY: PASS layout=eliot-doc-shards-v1 authority=main'
"""
    write_utf8(root / "scripts/verify-normative.ps1", content)


def patch_verify_pipeline(root: Path) -> None:
    path = root / "scripts/verify.ps1"
    if not path.exists():
        return
    text = read_utf8(path)
    if "$docsShardVerifier" not in text:
        needle = "$agentRouteBundleVerifier = Join-Path $PSScriptRoot 'verify-agent-route-bundles.py'\n"
        replacement = (
            needle
            + "$docsShardVerifier = Join-Path $PSScriptRoot 'docs_shards.py'\n"
            + "$docsRouter = Join-Path $PSScriptRoot 'docs_router.py'\n"
        )
        if needle not in text:
            raise DocsError("cannot patch scripts/verify.ps1 variable block")
        text = text.replace(needle, replacement, 1)
    if "Name = 'documentation-shards'" not in text:
        needle = "$steps = @(\n"
        insertion = """$steps = @(
    [pscustomobject]@{
        Name = 'documentation-shards'
        Command = { python $docsShardVerifier verify --root $repoRoot }
    },
    [pscustomobject]@{
        Name = 'documentation-routes'
        Command = { python $docsRouter check --root $repoRoot }
    },
"""
        if needle not in text:
            raise DocsError("cannot patch scripts/verify.ps1 step block")
        text = text.replace(needle, insertion, 1)
    write_utf8(path, text)


def migrate(root: Path) -> None:
    root = root.resolve()
    pair_path = root / "docs/normative-pair.toml"
    old_pair = load_simple_toml(pair_path)
    old_index_path = root / "docs/architecture/INDEX.md"
    old_index = read_utf8(old_index_path)
    old_readme_path = root / "docs/architecture/README.md"
    old_readme = read_utf8(old_readme_path)
    history_dir = root / "docs/architecture/navigation-history"
    history_dir.mkdir(parents=True, exist_ok=True)
    write_utf8(history_dir / "README.pre-sharding.txt", old_readme)
    write_utf8(history_dir / "INDEX.pre-sharding.txt", old_index)
    old_contract_path = root / "docs/ARCHITECTURE_CONTRACT.md"
    old_contract = read_utf8(old_contract_path)

    manifests_by_key: dict[str, dict[str, Any]] = {}
    for spec in SOURCE_SPECS:
        legacy_path = repo_path(root, spec["legacy"])
        source_text = read_utf8(legacy_path)
        if GENERATED_MARKER in source_text[:300]:
            raise DocsError(
                f"{spec['legacy']} is already a compatibility map; migrate is one-shot"
            )
        expected = str(old_pair.get(f"{spec['key']}_sha256", ""))
        actual = sha256_text(source_text)
        if expected != actual:
            raise DocsError(
                f"{spec['key']} source does not match adopted receipt: "
                f"expected {expected}, actual {actual}"
            )

        fragments, _ = build_fragments(spec, source_text)
        manifest = manifest_from_fragments(spec, source_text, fragments)
        manifests_by_key[spec["key"]] = manifest

        for fragment in fragments:
            write_utf8(repo_path(root, fragment.path), fragment.rendered_text)
        write_utf8(
            repo_path(root, spec["manifest"]),
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        )
        write_utf8(repo_path(root, spec["entry"]), render_source_readme(spec, manifest))
        render_group_readmes(root, spec, manifest)
        write_utf8(legacy_path, render_compatibility_map(spec, manifest))

    pair_text = render_pair_receipt(old_pair, manifests_by_key)
    write_utf8(pair_path, pair_text)
    new_pair = load_simple_toml(pair_path)
    expected_pair_key = pair_key(
        str(new_pair["architecture_sha256"]),
        str(new_pair["implementation_sha256"]),
    )
    if str(new_pair["pair_key"]) != expected_pair_key:
        raise DocsError(
            f"pair key changed unexpectedly: receipt={new_pair['pair_key']} "
            f"computed={expected_pair_key}"
        )

    handle_payload, handle_markdown = build_handle_index(
        [manifests_by_key["architecture"], manifests_by_key["implementation"]]
    )
    write_utf8(
        root / "docs/architecture/handle-index.json",
        json.dumps(handle_payload, ensure_ascii=False, indent=2) + "\n",
    )
    write_utf8(root / "docs/architecture/HANDLE_INDEX.md", handle_markdown)
    write_utf8(
        root / "docs/architecture/READING_PROTOCOL.md",
        render_reading_protocol(expected_pair_key),
    )
    write_utf8(
        root / "docs/architecture/README.md",
        render_architecture_readme(expected_pair_key),
    )
    write_utf8(root / "docs/architecture/INDEX.md", render_topic_index(old_index))
    write_utf8(old_contract_path, render_architecture_contract(old_contract, new_pair))
    write_utf8(
        root / "docs/architecture/SPLIT_REPORT.md",
        render_split_report(
            [manifests_by_key["architecture"], manifests_by_key["implementation"]],
            expected_pair_key,
        ),
    )
    patch_navigation_surfaces(root)
    replace_normative_verifier(root)
    patch_verify_pipeline(root)


def load_manifest(root: Path, relative: str) -> dict[str, Any]:
    path = repo_path(root, relative)
    try:
        payload = json.loads(read_utf8(path))
    except (json.JSONDecodeError, OSError) as exc:
        raise DocsError(f"cannot read shard manifest {relative}: {exc}") from exc
    if payload.get("schema_version") != SCHEMA:
        raise DocsError(f"unsupported manifest schema in {relative}")
    return payload


def verify_manifest(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    reconstructed: list[str] = []
    expected_order = 0
    expected_start = 0
    largest = 0
    for record in manifest["fragments"]:
        order = int(record["order"])
        if order != expected_order:
            raise DocsError(
                f"{manifest['source_key']} fragment order gap: "
                f"expected {expected_order}, found {order}"
            )
        expected_order += 1
        if int(record["source_start_char"]) != expected_start:
            raise DocsError(
                f"{manifest['source_key']} source range gap before {record['path']}"
            )
        expected_start = int(record["source_end_char"])

        path = repo_path(root, str(record["path"]))
        if not path.is_file():
            raise DocsError(f"missing normative fragment: {record['path']}")
        rendered = read_utf8(path)
        rendered_hash = sha256_text(rendered)
        if rendered_hash != record["rendered_sha256"]:
            raise DocsError(
                f"rendered fragment hash mismatch: {record['path']} "
                f"expected {record['rendered_sha256']}, actual {rendered_hash}"
            )
        if len(rendered.encode("utf-8")) != int(record["rendered_bytes"]):
            raise DocsError(f"rendered fragment byte count mismatch: {record['path']}")
        largest = max(largest, int(record["rendered_bytes"]))
        source = reverse_rewrites(rendered, record.get("navigation_rewrites", []))
        if sha256_text(source) != record["source_sha256"]:
            raise DocsError(f"source fragment hash mismatch after reverse rewrite: {record['path']}")
        if len(source.encode("utf-8")) != int(record["source_bytes"]):
            raise DocsError(f"source fragment byte count mismatch: {record['path']}")
        reconstructed.append(source)

    text = "".join(reconstructed)
    actual_hash = sha256_text(text)
    if actual_hash != manifest["source_sha256"]:
        raise DocsError(
            f"{manifest['source_key']} reconstruction mismatch: "
            f"expected {manifest['source_sha256']}, actual {actual_hash}"
        )
    if len(text.encode("utf-8")) != int(manifest["source_bytes"]):
        raise DocsError(f"{manifest['source_key']} reconstructed byte count mismatch")
    if len(text) != int(manifest["source_characters"]):
        raise DocsError(f"{manifest['source_key']} reconstructed character count mismatch")
    if expected_start != len(text):
        raise DocsError(f"{manifest['source_key']} final source range mismatch")
    return {
        "source": manifest["source_key"],
        "fragments": expected_order,
        "bytes": len(text.encode("utf-8")),
        "sha256": actual_hash,
        "largest_fragment": largest,
    }


def verify_generated_surfaces(root: Path, manifests: dict[str, dict[str, Any]]) -> None:
    for spec in SOURCE_SPECS:
        legacy = read_utf8(repo_path(root, spec["legacy"]))
        expected = render_compatibility_map(spec, manifests[spec["key"]])
        if legacy != expected:
            raise DocsError(f"stale compatibility map: {spec['legacy']}")
        expected_readme = render_source_readme(spec, manifests[spec["key"]])
        actual_readme = read_utf8(repo_path(root, spec["entry"]))
        if actual_readme != expected_readme:
            raise DocsError(f"stale source index: {spec['entry']}")

    payload, markdown = build_handle_index(
        [manifests["architecture"], manifests["implementation"]]
    )
    actual_payload = json.loads(read_utf8(root / "docs/architecture/handle-index.json"))
    if actual_payload != payload:
        raise DocsError("stale docs/architecture/handle-index.json")
    if read_utf8(root / "docs/architecture/HANDLE_INDEX.md") != markdown:
        raise DocsError("stale docs/architecture/HANDLE_INDEX.md")


def markdown_anchors(text: str) -> set[str]:
    headings = parse_headings(text)
    anchors = {heading.source_anchor for heading in headings}
    for match in re.finditer(
        r"<(?:a|span)\s+[^>]*(?:id|name)\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
        text,
        re.I,
    ):
        anchors.add(match.group(1))
    return anchors


def should_skip_destination(destination: str) -> bool:
    return (
        not destination
        or destination.startswith(("http://", "https://", "mailto:", "tel:", "data:"))
        or destination.startswith("//")
        or any(token in destination for token in ("${{", "{{", "}}", "<path>", "..."))
    )


def verify_markdown_links(root: Path) -> dict[str, int]:
    markdown_files = sorted(
        path for path in root.rglob("*.md") if ".git" not in path.parts
    )
    anchor_cache: dict[Path, set[str]] = {}
    checked = 0
    failures: list[str] = []

    for source in markdown_files:
        text = read_utf8(source)
        for _, _, raw_dest in find_link_destinations(text):
            dest, _ = unwrap_destination(raw_dest)
            dest = html.unescape(dest)
            if should_skip_destination(dest):
                continue
            parsed = urllib.parse.urlsplit(dest)
            if parsed.scheme or parsed.netloc:
                continue
            path_part = urllib.parse.unquote(parsed.path)
            fragment = urllib.parse.unquote(parsed.fragment)
            if path_part.startswith("/"):
                target = root / path_part.lstrip("/")
            elif path_part:
                target = (source.parent / path_part).resolve()
            else:
                target = source.resolve()
            try:
                target.relative_to(root.resolve())
            except ValueError:
                failures.append(f"{source.relative_to(root)} -> escapes repo: {dest}")
                continue
            checked += 1
            if not target.exists():
                failures.append(f"{source.relative_to(root)} -> missing: {dest}")
                continue
            if fragment and target.is_file() and target.suffix.lower() in (".md", ".markdown"):
                anchors = anchor_cache.setdefault(target, markdown_anchors(read_utf8(target)))
                if fragment not in anchors:
                    failures.append(
                        f"{source.relative_to(root)} -> missing anchor "
                        f"{target.relative_to(root)}#{fragment}"
                    )

    if failures:
        preview = "\n".join(f"  - {failure}" for failure in failures[:100])
        suffix = "" if len(failures) <= 100 else f"\n  ... {len(failures) - 100} more"
        raise DocsError(f"broken Markdown links ({len(failures)}):\n{preview}{suffix}")
    return {"markdown_files": len(markdown_files), "links_checked": checked}


def verify_pair(root: Path, manifests: dict[str, dict[str, Any]]) -> str:
    receipt = load_simple_toml(root / "docs/normative-pair.toml")
    if receipt.get("schema_version") != PAIR_SCHEMA:
        raise DocsError("normative-pair receipt is not the sharded schema")
    if receipt.get("status") != "accepted":
        raise DocsError("normative pair is not accepted")
    if receipt.get("repository_authority_branch") != "main":
        raise DocsError("main is not the authority branch")
    if receipt.get("content_layout") != SCHEMA:
        raise DocsError("normative receipt content layout mismatch")

    for spec in SOURCE_SPECS:
        key = spec["key"]
        if receipt.get(f"{key}_path") != spec["manifest"]:
            raise DocsError(f"{key}_path does not identify its manifest")
        if receipt.get(f"{key}_entry_path") != spec["entry"]:
            raise DocsError(f"{key}_entry_path mismatch")
        if receipt.get(f"{key}_compatibility_path") != spec["legacy"]:
            raise DocsError(f"{key}_compatibility_path mismatch")
        if receipt.get(f"{key}_sha256") != manifests[key]["source_sha256"]:
            raise DocsError(f"{key} receipt hash differs from reconstructed source")

    computed_pair = pair_key(
        str(receipt["architecture_sha256"]),
        str(receipt["implementation_sha256"]),
    )
    if receipt.get("pair_key") != computed_pair:
        raise DocsError(
            f"normative pair key mismatch: receipt={receipt.get('pair_key')} "
            f"computed={computed_pair}"
        )

    contract = read_utf8(root / "docs/ARCHITECTURE_CONTRACT.md")
    required = [
        str(receipt["architecture_path"]),
        str(receipt["implementation_path"]),
        str(receipt["architecture_sha256"]).upper(),
        str(receipt["implementation_sha256"]).upper(),
        computed_pair,
    ]
    for value in required:
        if value not in contract:
            raise DocsError(f"architecture contract is missing current identity: {value}")

    retired = (
        "docs/normative",
        "docs/architecture/ELIOT_ARCHITECTURE_ENGLISH_FINAL_2026-08-28.md",
        "docs/architecture/ELIOT_IMPLEMENTATION_ENGLISH_FINAL_2026-08-28.md",
    )
    for relative in retired:
        if repo_path(root, relative).exists():
            raise DocsError(f"retired normative authority surface is present: {relative}")
    return computed_pair


def verify(root: Path, normative_only: bool = False) -> None:
    root = root.resolve()
    manifests = {spec["key"]: load_manifest(root, spec["manifest"]) for spec in SOURCE_SPECS}
    results = [verify_manifest(root, manifests[spec["key"]]) for spec in SOURCE_SPECS]
    pair = verify_pair(root, manifests)
    verify_generated_surfaces(root, manifests)
    link_result = {"markdown_files": 0, "links_checked": 0}
    if not normative_only:
        link_result = verify_markdown_links(root)
    print(
        "DOC_SHARDS_VERIFY: PASS "
        f"pair={pair} "
        + " ".join(
            f"{item['source']}_fragments={item['fragments']} "
            f"{item['source']}_bytes={item['bytes']} "
            f"{item['source']}_largest={item['largest_fragment']}"
            for item in results
        )
        + f" markdown_files={link_result['markdown_files']} "
        f"links={link_result['links_checked']}"
    )


def assemble(root: Path, source: str, output: Path) -> None:
    spec = next((item for item in SOURCE_SPECS if item["key"] == source), None)
    if spec is None:
        raise DocsError(f"unknown source: {source}")
    manifest = load_manifest(root.resolve(), spec["manifest"])
    chunks: list[str] = []
    for record in manifest["fragments"]:
        rendered = read_utf8(repo_path(root.resolve(), record["path"]))
        chunks.append(reverse_rewrites(rendered, record.get("navigation_rewrites", [])))
    write_utf8(output, "".join(chunks))
    actual = sha256_text(read_utf8(output))
    if actual != manifest["source_sha256"]:
        raise DocsError(f"assembled {source} hash mismatch")
    print(f"DOC_SHARDS_ASSEMBLE: PASS source={source} sha256={actual} output={output}")


def self_test() -> None:
    sample = """# Sample Book
Intro [jump](#i11-target).

# I0. Start
## I0.1. First
Text.

# I1. Other
## I1.1. Target
Done.
"""
    spec = {
        "key": "implementation",
        "legacy": "docs/architecture/ELIOT_IMPLEMENTATION.md",
        "manifest": "docs/architecture/implementation/manifest.json",
        "entry": "docs/architecture/implementation/README.md",
        "prefix": "I",
        "label": "Implementation",
    }
    fragments, headings = build_fragments(spec, sample)
    if not headings or len(fragments) < 4:
        raise DocsError("self-test did not produce expected fragments")
    reconstructed = "".join(
        reverse_rewrites(fragment.rendered_text, fragment.rewrites) for fragment in fragments
    )
    if reconstructed != sample:
        raise DocsError("self-test reconstruction differs from source")
    if not any(fragment.rewrites for fragment in fragments):
        raise DocsError("self-test did not rewrite a cross-fragment link")
    duplicate = assign_anchors(["Same", "Same", "Other"])
    if duplicate != ["same", "same-1", "other"]:
        raise DocsError(f"slug duplicate self-test failed: {duplicate}")
    if pair_key("a" * 64, "b" * 64) == pair_key("b" * 64, "a" * 64):
        raise DocsError("pair-key domain/order self-test failed")
    print("DOC_SHARDS_SELF_TEST: PASS cases=5")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    migrate_parser = sub.add_parser("migrate")
    migrate_parser.add_argument("--root", type=Path, default=Path("."))

    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--root", type=Path, default=Path("."))
    verify_parser.add_argument("--normative-only", action="store_true")

    assemble_parser = sub.add_parser("assemble")
    assemble_parser.add_argument("--root", type=Path, default=Path("."))
    assemble_parser.add_argument("--source", choices=("architecture", "implementation"), required=True)
    assemble_parser.add_argument("--output", type=Path, required=True)

    sub.add_parser("self-test")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "migrate":
            migrate(args.root)
            print("DOC_SHARDS_MIGRATE: PASS")
        elif args.command == "verify":
            verify(args.root, normative_only=args.normative_only)
        elif args.command == "assemble":
            assemble(args.root, args.source, args.output)
        elif args.command == "self-test":
            self_test()
        else:
            raise DocsError(f"unsupported command: {args.command}")
        return 0
    except DocsError as exc:
        print(f"DOC_SHARDS_FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
