#!/usr/bin/env python3
"""Validate repository-local Markdown links and anchors without network access."""

from __future__ import annotations

import argparse
import dataclasses
import re
import sys
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import unquote, urlsplit

FENCE_RE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")
ATX_RE = re.compile(r"^[ \t]{0,3}(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$")
SETEXT_RE = re.compile(r"^[ \t]*(=+|-+)[ \t]*$")
INLINE_LINK_RE = re.compile(r"!?\[[^\]]*\]\((?P<target>[^)]+)\)")
REFERENCE_DEF_RE = re.compile(r"^[ \t]{0,3}\[[^\]]+\]:[ \t]*(?P<target>\S+)")
INLINE_CODE_RE = re.compile(r"`+[^`]*`+")
HTML_ANCHOR_RE = re.compile(
    r"<a\s+[^>]*(?:id|name)=[\"'](?P<anchor>[^\"']+)[\"'][^>]*>",
    re.IGNORECASE,
)
HTML_TAG_RE = re.compile(r"<[^>]+>")
MARKDOWN_LINK_TEXT_RE = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
EXTERNAL_SCHEMES = {
    "http",
    "https",
    "mailto",
    "ftp",
    "data",
    "javascript",
    "tel",
    "sms",
}
DEFAULT_IGNORES = {
    ".git",
    ".eliot",
    ".eliot-docs",
    "target",
    "node_modules",
    ".venv",
    "venv",
}


@dataclasses.dataclass(frozen=True)
class Link:
    source: Path
    line: int
    raw_target: str


@dataclasses.dataclass(frozen=True)
class Failure:
    source: Path
    line: int
    target: str
    reason: str


def clean_heading(raw: str) -> str:
    value = raw.strip()
    value = HTML_TAG_RE.sub("", value)
    value = MARKDOWN_LINK_TEXT_RE.sub(lambda match: match.group(1), value)
    value = INLINE_CODE_RE.sub(lambda match: match.group(0).strip("`"), value)
    value = value.replace("**", "").replace("__", "")
    value = value.replace("*", "").replace("_", "")
    return value.strip()


def github_slug(raw: str) -> str:
    value = clean_heading(raw).lower()
    kept: list[str] = []
    for character in value:
        if character.isalnum() or character in {" ", "-", "_"}:
            kept.append(character)
    return re.sub(r"\s+", "-", "".join(kept).strip())


def markdown_anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    anchors: set[str] = set()
    slug_counts: dict[str, int] = {}
    fence_marker: str | None = None
    fence_len = 0
    previous_text: str | None = None

    def add_heading(title: str) -> None:
        base = github_slug(title)
        if not base:
            return
        count = slug_counts.get(base, 0)
        slug_counts[base] = count + 1
        anchors.add(base if count == 0 else f"{base}-{count}")

    for line in lines:
        fence = FENCE_RE.match(line)
        if fence:
            marker = fence.group(1)
            if fence_marker is None:
                fence_marker = marker[0]
                fence_len = len(marker)
            elif marker[0] == fence_marker and len(marker) >= fence_len:
                fence_marker = None
                fence_len = 0
            previous_text = None
            continue
        if fence_marker is not None:
            continue

        for match in HTML_ANCHOR_RE.finditer(line):
            anchors.add(unquote(match.group("anchor")).lower())

        heading = ATX_RE.match(line)
        if heading:
            add_heading(heading.group(2))
            previous_text = None
            continue
        if previous_text and SETEXT_RE.match(line):
            add_heading(previous_text)
            previous_text = None
            continue
        previous_text = line.strip() or None
    return anchors


def strip_destination(raw: str) -> str:
    value = raw.strip()
    if value.startswith("<") and ">" in value:
        return value[1 : value.index(">")]
    # An optional Markdown title follows whitespace. Literal spaces in a path
    # must be percent-encoded.
    return value.split(maxsplit=1)[0]


def iter_markdown_links(path: Path) -> Iterable[Link]:
    text = path.read_text(encoding="utf-8")
    fence_marker: str | None = None
    fence_len = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        fence = FENCE_RE.match(line)
        if fence:
            marker = fence.group(1)
            if fence_marker is None:
                fence_marker = marker[0]
                fence_len = len(marker)
            elif marker[0] == fence_marker and len(marker) >= fence_len:
                fence_marker = None
                fence_len = 0
            continue
        if fence_marker is not None:
            continue
        candidate = INLINE_CODE_RE.sub("", line)
        for match in INLINE_LINK_RE.finditer(candidate):
            yield Link(path, line_number, strip_destination(match.group("target")))
        reference = REFERENCE_DEF_RE.match(candidate)
        if reference:
            yield Link(path, line_number, strip_destination(reference.group("target")))


def markdown_files(repo_root: Path, roots: Sequence[Path]) -> list[Path]:
    result: set[Path] = set()
    for root in roots:
        absolute = root if root.is_absolute() else repo_root / root
        if absolute.is_file():
            if absolute.suffix.lower() == ".md":
                result.add(absolute.resolve())
            continue
        if not absolute.exists():
            raise FileNotFoundError(f"link-check root does not exist: {root}")
        for path in absolute.rglob("*.md"):
            relative_parts = path.relative_to(repo_root).parts
            if any(part in DEFAULT_IGNORES for part in relative_parts):
                continue
            result.add(path.resolve())
    return sorted(result)


def resolve_local_target(
    repo_root: Path, link: Link
) -> tuple[Path | None, str | None]:
    target = link.raw_target
    if not target:
        return None, None
    parsed = urlsplit(target)
    if parsed.scheme.lower() in EXTERNAL_SCHEMES or target.startswith("//"):
        return None, None
    path_text = unquote(parsed.path)
    fragment = unquote(parsed.fragment).lower() or None
    if not path_text:
        return link.source, fragment
    if path_text.startswith("/"):
        target_path = repo_root / path_text.lstrip("/")
    else:
        target_path = link.source.parent / path_text
    target_path = target_path.resolve()
    try:
        target_path.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise ValueError("target escapes repository root") from exc
    if target_path.is_dir():
        target_path = target_path / "README.md"
    return target_path, fragment


def check_links(repo_root: Path, files: Sequence[Path]) -> list[Failure]:
    failures: list[Failure] = []
    anchor_cache: dict[Path, set[str]] = {}
    for source in files:
        for link in iter_markdown_links(source):
            try:
                target_path, fragment = resolve_local_target(repo_root, link)
            except ValueError as exc:
                failures.append(Failure(source, link.line, link.raw_target, str(exc)))
                continue
            if target_path is None:
                continue
            if not target_path.exists():
                failures.append(
                    Failure(source, link.line, link.raw_target, "target does not exist")
                )
                continue
            if fragment and target_path.suffix.lower() == ".md":
                if re.fullmatch(r"l\d+(?:-l\d+)?", fragment):
                    continue
                anchors = anchor_cache.setdefault(
                    target_path, markdown_anchors(target_path)
                )
                if fragment not in anchors:
                    failures.append(
                        Failure(
                            source,
                            link.line,
                            link.raw_target,
                            f"anchor #{fragment} does not exist in "
                            f"{target_path.relative_to(repo_root).as_posix()}",
                        )
                    )
    return failures


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "roots",
        type=Path,
        nargs="*",
        default=[Path(".")],
        help="files/directories to scan; default is the repository root",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = args.repo_root.resolve()
    try:
        files = markdown_files(repo_root, args.roots)
    except (FileNotFoundError, UnicodeDecodeError) as exc:
        print(f"DOC_LINK_CHECK_FAIL: {exc}", file=sys.stderr)
        return 2
    failures = check_links(repo_root, files)
    if failures:
        for failure in failures:
            source = failure.source.relative_to(repo_root).as_posix()
            print(
                f"{source}:{failure.line}: {failure.reason}: {failure.target}",
                file=sys.stderr,
            )
        print(
            f"DOC_LINK_CHECK_FAIL: files={len(files)} failures={len(failures)}",
            file=sys.stderr,
        )
        return 1
    print(f"DOC_LINK_CHECK: PASS files={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
