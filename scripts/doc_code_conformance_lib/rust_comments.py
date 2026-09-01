"""Rust comment spans used by documentation/source conformance checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator


@dataclass(frozen=True)
class CommentSpan:
    start: int
    end: int
    body_start: int
    body_end: int


def _raw_string(text: str, offset: int) -> tuple[int, int] | None:
    for prefix in ("br", "cr", "r"):
        if not text.startswith(prefix, offset):
            continue
        cursor = offset + len(prefix)
        hashes = 0
        while cursor < len(text) and text[cursor] == "#":
            cursor += 1
            hashes += 1
        if cursor < len(text) and text[cursor] == '"':
            return cursor + 1, hashes
    return None


def _skip_quoted(text: str, offset: int, quote: str) -> int:
    cursor = offset + 1
    while cursor < len(text):
        current = text[cursor]
        if current == "\\":
            cursor += 2
            continue
        cursor += 1
        if current == quote:
            return cursor
        if current in "\r\n" and quote == "'":
            return offset + 1
    return cursor


def comment_spans(text: str) -> tuple[CommentSpan, ...]:
    spans: list[CommentSpan] = []
    cursor = 0
    length = len(text)
    while cursor < length:
        raw = _raw_string(text, cursor)
        if raw is not None:
            body, hashes = raw
            terminator = '"' + ("#" * hashes)
            end = text.find(terminator, body)
            cursor = length if end < 0 else end + len(terminator)
            continue

        if text.startswith("//", cursor):
            end = text.find("\n", cursor + 2)
            if end < 0:
                end = length
            spans.append(CommentSpan(cursor, end, cursor + 2, end))
            cursor = end
            continue

        if text.startswith("/*", cursor):
            start = cursor
            cursor += 2
            depth = 1
            while cursor < length and depth:
                if text.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif text.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            end = cursor
            body_end = end - 2 if depth == 0 else end
            spans.append(CommentSpan(start, end, start + 2, body_end))
            continue

        current = text[cursor]
        if current == '"':
            cursor = _skip_quoted(text, cursor, '"')
            continue
        if current == "'":
            candidate = _skip_quoted(text, cursor, "'")
            if candidate > cursor + 1:
                cursor = candidate
                continue
        cursor += 1

    return tuple(spans)


def iter_rust_comments(text: str) -> Iterator[tuple[str, int]]:
    for span in comment_spans(text):
        yield text[span.body_start : span.body_end], span.body_start


def code_projection(text: str) -> str:
    pieces: list[str] = []
    cursor = 0
    for span in comment_spans(text):
        pieces.append(text[cursor : span.start])
        pieces.append("\x00COMMENT\x00")
        cursor = span.end
    pieces.append(text[cursor:])
    return "".join(pieces)
