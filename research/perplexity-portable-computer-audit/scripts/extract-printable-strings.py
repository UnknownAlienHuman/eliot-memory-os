#!/usr/bin/env python3
"""Streaming printable-string extractor for static binary inspection.

The input is treated only as bytes: it is never imported, decoded as code, or
executed. Output lines contain a byte offset, encoding, and escaped string.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _emit(out, offset: int, encoding: str, value: str) -> None:
    out.write(json.dumps({"offset": offset, "encoding": encoding, "string": value}, ensure_ascii=False) + "\n")


def _ascii(data: bytes, base: int, state: bytearray, start: int | None, out, minimum: int) -> tuple[int | None, bytearray]:
    for index, byte in enumerate(data):
        absolute = base + index
        if 0x20 <= byte <= 0x7E:
            if start is None:
                start = absolute
            state.append(byte)
        else:
            if start is not None and len(state) >= minimum:
                _emit(out, start, "ASCII", state.decode("ascii"))
            state.clear()
            start = None
    return start, state


def _utf16le(data: bytes, base: int, state: bytearray, start: int | None, out, minimum: int) -> tuple[int | None, bytearray]:
    # Keep code-unit alignment across chunks. Printable UTF-16LE ASCII-range
    # characters have a printable low byte and a zero high byte.
    if len(data) % 2:
        raise ValueError("UTF-16 scanner received an unaligned chunk")
    for index in range(0, len(data), 2):
        absolute = base + index
        low, high = data[index], data[index + 1]
        printable = 0x20 <= low <= 0x7E and high == 0
        if printable:
            if start is None:
                start = absolute
            state.extend((low, high))
        else:
            if start is not None and len(state) // 2 >= minimum:
                _emit(out, start, "UTF-16LE", state.decode("utf-16le"))
            state.clear()
            start = None
    return start, state


def extract(source: Path, output, minimum: int, chunk_size: int) -> None:
    ascii_state = bytearray()
    ascii_start = None
    utf_state = bytearray()
    utf_start = None
    utf_pending = b""
    offset = 0
    with source.open("rb") as stream:
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            ascii_start, ascii_state = _ascii(chunk, offset, ascii_state, ascii_start, output, minimum)
            # Keep one byte across chunks so code-unit offsets remain exact.
            utf_chunk = utf_pending + chunk
            utf_base = offset - len(utf_pending)
            if len(utf_chunk) % 2:
                utf_pending = utf_chunk[-1:]
                utf_chunk = utf_chunk[:-1]
            else:
                utf_pending = b""
            utf_start, utf_state = _utf16le(utf_chunk, utf_base, utf_state, utf_start, output, minimum)
            offset += len(chunk)
    if ascii_start is not None and len(ascii_state) >= minimum:
        _emit(output, ascii_start, "ASCII", ascii_state.decode("ascii"))
    if utf_start is not None and len(utf_state) // 2 >= minimum:
        _emit(output, utf_start, "UTF-16LE", utf_state.decode("utf-16le"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract ASCII and UTF-16LE printable strings without executing input")
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=None)
    parser.add_argument("-m", "--minimum", type=int, default=6)
    parser.add_argument("--chunk-size", type=int, default=1024 * 1024)
    args = parser.parse_args()
    if args.minimum < 1 or args.chunk_size < 2:
        parser.error("minimum must be positive and chunk-size must be at least 2")
    if not args.input.is_file():
        parser.error(f"input is not a regular file: {args.input}")
    if args.output is None:
        extract(args.input, sys.stdout, args.minimum, args.chunk_size)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8", newline="\n") as handle:
            extract(args.input, handle, args.minimum, args.chunk_size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
