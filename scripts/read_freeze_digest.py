#!/usr/bin/env python3
"""Verify the normalized SHA-256 readback in a cognitive schema freeze.

The freeze stores a self-describing digest: its own value is replaced with 64
ASCII zeroes before hashing.  This keeps the readback reproducible without
claiming that a file can contain its ordinary whole-file hash.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


_DIGEST_LINE = re.compile(rb"(?m)^current_digest = \"([^\"]*)\"(\r?)$")
_ZERO_DIGEST = b"0" * 64


def _readback(path: Path) -> tuple[str, str]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ValueError(f"cannot read {path}: {error}") from error

    matches = list(_DIGEST_LINE.finditer(payload))
    if len(matches) != 1:
        raise ValueError("freeze must contain exactly one current_digest line")

    match = matches[0]
    recorded = match.group(1).decode("ascii")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", recorded):
        raise ValueError("current_digest must be lowercase sha256:<64 hex>")

    normalized = payload[: match.start(1)] + _ZERO_DIGEST + payload[match.end(1) :]
    computed = hashlib.sha256(normalized).hexdigest()
    return recorded, computed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args()

    try:
        recorded, computed = _readback(args.path)
    except ValueError as error:
        print(json.dumps({"path": str(args.path), "error": str(error)}))
        return 2

    result = {
        "path": str(args.path),
        "recorded": f"sha256:{recorded.removeprefix('sha256:')}",
        "computed": f"sha256:{computed}",
        "match": recorded == f"sha256:{computed}",
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["match"] else 1


if __name__ == "__main__":
    sys.exit(main())
