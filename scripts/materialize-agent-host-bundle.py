#!/usr/bin/env python3
"""Materialize one deterministic ELIOT agent-host bundle."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_host_bundle import BundleError, MANIFEST_PATH, materialize_host_bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", choices=("codex", "opencode", "claude", "antigravity"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    try:
        receipt = materialize_host_bundle(
            arguments.root,
            arguments.host,
            arguments.output,
            arguments.manifest,
        )
    except BundleError as error:
        print(f"AGENT_HOST_BUNDLE_ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
