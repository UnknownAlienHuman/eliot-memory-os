#!/usr/bin/env python3
"""Run the zero-model Antigravity executable/help preflight."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from antigravity_runtime_preflight import (
    CONTRACT_PATH,
    AntigravityPreflightError,
    canonical_json_bytes,
    load_contract,
    run_preflight,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    try:
        contract = load_contract(root, arguments.contract)
        receipt = run_preflight(root, contract)
    except AntigravityPreflightError as error:
        print(f"ANTIGRAVITY_RUNTIME_PREFLIGHT_ERROR: {error}", file=sys.stderr)
        return 2
    encoded = canonical_json_bytes(receipt) + b"\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_bytes(encoded)
    else:
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
