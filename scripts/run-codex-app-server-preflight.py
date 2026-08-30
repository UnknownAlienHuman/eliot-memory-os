#!/usr/bin/env python3
"""Run or inspect the stable zero-model Codex App Server preflight."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from codex_app_server_preflight import (
    CONTRACT_PATH,
    CodexPreflightError,
    canonical_json_bytes,
    load_contract,
    run_preflight,
    stable_messages,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--emit-requests-only", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()

    try:
        contract = load_contract(root, arguments.contract)
        value = stable_messages(contract) if arguments.emit_requests_only else run_preflight(root, contract)
    except CodexPreflightError as error:
        print(f"CODEX_APP_SERVER_PREFLIGHT_ERROR: {error}", file=sys.stderr)
        return 2

    encoded = canonical_json_bytes(value) + b"\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_bytes(encoded)
    else:
        print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
