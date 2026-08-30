#!/usr/bin/env python3
"""Run or inspect the zero-model OpenCode server preflight."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from opencode_server_preflight import (
    CONTRACT_PATH,
    OpenCodePreflightError,
    canonical_json_bytes,
    load_contract,
    run_preflight,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    parser.add_argument("--password-file", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--emit-launch-only", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    try:
        contract = load_contract(root, arguments.contract)
        if arguments.emit_launch_only:
            value = {
                "program": contract["program"],
                "argv": [*contract["launch"]["argv_prefix"], "<reserved_loopback_port>"],
                "shell": False,
                "hostname": "127.0.0.1",
                "environment_allowlist": contract["launch"]["environment_allowlist"],
                "credential_environment_variable": contract["launch"]["credential_environment_variable"],
                "credential_value": None,
                "model_calls": 0,
                "session_calls": 0,
                "route_admitted": False,
            }
        else:
            if arguments.password_file is None:
                raise OpenCodePreflightError("--password-file is required for a live preflight")
            value = run_preflight(root, contract, arguments.password_file.resolve())
    except OpenCodePreflightError as error:
        print(f"OPENCODE_SERVER_PREFLIGHT_ERROR: {error}", file=sys.stderr)
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
