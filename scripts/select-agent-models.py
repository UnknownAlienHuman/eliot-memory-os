#!/usr/bin/env python3
"""Select receipted route/model candidates for bounded AgentAttempt roles."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_model_selector import (
    FIXTURE_PATH,
    POLICY_PATH,
    SelectionError,
    canonical_json_bytes,
    load_json,
    select_models,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    parser.add_argument("--catalogue", type=Path, default=FIXTURE_PATH)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()

    root = arguments.root.resolve()
    try:
        policy = load_json(root / arguments.policy, "model-selection policy")
        catalogue = load_json(root / arguments.catalogue, "route catalogue")
        receipt = select_models(policy, catalogue)
    except SelectionError as error:
        print(f"AGENT_MODEL_SELECTION_ERROR: {error}", file=sys.stderr)
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
