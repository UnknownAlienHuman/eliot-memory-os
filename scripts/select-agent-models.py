#!/usr/bin/env python3
"""CLI and deterministic negative tests for ELIOT model selection."""
from __future__ import annotations

import argparse
import copy
from pathlib import Path
import sys

from agent_model_selector import SelectionError, canonical_bytes, read_json, select_models, write_receipt

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "integrations/agent-runtimes/model-selection.policy.json"
DEFAULT_INPUT = ROOT / "integrations/agent-runtimes/model-selection.fixture.json"


def expect_failure(name: str, policy: dict, request: dict, contains: str) -> None:
    try:
        select_models(policy, request)
    except SelectionError as error:
        if contains not in str(error):
            raise AssertionError(f"{name}: wrong failure: {error}") from error
        return
    raise AssertionError(f"{name}: expected failure")


def self_test() -> None:
    policy = read_json(DEFAULT_POLICY)
    request = read_json(DEFAULT_INPUT)
    first = select_models(policy, request)
    second = select_models(copy.deepcopy(policy), copy.deepcopy(request))
    assert canonical_bytes(first) == canonical_bytes(second), "determinism"
    assert [row["host"] for row in first["selections"]] == ["codex", "opencode", "claude", "antigravity"]
    assert first["provider_executions"] == 0 and first["dispatch_authority"] is False
    assert first["diversity_status"] == "satisfied"

    secret = copy.deepcopy(request)
    secret["candidates"][0]["api_key"] = "not-a-real-key"
    expect_failure("secret input", policy, secret, "secret-bearing")

    weak = copy.deepcopy(request)
    weak["candidates"][0]["capabilities"]["tool_use"]["evidence"] = "documented"
    expect_failure("weak evidence", policy, weak, "no eligible")

    quota = copy.deepcopy(request)
    quota["candidates"][1]["quota_status"] = "exhausted"
    expect_failure("exhausted quota", policy, quota, "no eligible")

    inferred = copy.deepcopy(request)
    inferred["candidates"][2]["model_id"] = "super-reasoning-model"
    inferred["candidates"][2]["capabilities"].pop("reasoning")
    expect_failure("no name inference", policy, inferred, "no eligible")

    fixed = copy.deepcopy(policy)
    fixed["fixed_model_id"] = "forbidden"
    expect_failure("fixed model policy", fixed, request, "fixed/default")

    duplicate = copy.deepcopy(request)
    duplicate["candidates"].append(copy.deepcopy(duplicate["candidates"][0]))
    expect_failure("duplicate candidate", policy, duplicate, "duplicate")

    degraded = copy.deepcopy(request)
    degraded["candidates"][2]["host"] = "codex"
    degraded["candidates"][2]["model_family"] = "codex-family"
    degraded_receipt = select_models(policy, degraded)
    challenger = next(row for row in degraded_receipt["selections"] if row["role"] == "challenger")
    assert challenger["diversity_status"] == "degraded"
    assert degraded_receipt["diversity_status"] == "degraded"

    print("AGENT_MODEL_SELECTOR_SELF_TEST: PASS cases=8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        receipt = select_models(read_json(args.policy), read_json(args.input))
        if args.output:
            write_receipt(args.output, receipt)
        else:
            sys.stdout.buffer.write(canonical_bytes(receipt) + b"\n")
        return 0
    except (SelectionError, AssertionError) as error:
        print(f"AGENT_MODEL_SELECTOR: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
