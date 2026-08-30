#!/usr/bin/env python3
"""CLI and deterministic negative tests for the development model-selection oracle."""
from __future__ import annotations

import argparse
import copy
from pathlib import Path
import sys
import tempfile

from agent_model_selector import (
    PROOF_CEILING,
    SelectionError,
    canonical_bytes,
    read_json,
    select_models,
    write_candidate,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "integrations/agent-runtimes/model-selection.policy.json"
DEFAULT_INPUT = ROOT / "integrations/agent-runtimes/model-selection.fixture.json"


def expect_failure(name: str, policy: object, request: object, contains: str) -> None:
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
    assert [row["host"] for row in first["selections"]] == [
        "codex",
        "opencode",
        "claude",
        "antigravity",
    ]
    assert first["provider_executions"] == 0 and first["dispatch_authority"] is False
    assert first["production_import_allowed"] is False
    assert first["proof_ceiling"] == PROOF_CEILING
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
    challenger = next(
        row for row in degraded_receipt["selections"] if row["role"] == "challenger"
    )
    assert challenger["diversity_status"] == "degraded"
    assert degraded_receipt["diversity_status"] == "degraded"

    missing_ceiling = copy.deepcopy(policy)
    missing_ceiling.pop("proof_ceiling")
    expect_failure("missing proof ceiling", missing_ceiling, request, "proof_ceiling")

    malformed_list = copy.deepcopy(policy)
    malformed_list["evidence_order"] = ["unknown", {"bad": "shape"}]
    expect_failure("malformed policy list", malformed_list, request, "nonblank string")

    wrong_boolean = copy.deepcopy(policy)
    wrong_boolean["allow_candidate_reuse"] = "false"
    expect_failure("wrong policy boolean", wrong_boolean, request, "boolean required")

    bad_dimension = copy.deepcopy(policy)
    bad_dimension["diversity_dimensions"] = ["host", "missing_field"]
    expect_failure("unknown diversity field", bad_dimension, request, "unsupported fields")

    bad_fingerprint = copy.deepcopy(request)
    bad_fingerprint["candidates"][0]["route_fingerprint"] = "sha256:not-a-digest"
    expect_failure("bad fingerprint", policy, bad_fingerprint, "canonical sha256")

    extensible = copy.deepcopy(policy)
    extensible["allowed_host_families"].append("future-host")
    future = copy.deepcopy(request)
    future["candidates"][0]["host"] = "future-host"
    future_result = select_models(extensible, future)
    assert future_result["selections"][0]["host"] == "future-host"

    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "candidate.json"
        write_candidate(output, first)
        write_candidate(output, copy.deepcopy(first))
        changed = copy.deepcopy(first)
        changed["selection_id"] = "conflicting-selection"
        try:
            write_candidate(output, changed)
        except SelectionError as error:
            assert "immutable candidate conflict" in str(error)
        else:
            raise AssertionError("immutable output conflict: expected failure")

    print("AGENT_MODEL_SELECTOR_ORACLE_SELF_TEST: PASS cases=15")


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
        candidate = select_models(read_json(args.policy), read_json(args.input))
        if args.output:
            write_candidate(args.output, candidate)
        else:
            sys.stdout.buffer.write(canonical_bytes(candidate) + b"\n")
        return 0
    except (SelectionError, AssertionError) as error:
        print(f"AGENT_MODEL_SELECTOR_ORACLE: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
