#!/usr/bin/env python3
"""Verify the provider-free ELIOT cross-route swarm Product Pulse."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Callable

from swarm_product_pulse import (
    CONTRACT_PATH,
    SCENARIO_PATH,
    SwarmPulseError,
    canonical_json_bytes,
    load_json,
    run_swarm_pulse,
)


def _expect_failure(case: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except SwarmPulseError:
        return
    raise AssertionError(f"expected fail-closed swarm case: {case}")


def _execute(root: Path, contract: dict, scenario: dict) -> dict:
    return run_swarm_pulse(root, contract, scenario)


def self_test(root: Path) -> None:
    contract = load_json(root / CONTRACT_PATH, "swarm pulse contract")
    scenario = load_json(root / SCENARIO_PATH, "swarm pulse scenario")

    first = _execute(root, contract, scenario)
    second = _execute(root, copy.deepcopy(contract), copy.deepcopy(scenario))
    if first != second:
        raise AssertionError("swarm pulse receipt is nondeterministic")
    if first["hosts"] != ["antigravity", "claude", "codex", "opencode"]:
        raise AssertionError("swarm pulse host denominator drifted")
    if first["provider_executions"] != 0 or first["eligible_for_route_promotion"] is not False:
        raise AssertionError("simulated pulse overclaimed runtime or promotion")

    raw_prompt = copy.deepcopy(scenario)
    raw_prompt["work_items"][0]["context_packet"]["raw_prompt"] = "forbidden"
    _expect_failure("raw/full prompt payload", lambda: _execute(root, contract, raw_prompt))

    selected_model = copy.deepcopy(scenario)
    selected_model["work_items"][0]["selected_model_id"] = "unreceipted-model"
    _expect_failure("unreceipted selected model", lambda: _execute(root, contract, selected_model))

    provider_execution = copy.deepcopy(scenario)
    provider_execution["work_items"][1]["provider_execution"] = True
    _expect_failure("provider execution overclaim", lambda: _execute(root, contract, provider_execution))

    native_child = copy.deepcopy(scenario)
    native_child["work_items"][2]["native_subagents"] = True
    _expect_failure("native subagent admission", lambda: _execute(root, contract, native_child))

    direct_chat = copy.deepcopy(scenario)
    direct_chat["mailbox"][0] = {
        "message_id": "mail:worker-to-worker",
        "from": "attempt:codex-001",
        "to": "attempt:opencode-001",
        "kind": "sealed_result_ref",
        "reference": "result:codex-001",
    }
    _expect_failure("direct worker group chat", lambda: _execute(root, contract, direct_chat))

    result_authority = copy.deepcopy(scenario)
    result_authority["sealed_results"][0]["candidate_only"] = False
    result_authority["sealed_results"][0]["authority"] = "task_decision"
    _expect_failure("worker result authority", lambda: _execute(root, contract, result_authority))

    unknown_descendant = copy.deepcopy(scenario)
    unknown_descendant["cancellation_receipts"][0]["descendants_closed"] = False
    unknown_descendant["cancellation_receipts"][0]["unknown_live_descendants"] = True
    _expect_failure("unknown live descendant", lambda: _execute(root, contract, unknown_descendant))

    no_dissent = copy.deepcopy(scenario)
    no_dissent["concilium"]["preserved_dissent"] = []
    _expect_failure("Concilium without dissent", lambda: _execute(root, contract, no_dissent))

    worker_decision = copy.deepcopy(scenario)
    worker_decision["decision"]["owner"] = "worker_vote"
    worker_decision["decision"]["disposition"] = "promote"
    worker_decision["decision"]["eligible_for_route_promotion"] = True
    _expect_failure("worker vote/promotion", lambda: _execute(root, contract, worker_decision))


def verify_current(root: Path) -> dict:
    contract = load_json(root / CONTRACT_PATH, "swarm pulse contract")
    scenario = load_json(root / SCENARIO_PATH, "swarm pulse scenario")
    receipt = _execute(root, contract, scenario)
    expected = {
        "work_items": 4,
        "agent_attempts": 4,
        "sealed_results": 3,
        "cancellations": 1,
        "mailbox_messages": 8,
        "provider_executions": 0,
        "selected_model_ids": 0,
        "native_subagents": False,
        "direct_group_chat": False,
        "worker_voting": False,
        "decision_owner": "task_controller_or_human",
        "decision_disposition": "simulated_no_promotion",
        "eligible_for_route_promotion": False,
        "proof_ceiling": "DETERMINISTIC_CONTROL_PLANE_SHAPE_ONLY",
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise AssertionError(f"receipt field drifted: {key}")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--emit-receipt", type=Path)
    arguments = parser.parse_args()
    root = arguments.root.resolve()

    if arguments.self_test:
        self_test(root)
        print("SWARM_PRODUCT_PULSE_SELF_TEST: PASS cases=9")
        return 0

    receipt = verify_current(root)
    if arguments.emit_receipt:
        arguments.emit_receipt.parent.mkdir(parents=True, exist_ok=True)
        arguments.emit_receipt.write_bytes(canonical_json_bytes(receipt) + b"\n")
    else:
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
