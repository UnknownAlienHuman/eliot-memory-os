#!/usr/bin/env python3
"""Verify Codex App Server preflight framing and bounded failure behavior."""
from __future__ import annotations

import argparse
import copy
import os
import sys
from pathlib import Path
from typing import Callable

from codex_app_server_preflight import (
    CONTRACT_PATH,
    CodexPreflightError,
    load_contract,
    run_preflight,
    stable_messages,
    validate_contract,
)

FIXTURE = Path("scripts/fixtures/fake-codex-app-server.py")


def _expect_failure(case: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except CodexPreflightError:
        return
    raise AssertionError(f"expected fail-closed Codex preflight case: {case}")


def _run_fake(root: Path, contract: dict, mode: str = "success") -> dict:
    environment = dict(os.environ)
    environment["OPENAI_API_KEY"] = "synthetic-value-must-not-forward"
    receipt = run_preflight(
        root,
        contract,
        program_override=Path(sys.executable),
        argv_override=[str((root / FIXTURE).resolve()), mode],
        environment_source=environment,
        skip_version_probe=True,
    )
    if "OPENAI_API_KEY" in receipt["environment_keys"]:
        raise AssertionError("provider credential variable crossed environment boundary")
    return receipt


def self_test(root: Path) -> None:
    contract = load_contract(root)
    messages = stable_messages(contract)
    if [message["method"] for message in messages] != ["initialize", "initialized", "model/list"]:
        raise AssertionError("stable message order drifted")
    if any("jsonrpc" in message for message in messages):
        raise AssertionError("stale JSON-RPC envelope entered requests")
    if any("protocolVersion" in str(message) for message in messages):
        raise AssertionError("ELIOT/internal protocol identifier entered provider wire")

    first = _run_fake(root, contract)
    second = _run_fake(root, contract)
    stable_fields = (
        "contract_sha256",
        "methods_sent",
        "catalogue_pages",
        "model_count",
        "default_model_id",
        "models",
        "model_calls",
        "thread_calls",
        "turn_calls",
        "experimental_api",
        "route_admitted",
        "proof_ceiling",
    )
    if any(first[field] != second[field] for field in stable_fields):
        raise AssertionError("fake transcript produced nondeterministic semantic receipt")
    if first["model_count"] != 3 or first["default_model_id"] != "fake-codex-a":
        raise AssertionError("paginated model catalogue was not normalized")
    if first["methods_sent"] != ["initialize", "initialized", "model/list", "model/list"]:
        raise AssertionError("unexpected methods were sent")
    if first["model_calls"] != 0 or first["thread_calls"] != 0 or first["turn_calls"] != 0:
        raise AssertionError("zero-model preflight crossed into execution")
    if first["route_admitted"] is not False or first["experimental_api"] is not False:
        raise AssertionError("preflight overclaimed route admission or experimental API")

    _expect_failure("duplicate model", lambda: _run_fake(root, contract, "duplicate-model"))
    _expect_failure("stale jsonrpc envelope", lambda: _run_fake(root, contract, "jsonrpc"))
    _expect_failure("mismatched response id", lambda: _run_fake(root, contract, "mismatch-id"))
    _expect_failure("server error", lambda: _run_fake(root, contract, "server-error"))
    _expect_failure("malformed JSONL", lambda: _run_fake(root, contract, "malformed"))
    _expect_failure("oversized JSONL", lambda: _run_fake(root, contract, "oversized"))

    fixed = copy.deepcopy(contract)
    fixed["fixed_model_id"] = "universal-model"
    _expect_failure("fixed model", lambda: validate_contract(fixed))

    experimental = copy.deepcopy(contract)
    experimental["requests"][0]["params"]["capabilities"]["experimentalApi"] = True
    _expect_failure("experimental API", lambda: validate_contract(experimental))

    protocol = copy.deepcopy(contract)
    protocol["requests"][0]["params"]["protocolVersion"] = "eliot.internal"
    _expect_failure("internal protocolVersion", lambda: validate_contract(protocol))

    forbidden = copy.deepcopy(contract)
    forbidden["requests"][2]["method"] = "turn/start"
    _expect_failure("forbidden model execution method", lambda: validate_contract(forbidden))


def verify_current(root: Path) -> dict:
    contract = load_contract(root, CONTRACT_PATH)
    receipt = _run_fake(root, contract)
    if receipt["model_count"] != 3:
        raise AssertionError("fake catalogue count mismatch")
    if receipt["process_tree_containment"] != "DIRECT_CHILD_ONLY_DIAGNOSTIC":
        raise AssertionError("diagnostic process proof ceiling drifted")
    if receipt["proof_ceiling"] != "ZERO_MODEL_DIAGNOSTIC_PREFLIGHT_ONLY":
        raise AssertionError("preflight proof ceiling drifted")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if arguments.self_test:
        self_test(root)
        print("CODEX_APP_SERVER_PREFLIGHT_SELF_TEST: PASS cases=10")
    else:
        verify_current(root)
        print("CODEX_APP_SERVER_PREFLIGHT_VERIFY: PASS models=3 model_calls=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
