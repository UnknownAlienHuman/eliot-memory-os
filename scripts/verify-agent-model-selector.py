#!/usr/bin/env python3
"""Verify ELIOT's deterministic route/model selection contract."""
from __future__ import annotations

import argparse
import copy
from pathlib import Path
from typing import Any, Callable

from agent_model_selector import (
    FIXTURE_PATH,
    POLICY_PATH,
    SelectionError,
    load_json,
    select_models,
    selection_for_role,
)


def _expect_failure(case: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except SelectionError:
        return
    raise AssertionError(f"expected fail-closed selector case: {case}")


def _selection(receipt: dict[str, Any], role: str) -> dict[str, Any]:
    selected = selection_for_role(receipt, role)
    if selected is None:
        raise AssertionError(f"role {role} was not selected")
    return selected


def _role_record(receipt: dict[str, Any], role: str) -> dict[str, Any]:
    for item in receipt["selections"]:
        if item["role"] == role:
            return item
    raise AssertionError(f"role record {role} is missing")


def _has_reason(receipt: dict[str, Any], role: str, model_id: str, prefix: str) -> bool:
    record = _role_record(receipt, role)
    for rejection in record["rejections"]:
        if rejection["model_id"] == model_id and any(reason.startswith(prefix) for reason in rejection["reason_codes"]):
            return True
    return False


def self_test(root: Path) -> None:
    policy = load_json(root / POLICY_PATH, "model-selection policy")
    catalogue = load_json(root / FIXTURE_PATH, "route catalogue")

    first = select_models(policy, catalogue)
    second = select_models(copy.deepcopy(policy), copy.deepcopy(catalogue))
    if first != second:
        raise AssertionError("selector is nondeterministic")
    if first["provider_executions"] != 0 or first["dispatch_authority"] is not False:
        raise AssertionError("selector overclaimed execution or dispatch authority")
    if first["authority"] != "candidate_route_selection_only":
        raise AssertionError("selector authority ceiling drifted")
    if first["diversity_status"] != "satisfied":
        raise AssertionError("four-host fixture did not satisfy diversity")
    selected_hosts = {
        role: _selection(first, role)["host"]
        for role in ("primary", "cheap_worker", "challenger", "verifier")
    }
    if selected_hosts != {
        "primary": "claude",
        "cheap_worker": "opencode",
        "challenger": "codex",
        "verifier": "antigravity",
    }:
        raise AssertionError(f"unexpected deterministic selections: {selected_hosts}")

    no_name_inference = copy.deepcopy(catalogue)
    codex_model = no_name_inference["routes"][0]["models"][0]
    codex_model["display_name"] = "Guaranteed Best Coding Model"
    codex_model["capabilities"]["coding"] = {
        "support": False,
        "evidence_level": "unknown",
    }
    no_name_receipt = select_models(policy, no_name_inference)
    if not _has_reason(no_name_receipt, "challenger", codex_model["model_id"], "CAPABILITY_UNSUPPORTED:coding"):
        raise AssertionError("selector inferred coding capability from a model name")

    exhausted = copy.deepcopy(catalogue)
    exhausted["routes"][1]["quota"]["status"] = "exhausted"
    exhausted_receipt = select_models(policy, exhausted)
    if _selection(exhausted_receipt, "cheap_worker")["host"] == "opencode":
        raise AssertionError("exhausted route remained selectable")
    if not _has_reason(exhausted_receipt, "cheap_worker", "opencode-fixture-worker", "QUOTA_NOT_DISPATCHABLE"):
        raise AssertionError("exhausted quota rejection was not receipted")

    weak = copy.deepcopy(catalogue)
    weak["routes"][3]["models"][0]["capabilities"]["structured_output"]["evidence_level"] = "declared"
    weak_receipt = select_models(policy, weak)
    if not _has_reason(
        weak_receipt,
        "verifier",
        "antigravity-fixture-verifier",
        "CAPABILITY_EVIDENCE_TOO_WEAK:structured_output",
    ):
        raise AssertionError("weak capability evidence remained eligible")

    degraded = copy.deepcopy(catalogue)
    for route in degraded["routes"]:
        for model in route["models"]:
            model["model_family"] = "one-shared-family"
    degraded_receipt = select_models(policy, degraded)
    if degraded_receipt["diversity_status"] != "degraded":
        raise AssertionError("diversity degradation was hidden")
    if _role_record(degraded_receipt, "challenger")["diversity_status"] != "degraded":
        raise AssertionError("challenger degradation was not receipted")

    secret = copy.deepcopy(catalogue)
    secret["routes"][0]["api_key"] = "must-not-enter-selector"
    _expect_failure("secret selector input", lambda: select_models(policy, secret))

    fixed = copy.deepcopy(policy)
    fixed["fixed_model_id"] = "universal-model"
    _expect_failure("fixed universal model", lambda: select_models(fixed, catalogue))

    duplicate = copy.deepcopy(catalogue)
    duplicate["routes"].append(copy.deepcopy(duplicate["routes"][0]))
    _expect_failure("duplicate route", lambda: select_models(policy, duplicate))


def verify_current(root: Path) -> None:
    policy = load_json(root / POLICY_PATH, "model-selection policy")
    catalogue = load_json(root / FIXTURE_PATH, "route catalogue")
    receipt = select_models(policy, catalogue)
    if len(receipt["selections"]) != 4:
        raise AssertionError("selector did not emit all four bounded roles")
    for role in ("primary", "cheap_worker", "challenger", "verifier"):
        selected = _selection(receipt, role)
        for field in (
            "host",
            "route_id",
            "route_fingerprint",
            "account_scope_hash",
            "catalogue_observed_at",
            "model_id",
            "model_family",
            "score",
            "score_components",
        ):
            if field not in selected:
                raise AssertionError(f"{role}: missing receipt field {field}")
    if receipt["provider_executions"] != 0 or receipt["dispatch_authority"] is not False:
        raise AssertionError("selector proof ceiling drifted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if arguments.self_test:
        self_test(root)
        print("AGENT_MODEL_SELECTOR_SELF_TEST: PASS cases=8")
    else:
        verify_current(root)
        print("AGENT_MODEL_SELECTOR_VERIFY: PASS roles=4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
