#!/usr/bin/env python3
"""Verify the Antigravity runtime preflight and read-only fallback ceiling."""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable

from antigravity_runtime_preflight import (
    CONTRACT_PATH,
    AntigravityPreflightError,
    ProgramOverride,
    load_contract,
    run_preflight,
    validate_contract,
)

FIXTURE = Path("scripts/fixtures/fake-antigravity-cli.py")


def expect_failure(case: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except AntigravityPreflightError:
        return
    raise AssertionError(f"expected fail-closed Antigravity preflight case: {case}")


def overrides(root: Path, primary_mode: str = "full", fallback_mode: str = "full") -> dict[str, ProgramOverride]:
    fixture = str((root / FIXTURE).resolve())
    return {
        "antigravity.headless": ProgramOverride(
            Path(sys.executable).resolve(),
            (fixture, "--mode", primary_mode, "--runtime", "primary"),
        ),
        "antigravity.agy-readonly": ProgramOverride(
            Path(sys.executable).resolve(),
            (fixture, "--mode", fallback_mode, "--runtime", "fallback"),
        ),
    }


def secret_rich_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "OPENAI_API_KEY": "must-not-forward",
            "ANTHROPIC_API_KEY": "must-not-forward",
            "GOOGLE_API_KEY": "must-not-forward",
            "GEMINI_API_KEY": "must-not-forward",
            "GITHUB_TOKEN": "must-not-forward",
        }
    )
    return environment


def self_test(root: Path) -> None:
    contract = load_contract(root)
    first = run_preflight(
        root,
        contract,
        overrides=overrides(root),
        environment_source=secret_rich_environment(),
    )
    second = run_preflight(
        root,
        copy.deepcopy(contract),
        overrides=overrides(root),
        environment_source=secret_rich_environment(),
    )
    stable_fields = (
        "contract_sha256",
        "runtimes",
        "primary_status",
        "fallback_status",
        "primary_missing_admission_requirements",
        "fallback_contract",
        "provider_credentials_used",
        "execution_calls",
        "model_calls",
        "route_admitted",
        "proof_ceiling",
    )
    if any(first[field] != second[field] for field in stable_fields):
        raise AssertionError("Antigravity preflight semantic receipt is nondeterministic")
    if first["primary_status"] != "observed_help_candidate":
        raise AssertionError("complete primary help markers were not observed")
    if first["fallback_status"] != "observed_read_only_fallback":
        raise AssertionError("read-only fallback was not classified")
    if first["provider_credentials_used"] is not False:
        raise AssertionError("preflight claimed provider credentials")
    if first["execution_calls"] != 0 or first["model_calls"] != 0 or first["route_admitted"] is not False:
        raise AssertionError("preflight crossed into execution or admission")
    primary = next(item for item in first["runtimes"] if item["route_role"] == "primary_candidate")
    if not primary["all_required_help_markers_observed"]:
        raise AssertionError("required help marker closure is false")
    if first["primary_missing_admission_requirements"] != [
        "observed_request_event_schema",
        "current_account_model_catalogue",
        "provider_interrupt_and_terminal_reconciliation",
        "process_tree_containment",
        "descendant_closure",
        "bounded_product_pulse",
    ]:
        raise AssertionError("help probe removed unproved admission requirements")
    fallback = first["fallback_contract"]
    if fallback["worktree_mutation"] is not False or fallback["resume"] is not False:
        raise AssertionError("fallback acquired mutation or continuation")
    if fallback["output_authority"] != "candidate_unified_diff_only":
        raise AssertionError("fallback output authority drifted")

    incomplete = run_preflight(
        root,
        contract,
        overrides=overrides(root, primary_mode="missing-json"),
        environment_source=secret_rich_environment(),
    )
    if incomplete["primary_status"] != "observed_help_incomplete":
        raise AssertionError("missing required help marker was not detected")
    if "required_help_markers" not in incomplete["primary_missing_admission_requirements"]:
        raise AssertionError("incomplete help incorrectly satisfied admission")

    absent_contract = copy.deepcopy(contract)
    for runtime in absent_contract["candidate_runtimes"]:
        runtime["program_candidates"] = [f"eliot-definitely-absent-{runtime['runtime_id']}"]
    absent = run_preflight(root, absent_contract, environment_source=secret_rich_environment())
    if any(runtime["status"] != "absent" for runtime in absent["runtimes"]):
        raise AssertionError("absent runtime was not represented truthfully")

    for mode in ("timeout", "oversized", "nonzero"):
        expect_failure(
            mode,
            lambda mode=mode: run_preflight(
                root,
                contract,
                overrides=overrides(root, primary_mode=mode),
                environment_source=secret_rich_environment(),
            ),
        )

    with tempfile.TemporaryDirectory(prefix="eliot-antigravity-preflight-") as temporary:
        directory = Path(temporary)
        invalid = {
            "antigravity.headless": ProgramOverride(directory, ()),
            "antigravity.agy-readonly": overrides(root)["antigravity.agy-readonly"],
        }
        expect_failure(
            "non-regular executable",
            lambda: run_preflight(root, contract, overrides=invalid),
        )

    fixed = copy.deepcopy(contract)
    fixed["fixed_model_id"] = "universal-model"
    expect_failure("fixed model", lambda: validate_contract(fixed))

    credentials = copy.deepcopy(contract)
    credentials["environment_allowlist"].append("GOOGLE_API_KEY")
    expect_failure("credential environment", lambda: validate_contract(credentials))

    fallback_drift = copy.deepcopy(contract)
    fallback_drift["fallback"]["worktree_mutation"] = True
    expect_failure("fallback mutation", lambda: validate_contract(fallback_drift))

    role_drift = copy.deepcopy(contract)
    role_drift["candidate_runtimes"][1]["route_role"] = "primary_candidate"
    expect_failure("duplicate primary role", lambda: validate_contract(role_drift))


def verify_current(root: Path) -> None:
    contract = load_contract(root, CONTRACT_PATH)
    receipt = run_preflight(
        root,
        contract,
        overrides=overrides(root),
        environment_source=secret_rich_environment(),
    )
    if receipt["proof_ceiling"] != "ZERO_MODEL_EXECUTABLE_AND_HELP_FINGERPRINT_ONLY":
        raise AssertionError("Antigravity proof ceiling drifted")
    if receipt["route_admitted"] is not False or receipt["model_calls"] != 0:
        raise AssertionError("Antigravity preflight overclaimed support")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if arguments.self_test:
        self_test(root)
        print("ANTIGRAVITY_RUNTIME_PREFLIGHT_SELF_TEST: PASS cases=10")
    else:
        verify_current(root)
        print("ANTIGRAVITY_RUNTIME_PREFLIGHT_VERIFY: PASS model_calls=0 route_admitted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
