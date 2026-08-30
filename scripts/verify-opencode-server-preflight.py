#!/usr/bin/env python3
"""Verify the OpenCode loopback server preflight with a fake runtime."""
from __future__ import annotations

import argparse
import copy
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable

from opencode_server_preflight import (
    CONTRACT_PATH,
    OpenCodePreflightError,
    load_contract,
    run_preflight,
    validate_contract,
)

FIXTURE = Path("scripts/fixtures/fake-opencode-server.py")


def expect_failure(case: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except OpenCodePreflightError:
        return
    raise AssertionError(f"expected fail-closed OpenCode preflight case: {case}")


def password_file(directory: Path) -> Path:
    path = directory / "opencode.password"
    path.write_text("test-opencode-password\n", encoding="utf-8")
    return path.resolve()


def run_fake(root: Path, contract: dict, password: Path, mode: str = "success") -> dict:
    environment = dict(os.environ)
    environment["OPENAI_API_KEY"] = "must-not-forward"
    environment["ANTHROPIC_API_KEY"] = "must-not-forward"
    receipt = run_preflight(
        root,
        contract,
        password,
        program_override=Path(sys.executable),
        argv_override_factory=lambda port: [
            str((root / FIXTURE).resolve()),
            "--host", "127.0.0.1",
            "--port", str(port),
            "--mode", mode,
        ],
        environment_source=environment,
        skip_version_probe=True,
    )
    if "OPENAI_API_KEY" in receipt["environment_keys"] or "ANTHROPIC_API_KEY" in receipt["environment_keys"]:
        raise AssertionError("provider API key crossed child environment boundary")
    if receipt["credential_value_recorded"] is not False:
        raise AssertionError("credential value was recorded")
    return receipt


def self_test(root: Path) -> None:
    contract = load_contract(root)
    with tempfile.TemporaryDirectory(prefix="eliot-opencode-preflight-") as temporary:
        password = password_file(Path(temporary))
        first = run_fake(root, contract, password)
        second = run_fake(root, contract, password)
        stable_fields = (
            "contract_sha256", "health", "openapi_version", "openapi_raw_sha256",
            "openapi_canonical_sha256", "operation_count", "required_capabilities",
            "optional_capabilities", "providers", "provider_count", "model_count",
            "catalogue_status", "session_calls", "model_calls", "event_stream_connections",
            "route_admitted", "proof_ceiling",
        )
        if any(first[field] != second[field] for field in stable_fields):
            raise AssertionError("fake OpenCode preflight produced nondeterministic semantic receipt")
        if first["model_count"] != 2 or first["provider_count"] != 1:
            raise AssertionError("provider/model catalogue was not normalized")
        if first["required_capabilities"] != {
            "event_stream": "GET /event",
            "provider_catalogue": "GET /provider",
            "session_abort": "POST /session/{sessionID}/abort",
            "session_create": "POST /session",
            "session_prompt": "POST /session/{sessionID}/message",
        }:
            raise AssertionError("required OpenAPI capability resolution drifted")
        if first["session_calls"] != 0 or first["model_calls"] != 0 or first["event_stream_connections"] != 0:
            raise AssertionError("zero-model preflight crossed into execution")
        if first["route_admitted"] is not False:
            raise AssertionError("preflight overclaimed route admission")

        empty = run_fake(root, contract, password, "empty-catalogue")
        if empty["model_count"] != 0 or empty["catalogue_status"] != "empty":
            raise AssertionError("empty current-account catalogue was not represented truthfully")

        for mode in (
            "missing-abort", "missing-event", "duplicate-model", "unauthorized", "unhealthy",
            "malformed-openapi", "oversized-openapi", "malformed-provider", "oversized-provider",
        ):
            expect_failure(mode, lambda mode=mode: run_fake(root, contract, password, mode))

        fixed = copy.deepcopy(contract)
        fixed["fixed_model_id"] = "universal-model"
        expect_failure("fixed model", lambda: validate_contract(fixed))

        session = copy.deepcopy(contract)
        session["session_creation_allowed"] = True
        expect_failure("session creation enabled", lambda: validate_contract(session))

        network = copy.deepcopy(contract)
        network["launch"]["hostname"] = "0.0.0.0"
        expect_failure("non-loopback launch", lambda: validate_contract(network))

        leaked = copy.deepcopy(contract)
        leaked["launch"]["environment_allowlist"].append("OPENAI_API_KEY")
        expect_failure("provider credential allowlist", lambda: validate_contract(leaked))


def verify_current(root: Path) -> None:
    contract = load_contract(root, CONTRACT_PATH)
    with tempfile.TemporaryDirectory(prefix="eliot-opencode-current-") as temporary:
        receipt = run_fake(root, contract, password_file(Path(temporary)))
    if receipt["proof_ceiling"] != "ZERO_MODEL_SERVER_PREFLIGHT_ONLY":
        raise AssertionError("OpenCode preflight proof ceiling drifted")
    if receipt["process_tree_containment"] != "DIRECT_CHILD_ONLY_DIAGNOSTIC":
        raise AssertionError("OpenCode diagnostic process containment overclaimed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if arguments.self_test:
        self_test(root)
        print("OPENCODE_SERVER_PREFLIGHT_SELF_TEST: PASS cases=13")
    else:
        verify_current(root)
        print("OPENCODE_SERVER_PREFLIGHT_VERIFY: PASS providers=1 models=2 model_calls=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
