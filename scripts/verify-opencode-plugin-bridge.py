#!/usr/bin/env python3
"""Verify the OpenCode plugin's persistent bridge and payload boundary."""
from __future__ import annotations

import argparse
import copy
import json
import tempfile
from pathlib import Path
from typing import Callable

CONTRACT = Path("integrations/opencode/plugin-bridge-contract.v2.json")
PLUGIN = Path("integrations/opencode/plugins/eliot.js")
TEST = Path("integrations/opencode/tests/eliot-plugin-bridge-v2.test.mjs")
CONTRACT_VERSION = "eliot.opencode-plugin-bridge.v2"


class VerifyError(RuntimeError):
    pass


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerifyError(f"{path}: unreadable JSON") from error
    if not isinstance(value, dict):
        raise VerifyError(f"{path}: JSON root must be an object")
    return value


def contract_errors(contract: dict) -> list[str]:
    errors: list[str] = []
    expected = {
        "schema_version": CONTRACT_VERSION,
        "transport_preference": ["authenticated_loopback_http"],
        "endpoint_path": "/v1/host-events",
        "allowed_schemes": ["http"],
        "url_credentials_allowed": False,
        "url_query_allowed": False,
        "url_fragment_allowed": False,
        "credential_source": "bounded_absolute_token_file",
        "credential_in_payload": False,
        "credential_in_logs": False,
        "raw_tool_arguments_allowed": False,
        "raw_tool_output_allowed": False,
        "raw_prompt_or_message_allowed": False,
        "raw_environment_allowed": False,
        "raw_error_or_stack_allowed": False,
        "passive_delivery": "bounded_serialized_nonblocking",
        "attached_mutation_gate": "fail_closed_without_explicit_decision",
        "legacy_process_spawn": False,
        "authority_ceiling": "observation_and_pre_effect_gate_candidate",
        "proof_ceiling": "PLUGIN_TRANSPORT_AND_PAYLOAD_BOUNDARY_ONLY",
    }
    for key, value in expected.items():
        if contract.get(key) != value:
            errors.append(f"contract:{key}")
    if set(contract.get("allowed_hosts", [])) != {"127.0.0.1", "localhost", "::1"}:
        errors.append("contract:allowed_hosts")
    if contract.get("accepted_gate_decisions") != ["allow", "allowed", "pass", "recorded"]:
        errors.append("contract:accepted_gate_decisions")
    if contract.get("denied_gate_decision") != "deny":
        errors.append("contract:denied_gate_decision")
    limits = contract.get("limits")
    if not isinstance(limits, dict):
        errors.append("contract:limits")
    else:
        required = {
            "request_bytes": 32768,
            "response_bytes": 65536,
            "token_file_bytes": 4096,
            "passive_queue_default": 64,
            "passive_queue_max": 256,
            "timeout_ms_default": 5000,
            "timeout_ms_min": 500,
            "timeout_ms_max": 15000,
            "retry_count": 1,
        }
        for key, value in required.items():
            if limits.get(key) != value:
                errors.append(f"contract:limits.{key}")
    return errors


def plugin_errors(text: str) -> list[str]:
    errors: list[str] = []
    forbidden = {
        "Bun.spawn": "process_spawn",
        "child_process": "process_spawn",
        "env: process.env": "full_environment_forward",
        "...process.env": "full_environment_forward",
        "JSON.stringify(input)": "raw_input_serialization",
        "JSON.stringify(output)": "raw_output_serialization",
        "metadata: input": "raw_input_serialization",
        "metadata: output": "raw_output_serialization",
        "return { decision: \"passive\"": "mutation_fail_open",
    }
    for marker, code in forbidden.items():
        if marker in text:
            errors.append(code)
    required = {
        'schema_version: "eliot.opencode-host-event.v2"': "event_schema",
        'url.pathname = "/v1/host-events"': "endpoint",
        '"Authorization": `Bearer ${token}`': "authorization",
        '"Idempotency-Key": eventId': "idempotency",
        "AbortController": "timeout",
        "MAX_REQUEST_BYTES": "request_bound",
        "MAX_RESPONSE_BYTES": "response_bound",
        "MAX_TOKEN_BYTES": "token_bound",
        "passiveQueueLimit": "queue_bound",
        "passiveQueue = passiveQueue.then": "serialized_queue",
        "projectedMetadata": "event_projector",
        "safeMetadataKey": "sensitive_argument_key_filter",
        "safeReasonCode": "reason_code_filter",
        "readBridgeToken": "token_file",
        "isSymbolicLink": "token_symlink_rejection",
        "if (required) throw new Error": "required_fail_closed",
        'if (decision === "deny")': "explicit_deny",
        "ACCEPTED_GATE_DECISIONS.has": "explicit_allow_set",
        "RETRYABLE_STATUS.has": "bounded_retry",
        "enqueuePassive": "passive_dispatch",
        "attachedTask() && mutating": "attached_mutation_gate",
    }
    for marker, code in required.items():
        if marker not in text:
            errors.append(f"missing:{code}")
    if text.count("fetch(") != 1:
        errors.append("unexpected_fetch_surface_count")
    if "result.reason" in text and "result.reason_code" not in text:
        errors.append("raw_reason_forwarding")
    envelope_start = text.find("const envelope = {")
    envelope_end = text.find("\n  }", envelope_start)
    if envelope_start < 0 or envelope_end < 0:
        errors.append("missing_envelope")
    else:
        envelope = text[envelope_start:envelope_end]
        for marker in ("args", "output", "prompt", "messages", "properties", "environment", "stack"):
            if marker in envelope:
                errors.append(f"envelope_raw_field:{marker}")
    return sorted(set(errors))


def verify(root: Path) -> None:
    contract_path = root / CONTRACT
    plugin_path = root / PLUGIN
    test_path = root / TEST
    for path in (contract_path, plugin_path, test_path):
        if not path.is_file():
            raise VerifyError(f"missing required file: {path.relative_to(root)}")
    errors = contract_errors(load_json(contract_path))
    errors.extend(plugin_errors(plugin_path.read_text(encoding="utf-8")))
    if errors:
        raise VerifyError("; ".join(sorted(set(errors))))


def expect_failure(case: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except VerifyError:
        return
    raise AssertionError(f"expected verifier failure: {case}")


def self_test(root: Path) -> None:
    contract = load_json(root / CONTRACT)
    plugin = (root / PLUGIN).read_text(encoding="utf-8")
    if contract_errors(contract) or plugin_errors(plugin):
        raise AssertionError("clean contract/plugin failed verifier primitives")

    bad_contract = copy.deepcopy(contract)
    bad_contract["legacy_process_spawn"] = True
    if "contract:legacy_process_spawn" not in contract_errors(bad_contract):
        raise AssertionError("legacy spawn contract drift was not detected")

    cases = {
        "process spawn": plugin + "\nBun.spawn(['legacy'])\n",
        "full env": plugin + "\nconst leaked = { ...process.env }\n",
        "raw input": plugin + "\nJSON.stringify(input)\n",
        "missing idempotency": plugin.replace('"Idempotency-Key": eventId,', ""),
        "missing timeout": plugin.replace("AbortController", "RemovedController"),
        "missing projector": plugin.replace("projectedMetadata", "removedProjector"),
        "fail open": plugin + '\nreturn { decision: "passive" }\n',
    }
    for case, text in cases.items():
        if not plugin_errors(text):
            raise AssertionError(f"plugin negative case was not detected: {case}")

    with tempfile.TemporaryDirectory(prefix="eliot-opencode-verifier-") as temporary:
        fake = Path(temporary)
        (fake / CONTRACT.parent).mkdir(parents=True)
        (fake / PLUGIN.parent).mkdir(parents=True)
        (fake / TEST.parent).mkdir(parents=True)
        (fake / CONTRACT).write_text(json.dumps(contract), encoding="utf-8")
        (fake / PLUGIN).write_text(plugin + "\nBun.spawn(['legacy'])\n", encoding="utf-8")
        (fake / TEST).write_text("test fixture", encoding="utf-8")
        expect_failure("repository process spawn", lambda: verify(fake))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if arguments.self_test:
        self_test(root)
        print("OPENCODE_PLUGIN_BRIDGE_SELF_TEST: PASS cases=8")
    else:
        verify(root)
        print("OPENCODE_PLUGIN_BRIDGE_VERIFY: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
