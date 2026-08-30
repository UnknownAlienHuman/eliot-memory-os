#!/usr/bin/env python3
"""Static verification for the Claude Agent SDK sidecar contract."""
from __future__ import annotations

import argparse
import copy
import json
import tempfile
from pathlib import Path

CONTRACT = Path("integrations/claude/agent-sdk-sidecar-contract.v2.json")
SIDECAR = Path("integrations/claude/agent-sdk-sidecar/eliot_claude_sidecar.py")
TESTS = Path("integrations/claude/agent-sdk-sidecar/test_sidecar.py")
VERSION = "eliot.claude-agent-sdk-sidecar.v2"


class VerifyError(RuntimeError):
    pass


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerifyError(f"{path}: unreadable JSON") from error
    if not isinstance(value, dict):
        raise VerifyError(f"{path}: root must be an object")
    return value


def contract_errors(contract: dict) -> list[str]:
    errors: list[str] = []
    expected = {
        "schema_version": VERSION,
        "transport": "stdio_ndjson",
        "requests": ["hello", "probe", "start", "cancel", "shutdown"],
        "setting_sources": [],
        "ambient_settings_allowed": False,
        "raw_mcp_servers_allowed": False,
        "raw_mcp_commands_allowed": False,
        "raw_plugin_paths_allowed": False,
        "raw_skill_bodies_allowed": False,
        "credentials_in_requests_allowed": False,
        "profile_resolution": "eliot_registry_ids_only",
        "model_catalogue_supported": False,
        "model_selection": "external_receipt_per_attempt",
        "fixed_model_id": None,
        "native_subagents": False,
        "terminal_result_separate_from_event_history": True,
        "task_authority": False,
        "attempt_authority": False,
        "finish_authority": False,
        "recovery_authority": False,
        "swarm_control_plane": "eliot.coordinate",
        "worker_result_authority": "candidate_only",
        "route_admitted": False,
        "proof_ceiling": "FAKE_SDK_AND_PROTOCOL_BEHAVIOR_ONLY",
    }
    for key, value in expected.items():
        if contract.get(key) != value:
            errors.append(f"contract:{key}")
    if contract.get("forbidden_permission_modes") != ["bypassPermissions"]:
        errors.append("contract:forbidden_permission_modes")
    if set(contract.get("permission_modes", [])) != {"default", "acceptEdits", "plan", "dontAsk"}:
        errors.append("contract:permission_modes")
    events = contract.get("events", [])
    for required in ("provider.error", "attempt.result", "attempt.cancelled", "attempt.failed", "attempt.cleanup"):
        if required not in events:
            errors.append(f"contract:event:{required}")
    return errors


def source_errors(text: str) -> list[str]:
    errors: list[str] = []
    forbidden = {
        '"bypassPermissions"': "bypass_permission_literal",
        "setting_sources=None": "ambient_setting_sources",
        "setting_sources=[": "ambient_setting_sources",
        "mcp_servers=": "raw_mcp_servers",
        "plugins=[": "raw_plugin_paths",
        "subagents=": "native_subagents",
        "task_complete\": True": "task_completion_authority",
        "route_admitted\": True": "route_admission_overclaim",
        "model_catalogue_supported\": True": "model_catalogue_overclaim",
    }
    for marker, code in forbidden.items():
        if marker in text:
            errors.append(code)
    required = {
        'PROTOCOL_VERSION = "eliot.claude-agent-sdk-sidecar.v2"': "protocol_version",
        'PERMISSION_MODES = {"default", "acceptEdits", "plan", "dontAsk"}': "permission_modes",
        'if request.get("setting_sources", []) != []': "empty_setting_sources",
        'if request.get("native_subagents", False) is not False': "subagent_rejection",
        '"model_selection_receipt_ref"': "model_receipt_binding",
        '"prompt_omitted": True': "prompt_omission",
        '"candidate_only": True': "candidate_only_result",
        '"task_complete": False': "no_task_completion",
        '"route_admitted": False': "no_route_admission",
        '"attempt.cancelled"': "cancel_terminal",
        '"attempt.cleanup"': "cleanup_event",
        'request_digest(request)': "request_idempotency",
        '"IDENTITY_CONFLICT"': "identity_conflict",
        'client.interrupt()': "provider_interrupt",
        'client.disconnect()': "provider_disconnect",
        'provider.error': "provider_error_history",
        'active.terminal.wait': "cancel_terminal_reconciliation",
        'active.cleanup.wait': "cancel_cleanup_reconciliation",
        'unknown_live_descendants': "descendant_closure_projection",
        'RealClaudeSdkFacade().probe()': "zero_model_probe",
    }
    for marker, code in required.items():
        if marker not in text:
            errors.append(f"missing:{code}")
    if "os.environ" in text:
        errors.append("ambient_environment_access")
    if "api_key" not in text or "access_token" not in text:
        errors.append("missing_protected_key_filters")
    return sorted(set(errors))


def verify(root: Path) -> None:
    for relative in (CONTRACT, SIDECAR, TESTS):
        if not (root / relative).is_file():
            raise VerifyError(f"missing required file: {relative}")
    errors = contract_errors(load_json(root / CONTRACT))
    errors.extend(source_errors((root / SIDECAR).read_text(encoding="utf-8")))
    if errors:
        raise VerifyError("; ".join(sorted(set(errors))))


def self_test(root: Path) -> None:
    contract = load_json(root / CONTRACT)
    source = (root / SIDECAR).read_text(encoding="utf-8")
    if contract_errors(contract) or source_errors(source):
        raise AssertionError("clean sidecar failed verifier primitives")

    bad = copy.deepcopy(contract)
    bad["native_subagents"] = True
    if "contract:native_subagents" not in contract_errors(bad):
        raise AssertionError("native-subagent contract drift was not detected")
    bad = copy.deepcopy(contract)
    bad["fixed_model_id"] = "universal-model"
    if "contract:fixed_model_id" not in contract_errors(bad):
        raise AssertionError("fixed-model drift was not detected")

    mutations = {
        "ambient settings": source.replace('if request.get("setting_sources", []) != []:', "if False:"),
        "subagents": source.replace('if request.get("native_subagents", False) is not False:', "if False:"),
        "task completion": source.replace('"task_complete": False', '"task_complete": True'),
        "route admission": source.replace('"route_admitted": False', '"route_admitted": True'),
        "prompt omission": source.replace('"prompt_omitted": True', '"prompt_omitted": False'),
        "request idempotency": source.replace("request_digest(request)", "'unbound'"),
        "disconnect": source.replace("client.disconnect()", "client.close_without_receipt()"),
    }
    for case, mutated in mutations.items():
        if not source_errors(mutated):
            raise AssertionError(f"source mutation was not detected: {case}")

    with tempfile.TemporaryDirectory(prefix="eliot-claude-sidecar-verify-") as temporary:
        fake = Path(temporary)
        (fake / CONTRACT.parent).mkdir(parents=True)
        (fake / SIDECAR.parent).mkdir(parents=True)
        (fake / TESTS.parent).mkdir(parents=True, exist_ok=True)
        (fake / CONTRACT).write_text(json.dumps(contract), encoding="utf-8")
        (fake / SIDECAR).write_text(source.replace('"task_complete": False', '"task_complete": True'), encoding="utf-8")
        (fake / TESTS).write_text("fixture", encoding="utf-8")
        try:
            verify(fake)
        except VerifyError:
            pass
        else:
            raise AssertionError("repository-level mutation did not fail")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.self_test:
        self_test(root)
        print("CLAUDE_AGENT_SDK_SIDECAR_SELF_TEST: PASS cases=10")
    else:
        verify(root)
        print("CLAUDE_AGENT_SDK_SIDECAR_VERIFY: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
