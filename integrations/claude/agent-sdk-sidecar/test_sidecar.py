#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

from eliot_claude_sidecar import (
    EVENT_VERSION,
    PROTOCOL_VERSION,
    SidecarController,
    SidecarError,
    redact_value,
    validate_request,
)

HERE = Path(__file__).resolve().parent
SIDECAR = HERE / "eliot_claude_sidecar.py"


def start_request(request_id: str = "request-start-1", attempt_id: str = "attempt-1") -> dict:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id,
        "type": "start",
        "task_id": "task-1",
        "work_item_id": "work-1",
        "attempt_id": attempt_id,
        "model_selection_receipt_ref": "selection-1",
        "model": "test-model",
        "fallback_model": None,
        "prompt": "Do the bounded test task.",
        "permission_mode": "plan",
        "max_turns": 8,
        "max_budget_usd": 1.0,
        "mcp_profile_ref": None,
        "skill_profile_ref": None,
        "plugin_profile_ref": None,
        "setting_sources": [],
        "native_subagents": False,
    }


class FakeFacade:
    def __init__(self, mode: str = "success") -> None:
        self.mode = mode
        self.run_count = 0
        self.probe_count = 0
        self.release = threading.Event()
        self.started = threading.Event()
        self.interrupts: list[str] = []

    def probe(self) -> dict:
        self.probe_count += 1
        return {
            "sdk_installed": True,
            "package": "fake-sdk",
            "package_version": "test",
            "provider_execution": False,
            "model_catalogue_supported": False,
            "route_admitted": False,
        }

    def run(self, request, emit, cancel_requested):
        self.run_count += 1
        self.started.set()
        if self.mode == "error_then_success":
            emit("provider.error", {"error_type": "RecoverableFake", "recoverable": True})
        if self.mode == "secret":
            emit("assistant.text", {"text": "sk-secret-material-1234567890"})
        if self.mode == "blocking":
            while not cancel_requested.is_set() and not self.release.wait(0.01):
                pass
        if self.mode == "failure":
            raise SidecarError("FAKE_FAILURE", "synthetic provider failure")
        emit("assistant.text", {"text": "candidate output"})
        return {
            "provider_session_id": "provider-session-1",
            "result": "candidate result",
            "num_turns": 1,
            "total_cost_usd": 0.01,
        }

    def interrupt(self, attempt_id: str) -> bool:
        self.interrupts.append(attempt_id)
        self.release.set()
        return True


class Capture:
    def __init__(self) -> None:
        self.items: list[dict] = []
        self.lock = threading.Lock()

    def __call__(self, item: dict) -> None:
        with self.lock:
            self.items.append(item)

    def snapshot(self) -> list[dict]:
        with self.lock:
            return list(self.items)

    def wait_for(self, predicate, timeout: float = 2.0) -> list[dict]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            items = self.snapshot()
            if predicate(items):
                return items
            time.sleep(0.01)
        self.fail_dump = self.snapshot()
        raise AssertionError(f"condition not observed: {self.fail_dump}")


class SidecarTests(unittest.TestCase):
    def test_hello_and_probe_do_not_execute_model(self) -> None:
        facade = FakeFacade()
        capture = Capture()
        controller = SidecarController(facade, capture)
        hello = controller.process({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": "hello-1",
            "type": "hello",
        })
        probe = controller.process({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": "probe-1",
            "type": "probe",
        })
        self.assertTrue(hello["ok"])
        self.assertFalse(hello["result"]["native_subagents"])
        self.assertTrue(probe["ok"])
        self.assertFalse(probe["result"]["provider_execution"])
        self.assertFalse(probe["result"]["model_catalogue_supported"])
        self.assertEqual(facade.run_count, 0)

    def test_start_ack_precedes_events_and_prompt_is_omitted(self) -> None:
        facade = FakeFacade()
        capture = Capture()
        controller = SidecarController(facade, capture)
        response = controller.process(start_request())
        self.assertTrue(response["ok"])
        items = capture.wait_for(lambda values: any(item.get("event_kind") == "attempt.cleanup" for item in values))
        self.assertEqual(items[0]["schema_version"], "eliot.claude-agent-sdk-sidecar.response.v2")
        events = [item for item in items if item.get("schema_version") == EVENT_VERSION]
        self.assertEqual([event["sequence"] for event in events], sorted(event["sequence"] for event in events))
        self.assertEqual(events[0]["event_kind"], "attempt.started")
        self.assertTrue(events[0]["payload"]["prompt_omitted"])
        self.assertNotIn("prompt", json.dumps(events))
        self.assertEqual(events[-2]["event_kind"], "attempt.result")
        self.assertEqual(events[-1]["event_kind"], "attempt.cleanup")
        self.assertTrue(events[-2]["payload"]["candidate_only"])
        self.assertFalse(events[-2]["payload"]["task_complete"])

    def test_historical_error_does_not_override_later_success(self) -> None:
        capture = Capture()
        controller = SidecarController(FakeFacade("error_then_success"), capture)
        controller.process(start_request())
        items = capture.wait_for(lambda values: any(item.get("event_kind") == "attempt.cleanup" for item in values))
        kinds = [item.get("event_kind") for item in items]
        self.assertIn("provider.error", kinds)
        self.assertIn("attempt.result", kinds)
        self.assertNotIn("attempt.failed", kinds)
        self.assertLess(kinds.index("provider.error"), kinds.index("attempt.result"))

    def test_cancel_is_attempt_bound_and_reconciles_terminal_cleanup(self) -> None:
        facade = FakeFacade("blocking")
        capture = Capture()
        controller = SidecarController(facade, capture)
        controller.process(start_request())
        self.assertTrue(facade.started.wait(1.0))
        wrong = controller.process({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": "cancel-wrong",
            "type": "cancel",
            "attempt_id": "other-attempt",
        })
        self.assertFalse(wrong["ok"])
        self.assertEqual(wrong["error"]["code"], "ATTEMPT_NOT_FOUND")
        cancelled = controller.process({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": "cancel-right",
            "type": "cancel",
            "attempt_id": "attempt-1",
        })
        self.assertTrue(cancelled["ok"])
        self.assertTrue(cancelled["result"]["terminal_confirmed"])
        self.assertTrue(cancelled["result"]["cleanup_confirmed"])
        self.assertEqual(cancelled["result"]["terminal_kind"], "attempt.cancelled")
        self.assertEqual(facade.interrupts, ["attempt-1"])
        items = capture.wait_for(lambda values: any(item.get("event_kind") == "attempt.cleanup" for item in values))
        kinds = [item.get("event_kind") for item in items]
        self.assertIn("attempt.cancelled", kinds)
        self.assertNotIn("attempt.result", kinds)

    def test_exact_start_replay_is_idempotent_and_conflict_is_rejected(self) -> None:
        facade = FakeFacade()
        capture = Capture()
        controller = SidecarController(facade, capture)
        request = start_request()
        first = controller.process(request)
        capture.wait_for(lambda values: any(item.get("event_kind") == "attempt.cleanup" for item in values))
        second = controller.process(dict(request))
        self.assertEqual(first, second)
        self.assertEqual(facade.run_count, 1)
        changed = dict(request)
        changed["prompt"] = "different canonical bytes"
        conflict = controller.process(changed)
        self.assertFalse(conflict["ok"])
        self.assertEqual(conflict["error"]["code"], "IDENTITY_CONFLICT")

    def test_only_one_attempt_can_be_active(self) -> None:
        facade = FakeFacade("blocking")
        controller = SidecarController(facade, Capture())
        controller.process(start_request())
        self.assertTrue(facade.started.wait(1.0))
        second = controller.process(start_request("request-start-2", "attempt-2"))
        self.assertFalse(second["ok"])
        self.assertEqual(second["error"]["code"], "ACTIVE_ATTEMPT_EXISTS")
        controller.process({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": "cancel-active",
            "type": "cancel",
            "attempt_id": "attempt-1",
        })

    def test_forbidden_settings_subagents_permissions_and_raw_fields(self) -> None:
        cases = []
        request = start_request()
        request["permission_mode"] = "bypassPermissions"
        cases.append((request, "PERMISSION_MODE_FORBIDDEN"))
        request = start_request()
        request["setting_sources"] = ["user"]
        cases.append((request, "AMBIENT_SETTINGS_FORBIDDEN"))
        request = start_request()
        request["native_subagents"] = True
        cases.append((request, "NATIVE_SUBAGENTS_FORBIDDEN"))
        request = start_request()
        request["api_key"] = "forbidden"
        cases.append((request, "UNKNOWN_FIELD"))
        request = start_request()
        request["raw_mcp_servers"] = {"x": {"command": "x"}}
        cases.append((request, "UNKNOWN_FIELD"))
        for raw, code in cases:
            response = SidecarController(FakeFacade(), Capture()).process(raw)
            self.assertFalse(response["ok"])
            self.assertEqual(response["error"]["code"], code)

    def test_prompt_and_budget_bounds(self) -> None:
        request = start_request()
        request["prompt"] = "x" * (262_144 + 1)
        response = SidecarController(FakeFacade(), Capture()).process(request)
        self.assertEqual(response["error"]["code"], "PROMPT_BOUND_EXCEEDED")
        request = start_request()
        request["max_budget_usd"] = 100.01
        response = SidecarController(FakeFacade(), Capture()).process(request)
        self.assertEqual(response["error"]["code"], "INVALID_REQUEST")

    def test_secret_redaction_applies_to_provider_events(self) -> None:
        capture = Capture()
        controller = SidecarController(FakeFacade("secret"), capture)
        controller.process(start_request())
        items = capture.wait_for(lambda values: any(item.get("event_kind") == "attempt.cleanup" for item in values))
        encoded = json.dumps(items)
        self.assertNotIn("sk-secret-material-1234567890", encoded)
        self.assertIn("[REDACTED]", encoded)
        value = redact_value({"password": "x", "nested": {"api_key": "y"}})
        self.assertEqual(value["password"], "[REDACTED]")
        self.assertEqual(value["nested"]["api_key"], "[REDACTED]")

    def test_normalized_start_keeps_profiles_as_ids_only(self) -> None:
        request = start_request()
        request["mcp_profile_ref"] = "mcp-profile-1"
        request["skill_profile_ref"] = "skill-profile-1"
        request["plugin_profile_ref"] = "plugin-profile-1"
        normalized = validate_request(request)
        self.assertEqual(normalized["setting_sources"], [])
        self.assertFalse(normalized["native_subagents"])
        self.assertEqual(normalized["mcp_profile_ref"], "mcp-profile-1")
        self.assertNotIn("mcp_servers", normalized)

    def test_stdio_hello_probe_shutdown(self) -> None:
        process = subprocess.Popen(
            [sys.executable, str(SIDECAR)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdin is not None and process.stdout is not None
        requests = [
            {"protocol_version": PROTOCOL_VERSION, "request_id": "stdio-hello", "type": "hello"},
            {"protocol_version": PROTOCOL_VERSION, "request_id": "stdio-probe", "type": "probe"},
            {"protocol_version": PROTOCOL_VERSION, "request_id": "stdio-shutdown", "type": "shutdown"},
        ]
        for request in requests:
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.flush()
            response = json.loads(process.stdout.readline())
            self.assertEqual(response["request_id"], request["request_id"])
            self.assertTrue(response["ok"])
        process.stdin.close()
        self.assertEqual(process.wait(timeout=5), 0)


if __name__ == "__main__":
    unittest.main()
