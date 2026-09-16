"""Focused lane-gate regressions for #764; fakes never prove live execution.

Only the two pre-command rejection gates are proven here (owner TESTS
order allows 1-2 focused tests). The remaining 764 matrix cases
(1-2, 5-21) plus manual-dispatch evidence stay Deferred and the issue
must stay open until they land with real component execution.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/wasm_component_lane.py"
spec = importlib.util.spec_from_file_location("eliot_wasm_component_lane", SCRIPT)
assert spec and spec.loader
lane = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lane
spec.loader.exec_module(lane)
FIXTURE = json.loads((ROOT / "scripts/testdata/wasm-component-lane/registry.json").read_bytes())["modules"]


class WasmComponentLaneTests(unittest.TestCase):
    def test_registry_fixture_binds_accepted_identities(self):
        entry = FIXTURE["eliot-context-compiler-wasm"]
        self.assertEqual(entry["package_id"], "eliot:current@0.1.0")
        self.assertEqual(entry["abi_revision"], 1)
        self.assertEqual(entry["capsule"]["operation"], entry["domain_operation"])

    # WORK_UNIT_CASE: 764/3
    def test_unknown_module_fails_before_commands(self):
        calls = []

        def never(argv, cwd, timeout=lane.COMMAND_TIMEOUT):
            calls.append(list(argv))
            self.fail("unknown module must not construct or execute a command")

        with self.assertRaises(lane.LaneError) as failure:
            lane.resolve_module(FIXTURE, "eliot-not-registered-wasm")
        self.assertEqual(str(failure.exception), "UNKNOWN_MODULE")
        self.assertEqual(calls, [])

    # WORK_UNIT_CASE: 764/4
    def test_traversal_absolute_separator_shell_injection_fail_before_commands(self):
        calls = []

        def never(argv, cwd, timeout=lane.COMMAND_TIMEOUT):
            calls.append(list(argv))
            self.fail("injection must not construct or execute a command")

        battery = [
            "../eliot-context-compiler-wasm",
            "..\\eliot-context-compiler-wasm",
            "/etc/passwd",
            "C:\\Windows\\Temp\\x",
            "crates/smart/eliot-context-compiler-wasm",
            "eliot-context-compiler-wasm;rm -rf /",
            "eliot-context-compiler-wasm|cat",
            "eliot-context-compiler-wasm&cargo build --workspace",
            "$(cargo build --workspace)",
            "`cargo build --workspace`",
            "eliot-context-compiler-wasm\ncargo build --workspace",
            "${CARGO_HOME}",
            "eliot-context-compiler-wasm*",
            "",
            "x" * 65,
        ]
        for attempt in battery:
            with self.subTest(attempt=attempt[:24]):
                with self.assertRaises(lane.LaneError):
                    lane.resolve_module(FIXTURE, attempt)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
