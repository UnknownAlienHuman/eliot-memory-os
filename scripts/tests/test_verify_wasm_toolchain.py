"""870B tests+fixtures half for #870 (E-WASM-TOOLCHAIN).

Owns exactly two offline checks bound to the checker's stable declaration
entry points: pinned guest-target verification + absent-manifest fail-closed.
Fixed fixture paths only; pure declaration parsing, no tools launched.
Remaining 870/1-3 and 870/5-16 are deferred to the manager-integrator / other owners (see
commit message). Fakes never prove live Rust; clean-bootstrap evidence stays
out of scope here.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify-wasm-toolchain.py"
FIXTURE_VALID = ROOT / "scripts/testdata/wasm-toolchain/valid.toml"
spec = importlib.util.spec_from_file_location("eliot_wasm_toolchain_check", SCRIPT)
assert spec and spec.loader
check = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = check
spec.loader.exec_module(check)


class ToolchainTests(unittest.TestCase):
    # WORK_UNIT_CASE: 870/4
    def test_pinned_guest_target_declared_once(self):
        raw = FIXTURE_VALID.read_bytes()
        declared = check.parse_declaration(raw)
        self.assertEqual(declared.channel, "1.97.1")
        self.assertIn(check.HOST_TARGET, declared.targets)
        self.assertEqual(declared.targets.count(check.GUEST_TARGET), 1)
        self.assertEqual(check.GUEST_TARGET, "wasm32-wasip2")
        live = check.read_declaration(ROOT)
        self.assertEqual(live.targets.count(check.GUEST_TARGET), 1)
        self.assertEqual(live.digest, declared.digest)

    def test_absent_manifest_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(check.ToolchainError) as failure:
                check.read_declaration(root)
            self.assertEqual(str(failure.exception), "TOOLCHAIN_UNAVAILABLE")
            self.assertEqual([p.name for p in root.iterdir()], [])

    # WORK_UNIT_CASE: 870/17 (salvaged from 870B: base 870/4 already covers
    # guest-declared-once; this binds the same property to the stable
    # declaration entry points. 870B's overwrite of this file is discarded.)
    def test_pinned_guest_target_declared_once(self):
        raw = VALID
        declared = check.parse_declaration(raw)
        self.assertEqual(declared.channel, "1.97.1")
        self.assertIn(check.HOST_TARGET, declared.targets)
        self.assertEqual(declared.targets.count(check.GUEST_TARGET), 1)
        self.assertEqual(check.GUEST_TARGET, "wasm32-wasip2")
        live = check.read_declaration(ROOT)
        self.assertEqual(live.targets.count(check.GUEST_TARGET), 1)
        self.assertEqual(live.digest, declared.digest)

    # WORK_UNIT_CASE: 870/18 (salvaged from 870B)
    def test_absent_manifest_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(check.ToolchainError) as failure:
                check.read_declaration(root)
            self.assertEqual(str(failure.exception), "TOOLCHAIN_UNAVAILABLE")
            self.assertEqual([p.name for p in root.iterdir()], [])


if __name__ == "__main__":
    unittest.main()
