"""Focused tests for the context measurement inventory oracle (issue #866)."""
from __future__ import annotations
import importlib.util
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "context_measurement_inventory.py"
FIXTURES = ROOT / "scripts" / "testdata" / "context-measurement-inventory"

_spec = importlib.util.spec_from_file_location("context_measurement_inventory", SCRIPT)
assert _spec is not None and _spec.loader is not None
oracle = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = oracle
_spec.loader.exec_module(oracle)


def _live():
    return oracle.build_inventory(ROOT, None, "unittest")


def _snapshot(root: Path) -> dict[str, bytes]:
    state: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            state[path.relative_to(root).as_posix()] = path.read_bytes()
    return state


class TestContextMeasurementInventory(unittest.TestCase):
    def test_header_closed_versioned_31(self) -> None:
        inv = _live()
        h = inv["header"]
        self.assertEqual(h["schema"], "eliot.context-measurement-inventory.v1")
        self.assertEqual(h["rule_revision"], "866.1")
        self.assertRegex(str(h["source_sha"]), r"\A[0-9a-f]{64}\Z")
        self.assertRegex(str(h["rule_digest"]), r"\A[0-9a-f]{64}\Z")
        self.assertRegex(str(h["owner_digest"]), r"\A[0-9a-f]{64}\Z")
        self.assertEqual(h["candidate_count"], 31)
        self.assertEqual(h["classified_count"], 31)
        self.assertEqual(len(inv["rows"]), 31)
        self.assertEqual(len(h["classifications"]), 10)
        self.assertEqual(len(set(h["classifications"])), 10)
        alloc = [str(x) for x in h["owner_allocations"]]  # type: ignore[union-attr]
        self.assertNotIn("#785", "".join(alloc))
        self.assertEqual(sum(int(x.split(":")[1]) for x in alloc), 31)
        self.assertEqual(sorted(alloc), alloc)
        self.assertRegex(str(inv["inventory_digest"]), r"\A[0-9a-f]{64}\Z")

    def test_rows_closed_and_bound(self) -> None:
        inv = _live()
        by_ref = {str(r["case_ref"]): r for r in inv["rows"]}
        for row in inv["rows"]:
            self.assertTrue(oracle.REQUIRED_ROW_KEYS.issubset(row.keys()), row.get("id"))
            self.assertIn(row["classification"], tuple(oracle.CLASSIFICATIONS))
            self.assertRegex(str(row["row_digest"]), r"\A[0-9a-f]{64}\Z")
            self.assertRegex(str(row["source_sha256"]), r"\A[0-9a-f]{64}\Z")
            self.assertTrue(row["evidence"] and row["invalidation"] and row["successor_scope"])
        self.assertEqual(by_ref["704/1"]["classification"], "normative-stu-estimate")
        self.assertEqual(by_ref["704/2"]["classification"], "exact-utf8-envelope")
        self.assertEqual(by_ref["880/8"]["classification"], "test-only")
        self.assertEqual(by_ref["880/5"]["classification"], "transformed-observation")
        self.assertEqual(by_ref["880/6"]["classification"], "stale-or-absent-observation")
        # Discovery/classification API reused by #787 stays importable.
        label, _ = oracle.classify_context_measurement("stu_for_bytes")
        self.assertEqual(label, "normative-stu-estimate")
        with self.assertRaises(oracle.InventoryError):
            oracle.classify_context_measurement("no-such-signal-xyz")

    def test_sync_identical_and_tamper_fails(self) -> None:
        tiny = (("704/1", "#704", "scan/a.rs", "stu_for_bytes"), ("880/1", "#880", "scan/b.rs", "fixed_overhead"))
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            scan = troot / "scan"
            shutil.copytree(FIXTURES, scan)
            (scan / "a.rs").write_text((scan / "stu_estimate.rs").read_text(), encoding="utf-8")
            (scan / "b.rs").write_text((scan / "capacity_fit.rs").read_text(), encoding="utf-8")
            inv = oracle.build_inventory(troot, tiny, "unittest")
            self.assertEqual(oracle._emit_toml(inv), oracle._emit_toml(oracle.build_inventory(troot, list(reversed(tiny)), "unittest")))
            first = oracle._emit_toml(_live())
            self.assertEqual(first, oracle._emit_toml(_live()), "shuffled-free rebuild stays identical")
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            for _ref, _own, rel, _sig in oracle.DENOMINATOR_CASES:
                src, dst = ROOT / rel, troot / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(src.read_bytes())
            self.assertEqual(oracle.cmd_sync(troot, "unittest-sync"), 0)
            target = troot / oracle.OWNED_TOML.as_posix()
            before = target.read_bytes()
            self.assertEqual(oracle.cmd_sync(troot, "unittest-sync"), 0)
            self.assertEqual(target.read_bytes(), before, "repeated sync stays byte-identical")
            self.assertEqual(oracle.cmd_check(troot), 0)
            with open(troot / "crates/smart/eliot-context-measurement/src/stu.rs", "ab") as fh:
                fh.write(b"\n// touch\n")
            self.assertNotEqual(oracle.cmd_check(troot), 0)
            oracle.cmd_sync(troot, "unittest-sync")
            self.assertEqual(oracle.cmd_check(troot), 0)
            tampered = target.read_text(encoding="utf-8").replace("exact-utf8-envelope", "test-only", 1)
            target.write_text(tampered, encoding="utf-8")
            self.assertNotEqual(oracle.cmd_check(troot), 0)

    def test_fail_closed_no_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            (troot / "scan").mkdir()
            (troot / "scan" / "bad.rs").write_text('let s = "unclosed;\n', encoding="utf-8")
            with self.assertRaises(oracle.InventoryError):
                oracle.build_inventory(troot, (("704/1", "#704", "scan/bad.rs", "stu_for_bytes"),), "u")
            with self.assertRaises(oracle.InventoryError):
                oracle.build_inventory(troot, (), "u")
            with self.assertRaises(oracle.InventoryError):
                oracle.build_inventory(ROOT, [("704/1", "#704", "no/such.rs", "stu_for_bytes")], "u")
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(oracle.cmd_check(Path(td).resolve()), 1)

    def test_source_api_guard(self) -> None:
        src = SCRIPT.read_text(encoding="utf-8")
        for pat in (r"^\s*import\s+subprocess", r"^\s*import\s+time\b", r"^\s*import\s+datetime",
                    r"subprocess\.", r"os\.system", r"time\.time", r"datetime\.now", r'"cargo"', r"'cargo'"):
            self.assertIsNone(re.search(pat, src, re.MULTILINE), pat)
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            scan = troot / "scan"
            shutil.copytree(FIXTURES, scan)
            before = _snapshot(troot)
            # Read-only live build changes nothing.
            _live()
            self.assertEqual(_snapshot(troot), before)


if __name__ == "__main__":
    unittest.main()
