"""Focused tests for the long-lived collection inventory oracle (issue #885).

Proportionate coverage only: header identity, row bindings, determinism and
tamper detection, fail-closed inputs, and the source/API guard. No matrices.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "long_lived_collection_inventory.py"
FIXTURES = ROOT / "scripts" / "testdata" / "long-lived-collections"

_spec = importlib.util.spec_from_file_location("long_lived_collection_inventory", SCRIPT)
assert _spec is not None and _spec.loader is not None
oracle = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = oracle
_spec.loader.exec_module(oracle)

REQUIRED_ROW_KEYS = frozenset(
    {
        "id",
        "package",
        "path",
        "struct_name",
        "field_name",
        "field_type",
        "span_start",
        "span_end",
        "source_sha256",
        "span_digest",
        "row_digest",
        "owner",
        "lifetime",
        "creation_site",
        "destruction_site",
        "persistence",
        "growth_callsites",
        "removal_callsites",
        "bound",
        "bound_status",
        "cardinality_key",
        "concurrency",
        "at_capacity_behavior",
        "over_capacity_behavior",
        "classification",
        "evidence",
        "repair_owner",
        "repair_issue",
        "invalidation",
        "successor_scope",
    }
)


def _build(scans: list[str]) -> dict:
    return oracle.build_inventory(ROOT, scans, "unittest")


def _snapshot(root: Path) -> dict[str, bytes]:
    state: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            state[path.relative_to(root).as_posix()] = path.read_bytes()
    return state


class TestLongLivedCollectionInventory(unittest.TestCase):
    def test_header_carries_closed_versioned_identity(self) -> None:
        inventory = _build(["scripts/testdata/long-lived-collections"])
        header = inventory["header"]
        self.assertEqual(header["schema"], "eliot.long-lived-collection-inventory.v1")
        self.assertEqual(header["rule_revision"], "885.1")
        self.assertRegex(str(header["source_sha"]), r"\A[0-9a-f]{64}\Z")
        self.assertEqual(header["scan_denominator_files"], 4)
        self.assertGreaterEqual(int(header["candidate_count"]), 3)
        self.assertEqual(int(header["classified_count"]), int(header["candidate_count"]))
        self.assertEqual(
            int(header["unresolved_count"]),
            sum(
                1
                for row in inventory["rows"]
                if row["classification"] in ("unbounded long-lived candidate", "ownership/lifetime unknown")
            ),
        )
        self.assertEqual(len(header["classifications"]), 12)
        self.assertEqual(len(set(header["classifications"])), 12)
        self.assertIn(header["coverage_disposition"], ("COMPLETE", "INCOMPLETE"))
        self.assertIn(header["safety_disposition"], ("NO_UNRESOLVED_GROWTH", "FINDINGS_REMAIN_BLOCKING"))
        self.assertEqual(header["proof_ceiling"], "STATIC_SOURCE_CLASSIFICATION_ONLY")
        self.assertRegex(str(inventory["inventory_digest"]), r"\A[0-9a-f]{64}\Z")

    def test_rows_bind_source_span_digest_and_closed_classification(self) -> None:
        inventory = _build(["scripts/testdata/long-lived-collections"])
        by_path: dict[str, list] = {}
        for row in inventory["rows"]:
            self.assertTrue(REQUIRED_ROW_KEYS.issubset(row.keys()), row.get("id"))
            self.assertIn(row["classification"], tuple(header for header in oracle.CLASSIFICATIONS))
            self.assertRegex(str(row["row_digest"]), r"\A[0-9a-f]{64}\Z")
            self.assertRegex(str(row["source_sha256"]), r"\A[0-9a-f]{64}\Z")
            self.assertRegex(str(row["span_digest"]), r"\A[0-9a-f]{64}\Z")
            self.assertTrue(row["evidence"], row["id"])
            self.assertTrue(row["invalidation"], row["id"])
            self.assertTrue(row["successor_scope"], row["id"])
            by_path.setdefault(str(row["path"]), []).append(row)

        local = by_path["scripts/testdata/long-lived-collections/request_local.rs"]
        self.assertEqual(len(local), 1)
        self.assertEqual(local[0]["classification"], "request-local/stack-bounded")
        self.assertTrue(local[0]["growth_callsites"])
        self.assertEqual(local[0]["repair_issue"], "none-required")

        dto = by_path.get("scripts/testdata/long-lived-collections/immutable_dto.rs", [])
        self.assertEqual(dto, [], "immutable DTO must not be treated as mutable growth")

        mutex = by_path["scripts/testdata/long-lived-collections/long_lived_mutex.rs"]
        self.assertEqual(len(mutex), 1)
        self.assertEqual(mutex[0]["classification"], "unbounded long-lived candidate")
        self.assertEqual(mutex[0]["struct_name"], "Registry")
        self.assertEqual(mutex[0]["field_name"], "inner")
        self.assertIn("HashMap", mutex[0]["field_type"])
        self.assertTrue(mutex[0]["growth_callsites"])
        self.assertEqual(mutex[0]["removal_callsites"], [])
        self.assertEqual(mutex[0]["concurrency"], "Mutex")
        self.assertEqual(mutex[0]["repair_owner"], "UNRESOLVED")
        self.assertEqual(mutex[0]["repair_issue"], "UNRESOLVED")

        static = by_path["scripts/testdata/long-lived-collections/static_global.rs"]
        self.assertEqual(len(static), 1)
        self.assertEqual(static[0]["classification"], "unbounded long-lived candidate")
        self.assertTrue(static[0]["growth_callsites"])

    def test_sync_is_byte_identical_and_check_detects_hand_edits(self) -> None:
        first = oracle._emit_toml(_build(["scripts/testdata/long-lived-collections"]))
        second = oracle._emit_toml(_build(["scripts/testdata/long-lived-collections"]))
        self.assertEqual(first, second)
        shuffled = oracle._emit_toml(
            oracle.build_inventory(
                ROOT,
                ["scripts/testdata/long-lived-collections/static_global.rs",
                 "scripts/testdata/long-lived-collections/request_local.rs",
                 "scripts/testdata/long-lived-collections/long_lived_mutex.rs",
                 "scripts/testdata/long-lived-collections/immutable_dto.rs"],
                "unittest",
            )
        )
        self.assertNotEqual(first, shuffled, "different scan roots select different sources")
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            scan = troot / "scan"
            shutil.copytree(FIXTURES, scan)
            code = oracle.cmd_sync(troot, ["scan"], "unittest-sync")
            self.assertEqual(code, 0)
            target = troot / oracle.OWNED_TOML.as_posix()
            before = target.read_bytes()
            code = oracle.cmd_sync(troot, ["scan"], "unittest-sync")
            self.assertEqual(code, 0)
            self.assertEqual(target.read_bytes(), before, "repeated sync must be byte-identical")
            self.assertEqual(oracle.cmd_check(troot), 0)
            # Changed source invalidates the row: stale, nonzero.
            (scan / "request_local.rs").write_bytes(
                (scan / "request_local.rs").read_bytes() + b"\n// touch\n",
                )
            self.assertEqual(oracle.cmd_check(troot), 1)
            oracle.cmd_sync(troot, ["scan"], "unittest-sync")
            self.assertEqual(oracle.cmd_check(troot), 0)
            # Hand-edited artifact digest mismatch fails closed, nonzero.
            tampered = target.read_text(encoding="utf-8").replace(
                "unbounded long-lived candidate", "lifecycle-removal", 1
            )
            target.write_text(tampered, encoding="utf-8")
            self.assertNotEqual(oracle.cmd_check(troot), 0)

    def test_malformed_and_missing_inputs_fail_closed_without_empty_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            scan = troot / "scan"
            scan.mkdir()
            (scan / "bad.rs").write_text('pub fn f() {\n    let s = "unclosed;\n}\n', encoding="utf-8")
            with self.assertRaises(oracle.InventoryError) as ctx:
                oracle.build_inventory(troot, ["scan"], "unittest")
            self.assertEqual(ctx.exception.code, "MALFORMED_RUST_SOURCE")
            self.assertFalse((troot / oracle.OWNED_TOML.as_posix()).exists())
        with self.assertRaises(oracle.InventoryError) as ctx:
            oracle.build_inventory(ROOT, ["scripts/testdata/long-lived-collections/absent.rs"], "unittest")
        self.assertEqual(ctx.exception.code, "SCAN_INPUT_MISSING")
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            (troot / "empty").mkdir()
            with self.assertRaises(oracle.InventoryError) as ctx:
                oracle.build_inventory(troot, ["empty"], "unittest")
            self.assertEqual(ctx.exception.code, "EMPTY_SCAN")
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            self.assertEqual(oracle.cmd_check(troot), 1, "missing artifact must be stale, not passing")

    def test_source_and_api_guard(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for pattern in (
            r"^\s*import\s+subprocess",
            r"^\s*import\s+socket",
            r"^\s*import\s+urllib",
            r"^\s*import\s+http\b",
            r"^\s*import\s+time\b",
            r"^\s*import\s+datetime",
            r"^\s*import\s+shutil",
            r"^\s*import\s+threading",
            r"subprocess\.",
            r"os\.system",
            r"os\.exec",
            r"os\.popen",
            r"socket\.",
            r"urllib",
            r"time\.time",
            r"time\.sleep",
            r"datetime\.now",
            r'"cargo"',
            r"'cargo'",
            r'"rustc"',
            r"MAX_",
        ):
            self.assertIsNone(
                re.search(pattern, source, re.MULTILINE), f"forbidden oracle pattern: {pattern}"
            )
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            scan = troot / "scan"
            shutil.copytree(FIXTURES, scan)
            (troot / "unrelated.txt").write_text("anchor", encoding="utf-8")
            before = _snapshot(troot)
            self.assertEqual(oracle.cmd_sync(troot, ["scan"], "unittest"), 0)
            after_sync = _snapshot(troot)
            changed = [key for key in after_sync if after_sync.get(key) != before.get(key)]
            self.assertEqual(changed, [oracle.OWNED_TOML.as_posix()])
            settled = _snapshot(troot)
            self.assertEqual(oracle.cmd_check(troot), 0)
            self.assertEqual(_snapshot(troot), settled, "check must be read-only")


if __name__ == "__main__":
    unittest.main()
