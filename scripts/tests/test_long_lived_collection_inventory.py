"""Dedicated suite for the long-lived collection inventory oracle (issue #885).

Frozen 30-case denominator: cases 885/1 to 885/30 below. Each test method is
one frozen case. The suite classifies long-lived mutable collection growth
and eviction ownership over read-only scan inputs, separates coverage
(complete rows) from safety (no unresolved growth), and never lets a
findings-bearing inventory pass as a product leak-free claim.
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

# Frozen denominator: exactly refs 885/1..885/30, each bound to one method.
FROZEN_CASES = (
    ("885/1", "frozen case list holds exactly refs 885/1..885/30"),
    ("885/2", "header carries closed versioned identity"),
    ("885/3", "denominator files and bytes are bound"),
    ("885/4", "candidate, classified, and unresolved counts agree"),
    ("885/5", "coverage COMPLETE coexists with FINDINGS_REMAIN_BLOCKING safety"),
    ("885/6", "proof ceiling is static-source classification only"),
    ("885/7", "request-local stack-bounded row"),
    ("885/8", "immutable DTO yields zero candidates"),
    ("885/9", "mutex-guarded long-lived growth is an unbounded candidate"),
    ("885/10", "static global growth is an unbounded candidate"),
    ("885/11", "literal capacity plus removal is hard-bounded"),
    ("885/12", "policy-owned growth is versioned-policy-bounded"),
    ("885/13", "same-slice removal without hard bound is lifecycle-removal"),
    ("885/14", "ttl signal with scheduled cleanup is TTL/lease bounded"),
    ("885/15", "cross-file removal is external compaction"),
    ("885/16", "append signal with retention is append-only segmented retention"),
    ("885/17", "cfg(test) region row is test-only"),
    ("885/18", "growth-free fields stay ownership/lifetime unknown"),
    ("885/19", "every row binds digests and a closed classification"),
    ("885/20", "closed set holds all twelve classifications"),
    ("885/21", "unresolved rows carry UNRESOLVED repair plus bounded successor scope"),
    ("885/22", "resolved rows carry owned repair and none-required successor"),
    ("885/23", "sync is byte-identical and check passes"),
    ("885/24", "source touch invalidates rows until resync"),
    ("885/25", "hand-edited artifact fails the digest check"),
    ("885/26", "oracle self-test passes deterministically"),
    ("885/27", "malformed and missing inputs fail closed without empty coverage"),
    ("885/28", "source and API guard holds"),
    ("885/29", "sync writes exactly one file and check is read-only"),
    ("885/30", "findings-bearing inventory never claims product leak-free"),
)

UNRESOLVED = ("unbounded long-lived candidate", "ownership/lifetime unknown")


def _build(scans: list[str]) -> dict:
    return oracle.build_inventory(ROOT, scans, "unittest")


def _fixture_inventory() -> dict:
    return _build(["scripts/testdata/long-lived-collections"])


def _rows_by_path(inventory: dict) -> dict[str, list]:
    by_path: dict[str, list] = {}
    for row in inventory["rows"]:
        by_path.setdefault(str(row["path"]), []).append(row)
    return by_path


def _snapshot(root: Path) -> dict[str, bytes]:
    state: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            state[path.relative_to(root).as_posix()] = path.read_bytes()
    return state


class TestLongLivedCollectionInventory(unittest.TestCase):
    def test_885_01_frozen_case_list(self) -> None:
        """885/1: frozen case list holds exactly refs 885/1..885/30."""
        refs = [ref for ref, _ in FROZEN_CASES]
        self.assertEqual(refs, [f"885/{number}" for number in range(1, 31)])
        labels = [label for _, label in FROZEN_CASES]
        self.assertEqual(len(set(labels)), 30)
        self.assertTrue(all(label for label in labels))

    def test_885_02_header_closed_versioned_identity(self) -> None:
        """885/2: header carries closed versioned identity."""
        header = _fixture_inventory()["header"]
        self.assertEqual(header["schema"], "eliot.long-lived-collection-inventory.v1")
        self.assertEqual(header["rule_revision"], "885.1")
        self.assertEqual(header["tool_version"], "0.1.0")
        self.assertEqual(header["scan_roots"], ["scripts/testdata/long-lived-collections"])
        self.assertEqual(len(header["classifications"]), 12)
        self.assertEqual(len(set(header["classifications"])), 12)

    def test_885_03_denominator_files_and_bytes_bound(self) -> None:
        """885/3: denominator files and bytes are bound."""
        header = _fixture_inventory()["header"]
        self.assertEqual(header["scan_denominator_files"], 13)
        expected_bytes = sum(
            (FIXTURES / name).stat().st_size for name in sorted(p.name for p in FIXTURES.glob("*.rs"))
        )
        self.assertEqual(header["scan_denominator_bytes"], expected_bytes)
        self.assertGreater(expected_bytes, 0)
        self.assertRegex(str(header["source_sha"]), r"\A[0-9a-f]{64}\Z")

    def test_885_04_counts_agree(self) -> None:
        """885/4: candidate, classified, and unresolved counts agree."""
        inventory = _fixture_inventory()
        header = inventory["header"]
        self.assertEqual(header["candidate_count"], 13)
        self.assertEqual(header["classified_count"], 13)
        self.assertEqual(len(inventory["rows"]), 13)
        self.assertEqual(
            int(header["unresolved_count"]),
            sum(1 for row in inventory["rows"] if row["classification"] in UNRESOLVED),
        )
        self.assertEqual(int(header["unresolved_count"]), 5)

    def test_885_05_coverage_complete_safety_blocking(self) -> None:
        """885/5: coverage COMPLETE coexists with FINDINGS_REMAIN_BLOCKING safety."""
        header = _fixture_inventory()["header"]
        self.assertEqual(header["coverage_disposition"], "COMPLETE")
        self.assertTrue(header["coverage_reason"])
        self.assertEqual(header["safety_disposition"], "FINDINGS_REMAIN_BLOCKING")
        self.assertNotEqual(header["coverage_disposition"], header["safety_disposition"])

    def test_885_06_proof_ceiling_static_only(self) -> None:
        """885/6: proof ceiling is static-source classification only."""
        inventory = _fixture_inventory()
        self.assertEqual(inventory["header"]["proof_ceiling"], "STATIC_SOURCE_CLASSIFICATION_ONLY")
        self.assertRegex(str(inventory["inventory_digest"]), r"\A[0-9a-f]{64}\Z")

    def test_885_07_request_local_row(self) -> None:
        """885/7: request-local stack-bounded row."""
        local = _rows_by_path(_fixture_inventory())[
            "scripts/testdata/long-lived-collections/request_local.rs"
        ]
        self.assertEqual(len(local), 1)
        self.assertEqual(local[0]["classification"], "request-local/stack-bounded")
        self.assertEqual(local[0]["owner"], "enclosing function frame")
        self.assertTrue(local[0]["growth_callsites"])
        self.assertEqual(local[0]["repair_issue"], "none-required")
        self.assertEqual(local[0]["successor_scope"], "none-required")

    def test_885_08_immutable_dto_zero_candidates(self) -> None:
        """885/8: immutable DTO yields zero candidates."""
        by_path = _rows_by_path(_fixture_inventory())
        self.assertEqual(
            by_path.get("scripts/testdata/long-lived-collections/immutable_dto.rs", []),
            [],
            "immutable DTO must not be treated as mutable growth",
        )

    def test_885_09_mutex_unbounded_candidate(self) -> None:
        """885/9: mutex-guarded long-lived growth is an unbounded candidate."""
        (row,) = _rows_by_path(_fixture_inventory())[
            "scripts/testdata/long-lived-collections/long_lived_mutex.rs"
        ]
        self.assertEqual(row["classification"], "unbounded long-lived candidate")
        self.assertEqual(row["struct_name"], "Registry")
        self.assertEqual(row["field_name"], "inner")
        self.assertIn("HashMap", row["field_type"])
        self.assertTrue(row["growth_callsites"])
        self.assertEqual(row["removal_callsites"], [])
        self.assertEqual(row["concurrency"], "Mutex")
        self.assertEqual(row["repair_owner"], "UNRESOLVED")
        self.assertEqual(row["repair_issue"], "UNRESOLVED")

    def test_885_10_static_global_unbounded_candidate(self) -> None:
        """885/10: static global growth is an unbounded candidate."""
        (row,) = _rows_by_path(_fixture_inventory())[
            "scripts/testdata/long-lived-collections/static_global.rs"
        ]
        self.assertEqual(row["classification"], "unbounded long-lived candidate")
        self.assertEqual(row["owner"], "static SEEN_MODELS")
        self.assertEqual(row["lifetime"], "process-global static")
        self.assertTrue(row["growth_callsites"])
        self.assertEqual(row["repair_issue"], "UNRESOLVED")

    def test_885_11_hard_bounded(self) -> None:
        """885/11: literal capacity plus removal is hard-bounded."""
        (row,) = _rows_by_path(_fixture_inventory())[
            "scripts/testdata/long-lived-collections/hard_bounded.rs"
        ]
        self.assertEqual(row["classification"], "long-lived hard-bounded")
        self.assertEqual(row["bound"], "with_capacity(64)")
        self.assertEqual(row["bound_status"], "hard")
        self.assertTrue(row["growth_callsites"])
        self.assertTrue(row["removal_callsites"])
        self.assertEqual(row["repair_issue"], "none-required")

    def test_885_12_versioned_policy_bounded(self) -> None:
        """885/12: policy-owned growth is versioned-policy-bounded."""
        (row,) = _rows_by_path(_fixture_inventory())[
            "scripts/testdata/long-lived-collections/versioned_policy_bounded.rs"
        ]
        self.assertEqual(row["classification"], "versioned-policy-bounded")
        self.assertEqual(row["bound_status"], "configured")
        self.assertTrue(row["growth_callsites"])
        self.assertEqual(row["repair_issue"], "none-required")

    def test_885_13_lifecycle_removal(self) -> None:
        """885/13: same-slice removal without hard bound is lifecycle-removal."""
        (row,) = _rows_by_path(_fixture_inventory())[
            "scripts/testdata/long-lived-collections/lifecycle_removal.rs"
        ]
        self.assertEqual(row["classification"], "lifecycle-removal")
        self.assertTrue(row["growth_callsites"])
        self.assertTrue(any(call.endswith(":clear") for call in row["removal_callsites"]))
        self.assertEqual(row["repair_issue"], "none-required")

    def test_885_14_ttl_lease_bounded(self) -> None:
        """885/14: ttl signal with scheduled cleanup is TTL/lease bounded."""
        (row,) = _rows_by_path(_fixture_inventory())[
            "scripts/testdata/long-lived-collections/ttl_lease.rs"
        ]
        self.assertEqual(row["classification"], "TTL/lease with scheduled bounded cleanup")
        self.assertEqual(row["bound_status"], "configured")
        self.assertTrue(str(row["bound"]).startswith("scheduled cleanup:"))
        self.assertEqual(row["cardinality_key"], "String")
        self.assertEqual(row["repair_issue"], "none-required")

    def test_885_15_external_compaction(self) -> None:
        """885/15: cross-file removal is external compaction."""
        by_path = _rows_by_path(_fixture_inventory())
        (row,) = by_path["scripts/testdata/long-lived-collections/compacted_store.rs"]
        self.assertEqual(row["classification"], "external compaction")
        self.assertEqual(row["bound_status"], "configured")
        cross = [call for call in row["removal_callsites"] if "(cross-file)" in call]
        self.assertEqual(len(cross), 1)
        self.assertIn("store_compactor.rs", cross[0])
        (compactor,) = by_path["scripts/testdata/long-lived-collections/store_compactor.rs"]
        self.assertEqual(compactor["classification"], "unbounded long-lived candidate")
        self.assertEqual(compactor["field_name"], "swept")

    def test_885_16_append_only_retention(self) -> None:
        """885/16: append signal with retention is append-only segmented retention."""
        by_path = _rows_by_path(_fixture_inventory())
        (row,) = by_path["scripts/testdata/long-lived-collections/append_only.rs"]
        self.assertEqual(row["classification"], "append-only durable segmented retention")
        self.assertEqual(row["struct_name"], "EventLog")
        self.assertEqual(row["field_name"], "events")
        self.assertEqual(row["bound_status"], "configured")
        self.assertTrue(any(call.endswith(":truncate") for call in row["removal_callsites"]))
        self.assertEqual(
            [r for r in by_path["scripts/testdata/long-lived-collections/append_only.rs"]
             if r["struct_name"] == "Event"],
            [],
            "scalar-only inner record must not yield a row",
        )

    def test_885_17_test_only_region(self) -> None:
        """885/17: cfg(test) region row is test-only."""
        (row,) = _rows_by_path(_fixture_inventory())[
            "scripts/testdata/long-lived-collections/test_only.rs"
        ]
        self.assertEqual(row["classification"], "test-only")
        self.assertEqual(row["struct_name"], "TestCache")
        self.assertTrue(row["growth_callsites"], "growth present but test signal wins")
        self.assertEqual(row["repair_issue"], "none-required")
        self.assertEqual(row["successor_scope"], "none-required")

    def test_885_18_ownership_unknown(self) -> None:
        """885/18: growth-free fields stay ownership/lifetime unknown."""
        rows = _rows_by_path(_fixture_inventory())[
            "scripts/testdata/long-lived-collections/ownership_unknown.rs"
        ]
        self.assertEqual(len(rows), 2)
        by_field = {row["field_name"]: row for row in rows}
        self.assertEqual(set(by_field), {"tags", "scores"})
        for row in rows:
            self.assertEqual(row["classification"], "ownership/lifetime unknown")
            self.assertEqual(row["growth_callsites"], [])
            self.assertEqual(row["bound_status"], "unknown")
            self.assertEqual(row["repair_owner"], "UNRESOLVED")
            self.assertEqual(row["repair_issue"], "UNRESOLVED")

    def test_885_19_row_digest_bindings(self) -> None:
        """885/19: every row binds digests and a closed classification."""
        inventory = _fixture_inventory()
        ids = [row["id"] for row in inventory["rows"]]
        self.assertEqual(ids, [f"c{number:04d}" for number in range(1, 14)])
        for row in inventory["rows"]:
            self.assertTrue(REQUIRED_ROW_KEYS.issubset(row.keys()), row.get("id"))
            self.assertIn(row["classification"], tuple(oracle.CLASSIFICATIONS))
            self.assertIn(row["bound_status"], tuple(oracle.BOUND_STATUSES))
            self.assertRegex(str(row["row_digest"]), r"\A[0-9a-f]{64}\Z")
            self.assertRegex(str(row["source_sha256"]), r"\A[0-9a-f]{64}\Z")
            self.assertRegex(str(row["span_digest"]), r"\A[0-9a-f]{64}\Z")
            self.assertTrue(row["evidence"], row["id"])
            self.assertTrue(row["invalidation"], row["id"])
            self.assertTrue(row["successor_scope"], row["id"])
            self.assertEqual(row["creation_site"], f"{row['path']}:{row['span_start']}")

    def test_885_20_closed_set_of_twelve(self) -> None:
        """885/20: closed set holds all twelve classifications."""
        self.assertEqual(
            tuple(oracle.CLASSIFICATIONS),
            (
                "request-local/stack-bounded",
                "immutable DTO",
                "test-only",
                "long-lived hard-bounded",
                "versioned-policy-bounded",
                "lifecycle-removal",
                "TTL/lease with scheduled bounded cleanup",
                "external compaction",
                "append-only durable segmented retention",
                "unbounded long-lived candidate",
                "ownership/lifetime unknown",
                "unrelated false positive",
            ),
        )
        self.assertEqual(
            set(oracle.UNRESOLVED_CLASSIFICATIONS),
            {"unbounded long-lived candidate", "ownership/lifetime unknown"},
        )
        self.assertEqual(tuple(oracle.BOUND_STATUSES), ("hard", "configured", "empirical", "none", "unknown"))

    def test_885_21_unresolved_rows_block(self) -> None:
        """885/21: unresolved rows carry UNRESOLVED repair plus bounded successor scope."""
        inventory = _fixture_inventory()
        unresolved = [row for row in inventory["rows"] if row["classification"] in UNRESOLVED]
        self.assertEqual(len(unresolved), 5)
        for row in unresolved:
            self.assertEqual(row["repair_owner"], "UNRESOLVED", row["id"])
            self.assertEqual(row["repair_issue"], "UNRESOLVED", row["id"])
            scope = str(row["successor_scope"])
            self.assertTrue(scope.startswith("bounded successor scope:"), row["id"])
            owner = row["struct_name"] or row["owner"]
            self.assertIn(f"{owner}.{row['field_name']}", scope, row["id"])

    def test_885_22_resolved_rows_owned(self) -> None:
        """885/22: resolved rows carry owned repair and none-required successor."""
        inventory = _fixture_inventory()
        resolved = [row for row in inventory["rows"] if row["classification"] not in UNRESOLVED]
        self.assertEqual(len(resolved), 8)
        for row in resolved:
            self.assertEqual(row["repair_issue"], "none-required", row["id"])
            self.assertIn(row["repair_owner"], ("none-required", row["package"]), row["id"])
            self.assertEqual(row["successor_scope"], "none-required", row["id"])

    def test_885_23_sync_byte_identical_check_passes(self) -> None:
        """885/23: sync is byte-identical and check passes."""
        first = oracle._emit_toml(_fixture_inventory())
        self.assertEqual(first, oracle._emit_toml(_fixture_inventory()))
        names = sorted(path.name for path in FIXTURES.glob("*.rs"))
        explicit = [f"scripts/testdata/long-lived-collections/{name}" for name in names]
        shuffled = oracle._emit_toml(_build(list(reversed(explicit))))
        self.assertNotEqual(first, shuffled, "different scan roots select different sources")
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            scan = troot / "scan"
            shutil.copytree(FIXTURES, scan)
            self.assertEqual(oracle.cmd_sync(troot, ["scan"], "unittest-sync"), 0)
            target = troot / oracle.OWNED_TOML.as_posix()
            before = target.read_bytes()
            self.assertEqual(oracle.cmd_sync(troot, ["scan"], "unittest-sync"), 0)
            self.assertEqual(target.read_bytes(), before, "repeated sync must be byte-identical")
            self.assertEqual(oracle.cmd_check(troot), 0)

    def test_885_24_source_touch_invalidates_until_resync(self) -> None:
        """885/24: source touch invalidates rows until resync."""
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            scan = troot / "scan"
            shutil.copytree(FIXTURES, scan)
            self.assertEqual(oracle.cmd_sync(troot, ["scan"], "unittest-sync"), 0)
            self.assertEqual(oracle.cmd_check(troot), 0)
            (scan / "request_local.rs").write_bytes(
                (scan / "request_local.rs").read_bytes() + b"\n// touch\n",
            )
            self.assertEqual(oracle.cmd_check(troot), 1)
            self.assertEqual(oracle.cmd_sync(troot, ["scan"], "unittest-sync"), 0)
            self.assertEqual(oracle.cmd_check(troot), 0)

    def test_885_25_hand_edit_fails_digest_check(self) -> None:
        """885/25: hand-edited artifact fails the digest check."""
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            scan = troot / "scan"
            shutil.copytree(FIXTURES, scan)
            self.assertEqual(oracle.cmd_sync(troot, ["scan"], "unittest-sync"), 0)
            target = troot / oracle.OWNED_TOML.as_posix()
            tampered = target.read_text(encoding="utf-8").replace(
                "unbounded long-lived candidate", "lifecycle-removal", 1
            )
            self.assertNotEqual(tampered, target.read_text(encoding="utf-8"))
            target.write_text(tampered, encoding="utf-8")
            self.assertNotEqual(oracle.cmd_check(troot), 0)

    def test_885_26_self_test_passes(self) -> None:
        """885/26: oracle self-test passes deterministically."""
        self.assertEqual(oracle.run_self_tests(), 0)
        self.assertEqual(oracle.run_self_tests(), 0)

    def test_885_27_fail_closed_inputs(self) -> None:
        """885/27: malformed and missing inputs fail closed without empty coverage."""
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

    def test_885_28_source_and_api_guard(self) -> None:
        """885/28: source and API guard holds."""
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

    def test_885_29_sync_writes_one_file_check_readonly(self) -> None:
        """885/29: sync writes exactly one file and check is read-only."""
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            scan = troot / "scan"
            shutil.copytree(FIXTURES, scan)
            (troot / "unrelated.txt").write_text("anchor", encoding="utf-8")
            before = _snapshot(troot)
            self.assertEqual(oracle.build_inventory(troot, ["scan"], "unittest")["header"]["candidate_count"], 13)
            self.assertEqual(_snapshot(troot), before, "scan inputs are read-only")
            self.assertEqual(oracle.cmd_sync(troot, ["scan"], "unittest"), 0)
            after_sync = _snapshot(troot)
            changed = [key for key in after_sync if after_sync.get(key) != before.get(key)]
            self.assertEqual(changed, [oracle.OWNED_TOML.as_posix()])
            settled = _snapshot(troot)
            self.assertEqual(oracle.cmd_check(troot), 0)
            self.assertEqual(_snapshot(troot), settled, "check must be read-only")

    def test_885_30_never_claims_leak_free(self) -> None:
        """885/30: findings-bearing inventory never claims product leak-free."""
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            scan = troot / "scan"
            shutil.copytree(FIXTURES, scan)
            self.assertEqual(oracle.cmd_sync(troot, ["scan"], "unittest-sync"), 0)
            self.assertEqual(oracle.cmd_check(troot), 0, "tooling passes on findings-bearing inventory")
            header = oracle.build_inventory(troot, ["scan"], "unittest-sync")["header"]
            self.assertEqual(header["safety_disposition"], "FINDINGS_REMAIN_BLOCKING")
            text = (troot / oracle.OWNED_TOML.as_posix()).read_text(encoding="utf-8")
            for claim in (
                "leak-free",
                "leak free",
                "no leaks",
                "VERIFIED_COMPLETE",
                "product safe",
                "proven bounded",
            ):
                self.assertNotIn(claim, text, f"forbidden product claim: {claim}")
            self.assertIn("STATIC_SOURCE_CLASSIFICATION_ONLY", text)


if __name__ == "__main__":
    unittest.main()
