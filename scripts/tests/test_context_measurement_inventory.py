"""Focused tests for the context measurement inventory oracle (issue #866)."""
from __future__ import annotations
import contextlib
import importlib.util
import io
import json
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


def _declared_sync_inputs() -> list[str]:
    """Every file a default-denominator `sync` reads, per the generator's own tables.

    Derived from the product rather than restated here so the temp-tree tests
    stage exactly what the real `sync`/`check` path demands. `build_inventory`
    loads the DENOMINATOR_CASES scan roots, the EXCLUSION_CASES scan inputs and
    (through `_build_consumer_worksets`) each consumer's declared test paths and
    routed required reading; `load_owner_map` additionally requires the frozen
    owner map itself.
    """
    rels: set[str] = {rel for _ref, _owner, rel, _sig in oracle.DENOMINATOR_CASES}
    rels |= {rel for _ref, rel, _needle, _reason in oracle.EXCLUSION_CASES}
    for owner in oracle.CONSUMER_SEAMS:
        rels |= set(oracle.CONSUMER_TEST_PATHS[owner])
        rels |= set(oracle.CONSUMER_ROUTED_READING[owner])
    rels.add(oracle.OWNER_MAP_PATH.as_posix())
    return sorted(rels)


def _check_verdict(root: Path) -> tuple[int, str, str]:
    """Run `cmd_check` and return its (exit code, typed code, status) triple.

    The oracle reports a typed disposition, not a bare non-zero exit, so the
    tests below assert the exact code that fired rather than only "not zero".
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = oracle.cmd_check(root)
    report = json.loads(buf.getvalue())
    return int(rc), str(report["code"]), str(report["status"])


class TestContextMeasurementInventory(unittest.TestCase):
    def test_header_closed_versioned_31(self) -> None:
        # This test was written against rule revision 866.1, whose denominator was
        # only the 31 frozen BASELINE_CASES and whose classification set held 10
        # values. Revisions 866.2 and 866.3 legitimately moved past that shape:
        #   - 866.2 (commit 088494c53) widened the denominator to the real
        #     per-consumer source seams, adding CONSUMER_SEAM_CASES and
        #     UNRESOLVED_CASES on top of the unchanged 31-case BASELINE_CASES,
        #     and added 5 classifications -> 15;
        #   - 866.3 added the remainder of the current rule set.
        # The 866.1 numbers were therefore stale expectations, not a product
        # regression: `build_inventory` now emits EXPECTED_DENOMINATOR_COUNT
        # (72) candidates over EXPECTED_BASELINE_COUNT (31) preserved baseline
        # rows, and every one of this test's other, still-valid properties --
        # the three hex64 digests, the closed unique classification set, the
        # absence of the forbidden #785 owner, the sorted owner allocations and
        # their sum equalling the candidate count -- are kept below and are now
        # derived from the generator's own constants instead of hard-coded
        # literals, so a future revision cannot silently re-stale them.
        inv = _live()
        h = inv["header"]
        self.assertEqual(h["schema"], oracle.SCHEMA)
        self.assertEqual(h["schema"], "eliot.context-measurement-inventory.v2")
        self.assertEqual(h["rule_revision"], oracle.RULE_REVISION)
        self.assertRegex(str(h["source_sha"]), r"\A[0-9a-f]{64}\Z")
        self.assertRegex(str(h["rule_digest"]), r"\A[0-9a-f]{64}\Z")
        self.assertRegex(str(h["owner_digest"]), r"\A[0-9a-f]{64}\Z")
        # Denominator is the full declared case set, not just the baseline.
        self.assertEqual(len(oracle.DENOMINATOR_CASES), oracle.EXPECTED_DENOMINATOR_COUNT)
        self.assertEqual(len(oracle.BASELINE_CASES), oracle.EXPECTED_BASELINE_COUNT)
        self.assertEqual(h["candidate_count"], oracle.EXPECTED_DENOMINATOR_COUNT)
        self.assertEqual(h["classified_count"], oracle.EXPECTED_DENOMINATOR_COUNT)
        self.assertEqual(len(inv["rows"]), oracle.EXPECTED_DENOMINATOR_COUNT)
        # The closed classification set grew from 866.1's 10 values.
        self.assertEqual(len(h["classifications"]), len(oracle.CLASSIFICATIONS))
        self.assertEqual(len(set(h["classifications"])), len(oracle.CLASSIFICATIONS))
        self.assertEqual(set(h["classifications"]), set(oracle.CLASSIFICATIONS))
        alloc = [str(x) for x in h["owner_allocations"]]  # type: ignore[union-attr]
        self.assertNotIn("#785", "".join(alloc))
        self.assertEqual(sum(int(x.split(":")[1]) for x in alloc), oracle.EXPECTED_DENOMINATOR_COUNT)
        self.assertEqual(sorted(alloc), alloc)
        # The 866.1 allocation set (#704:9 #783:8 #878:6 #880:8 = 31) no longer
        # holds; the current closed allocation is the declared one.
        self.assertEqual(
            alloc,
            sorted(f"{owner}:{count}" for owner, count in oracle.EXPECTED_OWNER_ALLOCATIONS),
        )
        self.assertRegex(str(inv["inventory_digest"]), r"\A[0-9a-f]{64}\Z")

    def test_rows_closed_and_bound(self) -> None:
        inv = _live()
        by_ref = {str(r["case_ref"]): r for r in inv["rows"]}
        for row in inv["rows"]:
            # The 866.1 generator exported this closed set as
            # `REQUIRED_ROW_KEYS`; revision 866.2 renamed it to `ROW_KEYS`
            # (commit 088494c53). The rename is the only change: the rows are
            # still required to carry the closed key set. The assertion is
            # therefore re-derived against the current symbol, not weakened --
            # it still demands every declared key on every row.
            self.assertTrue(oracle.ROW_KEYS.issubset(row.keys()), row.get("id"))
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
            # The old test staged a tree holding only the DENOMINATOR_CASES scan
            # roots. A default-denominator `sync` reads every declared input,
            # not just those, and rule revision 866.2 widened that input set, so
            # the staged tree was missing 22 declared files and `cmd_sync`
            # correctly failed closed with SOURCE_NOT_REGULAR_FILE on the first
            # one it needed (crates/eliot-app/src/cognitive_field_runner.rs, an
            # EXCLUSION_CASE scan input). The product is right to demand the
            # whole declared input set; the test was staging an incomplete tree.
            # Stage the set the generator itself declares so the real sync/check
            # path runs instead of dying on the first absent input.
            declared_inputs = _declared_sync_inputs()
            self.assertEqual(len(declared_inputs), len(set(declared_inputs)))
            scan_roots = {rel for _ref, _owner, rel, _sig in oracle.DENOMINATOR_CASES}
            self.assertTrue(scan_roots < set(declared_inputs), "sync reads more than the scan roots")
            for rel in declared_inputs:
                src, dst = ROOT / rel, troot / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(src.read_bytes())
            self.assertEqual(oracle.cmd_sync(troot, "unittest-sync"), 0)
            target = troot / oracle.OWNED_TOML.as_posix()
            before = target.read_bytes()
            self.assertEqual(oracle.cmd_sync(troot, "unittest-sync"), 0)
            self.assertEqual(target.read_bytes(), before, "repeated sync stays byte-identical")
            # `check` certifies a COMPLETE denominator. The frozen denominator
            # still declares UNRESOLVED_CASES -- rows outside every declared
            # seam whose owner is "unresolved" -- so coverage_disposition is
            # INCOMPLETE and `check` refuses to certify: it reports
            # UNRESOLVED_ROWS_BLOCK_COMPLETE_DENOMINATOR with status "blocked"
            # and exit 2. Exit 0 would require a zero-unresolved denominator the
            # current rule set does not produce, so the test asserts the real
            # documented contract AND pins the cause, rather than dropping the
            # assertion: the block must name the unresolved rows, the stored
            # header must agree with it, and every declared consumer workset
            # must itself be dispatch-ready, proving the ONLY thing standing
            # between this artifact and certification is the unallocated rows.
            stored = oracle._parse_toml(target.read_bytes(), source=oracle.OWNED_TOML.as_posix())
            self.assertEqual(stored["header"]["owner_map_status"], "SUPPLIED")
            self.assertEqual(stored["header"]["coverage_disposition"], "INCOMPLETE")
            unresolved_expected = dict(oracle.EXPECTED_OWNER_ALLOCATIONS)[oracle.UNRESOLVED_OWNER]
            self.assertEqual(stored["header"]["unresolved_count"], unresolved_expected)
            self.assertEqual(
                _check_verdict(troot),
                (2, "UNRESOLVED_ROWS_BLOCK_COMPLETE_DENOMINATOR", "blocked"),
            )
            self.assertEqual(
                [ws for ws in stored["consumer_worksets"] if not ws["dispatch_ready"]], []
            )
            # A scanned-source edit is drift, reported as such, not as a block.
            with open(troot / "crates/smart/eliot-context-measurement/src/stu.rs", "ab") as fh:
                fh.write(b"\n// touch\n")
            self.assertEqual(_check_verdict(troot), (1, "STALE_ARTIFACT", "stale"))
            oracle.cmd_sync(troot, "unittest-sync")
            self.assertEqual(
                _check_verdict(troot),
                (2, "UNRESOLVED_ROWS_BLOCK_COMPLETE_DENOMINATOR", "blocked"),
                "re-sync re-derives the artifact, so only the unresolved rows remain",
            )
            # A hand-edited classification is a malformed artifact, not drift.
            tampered = target.read_text(encoding="utf-8").replace("exact-utf8-envelope", "test-only", 1)
            target.write_text(tampered, encoding="utf-8")
            self.assertEqual(_check_verdict(troot), (2, "CLASSIFICATION_NOT_CLOSED", "error"))

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
