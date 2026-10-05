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


def _write(troot: Path, rel: str, text: str) -> None:
    target = troot / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


class TestContextMeasurementInventory(unittest.TestCase):
    def test_header_closed_versioned_72(self) -> None:
        inv = _live()
        h = inv["header"]
        self.assertEqual(h["schema"], "eliot.context-measurement-inventory.v2")
        self.assertEqual(h["rule_revision"], "866.3")
        self.assertRegex(str(h["source_sha"]), r"\A[0-9a-f]{64}\Z")
        self.assertRegex(str(h["rule_digest"]), r"\A[0-9a-f]{64}\Z")
        self.assertRegex(str(h["owner_digest"]), r"\A[0-9a-f]{64}\Z")
        self.assertEqual(h["candidate_count"], 126)
        self.assertEqual(h["classified_count"], 126)
        self.assertEqual(len(inv["rows"]), 126)
        self.assertEqual(len(h["classifications"]), 15)
        self.assertEqual(len(set(h["classifications"])), 15)
        alloc = [str(x) for x in h["owner_allocations"]]  # type: ignore[union-attr]
        self.assertNotIn("#785", "".join(alloc))
        self.assertEqual(sum(int(x.split(":")[1]) for x in alloc), 126)
        self.assertEqual(sorted(alloc), ['#704:9', '#783:21', '#878:17', '#880:21', 'unresolved:58'])
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
        tiny = (("704/1", "#704", "scan/a.rs", "stu_for_bytes"), ("880/1", "#880", "scan/b.rs", "fixed_overhead@@0"))
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
            for _ref, rel, _needle, _reason in oracle.EXCLUSION_CASES:
                src, dst = ROOT / rel, troot / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(src.read_bytes())
            for _own, rels in oracle.CONSUMER_TEST_PATHS.items():
                for rel in rels:
                    src, dst = ROOT / rel, troot / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    dst.write_bytes(src.read_bytes())
            for _own, rels in oracle.CONSUMER_ROUTED_READING.items():
                for rel in rels:
                    src, dst = ROOT / rel, troot / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    dst.write_bytes(src.read_bytes())
            map_src = ROOT / oracle.OWNER_MAP_PATH.as_posix()
            map_dst = troot / oracle.OWNER_MAP_PATH.as_posix()
            map_dst.parent.mkdir(parents=True, exist_ok=True)
            map_dst.write_bytes(map_src.read_bytes())
            self.assertEqual(oracle.cmd_sync(troot, "unittest-sync"), 0)
            target = troot / oracle.OWNED_TOML.as_posix()
            before = target.read_bytes()
            self.assertEqual(oracle.cmd_sync(troot, "unittest-sync"), 0)
            self.assertEqual(target.read_bytes(), before, "repeated sync stays byte-identical")
            self.assertEqual(oracle.cmd_check(troot), 2)
            with open(troot / "crates/smart/eliot-context-measurement/src/stu.rs", "ab") as fh:
                fh.write(b"\n// touch\n")
            self.assertEqual(oracle.cmd_check(troot), 1)
            oracle.cmd_sync(troot, "unittest-sync")
            self.assertEqual(oracle.cmd_check(troot), 2)
            tampered = target.read_text(encoding="utf-8").replace("exact-utf8-envelope", "test-only", 1)
            target.write_text(tampered, encoding="utf-8")
            self.assertEqual(oracle.cmd_check(troot), 2)

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
            # A live build must prove read-only against the PASSED root, not the
            # repo ROOT: stage every default-denominator input, snapshot, build,
            # and compare. Calling _live() here would only re-read repo ROOT.
            staged = {rel for _ref, _own, rel, _sig in oracle.DENOMINATOR_CASES}
            staged |= {rel for _ref, rel, _needle, _reason in oracle.EXCLUSION_CASES}
            staged.add(oracle.OWNER_MAP_PATH.as_posix())
            for paths in oracle.CONSUMER_TEST_PATHS.values():
                staged |= set(paths)
            for paths in oracle.CONSUMER_ROUTED_READING.values():
                staged |= set(paths)
            for rel in sorted(staged):
                src_file, dst = ROOT / rel, troot / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(src_file.read_bytes())
            before = _snapshot(troot)
            inv = oracle.build_inventory(troot, None, "unittest-guard")
            self.assertEqual(len(inv["rows"]), 126)
            self.assertEqual(_snapshot(troot), before)

    # WORK_UNIT_CASE: 866/1
    def test_case_01_exact_scan_root_denominator(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            _write(troot, "scan/a.rs", "pub fn stu_for_bytes(len: u64) -> u64 {\n    len / 3\n}\n")
            _write(troot, "scan/b.rs", "pub struct Envelope {\n    pub rendered_utf8_bytes: u64,\n}\n")
            cases = (
                ("C1a", "#704", "scan/a.rs", "stu_for_bytes"),
                ("C1b", "#704", "scan/b.rs", "rendered_utf8_bytes"),
            )
            inv = oracle.build_inventory(troot, cases, "case-01")
            by_ref = {str(r["case_ref"]): r for r in inv["rows"]}
            self.assertEqual(set(by_ref), {"C1a", "C1b"})
            self.assertEqual(by_ref["C1a"]["classification"], "normative-stu-estimate")
            self.assertEqual(by_ref["C1b"]["classification"], "exact-utf8-envelope")
            self.assertEqual(sorted(str(h) for h in inv["header"]["scan_roots"]), ["scan/a.rs", "scan/b.rs"])

    # WORK_UNIT_CASE: 866/2
    def test_case_02_byte_ratio_four_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            body = (FIXTURES / "mutated_bodies.rs").read_text(encoding="utf-8")
            _write(troot, "scan/m.rs", body)
            cases = (("C2", "#704", "scan/m.rs", "fn measure_rounded_up_sum"),)
            inv = oracle.build_inventory(troot, cases, "case-02")
            frozen = [r for r in inv["rows"] if str(r["case_ref"]) == "C2"]
            self.assertEqual(len(frozen), 1)
            self.assertEqual(frozen[0]["classification"], "token_estimate_without_tokenizer")
            auto = [r for r in inv["rows"] if str(r["case_ref"]).startswith("auto/")]
            self.assertEqual(len(auto), 1)
            self.assertEqual(auto[0]["item"], "fn measure_chars_claimed_tokens")
            self.assertEqual(auto[0]["owner"], "unresolved")
            self.assertEqual(auto[0]["status"], "unresolved")

    # WORK_UNIT_CASE: 866/3
    def test_case_03_character_estimate_detected_separately(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            _write(
                troot,
                "scan/c.rs",
                "pub fn estimate_chars_claimed(input: &str) -> u64 {\n"
                "    input.chars().count().div_ceil(4) as u64\n"
                "}\n",
            )
            cases = (("C3", "#704", "scan/c.rs", "fn estimate_chars_claimed"),)
            inv = oracle.build_inventory(troot, cases, "case-03")
            self.assertEqual(len(inv["rows"]), 1)
            self.assertEqual(inv["rows"][0]["classification"], "character_count_mislabeled_as_tokens")

    # WORK_UNIT_CASE: 866/4
    def test_case_04_non_ascii_bytes_not_characters(self) -> None:
        line = '    // caf\u00e9 \u2014 non-ASCII marker: bytes, not chars'
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            _write(
                troot,
                "scan/u.rs",
                "pub fn estimate_small(text: &str) -> u64 {\n"
                + line
                + "\n"
                + "    text.len().div_ceil(4) as u64\n"
                + "}\n",
            )
            cases = (("C4", "#704", "scan/u.rs", "fn estimate_small"),)
            inv = oracle.build_inventory(troot, cases, "case-04")
            self.assertEqual(len(inv["rows"]), 1)
            row = inv["rows"][0]
            self.assertEqual(row["classification"], "token_estimate_without_tokenizer")
            raw_lines = (troot / "scan/u.rs").read_text(encoding="utf-8").splitlines()
            expect = sum(len(l.encode("utf-8")) + 1 for l in raw_lines[int(row["span_start"]) - 1 : int(row["span_end"])])
            self.assertEqual(int(row["span_bytes"]), expect)
            self.assertGreater(expect, sum(len(l) + 1 for l in raw_lines[int(row["span_start"]) - 1 : int(row["span_end"])]))

    # WORK_UNIT_CASE: 866/5
    def test_case_05_local_estimate_helper_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            body = (FIXTURES / "second_occurrence.rs").read_text(encoding="utf-8")
            _write(troot, "scan/s.rs", body)
            cases = (("C5", "#704", "scan/s.rs", "stu_for_bytes@@0"),)
            inv = oracle.build_inventory(troot, cases, "case-05")
            frozen = [r for r in inv["rows"] if str(r["case_ref"]) == "C5"]
            self.assertEqual(len(frozen), 1)
            self.assertEqual(frozen[0]["classification"], "normative-stu-estimate")
            self.assertEqual((int(frozen[0]["span_start"]), int(frozen[0]["span_end"])), (3, 3))
            auto = [r for r in inv["rows"] if str(r["case_ref"]).startswith("auto/")]
            self.assertEqual(len(auto), 2)
            for row in auto:
                self.assertEqual(row["owner"], "unresolved")
                self.assertEqual(row["status"], "unresolved")

    # WORK_UNIT_CASE: 866/6
    def test_case_06_bare_estimate_field_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            _write(troot, "scan/r.rs", "pub struct Reading {\n    pub estimated_tokens: usize,\n}\n")
            cases = (("C6", "#704", "scan/r.rs", "estimated_tokens"),)
            inv = oracle.build_inventory(troot, cases, "case-06")
            self.assertEqual(len(inv["rows"]), 1)
            self.assertEqual(inv["rows"][0]["classification"], "bare_measurement_field_or_conversion")

    # WORK_UNIT_CASE: 866/7
    def test_case_07_owner_classified_not_defect(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            body = (FIXTURES / "stu_estimate.rs").read_text(encoding="utf-8")
            _write(troot, "scan/stu.rs", body)
            cases = (("C7", "#704", "scan/stu.rs", "stu_for_bytes"),)
            inv = oracle.build_inventory(troot, cases, "case-07")
            self.assertEqual(len(inv["rows"]), 1)
            row = inv["rows"][0]
            self.assertEqual(row["classification"], "normative-stu-estimate")
            self.assertEqual(row["status"], "unresolved")
            self.assertTrue(row["dispatch_blocked"])

    # WORK_UNIT_CASE: 866/8
    def test_case_08_unrelated_collection_length_excluded(self) -> None:
        cache = oracle._load_files(ROOT, ["crates/eliot-app/src/cognitive_field_runner.rs"])
        record = cache["crates/eliot-app/src/cognitive_field_runner.rs"]
        start, end = oracle._locate_signal(record, record["path"], "executions.len().div_ceil(target_chunks)")
        label, evidence = oracle.classify_context_measurement("executions.len().div_ceil(target_chunks)", str(record["path"]))
        self.assertEqual(label, "unrelated_byte_or_character_metric")
        self.assertTrue(evidence)
        self.assertGreaterEqual(end, start)

    # WORK_UNIT_CASE: 866/9
    def test_case_09_true_ui_character_metric_excluded(self) -> None:
        cache = oracle._load_files(ROOT, ["crates/eliot-engine/src/host.rs"])
        record = cache["crates/eliot-engine/src/host.rs"]
        start, end = oracle._locate_signal(record, record["path"], "descriptions += description_characters")
        label, evidence = oracle.classify_context_measurement(
            "descriptions += description_characters", str(record["path"])
        )
        self.assertEqual(label, "unrelated_byte_or_character_metric")
        self.assertTrue(evidence)
        self.assertGreaterEqual(end, start)

    # WORK_UNIT_CASE: 866/10
    def test_case_10_scope_respects_enclosing_item(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            _write(
                troot,
                "scan/s.rs",
                "pub fn stu_for_bytes(len: u64) -> u64 {\n"
                "    len / 3\n"
                "}\n"
                "#[cfg(test)]\n"
                "mod tests {\n"
                "    use super::*;\n"
                "    #[test]\n"
                "    fn check_it() {\n"
                "        assert_eq!(stu_for_bytes(9), 3);\n"
                "    }\n"
                "}\n",
            )
            cases = (
                ("C10a", "#704", "scan/s.rs", "pub fn stu_for_bytes"),
                ("C10b", "#704", "scan/s.rs", "fn check_it"),
            )
            inv = oracle.build_inventory(troot, cases, "case-10")
            by_ref = {str(r["case_ref"]): r for r in inv["rows"]}
            self.assertEqual(set(by_ref), {"C10a", "C10b"})
            self.assertEqual(by_ref["C10a"]["item_scope"], "production")
            self.assertEqual(by_ref["C10a"]["classification"], "normative-stu-estimate")
            self.assertEqual(by_ref["C10b"]["item_scope"], "test")
            self.assertEqual(by_ref["C10b"]["classification"], "test-only")

    # WORK_UNIT_CASE: 866/11
    def test_case_11_markers_in_strings_comments_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            _write(
                troot,
                "scan/m.rs",
                "// stu_for_bytes planning note, not code\n"
                "pub fn real_work(len: u64) -> u64 {\n"
                '    let _tag = "measure_exact_utf8";\n'
                "    len / 3\n"
                "}\n",
            )
            cache = oracle._load_files(troot, ["scan/m.rs"])
            record = cache["scan/m.rs"]
            masked = str(record["masked"])
            self.assertNotIn("stu_for_bytes", masked)
            self.assertNotIn("measure_exact_utf8", masked)
            self.assertEqual(oracle._locate_all_occurrences(record, "scan/m.rs", "stu_for_bytes"), [])
            self.assertEqual(oracle._locate_all_occurrences(record, "scan/m.rs", "measure_exact_utf8"), [])
            live = oracle._locate_all_occurrences(record, "scan/m.rs", "len / 3")
            self.assertEqual(len(live), 1)

    # WORK_UNIT_CASE: 866/12
    def test_case_12_multiline_chain_exact_span(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            _write(
                troot,
                "scan/c.rs",
                "pub fn estimate_tokens_chained(input: &[u8]) -> u64 {\n"
                "    input\n"
                "        .len()\n"
                "        .div_ceil(4) as u64\n"
                "}\n",
            )
            cases = (("C12", "#704", "scan/c.rs", "fn estimate_tokens_chained"),)
            inv = oracle.build_inventory(troot, cases, "case-12")
            self.assertEqual(len(inv["rows"]), 1)
            row = inv["rows"][0]
            self.assertEqual((int(row["span_start"]), int(row["span_end"])), (1, 5))
            self.assertEqual(row["item"], "fn estimate_tokens_chained")
            self.assertEqual(row["classification"], "token_estimate_without_tokenizer")

    # WORK_UNIT_CASE: 866/13
    def test_case_13_one_classification_per_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            _write(troot, "scan/a.rs", "pub fn stu_for_bytes(len: u64) -> u64 {\n    len / 3\n}\n")
            _write(troot, "scan/b.rs", "pub struct Envelope {\n    pub rendered_utf8_bytes: u64,\n}\n")
            cases = (
                ("C13a", "#704", "scan/a.rs", "stu_for_bytes"),
                ("C13b", "#704", "scan/b.rs", "rendered_utf8_bytes"),
            )
            inv = oracle.build_inventory(troot, cases, "case-13")
            self.assertEqual(len(inv["rows"]), 2)
            for row in inv["rows"]:
                self.assertIn(row["classification"], tuple(oracle.CLASSIFICATIONS))
                self.assertEqual(set(row.keys()), oracle.REQUIRED_ROW_KEYS)
                self.assertRegex(str(row["row_digest"]), r"\A[0-9a-f]{64}\Z")

    # WORK_UNIT_CASE: 866/14
    def test_case_14_duplicate_identity_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            _write(troot, "scan/a.rs", "pub fn stu_for_bytes(len: u64) -> u64 {\n    len / 3\n}\n")
            dup = (
                ("D", "#704", "scan/a.rs", "stu_for_bytes"),
                ("D", "#704", "scan/a.rs", "stu_for_bytes"),
            )
            try:
                oracle.build_inventory(troot, dup, "case-14-dup")
            except oracle.InventoryError as exc:
                self.assertEqual(exc.code, "DUPLICATE_ROW_IDENTITY")
            else:
                self.fail("duplicate case_ref must fail closed")
            body = (FIXTURES / "second_occurrence.rs").read_text(encoding="utf-8")
            _write(troot, "scan/s.rs", body)
            try:
                oracle.build_inventory(troot, (("A", "#704", "scan/s.rs", "stu_for_bytes"),), "case-14-amb")
            except oracle.InventoryError as exc:
                self.assertEqual(exc.code, "AMBIGUOUS_SIGNAL")
            else:
                self.fail("unqualified multi-match needle must fail closed")

    # WORK_UNIT_CASE: 866/15
    def test_case_15_unresolved_blocks_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            _write(troot, "scan/u.rs", "pub struct R {\n    pub estimated_tokens: usize,\n}\n")
            cases = (("C15", "unresolved", "scan/u.rs", "estimated_tokens"),)
            inv = oracle.build_inventory(troot, cases, "case-15")
            self.assertEqual(len(inv["rows"]), 1)
            row = inv["rows"][0]
            self.assertEqual(row["status"], "unresolved")
            self.assertTrue(row["dispatch_blocked"])
            self.assertEqual(inv["header"]["coverage_disposition"], "INCOMPLETE")

    # WORK_UNIT_CASE: 866/16
    def test_case_16_exact_accepted_owner_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            troot = Path(td).resolve()
            _write(troot, "scan/r.rs", "pub fn stu_for_bytes(len: u64) -> u64 {\n    len / 3\n}\n")
            cases = (("C16", "#704", "scan/r.rs", "stu_for_bytes"),)
            owner_map = ({"#704": {"source_paths": ["scan/r.rs"]}}, "SUPPLIED", "case-16-digest")
            inv = oracle.build_inventory(troot, cases, "case-16", owner_map)
            self.assertEqual(len(inv["rows"]), 1)
            row = inv["rows"][0]
            self.assertEqual(row["status"], "owned")
            self.assertFalse(row["dispatch_blocked"])


if __name__ == "__main__":
    unittest.main()
