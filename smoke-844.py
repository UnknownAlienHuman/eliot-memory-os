"""Cargo-free smoke probe for the #844 lane (NOT part of the deliverable).

Parses Rust + Python WORK_UNIT_CASE markers through the accepted #851
interface and exercises the pure-source predicates of the new wrapper.
Runs no cargo, starts no subprocess, mutates nothing.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.work_unit_gate import case_binding as cb
from scripts.tests import test_ors_process_evidence_acceptance as acc

tests_source = acc.check_read_source_text(acc.TESTS_RS_REL)
own_text = acc.check_read_source_text(acc.OWN_REL)

rust_markers = cb.parse_rust_markers(tests_source, acc.TESTS_RS_REL, expected_issue=844)
pairs = sorted((m.case_issue, m.case_number) for m in rust_markers)
assert pairs == [(844, n) for n in range(1, 24)], pairs
assert len({m.qualified_name for m in rust_markers}) == 23
bad = [m for m in rust_markers if m.adequacy_problem is not None]
assert not bad, [(m.test_name, m.adequacy_problem) for m in bad]
print("rust markers 1..23 ok:")
for m in rust_markers:
    print(f"  844/{m.case_number} -> {m.test_name}")

py_markers = cb.parse_python_markers(
    own_text, acc.OWN_REL,
    module_name="scripts.tests.test_ors_process_evidence_acceptance",
    expected_issue=844,
)
py_pairs = sorted((m.case_issue, m.case_number) for m in py_markers)
assert py_pairs == [(844, n) for n in range(24, 28)], py_pairs
print("python markers 24..27 ok:")
for m in py_markers:
    print(f"  844/{m.case_number} -> {m.qualified_name}")

fixture_item = acc.check_extract_fn_item(tests_source, acc.FIXTURE_FN)
n = acc.check_fixture_names_canonical_constant(fixture_item)
print(f"fixture constant check ok (uses={n})")
assert acc.check_observation_axes_preserved(tests_source)
print("axes preservation check ok")
evidence_source = acc.check_read_source_text(acc.EVIDENCE_RS_REL)
model_source = acc.check_read_source_text(acc.MODEL_RS_REL)
assert acc.check_production_sources_stable(evidence_source, model_source)
print("production stability check ok")
assert acc.check_suite_green(
    b"test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured;\n")
print("suite-green checker ok (incl. negative probe below)")
try:
    acc.check_suite_green(b"test result: ok. 1 passed; 1 failed; 0 ignored;\n")
except AssertionError:
    print("suite-green negative probe ok")
else:
    raise SystemExit("suite-green negative probe FAILED")
print("SMOKE_OK")
