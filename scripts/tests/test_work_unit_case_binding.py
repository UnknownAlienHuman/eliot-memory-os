"""Unit tests for work-unit case marker binding and reconciliation (#851).

Every numbered case 1..44 corresponds to one distinct obligation in the issue
acceptance contract. Marked with exact `# WORK_UNIT_CASE: 851/<case>` annotations.
"""
from __future__ import annotations

import ast
from pathlib import Path
import random
import unittest

from scripts.work_unit_gate import case_binding as b
from scripts.work_unit_gate import contracts as c

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "scripts/testdata/work-unit-gate/case-binding"

REPO = c.RepositoryIdentity("UnknownAlienHuman", "eliot-memory-os")
ISSUE = c.IssueIdentity(REPO, 851)
OTHER_ISSUE = c.IssueIdentity(REPO, 999)
TEST_ROOT = c.RepositoryPath("scripts/tests")
SOURCE_ROOT = c.RepositoryPath("scripts/work_unit_gate")


def make_descriptor(cases: int = 44, mode: c.RunnerMode = c.RunnerMode.PYTHON_UNITTEST) -> c.WorkUnitDescriptor:
    pkg = c.PackageIdentity("sample-pkg") if mode is c.RunnerMode.RUST_PACKAGE else None
    return c.WorkUnitDescriptor(
        schema_version=c.WORK_UNIT_DESCRIPTOR_SCHEMA,
        identity=c.DescriptorIdentity("851-case-binding"),
        issue=ISSUE,
        unit=c.WorkUnitIdentity("D-WU-BINDINGS"),
        mode=mode,
        source_roots=(SOURCE_ROOT,),
        test_roots=(TEST_ROOT,),
        matrix_cases=cases,
        proof_ceiling=c.ProofCeiling("assignment-source-only"),
        revision=1,
        body_sha256="a" * 64,
        matrix_sha256="b" * 64,
        require_workspace_member=False,
        requirements=c.VerificationRequirements(source_floor=1, public_floor=0, test_floor=cases, required_guards=()),
        bounds=c.ExecutionBounds(wall_ms=60000, idle_ms=10000, output_bytes=1048576, line_bytes=65536, discovery_tests=1000, child_processes=4),
        package=pkg,
    )


def make_assignment(cases: int = 44) -> c.AssignmentSourceReceipt:
    return c.AssignmentSourceReceipt(
        issue=ISSUE,
        state=c.IssueState.OPEN,
        unit=c.WorkUnitIdentity("D-WU-BINDINGS"),
        authority=c.SourceAuthority.LIVE_GITHUB,
        title="[D-WU-BINDINGS] Bind every assignment case to one discovered and executed test",
        body_sha256="a" * 64,
        matrix_cases=cases,
        proof_ceiling=c.ProofCeiling("assignment-source-only"),
        matrix_sha256="b" * 64,
        source_use=c.AssignmentSourceUse.ACTIVE_ASSIGNMENT,
        origin="https://api.github.com",
        live_etag='W/"fixture"',
    )


def make_disc(desc: c.WorkUnitDescriptor, test_name: str, number: int = 1, path: str = "scripts/tests/test_case.py") -> c.DiscoveredTestReceipt:
    test = c.TestIdentity(desc.mode, test_name)
    loc = c.SourceLocation(c.RepositoryPath(path), number)
    return c.DiscoveredTestReceipt(desc.identity, desc.sha256, test, loc, "c" * 64, "d" * 64, desc.phase)


def make_exec(disc: c.DiscoveredTestReceipt, disposition: c.ExecutionDisposition = c.ExecutionDisposition.EXECUTED_PASS) -> c.TestExecutionRecord:
    return c.TestExecutionRecord(disc.test, disposition, disc)


class CaseBindingTests(unittest.TestCase):
    # WORK_UNIT_CASE: 851/1
    def test_case_01_valid_plain_rust_test_binding(self):
        source = """
// WORK_UNIT_CASE: 851/1
#[test]
fn direct_activation_valid() {
    assert_eq!(2 + 2, 4);
}
"""
        markers = b.parse_rust_markers(source, "scripts/tests/test_foo.rs")
        self.assertEqual(1, len(markers))
        self.assertEqual(851, markers[0].case_issue)
        self.assertEqual(1, markers[0].case_number)
        self.assertEqual("direct_activation_valid", markers[0].test_name)
        self.assertFalse(markers[0].is_async)

    # WORK_UNIT_CASE: 851/2
    def test_case_02_supported_tokio_test_binding(self):
        source = """
// WORK_UNIT_CASE: 851/2
#[tokio::test]
async fn async_direct_activation() {
    let x = 1;
    assert_eq!(x, 1);
}
"""
        markers = b.parse_rust_markers(source, "scripts/tests/test_async.rs")
        self.assertEqual(1, len(markers))
        self.assertEqual(2, markers[0].case_number)
        self.assertTrue(markers[0].is_async)

    # WORK_UNIT_CASE: 851/3
    def test_case_03_allowed_inert_attributes_preserve_exact_adjacency(self):
        source = """
// WORK_UNIT_CASE: 851/3
#[allow(dead_code)]
#[should_panic(expected = "boom")]
#[test]
fn inert_attributes_test() {
    panic!("boom");
}
"""
        markers = b.parse_rust_markers(source, "scripts/tests/test_inert.rs")
        self.assertEqual(1, len(markers))
        self.assertEqual(3, markers[0].case_number)

    # WORK_UNIT_CASE: 851/4
    def test_case_04_blank_intervening_ordinary_comment_detaches_marker(self):
        source_blank = """
// WORK_UNIT_CASE: 851/4

#[test]
fn detached_by_blank() {
    assert_eq!(1, 1);
}
"""
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_rust_markers(source_blank, "scripts/tests/test_detached.rs")
        self.assertEqual(b.CaseBindingProblem.DETACHED_MARKER, cm.exception.problem)

        source_comment = """
// WORK_UNIT_CASE: 851/4
// ordinary intervening comment
#[test]
fn detached_by_comment() {
    assert_eq!(1, 1);
}
"""
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_rust_markers(source_comment, "scripts/tests/test_detached.rs")
        self.assertEqual(b.CaseBindingProblem.DETACHED_MARKER, cm.exception.problem)

    # WORK_UNIT_CASE: 851/5
    def test_case_05_marker_before_non_test_function_rejected(self):
        source = """
// WORK_UNIT_CASE: 851/5
fn helper_not_a_test() {
    println!("hello");
}
"""
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_rust_markers(source, "scripts/tests/test_non_test.rs")
        self.assertEqual(b.CaseBindingProblem.MARKER_BEFORE_NON_TEST, cm.exception.problem)

    # WORK_UNIT_CASE: 851/6
    def test_case_06_normal_string_marker_ignored(self):
        source = """
#[test]
fn test_string_literal() {
    let literal = "// WORK_UNIT_CASE: 851/6";
    assert!(!literal.is_empty());
}
"""
        markers = b.parse_rust_markers(source, "scripts/tests/test_str.rs")
        self.assertEqual(0, len(markers))

    # WORK_UNIT_CASE: 851/7
    def test_case_07_raw_byte_string_marker_ignored(self):
        source = """
#[test]
fn test_raw_byte_string() {
    let raw_b = br#"// WORK_UNIT_CASE: 851/7"#;
    assert_eq!(raw_b.len(), 24);
}
"""
        markers = b.parse_rust_markers(source, "scripts/tests/test_raw.rs")
        self.assertEqual(0, len(markers))

    # WORK_UNIT_CASE: 851/8
    def test_case_08_doc_block_nested_comment_marker_ignored(self):
        source = """
/// // WORK_UNIT_CASE: 851/8
/*
  nested block: /* // WORK_UNIT_CASE: 851/8 */
*/
#[test]
fn test_block_comment_ignored() {
    assert_eq!(1 + 1, 2);
}
"""
        markers = b.parse_rust_markers(source, "scripts/tests/test_comments.rs")
        self.assertEqual(0, len(markers))

    # WORK_UNIT_CASE: 851/9
    def test_case_09_macro_generated_fixture_marker_ignored_or_attribution_fails_closed(self):
        source = """
macro_rules! define_test {
    ($name:ident) => {
        // WORK_UNIT_CASE: 851/9
        #[test]
        fn $name() { assert_eq!(1, 1); }
    };
}
"""
        # In macro definition, $name is not a valid function identifier
        with self.assertRaises(b.CaseBindingError):
            b.parse_rust_markers(source, "scripts/tests/test_macro.rs")

    # WORK_UNIT_CASE: 851/10
    def test_case_10_unclosed_lexical_state_fails_closed(self):
        source_unclosed_block = "/* unclosed block comment // WORK_UNIT_CASE: 851/10"
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_rust_markers(source_unclosed_block, "scripts/tests/test_unclosed.rs")
        self.assertEqual(b.CaseBindingProblem.UNCLOSED_LEXICAL_STATE, cm.exception.problem)

        source_unclosed_str = 'let s = "unclosed string;'
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_rust_markers(source_unclosed_str, "scripts/tests/test_unclosed.rs")
        self.assertEqual(b.CaseBindingProblem.UNCLOSED_LEXICAL_STATE, cm.exception.problem)

    # WORK_UNIT_CASE: 851/11
    def test_case_11_ignored_rust_test_rejected(self):
        source = """
// WORK_UNIT_CASE: 851/11
#[ignore]
#[test]
fn test_ignored() {
    assert_eq!(1, 1);
}
"""
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_rust_markers(source, "scripts/tests/test_ignore.rs")
        self.assertEqual(b.CaseBindingProblem.IGNORED_TEST, cm.exception.problem)

    # WORK_UNIT_CASE: 851/12
    def test_case_12_false_unsupported_unresolved_cfg_cannot_establish_passing_binding(self):
        desc = make_descriptor(1, c.RunnerMode.RUST_PACKAGE)
        assign = make_assignment(1)
        marker = b.ParsedMarker(851, 1, "test_cfg", "test_cfg", "scripts/tests/test_cfg.rs", 10, 1, has_cfg=True)
        disc = make_disc(desc, "test_cfg", 1, "scripts/tests/test_cfg.rs")
        exec_record = make_exec(disc, c.ExecutionDisposition.CFG_DISABLED)
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, [marker], [disc], [exec_record])
        self.assertEqual(b.CaseBindingProblem.NON_PASSING_DISPOSITION, cm.exception.problem)

    # WORK_UNIT_CASE: 851/13
    def test_case_13_duplicate_rust_qualified_identity_rejected(self):
        source = """
// WORK_UNIT_CASE: 851/13
#[test]
fn test_duplicate() {
    assert_eq!(1, 1);
}

// WORK_UNIT_CASE: 851/14
#[test]
fn test_duplicate() {
    assert_eq!(2, 2);
}
"""
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_rust_markers(source, "scripts/tests/test_dup.rs")
        self.assertEqual(b.CaseBindingProblem.DUPLICATE_TEST_IDENTITY, cm.exception.problem)

    # WORK_UNIT_CASE: 851/14
    def test_case_14_valid_python_test_case_method_binding(self):
        source = """
import unittest

class SampleTest(unittest.TestCase):
    # WORK_UNIT_CASE: 851/14
    def test_method(self):
        self.assertEqual(2 * 3, 6)
"""
        markers = b.parse_python_markers(source, "scripts/tests/test_py.py", module_name="test_py")
        self.assertEqual(1, len(markers))
        self.assertEqual(851, markers[0].case_issue)
        self.assertEqual(14, markers[0].case_number)
        self.assertEqual("test_py.SampleTest.test_method", markers[0].qualified_name)
        self.assertIsNone(markers[0].adequacy_problem)

    # WORK_UNIT_CASE: 851/15
    def test_case_15_valid_explicitly_registered_metadata_function_binding(self):
        source = """
# WORK_UNIT_CASE: 851/15
def test_metadata_entry():
    data = {"active": True}
    assert data["active"] is True
"""
        markers = b.parse_python_markers(source, "scripts/tests/test_meta.py",
                                         module_name="test_meta", mode=c.RunnerMode.METADATA_PYTHON)
        self.assertEqual(1, len(markers))
        self.assertEqual(15, markers[0].case_number)
        self.assertEqual("test_meta.test_metadata_entry", markers[0].qualified_name)

    # WORK_UNIT_CASE: 851/16
    def test_case_16_string_docstring_marker_ignored(self):
        source = """
import unittest

class DocTest(unittest.TestCase):
    '''
    # WORK_UNIT_CASE: 851/16
    '''
    def test_docstring(self):
        self.assertEqual(1, 1)
"""
        markers = b.parse_python_markers(source, "scripts/tests/test_doc.py", module_name="test_doc")
        self.assertEqual(0, len(markers))

    # WORK_UNIT_CASE: 851/17
    def test_case_17_detached_ambiguous_class_level_python_marker_rejected(self):
        source_class = """
import unittest

# WORK_UNIT_CASE: 851/17
class ClassMarkerTest(unittest.TestCase):
    def test_one(self):
        self.assertEqual(1, 1)
"""
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_python_markers(source_class, "scripts/tests/test_class.py", module_name="test_class")
        self.assertEqual(b.CaseBindingProblem.AMBIGUOUS_MARKER, cm.exception.problem)

        source_detached = """
import unittest

class DetachedTest(unittest.TestCase):
    # WORK_UNIT_CASE: 851/17

    def test_one(self):
        self.assertEqual(1, 1)
"""
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_python_markers(source_detached, "scripts/tests/test_detached.py", module_name="test_detached")
        self.assertEqual(b.CaseBindingProblem.DETACHED_MARKER, cm.exception.problem)

    # WORK_UNIT_CASE: 851/18
    def test_case_18_skipped_python_decorator_rejected(self):
        source = """
import unittest

class SkippedTest(unittest.TestCase):
    # WORK_UNIT_CASE: 851/18
    @unittest.skip("not ready")
    def test_skipped(self):
        self.assertEqual(1, 1)
"""
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_python_markers(source, "scripts/tests/test_skip.py", module_name="test_skip")
        self.assertEqual(b.CaseBindingProblem.SKIPPED_DECORATOR, cm.exception.problem)

    # WORK_UNIT_CASE: 851/19
    def test_case_19_dynamic_generated_unknown_identity_rejected(self):
        source = """
import unittest

class DynamicTest(unittest.TestCase):
    pass
"""
        # Dynamic monkey patching cannot produce AST markers
        markers = b.parse_python_markers(source, "scripts/tests/test_dynamic.py", module_name="test_dynamic")
        self.assertEqual(0, len(markers))

    # WORK_UNIT_CASE: 851/20
    def test_case_20_duplicate_module_class_method_identity_rejected(self):
        source = """
import unittest

class DupTest(unittest.TestCase):
    # WORK_UNIT_CASE: 851/20
    def test_dup(self):
        self.assertEqual(1, 1)

    # WORK_UNIT_CASE: 851/21
    def test_dup(self):
        self.assertEqual(2, 2)
"""
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_python_markers(source, "scripts/tests/test_dup.py", module_name="test_dup")
        self.assertEqual(b.CaseBindingProblem.DUPLICATE_TEST_IDENTITY, cm.exception.problem)

    # WORK_UNIT_CASE: 851/21
    def test_case_21_foreign_imported_test_path_rejected(self):
        desc = make_descriptor(1)
        assign = make_assignment(1)
        marker = b.ParsedMarker(851, 1, "test_fn", "test_fn", "crates/foreign/tests/test_foreign.rs", 10, 1)
        disc = make_disc(desc, "test_fn", 1, "scripts/tests/test_case.py")
        exec_record = make_exec(disc)
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, [marker], [disc], [exec_record])
        self.assertEqual(b.CaseBindingProblem.FOREIGN_TEST_PATH, cm.exception.problem)

    # WORK_UNIT_CASE: 851/22
    def test_case_22_malformed_python_syntax_fails_closed(self):
        malformed = "def incomplete_func(: \n    # WORK_UNIT_CASE: 851/22"
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_python_markers(malformed, "scripts/tests/test_bad.py")
        self.assertEqual(b.CaseBindingProblem.SYNTAX_ERROR, cm.exception.problem)

    # WORK_UNIT_CASE: 851/23
    def test_case_23_complete_exact_reconciliation_succeeds(self):
        n = 3
        desc = make_descriptor(n)
        assign = make_assignment(n)
        markers = [b.ParsedMarker(851, i, f"test_case_{i}", f"scripts.tests.test_case_{i}",
                                 "scripts/tests/test_case.py", i * 10, 1) for i in range(1, n + 1)]
        discoveries = [make_disc(desc, f"scripts.tests.test_case_{i}", i) for i in range(1, n + 1)]
        executions = [make_exec(d) for d in discoveries]

        receipt = b.reconcile_case_bindings(assign, desc, markers, discoveries, executions)
        self.assertIsInstance(receipt, c.CaseAccountingReceipt)
        self.assertEqual(c.OverallResult.PASS, receipt.result)
        self.assertEqual(n, len(receipt.members))
        for i in range(1, n + 1):
            self.assertEqual(i, receipt.members[i - 1].case.number)
            self.assertEqual(c.ExecutionDisposition.EXECUTED_PASS, receipt.members[i - 1].execution.disposition)

    # WORK_UNIT_CASE: 851/24
    def test_case_24_missing_first_middle_last_case_fails_and_names_id(self):
        desc = make_descriptor(3)
        assign = make_assignment(3)

        # Missing first case (1)
        m_missing_1 = [
            b.ParsedMarker(851, 2, "t2", "t2", "scripts/tests/test.py", 20, 1),
            b.ParsedMarker(851, 3, "t3", "t3", "scripts/tests/test.py", 30, 1),
        ]
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, m_missing_1, [], [])
        self.assertEqual(b.CaseBindingProblem.MISSING_CASE, cm.exception.problem)
        self.assertIn("1", cm.exception.detail)

        # Missing middle case (2)
        m_missing_2 = [
            b.ParsedMarker(851, 1, "t1", "t1", "scripts/tests/test.py", 10, 1),
            b.ParsedMarker(851, 3, "t3", "t3", "scripts/tests/test.py", 30, 1),
        ]
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, m_missing_2, [], [])
        self.assertEqual(b.CaseBindingProblem.MISSING_CASE, cm.exception.problem)
        self.assertIn("2", cm.exception.detail)

        # Missing last case (3)
        m_missing_3 = [
            b.ParsedMarker(851, 1, "t1", "t1", "scripts/tests/test.py", 10, 1),
            b.ParsedMarker(851, 2, "t2", "t2", "scripts/tests/test.py", 20, 1),
        ]
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, m_missing_3, [], [])
        self.assertEqual(b.CaseBindingProblem.MISSING_CASE, cm.exception.problem)
        self.assertIn("3", cm.exception.detail)

    # WORK_UNIT_CASE: 851/25
    def test_case_25_duplicate_case_fails(self):
        desc = make_descriptor(2)
        assign = make_assignment(2)
        markers = [
            b.ParsedMarker(851, 1, "t1", "t1", "scripts/tests/test.py", 10, 1),
            b.ParsedMarker(851, 1, "t2", "t2", "scripts/tests/test.py", 20, 1),
        ]
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, markers, [], [])
        self.assertEqual(b.CaseBindingProblem.DUPLICATE_CASE, cm.exception.problem)

    # WORK_UNIT_CASE: 851/26
    def test_case_26_zero_negative_above_range_case_fails(self):
        desc = make_descriptor(2)
        assign = make_assignment(2)
        for bad_num in (0, -1, 3, 99):
            markers = [b.ParsedMarker(851, bad_num, "t", "t", "scripts/tests/test.py", 10, 1)]
            with self.assertRaises(b.CaseBindingError) as cm:
                b.reconcile_case_bindings(assign, desc, markers, [], [])
            self.assertEqual(b.CaseBindingProblem.CASE_NUMBER_OUT_OF_BOUNDS, cm.exception.problem)

    # WORK_UNIT_CASE: 851/27
    def test_case_27_foreign_issue_marker_cannot_satisfy_assignment(self):
        desc = make_descriptor(1)
        assign = make_assignment(1)
        marker = b.ParsedMarker(999, 1, "t", "t", "scripts/tests/test.py", 10, 1)
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, [marker], [], [])
        self.assertEqual(b.CaseBindingProblem.FOREIGN_ISSUE, cm.exception.problem)

    # WORK_UNIT_CASE: 851/28
    def test_case_28_one_function_cannot_claim_two_cases(self):
        desc = make_descriptor(2)
        assign = make_assignment(2)
        markers = [
            b.ParsedMarker(851, 1, "test_both", "test_both", "scripts/tests/test.py", 10, 1),
            b.ParsedMarker(851, 2, "test_both", "test_both", "scripts/tests/test.py", 11, 1),
        ]
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, markers, [], [])
        self.assertEqual(b.CaseBindingProblem.FUNCTION_MULTIPLE_CASES, cm.exception.problem)

    # WORK_UNIT_CASE: 851/29
    def test_case_29_equal_leaf_names_in_different_modules_remain_distinct(self):
        desc = make_descriptor(2)
        assign = make_assignment(2)
        markers = [
            b.ParsedMarker(851, 1, "test_leaf", "mod_a.test_leaf", "scripts/tests/test_a.py", 10, 1),
            b.ParsedMarker(851, 2, "test_leaf", "mod_b.test_leaf", "scripts/tests/test_b.py", 10, 1),
        ]
        d1 = make_disc(desc, "mod_a.test_leaf", 1, "scripts/tests/test_a.py")
        d2 = make_disc(desc, "mod_b.test_leaf", 2, "scripts/tests/test_b.py")
        receipt = b.reconcile_case_bindings(assign, desc, markers, [d1, d2], [make_exec(d1), make_exec(d2)])
        self.assertEqual("mod_a.test_leaf", receipt.members[0].execution.test.qualified_name)
        self.assertEqual("mod_b.test_leaf", receipt.members[1].execution.test.qualified_name)

    # WORK_UNIT_CASE: 851/30
    def test_case_30_source_bound_test_absent_from_discovery_fails(self):
        desc = make_descriptor(1)
        assign = make_assignment(1)
        marker = b.ParsedMarker(851, 1, "test_absent", "test_absent", "scripts/tests/test.py", 10, 1)
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, [marker], [], [])
        self.assertEqual(b.CaseBindingProblem.TEST_NOT_DISCOVERED, cm.exception.problem)

    # WORK_UNIT_CASE: 851/31
    def test_case_31_discovered_but_unexecuted_test_fails(self):
        desc = make_descriptor(1)
        assign = make_assignment(1)
        marker = b.ParsedMarker(851, 1, "test_one", "test_one", "scripts/tests/test.py", 10, 1)
        disc = make_disc(desc, "test_one", 1, "scripts/tests/test.py")
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, [marker], [disc], [])
        self.assertEqual(b.CaseBindingProblem.TEST_NOT_EXECUTED, cm.exception.problem)

    # WORK_UNIT_CASE: 851/32
    def test_case_32_execution_fail_error_timeout_fails(self):
        desc = make_descriptor(1)
        assign = make_assignment(1)
        marker = b.ParsedMarker(851, 1, "test_fail", "test_fail", "scripts/tests/test.py", 10, 1)
        disc = make_disc(desc, "test_fail", 1, "scripts/tests/test.py")
        exec_fail = make_exec(disc, c.ExecutionDisposition.EXECUTED_FAIL)
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, [marker], [disc], [exec_fail])
        self.assertEqual(b.CaseBindingProblem.EXECUTION_FAILED, cm.exception.problem)

    # WORK_UNIT_CASE: 851/33
    def test_case_33_skip_ignore_cfg_disabled_filtered_unavailable_cannot_pass(self):
        desc = make_descriptor(1)
        assign = make_assignment(1)
        marker = b.ParsedMarker(851, 1, "test_disp", "test_disp", "scripts/tests/test.py", 10, 1)
        disc = make_disc(desc, "test_disp", 1, "scripts/tests/test.py")
        for bad_disp in (c.ExecutionDisposition.SKIPPED, c.ExecutionDisposition.IGNORED,
                         c.ExecutionDisposition.CFG_DISABLED, c.ExecutionDisposition.TIMED_OUT,
                         c.ExecutionDisposition.UNAVAILABLE):
            with self.assertRaises(b.CaseBindingError) as cm:
                b.reconcile_case_bindings(assign, desc, [marker], [disc], [make_exec(disc, bad_disp)])
            self.assertEqual(b.CaseBindingProblem.NON_PASSING_DISPOSITION, cm.exception.problem)

    # WORK_UNIT_CASE: 851/34
    def test_case_34_duplicate_discovery_execution_record_fails(self):
        desc = make_descriptor(1)
        assign = make_assignment(1)
        marker = b.ParsedMarker(851, 1, "test_dup", "test_dup", "scripts/tests/test.py", 10, 1)
        d1 = make_disc(desc, "test_dup", 1, "scripts/tests/test.py")
        d2 = make_disc(desc, "test_dup", 1, "scripts/tests/test.py")
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, [marker], [d1, d2], [make_exec(d1)])
        self.assertEqual(b.CaseBindingProblem.DUPLICATE_DISCOVERY, cm.exception.problem)

        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, [marker], [d1], [make_exec(d1), make_exec(d1)])
        self.assertEqual(b.CaseBindingProblem.DUPLICATE_EXECUTION, cm.exception.problem)

    # WORK_UNIT_CASE: 851/35
    def test_case_35_unrelated_extra_tests_cannot_repair_missing_coverage(self):
        desc = make_descriptor(2)
        assign = make_assignment(2)
        # Case 1 present, Case 2 missing; but an extra unmapped test 99 exists
        markers = [b.ParsedMarker(851, 1, "test_1", "test_1", "scripts/tests/test.py", 10, 1)]
        d1 = make_disc(desc, "test_1", 1)
        d_extra = make_disc(desc, "test_extra", 99)
        with self.assertRaises(b.CaseBindingError) as cm:
            b.reconcile_case_bindings(assign, desc, markers, [d1, d_extra], [make_exec(d1), make_exec(d_extra)])
        self.assertEqual(b.CaseBindingProblem.MISSING_CASE, cm.exception.problem)
        self.assertIn("2", cm.exception.detail)

    # WORK_UNIT_CASE: 851/36
    def test_case_36_randomized_traversal_gives_identical_ordered_receipts(self):
        n = 5
        desc = make_descriptor(n)
        assign = make_assignment(n)
        markers = [b.ParsedMarker(851, i, f"test_{i}", f"test_{i}", "scripts/tests/test.py", i * 10, 1) for i in range(1, n + 1)]
        discoveries = [make_disc(desc, f"test_{i}", i) for i in range(1, n + 1)]
        executions = [make_exec(d) for d in discoveries]

        r1 = b.reconcile_case_bindings(assign, desc, list(markers), list(discoveries), list(executions))

        # Randomize input sequences
        shuffled_markers = list(markers)
        shuffled_disc = list(discoveries)
        shuffled_exec = list(executions)
        rng = random.Random(42)
        rng.shuffle(shuffled_markers)
        rng.shuffle(shuffled_disc)
        rng.shuffle(shuffled_exec)

        r2 = b.reconcile_case_bindings(assign, desc, shuffled_markers, shuffled_disc, shuffled_exec)

        self.assertEqual(c.canonical_sha256(r1), c.canonical_sha256(r2))
        self.assertEqual([m.case.number for m in r1.members], [m.case.number for m in r2.members])

    # WORK_UNIT_CASE: 851/37
    def test_case_37_empty_pass_return_only_body_rejected(self):
        sources = [
            "def test_empty(self):\n    pass\n",
            "def test_return(self):\n    return\n",
            "def test_doc_only(self):\n    '''only doc'''\n",
        ]
        for src in sources:
            tree = ast.parse(src)
            prob, _, _ = b.check_python_function_adequacy(tree.body[0])
            self.assertEqual(b.CaseBindingProblem.EMPTY_TEST_BODY, prob)

    # WORK_UNIT_CASE: 851/38
    def test_case_38_unconditional_true_assertion_rejected(self):
        sources = [
            "def test_true(self):\n    self.assertTrue(True)\n",
            "def test_assert_true(self):\n    assert True\n",
            "def test_assert_not_false(self):\n    assert not False\n",
            "def test_false_val(self):\n    self.assertFalse(False)\n",
        ]
        for src in sources:
            tree = ast.parse(src)
            prob, _, _ = b.check_python_function_adequacy(tree.body[0])
            self.assertEqual(b.CaseBindingProblem.UNCONDITIONAL_TRUE, prob)

    # WORK_UNIT_CASE: 851/39
    def test_case_39_trivial_self_equality_rejected(self):
        sources = [
            "def test_eq_self(self):\n    x = 10\n    self.assertEqual(x, x)\n",
            "def test_is_self(self):\n    x = 'foo'\n    self.assertIs(x, x)\n",
            "def test_assert_eq(self):\n    x = [1]\n    assert x == x\n",
        ]
        for src in sources:
            tree = ast.parse(src)
            prob, _, _ = b.check_python_function_adequacy(tree.body[0])
            self.assertEqual(b.CaseBindingProblem.TRIVIAL_SELF_EQUALITY, prob)

    # WORK_UNIT_CASE: 851/40
    def test_case_40_no_check_constant_construction_rejected(self):
        source = """
def test_no_check(self):
    x = 100
    y = [1, 2, 3]
    _ = x + len(y)
"""
        tree = ast.parse(source)
        prob, _, _ = b.check_python_function_adequacy(tree.body[0])
        self.assertEqual(b.CaseBindingProblem.NO_CHECK_CONSTANT, prob)

    # WORK_UNIT_CASE: 851/41
    def test_case_41_supported_assertion_shapes_accepted_with_execution_binding(self):
        sources = [
            "def test_eq(self):\n    self.assertEqual(1 + 1, 2)\n",
            "def test_in(self):\n    self.assertIn('a', ['a', 'b'])\n",
            "def test_raises(self):\n    with self.assertRaises(ValueError):\n        raise ValueError()\n",
            "def test_assert_expr(self):\n    actual = 42\n    assert actual == 42\n",
        ]
        for src in sources:
            tree = ast.parse(src)
            prob, _, _ = b.check_python_function_adequacy(tree.body[0])
            self.assertIsNone(prob)

    # WORK_UNIT_CASE: 851/42
    def test_case_42_unknown_complex_assertion_shape_retains_lower_proof_ceiling(self):
        source = """
def test_custom_helper(self):
    self.check_custom_invariant(10, 20)
"""
        tree = ast.parse(source)
        prob, _, downgrade = b.check_python_function_adequacy(tree.body[0])
        self.assertIsNone(prob)
        self.assertTrue(downgrade)

    # WORK_UNIT_CASE: 851/43
    def test_case_43_each_file_byte_depth_test_case_bound_and_one_over_fails_explicitly(self):
        limits = b.BindingLimits(max_source_bytes=100, max_line_bytes=50, max_lexical_depth=3)
        # Source bytes bound and one-over
        ok_src = (" " * 40 + "\n") * 2
        b._check_source_bounds(ok_src.encode("utf-8"), limits)
        too_big = (" " * 40 + "\n") * 3
        with self.assertRaises(b.CaseBindingError) as cm:
            b._check_source_bounds(too_big.encode("utf-8"), limits)
        self.assertEqual(b.CaseBindingProblem.FILE_SIZE_LIMIT, cm.exception.problem)

        # Line bytes bound and one-over
        long_line = "a" * 51 + "\n"
        with self.assertRaises(b.CaseBindingError) as cm:
            b._check_source_bounds(long_line.encode("utf-8"), limits)
        self.assertEqual(b.CaseBindingProblem.LINE_LENGTH_LIMIT, cm.exception.problem)

        # Lexical depth bound and one-over
        deep_comment = "/* /* /* /* */ */ */ */"
        with self.assertRaises(b.CaseBindingError) as cm:
            b.parse_rust_markers(deep_comment, "test.rs", limits=limits)
        self.assertEqual(b.CaseBindingProblem.LEXICAL_DEPTH_LIMIT, cm.exception.problem)

    # WORK_UNIT_CASE: 851/44
    def test_case_44_source_api_guard_proves_no_network_subprocess_mutation_or_duplicate_contracts(self):
        target_file = ROOT / "scripts/work_unit_gate/case_binding.py"
        source_text = target_file.read_text(encoding="utf-8")
        tree = ast.parse(source_text)

        # 1. Banned imports
        imported_modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module)

        banned_modules = {"subprocess", "requests", "urllib", "http", "socket", "ctypes"}
        self.assertTrue(imported_modules.isdisjoint(banned_modules),
                        f"Found banned module imports: {imported_modules & banned_modules}")

        # 2. Banned call attributes
        banned_attrs = {
            "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
            "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
            "system", "popen", "remove", "unlink", "rmdir", "rmtree",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    self.fail("eval/exec call forbidden")
                if isinstance(node.func, ast.Attribute) and node.func.attr in banned_attrs:
                    self.fail(f"banned attribute call: {node.func.attr}")

        # 3. No duplicate contract owner classes defined in case_binding
        defined_classes = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
        contract_classes = {
            "CaseMarker", "CaseIdentity", "CaseAccountingMember", "CaseAccountingReceipt",
            "WorkUnitDescriptor", "AssignmentSourceReceipt", "DiscoveredTestReceipt", "TestExecutionRecord",
        }
        self.assertTrue(defined_classes.isdisjoint(contract_classes),
                        f"case_binding defines duplicate contract classes: {defined_classes & contract_classes}")


if __name__ == "__main__":
    unittest.main()
