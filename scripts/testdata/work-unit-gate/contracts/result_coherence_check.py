"""Preserved aggregate-coherence regressions, using explicit v4 evidence.

The ten original regressions remain. Constructor migration supplies current
assignment/phase bindings; legacy summaries cannot be promoted into executions.
"""
from __future__ import annotations

import dataclasses
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tests.test_work_unit_gate_contracts import (
    assignment, cases, catalogue, cohort, descriptor, evidence, finding,
    plan, row, shape, workspace, PROOF,
)
from scripts.work_unit_gate import contracts as current
from scripts.work_unit_gate import _contracts_v2 as legacy


class ResultCoherenceRegressionTests(unittest.TestCase):
    def test_all_pass_exact_cohort_has_only_pass_result(self):
        desc = descriptor()
        selected, rows = plan(desc), (evidence(desc),)
        cohort(selected, rows)
        for result in current.OverallResult:
            if result is not current.OverallResult.PASS:
                with self.subTest(result=result), self.assertRaises(current.ContractViolation):
                    cohort(selected, rows, result)

    def test_nonpass_row_class_determines_aggregate_class(self):
        desc = descriptor()
        classes = {
            current.OverallResult.CONTRACT_FAILURE: current.FindingClass.CONTRACT_DEFECT,
            current.OverallResult.CONFIGURATION_FAILURE: current.FindingClass.CONFIGURATION_DEFECT,
            current.OverallResult.INCOMPLETE_EVIDENCE: current.FindingClass.SOURCE_UNAVAILABLE,
        }
        for result, kind in classes.items():
            source = shape(desc, result=result, findings=(finding(kind),))
            rows = (evidence(desc, source=source, package_result=result),)
            cohort(plan(desc), rows, result)
            for invalid in current.OverallResult:
                if invalid is not result:
                    with self.subTest(expected=result, supplied=invalid), self.assertRaises(current.ContractViolation):
                        cohort(plan(desc), rows, invalid)

    def test_all_pass_cohort_without_exact_denominator_is_incomplete(self):
        # v4 requires an explicit selected plan. Missing selected results remain
        # incomplete even when every supplied execution passed.
        a, b = descriptor(), descriptor(858)
        selected, rows = plan(a, b), (evidence(a),)
        receipt = cohort(selected, rows, current.OverallResult.INCOMPLETE_EVIDENCE)
        self.assertEqual((1, 2), (receipt.matrix_cases, receipt.expected_matrix_cases))
        with self.assertRaises(current.ContractViolation):
            cohort(selected, rows)
        with self.assertRaises(current.ContractViolation):
            dataclasses.replace(receipt, plan=None)

    def test_incomplete_finding_cannot_be_laundered_by_case_pass(self):
        desc = descriptor()
        incomplete = finding(current.FindingClass.SOURCE_UNAVAILABLE)
        receipt = cases(desc, result=current.OverallResult.INCOMPLETE_EVIDENCE, findings=(incomplete,))
        self.assertIs(receipt.result, current.OverallResult.INCOMPLETE_EVIDENCE)
        with self.assertRaises(current.ContractViolation):
            cases(desc, findings=(incomplete,))

    def test_incomplete_finding_cannot_be_laundered_by_source_or_workspace_pass(self):
        desc = descriptor()
        incomplete = (finding(current.FindingClass.INCOMPLETE_EVIDENCE),)
        for constructor in (shape, workspace):
            constructor(desc, result=current.OverallResult.INCOMPLETE_EVIDENCE, findings=incomplete)
            with self.assertRaises(current.ContractViolation):
                constructor(desc, findings=incomplete)

    def test_assignment_descriptor_denominator_is_load_bearing_everywhere(self):
        desc = descriptor(count=2)
        wrong = assignment(descriptor())
        for constructor in (shape, workspace):
            with self.assertRaises(current.ContractViolation):
                constructor(desc, assignment=wrong)

    def test_mixed_contract_and_incomplete_findings_cannot_hide_contract_failure(self):
        mixed = (finding(current.FindingClass.SOURCE_UNAVAILABLE), finding(current.FindingClass.CONTRACT_DEFECT))
        desc = descriptor()
        receipt = shape(desc, result=current.OverallResult.CONTRACT_FAILURE, findings=mixed)
        self.assertIs(receipt.result, current.OverallResult.CONTRACT_FAILURE)
        with self.assertRaises(current.ContractViolation):
            shape(desc, result=current.OverallResult.INCOMPLETE_EVIDENCE, findings=mixed)

    def test_generic_component_uses_same_mixed_finding_priority(self):
        mixed = (finding(current.FindingClass.SOURCE_UNAVAILABLE), finding(current.FindingClass.CONTRACT_DEFECT))
        current.ComponentGateReceipt("component", current.OverallResult.CONTRACT_FAILURE, mixed, PROOF)
        with self.assertRaises(current.ContractViolation):
            current.ComponentGateReceipt("component", current.OverallResult.INCOMPLETE_EVIDENCE, mixed, PROOF)

    def test_descriptor_mapping_failures_are_closed_and_redacted(self):
        class BrokenMapping(dict):
            def __iter__(self):
                raise RuntimeError("SECRET_CANARY_FROM_MAPPING")
        with self.assertRaises(current.ContractViolation) as captured:
            current.WorkUnitDescriptor.from_mapping(BrokenMapping())
        self.assertEqual("descriptor input must be an exact dictionary", str(captured.exception))
        self.assertIsNone(captured.exception.__cause__)
        self.assertNotIn("SECRET_CANARY", str(captured.exception))

    def test_current_public_receipts_do_not_resolve_to_legacy_aggregators(self):
        for name in ("CaseAccountingReceipt", "CohortReceipt", "ComponentGateReceipt"):
            self.assertIsNot(getattr(current, name), getattr(legacy, name))
        self.assertIs(current.CohortRow, current.VerificationEvidence)
        self.assertNotIn("_contracts_v2", current.__all__)


if __name__ == "__main__":
    unittest.main()
