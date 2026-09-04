"""Focused regression checks for D-WU-C0-FIX aggregate-result coherence."""
from __future__ import annotations

import dataclasses
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tests.test_work_unit_gate_contracts import (
    assignment,
    case_receipt,
    descriptor,
    finding,
    issue,
    member,
    proof,
    source_receipt,
    unit,
)
from scripts.work_unit_gate import contracts as current
from scripts.work_unit_gate import _contracts_v2 as legacy
from scripts.work_unit_gate.contracts import (
    CaseAccountingReceipt,
    CohortReceipt,
    CohortRow,
    ContractViolation,
    ExecutionDisposition,
    FindingClass,
    OverallResult,
    SourceShapeGateReceipt,
    WorkspaceAdmissionReceipt,
    WorkspaceDisposition,
    cohort_digest,
)


class ResultCoherenceRegressionTests(unittest.TestCase):
    def test_all_pass_exact_cohort_has_only_pass_result(self) -> None:
        desc = descriptor()
        row = CohortRow(issue(), unit(), desc.mode, 1, desc.sha256, desc.identity, OverallResult.PASS)
        denominator = (desc.sha256,)
        digest = cohort_digest((row,), 1, 1, denominator, proof())
        CohortReceipt((row,), OverallResult.PASS, proof(), 1, 1, digest, denominator)
        for result in (
            OverallResult.CONTRACT_FAILURE,
            OverallResult.CONFIGURATION_FAILURE,
            OverallResult.INCOMPLETE_EVIDENCE,
        ):
            with self.subTest(result=result), self.assertRaises(ContractViolation):
                CohortReceipt((row,), result, proof(), 1, 1, digest, denominator)

    def test_nonpass_row_class_determines_aggregate_class(self) -> None:
        desc = descriptor()
        passing = CohortRow(issue(), unit(), desc.mode, 1, desc.sha256, desc.identity, OverallResult.PASS)
        expectations = {
            OverallResult.CONTRACT_FAILURE: OverallResult.CONTRACT_FAILURE,
            OverallResult.CONFIGURATION_FAILURE: OverallResult.CONFIGURATION_FAILURE,
            OverallResult.INCOMPLETE_EVIDENCE: OverallResult.INCOMPLETE_EVIDENCE,
        }
        for row_result, aggregate in expectations.items():
            row = dataclasses.replace(passing, result=row_result)
            CohortReceipt((row,), aggregate, proof())
            for invalid in OverallResult:
                if invalid is aggregate:
                    continue
                with self.subTest(row=row_result, invalid=invalid), self.assertRaises(ContractViolation):
                    CohortReceipt((row,), invalid, proof())

    def test_all_pass_cohort_without_exact_denominator_is_incomplete(self) -> None:
        desc = descriptor()
        row = CohortRow(issue(), unit(), desc.mode, 1, desc.sha256, desc.identity, OverallResult.PASS)
        CohortReceipt((row,), OverallResult.INCOMPLETE_EVIDENCE, proof())
        with self.assertRaises(ContractViolation):
            CohortReceipt((row,), OverallResult.PASS, proof())

    def test_incomplete_finding_cannot_be_laundered_by_case_pass(self) -> None:
        desc = descriptor()
        incomplete = finding(FindingClass.SOURCE_UNAVAILABLE)
        receipt = case_receipt(
            desc,
            (ExecutionDisposition.EXECUTED_PASS,),
            OverallResult.INCOMPLETE_EVIDENCE,
            findings=(incomplete,),
        )
        self.assertIs(receipt.result, OverallResult.INCOMPLETE_EVIDENCE)
        with self.assertRaises(ContractViolation):
            case_receipt(
                desc,
                (ExecutionDisposition.EXECUTED_PASS,),
                OverallResult.PASS,
                findings=(incomplete,),
            )

    def test_incomplete_finding_cannot_be_laundered_by_source_or_workspace_pass(self) -> None:
        desc = descriptor()
        incomplete = finding(FindingClass.INCOMPLETE_EVIDENCE)
        SourceShapeGateReceipt(
            assignment(), desc, OverallResult.INCOMPLETE_EVIDENCE, (incomplete,), desc.proof_ceiling
        )
        WorkspaceAdmissionReceipt(
            assignment(), desc, desc.package, desc.module, WorkspaceDisposition.MEMBER,
            OverallResult.INCOMPLETE_EVIDENCE, (incomplete,), desc.proof_ceiling,
        )
        with self.assertRaises(ContractViolation):
            SourceShapeGateReceipt(assignment(), desc, OverallResult.PASS, (incomplete,), desc.proof_ceiling)
        with self.assertRaises(ContractViolation):
            WorkspaceAdmissionReceipt(
                assignment(), desc, desc.package, desc.module, WorkspaceDisposition.MEMBER,
                OverallResult.PASS, (incomplete,), desc.proof_ceiling,
            )

    def test_assignment_descriptor_denominator_is_load_bearing_everywhere(self) -> None:
        desc = descriptor(matrix_cases=2)
        wrong_assignment = assignment(1)
        with self.assertRaisesRegex(ContractViolation, "matrix denominator"):
            SourceShapeGateReceipt(wrong_assignment, desc, OverallResult.PASS, (), desc.proof_ceiling)
        with self.assertRaisesRegex(ContractViolation, "matrix denominator"):
            WorkspaceAdmissionReceipt(
                wrong_assignment, desc, desc.package, desc.module, WorkspaceDisposition.MEMBER,
                OverallResult.PASS, (), desc.proof_ceiling,
            )

    def test_current_public_receipts_do_not_resolve_to_legacy_aggregators(self) -> None:
        self.assertIs(current.CaseAccountingReceipt, CaseAccountingReceipt)
        self.assertIs(current.CohortReceipt, CohortReceipt)
        self.assertIsNot(current.CaseAccountingReceipt, legacy.CaseAccountingReceipt)
        self.assertIsNot(current.CohortReceipt, legacy.CohortReceipt)
        self.assertNotIn("_contracts_v2", current.__all__)


if __name__ == "__main__":
    unittest.main()
