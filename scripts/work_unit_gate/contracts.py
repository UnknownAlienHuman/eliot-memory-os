"""Current closed value contracts for the ELIOT work-unit gate.

The immutable identity and canonical-value layer from the merged #853 surface is
retained in :mod:`._contracts_v2`.  This module is the sole current public
facade.  It replaces the receipt aggregators whose legacy implementation did
not derive every aggregate result from its load-bearing evidence.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import _contracts_v2 as _base
from ._contracts_v2 import *  # noqa: F401,F403


def _combine_results(results: tuple[OverallResult, ...]) -> OverallResult:
    """Derive one aggregate result from exact child/evidence results."""
    if not results:
        raise ContractViolation("result evidence cannot be empty")
    for result in results:
        _base._exact_type(result, OverallResult, "result evidence")
    if OverallResult.CONFIGURATION_FAILURE in results:
        return OverallResult.CONFIGURATION_FAILURE
    if OverallResult.CONTRACT_FAILURE in results:
        return OverallResult.CONTRACT_FAILURE
    if OverallResult.INCOMPLETE_EVIDENCE in results:
        return OverallResult.INCOMPLETE_EVIDENCE
    return OverallResult.PASS


class WorkUnitDescriptor(_base.WorkUnitDescriptor):
    """Current descriptor with fail-closed mapping construction."""

    @classmethod
    def from_mapping(cls, value: object) -> "WorkUnitDescriptor":
        try:
            return _base.WorkUnitDescriptor.from_mapping.__func__(cls, value)
        except ContractViolation:
            raise
        except Exception:
            raise ContractViolation("descriptor mapping access failed") from None


def _finding_result(findings: tuple[Finding, ...]) -> OverallResult:
    """Derive the strongest exact result class from error findings."""
    results: list[OverallResult] = []
    for item in findings:
        if item.severity is not FindingSeverity.ERROR:
            continue
        if item.finding_class in {
            FindingClass.CONFIGURATION_DEFECT,
            FindingClass.INTERNAL_DEFECT,
        }:
            results.append(OverallResult.CONFIGURATION_FAILURE)
        elif item.finding_class in {
            FindingClass.SOURCE_UNAVAILABLE,
            FindingClass.INCOMPLETE_EVIDENCE,
        }:
            results.append(OverallResult.INCOMPLETE_EVIDENCE)
        else:
            results.append(OverallResult.CONTRACT_FAILURE)
    return _combine_results(tuple(results) or (OverallResult.PASS,))


def _require_assignment_descriptor(
    assignment: AssignmentSourceReceipt,
    descriptor: WorkUnitDescriptor,
    owner: str,
) -> None:
    _base._exact_type(assignment, AssignmentSourceReceipt, "assignment")
    _base._exact_type(descriptor, WorkUnitDescriptor, "descriptor")
    if assignment.issue != descriptor.issue:
        raise ContractViolation(f"{owner} issue does not match descriptor")
    if assignment.unit != descriptor.unit:
        raise ContractViolation(f"{owner} unit does not match descriptor")
    if assignment.matrix_cases != descriptor.matrix_cases:
        raise ContractViolation(f"{owner} matrix denominator does not match descriptor")


@dataclass(frozen=True)
class CaseAccountingReceipt:
    assignment: AssignmentSourceReceipt
    descriptor: WorkUnitDescriptor
    members: tuple[CaseAccountingMember, ...]
    result: OverallResult
    proof_ceiling: ProofCeiling
    findings: tuple[Finding, ...] = ()

    def __post_init__(self) -> None:
        _require_assignment_descriptor(self.assignment, self.descriptor, "case-accounting")
        _base._exact_type(self.result, OverallResult, "result")
        _base._exact_type(self.proof_ceiling, ProofCeiling, "proof_ceiling")
        if self.proof_ceiling != self.descriptor.proof_ceiling:
            raise ContractViolation("case-accounting proof ceiling does not match descriptor")

        members = _base._tuple_of_exact(
            self.members,
            CaseAccountingMember,
            "members",
            maximum=MAX_MATRIX_CASES,
        )
        ordered = tuple(sorted(members, key=lambda item: item.case.number))
        object.__setattr__(self, "members", ordered)
        findings = _base._normalize_findings(self.findings)
        object.__setattr__(self, "findings", findings)

        numbers: list[int] = []
        tests: list[TestIdentity] = []
        for member in ordered:
            if member.case.issue != self.assignment.issue:
                raise ContractViolation("member issue does not match assignment issue")
            member.case.require_within(self.assignment.matrix_cases)
            discovery = member.execution.discovery
            if discovery is None:
                raise ContractViolation("case member lost its required discovery receipt")
            if discovery.descriptor != self.descriptor.identity:
                raise ContractViolation("member discovery descriptor identity does not match")
            if discovery.descriptor_sha256 != self.descriptor.sha256:
                raise ContractViolation("member discovery descriptor digest does not match")
            numbers.append(member.case.number)
            tests.append(member.execution.test)

        if len(numbers) != len(set(numbers)):
            raise ContractViolation("duplicate case-accounting member")
        if len(tests) != len(set(tests)):
            raise ContractViolation("one test identity cannot cover multiple cases")

        expected_numbers = list(range(1, self.assignment.matrix_cases + 1))
        dispositions = [member.execution.disposition for member in ordered]
        if ExecutionDisposition.EXECUTED_FAIL in dispositions:
            execution_result = OverallResult.CONTRACT_FAILURE
        elif (
            self.assignment.state is IssueState.OPEN
            and numbers == expected_numbers
            and dispositions
            and all(item is ExecutionDisposition.EXECUTED_PASS for item in dispositions)
        ):
            execution_result = OverallResult.PASS
        else:
            execution_result = OverallResult.INCOMPLETE_EVIDENCE

        expected = _combine_results((execution_result, _finding_result(findings)))
        _base._require_result(self.result, expected, "case-accounting")


@dataclass(frozen=True)
class SourceShapeGateReceipt:
    assignment: AssignmentSourceReceipt
    descriptor: WorkUnitDescriptor
    result: OverallResult
    findings: tuple[Finding, ...]
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        _require_assignment_descriptor(self.assignment, self.descriptor, "source-shape")
        _base._exact_type(self.result, OverallResult, "result")
        _base._exact_type(self.proof_ceiling, ProofCeiling, "proof_ceiling")
        if self.proof_ceiling != self.descriptor.proof_ceiling:
            raise ContractViolation("source-shape proof ceiling does not match descriptor")
        findings = _base._normalize_findings(self.findings)
        object.__setattr__(self, "findings", findings)
        state_result = (
            OverallResult.PASS
            if self.assignment.state is IssueState.OPEN
            else OverallResult.INCOMPLETE_EVIDENCE
        )
        expected = _combine_results((state_result, _finding_result(findings)))
        _base._require_result(self.result, expected, "source-shape")


@dataclass(frozen=True)
class PackageGateReceipt:
    assignment: AssignmentSourceReceipt
    descriptor: WorkUnitDescriptor
    package: PackageIdentity
    module: ModuleIdentity | None
    source_shape: SourceShapeGateReceipt
    case_accounting: CaseAccountingReceipt
    result: OverallResult
    findings: tuple[Finding, ...]
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        _require_assignment_descriptor(self.assignment, self.descriptor, "package")
        _base._exact_type(self.package, PackageIdentity, "package")
        if self.module is not None:
            _base._exact_type(self.module, ModuleIdentity, "module")
        _base._exact_type(self.source_shape, SourceShapeGateReceipt, "source_shape")
        _base._exact_type(self.case_accounting, CaseAccountingReceipt, "case_accounting")
        _base._exact_type(self.result, OverallResult, "result")
        _base._exact_type(self.proof_ceiling, ProofCeiling, "proof_ceiling")
        if self.descriptor.package != self.package:
            raise ContractViolation("package does not match descriptor package")
        if self.descriptor.module != self.module:
            raise ContractViolation("module does not match descriptor module")
        if self.source_shape.assignment != self.assignment:
            raise ContractViolation("source-shape assignment does not match package")
        if self.case_accounting.assignment != self.assignment:
            raise ContractViolation("case assignment does not match package")
        if self.source_shape.descriptor != self.descriptor:
            raise ContractViolation("source-shape descriptor does not match package")
        if self.case_accounting.descriptor != self.descriptor:
            raise ContractViolation("case descriptor does not match package")
        if self.proof_ceiling != self.descriptor.proof_ceiling:
            raise ContractViolation("package proof ceiling does not match descriptor")
        findings = _base._normalize_findings(self.findings)
        object.__setattr__(self, "findings", findings)
        expected = _combine_results(
            (
                _finding_result(findings),
                self.source_shape.result,
                self.case_accounting.result,
            )
        )
        _base._require_result(self.result, expected, "package")


@dataclass(frozen=True)
class WorkspaceAdmissionReceipt:
    assignment: AssignmentSourceReceipt
    descriptor: WorkUnitDescriptor
    package: PackageIdentity
    module: ModuleIdentity | None
    disposition: WorkspaceDisposition
    result: OverallResult
    findings: tuple[Finding, ...]
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        _require_assignment_descriptor(self.assignment, self.descriptor, "workspace")
        _base._exact_type(self.package, PackageIdentity, "package")
        if self.module is not None:
            _base._exact_type(self.module, ModuleIdentity, "module")
        _base._exact_type(self.disposition, WorkspaceDisposition, "disposition")
        _base._exact_type(self.result, OverallResult, "result")
        _base._exact_type(self.proof_ceiling, ProofCeiling, "proof_ceiling")
        if self.descriptor.package != self.package:
            raise ContractViolation("workspace package does not match descriptor")
        if self.descriptor.module != self.module:
            raise ContractViolation("workspace module does not match descriptor")
        if self.proof_ceiling != self.descriptor.proof_ceiling:
            raise ContractViolation("workspace proof ceiling does not match descriptor")
        findings = _base._normalize_findings(self.findings)
        object.__setattr__(self, "findings", findings)
        disposition_result = {
            WorkspaceDisposition.MEMBER: OverallResult.PASS,
            WorkspaceDisposition.EXCLUDED: OverallResult.INCOMPLETE_EVIDENCE,
            WorkspaceDisposition.STANDALONE: OverallResult.INCOMPLETE_EVIDENCE,
            WorkspaceDisposition.UNAVAILABLE: OverallResult.INCOMPLETE_EVIDENCE,
            WorkspaceDisposition.CONFIGURATION_DEFECT: OverallResult.CONFIGURATION_FAILURE,
        }[self.disposition]
        expected = _combine_results((disposition_result, _finding_result(findings)))
        _base._require_result(self.result, expected, "workspace-admission")


@dataclass(frozen=True)
class ComponentGateReceipt:
    """Bounded generic summary; never a package/workspace evidence substitute."""

    component: str
    result: OverallResult
    findings: tuple[Finding, ...]
    proof_ceiling: ProofCeiling

    def __post_init__(self) -> None:
        object.__setattr__(self, "component", _base._token(self.component, "component"))
        _base._exact_type(self.result, OverallResult, "result")
        _base._exact_type(self.proof_ceiling, ProofCeiling, "proof_ceiling")
        findings = _base._normalize_findings(self.findings)
        object.__setattr__(self, "findings", findings)
        _base._require_result(self.result, _finding_result(findings), "component-summary")


@dataclass(frozen=True)
class CohortReceipt:
    rows: tuple[CohortRow, ...]
    result: OverallResult
    proof_ceiling: ProofCeiling
    expected_rows: int | None = None
    expected_matrix_cases: int | None = None
    aggregate_sha256: str | None = None
    expected_descriptor_sha256s: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _base._exact_type(self.result, OverallResult, "result")
        _base._exact_type(self.proof_ceiling, ProofCeiling, "proof_ceiling")
        rows = _base._tuple_of_exact(
            self.rows,
            CohortRow,
            "rows",
            maximum=MAX_COHORT_ROWS,
            nonempty=True,
        )
        ordered = tuple(sorted(rows, key=_base._cohort_row_key))
        object.__setattr__(self, "rows", ordered)
        if len({row.issue for row in ordered}) != len(ordered):
            raise ContractViolation("duplicate cohort issue identity")
        if len({row.unit for row in ordered}) != len(ordered):
            raise ContractViolation("duplicate cohort work-unit identity")
        if len({row.descriptor_sha256 for row in ordered}) != len(ordered):
            raise ContractViolation("duplicate cohort descriptor digest")

        if type(self.expected_descriptor_sha256s) is not tuple:
            raise ContractViolation("expected descriptor denominator must be a tuple")
        denominator = tuple(
            sorted(
                _base._sha256(value, "expected descriptor digest")
                for value in self.expected_descriptor_sha256s
            )
        )
        if len(denominator) != len(set(denominator)):
            raise ContractViolation("duplicate expected descriptor digest")
        object.__setattr__(self, "expected_descriptor_sha256s", denominator)

        if self.expected_rows is not None:
            object.__setattr__(
                self,
                "expected_rows",
                _base._positive(
                    self.expected_rows,
                    "expected_rows",
                    maximum=MAX_COHORT_ROWS,
                ),
            )
        if self.expected_matrix_cases is not None:
            object.__setattr__(
                self,
                "expected_matrix_cases",
                _base._positive(
                    self.expected_matrix_cases,
                    "expected_matrix_cases",
                    maximum=MAX_MATRIX_CASES * MAX_COHORT_ROWS,
                ),
            )
        if self.aggregate_sha256 is not None:
            object.__setattr__(
                self,
                "aggregate_sha256",
                _base._sha256(self.aggregate_sha256, "aggregate_sha256"),
            )

        denominator_flags = (
            self.expected_rows is not None,
            self.expected_matrix_cases is not None,
            self.aggregate_sha256 is not None,
            bool(denominator),
        )
        if any(denominator_flags) and not all(denominator_flags):
            raise ContractViolation(
                "cohort denominator, arithmetic, and digest must be all present or all absent"
            )
        exact_denominator = all(denominator_flags)
        actual_digests = tuple(sorted(row.descriptor_sha256 for row in ordered))
        if exact_denominator:
            assert self.expected_rows is not None
            assert self.expected_matrix_cases is not None
            assert self.aggregate_sha256 is not None
            if self.expected_rows != len(ordered):
                raise ContractViolation("cohort row denominator mismatch")
            if self.expected_matrix_cases != self.matrix_cases:
                raise ContractViolation("cohort matrix arithmetic mismatch")
            if actual_digests != denominator:
                raise ContractViolation("cohort descriptor denominator mismatch")
            calculated = cohort_digest(
                ordered,
                self.expected_rows,
                self.expected_matrix_cases,
                denominator,
                self.proof_ceiling,
            )
            if self.aggregate_sha256 != calculated:
                raise ContractViolation("cohort aggregate digest mismatch")

        row_result = _combine_results(tuple(row.result for row in ordered))
        expected = (
            OverallResult.INCOMPLETE_EVIDENCE
            if row_result is OverallResult.PASS and not exact_denominator
            else row_result
        )
        if self.result is OverallResult.PASS and row_result is not OverallResult.PASS:
            raise ContractViolation("passing cohort requires every row to pass")
        if self.result is OverallResult.PASS and not exact_denominator:
            raise ContractViolation(
                "passing cohort requires exact denominator, arithmetic, and digest"
            )
        _base._require_result(self.result, expected, "cohort")

    @property
    def matrix_cases(self) -> int:
        return sum(row.matrix_cases for row in self.rows)


__all__ = list(_base.__all__)
