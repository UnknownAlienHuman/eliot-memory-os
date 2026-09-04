from __future__ import annotations

import ast
import dataclasses
import unittest
from pathlib import Path

from scripts.work_unit_gate.contracts import (
    AssignmentRelation,
    AssignmentSourceReceipt,
    BoundedDiagnostic,
    CaseAccountingMember,
    CaseAccountingReceipt,
    CaseIdentity,
    CaseMarker,
    CohortReceipt,
    CohortRow,
    ContractViolation,
    ExecutionDisposition,
    Finding,
    FindingClass,
    FindingSeverity,
    IssueIdentity,
    IssueState,
    MAX_DIAGNOSTIC_BYTES,
    MAX_DIAGNOSTIC_FIELDS,
    ModuleIdentity,
    OverallResult,
    PackageIdentity,
    ProofCeiling,
    PullRequestIdentity,
    RelationRole,
    RemediationCode,
    RepositoryIdentity,
    RepositoryPath,
    RunnerMode,
    SourceAuthority,
    SourceLocation,
    TestExecutionRecord,
    TestIdentity,
    WorkUnitIdentity,
    canonical_bytes,
    canonical_sha256,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_SOURCE = ROOT / "scripts" / "work_unit_gate" / "contracts.py"


def repository() -> RepositoryIdentity:
    return RepositoryIdentity("UnknownAlienHuman", "eliot-memory-os")


def issue(number: int = 848) -> IssueIdentity:
    return IssueIdentity(repository(), number)


def proof() -> ProofCeiling:
    return ProofCeiling("work-unit-contract-only")


def assignment(
    matrix_cases: int = 1,
    *,
    authority: SourceAuthority = SourceAuthority.LIVE_GITHUB,
) -> AssignmentSourceReceipt:
    kwargs: dict[str, str] = {}
    if authority is SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT:
        kwargs["snapshot_sha256"] = "b" * 64
    else:
        kwargs["live_etag"] = 'W/"issue-848"'
    return AssignmentSourceReceipt(
        issue=issue(),
        state=IssueState.OPEN,
        unit=WorkUnitIdentity("D-WU-C0"),
        authority=authority,
        title="Closed work-unit contracts",
        body_sha256="a" * 64,
        matrix_cases=matrix_cases,
        proof_ceiling=proof(),
        **kwargs,
    )


def member(
    number: int,
    disposition: ExecutionDisposition = ExecutionDisposition.EXECUTED_PASS,
    *,
    name: str | None = None,
) -> CaseAccountingMember:
    case = CaseIdentity(issue(), number)
    test = TestIdentity(
        RunnerMode.PYTHON_UNITTEST,
        name or f"tests.ContractTests.test_case_{number}",
    )
    marker = CaseMarker(
        case,
        test,
        SourceLocation(RepositoryPath("scripts/tests/test_contracts.py"), number),
    )
    execution = TestExecutionRecord(test, disposition)
    return CaseAccountingMember(case, marker, execution)


class ContractTests(unittest.TestCase):
    # WORK_UNIT_CASE: 848/1
    def test_identity_types_are_not_interchangeable(self) -> None:
        pr = PullRequestIdentity(repository(), 853)
        with self.assertRaises(ContractViolation):
            AssignmentRelation(pr, RelationRole.IMPLEMENTS, issue())  # type: ignore[arg-type]
        self.assertNotEqual(PackageIdentity("eliot-cli"), ModuleIdentity("eliot-cli"))

    # WORK_UNIT_CASE: 848/2
    def test_source_authority_vocabulary_is_exact(self) -> None:
        self.assertEqual(
            {"live-github", "explicit-offline-snapshot"},
            {item.value for item in SourceAuthority},
        )

    # WORK_UNIT_CASE: 848/3
    def test_relation_role_vocabulary_is_exact(self) -> None:
        self.assertEqual(
            {"implements", "verified-by", "integrated-by", "blocked-by", "supersedes"},
            {item.value for item in RelationRole},
        )

    # WORK_UNIT_CASE: 848/4
    def test_runner_mode_vocabulary_is_exact(self) -> None:
        self.assertEqual(
            {"rust-package", "python-unittest", "metadata-python"},
            {item.value for item in RunnerMode},
        )

    # WORK_UNIT_CASE: 848/5
    def test_execution_disposition_vocabulary_is_exact(self) -> None:
        self.assertEqual(
            {
                "discovered",
                "executed-pass",
                "executed-fail",
                "skipped",
                "ignored",
                "cfg-disabled",
                "timed-out",
                "unavailable",
            },
            {item.value for item in ExecutionDisposition},
        )

    # WORK_UNIT_CASE: 848/6
    def test_discovered_is_not_executed_pass(self) -> None:
        with self.assertRaisesRegex(ContractViolation, "execute successfully"):
            CaseAccountingReceipt(
                assignment(),
                (member(1, ExecutionDisposition.DISCOVERED),),
                OverallResult.PASS,
                proof(),
            )

    # WORK_UNIT_CASE: 848/7
    def test_skipped_is_not_pass(self) -> None:
        with self.assertRaises(ContractViolation):
            CaseAccountingReceipt(
                assignment(),
                (member(1, ExecutionDisposition.SKIPPED),),
                OverallResult.PASS,
                proof(),
            )

    # WORK_UNIT_CASE: 848/8
    def test_ignored_is_not_pass(self) -> None:
        with self.assertRaises(ContractViolation):
            CaseAccountingReceipt(
                assignment(),
                (member(1, ExecutionDisposition.IGNORED),),
                OverallResult.PASS,
                proof(),
            )

    # WORK_UNIT_CASE: 848/9
    def test_cfg_disabled_is_not_pass(self) -> None:
        with self.assertRaises(ContractViolation):
            CaseAccountingReceipt(
                assignment(),
                (member(1, ExecutionDisposition.CFG_DISABLED),),
                OverallResult.PASS,
                proof(),
            )

    # WORK_UNIT_CASE: 848/10
    def test_timeout_is_not_pass(self) -> None:
        with self.assertRaises(ContractViolation):
            CaseAccountingReceipt(
                assignment(),
                (member(1, ExecutionDisposition.TIMED_OUT),),
                OverallResult.PASS,
                proof(),
            )

    # WORK_UNIT_CASE: 848/11
    def test_live_and_offline_receipts_cannot_be_combined(self) -> None:
        with self.assertRaisesRegex(ContractViolation, "live source"):
            AssignmentSourceReceipt(
                issue(),
                IssueState.OPEN,
                WorkUnitIdentity("D-WU-C0"),
                SourceAuthority.LIVE_GITHUB,
                "title",
                "a" * 64,
                1,
                proof(),
                None,
                "b" * 64,
            )
        with self.assertRaisesRegex(ContractViolation, "live ETag"):
            AssignmentSourceReceipt(
                issue(),
                IssueState.OPEN,
                WorkUnitIdentity("D-WU-C0"),
                SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT,
                "title",
                "a" * 64,
                1,
                proof(),
                "etag",
                "b" * 64,
            )

    # WORK_UNIT_CASE: 848/12
    def test_assignment_denominator_must_be_positive_and_finite(self) -> None:
        with self.assertRaises(ContractViolation):
            assignment(0)
        with self.assertRaises(ContractViolation):
            assignment(100_001)
        with self.assertRaises(ContractViolation):
            assignment(True)  # type: ignore[arg-type]

    # WORK_UNIT_CASE: 848/13
    def test_case_identity_must_be_positive_and_in_range(self) -> None:
        with self.assertRaises(ContractViolation):
            CaseIdentity(issue(), 0)
        valid = CaseIdentity(issue(), 2)
        with self.assertRaisesRegex(ContractViolation, "exceeds"):
            valid.require_within(1)

    # WORK_UNIT_CASE: 848/14
    def test_duplicate_case_member_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractViolation, "duplicate case"):
            CaseAccountingReceipt(
                assignment(2),
                (
                    member(1, name="tests.Cases.test_a"),
                    member(1, name="tests.Cases.test_b"),
                ),
                OverallResult.CONTRACT_FAILURE,
                proof(),
            )

    # WORK_UNIT_CASE: 848/15
    def test_missing_denominator_member_prevents_pass(self) -> None:
        with self.assertRaisesRegex(ContractViolation, "complete exact"):
            CaseAccountingReceipt(
                assignment(2),
                (member(1),),
                OverallResult.PASS,
                proof(),
            )

    # WORK_UNIT_CASE: 848/16
    def test_aggregate_extra_tests_cannot_fill_missing_case(self) -> None:
        unrelated = TestExecutionRecord(
            TestIdentity(RunnerMode.PYTHON_UNITTEST, "tests.Other.test_padding"),
            ExecutionDisposition.EXECUTED_PASS,
        )
        self.assertEqual(ExecutionDisposition.EXECUTED_PASS, unrelated.disposition)
        with self.assertRaises(ContractViolation):
            CaseAccountingReceipt(
                assignment(2),
                (member(1),),
                OverallResult.PASS,
                proof(),
            )

    # WORK_UNIT_CASE: 848/17
    def test_issue_number_does_not_encode_relation_role(self) -> None:
        source, target = issue(848), issue(837)
        verified = AssignmentRelation(source, RelationRole.VERIFIED_BY, target)
        integrated = AssignmentRelation(source, RelationRole.INTEGRATED_BY, target)
        self.assertNotEqual(verified, integrated)
        self.assertNotEqual(canonical_sha256(verified), canonical_sha256(integrated))

    # WORK_UNIT_CASE: 848/18
    def test_configuration_and_contract_failures_are_distinct(self) -> None:
        self.assertIsNot(
            OverallResult.CONFIGURATION_FAILURE,
            OverallResult.CONTRACT_FAILURE,
        )
        self.assertNotEqual(
            OverallResult.CONFIGURATION_FAILURE.value,
            OverallResult.CONTRACT_FAILURE.value,
        )

    # WORK_UNIT_CASE: 848/19
    def test_incomplete_evidence_is_not_pass_or_fail(self) -> None:
        self.assertNotIn(
            OverallResult.INCOMPLETE_EVIDENCE,
            {OverallResult.PASS, OverallResult.CONTRACT_FAILURE},
        )

    # WORK_UNIT_CASE: 848/20
    def test_finding_requires_owner_and_remediation(self) -> None:
        finding = Finding(
            FindingSeverity.ERROR,
            FindingClass.INVALID_IDENTITY,
            WorkUnitIdentity("D-WU-C0"),
            RemediationCode("FIX_IDENTITY"),
            "issue and descriptor identities disagree",
        )
        self.assertEqual("D-WU-C0", finding.owner.value)
        with self.assertRaises(ContractViolation):
            RemediationCode("fix it")
        with self.assertRaises(ContractViolation):
            Finding(
                FindingSeverity.ERROR,
                FindingClass.INVALID_IDENTITY,
                WorkUnitIdentity(" "),
                RemediationCode("FIX_IDENTITY"),
                "message",
            )

    # WORK_UNIT_CASE: 848/21
    def test_diagnostic_bounds_reject_one_over(self) -> None:
        BoundedDiagnostic("x" * MAX_DIAGNOSTIC_BYTES)
        with self.assertRaises(ContractViolation):
            BoundedDiagnostic("x" * (MAX_DIAGNOSTIC_BYTES + 1))
        fields = tuple(
            (f"field-{index}", "value")
            for index in range(MAX_DIAGNOSTIC_FIELDS)
        )
        BoundedDiagnostic("summary", fields)
        with self.assertRaises(ContractViolation):
            BoundedDiagnostic("summary", fields + (("extra", "value"),))

    # WORK_UNIT_CASE: 848/22
    def test_canonical_bytes_are_stable_under_set_and_mapping_permutation(self) -> None:
        left = {
            "roles": frozenset({"verified-by", "blocked-by"}),
            "counts": {"b": 2, "a": 1},
        }
        right = {
            "counts": {"a": 1, "b": 2},
            "roles": frozenset({"blocked-by", "verified-by"}),
        }
        self.assertEqual(canonical_bytes(left), canonical_bytes(right))
        self.assertEqual(canonical_sha256(left), canonical_sha256(right))

    # WORK_UNIT_CASE: 848/23
    def test_load_bearing_change_changes_digest(self) -> None:
        base = CohortReceipt(
            (
                CohortRow(
                    issue(848),
                    WorkUnitIdentity("D-WU-C0"),
                    RunnerMode.PYTHON_UNITTEST,
                    24,
                    "c" * 64,
                ),
            ),
            OverallResult.PASS,
            proof(),
        )
        changed = CohortReceipt(
            (
                CohortRow(
                    issue(848),
                    WorkUnitIdentity("D-WU-C0"),
                    RunnerMode.PYTHON_UNITTEST,
                    25,
                    "c" * 64,
                ),
            ),
            OverallResult.PASS,
            proof(),
        )
        self.assertNotEqual(canonical_sha256(base), canonical_sha256(changed))

    # WORK_UNIT_CASE: 848/24
    def test_contract_module_has_no_io_process_mutation_or_arbitrary_command_surface(self) -> None:
        source = CONTRACTS_SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden_import_roots = {
            "asyncio",
            "http",
            "os",
            "pathlib.Path",
            "requests",
            "shutil",
            "socket",
            "subprocess",
            "urllib",
        }
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        self.assertTrue(imported.isdisjoint(forbidden_import_roots), imported)

        forbidden_field_names = {
            "argv",
            "command",
            "credentials",
            "environment",
            "executable",
            "secret",
            "shell",
            "token",
            "url",
        }
        declared_fields = {
            field.name
            for value in vars(
                __import__("scripts.work_unit_gate.contracts", fromlist=["*"])
            ).values()
            if dataclasses.is_dataclass(value)
            for field in dataclasses.fields(value)
        }
        self.assertTrue(
            declared_fields.isdisjoint(forbidden_field_names),
            declared_fields,
        )
        for token in (
            "urlopen(",
            "subprocess.run(",
            ".write_text(",
            ".unlink(",
            "os.environ",
        ):
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
