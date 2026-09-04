from __future__ import annotations
import ast
import dataclasses
import importlib
import unittest
from pathlib import Path
from scripts.work_unit_gate.contracts import AssignmentRelation, AssignmentSourceReceipt, BoundedDiagnostic, CONTRACT_SCHEMA_REVISION, CaseAccountingMember, CaseAccountingReceipt, CaseIdentity, CaseMarker, CohortReceipt, CohortRow, ComponentGateReceipt, ContractViolation, DescriptorIdentity, DiscoveredTestReceipt, ExecutionDisposition, Finding, FindingClass, FindingSeverity, IssueIdentity, IssueState, ModuleIdentity, OverallResult, PackageGateReceipt, PackageIdentity, ProofCeiling, PullRequestIdentity, RELATION_ROLE_WIRE_REVISION, RelationRole, RemediationCode, RepositoryIdentity, RepositoryPath, RunnerMode, SourceAuthority, SourceLocation, SourceShapeGateReceipt, TestExecutionRecord, TestIdentity, WORK_UNIT_DESCRIPTOR_SCHEMA, WorkUnitDescriptor, WorkUnitIdentity, WorkspaceAdmissionReceipt, WorkspaceDisposition, canonical_bytes, canonical_sha256, cohort_digest
ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_SOURCE = ROOT / 'scripts' / 'work_unit_gate' / 'contracts.py'

def repository() -> RepositoryIdentity:
    return RepositoryIdentity('UnknownAlienHuman', 'eliot-memory-os')

def issue(number: int=857) -> IssueIdentity:
    return IssueIdentity(repository(), number)

def unit() -> WorkUnitIdentity:
    return WorkUnitIdentity('D-WU-C0-FIX')

def proof(value: str='work-unit-contract-only') -> ProofCeiling:
    return ProofCeiling(value)

def descriptor(*, matrix_cases: int=1, identity: str='work-unit-857', proof_value: str='work-unit-contract-only', source_roots: tuple[RepositoryPath, ...] | None=None, test_roots: tuple[RepositoryPath, ...] | None=None) -> WorkUnitDescriptor:
    return WorkUnitDescriptor(schema_version=WORK_UNIT_DESCRIPTOR_SCHEMA, identity=DescriptorIdentity(identity), issue=issue(), unit=unit(), mode=RunnerMode.PYTHON_UNITTEST, source_roots=(RepositoryPath('scripts/work_unit_gate/contracts.py'),) if source_roots is None else source_roots, test_roots=(RepositoryPath('scripts/tests/test_work_unit_gate_contracts.py'),) if test_roots is None else test_roots, matrix_cases=matrix_cases, proof_ceiling=proof(proof_value), package=PackageIdentity('work-unit-gate'), module=ModuleIdentity('scripts.work_unit_gate.contracts'))

def assignment(matrix_cases: int=1) -> AssignmentSourceReceipt:
    return AssignmentSourceReceipt(issue=issue(), state=IssueState.OPEN, unit=unit(), authority=SourceAuthority.LIVE_GITHUB, title='Complete missing work-unit contracts', body_sha256='a' * 64, matrix_cases=matrix_cases, proof_ceiling=ProofCeiling('assignment-source-only'), live_etag='W/"857"')

def finding(finding_class: FindingClass, *, severity: FindingSeverity=FindingSeverity.ERROR) -> Finding:
    return Finding(severity=severity, finding_class=finding_class, owner=unit(), remediation=RemediationCode('FIX_CONTRACT'), message='deterministic fixture finding')

def member(number: int, desc: WorkUnitDescriptor, disposition: ExecutionDisposition=ExecutionDisposition.EXECUTED_PASS, *, test_name: str | None=None) -> CaseAccountingMember:
    test = TestIdentity(desc.mode, test_name or f'scripts.tests.ContractTests.test_case_{number}')
    location = SourceLocation(desc.test_roots[0], number)
    case = CaseIdentity(desc.issue, number)
    marker = CaseMarker(case, test, location)
    discovery = DiscoveredTestReceipt(descriptor=desc.identity, descriptor_sha256=desc.sha256, test=test, location=location)
    execution = TestExecutionRecord(test=test, disposition=disposition, discovery=discovery)
    return CaseAccountingMember(case, marker, execution)

def case_receipt(desc: WorkUnitDescriptor, dispositions: tuple[ExecutionDisposition, ...], result: OverallResult, *, findings: tuple[Finding, ...]=()) -> CaseAccountingReceipt:
    return CaseAccountingReceipt(assignment=assignment(desc.matrix_cases), descriptor=desc, members=tuple((member(index, desc, disposition) for index, disposition in enumerate(dispositions, start=1))), result=result, proof_ceiling=desc.proof_ceiling, findings=findings)

def source_receipt(desc: WorkUnitDescriptor, result: OverallResult=OverallResult.PASS, *, findings: tuple[Finding, ...]=()) -> SourceShapeGateReceipt:
    return SourceShapeGateReceipt(assignment=assignment(desc.matrix_cases), descriptor=desc, result=result, findings=findings, proof_ceiling=desc.proof_ceiling)

def package_receipt(desc: WorkUnitDescriptor) -> PackageGateReceipt:
    source = source_receipt(desc)
    cases = case_receipt(desc, tuple((ExecutionDisposition.EXECUTED_PASS for _ in range(desc.matrix_cases))), OverallResult.PASS)
    return PackageGateReceipt(assignment=assignment(desc.matrix_cases), descriptor=desc, package=desc.package, module=desc.module, source_shape=source, case_accounting=cases, result=OverallResult.PASS, findings=(), proof_ceiling=desc.proof_ceiling)

class ContractClosureTests(unittest.TestCase):

    # WORK_UNIT_CASE: 857/1
    def test_descriptor_identity_and_schema_round_trip(self) -> None:
        desc = descriptor()
        self.assertEqual(WORK_UNIT_DESCRIPTOR_SCHEMA, desc.schema_version)
        self.assertEqual(desc, WorkUnitDescriptor.from_mapping(dataclasses.asdict(desc) | {'identity': desc.identity, 'issue': desc.issue, 'unit': desc.unit, 'mode': desc.mode, 'source_roots': desc.source_roots, 'test_roots': desc.test_roots, 'proof_ceiling': desc.proof_ceiling, 'package': desc.package, 'module': desc.module}))
        self.assertEqual(64, len(desc.sha256))

    # WORK_UNIT_CASE: 857/2
    def test_descriptor_keeps_owner_identity_types_distinct(self) -> None:
        desc = descriptor()
        self.assertIs(type(desc.issue), IssueIdentity)
        self.assertIs(type(desc.unit), WorkUnitIdentity)
        self.assertIs(type(desc.package), PackageIdentity)
        self.assertIs(type(desc.module), ModuleIdentity)
        with self.assertRaises(ContractViolation):
            WorkUnitDescriptor(WORK_UNIT_DESCRIPTOR_SCHEMA, DescriptorIdentity('wrong-owner'), PullRequestIdentity(repository(), 858), unit(), RunnerMode.PYTHON_UNITTEST, desc.source_roots, desc.test_roots, 1, proof())

    # WORK_UNIT_CASE: 857/3
    def test_source_roots_are_nonempty_unique_and_canonical(self) -> None:
        first = RepositoryPath('scripts/a.py')
        second = RepositoryPath('scripts/b.py')
        desc = descriptor(source_roots=(second, first))
        self.assertEqual((first, second), desc.source_roots)
        with self.assertRaisesRegex(ContractViolation, 'cannot be empty'):
            descriptor(source_roots=())
        with self.assertRaisesRegex(ContractViolation, 'duplicate source'):
            descriptor(source_roots=(first, first))

    # WORK_UNIT_CASE: 857/4
    def test_test_roots_are_nonempty_unique_and_canonical(self) -> None:
        first = RepositoryPath('scripts/tests/a.py')
        second = RepositoryPath('scripts/tests/b.py')
        desc = descriptor(test_roots=(second, first))
        self.assertEqual((first, second), desc.test_roots)
        with self.assertRaisesRegex(ContractViolation, 'cannot be empty'):
            descriptor(test_roots=())
        with self.assertRaisesRegex(ContractViolation, 'duplicate test'):
            descriptor(test_roots=(first, first))

    # WORK_UNIT_CASE: 857/5
    def test_descriptor_denominator_and_proof_ceiling_change_digest(self) -> None:
        base = descriptor(matrix_cases=1)
        count_changed = descriptor(matrix_cases=2)
        proof_changed = descriptor(proof_value='narrower-proof')
        self.assertNotEqual(base.sha256, count_changed.sha256)
        self.assertNotEqual(base.sha256, proof_changed.sha256)

    # WORK_UNIT_CASE: 857/6
    def test_arbitrary_execution_fields_are_rejected_by_closed_descriptor(self) -> None:
        desc = descriptor()
        payload = {field.name: getattr(desc, field.name) for field in dataclasses.fields(desc)}
        for forbidden in ('command', 'argv', 'executable', 'shell', 'url', 'environment', 'secret'):
            with self.subTest(forbidden=forbidden):
                with self.assertRaisesRegex(ContractViolation, 'unknown'):
                    WorkUnitDescriptor.from_mapping(payload | {forbidden: 'x'})

    # WORK_UNIT_CASE: 857/7
    def test_discovery_binds_descriptor_mode_test_and_location(self) -> None:
        desc = descriptor()
        item = member(1, desc)
        discovery = item.execution.discovery
        self.assertIsNotNone(discovery)
        assert discovery is not None
        self.assertEqual(desc.identity, discovery.descriptor)
        self.assertEqual(desc.sha256, discovery.descriptor_sha256)
        self.assertEqual(desc.mode, discovery.test.mode)
        self.assertEqual(item.marker.location, discovery.location)

    # WORK_UNIT_CASE: 857/8
    def test_execution_without_matching_discovery_is_rejected(self) -> None:
        desc = descriptor()
        first = member(1, desc)
        other = TestIdentity(desc.mode, 'tests.Other.test_identity')
        with self.assertRaisesRegex(ContractViolation, 'does not match'):
            TestExecutionRecord(other, ExecutionDisposition.EXECUTED_PASS, discovery=first.execution.discovery)
        with self.assertRaisesRegex(ContractViolation, 'requires an exact discovery'):
            CaseAccountingMember(first.case, first.marker, TestExecutionRecord(first.marker.test, ExecutionDisposition.EXECUTED_PASS))

    # WORK_UNIT_CASE: 857/9
    def test_discovery_and_executed_pass_are_distinct_and_digest_distinct(self) -> None:
        desc = descriptor()
        item = member(1, desc)
        discovery_only = TestExecutionRecord(item.execution.test, ExecutionDisposition.DISCOVERED, discovery=item.execution.discovery)
        self.assertIsNot(discovery_only.disposition, item.execution.disposition)
        self.assertNotEqual(canonical_sha256(discovery_only), canonical_sha256(item.execution))

    # WORK_UNIT_CASE: 857/10
    def test_case_marker_reconciles_to_one_discovery_and_execution(self) -> None:
        desc = descriptor()
        item = member(1, desc)
        receipt = CaseAccountingReceipt(assignment(1), desc, (item,), OverallResult.PASS, desc.proof_ceiling)
        self.assertEqual(item.marker.test, receipt.members[0].execution.test)
        self.assertEqual(item.marker.location, receipt.members[0].execution.discovery.location)

    # WORK_UNIT_CASE: 857/11
    def test_complete_all_pass_denominator_yields_pass(self) -> None:
        desc = descriptor(matrix_cases=3)
        receipt = case_receipt(desc, (ExecutionDisposition.EXECUTED_PASS, ExecutionDisposition.EXECUTED_PASS, ExecutionDisposition.EXECUTED_PASS), OverallResult.PASS)
        self.assertIs(receipt.result, OverallResult.PASS)

    # WORK_UNIT_CASE: 857/12
    def test_all_pass_evidence_cannot_claim_any_nonpass_result(self) -> None:
        desc = descriptor()
        for result in (OverallResult.CONTRACT_FAILURE, OverallResult.CONFIGURATION_FAILURE, OverallResult.INCOMPLETE_EVIDENCE):
            with self.subTest(result=result):
                with self.assertRaisesRegex(ContractViolation, 'contradicts'):
                    case_receipt(desc, (ExecutionDisposition.EXECUTED_PASS,), result)

    # WORK_UNIT_CASE: 857/13
    def test_executed_failure_requires_contract_failure(self) -> None:
        desc = descriptor()
        receipt = case_receipt(desc, (ExecutionDisposition.EXECUTED_FAIL,), OverallResult.CONTRACT_FAILURE)
        self.assertIs(receipt.result, OverallResult.CONTRACT_FAILURE)
        for invalid in (OverallResult.PASS, OverallResult.INCOMPLETE_EVIDENCE):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ContractViolation):
                    case_receipt(desc, (ExecutionDisposition.EXECUTED_FAIL,), invalid)

    # WORK_UNIT_CASE: 857/14
    def test_skipped_ignored_and_cfg_disabled_are_incomplete_nonpass(self) -> None:
        desc = descriptor()
        for disposition in (ExecutionDisposition.SKIPPED, ExecutionDisposition.IGNORED, ExecutionDisposition.CFG_DISABLED):
            with self.subTest(disposition=disposition):
                receipt = case_receipt(desc, (disposition,), OverallResult.INCOMPLETE_EVIDENCE)
                self.assertIs(receipt.result, OverallResult.INCOMPLETE_EVIDENCE)

    # WORK_UNIT_CASE: 857/15
    def test_timeout_and_unavailable_remain_explicit_nonpass(self) -> None:
        desc = descriptor()
        for disposition in (ExecutionDisposition.TIMED_OUT, ExecutionDisposition.UNAVAILABLE):
            with self.subTest(disposition=disposition):
                receipt = case_receipt(desc, (disposition,), OverallResult.INCOMPLETE_EVIDENCE)
                self.assertIs(disposition, receipt.members[0].execution.disposition)

    # WORK_UNIT_CASE: 857/16
    def test_configuration_failure_requires_configuration_evidence(self) -> None:
        desc = descriptor()
        with self.assertRaises(ContractViolation):
            case_receipt(desc, (ExecutionDisposition.EXECUTED_FAIL,), OverallResult.CONFIGURATION_FAILURE)
        receipt = case_receipt(desc, (ExecutionDisposition.EXECUTED_PASS,), OverallResult.CONFIGURATION_FAILURE, findings=(finding(FindingClass.CONFIGURATION_DEFECT),))
        self.assertIs(receipt.result, OverallResult.CONFIGURATION_FAILURE)

    # WORK_UNIT_CASE: 857/17
    def test_source_shape_receipt_binds_exact_owner_descriptor_and_assignment(self) -> None:
        desc = descriptor()
        receipt = source_receipt(desc)
        self.assertEqual(desc, receipt.descriptor)
        self.assertEqual(desc.issue, receipt.assignment.issue)
        self.assertEqual(desc.unit, receipt.assignment.unit)
        with self.assertRaises(ContractViolation):
            SourceShapeGateReceipt(assignment(), descriptor(identity='other'), OverallResult.CONTRACT_FAILURE, (finding(FindingClass.CONTRACT_DEFECT),), ProofCeiling('wrong-proof'))

    # WORK_UNIT_CASE: 857/18
    def test_package_receipt_binds_package_module_descriptor_and_assignment(self) -> None:
        desc = descriptor()
        receipt = package_receipt(desc)
        self.assertEqual(desc.package, receipt.package)
        self.assertEqual(desc.module, receipt.module)
        self.assertEqual(desc, receipt.case_accounting.descriptor)
        with self.assertRaisesRegex(ContractViolation, 'package does not match'):
            PackageGateReceipt(receipt.assignment, desc, PackageIdentity('wrong-package'), desc.module, receipt.source_shape, receipt.case_accounting, OverallResult.PASS, (), desc.proof_ceiling)

    # WORK_UNIT_CASE: 857/19
    def test_package_pass_does_not_imply_workspace_admission(self) -> None:
        desc = descriptor()
        package = package_receipt(desc)
        excluded = WorkspaceAdmissionReceipt(assignment(desc.matrix_cases), desc, desc.package, desc.module, WorkspaceDisposition.EXCLUDED, OverallResult.INCOMPLETE_EVIDENCE, (), desc.proof_ceiling)
        self.assertIs(package.result, OverallResult.PASS)
        self.assertIs(excluded.result, OverallResult.INCOMPLETE_EVIDENCE)

    # WORK_UNIT_CASE: 857/20
    def test_workspace_dispositions_remain_distinct(self) -> None:
        desc = descriptor()
        expectations = {WorkspaceDisposition.MEMBER: OverallResult.PASS, WorkspaceDisposition.EXCLUDED: OverallResult.INCOMPLETE_EVIDENCE, WorkspaceDisposition.STANDALONE: OverallResult.INCOMPLETE_EVIDENCE, WorkspaceDisposition.UNAVAILABLE: OverallResult.INCOMPLETE_EVIDENCE, WorkspaceDisposition.CONFIGURATION_DEFECT: OverallResult.CONFIGURATION_FAILURE}
        observed = {}
        for disposition, result in expectations.items():
            receipt = WorkspaceAdmissionReceipt(assignment(), desc, desc.package, desc.module, disposition, result, (), desc.proof_ceiling)
            observed[receipt.disposition] = receipt.result
        self.assertEqual(expectations, observed)

    # WORK_UNIT_CASE: 857/21
    def test_workspace_result_cannot_contradict_member_state(self) -> None:
        desc = descriptor()
        with self.assertRaisesRegex(ContractViolation, 'contradicts'):
            WorkspaceAdmissionReceipt(assignment(), desc, desc.package, desc.module, WorkspaceDisposition.EXCLUDED, OverallResult.PASS, (), desc.proof_ceiling)
        with self.assertRaisesRegex(ContractViolation, 'contradicts'):
            WorkspaceAdmissionReceipt(assignment(), desc, desc.package, desc.module, WorkspaceDisposition.MEMBER, OverallResult.INCOMPLETE_EVIDENCE, (), desc.proof_ceiling)

    # WORK_UNIT_CASE: 857/22
    def test_generic_component_summary_is_not_exact_package_or_workspace_receipt(self) -> None:
        generic = ComponentGateReceipt('component', OverallResult.PASS, (), proof())
        self.assertIs(type(generic), ComponentGateReceipt)
        self.assertNotIsInstance(generic, PackageGateReceipt)
        self.assertNotIsInstance(generic, WorkspaceAdmissionReceipt)

    # WORK_UNIT_CASE: 857/23
    def test_passing_cohort_requires_complete_accepted_row_denominator(self) -> None:
        row = CohortRow(issue(), unit(), RunnerMode.PYTHON_UNITTEST, 38, descriptor(matrix_cases=38).sha256, DescriptorIdentity('work-unit-857'), OverallResult.PASS)
        denominator = (row.descriptor_sha256,)
        digest = cohort_digest((row,), 1, 38, denominator, proof())
        receipt = CohortReceipt((row,), OverallResult.PASS, proof(), 1, 38, digest, denominator)
        self.assertEqual(1, receipt.expected_rows)
        self.assertEqual(38, receipt.matrix_cases)

    # WORK_UNIT_CASE: 857/24
    def test_missing_extra_duplicate_or_nonpass_cohort_row_prevents_pass(self) -> None:
        desc = descriptor()
        passing = CohortRow(issue(), unit(), desc.mode, 1, desc.sha256, desc.identity, OverallResult.PASS)
        digest = cohort_digest((passing,), 1, 1, (desc.sha256,), proof())
        with self.assertRaisesRegex(ContractViolation, 'row denominator'):
            CohortReceipt((passing,), OverallResult.PASS, proof(), 2, 1, digest, (desc.sha256,))
        nonpass = dataclasses.replace(passing, result=OverallResult.INCOMPLETE_EVIDENCE)
        nonpass_digest = cohort_digest((nonpass,), 1, 1, (desc.sha256,), proof())
        with self.assertRaisesRegex(ContractViolation, 'every row'):
            CohortReceipt((nonpass,), OverallResult.PASS, proof(), 1, 1, nonpass_digest, (desc.sha256,))
        with self.assertRaisesRegex(ContractViolation, 'duplicate cohort'):
            CohortReceipt((passing, passing), OverallResult.CONTRACT_FAILURE, proof())

    # WORK_UNIT_CASE: 857/25
    def test_cohort_matrix_arithmetic_is_exact(self) -> None:
        desc = descriptor(matrix_cases=2)
        row = CohortRow(issue(), unit(), desc.mode, 2, desc.sha256, desc.identity, OverallResult.PASS)
        digest = cohort_digest((row,), 1, 2, (desc.sha256,), proof())
        with self.assertRaisesRegex(ContractViolation, 'matrix arithmetic'):
            CohortReceipt((row,), OverallResult.PASS, proof(), 1, 3, digest, (desc.sha256,))

    # WORK_UNIT_CASE: 857/26
    def test_supplied_cohort_digest_must_match_canonical_payload(self) -> None:
        desc = descriptor()
        row = CohortRow(issue(), unit(), desc.mode, 1, desc.sha256, desc.identity, OverallResult.PASS)
        with self.assertRaisesRegex(ContractViolation, 'aggregate digest'):
            CohortReceipt((row,), OverallResult.PASS, proof(), 1, 1, 'f' * 64, (desc.sha256,))

    # WORK_UNIT_CASE: 857/27
    def test_row_descriptor_result_and_count_change_cohort_digest(self) -> None:
        desc = descriptor()
        base = CohortRow(issue(), unit(), desc.mode, 1, desc.sha256, desc.identity, OverallResult.PASS)
        changed_result = dataclasses.replace(base, result=OverallResult.INCOMPLETE_EVIDENCE)
        changed_count = dataclasses.replace(base, matrix_cases=2)
        other_desc = descriptor(identity='other-descriptor')
        changed_descriptor = dataclasses.replace(base, descriptor=other_desc.identity, descriptor_sha256=other_desc.sha256)
        self.assertEqual(4, len({canonical_sha256(base), canonical_sha256(changed_result), canonical_sha256(changed_count), canonical_sha256(changed_descriptor)}))

    # WORK_UNIT_CASE: 857/28
    def test_nonstring_or_stringification_colliding_mapping_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ContractViolation, 'exact strings'):
            canonical_bytes({1: 'numeric', '1': 'text'})

        class Key:

            def __str__(self) -> str:
                return 'same'
        with self.assertRaises(ContractViolation):
            canonical_bytes({Key(): 1, 'same': 2})

    # WORK_UNIT_CASE: 857/29
    def test_path_aliases_are_rejected_before_normalization(self) -> None:
        for value in ('a//b', 'a/./b', 'a/../b', 'a/b/'):
            with self.subTest(value=value):
                with self.assertRaises(ContractViolation):
                    RepositoryPath(value)

    # WORK_UNIT_CASE: 857/30
    def test_absolute_unc_drive_and_backslash_paths_are_rejected(self) -> None:
        for value in ('/a/b', '//server/share', 'C:/a', 'a\\b'):
            with self.subTest(value=value):
                with self.assertRaises(ContractViolation):
                    RepositoryPath(value)

    # WORK_UNIT_CASE: 857/31
    def test_percent_encoding_remains_literal_and_is_never_decoded(self) -> None:
        path = RepositoryPath('a/%2e%2e/%2F/b')
        self.assertEqual('a/%2e%2e/%2F/b', path.value)
        self.assertNotEqual(path, RepositoryPath('a/b'))

    # WORK_UNIT_CASE: 857/32
    def test_malformed_diagnostic_fields_raise_contract_violation(self) -> None:
        malformed = (('only-one',), ['key', 'value'], (1, 'value'), ('key', object()))
        for entry in malformed:
            with self.subTest(entry=entry):
                with self.assertRaises(ContractViolation):
                    BoundedDiagnostic('summary', (entry,))

    # WORK_UNIT_CASE: 857/33
    def test_relation_role_wire_spelling_is_frozen_and_aliases_rejected(self) -> None:
        self.assertEqual('hyphenated-v1', RELATION_ROLE_WIRE_REVISION)
        self.assertEqual('verified-by', RelationRole.VERIFIED_BY.value)
        self.assertEqual('integrated-by', RelationRole.INTEGRATED_BY.value)
        self.assertEqual('blocked-by', RelationRole.BLOCKED_BY.value)
        for alias in ('verified_by', 'integrated_by', 'blocked_by'):
            with self.assertRaises(ValueError):
                RelationRole(alias)

    # WORK_UNIT_CASE: 857/34
    def test_valid_853_identities_survive_and_weak_execution_is_explicit_legacy(self) -> None:
        repo = RepositoryIdentity('UnknownAlienHuman', 'eliot-memory-os')
        self.assertEqual('UnknownAlienHuman/eliot-memory-os', repo.full_name)
        live = AssignmentSourceReceipt(IssueIdentity(repo, 848), IssueState.OPEN, WorkUnitIdentity('D-WU-C0'), SourceAuthority.LIVE_GITHUB, 'Closed work-unit contracts', 'a' * 64, 24, ProofCeiling('contract-only'), 'W/"848"')
        self.assertEqual(24, live.matrix_cases)
        desc = descriptor()
        exact = member(1, desc)
        legacy = TestExecutionRecord(exact.marker.test, ExecutionDisposition.EXECUTED_PASS)
        self.assertIsNone(legacy.discovery)
        with self.assertRaisesRegex(ContractViolation, 'requires an exact discovery'):
            CaseAccountingMember(exact.case, exact.marker, legacy)

    # WORK_UNIT_CASE: 857/35
    def test_execution_workspace_and_proof_changes_are_digest_load_bearing(self) -> None:
        desc = descriptor()
        item = member(1, desc)
        failed = dataclasses.replace(item.execution, disposition=ExecutionDisposition.EXECUTED_FAIL)
        self.assertNotEqual(canonical_sha256(item.execution), canonical_sha256(failed))
        member_receipt = WorkspaceAdmissionReceipt(assignment(), desc, desc.package, desc.module, WorkspaceDisposition.MEMBER, OverallResult.PASS, (), desc.proof_ceiling)
        excluded_receipt = WorkspaceAdmissionReceipt(assignment(), desc, desc.package, desc.module, WorkspaceDisposition.EXCLUDED, OverallResult.INCOMPLETE_EVIDENCE, (), desc.proof_ceiling)
        self.assertNotEqual(canonical_sha256(member_receipt), canonical_sha256(excluded_receipt))
        self.assertNotEqual(desc.sha256, descriptor(proof_value='other-proof').sha256)

    # WORK_UNIT_CASE: 857/36
    def test_downstream_units_can_import_complete_shared_contract_surface(self) -> None:
        module = importlib.import_module('scripts.work_unit_gate')
        required = {'WorkUnitDescriptor', 'DescriptorIdentity', 'DiscoveredTestReceipt', 'TestExecutionReceipt', 'SourceShapeGateReceipt', 'PackageGateReceipt', 'WorkspaceAdmissionReceipt', 'CohortReceipt', 'cohort_digest'}
        self.assertTrue(required.issubset(set(module.__all__)))
        desc = descriptor()
        self.assertIsInstance(source_receipt(desc), SourceShapeGateReceipt)
        self.assertIsInstance(package_receipt(desc), PackageGateReceipt)

    # WORK_UNIT_CASE: 857/37
    def test_contract_source_has_no_io_process_mutation_or_command_surface(self) -> None:
        source = CONTRACTS_SOURCE.read_text(encoding='utf-8')
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update((alias.name for alias in node.names))
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        forbidden_imports = {'asyncio', 'http', 'os', 'requests', 'shutil', 'socket', 'subprocess', 'urllib'}
        self.assertTrue(imported.isdisjoint(forbidden_imports), imported)
        forbidden_fields = {'argv', 'command', 'credentials', 'environment', 'executable', 'secret', 'shell', 'token', 'url'}
        declared_fields = {field.name for value in vars(importlib.import_module('scripts.work_unit_gate.contracts')).values() if dataclasses.is_dataclass(value) for field in dataclasses.fields(value)}
        self.assertTrue(declared_fields.isdisjoint(forbidden_fields), declared_fields)
        for token in ('urlopen(', 'subprocess.run(', '.write_text(', '.write_bytes(', '.unlink(', 'os.environ'):
            self.assertNotIn(token, source)

    # WORK_UNIT_CASE: 857/38
    def test_malformed_and_cyclic_inputs_fail_bounded_without_silent_overwrite(self) -> None:
        malformed_values = (object(), 1.5, {1: 'not-string-key'}, ['x'] * 100001)
        for value in malformed_values:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(ContractViolation):
                    canonical_bytes(value)
        cyclic: list[object] = []
        cyclic.append(cyclic)
        with self.assertRaisesRegex(ContractViolation, 'cycle'):
            canonical_bytes(cyclic)
        with self.assertRaises(ContractViolation):
            WorkUnitDescriptor.from_mapping({'schema_version': WORK_UNIT_DESCRIPTOR_SCHEMA})
        self.assertEqual(CONTRACT_SCHEMA_REVISION, 'eliot-work-unit-contracts-v2')
if __name__ == '__main__':
    unittest.main()
