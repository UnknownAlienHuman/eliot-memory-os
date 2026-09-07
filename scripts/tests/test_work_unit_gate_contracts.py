"""v4 contract regressions. Values are fixtures, never execution certificates."""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib
import json
from pathlib import Path
import random
import unittest

from scripts.work_unit_gate import contracts as c
from scripts.work_unit_gate import _contracts_v2 as historical

ROOT = Path(__file__).resolve().parents[2]
REPO = c.RepositoryIdentity("UnknownAlienHuman", "eliot-memory-os")
BODY, MATRIX, SOURCE, ARTIFACT = (char * 64 for char in "abcd")
PROOF = c.ProofCeiling("work-unit-contract-only")
GUARD = c.WorkUnitIdentity("source-shape")


def descriptor(number=857, *, count=1, require_member=False, **changes):
    data = dict(schema_version=c.WORK_UNIT_DESCRIPTOR_SCHEMA,
                identity=c.DescriptorIdentity(f"work-unit-{number}"),
                issue=c.IssueIdentity(REPO, number), unit=c.WorkUnitIdentity(f"unit-{number}"),
                mode=c.RunnerMode.PYTHON_UNITTEST,
                source_roots=(c.RepositoryPath("scripts/work_unit_gate/contracts.py"),),
                test_roots=(c.RepositoryPath("scripts/tests/test_work_unit_gate_contracts.py"),),
                matrix_cases=count, proof_ceiling=PROOF, revision=1,
                body_sha256=BODY, matrix_sha256=MATRIX, require_workspace_member=require_member,
                requirements=c.VerificationRequirements(1, 0, count, (GUARD,)),
                bounds=c.ExecutionBounds(60000, 30000, 65536, 4096, 1000, 8),
                package=c.PackageIdentity("work-unit-gate"), module=c.ModuleIdentity("scripts.work_unit_gate"))
    return c.WorkUnitDescriptor(**(data | changes))


def assignment(desc, **changes):
    return c.AssignmentSourceReceipt(**(dict(issue=desc.issue, state=c.IssueState.OPEN, unit=desc.unit,
        authority=c.SourceAuthority.LIVE_GITHUB, title="contract test fixture", body_sha256=desc.body_sha256,
        matrix_cases=desc.matrix_cases, proof_ceiling=c.ProofCeiling("assignment-source-only"),
        matrix_sha256=desc.matrix_sha256, source_use=c.AssignmentSourceUse.ACTIVE_ASSIGNMENT,
        origin="https://api.github.com", live_etag='W/"fixture"') | changes))


def finding(kind):
    return c.Finding(c.FindingSeverity.ERROR, kind, c.WorkUnitIdentity("verifier"),
                     c.RemediationCode("FIX_CONTRACT"), "fixture finding")


def member(desc, number=1, disposition=c.ExecutionDisposition.EXECUTED_PASS, **changes):
    test = c.TestIdentity(desc.mode, f"scripts.tests.ContractTests.test_case_{number}")
    location = c.SourceLocation(desc.test_roots[0], number)
    found = c.DiscoveredTestReceipt(desc.identity, desc.sha256, test, location, SOURCE, ARTIFACT, desc.phase)
    found = dataclasses.replace(found, **changes)
    case = c.CaseIdentity(desc.issue, number)
    return c.CaseAccountingMember(case, c.CaseMarker(case, found.test, location),
                                  c.TestExecutionRecord(found.test, disposition, found))


def cases(desc, *, members=None, result=c.OverallResult.PASS, findings=(), source=None):
    if members is None:
        members = tuple(member(desc, number) for number in range(1, desc.matrix_cases + 1))
    return c.CaseAccountingReceipt(source or assignment(desc), desc, members, result, desc.proof_ceiling, findings)


def shape(desc, *, result=c.OverallResult.PASS, findings=(), **changes):
    data = dict(assignment=assignment(desc), descriptor=desc, result=result, findings=findings,
                proof_ceiling=desc.proof_ceiling, source_sha256=SOURCE, source_items=1,
                public_items=0, test_items=desc.matrix_cases,
                guards=(c.GuardResult(GUARD, c.OverallResult.PASS),))
    return c.SourceShapeGateReceipt(**(data | changes))


def workspace(desc, disposition=c.WorkspaceDisposition.MEMBER, result=c.OverallResult.PASS, **changes):
    data = dict(assignment=assignment(desc), descriptor=desc, package=desc.package, module=desc.module,
                disposition=disposition, result=result, findings=(), proof_ceiling=desc.proof_ceiling)
    return c.WorkspaceAdmissionReceipt(**(data | changes))


def evidence(desc, *, source=None, accounting=None, membership=None, package_result=c.OverallResult.PASS):
    source = source or shape(desc)
    accounting = accounting or cases(desc)
    membership = membership or workspace(desc)
    package = None if desc.package is None else c.PackageGateReceipt(
        source.assignment, desc, desc.package, desc.module, source, accounting, package_result, (), desc.proof_ceiling)
    return c.VerificationEvidence(source, accounting, membership, package)


def row(desc, disposition=c.CatalogueDisposition.ASSIGNED, **changes):
    return c.CatalogueRow(**(dict(issue=desc.issue, unit=desc.unit, body_sha256=desc.body_sha256,
                                 descriptor=desc, disposition=disposition) | changes))


def catalogue(*rows):
    return c.CatalogueIntegrityReceipt(rows, tuple(item.issue for item in rows))


def plan(*descriptors, cat=None, scope=c.SelectionScope.SELECTED, prerequisites=()):
    cat = cat or catalogue(*(row(desc) for desc in descriptors))
    selection = c.VerificationSelection(cat.sha256, "e" * 64, scope, tuple(desc.issue for desc in descriptors))
    return c.SelectedVerificationPlan(cat, selection, descriptors, prerequisites)


def cohort(selected, rows, result=c.OverallResult.PASS):
    return c.CohortReceipt(selected, rows, result, c.cohort_digest(selected, rows))


class ContractClosureTests(unittest.TestCase):
    # WORK_UNIT_CASE: 857/1
    def test_descriptor_identity_and_schema_round_trip(self):
        desc = descriptor()
        payload = {field.name: getattr(desc, field.name) for field in dataclasses.fields(desc)}
        self.assertEqual(desc, c.WorkUnitDescriptor.from_mapping(payload))
        self.assertEqual("eliot-work-unit-descriptor-v2", desc.schema_version)
        self.assertEqual(hashlib.sha256(c.canonical_bytes(desc)).hexdigest(), desc.sha256)

    # WORK_UNIT_CASE: 857/2
    def test_descriptor_keeps_owner_identity_types_distinct(self):
        for field, value in (("issue", c.PullRequestIdentity(REPO, 857)), ("unit", c.ModuleIdentity("unit")),
                             ("package", c.WorkUnitIdentity("package")), ("mode", "python-unittest")):
            with self.subTest(field=field), self.assertRaises(c.ContractViolation):
                descriptor(**{field: value})

    # WORK_UNIT_CASE: 857/3
    def test_source_roots_are_nonempty_unique_and_canonical(self):
        a, b = c.RepositoryPath("scripts/a.py"), c.RepositoryPath("scripts/b.py")
        self.assertEqual((a, b), descriptor(source_roots=(b, a)).source_roots)
        for roots in ((), (a, a), [a]):
            with self.assertRaises(c.ContractViolation):
                descriptor(source_roots=roots)

    # WORK_UNIT_CASE: 857/4
    def test_test_roots_are_nonempty_unique_and_canonical(self):
        a, b = c.RepositoryPath("tests/a.py"), c.RepositoryPath("tests/b.py")
        self.assertEqual((a, b), descriptor(test_roots=(b, a)).test_roots)
        for roots in ((), (a, a), (c.RepositoryPath("tests/**"),)):
            with self.assertRaises(c.ContractViolation):
                descriptor(test_roots=roots)

    # WORK_UNIT_CASE: 857/5
    def test_descriptor_denominator_and_proof_ceiling_change_digest(self):
        original = descriptor()
        variants = (descriptor(count=2), descriptor(proof_ceiling=c.ProofCeiling("narrower")),
                    descriptor(matrix_sha256="f" * 64), descriptor(revision=2))
        self.assertEqual(5, len({original.sha256, *(value.sha256 for value in variants)}))

    # WORK_UNIT_CASE: 857/6
    def test_arbitrary_execution_fields_are_rejected_by_closed_descriptor(self):
        desc = descriptor()
        payload = {field.name: getattr(desc, field.name) for field in dataclasses.fields(desc)}
        for forbidden in ("command", "argv", "executable", "shell", "url", "environment", "secret", "output_path"):
            with self.subTest(field=forbidden), self.assertRaises(c.ContractViolation):
                c.WorkUnitDescriptor.from_mapping(payload | {forbidden: "secret-canary"})

    # WORK_UNIT_CASE: 857/7
    def test_discovery_binds_descriptor_mode_test_and_location(self):
        desc = descriptor()
        item = member(desc)
        found = item.execution.discovery
        self.assertEqual((desc.identity, desc.sha256, desc.phase, SOURCE, ARTIFACT),
                         (found.descriptor, found.descriptor_sha256, found.phase, found.source_sha256, found.artifact_sha256))
        other_test = c.TestIdentity(c.RunnerMode.RUST_PACKAGE, "other::test")
        with self.assertRaises(c.ContractViolation):
            cases(desc, members=(member(desc, test=other_test),))

    # WORK_UNIT_CASE: 857/8
    def test_execution_without_matching_discovery_is_rejected(self):
        item = member(descriptor())
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(item.execution, discovery=None)
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(item.execution, test=c.TestIdentity(c.RunnerMode.PYTHON_UNITTEST, "other.test"))

    # WORK_UNIT_CASE: 857/9
    def test_discovery_and_executed_pass_are_distinct_and_digest_distinct(self):
        desc = descriptor()
        item = member(desc)
        discovered = dataclasses.replace(item.execution, disposition=c.ExecutionDisposition.DISCOVERED)
        self.assertNotEqual(c.canonical_sha256(item.execution), c.canonical_sha256(discovered))
        receipt = cases(desc, members=(dataclasses.replace(item, execution=discovered),), result=c.OverallResult.INCOMPLETE_EVIDENCE)
        self.assertIs(receipt.result, c.OverallResult.INCOMPLETE_EVIDENCE)

    # WORK_UNIT_CASE: 857/10
    def test_case_marker_reconciles_to_one_discovery_and_execution(self):
        desc = descriptor()
        item = member(desc)
        self.assertEqual(item, cases(desc).members[0])
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(item, marker=c.CaseMarker(item.case, item.marker.test,
                                                         c.SourceLocation(item.marker.location.path, 99)))

    # WORK_UNIT_CASE: 857/11
    def test_complete_all_pass_denominator_yields_pass(self):
        desc = descriptor(count=3)
        receipt = cases(desc)
        self.assertIs(receipt.result, c.OverallResult.PASS)
        self.assertEqual((1, 2, 3), tuple(item.case.number for item in receipt.members))
        with self.assertRaises(c.ContractViolation):
            cases(desc, members=receipt.members[:-1])

    # WORK_UNIT_CASE: 857/12
    def test_all_pass_evidence_cannot_claim_any_nonpass_result(self):
        for result in (c.OverallResult.CONTRACT_FAILURE, c.OverallResult.CONFIGURATION_FAILURE, c.OverallResult.INCOMPLETE_EVIDENCE):
            with self.subTest(result=result), self.assertRaises(c.ContractViolation):
                cases(descriptor(), result=result)

    # WORK_UNIT_CASE: 857/13
    def test_executed_failure_requires_contract_failure(self):
        desc = descriptor()
        failed = (member(desc, disposition=c.ExecutionDisposition.EXECUTED_FAIL),)
        self.assertIs(cases(desc, members=failed, result=c.OverallResult.CONTRACT_FAILURE).result, c.OverallResult.CONTRACT_FAILURE)
        for result in (c.OverallResult.PASS, c.OverallResult.INCOMPLETE_EVIDENCE):
            with self.assertRaises(c.ContractViolation):
                cases(desc, members=failed, result=result)

    # WORK_UNIT_CASE: 857/14
    def test_skipped_ignored_and_cfg_disabled_are_incomplete_nonpass(self):
        for disposition in (c.ExecutionDisposition.SKIPPED, c.ExecutionDisposition.IGNORED, c.ExecutionDisposition.CFG_DISABLED):
            desc = descriptor()
            receipt = cases(desc, members=(member(desc, disposition=disposition),), result=c.OverallResult.INCOMPLETE_EVIDENCE)
            self.assertIs(receipt.members[0].execution.disposition, disposition)
            with self.assertRaises(c.ContractViolation):
                dataclasses.replace(receipt, result=c.OverallResult.PASS)

    # WORK_UNIT_CASE: 857/15
    def test_timeout_and_unavailable_remain_explicit_nonpass(self):
        desc = descriptor()
        for disposition in (c.ExecutionDisposition.TIMED_OUT, c.ExecutionDisposition.UNAVAILABLE):
            receipt = cases(desc, members=(member(desc, disposition=disposition),), result=c.OverallResult.INCOMPLETE_EVIDENCE)
            with self.assertRaises(c.ContractViolation):
                dataclasses.replace(receipt, result=c.OverallResult.PASS)

    # WORK_UNIT_CASE: 857/16
    def test_configuration_failure_requires_configuration_evidence(self):
        desc = descriptor()
        with self.assertRaises(c.ContractViolation):
            cases(desc, members=(member(desc, disposition=c.ExecutionDisposition.EXECUTED_FAIL),), result=c.OverallResult.CONFIGURATION_FAILURE)
        receipt = cases(desc, result=c.OverallResult.CONFIGURATION_FAILURE, findings=(finding(c.FindingClass.CONFIGURATION_DEFECT),))
        self.assertIs(receipt.members[0].execution.disposition, c.ExecutionDisposition.EXECUTED_PASS)

    # WORK_UNIT_CASE: 857/17
    def test_source_shape_receipt_binds_exact_owner_descriptor_and_assignment(self):
        desc = descriptor()
        receipt = shape(desc)
        for field, value in (("body_sha256", "f" * 64), ("matrix_sha256", "f" * 64),
                             ("unit", c.WorkUnitIdentity("other")), ("matrix_cases", 2)):
            with self.subTest(field=field), self.assertRaises(c.ContractViolation):
                dataclasses.replace(receipt, assignment=assignment(desc, **{field: value}))

    # WORK_UNIT_CASE: 857/18
    def test_package_receipt_binds_package_module_descriptor_and_assignment(self):
        desc = descriptor()
        receipt = evidence(desc).package
        self.assertEqual(desc.package, receipt.package)
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(receipt, package=c.PackageIdentity("other"))
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(receipt, source_shape=shape(desc, source_sha256="f" * 64))

    # WORK_UNIT_CASE: 857/19
    def test_package_pass_does_not_imply_workspace_admission(self):
        desc = descriptor(require_member=True)
        package = evidence(desc).package
        excluded = workspace(desc, c.WorkspaceDisposition.EXCLUDED, c.OverallResult.INCOMPLETE_EVIDENCE)
        self.assertIs(package.result, c.OverallResult.PASS)
        self.assertIs(c.VerificationEvidence(package.source_shape, package.case_accounting, excluded, package).result,
                      c.OverallResult.INCOMPLETE_EVIDENCE)

    # WORK_UNIT_CASE: 857/20
    def test_workspace_dispositions_remain_distinct(self):
        desc = descriptor(require_member=True)
        expected = {c.WorkspaceDisposition.MEMBER: c.OverallResult.PASS,
                    c.WorkspaceDisposition.EXCLUDED: c.OverallResult.INCOMPLETE_EVIDENCE,
                    c.WorkspaceDisposition.STANDALONE: c.OverallResult.INCOMPLETE_EVIDENCE,
                    c.WorkspaceDisposition.UNAVAILABLE: c.OverallResult.INCOMPLETE_EVIDENCE,
                    c.WorkspaceDisposition.CONFIGURATION_DEFECT: c.OverallResult.CONFIGURATION_FAILURE}
        self.assertEqual(expected, {state: workspace(desc, state, result).result for state, result in expected.items()})
        nonrust = descriptor(package=None, module=None)
        self.assertIs(workspace(nonrust, c.WorkspaceDisposition.NOT_APPLICABLE).result, c.OverallResult.PASS)

    # WORK_UNIT_CASE: 857/21
    def test_workspace_result_cannot_contradict_member_state(self):
        desc = descriptor(require_member=True)
        for state in (c.WorkspaceDisposition.EXCLUDED, c.WorkspaceDisposition.STANDALONE, c.WorkspaceDisposition.UNAVAILABLE):
            with self.assertRaises(c.ContractViolation):
                workspace(desc, state)
        with self.assertRaises(c.ContractViolation):
            workspace(desc, c.WorkspaceDisposition.NOT_APPLICABLE)

    # WORK_UNIT_CASE: 857/22
    def test_generic_component_summary_is_not_exact_package_or_workspace_receipt(self):
        desc = descriptor()
        summary = c.ComponentGateReceipt("component", c.OverallResult.PASS, (), PROOF)
        actual = evidence(desc)
        for field in ("source_shape", "case_accounting", "workspace", "package"):
            with self.subTest(field=field), self.assertRaises(c.ContractViolation):
                dataclasses.replace(actual, **{field: summary})

    # WORK_UNIT_CASE: 857/23
    def test_passing_cohort_requires_complete_accepted_row_denominator(self):
        a, b = descriptor(), descriptor(858)
        selected = plan(a, b)
        result = cohort(selected, (evidence(a), evidence(b)))
        self.assertEqual(2, result.expected_matrix_cases)
        with self.assertRaises(c.ContractViolation):
            cohort(selected, (evidence(a),))

    # WORK_UNIT_CASE: 857/24
    def test_missing_extra_duplicate_and_nonpass_cohort_rows_cannot_pass(self):
        a, b = descriptor(), descriptor(858)
        selected, actual = plan(a), evidence(a)
        for rows in ((), (actual, actual), (actual, evidence(b))):
            with self.subTest(size=len(rows)), self.assertRaises(c.ContractViolation):
                cohort(selected, rows)
        missing = cohort(selected, (), c.OverallResult.INCOMPLETE_EVIDENCE)
        self.assertEqual(0, missing.matrix_cases)
        self.assertEqual(1, missing.expected_matrix_cases)
        nonpass = evidence(a, membership=workspace(a, c.WorkspaceDisposition.UNAVAILABLE, c.OverallResult.INCOMPLETE_EVIDENCE))
        with self.assertRaises(c.ContractViolation):
            cohort(selected, (nonpass,))

    # WORK_UNIT_CASE: 857/25
    def test_cohort_matrix_arithmetic_is_exact(self):
        a, b = descriptor(count=2), descriptor(858, count=4)
        cat = catalogue(row(a), row(b, c.CatalogueDisposition.PLANNED))
        selected = plan(a, cat=cat)
        result = cohort(selected, (evidence(a),))
        self.assertEqual(6, cat.matrix_cases)
        self.assertEqual(2, selected.matrix_cases)
        self.assertEqual((2, 2), (result.matrix_cases, result.expected_matrix_cases))
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(selected, descriptors=(descriptor(count=3),))

    # WORK_UNIT_CASE: 857/26
    def test_supplied_cohort_digest_must_match_canonical_payload(self):
        desc = descriptor()
        selected, rows = plan(desc), (evidence(desc),)
        result = cohort(selected, rows)
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(result, aggregate_sha256="f" * 64)
        payload = {"schema": c.CONTRACT_SCHEMA_REVISION, "kind": "execution-cohort",
                   "plan_sha256": selected.sha256, "rows": rows}
        self.assertEqual(hashlib.sha256(c.canonical_bytes(payload)).hexdigest(), result.aggregate_sha256)

    # WORK_UNIT_CASE: 857/27
    def test_row_descriptor_result_and_count_change_cohort_digest(self):
        a, b = descriptor(), descriptor(count=2)
        passing = evidence(a)
        failed_cases = cases(a, members=(member(a, disposition=c.ExecutionDisposition.EXECUTED_FAIL),), result=c.OverallResult.CONTRACT_FAILURE)
        failed = evidence(a, accounting=failed_cases, package_result=c.OverallResult.CONTRACT_FAILURE)
        self.assertNotEqual(c.cohort_digest(plan(a), (passing,)), c.cohort_digest(plan(a), (failed,)))
        self.assertNotEqual(c.cohort_digest(plan(a), (passing,)), c.cohort_digest(plan(b), (evidence(b),)))
        with self.assertRaises(c.ContractViolation):
            cohort(plan(a), (evidence(b),))

    # WORK_UNIT_CASE: 857/28
    def test_nonstring_or_stringification_colliding_mapping_keys_are_rejected(self):
        for payload in ({1: "numeric", "1": "text"}, {object(): "x"}):
            with self.assertRaises(c.ContractViolation):
                c.canonical_bytes(payload)
        with self.assertRaises(c.ContractViolation):
            c.WorkUnitDescriptor.from_mapping({1: "x"})

    # WORK_UNIT_CASE: 857/29
    def test_path_aliases_are_rejected_before_normalization(self):
        for value in ("a//b", "a/./b", "a/../b", "a/b/"):
            with self.subTest(value=value), self.assertRaises(c.ContractViolation):
                c.RepositoryPath(value)

    # WORK_UNIT_CASE: 857/30
    def test_absolute_unc_drive_and_backslash_paths_are_rejected(self):
        for value in ("/a/b", "//server/share", "C:/a", "a\\b"):
            with self.subTest(value=value), self.assertRaises(c.ContractViolation):
                c.RepositoryPath(value)

    # WORK_UNIT_CASE: 857/31
    def test_percent_encoding_remains_literal_and_is_never_decoded(self):
        path = c.RepositoryPath("a/%2e%2e/%2F/b")
        self.assertEqual("a/%2e%2e/%2F/b", path.value)
        self.assertNotEqual(path, c.RepositoryPath("a/b"))

    # WORK_UNIT_CASE: 857/32
    def test_malformed_diagnostic_fields_raise_contract_violation(self):
        for entry in (("one",), ["key", "value"], (1, "value"), ("key", object())):
            with self.subTest(type=type(entry).__name__), self.assertRaises(c.ContractViolation):
                c.BoundedDiagnostic("summary", (entry,))

    # WORK_UNIT_CASE: 857/33
    def test_relation_role_wire_spelling_is_frozen_and_aliases_rejected(self):
        self.assertEqual("hyphenated-v1", c.RELATION_ROLE_WIRE_REVISION)
        self.assertEqual(["implements", "verified-by", "integrated-by", "blocked-by", "supersedes"],
                         [role.value for role in c.RelationRole])
        for alias in ("verified_by", "integrated_by", "blocked_by"):
            with self.assertRaises(c.ContractViolation):
                c.RelationRole(alias)
        self.assertNotEqual(c.RelationRole.BLOCKED_BY.value, c.AssignmentSourceUse.PREREQUISITE_EVIDENCE.value)

    # WORK_UNIT_CASE: 857/34
    def test_valid_853_identities_survive_and_weak_execution_is_explicit_legacy(self):
        desc = descriptor()
        old = historical.AssignmentSourceReceipt(desc.issue, c.IssueState.OPEN, desc.unit,
            c.SourceAuthority.LIVE_GITHUB, "historical source", BODY, 1, PROOF)
        self.assertEqual(REPO, old.issue.repository)
        with self.assertRaises(c.ContractViolation):
            shape(desc, assignment=old)
        legacy = historical.TestExecutionRecord(member(desc).execution.test, c.ExecutionDisposition.EXECUTED_PASS)
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(member(desc), execution=legacy)

    # WORK_UNIT_CASE: 857/35
    def test_execution_workspace_and_proof_changes_are_digest_load_bearing(self):
        desc = descriptor()
        actual = evidence(desc)
        excluded = evidence(desc, membership=workspace(desc, c.WorkspaceDisposition.EXCLUDED))
        self.assertNotEqual(c.canonical_sha256(actual), c.canonical_sha256(excluded))
        self.assertNotEqual(desc.sha256, descriptor(proof_ceiling=c.ProofCeiling("other")).sha256)
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(actual.package, proof_ceiling=c.ProofCeiling("release-verified"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            desc.bounds.wall_ms = 1

    # WORK_UNIT_CASE: 857/36
    def test_downstream_units_can_import_complete_shared_contract_surface(self):
        public = importlib.import_module("scripts.work_unit_gate")
        fields = json.loads((ROOT / "scripts/testdata/work-unit-gate/contracts/v4-fields.json").read_text())
        for name, names in fields["fields"].items():
            cls = getattr(public, name)
            self.assertIn(name, public.__all__)
            self.assertEqual(names, [field.name for field in dataclasses.fields(cls)], name)
        desc = descriptor()
        source = assignment(desc)
        run = evidence(desc)
        self.assertIs(type(source), public.AssignmentSourceReceipt)
        self.assertIs(type(run.case_accounting), public.CaseAccountingReceipt)
        self.assertIs(type(cohort(plan(desc), (run,))), public.CohortReceipt)

    # WORK_UNIT_CASE: 857/37
    def test_contract_source_has_no_io_process_mutation_or_command_surface(self):
        source = (ROOT / "scripts/work_unit_gate/contracts.py").read_text()
        tree = ast.parse(source)
        imports = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        imports |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        self.assertTrue(imports.isdisjoint({"asyncio", "http", "os", "requests", "shutil", "socket", "subprocess", "urllib", "time"}))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"open", "exec", "eval", "__import__"})
        forbidden = {"argv", "command", "credentials", "environment", "executable", "secret", "shell", "token", "url"}
        declared = {field.name for obj in vars(c).values() if isinstance(obj, type) and dataclasses.is_dataclass(obj)
                    for field in dataclasses.fields(obj)}
        self.assertTrue(declared.isdisjoint(forbidden))

    # WORK_UNIT_CASE: 857/38
    def test_malformed_and_cyclic_inputs_fail_bounded_without_silent_overwrite(self):
        for value in (object(), 1.5, {1: "x"}, ["x"] * 100001, "\ud800"):
            with self.subTest(type=type(value).__name__), self.assertRaises(c.ContractViolation):
                c.canonical_bytes(value)
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(c.ContractViolation):
            c.canonical_bytes(cycle)
        randomizer = random.Random(857)
        for _ in range(50):
            desc = descriptor(count=randomizer.randrange(1, 10))
            with self.assertRaises(c.ContractViolation):
                dataclasses.replace(desc, require_workspace_member=randomizer.randrange(10))
        with self.assertRaises(c.ContractViolation):
            c.WorkUnitDescriptor.from_mapping({"schema_version": c.WORK_UNIT_DESCRIPTOR_SCHEMA})

    # WORK_UNIT_CASE: 857/39
    def test_package_local_proof_does_not_require_its_future_workspace_admission(self):
        local, admitted = descriptor(), descriptor(require_member=True)
        self.assertNotEqual(local.sha256, admitted.sha256)
        for state in (c.WorkspaceDisposition.EXCLUDED, c.WorkspaceDisposition.STANDALONE):
            self.assertIs(workspace(local, state).result, c.OverallResult.PASS)
            with self.assertRaises(c.ContractViolation):
                workspace(admitted, state)
        with self.assertRaises(c.ContractViolation):
            workspace(local, c.WorkspaceDisposition.UNAVAILABLE)
        with self.assertRaises(c.ContractViolation):
            cases(admitted, members=(member(admitted, phase=c.VerificationPhase.PACKAGE_LOCAL),))

    # WORK_UNIT_CASE: 857/40
    def test_required_source_or_workspace_failure_cannot_be_hidden_by_passing_tests(self):
        desc = descriptor()
        accounting = cases(desc)
        bad_source = shape(desc, result=c.OverallResult.CONTRACT_FAILURE, source_items=0)
        run = evidence(desc, source=bad_source, accounting=accounting, package_result=c.OverallResult.CONTRACT_FAILURE)
        self.assertIs(cohort(plan(desc), (run,), c.OverallResult.CONTRACT_FAILURE).result, c.OverallResult.CONTRACT_FAILURE)
        self.assertIs(run.case_accounting.members[0].execution.disposition, c.ExecutionDisposition.EXECUTED_PASS)
        with self.assertRaises(c.ContractViolation):
            cohort(plan(desc), (run,))
        unready = evidence(desc, membership=workspace(desc, c.WorkspaceDisposition.UNAVAILABLE, c.OverallResult.INCOMPLETE_EVIDENCE))
        with self.assertRaises(c.ContractViolation):
            cohort(plan(desc), (unready,))

    # WORK_UNIT_CASE: 857/41
    def test_closed_prerequisite_source_does_not_authorize_implementation_or_prove_merge(self):
        desc = descriptor()
        closed = assignment(desc, state=c.IssueState.CLOSED, source_use=c.AssignmentSourceUse.PREREQUISITE_EVIDENCE)
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(closed, source_use=c.AssignmentSourceUse.ACTIVE_ASSIGNMENT)
        with self.assertRaises(c.ContractViolation):
            cases(desc, source=closed)
        self.assertNotIn("accepted_commit", {field.name for field in dataclasses.fields(closed)})
        with self.assertRaises(c.ContractViolation):
            c.PrerequisiteEvidence(closed, "future-main", "e" * 64)

    # WORK_UNIT_CASE: 857/42
    def test_offline_capture_requires_independently_expected_identity_shape(self):
        desc = descriptor()
        capture = c.OfflineCaptureBinding(desc.issue, desc.unit, BODY, MATRIX, "d" * 64, "d" * 64, c.WorkUnitIdentity("controller"),
            "e" * 64, "e" * 64, "f" * 64, 100, 200, False)
        offline = assignment(desc, authority=c.SourceAuthority.EXPLICIT_OFFLINE_SNAPSHOT, live_etag=None, offline_capture=capture)
        self.assertEqual(capture, offline.offline_capture)
        for changes in ({"offline_capture": None}, {"live_etag": "live"}, {"origin": "https://untrusted.invalid"}):
            with self.assertRaises(c.ContractViolation):
                dataclasses.replace(offline, **changes)
        for changes in ({"expected_snapshot_sha256": "a" * 64}, {"expected_capture_receipt_sha256": "a" * 64},
                        {"invalidated": True}, {"expires_at": 100}):
            with self.assertRaises(c.ContractViolation):
                dataclasses.replace(capture, **changes)
        for field in ("body_sha256", "matrix_sha256"):
            with self.assertRaises(c.ContractViolation):
                dataclasses.replace(offline, **{field: "f" * 64})
        with self.assertRaises(c.ContractViolation):
            assignment(desc, offline_capture=capture)
        # This shape check does not assert the producer was trusted or that an
        # injected clock observed freshness. The source adapter owns both.

    # WORK_UNIT_CASE: 857/43
    def test_changed_assignment_body_or_matrix_invalidates_dependent_receipts(self):
        desc = descriptor()
        payload = {field.name: getattr(desc, field.name) for field in dataclasses.fields(desc)}
        for field in ("body_sha256", "matrix_sha256"):
            without = dict(payload)
            del without[field]
            with self.assertRaises(c.ContractViolation):
                c.WorkUnitDescriptor.from_mapping(without)
            changed = dataclasses.replace(desc, **{field: "f" * 64})
            self.assertNotEqual(desc.sha256, changed.sha256)
            with self.assertRaises(c.ContractViolation):
                cases(changed, members=(member(desc),))

    # WORK_UNIT_CASE: 857/44
    def test_version_transition_does_not_mutate_or_promote_historical_contracts(self):
        path = ROOT / "scripts/work_unit_gate/_contracts_v2.py"
        raw = path.read_bytes()
        self.assertEqual("2efc073bc0ea0d63be12852d746ede04ad4ccbe8",
                         hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())
        self.assertEqual("eliot-work-unit-contracts-v4", c.CONTRACT_SCHEMA_REVISION)
        self.assertEqual("eliot-work-unit-contracts-v2", historical.CONTRACT_SCHEMA_REVISION)
        desc = descriptor()
        old = historical.WorkUnitDescriptor(historical.WORK_UNIT_DESCRIPTOR_SCHEMA, desc.identity, desc.issue, desc.unit,
            desc.mode, desc.source_roots, desc.test_roots, desc.matrix_cases, desc.proof_ceiling, desc.package, desc.module)
        self.assertNotEqual(old.sha256, desc.sha256)
        with self.assertRaises(c.ContractViolation):
            c.WorkUnitDescriptor.from_mapping({field.name: getattr(old, field.name) for field in dataclasses.fields(old)})
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(desc, schema_version=historical.WORK_UNIT_DESCRIPTOR_SCHEMA)

    # WORK_UNIT_CASE: 857/45
    def test_complete_catalogue_may_include_planned_and_blocked_unexecuted_work(self):
        a, b, d = descriptor(), descriptor(858), descriptor(859)
        cat = catalogue(row(a), row(b, c.CatalogueDisposition.PLANNED, descriptor=None),
                        row(d, c.CatalogueDisposition.BLOCKED))
        self.assertIs(cat.result, c.CatalogueResult.INTEGRITY_VALID)
        self.assertNotEqual(c.OverallResult.PASS, cat.result)
        self.assertEqual("catalogue-integrity-only", cat.proof_ceiling.value)
        with self.assertRaises(c.ContractViolation):
            cohort(plan(a, cat=cat), (cat,))
        with self.assertRaises(c.ContractViolation):
            c.CatalogueIntegrityReceipt(cat.rows[:-1], cat.expected_issues)

    # WORK_UNIT_CASE: 857/46
    def test_selected_package_can_pass_without_unrelated_planned_work_but_not_without_prerequisite(self):
        a, b, dependency = descriptor(), descriptor(858), descriptor(856)
        cat = catalogue(row(a, prerequisites=(dependency.issue,)), row(b, c.CatalogueDisposition.PLANNED),
                        row(dependency, c.CatalogueDisposition.ACCEPTED_HISTORICAL))
        prerequisite = c.PrerequisiteEvidence(assignment(dependency, state=c.IssueState.CLOSED,
            source_use=c.AssignmentSourceUse.PREREQUISITE_EVIDENCE), "d" * 40, "e" * 64)
        selected = plan(a, cat=cat, prerequisites=(prerequisite,))
        self.assertIs(cohort(selected, (evidence(a),)).result, c.OverallResult.PASS)
        with self.assertRaises(c.ContractViolation):
            plan(a, cat=cat)
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(selected, prerequisites=(prerequisite.source,))

    # WORK_UNIT_CASE: 857/47
    def test_selection_omission_substitution_and_subset_promotion_are_rejected(self):
        a, b = descriptor(), descriptor(858)
        cat = catalogue(row(a), row(b))
        full = plan(a, b, cat=cat, scope=c.SelectionScope.FULL_PROJECT)
        subset = plan(a, cat=cat)
        self.assertNotEqual(full.sha256, subset.sha256)
        with self.assertRaises(c.ContractViolation):
            plan(a, cat=cat, scope=c.SelectionScope.FULL_PROJECT)
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(full, descriptors=(a,))
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(subset, descriptors=(b,))
        with self.assertRaises(c.ContractViolation):
            cohort(full, (evidence(a),))
        with self.assertRaises(c.ContractViolation):
            c.SelectedVerificationPlan(cat, dataclasses.replace(subset.selection, catalogue_sha256="f" * 64), (a,), ())

    # WORK_UNIT_CASE: 857/48
    def test_canonical_digest_and_bootstrap_have_no_self_or_future_commit_dependency(self):
        desc = descriptor()
        selected = plan(desc)
        run = evidence(desc)
        result = cohort(selected, (run,))
        self.assertEqual(c.cohort_digest(selected, (run,)), result.aggregate_sha256)
        self.assertNotIn("sha256", {field.name for field in dataclasses.fields(selected)})
        self.assertNotIn("accepted_commit", {field.name for field in dataclasses.fields(selected)})
        with self.assertRaises(c.ContractViolation):
            row(desc, prerequisites=(desc.issue,))
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(result, aggregate_sha256=c.canonical_sha256(result))
        self.assertEqual(selected.sha256, plan(desc).sha256)


class AdditionalRegressionTests(unittest.TestCase):
    def test_all_three_modes_share_the_closed_descriptor(self):
        for mode in c.RunnerMode:
            desc = descriptor(mode=mode)
            actual = evidence(desc)
            self.assertIs(cohort(plan(desc), (actual,)).result, c.OverallResult.PASS)

    def test_old_cohort_summary_cannot_replace_current_evidence(self):
        desc = descriptor()
        summary = c.LegacyCohortRowV2(desc.issue, desc.unit, desc.mode, 1, desc.sha256, desc.identity, c.OverallResult.PASS)
        with self.assertRaises(c.ContractViolation):
            cohort(plan(desc), (summary,))

    def test_incomplete_finding_does_not_hide_execution_failure(self):
        desc = descriptor()
        receipt = cases(desc, members=(member(desc, disposition=c.ExecutionDisposition.EXECUTED_FAIL),),
                        result=c.OverallResult.CONTRACT_FAILURE, findings=(finding(c.FindingClass.SOURCE_UNAVAILABLE),))
        self.assertIs(receipt.result, c.OverallResult.CONTRACT_FAILURE)
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(receipt, result=c.OverallResult.INCOMPLETE_EVIDENCE)

    def test_workspace_finding_cannot_be_overridden_by_membership(self):
        desc = descriptor()
        with self.assertRaises(c.ContractViolation):
            workspace(desc, findings=(finding(c.FindingClass.SOURCE_UNAVAILABLE),))

    def test_guard_and_floor_denominators_are_independent(self):
        desc = descriptor()
        with self.assertRaises(c.ContractViolation):
            shape(desc, guards=())
        self.assertIs(shape(desc, guards=(), result=c.OverallResult.INCOMPLETE_EVIDENCE).result,
                      c.OverallResult.INCOMPLETE_EVIDENCE)
        with self.assertRaises(c.ContractViolation):
            shape(desc, guards=(c.GuardResult(c.WorkUnitIdentity("foreign"), c.OverallResult.PASS),))
        for name in ("source_items", "public_items", "test_items"):
            for value in (-1, True, 100001):
                with self.assertRaises(c.ContractViolation):
                    shape(desc, **{name: value})

    def test_all_execution_bounds_have_exact_limits(self):
        bounds = descriptor().bounds
        for name, maximum in (("wall_ms", 86400000), ("idle_ms", 86400000), ("output_bytes", 67108864),
                              ("line_bytes", 1048576), ("discovery_tests", 100000), ("child_processes", 64)):
            for invalid in (0, -1, True, maximum + 1, 1.5):
                with self.subTest(name=name, value=invalid), self.assertRaises(c.ContractViolation):
                    dataclasses.replace(bounds, **{name: invalid})
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(bounds, idle_ms=bounds.wall_ms + 1)
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(bounds, line_bytes=bounds.output_bytes + 1)

    def test_hostile_mapping_raises_bounded_contract_error(self):
        from collections.abc import Mapping
        class Hostile(Mapping):
            def __iter__(self):
                raise RuntimeError("secret-canary")
            def __getitem__(self, key):
                raise RuntimeError("secret-canary")
            def __len__(self):
                return 1
        for operation in (c.WorkUnitDescriptor.from_mapping, c.canonical_bytes):
            with self.assertRaises(c.ContractViolation) as error:
                operation(Hostile())
            self.assertNotIn("secret-canary", str(error.exception))

    def test_canonical_order_does_not_change_catalogue_or_cohort_identity(self):
        a, b = descriptor(), descriptor(858)
        forward, backward = catalogue(row(a), row(b)), catalogue(row(b), row(a))
        self.assertEqual(forward.sha256, backward.sha256)
        selected = plan(a, b, cat=forward)
        self.assertEqual(c.cohort_digest(selected, (evidence(a), evidence(b))),
                         c.cohort_digest(selected, (evidence(b), evidence(a))))

    def test_exact_evidence_type_and_nested_immutability(self):
        desc = descriptor()
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(plan(desc), descriptors=[desc])
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(catalogue(row(desc)), rows=[row(desc)])
        with self.assertRaises(c.ContractViolation):
            c.VerificationRequirements(1, 0, 1, [GUARD])

    def test_duplicate_case_and_foreign_source_are_rejected(self):
        desc = descriptor(count=2)
        with self.assertRaises(c.ContractViolation):
            cases(desc, members=(member(desc), member(desc)))
        with self.assertRaises(c.ContractViolation):
            dataclasses.replace(evidence(desc), source_shape=shape(desc, source_sha256="f" * 64))
        with self.assertRaises(c.ContractViolation):
            cases(desc, members=(member(desc, 1, descriptor_sha256="f" * 64), member(desc, 2)))

    def test_canonicalizer_redacts_valueerror_from_untrusted_mapping(self):
        from collections.abc import Mapping
        class Hostile(Mapping):
            def __iter__(self):
                raise ValueError("secret-canary")
            def __getitem__(self, key):
                raise ValueError("secret-canary")
            def __len__(self):
                return 1
        with self.assertRaises(c.ContractViolation) as error:
            c.canonical_bytes(Hostile())
        self.assertNotIn("secret-canary", str(error.exception))

    def test_workspace_identity_cannot_be_replaced_by_equal_looking_object(self):
        class Impostor:
            def __eq__(self, other):
                return True
            def __ne__(self, other):
                return False
        desc = descriptor()
        for name in ("package", "module"):
            with self.assertRaises(c.ContractViolation):
                workspace(desc, **{name: Impostor()})


if __name__ == "__main__":
    unittest.main()
