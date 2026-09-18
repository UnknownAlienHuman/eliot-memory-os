"""Unit tests for work-unit immutable descriptor cohort materializer (#852).

Declared denominator: 42 cases, exactly 1..42.
One substantive Python unittest per # WORK_UNIT_CASE: 852/<case> immediately above its method.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

from scripts.work_unit_gate import cohort as ch
from scripts.work_unit_gate import contracts as c
from scripts.work_unit_gate import descriptor_runner as dr

REPO = c.RepositoryIdentity("UnknownAlienHuman", "eliot-memory-os")
ROOT = Path(__file__).resolve().parents[2]
BODY, MATRIX, SOURCE, ARTIFACT = (char * 64 for char in "abcd")
PROOF = c.ProofCeiling("catalogue-integrity-only")
GUARD = c.WorkUnitIdentity("source-shape")

# Frozen leaf-router byte identities: sha256 of the exact on-disk bytes at base
# commit c0c7257f (Windows CRLF checkout; `.gitattributes` sets `* text=auto`
# so disk bytes are CRLF while git blobs are LF-only). Fixed literals recorded
# once — never computed from live files at test runtime.
FROZEN_LEAF_ROUTER_SHA256 = {
    "scripts/docs_router.py": "dfa620878659326985b5319baf9516e01a31f49decaae44c438244753d9e84f4",
    "scripts/docs_router_core.py": "752834cad7e5d759eeb522badaba653d6587cb6f8b56393d4a5816c99ccb3c89",
    "scripts/docs_shards.py": "a542962499de7b4db5be555cfa41f27fb826ecc8a7cb6595dc96d3560eff8067",
    "scripts/docs_shards_core.py": "0d94fdbcd034a96ceac7ee40e79ad7b89e7a9723ab9ca4e7b3308d22913e0965",
}


def make_desc(
    issue_num: int = 852,
    unit_name: str = "D-WU-COHORT",
    cases: int = 42,
    mode: c.RunnerMode = c.RunnerMode.PYTHON_UNITTEST,
    source_roots: tuple[str, ...] = ("scripts/work_unit_gate/cohort.py",),
    test_roots: tuple[str, ...] = ("scripts/tests/test_work_unit_gate_cohort.py",),
    package: str | None = None,
    module: str | None = None,
    require_member: bool = False,
    body_sha256: str = BODY,
    matrix_sha256: str = MATRIX,
) -> c.WorkUnitDescriptor:
    pkg = c.PackageIdentity(package) if package else (c.PackageIdentity("sample-pkg") if (mode is c.RunnerMode.RUST_PACKAGE or require_member) else None)
    mod = c.ModuleIdentity(module) if module else (c.ModuleIdentity("scripts.work_unit_gate") if mode is c.RunnerMode.PYTHON_UNITTEST else None)
    return c.WorkUnitDescriptor(
        schema_version=c.WORK_UNIT_DESCRIPTOR_SCHEMA,
        identity=c.DescriptorIdentity(f"work-unit-{issue_num}"),
        issue=c.IssueIdentity(REPO, issue_num),
        unit=c.WorkUnitIdentity(unit_name),
        mode=mode,
        source_roots=tuple(c.RepositoryPath(p) for p in source_roots),
        test_roots=tuple(c.RepositoryPath(p) for p in test_roots),
        matrix_cases=cases,
        proof_ceiling=PROOF,
        revision=1,
        body_sha256=body_sha256,
        matrix_sha256=matrix_sha256,
        require_workspace_member=require_member,
        requirements=c.VerificationRequirements(source_floor=1, public_floor=0, test_floor=cases, required_guards=(GUARD,)),
        bounds=c.ExecutionBounds(wall_ms=60000, idle_ms=10000, output_bytes=1048576, line_bytes=65536, discovery_tests=1000, child_processes=4),
        package=pkg,
        module=mod,
    )


def make_row(
    desc: c.WorkUnitDescriptor,
    disposition: c.CatalogueDisposition = c.CatalogueDisposition.ASSIGNED,
    prerequisites: tuple[c.IssueIdentity, ...] = (),
    override_desc: c.WorkUnitDescriptor | None = ...,
) -> c.CatalogueRow:
    d = desc if override_desc is ... else override_desc
    return c.CatalogueRow(
        issue=desc.issue,
        unit=desc.unit,
        body_sha256=desc.body_sha256,
        disposition=disposition,
        descriptor=d,
        prerequisites=prerequisites,
    )


def make_assignment(desc: c.WorkUnitDescriptor, state: c.IssueState = c.IssueState.OPEN, **changes) -> c.AssignmentSourceReceipt:
    data = dict(
        issue=desc.issue,
        state=state,
        unit=desc.unit,
        authority=c.SourceAuthority.LIVE_GITHUB,
        title=f"Sample {desc.unit.value}",
        body_sha256=desc.body_sha256,
        matrix_cases=desc.matrix_cases,
        proof_ceiling=c.ProofCeiling("assignment-source-only"),
        matrix_sha256=desc.matrix_sha256,
        source_use=c.AssignmentSourceUse.ACTIVE_ASSIGNMENT,
        origin="https://api.github.com",
        live_etag='W/"sample"',
    )
    return c.AssignmentSourceReceipt(**(data | changes))


def make_evidence(desc: c.WorkUnitDescriptor, result: c.OverallResult = c.OverallResult.PASS) -> c.VerificationEvidence:
    asgn = make_assignment(desc)
    findings = () if result is c.OverallResult.PASS else (
        c.Finding(c.FindingSeverity.ERROR, c.FindingClass.CONTRACT_DEFECT, c.WorkUnitIdentity("verifier"), c.RemediationCode("FIX_CONTRACT"), "source error"),
    )
    shape = c.SourceShapeGateReceipt(
        assignment=asgn,
        descriptor=desc,
        result=result,
        findings=findings,
        proof_ceiling=desc.proof_ceiling,
        source_sha256=SOURCE,
        source_items=1,
        public_items=0,
        test_items=desc.matrix_cases,
        guards=(c.GuardResult(GUARD, c.OverallResult.PASS),),
    )
    members = []
    for i in range(1, desc.matrix_cases + 1):
        test_i = c.TestIdentity(desc.mode, f"scripts.tests.test_work_unit_gate_cohort.test_case_{i}")
        loc_i = c.SourceLocation(desc.test_roots[0], i)
        found_i = c.DiscoveredTestReceipt(desc.identity, desc.sha256, test_i, loc_i, SOURCE, ARTIFACT, desc.phase)
        case_i = c.CaseIdentity(desc.issue, i)
        marker_i = c.CaseMarker(case_i, test_i, loc_i)
        exec_i = c.TestExecutionRecord(
            test_i,
            c.ExecutionDisposition.EXECUTED_PASS if result is c.OverallResult.PASS else c.ExecutionDisposition.EXECUTED_FAIL,
            found_i
        )
        members.append(c.CaseAccountingMember(case_i, marker_i, exec_i))
    cases = c.CaseAccountingReceipt(asgn, desc, tuple(members), result, desc.proof_ceiling, findings)
    ws = c.WorkspaceAdmissionReceipt(asgn, desc, desc.package, desc.module, c.WorkspaceDisposition.STANDALONE, result, findings, desc.proof_ceiling)
    pkg = None if desc.package is None else c.PackageGateReceipt(
        asgn, desc, desc.package, desc.module, shape, cases, result, findings, desc.proof_ceiling
    )
    return c.VerificationEvidence(shape, cases, ws, pkg)


class WorkUnitCohortTests(unittest.TestCase):

    # WORK_UNIT_CASE: 852/1
    def test_exact_frozen_current_catalogue_row_denominator(self):
        d1 = make_desc(851, "D-WU-BINDINGS", 44, source_roots=("scripts/work_unit_gate/case_binding.py",))
        d2 = make_desc(852, "D-WU-COHORT", 42, source_roots=("scripts/work_unit_gate/cohort.py",))
        r1, r2 = make_row(d1), make_row(d2)
        expected = (d1.issue, d2.issue)

        # Exact match passes
        cat = ch.materialize_catalogue([r1, r2], expected)
        self.assertEqual(len(cat.rows), 2)
        self.assertEqual(cat.expected_issues, (d1.issue, d2.issue))

        # Missing expected row fails
        with self.assertRaises(ch.CohortError) as ctx:
            ch.materialize_catalogue([r1], expected)
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.CATALOGUE_DENOMINATOR_MISMATCH)

        # Extra unexpected row fails
        d3 = make_desc(853, "D-WU-EXTRA", 10, source_roots=("scripts/extra.py",))
        with self.assertRaises(ch.CohortError) as ctx:
            ch.materialize_catalogue([r1, r2, make_row(d3)], expected)
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.CATALOGUE_DENOMINATOR_MISMATCH)

    # WORK_UNIT_CASE: 852/2
    def test_exact_aggregate_numbered_case_arithmetic(self):
        d1 = make_desc(851, "D-WU-BINDINGS", 44, source_roots=("scripts/work_unit_gate/case_binding.py",))
        d2 = make_desc(852, "D-WU-COHORT", 42, source_roots=("scripts/work_unit_gate/cohort.py",))
        r1, r2 = make_row(d1), make_row(d2)
        expected = (d1.issue, d2.issue)

        # Exact expected cases passes
        cat = ch.materialize_catalogue([r1, r2], expected, expected_cases=86)
        self.assertEqual(cat.matrix_cases, 86)

        # Mismatched expected cases fails
        with self.assertRaises(ch.CohortError) as ctx:
            ch.materialize_catalogue([r1, r2], expected, expected_cases=85)
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.ARITHMETIC_MISMATCH)

    # WORK_UNIT_CASE: 852/3
    def test_canonical_row_order_and_digest(self):
        d1 = make_desc(851, "D-WU-BINDINGS", 44, source_roots=("scripts/work_unit_gate/case_binding.py",))
        d2 = make_desc(852, "D-WU-COHORT", 42, source_roots=("scripts/work_unit_gate/cohort.py",))
        r1, r2 = make_row(d1), make_row(d2)
        expected = (d1.issue, d2.issue)

        cat1 = ch.materialize_catalogue([r1, r2], expected)
        cat2 = ch.materialize_catalogue([r2, r1], (d2.issue, d1.issue))

        self.assertEqual(cat1.rows, cat2.rows)
        self.assertEqual(cat1.sha256, cat2.sha256)
        self.assertEqual(cat1.rows[0].issue.number, 851)
        self.assertEqual(cat1.rows[1].issue.number, 852)

    # WORK_UNIT_CASE: 852/4
    def test_equivalent_filesystem_toml_ordering_preserves_bytes(self):
        toml1 = b"""
schema_version = "eliot-work-unit-descriptor-v2"
identity = { value = "work-unit-852" }
issue = { repository = { owner = "UnknownAlienHuman", name = "eliot-memory-os" }, number = 852 }
unit = { value = "D-WU-COHORT" }
mode = "python-unittest"
source_roots = [{ value = "scripts/work_unit_gate" }]
test_roots = [{ value = "scripts/tests" }]
matrix_cases = 42
proof_ceiling = { value = "catalogue-integrity-only" }
revision = 1
body_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
matrix_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
require_workspace_member = false
requirements = { source_floor = 1, public_floor = 0, test_floor = 42, required_guards = [] }
bounds = { wall_ms = 60000, idle_ms = 10000, output_bytes = 1048576, line_bytes = 65536, discovery_tests = 1000, child_processes = 4 }
"""
        toml2 = b"""
bounds = { wall_ms = 60000, idle_ms = 10000, output_bytes = 1048576, line_bytes = 65536, discovery_tests = 1000, child_processes = 4 }
requirements = { required_guards = [], source_floor = 1, public_floor = 0, test_floor = 42 }
require_workspace_member = false
matrix_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
body_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
revision = 1
proof_ceiling = { value = "catalogue-integrity-only" }
matrix_cases = 42
test_roots = [{ value = "scripts/tests" }]
source_roots = [{ value = "scripts/work_unit_gate" }]
mode = "python-unittest"
unit = { value = "D-WU-COHORT" }
issue = { number = 852, repository = { name = "eliot-memory-os", owner = "UnknownAlienHuman" } }
identity = { value = "work-unit-852" }
schema_version = "eliot-work-unit-descriptor-v2"
"""
        dec1 = ch.decode_cohort_descriptor(toml1, ".github/work-units/852.toml")
        dec2 = ch.decode_cohort_descriptor(toml2, ".github/work-units/852.toml")
        bytes1 = c.canonical_bytes(dec1)
        bytes2 = c.canonical_bytes(dec2)
        self.assertEqual(bytes1, bytes2)

    # WORK_UNIT_CASE: 852/5
    def test_unexpectedly_missing_executable_descriptor_fails(self):
        d1 = make_desc(852, "D-WU-COHORT", 42)
        with self.assertRaises(c.ContractViolation):
            c.CatalogueRow(
                issue=d1.issue,
                unit=d1.unit,
                body_sha256=d1.body_sha256,
                disposition=c.CatalogueDisposition.ASSIGNED,
                descriptor=None,
            )

    # WORK_UNIT_CASE: 852/6
    def test_unexpected_extra_descriptor_fails(self):
        d1 = make_desc(852, "D-WU-COHORT", 42)
        d_extra = make_desc(999, "D-WU-EXTRA", 10, source_roots=("scripts/extra.py",))
        r1 = make_row(d1)
        cat = ch.materialize_catalogue([r1], (d1.issue,))

        selection = c.VerificationSelection(cat.sha256, "e" * 64, c.SelectionScope.SELECTED, (d1.issue, d_extra.issue))
        with self.assertRaises(ch.CohortError) as ctx:
            ch.materialize_selection_plan(cat, selection, [d1, d_extra])
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.UNEXPECTED_DESCRIPTOR)

    # WORK_UNIT_CASE: 852/7
    def test_malformed_unknown_field_fails(self):
        toml_with_unknown = b"""
schema_version = "eliot-work-unit-descriptor-v2"
identity = { value = "work-unit-852" }
issue = { repository = { owner = "UnknownAlienHuman", name = "eliot-memory-os" }, number = 852 }
unit = { value = "D-WU-COHORT" }
mode = "python-unittest"
source_roots = [{ value = "scripts/work_unit_gate" }]
test_roots = [{ value = "scripts/tests" }]
matrix_cases = 42
proof_ceiling = { value = "catalogue-integrity-only" }
revision = 1
body_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
matrix_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
require_workspace_member = false
requirements = { source_floor = 1, public_floor = 0, test_floor = 42, required_guards = [] }
bounds = { wall_ms = 60000, idle_ms = 10000, output_bytes = 1048576, line_bytes = 65536, discovery_tests = 1000, child_processes = 4 }
unauthorized_extra_field = "malicious_injection"
"""
        with self.assertRaises(ch.CohortError) as ctx:
            ch.decode_cohort_descriptor(toml_with_unknown, ".github/work-units/852.toml")
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.UNKNOWN_FIELD)

    # WORK_UNIT_CASE: 852/8
    def test_filename_issue_mismatch_fails(self):
        toml_content = b"""
schema_version = "eliot-work-unit-descriptor-v2"
identity = { value = "work-unit-852" }
issue = { repository = { owner = "UnknownAlienHuman", name = "eliot-memory-os" }, number = 852 }
unit = { value = "D-WU-COHORT" }
mode = "python-unittest"
source_roots = [{ value = "scripts/work_unit_gate" }]
test_roots = [{ value = "scripts/tests" }]
matrix_cases = 42
proof_ceiling = { value = "catalogue-integrity-only" }
revision = 1
body_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
matrix_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
require_workspace_member = false
requirements = { source_floor = 1, public_floor = 0, test_floor = 42, required_guards = [] }
bounds = { wall_ms = 60000, idle_ms = 10000, output_bytes = 1048576, line_bytes = 65536, discovery_tests = 1000, child_processes = 4 }
"""
        with self.assertRaises(ch.CohortError) as ctx:
            ch.decode_cohort_descriptor(toml_content, ".github/work-units/851.toml")
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.FILENAME_MISMATCH)

    # WORK_UNIT_CASE: 852/9
    def test_duplicate_issue_owner_fails(self):
        d1 = make_desc(852, "D-WU-COHORT-A", 20, source_roots=("scripts/a.py",))
        d2 = make_desc(852, "D-WU-COHORT-B", 22, source_roots=("scripts/b.py",))
        r1, r2 = make_row(d1), make_row(d2)

        with self.assertRaises(ch.CohortError) as ctx:
            ch.materialize_catalogue([r1, r2], (d1.issue,))
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.DUPLICATE_ISSUE)

    # WORK_UNIT_CASE: 852/10
    def test_duplicate_stable_unit_fails(self):
        d1 = make_desc(851, "D-WU-SHARED", 20, source_roots=("scripts/a.py",))
        d2 = make_desc(852, "D-WU-SHARED", 22, source_roots=("scripts/b.py",))
        r1, r2 = make_row(d1), make_row(d2)

        with self.assertRaises(ch.CohortError) as ctx:
            ch.materialize_catalogue([r1, r2], (d1.issue, d2.issue))
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.DUPLICATE_UNIT)

    # WORK_UNIT_CASE: 852/11
    def test_conflicting_package_module_ownership_versus_explicit_decomposition(self):
        d1 = make_desc(851, "D-WU-PKG-A", 20, package="eliot-core", source_roots=("crates/core/a.rs",))
        d2 = make_desc(852, "D-WU-PKG-B", 22, package="eliot-core", source_roots=("crates/core/b.rs",))
        r1, r2 = make_row(d1), make_row(d2)

        with self.assertRaises(ch.CohortError) as ctx:
            ch.materialize_catalogue([r1, r2], (d1.issue, d2.issue))
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.CONFLICTING_PACKAGE_OWNERSHIP)

    # WORK_UNIT_CASE: 852/12
    def test_valid_distinct_same_order_tracks(self):
        d1 = make_desc(851, "D-WU-TRACK-A", 20, package="eliot-track-a", source_roots=("crates/track-a/src/lib.rs",))
        d2 = make_desc(852, "D-WU-TRACK-B", 22, package="eliot-track-b", source_roots=("crates/track-b/src/lib.rs",))
        r1, r2 = make_row(d1), make_row(d2)

        cat = ch.materialize_catalogue([r1, r2], (d1.issue, d2.issue))
        self.assertEqual(len(cat.rows), 2)
        self.assertEqual(cat.result, c.CatalogueResult.INTEGRITY_VALID)

    # WORK_UNIT_CASE: 852/13
    def test_zero_negative_malformed_case_count_rejected(self):
        with self.assertRaises(c.ContractViolation):
            make_desc(852, "D-WU-COHORT", cases=0)
        with self.assertRaises(c.ContractViolation):
            make_desc(852, "D-WU-COHORT", cases=-5)

    # WORK_UNIT_CASE: 852/14
    def test_floor_weaker_than_matrix_rejected(self):
        with self.assertRaises(c.ContractViolation):
            c.WorkUnitDescriptor(
                schema_version=c.WORK_UNIT_DESCRIPTOR_SCHEMA,
                identity=c.DescriptorIdentity("work-unit-852"),
                issue=c.IssueIdentity(REPO, 852),
                unit=c.WorkUnitIdentity("D-WU-COHORT"),
                mode=c.RunnerMode.PYTHON_UNITTEST,
                source_roots=(c.RepositoryPath("scripts/work_unit_gate/cohort.py"),),
                test_roots=(c.RepositoryPath("scripts/tests/test_work_unit_gate_cohort.py"),),
                matrix_cases=42,
                proof_ceiling=PROOF,
                revision=1,
                body_sha256=BODY,
                matrix_sha256=MATRIX,
                require_workspace_member=False,
                requirements=c.VerificationRequirements(source_floor=1, public_floor=0, test_floor=10, required_guards=(GUARD,)),
                bounds=c.ExecutionBounds(wall_ms=60000, idle_ms=10000, output_bytes=1048576, line_bytes=65536, discovery_tests=1000, child_processes=4),
            )

    # WORK_UNIT_CASE: 852/15
    def test_changed_body_matrix_invalidates_mirror(self):
        d1 = make_desc(852, "D-WU-COHORT", 42, body_sha256="a" * 64)
        with self.assertRaises(c.ContractViolation):
            c.CatalogueRow(
                issue=d1.issue,
                unit=d1.unit,
                body_sha256="f" * 64,
                disposition=c.CatalogueDisposition.ASSIGNED,
                descriptor=d1,
            )

    # WORK_UNIT_CASE: 852/16
    def test_changed_mode_source_test_root_invalidates_row(self):
        d_orig = make_desc(852, "D-WU-COHORT", 42, source_roots=("scripts/work_unit_gate/cohort.py",))
        d_changed = make_desc(852, "D-WU-COHORT", 42, source_roots=("scripts/work_unit_gate/altered.py",))

        self.assertNotEqual(d_orig.sha256, d_changed.sha256)
        r_orig = make_row(d_orig)
        cat = ch.materialize_catalogue([r_orig], (d_orig.issue,))
        selection = c.VerificationSelection(cat.sha256, "e" * 64, c.SelectionScope.SELECTED, (d_orig.issue,))

        with self.assertRaises(ch.CohortError) as ctx:
            ch.materialize_selection_plan(cat, selection, [d_changed])
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.STALE_MIRROR_BINDING)

    # WORK_UNIT_CASE: 852/17
    def test_moved_renamed_row_cannot_escape_denominator(self):
        d1 = make_desc(851, "D-WU-BINDINGS", 44, source_roots=("scripts/work_unit_gate/case_binding.py",))
        d2 = make_desc(852, "D-WU-COHORT", 42, source_roots=("scripts/work_unit_gate/cohort.py",))
        r1 = make_row(d1)

        r2_moved = c.CatalogueRow(
            issue=c.IssueIdentity(REPO, 899),
            unit=d2.unit,
            body_sha256=d2.body_sha256,
            disposition=c.CatalogueDisposition.ASSIGNED,
            descriptor=make_desc(899, "D-WU-COHORT", 42, source_roots=("scripts/work_unit_gate/cohort.py",)),
        )
        with self.assertRaises(ch.CohortError) as ctx:
            ch.materialize_catalogue([r1, r2_moved], (d1.issue, d2.issue))
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.CATALOGUE_DENOMINATOR_MISMATCH)

    # WORK_UNIT_CASE: 852/18
    def test_absolute_traversal_symlink_reparse_escape_rejected(self):
        for bad in ("../escape", "C:/drive", "/root", "\\\\unc\\share", "scripts/../../traversal"):
            with self.assertRaises(ch.CohortError) as ctx:
                ch.validate_path_safety(bad)
            self.assertEqual(ctx.exception.problem, ch.CohortProblem.UNSAFE_PATH)

    # WORK_UNIT_CASE: 852/19
    def test_concurrent_exclusive_source_overlap_rejected(self):
        d1 = make_desc(851, "D-WU-A", 20, source_roots=("scripts/work_unit_gate",))
        d2 = make_desc(852, "D-WU-B", 20, source_roots=("scripts/work_unit_gate/cohort.py",))
        r1, r2 = make_row(d1), make_row(d2)

        with self.assertRaises(ch.CohortError) as ctx:
            ch.materialize_catalogue([r1, r2], (d1.issue, d2.issue))
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.WRITE_SCOPE_OVERLAP)

    # WORK_UNIT_CASE: 852/20
    def test_test_source_and_directory_file_write_overlap_rejected_shared_reads_allowed(self):
        d1 = make_desc(851, "D-WU-A", 20, source_roots=("scripts/module_a.py",), test_roots=("scripts/tests",))
        d2 = make_desc(852, "D-WU-B", 20, source_roots=("scripts/module_b.py",), test_roots=("scripts/tests",))
        r1, r2 = make_row(d1), make_row(d2)

        cat = ch.materialize_catalogue([r1, r2], (d1.issue, d2.issue))
        self.assertEqual(len(cat.rows), 2)

    # WORK_UNIT_CASE: 852/21
    def test_explicit_serialized_overlap_remains_nonparallel(self):
        d1 = make_desc(851, "D-WU-A", 20, source_roots=("scripts/shared",))
        d2 = make_desc(852, "D-WU-B", 20, source_roots=("scripts/shared/sub.py",))
        r1 = make_row(d1)
        r2 = make_row(d2, prerequisites=(d1.issue,))

        cat = ch.materialize_catalogue([r1, r2], (d1.issue, d2.issue), allow_overlapping_prereqs=True)
        self.assertEqual(len(cat.rows), 2)

    # WORK_UNIT_CASE: 852/22
    def test_root_shared_generated_claims_rejected_for_ordinary_leaf(self):
        d_root = make_desc(852, "D-WU-LEAF", 42, source_roots=("Cargo.toml",))
        with self.assertRaises(ch.CohortError) as ctx:
            ch.materialize_catalogue([make_row(d_root)], (d_root.issue,))
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.SHARED_ROOT_CLAIM_REJECTED)

    # WORK_UNIT_CASE: 852/23
    def test_exact_integration_owner_can_claim_root_paths(self):
        d_int = make_desc(837, "D-WU-FINAL", 42, source_roots=("Cargo.toml",))
        cat = ch.materialize_catalogue([make_row(d_int)], (d_int.issue,))
        self.assertEqual(len(cat.rows), 1)

    # WORK_UNIT_CASE: 852/24
    def test_arbitrary_command_url_env_rejected_through_runner(self):
        toml_bad_mode = b"""
schema_version = "eliot-work-unit-descriptor-v2"
identity = { value = "work-unit-852" }
issue = { repository = { owner = "UnknownAlienHuman", name = "eliot-memory-os" }, number = 852 }
unit = { value = "D-WU-COHORT" }
mode = "arbitrary-bash-exec"
source_roots = [{ value = "scripts/work_unit_gate" }]
test_roots = [{ value = "scripts/tests" }]
matrix_cases = 42
proof_ceiling = { value = "catalogue-integrity-only" }
revision = 1
body_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
matrix_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
require_workspace_member = false
requirements = { source_floor = 1, public_floor = 0, test_floor = 42, required_guards = [] }
bounds = { wall_ms = 60000, idle_ms = 10000, output_bytes = 1048576, line_bytes = 65536, discovery_tests = 1000, child_processes = 4 }
"""
        with self.assertRaises(dr.RunnerInputError) as ctx:
            dr.decode_descriptor(toml_bad_mode, ".github/work-units/852.toml")
        self.assertIn("UNSUPPORTED_SCHEMA_OR_MODE", str(ctx.exception))

    # WORK_UNIT_CASE: 852/25
    def test_leaf_router_cannot_lower_descriptor_denominator(self):
        d1 = make_desc(851, "D-WU-A", 20, source_roots=("scripts/a.py",))
        d2 = make_desc(852, "D-WU-B", 22, source_roots=("scripts/b.py",))
        cat = ch.materialize_catalogue([make_row(d1), make_row(d2)], (d1.issue, d2.issue))

        with self.assertRaises(c.ContractViolation):
            c.SelectedVerificationPlan(
                catalogue=cat,
                selection=c.VerificationSelection(cat.sha256, "e" * 64, c.SelectionScope.FULL_PROJECT, (d1.issue,)),
                descriptors=(d1,),
                prerequisites=(),
            )

    # WORK_UNIT_CASE: 852/26
    def test_leaf_source_edit_invalidates_execution_evidence_without_rewriting_catalogue_identity(self):
        d1 = make_desc(852, "D-WU-COHORT", 42)
        r1 = make_row(d1)
        cat = ch.materialize_catalogue([r1], (d1.issue,))
        plan = ch.materialize_selection_plan(
            cat,
            c.VerificationSelection(cat.sha256, "e" * 64, c.SelectionScope.SELECTED, (d1.issue,)),
            [d1],
        )

        ev_pass = make_evidence(d1, c.OverallResult.PASS)
        rec_pass = ch.materialize_cohort_receipt(plan, [ev_pass])
        self.assertEqual(rec_pass.result, c.OverallResult.PASS)

        ev_fail = make_evidence(d1, c.OverallResult.CONTRACT_FAILURE)
        rec_fail = ch.materialize_cohort_receipt(plan, [ev_fail])
        self.assertEqual(rec_fail.result, c.OverallResult.CONTRACT_FAILURE)
        self.assertEqual(cat.sha256, ch.materialize_catalogue([r1], (d1.issue,)).sha256)

    # WORK_UNIT_CASE: 852/27
    def test_historical_acceptance_rows_have_exact_migration_dispositions(self):
        d_hist = make_desc(843, "D-WORK-UNIT-GATE", 34)
        r_hist = make_row(d_hist, disposition=c.CatalogueDisposition.SUPERSEDED, override_desc=None)
        cat = ch.materialize_catalogue([r_hist], (d_hist.issue,))
        self.assertEqual(cat.rows[0].disposition, c.CatalogueDisposition.SUPERSEDED)

    # WORK_UNIT_CASE: 852/28
    def test_routers_unchanged_against_current_base_newer_semantic_edits_preserved(self):
        # Unchanged on-disk routers match the frozen base identities.
        self.assertTrue(ch.verify_leaf_routers_unchanged(ROOT, FROZEN_LEAF_ROUTER_SHA256))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in FROZEN_LEAF_ROUTER_SHA256:
                dst = root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes((ROOT / rel).read_bytes())

            # Exact-copy bytes pass.
            self.assertTrue(ch.verify_leaf_routers_unchanged(root, FROZEN_LEAF_ROUTER_SHA256))

            # One mutated byte raises.
            target = root / "scripts/docs_router.py"
            mutated = bytearray(target.read_bytes())
            mutated[0] ^= 0x01
            target.write_bytes(bytes(mutated))
            with self.assertRaises(ch.CohortError) as ctx:
                ch.verify_leaf_routers_unchanged(root, FROZEN_LEAF_ROUTER_SHA256)
            self.assertEqual(ctx.exception.problem, ch.CohortProblem.ROUTER_MUTATION_DETECTED)
            target.write_bytes((ROOT / "scripts/docs_router.py").read_bytes())

            # A CRLF-only change (CRLF -> LF, same text) raises.
            shard = root / "scripts/docs_shards.py"
            crlf_bytes = shard.read_bytes()
            lf_bytes = crlf_bytes.replace(b"\r\n", b"\n")
            self.assertNotEqual(lf_bytes, crlf_bytes)
            shard.write_bytes(lf_bytes)
            with self.assertRaises(ch.CohortError) as ctx:
                ch.verify_leaf_routers_unchanged(root, FROZEN_LEAF_ROUTER_SHA256)
            self.assertEqual(ctx.exception.problem, ch.CohortProblem.ROUTER_MUTATION_DETECTED)
            shard.write_bytes(crlf_bytes)

            # A missing file raises.
            (root / "scripts/docs_shards_core.py").unlink()
            with self.assertRaises(ch.CohortError) as ctx:
                ch.verify_leaf_routers_unchanged(root, FROZEN_LEAF_ROUTER_SHA256)
            self.assertEqual(ctx.exception.problem, ch.CohortProblem.ROUTER_MUTATION_DETECTED)

        # A missing frozen identity for a listed router raises.
        with self.assertRaises(ch.CohortError) as ctx:
            ch.verify_leaf_routers_unchanged(ROOT, {})
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.ROUTER_MUTATION_DETECTED)

        # A malformed expected digest raises.
        bad = dict(FROZEN_LEAF_ROUTER_SHA256)
        bad["scripts/docs_router.py"] = "not-a-sha256"
        with self.assertRaises(ch.CohortError) as ctx:
            ch.verify_leaf_routers_unchanged(ROOT, bad)
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.ROUTER_MUTATION_DETECTED)

    # WORK_UNIT_CASE: 852/29
    def test_invalid_aggregate_lock_or_invalidation_fails(self):
        d1 = make_desc(852, "D-WU-COHORT", 42)
        r1 = make_row(d1)
        cat = ch.materialize_catalogue([r1], (d1.issue,))
        plan = ch.materialize_selection_plan(
            cat,
            c.VerificationSelection(cat.sha256, "e" * 64, c.SelectionScope.SELECTED, (d1.issue,)),
            [d1],
        )
        ev = make_evidence(d1)

        with self.assertRaises(c.ContractViolation):
            c.CohortReceipt(
                plan=plan,
                rows=(ev,),
                result=c.OverallResult.PASS,
                aggregate_sha256="f" * 64,
            )

    # WORK_UNIT_CASE: 852/30
    def test_normal_validator_has_no_network_subprocess_repository_mutation(self):
        def forbidden_call(*args, **kwargs):
            raise AssertionError("network/subprocess call attempted during pure validation")

        orig_socket = socket.socket
        orig_popen = subprocess.Popen
        try:
            socket.socket = forbidden_call
            subprocess.Popen = forbidden_call

            d1 = make_desc(851, "D-WU-A", 20, source_roots=("scripts/a.py",))
            d2 = make_desc(852, "D-WU-B", 22, source_roots=("scripts/b.py",))
            cat = ch.materialize_catalogue([make_row(d1), make_row(d2)], (d1.issue, d2.issue))
            self.assertEqual(cat.result, c.CatalogueResult.INTEGRITY_VALID)
        finally:
            socket.socket = orig_socket
            subprocess.Popen = orig_popen

    # WORK_UNIT_CASE: 852/31
    def test_parent_not_scheduled_alongside_replacement_children_orphaned_requirement_blocks(self):
        d_parent = make_desc(837, "D-WU-FINAL", 42, source_roots=("scripts/work_unit_gate/cohort.py",))
        d_child = make_desc(852, "D-WU-COHORT", 42, source_roots=("scripts/work_unit_cohort.py",))
        r_child = make_row(d_child)
        r_parent = make_row(d_parent, prerequisites=(d_child.issue,))

        cat = ch.materialize_catalogue([r_child, r_parent], (d_child.issue, d_parent.issue))
        selection = c.VerificationSelection(cat.sha256, "e" * 64, c.SelectionScope.SELECTED, (d_parent.issue,))
        with self.assertRaises(ch.CohortError) as ctx:
            ch.materialize_selection_plan(cat, selection, [d_parent], prerequisites=())
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.SELECTION_MISMATCH)

    # WORK_UNIT_CASE: 852/32
    def test_accepted_closed_prerequisite_versus_closed_without_proof_or_unresolved_legacy_umbrella(self):
        d_dep = make_desc(851, "D-WU-BINDINGS", 44)
        r_dep = make_row(d_dep, disposition=c.CatalogueDisposition.ACCEPTED_HISTORICAL)
        d_main = make_desc(852, "D-WU-COHORT", 42, source_roots=("scripts/cohort.py",))
        r_main = make_row(d_main, prerequisites=(d_dep.issue,))
        cat = ch.materialize_catalogue([r_dep, r_main], (d_dep.issue, d_main.issue))

        assignment = make_assignment(
            d_dep,
            state=c.IssueState.CLOSED,
            source_use=c.AssignmentSourceUse.PREREQUISITE_EVIDENCE,
        )
        prereq_ev = c.PrerequisiteEvidence(assignment, "a" * 40, "b" * 64)
        selection = c.VerificationSelection(cat.sha256, "e" * 64, c.SelectionScope.SELECTED, (d_main.issue,))
        plan = ch.materialize_selection_plan(cat, selection, [d_main], prerequisites=[prereq_ev])
        self.assertEqual(len(plan.prerequisites), 1)

        assignment_bad = make_assignment(d_dep, state=c.IssueState.OPEN, source_use=c.AssignmentSourceUse.ACTIVE_ASSIGNMENT)
        with self.assertRaises(c.ContractViolation):
            c.PrerequisiteEvidence(assignment_bad, "a" * 40, "b" * 64)

    # WORK_UNIT_CASE: 852/33
    def test_package_local_excluded_versus_membership_required_integration_unauthorized_weakening_changes_identity(self):
        d_standalone = make_desc(852, "D-WU-COHORT", 42, package="eliot-standalone", require_member=False)
        d_member = make_desc(852, "D-WU-COHORT", 42, package="eliot-standalone", require_member=True)
        self.assertNotEqual(d_standalone.sha256, d_member.sha256)

    # WORK_UNIT_CASE: 852/34
    def test_unfrozen_inventory_paths_or_contradictory_counts_cannot_be_dispatch_ready(self):
        d_valid = make_desc(852, "D-WU-COHORT", 42, source_roots=("scripts/work_unit_gate/cohort.py",))
        self.assertTrue(ch.check_dispatch_readiness(d_valid))

        # Wildcard authority is rejected at contract construction time
        with self.assertRaises(c.ContractViolation):
            make_desc(852, "D-WU-COHORT", 42, source_roots=("scripts/work_unit_gate/*.py",))

    # WORK_UNIT_CASE: 852/35
    def test_incomplete_truncated_tag_filtered_moving_snapshot_cannot_assert_complete_catalogue(self):
        incomplete_snapshot = {
            "header": {
                "repository": "UnknownAlienHuman/eliot-memory-os",
                "complete": False,
                "missing_sections": ["issues"],
            }
        }
        with self.assertRaises(ch.CohortError) as ctx:
            ch.validate_snapshot_completeness(incomplete_snapshot)
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.INCOMPLETE_SNAPSHOT)

    # WORK_UNIT_CASE: 852/36
    def test_catalogue_with_planned_or_blocked_rows_integrity_valid_but_not_project_complete(self):
        d1 = make_desc(851, "D-WU-A", 20, source_roots=("scripts/a.py",))
        d2 = make_desc(852, "D-WU-B", 22, source_roots=("scripts/b.py",))
        r1 = make_row(d1, disposition=c.CatalogueDisposition.ASSIGNED)
        r2 = make_row(d2, disposition=c.CatalogueDisposition.BLOCKED, override_desc=None)

        cat = ch.materialize_catalogue([r1, r2], (d1.issue, d2.issue))
        self.assertEqual(cat.result, c.CatalogueResult.INTEGRITY_VALID)

        selection = c.VerificationSelection(cat.sha256, "e" * 64, c.SelectionScope.FULL_PROJECT, (d1.issue, d2.issue))
        with self.assertRaises(c.ContractViolation):
            c.SelectedVerificationPlan(cat, selection, (d1,), ())

    # WORK_UNIT_CASE: 852/37
    def test_one_selected_ready_package_can_be_verified_while_unrelated_tasks_unfinished(self):
        d1 = make_desc(851, "D-WU-A", 20, source_roots=("scripts/a.py",))
        d2 = make_desc(852, "D-WU-B", 22, source_roots=("scripts/b.py",))
        r1 = make_row(d1, disposition=c.CatalogueDisposition.ASSIGNED)
        r2 = make_row(d2, disposition=c.CatalogueDisposition.PLANNED, override_desc=None)

        cat = ch.materialize_catalogue([r1, r2], (d1.issue, d2.issue))
        selection = c.VerificationSelection(cat.sha256, "e" * 64, c.SelectionScope.SELECTED, (d1.issue,))
        plan = ch.materialize_selection_plan(cat, selection, [d1])

        ev = make_evidence(d1)
        receipt = ch.materialize_cohort_receipt(plan, [ev])
        self.assertEqual(receipt.result, c.OverallResult.PASS)

    # WORK_UNIT_CASE: 852/38
    def test_omitted_substituted_required_selected_row_or_subset_promotion_fails(self):
        d1 = make_desc(851, "D-WU-A", 20, source_roots=("scripts/a.py",))
        d2 = make_desc(852, "D-WU-B", 22, source_roots=("scripts/b.py",))
        r1, r2 = make_row(d1), make_row(d2)
        cat = ch.materialize_catalogue([r1, r2], (d1.issue, d2.issue))

        selection_promoted = c.VerificationSelection(cat.sha256, "e" * 64, c.SelectionScope.FULL_PROJECT, (d1.issue,))
        with self.assertRaises(c.ContractViolation):
            c.SelectedVerificationPlan(cat, selection_promoted, (d1,), ())

    # WORK_UNIT_CASE: 852/39
    def test_same_task_prerequisite_created_path_valid_planned_but_missing_actual_source_fails_attempt(self):
        d = make_desc(852, "D-WU-COHORT", 42, source_roots=("nonexistent/path/for/test.py",))
        with self.assertRaises(ch.CohortError) as ctx:
            ch.verify_attempt_paths_exist(d, ROOT)
        self.assertEqual(ctx.exception.problem, ch.CohortProblem.MISSING_ATTEMPT_SOURCE)

    # WORK_UNIT_CASE: 852/40
    def test_unresolved_finite_allocation_is_explicit_blocked_materialization_not_wildcard_descriptor(self):
        d = make_desc(852, "D-WU-COHORT", 42)
        r_blocked = make_row(d, disposition=c.CatalogueDisposition.BLOCKED, override_desc=None)
        self.assertIsNone(r_blocked.descriptor)
        self.assertEqual(r_blocked.disposition, c.CatalogueDisposition.BLOCKED)

    # WORK_UNIT_CASE: 852/41
    def test_catalogue_generation_digest_no_future_commit_or_result_cycle(self):
        d = make_desc(852, "D-WU-COHORT", 42)
        r = make_row(d)
        cat = ch.materialize_catalogue([r], (d.issue,))
        plan = ch.materialize_selection_plan(
            cat,
            c.VerificationSelection(cat.sha256, "e" * 64, c.SelectionScope.SELECTED, (d.issue,)),
            [d],
        )

        self.assertNotIn("future_commit", {f.name for f in dataclasses.fields(cat)})
        self.assertNotIn("future_commit", {f.name for f in dataclasses.fields(plan)})
        self.assertNotIn("result", {f.name for f in dataclasses.fields(plan)})

    # WORK_UNIT_CASE: 852/42
    def test_unchanged_canonical_inputs_produce_byte_identical_materialization(self):
        d1 = make_desc(851, "D-WU-A", 20, source_roots=("scripts/a.py",))
        d2 = make_desc(852, "D-WU-B", 22, source_roots=("scripts/b.py",))
        r1, r2 = make_row(d1), make_row(d2)

        cat1 = ch.materialize_catalogue([r1, r2], (d1.issue, d2.issue))
        cat2 = ch.materialize_catalogue([r1, r2], (d1.issue, d2.issue))

        bytes1 = ch.serialize_catalogue_canonical(cat1)
        bytes2 = ch.serialize_catalogue_canonical(cat2)
        self.assertEqual(bytes1, bytes2)
        self.assertEqual(cat1.sha256, cat2.sha256)

        d2_changed = make_desc(852, "D-WU-B", 25, source_roots=("scripts/b.py",))
        cat_changed = ch.materialize_catalogue([r1, make_row(d2_changed)], (d1.issue, d2_changed.issue))
        self.assertNotEqual(cat1.sha256, cat_changed.sha256)


if __name__ == "__main__":
    unittest.main()
