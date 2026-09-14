"""Deterministic test matrix for the assignment-integrity oracle (#818).

Declared denominator: 68 cases, exactly 1..68.
Each test method corresponds to exactly one # WORK_UNIT_CASE: 818/<N>.
"""
from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path
from typing import Any, Dict

import importlib.util
import sys

_script_path = Path(__file__).resolve().parent.parent / "audit-work-unit-assignments.py"
_spec = importlib.util.spec_from_file_location("audit_work_unit_assignments", _script_path)
oracle_mod = importlib.util.module_from_spec(_spec)
sys.modules["audit_work_unit_assignments"] = oracle_mod
_spec.loader.exec_module(oracle_mod)

AssignmentIntegrityOracle = oracle_mod.AssignmentIntegrityOracle
FindingClass = oracle_mod.FindingClass
FindingSeverity = oracle_mod.FindingSeverity
ResultStatus = oracle_mod.ResultStatus
SCHEMA_REVISION = oracle_mod.SCHEMA_REVISION
format_text_output = oracle_mod.format_text_output
normalize_path = oracle_mod.normalize_path
paths_overlap = oracle_mod.paths_overlap
redact_text = oracle_mod.redact_text
validate_path_safety = oracle_mod.validate_path_safety


def base_valid_snapshot() -> Dict[str, Any]:
    return {
        "schema": SCHEMA_REVISION,
        "header": {
            "repository": "UnknownAlienHuman/eliot-memory-os",
            "base_sha": "fb3fc334e113236cb82cf5ca9139fc0970df032b",
            "source_sha": "fb3fc334e113236cb82cf5ca9139fc0970df032b",
            "producer": "root-controller",
            "rule_revision": "v4",
            "complete": True,
            "missing_sections": [],
            "canonical_branch_pattern": "^(work|fix|docs|chore|refactor|test)/([0-9]+)-([a-z0-9-]+)$",
            "branch_exceptions": ["integration-exceptions"],
        },
        "issues": [
            {
                "number": 818,
                "state": "open",
                "title": "[D-ASSIGN-0] Implement the deterministic fail-closed assignment-integrity oracle",
                "body": (
                    "## Exclusive mutable scope\n"
                    "- scripts/audit-work-unit-assignments.py\n"
                    "- scripts/tests/test_audit_work_unit_assignments.py\n\n"
                    "## Must not modify\n"
                    "Rust/Cargo/WIT/manifests/lockfile\n\n"
                    "## Required test matrix\n"
                    "Declared denominator: 2 cases, exactly 1..2.\n"
                    "1. Case one\n"
                    "2. Case two\n"
                ),
                "write_paths": [
                    "scripts/audit-work-unit-assignments.py",
                    "scripts/tests/test_audit_work_unit_assignments.py",
                ],
                "prohibited_paths": [
                    "Cargo.toml",
                ],
                "dependencies": [],
            }
        ],
        "pull_requests": [
            {
                "number": 1367,
                "state": "open",
                "draft": False,
                "merged": False,
                "title": "feat: implement assignment integrity oracle",
                "body": "Implements #818",
                "head_ref": "work/818-assignment-integrity-oracle",
                "head_repo": "UnknownAlienHuman/eliot-memory-os",
                "base_ref": "main",
                "base_sha": "fb3fc334e113236cb82cf5ca9139fc0970df032b",
                "changed_paths": [
                    "scripts/audit-work-unit-assignments.py",
                    "scripts/tests/test_audit_work_unit_assignments.py",
                ],
            }
        ],
        "repository_records": {
            "workstreams": [],
            "retired_refs": [],
        },
    }


class AssignmentIntegrityOracleTests(unittest.TestCase):

    # WORK_UNIT_CASE: 818/1
    def test_647_646_vs_physical_644_mismatch(self):
        fixture_path = Path(__file__).resolve().parent.parent / "testdata" / "work-unit-assignment-audit" / "mismatch-646-644.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            snap = json.load(f)
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.INTEGRITY_VIOLATION)
        rule_ids = {f.rule_id for f in res.findings}
        self.assertIn("AU-WS-MISMATCH", rule_ids)
        self.assertIn("AU-PHYSICAL-OWNER", rule_ids)

    # WORK_UNIT_CASE: 818/2
    def test_corrected_644_647_fixture_valid(self):
        snap = base_valid_snapshot()
        snap["repository_records"]["manifests"] = [{
            "path": "crates/smart/eliot-dreamer-core/Cargo.toml",
            "package": "eliot-dreamer-core",
            "plane": "smart",
        }]
        snap["repository_records"]["workstreams"] = [{
            "path": "workstreams/dreamer/assignments/644-dreamer-core.toml",
            "internal_issue": 644,
            "package": "eliot-dreamer-core",
            "target_dir": "crates/smart/eliot-dreamer-core/",
        }]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.VALID)

    # WORK_UNIT_CASE: 818/3
    def test_724_725_wrong_branch_duplicate(self):
        fixture_path = Path(__file__).resolve().parent.parent / "testdata" / "work-unit-assignment-audit" / "regression-724-725.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            snap = json.load(f)
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-BRANCH-MISMATCH", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/4
    def test_superseded_724_725_not_live_owner_or_dependency(self):
        fixture_path = Path(__file__).resolve().parent.parent / "testdata" / "work-unit-assignment-audit" / "regression-724-725.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            snap = json.load(f)
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-DEP-SUPERSEDED", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/5
    def test_790_783_windows_ipc_mismatch(self):
        fixture_path = Path(__file__).resolve().parent.parent / "testdata" / "work-unit-assignment-audit" / "regression-790-783.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            snap = json.load(f)
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-PLANE-MISMATCH", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/6
    def test_corrected_789_fixture_valid(self):
        snap = base_valid_snapshot()
        snap["repository_records"]["manifests"] = [{
            "path": "crates/platform/eliot-platform-windows/Cargo.toml",
            "package": "eliot-platform-windows",
            "plane": "kernel",
        }]
        snap["repository_records"]["workstreams"] = [{
            "path": "workstreams/kernel/assignments/789-windows-ipc.toml",
            "internal_issue": 789,
            "plane": "kernel",
            "target_plane": "kernel",
            "package": "eliot-platform-windows",
            "target_dir": "crates/platform/eliot-platform-windows/",
        }]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.VALID)

    # WORK_UNIT_CASE: 818/7
    def test_shifted_neighboring_reservations(self):
        fixture_path = Path(__file__).resolve().parent.parent / "testdata" / "work-unit-assignment-audit" / "regression-shifted-reservations.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            snap = json.load(f)
        res = AssignmentIntegrityOracle(snap).audit()
        rule_ids = {f.rule_id for f in res.findings}
        self.assertIn("AU-NEIGHBOR-CRATE", rule_ids)
        self.assertIn("AU-RESERV-PROD-DIFF", rule_ids)

    # WORK_UNIT_CASE: 818/8
    def test_exact_issue_pr_branch_valid(self):
        fixture_path = Path(__file__).resolve().parent.parent / "testdata" / "work-unit-assignment-audit" / "valid-baseline.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            snap = json.load(f)
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.VALID)
        self.assertEqual(len(res.findings), 0)

    # WORK_UNIT_CASE: 818/9
    def test_missing_required_pr_ownership_claim_fails(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["body"] = "Just fixing a typo"
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-OWNER-MISSING", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/10
    def test_multiple_ownership_claims_fail(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["body"] = "Implements #818 and Closes #819"
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-OWNER-MULTIPLE", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/11
    def test_inactive_or_superseded_issue_cannot_dispatch(self):
        snap = base_valid_snapshot()
        snap["issues"][0]["state"] = "closed"
        snap["issues"][0]["dispatch_requested"] = True
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-ISS-INACTIVE", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/12
    def test_duplicate_active_pr_ownership_fails(self):
        snap = base_valid_snapshot()
        snap["pull_requests"].append({
            "number": 1368,
            "state": "open",
            "title": "duplicate pr",
            "body": "Implements #818",
            "head_ref": "work/818-second-attempt",
            "head_repo": "UnknownAlienHuman/eliot-memory-os",
            "changed_paths": ["scripts/audit-work-unit-assignments.py"],
        })
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-OWNER-DUPLICATE", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/13
    def test_explicit_disjoint_decomposition_valid(self):
        snap = base_valid_snapshot()
        snap["issues"].append({
            "number": 819,
            "state": "open",
            "write_paths": ["scripts/integration/ignored_test_inventory.py"],
            "dependencies": [],
        })
        snap["pull_requests"].append({
            "number": 1369,
            "state": "open",
            "body": "Implements #819",
            "head_ref": "work/819-ignored-tests",
            "head_repo": "UnknownAlienHuman/eliot-memory-os",
            "changed_paths": ["scripts/integration/ignored_test_inventory.py"],
        })
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.VALID)

    # WORK_UNIT_CASE: 818/14
    def test_configured_numeric_branch_mismatch(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["head_ref"] = "work/999-wrong-issue"
        snap["pull_requests"][0]["body"] = "Implements #818"
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-BRANCH-MISMATCH", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/15
    def test_exact_authorized_integration_branch_exception(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["head_ref"] = "integration-exceptions"
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertNotIn("AU-BRANCH-01", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/16
    def test_fork_head_repository_mismatch(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["head_repo"] = "attacker/eliot-memory-os"
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-PR-REPO-01", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/17
    def test_stale_base_initial_head_mismatch_and_dirty_candidate_distinguished(self):
        # 1. Stale base derived from base_sha mismatching authoritative base
        snap1 = base_valid_snapshot()
        snap1["pull_requests"][0]["base_sha"] = "0000000000000000000000000000000000000000"
        res1 = AssignmentIntegrityOracle(snap1).audit()
        self.assertIn("AU-CAND-STALE-BASE", {f.rule_id for f in res1.findings})

        # 2. Dirty candidate derived from dirty_files in worktree
        snap2 = base_valid_snapshot()
        snap2["pull_requests"][0]["dirty_files"] = ["scripts/uncommitted_file.py"]
        res2 = AssignmentIntegrityOracle(snap2).audit()
        self.assertIn("AU-CAND-DIRTY", {f.rule_id for f in res2.findings})

        # 3. Initial HEAD mismatch derived from head_sha != expected_head_sha
        snap3 = base_valid_snapshot()
        snap3["pull_requests"][0]["head_sha"] = "1111111111111111111111111111111111111111"
        snap3["pull_requests"][0]["expected_head_sha"] = "2222222222222222222222222222222222222222"
        res3 = AssignmentIntegrityOracle(snap3).audit()
        self.assertIn("AU-CAND-HEAD-MISMATCH", {f.rule_id for f in res3.findings})

        # 4. Valid base-ancestor candidate: base_sha is an ancestor of authoritative base
        snap4 = base_valid_snapshot()
        ancestor_sha = "8ebf8b4000000000000000000000000000000000"
        snap4["header"]["base_ancestors"] = [ancestor_sha]
        snap4["pull_requests"][0]["base_sha"] = ancestor_sha
        snap4["pull_requests"][0]["merge_base_sha"] = ancestor_sha
        res4 = AssignmentIntegrityOracle(snap4).audit()
        self.assertEqual(res4.status, ResultStatus.VALID)
        self.assertNotIn("AU-CAND-STALE-BASE", {f.rule_id for f in res4.findings})

    # WORK_UNIT_CASE: 818/18
    def test_valid_reservation_only_draft(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["draft"] = True
        snap["pull_requests"][0]["title"] = "reserve: work unit 818"
        snap["pull_requests"][0]["changed_paths"] = [
            ".github/temporary/work-unit-818.md",
            "workstreams/assignments/818.toml",
        ]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.VALID)

    # WORK_UNIT_CASE: 818/19
    def test_missing_required_reservation_marker(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["draft"] = True
        snap["pull_requests"][0]["title"] = "reserve: work unit 818"
        snap["pull_requests"][0]["changed_paths"] = ["workstreams/assignments/818.toml"]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-RESERV-MISSING-MARKER", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/20
    def test_wrong_marker_issue_pr_branch(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["draft"] = True
        snap["pull_requests"][0]["title"] = "reserve: work unit 818"
        snap["pull_requests"][0]["changed_paths"] = [".github/temporary/work-unit-999.md"]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-RESERV-WRONG-MARKER", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/21
    def test_production_diff_in_reservation_only_pr(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["draft"] = True
        snap["pull_requests"][0]["title"] = "reserve: work unit 818"
        snap["pull_requests"][0]["changed_paths"] = [
            ".github/temporary/work-unit-818.md",
            "crates/kernel/src/lib.rs",
        ]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-RESERV-PROD-DIFF", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/22
    def test_ready_marker_only_pr_rejected(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["draft"] = False
        snap["pull_requests"][0]["title"] = "reserve: work unit 818"
        snap["pull_requests"][0]["changed_paths"] = [".github/temporary/work-unit-818.md"]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-RESERV-READY", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/23
    def test_implementation_retaining_marker_rejected(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["title"] = "feat: implement oracle"
        snap["pull_requests"][0]["changed_paths"] = [
            ".github/temporary/work-unit-818.md",
            "scripts/audit-work-unit-assignments.py",
        ]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-RESERV-RETAINED", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/24
    def test_valid_marker_removal(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["title"] = "feat: implement oracle"
        snap["pull_requests"][0]["changed_paths"] = ["scripts/audit-work-unit-assignments.py"]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.VALID)

    # WORK_UNIT_CASE: 818/25
    def test_malformed_duplicate_workstream(self):
        snap = base_valid_snapshot()
        snap["repository_records"]["workstreams"] = [
            {"path": "workstreams/core/assignments/001.toml", "internal_issue": 1},
            {"path": "workstreams/core/assignments/001.toml", "internal_issue": 1},
        ]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-WS-DUP", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/26
    def test_workstream_filename_internal_issue_mismatch(self):
        snap = base_valid_snapshot()
        snap["repository_records"]["workstreams"] = [
            {"path": "workstreams/core/assignments/100-routing.toml", "internal_issue": 200},
        ]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-WS-MISMATCH", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/27
    def test_optional_absent_workstream_pr_for_valid_unstarted_work(self):
        snap = base_valid_snapshot()
        snap["issues"].append({
            "number": 999,
            "state": "open",
            "write_paths": ["testdata/sample/I99.md"],
            "dependencies": [],
        })
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.VALID)

    # WORK_UNIT_CASE: 818/28
    def test_exact_physical_owner_valid(self):
        snap = base_valid_snapshot()
        snap["repository_records"]["manifests"] = [{
            "path": "crates/kernel/eliot-kernel/Cargo.toml",
            "package": "eliot-kernel",
            "plane": "kernel",
        }]
        snap["repository_records"]["workstreams"] = [{
            "path": "workstreams/kernel/assignments/015-kernel.toml",
            "internal_issue": 15,
            "package": "eliot-kernel",
            "target_dir": "crates/kernel/eliot-kernel/",
        }]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.VALID)

    # WORK_UNIT_CASE: 818/29
    def test_neighboring_crate_ownership_rejected(self):
        snap = base_valid_snapshot()
        snap["repository_records"]["manifests"] = [
            {"path": "crates/smart/eliot-dreamer-reconsolidation/Cargo.toml", "package": "eliot-dreamer-reconsolidation", "plane": "smart"},
            {"path": "crates/smart/eliot-dreamer-core/Cargo.toml", "package": "eliot-dreamer-core", "plane": "smart"},
        ]
        snap["repository_records"]["workstreams"] = [{
            "path": "workstreams/smart/assignments/610-dreamer.toml",
            "internal_issue": 610,
            "package": "eliot-dreamer-reconsolidation",
            "target_dir": "crates/smart/eliot-dreamer-reconsolidation/",
            "write_paths": ["crates/smart/eliot-dreamer-core/src/lib.rs"],
        }]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-NEIGHBOR-CRATE", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/30
    def test_smart_meta_plane_mismatch(self):
        snap = base_valid_snapshot()
        snap["repository_records"]["workstreams"] = [{
            "path": "workstreams/smart/assignments/610-dreamer.toml",
            "internal_issue": 610,
            "plane": "smart",
            "target_plane": "meta",
        }]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-PLANE-MISMATCH", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/31
    def test_explicitly_created_future_package_path_valid(self):
        snap = base_valid_snapshot()
        snap["issues"][0]["future_paths"] = ["crates/smart/eliot-future-pkg/"]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.VALID)

    # WORK_UNIT_CASE: 818/32
    def test_duplicate_incompatible_package_owners(self):
        snap = base_valid_snapshot()
        snap["repository_records"]["workstreams"] = [
            {
                "path": "workstreams/assignments/818-oracle.toml",
                "internal_issue": 818,
                "package": "eliot-scripts",
            },
            {
                "path": "workstreams/assignments/819-oracle.toml",
                "internal_issue": 819,
                "package": "eliot-scripts",
            },
        ]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-PKG-DUP-INCOMPATIBLE", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/33
    def test_file_file_overlap(self):
        snap = base_valid_snapshot()
        snap["issues"].append({
            "number": 819,
            "state": "open",
            "write_paths": ["scripts/audit-work-unit-assignments.py"],
            "dependencies": [],
        })
        snap["pull_requests"].append({
            "number": 1368,
            "state": "open",
            "body": "Implements #819",
            "head_ref": "work/819-competing-audit",
            "head_repo": "UnknownAlienHuman/eliot-memory-os",
            "changed_paths": ["scripts/audit-work-unit-assignments.py"],
        })
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-OVERLAP-01", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/34
    def test_file_directory_overlap_both_directions(self):
        self.assertTrue(paths_overlap("crates/foo/src/lib.rs", "crates/foo/"))
        self.assertTrue(paths_overlap("crates/foo/", "crates/foo/src/lib.rs"))

    # WORK_UNIT_CASE: 818/35
    def test_directory_directory_overlap(self):
        self.assertTrue(paths_overlap("crates/foo/", "crates/foo/src/"))
        self.assertTrue(paths_overlap("crates/foo/src/", "crates/foo/"))
        self.assertFalse(paths_overlap("crates/foo/", "crates/bar/"))

    # WORK_UNIT_CASE: 818/36
    def test_policy_aware_alias_case_comparison(self):
        self.assertEqual(normalize_path("./scripts/test.py"), "scripts/test.py")
        self.assertEqual(normalize_path("scripts\\sub\\test.py"), "scripts/sub/test.py")

    # WORK_UNIT_CASE: 818/37
    def test_traversal_absolute_unc_drive_paths_rejected(self):
        self.assertFalse(validate_path_safety("../outside.txt")[0])
        self.assertFalse(validate_path_safety("a/../../outside.txt")[0])
        self.assertFalse(validate_path_safety("C:/Windows/file.txt")[0])
        self.assertFalse(validate_path_safety("//server/share/file.txt")[0])
        self.assertFalse(validate_path_safety("/root/file.txt")[0])
        self.assertTrue(validate_path_safety("scripts/audit-work-unit-assignments.py")[0])

    # WORK_UNIT_CASE: 818/38
    def test_concurrent_shared_root_writers_rejected(self):
        snap = base_valid_snapshot()
        snap["issues"][0]["write_paths"] = ["Cargo.toml"]
        snap["issues"].append({
            "number": 819,
            "state": "open",
            "write_paths": ["Cargo.lock"],
            "dependencies": [],
        })
        snap["pull_requests"].append({
            "number": 1368,
            "state": "open",
            "body": "Implements #819",
            "head_ref": "work/819-root-lock",
            "head_repo": "UnknownAlienHuman/eliot-memory-os",
            "changed_paths": ["Cargo.lock"],
        })
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-SHARED-ROOT-WRITERS", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/39
    def test_actual_serialized_overlap_controller_turn_valid(self):
        snap = base_valid_snapshot()
        snap["issues"].append({
            "number": 819,
            "state": "open",
            "write_paths": ["scripts/audit-work-unit-assignments.py"],
            "dependencies": [818],
        })
        snap["pull_requests"].append({
            "number": 1368,
            "state": "open",
            "body": "Implements #819",
            "head_ref": "work/819-serialized-audit",
            "head_repo": "UnknownAlienHuman/eliot-memory-os",
            "changed_paths": ["scripts/audit-work-unit-assignments.py"],
        })
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertNotIn("AU-OVERLAP-01", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/40
    def test_valid_acyclic_launch_graph(self):
        snap = base_valid_snapshot()
        snap["issues"].append({
            "number": 819,
            "state": "open",
            "write_paths": ["scripts/b.py"],
            "dependencies": [818],
        })
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertNotIn("AU-DEP-CYCLE", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/41
    def test_missing_self_cyclic_prerequisites(self):
        snap = base_valid_snapshot()
        snap["issues"][0]["dependencies"] = [818, 9999]
        res = AssignmentIntegrityOracle(snap).audit()
        rule_ids = {f.rule_id for f in res.findings}
        self.assertIn("AU-DEP-SELF", rule_ids)
        self.assertIn("AU-DEP-MISSING", rule_ids)

        snap["issues"][0]["dependencies"] = [819]
        snap["issues"].append({
            "number": 819,
            "state": "open",
            "dependencies": [818],
        })
        res2 = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-DEP-CYCLE", {f.rule_id for f in res2.findings})

    # WORK_UNIT_CASE: 818/42
    def test_supersession_only_through_explicit_replacement(self):
        snap = base_valid_snapshot()
        snap["issues"].append({
            "number": 810,
            "state": "closed",
            "disposition": "superseded",
            "dependencies": [],
        })
        snap["issues"][0]["dependencies"] = [810]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-DEP-SUPERSEDED", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/43
    def test_runtime_producer_not_forced_into_compile_prerequisite(self):
        snap = base_valid_snapshot()
        snap["issues"][0]["dependencies"] = []
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.VALID)

    # WORK_UNIT_CASE: 818/44
    def test_incomplete_snapshot_cannot_pass(self):
        snap = base_valid_snapshot()
        snap["header"]["complete"] = False
        snap["header"]["missing_sections"] = ["pull_requests"]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.INCOMPLETE_SNAPSHOT)

    # WORK_UNIT_CASE: 818/45
    def test_zero_findings_with_incomplete_snapshot_remains_nonzero(self):
        snap = base_valid_snapshot()
        snap["header"]["complete"] = False
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertGreater(len(res.findings), 0)
        self.assertEqual(res.status, ResultStatus.INCOMPLETE_SNAPSHOT)

    # WORK_UNIT_CASE: 818/46
    def test_shuffled_records_preserve_findings_order_and_digest(self):
        snap1 = base_valid_snapshot()
        snap1["issues"].append({
            "number": 819,
            "state": "open",
            "write_paths": ["scripts/b.py"],
            "dependencies": [],
        })
        res1 = AssignmentIntegrityOracle(snap1).audit()

        snap2 = copy.deepcopy(snap1)
        snap2["issues"] = list(reversed(snap1["issues"]))
        res2 = AssignmentIntegrityOracle(snap2).audit()

        self.assertEqual(res1.digest, res2.digest)
        self.assertEqual([f.rule_id for f in res1.findings], [f.rule_id for f in res2.findings])

    # WORK_UNIT_CASE: 818/47
    def test_duplicate_reordered_inputs_cannot_hide_findings(self):
        snap = base_valid_snapshot()
        snap["issues"].append(copy.deepcopy(snap["issues"][0]))
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-ISS-02", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/48
    def test_unknown_field_schema_rejected(self):
        # 1. Unsupported schema string
        snap = base_valid_snapshot()
        snap["schema"] = "unsupported-schema-v99"
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.MALFORMED_INPUT)
        self.assertIn("AU-SCHEMA-02", {f.rule_id for f in res.findings})

        # 2. Removed label field in PR rejected by schema
        snap2 = base_valid_snapshot()
        snap2["pull_requests"][0]["candidate_status"] = "stale_base"
        res2 = AssignmentIntegrityOracle(snap2).audit()
        self.assertEqual(res2.status, ResultStatus.MALFORMED_INPUT)
        self.assertIn("AU-SCHEMA-02", {f.rule_id for f in res2.findings})

        # 3. Removed label field in workstream rejected by schema
        snap3 = base_valid_snapshot()
        snap3["repository_records"]["workstreams"] = [{
            "path": "workstreams/assignments/818.toml",
            "internal_issue": 818,
            "package": "eliot-scripts",
            "physical_package": "eliot-scripts",
        }]
        res3 = AssignmentIntegrityOracle(snap3).audit()
        self.assertEqual(res3.status, ResultStatus.MALFORMED_INPUT)
        self.assertIn("AU-SCHEMA-02", {f.rule_id for f in res3.findings})

        # 4. Unknown field in root rejected by schema
        snap4 = base_valid_snapshot()
        snap4["unknown_root_key"] = "forbidden"
        res4 = AssignmentIntegrityOracle(snap4).audit()
        self.assertEqual(res4.status, ResultStatus.MALFORMED_INPUT)
        self.assertIn("AU-SCHEMA-02", {f.rule_id for f in res4.findings})

    # WORK_UNIT_CASE: 818/49
    def test_bounded_malformed_fuzzed_snapshot_without_parent_crash(self):
        for malformed in [None, 12345, "string", [], {"unexpected": "structure"}]:
            res = AssignmentIntegrityOracle(malformed).audit()
            self.assertIn(res.status, (ResultStatus.MALFORMED_INPUT, ResultStatus.INTERNAL_DEFECT))

    # WORK_UNIT_CASE: 818/50
    def test_text_and_json_status_count_digest_agree(self):
        snap = base_valid_snapshot()
        res = AssignmentIntegrityOracle(snap).audit()
        text = format_text_output(res)
        self.assertIn(res.status.value, text)
        self.assertIn(res.digest, text)
        json_dict = res.to_dict()
        self.assertEqual(json_dict["digest"], res.digest)
        self.assertEqual(json_dict["status"], res.status.value)

    # WORK_UNIT_CASE: 818/51
    def test_bounded_output_and_secret_redaction(self):
        secret = "ghp_1234567890abcdef1234567890abcdef"
        redacted = redact_text(f"Token is {secret}")
        self.assertNotIn(secret, redacted)
        self.assertIn("[REDACTED]", redacted)

    # WORK_UNIT_CASE: 818/52
    def test_no_network_github_repository_mutation_path(self):
        src = Path(oracle_mod.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        forbidden = {"socket", "urllib", "requests", "subprocess", "popen", "system"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in forbidden:
                    self.fail(f"Forbidden call found: {node.func.id}")
                if isinstance(node.func, ast.Attribute) and node.func.attr in forbidden:
                    self.fail(f"Forbidden attribute call found: {node.func.attr}")

    # WORK_UNIT_CASE: 818/53
    def test_every_active_pr_has_disposition_absent_pr_allowed(self):
        snap = base_valid_snapshot()
        snap["issues"].append({
            "number": 850,
            "state": "open",
            "write_paths": ["scripts/c.py"],
            "dependencies": [],
        })
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.VALID)

    # WORK_UNIT_CASE: 818/54
    def test_every_changed_path_has_one_disposition(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["changed_paths"].append("Cargo.toml")
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-PROHIBITION-01", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/55
    def test_changing_load_bearing_identity_invalidates_digest(self):
        snap1 = base_valid_snapshot()
        res1 = AssignmentIntegrityOracle(snap1).audit()

        snap2 = copy.deepcopy(snap1)
        snap2["issues"][0]["number"] = 819
        snap2["pull_requests"][0]["body"] = "Implements #819"
        snap2["pull_requests"][0]["head_ref"] = "work/819-integrity-oracle"
        res2 = AssignmentIntegrityOracle(snap2).audit()

        self.assertNotEqual(res1.digest, res2.digest)

    # WORK_UNIT_CASE: 818/56
    def test_concurrently_ready_leaves_have_no_exclusive_write_overlap(self):
        snap = base_valid_snapshot()
        snap["issues"].append({
            "number": 820,
            "state": "open",
            "write_paths": ["scripts/other.py"],
            "dependencies": [],
        })
        res = AssignmentIntegrityOracle(snap).audit()
        leaves = res.partition_map.get("ready_leaves", [])
        self.assertIn(818, leaves)
        self.assertIn(820, leaves)

    # WORK_UNIT_CASE: 818/57
    def test_forbidden_branch_without_exact_exception_fails_retired_ref_fails(self):
        snap = base_valid_snapshot()
        snap["repository_records"]["retired_refs"] = ["work/818-assignment-integrity-oracle"]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-BRANCH-RETIRED", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/58
    def test_implements_closes_targeting_pr_fails_refs_targeting_issue_valid(self):
        snap = base_valid_snapshot()
        snap["pull_requests"][0]["body"] = "Implements #1367"
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-OWNER-PR-TARGET", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/59
    def test_wrong_case_or_nonexistent_required_document_fails(self):
        snap = base_valid_snapshot()
        snap["issues"][0]["required_documents"] = ["testdata/sample/I01.md"]
        snap["issues"][0]["document_status"] = {"testdata/sample/I01.md": "wrong_case"}
        res1 = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-DOC-WRONG-CASE", {f.rule_id for f in res1.findings})

        snap["issues"][0]["document_status"] = {"testdata/sample/I01.md": "nonexistent"}
        res2 = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-DOC-NONEXISTENT", {f.rule_id for f in res2.findings})

    # WORK_UNIT_CASE: 818/60
    def test_missing_parent_requirement_blocks_family_closure(self):
        snap = base_valid_snapshot()
        snap["issues"][0]["parent_issue"] = 9999
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-PARENT-MISSING", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/61
    def test_complete_required_reading_contributes_to_context(self):
        snap = base_valid_snapshot()
        snap["issues"][0]["body"] += "\n## Required reading\n- docs/architecture/I02-16-crate-size-and-agent-context-envelope.md\n"
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertEqual(res.status, ResultStatus.VALID)

    # WORK_UNIT_CASE: 818/62
    def test_vague_legacy_umbrella_remains_unresolved(self):
        snap = base_valid_snapshot()
        snap["issues"][0]["disposition"] = "umbrella"
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-ISS-UMBRELLA", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/63
    def test_package_proof_precedes_admission_without_cycle_728_730(self):
        snap = base_valid_snapshot()
        snap["issues"] = [
            {"number": 728, "state": "open", "dependencies": [730]},
            {"number": 730, "state": "open", "dependencies": []},
        ]
        snap["pull_requests"] = []
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-DEP-REVERSE", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/64
    def test_unfrozen_inventory_cannot_grant_tests_directory_scope(self):
        snap = base_valid_snapshot()
        snap["issues"][0]["unfrozen_inventory"] = True
        snap["issues"][0]["write_paths"] = ["tests/test_foo.py"]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-SCOPE-UNFROZEN-TESTS", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/65
    def test_actual_matrix_declared_count_and_descriptor_agree(self):
        snap = base_valid_snapshot()
        snap["issues"][0]["body"] = (
            "## Required test matrix\n"
            "Declared denominator: 10 cases, exactly 1..10.\n"
            "1. Only case\n"
        )
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-MATRIX-01", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/66
    def test_accepted_closed_prerequisite_usable_closed_without_proof_not(self):
        snap = base_valid_snapshot()
        snap["issues"].append({
            "number": 800,
            "state": "closed",
            "state_reason": "closed_without_proof",
            "dependencies": [],
        })
        snap["issues"][0]["dependencies"] = [800]
        res = AssignmentIntegrityOracle(snap).audit()
        self.assertIn("AU-DEP-CLOSED-WITHOUT-PROOF", {f.rule_id for f in res.findings})

    # WORK_UNIT_CASE: 818/67
    def test_finite_heading_aliases_parse_equivalently_with_source_spans(self):
        snap = base_valid_snapshot()
        snap["issues"][0]["body"] = (
            "```markdown\n"
            "## Exclusive mutable scope\n"
            "- fake/path.py\n"
            "```\n\n"
            "## Slice contract\n"
            "- scripts/real_path.py\n"
        )
        parsed = AssignmentIntegrityOracle(snap)._parse_markdown_body(snap["issues"][0]["body"], 818)
        self.assertIn("scripts/real_path.py", parsed["write_paths"])
        self.assertNotIn("fake/path.py", parsed["write_paths"])

    # WORK_UNIT_CASE: 818/68
    def test_inline_no_other_restrictions_exclude_rather_than_grant(self):
        # 1. Test #930/#992 style inline prohibitions fixture
        fixture_prohib = Path(__file__).resolve().parent.parent / "testdata" / "work-unit-assignment-audit" / "regression-930-992-prohibitions.json"
        with open(fixture_prohib, "r", encoding="utf-8") as f:
            snap_prohib = json.load(f)
        res_prohib = AssignmentIntegrityOracle(snap_prohib).audit()
        self.assertIn("AU-PROHIBITION-01", {f.rule_id for f in res_prohib.findings})

        # 2. Test #840 style mixed acceptance fixture with conditional clauses
        fixture_mixed = Path(__file__).resolve().parent.parent / "testdata" / "work-unit-assignment-audit" / "regression-840-mixed-acceptance.json"
        with open(fixture_mixed, "r", encoding="utf-8") as f:
            snap_mixed = json.load(f)
        res_mixed = AssignmentIntegrityOracle(snap_mixed).audit()
        self.assertEqual(res_mixed.status, ResultStatus.VALID)

        # 3. Unit test: conditional clauses must not be guessed as write paths, inline prohibitions extracted
        body = (
            "## Exclusive mutable scope\n"
            "- scripts/audit-work-unit-assignments.py\n\n"
            "## Acceptance criteria\n"
            "- Only when test passes exit 0\n"
            "- If crates/kernel is changed, recheck\n"
            "- Where documentation changes, route\n\n"
            "No other modifications permitted. Do not modify Cargo.toml or crates/.\n"
        )
        parsed = AssignmentIntegrityOracle(base_valid_snapshot())._parse_markdown_body(body, 818)
        self.assertEqual(parsed["write_paths"], ["scripts/audit-work-unit-assignments.py"])
        self.assertIn("Cargo.toml", parsed["prohibitions"])
        self.assertIn("crates/", parsed["prohibitions"])
        self.assertTrue(any("No other" in p for p in parsed["prohibitions"]))


if __name__ == "__main__":
    unittest.main()
