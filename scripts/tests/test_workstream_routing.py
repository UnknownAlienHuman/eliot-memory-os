"""Unit tests for workstream routing verifier (issue #1233)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

# Load scripts/verify-workstream-routing.py dynamically
_script_path = Path(__file__).resolve().parents[1] / "verify-workstream-routing.py"
_spec = importlib.util.spec_from_file_location("verify_workstream_routing", _script_path)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load {_script_path}")
vwr = importlib.util.module_from_spec(_spec)
sys.modules["verify_workstream_routing"] = vwr
_spec.loader.exec_module(vwr)

EXPECTED_ACTIVE_SCHEMA = vwr.EXPECTED_ACTIVE_SCHEMA
OBSOLETE_AUDIT_SHA = vwr.OBSOLETE_AUDIT_SHA
paths_overlap = vwr.paths_overlap
verify = vwr.verify
verify_active_toml = vwr.verify_active_toml
verify_active_writers = vwr.verify_active_writers
verify_assignments = vwr.verify_assignments
verify_project_map = vwr.verify_project_map
verify_snapshot = vwr.verify_snapshot


class TestWorkstreamRouting(unittest.TestCase):
    def test_paths_overlap(self) -> None:
        self.assertTrue(paths_overlap("crates/kernel/", "crates/kernel/eliot-kernel/"))
        self.assertTrue(paths_overlap("crates/kernel/eliot-kernel/src/lib.rs", "crates/kernel/eliot-kernel/src/"))
        self.assertFalse(paths_overlap("crates/kernel/", "crates/storage/"))
        self.assertFalse(paths_overlap("crates/kernel/eliot-kernel/", "crates/kernel/eliot-host/"))

    def test_verify_active_toml_valid(self) -> None:
        payload = {
            "schema": EXPECTED_ACTIVE_SCHEMA,
            "authority_branch": "main",
            "branch_policy": {
                "standard_branch_requires_open_issue": True,
                "requires_current_main_ancestor": True,
                "one_issue_one_branch_one_pr": True,
            },
            "workstream": [{"id": "core-daemons", "status": "active", "branch_strategy": "fresh"}],
        }
        self.assertEqual(verify_active_toml(payload), [])

    def test_verify_active_toml_invalid_schema(self) -> None:
        payload = {
            "schema": "eliot.wrong-schema",
            "authority_branch": "main",
            "branch_policy": {
                "standard_branch_requires_open_issue": True,
                "requires_current_main_ancestor": True,
                "one_issue_one_branch_one_pr": True,
            },
            "workstream": [{"id": "core-daemons", "status": "active", "branch_strategy": "fresh"}],
        }
        findings = verify_active_toml(payload)
        self.assertTrue(any(f.code == "active_schema_drift" for f in findings))

    def test_verify_active_toml_missing_workstreams(self) -> None:
        payload = {
            "schema": EXPECTED_ACTIVE_SCHEMA,
            "authority_branch": "main",
            "branch_policy": {
                "standard_branch_requires_open_issue": True,
                "requires_current_main_ancestor": True,
                "one_issue_one_branch_one_pr": True,
            },
            "workstream": [],
        }
        findings = verify_active_toml(payload)
        self.assertTrue(any(f.code == "active_workstreams" for f in findings))

    def test_verify_assignments_valid(self) -> None:
        assignments = [
            ("workstreams/core/assignments/014.toml", {"issue": 14, "work_unit": {}, "scope": {"primary_paths": ["bins/eliot-host/"]}}),
            ("workstreams/core/assignments/015.toml", {"issue": 15, "work_unit": {}, "scope": {"primary_paths": ["bins/eliot-kernel/"]}}),
        ]
        self.assertEqual(verify_assignments(assignments), [])

    def test_verify_assignments_orphan(self) -> None:
        assignments = [
            ("workstreams/core/assignments/unassigned.toml", {"work_unit": {}, "scope": {"primary_paths": ["crates/test/"]}}),
        ]
        findings = verify_assignments(assignments)
        self.assertTrue(any(f.code == "orphan_item" for f in findings))

    def test_verify_active_writers_no_overlap(self) -> None:
        writers = [
            {"issue": 101, "source": "mgr01", "paths": ["crates/kernel/"]},
            {"issue": 102, "source": "mgr02", "paths": ["crates/smart/"]},
        ]
        self.assertEqual(verify_active_writers(writers), [])

    def test_verify_active_writers_duplicate_writer(self) -> None:
        writers = [
            {"issue": 101, "source": "mgr01", "paths": ["crates/kernel/service.rs"]},
            {"issue": 102, "source": "mgr02", "paths": ["crates/kernel/"]},
        ]
        findings = verify_active_writers(writers)
        self.assertTrue(any(f.code == "duplicate_writer" for f in findings))

    def test_verify_project_map_clean(self) -> None:
        clean = "Status: stable source-plane and capability boundary routing map for `main`."
        self.assertEqual(verify_project_map(clean), [])

    def test_verify_project_map_obsolete_sha(self) -> None:
        obsolete = f"Status: current map audited against {OBSOLETE_AUDIT_SHA} on 2026-08-31."
        findings = verify_project_map(obsolete)
        self.assertTrue(any(f.code == "map_registry_contradiction" for f in findings))

    def test_verify_snapshot_valid(self) -> None:
        snapshot = {
            "repository": "UnknownAlienHuman/eliot-memory-os",
            "ref": "main",
            "commit_sha": "8dc9585805ddef8f4ca7ced5a87bbb7147c936bc",
            "observed_at": "2026-09-13T10:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "page_complete": True,
            "issues": [{"number": 1233, "state": "open"}],
            "active_writers": [{"issue": 1233, "source": "mgr03", "paths": ["workstreams/repository/assignments/1233-"]}],
        }
        self.assertEqual(verify_snapshot(snapshot, []), [])

    def test_verify_snapshot_stale(self) -> None:
        snapshot = {
            "repository": "UnknownAlienHuman/eliot-memory-os",
            "ref": "main",
            "commit_sha": "8dc9585805ddef8f4ca7ced5a87bbb7147c936bc",
            "observed_at": "2026-09-01T00:00:00Z",
            "expires_at": "2026-09-02T00:00:00Z",
            "page_complete": True,
        }
        findings = verify_snapshot(snapshot, [])
        self.assertTrue(any(f.code == "stale_snapshot" for f in findings))

    def test_verify_snapshot_incomplete(self) -> None:
        snapshot = {
            "repository": "UnknownAlienHuman/eliot-memory-os",
            "ref": "main",
            "commit_sha": "8dc9585805ddef8f4ca7ced5a87bbb7147c936bc",
            "observed_at": "2026-09-13T10:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "page_complete": False,
        }
        findings = verify_snapshot(snapshot, [])
        self.assertTrue(any(f.code == "incomplete_snapshot" for f in findings))

    def test_verify_snapshot_closed_active(self) -> None:
        snapshot = {
            "repository": "UnknownAlienHuman/eliot-memory-os",
            "ref": "main",
            "commit_sha": "8dc9585805ddef8f4ca7ced5a87bbb7147c936bc",
            "observed_at": "2026-09-13T10:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "page_complete": True,
            "issues": [{"number": 999, "state": "closed"}],
        }
        assignments = [
            ("workstreams/core/assignments/999.toml", {"issue": 999, "status": "active"}),
        ]
        findings = verify_snapshot(snapshot, assignments)
        self.assertTrue(any(f.code == "closed_active_item" for f in findings))

    def test_verify_full_repo(self) -> None:
        root = Path(__file__).resolve().parents[2]
        findings = verify(root)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
