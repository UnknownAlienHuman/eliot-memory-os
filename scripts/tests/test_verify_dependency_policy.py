"""Unit tests for dependency admission policy verifier (issue #1229)."""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

# Load scripts/verify-dependency-policy.py dynamically
_script_path = Path(__file__).resolve().parents[1] / "verify-dependency-policy.py"
_spec = importlib.util.spec_from_file_location("verify_dependency_policy", _script_path)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load {_script_path}")
vdp = importlib.util.module_from_spec(_spec)
sys.modules["verify_dependency_policy"] = vdp
_spec.loader.exec_module(vdp)

run_self_tests = vdp.run_self_tests
verify_all = vdp.verify_all
check_cargo_inventory = vdp.check_cargo_inventory
check_exceptions = vdp.check_exceptions
check_python_ecosystem = vdp.check_python_ecosystem
check_nuget_ecosystem = vdp.check_nuget_ecosystem
check_external_executables = vdp.check_external_executables
build_receipt = vdp.build_receipt
STATUS_PASS = vdp.STATUS_PASS


class TestVerifyDependencyPolicy(unittest.TestCase):
    def test_self_test_runs_cleanly(self) -> None:
        exit_code = run_self_tests()
        self.assertEqual(exit_code, 0)

    def test_current_repository_passes_offline(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        findings, status, receipt, _, direct_count = verify_all(repo_root, "offline-source")
        self.assertEqual(status, STATUS_PASS)
        self.assertEqual(findings, [])
        self.assertGreater(direct_count, 0)
        self.assertEqual(receipt["proof_ceiling"], "OFFLINE_SOURCE_EVIDENCE_ONLY")

    def test_missing_inventory_entry_rejected(self) -> None:
        manifest_fixture = {
            "schema": "eliot.dependency-policy.v1",
            "scanner": {"tool": "cargo-deny"},
            "direct_dependencies": {
                "known_crate": {
                    "consumer": "test",
                    "owner": "test",
                    "reason": "test",
                    "features": [],
                    "public_exposure": "none",
                    "removal_plan": "none",
                }
            },
        }
        findings = check_cargo_inventory(manifest_fixture, {"known_crate", "unregistered_crate"})
        self.assertTrue(any(f.code == "DEP-003" and "unregistered_crate" in f.detail for f in findings))

    def test_expired_exception_rejected(self) -> None:
        manifest_exc = {
            "exceptions": [
                {
                    "package": "old-crate",
                    "version": "0.1.0",
                    "advisory": "RUSTSEC-2021-0001",
                    "owner": "security",
                    "compensating_control": "sandbox",
                    "expires_at": "2022-01-01T00:00:00Z",
                    "removal_condition": "upgrade",
                }
            ]
        }
        findings = check_exceptions(manifest_exc, now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc))
        self.assertTrue(any(f.code == "DEP-010" and "expired" in f.detail for f in findings))

    def test_unexpired_exception_accepted(self) -> None:
        manifest_exc = {
            "exceptions": [
                {
                    "package": "current-crate",
                    "version": "0.1.0",
                    "advisory": "RUSTSEC-2026-9999",
                    "owner": "security",
                    "compensating_control": "sandbox",
                    "expires_at": "2027-01-01T00:00:00Z",
                    "removal_condition": "upgrade",
                }
            ]
        }
        findings = check_exceptions(manifest_exc, now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc))
        self.assertEqual(findings, [])

    def test_unhashed_python_requirement_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            sdir = root / "scripts"
            sdir.mkdir(parents=True)
            (sdir / "requirements-verification.txt").write_text("pyyaml==6.0.2\n", encoding="utf-8")
            findings = check_python_ecosystem(root)
            self.assertTrue(any(f.code == "DEP-008" for f in findings))

    def test_missing_nuget_lock_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            op_dir = root / "apps" / "Eliot.Operator"
            op_dir.mkdir(parents=True)
            (op_dir / "Eliot.Operator.csproj").write_text(
                "<Project><PropertyGroup><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup></Project>",
                encoding="utf-8",
            )
            findings = check_nuget_ecosystem(root)
            self.assertTrue(any(f.code == "DEP-007" and "missing" in f.detail for f in findings))

    def test_missing_external_executable_rejected(self) -> None:
        findings = check_external_executables({})
        self.assertTrue(any(f.code == "DEP-009" and "surrealdb" in f.detail for f in findings))

    def test_receipt_ceilings_distinct(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        _, _, r_offline, _, _ = verify_all(repo_root, "offline-source")
        self.assertEqual(r_offline["proof_ceiling"], "OFFLINE_SOURCE_EVIDENCE_ONLY")
        self.assertNotIn("advisory_snapshot", r_offline)

        _, _, r_current, _, _ = verify_all(repo_root, "current-advisories")
        self.assertEqual(r_current["proof_ceiling"], "DEPENDENCY_ADMISSION_AND_ADVISORY_EVIDENCE_CANDIDATE")
        self.assertIn("advisory_snapshot", r_current)


if __name__ == "__main__":
    unittest.main()
