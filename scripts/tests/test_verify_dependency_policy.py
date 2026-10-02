"""Unit tests for dependency admission policy verifier (issue #1229)."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
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
check_inventory_disposition_evidence = vdp.check_inventory_disposition_evidence
check_exceptions = vdp.check_exceptions
check_exception_lock_drift = vdp.check_exception_lock_drift
check_policy_manifest = vdp.check_policy_manifest
derive_overall_status = vdp._derive_overall_status
check_python_ecosystem = vdp.check_python_ecosystem
check_nuget_ecosystem = vdp.check_nuget_ecosystem
check_external_executables = vdp.check_external_executables
build_receipt = vdp.build_receipt
STATUS_PASS = vdp.STATUS_PASS
STATUS_INCOMPLETE = vdp.STATUS_INCOMPLETE
STATUS_FINDINGS = vdp.STATUS_FINDINGS

_POPULATED_FEATURES = ["derive"]


class TestVerifyDependencyPolicy(unittest.TestCase):
    def _candidate_advisory_fixture(self, query_version: str, vulnerabilities: list[dict]) -> tuple[Path, dict, dict]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        evidence_dir = root / ".eliot" / "dependency-policy" / "surrealdb" / "v3.2.0"
        evidence_dir.mkdir(parents=True)
        query_path = ".eliot/dependency-policy/surrealdb/v3.2.0/osv-query.json"
        response_path = ".eliot/dependency-policy/surrealdb/v3.2.0/osv-response.json"
        query_bytes = (json.dumps({
            "package": {"ecosystem": "crates.io", "name": "surrealdb"},
            "version": query_version,
        }, separators=(",", ":")) + "\r\n").encode("utf-8")
        response_bytes = (json.dumps({"vulns": vulnerabilities}, separators=(",", ":")) + "\n").encode("utf-8")
        (root / query_path).write_bytes(query_bytes)
        (root / response_path).write_bytes(response_bytes)
        retrieved_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        refresh = {
            "status": "verified",
            "query": {"path": query_path, "sha256": hashlib.sha256(query_bytes).hexdigest()},
            "response": {
                "path": response_path,
                "sha256": hashlib.sha256(response_bytes).hexdigest(),
                "retrieved_at_utc": retrieved_at,
                "age_seconds": 0,
            },
            "maximum_age_hours": 24,
        }
        candidate = {
            "version": "3.2.0",
            "advisory_package": "surrealdb",
            "advisory_ecosystem": "crates.io",
            "advisory_scope": "rust-crate",
            "advisory_query_path": query_path,
            "advisory_response_path": response_path,
            "advisory_max_age_hours": 24,
        }
        return root, candidate, {"candidate_advisory_refresh": refresh}

    def test_self_test_runs_cleanly(self) -> None:
        exit_code = run_self_tests()
        self.assertEqual(exit_code, 0)

    def test_selected_candidate_advisory_receipt_binds_exact_version(self) -> None:
        root, candidate, provisioning = self._candidate_advisory_fixture("3.2.0", [])
        findings: list = []
        evidence = vdp._validate_candidate_release_advisories(root, {}, candidate, provisioning, findings)
        self.assertEqual(findings, [])
        self.assertEqual(evidence["evidence_status"], "verified")
        self.assertEqual(evidence["advisory_status"], "no_known_vulnerabilities")
        self.assertEqual(evidence["query"]["body"]["version"], "3.2.0")
        self.assertEqual(evidence["distributed_binary_applicability"], "unestablished")

    def test_selected_candidate_advisory_receipt_rejects_wrong_query_version(self) -> None:
        root, candidate, provisioning = self._candidate_advisory_fixture("3.1.4", [])
        findings: list = []
        evidence = vdp._validate_candidate_release_advisories(root, {}, candidate, provisioning, findings)
        self.assertEqual(evidence["evidence_status"], "findings")
        self.assertTrue(any("exact package, ecosystem and version" in finding.detail for finding in findings))

    def test_selected_candidate_advisory_receipt_keeps_candidate_findings(self) -> None:
        vulnerability = {
            "id": "RUSTSEC-2026-9999",
            "affected": [{"package": {"ecosystem": "crates.io", "name": "surrealdb"}}],
        }
        root, candidate, provisioning = self._candidate_advisory_fixture("3.2.0", [vulnerability])
        findings: list = []
        evidence = vdp._validate_candidate_release_advisories(root, {}, candidate, provisioning, findings)
        self.assertEqual(findings, [])
        self.assertEqual(evidence["advisory_status"], "findings")
        self.assertEqual(evidence["advisory_ids"], ["RUSTSEC-2026-9999"])

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

    # --- issue #1229 A2: direct-dependency disposition evidence ---
    #
    # Presence of a required key is not evidence. A disposition that is keyed
    # but empty (or whitespace-only) must be a DEP-003 finding rather than a
    # clean run whose empty values are published into the SBOM by
    # `_inventory_disposition`.

    _DISPOSITION_BLANK_FIELDS = ("consumer", "owner", "reason", "public_exposure", "removal_plan")

    def _rust_disposition_fixture(self, entry: dict) -> dict:
        return {
            "schema": "eliot.dependency-policy.v1",
            "scanner": {"tool": "cargo-deny"},
            "direct_dependencies": {"serde": entry},
        }

    def _populated_rust_disposition(self) -> dict:
        return {
            "ecosystem": "rust",
            "version": "1.0.228",
            "consumer": "crates/foundation/eliot-evidence",
            "owner": "crates/foundation/eliot-evidence",
            "reason": "serde derive for canonical evidence records",
            "features": list(_POPULATED_FEATURES),
            "public_exposure": "none",
            "removal_plan": "hand-rolled serialization",
        }

    def _empty_rust_disposition(self) -> dict:
        return {
            "ecosystem": "rust",
            "version": "1.0.228",
            "consumer": "",
            "owner": "",
            "reason": "",
            "features": [],
            "public_exposure": "",
            "removal_plan": "",
        }

    def _blank_field_detail(self, findings: list, dep: str) -> str:
        details = [
            finding.detail
            for finding in findings
            if finding.code == "DEP-003"
            and dep in finding.detail
            and "is missing valid fields:" in finding.detail
        ]
        self.assertEqual(len(details), 1, f"expected exactly one blank-value finding for '{dep}'")
        return details[0].split("is missing valid fields:", 1)[1]

    @staticmethod
    def _named_fields(named: str) -> set[str]:
        return {part.strip() for part in named.split(",") if part.strip()}

    def test_empty_direct_disposition_rejected(self) -> None:
        manifest_fixture = self._rust_disposition_fixture(self._empty_rust_disposition())
        findings = check_cargo_inventory(manifest_fixture, {"serde"})
        self.assertTrue(findings, "an all-empty disposition must not verify")
        named = self._named_fields(self._blank_field_detail(findings, "serde"))
        self.assertEqual(named, set(self._DISPOSITION_BLANK_FIELDS))
        self.assertNotEqual(derive_overall_status(vdp.STATUS_PASS, findings), STATUS_PASS)

    def test_whitespace_only_direct_disposition_field_rejected(self) -> None:
        for blank in ("   ", "\t", "\n", " \t\n "):
            entry = self._populated_rust_disposition()
            entry["owner"] = blank
            with self.subTest(owner=repr(blank)):
                findings = check_cargo_inventory(self._rust_disposition_fixture(entry), {"serde"})
                self.assertTrue(findings, "a whitespace-only owner must not verify")
                named = self._named_fields(self._blank_field_detail(findings, "serde"))
                self.assertEqual(named, {"owner"})

    def test_populated_direct_disposition_accepted(self) -> None:
        manifest_fixture = self._rust_disposition_fixture(self._populated_rust_disposition())
        self.assertEqual(check_cargo_inventory(manifest_fixture, {"serde"}), [])

    def test_removed_inventory_key_still_reported_as_missing_field(self) -> None:
        entry = self._populated_rust_disposition()
        del entry["removal_plan"]
        findings = check_cargo_inventory(self._rust_disposition_fixture(entry), {"serde"})
        self.assertTrue(
            any(
                finding.code == "DEP-003"
                and "missing required field" in finding.detail
                and "removal_plan" in finding.detail
                for finding in findings
            ),
            findings,
        )

    def test_blank_feature_name_rejected(self) -> None:
        entry = self._populated_rust_disposition()
        entry["features"] = ["  "]
        findings = check_cargo_inventory(self._rust_disposition_fixture(entry), {"serde"})
        self.assertIn("features", self._blank_field_detail(findings, "serde"))

    def test_non_ecosystem_disposition_entry_rejected_without_features(self) -> None:
        # A nuget entry holding only ecosystem+version yields zero findings
        # today: check_cargo_inventory only ever sees the Rust direct set.
        manifest_fixture = {
            "direct_dependencies": {
                "Microsoft.WindowsAppSDK": {"ecosystem": "nuget", "version": "2.3.1"}
            }
        }
        findings = check_inventory_disposition_evidence(manifest_fixture)
        named = self._named_fields(self._blank_field_detail(findings, "Microsoft.WindowsAppSDK"))
        self.assertEqual(named, set(self._DISPOSITION_BLANK_FIELDS))
        self.assertNotEqual(derive_overall_status(vdp.STATUS_PASS, findings), STATUS_PASS)

    def test_declared_inventory_entries_carry_populated_dispositions(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        _, manifest_data = check_policy_manifest(repo_root)
        # Every entry the manifest declares carries a populated disposition,
        # for every ecosystem.
        self.assertEqual(check_inventory_disposition_evidence(manifest_data), [])
        # The Rust gate must stay silent on exactly the declared Rust roots.
        rust_roots = {
            name
            for name, entry in manifest_data["direct_dependencies"].items()
            if isinstance(entry, dict) and entry.get("ecosystem") == "rust"
        }
        self.assertTrue(rust_roots)
        self.assertEqual(check_cargo_inventory(manifest_data, rust_roots), [])

    # --- issue #1229 A6: advisory exception evidence ---

    _EXCEPTION_BLANK_FIELDS = ("owner", "compensating_control", "removal_condition", "expires_at")

    def _exception_fixture(self, entry: dict) -> dict:
        return {"exceptions": [entry]}

    def _populated_exception(self) -> dict:
        return {
            "package": "vuln-pkg",
            "version": "1.0.0",
            "advisory": "RUSTSEC-2020-0001",
            "owner": "security",
            "compensating_control": "isolated",
            "expires_at": "2027-01-01T00:00:00Z",
            "removal_condition": "replace",
        }

    def _exception_blank_detail(self, findings: list, pkg: str) -> str:
        details = [
            finding.detail
            for finding in findings
            if finding.code == "DEP-010"
            and f"exception for package '{pkg}' is missing valid fields:" in finding.detail
        ]
        self.assertEqual(len(details), 1, f"expected exactly one blank-evidence finding for '{pkg}'")
        return details[0].split("is missing valid fields:", 1)[1]

    def test_empty_exception_evidence_rejected(self) -> None:
        entry = self._populated_exception()
        for field in self._EXCEPTION_BLANK_FIELDS:
            entry[field] = ""
        findings = check_exceptions(self._exception_fixture(entry), now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc))
        self.assertTrue(findings, "an exception with no evidence must not verify")
        named = self._named_fields(self._exception_blank_detail(findings, "vuln-pkg"))
        self.assertEqual(named, set(self._EXCEPTION_BLANK_FIELDS))
        self.assertNotEqual(derive_overall_status(vdp.STATUS_PASS, findings), STATUS_PASS)

    def test_whitespace_only_exception_evidence_rejected(self) -> None:
        for blank in ("   ", "\t", "\n", " \t\n "):
            entry = self._populated_exception()
            for field in self._EXCEPTION_BLANK_FIELDS:
                entry[field] = blank
            with self.subTest(blank=repr(blank)):
                findings = check_exceptions(
                    self._exception_fixture(entry), now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc)
                )
                named = self._named_fields(self._exception_blank_detail(findings, "vuln-pkg"))
                self.assertEqual(named, set(self._EXCEPTION_BLANK_FIELDS))

    def test_empty_exception_expiry_is_a_finding_not_a_skip(self) -> None:
        # An exception MUST carry an expiry: docs/DEPENDENCY_POLICY.md:44
        # ("Advisory and license exceptions are explicit and scoped"), the
        # manifest header ("owned, expiring and invalidated by drift"), and
        # the module docstring ("Structured expiring exceptions"). An empty
        # expires_at used to skip the expiry branch entirely, so the exception
        # was neither owned, nor expiring, nor bounded.
        entry = self._populated_exception()
        entry["expires_at"] = ""
        findings = check_exceptions(self._exception_fixture(entry), now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc))
        named = self._named_fields(self._exception_blank_detail(findings, "vuln-pkg"))
        self.assertEqual(named, {"expires_at"})

    def test_populated_expired_exception_still_reports_expiry(self) -> None:
        entry = self._populated_exception()
        entry["expires_at"] = "2020-01-01T00:00:00Z"
        findings = check_exceptions(self._exception_fixture(entry), now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc))
        self.assertTrue(
            any(finding.code == "DEP-010" and "expired on 2020-01-01T00:00:00Z" in finding.detail for finding in findings),
            findings,
        )

    def test_populated_drifted_exception_still_reports_drift(self) -> None:
        denominator = {
            "rust": {"locked_packages": [{"name": "serde", "version": "1.0.228"}]},
            "nuget": {"locked_packages": []},
            "python": {"locked_packages": []},
        }
        drifted = self._exception_fixture(self._populated_exception())
        drifted["exceptions"][0].update(
            {"package": "serde", "version": "9.9.9", "advisory": "RUSTSEC-2026-0001"}
        )
        findings = check_exception_lock_drift(drifted, denominator)
        self.assertTrue(
            any(
                finding.code == "DEP-010" and "drifted from version '9.9.9'" in finding.detail
                for finding in findings
            ),
            findings,
        )

    def test_bound_exception_passes_drift_join(self) -> None:
        denominator = {
            "rust": {"locked_packages": [{"name": "serde", "version": "1.0.228"}]},
            "nuget": {"locked_packages": []},
            "python": {"locked_packages": []},
        }
        bound = self._exception_fixture(self._populated_exception())
        bound["exceptions"][0].update({"package": "serde", "version": "1.0.228"})
        self.assertEqual(check_exception_lock_drift(bound, denominator), [])

    def test_blank_exception_identity_is_not_skipped_by_drift_join(self) -> None:
        # The drift join used to `continue` past an exception whose
        # package/version were not non-empty strings, so blank identity was
        # never bound to a lock at all.
        denominator = {
            "rust": {"locked_packages": [{"name": "serde", "version": "1.0.228"}]},
            "nuget": {"locked_packages": []},
            "python": {"locked_packages": []},
        }
        entry = self._populated_exception()
        entry["package"] = "  "
        entry["version"] = ""
        findings = check_exception_lock_drift(self._exception_fixture(entry), denominator)
        self.assertTrue(
            any(
                finding.code == "DEP-010"
                and "cannot be bound" in finding.detail
                and "package and version must be non-empty strings" in finding.detail
                for finding in findings
            ),
            findings,
        )

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
