"""Unit tests for dependency admission policy verifier (issue #1229)."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
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


def receipt_digest_of(receipt: dict) -> str:
    """Recompute the canonical receipt digest an artifact envelope must carry."""

    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


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

    # --- issue #1229: the SBOM artifact path must publish no disposition
    #     the validator refuses ---
    #
    # `_inventory_disposition` and `build_sbom_artifact` re-read the raw
    # config table rather than reusing the validator's verdict, so "the
    # validator refuses" is not on its own proof that the artifact is safe.
    # These cases drive the real artifact path over a real `build_receipt`
    # and assert the published component disposition directly.

    _RUST_DENOMINATOR = {
        "status": "complete",
        "rust": {
            "direct_dependencies": ["serde"],
            "locked_packages": [
                {
                    "name": "serde",
                    "version": "1.0.228",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "checksum": "a" * 64,
                    "dependencies": [],
                }
            ],
        },
    }

    def _artifact_root(self) -> Path:
        """A minimal, self-contained root whose policy inputs all exist.

        `build_receipt` binds real input digests, a real source commit and the
        configured Node surface from the root it is given, so the receipt
        carries this case's status only when every input it reads is present
        and bound.
        """

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "config").mkdir()
        (root / "scripts").mkdir()
        (root / "integrations").mkdir()
        (root / "Cargo.lock").write_text("# empty lock\n", encoding="utf-8")
        (root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        (root / "deny.toml").write_text('[licenses]\nallow = ["MIT"]\n', encoding="utf-8")
        (root / "config" / "dependency-policy.toml").write_text(
            "schema = 'eliot.dependency-policy.v1'\n", encoding="utf-8"
        )
        (root / "scripts" / "requirements-verification.txt").write_text(
            "jsonschema==4.25.1 --hash=sha256:" + "0" * 64 + "\n", encoding="utf-8"
        )
        (root / "scripts" / "verify-dependency-policy.py").write_text("# verifier\n", encoding="utf-8")
        # The receipt binds a real source commit, so the fixture root is a real
        # repository with one committed revision rather than an unprovenanced
        # or uncommitted directory.
        subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True, text=True)
        subprocess.run(
            ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@e.invalid",
             "commit", "--quiet", "--allow-empty", "-m", "fixture"],
            check=True,
            capture_output=True,
            text=True,
        )
        return root

    def _receipt_for(self, manifest_fixture: dict, findings: list, *, prepare=None) -> dict:
        """Build the executed receipt the artifact path actually consumes.

        The receipt is built over an isolated minimal root so that the only
        findings in it are the ones this case supplies: `build_receipt` binds
        real input digests, a real source commit and the configured Node surface
        from the root it is given, so the repository root would otherwise
        contribute findings unrelated to this case.

        `prepare` receives that root so a case whose manifest declares further
        real inputs (an external-executable catalogue, a provisioning receipt)
        can materialise them instead of carrying an unrelated DEP-013
        missing-input finding into a status assertion.
        """

        root = self._artifact_root()
        contract = root / "integrations" / "plugin-bridge-contract.json"
        contract.write_text(json.dumps({"surface": "integrations/surface.js"}) + "\n", encoding="utf-8")
        (root / "integrations" / "surface.js").write_text("// no external imports\n", encoding="utf-8")
        if prepare is not None:
            prepare(root)

        manifest_with_inputs = dict(manifest_fixture)
        manifest_with_inputs["ecosystems"] = {
            "rust": {
                "manifest": "Cargo.toml",
                "lockfile": "Cargo.lock",
                "policy_file": "deny.toml",
                "targets": ["x86_64-pc-windows-msvc"],
                "features": ["--all-features"],
            },
            "node": {
                "contract": "integrations/plugin-bridge-contract.json",
                "package_root": "integrations",
            },
        }
        manifest_with_inputs.setdefault("exceptions", [])
        manifest_with_inputs.setdefault("external_executables", {})
        manifest_with_inputs["scanner"] = {
            "tool": "cargo-deny",
            "version": "0.20.2",
            "executable": "cargo-deny",
            "sha256": "a" * 64,
            "advisory_owner": "cargo-deny-advisories",
            "checks": ["advisories", "bans", "licenses", "sources"],
        }

        return build_receipt(
            root,
            "offline-source",
            derive_overall_status(vdp.STATUS_PASS, findings),
            list(findings),
            manifest_with_inputs,
            {"bans": {"errors": 0}},
            1,
            ecosystem_denominator=dict(self._RUST_DENOMINATOR),
        )

    def _serde_component(self, sbom: dict) -> dict:
        matches = [c for c in sbom["components"] if c.get("name") == "serde"]
        self.assertEqual(len(matches), 1, sbom["components"])
        return matches[0]

    @staticmethod
    def _is_empty_disposition(disposition: object) -> bool:
        if not isinstance(disposition, dict):
            return False
        return all(
            value in (None, "", [], {})
            for key, value in disposition.items()
            if key != "platform_scope"
        )

    def _assert_no_empty_disposition_under_pass(self, receipt: dict, manifest_fixture: dict) -> None:
        """The security property: no admitted dependency publishes a blank disposition.

        A blank disposition can only reach a downstream reader through an
        artifact whose envelope says PASS, so this drives the same artifact path
        with the ONLY difference that matters -- the executed verdict -- and
        asserts the disposition is published verbatim when the gate passes.
        """

        passing = self._receipt_for(manifest_fixture, [])
        self.assertEqual(passing["status"], STATUS_PASS)
        sbom = vdp.build_sbom_artifact(passing, manifest_fixture)
        self.assertEqual(sbom["status"], STATUS_PASS)
        offending = [
            c
            for c in sbom["components"]
            if c.get("direct") and self._is_empty_disposition(c.get("disposition"))
        ]
        self.assertEqual(offending, [], "a PASSING gate must publish no empty disposition")

    def test_sbom_never_publishes_an_empty_direct_disposition(self) -> None:
        # An all-empty direct-dependency disposition is a DEP-003 finding, so
        # the executed receipt is INCOMPLETE and the artifact can never present
        # itself as the disclosure of an admitted dependency: a passing gate is
        # the only thing that would let a blank disposition ship, and the
        # validator refuses it first.
        manifest_fixture = self._rust_disposition_fixture(self._empty_rust_disposition())
        findings = check_cargo_inventory(manifest_fixture, {"serde"})
        findings += check_inventory_disposition_evidence(manifest_fixture)
        self.assertTrue(findings, "an all-empty disposition must not verify")

        receipt = self._receipt_for(manifest_fixture, findings)
        self.assertNotEqual(receipt["status"], STATUS_PASS)
        sbom = vdp.build_sbom_artifact(receipt, manifest_fixture)
        self.assertNotEqual(sbom["status"], STATUS_PASS)
        # The artifact faithfully carries the executed verdict; it cannot launder
        # the refused disposition into a PASS.
        self.assertEqual(sbom["status"], receipt["status"])
        self.assertEqual(sbom["receipt_digest"], receipt_digest_of(receipt))
        # The refused blank values may still be visible, but only under a
        # non-PASS envelope: an admitted dependency never carries one.
        self._assert_no_empty_disposition_under_pass(receipt, manifest_fixture)

    def test_sbom_disposition_is_populated_evidence_when_accepted(self) -> None:
        # The positive control: the same artifact path on a populated
        # disposition publishes the real evidence, so the refusal above is a
        # property of the empty evidence and not of the artifact shape.
        manifest_fixture = self._rust_disposition_fixture(self._populated_rust_disposition())
        findings = check_cargo_inventory(manifest_fixture, {"serde"})
        self.assertEqual(findings, [])

        sbom = vdp.build_sbom_artifact(self._receipt_for(manifest_fixture, findings), manifest_fixture)
        disposition = self._serde_component(sbom).get("disposition")
        self.assertFalse(self._is_empty_disposition(disposition))
        self.assertEqual(disposition["consumer"], "crates/foundation/eliot-evidence")
        self.assertEqual(disposition["owner"], "crates/foundation/eliot-evidence")
        self.assertEqual(disposition["features"], list(_POPULATED_FEATURES))

    def test_sbom_never_publishes_an_empty_non_ecosystem_disposition(self) -> None:
        # `check_cargo_inventory` only ever sees the Rust direct set, so the
        # NuGet row reaches the SBOM through `check_inventory_disposition_evidence`.
        manifest_fixture = {
            "direct_dependencies": {
                "Microsoft.WindowsAppSDK": {
                    "ecosystem": "nuget",
                    "version": "2.3.1",
                    "consumer": "",
                    "owner": "",
                    "reason": "",
                    "public_exposure": "",
                    "removal_plan": "",
                }
            },
            "exceptions": [],
            "external_executables": {},
        }
        findings = check_inventory_disposition_evidence(manifest_fixture)
        self.assertTrue(findings, "an all-empty non-Rust disposition must not verify")

        receipt = self._receipt_for(manifest_fixture, findings)
        self.assertNotEqual(receipt["status"], STATUS_PASS)
        sbom = vdp.build_sbom_artifact(receipt, manifest_fixture)
        self.assertNotEqual(sbom["status"], STATUS_PASS)
        self.assertEqual(sbom["status"], receipt["status"])
        self._assert_no_empty_disposition_under_pass(receipt, manifest_fixture)

    def test_sbom_omits_a_disposition_the_validator_refused(self) -> None:
        # `_inventory_disposition` reuses the validator's own rule
        # (`_malformed_disposition_fields` plus the missing-required-field set
        # that `check_inventory_disposition_evidence` rejects), so a refused
        # disposition is reported as absent rather than published as blank
        # evidence. The artifact never emits an all-empty disposition, whatever
        # verdict the enclosing run carries.
        manifest_fixture = self._rust_disposition_fixture(self._empty_rust_disposition())
        findings = check_cargo_inventory(manifest_fixture, {"serde"})
        findings += check_inventory_disposition_evidence(manifest_fixture)
        self.assertTrue(findings, "an all-empty disposition must not verify")

        receipt = self._receipt_for(manifest_fixture, findings)
        sbom = vdp.build_sbom_artifact(receipt, manifest_fixture)
        disposition = self._serde_component(sbom).get("disposition")
        self.assertIsNone(disposition, "a refused disposition must be omitted, not published blank")
        # The direct-binding refusal is independent of the run's verdict: even a
        # hand-built PASS receipt over the same empty entry cannot publish it.
        passing_receipt = self._receipt_for(manifest_fixture, [])
        self.assertEqual(passing_receipt["status"], STATUS_PASS)
        passing_sbom = vdp.build_sbom_artifact(passing_receipt, manifest_fixture)
        self.assertIsNone(self._serde_component(passing_sbom).get("disposition"))

    def test_sbom_publishes_every_field_of_a_populated_disposition(self) -> None:
        # The positive control: a fully populated entry is validated and then
        # published with every field present, so the refusal above is a property
        # of the empty evidence and not of the artifact shape.
        manifest_fixture = self._rust_disposition_fixture(self._populated_rust_disposition())
        self.assertEqual(check_cargo_inventory(manifest_fixture, {"serde"}), [])
        self.assertEqual(check_inventory_disposition_evidence(manifest_fixture), [])

        receipt = self._receipt_for(manifest_fixture, [])
        self.assertEqual(receipt["status"], STATUS_PASS)
        sbom = vdp.build_sbom_artifact(receipt, manifest_fixture)
        disposition = self._serde_component(sbom).get("disposition")
        self.assertIsInstance(disposition, dict)
        self.assertEqual(disposition["consumer"], "crates/foundation/eliot-evidence")
        self.assertEqual(disposition["owner"], "crates/foundation/eliot-evidence")
        self.assertEqual(disposition["reason"], "serde derive for canonical evidence records")
        self.assertEqual(disposition["features"], list(_POPULATED_FEATURES))
        self.assertEqual(disposition["platform_scope"], "all_configured_targets")
        self.assertEqual(disposition["public_exposure"], "none")
        self.assertEqual(disposition["removal_plan"], "hand-rolled serialization")
        self.assertFalse(self._is_empty_disposition(disposition))

    def test_advisory_report_publishes_the_exception_binding_check(self) -> None:
        # `check_exception_lock_drift` replaced a silent `continue` with a
        # binding finding; the advisory report publishes exactly the DEP-010
        # findings of the receipt that produced it, so the new check reaches
        # the artifact instead of stopping inside the validator.
        denominator = {"rust": {"locked_packages": [{"name": "serde", "version": "1.0.228"}]}}
        entry = self._populated_exception()
        entry["package"] = "  "
        entry["version"] = ""
        manifest_fixture = self._exception_fixture(entry)
        findings = check_exceptions(
            manifest_fixture, now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc)
        )
        findings += check_exception_lock_drift(manifest_fixture, denominator)
        binding = [
            f for f in findings if f.code == "DEP-010" and "cannot be bound" in f.detail
        ]
        self.assertTrue(binding, findings)

        receipt = self._receipt_for(manifest_fixture, findings)
        report = vdp.build_advisory_report_artifact(receipt, manifest_fixture)
        self.assertNotEqual(report["status"], STATUS_PASS)
        published = {finding["detail"] for finding in report["exception_findings"]}
        self.assertIn(binding[0].detail, published)

    def test_advisory_report_refuses_an_all_empty_exception(self) -> None:
        entry = self._populated_exception()
        for field in self._EXCEPTION_BLANK_FIELDS:
            entry[field] = ""
        manifest_fixture = self._exception_fixture(entry)
        findings = check_exceptions(
            manifest_fixture, now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc)
        )
        self.assertTrue(findings, "an exception with no evidence must not verify")

        receipt = self._receipt_for(manifest_fixture, findings)
        report = vdp.build_advisory_report_artifact(receipt, manifest_fixture)
        self.assertNotEqual(report["status"], STATUS_PASS)
        self.assertTrue(report["exception_findings"])
        # The digest binds exactly the exception state the artifact publishes,
        # which no longer carries the refused row (see
        # `test_advisory_report_publishes_no_blank_exception_value`).
        self.assertEqual(report["exceptions"], [])
        self.assertEqual(
            report["exceptions_digest"], vdp._canonical_digest(report["exceptions"])
        )

    # --- `[external_executables]`: the same value channel as a direct
    #     dependency, on the surface docs/DEPENDENCY_POLICY.md:120-121
    #     governs separately ("inventoried with version, digest, license,
    #     trust model, and removal boundary") ---

    def _materialize_external_inputs(self, entry: dict):
        """Create the real inputs an `[external_executables]` entry declares.

        `build_receipt` binds every declared external-executable input, so the
        catalogue path and the provisioning receipt must exist in the fixture
        root or the receipt carries an unrelated DEP-013 missing-input finding
        and stops being a PASS.
        """

        def prepare(root: Path) -> None:
            catalog = root / Path(entry["catalog"])
            catalog.parent.mkdir(parents=True, exist_ok=True)
            catalog.write_text("{}\n", encoding="utf-8")
            provisioning = root / ".eliot" / "dependency-policy" / "surrealdb"
            provisioning.mkdir(parents=True, exist_ok=True)
            (provisioning / "provisioning-receipt.json").write_text("{}\n", encoding="utf-8")

        return prepare

    def _external_receipt_for(self, manifest_fixture: dict, findings: list) -> dict:
        entry = manifest_fixture["external_executables"]["surrealdb"]
        return self._receipt_for(manifest_fixture, findings, prepare=self._materialize_external_inputs(entry))

    def _external_executable_fixture(self, entry: dict) -> dict:
        return {"external_executables": {"surrealdb": entry}}

    def _populated_external_executable(self) -> dict:
        return {
            "name": "surreal.exe",
            "version": "3.1.4",
            "license": "BSL-1.1",
            "sha256": "b" * 64,
            "catalog": "docs/release/SURREALDB_WINDOWS_X64.lock.json",
            "release_asset": "https://example.invalid/surreal-v3.1.4.windows-amd64.exe",
            "consumer": "crates/storage/eliot-store-surreal",
            "owner": "crates/storage/eliot-store-surreal",
            "trust_model": "local-loopback-service-only",
            "removal_boundary": "pluggable-storage-facade",
            "advisory_findings": ["GHSA-848m-r628-vrxw"],
        }

    def _blank_external_executable(self) -> dict:
        entry = self._populated_external_executable()
        for field in self._EXTERNAL_DISPOSITION_FIELDS:
            entry[field] = ""
        return entry

    def _external_component(self, sbom: dict) -> dict:
        matches = [c for c in sbom["components"] if c.get("ecosystem") == "external-executable"]
        self.assertEqual(len(matches), 1, sbom["components"])
        return matches[0]

    def test_sbom_never_publishes_an_empty_external_executable_disposition(self) -> None:
        # The only gate on `[external_executables]` is a presence-only loop in
        # `_collect_external_evidence` (`for req in required: if req not in
        # surreal`), so all four disposition fields present-but-empty reaches
        # the SBOM as blank evidence. `_external_executable_disposition`
        # reuses the same `_malformed_disposition_fields` rule the
        # `direct_dependencies` join uses, so a blank entry is reported absent
        # whatever verdict the enclosing run carries.
        manifest_fixture = self._external_executable_fixture(self._blank_external_executable())
        entry = manifest_fixture["external_executables"]["surrealdb"]
        self.assertEqual(
            vdp._external_executable_disposition(entry),
            None,
            "a blank external-executable disposition must not be published",
        )

        # Every disposition field is blank under the presence-only gate, so
        # that gate alone cannot report the entry; the SBOM path is the guard
        # under test and must be silent about the blank values.
        receipt = self._external_receipt_for(manifest_fixture, [])
        self.assertEqual(receipt["status"], STATUS_PASS)
        sbom = vdp.build_sbom_artifact(receipt, manifest_fixture)
        component = self._external_component(sbom)
        self.assertIsNone(
            component.get("disposition"), "a blank external disposition must be omitted, not published blank"
        )
        # The component itself is still published, so a reader sees the
        # executable and its absence of validated disposition rather than a
        # fabricated blank one.
        self.assertEqual(component["name"], "surreal.exe")
        self.assertEqual(component["version"], "3.1.4")

    def test_sbom_publishes_every_field_of_a_populated_external_executable(self) -> None:
        # The positive control: a fully populated external executable publishes
        # every disposition field, so the refusal above is a property of the
        # blank evidence and not of the artifact shape.
        manifest_fixture = self._external_executable_fixture(self._populated_external_executable())
        self.assertEqual(
            vdp._external_executable_disposition(
                manifest_fixture["external_executables"]["surrealdb"]
            ),
            {
                "consumer": "crates/storage/eliot-store-surreal",
                "owner": "crates/storage/eliot-store-surreal",
                "trust_model": "local-loopback-service-only",
                "removal_boundary": "pluggable-storage-facade",
                "advisory_ids": ["GHSA-848m-r628-vrxw"],
            },
        )

        receipt = self._external_receipt_for(manifest_fixture, [])
        self.assertEqual(receipt["status"], STATUS_PASS)
        sbom = vdp.build_sbom_artifact(receipt, manifest_fixture)
        component = self._external_component(sbom)
        self.assertEqual(component["name"], "surreal.exe")
        self.assertEqual(component["version"], "3.1.4")
        self.assertEqual(component["license"], "BSL-1.1")
        self.assertEqual(component["integrity"]["digest"], "b" * 64)
        disposition = component.get("disposition")
        self.assertIsInstance(disposition, dict)
        for field, value in (
            ("consumer", "crates/storage/eliot-store-surreal"),
            ("owner", "crates/storage/eliot-store-surreal"),
            ("trust_model", "local-loopback-service-only"),
            ("removal_boundary", "pluggable-storage-facade"),
        ):
            self.assertEqual(disposition[field], value)
        self.assertEqual(disposition["advisory_ids"], ["GHSA-848m-r628-vrxw"])
        self.assertFalse(self._is_empty_disposition(disposition))

    def test_advisory_report_publishes_no_blank_exception_value(self) -> None:
        # `build_advisory_report_artifact` published the RAW table, so an
        # all-empty exception shipped its blank owner/control/expiry verbatim.
        # `_validated_exceptions` reuses the validator's own
        # `_EXCEPTION_REQUIRED_FIELDS` rule, so a refused row is reported as
        # absent; the DEP-010 verdict channel still publishes the finding.
        entry = self._populated_exception()
        for field in self._EXCEPTION_BLANK_FIELDS:
            entry[field] = ""
        manifest_fixture = self._exception_fixture(entry)
        findings = check_exceptions(
            manifest_fixture, now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc)
        )
        self.assertTrue(findings, "an exception with no evidence must not verify")

        receipt = self._receipt_for(manifest_fixture, findings)
        self.assertEqual(receipt["exceptions"], [], "a refused exception must not enter the bound state")
        report = vdp.build_advisory_report_artifact(receipt, manifest_fixture)
        self.assertEqual(report["exceptions"], [])
        self.assertEqual(
            report["exceptions_digest"], vdp._canonical_digest(report["exceptions"])
        )
        # The verdict channel is untouched by the value-channel guard.
        self.assertTrue(report["exception_findings"])
        self.assertIn(findings[0].detail, {f["detail"] for f in report["exception_findings"]})

    def test_advisory_report_publishes_a_validated_exception_verbatim(self) -> None:
        # The positive control: a fully populated, unexpired exception is
        # published verbatim and its digest still binds the published rows.
        manifest_fixture = self._exception_fixture(self._populated_exception())
        self.assertEqual(
            check_exceptions(manifest_fixture, now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc)), []
        )

        receipt = self._receipt_for(manifest_fixture, [])
        self.assertEqual(receipt["exceptions"], manifest_fixture["exceptions"])
        self.assertEqual(
            receipt["exceptions_digest"], vdp._canonical_digest(manifest_fixture["exceptions"])
        )
        report = vdp.build_advisory_report_artifact(receipt, manifest_fixture)
        self.assertEqual(report["exceptions"], manifest_fixture["exceptions"])
        self.assertEqual(
            report["exceptions_digest"], vdp._canonical_digest(report["exceptions"])
        )
        self.assertEqual(report["exception_findings"], [])

    def test_advisory_report_keeps_the_digest_bound_to_the_published_state(self) -> None:
        # The digest must bind exactly the rows the artifact publishes, so a
        # reader can recompute it from `exceptions` alone.
        populated = self._exception_fixture(self._populated_exception())
        refused = self._populated_exception()
        for field in self._EXCEPTION_BLANK_FIELDS:
            refused[field] = "  "
        mixed = {"exceptions": [self._populated_exception(), refused]}

        for manifest_fixture in (populated, mixed):
            findings = check_exceptions(
                manifest_fixture, now_dt=datetime(2026, 9, 13, tzinfo=timezone.utc)
            )
            receipt = self._receipt_for(manifest_fixture, findings)
            report = vdp.build_advisory_report_artifact(receipt, manifest_fixture)
            self.assertEqual(
                report["exceptions_digest"], vdp._canonical_digest(report["exceptions"])
            )
            # The refused row is the only one dropped from a mixed table.
            self.assertEqual(report["exceptions"], [self._populated_exception()])

    # --- issue #1229 A6: advisory exception evidence ---

    _EXCEPTION_BLANK_FIELDS = ("owner", "compensating_control", "removal_condition", "expires_at")

    # `docs/DEPENDENCY_POLICY.md:120-121`: an external executable is
    # "inventoried with version, digest, license, trust model, and removal
    # boundary"; its consumer/owner come from the shared admission rule
    # (`:11` "a real current consumer and owner").
    _EXTERNAL_DISPOSITION_FIELDS = ("consumer", "owner", "trust_model", "removal_boundary")

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
