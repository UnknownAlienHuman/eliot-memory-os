"""Canonical Python case bindings for work unit #907 (D-INT-CORE harness core).

Declared denominator: exactly 40 cases, 907/1..40, each marked with
``# WORK_UNIT_CASE: 907/<n>`` immediately above its unittest method.

Cases 1-32 execute the corresponding actual PowerShell self-test case through
scripts/integration/powershell_case_bridge.py and assert its structured
result payload (never just exit zero). They require the WRITER-C suite
``scripts/tests/IntegrationHarness.Core.Tests.ps1``; when that file is absent
(as in an isolated writer worktree) the bridge fails closed and these cases
honestly fail -- never fake a pass.

Cases 33-40 test the bridge/containment protocol with bounded deterministic
fixtures under scripts/testdata/integration/harness-core/ only.
"""

from __future__ import annotations

import inspect
import json
import re
import unittest
from pathlib import Path

from scripts.integration import powershell_case_bridge as bridge
from scripts.work_unit_gate import contracts as contracts
from scripts.work_unit_gate import descriptor_runner as runner

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "scripts" / "testdata" / "integration" / "harness-core"

CASE_METHODS = (
    "test_907_01_single_profile_default_launches_nothing",
    "test_907_02_whatif_deterministic_finite_plan",
    "test_907_03_whatif_creates_no_resources",
    "test_907_04_validate_configuration_plan_only",
    "test_907_05_unavailable_prerequisite_vs_invalid_configuration",
    "test_907_06_incomplete_inventory_vs_missing_provider",
    "test_907_07_provider_interface_rejects_arbitrary_methods",
    "test_907_08_provider_revision_and_inventory_digest_load_bearing",
    "test_907_09_unique_run_root_and_owner_receipt",
    "test_907_10_path_escape_and_foreign_root_rejected",
    "test_907_11_exact_group_union_no_implicit_selection",
    "test_907_12_incompatible_groups_rejected",
    "test_907_13_missing_duplicate_identity_blocks_start",
    "test_907_14_exact_invocation_and_zero_match_rejected",
    "test_907_15_prebuilt_binary_receipt_required",
    "test_907_16_observed_process_is_not_readiness",
    "test_907_17_readiness_timeout_blocks_tests",
    "test_907_18_one_terminal_disposition_per_test",
    "test_907_19_pass_requires_executed_receipt",
    "test_907_20_outcome_taxonomy_distinct",
    "test_907_21_no_automatic_retry_first_failure_preserved",
    "test_907_22_recurrence_preserves_every_attempt",
    "test_907_23_reset_contamination_blocks_remainder",
    "test_907_24_wall_idle_timeout_injected_clock",
    "test_907_25_timeout_stops_owned_process_tree",
    "test_907_26_foreign_resources_never_touched",
    "test_907_27_unknown_cleanup_requires_reconciliation",
    "test_907_28_counts_reconcile_exactly",
    "test_907_29_bad_receipts_prevent_complete",
    "test_907_30_fingerprint_stable_and_sensitive",
    "test_907_31_secret_canaries_absent",
    "test_907_32_no_foreign_mutation_reverse_cleanup_preserves_failure",
    "test_907_33_registered_case_binds_python_identity",
    "test_907_34_arbitrary_input_rejected",
    "test_907_35_zero_exit_without_result_fails",
    "test_907_36_duplicate_foreign_missing_skipped_fail",
    "test_907_37_changed_suite_content_invalidates_binding",
    "test_907_38_malformed_truncated_oversized_fail",
    "test_907_39_timeout_cleanup_unknown_cannot_pass",
    "test_907_40_source_identities_and_results_reconcile",
)


def _fixture_bytes(name: str) -> bytes:
    path = FIXTURES / name
    assert path.is_file(), f"fixture missing: {name}"
    return path.read_bytes()


def _fixture_json(name: str):
    return json.loads(_fixture_bytes(name).decode("utf-8"))


class TestIntegrationHarnessCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        payload = _fixture_json("cases.json")
        rows = payload["rows"]
        assert isinstance(rows, list) and len(rows) == 32
        cls.rows = {row["case_id"]: row for row in rows}

    def _row(self, case_id: int) -> dict:
        row = self.rows.get(case_id)
        self.assertIsNotNone(row, f"inventory row missing for 907/{case_id}")
        self.assertEqual(row["case_id"], case_id)
        self.assertTrue(isinstance(row["title"], str) and row["title"].strip(),
                        f"inventory row 907/{case_id} has no title")
        return row

    def _assert_live_result(self, case_id: int, result: bridge.CaseResult) -> None:
        """Real assertions on the returned structured payload, not exit zero."""
        self.assertEqual(result.outcome, "Passed")
        self.assertEqual(result.case_id, case_id)
        self.assertEqual(result.suite, bridge.CORE_SUITE_NAME)
        self.assertEqual(result.schema_version, bridge.SCHEMA_VERSION)
        self.assertEqual(result.identity, f"907/{case_id}")
        self.assertEqual(result.truncated_bytes, 0)
        self.assertEqual(result.bound_python_identity, self.id())
        self.assertEqual(result.returncode, 0)

    def _run_live(self, case_id: int) -> bridge.CaseResult:
        self._row(case_id)
        try:
            result = bridge.run_case(case_id, python_identity=self.id())
        except bridge.HarnessError as exc:
            self.fail(f"honest bridge failure for 907/{case_id} [{exc.code}]: {exc}")
        self._assert_live_result(case_id, result)
        return result

    # WORK_UNIT_CASE: 907/1
    def test_907_01_single_profile_default_launches_nothing(self):
        self._run_live(1)

    # WORK_UNIT_CASE: 907/2
    def test_907_02_whatif_deterministic_finite_plan(self):
        self._run_live(2)

    # WORK_UNIT_CASE: 907/3
    def test_907_03_whatif_creates_no_resources(self):
        self._run_live(3)

    # WORK_UNIT_CASE: 907/4
    def test_907_04_validate_configuration_plan_only(self):
        self._run_live(4)

    # WORK_UNIT_CASE: 907/5
    def test_907_05_unavailable_prerequisite_vs_invalid_configuration(self):
        self._run_live(5)

    # WORK_UNIT_CASE: 907/6
    def test_907_06_incomplete_inventory_vs_missing_provider(self):
        self._run_live(6)

    # WORK_UNIT_CASE: 907/7
    def test_907_07_provider_interface_rejects_arbitrary_methods(self):
        self._run_live(7)

    # WORK_UNIT_CASE: 907/8
    def test_907_08_provider_revision_and_inventory_digest_load_bearing(self):
        self._run_live(8)

    # WORK_UNIT_CASE: 907/9
    def test_907_09_unique_run_root_and_owner_receipt(self):
        self._run_live(9)

    # WORK_UNIT_CASE: 907/10
    def test_907_10_path_escape_and_foreign_root_rejected(self):
        self._run_live(10)

    # WORK_UNIT_CASE: 907/11
    def test_907_11_exact_group_union_no_implicit_selection(self):
        self._run_live(11)

    # WORK_UNIT_CASE: 907/12
    def test_907_12_incompatible_groups_rejected(self):
        self._run_live(12)

    # WORK_UNIT_CASE: 907/13
    def test_907_13_missing_duplicate_identity_blocks_start(self):
        self._run_live(13)

    # WORK_UNIT_CASE: 907/14
    def test_907_14_exact_invocation_and_zero_match_rejected(self):
        self._run_live(14)

    # WORK_UNIT_CASE: 907/15
    def test_907_15_prebuilt_binary_receipt_required(self):
        self._run_live(15)

    # WORK_UNIT_CASE: 907/16
    def test_907_16_observed_process_is_not_readiness(self):
        self._run_live(16)

    # WORK_UNIT_CASE: 907/17
    def test_907_17_readiness_timeout_blocks_tests(self):
        self._run_live(17)

    # WORK_UNIT_CASE: 907/18
    def test_907_18_one_terminal_disposition_per_test(self):
        self._run_live(18)

    # WORK_UNIT_CASE: 907/19
    def test_907_19_pass_requires_executed_receipt(self):
        self._run_live(19)

    # WORK_UNIT_CASE: 907/20
    def test_907_20_outcome_taxonomy_distinct(self):
        self._run_live(20)

    # WORK_UNIT_CASE: 907/21
    def test_907_21_no_automatic_retry_first_failure_preserved(self):
        self._run_live(21)

    # WORK_UNIT_CASE: 907/22
    def test_907_22_recurrence_preserves_every_attempt(self):
        self._run_live(22)

    # WORK_UNIT_CASE: 907/23
    def test_907_23_reset_contamination_blocks_remainder(self):
        self._run_live(23)

    # WORK_UNIT_CASE: 907/24
    def test_907_24_wall_idle_timeout_injected_clock(self):
        self._run_live(24)

    # WORK_UNIT_CASE: 907/25
    def test_907_25_timeout_stops_owned_process_tree(self):
        self._run_live(25)

    # WORK_UNIT_CASE: 907/26
    def test_907_26_foreign_resources_never_touched(self):
        self._run_live(26)

    # WORK_UNIT_CASE: 907/27
    def test_907_27_unknown_cleanup_requires_reconciliation(self):
        self._run_live(27)

    # WORK_UNIT_CASE: 907/28
    def test_907_28_counts_reconcile_exactly(self):
        self._run_live(28)

    # WORK_UNIT_CASE: 907/29
    def test_907_29_bad_receipts_prevent_complete(self):
        self._run_live(29)

    # WORK_UNIT_CASE: 907/30
    def test_907_30_fingerprint_stable_and_sensitive(self):
        self._run_live(30)

    # WORK_UNIT_CASE: 907/31
    def test_907_31_secret_canaries_absent(self):
        self._run_live(31)

    # WORK_UNIT_CASE: 907/32
    def test_907_32_no_foreign_mutation_reverse_cleanup_preserves_failure(self):
        self._run_live(32)

    # WORK_UNIT_CASE: 907/33
    def test_907_33_registered_case_binds_python_identity(self):
        try:
            result = bridge.run_case(1, python_identity=self.id())
        except bridge.HarnessError as exc:
            self.fail(f"honest bridge failure for 907/33 [{exc.code}]: {exc}")
        self.assertEqual(result.bound_python_identity, self.id())
        self.assertEqual(result.case_id, 1)
        self.assertEqual(result.identity, "907/1")
        binding = bridge.resolve_case(suite_path=bridge.CORE_SUITE_PATH,
                                      case_id=1)
        self.assertEqual(result.content_digest, binding.content_digest)

    # WORK_UNIT_CASE: 907/34
    def test_907_34_arbitrary_input_rejected(self):
        rejected = _fixture_json("rejected-requests.json")
        for suite_path in rejected["unregistered_suites"]:
            with self.assertRaises(bridge.HarnessError, msg=suite_path):
                bridge.resolve_case(suite_path=suite_path, case_id=1)
        for suite_path in rejected["not_executable_here"]:
            with self.assertRaisesRegex(bridge.HarnessError,
                                        "SUITE_NOT_EXECUTABLE_HERE"):
                bridge.resolve_case(suite_path=suite_path, case_id=1)
        for bad_id in (0, 33, -1):
            with self.assertRaises(bridge.HarnessError):
                bridge.resolve_case(suite_path=bridge.CORE_SUITE_PATH,
                                    case_id=bad_id)
        for bad_id in ("1", 1.0, None, True):
            with self.assertRaises(bridge.HarnessError):
                bridge.resolve_case(suite_path=bridge.CORE_SUITE_PATH,
                                    case_id=bad_id)
        # The bridge offers no arbitrary script/executable/argv/environment/
        # working-directory input: the public seam takes only registered ids.
        params = inspect.signature(bridge.run_case).parameters
        self.assertEqual(set(params), {"case_id", "python_identity", "timeout_s"})
        resolve_params = inspect.signature(bridge.resolve_case).parameters
        self.assertNotIn("argv", resolve_params)
        self.assertNotIn("env", resolve_params)
        self.assertNotIn("executable", resolve_params)
        self.assertNotIn("cwd", resolve_params)
        # Tampered argv never reaches a child, even at the contained seam.
        env = bridge._child_env()
        pwsh = bridge._resolve_pwsh(env)
        binding_abs = __import__("os").path.abspath(
            str(ROOT / bridge.CORE_SUITE_PATH))
        good = [pwsh, "-NoProfile", "-NonInteractive", "-File",
                binding_abs, "-CaseId", "1"]
        tampered = list(good)
        tampered[1:3] = ["-Command", "Start-Sleep 30"]
        with self.assertRaises(bridge.HarnessError):
            bridge._run_contained(tampered, timeout_s=5.0, output_cap=16384,
                                  line_cap=4096, child_env=env, pwsh_path=pwsh,
                                  suite_abs=binding_abs, case_id=1)
        wrong_exe = list(good)
        wrong_exe[0] = "C:\\Windows\\System32\\cmd.exe"
        with self.assertRaises(bridge.HarnessError):
            bridge._run_contained(wrong_exe, timeout_s=5.0, output_cap=16384,
                                  line_cap=4096, child_env=env, pwsh_path=pwsh,
                                  suite_abs=binding_abs, case_id=1)

    # WORK_UNIT_CASE: 907/35
    def test_907_35_zero_exit_without_result_fails(self):
        pinned = _fixture_json("payload-ok.json")
        digest = pinned["content_digest"]
        with self.assertRaisesRegex(bridge.HarnessError, "MISSING_RESULT"):
            bridge.verify_result_bytes(_fixture_bytes("empty-output.bin"),
                                       case_id=7,
                                       suite_path=bridge.CORE_SUITE_PATH,
                                       expected_digest=digest,
                                       python_identity=self.id(),
                                       returncode=0)
        with self.assertRaisesRegex(bridge.HarnessError, "SCHEMA_FIELDS"):
            bridge.verify_result_bytes(
                _fixture_bytes("payload-empty-object.json"), case_id=7,
                suite_path=bridge.CORE_SUITE_PATH, expected_digest=digest,
                python_identity=self.id(), returncode=0)

    # WORK_UNIT_CASE: 907/36
    def test_907_36_duplicate_foreign_missing_skipped_fail(self):
        pinned = _fixture_json("payload-ok.json")
        digest = pinned["content_digest"]
        with self.assertRaisesRegex(bridge.HarnessError, "DUPLICATE_RESULT"):
            bridge.verify_result_bytes(_fixture_bytes("payload-duplicate.json"),
                                       case_id=7,
                                       suite_path=bridge.CORE_SUITE_PATH,
                                       expected_digest=digest,
                                       python_identity=self.id(),
                                       returncode=0)
        with self.assertRaisesRegex(bridge.HarnessError,
                                    "RESULT_SUITE_MISMATCH"):
            bridge.verify_result_bytes(_fixture_bytes("payload-foreign.json"),
                                       case_id=7,
                                       suite_path=bridge.CORE_SUITE_PATH,
                                       expected_digest=digest,
                                       python_identity=self.id(),
                                       returncode=0)
        foreign_case = dict(pinned)
        foreign_case["case_id"] = 8
        foreign_case["identity"] = "907/8"
        with self.assertRaisesRegex(bridge.HarnessError,
                                    "RESULT_CASE_MISMATCH"):
            bridge.verify_result_bytes(
                json.dumps(foreign_case).encode("utf-8"), case_id=7,
                suite_path=bridge.CORE_SUITE_PATH, expected_digest=digest,
                python_identity=self.id(), returncode=0)
        with self.assertRaisesRegex(bridge.HarnessError, "OUTCOME_SKIPPED"):
            bridge.verify_result_bytes(_fixture_bytes("payload-skipped.json"),
                                       case_id=9,
                                       suite_path=bridge.CORE_SUITE_PATH,
                                       expected_digest=digest,
                                       python_identity=self.id(),
                                       returncode=0)

    # WORK_UNIT_CASE: 907/37
    def test_907_37_changed_suite_content_invalidates_binding(self):
        pinned = _fixture_json("payload-ok.json")
        digest = pinned["content_digest"]
        # Positive control: the pinned digest binds its own payload.
        ok_result = bridge.verify_result_bytes(
            _fixture_bytes("payload-ok.json"), case_id=7,
            suite_path=bridge.CORE_SUITE_PATH, expected_digest=digest,
            python_identity=self.id(), returncode=0)
        self.assertEqual(ok_result.outcome, "Passed")
        self.assertEqual(ok_result.content_digest, digest)
        # Changed content invalidates the binding.
        with self.assertRaisesRegex(bridge.HarnessError,
                                    "RESULT_DIGEST_MISMATCH"):
            bridge.verify_result_bytes(
                _fixture_bytes("payload-digest-mismatch.json"), case_id=7,
                suite_path=bridge.CORE_SUITE_PATH, expected_digest=digest,
                python_identity=self.id(), returncode=0)

    # WORK_UNIT_CASE: 907/38
    def test_907_38_malformed_truncated_oversized_fail(self):
        pinned = _fixture_json("payload-ok.json")
        digest = pinned["content_digest"]
        with self.assertRaisesRegex(bridge.HarnessError, "MALFORMED_RESULT"):
            bridge.verify_result_bytes(
                _fixture_bytes("payload-malformed.json"), case_id=7,
                suite_path=bridge.CORE_SUITE_PATH, expected_digest=digest,
                python_identity=self.id(), returncode=0)
        with self.assertRaisesRegex(bridge.HarnessError, "TRUNCATED_RESULT"):
            bridge.verify_result_bytes(
                _fixture_bytes("payload-truncated.json"), case_id=7,
                suite_path=bridge.CORE_SUITE_PATH, expected_digest=digest,
                python_identity=self.id(), returncode=0)
        oversized = _fixture_bytes("payload-oversized.json")
        self.assertGreater(len(oversized), 16384)
        with self.assertRaisesRegex(bridge.HarnessError, "OVERSIZED_OUTPUT"):
            bridge.verify_result_bytes(oversized, case_id=7,
                                       suite_path=bridge.CORE_SUITE_PATH,
                                       expected_digest=digest,
                                       python_identity=self.id(),
                                       returncode=0)

    # WORK_UNIT_CASE: 907/39
    def test_907_39_timeout_cleanup_unknown_cannot_pass(self):
        timeout_record = _fixture_json("timeout-record.json")
        self.assertEqual(
            runner.cleanup_verdict(
                cleanup=timeout_record["cleanup"],
                active_processes=timeout_record["active_processes"],
                truncated=timeout_record["truncated"]), "non-green")
        self.assertEqual(runner.phase_verdict("execute", "timeout"), "non-green")
        unknown_record = _fixture_json("cleanup-unknown-record.json")
        self.assertEqual(
            runner.cleanup_verdict(
                cleanup=unknown_record["cleanup"],
                active_processes=unknown_record["active_processes"],
                truncated=unknown_record["truncated"]), "non-green")
        # Deterministic mapping: a contained timeout is cleanup-unknown.
        mapped = bridge._timeout_unknown(timeout_s=0.05, reaped=True)
        self.assertEqual(mapped.code, "TIMEOUT_CLEANUP_UNKNOWN")
        self.assertEqual(mapped.details.get("cleanup"), "unknown")
        # Live path: the fixed argv under a tightened bound cannot pass and
        # must leave the owned child reaped (no unowned descendant). In an
        # isolated worktree the registered suite file is absent so pwsh exits
        # fast and verification fails; integrated, the bound fires first.
        env = bridge._child_env()
        pwsh = bridge._resolve_pwsh(env)
        suite_abs = __import__("os").path.abspath(
            str(ROOT / bridge.CORE_SUITE_PATH))
        argv = [pwsh, "-NoProfile", "-NonInteractive", "-File",
                suite_abs, "-CaseId", "1"]
        pinned = _fixture_json("payload-ok.json")
        try:
            completed = bridge._run_contained(
                argv, timeout_s=0.05, output_cap=16384, line_cap=4096,
                child_env=env, pwsh_path=pwsh, suite_abs=suite_abs, case_id=1)
        except bridge.HarnessError as exc:
            self.assertIn(exc.code, ("TIMEOUT_CLEANUP_UNKNOWN",
                                     "SUITE_MISSING", "SPAWN_FAILED",
                                     "OVERSIZED_OUTPUT", "LINE_BOUND",
                                     "NON_UTF8_OUTPUT"))
            if exc.code == "TIMEOUT_CLEANUP_UNKNOWN":
                self.assertEqual(exc.details.get("cleanup"), "unknown")
                self.assertTrue(exc.details.get("reaped"))
        else:
            self.assertTrue(completed.reaped)
            with self.assertRaises(bridge.HarnessError):
                bridge.verify_result_bytes(
                    completed.stdout, case_id=1,
                    suite_path=bridge.CORE_SUITE_PATH,
                    expected_digest=pinned["content_digest"],
                    python_identity=self.id(),
                    returncode=completed.returncode)

    # WORK_UNIT_CASE: 907/40
    def test_907_40_source_identities_and_results_reconcile(self):
        source = Path(__file__).read_text(encoding="utf-8")
        markers = [int(m) for m in re.findall(r"# WORK_UNIT_CASE: 907/(\d+)",
                                              source)]
        self.assertEqual(len(markers), 40)
        self.assertEqual(sorted(markers), list(range(1, 41)))
        self.assertEqual(len(CASE_METHODS), 40)
        for index, name in enumerate(CASE_METHODS, start=1):
            self.assertTrue(hasattr(TestIntegrationHarnessCore, name),
                            f"method missing for 907/{index}: {name}")
            method = getattr(TestIntegrationHarnessCore, name)
            self.assertTrue(callable(method))
            qualified = (f"{bridge.PYTHON_SUITE_MODULE}."
                         f"TestIntegrationHarnessCore.{name}")
            identity = contracts.TestIdentity(
                mode=contracts.RunnerMode.PYTHON_UNITTEST,
                qualified_name=qualified)
            self.assertEqual(identity.qualified_name, qualified)
        rows = _fixture_json("cases.json")["rows"]
        self.assertEqual(sorted(r["case_id"] for r in rows), list(range(1, 33)))
        bound = runner.bind_python_suite(
            root=ROOT, module=bridge.PYTHON_SUITE_MODULE,
            test_roots=list(bridge.PYTHON_TEST_ROOTS))
        self.assertEqual(
            bound, "scripts/tests/test_integration_harness_core.py")
        # A wrapper fabricating success without executing its case fails:
        # the fabricated payload cannot carry the bound content digest.
        pinned = _fixture_json("payload-ok.json")
        with self.assertRaisesRegex(bridge.HarnessError,
                                    "RESULT_DIGEST_MISMATCH"):
            bridge.verify_result_bytes(
                _fixture_bytes("payload-fabricated-success.json"), case_id=12,
                suite_path=bridge.CORE_SUITE_PATH,
                expected_digest=pinned["content_digest"],
                python_identity=self.id(), returncode=0)


if __name__ == "__main__":
    unittest.main()
