"""#846 acceptance predicates for Agent Bridge Windows package staging.

Declared denominator: 40 cases, exactly 1..40, bound one-to-one to the
numbered obligations in `control-20260923-impl/v2/issues/846/TASK.md`
("Required test matrix").

Oracle ownership (I18.27)
-------------------------
This suite changes no production source, so every expected value below is
derived from UNCHANGED source or from the issue/architecture contract, never
from the output of a prior run of the thing being verified:

* Cases 1-4, 7-11, 13, 15-34, 37, 39 read the *current* bytes of
  `package_staging.rs` and assert the tokens the documented staging contract
  requires to be present. The oracle is the contract; a missing token fails.
* Cases 5, 6, 12, 14, 24, 36, 38, 40 evaluate the negative-evidence gate
  against one mutated copy of a single baseline record, asserting the exact
  named rejection reason.
* Cases 35 and 36 are the *run-evidence* predicates: they FAIL when no actual
  selected Windows run record is supplied, because TASK.md states "Missing
  setup stays incomplete, never simulated pass" and "No zero-selected,
  cfg-elided, marker-only or fabricated supported-environment acceptance."

No case re-implements the stager and none compares the implementation to
itself. No case executes cargo, spawns a process, opens a socket, reads the
clock, or reads ambient environment variables.

The whole negative-evidence layer is inert: `invalid_evidence.json` holds
finite literals only, is parsed, never executed, contacted or applied to any
real environment.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGING_REL = "crates/kernel/eliot-platform-windows/src/package_staging.rs"
STAGING = REPO_ROOT / STAGING_REL
FIXTURE = REPO_ROOT / "scripts" / "testdata" / "windows-staging" / "invalid_evidence.json"

# --- Documented contract constants (TASK.md) -------------------------------
# "the named staging set contains 11 functions and two distinct post-create
# fault subcases" (TASK.md, Objective and current status)
AGENT_BRIDGE_TESTS = (
    "agent_bridge_post_create_failures_clean_exact_temporary",
    "agent_bridge_staging_success_receipts_are_serializable_and_read_back",
    "agent_bridge_staging_rejects_source_substitution",
    "agent_bridge_staging_rejects_destination_preexistence_without_overwrite",
    "agent_bridge_staging_retry_rejects_foreign_bytes_and_absence",
    "agent_bridge_prepared_roundtrip_and_binding_substitution_are_rejected",
    "agent_bridge_prepared_reconcile_publishes_before_rename_recovery",
    "agent_bridge_prepared_response_loss_after_rename_reconciles_exactly",
    "agent_bridge_prepare_retry_uses_fresh_temp_without_adopting_orphan",
    "agent_bridge_prepared_foreign_temp_and_final_never_adopted",
    "agent_bridge_prepared_rejects_foreign_temp_shape",
)
FAULT_SUBCASES = (
    "AGENT_BRIDGE_FAIL_FINAL_PATH",
    "AGENT_BRIDGE_FAIL_DESTINATION_EXISTS",
)
# "Current D-INT ownership is #905 inventory, #907 orchestration, #911 Windows
# topology" (TASK.md, Dependencies and environment)
DINT_OWNER_ISSUES = frozenset({905, 907, 911})
HISTORICAL_BASELINE_FAILURES = 13
TEST_MOD = re.compile(r"mod tests \{", re.MULTILINE)

EVIDENCE_RECORD_VERSION = "eliot.windows-staging.evidence.v1"
EVIDENCE_SCOPE = "package-staging-agent-bridge"
ACCEPTED_PROOF_LEVEL = "package-test"
FILTERED_INVOCATION = "package_staging::tests::agent_bridge_"

# The only paths #846 may change (TASK.md, Exclusive mutable scope).
ALLOWED_CHANGED_PATHS = frozenset(
    {
        STAGING_REL,
        "scripts/tests/test_windows_staging_acceptance.py",
        "scripts/testdata/windows-staging/invalid_evidence.json",
    }
)
# The retired reservation marker is never test evidence (TASK.md, Objective).
FORBIDDEN_CHANGED_PATHS = frozenset({".github/temporary/work-unit-846.md"})

_SOURCE_CACHE: dict = {}
_FIXTURES: dict = {}


def source() -> str:
    """Current package_staging.rs bytes, read once, never taken from a run."""
    if "text" not in _SOURCE_CACHE:
        raw = STAGING.read_bytes()
        _SOURCE_CACHE["text"] = raw.decode("utf-8")
        _SOURCE_CACHE["sha256"] = hashlib.sha256(raw).hexdigest()
    return _SOURCE_CACHE["text"]


def source_sha256() -> str:
    source()
    return _SOURCE_CACHE["sha256"]


def test_module_text() -> str:
    """The `mod tests` body only: the Agent Bridge test module under repair."""
    text = source()
    start = TEST_MOD.search(text)
    assert start is not None, "package_staging.rs has no `mod tests` block"
    return text[start.start() :]


def agent_bridge_staging_tests() -> str:
    """Only the eleven named Agent Bridge staging test bodies.

    Bounded by the first and the last of the eleven names, so helper and
    regression code placed elsewhere in `mod tests` is never included.
    """
    module = test_module_text()
    ordered = sorted(AGENT_BRIDGE_TESTS, key=module.index)
    start = module.index("fn %s() -> TestResult" % ordered[0])
    end = module.index("\n    #[test]", module.index("fn %s() -> TestResult" % ordered[-1]))
    return module[start:end]


def load_fixtures() -> dict:
    if not _FIXTURES:
        _FIXTURES.update(json.loads(FIXTURE.read_text(encoding="utf-8")))
    return _FIXTURES


def fixture_records() -> list:
    """The negative fixtures, each re-pinned to the CURRENT source digest.

    A negative fixture is a VALID record with exactly one named defect. If the
    fixture file also pinned a real blob digest, that digest would go stale the
    moment anyone else touched `package_staging.rs` — and because the source
    check runs first, every fixture would then be rejected as
    `R-STALE-SOURCE-DIGEST` instead of for the reason it names. The fixtures
    would silently stop testing what they claim to test.

    So the source digest is re-pinned here to the live source. The fixture keeps
    its own one deliberate defect, and the digest-defect case carries that
    defect in the field itself and is not re-pinned, because the digest IS its
    defect.

    This works on COPIES: the loaded fixture document is never mutated, so
    `test_fixtures_are_finite_and_inert` still compares the on-disk bytes.
    """
    live = source_sha256()
    records = []
    for record in load_fixtures()["fixtures"]:
        if record.get("expected_reason") == "R-STALE-SOURCE-DIGEST":
            records.append(record)
            continue
        source = record.get("evidence", {}).get("source")
        if isinstance(source, dict) and source.get("path") == STAGING_REL:
            record = copy.deepcopy(record)
            record["evidence"]["source"]["blob_sha256"] = live
        records.append(record)
    return records


def baseline_record() -> dict:
    """A pristine, accepted baseline record, rebuilt from the fixture shape.

    The baseline is *not* read from the fixture file's own records (those are
    deliberately mutated). It is reconstructed from this module's documented
    constants, so the gate's positive path is an independent oracle too.
    """
    return {
        "record_version": EVIDENCE_RECORD_VERSION,
        "issue": 846,
        "scope": EVIDENCE_SCOPE,
        "source": {
            "path": STAGING_REL,
            "blob_sha256": source_sha256(),
            "assignment_sha256": "1" * 64,
        },
        "environment": {
            "os": "Windows",
            "windows_build": "10.0.26100",
            "runner": "controller-windows",
            "toolchain": "rustc 1.90.0",
            "elevated": True,
            "privilege_facts_recorded": True,
            "protected_program_data_contour": "C:\\ProgramData",
            "protected_root_disposition": "available",
            "fixture_setup_disposition": "ready",
            "protected_root_lease_verified": True,
        },
        "run": {
            "filtered_invocation": FILTERED_INVOCATION,
            "selected_tests": list(AGENT_BRIDGE_TESTS),
            "selected_count": len(AGENT_BRIDGE_TESTS),
            "fault_subcases": list(FAULT_SUBCASES),
            "assertions_executed": 96,
            "outcome": "passed",
            "cleanup_status": "clean",
            "unaccounted_residue": [],
            "unrelated_failures": [],
        },
        "privileged": {
            "required": True,
            "supported_environment": True,
            "environment_owner": "#911",
            "provenance": {
                "windows_identity": "10.0.26100",
                "runner": "controller-windows",
                "elevation": "administrator",
                "captured_by": "D-INT Windows topology owner",
            },
        },
        "clippy": {"broad_suppression": False},
        "proof_level": ACCEPTED_PROOF_LEVEL,
        "changed_paths": sorted(ALLOWED_CHANGED_PATHS),
    }


def evidence_path(reason: str) -> Path:
    """Exact location of the run-evidence record for an environment/run case."""
    return REPO_ROOT / "scripts" / "testdata" / "windows-staging" / "evidence" / (
        "%s.json" % reason
    )


def load_run_evidence(name: str):
    """Load an independently captured run-evidence record, or None.

    `None` means no actual Windows execution record exists in this tree. Per
    TASK.md that is *incomplete*, never a pass, so the caller must fail.
    """
    path = evidence_path(name)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


# --- Negative-evidence gate -------------------------------------------------
def validate_source_run_evidence(record) -> tuple:
    """Fail-closed acceptance gate for one #846 evidence record.

    Returns `(accepted, reason)`. `reason` is `None` only when the record is
    genuine staging evidence for #846. Every rejection names a documented
    reason, so a fixture can never pass by merely being different.

    The gate inspects literal fields only. It never executes, contacts or
    applies anything a record contains.
    """
    if not isinstance(record, dict):
        return False, "R-RECORD-VERSION"

    if record.get("record_version") != EVIDENCE_RECORD_VERSION:
        return False, "R-RECORD-VERSION"
    if record.get("issue") != 846 or record.get("scope") != EVIDENCE_SCOPE:
        return False, "R-ISSUE-MISMATCH"

    # --- source: the exact #846 subject at a current revision --------------
    src = record.get("source")
    if not isinstance(src, dict):
        return False, "R-SOURCE-PATH-UNKNOWN"
    if src.get("path") != STAGING_REL:
        return False, "R-SOURCE-PATH-UNKNOWN"
    blob = src.get("blob_sha256")
    if not isinstance(blob, str) or not re.fullmatch(r"[0-9a-f]{64}", blob):
        return False, "R-STALE-SOURCE-DIGEST"
    if not src.get("assignment_sha256"):
        return False, "R-STALE-SOURCE-DIGEST"
    if blob != source_sha256():
        # Case 34: a digest that does not match current unchanged source makes
        # every downstream claim in the record stale or forged.
        return False, "R-STALE-SOURCE-DIGEST"

    # --- environment: privilege facts, protected contour, fixture state ---
    env = record.get("environment")
    if not isinstance(env, dict):
        return False, "R-MISSING-ENVIRONMENT-FACTS"
    if not env.get("privilege_facts_recorded"):
        return False, "R-MISSING-ENVIRONMENT-FACTS"
    if env.get("os") != "Windows" or not env.get("windows_build"):
        return False, "R-MISSING-ENVIRONMENT-FACTS"
    contour = env.get("protected_program_data_contour")
    if not isinstance(contour, str) or not contour.lower().startswith("c:\\programdata"):
        # Case 6: the protected ProgramData contour may not be replaced by an
        # arbitrary writable directory.
        return False, "R-PROTECTED-ROOT-SUBSTITUTED"
    if env.get("fixture_setup_disposition") != "ready":
        # Cases 9/11: unavailable privilege is not a passing staging test.
        return False, "R-FIXTURE-SETUP-SILENTLY-UNAVAILABLE"
    if not env.get("protected_root_lease_verified"):
        # Case 9: ProtectedRootLease open failure must be explicit.
        return False, "R-PROTECTED-ROOT-LEASE-UNVERIFIED"

    # --- run: real selection, real assertions, accounted cleanup -----------
    run = record.get("run")
    if not isinstance(run, dict):
        return False, "R-ZERO-SELECTED-TESTS"
    if run.get("filtered_invocation") != FILTERED_INVOCATION:
        return False, "R-FORGED-SELECTION"
    selected = run.get("selected_tests")
    if not isinstance(selected, list) or not selected:
        # Cases 11/35: a zero-selected run establishes nothing.
        return False, "R-ZERO-SELECTED-TESTS"
    if sorted(selected) != sorted(AGENT_BRIDGE_TESTS):
        # Cases 1/2: the selected set must be exactly the eleven named staging
        # functions; a truncated or renamed denominator does not reconcile.
        return False, "R-FORGED-SELECTION"
    if run.get("selected_count") != len(AGENT_BRIDGE_TESTS):
        return False, "R-FORGED-SELECTION"
    subcases = run.get("fault_subcases")
    if not isinstance(subcases, list) or sorted(subcases) != sorted(FAULT_SUBCASES):
        # Cases 28/29: both post-create fault subcases are separately asserted;
        # a complete-looking function count does not prove subcase coverage.
        return False, "R-SUBCASE-NOT-EXERCISED"
    if not isinstance(run.get("assertions_executed"), int) or run["assertions_executed"] <= 0:
        # Case 11: never a pass with no executed assertion.
        return False, "R-ASSERTION-FREE-SUCCESS"
    if run.get("cleanup_status") == "failed":
        # Case 10: cleanup failure cannot become environment-unavailable success.
        return False, "R-CLEANUP-FAILED"
    if run.get("cleanup_status") != "clean":
        # Case 32: unknown cleanup remains non-passing.
        return False, "R-CLEANUP-UNKNOWN"
    residue = run.get("unaccounted_residue")
    if not isinstance(residue, list):
        return False, "R-UNACCOUNTED-RESIDUE"
    if residue:
        # Case 31: owned fixture objects are cleaned after pass. Case 30:
        # cleanup may not claim an object the fixture never owned.
        if any(entry.get("owner") != "fixture" for entry in residue):
            return False, "R-FOREIGN-RESIDUE-CLAIMED"
        return False, "R-UNACCOUNTED-RESIDUE"
    if run.get("outcome") != "passed":
        # Case 35: a failing run stays non-green unless its failures are
        # separately owned; an unowned failure is never a pass.
        if not run.get("unrelated_failures"):
            return False, "R-NON-GREEN-UNOWNED"

    # --- privileged case: exact environment owner, real provenance ---------
    priv = record.get("privileged")
    if not isinstance(priv, dict):
        return False, "R-ENVIRONMENT-OWNER-MISSING"
    if priv.get("required") and not priv.get("supported_environment"):
        # Case 14: an unsupported environment is not evidence.
        return False, "R-UNSUPPORTED-ENVIRONMENT-AS-EVIDENCE"
    if priv.get("required"):
        owner = priv.get("environment_owner")
        owner_issue = None
        if isinstance(owner, str) and owner.startswith("#"):
            try:
                owner_issue = int(owner[1:])
            except ValueError:
                owner_issue = None
        if owner_issue is None or owner_issue not in DINT_OWNER_ISSUES:
            # Case 12: the privileged case has an exact D-INT owner.
            return False, (
                "R-ENVIRONMENT-OWNER-MISSING"
                if owner is None
                else "R-ENVIRONMENT-OWNER-UNKNOWN"
            )
        prov = priv.get("provenance")
        if not isinstance(prov, dict) or not all(
            prov.get(key) for key in ("windows_identity", "runner", "elevation", "captured_by")
        ):
            # Case 36: actual current privileged Windows run provenance.
            return False, "R-PROVENANCE-MISSING"

    # --- Clippy without broad suppression (case 37) ----------------------
    clippy = record.get("clippy")
    if not isinstance(clippy, dict) or clippy.get("broad_suppression"):
        return False, "R-CLIPPY-BROAD-SUPPRESSION"

    # --- exact test-only changed paths (case 38) -------------------------
    changed = record.get("changed_paths")
    if not isinstance(changed, list) or not changed:
        return False, "R-CHANGED-PATH-OUT-OF-SCOPE"
    if FORBIDDEN_CHANGED_PATHS.intersection(changed):
        # The retired reservation marker is never test evidence.
        return False, "R-CHANGED-PATH-OUT-OF-SCOPE"
    if not set(changed).issubset(ALLOWED_CHANGED_PATHS):
        return False, "R-CHANGED-PATH-OUT-OF-SCOPE"

    # --- proof level must not be relabelled (case 40) --------------------
    if record.get("proof_level") != ACCEPTED_PROOF_LEVEL:
        return False, "R-PROOF-RELABELLED"

    return True, None


class WindowsStagingAcceptance(unittest.TestCase):
    """Cases 1..40 of the #846 required test matrix."""

    @classmethod
    def setUpClass(cls) -> None:
        assert STAGING.is_file(), STAGING_REL
        assert FIXTURE.is_file(), FIXTURE
        load_fixtures()

    # -- case 1 ----------------------------------------------------------
    # WORK_UNIT_CASE: 846/1
    def test_case_01_named_staging_denominator_on_current_source(self) -> None:
        """The eleven named staging functions exist and are individually bound."""
        module = test_module_text()
        for name in AGENT_BRIDGE_TESTS:
            self.assertRegex(
                module,
                r"fn %s\(\) -> TestResult" % re.escape(name),
                "missing named staging function: %s" % name,
            )
        # Each of the eleven is preceded by its own `#[test]`.
        for name in AGENT_BRIDGE_TESTS:
            index = module.index("fn %s() -> TestResult" % name)
            window = module[max(0, index - 200) : index]
            self.assertIn("#[test]", window, "no #[test] binds %s" % name)

    # -- case 2 ----------------------------------------------------------
    # WORK_UNIT_CASE: 846/2
    def test_case_02_historical_thirteen_reconciles_against_current_set(self) -> None:
        """Historical 13 failures reconcile as 11 functions + 2 subcases."""
        module = test_module_text()
        self.assertEqual(HISTORICAL_BASELINE_FAILURES, 13)
        self.assertEqual(len(AGENT_BRIDGE_TESTS), 11)
        self.assertEqual(len(FAULT_SUBCASES), 2)
        self.assertEqual(len(AGENT_BRIDGE_TESTS) + len(FAULT_SUBCASES), HISTORICAL_BASELINE_FAILURES)
        # Both subcases are armed by the same function, and both are asserted.
        post_create = agent_bridge_staging_tests()
        post_create = post_create.split("fn agent_bridge_post_create_failures_clean_exact_temporary(")[1]
        post_create = post_create.split("\n    #[test]")[0]
        for subcase in FAULT_SUBCASES:
            self.assertIn("arm_agent_bridge_post_create_failure(%s);" % subcase, post_create)

    # -- case 3 ----------------------------------------------------------
    # WORK_UNIT_CASE: 846/3
    def test_case_03_exact_stage_and_code_error_chain_is_retained(self) -> None:
        """Each injected fault keeps its own stage/code pair, not a generic error."""
        text = source()
        self.assertIn(
            "stage: PackageStagingStage::GetFinalPathNameByHandleW,\n            code: 5,",
            text,
        )
        self.assertIn(
            "stage: PackageStagingStage::GetFileInformationByHandle,\n            code: 5,",
            text,
        )
        # The raw status is rendered verbatim into the durable message.
        self.assertIn('write!(formatter, "{stage:?} failed with Win32 status {code:#010x}")', text)

    # -- case 4 ----------------------------------------------------------
    # WORK_UNIT_CASE: 846/4
    def test_case_04_fixture_causes_separate_from_production_causes(self) -> None:
        """Fixture setup and production outcomes use distinct error variants."""
        text = source()
        module = test_module_text()
        # Setup failures are fixture-caused and typed as environment facts.
        self.assertIn("fn security_fixture_unavailable(", module)
        for variant in (
            "PackageStagingError::RootUnavailable",
            "PackageStagingError::ReparsePoint",
            "PackageStagingError::UnsupportedPlatform",
        ):
            self.assertIn(variant, text)
        # Production-cause variants remain distinct from the fixture verdict.
        for variant in (
            "PackageStagingError::RollbackRefused",
            "PackageStagingError::SecurityMismatch",
        ):
            self.assertIn(variant, text)

    # -- case 5 ----------------------------------------------------------
    # WORK_UNIT_CASE: 846/5
    def test_case_05_environment_privilege_facts_are_recorded(self) -> None:
        """A real staging record must carry recorded privilege facts."""
        record = baseline_record()
        ok, reason = validate_source_run_evidence(record)
        self.assertTrue(ok, reason)
        for missing in (False, None, ""):
            record["environment"]["privilege_facts_recorded"] = missing
            ok, reason = validate_source_run_evidence(record)
            self.assertFalse(ok, missing)
            self.assertEqual(reason, "R-MISSING-ENVIRONMENT-FACTS", missing)
            record["environment"]["privilege_facts_recorded"] = True

    # -- case 6 ----------------------------------------------------------
    # WORK_UNIT_CASE: 846/6
    def test_case_06_protected_programdata_contour_dispositions(self) -> None:
        """Only a ProgramData-resident contour is protected-root evidence."""
        record = baseline_record()
        ok, reason = validate_source_run_evidence(record)
        self.assertTrue(ok, reason)
        for bogus in (
            "C:\\Users\\runner\\AppData\\Local\\Temp",
            "C:\\Temp",
            "\\\\server\\share\\programdata",
            "C:/ProgramDataX",
        ):
            record["environment"]["protected_program_data_contour"] = bogus
            ok, reason = validate_source_run_evidence(record)
            self.assertFalse(ok, bogus)
            self.assertEqual(reason, "R-PROTECTED-ROOT-SUBSTITUTED", bogus)

    # -- case 7 ----------------------------------------------------------
    # WORK_UNIT_CASE: 846/7
    def test_case_07_root_creation_failure_and_partial_residue_accounting(self) -> None:
        """Generation-root creation is create-only and refusal is typed."""
        text = source()
        self.assertIn("fn create_generation_root(", text)
        self.assertIn("fn is_create_new_collision(", text)
        self.assertIn("PackageStagingError::GenerationExists", text)
        # Partial residue is a typed non-success, never silently clean.
        self.assertIn("PackageStagingError::PartialTree", text)

    # -- case 8 ----------------------------------------------------------
    # WORK_UNIT_CASE: 846/8
    def test_case_08_intermediate_directory_failure_cleans_exactly(self) -> None:
        """Created directories are tracked for exact reverse-order deletion."""
        text = source()
        self.assertIn("struct CreatedDirectory {", text)
        self.assertIn("struct CreatedTree {", text)
        self.assertIn("directories: Vec<CreatedDirectory>", text)
        self.assertIn("fn delete_open_handle(", text)

    # -- case 9 ----------------------------------------------------------
    # WORK_UNIT_CASE: 846/9
    def test_case_09_protected_root_lease_open_failure_is_explicit(self) -> None:
        """Lease-open failure must be explicit, never a silent default pass."""
        self.assertIn("ProtectedRootLease::open_existing(&fixture.root_path)", test_module_text())
        record = baseline_record()
        record["environment"]["protected_root_lease_verified"] = False
        ok, reason = validate_source_run_evidence(record)
        self.assertFalse(ok)
        self.assertEqual(reason, "R-PROTECTED-ROOT-LEASE-UNVERIFIED")
        self.assertIn("PackageStagingError::RootUnavailable", source())

    # -- case 10 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/10
    def test_case_10_cleanup_failure_cannot_become_environment_success(self) -> None:
        """A failed cleanup is never reported as a passing staging run."""
        record = baseline_record()
        record["run"]["cleanup_status"] = "failed"
        ok, reason = validate_source_run_evidence(record)
        self.assertFalse(ok)
        self.assertEqual(reason, "R-CLEANUP-FAILED")
        # Cleanup failures are still typed production errors, not test skips.
        self.assertIn("PackageStagingError::RollbackRefused", source())

    # -- case 11 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/11
    def test_case_11_no_assertion_free_ok_after_unavailable_setup(self) -> None:
        """TASK.md: "A path returning None then Ok(()) ... is not a passing test"."""
        record = baseline_record()
        record["run"]["assertions_executed"] = 0
        ok, reason = validate_source_run_evidence(record)
        self.assertFalse(ok)
        self.assertEqual(reason, "R-ASSERTION-FREE-SUCCESS")
        # The same rule holds inside the Rust fixture: unavailable privilege is
        # reported as an explicit error, never a silent Ok(()).
        module = test_module_text()
        staging_tests = agent_bridge_staging_tests()
        self.assertNotIn("return Ok(());", staging_tests)
        self.assertIn("agent_bridge_fixture_unavailable()", module)
        # And the fixture degrades to an explicit unavailable verdict only.
        fixture = module.split("fn agent_bridge_fixture(")[1]
        fixture = fixture.split("\n    #[cfg(windows)]\n    fn agent_bridge_request")[0]
        self.assertIn("Ok(None)", fixture)
        self.assertIn("FixtureUnavailable", module)

    # -- case 12 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/12
    def test_case_12_privileged_case_has_exact_dint_owner(self) -> None:
        """The privileged scenario routes to an exact documented D-INT owner."""
        self.assertIn(911, DINT_OWNER_ISSUES)
        record = baseline_record()
        for owner in ("#905", "#907", "#911"):
            record["privileged"]["environment_owner"] = owner
            ok, reason = validate_source_run_evidence(record)
            self.assertTrue(ok, owner)
        for wrong in ("#846", "#8", "911", "owner-unknown"):
            record["privileged"]["environment_owner"] = wrong
            ok, reason = validate_source_run_evidence(record)
            self.assertFalse(ok, wrong)
            self.assertEqual(reason, "R-ENVIRONMENT-OWNER-UNKNOWN", wrong)

    # -- case 13 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/13
    def test_case_13_deterministic_contract_logic_still_exercised(self) -> None:
        """Non-privileged deterministic staging contracts remain under test."""
        module = test_module_text()
        for name in (
            "fn digest_helpers_encode_one_sha256_for_known_vector",
            "fn relative_path_rejects_escape_ads_device_and_trailing_forms",
            "fn trusted_source_root_rejects_verbatim_device_and_traversal_inputs",
            "fn bounded_manifest_inputs_are_rejected_before_filesystem_work",
            "fn wintrust_statuses_are_typed_and_fail_closed",
            "fn exact_tree_matching_rejects_extra_missing_and_kind_mismatch",
            "fn create_new_collision_codes_are_typed_as_generation_exists",
        ):
            self.assertIn(name, module)

    # -- case 14 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/14
    def test_case_14_privileged_case_needs_real_supported_environment(self) -> None:
        """Without a supported Windows environment the privileged case stays open."""
        record = baseline_record()
        record["privileged"]["supported_environment"] = False
        ok, reason = validate_source_run_evidence(record)
        self.assertFalse(ok)
        self.assertEqual(reason, "R-UNSUPPORTED-ENVIRONMENT-AS-EVIDENCE")
        # Portable contract checks may complement, never replace it.
        self.assertIn("fn verify_retained_agent_bridge_parent(", source())

    # -- case 15 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/15
    def test_case_15_staged_source_identity_digest_size_preserved(self) -> None:
        """Source identity, SHA-256 and size are all re-proved at prepare."""
        text = source()
        prepare = text.split("pub fn prepare_agent_bridge_stage(")[1]
        prepare = prepare.split("\npub fn rename_agent_bridge_file_from_handle")[0]
        for token in ("source_identity", "source_sha256", "source_size"):
            self.assertIn(token, prepare)
        self.assertIn("sha256: prepared.source_sha256.clone(),", text)
        self.assertIn("size: prepared.source_size,", text)

    # -- case 16 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/16
    def test_case_16_prepared_and_receipt_round_trip_on_current_wire(self) -> None:
        """Prepared/receipt wire identity and version are exact and shared."""
        text = source()
        self.assertIn('pub const AGENT_BRIDGE_STAGE_WIRE: &str = "eliot.agent-bridge.stage.v1";', text)
        self.assertIn("pub const AGENT_BRIDGE_STAGE_WIRE_VERSION: u32 = 1;", text)
        for struct in ("AgentBridgeStagePrepared", "AgentBridgeStagingReceipt"):
            head = text.split("pub struct %s {" % struct)[0]
            block = text.split("pub struct %s {" % struct)[1].split("\n}")[0]
            self.assertIn("#[serde(deny_unknown_fields)]", head[-300:])
            self.assertIn("pub wire: String,", block)
            self.assertIn("pub wire_version: u32,", block)
        # Both records are validated against the same constants.
        self.assertIn(
            "if prepared.wire != AGENT_BRIDGE_STAGE_WIRE\n"
            "        || prepared.wire_version != AGENT_BRIDGE_STAGE_WIRE_VERSION",
            text,
        )

    # -- case 17 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/17
    def test_case_17_source_substitution_is_rejected(self) -> None:
        """Request source facts are all re-proved, not trusted from the caller."""
        validate = source().split("fn validate_agent_bridge_request(")[1]
        validate = validate.split("\nfn final_path_after_agent_bridge_create(")[0]
        self.assertIn("request.source_identity.file_index == 0", validate)
        self.assertIn("super::valid_sha256_hex(&request.source_sha256)", validate)
        self.assertIn("request.source_size > MAX_PACKAGE_FILE_BYTES", validate)
        self.assertIn("PackageStagingError::IdentityMismatch", validate)

    # -- case 18 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/18
    def test_case_18_preexisting_destination_rejected_without_overwrite(self) -> None:
        """Publication is no-replace; an existing destination is never adopted."""
        publish = source().split("pub fn publish_agent_bridge_stage(")[1]
        publish = publish.split("\npub fn reconcile_agent_bridge_stage(")[0]
        self.assertIn("if path_exists(&prepared.destination_path)? {", publish)
        self.assertIn("return Err(PackageStagingError::IdentityMismatch);", publish)
        # The only rename entry point carries the no-replace publication seam.
        self.assertIn("fn rename_agent_bridge_file_from_handle(", source())

    # -- case 19 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/19
    def test_case_19_foreign_byte_retry_is_rejected(self) -> None:
        """A retry over foreign bytes is a hash mismatch, never a silent success."""
        publish = source().split("pub fn publish_agent_bridge_stage(")[1]
        publish = publish.split("\npub fn reconcile_agent_bridge_stage(")[0]
        self.assertIn(
            "if actual.sha256 != prepared.source_sha256 || actual.size != prepared.source_size {\n"
            "        return Err(PackageStagingError::HashMismatch);",
            publish,
        )

    # -- case 19b (case 24 sub-predicate folded into case 24) --------------
    # WORK_UNIT_CASE: 846/20
    def test_case_20_missing_destination_retains_partial_tree_error(self) -> None:
        """Both absent leaves yield PartialTree, a typed non-success."""
        reconcile = source().split("pub fn reconcile_agent_bridge_stage(")[1]
        self.assertIn("(false, false) => Err(PackageStagingError::PartialTree),", reconcile)
        publish = source().split("pub fn publish_agent_bridge_stage(")[1]
        publish = publish.split("\npub fn reconcile_agent_bridge_stage(")[0]
        self.assertIn("return Err(PackageStagingError::PartialTree);", publish)

    # -- case 21 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/21
    def test_case_21_every_prepared_binding_substitution_is_rejected(self) -> None:
        """All nine prepared bindings are independently validated."""
        validate = source().split("fn validate_agent_bridge_prepared(")[1]
        validate = validate.split("\nfn agent_bridge_receipt_from_prepared(")[0]
        for token in (
            "prepared.wire != AGENT_BRIDGE_STAGE_WIRE",
            "prepared.wire_version != AGENT_BRIDGE_STAGE_WIRE_VERSION",
            "prepared.destination_identity != prepared.temporary_identity",
            "&prepared.transaction_id",
            "&prepared.effect_id",
            "&prepared.request_digest",
            "prepared.source_identity.file_index == 0",
            "prepared.parent_identity.file_index == 0",
            "prepared.temporary_identity.file_index == 0",
            "prepared.destination_identity.file_index == 0",
            "prepared.source_size == 0",
            "super::valid_sha256_hex(&prepared.source_sha256)",
            "validate_agent_bridge_temporary_name(",
        ):
            self.assertIn(token, validate)
        # Every rejection in this function is the single fail-closed variant.
        self.assertEqual(validate.count("return Err(PackageStagingError::IdentityMismatch);"), 5)

    # -- case 22 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/22
    def test_case_22_pre_rename_recovery_publishes_exactly_once(self) -> None:
        """A present temporary with absent final publishes through one seam."""
        reconcile = source().split("pub fn reconcile_agent_bridge_stage(")[1]
        self.assertIn(
            "(false, true) => publish_agent_bridge_stage(installation_root, prepared),", reconcile
        )
        publish = source().split("pub fn publish_agent_bridge_stage(")[1]
        publish = publish.split("\npub fn reconcile_agent_bridge_stage(")[0]
        self.assertEqual(publish.count("rename_agent_bridge_file_from_handle("), 1)

    # -- case 23 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/23
    def test_case_23_response_loss_reconcile_returns_original_receipt(self) -> None:
        """After rename, reconcile reads the published object, not a new copy."""
        reconcile = source().split("pub fn reconcile_agent_bridge_stage(")[1]
        self.assertIn("(true, false) => read_prepared_final(prepared),", reconcile)
        receipt = source().split("fn agent_bridge_receipt_from_prepared(")[1]
        receipt = receipt.split("\n#[cfg(windows)]\nfn verify_retained_agent_bridge_parent")[0]
        self.assertIn("create_disposition: AgentBridgeStagingCreateDisposition::Created,", receipt)
        self.assertIn("sha256: prepared.source_sha256.clone(),", receipt)

    # -- case 24 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/24
    def test_case_24_repeat_prepare_uses_fresh_temp_without_adopting_orphan(self) -> None:
        """Each prepare mints a nonce-scoped temporary; none is reused."""
        text = source()
        prefix = text.split("fn agent_bridge_operation_temporary_prefix(")[1]
        prefix = prefix.split("\nfn agent_bridge_operation_temporary_path(")[0]
        for binding in ("parent", "transaction_id", "effect_id", "request_digest", "destination"):
            self.assertIn(binding, prefix)
        path = text.split("fn agent_bridge_operation_temporary_path(")[1]
        path = path.split("\nfn validate_agent_bridge_temporary_name(")[0]
        self.assertIn("nonce = super::unique_suffix()", path)
        # Publication refuses to adopt a left-over temporary beside a final.
        publish = text.split("pub fn publish_agent_bridge_stage(")[1]
        publish = publish.split("\npub fn reconcile_agent_bridge_stage(")[0]
        self.assertIn(
            "if path_exists(&prepared.destination_path)? {\n"
            "        if path_exists(&prepared.temporary_path)? {\n"
            "            return Err(PackageStagingError::IdentityMismatch);",
            publish,
        )

    # -- case 25 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/25
    def test_case_25_foreign_temp_rejected_by_identity(self) -> None:
        """Temporary readback proves identity, not the pathname."""
        publish = source().split("pub fn publish_agent_bridge_stage(")[1]
        publish = publish.split("\npub fn reconcile_agent_bridge_stage(")[0]
        self.assertIn(
            "read_destination_snapshot_handle(\n"
            "        &temporary,\n"
            "        &prepared.temporary_path,\n"
            "        prepared.source_size,\n"
            "        prepared.temporary_identity,\n"
            "    )",
            publish,
        )
        validate = source().split("fn validate_agent_bridge_prepared(")[1]
        self.assertIn("prepared.destination_identity != prepared.temporary_identity", validate)

    # -- case 26 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/26
    def test_case_26_foreign_final_rejected_by_identity_and_hash(self) -> None:
        """Published readback proves both identity and exact bytes."""
        final = source().split("fn read_prepared_final_from_handle(")[1]
        final = final.split("\n#[cfg(windows)]\nfn flush_agent_bridge_parent")[0]
        self.assertIn("prepared.destination_identity,", final)
        self.assertIn("prepared.source_size,", final)
        self.assertIn(
            "if actual.sha256 != prepared.source_sha256 || actual.size != prepared.source_size {",
            final,
        )
        self.assertIn("return Err(PackageStagingError::HashMismatch);", final)
        # A size divergence is translated to identity mismatch at the binding layer.
        self.assertIn(
            "PackageStagingError::SizeMismatch => PackageStagingError::IdentityMismatch",
            source(),
        )

    # -- case 27 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/27
    def test_case_27_foreign_temp_shape_is_rejected(self) -> None:
        """Temporary naming is a grammar, not an arbitrary sibling filename."""
        name = source().split("fn validate_agent_bridge_temporary_name(")[1]
        name = name.split("\nfn validate_stage_binding(")[0]
        self.assertIn("if !super::windows_paths_equal(parent, temporary_parent) {", name)
        self.assertIn(".strip_prefix(&prefix)", name)
        self.assertIn('.strip_suffix(".tmp")', name)
        self.assertIn("nonce_parts.len() != 3", name)
        self.assertIn("byte.is_ascii_digit()", name)
        self.assertIn("nonce.len() > 128", name)
        self.assertEqual(name.count("return Err(PackageStagingError::IdentityMismatch);"), 4)

    # -- case 28 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/28
    def test_case_28_injected_final_path_failure_cleans_exact_temp(self) -> None:
        """Injected final-path failure is typed, and the temp seam is checked."""
        text = source()
        self.assertIn("if staged_bridge_failure() == AGENT_BRIDGE_FAIL_FINAL_PATH {", text)
        module = test_module_text()
        self.assertIn("arm_agent_bridge_post_create_failure(AGENT_BRIDGE_FAIL_FINAL_PATH);", module)
        self.assertIn("fn assert_no_agent_bridge_temporary(", module)
        self.assertIn('assert!(!found, "unexpected retained Agent Bridge temporary");', module)

    # -- case 29 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/29
    def test_case_29_distinct_destination_fault_cleans_exact_temp(self) -> None:
        """The second fault subcase has its own stage/code and its own assertion."""
        text = source()
        self.assertIn(
            "if staged_bridge_failure() == AGENT_BRIDGE_FAIL_DESTINATION_EXISTS {", text
        )
        module = test_module_text()
        self.assertIn(
            "arm_agent_bridge_post_create_failure(AGENT_BRIDGE_FAIL_DESTINATION_EXISTS);", module,
        )
        # Both subcases are separately injected inside the one counted function.
        body = agent_bridge_staging_tests()
        body = body.split("fn agent_bridge_post_create_failures_clean_exact_temporary(")[1]
        body = body.split("\n    #[test]")[0]
        self.assertEqual(body.count("arm_agent_bridge_post_create_failure("), 2)
        self.assertEqual(body.count("assert_no_agent_bridge_temporary(&fixture"), 2)
        self.assertEqual(
            len(FAULT_SUBCASES),
            len({sub for sub in FAULT_SUBCASES if sub in body}),
        )

    # -- case 30 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/30
    def test_case_30_unrelated_parent_objects_are_not_deleted(self) -> None:
        """Cleanup is limited to fixture-owned identities."""
        module = test_module_text()
        self.assertIn("fn cleanup_agent_bridge_fixture(fixture: AgentBridgeFixture) {", module)
        cleanup = module.split("fn cleanup_agent_bridge_fixture(")[1].split("\n    }")[0]
        for owned in ("fixture.root", "fixture.source_path", "fixture.root_path"):
            self.assertIn(owned, cleanup)
        # Cleanup never names the destination: the provider owns publication.
        self.assertNotIn("fixture.destination_path", cleanup)
        # Production refuses a foreign identity instead of deleting anyway.
        self.assertIn(
            "Err(PackageStagingError::IdentityMismatch)\n        );\n"
            '        assert!(path.exists(), "foreign receipt must not delete the file");',
            source(),
        )

    # -- case 31 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/31
    def test_case_31_owned_fixture_objects_are_cleaned_after_pass(self) -> None:
        """Owned handles, files and directories are released on every path."""
        module = test_module_text()
        body = module.split("mod tests {")[1]
        # Every staging test releases its fixture on both arms.
        self.assertEqual(body.count("cleanup_agent_bridge_fixture(fixture);"), 21)
        # A fixture that reports unavailable must also have cleaned up.
        self.assertIn("let _ = std::fs::remove_dir_all(&root_path);", module)
        record = baseline_record()
        record["run"]["unaccounted_residue"] = [
            {"path": "C:\\ProgramData\\eliot-agent-bridge-stage-1-2-3", "owner": "fixture", "removed": False}
        ]
        ok, reason = validate_source_run_evidence(record)
        self.assertFalse(ok)
        self.assertEqual(reason, "R-UNACCOUNTED-RESIDUE")

    # -- case 32 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/32
    def test_case_32_unknown_or_failed_cleanup_stays_nonpassing(self) -> None:
        """Only an explicit clean disposition is a pass."""
        record = baseline_record()
        for disposition, expected in (
            ("failed", "R-CLEANUP-FAILED"),
            ("unknown", "R-CLEANUP-UNKNOWN"),
            ("", "R-CLEANUP-UNKNOWN"),
        ):
            record["run"]["cleanup_status"] = disposition
            ok, reason = validate_source_run_evidence(record)
            self.assertFalse(ok, disposition)
            self.assertEqual(reason, expected, disposition)

    # -- case 33 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/33
    def test_case_33_production_security_tokens_are_unchanged(self) -> None:
        """Every security/identity/hash/path/wire token survives on current source."""
        text = source()
        for token in (
            'pub const AGENT_BRIDGE_STAGE_WIRE: &str = "eliot.agent-bridge.stage.v1";',
            "pub const AGENT_BRIDGE_STAGE_WIRE_VERSION: u32 = 1;",
            "pub const MAX_PACKAGE_FILES: usize = 4096;",
            "pub const MAX_PACKAGE_PATH_DEPTH: usize = 32;",
            "pub const MAX_PACKAGE_FILE_BYTES: u64 = 512 * 1024 * 1024;",
            "pub const MAX_PACKAGE_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;",
            "pub const MAX_ENUMERATED_ENTRIES: usize = MAX_PACKAGE_FILES * 2 + MAX_PACKAGE_PATH_DEPTH;",
            "fn agent_bridge_path_is_at_or_below(",
            "fn validate_agent_bridge_temporary_name(",
            "fn validate_agent_bridge_prepared(",
            "fn read_prepared_final(",
            "fn read_prepared_final_from_handle(",
            "fn map_prepared_binding_size_error(",
            "PackageStagingError::IdentityMismatch",
            "PackageStagingError::HashMismatch",
            "PackageStagingError::PartialTree",
            "PackageStagingError::GenerationExists",
            "PackageStagingError::RollbackRefused",
            "PackageStagingError::SecurityMismatch",
        ):
            self.assertIn(token, text)

    # -- case 34 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/34
    def test_case_34_no_broad_ignore_cfg_or_assertion_deletion(self) -> None:
        """No blanket suppression exists on the file under acceptance."""
        text = source()
        for forbidden in (
            "#[ignore]",
            "#![allow(",
            "allow(dead_code)",
            "todo!",
            "unimplemented!",
            "cfg_attr(",
            "allow(clippy::all)",
        ):
            self.assertNotIn(forbidden, text)
        # The only allows are narrow, reasoned, per-lint lints.
        allows = re.findall(r"#\[allow\((.*?)\)\]", text, re.DOTALL)
        self.assertTrue(allows, "expected the file's narrow reasoned allows")
        for allow in allows:
            self.assertIn("reason =", allow)
        for allow in allows:
            self.assertNotIn("clippy::all", allow)
        # A stale source digest is rejected before anything else is believed.
        record = baseline_record()
        record["source"]["blob_sha256"] = "0" * 64
        ok, reason = validate_source_run_evidence(record)
        self.assertFalse(ok)
        self.assertEqual(reason, "R-STALE-SOURCE-DIGEST")

    # -- case 35 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/35
    def test_case_35_package_run_passes_or_stays_non_green(self) -> None:
        """Actual run evidence: a red run must name its separately owned failures."""
        record = load_run_evidence("case-35-package-run")
        if record is None:
            self.fail(
                "no actual package run evidence at %s; per TASK.md a missing "
                "Windows run stays incomplete and is never a simulated pass" % evidence_path("case-35-package-run")
            )
        ok, reason = validate_source_run_evidence(record)
        self.assertTrue(ok, reason)

    # -- case 36 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/36
    def test_case_36_privileged_run_carries_real_provenance(self) -> None:
        """Actual privileged run evidence must carry Windows provenance."""
        record = load_run_evidence("case-36-privileged-run")
        if record is None:
            self.fail(
                "no actual privileged Windows run evidence at %s; per TASK.md "
                "missing setup stays incomplete, never a simulated pass"
                % evidence_path("case-36-privileged-run")
            )
        ok, reason = validate_source_run_evidence(record)
        self.assertTrue(ok, reason)

    # -- case 37 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/37
    def test_case_37_package_clippy_has_no_broad_suppression(self) -> None:
        """The recorded Clippy evidence may not rest on broad suppression."""
        record = baseline_record()
        record["clippy"] = {"broad_suppression": True}
        ok, reason = validate_source_run_evidence(record)
        self.assertFalse(ok)
        self.assertEqual(reason, "R-CLIPPY-BROAD-SUPPRESSION")
        # Source-side corroboration: the file's own allows are narrow, reasoned.
        allows = re.findall(r"#\[allow\((.*?)\)\]", source(), re.DOTALL)
        self.assertTrue(allows)
        for allow in allows:
            self.assertIn("reason =", allow)

    # -- case 38 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/38
    def test_case_38_changed_paths_are_exactly_test_only(self) -> None:
        """Only the three #846-scope paths may appear in the diff evidence."""
        self.assertEqual(
            ALLOWED_CHANGED_PATHS,
            frozenset(
                {
                    STAGING_REL,
                    "scripts/tests/test_windows_staging_acceptance.py",
                    "scripts/testdata/windows-staging/invalid_evidence.json",
                }
            ),
        )
        record = baseline_record()
        ok, reason = validate_source_run_evidence(record)
        self.assertTrue(ok, reason)
        for out_of_scope in (
            "Cargo.toml",
            "Cargo.lock",
            "AGENTS.md",
            ".swarm/state.json",
            "scripts/docs_read.py",
        ):
            record["changed_paths"] = sorted(ALLOWED_CHANGED_PATHS) + [out_of_scope]
            ok, reason = validate_source_run_evidence(record)
            self.assertFalse(ok, out_of_scope)
            self.assertEqual(reason, "R-CHANGED-PATH-OUT-OF-SCOPE", out_of_scope)

    # -- case 39 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/39
    def test_case_39_no_second_stager_or_weakened_ownership(self) -> None:
        """Exactly one Agent Bridge stager exists and ownership is not weakened."""
        text = source()
        for entry in (
            "pub fn prepare_agent_bridge_stage(",
            "pub fn publish_agent_bridge_stage(",
            "pub fn reconcile_agent_bridge_stage(",
            "pub struct AgentBridgeStagePrepared {",
        ):
            self.assertEqual(text.count(entry), 1, entry)
        # Ownership refusal stays in force.
        self.assertIn("PackageStagingError::RollbackRefused", text)
        # No second, alternate staging entry point was introduced.
        for absent in (
            "fn stage_agent_bridge(",
            "fn prepare_agent_bridge_stage_unsafe(",
            "fn copy_agent_bridge_stage(",
        ):
            self.assertNotIn(absent, text)

    # -- case 40 ---------------------------------------------------------
    # WORK_UNIT_CASE: 846/40
    def test_case_40_package_proof_is_not_relabelled(self) -> None:
        """A package test result stays a package-test proof level."""
        record = baseline_record()
        ok, reason = validate_source_run_evidence(record)
        self.assertTrue(ok, reason)
        for relabel in ("ProductProof", "installation", "release", "runtime-support"):
            record["proof_level"] = relabel
            ok, reason = validate_source_run_evidence(record)
            self.assertFalse(ok, relabel)
            self.assertEqual(reason, "R-PROOF-RELABELLED", relabel)


class InvalidEvidenceFixtureTests(unittest.TestCase):
    """W3: every negative fixture must be rejected, with its named reason."""

    @classmethod
    def setUpClass(cls) -> None:
        assert FIXTURE.is_file(), FIXTURE
        load_fixtures()

    def test_every_invalid_fixture_is_rejected_for_its_named_reason(self) -> None:
        for entry in fixture_records():
            ok, reason = validate_source_run_evidence(entry["evidence"])
            self.assertFalse(ok, "fixture %s was accepted as evidence" % entry["id"])
            self.assertEqual(reason, entry["expected_reason"], entry["id"])

    def test_fixtures_are_finite_and_inert(self) -> None:
        inert = load_fixtures()["inertness"]
        self.assertEqual(inert["record_count"], len(fixture_records()))
        for key in (
            "executes_code",
            "spawns_processes",
            "performs_io",
            "opens_network",
            "reads_clock",
            "reads_ambient_environment",
            "expands_placeholders",
            "unbounded_generators",
        ):
            self.assertFalse(inert[key], key)
        raw = FIXTURE.read_text(encoding="utf-8")
        for token in ("${", "{{", "<repeat", "ELIOT_", "os.environ", "PATH="):
            self.assertNotIn(token, raw, token)
        # A closed, finite document: re-parsing yields the identical value.
        self.assertEqual(json.loads(raw), load_fixtures())


if __name__ == "__main__":  # pragma: no cover - manual invocation helper
    unittest.main()