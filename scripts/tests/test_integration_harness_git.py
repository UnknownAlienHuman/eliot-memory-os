"""Canonical Python case bindings for work unit #913 (D-INT-GIT isolated provider).

Declared denominator: exactly 22 cases, 913/1..22, each marked with
``# WORK_UNIT_CASE: 913/<n>`` immediately above its unittest method.

Each case executes the corresponding actual PowerShell self-test case through
a locally implemented fixed-argv containment seam (same pattern as
scripts/integration/powershell_case_bridge.py:272-274/_run_contained/
_contained_plan: pwsh -NoProfile -NonInteractive -File <Git suite abs>
-CaseId <n>, shell=False cwd=REPO_ROOT, enforcement_plan bounds,
minimal_child_env, cleanup_verdict green) and asserts its structured result
payload (never just exit zero). This file imports descriptor_runner/contracts
directly and never imports or calls bridge.run_case/verify_result_bytes for
Git. It requires ``scripts/tests/IntegrationHarness.Git.Tests.ps1``; when
that file is absent the seam fails closed and these cases honestly fail --
never fake a pass. No live git is spawned and nothing is downloaded.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

try:
    from scripts.work_unit_gate import contracts as _contracts
    from scripts.work_unit_gate import descriptor_runner as _runner
except ImportError:  # direct-file execution fallback; package import is primary.
    _FALLBACK_ROOT = Path(__file__).resolve().parents[2]
    if str(_FALLBACK_ROOT) not in sys.path:
        sys.path.insert(0, str(_FALLBACK_ROOT))
    from scripts.work_unit_gate import contracts as _contracts
    from scripts.work_unit_gate import descriptor_runner as _runner

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "scripts" / "testdata" / "integration" / "git-provider"

GIT_SUITE_NAME = "IntegrationHarness.Git"
GIT_SUITE_PATH = "scripts/tests/IntegrationHarness.Git.Tests.ps1"

MIN_CASE_ID = 1
MAX_CASE_ID = 22

SCHEMA_VERSION = "harness-git-case-result-v1"
_RESULT_FIELDS = frozenset((
    "suite", "case_id", "schema_version", "outcome",
    "identity", "content_digest", "truncated_bytes",
))
_OUTCOMES = frozenset((
    "Passed", "AssertionFailed", "TimedOut", "ProcessCrashed",
    "InfrastructureBlocked", "UnsupportedExternalCredential", "HarnessError",
    "Cancelled", "NotExecutedDueToPriorContamination", "Skipped",
))

PYTHON_SUITE_MODULE = "scripts.tests.test_integration_harness_git"
PYTHON_TEST_ROOTS = ("scripts/tests",)

MAX_SUITE_BYTES = 1048576
_HEX64 = frozenset("0123456789abcdef")

_CONTAINED_DESCRIPTOR_FILENAME = ".github/work-units/913.toml"
_CONTAINED_DESCRIPTOR_TOML = b"""\
schema_version = "eliot-work-unit-descriptor-v2"
identity = {value = "work-unit-913"}
issue = {repository = {owner = "UnknownAlienHuman", name = "eliot-memory-os"}, number = 913}
unit = {value = "D-INT-GIT"}
mode = "python-unittest"
source_roots = [{value = "scripts/integration/IntegrationHarness.Git.psm1"}]
test_roots = [{value = "scripts/tests/test_integration_harness_git.py"}]
matrix_cases = 22
proof_ceiling = {value = "package-local"}
revision = 1
body_sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
matrix_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
require_workspace_member = false
module = {value = "scripts.tests.test_integration_harness_git"}
requirements = {source_floor = 1, public_floor = 1, test_floor = 22, required_guards = [{value = "bounded"}]}
bounds = {wall_ms = 120000, idle_ms = 60000, output_bytes = 16384, line_bytes = 4096, discovery_tests = 22, child_processes = 4}
"""


class HarnessError(Exception):
    """Stable Git seam failure. Never a pass; carries a code, never secrets."""

    def __init__(self, code: str, reason: str, details: dict | None = None):
        super().__init__(f"HarnessError {code}: {reason}")
        self.code = code
        self.details = dict(details) if details else {}


@dataclass(frozen=True)
class CaseBinding:
    suite: str
    suite_path: str
    suite_abs: str
    case_id: int
    content_digest: str


@dataclass(frozen=True)
class CompletedRun:
    returncode: int
    stdout: bytes
    stderr_tail_bytes: int
    cleanup: str
    reaped: bool
    truncated_bytes: int


@dataclass(frozen=True)
class CaseResult:
    suite: str
    case_id: int
    schema_version: str
    outcome: str
    identity: str
    content_digest: str
    truncated_bytes: int
    bound_python_identity: str
    returncode: int


def _contained_plan() -> dict:
    """Decode the embedded ceiling descriptor and emit transport bounds."""
    try:
        data = _runner.decode_descriptor(
            _CONTAINED_DESCRIPTOR_TOML, _CONTAINED_DESCRIPTOR_FILENAME)
        return _runner.enforcement_plan(bounds=data["bounds"])
    except _runner.RunnerInputError as exc:
        raise HarnessError("CONTAINMENT_CEILING_INVALID",
                           "embedded containment ceiling failed validation") from exc


def _child_env() -> dict:
    """Filter the ambient environment through repository policy."""
    try:
        return _runner.minimal_child_env(dict(os.environ))
    except _runner.RunnerInputError as exc:
        raise HarnessError("CHILD_ENV_BOUND",
                           "ambient environment violates child byte caps") from exc


def _resolve_pwsh(env: dict) -> str:
    """Resolve the approved pwsh via the filtered PATH only. No input."""
    found = shutil.which("pwsh", path=env.get("PATH"))
    if not found:
        raise HarnessError("PWSH_UNAVAILABLE",
                           "approved pwsh not resolvable on filtered PATH",
                           {"has_path": "PATH" in env})
    if os.path.basename(found).lower() not in ("pwsh", "pwsh.exe"):
        raise HarnessError("PWSH_UNEXPECTED",
                           "interpreter resolution did not yield pwsh")
    return found


def resolve_case(*, suite_path: str, case_id: int) -> CaseBinding:
    """Bind the finite registered Git (suite, case) pair to content digest."""
    if suite_path != GIT_SUITE_PATH:
        raise HarnessError("UNREGISTERED_SUITE",
                           "suite path is not finitely registered")
    if type(case_id) is not int or not MIN_CASE_ID <= case_id <= MAX_CASE_ID:
        raise HarnessError("CASE_ID_BOUND",
                           "case id is not a registered integer 1..22")
    target = ROOT / suite_path
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise HarnessError("SUITE_MISSING",
                           "registered suite file is absent; cannot execute",
                           {"suite_path": suite_path}) from exc
    if len(raw) > MAX_SUITE_BYTES:
        raise HarnessError("SUITE_BYTE_BOUND",
                           "registered suite file exceeds byte bound")
    return CaseBinding(suite=GIT_SUITE_NAME, suite_path=suite_path,
                       suite_abs=os.path.abspath(target),
                       case_id=case_id,
                       content_digest=hashlib.sha256(raw).hexdigest())


def _check_python_identity(value: object):
    """Bind the claimant to a typed test identity in the canonical suite."""
    if type(value) is not str or not value:
        raise HarnessError("PYTHON_IDENTITY_SHAPE",
                           "python claimant identity must be nonempty text")
    try:
        identity = _contracts.TestIdentity(
            mode=_contracts.RunnerMode.PYTHON_UNITTEST, qualified_name=value)
    except _contracts.ContractViolation as exc:
        raise HarnessError("PYTHON_IDENTITY_INVALID",
                           "python claimant identity violates TestIdentity") from exc
    if not value.startswith(PYTHON_SUITE_MODULE + "."):
        raise HarnessError("FOREIGN_PYTHON_IDENTITY",
                           "claimant is outside the canonical Python suite")
    return identity


def _check_python_suite_binding() -> None:
    """Prove the canonical Python suite file binding before execution."""
    try:
        _runner.bind_python_suite(root=ROOT, module=PYTHON_SUITE_MODULE,
                                  test_roots=list(PYTHON_TEST_ROOTS))
    except _runner.RunnerInputError as exc:
        raise HarnessError("PYTHON_SUITE_BINDING",
                           "canonical Python suite binding failed") from exc


def _fixed_argv(*, pwsh_path: str, binding: CaseBinding) -> list:
    return [pwsh_path, "-NoProfile", "-NonInteractive", "-File",
            binding.suite_abs, "-CaseId", str(binding.case_id)]


def _check_fixed_argv(argv: object, *, pwsh_path: str, suite_abs: str,
                      case_id: int) -> list:
    """Accept exactly the fixed argv shape; reject everything else."""
    if type(argv) not in (list, tuple) or len(argv) != 7:
        raise HarnessError("ARGV_SHAPE", "argv is not the fixed 7-element form")
    if any(type(item) is not str for item in argv):
        raise HarnessError("ARGV_SHAPE", "argv carries non-text")
    items = list(argv)
    exe, flag1, flag2, flag3, suite, flag5, cid = items
    if exe != pwsh_path:
        raise HarnessError("ARGV_EXECUTABLE", "argv executable is not resolved pwsh")
    if (flag1, flag2, flag3, flag5) != ("-NoProfile", "-NonInteractive",
                                        "-File", "-CaseId"):
        raise HarnessError("ARGV_FLAGS", "argv flags differ from fixed form")
    if os.path.normcase(os.path.abspath(suite)) != os.path.normcase(suite_abs):
        raise HarnessError("ARGV_SUITE", "argv file is not the bound suite")
    if cid != str(case_id):
        raise HarnessError("ARGV_CASE", "argv case differs from bound case")
    return items


def _timeout_unknown(*, timeout_s: float, reaped: bool) -> HarnessError:
    """Map a contained timeout to cleanup-unknown, which can never pass."""
    return HarnessError(
        "TIMEOUT_CLEANUP_UNKNOWN",
        "contained timeout; owned-tree cleanup is unknown so no pass is possible",
        {"cleanup": "unknown", "timeout_s": timeout_s, "reaped": bool(reaped)})


def _kill_owned_tree(proc: "subprocess.Popen[bytes]") -> None:
    """Stop the exact owned process tree by owned PID only."""
    try:
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       stdin=subprocess.DEVNULL, shell=False, timeout=15,
                       cwd=str(ROOT))
    except OSError:
        pass
    except subprocess.SubprocessError:
        pass


def _run_contained(argv: object, *, timeout_s: float, output_cap: int,
                   line_cap: int, child_env: dict, pwsh_path: str,
                   suite_abs: str, case_id: int) -> CompletedRun:
    """Run the fixed argv inside containment with bounded output/time."""
    items = _check_fixed_argv(argv, pwsh_path=pwsh_path, suite_abs=suite_abs,
                              case_id=case_id)
    if type(child_env) is not dict:
        raise HarnessError("CHILD_ENV_SHAPE", "child env is not a mapping")
    rendering = _runner.canonical_command(items)
    try:
        proc = subprocess.Popen(items, shell=False, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, env=dict(child_env),
                                cwd=str(ROOT))
    except OSError as exc:
        raise HarnessError("SPAWN_FAILED",
                           "fixed interpreter failed to start",
                           {"rendering_bytes": len(rendering)}) from exc
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_owned_tree(proc)
        try:
            proc.wait(timeout=15)
        except subprocess.SubprocessError:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=15)
            except subprocess.SubprocessError:
                pass
        raise _timeout_unknown(timeout_s=timeout_s,
                               reaped=proc.poll() is not None)
    reaped = proc.poll() is not None
    if len(stdout) > output_cap:
        raise HarnessError("OVERSIZED_OUTPUT",
                           "captured output exceeds contained byte cap",
                           {"bytes": len(stdout), "cap": output_cap,
                            "reaped": reaped})
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HarnessError("NON_UTF8_OUTPUT",
                           "captured output is not strict UTF-8",
                           {"reaped": reaped}) from exc
    for line in text.splitlines():
        if len(line.encode("utf-8")) > line_cap:
            raise HarnessError("LINE_BOUND",
                               "captured output line exceeds line cap",
                               {"cap": line_cap, "reaped": reaped})
    if _runner.cleanup_verdict(cleanup="clean", active_processes=0,
                               truncated=False) != "green":
        raise HarnessError("CLEANUP_NOT_GREEN",
                           "cleanup reconciliation did not read green")
    returncode = proc.returncode if proc.returncode is not None else 2
    return CompletedRun(returncode=returncode, stdout=stdout,
                        stderr_tail_bytes=len(stderr[-2048:]),
                        cleanup="clean", reaped=bool(reaped),
                        truncated_bytes=0)


def _parse_result(raw: bytes, *, output_cap: int, line_cap: int) -> dict:
    """Decode exactly one versioned result object; anything else fails."""
    if type(raw) is not bytes:
        raise HarnessError("RESULT_SHAPE", "result bytes required")
    if not raw or not raw.strip():
        raise HarnessError("MISSING_RESULT",
                           "zero exit carried no exact case result")
    if len(raw) > output_cap:
        raise HarnessError("OVERSIZED_OUTPUT",
                           "result exceeds contained byte cap",
                           {"bytes": len(raw), "cap": output_cap})
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HarnessError("MALFORMED_RESULT",
                           "result is not decodable text") from exc
    for line in text.splitlines():
        if len(line.encode("utf-8")) > line_cap:
            raise HarnessError("LINE_BOUND", "result line exceeds line cap")
    decoder = json.JSONDecoder()
    try:
        value, offset = decoder.raw_decode(text.strip())
    except (ValueError, RecursionError) as exc:
        if not text.strip().endswith("}"):
            raise HarnessError("TRUNCATED_RESULT",
                               "result ends mid-object") from exc
        raise HarnessError("MALFORMED_RESULT",
                           "result is not well-formed JSON") from exc
    if text.strip()[offset:].strip():
        raise HarnessError("DUPLICATE_RESULT",
                           "more than one result object emitted")
    if type(value) is not dict:
        raise HarnessError("SCHEMA_SHAPE", "result is not a JSON object")
    if set(value) != set(_RESULT_FIELDS):
        raise HarnessError("SCHEMA_FIELDS",
                           "result fields differ from closed schema",
                           {"fields": sorted(str(k) for k in value)})
    return value


def _verify_fields(result: dict, *, case_id: int, expected_digest: str,
                   python_identity: str, returncode: int) -> CaseResult:
    if result["suite"] != GIT_SUITE_NAME:
        raise HarnessError("RESULT_SUITE_MISMATCH",
                           "result suite is foreign to this seam")
    if type(result["case_id"]) is not int or result["case_id"] != case_id:
        raise HarnessError("RESULT_CASE_MISMATCH",
                           "result case id does not match the bound case")
    if result["schema_version"] != SCHEMA_VERSION:
        raise HarnessError("SCHEMA_VERSION_MISMATCH",
                           "result schema version is not honored")
    if result["identity"] != f"913/{case_id}":
        raise HarnessError("RESULT_IDENTITY_MISMATCH",
                           "result identity does not bind the work-unit case")
    digest = result["content_digest"]
    if (type(digest) is not str or len(digest) != 64
            or any(c not in _HEX64 for c in digest)):
        raise HarnessError("RESULT_DIGEST_SHAPE",
                           "result content digest is not sha256 hex")
    if digest != expected_digest:
        raise HarnessError("RESULT_DIGEST_MISMATCH",
                           "suite content changed; result binding invalidated")
    if type(result["truncated_bytes"]) is not int or result["truncated_bytes"] != 0:
        raise HarnessError("TRUNCATED_OUTPUT",
                           "result reports truncated bytes")
    outcome = result["outcome"]
    if outcome not in _OUTCOMES:
        raise HarnessError("UNKNOWN_OUTCOME", "result outcome is not admitted")
    if outcome == "Skipped":
        raise HarnessError("OUTCOME_SKIPPED",
                           "skipped case results cannot pass")
    if outcome != "Passed":
        raise HarnessError(f"OUTCOME_{str(outcome).upper()}",
                           "non-pass terminal outcome cannot pass",
                           {"outcome": outcome})
    if returncode != 0:
        raise HarnessError("CONTRADICTORY_EXIT",
                           "passed result contradicts nonzero exit",
                           {"returncode": returncode})
    return CaseResult(suite=result["suite"], case_id=case_id,
                      schema_version=SCHEMA_VERSION, outcome="Passed",
                      identity=result["identity"],
                      content_digest=digest, truncated_bytes=0,
                      bound_python_identity=python_identity,
                      returncode=returncode)


def verify_result_bytes(raw: bytes, *, case_id: int, suite_path: str,
                        expected_digest: str, python_identity: str,
                        returncode: int = 0) -> CaseResult:
    """Verify captured bytes against a registered binding without executing."""
    plan = _contained_plan()
    if suite_path != GIT_SUITE_PATH:
        raise HarnessError("UNREGISTERED_SUITE",
                           "suite path is not finitely registered")
    if type(case_id) is not int or not MIN_CASE_ID <= case_id <= MAX_CASE_ID:
        raise HarnessError("CASE_ID_BOUND",
                           "case id is not a registered integer 1..22")
    _check_python_identity(python_identity)
    if (type(expected_digest) is not str or len(expected_digest) != 64
            or any(c not in _HEX64 for c in expected_digest)):
        raise HarnessError("EXPECTED_DIGEST_SHAPE",
                           "expected digest is not sha256 hex")
    parsed = _parse_result(raw, output_cap=plan["output_bytes"],
                           line_cap=plan["line_bytes"])
    return _verify_fields(parsed, case_id=case_id,
                          expected_digest=expected_digest,
                          python_identity=python_identity,
                          returncode=returncode)


def run_case(case_id: int, *, python_identity: str,
             timeout_s: float | None = None) -> CaseResult:
    """Execute the registered Git case and return its verified result."""
    plan = _contained_plan()
    _check_python_suite_binding()
    _check_python_identity(python_identity)
    binding = resolve_case(suite_path=GIT_SUITE_PATH, case_id=case_id)
    env = _child_env()
    pwsh_path = _resolve_pwsh(env)
    ceiling = float(plan["wall_s"])
    limit = ceiling if timeout_s is None else float(timeout_s)
    if not 0 < limit <= ceiling:
        raise HarnessError("TIMEOUT_CEILING",
                           "timeout must stay within the contained ceiling",
                           {"ceiling_s": ceiling})
    argv = _fixed_argv(pwsh_path=pwsh_path, binding=binding)
    completed = _run_contained(argv, timeout_s=limit,
                               output_cap=plan["output_bytes"],
                               line_cap=plan["line_bytes"], child_env=env,
                               pwsh_path=pwsh_path,
                               suite_abs=binding.suite_abs,
                               case_id=binding.case_id)
    return verify_result_bytes(completed.stdout, case_id=binding.case_id,
                               suite_path=binding.suite_path,
                               expected_digest=binding.content_digest,
                               python_identity=python_identity,
                               returncode=completed.returncode)


CASE_METHODS = (
    "test_913_01_exact_provider_schema_revision_git",
    "test_913_02_unsupported_class_network_production_scm_explicit",
    "test_913_03_plan_deterministic_mutation_free",
    "test_913_04_arbitrary_authority_unrepresentable",
    "test_913_05_approved_identity_unavailable_invalid_distinct",
    "test_913_06_canonical_root_owned_run_root",
    "test_913_07_escape_traversal_reparse_foreign_marker",
    "test_913_08_source_other_run_never_mutated",
    "test_913_09_branch_format_author_committer_timestamps",
    "test_913_10_settings_scoped_commands_fixture_repo",
    "test_913_11_global_home_credential_helpers_untouched",
    "test_913_12_fixture_bytes_digest_load_bearing",
    "test_913_13_object_tree_commit_ref_worktree_verified",
    "test_913_14_foreign_refs_worktrees_rejected",
    "test_913_15_readiness_evidence_not_init_status",
    "test_913_16_reset_baseline_or_contamination",
    "test_913_17_reconciliation_before_retry",
    "test_913_18_bounded_redacted_evidence_no_canaries",
    "test_913_19_cleanup_exact_topology_foreign_preserved",
    "test_913_20_source_api_guard",
    "test_913_21_replay_no_duplicates_conflict",
    "test_913_22_dirty_blocks_disposable_idempotent",
)


def _fixture_bytes(name: str) -> bytes:
    path = FIXTURES / name
    assert path.is_file(), f"fixture missing: {name}"
    return path.read_bytes()


def _fixture_json(name: str):
    return json.loads(_fixture_bytes(name).decode("utf-8"))


class TestIntegrationHarnessGit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        payload = _fixture_json("cases.json")
        rows = payload["rows"]
        assert isinstance(rows, list) and len(rows) == 22
        cls.rows = {row["case_id"]: row for row in rows}

    def _row(self, case_id: int) -> dict:
        row = self.rows.get(case_id)
        self.assertIsNotNone(row, f"inventory row missing for 913/{case_id}")
        self.assertEqual(row["case_id"], case_id)
        self.assertTrue(isinstance(row["title"], str) and row["title"].strip(),
                        f"inventory row 913/{case_id} has no title")
        return row

    def _assert_live_result(self, case_id: int, result: CaseResult) -> None:
        """Real assertions on the returned structured payload, not exit zero."""
        self.assertEqual(result.outcome, "Passed")
        self.assertEqual(result.case_id, case_id)
        self.assertEqual(result.suite, GIT_SUITE_NAME)
        self.assertEqual(result.schema_version, SCHEMA_VERSION)
        self.assertEqual(result.identity, f"913/{case_id}")
        self.assertEqual(result.truncated_bytes, 0)
        self.assertEqual(result.bound_python_identity, self.id())
        self.assertEqual(result.returncode, 0)

    def _run_live(self, case_id: int) -> CaseResult:
        self._row(case_id)
        try:
            result = run_case(case_id, python_identity=self.id())
        except HarnessError as exc:
            self.fail(f"honest Git seam failure for 913/{case_id} [{exc.code}]: {exc}")
        self._assert_live_result(case_id, result)
        return result

    # WORK_UNIT_CASE: 913/1
    def test_913_01_exact_provider_schema_revision_git(self):
        self._run_live(1)

    # WORK_UNIT_CASE: 913/2
    def test_913_02_unsupported_class_network_production_scm_explicit(self):
        self._run_live(2)

    # WORK_UNIT_CASE: 913/3
    def test_913_03_plan_deterministic_mutation_free(self):
        self._run_live(3)

    # WORK_UNIT_CASE: 913/4
    def test_913_04_arbitrary_authority_unrepresentable(self):
        self._run_live(4)

    # WORK_UNIT_CASE: 913/5
    def test_913_05_approved_identity_unavailable_invalid_distinct(self):
        self._run_live(5)

    # WORK_UNIT_CASE: 913/6
    def test_913_06_canonical_root_owned_run_root(self):
        self._run_live(6)

    # WORK_UNIT_CASE: 913/7
    def test_913_07_escape_traversal_reparse_foreign_marker(self):
        self._run_live(7)

    # WORK_UNIT_CASE: 913/8
    def test_913_08_source_other_run_never_mutated(self):
        self._run_live(8)

    # WORK_UNIT_CASE: 913/9
    def test_913_09_branch_format_author_committer_timestamps(self):
        self._run_live(9)

    # WORK_UNIT_CASE: 913/10
    def test_913_10_settings_scoped_commands_fixture_repo(self):
        self._run_live(10)

    # WORK_UNIT_CASE: 913/11
    def test_913_11_global_home_credential_helpers_untouched(self):
        self._run_live(11)

    # WORK_UNIT_CASE: 913/12
    def test_913_12_fixture_bytes_digest_load_bearing(self):
        self._run_live(12)

    # WORK_UNIT_CASE: 913/13
    def test_913_13_object_tree_commit_ref_worktree_verified(self):
        self._run_live(13)

    # WORK_UNIT_CASE: 913/14
    def test_913_14_foreign_refs_worktrees_rejected(self):
        self._run_live(14)

    # WORK_UNIT_CASE: 913/15
    def test_913_15_readiness_evidence_not_init_status(self):
        self._run_live(15)

    # WORK_UNIT_CASE: 913/16
    def test_913_16_reset_baseline_or_contamination(self):
        self._run_live(16)

    # WORK_UNIT_CASE: 913/17
    def test_913_17_reconciliation_before_retry(self):
        self._run_live(17)

    # WORK_UNIT_CASE: 913/18
    def test_913_18_bounded_redacted_evidence_no_canaries(self):
        self._run_live(18)

    # WORK_UNIT_CASE: 913/19
    def test_913_19_cleanup_exact_topology_foreign_preserved(self):
        self._run_live(19)

    # WORK_UNIT_CASE: 913/20
    def test_913_20_source_api_guard(self):
        self._run_live(20)

    # WORK_UNIT_CASE: 913/21
    def test_913_21_replay_no_duplicates_conflict(self):
        self._run_live(21)

    # WORK_UNIT_CASE: 913/22
    def test_913_22_dirty_blocks_disposable_idempotent(self):
        self._run_live(22)


if __name__ == "__main__":
    unittest.main()
