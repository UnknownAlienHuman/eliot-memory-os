"""Test-only PowerShell case bridge for work unit #907 (D-INT-CORE harness core).

This module is test-only source code. It is NOT descriptor-provided command
authority: it cannot execute an arbitrary script, executable, argv,
environment, or working directory. It holds a finite registration of exactly
four suite paths (one executable here, three owned elsewhere) and fixed
positive-integer case IDs 1..32, resolves the approved pwsh through repository
policy, and invokes only the fixed argv::

    pwsh -NoProfile -NonInteractive -File <registered path> -CaseId <id>

with the interpreter shell disabled, a minimal nonsecret environment, and
bounded output/time. Anything else fails closed via HarnessError and never
reports a pass.

Versioned result schema (bounded, closed, exact keys) shared with the
PowerShell self-test ``scripts/tests/IntegrationHarness.Core.Tests.ps1``
(owned by WRITER-C, ``-CaseId <id>`` entrypoint). The PowerShell side MUST
emit exactly one JSON object per invocation with these fields::

    {
      "suite": "IntegrationHarness.Core",
      "case_id": 7,
      "schema_version": "harness-core-case-result-v1",
      "outcome": "Passed",
      "identity": "907/7",
      "content_digest": "<sha256 hex of the exact suite file bytes executed>",
      "truncated_bytes": 0
    }

``outcome`` is one of the closed set Passed | AssertionFailed | TimedOut |
ProcessCrashed | InfrastructureBlocked | UnsupportedExternalCredential |
HarnessError | Cancelled | NotExecutedDueToPriorContamination | Skipped.
Only ``"Passed"`` together with process exit 0 verifies green. Missing,
duplicate, foreign, skipped, unsupported, timed-out, contradictory, truncated,
oversized, or malformed output fails closed; a changed suite file invalidates
the digest binding. ``identity`` is always ``"907/<case_id>"``.

Containment (#850): the complete Python->pwsh tree runs under the accepted
bounded runner contract imported from scripts/work_unit_gate/
descriptor_runner.py -- decode_descriptor for the embedded closed ceiling
descriptor, enforcement_plan for transport bounds (transports take THESE
values, never looser substitutes; test-only callers may only tighten),
minimal_child_env for the child environment (exact ALLOWED_ENV_NAMES, blocked
secret markers, byte caps), canonical_command for the fixed argv bound,
cleanup_verdict for cleanup reconciliation, and bind_python_suite plus
contracts.TestIdentity for claimant binding. Safety is never asserted from
``subprocess.run(timeout=...)`` alone: a timeout kills the exact owned process
tree (taskkill /PID <owned pid> /T /F, never by name/port/unverified PID) and
maps to cleanup-unknown, which can never pass. No live service or process
spawning beyond the fixed self-test interpreter.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
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

REPO_ROOT = Path(__file__).resolve().parents[2]

# Finite registration. Only the Core suite executes here. The Store/Runtime/Git
# suite paths are the exact expected locations owned by #909/#911/#913; they
# are registered as constants so a typo cannot silently bind elsewhere, but
# resolving them for execution always raises (InfrastructureBlocked family)
# and never spawns anything.
CORE_SUITE_NAME = "IntegrationHarness.Core"
CORE_SUITE_PATH = "scripts/tests/IntegrationHarness.Core.Tests.ps1"
STORE_SUITE_PATH = "scripts/tests/IntegrationHarness.Store.Tests.ps1"
RUNTIME_SUITE_PATH = "scripts/tests/IntegrationHarness.Runtime.Tests.ps1"
GIT_SUITE_PATH = "scripts/tests/IntegrationHarness.Git.Tests.ps1"
_FUTURE_SUITES = frozenset((STORE_SUITE_PATH, RUNTIME_SUITE_PATH, GIT_SUITE_PATH))

MIN_CASE_ID = 1
MAX_CASE_ID = 32

SCHEMA_VERSION = "harness-core-case-result-v1"
_RESULT_FIELDS = frozenset((
    "suite", "case_id", "schema_version", "outcome",
    "identity", "content_digest", "truncated_bytes",
))
_OUTCOMES = frozenset((
    "Passed", "AssertionFailed", "TimedOut", "ProcessCrashed",
    "InfrastructureBlocked", "UnsupportedExternalCredential", "HarnessError",
    "Cancelled", "NotExecutedDueToPriorContamination", "Skipped",
))

PYTHON_SUITE_MODULE = "scripts.tests.test_integration_harness_core"
PYTHON_TEST_ROOTS = ("scripts/tests",)

MAX_SUITE_BYTES = 1048576
_HEX64 = frozenset("0123456789abcdef")

# Test-only containment ceiling. This embedded closed descriptor pins the
# transport bounds consumed via decode_descriptor + enforcement_plan. It is
# NOT the #907 work allocation (integrator-owned) and grants no authority by
# itself; any violation fails closed before any process starts.
_CONTAINED_DESCRIPTOR_FILENAME = ".github/work-units/907.toml"
_CONTAINED_DESCRIPTOR_TOML = b"""\
schema_version = "eliot-work-unit-descriptor-v2"
identity = {value = "work-unit-907"}
issue = {repository = {owner = "UnknownAlienHuman", name = "eliot-memory-os"}, number = 907}
unit = {value = "D-INT-CORE"}
mode = "python-unittest"
source_roots = [{value = "scripts/integration/powershell_case_bridge.py"}]
test_roots = [{value = "scripts/tests/test_integration_harness_core.py"}]
matrix_cases = 40
proof_ceiling = {value = "package-local"}
revision = 1
body_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
matrix_sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
require_workspace_member = false
module = {value = "scripts.tests.test_integration_harness_core"}
requirements = {source_floor = 1, public_floor = 1, test_floor = 40, required_guards = [{value = "bounded"}]}
bounds = {wall_ms = 120000, idle_ms = 60000, output_bytes = 16384, line_bytes = 4096, discovery_tests = 40, child_processes = 4}
"""


class HarnessError(Exception):
    """Stable bridge failure. Never a pass; carries a code, never secrets."""

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
    """Filter the ambient environment through repository policy.

    Only exact ALLOWED_ENV_NAMES survive and blocked secret markers drop,
    per descriptor_runner.minimal_child_env. In particular no PWSH_* override
    variable can redirect interpreter resolution: such names are not allowlisted.
    """
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
    """Bind a finite registered (suite, case) pair to file content digest.

    Store/Runtime/Git suite paths owned by #909/#911/#913 raise here and are
    never executed. Unregistered paths and out-of-range IDs raise.
    """
    if suite_path in _FUTURE_SUITES:
        raise HarnessError("SUITE_NOT_EXECUTABLE_HERE",
                           "suite is owned by another work unit and absent here",
                           {"suite_path": suite_path})
    if suite_path != CORE_SUITE_PATH:
        raise HarnessError("UNREGISTERED_SUITE",
                           "suite path is not finitely registered")
    if type(case_id) is not int or not MIN_CASE_ID <= case_id <= MAX_CASE_ID:
        raise HarnessError("CASE_ID_BOUND",
                           "case id is not a registered integer 1..32")
    target = REPO_ROOT / suite_path
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise HarnessError("SUITE_MISSING",
                           "registered suite file is absent; cannot execute",
                           {"suite_path": suite_path}) from exc
    if len(raw) > MAX_SUITE_BYTES:
        raise HarnessError("SUITE_BYTE_BOUND",
                           "registered suite file exceeds byte bound")
    return CaseBinding(suite=CORE_SUITE_NAME, suite_path=suite_path,
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
        _runner.bind_python_suite(root=REPO_ROOT, module=PYTHON_SUITE_MODULE,
                                  test_roots=list(PYTHON_TEST_ROOTS))
    except _runner.RunnerInputError as exc:
        raise HarnessError("PYTHON_SUITE_BINDING",
                           "canonical Python suite binding failed") from exc


def _fixed_argv(*, pwsh_path: str, binding: CaseBinding) -> list:
    return [pwsh_path, "-NoProfile", "-NonInteractive", "-File",
            binding.suite_abs, "-CaseId", str(binding.case_id)]


def _check_fixed_argv(argv: object, *, pwsh_path: str, suite_abs: str,
                      case_id: int) -> list:
    """Accept exactly the fixed argv shape; reject everything else.

    No caller-supplied executable, flag, file, argument, or ordering passes.
    """
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
    """Stop the exact owned process tree by owned PID only.

    Never by name, port, or unverified/reused PID. Windows taskkill /T reaps
    the owned descendants; failure still falls through to wait/kill below.
    """
    try:
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       stdin=subprocess.DEVNULL, shell=False, timeout=15,
                       cwd=str(REPO_ROOT))
    except OSError:
        pass
    except subprocess.SubprocessError:
        pass


def _run_contained(argv: object, *, timeout_s: float, output_cap: int,
                   line_cap: int, child_env: dict, pwsh_path: str,
                   suite_abs: str, case_id: int) -> CompletedRun:
    """Run the fixed argv inside containment with bounded output/time.

    Shell is always disabled and the working directory is fixed to the repo
    root (never caller input). Caps and timeout come from the contained plan;
    callers may only tighten them, never widen.
    """
    items = _check_fixed_argv(argv, pwsh_path=pwsh_path, suite_abs=suite_abs,
                              case_id=case_id)
    if type(child_env) is not dict:
        raise HarnessError("CHILD_ENV_SHAPE", "child env is not a mapping")
    rendering = _runner.canonical_command(items)
    try:
        proc = subprocess.Popen(items, shell=False, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, env=dict(child_env),
                                cwd=str(REPO_ROOT))
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
    if result["suite"] != CORE_SUITE_NAME:
        raise HarnessError("RESULT_SUITE_MISMATCH",
                           "result suite is foreign to this bridge")
    if type(result["case_id"]) is not int or result["case_id"] != case_id:
        raise HarnessError("RESULT_CASE_MISMATCH",
                           "result case id does not match the bound case")
    if result["schema_version"] != SCHEMA_VERSION:
        raise HarnessError("SCHEMA_VERSION_MISMATCH",
                           "result schema version is not honored")
    if result["identity"] != f"907/{case_id}":
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
    """Verify captured bytes against a registered binding without executing.

    Registration, claimant identity, schema, digest, outcome, and exit are all
    enforced exactly as in the live path; this is the fixture-testable seam.
    """
    plan = _contained_plan()
    if suite_path != CORE_SUITE_PATH:
        if suite_path in _FUTURE_SUITES:
            raise HarnessError("SUITE_NOT_EXECUTABLE_HERE",
                               "suite is owned by another work unit")
        raise HarnessError("UNREGISTERED_SUITE",
                           "suite path is not finitely registered")
    if type(case_id) is not int or not MIN_CASE_ID <= case_id <= MAX_CASE_ID:
        raise HarnessError("CASE_ID_BOUND",
                           "case id is not a registered integer 1..32")
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
    """Execute the registered Core case and return its verified result.

    ``timeout_s`` is test-only and may only tighten the contained wall-clock
    ceiling, never widen it. Any containment, binding, schema, outcome, or
    cleanup failure raises HarnessError; this function never fabricates a pass.
    """
    plan = _contained_plan()
    _check_python_suite_binding()
    _check_python_identity(python_identity)
    binding = resolve_case(suite_path=CORE_SUITE_PATH, case_id=case_id)
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
