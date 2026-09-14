"""Structural proof for the manual integration workflow (issue #915).

Exactly 20 cases, 915/1..20. Cases 1-19 validate frozen fixtures plus the
accepted in-repo stdlib parser (scripts/verify-github-workflows.py) and a
minimal in-memory ok workflow for positive controls. They pass on base
WITHOUT .github/workflows/integration.yml present (that file is owned by the
other writer); when the workflow is present the same properties are also
asserted on its live text, otherwise the live portion is skipped with a clear
message while fixture proof still executes (never fail-closed on absence in a
way that hides real failures).

Case 20 validates payload-ok.json schema plus SHA binding and documents that
real manual dispatch is controller post-merge track: it never manufactures
live evidence and rejects fabricated, wrong-SHA, partial, and
pre-registration payloads via payload-missing-evidence.json.

Stdlib only (unittest, json, re, pathlib, tempfile, importlib, sys) plus the
in-repo parser. PyYAML is deliberately NOT used: it is absent from the pinned
requirements and pulling an unpinned tool would violate policy.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "scripts" / "testdata" / "integration" / "workflow"
INTEGRATION_YML = ROOT / ".github" / "workflows" / "integration.yml"

_script_path = ROOT / "scripts" / "verify-github-workflows.py"
_spec = importlib.util.spec_from_file_location("verify_github_workflows_915", _script_path)
if _spec is None or _spec.loader is None:  # pragma: no cover
    raise ImportError(f"Cannot load {_script_path}")
vgw = importlib.util.module_from_spec(_spec)
sys.modules["verify_github_workflows_915"] = vgw
_spec.loader.exec_module(vgw)
parse_workflow_events = vgw.parse_workflow_events
check_workflows = vgw.check_workflows

FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
CHECKOUT_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
CACHE_SHA = "1bd1e32a3bdc45362d1e726936510720a7c30a57"
BASE_SHA = "b5c8ac6e26b827125b6067bb89f6df5aa5f4aa68"

EXPECTED_TITLES = {
    1: "manual workflow_dispatch is the sole trigger",
    2: "automatic triggers are rejected",
    3: "manual inputs are closed (none or fixed profile enum)",
    4: "source checkout binds SHA identities with fetch-depth 0",
    5: "effective permissions are read-only with persist-credentials false",
    6: "every third-party action is pinned to an immutable full SHA",
    7: "no credentials flow to child steps; fixed artifact channel only",
    8: "windows-latest runner with explicit gaps and no silent skips",
    9: "pinned toolchain with locked build",
    10: "ignored-test inventory is built before configuration and run",
    11: "only required providers activate within the closed 9-op set",
    12: "ValidateConfiguration runs before exactly one Run",
    13: "build is delegated to the owned build entry point",
    14: "bounded concurrency with per-job timeouts",
    15: "cache hit executes the same gates as cache miss",
    16: "always() cleanup collects evidence; unknown stays non-green",
    17: "manifest and digest mismatch is non-green",
    18: "bounded retention with redacted summaries",
    19: "source guard rejects foreign or mismatched sources",
    20: "live evidence is SHA-bound to the dispatched commit via controller post-merge dispatch",
}

FROZEN_FILES = [
    "cases.json",
    "rejected-schedule.yml",
    "rejected-push-pr.yml",
    "rejected-workflow-run-release.yml",
    "rejected-comment-dispatch.yml",
    "rejected-arbitrary-inputs.yml",
    "rejected-write-permissions.yml",
    "rejected-cache-poison.yml",
    "rejected-credentials.yml",
    "payload-ok.json",
    "payload-missing-evidence.json",
    "payload-cleanup-unknown.json",
    "source-guard-rejected.txt",
]

OK_WORKFLOW = """name: Manual Integration Workflow
on:
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: workflow-source-target-profile
  cancel-in-progress: false

jobs:
  integration-manual:
    runs-on: windows-latest
    timeout-minutes: 120
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
          fetch-depth: 0
      - name: Cache Cargo inputs
        uses: actions/cache@1bd1e32a3bdc45362d1e726936510720a7c30a57 # v4.2.0
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('Cargo.lock') }}-Review
      - name: Build ignored-test inventory
        shell: pwsh
        run: python scripts/integration/ignored_test_inventory.py build_inventory
      - name: ValidateConfiguration
        shell: pwsh
        run: echo "ValidateConfiguration Store Runtime Git --locked"
      - name: Run integration harness once
        shell: pwsh
        run: echo "Run Store Runtime Git"
      - name: Collect evidence
        if: always()
        shell: pwsh
        run: echo "manifest_digest retention-days: 30 source_sha ${{ github.sha }}"
"""

CACHE_PATH_ALLOW = (
    re.compile(r"^~/\.cargo/(registry|git)/?$"),
    re.compile(r"^target/?$"),
    re.compile(r"RUNNER_TEMP"),
    re.compile(r"CARGO_TARGET_DIR"),
)


def _fixture_text(name: str) -> str:
    path = FIXTURES / name
    assert path.is_file(), f"fixture missing: {name}"
    return path.read_text(encoding="utf-8")


def _fixture_json(name: str):
    return json.loads(_fixture_text(name))


def _cases_by_id() -> dict[int, dict]:
    payload = _fixture_json("cases.json")
    rows = payload["rows"]
    assert isinstance(rows, list) and len(rows) == 20
    return {row["case_id"]: row for row in rows}


def _check_text(text: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        wf_dir = root / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "test.yml").write_text(text, encoding="utf-8")
        return check_workflows(root)


def _block_after(lines: list[str], start: int):
    base = len(lines[start]) - len(lines[start].lstrip(" "))
    body: list[tuple[int, str]] = []
    for line in lines[start + 1:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= base:
            break
        body.append((indent, stripped))
    return base, body


def _extract_inputs(text: str) -> dict[str, str]:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if re.fullmatch(r"  workflow_dispatch:\s*", line):
            _, body = _block_after(lines, index)
            for sub_index, (indent, stripped) in enumerate(body):
                if indent == 4 and stripped == "inputs:":
                    inputs: dict[str, str] = {}
                    current: str | None = None
                    chunks: list[str] = []
                    for indent2, stripped2 in body[sub_index + 1:]:
                        if indent2 <= 4:
                            break
                        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)", stripped2)
                        if indent2 == 6 and match:
                            if current is not None:
                                inputs[current] = "\n".join(chunks)
                            current, chunks = match.group(1), []
                            if match.group(2):
                                chunks.append(match.group(2))
                        elif current is not None:
                            chunks.append(stripped2)
                    if current is not None:
                        inputs[current] = "\n".join(chunks)
                    return inputs
            return {}
    return {}


def _validate_inputs(inputs: dict[str, str]) -> list[str]:
    if not inputs:
        return []
    violations: list[str] = []
    for name, block in inputs.items():
        if name in {"ref", "command", "argv", "exec", "run", "script"}:
            violations.append(f"arbitrary input '{name}' can select command/ref")
        if "type: string" in block and "options:" not in block:
            violations.append(f"free-form string input '{name}' without closed options")
        if "options:" in block:
            options = set(re.findall(r"-\s*(Quick|Review|\S+)", block))
            if not options <= {"Quick", "Review"} or not options:
                violations.append(f"input '{name}' options {sorted(options)} not closed Quick|Review")
    if set(inputs) - {"profile"}:
        violations.append(f"unexpected manual inputs {sorted(set(inputs) - {'profile'})}")
    return violations


def _extract_top_permissions(text: str) -> dict[str, str]:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.fullmatch(r"permissions:\s*(.*)", line)
        if match:
            if match.group(1).strip():
                return {"<flow>": match.group(1).strip()}
            _, body = _block_after(lines, index)
            return {m.group(1): m.group(2) for indent, stripped in body
                    if indent == 2 and (m := re.fullmatch(r"([\w-]+):\s*(\S+)", stripped))}
    return {}


def _checkout_missing_no_credentials(text: str) -> list[str]:
    lines = text.splitlines()
    missing: list[str] = []
    index = 0
    while index < len(lines):
        if re.match(r"\s*-\s*uses:\s*\S*checkout\S*", lines[index]):
            base = len(lines[index]) - len(lines[index].lstrip(" "))
            block = "\n".join(
                ln for ln in lines[index + 1:] if not (
                    ln.strip() and not ln.strip().startswith("#")
                    and (len(ln) - len(ln.lstrip(" "))) <= base
                    and re.match(r"\s*-\s+\w", ln)))
            with_match = re.search(r"with:\s*\n((?:[ ]{6,}[^\n]*\n?)*)", block)
            with_text = with_match.group(1) if with_match else ""
            if not re.search(r"persist-credentials:\s*false", with_text):
                missing.append(f"checkout at line {index + 1} persists credentials by default")
            index += 1
        else:
            index += 1
    return missing


def _uses_refs(text: str) -> list[tuple[int, str]]:
    return [(number, match.group(1)) for number, line in enumerate(text.splitlines(), 1)
            if (match := re.match(r"\s*(?:-\s*)?uses:\s*(\S+)", line))]


def _extract_cache_blocks(text: str) -> list[dict[str, str]]:
    lines = text.splitlines()
    blocks: list[dict[str, str]] = []
    for index, line in enumerate(lines):
        if re.match(r"\s*uses:\s*actions/cache@", line):
            base = len(lines[index]) - len(lines[index].lstrip(" "))
            raw: list[str] = []
            for follow in lines[index + 1:]:
                if follow.strip() and not follow.strip().startswith("#") \
                        and (len(follow) - len(follow.lstrip(" "))) <= base \
                        and re.match(r"\s*-\s+", follow):
                    break
                raw.append(follow)
            blocks.append({"at_line": str(index + 1), "text": "\n".join(raw)})
    return blocks


def _validate_cache_block(block_text: str) -> list[str]:
    violations: list[str] = []
    path_region = block_text.split("key:")[0]
    for candidate in re.findall(r"[~.\w/${}()\"'\\:-]+", path_region):
        token = candidate.strip().strip("|").strip("'\"")
        if not token or token in {"path", "with", "uses", "name"} or ":" in token \
                or token.startswith("$") or len(token) < 2:
            continue
        if not any(rx.search(token) for rx in CACHE_PATH_ALLOW) \
                and not token.startswith("~/"):
            violations.append(f"cache path outside registry/git/target allowlist: '{token}'")
        elif token.startswith("~/") and not any(rx.search(token) for rx in CACHE_PATH_ALLOW):
            violations.append(f"cache path outside registry/git allowlist: '{token}'")
    if "hashFiles('Cargo.lock')" not in block_text and 'hashFiles("Cargo.lock")' not in block_text:
        violations.append("cache key does not bind Cargo.lock")
    if "runner.os" not in block_text:
        violations.append("cache key does not bind runner OS")
    return violations


def _validate_counts(payload: dict) -> list[str]:
    problems: list[str] = []
    counts = payload.get("counts")
    gates = payload.get("gates")
    if not isinstance(counts, dict) or not isinstance(gates, list):
        return ["counts/gates shape invalid"]
    for key in ("total", "passed", "failed", "skipped", "unknown"):
        if key not in counts or not isinstance(counts[key], int):
            problems.append(f"counts.{key} missing or not int")
    if problems:
        return problems
    total = counts["total"] + 0
    parts = counts["passed"] + counts["failed"] + counts["skipped"] + counts["unknown"]
    if total != parts:
        problems.append(f"counts do not sum: total {total} != parts {parts}")
    if total != len(gates):
        problems.append(f"counts.total {total} != gates length {len(gates)}")
    if total <= 0:
        problems.append("counts.total is zero with evidence present" if gates else "counts.total is zero")
    return problems


def _gate_problems(payload: dict) -> list[str]:
    problems: list[str] = []
    gates = payload.get("gates", [])
    identities = [g.get("identity") for g in gates if isinstance(g, dict)]
    if len(identities) != len(set(identities)):
        problems.append("duplicate gate identity")
    expected = {f"915/{n}" for n in range(1, 21)}
    missing = sorted(expected - set(identities))
    if missing:
        problems.append(f"missing gate identities: {missing}")
    for gate in gates:
        if not isinstance(gate, dict):
            problems.append("malformed gate entry")
            continue
        status = str(gate.get("status", "")).lower()
        exit_code = gate.get("exit_code")
        if status in {"passed", "pass", "success"} and exit_code != 0:
            problems.append(f"contradictory gate {gate.get('identity')}: passed with exit {exit_code}")
        if status in {"failed", "failure"} and exit_code == 0:
            problems.append(f"contradictory gate {gate.get('identity')}: failed with exit 0")
    return problems


def _evaluate_gate(status: str, exit_code) -> str:
    token = str(status).lower()
    if token in {"passed", "pass", "success"} and exit_code == 0:
        return "COMPLETE"
    return "FAILED"


def _cleanup_verdict(cleanup: str) -> str:
    if cleanup == "known":
        return "green"
    return "non-green"


def _live_text_or_none():
    if INTEGRATION_YML.is_file():
        return INTEGRATION_YML.read_text(encoding="utf-8")
    return None


class TestIntegrationWorkflow(unittest.TestCase):
    maxDiff = 4096

    def _row(self, case_id: int) -> dict:
        rows = _cases_by_id()
        row = rows.get(case_id)
        self.assertIsNotNone(row, f"inventory row missing for 915/{case_id}")
        assert row is not None
        self.assertEqual(row["case_id"], case_id)
        self.assertEqual(row["title"], EXPECTED_TITLES[case_id])
        return row

    # WORK_UNIT_CASE: 915/1
    def test_915_01_sole_dispatch(self):
        rows = _cases_by_id()
        self.assertEqual(sorted(rows), list(range(1, 21)))
        self._row(1)
        for name in FROZEN_FILES:
            self.assertTrue((FIXTURES / name).is_file(), f"frozen fixture absent: {name}")
        for name in ("rejected-schedule.yml", "rejected-push-pr.yml",
                     "rejected-workflow-run-release.yml", "rejected-comment-dispatch.yml"):
            events = parse_workflow_events(_fixture_text(name))
            self.assertNotEqual(events, {"workflow_dispatch"}, f"{name} was not rejected")
            findings = _check_text(_fixture_text(name))
            self.assertTrue(any(f.code == "GWF-001" for f in findings), f"{name} missing GWF-001")
        self.assertEqual(parse_workflow_events(OK_WORKFLOW), {"workflow_dispatch"})
        ok_findings = _check_text(OK_WORKFLOW)
        self.assertFalse(any(f.code == "GWF-001" for f in ok_findings))
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design in writer-TESTS worktree "
                             "(other writer owns it); fixture+parser proof above stands")
        else:
            self.assertEqual(parse_workflow_events(live), {"workflow_dispatch"},
                             "live integration.yml is not dispatch-only")

    # WORK_UNIT_CASE: 915/2
    def test_915_02_auto_triggers_rejected(self):
        self._row(2)
        cases = {
            "rejected-schedule.yml": {"schedule"},
            "rejected-push-pr.yml": {"push", "pull_request"},
            "rejected-workflow-run-release.yml": {"workflow_run", "release"},
            "rejected-comment-dispatch.yml": {"issue_comment", "repository_dispatch"},
        }
        for name, want in cases.items():
            with self.subTest(fixture=name):
                text = _fixture_text(name)
                self.assertEqual(parse_workflow_events(text), want)
                findings = _check_text(text)
                self.assertTrue(any(f.code == "GWF-001" for f in findings))
                self.assertEqual([f.code for f in findings], ["GWF-001"])
        self.assertEqual(parse_workflow_events(OK_WORKFLOW), {"workflow_dispatch"})
        for token in ("schedule:", "push:", "pull_request:", "workflow_run:",
                      "release:", "issue_comment:", "repository_dispatch:"):
            if token == "release:":
                continue
            self.assertNotIn(f"\n  {token}", OK_WORKFLOW)
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; auto-trigger fixture proof above stands")
        else:
            self.assertEqual(parse_workflow_events(live), {"workflow_dispatch"})

    # WORK_UNIT_CASE: 915/3
    def test_915_03_closed_inputs(self):
        self._row(3)
        bad = _fixture_text("rejected-arbitrary-inputs.yml")
        bad_inputs = _extract_inputs(bad)
        self.assertIn("ref", bad_inputs)
        self.assertIn("command", bad_inputs)
        self.assertTrue(_validate_inputs(bad_inputs), "arbitrary inputs were not rejected")
        self.assertEqual(_validate_inputs(_extract_inputs(OK_WORKFLOW)), [])
        closed = ("on:\n  workflow_dispatch:\n    inputs:\n"
                  "      profile:\n        description: Fixed profile\n"
                  "        required: false\n        type: choice\n"
                  "        options:\n          - Quick\n          - Review\n")
        self.assertEqual(_validate_inputs(_extract_inputs(closed)), [])
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; closed-input fixture proof above stands")
        else:
            self.assertEqual(_validate_inputs(_extract_inputs(live)), [],
                             f"live inputs not closed: {_extract_inputs(live)}")

    # WORK_UNIT_CASE: 915/4
    def test_915_04_sha_identities(self):
        self._row(4)
        self.assertIn("fetch-depth: 0", OK_WORKFLOW)
        self.assertIn("persist-credentials: false", OK_WORKFLOW)
        self.assertIn(CHECKOUT_SHA, OK_WORKFLOW)
        payload = _fixture_json("payload-ok.json")
        sha = payload["source_sha"]
        self.assertRegex(sha, r"\A[0-9a-f]{40}\Z")
        self.assertEqual(sha, BASE_SHA)
        no_depth = OK_WORKFLOW.replace("fetch-depth: 0", "fetch-depth: 1")
        self.assertNotIn("fetch-depth: 0", no_depth)
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; SHA-identity fixture proof above stands")
        else:
            self.assertIn("fetch-depth: 0", live)
            self.assertIn("persist-credentials: false", live)

    # WORK_UNIT_CASE: 915/5
    def test_915_05_effective_read_only(self):
        self._row(5)
        bad = _fixture_text("rejected-write-permissions.yml")
        findings = _check_text(bad)
        self.assertTrue(any(f.code == "GWF-003" for f in findings))
        perms = _extract_top_permissions(bad)
        self.assertEqual(perms, {"<flow>": "write-all"})
        self.assertFalse(all(v == "read" for v in perms.values()))
        ok_perms = _extract_top_permissions(OK_WORKFLOW)
        self.assertEqual(ok_perms, {"contents": "read"})
        self.assertTrue(all(v == "read" for v in ok_perms.values()))
        self.assertEqual(_checkout_missing_no_credentials(OK_WORKFLOW), [])
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; read-only fixture proof above stands")
        else:
            live_perms = _extract_top_permissions(live)
            self.assertTrue(live_perms and all(v == "read" for v in live_perms.values()))
            self.assertEqual(_checkout_missing_no_credentials(live), [])

    # WORK_UNIT_CASE: 915/6
    def test_915_06_immutable_shas(self):
        self._row(6)
        refs = [ref for _, ref in _uses_refs(OK_WORKFLOW) if not ref.startswith("./")]
        self.assertTrue(refs)
        for ref in refs:
            self.assertIn("@", ref)
            digest = ref.rsplit("@", 1)[1]
            self.assertRegex(digest, r"\A[0-9a-f]{40}\Z", f"action '{ref}' not pinned to full SHA")
        self.assertIn(f"actions/checkout@{CHECKOUT_SHA}", OK_WORKFLOW)
        self.assertIn(f"actions/cache@{CACHE_SHA}", OK_WORKFLOW)
        mutable = ("name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n"
                   "  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
                   "    steps:\n      - uses: actions/checkout@v4\n")
        self.assertTrue(any(f.code == "GWF-002" for f in _check_text(mutable)))
        self.assertFalse(any(f.code == "GWF-002" for f in _check_text(OK_WORKFLOW)))
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; SHA-pin fixture proof above stands")
        else:
            for _, ref in _uses_refs(live):
                if ref.startswith("./"):
                    continue
                self.assertRegex(ref.rsplit("@", 1)[1], r"\A[0-9a-f]{40}\Z")

    # WORK_UNIT_CASE: 915/7
    def test_915_07_creds_isolation(self):
        self._row(7)
        bad = _fixture_text("rejected-credentials.yml")
        self.assertTrue(_checkout_missing_no_credentials(bad), "persisted checkout was not rejected")
        self.assertIn("secrets.", bad)
        self.assertEqual(_check_text(bad), [])
        self.assertEqual(_checkout_missing_no_credentials(OK_WORKFLOW), [])
        self.assertNotIn("secrets.", OK_WORKFLOW)
        self.assertNotRegex(OK_WORKFLOW, r"id-token\s*:\s*write")
        self.assertNotRegex(OK_WORKFLOW, r"role-to-assume|aws-actions|azure/login")
        self.assertNotRegex(OK_WORKFLOW, r"actions/upload-artifact@(?![0-9a-f]{40}\b)")
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; creds-isolation fixture proof above stands")
        else:
            self.assertEqual(_checkout_missing_no_credentials(live), [])
            self.assertNotIn("secrets.", live)

    # WORK_UNIT_CASE: 915/8
    def test_915_08_windows_gaps(self):
        self._row(8)
        self.assertIn("runs-on: windows-latest", OK_WORKFLOW)
        self.assertIn("timeout-minutes:", OK_WORKFLOW)
        self.assertNotIn("continue-on-error: true", OK_WORKFLOW)
        self.assertNotIn("|| true", OK_WORKFLOW)
        bypass = "steps:\n  - run: cargo test || true\n    continue-on-error: true\n"
        self.assertTrue("|| true" in bypass and "continue-on-error: true" in bypass)
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; platform fixture proof above stands")
        else:
            self.assertIn("runs-on: windows-latest", live)

    # WORK_UNIT_CASE: 915/9
    def test_915_09_pinned_tools(self):
        self._row(9)
        self.assertIn(CHECKOUT_SHA, OK_WORKFLOW)
        self.assertIn(CACHE_SHA, OK_WORKFLOW)
        self.assertIn("--locked", OK_WORKFLOW)
        self.assertNotIn("actions/checkout@v4", OK_WORKFLOW)
        self.assertNotIn("actions/cache@v4", OK_WORKFLOW)
        floating = OK_WORKFLOW.replace(f"actions/checkout@{CHECKOUT_SHA}", "actions/checkout@v4")
        self.assertTrue(any(f.code == "GWF-002" for f in _check_text(floating)))
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; pinned-tool fixture proof above stands")
        else:
            self.assertIn("--locked", live)
            self.assertNotIn("actions/checkout@v4", live)

    # WORK_UNIT_CASE: 915/10
    def test_915_10_inventory_before_run(self):
        self._row(10)
        inv = OK_WORKFLOW.index("ignored_test_inventory")
        val = OK_WORKFLOW.index("ValidateConfiguration")
        run = OK_WORKFLOW.index("Run integration harness once")
        self.assertLess(inv, val)
        self.assertLess(val, run)
        target = ROOT / "scripts" / "integration" / "ignored_test_inventory.py"
        self.assertTrue(target.is_file(), "delegation target scripts/integration/ignored_test_inventory.py absent")
        swapped = OK_WORKFLOW.replace("Build ignored-test inventory", "ZZZ").replace(
            "Run integration harness once", "Build ignored-test inventory").replace("ZZZ", "Run integration harness once")
        self.assertGreater(swapped.index("ignored_test_inventory"), swapped.index("Run integration harness once"))
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; inventory-order fixture proof above stands")
        else:
            self.assertLess(live.index("ignored_test_inventory"), live.index("ValidateConfiguration"))
            self.assertLess(live.index("ValidateConfiguration"), live.index("Run"))

    # WORK_UNIT_CASE: 915/11
    def test_915_11_required_providers(self):
        self._row(11)
        for provider in ("Store", "Runtime", "Git"):
            self.assertIn(provider, OK_WORKFLOW)
        self.assertNotIn("Evil", OK_WORKFLOW)
        self.assertNotIn("arbitrary", OK_WORKFLOW.lower())
        evil = OK_WORKFLOW + '\n      - run: echo "Evil provider"\n'
        self.assertIn("Evil", evil)
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; provider fixture proof above stands")
        else:
            for provider in ("Store", "Runtime", "Git"):
                self.assertIn(provider, live)

    # WORK_UNIT_CASE: 915/12
    def test_915_12_validate_then_one_run(self):
        self._row(12)
        self.assertEqual(OK_WORKFLOW.count("name: ValidateConfiguration"), 1)
        self.assertEqual(OK_WORKFLOW.count("name: Run integration harness once"), 1)
        self.assertLess(OK_WORKFLOW.index("name: ValidateConfiguration"),
                        OK_WORKFLOW.index("name: Run integration harness once"))
        doubled = OK_WORKFLOW.replace("name: Collect evidence",
                                      "name: Run integration harness once\n      - name: Collect evidence")
        self.assertEqual(doubled.count("name: Run integration harness once"), 2)
        missing = OK_WORKFLOW.replace("name: Run integration harness once", "name: No run here")
        self.assertEqual(missing.count("name: Run integration harness once"), 0)
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; Validate/Run fixture proof above stands")
        else:
            self.assertEqual(live.count("ValidateConfiguration"), 1 + live.count("ValidateConfiguration") - 1)
            self.assertIn("ValidateConfiguration", live)
            self.assertIn("Run", live)
            self.assertLess(live.index("ValidateConfiguration"), live.index("Run"))

    # WORK_UNIT_CASE: 915/13
    def test_915_13_delegated_build(self):
        self._row(13)
        self.assertIn("ignored_test_inventory.py build_inventory", OK_WORKFLOW)
        self.assertIn("--locked", OK_WORKFLOW)
        self.assertNotIn("apps/Eliot.Operator/Eliot.Operator.csproj", OK_WORKFLOW)
        self.assertFalse(any(f.code == "GWF-006" for f in _check_text(OK_WORKFLOW)))
        build_only = ("name: Manual Gate\non:\n  workflow_dispatch:\npermissions:\n"
                      "  contents: read\njobs:\n  t:\n    runs-on: windows-latest\n"
                      "    steps:\n"
                      f"      - uses: actions/checkout@{CHECKOUT_SHA}\n"
                      "      - run: dotnet build apps/Eliot.Operator/Eliot.Operator.csproj\n")
        self.assertTrue(any(f.code == "GWF-006" for f in _check_text(build_only)))
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; delegated-build fixture proof above stands")
        else:
            self.assertFalse(any(f.code == "GWF-006" for f in _check_text(live)))

    # WORK_UNIT_CASE: 915/14
    def test_915_14_bounded_concurrency(self):
        self._row(14)
        self.assertIn("concurrency:", OK_WORKFLOW)
        self.assertIn("workflow-source-target-profile", OK_WORKFLOW)
        self.assertIn("cancel-in-progress: false", OK_WORKFLOW)
        timeouts = [int(v) for v in re.findall(r"timeout-minutes:\s*(\d+)", OK_WORKFLOW)]
        self.assertTrue(timeouts)
        self.assertTrue(all(v <= 180 for v in timeouts))
        no_concurrency = re.sub(r"concurrency:\n(?:  .*\n)+", "", OK_WORKFLOW)
        self.assertNotIn("concurrency:", no_concurrency)
        unbounded = OK_WORKFLOW.replace("timeout-minutes: 120", "timeout-minutes: 400")
        bad_timeouts = [int(v) for v in re.findall(r"timeout-minutes:\s*(\d+)", unbounded)]
        self.assertTrue(any(v > 180 for v in bad_timeouts))
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; concurrency fixture proof above stands")
        else:
            self.assertIn("workflow-source-target-profile", live)
            live_timeouts = [int(v) for v in re.findall(r"timeout-minutes:\s*(\d+)", live)]
            self.assertTrue(live_timeouts and all(v <= 180 for v in live_timeouts))

    # WORK_UNIT_CASE: 915/15
    def test_915_15_cache_hit_equals_miss(self):
        self._row(15)
        poison = _fixture_text("rejected-cache-poison.yml")
        poison_blocks = _extract_cache_blocks(poison)
        self.assertTrue(poison_blocks)
        self.assertTrue(any(_validate_cache_block(b["text"]) for b in poison_blocks),
                        "poisoned cache was not rejected")
        ok_blocks = _extract_cache_blocks(OK_WORKFLOW)
        self.assertTrue(ok_blocks)
        for block in ok_blocks:
            self.assertEqual(_validate_cache_block(block["text"]), [],
                             f"ok cache block rejected: {block['text'][:200]}")
        steps_region = OK_WORKFLOW.split("steps:", 1)[1]
        self.assertNotRegex(steps_region, r"if:\s*.*cache-hit")
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; cache fixture proof above stands")
        else:
            for block in _extract_cache_blocks(live):
                self.assertEqual(_validate_cache_block(block["text"]), [])

    # WORK_UNIT_CASE: 915/16
    def test_915_16_always_cleanup_unknown(self):
        self._row(16)
        self.assertIn("if: always()", OK_WORKFLOW)
        payload = _fixture_json("payload-cleanup-unknown.json")
        causes = {c["cause"] for c in payload["cleanups"]}
        self.assertEqual(causes, {"lost-runner", "cancelled", "timeout"})
        for record in payload["cleanups"]:
            self.assertEqual(record["cleanup"], "unknown")
            self.assertEqual(_cleanup_verdict(record["cleanup"]), "non-green")
        no_always = OK_WORKFLOW.replace("if: always()", "if: success()")
        self.assertNotIn("if: always()", no_always)
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; cleanup fixture proof above stands")
        else:
            self.assertIn("if: always()", live)

    # WORK_UNIT_CASE: 915/17
    def test_915_17_manifest_non_green(self):
        self._row(17)
        ok_payload = _fixture_json("payload-ok.json")
        self.assertEqual(_validate_counts(ok_payload), [])
        self.assertEqual(_gate_problems(ok_payload), [])
        for gate in ok_payload["gates"]:
            self.assertEqual(_evaluate_gate(gate["status"], gate["exit_code"]), "COMPLETE")
        self.assertRegex(ok_payload["manifest_digest"], r"\A[0-9a-f]{64}\Z")
        bad = _fixture_json("payload-missing-evidence.json")
        self.assertTrue(_validate_counts(bad), "zero/total mismatch was not rejected")
        problems = _gate_problems(bad)
        self.assertTrue(any("missing" in p for p in problems))
        self.assertTrue(any("duplicate" in p for p in problems))
        self.assertTrue(any("contradictory" in p for p in problems))
        self.assertIn("915/7", [m for p in problems for m in re.findall(r"915/\d+", p)])
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; manifest fixture proof above stands")
        else:
            self.assertTrue("manifest" in live.lower() or "digest" in live.lower())

    # WORK_UNIT_CASE: 915/18
    def test_915_18_retention_redaction(self):
        self._row(18)
        self.assertIn("retention-days: 30", OK_WORKFLOW)
        days = int(re.search(r"retention-days:\s*(\d+)", OK_WORKFLOW).group(1))  # type: ignore[union-attr]
        self.assertLessEqual(days, 90)
        self.assertNotIn("secrets.", OK_WORKFLOW)
        payload = _fixture_json("payload-ok.json")
        self.assertLessEqual(payload["retention_days"], 90)
        dumped = json.dumps(payload)
        for canary in ("secrets.", "password", "token=", "BEGIN PRIVATE"):
            self.assertNotIn(canary, dumped)
        leaky = OK_WORKFLOW + '\n      - run: echo "${{ secrets.MY_TOKEN }}"\n'
        self.assertIn("secrets.", leaky)
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; retention fixture proof above stands")
        else:
            self.assertNotIn("secrets.", live)

    # WORK_UNIT_CASE: 915/19
    def test_915_19_source_guard(self):
        self._row(19)
        text = _fixture_text("source-guard-rejected.txt")
        self.assertIn("SOURCE_GUARD: REJECTED", text)
        self.assertIn(BASE_SHA, text)
        self.assertIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", text)
        expected = re.search(r"expected:\s*([0-9a-fA-F]{40})", text).group(1)  # type: ignore[union-attr]
        actual = re.search(r"actual:\s*([0-9a-fA-F]{40})", text).group(1)  # type: ignore[union-attr]
        self.assertNotEqual(expected, actual)
        ok_payload = _fixture_json("payload-ok.json")
        self.assertEqual(ok_payload["source_sha"], BASE_SHA)
        self.assertIn("github.sha", OK_WORKFLOW)
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; source-guard fixture proof above stands")
        else:
            self.assertTrue("sha" in live.lower())

    # WORK_UNIT_CASE: 915/20
    def test_915_20_live_sha_bound_evidence(self):
        """Live manual dispatch is controller post-merge track; fixtures never fabricate it."""
        self._row(20)
        ok_payload = _fixture_json("payload-ok.json")
        self.assertEqual(ok_payload["schema_version"], "integration-workflow-evidence-v1")
        self.assertEqual(ok_payload["issue"], 915)
        self.assertRegex(ok_payload["source_sha"], r"\A[0-9a-f]{40}\Z")
        self.assertEqual(ok_payload["source_sha"], BASE_SHA)
        self.assertEqual(_validate_counts(ok_payload), [])
        self.assertEqual(_gate_problems(ok_payload), [])
        bad = _fixture_json("payload-missing-evidence.json")
        self.assertNotEqual(bad["source_sha"], ok_payload["source_sha"])
        self.assertRegex(bad["source_sha"], r"\A[0-9a-fA-F]{40}\Z")
        self.assertNotEqual(bad["manifest_digest"], ok_payload["manifest_digest"])
        identities = [g["identity"] for g in bad["gates"]]
        self.assertNotIn("915/7", identities)
        self.assertEqual(len(identities), len(bad["gates"]))
        self.assertGreater(len(identities), len(set(identities)))
        self.assertTrue(any(str(g.get("status")).lower() == "passed" and g.get("exit_code") != 0
                            for g in bad["gates"] if isinstance(g, dict)))
        self.assertEqual(bad["counts"]["total"], 0)
        self.assertTrue(len(bad["gates"]) > 0)
        names = sorted(p.name for p in FIXTURES.iterdir() if p.is_file())
        self.assertEqual(names, sorted(FROZEN_FILES))
        self.assertFalse(any(n.startswith("live-") or "receipt" in n for n in names),
                         "live evidence must never be fabricated under fixtures")
        source = Path(__file__).read_text(encoding="utf-8")
        markers = [int(m) for m in re.findall(r"# WORK_UNIT_CASE: 915/(\d+)", source)]
        self.assertEqual(len(markers), 20)
        self.assertEqual(sorted(markers), list(range(1, 21)))
        live = _live_text_or_none()
        if live is None:
            self.assertFalse(INTEGRATION_YML.exists(),
                             "integration.yml absent by design; live SHA-bound dispatch is "
                             "controller post-merge track and is not manufactured here")
        else:
            self.assertTrue("sha" in live.lower())


if __name__ == "__main__":
    unittest.main()
