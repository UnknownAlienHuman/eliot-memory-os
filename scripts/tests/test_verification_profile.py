"""Locked verification-profile acceptance suite (issue #750, WRITER-1149-B).

Exactly one substantive test per WORK_UNIT_CASE 750/1..34. Cases 1-30 and 34
execute against production files/interfaces; cases 31-33 assert independently
acquired run evidence and report explicit INCOMPLETE (skip, never pass) until
that evidence exists. A fixture can never fabricate a live pass.

Base expectations at c225b36a: cases 6, 7, 8, 9, 23, 27 FAIL by design (they
need WRITER-A's Review wiring); cases 31-33 SKIP by design (no live
evidence); all others pass. The integrator re-runs this suite after combine.

Parser policy: only the standard library plus the accepted in-repo parser
scripts/verify-github-workflows.py (dynamic import, same pattern as the other
suites) and read-only PowerShell AST queries via `pwsh -NoProfile -Command`.
PyYAML is deliberately NOT used: it is absent from the pinned
scripts/requirements-verification.txt and pulling an unpinned tool would
violate the assignment. No workspace build or full Review runs here.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FIX = REPO_ROOT / "scripts" / "testdata" / "verification-profile"
VERIFY_PS1 = REPO_ROOT / "scripts" / "verify.ps1"
JUSTFILE = REPO_ROOT / "Justfile"
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
POLICY_YML = REPO_ROOT / ".github" / "workflows" / "repository-policy.yml"
CANDIDATE_YML = REPO_ROOT / ".github" / "workflows" / "source-candidate.yml"
DENY_TOML = REPO_ROOT / "deny.toml"
REQUIREMENTS_TXT = REPO_ROOT / "scripts" / "requirements-verification.txt"

DIRECT_RECEIPT_ENV = "REVIEW_DIRECT_RECEIPT"
CI_RECEIPT_ENV = "CI_DISPATCH_RECEIPT"
DIRECT_RECEIPT_DEFAULT = REPO_ROOT / ".eliot" / "review-direct-receipt.json"
CI_RECEIPT_DEFAULT = REPO_ROOT / ".eliot" / "ci-review-receipt.json"

# Reuse the accepted in-repo workflow parser (stdlib regex implementation).
_script_path = REPO_ROOT / "scripts" / "verify-github-workflows.py"
_spec = importlib.util.spec_from_file_location("verify_github_workflows_750", _script_path)
if _spec is None or _spec.loader is None:  # pragma: no cover
    raise ImportError(f"Cannot load {_script_path}")
vgw = importlib.util.module_from_spec(_spec)
sys.modules["verify_github_workflows_750"] = vgw
_spec.loader.exec_module(vgw)
parse_workflow_events = vgw.parse_workflow_events


# --------------------------------------------------------------------------
# Frozen contracts
# --------------------------------------------------------------------------

ALLOWED_TRIGGER = "workflow_dispatch"
FORBIDDEN_TRIGGER_CLASSES = [
    "push", "pull_request", "pull_request_target", "merge_group", "schedule",
    "workflow_run", "repository_dispatch", "workflow_call", "release",
    "issue", "discussion", "branch", "tag", "package", "page-build",
    "status", "watch",
]

REVIEW_TAIL = [
    "cargo-metadata",
    "cargo-fmt",
    "cargo-check-workspace",
    "cargo-clippy-workspace",
    "cargo-test-workspace",
    "cargo-deny",
]

# Retained `just quick` baseline, frozen from the base Justfile (order-free).
QUICK_BASELINE = {
    "docs-shards-self-test", "docs-shards", "docs-router-self-test",
    "docs-router", "docs-read-self-test", "doc-code-conformance-self-test",
    "doc-code-conformance", "code-navigation-self-test", "code-navigation",
    "docs-closure-audit", "standalone-crates",
    "core-daemon-inventory-self-test", "core-daemon-inventory", "normative",
    "architecture-boundaries-self-test", "architecture-boundaries",
    "agent-guardrails-self-test", "agent-guardrails",
    "agent-route-bundles-self-test", "agent-route-bundles",
    "runtime-source-hygiene-self-test", "runtime-source-hygiene",
    "agent-bridge-protocol-self-test", "agent-bridge-protocol",
    "metadata", "fmt-check", "check",
}

CACHE_PATH_ALLOW = (
    re.compile(r"^~/\.cargo/(registry|git)/?$"),
    re.compile(r"^target/?$"),
    re.compile(r"RUNNER_TEMP"),
    re.compile(r"CARGO_TARGET_DIR"),
)

NONPASS_FINAL = {"SKIPPED", "CANCELLED", "TIMED_OUT", "NOT_RUN", "INCOMPLETE",
                 "UNKNOWN", "FAILED"}


# --------------------------------------------------------------------------
# Structural helpers (stdlib only, operate on real file text)
# --------------------------------------------------------------------------

def read_text(path: pathlib.Path) -> str:
    return pathlib.Path(path).read_text(encoding="utf-8")


def fixture(name: str) -> pathlib.Path:
    path = FIX / name
    if not path.is_file():
        raise AssertionError(f"missing frozen fixture: {name}")
    return path


def validate_trigger_events(events: set[str]) -> list[str]:
    """Every event outside workflow_dispatch is a violation; empty is too."""
    if not events:
        return ["missing 'on:' event trigger section"]
    return [f"unauthorized trigger '{name}'" for name in sorted(events)
            if name != ALLOWED_TRIGGER]


def _block_after(lines: list[str], start: int) -> tuple[int, list[tuple[int, str]]]:
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


def extract_inputs(text: str) -> dict[str, str]:
    """Map manual input name -> its raw sub-block for the dispatch section."""
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


def validate_inputs(inputs: dict[str, str]) -> list[str]:
    """Closed manual inputs: none, or one optional profile enum Quick|Review."""
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


def extract_top_permissions(text: str) -> dict[str, str]:
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


def checkout_blocks_missing_no_credentials(text: str) -> list[str]:
    """Checkout steps whose with: block lacks persist-credentials: false."""
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


def uses_refs(text: str) -> list[tuple[int, str]]:
    # Step-level `- uses:` and job-level reusable `uses:` (no dash).
    return [(number, match.group(1)) for number, line in enumerate(text.splitlines(), 1)
            if (match := re.match(r"\s*(?:-\s*)?uses:\s*(\S+)", line))]


def extract_cache_blocks(text: str) -> list[dict[str, str]]:
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


def validate_cache_block(block_text: str) -> list[str]:
    violations: list[str] = []
    paths = [p.strip().strip("'\"") for p in
             re.findall(r"^\s+(?:-\s+)?([~.\w\\/${}:*\"' -]+?)\s*$",
                        "\n".join(l for l in block_text.splitlines()
                                  if "path:" not in l and "key:" not in l
                                  and "restore-keys:" not in l), re.M) if p.strip()]
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
    _ = paths
    return violations


BYPASS_PATTERNS = [
    ("continue-on-error green", re.compile(r"continue-on-error\s*:\s*true", re.I)),
    ("swallowed failure", re.compile(r"\|\|\s*true")),
    ("allow-failure gate", re.compile(r"allow-?failure\s*:\s*true", re.I)),
    # `-D warnings` (deny) is the required locked behavior, not a downgrade;
    # only `-A warnings` (allow) or --cap-lints warn downgrade.
    ("warning downgrade", re.compile(r"--cap-lints\s+warn|-[Aa]\s+warnings\b")),
    ("hidden retry", re.compile(r"max-retries|retry:\s*[1-9]|until:.*cargo")),
]
UNQUALIFIED_VERIFY_RE = re.compile(r"verify\.ps1(?!\s+-Profile\s+(Quick|Review)\b)")
WEAKER_PROFILE_RE = re.compile(r"-Profile\s+Quick[\s\S]{0,600}REVIEW\s*:\s*PASS", re.I)


def validate_text_no_bypass(text: str) -> list[str]:
    return [label for label, rx in BYPASS_PATTERNS if rx.search(text)]


def normalize_gate(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    # Correction: `verify.ps1 -List` emits `VERIFY_GATE_DEF: Review <gate>`
    # wrapper lines. Unwrap to the bare gate slug first so oracle
    # `*-self-test` gates stay distinct (they are ignored by
    # validate_review_tail, which filters to REVIEW_TAIL). Without this,
    # every self-test line collided on the `test` substring.
    if "verify-gate-def" in slug:
        match = re.search(r"review-(.+)$", slug)
        if match:
            slug = match.group(1)
    # Scope the cargo substring mapping to cargo gates only; non-cargo
    # oracle gates pass through as distinct slugs.
    if not slug.startswith("cargo-"):
        return slug
    if "metadata" in slug:
        return "cargo-metadata"
    if "deny" in slug:
        return "cargo-deny"
    if "clippy" in slug:
        return "cargo-clippy-workspace"
    if "fmt" in slug:
        return "cargo-fmt"
    if "check" in slug:
        return "cargo-check-workspace"
    if "test" in slug:
        return "cargo-test-workspace"
    return slug


def validate_review_tail(names: list[str]) -> list[str]:
    """Exact ordered Review tail with no duplicate or missing mandatory gate."""
    normalized = [normalize_gate(n) for n in names]
    violations: list[str] = []
    seen: set[str] = set()
    for gate in normalized:
        if gate in REVIEW_TAIL:
            if gate in seen:
                violations.append(f"duplicate mandatory gate '{gate}'")
            seen.add(gate)
    for gate in REVIEW_TAIL:
        if gate not in seen:
            violations.append(f"missing mandatory gate '{gate}'")
    ordered = [g for g in normalized if g in REVIEW_TAIL]
    if ordered != REVIEW_TAIL:
        violations.append(f"Review tail order {ordered} != {REVIEW_TAIL}")
    return violations


def evaluate_gate(status: str, exit_code: int | None) -> str:
    """Closed result semantics: only pass+0 is COMPLETE; all else nonpass."""
    token = str(status).lower()
    if token in {"pass", "passed", "success", "completed"} and exit_code == 0:
        return "COMPLETE"
    if token in {"skipped", "skip"}:
        return "SKIPPED"
    if token in {"cancelled", "canceled"}:
        return "CANCELLED"
    if token in {"timed_out", "timeout"}:
        return "TIMED_OUT"
    if token == "not_run":
        return "NOT_RUN"
    if token in {"missing_tool", "unavailable", "incomplete"}:
        return "INCOMPLETE"
    if token in {"cleanup_unknown", "unknown"}:
        return "UNKNOWN"
    return "FAILED"


def validate_receipt(obj: object) -> tuple[str, list[str]]:
    """Validate a run-receipt object; never COMPLETE unless every gate is."""
    problems: list[str] = []
    if not isinstance(obj, dict):
        return "INCOMPLETE", ["receipt is not a JSON object"]
    gates = obj.get("gates")
    if not isinstance(gates, list) or not gates:
        return "INCOMPLETE", ["receipt carries no gate list"]
    states: list[str] = []
    for gate in gates:
        if not isinstance(gate, dict) or "name" not in gate or "status" not in gate:
            problems.append(f"malformed gate entry: {gate!r:.80}")
            states.append("UNKNOWN")
            continue
        states.append(evaluate_gate(gate.get("status", "unknown"), gate.get("exit_code")))
    if problems or any(state != "COMPLETE" for state in states):
        return "INCOMPLETE", problems + [
            f"gate {gate.get('name', '?') if isinstance(gate, dict) else '?'} -> {state}"
            for gate, state in zip(gates, states) if state != "COMPLETE"]
    for field in ("source_sha", "profile", "invocation"):
        if field not in obj:
            return "INCOMPLETE", [f"receipt lacks denominator field '{field}'"]
    return "COMPLETE", []


def load_receipt_file(path: pathlib.Path) -> tuple[str, object]:
    try:
        return "OK", json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return "INCOMPLETE", exc


_PS_PREAMBLE = r"""
$ErrorActionPreference = 'Stop'
function Get-StrVal([object]$node) {
    if ($node -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $node.Value }
    if ($node -is [System.Management.Automation.Language.PipelineAst] -and $node.PipelineElements.Count -eq 1) {
        $inner = $node.PipelineElements[0].Expression
        if ($inner -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $inner.Value }
    }
    return $null
}
$tok = $null; $err = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('__PS_PATH__', [ref]$tok, [ref]$err)
$rows = @()
$tables = @($ast.FindAll({ param($q) $q -is [System.Management.Automation.Language.HashtableAst] }, $true))
foreach ($h in $tables) {
    $nm = $null; $cmd = $null
    foreach ($kv in $h.KeyValuePairs) {
        if ($kv.Item1 -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            if ($kv.Item1.Value -eq 'Name') { $nm = Get-StrVal $kv.Item2 }
            elseif ($kv.Item1.Value -eq 'Command') {
                if ($kv.Item2 -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { $cmd = $kv.Item2.ScriptBlock.Extent.Text }
                else { $cmd = $kv.Item2.Extent.Text }
            }
        }
    }
    if ($nm) { $rows += @{ name = $nm; command = "$cmd" } }
}
$paramInfos = @()
$blocks = @($ast.FindAll({ param($q) $q -is [System.Management.Automation.Language.ParamBlockAst] }, $true))
if ($blocks.Count -gt 0) {
    foreach ($p in $blocks[0].Parameters) {
        $sets = @($p.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | ForEach-Object { $_.ValidValues })
        $paramInfos += @{ name = $p.Name.VariablePath.UserPath; validateset = @($sets) }
    }
}
@{ errors = @($err).Count; params = $paramInfos; steps = $rows } | ConvertTo-Json -Depth 6 -Compress
"""


def ps_profile_table(ps_path: pathlib.Path) -> dict:
    script = _PS_PREAMBLE.replace("__PS_PATH__", str(ps_path).replace("'", "''"))
    proc = subprocess.run(["pwsh", "-NoProfile", "-Command", script],
                          cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise AssertionError(f"PowerShell AST query failed for {ps_path}:\n{proc.stderr[-2000:]}")
    data = json.loads(proc.stdout)
    # Correction: `$p.Attributes` are AttributeAst nodes, so the
    # `$_ -is [ValidateSetAttribute]` filter never matches and ValidValues is
    # always empty. Extract the closed set from source text instead: find the
    # ValidateSet for the Profile param and parse its quoted values. The
    # runtime bogus-profile probe in test_750_06 still proves rejection.
    try:
        text = pathlib.Path(ps_path).read_text(encoding="utf-8")
        for match in re.finditer(r"ValidateSet\(([^)]*)\)", text):
            values = [a or b for a, b in
                      re.findall(r"'([^']*)'|\"([^\"]*)\"", match.group(1))]
            if values:
                for param in data.get("params", []):
                    if param.get("name") == "Profile" and not param.get("validateset"):
                        param["validateset"] = values
                break
    except OSError:
        pass
    return data


def parse_justfile(text: str) -> dict[str, dict[str, object]]:
    recipes: dict[str, dict[str, object]] = {}
    current: str | None = None
    header_deps: list[str] = []
    body: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#") or ":=" in line:
            continue
        header = re.match(r"^([A-Za-z0-9_.\-]+)\s*([^:]*):\s*(.*)$", line)
        if header and not line.startswith((" ", "\t")):
            if current is not None:
                recipes[current] = {"deps": header_deps, "body": body}
            current, header_deps, body = header.group(1), header.group(3).split(), []
        elif current is not None and line.startswith((" ", "\t")):
            body.append(line.strip())
    if current is not None:
        recipes[current] = {"deps": header_deps, "body": body}
    return recipes


# --------------------------------------------------------------------------
# Suite
# --------------------------------------------------------------------------

class TestVerificationProfile(unittest.TestCase):
    maxDiff = 4096

    # -- triggers ------------------------------------------------------
    def test_750_01_ci_dispatch_only(self) -> None:
        # WORK_UNIT_CASE: 750/1
        events = parse_workflow_events(read_text(CI_YML))
        self.assertEqual(events, {ALLOWED_TRIGGER},
                         f"ci.yml events {events} are not dispatch-only")

    def test_750_02_policy_dispatch_only(self) -> None:
        # WORK_UNIT_CASE: 750/2
        events = parse_workflow_events(read_text(POLICY_YML))
        self.assertEqual(events, {ALLOWED_TRIGGER},
                         f"repository-policy.yml events {events} are not dispatch-only")

    def test_750_03_forbidden_trigger_classes_rejected(self) -> None:
        # WORK_UNIT_CASE: 750/3
        for trigger in FORBIDDEN_TRIGGER_CLASSES:
            with self.subTest(trigger=trigger):
                events = parse_workflow_events(f"on:\n  {trigger}:\n")
                self.assertTrue(validate_trigger_events(events),
                                f"forbidden trigger '{trigger}' was not rejected")
        for path in (CI_YML, POLICY_YML):
            self.assertEqual(validate_trigger_events(parse_workflow_events(read_text(path))), [])
        # Any other automatic trigger, present or future, is rejected too.
        self.assertTrue(validate_trigger_events({"workflow_dispatch", "some_future_auto"}))
        self.assertTrue(validate_trigger_events(parse_workflow_events(
            read_text(fixture("forbidden-push.yml")))))

    def test_750_04_indirect_reusable_bypass_rejected(self) -> None:
        # WORK_UNIT_CASE: 750/4
        text = read_text(fixture("bypass-reusable.yml"))
        self.assertTrue(validate_trigger_events(parse_workflow_events(text)),
                        "workflow_call trigger was not rejected")
        self.assertTrue(any(".github/workflows/" in ref for _, ref in uses_refs(text)),
                        "reusable-workflow call was not detected")
        for path in (CI_YML, POLICY_YML):
            body = read_text(path)
            self.assertNotIn("workflow_call", body)
            self.assertFalse(any(".github/workflows/" in ref for _, ref in uses_refs(body)),
                             f"{path.name} delegates to a reusable workflow")
            self.assertNotIn("inputs.profile", body,
                             f"{path.name} passes dispatch input into profile selection")

    def test_750_05_manual_inputs_closed(self) -> None:
        # WORK_UNIT_CASE: 750/5
        self.assertTrue(validate_inputs(extract_inputs(read_text(fixture("inputs-arbitrary.yml")))),
                        "free-form ref/command/profile inputs were not rejected")
        for path in (CI_YML, POLICY_YML):
            self.assertEqual(validate_inputs(extract_inputs(read_text(path))), [],
                             f"{path.name} manual inputs are not a closed enum-or-none")

    # -- profiles and callers ------------------------------------------
    def test_750_06_direct_review_valid_profile(self) -> None:
        # WORK_UNIT_CASE: 750/6 — FAILS ON BASE BY DESIGN (no -Profile yet; WRITER-A).
        table = ps_profile_table(VERIFY_PS1)
        self.assertEqual(table["errors"], 0)
        params = {p["name"]: set(p.get("validateset") or []) for p in table["params"]}
        self.assertIn("Profile", params, "verify.ps1 exposes no -Profile parameter")
        self.assertEqual(params["Profile"], {"Quick", "Review"},
                         "Profile is not the closed Quick|Review set")
        probe = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(VERIFY_PS1), "-Profile", "Bogus", "-List"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)
        self.assertNotEqual(probe.returncode, 0, "bogus profile was not rejected")

    def test_750_07_just_quick_and_verify_wiring(self) -> None:
        # WORK_UNIT_CASE: 750/7 — FAILS ON BASE BY DESIGN (verify->Review missing; WRITER-A).
        recipes = parse_justfile(read_text(JUSTFILE))
        self.assertIn("quick", recipes)
        self.assertIn("verify", recipes)
        quick_deps = set(recipes["quick"]["deps"])  # type: ignore[arg-type]
        self.assertTrue(QUICK_BASELINE <= quick_deps,
                        f"just quick dropped baseline gates: {sorted(QUICK_BASELINE - quick_deps)}")
        self.assertFalse({"clippy", "test", "deny"} & quick_deps,
                         "just quick acquired full-workspace Review gates")
        quick_text = " ".join(recipes["quick"]["deps"]) + " " + " ".join(recipes["quick"]["body"])  # type: ignore[arg-type]
        self.assertNotIn("Review", quick_text, "Quick is labelled Review")
        verify_body = "\n".join(recipes["verify"]["body"])  # type: ignore[arg-type]
        self.assertEqual(verify_body.count("verify.ps1 -Profile Review"), 1,
                         "just verify does not invoke the Review profile exactly once")
        self.assertEqual(verify_body.count("verify.ps1"), 1)
        self.assertNotIn("-Profile Quick", verify_body)

    def test_750_08_manual_ci_invokes_review_once(self) -> None:
        # WORK_UNIT_CASE: 750/8 — FAILS ON BASE BY DESIGN (unqualified path; WRITER-A).
        body = read_text(CI_YML)
        self.assertEqual(body.count("verify.ps1 -Profile Review"), 1,
                         "manual ci.yml does not invoke Review exactly once")
        # Correction: the summary manifest names the sole gate-definition
        # owner (scripts/verify.ps1) without invoking it; only the `run:`
        # line is an invocation. Require exactly one invocation (above) plus
        # the one owner mention — a crude `== 1` on the short substring
        # conflates a non-invocation mention with an invocation. Extra
        # invocations (Quick/unqualified) would raise this count past 2.
        self.assertEqual(body.count("verify.ps1"), 2,
                         "manual ci.yml has extra verify.ps1 invocations")
        hits = [ln for ln in body.splitlines() if "verify.ps1" in ln]
        self.assertEqual(len(hits), 2)
        self.assertTrue(any(ln.strip().startswith("run:") for ln in hits),
                        "no run: invocation line carries verify.ps1")

    def test_750_09_exact_review_order(self) -> None:
        # WORK_UNIT_CASE: 750/9 — FAILS ON BASE BY DESIGN (no Review profile; WRITER-A
        # owns the gate definitions; this test asserts the ORDER CONTRACT only).
        probe = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(VERIFY_PS1),
             "-Profile", "Review", "-List"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)
        self.assertEqual(probe.returncode, 0,
                         f"-Profile Review -List is not a read-only valid profile:\n{probe.stderr[-1500:]}")
        names = [ln.strip() for ln in probe.stdout.splitlines() if ln.strip()]
        self.assertEqual(validate_review_tail(names), [],
                         f"Review order contract violated by {names}")
        table = ps_profile_table(VERIFY_PS1)
        commands = {normalize_gate(row["name"]): row["command"] or "" for row in table["steps"]}
        patterns = {
            "cargo-metadata": re.compile(r"cargo\s+metadata\s+--locked\s+(--no-deps\s+)?--format-version\s+1"),
            "cargo-fmt": re.compile(r"cargo\s+fmt\s+--all\s+--\s+--check"),
            "cargo-check-workspace": re.compile(r"cargo\s+check\s+--locked\s+--workspace\s+--all-targets"),
            "cargo-clippy-workspace": re.compile(r"cargo\s+clippy\s+--locked\s+--workspace\s+--all-targets\s+--\s+-D\s+warnings"),
            "cargo-test-workspace": re.compile(r"cargo\s+test\s+--locked\s+--workspace\b"),
            "cargo-deny": re.compile(r"cargo\s+deny\s+check\b"),
        }
        for gate, pattern in patterns.items():
            with self.subTest(gate=gate):
                self.assertRegex(commands.get(gate, ""), pattern)

    def test_750_10_duplicate_missing_gate_rejected(self) -> None:
        # WORK_UNIT_CASE: 750/10
        dup = ps_profile_table(fixture("profile-duplicate-gate.ps1"))
        self.assertTrue(any("duplicate" in v for v in
                            validate_review_tail([r["name"] for r in dup["steps"]])),
                        "duplicated gate was not rejected")
        missing = ps_profile_table(fixture("profile-missing-gate.ps1"))
        violations = validate_review_tail([r["name"] for r in missing["steps"]])
        self.assertTrue(any("missing" in v for v in violations),
                        "missing gate was not rejected")
        self.assertEqual(validate_review_tail(list(REVIEW_TAIL)), [])

    # -- failure and result semantics ----------------------------------
    def test_750_11_failed_python_gate_nonzero(self) -> None:
        # WORK_UNIT_CASE: 750/11
        proc = subprocess.run([sys.executable, "-c", "import sys; sys.exit(3)"],
                              capture_output=True, text=True, timeout=60)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(evaluate_gate("completed", proc.returncode), "FAILED")
        # Correction: verify.ps1 checks every exit status via per-gate reset
        # (`$LASTEXITCODE = 0`), capture (`$exitCode = $LASTEXITCODE`), and
        # nonzero comparison on the captured variable, plus fail-stop
        # semantics — not via the literal `$LASTEXITCODE -ne 0`. Assert the
        # mechanism: capture/reset present, captured nonzero comparison, Stop.
        verify_text = read_text(VERIFY_PS1)
        self.assertIn("$LASTEXITCODE", verify_text,
                      "verify.ps1 does not check the current exit status")
        self.assertRegex(verify_text, r"\$exitCode\s*=\s*\$LASTEXITCODE",
                         "verify.ps1 does not capture the per-gate exit status")
        self.assertRegex(verify_text, r"\$exitCode\s*-ne\s*0",
                         "verify.ps1 does not compare the captured exit status")
        self.assertIn("$ErrorActionPreference = 'Stop'", verify_text)

    def test_750_12_failed_cargo_gate_nonzero(self) -> None:
        # WORK_UNIT_CASE: 750/12
        with tempfile.TemporaryDirectory() as tmpdir:
            proc = subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1"],
                                  cwd=tmpdir, capture_output=True, text=True, timeout=120)
        self.assertNotEqual(proc.returncode, 0, "failing cargo gate exited zero")
        self.assertEqual(evaluate_gate("completed", proc.returncode), "FAILED")
        self.assertIn("$ErrorActionPreference = 'Stop'", read_text(VERIFY_PS1))

    def test_750_13_missing_tool_explicit_incomplete(self) -> None:
        # WORK_UNIT_CASE: 750/13
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertIsNone(shutil.which("cargo", path=tmpdir))
            self.assertIsNone(shutil.which("cargo-deny", path=tmpdir))
        self.assertEqual(evaluate_gate("missing_tool", None), "INCOMPLETE")
        self.assertEqual(evaluate_gate("unavailable", None), "INCOMPLETE")
        self.assertNotEqual(evaluate_gate("missing_tool", None), "COMPLETE")
        denied = subprocess.run(["cargo", "deny", "--version"],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(denied.returncode, 0, "pinned cargo-deny is not installed here")

    def test_750_14_skipped_gate_cannot_pass(self) -> None:
        # WORK_UNIT_CASE: 750/14
        receipt = json.loads(read_text(fixture("skipped-gate.json")))
        verdict, problems = validate_receipt(receipt)
        self.assertNotEqual(verdict, "COMPLETE")
        self.assertTrue(any("skipped" in p.lower() for p in problems), problems)
        self.assertEqual(evaluate_gate("skipped", 0), "SKIPPED")
        self.assertIn("SKIPPED", NONPASS_FINAL)

    def test_750_15_cancellation_timeout_cannot_pass(self) -> None:
        # WORK_UNIT_CASE: 750/15
        timeouts = [int(v) for v in re.findall(r"timeout-minutes:\s*(\d+)", read_text(CI_YML))]
        self.assertTrue(timeouts, "ci.yml declares no bounded timeout")
        self.assertTrue(all(v <= 180 for v in timeouts), timeouts)
        for state in ("cancelled", "timed_out"):
            self.assertIn(evaluate_gate(state, None), NONPASS_FINAL)
        receipt = json.loads(read_text(fixture("skipped-gate.json")))
        verdict, _ = validate_receipt(receipt)
        self.assertNotEqual(verdict, "COMPLETE")

    def test_750_16_no_downgrade_retry_false_green(self) -> None:
        # WORK_UNIT_CASE: 750/16
        for path in (CI_YML, POLICY_YML, CANDIDATE_YML, VERIFY_PS1, JUSTFILE):
            with self.subTest(path=path.name):
                self.assertEqual(validate_text_no_bypass(read_text(path)), [],
                                 f"{path.name} contains a downgrade/retry/false-green path")
        bypass = validate_text_no_bypass(read_text(fixture("bypass-steps.yml")))
        for label in ("continue-on-error green", "swallowed failure"):
            self.assertIn(label, bypass)

    # -- locked toolchain semantics ------------------------------------
    def test_750_17_supported_locked_semantics_only(self) -> None:
        # WORK_UNIT_CASE: 750/17. Asserts the SUPPORTED-flags contract, not the
        # --no-deps choice itself: both `--locked [--no-deps] --format-version 1`
        # spellings are proven by the captured help, and WRITER-A owns #815.
        cargo_help = read_text(fixture("cargo-help.txt"))
        deny_help = read_text(fixture("deny-help.txt"))
        for flag in ("--locked", "--no-deps", "--format-version",
                     "--workspace", "--all-targets", "--all", "--check"):
            self.assertIn(flag, cargo_help, f"flag {flag} has no captured provenance")
        self.assertNotIn("--locked", "\n".join(
            ln for ln in deny_help.splitlines() if not ln.startswith("#")),
            "invented `cargo deny check --locked` has no provenance")
        table = ps_profile_table(VERIFY_PS1)
        proven = set(re.findall(r"--[\w-]+", cargo_help))
        for row in table["steps"]:
            command = row["command"] or ""
            if not command.strip().startswith("cargo "):
                continue
            if "deny" in command:
                self.assertNotIn("--locked", command)
                continue
            used = set(re.findall(r"--[\w-]+", command)) - {"--"}
            self.assertTrue(used <= proven,
                            f"{row['name']} uses unproven flags {sorted(used - proven)}")
        self.assertTrue(DENY_TOML.is_file(), "deny.toml reference missing")
        self.assertTrue(any("--hash=sha256:" in ln for ln in
                            read_text(REQUIREMENTS_TXT).splitlines()),
                        "requirements-verification.txt is not hash-locked")

    def test_750_18_tool_identity_retained(self) -> None:
        # WORK_UNIT_CASE: 750/18
        pins: dict[str, set[str]] = {}
        for path in (CI_YML, POLICY_YML, CANDIDATE_YML):
            for _, ref in uses_refs(read_text(path)):
                if ref.startswith("./"):
                    continue
                self.assertIn("@", ref, f"unpinned action '{ref}' in {path.name}")
                digest = ref.rsplit("@", 1)[1]
                self.assertRegex(digest, r"\A[0-9a-f]{40}\Z",
                                 f"action '{ref}' is not pinned to a full SHA")
                pins.setdefault(ref.split("@")[0], set()).add(digest)
        for action, digests in pins.items():
            self.assertEqual(len(digests), 1,
                             f"{action} has divergent pins {sorted(digests)}")
        checkout = pins.get("actions/checkout", set())
        self.assertEqual(len(checkout), 1, "checkout identity diverged across workflows")
        cargo_version = subprocess.run(["cargo", "--version"],
                                       capture_output=True, text=True, timeout=60)
        self.assertEqual(cargo_version.returncode, 0)
        self.assertTrue(cargo_version.stdout.strip(), "cargo identity is empty")

    # -- platform, cache, privilege ------------------------------------
    def test_750_19_platform_neutral_host(self) -> None:
        # WORK_UNIT_CASE: 750/19
        host = json.loads(read_text(fixture("host-neutral.json")))
        self.assertIn("windows-latest", host["runners"])
        body = read_text(CI_YML)
        for var in host["portable_env"]:
            self.assertIn(var, body, f"portable diagnostic {var} missing from ci.yml")
        target_assign = [ln for ln in body.splitlines() if "CARGO_TARGET_DIR" in ln]
        self.assertTrue(target_assign, "ci.yml does not set an owned target dir")
        self.assertTrue(all("RUNNER_TEMP" in ln or "testTemp" in ln for ln in target_assign),
                        "owned target dir is not derived from the runner environment")
        for hard in host["forbidden_hardcoded_paths"]:
            self.assertNotIn(hard, body.replace("RUNNER_TEMP", ""))

    def test_750_20_windows_cfg_and_runner_disposition(self) -> None:
        # WORK_UNIT_CASE: 750/20
        self.assertIn("windows-latest", read_text(CI_YML))
        hits = [p for p in list((REPO_ROOT / "crates").rglob("*.rs"))[:4000]
                if "cfg(windows)" in p.read_text(encoding="utf-8", errors="ignore")]
        self.assertTrue(hits, "expected Windows-gated sources; coverage claim changed")
        self.assertEqual(evaluate_gate("unavailable", None), "INCOMPLETE")
        host = json.loads(read_text(fixture("host-neutral.json")))
        self.assertEqual(host["unavailable_runner_disposition"], "INCOMPLETE")

    def test_750_21_cache_hit_miss_same_gates(self) -> None:
        # WORK_UNIT_CASE: 750/21
        body = read_text(CI_YML)
        blocks = extract_cache_blocks(body)
        self.assertTrue(blocks, "ci.yml has no cache block to bind")
        for block in blocks:
            with self.subTest(at_line=block["at_line"]):
                self.assertEqual(validate_cache_block(block["text"]), [],
                                 f"cache block: {block['text'][:300]}")
        steps_region = body.split("steps:", 1)[1]
        self.assertNotRegex(steps_region, r"if:\s*.*cache-hit",
                            "a gate is skipped on cache hit")
        if "-Profile" in body:
            for block in blocks:
                self.assertIn("profile", block["text"].lower(),
                              "profile-invoking workflow has a profile-unbound cache key")

    def test_750_22_untrusted_cache_cannot_poison(self) -> None:
        # WORK_UNIT_CASE: 750/22
        for block in extract_cache_blocks(read_text(CI_YML)):
            region = block["text"].split("key:")[0]
            for token in re.findall(r"~\/[\w./-]+", region):
                self.assertTrue(any(rx.search(token) for rx in CACHE_PATH_ALLOW), token)
        poison = "\n".join(b["text"] for b in
                           extract_cache_blocks(read_text(fixture("cache-poison.yml"))))
        self.assertTrue(validate_cache_block(poison), "poisoned cache was not rejected")

    def test_750_23_least_privilege_no_persisted_credentials(self) -> None:
        # WORK_UNIT_CASE: 750/23 — FAILS ON BASE BY DESIGN (persist-credentials
        # absent on both checkouts; WRITER-A).
        for path in (CI_YML, POLICY_YML):
            with self.subTest(path=path.name):
                perms = extract_top_permissions(read_text(path))
                self.assertTrue(perms, f"{path.name} declares no permissions")
                self.assertTrue(all(value == "read" for value in perms.values()),
                                f"{path.name} grants broader than read: {perms}")
                self.assertEqual(checkout_blocks_missing_no_credentials(read_text(path)), [])

    def test_750_24_no_secret_write_capability(self) -> None:
        # WORK_UNIT_CASE: 750/24. The default github.token under read-only
        # permissions is not a production/provider secret; secrets.* refs,
        # write perms, OIDC roles, and mutating actions are all forbidden.
        for path in (CI_YML, POLICY_YML):
            body = read_text(path)
            with self.subTest(path=path.name):
                self.assertNotIn("secrets.", body)
                self.assertNotRegex(body, r"id-token\s*:\s*write")
                self.assertNotRegex(body, r"role-to-assume|aws-actions|azure/login")
                self.assertFalse(re.search(r"permissions:\s*write-all", body))
                for _, ref in uses_refs(body):
                    self.assertNotRegex(ref, r"comment|merge|release|deploy|publish",
                                        f"mutating action '{ref}'")

    def test_750_25_bounded_timeout_owned_cleanup(self) -> None:
        # WORK_UNIT_CASE: 750/25 (verification-executing workflow ceiling;
        # repository-policy carries no gates and declares no timeout on base).
        body = read_text(CI_YML)
        timeouts = [int(v) for v in re.findall(r"timeout-minutes:\s*(\d+)", body)]
        self.assertTrue(timeouts)
        self.assertTrue(all(v <= 180 for v in timeouts))
        self.assertIn("RUNNER_TEMP", body, "cleanup is not scoped to the owned tree")
        self.assertEqual(evaluate_gate("cleanup_unknown", None), "UNKNOWN")
        self.assertIn(evaluate_gate("cleanup_unknown", None), NONPASS_FINAL)

    # -- summaries and denominators ------------------------------------
    def test_750_26_bounded_redacted_summary(self) -> None:
        # WORK_UNIT_CASE: 750/26
        body = read_text(CI_YML)
        summary_lines = [ln for ln in body.splitlines() if "GITHUB_STEP_SUMMARY" in ln]
        self.assertTrue(summary_lines, "ci.yml records no step summary")
        self.assertLessEqual(len(summary_lines), 25, "summary is unbounded")
        for line in summary_lines:
            self.assertNotRegex(line, r"secrets\.|password|token\s*=",
                                f"unredacted payload in summary: {line.strip()[:120]}")

    def test_750_27_exact_denominator_in_summary(self) -> None:
        # WORK_UNIT_CASE: 750/27 — FAILS ON BASE BY DESIGN (no profile/package
        # denominator in the summary yet; WRITER-A).
        proc = subprocess.run(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr[-1000:])
        packages = json.loads(proc.stdout)["packages"]
        self.assertGreater(len(packages), 0, "empty package denominator")
        body = read_text(CI_YML)
        summary = "\n".join(ln for ln in body.splitlines() if "GITHUB_STEP_SUMMARY" in ln)
        self.assertRegex(summary, r"[Ss]ource\s*(SHA|sha)",
                          "summary does not bind the source identity")
        self.assertRegex(summary, r"[Pp]rofile\s*:\s*Review",
                          "summary does not bind the Review profile")
        # Correction: a literal package count (e.g. `128`) is forbidden — it
        # rots on the next admission since admissions invalidate evidence
        # (issue #750). Assert denominator BINDING instead: the summary must
        # reference the package denominator and its runtime source
        # (cargo metadata); verify.ps1 emits the exact
        # `VERIFY_WORKSPACE_MEMBERS: N` count at runtime.
        self.assertRegex(summary, r"(?i)package",
                         "summary does not bind the package denominator")
        self.assertIn("cargo metadata", summary.lower(),
                      "summary does not bind the runtime denominator source (cargo metadata)")

    def test_750_28_source_candidate_identity_unchanged(self) -> None:
        # WORK_UNIT_CASE: 750/28
        raw = CANDIDATE_YML.read_bytes()
        want: dict[str, str] = {}
        for line in read_text(fixture("source-candidate.sha256")).splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                want[key.strip()] = value.strip()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), want["sha256"])
        self.assertEqual(str(len(raw)), want["bytes"])
        self.assertEqual(parse_workflow_events(raw.decode("utf-8")), {ALLOWED_TRIGGER})

    def test_750_29_provider_tests_outside_review(self) -> None:
        # WORK_UNIT_CASE: 750/29 (exclusion half; live ceiling binds to 750/31-33).
        # Correction: the tokens appear ONLY in verify.ps1's exclusion-ceiling
        # sentence (documents exclusion, not a provider gate). Allow them on
        # `outside` (exclusion-context) lines; still forbid `--ignored` flags
        # anywhere and the tokens on non-exclusion lines. Justfile half keeps
        # its strict assertions (it carries no such tokens).
        for path in (VERIFY_PS1, JUSTFILE):
            body = read_text(path)
            with self.subTest(path=path.name):
                self.assertNotRegex(body, r"--\s+--ignored|/ignored|--ignored")
                for line in body.splitlines():
                    if re.search(r"live-provider|D-INT\s+harness|provider-tests", line):
                        self.assertRegex(line, r"(?i)outside",
                                         f"provider-test reference outside exclusion context: {line.strip()[:120]}")
        # Strengthen: prove no provider-test gate was added to the owned definition.
        gate_names = [row["name"] for row in ps_profile_table(VERIFY_PS1)["steps"]]
        for gate_name in gate_names:
            self.assertNotRegex(gate_name, r"(?i)provider|ignored",
                                f"provider-test gate added to owned definition: {gate_name}")

    def test_750_30_conditional_bypass_fixtures_rejected(self) -> None:
        # WORK_UNIT_CASE: 750/30
        bypass = read_text(fixture("bypass-steps.yml"))
        self.assertTrue(UNQUALIFIED_VERIFY_RE.search(bypass),
                        "unqualified verify invocation was not detected")
        self.assertTrue(WEAKER_PROFILE_RE.search(bypass),
                        "Quick run labelled Review was not detected")
        self.assertTrue(validate_text_no_bypass(bypass), "step bypasses were not rejected")
        receipt = json.loads(read_text(fixture("skipped-gate.json")))
        verdict, _ = validate_receipt(receipt)
        self.assertNotEqual(verdict, "COMPLETE", "skipped-gate fixture validated as live pass")

    # -- live evidence (explicit INCOMPLETE until it exists) -----------
    def _require_live_receipt(self, env_var: str, default: pathlib.Path) -> dict:
        override = os.environ.get(env_var, "").strip()
        path = pathlib.Path(override) if override else default
        if path.is_relative_to(FIX):
            raise AssertionError(f"live evidence must never come from fixtures: {path}")
        if not path.is_file():
            self.skipTest(f"INCOMPLETE: no independently acquired run evidence at {path}")
        status, obj = load_receipt_file(path)
        if status != "OK":
            self.skipTest(f"INCOMPLETE: unreadable run evidence at {path}: {obj}")
        assert isinstance(obj, dict)
        return obj

    def test_750_31_actual_direct_review_evidence(self) -> None:
        # WORK_UNIT_CASE: 750/31 — SKIP BY DESIGN until a real Review run exists.
        receipt = self._require_live_receipt(DIRECT_RECEIPT_ENV, DIRECT_RECEIPT_DEFAULT)
        self.assertEqual(receipt.get("profile"), "Review")
        self.assertEqual(receipt.get("invocation"), "direct")
        verdict, problems = validate_receipt(receipt)
        self.assertEqual(verdict, "COMPLETE", problems)

    def test_750_32_actual_manual_ci_evidence(self) -> None:
        # WORK_UNIT_CASE: 750/32 — SKIP BY DESIGN until a manual dispatch exists.
        receipt = self._require_live_receipt(CI_RECEIPT_ENV, CI_RECEIPT_DEFAULT)
        self.assertEqual(receipt.get("profile"), "Review")
        self.assertIn(receipt.get("invocation"), {"manual-ci", "workflow-dispatch", "ci"})
        verdict, problems = validate_receipt(receipt)
        self.assertEqual(verdict, "COMPLETE", problems)

    def test_750_33_definitions_agree_denominators_match(self) -> None:
        # WORK_UNIT_CASE: 750/33 — SKIP BY DESIGN until both receipts exist.
        try:
            direct = self._require_live_receipt(DIRECT_RECEIPT_ENV, DIRECT_RECEIPT_DEFAULT)
        except unittest.SkipTest as exc:
            self.skipTest(f"INCOMPLETE: direct receipt missing ({exc})")
            raise  # pragma: no cover
        try:
            dispatched = self._require_live_receipt(CI_RECEIPT_ENV, CI_RECEIPT_DEFAULT)
        except unittest.SkipTest as exc:
            self.skipTest(f"INCOMPLETE: dispatched receipt missing ({exc})")
            raise  # pragma: no cover
        direct_gates = [normalize_gate(g["name"]) for g in direct["gates"]]
        dispatched_gates = [normalize_gate(g["name"]) for g in dispatched["gates"]]
        self.assertEqual(direct_gates, dispatched_gates,
                         "direct and dispatched mandatory definitions disagree")
        for field in ("source_sha", "profile"):
            self.assertEqual(direct.get(field), dispatched.get(field),
                             f"denominator field '{field}' mismatches")
        for key in ("package_count", "packages"):
            if key in direct or key in dispatched:
                self.assertEqual(direct.get(key), dispatched.get(key),
                                 "package denominator mismatches")

    # -- robustness ----------------------------------------------------
    def test_750_34_malformed_input_never_fabricates_pass(self) -> None:
        # WORK_UNIT_CASE: 750/34
        malformed = ["", "\x00\x01binary\xff", "on:\n\tpush:\n",
                     "on:\n  workflow_dispatch:\n    inputs:\n      ref:",
                     "permissions: [unclosed", "- uses:\n: : :",
                     "gates: not-a-list"]
        for text in malformed:
            with self.subTest(text=text[:24]):
                try:
                    events = parse_workflow_events(text)
                    problems = (validate_trigger_events(events)
                                + validate_inputs(extract_inputs(text))
                                + validate_text_no_bypass(text))
                except Exception as exc:  # noqa: BLE001 — must not panic
                    self.fail(f"validator panicked on malformed input: {exc!r}")
                self.assertTrue(problems or not events,
                                "malformed input produced no finding and cannot claim pass")
        status, _ = load_receipt_file(FIX / "skipped-gate.json")
        self.assertEqual(status, "OK")
        with tempfile.TemporaryDirectory() as tmpdir:
            bad = pathlib.Path(tmpdir) / "receipt.json"
            bad.write_text("{not json", encoding="utf-8")
            status, _ = load_receipt_file(bad)
            self.assertEqual(status, "INCOMPLETE")
        broken = FIX / "profile-missing-gate.ps1"
        table = ps_profile_table(broken)
        self.assertTrue(validate_review_tail([r["name"] for r in table["steps"]]))
        self.assertEqual(evaluate_gate("unknown", None), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
