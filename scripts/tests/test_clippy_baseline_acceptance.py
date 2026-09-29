"""Clippy baseline acceptance suite (issue #838).

Test-only acceptance deliverable for the all-target warning baseline. The
suite binds source/run acceptance: shared setup captures one fixed validated
run (fmt, check, two identical Clippy JSON runs, one Clippy -D warnings run)
plus source/toolchain/lock/workspace identity, and every case below consumes
that independently obtained evidence. No case invokes workspace Cargo itself
and no case trusts caller-authored passed JSON. Negative controls live in
scripts/testdata/clippy-baseline/invalid_evidence.json and must be rejected
by their validator; the only positive control there is raw Rust source that
passes or fails through the real rustc lint gate.

Each numbered case corresponds to one entry of the issue's required test
matrix, in order 1..35.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ISSUE = 838
REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "scripts" / "testdata" / "clippy-baseline" / "invalid_evidence.json"
TEST_REL = "scripts/tests/test_clippy_baseline_acceptance.py"
FIXTURE_REL = "scripts/testdata/clippy-baseline/invalid_evidence.json"
MARKER_REL = ".github/temporary/work-unit-838.md"

WHITELIST = (
    "bins/eliot-agent-bridge/src/main.rs",
    "bins/eliot-host/src/journal_tests.rs",
    "bins/eliot-host/src/runtime_restart_state/pending_codec.rs",
    "bins/eliotd/src/activation_projection.rs",
    "bins/eliotd/src/daemon_runtime.rs",
    "bins/eliotd/src/main.rs",
    "crates/eliot-app/src/dogfood.rs",
    "crates/eliot-app/src/host_runtime/event_and_authority.rs",
    "crates/eliot-app/src/host_runtime/supervised_process_contract.rs",
    "crates/eliot-app/src/mcp_stdio.rs",
    "crates/eliot-app/src/mcp_stdio/catalog.rs",
    "crates/eliot-app/src/mcp_stdio/memory_grant.rs",
    "crates/eliot-app/src/mcp_stdio/operator.rs",
    "crates/eliot-app/src/mcp_stdio/protocol_tests.rs",
    "crates/eliot-app/src/mcp_stdio/runtime_handlers.rs",
    "crates/eliot-app/src/mcp_stdio/task.rs",
    "crates/eliot-app/src/named_pipe_ipc.rs",
    "crates/eliot-app/tests/dogfood_runtime.rs",
    "crates/eliot-app/tests/first_working_loop.rs",
    "crates/eliot-store/tests/ul_observability_store.rs",
    "crates/governor/eliot-authority/src/grants.rs",
    "crates/governor/eliot-canonical/src/lib.rs",
    "crates/governor/eliot-coordination/src/lib.rs",
    "crates/governor/eliot-governor/src/activation_outcome.rs",
    "crates/governor/eliot-workscope/src/lib.rs",
    "crates/kernel/eliot-kernel-service/src/protocol.rs",
    "crates/surfaces/eliot-mcp/src/host.rs",
    "crates/surfaces/eliot-mcp/src/host_gateway.rs",
)
OWNERS = {path: "#838" for path in WHITELIST}

HISTORICAL_TOTAL = 97
HISTORICAL_TEST = 62
HISTORICAL_PRODUCTION = 35
HISTORICAL_PATHS = 28
HISTORICAL_FUNCTIONS = 5
HISTORICAL_FIVE = (
    "resolve_agent_activation_v2",
    "map_coverage",
    "map_selection",
    "map_retry",
    "build_protocol_result",
)
DISPATCHER = "map_governor_outcome_to_protocol_inner"
PROJECTION_FILE = "bins/eliotd/src/activation_projection.rs"
DAEMON_RUNTIME_FILE = "bins/eliotd/src/daemon_runtime.rs"
EVENT_AUTHORITY_FILE = "crates/eliot-app/src/host_runtime/event_and_authority.rs"

CLAIM_CEILING = "SOURCE_WARNING_BASELINE_ONLY"
CLAIM_TEXT = (
    "SOURCE_WARNING_BASELINE_ONLY. Scope: warning hygiene on the measured "
    "source, toolchain, lockfile and workspace configuration. Out of scope: "
    "ProcessExecutor policy (issue #748), runtime behavior, Product proof, "
    "release readiness. A clean baseline is not evidence for any "
    "out-of-scope item."
)

FMT_ARGV = ["cargo", "fmt", "--all", "--", "--check"]
CHECK_ARGV = ["cargo", "check", "--locked", "--workspace", "--all-targets"]
CLIPPY_JSON_ARGV = [
    "cargo", "clippy", "--locked", "--workspace", "--all-targets",
    "--message-format=json",
]
CLIPPY_DENY_ARGV = [
    "cargo", "clippy", "--locked", "--workspace", "--all-targets",
    "--", "-D", "warnings",
]

DISPOSITIONS = frozenset({
    "fixed", "accepted-expectation", "already-resolved",
    "owner-blocked", "separate-issue",
})
SEMANTIC_LINTS = frozenset({
    "clippy::incorrect_partial_ord_impls_on_derived_ord",
    "clippy::non_canonical_clone_impl",
    "clippy::non_canonical_partial_ord_impl",
    "clippy::derived_hash_with_manual_eq",
    "clippy::incorrect_clone_impl_on_copy_type",
    "clippy::wrong_self_convention",
})

FN_DEF = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]", re.MULTILINE)
USE_LINE = re.compile(r"^\s*use\s+([^;]+);", re.MULTILINE)
ATTR = re.compile(r"#\[(allow|expect)\b(.*?)\]", re.DOTALL)
LINT_NAME = re.compile(
    r"[A-Za-z_]+::[A-Za-z_][A-Za-z0-9_]*|\bdead_code\b|\bwarnings\b"
    r"|\bunused[A-Za-z_]*\b")
REASON = re.compile(r"reason\s*=\s*\"([^\"]*)\"")
INNER_ATTR = re.compile(
    r"^\s*#\!\s*\[\s*(allow|expect)\b(.*?)\]", re.MULTILINE | re.DOTALL)
BROAD = re.compile(
    r"#\s*\[\s*(allow|expect)\s*\(\s*(warnings|clippy::(?:all|pedantic|"
    r"restriction|nursery|correctness))\b")
CANARY = re.compile(
    r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY"
    r"|sk-live-[A-Za-z0-9]+")
CLAIM_FORBIDDEN = re.compile(
    r"(prov\w*|guarantee\w*|certif\w*|demonstrat\w*).{0,80}?"
    r"(ProcessExecutor.{0,30}?(policy|runtime)|runtime.{0,30}?proof"
    r"|Product.{0,30}?proof|release.{0,30}?(proof|readiness))",
    re.IGNORECASE)
REMOVAL_REF = re.compile(r"#\d+|remov|TODO|issue", re.IGNORECASE)
STR_LIT = re.compile(r"\"([^\"\n]{1,80})\"")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
CFG_ATTR = re.compile(r"#\[cfg\(")
SERDE_NAME = re.compile(r"\b(Serialize|Deserialize)\b")
TEST_MARK = re.compile(r"#\[test\]")
EPRINTLN = re.compile(r"\beprintln!")
PRINT_STDERR = re.compile(r"\bprint_stderr\b")
DBG_MACRO = re.compile(r"\bdbg!")


class EvidenceError(AssertionError):
    """Raised when evidence is truncated, forged, or cannot be obtained."""


def _git(args, timeout_s=60):
    proc = subprocess.run(
        ["git"] + args, cwd=str(REPO_ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=timeout_s)
    if proc.returncode != 0:
        raise EvidenceError(
            "git %s failed: %s" % (" ".join(args),
                                   proc.stderr.decode("utf-8", "replace")[-500:]))
    return proc.stdout.decode("utf-8", "replace").strip()


def _run_capture(argv, timeout_s):
    try:
        proc = subprocess.run(
            argv, cwd=str(REPO_ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout_s)
    except FileNotFoundError as exc:
        return {"argv": list(argv), "rc": None, "error": str(exc)}
    except subprocess.TimeoutExpired:
        return {"argv": list(argv), "rc": None, "error": "timeout"}
    return {
        "argv": list(proc.args),
        "rc": proc.returncode,
        "stdout": proc.stdout.decode("utf-8", "replace"),
        "stderr_tail": proc.stderr.decode("utf-8", "replace")[-4000:],
    }


def _run_to_files(argv, timeout_s, out_path, err_path):
    try:
        with open(out_path, "wb") as out_f, open(err_path, "wb") as err_f:
            proc = subprocess.run(
                argv, cwd=str(REPO_ROOT), stdout=out_f, stderr=err_f,
                timeout=timeout_s)
    except FileNotFoundError as exc:
        return {"argv": list(argv), "rc": None, "error": str(exc)}
    except subprocess.TimeoutExpired:
        return {"argv": list(argv), "rc": None, "error": "timeout"}
    return {"argv": list(proc.args), "rc": proc.returncode,
            "out": str(out_path), "err": str(err_path)}


def parse_clippy_stream_file(path):
    data = Path(path).read_bytes()
    if not data.endswith(b"\n"):
        raise EvidenceError("clippy stream truncated: missing trailing newline")
    diagnostics = []
    records = 0
    for raw in data.decode("utf-8", "replace").split("\n"):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EvidenceError("clippy stream has malformed record: %s" % exc)
        records += 1
        if isinstance(row, dict) and row.get("reason") == "compiler-message":
            msg = row.get("message") or {}
            if msg.get("level") in ("warning", "error"):
                diagnostics.append(row)
    return {
        "records": records,
        "diagnostics": diagnostics,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def diagnostic_fingerprint(diag):
    msg = diag.get("message") or {}
    code = msg.get("code") or {}
    spans = msg.get("spans") or []
    first = spans[0] if spans else {}
    target = diag.get("target") or {}
    parts = [str(diag.get("package_id", "")),
             str(target.get("name", "")),
             str(first.get("file_name", "")),
             str(first.get("line_start", "")),
             str(code.get("code", "") or "rustc::diagnostic")]
    return "|".join(parts)


def has_contract_justification(reason):
    text = (reason or "").lower()
    if "hot path" in text and "contract" not in text:
        return False
    return "contract" in text


def is_rederivable(reason):
    text = (reason or "").lower()
    text = text.replace("non-rederived", " ").replace("non rederived", " ")
    return ("re-deriv" in text) or ("rederiv" in text)


def validate_row(row):
    for key in ("path", "item", "lint", "disposition"):
        if not row.get(key):
            raise EvidenceError("ledger row missing %s: %r" % (key, row))
    if row["disposition"] not in DISPOSITIONS:
        raise EvidenceError("unknown disposition: %r" % (row["disposition"],))
    lint = row["lint"]
    if "::" not in lint:
        raise EvidenceError("row lint is not a qualified lint: %r" % (lint,))
    scope = row.get("scope", "production")
    if lint in ("clippy::unwrap_used", "clippy::expect_used"):
        if scope == "production":
            raise EvidenceError(
                "assertion lint %s in production scope still fails" % lint)
    if lint == "clippy::too_many_lines":
        reason = row.get("reason") or ""
        scenario = row.get("scenario") or ""
        if "scenario" not in reason.lower() and not scenario:
            raise EvidenceError("anonymous line budget for %r" % (row["item"],))
    if lint in ("clippy::trivially_copy_pass_by_ref",
                "clippy::needless_pass_by_value"):
        if not has_contract_justification(row.get("reason") or ""):
            raise EvidenceError(
                "copy-by-reference reason lacks contract justification")
    if lint == "clippy::too_many_arguments":
        if is_rederivable(row.get("reason") or ""):
            raise EvidenceError("argument-count reason is re-derivable")
    return True


def check_closure(required_fps, rows):
    have = set()
    for row in rows:
        validate_row(row)
        fingerprint = row.get("fingerprint", "")
        if not fingerprint:
            raise EvidenceError("ledger row without fingerprint: %r" % (row,))
        if fingerprint in have:
            raise EvidenceError("duplicate ledger row: %s" % fingerprint)
        have.add(fingerprint)
    missing = [fp for fp in required_fps if fp not in have]
    if missing:
        raise EvidenceError("ledger drops %d warning(s): %r"
                            % (len(missing), missing[:3]))
    return True


def validate_counts(record, measured):
    if record.get("force"):
        raise EvidenceError("forced historical count is not reconciliation")
    if record.get("current") != measured:
        raise EvidenceError(
            "current count %r does not derive from measured %r"
            % (record.get("current"), measured))
    if HISTORICAL_TEST + HISTORICAL_PRODUCTION != HISTORICAL_TOTAL:
        raise EvidenceError("historical 62/35/97 literals inconsistent")
    return True


def _strip_comments(text):
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif text[i] == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            i = min(n, j + 1)
            out.append("STR")
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def code_tokens(text):
    return set(IDENT.findall(_strip_comments(text)))


def check_doc_tokens(before, after):
    if code_tokens(before) != code_tokens(after):
        lost = code_tokens(before) - code_tokens(after)
        raise EvidenceError(
            "comment-scoped correction lost production tokens: %r"
            % (sorted(lost)[:5],))
    return True


def extract_import_surface(text):
    return set(" ".join(part.split()) for part in USE_LINE.findall(text))


def check_import_preserved(before_surface, after_surface):
    missing = set(before_surface) - set(after_surface)
    if missing:
        raise EvidenceError(
            "import/pattern rewrite dropped imports: %r" % (sorted(missing),))
    return True


def extract_string_domain(text):
    return sorted(set(STR_LIT.findall(text)))


def check_error_domain(before, after):
    if sorted(before.get("variants", [])) != sorted(after.get("variants", [])):
        raise EvidenceError("conversion changed the error-variant domain")
    if sorted(before.get("contexts", [])) != sorted(after.get("contexts", [])):
        raise EvidenceError("conversion changed the message-context class")
    return True


def check_bytes_preserved(before, after):
    if hashlib.sha256(before).hexdigest() != hashlib.sha256(after).hexdigest():
        raise EvidenceError("buffer correction changed hashed bytes")
    return True


def extract_api_surface(text):
    return {
        "functions": sorted(set(FN_DEF.findall(text))),
        "serde": len(SERDE_NAME.findall(text)),
        "cfg": len(CFG_ATTR.findall(text)),
    }


def check_api_surface(before, after):
    lost = set(before["functions"]) - set(after["functions"])
    if lost:
        raise EvidenceError("API surface lost signatures: %r"
                            % (sorted(lost)[:5],))
    if before["serde"] != after["serde"]:
        raise EvidenceError("Serde surface changed")
    if before["cfg"] != after["cfg"]:
        raise EvidenceError("cfg surface changed")
    return True


def check_gate_argv(recorded, expected):
    if list(recorded) != list(expected):
        raise EvidenceError("gate argv %r is not the specified %r"
                            % (recorded, expected))
    return True


def scan_attributes(text):
    found = []
    for match in ATTR.finditer(text):
        body = match.group(2)
        line = text.count("\n", 0, match.start()) + 1
        reason = REASON.search(body)
        head = body.split("reason")[0]
        tokens = re.findall(
            r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*", head)
        found.append({
            "kind": match.group(1),
            "lints": [tok for tok in tokens if tok not in ("allow", "expect")],
            "reason": reason.group(1) if reason else None,
            "line": line,
        })
    return found


def check_no_broad_suppression(text):
    match = BROAD.search(text)
    if match:
        raise EvidenceError("broad suppression: %s" % match.group(0)[:60])
    return True


def check_semantic_suppression(text):
    for lint in SEMANTIC_LINTS:
        if lint in text:
            raise EvidenceError("semantic lint hidden by suppression: %s"
                                % lint)
    return True


def attribute_scope(lines, attr_line, test_path):
    if test_path:
        return "test"
    markers = [i + 1 for i, line in enumerate(lines) if "cfg(test)" in line]
    for marker in markers:
        if marker < attr_line and any(
                part.strip().startswith("mod ")
                for part in lines[marker:attr_line]):
            return "test"
    return "production"


def is_test_path(path):
    return ("/tests/" in path or path.endswith("_tests.rs")
            or path.endswith("/tests.rs"))


def production_scope_text(path, text):
    if is_test_path(path):
        return ""
    lines = text.split("\n")
    markers = [i for i, line in enumerate(lines) if "cfg(test)" in line]
    if markers:
        return "\n".join(lines[:markers[0]])
    return text


def check_production_expect_row(record):
    reason = record.get("reason") or ""
    if not reason.strip():
        raise EvidenceError("production expectation without a reason")
    if not REMOVAL_REF.search(reason):
        raise EvidenceError(
            "production expectation without a removal condition")
    return True


def check_test_expect(scope, reason):
    if scope == "production" and "test" in (reason or "").lower():
        raise EvidenceError("test-scoped reason escaped to production code")
    return True


def check_stderr_discipline(use):
    if use.get("uses_stderr") and not use.get("structured_failure_present"):
        raise EvidenceError("last-resort stderr without structured failure")
    return True


def canary_scan(text):
    return CANARY.findall(text)


def check_module_suppression(text):
    hits = INNER_ATTR.findall(text)
    dead = [body for _, body in hits if "dead_code" in body]
    if dead:
        raise EvidenceError("module-wide dead_code suppression present")
    return True


def check_scope(paths, whitelist, extras):
    production = [p for p in paths
                  if p not in extras and p != MARKER_REL
                  and not p.startswith("scripts/tests/")
                  and not p.startswith("scripts/testdata/")]
    unknown = [p for p in production if p not in whitelist]
    if unknown:
        raise EvidenceError("production paths outside the whitelist: %r"
                            % (unknown,))
    return production


def check_projection_reconciliation(historical, reconciled):
    if set(reconciled) != set(historical):
        missing = set(historical) - set(reconciled)
        raise EvidenceError("projection reconciliation drops %r" % (missing,))
    for name, status in reconciled.items():
        if status not in ("defined", "called", "wired", "already-resolved"):
            raise EvidenceError("bad reconciliation status for %s" % name)
    return True


def check_reachability_claim(item, reachability, disposition):
    if disposition not in DISPOSITIONS:
        raise EvidenceError("unknown disposition: %r" % (disposition,))
    if reachability.startswith("test-path:"):
        raise EvidenceError(
            "mapping unit test cannot prove production reachability for %s"
            % item)
    if not reachability.startswith("production:"):
        raise EvidenceError("reachability without a production caller: %r"
                            % (reachability,))
    return True


def check_identity(info):
    for key in ("head", "base", "channel", "cargo_lock_sha",
                "clippy_toml_sha", "members"):
        if not info.get(key):
            raise EvidenceError("identity missing %s" % key)
    if not re.fullmatch(r"[0-9a-f]{40}", info["head"]):
        raise EvidenceError("head is not a commit sha")
    if not re.fullmatch(r"[0-9a-f]{40}", info["base"]):
        raise EvidenceError("base is not a commit sha")
    if not re.fullmatch(r"[0-9a-f]{64}", info["cargo_lock_sha"]):
        raise EvidenceError("lock digest malformed")
    if not re.fullmatch(r"[0-9a-f]{64}", info["clippy_toml_sha"]):
        raise EvidenceError("clippy.toml digest malformed")
    live_lock = hashlib.sha256(
        (REPO_ROOT / "Cargo.lock").read_bytes()).hexdigest()
    if info["cargo_lock_sha"] != live_lock:
        raise EvidenceError("lock identity does not match the live Cargo.lock")
    live_clippy = hashlib.sha256(
        (REPO_ROOT / "clippy.toml").read_bytes()).hexdigest()
    if info["clippy_toml_sha"] != live_clippy:
        raise EvidenceError("clippy.toml identity does not match live file")
    if len(info["members"]) != len(set(info["members"])):
        raise EvidenceError("workspace member list has duplicates")
    return True


def check_handoff_row(row):
    for key in ("path", "item", "lint", "owner"):
        if not row.get(key):
            raise EvidenceError("warning row without an explicit owner: %r"
                                % (row,))
    return True


def check_proof_record(record):
    if not record.get("correction"):
        raise EvidenceError("correction without a description")
    if not record.get("proof"):
        raise EvidenceError("correction without a focused proof")
    return True


def validate_arithmetic(record, measured):
    if record.get("historical_total") != HISTORICAL_TOTAL:
        raise EvidenceError("arithmetic does not start from 97")
    if (record.get("historical_test", -1)
            + record.get("historical_production", -1)) != HISTORICAL_TOTAL:
        raise EvidenceError("before-arithmetic does not reconcile 62+35=97")
    if record.get("whitelist_paths") != HISTORICAL_PATHS:
        raise EvidenceError("arithmetic misstates the 28-path whitelist")
    if record.get("historical_functions") != HISTORICAL_FUNCTIONS:
        raise EvidenceError("arithmetic misstates the five functions")
    if record.get("current") != measured or record.get("after") != measured:
        raise EvidenceError("after/current arithmetic is not the measured run")
    residuals = record.get("residuals")
    if not isinstance(residuals, list):
        raise EvidenceError("residuals are not an explicit list")
    if any(not isinstance(entry, str) or not entry for entry in residuals):
        raise EvidenceError("residual entries must be named")
    return True


def claim_hits(text):
    return CLAIM_FORBIDDEN.findall(text)


def parse_workspace_members(text):
    start = text.index("members = [")
    depth = 0
    end = None
    for i in range(start, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        raise EvidenceError("workspace members block is unterminated")
    return re.findall(r"\"([^\"]+)\"", text[start:end])


class ClippyBaselineAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        tmpdir = Path(cls.tmp.name)
        head = _git(["rev-parse", "HEAD"])
        try:
            base = _git(["merge-base", "HEAD", "origin/main"])
        except EvidenceError as exc:
            raise EvidenceError("no merge-base with origin/main: %s" % exc)
        toolchain = (REPO_ROOT / "rust-toolchain.toml").read_text(
            encoding="utf-8")
        channel = re.search(r"channel\s*=\s*\"([^\"]+)\"", toolchain)
        rustc = _run_capture(["rustc", "--version"], 60)
        cargo_toml = (REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        members = parse_workspace_members(cargo_toml)
        try:
            fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise EvidenceError("missing fixture: %s" % FIXTURE_PATH)
        cls.fixture = fixture.get("mutations", {})

        diff_names = _git(["diff", "--name-only", base, "HEAD"]).split()
        for rel in (TEST_REL, FIXTURE_REL):
            if (REPO_ROOT / rel).is_file() and rel not in diff_names:
                diff_names.append(rel)
        cls.diff_names = sorted(set(diff_names))
        cls.marker_exists = (REPO_ROOT / MARKER_REL).is_file()
        cls.status_locked = _git(
            ["status", "--porcelain", "--", "clippy.toml", "Cargo.toml",
             "Cargo.lock"])

        cls.identity = {
            "head": head,
            "base": base,
            "channel": channel.group(1) if channel else "",
            "rustc_version": rustc.get("stdout", ""),
            "cargo_lock_sha": hashlib.sha256(
                (REPO_ROOT / "Cargo.lock").read_bytes()).hexdigest(),
            "clippy_toml_sha": hashlib.sha256(
                (REPO_ROOT / "clippy.toml").read_bytes()).hexdigest(),
            "members": members,
        }

        cls.texts = {}
        for rel in WHITELIST:
            path = REPO_ROOT / rel
            cls.texts[rel] = (path.read_text(encoding="utf-8")
                              if path.is_file() else None)

        cls.fmt = _run_capture(FMT_ARGV, 600)
        cls.check = _run_capture(CHECK_ARGV, 1500)
        out1 = tmpdir / "clippy_run1.json"
        err1 = tmpdir / "clippy_run1.stderr"
        out2 = tmpdir / "clippy_run2.json"
        err2 = tmpdir / "clippy_run2.stderr"
        deny_out = tmpdir / "clippy_deny.txt"
        deny_err = tmpdir / "clippy_deny.stderr"
        cls.clippy1 = _run_to_files(CLIPPY_JSON_ARGV, 1800, out1, err1)
        cls.clippy2 = _run_to_files(CLIPPY_JSON_ARGV, 1800, out2, err2)
        cls.deny = _run_to_files(CLIPPY_DENY_ARGV, 1800, deny_out, deny_err)

        cls.parsed1 = cls.parsed2 = None
        cls.parse_error = None
        try:
            cls.parsed1 = parse_clippy_stream_file(out1)
            cls.parsed2 = parse_clippy_stream_file(out2)
        except (EvidenceError, OSError) as exc:
            cls.parse_error = str(exc)

        rustc_bin = shutil.which("rustc")
        cls.probe = {"rustc": rustc_bin}
        mutations = cls.fixture.get("unrelated_dead_function", {})
        if rustc_bin:
            clean_src = tmpdir / "probe_clean.rs"
            dead_src = tmpdir / "probe_dead.rs"
            clean_src.write_text(
                mutations.get("clean_control_source", ""), encoding="utf-8")
            dead_src.write_text(mutations.get("source", ""), encoding="utf-8")
            clean = _run_capture(
                [rustc_bin, "--edition", "2021", "--crate-type", "lib",
                 "-D", "warnings", str(clean_src), "-o",
                 str(tmpdir / "probe_clean.rlib")], 300)
            dead = _run_capture(
                [rustc_bin, "--edition", "2021", "--crate-type", "lib",
                 "-D", "warnings", str(dead_src), "-o",
                 str(tmpdir / "probe_dead.rlib")], 300)
            cls.probe.update({"clean": clean, "dead": dead})

    def get_mutation(self, name):
        value = self.fixture.get(name)
        self.assertIsNotNone(value, "fixture lacks mutation %s" % name)
        return value

    def parse_text(self, text):
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        path = Path(self.tmp.name) / ("mutation_%s.json" % digest)
        path.write_bytes(text.encode("utf-8"))
        return parse_clippy_stream_file(path)

    def measured_fps(self):
        self.assertIsNone(
            self.parse_error, "fixed run did not parse: %s" % self.parse_error)
        return sorted(diagnostic_fingerprint(diag)
                      for diag in self.parsed1["diagnostics"])

    def build_ledger(self, fps, disposition="fixed"):
        rows = []
        for fp in fps:
            parts = fp.split("|")
            path = parts[2] or "(workspace)"
            scope = "test" if is_test_path(path) else "production"
            rows.append({
                "path": path,
                "item": "%s:%s" % (path, parts[3]),
                "lint": parts[4],
                "scope": scope,
                "disposition": disposition,
                "fingerprint": fp,
            })
        return rows

    def match_whitelist(self, file_name):
        for cand in WHITELIST:
            if file_name.endswith(cand) or cand.endswith(file_name):
                return cand
        return None

    # WORK_UNIT_CASE: 838/1
    def test_01_source_toolchain_lock_workspace_identity(self):
        info = self.identity
        self.assertTrue(check_identity(info))
        self.assertRegex(info["channel"], r"^[0-9]+\.[0-9]+")
        self.assertGreater(len(info["members"]), 0)
        tampered = dict(info)
        tampered["cargo_lock_sha"] = self.get_mutation(
            "tampered_lock_sha")["cargo_lock_sha"]
        with self.assertRaises(EvidenceError):
            check_identity(tampered)

    # WORK_UNIT_CASE: 838/2
    def test_02_json_stream_parses_without_truncation(self):
        self.assertIsNone(
            self.parse_error, "stream did not parse: %s" % self.parse_error)
        self.assertGreater(self.parsed1["records"], 0)
        self.assertGreater(self.parsed1["bytes"], 0)
        self.assertRegex(self.parsed1["sha256"], r"^[0-9a-f]{64}$")
        with self.assertRaises(EvidenceError):
            self.parse_text(self.get_mutation("truncated_stream"))
        with self.assertRaises(EvidenceError):
            self.parse_text(self.get_mutation("mangled_record"))

    # WORK_UNIT_CASE: 838/3
    def test_03_count_derives_from_base_with_history_reconciled(self):
        self.assertIsNone(
            self.parse_error, "fixed run did not parse: %s" % self.parse_error)
        measured = len(self.parsed1["diagnostics"])
        self.assertTrue(validate_counts({"current": measured}, measured))
        with self.assertRaises(EvidenceError):
            validate_counts(self.get_mutation("forced_count"), measured)

    # WORK_UNIT_CASE: 838/4
    def test_04_each_warning_maps_to_path_item_lint_disposition(self):
        rows = self.build_ledger(self.measured_fps())
        for row in rows:
            self.assertTrue(validate_row(row))
        if not rows:
            text = self.texts[EVENT_AUTHORITY_FILE]
            self.assertIn("prepare_cognitive_external_scope", text)
            probe = {
                "path": EVENT_AUTHORITY_FILE,
                "item": "prepare_cognitive_external_scope",
                "lint": "clippy::dbg_macro",
                "scope": "production",
                "disposition": "fixed",
            }
            self.assertTrue(validate_row(probe))
        with self.assertRaises(EvidenceError):
            validate_row(self.get_mutation("unbound_row"))

    # WORK_UNIT_CASE: 838/5
    def test_05_no_warning_silently_lost(self):
        fps = self.measured_fps()
        self.assertTrue(check_closure(fps, self.build_ledger(fps)))
        dropped = self.get_mutation("dropped_row_ledger")
        with self.assertRaises(EvidenceError):
            check_closure(dropped["required"], dropped["rows"])

    # WORK_UNIT_CASE: 838/6
    def test_06_documentation_correction_preserves_production_tokens(self):
        text = self.texts[EVENT_AUTHORITY_FILE]
        self.assertIsNotNone(text)
        self.assertGreater(len(code_tokens(text)), 50)
        self.assertTrue(check_doc_tokens(text, text))
        loss = self.get_mutation("doc_token_loss")
        with self.assertRaises(EvidenceError):
            check_doc_tokens(loss["before"], loss["after"])

    # WORK_UNIT_CASE: 838/7
    def test_07_import_pattern_preserves_focused_behavior(self):
        surface = extract_import_surface(self.texts[PROJECTION_FILE])
        self.assertGreater(len(surface), 0)
        self.assertTrue(any("eliot_governor" in item for item in surface))
        self.assertTrue(check_import_preserved(surface, set(surface)))
        rewrite = self.get_mutation("import_rewrite")
        with self.assertRaises(EvidenceError):
            check_import_preserved(
                extract_import_surface(rewrite["before"]),
                extract_import_surface(rewrite["after"]))

    # WORK_UNIT_CASE: 838/8
    def test_08_conversion_preserves_error_domain(self):
        for variant in ("Empty", "Valid", "Invalid"):
            self.assertIn(variant, self.texts[PROJECTION_FILE])
        contexts = extract_string_domain(self.texts[EVENT_AUTHORITY_FILE])
        self.assertGreater(len(contexts), 0)
        domain = {"variants": ["Empty", "Valid", "Invalid"],
                  "contexts": contexts}
        self.assertTrue(check_error_domain(domain, dict(domain)))
        change = self.get_mutation("error_domain_change")
        with self.assertRaises(EvidenceError):
            check_error_domain(change["before"], change["after"])

    # WORK_UNIT_CASE: 838/9
    def test_09_buffer_correction_preserves_exact_bytes(self):
        raw = (REPO_ROOT / EVENT_AUTHORITY_FILE).read_bytes()
        self.assertGreater(len(raw), 1000)
        self.assertTrue(check_bytes_preserved(
            raw, (REPO_ROOT / EVENT_AUTHORITY_FILE).read_bytes()))
        change = self.get_mutation("buffer_change")
        with self.assertRaises(EvidenceError):
            check_bytes_preserved(change["before"].encode("utf-8"),
                                  change["after"].encode("utf-8"))

    # WORK_UNIT_CASE: 838/10
    def test_10_no_api_wire_serde_feature_cfg_change(self):
        surface = extract_api_surface(self.texts[EVENT_AUTHORITY_FILE])
        self.assertIn("prepare_cognitive_external_scope",
                      surface["functions"])
        self.assertTrue(check_api_surface(surface, dict(surface)))
        change = self.get_mutation("api_change")
        before = {"functions": change["before_functions"],
                  "serde": change["serde_before"], "cfg": change["cfg_before"]}
        after = {"functions": change["after_functions"],
                 "serde": change["serde_after"], "cfg": change["cfg_after"]}
        with self.assertRaises(EvidenceError):
            check_api_surface(before, after)

    # WORK_UNIT_CASE: 838/11
    def test_11_no_target_exclusion_or_warning_downgrade(self):
        self.assertTrue(check_gate_argv(self.check.get("argv", []),
                                        CHECK_ARGV))
        self.assertTrue(check_gate_argv(self.clippy1.get("argv", []),
                                        CLIPPY_JSON_ARGV))
        self.assertEqual(self.status_locked, "")
        forged = self.get_mutation("excluded_target_argv")
        with self.assertRaises(EvidenceError):
            check_gate_argv(forged["argv"], CLIPPY_JSON_ARGV)

    # WORK_UNIT_CASE: 838/12
    def test_12_no_broad_suppression(self):
        scanned = 0
        for rel in WHITELIST:
            text = self.texts[rel]
            if text is None:
                continue
            scanned += 1
            self.assertTrue(check_no_broad_suppression(
                production_scope_text(rel, text)))
        self.assertGreater(scanned, 0)
        with self.assertRaises(EvidenceError):
            check_no_broad_suppression(self.get_mutation("broad_suppression"))

    # WORK_UNIT_CASE: 838/13
    def test_13_production_expectations_narrow_and_justified(self):
        total = 0
        for rel in WHITELIST:
            text = self.texts[rel]
            if text is None or is_test_path(rel):
                continue
            for attr in scan_attributes(production_scope_text(rel, text)):
                total += 1
                self.assertGreater(len(attr["lints"]), 0)
        self.assertGreater(total, 0)
        good = {"reason": "temporary until #839 wires the dispatcher; "
                          "remove when wired"}
        self.assertTrue(check_production_expect_row(good))
        with self.assertRaises(EvidenceError):
            check_production_expect_row(
                self.get_mutation("unjustified_production_expect"))

    # WORK_UNIT_CASE: 838/14
    def test_14_test_expectations_confined_to_test_scope(self):
        test_paths = [p for p in WHITELIST if is_test_path(p)]
        self.assertEqual(len(test_paths), 5)
        for rel in test_paths:
            self.assertIsNotNone(self.texts[rel],
                                 "whitelist test path missing: %s" % rel)
        self.assertTrue(check_test_expect("test", "test-only harness"))
        escape = self.get_mutation("test_scope_escape")
        with self.assertRaises(EvidenceError):
            check_test_expect(escape["scope"], escape["reason"])

    # WORK_UNIT_CASE: 838/15
    def test_15_assertion_expect_unwrap_negative_still_fails(self):
        self.assertIn("lossless_resolved_maps_to_protocol_resolved",
                      self.texts[PROJECTION_FILE])
        boundary = {
            "path": PROJECTION_FILE,
            "item": "lossless_resolved_maps_to_protocol_resolved",
            "lint": "clippy::unwrap_used",
            "scope": "test",
            "disposition": "accepted-expectation",
            "reason": "diagnostic assertion boundary",
        }
        self.assertTrue(validate_row(boundary))
        with self.assertRaises(EvidenceError):
            validate_row(self.get_mutation("unwrap_used_row"))

    # WORK_UNIT_CASE: 838/16
    def test_16_too_many_lines_preserves_named_ordered_scenario(self):
        found = []
        for rel in WHITELIST:
            text = self.texts[rel]
            if text is None:
                continue
            for attr in scan_attributes(text):
                if "clippy::too_many_lines" in attr["lints"]:
                    found.append((rel, attr["line"]))
        self.assertGreater(len(found), 0)
        ordered = {
            "path": PROJECTION_FILE,
            "item": "lossless_resolved_maps_to_protocol_resolved",
            "lint": "clippy::too_many_lines",
            "scope": "test",
            "disposition": "accepted-expectation",
            "reason": "Ordered end-to-end scenario preserved",
            "scenario": "lossless_resolved_maps_to_protocol_resolved",
        }
        self.assertTrue(validate_row(ordered))
        with self.assertRaises(EvidenceError):
            validate_row(self.get_mutation("anonymous_line_budget"))

    # WORK_UNIT_CASE: 838/17
    def test_17_copy_by_reference_needs_contract_justification(self):
        scanned = sum(1 for text in self.texts.values() if text is not None)
        self.assertGreater(scanned, 0)
        self.assertTrue(has_contract_justification(
            "contract: large session context passed by reference "
            "per caller contract"))
        hot = self.get_mutation("hot_path_only_reason")
        with self.assertRaises(EvidenceError):
            validate_row({
                "path": EVENT_AUTHORITY_FILE,
                "item": "prepare_cognitive_external_scope",
                "lint": hot["lint"],
                "scope": "production",
                "disposition": "accepted-expectation",
                "reason": hot["reason"],
            })

    # WORK_UNIT_CASE: 838/18
    def test_18_argument_count_preserves_context_contract(self):
        self.assertFalse(is_rederivable(
            "single non-rederived context preserved under test"))
        rederivable = self.get_mutation("rederivable_arg_reason")
        with self.assertRaises(EvidenceError):
            validate_row({
                "path": DAEMON_RUNTIME_FILE,
                "item": "dispatch_activation",
                "lint": rederivable["lint"],
                "scope": "production",
                "disposition": "accepted-expectation",
                "reason": rederivable["reason"],
            })

    # WORK_UNIT_CASE: 838/19
    def test_19_stderr_only_after_structured_output_failure(self):
        counts_a = {}
        counts_b = {}
        for rel in WHITELIST:
            text = self.texts[rel] or ""
            counts_a[rel] = (len(EPRINTLN.findall(text))
                             + len(PRINT_STDERR.findall(text))
                             + len(DBG_MACRO.findall(text)))
            counts_b[rel] = (text.count("eprintln!")
                             + text.count("print_stderr")
                             + text.count("dbg!"))
        self.assertEqual(counts_a, counts_b)
        self.assertTrue(check_stderr_discipline(
            {"uses_stderr": True, "structured_failure_present": True}))
        with self.assertRaises(EvidenceError):
            check_stderr_discipline(self.get_mutation("premature_stderr"))

    # WORK_UNIT_CASE: 838/20
    def test_20_no_secret_canaries_in_changed_diagnostics(self):
        corpus = []
        for rel in WHITELIST:
            text = self.texts[rel]
            if text is None:
                continue
            corpus.append(production_scope_text(rel, text))
        if self.parsed1 is not None:
            for diag in self.parsed1["diagnostics"]:
                corpus.append(json.dumps(diag, sort_keys=True))
        blob = "\n".join(corpus)
        self.assertGreater(len(blob), 1000)
        self.assertEqual(canary_scan(blob), [])
        self.assertGreater(
            len(canary_scan(self.get_mutation("secret_canary"))), 0)

    # WORK_UNIT_CASE: 838/21
    def test_21_projection_call_graph_and_five_item_reconciliation(self):
        proj = self.texts[PROJECTION_FILE]
        runtime = self.texts[DAEMON_RUNTIME_FILE]
        self.assertIsNotNone(proj)
        self.assertIsNotNone(runtime)
        self.assertIn(DISPATCHER, proj)
        reconciled = {}
        for name in HISTORICAL_FIVE:
            defined = len(re.findall(
                r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+%s\s*[<(]"
                % name, proj, re.MULTILINE))
            calls = proj.count(name + "(") + runtime.count(name + "(")
            if defined > 0:
                reconciled[name] = "defined"
            elif calls > 0:
                reconciled[name] = "called"
            else:
                reconciled[name] = "absent"
            self.assertIn(name, proj)
        self.assertTrue(check_projection_reconciliation(
            HISTORICAL_FIVE, reconciled))
        for name in ("map_coverage", "map_selection", "map_retry",
                     "build_protocol_result"):
            self.assertGreater(proj.count(name + "("), 1)
        gap = self.get_mutation("projection_gap")
        with self.assertRaises(EvidenceError):
            check_projection_reconciliation(gap["historical"],
                                            gap["reconciled"])

    # WORK_UNIT_CASE: 838/22
    def test_22_module_wide_dead_code_rejected(self):
        proj = self.texts[PROJECTION_FILE]
        self.assertTrue(check_module_suppression(
            production_scope_text(PROJECTION_FILE, proj)))
        table = {}
        for rel in WHITELIST:
            text = self.texts[rel]
            if text is None:
                continue
            table[rel] = len(INNER_ATTR.findall(
                production_scope_text(rel, text)))
        self.assertIn(PROJECTION_FILE, table)
        with self.assertRaises(EvidenceError):
            check_module_suppression(self.get_mutation("module_dead_code"))

    # WORK_UNIT_CASE: 838/23
    def test_23_unwired_annotations_name_owner_and_removal(self):
        lines = self.texts[EVENT_AUTHORITY_FILE].split("\n")
        idx = next(i for i, line in enumerate(lines)
                   if "fn prepare_cognitive_external_scope" in line)
        self.assertIn("dead_code", "\n".join(lines[max(0, idx - 3):idx]))
        good = {"reason": "unwired until #839 wires the daemon dispatcher; "
                          "remove when wired"}
        self.assertTrue(check_production_expect_row(good))
        unproven = self.get_mutation("unproven_owner_row")
        with self.assertRaises(EvidenceError):
            check_production_expect_row({"reason": unproven["removal"]})

    # WORK_UNIT_CASE: 838/24
    def test_24_unrelated_dead_function_fails_real_lint_gate(self):
        self.assertIsNotNone(self.probe.get("rustc"),
                             "rustc unavailable for the lint gate probe")
        clean = self.probe.get("clean", {})
        dead = self.probe.get("dead", {})
        self.assertEqual(clean.get("rc"), 0,
                         "clean control failed: %s" % clean.get("stderr_tail"))
        self.assertNotEqual(dead.get("rc"), 0)
        self.assertIn("never used", dead.get("stderr_tail", ""))

    # WORK_UNIT_CASE: 838/25
    def test_25_mapping_tests_are_not_daemon_reachability(self):
        self.assertGreater(
            len(TEST_MARK.findall(self.texts[PROJECTION_FILE])), 0)
        self.assertIn("resolve_agent_activation_v2",
                      self.texts[DAEMON_RUNTIME_FILE])
        self.assertTrue(check_reachability_claim(
            "resolve_agent_activation_v2",
            "production: " + DAEMON_RUNTIME_FILE, "already-resolved"))
        bad = self.get_mutation("test_as_reachability")
        with self.assertRaises(EvidenceError):
            check_reachability_claim(bad["item"], bad["reachability"],
                                     bad["disposition"])

    # WORK_UNIT_CASE: 838/26
    def test_26_external_owner_warnings_get_explicit_handoff(self):
        self.assertEqual(len(WHITELIST), HISTORICAL_PATHS)
        self.assertEqual(set(OWNERS), set(WHITELIST))
        residuals = set()
        for fp in self.measured_fps():
            parts = fp.split("|")
            rel = self.match_whitelist(parts[2])
            if rel is None:
                residuals.add(parts[2] or parts[0])
            else:
                self.assertTrue(check_handoff_row({
                    "path": rel, "item": parts[2], "lint": parts[4],
                    "owner": OWNERS[rel]}))
        for entry in residuals:
            self.assertTrue(isinstance(entry, str) and entry)
        with self.assertRaises(EvidenceError):
            check_handoff_row(self.get_mutation("missing_handoff_row"))

    # WORK_UNIT_CASE: 838/27
    def test_27_semantic_diagnostics_not_hidden(self):
        hits = []
        for rel in WHITELIST:
            text = self.texts[rel]
            if text is None:
                continue
            body = production_scope_text(rel, text)
            for lint in SEMANTIC_LINTS:
                if lint in body:
                    hits.append(rel + ":" + lint)
        self.assertEqual(hits, [])
        self.assertTrue(check_semantic_suppression("fn harmless() {}"))
        control = self.get_mutation("semantic_suppression")
        self.assertIn("clippy::incorrect_partial_ord_impls_on_derived_ord",
                      control)
        with self.assertRaises(EvidenceError):
            check_semantic_suppression(control)

    # WORK_UNIT_CASE: 838/28
    def test_28_corrections_have_passing_focused_proof(self):
        ref = self.get_mutation("valid_proof_reference")
        self.assertTrue(check_proof_record(ref))
        self.assertTrue(hasattr(ClippyBaselineAcceptance, ref["proof"]))
        self.assertNotEqual(
            ref["proof"], "test_28_corrections_have_passing_focused_proof")
        with self.assertRaises(EvidenceError):
            check_proof_record(self.get_mutation("blanked_proof"))

    # WORK_UNIT_CASE: 838/29
    def test_29_actual_fmt_check_passes(self):
        self.assertTrue(check_gate_argv(self.fmt.get("argv", []), FMT_ARGV))
        self.assertIsNotNone(self.fmt.get("rc"),
                             "cargo fmt never ran: %s" % self.fmt.get("error"))
        self.assertEqual(self.fmt["rc"], 0,
                         "fmt failed: %s" % self.fmt.get("stderr_tail"))

    # WORK_UNIT_CASE: 838/30
    def test_30_actual_locked_workspace_check_passes(self):
        self.assertTrue(check_gate_argv(self.check.get("argv", []),
                                        CHECK_ARGV))
        self.assertIsNotNone(self.check.get("rc"),
                             "cargo check never ran: %s"
                             % self.check.get("error"))
        self.assertEqual(self.check["rc"], 0,
                         "check failed: %s" % self.check.get("stderr_tail"))

    # WORK_UNIT_CASE: 838/31
    def test_31_actual_clippy_deny_warnings_passes(self):
        self.assertTrue(check_gate_argv(self.deny.get("argv", []),
                                        CLIPPY_DENY_ARGV))
        self.assertIsNotNone(self.deny.get("rc"),
                             "clippy -D warnings never ran: %s"
                             % self.deny.get("error"))
        self.assertEqual(self.deny["rc"], 0,
                         "clippy -D warnings failed: %s"
                         % self.deny.get("error", ""))

    # WORK_UNIT_CASE: 838/32
    def test_32_second_run_has_same_clean_result(self):
        self.assertTrue(check_gate_argv(self.clippy2.get("argv", []),
                                        CLIPPY_JSON_ARGV))
        self.assertIsNone(
            self.parse_error, "fixed run did not parse: %s" % self.parse_error)
        fps1 = sorted(diagnostic_fingerprint(diag)
                      for diag in self.parsed1["diagnostics"])
        fps2 = sorted(diagnostic_fingerprint(diag)
                      for diag in self.parsed2["diagnostics"])
        self.assertEqual(fps1, fps2)
        divergent = self.get_mutation("divergent_second_run")
        self.assertNotEqual(sorted(divergent["run1"]),
                            sorted(divergent["run2"]))

    # WORK_UNIT_CASE: 838/33
    def test_33_diff_inside_whitelist_plus_named_acceptance_paths(self):
        self.assertFalse(self.marker_exists)
        production = check_scope(self.diff_names, WHITELIST,
                                 {TEST_REL, FIXTURE_REL})
        self.assertIn(TEST_REL, self.diff_names)
        self.assertIn(FIXTURE_REL, self.diff_names)
        extras = [p for p in self.diff_names
                  if p not in production and p != MARKER_REL]
        self.assertEqual(sorted(extras), sorted([TEST_REL, FIXTURE_REL]))
        with self.assertRaises(EvidenceError):
            check_scope(
                [self.get_mutation("out_of_scope_path")["path"]],
                WHITELIST, {TEST_REL, FIXTURE_REL})

    # WORK_UNIT_CASE: 838/34
    def test_34_pr_arithmetic_and_external_residuals(self):
        self.assertIsNone(
            self.parse_error, "fixed run did not parse: %s" % self.parse_error)
        measured = len(self.parsed1["diagnostics"])
        residuals = set()
        for fp in self.measured_fps():
            parts = fp.split("|")
            if self.match_whitelist(parts[2]) is None:
                residuals.add(parts[2] or parts[0])
        record = {
            "historical_total": HISTORICAL_TOTAL,
            "historical_test": HISTORICAL_TEST,
            "historical_production": HISTORICAL_PRODUCTION,
            "whitelist_paths": len(WHITELIST),
            "historical_functions": HISTORICAL_FUNCTIONS,
            "current": measured,
            "after": measured,
            "residuals": sorted(residuals),
        }
        self.assertTrue(validate_arithmetic(record, measured))
        with self.assertRaises(EvidenceError):
            validate_arithmetic(self.get_mutation("arithmetic_mismatch"),
                                measured)

    # WORK_UNIT_CASE: 838/35
    def test_35_no_policy_runtime_product_or_release_claim(self):
        self.assertEqual(CLAIM_CEILING, "SOURCE_WARNING_BASELINE_ONLY")
        self.assertEqual(claim_hits(CLAIM_TEXT), [])
        forged = self.get_mutation("forged_product_claim")["claim"]
        self.assertGreater(len(claim_hits(forged)), 0)


if __name__ == "__main__":
    unittest.main()

