"""Dedicated acceptance suite for issue #838 (D-CLIPPY-BASELINE).

What this is
------------
The genuinely missing deliverable of #838. The issue names a *metadata-Python*
suite with one substantive test per ``# WORK_UNIT_CASE: 838/<case>``, cases
exactly ``1..35``. It is explicitly **not** 35 duplicate Rust product tests, and
it is explicitly **not** another Cargo runner or a production lint framework: the
Cargo surface is a *shared, once-per-run* validated capture that every case
reuses (issue: "shared setup may reuse a fixed validated run", "Perform the
required second Clippy run once, not in every acceptance test").

Evidence discipline
-------------------
* No caller-authored passed JSON. The JSON evidence is produced by executing
  ``cargo clippy --locked --workspace --all-targets --message-format=json``
  in this process and parsing its own stdout.
* No recursive workspace Cargo invocation per case. Every command runs exactly
  once, in :meth:`ClippyBaselineAcceptance.setUpClass`.
* The expected sets (the 28-path whitelist, the historical 97 arithmetic, the
  five projection functions, the valid disposition vocabulary) are written out
  as literals in this module. They are never recomputed from the thing they
  check, so no case compares two copies of the same list.
* Every negative case drives a mutation from
  ``scripts/testdata/clippy-baseline/invalid_evidence.json`` through the *same*
  validator that is applied to the real current evidence. A mutation the
  validator accepts is a hole and fails the case.

Honest limits, stated up front
------------------------------
``cargo check``/``cargo clippy -D warnings`` do not currently pass on this base
(there are pre-existing hard compile errors in
``crates/meta/eliot-learning-activation-assessment/tests/` and
``bins/eliotd`, ``bins/eliot-agent-bridge``, ``crates/governor/eliot-authority``
and ``crates/kernel/eliot-kernel-service`` test targets). Cases 30, 31 and 32
therefore assert the real requirement and FAIL until those owners land. That
is the intended signal; this suite must not be rigged to report green.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "scripts" / "testdata" / "clippy-baseline" / "invalid_evidence.json"
ISSUE = 838

# ---------------------------------------------------------------------------
# Independent expected sets. Written out literally; never derived from the
# evidence they are compared against.
# ---------------------------------------------------------------------------

# The frozen 28-path production whitelist, transcribed from the issue body.
WHITELIST = frozenset(
    """
    bins/eliot-agent-bridge/src/main.rs
    bins/eliot-host/src/journal_tests.rs
    bins/eliot-host/src/runtime_restart_state/pending_codec.rs
    bins/eliotd/src/activation_projection.rs
    bins/eliotd/src/daemon_runtime.rs
    bins/eliotd/src/main.rs
    crates/eliot-app/src/dogfood.rs
    crates/eliot-app/src/host_runtime/event_and_authority.rs
    crates/eliot-app/src/host_runtime/supervised_process_contract.rs
    crates/eliot-app/src/mcp_stdio.rs
    crates/eliot-app/src/mcp_stdio/catalog.rs
    crates/eliot-app/src/mcp_stdio/memory_grant.rs
    crates/eliot-app/src/mcp_stdio/operator.rs
    crates/eliot-app/src/mcp_stdio/protocol_tests.rs
    crates/eliot-app/src/mcp_stdio/runtime_handlers.rs
    crates/eliot-app/src/mcp_stdio/task.rs
    crates/eliot-app/src/named_pipe_ipc.rs
    crates/eliot-app/tests/dogfood_runtime.rs
    crates/eliot-app/tests/first_working_loop.rs
    crates/eliot-store/tests/ul_observability_store.rs
    crates/governor/eliot-authority/src/grants.rs
    crates/governor/eliot-canonical/src/lib.rs
    crates/governor/eliot-coordination/src/lib.rs
    crates/governor/eliot-governor/src/activation_outcome.rs
    crates/governor/eliot-workscope/src/lib.rs
    crates/kernel/eliot-kernel-service/src/protocol.rs
    crates/surfaces/eliot-mcp/src/host.rs
    crates/surfaces/eliot-mcp/src/host_gateway.rs
    """.split()
)
assert len(WHITELIST) == 28, "the frozen whitelist must be exactly 28 paths"

# The only non-production paths this issue may create, plus the vacuous marker
# removal named by the issue.
EXTRA_ALLOWED = frozenset(
    {
        "scripts/tests/test_clippy_baseline_acceptance.py",
        "scripts/testdata/clippy-baseline/invalid_evidence.json",
    }
)
MARKER_REMOVAL = ".github/temporary/work-unit-838.md"

# The historical arithmetic the issue states, kept verbatim and reconciled
# rather than restated as a current count.
HISTORICAL_TOTAL = 97
HISTORICAL_TEST_CONTEXT = 62
HISTORICAL_PRODUCTION_CONTEXT = 35
HISTORICAL_CHANGED_PATHS = 28
HISTORICAL_DEAD_PROJECTION_FUNCTIONS = 5

# The five historical dead v2 mapping functions in
# bins/eliotd/src/activation_projection.rs, with the production caller that
# current source proves for each. The reachability values are production
# `src/` call sites, never test paths.
PROJECTION_FIVE = {
    "resolve_agent_activation_v2": "bins/eliotd/src/daemon_runtime.rs::AgentActivationResolver::resolve_agent_activation_v2",
    "map_coverage": "bins/eliotd/src/activation_projection.rs::map_governor_outcome_to_protocol_inner",
    "map_selection": "bins/eliotd/src/activation_projection.rs::map_governor_outcome_to_protocol_inner",
    "map_retry": "bins/eliotd/src/activation_projection.rs::map_governor_outcome_to_protocol_inner",
    "build_protocol_result": "bins/eliotd/src/activation_projection.rs::map_governor_outcome_to_protocol_inner",
}

VALID_DISPOSITIONS = frozenset(
    {
        "FIXED_MECHANICAL",
        "FIXED_ITEM_EXPECTATION",
        "ACCEPTED_NARROW_EXPECTATION",
        "ALREADY_RESOLVED_CURRENT_EVIDENCE",
        "OWNER_BLOCKED",
        "SEPARATE_CAUSAL_ISSUE",
    }
)

POLICY_LINT = "clippy::disallowed_methods"
POLICY_OWNER = "#748 (sole ProcessExecutor / root policy; BLOCKED-BY, not fixed here)"

# Lints that carry semantic or error-domain meaning. Suppressing one of these
# is never a mechanical correction.
SEMANTIC_LINTS = frozenset(
    {
        "clippy::result_large_err",
        "clippy::cast_possible_wrap",
        "clippy::cast_possible_truncation",
        "clippy::large_enum_variant",
        "clippy::large_futures",
        "clippy::unnecessary_wraps",
        "clippy::unnecessary_lazy_evaluations",
        "clippy::default_trait_access",
        "clippy::map_unwrap_or",
        "clippy::disallowed_methods",
    }
)

BROAD_SUPPRESSION_PATTERNS = (
    r"#!\s*\[\s*allow\s*\(\s*warnings\s*\)",
    r"#!\s*\[\s*allow\s*\(\s*clippy::all\s*\)",
    r"#!\s*\[\s*allow\s*\(\s*clippy::pedantic\s*\)",
    r"#!\s*\[\s*allow\s*\(\s*clippy::",
    r"#!\s*\[\s*allow\s*\(\s*dead_code\s*\)",
    r"-A\s+warnings",
    r"-A\s+clippy",
)

SECRET_PATTERNS = (
    r"sk-canary-\d+",
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"(?i)\b(api[_-]?key|secret|password|passwd|bearer[_-]?token)\s*[:=]\s*\"[^\"]{8,}\"",
)

CAPTURE_WORKSPACE = [
    "cargo",
    "clippy",
    "--locked",
    "--workspace",
    "--all-targets",
    "--message-format=json",
]
SECOND_CAPTURE_WORKSPACE = CAPTURE_WORKSPACE  # identical source/tool/config


# ---------------------------------------------------------------------------
# Small helpers.
# ---------------------------------------------------------------------------


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def repo_rel(path: str) -> str:
    return path.replace("\\", "/").split("W2-838/")[-1].split("M-W2/")[-1]


def git(*args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise AssertionError(
            "git %s failed (%d): %s" % (" ".join(args), proc.returncode, proc.stderr)
        )
    return proc.stdout


def run_capture(argv: list[str], timeout: int = 5400) -> tuple[int, str, str]:
    env = dict(os.environ)
    env.setdefault("CARGO_INCREMENTAL", "0")
    env.setdefault(
        "CARGO_TARGET_DIR", r"C:\Development\Rust\projects\eliot-swarm\targets\W2"
    )
    proc = subprocess.run(
        argv, cwd=REPO_ROOT, capture_output=True, text=True, check=False, env=env, timeout=timeout
    )
    return proc.returncode, proc.stdout, proc.stderr


def parse_clippy_stream(raw: str) -> list[dict]:
    """Parse a complete ``--message-format=json`` stream.

    Rejects truncation: the payload must end with a newline and every
    non-empty line must be a complete JSON record. Returns the diagnostic
    records only; non-diagnostic records (compiler-artifact,
    build-script-executed, build-finished) are counted separately by the
    caller.
    """
    if raw and not raw.endswith("\n"):
        raise ValueError("stream is truncated: payload does not end with a newline")
    records = []
    for index, line in enumerate(raw.splitlines()):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError("stream record %d does not parse: %s" % (index, exc)) from exc
    return records


def diagnostics_from_records(records: list[dict]) -> list[dict]:
    rows = []
    for record in records:
        if record.get("reason") != "compiler-message":
            continue
        message = record.get("message") or {}
        if message.get("level") not in ("warning", "error"):
            continue
        spans = message.get("spans") or []
        primary = next((s for s in spans if s.get("is_primary")), spans[0] if spans else {})
        rows.append(
            {
                "level": message.get("level"),
                "code": (message.get("code") or {}).get("code"),
                "path": repo_rel(primary.get("file_name") or ""),
                "line": primary.get("line_start"),
                "target": record.get("target", {}).get("name"),
                "kinds": tuple(record.get("target", {}).get("kind") or ()),
                "message": message.get("message", ""),
            }
        )
    return rows


def target_class(row: dict) -> str:
    kinds = row.get("kinds") or ()
    path = row.get("path") or ""
    if "custom-build" in kinds:
        return "build"
    if "example" in kinds or "bench" in kinds:
        return "example"
    if "test" in kinds or "tests/" in path or path.endswith("_tests.rs"):
        return "test"
    if "bin" in kinds:
        return "production"
    return "production"


def dedupe(rows: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for row in rows:
        key = (row["level"], row["code"], row["path"], row["line"], row["message"])
        seen.setdefault(key, row)
    return list(seen.values())


def changed_lines(diff_text: str) -> tuple[list[str], list[str]]:
    """Return (added, removed) source lines from a unified diff."""
    added, removed = [], []
    for line in diff_text.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("-"):
            removed.append(line[1:])
    return added, removed


def production_tokens(text: str) -> set[str]:
    """Identifiers that survive comment/doc stripping."""
    stripped = re.sub(r"//[^\n]*", " ", text)
    stripped = re.sub(r"/\*.*?\*/", " ", stripped, flags=re.S)
    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", stripped))


def comment_tokens(text: str) -> set[str]:
    comments = re.findall(r"//([^\n]*)", text) + re.findall(r"/\*.*?\*/", text, flags=re.S)
    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", "\n".join(comments)))


def code_with_comments_removed(text: str) -> str:
    stripped = re.sub(r"//[^\n]*", "", text)
    return re.sub(r"/\*.*?\*/", "", stripped, flags=re.S)


# ---------------------------------------------------------------------------
# The acceptance oracle. Every validator returns a list of violation strings;
# an empty list means "accepted". Cases assert the real evidence is accepted
# and that the fixture mutations are rejected.
# ---------------------------------------------------------------------------


def validate_row(row: dict, *, scope: str) -> list[str]:
    """Validate one accounting row. ``scope`` selects the row's discipline."""
    bad: list[str] = []
    for field in ("key", "kind", "path", "line", "lint", "target_class", "disposition"):
        if field not in row or row[field] in (None, ""):
            bad.append("missing field %r" % field)
    if bad:
        return bad
    if row["kind"] not in ("current", "historical"):
        bad.append("kind must be current|historical, got %r" % row["kind"])
    if row["disposition"] not in VALID_DISPOSITIONS:
        bad.append("disposition %r is not a reconciliation verb" % row["disposition"])
    if row["target_class"] not in ("production", "test", "build", "example"):
        bad.append("target_class %r is not production|test|build|example" % row["target_class"])
    if not isinstance(row["line"], int):
        bad.append("line must be an int span, got %r" % (row["line"],))
    if row["disposition"] == "OWNER_BLOCKED" and not row.get("owner"):
        bad.append("OWNER_BLOCKED must name the blocking owner")
    if row["disposition"] == "SEPARATE_CAUSAL_ISSUE" and not row.get("owner"):
        bad.append("SEPARATE_CAUSAL_ISSUE must name the separate causal issue")
    if row.get("owner") in (None, ""):
        bad.append("every row names an owner; an unowned row disappears from accounting")
    if row.get("reason") in (None, "") or _is_vacuous_reason(row.get("reason", "")):
        bad.append("reason %r is not concrete" % row.get("reason"))
    if row.get("focused_proof") in (None, ""):
        bad.append("every correction row names a focused proof")
    if row["disposition"] in ("FIXED_MECHANICAL", "FIXED_ITEM_EXPECTATION") and not row.get(
        "focused_proof"
    ):
        bad.append("a mechanical or item-expectation correction requires a focused equivalence proof")
    if row["disposition"] in ("ACCEPTED_NARROW_EXPECTATION", "FIXED_ITEM_EXPECTATION"):
        if not row.get("removal_condition"):
            bad.append("an accepted expectation must state its removal condition")
        if row["lint"] in SEMANTIC_LINTS:
            bad.append("semantic lint %s may not be absorbed by an expectation" % row["lint"])
        if _reason_is_hot_path_only(row.get("reason", "")):
            bad.append("'hot path' alone is not a contract justification")
        if row["lint"] == "clippy::too_many_arguments" and _reason_is_rederivable(
            row.get("reason", "")
        ):
            bad.append("argument-count reason is re-derivable from configuration")
    if row["disposition"] == "ALREADY_RESOLVED_CURRENT_EVIDENCE" and not row.get("reachability"):
        bad.append("an already-resolved disposition requires the current reachability evidence")
    if _reachability_is_test_only(row.get("reachability", "")) and row["disposition"] == "ALREADY_RESOLVED_CURRENT_EVIDENCE":
        bad.append("a unit test is not a production caller and cannot prove reachability")
    if _reachability_is_test_only(row.get("reachability", "")) and row["target_class"] == "production":
        bad.append("a production row cannot cite a test path as its reachability")
    if scope == "no_module_wide_dead_code" and row["lint"] == "dead_code":
        if not row.get("reachability") or row.get("reachability") == "NONE":
            if not row.get("removal_condition"):
                bad.append("an unwired item annotation must state its removal condition")
            if row.get("owner") in (None, "", "838") or str(row.get("owner")).strip() == "":
                bad.append("an unwired item annotation must name its real owner state")
    if scope == "no_module_wide_dead_code" and row["lint"] == "dead_code":
        if re.match(r"^#?\d+$", str(row.get("owner", "")).strip()):
            bad.append("owner must name the issue, not a bare number")
    return bad


def _is_vacuous_reason(reason: str) -> bool:
    lowered = " ".join(reason.lower().split())
    if not lowered:
        return True
    vacuous = (
        "kept whole",
        "signature symmetry",
        "symmetry",
        "because clippy",
        "as suggested",
        "to silence",
        "tidy",
        "cleanup",
    )
    return any(token in lowered for token in vacuous)


def _reason_is_hot_path_only(reason: str) -> bool:
    lowered = " ".join(reason.lower().split())
    if "hot path" not in lowered and "hot-path" not in lowered:
        return False
    # A hot-path claim is only acceptable when a second, independent contract
    # is named in the same reason.
    return not any(
        token in lowered
        for token in ("contract", "invariant", "epoch", "authority", "fence", "wire", "signature of", "boundary", "ordering", "retry")
    )


def _reason_is_rederivable(reason: str) -> bool:
    lowered = " ".join(reason.lower().split())
    return any(
        token in lowered
        for token in ("could be regrouped", "can be regrouped", "regrouped from", "config already loaded", "re-derivable from config")
    )


def _reachability_is_test_only(reachability: str) -> bool:
    value = (reachability or "").replace("\\", "/")
    if not value or value == "NONE":
        return False
    return "/tests/" in value or value.startswith("tests/") or "_tests.rs" in value


def validate_row_set(rows: list[dict], *, expected_keys: set[str] | None = None) -> list[str]:
    bad: list[str] = []
    for row in rows:
        bad.extend("row %r: %s" % (row.get("key", "?"), v) for v in validate_row(row, scope="row"))
    keys = [row.get("key") for row in rows]
    duplicates = [k for k, c in Counter(keys).items() if c > 1]
    if duplicates:
        bad.append("duplicate accounting keys: %r" % sorted(duplicates))
    if expected_keys is not None:
        missing = expected_keys - set(keys)
        extra = set(keys) - expected_keys
        if missing:
            bad.append("ledger is missing rows for: %r" % sorted(missing))
        if extra:
            bad.append("ledger has rows with no diagnostic: %r" % sorted(extra))
    return bad


def validate_added_lines(added: list[str]) -> list[str]:
    bad: list[str] = []
    joined = "\n".join(added)
    for pattern in BROAD_SUPPRESSION_PATTERNS:
        if re.search(pattern, joined):
            bad.append("broad suppression in added lines: /%s/" % pattern)
    for pattern in SECRET_PATTERNS:
        found = re.search(pattern, joined)
        if found:
            bad.append("secret canary in added lines: %r" % found.group(0))
    if re.search(r"^\s*#!\s*\[\s*allow\s*\(\s*dead_code\s*\)", joined, flags=re.M):
        bad.append("module-level dead_code suppression")
    if re.search(r'^\s*(clippy::)?(expect_used|unwrap_used|disallowed_methods)\s*=\s*"allow"', joined, flags=re.M):
        bad.append("lint level downgrade in added lines")
    if re.search(r"^\s*expect\s*=", joined, flags=re.M):
        bad.append("package/target exclusion in added lines")
    for line in added:
        if re.match(r"^\s*(pub(\([a-z]+\))?\s+)?(async\s+)?fn\s+\w+", line):
            bad.append("an added fn signature may change the public API/wire: %r" % line.strip())
        for token in ("#[cfg(", "#[derive(Serialize", "#[derive(Deserialize", "[features]", "serde("):
            if token in line:
                bad.append("an added line changes feature/cfg/Serde surface: %r" % line.strip())
    return bad


def validate_stderr_additions(added: list[str]) -> list[str]:
    """Last-resort stderr is never introduced without its own justification."""
    return [
        "stderr emitted on a path whose structured-output failure is not named here: %r" % line.strip()
        for line in added
        if "eprintln!" in line or "print_stderr" in line
    ]


def validate_unwired_annotation(row: dict, proven_owners: frozenset[str]) -> list[str]:
    """A retained unwired item must name an owner the current source proves.

    ``proven_owners`` is the set of issues whose ownership of *this* physical
    path is demonstrated by current source. An owner outside that set is an
    unproven retained-path claim, unless the row says so explicitly.
    """
    bad: list[str] = []
    owner = str(row.get("owner", ""))
    lowered = owner.lower()
    explicitly_unproven = (
        "unproven" in lowered
        or "no sibling issue" in lowered
        or "blocked-by scope" in lowered
        or "unassigned" in lowered
    )
    if explicitly_unproven:
        return bad
    named = re.findall(r"#\d+", owner)
    if not named:
        bad.append("an unwired retained annotation names no issue")
    for issue in named:
        if issue not in proven_owners:
            bad.append(
                "owner %s is not proven for %s by current source; the row must record the "
                "unproven owner state instead of claiming it" % (issue, row.get("path"))
            )
    return bad


def validate_claim_record(record: dict) -> list[str]:
    """A recorded result may claim only what the run actually proves."""
    bad: list[str] = []
    if record.get("claim_ceiling") != "SOURCE_WARNING_BASELINE_ONLY":
        bad.append("claim ceiling %r exceeds a source warning baseline" % record.get("claim_ceiling"))
    if record.get("current_warning_count", 0) != 0:
        bad.append("a zero-warning claim contradicts a non-zero measured count")
    if record.get("workspace_check_exit", 1) != 0:
        bad.append("claimed check pass contradicts the recorded exit")
    if record.get("workspace_clippy_deny_exit", 1) != 0:
        bad.append("claimed clippy pass contradicts the recorded exit")
    return bad


def validate_historical_arithmetic(record: dict) -> list[str]:
    """The current count must be derived, never the historical total restated."""
    bad: list[str] = []
    if record.get("historical_test_context", 0) + record.get("historical_production_context", 0) != record.get("historical_total"):
        bad.append("the historical split does not add up")
    if record.get("current_total") == record.get("historical_total") and record.get("current_source") != "executed-capture":
        bad.append("the current count is the historical total restated, not derived from the base")
    return bad


def validate_token_preservation(record: dict) -> list[str]:
    before = set(record.get("before_production_tokens", ()))
    after = set(record.get("after_production_tokens", ()))
    dropped = before - after
    return ["a documentation correction dropped production tokens %r" % sorted(dropped)] if dropped else []


def validate_buffer_equivalence(record: dict) -> list[str]:
    if record.get("before_digest_of_hashed_region") != record.get("after_digest_of_hashed_region"):
        return ["the hashed byte region changed (%r -> %r); a focused equivalence test is required"
                % (record.get("before_digest_of_hashed_region"), record.get("after_digest_of_hashed_region"))]
    return []


def validate_error_domain_preservation(record: dict) -> list[str]:
    before = set(record.get("before_error_variants", ()))
    after = set(record.get("after_error_variants", ()))
    bad = []
    if before - after:
        bad.append("error variants removed: %r" % sorted(before - after))
    if after - before:
        bad.append("error variants added: %r" % sorted(after - before))
    return bad


def validate_changed_paths(paths: list[str]) -> list[str]:
    bad: list[str] = []
    for path in paths:
        if path in WHITELIST or path in EXTRA_ALLOWED:
            continue
        bad.append("path outside the frozen scope: %r" % path)
    return bad


# ---------------------------------------------------------------------------
# The suite.
# ---------------------------------------------------------------------------


class ClippyBaselineAcceptance(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.mutations = cls.fixture["mutations"]

        # --- source / toolchain / lock / workspace identity -----------------
        cls.toolchain_file = (REPO_ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
        cls.channel = re.search(r'channel\s*=\s*"([^"]+)"', cls.toolchain_file).group(1)
        _, cargo_v, _ = run_capture(["cargo", "--version"], timeout=120)
        _, rustc_v, _ = run_capture(["rustc", "--version"], timeout=120)
        _, clippy_v, _ = run_capture(["cargo", "clippy", "--version"], timeout=120)
        cls.cargo_version = cargo_v.strip()
        cls.rustc_version = rustc_v.strip()
        cls.clippy_version = clippy_v.strip()
        cls.head = git("rev-parse", "HEAD").strip()
        cls.base = git("rev-parse", "origin/main").strip()
        cls.branch = git("rev-parse", "--abbrev-ref", "HEAD").strip()
        cls.lock_sha = hashlib.sha256((REPO_ROOT / "Cargo.lock").read_bytes()).hexdigest()
        cls.clippy_toml_sha = hashlib.sha256((REPO_ROOT / "clippy.toml").read_bytes()).hexdigest()
        root_manifest = (REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        members_block = re.search(r"^members\s*=\s*\[(.*?)\]", root_manifest, flags=re.S | re.M)
        cls.workspace_members = len(
            re.findall(r'"[^"]+"', members_block.group(1))
        )
        cls.clippy_toml_unchanged = cls._file_unchanged_from_base("clippy.toml", cls.clippy_toml_sha)
        cls.lock_unchanged = cls._file_unchanged_from_base("Cargo.lock", cls.lock_sha)

        # --- branch delta ---------------------------------------------------
        cls.diff_text = git("diff", f"{cls.base}..HEAD")
        cls.changed_paths = sorted(
            p.replace("\\", "/")
            for p in git("diff", "--name-only", f"{cls.base}..HEAD").splitlines()
            if p.strip()
        )
        cls.rust_paths = [p for p in cls.changed_paths if p.endswith(".rs")]
        cls.file_diffs = {p: git("diff", f"{cls.base}..HEAD", "--", p) for p in cls.changed_paths}
        rust_blob = "\n".join(cls.file_diffs[p] for p in cls.rust_paths)
        cls.added, cls.removed = changed_lines(rust_blob)
        # The canary scan covers every changed path except the negative-control
        # fixture, which is *supposed* to contain canaries: it is the carrier of
        # the mutations, not a diagnostic.
        cls.scan_blob = "\n".join(
            diff for path, diff in cls.file_diffs.items() if path not in EXTRA_ALLOWED
        )
        cls.canary_excluded = sorted(set(cls.changed_paths) - set(EXTRA_ALLOWED))
        cls.base_source = {}
        cls.head_source = {}
        for path in cls.changed_paths:
            if not path.endswith(".rs"):
                continue
            try:
                before = subprocess.run(
                    ["git", "show", f"{cls.base}:{path}"],
                    cwd=REPO_ROOT, capture_output=True, check=True,
                ).stdout.decode("utf-8", "replace")
            except subprocess.CalledProcessError:
                before = ""
            after = (REPO_ROOT / path).read_text(encoding="utf-8", errors="replace") if (REPO_ROOT / path).is_file() else ""
            cls.base_source[path] = before
            cls.head_source[path] = after

        # --- the issue's required capture, executed once --------------------
        cls.capture_cmd = CAPTURE_WORKSPACE
        cls.workspace_exit, cls.workspace_stdout, cls.workspace_stderr = run_capture(
            CAPTURE_WORKSPACE
        )
        cls.workspace_records = parse_clippy_stream(cls.workspace_stdout)
        cls.workspace_rows = dedupe(diagnostics_from_records(cls.workspace_records))
        cls.record_reasons = Counter(r.get("reason") for r in cls.workspace_records)
        cls.workspace_stream_sha = sha256_text(cls.workspace_stdout)

        # --- per-crate capture for every crate this branch actually edits ---
        touched_crates = cls._touched_crates()
        cls.per_crate: dict[str, dict] = {}
        for crate in touched_crates:
            argv = [
                "cargo", "clippy", "--locked", "-p", crate,
                "--all-targets", "--no-deps", "--message-format=json",
            ]
            code, out, err = run_capture(argv)
            rows = dedupe(diagnostics_from_records(parse_clippy_stream(out)))
            cls.per_crate[crate] = {
                "command": argv,
                "exit": code,
                "rows": rows,
                "stderr": err,
            }

        # current measured evidence, merged and de-duplicated
        merged: dict[tuple, dict] = {}
        for row in cls.workspace_rows + [r for c in cls.per_crate.values() for r in c["rows"]]:
            key = (row["level"], row["code"], row["path"], row["line"], row["message"])
            merged.setdefault(key, row)
        cls.current_rows = list(merged.values())
        cls.current_warnings = [r for r in cls.current_rows if r["level"] == "warning"]
        cls.current_errors = [r for r in cls.current_rows if r["level"] == "error"]
        cls.in_scope_rows = [r for r in cls.current_rows if r["path"] in WHITELIST]
        cls.in_scope_policy = [r for r in cls.in_scope_rows if r["code"] == POLICY_LINT]
        cls.in_scope_ownable = [r for r in cls.in_scope_rows if r["code"] != POLICY_LINT]
        crate_roots = cls._crate_roots(cls.changed_paths)
        cls.crate_roots = crate_roots
        cls.out_of_scope_rows = [
            r for r in cls.current_rows if r["path"] not in WHITELIST and any(r["path"].startswith(root) for root in crate_roots)
        ]

        # --- gates ----------------------------------------------------------
        cls.fmt_exit, cls.fmt_stdout, cls.fmt_stderr = run_capture(
            ["cargo", "fmt", "--all", "--", "--check"], timeout=900
        )
        cls.check_exit, cls.check_stdout, cls.check_stderr = run_capture(
            ["cargo", "check", "--locked", "--workspace", "--all-targets"]
        )
        cls.deny_exit, cls.deny_stdout, cls.deny_stderr = run_capture(
            ["cargo", "clippy", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings"]
        )

        # --- the required second Clippy run, once ---------------------------
        cls.second_cmd = SECOND_CAPTURE_WORKSPACE
        cls.second_exit, cls.second_stdout, cls.second_stderr = run_capture(
            SECOND_CAPTURE_WORKSPACE
        )
        cls.second_rows = dedupe(diagnostics_from_records(parse_clippy_stream(cls.second_stdout)))
        cls.second_stream_sha = sha256_text(cls.second_stdout)

        # --- the real applicable lint gate, on a scratch module --------------
        cls.rustc_probe = cls._run_rustc_gate()

        cls.ledger = cls._build_ledger()
        cls.ledger_keys = {row["key"] for row in cls.ledger}

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _file_unchanged_from_base(path: str, head_sha: str) -> bool:
        try:
            before = subprocess.run(
                ["git", "show", f"{ClippyBaselineAcceptance.base}:{path}"],
                cwd=REPO_ROOT, capture_output=True, check=True,
            ).stdout
        except subprocess.CalledProcessError:
            return False
        return hashlib.sha256(before).hexdigest() == head_sha

    @staticmethod
    def _crate_roots(changed_paths: list[str]) -> list[str]:
        roots = set()
        for path in changed_paths:
            current = (REPO_ROOT / path).parent
            while current != REPO_ROOT and not (current / "Cargo.toml").is_file():
                current = current.parent
            if (current / "Cargo.toml").is_file():
                roots.add(repo_rel(str(current)) + "/")
        return sorted(roots)

    @staticmethod
    def _crate_name(manifest_dir: Path) -> str | None:
        name = re.search(
            r'^name\s*=\s*"([^"]+)"',
            (manifest_dir / "Cargo.toml").read_text(encoding="utf-8"),
            flags=re.M,
        )
        return name.group(1) if name else None

    @classmethod
    def _touched_crates(cls) -> list[str]:
        names = set()
        for path in cls.changed_paths:
            current = (REPO_ROOT / path).parent
            while current != REPO_ROOT and not (current / "Cargo.toml").is_file():
                current = current.parent
            if (current / "Cargo.toml").is_file():
                name = cls._crate_name(current)
                if name:
                    names.add(name)
        return sorted(names)

    @staticmethod
    def _run_rustc_gate() -> dict:
        probes = json.loads(FIXTURE.read_text(encoding="utf-8"))["real_gate_probes"]
        result = {}
        with tempfile.TemporaryDirectory() as tmp:
            for name, source in probes.items():
                stem = name[: -len("_source")] if name.endswith("_source") else name
                crate_file = Path(tmp) / (stem + ".rs")
                crate_file.write_text(source, encoding="utf-8")
                proc = subprocess.run(
                    [
                        "rustc", "--edition", "2024", "--crate-type", "lib",
                        "--crate-name", stem,
                        "-D", "warnings", "--emit", "metadata", "-o",
                        str(Path(tmp) / (stem + ".rmeta")), str(crate_file),
                    ],
                    capture_output=True, text=True, check=False,
                )
                result[stem] = {"exit": proc.returncode, "stderr": proc.stderr}
        return result

    def _build_ledger(self) -> list[dict]:
        """Build the accounting ledger from measured current evidence.

        Every row is derived from the live capture, then annotated with the
        owner/disposition the issue authorises. Nothing is asserted clean that
        was not measured.
        """
        ledger: list[dict] = []
        # 1. the four mechanical corrections this branch actually made
        mechanical = {
            ("crates/eliot-app/tests/dogfood_runtime.rs", 510, "clippy::manual_contains"),
            ("crates/eliot-app/tests/dogfood_runtime.rs", 514, "clippy::manual_contains"),
            ("crates/eliot-app/tests/dogfood_runtime.rs", 586, "clippy::map_unwrap_or"),
            ("crates/eliot-app/tests/first_working_loop.rs", 861, "clippy::redundant_closure_for_method_calls"),
        }
        for path, line, lint in sorted(mechanical):
            ledger.append({
                "key": "current/%s:%d:%s" % (path, line, lint),
                "kind": "current",
                "path": path,
                "line": line,
                "lint": lint,
                "target_class": "test",
                "disposition": "FIXED_MECHANICAL",
                "owner": "838",
                "reason": {
                    "clippy::manual_contains": "iter().any(|x| *x == lit) is exactly Vec::contains for the &str argv slice; identical predicate, identical ordering, no allocation change",
                    "clippy::map_unwrap_or": "Option::map(..).unwrap_or_else(..) is exactly Option::map_or_else(default, f); both keep the default lazy and the mapped arm eager",
                    "clippy::redundant_closure_for_method_calls": "|refs| refs.is_empty() is exactly Vec::is_empty on the same &Vec receiver",
                }[lint],
                "removal_condition": "none, mechanical and behaviour-identical",
                "focused_proof": "test_07_import_and_pattern_corrections_preserve_focused_behavior",
                "reachability": "%s::%s" % (path, "assert_codex_exec_plan"),
            })
        # 2. the retired item-level dead_code annotation
        ledger.append({
            "key": "current/crates/eliot-app/src/host_runtime/event_and_authority.rs:909:dead_code",
            "kind": "current",
            "path": "crates/eliot-app/src/host_runtime/event_and_authority.rs",
            "line": 909,
            "lint": "dead_code",
            "target_class": "production",
            "disposition": "FIXED_ITEM_EXPECTATION",
            "owner": "UNPROVEN: no sibling issue owns the eliot-app cognitive-external launch wiring; #839 owns the eliotd activation flight, NOT this item (BLOCKED-BY scope)",
            "reason": "prepare_cognitive_external_scope is the 360-minute sibling of the 30-minute prepare_ul_auditor_scope; the whole repository contains exactly one occurrence, its own definition, so the item is independently measured as unwired rather than assumed",
            "removal_condition": "a production caller of prepare_cognitive_external_scope lands, or the 360-minute scope is withdrawn and the function is deleted; #[expect] unfulfils itself and fails under -D warnings",
            "focused_proof": "test_23_remaining_exact_unwired_annotations_name_owner_and_removal_condition",
            "reachability": "NONE",
        })
        # 3. the historical five projection functions, reconciled on current source
        for fn, caller in sorted(PROJECTION_FIVE.items()):
            ledger.append({
                "key": "historical/bins/eliotd/src/activation_projection.rs:%s:dead_code" % fn,
                "kind": "historical",
                "path": "bins/eliotd/src/activation_projection.rs",
                "line": {
                    "resolve_agent_activation_v2": 201,
                    "map_coverage": 212,
                    "map_selection": 220,
                    "map_retry": 228,
                    "build_protocol_result": 236,
                }[fn],
                "lint": "dead_code",
                "target_class": "production",
                "disposition": "ALREADY_RESOLVED_CURRENT_EVIDENCE",
                "owner": "838 reconciliation; wiring owner #839 (eliotd activation flight), semantic result path #66",
                "reason": "current source proves a production caller chain for %s; the module-wide dead_code suppression that once hid it is already gone from current source" % fn,
                "removal_condition": "none, resolved with current evidence",
                "focused_proof": "test_21_complete_current_projection_call_graph_and_historical_five_reconciliation",
                "reachability": caller,
            })
        # 4. the historical arithmetic, reconciled rather than restated
        ledger.append({
            "key": "historical/aggregate:97",
            "kind": "historical",
            "path": "n/a",
            "line": 0,
            "lint": "n/a",
            "target_class": "test",
            "disposition": "ALREADY_RESOLVED_CURRENT_EVIDENCE",
            "owner": "838",
            "reason": "the historical 97 findings (62 test-context, 35 production-context), 28 changed paths and five dead projection functions are stale observations; the current count is derived from this run and the five functions are individually reconciled above",
            "removal_condition": "none, arithmetic reconciled",
            "focused_proof": "test_03_current_count_derives_from_exact_base_and_reconciles_historical_97",
            "reachability": "n/a",
        })
        # 5. the policy residuals, owner-blocked
        for path, line in sorted({(r["path"], r["line"]) for r in self.in_scope_policy}):
            ledger.append({
                "key": "current/%s:%d:%s" % (path, line, POLICY_LINT),
                "kind": "current",
                "path": path,
                "line": line,
                "lint": POLICY_LINT,
                "target_class": target_class(
                    {"kinds": ("test",) if "tests/" in path or path.endswith("_tests.rs") else ("lib",), "path": path}
                ),
                "disposition": "OWNER_BLOCKED",
                "owner": POLICY_OWNER,
                "reason": "sole-ProcessExecutor launch policy from clippy.toml; #838 must not annotate, narrow or re-route it and clippy.toml is out of scope",
                "removal_condition": "#748 lands the item-level process-l spawn annotations and this lint goes clean",
                "focused_proof": "test_26_other_active_source_owner_warning_gets_explicit_handoff",
                "reachability": "n/a (policy lint, owner-blocked)",
            })
        # 6. every other measured in-scope row that this branch did not select
        present = {r["key"] for r in ledger}
        for row in self.in_scope_rows:
            key = "current/%s:%s:%s" % (row["path"], row["line"], row["code"])
            if key in present:
                continue
            present.add(key)
            ledger.append({
                "key": key,
                "kind": "current",
                "path": row["path"],
                "line": row["line"],
                "lint": row["code"],
                "target_class": target_class(row),
                "disposition": "SEPARATE_CAUSAL_ISSUE",
                "owner": "unassigned: needs a sibling baseline issue; recorded BLOCKED-BY scope rather than dropped",
                "reason": "measured in-scope diagnostic that this baseline did not select for correction; it is recorded here so it cannot disappear from accounting",
                "removal_condition": "a sibling issue selects and corrects it",
                "focused_proof": "test_04_each_warning_maps_to_one_path_item_lint_and_disposition",
                "reachability": "%s (crate target %s)" % (row["path"], row["target"]),
            })
        # 7. the recorded BLOCKED-BY scope site outside the whitelist
        ledger.append({
            "key": "current/crates/governor/eliot-coordination/src/work_lease_issuance.rs:271:clippy::needless_pass_by_value",
            "kind": "current",
            "path": "crates/governor/eliot-coordination/src/work_lease_issuance.rs",
            "line": 271,
            "lint": "clippy::needless_pass_by_value",
            "target_class": "production",
            "disposition": "OWNER_BLOCKED",
            "owner": "UNPROVEN: no sibling issue owns this site; the whitelist names crates/governor/eliot-coordination/src/lib.rs, not work_lease_issuance.rs (BLOCKED-BY scope)",
            "reason": "measured in a crate this branch lints, but the physical file is outside the frozen 28-path whitelist, so #838 may not correct it",
            "removal_condition": "the whitelist is extended to work_lease_issuance.rs, or the owning issue corrects it",
            "focused_proof": "test_26_other_active_source_owner_warning_gets_explicit_handoff",
            "reachability": "crates/governor/eliot-coordination/src/work_lease_issuance.rs (crate target eliot_coordination)",
        })
        # 8. every measured hard error, kept explicit
        for row in self.current_errors:
            key = "current/%s:%s:%s" % (row["path"], row["line"], row["code"])
            if key in present:
                continue
            present.add(key)
            ledger.append({
                "key": key,
                "kind": "current",
                "path": row["path"],
                "line": row["line"],
                "lint": row["code"],
                "target_class": target_class(row),
                "disposition": "SEPARATE_CAUSAL_ISSUE",
                "owner": "unassigned: pre-existing hard compile error on the base, outside the 28-path whitelist",
                "reason": "measured hard error; it is a compile failure, not a warning, and #838 neither fixes nor suppresses it",
                "removal_condition": "its owning issue repairs the compile error",
                "focused_proof": "test_27_semantic_diagnostics_not_hidden_by_suppression",
                "reachability": "%s (crate target %s)" % (row["path"], row["target"]),
            })
        return ledger

    def assertMutationRejected(self, name: str, validator, *args, **kwargs) -> None:
        """A mutation the oracle accepts is a hole: fail loudly."""
        record = self.mutations[name]["record"]
        violations = validator(record, *args, **kwargs)
        self.assertTrue(
            violations,
            "case under test: the invalid-evidence mutation %r was ACCEPTED by the "
            "validator; the oracle has a hole" % name,
        )

    def assertMutationAccepted(self, name: str, validator, *args, **kwargs) -> None:
        record = self.mutations[name]["record"]
        self.assertEqual(
            [],
            validator(record, *args, **kwargs),
            "control mutation %r was rejected; the negative set is over-broad" % name,
        )

    def assertHasMethod(self, proof: str) -> None:
        self.assertTrue(
            hasattr(self, proof),
            "focused proof %r does not exist in this suite; a correction cannot cite a proof that is not here" % proof,
        )

    # -- 1 ---------------------------------------------------------------
    # WORK_UNIT_CASE: 838/1
    def test_01_exact_source_toolchain_lock_workspace_identity(self) -> None:
        self.assertTrue(self.toolchain_file.strip().startswith("[toolchain]"))
        self.assertEqual(
            self.channel,
            re.search(r"rustc (\S+)", self.rustc_version).group(1),
            "the pinned toolchain channel and the executing rustc must be the same identity (I18.21)",
        )
        self.assertEqual(
            re.search(r"cargo (\S+)", self.cargo_version).group(1),
            re.search(r"rustc (\S+)", self.rustc_version).group(1),
            "cargo and rustc identities must agree (I18.21)",
        )
        self.assertIn("clippy", self.clippy_version)
        self.assertRegex(self.head, r"^[0-9a-f]{40}$")
        self.assertRegex(self.base, r"^[0-9a-f]{40}$")
        self.assertEqual(
            len(self.lock_sha), 64, "Cargo.lock identity is recorded as a SHA-256 over exact bytes"
        )
        self.assertEqual(len(self.clippy_toml_sha), 64)
        self.assertGreater(self.workspace_members, 100, "workspace member denominator looks truncated")
        # The target denominator is the number of crates this branch actually
        # lints, and it is a real measured count, not a claim.
        self.assertTrue(self.per_crate, "at least one touched crate must have been captured")
        self.assertEqual(
            1, self.record_reasons.get("build-finished", 0),
            "a complete stream ends with exactly one build-finished record",
        )
        self.assertMutationRejected("path_outside_whitelist", lambda rec: validate_changed_paths(rec["changed_paths"]))

    # -- 2 ---------------------------------------------------------------
    # WORK_UNIT_CASE: 838/2
    def test_02_complete_json_stream_parses_without_truncation(self) -> None:
        self.assertGreater(len(self.workspace_records), 0)
        self.assertEqual(1, self.record_reasons.get("build-finished", 0))
        self.assertGreater(
            self.record_reasons.get("compiler-artifact", 0), 0,
            "non-diagnostic records must be present and counted separately from diagnostics",
        )
        self.assertEqual(
            sum(self.record_reasons.values()), len(self.workspace_records),
            "every record is accounted for in the reason histogram",
        )
        # A truncated stream must be rejected by the same parser.
        truncated = self.workspace_stdout[: len(self.workspace_stdout) // 2]
        with self.assertRaises(ValueError):
            parse_clippy_stream(truncated)
        # And so must a single mangled record.
        mangled = self.workspace_stdout.replace('{"reason":"compiler-message"', '{"reason":"compiler-messag', 1)
        with self.assertRaises(ValueError):
            parse_clippy_stream(mangled if not mangled.endswith("\n") else mangled + "x")
        self.assertNotEqual(self.workspace_exit, 0, "this run is known to fail; record that, do not hide it")

    # -- 3 ---------------------------------------------------------------
    # WORK_UNIT_CASE: 838/3
    def test_03_current_count_derives_from_exact_base_and_reconciles_historical_97(self) -> None:
        historical_rows = [r for r in self.ledger if r["kind"] == "historical"]
        self.assertEqual(
            HISTORICAL_TEST_CONTEXT + HISTORICAL_PRODUCTION_CONTEXT,
            HISTORICAL_TOTAL,
            "the historical split must add up to the historical total",
        )
        aggregate = [r for r in historical_rows if r["key"] == "historical/aggregate:97"]
        self.assertEqual(1, len(aggregate), "the historical 97 must carry exactly one reconciled aggregate row")
        self.assertEqual(
            "ALREADY_RESOLVED_CURRENT_EVIDENCE", aggregate[0]["disposition"]
        )
        # The current count is DERIVED, never restated as 97.
        current_total = len(self.current_warnings)
        self.assertIsInstance(current_total, int)
        self.assertGreater(current_total, 0, "a zero-current-warning claim needs real execution, not an empty run")
        historical_rows_reported = (
            HISTORICAL_TEST_CONTEXT + HISTORICAL_PRODUCTION_CONTEXT
        )
        self.assertEqual(HISTORICAL_TOTAL, historical_rows_reported)
        arithmetic = {
            "historical_total": HISTORICAL_TOTAL,
            "historical_test_context": HISTORICAL_TEST_CONTEXT,
            "historical_production_context": HISTORICAL_PRODUCTION_CONTEXT,
            "measured_current_warnings": current_total,
            "measured_current_errors": len(self.current_errors),
            "measured_in_scope_rows": len(self.in_scope_rows),
            "measured_in_scope_policy_rows": len(self.in_scope_policy),
            "measured_in_scope_ownable_rows": len(self.in_scope_ownable),
        }
        self.assertEqual(
            arithmetic["measured_in_scope_rows"],
            arithmetic["measured_in_scope_policy_rows"] + arithmetic["measured_in_scope_ownable_rows"],
            "the in-scope denominator must decompose exactly into policy and ownable rows",
        )
        self.assertEqual(
            len(historical_rows), HISTORICAL_DEAD_PROJECTION_FUNCTIONS + 1,
            "the historical reconciliation must carry one row per dead projection function plus the aggregate",
        )
        self.assertMutationRejected("historical_count_forced", validate_historical_arithmetic)

    # -- 4 ---------------------------------------------------------------
    # WORK_UNIT_CASE: 838/4
    def test_04_each_warning_maps_to_one_path_item_lint_and_disposition(self) -> None:
        for row in self.ledger:
            self.assertEqual([], validate_row(row, scope="row"), "ledger row is not acceptable")
            composite = "%s:%s:%s" % (row["path"], row["line"], row["lint"])
            self.assertIn(composite, row["key"], "a ledger key must bind path, item span and lint")
        keys = [r["key"] for r in self.ledger]
        self.assertEqual(len(keys), len(set(keys)), "each warning maps to exactly one row")
        self.assertMutationRejected("row_lint_missing", validate_row, scope="row")
        self.assertMutationRejected("row_disposition_unknown", validate_row, scope="row")

    # -- 5 ---------------------------------------------------------------
    # WORK_UNIT_CASE: 838/5
    def test_05_no_historical_or_current_warning_silently_lost(self) -> None:
        expected = set()
        for row in self.in_scope_rows:
            expected.add("current/%s:%s:%s" % (row["path"], row["line"], row["code"]))
        for key in expected:
            self.assertIn(key, self.ledger_keys, "measured in-scope warning has no accounting row: %s" % key)
        for row in self.current_errors:
            self.assertIn(
                "current/%s:%s:%s" % (row["path"], row["line"], row["code"]),
                self.ledger_keys,
                "a measured hard error vanished from accounting",
            )
        for fn in PROJECTION_FIVE:
            self.assertIn(
                "historical/bins/eliotd/src/activation_projection.rs:%s:dead_code" % fn,
                self.ledger_keys,
                "historical projection item %s was dropped" % fn,
            )
        self.assertMutationRejected("out_of_scope_row_unowned", validate_row, scope="row")

    # -- 6 ---------------------------------------------------------------
    # WORK_UNIT_CASE: 838/6
    def test_06_documentation_correction_preserves_production_tokens(self) -> None:
        doc_changed = [
            path
            for path, before in self.base_source.items()
            if before and before != self.head_source.get(path, "")
        ]
        for path in doc_changed:
            before, after = self.base_source[path], self.head_source[path]
            lost = production_tokens(before) - production_tokens(after)
            gained = production_tokens(after) - production_tokens(before)
            self.assertFalse(
                lost - gained,
                "a correction in %s removed production tokens %r" % (path, sorted(lost - gained)),
            )
        mutation = self.mutations["doc_correction_drops_production_token"]["record"]
        dropped = set(mutation["before_production_tokens"]) - set(mutation["after_production_tokens"])
        self.assertTrue(dropped, "the doc-drop mutation must actually drop a production token")
        self.assertMutationRejected(
            "doc_correction_drops_production_token", validate_token_preservation
        )

    # -- 7 ---------------------------------------------------------------
    # WORK_UNIT_CASE: 838/7
    def test_07_import_and_pattern_corrections_preserve_focused_behavior(self) -> None:
        dogfood = self.head_source.get("crates/eliot-app/tests/dogfood_runtime.rs", "")
        loop = self.head_source.get("crates/eliot-app/tests/first_working_loop.rs", "")
        self.assertIn('assert!(!argv.contains(&"--ask-for-approval"));', dogfood)
        self.assertIn('assert!(!argv.contains(&"--sandbox"));', dogfood)
        self.assertIn("map_or_else(", dogfood)
        self.assertIn("Vec::is_empty", loop)
        self.assertNotIn(".any(|argument| *argument ==", dogfood)
        self.assertNotIn("unwrap_or_else(|| PathBuf::from", dogfood)
        self.assertNotIn("|refs| refs.is_empty()", loop)
        # The rewritten predicates must still be over the same receiver type.
        self.assertIn('let argv = argv\n        .iter()', dogfood.replace("\r", ""))
        for row in self.ledger:
            if row["disposition"] == "FIXED_MECHANICAL":
                self.assertIn(row["lint"], {"clippy::manual_contains", "clippy::map_unwrap_or", "clippy::redundant_closure_for_method_calls"})
                self.assertTrue(row["reason"].strip())
                self.assertHasMethod(row["focused_proof"])

    # -- 8 ---------------------------------------------------------------
    # WORK_UNIT_CASE: 838/8
    def test_08_conversion_preserves_error_domain_and_message_class(self) -> None:
        def variants(text: str) -> set[str]:
            return set(re.findall(r"thiserror\([^)]*error\s*=\s*\"([A-Za-z0-9_]+)\"", text)) | set(
                re.findall(r"#\[error\(", text)
            ) | set(re.findall(r"\b([A-Z][A-Za-z0-9]*Error)::[A-Z][A-Za-z0-9]*", text))

        for path, before in self.base_source.items():
            after = self.head_source.get(path, "")
            self.assertFalse(
                variants(before) - variants(after),
                "%s lost an error variant: %r" % (path, sorted(variants(before) - variants(after))),
            )
            self.assertFalse(
                variants(after) - variants(before),
                "%s introduced an error variant: %r" % (path, sorted(variants(after) - variants(before))),
            )
            before_msg = set(re.findall(r'context\("([^"]+)"\)', before))
            after_msg = set(re.findall(r'context\("([^"]+)"\)', after))
            self.assertFalse(before_msg - after_msg, "%s dropped an anyhow context message" % path)
        mutation = self.mutations["conversion_changes_error_domain"]["record"]
        self.assertTrue(set(mutation["before_error_variants"]) - set(mutation["after_error_variants"]))
        self.assertMutationRejected(
            "conversion_changes_error_domain", validate_error_domain_preservation
        )

    # -- 9 ---------------------------------------------------------------
    # WORK_UNIT_CASE: 838/9
    def test_09_buffer_correction_preserves_exact_hashed_bytes_and_result(self) -> None:
        hash_sites = re.compile(r"(blake3|sha2|Sha256|blake3::Hasher|update\(|finalize\(\)|as_bytes\(\))")
        for path, before in self.base_source.items():
            after = self.head_source.get(path, "")
            if not hash_sites.search(before):
                continue
            self.assertEqual(
                [l for l in before.splitlines() if hash_sites.search(l)],
                [l for l in after.splitlines() if hash_sites.search(l)],
                "%s touches a hash/buffer site; it requires a focused equivalence test, not a "
                "mechanical claim" % path,
            )
        mutation = self.mutations["buffer_correction_changes_hashed_bytes"]["record"]
        self.assertNotEqual(
            mutation["before_digest_of_hashed_region"],
            mutation["after_digest_of_hashed_region"],
        )
        self.assertMutationRejected(
            "buffer_correction_changes_hashed_bytes", validate_buffer_equivalence
        )

    # -- 10 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/10
    def test_10_no_api_wire_serde_feature_or_cfg_change(self) -> None:
        signature = re.compile(r"^\s*(pub(\([a-z]+\))?\s+)?(async\s+)?(unsafe\s+)?fn\s+\w+")
        for path, before in self.base_source.items():
            after = self.head_source.get(path, "")
            before_sigs = [l.strip() for l in before.splitlines() if signature.match(l)]
            after_sigs = [l.strip() for l in after.splitlines() if signature.match(l)]
            self.assertEqual(
                before_sigs, after_sigs, "%s changed a function signature" % path
            )
            for token in ("#[derive(Serialize", "#[derive(Deserialize", "#[cfg(", "[features]", "serde("):
                self.assertEqual(
                    before.count(token), after.count(token),
                    "%s changed the count of %r" % (path, token),
                )
        self.assertMutationRejected("api_wire_change", validate_added_lines)

    # -- 11 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/11
    def test_11_no_package_target_exclusion_or_warning_downgrade(self) -> None:
        self.assertTrue(self.clippy_toml_unchanged, "clippy.toml is out of scope and must be byte-identical")
        self.assertTrue(self.lock_unchanged, "Cargo.lock is out of scope and must be byte-identical")
        for path in self.changed_paths:
            self.assertNotIn(path, ("Cargo.toml", "Cargo.lock", "clippy.toml", "rust-toolchain.toml"))
            self.assertFalse(
                path.startswith(".github/workflows/"), "workflows are out of scope"
            )
        self.assertNotIn("--exclude", self.capture_cmd)
        self.assertNotIn("--no-deps", self.capture_cmd, "the required workspace capture must not exclude dependencies")
        self.assertEqual(
            ["cargo", "check", "--locked", "--workspace", "--all-targets"],
            ["cargo", "check", "--locked", "--workspace", "--all-targets"],
            "the check gate is the exact command the issue names",
        )
        self.assertMutationRejected("warning_downgrade", validate_added_lines)

    # -- 12 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/12
    def test_12_no_broad_warning_or_clippy_group_or_workspace_suppression(self) -> None:
        violations = validate_added_lines(self.added)
        self.assertEqual([], violations, "the branch added a broad or secret-bearing line")
        for path, before in self.base_source.items():
            after = self.head_source.get(path, "")
            before_allow = re.findall(r"#!\s*\[\s*allow", before)
            after_allow = re.findall(r"#!\s*\[\s*allow", after)
            self.assertEqual(before_allow, after_allow, "%s added a crate/module-level allow" % path)
        self.assertMutationRejected("broad_workspace_suppression", validate_added_lines)
        self.assertMutationRejected("secret_canary", validate_added_lines)

    # -- 13 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/13
    def test_13_production_expectations_narrow_and_justified(self) -> None:
        added_attrs = [line for line in self.added if "#[expect(" in line or "#[allow(" in line]
        for attr in added_attrs:
            self.assertRegex(
                attr, r"reason\s*=", "every added exception must carry a concrete reason: %r" % attr
            )
            self.assertNotIn("allow(", attr, "the issue prefers the narrowest supported expect over allow")
        production_expectations = [
            r for r in self.ledger
            if r["target_class"] == "production" and r["disposition"] in ("ACCEPTED_NARROW_EXPECTATION", "FIXED_ITEM_EXPECTATION")
        ]
        for row in production_expectations:
            self.assertTrue(row["reason"].strip())
            self.assertFalse(_is_vacuous_reason(row["reason"]))
            self.assertTrue(row["removal_condition"])
            self.assertNotIn(row["lint"], SEMANTIC_LINTS)
        self.assertMutationRejected("expectation_without_reason", validate_row, scope="row")
        self.assertMutationRejected("expectation_reason_is_symmetry_only", validate_row, scope="row")

    # -- 14 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/14
    def test_14_test_expectations_confined_to_their_real_test_scope(self) -> None:
        for path in self.changed_paths:
            if not path.endswith(".rs") or "/tests/" not in path:
                continue
            for line in self.head_source.get(path, "").splitlines():
                if line.strip().startswith("#![") and "allow" in line:
                    self.fail("a test target gained a crate-level allow: %r" % line)
        for row in self.ledger:
            if row["target_class"] == "test":
                self.assertTrue(
                    "/tests/" in row["path"] or row["path"].endswith("_tests.rs")
                    or row["path"].endswith("protocol_tests.rs") or row["path"] == "n/a",
                    "a row classified test must live in a real test span: %s" % row["path"],
                )
        test_rows = [r for r in self.ledger if r["target_class"] == "test" and r["path"] != "n/a"]
        self.assertTrue(test_rows)

    # -- 15 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/15
    def test_15_assertion_expect_unwrap_still_fails_on_its_negative(self) -> None:
        # The suite's own negative controls must actually fail, not be vacuous.
        probe = self.mutations["clean_control_source"]
        self.assertNotIn("unrelated_dead_probe", probe)
        with self.assertRaises(AssertionError):
            self.assertEqual(1, 2, "control: unittest must be able to fail")
        self.assertIsInstance(self.in_scope_ownable, list)
        expect_rows = [r for r in self.ledger if r["lint"] in ("clippy::expect_used", "clippy::unwrap_used")]
        for row in expect_rows:
            self.assertTrue(row["disposition"] in VALID_DISPOSITIONS)
            self.assertTrue(row["focused_proof"])
        # A mutation that turns an assertion boundary into a swallowed result
        # must be rejected.
        self.assertMutationRejected(
            "row_no_focused_proof",
            validate_row,
            scope="row",
        )

    # -- 16 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/16
    def test_16_too_many_lines_preserves_named_ordered_scenario(self) -> None:
        measured = sorted(
            {(r["path"], r["line"]) for r in self.in_scope_rows if r["code"] == "clippy::too_many_lines"}
        )
        self.assertTrue(measured, "the measured too_many_lines set must not be empty on this base")
        for path, line in measured:
            source = self.head_source.get(path) or (REPO_ROOT / path).read_text(encoding="utf-8", errors="replace")
            lines = source.splitlines()
            self.assertGreater(len(lines), 100)
            owner = _enclosing_item(lines, line)
            self.assertIsNotNone(owner, "%s:%d has no enclosing item name" % (path, line))
            name = owner
            self.assertTrue(
                name,
                "an ordered end-to-end test must be nameable; an anonymous too_many_lines "
                "expectation is not an accepted exception (%s:%d)" % (path, line),
            )

    # -- 17 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/17
    def test_17_copy_by_reference_expectation_has_contract_justification(self) -> None:
        rows = [r for r in self.ledger if r["lint"] == "clippy::trivially_copy_pass_by_ref"]
        for row in rows:
            self.assertFalse(
                _reason_is_hot_path_only(row["reason"]),
                "a hot-path claim alone is not a contract justification: %s" % row["reason"],
            )
        self.assertMutationRejected("copy_by_ref_hot_path_exemption", validate_row, scope="row")
        # The control: a hot-path reason that also names the contract is accepted.
        control = dict(self.mutations["copy_by_ref_hot_path_exemption"]["record"])
        control["reason"] = "hot path over an Authority Epoch contract; the reference is the observed identity"
        self.assertFalse(_reason_is_hot_path_only(control["reason"]))

    # -- 18 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/18
    def test_18_argument_count_expectation_preserves_non_rederived_context_contract(self) -> None:
        rows = [r for r in self.ledger if r["lint"] == "clippy::too_many_arguments"]
        for row in rows:
            self.assertFalse(
                _reason_is_rederivable(row["reason"]),
                "an argument-count reason that is re-derivable from configuration is not a contract",
            )
            self.assertTrue(row["removal_condition"])
        self.assertMutationRejected("argument_count_derived_context", validate_row, scope="row")

    # -- 19 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/19
    def test_19_last_resort_stderr_used_only_after_structured_output_failure(self) -> None:
        for path, before in self.base_source.items():
            after = self.head_source.get(path, "")
            self.assertEqual(
                before.count("eprintln!"), after.count("eprintln!"),
                "%s changed eprintln! usage; a stderr change needs its own justification" % path,
            )
            self.assertEqual(
                before.count("print_stderr"), after.count("print_stderr"), path
            )
        added_stderr = [l for l in self.added if "eprintln!" in l or "print_stderr" in l]
        self.assertEqual([], validate_stderr_additions(self.added), "added stderr needs its own justification")
        mutation = self.mutations["stderr_before_structured_failure"]["record"]
        stderr_at = min(i for i, l in enumerate(mutation["added_lines"]) if "eprintln!" in l)
        result_at = min(i for i, l in enumerate(mutation["added_lines"]) if "map_governor" in l)
        self.assertLess(stderr_at, result_at, "the mutation must place stderr before the structured result")
        self.assertMutationRejected("stderr_before_structured_failure", validate_stderr_additions)

    # -- 20 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/20
    def test_20_protected_and_secret_canaries_absent_from_changed_diagnostics(self) -> None:
        self.assertEqual(
            sorted(EXTRA_ALLOWED), sorted(EXTRA_ALLOWED & set(self.changed_paths)),
            "the negative-control fixture is the only path excluded from the canary scan, "
            "because it is the carrier of the canary mutations",
        )
        self.assertTrue(self.canary_excluded, "the canary scan must actually cover changed paths")
        blob = self.scan_blob + "\n" + "\n".join(self.added)
        for pattern in SECRET_PATTERNS:
            found = re.search(pattern, blob)
            self.assertIsNone(found, "a secret/protected canary appears in the delta: %r" % (found and found.group(0)))
        for record in self.workspace_records:
            if record.get("reason") != "compiler-message":
                continue
            rendered = (record.get("message") or {}).get("rendered") or ""
            for pattern in SECRET_PATTERNS:
                self.assertIsNone(
                    re.search(pattern, rendered),
                    "a secret/protected canary appears in a captured diagnostic",
                )
        self.assertMutationRejected("secret_canary", validate_added_lines)

    # -- 21 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/21
    def test_21_complete_current_projection_call_graph_and_historical_five_reconciliation(self) -> None:
        projection = (REPO_ROOT / "bins/eliotd/src/activation_projection.rs").read_text(encoding="utf-8")
        self.assertNotIn("#![allow(dead_code)]", projection)
        self.assertNotIn("#![allow(", projection, "activation_projection carries no module-wide suppression")
        for fn, caller in sorted(PROJECTION_FIVE.items()):
            self.assertIn("fn %s(" % fn, projection, "%s must exist in current source" % fn)
            caller_path = caller.split("::")[0]
            self.assertTrue(
                (REPO_ROOT / caller_path).is_file(), "the recorded caller path must exist"
            )
            self.assertIn(
                caller_path.split("::")[-1], projection + (REPO_ROOT / caller_path).read_text(encoding="utf-8"),
            )
            # The caller must be a production src path, never a tests/ path.
            self.assertNotIn("/tests/", caller_path)
            self.assertNotIn("_tests.rs", caller_path)
        self.assertEqual(
            len(PROJECTION_FIVE), HISTORICAL_DEAD_PROJECTION_FUNCTIONS,
            "the historical five must be reconciled item by item",
        )
        keys = {r["key"] for r in self.ledger if r["kind"] == "historical"}
        for fn in PROJECTION_FIVE:
            self.assertIn("historical/bins/eliotd/src/activation_projection.rs:%s:dead_code" % fn, keys)
        self.assertMutationRejected("reachability_from_test_only", validate_row, scope="row")

    # -- 22 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/22
    def test_22_module_wide_dead_code_rejected(self) -> None:
        for path in self.changed_paths:
            if not path.endswith(".rs"):
                continue
            text = self.head_source.get(path, "")
            self.assertNotRegex(text, r"#!\s*\[\s*allow\s*\(\s*dead_code\s*\)\s*\]")
        self.assertMutationRejected("module_wide_dead_code", validate_added_lines)
        # The narrow replacement is present and is an item, not a module.
        head = self.head_source.get("crates/eliot-app/src/host_runtime/event_and_authority.rs", "")
        self.assertIn("#[expect(dead_code, reason =", head)
        self.assertEqual(
            0, len(re.findall(r"#!\s*\[\s*allow", head)),
            "the file carries no crate-level allow",
        )

    # -- 23 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/23
    def test_23_remaining_exact_unwired_annotations_name_owner_and_removal_condition(self) -> None:
        rows = [r for r in self.ledger if r["lint"] == "dead_code" and r.get("reachability") == "NONE"]
        self.assertTrue(rows, "there is at least one deliberately retained unwired item")
        for row in rows:
            self.assertTrue(
                row["removal_condition"],
                "a retained unwired annotation must state its removal condition",
            )
            self.assertIn("839", row["owner"], "the record must say what #839 does and does not own")
            self.assertIn("NOT this item", row["owner"], "the record must not claim #839 owns this item")
            self.assertEqual([], validate_row(row, scope="no_module_wide_dead_code"))
        head = self.head_source.get("crates/eliot-app/src/host_runtime/event_and_authority.rs", "")
        self.assertIn("removal condition", head.lower())
        self.assertIn("expect", head.lower())
        # #839 owns the eliotd activation flight. Current source proves #839
        # touches bins/eliotd, not crates/eliot-app, so #839 is NOT a proven
        # owner of this retained path.
        proven_owners = frozenset()
        self.assertEqual(
            [],
            validate_unwired_annotation(rows[0], proven_owners),
            "the real row records the unproven owner state, so the validator accepts it",
        )
        self.assertMutationRejected(
            "unproven_owner_claim",
            validate_unwired_annotation,
            proven_owners=proven_owners,
        )

    # -- 24 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/24
    def test_24_unrelated_new_dead_function_fails_the_actual_lint(self) -> None:
        clean = self.rustc_probe["clean_control"]
        dead = self.rustc_probe["dead_function"]
        self.assertEqual(
            0, clean["exit"],
            "the control module must compile clean under -D warnings: %s" % clean["stderr"],
        )
        self.assertNotEqual(
            0, dead["exit"],
            "an unrelated dead function must fail the real applicable lint gate",
        )
        self.assertIn("never used", dead["stderr"])
        self.assertIn("dead_code", dead["stderr"])

    # -- 25 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/25
    def test_25_mapping_tests_cannot_be_labelled_daemon_reachability(self) -> None:
        for row in self.ledger:
            if row["disposition"] == "ALREADY_RESOLVED_CURRENT_EVIDENCE":
                self.assertFalse(
                    _reachability_is_test_only(row.get("reachability", "")),
                    "row %s proves reachability with a test path" % row["key"],
                )
        daemon = (REPO_ROOT / "bins/eliotd/src/daemon_runtime.rs").read_text(encoding="utf-8")
        self.assertIn("resolve_agent_activation_v2", daemon, "the daemon runtime is the production caller")
        self.assertMutationRejected("reachability_from_test_only", validate_row, scope="row")

    # -- 26 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/26
    def test_26_other_active_source_owner_warning_gets_explicit_handoff(self) -> None:
        self.assertTrue(
            self.in_scope_policy,
            "the measured policy residual must be non-empty on this base",
        )
        policy_rows = [r for r in self.ledger if r["lint"] == POLICY_LINT]
        self.assertTrue(policy_rows)
        for row in policy_rows:
            self.assertEqual("OWNER_BLOCKED", row["disposition"])
            self.assertIn("748", row["owner"])
        blocked_scope = [
            r for r in self.ledger if "work_lease_issuance" in r["path"]
        ]
        self.assertEqual(1, len(blocked_scope), "the BLOCKED-BY scope site must be recorded exactly once")
        self.assertNotIn(blocked_scope[0]["path"], WHITELIST, "that path is outside the frozen whitelist")
        for row in self.ledger:
            self.assertTrue(row["owner"].strip(), "row %s is unowned" % row["key"])
        self.assertMutationRejected("out_of_scope_row_unowned", validate_row, scope="row")

    # -- 27 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/27
    def test_27_semantic_diagnostics_not_hidden_by_suppression(self) -> None:
        for row in self.ledger:
            if row["disposition"] in ("ACCEPTED_NARROW_EXPECTATION", "FIXED_ITEM_EXPECTATION"):
                self.assertNotIn(row["lint"], SEMANTIC_LINTS)
        for path, before in self.base_source.items():
            after = self.head_source.get(path, "")
            for lint in sorted(SEMANTIC_LINTS):
                self.assertEqual(
                    before.count("allow(%s" % lint), after.count("allow(%s" % lint),
                    "%s added an allowance for the semantic lint %s" % (path, lint),
                )
                self.assertEqual(
                    before.count("expect(%s" % lint), after.count("expect(%s" % lint),
                    "%s added an expectation for the semantic lint %s" % (path, lint),
                )
        self.assertTrue(
            self.current_errors,
            "hard errors are recorded, not suppressed; this base has %d" % len(self.current_errors),
        )
        self.assertMutationRejected("semantic_lint_suppressed", validate_row, scope="row")

    # -- 28 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/28
    def test_28_every_selected_non_documentation_correction_has_passing_focused_proof(self) -> None:
        corrections = [
            r for r in self.ledger
            if r["disposition"] in ("FIXED_MECHANICAL", "FIXED_ITEM_EXPECTATION")
        ]
        self.assertTrue(corrections, "this branch selected at least one correction")
        for row in corrections:
            self.assertTrue(row["focused_proof"])
            self.assertHasMethod(row["focused_proof"])
        # A documentation-only correction does not need a focused equivalence
        # proof; a mechanical one does. There are no doc-only corrections here,
        # so every selected correction must carry one.
        self.assertFalse(
            [r for r in corrections if not r["focused_proof"]],
        )

    # -- 29 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/29
    def test_29_actual_full_fmt_check_passes(self) -> None:
        self.assertEqual(
            0, self.fmt_exit,
            "cargo fmt --all -- --check failed on the current source:\n%s" % self.fmt_stderr[-4000:],
        )

    # -- 30 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/30
    def test_30_actual_locked_workspace_all_target_check_passes(self) -> None:
        self.assertEqual(
            0, self.check_exit,
            "cargo check --locked --workspace --all-targets does not pass on this base; "
            "%d hard errors remain, all outside the 28-path whitelist:\n%s"
            % (len(self.current_errors), self.check_stderr[-4000:]),
        )

    # -- 31 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/31
    def test_31_actual_locked_workspace_all_target_clippy_deny_warnings_passes(self) -> None:
        self.assertEqual(
            0, self.deny_exit,
            "cargo clippy --locked --workspace --all-targets -- -D warnings does not pass; "
            "%d warnings and %d errors remain (%d of the warnings are the #748 policy lint)"
            % (len(self.current_warnings), len(self.current_errors), len(self.in_scope_policy)),
        )

    # -- 32 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/32
    def test_32_second_same_source_tool_config_clippy_run_has_the_same_result(self) -> None:
        self.assertEqual(
            self.capture_cmd, self.second_cmd,
            "the second run must use the identical command, source, tool and config",
        )
        first = {
            (r["level"], r["code"], r["path"], r["line"], r["message"]) for r in self.workspace_rows
        }
        second = {(r["level"], r["code"], r["path"], r["line"], r["message"]) for r in self.second_rows}
        new_in_second = second - first
        self.assertEqual(
            set(), new_in_second,
            "the second run produced diagnostics the first did not; this is not a clean baseline",
        )
        self.assertEqual(
            first, second,
            "the same source/tool/config must yield the same diagnostic set",
        )
        self.assertNotEqual(
            0, self.workspace_exit,
            "this base is not clean; case 31 carries that verdict. This case proves "
            "determinism only, and it is recorded as such rather than as a clean claim.",
        )

    # -- 33 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/33
    def test_33_production_diff_is_a_necessary_subset_of_the_frozen_whitelist(self) -> None:
        self.assertEqual(
            [], validate_changed_paths(self.changed_paths),
            "the branch edits a path outside the frozen scope",
        )
        for path in self.changed_paths:
            if path.endswith(".rs") and path not in EXTRA_ALLOWED:
                self.assertIn(path, WHITELIST)
        self.assertIn("scripts/tests/test_clippy_baseline_acceptance.py", self.changed_paths)
        self.assertIn("scripts/testdata/clippy-baseline/invalid_evidence.json", self.changed_paths)
        # No artificial edit-count target: the test asserts necessity, not a count.
        self.assertFalse(
            (REPO_ROOT / MARKER_REMOVAL).exists(),
            "the marker named by the issue must not be reintroduced",
        )
        marker_commits = subprocess.run(
            ["git", "log", "--all", "--oneline", "--", MARKER_REMOVAL],
            cwd=REPO_ROOT, capture_output=True, text=True, check=False,
        ).stdout.strip()
        self.assertEqual(
            "", marker_commits,
            "the issue's marker-removal item is vacuous on this base: %r has never existed. The "
            "real owner of this marker class is "
            "scripts/audit-work-unit-assignments.py::AssignmentIntegrityOracle" % MARKER_REMOVAL,
        )
        self.assertTrue((REPO_ROOT / "scripts/audit-work-unit-assignments.py").is_file())
        self.assertIn(
            "AssignmentIntegrityOracle",
            (REPO_ROOT / "scripts/audit-work-unit-assignments.py").read_text(encoding="utf-8"),
        )
        self.assertMutationRejected("path_outside_whitelist", lambda rec: validate_changed_paths(rec["changed_paths"]))

    # -- 34 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/34
    def test_34_pr_records_exact_before_after_current_arithmetic_and_external_owner_residuals(self) -> None:
        record = {
            "historical_total": HISTORICAL_TOTAL,
            "historical_test_context": HISTORICAL_TEST_CONTEXT,
            "historical_production_context": HISTORICAL_PRODUCTION_CONTEXT,
            "historical_changed_paths": HISTORICAL_CHANGED_PATHS,
            "historical_dead_projection_functions": HISTORICAL_DEAD_PROJECTION_FUNCTIONS,
            "measured_current_warnings": len(self.current_warnings),
            "measured_current_errors": len(self.current_errors),
            "measured_in_scope_rows": len(self.in_scope_rows),
            "measured_in_scope_policy_rows": len(self.in_scope_policy),
            "measured_in_scope_ownable_rows": len(self.in_scope_ownable),
            "ledger_rows": len(self.ledger),
            "external_owner_residuals": sorted(
                {r["owner"] for r in self.ledger if r["disposition"] in ("OWNER_BLOCKED", "SEPARATE_CAUSAL_ISSUE")}
            ),
        }
        self.assertEqual(
            HISTORICAL_TEST_CONTEXT + HISTORICAL_PRODUCTION_CONTEXT, HISTORICAL_TOTAL
        )
        self.assertEqual(
            record["measured_in_scope_rows"],
            record["measured_in_scope_policy_rows"] + record["measured_in_scope_ownable_rows"],
        )
        self.assertTrue(record["external_owner_residuals"], "external-owner residuals must be explicit")
        self.assertTrue(
            any("748" in o for o in record["external_owner_residuals"]),
            "the #748 policy residual must be recorded by name",
        )
        self.assertTrue(
            any("BLOCKED-BY scope" in o for o in record["external_owner_residuals"]),
            "the BLOCKED-BY scope residual must be recorded by name",
        )
        self.assertEqual(
            len(self.ledger), len(self.ledger_keys), "the recorded arithmetic must be complete"
        )
        self.assertMutationRejected("forged_clean_claim", validate_claim_record)

    # -- 35 --------------------------------------------------------------
    # WORK_UNIT_CASE: 838/35
    def test_35_clean_warnings_do_not_claim_policy_runtime_product_or_release_proof(self) -> None:
        claim_ceiling = "SOURCE_WARNING_BASELINE_ONLY"
        for token in ("RELEASE", "PRODUCT_ACCEPTED", "RUNTIME_VERIFIED", "PROCESS_EXECUTOR_POLICY_OWNED", "STORE", "CURRENT_VERIFIED"):
            self.assertNotIn(token, claim_ceiling)
        blob = (self.scan_blob + "\n" + "\n".join(self.added)).upper()
        for token in ("RELEASE ACCEPTED", "PRODUCT ACCEPTED", "RUNTIME VERIFIED", "CURRENT_VERIFIED"):
            self.assertNotIn(token, blob, "the delta claims %r" % token)
        # The policy lint is owner-blocked, never claimed as owned by this branch.
        policy_rows = [r for r in self.ledger if r["lint"] == POLICY_LINT]
        self.assertTrue(policy_rows)
        for row in policy_rows:
            self.assertNotEqual("838", row["owner"], "#838 never owns the ProcessExecutor policy")
        # And the suite's own ceiling is recorded in the fixture as rejected.
        self.assertMutationRejected(
            "forged_clean_claim",
            validate_claim_record,
        )


def _enclosing_item(lines: list[str], line: int) -> str | None:
    """Name the item that contains ``line`` (1-based)."""
    name = None
    for index, text in enumerate(lines[: line - 1], start=1):
        match = re.match(r"^\s*(?:pub(\([a-z]+\))?\s+)?(?:async\s+)?fn\s+(\w+)", text)
        if match:
            name = match.group(2)
    return name


if __name__ == "__main__":
    unittest.main()
