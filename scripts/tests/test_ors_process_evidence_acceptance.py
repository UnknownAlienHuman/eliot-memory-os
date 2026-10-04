"""ORS process-evidence v2 fixture acceptance for issue 844 (cases 24..27).

[D-TEST-ORS-PROCESS-EVIDENCE]: migrate the shared ProcessEvidence fixture in
`crates/kernel/eliot-ors/src/tests.rs` to the explicit v2 contract (canonical
`PROCESS_EVIDENCE_SCHEMA_VERSION` / `PROCESS_EVIDENCE_LEGACY_SCHEMA_VERSION`,
no legacy keys on the current path, no mixed-form acceptance) while preserving
every history, idempotency, key and corruption assertion. Test-only work: no
production ORS/process, Cargo/lock, workflow, documentation or gate change.

Documentation routing (run from the repository root before mutation):
  python scripts/docs_read.py read \
    --path crates/kernel/eliot-ors/src/tests.rs \
    --path scripts/tests/test_ors_process_evidence_acceptance.py \
    --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
Verified bundle read for this lane (not re-routed by this writer):
  .eliot/docs-read-bundle-844-W4.md
  route receipt: sha256:b53e145c1affcafc8cfc0aec7ede3d8a3b966c34eb2ead038d8ddc212a5ba054
  normative pair: sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1
Required items read from that bundle: AGENTS.md, WORKFLOW.md, Cargo.toml,
docs/ARCHITECTURE_CONTRACT.md, docs/architecture/READING_PROTOCOL.md,
docs/architecture/I18-testing-and-instrumental-grounding-strategy.md,
docs/architecture/I01-08-exact-ownership-and-call-paths.md,
docs/architecture/I02-17-parallel-agent-development-contract.md,
crates/AGENTS.md, crates/kernel/AGENTS.md, bins/AGENTS.md, plus
docs/architecture/I05-22-schema-and-migration-rules.md read from disk.
Directly read afterwards: the exact `process_evidence` fixture and the three
named tests in `crates/kernel/eliot-ors/src/tests.rs`; the current/legacy
decoder in `crates/kernel/eliot-process/src/execution_evidence.rs`;
`ProcessEvidenceRecord` validation/key logic in
`crates/kernel/eliot-ors/src/model.rs`; the accepted metadata/run-binding
interfaces in `scripts/work_unit_gate/` (#850/#851). Attestation: every required
item above was read before this wrapper was reviewed and fixed.

Case split (issues/844/TASK.md "Required test matrix"): cases 1..23 are Rust
tests in `crates/kernel/eliot-ors/src/tests.rs` and are owned by the concurrent
Rust writer; this file carries exactly the four source/run cases 24..27.
  24 all three original named tests are discovered, selected and pass;
  25 the ORS all-target suite and Clippy run without weakened/excluded tests;
  26 the actual changed paths stay inside the exact test-only scope;
  27 a source/API comparison proves no ORS/process production semantic change.

Accepted-owner reuse (no second general source parser or runner):
  * case markers are parsed with scripts.work_unit_gate.case_binding
    (lexical/AST oracle from #851); the Rust file is expected to carry exactly
    844/1..23 and this file exactly 844/24..27. Both parsers reject a detached
    marker, an `#[ignore]` test, a skip decorator and an empty/placeholder body.
  * fixed command vectors are guarded with
    scripts.work_unit_gate.descriptor_runner.assert_no_workspace_wide and each
    libtest transcript is accepted only through its parse_rust_exact grammar
    plus phase_verdict (runner owners from #850).
  * `check_extract_fn_item` is a single-item reader scoped to one named Rust `fn`
    with brace balancing; it is not a general parser. Fixture and test predicates
    count tokens inside that parsed item (comments stripped), never global
    substring matches over the file. `check_api_surface` is a closed
    line-oriented projection of `pub`-declared items used only for the
    base-versus-worktree production comparison in case 27.
  * subprocesses run fixed argv tuples only (no shell, no interpolated input,
    no network), every tuple gated through ALLOWED_ARGV. The cargo target dir is
    derived once from CARGO_TARGET_DIR when the environment sets it, otherwise
    from the repository layout under <repo parent>/targets/; it is never
    hardcoded to a drive root or to C:/Temp and never creates a drive or mount.
    The shared setUpClass executes each fixed exact Rust test once plus the
    fixed package suite and Clippy once, and retains the validated results; no
    historical passed-JSON or marker-only evidence.

The owned status and candidate-range observations are acquired unscoped so
out-of-scope changes cannot be hidden by a Git pathspec; the separate
forbidden-family observations are limited to the listed families and exclude
the two owned files. The candidate range is origin/main...HEAD, so this check
must run before merge; after merge it is empty and fails closed. The combined
owned observation must equal the two EDIT paths, and both forbidden
observations must be empty.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

try:
    from scripts.work_unit_gate import case_binding as cb
    from scripts.work_unit_gate import descriptor_runner as dr
except ImportError:  # direct-file execution fallback; package import is primary.
    _FALLBACK_ROOT = Path(__file__).resolve().parents[2]
    if str(_FALLBACK_ROOT) not in sys.path:
        sys.path.insert(0, str(_FALLBACK_ROOT))
    from scripts.work_unit_gate import case_binding as cb
    from scripts.work_unit_gate import descriptor_runner as dr

ROOT = Path(__file__).resolve().parents[2]
TESTS_RS_REL = "crates/kernel/eliot-ors/src/tests.rs"
OWN_REL = "scripts/tests/test_ors_process_evidence_acceptance.py"
MARKER_REL = ".github/temporary/work-unit-844.md"
EVIDENCE_RS_REL = "crates/kernel/eliot-process/src/execution_evidence.rs"
MODEL_RS_REL = "crates/kernel/eliot-ors/src/model.rs"
FIXTURE_FN = "process_evidence"
NAMED_TESTS = (
    "tests::process_evidence_appends_history_idempotently_and_recovers_in_order",
    "tests::process_evidence_readback_rejects_noncanonical_raw_key_suffix",
    "tests::process_evidence_raw_wire_handles_colon_percent_siblings_mixed_rows_and_endpoint",
)

# Closed test-only scope and closed forbidden families (case 26).
OWNED_RELS = (TESTS_RS_REL, OWN_REL)
FORBIDDEN_FAMILIES = (
    "Cargo.toml",
    "Cargo.lock",
    ".github",
    "docs",
    "crates/kernel/eliot-ors/src",
    "crates/kernel/eliot-process/src",
    "scripts",
)

# Closed production comparison set (case 27): every ORS/process production file
# whose semantic change this work unit must be able to detect.
PROD_RELS = (
    "crates/kernel/eliot-ors/src/lib.rs",
    MODEL_RS_REL,
    "crates/kernel/eliot-ors/src/store.rs",
    "crates/kernel/eliot-ors/src/persistence_codec.rs",
    "crates/kernel/eliot-ors/src/process_stream_recovery.rs",
    "crates/kernel/eliot-process/src/lib.rs",
    EVIDENCE_RS_REL,
)

CANONICAL_CONST = "eliot_process::PROCESS_EVIDENCE_SCHEMA_VERSION"
LEGACY_CONST = "eliot_process::PROCESS_EVIDENCE_LEGACY_SCHEMA_VERSION"
OBSERVED_AXIS = '"OBSERVED"'
NON_ASSERTABLE_AXIS = '"NON_ASSERTABLE_UNVERIFIED"'
ESCALATED_AXIS = '"VERIFIED"'
STALE_FIXTURE_TOKENS = (
    "eliot-process-evidence-v2",
    "eliot-process-evidence-legacy-v1",
    "eliot-process-evidence-v1",
    "stdout_ref",
    "stderr_ref",
)

# Weakening tokens that must never appear in a fixed cargo argv (case 25).
WEAKENING_TOKENS = (
    "--no-run",
    "--no-fail-fast",
    "--ignored",
    "--include-ignored",
    "--skip",
    "--test",
    "-A",
    "--allow",
    "--cap-lints",
    "--keep-going",
)

EXACT_ARGV = tuple(
    ("cargo", "test", "--locked", "-p", "eliot-ors", "--lib", name, "--", "--exact")
    for name in NAMED_TESTS
)
SUITE_ARGV = ("cargo", "test", "--locked", "-p", "eliot-ors", "--all-targets")
CLIPPY_ARGV = ("cargo", "clippy", "--locked", "-p", "eliot-ors", "--all-targets",
               "--", "-D", "warnings")
GIT_DIFF_CHECK_ARGV = ("git", "diff", "--check")
GIT_STATUS_OWNED_ARGV = ("git", "status", "--porcelain=v1", "--untracked-files=no")
GIT_STATUS_FORBIDDEN_ARGV = (
    "git", "status", "--porcelain=v1", "--",
    *FORBIDDEN_FAMILIES,
    f":(exclude){TESTS_RS_REL}", f":(exclude){OWN_REL}",
)
GIT_RANGE_OWNED_ARGV = ("git", "diff", "--name-only", "origin/main...HEAD")
# The two scope observations above are acquired UNSCOPED on purpose: a status or a
# diff that filters the owned paths at the git call site can never report an
# out-of-scope edit, so the filter belongs to the comparison, not to the
# acquisition. The range is three-dot so that unrelated commits merged into
# origin/main after this branch forked do not appear as changes of this delivery.
# Untracked files are excluded from the status observation because an untracked
# file is in no candidate commit. Run against the candidate branch: once the
# delivery is merged the committed range is empty and the scope check refuses
# (fail-closed, never a silent pass).
GIT_RANGE_FORBIDDEN_ARGV = (
    "git", "diff", "--name-only", "origin/main...HEAD", "--",
    *FORBIDDEN_FAMILIES,
    f":(exclude){TESTS_RS_REL}", f":(exclude){OWN_REL}",
)
GIT_BASE_PROD_ARGV = tuple(("git", "show", f"origin/main:{rel}") for rel in PROD_RELS)
ALLOWED_ARGV = frozenset(
    EXACT_ARGV
    + (
        SUITE_ARGV,
        CLIPPY_ARGV,
        GIT_DIFF_CHECK_ARGV,
        GIT_STATUS_OWNED_ARGV,
        GIT_STATUS_FORBIDDEN_ARGV,
        GIT_RANGE_OWNED_ARGV,
        GIT_RANGE_FORBIDDEN_ARGV,
    )
    + GIT_BASE_PROD_ARGV
)

MAX_SOURCE_BYTES = 8_388_608
MAX_CHILD_OUTPUT_BYTES = 8_388_608
EXACT_TIMEOUT_S = 900
SUITE_TIMEOUT_S = 1800
CLIPPY_TIMEOUT_S = 1800
GIT_TIMEOUT_S = 120
# Smallest owner API surface this comparison accepts; keeps the projection from
# passing vacuously on an empty extraction.
MIN_API_SURFACE = 8


def resolve_target_dir():
    """One fixed cargo target dir: the environment's, else the repository's.

    The repository's own disk area is the default, so no build tree is ever
    written to a drive root, to C:/Temp, or to a path this wrapper invented.
    A value with no directory name below its anchor is refused, so no drive
    letter or mount is ever created.
    """
    configured = os.environ.get("CARGO_TARGET_DIR", "").strip()
    candidate = Path(configured) if configured else ROOT.parent / "targets" / "target-844"
    resolved = Path(os.path.abspath(str(candidate)))
    anchor = resolved.anchor
    remainder = resolved.as_posix()[len(anchor):].strip("/")
    if not remainder or set(remainder) <= {".", ".."}:
        raise AssertionError(f"cargo target dir names no directory: {resolved}")
    return str(resolved)


TARGET_DIR = resolve_target_dir()


def check_read_source_text(rel):
    """Bounded read of one repository-relative source path (no mutation)."""
    if not isinstance(rel, str) or not rel or rel.startswith("/") or ".." in rel.split("/"):
        raise AssertionError(f"non-canonical relative path: {rel!r}")
    if "\\" in rel or ":" in rel:
        raise AssertionError(f"non-canonical relative path: {rel!r}")
    path = ROOT / Path(*rel.split("/"))
    raw = path.read_bytes()
    if len(raw) > MAX_SOURCE_BYTES:
        raise AssertionError(f"source over bound: {rel}")
    return raw.decode("utf-8")


def check_extract_fn_item(source, fn_name, indent=""):
    """Single-item reader: brace-balanced body of one named Rust `fn` only."""
    anchor = "\n" + indent + "fn " + fn_name + "("
    start = source.find(anchor)
    if start < 0:
        raise AssertionError(f"fn item not found: {fn_name}")
    start += 1
    brace = source.find("{", start)
    if brace < 0:
        raise AssertionError(f"fn signature malformed: {fn_name}")
    depth = 0
    in_str = False
    in_char = False
    escaped = False
    in_line_comment = False
    i = brace
    while i < len(source):
        char = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
        elif in_str:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_str = False
        elif in_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "'":
                in_char = False
        elif char == "/" and nxt == "/":
            in_line_comment = True
            i += 1
        elif char == '"':
            in_str = True
        elif char == "'" and nxt != "" and i + 2 < len(source) and source[i + 2] == "'":
            in_char = True
            i += 2
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    raise AssertionError(f"fn item unclosed: {fn_name}")


def check_strip_line_comments(item):
    """Remove `//` tails so fixtures/comments can never satisfy token counts."""
    kept = []
    for line in item.splitlines():
        cut = line.find("//")
        kept.append(line[:cut] if cut >= 0 else line)
    return "\n".join(kept)


def check_api_surface(text):
    """Closed projection of declared items: base and worktree must agree.

    This is the source/API comparison of case 27. It is a line-oriented
    projection of `pub`-declared items (public, `pub(crate)`, `pub(super)`,
    `pub(in path)`), normalized for whitespace. It is deliberately not a Rust
    parser: it makes no claim about bodies, and it refuses an empty projection.
    """
    kept = []
    for line in check_strip_line_comments(text).splitlines():
        stripped = line.strip()
        if not stripped.startswith("pub"):
            continue
        match = re.match(r"pub(?:\([^)]*\))?\s+(?:async\s+|const\s+|unsafe\s+)*"
                         r"(?:fn|struct|enum|trait|type|const|static|mod|use)\b",
                         stripped)
        if match:
            kept.append(re.sub(r"\s+", " ", stripped))
    surface = tuple(kept)
    if len(surface) < MIN_API_SURFACE:
        raise AssertionError(f"implausible API surface projection: {len(surface)} items")
    return surface


def check_production_api_unchanged(rel, worktree_text, base_text):
    """Exact equality of the declared API surface against the base revision."""
    worktree_surface = check_api_surface(worktree_text)
    base_surface = check_api_surface(base_text)
    if worktree_surface != base_surface:
        only_worktree = [line for line in worktree_surface if line not in base_surface]
        only_base = [line for line in base_surface if line not in worktree_surface]
        raise AssertionError(
            f"production API surface changed in {rel}: "
            f"+{only_worktree[:4]!r} -{only_base[:4]!r}"
        )
    return len(worktree_surface)


def check_fixture_uses_canonical_current_version(fixture_item):
    """The shared fixture names the canonical constant exactly once, no literal."""
    code = check_strip_line_comments(fixture_item)
    uses = code.count(CANONICAL_CONST)
    if uses != 1:
        raise AssertionError(f"fixture must name {CANONICAL_CONST} exactly once, found {uses}")
    if code.count(LEGACY_CONST):
        raise AssertionError("current fixture names the legacy version constant")
    for token in STALE_FIXTURE_TOKENS:
        if token in code:
            raise AssertionError(f"stale literal remains in fixture item: {token}")
    if "schema_version" not in code:
        raise AssertionError("fixture carries no explicit schema_version")
    return uses


def check_fixture_observation_axes(fixture_item):
    """Observation-only axes are preserved and never escalated in the fixture."""
    code = check_strip_line_comments(fixture_item)
    for token in (OBSERVED_AXIS, NON_ASSERTABLE_AXIS):
        if token not in code:
            raise AssertionError(f"observation-only axes token missing: {token}")
    if ESCALATED_AXIS in code:
        raise AssertionError("fixture claims verified process execution")
    return True


def check_named_test_assertions_kept(test_item):
    """Each named test keeps real assertions: no is-ok-only or emptied body."""
    code = check_strip_line_comments(test_item)
    assertions = len(re.findall(r"\bassert(?:_eq|_ne)?!", code))
    matches = len(re.findall(r"\bmatches!", code))
    panics = len(re.findall(r"\bpanic!", code))
    if assertions + matches + panics < 2:
        raise AssertionError("named test lost its checked assertions")
    if re.search(r"\bassert!\s*\(\s*true\s*\)", code):
        raise AssertionError("named test degraded to an unconditional true assertion")
    return assertions + matches + panics


def check_run_fixed(argv, timeout_s):
    """Execute one allow-listed fixed vector (no shell, bounded, no input)."""
    if argv not in ALLOWED_ARGV:
        raise AssertionError(f"argv not in the fixed allow-list: {argv!r}")
    if argv[0] == "cargo":
        dr.assert_no_workspace_wide(list(argv))
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = TARGET_DIR
    Path(TARGET_DIR).mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        list(argv), cwd=ROOT, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=timeout_s, check=False,
    )
    if len(completed.stdout) > MAX_CHILD_OUTPUT_BYTES:
        raise AssertionError("child output over bound")
    return completed


def check_split_libtest_transcript(raw):
    """Split cargo wrapper lines from the single libtest transcript section."""
    if raw.count(b"\nrunning ") != 1:
        raise AssertionError("expected exactly one libtest transcript section")
    return b"\nrunning " + raw.split(b"\nrunning ")[1]


def check_discovered_count(transcript):
    """Derive the discovery denominator from the transcript's filtered count."""
    match = re.search(rb"(\d+) filtered out", transcript)
    if not match:
        raise AssertionError("no filtered-out denominator in transcript")
    discovered = int(match.group(1)) + 1
    if discovered < 1:
        raise AssertionError("empty discovery denominator")
    return discovered


def check_suite_green(suite_output):
    """Every libtest result line must report zero failures and zero ignored."""
    text = suite_output.decode("utf-8")
    result_lines = [line for line in text.splitlines() if line.startswith("test result:")]
    if not result_lines:
        raise AssertionError("package suite produced no test-result lines")
    for line in result_lines:
        if "0 failed" not in line:
            raise AssertionError(f"suite result line not green: {line!r}")
        if "0 ignored" not in line:
            raise AssertionError(f"suite result line excludes tests: {line!r}")
    return len(result_lines)


def check_no_excluded_tests(suite_text, expected_short_names):
    """Every bound test must be reported executed, not filtered or ignored."""
    if " ... ignored" in suite_text:
        raise AssertionError("suite reports an ignored test")
    for line in suite_text.splitlines():
        if line.startswith("test result:") and " 0 filtered out" not in line:
            raise AssertionError(f"suite filtered tests out: {line!r}")
    missing = [name for name in expected_short_names if name + " ... ok" not in suite_text]
    if missing:
        raise AssertionError(f"bound tests not reported executed: {missing!r}")
    return len(expected_short_names)


def check_argv_not_weakened(argv, required):
    """A fixed cargo argv must carry the required real-run/deny flags."""
    for token in required:
        if token not in argv:
            raise AssertionError(f"argv drops required token {token!r}: {argv!r}")
    for token in WEAKENING_TOKENS:
        if token in argv:
            raise AssertionError(f"argv weakens the run with {token!r}: {argv!r}")
    return True


def check_clippy_output(clippy_output):
    """Clippy must finish clean: no warning summary, no error summary."""
    text = clippy_output.decode("utf-8")
    for marker in ("warning:", "error:", "could not compile"):
        if marker in text:
            raise AssertionError(f"clippy output is not clean: {marker!r}")
    return True


def check_forbidden_scope_observation(observation_text, kind):
    """Any changed path in a forbidden family is refused."""
    lines = [line for line in observation_text.splitlines() if line.strip()]
    if lines:
        raise AssertionError(f"forbidden {kind} changed paths: {lines!r}")
    return True


def check_owned_scope_observation(status_text, range_text):
    """Owned changes are a subset of the closed two-path set and really exist."""
    observed = set()
    for line in status_text.splitlines():
        if not line.strip():
            continue
        path = line[3:].strip().strip('"')
        observed.add(path)
    for line in range_text.splitlines():
        if line.strip():
            observed.add(line.strip())
    outside = sorted(path for path in observed if path not in OWNED_RELS)
    if outside:
        raise AssertionError(f"changed paths outside the test-only scope: {outside!r}")
    if TESTS_RS_REL not in observed:
        raise AssertionError("owned test module is not among the changed paths")
    if OWN_REL not in observed:
        raise AssertionError("this wrapper is not among the changed paths")
    return sorted(observed)


class OrsProcessEvidenceAcceptanceTests(unittest.TestCase):
    """Four-case source/run acceptance matrix for issue 844 (cases 24..27)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tests_source = check_read_source_text(TESTS_RS_REL)
        cls.fixture_item = check_extract_fn_item(cls.tests_source, FIXTURE_FN)
        cls.named_items = {
            name.split("::", 1)[1]: check_extract_fn_item(
                cls.tests_source, name.split("::", 1)[1])
            for name in NAMED_TESTS
        }
        own_text = check_read_source_text(OWN_REL)
        rust_markers = cb.parse_rust_markers(
            cls.tests_source, TESTS_RS_REL, expected_issue=844)
        pairs = sorted((marker.case_issue, marker.case_number) for marker in rust_markers)
        if pairs != [(844, n) for n in range(1, 24)]:
            raise AssertionError(f"rust marker binding mismatch: {pairs!r}")
        qualified = [marker.qualified_name for marker in rust_markers]
        if len(set(qualified)) != 23:
            raise AssertionError("duplicate rust marker identities")
        if any(marker.adequacy_problem is not None for marker in rust_markers):
            raise AssertionError("placeholder rust test in 844 bindings")
        if any(marker.has_ignore or marker.has_cfg for marker in rust_markers):
            raise AssertionError("ignored or cfg-gated rust test in 844 bindings")
        cls.rust_markers = rust_markers
        cls.bound_short_names = tuple(sorted(marker.test_name for marker in rust_markers))
        py_markers = cb.parse_python_markers(
            own_text, OWN_REL,
            module_name="scripts.tests.test_ors_process_evidence_acceptance",
            expected_issue=844,
        )
        py_pairs = sorted((marker.case_issue, marker.case_number) for marker in py_markers)
        if py_pairs != [(844, n) for n in range(24, 28)]:
            raise AssertionError(f"python marker binding mismatch: {py_pairs!r}")
        if any(marker.adequacy_problem is not None for marker in py_markers):
            raise AssertionError("placeholder python case in 844 bindings")

        cls.exact_runs = []
        for argv, name in zip(EXACT_ARGV, NAMED_TESTS):
            completed = check_run_fixed(argv, EXACT_TIMEOUT_S)
            if completed.returncode != 0:
                raise AssertionError(f"fixed exact run failed: {name}")
            transcript = check_split_libtest_transcript(completed.stdout)
            discovered = check_discovered_count(transcript)
            parsed = dr.parse_rust_exact(transcript, name, completed.returncode, discovered)
            if parsed.outcome != "pass":
                raise AssertionError(f"fixed exact run did not pass: {name}")
            cls.exact_runs.append((name, transcript, discovered, parsed))

        suite = check_run_fixed(SUITE_ARGV, SUITE_TIMEOUT_S)
        cls.suite_returncode = suite.returncode
        cls.suite_output = suite.stdout
        clippy = check_run_fixed(CLIPPY_ARGV, CLIPPY_TIMEOUT_S)
        cls.clippy_returncode = clippy.returncode
        cls.clippy_output = clippy.stdout

        cls.owned_status_text = check_run_fixed(
            GIT_STATUS_OWNED_ARGV, GIT_TIMEOUT_S).stdout.decode("utf-8")
        cls.forbidden_status_text = check_run_fixed(
            GIT_STATUS_FORBIDDEN_ARGV, GIT_TIMEOUT_S).stdout.decode("utf-8")
        cls.owned_range_text = check_run_fixed(
            GIT_RANGE_OWNED_ARGV, GIT_TIMEOUT_S).stdout.decode("utf-8")
        cls.forbidden_range_text = check_run_fixed(
            GIT_RANGE_FORBIDDEN_ARGV, GIT_TIMEOUT_S).stdout.decode("utf-8")
        cls.base_prod_text = {
            rel: check_run_fixed(("git", "show", f"origin/main:{rel}"),
                                 GIT_TIMEOUT_S).stdout.decode("utf-8")
            for rel in PROD_RELS
        }
        cls.prod_surface_sizes = {
            rel: check_production_api_unchanged(
                rel, check_read_source_text(rel), cls.base_prod_text[rel])
            for rel in PROD_RELS
        }
        diff_check = check_run_fixed(GIT_DIFF_CHECK_ARGV, GIT_TIMEOUT_S)
        if diff_check.returncode != 0:
            raise AssertionError("git diff --check reported whitespace errors")

    # WORK_UNIT_CASE: 844/24
    def test_case_24_named_tests_discovered_selected_and_pass(self):
        """All three original named tests are discovered, selected and pass."""
        self.assertEqual(len(self.exact_runs), 3)
        bound = set(self.bound_short_names)
        denominators = set()
        for name, transcript, discovered, parsed in self.exact_runs:
            short = name.split("::", 1)[1]
            self.assertIn(short, bound)
            self.assertEqual(parsed.identity, name)
            self.assertEqual(parsed.outcome, "pass")
            self.assertEqual(parsed.filtered, discovered - 1)
            self.assertGreater(check_named_test_assertions_kept(
                self.named_items[short]), 1)
            self.assertEqual(dr.phase_verdict("execute", parsed.outcome), "green")
            denominators.add(discovered)
        # The denominator is read from the three transcripts, never from a
        # constant, and all three focused runs must see the same lib inventory.
        self.assertEqual(len(denominators), 1)
        discovered = denominators.pop()
        self.assertGreaterEqual(discovered, len(self.bound_short_names))

        # Negative run fixtures: missing selection, excluded result, stale
        # denominator and a failed run must all be refused by the owner parser.
        name, transcript, discovered, _ = self.exact_runs[0]
        with self.assertRaises(dr.RunnerInputError):
            dr.parse_rust_exact(transcript, "tests::process_evidence_absent_test",
                                0, discovered)
        with self.assertRaises(dr.RunnerInputError):
            dr.parse_rust_exact(transcript, name, 1, discovered)
        with self.assertRaises(dr.RunnerInputError):
            dr.parse_rust_exact(transcript, name, 0, discovered + 1)
        ignored = transcript.replace(b" ... ok", b" ... ignored")
        with self.assertRaises(dr.RunnerInputError):
            dr.parse_rust_exact(ignored, name, 0, discovered)
        self.assertEqual(dr.phase_verdict("execute", "failure"), "non-green")
        self.assertEqual(dr.phase_verdict("execute", "skip"), "non-green")

    # WORK_UNIT_CASE: 844/25
    def test_case_25_package_suite_and_clippy_green_without_weakening(self):
        """ORS all-target suite and Clippy run; no test weakened or excluded."""
        self.assertTrue(check_argv_not_weakened(
            SUITE_ARGV, ("--locked", "-p", "eliot-ors", "--all-targets", "test")))
        self.assertTrue(check_argv_not_weakened(
            CLIPPY_ARGV, ("--locked", "-p", "eliot-ors", "--all-targets", "-D", "warnings")))
        self.assertEqual(self.suite_returncode, 0)
        suite_text = self.suite_output.decode("utf-8")
        self.assertGreater(check_suite_green(self.suite_output), 0)
        self.assertEqual(
            check_no_excluded_tests(suite_text, self.bound_short_names),
            len(self.bound_short_names),
        )
        for name in NAMED_TESTS:
            self.assertIn(name.split("::", 1)[1] + " ... ok", suite_text)
        self.assertEqual(self.clippy_returncode, 0)
        self.assertTrue(check_clippy_output(self.clippy_output))

        # Negative run fixtures: a failing line, an ignored test, a filtered
        # test, a weakened argv and a dirty clippy output must all be refused.
        with self.assertRaises(AssertionError):
            check_suite_green(b"test result: ok. 1 passed; 1 failed; 0 ignored;\n")
        with self.assertRaises(AssertionError):
            check_suite_green(b"test result: ok. 1 passed; 0 failed; 1 ignored;\n")
        with self.assertRaises(AssertionError):
            check_no_excluded_tests(
                self.suite_output.decode("utf-8") + "tests::absent_test ... ignored\n",
                self.bound_short_names,
            )
        with self.assertRaises(AssertionError):
            check_no_excluded_tests(suite_text, self.bound_short_names + ("tests::absent_test",))
        with self.assertRaises(AssertionError):
            check_argv_not_weakened(SUITE_ARGV + ("--no-run",), ("--all-targets",))
        with self.assertRaises(AssertionError):
            check_argv_not_weakened(CLIPPY_ARGV[:5], ("-D", "warnings"))
        with self.assertRaises(AssertionError):
            check_clippy_output(b"warning: unused import\n")

    # WORK_UNIT_CASE: 844/26
    def test_case_26_changed_paths_stay_inside_test_only_scope(self):
        """Actual changed paths are exactly the owned test module plus wrapper."""
        self.assertFalse((ROOT / Path(*MARKER_REL.split("/"))).exists())
        self.assertEqual(
            check_fixture_uses_canonical_current_version(self.fixture_item), 1)
        self.assertTrue(check_forbidden_scope_observation(
            self.forbidden_status_text, "worktree"))
        self.assertTrue(check_forbidden_scope_observation(
            self.forbidden_range_text, "committed"))
        self.assertEqual(
            check_owned_scope_observation(self.owned_status_text, self.owned_range_text),
            sorted(OWNED_RELS),
        )

        # Negative source fixtures: a production path in the worktree set, in
        # the committed set, and an empty/foreign owned observation all fail.
        with self.assertRaises(AssertionError):
            check_forbidden_scope_observation(
                " M crates/kernel/eliot-ors/src/model.rs\n", "worktree")
        with self.assertRaises(AssertionError):
            check_forbidden_scope_observation(
                "crates/kernel/eliot-process/src/execution_evidence.rs\n", "committed")
        with self.assertRaises(AssertionError):
            check_owned_scope_observation(
                " M crates/kernel/eliot-ors/src/store.rs\n", "")
        with self.assertRaises(AssertionError):
            check_owned_scope_observation(
                " M " + TESTS_RS_REL + "\n", "")
        with self.assertRaises(AssertionError):
            check_owned_scope_observation("", "")

    # WORK_UNIT_CASE: 844/27
    def test_case_27_no_production_semantic_change(self):
        """No ORS/process production semantic change; declared API is identical."""
        self.assertTrue(check_forbidden_scope_observation(
            self.forbidden_status_text, "worktree"))
        self.assertTrue(check_forbidden_scope_observation(
            self.forbidden_range_text, "committed"))
        self.assertEqual(sorted(self.prod_surface_sizes), sorted(PROD_RELS))
        for rel in PROD_RELS:
            self.assertGreaterEqual(self.prod_surface_sizes[rel], MIN_API_SURFACE)

        # Negative source fixtures: renaming, removing or retyping one declared
        # production item must be detected by the same comparison.
        base = self.base_prod_text[EVIDENCE_RS_REL]
        worktree = check_read_source_text(EVIDENCE_RS_REL)
        renamed = base.replace("pub const PROCESS_EVIDENCE_SCHEMA_VERSION",
                               "pub const RENAMED_SCHEMA_VERSION", 1)
        with self.assertRaises(AssertionError):
            check_production_api_unchanged(EVIDENCE_RS_REL, worktree, renamed)
        dropped = base.replace(
            "    pub fn new_typed(\n", "    fn new_typed(\n", 1)
        with self.assertRaises(AssertionError):
            check_production_api_unchanged(EVIDENCE_RS_REL, worktree, dropped)
        with self.assertRaises(AssertionError):
            check_api_surface("// pub const PROCESS_EVIDENCE_SCHEMA_VERSION: &str;\n")
        with self.assertRaises(AssertionError):
            check_production_api_unchanged(
                EVIDENCE_RS_REL,
                worktree.replace("pub const fn stdout(&self)",
                                 "pub const fn stdout_mut(&self)", 1),
                base,
            )
        with self.assertRaises(AssertionError):
            check_production_api_unchanged(
                EVIDENCE_RS_REL,
                base.replace("pub const fn stdout(&self)",
                             "pub const fn stdout_mut(&self)", 1),
                worktree,
            )
        self.assertTrue(check_fixture_observation_axes(self.fixture_item))
        with self.assertRaises(AssertionError):
            check_fixture_observation_axes(
                self.fixture_item.replace(OBSERVED_AXIS, ESCALATED_AXIS, 1))
        with self.assertRaises(AssertionError):
            check_fixture_uses_canonical_current_version(
                self.fixture_item.replace(CANONICAL_CONST, '"eliot-process-evidence-v2"', 1))
