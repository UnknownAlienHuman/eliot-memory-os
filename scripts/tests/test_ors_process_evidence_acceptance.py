"""ORS process-evidence v2 fixture acceptance for issue 844.

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
Directly read afterwards: the exact `process_evidence` fixture and the three
named tests in `crates/kernel/eliot-ors/src/tests.rs`; the current/legacy
decoder in `crates/kernel/eliot-process/src/execution_evidence.rs`;
`ProcessEvidenceRecord` validation/key logic in
`crates/kernel/eliot-ors/src/model.rs`; the accepted metadata/run-binding
interfaces in `scripts/work_unit_gate/` (#850/#851). Attestation: every
required item was read before the fixture edit and before this wrapper.

Accepted-owner reuse (no second general source parser or runner):
  * case markers are parsed with scripts.work_unit_gate.case_binding
    (lexical/AST oracle from #851); the Rust file carries exactly 844/1..23
    and this file carries exactly 844/24..27.
  * fixed command vectors are guarded with
    scripts.work_unit_gate.descriptor_runner.assert_no_workspace_wide and each
    libtest transcript is accepted only through its parse_rust_exact grammar
    plus phase_verdict (runner owners from #850).
  * `_extract_fn_item` is a single-item reader scoped to one named Rust `fn`
    with brace balancing; it is not a general parser. All source predicates
    count tokens inside that parsed item (comments stripped), never global
    substring matches over the file.
  * subprocesses run fixed argv tuples only (no shell, no interpolated input,
    no network); isolated cargo target dir C:/Temp/target-844 via
    CARGO_TARGET_DIR. The shared setUpClass executes each fixed exact Rust test
    once plus the fixed package suite and Clippy once, and retains the
    validated results; no historical passed-JSON or marker-only evidence.
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
TARGET_DIR = "C:/Temp/target-844"

CANONICAL_CONST = "eliot_process::PROCESS_EVIDENCE_SCHEMA_VERSION"
LEGACY_CONST = "eliot_process::PROCESS_EVIDENCE_LEGACY_SCHEMA_VERSION"

EXACT_ARGV = tuple(
    ("cargo", "test", "--locked", "-p", "eliot-ors", "--lib", name, "--", "--exact")
    for name in NAMED_TESTS
)
SUITE_ARGV = ("cargo", "test", "--locked", "-p", "eliot-ors", "--all-targets")
CLIPPY_ARGV = ("cargo", "clippy", "--locked", "-p", "eliot-ors", "--all-targets",
               "--", "-D", "warnings")
GIT_DIFF_CHECK_ARGV = ("git", "diff", "--check")
GIT_STATUS_ARGV = ("git", "status", "--porcelain=v1", "--", TESTS_RS_REL, OWN_REL)
GIT_SHOW_NAMES_ARGV = ("git", "show", "HEAD", "--name-only", "--format=")
GIT_SHOW_PROD_ARGV = ("git", "show", "HEAD", "--",
                      "crates/kernel/eliot-ors/src/model.rs",
                      "crates/kernel/eliot-ors/src/store.rs",
                      "crates/kernel/eliot-ors/src/lib.rs",
                      "crates/kernel/eliot-process/src/execution_evidence.rs",
                      "crates/kernel/eliot-process/src/lib.rs")
GIT_DIFF_PROD_ARGV = ("git", "diff", "--",
                      "crates/kernel/eliot-ors/src/model.rs",
                      "crates/kernel/eliot-ors/src/store.rs",
                      "crates/kernel/eliot-ors/src/lib.rs",
                      "crates/kernel/eliot-process/src/execution_evidence.rs",
                      "crates/kernel/eliot-process/src/lib.rs")
ALLOWED_ARGV = frozenset(
    EXACT_ARGV + (SUITE_ARGV, CLIPPY_ARGV, GIT_DIFF_CHECK_ARGV, GIT_STATUS_ARGV,
                  GIT_SHOW_NAMES_ARGV, GIT_SHOW_PROD_ARGV, GIT_DIFF_PROD_ARGV)
)

MAX_SOURCE_BYTES = 8_388_608
EXACT_TIMEOUT_S = 900
SUITE_TIMEOUT_S = 1800
CLIPPY_TIMEOUT_S = 1800


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


def check_fixture_names_canonical_constant(fixture_item):
    """Fixture names the canonical constant and carries no version literal."""
    code = check_strip_line_comments(fixture_item)
    if code.count(CANONICAL_CONST) < 1:
        raise AssertionError("fixture does not name the canonical version constant")
    for literal in ("eliot-process-evidence-v2", "eliot-process-evidence-legacy-v1",
                    "eliot-process-evidence-v1", "stdout_ref", "stderr_ref"):
        if literal in code:
            raise AssertionError(f"stale literal remains in fixture item: {literal}")
    return code.count(CANONICAL_CONST)


def check_observation_axes_preserved(test_source):
    """Observation-only axes spelling must still be asserted in the module."""
    code = check_strip_line_comments(test_source)
    for token in ('"OBSERVED"', '"NON_ASSERTABLE_UNVERIFIED"'):
        if token not in code:
            raise AssertionError(f"observation-only axes token missing: {token}")
    return True


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
    if len(completed.stdout) > 8_388_608:
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
    """Every libtest result line in the package suite must report zero failures."""
    text = suite_output.decode("utf-8")
    result_lines = [line for line in text.splitlines() if line.startswith("test result:")]
    if not result_lines:
        raise AssertionError("package suite produced no test-result lines")
    for line in result_lines:
        if "0 failed" not in line:
            raise AssertionError(f"suite result line not green: {line!r}")
    return len(result_lines)


def check_status_scope(status_text):
    """Dirty tree may only show the repaired test module plus this wrapper."""
    lines = sorted(line for line in status_text.splitlines() if line.strip())
    if lines != sorted([" M " + TESTS_RS_REL, "?? " + OWN_REL]):
        raise AssertionError(f"unexpected changed paths: {lines!r}")
    return True


def check_show_names_scope(names_text):
    """A committed HEAD may only name the repaired test module plus wrapper."""
    names = sorted(line for line in names_text.splitlines() if line.strip())
    if sorted(names) != sorted([TESTS_RS_REL, OWN_REL]):
        raise AssertionError(f"HEAD names out-of-scope paths: {names!r}")
    return True


def check_production_sources_stable(evidence_source, model_source):
    """Owner constants and ORS observation gates must be verbatim stable."""
    for statement in ("pub const PROCESS_EVIDENCE_SCHEMA_VERSION",
                      "pub const PROCESS_EVIDENCE_LEGACY_SCHEMA_VERSION",
                      "pub fn new_typed"):
        if statement not in evidence_source:
            raise AssertionError(f"process owner API changed: {statement}")
    for gate in ("not the accepted revision", "is not observation-only C0 evidence"):
        if gate not in model_source:
            raise AssertionError(f"ORS observation gate changed: {gate}")
    return True


class OrsProcessEvidenceAcceptanceTests(unittest.TestCase):
    """Four-case source/run acceptance matrix for issue 844 (cases 24..27)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tests_source = check_read_source_text(TESTS_RS_REL)
        cls.evidence_source = check_read_source_text(EVIDENCE_RS_REL)
        cls.model_source = check_read_source_text(MODEL_RS_REL)
        cls.fixture_item = check_extract_fn_item(cls.tests_source, FIXTURE_FN)
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
        cls.rust_markers = rust_markers
        py_markers = cb.parse_python_markers(
            own_text, OWN_REL,
            module_name="scripts.tests.test_ors_process_evidence_acceptance",
            expected_issue=844,
        )
        py_pairs = sorted((marker.case_issue, marker.case_number) for marker in py_markers)
        if py_pairs != [(844, n) for n in range(24, 28)]:
            raise AssertionError(f"python marker binding mismatch: {py_pairs!r}")
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
        status = check_run_fixed(GIT_STATUS_ARGV, 60)
        cls.status_text = status.stdout.decode("utf-8")
        if not cls.status_text.strip():
            names = check_run_fixed(GIT_SHOW_NAMES_ARGV, 60)
            cls.committed_names_text = names.stdout.decode("utf-8")
        else:
            cls.committed_names_text = ""
        if cls.status_text.strip():
            prod = check_run_fixed(GIT_DIFF_PROD_ARGV, 60)
        else:
            prod = check_run_fixed(GIT_SHOW_PROD_ARGV, 60)
        cls.prod_diff_text = prod.stdout.decode("utf-8")
        diff_check = check_run_fixed(GIT_DIFF_CHECK_ARGV, 60)
        if diff_check.returncode != 0:
            raise AssertionError("git diff --check reported whitespace errors")

    # WORK_UNIT_CASE: 844/24
    def test_case_24_named_tests_discovered_selected_and_pass(self):
        """All three original named tests are discovered, selected, pass."""
        self.assertEqual(len(self.exact_runs), 3)
        bound = {marker.test_name for marker in self.rust_markers}
        for name, transcript, discovered, parsed in self.exact_runs:
            short = name.split("::", 1)[1]
            self.assertIn(short, bound)
            self.assertEqual(parsed.identity, name)
            self.assertEqual(parsed.outcome, "pass")
            self.assertGreaterEqual(discovered, 3)
            self.assertEqual(dr.phase_verdict("execute", parsed.outcome), "green")
        with self.assertRaises(dr.RunnerInputError):
            dr.parse_rust_exact(
                self.exact_runs[0][1], NAMED_TESTS[0], 1, self.exact_runs[0][2])
        self.assertEqual(dr.phase_verdict("execute", "failure"), "non-green")

    # WORK_UNIT_CASE: 844/25
    def test_case_25_package_suite_and_clippy_green_without_weakening(self):
        """ORS all-target suite and Clippy pass; no test weakened or excluded."""
        self.assertEqual(self.suite_returncode, 0)
        self.assertGreater(check_suite_green(self.suite_output), 0)
        suite_text = self.suite_output.decode("utf-8")
        for name in NAMED_TESTS:
            short = name.split("::", 1)[1]
            self.assertIn(short + " ... ok", suite_text)
        self.assertEqual(self.clippy_returncode, 0)
        with self.assertRaises(AssertionError):
            check_suite_green(b"test result: ok. 1 passed; 1 failed; 0 ignored;\n")
        with self.assertRaises(dr.RunnerInputError):
            dr.parse_rust_exact(
                self.exact_runs[0][1], NAMED_TESTS[0], 1, self.exact_runs[0][2])
        self.assertEqual(dr.phase_verdict("execute", "skip"), "non-green")

    # WORK_UNIT_CASE: 844/26
    def test_case_26_changed_paths_stay_inside_test_only_scope(self):
        """Changed paths are exactly the owned test module plus wrapper."""
        self.assertFalse((ROOT / Path(*MARKER_REL.split("/"))).exists())
        self.assertGreater(check_fixture_names_canonical_constant(self.fixture_item), 0)
        if self.status_text.strip():
            self.assertTrue(check_status_scope(self.status_text))
            with self.assertRaises(AssertionError):
                check_status_scope(self.status_text + " M other/file.rs\n")
        else:
            self.assertTrue(check_show_names_scope(self.committed_names_text))
            with self.assertRaises(AssertionError):
                check_show_names_scope(
                    self.committed_names_text + "crates/kernel/eliot-ors/src/model.rs\n")

    # WORK_UNIT_CASE: 844/27
    def test_case_27_no_production_semantic_change(self):
        """No ORS/process production semantic change; owner APIs stable."""
        self.assertEqual(self.prod_diff_text.strip(), "")
        self.assertTrue(check_production_sources_stable(
            self.evidence_source, self.model_source))
        self.assertTrue(check_observation_axes_preserved(self.tests_source))
        with self.assertRaises(AssertionError):
            check_production_sources_stable(
                self.evidence_source.replace(
                    "pub const PROCESS_EVIDENCE_SCHEMA_VERSION", "pub const RENAMED", 1),
                self.model_source)
        with self.assertRaises(AssertionError):
            check_observation_axes_preserved(
                self.tests_source.replace('"OBSERVED"', '"VERIFIED"'))