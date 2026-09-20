"""CLI provider-identity contract acceptance for issue 840.

[D-TEST-CLI-CONTRACT]: remove the stale duplicated MCP version assertion from
`provider_identity_comes_from_actual_contract_shapes` in
`crates/surfaces/eliot-cli/src/lib.rs`. The production constant
`MCP_SURFACE_CONTRACT_REVISION` still delegates to `eliot_mcp::CONTRACT_REVISION`;
MCP is not a row of the four-provider catalogue. No production, Cargo, workflow,
gate-descriptor or shared-registry change.

Documentation routing (run from the repository root before mutation):
  python scripts/docs_read.py read --path crates/surfaces/eliot-cli/src/lib.rs \
    --path scripts/tests/test_cli_contract_acceptance.py \
    --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
  route receipt: sha256:879188a00e44c34636ee258bb6c94d94f5bbec097da10c364bdfd69ede2a6967
  read receipt:  sha256:2ff59b2bebd3a61029ad87b09c6c37fb254b4c9fe2ef8b20643398e631ffcae0
  matched routes: generic-source, human-surfaces, workspace-governance (38 required items)
  bundle SHA-256: 3f3e57feffcbbb38bb4041ebe0c738e2cb35672a3ca7696d19972a9d664ca819
Directly read afterwards: docs/architecture/I07-06-mcp-surface.md (I7.6, MCP
surface owns the canonical tools, not the CLI catalogue) and
docs/architecture/I00-04-change-classes.md (Local-class repair, module checks).
Attestation: the full verified bundle was read; every required handle above was
opened before the one-line product edit and before this wrapper was written.

Accepted-owner reuse (no second general source parser or runner):
  * case markers are parsed with scripts.work_unit_gate.case_binding
    (tokenize/AST oracle from #851); the file carries exactly 840/1..10.
  * fixed command vectors are guarded with
    scripts.work_unit_gate.descriptor_runner.assert_no_workspace_wide and the
    libtest transcript is accepted only through its parse_rust_exact grammar
    plus phase_verdict (runner owners from #850).
  * `_extract_fn_item` is a single-item reader scoped to one named Rust `fn`
    with brace balancing; it is not a general parser. All source predicates
    count tokens inside that parsed item (comments stripped), never global
    substring matches over the file.
  * subprocesses run fixed argv tuples only (no shell, no interpolated input,
    no network); isolated cargo target dir C:/Temp/target-go49 via
    CARGO_TARGET_DIR. The shared setUpClass executes the fixed exact Rust test
    once and the fixed package suite once per candidate and retains the
    validated results; no historical passed-JSON or marker-only evidence.
"""
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

from scripts.work_unit_gate import case_binding as cb
from scripts.work_unit_gate import descriptor_runner as dr

ROOT = Path(__file__).resolve().parents[2]
LIB_RS_REL = "crates/surfaces/eliot-cli/src/lib.rs"
MCP_RS_REL = "crates/surfaces/eliot-mcp/src/lib.rs"
OWN_REL = "scripts/tests/test_cli_contract_acceptance.py"
MARKER_REL = ".github/temporary/work-unit-840.md"
TEST_FN = "provider_identity_comes_from_actual_contract_shapes"
PROVIDERS_FN = "provider_contracts"
RUST_TEST_ID = "tests::" + TEST_FN
TARGET_DIR = "C:/Temp/target-go49"

STALE_STATEMENT = "assert_eq!(MCP_SURFACE_CONTRACT_REVISION, eliot_mcp::CONTRACT_REVISION);"
PROD_STATEMENT = "pub const MCP_SURFACE_CONTRACT_REVISION: &str = eliot_mcp::CONTRACT_REVISION;"
MCP_OWNER_STATEMENT = 'pub const CONTRACT_REVISION: &str = "1.2.0";'
COUNT_ASSERT = "assert_eq!(providers.len(), 4);"
VERSION_ASSERT = "!provider.contract_version.trim().is_empty()"
DIGEST_ASSERT = "provider.shape_sha256.len() == 64"
EXPECTED_ROWS = (
    ("C0-02", "eliot-receipts"),
    ("C0-04", "eliot-runtime-contracts"),
    ("C0-07", "eliot-protocol"),
    ("C0-11", "eliot-observation-contracts"),
)

# Frozen post-repair counterpart of the exact Rust test item (indentation kept).
FROZEN_TEST_ITEM = """    fn provider_identity_comes_from_actual_contract_shapes() -> Result<(), CatalogueError> {
        let providers = CommandCatalogue::current().providers()?;
        assert_eq!(providers.len(), 4);
        assert!(
            providers
                .iter()
                .all(|provider| !provider.contract_version.trim().is_empty())
        );
        assert!(
            providers
                .iter()
                .all(|provider| provider.shape_sha256.len() == 64)
        );
        Ok(())
    }"""

EXACT_ARGV = (
    "cargo", "test", "--locked", "-p", "eliot-cli", "--lib", RUST_TEST_ID, "--", "--exact",
)
SUITE_ARGV = ("cargo", "test", "--locked", "-p", "eliot-cli", "--all-targets")
GIT_DIFF_CHECK_ARGV = ("git", "diff", "--check")
GIT_NUMSTAT_ARGV = ("git", "diff", "--numstat", "--", LIB_RS_REL)
GIT_DIFF_LIB_ARGV = ("git", "diff", "--", LIB_RS_REL)
GIT_STATUS_ARGV = ("git", "status", "--porcelain=v1", "--", LIB_RS_REL, OWN_REL)
GIT_RANGE_NUMSTAT_ARGV = ("git", "diff", "origin/main", "--numstat", "--", LIB_RS_REL, OWN_REL)
ALLOWED_ARGV = frozenset((
    EXACT_ARGV, SUITE_ARGV, GIT_DIFF_CHECK_ARGV, GIT_NUMSTAT_ARGV,
    GIT_DIFF_LIB_ARGV, GIT_STATUS_ARGV, GIT_RANGE_NUMSTAT_ARGV,
))

MAX_SOURCE_BYTES = 8_388_608
EXACT_TIMEOUT_S = 900
SUITE_TIMEOUT_S = 1800


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


def check_extract_fn_item(source, fn_name, indent="    "):
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


def check_production_section(source):
    """Production code is everything before the outer `mod tests` boundary."""
    boundary = "\n#[cfg(test)]\nmod tests {"
    if source.count(boundary) != 1:
        raise AssertionError("expected exactly one outer mod-tests boundary")
    return source.split(boundary)[0]


def check_stale_disposition(lib_source, test_item, exact_outcome):
    """Baseline failure is the obsolete literal; else the exact correct state.

    Returns 'stale-present' for the pre-repair duplication or 'already-correct'
    for the repaired state with frozen-item plus passing-run evidence.
    """
    prod = check_production_section(lib_source)
    prod_ok = check_strip_line_comments(prod).count("MCP_SURFACE_CONTRACT_REVISION") == 1
    prod_ok = prod_ok and PROD_STATEMENT in prod
    stale_n = check_strip_line_comments(test_item).count(STALE_STATEMENT)
    if stale_n == 1 and prod_ok:
        return "stale-present"
    if stale_n == 0 and prod_ok and test_item == FROZEN_TEST_ITEM and exact_outcome == "pass":
        return "already-correct"
    raise AssertionError(
        f"disposition not proven: stale_n={stale_n} prod_ok={prod_ok} "
        f"frozen={test_item == FROZEN_TEST_ITEM} exact={exact_outcome}"
    )


def check_production_delegation(lib_source, mcp_source):
    """Production alias must delegate to the canonical MCP owner, verbatim."""
    prod = check_production_section(lib_source)
    if check_strip_line_comments(prod).count(PROD_STATEMENT) != 1:
        raise AssertionError("production delegation statement not unique")
    alias = next(line for line in prod.splitlines() if PROD_STATEMENT in line)
    if '"' in alias:
        raise AssertionError("production alias must not copy a version literal")
    if MCP_OWNER_STATEMENT not in mcp_source:
        raise AssertionError("canonical MCP owner revision changed")
    return alias.strip()


def check_no_second_literal(test_item):
    """No MCP version token or copied revision literal may remain in the test."""
    code = check_strip_line_comments(test_item)
    for token in ("MCP_SURFACE_CONTRACT_REVISION", "eliot_mcp::CONTRACT_REVISION", '"1.2.0"'):
        if token in code:
            raise AssertionError(f"stale MCP literal remains in test item: {token}")
    return code.count("assert")


def check_count_assertion(test_item):
    """The retained test must still require exactly four providers."""
    if COUNT_ASSERT not in check_strip_line_comments(test_item):
        raise AssertionError("four-provider count assertion missing")
    return 4


def check_parse_provider_rows(providers_item):
    """Parse the actual provider rows from the parsed `provider_contracts` item."""
    code = check_strip_line_comments(providers_item)
    rows = tuple(re.findall(r'provider\(\s*"([^"]+)",\s*"([^"]+)"', code))
    return rows


def check_provider_rows(providers_item):
    """Catalogue rows must be exactly the four admitted providers."""
    rows = check_parse_provider_rows(providers_item)
    if rows != EXPECTED_ROWS:
        raise AssertionError(f"provider rows mismatch: {rows!r}")
    return rows


def check_no_mcp_row(providers_item):
    """No MCP provider row may be invented in the catalogue."""
    code = check_strip_line_comments(providers_item)
    if "mcp" in code.lower():
        raise AssertionError("invented MCP provider row")
    calls = len(re.findall(r"provider\(", code))
    if calls != 4:
        raise AssertionError(f"expected 4 provider calls, found {calls}")
    return calls


def check_version_assertion(test_item):
    """Every provider's nonempty version assertion must remain effective."""
    if VERSION_ASSERT not in check_strip_line_comments(test_item):
        raise AssertionError("nonempty version assertion missing")
    return True


def check_digest_assertion(test_item):
    """Every provider's 64-character digest assertion must remain effective."""
    if DIGEST_ASSERT not in check_strip_line_comments(test_item):
        raise AssertionError("64-char digest assertion missing")
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


def check_lib_diff_text(diff_text):
    """Product diff for lib.rs must be solely the stale-line removal."""
    removed = [line[1:] for line in diff_text.splitlines()
               if line.startswith("-") and not line.startswith("---")]
    added = [line[1:] for line in diff_text.splitlines()
             if line.startswith("+") and not line.startswith("+++")]
    if removed != ["        " + STALE_STATEMENT] or added != []:
        raise AssertionError(f"diff is not the sole stale-line removal: -{removed!r} +{added!r}")
    return True


def check_lib_numstat(numstat_text):
    """Numstat for lib.rs must read exactly one deletion and zero additions."""
    lines = [line for line in numstat_text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise AssertionError(f"numstat must be one line: {lines!r}")
    parts = lines[0].split()
    if tuple(parts) != ("0", "1", LIB_RS_REL):
        raise AssertionError(f"numstat mismatch: {parts!r}")
    return True


def check_status_text(status_text):
    """Only the repaired lib plus this new wrapper may show as changed."""
    lines = sorted(line for line in status_text.splitlines() if line.strip())
    if lines != sorted([" M " + LIB_RS_REL, "?? " + OWN_REL]):
        raise AssertionError(f"unexpected changed paths: {lines!r}")
    return True


def check_range_numstat(numstat_text):
    """Committed fallback: origin/main delta is the removal plus this wrapper."""
    entries = {}
    for line in numstat_text.splitlines():
        if not line.strip():
            continue
        added, deleted, path = line.split()
        entries[path] = (added, deleted)
    if entries.get(LIB_RS_REL) != ("0", "1"):
        raise AssertionError(f"range lib entry mismatch: {entries!r}")
    own = entries.get(OWN_REL)
    if own is None or own[1] != "0" or int(own[0]) <= 0:
        raise AssertionError(f"range wrapper entry mismatch: {entries!r}")
    if set(entries) != {LIB_RS_REL, OWN_REL}:
        raise AssertionError(f"range entries mismatch: {entries!r}")
    return True


class CliContractAcceptanceTests(unittest.TestCase):
    """Ten-case acceptance matrix for issue 840 (denominator exactly 1..10)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.lib_source = check_read_source_text(LIB_RS_REL)
        cls.mcp_source = check_read_source_text(MCP_RS_REL)
        cls.test_item = check_extract_fn_item(cls.lib_source, TEST_FN, indent="    ")
        cls.providers_item = check_extract_fn_item(cls.lib_source, PROVIDERS_FN, indent="")
        own_text = check_read_source_text(OWN_REL)
        markers = cb.parse_python_markers(
            own_text, OWN_REL,
            module_name="scripts.tests.test_cli_contract_acceptance",
            expected_issue=840,
        )
        pairs = sorted((marker.case_issue, marker.case_number) for marker in markers)
        if pairs != [(840, n) for n in range(1, 11)]:
            raise AssertionError(f"marker binding mismatch: {pairs!r}")
        qualified = [marker.qualified_name for marker in markers]
        if len(set(qualified)) != 10:
            raise AssertionError("duplicate marker identities")
        cls.markers = markers
        exact = check_run_fixed(EXACT_ARGV, EXACT_TIMEOUT_S)
        if exact.returncode != 0:
            raise AssertionError(f"fixed exact run failed: rc={exact.returncode}")
        transcript = check_split_libtest_transcript(exact.stdout)
        discovered = check_discovered_count(transcript)
        cls.exact_transcript = transcript
        cls.exact_discovered = discovered
        cls.exact_parsed = dr.parse_rust_exact(
            transcript, RUST_TEST_ID, exact.returncode, discovered)
        if cls.exact_parsed.outcome != "pass":
            raise AssertionError("fixed exact run did not pass")
        suite = check_run_fixed(SUITE_ARGV, SUITE_TIMEOUT_S)
        cls.suite_returncode = suite.returncode
        cls.suite_output = suite.stdout

    # WORK_UNIT_CASE: 840/1
    def test_case_01_baseline_is_obsolete_literal_or_exact_correct_state(self):
        """Baseline failure is the obsolete literal; repaired state is exact."""
        disposition = check_stale_disposition(
            self.lib_source, self.test_item, self.exact_parsed.outcome)
        self.assertEqual(disposition, "already-correct")
        doubled = self.test_item.replace(
            "        let providers",
            "        " + STALE_STATEMENT + "\n        " + STALE_STATEMENT + "\n        let providers",
            1,
        )
        with self.assertRaises(AssertionError):
            check_stale_disposition(self.lib_source, doubled, "pass")
        literal_prod = self.lib_source.replace(PROD_STATEMENT, PROD_STATEMENT.replace(
            "eliot_mcp::CONTRACT_REVISION", '"1.2.0"'), 1)
        with self.assertRaises(AssertionError):
            check_stale_disposition(literal_prod, self.test_item, "pass")

    # WORK_UNIT_CASE: 840/2
    def test_case_02_production_mcp_constant_still_delegates(self):
        """Production alias delegates to the canonical MCP owner, no literal."""
        alias = check_production_delegation(self.lib_source, self.mcp_source)
        self.assertEqual(alias, PROD_STATEMENT)
        literal_prod = self.lib_source.replace(PROD_STATEMENT, PROD_STATEMENT.replace(
            "eliot_mcp::CONTRACT_REVISION", '"1.2.0"'), 1)
        with self.assertRaises(AssertionError):
            check_production_delegation(literal_prod, self.mcp_source)
        bumped_owner = self.mcp_source.replace('"1.2.0"', '"9.9.9"', 1)
        with self.assertRaises(AssertionError):
            check_production_delegation(self.lib_source, bumped_owner)

    # WORK_UNIT_CASE: 840/3
    def test_case_03_no_second_mcp_literal_remains_in_test(self):
        """No second MCP version token remains inside the repaired test item."""
        asserts = check_no_second_literal(self.test_item)
        self.assertGreater(asserts, 0)
        mutated = self.test_item.replace(
            "        let providers",
            "        " + STALE_STATEMENT + "\n        let providers", 1)
        with self.assertRaises(AssertionError):
            check_no_second_literal(mutated)

    # WORK_UNIT_CASE: 840/4
    def test_case_04_catalogue_and_test_require_four_providers(self):
        """Count assertion and catalogue rows still require exactly four."""
        self.assertEqual(check_count_assertion(self.test_item), 4)
        self.assertEqual(check_provider_rows(self.providers_item), EXPECTED_ROWS)
        widened = self.test_item.replace(COUNT_ASSERT, COUNT_ASSERT.replace(", 4);", ", 5);"), 1)
        with self.assertRaises(AssertionError):
            check_count_assertion(widened)
        invented = self.providers_item.replace(
            "    ])",
            '        provider(\n            "C0-99",\n            "eliot-mcp",\n'
            '            "mcp",\n            "9.9.9",\n            "0" * 64,\n        ),\n    ])',
            1,
        )
        with self.assertRaises(AssertionError):
            check_provider_rows(invented)

    # WORK_UNIT_CASE: 840/5
    def test_case_05_nonempty_version_assertion_effective(self):
        """Nonempty version check is present and runs in the passing test."""
        self.assertTrue(check_version_assertion(self.test_item))
        self.assertEqual(self.exact_parsed.outcome, "pass")
        block = ("        assert!(\n            providers\n"
                 "                .iter()\n"
                 "                .all(|provider| " + VERSION_ASSERT + ")\n        );\n")
        self.assertIn(block, self.test_item)
        weakened = self.test_item.replace(block, "", 1)
        with self.assertRaises(AssertionError):
            check_version_assertion(weakened)

    # WORK_UNIT_CASE: 840/6
    def test_case_06_digest_assertion_effective(self):
        """64-character digest check is present and runs in the passing test."""
        self.assertTrue(check_digest_assertion(self.test_item))
        self.assertEqual(self.exact_parsed.outcome, "pass")
        block = ("        assert!(\n            providers\n"
                 "                .iter()\n"
                 "                .all(|provider| " + DIGEST_ASSERT + ")\n        );\n")
        self.assertIn(block, self.test_item)
        weakened = self.test_item.replace(block, "", 1)
        with self.assertRaises(AssertionError):
            check_digest_assertion(weakened)

    # WORK_UNIT_CASE: 840/7
    def test_case_07_no_mcp_provider_row_invented(self):
        """Catalogue gains no MCP provider row; exactly four provider calls."""
        self.assertEqual(check_no_mcp_row(self.providers_item), 4)
        invented = self.providers_item.replace(
            "    ])",
            '        provider(\n            "C0-99",\n            "eliot-mcp",\n'
            '            "mcp",\n            "9.9.9",\n            "0" * 64,\n        ),\n    ])',
            1,
        )
        with self.assertRaises(AssertionError):
            check_no_mcp_row(invented)

    # WORK_UNIT_CASE: 840/8
    def test_case_08_exact_rust_test_discovered_once_and_passes(self):
        """Fixed exact target is discovered once, passes, and is owner-verified."""
        dr.assert_no_workspace_wide(list(EXACT_ARGV))
        self.assertEqual(self.exact_parsed.identity, RUST_TEST_ID)
        self.assertEqual(self.exact_parsed.outcome, "pass")
        self.assertGreaterEqual(self.exact_discovered, 1)
        self.assertEqual(
            dr.phase_verdict("execute", self.exact_parsed.outcome), "green")
        with self.assertRaises(dr.RunnerInputError):
            dr.parse_rust_exact(
                self.exact_transcript, RUST_TEST_ID, 1, self.exact_discovered)
        self.assertEqual(dr.phase_verdict("execute", "failure"), "non-green")

    # WORK_UNIT_CASE: 840/9
    def test_case_09_package_suite_passes_and_failure_stays_non_green(self):
        """Current CLI package suite passes; failures can never read as green."""
        self.assertEqual(self.suite_returncode, 0)
        result_lines = [line for line in self.suite_output.decode("utf-8").splitlines()
                        if line.startswith("test result:")]
        self.assertGreater(len(result_lines), 0)
        for line in result_lines:
            self.assertIn("0 failed", line)
        self.assertIn(TEST_FN + " ... ok", self.suite_output.decode("utf-8"))
        with self.assertRaises(dr.RunnerInputError):
            dr.parse_rust_exact(
                self.exact_transcript, RUST_TEST_ID, 1, self.exact_discovered)
        self.assertEqual(dr.phase_verdict("execute", "failure"), "non-green")
        self.assertEqual(dr.phase_verdict("execute", "skip"), "non-green")

    # WORK_UNIT_CASE: 840/10
    def test_case_10_diff_is_sole_removal_plus_wrapper(self):
        """Product diff is only the stale-line removal; wrapper/marker only."""
        self.assertFalse((ROOT / Path(*MARKER_REL.split("/"))).exists())
        numstat = check_run_fixed(GIT_NUMSTAT_ARGV, 60)
        diff = check_run_fixed(GIT_DIFF_LIB_ARGV, 60)
        status = check_run_fixed(GIT_STATUS_ARGV, 60)
        if diff.stdout.strip():
            self.assertTrue(check_lib_diff_text(diff.stdout.decode("utf-8")))
            self.assertTrue(check_lib_numstat(numstat.stdout.decode("utf-8")))
            self.assertTrue(check_status_text(status.stdout.decode("utf-8")))
        else:
            ranged = check_run_fixed(GIT_RANGE_NUMSTAT_ARGV, 60)
            self.assertTrue(check_range_numstat(ranged.stdout.decode("utf-8")))
            self.assertEqual(status.stdout.strip(), b"")
        with self.assertRaises(AssertionError):
            check_lib_diff_text(
                diff.stdout.decode("utf-8") + "+        bogus = 1;\n")
        with self.assertRaises(AssertionError):
            check_lib_numstat("1\t1\t" + LIB_RS_REL + "\n")
        with self.assertRaises(AssertionError):
            check_status_text(
                " M " + LIB_RS_REL + "\n M other/file.rs\n")
