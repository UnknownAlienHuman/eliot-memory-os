"""Bounded read-only validator checks for the Host diagnostic coverage table (#985).

Issue #985 exclusive scope, work item W2: the reviewed table and this validator
have no offline unit test, so every negative contract in
``scripts/audit_host_diagnostic_coverage.py`` was reachable only by mutating the
live Host tree. These checks run the validator against a frozen synthetic tree
under ``scripts/testdata/host-diagnostic-coverage/synthetic/``, copied into a
temporary root per test. The synthetic tree is test input only: it is never the
reviewed production table (that stays at the validator's fixed
``scripts/testdata/host-diagnostic-coverage/coverage.toml`` path) and it never
claims live repository status.

Baseline: the synthetic tree is INCOMPLETE with zero stale findings - two sink
delivery boundaries stay honestly incomplete because the fixture has no
reachable Event Log seam. Every negative below proves one fail-closed contract
of the validator, never a hand-authored flag.

Run from the repository root:

    python -m unittest scripts.tests.test_host_diagnostic_coverage -v
"""

from __future__ import annotations

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts import audit_host_diagnostic_coverage as audit

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_REL = "scripts/testdata/host-diagnostic-coverage/synthetic"
FIXTURE_ROOT = REPO_ROOT / FIXTURE_REL
TABLE_REL = audit.TABLE_REL

SRC = "bins/eliot-host/src"
TESTS = "bins/eliot-host/tests"
SYNTH_TESTS = f"{TESTS}/host_synthetic_diagnostics.rs"
SYNTH_TABLE = f"{FIXTURE_REL}/{TABLE_REL}"

FACADE = f"{SRC}/host_diagnostics.rs"
LIB_RS = f"{SRC}/lib.rs"
MAIN_RS = f"{SRC}/main.rs"
SINK_RS = f"{SRC}/host_sink.rs"
CONSOLE_RS = f"{SRC}/host_console.rs"
RECOVERY_RS = f"{SRC}/host_recovery.rs"
ARTIFACT_RS = f"{SRC}/host_launch_artifact.rs"
MANIFEST = "bins/eliot-host/Cargo.toml"

# The frozen synthetic denominator, asserted so a fixture cannot grow silently.
FROZEN_FIXTURE_FILES = (
    f"{SRC}/host_console.rs",
    f"{SRC}/host_diagnostics.rs",
    f"{SRC}/host_launch_artifact.rs",
    f"{SRC}/host_launch_options.rs",
    f"{SRC}/host_launch_options_tests.rs",
    f"{SRC}/host_receipt.rs",
    f"{SRC}/host_recovery.rs",
    f"{SRC}/host_sink.rs",
    f"{SRC}/lib.rs",
    f"{SRC}/main.rs",
    SYNTH_TESTS,
    MANIFEST,
    TABLE_REL,
)

ZERO_DIGEST = "0" * 64

# The production-shaped `tracing` use every facade-bypass control injects. It is
# a real macro call, never a comment: a comment exercises the comment skip, not
# the cfg-scoped exemption the check exists to prove.
TRACING_USE = 'tracing::info!("leaked");'


def replace_once(text: str, old: str, new: str) -> str:
    """Replace exactly one occurrence, refusing an ambiguous or absent anchor."""
    count = text.count(old)
    if count != 1:
        raise AssertionError(f"anchor is not unique ({count}): {old!r}")
    return text.replace(old, new)


def boundary_span(text: str, boundary_id: str) -> tuple[int, int]:
    """Byte range of one ``[[boundary]]`` block inside a rendered table."""
    marker = f'[[boundary]]\nid = "{boundary_id}"\n'
    start = text.index(marker)
    following = text.find("\n[[boundary]]\n", start + 1)
    return start, len(text) if following < 0 else following + 1


def edit_boundary(text: str, boundary_id: str, old: str, new: str) -> str:
    """Apply one replacement inside a single boundary block only."""
    start, end = boundary_span(text, boundary_id)
    return text[:start] + replace_once(text[start:end], old, new) + text[end:]


def add_to_boundary(text: str, boundary_id: str, line: str) -> str:
    """Insert one extra key into a boundary block, before its sub-tables."""
    start, end = boundary_span(text, boundary_id)
    block = text[start:end]
    anchor = first_line(block, "ceiling_detail_bytes")
    return text[:start] + replace_once(block, anchor + "\n", anchor + "\n" + line) + text[end:]


def repin_span(root: Path, text: str, boundary_id: str, tag: str, start: int, end: int) -> str:
    """Repoint one recorded span at ``start``-``end`` with a recomputed digest.

    The digest is recomputed from the frozen source with the validator's own
    span helper, so a mutation can isolate a content rule from digest staleness.
    """
    start_idx, end_idx = boundary_span(text, boundary_id)
    block = text[start_idx:end_idx]
    source = (root / boundary_file(block)).read_text(encoding="utf-8").split("\n")
    digest = audit.span_digest_from_lines(source, start, end)
    head, sep, tail = block.partition(f"[[boundary.{tag}]]")
    body = sep + tail
    body = replace_once(body, first_line(body, "start"), f"start = {start}")
    body = replace_once(body, first_line(body, "end"), f"end = {end}")
    body = replace_once(body, first_line(body, "digest"), f'digest = "{digest}"')
    return text[:start_idx] + head + body + text[end_idx:]


def first_line(block: str, key: str) -> str:
    """The first ``key = ...`` line of a boundary block, verbatim."""
    for line in block.split("\n"):
        if line.startswith(f"{key} = "):
            return line
    raise AssertionError(f"no {key} line in the boundary block")


def boundary_file(block: str) -> str:
    """Source path recorded by one boundary block."""
    for line in block.split("\n"):
        if line.startswith("file = "):
            return line.split('"')[1]
    raise AssertionError("no file line in the boundary block")


def input_paths(table_text: str) -> list[str]:
    """Input paths declared by a rendered table (line-oriented, no TOML writer)."""
    lines = table_text.split("\n")
    return [
        lines[index + 1].split('"')[1]
        for index, line in enumerate(lines[:-1])
        if line == "[[input]]"
    ]


def line_of(text: str, needle: str) -> int:
    """1-based line number of ``needle`` in ``text``, refusing an absent anchor."""
    offset = text.find(needle)
    if offset < 0:
        raise AssertionError(f"anchor absent: {needle!r}")
    return text.count("\n", 0, offset) + 1


def duplicate_input(text: str, rel: str) -> str:
    """Copy one ``[[input]]`` entry in place, producing a duplicate declaration."""
    lines = text.split("\n")
    for index, line in enumerate(lines):
        if line == f'path = "{rel}"' and lines[index - 1] == "[[input]]":
            block = lines[index - 1:index + 2]
            return "\n".join(lines[:index - 1] + block + block + lines[index + 2:])
    raise AssertionError(f"no [[input]] entry for {rel}")


class SyntheticCoverageTests(unittest.TestCase):
    """Each test materializes the frozen synthetic tree into its own root."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="eliot-985-coverage-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        shutil.copytree(FIXTURE_ROOT, self.root, dirs_exist_ok=True)

    # ------------------------------------------------------------- helpers

    def verdict(self, root: Path | None = None, fmt: str = "text") -> tuple[int, str]:
        """Run the validator's closed CLI and return (exit code, rendered text)."""
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = audit.main(["--root", str(root or self.root), "--format", fmt])
        return code, buffer.getvalue()

    def read(self, rel: str) -> str:
        return (self.root / rel).read_text(encoding="utf-8")

    def write(self, rel: str, text: str) -> None:
        # newline="" keeps the mutated source byte-exact apart from the mutation.
        (self.root / rel).write_text(text, encoding="utf-8", newline="")

    def write_table(self, text: str) -> None:
        self.write(TABLE_REL, text)

    def assert_stale(self, needle: str) -> None:
        code, rendered = self.verdict()
        self.assertEqual(code, audit.EXIT_CODES["STALE"], rendered)
        self.assertIn(needle, rendered)

    def inject(self, rel: str, block: str) -> int:
        """Append ``block`` to a tracked fixture file; return the injected line."""
        text = self.read(rel) + block
        self.write(rel, text)
        return line_of(text, TRACING_USE)

    def inject_top(self, rel: str, block: str) -> int:
        """Insert ``block`` as the first item of a tracked fixture file.

        The block lands after the leading ``//!`` header and before every other
        item, so it sits above any ``#[cfg(...)]`` gate the file already owns.
        """
        lines = self.read(rel).split("\n")
        head = 0
        while lines[head].startswith("//!"):
            head += 1
        text = "\n".join(lines[:head] + block.rstrip("\n").split("\n") + lines[head:])
        self.write(rel, text)
        return line_of(text, TRACING_USE)

    def assert_scan_silent(self, rel: str) -> None:
        """The mutation landed and was scanned, yet the bypass scan stayed silent.

        Asserting the digest staleness alongside the silence is what makes this
        control meaningful: without it, a mutation that never reached the scan
        would satisfy a bare "not reported" assertion for the wrong reason.
        """
        code, rendered = self.verdict()
        self.assertEqual(code, audit.EXIT_CODES["STALE"], rendered)
        self.assertIn(f"file digest mismatch (stale table): {rel}", rendered)
        self.assertNotIn("tracing use outside facade", rendered)

    # --------------------------------------------------------- positive side

    def test_synthetic_baseline_is_honest_incomplete_without_stale(self) -> None:
        code, rendered = self.verdict()
        self.assertEqual(code, audit.EXIT_CODES["INCOMPLETE"], rendered)
        self.assertIn("files=10 boundaries=11 proven=9 incomplete=2 stale=0", rendered)
        self.assertNotIn("STALE ", rendered)

    def test_synthetic_json_renders_from_the_same_validated_result(self) -> None:
        import json

        code, rendered = self.verdict(fmt="json")
        payload = json.loads(rendered)
        self.assertEqual(code, audit.EXIT_CODES["INCOMPLETE"])
        self.assertEqual(payload["schema"], audit.SCHEMA)
        self.assertEqual(payload["verdict"], "INCOMPLETE")
        self.assertEqual(payload["counts"], {"files": 10, "boundaries": 11})
        self.assertEqual(payload["stale"], [])
        self.assertEqual(
            sorted(item["id"] for item in payload["incomplete"]),
            ["S-sink-start-delivery", "S-sink-stop-delivery"],
        )

    def test_synthetic_incompletes_name_their_owner_and_reason(self) -> None:
        _code, rendered = self.verdict()
        self.assertIn(
            "INCOMPLETE S-sink-start-delivery [host_seam_unavailable] owner=984", rendered
        )
        self.assertIn(
            "INCOMPLETE S-sink-stop-delivery [host_seam_unavailable] owner=984", rendered
        )

    def test_fixture_file_denominator_is_frozen(self) -> None:
        present = sorted(
            str(path.relative_to(self.root)).replace("\\", "/")
            for path in self.root.rglob("*")
            if path.is_file()
        )
        self.assertEqual(present, sorted(FROZEN_FIXTURE_FILES))

    def test_synthetic_table_is_not_the_reviewed_production_table(self) -> None:
        self.assertTrue((REPO_ROOT / TABLE_REL).is_file())
        self.assertTrue((FIXTURE_ROOT / TABLE_REL).is_file())
        self.assertNotEqual(
            (REPO_ROOT / TABLE_REL).read_bytes(), (FIXTURE_ROOT / TABLE_REL).read_bytes()
        )

    def test_validator_reads_its_fixed_table_path_only(self) -> None:
        table = self.read(TABLE_REL)
        self.assertNotIn(TABLE_REL, input_paths(table))
        self.assertEqual(audit.TABLE_REL, TABLE_REL)

    # ----------------------------------------------------------- negative side

    def test_missing_table_fails_closed(self) -> None:
        (self.root / TABLE_REL).unlink()
        self.assert_stale(f"missing table: {TABLE_REL}")

    def test_malformed_table_fails_closed(self) -> None:
        self.write_table("schema = \n")
        self.assert_stale("malformed table:")

    def test_schema_identity_drift_fails_closed(self) -> None:
        self.write_table(replace_once(self.read(TABLE_REL), "issue = 985", "issue = 984"))
        self.assert_stale("issue must be 985")

    def test_source_mutation_stales_the_file_digest(self) -> None:
        self.write(SINK_RS, self.read(SINK_RS) + "\n// mutated by a negative check\n")
        self.assert_stale(f"file digest mismatch (stale table): {SINK_RS}")

    def test_untracked_source_file_fails_closed(self) -> None:
        new = self.root / SRC / "host_untracked.rs"
        new.write_text("//! untracked synthetic source\n", encoding="utf-8")
        self.assert_stale("untracked-by-table source file (new/moved source)")

    def test_reconciliation_count_drift_fails_closed(self) -> None:
        self.write_table(replace_once(self.read(TABLE_REL), "current_count = 10", "current_count = 11"))
        self.assert_stale("reconciliation.current_count != len([[file]])")

    def test_input_digest_mismatch_fails_closed(self) -> None:
        table = self.read(TABLE_REL)
        marker = f'path = "{SYNTH_TESTS}"\nsha256 = "'
        head, _, tail = table.partition(marker)
        flipped = "0" if tail[0] != "0" else "1"
        self.write_table(head + marker + flipped + tail[1:])
        self.assert_stale(f"input digest mismatch (stale table): {SYNTH_TESTS}")

    def test_duplicate_input_fails_closed(self) -> None:
        self.write_table(duplicate_input(self.read(TABLE_REL), MANIFEST))
        self.assert_stale(f"duplicate input: {MANIFEST}")

    def test_table_listed_in_its_own_inputs_fails_closed(self) -> None:
        table = self.read(TABLE_REL)
        anchor = f'[[input]]\npath = "{SYNTH_TESTS}"'
        injected = f'[[input]]\npath = "{TABLE_REL}"\nsha256 = "{ZERO_DIGEST}"\n\n'
        self.write_table(replace_once(table, anchor, injected + anchor))
        self.assert_stale("table must be excluded from its own input digests")

    def test_duplicate_boundary_id_fails_closed(self) -> None:
        table = edit_boundary(self.read(TABLE_REL), "S-facade-entrypoint", 'id = "S-facade-entrypoint"', 'id = "S-facade-singleton"')
        self.write_table(table)
        self.assert_stale("duplicate boundary id: S-facade-singleton")

    def test_terminal_code_designated_twice_fails_closed(self) -> None:
        table = edit_boundary(self.read(TABLE_REL), "S-lib-start-result", "start_result_failed", "start_request_failed")
        table = edit_boundary(table, "S-lib-start-result", "HOST_TERMINAL_CODE_START_RESULT", "HOST_TERMINAL_CODE_START_REQUEST")
        self.write_table(table)
        self.assert_stale("code 'start_request_failed' designated by both")

    def test_matrix_case_coverage_drift_fails_closed(self) -> None:
        self.write_table(replace_once(self.read(TABLE_REL), "n = 7", "n = 19"))
        self.assert_stale("matrix must cover exactly cases 1..18")

    def test_unknown_exclusion_kind_fails_closed(self) -> None:
        self.write_table(replace_once(self.read(TABLE_REL), 'exclusion = "facade"', 'exclusion = "behavior"'))
        self.assert_stale("unknown exclusion 'behavior'")

    def test_facade_exclusion_containing_behavior_fails_closed(self) -> None:
        self.write(ARTIFACT_RS, self.read(ARTIFACT_RS) + "\nfn synthetic_helper() {}\n")
        self.assert_stale(f"{ARTIFACT_RS}: facade contains a fn definition (exclusion lost)")

    def test_test_only_exclusion_without_test_cfg_fails_closed(self) -> None:
        self.write_table(replace_once(self.read(TABLE_REL), 'cfg = "test"', 'cfg = "always"'))
        self.assert_stale("test_only exclusion without a test cfg")

    def test_proven_boundary_without_test_binding_fails_closed(self) -> None:
        table = self.read(TABLE_REL)
        block = f'[[boundary.test]]\nfile = "{SYNTH_TESTS}"\ncase = "facade_singleton_bound"\n\n'
        self.write_table(replace_once(table, block, ""))
        self.assert_stale("proven boundary without a test binding")

    def test_test_binding_outside_the_fixed_roots_fails_closed(self) -> None:
        table = edit_boundary(self.read(TABLE_REL), "S-facade-singleton", SYNTH_TESTS, "scripts/other.rs")
        self.write_table(table)
        self.assert_stale("test file outside fixed roots")

    def test_missing_test_case_function_fails_closed(self) -> None:
        table = edit_boundary(self.read(TABLE_REL), "S-facade-singleton", "facade_singleton_bound", "no_such_case")
        self.write_table(table)
        self.assert_stale("test case fn no_such_case missing")

    def test_changed_pin_line_fails_closed(self) -> None:
        table = edit_boundary(self.read(TABLE_REL), "S-facade-singleton", "line = 9", "line = 10")
        self.write_table(table)
        self.assert_stale(f"pin text changed at {MAIN_RS}:10")

    def test_unexpected_zeroscan_site_fails_closed(self) -> None:
        scan = (
            'zeroscan = [{ ident = "reject_installation", '
            f'allowed = ["{RECOVERY_RS}:999"] }}]\n'
        )
        self.write_table(add_to_boundary(self.read(TABLE_REL), "S-facade-singleton", scan))
        self.assert_stale("zeroscan reject_installation: unexpected")

    def test_terminal_ref_cycle_fails_closed(self) -> None:
        cycle = 'terminals = ["S-lib-start-result"]\n'
        self.write_table(add_to_boundary(self.read(TABLE_REL), "S-lib-start-result", cycle))
        self.assert_stale("terminal ref cycle: S-lib-start-result -> S-lib-start-result")

    def test_external_caller_path_escape_fails_closed(self) -> None:
        escape = f'ext_caller = {{ file = "../outside.rs", start = 1, end = 2, digest = "{ZERO_DIGEST}" }}\n'
        self.write_table(add_to_boundary(self.read(TABLE_REL), "S-facade-singleton", escape))
        self.assert_stale("ext_caller path escapes root: ../outside.rs")

    def test_sink_reason_outside_a_sink_fails_closed(self) -> None:
        table = edit_boundary(self.read(TABLE_REL), "S-console-terminal", 'status = "proven"', 'status = "incomplete"\nreason = "host_seam_unavailable"')
        self.write_table(table)
        self.assert_stale("host_seam_unavailable is sink-only")

    def test_missing_callsite_without_absence_span_fails_closed(self) -> None:
        table = edit_boundary(self.read(TABLE_REL), "S-sink-stop-delivery", "host_seam_unavailable", "missing_callsite")
        self.write_table(table)
        self.assert_stale("missing_callsite needs an absence span")

    def test_incomplete_delivery_claiming_tests_fails_closed(self) -> None:
        binding = f'[[boundary.test]]\nfile = "{SYNTH_TESTS}"\ncase = "scm_receipt_bound"\n\n'
        table = replace_once(
            self.read(TABLE_REL),
            '[[boundary]]\nid = "S-sink-stop-delivery"',
            binding + '[[boundary]]\nid = "S-sink-stop-delivery"',
        )
        self.write_table(table)
        self.assert_stale("S-sink-start-delivery incomplete delivery must not claim tests")

    # The `B-facade-singleton` bypass scan is a PRODUCTION-contour check with two
    # exemptions: a full-line comment, and a `cfg`-gated region the admitted cfg
    # vocabulary resolves as test-only. A comment control can only ever exercise
    # the first exemption, so the controls below all inject a real production
    # `tracing::info!` line. Each one also asserts the exact `path:line`, which
    # is what pins the report to the injected use rather than to some other
    # finding in the same run.

    def test_tracing_use_outside_the_facade_fails_closed(self) -> None:
        line = self.inject(CONSOLE_RS, f"\n{TRACING_USE}\n")
        self.assert_stale(f"tracing use outside facade: {CONSOLE_RS}:{line}")

    def test_tracing_use_in_a_recognised_test_cfg_is_silent(self) -> None:
        """``#[cfg(all(test, windows))]`` is admitted vocabulary: test-only.

        This is the positive half of the exemption. Its discriminating power is
        only real because the fail-closed control below pins the opposite
        verdict for an unrecognised cfg carrying the same ``test`` predicate.
        """
        line = self.inject(
            LIB_RS,
            "\n#[cfg(all(test, windows))]\nmod synthetic_capture {\n"
            f"    {TRACING_USE}\n"
            "}\n",
        )
        self.assertGreater(line, line_of(self.read(LIB_RS), "#[cfg(all(test, windows))]"))
        self.assert_scan_silent(LIB_RS)

    def test_tracing_use_in_an_unrecognised_test_cfg_still_fails_closed(self) -> None:
        """The fail-closed property: an unfamiliar cfg cannot widen the exemption.

        ``#[cfg(all(test, feature = "..."))]`` is outside the admitted vocabulary,
        so the scanner must treat it as NOT test-only and report the use. A
        scanner that widened the exemption on any ``test``-bearing attribute
        would pass the recognised-cfg control above and fail this one, so the
        pair distinguishes "recognised test cfg" from "unrecognised cfg".
        """
        line = self.inject(
            LIB_RS,
            "\n#[cfg(all(test, feature = \"synthetic-capture\"))]\n"
            "mod synthetic_capture {\n"
            f"    {TRACING_USE}\n"
            "}\n",
        )
        self.assert_stale(f"tracing use outside facade: {LIB_RS}:{line}")

    def test_tracing_use_under_a_non_test_cfg_is_reported(self) -> None:
        """``#[cfg(windows)]`` is admitted vocabulary but not test-only.

        This is the recognised-cfg counterpart to the fail-closed control: the
        exemption keys on ``test`` being provably required, not on the cfg being
        one the parser happens to accept.
        """
        line = self.inject(
            LIB_RS,
            "\n#[cfg(windows)]\nmod synthetic_probe {\n"
            f"    {TRACING_USE}\n"
            "}\n",
        )
        self.assert_stale(f"tracing use outside facade: {LIB_RS}:{line}")

    def test_tracing_use_in_a_doc_comment_is_silent(self) -> None:
        """A doc comment describing the seam is not a production use."""
        self.write(
            CONSOLE_RS,
            self.read(CONSOLE_RS)
            + f"\n/// Emits via {TRACING_USE} in the console contour.\n",
        )
        self.assert_scan_silent(CONSOLE_RS)

    def test_tracing_use_above_a_test_gate_is_reported(self) -> None:
        """The exemption cannot leak upward past the gated item it belongs to.

        ``lib.rs`` already owns a ``#[cfg(test)] mod`` below its production
        items. Injecting the production use at the very top of the same file
        puts it above that gate, so a scanner that widened the exemption to the
        whole file (or leaked it upward) would go silent here.
        """
        line = self.inject_top(
            LIB_RS,
            "fn synthetic_console_probe() {\n"
            f"    {TRACING_USE}\n"
            "}\n",
        )
        self.assertLess(line, line_of(self.read(LIB_RS), "#[cfg(test)]"))
        self.assert_stale(f"tracing use outside facade: {LIB_RS}:{line}")

    def test_host_consuming_the_platform_port_fails_closed(self) -> None:
        self.write(SINK_RS, self.read(SINK_RS) + "\npub use platform_windows::event_log::EventLogSink;\n")
        self.assert_stale("Host now consumes the platform port")

    def test_manifest_enabling_the_event_log_feature_fails_closed(self) -> None:
        self.write(MANIFEST, self.read(MANIFEST) + '\nwinapi = { features = ["Win32_System_EventLog"] }\n')
        self.assert_stale("Host manifest now enables Win32_System_EventLog")

    def test_lost_subscriber_singularity_fails_closed(self) -> None:
        self.write(
            MAIN_RS,
            self.read(MAIN_RS).replace(
                "fn main() {", "fn main() {\n    eliot_host::host_diagnostics::install_host_diagnostics();", 1
            ),
        )
        self.assert_stale("install_host_diagnostics singularity lost in main.rs")

    def test_entrypoint_site_carrying_a_terminal_pattern_fails_closed(self) -> None:
        table = repin_span(self.root, self.read(TABLE_REL), "S-facade-entrypoint", "site", 37, 39)
        self.write_table(table)
        self.assert_stale("entrypoint site contains terminal pattern 'observe_terminal'")

    def test_absence_span_that_now_carries_a_pattern_fails_closed(self) -> None:
        self.write(
            RECOVERY_RS,
            self.read(RECOVERY_RS).replace(
                "use crate::host_launch_options::reject_installation;",
                "use crate::{host_diagnostics::observe_entrypoint, host_launch_options::reject_installation};",
            ),
        )
        table = repin_span(self.root, self.read(TABLE_REL), "S-recovery-propagated", "absence", 6, 7)
        self.write_table(table)
        self.assert_stale("absence span now contains 'observe_entrypoint'")

    def test_boundary_site_digest_mismatch_fails_closed(self) -> None:
        table = edit_boundary(self.read(TABLE_REL), "S-facade-singleton", "start = 27", "start = 26")
        self.write_table(table)
        self.assert_stale("site digest mismatch at")


if __name__ == "__main__":
    unittest.main()
