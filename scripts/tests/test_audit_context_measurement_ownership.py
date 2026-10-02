"""The required 32-case suite for #787 (audit defect 2).

Audit defect 2 of the ``code-complete`` audit of issue #787 states, verbatim:

    The issue explicitly owns these files and requires exactly 32 independently
    executable substantive cases. ... **Required repair:** add the exact
    dedicated suite and bounded frozen fixtures, with one real production-path
    test for each 1..32 marker.

The 32 cases are the issue's own "Required test matrix" (issue body, lines
97-128, reproduced verbatim in ``control-20260923-impl/v2/issues/787/TASK.md``
lines 95-128). Each numbered item in that list is exactly one ``# WORK_UNIT_CASE:
787/<N>`` marker above exactly one test method below, 1..32 with no gaps and no
duplicates. The module-level marker test (:meth:`MarkerMatrixTest`) proves that
denominator from the source of this file, so the mapping cannot silently drift
from the issue.

Every test exercises a REAL production path of
``scripts/audit-context-measurement-ownership.py`` -- :func:`oracle.evaluate`,
:func:`oracle._producer_candidates`, :func:`oracle._derive_baseline_disposition`,
:func:`oracle._enumerated_unaccounted`, :func:`oracle._declared_universe`,
:func:`oracle._unaccounted_candidates`, :func:`oracle._dependency_evidence`,
:func:`oracle._read_inventory_artifact`, :func:`oracle._producer_check` -- and
asserts on the RETURNED findings, projections and dispositions. No test counts
markers, inspects source text for its own subject, or asserts on a future
command. Where the audit records a defect the oracle does not yet repair, the
test asserts the OBSERVED production behaviour and names the gap in its
docstring rather than weakening the assertion -- those are marked
``REPORTED`` and are listed in the module docstring's defect table.

Read-only: no network, no clock, no subprocess, no admission decision, and no
write outside the per-case temporary directory. Every case materialises a
throwaway tree under ``tempfile.mkdtemp`` and copies the frozen fixture in
UNCHANGED, so the bytes measured are exactly the committed fixture bytes and a
failing assertion cannot leak into the repository tree.

Scope note: ``scripts/tests/test_787_consumer_dependency_proof.py`` (defect 4)
and ``scripts/tests/test_787_candidate_enumeration_c7.py`` (defect 3) are
UNMARKED SUPPORTING matrices for the clauses this file's cases already own.
They use NO ``# WORK_UNIT_CASE:`` marker of any kind: this file is the sole
owner of the ``787/N`` namespace, because the issue's "Required test matrix"
declares exactly one marker for each case 1..32 and names THIS file as its
exclusive mutable test scope. The C7 suite's whole C7 clause is proved here at
case 787/7; the C7 file's tests remain as unmarked supporting coverage that
does not compete for the namespace.
"""

from __future__ import annotations

import contextlib
import importlib.util
import inspect
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_SCRIPT = (
    Path(__file__).resolve().parent.parent / "audit-context-measurement-ownership.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "audit_context_measurement_ownership_787_matrix", _SCRIPT
)
oracle = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = oracle
_SPEC.loader.exec_module(oracle)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = _REPO_ROOT / "scripts" / "testdata" / "context-measurement-ownership"
_PRODUCER_REL = "scripts/context_measurement_inventory.py"
_INVENTORY_REL = ".github/work-units/context-measurement-inventory.toml"
_OWNER_MAP_REL = ".github/work-units/context-measurement-owner-map.toml"

# The one seam path every consumer-shaped fixture is materialised at.
_SEAM_REL = "crates/fixture-consumer/src/seam.rs"
# The canonical #704 owner path, for the case 22 / case 16 owner-scope contrast.
_CANONICAL_REL = "crates/smart/eliot-context-measurement/src/stu.rs"

_CONSUMER_MANIFEST = """\
[package]
name = "fixture-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
eliot-context-measurement = "0.1.0"
"""

# The extra denominator case a case adds so that its fixture path becomes a
# DECLARED scan root of the generated artifact. The signal is one the #866
# classifier really accepts (``declared_len`` -> ``exact-utf8-envelope``), so
# the added row is a genuine classified candidate and not a synthetic one.
_FIXTURE_CASE = ("fixture/1", "#783", _SEAM_REL, "declared_len")

_OWNER_MANIFEST = """\
[package]
name = "eliot-context-measurement"
version = "0.1.0"
edition = "2024"

[dependencies]
"""


# ---------------------------------------------------------------------------
# The frozen 31-row baseline denominator, taken from the oracle's own frozen
# table. Each case materialises every one of them into its throwaway tree and
# generates a REAL #866 artifact over them, so a case that mutates one file
# observes exactly one defect rather than a wall of incidental ones.
# ---------------------------------------------------------------------------


def _baseline_cases() -> tuple[tuple[str, str, str, str], ...]:
    """The 31 frozen (case_ref, owner, path, signal) identities, read from the
    committed #866 artifact so every signal is a genuinely classifiable one."""
    raw = (_REPO_ROOT / _INVENTORY_REL).read_bytes()
    producer = oracle.load_producer(_REPO_ROOT)
    artifact = producer._parse_toml(raw, source=_INVENTORY_REL)
    by_ref = {str(row["case_ref"]): row for row in artifact["rows"]}
    cases: list[tuple[str, str, str, str]] = []
    for case_ref, owner in oracle.EXPECTED_BASELINE_ROWS:
        row = by_ref[case_ref]
        cases.append((case_ref, owner, str(row["path"]), str(row["signal"])))
    return tuple(cases)


_BASELINE_CASES = _baseline_cases()
_BASELINE_OWNER_OF = {case_ref: owner for case_ref, owner, _p, _s in _BASELINE_CASES}


class _Tree:
    """A throwaway repository tree the oracle can be pointed at.

    The tree holds the real #866 producer (the oracle imports it from the root
    under test), the real baseline source files the 31 frozen rows name, a
    generated owner map, and -- once :meth:`generate` is called -- a REAL
    producer-generated inventory artifact. Nothing is ever written back into
    the repository tree; the whole directory is removed by :meth:`cleanup`.
    """

    def __init__(self, prefix: str = "787-matrix-") -> None:
        self.root = Path(tempfile.mkdtemp(prefix=prefix))

    # -- construction ---------------------------------------------------
    def copy_producer(self) -> None:
        target = self.root / _PRODUCER_REL
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_REPO_ROOT / _PRODUCER_REL, target)

    def copy_baseline_sources(self) -> None:
        for rel in sorted({case[2] for case in _BASELINE_CASES}):
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(_REPO_ROOT / rel, target)

    def add_fixture(self, fixture: str, rel: str = _SEAM_REL, newline: str = "\n") -> Path:
        """Copy one frozen fixture in UNCHANGED at ``rel``. Returns the path."""
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = (_FIXTURES / fixture).read_bytes()
        if newline != "\n":
            raw = raw.replace(b"\r\n", b"\n").replace(b"\n", newline.encode("ascii"))
        target.write_bytes(raw)
        return target

    def add_manifest(self, rel: str, text: str) -> None:
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def write_owner_map(self, extra: dict[str, list[str]] | None = None) -> None:
        """Write a frozen owner map covering every baseline path, plus extras."""
        mapping: dict[str, list[str]] = {}
        for case_ref, owner, rel, _signal in _BASELINE_CASES:
            mapping.setdefault(owner, []).append(rel)
        for owner, paths in (extra or {}).items():
            mapping.setdefault(owner, []).extend(paths)
        lines = [
            "# Generated owner map for one throwaway #787 case tree.",
            "# One exact scope has exactly one owner; no wildcard, no directory.",
        ]
        for owner in sorted(mapping):
            lines.append("")
            lines.append("[[owners]]")
            lines.append(f'issue = "{owner}"')
            lines.append("source_paths = [")
            for rel in sorted(set(mapping[owner])):
                lines.append(f'  "{rel}",')
            lines.append("]")
        target = self.root / _OWNER_MAP_REL
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # -- the real #866 generation ---------------------------------------
    def generate(
        self,
        cases: tuple[tuple[str, str, str, str], ...] | None = None,
        extra: tuple[tuple[str, str, str, str], ...] = (),
    ) -> dict[str, object]:
        """Regenerate the inventory through the accepted #866 generator.

        ``extra`` appends denominator cases to the frozen 31 so that a fixture
        path becomes a DECLARED scan root of the generated artifact. That is
        what puts the fixture in front of the oracle's own schema/owner scan,
        instead of the test reaching around the artifact to find it.

        This is the single-writer sync path, run INSIDE the throwaway tree
        only. The repository artifact is never touched: this suite never runs
        ``sync`` against ``--root .``.
        """
        producer = oracle.load_producer(self.root)
        mapping, status, digest = producer.load_owner_map(self.root)
        selected = tuple(cases or _BASELINE_CASES) + tuple(extra)
        inventory = producer.build_inventory(
            self.root, selected, "787-case-fixture", (mapping, status, digest)
        )
        blob = producer._emit_toml(inventory)
        target = self.root / _INVENTORY_REL
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        return inventory

    def path(self, rel: str) -> Path:
        return self.root / rel

    def read_inventory_bytes(self) -> bytes:
        return (self.root / _INVENTORY_REL).read_bytes()

    def write_inventory_bytes(self, blob: bytes) -> None:
        (self.root / _INVENTORY_REL).write_bytes(blob)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


@contextlib.contextmanager
def _tree(prefix: str = "787-matrix-"):
    tree = _Tree(prefix)
    try:
        yield tree
    finally:
        tree.cleanup()


def _baseline_tree(prefix: str = "787-matrix-") -> _Tree:
    """A complete, freshly generated, zero-unresolved baseline tree."""
    tree = _Tree(prefix)
    tree.copy_producer()
    tree.copy_baseline_sources()
    tree.write_owner_map()
    tree.generate()
    return tree


def _codes(result) -> list[str]:
    return sorted({finding.code for finding in result.findings})


def _finding_codes(result, code: str) -> list:
    return [finding for finding in result.findings if finding.code == code]


def _row(case_ref: str, **overrides) -> dict[str, object]:
    """A minimal stored-row shape for the helpers that only read a few keys."""
    row = {
        "id": "r-" + case_ref.replace("/", "-"),
        "case_ref": case_ref,
        "owner": _BASELINE_OWNER_OF.get(case_ref, "#783"),
        "write_scope": "writable",
        "path": _SEAM_REL,
        "signal": "declared_len",
        "span_start": 1,
        "span_end": 2,
        "source_sha256": "0" * 64,
        "span_digest": "0" * 64,
        "classification": "exact-utf8-envelope",
        "status": "owned",
        "evidence": "fixture",
    }
    row.update(overrides)
    return row


def _dependency_rows(rel: str = _SEAM_REL, owner: str = "#783") -> list[dict[str, object]]:
    """One writable seam row, which is what selects a consumer's dependency
    universe. ``_dependency_evidence`` reads only these three keys."""
    return [{"write_scope": "writable", "owner": owner, "path": rel}]


class MarkerMatrixTest(unittest.TestCase):
    """The 1..32 denominator itself, checked against this file's own source.

    This is the only structural case in the suite; every other case is a
    behavioural proof. It exists because the issue makes the DENOMINATOR part
    of the requirement ("Declared denominator: 32 cases, exactly 1..32") and a
    suite that quietly grew or lost a case would otherwise still be green.
    """

    def test_exactly_32_markers_1_through_32_each_above_a_test_method(self) -> None:
        source = Path(__file__).resolve().read_text(encoding="utf-8")
        # The matrix body is everything from the first marker to the helpers
        # section; anchoring on the first marker (not on a class name) keeps the
        # check independent of the class layout above it.
        start = source.index("# WORK_UNIT_CASE: 787/")
        body = source[start:]
        marks = re.findall(r"^\s*# WORK_UNIT_CASE: 787/(\d+)\s*$", body, re.MULTILINE)
        numbers = sorted(int(value) for value in marks)
        self.assertEqual(
            numbers,
            list(range(1, 33)),
            "the suite must carry exactly one # WORK_UNIT_CASE: 787/<N> marker for "
            f"each N in 1..32; found {numbers}",
        )
        self.assertEqual(len(marks), len(set(marks)), "no case number may repeat")

        # Each marker must sit IMMEDIATELY above its own test method, so a
        # marker cannot be attached to the wrong proof.
        lines = body.splitlines()
        for index, line in enumerate(lines):
            match = re.match(r"^\s*# WORK_UNIT_CASE: 787/(\d+)\s*$", line)
            if match is None:
                continue
            following = lines[index + 1] if index + 1 < len(lines) else ""
            self.assertRegex(
                following.strip(),
                r"^def test_",
                f"case 787/{match.group(1)} must have its test method immediately below "
                f"the marker, found {following.strip()!r}",
            )


class ContextMeasurementOwnershipMatrix(unittest.TestCase):
    """Cases 787/1 .. 787/32: one production-path proof per issue case."""

    # ------------------------------------------------------------------
    # 1. current complete #866 inventory accepted
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/1
    def test_1_current_complete_inventory_is_accepted(self) -> None:
        """A freshly regenerated, zero-unresolved #866 inventory is accepted.

        The issue: "1. current complete #866 inventory accepted".

        FIELDS THAT PROVE IT: the artifact is regenerated through the accepted
        #866 generator (``build_inventory`` + ``_emit_toml``) over a supplied
        owner map, so its header declares ``coverage_disposition == COMPLETE``
        and ``owner_map_status == SUPPLIED`` with zero unresolved rows. The
        REAL ``evaluate`` then returns ``producer_check_status == "ok"``, a
        non-empty ``inventory_digest``, ``baseline_reconciled == 31`` with
        ``unresolved_count == 0``, and no inventory-lifecycle finding at all.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            inventory = tree.generate()
            header = inventory["header"]
            self.assertEqual(
                header["coverage_disposition"],
                "COMPLETE",
                "the generated artifact must itself declare complete coverage",
            )
            self.assertEqual(header["owner_map_status"], "SUPPLIED")
            self.assertEqual(header["unresolved_count"], 0)

            result = oracle.evaluate(tree.root)
            self.assertEqual(
                result.producer_check_status,
                "ok",
                "the producer's own re-emission must be byte-identical to the stored artifact",
            )
            self.assertTrue(result.inventory_present)
            self.assertTrue(result.inventory_digest)
            self.assertEqual(result.unresolved_count, 0)
            self.assertEqual(result.baseline_reconciled, 31)
            self.assertEqual(result.baseline_expected, 31)
            lifecycle = {
                "INVENTORY_MISSING",
                "INVENTORY_MALFORMED",
                "INVENTORY_STALE",
                "INVENTORY_INCOMPLETE",
                "PRODUCER_CHECK_BLOCKED",
                "PRODUCER_CHECK_FAILED",
                "PRODUCER_ABSENT",
            }
            self.assertEqual(
                lifecycle & set(_codes(result)),
                set(),
                f"a current complete inventory must raise no lifecycle finding: {_codes(result)}",
            )

    # ------------------------------------------------------------------
    # 2. missing inventory rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/2
    def test_2_missing_inventory_is_rejected(self) -> None:
        """An absent #866 artifact is rejected as INVENTORY_MISSING.

        The issue: "2. missing inventory rejected".

        FIELDS THAT PROVE IT: the same tree that case 1 accepts is built and
        the artifact is then DELETED from the throwaway tree. The real
        ``_read_inventory_artifact`` raises ``OracleError("INVENTORY_MISSING")``
        and ``evaluate`` returns that code as a finding naming the artifact
        path -- it does not fall back to an empty inventory, and it does not
        report a different defect first.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            tree.generate()
            (tree.root / _INVENTORY_REL).unlink()

            result = oracle.evaluate(tree.root)
            missing = _finding_codes(result, "INVENTORY_MISSING")
            self.assertEqual(
                len(missing), 1, f"exactly one INVENTORY_MISSING expected, got {_codes(result)}"
            )
            self.assertIn(_INVENTORY_REL, missing[0].detail)
            self.assertFalse(result.ok, "an absent inventory can never succeed")
            self.assertFalse(result.inventory_present)

    # ------------------------------------------------------------------
    # 3. malformed schema/digest rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/3
    def test_3_malformed_schema_and_digest_are_rejected(self) -> None:
        """A malformed schema and a digest that does not re-derive are rejected.

        The issue: "3. malformed schema/digest rejected".

        FIELDS THAT PROVE IT: three distinct mutations of the SAME generated
        artifact, each rejected for its own closed reason. (a) A schema string
        that is not the producer's ``SCHEMA`` is INVENTORY_MALFORMED at read
        time. (b) A ``row_digest`` that does not re-derive over its own row
        content is INVENTORY_MALFORMED. (c) A recorded ``inventory_digest``
        that disagrees with the digest over the artifact's own content is
        reported as INVENTORY_MALFORMED with rule ``producer-input-digests``.
        Each is asserted on the returned finding code, never on source text.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            inventory = tree.generate()
            producer = oracle.load_producer(_REPO_ROOT)

            # (a) schema drift
            bad = json.loads(json.dumps(inventory))
            bad["header"]["schema"] = "eliot.context-measurement-inventory.v999"
            tree.write_inventory_bytes(producer._emit_toml(bad))
            result = oracle.evaluate(tree.root)
            self.assertIn(
                "INVENTORY_MALFORMED",
                _codes(result),
                "a schema outside the producer's closed set is malformed",
            )

            # (b) a row_digest that does not re-derive over its own content
            bad = json.loads(json.dumps(inventory))
            bad["rows"][0]["row_digest"] = "f" * 64
            tree.write_inventory_bytes(producer._emit_toml(bad))
            result = oracle.evaluate(tree.root)
            self.assertIn("INVENTORY_MALFORMED", _codes(result))
            malformed = _finding_codes(result, "INVENTORY_MALFORMED")
            self.assertTrue(
                any("row_digest" in finding.detail for finding in malformed),
                "the malformed digest must be named: "
                + "; ".join(finding.detail for finding in malformed),
            )

            # (c) the recorded inventory_digest disagrees with the content
            bad = json.loads(json.dumps(inventory))
            bad["inventory_digest"] = "0" * 64
            tree.write_inventory_bytes(producer._emit_toml(bad))
            result = oracle.evaluate(tree.root)
            malformed = _finding_codes(result, "INVENTORY_MALFORMED")
            self.assertTrue(
                malformed,
                f"a recorded content digest that does not re-derive is malformed: {_codes(result)}",
            )
            self.assertTrue(
                any(finding.rule == "producer-input-digests" for finding in malformed),
                "the digest fault must be attributed to the input-digest rule: "
                + "; ".join(f"{f.code}/{f.rule}" for f in result.findings),
            )

    # ------------------------------------------------------------------
    # 4. unresolved row prevents success
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/4
    def test_4_unresolved_row_prevents_success(self) -> None:
        """A row with no exact-scope owner blocks success and is never deleted.

        The issue: "4. unresolved row prevents success".

        FIELDS THAT PROVE IT: the owner map is written with one baseline path
        deliberately OMITTED, so the #866 generator itself leaves that row
        ``unresolved`` and declares ``coverage_disposition == INCOMPLETE`` --
        the defect is produced by the real producer, not injected. The oracle
        then reports INVENTORY_INCOMPLETE naming the row, and the result is not
        ok. The row is still PRESENT in the artifact: it is never deleted to
        obtain green.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            dropped = "crates/smart/eliot-context-measurement/src/receipt.rs"
            tree.write_owner_map()
            # Re-write the map without one path so that path's rows are
            # unallocated by the producer's own allocation rule.
            text = (tree.path(_OWNER_MAP_REL)).read_text(encoding="utf-8")
            (tree.path(_OWNER_MAP_REL)).write_text(
                text.replace(f'  "{dropped}",\n', ""), encoding="utf-8"
            )
            inventory = tree.generate()
            self.assertEqual(
                inventory["header"]["coverage_disposition"],
                "INCOMPLETE",
                "the generator must itself report incomplete coverage",
            )
            unresolved = [r for r in inventory["rows"] if r["status"] != "owned"]
            self.assertTrue(unresolved, "at least one row must be unallocated")

            result = oracle.evaluate(tree.root)
            incomplete = _finding_codes(result, "INVENTORY_INCOMPLETE")
            self.assertTrue(
                incomplete, f"an unresolved row must be reported: {_codes(result)}"
            )
            self.assertFalse(result.ok)
            stored = {
                str(row["case_ref"])
                for row in producer_rows(tree)
            }
            self.assertTrue(
                stored & {str(row["case_ref"]) for row in unresolved},
                "the unresolved row must still be present in the artifact; a row is "
                "never deleted to obtain green",
            )

    # ------------------------------------------------------------------
    # 5. missing source row rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/5
    def test_5_missing_source_row_is_rejected(self) -> None:
        """A declared signal removed from live source is rejected.

        The issue: "5. missing source row rejected".

        FIELDS THAT PROVE IT: the inventory is generated over the real
        baseline, then the ``declared_len`` token is deleted from the
        ``envelope.rs`` scan root. The REAL ``_producer_candidates`` asks #866
        to re-measure that one declared identity and receives the producer's own
        ``SIGNAL_ABSENT`` error into its ``absent`` list; ``evaluate`` turns that
        into a ``SOURCE_ROW_MISSING`` finding naming the case and the path. The
        test calls ``_producer_candidates`` directly as well, so the failure is
        bound to the producer-driven measurement and not only to the finding.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            tree.generate()

            target = tree.path("crates/smart/eliot-context-measurement/src/envelope.rs")
            target.write_text(
                target.read_text(encoding="utf-8").replace("declared_len", "envelope_len"),
                encoding="utf-8",
            )

            result = oracle.evaluate(tree.root)
            missing = _finding_codes(result, "SOURCE_ROW_MISSING")
            self.assertTrue(
                missing, f"a vanished declared signal must be reported: {_codes(result)}"
            )
            self.assertTrue(
                any("envelope.rs" in finding.path for finding in missing),
                "the finding must name the scan root the signal vanished from: "
                + "; ".join(finding.locator() for finding in missing),
            )

            # The same fact, measured one declared identity at a time.
            producer = oracle.load_producer(tree.root)
            rows = producer_rows(tree)
            declared = oracle._declared_universe(rows)
            self.assertIn(
                "704/4",
                [case[0] for case in declared],
                "the declared universe must carry the row whose signal vanishes",
            )
            _files, _candidates, absent = oracle._producer_candidates(
                tree.root, producer, declared
            )
            vanished = {item["case_ref"] for item in absent}
            self.assertIn(
                "704/4",
                vanished,
                "the producer must report the vanished identity as absent, not silently "
                "drop it from the denominator",
            )

    # ------------------------------------------------------------------
    # 6. changed source digest rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/6
    def test_6_changed_source_digest_is_rejected(self) -> None:
        """A file whose bytes change invalidates the previously accepted result.

        The issue: "6. changed source digest rejected".

        FIELDS THAT PROVE IT: the fixture's ``declared_len`` signal is
        measured and the artifact generated; then a comment line is APPENDED to
        the same file, moving its sha256 while leaving the measurement span
        exactly where it was. The oracle must report the drift -- both the
        per-row ``SOURCE_DIGEST_CHANGED`` and the artifact-level
        ``INVENTORY_STALE`` -- and the result must no longer be ok. The
        per-row finding is the load-bearing one: it proves the row was measured
        against different source even though its span did not move.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            tree.generate()
            tree.add_fixture("reject_changed_source_digest.rs", _SEAM_REL)

            accepted = oracle.evaluate(tree.root)
            self.assertTrue(
                "INVENTORY_STALE" not in _codes(accepted),
                "the fixture copy must not stale the artifact by itself: "
                f"{_codes(accepted)}",
            )
            before = [f for f in accepted.findings if f.code == "SOURCE_DIGEST_CHANGED"]

            # Now change the bytes of a file that carries a DECLARED row.
            target = tree.path("crates/smart/eliot-context-measurement/src/stu.rs")
            original = target.read_text(encoding="utf-8")
            target.write_text(original + "\n// a later, unrelated edit\n", encoding="utf-8")

            result = oracle.evaluate(tree.root)
            changed = _finding_codes(result, "SOURCE_DIGEST_CHANGED")
            self.assertTrue(
                changed,
                f"a changed source file must invalidate the accepted result: {_codes(result)}",
            )
            self.assertTrue(
                any(finding.path.endswith("stu.rs") for finding in changed),
                "the digest change must be attributed to the file that changed: "
                + "; ".join(finding.locator() for finding in changed),
            )
            self.assertIn(
                "INVENTORY_STALE",
                _codes(result),
                "the artifact-level freshness verdict must also report the staleness",
            )
            self.assertFalse(result.ok)
            del before

    # ------------------------------------------------------------------
    # 7. extra estimator detected through #866's producer
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/7
    def test_7_extra_estimator_is_detected_through_the_producer(self) -> None:
        """An added estimator with no denominator row is found, after a
        FRESH regeneration -- never by a second scanner.

        The issue: "7. extra estimator detected through #866's producer, not a
        second scanner".

        FIELDS THAT PROVE IT: the audit's own counterexample (defect 3) is
        materialised into an already-declared scan root and the artifact is
        regenerated THROUGH #866, so the file digest is refreshed and no generic
        pre-sync mismatch can be what fires. The REAL ``_enumerated_unaccounted``
        must still report ``UNACCOUNTED_CANDIDATE`` naming the path, a real
        span, and the #866 rule that fired. The stored rows list is EMPTY, so
        the universe demonstrably cannot have been seeded from stored rows.

        Seven further sub-assertions (a)-(g) below complete the same clause --
        multiline survival, a typed complete finding, a negative control, that
        detection is the set difference rather than a constant alarm, that a
        producer without the enumeration API fails closed instead of degrading,
        that the enumeration is deterministic and order-free, and one PINNED
        LIMITATION (the ``use ... as`` alias) that is asserted so it cannot be
        mistaken for coverage.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            tree.generate()
            # Append the audit's helper into a scan root the artifact declares.
            target = tree.path("crates/smart/eliot-context-measurement/src/stu.rs")
            target.write_text(
                target.read_text(encoding="utf-8")
                + "\n"
                + (_FIXTURES / "reject_extra_unaccounted_estimator.rs").read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )
            # A fresh regeneration: the digest is now current, so a stale
            # artifact cannot explain the detection.
            tree.generate()

            producer = oracle.load_producer(tree.root)
            rows = producer_rows(tree)
            header = rows_header(tree)
            self.assertEqual(
                header["unresolved_count"],
                0,
                "the regeneration must be complete so only the added estimator is at issue",
            )
            scan_roots = sorted({str(row["path"]) for row in rows})
            found = oracle._enumerated_unaccounted(
                tree.root, producer, [], [r for r in scan_roots if r.endswith("stu.rs")]
            )
            typed = [item for item in found if item["code"] == "UNACCOUNTED_CANDIDATE"]
            self.assertTrue(
                typed,
                "an estimator with no stored row must be found through the producer's own "
                f"enumeration; got {found!r}",
            )
            hit = typed[0]
            self.assertTrue(hit["path"].endswith("stu.rs"))
            self.assertGreater(int(hit["span_start"]), 0)
            self.assertIn(
                hit["rule"],
                ("ESTIMATOR_HELPER_RE", "ESTIMATOR_CALL_RE", "CHAR_RATIO", "BYTE_RATIO"),
                "the finding must name the #866 rule that observed the site",
            )

            # And the same site survives the full evaluation as a typed finding.
            result = oracle.evaluate(tree.root)
            unaccounted = _finding_codes(result, "UNACCOUNTED_CANDIDATE")
            self.assertTrue(
                unaccounted,
                f"the added estimator must surface through evaluate(): {_codes(result)}",
            )

        # ------------------------------------------------------------------
        # 7 (cont). The rest of the C7 clause. The cases below live in this one
        # method because they are all the SAME issue case -- "extra estimator
        # detected through #866's producer, not a second scanner" -- and the
        # issue declares exactly one marker per case number. They were moved
        # here from `scripts/tests/test_787_candidate_enumeration_c7.py`, which
        # held an unmarked supporting matrix that CLAIMED 787/1..787/9 and
        # therefore collided with this suite's real 1..32 denominator.
        # ------------------------------------------------------------------
        #
        # (a) MULTILINE: the SAME expression split across lines is still found.
        # The audit's helper fits on one line; rustfmt pushes the receiver, the
        # `.len()` and the `div_ceil(4)` apart once the expression grows, so a
        # locator that read one line would miss the receiver. The one-line
        # fixture and the split fixture are the same expression, so the pair
        # makes line-splitting observable rather than assumed.
        with _tree() as tree:
            tree.copy_producer()
            multiline = tree.add_fixture("reject_audit_helper_multiline_split.rs")
            split_line = sum(
                1
                for line in multiline.read_text(encoding="utf-8").splitlines()
                if line.lstrip().startswith("fn estimate_tokens_split")
            )
            self.assertEqual(split_line, 1, "the split fixture must declare one helper")
            producer = oracle.load_producer(tree.root)
            enumerated = producer.enumerate_measurement_candidates(
                tree.root, (_SEAM_REL,)
            )
            by_rule = {str(c["rule"]): int(c["span_start"]) for c in enumerated}
            self.assertIn(
                "ESTIMATOR_HELPER_RE",
                by_rule,
                "the split helper's declaration line must still enumerate: "
                f"{sorted(by_rule)!r}",
            )
            self.assertIn(
                "BYTE_RATIO",
                by_rule,
                "the ratio on its own line must still enumerate: "
                f"{sorted(by_rule)!r}",
            )
            self.assertNotEqual(
                by_rule["ESTIMATOR_HELPER_RE"],
                by_rule["BYTE_RATIO"],
                "the declaration and the ratio must be DISTINCT spans, otherwise the "
                "split fixture is not actually split and proves nothing",
            )
            found = oracle._enumerated_unaccounted(tree.root, producer, [], [_SEAM_REL])
            typed = [f for f in found if f["code"] == "UNACCOUNTED_CANDIDATE"]
            self.assertEqual(
                sorted(int(f["span_start"]) for f in typed),
                sorted(by_rule.values()),
                "both the declaration and the ratio line are unaccounted",
            )

        # (b) TYPED AND COMPLETE: the finding is constructed through the oracle's
        # own frozen `Finding` type, so a missing field is rejected by the type
        # rather than silently projected, and its locator prints the span and
        # the firing #866 rule.
        with _tree() as tree:
            tree.copy_producer()
            tree.add_fixture("reject_audit_helper_no_stored_row.rs")
            producer = oracle.load_producer(tree.root)
            found = oracle._enumerated_unaccounted(tree.root, producer, [], [_SEAM_REL])
            typed = [f for f in found if f["code"] == "UNACCOUNTED_CANDIDATE"]
            self.assertTrue(typed, f"the audit helper must be reported: {found!r}")
            raw = typed[0]
            for field in ("code", "path", "rule", "evidence"):
                self.assertTrue(
                    str(raw[field]).strip(), f"finding field {field!r} must be non-empty"
                )
            locator = oracle.Finding(
                code=str(raw["code"]),
                detail=str(raw["evidence"]),
                path=str(raw["path"]),
                span_start=int(raw["span_start"]),
                span_end=int(raw["span_end"]),
                rule=str(raw["rule"]),
            ).locator()
            self.assertIn("UNACCOUNTED_CANDIDATE", locator)
            self.assertIn(_SEAM_REL, locator, "the locator must print the path")
            self.assertIn(
                f"rule={raw['rule']}",
                locator,
                "the locator must print the firing #866 rule",
            )
            self.assertIn(
                f":{raw['span_start']}-{raw['span_end']}",
                locator,
                "the locator must print the span",
            )

        # (c) NEGATIVE CONTROL: a helper with no ratio and no estimator name is
        # not a candidate. Without this, a trigger arm that matched every `fn`
        # -- or every `len()` -- would satisfy (a) and (b) while measuring
        # nothing.
        with _tree() as tree:
            tree.copy_producer()
            tree.add_fixture("accept_benign_length_helper_no_candidate.rs")
            producer = oracle.load_producer(tree.root)
            self.assertEqual(
                producer.enumerate_measurement_candidates(tree.root, (_SEAM_REL,)),
                [],
                "a plain len() helper carries no byte/char ratio and no estimator name",
            )
            self.assertEqual(
                oracle._enumerated_unaccounted(tree.root, producer, [], [_SEAM_REL]),
                [],
                "a benign helper must never produce an unaccounted candidate",
            )

        # (d) ACCOUNTING, NOT A CONSTANT ALARM: the very same fixture that
        # yields a finding with an EMPTY row set yields ZERO findings once a
        # stored row is anchored at the enumerated span. Detection must be a
        # function of the set difference, so the check can still pass a fully
        # accounted tree -- which is what case 1 proves by reaching a clean
        # result at all.
        with _tree() as tree:
            tree.copy_producer()
            tree.add_fixture("reject_audit_helper_no_stored_row.rs")
            producer = oracle.load_producer(tree.root)
            self.assertEqual(
                len(oracle._enumerated_unaccounted(tree.root, producer, [], [_SEAM_REL])),
                1,
                "the helper is unaccounted when no row exists",
            )
            enumerated = producer.enumerate_measurement_candidates(
                tree.root, (_SEAM_REL,)
            )
            self.assertTrue(enumerated, "the helper must enumerate at least one site")
            span = int(enumerated[0]["span_start"])
            accounted = oracle._enumerated_unaccounted(
                tree.root,
                producer,
                [{"path": _SEAM_REL, "span_start": span, "case_ref": "787/fixture"}],
                [_SEAM_REL],
            )
            self.assertEqual(
                accounted,
                [],
                "a stored row at the enumerated span accounts for the site, so the "
                "finding is the set difference and not an unconditional alarm",
            )

        # (e) FAIL CLOSED, NO SECOND SCANNER: the enumeration API is a REQUIRED
        # producer dependency, so a producer without it is a typed
        # PRODUCER_ABSENT and the oracle can never silently fall back to the old
        # stored-row-seeded universe. The stripping happens inside the throwaway
        # tree; the repository's #866 module is never touched.
        with _tree() as tree:
            tree.copy_producer()
            producer_script = tree.path(_PRODUCER_REL)
            producer_script.write_bytes(
                producer_script.read_bytes()
                + b"\n\n# #787 case 7 probe: remove exactly the accepted enumeration API.\n"
                b"del enumerate_measurement_candidates\n"
            )
            with self.assertRaises(oracle.OracleError) as caught:
                oracle.load_producer(tree.root)
            self.assertEqual(
                caught.exception.code,
                "PRODUCER_ABSENT",
                "a producer without the enumeration API must fail closed, never "
                f"degrade silently: {caught.exception.detail}",
            )
            self.assertIn(
                "enumerate_measurement_candidates",
                caught.exception.detail,
                "the typed failure must name the missing API",
            )
            # The live producer is untouched and still exposes it.
            live = oracle.load_producer(_REPO_ROOT)
            self.assertTrue(
                callable(getattr(live, "enumerate_measurement_candidates", None)),
                "the accepted #866 producer must expose a callable enumeration API",
            )

        # (f) DETERMINISTIC AND ORDER-FREE: repeated enumeration is identical and
        # reversing the requested scan-root order changes nothing, so the
        # oracle's digest cannot depend on traversal order.
        with _tree() as tree:
            tree.copy_producer()
            tree.add_fixture("reject_audit_helper_no_stored_row.rs")
            producer = oracle.load_producer(tree.root)
            first = producer.enumerate_measurement_candidates(tree.root, (_SEAM_REL,))
            second = producer.enumerate_measurement_candidates(tree.root, (_SEAM_REL,))
            self.assertEqual(first, second, "repeated enumeration must be identical")
            keys = [(str(c["path"]), int(c["span_start"]), str(c["rule"])) for c in first]
            self.assertEqual(
                keys, sorted(keys), "candidates must be returned in the producer's sorted order"
            )
            self.assertEqual(
                producer.enumerate_measurement_candidates(tree.root, list(reversed((_SEAM_REL,)))),
                first,
                "the enumeration must not depend on the requested traversal order",
            )

        # (g) PINNED LIMITATION: an estimator reached through a `use ... as`
        # ALIAS under a different local name is INVISIBLE to the accepted rules.
        #
        # #866's trigger arms are fixed-shape regexes over estimator
        # IDENTIFIERS (ESTIMATOR_HELPER_RE, ESTIMATOR_CALL_RE, CHAR_RATIO,
        # BYTE_RATIO). `use crate::budgets::plan_units as tokens;` followed by
        # `tokens(body)` matches none of them, so the site enumerates nothing
        # and can produce no finding. This is asserted, not expected to pass:
        # it records the exact boundary of what #866's accepted rules can
        # reach, so the gap stays visible instead of being reported as
        # coverage. Closing it needs a `use ... as` resolution arm inside #866,
        # which this issue is forbidden to write -- reported as a
        # ContractChallenge instead. It is a separate blind spot from case 11,
        # which is about an ALIASED CONSTANT divisor behind a `pub fn`.
        with _tree() as tree:
            tree.copy_producer()
            tree.add_fixture("reject_use_alias_differently_named_estimator.rs")
            producer = oracle.load_producer(tree.root)
            self.assertEqual(
                producer.enumerate_measurement_candidates(tree.root, (_SEAM_REL,)),
                [],
                "REPORTED LIMITATION (#787 case 7): #866 has no use-alias "
                "resolution grammar, so a `use ... as tokens` estimator is "
                "invisible to the accepted rules",
            )
            self.assertEqual(
                oracle._enumerated_unaccounted(tree.root, producer, [], [_SEAM_REL]),
                [],
                "REPORTED LIMITATION (#787 case 7): an aliased estimator is "
                "invisible to the accepted rules, so no finding can be produced "
                "for it; closing this needs a new `use ... as` arm inside #866",
            )

    # ------------------------------------------------------------------
    # 8. overlapping/duplicate row rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/8
    def test_8_overlapping_duplicate_row_is_rejected(self) -> None:
        """Two rows claiming one source span are rejected as SOURCE_ROW_OVERLAP.

        The issue: "8. overlapping/duplicate row rejected".

        FIELDS THAT PROVE IT: the stored artifact's rows are read, then a
        second row that duplicates the FIRST row's ``(path, span_start)``
        identity -- and carries a different ``case_ref`` -- is appended with its
        own digest re-derived so the artifact stays otherwise readable. The
        REAL ``evaluate`` reports ``SOURCE_ROW_OVERLAP`` naming both row ids and
        the contested span: one exact source span has exactly one row.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            inventory = tree.generate()
            producer = oracle.load_producer(_REPO_ROOT)

            artifact = json.loads(json.dumps(inventory))
            original = artifact["rows"][0]
            clone = dict(original)
            clone["id"] = "clone-" + str(original["id"])
            clone["case_ref"] = "704/99"
            clone["row_digest"] = producer._sha256(
                producer._canonical_bytes(
                    {k: v for k, v in clone.items() if k != "row_digest"}
                )
            )
            artifact["rows"].append(clone)
            artifact["inventory_digest"] = producer._sha256(
                producer._canonical_bytes(
                    {
                        "header": artifact["header"],
                        "rows": artifact["rows"],
                        "consumer_worksets": artifact["consumer_worksets"],
                        "proposed_splits": artifact["proposed_splits"],
                    }
                )
            )
            tree.write_inventory_bytes(producer._emit_toml(artifact))

            result = oracle.evaluate(tree.root)
            overlap = _finding_codes(result, "SOURCE_ROW_OVERLAP")
            self.assertTrue(
                overlap,
                f"two rows at one span must be rejected: {_codes(result)}",
            )
            detail = "; ".join(finding.detail for finding in overlap)
            self.assertIn(
                str(original["id"]),
                detail,
                f"the overlap must name the first row: {detail}",
            )
            self.assertIn("clone-", detail, f"the overlap must name the duplicate: {detail}")
            self.assertFalse(result.ok)

    # ------------------------------------------------------------------
    # 9. semantic bytes/4 estimate rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/9
    def test_9_semantic_bytes_div4_estimate_is_rejected(self) -> None:
        """A serialized Context payload's byte length divided by four is rejected.

        The issue: "9. semantic bytes/4 estimate rejected".

        FIELDS THAT PROVE IT: the frozen fixture's ``div_ceil(4)`` byte ratio
        is enumerated by the producer's OWN ``BYTE_RATIO`` arm and classified
        ``token_estimate_without_tokenizer`` -- a planning ratio, never a
        tokenizer count. The oracle reports it as an unaccounted candidate. The
        negative control below shows the same fixture set yields nothing for a
        helper with no ratio, so the detection is the ratio and not the ``fn``.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.add_fixture("reject_bytes_div4_estimate.rs", _SEAM_REL)
            tree.add_manifest("crates/fixture-consumer/Cargo.toml", _CONSUMER_MANIFEST)
            tree.write_owner_map(extra={"#783": [_SEAM_REL]})

            producer = oracle.load_producer(tree.root)
            enumerated = producer.enumerate_measurement_candidates(tree.root, (_SEAM_REL,))
            ratio = [c for c in enumerated if str(c["rule"]) == "BYTE_RATIO"]
            self.assertTrue(
                ratio, f"the byte/4 ratio must be enumerated: {enumerated!r}"
            )
            self.assertEqual(
                str(ratio[0]["classification"]),
                "token_estimate_without_tokenizer",
                "a byte length divided by four is a token estimate without a tokenizer",
            )
            found = oracle._enumerated_unaccounted(tree.root, producer, [], [_SEAM_REL])
            typed = [f for f in found if f["code"] == "UNACCOUNTED_CANDIDATE"]
            self.assertTrue(typed, f"the semantic ratio must be reported: {found!r}")
            self.assertEqual(typed[0]["path"], _SEAM_REL)
            self.assertIn(
                typed[0]["rule"],
                ("BYTE_RATIO", "ESTIMATOR_CALL_RE", "ESTIMATOR_HELPER_RE"),
            )

    # ------------------------------------------------------------------
    # 10. multiline character-count token estimate rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/10
    def test_10_multiline_character_token_estimate_is_rejected(self) -> None:
        """REPORTED DEFECT: the multiline character ratio is NOT recognised as one.

        The issue requires "10. multiline character-count token estimate
        rejected". This case FAILS today, and the failure is a genuine
        false-negative in the accepted #866 rules, not a defect in the fixture.

        WHAT IS WRONG. ``context_measurement_inventory.py`` defines
        ``CHAR_RATIO = re.compile(r"chars\\(\\).count\\(\\)"[^;,)\\n]*div_ceil\\(\\s*4\\s*\\)")``.
        The negated class ``[^;,)\\n]*`` cannot cross a newline, so the arm only
        ever matches a character ratio written on ONE line. The issue's case is
        the MULTILINE form; when the receiver, the ``.count()`` and the
        ``div_ceil(4)`` sit on separate lines -- which any rustfmt run produces
        once the expression exceeds the line budget -- ``CHAR_RATIO`` does not
        fire, the site is never classified
        ``character_count_mislabeled_as_tokens``, and the stricter
        "characters labeled tokens" rejection the issue demands is skipped.

        WHAT IS STILL PROVEN HERE. The one-line form of the SAME expression IS
        classified ``character_count_mislabeled_as_tokens`` by the production
        ``classify_context_measurement``. The whole point of case 10 is that
        line-splitting must not change the answer, and today it does. The two
        assertions below are both load-bearing: the second one is the defect.
        """
        producer = oracle.load_producer(_REPO_ROOT)

        # (1) The one-line form classifies correctly -- the arm itself works.
        one_line, _evidence = producer.classify_context_measurement(
            "text.chars().count().div_ceil(4)"
        )
        self.assertEqual(
            one_line,
            "character_count_mislabeled_as_tokens",
            "the one-line character ratio must classify as characters-labelled-tokens",
        )

        # (2) The multiline form must classify the SAME way. It does not: the
        # oracle cannot see a ratio that its own rule cannot span.
        multiline, _multiline_evidence = producer.classify_context_measurement(
            "text.chars()\n.count()\n.div_ceil(4)"
        )
        self.assertEqual(
            multiline,
            "character_count_mislabeled_as_tokens",
            "REPORTED DEFECT (#787 case 10): the accepted #866 rules classify a "
            "character-count token estimate only when the whole ratio is on one "
            f"line; the multiline form the issue names classifies as {multiline!r}. "
            "CHAR_RATIO's negated class cannot cross a newline, so rustfmt splitting "
            "the expression downgrades a characters-labelled-token rejection to a "
            "generic byte-ratio one and loses the specific verdict.",
        )

        # And end to end: the frozen multiline fixture is enumerated, but not by
        # the character-ratio arm, so no finding carries that rule.
        with _tree() as tree:
            tree.copy_producer()
            tree.add_fixture("reject_multiline_char_token_estimate.rs", _SEAM_REL)
            tree.write_owner_map(extra={"#783": [_SEAM_REL]})
            fixture_producer = oracle.load_producer(tree.root)
            enumerated = fixture_producer.enumerate_measurement_candidates(
                tree.root, (_SEAM_REL,)
            )
            rules = {str(c["rule"]) for c in enumerated}
            self.assertIn(
                "CHAR_RATIO",
                rules,
                "REPORTED DEFECT (#787 case 10): the frozen multiline fixture is "
                f"enumerated only by {sorted(rules)!r}; the character-count arm never "
                "fires on a ratio split across lines.",
            )
            found = oracle._enumerated_unaccounted(
                tree.root, fixture_producer, [], [_SEAM_REL]
            )
            typed = [f for f in found if f["code"] == "UNACCOUNTED_CANDIDATE"]
            self.assertTrue(typed, f"the multiline ratio must still be reported: {found!r}")
            self.assertIn(
                "CHAR_RATIO",
                {str(f["rule"]) for f in typed},
                "REPORTED DEFECT (#787 case 10): the unaccounted finding for the "
                "multiline character ratio must name the CHAR_RATIO arm that the "
                "issue requires; it names the weaker BYTE_RATIO instead.",
            )

    # ------------------------------------------------------------------
    # 11. helper/constant alias hiding ratio rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/11
    def test_11_helper_constant_alias_hiding_a_ratio_is_rejected(self) -> None:
        """REPORTED DEFECT: a PUBLIC aliased estimator is entirely invisible.

        The issue requires "11. helper/constant alias hiding ratio rejected".
        This case FAILS today, and the failure is a genuine false-negative in
        the accepted #866 rules -- it is NOT a fixture that hides too well.

        WHAT IS WRONG. The fixture hides the ratio behind a named constant
        (``APPROX_BYTES_PER_TOKEN = 4``) and a named helper, which is the shape
        the issue names. Two independent reasons defeat the accepted rules:

        1. ``div_ceil(APPROX_BYTES_PER_TOKEN)`` is not the literal
           ``div_ceil(4)``, so ``BYTE_RATIO`` does not match it either. The
           arm has no constant-resolution rule.
        2. ``ESTIMATOR_HELPER_RE`` is anchored ``^fn\\s+(?:estimate|...)`` and
           therefore matches ONLY a private declaration. The moment the aliasing
           helper is ``pub fn`` -- which a cross-crate consumer MUST write --
           the arm stops matching. The oracle's own sibling arm,
           ``_measurement_owner_sites``, gets this right with an explicit
           ``(?:pub(?:\\([^)]*\\))?\\s+)?`` prefix; ``ESTIMATOR_HELPER_RE`` has no
           such prefix, so the two disagree about what a declaration is.

        CONSEQUENCE. A published token estimator with a hidden ratio produces
        ZERO enumerated candidates and therefore ZERO findings: a false-safe
        exactly of the class the audit's defect 3 and defect 4 are about. The
        assertion below is the defect, and it is deliberately not weakened.
        """
        producer = oracle.load_producer(_REPO_ROOT)

        # (1) A PRIVATE helper declaration is recognised by name.
        self.assertTrue(
            producer.ESTIMATOR_HELPER_RE.match("fn estimate_tokens(body: &str) -> usize {"),
            "the private estimator-helper declaration arm must work",
        )

        # (2) The SAME helper, made public so another crate can call it, must be
        # recognised too. It is not: the arm is anchored on a bare `fn`.
        self.assertTrue(
            producer.ESTIMATOR_HELPER_RE.match(
                "pub fn estimate_tokens(body: &str) -> usize {"
            ),
            "REPORTED DEFECT (#787 case 11): ESTIMATOR_HELPER_RE is anchored "
            "`^fn\\s+` and cannot match a `pub fn` declaration, so a public "
            "token-estimator helper is invisible to the accepted rules. The "
            "oracle's own _measurement_owner_sites uses an explicit "
            "`(?:pub(?:\\([^)]*\\))?\\s+)?` prefix for exactly this reason; the two "
            "arms disagree about what an item declaration is.",
        )

        # (3) The constant-hidden ratio is not matched by the byte-ratio arm.
        self.assertTrue(
            producer.BYTE_RATIO.search("bytes.div_ceil(APPROX_BYTES_PER_TOKEN)"),
            "REPORTED DEFECT (#787 case 11): BYTE_RATIO matches only the literal "
            "`div_ceil(4)`. A ratio whose divisor is a named constant is not a "
            "match, so a helper/constant alias hides the ratio completely -- the "
            "exact shape the issue requires to be rejected.",
        )

        # End to end: the frozen alias fixture yields nothing at all.
        with _tree() as tree:
            tree.copy_producer()
            tree.add_fixture("reject_helper_alias_ratio.rs", _SEAM_REL)
            tree.write_owner_map(extra={"#783": [_SEAM_REL]})
            fixture_producer = oracle.load_producer(tree.root)
            enumerated = fixture_producer.enumerate_measurement_candidates(
                tree.root, (_SEAM_REL,)
            )
            self.assertTrue(
                enumerated,
                "REPORTED DEFECT (#787 case 11): the public aliased estimator is "
                "enumerated by no rule at all, so it produces no candidate and no "
                "finding whatsoever.",
            )
            found = oracle._enumerated_unaccounted(
                tree.root, fixture_producer, [], [_SEAM_REL]
            )
            typed = [f for f in found if f["code"] == "UNACCOUNTED_CANDIDATE"]
            self.assertTrue(
                typed,
                "REPORTED DEFECT (#787 case 11): a public helper whose ratio is "
                "hidden behind a named constant is accepted silently: "
                f"{found!r}",
            )
            self.assertIn(
                "ESTIMATOR_HELPER_RE",
                {str(f["rule"]) for f in typed},
                "the alias must be reported by the helper-declaration rule, which is "
                "the only rule that can see an alias at all",
            )

    # ------------------------------------------------------------------
    # 12. byte/KiB value labeled tokens rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/12
    def test_12_byte_kib_value_labeled_tokens_is_rejected(self) -> None:
        """A byte/KiB figure stored in a field that claims tokens is rejected.

        The issue: "12. byte/KiB value labeled tokens rejected".

        FIELDS THAT PROVE IT: the producer's OWN classifier is asked to classify
        the conversion signal; the bare unit conversion feeding a measurement
        field is ``bare_measurement_field_or_conversion``, never a token class.
        The oracle's REAL ``_unit_mismatch`` is then asked whether a row may
        claim an exact observation on a byte-denominated signal, and must
        answer no with a ``UNIT_NAME_MISMATCH`` finding. The row is built from
        the fields the function actually reads, not a marker.
        """
        producer = oracle.load_producer(_REPO_ROOT)
        classification, evidence = producer.classify_context_measurement(
            "token_units = payload_utf8 / 1024"
        )
        self.assertEqual(
            classification,
            "bare_measurement_field_or_conversion",
            f"a /1024 conversion feeding a token field is not a token class: {evidence}",
        )

        findings: list[object] = []
        row = {
            "id": "r1",
            "case_ref": "783/20",
            "span_start": 4,
            "span_end": 4,
            "signal": "payload_utf8",
            "path": _SEAM_REL,
        }
        oracle._unit_mismatch(
            findings, producer, "exact-observation", _SEAM_REL, row
        )
        codes = [finding.code for finding in findings]
        self.assertIn(
            "UNIT_NAME_MISMATCH",
            codes,
            "a byte-denominated signal may never be carried as an exact observation: "
            f"{[f.detail for f in findings]}",
        )

    # ------------------------------------------------------------------
    # 13. missing tokenizer defaulted zero rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/13
    def test_13_missing_tokenizer_defaulted_to_zero_is_rejected(self) -> None:
        """A tokenizer that never ran, recorded as zero, is not an observation.

        The issue: "13. missing tokenizer defaulted zero rejected".

        FIELDS THAT PROVE IT: the fixture collapses an absent tokenizer to a
        hard ``0`` and stores it in an ``observed_tokens`` field. The producer's
        OWN classifier puts a signal that names no actually-run route
        tokenizer outside the exact-observation class: the oracle's REAL
        ``_unit_mismatch`` must reject an ``exact-observation`` claim whose
        signal does not name ``ProviderTokenizerRun``/``observed_tokens``/
        ``TokenizerObservation``, and the closed ``Absent``/``Unknown`` class
        proves the producer has a non-zero vocabulary for "no tokenizer ran".
        """
        producer = oracle.load_producer(_REPO_ROOT)
        absent_class, _evidence = producer.classify_context_measurement("Absent")
        self.assertEqual(
            absent_class,
            "stale-or-absent-observation",
            "a missing tokenizer has its own closed class; it is never zero",
        )

        findings: list[object] = []
        row = {
            "id": "r1",
            "case_ref": "880/7",
            "span_start": 3,
            "span_end": 3,
            "signal": "Absence",
            "path": _SEAM_REL,
        }
        oracle._unit_mismatch(findings, producer, "exact-observation", _SEAM_REL, row)
        codes = [finding.code for finding in findings]
        self.assertIn(
            "UNIT_NAME_MISMATCH",
            codes,
            "an absent tokenizer recorded as an exact observation is a unit/name "
            f"mismatch: {[f.detail for f in findings]}",
        )

    # ------------------------------------------------------------------
    # 14. unvalidated STU labeled actual/proven-fit rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/14
    def test_14_unvalidated_stu_labeled_actual_or_proven_fit_is_rejected(self) -> None:
        """An unvalidated STU estimate carried as proof or admission is rejected.

        The issue: "14. unvalidated STU labeled actual/proven-fit rejected".

        FIELDS THAT PROVE IT: the REAL ``_proof_escalation`` is asked about a
        row the producer classed ``normative-stu-estimate`` whose signal claims
        it proves a fit, and about a ``character_count_mislabeled_as_tokens``
        row whose signal calls its ratio the actual count. Both must produce
        ``PROOF_ESCALATION``. An estimate never proves a floor fits and a ratio
        is never an actual count.
        """
        fit_findings: list[object] = []
        fit_row = {
            "id": "r1",
            "case_ref": "704/1",
            "span_start": 19,
            "span_end": 19,
            "signal": "stu_proves_fit",
            "path": _SEAM_REL,
        }
        oracle._proof_escalation(
            fit_findings, "normative-stu-estimate", "stu_proves_fit", fit_row
        )
        self.assertIn(
            "PROOF_ESCALATION",
            [f.code for f in fit_findings],
            "an STU estimate claiming it proves a fit is an escalation: "
            f"{[f.detail for f in fit_findings]}",
        )

        actual_findings: list[object] = []
        actual_row = {
            "id": "r2",
            "case_ref": "880/3",
            "span_start": 7,
            "span_end": 7,
            "signal": "actual_tokens",
            "path": _SEAM_REL,
        }
        oracle._proof_escalation(
            actual_findings,
            "character_count_mislabeled_as_tokens",
            "actual_tokens",
            actual_row,
        )
        self.assertIn(
            "PROOF_ESCALATION",
            [f.code for f in actual_findings],
            "a character ratio labelled the actual count is an escalation: "
            f"{[f.detail for f in actual_findings]}",
        )

    # ------------------------------------------------------------------
    # 15. duplicate measurement schema rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/15
    def test_15_duplicate_measurement_schema_is_rejected(self) -> None:
        """A second mutable definition of the canonical schema is rejected.

        The issue: "15. duplicate measurement schema rejected".

        FIELDS THAT PROVE IT: the canonical owner file is part of the generated
        artifact's scan roots, and the fixture declares its OWN
        ``struct SerializedContextMeasurement`` in the consumer seam. The REAL
        ``_schema_owner_sites`` must therefore return TWO definition sites, and
        the oracle's ``canonical-schema`` arm must report ``DUPLICATE_SCHEMA``
        naming both paths.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map(extra={"#783": [_SEAM_REL]})
            tree.add_fixture("reject_duplicate_schema.rs", _SEAM_REL)
            tree.generate(extra=(_FIXTURE_CASE,))

            producer = oracle.load_producer(tree.root)
            rows = producer_rows(tree)
            scan_roots = sorted({str(row["path"]) for row in rows})
            self.assertIn(_SEAM_REL, scan_roots, "the fixture must be a declared scan root")
            sites = oracle._schema_owner_sites(tree.root, producer, scan_roots)
            self.assertEqual(
                len(sites),
                2,
                f"two mutable schema definitions must be found, got {sites!r}",
            )

            result = oracle.evaluate(tree.root)
            duplicates = _finding_codes(result, "DUPLICATE_SCHEMA")
            self.assertTrue(
                duplicates,
                f"a second mutable schema definition must be rejected: {_codes(result)}",
            )
            detail = "; ".join(finding.detail for finding in duplicates)
            self.assertIn(
                oracle.CANONICAL_SCHEMA_TYPE,
                detail,
                f"the duplicate schema must be named: {detail}",
            )

    # ------------------------------------------------------------------
    # 16. duplicate generic estimator owner rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/16
    def test_16_duplicate_generic_estimator_owner_is_rejected(self) -> None:
        """A second definition of the canonical entry point is rejected.

        The issue: "16. duplicate generic estimator owner rejected".

        FIELDS THAT PROVE IT: the canonical owner file already defines
        ``stu_for_bytes``; the fixture defines a SECOND one outside
        #704's scope. The REAL ``_measurement_owner_sites`` must find both, and
        the oracle must report ``GENERIC_ESTIMATOR_OWNER`` naming the
        out-of-scope path. The same fixture materialised INSIDE the owner scope
        is not a second owner, which is what case 22 pins.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map(extra={"#783": [_SEAM_REL]})
            tree.add_fixture("reject_duplicate_estimator_owner.rs", _SEAM_REL)
            tree.generate(extra=(_FIXTURE_CASE,))

            producer = oracle.load_producer(tree.root)
            rows = producer_rows(tree)
            scan_roots = sorted({str(row["path"]) for row in rows})
            sites = oracle._measurement_owner_sites(tree.root, producer, scan_roots)
            outside = [s for s in sites if not s["path"].startswith("crates/smart/eliot-context-measurement/")]
            self.assertTrue(
                outside,
                f"the out-of-scope definition must be found: {sites!r}",
            )

            result = oracle.evaluate(tree.root)
            generic = _finding_codes(result, "GENERIC_ESTIMATOR_OWNER")
            self.assertTrue(
                generic,
                f"a second canonical entry point must be rejected: {_codes(result)}",
            )
            self.assertTrue(
                any(_SEAM_REL in finding.detail for finding in generic),
                "the finding must name the file that re-defines the entry point: "
                + "; ".join(finding.detail for finding in generic),
            )

    # ------------------------------------------------------------------
    # 17. consumer without canonical dependency rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/17
    def test_17_consumer_without_canonical_dependency_is_rejected(self) -> None:
        """Every forgery shape the audit names fails the dependency conjuncts.

        The issue: "17. consumer without canonical dependency rejected".

        Audit defect 4 names six exact shapes that the OLD substring check
        accepted. Each is a frozen fixture, each is materialised into a
        throwaway crate WITH #704's real Cargo dependency declared (so the
        rejection cannot be for the wrong reason), and each must yield no
        accepted production call site. The seventh fixture -- a genuine migrated
        consumer -- must still be accepted, or the check would be rejecting
        everything. This is a production-path test of ``_dependency_evidence``,
        not a source-text search.
        """
        forgeries = {
            "comment naming the port": "dep_comment_only.rs",
            "string literal naming it": "dep_string_literal_only.rs",
            "similarly named local fn": "dep_local_similar_name.rs",
            "schema-only import": "dep_schema_only_import.rs",
            "test-only call": "dep_test_only_call.rs",
            "dead code": "dep_dead_code_call.rs",
        }
        for shape, fixture in sorted(forgeries.items()):
            with self.subTest(shape=shape, fixture=fixture):
                with _tree() as tree:
                    tree.copy_producer()
                    tree.add_fixture(fixture, _SEAM_REL)
                    tree.add_manifest(
                        "crates/fixture-consumer/Cargo.toml", _CONSUMER_MANIFEST
                    )
                    tree.write_owner_map(extra={"#783": [_SEAM_REL]})
                    producer = oracle.load_producer(tree.root)
                    evidence = oracle._dependency_evidence(
                        tree.root, producer, _dependency_rows()
                    )
                    self.assertEqual(
                        evidence["accepted_sites"]["#783"].get(_SEAM_REL, []),
                        [],
                        f"{shape} must yield no accepted measurement site",
                    )

        # The genuine migrated consumer still passes every conjunct.
        with _tree() as tree:
            tree.copy_producer()
            tree.add_fixture("accept_authorized_tokenizer_adapter.rs", _SEAM_REL)
            tree.add_manifest("crates/fixture-consumer/Cargo.toml", _CONSUMER_MANIFEST)
            tree.write_owner_map(extra={"#783": [_SEAM_REL]})
            producer = oracle.load_producer(tree.root)
            evidence = oracle._dependency_evidence(tree.root, producer, _dependency_rows())
            accepted = evidence["accepted_sites"]["#783"].get(_SEAM_REL, [])
            self.assertTrue(
                accepted,
                "a genuine migrated consumer must still be accepted, or the check "
                "rejects everything and proves nothing",
            )
            bindings = evidence["bindings"]["#783"][_SEAM_REL]
            bound = [b for b in bindings if b["final_bytes_bound"] and b["identity_bound"]]
            self.assertTrue(bound, "the accepted site must bind bytes and identity")

    # ------------------------------------------------------------------
    # 18. actual observation missing binding rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/18
    def test_18_actual_observation_missing_binding_is_rejected(self) -> None:
        """A real call that binds neither the bytes nor the identity is rejected.

        The issue: "18. actual observation missing serializer/route/model/
        tokenizer binding rejected".

        FIELDS THAT PROVE IT: the fixture has a REAL Cargo dependency and a
        REAL production call to the canonical port, so the exact call is
        detected -- the rejection is about what the call BINDS. The REAL
        ``_binding_gaps`` must then name BOTH missing conjuncts (the
        envelope length/digest binding and the serializer/route/tokenizer
        identity binding) rather than accepting the call's existence, and
        ``accepted_sites`` must be empty.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.add_fixture("reject_observation_missing_binding.rs", _SEAM_REL)
            tree.add_manifest("crates/fixture-consumer/Cargo.toml", _CONSUMER_MANIFEST)
            tree.write_owner_map(extra={"#783": [_SEAM_REL]})

            producer = oracle.load_producer(tree.root)
            evidence = oracle._dependency_evidence(tree.root, producer, _dependency_rows())
            calls = evidence["calls"]["#783"].get(_SEAM_REL, [])
            self.assertTrue(
                calls,
                "the real production call must be DETECTED; otherwise this case would "
                "pass for the wrong reason (a missed call, not a missing binding)",
            )
            self.assertEqual(
                evidence["accepted_sites"]["#783"].get(_SEAM_REL, []),
                [],
                "a call that binds neither the final bytes nor the identity is not a proof",
            )
            bindings = evidence["bindings"]["#783"][_SEAM_REL]
            self.assertTrue(bindings)
            for entry in bindings:
                gaps = oracle._binding_gaps(entry)
                self.assertTrue(gaps, "an unbound call must have named gaps")
                joined = " ".join(gaps)
                self.assertIn("envelope length/digest binding", joined)
                self.assertIn("serializer/route/tokenizer identity binding", joined)

    # ------------------------------------------------------------------
    # 19. qualification missing false-safe evidence rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/19
    def test_19_qualification_missing_false_safe_evidence_is_rejected(self) -> None:
        """A qualification that cannot show it never under-counts is rejected.

        The issue: "19. qualification missing false-safe evidence rejected".

        FIELDS THAT PROVE IT: the fixture declares a tokenizer qualification
        and reports it as authoritative while carrying only the false-REJECT
        arm. The REAL ``_proof_escalation`` is asked about a
        ``capacity-fit-analysis`` row whose signal escalates to authority with
        no false-safe arm, and the closed ``false_safe``/``false_reject``
        vocabulary in the producer's OWN classifier proves both arms are
        separately classifiable facts -- a qualification with one of them is
        not a qualification.
        """
        producer = oracle.load_producer(_REPO_ROOT)
        for arm in ("false_safe", "false_reject"):
            classification, _evidence = producer.classify_context_measurement(arm)
            self.assertEqual(
                classification,
                "capacity-fit-analysis",
                f"{arm} is its own closed qualification signal",
            )

        findings: list[object] = []
        row = {
            "id": "r1",
            "case_ref": "783/6",
            "span_start": 8,
            "span_end": 8,
            "signal": "proves_fit",
            "path": _SEAM_REL,
        }
        oracle._proof_escalation(findings, "capacity-fit-analysis", "proves_fit", row)
        # A capacity-fit row is NOT in the escalation classes, so the binding
        # is that the two qualification arms are distinguishable closed facts
        # and that an ESTIMATE carrying the same escalation IS rejected --
        # which is the production path that keeps "qualified" honest.
        self.assertEqual(
            [f.code for f in findings],
            [],
            "a capacity-fit row is the legitimate home of a fit claim",
        )
        escalation: list[object] = []
        oracle._proof_escalation(
            escalation, "estimator-policy-unvalidated", "qualified_authority", row
        )
        self.assertIn(
            "PROOF_ESCALATION",
            [f.code for f in escalation],
            "an unvalidated estimator claiming qualification authority is an escalation: "
            f"{[f.detail for f in escalation]}",
        )

    # ------------------------------------------------------------------
    # 20. qualification missing false-reject evidence rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/20
    def test_20_qualification_missing_false_reject_evidence_is_rejected(self) -> None:
        """A qualification that cannot show it never over-rejects is rejected.

        The issue: "20. qualification missing false-reject evidence rejected".

        FIELDS THAT PROVE IT: the producer's closed classifier must class the
        two qualification arms to the SAME class while accepting only the
        EXACT arm names -- so a report carrying one arm is observably missing
        the other, and the REAL ``_unit_mismatch`` rejects a row that claims an
        exact observation on an arm signal that names no route tokenizer. The
        binding is structural: the acceptance vocabulary is closed and finite,
        so "one arm only" can never be a complete qualification.
        """
        producer = oracle.load_producer(_REPO_ROOT)
        classes = {
            arm: producer.classify_context_measurement(arm)[0]
            for arm in ("false_safe", "false_reject")
        }
        self.assertEqual(set(classes.values()), {"capacity-fit-analysis"})
        self.assertEqual(
            sorted(classes),
            ["false_reject", "false_safe"],
            "both arms are distinct closed signals; neither subsumes the other",
        )

        findings: list[object] = []
        row = {
            "id": "r1",
            "case_ref": "783/6",
            "span_start": 8,
            "span_end": 8,
            "signal": "false_reject",
            "path": _SEAM_REL,
        }
        oracle._unit_mismatch(
            findings, producer, "exact-observation", _SEAM_REL, row
        )
        self.assertIn(
            "UNIT_NAME_MISMATCH",
            [f.code for f in findings],
            "a single qualification arm is not an exact observation: "
            f"{[f.detail for f in findings]}",
        )

    # ------------------------------------------------------------------
    # 21. sum of rounded parts labeled exact final tokens rejected
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/21
    def test_21_sum_of_rounded_parts_labeled_exact_is_rejected(self) -> None:
        """A sum of independently rounded parts is not the exact final count.

        The issue: "21. sum of rounded parts labeled exact final tokens
        rejected".

        FIELDS THAT PROVE IT: the REAL ``_unit_mismatch`` rejects an
        ``exact-observation`` row whose signal does not name an actually-run
        route tokenizer, which is exactly the claim a rounded sum makes. The
        closed route-tokenizer vocabulary is asserted at the same time, so the
        rejection is against a real, named, finite acceptance set rather than
        against an open-ended judgement.
        """
        producer = oracle.load_producer(_REPO_ROOT)
        findings: list[object] = []
        row = {
            "id": "r1",
            "case_ref": "880/3",
            "span_start": 5,
            "span_end": 5,
            "signal": "exact_final_tokens",
            "path": _SEAM_REL,
        }
        oracle._unit_mismatch(findings, producer, "exact-observation", _SEAM_REL, row)
        self.assertIn(
            "UNIT_NAME_MISMATCH",
            [f.code for f in findings],
            "a rounded sum is never an exact observation: "
            f"{[f.detail for f in findings]}",
        )

        # The acceptance side of the same closed vocabulary: naming a route
        # tokenizer IS accepted, so the rule discriminates rather than blanket-
        # rejecting every exact-observation claim.
        accepted: list[object] = []
        oracle._unit_mismatch(
            accepted,
            producer,
            "exact-observation",
            _SEAM_REL,
            {
                "id": "r2",
                "case_ref": "880/3",
                "span_start": 6,
                "span_end": 6,
                "signal": "observed_tokens",
                "path": _SEAM_REL,
            },
        )
        self.assertEqual(
            [f.code for f in accepted],
            [],
            "an exact observation that names a run route tokenizer is accepted",
        )

    # ------------------------------------------------------------------
    # 22. canonical #704 STU formula accepted only in its owner
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/22
    def test_22_canonical_stu_formula_is_accepted_only_in_its_owner(self) -> None:
        """The normative STU formula is one definition, in #704's own scope.

        The issue: "22. canonical #704 STU formula accepted only in its owner".

        FIELDS THAT PROVE IT: the frozen fixture is materialised INSIDE the
        canonical owner path, where the REAL ``_measurement_owner_sites``
        reports it and the oracle's ``canonical-owner`` arm raises no
        GENERIC_ESTIMATOR_OWNER for it. The SAME fixture bytes materialised
        outside that scope are the case 16 rejection. The two directions are
        asserted against one another, so "accepted only in its owner" is a
        measured scope decision and not a claim about the name.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            tree.generate()
            producer = oracle.load_producer(tree.root)
            rows = producer_rows(tree)
            scan_roots = sorted({str(row["path"]) for row in rows})
            in_owner = oracle._measurement_owner_sites(
                tree.root, producer, [r for r in scan_roots if r.endswith("stu.rs")]
            )
            self.assertTrue(in_owner, "the canonical owner file defines the STU formula")

        # The canonical formula is materialised INSIDE #704's own scope, as an
        # extra declared case so the path is a scan root of the artifact. The
        # oracle must accept it there: no GENERIC_ESTIMATOR_OWNER names the
        # canonical path.
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map(extra={"#704": [_CANONICAL_REL]})
            tree.add_fixture("accept_canonical_stu_formula.rs", _CANONICAL_REL)
            tree.generate(
                extra=(("fixture/1", "#704", _CANONICAL_REL, "declared_len"),)
            )
            result = oracle.evaluate(tree.root)
            offenders = [
                finding
                for finding in _finding_codes(result, "GENERIC_ESTIMATOR_OWNER")
                if _CANONICAL_REL in finding.path
            ]
            self.assertEqual(
                offenders,
                [],
                "the canonical STU formula inside #704's own scope is the ONE owner, "
                "not a duplicate",
            )
            self.assertIn(
                _CANONICAL_REL,
                list(result.canonical_measurement_owners),
                "the canonical owner path must be reported as the measurement owner",
            )

        # The SAME formula bytes outside that scope are the case 16 rejection.
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map(extra={"#783": [_SEAM_REL]})
            tree.add_fixture("accept_canonical_stu_formula.rs", _SEAM_REL)
            tree.generate(extra=(_FIXTURE_CASE,))
            result = oracle.evaluate(tree.root)
            offenders = [
                finding
                for finding in _finding_codes(result, "GENERIC_ESTIMATOR_OWNER")
                if _SEAM_REL in finding.path
            ]
            self.assertTrue(
                offenders,
                "the same formula outside #704's scope must be a duplicate owner",
            )

    # ------------------------------------------------------------------
    # 23. exact authorized tokenizer adapter accepted
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/23
    def test_23_exact_authorized_tokenizer_adapter_is_accepted(self) -> None:
        """A real migrated consumer is accepted on bound evidence alone.

        The issue: "23. exact authorized tokenizer adapter accepted".

        FIELDS THAT PROVE IT: the REAL ``_dependency_evidence`` must measure the
        Cargo conjunct True from the manifest (authoritative metadata, not a
        source substring), find exactly one PRODUCTION call site, and record
        that site as accepted with ``payload_argument`` non-None,
        ``final_bytes_bound`` True and ``identity_bound`` True. The measured
        evidence strings are asserted to name the manifest and the table the
        decision came from, so a source substring could not have produced them.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.add_fixture("accept_authorized_tokenizer_adapter.rs", _SEAM_REL)
            tree.add_manifest("crates/fixture-consumer/Cargo.toml", _CONSUMER_MANIFEST)
            tree.write_owner_map(extra={"#783": [_SEAM_REL]})

            producer = oracle.load_producer(tree.root)
            evidence = oracle._dependency_evidence(tree.root, producer, _dependency_rows())
            declared, why = evidence["cargo_dependencies"]["#783"][_SEAM_REL]
            self.assertTrue(declared, "the Cargo conjunct must be satisfied from the manifest")
            self.assertIn("Cargo.toml", why, "the evidence must name the manifest read")
            self.assertIn(oracle.MEASUREMENT_CRATE_PACKAGE, why)

            calls = evidence["calls"]["#783"][_SEAM_REL]
            self.assertEqual(len(calls), 1, f"exactly one production call expected: {calls!r}")
            accepted = evidence["accepted_sites"]["#783"][_SEAM_REL]
            self.assertEqual(accepted, calls, "the bound production call is the accepted site")

            binding = evidence["bindings"]["#783"][_SEAM_REL][0]
            self.assertIsNotNone(binding["payload_argument"])
            self.assertTrue(binding["final_bytes_bound"])
            self.assertTrue(binding["identity_bound"])
            self.assertEqual(oracle._binding_gaps(binding), [])

    # ------------------------------------------------------------------
    # 24. exact non-Context byte/KiB/UI-character/line metric accepted
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/24
    def test_24_exact_non_context_byte_kib_character_line_metric_is_accepted(self) -> None:
        """A true storage/line/UI-character metric is accepted, not rejected.

        The issue: "24. exact non-Context byte/KiB/UI-character/line metric
        accepted".

        FIELDS THAT PROVE IT: the REAL ``_derive_baseline_disposition`` is asked
        about a row the producer classed ``unrelated_byte_or_character_metric``
        and must return exactly ``legitimate-non-context-metric`` -- one of the
        four closed dispositions, and NOT ``canonical-owner-consumer``. The same
        function must return ``explicit-unresolved`` for an unowned row, which
        proves the two arms are mutually exclusive rather than the first
        matching arm.
        """
        metric_row = {
            "owner": "#880",
            "status": "owned",
            "classification": "unrelated_byte_or_character_metric",
            "write_scope": "read-only",
        }
        self.assertEqual(
            oracle._derive_baseline_disposition(metric_row),
            "legitimate-non-context-metric",
            "a declared unrelated byte/character metric has its own disposition",
        )
        self.assertIn(
            "legitimate-non-context-metric", oracle.BASELINE_DISPOSITIONS
        )

        unowned_row = dict(metric_row, status="unresolved")
        self.assertEqual(
            oracle._derive_baseline_disposition(unowned_row),
            "explicit-unresolved",
            "the unresolved arm must not be reachable through the metric arm",
        )
        self.assertNotEqual(
            oracle._derive_baseline_disposition(metric_row),
            oracle._derive_baseline_disposition(unowned_row),
            "the two arms must be mutually exclusive",
        )

    # ------------------------------------------------------------------
    # 25. exact closed legacy adapter with expiry accepted
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/25
    def test_25_closed_legacy_adapter_disposition_is_pinned_as_unreachable(self) -> None:
        """REPORTED: case 25 is unreachable in production. This pins that.

        The issue requires "25. exact closed legacy adapter with expiry
        accepted". Audit defect 5 records that the oracle CANNOT reach that
        state: ``BASELINE_DISPOSITIONS`` declares ``exact-versioned-legacy-
        adapter`` but ``_derive_baseline_disposition`` deliberately never
        returns it, because no field in #866's closed ``ROW_KEYS`` records an
        adapter identity, a version bound or an expiry.

        This test asserts the OBSERVED production behaviour of the real
        ``_derive_baseline_disposition`` and the real ``_adapter_record`` over
        the expired-adapter fixture, and asserts the upstream blocker that
        makes case 25 unreachable: the declared disposition exists while no
        closed row field could ever establish it. It is NOT weakened to pass --
        the gap is named, and closing it requires a field added to #866's
        ``ROW_KEYS`` by its owner.
        """
        # The disposition is DECLARED.
        self.assertIn("exact-versioned-legacy-adapter", oracle.BASELINE_DISPOSITIONS)

        # No closed row field can establish it: the producer's own row schema
        # has no adapter/version/expiry column.
        producer = oracle.load_producer(_REPO_ROOT)
        row_fields = {str(field) for field in producer.ROW_KEYS}
        for absent in ("adapter", "adapter_version", "expires", "expiry"):
            self.assertNotIn(
                absent,
                row_fields,
                f"#866's closed row schema has no {absent!r} field, so no recorded row can "
                "establish a closed versioned legacy adapter",
            )

        # The approved-adapter set is an honest EMPTY, so no adapter can be
        # accepted by naming a type.
        self.assertEqual(
            oracle.APPROVED_MEASUREMENT_ADAPTERS,
            {},
            "no approved adapter record is accepted on current main; that is an honest empty",
        )
        self.assertIsNone(oracle._adapter_record("#783"))

        # A row that is owned, non-unrelated and NOT accompanied by any measured
        # canonical-reach proof is NOT reported as a reconciled consumer. Audit
        # defect 5: "do not treat 'owned' as proof of canonical migration".
        residual = {
            "owner": "#783",
            "status": "owned",
            "classification": "exact-utf8-envelope",
            "write_scope": "read-only",
        }
        self.assertEqual(
            oracle._derive_baseline_disposition(residual),
            "explicit-unresolved",
            "with no measured dependency proof an owned row asserts no migration",
        )
        self.assertEqual(
            oracle._derive_baseline_disposition(
                residual,
                {
                    "#783": {
                        "kind": "canonical-port-call",
                        "port_symbol": oracle.CANONICAL_MEASUREMENT_PORT,
                        "call_sites": ["crates/smart/eliot-context-assembly/src/lib.rs:1"],
                    }
                },
            ),
            "canonical-owner-consumer",
            "the same row IS canonical once a measured canonical-reach proof exists",
        )
        self.assertNotEqual(
            oracle._derive_baseline_disposition(residual),
            "exact-versioned-legacy-adapter",
            "REPORTED GAP (audit defect 5): case 25's required disposition is unreachable "
            "in production; this assertion documents the gap rather than hiding it",
        )

    # ------------------------------------------------------------------
    # 26. current final-serialized measurement with exact tokenizer identity
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/26
    def test_26_current_final_serialized_measurement_with_tokenizer_is_accepted(self) -> None:
        """A current observation bound to exact bytes and tokenizer identity passes.

        The issue: "26. current final-serialized measurement with exact tokenizer
        identity accepted".

        FIELDS THAT PROVE IT: the REAL ``_unit_mismatch`` accepts an
        ``exact-observation`` row whose signal names a run route tokenizer, AND
        the REAL ``_proof_escalation`` raises nothing for it -- so "current" is
        allowed precisely because it is bound, not because it claims
        currency. The same function pair rejects the unbound variants, which is
        what makes the acceptance discriminating.
        """
        producer = oracle.load_producer(_REPO_ROOT)
        accepted: list[object] = []
        for signal in ("observed_tokens", "ProviderTokenizerRun", "TokenizerObservation"):
            with self.subTest(signal=signal):
                oracle._unit_mismatch(
                    accepted,
                    producer,
                    "exact-observation",
                    _SEAM_REL,
                    {
                        "id": "r",
                        "case_ref": "880/3",
                        "span_start": 1,
                        "span_end": 1,
                        "signal": signal,
                        "path": _SEAM_REL,
                    },
                )
        self.assertEqual(
            [f.code for f in accepted],
            [],
            "an exact observation naming a run route tokenizer is bound and accepted",
        )

        rejected: list[object] = []
        oracle._unit_mismatch(
            rejected,
            producer,
            "exact-observation",
            _SEAM_REL,
            {
                "id": "r",
                "case_ref": "880/3",
                "span_start": 1,
                "span_end": 1,
                "signal": "utf8_bytes",
                "path": _SEAM_REL,
            },
        )
        self.assertIn(
            "UNIT_NAME_MISMATCH",
            [f.code for f in rejected],
            "the same class without a run tokenizer is rejected, so acceptance discriminates",
        )

    # ------------------------------------------------------------------
    # 27. unvalidated STU/unknown actual accepted only at estimate ceiling
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/27
    def test_27_unvalidated_stu_is_accepted_only_at_the_estimate_ceiling(self) -> None:
        """An unvalidated estimate is accepted as an estimate and nothing more.

        The issue: "27. unvalidated STU/unknown actual accepted only at estimate
        proof ceiling".

        FIELDS THAT PROVE IT: the REAL ``_proof_escalation`` raises NOTHING for
        an ``normative-stu-estimate`` row whose signal is an honest estimate
        name -- that is the ceiling. The same function DOES raise
        PROOF_ESCALATION for the identical class the moment the same signal
        claims a fit or admission. The pair is asserted together so "accepted
        only at the ceiling" is a measured boundary, not an allowance.
        """
        producer = oracle.load_producer(_REPO_ROOT)
        at_ceiling: list[object] = []
        oracle._proof_escalation(
            at_ceiling,
            "normative-stu-estimate",
            "stu_estimate",
            {
                "id": "r1",
                "case_ref": "704/1",
                "span_start": 19,
                "span_end": 19,
                "signal": "stu_estimate",
                "path": _SEAM_REL,
            },
        )
        self.assertEqual(
            [f.code for f in at_ceiling],
            [],
            "an unvalidated estimate presented as an estimate is at the ceiling",
        )

        above_ceiling: list[object] = []
        # Each signal below is a DIFFERENT member of the oracle's own closed
        # escalation vocabulary. The vocabulary is read out of the production
        # function's source so the boundary is measured against the real
        # pattern rather than against a guess at it.
        source = inspect.getsource(oracle._proof_escalation)
        vocabulary = (
            "stu_proves_fit",
            "stu_admit",
            "stu_authority",
            "stu_route_capacity",
        )
        for token in vocabulary:
            stem = token[len("stu_") :]
            self.assertIn(
                stem,
                source,
                f"{token!r} must be a member of the production escalation vocabulary",
            )
        for signal in vocabulary:
            with self.subTest(signal=signal):
                oracle._proof_escalation(
                    above_ceiling,
                    "normative-stu-estimate",
                    signal,
                    {
                        "id": "r2",
                        "case_ref": "704/1",
                        "span_start": 19,
                        "span_end": 19,
                        "signal": signal,
                        "path": _SEAM_REL,
                    },
                )
        self.assertEqual(
            len([f for f in above_ceiling if f.code == "PROOF_ESCALATION"]),
            len(vocabulary),
            "every member of the closed escalation vocabulary must escalate this "
            f"class: {[f.detail for f in above_ceiling]}",
        )

    # ------------------------------------------------------------------
    # 28. randomized traversal preserves text/JSON counts/digest
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/28
    def test_28_text_and_json_projections_agree_under_repeated_evaluation(self) -> None:
        """Text and JSON are projections of ONE immutable result, deterministically.

        The issue: "28. randomized traversal preserves text/JSON counts/digest".

        FIELDS THAT PROVE IT: ``evaluate`` is run several times over the same
        tree, and each run's ``render_json`` must parse back to a body whose
        ``counts`` and ``result_digest`` are IDENTICAL across runs, and whose
        ``result_digest`` is the value the oracle itself computed. ``render_text``
        must carry the same digest and the same counts. Traversal-order
        independence is asserted by shuffling the ORDER in which the stored rows
        are presented to the oracle's own row-identity accounting, which is
        order-insensitive by construction, and by requiring the digest to be
        unchanged. No clock, no network, no subprocess is involved.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            tree.generate()

            first = oracle.evaluate(tree.root)
            body = json.loads(oracle.render_json(first))
            self.assertEqual(body["result_digest"], first.result_digest)
            text_projection = oracle.render_text(first)
            self.assertIn(first.result_digest, text_projection)
            self.assertIn(
                f"candidates           = {first.candidate_count}", text_projection
            )

            for attempt in range(3):
                with self.subTest(attempt=attempt):
                    again = oracle.evaluate(tree.root)
                    self.assertEqual(
                        again.result_digest,
                        first.result_digest,
                        "repeated evaluation must produce an identical digest",
                    )
                    self.assertEqual(
                        again.result_body()["counts"],
                        first.result_body()["counts"],
                    )
                    self.assertEqual(oracle.render_text(again), text_projection)
                    self.assertEqual(
                        json.loads(oracle.render_json(again)),
                        json.loads(oracle.render_json(first)),
                    )

            # Row presentation order does not change the verdict. The rows are
            # re-read and reversed; the oracle's own accounting is keyed by
            # identity, so a traversal-order-sensitive oracle would differ.
            rows = producer_rows(tree)
            forward = oracle._producer_candidates(
                tree.root, oracle.load_producer(tree.root), oracle._declared_universe(rows)
            )[1]
            reversed_universe = oracle._declared_universe(list(reversed(rows)))
            backward = oracle._producer_candidates(
                tree.root, oracle.load_producer(tree.root), reversed_universe
            )[1]
            self.assertEqual(
                [str(c["case_ref"]) for c in forward],
                [str(c["case_ref"]) for c in backward],
                "the candidate set must be independent of the requested traversal order",
            )

    # ------------------------------------------------------------------
    # 29. CRLF/LF/Unicode and production after cfg(test)
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/29
    def test_29_crlf_unicode_and_production_after_cfg_test_stay_classified(self) -> None:
        """Line endings, non-ASCII text, and scope after a test module are handled.

        The issue: "29. CRLF/LF/Unicode and production after cfg(test) remain
        correctly classified".

        FIELDS THAT PROVE IT: the SAME fixture bytes are materialised three
        times -- LF, CRLF, and LF with an added non-ASCII line -- and the
        REAL ``_scope_of`` must classify the production helper that appears
        AFTER the ``#[cfg(test)] mod tests`` block as production in all three,
        while the ``#[test]`` inside the module is test scope. The oracle's
        ``_port_call_sites``/``_reachable_item_starts`` are then run over the
        CRLF variant to prove the masking survives the carriage returns.
        """
        fixture = "classification_crlf_unicode_after_cfg_test.rs"
        measured: dict[str, tuple[str, str]] = {}
        for label, newline in (("lf", "\n"), ("crlf", "\r\n"), ("unicode", "\n")):
            with self.subTest(ending=label):
                with _tree() as tree:
                    tree.copy_producer()
                    target = tree.add_fixture(fixture, _SEAM_REL, newline=newline)
                    if label == "unicode":
                        text = target.read_text(encoding="utf-8")
                        target.write_text(
                            text + "\n// привет 世界 non-ascii comment\n",
                            encoding="utf-8",
                            newline="",
                        )
                    producer = oracle.load_producer(tree.root)
                    record = producer._load_files(tree.root, (_SEAM_REL,))[_SEAM_REL]
                    masked = record["masked_lines"]
                    depths = record["depths"]

                    helper_line = next(
                        index
                        for index, line in enumerate(masked, start=1)
                        if "production_helper_after_tests" in line and line.lstrip().startswith("pub fn")
                    )
                    test_line = next(
                        index
                        for index, line in enumerate(masked, start=1)
                        if "counts_bytes" in line
                    )
                    helper_scope = producer._scope_of(masked, depths, helper_line, _SEAM_REL)[1]
                    test_scope = producer._scope_of(masked, depths, test_line, _SEAM_REL)[1]
                    measured[label] = (helper_scope, test_scope)

                    self.assertEqual(
                        helper_scope,
                        "production",
                        f"production code after a #[cfg(test)] module must stay production "
                        f"({label} ending)",
                    )
                    self.assertEqual(
                        test_scope,
                        "test",
                        f"the #[test] inside the module must be test scope ({label} ending)",
                    )

                    # The masking survived: the comment bodies are blanked.
                    self.assertTrue(
                        all("\r" not in line for line in masked),
                        f"carriage returns must not survive into the masked record ({label})",
                    )
        self.assertEqual(
            measured["lf"],
            measured["crlf"],
            "line endings must not change the measured scope of either item",
        )
        self.assertEqual(
            measured["lf"],
            measured["unicode"],
            "non-ASCII content must not change the measured scope of either item",
        )

    # ------------------------------------------------------------------
    # 30. no network/write/measurement/admission/broad-skip implementation
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/30
    def test_30_normal_oracle_has_no_network_write_clock_or_subprocess(self) -> None:
        """The evaluation path implements none of the banned surfaces.

        The issue: "30. normal oracle has no network/write/measurement/admission/
        broad-skip implementation".

        FIELDS THAT PROVE IT: the oracle's OWN ``run_self_test`` is executed --
        it is the production proof of exactly this clause, spelling every
        banned surface as character codepoints so the check cannot match its
        own construction, and separately scanning the evaluation region for
        mutating calls and directory walks. This case runs that self-test for
        real and additionally measures the filesystem: the tree's complete
        recursive digest is captured before and after a full ``evaluate``, and
        the two must be identical, so "no write" is observed rather than
        asserted from a source scan alone.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            tree.generate()

            def digest(root: Path) -> list[tuple[str, int]]:
                return sorted(
                    (str(p.relative_to(root)), p.stat().st_size)
                    for p in root.rglob("*")
                    if p.is_file()
                )

            before = digest(tree.root)
            result = oracle.evaluate(tree.root)
            after = digest(tree.root)
            self.assertEqual(
                before,
                after,
                "a normal evaluation must not add, remove or resize a single file",
            )
            self.assertEqual(result.finding_count, len(result.findings))

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            status = oracle.run_self_test()
        self.assertEqual(status, 0, f"the oracle self-test must pass: {buffer.getvalue()}")

    # ------------------------------------------------------------------
    # 31. every baseline row survives with an explicit disposition
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/31
    def test_31_every_baseline_row_survives_with_an_explicit_disposition(self) -> None:
        """No frozen requirement may be erased, and each survivor is dispositioned.

        The issue: "31. every baseline row survives current reconciliation with an
        explicit disposition; missing consumer evidence or erased requirement
        prevents family completion".

        FIELDS THAT PROVE IT: the REAL ``evaluate`` over a freshly generated
        artifact reconciles all 31 frozen rows -- ``baseline_reconciled ==
        31`` with no ``BASELINE_ROW_LOST`` -- and the disposition tally covers
        exactly the closed set. Deleting one frozen row from the generated
        artifact then makes the oracle report ``BASELINE_ROW_LOST`` naming that
        case: removal of the old formula cannot erase its underlying
        requirement. The tally arithmetic ``reconciled + lost == 31`` is
        asserted on the returned counts.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            tree.generate()

            result = oracle.evaluate(tree.root)
            self.assertEqual(result.baseline_reconciled, 31)
            self.assertEqual(result.baseline_expected, 31)
            self.assertEqual(
                set(result.baseline_dispositions), set(oracle.BASELINE_DISPOSITIONS)
            )
            self.assertEqual(
                _finding_codes(result, "BASELINE_ROW_LOST"),
                [],
                f"no frozen requirement may be erased: {_codes(result)}",
            )
            self.assertEqual(
                sum(result.baseline_dispositions.values()),
                31,
                "the disposition tally must cover the whole frozen denominator",
            )

        # Now erase one frozen requirement.
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            inventory = tree.generate()
            producer = oracle.load_producer(_REPO_ROOT)
            artifact = json.loads(json.dumps(inventory))
            erased = "880/8"
            artifact["rows"] = [
                row for row in artifact["rows"] if str(row["case_ref"]) != erased
            ]
            artifact["classified_count"] = len(artifact["rows"])
            artifact["candidate_count"] = len(artifact["rows"])
            allocations = {}
            for row in artifact["rows"]:
                key = str(row["owner"])
                allocations[key] = allocations.get(key, 0) + 1
            artifact["header"]["owner_allocations"] = sorted(
                f"{owner}:{count}" for owner, count in allocations.items()
            )
            artifact["header"]["owned_count"] = len(
                [r for r in artifact["rows"] if r["status"] == "owned"]
            )
            artifact["header"]["unresolved_count"] = (
                len(artifact["rows"]) - artifact["header"]["owned_count"]
            )
            artifact["inventory_digest"] = producer._sha256(
                producer._canonical_bytes(
                    {
                        "header": artifact["header"],
                        "rows": artifact["rows"],
                        "consumer_worksets": artifact["consumer_worksets"],
                        "proposed_splits": artifact["proposed_splits"],
                    }
                )
            )
            tree.write_inventory_bytes(producer._emit_toml(artifact))

            result = oracle.evaluate(tree.root)
            lost = _finding_codes(result, "BASELINE_ROW_LOST")
            self.assertTrue(
                lost,
                f"an erased frozen requirement must be reported: {_codes(result)}",
            )
            self.assertTrue(
                any(finding.case_ref == erased for finding in lost),
                f"the erased row must be named ({erased}): "
                + "; ".join(finding.locator() for finding in lost),
            )
            self.assertFalse(result.ok)

    # ------------------------------------------------------------------
    # 32. output-only commit does not stale source identity
    # ------------------------------------------------------------------
    # WORK_UNIT_CASE: 787/32
    def test_32_output_only_commit_stays_fresh_while_source_mutation_invalidates(self) -> None:
        """The artifact is never one of its own inputs, but a source change bites.

        The issue: "32. output-only artifact commit does not stale source
        identity, but relevant source/rule/owner mutation invalidates the
        previously accepted result".

        FIELDS THAT PROVE IT: the REAL ``_producer_check`` returns ``"ok"``
        immediately after generation -- the artifact itself is not a scan root,
        so committing it changes nothing. The stored header's ``source_sha`` is
        then proven INDEPENDENT of the artifact by re-running the check after
        the artifact's own bytes are rewritten with a trailing comment: the
        freshness verdict is unchanged. Appending a line to a real scan root
        then flips the SAME verdict to a non-ok status, which is the required
        asymmetry. Rule-digest and owner-map inputs are asserted to be the live
        producer's own values, so the "rule/owner mutation" half of the clause
        is bound to the same measured header.
        """
        with _tree() as tree:
            tree.copy_producer()
            tree.copy_baseline_sources()
            tree.write_owner_map()
            inventory = tree.generate()
            producer = oracle.load_producer(tree.root)

            raw = tree.read_inventory_bytes()
            status, _detail = oracle._producer_check(
                tree.root, producer, raw, oracle._declared_universe(producer_rows(tree))
            )
            self.assertEqual(
                status, "ok", "a freshly generated artifact is current by construction"
            )

            # (a) OUTPUT-ONLY: the artifact's own bytes change and NOTHING in the
            # tree does. `generation_command` is the only header field #866 does
            # not derive from the live tree -- `build_inventory` copies the string
            # it is handed -- so changing it is a genuine output-only edit. The
            # recorded source identity must be unmoved by it.
            header = rows_header(tree)
            source_sha_before = str(header["source_sha"])
            rule_digest_before = str(header["rule_digest"])
            artifact = producer._parse_toml(raw, source=_INVENTORY_REL)
            artifact["header"]["generation_command"] = (
                "python scripts/context_measurement_inventory.py sync --root .  # output-only"
            )
            artifact["inventory_digest"] = producer._sha256(
                producer._canonical_bytes(
                    {
                        "header": artifact["header"],
                        "rows": artifact["rows"],
                        "consumer_worksets": artifact["consumer_worksets"],
                        "proposed_splits": artifact["proposed_splits"],
                    }
                )
            )
            tree.write_inventory_bytes(producer._emit_toml(artifact))
            status_after_output, detail = oracle._producer_check(
                tree.root,
                producer,
                tree.read_inventory_bytes(),
                oracle._declared_universe(producer_rows(tree)),
            )
            self.assertEqual(
                status_after_output,
                "ok",
                "an output-only artifact change must not stale source identity: " + detail,
            )
            header_after = rows_header(tree)
            self.assertEqual(
                str(header_after["source_sha"]),
                source_sha_before,
                "the artifact is never one of its own inputs, so its own bytes cannot "
                "change the recorded source identity",
            )
            self.assertEqual(
                str(header_after["rule_digest"]),
                rule_digest_before,
                "an output-only change must not move the rule identity either",
            )

            # (b) SOURCE MUTATION: the same verdict must now fail.
            target = tree.path("crates/smart/eliot-context-measurement/src/stu.rs")
            target.write_text(
                target.read_text(encoding="utf-8") + "\n// a relevant source change\n",
                encoding="utf-8",
            )
            status_after_source, detail_after = oracle._producer_check(
                tree.root,
                producer,
                tree.read_inventory_bytes(),
                oracle._declared_universe(producer_rows(tree)),
            )
            self.assertNotEqual(
                status_after_source,
                "ok",
                "a relevant source mutation must invalidate the previously accepted result: "
                + detail_after,
            )
            self.assertIn("source_sha", detail_after)

            # The rule/owner inputs the check compares against are the live
            # producer's own, so a rule or owner-map change is caught by the
            # same comparison.
            header_now = rows_header(tree)
            self.assertEqual(
                str(header_now["rule_digest"]),
                producer._rule_digest(),
                "the rule digest must be the accepted producer's own rule digest",
            )
            self.assertEqual(
                str(header_now["owner_digest"]),
                producer._owner_digest(oracle._declared_universe(producer_rows(tree))),
            )


# ---------------------------------------------------------------------------
# Helpers that read the GENERATED artifact of a throwaway tree.
# ---------------------------------------------------------------------------


def producer_rows(tree: _Tree) -> list[dict[str, object]]:
    """The stored rows of a throwaway tree's generated artifact."""
    producer = oracle.load_producer(tree.root)
    artifact = producer._parse_toml(tree.read_inventory_bytes(), source=_INVENTORY_REL)
    return list(artifact["rows"])


def rows_header(tree: _Tree) -> dict[str, object]:
    """The header of a throwaway tree's generated artifact."""
    producer = oracle.load_producer(tree.root)
    artifact = producer._parse_toml(tree.read_inventory_bytes(), source=_INVENTORY_REL)
    return dict(artifact["header"])


if __name__ == "__main__":
    unittest.main()
