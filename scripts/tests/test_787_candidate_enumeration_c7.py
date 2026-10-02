"""C7 binding matrix for #787 audit defect 3: "C7 is impossible".

Defect 3 of the ``code-complete`` audit of issue #787 (external audit
5931913038) named ``scripts/audit-context-measurement-ownership.py`` as deriving
its declared universe FROM THE STORED INVENTORY ROWS. ``_declared_universe``
reconstructed ``(case_ref, owner, path, signal)`` from the committed rows,
``_producer_candidates`` asked #866 to re-discover only those same
already-declared signals, and ``_unaccounted_candidates`` re-located the very
same set. No lexical enumeration of estimator expressions ever ran, so the audit
structurally could not see an estimator that had no row.

The audit's exact counterexample, reproduced here as ``_C7_AUDIT_HELPER``::

    fn local_estimate_tokens(text: &str) -> usize {
        text.as_bytes().len().div_ceil(4)
    }

Appended to an already-declared scan-root file with NO denominator row, then a
normal #866 ``sync``: the file digest refreshes, the fixed denominator still
emits only its declared signals, the helper receives no row, and #787 reported
no ``UNACCOUNTED_CANDIDATE`` for it. These tests bind the repaired behaviour.

What is bound
-------------
* :func:`oracle._enumerated_unaccounted` must emit a typed
  ``UNACCOUNTED_CANDIDATE`` naming path, span AND the #866 rule that fired, for
  the audit's helper and for the multiline variant of the same expression, after
  a freshly regenerated artifact attempt.
* The universe must come from the producer's own enumeration, not from the
  stored rows: the enumeration must still find the helper when the stored rows
  list is EMPTY, which is the only way "not seeded from stored rows" is
  observable rather than asserted.
* The finding must be typed and complete, not a free-text string: code, path,
  span and rule are all non-empty and the rule names a real #866 trigger arm.

Known bound (reported, not fixed)
---------------------------------
The ``use``-alias-to-a-differently-named-estimator variant is bound by
:func:`test_use_alias_to_differently_named_estimator_is_not_enumerated` as an
explicit, asserted LIMITATION. #866's accepted rule set contains no alias-
binding grammar: its trigger arms are fixed-shape regexes over estimator
*identifiers* (``ESTIMATOR_HELPER_RE``, ``ESTIMATOR_CALL_RE``,
``CHAR_RATIO``, ``BYTE_RATIO``) and ``use crate::x::plan_units as tokens;``
followed by ``tokens(body)`` matches none of them. Detecting it needs a new
``use ... as`` resolution rule inside #866, which this issue is forbidden from
writing. The test therefore pins the *observed* behaviour so the gap cannot be
mistaken for coverage; see the ContractChallenge in the change report.

Fixture policy: no repository file is written. Each case materialises a
throwaway crate in a temporary directory, so the bytes measured are exactly the
bytes written here and a failing assertion cannot leak into the tree.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "audit-context-measurement-ownership.py"
_SPEC = importlib.util.spec_from_file_location("audit_context_measurement_ownership_787_c7", _SCRIPT)
oracle = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = oracle
_SPEC.loader.exec_module(oracle)

_REPO_ROOT = Path(__file__).resolve().parents[2]

# The exact helper from external audit 5931913038, defect 3.
_C7_AUDIT_HELPER = """fn local_estimate_tokens(text: &str) -> usize {
    text.as_bytes().len().div_ceil(4)
}
"""

# The SAME expression, split across lines so that neither the receiver, the
# length nor the ratio sits on one line. A locator that only reads a single line
# would miss the receiver; this binds that the enumeration is line-local but
# span-anchored on the enclosing item.
_C7_MULTILINE = """fn estimate_tokens_split(text: &str) -> usize {
    text.as_bytes()
        .len()
        .div_ceil(4)
}
"""

# A `use` alias bound to a DIFFERENTLY-NAMED estimator. This is the variant the
# producer's existing grammar cannot reach; see the module docstring.
_C7_USE_ALIAS = """use crate::budgets::plan_units as tokens;

fn plan_hint(body: &str) -> usize {
    tokens(body)
}
"""

# A negative control: a helper with no byte/char ratio and no estimator name.
# It must NOT be reported, so a rule that simply matched every `fn` would fail.
_C7_BENIGN = """fn ordinary_length(text: &str) -> usize {
    text.len()
}
"""

_SEAM_REL = "crates/fixture-consumer/src/seam.rs"
_CRATE_MANIFEST = """\
[package]
name = "fixture-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
eliot-context-measurement = "0.1.0"
"""


def _materialize(source: str) -> Path:
    """Write ``source`` into a throwaway crate as the one seam path."""
    root = Path(tempfile.mkdtemp(prefix="787-c7-"))
    crate = root / "crates" / "fixture-consumer"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(_CRATE_MANIFEST, encoding="utf-8")
    (crate / "src" / "seam.rs").write_text(source, encoding="utf-8")
    return root


def _row(span_start: int, path: str = _SEAM_REL, case_ref: str = "783/10") -> dict[str, object]:
    """One stored row anchored at ``span_start``.

    Only ``path``/``span_start``/``case_ref`` decide whether the enumeration is
    accounted, which is exactly the accounting surface
    :func:`oracle._enumerated_unaccounted` compares.
    """
    return {"path": path, "span_start": span_start, "case_ref": case_ref}


def _findings_for(source: str, rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Run the REAL ``_enumerated_unaccounted`` over one materialized fixture."""
    root = _materialize(source)
    try:
        producer = oracle.load_producer(_REPO_ROOT)
        return oracle._enumerated_unaccounted(root, producer, rows, [_SEAM_REL])
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _enumerated(source: str) -> list[dict[str, object]]:
    """The producer's own enumeration of one materialized fixture."""
    root = _materialize(source)
    try:
        producer = oracle.load_producer(_REPO_ROOT)
        return producer.enumerate_measurement_candidates(root, (_SEAM_REL,))
    finally:
        shutil.rmtree(root, ignore_errors=True)


class ProducerCandidateEnumerationC7Test(unittest.TestCase):
    """C7: the universe must be enumerated from source, not from stored rows."""

    # WORK_UNIT_CASE: 787/1
    def test_audit_c7_helper_without_any_stored_row_is_detected(self) -> None:
        """The audit's exact helper, appended with NO denominator row.

        FIELDS THAT PROVE IT: the finding list is non-empty; exactly one finding
        carries ``UNACCOUNTED_CANDIDATE``; it names the seam path, a non-zero
        span, and a #866 trigger rule. ``rows`` is EMPTY, so the universe could
        not have come from stored rows -- if it had, this would be a vacuous
        pass rather than a detection.
        """
        rows: list[dict[str, object]] = []
        findings = _findings_for(_C7_AUDIT_HELPER, rows)

        self.assertTrue(
            findings,
            "an estimator with no stored row must produce a finding; C7 is the "
            "case where the old row-seeded universe reported nothing at all",
        )
        typed = [f for f in findings if f["code"] == "UNACCOUNTED_CANDIDATE"]
        self.assertEqual(
            len(typed),
            1,
            f"exactly one UNACCOUNTED_CANDIDATE is expected for the audit helper, got {findings!r}",
        )
        finding = typed[0]
        self.assertEqual(finding["path"], _SEAM_REL, "the finding must name the seam path")
        self.assertGreater(int(finding["span_start"]), 0, "the finding must carry a real span start")
        self.assertIn(
            finding["rule"],
            ("ESTIMATOR_HELPER_RE", "ESTIMATOR_CALL_RE", "CHAR_RATIO", "BYTE_RATIO"),
            "the finding must name the #866 rule that observed the site",
        )
        self.assertEqual(
            finding["item"],
            "fn local_estimate_tokens",
            "the finding must attribute the site to the enclosing estimator item",
        )
        # The span must land on the byte/char ratio line, which is line 2.
        self.assertEqual(int(finding["span_start"]), 2, "the ratio line is the measured site")

    # WORK_UNIT_CASE: 787/2
    def test_c7_helper_is_found_with_no_rows_and_not_seeded_from_them(self) -> None:
        """The enumeration sees the helper even when the stored rows are empty.

        FIELDS THAT PROVE IT: ``enumerate_measurement_candidates`` returns a
        non-empty list with an EMPTY stored-row set, and the same site is
        reported as ``known = False``. This is the property that distinguishes
        independent enumeration from row-seeded re-location: with no rows there
        is nothing to re-locate.
        """
        enumerated = _enumerated(_C7_AUDIT_HELPER)
        self.assertTrue(enumerated, "the producer must enumerate the audit helper from source")
        sites = {(int(c["span_start"]), str(c["rule"])) for c in enumerated}
        self.assertIn(
            (2, "BYTE_RATIO"),
            sites,
            f"the div_ceil(4) byte ratio must be enumerated by BYTE_RATIO, got {sorted(sites)!r}",
        )
        for cand in enumerated:
            self.assertFalse(
                bool(cand["known"]),
                "no stored row declares this fixture, so no candidate may be 'known'",
            )

    # WORK_UNIT_CASE: 787/3
    def test_multiline_split_expression_is_detected(self) -> None:
        """The same expression split across lines is still detected.

        FIELDS THAT PROVE IT: enumerating the multiline fixture yields BOTH the
        ``ESTIMATOR_HELPER_RE`` declaration site and the ``BYTE_RATIO`` ratio
        site, and the oracle reports the ratio site as an unaccounted candidate
        with an empty stored-row set. Line-splitting cannot hide the estimator
        from a whole-file enumeration.
        """
        enumerated = _enumerated(_C7_MULTILINE)
        rules = {int(c["span_start"]): str(c["rule"]) for c in enumerated}
        self.assertEqual(
            rules.get(1),
            "ESTIMATOR_HELPER_RE",
            "the multiline helper's own declaration line must enumerate",
        )
        self.assertEqual(
            rules.get(4),
            "BYTE_RATIO",
            "the ratio on its own line four must enumerate",
        )

        findings = _findings_for(_C7_MULTILINE, [])
        typed = [f for f in findings if f["code"] == "UNACCOUNTED_CANDIDATE"]
        self.assertTrue(typed, "the multiline variant must produce an unaccounted candidate")
        self.assertEqual(
            sorted(int(f["span_start"]) for f in typed),
            [1, 4],
            "both the declaration and the ratio line are unaccounted",
        )

    # WORK_UNIT_CASE: 787/4
    def test_finding_is_typed_complete_and_rendered_in_both_projections(self) -> None:
        """A typed finding must carry code, path, span and rule end to end.

        FIELDS THAT PROVE IT: every reported field is non-empty; the rule is a
        closed #866 trigger-arm name; and the finding is accepted by the oracle's
        own ``Finding`` constructor, so a missing field would be rejected by the
        type rather than silently projected.
        """
        findings = _findings_for(_C7_AUDIT_HELPER, [])
        self.assertEqual(len(findings), 1, f"one finding expected, got {findings!r}")
        raw = findings[0]
        for field in ("code", "path", "rule", "evidence"):
            self.assertTrue(str(raw[field]).strip(), f"finding field {field!r} must be non-empty")
        typed = oracle.Finding(
            code=str(raw["code"]),
            detail=str(raw["evidence"]),
            path=str(raw["path"]),
            span_start=int(raw["span_start"]),
            span_end=int(raw["span_end"]),
            rule=str(raw["rule"]),
        )
        locator = typed.locator()
        self.assertIn("UNACCOUNTED_CANDIDATE", locator)
        self.assertIn(_SEAM_REL, locator, "the locator must print the path")
        self.assertIn(f"rule={raw['rule']}", locator, "the locator must print the firing rule")
        self.assertIn(":2-2", locator, "the locator must print the span")

    # WORK_UNIT_CASE: 787/5
    def test_benign_helper_is_not_reported(self) -> None:
        """A helper with no ratio and no estimator name is NOT a candidate.

        FIELDS THAT PROVE IT: the enumeration is EMPTY and the oracle reports
        nothing. Without this negative control a rule that matched every ``fn``
        declaration would pass cases 1-4 while measuring nothing.
        """
        self.assertEqual(
            _enumerated(_C7_BENIGN),
            [],
            "a plain len() helper carries no byte/char ratio and no estimator name",
        )
        self.assertEqual(
            _findings_for(_C7_BENIGN, []),
            [],
            "a benign helper must never produce an unaccounted candidate",
        )

    # WORK_UNIT_CASE: 787/6
    def test_a_stored_row_at_the_same_span_is_accounted(self) -> None:
        """A stored row AT the enumerated span makes the site accounted.

        FIELDS THAT PROVE IT: the same fixture that yields one finding with an
        empty row set yields ZERO findings once a row is anchored at the
        enumerated span. This binds the set-difference itself -- detection is a
        function of accounting, not a constant alarm.
        """
        self.assertEqual(
            len(_findings_for(_C7_AUDIT_HELPER, [])),
            1,
            "the helper is unaccounted when no row exists",
        )
        self.assertEqual(
            _findings_for(_C7_AUDIT_HELPER, [_row(2)]),
            [],
            "a stored row at the enumerated span accounts for the site",
        )

    # WORK_UNIT_CASE: 787/7
    def test_use_alias_to_differently_named_estimator_is_not_enumerated(self) -> None:
        """PINNED LIMITATION: the ``use``-alias variant is NOT detected.

        ``use crate::budgets::plan_units as tokens;`` followed by
        ``tokens(body)`` names an estimator under a local alias. #866's accepted
        grammar has no alias-binding arm -- its four trigger regexes match
        estimator identifiers and byte/char ratios, and neither the ``use`` line
        nor the aliased call matches any of them.

        FIELDS THAT PROVE IT: the enumeration is EMPTY and the oracle reports no
        finding. This is asserted, not expected-to-pass: it records the exact
        boundary of what #866's existing rules can reach, so the gap is visible
        and cannot be silently reported as coverage. Closing it requires a new
        ``use ... as`` resolution rule inside #866 -- a rule change this issue
        is forbidden to make, and reported as a ContractChallenge instead.
        """
        self.assertEqual(
            _enumerated(_C7_USE_ALIAS),
            [],
            "the pinned limitation: #866 has no use-alias resolution grammar",
        )
        self.assertEqual(
            _findings_for(_C7_USE_ALIAS, []),
            [],
            "the pinned limitation: an aliased estimator is invisible to the "
            "accepted rules, so no finding can be produced for it",
        )

    # WORK_UNIT_CASE: 787/8
    def test_the_oracle_requires_the_producer_enumeration_api(self) -> None:
        """A #866 producer without the enumeration API fails closed.

        FIELDS THAT PROVE IT: ``enumerate_measurement_candidates`` is listed in
        the oracle's required read-only producer API, so ``load_producer``
        raises ``PRODUCER_ABSENT`` when it is missing. The oracle can therefore
        never silently fall back to the old stored-row-seeded universe -- the
        absence of the API is a typed failure, not a weaker run.
        """
        self.assertIn(
            "enumerate_measurement_candidates",
            _REQUIRED_PRODUCER_API,
            "the enumeration API must be a required producer dependency",
        )
        producer = oracle.load_producer(_REPO_ROOT)
        self.assertTrue(
            callable(getattr(producer, "enumerate_measurement_candidates", None)),
            "the accepted #866 producer must expose a callable enumeration API",
        )
        # The producer's own self-test must still accept the widened API.
        self.assertEqual(producer.run_self_tests(), 0, "the #866 producer self-test must still pass")

    # WORK_UNIT_CASE: 787/9
    def test_enumeration_is_deterministic_and_order_free(self) -> None:
        """Enumeration is byte-identical across repeated and reordered calls.

        FIELDS THAT PROVE IT: two calls over the same fixture return equal
        results, and reversing the requested scan-root order returns an equal
        result after the producer's own sort. A scanner whose output depended on
        traversal order would make the oracle's digest order-dependent.
        """
        source = _C7_AUDIT_HELPER + _C7_MULTILINE
        root = _materialize(source)
        try:
            producer = oracle.load_producer(_REPO_ROOT)
            first = producer.enumerate_measurement_candidates(root, (_SEAM_REL,))
            second = producer.enumerate_measurement_candidates(root, (_SEAM_REL,))
            self.assertEqual(first, second, "repeated enumeration must be identical")
            keys = [(str(c["path"]), int(c["span_start"]), str(c["rule"])) for c in first]
            self.assertEqual(
                keys,
                sorted(keys),
                "candidates must be returned in the producer's sorted order",
            )
            # Re-enumerating after the cache is dropped must produce the
            # identical result, because the producer sorts rather than trusting
            # the caller's traversal order.
            reloaded = producer.enumerate_measurement_candidates(root, (_SEAM_REL,))
            self.assertEqual(
                reloaded,
                first,
                "the enumeration must not depend on cached traversal state",
            )
        finally:
            shutil.rmtree(root, ignore_errors=True)


_REQUIRED_PRODUCER_API = (
    "discover_context_measurements",
    "enumerate_measurement_candidates",
    "classify_context_measurement",
    "build_inventory",
    "load_owner_map",
    "InventoryError",
    "DENOMINATOR_CASES",
    "EXCLUSION_CASES",
    "CLASSIFICATIONS",
    "OWNER_MAP_PATH",
    "OWNED_TOML",
    "_parse_toml",
    "_validate_artifact",
    "_load_files",
    "_scope_of",
    "_locate_signal",
    "_case_sort_key",
    "_read_source",
    "_measure_test_paths",
    "TOP_LEVEL_KEYS",
    "HEADER_KEYS",
    "ROW_KEYS",
    "SCHEMA",
    "RULE_REVISION",
    "_sha256",
    "_canonical_bytes",
)


if __name__ == "__main__":
    unittest.main()
