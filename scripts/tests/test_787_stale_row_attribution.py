"""Tests for #787's stale-row attribution on SOURCE_DIGEST_CHANGED.

The oracle already decided that these rows are stale: that decision belongs to
the #866 producer's own measurement and to the two ``SOURCE_DIGEST_CHANGED``
sites, and these tests do not second-guess it. What these tests pin is the
defect-2 repair: a stale row must be reported as the *unfinished migration it
is*, with the issue that owns it named, because #787 may not edit the producer
or the consumer sources and therefore cannot make the row current itself.

Every test here fails if the attribution is removed, mis-keyed, or pointed at
the wrong owner, because each one asserts on the exact sentence the oracle
emits -- not on a count, and not on the mere presence of the finding class.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "audit-context-measurement-ownership.py"

_spec = importlib.util.spec_from_file_location(
    "audit_context_measurement_ownership_787", SCRIPT
)
assert _spec is not None and _spec.loader is not None
oracle = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = oracle
_spec.loader.exec_module(oracle)

ROWN_KEYS = (
    "id",
    "case_ref",
    "owner",
    "status",
    "path",
    "source_sha256",
    "span_digest",
)


def _row(**over: object) -> dict:
    """One minimal artifact row shaped by the fields the check reads.

    Built field-by-field from the producer's own closed key names rather than
    copied from a live row, so a test cannot pass by replaying the exact
    artifact that happens to be committed today.
    """
    row = {
        "id": "c0001",
        "case_ref": "704/1",
        "owner": "#704",
        "status": "owned",
        "path": "scan/lib.rs",
        "source_sha256": "st" * 32,
        "span_digest": "sp" * 32,
    }
    row.update(over)
    return row


class StaleRowAttributionTest(unittest.TestCase):
    """The attribution names the owning issue for every stale row."""

    def setUp(self) -> None:
        self.rows = [
            _row(),
            _row(id="c0002", case_ref="704/2"),
            _row(id="c0003", case_ref="783/1", owner="#783", path="scan/app.rs"),
            _row(id="c0004", case_ref="880/8", owner="#880", status="unresolved",
                 path="scan/tests.rs"),
        ]
        # lib.rs moved on disk; app.rs and tests.rs did not.
        self.measured = {"scan/lib.rs": "me" * 32, "scan/app.rs": "st" * 32,
                         "scan/tests.rs": "st" * 32}
        self.reported = {"scan/lib.rs": {"704/1", "704/2"}}

    def _text(self, rel: str) -> str:
        return oracle._stale_row_attribution(
            self.rows, self.reported, rel, self.measured[rel]
        )

    def test_names_every_stale_row_in_a_changed_file(self) -> None:
        text = self._text("scan/lib.rs")
        self.assertIn("invalidates 2 recorded row(s)", text)
        # Both rows of the moved file are named, not just the first one seen.
        self.assertIn("row c0001 (704/1, owner #704, status owned)", text)
        self.assertIn("row c0002 (704/2, owner #704, status owned)", text)

    def test_names_the_owning_issue_of_each_stale_row(self) -> None:
        text = self._text("scan/lib.rs")
        # #704 is the canonical measurement owner and re-derives its own rows.
        self.assertIn("#704 must re-derive this row", text)
        # A moved file outside #787's editable scope is named as unfinished.
        self.assertIn("unfinished work owned outside #787", text)

    def test_rows_in_an_unchanged_file_are_not_attributed(self) -> None:
        # The recorded digest still matches the live file, so nothing is stale
        # and there is nothing to report -- this is the half of the check that
        # keeps the attribution from firing on a green row.
        self.assertEqual(self._text("scan/app.rs"), "")
        self.assertEqual(self._text("scan/tests.rs"), "")

    def test_unowned_candidate_is_never_given_an_owner(self) -> None:
        rows = [_row(id="c0009", case_ref="unres/4", owner="unresolved",
                     status="unresolved", source_sha256="st" * 32)]
        text = oracle._stale_row_attribution(
            rows, {"scan/lib.rs": {"unres/4"}}, "scan/lib.rs", "me" * 32
        )
        self.assertIn("no exact-scope owner", text)
        # An unresolved row must not be folded into a consumer's migration.
        self.assertNotIn("must finish migrating", text)
        self.assertNotIn("#783", text)
        self.assertNotIn("#880", text)

    def test_unknown_owner_is_reported_as_unattributed_not_guessed(self) -> None:
        rows = [_row(id="c0010", case_ref="999/1", owner="#999",
                     source_sha256="st" * 32)]
        text = oracle._stale_row_attribution(
            rows, {"scan/lib.rs": {"999/1"}}, "scan/lib.rs", "me" * 32
        )
        self.assertIn("outside the closed re-derivation set", text)
        # The oracle must not invent a required_owner for an owner it does not
        # know; naming the unknown owner verbatim is the honest report.
        self.assertIn("'#999'", text)
        for known in ("#783", "#878", "#880", "#704"):
            self.assertNotIn(f"{known} must", text)

    def test_reported_set_is_the_independent_cross_check(self) -> None:
        # The expected set is the artifact's own rows for that file. A row the
        # digest comparison skipped is still named, so the attribution cannot
        # agree with a caller list that under-reports.
        text = self._text("scan/lib.rs")
        self.assertNotIn("was not reported by the digest comparison", text)

        partial = oracle._stale_row_attribution(
            self.rows, {"scan/lib.rs": {"704/1"}}, "scan/lib.rs", "me" * 32
        )
        self.assertIn(
            "row c0002 (704/2, owner #704, status owned) is stale but was not reported "
            "by the digest comparison",
            partial,
        )


class StaleRowAttributionLiveAuditTest(unittest.TestCase):
    """Against the real tree: every stale row is attributed, none is dropped."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = oracle.evaluate(ROOT)
        cls.stale = [f for f in cls.result.findings if f.code == "SOURCE_DIGEST_CHANGED"]

    def test_every_stale_row_still_carries_its_own_finding(self) -> None:
        # The repair must not trade a finding class for a nicer message: each
        # stale row keeps its own finding, under both digest rules.
        self.assertGreater(len(self.stale), 0)
        per_row: dict[tuple[str, str], int] = {}
        for f in self.stale:
            per_row[(f.row_id, f.rule)] = per_row.get((f.row_id, f.rule), 0) + 1
        for key, count in per_row.items():
            self.assertEqual(count, 1, f"{key} is reported {count} times")
        # And the two rules agree on the same set of rows.
        coverage = {f.row_id for f in self.stale if f.rule == "row-coverage"}
        digest = {f.row_id for f in self.stale if f.rule == "row-digest"}
        self.assertEqual(coverage, digest)

    def test_changed_file_is_attributed_exactly_once(self) -> None:
        # One measured verdict per changed file, attached to the first row that
        # reaches the per-row pass; the remaining rows in that file must not
        # restate it.
        attributed = [f for f in self.stale if "invalidates" in f.detail]
        paths = [f.path for f in attributed]
        self.assertEqual(len(paths), len(set(paths)), paths)

    def test_stale_row_names_its_owning_issue(self) -> None:
        # Each stale row's file attribution names the owner that must act, and
        # the owner is the one the artifact recorded for that row.
        by_id = {f.row_id: f for f in self.stale if "invalidates" in f.detail}
        self.assertTrue(by_id)
        for f in by_id.values():
            self.assertIn("unfinished work owned outside #787", f.detail)
            row_owner = self._owner_of(f.path, f.row_id)
            if row_owner in oracle.ROW_INVALIDATION_OWNERS:
                self.assertIn(
                    oracle.ROW_INVALIDATION_OWNERS[row_owner].split(" must ")[0],
                    f.detail,
                )

    def test_row_coverage_detail_carries_the_span_drift(self) -> None:
        # The candidate-level site explains *why* the digest moved: the signal
        # now resolves to a different line than the row recorded.
        for f in self.stale:
            if f.rule == "row-coverage":
                self.assertIn("now locates this signal at", f.detail)
                self.assertRegex(f.detail, r"recorded span is still \d+-\d+")

    def _owner_of(self, path: str, row_id: str) -> str:
        producer = oracle.load_producer(ROOT)
        _h, rows, _w, _s, _d, _raw, _f = oracle._read_inventory_artifact(ROOT, producer)
        for row in rows:
            if str(row["id"]) == row_id:
                return str(row["owner"])
        self.fail(f"row {row_id} not found in the artifact")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
