"""Minimal proof for issue #1860 (migration inventory and impact graph).

Owner order is minimal proof only: no fixture matrices, no test campaigns.
Covers exactly the acceptance predicates that do not need a live tree scan:
every dispositioned row carries an allowed I19.3 verb plus a named owner, the
repair impact graph is closed, and the Product Proof plan names the
installed-route receipt. The live-tree gate itself is
`python scripts/migration_inventory_1860.py --check`.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import migration_inventory_1860 as inv

ALLOWED = {"KEEP", "WRAP", "EXTRACT", "REWORK", "REPLACE", "RETIRE", "UNKNOWN"}


class TestMigrationInventory1860(unittest.TestCase):
    def test_tool_self_test_passes(self) -> None:
        self.assertEqual(inv.run_self_tests(), 0)

    def test_explicit_rows_carry_allowed_verbs_and_named_owners(self) -> None:
        rows = (
            [(p, inv.RETIRE_PATHS[p]) for p in inv.RETIRE_PATHS]
            + [(p, inv.WRAP_PATHS[p]) for p in inv.WRAP_PATHS]
            + [(p, inv.UNKNOWN_PATHS[p]) for p in inv.UNKNOWN_PATHS]
            + [(p, inv.KEEP_PATHS[p]) for p in inv.KEEP_PATHS]
        )
        self.assertGreaterEqual(len(rows), 20, "explicit ledger must be non-trivial")
        for path, (owner, rationale) in rows:
            with self.subTest(path=path):
                disp, got_owner, got_rationale = inv.assign_disposition(path, {})
                self.assertIn(disp, ALLOWED)
                self.assertTrue(got_owner.strip(), "named owner required")
                self.assertTrue(got_rationale.strip(), "rationale required")

    def test_fallback_is_fail_closed_unknown(self) -> None:
        disp, owner, rationale = inv.assign_disposition("crates/never-seen/eliot-x", {})
        self.assertEqual(disp, "UNKNOWN")
        self.assertTrue(owner.strip())
        self.assertIn("fail-closed", rationale)

    def test_impact_graph_is_closed(self) -> None:
        nodes = {n for n, _ in inv.IMPACT_NODES}
        self.assertEqual(len(nodes), len(inv.IMPACT_NODES), "node ids must be unique")
        for frm, to, rel in inv.IMPACT_EDGES:
            with self.subTest(edge=f"{frm}->{to}"):
                self.assertIn(frm, nodes)
                self.assertIn(to, nodes)
                self.assertTrue(rel.strip())
        self.assertIn("WINDOWS-PRODUCT-PROOF", nodes)

    def test_product_proof_plan_names_installed_route_receipt(self) -> None:
        plan = ROOT / inv.PRODUCT_PROOF_PLAN
        self.assertTrue(plan.is_file(), f"missing {inv.PRODUCT_PROOF_PLAN}")
        body = plan.read_text(encoding="utf-8", errors="replace")
        self.assertIn(inv.INSTALLED_ROUTE_RECEIPT, body)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
