"""Fail-closed excluded-disposition gate proof (issue #1811, slice 2 / go15).

Covers the REMAINDER from slice 1: every standalone/excluded package carries
a checked-in disposition verb (KEEP/WRAP/EXTRACT/REWORK/REPLACE/RETIRE/UNKNOWN)
plus a named owner, and any build/release consumption of an inventoried
package without provenance, lock, toolchain, license, and SBOM evidence is
rejected.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "workstreams/security/standalone-crate-dispositions.toml"
GATE = ROOT / "scripts/verify-excluded-dispositions-1811.py"
ALLOWED = {"KEEP", "WRAP", "EXTRACT", "REWORK", "REPLACE", "RETIRE", "UNKNOWN"}


def run_gate(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )


class TestExcludedDispositionsGate1811(unittest.TestCase):
    def test_every_row_has_disposition_verb_and_named_owner(self) -> None:
        data = tomllib.loads(INVENTORY.read_text(encoding="utf-8"))
        rows = data.get("crate", [])
        self.assertGreaterEqual(len(rows), 11, "must cover the standalone denominator")
        for row in rows:
            with self.subTest(crate=row.get("path")):
                self.assertIn(str(row.get("disposition")), ALLOWED)
                self.assertTrue(str(row.get("owner", "")).strip())

    def test_gate_passes_on_current_tree(self) -> None:
        completed = run_gate(ROOT)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("EXCLUDED_DISPOSITIONS: PASS", completed.stdout)

    def test_gate_rejects_consumer_without_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            # minimal repo skeleton: root workspace + inventory copy + one
            # standalone crate + one consumer referencing it by path
            (tmp_root / "workstreams/security").mkdir(parents=True)
            (tmp_root / INVENTORY.relative_to(ROOT)).write_bytes(INVENTORY.read_bytes())
            (tmp_root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["consumer"]\nexclude = []\n', encoding="utf-8"
            )
            stand = tmp_root / "standalone-a"
            stand.mkdir()
            (stand / "Cargo.toml").write_text(
                '[package]\nname = "standalone-a"\nversion = "0.1.0"\nedition = "2021"\n\n[workspace]\n',
                encoding="utf-8",
            )
            consumer = tmp_root / "consumer"
            consumer.mkdir()
            (consumer / "Cargo.toml").write_text(
                '[package]\nname = "consumer"\nversion = "0.1.0"\nedition = "2021"\n\n'
                '[dependencies]\nstandalone-a = { path = "../standalone-a" }\n',
                encoding="utf-8",
            )
            # inventory in tmp points at a different path layout, so rewrite
            # the single row to match this fixture denominator
            (tmp_root / INVENTORY.relative_to(ROOT)).write_text(
                '[[crate]]\npath = "standalone-a"\npackage = "standalone-a"\n'
                'disposition = "REWORK"\nowner = "fixture-owner"\n',
                encoding="utf-8",
            )
            completed = run_gate(tmp_root)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("without", completed.stdout)
            self.assertIn("provenance", completed.stdout)


if __name__ == "__main__":
    unittest.main()
