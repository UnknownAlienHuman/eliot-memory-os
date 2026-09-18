"""Disposition+owner inventory proof for standalone-workspace crates (issue #1811).

Acceptance pinned here: every standalone-workspace package has a checked-in
disposition and named owner in
`workstreams/security/standalone-crate-dispositions.toml`.

The denominator is derived from the tree with the same rule as
`scripts/verify-standalone-crates.py` (own `[workspace]` table, carries a
`[package]`, neither a root member nor in root `exclude`, ignoring
`target`/`testdata`/`fixtures`), never from the inventory itself, so a new
undeclared standalone crate, a stale row, or an edited admission marker fails
instead of diverging silently. SBOM/lock/provenance and release gating are
REMAINDER and are not asserted here.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "workstreams/security/standalone-crate-dispositions.toml"
IGNORED_PARTS = {"target", "testdata", "fixtures"}

REQUIRED_ROW_KEYS = {
    "path",
    "package",
    "standalone",
    "prototype",
    "source_status",
    "workspace_admission",
    "lifecycle_owner",
    "lifecycle_owner_source",
    "integration_owner",
    "integration_owner_source",
    "production_boundary",
    "remainder",
}


def discover_standalone_packages(root: Path) -> dict[str, str]:
    """Map crate dir (posix, relative) -> package name for standalone packages."""
    data = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    members = set(data.get("members", []))
    exclude = set(data.get("exclude", []))
    found: dict[str, str] = {}
    for manifest in sorted(root.rglob("Cargo.toml")):
        if any(part in IGNORED_PARTS for part in manifest.parts):
            continue
        if manifest == root / "Cargo.toml":
            continue
        text = manifest.read_text(encoding="utf-8")
        if "[workspace]" not in text:
            continue
        relative = manifest.parent.relative_to(root).as_posix()
        if relative in members or relative in exclude:
            continue
        parsed = tomllib.loads(text)
        if "package" not in parsed:
            continue
        found[relative] = str(parsed["package"]["name"])
    return found


def load_inventory() -> dict:
    return tomllib.loads(INVENTORY.read_text(encoding="utf-8"))


class TestStandaloneDispositions1811(unittest.TestCase):
    def test_inventory_denominator_matches_tree(self) -> None:
        discovered = discover_standalone_packages(ROOT)
        rows = load_inventory().get("crate", [])
        inventoried = {str(row["path"]): str(row["package"]) for row in rows}
        self.assertEqual(
            inventoried,
            discovered,
            "inventory rows must equal the tree-derived standalone denominator: "
            f"missing={sorted(set(discovered) - set(inventoried))} "
            f"stale={sorted(set(inventoried) - set(discovered))}",
        )

    def test_every_row_has_disposition_and_named_owner(self) -> None:
        for row in load_inventory().get("crate", []):
            with self.subTest(crate=row.get("path")):
                self.assertTrue(
                    REQUIRED_ROW_KEYS <= set(row),
                    f"row is missing keys: {sorted(REQUIRED_ROW_KEYS - set(row))}",
                )
                for key in (
                    "workspace_admission",
                    "lifecycle_owner",
                    "lifecycle_owner_source",
                    "integration_owner",
                    "integration_owner_source",
                ):
                    self.assertTrue(
                        str(row[key]).strip(),
                        f"{key} must be a named non-empty value",
                    )
                self.assertTrue(row["prototype"], "standalone rows are prototypes")
                owner_source = ROOT / str(row["lifecycle_owner_source"])
                self.assertTrue(
                    owner_source.is_file(),
                    f"lifecycle owner source must exist: {owner_source}",
                )

    def test_workspace_admission_matches_live_manifest(self) -> None:
        for row in load_inventory().get("crate", []):
            with self.subTest(crate=row.get("path")):
                manifest = ROOT / str(row["path"]) / "Cargo.toml"
                live = tomllib.loads(manifest.read_text(encoding="utf-8"))
                metadata = live["package"]["metadata"]["eliot"]
                for key in ("source_status", "workspace_admission"):
                    self.assertEqual(
                        str(row[key]),
                        str(metadata[key]),
                        f"inventory {key} must quote the live manifest verbatim",
                    )
                self.assertEqual(
                    str(row["package"]), str(live["package"]["name"])
                )

    def test_rows_are_unique_and_sorted(self) -> None:
        paths = [str(row["path"]) for row in load_inventory().get("crate", [])]
        self.assertEqual(len(paths), len(set(paths)), "duplicate inventory rows")
        self.assertEqual(paths, sorted(paths), "rows must stay sorted by path")


if __name__ == "__main__":
    unittest.main()
