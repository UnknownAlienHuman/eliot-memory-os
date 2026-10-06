"""Refuse retired authority and campaign surfaces from the accepted record (issue #1225).

The retirement authority lives in workstreams/security/retired-authority-surfaces.toml,
never in an inline workflow list: retiring or restoring a surface means changing
that record, and the verdict follows the record. A missing or malformed record
is an error, never a silent pass.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

DEFAULT_RECORD = Path("workstreams/security/retired-authority-surfaces.toml")


def load_record_surfaces(record_path: Path) -> list[str]:
    """Read the accepted surface paths, failing closed on any malformed record."""
    try:
        with record_path.open("rb") as handle:
            record = tomllib.load(handle)
    except OSError as exc:
        raise ValueError(f"{record_path}: cannot read retirement record ({exc})") from exc
    surfaces = record.get("surface", [])
    if not isinstance(surfaces, list) or not surfaces:
        raise ValueError(f"{record_path}: 'surface' must be a non-empty array of tables")
    paths = []
    for entry in surfaces:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or not entry["path"].strip():
            raise ValueError(f"{record_path}: every [[surface]] entry must carry a non-empty 'path'")
        paths.append(entry["path"])
    if len(set(paths)) != len(paths):
        raise ValueError(f"{record_path}: duplicate surface paths")
    return paths


def check_retired_surfaces(root: Path, surfaces: list[str]) -> list[str]:
    """Return the record paths still present under root (empty means retired)."""
    return sorted(path for path in surfaces if (root / path).exists())


def run_self_tests() -> int:
    import tempfile

    print("Running retired-authority-surfaces self-tests...")

    # Case 1: a present surface is refused.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "swarm").mkdir()
        if check_retired_surfaces(root, ["swarm", "reports"]) != ["swarm"]:
            print("SELF_TEST_FAILURE: expected present surface 'swarm' refused", file=sys.stderr)
            return 1

    # Case 2: a fully retired record is accepted.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        if check_retired_surfaces(root, ["swarm", "reports"]):
            print("SELF_TEST_FAILURE: expected absent surfaces accepted", file=sys.stderr)
            return 1

    # Case 3: editing the record flips the verdict.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "swarm").mkdir()
        record = root / "record.toml"
        record.write_text('[[surface]]\npath = "swarm"\n', encoding="utf-8")
        if check_retired_surfaces(root, load_record_surfaces(record)) != ["swarm"]:
            print("SELF_TEST_FAILURE: expected record-listed surface refused", file=sys.stderr)
            return 1
        record.write_text('[[surface]]\npath = "reports"\n', encoding="utf-8")
        if check_retired_surfaces(root, load_record_surfaces(record)):
            print("SELF_TEST_FAILURE: expected edited record to flip the verdict", file=sys.stderr)
            return 1

    # Case 4: a malformed record fails closed, never silently passes.
    with tempfile.TemporaryDirectory() as tmp:
        record = Path(tmp) / "record.toml"
        record.write_text('[[surface]]\npath = ""\n', encoding="utf-8")
        try:
            load_record_surfaces(record)
        except ValueError:
            pass
        else:
            print("SELF_TEST_FAILURE: expected malformed record rejected", file=sys.stderr)
            return 1

    print("RETIRED_AUTHORITY_SURFACES_SELF_TEST: PASS (4/4 cases verified)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refuse retired authority and campaign surfaces.")
    parser.add_argument("--root", default=".", help="Repository root directory")
    parser.add_argument("--record", default=str(DEFAULT_RECORD), help="Accepted retirement record")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_tests()

    root = Path(args.root)
    try:
        surfaces = load_record_surfaces(Path(args.record))
    except ValueError as exc:
        print(f"RETIRED_AUTHORITY_SURFACES: ERROR {exc}", file=sys.stderr)
        return 2
    present = check_retired_surfaces(root, surfaces)
    if present:
        for path in present:
            print(f"RETIRED_AUTHORITY_SURFACES: refused: retired surface is present: {path}")
        return 1
    print(f"RETIRED_AUTHORITY_SURFACES: PASS ({len(surfaces)}/{len(surfaces)} retired surfaces absent)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
