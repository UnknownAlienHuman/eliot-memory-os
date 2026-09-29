#!/usr/bin/env python3
"""Generate the executable capability-cell registry block of the #13 contract (#18 W1).

The canonical source of the daemon capability cells is
`bins/eliotd/Cargo.toml::[package.metadata.eliot]` (`functional_cell_refs` and
`functional_cell_state_owners`). The `[[declared_functional_cell]]` block of
`workstreams/core-daemons/capability-cell-registry.contract.toml` is GENERATED
from that manifest instead of hand-copied, so the contract can never silently
diverge from the declaration it claims to project (I2.23: a generated
`CapabilityCellRegistry` is compiled from `[package.metadata.eliot]`
`.functional_cell_refs`; prose never maintains a parallel list).

Usage:

    python scripts/gen_capability_cell_registry.py            # write the block
    python scripts/gen_capability_cell_registry.py --check    # gate: non-zero if stale

`--check` compares the committed block byte for byte against what the current
manifest would emit. A manifest cell/owner change therefore fails the gate
until the contract is regenerated and reviewed. A hand-edited generated row
cannot be kept, because the check compares bytes.

Ownership truth flows one way, manifest -> contract. The per-cell evidence
pointers (`source_owner`, `source_evidence`, `state_evidence`,
`runtime_bundle`, `stateless`) are pinned per-cell annex data carried from the
existing rows keyed by cell id: they are pointers into the source, not a
parallel owner list, and the generator refuses to invent, drop, or reassign
one. A cell with an undeclared state owner, or a second owner for the same
mutable state, is a registry defect (I2.23), and the generator fails closed
instead of emitting it.

The generator fails closed. A missing manifest table, a refs/owners cell-set
mismatch, a duplicate cell, an owner symbol claimed by two cells, a manifest
cell with no pinned evidence row, and a pinned row for a cell the manifest no
longer declares are each a non-zero exit with a named reason, so the committed
block can never silently diverge from the manifest it claims to mirror.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

# ---------------------------------------------------------------------------
# Pinned inputs.
# ---------------------------------------------------------------------------

MANIFEST_RELATIVE = "bins/eliotd/Cargo.toml"
CONTRACT_RELATIVE = "workstreams/core-daemons/capability-cell-registry.contract.toml"
METADATA_POINTER = "bins/eliotd/Cargo.toml::package.metadata.eliot.functional_cell_refs"

BEGIN_MARKER = (
    "# BEGIN GENERATED declared_functional_cell "
    "(scripts/gen_capability_cell_registry.py from "
    "bins/eliotd/Cargo.toml [package.metadata.eliot]; do not hand-edit)"
)
END_MARKER = "# END GENERATED declared_functional_cell"

ANNEX_FIELDS = (
    "source_owner",
    "source_evidence",
    "state_evidence",
    "runtime_bundle",
    "stateless",
)


class RegistryError(Exception):
    """Fail-closed named reason; the exit code distinguishes stale from broken."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


def load_manifest_cells(manifest_path: Path) -> tuple[list[str], dict[str, dict[str, str]]]:
    """Return manifest cell order and the cell -> {state, owner} map."""
    try:
        payload = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise RegistryError("MANIFEST_UNREADABLE", str(error)) from error
    metadata = payload.get("package", {}).get("metadata", {}).get("eliot")
    if not isinstance(metadata, dict):
        raise RegistryError(
            "MANIFEST_METADATA_MISSING",
            f"{MANIFEST_RELATIVE} has no [package.metadata.eliot] table",
        )
    refs = metadata.get("functional_cell_refs")
    if not isinstance(refs, list) or not refs or not all(
        isinstance(cell, str) and cell.strip() for cell in refs
    ):
        raise RegistryError(
            "FUNCTIONAL_CELL_REFS_MISSING",
            "functional_cell_refs must be a non-empty string list",
        )
    owners = metadata.get("functional_cell_state_owners")
    if not isinstance(owners, list) or not owners:
        raise RegistryError(
            "STATE_OWNERS_MISSING",
            "functional_cell_state_owners must be a non-empty table list",
        )
    by_cell: dict[str, dict[str, str]] = {}
    seen_owners: dict[str, str] = {}
    for index, entry in enumerate(owners):
        if not isinstance(entry, dict):
            raise RegistryError(
                "STATE_OWNER_SHAPE",
                f"functional_cell_state_owners[{index}] is not a table",
            )
        cell = entry.get("cell")
        state = entry.get("state")
        owner = entry.get("owner")
        for field, value in (("cell", cell), ("state", state), ("owner", owner)):
            if not isinstance(value, str) or not value.strip():
                raise RegistryError(
                    "STATE_OWNER_SHAPE",
                    f"functional_cell_state_owners[{index}] has an empty {field}",
                )
        if cell in by_cell:
            raise RegistryError("DUPLICATE_CELL", f"cell is declared twice: {cell}")
        if owner in seen_owners:
            raise RegistryError(
                "DUPLICATE_STATE_OWNER",
                f"owner {owner} is claimed by {seen_owners[owner]} and {cell}; "
                "a second owner for mutable state is a registry defect",
            )
        seen_owners[owner] = cell
        by_cell[cell] = {"state": state, "owner": owner}
    if set(refs) != set(by_cell):
        missing = sorted(set(refs) - set(by_cell))
        extra = sorted(set(by_cell) - set(refs))
        raise RegistryError(
            "CELL_SET_MISMATCH",
            f"functional_cell_refs and functional_cell_state_owners disagree: "
            f"refs-without-owner={missing} owners-without-ref={extra}",
        )
    if len(set(refs)) != len(refs):
        raise RegistryError("DUPLICATE_CELL", "functional_cell_refs repeats a cell")
    return list(refs), by_cell


def load_evidence_annex(contract_text: str) -> dict[str, dict[str, object]]:
    """Return the pinned per-cell evidence columns keyed by cell id."""
    try:
        payload = tomllib.loads(contract_text)
    except tomllib.TOMLDecodeError as error:
        raise RegistryError("CONTRACT_UNREADABLE", str(error)) from error
    rows = payload.get("declared_functional_cell", [])
    if not isinstance(rows, list):
        raise RegistryError("CONTRACT_SHAPE", "declared_functional_cell is not an array")
    annex: dict[str, dict[str, object]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not isinstance(row.get("cell"), str):
            raise RegistryError(
                "CONTRACT_SHAPE", f"declared_functional_cell[{index}] names no cell"
            )
        cell = row["cell"]
        if cell in annex:
            raise RegistryError("DUPLICATE_ANNEX_CELL", f"annex repeats cell: {cell}")
        pinned: dict[str, object] = {}
        for field in ANNEX_FIELDS:
            value = row.get(field)
            if field == "stateless":
                if not isinstance(value, bool):
                    raise RegistryError(
                        "EVIDENCE_PIN_SHAPE",
                        f"cell {cell} has a non-boolean stateless pin",
                    )
            elif not isinstance(value, str) or not value.strip():
                raise RegistryError(
                    "EVIDENCE_PIN_SHAPE", f"cell {cell} has an empty {field} pin"
                )
            pinned[field] = value
        annex[cell] = pinned
    return annex


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_row(cell: str, owner: str, annex: dict[str, object]) -> str:
    lines = [
        "[[declared_functional_cell]]",
        f"cell = {_quote(cell)}",
        f"declared_by = {_quote(METADATA_POINTER)}",
        f"source_owner = {_quote(str(annex['source_owner']))}",
        f"mutable_state_owner = {_quote(owner)}",
        f"source_evidence = {_quote(str(annex['source_evidence']))}",
        f"state_evidence = {_quote(str(annex['state_evidence']))}",
        f"runtime_bundle = {_quote(str(annex['runtime_bundle']))}",
        f"stateless = {'true' if annex['stateless'] else 'false'}",
    ]
    return "\n".join(lines)


def render_block(
    cells: list[str],
    owners: dict[str, dict[str, str]],
    annex: dict[str, dict[str, object]],
) -> str:
    """Render the generated inner block, including its surrounding newlines."""
    missing = [cell for cell in cells if cell not in annex]
    if missing:
        raise RegistryError(
            "EVIDENCE_PIN_MISSING",
            f"manifest cells with no pinned evidence row: {missing}",
        )
    stale = sorted(set(annex) - set(cells))
    if stale:
        raise RegistryError(
            "STALE_EVIDENCE_PIN",
            f"pinned evidence rows for cells the manifest no longer declares: {stale}",
        )
    rows = [render_row(cell, owners[cell]["owner"], annex[cell]) for cell in cells]
    return "\n" + "\n\n".join(rows) + "\n"


def replace_block(contract_text: str, block: str) -> str:
    begin = contract_text.find(BEGIN_MARKER)
    end = contract_text.find(END_MARKER)
    if begin < 0 or end < 0 or end < begin:
        raise RegistryError(
            "GENERATED_BLOCK_MARKERS_MISSING",
            "the contract carries no generated declared_functional_cell block",
        )
    head = contract_text[: begin + len(BEGIN_MARKER)]
    tail = contract_text[end:]
    return head + block + tail


def emit(root: Path) -> tuple[str, str]:
    """Return (committed_text, regenerated_text) for the contract file."""
    manifest_path = root / MANIFEST_RELATIVE
    contract_path = root / CONTRACT_RELATIVE
    try:
        committed = contract_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise RegistryError("CONTRACT_UNREADABLE", str(error)) from error
    cells, owners = load_manifest_cells(manifest_path)
    annex = load_evidence_annex(committed)
    return committed, replace_block(committed, render_block(cells, owners, annex))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the capability-cell registry block from the eliotd manifest."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    try:
        committed, regenerated = emit(root)
    except RegistryError as error:
        print(f"CAPABILITY_CELL_REGISTRY_{error.reason}: {error}", file=sys.stderr)
        return 2
    if regenerated == committed:
        print(
            "CAPABILITY_CELL_REGISTRY_GENERATE: IN_SYNC "
            f"source={MANIFEST_RELATIVE} contract={CONTRACT_RELATIVE}"
        )
        return 0
    if args.check:
        print(
            "CAPABILITY_CELL_REGISTRY_STALE: regenerate with "
            "python scripts/gen_capability_cell_registry.py",
            file=sys.stderr,
        )
        return 1
    (root / CONTRACT_RELATIVE).write_text(regenerated, encoding="utf-8")
    print(
        "CAPABILITY_CELL_REGISTRY_GENERATE: WROTE "
        f"source={MANIFEST_RELATIVE} contract={CONTRACT_RELATIVE}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
