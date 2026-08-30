"""Cross-cell uniqueness checks for explicit ownership claims."""

from __future__ import annotations

from .model import Cell, Finding


def ownership_findings(cells: list[Cell]) -> list[Finding]:
    findings: list[Finding] = []
    cell_ids: dict[str, Cell] = {}
    state_owners: dict[str, tuple[str, str]] = {}
    contract_owners: dict[str, tuple[str, str]] = {}

    for cell in cells:
        if cell.cell_id in cell_ids:
            findings.append(
                Finding(
                    "duplicate_cell_id",
                    cell.cell_manifest,
                    f"also declared by {cell_ids[cell.cell_id].package}",
                    cell.package,
                    cell.cell_id,
                )
            )
        else:
            cell_ids[cell.cell_id] = cell

        for state in cell.owned_state:
            previous = state_owners.get(state.state_id)
            if previous:
                findings.append(
                    Finding(
                        "duplicate_state_owner",
                        cell.cell_manifest,
                        f"{state.state_id} already owned by {previous[0]} in {previous[1]}",
                        cell.package,
                        cell.cell_id,
                    )
                )
            else:
                state_owners[state.state_id] = (state.owner, cell.cell_id)

        for contract in cell.contracts:
            previous = contract_owners.get(contract.path)
            if previous and previous[0] != contract.owner:
                findings.append(
                    Finding(
                        "duplicate_contract_owner",
                        contract.path,
                        f"{contract.owner} conflicts with {previous[0]} from {previous[1]}",
                        cell.package,
                        cell.cell_id,
                    )
                )
            else:
                contract_owners[contract.path] = (contract.owner, cell.cell_id)

    return findings
