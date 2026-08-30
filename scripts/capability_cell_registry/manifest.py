"""Package and cell-manifest discovery and validation."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .model import (
    CELL_SCHEMA,
    EXECUTION_CONTOURS,
    EXECUTION_VALUES,
    REPLACEMENT_CLASSES,
    SKIP_DIRS,
    SUPPORT_VALUES,
    Cell,
    ContractSource,
    ScopeSelection,
    StateOwner,
    fail,
    nonempty,
    read_toml,
    relative,
    repo_path,
    sha256,
    string_list,
)


def matching_scope(package_root: str, scope: ScopeSelection) -> tuple[str, ...]:
    package = PurePosixPath(package_root)
    selectors: set[str] = set()
    for explicit in scope.explicit_package_roots:
        if package == PurePosixPath(explicit):
            selectors.add(f"package:{explicit}")
    for selected_path in scope.selected_paths:
        if selected_path in scope.explicit_package_roots:
            continue
        path = PurePosixPath(selected_path)
        if package == path or path in package.parents or package in path.parents:
            selectors.add(f"inventory-path:{selected_path}")
    return tuple(sorted(selectors))


def cargo_manifests(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS]
        if "Cargo.toml" in files:
            yield Path(current) / "Cargo.toml"


def parse_states(
    cell_id: str,
    value: Any,
    stateless: bool,
) -> tuple[StateOwner, ...]:
    if value is None:
        states: tuple[StateOwner, ...] = ()
    else:
        if not isinstance(value, list):
            fail(f"cell {cell_id} owned_state must be a list")
        parsed: list[StateOwner] = []
        for index, item in enumerate(value):
            if not isinstance(item, dict):
                fail(f"cell {cell_id} owned_state[{index}] must be a table")
            parsed.append(
                StateOwner(
                    nonempty(f"cell {cell_id} state_id", item.get("state_id")),
                    nonempty(f"cell {cell_id} state owner", item.get("owner")),
                )
            )
        states = tuple(sorted(parsed, key=lambda state: state.state_id))
    if len({state.state_id for state in states}) != len(states):
        fail(f"cell {cell_id} repeats a state identity")
    if stateless == bool(states):
        fail(
            f"cell {cell_id} must declare either statelessness or owned state, "
            "not both/neither"
        )
    return states


def parse_cell_manifest(
    root: Path,
    *,
    package_name: str,
    package_manifest: str,
    source_owner: str,
    manifest_path: Path,
    selectors: tuple[str, ...],
) -> list[Cell]:
    payload = read_toml(manifest_path)
    if payload.get("schema") != CELL_SCHEMA or payload.get("package") != package_name:
        fail(f"{relative(root, manifest_path)} has wrong schema or package")
    raw_cells = payload.get("cell")
    if not isinstance(raw_cells, list) or not raw_cells:
        fail(f"{relative(root, manifest_path)} must contain [[cell]] records")
    manifest_hash = sha256(manifest_path.read_bytes())
    result: list[Cell] = []
    for raw in raw_cells:
        if not isinstance(raw, dict):
            fail(f"{relative(root, manifest_path)} contains a non-table cell")
        cell_id = nonempty("cell_id", raw.get("cell_id"))
        stateless = raw.get("stateless")
        if not isinstance(stateless, bool):
            fail(f"cell {cell_id} must declare boolean stateless")
        states = parse_states(cell_id, raw.get("owned_state"), stateless)

        contour = nonempty(
            f"cell {cell_id} execution_contour", raw.get("execution_contour")
        )
        replacement = nonempty(
            f"cell {cell_id} replacement_class", raw.get("replacement_class")
        )
        support = nonempty(
            f"cell {cell_id} implementation_support", raw.get("implementation_support")
        )
        execution = nonempty(
            f"cell {cell_id} evidence_execution_status",
            raw.get("evidence_execution_status"),
        )
        if contour not in EXECUTION_CONTOURS:
            fail(f"cell {cell_id} has unknown execution contour {contour}")
        if replacement not in REPLACEMENT_CLASSES:
            fail(f"cell {cell_id} has unknown replacement class {replacement}")
        if support not in SUPPORT_VALUES or execution not in EXECUTION_VALUES:
            fail(f"cell {cell_id} has unknown support/evidence status")
        if support == "CURRENT_VERIFIED" and execution != "EXECUTED":
            fail(f"cell {cell_id} claims CURRENT_VERIFIED without EXECUTED evidence")

        contract_owner = nonempty(
            f"cell {cell_id} contract_owner", raw.get("contract_owner")
        )
        contracts = tuple(
            sorted(
                (
                    ContractSource(
                        relative(root, path),
                        contract_owner,
                        sha256(path.read_bytes()),
                    )
                    for path in (
                        repo_path(root, item, f"cell {cell_id} contract")
                        for item in string_list(
                            f"cell {cell_id} contract_sources",
                            raw.get("contract_sources"),
                        )
                    )
                ),
                key=lambda contract: contract.path,
            )
        )

        pulse = raw.get("product_pulse")
        not_applicable = raw.get("not_applicable_reason")
        if bool(pulse) == bool(not_applicable):
            fail(
                f"cell {cell_id} must declare exactly one product_pulse "
                "or not_applicable_reason"
            )

        result.append(
            Cell(
                cell_id=cell_id,
                package=package_name,
                package_manifest=package_manifest,
                cell_manifest=relative(root, manifest_path),
                causal_responsibility=nonempty(
                    f"cell {cell_id} causal_responsibility",
                    raw.get("causal_responsibility"),
                ),
                source_maintenance_owner=source_owner,
                lifecycle_owner=nonempty(
                    f"cell {cell_id} lifecycle_owner", raw.get("lifecycle_owner")
                ),
                runtime_owner=nonempty(
                    f"cell {cell_id} runtime_owner", raw.get("runtime_owner")
                ),
                runtime_bundle=nonempty(
                    f"cell {cell_id} runtime_bundle", raw.get("runtime_bundle")
                ),
                execution_contour=contour,
                replacement_class=replacement,
                removal_boundary=nonempty(
                    f"cell {cell_id} removal_boundary", raw.get("removal_boundary")
                ),
                stateless=stateless,
                owned_state=states,
                allowed_effect_classes=string_list(
                    f"cell {cell_id} effects",
                    raw.get("allowed_effect_classes"),
                    allow_empty=True,
                ),
                contracts=contracts,
                proof_entrypoint=nonempty(
                    f"cell {cell_id} proof_entrypoint", raw.get("proof_entrypoint")
                ),
                proof_ceiling=nonempty(
                    f"cell {cell_id} proof_ceiling", raw.get("proof_ceiling")
                ),
                edge_profiles=string_list(
                    f"cell {cell_id} edge_profiles",
                    raw.get("edge_profiles"),
                    allow_empty=True,
                ),
                product_pulse=(
                    nonempty(f"cell {cell_id} product_pulse", pulse) if pulse else None
                ),
                not_applicable_reason=(
                    nonempty(
                        f"cell {cell_id} not_applicable_reason", not_applicable
                    )
                    if not_applicable
                    else None
                ),
                implementation_support=support,
                evidence_execution_status=execution,
                providers=string_list(
                    f"cell {cell_id} providers",
                    raw.get("providers"),
                    allow_empty=True,
                ),
                consumers=string_list(
                    f"cell {cell_id} consumers",
                    raw.get("consumers"),
                    allow_empty=True,
                ),
                invalidation=string_list(
                    f"cell {cell_id} invalidation", raw.get("invalidation")
                ),
                manifest_sha256=manifest_hash,
                scope_selectors=selectors,
            )
        )
    return result
