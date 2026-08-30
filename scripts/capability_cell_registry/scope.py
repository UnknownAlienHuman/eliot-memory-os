"""Normative-pair and explicit registry-scope loading."""

from __future__ import annotations

import json
from pathlib import Path

from .model import (
    PAIR_ALGORITHM,
    PAIR_DOMAIN,
    PAIR_SCHEMA,
    SCOPE_SCHEMA,
    ScopeSelection,
    document_digest,
    fail,
    nonempty,
    read_toml,
    relative,
    repo_directory,
    repo_path,
    sha256,
    string_list,
)


def normative_pair(root: Path) -> dict[str, str]:
    receipt = read_toml(root / "docs/normative-pair.toml")
    if receipt.get("schema_version") != PAIR_SCHEMA:
        fail("unsupported normative-pair schema")
    if (
        receipt.get("status") != "accepted"
        or receipt.get("repository_authority_branch") != "main"
    ):
        fail("normative pair is not accepted on main")
    if receipt.get("pair_key_algorithm") != PAIR_ALGORITHM:
        fail("unsupported normative-pair algorithm")

    architecture = document_digest(
        "architecture_sha256", receipt.get("architecture_sha256")
    )
    implementation = document_digest(
        "implementation_sha256", receipt.get("implementation_sha256")
    )
    for label, path_key, expected in (
        ("Architecture", "architecture_path", architecture),
        ("Implementation", "implementation_path", implementation),
    ):
        path = repo_path(root, receipt.get(path_key), path_key)
        actual = sha256(path.read_bytes())
        if actual != expected:
            fail(f"{label} digest mismatch: receipt={expected} actual={actual}")

    material = (
        PAIR_DOMAIN
        + architecture.encode()
        + b"\x00"
        + implementation.encode()
        + b"\x00"
    )
    pair_key = "sha256:" + sha256(material)
    if receipt.get("pair_key") != pair_key:
        fail(
            "normative pair key mismatch: "
            f"receipt={receipt.get('pair_key')} actual={pair_key}"
        )
    return {
        "pair_key": pair_key,
        "architecture_sha256": architecture,
        "implementation_sha256": implementation,
    }


def load_inventory(
    root: Path,
    path_value: object,
) -> tuple[str, str, list[tuple[str, tuple[str, ...]]]]:
    path = repo_path(root, path_value, "scope inventory_path")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse scope inventory: {error}")
    units = payload.get("units")
    if not isinstance(units, list):
        fail("scope inventory has no units list")
    result: list[tuple[str, tuple[str, ...]]] = []
    for index, unit in enumerate(units):
        if not isinstance(unit, dict):
            fail(f"inventory unit {index} is not an object")
        result.append(
            (
                nonempty(f"inventory unit {index} id", unit.get("id")),
                string_list(f"inventory unit {index} paths", unit.get("paths")),
            )
        )
    if len({unit_id for unit_id, _ in result}) != len(result):
        fail("scope inventory contains duplicate unit IDs")
    return relative(root, path), sha256(path.read_bytes()), result


def load_scope(root: Path) -> ScopeSelection:
    contract_path = root / "config/capability-cell-registry-scope.toml"
    payload = read_toml(contract_path)
    if payload.get("schema") != SCOPE_SCHEMA:
        fail("unsupported capability-cell registry scope schema")

    inventory_path, inventory_hash, units = load_inventory(
        root, payload.get("inventory_path")
    )
    unit_map = {unit_id: paths for unit_id, paths in units}
    selected_units = string_list(
        "scope inventory_unit_ids",
        payload.get("inventory_unit_ids"),
        allow_empty=True,
    )
    unknown_units = sorted(set(selected_units).difference(unit_map))
    if unknown_units:
        fail(f"scope references unknown inventory units: {', '.join(unknown_units)}")

    explicit_roots_raw = string_list("scope package_roots", payload.get("package_roots"))
    explicit_roots: list[str] = []
    for index, value in enumerate(explicit_roots_raw):
        package_root = repo_directory(root, value, f"scope package_roots[{index}]")
        explicit_roots.append(relative(root, package_root))

    selected_paths = set(explicit_roots)
    for unit_id in selected_units:
        selected_paths.update(path.rstrip("/") for path in unit_map[unit_id])

    unselected_units = tuple(sorted(set(unit_map).difference(selected_units)))
    coverage_status = (
        "FULL_INVENTORY_SCOPE" if not unselected_units else "DECLARED_PARTIAL_SCOPE"
    )
    return ScopeSelection(
        contract_path=relative(root, contract_path),
        contract_sha256=sha256(contract_path.read_bytes()),
        inventory_path=inventory_path,
        inventory_sha256=inventory_hash,
        explicit_package_roots=tuple(sorted(explicit_roots)),
        selected_inventory_units=selected_units,
        unselected_inventory_units=unselected_units,
        selected_paths=tuple(sorted(selected_paths)),
        coverage_status=coverage_status,
    )
