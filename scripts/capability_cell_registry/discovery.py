"""Discover explicitly admitted packages and parse their cell manifests."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from .manifest import cargo_manifests, matching_scope, parse_cell_manifest
from .model import Cell, Finding, RegistryError, ScopeSelection, nonempty, read_toml, relative, repo_path


def discover_cells(
    root: Path,
    scope: ScopeSelection,
) -> tuple[list[Cell], list[Finding]]:
    findings: list[Finding] = []
    cells: list[Cell] = []
    package_names: dict[str, str] = {}

    for manifest in sorted(cargo_manifests(root)):
        payload = read_toml(manifest)
        package = payload.get("package")
        if not isinstance(package, dict):
            continue
        name = nonempty(f"{relative(root, manifest)} package.name", package.get("name"))
        package_manifest = relative(root, manifest)
        previous = package_names.get(name)
        if previous:
            findings.append(
                Finding(
                    "duplicate_package_name",
                    package_manifest,
                    f"also declared by {previous}",
                    name,
                )
            )
            continue
        package_names[name] = package_manifest
        package_root = relative(root, manifest.parent)
        matched = matching_scope(package_root, scope)
        if not matched:
            continue

        metadata = package.get("metadata")
        eliot = metadata.get("eliot") if isinstance(metadata, dict) else None
        if not isinstance(eliot, dict):
            findings.append(
                Finding(
                    "missing_eliot_metadata",
                    package_manifest,
                    "in-scope package lacks [package.metadata.eliot]",
                    name,
                )
            )
            continue
        source_owner = eliot.get("source_maintenance_owner")
        cell_manifest = eliot.get("cell_manifest")
        if not isinstance(source_owner, str) or not source_owner.strip():
            findings.append(
                Finding(
                    "missing_source_maintenance_owner",
                    package_manifest,
                    "source maintenance owner is not declared",
                    name,
                )
            )
            continue
        if not isinstance(cell_manifest, str) or not cell_manifest.strip():
            findings.append(
                Finding(
                    "missing_cell_manifest",
                    package_manifest,
                    "package-local cell manifest is not declared",
                    name,
                )
            )
            continue
        try:
            path = repo_path(
                root,
                str(
                    PurePosixPath(package_root)
                    / PurePosixPath(cell_manifest.replace("\\", "/"))
                ),
                f"{name} cell_manifest",
            )
            cells.extend(
                parse_cell_manifest(
                    root,
                    package_name=name,
                    package_manifest=package_manifest,
                    source_owner=source_owner.strip(),
                    manifest_path=path,
                    selectors=matched,
                )
            )
        except RegistryError as error:
            findings.append(
                Finding("invalid_cell_manifest", package_manifest, str(error), name)
            )

    return cells, findings
