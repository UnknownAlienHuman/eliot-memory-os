"""Build the deterministic repository code-navigation registry."""

from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
from typing import Any

from .blocks import load_blocks, load_docs_router
from .cargo import (
    discover_manifests,
    expand_workspace_paths,
    inferred_targets,
    iter_dependency_specs,
    package_metadata,
    resolve_dependency_spec,
)
from .common import (
    DEFAULT_BLOCKS,
    DEFAULT_HANDLE_INDEX,
    NavigationError,
    SCHEMA,
    normalize_repo_path,
    path_matches,
    read_json,
    read_toml,
    relative_to_root,
    sha256_file,
    walk_files,
)
from .rust import module_locator


def build_registry(root: Path, blocks_relative: str = DEFAULT_BLOCKS) -> dict[str, Any]:
    root = root.resolve()
    root_manifest = root / "Cargo.toml"
    if not root_manifest.is_file():
        raise NavigationError("repository root has no Cargo.toml")
    root_payload = read_toml(root_manifest)
    workspace = root_payload.get("workspace")
    if not isinstance(workspace, dict):
        raise NavigationError("root Cargo.toml has no [workspace] table")

    raw_members = workspace.get("members")
    if not isinstance(raw_members, list) or not raw_members:
        raise NavigationError("workspace.members must be a non-empty array")
    members = expand_workspace_paths(root, [str(item) for item in raw_members], "workspace.members")

    raw_excludes = workspace.get("exclude", [])
    if not isinstance(raw_excludes, list):
        raise NavigationError("workspace.exclude must be an array")
    excludes = set(
        expand_workspace_paths(root, [str(item) for item in raw_excludes], "workspace.exclude")
        if raw_excludes
        else []
    )
    members = [member for member in members if member not in excludes]

    raw_defaults = workspace.get("default-members", [])
    if not isinstance(raw_defaults, list):
        raise NavigationError("workspace.default-members must be an array")
    defaults = set(
        expand_workspace_paths(
            root,
            [str(item) for item in raw_defaults],
            "workspace.default-members",
        )
        if raw_defaults
        else members
    )
    missing_defaults = defaults.difference(members)
    if missing_defaults:
        raise NavigationError(
            "default members are not workspace members: "
            + ", ".join(sorted(missing_defaults))
        )

    manifest_paths = discover_manifests(root)
    package_by_root: dict[str, dict[str, Any]] = {}
    workspace_dependencies = workspace.get("dependencies")
    if not isinstance(workspace_dependencies, dict):
        workspace_dependencies = {}

    for manifest_relative in manifest_paths:
        manifest_path = root / manifest_relative
        payload = read_toml(manifest_path)
        package = payload.get("package")
        if not isinstance(package, dict):
            continue
        name = str(package.get("name", "")).strip()
        if not name:
            raise NavigationError(f"package has no name: {manifest_relative}")
        package_root = relative_to_root(root, manifest_path.parent)
        metadata = package_metadata(payload)
        package_by_root[package_root] = {
            "name": name,
            "manifest_path": manifest_relative,
            "root_path": package_root,
            "workspace_member": package_root in members,
            "default_member": package_root in defaults,
            "edition": str(package.get("edition", "")),
            "rust_version": str(package.get("rust-version", "")),
            "layer": str(metadata.get("layer", "")),
            "purpose": str(metadata.get("purpose", "")),
            "source_maintenance_owner": str(metadata.get("source_maintenance_owner", "")),
            "functional_cell_refs": list(metadata.get("functional_cell_refs", []))
            if isinstance(metadata.get("functional_cell_refs", []), list)
            else [],
            "contract_refs": list(metadata.get("contract_refs", []))
            if isinstance(metadata.get("contract_refs", []), list)
            else [],
            "targets": inferred_targets(manifest_path.parent, payload),
            "_payload": payload,
            "dependencies": [],
            "reverse_dependencies": [],
            "rust_files": [],
        }

    for member in members:
        if member not in package_by_root:
            raise NavigationError(
                f"workspace member has no [package] manifest: {member}/Cargo.toml"
            )

    roots = sorted(package_by_root, key=lambda value: (len(PurePosixPath(value).parts), value))
    names: dict[str, list[str]] = {}
    for package_root, package in package_by_root.items():
        names.setdefault(package["name"], []).append(package_root)

    for package_root, package in package_by_root.items():
        payload = package.pop("_payload")
        for kind, alias, spec in iter_dependency_specs(payload):
            package_name, raw_path, path_base = resolve_dependency_spec(
                alias,
                spec,
                workspace_dependencies,
            )
            local_root: str | None = None
            if raw_path is not None:
                base = root if path_base == "workspace" else root / package_root
                resolved = (base / raw_path).resolve()
                try:
                    local_root = relative_to_root(root, resolved)
                except NavigationError:
                    local_root = None
            elif len(names.get(package_name, [])) == 1:
                candidate = names[package_name][0]
                if package_by_root[candidate]["workspace_member"]:
                    local_root = candidate
            package["dependencies"].append(
                {
                    "alias": alias,
                    "package": package_name,
                    "kind": kind,
                    "path": raw_path,
                    "local_package_root": local_root
                    if local_root in package_by_root
                    else None,
                }
            )
        package["dependencies"].sort(
            key=lambda item: (item["kind"], item["package"], item["alias"])
        )

    for package_root, package in package_by_root.items():
        for dependency in package["dependencies"]:
            local_root = dependency["local_package_root"]
            if local_root:
                package_by_root[local_root]["reverse_dependencies"].append(
                    {
                        "name": package["name"],
                        "root_path": package_root,
                        "kind": dependency["kind"],
                    }
                )

    all_files = walk_files(root)
    rust_files = [path for path in all_files if path.endswith(".rs")]
    package_roots_desc = sorted(
        package_by_root,
        key=lambda value: (-len(PurePosixPath(value).parts), value),
    )
    for rust_file in rust_files:
        owner = next(
            (
                package_root
                for package_root in package_roots_desc
                if rust_file == package_root
                or rust_file.startswith(package_root.rstrip("/") + "/")
            ),
            None,
        )
        if owner is None:
            continue
        package_relative = PurePosixPath(rust_file).relative_to(owner).as_posix()
        record = {"path": rust_file, **module_locator(package_by_root[owner]["name"], package_relative)}
        package_by_root[owner]["rust_files"].append(record)

    blocks = load_blocks(root, blocks_relative)
    handle_index = read_json(root / DEFAULT_HANDLE_INDEX)
    handles = handle_index.get("handles")
    if not isinstance(handles, dict) or not handles:
        raise NavigationError("documentation handle index is empty or invalid")

    for block in blocks:
        pattern_matches = {
            pattern: sorted(
                path for path in all_files if path_matches(path, pattern)
            )
            for pattern in block["path_globs"]
        }
        empty_patterns = [
            pattern for pattern, matches in pattern_matches.items() if not matches
        ]
        if empty_patterns:
            raise NavigationError(
                f"logical block {block['id']} has path selectors that match no files: "
                + ", ".join(empty_patterns)
            )
        block["path_match_counts"] = {
            pattern: len(matches) for pattern, matches in pattern_matches.items()
        }
        block["matched_files"] = sorted(
            {
                path
                for matches in pattern_matches.values()
                for path in matches
            }
        )
        unknown_handles = [
            handle
            for handle in block["documentation_handles"]
            if handle not in handles
        ]
        if unknown_handles:
            raise NavigationError(
                f"logical block {block['id']} has unknown documentation handles: "
                + ", ".join(unknown_handles)
            )

    docs_router = load_docs_router(root)
    docs_config = docs_router.load_config(root)
    for block in blocks:
        sample_paths = block["matched_files"][:1]
        matched = docs_router.matched_routes(
            docs_config,
            sample_paths,
            block["route_topic"],
        )
        block["documentation_route_ids"] = [route.route_id for route in matched]
        if not block["documentation_route_ids"]:
            raise NavigationError(
                f"logical block {block['id']} resolves no documentation route"
            )

    for package in package_by_root.values():
        package["reverse_dependencies"].sort(
            key=lambda item: (item["name"], item["root_path"], item["kind"])
        )
        package["rust_files"].sort(key=lambda item: item["path"])
        package["logical_blocks"] = [
            block["id"]
            for block in blocks
            if any(
                path_matches(package["root_path"], pattern)
                or path_matches(package["manifest_path"], pattern)
                for pattern in block["path_globs"]
            )
        ]
        if package["workspace_member"] and not package["logical_blocks"]:
            raise NavigationError(
                f"workspace package is outside every logical block: {package['root_path']}"
            )

    packages = sorted(
        package_by_root.values(),
        key=lambda item: (
            not item["workspace_member"],
            not item["default_member"],
            item["root_path"],
        ),
    )
    return {
        "schema_version": SCHEMA,
        "workspace_manifest": {
            "path": "Cargo.toml",
            "sha256": sha256_file(root_manifest),
            "members": members,
            "default_members": sorted(defaults),
        },
        "logical_block_config": {
            "path": blocks_relative,
            "sha256": sha256_file(root / blocks_relative),
        },
        "packages": packages,
        "logical_blocks": blocks,
        "counts": {
            "workspace_members": sum(1 for package in packages if package["workspace_member"]),
            "default_members": sum(1 for package in packages if package["default_member"]),
            "nonmember_packages": sum(1 for package in packages if not package["workspace_member"]),
            "rust_files": sum(len(package["rust_files"]) for package in packages),
            "logical_blocks": len(blocks),
        },
    }


def matching_package(registry: dict[str, Any], path: str) -> dict[str, Any] | None:
    path = normalize_repo_path(path)
    candidates = [
        package
        for package in registry["packages"]
        if path == package["root_path"]
        or path.startswith(package["root_path"].rstrip("/") + "/")
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: len(PurePosixPath(item["root_path"]).parts))
