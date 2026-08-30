"""Cargo workspace, package, target, dependency, and AGENTS discovery."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

from .common import (
    DEPENDENCY_TABLES,
    NavigationError,
    normalize_repo_path,
    read_toml,
    relative_to_root,
    walk_files,
)


def expand_workspace_paths(
    root: Path,
    patterns: Sequence[str],
    field: str,
) -> list[str]:
    expanded: set[str] = set()
    for raw in patterns:
        pattern = normalize_repo_path(str(raw))
        has_magic = any(character in pattern for character in "*?[")
        candidates = root.glob(pattern) if has_magic else [root / pattern]
        matched = False
        for candidate in candidates:
            if not candidate.is_dir():
                continue
            manifest = candidate / "Cargo.toml"
            if not manifest.is_file():
                continue
            expanded.add(relative_to_root(root, candidate))
            matched = True
        if not matched:
            raise NavigationError(
                f"{field} entry resolves to no package directory: {raw!r}"
            )
    return sorted(expanded)


def discover_manifests(root: Path) -> list[str]:
    manifests: list[str] = []
    for relative in walk_files(root):
        if PurePosixPath(relative).name == "Cargo.toml":
            manifests.append(relative)
    return sorted(manifests)


def package_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    package = payload.get("package")
    if not isinstance(package, dict):
        return {}
    metadata = package.get("metadata")
    if not isinstance(metadata, dict):
        return {}
    eliot = metadata.get("eliot")
    return eliot if isinstance(eliot, dict) else {}


def inferred_targets(package_root: Path, payload: dict[str, Any]) -> list[dict[str, str]]:
    package = payload.get("package")
    if not isinstance(package, dict):
        return []
    package_name = str(package.get("name", "")).strip()
    targets: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, name: str, path: Path) -> None:
        if not path.is_file():
            return
        key = (kind, str(path.resolve()))
        if key in seen:
            return
        seen.add(key)
        targets.append(
            {
                "kind": kind,
                "name": name,
                "path": path.relative_to(package_root).as_posix(),
            }
        )

    raw_lib = payload.get("lib")
    if isinstance(raw_lib, dict) and raw_lib.get("path"):
        add("lib", str(raw_lib.get("name") or package_name), package_root / str(raw_lib["path"]))
    else:
        add("lib", package_name, package_root / "src/lib.rs")

    raw_bins = payload.get("bin")
    if isinstance(raw_bins, dict):
        raw_bins = [raw_bins]
    if isinstance(raw_bins, list):
        for raw in raw_bins:
            if not isinstance(raw, dict):
                continue
            path = raw.get("path")
            if path:
                add("bin", str(raw.get("name") or package_name), package_root / str(path))

    add("bin", package_name, package_root / "src/main.rs")
    bin_dir = package_root / "src/bin"
    if bin_dir.is_dir():
        for file_path in sorted(bin_dir.glob("*.rs")):
            add("bin", file_path.stem, file_path)
        for main_path in sorted(bin_dir.glob("*/main.rs")):
            add("bin", main_path.parent.name, main_path)

    build_path = package.get("build")
    if isinstance(build_path, str):
        add("build", "build-script", package_root / build_path)
    elif build_path is not False:
        add("build", "build-script", package_root / "build.rs")

    for kind, directory in (
        ("example", package_root / "examples"),
        ("test", package_root / "tests"),
        ("bench", package_root / "benches"),
    ):
        if directory.is_dir():
            for file_path in sorted(directory.glob("*.rs")):
                add(kind, file_path.stem, file_path)

    return sorted(targets, key=lambda item: (item["kind"], item["name"], item["path"]))


def iter_dependency_specs(payload: dict[str, Any]) -> Iterable[tuple[str, str, Any]]:
    for table_name in DEPENDENCY_TABLES:
        table = payload.get(table_name)
        if isinstance(table, dict):
            for alias, spec in table.items():
                yield table_name, str(alias), spec

    target = payload.get("target")
    if isinstance(target, dict):
        for condition, tables in target.items():
            if not isinstance(tables, dict):
                continue
            for table_name in DEPENDENCY_TABLES:
                table = tables.get(table_name)
                if isinstance(table, dict):
                    for alias, spec in table.items():
                        yield f"target:{condition}:{table_name}", str(alias), spec


def resolve_dependency_spec(
    alias: str,
    spec: Any,
    workspace_dependencies: dict[str, Any],
) -> tuple[str, str | None, str]:
    effective = spec
    path_base = "package"
    if isinstance(spec, dict) and spec.get("workspace") is True:
        effective = workspace_dependencies.get(alias, spec)
        path_base = "workspace"

    package_name = alias
    dependency_path: str | None = None
    if isinstance(effective, dict):
        package_name = str(effective.get("package") or alias)
        raw_path = effective.get("path")
        if isinstance(raw_path, str) and raw_path.strip():
            dependency_path = raw_path
    return package_name, dependency_path, path_base


def nearest_agents(root: Path, relative: str) -> list[str]:
    relative = normalize_repo_path(relative)
    pure = PurePosixPath(relative)
    target = root / pure
    parts = pure.parts if target.is_dir() else pure.parts[:-1]
    found: list[str] = []
    if (root / "AGENTS.md").is_file():
        found.append("AGENTS.md")
    for end in range(1, len(parts) + 1):
        candidate = PurePosixPath(*parts[:end], "AGENTS.md").as_posix()
        if candidate != "AGENTS.md" and (root / candidate).is_file():
            found.append(candidate)
    return found
