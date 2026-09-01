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


def _manifest_path(
    package_root: Path,
    raw_path: Any,
    field: str,
) -> str:
    """Resolve a manifest path and return its canonical package-relative form."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise NavigationError(f"{field} must be a non-empty string")
    normalized = raw_path.strip().replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        raise NavigationError(f"{field} must be repository-relative: {raw_path!r}")
    candidate = (package_root / PurePosixPath(normalized)).resolve()
    try:
        relative = candidate.relative_to(package_root.resolve())
    except ValueError as exc:
        raise NavigationError(f"{field} escapes package root: {raw_path!r}") from exc
    return normalize_repo_path(relative.as_posix())


def resolve_dependency_path(
    root: Path,
    package_root: str,
    raw_path: Any,
    path_base: str,
    field: str,
) -> str:
    """Resolve a dependency path into a canonical repository-relative path."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise NavigationError(f"{field} must be a non-empty string")
    normalized = raw_path.strip().replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        raise NavigationError(f"{field} must be repository-relative: {raw_path!r}")
    base = root if path_base == "workspace" else root / PurePosixPath(package_root)
    resolved = (base / PurePosixPath(normalized)).resolve()
    return relative_to_root(root, resolved)


def expand_workspace_paths(
    root: Path,
    patterns: Sequence[str],
    field: str,
) -> list[str]:
    expanded: set[str] = set()
    for raw in patterns:
        if not isinstance(raw, str) or not raw.strip():
            raise NavigationError(f"{field} contains an invalid path selector")
        pattern = normalize_repo_path(raw)
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


def inferred_targets(
    package_root: Path,
    payload: dict[str, Any],
    strict: bool = True,
) -> list[dict[str, str]]:
    package = payload.get("package")
    if not isinstance(package, dict):
        return []
    package_name = str(package.get("name", "")).strip()
    if not package_name:
        raise NavigationError("Cargo package has no name")

    def auto_enabled(key: str) -> bool:
        value = package.get(key, True)
        if not isinstance(value, bool):
            raise NavigationError(f"Cargo package.{key} must be boolean")
        return value

    targets: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, name: Any, raw_path: Any, required: bool = False) -> None:
        relative = _manifest_path(package_root, raw_path, f"Cargo {kind} target path")
        path = package_root / PurePosixPath(relative)
        if not path.is_file():
            if required and strict:
                raise NavigationError(f"Cargo {kind} target does not exist: {relative}")
            return
        key = (kind, relative)
        if key in seen:
            return
        seen.add(key)
        targets.append(
            {
                "kind": kind,
                "name": str(name).strip() if name is not None else Path(relative).stem,
                "path": relative,
            }
        )

    raw_lib = payload.get("lib")
    if raw_lib is not None and not isinstance(raw_lib, dict):
        raise NavigationError("Cargo [lib] must be a table")
    if isinstance(raw_lib, dict):
        add(
            "lib",
            raw_lib.get("name") or package_name,
            raw_lib["path"] if "path" in raw_lib else "src/lib.rs",
            True,
        )
    elif auto_enabled("autolib"):
        add("lib", package_name, "src/lib.rs")

    raw_bins = payload.get("bin", [])
    if isinstance(raw_bins, dict):
        raw_bins = [raw_bins]
    if not isinstance(raw_bins, list):
        raise NavigationError("Cargo [[bin]] must be a table or array of tables")
    for raw in raw_bins:
        if not isinstance(raw, dict):
            raise NavigationError("Cargo [[bin]] declaration must be a table")
        raw_path = raw.get("path")
        declared_name = raw.get("name")
        if declared_name is not None and not isinstance(declared_name, str):
            raise NavigationError("Cargo [[bin]].name must be a string")
        if raw_path is None:
            name = declared_name or package_name
            raw_path = "src/main.rs" if name == package_name else f"src/bin/{name}.rs"
        else:
            name = declared_name or PurePosixPath(str(raw_path).replace("\\", "/")).stem
        add("bin", name, raw_path, True)

    if auto_enabled("autobins"):
        add("bin", package_name, "src/main.rs")
        bin_dir = package_root / "src" / "bin"
        if bin_dir.is_dir():
            for file_path in sorted(bin_dir.glob("*.rs")):
                add("bin", file_path.stem, file_path.relative_to(package_root).as_posix())
            for main_path in sorted(bin_dir.glob("*/main.rs")):
                add("bin", main_path.parent.name, main_path.relative_to(package_root).as_posix())

    build_path = package.get("build")
    if isinstance(build_path, str):
        add("build", "build-script", build_path, True)
    elif build_path is not False:
        add("build", "build-script", "build.rs")

    for kind, directory, auto_key in (
        ("example", "examples", "autoexamples"),
        ("test", "tests", "autotests"),
        ("bench", "benches", "autobenches"),
    ):
        declarations = payload.get(kind, [])
        if isinstance(declarations, dict):
            declarations = [declarations]
        if not isinstance(declarations, list):
            raise NavigationError(f"Cargo [[{kind}]] must be a table or array of tables")
        for raw in declarations:
            if not isinstance(raw, dict):
                raise NavigationError(f"Cargo [[{kind}]] declaration must be a table")
            name = raw.get("name")
            raw_path = raw.get("path")
            if raw_path is None:
                if not isinstance(name, str) or not name.strip():
                    raise NavigationError(f"Cargo [[{kind}]] requires a name or path")
                raw_path = f"{directory}/{name}.rs"
            add(kind, name, raw_path, True)
        if not auto_enabled(auto_key):
            continue
        directory_path = package_root / directory
        if directory_path.is_dir():
            for file_path in sorted(directory_path.glob("*.rs")):
                add(kind, file_path.stem, file_path.relative_to(package_root).as_posix())

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
    if not isinstance(spec, (str, dict)):
        raise NavigationError(f"dependency {alias!r} has an invalid specification")
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
        if raw_path is not None and not isinstance(raw_path, str):
            raise NavigationError(f"dependency {alias!r}.path must be a string")
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
