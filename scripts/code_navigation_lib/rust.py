"""Filesystem-derived Rust module locators."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from .common import NavigationError, normalize_repo_path


def module_locator(
    package_name: str,
    package_relative: str,
    targets: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    crate = package_name.replace("-", "_")
    package_relative = normalize_repo_path(package_relative)
    path = PurePosixPath(package_relative)
    parts = list(path.parts)
    role = "source"
    module_parts: list[str] = []

    if package_relative == "build.rs":
        role = "build-script"
        module_parts = ["build_script"]
    elif parts[:1] == ["src"]:
        rest = parts[1:]
        if rest == ["lib.rs"]:
            role = "crate-root"
        elif rest == ["main.rs"]:
            role = "binary-root"
            module_parts = ["bin"]
        elif len(rest) >= 2 and rest[0] == "bin":
            role = "binary"
            if rest[-1] == "main.rs":
                module_parts = ["bin", *rest[1:-1]]
            else:
                module_parts = ["bin", *rest[:-1], Path(rest[-1]).stem]
        else:
            if rest and rest[-1] == "mod.rs":
                module_parts = rest[:-1]
            elif rest:
                module_parts = [*rest[:-1], Path(rest[-1]).stem]
    elif parts[:1] == ["tests"]:
        role = "integration-test"
        module_parts = ["integration_test", *parts[1:-1], Path(parts[-1]).stem]
    elif parts[:1] == ["examples"]:
        role = "example"
        module_parts = ["example", *parts[1:-1], Path(parts[-1]).stem]
    elif parts[:1] == ["benches"]:
        role = "bench"
        module_parts = ["bench", *parts[1:-1], Path(parts[-1]).stem]
    else:
        role = "rust-file"
        module_parts = ["file", *parts[:-1], Path(parts[-1]).stem]

    result: dict[str, Any] = {
        "module_locator": "::".join([crate, *[part for part in module_parts if part]]),
        "role": role,
        "locator_assurance": "filesystem-derived; verify declarations/reachability in Code Graph and source",
    }
    if targets is None:
        return result
    matches = [
        target
        for target in targets
        if normalize_repo_path(str(target["path"])) == package_relative
    ]
    identities = {(str(target["kind"]), str(target["name"])) for target in matches}
    if len(identities) > 1:
        raise NavigationError(f"source path has ambiguous Cargo targets: {package_relative}")
    if not identities:
        return result
    kind, name = next(iter(identities))
    target_name = name.replace("-", "_")
    result["target_kind"] = kind
    result["target_name"] = name
    if kind == "lib":
        result["role"] = "crate-root"
        result["module_locator"] = crate
    elif kind == "bin":
        result["role"] = "binary"
        result["module_locator"] = f"{crate}::bin::{target_name}"
    elif kind == "example":
        result["role"] = "example"
        result["module_locator"] = f"{crate}::example::{target_name}"
    elif kind == "test":
        result["role"] = "integration-test"
        result["module_locator"] = f"{crate}::integration_test::{target_name}"
    elif kind == "bench":
        result["role"] = "bench"
        result["module_locator"] = f"{crate}::bench::{target_name}"
    elif kind == "build":
        result["role"] = "build-script"
        result["module_locator"] = f"{crate}::build_script"
    return result
