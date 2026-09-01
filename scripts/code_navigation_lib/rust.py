"""Filesystem-derived Rust module locators."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from .common import NavigationError


def module_locator(package_name: str, package_relative: str) -> dict[str, str]:
    crate = package_name.replace("-", "_")
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

    module = "::".join([crate, *[part for part in module_parts if part]])
    return {
        "module_locator": module,
        "role": role,
        "locator_assurance": "filesystem-derived; verify declarations/reachability in Code Graph and source",
    }
