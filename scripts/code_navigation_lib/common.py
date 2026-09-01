"""Shared path, serialization, and filesystem primitives."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SCHEMA = "eliot-code-navigation-v1"
DEFAULT_BLOCKS = "docs/code-navigation/logical-blocks.toml"
DEFAULT_HANDLE_INDEX = "docs/architecture/handle-index.json"
DEFAULT_DOC_ROUTER = "scripts/docs_router.py"
SKIP_DIRS = {
    ".git",
    ".idea",
    ".vscode",
    ".eliot",
    ".eliot-dev",
    ".eliot-governor",
    ".codebase-memory",
    "__pycache__",
    "target",
    "dist",
    "node_modules",
    "obj",
}
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


class NavigationError(RuntimeError):
    pass


def read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise NavigationError(f"cannot read TOML {path}: {exc}") from exc


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NavigationError(f"cannot read JSON {path}: {exc}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_repo_path(value: str) -> str:
    value = value.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    value = re.sub(r"/+", "/", value)
    if value in ("", "."):
        return "."
    if re.match(r"^[A-Za-z]:", value):
        raise NavigationError(f"path must be repository-relative: {value!r}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts:
        raise NavigationError(
            f"path must be repository-relative and non-traversing: {value!r}"
        )
    return pure.as_posix()


def relative_to_root(root: Path, path: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise NavigationError(f"path escapes repository root: {path}") from exc
    value = relative.as_posix()
    return value if value else "."


def path_matches(path: str, pattern: str) -> bool:
    path = normalize_repo_path(path)
    pattern = normalize_repo_path(pattern)
    if fnmatch.fnmatchcase(path, pattern):
        return True
    if pattern.endswith("/**") and path == pattern[:-3].rstrip("/"):
        return True
    if pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:]):
        return True
    return False


def walk_files(root: Path) -> list[str]:
    files: list[str] = []
    for current, dirs, names in os.walk(root):
        dirs[:] = sorted(
            directory
            for directory in dirs
            if directory not in SKIP_DIRS
        )
        current_path = Path(current)
        for name in sorted(names):
            files.append(relative_to_root(root, current_path / name))
    return files
