#!/usr/bin/env python3
"""Hardened front door for the deterministic documentation router.

The implementation remains in ``docs_router_core``. This front door owns
portable repository-path normalization, deletion-aware changed-path discovery,
and their executable negative fixtures.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Sequence

import docs_router_core as _core
from docs_router_core import *  # noqa: F403

DRIVE_QUALIFIED_PATH_REJECTED = "eliot-doc-router-drive-qualified-path-v1"
_core_self_test = _core.self_test


def normalize_repo_path(value: str) -> str:
    value = value.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    value = re.sub(r"/+", "/", value)
    if value in ("", "."):
        return "."
    if re.match(r"^[A-Za-z]:", value):
        raise RouteError(  # noqa: F405
            f"path must be repository-relative and non-traversing: {value!r}"
        )
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts:
        raise RouteError(  # noqa: F405
            f"path must be repository-relative and non-traversing: {value!r}"
        )
    return pure.as_posix()


def git_changed_paths(root: Path, changed_from: str) -> list[str]:
    if not changed_from.strip():
        raise RouteError("--changed-from cannot be empty")  # noqa: F405
    command = [
        "git",
        "-C",
        str(root),
        "diff",
        "--name-only",
        "--diff-filter=ACMRTUXBD",
        f"{changed_from}...HEAD",
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RouteError(  # noqa: F405
            f"git diff failed for {changed_from}: {completed.stderr.strip()}"
        )
    paths = [
        normalize_repo_path(line)
        for line in completed.stdout.splitlines()
        if line.strip()
    ]
    if not paths:
        raise RouteError(  # noqa: F405
            f"no changed paths found from {changed_from} to HEAD"
        )
    return sorted(set(paths))


def _git(root: Path, *arguments: str) -> None:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RouteError(  # noqa: F405
            f"router self-test git failure: {' '.join(arguments)}: "
            f"{completed.stderr.strip()}"
        )


def self_test() -> None:
    _core_self_test()

    for candidate in ("C:/repo/file.md", r"C:\repo\file.md"):
        try:
            normalize_repo_path(candidate)
        except RouteError:  # noqa: F405
            pass
        else:
            raise RouteError(  # noqa: F405
                f"drive-qualified path self-test failed: {candidate}"
            )

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _git(root, "init", "-b", "main")
        _git(root, "config", "user.name", "ELIOT Router Test")
        _git(root, "config", "user.email", "router@example.invalid")
        tracked = root / "deleted.md"
        tracked.write_text("tracked\n", encoding="utf-8")
        _git(root, "add", "deleted.md")
        _git(root, "commit", "-m", "seed")
        base = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        tracked.unlink()
        _git(root, "add", "-A")
        _git(root, "commit", "-m", "delete")
        if git_changed_paths(root, base) != ["deleted.md"]:
            raise RouteError(  # noqa: F405
                "--changed-from deletion self-test failed"
            )

    print("DOC_ROUTER_HARDENING_SELF_TEST: PASS cases=3")


_core.normalize_repo_path = normalize_repo_path
_core.git_changed_paths = git_changed_paths
_core.self_test = self_test
main = _core.main


if __name__ == "__main__":
    raise SystemExit(main())
