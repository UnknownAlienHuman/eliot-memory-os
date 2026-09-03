#!/usr/bin/env python3
"""Hardened front door for the deterministic documentation router.

The implementation remains in ``docs_router_core``. This front door owns
portable repository-path normalization, deletion-aware changed-path discovery,
real-path route-payload coverage, and their executable negative fixtures.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Sequence

import docs_router_core as _core
from docs_router_core import *  # noqa: F403

DRIVE_QUALIFIED_PATH_REJECTED = "eliot-doc-router-drive-qualified-path-v1"
_core_self_test = _core.self_test
_core_load_config = _core.load_config


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


def _with_real_path_examples(root: Path, config: Config) -> Config:  # noqa: F405
    """Give every live path-backed route a deterministic payload probe."""

    tracked = _core.tracked_files(root)
    examples = list(config.examples)
    covered = {
        str(route_id)
        for example in examples
        for route_id in example.get("expect_routes", ())
    }
    for route in config.routes:
        if route.route_id in covered:
            continue
        candidate = next(
            (
                path
                for path in tracked
                if any(_core.path_matches(path, pattern) for pattern in route.path_globs)
            ),
            None,
        )
        if candidate is None:
            continue
        examples.append(
            {
                "path": candidate,
                "topic": "",
                "expect_routes": (route.route_id,),
            }
        )
        covered.add(route.route_id)
    return replace(config, examples=tuple(examples))


def load_config(root: Path, relative: str = DEFAULT_CONFIG) -> Config:  # noqa: F405
    return _with_real_path_examples(root, _core_load_config(root, relative))


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
    # Keep the legacy core fixture stable; the wrapper-specific route coverage
    # is exercised independently below.
    _core.load_config = _core_load_config
    try:
        _core_self_test()
    finally:
        _core.load_config = load_config

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

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        candidate = root / "crates/a/Cargo.toml"
        candidate.parent.mkdir(parents=True)
        candidate.write_text("[package]\nname='a'\n", encoding="utf-8")
        rule = RouteRule(  # noqa: F405
            route_id="live-route",
            description="test",
            path_globs=("crates/**",),
            topic_keywords=(),
            required_handles=(),
            optional_handles=(),
            required_files=(),
            optional_files=(),
            max_required_bytes=None,
        )
        config = Config(  # noqa: F405
            pair_schema="",
            baseline_handles=(),
            baseline_files=(),
            baseline_optional_handles=(),
            baseline_optional_files=(),
            max_required_bytes=1,
            routes=(rule,),
            examples=(),
        )
        augmented = _with_real_path_examples(root, config)
        if len(augmented.examples) != 1:
            raise RouteError("live route payload example was not synthesized")  # noqa: F405
        example = augmented.examples[0]
        if example["path"] != "crates/a/Cargo.toml" or example["expect_routes"] != (
            "live-route",
        ):
            raise RouteError("live route payload example is nondeterministic")  # noqa: F405

    print("DOC_ROUTER_HARDENING_SELF_TEST: PASS cases=4")


_core.normalize_repo_path = normalize_repo_path
_core.git_changed_paths = git_changed_paths
_core.load_config = load_config
_core.self_test = self_test
main = _core.main


if __name__ == "__main__":
    raise SystemExit(main())
