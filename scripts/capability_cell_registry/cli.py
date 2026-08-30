"""Command-line entrypoint for capability-cell evidence."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from .compiler import compile_registry
from .fixtures import self_test
from .model import RegistryError, fail, source_identity


def current_source(root: Path, explicit: str | None) -> str:
    if explicit:
        return source_identity(explicit)
    if os.environ.get("GITHUB_SHA"):
        return source_identity(os.environ["GITHUB_SHA"])
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        fail("--source-sha is required when Git identity is unavailable")
    return source_identity(completed.stdout.strip())


def write_registry(path: Path | None, registry: dict[str, object]) -> None:
    text = json.dumps(registry, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if path is None:
        sys.stdout.write(text)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("generate", "validate", "self-test"))
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--source-sha")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-partial", action="store_true")
    args = parser.parse_args()

    if args.command == "self-test":
        self_test()
        return 0

    root = args.repo.resolve()
    exact_source = current_source(root, args.source_sha)
    registry, findings = compile_registry(root, exact_source)
    if findings and not args.allow_partial:
        codes = ", ".join(sorted({finding.code for finding in findings}))
        fail(f"registry is PARTIAL with {len(findings)} finding(s): {codes}")

    if args.command == "generate":
        write_registry(args.output, registry)
        print(
            "CAPABILITY_CELL_REGISTRY_GENERATE: "
            f"{registry['status']} cells={len(registry['cells'])} "
            f"findings={len(findings)} coverage={registry['scope']['coverage_status']}",
            file=sys.stderr,
        )
    else:
        if args.output is None or not args.output.is_file():
            fail("validate requires an existing --output file")
        try:
            observed = json.loads(args.output.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            fail(f"cannot parse existing registry: {error}")
        if observed != registry:
            fail("generated registry is stale or does not match current inputs")
        print(
            "CAPABILITY_CELL_REGISTRY_VALIDATE: PASS "
            f"cells={len(registry['cells'])} source={exact_source} "
            f"coverage={registry['scope']['coverage_status']}"
        )
    return 0


def run() -> None:
    try:
        raise SystemExit(main())
    except RegistryError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
