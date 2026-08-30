#!/usr/bin/env python3
"""Deterministic fake Antigravity/agy CLI for zero-model preflight tests."""
from __future__ import annotations

import argparse
import os
import sys
import time


SECRET_KEYS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "GITHUB_TOKEN",
)


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--mode", default="full")
    parser.add_argument("--runtime", choices=("primary", "fallback"), default="primary")
    known, rest = parser.parse_known_args()

    if any(key in os.environ for key in SECRET_KEYS):
        print("secret environment crossed boundary", file=sys.stderr)
        return 77
    if known.mode == "timeout":
        time.sleep(10)
    if known.mode == "nonzero":
        print("synthetic failure", file=sys.stderr)
        return 9
    if rest == ["--version"]:
        print(f"fake-antigravity-{known.runtime} 1.0.0")
        return 0
    if rest in (["exec", "--help"], ["--help"]):
        if known.mode == "oversized":
            sys.stdout.write("x" * (2 * 1024 * 1024))
            return 0
        if known.runtime == "fallback":
            print("usage: agy [--model MODEL] [--workspace PATH] --diff")
            return 0
        if known.mode == "missing-json":
            print("usage: antigravity exec --stdin --model MODEL --workspace PATH")
            return 0
        if known.mode == "missing-stdin":
            print("usage: antigravity exec --json --model MODEL --workspace PATH")
            return 0
        print(
            "usage: antigravity exec --stdin --json --persistent "
            "--resume SESSION --model MODEL --permission PROFILE --workspace PATH"
        )
        return 0
    print("unexpected invocation", file=sys.stderr)
    return 8


if __name__ == "__main__":
    raise SystemExit(main())
