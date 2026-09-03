#!/usr/bin/env python3
"""One-shot exact upgrade for specialized Dreamer, Watchdog, and Doctor routes."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def blob(relative: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), "hash-object", relative],
        text=True,
    ).strip()


def replace_exact(
    relative: str,
    old: str,
    new: str,
    expected_blob: str,
) -> None:
    path = ROOT / relative
    actual = blob(relative)
    if actual != expected_blob:
        raise SystemExit(
            f"specialized-route source moved: {relative} "
            f"expected={expected_blob} actual={actual}"
        )
    value = path.read_text(encoding="utf-8")
    count = value.count(old)
    if count != 1:
        raise SystemExit(
            f"specialized-route patch point count={count}: {relative}"
        )
    path.write_text(value.replace(old, new, 1), encoding="utf-8", newline="")


def main() -> int:
    replace_exact(
        "docs/code-navigation/logical-blocks.toml",
        'documentation_handles = ["I12.13", "I17.11"]\n'
        'documentation_route_ids = ["memory-context"]\n\n'
        '[[block]]\n'
        'id = "security-privacy"',
        'documentation_handles = ["I12.13", "I17.11"]\n'
        'documentation_route_ids = ["memory-context"]\n\n'
        '[[block]]\n'
        'id = "dreamer-cognition"\n'
        'title = "Dreamer cognition and reflection"\n'
        'responsibility = "Dreamer orientation, bounded reflection, hypotheses, orchestration candidates, and sleep-like cognitive work."\n'
        'route_topic = "dreamer reflection hypothesis offline cognition orchestration"\n'
        'path_globs = [\n'
        '  "crates/smart/eliot-dreamer-*/**",\n'
        '  "bins/eliot-dreamer/**",\n'
        ']\n'
        'documentation_handles = ["A9", "I9"]\n'
        'documentation_route_ids = ["dreamer"]\n\n'
        '[[block]]\n'
        'id = "security-privacy"',
        "c15342e9460dc46f707cfc63b7106a12f037aed1",
    )

    logical = ROOT / "docs/code-navigation/logical-blocks.toml"
    logical_after_first = subprocess.check_output(
        ["git", "hash-object", "--stdin"],
        input=logical.read_bytes(),
    ).decode().strip()
    replace_exact(
        "docs/code-navigation/logical-blocks.toml",
        'documentation_handles = ["I8.3", "I14.25"]\n'
        'documentation_route_ids = ["supervision-meta"]\n\n'
        '[[block]]\n'
        'id = "operator-surfaces"',
        'documentation_handles = ["I8.3", "I14.25"]\n'
        'documentation_route_ids = ["supervision-meta"]\n\n'
        '[[block]]\n'
        'id = "watchdog-runtime"\n'
        'title = "Watchdog liveness and protected observation"\n'
        'responsibility = "Independent Watchdog liveness observation, protected spool evidence, and bounded recovery interaction."\n'
        'route_topic = "watchdog liveness protected spool recovery observation"\n'
        'path_globs = [\n'
        '  "bins/eliot-watchdog/**",\n'
        ']\n'
        'documentation_handles = ["A8.1", "A13.2", "A13.8", "I2.16", "I2.23", "I8.1", "I8.2"]\n'
        'documentation_route_ids = ["watchdog"]\n\n'
        '[[block]]\n'
        'id = "doctor-operations"\n'
        'title = "Doctor diagnostics and bounded repair"\n'
        'responsibility = "Doctor diagnostics, recovery recipes, bounded repair, maintenance, and operational status."\n'
        'route_topic = "doctor diagnostics repair recovery recipe maintenance operational status"\n'
        'path_globs = [\n'
        '  "bins/eliot-doctor/**",\n'
        ']\n'
        'documentation_handles = ["A13.3", "A13.12", "I14", "I15", "I16"]\n'
        'documentation_route_ids = ["doctor-operations"]\n\n'
        '[[block]]\n'
        'id = "operator-surfaces"',
        logical_after_first,
    )

    replace_exact(
        "docs/architecture/route-rules.toml",
        'path_globs = ["bins/eliot-dreamer/**", "crates/**/*dream*/**"]',
        'path_globs = ["bins/eliot-dreamer/**", '
        '"crates/smart/eliot-dreamer-*", "crates/**/*dream*/**"]',
        "d6b913a915e9d96703b785faae44eb3e018d33ac",
    )

    subprocess.run(
        [sys.executable, "scripts/docs_router.py", "sync", "--root", "."],
        cwd=ROOT,
        check=True,
    )
    print("SPECIALIZED_PACKAGE_ROUTES_UPGRADE: PASS blocks=3")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
