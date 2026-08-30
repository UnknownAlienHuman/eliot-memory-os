#!/usr/bin/env python3
"""Regression discriminator for executable drift during one Antigravity preflight."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import antigravity_runtime_preflight as preflight


def _stream_receipt(payload: bytes) -> dict[str, Any]:
    return {
        "sha256": preflight.sha256_bytes(payload),
        "total_bytes": len(payload),
        "retained_bytes": len(payload),
        "truncated": False,
        "complete": True,
        "read_failed": False,
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    contract = preflight.load_contract(root)
    runtime = next(
        candidate
        for candidate in contract["candidate_runtimes"]
        if candidate["route_role"] == "primary_candidate"
    )

    with tempfile.TemporaryDirectory(prefix="eliot-antigravity-executable-drift-") as temporary:
        executable = Path(temporary) / "antigravity-candidate"
        executable.write_bytes(b"generation-a")
        calls = 0
        original_runner = preflight.run_bounded

        def mutating_runner(
            command: list[str],
            environment: dict[str, str],
            timeout_ms: int,
            max_stdout: int,
            max_stderr: int,
        ) -> tuple[bytes, dict[str, Any], dict[str, Any], int]:
            del command, environment, timeout_ms, max_stdout, max_stderr
            nonlocal calls
            calls += 1
            if calls == 1:
                payload = b"antigravity 1.0\n"
                executable.write_bytes(b"generation-b")
            else:
                payload = b"stdin json model workspace\n"
            return payload, _stream_receipt(payload), _stream_receipt(b""), 0

        preflight.run_bounded = mutating_runner
        try:
            try:
                preflight._probe_runtime(
                    contract,
                    runtime,
                    {},
                    preflight.ProgramOverride(executable),
                )
            except preflight.AntigravityPreflightError:
                print("ANTIGRAVITY_EXECUTABLE_STABILITY_REGRESSION: PASS")
                return 0
        finally:
            preflight.run_bounded = original_runner

    raise AssertionError(
        "preflight accepted version/help evidence produced across two executable generations"
    )


if __name__ == "__main__":
    raise SystemExit(main())
