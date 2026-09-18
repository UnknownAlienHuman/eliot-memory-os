#!/usr/bin/env python3
"""Thin compatibility delegate for the D-WU-FINAL gate (#837).

Legacy source-shape diagnostics, NOT work-unit completion evidence. This
entrypoint delegates without divergence to scripts.work_unit_gate.__main__
(the final orchestration). It runs no Cargo command itself and cannot approve
a work unit. No work unit is accepted by the legacy path.

Usage:
    python scripts/verify-work-unit.py --crate <name> [--root .] [--no-cargo]
    python scripts/verify-work-unit.py --proof <kind> [options]
    python scripts/verify-work-unit.py --help

Exit codes:
    0  help only, or explicitly requested proof satisfied (never legacy)
    1  execution evidence incomplete / contract failure
    2  usage / configuration / internal failure
"""
from __future__ import annotations

import sys
from pathlib import Path


def _gate_main(argv: list[str]) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    try:
        from scripts.work_unit_gate.__main__ import main as gate_main
    except Exception as exc:
        print(f"error: gate unavailable ({type(exc).__name__})", file=sys.stderr)
        return 2
    if not callable(gate_main):
        print("error: gate malformed; bounded non-success", file=sys.stderr)
        return 2
    try:
        code = gate_main(argv)
    except SystemExit:
        # Preserve legacy behaviour: usage errors raise SystemExit(2) for
        # in-process callers (rejected before inspection), not a return.
        raise
    except Exception as exc:
        print(f"error: gate internal ({type(exc).__name__})", file=sys.stderr)
        return 2
    if type(code) is not int or code not in (0, 1, 2):
        print("error: gate malformed return; bounded non-success", file=sys.stderr)
        return 2
    return code


def crate_dir(root, crate):
    """Compatibility shim: legacy crate lookup (patched by tests to assert
    no inspection happens before usage rejection). Delegates to the gate."""
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    try:
        from scripts.work_unit_gate.__main__ import _legacy_crate_dir as _impl
    except Exception:
        raise AssertionError("unexpected inspection")
    return _impl(root, crate)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    return _gate_main(args)


if __name__ == "__main__":
    sys.exit(main())
