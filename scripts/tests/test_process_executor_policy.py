"""Focused ProcessExecutor boundary tests (issue #748, Slice B).

Slice B owns tests plus frozen fixtures only; the oracle
(`scripts/audit-architecture-boundaries.py`) and policy
(`config/architecture-boundaries.toml`) are owned by Slice A and are never
mutated here. Frozen fixtures live under
`scripts/testdata/process-executor-policy/`.

Base: 6d48a6ce43ff0524d386063182104f6e5e28840e
Branch: work/748-process-executor-tests

Binding assumption (for the manager-integrator): these tests bind to the base
oracle entry points for the issue's "existing process-launch discovery" and
"exact exception validation" owner, namely `_contains_direct_process_launch`
(discovery, backs `untracked_direct_process_launch`), `_matches_owner`
(exception validation against `process_owner`), `_production_prefix`
(production/test attribution), and `load_policy` (policy reader). If Slice A
renames or extends these validators for alias/wrapper/macro/raw-API gap
coverage, the integrator must rebind 748/1 and 748/2 to the new names; the
fixture semantics below (unauthorized constructor detected, accepted executor
surface clean) are the stable contract.

The issue's 35-case matrix is DEFERRED by binding owner order ("one or two
focused tests per real change; no matrices"). This file therefore contains
exactly the two focused cases 748/1 and 748/2.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "scripts" / "testdata" / "process-executor-policy"
ORACLE_PATH = REPO_ROOT / "scripts" / "audit-architecture-boundaries.py"
POLICY_PATH = REPO_ROOT / "config" / "architecture-boundaries.toml"

FROZEN_FIXTURES = [
    "unauthorized-std-constructor.rs",
    "accepted-executor.rs",
]

_spec = importlib.util.spec_from_file_location(
    "audit_architecture_boundaries", ORACLE_PATH
)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load {ORACLE_PATH}")
oracle = importlib.util.module_from_spec(_spec)
sys.modules["audit_architecture_boundaries"] = oracle
_spec.loader.exec_module(oracle)

_contains_direct_process_launch = oracle._contains_direct_process_launch
_matches_owner = oracle._matches_owner
_production_prefix = oracle._production_prefix
load_policy = oracle.load_policy


def _read_fixture(name: str) -> str:
    path = FIXTURE_DIR / name
    return path.read_text(encoding="utf-8")


class TestProcessExecutorPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        missing = [n for n in FROZEN_FIXTURES if not (FIXTURE_DIR / n).is_file()]
        assert not missing, "missing frozen fixtures: %r" % (missing,)
        assert ORACLE_PATH.is_file(), "missing oracle: %r" % (ORACLE_PATH,)
        assert POLICY_PATH.is_file(), "missing policy: %r" % (POLICY_PATH,)

    # WORK_UNIT_CASE: 748/1
    def test_01_unauthorized_std_constructor_detected(self) -> None:
        content = _read_fixture("unauthorized-std-constructor.rs")
        self.assertTrue(
            _contains_direct_process_launch(content),
            "unauthorized std constructor fixture must trigger discovery",
        )
        self.assertTrue(
            _contains_direct_process_launch(_production_prefix(content)),
            "detection must hold on the production prefix (no cfg(test) elision)",
        )
        policy = load_policy(POLICY_PATH)
        relative = "scripts/testdata/process-executor-policy/unauthorized-std-constructor.rs"
        self.assertFalse(
            _matches_owner(relative, policy),
            "unauthorized fixture path must not match any process_owner exception",
        )

    # WORK_UNIT_CASE: 748/2
    def test_02_accepted_executor_surface_passes(self) -> None:
        content = _read_fixture("accepted-executor.rs")
        self.assertFalse(
            _contains_direct_process_launch(content),
            "accepted executor fixture must not trigger discovery",
        )
        self.assertFalse(
            _contains_direct_process_launch(_production_prefix(content)),
            "accepted surface must stay clean on the production prefix",
        )
        policy = load_policy(POLICY_PATH)
        self.assertTrue(
            _matches_owner(
                "crates/instrument/eliot-process-executor/src/lib.rs", policy
            ),
            "canonical sole-owner path must match a process_owner exception",
        )


if __name__ == "__main__":
    unittest.main()
