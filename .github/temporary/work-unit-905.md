# Assignment reservation

Owning issue: #905
Implementation branch: `feat/905-ignored-test-inventory`
Required predecessor: D-CI #750
Parent umbrella: superseded D-INT #752

Status: **blocked marker-only** until #750 integrates and this branch is rebased onto current `main`.

Exclusive mutable scope after activation:

- `scripts/integration/ignored_test_inventory.py`
- `scripts/tests/test_ignored_test_inventory.py`
- `scripts/testdata/integration/ignored-test-inventory/**`
- this marker until implementation begins

Read-only inventory only. No Rust source/test/ignore marker, integration harness, provisioner, workflow, Cargo/lock, Justfile, verification script or documentation change.

Issue #905 is the complete 26-case execution contract. Remove this marker when implementation begins and before ready-for-review.
