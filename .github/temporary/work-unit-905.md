# Assignment reservation

Owning issue: #905
Branch: `work/905-d-int-inventory`
Base: current `main` at reservation creation
Parent umbrella: D-INT #752

Exclusive responsibility: build the complete source ↔ compiled-discovery ignored-test inventory and canonical environment classification manifest.

Exclusive mutable scope:

- `scripts/integration/ignored_test_inventory.py`
- `scripts/tests/test_ignored_test_inventory.py`
- `scripts/testdata/integration/ignored-test-inventory/**`
- `.github/integration/ignored-test-inventory.toml`
- this reservation marker until implementation begins

Issue #905 is the complete 26-case execution contract. No provisioner, final harness, workflow, Rust source, Cargo manifest/lockfile or documentation change belongs here.

Remove this marker when implementation starts and before ready-for-review.
