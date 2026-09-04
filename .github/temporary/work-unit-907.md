# Assignment reservation

Owning issue: #907
Implementation branch: `feat/907-integration-harness-core`
Required predecessors: D-CI #750 and D-INT-INV #905
Parent umbrella: superseded D-INT #752

Status: **blocked marker-only** until #750 and #905 integrate and this branch is rebased onto current `main`.

Exclusive mutable scope after activation:

- `scripts/run-isolated-tests.ps1`
- `scripts/integration/IntegrationHarness.Core.psm1`
- `scripts/integration/IntegrationHarness.Model.psm1`
- `scripts/tests/IntegrationHarness.Core.Tests.ps1`
- `scripts/testdata/integration/harness-core/**`
- this marker until implementation begins

Generic orchestration only. No ignored-test inventory, Store/Runtime/Git provisioner, workflow, Rust source/test/ignore marker, Cargo/lock, Justfile, verification script or documentation change.

Issue #907 is the complete 32-case execution contract. Remove this marker when implementation begins and before ready-for-review.
