# Assignment reservation

Owning issue: #909
Implementation branch: `feat/909-surrealdb-integration-provider`
Required predecessors: D-INT-INV #905 and D-INT-CORE #907
Parent umbrella: superseded D-INT #752

Status: **blocked marker-only** until #905 and #907 integrate and this branch is rebased onto current `main`.

Exclusive mutable scope after activation:

- `scripts/integration/IntegrationHarness.Store.psm1`
- `scripts/tests/IntegrationHarness.Store.Tests.ps1`
- `scripts/testdata/integration/store-provider/**`
- this marker until implementation begins

Authenticated isolated SurrealDB 3.1.4 provider only. No core/inventory, Runtime/Git provider, workflow, Rust source/test, Cargo/lock, release catalog/script, global machine configuration or documentation change.

Issue #909 is the complete 22-case execution contract. Remove this marker when implementation begins and before ready-for-review.
