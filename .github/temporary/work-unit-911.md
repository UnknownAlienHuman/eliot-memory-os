# Assignment reservation

Owning issue: #911
Implementation branch: `feat/911-windows-runtime-integration-provider`
Required predecessors: D-INT-INV #905 and D-INT-CORE #907
External composed providers: D-INT-STORE #909 and D-INT-GIT only when inventory rows require them
Parent umbrella: superseded D-INT #752

Status: **blocked marker-only** until #905 and #907 integrate and this branch is rebased onto current `main`.

Exclusive mutable scope after activation:

- `scripts/integration/IntegrationHarness.Runtime.psm1`
- `scripts/tests/IntegrationHarness.Runtime.Tests.ps1`
- `scripts/testdata/integration/runtime-provider/**`
- this marker until implementation begins

Isolated Windows runtime topology only. No core/inventory, Store/Git provider, workflow, Rust source/test, Cargo/lock, release/build script, global service/ACL/firewall configuration or documentation change.

Issue #911 is the complete 28-case execution contract. Remove this marker when implementation begins and before ready-for-review.
