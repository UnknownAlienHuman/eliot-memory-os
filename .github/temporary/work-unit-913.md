# Assignment reservation

Owning issue: #913
Implementation branch: `feat/913-isolated-git-integration-provider`
Required predecessors: D-INT-INV #905 and D-INT-CORE #907
Parent umbrella: superseded D-INT #752

Status: **blocked marker-only** until #905 and #907 integrate and this branch is rebased onto current `main`.

Exclusive mutable scope after activation:

- `scripts/integration/IntegrationHarness.Git.psm1`
- `scripts/tests/IntegrationHarness.Git.Tests.ps1`
- `scripts/testdata/integration/git-provider/**`
- this marker until implementation begins

Isolated local Git repository/worktree provider only. No core/inventory, Store/Runtime provider, workflow, Rust source/test, Cargo/lock, source repository `.git/**`, global/system Git config, credentials, network or documentation change.

Issue #913 is the complete 20-case execution contract. Remove this marker when implementation begins and before ready-for-review.
