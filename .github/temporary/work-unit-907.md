# Assignment reservation

Owning issue: #907
Branch: `work/907-d-int-core`
Base: current `main` at reservation creation
Required predecessor: D-INT-INV #905
Parent umbrella: D-INT #752

Exclusive responsibility: implement the bounded isolated-test harness state machine and fake-provisioner proof.

Exclusive mutable scope:

- `scripts/integration/run-isolated-tests.ps1`
- `scripts/integration/IntegrationHarness.Core.psm1`
- `scripts/integration/IntegrationHarness.Model.psm1`
- `scripts/tests/IntegrationHarness.Core.Tests.ps1`
- `scripts/testdata/integration/harness-core/**`
- this reservation marker until implementation begins

Issue #907 is the complete 30-case execution contract. No concrete SurrealDB, Windows runtime, Git/worktree provisioner, workflow, Rust/Cargo or documentation change belongs here.

Remain marker-only until #905 integrates. Remove this marker when implementation starts and before ready-for-review.
