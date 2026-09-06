# Assignment reservation

Owning issue: #909
Branch: `work/909-d-int-store`
Base: current `main` at reservation creation
Required predecessors: D-INT-INV #905 and D-INT-CORE #907
Parent umbrella: D-INT #752

Exclusive responsibility: implement the isolated SurrealDB/Store provisioner for accepted `surrealdb-store` inventory rows.

Exclusive mutable scope:

- `scripts/integration/IntegrationHarness.SurrealDb.psm1`
- `scripts/tests/IntegrationHarness.SurrealDb.Tests.ps1`
- `scripts/testdata/integration/surrealdb/**`
- this reservation marker until implementation begins

Issue #909 is the complete 22-case execution contract. No inventory, harness-core, Windows runtime, Git/worktree, Rust/Cargo, workflow or documentation change belongs here.

Remain marker-only until #905 and #907 integrate and the inventory actually requires this provisioner. Remove this marker when implementation starts and before ready-for-review.
