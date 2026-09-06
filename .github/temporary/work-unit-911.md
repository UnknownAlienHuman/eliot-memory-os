# Assignment reservation

Owning issue: #911
Branch: `work/911-d-int-runtime`
Base: current `main` at reservation creation
Required predecessors: D-INT-INV #905 and D-INT-CORE #907
Parent umbrella: D-INT #752

Exclusive responsibility: implement the isolated Windows Kernel/Host/Governor/Watchdog runtime-topology provisioner for accepted `windows-runtime` inventory rows.

Exclusive mutable scope:

- `scripts/integration/IntegrationHarness.WindowsRuntime.psm1`
- `scripts/tests/IntegrationHarness.WindowsRuntime.Tests.ps1`
- `scripts/testdata/integration/windows-runtime/**`
- this reservation marker until implementation begins

Issue #911 is the complete 24-case execution contract. No inventory, harness-core, SurrealDB, Git/worktree, Rust/Cargo, workflow or documentation change belongs here.

Remain marker-only until #905 and #907 integrate and the inventory actually requires this provisioner. Remove this marker when implementation starts and before ready-for-review.
