# Assignment reservation

Owning issue: #913
Branch: `work/913-d-int-git`
Base: current `main` at reservation creation
Required predecessors: D-INT-INV #905 and D-INT-CORE #907
Parent umbrella: D-INT #752

Exclusive responsibility: implement the disposable local Git repository/ref/worktree provisioner for accepted `git-worktree` inventory rows.

Exclusive mutable scope:

- `scripts/integration/IntegrationHarness.Git.psm1`
- `scripts/tests/IntegrationHarness.Git.Tests.ps1`
- `scripts/testdata/integration/git-worktree/**`
- this reservation marker until implementation begins

Issue #913 is the complete 18-case execution contract. The production checkout, global Git config, network remotes, inventory, harness core, sibling provisioners, Rust/Cargo, workflow and documentation are outside scope.

Remain marker-only until #905 and #907 integrate and the inventory actually requires this provisioner. Remove this marker when implementation starts and before ready-for-review.
