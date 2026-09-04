# Assignment reservation

Owning issue: #915
Implementation branch: `feat/915-manual-integration-workflow`
Required predecessors: D-CI #750, D-INT-INV #905, D-INT-CORE #907, and every provider class required by the accepted inventory
Parent umbrella: superseded D-INT #752

Status: **blocked marker-only** until all required predecessors integrate and this branch is rebased onto current `main`.

Exclusive mutable scope after activation:

- `.github/workflows/integration.yml`
- `scripts/tests/test_integration_workflow.py`
- `scripts/testdata/integration/workflow/**`
- this marker until implementation begins

Manual `workflow_dispatch` only. No schedule/automatic trigger, existing workflow, harness/core/inventory/provider, Rust/Cargo/Just/release/docs or GitHub-write/secret authority change.

Issue #915 is the complete 20-case execution contract. Remove this marker when implementation begins and before ready-for-review.
