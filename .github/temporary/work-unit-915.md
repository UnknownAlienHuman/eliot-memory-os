# Assignment reservation

Owning issue: #915
Branch: `work/915-d-int-workflow`
Base: current `main` at reservation creation
Required predecessors: D-INT-INV #905, D-INT-CORE #907, and only inventory-activated provisioners among #909/#911/#913
Parent umbrella: D-INT #752

Exclusive responsibility: add the final least-privilege manual/scheduled isolated-integration workflow and structural oracle.

Exclusive mutable scope:

- `.github/workflows/integration.yml`
- `scripts/tests/test_integration_workflow_contract.py`
- `scripts/testdata/integration/workflow/**`
- this reservation marker until implementation begins

Issue #915 is the complete 18-case execution contract. No inventory, harness, provisioner, Rust/Cargo, other workflow, repository setting, secret/environment or documentation change belongs here.

Remain marker-only until all required predecessors integrate. Remove this marker when implementation starts and before ready-for-review.
