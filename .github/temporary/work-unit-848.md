# Assignment reservation

Owning issue: #848
Implementation branch: `work/848-work-unit-gate-contracts`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`
Parent integration: #837

Exclusive mutable scope:

- `scripts/work_unit_gate/__init__.py`
- `scripts/work_unit_gate/contracts.py`
- `scripts/tests/test_work_unit_gate_contracts.py`
- `scripts/testdata/work-unit-gate/contracts/**`
- this reservation marker only until implementation begins

The issue body is the complete 24-case contract. This unit defines immutable verification vocabulary and intrinsic invariants only. It performs no network, subprocess, repository scan/mutation, assignment fetching, runner execution, case parsing, cohort migration or final CLI integration.

Remove this marker when implementation begins and before ready-for-review.
