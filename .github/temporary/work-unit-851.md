# Assignment reservation

Owning issue: #851
Branch: `work/851-work-unit-case-bindings`
Base revision: `d89d3e7b9d012993aa22a8d00db75f6a6740a2de`
Consumes: D-WU-C0 #848 merged by PR #853
Parent integration: #837

Exclusive mutable scope:

- `scripts/work_unit_gate/case_binding.py`
- `scripts/tests/test_work_unit_case_binding.py`
- `scripts/testdata/work-unit-gate/case-binding/**`
- this marker only until implementation begins

Issue #851 is the complete 44-case contract. Implement language-aware Rust/Python marker attribution, exact discovery/execution reconciliation and the bounded anti-placeholder floor. No assignment fetch, subprocess runner, cohort, final CLI, descriptor, leaf source/test/router, Cargo/Rust, workflow or documentation change.

Remove this marker when implementation starts and before ready-for-review.
