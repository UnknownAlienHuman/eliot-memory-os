# Assignment reservation

Owning issue: #851
Implementation PR: #856
Branch: `work/851-work-unit-case-bindings`
Original base revision: `d89d3e7b9d012993aa22a8d00db75f6a6740a2de`
Required predecessor: D-WU-C0-FIX #857 / PR #858
Parent integration: #837

Status: **blocked marker-only** until #858 merges. Rebase current `main` after #858 before creating `case_binding.py` or any production test/fixture.

Exclusive mutable scope after the predecessor gate:

- `scripts/work_unit_gate/case_binding.py`
- `scripts/tests/test_work_unit_case_binding.py`
- `scripts/testdata/work-unit-gate/case-binding/**`
- this marker only until implementation begins

Issue #851 is the complete 44-case contract. Implement language-aware Rust/Python marker attribution and exact case→discovery→execution reconciliation using the corrected shared discovery/execution/result contracts from #858. Do not define local substitutes or weaken anti-placeholder accounting.

No assignment fetch, subprocess runner, cohort, final CLI, descriptor, leaf source/test/router, Cargo/Rust, workflow or documentation change.

Remove this marker when implementation starts and before ready-for-review.
