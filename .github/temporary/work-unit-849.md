# Assignment reservation

Owning issue: #849
Branch: `work/849-work-unit-assignment-source`
Base revision: `d89d3e7b9d012993aa22a8d00db75f6a6740a2de`
Consumes: D-WU-C0 #848 merged by PR #853
Parent integration: #837

Exclusive mutable scope:

- `scripts/work_unit_gate/assignment_source.py`
- `scripts/tests/test_work_unit_assignment_source.py`
- `scripts/testdata/work-unit-gate/assignment-source/**`
- this marker only until implementation begins

Issue #849 is the complete 32-case contract. Implement fixed-origin GET-only live authority, bounded Markdown matrix parsing and explicit identity/freshness-bound offline snapshots. No case parser, runner, cohort, final CLI, leaf router, Cargo/Rust, workflow or documentation change.

Remove this marker when implementation starts and before ready-for-review.
