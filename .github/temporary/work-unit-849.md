# Assignment reservation

Owning issue: #849
Implementation PR: #854
Branch: `work/849-work-unit-assignment-source`
Original base revision: `d89d3e7b9d012993aa22a8d00db75f6a6740a2de`
Required predecessor: D-WU-C0-FIX #857 / PR #858
Parent integration: #837

Status: **blocked marker-only** until #858 merges. Rebase current `main` after #858 before creating `assignment_source.py` or any production test/fixture.

Exclusive mutable scope after the predecessor gate:

- `scripts/work_unit_gate/assignment_source.py`
- `scripts/tests/test_work_unit_assignment_source.py`
- `scripts/testdata/work-unit-gate/assignment-source/**`
- this marker only until implementation begins

Issue #849 is the complete 32-case contract. Implement fixed-origin GET-only live authority, bounded Markdown matrix parsing and explicit identity/freshness-bound offline snapshots. Consume the corrected C0 descriptor/source-receipt identities from #858; do not define local contract substitutes.

No case parser, runner, cohort, final CLI, leaf router, Cargo/Rust, workflow or documentation change.

Remove this marker when implementation starts and before ready-for-review.
