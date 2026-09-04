# Assignment reservation

Owning issue: #850
Implementation PR: #855
Branch: `work/850-work-unit-descriptor-runners`
Original base revision: `d89d3e7b9d012993aa22a8d00db75f6a6740a2de`
Required predecessor: D-WU-C0-FIX #857 / PR #858
Parent integration: #837

Status: **blocked marker-only** until #858 merges. Rebase current `main` after #858 before creating `descriptor_runner.py` or any production test/fixture.

Exclusive mutable scope after the predecessor gate:

- `scripts/work_unit_gate/descriptor_runner.py`
- `scripts/tests/test_work_unit_descriptor_runner.py`
- `scripts/testdata/work-unit-gate/descriptor-runner/**`
- this marker only until implementation begins

Issue #850 is the complete 40-case contract. Implement the three fixed bounded `rust-package`, `python-unittest` and `metadata-python` runners around the corrected shared descriptor, discovery, execution, package and workspace contracts from #858. Do not define local substitutes.

No arbitrary command, executable, URL, environment, secret, glob or checkout escape. No assignment source, case parser, cohort, final CLI, leaf router, Cargo/Rust, workflow or documentation change.

Remove this marker when implementation starts and before ready-for-review.
