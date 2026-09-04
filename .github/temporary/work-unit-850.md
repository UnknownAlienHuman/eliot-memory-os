# Assignment reservation

Owning issue: #850
Branch: `work/850-work-unit-descriptor-runners`
Base revision: `d89d3e7b9d012993aa22a8d00db75f6a6740a2de`
Consumes: D-WU-C0 #848 merged by PR #853
Parent integration: #837

Exclusive mutable scope:

- `scripts/work_unit_gate/descriptor_runner.py`
- `scripts/tests/test_work_unit_descriptor_runner.py`
- `scripts/testdata/work-unit-gate/descriptor-runner/**`
- this marker only until implementation begins

Issue #850 is the complete 40-case contract. Implement a closed descriptor schema and fixed bounded `rust-package`, `python-unittest`, and `metadata-python` runners. No arbitrary command, executable, URL, environment, secret, glob or checkout escape. No assignment source, case parser, cohort, final CLI, leaf router, Cargo/Rust, workflow or documentation change.

Remove this marker when implementation starts and before ready-for-review.
