# Assignment reservation

Owning issue: #818
Implementation PR: #822
Branch: `audit/818-work-unit-assignment-integrity`
Base revision: `d89d3e7b9d012993aa22a8d00db75f6a6740a2de`
Semantic owner: deterministic offline assignment identity, satisfiability, scope-overlap and dependency oracle
Required matrix: 56 cases

Exclusive mutable scope:

- `scripts/audit-work-unit-assignments.py`
- `scripts/tests/test_audit_work_unit_assignments.py`
- `scripts/testdata/work-unit-assignment-audit/**`
- this marker until implementation begins

The semantic core consumes a frozen metadata snapshot and must not call or mutate GitHub. Issue #818 is the full contract. Remove this marker when implementation begins and before ready-for-review.
