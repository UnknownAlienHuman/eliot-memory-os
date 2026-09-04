# Assignment reservation

Owning issue: #857
Implementation branch: `fix/857-work-unit-contract-closure`
Predecessor: merged D-WU-C0 #848 / PR #853

Exclusive responsibility: complete the shared work-unit verification contracts and intrinsic canonical/result-coherence invariants omitted by #853.

Exclusive mutable scope:

- `scripts/work_unit_gate/contracts.py`
- `scripts/work_unit_gate/__init__.py` only for required exports
- `scripts/tests/test_work_unit_gate_contracts.py`
- additive fixtures under `scripts/testdata/work-unit-gate/contracts/**`
- this temporary marker until implementation begins

Issue #857 contains the complete 38-case execution contract. It blocks #849, #850, #851 and #852 from defining production contract substitutes until this correction merges and they rebase.

Remove this marker when implementation starts and before ready-for-review.
