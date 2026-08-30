## I13.2. Conflict Set

```yaml
ConflictSet:
  conflict_id:
  type:
  scope_id/task_id:
  candidates:
  evidence_and_lineage:
  authority_and_owners:
  common_mode_failures:
  resolved_parts:
  unresolved_residue:
  argument_acceptability:
  minimal_supporting_assumption_sets_and_defeated_argument_refs:
  discriminative_probe:
  decision_owner:
  affected_actions:
  state: open | investigating | decided | superseded | resolved
```

Conflict is localized state, not global failure.

Claim acceptability is structured, not scalar:

```text
GROUNDED               supported by an admitted, undefeated argument;
CONTESTED              coherent support and an undefeated attack coexist;
DEFEATED               support invalidated;
ASSUMPTION_DEPENDENT   valid only under a named assumption set;
UNDECIDED              no sufficient argument either way.
```

This `argument_acceptability` axis describes support/attack relations inside one Conflict Set. It is orthogonal to I12.5 epistemic status, I7.27 evidence execution/evaluation and the Conflict Set lifecycle state; it does not create another global status dictionary.

A single confidence number is not a substitute: it does not say which assumptions were used, which evidence is independent, what happens if one source is retracted, or who produced the number. `CONTESTED` and `UNDECIDED` are legitimate terminal argumentative states while the Conflict Set itself may remain open, decided or resolved; the system is not obliged to pick a winner when the available evidence is non-diagnostic.

This is a semantics of relations, not an instruction to build a graph database (I12.9).

