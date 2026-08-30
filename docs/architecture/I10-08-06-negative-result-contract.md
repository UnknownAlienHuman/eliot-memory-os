### I10.8.6. Negative-result contract

Absence is a fact only when all conditions hold:

```text
freshness is exact for the candidate and scope;
coverage is complete for the queried relation/scope;
the instrument contract can prove absence;
no higher-authority contradictory evidence exists.
```

Otherwise ELIOT returns a typed unknown such as:

```text
not_found_in_partial_index;
unknown_due_to_staleness;
unknown_due_to_cfg_or_macro_coverage;
unknown_due_to_worktree_overlay;
unknown_due_to_truncation_or_tool_failure.
```

Statements such as `no callers`, `dead symbol`, `no dependents` and `change cannot affect X` never arise from incomplete heuristic evidence.

