## I12.22. Theory Portfolio and practical weighting

A `TheoryPortfolio` preserves competing scoped models. It does not collapse them into one scalar confidence.

```yaml
TheoryModel:
  theory_id:
  question_and_scope:
  proposition_or_mechanism:
  dependencies:
  supporting_evidence:
  counterevidence:
  predictions_and_tests:
  successful_and_failed_transfers:
  downstream_artifact/procedure effects:
  source/independence profile:
  freshness_and_revision_conditions:
  operational_status: candidate | usable | preferred | contested | stale | refuted
```

Update rules:

```text
independent observation, discriminative prediction hit and practical verifier success
  → add scoped support;

failed prediction, downstream artifact/procedure error, invalid verifier,
poisoned lineage or scope drift
  → reduce current applicability/support and open review;

agreement sharing one Evidence Lineage
  → one support family, not many votes;

success in new scope
  → transfer support only after revalidation;

replacement theory
  → old theory/history retained with supersession/revision links.
```

A theory that remains locally successful but causes errors in dependent models/procedures is not silently discarded; dependency graph opens or updates `ConflictSet(kind=theory_conflict)` and selects discriminative tests through Concilium.

