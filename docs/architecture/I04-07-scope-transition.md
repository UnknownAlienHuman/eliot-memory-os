## I4.7. Scope transition

Expand/contract/merge/split/move:

```text
1. create proposed ScopeTransition;
2. identify records/authority affected;
3. preserve old scope and provenance;
4. copy/reference data only as candidates unless validity transfers deterministically;
5. issue new scope generation;
6. invalidate incompatible sessions/leases;
7. verify new truth and access boundaries;
8. commit receipt.
```

Cross-scope atomicity is not promised. Use a saga with visible partial outcomes.

