## I12.7. Cue Index

Derived projection:

```text
(scope, cue_kind, normalized_value)
→ record handles, status, freshness, danger, token estimate.
```

Hot mirror uses immutable per-scope snapshots via `ArcSwap`. Updates come from canonical outbox. Full rebuild is possible.

Firing rules:

```text
inputs come only from observed task/tool/world events;
exact matches precede prefix/signature matches;
negative memory and invariants precede decisions, claims, skills and capsules;
items already delivered in one Session are suppressed unless invalidated;
result count/payload is bounded; overflow is a resource handle;
normal firing is deterministic and model-free.
```

No redb semantic index.

