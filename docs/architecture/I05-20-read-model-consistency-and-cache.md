## I5.20. Read model, consistency and cache

Read tiers:

```text
Q0 handle/preview;
Q1 current task/scope state;
Q2 exact evidence and relations;
Q3 Active Understanding View / Context Packet;
Q4 audit/replay/evidence pack;
Q5 research/reconstruction cold job.
```

`ReadConsistency` modes:

```text
eventual             — cheap preview;
at_least_revision    — read-your-write after receipt;
stable_scope         — coherent packet/current-position assembly;
exact_fence           — all listed dependency revisions must match.
```

Stable-scope algorithm:

```text
derive the exact dependency revision keys for the requested view;
read RevisionHead set A;
execute bounded named reads;
read the same RevisionHead set B;
if every dependency revision matches, publish;
else retry once or return stale/churn directive.
```

`ScopeRevisionView` is a rebuildable aggregate for previews and diagnostics. It is not a write-serialization row and is never sufficient for a Material State Fence by itself.

Caches are revision-keyed and reconstructible:

```text
RevisionHeadCache;
PacketCache;
Cue/Activation mirror;
Module Catalog / Capability Registry snapshot;
read-through exact-atom cache.
```

No cache invents freshness. Every reused response has dependency set and invalidation conditions. Cache reuse also obeys I2.22: integrity is separate from origin authentication, untrusted roots/reparse paths are rejected or treated as misses, and a cache is never a correctness dependency.

