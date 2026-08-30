## I12.16. Context consistency

Compiler:

```text
derives the exact dependency RevisionHead keys and reads them as Fence A;
queries required projections;
reads the same RevisionHead set as Fence B;
if every relevant dependency is unchanged → coherent;
if changed once → retry;
if churn persists → return explicit stale/partial sections or require refresh.
```

It does not claim simultaneous observation of independent truth surfaces when none exists.

