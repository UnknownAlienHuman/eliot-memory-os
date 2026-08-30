## I12.17. Compaction and resume

Pre-compaction `HandoffCheckpoint` preserves:

```text
goal/acceptance;
current plan revision;
done/open/killed/deferred;
current epistemic position handles;
exact load-bearing atoms;
current diff/artifacts;
pending verifiers;
critical attention/conflicts;
next action and stop condition;
State Fence;
known losses.
```

Resume:

```text
revalidate scope/world/module generations;
revoke stale leases;
rebuild delta View from canonical state;
explicitly mark lost distinctions;
never treat summary as original rationale/evidence.
```

