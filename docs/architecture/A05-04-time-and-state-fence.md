## A5.4. Time and State Fence

Load-bearing state preserves:

```text
valid time;
known time;
transaction time;
resource generation;
task, policy, and integration revisions.
```

The Governor assigns canonical causal order. External timestamps remain observations. Lease expiry and local scheduling use monotonic-compatible clocks; a clock anomaly creates a Problem State and revalidation, not a silent authority extension.

A State Fence contains only dependencies capable of changing the decision. A change to an unrelated resource does not invalidate the entire task.

