## A13.9. Concurrency and Durable Execution

Rule:

```text
parallel where independent;
ordered where causal.
```

One canonical write authority does not mean one global writer thread: independent Ordering Scopes execute concurrently through bounded lanes or tasks, while causally conflicting transitions are ordered.

Conflicting transitions in one Ordering Scope have one owner. A multi-scope operation declares its Coordination Scope in advance and uses deterministic ordering or an explicit saga with visible partial outcomes.

No transaction, exclusive owner, or global lock may be held during unbounded model, tool, or network wait. First record intent and State Fence, then perform external work, then reconcile idempotently under fencing.

A Durable Job has identity, owner, checkpoint, budget, cancellation, State Fence, and outcome. At-least-once execution is permitted only for idempotent, fenced, or reconciled effects.

Job completion is not Task completion:

```text
COMPLETED job → candidate artifact or result;
PARTIAL, FAILED, CANCELLED, or STALE job → coverage gap or replanning;
Task VERIFIED_COMPLETE → only through acceptance verification.
```

**ARCH-ORD-01 — Parallel where independent; ordered where causal.** Concurrency increases throughput but does not remove the single owner of conflicting state, fencing, or reconciliation.

