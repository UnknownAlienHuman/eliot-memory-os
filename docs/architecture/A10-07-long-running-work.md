## A10.7. Long-Running Work

Work lasting hours or weeks lives in durable state:

```text
tasks and commitments;
work graph;
Durable Jobs;
checkpoints;
State Fences and Authority Epochs;
Decision, Unknown, Failure, and Artifact ledgers;
Coordination Events;
budgets and progress trends.
```

Assignments, claims, heartbeats, checkpoints, cancellations, and results exist as durable idempotent Coordination Events bound to the work item, causal predecessor, State Fence, and Authority Epoch. A retry uses the same identity; reassignment fences the previous owner first.

Loss of agent context, coordinator, or process does not destroy confirmed work. At reconciliation boundaries, the system reviews State Fences, open Problems and Conflicts, stalled branches, budgets, invalidated evidence, and the next safe action; Watchdog initiates review on drift, not only timeout.

**ARCH-SWM-02 — Swarm coordination survives agents and retries.** Coordination is durable, idempotent, and epoch-fenced; a process is not the sole carrier of an assignment or result.

**ARCH-LONG-01 — Long work lives in durable state.** A session and model route are replaceable executors, not the sole carriers of plan, evidence, and commitments.

