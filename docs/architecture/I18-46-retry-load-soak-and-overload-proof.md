## I18.46. Retry, load, soak and overload proof

Performance testing targets the real swarm load classes:

```text
many queued tasks and short model/tool events;
compile/test bursts from parallel worktrees;
large streaming outputs;
lease and heartbeat pressure;
provider quota resets;
shadow duplication;
restart and recovery waves.
```

Admission occurs before spawn. Separate pools protect control, interactive verification, ordinary execution, component build, simulation and background work. Tests prove bounded mailboxes, retry budgets, cancellation propagation, load shedding order and preservation of audit-critical events.

Optimization order remains:

```text
correctness/invariants
→ bounded resources
→ profiling
→ remove accidental copies/allocations
→ batch/cache/pool
→ serialization/allocator/runtime specialization only after evidence.
```

Zero-copy formats, custom allocators, shared memory, thread-per-core runtimes or a second build system are Research Gate decisions, not default remedies.

