## I2.15. Hot-path modularity

### Runtime hot path

Normal decision path:

```text
IPC/frame receive
→ identity/session/fence validation
→ immutable state snapshots
→ exact task/cue/attention lookup
→ deterministic policy/gate
→ compact response/receipt.
```

Hot-path crates may be numerous: static linkage adds no runtime hop. Their contracts require:

```text
no model call;
no process startup or module discovery;
no index rebuild or blocking filesystem scan;
no unbounded DB/tool/network wait;
no lock held across `await`;
no mutable cross-crate singleton;
bounded allocations/collections;
immutable or versioned snapshot inputs;
explicit stale/degraded result;
cheap tracing with raw expansion by handle.
```

Hot data is published through immutable snapshots or atomic generation swap. Writer and cold services prepare projections asynchronously; the hot path only reads a compatible revision.

### Dependency shape

There is no fixed maximum crate-layer count. Review starts for observed causes:

```text
latency trace shows material overhead;
build critical path and reverse fan-out slow the change loop;
the agent workset loses the Decision Safety Floor or complete causal closure;
a dependency cycle or heavy adapter enters the hot path;
a high-churn contract hub forces unrelated crates to rebuild continually;
ownership or recovery boundary becomes unclear.
```

Contract hubs must remain stable; heavy adapters, UI, Researcher, Dreamer, vendor SDKs, and test frameworks stay outside the hot path. A thin composition root is the Default, not a numerical depth rule.

### Cold path

```text
model jobs;
Dreamer/Researcher;
semantic indexing;
compaction/consolidation;
large graph traversal;
coverage/mutation;
module startup/update;
repair/migration;
full report rendering.
```

The cold path never blocks an action gate silently. It creates a Durable Job and later updates a projection.

