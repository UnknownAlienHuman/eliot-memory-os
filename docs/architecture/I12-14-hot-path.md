## I12.14. Hot path

The hot path is a bounded synchronous control/evidence path assembled from the `hot-spine` crate group defined in I2.15. It may include many Rust crates while remaining one in-process call graph inside Kernel or `eliotd`.

```text
session/task lookup;
State Fence and Governance Profile check;
exact current-state/cue lookup;
precomputed activation/attention read;
authority/admission decision;
packet delta and decision-local tail assembly;
ready capability/profile lookup;
small canonical read/write admission and receipt.
```

It MUST NOT perform:

```text
model inference;
Dreamer/Watchdog Agent call;
process or service startup;
Cargo/rustc/test execution;
semantic indexing or graph rebuild;
network discovery;
migration/repair;
unbounded storage scan;
unbounded decompression/rendering;
waiting on an optional Module that is not already READY.
```

Hot-path dependencies are explicit in `HotPathManifest`:

```yaml
HotPathManifest:
  operation:
  owning_service:
  crate_closure:
  immutable_snapshot_dependencies:
  queues_and_capacity:
  synchronous_external_calls:
  fallback_or_degradation:
  HotPathProfile_ref:
```

Rules:

```text
crate closure must be acyclic and free of vendor SDK leakage;
state is read through immutable/revisioned snapshots where possible;
queues are bounded and expose backpressure;
no hidden global singleton or detached task;
optional process call is allowed only under I2.15 readiness/latency/fallback contract;
semantic/cold work updates PendingContextDelta asynchronously;
failed/stale evidence returns handle, unknown, probe or RecoveryDirective;
no background work is smuggled into a gate because the caller is waiting.
```

Every hot operation has measured queue wait, service time, allocations, lock contention, cache behavior and degradation rate. A crate entering the hot-spine group requires a HotPathProfile and an affected product pulse.

