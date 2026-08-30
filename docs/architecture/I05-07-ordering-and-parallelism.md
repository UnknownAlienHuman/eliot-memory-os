## I5.7. Ordering and parallelism

`OrderingScope` is selected by the state whose preconditions may mutually invalidate.

DEFAULT classes:

```text
scope:<scope_id>
task:<task_id>
problem:<problem_id>
module:<module_id>
principal:<principal_id>
config:<config_domain>
```

One `OrderingScope` has one active writer epoch and one in-flight canonical transition. Independent Ordering Scopes execute concurrently.

Multi-scope transition:

```text
declare all scopes before execution;
sort by stable scope identity;
reserve every scope sequence atomically in one ORS transaction or reserve none;
assign one monotonic reservation_order from the single ORS coordinator;
store transaction verifies every declared `RevisionHead` dependency and every expected `OrderingHead` sequence/hash before commit;
release/finalize all reservations from one canonical receipt;
use an explicit saga when external effects, long waits or substrate limits prevent one transaction.
```

The ORS reservation produces an immutable `WriterReservationToken` bound to:

```text
writer_epoch;
reservation_order;
all Ordering Scopes and reserved sequences;
PreparedTransition/admission digest;
expected RevisionHeads/OrderingHeads;
expiry and recovery owner.
```

`reserve → eligible → execute → finalize/release` checks the same token and writer epoch at every step. A stale executor cannot finalize or release another generation's reservation. Recovery reconciles the token against the canonical receipt before reuse or disposition. Metrics include oldest-ready age, per-scope wait, head retries, reservation conflicts and executor utilization; they diagnose starvation without replacing per-OrderingScope concurrency by a global writer gate.

All multi-scope reservations pass through one short ORS write transaction. Its `reservation_order` creates the same precedence between overlapping operations in every shared scope and therefore prevents cyclic wait graphs. This does **not** serialize independent store transactions: operations with disjoint Ordering Scopes execute concurrently after reservation. No scope lock/DB transaction is held while waiting for a predecessor, model, tool or network operation.

### WriteCoordinator

Committed and uncommitted order have different owners:

```text
Canonical Store `OrderingHead`
  owns the last committed sequence/hash of durable semantic history;

ORS `ReservationHead`
  owns only uncommitted reservations, predecessor waits and retry/dead-letter state;
  it cannot advance canonical history by itself.
```

Execution rules:

```text
configurable executor lanes share one fair ready-scope scheduler;
one canonical transaction may be in flight per Ordering Scope;
independent scopes may commit concurrently, even when assigned to one executor lane;
a retry delay blocks only that scope head, never the whole lane;
deterministic rejection/dead-letter closes or explicitly gaps the reserved sequence before successors proceed;
recovery reconciles ORS reservations against canonical OrderingHeads/receipts before new allocation;
lane-count change requires drained generation switch.
```

Initial desktop default:

```text
writer_executors = min(4, logical_cpu_count)
store_transaction_limit = writer_executors
```

These are runtime defaults and are tuned by real store workload. Increasing them cannot weaken ordering, ORS capacity, Control Reserve or receipt reconciliation.

