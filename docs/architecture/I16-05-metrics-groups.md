## I16.5. Metrics groups

### System

```text
process/module/adapter health;
restart/quarantine/rollback;
CPU/memory/handles/process descendants;
startup/idle-drain and time-to-safe-recovery;
control reserve;
queue depth/age/bytes and WIP admission;
store health/latency/retries;
ORS size/reconciliation;
testd queue/build/cache/link/test/simulation pressure and time-to-diagnostic;
WASM compile/instantiate/pool/RSS/trap/host-call/output and generation divergence;
native worker process-tree, cancellation, orphan and restart evidence.
```

### Product and development

```text
accepted Product Identity and identity divergence;
current Product Objective and open causal properties;
time since last verified product delta;
repairs per failure class and Mechanism Review count;
activity artifacts per verified product delta;
zero-test, wrong-scope and stale-generation runs;
local PASS / product FAIL contradictions;
status/certificate invalidations;
feature-freeze scope and escape attempts;
failures that produced no behavioral change.
```

Activity metrics are diagnostic counter-metrics. They are never combined into a progress score without grounded product delta.

### Agent/Harness/Route

```text
active tasks, attempts, native sessions and children;
requested vs actual route and route drift;
capability evidence age/failure/quarantine;
continuity kinds and resume success;
event gaps/cursor lag/normalization loss;
trace completeness and Governance Profile axes;
progress age, repeated tool/error loops and cancellation latency;
finish outcomes and verifier coverage.
```

### Understanding/Memory

```text
cue coverage and exact zero-graph firing;
packet size/exact-evidence/position/profile and tokenizer-estimator error;
stale/conflict/unknown and recall disposition;
retrieval admission/suppression and no-graph/full-context controls;
time to orientation, first action, first safe action, first correct action and verifier;
prediction calibration and rival/probe quality;
memory transformation acceptance/false merge/false deletion/false retention;
negative transfer and Architecture conformance gaps.
```

### Swarm/Portfolio

```text
recipe and plan revisions;
fan-out/depth/active lanes;
unique vs repeated coverage;
Evidence Lineage and independence;
writer/reviewer/arbitration mix;
failed/stale/deferred branches;
synthesis/audit latency;
marginal verified contribution of added lanes;
route/task-class success profile;
environment contention and cleanup.
```

### Human

```text
attention queue age and persistent-item resolution time;
missed critical risk and false-critical rate;
notification count, interruption duration and resumption quality/time;
approval opportunities, pre-exposure prevention, conditional intervention and final harm;
benign false blocks, approval count/latency and abandoned work;
intervention/takeover/recovery success;
task correctness, rework and Human-visible degraded time;
privacy/monitoring burden and field-level access/erasure requests.
```

### Usage and cost

Store separately:

```text
input, cached input, output and exposed reasoning tokens;
request/tool/model/native-child counts;
root vs child vs aggregate scope;
wall time and CPU/RAM/process use;
subscription quota fraction/reset/source;
API billed cost, runtime-reported cost and ELIOT estimate;
retry/replay/compaction/environment cost.
```

Truth hierarchy:

```text
provider invoice/API meter
> provider SDK/account meter
> runtime telemetry
> ELIOT estimate
> unknown/not_exposed.
```

Subscription quota is not converted to currency without a provider contract.

