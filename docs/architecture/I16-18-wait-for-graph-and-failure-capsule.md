## I16.18. Wait-for graph and Failure Capsule

ELIOT maintains a derived wait-for graph for active attempts, jobs and resources:

```text
attempt/job → lease, mailbox, process, provider quota, human approval,
worktree/environment, store scope, artifact or child attempt.
```

It is diagnostic evidence, not a scheduler authority. Cycles, stale holders, oldest wait age and missing heartbeats feed Diagnostic Brief and Watchdog signals.

Any nontrivial failed, timed-out, cancelled-with-effects or unknown-outcome run produces a content-addressed `FailureCapsule` containing:

```text
Product/WorkScope/task/attempt and State Fence;
route/runtime/toolchain/build/test profile identities;
base/candidate/artifact digests;
last causal events and normalized failure signature;
raw log/trace handles and truncation facts;
wait-for graph excerpt;
seed, schedule and failpoint set when simulated;
process/resource/cleanup evidence;
known effects and unknown outcomes;
reproduction command/profile;
current hypothesis, rivals and next discriminator;
privacy/redaction receipt.
```

The capsule is sufficient for replay or bounded diagnosis without sending all raw logs to the model. A retry never overwrites the first capsule; attempts form a lineage.

