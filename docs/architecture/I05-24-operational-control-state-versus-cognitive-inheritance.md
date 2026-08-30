## I5.24. Operational control state versus cognitive inheritance

The canonical store contains several governed state families under one owner, but they do not have interchangeable authority.

```text
Operational control state
  TaskContract, WorkItem, Attempt, Lease, Authority Epoch, Effect ledger,
  GenerationCutover, Durable Job, outbox and terminal receipts;

Cognitive inheritance
  sources, observations, evidence, epistemic positions, models, decisions,
  procedures, failures, relations and memory lifecycle;

Derived indexes/projections
  Ready Queue, search/cue/code graphs, packets, dashboards and reports;

Artifact state
  immutable source/output/build/log/component/failure objects by digest.
```

Task, lease, effect, generation and job truth is resolved from operational records and receipts, never from semantic similarity, a memory summary, an agent narrative or a derived index. Cognitive inheritance may inform planning and verification but does not authorize an effect. Derived projections are rebuildable and cannot become a second control ledger.

This is a logical separation, not a requirement for four databases. The first SurrealDB implementation may keep the families under one transaction boundary while preserving owners, schemas, queries, retention and recovery rules.

