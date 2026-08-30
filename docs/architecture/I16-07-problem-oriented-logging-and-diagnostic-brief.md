## I16.7. Problem-oriented logging and Diagnostic Brief

Operational logs are not bulk semantic memory. They remain rolling files/events; only exact anomaly windows, normalized diagnostics, receipts and selected evidence handles enter canonical/problem state.

`LogWindowRef` records source/process generation, time/sequence range, hash, redaction status and retention. Agent receives no unbounded log dump by default.

Trigger:

```text
Problem opened/updated;
repeated failure/no-progress;
module crash or restart exhaustion;
security/integration gap;
user/agent request;
release/canary failure.
```

Diagnostic compiler joins:

```text
symptom/severity and affected Module/WorkScope/tasks;
causal timeline from receipts/events;
exact LogWindowRef/evidence handles;
correlated code/config/module generation changes;
graph/dependency relations;
prior failures and attempted repairs;
unknowns and observation gaps;
one cheapest useful probe/repair/escalation.
```

Correlation is marked as hypothesis until intervention/verifier. Brief has State Fence and invalidation condition. If telemetry is insufficient, it returns a gap and required observation rather than forcing the agent to search blindly or invent a cause.

