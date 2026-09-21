## I7.6. MCP surface

Current concrete logical tools:

```text
eliot.state       — current task/scope/attention/health preview;
eliot.packet      — compile or refresh Active Understanding View;
eliot.observe     — capture observation/decision/failure/outcome naturally;
eliot.query       — exact/pull/Dreamer orientation query;
eliot.act         — request/inspect action authority and contract;
eliot.verify      — run/register verification result;
eliot.coordinate  — work items, agents, Concilium, swarm;
eliot.finish      — submit typed finish attempt.
```

`eliot.query` carries an explicit `QueryIntent` for broad/current/history/provenance/navigation/verification/change-impact/context-reconstruction requests. An immutable exact resource URI may determine its own intent. A broad query with no resolvable intent is rejected with `INVALID_ARGUMENT`; the server does not silently treat historical reconstruction as the current supported position or navigation as evidence.

`eliot.observe` is the single capture surface and has typed suboperations:

```text
observation    — what was observed, with source/effect metadata;
decision       — chosen path, alternatives and revisit condition;
failure        — failed path, signature, evidence and next discriminator;
outcome        — actual artifact/effect/verifier result;
influence_ack  — how a delivered memory item affected the next public decision/action/verifier.
```

`MemoryInfluenceAcknowledgement` is not a claim about hidden reasoning. It names the memory handle, influence class and a downstream public reference. `changed_action`, `changed_verifier` and `prevented_failure` are rejected without an applicable action/verification/outcome reference. Missing acknowledgement means `unknown`, not `unused`. Delivery, acknowledgement, use and causal benefit remain different states.

A legacy bridge may expose `eliot.memory_use` as an alias for `eliot.observe { kind: influence_ack }`; it is not a ninth canonical hot operation and cannot carry different semantics.

Large packets and evidence use MCP resources. Long operations use MCP Tasks when supported; otherwise return ELIOT Durable Job handle.

`eliot.coordinate` is the single semantic execution-fabric surface. Its operation discriminator covers:

```text
delegate   — create a bounded work item/attempt;
audit      — request independent review over a sealed artifact packet;
compare    — compare isolated candidates through deterministic criteria and Concilium;
wait       — await durable run/job changes;
inspect    — read run lineage, evidence, route and capacity state;
cancel     — cancel/reconcile a run or subtree;
send       — durable mailbox/attention response.
```

These are not additional hot MCP tools and do not expose vendor flags or binary paths. Bridges may present convenience aliases, but canonical semantics remain `eliot.coordinate`.

Worker profiles may expose only subset. Tool descriptions remain short; deep contracts are resources/schema.

Tool input/output schemas are generated from the same `serde`/`schemars` contract types used by EBP clients. Hand-written MCP schemas, separate field names or host-specific semantic forks are forbidden. Compatibility adapters translate at the bridge boundary and are tested against canonical semantic fixtures.

