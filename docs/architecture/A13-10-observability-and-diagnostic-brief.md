## A13.10. Observability and Diagnostic Brief

The system distinguishes:

```text
Operational logs — diagnostics; may rotate;
Metrics — aggregates and trends;
Durable audit — authority, transitions, receipts, and incidents;
Reports — Human and agent projections.
```

An elegant report does not prove a transition; absence of a log line does not invalidate a receipt. Operational logs do not become Cognitive Inheritance automatically: only anchored observations and diagnostic evidence enter memory, while bulk external logs or documents require the Researcher acquisition path. Loss of lifecycle, authority, material-action, verification, Incident, or Critical Attention telemetry becomes a Problem State, downgrades demonstrable guarantees, and cannot be closed by a retrospective model narrative.

An agent should not have to search raw logs for an unknown problem. For a crash, timeout, deadlock, failed verification, unknown outcome, or regression, ELIOT preserves a reproducible Failure Capsule: exact Product, Task, and Attempt identity; State Fence; input and artifact generations; event tail; tool and process identities; effect disposition; raw evidence handles; applicable seed, schedule, or failpoint; minimal rerun; and current hypotheses.

From it, ELIOT compiles a Diagnostic Brief:

```text
symptom and severity;
affected Module, WorkScope, and tasks;
causal timeline and evidence handles;
correlated changes and graph relations;
prior failures and attempted repairs;
unknowns;
next discriminator, probe, repair, or escalation.
```

Correlation remains a hypothesis until supported by intervention or evaluation evidence. Repeated debugging begins with a reproducible discriminator, not another broad log review.

**ARCH-OBS-01 — Logs, metrics, audit, and reports are distinct.** Diagnostic flow helps explain a problem, but authority and transition facts are established by receipts and evidence.

