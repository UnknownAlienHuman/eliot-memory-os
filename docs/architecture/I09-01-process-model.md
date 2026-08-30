## I9.1. Process model

`eliot-dreamer.exe` — separate supervised AI service and the primary cold-path intelligence coordinator of ELIOT. The process is demand-started for an admitted Dreamer query/job/maintenance obligation and may stop when no such obligation remains; while active but between model calls it stays lightweight and launches no permanent LLM loop. “Primary intelligence” means that it organizes hypotheses, maintenance and cognitive work; it does not mean canonical ownership, unrestricted execution or final authority.

```text
Dreamer request/problem trigger
→ policy/budget admission
→ bounded input bundle
→ one model agent or controlled swarm
→ structured candidate output
→ provenance/loss checks
→ deliver result
→ explicit disposition by the named Governor, task, WorkScope or Human decision owner.
```

Dreamer has no DB credentials and no canonical write endpoint except candidate submission through Governor.

