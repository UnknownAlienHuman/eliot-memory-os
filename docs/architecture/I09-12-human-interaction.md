## I9.12. Human interaction

Human can ask Dreamer through Control Plane:

```text
Orientation or Memory Query;
Architecture / Implementation Query;
Research Query or ELIOT Research handoff;
Conflict / Incident Analysis;
Curation, Maintenance or Memory Repair Request;
configuration explanation/change request;
launch, pause, inspect or replan an external agent/swarm on a selected project.
```

Natural-language chat produces an `OperatorIntentCandidate`, not a direct shell/DB/config command. The UI shows the resolved WorkScope/task, proposed agents/tools, route and actual capability evidence, context/budget, effects, risk, approvals and rollback before execution. Human can edit or reject the plan. Dreamer may answer immediately for read-only orientation, but launch/configuration/maintenance operations follow their normal owners and receipts.

Human sees sources, route, cost, uncertainty and whether result is candidate.

