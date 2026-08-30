## A9.5. Interfaces and Outputs

Three surfaces are theoretically required:

```text
Main Agent ↔ Dreamer;
Human ↔ Dreamer;
Watchdog or system jobs ↔ Dreamer.
```

Typical requests:

```text
Orientation Query;
Memory Query;
Architecture Query;
Research Query;
Curation Request;
Conflict Analysis;
Memory Repair Request.
```

Typical results:

```text
Dream Packet;
Research Brief;
Architecture Brief;
Clarification Request;
Curation Candidate;
Conflict Brief.
```

Every result includes the question, WorkScope and State Fence, evidence handles, model synthesis separated from evidence, rivals, unknowns, coverage gaps, route and cost, and an invalidation condition.

