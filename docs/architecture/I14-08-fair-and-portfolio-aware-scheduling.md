## I14.8. Fair and portfolio-aware scheduling

```text
separate control, interactive, verification, route/model and background pools;
weighted fair polling and age within class;
per-principal/module/swarm/route/auth-profile WIP limits;
pessimistic quota reservation through the fenced admission saga and later reconciliation;
strong reviewer/arbitration reserve protected from bulk workers;
background/model/swarm admission pauses under interactive/control pressure;
one writer per deliverable by default;
no unbounded retries or recursive fanout.
```

Scheduler is pull-based: terminal/deferred/blocked attempt releases its slot, then the next currently admissible Ready Work Item is selected. Mechanical queue progress never depends on an LLM remembering to start another agent.

