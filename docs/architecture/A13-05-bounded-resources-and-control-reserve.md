## A13.5. Bounded Resources and Control Reserve

Queues, buffers, jobs, model calls, agents, and outage spools are bounded.

Under saturation:

```text
new work receives backpressure;
an accepted operation preserves identity;
background work yields to interactive work and verification;
noncritical enrichment is dropped first;
one poison operation moves to dead-letter or quarantine;
independent Ordering Scopes continue;
false acceptance is prohibited.
```

Admission and scheduling isolate budgets by Module, principal, task, and swarm: one branch cannot displace independent work or Control Reserve.

Control Reserve protects capacity for:

```text
cancellation and fencing;
health and critical telemetry;
Critical Attention, Problem, and Incident transitions;
persistent notification inbox;
safe shutdown;
recovery.
```

Reserve exists at every relevant bottleneck, not merely as high priority. Its loss is recorded through a last-resort path outside normal workload. If that path is also unavailable, the system explicitly loses its control guarantee.

