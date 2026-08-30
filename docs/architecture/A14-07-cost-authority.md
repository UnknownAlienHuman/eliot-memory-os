## A14.7. Cost Authority

The System Owner sets available routes, global privacy and cost ceilings, and automation policy. The Requester sets task budget and preferences within those bounds; the Task Controller may only narrow them. Governor and Agent Coordinator account for actual consumption from provider and tool receipts attributed to a task, job, or swarm.

When the budget is exhausted:

```text
no new paid job starts;
active work is checkpointed;
verified partial work is preserved;
the coverage gap and options remain visible;
an unauthorized expensive fallback is prohibited.
```

**ARCH-ECON-01 — Cost is authority.** Intelligence has a price; no system service creates a bill without an owner and envelope.

