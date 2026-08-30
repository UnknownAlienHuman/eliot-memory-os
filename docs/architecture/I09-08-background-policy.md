## I9.8. Background policy

Dreamer background work uses the canonical `MaintenanceAutomationMode` of I14.22 rather than a second scheduler-policy enum. DEFAULT desktop mode for Dreamer curation is `idle_only`, with no external model calls unless the user enables them and a route/budget exists. `off` disables even proactive curation recommendations except safety/recovery obligations; `suggest_only` creates a deduplicated Human-board proposal without starting a model job.

Triggers:

```text
candidate backlog crossed value threshold;
repeated failure/conflict;
user/Main Agent query;
Watchdog Problem State;
Architecture/WorkScope generation change;
memory health degradation;
maintenance schedule.
```

One observation never automatically means one model call. Jobs are batched by scope/problem.

### DreamCycle — bounded “sleep-like” maintenance

A `DreamCycle` is the explicit implementation analogue of human sleep-like offline integration. It is one `Dreamer curation` maintenance `DurableJob`, not a new scheduler or memory lifecycle. It is not a permanent thinking loop and does not rewrite memory. A cycle selects a bounded scope and review horizon, replays recent/active episodes plus unresolved conflicts and utility signals, then may launch short curation/challenge agents to propose:

```text
episode consolidation and compact orientation;
duplicate/false-merge review;
relation, concept, procedure or FailureFingerprint candidates;
reconsolidation/reopen/extinction candidates;
context/Skill/tool-surface improvements;
missing evidence, unresolved contradictions and discriminative probes.
```

Every cycle records the sampled coverage, omitted material, model/agent routes, budget, candidate set, rejected transformations and later utility. Primary evidence and minority alternatives remain intact. A cycle whose outputs are unused, repeatedly wrong or more expensive than the measured benefit is narrowed, disabled or sent to Mechanism Review.

### Candidate backlog discipline

Dreamer does not create an unbounded advice heap. Curation/research candidates are deduplicated by target, problem class, source lineage and proposed effect. The active backlog is bounded by policy; stale, superseded and low-value candidates are compressed or archived with receipts. A Material unresolved candidate without an owner becomes Human/Agent Attention instead of being regenerated repeatedly. Only one automatic experiment per target may be active at a time.

