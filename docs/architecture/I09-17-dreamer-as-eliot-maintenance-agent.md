## I9.17. Dreamer as ELIOT maintenance agent

Dreamer is the default intelligent service for maintaining ELIOT’s own cognitive quality. It reviews the `eliot_system` experience bank, open Problems, AgentFeedbackReceipts, memory/context quality, stale capabilities and maintenance debt, then proposes a bounded plan to the daemon.

Allowed requests:

```text
run a curation/orientation/diagnostic job;
spawn one agent or an admitted swarm through Agent Coordinator;
ask an external strong agent for bounded diagnosis;
propose route/model/tool/plugin installation or requalification;
propose configuration or maintenance changes;
prepare an ImprovementCandidate or Human decision packet.
```

Dreamer never acts as an unobserved administrator. Every request has an initiating user/problem/policy trigger, exact scope, budget, state fence, expected delta and rollback. Watchdog observes the request, configuration publication, spawned descendants and post-change outcome. A spontaneous or repeatedly ineffective Dreamer action is itself self-scope evidence and may roll back the candidate route/profile or require Human review.

