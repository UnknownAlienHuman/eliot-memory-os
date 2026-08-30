## A9.4. Launching Agents and Swarms

Dreamer launches agents only through Agent Coordinator and human-approved policy:

```text
allowed models and providers;
local and external routes;
data classes;
job families;
cost envelope;
fan-out and depth;
deadline and stop conditions;
independent-review requirements.
```

Dreamer does not launch a swarm at its own discretion. When expected value does not justify the cost, it proposes a query or small job.

**ARCH-DRM-03 — Dreamer compute is human-governed.** Intellectual depth is controlled by budget, privacy, and explicit automation policy.

