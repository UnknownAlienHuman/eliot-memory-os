## A13.2. Kernel and Failure Domains

A minimally live Kernel can:

```text
withhold unsupported authority;
preserve or safely freeze canonical state;
show health and unavailable guarantees;
accept cancellation or recovery requests;
fence stale owners;
manage independent Module lifecycles.
```

The Kernel does not depend on a model call, Dreamer, graph, external provider, UI, or one adapter.

The Host Supervisor operates outside the shared process failure domain of Kernel, Watchdog, and Doctor. It starts, stops, and bounded-restarts approved services, but neither reads project semantics nor selects a repair hypothesis. Kernel, Watchdog, and Doctor have separate service identities and restart budgets; repeated failure of any one becomes a Problem State rather than an endless restart loop.

The final honest boundary is platform failure: if the Host Supervisor, operating system or machine, and fallback notification path are all lost, ELIOT does not promise to report its own total disappearance. Recovery is then manual or platform-level.

