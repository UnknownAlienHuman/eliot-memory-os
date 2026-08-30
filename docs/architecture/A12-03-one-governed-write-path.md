## A12.3. One Governed Write Path

An agent, Dreamer, Watchdog Agent, Doctor, or external service receives no direct canonical write path.

```text
proposal or observation
→ admission and provenance
→ governed transition
→ canonical receipt.
```

A logically single semantic transition atomically binds event and history, current projections, affected revisions, and receipt. If the substrate cannot provide shared atomicity across several scopes or external effects, the system uses an explicit staged or saga transition with visible partial outcomes.

Direct storage access, a shell or database-protocol bypass, or a second writer is a security and integrity problem regardless of how plausible the content appears.

**ARCH-SEC-02 — One canonical transition path.** A recovery interface may preserve intent and evidence, but cannot become a hidden second Governor.

