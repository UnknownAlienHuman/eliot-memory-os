## A12.1. Security Assumes Breach

ELIOT does not assume that prompt injection, poisoned memory, a malicious Tool Definition, or a compromised model will always be detected in advance.

Defense is layered:

```text
Hard Boundaries;
buffering;
separation of instruction, data, evidence, and authority;
origin-bound provenance;
bounds on allowed influence and effects;
multiple independent routes;
quarantine and revocation;
backup, restore, and recovery;
Watchdog observation;
Human escalation.
```

**ARCH-SEC-01 — Assume compromise; preserve control and recovery.** Security succeeds when a breach gains no hidden authority, has a bounded blast radius, is detectable, and is reversible.

