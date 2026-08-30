## I5.22. Schema and migration rules

```text
core schema is explicit and versioned;
relation endpoints and required fields are enforced where supported;
migration IDs/checksums are immutable after release;
one migration lease exists per installation;
additive/forward-compatible change is preferred;
data rewrites are Durable Jobs with checkpoints;
destructive/irreversible migration requires backup and Human approval;
blocking migration prevents normal writer readiness, not all recovery inspection;
every migration produces schema snapshot and receipt;
rollback class is declared: reversible | forward-repair | restore-required.
```

Migration code runs only through the store bridge under Kernel-issued migration capability. Agents never execute arbitrary migration queries.

