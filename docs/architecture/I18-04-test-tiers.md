## I18.4. Test tiers

A **proof level** says what a result can establish. A **test tier** says how broadly the current change is checked. They are orthogonal: a narrow T1 real process contract may provide EdgeProof, while a broad T3 collection of weak shape checks still does not provide ProductProof.

```text
T0 — changed crate/micro-module: package-selective compile, static/schema, unit/property/golden;
T1 — module public contract, parser/profile contract and health;
T2 — affected provider/consumer edges and one relevant runtime scenario;
T3 — selected authority/data/security/recovery/concurrency/migration/product path;
T4 — release matrix, long-running recovery, installer/update and full supported profile.
```

A tier says how broadly a change is checked; a **fidelity level** says how well the check represents the target. The two are orthogonal and both travel with the evidence:

```text
F0 schema/syntax/static   F1 unit/property   F2 reduced model or toy simulation
F3 realistic simulation or integration       F4 held-out representative workload
F5 shadow or independent environment         F6 physical/external replication
```

Escalation is budget-aware: a higher fidelity level is used after a cheaper level has narrowed the candidate set, when the remaining uncertainty is decision-relevant, and when expected value exceeds the added cost. Every result carries its fidelity level, represented target, omitted factors, validated range and transfer boundary. A high tier of low-fidelity checks does not become a high-fidelity proof.

T3 is triggered only by relevant load-bearing impact. A UI font/style change runs UI build, template/snapshot and accessibility smoke; it does not run database restore, Kernel split-brain or every route.

A full workspace suite may be requested for diagnosis or release, but it is not the default response to local change.

