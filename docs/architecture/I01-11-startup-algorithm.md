## I1.11. Startup algorithm

```text
1. Host opens and validates HostStateJournal, the approved artifact registry and the independent Watchdog service state through SCM.
2. Host reconciles stale process lineages, then starts Kernel with the exclusive installation mutex and a dedicated Kernel Job Object.
3. Kernel opens ORS, verifies the integrity anchor and loads the Generation Registry.
4. Kernel validates the approved Blob Store manifest. It starts the blob generation on the first non-inline capture, recovery or GC demand; a failed blob probe degrades only large-payload capture and never fabricates a canonical BlobRef.
5. When canonical access is required, Kernel requests Host to start/reuse the canonical-store Job Object, then starts/reconnects the store bridge and waits for independent readiness/schema probes.
6. Kernel reconciles pending/unknown operations before enabling normal writes.
7. Kernel starts candidate `eliotd` and performs protocol/contract handshake.
8. `eliotd` loads Config/Policy snapshots and rebuilds hot mirrors from named reads/outbox cursor.
9. Required capability set is evaluated; optional failures become visible degradation.
10. Kernel publishes front-door readiness and releases queued attaches.
11. Watchdog independently confirms process/plugin/heartbeat coverage and updates the supervision evidence used by the Governance Profile.
```

Front-door readiness permits attach, inspection and policy-allowed low-impact work. Material/Critical authority remains capped by the current Governance Profile; it is not unlocked merely because the pipe is ready. No agent receives Material authority while ORS reconciliation, schema compatibility, authority-epoch recovery or the required supervision/enforcement evidence is incomplete.

