## I8.3. Deterministic supervision loop

```text
observe
→ normalize event
→ correlate with registered process/session/module/task
→ evaluate deterministic rules
→ deduplicate/update Signal
→ open/update problem intent if threshold crossed
→ emit a signed pre-authorized containment request to the owning Host/Kernel boundary
→ invoke Doctor or bounded Watchdog Agent if semantic diagnosis needed
→ verify resolution
→ close/reopen/escalate.
```

No LLM call in heartbeat or hard security path. Watchdog does not write HostStateJournal, ORS or canonical state directly. Host/Kernel revalidate target, evidence, recipe class, current epoch and allowed effect before executing containment. If Kernel is unreachable, Host may perform only a pre-registered process stop/restart/fence action; result is written to HostStateJournal and Watchdog spool for later canonical reconciliation.

Process liveness and control responsiveness are separate. Watchdog performs an authenticated bounded `HostResponsivenessChallenge` against the current HostInstallationEpoch. `process_alive + challenge_timeout` becomes `ALIVE_UNRESPONSIVE`, not healthy. Under an installation-time pre-authorized SCM recovery policy, Watchdog may request SCM to stop/restart only the exact Host service generation after the challenge and restart budget fail; it cannot select artifacts, alter semantic state or widen authority. Every attempt is recorded in the Watchdog spool and Windows Event Log for later reconciliation.

