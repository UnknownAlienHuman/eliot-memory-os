## I8.1. Process and authority

`eliot-watchdog.exe` is a separate Windows service or process outside the Host and Kernel failure domain. Its run policy is dual: while a valid `SupervisionLease` exists for an observable Session, AgentAttempt, Durable Job, protected effect, maintenance or recovery operation, or explicit supervision policy, the minimal deterministic sensor remains running even if Kernel and `eliotd` sleep; a dormant registered WorkScope alone is insufficient. Outside that active interval it stops after persisting journal cursors and wake intents. Host, CLI, or SCM may start it on demand. Watchdog never becomes a Host or Kernel child and remains independently observable during `eliotd` failure.

This is the direct Implementation of Architecture 4.5: Watchdog is continuous and independent for every interval in which ELIOT is observably used or claims supervision. When there is no active Session, job, effect, maintenance/recovery obligation or user-enabled supervision policy, the interval is closed, cursors/wake state are persisted and Watchdog may stop. There is no claim of machine-wide observation outside such an interval and no Architecture conflict.

Watchdog owns:

```text
supervision observations;
signal processing state;
independent minimal spool;
security/liveness rules;
request to contain, diagnose, restart or escalate.
```

Watchdog does not own:

```text
canonical semantic transitions;
Current Epistemic Position;
task decisions;
module repair execution;
Architecture changes;
completion;
model/swarm budget.
```

Canonical Problem/Incident transition performs Governor. If Governor is unavailable, Watchdog writes `problem_intent`/`incident_intent` into its **own physically separate minimal spool** (`watchdog.redb`) for later reconciliation. This spool uses the same restricted non-semantic envelope as ORS but is not stored in the Kernel ORS failure domain.

