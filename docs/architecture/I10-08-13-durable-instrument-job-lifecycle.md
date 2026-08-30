### I10.8.13. Durable Instrument job lifecycle

A profile run is a specialization of the one canonical Durable Job machine in I14.20; it does not define a competing execution lifecycle.

Canonical job state remains:

```text
NOT_STARTED → QUEUED → LEASED → RUNNING ↔ CHECKPOINTED
→ VERIFYING
→ COMPLETED | PARTIAL | FAILED | CANCELLED | STALE | UNKNOWN_OUTCOME.
```

Instrument-specific progress is an orthogonal `InstrumentPhase`:

```text
RESOLVING
→ PROVISIONING
→ RUNNING_STAGE
→ PARSING
→ FINALIZING.
```

Each stage has:

```text
stable stage/operation identity;
profile and InstrumentSpec revision;
candidate/State Fence;
ProcessExecutor operation ref;
raw stream and parser checkpoint;
resource reservation;
result/disposition.
```

Runner/daemon restart behavior:

```text
process still owned and observable
  → reconcile ProcessEvidence and continue/finalize;

process terminated with proven no effect
  → retry under the same stage identity according to profile;

outcome unknown or generated external artifact ambiguous
  → UNKNOWN_OUTCOME, block only dependent profile/acceptance and reconcile;

parser failed after raw capture
  → preserve raw evidence, rerun parser generation without rerunning tool when safe.
```

No detached compiler/test/index process survives loss of its owned job lineage. Re-execution never hides the first failed/unknown attempt.

