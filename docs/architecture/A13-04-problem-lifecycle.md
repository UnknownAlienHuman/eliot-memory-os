## A13.4. Problem Lifecycle

```text
OPEN
→ TRIAGED
→ DIAGNOSING | CONTAINED | REPAIRING
→ VERIFYING
→ RESOLVED | ACCEPTED_RISK | SUPERSEDED | QUARANTINED.
```

New evidence may reopen a problem. The owner has a review or lease condition; loss of the owner triggers reassignment or escalation rather than closure.

A Signal, restart, notification, or acknowledgement is not resolution.

If the Governor is unavailable, Kernel or Watchdog stores only `problem/incident intent` and an evidence locator in Operational Recovery State; the canonical Problem State is created after reconciliation.

