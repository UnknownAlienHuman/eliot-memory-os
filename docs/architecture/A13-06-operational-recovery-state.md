## A13.6. Operational Recovery State

When the canon is unavailable, only the following may be stored:

```text
operation identity and opaque envelope or artifact locator;
idempotency, sequence, and reconciliation state;
job checkpoint and cancellation;
Authority Epoch and suspended leases;
Module health and restart attempts;
problem and incident intents;
Recovery Manifest, backup pointers, and integrity anchors.
```

ORS does not interpret content as claims, decisions, Current Epistemic Position, or project graph, and grants no authority. Privacy and provenance remain intact. When the canon returns, operations are reconciled by receipt before replay. An unknown commit or external-effect outcome is first resolved through operation identity and observations; blind retry is prohibited.

