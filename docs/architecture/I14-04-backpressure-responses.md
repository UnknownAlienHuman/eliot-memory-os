## I14.4. Backpressure responses

```text
BUSY                 — request not accepted; retry directive;
STORAGE_BACKPRESSURE — no durable staging available;
ACCEPTED_PENDING     — staged; do not retry, poll operation;
DB_UNAVAILABLE       — canonical-sensitive action blocked;
BUDGET_EXHAUSTED     — checkpoint and ask for route/scope/budget decision;
STATE_CHURN          — packet/read could not stabilize;
CAPABILITY_DEGRADED  — requested operation unavailable, alternatives shown;
```

Every response includes `RecoveryDirective`.

