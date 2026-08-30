## I14.21. Unknown commit recovery

```text
connection fails during commit;
Kernel queries WriteReceipt by idempotency key;
if committed → reconcile ORS;
if known rollback → retry under same identity;
if unknown → pause Ordering Scope, preserve operation and open Problem State;
Human/Doctor chooses evidence-backed reconciliation; no blind duplicate effect.
```

