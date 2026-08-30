## I14.13. Idle drain and cancellation

Drain hierarchy:

```text
stop new work;
cancel noncritical child tasks;
checkpoint durable jobs;
quiesce modules;
complete/abort in-flight canonical transactions explicitly;
flush receipts/outbox;
stop dependency order;
write clean shutdown manifest.
```

Cancellation never claims rollback of already executed external effect.

