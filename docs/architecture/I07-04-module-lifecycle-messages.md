## I7.4. Module lifecycle messages

```text
Start
Ready
Health
Execute
Result
Event
Cancel
Quiesce
Checkpoint
RestoreCheckpoint
DrainStatus
Shutdown
Fatal
```

Every request has idempotency identity, deadline and cancellation semantics. Every durable lifecycle `Event` follows the EventEnvelope replay/ack contract of I7.2.

