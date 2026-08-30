## I7.14. Session lifecycle

```text
ATTACHING → ACTIVE ↔ SUSPENDED → DETACHED | EXPIRED | REVOKED
```

Session loss:

```text
revokes session-bound leases;
checkpoints durable tasks/jobs;
does not delete work/evidence;
raises Authority Epoch before reassignment;
retains Route Continuation State only under policy/TTL.
```

MCP connection loss, stdio restart or HTTP reconnect does not end the ELIOT Session automatically. Session state changes only through the application lifecycle, expiry/revocation or explicit detach; transport bindings may be replaced and are recorded as continuity observations.

