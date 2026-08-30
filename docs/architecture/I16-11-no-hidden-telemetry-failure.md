## I16.11. No hidden telemetry failure

Critical event path:

```text
normal audit write;
if unavailable → ORS/Watchdog spool;
if unavailable → last-resort control slot/event log;
if all unavailable → visible control-loss state when next channel returns.
```

Silent success is forbidden.


---

