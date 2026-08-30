## I18.9. Hard Boundary discriminators

Before broad feature depth, the current recovery line passes independently:

```text
Forged finish:
  caller prose, `accepted=true`, missing fields and legacy payload cannot produce VERIFIED_COMPLETE;

Lossless payload:
  arbitrary nested JSON is byte-exact through write, restart, read, backup and isolated restore;

One control path:
  report deletion/tampering cannot change authority;
  live CLI/MCP writes use one GovernorRuntime composition;
  stale epoch/principal/revision is denied;

One process path:
  every governed external tool is launched through ProcessExecutor;
  direct spawn lint is clean; cancellation leaves no unaccounted child.
```

A pass on one cannot compensate for another.

