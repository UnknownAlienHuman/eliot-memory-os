## I8.5. Hook/plugin health

Watchdog tracks:

```text
expected hook set;
last event per hook;
sequence gaps;
plugin/config hash;
active MCP registration count;
bridge protocol version;
observed tools vs declared intercept coverage;
unknown-origin changes;
failed hook exit/status;
multiple competing ELIOT registrations.
```

`installed = true` is not `healthy = true`.

Health compares one semantic installation chain:

```text
tracked source manifest;
generated plugin/Skill/schema manifest;
installed cache/config/registration manifest;
bridge and executable hashes;
active process/runtime fingerprint;
live event readback and coverage receipt.
```

It also tests bounded reentrancy, backpressure, crash, timeout and duplicate-registration behavior. A matching config file without a live event path is `INSTALLED_UNOBSERVED`, not healthy.

