## I9.13. Remote Dreamer gateway

Optional future process `eliot-dream-gateway`.

Allowed:

```text
authenticated bounded question;
predefined WorkScope visibility;
read-only redacted bundle;
answer with citations and gateway-scoped signed references allowed for the remote principal;
audit and security signal.
```

Forbidden:

```text
direct database/retrieval API;
local filesystem/tool access;
write or agent-launch authority;
raw operational telemetry;
broad project enumeration;
secret-bearing bundle.
```

Remote references never expose local `eliot://`, filesystem, blob path, DB key or reusable internal capability. The gateway resolves them through principal-bound, expiring answer resources and re-applies privacy/visibility checks on every expansion.

Remote input always instruction-tainted data. Gateway can be disabled independently.

