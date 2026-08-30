## I15.3. Least privilege processes

```text
Host: service/process management only;
Kernel: ORS, control and generation routing; it may start/route bridges but has no DB or user-subscription credentials;
Store bridge: DB credentials, no agent/model;
Blob service: payload CAS/encryption/compression, no DB credentials or semantic query;
Daemon: domain operations via public store/blob APIs, no DB credentials;
Watchdog: sensors/spool, no canonical write;
User Broker: exact user/session-scoped launches and workspace adapters under one-time leases; no DB, Module Catalog, route-policy or broad-shell authority;
Dreamer/modules: scoped data/tools, no canonical credentials;
UI: loopback API only; exact loopback `Host`/`Origin` validation is mandatory and DNS-rebinding forms are rejected.
```

