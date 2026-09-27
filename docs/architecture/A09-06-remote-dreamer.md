## A9.6. Remote Dreamer

Online access is permitted only as a bounded question/recall surface. The first remote deployment is single-owner, with external authentication and access-policy administration delegated to the owner's Cloudflare account. ELIOT does not build user accounts or an authentication service.

A remote client receives no:

```text
database credentials or raw canonical browsing;
local filesystem or tools;
write or agent-launch authority;
Kernel/Host/ELIOT administrative control;
unfiltered operational telemetry.
```

The gateway accepts only the externally authenticated owner identity or designated owner automation, verifies the external provider's assertion, and uses the Kernel-issued restricted principal/Session binding. External identity never replaces local process isolation or creates authority. Existing owners limit WorkScope and query class, compile the read-only bundle and control disclosure. The gateway filters inputs and outputs, serves safe bounded citations, does not execute embedded instructions and forwards security signals to Watchdog.

The gateway is independently disabled and fails closed. Additional users, paid accounts, remote writes or broader authority require a separate Architecture Owner decision; they are not implied by successful single-owner authentication.

---
