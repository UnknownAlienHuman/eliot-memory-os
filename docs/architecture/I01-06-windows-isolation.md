## I1.6. Windows isolation

DEFAULT:

```text
a separate Job Object is created for each failure domain and Module generation;
Watchdog and Kernel do not share a child-kill domain;
all child processes enter the applicable Windows Job Object;
Kernel descendants remain inside the Host-owned Kernel Job Object and MAY additionally enter nested per-Module/per-attempt Job Objects for tighter limits; startup probes verify the required nesting and kill-on-close semantics on the supported Windows build;
the process tree receives kill-on-close at its outer ownership boundary;
CPU, memory, and process limits are set by Module Manifest;
`system_service` uses a dedicated low-privilege service identity; `user_mode` runs under the current user without pretending to be an SCM service;
named pipes use explicit ACLs;
models and third-party Modules do not inherit secrets by default;
versioned binaries are never replaced in place while running.
```

### User-session isolation

`eliot-user-broker.exe` runs under the interactive user's token, in its own Job Object and immutable generation. Kernel never injects into an arbitrary desktop process. Registration binds installation identity, authorized SID, user-session ID, exact artifact hash and a short-lived launch nonce.

Each WorkScope resource declares its execution/access identity: `service`, `interactive_user:<sid>` or `remote`. The installer does not silently rewrite project ACLs. User-profile roots are observed or mutated through a broker-launched scoped adapter unless the Human explicitly grants the service identity access to that exact root. Snapshots and artifacts crossing back to the service preserve source SID, path scope, privacy and effect receipts.

Logout, session termination, policy change or broker loss revokes broker-bound execution leases and starts attempt reconciliation; machine-scoped canonical work remains intact.

