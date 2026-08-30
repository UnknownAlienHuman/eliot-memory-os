## I8.10. Containment

Watchdog issues signed requests for pre-authorized circuit breakers; it does not mutate HostStateJournal, ORS, Module Catalog, route policy or canonical state itself.

```text
request Host/Kernel to close normal admission;
request Kernel to revoke/fence a Session, lease or Module epoch;
request Kernel to quarantine a module generation;
request Host/Kernel to stop a child process;
request the owning gateway/module to disable remote Dream access;
request Governor to remove a route from new admission;
preserve evidence and request scoped isolation.
```

The receiving owner revalidates current epoch, target, evidence, recipe class and exact allowed effect, then records the actual containment receipt. Watchdog cannot create a new permission, canonical transition or semantic conclusion.

If Governor is unavailable, Host may execute only its pre-registered process stop/restart/fence operations; an independent effect interlock may deny only the exact effect class it already owns. Both record a non-semantic result/intent in HostStateJournal or the physically separate Watchdog spool for later reconciliation. Kernel ORS receives that intent only after the corresponding control path is available.

