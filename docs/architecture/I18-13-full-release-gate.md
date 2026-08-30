## I18.13. Full release gate

ReleaseProof includes:

```text
clean build, lockfile, SBOM/license/source identities;
all supported Module and InstrumentProfile contract suites;
canonical store migration/backup/restore;
Host/Kernel/daemon/module update and rollback;
security/authority/privacy and direct-spawn/write-path checks;
representative agent hosts/routes;
long-running resume and swarm coordinator recovery;
Windows installer/update/uninstall;
local/CI profile parity;
exact Product Identity and evidence manifest.
```

Release gate is infrequent and is not run after every local patch.

