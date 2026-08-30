## A13.7. Backups, Restore, and Migration

A backup includes canonical state, referenced immutable artifacts, policy and configuration snapshots, required pending operational state, purge ledger, Architecture revision digest, manifest, and checksums.

Restore occurs in an isolated area and verifies:

```text
schema and format compatibility;
provenance and integrity;
privacy purge and revocation closure;
semantic inheritance preservation;
Authority Epoch monotonicity;
external-effect reconciliation.
```

Cutover requires separate authority. Old sessions, leases, approvals, and epochs do not revive. The new Authority Epoch lineage must be strictly newer than every observed value, or globally distinct when a shared maximum cannot be demonstrated.

Canonical migration is a governed transformation, not an ordinary restart:

```text
backup and isolated rehearsal;
coverage, preservation, and faithfulness proof;
compatibility window;
checkpoint and resume;
explicit irreversible boundary;
Human authority;
rollback or recovery plan.
```

**ARCH-RES-03 — Recovery cannot resurrect invalid state.** Backup, restore, reindex, and migration preserve history, purge, revocation, and fencing.

