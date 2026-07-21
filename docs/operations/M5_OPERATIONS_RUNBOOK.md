# M5 Operations Runbook

## Safety invariants

- Online backup uses `surreal export`; it never copies an open RocksDB directory.
- Credentials come from the configured password file and enter the SurrealDB CLI only through `SURREAL_USER` and `SURREAL_PASS`.
- The default template keeps the SurrealDB password under `%LOCALAPPDATA%/Eliot/secrets`, beside the single default owner and outside synced repositories. Password creation is create-new only; a single fail-closed ACL command removes inheritance/common broad grants and grants only the current Windows SID and `SYSTEM` before secret bytes are written. `%LOCALAPPDATA%` paths must name a normalized file below that root. Custom password files receive the same file ACL hardening and reparse-point rejection.
- Restore imports only into an isolated endpoint whose storage belongs to a new target data-root. A non-dry restore requires maintenance mode and the exact action hash returned by the plan.
- Historical ingestion accepts typed JSON artifacts. Raw `.surql` is rejected even in maintenance mode.
- `eliot_memory_curation_preview` is read-only and revision-fenced. Ruleset `eliot-l13-curation-v1` scans at most 1,000 canonical task records, pages at most 100 findings, reports exact/truncated totals, protects explicit counterexamples/minority records, and proposes only reversible archive/suppress actions; it never mutates or deletes memory.
- Blob purge requires grace expiry, two consecutive scans, an exact approval hash, and a clear load gate.
- Cutover commands produce a manifest. They do not install, start, stop, or reconfigure a Windows service.

## Backup

Plan without contacting SurrealDB:

```powershell
eliot-governor --config <config> backup plan --kind logical
```

Create and verify a logical backup:

```powershell
eliot-governor --config <config> backup run --kind logical
eliot-governor --config <config> backup verify --backup latest
eliot-governor --config <config> backup report
```

The report lists the governed backup inventory and each backup's current verification status. The manifest records the governor/schema versions, logical export, config/policy/control-WAL snapshots, blob manifest, copied blob payload inventory, and BLAKE3 checksums. Blob capture rejects symlinks and refuses a concurrent source change. Verification fails on a missing, additional, escaped, or tampered payload. Secret-like files are excluded from snapshots, including `.env*`, token/auth/password/credential filenames, private keys, PFX/P12 certificates, KeePass databases, and common SSH private-key names.

## Restore drill

1. Create an isolated config with a new loopback port, a new RocksDB path under the target root, and a separate password file.
2. Start that isolated SurrealDB owner.
3. Generate the exact restore plan. Its `exact_action_hash` binds the backup checksums, target root, endpoint, namespace/database, and storage path:

```powershell
eliot-governor --config <source-config> restore plan --backup latest `
  --target <new-data-root> --target-config <isolated-config>
```

4. Execute using that unchanged hash:

```powershell
eliot-governor --config <source-config> restore run --backup latest `
  --target <new-data-root> --target-config <isolated-config> --maintenance-mode `
  --approval-hash <exact_action_hash>
```

5. After validation, stop the isolated target and plan rollback. Rollback quarantines the restored root; it does not delete it:

```powershell
eliot-governor --config <source-config> restore rollback --target <new-data-root> --dry-run
eliot-governor --config <source-config> restore rollback --target <new-data-root> `
  --maintenance-mode --approval-hash <rollback_exact_action_hash>
```

Run the repository proof with `scripts/test-m5-isolated-operations.ps1`. It seeds a real governed TaskContract and candidate Claim in RocksDB, captures the full blob set, detects tampering, restores to a second server, checks revisions and WriterActor idempotency, imports typed historical records without epistemic upgrade, launches the current Governor through its authenticated named-daemon MCP path, reads the restored Operator snapshot, proves the source export did not change, and exercises rollback quarantine.

The test uses a unique named instance under a temporary `LOCALAPPDATA`, verifies the child publication identity before writing any stop marker, and proves an isolated fake `default` marker remains unchanged. These fail-closed guards are part of the maintained test contract.

## Historical import

```powershell
eliot-governor --config <config> import preview --path <staged-json>
eliot-governor --config <config> import execute --path <staged-json> `
  --approval-hash <plan_hash> --maintenance-mode
```

Re-preview immediately before execute. `claim`, `evidence`/`source_snapshot`, `failure`, and `verification` artifacts become their corresponding semantic commands. Claims remain candidate and historical verification remains inconclusive. Each accepted artifact receives a deterministic idempotency key and a canonical WriterActor receipt. Unsupported artifacts are written to quarantine; receipt files make reruns idempotent and the second preview produces zero new mutations.

## Blob GC

Run `blob gc-plan` twice after the configured grace interval. Only the second stable scan emits deletion candidates. Use `blob gc-run --dry-run` first, then provide the exact `approval_hash` from the final plan. If the runtime is under load, pass `--under-load`; purge will be refused.

## Doctor

`doctor operations` reports `ready`, `degraded`, or `blocked`. It checks root and storage sync placement, active runtime owner PIDs, Surreal CLI/endpoint/secret availability, schema and Operator protocol/hash compatibility, latest backup checksum and age, unreceipted imports, endpoint route health, writable import routes, at least 1 GiB free disk space, and ACL visibility. Missing/stale backup or an offline configured route degrades the report; unsafe ownership, storage, schema/protocol, import, disk, or ACL state blocks it.
