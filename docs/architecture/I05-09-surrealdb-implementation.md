## I5.9. SurrealDB implementation

SurrealDB bridge TARGET DEFAULT (current support is determined only by I0.5 evidence):

```text
separate server process;
remote Rust SDK only inside bridge;
stable fields enforced by generated codecs/schema constraints; SCHEMAFULL preferred for mature records;
typed relation tables;
parameterized named queries;
server-side transactions;
RocksDB-backed single-node service until measured replacement;
logical backup/export only; no copying live DB files.
```

The retained audited source lineage did not prove generic payload round-trip, admission or migration guarantees. That result is regression evidence, not a current repository verdict: current support is classified only by an exact I0.5 `CurrentSystemEvidenceSnapshot`. `SCHEMALESS` by itself is not the defect: a flexible payload is admissible only behind a tagged/versioned codec, required-field constraints, property-based round-trip tests and explicit migration. Stable records normally use SCHEMAFULL or equivalent generated constraints.

### Compatibility gate

SurrealDB 3.2.x is admissible in production after:

```text
schema/migration rehearsal;
transaction/idempotency proof;
crash/restart proof;
backup/restore proof;
query latency on real ELIOT fixture;
no regression against fallback line.
```

Until then, an installation may use only its latest locally qualified fallback generation, regardless of minor-line label. `compatibility.toml` exposes the active decision.

### Store connection generations

Store bridge maintains a fixed bounded client set, not one connection per request:

```text
read clients       — named Q0–Q4 reads under read semaphore;
write clients      — canonical transactions under WriteCoordinator limit;
health/admin client— isolated version/schema/backup/health operations.
```

The target primary transport is the remote RPC/WebSocket path admitted by the exact current compatibility profile. Without that evidence, transport support remains unqualified. HTTP/admin fallback may be used only when separately admitted for the exact health/recovery operation. CLI/offline access requires a stopped store and maintenance authority. Raw database MCP/passthrough is forbidden.

Each client set has a generation, deadlines and bounded reconnect backoff. A broken generation is replaced explicitly; an in-flight write with unknown outcome is resolved by `WriteReceipt` before any replay.

### Canonical-store process generation replacement

The upstream server binary is a Host-managed dependency generation, not an in-place mutable executable and not a second Module Catalog owner.

```text
install immutable candidate binary/config;
rehearse candidate against an isolated imported/copy-on-write dataset;
verify file-format, protocol, schema, transaction and backup compatibility;
quiesce new canonical transactions and reconcile in-flight receipts;
create an ExportFence/backup receipt when the update can change durable format;
prove old process termination and exclusive release of the production data root;
start candidate through HostStateJournal/ManagedDependencyRecord;
verify process liveness plus store-bridge semantic readiness;
resume writes or stop candidate and restart a compatible generation.
```

Two server processes never open the same production data root. A server crash during a possibly committed transaction is reconciled by operation identity/WriteReceipt before any retry. Binary rollback is allowed only while durable format remains compatible; otherwise use isolated restore or forward repair.

`ServiceContract` for the canonical store declares a vendor-supported graceful stop route when one is available, a bounded drain deadline, process-exit observation and a final forced Job Object termination fallback. Forced termination is never called a clean shutdown; the next start performs storage-integrity and unknown-write reconciliation before admitting canonical writes.

