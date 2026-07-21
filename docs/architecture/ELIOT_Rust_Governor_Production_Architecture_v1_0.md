# ELIOT Rust Memory OS Governor
## Production architecture and implementation contract v1.0

**Дата:** 2026-06-18  
**Статус:** final architecture decision; production-first; код в документе отсутствует  
**Назначение:** Codex должен реализовать Governor по этому документу без самостоятельного выбора архитектуры  
**Primary brain:** Codex  
**Canonical durable memory:** SurrealDB 3.x server with RocksDB production storage  
**Governor implementation:** Rust  
**Deliberate native exception:** RocksDB remains inside the SurrealDB process because it is the upstream-recommended conservative single-node production engine; SurrealKV stays migration/experimental until it leaves beta  
**Primary Codex integration:** native Codex plugin + MCP over stdio + lifecycle hooks  
**External-agent integration:** MCP over stdio or authenticated localhost Streamable HTTP  
**Primary OS:** Windows; core remains portable  

---

# 0. Final decision

Мы пишем **один production Governor на Rust**, а не набор тестовых прокладок, prompt-шаблонов и прямых SurrealQL-вызовов.

```text
Codex / Codex subagents / Antigravity / other MCP agents
                         |
               Codex plugin + hooks
                         |
                MCP stdio / HTTP MCP
                         v
                 eliot-governor.exe
                         |
        +----------------+----------------+
        |                |                |
        v                v                v
 Cognitive Engine   Coordination     Tool Adapters
        |                |                |
        +----------------+----------------+
                         |
                  Governed Storage
                         |
          +--------------+--------------+
          |                             |
          v                             v
 SurrealDB server + RocksDB       local redb control WAL
 canonical memory                queue/session/recovery only
          |
          v
 content-addressed blob store for large raw artifacts
```

Краткая формула:

```text
Codex thinks and synthesizes.
Governor reconstructs state, controls authority, coordinates agents and records proof.
SurrealDB stores canonical governed memory.
redb protects the operational write path; it is not project memory.
Truth adapters check code, runtime, diagnostics, docs and external systems.
```

## 0.1. Decisions that supersede earlier drafts

1. **No FileStore or mock backend as the first implementation.** Первый рабочий build сразу подключается к отдельному SurrealDB server process and writes real schema.
2. **No `surreal mcp` in the production agent path.** После cutover агенты видят только Governor MCP. Прямой SurrealDB MCP остается emergency diagnostic surface and is disabled by default.
3. **SurrealDB runs as a separate local service with a RocksDB data path.** Governor never embeds a storage engine in normal mode and does not tie DB lifetime to a Codex session. The existing SurrealKV store is a migration source, not the production target.
4. **One bounded writer is the v1 safety baseline.** Governor is the only application write authority. The implemented `WriterActor` serializes durable envelopes through one bounded channel and preserves deterministic project sequence/idempotency. Partitioned writer lanes remain a measured scale-out target, not a current product claim.
5. **Normal ingress is not a directory of `.surql` files.** Normal requests use typed MCP/IPC envelopes, are durably staged in redb, and are converted to SurrealQL only inside Governor. File inbox remains recovery/import only.
6. **Codex integration is a real plugin.** It bundles MCP configuration, skills and deterministic lifecycle hooks.
7. **Governor owns the code-understanding route.** Codex no longer has to discover and manually combine every graph/LSP/API tool. Governor calls typed adapters and returns a `CodeCortexReport`.
8. **Operational logs and audit records are different systems.** Debug logs may rotate or sample; receipts, state transitions and proof events may not be dropped.
9. **No online self-modifying policy.** Meta-learning produces candidates. Policy, skill and retrieval changes require explicit promotion and replay evidence.
10. **No unnecessary infrastructure.** No NATS, Temporal, LangGraph, Python runtime, Node orchestration framework, Qdrant or second graph DB in v1.
11. **Reliability overrides language purity at the storage-engine boundary.** The Governor, control plane, IPC, MCP, WAL, policies and adapters are Rust/native-first. RocksDB is the single deliberate C++ dependency hidden behind the SurrealDB server because SurrealDB currently recommends it for conservative single-node production; changing to SurrealKV requires a later ADR and measured migration gate.

## 0.2. Why this is the chosen topology

The current machine audit already proved that multiple embedded processes opening the same SurrealKV path can produce a Windows lock conflict, while a server owner accepts concurrent client operations. The same audit also shows that exact code-graph and file-local diagnostics calls are fast, while broad semantic search and duplicate Node/MCP processes are the expensive surfaces. Therefore the production architecture centralizes long-lived tool processes, uses a server DB owner, performs exact retrieval first, and keeps the agent-visible tool surface small. For the new production data root, the server uses RocksDB rather than carrying the prototype SurrealKV engine forward: current SurrealDB guidance classifies SurrealKV as beta and recommends RocksDB for conservative single-node server workloads.

---

# 1. Architectural contract

## 1.1. Governor is instrumental, not a second brain

Governor must not imitate Codex with hand-written heuristics or embed an autonomous LLM loop in its core.

Governor performs five kinds of work:

```text
1. deterministic state reconstruction;
2. deterministic admission, authority and lifecycle gates;
3. orchestration of exact truth tools;
4. compilation of small typed packets;
5. durable coordination, trace and proof bookkeeping.
```

Codex performs:

```text
semantic synthesis;
hypothesis generation;
causal explanation;
implementation design;
code generation;
judgment under unresolved ambiguity.
```

Model-required background work is represented as a `ReasoningJob` and routed to a registered agent worker. Its output remains candidate-only until verified.

## 1.2. Governor owns these authorities

```text
canonical memory write admission;
current-truth status assembly;
agent identity and scope;
work leases and write-set leases;
packet construction and provenance;
understanding/action/finish gates;
memory lifecycle and forgetting receipts;
trace completeness;
policy/config snapshots;
DB health and recovery state.
```

## 1.3. Governor does not own these truths

```text
source code contents;
Git branch/diff/history;
runtime behavior;
tests/build/lint/typecheck output;
official API documentation;
human decisions;
external artifacts.
```

Those are truth planes. Governor queries them, anchors observations and resolves current state; it does not replace them.

## 1.4. Non-goals

Do not implement:

```text
another DBMS;
an embedding model;
a general RAG framework;
a replacement for Codex;
a replacement for codebase-memory-mcp;
a replacement for LSP/IDE diagnostics;
a general workflow engine;
a distributed cluster bus;
a visual control room;
a second canonical memory system.
```

---

# 2. Patterns adopted from existing systems

This design deliberately imports mechanisms, not entire products.

| Donor/system | Adopted pattern | Rejected pattern |
|---|---|---|
| GitHub Copilot Memory | repository scope, citation-backed facts, validation against current code before use, expiry | opaque provider-owned authority |
| Spectron | one ACID boundary for graph/document/structured memory, provenance, tri-temporal history, fused-rank trace, one MCP surface | closed early-preview dependency |
| Graphiti/Zep | episodes as provenance, fact validity windows, supersession instead of overwrite, incremental temporal graph | Python service and second graph owner |
| MentisDB | append-first ledger, immutable/versioned skill history, signed provenance concepts | second durable brain and unbounded thought-chain storage |
| Acontext | inspectable Markdown skills distilled from successful traces | treating every memory as a skill |
| Cloudflare Durable Objects | serialized state owner per logical entity, persistent coordination, hibernation pattern | cloud-specific runtime |
| AgenticMemory | typed cognitive events, corrections and decision lineage, local-first Rust implementation | replacing ELIOT schema with `.amem` ontology |
| MCP 2025-11-25 | typed tools, structured output schemas, resources, subscriptions, tasks, stdio and Streamable HTTP | state hidden only in transport session IDs |
| Codex plugins/hooks | native bundle of skills, MCP and deterministic lifecycle interception | relying on AGENTS.md alone |

## 2.1. Central lesson

A useful memory system does not maximize stored text or retrieval recall. It enforces this chain:

```text
observation
-> exact evidence
-> scoped claim
-> current-truth resolution
-> decision-local packet
-> action with verifier
-> outcome
-> selective learning or forgetting
```

## 2.2. Production patterns used deliberately

| Pattern | Eliot implementation | Why |
|---|---|---|
| bounded write ownership | one `WriterActor` over `ControlWal` and `CanonicalStore` | keeps v1 ordering, recovery and idempotency explicit |
| canonical transactional receipt | domain projections, `scope_head`, `canonical_record` and `write_receipt` in one parameterized store operation | a receipt cannot claim a product-record write that did not commit |
| CQRS-light | semantic command writes; staged L0-L4 read models | agents never see tables and hot reads stay compact |
| idempotent at-least-once delivery | `write_id`, `message_id`, canonical receipts | retries and reconnects do not duplicate memory |
| fencing leases | monotonic lease epochs on work/action/worktree authority | expired or partitioned agents cannot continue mutating |
| typed product records plus projections | lossless `canonical_record` bodies with materialized current state | supports lifecycle/replay/autonomy inspection without inventing an unimplemented event journal |
| supervised task tree | Tokio cancellation tokens, bounded queues and explicit restart budgets | one failed adapter cannot destabilize the daemon |
| progressive disclosure | MCP tools + resources + tasks, L0 before L2/L3 | controls tool and token entropy |
| capability-based access | role profile + project/task scope + lease epoch | transport identity alone never grants authority |
| evidence-mediated conflict resolution | ConflictSet + discriminative probe | model voting or prestige cannot manufacture truth |

Rejected as unnecessary in v1:

```text
CRDTs or distributed consensus — one local Governor owns canonical coordination;
NATS/Kafka — bounded in-process channels plus durable redb/SurrealDB state are sufficient;
Temporal/LangGraph — a small typed durable JobScheduler covers the bounded job set;
general actor framework — Tokio tasks with explicit ownership are clearer and lighter;
polyglot plugin ABI — adapters are compiled Rust or supervised MCP/CLI processes;
second graph/vector database — no measured need and it would split authority.
```

---

# 3. Production runtime topology

## 3.1. Processes

Normal Windows installation has three long-lived native processes at most:

```text
1. SurrealDB service
   surreal start ... rocksdb://C:/ProgramData/Eliot/data/surrealdb
   sole owner of the RocksDB data directory

2. Eliot Governor service
   eliot-governor.exe daemon run
   sole application authority for memory and coordination

3. Optional code-truth adapter process
   codebase-memory-mcp.exe
   one shared process managed by Governor, not one per Codex thread
```

VS Code/LuaLS remains an existing IDE process when the project requires it. Node-based adapters such as current `wow_api` or `context7` are **lazy**: spawn on demand and terminate after idle TTL. They are never pinned as duplicate processes for every agent.

## 3.2. Codex process path

```text
Codex
  -> plugin-bundled MCP command:
       eliot-governor.exe mcp stdio --profile codex
  -> local IPC named pipe
  -> long-running Governor daemon
```

The stdio process is a thin transport shim. It contains no canonical state, no DB connection and no writer.

## 3.3. Other-agent path

Local agents choose one of:

```text
stdio:
  eliot-governor.exe mcp stdio --profile <profile>

Streamable HTTP:
  http://127.0.0.1:<configured-port>/mcp
  scoped bearer token required
```

Remote bind is disabled in v1. A future remote deployment must add TLS, OAuth client credentials or mTLS, per-request authorization and explicit operator enablement.

## 3.4. Database process path

```text
Governor daemon
  -> SurrealDB Rust SDK
  -> WebSocket/RPC connection to 127.0.0.1
  -> namespace eliot / database system
```

Supported DB modes:

| Mode | Status | Purpose |
|---|---|---|
| `remote_ws` | production default | normal reads/writes to local SurrealDB service |
| `remote_http` | fallback | health/admin compatibility when WebSocket unavailable |
| `cli_recovery` | emergency only | offline export/import/diagnostics against a stopped service, never hot path |
| `surreal_mcp_passthrough` | forbidden in normal mode | bypasses Governor authority |

Only one mode may hold write authority at a time.

Governor keeps a fixed `DbClientSet`, never a connection per request:

```text
read client   — reused for L0-L4 queries under read semaphores;
write client  — reused by writer lanes for bounded concurrent transactions;
health/admin client — isolated from application load for health, version and migration checks.
```

Each client has connection generation, bounded reconnect backoff and request deadline. Replacing a broken generation cancels or fails its in-flight requests explicitly; it never silently replays a transaction with unknown commit status.

## 3.5. Service ownership

The SurrealDB service owns storage files. Governor owns application writes. These are different responsibilities.

```text
SurrealDB service:
  file locking, transactions, indexes, query execution, persistence.

Governor:
  schemas, admission, idempotency, ordering, receipts, current truth,
  context compilation, agent authority and recovery policy.
```

Governor monitors the DB service through health queries and Windows Service Control Manager. It may perform one bounded restart after a failed healthcheck if policy allows. It must never enter an infinite restart loop.

## 3.6. Storage-engine decision

Production v1 initially pins the already installed SurrealDB server line `3.1.4` and a matching Rust SDK compatibility line in `Cargo.lock` and the service manifest. Upgrades require migration rehearsal, backup/restore proof and the normal release gate.

Production v1 uses this exact ownership chain:

```text
Windows Service Control Manager
  -> surreal.exe server process
  -> RocksDB storage engine
  -> C:\ProgramData\Eliot\data\surrealdb
```

Rules:

```text
RocksDB is the production default for the single-node server;
SurrealKV is accepted only as the legacy import source and an explicit experimental profile;
Governor is compiled with the remote SurrealDB Rust SDK transport only;
Governor never links an embedded RocksDB or SurrealKV engine;
no agent sees the storage URI or database credentials;
server credentials are supplied through protected environment/secret configuration, never command-line logs;
the database directory is excluded from OneDrive, antivirus indexing exceptions are operator-controlled, and live files are never copied for backup;
all backups use logical export or a documented offline snapshot procedure.
```

This is the only deliberate exception to the native-Rust preference. Replacing RocksDB with SurrealKV is allowed only after all of the following are true:

```text
upstream no longer marks SurrealKV beta for the chosen deployment;
backup/restore and crash-recovery tests pass on the real Eliot workload;
p95/p99 write, graph traversal and packet queries meet the same or better SLOs;
no regression appears in transaction durability, versioning or operational tooling;
a migration ADR is approved and a reversible cutover is documented.
```

---

# 4. Rust workspace and dependency boundaries

## 4.1. Workspace layout

Use four crates. Do not create a dozen micro-crates.

```text
eliot-governor/
  Cargo.toml
  crates/
    eliot-types/       # pure schemas, enums, IDs, validation rules
    eliot-store/       # SurrealDB, redb WAL, blob CAS, migrations
    eliot-engine/      # governance, cognition, coordination, adapters
    eliot-app/         # daemon, CLI, MCP, HTTP, hooks, Windows service
  migrations/
  plugin/
  config/
  docs/
```

### `eliot-types`

Rules:

```text
no network;
no filesystem;
no Tokio requirement except optional async traits are forbidden here;
Serde + Schemars types;
pure validation helpers;
stable wire schemas.
```

Contains IDs, envelopes, receipts, task/claim states, packets, reports and policy decisions.

### `eliot-store`

Contains:

```text
SurrealStore;
ControlWal based on redb;
BlobStore;
migration runner;
transaction builder;
query registry;
backup/export coordination;
repository implementations.
```

### `eliot-engine`

Contains:

```text
CurrentTruthResolver;
MemoryAdmission;
ContextCompiler;
CodeCortex;
CognitiveGate;
ActionGate;
FinishGate;
WriterCoordinator;
AgentCoordinator;
AdapterSupervisor;
JobScheduler;
ReportService;
LifecycleService;
ReasoningBroker.
```

### `eliot-app`

Contains:

```text
main binary;
Windows service entry point;
local IPC server/client;
rmcp stdio and Streamable HTTP frontends;
Axum health/metrics endpoints;
Codex hook subcommands;
CLI admin commands.
```

## 4.2. Rust implementation style

Use plain supervised Tokio tasks and typed channels. Do not use Actix actors.

Reason:

```text
Tokio tasks are sufficient;
state ownership remains explicit;
less framework magic;
fewer dependencies;
easier cancellation and profiling;
no duplicate actor abstraction over MCP/HTTP services.
```

Every service has:

```rust
trait ServiceLifecycle {
    async fn start(&self, ctx: ServiceContext) -> Result<ServiceHandle>;
    async fn shutdown(&self, deadline: Instant) -> Result<()>;
    async fn health(&self) -> ServiceHealth;
}
```

This is a conceptual signature; exact Rust syntax may differ, but responsibilities may not.

## 4.3. Core dependency decisions

| Need | Rust choice | Reason |
|---|---|---|
| async runtime | `tokio` | mature, bounded channels, process/network/Windows named pipes |
| MCP | official `rmcp` | stdio + Streamable HTTP + tools/resources/tasks |
| HTTP/health | `axum` + `tower` | small, Tokio-native, timeouts/concurrency/load shedding |
| canonical DB | `surrealdb` Rust SDK | typed local connection to server and transactions |
| operational WAL | `redb` | pure Rust, ACID, crash-safe, one writer/concurrent readers |
| serialization | `serde`, `serde_json`, `schemars` | wire schemas and JSON Schema |
| config snapshots | `arc-swap` | lock-light atomic config replacement |
| IDs | `uuid` v7 | sortable unique IDs |
| hashing | `blake3` | fast content addressing and checksums |
| compression | `zstd` | large raw evidence and report bundles |
| logging | `tracing`, `tracing-subscriber`, `tracing-appender` | structured async spans/files |
| filesystem watch | `notify` | config/recovery inbox changes |
| path rules | `globset` | compiled project/write-set policy |
| error model | `thiserror`; `anyhow` only at binary boundary | typed library failures |
| Windows service | `windows-service` | self-contained native service management |
| synchronization | Tokio primitives + `parking_lot` for short sync sections | explicit, low overhead |

Do not add a dependency until its architectural owner and removal boundary are explicit.

---

# 5. Internal runtime model

## 5.1. Supervised services

The daemon starts these services in order:

```text
1. ConfigService
2. ControlWal
3. BlobStore
4. DatabaseMonitor + SurrealStore
5. MigrationService
6. WriterCoordinator
7. ReadService
8. PolicyEngine
9. AgentCoordinator
10. AdapterSupervisor
11. CognitiveEngine
12. JobScheduler
13. ReportService
14. IPC server
15. HTTP MCP/health endpoint if enabled
16. MaintenanceScheduler
```

If steps 1-8 fail, daemon is not ready. Optional adapters may fail without preventing read-only memory operation.

## 5.2. No unbounded queues

Every async queue is bounded.

Default queue classes:

```text
interactive: 512
verification: 512
normal writes: 2048
background: 1024
report rendering: 128
adapter requests per adapter: 64
```

When a queue is full:

```text
return BUSY;
include retry_after_ms;
do not create another in-memory backlog;
do not block MCP transport indefinitely.
```

## 5.3. Priority scheduling

Use separate bounded channels, not a custom unbounded priority heap.

Weighted poll:

```text
8 interactive operations
4 verification operations
2 normal operations
1 background operation
repeat
```

Background maintenance pauses when interactive queue depth exceeds configured threshold.

## 5.4. Cancellation

Every long operation receives:

```text
CancellationToken;
deadline;
operation_id;
trace_id;
agent_session_id;
task_id if present.
```

No detached `tokio::spawn` is allowed without registration in the supervisor.

## 5.5. Local IPC

Windows primary IPC:

```text
\\.\pipe\eliot-governor-v1
```

Unix fallback:

```text
$XDG_RUNTIME_DIR/eliot-governor-v1.sock
```

Wire format:

```yaml
IpcFrame:
  protocol_version:
  kind: request | response | event | cancel | heartbeat
  connection_id:
  request_id:
  payload_type:
  payload:
```

Framing:

```text
4-byte little-endian payload length;
UTF-8 JSON body;
request/response correlation by request_id;
server-initiated events for resource/job/mailbox updates;
maximum frame size and per-connection in-flight count enforced.
```

Why JSON rather than a private binary protocol:

```text
small local payloads;
wire debuggability;
reuse of Serde schemas;
no second schema/compiler system;
performance cost is insignificant compared with DB/tool calls.
```

The daemon creates a random IPC token on each start. The token file and named-pipe ACL are restricted to the current user/service identity. The stdio shim reads the token and performs a handshake before forwarding calls.

---

# 6. Storage architecture

## 6.1. Three storage classes

### A. SurrealDB server on RocksDB — canonical memory

The SurrealDB query/transaction layer owns the canonical model; RocksDB is only its production persistence engine and is never exposed as an Eliot API.

Stores governed durable state:

```text
tasks, evidence, claims, relations, decisions, failures, skills,
verification, packets, proof, agent coordination history, audit events,
receipts, lifecycle state, policy/config snapshots.
```

### B. redb — operational control WAL

Stores only Governor operational state:

```text
pending write envelopes;
local receipt mirror;
uncommitted outbox events;
agent heartbeat cache/checkpoints;
job resume state;
IPC token metadata;
last known DB health;
recovery cursor.
```

It is explicitly forbidden to store project semantic memory in redb. If redb is lost, canonical memory remains intact; only pending/unacknowledged operational work may require recovery.

### C. BlobStore — large immutable payloads

Filesystem content-addressed store:

```text
.eliot/blobs/<first-two-hash-bytes>/<blake3-hash>.zst
```

Stores:

```text
raw tool output;
large logs;
source snapshots;
external review bundles;
large reports;
document bodies;
trace attachments.
```

SurrealDB stores `BlobRef`, size, content type, compression, checksum, retention and source metadata.

## 6.2. Blob algorithm

```text
1. Stream input through redaction policy and BLAKE3 hasher.
2. If payload <= inline threshold, store inline in EvidenceAtom/ToolObservation.
3. Otherwise compress with zstd to a temp file.
4. fsync temp file.
5. Atomic rename to hash path.
6. Submit BlobRef in the same MemoryWriteEnvelope as metadata.
7. If DB commit fails, orphan is harmless and GC may remove it after grace period.
8. Never overwrite an existing hash object.
```

Default inline threshold: `32 KiB`. Configurable.

## 6.3. Canonical write model: implemented v1

Every admitted v1 envelope atomically produces or updates:

```text
1. typed materialized current-state records carried by the semantic command;
2. a lossless `canonical_record` for supported lifecycle/replay/meta/autonomy product records;
3. a `write_receipt` bound to `write_id` and `input_hash`;
4. `scope_head` memory revision and project-sequence increments.
```

The parameterized `apply_write_envelope.surql` operation commits these records as one
SurrealDB transaction boundary. The durable `ControlWal` reconciles ambiguous commit
results by reading the canonical receipt before retrying.

An immutable `memory_event` journal and transactional notification outbox are target
scale-out/recovery features. They are not required to reconstruct or operate the current
v1 product and must not be described as already implemented.

The implemented product-record projection for lifecycle, replay/meta and autonomy
receipts is `canonical_record`. Its authoritative typed body is the exact JSON byte
sequence carried as unpadded base64 in `receipt_body_json_b64`; `receipt_body` is
retained as a legacy/read-side compatibility projection. Readers prefer the lossless
field and fail closed if it is malformed, while pre-existing rows without it remain
readable. Exact subject filters are reconstructed from string fragments so SurrealDB
SQON inference cannot reinterpret handles, UUID-like values, Windows paths, URLs or
approval hashes. The projection is written inside the same WriterActor/CanonicalStore
transaction and carries the canonical receipt, revision and project sequence.

## 6.4. Per-project revisions

Each project has:

```yaml
ScopeState:
  project_id:
  memory_revision: u64
  truth_revision: u64
  task_revision: u64
  policy_revision: u64
  last_project_sequence: u64
  last_commit_id:
  updated_at:
```

Writer lane increments relevant counters in the same transaction as the mutation. Packet and cache keys depend on these revisions.

No global sequence is required for normal reads. `commit_id = UUIDv7` plus timestamp provides global trace ordering; project revisions provide consistency.

---

# 7. Canonical data model

## 7.1. Table families

### Identity and scope

```text
project
project_profile
agent_identity
agent_session
capability_token
approval_request
approval_record
policy_snapshot
config_snapshot
scope_state
```

### Task and coordination

```text
task_contract
acceptance_item
active_decision_state
work_item
unknown_item
work_lease
worktree_lease
handoff_artifact
mailbox_message
blackboard_item
conflict_set
agent_result
```

### Evidence and memory

```text
source_snapshot
evidence_atom
tool_observation
diagnostic_event
episode
claim_card
hypothesis_card
decision_note
failure_fingerprint
skill_card
research_artifact
artifact_ref
blob_ref
```

### Cognition and action

```text
current_truth_view
code_cortex_report
context_packet
context_cargo_receipt
understanding_proof
probe_envelope
action_contract
action_lease
verification_run
finish_attempt
finish_decision
completion_proof
external_review_result
```

### Control and audit

```text
memory_event
write_receipt
operation_job
outbox_event
trace_span
policy_decision
incident_record
lifecycle_request
tombstone
report_manifest
```

## 7.2. Relation tables

Use `SCHEMAFULL TYPE RELATION ... ENFORCED` where endpoints are fixed.

```text
supports
contradicts
verified_by
supersedes
belongs_to
depends_on
calls
reads
writes
produces
consumes
blocks
unblocks
resolved_by
invalidated_by
mentions
derived_from
assigned_to
included_in
used_for
suppressed_by
authorized_by
satisfies
reopens
```

Graph edges are typed facts with provenance and lifecycle, not unlabeled convenience links.

Canonical edge directions:

| From | Relation | To | Meaning |
|---|---|---|---|
| `evidence_atom` | `supports` | `claim_card` | exact evidence supports a claim |
| `evidence_atom` or `claim_card` | `contradicts` | `claim_card` | counterevidence or conflicting claim |
| `claim_card` | `verified_by` | `verification_run` | verifier-backed epistemic upgrade |
| newer `claim_card` | `supersedes` | older `claim_card` | history preserved; older item not current |
| task/claim/artifact | `belongs_to` | project/task | explicit scope ownership |
| memory/evidence item | `included_in` | `context_packet` | compiler admitted the item |
| memory/evidence item | `used_for` | `understanding_proof` or `action_contract` | item changed an authorized decision |
| memory item | `suppressed_by` | `context_packet` or `policy_decision` | explicit non-inclusion reason |
| `action_contract` | `authorized_by` | `action_lease` / `policy_decision` | executable authority chain |
| `verification_run` | `satisfies` | `acceptance_item` | proof coverage for finish |
| probe/evidence | `reopens` | `failure_fingerprint` | discriminative evidence permits retry |

Every edge carries `project_id`, source/evidence references, lifecycle, timestamps and schema version. An edge with no provenance is rejected from durable semantic memory.

## 7.3. Mandatory fields on durable cognitive records

```yaml
id:
project_id:
scope:
branch:
commit:
environment:
created_at:
observed_at:
valid_from:
valid_until:
known_from:
known_until:
transaction_from:
transaction_until:
status:
authority:
taint:
lifecycle_status:
visibility:
source_refs:
evidence_refs:
verification_refs:
supersedes_refs:
policy_version:
schema_version:
```

Optional values remain explicit `option<T>` fields. Free-form undeclared fields are not allowed on core tables.

## 7.4. Required indexes

At minimum:

```text
write_receipt(write_id) UNIQUE
memory_event(project_id, project_revision)
scope_state(project_id) UNIQUE
agent_session(session_id) UNIQUE
approval_request(status, expires_at)
task_contract(project_id, status, updated_at)
active_decision_state(task_id) UNIQUE
unknown_item(task_id, status, updated_at)
work_lease(project_id, state, expires_at)
handoff_artifact(task_id, created_at)
mailbox_message(recipient_session_id, sequence)
claim_card(project_id, subject_key, epistemic_status, lifecycle_status)
hypothesis_card(task_id, status, updated_at)
evidence_atom(project_id, checksum)
diagnostic_event(project_id, file_path, status, observed_at)
verification_run(task_id, status, observed_at)
finish_attempt(task_id, submitted_at)
finish_decision(finish_attempt_id) UNIQUE
policy_decision(operation_id, decided_at)
context_packet(task_id, project_revision, created_at)
operation_job(owner_session_id, status, updated_at)
outbox_event(status, created_at)
incident_record(status, severity, opened_at)
```

Full-text indexes may cover claim proposition, decision summary and failure signature. Vector indexes are optional and disabled until benchmarked; vector similarity never returns final truth.

## 7.5. Schema rules

```text
core tables are SCHEMAFULL;
relation endpoints are ENFORCED;
agent DB credentials have no schema mutation rights;
only migration role may alter schema;
migrations are embedded `.surql` resources with checksum and version;
Governor refuses ready state if schema version is unsupported.
```


## 7.6. Migration rules

```text
migration IDs are monotonically ordered and immutable after release;
each migration has BLAKE3 checksum, minimum/maximum DB version and rollback class;
one migration lease exists system-wide;
backup is mandatory before destructive or data-rewriting migration;
forward-compatible additive migration is preferred;
field/status rewrites run as resumable operation jobs with checkpoints;
no agent session can start while a required blocking migration is incomplete;
irreversible migration requires explicit admin command and confirmation token;
Governor stores migration receipt and schema snapshot.
```

Migrations are compiled into the Governor binary as audited `.surql` resources. SurrealKit may be used by maintainers to inspect or author migrations, but it is not a production runtime dependency and does not receive independent write authority.

## 7.7. Change notification and outbox

Governor is the sole normal writer, so hot invalidation comes from the transaction outbox rather than polling. V1 does not depend on SurrealDB changefeeds; the immutable event journal plus transactional outbox are the recovery/audit mechanism. Changefeeds are reserved for a later measured ADR and agents never consume raw DB changes.

```text
transaction commits domain mutation + outbox row;
OutboxDispatcher publishes local resource/job notifications;
subscriber lag never blocks commit;
undelivered outbox rows remain queryable and are compacted after retention;
changefeed/outbox mismatch triggers projection-health incident.
```


## 7.8. Critical record shapes that Codex must not invent

### `ActiveDecisionState`

```yaml
ActiveDecisionState:
  task_id:
  state_revision:
  current_plan:
  why_current_plan:
  completed_work_item_ids:
  paused_path_ids:
  killed_path_ids:
  open_blocker_ids:
  next_required_boundary:
  next_best_probe_or_action:
  revision_triggers:
  updated_by_session_id:
  updated_at:
```

There is one current row per task plus immutable transition events. Updating it requires the expected `state_revision`; a stale agent receives a conflict rather than overwriting the active plan.

### `UnknownItem` and `HypothesisCard`

```yaml
UnknownItem:
  unknown_id:
  task_id:
  question:
  why_material:
  blocks_action_kinds:
  cheapest_probe:
  status: open | resolved | accepted_risk | obsolete
  evidence_refs:

HypothesisCard:
  hypothesis_id:
  task_id:
  proposition:
  mechanism:
  support_refs:
  counterevidence_refs:
  predicted_observable:
  discriminative_probe_ref:
  kill_criteria:
  status: candidate | supported | refuted | parked | promoted_to_claim
```

A hypothesis cannot enter `verified_now`. Promotion creates or updates a separate ClaimCard through a verifier-backed mutation.

### `DiagnosticEvent`

```yaml
DiagnosticEvent:
  diagnostic_id:
  project_id:
  task_id:
  tool_id:
  tool_version:
  config_hash:
  branch:
  commit:
  dirty_state_hash:
  file_path:
  byte_or_line_range:
  severity:
  rule_id:
  message:
  raw_observation_ref:
  observed_at:
  freshness_rule:
  status: active | resolved | stale | suppressed
```

Deduplication key:

```text
BLAKE3(tool_id || tool_version || config_hash || commit || dirty_state_hash
       || canonical_path || range || rule_id || normalized_message)
```

Diagnostics remain tool observations, not model-authored facts. Any model explanation is stored separately as a candidate.

### `ProbeEnvelope`

```yaml
ProbeEnvelope:
  probe_id:
  task_id:
  hypothesis_or_unknown_ref:
  question:
  expected_observable:
  adapter_and_operation:
  execution_scope:
  safety_preconditions:
  actual_observation_refs:
  expected_vs_actual_delta:
  resulting_status_changes:
  next_decision:
```

The expected observable is fixed before execution to prevent retrospective rationalization.

### `HandoffArtifact`

```yaml
HandoffArtifact:
  handoff_id:
  task_id:
  boundary_kind: compaction | interruption | session_stop | branch_switch
  active_decision_state_ref:
  current_truth_refs:
  exact_atom_refs:
  current_diff_ref:
  pending_verifier_refs:
  forbidden_resumption_refs:
  next_action:
  revision_fence:
  created_at:
```

It is a state checkpoint, not an authoritative prose summary. Resume always revalidates branch, diff, runtime and revisions.

### `FinishAttempt`, `FinishDecision` and `PolicyDecision`

```yaml
FinishAttempt:
  finish_attempt_id:
  task_id:
  session_id:
  completion_proof_ref:
  requested_status:
  submitted_at:

FinishDecision:
  finish_decision_id:
  finish_attempt_id:
  verdict:
  uncovered_acceptance_items:
  failed_or_missing_verifiers:
  material_unknowns:
  next_allowed_action:
  policy_snapshot_id:
  decided_at:

PolicyDecision:
  policy_decision_id:
  operation_id:
  principal_ref:
  policy_snapshot_id:
  rule_ids:
  input_hash:
  verdict:
  reason_codes:
  human_approval_ref:
  decided_at:
```

Attempts and decisions are immutable. A new proof creates a new attempt; previous denials are not overwritten.

## 7.9. Core memory and proof records

### `SourceSnapshot`, `EvidenceAtom` and `ToolObservation`

```yaml
SourceSnapshot:
  source_snapshot_id:
  project_id:
  source_kind: file | code | command | log | document | web | human | external_agent | artifact
  canonical_locator:
  source_version_or_commit:
  content_checksum:
  captured_at:
  capture_tool_id:
  capture_tool_version:
  scope:
  taint:
  blob_ref:

EvidenceAtom:
  evidence_id:
  source_snapshot_id:
  kind: code_span | config_value | command_output | log_line | diagnostic | document_clause | user_correction | artifact_observation
  exact_text_or_blob_ref:
  exact_anchor:
  anchor_checksum:
  normalized_subject_key:
  observed_at:
  branch_commit_environment:
  authority:
  taint:
  lifecycle_status:

ToolObservation:
  observation_id:
  tool_id:
  tool_version:
  normalized_input_hash:
  input_scope:
  started_at:
  ended_at:
  exit_or_protocol_status:
  output_excerpt_or_blob_ref:
  side_effect_manifest:
  evidence_atom_refs:
  taint:
```

The exact source payload is immutable. Re-parsing creates a new Parse/ToolObservation and new atoms; it does not silently alter old evidence.

### `ClaimCard`

```yaml
ClaimCard:
  claim_id:
  project_id:
  subject_key:
  proposition:
  scope:
  epistemic_status: observed | supported | verified | contested | stale | superseded | rejected | unknown
  epistemic_grade: direct | inferential | weak | none
  support_refs:
  counterevidence_refs:
  verification_refs:
  valid_from:
  valid_until:
  known_from:
  known_until:
  transaction_from:
  transaction_until:
  branch_commit_environment:
  revalidation_handle:
  supersedes_refs:
  lifecycle_status:
  visibility:
  recall_priority:
```

Rules:

```text
`verified` requires at least one active supports edge and one current registered VerificationRun;
no summary/model output upgrades status by itself;
branch/env/version mismatch demotes use to historical or requires revalidation;
supersession preserves history and removes the old claim from current-truth selection;
claims with missing provenance remain weak legacy recall.
```

### `FailureFingerprint`

```yaml
FailureFingerprint:
  failure_id:
  project_id:
  task_class:
  trigger_signature:
  failed_action_signature:
  affected_paths_symbols_entities:
  violated_invariant:
  observed_failure_refs:
  causal_explanation_status:
  why_it_failed_candidate_or_verified_ref:
  do_not_repeat_until:
  reopen_conditions:
  required_discriminative_check:
  last_activated_at:
  prevented_repeat_count:
  false_activation_count:
  lifecycle_status:
```

A fingerprint blocks only within matching scope and only while reopen conditions remain unsatisfied. Its activation is itself audited so overbroad negative memory can be corrected.

### `SkillCard`

```yaml
SkillCard:
  skill_id:
  name:
  purpose:
  applies_when:
  does_not_apply_when:
  required_inputs:
  ordered_steps:
  required_tools_and_capabilities:
  expected_outputs:
  verification_plan:
  stop_conditions:
  known_failure_modes:
  rollback_or_recovery:
  source_trace_refs:
  replay_result_refs:
  success_count:
  failure_count:
  last_verified_at:
  version:
  lifecycle_status: candidate | active | stale | archived | quarantined
  owner:
```

Only active skills may be offered in normal recall. Promotion requires proven transfer and an explicit `does_not_apply_when` boundary; a successful one-off trace is not a skill.

### `ActionContract`, `VerificationRun` and `CompletionProof`

```yaml
ActionContract:
  action_contract_id:
  task_id:
  understanding_proof_ref:
  preconditions:
  read_set:
  write_set:
  preserved_invariants:
  expected_observation:
  postconditions:
  verifier_ref:
  blast_radius:
  rollback_or_compensation:
  risk_tier:

VerificationRun:
  verification_run_id:
  verifier_id:
  verifier_version:
  config_hash:
  task_id:
  project_scope:
  branch_commit_dirty_state:
  input_artifact_refs:
  expected_observation:
  actual_observation_refs:
  status: passed | failed | inconclusive | not_run | stale
  started_at:
  finished_at:
  residual_uncertainty:
  raw_tool_observation_ref:

CompletionProof:
  completion_proof_id:
  task_id:
  packet_id:
  acceptance_item_results:
  changed_artifact_refs:
  verification_run_refs:
  checks_not_run_and_why:
  remaining_unknown_refs:
  rollback_or_followup:
  requested_status:
```

`VerificationRun` is authoritative only for verifier IDs registered by the project profile and only for the exact branch/commit/config/artifact scope it observed.

### `ContextPacket` manifest

```yaml
ContextPacket:
  packet_id:
  task_id:
  profile:
  revision_fence:
  policy_snapshot_id:
  task_frame_ref:
  current_truth_refs:
  active_continuity_refs:
  causal_slice_refs:
  negative_memory_refs:
  exact_atom_refs:
  unknown_refs:
  allowed_action_summary:
  verifier_refs:
  suppressed_candidate_refs_and_reasons:
  expansion_resource_uris:
  structured_bytes:
  rendered_bytes:
  created_at:
  invalidated_at:
```

The manifest is canonical; rendered Markdown is a projection and may be regenerated without changing the packet identity or epistemic status.

---

# 8. Canonical write path

## 8.1. Write authority

No agent, plugin hook, adapter or maintenance job receives SurrealDB credentials or submits SurrealQL.

The only normal mutation route is:

```text
Agent/model/tool
  -> typed Governor command
  -> identity/scope validation
  -> semantic validation
  -> policy/admission gates
  -> durable staging in ControlWal
  -> one bounded WriterActor over ControlWal
  -> one SurrealDB transaction
  -> canonical receipt + revision
  -> MCP/IPC response
```

This rule is absolute. A direct DB write is an administrative incident, not a supported shortcut.

## 8.2. Agent-facing mutation language

Agents write **semantic commands**, not database rows. The command enum is closed and versioned.

```text
EvidenceIngest
ToolObservationRecord
DiagnosticBatchRecord
UnknownRecord
UnknownResolve
HypothesisPropose
HypothesisUpdate
ClaimPropose
ClaimSupport
ClaimContest
ClaimVerify
ClaimSupersede
DecisionRecord
FailureRecord
ActiveDecisionTransition
TaskStateTransition
WorkItemUpdate
ProbeRecord
HandoffRecord
VerificationRecord
ContextCargoRecord
AgentResultRecord
SkillCandidatePropose
LifecycleRequestCreate
ExternalReviewRecord
CompletionProofSubmit
```

New command variants require a schema migration and an explicit policy owner. Do not add a generic `RawRecordUpsert` escape hatch.

Command authority is fixed:

```text
any scoped agent may propose evidence, unknowns or hypotheses;
only the active controller may transition ActiveDecisionState;
only registered diagnostic/verifier adapters may create authoritative DiagnosticEvent/VerificationRun observations;
only a verifier role or deterministic verifier adapter may request ClaimVerify;
workers may submit candidate results but cannot mutate task completion;
CompletionProofSubmit always creates an immutable FinishAttempt evaluated by FinishGate;
maintenance roles may propose lifecycle/skill changes but cannot directly promote them.
```

## 8.3. `MemoryWriteEnvelope`

```yaml
MemoryWriteEnvelope:
  schema_version: "1"
  write_id: uuid_v7
  submitted_at:

  principal:
    agent_id:
    session_id:
    role:
    model_route:

  scope:
    project_id:
    task_id:
    work_item_id:
    branch:
    commit:
    environment:

  consistency:
    expected_memory_revision:
    expected_task_revision:
    conflict_policy: reject | append_candidate | create_conflict_set

  authority:
    requested_effect: candidate | supported | verified | control_state
    work_lease_id:
    work_lease_epoch:
    action_lease_id:
    action_lease_epoch:
    approval_ref:

  commands:
    - kind:
      payload:

  source_refs:
  exact_anchor_refs:
  blob_refs:
  verification_refs:

  taint:
  lifecycle:
  client_metadata:
```

Rules:

```text
one envelope belongs to exactly one project;
one envelope may contain multiple commands only when they form one atomic semantic change;
one envelope may not mutate two projects;
write_id is globally unique and idempotent;
caller-supplied status cannot exceed caller authority;
external model output defaults to candidate;
verified status requires admissible VerificationRun references;
control_state requires controller/admin authority and matching task revision.
```

Cross-project knowledge is represented by a scoped reference or copied candidate with provenance. V1 intentionally forbids cross-project atomic transactions; this avoids distributed locks and hidden coupling.

## 8.4. Admission algorithm

The `WriteAdmissionService` executes these steps in order:

```text
1. Authenticate principal and load immutable AgentSession.
2. Validate JSON/Serde schema and envelope size.
3. Resolve project/task/work-item scope.
4. Verify that branch/commit/environment claims are not fabricated:
   compare with registered project state or require candidate status.
5. Check capability profile for every command variant.
6. Canonicalize paths, identifiers, timestamps and source handles.
7. Validate evidence and verification references exist and are visible to the principal.
8. Apply taint propagation.
9. Apply epistemic ceiling:
   candidate worker cannot submit verified truth;
   memory recall cannot grant authority;
   model rationale cannot count as evidence.
10. Apply conflict preconditions against requested revisions.
11. Apply lifecycle and retention rules.
12. Produce a deterministic `MutationPlan`.
13. Hash the canonical envelope and plan.
14. Persist `PendingWrite` in redb before acknowledging acceptance.
15. Assign project sequence and writer lane.
```

No LLM call occurs inside admission. If semantic interpretation is missing, the request is rejected with `NEEDS_REASONING_CANDIDATE`; a separate ReasoningJob may create a new candidate envelope.

## 8.5. Durable staging in redb

The staging transaction stores:

```yaml
PendingWrite:
  write_id:
  envelope_hash:
  canonical_envelope:
  project_id:
  project_sequence:
  lane_id:
  state: staged
  attempt_count: 0
  next_attempt_at:
  received_at:
  caller_waiter_ids:
```

The redb write is intentionally tiny. Large payloads must already be in BlobStore and are referenced by hash.

The current production v1 runtime uses one bounded `WriterActor::channel` over the
durable `ControlWal` and one `CanonicalStore`. It admits one deterministic envelope at
a time, preserves project sequence/idempotency, and returns the per-write canonical
receipt. This is the implemented safety baseline; it does not yet claim multiple
writer lanes or group commit.

The following `ControlWalActor` group-commit design is the target scale-out contract,
not current implementation:

```text
drain immediately available submissions for at most 1 ms or 64 envelopes;
validate total encoded batch bytes against the WAL transaction cap;
reserve per-project sequences and write all staging records in one redb transaction;
acknowledge each caller only after that redb transaction commits;
under low load, flush the first request immediately rather than waiting for a full batch.
```

This batches local fsync/transaction overhead without coupling canonical SurrealDB commits: each envelope still receives its own DB transaction and receipt.

Acknowledgement modes:

| Mode | Meaning |
|---|---|
| `commit` | wait for canonical DB receipt up to caller deadline |
| `accepted` | return operation handle after durable staging |
| `fire_and_observe` | maintenance-only; no interactive waiter |

If `commit` exceeds its deadline, return `ACCEPTED_PENDING`, never a false failure. The caller can read the operation resource or poll the MCP task.

## 8.6. Project writer lanes (target scale-out)

Governor remains the sole application writer. The lane topology below is reserved for
a future measured throughput need; production v1 intentionally uses the single bounded
WriterActor described above.

```text
ControlWalActor
  -> maintains one durable sequence cursor per project in redb
  -> initializes that cursor from canonical ScopeState.last_project_sequence
  -> atomically reserves the next monotonically increasing project_sequence
  -> stable_lane = blake3(project_id) mod configured_lane_count

WriterCoordinator
  -> N bounded lane workers
  -> each lane owns a map of per-project FIFO queues
  -> a fair ready-project scheduler selects eligible queue heads
  -> one in-flight transaction per project
  -> independent projects may execute concurrently, including projects sharing one lane
```

Default:

```text
writer_lanes = min(4, logical_cpu_count)
max_db_transactions = writer_lanes
```

Hard rules:

```text
same project commits in project_sequence order;
transaction precondition requires ScopeState.last_project_sequence == project_sequence - 1;
a retryable failure blocks later writes for that project only, not other projects sharing its lane;
the lane scheduler uses bounded round-robin/ready-time fairness and never sleeps on one project's retry timer;
a deterministic rejection creates a rejected receipt and releases the next sequence;
a dead-lettered write creates an explicit sequence-gap event before later writes continue;
lane count changes require a drained restart;
no lock is held while waiting for an external tool or model.
```

Why project lanes rather than one global writer:

```text
causal ordering is normally project-local;
independent projects should not block each other;
SurrealDB server already provides transaction isolation;
agent concurrency becomes bounded and predictable;
no CRDT or distributed consensus is required for one local Governor daemon.
```

## 8.7. Write execution algorithm

For each next eligible `PendingWrite`:

```text
1. Re-read current `ScopeState` and idempotency receipt.
2. Verify `ScopeState.last_project_sequence == pending.project_sequence - 1`; otherwise pause the project queue and reconcile the missing/duplicate sequence.
3. If receipt for write_id exists:
     mirror it into redb;
     complete waiters;
     mark staged record complete;
     stop.
4. Revalidate revision preconditions and policy version.
5. Convert MutationPlan into named parameterized SurrealQL operations.
6. Begin one SurrealDB transaction.
7. Apply typed materialized records and relation edges.
8. Persist supported lossless `canonical_record` product projections.
9. Increment `scope_head` revisions and project sequence.
10. Write the canonical `write_receipt` bound to the envelope input hash.
11. Commit the parameterized SurrealDB operation.
12. Mirror the receipt and mark the WAL entry committed.
13. Notify the waiting MCP/IPC caller.
```

A single envelope is the atomic unit. V1 does not combine unrelated envelopes into one
DB transaction. Event hash chains, a notification outbox, group commit and parallel
writer lanes remain explicitly versioned target work.

## 8.8. Receipt model

```yaml
WriteReceipt:
  write_id:
  operation_id:
  project_id:
  project_sequence:
  status: committed | rejected | retrying | dead_letter | cancelled
  commit_id:
  memory_revision_before:
  memory_revision_after:
  task_revision_before:
  task_revision_after:
  applied_command_ids:
  emitted_event_ids:
  projection_ids:
  policy_version:
  schema_version:
  committed_at:
  error_code:
  exact_error_ref:
  retryable:
```

A successful MCP response without a canonical `WriteReceipt` is forbidden for a durable mutation.

## 8.9. Retry and dead-letter policy

Classify failures, do not retry all errors.

```text
transient DB unavailable / timeout:
  exponential backoff with full jitter;
  bounded attempts and bounded outage age;
  project lane remains ordered.

revision conflict:
  reject immediately or create ConflictSet according to envelope policy.

schema/policy/permission/evidence failure:
  deterministic reject; no retry.

unknown commit outcome:
  query write_receipt(write_id) before retry.

persistent internal error:
  dead-letter + IncidentRecord + exact blob/log reference.
```

Default retry schedule:

```text
100 ms, 250 ms, 500 ms, 1 s, 2 s, 5 s, 10 s, then outage policy.
```

The queue has byte and item limits. Once exceeded, new writes are rejected with `STORAGE_BACKPRESSURE`; Governor never grows an unlimited outage backlog.

## 8.10. Recovery inbox

The legacy `.eliot/inbox` remains only for:

```text
migration import;
emergency manual recovery;
offline producer compatibility.
```

Accepted recovery file format is a signed/hashed JSON `MemoryWriteEnvelope`, not arbitrary `.surql`.

```text
write *.json.tmp
fsync
atomic rename to *.json
Governor imports into ControlWal
file moves to applied/rejected/dead-letter with receipt sidecar
```

Raw `.surql` import is admin-only and requires maintenance mode.

---

# 9. Canonical read path

## 9.1. Agents never browse tables

The read API exposes task/state/evidence concepts, not database queries.

```text
L0 — handles/previews
L1 — current scoped state
L2 — exact evidence/relations
L3 — compiled understanding packet
L4 — audit/replay/evidence pack
```

All responses contain provenance, scope, revision and truncation metadata.

## 9.2. Read consistency modes

```yaml
ReadConsistency:
  mode: eventual | at_least_revision | stable_scope
  min_memory_revision:
  min_task_revision:
  wait_timeout_ms:
```

Semantics:

| Mode | Use |
|---|---|
| `eventual` | cheap previews where a small lag is harmless |
| `at_least_revision` | read-your-write after a receipt |
| `stable_scope` | packet/current-truth construction |

`at_least_revision` waits on ScopeHeadCache notification, not polling, then reads the DB.

## 9.3. Stable-scope fence algorithm

To compile a coherent packet without a long global lock:

```text
1. Read ScopeState as fence A.
2. Execute named read queries for task, truth, memory and coordination state.
3. Read ScopeState as fence B.
4. If relevant revisions match, result is coherent.
5. If they differ, retry once.
6. If they change again, return BUSY_STATE_CHURN or a clearly marked stale preview.
```

V1 always uses this revision-fence contract for packet/current-state assembly. Codex must not invent a separate read-consistency path. A future DB-transaction optimization may be introduced only through an ADR after equivalent semantics and latency are measured.

## 9.4. L0 preview

`recall` first returns small handles:

```yaml
RecallHit:
  handle:
  kind:
  title_or_proposition:
  status:
  scope_fit:
  freshness:
  authority:
  decision_delta_hint:
  exact_anchor_count:
  verification_count:
  relation_preview:
  project_revision:
```

Default maximum: 12 hits. No raw document body, giant code span or full trace.

Candidate generation order:

```text
1. direct ID/known handle;
2. exact subject/entity/symbol/path match;
3. current task and continuity relations;
4. lexical full-text match;
5. graph-neighborhood expansion;
6. optional vector/hybrid shortlist only after enabled by benchmark.
```

## 9.5. L1 current state

`CurrentStateView` is deterministic and compact:

```yaml
CurrentStateView:
  project:
  task:
  acceptance:
  active_plan:
  completed_items:
  open_items:
  blockers:
  killed_paths:
  work_leases:
  branch_commit_environment:
  verified_now:
  assumed_now:
  conflicted_now:
  do_not_use_as_current_truth:
  recent_failures:
  next_required_boundary:
  revisions:
  freshness:
```

The view does not repeat evidence payloads. Every item has an expansion handle.

## 9.6. L2 exact atoms

Fetch by handles, never by “give all evidence”.

```yaml
EvidencePackSlice:
  requested_handles:
  evidence_atoms:
  exact_anchors:
  supporting_relations:
  counterevidence:
  verification_runs:
  supersession_chain:
  blob_handles:
  omitted_count:
  continuation_cursor:
```

Default response budget:

```text
64 KiB structured JSON;
200 exact atoms maximum;
large content becomes BlobRef/resource URI;
continuation cursor is opaque and revision-bound.
```

## 9.7. L3 packet

The packet compiler returns:

```text
canonical structured packet JSON;
rendered Markdown resource;
DecisionLocalitySuffix;
ContextProvenanceReport;
packet_id and revision fence;
expansion resources.
```

Tool output returns the compact structured representation and resource URI. The full rendered packet is read only when needed.

## 9.8. L4 audit and replay

L4 is never auto-loaded into a normal prompt. It includes:

```text
full evidence and counterevidence graph;
retrieval rank trace;
write receipts;
state-transition history;
packet cargo receipts;
agent messages and results;
verifier details;
finish decision;
policy/config snapshots;
incident/recovery details.
```

## 9.9. Revision-aware cache

V1 uses two explicit bounded caches only:

```text
ScopeHeadCache:
  project_id -> revisions/last commit/notification channel.

PacketCache:
  key = task_id + memory_revision + truth_revision + task_revision
        + policy_revision + packet_profile + budget_class.
```

Implementation:

```text
HashMap under parking_lot::RwLock;
strict item/byte cap;
LRU timestamps maintained explicitly;
revision-key invalidation rather than TTL guessing;
no third-party distributed cache;
no cached answer without dependency revisions.
```

Evidence payloads are not copied into the cache; packets contain handles and small exact atoms.

## 9.10. MCP resources

Canonical resource URI forms:

```text
eliot://project/{project_id}/state
eliot://task/{task_id}/packet/{packet_id}
eliot://task/{task_id}/handoff/latest
eliot://evidence/{evidence_id}
eliot://claim/{claim_id}/evidence
eliot://job/{job_id}/result
eliot://agent/{session_id}/mailbox
eliot://report/task/{task_id}/latest
eliot://report/health/latest
eliot://blob/{blake3_hash}
```

Resources support list/read where appropriate. Subscriptions are allowed for:

```text
task state;
mailbox;
operation job status;
packet invalidation;
health state.
```

Subscriptions are notifications, not authority. Clients must still read the new version.

## 9.11. Response rendering

Every operation has one canonical structured response. Optional renderers:

```text
JSON — machine canonical;
Markdown — Codex/human view;
compact text — hook context injection only.
```

Rendering never changes semantic status. A Markdown report is a projection of canonical JSON and includes its source record IDs and revision.

---

# 10. Cognitive Engine

## 10.1. Purpose

Governor does not generate intelligence independently. It externalizes the cognitive control functions that Codex cannot reliably preserve inside a conversation:

```text
attention;
working-state continuity;
truth-status separation;
causal project reconstruction;
negative memory;
action admissibility;
reality testing;
completion proof;
learning and forgetting.
```

The engine consists of deterministic components plus explicit typed requests for model reasoning.

## 10.2. Components

```text
TaskFramer
CurrentTruthResolver
MemoryAdmissionService
NegativeMemoryGate
ContextCompiler
CodeCortex
DiagnosticNormalizer
CognitiveGate
ActionGate
VerificationPlanner
FinishGate
MemoryInfluenceTracker
ReasoningBroker
SleepCurator (cold path)
```

## 10.3. Task framing

A task becomes active only after a valid `TaskContract` exists.

```yaml
TaskContract:
  task_id:
  project_id:
  user_goal:
  normalized_goal:
  scope:
  non_goals:
  acceptance_items:
  expected_artifacts:
  risk_tier:
  allowed_paths:
  forbidden_paths:
  stop_conditions:
  verifier_requirements:
  owner_session_id:
  policy_snapshot_id:
```

Codex may propose normalization and acceptance decomposition. Governor validates that no user constraint disappeared and stores both original and normalized forms.

## 10.4. CurrentTruthResolver

Inputs:

```text
registered project branch/commit/environment;
current code/runtime/tool observations;
active claims and supersession chains;
source authority rules;
valid/known/transaction time;
verification freshness policy.
```

Deterministic resolution order:

```text
1. exact live observation in matching branch/env;
2. current verified claim with unexpired verifier;
3. supported claim in matching scope;
4. remembered/derived candidate;
5. unresolved conflict/unknown.
```

Output categories are immutable:

```text
verified_now;
supported_now;
assumed_now;
conflicted_now;
stale_or_superseded;
do_not_use_as_current_truth;
required_probe.
```

A model may explain a conflict but may not select the current value when a deterministic freshness rule applies.

## 10.5. Memory admission

Retrieval candidates are scored before packet inclusion.

```text
admission_score =
    exact_scope_fit
  + current_task_relation
  + evidence_strength
  + freshness
  + authority
  + expected_decision_delta
  + negative_memory_value
  + verifier_value
  - stale_risk
  - contradiction_risk
  - taint_risk
  - token_cost
  - repetition
  - distraction_cost
```

The formula is an ordered policy with normalized integer features, not a hidden floating-point ML model in v1. The result is inspectable as `FusedRankTrace`.

Admission decisions:

```text
include_exact;
include_handle;
include_with_warning;
require_revalidation;
suppress;
quarantine.
```

## 10.5.1. NegativeMemoryGate

Negative memory is checked before positive procedures or analogous fixes are admitted.

Inputs:

```text
proposed action kind and normalized write-set;
CodeCortex files/symbols/APIs/invariants;
active FailureFingerprints in matching project/task class;
new evidence and reopen conditions.
```

Algorithm:

```text
1. Retrieve exact and structural failure matches; embedding similarity alone cannot block an action.
2. Compare trigger pattern, failed action pattern, affected entities and violated invariant.
3. If a fingerprint matches and reopen conditions are unmet: BLOCK or REQUIRE_PROBE.
4. If new discriminative evidence satisfies reopen conditions: create a reopen receipt and allow normal CognitiveGate evaluation.
5. Put the blocking failure and required check into DecisionLocalitySuffix.
6. Record whether the fingerprint prevented repetition or was a false activation.
```

Outputs:

```text
NO_MATCH;
WARN_SIMILAR;
REQUIRE_DISCRIMINATIVE_PROBE;
BLOCK_REPEATED_FAILURE;
REOPENED_WITH_EVIDENCE.
```

## 10.6. ContextCompiler

Compilation stages:

```text
1. Load TaskContract and pinned policy snapshot.
2. Resolve stable current state and current truth.
3. Load active continuity, work items, leases and killed paths.
4. Run/refresh CodeCortex if code understanding is required and stale.
5. Retrieve negative memory before positive procedures.
6. Retrieve decisions/procedures/evidence by decision delta.
7. Apply admission and token/payload budgets.
8. Build causal slice and invariant set from verified handles.
9. Add unknowns and required discriminative probes.
10. Select minimal tool/capability hotset.
11. Add allowed next actions, verifier and stop conditions.
12. Render DecisionLocalitySuffix last.
13. Persist packet manifest and ContextCargoReceipt expectations.
```

Packet ordering is fixed:

```text
current task and acceptance;
current truth;
causal bridge;
active continuity;
negative memory;
exact atoms;
unknowns;
action boundary;
verifier;
DecisionLocalitySuffix.
```

No generic model-written summary is inserted ahead of current truth.

## 10.6.1. DiagnosticNormalizer

Diagnostics from VS Code/LSP, project scripts, linters, tests and external analyzers are normalized deterministically before they influence truth or completion.

```text
raw adapter result
-> preserve raw output as ToolObservation/BlobRef
-> parse tool-native fields
-> canonicalize path/range/severity/rule
-> attach tool version, config hash, branch/commit/dirty state
-> deduplicate into DiagnosticEvent
-> map configured diagnostic classes to verifier or blocker semantics
```

Rules:

```text
an LLM never rewrites the diagnostic message into the canonical event;
parser failure preserves raw output and returns PARSE_INCOMPLETE;
resolved diagnostics are retained historically but excluded from active packets;
stale config/commit diagnostics cannot satisfy a current verifier;
workspace-wide floods are summarized as counts plus exact handles, never dumped into context.
```

## 10.7. ReasoningBroker

Semantic operations that require a model are explicit jobs:

```text
CausalSliceDraft
ClaimExtractionCandidate
ConflictExplanationCandidate
TaskDecompositionCandidate
ProcedureCandidate
ResearchDistillationCandidate
DreamCandidate
```

A `ReasoningJob` contains:

```yaml
ReasoningJob:
  job_id:
  requested_capability:
  input_handle_set:
  output_schema:
  allowed_agent_roles:
  preferred_route:
  budget:
  deadline:
  candidate_only: true
```

Routes:

```text
primary controller Codex session;
registered Codex subagent;
Antigravity/Gemini worker;
other approved MCP worker.
```

The result must cite input handles. Governor validates shape, scope, taint and authority, then stores it as a candidate. There is no hidden background LLM inside the daemon.

## 10.8. UnderstandingProof handshake

For a nontrivial mutation, Codex must reconstruct the packet into a concise typed proof.

```yaml
UnderstandingProof:
  proof_id:
  task_id:
  packet_id:
  packet_revisions:
  proposed_action_kind:

  goal:
    restated_goal:
    acceptance_refs:

  current_truth_used:
    verified_refs:
    assumption_refs:
    conflict_refs:
    prohibited_stale_refs:

  causal_bridge:
    domain_concept:
    module_boundary:
    file_symbol_config_hops:
    control_flow_hops:
    data_flow_hops:
    state_flow_hops:
    runtime_observable:
    verifier_ref:

  invariants:
  negative_memory_checked:
  material_unknowns:
  expected_observation:
  proposed_write_set:
  rollback_or_compensation:
```

This is not a request for private chain-of-thought. It is an externally verifiable action model with evidence handles.

## 10.9. CognitiveGate

The gate checks:

```text
packet is current enough for the risk tier;
all cited handles exist and are visible;
verified refs are actually verified/current;
stale refs are not used as current truth;
causal bridge reaches a runtime/artifact observable;
write-set is within TaskContract and leases;
load-bearing hops have evidence or are labeled unknown;
negative memory was checked;
required external APIs were verified through truth adapters;
verifier exists and is executable;
material unknowns are not concealed.
```

Decisions:

```text
ALLOW_READ_ONLY
ALLOW_ACTION_LEASE
REQUIRE_PROBE
REQUIRE_PACKET_REFRESH
REQUIRE_HUMAN_APPROVAL
BLOCK
```

An allowed proof produces a short-lived `ActionLease`:

```yaml
ActionLease:
  action_lease_id:
  lease_epoch:
  holder_session_id:
  task_id:
  work_item_id:
  packet_revision_fence:
  allowed_action_kinds:
  allowed_read_set:
  allowed_write_set:
  max_tool_calls:
  issued_at:
  expires_at:
  policy_snapshot_id:
  required_verifier:
  state: active | consumed | revoked | expired
```

The monotonic `lease_epoch` is a fencing token. Every mutating tool authorization and resulting semantic write must present the current epoch; an old process cannot continue after revocation merely because it still holds an old serialized lease.

## 10.10. Cognitive risk tiers

| Tier | Example | Required cognition |
|---|---|---|
| R0 | read/search/report | no proof; scope and taint still enforced |
| R1 | one-file reversible edit with exact owner | compact proof + verifier |
| R2 | multi-file behavior/API/state change | fresh CodeCortex + full proof |
| R3 | destructive, external side effect, policy/schema/security | full proof + explicit human/admin approval |
| R4 | forbidden by policy | never authorized |

Risk is classified from executable impact, not from the model's explanation.

## 10.11. ActionGate

Before a mutating tool call:

```text
1. Match tool and input against ToolProfile.
2. Resolve canonical paths/resources.
3. Compute read-set/write-set/side effects.
4. Verify ActionLease covers the operation and its fencing epoch is current.
5. Verify worktree/work-item lease IDs and fencing epochs.
6. Verify current revisions still satisfy the lease.
7. Enforce ChangeBudget and forbidden paths.
8. Return allow/deny/approval requirement.
```

The lease is consumed or updated after the tool observation. It cannot authorize arbitrary future calls.

## 10.12. VerificationPlanner and FinishGate

A task cannot finish from prose. `CompletionProof` maps every acceptance item to evidence and a verifier.

```yaml
CompletionProof:
  task_id:
  packet_id:
  acceptance_results:
    - acceptance_item_id:
      status: passed | failed | blocked | waived
      evidence_refs:
      verification_refs:
      residual_uncertainty:
  changed_artifacts:
  checks_run:
  checks_not_run_and_why:
  remaining_unknowns:
  rollback_or_followup:
  requested_status:
```

Finish outcomes:

```text
DONE_VERIFIED
PARTIAL_PROGRESS
BLOCKED_BY_UNKNOWN
FAILED_VERIFIER
DEGRADED_NO_PROOF
UNSAFE_TO_FINISH
```

Only `DONE_VERIFIED` closes the task as completed.

## 10.13. Memory influence tracking

Governor never claims to know hidden model reasoning. It records observable influence:

```text
memory handle cited in UnderstandingProof;
handle included in ActionContract;
handle used to select/skip a tool;
handle connected to a verifier;
handle cited in CompletionProof;
handle explicitly rejected as stale/irrelevant.
```

`ContextCargoReceipt` updates future admission:

```text
used_and_changed_action;
used_for_verification;
seen_but_not_used;
suppressed_as_stale;
loaded_repeatedly_without_delta.
```

Repeated low-delta cargo is demoted from hot packets.

---

# 11. CodeCortex: project understanding subsystem

## 11.1. Contract

CodeCortex is an orchestrator over truth adapters. It does not replace the code index, LSP or diagnostics and does not duplicate the full code graph into SurrealDB.

Its output must establish this bridge:

```text
human intent
-> domain concept
-> project/module boundary
-> files/symbols/config
-> control/data/state path
-> runtime/artifact behavior
-> verifier
```

## 11.2. Adapter order

Exact-first default route:

```text
1. GitStateAdapter
2. ProjectProfile/TOC/manifest adapter
3. CodeGraphAdapter (`project_memory` / codebase-memory-mcp)
4. RipgrepAdapter
5. AstGrepAdapter
6. LspAdapter / VS Code MCP
7. DomainApiAdapter (`wow_api` for WoW)
8. DiagnosticsAdapter
9. VerifierMapAdapter
10. targeted docs adapter only for unresolved external facts
```

Broad natural-language graph search is fallback, not step 1.

## 11.3. Planning algorithm

```text
1. Capture branch, commit, dirty diff and changed paths.
2. Extract explicit paths, symbols, APIs and domain terms from TaskContract.
3. Resolve project profile and load-order/manifest boundaries.
4. Query exact files/symbols in code graph.
5. Expand only typed edges required for the question:
     callers, callees, reads, writes, member_of, depends_on.
6. Cap graph depth and fan-out; preserve expansion handles.
7. Verify definitions/references through LSP where available.
8. Use ripgrep for exact text/registration/config anchors.
9. Use ast-grep for structural patterns and unsafe broad matches.
10. Verify external/domain APIs through authoritative adapter.
11. Collect file-local diagnostics and mapped deterministic checks.
12. Identify runtime observable and executable verifier.
13. Record unknown hops and the cheapest probe for each.
14. Build `CodeCortexReport` with exact provenance.
```

Default graph limits:

```text
initial roots: 12
hop depth: 2
max nodes in report: 80
max edges in report: 160
full graph payload: never
```

A deeper query requires an explicit job and returns handles, not a prompt dump.

## 11.4. `CodeCortexReport`

```yaml
CodeCortexReport:
  report_id:
  project_id:
  task_id:
  branch:
  commit:
  dirty_state_hash:
  generated_at:

  domain_concept:
  architecture_boundary:
  module_owners:
  entrypoints:
  concept_symbol_links:
  execution_paths:
  data_flows:
  state_transitions:
  external_api_surfaces:
  configuration_and_load_order:
  invariants:
  blast_radius:
  diagnostics:
  runtime_observables:
  verifier_map:
  known_failures:
  unknown_hops:
  exact_evidence_handles:
  adapter_trace:
  freshness_rules:
```

## 11.5. Freshness and invalidation

A code-understanding artifact is scoped to:

```text
project + branch + commit + dirty_state_hash + adapter versions.
```

It becomes stale when:

```text
commit changes in affected paths;
dirty diff touches a referenced file;
manifest/load order changes;
LSP/project index revision changes materially;
domain API documentation version changes;
verifier configuration changes.
```

Governor may reuse unaffected sections by dependency handles. It may not silently present a stale report as current.

## 11.6. What is written to canonical memory

Write only decision-useful derived artifacts:

```text
ProjectCapsule
ModuleCapsule
ConceptSymbolLink
ExecutionPathView
DataFlowView
InvariantCard
BlastRadiusView
DiagnosticMap
VerifierMap
FailureFingerprint
CodeCortexReport manifest
```

Do not copy all symbols/call edges from `project_memory`. The code graph remains a derived truth index; canonical memory stores scoped understanding, decisions and outcomes.

## 11.7. Edit gate

For R2/R3 code changes, no `ActionLease` is issued unless:

```text
CodeCortexReport is fresh;
module owner and write-set are identified;
call/data/state path is represented or explicitly unknown;
invariants are listed;
external APIs are verified;
runtime observable and verifier are present.
```

If any load-bearing hop is unknown, Governor returns the exact next probe rather than allowing Codex to improvise.

---

# 12. Collective cognition and multi-agent coordination

## 12.1. Principle

Multiple agents are parallel instruments, not a democratic committee.

```text
Controller decides under Governor gates.
Workers produce bounded candidates/artifacts.
Auditors challenge claims and diffs.
Verifiers produce deterministic observations.
Curators propose memory/skill lifecycle changes.
Governor owns leases, state, authority, ordering and proof.
```

No majority vote can turn a claim into truth. Evidence and verifier authority resolve conflicts.

## 12.2. Agent roles

| Role | May read | May write | May authorize |
|---|---|---|---|
| `controller` | scoped full task packet/evidence | task state, decisions, candidates, proofs | action/finish requests under policy |
| `worker` | assigned work-item packet | candidate result, evidence, tool observations | nothing outside lease |
| `auditor` | task/diff/evidence packet | audit findings candidate | no code/memory truth |
| `verifier` | verifier inputs and artifacts | VerificationRun | verification status only for registered verifier |
| `curator` | eligible traces/memory | skill/forgetting/promotion candidates | no direct promotion |
| `admin` | system scope | config/policy/migration operations | explicit administrative authority |

External models receive `worker` or `auditor`, never `controller` or `admin` by default.

## 12.3. Agent identity and session

```yaml
AgentSession:
  session_id:
  agent_id:
  model_route:
  harness:
  role:
  project_scope:
  task_scope:
  capability_profile_id:
  parent_session_id:
  started_at:
  heartbeat_at:
  expires_at:
  status:
  policy_snapshot_id:
```

Every MCP request is bound to a session. Transport identity alone is insufficient.

## 12.4. Work decomposition

Only controller or an approved planner candidate may propose work items. Governor validates:

```text
work items map to acceptance items;
write-sets do not overlap unless explicitly serialized;
dependencies form an acyclic active plan;
each item has expected artifact and verifier;
parallelism produces expected benefit;
agent/tool capability matches the item.
```

Default maximum active agents per task: `4`. Higher values require project policy. Default multi-agent swarm is forbidden.

## 12.5. Work leases

```yaml
WorkLease:
  lease_id:
  task_id:
  work_item_id:
  holder_session_id:
  lease_epoch:
  allowed_read_set:
  allowed_write_set:
  worktree_ref:
  base_commit:
  expected_artifacts:
  required_verifier:
  issued_at:
  expires_at:
  heartbeat_interval:
  state:
```

Rules:

```text
one mutating holder per overlapping write-set;
read-only auditors may coexist;
leases are revocable and every grant/regrant increments `lease_epoch`;
expired or stale-epoch agent cannot write control state;
lease renewal requires heartbeat, unchanged conflict preconditions and an upper-bound lifetime;
external workers mutate only disposable worktrees.
```

## 12.6. Worktree leases

For code-writing parallel agents:

```text
one disposable Git worktree per mutating worker;
base commit and dirty-state snapshot recorded;
worker cannot touch live controller tree;
diff artifact is returned to controller;
Governor checks path/write-set and base drift before acceptance;
controller applies or rejects the diff.
```

Governor stores worktree metadata, not the whole repository.

`WorktreeLease` has its own `lease_epoch`, canonical path, base commit and owner session. The Git adapter validates the current epoch again when capturing or applying a diff; directory possession alone is not authority.

### Governed diff acceptance

For R2/R3 changes, the mandatory default production path is:

```text
worker writes only in leased worktree;
Governor captures binary-safe Git diff and changed-file manifest;
path/write-set and generated-file rules are checked;
required verifiers run in the worktree;
controller accepts or rejects the candidate diff;
Governor checks live base commit and pre-existing dirty files;
Governor applies the diff through a registered Git adapter transaction;
post-apply verifier runs in the live/controller tree;
result and rollback patch receive canonical receipts.
```

Governor never uses `git reset --hard`, never overwrites unrelated dirty user files and never auto-resolves a semantic merge conflict. Base drift or touched dirty paths produce a ConflictSet.

## 12.7. Blackboard

The blackboard is typed shared state, not an unbounded chat transcript.

Allowed item kinds:

```text
FindingCandidate
EvidenceHandle
Unknown
HypothesisCandidate
ConflictNotice
DecisionRequest
VerifierResult
ArtifactHandle
Blocker
```

Each item has owner, scope, expiry, evidence and status. Free-form prose goes to BlobStore and is referenced, not duplicated in every packet.

## 12.8. Mailbox

```yaml
MailboxMessage:
  message_id:
  sender_session_id:
  recipient_session_id_or_role:
  task_id:
  sequence:
  kind:
  payload_ref:
  requires_ack:
  created_at:
  expires_at:
  acknowledged_at:
```

Delivery semantics:

```text
at-least-once notification;
idempotent message_id;
ordered per recipient/task sequence;
explicit acknowledgement for control messages;
large payload by resource/blob handle;
undelivered messages remain durable in SurrealDB.
```

## 12.9. Conflict handling

When agents disagree:

```text
1. Create ConflictSet with candidate claims/actions.
2. Preserve each source and evidence chain.
3. Apply deterministic authority/freshness rules.
4. If unresolved, request the cheapest discriminative verifier/probe.
5. Controller may choose only after the conflict and residual uncertainty are explicit.
6. Record decision and why alternatives were rejected.
```

Agent count or model prestige is not a resolution rule.

## 12.10. Concurrent admission through Governor

Many agents can submit concurrently, while v1 deliberately serializes canonical write
execution:

```text
MCP/IPC admission runs concurrently;
redb staging gives durable backpressure;
project sequence provides order;
one bounded WriterActor prevents competing store owners;
revision preconditions detect stale plans;
work leases reduce semantic conflicts;
receipts provide read-after-write revision;
external agents are authority-capped.
```

Per-project writer lanes are a later throughput optimization and require a measured ADR;
they are not part of current acceptance evidence.

Two agents may append independent evidence to one project. They may not both change the same active decision state without a revision conflict or explicit conflict-set operation.

## 12.11. Lost-agent recovery

```text
heartbeat expires;
AgentSession -> disconnected;
active ActionLease revoked and epoch advanced;
WorkLease -> grace period, then epoch advanced before reassignment;
uncommitted worktree retained for inspection;
controller receives mailbox event;
work item becomes resumable or blocked;
no candidate output is silently promoted.
```

## 12.12. Collective learning

After task closure, Governor groups contributions by observable effect:

```text
which agent finding changed action;
which verifier killed a hypothesis;
which candidate was rejected and why;
which packet item was unused;
which procedure reduced cost or errors.
```

This feeds candidate skill/retrieval-policy updates. It does not rank agents by persuasive prose.

---

# 13. MCP and agent API

## 13.1. Tool-surface rule

Codex should normally see **eight hot tools**. Complex operations are discriminated unions inside typed tools, not dozens of narrowly named MCP methods.

### Hot tools

```text
eliot.bootstrap
eliot.state
eliot.recall
eliot.packet
eliot.understanding
eliot.record
eliot.coordinate
eliot.finish
```

### Lazy tools

```text
eliot.codecortex
eliot.verify
eliot.external_review
eliot.lifecycle
eliot.job
```

### Admin tools

Admin operations are CLI/local IPC only by default and are not exposed to ordinary MCP clients:

```text
doctor, migrate, backup, restore, policy validate/promote,
queue inspect/retry/dead-letter, incident acknowledge, service control.
```

## 13.2. `eliot.bootstrap`

Purpose: one deterministic entry call at session/task start.

Input modes:

```text
attach_session;
open_task;
resume_task;
attach_work_item.
```

Returns:

```text
AgentSession;
TaskContract summary;
CurrentStateView;
current packet resource or reason packet is required;
active capabilities;
pending mailbox count;
health/degraded flags.
```

It must not return a giant project history.

## 13.3. `eliot.state`

Operations:

```text
current;
timeline_preview;
work_items;
leases;
mailbox_summary;
health.
```

All are read-only and revision-bearing.

## 13.4. `eliot.recall`

Operations:

```text
search_l0;
fetch_l2;
relationships;
current_entity;
recent_failures;
procedure_candidates.
```

The caller must explicitly expand handles. A broad query receives a warning and a capped preview.

## 13.5. `eliot.packet`

Operations:

```text
compile;
refresh;
read_manifest;
explain_inclusion;
```

`explain_inclusion` returns FusedRankTrace and cargo policy for selected handles; it does not expose private model reasoning.

## 13.6. `eliot.understanding`

Operations:

```text
submit_proof;
refresh_required_probe;
request_action_lease;
release_action_lease.
```

Result is a CognitiveGate decision and, when allowed, a bounded ActionLease.

## 13.7. `eliot.record`

Accepts the closed semantic command envelope from section 8.

Operations:

```text
submit;
receipt;
record_tool_observation;
record_verification;
record_agent_result.
```

Profiles restrict command variants. The tool never accepts raw SQL or arbitrary table names.

## 13.8. `eliot.coordinate`

Operations:

```text
delegate_work_item;
claim_work_item;
heartbeat;
send_message;
ack_message;
publish_blackboard_item;
open_conflict;
submit_candidate_result;
release_lease.
```

## 13.9. `eliot.finish`

Operations:

```text
preview_gaps;
submit_completion_proof;
read_finish_decision.
```

A denied finish returns exact uncovered acceptance items, failed verifiers and next allowed action.

## 13.10. Lazy operations as MCP tasks

These operations may outlive one normal request:

```text
CodeCortex deep run;
full verification suite;
external Antigravity review;
report generation;
sleep/replay analysis;
large import/export.
```

Use MCP Tasks when the client negotiates task capability:

```text
operation returns task/job handle;
client polls status or subscribes to resource update;
result is available at `eliot://job/{id}/result`;
cancellation maps to Governor CancellationToken;
job state is durable.
```

If Tasks are unavailable, return the same durable `operation_job` handle and use `eliot.job`.

## 13.11. Structured outputs

Every tool defines `inputSchema` and `outputSchema`. Result payload uses `structuredContent` as canonical form.

Text content is limited to:

```text
one-line status;
compact human explanation;
resource URI for expansion.
```

## 13.12. Error contract

```yaml
EliotError:
  code:
  message:
  retryable:
  operation_id:
  project_id:
  task_id:
  current_revisions:
  expected_revisions:
  required_action:
  evidence_or_incident_ref:
  retry_after_ms:
```

Stable codes include:

```text
UNAUTHENTICATED
FORBIDDEN
SCOPE_MISMATCH
STALE_REVISION
PACKET_STALE
UNDERSTANDING_REQUIRED
ACTION_LEASE_REQUIRED
WRITESET_VIOLATION
VERIFIER_REQUIRED
CURRENT_TRUTH_CONFLICT
DB_UNAVAILABLE
STORAGE_BACKPRESSURE
ADAPTER_UNAVAILABLE
DEADLINE_EXCEEDED
ACCEPTED_PENDING
INCIDENT_MODE
```

## 13.13. MCP transport profiles

```text
codex_controller:
  stdio; full project controller tools under plugin hooks.

codex_worker:
  stdio; scoped worker/coordination/candidate writes.

external_auditor:
  stdio or HTTP; read packets/evidence, write candidate findings only.

verifier:
  stdio; read verifier inputs, write registered VerificationRun only.

human_readonly:
  authenticated named-pipe MCP; typed read projections/resources/reports only.

human_operator:
  authenticated named-pipe MCP; typed Governor queries and explicitly authorized
  commands with retry-stable idempotency and canonical receipts.
```

The server advertises only tools allowed for the authenticated profile, reducing tool-selection entropy.
Neither human profile receives SurrealDB credentials or direct database authority;
all business rules, mutation validation and durable writes remain Governor-owned.


## 13.14. MCP facade and stdio shim algorithm

The MCP schema/handlers are defined once as `McpFacade<GovernorApi>`.

```text
daemon HTTP MCP:
  McpFacade<DirectGovernorApi> -> engine/services directly.

Codex stdio shim:
  McpFacade<IpcGovernorClient> -> named-pipe requests/events -> daemon.
```

The shim is not a raw byte proxy and not a second Governor. It owns only:

```text
MCP initialize/capability negotiation;
tool/resource/task schema exposure;
conversion between MCP calls and typed GovernorApi requests;
forwarding daemon events as MCP notifications;
stdout/stderr discipline;
connection cancellation and shutdown.
```

All semantic decisions, sessions, jobs, resources and canonical state live in the daemon. Tool schemas are generated from the same `eliot-types` definitions for both transports, preventing stdio/HTTP drift.


---

# 14. Native Codex plugin integration

## 14.1. Plugin is the default installation unit

The Codex integration is delivered as one plugin directory. Installation is not considered complete until the operator has reviewed and trusted the plugin-bundled hooks; Codex does not automatically trust newly installed plugin hooks.

```text
plugin/eliot-governor/
  .codex-plugin/
    plugin.json
  .mcp.json
  hooks/
    hooks.json
  skills/
    eliot-task-cycle/
      SKILL.md
    eliot-code-understanding/
      SKILL.md
    eliot-delegation/
      SKILL.md
    eliot-verification-finish/
      SKILL.md
  README.md
```

The manifest declares compatibility with the installed Governor protocol version. Codex must validate the manifest against the current official plugin schema during implementation; it may not invent a different plugin layout.

## 14.2. MCP declaration

`.mcp.json` registers exactly one ELIOT server:

```text
command: eliot-governor.exe
args: ["mcp", "stdio", "--profile", "codex_controller"]
```

Project-specific truth tools may remain configured during migration, but the target state is that Governor owns their orchestration. Direct `eliot_surrealdb` is removed from normal Codex configuration after cutover.

## 14.3. Hook executable

Every hook invokes the installed Rust binary:

```text
eliot-governor.exe hook <event-name>
```

There are no PowerShell/Node/Python hook wrappers. Hook input is read from stdin, parsed into the official event schema, normalized and forwarded over local IPC.

Hook stdout is only the official hook response. Diagnostics go to stderr and tracing files.

## 14.4. Hook map

### `SessionStart`

Algorithm:

```text
1. Handshake plugin/daemon protocol versions.
2. Register or resume AgentSession.
3. Resolve workspace/project identity from canonical path and Git state.
4. Attach active task if unambiguous.
5. Return compact additional context:
     Governor health;
     session/task IDs;
     current status;
     instruction to call `eliot.bootstrap`;
     forbidden direct-memory path.
```

Do not inject a full packet automatically.

### `UserPromptSubmit`

```text
1. Record exact user instruction as tainted SourceSnapshot/EvidenceAtom.
2. Detect whether this is continuation, correction, interruption or new task.
3. If interruption, create InterruptBarrier and kill/pause incompatible plan branches.
4. Update task intent candidate; do not silently rewrite acceptance criteria.
5. Return task handle and whether packet refresh is mandatory.
```

Semantic task normalization is performed by Codex through `eliot.bootstrap`/TaskContract, not hidden in the hook.

### `SubagentStart`

```text
1. Register child AgentSession with parent, role and task scope.
2. Validate requested role and capability profile.
3. Attach or create WorkLease when prerequisites exist.
4. Return a role-specific compact packet/resource handle.
5. If no isolated worktree/write-set exists, register the subagent as read-only/unauthorized for mutation and explain the missing prerequisite.
```

Current Codex hook semantics do not let `SubagentStart` reliably prevent the subagent process from starting. Enforcement therefore happens through the registered role, absence of ActionLease, reduced MCP profile and `PreToolUse` denial—not through a fictional start veto.

### `PreToolUse`

This is the low-latency ActionGate bridge.

```text
1. Normalize tool name and input using ToolProfile registry.
2. Classify read/write/external/destructive impact.
3. Resolve paths and resources.
4. Ask Governor ActionGate using current session/task and ActionLease.
5. Return allow, deny, or permission requirement with exact reason.
```

Hard denials include:

```text
direct SurrealDB access;
starting a second DB owner;
writing Governor data directories;
mutating outside leased paths;
live-tree external-worker writes;
policy/config widening without approval;
finish-like actions without proof where detectable.
```

Codex hooks are a guardrail, not the sole OS security boundary. The architecture also relies on reduced tool exposure, Codex sandbox/approval policy, filesystem ACLs and no DB credentials in agent environments.

### `PermissionRequest`

```text
1. Map requested escalation to impact class.
2. Compare with AgentSession role, TaskContract and policy snapshot.
3. Deny memory/schema/service/secret escalation for non-admin roles.
4. Require explicit human approval for R3 actions.
5. Record the decision and request payload hash.
```

### `PostToolUse`

```text
1. Record ToolObservation with tool, input hash, exit/status, duration and side effects.
2. Inline only bounded output; large output goes to BlobStore.
3. Extract exact anchors deterministically where adapter supports it.
4. Update ActionLease usage.
5. Trigger packet invalidation or verifier state update when relevant.
```

PostToolUse recording is asynchronous after a bounded durable local spool write. It must not make normal Codex tools feel slow.

### `PreCompact`

```text
1. Persist HandoffArtifact with current goal, completed/open items, killed paths,
   exact current truth handles, current diff, pending verifiers and next action.
2. Pin the packet/policy/revision snapshot.
3. Return compact handoff text for the compaction boundary.
```

### `PostCompact`

```text
1. Reconcile Git/branch/diff/runtime state against handoff.
2. Invalidate stale assumptions and action leases.
3. Compile resume packet.
4. Return only active path, forbidden resumptions, next action and verifier.
```

### `SubagentStop`

```text
1. Require AgentResult or explicit failure/blocker.
2. Revoke leases and capture worktree diff/artifacts.
3. Mark result candidate-only unless verifier role produced a valid VerificationRun.
4. Notify controller mailbox.
```

### `Stop`

```text
1. Detect active task and requested completion status.
2. Query FinishGate.
3. If verified complete, allow stop and attach final report handle.
4. If incomplete, block stop once with exact missing acceptance/verifier and next action.
5. If task is genuinely blocked, allow a BLOCKED/PARTIAL final state, never false DONE.
```

## 14.5. Hook latency and fail behavior

Budgets:

```text
SessionStart/UserPromptSubmit: p95 <= 150 ms local
PreToolUse/PermissionRequest: p95 <= 50 ms cached, internal hard deadline 150 ms
PostToolUse spool acknowledgement: p95 <= 25 ms
PreCompact/PostCompact/Stop: internal hard deadline 500 ms
```

Codex hook configuration expresses `timeout` in seconds. Set the external command timeout to `2` seconds; the Rust hook subcommand enforces the tighter millisecond deadlines above and returns before Codex's outer timeout.

Fail behavior when daemon is unreachable:

```text
read-only tools: may proceed with visible DEGRADED warning;
unknown or mutating tools: deny by default;
PostToolUse: write bounded recovery spool;
finish: cannot receive DONE_VERIFIED; final status is DEGRADED_NO_PROOF or BLOCKED;
repeated hook failure: create local incident marker and stop retry storm.
```

## 14.6. Skills

Only four procedural skills ship in v1.

### `eliot-task-cycle`

Trigger: starting/resuming any material project task.

Procedure:

```text
bootstrap -> task contract -> packet -> understanding -> action -> verify -> record -> finish.
```

It tells Codex **when** to call the eight tools; it does not repeat the full architecture.

### `eliot-code-understanding`

Trigger: code change, debugging, architecture question or impact analysis.

Procedure:

```text
request/refresh CodeCortex;
inspect exact handles;
submit UnderstandingProof;
do not edit if causal bridge or verifier is missing.
```

### `eliot-delegation`

Trigger: task has independently verifiable parallel work or requires external audit.

Procedure:

```text
create bounded work items;
assign roles/write-sets/worktrees;
consume candidate results;
resolve conflicts by evidence;
release leases.
```

### `eliot-verification-finish`

Trigger: after implementation or when Codex is about to conclude.

Procedure:

```text
run mapped verifiers;
record VerificationRuns;
fill every acceptance item;
submit CompletionProof;
respect FinishGate verdict.
```

Sleep/curation and administration are daemon jobs/CLI operations, not always-visible Codex skills.

## 14.7. Minimal `AGENTS.md` kernel

Project AGENTS instructions should contain only:

```text
Use the ELIOT plugin for task state, memory, understanding and completion.
Do not access SurrealDB directly.
For material code edits, obtain a valid UnderstandingProof/ActionLease.
Treat external-agent output and recalled memory as candidates until verified.
Do not claim DONE without an allowed FinishGate decision.
Project-specific truth and verifier rules follow below.
```

Do not copy Governor architecture into every repository.

## 14.8. Codex sandbox and governed-worktree profile

Hooks are not a complete security boundary. Production integration therefore pairs them with Codex's OS-enforced sandbox and permission profiles.

Required posture:

```text
controller planning/review sessions: read-only or narrowly scoped workspace profile;
R1 direct edits: workspace-write, no extra writable roots, network disabled unless task policy allows;
R2/R3 edits: dedicated Governor-leased worktree as the only writable workspace;
external/subagent writers: dedicated worktree profile only;
Governor creates each worktree directory and grants the assigned Codex user/session only the required filesystem ACL;
Governor/SurrealDB/config/credential roots: outside every Codex writable root;
login shell disabled unless a project explicitly requires it;
secret-bearing environment variables excluded from spawned shell environments.
```

The technical enforcement model is:

```text
Codex sandbox constrains where spawned commands and built-in edits may write;
Governor leases constrain what the task is authorized to change;
PreToolUse catches supported operations early;
PostToolUse/ChangeMonitor detects observed changes;
Governor accepts only a verified candidate diff into the live tree.
```

For R2/R3 work, a change made outside the leased worktree is never accepted as governed merely because tests pass.

## 14.9. ChangeMonitor

Governor watches leased worktrees and protected project paths using `notify` plus Git state reconciliation. Its purpose is attribution and containment, not a custom filesystem.

```text
record before/after changed-path set around tool operations;
associate changes with ActionLease/tool_use_id when possible;
mark unleased changes as unauthorized/unknown-origin;
block diff acceptance and finish until reconciled;
never auto-revert pre-existing human changes;
store exact diff/status evidence.
```

---

# 15. External models and Antigravity

## 15.1. Two integration forms

### Agent as MCP client

An approved agent/harness connects to Governor over stdio or authenticated localhost HTTP and receives a scoped role profile.

### Agent as supervised subprocess

Governor invokes an `ExternalAgentAdapter` such as official Antigravity CLI `agy`, captures output/artifacts, and exposes the operation as a durable job.

## 15.2. Antigravity route

Target route:

```text
Codex controller
  -> eliot.external_review
  -> Governor ExternalAgentAdapter
  -> official `agy` subprocess
  -> scratch worktree / read-only bundle
  -> ExternalReviewResult candidate
  -> controller + verifiers decide
```

The adapter must not scrape private Antigravity IDE services, token stores or undocumented localhost ports.

`agy -p` is treated as a block-output subprocess unless the installed official CLI documents stronger streaming/session semantics. Governor supplies its own job status, cancellation process group and artifact capture.

## 15.3. External request

```yaml
ExternalReviewRequest:
  request_id:
  task_id:
  role: auditor | worker
  question:
  packet_ref:
  evidence_refs:
  diff_or_artifact_refs:
  allowed_paths:
  worktree_ref:
  forbidden_actions:
  output_schema:
  budget:
  deadline:
  candidate_only: true
```

Only the minimum relevant packet/evidence is sent. Secrets and unrelated project memory are excluded.

## 15.4. External result

```yaml
ExternalReviewResult:
  result_id:
  provider:
  model_route:
  request_id:
  status:
  findings:
  proposed_changes:
  evidence_refs:
  artifact_refs:
  command_trace_refs:
  uncertainty:
  verifier_suggestions:
  candidate_only: true
```

Governor rejects results that omit required structured fields or cite unavailable evidence. Raw stdout remains a blob attachment, not canonical knowledge.

## 15.5. Authority boundary

External agents may create:

```text
EvidenceCandidate;
AuditFindingCandidate;
HypothesisCandidate;
ProcedureCandidate;
DiffArtifactCandidate;
ToolObservation;
AgentResult.
```

They may not directly create:

```text
verified current truth;
active policy;
permission grants;
canonical architecture decisions;
DONE_VERIFIED;
direct live-tree mutations.
```

## 15.6. Other AI models

A new model is integrated by one of:

```text
MCP client profile;
CLI/subprocess ExternalAgentAdapter;
future supported SDK adapter.
```

The model-specific adapter normalizes lifecycle and artifacts. It must not fork memory schemas or create a provider-specific truth boundary.

---

# 16. Adapter subsystem

## 16.1. Adapter classes

```text
TruthAdapter
CodeGraphAdapter
LspAdapter
DiagnosticsAdapter
DomainApiAdapter
DocumentationAdapter
ExternalAgentAdapter
ArtifactVerifierAdapter
```

## 16.2. Core adapter contract

```rust
trait Adapter {
    fn id(&self) -> AdapterId;
    fn capabilities(&self) -> CapabilityManifest;
    async fn health(&self) -> AdapterHealth;
    async fn execute(
        &self,
        request: AdapterRequest,
        ctx: AdapterContext,
    ) -> Result<AdapterResult, AdapterError>;
    async fn shutdown(&self, deadline: Instant) -> Result<()>;
}
```

Conceptual requirements:

```text
bounded request/response size;
deadline and cancellation;
raw output capture;
tool/version metadata;
exact failure semantics;
no direct canonical DB writes;
no implicit model call;
all external text tainted.
```

## 16.3. V1 adapters

### Built into Governor

```text
GitStateAdapter
RipgrepAdapter
AstGrepAdapter
FilesystemMetadataAdapter
Process/ServiceHealthAdapter
```

These call native binaries/APIs with explicit argument arrays. Avoid shell interpolation.

### Long-lived supervised adapter

```text
codebase-memory-mcp
```

One shared process per indexed repository set, not one per agent. Governor acts as MCP client and owns restart/backoff.

### Existing local MCP adapters

```text
VS Code MCP / LuaLS
wow_api
context7
```

VS Code and `wow_api` are project profile dependencies. Context7 is lazy/cold and never on the normal exact-code route.

### External agent

```text
agy
```

Lazy supervised subprocess; not pinned when unused.

## 16.4. AdapterSupervisor

For each adapter:

```text
state = disabled | starting | ready | degraded | open_circuit | stopping | failed
bounded request channel
max concurrency
health probe
idle TTL
restart budget
circuit breaker
version/capability cache
```

Default circuit breaker:

```text
open after 5 consecutive transport failures;
initial open period 30 s;
probe one request in half-open;
manual reset available;
semantic “no results” is not a transport failure.
```

## 16.5. Process execution rules

```text
use tokio::process::Command;
pass executable and args separately;
set explicit cwd/environment allowlist;
create process group/job object for cancellation;
cap stdout/stderr in memory;
stream overflow to BlobStore;
kill process tree on deadline;
record exact exit code and duration;
never expose secrets in command line or logs.
```

## 16.6. Adapter result normalization

```yaml
AdapterObservation:
  adapter_id:
  adapter_version:
  capability:
  request_hash:
  project_scope:
  observed_at:
  duration_ms:
  status:
  structured_items:
  exact_anchor_refs:
  raw_blob_ref:
  exit_or_protocol_status:
  taint:
  freshness:
```

CodeGraph/LSP/diagnostic adapters must preserve exact file/line/symbol identity, not only prose.

## 16.7. Adapter selection

Selection is deterministic from:

```text
project profile;
requested capability;
truth authority;
current health;
latency budget;
known failure profile.
```

The model may request a capability, but it does not choose an arbitrary provider when a canonical project adapter exists.

---

# 17. Configuration and policy

## 17.1. Production data root

Active database, WAL and lock files must not live in OneDrive or another sync folder.

Windows default:

```text
C:\ProgramData\Eliot\
  config\
  data\surrealdb\
  data\control.redb
  blobs\
  logs\
  reports\
  backups\
  worktrees\
  run\
```

Non-service user-mode fallback:

```text
C:\EliotData\<user>\
```

The existing `MCP\.eliot\surrealdb` store is a migration source, not the final production location. Project repositories may contain read-only profile files and exported reports, not live DB/WAL files.

## 17.2. Configuration layers

Precedence from strongest to weakest:

```text
1. compiled non-negotiable invariants;
2. machine `governor.toml`;
3. promoted project profile snapshot;
4. role capability profile;
5. TaskContract narrowing overrides.
```

Lower layers may narrow authority but may not widen a stronger restriction.

## 17.3. Files

```text
config/governor.toml
config/roles.toml
config/tools.toml
config/retention.toml
config/projects/<project_id>.toml
config/policies/<policy_name>.toml
```

Every file has:

```text
schema_version;
config_version;
owner;
effective_from;
optional expires_at;
content hash.
```

## 17.4. Typed policy, not scripting

V1 policy is declarative Rust data:

```text
role -> allowed operations;
tool -> impact class and input extraction rules;
path/resource globs -> allowed/forbidden;
risk tier -> proof/approval/verifier requirements;
memory kind -> epistemic ceiling and retention;
adapter -> authority/freshness;
queue/latency/resource budgets.
```

Use enums, sets, integer thresholds and compiled `globset` patterns. Do not embed JavaScript, Python, Rego or an arbitrary expression language in the hot path.

Cedar may be evaluated later if policy complexity objectively exceeds the typed rule system. It is not a v1 dependency.

## 17.5. Policy snapshot

Each task/session pins a `policy_snapshot_id`. Every gate and write receipt records it.

A policy change:

```text
validate schema;
compile all globs/rules;
run static conflict lint;
calculate content hash;
store candidate snapshot;
require admin promotion for authority-expanding changes;
atomically swap Arc<RuntimePolicy>;
notify sessions;
force packet/action-lease refresh where relevant.
```

Old tasks keep their snapshot unless a security revocation explicitly invalidates it.

## 17.6. Hot reload

Safe hot-reload fields:

```text
log level;
report schedule;
idle TTLs;
read/result payload budgets within hard bounds;
adapter enable/disable;
non-authority performance thresholds;
retention schedules that do not delete immediately.
```

Restart-required fields:

```text
DB endpoint/auth mode;
data root;
writer lane count;
IPC pipe name;
HTTP bind;
core schema version;
credential provider.
```

Rejected config never replaces the active snapshot. Error report includes exact field and keeps last known good version.

## 17.7. Project profile

```yaml
ProjectProfile:
  project_id:
  canonical_root:
  repo_type:
  truth_adapters:
  manifests_and_load_order:
  language_servers:
  domain_api_adapters:
  verifier_map:
  protected_paths:
  default_change_budget:
  external_agent_policy:
  memory_scope_rules:
```

A repository file may propose profile changes, but Governor does not auto-promote a profile modified by the same agent/task it governs. Profile changes are R3 administrative actions.

## 17.8. Credentials

Credentials are referenced by logical secret ID. Values are stored using Windows Credential Manager/DPAPI or service-account environment injection, not TOML, DB records, logs or model packets.

---

# 18. Logs, metrics, audit and reports

## 18.1. Four distinct observability classes

```text
Operational logs — debugging and runtime health; lossy/rotatable.
Metrics — aggregates and SLOs; no payloads.
Durable audit — canonical events/receipts/policy decisions; non-lossy.
Reports — human/Codex projections from canonical state.
```

Do not treat one giant JSONL file as all four.

## 18.2. Operational logs

Use `tracing` spans with JSON output.

Directory:

```text
logs/governor-current.jsonl
logs/governor-YYYY-MM-DD-N.jsonl
logs/error-YYYY-MM-DD-N.jsonl
```

Required fields:

```text
timestamp;
level;
target/module;
service;
operation_id;
trace_id;
project_id;
task_id;
session_id;
write_id/job_id when present;
duration_ms;
result_code;
queue_depth;
DB/adaptor health state.
```

Forbidden fields:

```text
OAuth/API tokens;
full prompts;
private reasoning/chain-of-thought;
full source files;
unredacted tool stdout;
credential-bearing command lines.
```

Rotation defaults:

```text
100 MiB per file;
14 days;
error logs 30 days;
compression after rotation;
retention configurable.
```

## 18.3. Durable audit

Canonical SurrealDB records:

```text
memory_event;
write_receipt;
policy_decision;
action_gate_decision;
finish_decision;
agent_session event;
lease transition;
operation_job transition;
incident_record;
lifecycle/tombstone receipt.
```

Per-project event hashes form a tamper-evident chain:

```text
event_hash = BLAKE3(project_id || project_sequence || event_type
                    || canonical_payload_hash || prev_event_hash)
```

This detects accidental/manual mutation. It is not a substitute for OS access control or backups.

## 18.4. Metrics

Expose localhost-only OpenMetrics endpoint, for example:

```text
http://127.0.0.1:<admin-port>/metrics
```

Use a small Rust metrics exporter. No external collector is required to run Governor.

Core metrics:

```text
eliot_requests_total{surface,operation,result}
eliot_request_duration_seconds{surface,operation}
eliot_queue_depth{class,lane}
eliot_write_commit_duration_seconds{lane}
eliot_write_retry_total{reason}
eliot_pending_wal_items
eliot_db_health_state
eliot_adapter_health_state{adapter}
eliot_packet_compile_seconds{profile}
eliot_packet_bytes{profile}
eliot_packet_items{profile}
eliot_memory_admission_total{decision,kind}
eliot_finish_decisions_total{status}
eliot_action_gate_total{decision,risk}
eliot_agent_sessions{role,status}
eliot_work_leases{state}
eliot_blob_bytes_total
eliot_dead_letter_total{reason}
```

Do not use high-cardinality IDs as metric labels.

## 18.5. Trace model

A `TraceSpan` records externally observable causality:

```yaml
TraceSpan:
  trace_id:
  parent_trace_id:
  task_id:
  session_id:
  operation_kind:
  input_handle_refs:
  packet_id:
  tool_or_adapter:
  expected_observation:
  actual_observation_refs:
  decision_or_gate_ref:
  duration_ms:
  token_or_cost_if_known:
  outcome:
```

It does not store hidden reasoning.

## 18.6. Reports

Canonical report is JSON. Markdown is generated from it.

```text
reports/health/latest.json + latest.md
reports/tasks/<task_id>/summary.json + summary.md
reports/tasks/<task_id>/understanding.json + understanding.md
reports/tasks/<task_id>/memory-influence.json + memory-influence.md
reports/tasks/<task_id>/completion.json + completion.md
reports/incidents/<incident_id>.json + .md
reports/daily/YYYY-MM-DD/memory-health.json + .md
reports/daily/YYYY-MM-DD/performance.json + .md
reports/sleep/<run_id>.json + .md
```

Reports include record IDs, revision fence, generation time and policy version. They never become truth merely because they read well.

## 18.7. Report generation policy

Report rendering runs in a low-priority bounded queue. It reads canonical state by handle and never blocks a write commit.

Generate:

```text
task report on finish/blocked state;
incident report on fatal/dead-letter threshold;
health report on request or significant state change;
daily summaries only when activity exists;
sleep report only for an actual consolidation run.
```

No report is regenerated on every tool call.

## 18.8. Redaction

Redaction happens before operational logging and before external-agent packaging.

Rules cover:

```text
known secret IDs and values;
Authorization/Cookie headers;
OAuth/JWT patterns;
private key blocks;
configured sensitive paths;
user-defined regexes with bounded execution.
```

Original sensitive evidence is either not stored or stored in a restricted encrypted external location; it is never casually put into BlobStore.

---

# 19. Performance architecture

## 19.1. Performance objective

The Governor must make the agent feel more focused, not slower. The hot path is local, exact, bounded and mostly deterministic.

Primary strategy:

```text
few processes;
few visible tools;
exact lookup before search;
small structured payloads;
no direct model calls in gates;
bounded queues;
parallel reads and project-local writes;
large data by content handle;
revision-based invalidation;
lazy cold adapters.
```

## 19.2. SLO targets on the current workstation class

Warm local p95 targets:

| Operation | Target |
|---|---:|
| stdio shim -> daemon IPC round trip | <= 5 ms |
| hook policy decision from cached state | <= 50 ms |
| current state L1 | <= 50 ms |
| exact L0 recall | <= 75 ms |
| L2 evidence fetch, small | <= 150 ms |
| packet compile, warm CodeCortex | <= 300 ms |
| durable small write commit | <= 250 ms |
| task bootstrap with warm project | <= 150 ms |
| exact CodeCortex report | <= 1.5 s |
| deep CodeCortex/external review | async job |

These are engineering budgets, not promises independent of disk/DB/project state. Every result records actual latency and degraded causes.

## 19.3. Payload budgets

```text
hook additional context: 8 KiB hard max;
hot MCP structured result: 64 KiB default, 256 KiB hard max;
packet rendered Markdown: project-configured token/byte budget;
inline evidence: 32 KiB each;
mailbox inline payload: 8 KiB;
external-agent request bundle: explicit budget, handles preferred;
raw logs/artifacts: BlobStore only.
```

## 19.4. Query design

All hot DB access uses a named query registry:

```text
current_state_by_task
active_scope_head
recall_exact_subject
recall_current_claims
fetch_evidence_atoms
fetch_relation_slice
recent_failure_fingerprints
active_decisions
packet_dependencies
work_leases_by_task
mailbox_after_sequence
write_receipt_by_id
```

Rules:

```text
parameterized queries only;
no agent-provided table/field names;
query plan/index review for hot queries;
explicit LIMIT and pagination;
no unbounded graph traversal;
no SELECT * on large payload tables;
blob bodies never joined into hot state.
```

## 19.5. Read concurrency

Use Tokio semaphores:

```text
interactive DB reads: 32 default
background DB reads: 4 default
adapter-specific limits from capability profile
```

Independent adapter calls in CodeCortex may run concurrently after exact roots are known. Do not launch every adapter speculatively.

## 19.6. Write throughput

Throughput comes from:

```text
concurrent admission;
tiny redb staging records with bounded 1 ms/64-item group commit;
project-lane parallelism;
one atomic envelope per transaction;
no external work inside DB transaction;
prepared named mutation builders;
large content outside DB rows;
short indexed receipt/idempotency checks.
```

Do not add Kafka/NATS/Temporal merely to increase local write throughput. The daemon and redb WAL already provide the required local durability and scheduling.

## 19.7. Memory allocation

```text
stream large input/output;
use bytes::Bytes/Arc for shared immutable buffers where useful;
avoid cloning packet/evidence bodies;
preallocate only bounded known collections;
keep canonical records in DB, not an ever-growing in-memory graph;
use system allocator initially;
change allocator only after profile evidence.
```

## 19.8. Build profile

Production release profile:

```toml
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
strip = "symbols"
overflow-checks = true
```

Keep unwind behavior and useful crash diagnostics unless profiling proves a different choice. No unsafe code is allowed without a documented module-level safety invariant and review.

## 19.9. Vector and semantic search policy

V1 does not require a vector engine.

Enable SurrealDB vector/hybrid search only when a real corpus benchmark shows that exact/full-text/graph admission misses valuable memories. Even then:

```text
vector result is L0 candidate only;
provenance/evidence is fetched separately;
no vector store becomes canonical owner;
index build/serving latency is measured independently.
```

Qdrant remains a possible derived index only after SurrealDB search fails a documented SLO/recall gate.

## 19.10. Process economy

Governor should reduce current duplicate process load:

```text
one Governor daemon;
one SurrealDB service;
one shared codebase-memory process per required index set;
one VS Code/LSP environment already used by the developer;
lazy Node adapters with idle shutdown;
one stdio shim per client, near-zero state.
```

The shim exits with Codex; daemon and DB remain alive.


---

# 20. Reliability, recovery and maintenance

## 20.1. Startup algorithm

```text
1. Acquire single-instance OS mutex for Governor.
2. Load built-in invariants and validate machine config.
3. Open ControlWal and recover its last clean-shutdown marker.
4. Initialize BlobStore and verify root/ACL/free-space thresholds.
5. Connect to SurrealDB server; do not start embedded storage.
6. Verify server version, namespace/database, auth and schema version.
7. Apply only forward migrations explicitly allowed by config.
8. Read ScopeState heads and reconcile pending redb writes against DB receipts.
9. Start writer lanes paused.
10. Start policy, coordination, adapter and cognitive services.
11. Resume eligible pending writes in project order.
12. Start IPC/MCP endpoints.
13. Mark service READY only after read/write self-check succeeds.
```

Optional adapter failure does not block READY if its project profile is not active. Canonical store or policy failure does.

## 20.2. Daemon health states

```text
STARTING
RECOVERING
READY
DEGRADED_READ_ONLY
DEGRADED_QUEUEING
INCIDENT_LOCKDOWN
DRAINING
STOPPED
FAULTED
```

Meaning:

| State | Reads | New writes | Mutating actions |
|---|---|---|---|
| READY | current | allowed | governed |
| DEGRADED_READ_ONLY | cached/DB where possible, marked stale | rejected | blocked |
| DEGRADED_QUEUEING | current/cached | durably queued up to cap | only if action does not depend on uncommitted truth |
| INCIDENT_LOCKDOWN | audit/admin only | rejected | blocked |
| DRAINING | allowed | rejected | no new leases |

## 20.3. DatabaseMonitor

Probe schedule:

```text
light health every 5 s;
latency/index/space probe every 60 s;
full graph/schema health on schedule or admin request;
no busy-loop.
```

Checks:

```text
connection/auth;
server version;
read query;
small transactional write/read in dedicated health table when enabled;
schema version;
last committed revision;
disk free space;
write latency;
backup age;
unexpected external change indicators.
```

Governor may request one bounded Windows service restart after configurable consecutive failures. Restart budget defaults to one attempt per 15 minutes. Repeated failure opens an incident and stops automation.

## 20.4. DB outage behavior

On lost DB connection:

```text
1. Mark ScopeHeadCache stale and health DEGRADED_QUEUEING.
2. Reject operations requiring fresh current truth.
3. Continue bounded durable staging only for safe evidence/candidate writes.
4. Do not authorize new R2/R3 mutations.
5. Retry connection with bounded exponential backoff.
6. On reconnect, verify server/schema/revisions before resuming lanes.
7. Reconcile every pending write by write_id before apply.
8. Refresh/invalidate packets and action leases.
```

If ControlWal reaches configured limits, reject new writes. Data loss is preferable to pretending a write succeeded; false success is forbidden.

If the daemon starts without DB access and redb has no trustworthy sequence cursor for a project, that project is read-only until canonical `last_project_sequence` can be loaded. Governor must not guess a new sequence base.

## 20.5. Unknown commit outcome

If connection fails during commit:

```text
never blindly reapply;
query canonical write_receipt by write_id;
if found, adopt committed receipt;
if absent and transaction is known rolled back, retry;
if status remains unknowable, pause project lane and open IncidentRecord.
```

## 20.6. ControlWal recovery

On restart:

```text
for each staged/applying item ordered by project_sequence:
  query DB receipt;
  committed -> mirror receipt and complete;
  absent + retryable -> return to staged;
  rejected receipt -> mark rejected;
  corrupted local record -> quarantine and incident;
```

A clean-shutdown marker and WAL schema version are required. Governor refuses to silently discard an unreadable WAL.

## 20.7. Safe shutdown

```text
1. Stop accepting new sessions/jobs/writes.
2. Notify MCP clients of draining state.
3. Revoke new lease issuance.
4. Wait bounded time for active DB transactions.
5. Return unstarted jobs to durable queue.
6. Flush tracing appenders and reports.
7. Persist clean-shutdown marker.
8. Close DB/adapter connections.
9. Exit.
```

The SurrealDB service has an independent lifetime and is not stopped during a normal Governor restart.

## 20.8. Backup model

Backups contain:

```text
SurrealDB export/snapshot;
ControlWal snapshot only for operational recovery;
BlobStore manifest and referenced blobs;
configuration/policy snapshots;
Governor/plugin versions;
backup manifest with BLAKE3 checksums.
```

Policy:

```text
daily incremental/logical backup where supported;
weekly full backup;
backup before migration;
retention defined in retention.toml;
copy to a separate local volume or approved backup target;
no live copy of open database files.
```

Restore is an administrative maintenance operation:

```text
stop Governor writers;
verify backup manifest;
restore to a new data directory;
start isolated DB service;
run schema/integrity checks;
switch configured data path only after validation;
preserve old store until explicit retirement.
```

Production v1 implements this with the native SurrealDB CLI logical export/import
against loopback server endpoints. Credentials are passed only through process
environment, exports are validated, manifests bind source endpoint/storage, versions,
config/policy/WAL snapshots, immutable blob payloads and checksums, and restore requires
maintenance mode plus an exact action hash for a different endpoint and storage root.
Restore validation starts an isolated Governor against the recovered store before any
cutover. Service/ProgramData mutation remains a separate operator-approved step;
without it the terminal deployment status is `READY_FOR_OPERATOR_CUTOVER`.

## 20.9. Blob garbage collection

```text
mark BlobRefs reachable from active/archive/tombstone/audit records;
retain unreferenced new blobs for grace period;
delete only after two scans or explicit purge receipt;
never delete blobs referenced by legal/audit retention;
record GC receipt and reclaimed bytes.
```

GC is low priority and pauses under interactive load.

The implemented GC plan is bound to a complete, current, scoped canonical
`BlobReferenceSnapshot` containing store revision, query hash, reachable references and
typed audit/legal retention references. Incomplete, stale, mismatched or drifted scans
fail closed. Purge additionally requires the grace period, two scans, an exact approval
hash and a final manifest/snapshot recheck; filenames alone never establish retention.

## 20.10. Maintenance jobs

V1 uses the internal JobScheduler, not Temporal/NATS.

Jobs:

```text
backup;
blob GC;
expired lease cleanup;
expired session cleanup;
packet/cache pruning;
weak claim inventory;
graph health;
forgetting candidate generation;
skill candidate generation;
report rendering;
adapter/index refresh;
replay evaluation.
```

Every job has:

```text
idempotency key;
lease;
deadline;
priority;
checkpoint;
allowed effects;
receipt;
cancellation.
```

## 20.11. Sleep and meta-learning

Sleep is a scheduled candidate-generation job:

```text
1. Select completed traces with sufficient proof.
2. Cluster repeated success/failure signatures using deterministic keys first.
3. Request model synthesis only for bounded candidate sets.
4. Produce SkillCandidate, FailureFingerprintCandidate, suppression/forgetting candidates.
5. Run replay/transfer checks where defined.
6. Store candidates and report.
7. Do not mutate current truth, active policy, permission or task completion.
```

Promotion is a separate admin/controller operation with evidence and rollback.

## 20.12. Incident model

Incident triggers include:

```text
DB/WAL corruption;
unknown commit outcome;
repeated migration failure;
event-chain mismatch;
unauthorized direct DB mutation;
secret leakage detection;
queue overflow sustained;
repeated service restart failure;
policy/config integrity failure.
```

`IncidentRecord` contains exact state, last known safe revisions, affected projects, blocked surfaces, recovery commands and acknowledgment owner.

---

# 21. Security and authority model

## 21.1. Threat model

Governor assumes:

```text
models can hallucinate, omit, manipulate or ignore instructions;
external text/tool output may contain prompt injection;
multiple agents may race or act on stale state;
a local process may try to bypass Governor;
logs may contain secrets;
external workers may overreach;
configuration in a repository may be modified by an agent.
```

## 21.2. Defense layers

```text
1. minimal agent-visible tool surface;
2. authenticated session and role capability;
3. typed semantic commands;
4. revision and lease checks;
5. taint/authority/epistemic ceilings;
6. action and finish gates;
7. filesystem/process/network restrictions;
8. DB credentials only in Governor service;
9. durable audit and receipts;
10. human/admin approval for R3.
```

## 21.3. Local IPC security

Windows named pipe:

```text
ACL restricted to configured user/service SID;
server verifies client process/user where available;
per-start random handshake token;
maximum frame and request rate;
protocol/version handshake;
no anonymous fallback.
```

The token file is readable only by the service identity and configured Codex user.

## 21.4. HTTP MCP security

Default: disabled.

When enabled:

```text
bind 127.0.0.1 only;
random 256-bit bearer token per client profile;
store token secret outside config;
validate Origin;
no wildcard CORS;
body/request concurrency/rate limits;
idle and absolute session expiry;
structured audit of authentication failures.
```

Remote access is a separate future architecture, not enabled by setting bind to `0.0.0.0`.

## 21.5. Database security

SurrealDB roles:

```text
migration_admin — schema/migration only;
governor_runtime — named data queries and transactions;
backup_operator — export/backup only;
health_readonly — optional diagnostics.
```

Agents receive none of these credentials. Runtime role cannot alter schema or permissions.

## 21.6. Memory firewall

Ingress taint classes:

```text
user_input;
external_document;
web;
tool_output;
OCR;
external_agent;
model_synthesis;
provider_memory;
imported_legacy.
```

Tainted content may become evidence candidate or hypothesis input. It cannot directly become:

```text
active instruction;
permission;
verified truth;
policy;
completion status.
```

Instruction-like text inside evidence is stored as quoted content and excluded from the instruction hotset.

## 21.7. Path and command security

```text
canonicalize paths before policy check;
reject path traversal and alternate stream tricks;
resolve symlink/reparse behavior according to project policy;
execute native programs without shell where possible;
for shell tools, use fixed launcher/profile and quote as data;
protect Governor/DB/config/credential paths;
external workers get separate worktrees and reduced environment.
```

## 21.8. Secret handling

```text
secrets represented by SecretRef;
values obtained only inside the adapter/service needing them;
redaction before logs/blobs/model requests;
zeroize buffers where practical;
never write secrets to SurrealDB semantic memory;
never include secrets in task packets or external-agent bundles.
```

## 21.9. Policy and profile integrity

Config/policy/plugin artifacts have version and BLAKE3 hash. Authority-widening changes require:

```text
admin identity;
explicit diff;
validation;
new policy snapshot;
audit receipt;
rollback reference.
```

An agent cannot edit its own role or verifier map and use the change in the same action path.

## 21.10. Human approval records

R3 authority is represented by a one-use durable approval, not by a phrase in chat or a model-generated rationale.

```yaml
ApprovalRequest:
  approval_id:
  requester_session_id:
  task_id:
  action_hash:
  exact_write_set_or_resource_set:
  reason_summary:
  risk_tier:
  requested_at:
  expires_at:
  status: pending | granted | denied | expired | consumed

ApprovalRecord:
  approval_id:
  human_or_admin_identity:
  decision:
  decided_at:
  constraints:
  authentication_method:
  audit_ref:
```

Grant/deny surfaces:

```text
`eliot-governor admin approval grant|deny <approval_id>`;
future trusted local UI;
Codex PermissionRequest only consumes an already valid approval or follows normal Codex approval for lower-risk sandbox escalation.
```

An agent, external model or auto-reviewer cannot mint the canonical R3 approval. The approval is bound to the exact action hash and expires after one use or timeout.

## 21.11. Denial-of-service controls

```text
bounded queues;
per-profile concurrency;
per-request payload limits;
per-agent job quotas;
timeouts/cancellation;
external subprocess CPU/time/output limits where OS permits;
background pause under load;
circuit breakers;
no unbounded graph/vector query.
```

---

# 22. Canonical state machines

## 22.1. Write operation

```text
RECEIVED
  -> VALIDATED
  -> STAGED
  -> ASSIGNED
  -> APPLYING
  -> COMMITTED

VALIDATED -> REJECTED
APPLYING -> RETRY_WAIT -> APPLYING
APPLYING -> UNKNOWN_COMMIT -> RECONCILING
RECONCILING -> COMMITTED | RETRY_WAIT | INCIDENT
RETRY_WAIT -> DEAD_LETTER after policy exhaustion
STAGED/ASSIGNED -> CANCELLED only before APPLYING
```

No terminal state may later become another terminal state without a new compensating operation.

## 22.2. Task lifecycle

```text
PROPOSED
-> OPEN
-> FRAMED
-> UNDERSTANDING_REQUIRED
-> ACTION_AUTHORIZED
-> EXECUTING
-> VERIFYING
-> DONE_VERIFIED
```

Alternative terminal/nonterminal transitions:

```text
ANY_ACTIVE -> BLOCKED
ANY_ACTIVE -> FAILED
ANY_ACTIVE -> PARTIAL
OPEN/FRAMED -> CANCELLED
DONE_VERIFIED -> REOPENED only by explicit new task/reopen event
```

## 22.3. Cognitive state

```text
NO_PACKET
-> PACKET_CURRENT
-> PROOF_SUBMITTED
-> PROBE_REQUIRED | ACTION_LEASED | BLOCKED
ACTION_LEASED
-> OBSERVATION_RECORDED
-> PACKET_STALE | VERIFYING
```

Any relevant revision change invalidates the action lease according to risk policy.

## 22.4. Agent session

```text
REGISTERING
-> ACTIVE
-> IDLE
-> ACTIVE
-> DISCONNECTED
-> EXPIRED

ACTIVE/IDLE -> REVOKED
ACTIVE -> DRAINING -> CLOSED
```

## 22.5. Work lease

```text
REQUESTED
-> GRANTED
-> ACTIVE
-> COMPLETED

ACTIVE -> RENEWING -> ACTIVE
ACTIVE -> EXPIRED
ACTIVE -> REVOKED
ACTIVE -> FAILED
```

## 22.6. Claim lifecycle

Epistemic status and lifecycle status are orthogonal.

```text
Epistemic:
  observed -> supported -> verified
  supported/verified -> contested
  any -> stale -> superseded
  candidate -> rejected

Lifecycle:
  active -> dormant | suppressed | archived | forgotten | quarantined
  dormant -> active | suppressed | archived | forgotten | quarantined
  suppressed -> active | archived | forgotten | quarantined
  archived -> active | forgotten | quarantined
  forgotten -> restored | quarantined
  restored -> active | suppressed | archived | forgotten | quarantined
  any governed state -> hard_deleted only through approved purge/tombstone path
```

A summary or model synthesis cannot move a claim upward. Verification or authoritative evidence is required.

## 22.7. External review job

```text
QUEUED
-> PREPARING_BUNDLE
-> RUNNING
-> CAPTURING
-> RESULT_CANDIDATE
-> REVIEWED_ACCEPTED | REVIEWED_REJECTED | EXPIRED

RUNNING -> CANCELLING -> CANCELLED
ANY -> FAILED
```

## 22.8. Daemon and DB

```text
Governor:
  STARTING -> RECOVERING -> READY
  READY -> DEGRADED_* -> READY
  ANY -> INCIDENT_LOCKDOWN
  READY/DEGRADED -> DRAINING -> STOPPED

DB:
  UNKNOWN -> CONNECTING -> HEALTHY
  HEALTHY -> SUSPECT -> UNAVAILABLE
  UNAVAILABLE -> RESTARTING -> CONNECTING
  repeated failure -> INCIDENT
```

---

# 23. Rust module and function contract

## 23.1. ID newtypes

Do not pass naked strings for canonical identities.

```rust
ProjectId
TaskId
WorkItemId
AgentId
SessionId
WriteId
OperationId
PacketId
ClaimId
EvidenceId
VerificationId
LeaseId
PolicySnapshotId
CommitId
BlobHash
```

Use UUIDv7 where globally generated; use validated stable strings only where the external system already owns identity.

## 23.2. Core enums

```rust
MemoryCommand
EpistemicStatus
LifecycleStatus
Visibility
TaintClass
AgentRole
RiskTier
GateDecision
FinishStatus
WriteStatus
JobStatus
ReadConsistency
AdapterCapability
```

Enums are non-exhaustive only at wire-version boundaries; internal matches must handle every variant explicitly.

## 23.3. Primary service interfaces

### `WriteAdmissionService`

```rust
async fn submit(
    &self,
    principal: &AgentPrincipal,
    envelope: MemoryWriteEnvelope,
    mode: AckMode,
    deadline: Instant,
) -> Result<WriteSubmission, EliotError>;
```

Responsibilities end after durable staging/waiter registration. It does not execute DB transactions.

### `ControlWal`

```rust
fn stage(&self, admitted: AdmittedWrite) -> Result<StagedWrite>;
fn next_for_lane(&self, lane: LaneId, now: OffsetDateTime) -> Result<Option<PendingWrite>>;
fn mark_applying(&self, write_id: WriteId) -> Result<()>;
fn mark_receipt(&self, receipt: &WriteReceipt) -> Result<()>;
fn schedule_retry(&self, write_id: WriteId, retry: RetryState) -> Result<()>;
fn recover_pending(&self) -> Result<Vec<PendingWriteSummary>>;
```

All redb access is mediated by one `ControlWalActor` so the rest of the daemon never contends for the single redb writer transaction.

### `CanonicalStore`

```rust
async fn apply_mutation(
    &self,
    admitted: &AdmittedWrite,
    current_scope: &ScopeState,
) -> Result<WriteReceipt, StoreError>;

async fn receipt(&self, write_id: WriteId) -> Result<Option<WriteReceipt>, StoreError>;
async fn scope_state(&self, project_id: &ProjectId) -> Result<ScopeState, StoreError>;
async fn execute_named<Q: NamedQuery>(&self, query: Q) -> Result<Q::Output, StoreError>;
```

Only named query/mutation types may reach the store.

### `ReadService`

```rust
async fn current_state(&self, req: CurrentStateRequest) -> Result<CurrentStateView>;
async fn recall_l0(&self, req: RecallRequest) -> Result<RecallPreview>;
async fn fetch_l2(&self, req: EvidenceFetchRequest) -> Result<EvidencePackSlice>;
async fn resource(&self, uri: EliotResourceUri) -> Result<ResourceContent>;
```

### `ContextCompiler`

```rust
async fn compile(&self, req: PacketCompileRequest) -> Result<CompiledPacket>;
```

It must return packet, manifest, provenance, scorecard and revision fence as one result.

### `CodeCortex`

```rust
async fn run(&self, req: CodeCortexRequest) -> Result<CodeCortexReport>;
```

### `CognitiveGate`

```rust
async fn evaluate(
    &self,
    principal: &AgentPrincipal,
    proof: UnderstandingProof,
) -> Result<CognitiveGateResult>;
```

### `ActionGate`

```rust
async fn evaluate_tool_call(
    &self,
    principal: &AgentPrincipal,
    call: NormalizedToolCall,
) -> Result<ActionGateResult>;
```

### `FinishGate`

```rust
async fn evaluate(
    &self,
    principal: &AgentPrincipal,
    proof: CompletionProof,
) -> Result<FinishDecision>;
```

### `NegativeMemoryGate`

```rust
async fn evaluate(
    &self,
    principal: &AgentPrincipal,
    request: NegativeMemoryRequest,
) -> Result<NegativeMemoryDecision>;
```

### `DiagnosticNormalizer`

```rust
fn normalize(
    &self,
    source: DiagnosticSource,
    raw: RawAdapterObservation,
    scope: DiagnosticScope,
) -> Result<DiagnosticBatch, DiagnosticError>;
```

### `SleepCurator`

```rust
async fn propose(
    &self,
    request: ConsolidationRequest,
) -> Result<ConsolidationCandidateSet>;
```

Every returned item is candidate-only and contains replay requirements. This interface cannot promote current truth, policy, skills or completion state.

### `AgentCoordinator`

```rust
async fn register_session(&self, req: RegisterSession) -> Result<AgentSession>;
async fn acquire_work(&self, req: WorkLeaseRequest) -> Result<WorkLeaseDecision>;
async fn heartbeat(&self, req: AgentHeartbeat) -> Result<HeartbeatAck>;
async fn send_message(&self, msg: MailboxMessageDraft) -> Result<MailboxReceipt>;
async fn submit_result(&self, result: AgentResultDraft) -> Result<AgentResultReceipt>;
```

## 23.4. Adapter interface implementation choice

Use one small dependency, `async-trait`, for object-safe dynamically registered adapters. Do not build a plugin ABI or dynamic library loader in v1.

Adapters are compiled into the binary or represented by configured MCP/CLI drivers. Adding an adapter requires source-level registration and a `CapabilityManifest`; changing which configured adapter is active does not require architecture changes.

## 23.5. Internal request context

Every service call carries:

```rust
RequestContext {
    operation_id,
    trace_id,
    principal,
    project_id,
    task_id,
    policy_snapshot,
    deadline,
    cancellation_token,
    payload_budget,
}
```

Do not use global mutable “current task” state.

## 23.6. Error taxonomy

Library errors are typed:

```text
ValidationError
AuthError
PolicyError
ConflictError
StoreError
WalError
BlobError
AdapterError
GateError
JobError
IncidentError
```

`anyhow` is allowed only at the application boundary to attach startup/CLI context. MCP/IPC responses map typed errors to stable `EliotError` codes.

## 23.7. Dependency direction

```text
eliot-types <- eliot-store
eliot-types <- eliot-engine
eliot-types + store + engine <- eliot-app
```

`eliot-store` must not depend on engine/policy. `eliot-types` must not depend on Tokio, SurrealDB, rmcp or Windows APIs.

## 23.8. Concurrency ownership

```text
ControlWalActor owns redb write transactions.
Each WriterLane owns ordering for assigned projects.
ScopeHeadCache owns revision notifications.
AgentCoordinator owns in-memory lease timers, mirrored canonically.
AdapterSupervisor owns child processes/connections.
ReportService owns render queue.
ConfigService owns ArcSwap snapshots.
```

No two modules may independently manage the same lifecycle.

## 23.9. Serialization rules

```text
all wire and durable schemas have explicit schema_version;
unknown required fields fail closed;
unknown optional enum variants from newer server return version error;
canonical hashing uses normalized serialized form;
floating point is avoided in authority/status/revision logic;
timestamps are UTC with explicit precision;
paths stored in normalized canonical form plus original display form.
```

## 23.10. Required crate set

Production core:

```text
tokio
tokio-util
rmcp
axum
tower
surrealdb
redb
serde
serde_json
schemars
toml
clap
tracing
tracing-subscriber
tracing-appender
thiserror
anyhow (app boundary only)
uuid
time
notify
globset
arc-swap
blake3
zstd
bytes
parking_lot
async-trait
regex
semver
metrics
metrics-exporter-prometheus
windows-service
windows
secrecy
zeroize
subtle
```

Do not introduce a general agent/RAG/workflow framework.

## 23.11. Dependency feature policy

Use minimal Cargo features; do not accept default feature explosions without inspection.

```text
tokio: rt-multi-thread, macros, sync, time, process, signal, net, io-util, fs;
rmcp: server/client pieces actually required for stdio and Streamable HTTP;
surrealdb: remote WebSocket protocol only, no embedded RocksDB/SurrealKV engines;
axum/tower: routing, timeout, limit, load-shed only;
windows: only named-pipe, ACL, Job Object, DPAPI and service-control APIs used;
serde/schemars: derive;
zstd: required stream API only.
```

Run `cargo tree -e features` and `cargo deny` as build hygiene. Removing unused features is part of performance work; replacing the architecture with hand-written unsafe network/database code is not.

## 23.12. Cargo feature profiles

The workspace exposes only these product profiles:

```text
default/service:
  daemon + named-pipe IPC + stdio MCP + remote SurrealDB + Windows service;

http-mcp:
  authenticated localhost Streamable HTTP listener;
  disabled in the default installation;

prometheus:
  localhost OpenMetrics exporter;
  optional because logs and canonical audit do not depend on it.
```

Rules:

```text
`axum`, HTTP-only Tower layers and Prometheus exporter are optional dependencies;
no embedded SurrealDB storage feature is compiled;
no development/mock storage feature is shipped in release artifacts;
external-agent adapters are runtime-configured and do not create one Cargo feature per model;
release builds use one locked dependency graph and reproducible `Cargo.lock`;
the Windows production target is `x86_64-pc-windows-msvc`;
the repository contains `rust-toolchain.toml` pinned to the selected stable toolchain with rustfmt and clippy.
```


---

# 24. Production-first implementation sequence

## 24.1. Rule

Codex must implement the real production path in vertical slices. Do not build a FileStore, fake Governor, mock MCP universe or parallel “temporary architecture”.

Tests may use an isolated real SurrealDB instance and temporary data directories, but production interfaces and store code remain the same.

## 24.2. Phase A — repository, service and real store

Create:

```text
four-crate workspace;
config loader and typed schemas;
Windows service entry point;
SurrealDB service configuration in remote server mode on a new RocksDB data root;
real migration runner;
ControlWal redb;
BlobStore;
startup health/doctor;
structured logging.
```

Exit criterion:

```text
Governor service reaches READY against real SurrealDB;
migration and health records are visible;
no Codex integration yet required.
```

## 24.3. Phase B — canonical write/read core

Implement:

```text
MemoryWriteEnvelope and command enum;
WriteAdmissionService;
ControlWalActor;
project writer lanes;
SurrealStore named transactions;
WriteReceipt/idempotency/recovery;
ScopeState revisions;
L0/L1/L2 ReadService;
real outage/reconnect behavior.
```

Exit criterion:

```text
two independent projects commit concurrently;
same-project writes preserve sequence;
crash/restart reconciles receipts without duplicate records;
read-after-write by revision works.
```

## 24.4. Phase C — daemon IPC, MCP and plugin

Implement:

```text
named-pipe IPC;
rmcp stdio shim;
eight hot MCP tools and resources;
MCP task/job support or compatible job fallback;
Codex plugin manifest/.mcp.json;
SessionStart/UserPromptSubmit/PostToolUse hooks;
minimal four skills.
```

Exit criterion:

```text
Codex installs plugin, bootstraps a real task, reads state, writes evidence and receives canonical receipt through Governor only.
```

This is the first usable build. It is not a throwaway prototype.

## 24.5. Phase D — cognition and enforcement

Implement:

```text
CurrentTruthResolver;
MemoryAdmission;
ContextCompiler;
UnderstandingProof;
CognitiveGate;
ActionLease/ActionGate;
CompletionProof/FinishGate;
remaining lifecycle hooks;
packet/resources/reports.
```

Exit criterion:

```text
material edit without fresh proof is denied;
stale memory cannot become verified_now;
incomplete task cannot become DONE_VERIFIED.
```

## 24.6. Phase E — live CodeCortex

Implement real adapters in order:

```text
Git;
ripgrep;
ast-grep;
codebase-memory-mcp;
VS Code/LSP MCP;
wow_api/domain API;
diagnostics/verifier map.
```

Exit criterion:

```text
Roth_UI task produces a fresh causal report with exact file/symbol/API/diagnostic/verifier handles and can authorize a bounded edit.
```

No mock adapters are retained in production.

## 24.7. Phase F — collective agents

Implement:

```text
AgentSession roles;
work items and leases;
worktree leases;
mailbox/blackboard/conflict sets;
SubagentStart/SubagentStop hooks;
role-specific MCP profiles;
resource subscriptions.
```

Exit criterion:

```text
controller and at least two workers operate concurrently without overlapping unauthorized writes; candidate results merge only through controller/gates.
```

## 24.8. Phase G — Antigravity and external models

Implement:

```text
ExternalAgentAdapter;
agy process lifecycle;
read-only/scratch-worktree request bundles;
job status/cancel/result;
external candidate authority boundary.
```

Exit criterion:

```text
Antigravity audit result is captured with artifacts and evidence refs, cannot directly modify current truth or DONE state, and remains optional when unavailable.
```

## 24.9. Phase H — maintenance and operational finish

Implement:

```text
backup/restore commands;
blob GC;
incident mode;
daily/task reports;
sleep candidate job;
policy/config promotion;
metrics dashboard endpoint;
installer/service/plugin packaging.
```

## 24.10. Explicitly forbidden implementation shortcuts

```text
no direct SurrealQL from Codex;
no FileStore substitute;
no “temporary” Python/Node daemon;
no second memory DB;
no unbounded channel;
no TODO stub returning success;
no all-tools-visible MCP catalog;
no online model-driven policy rewrite;
no service tied to one Codex process;
no active DB files in OneDrive;
no external worker in live tree.
```

---

# 25. Cutover from the current prototype

## 25.1. Historical pre-Governor source state

The historical prototype baseline used:

```text
`surreal mcp` stdio process as storage owner;
legacy SurrealKV under MCP\.eliot\surrealdb;
direct Codex `eliot_surrealdb` MCP registration;
`.surql` inbox/prototype skills;
existing typed claims/relations/lifecycle records.
```

The data is valuable and must be migrated through typed preview/execute import, never by
executing historical raw `.surql` as product ingress.

The implemented product boundary now runs one user-mode Governor over authenticated
named-pipe MCP, WriterActor/ControlWal/CanonicalStore, and a separate loopback SurrealDB
server with RocksDB outside OneDrive. Codex/OpenCode/Antigravity and the native WinUI 3
Operator access memory only through Governor profiles. The legacy global
`eliot_surrealdb` process remains an evidence/history plane and is not the product store.
Administrative service cutover is plan-only until exact operator approval; unsigned
release staging is supported, while Authenticode signing remains an external release
tail.

## 25.2. Cutover sequence

```text
1. Stop new prototype writes and close Codex sessions using direct DB MCP.
2. Verify no second SurrealDB owner is running.
3. Take logical export and filesystem backup while owner is cleanly stopped.
4. Start the approved deployment mode with a new local non-OneDrive RocksDB data root. The implemented user-mode root is `%LOCALAPPDATA%\Eliot\data`; Windows service installation remains an exact-approval cutover tail.
5. Start the isolated RocksDB-backed server and import the logical export from the legacy SurrealKV store.
6. Apply Governor schema migrations and create scope revisions/receipts/event metadata.
7. Mark historical claims lacking supports/verified_by as weak legacy recall.
8. Convert pending validated inbox items to MemoryWriteEnvelope imports.
9. Install Governor service and run recovery/graph/lifecycle health checks.
10. Install Codex plugin and verify stdio shim -> named pipe -> daemon.
11. Remove/disable direct `eliot_surrealdb` from normal Codex config.
12. Run real read/write/current-state/packet/forget-restore smoke through Governor.
13. Preserve old store read-only until explicit migration acceptance.
```

Never run old stdio owner and new server against the same storage path.

## 25.3. Skill migration

Existing ELIOT skills are consolidated:

```text
memory-owner-recovery -> daemon/admin docs, not hot skill;
memory-protocol -> eliot-task-cycle;
codecortex -> eliot-code-understanding;
diagnostics-finish -> eliot-verification-finish;
agy-auditor -> eliot-delegation plus external-review profile;
sleep-curator -> daemon maintenance/admin workflow.
```

## 25.4. Legacy data policy

```text
preserve source/evidence/claim IDs where possible;
create migration event and import receipt;
never silently upgrade epistemic status;
backfill relations only from exact existing references;
unknown provenance remains unknown;
legacy raw prose is quarantined or archived, not hot recall.
```

---

# 26. Definition of done and architectural no-go gates

## 26.1. Governor v1 is done only when

```text
1. SurrealDB and Governor run as independent Windows services.
2. All normal agent memory access goes through Governor.
3. Codex plugin installs MCP, hooks and four skills natively.
4. Direct DB access is absent from agent profiles.
5. Real typed writes are durable, idempotent and revision-bearing.
6. Same-project ordering and independent-project concurrency work.
7. Read ladder L0-L4 and resources enforce payload budgets.
8. Current truth is separated from recalled memory.
9. CodeCortex builds the intent->symbol->runtime->verifier bridge.
10. R2/R3 edits require UnderstandingProof and ActionLease.
11. Finish requires CompletionProof and FinishGate.
12. Multiple agents coordinate through leases/mailbox/candidate results.
13. External models are candidate-only and isolated.
14. DB outage/restart recovers without duplicate durable writes.
15. Operational logs, durable audit, metrics and reports are distinct.
16. Active DB/WAL files are outside OneDrive.
17. Backup/restore and incident procedures are operational.
18. No mock storage or alternate temporary runtime remains in the product.
```

## 26.2. Hard no-go conditions

Do not declare v1 ready if any is true:

```text
Codex still writes SurrealDB directly;
raw SQL is exposed through MCP;
agent can mark a claim verified without verifier authority;
agent can finish without acceptance coverage;
external worker can write live tree or current truth;
multiple processes can own one embedded database path;
production continues on legacy beta SurrealKV without an explicit ADR and migration gate;
queue can grow without bound;
packet compiler emits giant raw dumps;
code understanding is broad summary without exact causal handles;
policy/config can be widened by ordinary task edits;
logs contain tokens/full prompts/private reasoning;
DB failure silently returns stale state as current;
write success can be returned without canonical receipt;
redb becomes a second semantic memory owner;
vector similarity is treated as evidence;
production depends on a Python/Node orchestration framework.
```

## 26.3. Decisions Codex may make during implementation

Codex may choose:

```text
private helper names;
small internal file grouping;
local error-context wording;
query implementation details that preserve named contracts;
UI/report formatting that preserves canonical fields.
```

Codex may not choose:

```text
another DB/topology;
another concurrency model;
a different authority model;
a generic SQL API;
more hot tools;
a second canonical memory;
a FileStore-first phase;
a different project-lane ordering rule;
a different role/promotion boundary;
a different plugin/hook workflow;
removal of proof/receipt/revision requirements.
```

Any required architectural deviation becomes an ADR proposal and is not silently implemented.

---

# Appendix A. Default configuration skeleton

```toml
schema_version = 1
config_version = "1.0.0"

[runtime]
instance_name = "eliot-local"
shutdown_grace_ms = 5000
max_blocking_threads = 8

[paths]
data_root = "C:/ProgramData/Eliot"
blob_root = "C:/ProgramData/Eliot/blobs"
log_root = "C:/ProgramData/Eliot/logs"
report_root = "C:/ProgramData/Eliot/reports"
backup_root = "C:/ProgramData/Eliot/backups"
worktree_root = "C:/ProgramData/Eliot/worktrees"

[database]
mode = "remote_ws"
endpoint = "ws://127.0.0.1:8123"
namespace = "eliot"
database = "system"
credential_ref = "eliot/surreal/runtime"
connect_timeout_ms = 2000
query_timeout_ms = 2000
max_concurrent_transactions = 4
restart_service_on_failure = true
restart_budget_per_15m = 1

[database_service]
service_name = "SurrealDB Eliot"
binary = "surreal"
storage_engine = "rocksdb"
storage_path = "C:/ProgramData/Eliot/data/surrealdb"
bind = "127.0.0.1:8123"
legacy_surreal_kv_path = "<USER_PROFILE>/path/to/legacy/surrealdb"
legacy_path_read_only = true

[control_wal]
path = "C:/ProgramData/Eliot/data/control.redb"
max_pending_items = 10000
max_pending_bytes = 536870912

[writer]
lanes = 4
interactive_commit_wait_ms = 1000
max_retry_age_seconds = 300

[queues]
interactive = 512
verification = 512
writes = 2048
background = 1024
reports = 128

[ipc]
pipe_name = "eliot-governor-v1"
max_frame_bytes = 1048576

[http_mcp]
enabled = false
bind = "127.0.0.1:8765"
admin_bind = "127.0.0.1:8766"

[read]
max_interactive_concurrency = 32
max_background_concurrency = 4
l0_default_hits = 12
l2_max_atoms = 200
structured_result_bytes = 65536
hard_result_bytes = 262144

[packet]
hook_context_bytes = 8192
cache_items = 256
cache_bytes = 67108864
stable_scope_retries = 1

[hooks]
pre_tool_timeout_ms = 150
post_tool_spool_timeout_ms = 50
boundary_timeout_ms = 500
fail_closed_for_mutation = true

[logging]
level = "info"
rotate_bytes = 104857600
retention_days = 14
error_retention_days = 30

[metrics]
enabled = true

[maintenance]
backup_cron = "0 3 * * *"
blob_gc_cron = "30 3 * * 0"
lease_sweep_seconds = 30
session_expiry_seconds = 600

[adapters.codebase_memory]
enabled = true
mode = "managed_mcp_process"
idle_ttl_seconds = 900
max_concurrency = 8

[adapters.vscode]
enabled = true
mode = "streamable_http_mcp"
endpoint = "http://127.0.0.1:3000/mcp"
max_concurrency = 4

[adapters.wow_api]
enabled = true
mode = "managed_mcp_process"
idle_ttl_seconds = 300
max_concurrency = 4

[adapters.context7]
enabled = true
mode = "managed_mcp_process"
idle_ttl_seconds = 120
max_concurrency = 2
cold_only = true

[adapters.antigravity]
enabled = false
executable = "agy"
write_mode = "scratch_worktree_only"
max_concurrency = 1
```

Values are defaults, not permission to skip environment validation.

---

# Appendix B. Role capability outline

```yaml
codex_controller:
  tools: [bootstrap, state, recall, packet, understanding, record, coordinate, finish,
          codecortex, verify, external_review, job]
  write_commands:
    - task/control state
    - candidate/support/decision/failure
    - verification and completion proof
  forbidden:
    - schema/admin
    - direct verified truth without verifier

codex_worker:
  tools: [bootstrap, state, recall, packet, understanding, record, coordinate, job]
  write_commands: [evidence, tool observation, candidate result]
  requires_work_lease: true

external_auditor:
  tools: [bootstrap, state, recall, packet, record, coordinate, job]
  write_commands: [audit finding candidate, evidence candidate, agent result]
  no_live_tree_write: true

verifier:
  tools: [bootstrap, state, recall, record, coordinate, job]
  write_commands: [verification run]
  verifier_ids: project-configured

curator:
  tools: [state, recall, packet, record, lifecycle, job]
  write_commands: [skill candidate, forgetting candidate, promotion candidate]
  direct_promotion: false
```

---

# Appendix C. Tool decision matrix

| Question | Final v1 decision |
|---|---|
| Canonical memory DB | SurrealDB server with RocksDB production storage |
| Agent DB access | none |
| Governor DB access | Rust SDK over local WebSocket/RPC; remote transport features only |
| Operational durable queue | redb |
| Large artifacts | BLAKE3-addressed zstd BlobStore |
| Agent protocol | MCP |
| Codex transport | plugin-bundled stdio shim -> named pipe |
| Other local agents | stdio or authenticated localhost Streamable HTTP |
| Internal message bus | bounded Tokio channels; no NATS |
| Workflow engine | internal durable JobScheduler; no Temporal |
| Write concurrency | concurrent admission, one bounded v1 WriterActor; project lanes are target scale-out |
| Multi-project atomic write | forbidden in v1 |
| Coordination | leases + mailbox + typed blackboard |
| Code understanding | CodeCortex exact truth-adapter orchestration |
| Policy | typed declarative TOML compiled to Rust rules |
| Hot skills | four |
| Hot MCP tools | eight |
| Vector search | disabled until measured need |
| External Google worker | official Antigravity `agy`, candidate-only |
| Production storage engine | RocksDB inside SurrealDB; SurrealKV legacy/experimental only |
| Production mock backend | none |

---

# Appendix D. Official and donor references

Primary implementation references:

- OpenAI Codex plugins: https://developers.openai.com/codex/plugins
- OpenAI Codex plugin construction: https://developers.openai.com/codex/plugins/build
- OpenAI Codex hooks: https://developers.openai.com/codex/hooks
- OpenAI Codex MCP: https://developers.openai.com/codex/mcp
- OpenAI Codex skills: https://developers.openai.com/codex/skills
- OpenAI Codex subagents: https://developers.openai.com/codex/subagents
- Model Context Protocol specification: https://modelcontextprotocol.io/specification/2025-11-25
- MCP transports: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- MCP tools: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- MCP resources: https://modelcontextprotocol.io/specification/2025-11-25/server/resources
- MCP tasks: https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks
- Official Rust MCP SDK (`rmcp`): https://github.com/modelcontextprotocol/rust-sdk
- SurrealDB: https://github.com/surrealdb/surrealdb
- SurrealDB deployment models and RocksDB recommendation: https://surrealdb.com/docs/build/deployment
- SurrealDB architecture and storage-engine status: https://surrealdb.com/docs/architecture
- SurrealDB Rust SDK: https://surrealdb.com/docs/sdk/rust
- SurrealDB `DEFINE TABLE`: https://surrealdb.com/docs/surrealql/statements/define/table
- SurrealDB relations: https://surrealdb.com/docs/surrealql/statements/relate
- SurrealDB changefeeds: https://surrealdb.com/docs/surrealql/statements/show
- SurrealDB Spectron: https://surrealdb.com/platform/spectron
- redb: https://github.com/cberner/redb
- Tokio: https://tokio.rs/
- tracing: https://github.com/tokio-rs/tracing
- codebase-memory-mcp: https://github.com/DeusData/codebase-memory-mcp
- ast-grep: https://github.com/ast-grep/ast-grep
- ripgrep: https://github.com/BurntSushi/ripgrep

Pattern donors, not runtime dependencies:

- GitHub Copilot Memory: https://github.blog/ai-and-ml/github-copilot/building-an-agentic-memory-system-for-github-copilot/
- Graphiti: https://github.com/getzep/graphiti
- AgenticMemory: https://github.com/agentralabs/agentic-memory
- MentisDB: https://github.com/cloudllm-ai/mentisdb
- Acontext: https://github.com/memodb-io/Acontext
- Cloudflare Agents: https://github.com/cloudflare/agents

---

# Final architecture statement

```text
ELIOT Governor v1 is one Rust daemon and one native Codex plugin.

Codex remains the reasoning brain.
Governor is the external cognitive and authority kernel.
SurrealDB server is the canonical durable memory.
redb is a small operational WAL, never a second brain.
CodeCortex composes exact project truth into causal understanding.
All agents read staged scoped views and write typed semantic commands.
Parallelism is controlled by leases and revisions; canonical v1 writes pass through one bounded WriterActor.
External models produce candidates, not authority.
Every durable write has a receipt.
Every material action has a proof and lease.
Every finish is verifier-gated.
Every learned rule remains candidate until replay/promotion.
```

This is the architecture Codex must implement. It is not a menu of alternatives.
