# Eliot V3 — реестр анализа

**Статус на 2026-10-26 · нормативная база Architecture draft.9 / Implementation draft.28 / Cognition draft.11 / Inference Contract 0.5; controller baseline `e42c464d`; активный рабочий реестр, не runtime gate.**

Это **единственный активный реестр** V3. Он показывает, что проверено, что решено только на design-уровне, чего нет в runtime и что делать следующим. Architecture/Implementation/Cognition/Inference Contract — нормативный проект; [AUDIT](AUDIT.md) и [AUDIT-MAP](AUDIT-MAP.md) сохраняют доказательства и стабильные source dispositions. Новый проход обновляет этот файл, а не создаёт новый отчёт.

## 1. Статусы

| Статус | Значение |
|---|---|
| `CHECKED` | Указанный source/design scope прочитан и вывод согласован. Не означает работающий runtime. |
| `DECIDED` | Для V3 выбрано решение; код/живой прогон отсутствует. |
| `PARTIAL` | Проверена часть connected edge; остаётся материальный непроверенный участок. |
| `GAP` | В выбранном caller→owner→result→consumer пути отсутствует необходимая связь. |
| `OPEN` | Требуется решение или чтение источника. |
| `BLOCKED` | Нужный источник недоступен. |
| `NOT SELECTED` | Механизм не нужен выбранной конструкции; это не полный аудит донора. |
| `NOT QUALIFIED` | Артефакт/механизм идентифицирован, но требуемый живой прогон не выполнен. |

Правила:

- README, search hit, DTO, fixture, receipt, release metadata или compilation сами по себе не дают runtime `CHECKED`;
- `IMPLEMENTED` появится только после реального input→operation→durable result/unknown→consumer→restart/readback;
- release/build provenance отличается от runtime qualification;
- новый механизм не вводится без named caller, owner, result/unknown и consumer;
- подробная хронология остаётся в Git; здесь хранится текущее состояние.

## 2. Активная матрица

### 2.1 Product, Base и memory semantics

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-001 | Product ownership | `CHECKED` design | Host/controller owns external work; daemon owns Memory application state; supervisor owns privileged installation/process effects. | Не возвращать Task/provider stack в Memory и не делать supervisor public admin service. |
| R-002 | Process family / idle drain | `DECIDED` / `NOT IMPLEMENTED` | One supervisor, daemon, active Store child, at most one disposable candidate; retained launch/root identity; finite drains. | Slice 0 process/IPC/shutdown implementation. |
| R-003 | Continuation address | `DECIDED` | Project/workspace + task or actor/session; path/branch/HEAD are environment. | Two-workspace/fork/late-result cases. |
| R-004 | Context packet identity | `CHECKED` design / `NOT IMPLEMENTED` | Rendered bytes/digest + exact revisions + gaps in ordinary observation/blob+links. | Coherent hydration and real host emission. |
| R-005 | Structured correction | `DECIDED` | Correction observation + revision/history + saved result in one transaction. | Stale conflict/replay/readback. |
| R-006 | Six tables / Store operations | `CHECKED` design / `NOT IMPLEMENTED` | STRICT DB, six SCHEMAFULL tables, fixed queries, typed DTOs and indexes. | Migration 0001/query corpus/DTOs. |
| R-007 | Current/history | `DECIDED` | Exact version handles; no fall-forward or predecessor resurrection. | Atomic publication/restart readback. |
| R-008 | Compound grounds | `PARTIAL` | Required groups/alternatives/advisory support separated. | Reducer, cycles, erase, concurrency. |
| R-009 | Retrieval arms / packing | `PARTIAL` | Exact/address/lexical/vector/relation arms independent. | Real plans/limits/noise/exception coverage. |
| R-010 | Processing-method consumer | `DECIDED` | Job freezes exact recipe revision and later consumer must read result. | Demonstrate changed later request/context. |
| R-011 | Cross-project reuse/disclosure | `DECIDED` | Origin, reuse scope and disclosure independent. | Scoped queries and deterministic reduction. |
| R-012 | Native hook capture | `CHECKED` design / `NOT IMPLEMENTED` | Finite Claude event profile selected. | Installed-build payload qualification. |
| R-013 | Native context delivery | `CHECKED` design / `NOT IMPLEMENTED` | Actual packet crosses host boundary; prepared/emitted/use distinct. | Timeout/resume/compact/fork/subagent cases. |
| R-019 | Backup/restore | `DECIDED` / `NOT IMPLEMENTED` | Application typed backup; restore is exact rollback, not invented row merge. | Windows round-trip, safety/disaster paths. |
| R-020 | Erasure/reappearance | `PARTIAL` | Monotonic fence, replay drain, controller fence and controlled-copy inventory. | Physical traversal across all generations. |
| R-021 | Recursive improvement | `PARTIAL` | Diagnose concrete failed edge; no intelligence score. | Connected source→revision→later-context path. |
| R-022 | Disagreement/anticipation | `CHECKED` design | Alternatives + grounds + cheapest discriminating observation; no voting. | Ordinary records after Base. |
| R-023 | Control/status/inbox | `DECIDED` | Daemon owns public control; privileged effect crosses inherited channel; status from actual facts. | Operation IDs and cross-owner readback. |
| R-025 | Interpretation triggers | `DECIDED` | New committed input/correction/question only; bookkeeping does not self-trigger. | Inspect enqueue callers and loops. |
| R-026 | Active/pending jobs | `DECIDED` | One active + one coalesced pending successor; waiting ≠ retry. | Continuous arrivals/modes/shutdown. |
| R-028 | Recipe bootstrap | `DECIDED` | Save default on first enable; upgrades do not overwrite edited method. | Purpose address and first-enable code. |
| R-029 | Outcome→next decision | `DECIDED` | One contribution per method revision/attempt/criterion. | Reducer/contradiction cases. |
| R-030 | Multi-stream coverage | `DECIDED` | Per-stream ranges; selected/supplied/covered distinct. | Late child/partial/omitted/successor cases. |
| R-033 | Useful Base / light extensions | `DECIDED` | One package/internal modules/vertical increments. | Enforce imports/features/startup. |
| R-034 | Vector→context | `DECIDED` | Exact revision/representation/effective space; no zero/shifted vector. | One connected semantic query after R-015. |
| R-035 | Overconstraints | `DECIDED` | Checks at actual owner boundary; no Governor platform. | Keep unknown metadata from becoming global gate. |
| R-036 | Commitments | `DECIDED` | Ordinary scoped memory; ACK/due/notification not resolution. | Create/update/read path. |
| R-037 | Stable work identity | `DECIDED` | Work identity separate from environment. | Attach/capture/query/late result. |
| R-038 | Resource/version continuity | `DECIDED` | Dirty bytes retained; rename/copy/convert do not rewrite identity. | Edit/move/partial-read cases. |
| R-039 | Decision frame→lexical | `DECIDED` | Focused cues and native candidate arm; no LLM query planner. | Actual tokens/plans/empty input. |
| R-040 | Bounded source reads | `DECIDED` | Metadata/excerpt then identity-bound pages; units explicit. | UTF-8/long-line/JSON/file readers. |
| R-041 | Automatic work/drain | `DECIDED` | off/idle/background; finite drain; profile may deny automatic. | Manual then one automatic episode. |
| R-042 | Curation consumer | `DECIDED` | Output must alter normal context/open/method request. | Before/after consumer proof. |
| R-043 | Consolidation/split | `DECIDED` | Replay/group/revision/synthesis/split distinct; old handles survive. | Publication/history code. |
| R-044 | Forgetting changes reader | `DECIDED` | Current reader follows current revision links; rarity/use ≠ truth. | Restart/correction/negative-memory cases. |
| R-045 | First episode result | `DECIDED` | create/revise/no-change/partial/error typed; operational failure ≠ no-change. | Useful/no-change/malformed/conflict runs. |

### 2.2 Inference, external capabilities and cognition

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-014 | Controller Task/agent route | `PARTIAL` / `NOT SELECTED` baseline | Useful for real agent work, excessive for one-shot Memory inference. | Keep optional richer route only. |
| R-015 | Batch embeddings | `GAP` | Contract exists; controller method absent. | Implement same Operation/copy/release lifecycle. |
| R-016 | Research path | `PARTIAL` | Run/status/report/section/citation donors exist. | Close R-031/R-032. |
| R-017 | Project views | `PARTIAL` | Scoped versioned views selected; real tool/deployment unqualified. | Two checkouts/late result/refresh. |
| R-018 | Documents | `PARTIAL` | Original bytes, retained representation and exact open selected. | Partial page/image conversion and limits. |
| R-027 | Agent result artifact projection | `GAP` | Optional agent route loses nested artifact refs publicly. | Fix only with real consumer. |
| R-031 | Research MCP decoder | `GAP` | Old request shape rejects current method/model before service. | Connect to current decoder. |
| R-032 | Citation/index coupling | `GAP` | Retained citation can fail when active index changes. | Read retained representation/range directly. |
| R-046 | Agent-route terminal body durability | `GAP` | Boot-local LRU before page capture. | Fix only if agent route selected. |
| R-047 | One-shot inference ownership | `CHECKED` design / `NOT IMPLEMENTED` | Memory owns semantics; controller owns physical execution/readback/copies. | Controller slice. |
| R-048 | `inference.text/embed` | `GAP` | Methods absent at `e42c464d`. | Implement staged admission/runner/result/unknown. |
| R-050 | Connection/profile/privacy/budget | `CHECKED` design / `NOT IMPLEMENTED` | Static connection/profile/digests/destination/limits/no fallback. | Parser/admission/disclosure reducer. |
| R-051 | Controlled-copy lifecycle | `GAP` | Input staged, result optional, independent cleanup and three dispositions designed. | Exact file owner/recovery. |
| R-052 | ScriptRun donor | `CHECKED` / `NOT SELECTED` | Wrong lifecycle; reuse Operation/recovery ideas only. | Do not route inference through ScriptRun. |
| R-053 | Narrow caller role | `DECIDED` / `NOT IMPLEMENTED` | `inference_client` exact allowlist; no MCP/generic writer. | Role registration/dispatch/read/cancel. |
| R-054 | Inference artifact provenance | `GAP` | Current domains/deletion omit inference. | Add input/result kinds and exact cleanup owner. |
| R-055 | Operation runner/recovery | `DECIDED` / `NOT IMPLEMENTED` | Existing ledger/wake/cancel enough; generic mutate unsafe. | Custom admission + bounded runner. |
| R-056 | Direct controller IPC | `CHECKED` donor / `NOT IMPLEMENTED` adapter | Pin exact `swarm-client`; no copied protocol/MCP/CLI. | Implement one Memory adapter. |
| R-057 | Initial provider adapters | `DECIDED` / `NOT IMPLEMENTED` | Closed loopback chat/embedding adapters; no arbitrary extras/retry/fallback. | Implement text first; HTTPS later. |
| R-068 | Destination admission | `CHECKED` design / `NOT IMPLEMENTED` | Controller resolves actual connection/destination and checks disclosure. | State mapping. |
| R-069 | One Memory controller adapter | `DECIDED` / `NOT IMPLEMENTED` | One client owns text/embed/read/cancel/release. | Pin and connect. |
| R-070 | No-result cleanup / erase abandonment | `CHECKED` design / `NOT IMPLEMENTED` | Result optional; terminal cleanup and abandonment fence selected. | Implement dispositions/recovery. |

### 2.3 Development-system failure analysis

| ID | Объект | Статус | Решение / разрыв |
|---|---|---|---|
| R-058 | Delivery incentives | `CHECKED` | Artifacts displaced integrated behavior; progress denominator is connected product edge. |
| R-059 | Append-only authority | `PARTIAL` | V3 docs/registry current; V2 authorities retire at cutover. |
| R-060 | Cheap preflight / WIP | `DECIDED` | Deterministic blockers before setup; overlap waits for terminal disposition. |
| R-061 | Completion criterion | `CHECKED` design | caller→owner→durable result/unknown→consumer→restart/readback. |
| R-062 | Crate/manifest inversion | `CHECKED` representative | ~188 packages and large manifests turned helpers into products. |
| R-063 | Generated inventories | `CHECKED` | Repository scans became permanent work; do not port. |
| R-064 | Intent–mechanism inversion | `CHECKED` | Intent-first prose coexisted with mandatory object families. |
| R-065 | Crate-first capacity target | `CHECKED` correlation / `PARTIAL` causality | One package/modules until measured boundary. |
| R-066 | Identity/proof multiplication | `CHECKED` | Synchronization graph outgrew product edge. |
| R-067 | Anti-proxy without backpressure | `CHECKED` | New mechanisms require connected need, one ledger and WIP stop. |

### 2.4 Base, Store and Windows boundaries

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-071 | Legacy hook forwarder | `CHECKED` exact code / `NOT SELECTED` | `forwarded` without send; content-hash spool; no replayer. | Do not port. |
| R-072 | Relay/spool ownership | `CHECKED` design / `NOT IMPLEMENTED` | Same immutable command; committed needs Store readback; staged needs file+directory durability. | Pipe/publication/replayer. |
| R-073 | Occurrence identity | `CHECKED` design / `NOT IMPLEMENTED` | Native/command ID occurrence; digest verifies bytes only. | Schema/index/conflict code. |
| R-074 | Claude schema drift | `PARTIAL` | Public profile selected; installed build unverified. | Installed qualification. |
| R-075 | Packet handoff | `CHECKED` design / `NOT IMPLEMENTED` | Actual packet; prepared/emitted/action/use distinct. | Host effect/readback. |
| R-077 | Legacy explicit packet call | `CHECKED` exact code / `NOT SELECTED` | Packet only after agent call; no SessionStart link. | Do not port. |
| R-078 | Legacy packet authority | `CHECKED` representative / `NOT SELECTED` | Parallel authority/projection without delivery. | Ordinary data only. |
| R-079 | Legacy empty exact selector/relation loss | `CHECKED` exact path | Empty selector broadens; endpoint filter hides relations. | Exact handle + relation descriptors. |
| R-080 | Legacy read caps/cursor | `CHECKED` exact path | Fixed caps without honest continuation. | Typed cursor/envelope. |
| R-081 | Exact-open consistency | `CHECKED` design / `NOT IMPLEMENTED` | Exact current/history/source/representation handles and dispositions. | Implement readers. |
| R-082 | SurrealDB Rust SDK fit | `CHECKED` / `NOT SELECTED` baseline | SDK 3.3.4 requires Rust 1.95 vs declared 1.94; policy/size unresolved. | Reconsider only after exact preflight. |
| R-083 | Exact Windows release identity | `CHECKED` release / `NOT QUALIFIED` | v3.3.4 commit/asset/size/SHA pinned. | Download/hash/PE/signature/live run. |
| R-084 | Store RPC/replay | `CHECKED` design / `NOT IMPLEMENTED` | Peer-verified Basic query-only socket owner; exact IDs; poison ambiguous link; typed JSON DTOs. | Implement. |
| R-085 | Schema/migrations/transactions | `CHECKED` design / `NOT IMPLEMENTED` | Checksummed migrations, generation/INFO, strict schema, unique/sentinel/FOR UPDATE. | Migration 0001/conflict tests. |
| R-086 | Durable publication / selection | `CHECKED` design / `NOT IMPLEMENTED` | Immutable no-replace and mutable expected-generation replacement are distinct. | Force old/new/unknown outcomes. |
| R-087 | RocksDB runtime | `CHECKED` build provenance / `OPEN` runtime | Official Windows build includes RocksDB; live profile unrun. | Slice 0 Windows run. |
| R-088 | CLI/env/capability posture | `CHECKED` source / `NOT QUALIFIED` | `surreal start`; sanitized env and closed arguments. | Exact Windows argv/env. |
| R-089 | Store capability surface | `CHECKED` source / `NOT QUALIFIED` | HTTP rpc, RPC query, system subject only; fixed-query client is statement boundary. | Allowed/denied matrix. |
| R-090 | Surreal export/import | `CHECKED` / `NOT SELECTED` | HTTP completion can hide export failure; import partial. | Keep disabled. |
| R-091 | Root/Owner/Editor | `DECIDED` / `NOT QUALIFIED` | Short root bootstrap; supervisor root/Owner; daemon Editor. | Live role/bootstrap/migration proof. |
| R-092 | Store readiness | `CHECKED` design / `NOT QUALIFIED` | Root/binary/process/listener/peer/ready/auth/socket/schema/typed probe conjunction. | Failure matrix. |
| R-093 | Startup import | `CHECKED` / `NOT SELECTED` | Failures can be logged while server becomes ready. | Never use. |
| R-094 | Storage URL/defaults | `CHECKED` source / `NOT QUALIFIED` | Supervisor canonical root URL + sync=every; no raw URL; no-defaults. | Windows spelling/restart. |
| R-095 | Binary materialization/signature | `PARTIAL` | SHA/build known; actual Authenticode unknown; retained executable handles selected. | Inspect exact asset and launch races. |
| R-096 | Graceful shutdown | `CHECKED` source / `NOT QUALIFIED` | Daemon quiesces; supervisor stops Store; Job kill containment; clean exit not receipt. | Active-maintenance/hang/restart. |
| R-097 | Acknowledged commit durability | `CHECKED` source / `NOT QUALIFIED` | sync=every can apply before fsync error; unknown requires readback. | Crash/fsync qualification. |
| R-098 | User provisioning/log secrecy | `CHECKED` source / `NOT QUALIFIED` | Local Argon2 PASSHASH; no credential/DDL/raw error logs. | Create/rotate/log proof. |
| R-099 | Closed environment/loopback | `CHECKED` source / `NOT QUALIFIED` | Defaults too open; supervisor supplies minimal profile. | Process inspection/adversarial env. |
| R-100 | JSON wire budget | `DECIDED` / `NOT IMPLEMENTED` | Explicit DTOs only; no generic Value/SELECT */copied CBOR. | Per-query round-trips. |
| R-101 | Application backup cut | `DECIDED` / `NOT IMPLEMENTED` | Daemon coherent typed cut; manifest owns completion. | Locks/encoding/mismatch/crash. |
| R-102 | WS Origin/auth | `CHECKED` source / `NOT QUALIFIED` | CORS is not WS auth; Basic on owned peer; guest query denied. | Origin/no-auth/socket exhaustion. |
| R-103 | Dynamic listener/peer ownership | `CHECKED` design / `NOT IMPLEMENTED` | Ephemeral reservation + retained child + listener/peer PID + existing-stream handshake. | Squat/PID/peer/bind cases. |
| R-104 | Relay→daemon IPC | `CHECKED` donor/design / `NOT IMPLEMENTED` | First named-pipe instance, DACL, remote rejection, mutual live-process attestation, bounded one-request protocol. | Implement hostile cases. |
| R-105 | Retained executable identity | `CHECKED` donor/design / `NOT IMPLEMENTED` | No-follow executable/ancestor handles, bounded digest, suspended child comparison. | Exact binary/race qualification. |
| R-106 | Store socket owner/cancellation | `CHECKED` donor/design / `NOT IMPLEMENTED` | Dedicated task; late/wrong/cancel ambiguity poisons connection. | Owner state tests. |
| R-107 | Replay barrier/restore monotonicity | `CHECKED` design / `NOT IMPLEMENTED` | Pause/drain active replay; deletion union; exact spool merge. | Implement. |
| R-108 | Supervisor↔daemon privileged channel | `CHECKED` design / `NOT IMPLEMENTED` | Exact inherited anonymous pipes, closed frames/op IDs; daemon quiesce, supervisor privileged effects. | Handle-list/channel/crash cases. |
| R-109 | Mutable selection/credential generations | `CHECKED` design / `NOT IMPLEMENTED` | Expected generation, current/pending/previous refs, unknown readback, delayed retirement. | Replacement/rotation/restart. |
| R-110 | Exact rollback denominator | `CHECKED` design / `NOT IMPLEMENTED` | No post-backup row merge without change log; safety backup and previous root retain divergence. | Rollback/disaster/prior-root proof. |
| R-111 | Retained data-root identity and ACL | `CHECKED` design / `NOT IMPLEMENTED` | Closed root ID beneath protected local root; no-follow directory/ancestor lease and DACL retained for Store lifetime. | Prove RocksDB works under selected sharing/ACL; force rename/reparse/broad ACL. |
| R-112 | Fence versus physical erasure | `CHECKED` design / `NOT IMPLEMENTED` | Deletion ledger prevents reintroduction but does not erase previous/candidate roots or backups; initial Base deletes whole offline generation or reports incomplete. | Physical delete/parent flush/absence and external-copy reporting. |
| R-113 | Store credential session revocation | `CHECKED` design / `NOT IMPLEMENTED` | Password update alone does not revoke authenticated WebSocket; rotation closes sockets and restarts Store before completion. | Editor/Owner rotation under active sessions and unknown mutation. |
| R-114 | Restored controller jobs | `CHECKED` design / `NOT IMPLEMENTED` | Known Operation IDs enter reconcile-required; no redispatch; pending proven-unsent jobs may resume retained request. | Implement after controller slice. |
| R-115 | Generation backpressure | `CHECKED` design / `NOT IMPLEMENTED` | At most one unretired previous root and pending/previous credential per role; second transition blocked. | Cutover/rotation/retirement state machine. |
| R-116 | Local plaintext confidentiality boundary | `CHECKED` design / `NOT IMPLEMENTED` | Local DB/spool/backups protected by account/DACL/volume, not app encryption; off-machine copies external. | DACL qualification and future portable-backup decision only if required. |

### 2.5 Stable controller caller continuity

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-117 | Inference caller identity across token rotation/restore | `CHECKED` source design / `GAP` runtime | Pinned controller credential is `client_id + token`; handshake retains Principal; Operation stores `caller_id`; correlation key/artifact grants are exact-caller. Contract 0.5 therefore makes `controller_client_id` stable and token replaceable. Changing client_id is principal migration and orphans read/cancel/release. Existing authenticated sockets must be closed/restarted on token rotation. `e42c464d` has no inference role/method/rotation workflow. | Implement same-client-id rotation/revocation, persist non-secret caller ID in Memory jobs/backups, prove old Operation read/release after rotation and restore; block redispatch on caller mismatch. |

## 3. Source coverage

| ID | Источник | Статус / граница |
|---|---|
| S-001–S-007 | V1/V2 requirements and supplied audits/reports | `CHECKED` for previously named sections/full supplied texts; not fresh full code audit. |
| S-008 | Release ZIP `audit-2026-10-16-incomplete` | `BLOCKED`; full corpus unavailable. |
| S-009 | `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | `BLOCKED`; full text absent. |
| S-010 | Named donors D01–D47 | `PARTIAL`; findings limited to exact paths/revisions. |
| S-011 | Independent subagent review | `OPEN`; no subagent execution tool available. |
| S-012 | Consolidated failure audit | `PARTIAL`; selected path, counts/runtime not reproduced. |
| S-013–S-016 | Controller inference/taskless/IPC/transport donors through `e42c464d` | `CHECKED` selected source paths; no live provider/worker run. |
| S-017–S-019 | Delivery collapse, workspace/manifests/inventories, retained old books | `CHECKED` exact issues/samples/targeted sections. |
| S-020 | Inference Contract 0.4 synchronization | Historical `CHECKED`; superseded by 0.5. |
| S-021–S-025 | Legacy Base hooks/packet/exact read and current Base docs | `CHECKED` selected paths/design; no live host. |
| S-026–S-031 | Dependency/platform inventory, Surreal docs/release/build/start | `CHECKED` source/release identity; no Windows run. |
| S-032–S-042 | Surreal capability/export/IAM/readiness/endpoint/shutdown/RocksDB/credentials/network/JSON | `CHECKED` exact `v3.3.4` paths; no live qualification. |
| S-043 | Application backup replacement | `CHECKED` design from exact Store sources/model; no round-trip. |
| S-044–S-048 | CORS/auth, endpoint owner, named-pipe, process-path, WebSocket lifecycle donors | `CHECKED` exact donors; no V3 implementation. |
| S-049 | Inherited supervisor-channel primitives | `CHECKED` Win32 docs + exact handle-list donor; no live channel. |
| S-050 | Mutable selection replacement | `CHECKED` Win32 MoveFileEx/ReplaceFile/Flush docs; no crash run. |
| S-051 | Restore merge denominator | `CHECKED` current model + absence of change log; exact rollback selected. |
| S-052 | Data-root/access and controlled-copy boundary | `CHECKED` current Windows/profile design; DACL/root lease/physical deletion unrun. |
| S-053 | Controller caller credential and handshake at `e42c464d` | `CHECKED`: `Credential {client_id, token}`, `client.hello`, retained Principal per connection. |
| S-054 | Controller exact-caller Operation/artifact scope at `e42c464d` | `CHECKED`: Operation stores caller_id; client_request_id projects only to same client_id; ExactCaller/ExactResultOperationCaller grants exist. |
| S-055 | Current normative synchronization | `PARTIAL`: Architecture 9 / Implementation 28 / README cover physical boundaries; Contract 0.5 adds caller continuity not yet mirrored in Implementation job fields/Cognition/README. |

## 4. Current findings

### Store/Windows/Base

- Store child identity includes retained executable **and selected data-root** identity; a config path is not enough.
- Daemon and supervisor are separate authority/failure domains. Public control stays with daemon; root/Owner/process/cutover stays with supervisor through one inherited closed channel.
- Store transport is query-only, peer-verified and cancellation-safe; Origin/CORS is not authorization.
- `sync=every` still has an applied-before-fsync-error edge; unknown outcome reconciles by application identity.
- Immutable publication and mutable selection replacement require different primitives.
- Backup is a coherent application cut; restore is exact rollback, not invented merge.
- Deletion fence prevents reintroduction but does not prove physical deletion of offline roots/backups.
- Password rotation must revoke live sessions; Store restart is part of completion.
- Previous generations are bounded and retired explicitly; pointer update never hides remaining bytes/secrets.
- Local backup is plaintext under Windows account/DACL, not portable encrypted backup.

### Controller caller continuity

Exact controller source establishes this chain:

```text
Credential { client_id, token }
→ client.hello
→ authenticated Principal retained for connection
→ Operation caller_id = principal.client_id
→ client_request_id projected only to same client_id
→ result artifact granted to exact result-operation caller
```

Therefore:

```text
token rotation with same client_id
  can preserve retained ownership after connection revocation/reconnect

new client_id
  is a different principal
  cannot normally read/cancel/release old Operations
  must not redispatch them under a new request
```

Contract 0.5 now owns the required stable principal and restore behavior. The controller implementation remains absent.

## 5. Frozen anti-patterns

Do not:

- create another registry, task manager, supervisor API, admin bus or proof platform;
- pass root/Owner, arbitrary SQL/path/argv/endpoint/secret into daemon control;
- change inference `client_id` during token rotation;
- keep authenticated controller/Store sockets alive after credential revocation;
- recover old inference through Operator/admin as normal path or issue a new request ID;
- claim physical erasure from a deletion fence while previous root/backup remains;
- run another cutover/rotation before prior generation is retired;
- claim portable encrypted backup from a local plaintext generation;
- merge post-backup Store rows without retained change log/conflict policy;
- use broad raw SurrealQL/generic CRUD/Value/SELECT *;
- equate path/PID/port/health/ready/101/acknowledgement with ownership or completion;
- use content digest as occurrence identity;
- report staged before file+directory durability/readback;
- replay possible mutation/inference after unknown outcome;
- treat clean process exit as durability receipt;
- silently fall back provider/model/destination/Store version/engine;
- port V2 crate/manifest/inventory/lease/proof machinery without a connected consumer.

## 6. Queue

| Priority | Work | Closes |
|---|---|---|
| P0 | Synchronize Implementation/Cognition/README with Contract 0.5 stable `controller_client_id`, credential generation and restore mismatch state; do not create another contract. | R-024, R-056, R-069, R-114, R-117, S-055 |
| P0 | Slice 0: exact binaries; executable/root leases+DACL; inherited supervisor channel; relay pipe; canonical RocksDB sync=every/no-defaults; sanitized env; listener/peer; root/Owner/Editor; query-only socket owner; DTO/migrations/conflicts/fsync unknown; immutable/mutable files; replay barrier; protected backup/exact rollback; physical erasure; credential revocation; generation backpressure; graceful/forced shutdown. | R-002, R-006, R-019–R-020, R-072–R-073, R-081–R-116 |
| P1 | Base Slice 1: supervisor/daemon/Store, selection owner, IPC/socket owners, migrations, capture/blob/spool/replay/status/restart/open. | R-001–R-007, R-019–R-020, R-033, R-037–R-040, R-071–R-116 |
| P1 | Base Slice 2: qualified Claude relay, continuation, packet emission, lexical retrieval, exact open, notes/corrections/commitments, backup/rollback/erase. | R-003–R-013, R-023, R-036, R-039–R-044, R-074–R-081, R-101, R-104, R-107–R-116 |
| P1 | Controller inference slice: stable caller registration/rotation, role, profiles, artifacts, runner, text/readback/release; no Task/ScriptRun/new table. | R-048, R-050–R-057, R-068–R-070, R-117 |
| P1 | One Memory controller adapter and first episode-learning path; restore reconciles old Operations without duplicate inference. | R-010, R-021, R-028–R-030, R-041–R-045, R-047–R-057, R-069–R-070, R-114, R-117 |
| P1 | One integrator/product edge/cheap preflight/terminal overlap disposition per slice. | R-058–R-061, R-067 |
| P2 | Installed Claude qualification. | R-012–R-013, R-074, S-022 |
| P2 | Embeddings/vector, optional agent projection, Research fixes, documents/views/grounds as independent increments. | R-008, R-014–R-018, R-027, R-031–R-032, R-034, R-046 |
| P2 | Retire V2 generated inventories/manifests during cutover. | R-059, R-063 |
| P3 | Obtain unavailable ZIP/report; deepen donors only for a selected unresolved edge. | S-008–S-010 |
| Final | Full tests after connected implementation; minimum relevant build/Clippy during code. | R-049 |

## 7. Recent changes

| Date / baseline | Change |
|---|---|
| 2026-10-23–24 | Episode recipe, controller boundary and Contract 0.1–0.4; R-047–R-070. |
| 2026-10-24 | Delivery collapse, anti-bureaucracy, Base capture/packet/open; R-058–R-081. |
| 2026-10-25 | Store/schema/Windows/release/capability/readiness/durability/backup; R-082–R-103. |
| 2026-10-26 / draft.26–27 | Relay IPC, retained launch, replay barrier, privileged channel, mutable selection, exact rollback; R-104–R-110. |
| 2026-10-26 / draft.28 | Retained data-root/DACL, physical erasure, restored-job reconciliation, session revocation, generation backpressure and local plaintext boundary; R-111–R-116. |
| 2026-10-26 / Contract 0.5 | Stable controller caller identity, same-client token rotation/revocation and restore continuity; R-117, S-053–S-055. |
