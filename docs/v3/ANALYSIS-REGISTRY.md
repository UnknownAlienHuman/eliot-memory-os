# Eliot V3 — реестр анализа

**Статус на 2026-10-26 · Architecture draft.10 / Implementation draft.31 / Cognition draft.14 / Inference Contract 0.9; controller authority `c8c0ee122c98a01be86bc5296a22a389662a1c89`; активный рабочий реестр, не runtime gate.**

Это **единственный активный реестр** V3. Он хранит текущее решение, границу доказательства, оставшийся разрыв и следующий connected step. [AUDIT](AUDIT.md) и [AUDIT-MAP](AUDIT-MAP.md) сохраняют исходные доказательства и stable dispositions; новый проход обновляет этот файл, а не создаёт новый отчёт.

## 1. Статусы

| Статус | Значение |
|---|---|
| `CHECKED` | Указанный source/design scope прочитан и вывод согласован. Не означает работающий runtime. |
| `DECIDED` | Для V3 выбрано решение; код/живой прогон отсутствует. |
| `PARTIAL` | Проверена часть connected edge; остаётся материальный непроверенный участок. |
| `GAP` | В caller→owner→result/unknown→consumer пути отсутствует необходимая связь. |
| `OPEN` | Требуется решение или чтение источника. |
| `BLOCKED` | Нужный источник недоступен. |
| `NOT SELECTED` | Механизм не нужен выбранной конструкции. |
| `NOT QUALIFIED` | Артефакт/механизм найден, но требуемый живой прогон не выполнен. |
| `SUPERSEDED` | Решение относилось к прежнему baseline; текущая authority выбрала другой механизм. |

Правила:

- README, DTO, fixture, receipt, CI или compilation сами по себе не дают runtime `CHECKED`;
- `IMPLEMENTED` появляется только после реального input→operation→durable result/unknown→consumer→restart/readback;
- новый механизм не вводится без named caller, owner, result/unknown и consumer;
- controller V1 используется только как явно названный donor; реализация идёт против текущего controller V2;
- подробная хронология остаётся в Git; здесь хранится текущее состояние.

## 2. Активная матрица

### 2.1 Product, Base и memory semantics

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-001 | Product ownership | `CHECKED` design | Host/controller owns external work; Memory daemon owns memory semantics/state; supervisor owns privileged installation/process effects. | Не возвращать Task/provider stack в Memory. |
| R-002 | Process family / idle drain | `DECIDED` / `NOT IMPLEMENTED` | Supervisor + daemon + active Store child + at most one candidate; retained identities; finite drains. | Slice 0 process/IPC/shutdown. |
| R-003 | Continuation address | `DECIDED` | Project/workspace + task or actor/session; path/branch/HEAD are environment. | Fork/two-workspace/late-result cases. |
| R-004 | Context packet identity | `CHECKED` design / `NOT IMPLEMENTED` | Rendered bytes/digest + exact revisions + gaps in ordinary data. | Real host emission/readback. |
| R-005 | Structured correction | `DECIDED` | Correction observation + revision/history + saved result atomically. | Conflict/replay/readback. |
| R-006 | Six tables / Store operations | `CHECKED` design / `NOT IMPLEMENTED` | `stream`, `observation`, `memory`, `memory_history`, `link`, `job`; strict schema, fixed queries, DTOs/indexes. | Migration 0001/query corpus. |
| R-007 | Current/history | `DECIDED` | Exact version handles; no fall-forward or predecessor resurrection. | Publication/restart readback. |
| R-008 | Compound grounds | `PARTIAL` | Required groups, alternatives and advisory support separated. | Reducer/cycle/erase/concurrency. |
| R-009 | Retrieval arms / packing | `PARTIAL` | Exact/address/lexical/vector/relation arms independent. | Real plans/limits/noise/exceptions. |
| R-010 | Processing-method consumer | `DECIDED` | Job freezes exact recipe revision; later consumer must actually read result. | Demonstrate changed later context. |
| R-011 | Reuse/disclosure | `DECIDED` | Origin, reuse scope and disclosure are independent. | Scoped queries/reduction. |
| R-012 | Native hook capture | `CHECKED` design / `NOT IMPLEMENTED` | Finite Claude event profile. | Installed-build payload qualification. |
| R-013 | Native context delivery | `CHECKED` design / `NOT IMPLEMENTED` | Actual packet crosses host boundary; prepared/emitted/use distinct. | Resume/compact/fork/subagent cases. |
| R-019 | Backup/restore | `CHECKED` design / `NOT IMPLEMENTED` | Typed application backup, brief spool cut, exact rollback and controller high-water inventory; no invented row merge or result adoption. | Windows round-trip, safety/disaster/history-gap cases. |
| R-020 | Erasure/reappearance | `PARTIAL` | Monotonic fence + physical controlled-copy traversal; provider-side effects external. | All generations/copies. |
| R-021 | Recursive improvement | `PARTIAL` | Diagnose a concrete failed edge; no intelligence score. | Source→revision→later-context path. |
| R-022 | Disagreement/anticipation | `CHECKED` design | Alternatives + grounds + cheapest discriminating observation; no voting. | Ordinary records after Base. |
| R-023 | Control/status/inbox | `DECIDED` | Daemon public control; supervisor closed privileged effects; status from readback. | Operation/readback paths. |
| R-024 | Normative synchronization | `CHECKED` design / `NOT IMPLEMENTED` | Architecture 10, Implementation 31, Cognition 14, Contract 0.9 and README agree on controller V2 `memory_inference`, pre-send `WriteId`, token_version, private copies, high-water restore inventory and brief spool cut. | Change all owner docs together when mechanism changes. |
| R-025 | Interpretation triggers | `DECIDED` | New committed input/correction/question only; bookkeeping does not self-trigger. | Inspect enqueue callers. |
| R-026 | Active/pending jobs | `DECIDED` | One active + one coalesced successor; waiting ≠ retry. | Arrival/shutdown modes. |
| R-028 | Recipe bootstrap | `DECIDED` | Save default on first enable; upgrades do not overwrite edited method. | First-enable code. |
| R-029 | Outcome→next decision | `DECIDED` | One contribution per method revision/attempt/criterion. | Contradiction reducer. |
| R-030 | Multi-stream coverage | `DECIDED` | Selected/supplied/covered ranges remain distinct. | Late child/partial/omitted cases. |
| R-033 | Useful Base / light extensions | `DECIDED` | One package/internal modules/vertical increments. | Enforce startup/import boundaries. |
| R-034 | Vector→context | `DECIDED` | Exact revision/representation/effective space; no zero/shifted vector. | One connected semantic query. |
| R-035 | Overconstraints | `DECIDED` | Checks at actual owner boundary; no Governor platform. | Prevent metadata gates. |
| R-036 | Commitments | `DECIDED` | Ordinary scoped memory; ACK/due/notification is not resolution. | Create/update/read path. |
| R-037 | Stable work identity | `DECIDED` | Work identity separate from environment. | Attach/capture/query/late result. |
| R-038 | Resource/version continuity | `DECIDED` | Dirty bytes retained; rename/copy/convert do not rewrite identity. | Edit/move/partial-read. |
| R-039 | Decision frame→lexical | `DECIDED` | Focused cues and native lexical arm; no LLM query planner. | Actual token/plans. |
| R-040 | Bounded source reads | `DECIDED` | Metadata/excerpt then identity-bound pages; explicit units. | UTF-8/long-line/JSON/file readers. |
| R-041 | Automatic work/drain | `DECIDED` | off/idle/background; finite drain; profile may deny automatic. | Manual then automatic episode. |
| R-042 | Curation consumer | `DECIDED` | Output must change normal context/open/method request. | Before/after consumer proof. |
| R-043 | Consolidation/split | `DECIDED` | Replay/group/revision/synthesis/split distinct; old handles survive. | Publication/history. |
| R-044 | Forgetting changes reader | `DECIDED` | Current reader follows current revision links; rarity/use ≠ truth. | Restart/correction/negative-memory. |
| R-045 | First episode result | `DECIDED` | create/revise/no-change/partial/error typed; operational failure ≠ no-change. | Useful/malformed/conflict runs. |

### 2.2 Inference, external capabilities and cognition

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-014 | Agent route | `NOT SELECTED` baseline | Real agent work may use controller Agents; one-shot Memory inference must not. | Keep richer route separate. |
| R-015 | Batch embeddings | `GAP` | Contract 0.9 defines shape; controller V2 method/runtime absent. | Later after connected text path. |
| R-016 | Research path | `PARTIAL` | Run/status/report/section/citation donors exist. | Close R-031/R-032. |
| R-017 | Project views | `PARTIAL` | Scoped versioned views selected; deployment unqualified. | Two-checkout/late-result refresh. |
| R-018 | Documents | `PARTIAL` | Original bytes, retained representation and exact open selected. | Partial-page/image conversion. |
| R-027 | Agent result artifact projection | `GAP` | Optional richer route loses nested artifact refs publicly. | Fix only with real consumer. |
| R-031 | Research decoder | `GAP` | Old request shape rejects current method/model before service. | Current decoder. |
| R-032 | Citation/index coupling | `GAP` | Retained citation may fail after active index change. | Read retained representation directly. |
| R-046 | Agent terminal body durability | `GAP` | Optional route uses boot-local body before page capture. | Fix only if selected. |
| R-047 | One-shot ownership | `CHECKED` design / `NOT IMPLEMENTED` | Memory owns semantics; controller owns physical execution/readback/copies. | Controller V2 extension. |
| R-048 | `inference.text/embed` | `GAP` | No current controller V2 methods. | Implement Contract 0.9 after controller L1. |
| R-049 | Verification order | `DECIDED` | Production code first; scoped build/Clippy after coherent increments; full suite after connected product. | Apply during code. |
| R-050 | Profile/privacy/budget | `CHECKED` design / `NOT IMPLEMENTED` | Static connection/profile/destination/limits; no fallback. | V2 config/admission. |
| R-051 | Controlled-copy lifecycle | `DECIDED` / `NOT IMPLEMENTED` | Private call-owned input/result files; independent cleanup/dispositions. | Exact file owner/recovery. |
| R-052 | Script/automation donor | `CHECKED` / `NOT SELECTED` | Controller V2 automation journal has wrong principal/trigger lifecycle. | Do not route inference through it. |
| R-053 | Narrow caller | `DECIDED` / `NOT IMPLEMENTED` | Dedicated `memory_inference`; no owner/Agent/project/automation fallback. | Registration/allowlist/fence. |
| R-054 | Inference provenance | `GAP` | Memory deletion/backup must include controller call/copy facts. | Add exact call/copy identities. |
| R-055 | Runner/recovery | `DECIDED` / `NOT IMPLEMENTED` | One bounded `inference_calls` runner; queued once, sending→readback/unknown. | V2 call row/runner. |
| R-056 | Controller IPC | `CHECKED` current design / `GAP` runtime | Use V2 JSON-RPC client and `client.identity`; V1 `swarm-client` is donor only. | Implement after V2 API. |
| R-057 | Initial adapters | `DECIDED` / `NOT IMPLEMENTED` | Closed loopback chat/embedding subsets; no extras/retry/redirect/fallback. | Text first. |
| R-068 | Destination admission | `CHECKED` design / `NOT IMPLEMENTED` | Controller resolves actual destination and checks disclosure. | State mapping. |
| R-069 | One Memory adapter | `DECIDED` / `NOT IMPLEMENTED` | One adapter owns identity/text/read/cancel/release/high-water/list. | Connect first learning loop. |
| R-070 | No-result cleanup / erase abandonment | `CHECKED` design / `NOT IMPLEMENTED` | Result optional; release and late-publication fence explicit. | Dispositions/recovery. |
| R-114 | Restored controller jobs | `SUPERSEDED` mechanism / `DECIDED` goal | Old unknown-Operation-ID path removed: Memory persists `WriteId` before send; same ID replays admission/readback. | Implement Contract 0.9 restore. |
| R-117 | Stable caller continuity | `CHECKED` design / `GAP` runtime | Stable `client_id`; V2 `token_version` rotates without changing call ownership. | Pre/post-rotation call read/release. |
| R-118 | V1 protocol-v2 hello | `SUPERSEDED` | Current authority is V2 JSON-RPC; selected identity read is `client.identity`. | Keep only as donor history. |
| R-119 | Owner erasure vs result bytes | `DECIDED` / `GAP` runtime | Owner can fence/erase exact calls by non-content facts; result bytes stay exact caller only. | Denial matrix. |
| R-120 | V1 pending credential bundle | `SUPERSEDED` | V2 owner command + deterministic token derivation removes unrecoverable-token window. | Keep only as donor history. |
| R-121 | Current-version fence | `DECIDED` / `GAP` runtime | Every Memory read/mutation reloads current registration/token_version; stale transport closes. | Per-dispatch fence. |
| R-122 | Reconcile-or-admit | `SUPERSEDED` | V2 external `WriteId` already provides exact retry/first admission/conflict. | Keep only as donor history. |
| R-123 | Current controller authority | `CHECKED` | `c8c0ee1` / PR #197 selects fresh SQLite/JSON-RPC/WriteId V2 and marks current Rust stack legacy. | Never implement against V1. |
| R-124 | Dedicated Memory principal | `DECIDED` / `NOT IMPLEMENTED` | `memory_inference` stable client + scoped token; no owner, Agent or automation reuse. | Controller decision/code after L1. |
| R-125 | `WriteId` call identity | `DECIDED` / `NOT IMPLEMENTED` | Memory commits ULID before send; call ID = WriteId; same payload returns same call. | Receipt/call integration. |
| R-126 | Minimal V2 durable state | `DECIDED` / `NOT IMPLEMENTED` | Reuse `write_receipts`; add only client registration + `inference_calls`; content files remain private. | Schema/retention/runner. |
| R-128 | Restore external-work inventory | `DECIDED` / `NOT IMPLEMENTED` | Backup stores controller admission high-water; restore inventories calls after cut and disables new inference until disposition. | high-water/list path. |
| R-129 | Inference retention gap | `DECIDED` / `NOT IMPLEMENTED` | Controller advances `earliest_retained_seq`; old restore gets `history_gap`, never false empty. | Retention/read contract. |

### 2.3 Development-system failure analysis

| ID | Объект | Статус | Решение / разрыв |
|---|---|---|---|
| R-058 | Delivery incentives | `CHECKED` | Integrated behavior, not artifact count, is progress denominator. |
| R-059 | Append-only authority | `CHECKED` design | V1 controller mechanism was replaced in-place in all current owner docs instead of adding an errata layer. |
| R-060 | Cheap preflight / WIP | `DECIDED` | Deterministic blockers before setup; overlap waits for terminal disposition. |
| R-061 | Completion criterion | `CHECKED` design | caller→owner→durable result/unknown→consumer→restart/readback. |
| R-062 | Crate/manifest inversion | `CHECKED` representative | Large package graph turned helpers into products. |
| R-063 | Generated inventories | `CHECKED` | Repository scans became permanent work; do not port. |
| R-064 | Intent–mechanism inversion | `CHECKED` | Intent prose coexisted with mandatory object families. |
| R-065 | Crate-first capacity target | `CHECKED` correlation / `PARTIAL` causality | One package/modules until measured boundary. |
| R-066 | Identity/proof multiplication | `CHECKED` | Synchronization graph outgrew product edge. |
| R-067 | Anti-proxy without backpressure | `CHECKED` | New mechanisms require connected need, one ledger and WIP stop. |

### 2.4 Base, Store and Windows boundaries

| ID | Объект | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|
| R-071 | Legacy hook forwarder | `CHECKED` / `NOT SELECTED` | `forwarded` without send; no replayer. | Do not port. |
| R-072 | Relay/spool ownership | `CHECKED` design / `NOT IMPLEMENTED` | One immutable command; committed needs Store readback; staged needs file+directory durability. | Pipe/publication/replayer. |
| R-073 | Occurrence identity | `CHECKED` design / `NOT IMPLEMENTED` | Native/command ID identifies occurrence; digest verifies bytes only. | Schema/index/conflict. |
| R-074 | Claude schema drift | `PARTIAL` | Public profile selected; installed build unverified. | Installed qualification. |
| R-075 | Packet handoff | `CHECKED` design / `NOT IMPLEMENTED` | Actual packet; prepared/emitted/action/use distinct. | Host effect/readback. |
| R-077 | Legacy explicit packet call | `CHECKED` / `NOT SELECTED` | Packet only after agent call; no SessionStart link. | Do not port. |
| R-078 | Legacy packet authority | `CHECKED` / `NOT SELECTED` | Parallel projection without delivery. | Ordinary data only. |
| R-079 | Empty exact selector/relation loss | `CHECKED` | Empty selector broadens; endpoint filter hides relations. | Exact handle + descriptors. |
| R-080 | Read caps/cursor | `CHECKED` | Fixed caps without continuation are incomplete. | Typed cursor/envelope. |
| R-081 | Exact-open consistency | `CHECKED` design / `NOT IMPLEMENTED` | Exact current/history/source/representation handles/dispositions. | Readers. |
| R-082 | Surreal Rust SDK fit | `CHECKED` / `NOT SELECTED` baseline | SDK toolchain/policy cost unresolved; fixed JSON RPC chosen. | Reconsider only after measured need. |
| R-083 | Windows release identity | `CHECKED` release / `NOT QUALIFIED` | Surreal 3.3.4 asset/commit/size/SHA pinned. | Download/hash/PE/signature/live. |
| R-084 | Store RPC/replay | `CHECKED` design / `NOT IMPLEMENTED` | Peer-verified Basic query-only socket owner; exact IDs; poison ambiguity; DTOs. | Implement. |
| R-085 | Schema/migrations/transactions | `CHECKED` design / `NOT IMPLEMENTED` | Checksummed migrations, strict schema, unique/sentinel/FOR UPDATE. | Migration 0001. |
| R-086 | Durable publication / selection | `CHECKED` design / `NOT IMPLEMENTED` | Immutable no-replace and mutable expected-generation replace are distinct. | Old/new/unknown outcomes. |
| R-087 | RocksDB runtime | `CHECKED` provenance / `OPEN` runtime | Official build includes RocksDB; live profile unrun. | Slice 0. |
| R-088 | CLI/env/capability posture | `CHECKED` source / `NOT QUALIFIED` | Closed argv/env/profile. | Windows process inspection. |
| R-089 | Store capability surface | `CHECKED` source / `NOT QUALIFIED` | RPC query/system only; fixed-query statement boundary. | Allowed/denied matrix. |
| R-090 | Export/import | `CHECKED` / `NOT SELECTED` | Completion/partial failure semantics unsafe. | Keep disabled. |
| R-091 | Root/Owner/Editor | `DECIDED` / `NOT QUALIFIED` | Short root bootstrap; supervisor root/Owner; daemon Editor. | Live provisioning. |
| R-092 | Store readiness | `CHECKED` design / `NOT QUALIFIED` | Root/binary/process/listener/peer/ready/auth/socket/schema/typed probe conjunction. | Failure matrix. |
| R-093 | Startup import | `CHECKED` / `NOT SELECTED` | Server may become ready after import failure. | Never use. |
| R-094 | Storage URL/defaults | `CHECKED` source / `NOT QUALIFIED` | Canonical root URL + sync=every + no-defaults. | Windows spelling/restart. |
| R-095 | Binary materialization/signature | `PARTIAL` | SHA/build known; Authenticode/live launch unknown. | Inspect exact asset. |
| R-096 | Graceful shutdown | `CHECKED` source / `NOT QUALIFIED` | Daemon quiesce; supervisor Store stop; Job containment; exit not receipt. | Active-maintenance/hang. |
| R-097 | Commit durability | `CHECKED` source / `NOT QUALIFIED` | sync=every still allows applied-before-fsync-error; readback required. | Crash/fsync run. |
| R-098 | User provisioning/log secrecy | `CHECKED` source / `NOT QUALIFIED` | PASSHASH; no credential/raw-error logging. | Create/rotate/log proof. |
| R-099 | Closed environment/loopback | `CHECKED` source / `NOT QUALIFIED` | Minimal env and exact loopback owner. | Adversarial env. |
| R-100 | JSON wire budget | `DECIDED` / `NOT IMPLEMENTED` | Explicit DTOs; no generic Value/`SELECT *`/copied CBOR. | Query round-trips. |
| R-101 | Application backup cut | `CHECKED` design / `NOT IMPLEMENTED` | Coherent typed cut; manifest owns completion; spool publication locked only for exact cut. | Windows backup/crash qualification. |
| R-102 | WS Origin/auth | `CHECKED` source / `NOT QUALIFIED` | CORS is not auth; Basic on owned peer; guest query denied. | Origin/no-auth/exhaustion. |
| R-103 | Listener/peer ownership | `CHECKED` design / `NOT IMPLEMENTED` | Reservation + retained child + listener/peer PID + stream handshake. | Squat/PID/peer. |
| R-104 | Relay→daemon IPC | `CHECKED` donor/design / `NOT IMPLEMENTED` | First pipe instance, DACL, remote rejection, mutual process attestation. | Hostile cases. |
| R-105 | Retained executable identity | `CHECKED` donor/design / `NOT IMPLEMENTED` | No-follow handles, digest, suspended child comparison. | Binary/race qualification. |
| R-106 | Store socket owner/cancellation | `CHECKED` donor/design / `NOT IMPLEMENTED` | Dedicated task; late/wrong/cancel ambiguity poisons socket. | Owner tests. |
| R-107 | Replay barrier/restore monotonicity | `CHECKED` design / `NOT IMPLEMENTED` | Pause/drain active replay; deletion union; exact spool cut/continuity. | Implement. |
| R-108 | Privileged inherited channel | `CHECKED` design / `NOT IMPLEMENTED` | Anonymous pipes, closed frames/op IDs; daemon quiesce, supervisor effects. | Handle/channel/crash. |
| R-109 | Selection/credential generations | `CHECKED` design / `NOT IMPLEMENTED` | Expected generation, current/pending/previous, unknown readback, delayed retirement. | Replacement/rotation. |
| R-110 | Exact rollback denominator | `CHECKED` design / `NOT IMPLEMENTED` | No post-backup row merge; safety backup/previous root retain divergence. | Rollback/disaster. |
| R-111 | Data-root identity/ACL | `CHECKED` design / `NOT IMPLEMENTED` | Protected local root, retained no-follow identity/DACL. | RocksDB sharing/ACL. |
| R-112 | Fence vs physical erasure | `CHECKED` design / `NOT IMPLEMENTED` | Offline root/backup must be deleted whole or erasure remains incomplete. | Delete/flush/absence. |
| R-113 | Store credential revocation | `CHECKED` design / `NOT IMPLEMENTED` | Password change alone does not revoke WS; close sockets/restart Store. | Active-session rotation. |
| R-115 | Generation backpressure | `CHECKED` design / `NOT IMPLEMENTED` | At most one unretired previous root/credential generation. | Transition state machine. |
| R-116 | Local plaintext boundary | `CHECKED` design / `NOT IMPLEMENTED` | DB/spool/backups protected by account/DACL/volume, not app encryption. | DACL qualification. |
| R-127 | Backup spool publication cut | `CHECKED` design / `NOT IMPLEMENTED` | Brief exact inventory/generation cut; release lock before long copy; post-cut staging continues. | Windows file primitive and crash/delta cases. |

## 3. Source coverage

| ID | Источник | Статус / граница |
|---|---|---|
| S-001–S-007 | V1/V2 requirements and supplied audits | `CHECKED` named scopes; not fresh full-code audit. |
| S-008 | Release ZIP `audit-2026-10-16-incomplete` | `BLOCKED`; full corpus unavailable. |
| S-009 | `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | `BLOCKED`; full text absent. |
| S-010 | Named donors D01–D47 | `PARTIAL`; exact paths/revisions only. |
| S-011 | Independent subagent review | `OPEN`; no subagent execution tool exposed. |
| S-012 | Consolidated failure audit | `PARTIAL`; selected evidence, counts/runtime not reproduced. |
| S-013–S-019 | Controller V1/taskless/IPC/delivery donors through `e42c464d` | `CHECKED` donor scope; no longer implementation authority. |
| S-020 | Inference Contract 0.1–0.8 | Historical; superseded by 0.9. |
| S-021–S-025 | Legacy Base hooks/packet/open + current Base docs | `CHECKED` selected paths/design; no live host. |
| S-026–S-052 | Surreal release/build/capabilities/IAM/network/JSON/Windows durability/selection/restore | `CHECKED` exact source/design; no full Windows runtime. |
| S-053–S-057 | Controller V1 credential/hello/Operation/artifact/provisioning source | `CHECKED` donor facts; superseded as target. |
| S-058 | Controller V2 authority `c8c0ee1`, merged PR #197 | `CHECKED`: fresh build, SQLite WAL, local JSON-RPC, WriteId, old runtime legacy. |
| S-059 | Controller V2 vision/architecture/decisions/roadmap | `CHECKED`: no Task engine; Memory requires explicit extension; L1 foundation absent. |
| S-060 | Controller V2 API/core/configuration/monitoring/automation | `CHECKED`: owner/Agent/automation identities do not fit Memory; WriteId/receipt, token, custody and retention donors selected. |
| S-061 | Controller PR #197 review threads | `CHECKED`: custody race, token revocation, secret allowlists, receipt retention and activation defects corrected in current spec. |
| S-062 | Backup/spool lock analysis | `CHECKED`: long publication lock blocks relay staging; brief cut selected. |
| S-063 | Disaster rollback external-work analysis | `CHECKED`: high-water/list/history-gap closes post-backup controller-call denominator. |
| S-064 | Contract 0.9 + owner-doc synchronization | `CHECKED` design / `NOT IMPLEMENTED`: Architecture 10 / Implementation 31 / Cognition 14 / Contract 0.9 / README agree. |

## 4. Current findings

### Controller V2 boundary

```text
Memory persists WriteId before send
→ authenticated V2 JSON-RPC memory_inference principal
→ receipt lookup / id_conflict / first admission
→ one inference_calls row + private input/result copies
→ bounded runner: queued → sending → settled|failed|unknown
→ exact caller range-read/release
→ later Memory consumer
```

- `e42c464d` is donor-only. Adding Memory methods to its `swarm-client`/Operation stack would implement against code selected for deletion.
- V2 no-token owner fallback is too broad; Agent token is generation-bound; project automation is rule-owned. None is the Memory principal.
- `WriteId` removes the unknown-Operation-ID branch. Lost reply repeats the same ID and exact bytes.
- Generic V2 artifacts are nonsecret configuration snapshots; prompts/results need private call-owned files.
- One client-registration row and one `inference_calls` row are the minimum honest new state.
- Restore needs `admission_seq/high_water/earliest_retained_seq`; a missing range is `history_gap`, not empty.

### Store/Windows/Base

- Store identity includes retained executable **and selected data-root** identity.
- Daemon and supervisor are separate authority/failure domains; privileged effects cross one inherited closed channel.
- Store transport is query-only, peer-verified and cancellation-safe; Origin/CORS is not authorization.
- `sync=every` still has applied-before-fsync-error; unknown reconciles by application identity.
- Immutable publication and mutable selection need different primitives.
- Backup is a coherent application cut; restore is exact rollback, not row merge.
- Spool publication lock covers only the exact cut; relay may stage post-cut events during long backup copy.
- Deletion fence prevents reintroduction but does not prove deletion of offline roots/backups.
- Store password rotation must revoke authenticated sockets; restart is part of completion.
- Previous generations are bounded and retired explicitly.
- Local backup is plaintext under account/DACL/volume security, not portable encrypted backup.

### Synchronization state

Architecture draft.10, Implementation draft.31, Cognition draft.14, Contract 0.9 and README now consistently select:

```text
controller V2 authority
memory_inference stable client
token_version current credential fence
pre-send WriteId as call identity
write_receipts + minimal inference_calls state
private input/result copies
one provider attempt / unknown without replay
brief spool cut
controller high-water + list + history_gap on restore
```

This is source/design synchronization only. Runtime remains absent.

## 5. Frozen anti-patterns

Do not:

- implement Memory inference in controller V1 or revive its roles/Operation/artifact surface;
- authenticate Memory as controller owner, Agent, project automation, script or no-token fallback;
- create another Task/Attempt/workflow/receipt/submission ledger;
- use a new `WriteId` after uncertain submission;
- place prompts/results in generic nonsecret artifacts, receipts, config or logs;
- replay provider work after possible send;
- infer external-call ordering from ULID time instead of controller admission sequence;
- treat post-backup controller inventory gap as empty;
- adopt post-backup result into restored cognition without exact job/source mapping;
- hold spool publication lock while paging Store or copying backup bytes;
- pass root/Owner, arbitrary SQL/path/argv/endpoint/secret into daemon control;
- claim physical erasure while previous root/backup/call copy remains;
- run a second cutover/rotation before prior generation retires;
- merge post-backup Store rows without retained change log/conflict policy;
- use broad SurrealQL/generic CRUD/Value/`SELECT *`;
- equate path/PID/port/health/ready/101/ack with ownership/completion;
- use content digest as occurrence identity;
- report staged before file+directory durability/readback;
- treat clean process exit as durability receipt;
- silently fall back provider/model/destination/Store version/engine;
- port generated inventories/lease/proof machinery without a connected consumer.

## 6. Queue

| Priority | Work | Closes |
|---|---|---|
| P0 | Slice 0: exact binaries; executable/root leases+DACL; inherited supervisor channel; relay pipe; RocksDB profile; listener/peer; root/Owner/Editor; socket owner; DTO/migrations/fsync unknown; immutable/mutable files; replay barrier; brief spool cut; backup/exact rollback; physical erasure; credential revocation; shutdown. | R-002, R-006, R-019–R-020, R-072–R-073, R-081–R-113, R-115–R-116, R-127 |
| P1 | Base Slice 1: supervisor/daemon/Store, IPC/socket owners, migrations, capture/blob/spool/replay/status/restart/open. | R-001–R-007, R-019–R-020, R-033, R-037–R-040, R-071–R-113, R-127 |
| P1 | Base Slice 2: qualified Claude relay, continuation, packet emission, lexical retrieval, notes/corrections/commitments, backup/rollback/erase. | R-003–R-013, R-023–R-024, R-036, R-039–R-045, R-074–R-081, R-101, R-104, R-107–R-113, R-127 |
| P1-controller | Complete controller V2 L0/L1 foundation first; do not patch legacy runtime. | R-123, S-058–S-060 |
| P1a | Controller V2 connected text inference: stable controller/client identity, token_version, `client.identity`, WriteId receipts, profiles, private copies, `inference_calls` runner, get/read/cancel/release/high-water/list and non-disclosing erase. | R-048, R-050–R-057, R-068–R-070, R-117, R-119, R-121, R-124–R-129 |
| P1a | One Memory adapter and first episode-learning consumer; restore reconciles same WriteIds and post-cut inventory without duplicate provider execution. | R-010, R-021, R-028–R-030, R-041–R-045, R-047–R-057, R-069–R-070, R-124–R-129 |
| P1b | Controller token rotation: same owner WriteId, deterministic re-derivation, stale transport reaping, pending/current/previous and delayed retirement. | R-109, R-115, R-117, R-121, R-124 |
| P1 | One integrator/product edge/cheap preflight/terminal overlap disposition per slice. | R-049, R-058–R-061, R-067 |
| P2 | Installed Claude qualification. | R-012–R-013, R-074 |
| P2 | Embeddings/vector, optional agent projection, Research, documents/views/grounds as independent increments. | R-008, R-014–R-018, R-027, R-031–R-032, R-034, R-046 |
| P2 | Retire old generated inventories/manifests at cutover. | R-059, R-063 |
| P3 | Obtain unavailable ZIP/report; deepen donors only for a selected unresolved edge. | S-008–S-010 |
| Final | Full tests after connected implementation; minimum relevant build/Clippy during code. | R-049 |

## 7. Recent changes

| Date / baseline | Change |
|---|---|
| 2026-10-23–24 | Episode recipe, initial controller boundary, delivery-collapse and Base semantics; R-047–R-081. |
| 2026-10-25 | Store/schema/Windows/release/readiness/durability/backup; R-082–R-103. |
| 2026-10-26 / draft.26–30, Contract 0.5–0.8 | Relay IPC, retained launch/root, exact rollback and stable V1 caller design; R-104–R-122. |
| 2026-10-26 / controller `c8c0ee1`, Contract 0.9 | Rebased boundary onto current controller V2: dedicated Memory principal, pre-send WriteId, minimal state, private copies and restore high-water inventory. R-123–R-129, S-058–S-064. |
| 2026-10-26 / Architecture 10, Implementation 31, Cognition 14, README | Replaced all active V1 controller mechanics, corrected long spool-lock backup defect and synchronized current owner documents. R-024, R-101, R-127. |
