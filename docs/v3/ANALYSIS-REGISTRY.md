# Eliot V3 — реестр анализа

**Статус на 2026-10-26 · нормативная база Architecture draft.8 / Implementation draft.26 / Cognition draft.11 / Inference Contract 0.4; controller `e42c464d`; активный рабочий реестр, не runtime gate.**

Этот файл — **единственный активный реестр** аудита и дальнейшей работы V3. Он отвечает на четыре вопроса:

1. что именно проверено;
2. на каком основании;
3. какое решение принято или какой разрыв найден;
4. что проверять или реализовывать следующим.

[Architecture](ARCHITECTURE.md), [Implementation](IMPLEMENTATION.md), [Cognition](COGNITION.md) и [Inference Contract](INFERENCE-CONTRACT.md) — нормативный проект. [AUDIT](AUDIT.md) хранит доказательный разбор, [AUDIT-MAP](AUDIT-MAP.md) — стабильную карту исходных требований и доноров. Git history хранит хронологию; новый проход обновляет этот реестр, а не создаёт ещё один отчёт.

## 1. Статусы и правила

| Статус | Значение |
|---|---|
| `CHECKED` | Указанный source/design scope прочитан и согласован с выводом. Не означает работающий runtime. |
| `DECIDED` | Для V3 выбрано конкретное решение; код ещё не проверен. |
| `PARTIAL` | Прочитан связанный путь или часть донора, но остаётся существенный непроверенный edge. |
| `GAP` | В выбранном producer→operation→result→consumer пути отсутствует необходимая связь. |
| `OPEN` | Решение или источник ещё требует проверки. |
| `BLOCKED` | Нужный источник недоступен. |
| `NOT SELECTED` | Механизм не нужен выбранной конструкции; это не полный аудит донора. |
| `NOT QUALIFIED` | Артефакт/механизм идентифицирован, но не прошёл требуемый живой прогон. |

Правила:

- строка называет точный объект, а не тему вообще;
- README, search hit, DTO, fixture, receipt или release metadata не дают `CHECKED` для runtime;
- исправление документа даёт `DECIDED`/`CHECKED` только для design;
- `IMPLEMENTED` появится только после реального кода и наблюдаемого input→operation→result→consumer→restart/recovery;
- точная release identity и build provenance отличаются от runtime qualification;
- новый механизм не вводится без названных caller, owner, retained result/unknown и consumer.

## 2. Активная матрица V3

### 2.1 Product, Base и память

| ID | Объект | Проверенный scope | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|---|
| R-001 | Граница продукта и владельцы | Architecture §§1–3; Implementation §§1–3; старые I9.1/I9.3/T12 | `CHECKED` | Host/controller владеет внешней задачей и инструментами; Eliot — наблюдениями, памятью, контекстом и finite jobs. | Не возвращать Task/Attempt/provider stack внутрь Memory без real consumer. |
| R-002 | Process family и idle drain | Implementation §§1,14; V2 I1.5/I14.22; Windows donors | `DECIDED` design / `NOT IMPLEMENTED` runtime | Один supervisor, daemon и exact-pinned SurrealDB child; retained executable identity before resume; mutually attested relay pipe; Store admission before capture; finite replay/job drain. | Реализовать mutex, executable lease, suspended Job Object launch, pipe owner checks, Store admission, graceful stop, restart и shutdown reconciliation. |
| R-003 | Continuation address | Architecture §4.1; Implementation §3.1; Cognition §2 | `DECIDED` | Project/workspace + task либо actor/session; branch/path/HEAD — environment state. | Проверить два workspaces, branch switch, fork, transfer, late result. |
| R-004 | Context packet identity | Architecture §4.5; Implementation §§4.7,5.9,6.3; Cognition §§6.6–6.7 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Packet = rendered bytes/digest + actual revisions + gaps; ordinary observation/blob+links, не PacketStore. | Реализовать coherent hydration, retention и actual host emission. |
| R-005 | Structured correction | Implementation §§5.3,5.6 | `DECIDED` | Correction observation + revision/history + saved result в одной transaction; replay не применяет дважды. | Реализовать command path, stale conflict и readback. |
| R-006 | Six tables and Store operations | Implementation §§4–5; SurrealDB 3.3.4 source/docs | `CHECKED` design / `NOT IMPLEMENTED` runtime | `STRICT` DB, six `SCHEMAFULL` tables, explicit fields, derived optional unique keys, fixed queries, snapshot transactions and JSON-safe Store DTOs. | Написать migration 0001/query assets/DTO projections и выполнить Slice 0. |
| R-007 | Revision/history/current | Architecture §4.5; Implementation §§4.3–4.5,5.6; Cognition §§3,8 | `DECIDED` | Exact version handle; current/history не подменяют друг друга; split не redirects old handles. | Реализовать atomic publication and restart readback. |
| R-008 | Compound grounds | Architecture §4.7; Implementation §8.3; Cognition §3.2 | `PARTIAL` | Required groups, alternatives и advisory support разделены; reverse traversal finite. | Реализовать reducer/traversal, cycles, erase, concurrent changes. |
| R-009 | Retrieval arms and packing | Implementation §7; Cognition §6 | `PARTIAL` | Exact/lexical/vector/relation arms independent; grouping не merge IDs/evidence. | Реальные query plans, bytes/tokens, OR noise, exceptions outside top-k. |
| R-010 | Processing method consumer | Implementation §10; Cognition §§7,9.1 | `DECIDED` | Job freezes recipe revision; request builder читает exact body. | Показать changed later request/context after revision. |
| R-011 | Cross-project reuse/disclosure | Architecture §4.6; Implementation §§4.3,9.2; Cognition §9.3 | `DECIDED` | Origin, reuse scope и disclosure independent. | Реализовать local/selected/owner queries and reduction. |
| R-012 | Native hook→observation | Main hooks `5aac094`; Claude docs; V3 books | `CHECKED` design / `NOT IMPLEMENTED` runtime | First profile: SessionStart, UserPromptSubmit, PostToolUse/Failure, Stop, SubagentStop, PostCompact, SessionEnd. | Квалифицировать installed Claude build/payload and implement relay. |
| R-013 | Native context delivery | Legacy hook output; Claude boundaries; V3 books | `CHECKED` design / `NOT IMPLEMENTED` runtime | Actual packet through host channel; status/local file не delivery; prepared/emitted/action/use separate. | Проверить timeout, startup/resume/clear/compact/fork/subagent cases. |

### 2.2 External capabilities, inference and cognition

| ID | Объект | Проверенный scope | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|---|
| R-014 | Controller Task/agent route | Controller `e42c464d` | `PARTIAL` | Полезен для real agent work, но избыточен для one-shot Memory inference; R-027/R-046 остаются. | Не использовать baseline `episode_learning`. |
| R-015 | Batch embeddings | Implementation §9.3; Contract §7 | `GAP` | `inference.embed`/per-input result спроектированы, метода в controller нет. | Реализовать controller route, затем vector mapping/query. |
| R-016 | Research request→report→source | Research `7c034569`; Implementation §9.3 | `PARTIAL` | Run/status/report/section/citation operations найдены; R-031/R-032 открыты. | Исправить parser/citation owner. |
| R-017 | Project views/self-view | Implementation §8.1 | `PARTIAL` | Scoped versioned views выбраны; deployment/tool не qualified. | Проверить two checkouts, late result, affected refresh. |
| R-018 | Document→representation→open | Docling/Core selected paths; Implementation §8.2 | `PARTIAL` | Original bytes, retained representation, excerpts, exact open определены. | Реальный partial page/image conversion and cost bounds. |
| R-019 | Backup/restore | Implementation §12; exact 3.3.4 export/import/JSON source; V2 reads | `DECIDED` design / `NOT IMPLEMENTED` runtime | Surreal logical export/import больше не владеет V3 backup. V3 closes mutation and replay admission, drains/reconciles the current replay, cuts canonical typed pages + blobs + deletion notices + pending/failed spool + sanitized config, then restores into a fresh candidate. Restore unions current installation deletion notices and merges current post-cut spool before cutover. | Реализовать exact barrier/encoding/manifest/restore/merge operations and run Windows round-trip. |
| R-020 | Erasure/reappearance | Architecture §4.10; Implementation §12.1; Cognition §13 | `PARTIAL` | Monotonic deletion notice, replay pause/drain, current-ledger restore union and controller late-result fence selected. | Реализовать traversal, backups/spool, in-flight replay and all controlled copies. |
| R-021 | Recursive improvement | Architecture §7; Cognition §10 | `PARTIAL` | Диагностируется конкретный failed edge; нет global intelligence score. | Connected source→context→result→revision path after Base/controller. |
| R-022 | Disagreement/anticipation | Architecture §8; Cognition §11 | `CHECKED` | Alternatives+grounds+cheapest distinguishing observation; no voting. | Ordinary records after core path. |
| R-023 | Control/status/inbox | Architecture §9; Implementation §13 | `DECIDED` | Status derives from binary/launch/pipe/engine/schema/process/socket/spool/replay/jobs/packets/reads/profile/copy facts. | Реализовать actual status and commands. |
| R-024 | Normative consistency | Architecture 8 / Implementation 26 / Cognition 11 / Contract 0.4 / README | `CHECKED` | Owner docs agree on retained launch identity, mutually attested relay IPC, closed child profile, `sync=every`, peer-verified query-only transport, socket owner, typed DTOs, replay barrier, shutdown and canonical backup/restore with deletion/spool reconciliation. No second contract/errata exists. | Synchronize only when a selected mechanism changes. |
| R-025 | Interpretation triggers | Implementation §§5.3,10; Cognition §10 | `DECIDED` | New committed input/correction/explicit question; replay/read/packet/release/cleanup do not self-trigger duplicate learning. | Проверить enqueue callers/loops. |
| R-026 | Active/pending jobs | Implementation §§4.6,5.7,10 | `DECIDED` | Optional unique slot: one active + one pending successor; waiting not retry. | Continuous arrivals, two projects, modes, shutdown. |
| R-027 | Agent result public artifact | Controller projection | `GAP` | Agent route loses nested artifact refs in public projection. | Fix only with real agent consumer. |
| R-028 | Recipe bootstrap | Implementation §10; Cognition §7.2 | `DECIDED` | Save default on first enable; upgrade does not overwrite edited revision. | Implement purpose address/first enable. |
| R-029 | Outcome→next decision | Implementation §§10–11; Cognition §9.2 | `DECIDED` | One current contribution per method revision/attempt/criterion. | Reducer and correction/contradiction cases. |
| R-030 | Multi-stream/late coverage | Implementation §10; Cognition §4 | `DECIDED` | Per-stream ranges; selected/supplied/covered distinct; no global bit. | Late child, partial body, omitted handle, successor. |
| R-031 | Research MCP decoder | Research parser | `GAP` | Old shape rejects current method/model request before capable service. | Connect MCP/discovery to current decoder. |
| R-032 | Research citation/index coupling | Research citation reader | `GAP` | Retained citation can fail when active index changed. | Open retained representation/range directly. |
| R-033 | Useful Base/light extensions | Architecture §3; Implementation §2 | `DECIDED` | One package, internal modules, Base, independent vertical increments. | Enforce imports/features/startup during code review. |
| R-034 | Vector→context | Implementation §§4.3,7,9.3 | `DECIDED` | Role/effective space/partial mapping; semantic revision unchanged. | Execute one connected semantic query after R-015. |
| R-035 | Overconstraints | Normative rereads; old privacy/routing | `DECIDED` | Narrow owner-boundary checks; no Governor platform. | Do not turn missing metadata into global permission gate. |
| R-036 | Commitments | Architecture §8; Implementation §11; Cognition §12 | `DECIDED` | Ordinary memory item; ACK/due/notification not resolution. | Implement explicit create/update/read. |
| R-037 | Stable work identity | Architecture §4.1; Implementation §3.1; Cognition §§2–3 | `DECIDED` | Work identity separated from environment. | Real attach/capture/query/late-result. |
| R-038 | Resource/version continuity | Architecture §§4.3–4.4; Implementation §§4.7,7.3 | `DECIDED` | Dirty bytes retained; rename/copy links preserve identities; equal bytes != same source. | Partial read after edit/move/conversion. |
| R-039 | Decision frame→lexical query | Implementation §7 | `DECIDED` | Exact cues and independent arms; no LLM query planner. | Actual tokens/plans/noise/empty input. |
| R-040 | Bounded source reading | Architecture §4.9; Implementation §§5.9,7.3,8.2 | `DECIDED` | Metadata/excerpt then exact ranges; identity-bound cursor; row/byte/element/text limits distinct. | Implement file/Store readers and long-line/UTF-8 cases. |
| R-041 | Automatic work/drain | Implementation §§1.3,10 | `DECIDED` | off/idle/background; finite drain; profile may deny automatic. | One automatic episode after manual. |
| R-042 | Curation consumer | Cognition §§8–10 | `DECIDED` | Output must change context/open/method request. | Same relevant request before/after revision. |
| R-043 | Consolidation/split | Cognition §8 | `DECIDED` | Replay, grouping, revision, synthesis, split distinct; original handles survive. | Implement publication/history. |
| R-044 | Forgetting changes reader | Cognition §13; Mem0 trace | `DECIDED` | Reader uses current revision links; rarity/use not truth. | Correction after restart and scoped negative memory. |
| R-045 | First episode result | Cognition §7; old I9 corpus | `DECIDED` | Zero-or-more changes, valid no-change, partial/error; operational failure never no-change. | Useful/no-change/partial/malformed/conflict runs. |
| R-046 | Claude terminal body in agent route | Controller Claude route | `GAP` | Optional agent route uses boot-local LRU before page capture. | Fix only if agent route selected; Base captures Stop directly. |
| R-047 | Inference without task manager | Controller Task path; V3 docs | `CHECKED` design / `NOT IMPLEMENTED` runtime | Memory owns semantics; controller owns execution/readback/temp copies. | Implement narrow path. |
| R-048 | `inference.text/embed` | Controller catalog; Contract 0.4 | `GAP` | Methods absent. | Implement staged admission/dedup/runner/result/unknown. |
| R-049 | Code-first/test timing | User direction; Implementation §14 | `DECIDED` | Production code first; minimum build/Clippy; full suite after connected product. Slice 0 is discrimination, not test platform. | Execute exact preflight, then code. |
| R-050 | Connection/profile/privacy/budget | Architecture §§2.3–2.4; Contract §§3–4,9 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Static connection/profile/digests/destination/limits/no fallback. | Parser/admission/disclosure reducer. |
| R-051 | Controlled-copy lifecycle | Contract §§5,13 | `GAP` | Input staged, result optional, per-copy cleanup, three dispositions. | Implement exact removal/fence/recovery. |
| R-052 | Taskless ScriptRun donor | Controller selected paths | `CHECKED` / `NOT SELECTED` | Different product lifecycle; only Operation/recovery ideas useful. | Do not route inference through it. |
| R-053 | Narrow caller authority | Controller Role/Store; Contract §2 | `DECIDED` design / `NOT IMPLEMENTED` runtime | `inference_client` exact allowlist, no MCP/generic writer. | Implement registration/dispatch/own reads-cancel. |
| R-054 | Inference artifact provenance | Controller artifacts; Contract §§5,11,13 | `GAP` | Current kinds/deletion omit inference. | Add kinds/provenance/grant/private exact removal. |
| R-055 | Operation runner/recovery/cancel | Controller Operation primitives | `DECIDED` design / `NOT IMPLEMENTED` runtime | Existing ledger/wake/cancel sufficient; generic mutate unsafe. | Custom admission + bounded runner. |
| R-056 | Direct controller IPC dependency | `swarm-client` `e42c464d`; Contract §2.1 | `CHECKED` design / `NOT IMPLEMENTED` adapter | Exact Git pin, no copied protocol/MCP/CLI; possible-write disconnect unknown. | Pin and implement adapter. |
| R-057 | First provider adapter | Controller HTTP donor; reqwest | `DECIDED` design / `NOT IMPLEMENTED` runtime | Closed loopback chat/embeddings; no arbitrary extras/retry/fallback; HTTPS later. | Implement/Clippy loopback text. |

### 2.3 Development-system failure analysis

| ID | Объект | Проверенный scope | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|---|
| R-058 | Delivery incentives | Issues #5305/#3014/#327 | `CHECKED` | Artifacts displaced integrated behavior; overlap lacked terminal disposition. | Measure closed product edges/blockers. |
| R-059 | Append-only authority | Historical issues/T files/inventories | `PARTIAL` | Corrections accumulated beside old plans; V3 docs/registry current. | Retire/label V2 authorities at cutover. |
| R-060 | Cheap preflight/WIP | Issue #5305; AGENTS/README | `DECIDED` | Deterministic blockers before setup; overlap waits. | Ordinary issue/PR ownership, no new gate. |
| R-061 | Completion criterion | Issues; Architecture §§1,11; Implementation §14 | `CHECKED` design | Caller→operation→durable result/unknown→consumer/readback→restart/recovery. | Denominator for every slice. |
| R-062 | Crate/manifest inversion | Root Cargo; sampled manifests | `CHECKED` representative / `PARTIAL` corpus | ~188 packages and large manifests turn helpers into products. | Keep internal module until measured boundary. |
| R-063 | Generated inventories | Exact two work-unit inventories | `CHECKED` | Scans became mandatory denominators. | Do not port; retire after consumer search. |
| R-064 | Intent–mechanism inversion | Old Architecture/Implementation | `CHECKED` | Intent-first prose coexisted with mandatory object families. | Admit only named connected mechanisms. |
| R-065 | Crate-first capacity target | Old Implementation; workspace | `CHECKED` correlation / `PARTIAL` causality | Permitted capacity became local default. | One package/modules; no contours/testd/promotion without boundary. |
| R-066 | Identity/proof multiplication | Old identity/conformance/CCU/capsules | `CHECKED` | Synchronization graph outgrew product edge. | Git/schema/operation IDs only at real boundaries. |
| R-067 | Anti-proxy rules lacked backpressure | Old clauses/issues/artifacts | `CHECKED` | Rules condemned proxies but did not block new object families. | One ledger/integrator/WIP stop/preflight. |
| R-068 | Authoritative destination admission | Contract §§3–4,6 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Controller resolves profile/connection/destination and checks disclosure/limits. | Implement state mapping. |
| R-069 | One Memory controller client | Implementation §9; Cognition §14 | `DECIDED` design / `NOT IMPLEMENTED` runtime | One adapter owns text/embed/read/cancel/release. | Pin `swarm-client`. |
| R-070 | No-result cleanup/erase abandonment | Contract §§5.3,12–13 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Result optional; terminal no-result cleans input; unresolved erase fences; per-copy states. | Implement dispositions/recovery. |

### 2.4 Detailed Base, Store and platform audit

| ID | Объект | Проверенный scope | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|---|
| R-071 | Legacy hook forwarder | `service.rs`; shape test; main search | `CHECKED` exact code | `forwarded` without send; content-hash spool; no production replay. | Do not port. |
| R-072 | Relay/spool ownership | Architecture/Implementation/Cognition current | `CHECKED` design / `NOT IMPLEMENTED` runtime | One immutable command; mutually attested one-request daemon pipe; committed requires Store readback; staged requires file+dir durability/readback. | Implement minimal pipe client/server, Windows publication and fair replay. |
| R-073 | Occurrence identity/source bytes | Current books | `CHECKED` design / `NOT IMPLEMENTED` runtime | Native/command ID identifies occurrence; digest verifies bytes; equal content stays distinct. | Implement fields/indexes/conflicts/exclusions. |
| R-074 | Claude schema drift | Actual hooks config/internal docs/public docs | `PARTIAL` | V3 event profile selected; installed build unverified. | Installed-version qualification. |
| R-075 | Packet handoff | Current books | `CHECKED` design / `NOT IMPLEMENTED` runtime | Actual bounded packet; prepared/emitted/associated/use distinct. | Host output/readback/gaps. |
| R-076 | Base normative consistency | README; Architecture 8; Implementation 26; Cognition 11 | `CHECKED` | Host/capture/pipe/spool/packet/open and Store launch/peer/socket/shutdown/wire/backup baselines are synchronized in owner docs. | Keep synchronized during code. |
| R-077 | Legacy packet explicit-call dependency | Task handlers/MCP/SKILL | `CHECKED` exact paths | Full packet only after explicit compile call; no SessionStart connection. | Do not port. |
| R-078 | Legacy packet authority multiplication | Context/commit/outbox paths | `CHECKED` representative / `NOT SELECTED` | Parallel authority/projection without automatic delivery. | Ordinary observation/blob+links. |
| R-079 | Legacy exact read empty selector/relation loss | ReadService/MCP/T13 | `CHECKED` exact paths | Empty exact selector can become broad; endpoint filter hides material relations. | One exact handle; return relation descriptors. |
| R-080 | Legacy read coverage/cursor | `fetch_atoms_l2.surql` and filters | `CHECKED` exact path | Fixed caps have no honest cursor/coverage. | Typed exact envelope/cursor. |
| R-081 | Exact-open consistency | Current README/books | `CHECKED` design / `NOT IMPLEMENTED` runtime | Exact current/history/source/representation handles, dispositions, ranges and identity cursor. | Implement readers and edge cases. |
| R-082 | SurrealDB Rust SDK fit | Root Cargo/toolchain/deny; SDK 3.3.4 metadata; V2 adapter | `CHECKED` / `NOT SELECTED` baseline | SDK requires Rust 1.95 while workspace declares 1.94; published license metadata conflicts with current allowlist on paper; no SDK dependency exists. | Reconsider only after exact cargo check/deny/size proof. |
| R-083 | Exact SurrealDB Windows release identity | Official release/tag API and build workflow; Implementation §§1.2–1.3 | `CHECKED` release identity / `NOT QUALIFIED` runtime | Tag `v3.3.4` resolves to commit `1ac2b1dba7cd177621a4cf5d507caebeb2414395`. Asset `surreal-v3.3.4.windows-amd64.exe`, asset ID `655787929`, size `321555968`, SHA-256 `1255a3b2e771b8853e9ee0aca0ddde09dbe4532248502a5d900eb3997955f0cc`. Installer verifies digest and retains approved bytes. | Download/hash approved asset and run Slice 0. |
| R-084 | Store RPC/mutation replay | V2 session donor; exact tag RPC/auth/format source | `CHECKED` design / `NOT IMPLEMENTED` runtime | Bounded peer-verified Basic `/rpc`, one dedicated socket owner, one in-flight fixed `query`, exact IDs, continuous control-frame handling, poison-on-timeout/protocol/cancellation ambiguity and no blind replay. JSON is admitted only for explicit canonical JSON-safe DTOs. | Implement owner task, raw connect/peer check, parser/bounds/typed projections/errors/readback. |
| R-085 | Schema/migration/transactions | Current SurrealDB docs; Implementation §§4–5.2 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Checksummed `.surql`, DB generation param/INFO, strict schemafull, derived unique keys, snapshot transactions, FOR UPDATE/sentinel. | Write migration 0001 and run conflict/rollback cases. |
| R-086 | Windows immutable publication | Microsoft API docs; current donors; Implementation §§5.4–5.5 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Local NTFS/ReFS; create-new temp; file flush; no-replace WRITE_THROUGH rename; parent flush; exact readback; post-rename sync failure unknown. | Implement and force file/rename/dir-sync/restart outcomes. |
| R-087 | SurrealDB RocksDB build/runtime qualification | Tag `v3.3.4` server Cargo + rolling Windows build; storage docs | `CHECKED` build provenance / `OPEN` runtime | Server default features include `storage-rocksdb`; official Windows asset is built with RocksDB support. Actual Windows RocksDB start/restart/conflict/durability remains unrun. | Run standalone asset against disposable canonical `rocksdb:` root with `sync=every`; no SurrealKV fallback. |
| R-088 | Standalone CLI, secrets and capability posture | Exact tag CLI/start/dbs/network/config source | `CHECKED` source design / `NOT QUALIFIED` runtime | Launch is `surreal start <canonical-storage-url>`. Supervisor supplies explicit bind/capabilities/no-defaults/no-identification/CORS and a sanitized child environment. It does not inherit arbitrary `SURREAL_*`, logging or telemetry variables. | Qualify exact argument/environment vector, path syntax and admissions on Windows. |
| R-089 | Exact Store capability surface | Exact tag capability/RPC/route/auth source | `CHECKED` source design / `NOT QUALIFIED` runtime | Selected live/candidate Store exposes HTTP route `rpc`, RPC method `query` only, arbitrary query only `system`; guest/record, all other methods, functions, net, script/eval/experimental denied. Basic middleware auth/database headers replace RPC signin/use; binary+peer identity replaces version; control Ping/Pong replaces RPC ping. | Run allowed/denied route/method/subject/function and authenticated-header matrix. |
| R-090 | SurrealDB export/import as backup donor | Exact tag core export, HTTP export and import source | `CHECKED` / `NOT SELECTED` | Core export holds one read snapshot, but HTTP sends success before the job ends and converts internal job failure/panic into server log plus normal body EOF. Import commits statement-by-statement and can leave partial state. Neither route owns V3 backup/restore. | Keep routes disabled; qualify R-101/R-107 instead. |
| R-091 | Store credential roles and bootstrap lifetime | Exact tag IAM roles/policy, startup, auth middleware, parser and signin source | `DECIDED` design / `NOT QUALIFIED` runtime | One retained root credential drives a short bootstrap and any unknown reconciliation. After root persistence/possible bind failure, same root restarts without secret env; root then authenticates only in an owned-peer Basic handshake and provisions NS/DB + DB Owner/Editor. Normal daemon uses Editor; migrations/user rotation/restore use Owner. | Slice 0 proves unknown bootstrap reconciliation, two root-free restarts and all role handshakes. |
| R-092 | SurrealDB readiness versus V3 Store readiness | Exact tag start/ready/heartbeat/auth/RPC source | `CHECKED` source design / `NOT QUALIFIED` runtime | Listener/status/health/version can be reachable while startup work is incomplete. Store ready requires exact launch/binary/process, listener owner, established peer owner, `/ready`, Editor Basic handshake, healthy socket owner, query-only denial matrix, schema/INFO and bounded production-client write/read/delete. | Run delayed/fatal/stale-heartbeat/peer-swap/bad-credential/bad-schema/probe matrix. |
| R-093 | Startup import as restore anti-donor | Exact tag `finish_startup`, readiness transition and issue evidence | `CHECKED` / `NOT SELECTED` | Startup import is non-transactional; failed statements are logged but startup can continue and become ready. It cannot own migration/restore or certify a candidate. | Never pass `--import-file`; use R-101/R-107. |
| R-094 | Storage URL and default database ownership | Exact tag endpoint parser/path tests/config source | `CHECKED` source design / `NOT QUALIFIED` Windows runtime | Installer generates one canonical RocksDB URL bound to retained root and explicitly includes `?sync=every`; raw caller URLs forbidden. Start with `--no-defaults`; installer creates only configured namespace/database. | Compare Windows spellings, prove same root/restart, `sync=every`, no `main/main`. |
| R-095 | External binary materialization and signature evidence | Official release/build workflows; V2 provisioner and path-lease donor | `PARTIAL` | Exact release SHA/build checksum known. No public signing step found, actual asset signature unobserved. V3 create-new materialization is followed by retained no-follow executable/ancestor handles, streaming hash and suspended-child image/file identity before resume. | Inspect actual assets on Windows and force launch TOCTOU cases. |
| R-096 | Graceful shutdown versus crash containment | Exact tag server signal/start/Datastore/RocksDB shutdown source | `CHECKED` source design / `NOT QUALIFIED` runtime | Normal stop closes mutation/new-replay admission, drains current replay, requests graceful SurrealDB shutdown and waits boundedly; Job Object kill is only deadline/crash containment. Clean exit is not a durability receipt. | Force active maintenance/replay, timeout, child hang and Job Object close; verify consistent restart. |
| R-097 | RocksDB acknowledged-commit durability | Exact tag RocksDB config, transaction commit and commit coordinator | `CHECKED` source design / `NOT QUALIFIED` runtime | Explicit `sync=every` commits then groups `flush_wal(true)` and acknowledges only after fsync. `never`/interval can lose acknowledged writes. Commit may apply before shutdown/WAL-sync error reaches caller, so that error is `OUTCOME_UNKNOWN` and requires identity readback. | Run crash/power-cut-oriented commit/readback/restart and sync-error classification. |
| R-098 | DB-user provisioning and log secrecy | Exact tag DEFINE USER parser/ToSql, Argon2/SCRAM/auth and slowlog source | `CHECKED` source design / `NOT QUALIFIED` runtime | Literal credential DDL can render into logs. Installer derives Argon2 PHC locally, sends only `PASSHASH` in fixed root/Owner query on a peer-verified Basic socket, disables slowlog/telemetry and treats headers/request/errors as secret-bearing. No statement/verifier enters logs. | Qualify PASSHASH create/rotate/handshake, buffer zeroization where practical and log absence under failure. |
| R-099 | Closed child environment and loopback surface | Exact tag CLI/network/CORS/metrics/config source; tower-http 0.6.11 CORS | `CHECKED` source design / `NOT QUALIFIED` runtime | Default CORS allows any Origin, identification headers/metrics are on and all `SURREAL_*` env values are imported. Supervisor constructs a minimal env and exact loopback profile. Closed Origin only controls readable CORS responses; it does not reject WebSocket. | Inspect env/listeners/routes/headers and adversarial inherited variables/browser origins. |
| R-100 | JSON wire type budget | Exact tag JSON/CBOR value conversion source; current V3 model | `DECIDED` design / `NOT IMPLEMENTED` runtime | JSON maps NONE/NULL together and turns record IDs, UUID, datetime, duration and decimal into lossy JSON forms; non-finite float becomes null. V3 keeps JSON only with explicit per-operation DTOs. No generic `Value`, `SELECT *` backup or CBOR tag reimplementation. | Freeze each table/query DTO and round-trip NONE/NULL/ID/time/vector edge cases. |
| R-101 | Application-owned backup cut and restore | R-019/R-090/R-100; six-table model; Windows publication primitive | `DECIDED` design / `NOT IMPLEMENTED` runtime | Backup closes mutation/new-replay admission, drains the active replay, cuts typed pages/blobs/deletions/pending+failed spool/config and publishes manifest. Restore accepts supported generations only, unions current deletion ledger, preserves current post-cut spool and original failed disposition, verifies/restarts under Editor and only then cuts over. | Define locks/encoding/manifest/merge and force crash, in-flight replay, late erasure, current spool, mismatch and candidate discard. |
| R-102 | WebSocket Origin and handshake authentication | SurrealDB auth/RPC route; tower-http 0.6.11 CORS; query subject gate | `CHECKED` source design / `NOT QUALIFIED` runtime | CORS does not reject ordinary WS upgrade and Origin is not auth. Upstream accepts anonymous socket, but query subject denies guest. V3 uses Basic + auth/selection headers on owned peer and allows only query. Anonymous socket/resource exhaustion remains a measured qualification risk. | Run malicious Origin/no-auth/many-socket matrix and decide from measured bounds. |
| R-103 | Dynamic port, listener and established-peer ownership | Surreal start bind order; V2 exact Windows TCP-owner donor; tokio-tungstenite 0.28 client API | `CHECKED` design / `NOT IMPLEMENTED` runtime | Reserve loopback ephemeral port, drop only before child resume, retry bind failure, bracket TCP-table listener/peer PID observations with retained process handle, then perform client_async on verified raw stream. Port/TCP/HTTP/101 alone never authorize credentials. | Implement minimal owner observations and force port squat, PID exit/reuse, peer swap and bind-after-bootstrap unknown. |
| R-104 | Relay→daemon local IPC | V2 `eliot-windows-ipc`, named-pipe peer/process admission, ADR-0002; Implementation §§1.3,6.2 | `CHECKED` donor/design / `NOT IMPLEMENTED` runtime | Installation-scoped first named-pipe instance, remote rejection, current-user+SYSTEM DACL and mutual live-process attestation. One bounded versioned length-prefixed request/response; no general session/lease/token platform. Same-account arbitrary code remains outside claimed boundary. | Implement minimal pipe boundary and force squat/SID/session/image/PID/job/frame/timeout cases. |
| R-105 | Retained executable launch identity | V2 `process_path_lease.rs`; Win32 file/process launch boundary | `CHECKED` donor/design / `NOT IMPLEMENTED` runtime | No-follow executable and ancestor handles deny write/delete sharing, stream exact digest, then suspended child image/file identity and Job assignment are verified before resume. Path/digest/PID alone are insufficient. | Adapt minimal primitive, remove unbounded read-to-end, qualify exact binaries and launch races. |
| R-106 | Store WebSocket owner/cancellation | V2 Store sessions; tokio-tungstenite; Surreal WebSocket control handling | `CHECKED` donor/design / `NOT IMPLEMENTED` runtime | One dedicated Tokio task owns each authenticated socket, one in-flight ID and continuous control/data read. Timeout, cancellation ambiguity, wrong/late response or protocol fault poisons/closes; mutation becomes unknown and reconnect repeats peer/auth admission. | Implement owner channel/state and force timeout/cancel/late/wrong/close/reconnect. |
| R-107 | Replay barrier and restore monotonicity | Implementation §§5.5,12; spool/deletion model | `CHECKED` design / `NOT IMPLEMENTED` runtime | Backup/erasure pause new replay and drain/reconcile current item before Store/spool cut. Restore unions current deletion ledger with backup notices and merges current post-cut spool by exact command/disposition; old backup cannot resurrect or downgrade. | Implement pause/drain, installation-ledger union, cutover merge and unknown reconciliation. |

## 3. Source coverage

| ID | Источник | Статус | Граница вывода |
|---|---|---|---|
| S-001 | V1 Canonical Master | `CHECKED` previously through §40 | Requirements read, not full code audit. |
| S-002 | V2 Architecture/Implementation selected sections | `PARTIAL` | Targeted rereads only. |
| S-003 | Claude audit revision 4 | `CHECKED` provided text | Ideas, not automatic norm. |
| S-004 | Eliot audit v9 | `CHECKED` provided text | Findings not rerun every SHA. |
| S-005 | Swarm audit 2026-10-06 | `CHECKED` provided text | Controller ownership separated. |
| S-006 | August architecture audit | `CHECKED` provided text | Proof machinery not carried automatically. |
| S-007 | LLM problems report | `CHECKED` provided text | Failure classes mapped, not reproduced. |
| S-008 | Release ZIP `audit-2026-10-16-incomplete` | `BLOCKED` | Metadata only; ZIP not read. |
| S-009 | `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | `BLOCKED` | Full text absent. |
| S-010 | Named donors D01–D47 | `PARTIAL` | Exact path/revision findings only. |
| S-011 | Independent subagent review | `OPEN` | No subagent execution tool available in this pass. |
| S-012 | Consolidated failure audit | `PARTIAL` | Selected curation path; counts/runtime not reproduced. |
| S-013 | Controller inference boundary | `CHECKED` selected paths through `e42c464d` | No live provider run. |
| S-014 | Old inference privacy/routing | `CHECKED` selected sections | Limits/no fallback retained; platform rejected. |
| S-015 | Controller taskless/Store primitives | `CHECKED` selected paths | Donors/anti-donors; no worker run. |
| S-016 | IPC/transport donors | `CHECKED` selected paths | No-replay IPC/bounded loopback/private files. |
| S-017 | Delivery-collapse evidence | `CHECKED` issues #5305/#3014/#327 | Mechanisms confirmed; no full census. |
| S-018 | Workspace/manifests/inventory sample | `CHECKED` exact sample | Not all crates/work units. |
| S-019 | Retained old Architecture/Implementation copies | `CHECKED` targeted sections | Not fresh whole-book audit. |
| S-020 | Current inference synchronization | `CHECKED` Contract 0.4 + books | Design only. |
| S-021 | Legacy Base hook/spool main `5aac094` | `CHECKED` exact files | Static audit; no live plugin/daemon. |
| S-022 | Claude Hooks public reference 2026-10-24 | `CHECKED` public docs | Does not prove installed build. |
| S-023 | Legacy packet/context main | `CHECKED` selected paths | No live packet run. |
| S-024 | Legacy exact L2 main | `CHECKED` selected paths | No live corpus/performance. |
| S-025 | Current Base normative synchronization | `CHECKED` Architecture 8 / Implementation 26 / Cognition 11 / README | Design only; no runtime/build/test. |
| S-026 | Repository dependency/platform inventory | `CHECKED` root Cargo/toolchain/deny, V2 Store/Windows donors | Establishes dependency and donor facts only. |
| S-027 | SurrealDB 3.3.4 docs/package metadata | `CHECKED` SDK/RPC/schema/index/transaction/storage docs | Public contract, not live binary proof. |
| S-028 | Microsoft Win32 file API docs | `CHECKED` CreateFile/FlushFileBuffers/MoveFile semantics | API contract, no crash/power-loss run. |
| S-029 | Store/durability normative synchronization | `CHECKED` Implementation 26 + README + R-082–R-107 | Owner design synchronized; no runtime qualification. |
| S-030 | SurrealDB `v3.3.4` release/tag/build provenance | `CHECKED` release API, tag commit, server Cargo, rolling channel and Windows build action | Exact identity/build features; no execution. |
| S-031 | SurrealDB standalone start source | `CHECKED` exact tag CLI/start/dbs | Exact arguments/defaults; Windows invocation still unrun. |
| S-032 | SurrealDB exact capability/RPC source | `CHECKED` tag `v3.3.4` dbs/capability/RPC/route source | Establishes CLI normalization and independent gates. |
| S-033 | SurrealDB exact export/import source | `CHECKED` tag `v3.3.4` CLI/core/HTTP export/import | Establishes coherent core export, hidden HTTP terminal failure and partial import; rejected as V3 owner. |
| S-034 | SurrealDB exact IAM roles/policy | `CHECKED` tag `v3.3.4` IAM roles/policy and import/edit checks | Establishes Editor/Owner distinction; no live users. |
| S-035 | SurrealDB exact readiness/startup source | `CHECKED` tag `v3.3.4` start/ready/dbs tests | Establishes port/health/ready separation, bind/startup ordering, bootstrap credential lifetime and startup-import defect. |
| S-036 | SurrealDB endpoint/default ownership source | `CHECKED` tag `v3.3.4` endpoint/config/no-defaults source | Establishes URL config precedence/default creation; no Windows run. |
| S-037 | External binary provision/signature paths | `CHECKED` official workflows and V2 provision selected paths | No public signing step found; actual PE signature unobserved. |
| S-038 | SurrealDB server/Datastore/RocksDB shutdown | `CHECKED` exact tag signal/start/network/Datastore/RocksDB shutdown paths | Establishes ordering, bounded drains and logged cleanup failures; no forced live shutdown. |
| S-039 | SurrealDB RocksDB sync/commit coordinator | `CHECKED` exact tag config, transaction and coordinator source | Establishes `sync=every`, grouped fsync and applied-before-sync-error edge; no power-loss run. |
| S-040 | SurrealDB credential material/logging | `CHECKED` exact tag DEFINE USER parser/ToSql, Argon2/SCRAM/auth and slowlog | Establishes literal/verifier/log and Basic-header behavior; no live rotation. |
| S-041 | SurrealDB network/environment defaults | `CHECKED` exact tag CLI, CORS, metrics, config-map and route source | Establishes defaults/environment intake; no Windows process inspection. |
| S-042 | SurrealDB JSON/CBOR value mapping | `CHECKED` exact tag RPC format and value conversion | Establishes JSON type loss and vendor-specific CBOR tags; no custom client run. |
| S-043 | V3 application backup replacement | `CHECKED` design from S-033/S-042 plus current six-table/blob/spool/config model | Selected canonical cut/format/restore mechanism only; no implementation/round-trip. |
| S-044 | WebSocket CORS/auth/query admission | `CHECKED` SurrealDB v3.3.4 auth/RPC route and tower-http 0.6.11 CORS call path | Establishes that Origin is not WS rejection and Basic middleware auth precedes query subject gate; no browser/live server run. |
| S-045 | Store endpoint ownership transport | `CHECKED` V2 `tcp_listener_owner.rs`, Surreal start bind order and tokio-tungstenite 0.28 `client_async_with_config` | Exact donors for minimal Windows owner observation and existing-stream handshake; no V3 implementation. |
| S-046 | Named-pipe local IPC donors | `CHECKED` V2 `eliot-windows-ipc`, `named_pipe_peer_auth.rs`, `named_pipe_process_admission.rs`, ADR-0002 and narrow app donor | Establishes first-instance/DACL/remote rejection, PID/process/SID/session checks and bounded framing; old role/session/lease platform not selected. |
| S-047 | Retained process-path lease donor | `CHECKED` V2 `process_path_lease.rs` | Establishes no-follow identity, deny-write/delete sharing, ancestor pinning and suspended-child comparison; donor's unbounded read-to-end hash is not selected. |
| S-048 | WebSocket lifecycle donors | `CHECKED` V2 Store session plus tokio-tungstenite/Surreal control-frame paths | Establishes bounds/IDs/control frames and the cancellation/late-response gap; no V3 owner task run. |

## 4. Findings from current focused passes

### 2026-10-24 — Base host/capture/context/open

Legacy `forwarded` was shape-only; spool lacked a durable replayer; occurrence used content hash; SessionStart returned status rather than context; packet creation depended on explicit agent call and parallel authority; exact L2 allowed broad empty selector, relation loss and silent fixed caps. Current Architecture 8 / Implementation 26 / Cognition 11 replace these paths without a new subsystem.

Counterexamples retained: two identical prompts are two occurrences; lost commit reply replays the same command; temp-before-rename is not staged; deletion notice blocks old replay; prepared packet is not emitted; exact empty selector is not broad; relation descriptor does not require neighbor body; capped page needs cursor; historical handle never falls forward.

### 2026-10-25–26 — Store, IPC, launch, durability and backup

Established:

1. no official SurrealDB SDK dependency exists; V2 uses custom WebSocket RPC;
2. current SDK requires Rust 1.95 while workspace declares 1.94 and its metadata needs explicit license admission;
3. V2 major-only pin and SurrealKV default are insufficient;
4. bounded RPC covers the required remote surface without engine/SDK linkage;
5. snapshot isolation needs unique values or locked sentinel records for set invariants;
6. strict/schemafull definitions, params and INFO support a small migration owner;
7. Windows immutable publication requires file flush, no-replace write-through rename, parent-directory flush and exact readback;
8. post-rename sync failure is a possible committed filesystem effect and must reconcile;
9. `v3.3.4` resolves to commit `1ac2b1dba7cd177621a4cf5d507caebeb2414395` and R-083 records the exact asset/digest;
10. official Windows build includes RocksDB, but runtime qualification remains open;
11. standalone launch is `surreal start`, not launcher syntax;
12. HTTP route and RPC method allowlists are separate gates;
13. arbitrary-query subject admission is separate again; private fixed queries remain the statement boundary;
14. root/namespace/database authenticated sessions map to `system`; guest and record remain separate;
15. listener/status/health can be available before Store is ready; `/ready` is necessary but insufficient;
16. startup import can fail statements and still let startup become ready;
17. first boot creates `main/main` unless `--no-defaults` is explicit;
18. bootstrap credentials create root only when no root user exists;
19. endpoint parser accepts multiple RocksDB spellings, so installer owns one canonical URL;
20. release/build/source proof is not runtime qualification;
21. graceful shutdown drains maintenance for at most 30s, then proceeds; several RocksDB cleanup failures are logged without making process exit a durability receipt;
22. RocksDB default is `sync=every`, but V3 pins it explicitly in URL. `never` and interval modes may lose acknowledged writes on crash/power loss;
23. under `sync=every` RocksDB applies each transaction before grouped `flush_wal(true)` result. Shutdown/fsync failure can return error after mutation exists: application `OUTCOME_UNKNOWN`;
24. literal credential DDL can be rendered into logs;
25. ordinary auth verifies Argon2 hash; SCRAM unnecessary with Postgres disabled. V3 provisions DB users via locally derived `PASSHASH`;
26. default child posture is too open: any Origin, identification headers, metrics and inherited `SURREAL_*`. Supervisor supplies sanitized environment/arguments;
27. core export holds one snapshot, but HTTP can return success/EOF after hidden terminal job failure;
28. import is statement-by-statement/partial; export/import routes are rejected as V3 owner;
29. JSON RPC is lossy for NONE/NULL and special types; generic JSON `Value` round-trip invalid;
30. copying Surreal CBOR tags would create another vendor protocol implementation; JSON remains only closed DTOs;
31. V3 backup is an application cut over typed pages, blobs, deletions, pending+failed spool and sanitized config;
32. owner docs carry these mechanisms directly;
33. root credentials otherwise remain in first child environment for process lifetime, so bootstrap child stops after root persistence;
34. backup/shutdown quiesce needs private `stage_required`, not public rejected;
35. backup digest needs versioned canonical encoding and supported format/schema gate;
36. tower-http CORS does not reject ordinary requests: it passes them inward and adds response headers. Surreal `/rpc` does not perform an Origin check, so `--allow-origin` is not WebSocket authorization;
37. Surreal's Basic auth middleware can authenticate and select DB during WebSocket upgrade before RPC dispatch. Therefore RPC signin/use are unnecessary; exact binary/process/peer identity replaces version and WebSocket control frames replace ping, leaving only query;
38. choosing a free port then connecting by address is insufficient. The unavoidable close-before-child-bind race is contained by retained child handle, Windows listener/established-peer PID observations and an existing-stream WebSocket handshake before any credential leaves the client;
39. relay→daemon IPC needs the same owner discipline: first named-pipe instance, current-user+SYSTEM DACL, remote rejection and mutual live-process identity. Pipe name or token alone does not close squatting/stale-process edges;
40. a caller-held WebSocket mutex is not enough for cancellation safety. One task must own the socket continuously, and any ambiguous timeout/cancel/protocol result must poison it so a late reply cannot satisfy a later request;
41. hashing an executable path before `CreateProcessW` leaves a launch TOCTOU. Retained no-follow file/ancestor handles plus suspended-child image/file comparison close the physical edge without importing the V2 platform framework;
42. backup must pause and drain the active replayer before Store/spool inventories. Restore must union current deletion notices and merge current post-cut spool; otherwise an old backup can resurrect erased data or lose/duplicate a command.

Qualification target, not a claimed working command:

```text
surreal start <installer-owned-canonical-rocksdb-url>?sync=every
--bind 127.0.0.1:<per-start-owned-port>
--deny-all
--allow-arbitrary-query system
--deny-arbitrary-query guest,record
--allow-http rpc
--allow-rpc query
--no-defaults
--no-identification-headers
--client-ip none
--allow-origin <reserved origin; CORS metadata, not WS auth>
```

The child receives a minimal allowlisted OS environment plus explicit `SURREAL_METRICS_ENABLED=false`; no inherited capability, slow-query, telemetry, Postgres, import or arbitrary `SURREAL_*`. Function allowlist starts empty.

Counterexamples, not runtime runs:

- executable path hashed, then file/ancestor swapped before resume → approved digest does not identify launched image;
- daemon pipe name exists but first-instance ownership is not required → local squatter becomes apparent daemon;
- current-user DACL or bearer token treated as complete peer identity → stale/unrelated same-user binary reaches application operations;
- caller times out and drops a mutex-held WebSocket future while socket stays reusable → late response can be consumed by the next request;
- replay commits after table paging but pending file is inventoried/deleted on another side of the cut → event is lost or duplicated;
- restore replaces current deletion ledger with old backup notices → later erasure is undone;
- backup pending command overwrites a current post-cut command or failed entry is restored as pending → identity conflict or poison replay returns;
- `sync=5s`/`never` → acknowledged recent commits may disappear;
- transaction applied then fsync/shutdown error → blind retry duplicates without readback;
- clean process exit after cleanup log error → not durability proof;
- inherited capability/metrics/slowlog/OTEL env → launch arguments do not describe behavior;
- default/closed Origin treated as WS gate → anonymous browser upgrade still reaches `/rpc`;
- public `connect_async` sends Basic header before process/peer ownership → credential can reach a port squatter;
- matching port or HTTP 200/101 trusted without listener/peer PID → wrong local process accepted;
- stable port from installation file treated as identity → stale/squatted listener can impersonate availability;
- PID row observed after original child exited without retained-handle bracketing → PID reuse can satisfy stale comparison;
- bootstrap bind fails after root persistence and installer generates new root secret → retained account becomes inaccessible;
- RPC signin/use/version/ping left enabled “for convenience” → unnecessary unauthenticated/mutable session surface;
- bootstrap child kept alive after root persistence → root password remains in environment;
- credential statement/verifier logged → sensitive disclosure;
- quiesce returns public rejected → valid event discarded instead of staged;
- HTTP export 200 then job failure → apparently complete EOF;
- broad Surreal dump → vendor state with no reliable terminal receipt;
- JSON `SELECT *` backup → type collapse;
- unordered serializer defines digest → equal rows hash differently;
- failed quarantine/config continuity omitted → restore loses retained state;
- unsupported backup generation accepted → unproven reinterpretation;
- CBOR tags copied locally → patch-level vendor protocol drift;
- pages mutate during backup → no single application cut;
- spool enumerated without publication cut → event falls between inventories;
- exact RocksDB build fails target profile → Slice 0 blocks, no fallback.

## 5. Решения, которые не открываются без нового основания

- не переносить V1/V2 runtime/compatibility facades;
- не создавать второй task manager/swarm/research engine/semantic DB;
- не создавать provider stack in Memory или Task/ScriptRun inference;
- не возвращать old Governor/platform/object families;
- не считать shapes/receipts/reports/IDs product behavior;
- не создавать PacketStore/packet authority/projection family;
- не считать issue/T-file/generated inventory current authority;
- не создавать crate/process per concept или per-helper manifests;
- не использовать content digest как occurrence identity;
- не считать pipe name/DACL/token/PID достаточной peer identity;
- не импортировать V2 IPC role/session/lease platform ради одного pipe;
- не проверять executable только path/digest до запуска без retained lease и child identity;
- не оставлять Store WebSocket reusable после ambiguous timeout/cancel/protocol result;
- не возвращать `forwarded` без Store readback;
- не возвращать `staged` до file+directory durability/readback;
- не использовать public `rejected` для temporary quiesce;
- не снимать backup barrier до drain/reconciliation текущего replay;
- не заменять current deletion ledger backup-копией;
- не overwrite current post-cut spool и не downgrade failed→pending при restore;
- не считать status/local file context delivery;
- не переносить PreToolUse/finish/compaction gates в Base;
- не требовать explicit agent call before host-boundary context;
- не использовать empty exact selector как broad read;
- не скрывать material relations/caps без cursor/gap;
- не подменять historical/source representation current/new one;
- не добавлять SurrealDB SDK без exact preflight;
- не pin only major/tag/name и не менять engine silently;
- не expose raw SurrealQL/generic CRUD;
- не использовать implicit schema/`IF NOT EXISTS` verification;
- не использовать existence/naive UPSERT/snapshot read как concurrency invariant;
- не replay mutation blindly after possible send/fsync/shutdown;
- не использовать replace-existing для immutable publication;
- не считать rename without directory sync durable;
- не считать clean exit/graceful shutdown durability receipt;
- не копировать live engine directory как backup;
- не fall back to SurrealKV;
- не использовать sync never/interval;
- не запускать standalone asset launcher syntax;
- не наследовать arbitrary parent environment;
- не держать bootstrap child с root env после persistence;
- не генерировать новый root secret для unknown bootstrap retry;
- не считать Origin/CORS WebSocket authentication;
- не отправлять Basic/credential до listener+peer owner verification;
- не считать port/TCP/HTTP/101 endpoint identity;
- не использовать high-level connect_async до owner check;
- не оставлять RPC signin/use/version/ping и другие ненужные методы;
- не оставлять metrics, any-Origin readability, identification, Postgres, slowlog, OTLP/import;
- не передавать root/plaintext DB password в daemon/argv/log/backup;
- не использовать PASSWORD при достаточном PASSHASH;
- не логировать credential header/request/DDL/verifier/raw error;
- не считать deny-all arbitrary-query policy;
- не разрешать surface шире query-only corpus;
- не считать port/status/health/ready/101 полным admission;
- не использовать startup import;
- не создавать default main/main;
- не принимать raw storage URL;
- не включать HTTP signin/export/import;
- не использовать Surreal export/import как app backup owner;
- не использовать generic JSON Value/SELECT *;
- не определять digest unordered/non-versioned encoding;
- не терять failed quarantine/config continuity;
- не принимать unsupported backup generation;
- не копировать Surreal CBOR protocol;
- не продолжать partially written restore;
- не использовать Editor для schema/user/restore;
- не использовать V2 replace-existing installer;
- не утверждать signature disposition без actual asset;
- не объявлять source/build proof runtime qualification.

## 6. Очередь

| Priority | Работа | Закрывает |
|---|---|---|
| P0 | Slice 0: exact Eliot/Surreal assets and retained launch identity; canonical RocksDB + sync=every/no-defaults; sanitized env; mutually attested relay pipe; dynamic loopback listener+peer; Origin non-authority/anonymous bounds; reconciled root bootstrap; peer-verified Basic root/Owner/Editor; query-only socket owner; typed DTOs/migrations/conflict/fsync unknown; stage_required and replay pause/drain; durable files; canonical backup with pending+failed/deletions/config and current-ledger/live-spool restore merge; graceful/forced shutdown/restart | R-002, R-006, R-019–R-020, R-072–R-073, R-081–R-107 |
| P1 | Base Slice 1: one package, supervisor/daemon/owned Store, launch/pipe/socket owners, migrations, CaptureCommand, indexes, blobs, spool/replay, status/restart open | R-001–R-007, R-019–R-020, R-033, R-037–R-040, R-071–R-073, R-079–R-107 |
| P1 | Base Slice 2: Claude relay, continuation, packet emission/retention, lexical retrieval, exact open, notes/corrections/commitments | R-003–R-013, R-023, R-036, R-039–R-044, R-074–R-081, R-104 |
| P1 | Controller inference slice | R-027, R-048, R-050–R-057, R-068–R-070 |
| P1 | One integrator/product edge/preflight/disposition per slice | R-058–R-061, R-067 |
| P1 | One Memory controller adapter on pinned swarm-client | R-056, R-069 |
| P1 | First episode-learning path after Base | R-010, R-021, R-028–R-030, R-041–R-045, R-047–R-057, R-068–R-070 |
| P2 | Installed Claude qualification | R-012–R-013, R-074, S-022 |
| P2 | Embeddings/vector arm | R-015, R-034, R-048, R-050–R-057, R-069–R-070 |
| P2 | Direct HTTPS only after TLS qualification | R-050, R-057 |
| P2 | Optional agent projection only with consumer | R-014, R-027, R-046 |
| P2 | Research fixes | R-016, R-031, R-032 |
| P2 | Documents/views/grounds increments | R-008, R-017, R-018, R-038, R-040 |
| P2 | Retire V2 generated inventories/manifests | R-059, R-063 |
| P3 | Obtain unavailable ZIP/report | S-008, S-009 |
| P3 | Deepen donor only for selected mechanism | S-010 |
| Final | Full tests after connected implementation; minimum build/Clippy during code | R-049 |

## 7. Последние изменения

| Дата / baseline | Изменение |
|---|---|
| 2026-10-23 / `2ee24de2` | First `episode_learning` recipe/result. |
| 2026-10-23 / `2ab45985` | Controller TaskPrompt/result traced. |
| 2026-10-24 / `d97b9bfb`–`0da78d29` | One-shot inference ownership and Contract 0.1–0.3. |
| 2026-10-24 / `c1401bb2`–`561fe900` | Delivery collapse/minimal mechanisms; R-058–R-067. |
| 2026-10-24 / `5f32d764`–`fdf53183` | Contract 0.4 synchronized; R-068–R-070. |
| 2026-10-24 / `036377ed`–`864ad1a2` | Base host/capture/spool/packet; R-071–R-076. |
| 2026-10-24 / `bfb23738`–`63120469` | Exact-open; R-077–R-081. |
| 2026-10-25 / `2bc53a9a`–`33666eea` | Store/schema/Windows durability; R-082–R-087. |
| 2026-10-25 / `0a162fee` | Exact asset/build/CLI; R-083/R-087/R-088. |
| 2026-10-25 / `9a4ed5ef` | Capability/import/roles; R-089–R-091. |
| 2026-10-25 / `17eb63ef` | Readiness/bootstrap/defaults/signature; R-092–R-095. |
| 2026-10-25 / `7353871a` | Shutdown/sync/PASSHASH/env/JSON/backup; R-096–R-101. |
| 2026-10-25 / `7d49fd2a`–`c799ed76` | Implementation draft.23 + README Store profile. |
| 2026-10-25 / `745087bd`–`353dd063` | Implementation draft.24 + README bootstrap/stage_required/canonical backup. |
| 2026-10-25 / `2f17d7ee`–`51921866` | Implementation draft.25 + README dynamic endpoint, owned listener/peer, Basic handshake, query-only RPC and Origin correction; R-102–R-103 and S-044–S-045. |
| 2026-10-26 / `57915d60`–`90b34be8` | Implementation draft.26 + README retained launch, mutually attested relay pipe, socket owner, replay barrier and monotonic restore; R-104–R-107 and S-046–S-048. |
