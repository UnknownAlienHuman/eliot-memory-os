# Eliot V3 — реестр анализа

**Статус на 2026-10-25 · нормативная база Architecture draft.8 / Implementation draft.22 / Cognition draft.11 / Inference Contract 0.4; controller `e42c464d`; активный рабочий реестр, не runtime gate.**

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
| R-002 | Process family и idle drain | Implementation §§1,14; V2 I1.5/I14.22; Windows donors | `DECIDED` design / `NOT IMPLEMENTED` runtime | Один supervisor, daemon и exact-pinned SurrealDB child; Store admission before capture; finite spool/job drain. | Реализовать mutex, suspended Job Object launch, Store admission, restart и shutdown. |
| R-003 | Continuation address | Architecture §4.1; Implementation §3.1; Cognition §2 | `DECIDED` | Project/workspace + task либо actor/session; branch/path/HEAD — environment state. | Проверить два workspaces, branch switch, fork, transfer, late result. |
| R-004 | Context packet identity | Architecture §3.5; Implementation §§4.7,5.9,6.3; Cognition §§6.6–6.7 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Packet = rendered bytes/digest + actual revisions + gaps; ordinary observation/blob+links, не PacketStore. | Реализовать coherent hydration, retention и actual host emission. |
| R-005 | Structured correction | Implementation §§5.3,5.6 | `DECIDED` | Correction observation + revision/history + saved result в одной transaction; replay не применяет дважды. | Реализовать command path, stale conflict и readback. |
| R-006 | Six tables and Store operations | Implementation §§4–5; SurrealDB 3.3.4 docs | `CHECKED` design / `NOT IMPLEMENTED` runtime | `STRICT` DB, six `SCHEMAFULL` tables, explicit fields, derived optional unique keys, fixed queries, snapshot transactions. | Написать migration 0001/query assets и выполнить Slice 0. |
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
| R-019 | Backup/restore | Implementation §12; exact 3.3.4 export/import source; V2 reads | `CHECKED` design / `NOT QUALIFIED` runtime | Logical export over authenticated HTTP route, V3-owned dump/blob/manifest publication and import into a fresh candidate. Import is statement-by-statement, may continue after failures and return partial state; any failed candidate is discarded whole. | Execute exact Windows RocksDB export/import and candidate-discard round-trip. |
| R-020 | Erasure/reappearance | Architecture §4.10; Implementation §12.1; Cognition §13 | `PARTIAL` | Deletion notice, replay check and controller late-result fence selected. | Реализовать traversal, backups/spool and all controlled copies. |
| R-021 | Recursive improvement | Architecture §7; Cognition §10 | `PARTIAL` | Диагностируется конкретный failed edge; нет global intelligence score. | Connected source→context→result→revision path after Base/controller. |
| R-022 | Disagreement/anticipation | Architecture §8; Cognition §11 | `CHECKED` | Alternatives+grounds+cheapest distinguishing observation; no voting. | Ordinary records after core path. |
| R-023 | Control/status/inbox | Architecture §9; Implementation §13 | `DECIDED` | Status derives from binary/engine/schema/process/spool/jobs/packets/reads/profile/copy facts. | Реализовать actual status and commands. |
| R-024 | Normative consistency | Architecture 8 / Implementation 22 / Cognition 11 / Contract 0.4 / README | `PARTIAL` | Existing books agree through Store baseline, but exact capability, readiness, bootstrap/defaults, maintenance route and credential-role decisions from R-089–R-095 are not yet mirrored in Implementation/README. | Update owner docs after Slice 0 freezes the working profile; do not create another contract. |
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
| R-072 | Relay/spool ownership | Architecture/Implementation/Cognition current | `CHECKED` design / `NOT IMPLEMENTED` runtime | One immutable command; committed requires Store readback; staged requires file+dir durability/readback. | Implement minimal Windows primitive and fair replay. |
| R-073 | Occurrence identity/source bytes | Current books | `CHECKED` design / `NOT IMPLEMENTED` runtime | Native/command ID identifies occurrence; digest verifies bytes; equal content stays distinct. | Implement fields/indexes/conflicts/exclusions. |
| R-074 | Claude schema drift | Actual hooks config/internal docs/public docs | `PARTIAL` | V3 event profile selected; installed build unverified. | Installed-version qualification. |
| R-075 | Packet handoff | Current books | `CHECKED` design / `NOT IMPLEMENTED` runtime | Actual bounded packet; prepared/emitted/associated/use distinct. | Host output/readback/gaps. |
| R-076 | Base normative consistency | README; Architecture 8; Implementation 22; Cognition 11 | `CHECKED` | Host/capture/spool/packet/open/Store baseline synchronized. | Keep synchronized during code. |
| R-077 | Legacy packet explicit-call dependency | Task handlers/MCP/SKILL | `CHECKED` exact paths | Full packet only after explicit compile call; no SessionStart connection. | Do not port. |
| R-078 | Legacy packet authority multiplication | Context/commit/outbox paths | `CHECKED` representative / `NOT SELECTED` | Parallel authority/projection without automatic delivery. | Ordinary observation/blob+links. |
| R-079 | Legacy exact read empty selector/relation loss | ReadService/MCP/T13 | `CHECKED` exact paths | Empty exact selector can become broad; endpoint filter hides material relations. | One exact handle; return relation descriptors. |
| R-080 | Legacy read coverage/cursor | `fetch_atoms_l2.surql` and filters | `CHECKED` exact path | Fixed caps have no honest cursor/coverage. | Typed exact envelope/cursor. |
| R-081 | Exact-open consistency | Current README/books | `CHECKED` design / `NOT IMPLEMENTED` runtime | Exact current/history/source/representation handles, dispositions, ranges and identity cursor. | Implement readers and edge cases. |
| R-082 | SurrealDB Rust SDK fit | Root Cargo/toolchain/deny; SDK 3.3.4 metadata; V2 adapter | `CHECKED` / `NOT SELECTED` baseline | SDK requires Rust 1.95 while workspace declares 1.94; published license metadata conflicts with current allowlist on paper; no SDK dependency exists. | Reconsider only after exact cargo check/deny/size proof. |
| R-083 | Exact SurrealDB Windows release identity | Official release/tag API and build workflow; Implementation §§1.2–1.3 | `CHECKED` release identity / `NOT QUALIFIED` runtime | Tag `v3.3.4` resolves to commit `1ac2b1dba7cd177621a4cf5d507caebeb2414395`. Asset `surreal-v3.3.4.windows-amd64.exe`, asset ID `655787929`, size `321555968`, SHA-256 `1255a3b2e771b8853e9ee0aca0ddde09dbe4532248502a5d900eb3997955f0cc`. Installer verifies digest and retains approved bytes. | Download/hash approved asset and run Slice 0. |
| R-084 | Store RPC/mutation replay | V2 session donor; exact tag RPC source | `CHECKED` design / `NOT IMPLEMENTED` runtime | Bounded JSON WS on `/rpc`, `json` subprotocol, fixed methods/queries, one in-flight/socket, exact IDs, no blind replay. Route and method capability gates are independent. | Implement parser/bounds/errors/readback. |
| R-085 | Schema/migration/transactions | Current SurrealDB docs; Implementation §§4–5.2 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Checksummed `.surql`, DB generation param/INFO, strict schemafull, derived unique keys, snapshot transactions, FOR UPDATE/sentinel. | Write migration 0001 and run conflict/rollback cases. |
| R-086 | Windows immutable publication | Microsoft API docs; current donors; Implementation §§5.4–5.5 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Local NTFS/ReFS; create-new temp; file flush; no-replace WRITE_THROUGH rename; parent flush; exact readback; post-rename sync failure unknown. | Implement and force file/rename/dir-sync/restart outcomes. |
| R-087 | SurrealDB RocksDB build/runtime qualification | Tag `v3.3.4` server Cargo + rolling Windows build; storage docs | `CHECKED` build provenance / `OPEN` runtime | Server default features include `storage-rocksdb`; official Windows asset is built with RocksDB support. Actual Windows RocksDB start/restart/conflict/export/import/durability remains unrun. | Run standalone asset against disposable `rocksdb:` root; no SurrealKV fallback. |
| R-088 | Standalone CLI, secrets and capability posture | Exact tag `cli/start.rs`, `dbs/mod.rs`, validator, auth arguments | `CHECKED` source design / `NOT QUALIFIED` runtime | Launch is `surreal start <storage-url>`. Non-secret path/bind/timeouts/capabilities are explicit. Secrets use child-only environment. `--deny-all` is necessary but arbitrary-query needs its own explicit subject selection. | Qualify exact argument vector, environment, path syntax and admissions on Windows. |
| R-089 | Exact Store capability surface | Exact tag `dbs/mod.rs`, RPC capabilities/method/protocol and `/rpc` route | `CHECKED` source design / `NOT QUALIFIED` runtime | Transparent qualification target: `--deny-all`; `--allow-arbitrary-query system`; `--deny-arbitrary-query guest,record`; HTTP routes `rpc,signin,export,import`; RPC methods `signin,use,version,query,ping`; no guest/net/script/eval/experimental. General arbitrary-query deny + specific system allow also source-normalizes correctly, but the explicit subject split avoids relying on that special case. Function allowlist starts empty and grows only from checked-in query corpus. Capability flags do not inspect SQL body, so fixed-query private client remains the real statement boundary. | Run allowed and denied route/method/subject/function matrix against exact asset; then mirror final profile in Implementation. |
| R-090 | Exact export/import and partial-restore semantics | Exact tag CLI `export.rs`/`import.rs`, network routes and auth arguments | `CHECKED` source design / `NOT QUALIFIED` runtime | Export/import are authenticated HTTP routes. CLI secrets can arrive through `SURREAL_USER/PASS` and DB selection env. Export must use an exact schema-generation-owned subset rather than broad defaults. Record versions are not exported; V3 history is ordinary rows. Import commits statement-by-statement, continues past failures and can return 422 with partial state. Startup import logs failed statements but can still mark the server ready, so it is not selected for migration or restore. | Export to V3-owned temp, hash/publish manifest, import once into empty candidate, discard entire candidate on any failure, then verify schema/counts/handles/conflicts. |
| R-091 | Store credential roles | Prior user constraint; exact tag auth levels, IAM roles/policy, credential startup and import permission | `DECIDED` design / `NOT QUALIFIED` runtime | Windows Credential Manager remains sole secret authority. Root bootstrap credential is installer/supervisor-only and creates a root user only when none exists; presence in environment does not prove later signin or rotation. Normal daemon uses database-scoped Editor. Schema/backup/restore use separate database-scoped Owner because import requires `Edit Any`; root does not enter daemon, backup manifest or CLI argv. | Slice 0 creates/signs in root once, provisions both DB users, proves runtime corpus under Editor and maintenance/export/import under Owner, then proves later restart without root secret. |
| R-092 | SurrealDB readiness versus V3 Store readiness | Exact tag `cli/start.rs`, `ntw/ready.rs`, startup tests | `CHECKED` source design / `NOT QUALIFIED` runtime | Listener/status/health/version can be reachable while startup work is incomplete. `/ready` is necessary and checks startup flag plus fresh node heartbeat, but is not sufficient for V3 Store. Store ready requires exact process/binary/listener ownership, `/ready` 200, runtime-credential signin/use, RPC version, schema generation/INFO and bounded write/read/delete readback. | Run delayed-start/fatal-start/stale-heartbeat/bad-credential/bad-schema/probe-failure matrix and verify no capture before full admission. |
| R-093 | Startup import as restore anti-donor | Exact tag `finish_startup`, readiness transition and current issue evidence | `CHECKED` / `NOT SELECTED` | Startup import is non-transactional; failed statements are logged but not returned, credential setup continues, and successful `finish_startup` can set ready. It cannot own migration/restore or certify a candidate. | Do not pass `--import-file`; use authenticated import into isolated candidate plus full verification/discard. |
| R-094 | Storage URL and default database ownership | Exact tag `any` endpoint parser/path tests and `no_defaults` startup source | `CHECKED` source design / `NOT QUALIFIED` Windows runtime | Local endpoint parser accepts `rocksdb:<path>`/`rocksdb://<path>` and preserves Windows drive/backslash forms after normalization. V3 supplies one installer-generated canonical URL and exact retained root; caller raw URLs are forbidden. Start with `--no-defaults` so SurrealDB does not create unowned `main/main`; installer creates only configured namespace/database. | Slice 0 compares accepted Windows spellings, chooses one canonical form, proves same root after restart and confirms no `main/main`. |
| R-095 | External binary materialization and signature evidence | Official release/build workflows; V2 provisioner and release docs | `PARTIAL` | Exact release SHA and build checksum exist. No Authenticode signing step was found in inspected public Windows build/promotion path, but actual asset signature was not inspected, so unsigned is not claimed. V3 installer uses create-new immutable destination, exact SHA-256/PE/path identity and retained approved bytes; old project-local provisioner `os.replace` path is not runtime installation authority. | Download actual asset on Windows, verify SHA/PE/Authenticode disposition, no-reparse source/destination and create-new publication; retain observed evidence without inventing signature. |

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
| S-025 | Current Base normative synchronization | `CHECKED` Architecture 8 / Implementation 22 / Cognition 11 / README | No runtime/build/test. |
| S-026 | Repository dependency/platform inventory | `CHECKED` root Cargo/toolchain/deny, V2 Store/Windows donors | Establishes dependency and donor facts only. |
| S-027 | SurrealDB 3.3.4 docs/package metadata | `CHECKED` SDK/RPC/schema/index/transaction/storage docs | Public contract, not live binary proof. |
| S-028 | Microsoft Win32 file API docs | `CHECKED` CreateFile/FlushFileBuffers/MoveFile semantics | API contract, no crash/power-loss run. |
| S-029 | Store/durability normative synchronization | `CHECKED` Implementation 22 + README + R-082–R-087 | Design only. |
| S-030 | SurrealDB `v3.3.4` release/tag/build provenance | `CHECKED` release API, tag commit, server Cargo, rolling channel and Windows build action | Exact identity/build features; no execution. |
| S-031 | SurrealDB standalone start source | `CHECKED` exact tag `cli/start.rs`, `dbs/mod.rs` | Exact arguments/defaults; Windows invocation still unrun. |
| S-032 | SurrealDB exact capability/RPC source | `CHECKED` tag `v3.3.4` `dbs/mod.rs`, validator, RPC capabilities/method/protocol and `/rpc` route | Establishes CLI normalization, allow/deny precedence, route/method/subject gates. Does not prove exact command line on Windows. |
| S-033 | SurrealDB exact export/import source | `CHECKED` tag `v3.3.4` CLI export/import, HTTP routes and auth arguments | Establishes route permissions, env credentials, export selection and partial import; no round-trip. |
| S-034 | SurrealDB exact IAM roles/policy | `CHECKED` tag `v3.3.4` IAM roles/policy plus import permission check | Establishes Editor/Owner distinction and why import needs Owner; user creation/sign-in not run. |
| S-035 | SurrealDB exact readiness/startup source | `CHECKED` tag `v3.3.4` `cli/start.rs`, `ntw/ready.rs`, `dbs/mod.rs` and tests | Establishes port/health/ready separation and startup-import readiness defect; no live timing/failure run. |
| S-036 | SurrealDB endpoint/default ownership source | `CHECKED` tag `v3.3.4` any-endpoint parser, path normalization tests and `no_defaults` code | Establishes accepted forms/default creation; no target Windows path execution. |
| S-037 | External binary provision/signature paths | `CHECKED` official rolling/release workflows and current V2 provision/release selected paths | No public signing step found; actual PE signature not observed. |

## 4. Findings from current focused passes

### 2026-10-24 — Base host/capture/context/open

Legacy `forwarded` was shape-only; spool lacked a durable replayer; occurrence used content hash; SessionStart returned status rather than context; packet creation depended on explicit agent call and parallel authority; exact L2 allowed broad empty selector, relation loss and silent fixed caps. Current Architecture 8 / Implementation 22 / Cognition 11 replace these paths without a new subsystem.

Counterexamples retained: two identical prompts are two occurrences; lost commit reply replays the same command; temp-before-rename is not staged; deletion notice blocks old replay; prepared packet is not emitted; exact empty selector is not broad; relation descriptor does not require neighbor body; capped page needs cursor; historical handle never falls forward.

### 2026-10-25 — Store, schema, capability, readiness and Windows durability

Established:

1. no official SurrealDB SDK dependency exists; V2 uses custom WebSocket RPC;
2. current SDK requires Rust 1.95 while workspace declares 1.94 and its package metadata needs explicit license admission;
3. V2 major-only pin and SurrealKV default are insufficient;
4. bounded JSON RPC covers the required remote surface without engine/SDK linkage;
5. snapshot isolation needs unique values or locked sentinel records for set invariants;
6. strict/schemafull definitions, params and INFO support a small migration owner;
7. Windows immutable publication requires file flush, no-replace write-through rename, parent-directory flush and exact readback;
8. post-rename sync failure is a possible committed filesystem effect and must reconcile;
9. logical export/import, not live engine-directory copy, owns application backup;
10. `v3.3.4` resolves to commit `1ac2b1dba7cd177621a4cf5d507caebeb2414395` and R-083 records the exact asset/digest;
11. official Windows build uses default server features including RocksDB, but runtime qualification remains open;
12. standalone launch is `surreal start`, not launcher syntax;
13. HTTP route and RPC method allowlists are separate gates;
14. `--deny-all` does not itself select arbitrary-query subjects; explicit system allow and guest/record denial are selected. The source also supports general arbitrary-query deny plus specific exceptions, but V3 avoids relying on that translation;
15. root/namespace/database authenticated sessions map to `system`, while guest and record actors remain separate targets;
16. exposing only RPC `query` still grants arbitrary SurrealQL to that authenticated system actor, so the private fixed-query client is the statement-level boundary;
17. export/import are separate HTTP routes; credentials/selection support environment variables;
18. import is non-transactional, continues after statement failures and can leave a partial database;
19. database Owner can edit any resource at its level, while Editor lacks `Any`, so maintenance import cannot use the runtime Editor identity;
20. listener/status/health can be available before query/auth readiness; `/ready` adds startup and heartbeat evidence but not V3 schema/credential/probe evidence;
21. startup import can log failed statements, continue, initialise credentials and let readiness turn true, so it cannot own V3 migration/restore;
22. first boot creates `main/main` unless `--no-defaults` is explicit;
23. bootstrap credentials create root only when no root user exists; later environment presence does not verify signin or rotate it;
24. endpoint parser accepts multiple RocksDB path spellings, so V3 must generate and qualify one canonical Windows form rather than preserve caller raw URL;
25. public build/provision paths establish SHA and PE provenance but do not establish Authenticode; actual asset inspection remains required;
26. release/build/source proof is not runtime qualification.

Qualification target, not a claimed working command:

```text
--deny-all
--allow-arbitrary-query system
--deny-arbitrary-query guest,record
--allow-http rpc,signin,export,import
--allow-rpc signin,use,version,query,ping
--no-defaults
```

The function allowlist is empty until the checked-in migration/query corpus proves a specific built-in function necessary.

Counterexamples, not runtime runs:

- `--deny-all` without explicit arbitrary-query subject selection → query surface remains broader than intended;
- broad arbitrary-query deny + system exception misread only from final allow/deny fields → audit the CLI normalization layer as well;
- allow RPC `query` but omit HTTP route `rpc` → WebSocket never reaches method dispatch;
- allow route `rpc` but omit method `signin` → connection exists but cannot authenticate;
- allow `query` to `guest` or `record` → accidental broader SQL principals;
- raw SurrealQL exposed behind a “private” caller wrapper → capability flags do not restrict statement family;
- TCP connected or `/health` 200 → backend/listener may exist while Store remains not ready;
- `/ready` 200 after startup import → does not prove every imported statement applied;
- root credentials present in child environment on an existing store → no proof that they match retained root user;
- omit `--no-defaults` → unowned `main/main` is created on first start;
- accept arbitrary `rocksdb:` string from config → path aliasing or another retained root can bypass installation identity;
- export default used unfiltered → users/configs/modules or other unowned resources can enter backup;
- `versions=true` assumed to preserve application history → unsupported; V3 history must be rows;
- retry failed import into same candidate → compounds unknown partial state;
- use runtime Editor for import → permission check on `Edit Any` refuses or tempts privilege widening;
- root secret handed to daemon/CLI argv → credential boundary violation;
- absence of a public signing step treated as proof of unsigned PE → unsupported until actual asset inspection;
- exact asset has RocksDB feature but `rocksdb:` startup fails on target Windows/filesystem → R-087 stays open, no fallback.

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
- не возвращать `forwarded` без Store readback;
- не возвращать `staged` до file+directory durability and exact readback;
- не overwrite conflicting pending command;
- не считать status/local file context delivery;
- не переносить PreToolUse/finish/compaction gates в Base;
- не требовать explicit agent call before host-boundary context;
- не использовать empty exact selector как broad read;
- не скрывать material relations или caps без cursor/gap;
- не подменять exact historical/source representation current/new one;
- не добавлять SurrealDB SDK без exact MSRV/license/build/size preflight;
- не pin SurrealDB only by major/tag/name or silently change storage engine;
- не expose raw caller SurrealQL/generic CRUD;
- не использовать schemaless/implicit definitions или `IF NOT EXISTS` как schema verification;
- не использовать existence query/naive UPSERT/snapshot read как concurrency invariant;
- не replay mutation blindly after possible send;
- не использовать `MOVEFILE_REPLACE_EXISTING` для immutable publication;
- не считать rename without successful directory sync durable success;
- не копировать live engine directory как Base backup;
- не fall back from RocksDB to beta SurrealKV;
- не запускать standalone release asset через launcher-only `surreal db start`;
- не передавать root password в daemon, backup manifest, argv или logs;
- не считать `--deny-all` arbitrary-query subject policy;
- не разрешать HTTP/RPC/subject/function surface шире exact checked-in corpus;
- не считать port, `/status`, `/health` или `/ready` отдельно полным V3 Store admission;
- не использовать `--import-file` для migrations/restore;
- не позволять SurrealDB создавать default `main/main`;
- не принимать raw storage URL или alternate path spelling как installation identity;
- не использовать embedded/local export/import path, bypassing owned server admission;
- не принимать broad default export as V3 backup;
- не продолжать restore в partially imported candidate;
- не использовать runtime Editor credential для maintenance import;
- не использовать V2 project-local replace-existing provisioner как V3 immutable installer;
- не утверждать Authenticode/unsigned disposition без наблюдения actual asset;
- не объявлять release/build provenance runtime qualification.

## 6. Очередь

| Priority | Работа | Закрывает |
|---|---|---|
| P0 | Slice 0: exact asset/hash/PE/signature disposition/version/help/start; canonical `rocksdb:` Windows path and no-defaults; bootstrap root then DB Owner/Editor; readiness timing and full Store admission; exact HTTP/RPC/arbitrary-query/function matrix; minimal fixed-query client; strict migrations; unique/FOR UPDATE/conflict/unknown readback; no-replace file publication; exact-subset export; failed startup/import candidate discard; logical restore verification and restart without root secret | R-002, R-006, R-019, R-072–R-073, R-081–R-095 |
| P0 | After Slice 0 freezes the working argument/credential/backup profile, update Implementation/README and return R-024 to `CHECKED`; no new contract file | R-024, R-089–R-095 |
| P1 | Base Slice 1: one package, supervisor/daemon/Store RPC, migrations, CaptureCommand, indexes, blobs, durable pending spool/replay, status and restart open | R-001–R-007, R-019–R-020, R-033, R-037–R-040, R-071–R-073, R-079–R-095 |
| P1 | Base Slice 2: qualified Claude relay, continuation, SessionStart/UserPromptSubmit packet emission, packet retention, lexical retrieval, exact open, notes/corrections/commitments and maintenance | R-003–R-013, R-023, R-036, R-039–R-044, R-074–R-081 |
| P1 | Controller inference slice: role/config/staging/dedup/runner/loopback text/readback/per-copy release; no Task/ScriptRun/new table | R-027, R-048, R-050–R-057, R-068–R-070 |
| P1 | One integrator/product edge/cheap preflight/terminal disposition per slice | R-058–R-061, R-067 |
| P1 | One Memory controller adapter on pinned `swarm-client` | R-056, R-069 |
| P1 | After Base, one episode-learning path with exact request/result/no-result/cleanup | R-010, R-021, R-028–R-030, R-041–R-045, R-047–R-057, R-068–R-070 |
| P2 | Installed Claude Code qualification | R-012–R-013, R-074, S-022 |
| P2 | Embeddings then vector arm through same lifecycle | R-015, R-034, R-048, R-050–R-057, R-069–R-070 |
| P2 | Direct HTTPS only after TLS qualification | R-050, R-057 |
| P2 | Optional agent-result projection only with real consumer | R-014, R-027, R-046 |
| P2 | Research parser/citation fixes | R-016, R-031, R-032 |
| P2 | Documents/project views/grounds as independent increments | R-008, R-017, R-018, R-038, R-040 |
| P2 | Retire V2 generated inventories/manifests during cutover | R-059, R-063 |
| P3 | Obtain unavailable ZIP/report | S-008, S-009 |
| P3 | Deepen donor only for selected unresolved mechanism | S-010 |
| Final | Full tests after connected implementation; minimum build/Clippy during code | R-049 |

## 7. Последние изменения

| Дата / baseline | Изменение |
|---|---|
| 2026-10-23 / `2ee24de2` | First `episode_learning` recipe/result. |
| 2026-10-23 / `2ab45985` | Controller TaskPrompt/result traced. |
| 2026-10-24 / `d97b9bfb`–`0da78d29` | One-shot inference ownership and Contract 0.1–0.3. |
| 2026-10-24 / `c1401bb2`–`561fe900` | Delivery collapse, manifests/inventories, minimal mechanisms; R-058–R-067. |
| 2026-10-24 / `5f32d764`–`fdf53183` | Contract 0.4 and books synchronized; R-068–R-070. |
| 2026-10-24 / `036377ed`–`864ad1a2` | Base host/capture/spool/packet; R-071–R-076. |
| 2026-10-24 / `bfb23738`–`63120469` | Exact-open contract; R-077–R-081. |
| 2026-10-25 / `2bc53a9a`–`33666eea` | Store/schema/transaction and Windows durability baseline; R-082–R-087. |
| 2026-10-25 / `0a162fee` | Exact v3.3.4 asset/tag/build/standalone launch evidence; R-083/R-087/R-088 and S-030/S-031. |
| 2026-10-25 / `9a4ed5ef` | Exact HTTP/RPC/query gates, partial import and credential roles; R-089–R-091 and S-032–S-034. |
| 2026-10-25 / readiness/bootstrap follow-up | Readiness layers, startup-import anti-donor, canonical storage/default ownership and signature evidence; R-092–R-095 and S-035–S-037. |
