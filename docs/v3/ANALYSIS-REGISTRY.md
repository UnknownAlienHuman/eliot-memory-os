# Eliot V3 — реестр анализа

**Статус на 2026-10-25 · нормативная база Architecture draft.8 / Implementation draft.22 / Cognition draft.11 / Inference Contract 0.4; controller `e42c464d`; активный рабочий реестр, не runtime gate.**

Этот файл отвечает на четыре вопроса:

1. что именно проверено;
2. на каком основании;
3. какое решение принято или какой разрыв найден;
4. что проверять следующим.

[Architecture](ARCHITECTURE.md), [Implementation](IMPLEMENTATION.md), [Cognition](COGNITION.md) и [Inference Contract](INFERENCE-CONTRACT.md) — нормативный проект. [AUDIT](AUDIT.md) — доказательная база и итоговый разбор. [AUDIT-MAP](AUDIT-MAP.md) — стабильная матрица исходных требований, исторических аудитов и доноров. **Этот файл — единственный активный реестр дальнейшего анализа.**

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

Правила:

- строка называет точный объект, а не тему вообще;
- README, search hit, DTO, fixture или receipt не дают `CHECKED` для runtime;
- исправление документа даёт `DECIDED`/`CHECKED` для design, не `IMPLEMENTED`;
- `IMPLEMENTED` появится только после реального кода и наблюдаемого input→operation→result→consumer;
- подробная историческая хронология остаётся в Git/AUDIT; здесь — активное состояние;
- новый проход обновляет существующую строку либо добавляет материальный новый риск, а не отдельный отчёт.

## 2. Активная матрица V3

| ID | Объект | Проверенный scope | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|---|
| R-001 | Граница продукта и владельцы | Architecture §§1–3; Implementation §§1–3; старые I9.1/I9.3/T12 | `CHECKED` | Host/controller владеет внешними задачами и инструментами; Eliot — памятью и собственными finite jobs. Controller владеет provider execution/readback, но не Memory job, recipe, coverage или publication. | Не возвращать Task/Attempt или provider stack внутрь Memory без нового real consumer. |
| R-002 | Локальная process family и idle drain | Implementation §§1,14; V2 I1.5/I14.22; current Windows donors | `DECIDED` design / `NOT IMPLEMENTED` runtime | Один supervisor, daemon и exact-pinned SurrealDB child; Store admission before capture; bounded spool drain; explicit shutdown не запускает Dreamer и не повторяет unknown calls. | Реализовать mutex, suspended Job Object launch, exact provider admission, restart, spool activation и cutover. |
| R-003 | Точный continuation address | Architecture §4.1; Implementation §3.1; Cognition §2 | `DECIDED` | Project/workspace + реальный task либо actor/session; branch/path/HEAD — environment state. | Проверить два workspaces, branch switch, fork, transfer и late result. |
| R-004 | Context packet identity | Architecture §3.5; Implementation §§4.7,5.9,6.3; Cognition §§6.6–6.7 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Packet хранит rendered bytes/digest и фактически включённые revisions; prepared/emitted/action-associated/use различены. Packet — ordinary observation/blob + links, не PacketStore. | Реализовать coherent hydration, packet retention и actual host emission/readback. |
| R-005 | Прямая структурированная поправка | Implementation §§5.3,5.6 | `DECIDED` | Correction observation + revision/history + saved result в одной caller-owned transaction; replay не применяет правку повторно. | Реализовать один command path и conflict/readback. |
| R-006 | Шесть таблиц и Store operations | Implementation §§4–5; SurrealDB 3.3.4 schema/index/transaction docs | `CHECKED` design / `NOT IMPLEMENTED` runtime | `STRICT` DB, six `SCHEMAFULL` tables, explicit fields, derived optional unique keys, fixed queries, snapshot transactions and full retry/readback rules selected. Exact `.surql` migrations and plans absent. | Написать migrations/query assets, run `INFO` verification, unique/conflict/read-volume preflight. |
| R-007 | Revision/history/current state | Architecture §4.5; Implementation §§4.3–4.5,5.6; Cognition §§3,8 | `DECIDED` | Exact version handle; current/history не подменяют друг друга; split не перенаправляет old handles. | Реализовать atomic publication, historical reads и restart readback. |
| R-008 | Compound grounds и propagation | Architecture §4.7; Implementation §8.3; Cognition §3.2 | `PARTIAL` | Required groups, alternatives и advisory support разделены; targeted reverse traversal выбрана. | Реализовать reducer/traversal; проверить cycles, erase и concurrent changes. |
| R-009 | Retrieval arms и packet grouping | Implementation §7; Cognition §6 | `PARTIAL` | Exact/lexical/vector/relation arms независимы; grouping не merge IDs или evidence. | Проверить реальные tokens/plans/bytes, OR noise и exception outside top-k. |
| R-010 | Реальный consumer processing method | Implementation §10; Cognition §§7,9.1 | `DECIDED` | Job freezes exact recipe revision; request builder читает её и вставляет в one inference request. | Реализовать и показать changed next request/context after revision. |
| R-011 | Cross-project reuse и disclosure | Architecture §4.6; Implementation §§4.3,9.2; Cognition §9.3 | `DECIDED` | Origin отдельно от reuse scope; shared method не расширяет disclosure sources или instance facts. | Реализовать local/selected/owner queries и deterministic disclosure reduction. |
| R-012 | Native hook → observation | Main hook paths `5aac094`; Claude docs; Architecture §3.3; Implementation §6.1; Cognition §4 | `CHECKED` design / `NOT IMPLEMENTED` runtime | First-host profile: SessionStart, UserPromptSubmit, PostToolUse, PostToolUseFailure, Stop, SubagentStop, PostCompact, SessionEnd. Exact event occurrence/source semantics определены. | Квалифицировать installed Claude version/payload и реализовать один real relay. |
| R-013 | Native context delivery | Legacy hook output; Claude SessionStart/UserPromptSubmit; Architecture §3.5; Implementation §6.3; Cognition §6.7 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Context — actual packet through supported host channel. Service status/local file не delivery. Retention, emission, action association and use separate. | Реализовать output/error/handoff; проверить timeout, startup/resume/clear/compact/fork и subagent boundaries. |
| R-014 | Controller Task/agent result route | Controller `e42c464d`: TaskSpec/claim/dispatch/Claude result | `PARTIAL` | Годится для agent work, но требует Task/Requirement/Attempt/binding и не выбран для one-shot Memory inference. R-027/R-046 остаются gaps. | Сохранить optional richer route; не использовать baseline `episode_learning`. |
| R-015 | Batch embeddings contract | Implementation §9.3; Inference Contract §7 | `GAP` | Controller `inference.embed` и canonical per-input result определены; метода нет в inspected controller catalog. | Реализовать controller route, затем vector mapping/query arm через one controller client. |
| R-016 | Research request→report→source | Research `7c034569`; Implementation §9.3 | `PARTIAL` | Реальные run/status/report/section/citation operations найдены; R-031/R-032 не исправлены. | Исправить Research owners и квалифицировать one profile. |
| R-017 | Project structure и Eliot self-view | Implementation §8.1; old structure adapter scope | `PARTIAL` | Scoped versioned views выбраны; structural tool/deployment не квалифицирован. | Проверить two checkouts, late result и affected-view refresh. |
| R-018 | Document→representation→open | Docling/Core selected paths; Implementation §8.2 | `PARTIAL` | Original bytes, retained representation, excerpts и exact open определены; decode/asset path не выполнен. | Реальная conversion/readback with partial pages/images and cost bounds. |
| R-019 | Backup/restore | Implementation §12; current SurrealDB storage/export docs; V2 restore reads | `PARTIAL` | Logical export + immutable blobs + selected spool + fresh candidate restore выбраны; copying live engine directory rejected. Exact 3.3.4 Windows RocksDB export/import round-trip not run. | Выполнить Slice 0 export/import/restart/uniqueness round-trip and cutover. |
| R-020 | Erasure и reappearance | Architecture §4.10; Implementation §12.1; Cognition §13; R-051/R-070/R-072 | `PARTIAL` | Withdrawal, exposure, refutation и physical erase разделены. Pending spool/deletion notice and controller late-result fence prevent reappearance. | Реализовать traversal, backup/spool cleanup, deletion check before replay commit и per-copy inference cleanup. |
| R-021 | Recursive improvement | Architecture §7; Cognition §10 | `PARTIAL` | Исправляется конкретный failed edge, включая capture/Store/spool/packet/open; нет global intelligence score or mandatory grader. | Выполнить connected source→context→result→revision path after Base/controller. |
| R-022 | Disagreement/anticipation | Architecture §8; Cognition §11 | `CHECKED` | Alternatives + grounds + cheapest discriminating observation; no voting; expiry != outcome. | Реализовать ordinary records after core path. |
| R-023 | Direct control/status/inbox | Architecture §9; Implementation §13 | `DECIDED` | Status derives from provider binary/version/digest, engine/schema, process/config/spool/jobs/results/packet/read/profile/cleanup facts; no readiness/attention store. | Реализовать Store admission, capture/spool/context/open/profile/cleanup visibility and commands. |
| R-024 | Normative-document consistency | Architecture draft.8; Implementation draft.22; Cognition draft.11; Contract 0.4; README current | `CHECKED` | Inference, Base capture/spool/packet/open and Store/durability baseline live in owner docs. Contract 0.4 remains sole cross-repo inference authority; no new Base/Store contract file. | При mechanism change синхронно обновлять owner docs и эту строку. |
| R-025 | Что запускает интерпретацию | Implementation §§5.3,10; Cognition §10 | `DECIDED` | New committed relevant input, correction or explicit question; Store retry/spool replay/packet handoff/read/release/cleanup do not self-trigger duplicate learning. | Проверить enqueue callers and dedup loops. |
| R-026 | Active/pending job и eligibility | Implementation §§4.6,5.7,10 | `DECIDED` | One active + coalesced pending successor enforced by optional unique slot key; first queued time preserved; waiting not retry. | Проверить continuous arrivals, two projects, modes and shutdown. |
| R-027 | Controller agent result→public artifact handle | Controller result projection `5b6b5bee/e42c464d` | `GAP` | Agent route stores nested refs but public projection loses them. | Fix only for real agent consumer; inference has separate closed receipt. |
| R-028 | Первый recipe bootstrap | Implementation §10; Cognition §7.2 | `DECIDED` | Bundled recipe saves at first enable; upgrade does not overwrite edited method. | Реализовать unique purpose address and first enable. |
| R-029 | Outcome→next decision | Implementation §§10–11; Cognition §9.2 | `DECIDED` | One current contribution per method revision/attempt/criterion; context/learning consumers. | Реализовать reducer and correction/contradiction cases. |
| R-030 | Multi-stream/late events/coverage | Implementation §10; Cognition §4 | `DECIDED` | Per-stream ranges and selected/supplied/covered distinction; no global high-water mark. | Проверить late child, partial body, omitted handle and successor. |
| R-031 | Research MCP request decoder | Research `7c034569` parser | `GAP` | Old MCP shape rejects newer method/model request before capable service. | Connect discovery/MCP to current decoder. |
| R-032 | Research citation depends on active index | Research `7c034569` citation reader | `GAP` | Retained citation can fail before source bytes when search projection changed. | Read saved representation/range directly. |
| R-033 | Useful Base/layers/light extensions | Architecture §3; Implementation §2 | `DECIDED` | One-package, internal modules, Base and independent vertical increments; no module platform. | During code review enforce imports/features/startup/Base without extensions. |
| R-034 | Encoder→derived vector→context | Implementation §§4.3,7,9.3 | `DECIDED` | Query/document role, effective space and partial batch; semantic revision unchanged. | After R-015 execute one semantic query. |
| R-035 | Architecture overconstraints | Normative rereads; old route/privacy pass | `DECIDED` | Unknown attribution/grounds no longer global blockers. Privacy/cost have narrow send-boundary checks; no Governor platform. | Do not turn missing metadata into permission gate outside owner boundary. |
| R-036 | Commitment lifecycle | Architecture §8; Implementation §11; Cognition §12 | `DECIDED` | Ordinary memory item; context/inbox readers; ACK/due/expiry do not resolve. | Implement explicit create/update/read; notifications later. |
| R-037 | Stable work identity and scoped facts | Architecture §4.1; Implementation §3.1; Cognition §§2–3 | `DECIDED` | Project/workspace/task identity separated from environment. | Real attach/capture/query/late-result path. |
| R-038 | Resource/version/representation continuity | Architecture §§4.3–4.4; Implementation §§4.7,7.3; Cognition §4 | `DECIDED` | Dirty bytes retained; rename/copy links preserve IDs; equal bytes != same source. | Check partial read after edit/move/conversion. |
| R-039 | Decision frame→lexical query | Implementation §7 | `DECIDED` | Focused question + exact cues; independent arms; no LLM planner. | Execute actual query/tokens/noise/empty input. |
| R-040 | Bounded source reading | Architecture §4.9; Implementation §§5.9,7.3,8.2; Cognition §6.5 | `DECIDED` | Metadata/excerpt then exact ranges; row/byte/element/text limits distinguished; exact cursor bound to identity/revision/options. | Implement real file/Store readers, UTF-8 ranges, long JSON/line and continuation. |
| R-041 | Automatic work and drain | Implementation §§1.3,10; R-055 | `DECIDED` | off/idle/background; finite drain; automatic inference also requires profile permission. | Implement one automatic episode after manual. |
| R-042 | Curation result consumer | Cognition §§8–10 | `DECIDED` | Output must change context/open/method request; unread report not completion. | Check same request before/after revision. |
| R-043 | Consolidation/split without ID merge | Cognition §8 | `DECIDED` | Replay, occurrence equality, grouping, revision, synthesis and split distinct; sources/handles survive. | Implement publication and historical handles. |
| R-044 | Forgetting changes reader | Cognition §13; Mem0 selected trace | `DECIDED` | Current reader uses current revision links; rare/unused not false. | Check correction after restart and scoped negative memory. |
| R-045 | First episode recipe/result | Cognition §7; old I9 corpus; Hy-Memory donor | `DECIDED` | Concrete instruction, zero-or-more changes, valid no-change and explicit partial/error. Operational failure/no-result/unknown never no-change. | Run after controller implementation: useful/no-change/partial/malformed/conflict. |
| R-046 | Claude terminal body durability | Controller Claude agent route | `GAP` | Optional agent route keeps body in boot-local LRU before page capture. | Fix only if agent route is used; Base host uses direct Stop/SubagentStop capture. |
| R-047 | One inference without second task manager | Old corpus; controller Task path; V3 docs | `CHECKED` design / `NOT IMPLEMENTED` runtime | Memory job owns semantics; controller owns execution/readback/temp copies. | Implement R-048 without Task/Attempt/provider stack in Memory. |
| R-048 | Controller `inference.text` / `inference.embed` | Controller catalog `e42c464d`; Contract 0.4 | `GAP` | Narrow methods absent; existing routes agent/task/script-oriented. | Implement staged admission, dedup, frozen profile, runner, result and unknown outcome. |
| R-049 | Code-first and test timing | User direction; Implementation §14 | `DECIDED` | Production code first, minimum build/Clippy per coherent increment; full suite after connected product. Slice 0 is dependency/durability discrimination, not a test platform. | Run exact preflight, then record minimum Clippy during code work. |
| R-050 | Minimal connection/profile/privacy/budget | Architecture §§2.3–2.4; Contract §§3–4,9 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Static connection/profile, digests, destination, two-state disclosure, finite limits, no fallback. | Implement parser/admission and disclosure reducer; qualify profiles. |
| R-051 | Inference controlled-copy lifecycle and erasure | Contract §§5,13; Architecture §2.5 | `GAP` | Input staged, result optional, per-copy cleanup with three dispositions. | Implement states/remove/fence/recovery/receipt/erasure. |
| R-052 | Taskless ScriptRun donor | Controller fixture/production paths | `CHECKED` / `NOT SELECTED` | Different product lifecycle; only Operation/recovery ideas useful. | Do not route inference through ScriptRun. |
| R-053 | Narrow inference caller authority | Controller Role/Store paths; Contract §2 | `DECIDED` design / `NOT IMPLEMENTED` runtime | Add `inference_client` exact allowlist, no MCP/generic writer. | Implement role/registration/allowlist/own reads-cancel. |
| R-054 | Closed inference artifact provenance | Controller ArtifactFiles/schema; Contract §§5,11,13 | `GAP` | Current kinds/deletion omit inference. | Add kinds, provenance, result grant and private exact removal. |
| R-055 | Operation-only runner/recovery/cancel | Controller Operation primitives; Contract §§8,10,12 | `DECIDED` design / `NOT IMPLEMENTED` runtime | Existing ledger/wake/cancel sufficient; generic mutate unsafe for raw payload. | Implement custom admission + bounded runner. |
| R-056 | Direct Memory→controller IPC dependency | `swarm-client` `e42c464d`; Contract §2.1 | `CHECKED` design / `NOT IMPLEMENTED` adapter | Exact Git dependency, no copied protocol/MCP/CLI; after-write disconnect unknown. | Pin revision, credential, frame bounds and exact reconnect replay. |
| R-057 | First provider adapter/transport | Controller OpenCode donor; reqwest; Hy-Memory | `DECIDED` design / `NOT IMPLEMENTED` runtime | Closed loopback Chat/Embeddings, no arbitrary extras/retry/fallback; loopback != local. HTTPS later explicit TLS. | Implement/Clippy loopback text first. |
| R-058 | Delivery throughput/artifact incentives | Issues #5305/#3014/#327; V3 docs | `CHECKED` | Visible artifacts displaced integrated behavior; overlap lacked disposition. | Measure closed edges/blockers. |
| R-059 | Append-only authority/context accretion | Historical issues/T files/inventories | `PARTIAL` | Corrections accumulated beside old plans; V3 docs/registry current. | Retire/label V2 authorities at cutover. |
| R-060 | Cheap preflight/WIP backpressure | Issue #5305; AGENTS/README | `DECIDED` | Reject config/stale/duplicate before expensive setup; overlap waits. | Use ordinary issue/PR ownership. |
| R-061 | Vertical completion criterion | Issues; Architecture §§1,11; Implementation §14 | `CHECKED` design | Caller→operation→durable result/unknown→consumer/readback→restart/recovery. | Denominator for slices/reviews. |
| R-062 | Physical decomposition/manifest inversion | Root Cargo; sampled manifests/source | `CHECKED` representative / `PARTIAL` corpus | ~188 packages/large manifests turn helpers into products. | Keep internal module until measured boundary. |
| R-063 | Generated inventories as work | Two exact work-unit inventories | `CHECKED` | Scans became mandatory denominators. | Do not port; retire after consumer search. |
| R-064 | Intent–mechanism inversion | Old Architecture/Implementation sections | `CHECKED` | Intent-first prose coexisted with mandatory object families. | Admit only after caller/owner/result/consumer. |
| R-065 | Crate-first capacity target | Old Implementation; current workspace | `CHECKED` correlation / `PARTIAL` causality | Crate capacity became local default. | One package/modules; no contours/testd/promotion before measured boundary. |
| R-066 | Identity/proof object multiplication | Old identity/conformance/CCU/capsules/proofs | `CHECKED` | Synchronization graph outgrew product edge. | Use Git/schema/operation IDs at real boundaries. |
| R-067 | Anti-proxy rules lacked backpressure | Old clauses/issues/artifacts | `CHECKED` | Rules condemned proxy work but did not block new object families. | One ledger/integrator/WIP stop/preflight. |
| R-068 | Authoritative profile/destination admission | Contract §§3–4,6; V3 books | `CHECKED` design / `NOT IMPLEMENTED` runtime | Controller resolves destination/digests and checks disclosure/origin/limits/format. | Implement waiting/rejection mapping. |
| R-069 | One Memory controller client | Implementation §9; Cognition §14 | `DECIDED` design / `NOT IMPLEMENTED` runtime | One adapter owns text/embed/read/cancel/release; semantics stay feature modules. | Pin `swarm-client`, implement adapter. |
| R-070 | No-result/partial cleanup/erasure abandonment | Contract §§5.3,12–13; V3 books | `CHECKED` design / `NOT IMPLEMENTED` runtime | Result optional; terminal no-result releases input; unresolved erase fences; per-copy states. | Implement dispositions/recovery/late fence. |
| R-071 | Legacy hook forwarder shape-only | `service.rs`; shape test; main search | `CHECKED` exact code | `forwarded` without send; spool path hash; no production caller/replayer found. | Do not port; exact CaptureCommand + ownership result. |
| R-072 | Base relay/spool ownership | Architecture §§3.4,4.2; Implementation §§3.2,4.8,5.3–5.5; Cognition §§1.1–1.2,10 | `CHECKED` design / `NOT IMPLEMENTED` runtime | One command before IPC; committed requires Store readback; staged requires create-new temp, file sync, no-replace WRITE_THROUGH rename, parent sync and exact readback; post-rename sync failure is unknown. | Implement minimal Windows primitive, fair replay, failed quarantine, deletion check and reconciliation. |
| R-073 | Occurrence identity/exact accepted source | Architecture §§4.2–4.3; Implementation §§3.2,4.2,5.3; Cognition §§1.1–1.2 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Native/command ID identifies occurrence; digest verifies bytes; unique indexes and exact conflict/readback selected. | Implement fields/indexes/conflicts and capture exclusions. |
| R-074 | First Claude host/schema drift | Actual hooks config, internal doc, official docs | `PARTIAL` | Selected V3 event profile is normative; installed Claude version/payload still unverified. | Run installed-version qualification and update adapter config. |
| R-075 | Real context packet handoff | Architecture §3.5; Implementation §§5.9,6.3; Cognition §6.7 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Actual bounded packet, ordinary retention/linking, prepared/emitted/associated/use distinction. | Implement host output/readback and gap handling. |
| R-076 | Base capture normative consistency | README; Architecture draft.8; Implementation draft.22; Cognition draft.11 | `CHECKED` | First-host event profile, CaptureCommand, Store admission, durable spool/replay, packet handoff and exact-open semantics synchronized without another contract doc. | Keep synchronized during implementation; runtime remains absent. |
| R-077 | Legacy packet compile is explicit-call-only | `task_handlers.rs`, MCP dispatch, `eliot-work/SKILL.md`, protocol support on main | `CHECKED` exact selected paths | Full packet only after explicit `eliot_compile_packet_l3`; no SessionStart connection found. | Do not port explicit-call dependency as Base. |
| R-078 | Legacy packet authority/projection multiplication | `context.rs`; packet commit/outbox/authority/projection paths | `CHECKED` representative / `NOT SELECTED` | Packet gained parallel authority/projection lifecycle without automatic delivery. | Ordinary packet observation/blob + links and one host emission; no packet authority store. |
| R-079 | Legacy exact L2 empty selector and relation loss | `ReadService`; MCP; T13; main `5aac094` | `CHECKED` exact paths | Empty handles can mean broad read; endpoint filter can hide material relation. | `open` requires one exact handle; return revision relation descriptors. |
| R-080 | Legacy L2 coverage/cursor incompleteness | `fetch_atoms_l2.surql`; response/filter paths | `CHECKED` exact query/path | Fixed relation caps lack honest cursor/coverage. | Typed exact envelope, per-unit bounds and cursor. |
| R-081 | Exact-open normative consistency | README; Architecture §4.9; Implementation §§5.9,7.3; Cognition §§6.4–6.5 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Current/historical/source/representation handles, descriptors, dispositions, ranges and identity-bound cursor synchronized. | Implement Store/file readers and missing/forbidden/erased/damaged/paged/revision-change cases. |
| R-082 | SurrealDB Rust SDK dependency fit | Root Cargo/rust-toolchain/deny; current SDK 3.3.4 docs/package metadata; V2 adapter | `CHECKED` / `NOT SELECTED` baseline | SDK needs Rust 1.95 while workspace declares MSRV 1.94; package license metadata points outside current allowlist; no SDK dependency exists. Bounded remote JSON RPC is smaller and already has donor code. | Implement minimal client; reconsider SDK only after exact cargo check/deny/size preflight proves benefit. |
| R-083 | Exact SurrealDB server identity | V2 major-only pin/config; current 3.3.4 docs; Implementation §§1.2–1.3 | `DECIDED` design / `NOT QUALIFIED` runtime | Pin exact 3.3.4 Windows binary path/version/SHA-256, loopback endpoint and engine; runtime `version`/schema/write-read probe before Store ready. Major-only compatibility is insufficient. | Acquire exact binary, record digest, run Slice 0 admission and failure cases. |
| R-084 | Store RPC and mutation replay | V2 `client/session.rs`; current RPC docs; Implementation §5.0 | `CHECKED` design / `NOT IMPLEMENTED` runtime | One bounded JSON WS client, `json` subprotocol, fixed methods/queries, one in-flight per socket, exact IDs, no blind reconnect replay. After-send mutation failure reconciles by app identity. | Implement RPC parser/bounds/error classification and unknown-outcome readback. |
| R-085 | Schema/migration/transaction ownership | Current SurrealDB STRICT/SCHEMAFULL/PARAM/INFO/UNIQUE/transaction docs; Implementation §§4–5.2 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Ordered checksummed `.surql`, DB generation param, INFO verification, strict schemafull tables, optional derived unique keys, snapshot transactions, `FOR UPDATE`/sentinel for read-set invariants. No SurrealKit baseline. | Write migration 0001 and fixed capture/revision queries; run conflict/rollback/readback cases. |
| R-086 | Windows immutable publication durability | Microsoft CreateFile/FlushFileBuffers/MoveFileEx docs; current replace/dir-sync donors; Implementation §§5.4–5.5 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Local fixed NTFS/ReFS only; create-new temp; file flush; no-replace WRITE_THROUGH rename; parent-directory flush; exact readback. Rename+sync failure is post-commit unknown. | Implement one internal primitive and exercise forced file/rename/dir-sync/restart outcomes. |
| R-087 | SurrealDB storage engine qualification | Current 3.3 deployment/file-backed docs; V2 SurrealKV config; Implementation §§1.2,14 | `OPEN` | SurrealDB 3.3 recommends RocksDB; SurrealKV is beta. RocksDB is selected first qualification target, but exact Windows binary support/durability/export-import has not been run. No silent fallback. | Slice 0: start exact binary on disposable RocksDB root, restart/conflict/export/import; block if unsupported. |

## 3. Source coverage

| ID | Источник | Статус | Граница вывода |
|---|---|---|---|
| S-001 | V1 Canonical Master | `CHECKED` previously read through §40 | Requirements read; not full V1 code audit. |
| S-002 | V2 Architecture/Implementation selected sections | `PARTIAL` | Many targeted rereads; no fresh whole-corpus claim. |
| S-003 | Claude audit revision 4 | `CHECKED` provided text | Ideas, not automatic norm. |
| S-004 | ELIOT audit v9 | `CHECKED` provided text | Findings not rerun every SHA. |
| S-005 | Swarm audit 2026-10-06 | `CHECKED` provided text | Controller ownership separated. |
| S-006 | August architecture audit | `CHECKED` provided text | Proof/policy machinery not auto-carried. |
| S-007 | LLM problems report | `CHECKED` provided text | Failure classes mapped, not reproduced. |
| S-008 | Release ZIP `audit-2026-10-16-incomplete` | `BLOCKED` | Metadata only; no 968-file semantic review claim. |
| S-009 | `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | `BLOCKED` | Full text absent. |
| S-010 | Donors D01–D47 and named systems | `PARTIAL` | Exact path/revision findings only. |
| S-011 | Independent subagent review | `OPEN` | No independent subagent tool available this pass. |
| S-012 | Consolidated failure audit 2026-08-05 | `PARTIAL` | Named curation path checked; counts/runtime not reproduced. |
| S-013 | Controller inference boundary | `CHECKED` selected controller paths through `e42c464d` | Design donor facts; no live provider run. |
| S-014 | Old inference privacy/routing corpus | `CHECKED` selected sections | Finite limits/no fallback kept; platform rejected. |
| S-015 | Controller taskless/Store primitives | `CHECKED` selected exact paths | Primitives/anti-donors; no worker/provider execution. |
| S-016 | Direct IPC/transport donors | `CHECKED` selected paths | No-replay IPC, bounded loopback, private files, missing current TLS. |
| S-017 | Delivery-collapse evidence | `CHECKED` issues #5305/#3014/#327 | Mechanisms confirmed; no full current census. |
| S-018 | Workspace/manifests/inventory sample | `CHECKED` exact sample | Repeated mechanism; not all crates/work-units. |
| S-019 | Retained old Architecture/Implementation copies | `CHECKED` targeted sections | Not full fresh line-by-line audit. |
| S-020 | Current inference synchronization | `CHECKED` Contract 0.4 + current books | Design consistency only. |
| S-021 | Legacy Base hook/spool path main `5aac094` | `CHECKED` exact selected files | Static audit; no live installed plugin/daemon/Store/Windows durability execution. |
| S-022 | Official Claude Code Hooks reference, 2026-10-24 | `CHECKED` current public docs | Does not prove installed version/payload. |
| S-023 | Legacy packet/context path main `5aac094` | `CHECKED` selected paths | Explicit-call dependency/machinery; no live packet execution. |
| S-024 | Legacy exact L2 path main `5aac094` | `CHECKED` selected paths | Empty-selector/relation/coverage defects; no live corpus/performance run. |
| S-025 | Current Base normative synchronization | `CHECKED` Architecture draft.8 / Implementation draft.22 / Cognition draft.11 / README | Base and Store design synchronized; no runtime/build/test execution. |
| S-026 | Current repository dependency/platform inventory | `CHECKED` root Cargo, rust-toolchain, deny.toml, V2 Store config/session, Windows file donors on main `5aac094` | Establishes no SDK dependency, MSRV/toolchain split, license allowlist, major-only server pin, custom RPC and replace-existing donor. No V3 code. |
| S-027 | Official SurrealDB 3.3.4 documentation/package metadata, checked 2026-10-25 | `CHECKED` SDK MSRV/version, RPC, STRICT/schema/INFO/PARAM/index/transaction and storage-engine pages | Public contract/design facts; does not prove exact downloaded Windows binary or performance/durability. |
| S-028 | Microsoft Win32 file API documentation, checked 2026-10-25 | `CHECKED` `CreateFileW`, `FlushFileBuffers`, `MoveFileExW`/`MoveFileW` semantics | API contract only; no V3 crash/power-loss run. |
| S-029 | Current Store/durability normative synchronization | `CHECKED` Implementation draft.22 + README + rows R-082–R-087 | Design/queue consistency only; Slice 0 remains unexecuted. |

### Источники прохода 2026-10-24 — Base host/capture/context/open boundary

Проверены legacy hook/spool, Claude docs/config, packet compiler/MCP/authority paths, exact L2 request/filter/SurQL and T13. Установлено: old `forwarded` is shape; spool lacks durable replayer; occurrence used content hash; startup returns status, not context; packet depends on explicit call and parallel authority; exact L2 permits broad empty selector, hides relations and silently caps coverage. Architecture 8 / Implementation 21 / Cognition 11 replaced those paths without a new platform.

Контрпримеры: identical prompts remain two occurrences; lost commit reply replays same command; temp-before-rename is not staged; deletion notice blocks old replay; prepared packet is not emitted; exact empty selector is not broad; relation descriptor returns without neighbor body; capped relation page needs cursor; historical handle never falls forward.

### Источники прохода 2026-10-25 — Store, schema and Windows durability boundary

Проверены:

- root `Cargo.toml`, `rust-toolchain.toml`, `deny.toml` and exact current Store/Windows donor files;
- current official SurrealDB Rust SDK, RPC, schema, index, transaction, deployment and file-backed documentation for 3.3.4;
- current Microsoft `CreateFileW`, `FlushFileBuffers`, `MoveFileExW` and `MoveFileW` documentation;
- current V3 Store/spool/backup statements.

Установлено:

1. repository has no official SurrealDB SDK dependency; V2 uses a large custom JSON WebSocket adapter;
2. current SDK requires Rust 1.95 while workspace declares MSRV 1.94, despite pinned dev toolchain 1.97.1;
3. current SDK package metadata/license file conflicts with the repository's current cargo-deny allowlist on paper; exact `cargo deny` remains the admission test;
4. V2 pins only provider major 3 and starts SurrealKV; this is too weak for reproducible schema/storage behavior;
5. remote JSON RPC supports the small required method surface and bounded fixed-query client without importing the engine/SDK;
6. snapshot isolation does not protect read-only predicate sets; unique keys or `FOR UPDATE` sentinel records are required;
7. unique indexes remain correct under concurrent writes by failing one transaction; the full immutable transaction must retry;
8. `STRICT`, `SCHEMAFULL`, DB params and `INFO` support a small migration owner without another registry/service;
9. SurrealDB 3.3 recommends RocksDB for production on-disk server deployments and labels SurrealKV beta;
10. the existing Windows replace helper uses `MOVEFILE_REPLACE_EXISTING` and cannot publish command-ID pending files;
11. Windows exposes file flush, no-replace same-volume rename and directory-handle flush needed for the selected protocol;
12. post-rename sync failure is an unknown committed filesystem effect and must reconcile, not report staged or overwrite.

Контрпримеры, не прогоны:

- exact server reports 3.3.5 under a 3.3.4 installation manifest → Store unavailable, not compatible-by-major;
- SDK compiles on Rust 1.97 but requires 1.95 → declared workspace MSRV 1.94 remains false for that dependency;
- `IF NOT EXISTS` sees an old index definition → startup must detect mismatch, not declare schema ready;
- two captures pass a prior existence check → unique index/transaction decides; one reads existing or conflicts;
- transaction reads “no active job” without unique key/sentinel → concurrent insert can violate the invariant;
- mutation response lost after send → read command/item identity before retry;
- pending final exists with different bytes → conflict, never replace;
- rename succeeds and parent flush fails → publication unknown; later exact verify + successful directory flush may reconcile;
- pending delete succeeds and directory flush fails → removal unknown; startup observes actual location and completes sync;
- copying live RocksDB directory as backup → not the application backup contract; use logical export into a fresh restore candidate;
- exact 3.3.4 Windows binary lacks working RocksDB profile → Slice 0 blocks; no silent SurrealKV fallback.

## 4. Решения, которые не открываются без нового основания

- не переносить V1/V2 runtime/compatibility facades;
- не создавать second task manager/swarm/research engine/semantic DB;
- не создавать provider stack in Memory or Task/ScriptRun inference;
- не сохранять raw inference through generic mutation or copy IPC;
- не возвращать old Governor/platform/object families;
- не блокировать Base optional capabilities;
- не считать shapes/receipts/reports/IDs product behavior;
- не создавать PacketStore/packet authority/projection family;
- не считать generated inventories/current issues current authority;
- не create crate/process per concept or per-helper manifests;
- не add ceremony to repair ceremony and not create errata docs;
- не use content digest as occurrence identity;
- не return `forwarded` without Store readback;
- не return `staged` before file sync + no-replace rename + parent sync + exact readback;
- не write spool directly to final path or overwrite a conflicting pending file;
- не treat service-status/local file as context delivery;
- не carry V2 PreToolUse/finish/compaction gates into Base;
- не require explicit agent call before useful context at host decision boundary;
- не let empty exact selector mean broad read;
- не hide material relation because neighbor body not requested;
- не claim complete read under fixed cap without cursor/gap;
- не substitute current/new representation for exact historical/source handle;
- не add official SurrealDB SDK before exact MSRV/license/build/size preflight;
- не pin SurrealDB only by major version or silently change storage engine;
- не expose caller-supplied SurrealQL/CRUD builder as Store application surface;
- не use schemaless/implicit tables or `IF NOT EXISTS` as changed-schema verification;
- не use prior existence query, naive `UPSERT` or snapshot read alone as concurrency invariant;
- не blindly replay a mutation after possible send;
- не use `MOVEFILE_REPLACE_EXISTING` for immutable spool/blob publication;
- не treat successful rename with failed directory sync as durable success;
- не copy live database engine directory as Base backup;
- не silently fall back from qualified RocksDB target to beta SurrealKV.

## 5. Очередь

| Priority | Работа | Закрывает |
|---|---|---|
| P0 | Execute Slice 0 dependency/durability preflight: exact SurrealDB 3.3.4 Windows binary/digest, RocksDB start/restart, minimal RPC, strict migrations, unique/FOR UPDATE/conflict/unknown readback, Windows no-replace publication/reconciliation and logical export/import | R-002, R-006, R-019, R-072–R-073, R-081–R-087 |
| P1 | Implement Memory Base Slice 1: one package, supervisor/daemon/Store RPC, migrations, exact CaptureCommand, identities/indexes, blobs, durable pending spool, bounded replay, status and restart open | R-001–R-007, R-019–R-020, R-033, R-037–R-040, R-071–R-073, R-079–R-087 |
| P1 | Implement Base Slice 2: qualified Claude relay, continuation, SessionStart/UserPromptSubmit context emission, packet retention/handoff, lexical retrieval, source open, notes/corrections/commitments and maintenance | R-003–R-013, R-023, R-036, R-039–R-044, R-074–R-081 |
| P1 | Controller first inference slice: role/config/staging/dedup/runner/loopback text/readback/per-copy release — no Task/ScriptRun/new table | R-027, R-048, R-050–R-057, R-068–R-070 |
| P1 | One integrator/product edge/cheap preflight/terminal overlap disposition per slice | R-058–R-061, R-067 |
| P1 | One Memory controller adapter on pinned `swarm-client` | R-056, R-069 |
| P1 | After Base, connect one episode learning path with exact request/result/no-result/cleanup | R-010, R-021, R-028–R-030, R-041–R-045, R-047–R-057, R-068–R-070 |
| P2 | Qualify installed Claude Code version/payload/timeouts/fork/subagent behavior | R-012–R-013, R-074, S-022 |
| P2 | Embeddings through same lifecycle, then vector arm | R-015, R-034, R-048, R-050–R-057, R-069–R-070 |
| P2 | Direct HTTPS only after TLS qualification | R-050, R-057 |
| P2 | Optional agent-result projection only for real consumer | R-014, R-027, R-046 |
| P2 | Research parser/citation fixes | R-016, R-031, R-032 |
| P2 | Documents/project views/grounds as independent increments | R-008, R-017, R-018, R-038, R-040 |
| P2 | Retire V2 generated inventories/manifests during cutover | R-059, R-063 |
| P3 | Obtain unavailable ZIP/report | S-008, S-009 |
| P3 | Deepen donor only for selected unresolved mechanism | S-010 |
| Final | Full tests after connected implementation; minimum build/Clippy during code | R-049 |

## 6. Последние изменения

| Дата / baseline | Изменение |
|---|---|
| 2026-10-23 / `2ee24de2` | First `episode_learning` recipe/result. |
| 2026-10-23 / `2ab45985` | Controller TaskPrompt/result traced. |
| 2026-10-24 / `d97b9bfb`–`0da78d29` | One-shot inference ownership and Contract 0.1–0.3. |
| 2026-10-24 / `c1401bb2`–`561fe900` | Delivery-collapse, manifests/inventories, goals→minimal mechanisms; R-058–R-067. |
| 2026-10-24 / `5f32d764`–`fdf53183` | Contract 0.4 and Architecture 7 / Implementation 20 / Cognition 10; R-068–R-070. |
| 2026-10-24 / `036377ed`–`864ad1a2` | Base host/capture/spool/packet and R-071–R-076/S-021–S-022. |
| 2026-10-24 / `bfb23738`–`63120469` | Exact-open contract; Architecture 8 / Implementation 21 / Cognition 11; R-077–R-081/S-023–S-025. |
| 2026-10-25 / `2bc53a9a`–`33666eea` | Store substrate/schema/transaction and Windows durability baseline; Implementation 22/README; R-082–R-087/S-026–S-029. |
