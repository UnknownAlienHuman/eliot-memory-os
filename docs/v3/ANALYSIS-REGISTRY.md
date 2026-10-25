# Eliot V3 — реестр анализа

**Статус на 2026-10-24 · нормативная база Architecture draft.7 / Implementation draft.20 / Cognition draft.10 / Inference Contract 0.4; controller `e42c464d`; активный рабочий реестр, не runtime gate.**

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
| R-001 | Граница продукта и владельцы | Architecture §§1–3; Implementation §§1–3; старые I9.1/I9.3/T12 | `CHECKED` | Host/controller владеет внешними задачами и инструментами; Eliot — памятью и собственными finite jobs. Controller владеет provider execution/readback, но не Memory job, recipe, coverage или publication. | Не возвращать Task/Attempt или provider stack внутрь Memory без нового реального consumer. |
| R-002 | Локальная process family и idle drain | Implementation §1; V2 I1.5/I14.22; Windows primitives прежних проходов | `DECIDED` | Один supervisor, daemon и SurrealDB child; конечный drain; explicit shutdown не запускает Dreamer cycle и не разрешает повтор unknown model call. | Реализовать и проверить Windows mutex, Job Object, restart и cutover. |
| R-003 | Точный continuation address | Architecture §4.1; Implementation §3.1; Cognition §2 | `DECIDED` | Project/workspace + реальный task либо actor/session; branch/path/HEAD — состояние. | Проверить два workspaces, branch switch, fork, transfer и late result. |
| R-004 | Context packet identity | Implementation §§5.5,6.2; Cognition §6; README Base host contract | `DECIDED` | Packet хранит фактически отрисованные revisions; prepared/emitted/action-associated/use различены. Packet — ordinary Eliot observation/blob + links, не PacketStore. | Провести выбранный packet/handoff contract в Implementation/Cognition и реализовать coherent hydration/readback. |
| R-005 | Прямая структурированная поправка | Implementation §§5.1,5.3–5.4 | `DECIDED` | Correction observation + revision/history + saved result в одной caller-owned transaction; replay не применяет правку повторно. | Реализовать один command path и conflict/readback. |
| R-006 | Шесть таблиц и Store operations | Implementation §§4–5 | `PARTIAL` | Общая схема и операции определены; SQL/indexes не выполнены. | Реализовать migrations/query files и проверить plans, uniqueness и объём чтения. |
| R-007 | Revision/history/current state | Architecture §4.4; Implementation §§4.3–4.5,5.3; Cognition §§3,8 | `DECIDED` | Exact version handle; current/history не подменяют друг друга; split не перенаправляет старые handles. | Реализовать atomic publication, historical reads и restart readback. |
| R-008 | Compound grounds и propagation | Architecture §4.6; Implementation §8.3; Cognition §3.2 | `PARTIAL` | Required groups, alternatives и advisory support разделены; targeted reverse traversal выбрана. | Реализовать reducer/traversal; проверить cycles, erase и concurrent changes. |
| R-009 | Retrieval arms и packet grouping | Implementation §7; Cognition §6 | `PARTIAL` | Exact/lexical/vector/relation arms независимы; grouping не merge IDs или evidence. | Проверить реальные tokens/plans/bytes, OR noise и exception outside top-k. |
| R-010 | Реальный consumer processing method | Implementation §§5.2,10.3; Cognition §§7,9.1 | `DECIDED` | Job freezes exact recipe revision; request builder читает её и вставляет в один inference request. | Реализовать и показать изменившийся следующий request/context после revision. |
| R-011 | Cross-project reuse и disclosure | Architecture §4.5; Implementation §§4.3,9.2; Cognition §9.3 | `DECIDED` | Origin отдельно от reuse scope; shared method не расширяет disclosure sources или instance facts. | Реализовать local/selected/owner queries и deterministic disclosure reduction. |
| R-012 | Native hook → observation | Main hook paths `5aac094`; current Claude hook reference; README Base host contract | `PARTIAL` | Выбран first-host profile: UserPromptSubmit, PostToolUse, PostToolUseFailure, Stop, SubagentStop, PostCompact, SessionEnd; SessionStart delivers context. Current V2 path не сохраняет точный event и теряет final/source material. | Синхронизировать Architecture/Implementation/Cognition, затем квалифицировать installed Claude version/payload и реализовать один real relay. |
| R-013 | Native context delivery | Main plugin hook output; current Claude SessionStart/UserPromptSubmit contracts; README | `PARTIAL` | Context должен быть actual packet through supported host channel. Старый SessionStart возвращает service-status phrase; local file/write не delivery. | Провести packet output/error/handoff states в books; проверить serialization, timeout, resume/clear/compact/fork и subagent boundary на installed host. |
| R-014 | Controller Task/agent result route | Controller `e42c464d`: TaskSpec/claim/dispatch/Claude result | `PARTIAL` | Годится для agent work, но требует Task/Requirement/Attempt/binding и не выбран для one-shot Memory inference. R-027/R-046 остаются его gaps. | Сохранить optional richer route; не использовать как baseline `episode_learning`. |
| R-015 | Batch embeddings contract | Implementation §§9.1,9.4; Inference Contract §7 | `GAP` | Controller `inference.embed` и canonical per-input result определены; метода нет в inspected controller catalog. | Реализовать controller route, затем vector mapping/query arm через один controller client. |
| R-016 | Research request→report→source | Research `7c034569` selected callers; Implementation §9.5 | `PARTIAL` | Реальные run/status/report/section/citation operations найдены; R-031/R-032 не исправлены. | Исправить Research owners и квалифицировать один профиль. |
| R-017 | Project structure и Eliot self-view | Implementation §8.1; old structure adapter scope | `PARTIAL` | Scoped versioned views выбраны; structural tool/deployment не квалифицирован. | Проверить два checkouts, late result и affected-view refresh. |
| R-018 | Document→representation→open | Docling/Core selected paths; Implementation §8.2 | `PARTIAL` | Original bytes, retained representation, excerpts и exact open определены; decode/asset path не выполнен. | Реальная conversion/readback с partial pages/images и cost bounds. |
| R-019 | Backup/restore | Implementation §12; Surreal/V2 restore reads прежних проходов | `PARTIAL` | Native logical export + blobs + fresh candidate restore выбраны. | Выполнить Base round-trip и Windows cutover. |
| R-020 | Erasure и reappearance | Architecture §4.8; Implementation §12.1; Cognition §13; R-051/R-070 | `PARTIAL` | Withdrawal, exposure, refutation и physical erase разделены. Controller input/result — controlled copies; unresolved Operation is fenced before erasure cleanup. | Реализовать traversal, backups/spool/late-result prevention и полный per-copy inference cleanup. |
| R-021 | Recursive improvement | Architecture §7; Cognition §10 | `PARTIAL` | Исправляется конкретный failed edge; нет global intelligence score или mandatory grader. | Выполнить connected request→revision→next context после R-048/R-050/R-051/R-053–R-057/R-068–R-070. |
| R-022 | Disagreement/anticipation | Architecture §8; Cognition §11 | `CHECKED` | Alternatives + grounds + cheapest discriminating observation; no voting; expiry != outcome. | Реализовать ordinary records after core path. |
| R-023 | Direct control/status/inbox | Implementation §13 | `DECIDED` | Status выводится из actual process/jobs/results/profile facts and per-copy cleanup; no readiness/attention store. | Реализовать configure/off/pause/cancel/status/inbox и connection/profile/cleanup visibility. |
| R-024 | Normative-document consistency | Architecture draft.7; Implementation draft.20; Cognition draft.10; Inference Contract 0.4; README current | `CHECKED` for inference boundary | Все normative документы используют current controller inference boundary. Новый Base host/capture contract tracked отдельно в R-076. | Не создавать errata layer; API change синхронно обновляет owner docs. |
| R-025 | Что запускает интерпретацию | Implementation §§5.1,10.5; Cognition §10 | `DECIDED` | New relevant input, correction or explicit question; accounting/read/release/embedding completion and terminal-no-result cleanup do not self-trigger. | Проверить enqueue callers и absence of loops. |
| R-026 | Active/pending job и eligibility | Implementation §§4.6,5.2,10.5 | `DECIDED` | Один active + coalesced pending target; first queued time сохраняется; waiting не retry. | Проверить continuous arrivals, two projects, off/idle/background и shutdown. |
| R-027 | Controller agent result→public artifact handle | Controller result writers/projection on `5b6b5bee/e42c464d` | `GAP` | `agent.result`/assembly сохраняют nested artifact refs, public projection их теряет. | Исправить optional agent-route projection только при реальном agent consumer; inference получает отдельный closed receipt. |
| R-028 | Первый recipe bootstrap | Implementation §10.3; Cognition §7.2 | `DECIDED` | Bundled recipe сохраняется при enable purpose; restart/upgrade не затирает изменённый method. | Реализовать unique purpose address и first enable. |
| R-029 | Outcome→next decision | Implementation §10.4; Cognition §9.2 | `DECIDED` | Один current contribution на method revision/attempt/criterion; context и learning — consumers. | Реализовать reducer и correction/contradiction cases. |
| R-030 | Multi-stream/late events/coverage | Implementation §10.1; Cognition §4 | `DECIDED` | Per-stream bounds and supplied-vs-covered distinction; no global high-water mark. | Проверить late child, partial body, omitted handle и successor. |
| R-031 | Research MCP request decoder | Research `7c034569` MCP/service parser | `GAP` | MCP old shape rejects newer selected method/model request before capable service. | Связать discovery/MCP с current application decoder. |
| R-032 | Research citation depends on active index | Research `7c034569` citation reader | `GAP` | Known retained citation can fail before source bytes if search projection changed. | Read saved representation/range directly under existing access. |
| R-033 | Useful Base/layers/light extensions | Old A2.3/I2.19/I6.4; Architecture §3; Implementation §2 | `DECIDED` | One-package start, acyclic internal modules, Base and independent vertical increments; no module platform. | При коде контролировать imports, features, startup and Base without extensions. |
| R-034 | Encoder→derived vector→context | Implementation §§4.3,7,9.4 | `DECIDED` | Query/document role, effective space and partial batch; semantic revision unchanged. | После R-015 выполнить one connected semantic query. |
| R-035 | Architecture overconstraints | Full normative rereads; old route/privacy pass | `DECIDED` | Unknown attribution/grounds no longer global blockers. Privacy/cost retain narrow deterministic send-boundary checks; no Governor platform. | Не превращать missing metadata в permission gate outside actual send. |
| R-036 | Commitment lifecycle | Architecture §8; Implementation §11.3; Cognition §12; old A7.5/A11.5 | `DECIDED` | Ordinary memory item; context/inbox readers; ACK/due/expiry do not resolve. | Реализовать explicit create/update/read; notifications later. |
| R-037 | Stable work identity and scoped facts | Architecture §4.1; Implementation §3.1; Cognition §§2–3 | `DECIDED` | Project/workspace/task identity separated from branch/location/version/time. | Реальный attach/capture/query/late-result path. |
| R-038 | Resource/version/representation continuity | Architecture §4.3; Implementation §4.7; Cognition §4 | `DECIDED` | Dirty bytes retained; rename/copy links не переписывают old IDs; equal bytes != same source. | Проверить partial read after edit/move and conversions. |
| R-039 | Decision frame→lexical query | Implementation §§7.1–7.3 | `DECIDED` | Focused question + exact cues; independent candidate arms; no LLM query planner. | Выполнить actual query/tokens/noise/empty input. |
| R-040 | Bounded source reading | Implementation §§5.6,7.5,8.2 | `DECIDED` | Metadata/excerpt first, selected ranges next; row limit != byte/decode limit. | Реальные file/Store readers, UTF-8 range and long JSON/line. |
| R-041 | Automatic work and drain | Implementation §§1.3,10.5; R-055 | `DECIDED` | off/idle/background; finite drain; automatic work additionally needs profile permission. Controller uses one bounded Operation runner. | Реализовать one automatic episode path after manual path. |
| R-042 | Curation result consumer | Cognition §§8–10 | `DECIDED` | Output must change normal context/open/method request; unread report not completion. | Проверить same relevant request before/after revision. |
| R-043 | Consolidation/split without ID merge | Cognition §8 | `DECIDED` | Replay, grouping, revision, synthesis and split distinct; sources and old handles survive. | Реализовать ordinary curation publication and historical handles. |
| R-044 | Forgetting changes reader | Cognition §13; Mem0 selected mutation/reader trace | `DECIDED` | Current reader uses current revision links; rare/unused not false. | Проверить correction after restart and scoped negative memory. |
| R-045 | First episode recipe/result | Cognition §7; old I9.4/I9.5/I9.7/I9.10; Hy-Memory extractor path | `DECIDED` | Concrete instruction, zero-or-more changes, typed result, valid no-change and explicit partial/error. Operational failure/no-result/unknown never becomes no-change. | Run after R-048/R-050/R-051/R-053–R-057/R-068–R-070; then useful/no-change/partial/malformed/conflict cases. |
| R-046 | Claude terminal body durability | Controller Claude stream/result path | `GAP` | Current optional agent route keeps body in boot-local bounded LRU before page capture. | Fix only if agent route is used; unrelated to direct inference artifact path. |
| R-047 | One inference without second task manager | Old I9.1/I9.3/T12; controller Task path; V3 docs | `CHECKED` design / `NOT IMPLEMENTED` runtime | One Memory job owns input/coverage/decoding/publication; controller one-shot inference owns provider execution/readback/temporary copies. | Implement R-048; do not create Task/Attempt or direct provider stack in Memory. |
| R-048 | Controller `inference.text` / `inference.embed` | Controller method catalog/source `e42c464d`; Inference Contract 0.4 | `GAP` | Narrow methods are absent. Existing routes are agent/task/script-oriented. | Implement custom staging admission, exact dedup, frozen profile/connection, runner, result artifact and unknown outcome. |
| R-049 | Code-first and test timing | User direction; Implementation §14; README | `DECIDED` | Production path first, minimum build/Clippy per coherent increment; no speculative test platform. Full suite after connected implementation. | During coding record minimum Clippy; later build tests around observable paths. |
| R-050 | Minimal connection/profile, privacy and budget | Old I9.4/I9.10/I3.6/I10.11/I10.4; Architecture §§2.3–2.4; Contract §§3–4,9 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Static connection + versioned profile, connection/profile digests, actual destination, two-state disclosure, finite limits and no fallback. No classifier/registry/approval platform. | Implement config parser/admission and Memory disclosure reducer; qualify actual profiles only when configured. |
| R-051 | Inference controlled-copy lifecycle and erasure | Controller artifacts/operations `e42c464d`; Architecture §2.5; Contract §§5,13 | `GAP` | Controller stages exact input; result is optional. Cleanup tracks each copy independently and uses `memory_copy_verified`, `terminal_without_result` or `abandon_for_erasure`. | Implement per-copy states, `remove_exact`, fencing, cleanup recovery, bounded text-free receipt and erasure integration. |
| R-052 | Taskless ScriptRun as inference donor | Controller taskless fixture and production `store/scripts.rs` on `e42c464d` | `CHECKED` / `NOT SELECTED` | Fixture qualifies Store admission but does not execute worker. Production path owns script registry, interpreter/process custody, authority/effects and multiple artifacts. | Reuse only Operation/recovery ideas; do not route inference through ScriptRun. |
| R-053 | Narrow inference caller authority | Controller Role/Store-call/object-scope path `e42c464d`; Contract §2 | `DECIDED` design / `NOT IMPLEMENTED` runtime | Existing roles are overbroad or incompatible. Add `inference_client` exact allowlist, no MCP discovery and no generic writer fallback. | Implement role serialization/registration, allowlist, own queued cancel and exact-caller reads. |
| R-054 | Closed inference artifact provenance | Controller `ArtifactFiles`, `object_scope` and schema `e42c464d`; Contract §§5,11,13 | `GAP` | Current decoder omits inference kinds and verified deletion. Result has closed read grant; input remains private; both require exact provenance/removal. | Add kinds, Operation provenance, result-only public grant and private `remove_exact`. |
| R-055 | Operation-only runner, recovery and cancellation | Generic mutation/dedup, Operation states/read/cancel `e42c464d`; Contract §§8,10,12 | `DECIDED` design / `NOT IMPLEMENTED` runtime | Existing replay/states/wake/queued cancel are sufficient. Generic mutate stores raw payload. No `inference_runs` or second scheduler selected. | Implement custom admission + bounded runner; queued cancel races CAS; sent/unknown reconciles without replay. |
| R-056 | Direct Memory→controller IPC dependency | `swarm-client` source `e42c464d`; Contract §2.1 | `CHECKED` design / `NOT IMPLEMENTED` Memory adapter | Authenticated call has no task policy/application replay; after-write disconnect becomes unknown. Exact Git dependency selected; no MCP/CLI/protocol copy. | Pin revision, load private credential, verify frame bounds and exact replay after reconnect. |
| R-057 | First provider adapter and transport boundary | Controller OpenCode donor, Cargo/reqwest features, Hy-Memory donor; Contract §9 | `DECIDED` design / `NOT IMPLEMENTED` runtime | First adapters are closed loopback Chat Completions/Embeddings without arbitrary extras/tools/stream/temperature/fallback/retry. Loopback != local destination. Direct HTTPS later with explicit TLS. | Implement/Clippy loopback text first; qualify destination; add HTTPS only as separate adapter. |
| R-058 | Delivery throughput and artifact incentives | Issues #5305, #3014, #327; V3 AGENTS/README | `CHECKED` | Branches, PRs, receipts/docs were treated as progress while product edges remained open; overlapping work lacked current disposition. | Measure closed product edges/blockers; require owner + terminal disposition. |
| R-059 | Append-only authority and context accretion | Historical issue bodies, root T files, inventories, V3 authority split | `PARTIAL` | Corrections accumulated beside superseded plans. V3 books + registry are current; Git/issues are history. | During cutover retire/label V2 authorities; no coequal V3 report. |
| R-060 | Cheap preflight and WIP backpressure | Issue #5305; AGENTS/README | `DECIDED` | Admission/config/duplicate-owner failures run before expensive setup. Overlap waits for terminal disposition. | Use ordinary issue/PR ownership; add no gate absent proven need. |
| R-061 | Vertical completion criterion | Issues #3014/#5305; Architecture §§1,11; Implementation §14 | `CHECKED` design | Completion = caller→operation→durable result/unknown→consumer/readback→restart/recovery. Local artifacts are intermediate. | Use as denominator for every slice/review. |
| R-062 | Физическое дробление и manifest inversion | Root Cargo; sampled helper manifests/source | `CHECKED` representative / `PARTIAL` corpus | ~188 packages and large per-helper manifests turn helpers into governed products. V3 begins one package/internal modules. | Keep `mod` until measured dependency/deployment/change boundary. |
| R-063 | Committed derived inventories as work | Two exact `.github/work-units` inventories | `CHECKED` exact files | Generated scans became mandatory denominators and permanent synchronization work. | Do not port; retire/archive after consumer search. |
| R-064 | Intent–mechanism inversion | Old Architecture/Implementation targeted sections; current samples | `CHECKED` | Intent-first/simplest-mechanism prose coexisted with mandatory identity/manifest/proof/work schemas. | Admit mechanisms only after named caller/owner/result/consumer; replace/delete over corrective layer. |
| R-065 | Crate-first decomposition as capacity target | Old Implementation status/I17; current workspace | `CHECKED` correlation / `PARTIAL` causality | Tens/hundreds crates, contours/testd/promotion became locally satisfiable default despite anti-metric prose. | One package/modules; no contour/test daemon/generation lifecycle before measured boundary. |
| R-066 | Identity/proof object multiplication | Old normative identity/conformance/Product Identity/CCU/capsules/proof levels | `CHECKED` exact constructs | Locally useful objects formed synchronization graph exceeding product edge cost. | Use Git/schema/operation IDs at real boundaries and product-edge evidence. |
| R-067 | Anti-proxy rules lacked admission backpressure | Old anti-ceremony clauses; issues #5305/#3014; artifacts | `CHECKED` | Rules condemned proxy work but did not prevent new artifact families before product proof or overlap disposition. | One ledger/integrator, WIP stop, cheap preflight, no mechanism before need. |
| R-068 | Authoritative profile/destination admission | Contract §§3–4,6; Architecture §§2.3–2.4; Implementation §9.2; Cognition §7.1 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Memory reduces disclosure/selects profile. Controller resolves connection/destination, freezes digests and checks disclosure/origin/limits/format. | Implement specific waiting/rejection mapping without retry loops. |
| R-069 | Один Memory-side controller client | Implementation §§2.1,9.1; Cognition §14; Contract §§1–2.1 | `DECIDED` design / `NOT IMPLEMENTED` runtime | One IPC adapter owns text/embed/Operation/artifact/cancel/release. Learning/vectors own semantics. | Pin `swarm-client` and implement one adapter before feature handlers. |
| R-070 | No-result, partial cleanup and erasure abandonment | Contract §§5.3,12–13; Architecture §§2.5,7.1,9; Implementation §§4.6,5.4,9.3,12.1; Cognition §§7.4–7.5,13 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Result is optional. Terminal no-result releases input; unresolved erasure explicitly abandons/fences; input/result cleanup states remain separate; aggregate `released` cannot hide partial failure. | Implement dispositions, per-copy receipt/recovery and late-result fence; exercise cancel/fail/unknown/partial-cleanup cases. |
| R-071 | Legacy hook forwarder is shape-only | `crates/eliot-engine/src/service.rs`; `tests/windows_service.rs`; code search on main `5aac094` | `CHECKED` exact code | `daemon_reachable=true` returns `forwarded` without sending; fallback writes a JSON file and path hash. Only test caller was found; test checks response shape, not Store/replay/consumer. | Do not port. Replace with one exact CaptureCommand and Store-or-durable-spool ownership result. |
| R-072 | Base relay/spool ownership | README current; legacy writers in `plugin.rs`/`service.rs` | `DECIDED` design / `NOT IMPLEMENTED` runtime | One command is created before IPC, reused by direct call/replay; committed requires Store readback, staged requires atomic durable spool; daemon is sole replayer; pending body removed after readback. | Conduct design into Implementation/Cognition, then implement temp+sync+rename+dir-sync, failed quarantine and finite fair replay. |
| R-073 | Occurrence identity and exact accepted source | `plugin.rs` main `5aac094`; README current | `DECIDED` design / `NOT IMPLEMENTED` runtime | Content hash is verification, not occurrence ID. Native IDs or relay command identify occurrence. Generic sanitizer/truncation cannot silently replace accepted source or erase URL/path/final message; limitations are explicit. | Add exact command/body/blob fields and replay conflict rules to Implementation/schema before code. |
| R-074 | First Claude host surface and schema drift | Actual `hooks.json`, Claude integration doc, current official Claude Code Hooks reference | `PARTIAL` | Actual plugin has 7 events; internal doc claims a different set of 8. Current public API exposes UserPromptSubmit, success/failure tool events, Stop/SubagentStop final messages, PostCompact and SessionEnd. README selects minimal V3 profile. | Verify installed Claude version and emitted payloads; then update V3 host adapter/config. Do not treat public docs as installed-runtime proof. |
| R-075 | Real context packet handoff | Legacy `stdout_for_decision`; official SessionStart/UserPromptSubmit outputs; README current | `DECIDED` design / `NOT IMPLEMENTED` runtime | Old SessionStart injects “event spooled” service prose. V3 emits actual bounded packet, records ordinary observation/blob + revision links, and distinguishes prepared/emitted/associated/use. | Sync books and implement actual hook output/readback; test timeout/resume/clear/compact/fork and explicit gap. |
| R-076 | Base capture normative consistency | README current versus Architecture draft.7 / Implementation draft.20 / Cognition draft.10 | `PARTIAL` | High-level first-host/capture/spool/packet decisions are selected in README; detailed books still contain only generic capture/spool language and do not yet define exact event profile or durability protocol. | Update Architecture/Implementation/Cognition in one pass; then change this row to CHECKED without creating another contract document. |

## 3. Source coverage

| ID | Источник | Статус | Граница вывода |
|---|---|---|---|
| S-001 | V1 Canonical Master | `CHECKED` ранее прочитанного документа до §40 | Requirements read; не полный V1 code audit. |
| S-002 | V2 Architecture/Implementation selected sections | `PARTIAL` | Много разделов перечитано по вопросам; весь корпус не объявлен свежо проверенным. |
| S-003 | Claude audit revision 4 | `CHECKED` provided text | Source of ideas, not automatic norm. |
| S-004 | ELIOT audit v9 | `CHECKED` provided text | Findings not rerun on every SHA. |
| S-005 | Swarm audit 2026-10-06 | `CHECKED` provided text | Controller ownership separated. |
| S-006 | August architecture audit | `CHECKED` provided text | Proof/policy machinery not auto-carried. |
| S-007 | LLM problems report | `CHECKED` provided text | Failure classes mapped; incidents not reproduced. |
| S-008 | Release ZIP `audit-2026-10-16-incomplete` | `BLOCKED` | Metadata only; no full 968-file semantic review claim. |
| S-009 | `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | `BLOCKED` | Full text absent. |
| S-010 | Donors D01–D47, Hy-Memory, Mem0, Docling, Research, controller | `PARTIAL` | Findings apply to exact paths/revisions; no whole donor qualification. |
| S-011 | Independent subagent review | `OPEN` | No independent subagent review available this pass. |
| S-012 | Consolidated failure audit 2026-08-05 | `PARTIAL` | Named curation preview path checked; counts/runtime not reproduced. |
| S-013 | Controller inference boundary | `CHECKED` Task/claim/dispatch/catalog/config/artifacts through `e42c464d` | Established Task cost and missing narrow inference/release; no live provider run. |
| S-014 | Old inference privacy/routing corpus | `CHECKED` selected old sections | Kept finite limits/requested-observed/no fallback; rejected platform. |
| S-015 | Controller taskless execution/Store primitives | `CHECKED` exact selected paths `e42c464d` | Reusable primitives and anti-donors; no worker/provider execution. |
| S-016 | Direct IPC/provider transport donors | `CHECKED` swarm-client/OpenCode/Cargo/reqwest; Hy-Memory partial | No-replay IPC, bounded loopback HTTP, private files, missing TLS feature. |
| S-017 | Repository delivery-collapse evidence | `CHECKED` issues #5305/#3014/#327 and retained surfaces | Mechanisms confirmed; no full current census. |
| S-018 | Workspace/manifests/generated inventories sample | `CHECKED` exact sampled paths | Repeated mechanism confirmed; not full semantic audit of all crates/work-units. |
| S-019 | Retained old Architecture/Implementation library copies | `CHECKED` targeted R-064–R-067 sections | Exact clauses inspected; not complete fresh line-by-line audit. |
| S-020 | Current normative inference synchronization pass | `CHECKED` Architecture draft.7 / Implementation draft.20 / Cognition draft.10 / Contract 0.4 | Inference owner/terms/result/no-result/cleanup consistent. No runtime/build/provider/Windows execution. |
| S-021 | Legacy Base hook/spool path on main `5aac094` | `CHECKED` exact `plugin.rs`, `service.rs`, hook intake, hook config, shape test and integration doc | Static code/config audit only. No live installed plugin, daemon delivery, Store replay or Windows durability execution. |
| S-022 | Official Claude Code Hooks reference, crawled 2026-10-24 | `CHECKED` current public schemas/lifecycle | Current docs establish available events/fields/context channels; they do not prove the user's installed Claude version or actual payload behavior. |

### Источники прохода 2026-10-24 — controller implementation boundary

Проверены:

- controller main `e42c464d58db770cc5490f46f391843f9fec8df2`;
- taskless ScriptRun fixture and production paths;
- generic mutation/dedup, Role dispatch, Operation projection/cancel and object scope;
- immutable artifact files and core Operation/artifact schema;
- `swarm-client` generic IPC, failure semantics, config and package boundary;
- current OpenCode bounded HTTP/private connection patterns;
- controller `reqwest` feature selection and upstream reqwest 0.13.5 feature table;
- Hy-Memory configurable provider and retry/extra-field behavior from prior pass.

Установлено:

1. exact Operation replay and direct authenticated IPC already exist;
2. Memory needs no MCP/CLI/copied transport;
3. generic mutation stores raw payload and cannot admit protected inference unchanged;
4. artifacts need inference provenance and exact deletion owner;
5. ScriptRun is not lightweight provider executor;
6. first adapter can be closed loopback Chat Completions;
7. loopback does not prove local destination;
8. current controller build lacks reqwest TLS for direct HTTPS;
9. arbitrary extras/blind retry are anti-donors;
10. Contract 0.4 defines minimal connection/profile/adapter/IPC and complete cleanup boundary; code remains absent.

Проектные контрпримеры, не прогоны:

- same request ID + another digest → conflict before provider I/O;
- protected prompt through generic mutate → raw SQLite duplicate survives cleanup;
- crash after input file before Operation commit → orphan, never executable;
- crash after result file before settle → verify deterministic file then settle;
- queued cancel wins before runner CAS → no provider call, input still released;
- runner CAS wins → local cancel cannot claim non-execution;
- IPC reply lost after write → exact replay, not new request ID;
- loopback forwards to cloud but says local → config defect;
- tool-call/no visible content → unsupported output, not no-change;
- length finish → partial, not complete;
- current build uses direct HTTPS adapter → unsupported until TLS feature;
- release reply lost → exact release replay;
- one copy removed and another mismatches → cleanup_incomplete, never released;
- unknown Operation erased → abandon fence before cleanup, external effect remains unknown;
- inference client attempts unrelated mutation → forbidden before generic writer path.

### Источники прохода 2026-10-24 — Base host/capture boundary

Проверены:

- `crates/eliot-engine/src/service.rs::HookIpcForwarder`;
- `crates/eliot-engine/tests/windows_service.rs::h1_hook_forwarder_spools_without_canonical_write`;
- `crates/eliot-engine/src/plugin.rs::EliotHookService`, `spool`, `stdout_for_decision` and sanitization/identity helpers;
- `bins/eliot-agent-bridge/src/hook_intake.rs`;
- actual `integrations/claude/eliot/hooks/hooks.json`;
- retained `docs/integrations/claude/CLAUDE_CODE_PLUGIN.md`;
- current official Claude Code Hooks reference for lifecycle, context injection and event fields.

Установлено:

1. legacy `forwarded` is a return shape, not delivery;
2. no production caller of `HookIpcForwarder` and no consumer/replayer of its spool were found;
3. shape test proves only JSON flags and reference prefix;
4. hook spool writes directly to final path without atomic durable publish;
5. event ID uses a short content-hash prefix, conflating occurrence and equality;
6. accepted payload is silently sanitized/truncated before durable memory, including generic URL/endpoint removal;
7. SessionStart returns service-status prose, not restored Memory context;
8. actual hook config, internal integration document and current official event surface disagree;
9. current official Stop/SubagentStop expose final messages directly; PostCompact exposes summary; UserPromptSubmit and SessionStart support context injection;
10. README now selects one exact Base relay/spool/packet design; detailed books remain to be synchronized.

## 4. Решения, которые не открываются без нового основания

- не переносить V1/V2 runtime/compatibility facades;
- не создавать второй task manager/swarm/research engine/semantic DB;
- не создавать provider/credential/router stack внутри Memory;
- не использовать Task/Attempt/ScriptRun для one-shot inference;
- не сохранять raw inference payload через generic mutation JSON;
- не копировать IPC и не запускать CLI per call;
- не создавать permanent Dreamer/model loop;
- не возвращать Governor route/capability/fingerprint/portfolio platform;
- не создавать отдельный inference scheduler/table;
- не добавлять generic artifact deletion;
- не использовать unspecified OpenAI-compatible extras;
- не считать loopback local destination;
- не дублировать connection/profile config в Memory для admission;
- не создавать отдельные IPC stacks для text/embed/read/release;
- не считать aggregate cleanup sufficient без per-copy facts;
- не удалять unresolved Operation content до abandon fence;
- не превращать operational failure/no-result в cognitive no-change;
- не блокировать Base из-за optional capabilities;
- не использовать similarity как authority/truth/applicability proof;
- не считать fixture/receipt/stored ID/shape object функцией;
- не создавать SkillRegistry/OutcomeStore/TruthRegistry/PacketStore;
- не требовать promotion/experiment/approval для каждого lesson;
- не строить universal plugin/query/workflow framework до consumer;
- не менять production behavior ради placeholder test;
- не расширять coverage claims;
- не создавать task catalogue/gate/branch manager/report DB/scheduler вместо GitHub owner path;
- не считать issue/history/T-file/receipt текущим V3 authority;
- не начинать expensive setup до cheap preflight;
- не открывать overlap без disposition;
- не считать prose/LOC/commits/agents/issues/PRs продуктовым прогрессом;
- не создавать crate/process per concept;
- не переносить per-helper manifests;
- не считать generated inventory permanent authority;
- не вводить old identity/proof work objects;
- не строить contours/test daemon/generation promotion до measured boundary;
- не исправлять церемонию новой церемонией;
- не создавать errata/compatibility doc для текущего V3: исправлять owner documents;
- не считать content digest occurrence identity;
- не возвращать `forwarded` без Store ownership/readback;
- не объявлять `staged` до atomic durable spool publication;
- не писать spool прямо в final path без sync/rename/dir sync;
- не сохранять silently sanitized projection вместо accepted source bytes;
- не считать service-status phrase контекстом;
- не переносить V2 PreToolUse/Stop/PreCompact governance gates в Base по умолчанию.

## 5. Очередь

| Priority | Работа | Закрывает |
|---|---|---|
| P1 | Синхронизировать README Base host/capture/spool/packet contract с Architecture/Implementation/Cognition; не создавать новый contract file | R-004, R-012, R-013, R-071–R-076 |
| P1 | Memory Base Slices 1–2: one real Claude relay, exact CaptureCommand, Store readback, atomic pending spool, daemon replay, exact open, actual context packet and restart path | R-001–R-013, R-019–R-026, R-033, R-036–R-040, R-071–R-075 |
| P1 | Controller first slice: role/allowlist, connection/profile parser, staging, dedup, runner, loopback text, pending-result recovery, closed receipt, per-copy release with three dispositions — no Task/Attempt/ScriptRun/new table | R-027, R-048, R-050–R-055, R-057, R-068, R-070 |
| P1 | One integrator/product edge/cheap preflight/terminal overlap disposition per slice | R-058–R-061, R-067 |
| P1 | One Rust package/internal modules; second crate/process only after measured boundary | R-033, R-062, R-065 |
| P1 | One Memory controller adapter on pinned `swarm-client`; no separate transports | R-056, R-069 |
| P1 | README goal→minimal-mechanism admission filter | R-064, R-066, R-067 |
| P1 | After Base connect learning with exact request/result/no-result/cleanup lifecycle | R-010, R-021, R-028–R-030, R-041–R-045, R-047–R-057, R-068–R-070 |
| P2 | Qualify actual installed Claude Code version/payloads and update first-host config; public docs alone are not runtime proof | R-012, R-013, R-074, S-022 |
| P2 | Embeddings through same Operation/per-copy release lifecycle, then vector mapping/query | R-015, R-034, R-048, R-050–R-057, R-069–R-070 |
| P2 | Direct HTTPS only after explicit TLS qualification | R-050, R-057 |
| P2 | Optional agent-result projection only for real consumer | R-014, R-027, R-046 |
| P2 | Research parser/citation fixes and one profile | R-016, R-031, R-032 |
| P2 | Document/project-view/grounds as independent increments | R-008, R-017, R-018, R-038, R-040 |
| P2 | Retire generated V2 inventories/per-helper manifests during cutover | R-059, R-063 |
| P3 | Obtain unavailable ZIP/report | S-008, S-009 |
| P3 | Deepen donor only for selected unresolved mechanism | S-010 |
| Final | Full tests after connected implementation; minimum relevant build/Clippy during development | R-049 |

## 6. Последние изменения

| Дата / baseline | Изменение |
|---|---|
| 2026-10-23 / `2ee24de2` | First `episode_learning` recipe/result. |
| 2026-10-23 / `2ab45985` | Controller TaskPrompt/result traced; R-027/R-046. |
| 2026-10-24 / `d97b9bfb` | Task lifecycle rejected for one-shot learning. |
| 2026-10-24 / `10f864d7` | Provider stack retained by controller. |
| 2026-10-24 / `d4657682` | Minimal profile/disclosure/result lifecycle; Contract 0.1. |
| 2026-10-24 / `e81c0503` | Implementation 18/Cognition 8 sync with 0.1. |
| 2026-10-24 / `27eda54c` | Contract 0.2 controlled input/caller/runner/release. |
| 2026-10-24 / `0da78d29` | Contract 0.3 direct IPC, connection/profile, destination, adapters. |
| 2026-10-24 / `c1401bb2` | Delivery-collapse constraints R-058–R-061/S-017. |
| 2026-10-24 / `4fcee2f6` | Workspace/manifests/inventory anti-patterns. |
| 2026-10-24 / `561fe900` | Goals→minimal mechanisms; R-064–R-067/S-019. |
| 2026-10-24 / `5f32d764`–`a03114ae` | Architecture 6 / Implementation 19 / Cognition 9 synced with Contract 0.3; R-068/R-069. |
| 2026-10-24 / `4e203676`–`fdf53183` | Contract 0.4 plus Architecture 7 / Implementation 20 / Cognition 10: optional result, three release dispositions, per-copy cleanup and abandon fence; R-070/S-020. |
| 2026-10-24 / `036377ed` | README selected first Claude Base event profile, exact occurrence identity, one CaptureCommand, atomic spool/replay and real packet handoff; R-071–R-076/S-021–S-022 registered. |
