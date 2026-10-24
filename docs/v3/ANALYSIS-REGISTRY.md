# Eliot V3 — реестр анализа

**Статус на 2026-10-24 · нормативная база Architecture draft.5 / Implementation draft.18 / Cognition draft.8 / Inference Contract 0.3; controller `e42c464d`; активный рабочий реестр, не runtime gate.**

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
| R-002 | Локальная process family и idle drain | Implementation §1; V2 I1.5/I14.22; Windows primitives прежних проходов | `DECIDED` | Один supervisor, daemon и SurrealDB child; конечный drain; explicit shutdown не запускает DreamCycle и не разрешает повтор unknown model call. | Реализовать и проверить Windows mutex, Job Object, restart и cutover. |
| R-003 | Точный continuation address | Architecture §3.3; Implementation §3.1; Cognition §2 | `DECIDED` | Project/workspace + реальный task либо actor/session; branch/path/HEAD — состояние. | Проверить два workspaces, branch switch, fork, transfer и late result. |
| R-004 | Context packet identity | Implementation §§5.5,6.2; Cognition §6 | `DECIDED` | Packet хранит фактически отрисованные revisions; offered/handoff/use различены; отсутствие correlation не блокирует память. | Реализовать coherent hydration и host correlation без agent ACK-формы. |
| R-005 | Прямая структурированная поправка | Implementation §§5.1,5.3–5.4 | `DECIDED` | Correction observation + revision/history + saved result в одной caller-owned transaction; replay не применяет правку повторно. | Реализовать один command path и conflict/readback. |
| R-006 | Шесть таблиц и Store operations | Implementation §§4–5 | `PARTIAL` | Общая схема и операции определены; SQL/indexes не выполнены. | Реализовать migrations/query files и проверить планы, uniqueness и объём чтения. |
| R-007 | Revision/history/current state | Architecture §4.3; Implementation §§4.3–4.5,5.3; Cognition §§3,8 | `DECIDED` | Exact version handle; current/history не подменяют друг друга; split не перенаправляет старые handles. | Реализовать atomic publication, historical reads и restart readback. |
| R-008 | Compound grounds и propagation | Architecture §4.5; Implementation §8.3; Cognition §3.2 | `PARTIAL` | Required groups, alternatives и advisory support разделены; targeted reverse traversal выбрана. | Реализовать reducer/traversal; проверить cycles, erase и concurrent changes. |
| R-009 | Retrieval arms и packet grouping | Implementation §7; Cognition §6 | `PARTIAL` | Exact/lexical/vector/relation arms независимы; grouping не merge IDs или evidence. | Проверить реальные tokens/plans/bytes, OR noise и exception outside top-k. |
| R-010 | Реальный consumer processing method | Implementation §§5.2,10.3; Cognition §§7,9.1 | `DECIDED` | Job freezes exact recipe revision; request builder читает её и вставляет в один inference request. | Реализовать и показать изменившийся следующий request/context после revision. |
| R-011 | Cross-project reuse и disclosure | Architecture §4.4; Implementation §§4.3,5.5,9.2; Cognition §9.3 | `DECIDED` | Origin отдельно от reuse scope; shared method не расширяет disclosure sources или instance facts. | Реализовать local/selected/owner queries и deterministic disclosure reduction. |
| R-012 | Native hook → observation | Implementation §6.1; Claude hook docs; claude-mem selected path | `PARTIAL` | IDs, representations и final-message distinction определены; donor теряет `last_assistant_message` в выбранном path. | Проверить installed payload/version и один реальный relay. |
| R-013 | Native context delivery | Implementation §6.2; Claude hook contracts | `PARTIAL` | Next-model boundaries и bounded JSON output выбраны; write != acceptance/use. | Проверить installed serialization, overflow, resume/child и duplicate boundary. |
| R-014 | Controller Task/agent result route | Controller `e42c464d`: TaskSpec/claim/dispatch/Claude result | `PARTIAL` | Годится для agent work, но требует Task/requirement/Attempt/binding и не выбран для one-shot Memory inference. R-027/R-046 остаются его gaps. | Сохранить optional richer route; не использовать как baseline `episode_learning`. |
| R-015 | Batch embeddings contract | Implementation §§9.1,9.4; Inference Contract §7 | `GAP` | `EmbeddingClient` и `inference.embed` определены; метода нет в inspected controller catalog. | Реализовать controller route и per-input result; затем Memory handler/query arm. |
| R-016 | Research request→report→source | Research `7c034569` selected callers; Implementation §9.5 | `PARTIAL` | Реальные run/status/report/section/citation operations найдены; R-031/R-032 не исправлены. | Исправить Research owners и квалифицировать один профиль. |
| R-017 | Project structure и Eliot self-view | Implementation §8.1; old structure adapter scope | `PARTIAL` | Scoped versioned views выбраны; structural tool/deployment не квалифицирован. | Проверить два checkouts, late result и affected-view refresh. |
| R-018 | Document→representation→open | Docling/Core selected paths; Implementation §8.2 | `PARTIAL` | Original bytes, retained representation, excerpts и exact open определены; decode/asset path не выполнен. | Реальная conversion/readback с partial pages/images и cost bounds. |
| R-019 | Backup/restore | Implementation §12; Surreal/V2 restore reads прежних проходов | `PARTIAL` | Native logical export + blobs + fresh candidate restore выбраны. | Выполнить Base round-trip и Windows cutover. |
| R-020 | Erasure и reappearance | Architecture §4.7; Implementation §12.1; Cognition §13; R-051 | `PARTIAL` | Withdrawal, exposure, refutation и physical erase разделены. Controller inference input/result являются controlled copies до release. | Реализовать traversal, backups/spool/late-result cleanup и полный inference payload release. |
| R-021 | Recursive improvement | Architecture §7; Cognition §10 | `PARTIAL` | Исправляется конкретный failed edge; нет global intelligence score или mandatory grader. | Выполнить connected request→revision→next context после R-048/R-050/R-051/R-053–R-057. |
| R-022 | Disagreement/anticipation | Architecture §8; Cognition §11 | `CHECKED` | Alternatives + grounds + cheapest discriminating observation; no voting; expiry != outcome. | Реализовать ordinary records after core path. |
| R-023 | Direct control/status/inbox | Implementation §13 | `DECIDED` | Status выводится из actual process/jobs/results/profile facts; no separate readiness or attention store. | Реализовать configure/off/pause/cancel/status/inbox и inference profile visibility. |
| R-024 | Normative-document consistency | Architecture draft.5; Implementation draft.18; Cognition draft.8; Inference Contract 0.3; README | `PARTIAL` | Task lifecycle и policy platform удалены. Contract 0.3 добавил controlled input, direct IPC and versioned first adapters; Implementation/Cognition ещё используют старые names/result-only lifecycle и не фиксируют adapter/connection split. | Синхронизировать Implementation/Cognition/Architecture/README references без добавления новой платформы. |
| R-025 | Что запускает интерпретацию | Implementation §§5.1,10.5 | `DECIDED` | New relevant input, correction or explicit question; accounting/read/release/embedding completion не self-trigger. | Проверить enqueue callers и absence of loops. |
| R-026 | Active/pending job и eligibility | Implementation §§4.6,5.2,10.5 | `DECIDED` | Один active + coalesced pending target; first queued time сохраняется; waiting не retry. | Проверить continuous arrivals, two projects, off/idle/background и shutdown. |
| R-027 | Controller agent result→public artifact handle | Controller result writers/projection on `5b6b5bee/e42c464d` | `GAP` | `agent.result`/assembly сохраняют nested artifact refs, public projection их теряет. | Исправить optional agent-route projection; inference methods получают отдельный закрытый receipt с первого implementation. |
| R-028 | Первый recipe bootstrap | Implementation §10.3; Cognition §7.2 | `DECIDED` | Bundled recipe сохраняется при enable purpose; restart/upgrade не затирает изменённый method. | Реализовать unique purpose address и first enable. |
| R-029 | Outcome→next decision | Implementation §10.4; Cognition §9.2 | `DECIDED` | Один current contribution на method revision/attempt/criterion; context и learning — consumers. | Реализовать reducer и correction/contradiction cases. |
| R-030 | Multi-stream/late events/coverage | Implementation §10.1; Cognition §4 | `DECIDED` | Per-stream bounds and supplied-vs-covered distinction; no global high-water mark. | Проверить late child, partial body, omitted handle и successor. |
| R-031 | Research MCP request decoder | Research `7c034569` MCP/service parser | `GAP` | MCP old shape rejects newer selected method/model request before capable service. | Связать discovery/MCP с current application decoder. |
| R-032 | Research citation depends on active index | Research `7c034569` citation reader | `GAP` | Known retained citation can fail before source bytes if search projection changed. | Read saved representation/range directly under existing access. |
| R-033 | Useful Base/layers/light extensions | Old A2.3/I2.19/I6.4; Architecture §3; Implementation §2 | `DECIDED` | One-package start, acyclic modules, Base and independent vertical increments; no module platform. | При коде контролировать imports, features, startup and Base without extensions. |
| R-034 | Encoder→derived vector→context | Implementation §§5.4,7.3,9.4 | `DECIDED` | Query/document role, effective space and partial batch; semantic revision unchanged. | После R-015 выполнить one connected semantic query. |
| R-035 | Architecture overconstraints | Full normative rereads; old route/privacy pass | `DECIDED` | Unknown attribution/grounds no longer global blockers. Privacy and cost retain narrow deterministic checks at external-send boundary; no Governor platform. | Не превращать missing metadata в permission gate outside actual send. |
| R-036 | Commitment lifecycle | Architecture §8; Implementation §11.3; old A7.5/A11.5 | `DECIDED` | Ordinary memory item; context/inbox readers; ACK/due/expiry do not resolve. | Реализовать explicit create/update/read; notifications later. |
| R-037 | Stable work identity and scoped facts | Architecture §3.3; Implementation §3.1; Cognition §§2–3 | `DECIDED` | Project/workspace/task identity separated from branch/location/version/time. | Реальный attach/capture/query/late-result path. |
| R-038 | Resource/version/representation continuity | Architecture §4.2; Implementation §4.7; Cognition §4 | `DECIDED` | Dirty bytes retained; rename/copy links do not rewrite old IDs; equal bytes != same source. | Проверить partial read after edit/move and conversions. |
| R-039 | Decision frame→lexical query | Implementation §7.3 | `DECIDED` | Focused question + exact cues; native OR candidate arm; no LLM query planner. | Выполнить actual query/tokens/noise/empty input. |
| R-040 | Bounded source reading | Implementation §§5.6,7.2,8.2 | `DECIDED` | Metadata/excerpt first, selected ranges next; row limit != byte/decode limit. | Реальные file/Store readers, UTF-8 range and long JSON/line. |
| R-041 | Automatic work and drain | Implementation §§1.3,10.5; R-055 | `DECIDED` | off/idle/background; finite drain; automatic model work additionally needs profile `allow_automatic`. Controller uses one bounded Operation runner, not another scheduler. | Реализовать one automatic episode path after manual path. |
| R-042 | Curation result consumer | Cognition §§8–10 | `DECIDED` | Output must change normal context/open/method request; unread report not completion. | Проверить same relevant request before/after revision. |
| R-043 | Consolidation/split without ID merge | Cognition §8 | `DECIDED` | Replay, grouping, revision, synthesis and split distinct; sources and old handles survive. | Реализовать ordinary curation publication and historical handles. |
| R-044 | Forgetting changes reader | Cognition §13; Mem0 selected mutation/reader trace | `DECIDED` | Current reader uses current revision links; rare/unused not false. | Проверить correction after restart and scoped negative memory. |
| R-045 | First episode recipe/result | Cognition §7; old I9.4/I9.5/I9.7/I9.10; Hy-Memory extractor path | `DECIDED` | Concrete instruction, zero-or-more changes, typed result, valid no-change and explicit partial/error. | Run after R-048/R-050/R-051/R-053–R-057; then useful/no-change/partial/malformed/conflict cases. |
| R-046 | Claude terminal body durability | Controller Claude stream/result path | `GAP` | Current optional agent route keeps body in boot-local bounded LRU before page capture. | Fix in controller adapter if agent route is used; unrelated to direct inference artifact path. |
| R-047 | One inference without second task manager | Old I9.1/I9.3/T12; controller Task path; V3 docs | `CHECKED` design / `NOT IMPLEMENTED` runtime | One Memory job owns input, coverage, decoding and publication; controller one-shot inference owns provider execution/readback only. | Implement R-048; do not create Task/Attempt or direct provider stack in Memory. |
| R-048 | Controller `inference.text` / `inference.embed` | Controller method catalog/source `e42c464d`; Inference Contract 0.3 | `GAP` | Narrow methods are absent. Existing routes are agent/task/script-oriented. | Implement custom content-staging admission, exact dedup, frozen profile/connection, Operation runner, result artifact and unknown outcome without Task/Attempt. |
| R-049 | Code-first and test timing | User direction; Implementation §14; README | `DECIDED` | Production path first, minimum build/Clippy per coherent increment; no speculative test platform. Full suite after connected product implementation. | During coding record minimum Clippy; later build tests around observable paths. |
| R-050 | Minimal inference connection/profile, privacy and budget | Old I9.4/I9.10/I3.6/I10.11/I10.4; Architecture §2.3; Contract §§3–4,9 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Static connection + versioned adapter profile, actual destination, automatic canonical digest, two-state disclosure, finite limits, requested/observed facts and no implicit fallback. No classifier, registry or approval platform. | Implement config parser/admission and Memory disclosure reducer; qualify actual profiles only when configured. |
| R-051 | Inference input/result copy lifecycle and erasure | Controller artifacts/operations `e42c464d`; Architecture §2.4; Contract §§5,13 | `GAP` | Controller stages exact input before I/O and result after I/O, then releases both after Memory verifies its copy. Result-only release leaves protected prompt/input indefinitely. | Implement `inference.release`, `remove_exact`, cleanup_pending recovery, bounded text-free receipt and erasure integration. |
| R-052 | Taskless ScriptRun as inference donor | Controller taskless fixture and production `store/scripts.rs` on `e42c464d` | `CHECKED` / `NOT SELECTED` | Fixture qualifies Store admission but explicitly does not execute worker. Production path owns script registry, bundles, interpreter/process custody, start gates, automation authority, effects and three artifact classes. | Reuse only Operation/recovery ideas; do not route inference through `script.run`, ScriptEffect or automation cause. |
| R-053 | Narrow inference caller authority | Controller Role/Store-call/object-scope path `e42c464d`; Contract §2 | `DECIDED` design / `NOT IMPLEMENTED` runtime | Existing Manager/Operator are overbroad; Module requires binding; Observer is read-only. Add `inference_client` with exact method allowlist, no MCP discovery and no generic writer fallback. | Implement role serialization/registration, allowlist, self-owned queued cancel and exact-caller reads. |
| R-054 | Closed inference artifact provenance | Controller `ArtifactFiles`, `object_scope` and artifacts schema `e42c464d`; Contract §§5,11,13 | `GAP` | Current artifact decoder accepts Task, Script and NativeResult domains only; supported file kinds omit inference; no verified deletion primitive exists. | Add `inference_input`/`inference_result`, exact Operation provenance, result-only public grant and private `remove_exact`. |
| R-055 | Operation-only runner, recovery and cancellation | Generic mutation/dedup, Operation states, exact caller read and `operation.cancel` on `e42c464d`; Contract §§8,10,12 | `DECIDED` design / `NOT IMPLEMENTED` runtime | Existing replay, states, wake signal and queued cancellation are sufficient. Generic mutate cannot be called unchanged because it stores raw payload. No `inference_runs` table or second scheduler is selected initially. | Implement custom admission plus one bounded runner; queued cancel races CAS, sent/unknown work reconciles without automatic replay. |
| R-056 | Direct Memory→controller IPC dependency | `swarm-client` lib/client/config/Cargo on `e42c464d`; Contract §2.1 | `CHECKED` design / `NOT IMPLEMENTED` Memory adapter | Generic authenticated call already has no task policy or application replay; after-write cancel/disconnect/partial reply becomes unknown. Crate is `publish=false` but can remain exact-revision source dependency; no MCP/CLI/protocol copy is selected. | Pin exact controller revision, load private credential, verify frame bounds and exercise exact replay after reconnect during implementation. |
| R-057 | First provider adapter and transport boundary | Controller OpenCode HTTP donor, Cargo reqwest features, reqwest 0.13.5 features, Hy-Memory provider donor; Contract §9 | `DECIDED` design / `NOT IMPLEMENTED` runtime | First adapters are versioned loopback Chat Completions/Embeddings with closed wire shape, no arbitrary extras/tools/stream/temperature/fallback/retry. Loopback hop does not imply local destination. Current controller reqwest build lacks TLS; direct HTTPS is later explicit adapter. | Implement/Clippy the loopback text adapter first; qualify local/external destination declarations and add HTTPS only with explicit TLS feature and its own qualification. |

## 3. Source coverage

| ID | Источник | Статус | Граница вывода |
|---|---|---|---|
| S-001 | V1 Canonical Master | `CHECKED` для ранее прочитанного полного документа до §40 | Requirements read; не полный code audit V1. |
| S-002 | V2 Architecture/Implementation selected sections | `PARTIAL` | Много разделов перечитано по конкретным вопросам; весь корпус не объявлен свежо проверенным. |
| S-003 | Claude audit revision 4 | `CHECKED` как предоставленный полный текст | Использован как source of ideas, не автоматический норматив. |
| S-004 | ELIOT audit v9 | `CHECKED` как предоставленный текст | Historical findings не перезапускались на каждом SHA. |
| S-005 | Swarm audit 2026-10-06 | `CHECKED` как предоставленный текст | Controller ownership отделён от Memory. |
| S-006 | August architecture audit | `CHECKED` как предоставленный текст | Proof/policy machinery не перенесена автоматически. |
| S-007 | LLM problems report | `CHECKED` как предоставленный текст | Failure classes mapped; incidents not reproduced. |
| S-008 | Release ZIP `audit-2026-10-16-incomplete` | `BLOCKED` | Metadata известно; полный 968-file semantic review не заявлен. |
| S-009 | `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | `BLOCKED` | Полный текст отсутствует. |
| S-010 | Donors D01–D47, Hy-Memory, Mem0, Docling, Research, controller | `PARTIAL` | Findings относятся к exact paths/revisions; ни один продукт не квалифицирован целиком. |
| S-011 | Independent subagent review | `OPEN` | В этом проходе независимого subagent review не было. |
| S-012 | Consolidated failure audit 2026-08-05 | `PARTIAL` | Проверен named curation preview path; historical counts/runtime not reproduced. |
| S-013 | Controller inference boundary | `CHECKED` для Task/claim/dispatch, method catalog, config/Route and artifact surface through `e42c464d` | Установлена цена Task lifecycle, отсутствие narrow inference methods и отсутствие ready release. Provider/live routes не запускались. |
| S-014 | Old inference privacy/routing corpus | `CHECKED` для I9.4, I9.10, I3.6, I10.11, I10.4 and old `RuntimeRoute` selected source | Сохранены finite limits, locality, requested/observed route and no silent fallback; rejected broader Governor/portfolio/fingerprint machinery. |
| S-015 | Controller taskless execution and Store primitives | `CHECKED` для taskless fixture, production ScriptRun, generic mutate/dedup, Role dispatch, operation/object scope, ArtifactFiles, core schema and cancel on `e42c464d` | Установлены reusable primitives и anti-donor boundaries. Worker/provider execution не запускались. |
| S-016 | Direct IPC and provider transport donors | `CHECKED` для `swarm-client`, OpenCode HTTP/config, controller Cargo and reqwest 0.13.5 feature table; Hy-Memory provider path already partial | Установлены no-replay IPC, loopback HTTP hardening, private-file pattern and missing current TLS feature. Provider/model quality/live compatibility не проверены. |

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
2. Memory needs no MCP surface, CLI process or copied transport;
3. generic mutation stores raw payload and cannot admit protected inference unchanged;
4. current artifacts need explicit inference provenance and deletion owner;
5. ScriptRun is not a lightweight provider executor;
6. first working provider adapter can be a closed loopback Chat-Completions path over the existing HTTP dependency;
7. loopback transport does not prove local data destination;
8. current controller build does not include reqwest TLS features, so direct external HTTPS is not yet present;
9. arbitrary provider extras and blind retry are rejected anti-donors;
10. Contract 0.3 now defines the minimal connection/profile/adapter/IPC boundary; code remains absent.

Проектные контрпримеры, не прогоны:

- conflicting request ID with another prompt digest → conflict before provider I/O;
- protected prompt through generic mutate → raw SQLite duplicate survives release;
- crash after input file before Operation commit → unregistered orphan, never executable;
- crash after result file before settle → verify deterministic file and finish settlement;
- queued cancel wins before runner CAS → no provider call;
- runner CAS wins → local cancel cannot claim non-execution;
- IPC reply lost after write → reconnect and exact replay, not new request ID;
- loopback gateway forwards to cloud but profile says local → configuration defect; disclosure must not be inferred from host address;
- provider returns tool call/no visible content → unsupported output, not no-change;
- finish reason indicates length limit → partial, not complete;
- current reqwest build attempts HTTPS direct adapter → unsupported until explicit TLS feature;
- Memory verifies result but release reply is lost → exact release replay;
- inference client attempts unrelated mutation → forbidden before generic writer path.

## 4. Решения, которые не открываются без нового основания

- не переносить V1/V2 runtime и compatibility facades;
- не создавать второй task manager, swarm, research engine или semantic DB;
- не создавать provider/credential/router stack внутри Memory при выбранном controller owner;
- не использовать controller Task/Attempt или ScriptRun для обычного one-shot memory inference;
- не сохранять raw inference payload через generic mutation JSON;
- не копировать controller IPC protocol в Memory и не запускать CLI на каждый call;
- не создавать permanent Dreamer process or model loop;
- не возвращать Governor route/capability/fingerprint/portfolio platform;
- не создавать отдельный inference scheduler/table до реальной необходимости;
- не добавлять public generic artifact deletion;
- не использовать unversioned “OpenAI-compatible” arbitrary extras as a production contract;
- не считать loopback доказательством local-only destination;
- не блокировать capture/read из-за inference, vectors, graph, map или telemetry;
- не использовать similarity как authority, truth или applicability proof;
- не считать fixture, receipt, stored ID или shape-valid object работающей функцией;
- не создавать SkillRegistry, OutcomeStore, TruthRegistry или PacketStore;
- не требовать promotion, experiment или approval для каждой provisional lesson;
- не строить universal plugin/query/workflow framework до второго реального consumer;
- не менять production behavior ради ложного тестового ожидания;
- не объявлять source, donor или runtime coverage шире фактически прочитанного/наблюдаемого.

## 5. Очередь

| Priority | Работа | Закрывает |
|---|---|---|
| P1 | Синхронизировать Architecture/Implementation/Cognition/README с Contract 0.3: direct IPC, connection/profile split, actual destination, controlled input/result, `inference.release`, closed adapter IDs | R-024, R-050–R-057 |
| P1 | В controller реализовать first production slice: caller role/allowlist, profile/connection parser, custom input staging, exact dedup, one Operation runner, loopback text adapter, pending-result recovery, public receipt/grant and release — без Task/Attempt/ScriptRun/new table | R-027, R-048, R-050–R-057 |
| P1 | Параллельно продолжать Memory Base Slices 1–2 независимо от model routes | R-001–R-013, R-019–R-026, R-033, R-036–R-040 |
| P1 | После Base подключить learning через pinned direct IPC client and exact result lifecycle | R-010, R-021, R-028–R-030, R-041–R-045, R-047–R-057 |
| P2 | Добавить loopback embeddings through the same lifecycle, затем vector handler/query | R-015, R-034, R-048, R-050–R-057 |
| P2 | Добавить direct HTTPS adapter только после explicit TLS feature/qualification | R-050, R-057 |
| P2 | Исправить optional agent-result projection/source retention только для real agent consumer | R-014, R-027, R-046 |
| P2 | Исправить Research parser/citation reader и подключить один профиль | R-016, R-031, R-032 |
| P2 | Реализовать Docling/project-view/grounds paths как независимые increments | R-008, R-017, R-018, R-038, R-040 |
| P3 | Получить недоступные ZIP/report | S-008, S-009 |
| P3 | Углублять донора только под незакрытый выбранный механизм | S-010 |
| Final | После connected implementation построить и запустить full test suite; во время разработки only minimum relevant build/Clippy | R-049 |

## 6. Последние изменения

| Дата / baseline | Изменение |
|---|---|
| 2026-10-23 / `2ee24de2` | Первый конкретный `episode_learning` recipe и typed result. |
| 2026-10-23 / `2ab45985` | Прослежен controller TaskPrompt/result path; подтверждены R-027/R-046. |
| 2026-10-24 / `d97b9bfb` | Controller Task lifecycle признан избыточным для one-shot learning. |
| 2026-10-24 / `10f864d7` | Provider stack оставлен у controller; переписаны normative docs. |
| 2026-10-24 / `d4657682` | Добавлены minimal inference profile, disclosure и controlled-result lifecycle; создан Contract 0.1. |
| 2026-10-24 / `e81c0503` | Implementation draft.18 и Cognition draft.8 синхронизированы с Contract 0.1. |
| 2026-10-24 / `27eda54c` | Contract 0.2: controlled input, narrow caller, Operation-only runner, input+result release and ScriptRun anti-donor. |
| 2026-10-24 / `0da78d29` | Contract 0.3: direct swarm-client IPC, connection/profile split, actual destination and versioned loopback text/embedding adapters; direct HTTPS separated by explicit TLS dependency. |
