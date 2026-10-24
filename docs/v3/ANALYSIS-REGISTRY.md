# Eliot V3 — реестр анализа

**Статус на 2026-10-24 · нормативная база Architecture draft.5 / Implementation draft.18 / Cognition draft.8 / Inference Contract 0.1; controller `38db378c`; активный рабочий реестр, не runtime gate.**

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
| R-014 | Controller Task/agent result route | Controller `38db378c`: TaskSpec/claim/dispatch/Claude result | `PARTIAL` | Годится для agent work, но требует Task/requirement/Attempt/binding и не выбран для one-shot Memory inference. R-027/R-046 остаются его gaps. | Сохранить optional richer route; не использовать как baseline `episode_learning`. |
| R-015 | Batch embeddings contract | Implementation §§9.1,9.4; Inference Contract §5 | `GAP` | `EmbeddingClient` и `inference.embed` определены; метода нет в inspected controller catalog. | Реализовать controller route и per-input result; затем Memory handler/query arm. |
| R-016 | Research request→report→source | Research `7c034569` selected callers; Implementation §9.5 | `PARTIAL` | Реальные run/status/report/section/citation operations найдены; R-031/R-032 не исправлены. | Исправить Research owners и квалифицировать один профиль. |
| R-017 | Project structure и Eliot self-view | Implementation §8.1; old structure adapter scope | `PARTIAL` | Scoped versioned views выбраны; structural tool/deployment не квалифицирован. | Проверить два checkouts, late result и affected-view refresh. |
| R-018 | Document→representation→open | Docling/Core selected paths; Implementation §8.2 | `PARTIAL` | Original bytes, retained representation, excerpts и exact open определены; decode/asset path не выполнен. | Реальная conversion/readback с partial pages/images и cost bounds. |
| R-019 | Backup/restore | Implementation §12; Surreal/V2 restore reads прежних проходов | `PARTIAL` | Native logical export + blobs + fresh candidate restore выбраны. | Выполнить Base round-trip и Windows cutover. |
| R-020 | Erasure и reappearance | Architecture §4.7; Implementation §12.1; Cognition §13 | `PARTIAL` | Withdrawal, exposure, refutation и physical erase разделены. Controller inference duplicate является controlled copy до release. | Реализовать traversal, backups/spool/late-result cleanup и inference duplicate release. |
| R-021 | Recursive improvement | Architecture §7; Cognition §10 | `PARTIAL` | Исправляется конкретный failed edge; нет global intelligence score или mandatory grader. | Выполнить connected request→revision→next context после R-048/R-050/R-051. |
| R-022 | Disagreement/anticipation | Architecture §8; Cognition §11 | `CHECKED` | Alternatives + grounds + cheapest discriminating observation; no voting; expiry != outcome. | Реализовать ordinary records after core path. |
| R-023 | Direct control/status/inbox | Implementation §13 | `DECIDED` | Status выводится из actual process/jobs/results/profile facts; no separate readiness or attention store. | Реализовать configure/off/pause/cancel/status/inbox и inference profile visibility. |
| R-024 | Normative-document consistency | Architecture draft.5; Implementation draft.18; Cognition draft.8; Inference Contract 0.1; README 24.10 | `CHECKED` | Task lifecycle удалён; Memory job, minimal profile, disclosure reduction, result copy/release and implementation order согласованы. | Поддерживать при следующих source/donor решениях; code всё ещё отсутствует. |
| R-025 | Что запускает интерпретацию | Implementation §§5.1,10.5 | `DECIDED` | New relevant input, correction or explicit question; accounting/read/release/embedding completion не self-trigger. | Проверить enqueue callers и absence of loops. |
| R-026 | Active/pending job и eligibility | Implementation §§4.6,5.2,10.5 | `DECIDED` | Один active + coalesced pending target; first queued time сохраняется; waiting не retry. | Проверить continuous arrivals, two projects, off/idle/background и shutdown. |
| R-027 | Controller agent result→public artifact handle | Controller result writers/projection on `5b6b5bee/38db378c` | `GAP` | `agent.result`/assembly сохраняют nested artifact refs, public projection их теряет. | Исправить optional agent-route projection; new inference methods must expose usable closed result receipt from first implementation. |
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
| R-041 | Automatic work and drain | Implementation §§1.3,10.5 | `DECIDED` | off/idle/background; finite drain; automatic model work additionally needs profile `allow_automatic`. | Реализовать one automatic episode path after manual path. |
| R-042 | Curation result consumer | Cognition §§8–10 | `DECIDED` | Output must change normal context/open/method request; unread report not completion. | Проверить same relevant request before/after revision. |
| R-043 | Consolidation/split without ID merge | Cognition §8 | `DECIDED` | Replay, grouping, revision, synthesis and split distinct; sources and old handles survive. | Реализовать ordinary curation publication and historical handles. |
| R-044 | Forgetting changes reader | Cognition §13; Mem0 selected mutation/reader trace | `DECIDED` | Current reader uses current revision links; rare/unused not false. | Проверить correction after restart and scoped negative memory. |
| R-045 | First episode recipe/result | Cognition §7; old I9.4/I9.5/I9.7/I9.10; Hy-Memory extractor path | `DECIDED` | Concrete instruction, zero-or-more changes, typed result, valid no-change and explicit partial/error. | Run after R-048/R-050/R-051; then useful/no-change/partial/malformed/conflict cases. |
| R-046 | Claude terminal body durability | Controller Claude stream/result path | `GAP` | Current optional agent route keeps body in boot-local bounded LRU before page capture. | Fix in controller adapter if agent route is used; unrelated to direct inference artifact path. |
| R-047 | One inference without second task manager | Old I9.1/I9.3/T12; controller Task path; V3 docs | `CHECKED` design / `NOT IMPLEMENTED` runtime | One Memory job owns input, coverage, decoding and publication; controller one-shot inference owns provider execution/readback only. | Implement R-048; do not create Task/Attempt or direct provider stack in Memory. |
| R-048 | Controller `inference.text` / `inference.embed` | Controller method catalog/source `38db378c`; Inference Contract | `GAP` | Narrow methods are absent. Existing routes are agent/task-oriented. | Implement closed contracts, dedup, frozen profile, one attempt, durable artifacts and unknown outcome without Task/Attempt. |
| R-049 | Code-first and test timing | User direction; Implementation §14; README | `DECIDED` | Production path first, minimum build/Clippy per coherent increment; no speculative test platform. Full suite after connected product implementation. | During coding record minimum Clippy; later build tests around observable paths. |
| R-050 | Minimal inference profile, privacy and budget | Old I9.4/I9.10/I3.6/I10.11/I10.4; Architecture §2.3; Implementation §§9.1–9.3; Inference Contract §§2–7 | `CHECKED` design / `NOT IMPLEMENTED` runtime | Small static profile, two-state disclosure, finite limits, requested/observed facts, no implicit fallback. No route classifier, capability registry or per-call approval platform. | Implement controller profile parser/admission and Memory disclosure reducer; qualify one local and one external profile only when actually configured. |
| R-051 | Inference result copy lifecycle and erasure | Controller public artifact surface; Architecture §2.4; Implementation §§5.4,9.3,12.1; Cognition §§7.5,13; Inference Contract §§7–9 | `GAP` | Memory must verify and copy exact result, then idempotently release controller-owned duplicate. Current inspected controller surface has no reviewed operation-owned inference release because inference route itself is absent. | Implement `inference.result.release`, bounded text-free receipt, cleanup retry/status and erasure integration. |

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
| S-013 | Controller inference boundary | `CHECKED` для Task/claim/dispatch, method catalog, config/Route and artifact surface on `38db378c` | Установлена цена Task lifecycle, отсутствие narrow inference methods и отсутствие готового inference-specific release. Provider/live routes не запускались. |
| S-014 | Old inference privacy/routing corpus | `CHECKED` для I9.4, I9.10, I3.6, I10.11, I10.4 and old `RuntimeRoute` selected source | Сохранены finite limits, locality, requested/observed route and no silent fallback; rejected broader Governor/portfolio/fingerprint machinery. |

### Источники прохода 2026-10-24

Проверены и согласованы:

- V3 Architecture draft.5, Implementation draft.18, Cognition draft.8, Inference Contract 0.1 и README;
- старые I9.4, I9.10, I3.6, I10.11, I10.4;
- old `RuntimeRoute` selected implementation;
- controller `38db378c` configuration, agent `Route`, method catalog and artifact read surface;
- прежние exact Task/Attempt/Claude result findings.

Установлено:

1. input/output/deadline, privacy locality, requested/observed route and no silent fallback are real requirements;
2. old role-cardinality bundle, Governor admission, capability evidence, route classifier and portfolio planner are not required for one-shot Memory inference;
3. controller agent `Route` is workspace/session/module-oriented and cannot be reused as untyped inference profile;
4. minimal profile and two-state disclosure are sufficient for first route;
5. result durability creates a controlled duplicate that needs explicit release and erasure accounting;
6. Architecture, Implementation, Cognition, README and the shared contract now agree;
7. controller methods, Memory adapter and runtime qualification remain absent.

Проектные контрпримеры, не прогоны:

- protected source + external-only profile → explicit disclosure gap, no silent omission;
- automatic job + profile with `allow_automatic=false` → waiting, not failure or implicit enable;
- provider/model profile reconfigured after admission → running Operation keeps frozen profile identity;
- usage absent → unknown, not zero;
- admission reply lost → exact replay recovers same Operation;
- provider timeout after possible send → unknown, no new request ID;
- controller restart after durable result → same artifact remains readable;
- Memory copy verified, release reply lost → exact idempotent release replay;
- Memory erased while controller copy remains → erasure incomplete;
- malformed/truncated body → not no-change;
- Store conflict after result → publication replay, not inference replay.

## 4. Решения, которые не открываются без нового основания

- не переносить V1/V2 runtime и compatibility facades;
- не создавать второй task manager, swarm, research engine или semantic DB;
- не создавать provider/credential/router stack внутри Memory при выбранном controller owner;
- не использовать controller Task/Attempt для обычного one-shot memory inference;
- не создавать permanent Dreamer process or model loop;
- не возвращать Governor route/capability/fingerprint/portfolio platform ради первого inference route;
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
| P1 | В controller реализовать `InferenceProfile`, `inference.text`, `inference.embed`, exact dedup, frozen profile, durable closed result receipt, unknown outcome и `inference.result.release` без Task/Attempt | R-015, R-027, R-048, R-050, R-051 |
| P1 | Затем реализовывать Base Slices 1–2: lifecycle, capture, revisions, exact/lexical context/open, maintenance | R-001–R-013, R-019–R-026, R-033, R-036–R-040 |
| P1 | После Base реализовать connected learning: recipe→disclosure→retained request/result→digest verification→decode→revision→next context→controller release | R-010, R-021, R-028–R-030, R-041–R-045, R-047–R-051 |
| P2 | Исправить optional controller agent-result projection/source retention только для реального agent-route consumer | R-014, R-027, R-046 |
| P2 | Реализовать vector handler/query после `inference.embed` | R-015, R-034 |
| P2 | Исправить Research parser/citation reader и подключить один профиль | R-016, R-031, R-032 |
| P2 | Реализовать Docling/project-view/grounds paths как независимые increments | R-008, R-017, R-018, R-038, R-040 |
| P3 | Получить недоступные ZIP/report | S-008, S-009 |
| P3 | Углублять донора только под незакрытый выбранный механизм | S-010 |
| Final | После connected implementation построить и запустить full test suite; во время разработки только minimum relevant build/Clippy | R-049 |

## 6. Последние изменения

| Дата / baseline | Изменение |
|---|---|
| 2026-10-23 / `2ee24de2` | Первый конкретный `episode_learning` recipe и typed result. |
| 2026-10-23 / `2ab45985` | Прослежен controller TaskPrompt/result path; подтверждены R-027/R-046. |
| 2026-10-24 / `d97b9bfb` | Установлено, что controller Task lifecycle избыточен для one-shot learning; временно выбран direct client. |
| 2026-10-24 / `10f864d7` | Исправлена вторая крайность: provider stack не переносится в Memory. Выбран narrow controller inference owner; переписаны normative docs. |
| 2026-10-24 / `d4657682` | Добавлены minimal inference profile, disclosure и controlled-result lifecycle; создан shared Inference Contract. |
| 2026-10-24 / current sync | Implementation draft.18 и Cognition draft.8 согласованы с Architecture draft.5 и Inference Contract; R-024 возвращён в `CHECKED`, R-050/R-051 включены во все lifecycle/erasure paths. |
