# Eliot V3 — реестр анализа

**Статус на 2026-10-22 · проверенная база `42b205a6` · активный рабочий реестр, не runtime gate.**

Этот файл отвечает только на четыре вопроса:

1. что именно проверено;
2. на каком основании;
3. какое решение принято или какой разрыв найден;
4. что проверять следующим.

[Architecture](ARCHITECTURE.md), [Implementation](IMPLEMENTATION.md) и [Cognition](COGNITION.md) — нормативный проект. [AUDIT.md](AUDIT.md) — доказательная база и итоговый разбор. [AUDIT-MAP.md](AUDIT-MAP.md) — стабильная матрица исходных требований, исторических аудитов и доноров. **Этот файл — единственный активный реестр дальнейшего анализа.**

## 1. Статусы и правила

| Статус | Значение |
|---|---|
| `CHECKED` | Указанный source/design scope прочитан и вывод согласован с ним. Не означает работающий runtime. |
| `DECIDED` | Для V3 выбрано конкретное решение; реализация ещё не проверена. |
| `PARTIAL` | Прочитан связанный путь или часть донора, но остаётся существенный непроверенный edge. |
| `GAP` | В текущих нормативных документах отсутствует необходимая связь или есть противоречие. |
| `OPEN` | Решение описано, но требуется source/API/schema/implementation проверка. |
| `BLOCKED` | Нужный источник недоступен. |
| `NOT SELECTED` | Механизм не нужен выбранной конструкции; это не заявление о полном аудите его исходников. |

Правила ведения:

- строка называет точный объект проверки, а не тему вообще;
- search hit, README или наличие типа не дают статус `CHECKED` для runtime-пути;
- исправление документа переводит `GAP` в `DECIDED`, а не в `IMPLEMENTED`;
- `IMPLEMENTED` появится только после реального кода и наблюдаемого producer→operation→result→consumer;
- новые проценты готовности не вычисляются;
- подробные старые координаты остаются в Git/AUDIT, а не копируются сюда;
- один проход обновляет существующую строку либо добавляет новую материальную строку, а не новый отчёт.

## 2. Перекрёстная проверка baseline 1.0-draft

| ID | Объект | Проверенный scope | Статус | Вывод / разрыв | Следующее действие |
|---|---|---|---|---|---|
| R-001 | Граница продукта и владельцы | Architecture §§1–3; Implementation §§1–3; Cognition §14 | `CHECKED` | Host/controller владеет задачами и эффектами; Eliot — памятью и интерпретацией; второго task owner нет. | Не менять без нового реального consumer/failure. |
| R-002 | Локальная process family | Implementation §1.3; Microsoft Mutex Objects, Job Objects, Process Creation Flags, прочитано 22.10 | `DECIDED` | Lifetime mutex удерживает supervisor, не relay; children создаются suspended, включаются в Job Object и затем запускаются; job handle не наследуется. Потеря supervisor завершает его children, новый demand start открывает прежние данные. | Реальная Windows-проверка parent job restrictions, readiness/progress, shutdown и spool durability остаётся открытой. |
| R-003 | Точный адрес continuation | Implementation §§4.3,5.5,7.2; native UNIQUE, 22.10 | `DECIDED` | Прежний exact index не запрещал два current item. Выбран один optional serialized full address с UNIQUE; key включает project/kind и действительную native namespace. Более точная поздняя identity не переименовывает общую session continuation. | Реализовать key/unique-create/read; проверить actual native ID scope, concurrent first attach и отсутствие подстановки чужой последней задачи. |
| R-004 | Identity context packet и атрибуция метода | Implementation §§4.4,5.5–5.6,6.3,10.5 | `DECIDED` | Packet хранит фактически отрисованные exact revisions, не новые heads, прочитанные позже. Исторический packet открывается как сохранённый текст; tracking остаётся необязательным для ответа и не новым опытом. | Реализовать version-coherent hydration/link reads и actual host correlation; не приписывать use из наличия packet ID. |
| R-005 | Прямая структурированная поправка | Implementation §§4.2,5.1,5.3–5.4,10.2 на `e6213e2f` и правка draft.2 | `DECIDED` | Ранее observation commit и edit допускали разрыв. Теперь correction, revision/history и её result handles записываются в одной caller-owned transaction; replay возвращает прежний результат до новой CAS-проверки. Stale edit сохраняется как неприменённая поправка, не теряется. | Реализовать один command entrypoint без fake job; проверить реальный commit/readback и conflict behavior. |
| R-006 | Шесть таблиц и Store operations | Implementation §§4–5; SurrealDB indexes/FTS/filtered KNN, 22.10 | `PARTIAL` | Уточнены optional unique address, typed reuse scope и candidate query до limit. Это не исполненные migrations: фактические nullable/array indexes, plans, concurrency и ordering ещё требуют реализации. | Создать конкретные migration/query files при начале кода; проверить schema + EXPLAIN выбранной server/SDK пары, не компенсировать неизвестный план новым store. |
| R-007 | Revision/history/current-state | Implementation §§4.4,5.3–5.6; Cognition §3 | `DECIDED` | Exact version: matching current либо history по полному item/revision в согласованном read. Current-only lookup не ищет последний historical row. Текст и grounds берутся одной editorial revision; обновление между search и hydration не подменяет handle. | Реализовать read/write queries и короткую consistency boundary без транзакции через model/host call; проверить missing/deleted/revised item. |
| R-008 | Compound grounds | Architecture §4.5; Implementation §4.5; Cognition §3.3 | `CHECKED` | Одна non-null group = AND; разные groups = OR; ungrouped evidence supportive. Это не theorem prover. | Определить query/recompute для затронутых items; проверить неизвестную композицию. |
| R-009 | Retrieval arms и packing | Implementation §§5.5–5.6,8.1; SurrealDB scoring/filtered vector docs | `PARTIAL` | Scope/recorded eligibility применяются внутри каждого arm до limit; union и semantic applicability идут до packing. Выбран lexical scope excerpt; native vector prefilter не обещан для любого array predicate. | Проверить actual query plans, current-state alternatives и полезный результат после отбрасывания кандидатов. SQL здесь не запускался. |
| R-010 | Реальный consumer method revision | Implementation §§5.2,9.2,10.3; Cognition §8.2 | `CHECKED` | Job фиксирует method ID/revision; request builder открывает exact body; новая версия влияет на последующие jobs. | Проверить controller adapter и фактический request body в Slice 3. |
| R-011 | Cross-project reuse | Architecture §4.4; Implementation §§3,4.3,5.5–5.6,10.4 | `DECIDED` | `reuse_scope={mode,projects}` использует stable project IDs. Выбираются local items либо eligible shared methods, не все чужие observations/views. Shared method не расширяет автоматически scope его источников при open. | Реализовать local/owner/selected запросы и scoped expansion, проверить отдельные query/route predicates без нового permission registry. |
| R-012 | Host capture | Implementation §6; audit donor/source findings | `PARTIAL` | Используются actual host results, child/parent streams и injected-text exclusion. Installed host event/version не проверены. | Квалифицировать конкретную Claude Code версию и event payloads перед Slice 2. |
| R-013 | Delivery semantics | Implementation §6.3; Cognition §§6.5,8.3 | `DECIDED` | Prepared, handoff, use и outcome различены; packet ID связывает exact delivered revisions; отсутствие correlation оставляет adherence unknown. | Квалифицировать adapter handoff feedback и implement best-effort tracking. |
| R-014 | Controller text execution и чтение результата | Controller `c3e331a3`: results registration, Store assembly, ArtifactFiles::plan/assemble; Implementation §9.1 | `PARTIAL` | Уже существуют page artifact/ACK replay и сборка непрерывного полного retained body. EOF/settled одной page не весь ответ; coverage retained prefix не отсутствие truncation. V3 использует существующие artifact operations, не второй assembler/journal. | Остались actual public artifact.read caller/object rights, выбранная route/request-result pair, lookup потерянного request ID и native-body retention после restart. A2 — target, не готовая recovery-гарантия. |
| R-015 | Batch embeddings | Implementation §9.3 | `OPEN` | Нужен controller API `profile + [(id, revision, text)] → vector/error`; текущий public route не подтверждён. | Реализовать/квалифицировать controller boundary; не агент и не отдельный scheduler Eliot. |
| R-016 | Research adapter | Architecture §8; Implementation §§9.4,11.3 | `OPEN` | Контракт результата определён; существующий callable Memory↔Research endpoint не подтверждён. | Проверить текущий Eliot Research surface и реализовать один adapter. |
| R-017 | Project structure | Implementation §8.3 | `PARTIAL` | `codebase-memory-mcp` выбран как внешний structural tool; selected handlers изучены, deployment/language coverage нет. | Квалифицировать один реальный repo flow и fallback scope. |
| R-018 | Documents/PDF/media | Implementation §§4.7,8.4 | `PARTIAL` | Source locators выбраны; Docling — внешний converter candidate. Реальный adapter и round-trip locator не проверены. | Проверить representative PDF/document conversion и exact `open` locator. |
| R-019 | Backup/restore | Architecture §9; Implementation §12 | `DECIDED` | Owner-selected restore не блокируется утратой auxiliary history; known deletions применяются; old effects не replay. | Проверить SurrealDB export/import и Windows file cutover in Slice 6. |
| R-020 | Erasure/forgetting | Architecture §§4.6,9; Implementation §12.1; Cognition §13 | `DECIDED` | Exposure, influence, supersession и erasure разделены; external copies — явная граница. | Определить concrete deletion traversal/current restrictions and backup handling. |
| R-021 | Recursive improvement/self-diagnosis | Architecture §7; Implementation §§10.6–10.7; Cognition §9 | `CHECKED` | Existing methods/jobs/outcomes; baseline/no-change; diagnosis corrects first supported failed step. | Реализация после connected method/outcome path; не отдельный runtime. |
| R-022 | Disagreement/anticipation | Architecture §8; Implementation §11; Cognition §§10–11 | `CHECKED` | Alternatives/grounds/discriminating observation; no voting; expiry does not fabricate outcome. | Реализовать ordinary memory representations after core claims/methods. |
| R-023 | Direct control/status | Architecture §9; Implementation §13 | `DECIDED` | Owner can inspect/pause/cancel/correct/erase/backup/restore through actual state; notification optional. | Define CLI/MCP requests after Slice 1 Store/lifecycle. |
| R-024 | Normative-document consistency | Architecture/Cognition 1.0; Implementation 1.0-draft.3; registry source scopes | `PARTIAL` | Уточнены uniqueness адреса, scope-before-top-k, revision-coherent open и различие page/body/model result. Владельцы/таблицы не изменены. Остальные runtime, backup и host/controller границы не объявляются закрытыми. | Продолжать по конкретным оставшимся reader/caller paths; текстовое решение не переводить в IMPLEMENTED. |
| R-025 | Какие сохранения запускают интерпретацию | Implementation §§4.2,5.1,6.3,9.3 | `DECIDED` | Prepared/handoff, read/status, claim renewal и готовый embedding не являются новым опытом. Kind/producer выбирает обычную обработку без LLM-классификатора; self-diagnosis может читать эти сведения при конкретной проблеме. | Реализовать существующие producer→enqueue callers и отсутствие циклов на обычном read. |
| R-026 | Один active и pending job, повтор и stale result | Implementation §§4.6,5.2,5.4; native UNIQUE semantics | `DECIDED` | Project входит в target. Вычисляемый optional tuple + один UNIQUE индекс обеспечивает два слота без lock table. Reclaim сохраняет job/request identity; stale semantic result не оставляет вечный active барьер, saved output переходит в нужную reconciliation. | SQL shape не запускался; проверить claim/capture/apply interleaving и actual controller readback при реализации. |

## 3. Источники и внешняя доказательная база

Полная матрица требований, T01–T37 и D01–D47 находится в [AUDIT-MAP](AUDIT-MAP.md). Здесь перечислены только активные ограничения источников.

| ID | Источник | Статус | Что это меняет |
|---|---|---|---|
| S-001 | V1 Canonical Master | `CHECKED` для полного текста до §40 | Цели отделены от тяжёлой governance doctrine; не означает полный V1 code audit. |
| S-002 | Understanding Layer v1.4 / выбранные V2 нормы | `PARTIAL` | Достаточно для выбранной конструкции; все нормы/2.6M строк не перечитаны. |
| S-003 | Claude revision 4 | `CHECKED` как полный предоставленный текст | 63 anchors и 8 boundaries reconciled; LOC/скорость не новые измерения. |
| S-004 | ELIOT audit v9 | `CHECKED` как полный предоставленный текст | T01–T37 reconciled; historical code findings not rerun. |
| S-005 | Swarm audit 2026-10-06 | `CHECKED` как полный предоставленный текст | Controller/process lessons separated from Memory OS ownership. |
| S-006 | August architecture audit | `CHECKED` как полный предоставленный текст | Findings used; praise of proof architecture not adopted automatically. |
| S-007 | LLM problems report | `CHECKED` as provided text | Failure classes mapped; incidents not reproduced. |
| S-008 | Release ZIP `audit-2026-10-16-incomplete` | `BLOCKED` | Metadata/assets known; contents/968 entries not semantically reviewed. |
| S-009 | `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | `BLOCKED` | Only references available; no substitute report accepted. |
| S-010 | External donors D01–D47 | `PARTIAL` | 17 source-code, 5 docs/paper, 25 unreconciled positions; adoption and review level remain separate. |
| S-011 | Independent subagent review | `OPEN` | No available GPT Luna/subagent execution was used; current review is single-agent. |

### Источники текущего прохода

База Memory OS: [Implementation на 42b205a6](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/42b205a6c59d3ec17c8afdfec2589da7458ad004/docs/v3/IMPLEMENTATION.md) и этот реестр, прочитаны полностью. Предмет правки — §§3,4.3–4.4,5.5–5.6,9.1. Это найденные недоопределённости моего проекта, не воспроизведённые дефекты V3.

Официальные документы SurrealDB, прочитанные 22.10.2026: [DEFINE INDEX](https://surrealdb.com/docs/reference/query-language/statements/define/indexes) — UNIQUE, отсутствие ключа, composite/array indexing; [scoring](https://surrealdb.com/docs/learn/data-models/full-text-search/scoring-and-ranking) — lexical query и score; [similarity search](https://surrealdb.com/docs/learn/data-models/vector-search/similarity-search) и [EXPLAIN](https://surrealdb.com/docs/reference/query-language/clauses/explain) — реальные условия native prefilter. Эти страницы подтверждают primitives, не выполнение конкретного query или его скорость. Прежние Windows/transaction readings сохранены в [реестре до правки](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/42b205a6c59d3ec17c8afdfec2589da7458ad004/docs/v3/ANALYSIS-REGISTRY.md); здесь заново не квалифицировались.

Controller прочитан на **`c3e331a37ef58b3b98f7859bfb9e40935501e106`**, не на прежнем `912df90f`:

| Источник / область | Что установлено | Чего это не устанавливает |
|---|---|---|
| [Module API](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/c3e331a37ef58b3b98f7859bfb9e40935501e106/docs/agent-operations/module-api.md), 1–225; [audit register](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/c3e331a37ef58b3b98f7859bfb9e40935501e106/docs/agent-operations/audit-register.md), 1–165 | Target API различает native effect, outcome envelope и body retention; текущие A2 gaps названы явно. | Документ не доказывает, что restart/spool уже реализованы. Antigravity cache finding в этом проходе унаследован, не перепроверен. |
| [Store results](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/c3e331a37ef58b3b98f7859bfb9e40935501e106/crates/swarm-kernel-host/src/store/results.rs#L1320-L1470) | Регистрация проверяет прежний settled page, записывает artifact/result/observation и ACK после commit. `result_page_persisted` относится к page. | Не полный audit prepare/authorization и не запуск чтения bytes. |
| [Store assembly](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/c3e331a37ef58b3b98f7859bfb9e40935501e106/crates/swarm-kernel-host/src/store/assembly.rs), файл целиком | Сохранённая local operation, адресные source pages, artifact registration и result readback; native inference здесь нет. | Public dispatcher/transport и весь credential/successor путь не прослежены до запуска. |
| [ArtifactFiles assembly](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/c3e331a37ef58b3b98f7859bfb9e40935501e106/crates/swarm-kernel-host/src/artifacts/assembly.rs#L350-L650), также 1–300 | `plan` проверяет origin/order/coverage; `assemble` читает bytes и сохраняет файл до DB registration. Coverage retained command prefix сохраняет flags truncation/read error. | Не семантический успех модели и не доказательство полноты исходного native потока. Конец функции/все reader helpers отдельно не проверены. |
| `store/runtime.rs` 1–380,1050–1480; `store/operations.rs` 1–260 | Прочитаны selected dispatch contracts, queue projection и public Operation projection; это навигация к оставшемуся caller. | Не закончена цепочка `agent.result` admission/source selection; отрицательные searches не доказывают отсутствия request-ID lookup. |

Взято существующее сохранение/сборка результата, а не controller proof vocabulary или его отдельная база. Следующий недочитанный вызов указан в R-014. Новых внешних донорских продуктов, полного release archive, installed host, models, БД, Windows, synthetic/product tests и независимых субагентов в этом проходе не было. Реестры controller не менялись: текущая поставка относится только к Memory OS documentation.

## 4. Решения, которые не открываются заново без нового основания

- не переносить V1/V2 runtime и compatibility facades;
- не создавать второй task manager, swarm, research engine or semantic database;
- не создавать proof/approval/policy platform для обычной памяти;
- не блокировать capture/read из-за embeddings, Dreamer, graph, map or telemetry;
- не использовать similarity как authority, truth or condition proof;
- не считать fixture, shape-valid object, receipt or stored ID выполненной функцией;
- не создавать отдельный SkillRegistry/OutcomeStore/TruthRegistry;
- не требовать experiment/promotion before every provisional useful method;
- не превращать auxiliary deletion history в запрет owner restore;
- не строить универсальный plugin/query/workflow framework до второго реального consumer;
- не менять production behavior для удовлетворения ложного тестового ожидания;
- не объявлять audit/source coverage полнее фактически прочитанного.

## 5. Очередь анализа и проектирования

| Priority | Работа | Закрывает |
|---|---|---|
| P1 | При начале реализации перенести выбранные address/scope/version queries в migrations; проверить actual plans и межпроектный отбор до limit | R-003, R-006–R-011, R-026 |
| P1 | Проверить выбранные Windows lifecycle/spool primitives и backup cutover на настоящем запуске, когда начнётся реализация | R-002, R-019, R-023 |
| P1 | Проследить controller public artifact.read и выбранную agent.result origin цепочку; отдельно установить request-ID recovery и adapter-body retention. Затем installed host integration | R-012, R-014 |
| P1 | Проверить packet→method→action/outcome linkage на одном реальном host path | R-004, R-013, R-010 |
| P2 | Реализовать/квалифицировать batch embeddings boundary | R-015 |
| P2 | Реализовать один Research adapter и один document adapter | R-016, R-018 |
| P2 | Квалифицировать one real project-structure path | R-017 |
| P3 | Получить недоступные ZIP/report при появлении источников | S-008, S-009 |
| P3 | Углублять конкретного донора только когда остаётся незакрытый выбранный механизм | S-010 |

## 6. Журнал изменений реестра

| Дата / baseline | Изменение |
|---|---|
| 2026-10-22 / `7408e946` | Создан active registry после согласованного rewrite. Перекрёстная проверка выявила R-003 exact continuation address, R-004 packet identity и R-005 direct correction mutation. |
| 2026-10-22 / `abec7502` | R-003–R-005 закрыты в Implementation 1.0-draft.1: exact continuation key/index, stable packet identity with revision-aware attribution, shared `publish_revision`. R-013 и R-024 обновлены. |
| 2026-10-22 / `e6213e2f` | Проверены replay/correction, capture→enqueue, claim/result и lifetime ownership; draft.2 устраняет dual-commit correction, неявный self-trigger, недоопределённые job slots и dispatch/readback window. R-006/R-024 уточнены до PARTIAL, добавлены R-025/R-026. Только документация; runtime не проверен. |
| 2026-10-22 / `42b205a6` | Draft.3: native unique continuation address, typed local/shared scope до candidate limit, точные revision/link reads и existing controller page/assembly path. Обновлены R-003/R-004/R-006/R-007/R-009/R-011/R-014/R-024, без новых реестров или таблиц. Доступность public read/restart не объявлена доказанной. |
