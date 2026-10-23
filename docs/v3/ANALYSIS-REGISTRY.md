# Eliot V3 — реестр анализа

**Статус на 2026-10-23 · база Memory OS `ff4f03a2`; controller `1c61629b` сопоставлен с `70b99db3` · активный рабочий реестр, не runtime gate.**

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
| `GAP` | В проекте или выбранном пути интеграции отсутствует необходимая связь; строка называет конкретного владельца разрыва. |
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
| R-010 | Реальный consumer method revision | Implementation §§5.2,10.3; Cognition §8.2, baseline `ff4f03a2` и draft.5 | `PARTIAL` | Прежний план фиксировал редакцию, но не задавал начальный текст и выбор по purpose. R-028 определяет эти переходы; request builder по-прежнему обязан использовать exact body. Storage alone не самоулучшение. | Реализовать первый model job из пустой проектной памяти и последующий job после изменения метода; проверить настоящий request body, не только наличие refs. |
| R-011 | Cross-project reuse | Architecture §4.4; Implementation §§3,4.3,5.5–5.6,10.4 | `DECIDED` | `reuse_scope={mode,projects}` использует stable project IDs. Выбираются local items либо eligible shared methods, не все чужие observations/views. Shared method не расширяет автоматически scope его источников при open. | Реализовать local/owner/selected запросы и scoped expansion, проверить отдельные query/route predicates без нового permission registry. |
| R-012 | Host capture | Implementation §6; audit donor/source findings | `PARTIAL` | Используются actual host results, child/parent streams и injected-text exclusion. Installed host event/version не проверены. | Квалифицировать конкретную Claude Code версию и event payloads перед Slice 2. |
| R-013 | Delivery semantics | Implementation §6.3; Cognition §§6.5,8.3 | `DECIDED` | Prepared, handoff, use и outcome различены; packet ID связывает exact delivered revisions; отсутствие correlation оставляет adherence unknown. | Квалифицировать adapter handoff feedback и implement best-effort tracking. |
| R-014 | Controller text execution и чтение результата | Controller `70b99db3`: Store::call/read_artifact, mutate_in_transaction_with_authority, public operation.get, result-origin admission | `PARTIAL` | Установлен exact replay caller/request/method/body: можно получить прежний admission без новой Store operation. Public artifact.read принимает bounded ranges и проверяет Bytes scope. Но выбранный readback теряет artifact handle — R-027. Generic result и prepared-Claude helper требуют source task.dispatch. | Исправить R-027 у controller; подключить одну actual dispatch→page→handle→bytes pair. Native-body retention/restart, successor identity и installed route остаются открытыми; не заменять их новым runtime Memory OS. |
| R-015 | Batch embeddings | Implementation §9.3 | `OPEN` | Нужен controller API `profile + [(id, revision, text)] → vector/error`; текущий public route не подтверждён. | Реализовать/квалифицировать controller boundary; не агент и не отдельный scheduler Eliot. |
| R-016 | Research adapter | Architecture §§8; Implementation §§9.4,11.3 | `OPEN` | Контракт результата определён; существующий callable Memory↔Research endpoint не подтверждён. | Проверить текущий Eliot Research surface и реализовать один adapter. |
| R-017 | Project structure | Implementation §8.3 | `PARTIAL` | `codebase-memory-mcp` выбран как внешний structural tool; selected handlers изучены, deployment/language coverage нет. | Квалифицировать один реальный repo flow и fallback scope. |
| R-018 | Documents/PDF/media | Implementation §§4.7,8.4 | `PARTIAL` | Source locators выбраны; Docling — внешний converter candidate. Реальный adapter и round-trip locator не проверены. | Проверить representative PDF/document conversion и exact `open` locator. |
| R-019 | Backup/restore | Architecture §9; Implementation §12 | `DECIDED` | Owner-selected restore не блокируется утратой auxiliary history; known deletions применяются; old effects не replay. | Проверить SurrealDB export/import и Windows file cutover in Slice 6. |
| R-020 | Erasure/forgetting | Architecture §§4.6,9; Implementation §12.1; Cognition §13 | `DECIDED` | Exposure, influence, supersession и erasure разделены; external copies — явная граница. | Определить concrete deletion traversal/current restrictions and backup handling. |
| R-021 | Recursive improvement/self-diagnosis | Architecture §7; Implementation §§10.3,10.5–10.7; Cognition §§8–9; V2 I12.24 1–210 | `PARTIAL` | Цель изменённой следующей попытки сохранена. Устранено недоопределённое outcome→consumer: текущий вклад, релевантное исключение в context, адресный пересмотр метода. Описанные циклы ещё не исполнялись. | Проверить фактический следующий decision/request, исходы и границы применимости; не подменять изменение поведения счётчиком или новым советом без consumer. |
| R-022 | Disagreement/anticipation | Architecture §8; Implementation §11; Cognition §§10–11 | `CHECKED` | Alternatives/grounds/discriminating observation; no voting; expiry does not fabricate outcome. | Реализовать ordinary memory representations after core claims/methods. |
| R-023 | Direct control/status | Architecture §9; Implementation §13 | `DECIDED` | Owner can inspect/pause/cancel/correct/erase/backup/restore through actual state; notification optional. | Define CLI/MCP requests after Slice 1 Store/lifecycle. |
| R-024 | Normative-document consistency | Architecture 1.0; Implementation draft.5; Cognition draft.1; empty-project и feedback walkthroughs | `PARTIAL` | Исправлены first recipe/selection и current outcome→next context/revision. R-027 по-прежнему внешний code GAP. Новые решения не закрывают runtime, старые sources и остальные операции. | Следующий design-read: границы входа/обработки при нескольких streams и составе оснований; код и installed integration квалифицировать при реализации. |
| R-025 | Какие сохранения запускают интерпретацию | Implementation §§4.2,5.1,6.3,9.3 | `DECIDED` | Prepared/handoff, read/status, claim renewal и готовый embedding не являются новым опытом. Kind/producer выбирает обычную обработку без LLM-классификатора; self-diagnosis может читать эти сведения при конкретной проблеме. | Реализовать существующие producer→enqueue callers и отсутствие циклов на обычном read. |
| R-026 | Один active и pending job, повтор и stale result | Implementation §§4.6,5.2,5.4; native UNIQUE semantics | `DECIDED` | Project входит в target. Вычисляемый optional tuple + один UNIQUE индекс обеспечивает два слота без lock table. Reclaim сохраняет job/request identity; stale semantic result не оставляет вечный active барьер, saved output переходит в нужную reconciliation. | SQL shape не запускался; проверить claim/capture/apply interleaving и actual controller readback при реализации. |
| R-027 | Сохранённый controller result → публичный artifact handle | Прежний writer→public projection trace на `70b99db3`; compare `70b99db3..1c61629b` 23.10 | `GAP` | В новом controller commit изменены только audit-register и delivery, не runtime. Прежнее несоответствие nested artifact_ref публичной проекции не исправлено и не объявлено заново воспроизведённым. | Исправить существующую method-specific projection у controller и прочитать результат штатным клиентом. Memory OS не получает обход через private DB/filename/logs; scope старого finding сохранён. |
| R-028 | Первый рецепт и выбор выполняемого метода | Implementation §§4.3,5.2,10.3,Slice 3; Cognition §8.2 | `DECIDED` | Поставляемый реальный текст создаётся обычной method-записью при первом setup проекта; purpose/config выбирают её, claim фиксирует revision. Restart/upgrade не перезаписывают наученное. Method role/purpose отличают processing recipe от task advice; ordinary context не выбирает служебный рецепт по похожести. | Написать текст и seed/selection caller для первого реализуемого purpose; проверить empty project, concurrent setup, edit, retry и upgrade. Никакого Bootstrap service или prompt registry. |
| R-029 | Исход попытки → один текущий вклад → следующая работа | Implementation §10.5; Cognition §8.3; V2 I12.24 AttemptLearningDelta как требование, не перенос DTO | `DECIDED` | Event replay и повторные отчёты об одной попытке различены. Outcome — addressed memory по method revision/attempt/criterion с источниками; correction заменяет текущий вклад. Context читает релевантные exceptions, learning пересматривает конкретный метод. Packet не доказывает use. | Реализовать reducer и два reader; проверить два reports об одном результате, противоположные исходы разных attempts, correction и следующий изменённый context. Aggregates — views, без новой таблицы и permanent counters. |

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

База — [V3 на ff4f03a2](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/ff4f03a20a73eb92f3f7f0d4e4d6c17c56030488/docs/v3): Architecture, Implementation, Cognition и реестр прочитаны полностью; README и начало итогового AUDIT до выбранной таблицы требований — для границ задачи. Основной предмет — §§5.2,10.3,10.5 и реальные потребители learning. Недоопределённость проекта не называется воспроизведённым дефектом отсутствующего V3 runtime.

| Источник / охват | Что использовано | Что не заявляется |
|---|---|---|
| [V2 I12.24, 1–210](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/architecture/I12-24-meta-learning-and-improvement-delivery.md#L1-L210) | Два learning loop; положительные триггеры; AttemptLearningDelta требует изменения следующей связанной попытки, не одного сохранения failure. | Не перенос CampaignLearningStateView, admission/promotion, canary и отдельного семейства DTO. Полный старый caller в этом проходе не перечитан. |
| Предоставленные `ELIOT_ARCHITECTURE_ENGLISH_FINAL_2026-08-28.md`, §§A14.5–A14.6 (2539–2567); `ELIOT_IMPLEMENTATION_ENGLISH_FINAL_2026-08-28.md`, начало I4.4.1 (4597–4617) и selected failure table (14985–15005) | Разделение результата, измерения и изменения будущей работы; пустая память — нормальное состояние. | Это выбранные выдержки старых документов, не полное повторное чтение. Точный seed/selector/outcome address в V3 — новое решение V3, не цитата старой спецификации. Readiness receipts и старое глобальное блокирование не возвращены. |
| [Controller compare 70b99db3…1c61629b](https://github.com/UnknownAlienHuman/eliot-swarm-controller/compare/70b99db3d8732d10a69d03d1dbe83afdd39a7229...1c61629b49e8d6b9763dc7f5be32a0135509d7e3) | Один commit меняет только два документа. Source finding R-027 остаётся по прежним неизменённым функциям. | Не новая квалификация native execution, credentials, restart или результат исправления. Controller code здесь не меняется. |

Подробный прежний trace R-014/R-027, SurrealDB/Windows и остальные source ranges остаются в [реестре на ff4f03a2](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/ff4f03a20a73eb92f3f7f0d4e4d6c17c56030488/docs/v3/ANALYSIS-REGISTRY.md). Изменение recipe от bundled default к сохранённой revision и изменение следующего context по исходу — проектные walkthroughs, не выполненные model runs. Новых доноров и чтения всего архива не было.

Первый рецепт остаётся обычным содержимым, не квитанцией готовности. Outcome остаётся обычной versioned memory, не новой системой приёмки. Подготовленные изменения затрагивают только Implementation, Cognition и этот реестр. Model/DB/Windows/runtime, Clippy/product tests и независимые субагенты не запускались.

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
| P1 | Следующий design-read: вход/coverage при нескольких streams и обновление выводов с составными grounds; отличить незавершённый смысл от требуемой реализации | R-008, R-024, R-026 |
| P1 | При начале реализации перенести выбранные address/scope/version queries в migrations; проверить actual plans и межпроектный отбор до limit | R-003, R-006–R-011, R-026 |
| P1 | Проверить выбранные Windows lifecycle/spool primitives и backup cutover на настоящем запуске, когда начнётся реализация | R-002, R-019, R-023 |
| P1 | Подключить public result projection controller: artifact handle, completion и page range. Затем проверить одну client request→receipt recovery→page→artifact.read цепочку с реальными credentials; отдельно native retention/restart | R-014, R-027 |
| P1 | Квалифицировать installed Claude capture/context boundary, не путать его с controller model execution | R-012 |
| P1 | При реализации соединить bundled recipe→claim→real request→исход→изменённый следующий context/метод, включая дедупликацию обратной связи | R-004, R-010, R-013, R-028, R-029 |
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
| 2026-10-22 / `3596330f`, controller `70b99db3` | Draft.4: проверены exact request replay и public artifact reader; выявлен R-027 writer→projection разрыв. План убирает предположение о готовом public result handle и задаёт узкую правку существующего controller consumer. R-014/R-024 остаются PARTIAL; runtime не изменён. |
| 2026-10-23 / `ff4f03a2`, controller compare `1c61629b` | Draft.5: описаны default recipe без модельного bootstrap, purpose-based выбор и freeze revision; outcome становится текущим вкладом с двумя consumers. Добавлены R-028/R-029; R-010/R-021 уточнены до PARTIAL. R-027 остаётся GAP, code не менялся. |
