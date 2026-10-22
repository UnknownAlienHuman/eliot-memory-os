# Eliot V3 — реестр анализа

**Статус на 2026-10-22 · проверенная база Memory OS `3596330f`, controller `70b99db3` · активный рабочий реестр, не runtime gate.**

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
| R-010 | Реальный consumer method revision | Implementation §§5.2,9.2,10.3; Cognition §8.2 | `CHECKED` | Job фиксирует method ID/revision; request builder открывает exact body; новая версия влияет на последующие jobs. | Проверить controller adapter и фактический request body в Slice 3. |
| R-011 | Cross-project reuse | Architecture §4.4; Implementation §§3,4.3,5.5–5.6,10.4 | `DECIDED` | `reuse_scope={mode,projects}` использует stable project IDs. Выбираются local items либо eligible shared methods, не все чужие observations/views. Shared method не расширяет автоматически scope его источников при open. | Реализовать local/owner/selected запросы и scoped expansion, проверить отдельные query/route predicates без нового permission registry. |
| R-012 | Host capture | Implementation §6; audit donor/source findings | `PARTIAL` | Используются actual host results, child/parent streams и injected-text exclusion. Installed host event/version не проверены. | Квалифицировать конкретную Claude Code версию и event payloads перед Slice 2. |
| R-013 | Delivery semantics | Implementation §6.3; Cognition §§6.5,8.3 | `DECIDED` | Prepared, handoff, use и outcome различены; packet ID связывает exact delivered revisions; отсутствие correlation оставляет adherence unknown. | Квалифицировать adapter handoff feedback и implement best-effort tracking. |
| R-014 | Controller text execution и чтение результата | Controller `70b99db3`: Store::call/read_artifact, mutate_in_transaction_with_authority, public operation.get, result-origin admission | `PARTIAL` | Установлен exact replay caller/request/method/body: можно получить прежний admission без новой Store operation. Public artifact.read принимает bounded ranges и проверяет Bytes scope. Но выбранный readback теряет artifact handle — R-027. Generic result и prepared-Claude helper требуют source task.dispatch. | Исправить R-027 у controller; подключить одну actual dispatch→page→handle→bytes pair. Native-body retention/restart, successor identity и installed route остаются открытыми; не заменять их новым runtime Memory OS. |
| R-015 | Batch embeddings | Implementation §9.3 | `OPEN` | Нужен controller API `profile + [(id, revision, text)] → vector/error`; текущий public route не подтверждён. | Реализовать/квалифицировать controller boundary; не агент и не отдельный scheduler Eliot. |
| R-016 | Research adapter | Architecture §8; Implementation §§9.4,11.3 | `OPEN` | Контракт результата определён; существующий callable Memory↔Research endpoint не подтверждён. | Проверить текущий Eliot Research surface и реализовать один adapter. |
| R-017 | Project structure | Implementation §8.3 | `PARTIAL` | `codebase-memory-mcp` выбран как внешний structural tool; selected handlers изучены, deployment/language coverage нет. | Квалифицировать один реальный repo flow и fallback scope. |
| R-018 | Documents/PDF/media | Implementation §§4.7,8.4 | `PARTIAL` | Source locators выбраны; Docling — внешний converter candidate. Реальный adapter и round-trip locator не проверены. | Проверить representative PDF/document conversion и exact `open` locator. |
| R-019 | Backup/restore | Architecture §9; Implementation §12 | `DECIDED` | Owner-selected restore не блокируется утратой auxiliary history; known deletions применяются; old effects не replay. | Проверить SurrealDB export/import и Windows file cutover in Slice 6. |
| R-020 | Erasure/forgetting | Architecture §§4.6,9; Implementation §12.1; Cognition §13 | `DECIDED` | Exposure, influence, supersession и erasure разделены; external copies — явная граница. | Определить concrete deletion traversal/current restrictions and backup handling. |
| R-021 | Recursive improvement/self-diagnosis | Architecture §7; Implementation §§10.6–10.7; Cognition §9 | `CHECKED` | Existing methods/jobs/outcomes; baseline/no-change; diagnosis corrects first supported failed step. | Реализация после connected method/outcome path; не отдельный runtime. |
| R-022 | Disagreement/anticipation | Architecture §8; Implementation §11; Cognition §§10–11 | `CHECKED` | Alternatives/grounds/discriminating observation; no voting; expiry does not fabricate outcome. | Реализовать ordinary memory representations after core claims/methods. |
| R-023 | Direct control/status | Architecture §9; Implementation §13 | `DECIDED` | Owner can inspect/pause/cancel/correct/erase/backup/restore through actual state; notification optional. | Define CLI/MCP requests after Slice 1 Store/lifecycle. |
| R-024 | Normative-document consistency | Implementation 1.0-draft.4 §§4.6,9.1,14; registry producer/consumer trace | `PARTIAL` | Прежнее «использовать artifact operations» не замыкало public consumer: handle есть в сохранённом результате, но не в проекции. План теперь называет required controller repair, exact request replay и реальный range-read. Остальные границы не объявлены закрытыми. | После исправления public response проверить реальный клиентский вызов; не считать запись документа исправлением кода controller. |
| R-025 | Какие сохранения запускают интерпретацию | Implementation §§4.2,5.1,6.3,9.3 | `DECIDED` | Prepared/handoff, read/status, claim renewal и готовый embedding не являются новым опытом. Kind/producer выбирает обычную обработку без LLM-классификатора; self-diagnosis может читать эти сведения при конкретной проблеме. | Реализовать существующие producer→enqueue callers и отсутствие циклов на обычном read. |
| R-026 | Один active и pending job, повтор и stale result | Implementation §§4.6,5.2,5.4; native UNIQUE semantics | `DECIDED` | Project входит в target. Вычисляемый optional tuple + один UNIQUE индекс обеспечивает два слота без lock table. Reclaim сохраняет job/request identity; stale semantic result не оставляет вечный active барьер, saved output переходит в нужную reconciliation. | SQL shape не запускался; проверить claim/capture/apply interleaving и actual controller readback при реализации. |
| R-027 | Сохранённый controller result → публичный artifact handle | `store/results.rs::record`, `store/assembly.rs::finish` → `object_reads::current_operation` → `operations::project_result_receipt` | `GAP` | Writer кладёт `artifact_ref`/range в `details`; публичная проекция не читает этот объект. Для assembly перечислен верхнеуровневый `artifact_id`, которого writer не выдаёт. Конкретный operation.get→artifact.read consumer недоопределён уже в реальном controller, не только в V3 prose. | В существующей method-specific projection controller вернуть типизированные result reference/completion/range; сохранить object checks. Runtime не изменён. Не обходить через private DB, вычисление имени файла или повтор inference. |

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

Memory OS: [Implementation и реестр на 3596330f](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/3596330f04751f9471e20eb38e63280f6e6a739e/docs/v3) прочитаны целиком; предмет правки — job request identity и §9.1. Предыдущие SurrealDB/Windows и assembly readings сохранены в [предыдущем реестре](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/3596330f04751f9471e20eb38e63280f6e6a739e/docs/v3/ANALYSIS-REGISTRY.md). В этом проходе они не повторялись.

Controller проверен на **`70b99db3d8732d10a69d03d1dbe83afdd39a7229`**. GitHub compare с `c3e331a3` показал только две изменённые страницы документации, без изменения runtime. [Обновлённый audit register](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/70b99db3d8732d10a69d03d1dbe83afdd39a7229/docs/agent-operations/audit-register.md) использован как навигация и источник ранее установленных ограничений, не как доказательство реализованного исправления.

| Прочитанный source path | Подтверждённый вывод | Непроверенная граница |
|---|---|---|
| [Store call/mutation](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/70b99db3d8732d10a69d03d1dbe83afdd39a7229/crates/swarm-kernel-host/src/store/mod.rs#L6013-L6250), также 1930–2190,5480–5850,6240–6490 | `mutate_in_transaction_with_authority` ищет прежнюю запись по caller/request, сравнивает method/canonical payload и возвращает сохранённый receipt до apply. `operation.get` принимает Operation ID и читает публичную проекцию, не private row. | Это не универсальное exactly-once исполнение у provider. Текущая авторизация должна сохраниться; новый caller или другой controller — другая область. |
| [object_reads 1–145](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/70b99db3d8732d10a69d03d1dbe83afdd39a7229/crates/swarm-kernel-host/src/store/object_reads.rs#L1-L145) → [operations projection 280–535](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/70b99db3d8732d10a69d03d1dbe83afdd39a7229/crates/swarm-kernel-host/src/store/operations.rs#L280-L535) | После object grant публичный reader вызывает `project_operation`/`project_result_receipt`. Он копирует только перечисленные top-level scalars; result.details для этих методов не переносится. | Не утверждается отсутствие любого другого публичного способа найти artifact. В этом указанном readback его reference отсутствует. |
| [Result registration 1370–1440](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/70b99db3d8732d10a69d03d1dbe83afdd39a7229/crates/swarm-kernel-host/src/store/results.rs#L1370-L1440) и [assembly finish 95–123](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/70b99db3d8732d10a69d03d1dbe83afdd39a7229/crates/swarm-kernel-host/src/store/assembly.rs#L95-L123) | Оба writer сохраняют ссылку как nested `details.artifact_ref`; страница также содержит range/EOF/next offset. Сопоставление с public projection подтверждает R-027 без гипотезы о недостающем сохранении файла. | Ни live запрос, ни исправление controller не выполнялись. Source success — выбранная ветвь, не сообщение о выполненном model call. |
| [Public assembly/read 3283–3433](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/70b99db3d8732d10a69d03d1dbe83afdd39a7229/crates/swarm-kernel-host/src/store/mod.rs#L3283-L3433) | Assembly возвращает прежний admission receipt даже после выполнения. `artifact.read` принимает 1–65536 bytes, разрешает реальные Bytes grants, отклоняет Module role и только затем обращается к файлу. | Все ветви object_scope/cache invalidation не прочитаны; порядок проверки не объявлен полным аудитом прав или race behavior. |
| [Result admission/Claude helper 4960–5580](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/70b99db3d8732d10a69d03d1dbe83afdd39a7229/crates/swarm-kernel-host/src/store/runtime.rs#L4960-L5580) | Generic selector требует source `task.dispatch`; prepared-Claude helper дополнительно требует текущий dispatch/Attempt. Strict Antigravity alternative разрешает status selector, не произвольный body. Происхождение следующего `agent.send` нельзя подменить первым dispatch. | Полный native adapter execution не запускался; не все provider-specific result paths просмотрены. Текст AR-006 не превращён в вывод обо всех провайдерах. |

Дополнительно прочитаны `operation_lifecycle.rs` 1–320 (private caller/request loader), `object_reads.rs` 145–285 и selected navigation portions `store/mod.rs` 1–210,3900–4180,4620–4950, `operations.rs` 2100–2420. Они не названы полной проверкой соответствующих больших файлов. Два отрицательных поиска по предполагаемым именам метода не дали сведений о наличии API; дальнейший вывод получен из фактического dispatcher/mutation кода, а не из отсутствия search hits.

**Граница результата:** repaired projection — требование к controller, не выполненное изменение. Подтверждённый request replay устраняет недоопределённость потерянного admission reply в плане Memory OS, но не восстанавливает утраченные native bytes. Новых donor/runtime/model/SQL/Windows запусков, product/synthetic tests или независимых субагентов нет. Current delivery ограничена двумя документами Memory OS; controller repo и его audit register не меняются.

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
| P1 | Подключить public result projection controller: artifact handle, completion и page range. Затем проверить одну client request→receipt recovery→page→artifact.read цепочку с реальными credentials; отдельно native retention/restart | R-014, R-027 |
| P1 | Квалифицировать installed Claude capture/context boundary, не путать его с controller model execution | R-012 |
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
| 2026-10-22 / `3596330f`, controller `70b99db3` | Draft.4: проверены exact request replay и public artifact reader; выявлен R-027 writer→projection разрыв. План убирает предположение о готовом public result handle и задаёт узкую правку существующего controller consumer. R-014/R-024 остаются PARTIAL; runtime не изменён. |
