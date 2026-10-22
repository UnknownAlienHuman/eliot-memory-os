# Eliot V3 — реестр анализа

**Статус на 2026-10-22 · baseline `abec7502` · активный рабочий реестр, не runtime gate.**

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
| R-002 | Локальная process family | Architecture §3; Implementation §1 | `DECIDED` | Один supervisor владеет daemon+SurrealDB; relay временный; daemon не наблюдает собственный hang. | Проверить Windows launch mutex, Job Object, readiness и idle shutdown при Slice 1. |
| R-003 | Точный адрес continuation | Architecture §5; Implementation §§3,4.3,5.5,6.1,7; Cognition §2 | `DECIDED` | `attach` возвращает exact continuation key; `memory` имеет `address_kind/address_key` и exact index; interleaved task/branch IDs не сливаются в session fallback. | Реализовать typed key construction и exact query в Slice 2. |
| R-004 | Identity context packet и атрибуция метода | Architecture §7; Implementation §§3,4.2,4.5,5.5,6.3,10.5; Cognition §§6.5,8.3 | `DECIDED` | `context` возвращает stable packet ID; prepared/handoff — application observations; packet links exact item/method revisions; later action/outcome carries ID only when host can correlate. | Реализовать packet event/link writes и host feedback; tracking failure must not suppress advice. |
| R-005 | Прямая структурированная поправка | Implementation §§5.3–5.4,6.1,10.2; Cognition §7 | `DECIDED` | Один internal `publish_revision` используется job result и captured direct correction; fake job/service не нужен. | Реализовать CAS/history/link transaction and direct-correction caller. |
| R-006 | Шесть таблиц и Store operations | Implementation §§4–5 | `CHECKED` | Схема и ownership согласованы; context packets остаются observations/links, нет mirrored search DB или отдельного skill/outcome store. | Спроектировать SurrealDB migration/query files и проверить планы на выбранной версии. |
| R-007 | Revision/history/current-state | Architecture §4; Implementation §§4.3–4.5,5.3–5.4; Cognition §3 | `CHECKED` | Current row, history, replacement и withdrawal разделены; старый predecessor не воскресает автоматически. | Реализовать CAS/update/history transaction; проверить zero-row behavior. |
| R-008 | Compound grounds | Architecture §4.5; Implementation §4.5; Cognition §3.3 | `CHECKED` | Одна non-null group = AND; разные groups = OR; ungrouped evidence supportive. Это не theorem prover. | Определить query/recompute для затронутых items; проверить неизвестную композицию. |
| R-009 | Retrieval arms и packing | Architecture §5; Implementation §§5.5,7–8; Cognition §6 | `CHECKED` | Exact/FTS/vector/relations независимы; union до applicability; display limit не candidate limit. | Проверить SQL/index/query plans и реальные budget limits в Slice 2/5. |
| R-010 | Реальный consumer method revision | Implementation §§5.2,9.2,10.3; Cognition §8.2 | `CHECKED` | Job фиксирует method ID/revision; request builder открывает exact body; новая версия влияет на последующие jobs. | Проверить controller adapter и фактический request body в Slice 3. |
| R-011 | Cross-project reuse | Architecture §§3,4.4; Implementation §§4.3,10.4; Cognition §8.4 | `CHECKED` | Origin не меняется; reuse scope фильтруется до top-k; counterexamples сохраняются. | Спроектировать typed reuse scope/index/query и disclosure filtering. |
| R-012 | Host capture | Implementation §6; audit donor/source findings | `PARTIAL` | Используются actual host results, child/parent streams и injected-text exclusion. Installed host event/version не проверены. | Квалифицировать конкретную Claude Code версию и event payloads перед Slice 2. |
| R-013 | Delivery semantics | Implementation §6.3; Cognition §§6.5,8.3 | `DECIDED` | Prepared, handoff, use и outcome различены; packet ID связывает exact delivered revisions; отсутствие correlation оставляет adherence unknown. | Квалифицировать adapter handoff feedback и implement best-effort tracking. |
| R-014 | Controller text execution | Implementation §9.1; audit §33 | `PARTIAL` | Реальный task-dispatch/model path найден; input admitted не completion. Later-send/result pairing ограничен. | Выбрать поддержанную request/result pair и durable result readback. |
| R-015 | Batch embeddings | Implementation §9.3 | `OPEN` | Нужен controller API `profile + [(id, revision, text)] → vector/error`; текущий public route не подтверждён. | Реализовать/квалифицировать controller boundary; не агент и не отдельный scheduler Eliot. |
| R-016 | Research adapter | Architecture §8; Implementation §§9.4,11.3 | `OPEN` | Контракт результата определён; существующий callable Memory↔Research endpoint не подтверждён. | Проверить текущий Eliot Research surface и реализовать один adapter. |
| R-017 | Project structure | Implementation §8.3 | `PARTIAL` | `codebase-memory-mcp` выбран как внешний structural tool; selected handlers изучены, deployment/language coverage нет. | Квалифицировать один реальный repo flow и fallback scope. |
| R-018 | Documents/PDF/media | Implementation §§4.7,8.4 | `PARTIAL` | Source locators выбраны; Docling — внешний converter candidate. Реальный adapter и round-trip locator не проверены. | Проверить representative PDF/document conversion и exact `open` locator. |
| R-019 | Backup/restore | Architecture §9; Implementation §12 | `DECIDED` | Owner-selected restore не блокируется утратой auxiliary history; known deletions применяются; old effects не replay. | Проверить SurrealDB export/import и Windows file cutover in Slice 6. |
| R-020 | Erasure/forgetting | Architecture §§4.6,9; Implementation §12.1; Cognition §13 | `DECIDED` | Exposure, influence, supersession и erasure разделены; external copies — явная граница. | Определить concrete deletion traversal/current restrictions and backup handling. |
| R-021 | Recursive improvement/self-diagnosis | Architecture §7; Implementation §§10.6–10.7; Cognition §9 | `CHECKED` | Existing methods/jobs/outcomes; baseline/no-change; diagnosis corrects first supported failed step. | Реализация после connected method/outcome path; не отдельный runtime. |
| R-022 | Disagreement/anticipation | Architecture §8; Implementation §11; Cognition §§10–11 | `CHECKED` | Alternatives/grounds/discriminating observation; no voting; expiry does not fabricate outcome. | Реализовать ordinary memory representations after core claims/methods. |
| R-023 | Direct control/status | Architecture §9; Implementation §13 | `DECIDED` | Owner can inspect/pause/cancel/correct/erase/backup/restore through actual state; notification optional. | Define CLI/MCP requests after Slice 1 Store/lifecycle. |
| R-024 | Normative-document consistency | Architecture 1.0, Implementation 1.0-draft.1, Cognition 1.0, README | `CHECKED` | Ownership and major paths align; R-003–R-005 closed without new tables/services. Runtime remains unimplemented. | Repeat after schema/API details materially change. |

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
| P1 | Спроектировать Slice 1 migrations/query files и Windows lifecycle primitives | R-002, R-006, R-007, R-019, R-023 |
| P1 | Квалифицировать installed Claude hooks и controller request/result readback | R-012, R-014 |
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
