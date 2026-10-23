# Eliot V3 — реестр анализа

**Статус на 2026-10-23 · проверенная база Memory OS `9b4a0bf4`, claude-mem `dcb28a76` · активный рабочий реестр, не runtime gate.**

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
| R-003 | Точный адрес continuation | Implementation §§4.3,6.1,7.2; native UNIQUE; Claude hook fields, 23.10 | `DECIDED` | Host namespace/session/agent определяют actor stream; role name и prompt ID не заменяют task identity. Session membership не доказывает immediate parent/spawn call. Новая точная связь дополняет прежний материал, не смешивает actor streams. | При реализации сверить native IDs, resume/fork, повторные child starts и concurrent attach. Installed payloads ещё не получены. |
| R-004 | Identity context packet и атрибуция метода | Implementation §§4.4,5.5–5.6,6.3,10.5 | `DECIDED` | Packet хранит фактически отрисованные exact revisions, не новые heads, прочитанные позже. Исторический packet открывается как сохранённый текст; tracking остаётся необязательным для ответа и не новым опытом. | Реализовать version-coherent hydration/link reads и actual host correlation; не приписывать use из наличия packet ID. |
| R-005 | Прямая структурированная поправка | Implementation §§4.2,5.1,5.3–5.4,10.2 на `e6213e2f` и правка draft.2 | `DECIDED` | Ранее observation commit и edit допускали разрыв. Теперь correction, revision/history и её result handles записываются в одной caller-owned transaction; replay возвращает прежний результат до новой CAS-проверки. Stale edit сохраняется как неприменённая поправка, не теряется. | Реализовать один command entrypoint без fake job; проверить реальный commit/readback и conflict behavior. |
| R-006 | Шесть таблиц и Store operations | Implementation §§4–5,8.5,10.1; выбранные native query primitives | `PARTIAL` | К прежним address/scope queries уточнены направление grounding links, reverse lookup и чтение по stream/ingest_seq. Это не исполненные migrations или query plans. | При реализации проверить schema, indexes, EXPLAIN, concurrency и ordering выбранной server/SDK пары. Нет второго graph/cursor store. |
| R-007 | Revision/history/current-state | Implementation §§4.4,5.3–5.6; Cognition §3 | `DECIDED` | Exact version: matching current либо history по полному item/revision в согласованном read. Current-only lookup не ищет последний historical row. Текст и grounds берутся одной editorial revision; обновление между search и hydration не подменяет handle. | Реализовать read/write queries и короткую consistency boundary без транзакции через model/host call; проверить missing/deleted/revised item. |
| R-008 | Compound grounds и пересмотр зависимых выводов | Architecture §4.5; Implementation §§4.5,8.5,12.1; Cognition §3.3; V2 I12.20/I12.37 | `PARTIAL` | Раньше проверено только обозначение AND/OR. Теперь group принадлежит conclusion revision; различены пригодное, нарушенное и неизвестное основание. Определены reverse links→finite job→qualification/revision→context, альтернативы и запрет считать исчезнувший член выполненным. Новая edition, недоступность, refutation и erasure не одно событие. | Реализовать reducer и paged propagation; проверить альтернативы, cycle, удалённый member, новые изменения во время обхода и видимость qualification до завершения пересмотра. Полная erasure/recovery остаётся R-020. |
| R-009 | Retrieval arms и packing | Implementation §§5.5–5.6,8.1; SurrealDB scoring/filtered vector docs | `PARTIAL` | Scope/recorded eligibility применяются внутри каждого arm до limit; union и semantic applicability идут до packing. Выбран lexical scope excerpt; native vector prefilter не обещан для любого array predicate. | Проверить actual query plans, current-state alternatives и полезный результат после отбрасывания кандидатов. SQL здесь не запускался. |
| R-010 | Реальный consumer method revision | Implementation §§5.2,10.3; Cognition §8.2, baseline `ff4f03a2` и draft.5 | `PARTIAL` | Прежний план фиксировал редакцию, но не задавал начальный текст и выбор по purpose. R-028 определяет эти переходы; request builder по-прежнему обязан использовать exact body. Storage alone не самоулучшение. | Реализовать первый model job из пустой проектной памяти и последующий job после изменения метода; проверить настоящий request body, не только наличие refs. |
| R-011 | Cross-project reuse | Architecture §4.4; Implementation §§3,4.3,5.5–5.6,10.4 | `DECIDED` | `reuse_scope={mode,projects}` использует stable project IDs. Выбираются local items либо eligible shared methods, не все чужие observations/views. Shared method не расширяет автоматически scope его источников при open. | Реализовать local/owner/selected запросы и scoped expansion, проверить отдельные query/route predicates без нового permission registry. |
| R-012 | Native hook → normalized observation | Implementation §6.1; Claude hooks reference 23.10; D45 `dcb28a76` adapter→dispatcher→summarize | `PARTIAL` | Уточнены session/actor/call/representation и final-message поля. У выбранного donor caller normalized input теряет last_assistant_message, хотя handler его читает; вместо него используется transcript. V3 сохраняет hook payload, различает absent/empty и не подставляет старый tail как текущий ответ. | Реализовать один relay; сверить installed version/payloads, child transcript path, отсутствие финальной строки на диске и позднее поступление. Donor code не исправлялся и не запускался. |
| R-013 | Native context delivery | Implementation §6.3; Claude add-context, JSON output, async и stop contracts | `PARTIAL` | Выбраны actual next-model boundaries и короткий JSON response. Stop feedback не пассивная доставка; hook overflow не full handoff. Packet имеет recipient, local write не доказывает принятие/использование. | При реализации проверить resume/child/repeated start, лимит строки, broken stdout и отсутствие лишнего turn. Installed acceptance не наблюдалась. |
| R-014 | Controller text execution и чтение результата | Controller `70b99db3`: Store::call/read_artifact, mutate_in_transaction_with_authority, public operation.get, result-origin admission | `PARTIAL` | Установлен exact replay caller/request/method/body: можно получить прежний admission без новой Store operation. Public artifact.read принимает bounded ranges и проверяет Bytes scope. Но выбранный readback теряет artifact handle — R-027. Generic result и prepared-Claude helper требуют source task.dispatch. | Исправить R-027 у controller; подключить одну actual dispatch→page→handle→bytes pair. Native-body retention/restart, successor identity и installed route остаются открытыми; не заменять их новым runtime Memory OS. |
| R-015 | Batch embeddings | Implementation §9.3 | `OPEN` | Нужен controller API `profile + [(id, revision, text)] → vector/error`; текущий public route не подтверждён. | Реализовать/квалифицировать controller boundary; не агент и не отдельный scheduler Eliot. |
| R-016 | Research adapter | Architecture §§8; Implementation §§9.4,11.3 | `OPEN` | Контракт результата определён; существующий callable Memory↔Research endpoint не подтверждён. | Проверить текущий Eliot Research surface и реализовать один adapter. |
| R-017 | Project structure | Implementation §8.3 | `PARTIAL` | `codebase-memory-mcp` выбран как внешний structural tool; selected handlers изучены, deployment/language coverage нет. | Квалифицировать один реальный repo flow и fallback scope. |
| R-018 | Documents/PDF/media | Implementation §§4.7,8.4 | `PARTIAL` | Source locators выбраны; Docling — внешний converter candidate. Реальный adapter и round-trip locator не проверены. | Проверить representative PDF/document conversion и exact `open` locator. |
| R-019 | Backup/restore | Architecture §9; Implementation §12 | `DECIDED` | Owner-selected restore не блокируется утратой auxiliary history; known deletions применяются; old effects не replay. | Проверить SurrealDB export/import и Windows file cutover in Slice 6. |
| R-020 | Erasure/forgetting | Architecture §§4.6,9; Implementation §§8.5,12.1; Cognition §§3.3,13 | `PARTIAL` | Уточнён потерянный required member: удалить link не значит доказать сокращённую группу. Альтернативное основание не разрешает оставить удаляемые bytes старой synthesis. Остальная cleanup/restore проводка не проверена. | Определить concrete deletion traversal, допустимый marker и backup handling; не сохранять удалённый текст ради provenance. |
| R-021 | Recursive improvement/self-diagnosis | Architecture §7; Implementation §§10.3,10.5–10.7; Cognition §§8–9; V2 I12.24 1–210 | `PARTIAL` | Цель изменённой следующей попытки сохранена. Устранено недоопределённое outcome→consumer: текущий вклад, релевантное исключение в context, адресный пересмотр метода. Описанные циклы ещё не исполнялись. | Проверить фактический следующий decision/request, исходы и границы применимости; не подменять изменение поведения счётчиком или новым советом без consumer. |
| R-022 | Disagreement/anticipation | Architecture §8; Implementation §11; Cognition §§10–11 | `CHECKED` | Alternatives/grounds/discriminating observation; no voting; expiry does not fabricate outcome. | Реализовать ordinary memory representations after core claims/methods. |
| R-023 | Direct control/status | Architecture §9; Implementation §13 | `DECIDED` | Owner can inspect/pause/cancel/correct/erase/backup/restore through actual state; notification optional. | Define CLI/MCP requests after Slice 1 Store/lifecycle. |
| R-024 | Normative-document consistency | Implementation draft.7 §§5.1,6,Slice 2; baseline `9b4a0bf4` | `PARTIAL` | Общая модель stream/coverage доведена до native hook mapping; разные representations одного call не новые trials; поздний response не доставляется в чужую работу. Добавлена защита от собственного read→learning цикла обычной классификацией producer. | Следующий source-read: Docling conversion→locator→exact open и доступный Research caller. Runtime, controller R-027 и архив не закрыты. |
| R-025 | Какие сохранения запускают интерпретацию | Implementation §§5.1,6.1,8.5,9.3 | `DECIDED` | Eliot context/open/status, наблюдаемые как tool hooks, тоже operational: упаковка своих знаний не новое evidence. Узнаются по настроенному tool/server mapping. Материальные внешние действия/поправки сохраняются; JSON с похожими словами не является основанием исключения. | Реализовать producer→enqueue callers и один end-to-end read без самозапуска reflection. Остальные premise-change правила сохраняются. |
| R-026 | Один active и pending job, повтор и stale result | Implementation §§4.6,5.2,5.4,10.1; native UNIQUE semantics | `DECIDED` | Frozen input сохраняется при reclaim; более поздние события и неохваченные portions остаются successor. Coverage относится к purpose/target и фактическому входу, не ко всему выбранному диапазону. | При реализации проверить claim/capture/apply, partial output, несколько streams и controller readback. SQL shape ещё не выполнялся. |
| R-027 | Сохранённый controller result → публичный artifact handle | Прежний writer→public projection trace на `70b99db3`; compare `70b99db3..1c61629b` предыдущего прохода | `GAP` | Последняя source-проверка не установила исправления nested artifact_ref. В этом проходе controller не перечитан и не изменён; прежний finding сохраняет свою ревизию и область. | Сначала сверить новый controller head; исправить существующую method-specific projection и прочитать результат штатным клиентом. Без private DB/filename/log обхода. |
| R-028 | Первый рецепт и выбор выполняемого метода | Implementation §§4.3,5.2,10.3,Slice 3; Cognition §8.2 | `DECIDED` | Поставляемый реальный текст создаётся обычной method-записью при первом setup проекта; purpose/config выбирают её, claim фиксирует revision. Restart/upgrade не перезаписывают наученное. Method role/purpose отличают processing recipe от task advice; ordinary context не выбирает служебный рецепт по похожести. | Написать текст и seed/selection caller для первого реализуемого purpose; проверить empty project, concurrent setup, edit, retry и upgrade. Никакого Bootstrap service или prompt registry. |
| R-029 | Исход попытки → один текущий вклад → следующая работа | Implementation §10.5; Cognition §8.3; V2 I12.24 AttemptLearningDelta как требование, не перенос DTO | `DECIDED` | Event replay и повторные отчёты об одной попытке различены. Outcome — addressed memory по method revision/attempt/criterion с источниками; correction заменяет текущий вклад. Context читает релевантные exceptions, learning пересматривает конкретный метод. Packet не доказывает use. | Реализовать reducer и два reader; проверить два reports об одном результате, противоположные исходы разных attempts, correction и следующий изменённый context. Aggregates — views, без новой таблицы и permanent counters. |
| R-030 | Несколько streams, поздние события и фактический охват | Implementation §§6.1,7.2,10.1; Cognition §§2,4; прежнее чтение V2 I12.37 | `DECIDED` | Правило A/B сохранено. Native mapping теперь не выдумывает immediate parent; поздняя association активирует сохранённый child input. Hook body, rendered tool result и transcript enrichment сохраняют source identity и не становятся независимыми попытками. | Реализовать ingress/stream mapping и reconcile complete transcript records; проверить позднюю запись файла, повторный stop/resume, ambiguous origin и actual parent receipt. |

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
| S-010 | External donors D01–D47 | `PARTIAL` | Прежний учёт: 17 source-code, 5 docs/paper, 25 unreconciled positions. Углублён D45, не добавлен новый донор и не выполнена полная повторная инвентаризация. | 
| S-011 | Independent subagent review | `OPEN` | No available GPT Luna/subagent execution was used; current review is single-agent. |

### Источники текущего прохода

База — [V3 на 9b4a0bf4](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/9b4a0bf433c8308242961a59d35940eae1e40d5f/docs/v3). AGENTS, полный Implementation и активный реестр прочитаны заново; Architecture/Cognition и V2 I12.37 не объявляются новым полным чтением. Предмет — native host adapter и потеря данных между его producer/normalizer/consumer. Общая архитектура и шесть таблиц не изменены.

**Официальная документация, прочитано 23.10.2026:** [Claude Code hooks](https://code.claude.com/docs/en/hooks), разделы Common input fields, JSON output/Add context, SessionStart, PostToolUse/Failure/Batch, SubagentStart/Stop, Stop/StopFailure, PostCompact и async behavior; обзор [subagents](https://code.claude.com/docs/en/sub-agents) использован только для границы отдельного контекста. В источнике есть session/agent/call identifiers и разные формы результата; transcript может отставать, а hooks передают final text. Ограничение hook-строки, повторный start и Stop feedback влияют на доставку. Это текущая публичная документация, не установленный build владельца. Номер версии, payload compatibility и live host acceptance остаются непроверенными.

**D45 claude-mem — `dcb28a768c6be4b8e451843210558275caa8ec44`:**

| Прочитано целиком | Подтверждённый source scope |
|---|---|
| [plugin/hooks/hooks.json](https://github.com/thedotmack/claude-mem/blob/dcb28a768c6be4b8e451843210558275caa8ec44/plugin/hooks/hooks.json) | `Stop` вызывает `hook claude-code summarize`; tool success/failure используют observation handler. В этом manifest нет SubagentStart/Stop registrations; это не утверждение об отсутствии иных интеграций во всём продукте. |
| [adapters/index.ts](https://github.com/thedotmack/claude-mem/blob/dcb28a768c6be4b8e451843210558275caa8ec44/src/cli/adapters/index.ts), [claude-code.ts](https://github.com/thedotmack/claude-mem/blob/dcb28a768c6be4b8e451843210558275caa8ec44/src/cli/adapters/claude-code.ts) | Выбран именно claudeCodeAdapter. Он сохраняет agent/tool IDs и failure fields, но не переносит raw `last_assistant_message` в normalized `lastAssistantMessage`. Сохранение других полей не отменяет эту потерю. |
| [hook-command.ts](https://github.com/thedotmack/claude-mem/blob/dcb28a768c6be4b8e451843210558275caa8ec44/src/cli/hook-command.ts), [handlers/index.ts](https://github.com/thedotmack/claude-mem/blob/dcb28a768c6be4b8e451843210558275caa8ec44/src/cli/handlers/index.ts) | Pipeline передаёт результат normalizeInput в выбранный summarizeHandler, добавляя platform; raw payload повторно не подмешивается. Это настоящий caller, не вывод только по объявлению поля. |
| [handlers/summarize.ts](https://github.com/thedotmack/claude-mem/blob/dcb28a768c6be4b8e451843210558275caa8ec44/src/cli/handlers/summarize.ts) | Есть предпочтительная ветвь готового final text, но в прослеженном Claude path она не получает поле. Используется transcript fallback; отсутствие текста/path/read может закончиться пропуском summary. Наличие agentId отдельно пропускает summary. |

**Вывод из source path, не live-инцидент:** готовый final text теряется до умеющего его использовать consumer. При отставшем transcript выбранный путь может пропустить текущий ответ или взять не тот доступный хвост; реальная частота и installed bundle не проверены. V3 сохраняет supplied text и его источник, различает отсутствие/пустоту, а дополнительный transcript читает отдельно с matching identity. Не копируем donor setup scripts, runtime topology или каждый его fallback. Полезный принцип — не превращать ошибку памяти в блокировку хоста — сохранён без сокрытия capture failure.

Остальные решения §6 — проектирование Eliot: composite actor/call/facet keys, стабильный ingress ID для собственного replay, короткий capture до фоновой интерпретации, recipient-bound packet и operational classification своих MCP reads. Они не объявляются готовыми возможностями донора. Прямой wire event не доказывает успех всей задачи; `agent_type`, prompt ID и законченный child report не восполняют неизвестный task/parent/receipt.

Предыдущие stream/grounds/controller readings находятся в [реестре на 9b4a0bf4](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/9b4a0bf433c8308242961a59d35940eae1e40d5f/docs/v3/ANALYSIS-REGISTRY.md). Controller и R-027 здесь не перечитаны и не исправлены. Нет нового полного archive audit, model/DB/Windows запуска, behavioural tests, Clippy или независимого субагентного review. Публикация ограничена Implementation и этим реестром; donor code, CI и другие репозитории не меняются.

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
| P1 | При реализации сверить выбранный Claude adapter с installed payloads: final text при отставшем transcript, child/resume identity, две формы одного call, stop без дополнительного turn и output budget | R-003, R-012, R-013, R-025, R-030 |
| P1 | При начале реализации перенести выбранные address/scope/version, stream-range и reverse-link queries в migrations; проверить actual plans, partial coverage и адресный пересмотр оснований | R-006–R-011, R-026, R-030 |
| P1 | Проверить выбранные Windows lifecycle/spool primitives и backup cutover на настоящем запуске, когда начнётся реализация | R-002, R-019, R-023 |
| P1 | Подключить public result projection controller: artifact handle, completion и page range. Затем проверить одну client request→receipt recovery→page→artifact.read цепочку с реальными credentials; отдельно native retention/restart | R-014, R-027 |
| P1 | При реализации соединить bundled recipe→claim→real request→исход→изменённый следующий context/метод, включая дедупликацию обратной связи | R-004, R-010, R-013, R-028, R-029 |
| P2 | Следующий source-read: Docling original→converted element→source locator→exact open; затем реальный callable Research input/result, без переноса ещё одного memory runtime | R-016, R-018 |
| P2 | Уточнить physical erasure/derived cleanup и backup cutover без потери loss-of-ground qualification | R-008, R-019, R-020 |
| P2 | Реализовать/квалифицировать batch embeddings boundary | R-015 |
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
| 2026-10-23 / `1be6e9c1` | Draft.6/Cognition draft.2: explicit multi-stream membership/input/coverage, late-child replay в нужный target и перенос неохваченного материала; обратные grounding links, альтернативы и конкретная qualification в context. R-030 добавлен; R-008/R-020 уточнены до PARTIAL. Только проектные исправления, без новых таблиц/служб и без runtime-прогона. |
| 2026-10-23 / `9b4a0bf4`, D45 `dcb28a76` | Draft.7: actual host fields/actor/call representations, final-message preservation, короткий durable capture, next-model delivery и host string cap. Прослежен donor normalized-field loss до summarize consumer. Обновлены существующие R-003/R-012/R-013/R-024/R-025/R-030; новых runtime owners и новых строк R не добавлено. |
