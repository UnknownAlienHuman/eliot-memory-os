# Eliot Memory OS V3 — сводный аудит документации и архитектуры

**Редакция 0.10 · 20 октября 2026 · документация до переписывания продукта.**

**Новый результат — [§25](#25-real-experience-input-and-normal-context-010):** обычный сборщик контекста действительно вызывает поиск опыта, но чтение случаев связано с готовностью карты проекта; стандартный режим отсекает только что сформированный опыт. В retained MCP обнаружены карточки навыков, создаваемые из шаблона вместо чтения хранилища, и обработчик, конструирующий успешное «доказательство исполнения» без исполнения. У Harness2 дочитаны доступ к материалам и модельный executor/cache. Решения внесены в [Cognition](COGNITION.md), не в новую платформу проверок.

Этот документ — один поддерживаемый аудит. Повторяющиеся отчёты о публикации и оговорки прошлых проходов сведены; предметные находки, 34 требования, 29 исходных сценариев и D01–D44 сохранены как содержание, а не как обещание побайтной идентичности. Полные подробные версии и результаты прежних проб остаются неизменными в [аудите 0.9](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/0a71fd7d1b784486ef38f66b11cdd15cc8f8f81e/docs/v3/AUDIT.md), [0.4](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c28359fc2716f3b498ea512ca24a57801d18014c/docs/v3/AUDIT.md) и [ранней редакции](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/3512f6e4f4c9ce59ba2959193e92c0728fadf00c/docs/v3/AUDIT.md). Сокращение повторов не является новым выполнением старых проверок.

[Architecture](ARCHITECTURE.md) определяет назначение и границы; [Implementation](IMPLEMENTATION.md) — устройство; [Cognition](COGNITION.md) — когнитивные операции внутри тех же модулей; [карта аудита](AUDIT-MAP.md) — прочитанные пути и следующий предметный шаг. Ни один из этих файлов не заменяет работающий продукт.

## 1. Источники, решения и границы проверки

| Источник | Версия и роль |
|---|---|
| V1 | `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`: Canonical Master, Production Architecture, Understanding Layer; исходные требования и донор |
| V2 | `5aac094834fb5635921b550c821cb933a1196105`: старые нормативы, исходники и незавершённые программы |
| База текущего изменения V3 | `0a71fd7d1b784486ef38f66b11cdd15cc8f8f81e`: опубликованная редакция 0.9 в PR #5325 |
| Аудит Claude | Приложенный `eliot-documentation-audit(1)(1).md`, редакция 4: предложения, измерения и сообщённые решения; не безошибочная спецификация |
| Архив | [audit-2026-10-16-incomplete](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete): материалы анализа и доноров, не обязательный backlog V3 |
| Hy-Memory | `7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a`: выбранные writer, reconciliation, store, System 2 и transfer пути прежних проходов |
| MemOS local plugin | `a7367d07e55db61099f7b4e2c1108bc5831a24f3`: выбранные `l2.ts` и `gain.ts`, не полный продукт |
| Eliot Swarm Controller | `96a0d5a6632cfbd541e804d7969d3e76e716bf6a`: прежняя ограниченная проверка integration document; другие старые findings сохраняют собственные ссылки |
| Harness2, D44 | `1cfe254e8d25b15f37048c3730134686abe60335`, commit 14.10.2026; [статья 2610.14224v1](https://arxiv.org/html/2610.14224v1), 09.10.2026 |
| LangMem, D16 | `48e3c11f5bb527282c7d5339c6a87a0b35abccfc`: background/reflection и prompt optimization, рассмотренные в 0.8–0.9 |

Прямое поручение владельца: V1/V2 становятся донорами, V3 пишется с нуля после документации; сохраняются самообучение, когниция, модульность, гибкость и лёгкость; Dreamer заменяем по модели. Приложение Claude сообщает дополнительные решения: Rust, demand-start, SurrealDB child, модели и embeddings через controller, векторы в полном продукте, отсутствие собственного роя. Точные будущие версии SDK, API и численные параметры не объявляются уже согласованными или работающими.

Различаются **факт исходника**, **вывод из порядка операций**, **изолированная проба** и **работа установленного приложения**. Поиск имени не доказывает глобальное отсутствие реализации. Прочитанный DTO не доказывает наличие его автоматического producer. Реальный caller важнее объявления интерфейса; даже он не подтверждает успешный live вызов без такого наблюдения.

Текущий проход не запускает V2/V3, БД, Windows-процессы или модели и не выдаёт собственное повторное чтение за независимый review. Полные GitHub write-actions и push permission доступны; ветка публикуется через API независимо от недоступной сети локального окружения. Не требуется новая квитанция чтения, чтобы назвать проверенную функцию и её конкретный недостаток.

## 2. Где началось разрастание

### 2.1 Масштаб и предел арифметики

Ниже сохранены измерения первого прохода, а не новый пересчёт.

| Показатель | V1 | V2 |
|---|---:|---:|
| Rust-файлы | 139 | 2 472 |
| Физические строки Rust, включая комментарии, пустые строки и inline tests | 172 579 | 2 638 670 |
| Tracked files | Не пересчитано | 4 999 |
| Cargo package manifests | Не пересчитано | 199 |
| Package manifests под bins | Не пересчитано | 15 |
| Markdown | Не пересчитано | 850 файлов / 47 012 строк |
| Python | Не пересчитано | 150 файлов / 144 845 строк |
| TOML | Не пересчитано | 421 файл / 587 866 строк |

Package не равен постоянно работающему процессу. Подсчёт физических строк не равен объёму production logic. Деление 2 638 670 на 50 даёт около 52 773 строк, но не доказывает бюджет работающей V3. Оценки «26,5 тысячи кода плюс 15 тысяч тестов» и «60–100 раз» остаются прогнозами с другим знаменателем. Считать нужно обязательный controller, адаптеры, SQL, эксплуатацию и реальные model calls, а не переместить расходы в соседний репозиторий.

### 2.2 V1 не следует клонировать целиком

[V1 Production Architecture §0–1](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Rust_Governor_Production_Architecture_v1_0.md#L1-L155) полезно отделяет инструментальный Governor от модели и использует серверную БД вместо нескольких competing stores. Но рядом уже предписывает redb Control WAL, leases, proof bookkeeping и продвижение policy/skills/retrieval. Компактная топология и аппарат доказательств — разные решения. Берём первое и реальные failure cases второго, не всю инфраструктуру.

### 2.3 V2 сделала сложную запись универсальным путём

[I1.2](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/architecture/I01-02-required-processes-of-the-first-complete-runtime.md) разделяет Host, Kernel, daemon, Watchdog, storage bridge и SurrealDB. Blob capability допускается co-located: нельзя приписывать документу обязательный отдельный blob executable. Однако каждая настоящая граница требует launch, ownership, доставки, restart и обработки неизвестного результата.

[I5.6](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/architecture/I05-06-admission-and-staging.md) задаёт 18 шагов записи: scope/task/fence/provenance, digests, ORS staging, ordering, DB transaction, receipt reconciliation, outbox. Kernel и storage bridge снова проверяют то, что прошло предыдущий слой. Это цена выбранной топологии, а не естественное свойство записи памяти.

**Корневое решение V3:** убрать ненужные межпроцессные границы и универсальные планы. Один typed domain call, проверка реального входа, stable retry identity и нужная транзакция заменяют старый distributed pipeline. Удалять случайные проверки, сохраняя pipeline, означало бы создавать следующую партию компенсаций.

### 2.4 Петля, которую нужно разорвать

Понятие получает тип; тип — отдельного владельца и lifecycle; состояние копируется; shape-PASS заменяет полезного consumer; незавершённость лечится квитанцией; квитанция требует собственного восстановления. В итоге система доказывает, что подготовила форму, но не помогает следующему действию.

Документы содержали и правильные запреты: [I17.11](../architecture/I17-11-delivery-depth-d3-grounded-smart-understanding.md) допускал D3a до всей необязательной широты D2. Следовательно, нельзя объяснить всё исключительно безупречным исполнением нормативов. Есть три разные причины: дорогая доктрина, ошибочное чтение и недостающая проводка. Аудит проверяет их по связанным функциям, а не только по размеру каталогов.

## 3. The 34 preserved requirements

Основания: [Canonical Master](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Canonical_Master.md), [Production Architecture](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Rust_Governor_Production_Architecture_v1_0.md), [Understanding Layer](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md). Это сохранение требований, не свидетельство выполненных тестов.

| № | Требование | Компактный механизм и сохраняемый смысл |
|---|---|---|
| 1 | Независимость от модели, провайдера и host | Общая память и реальные адаптеры; совместимость интерфейса не обещает одинакового качества |
| 2 | Внешняя когнитивная петля | Наблюдение → контекст → действие/исход → изменение следующей работы |
| 3 | Автономность понимания | Автоматические карты и provisional методы без approval каждой записи |
| 4 | Экономия токенов и операций | Exact/lexical, совместимые vectors, batching, раскрытие; без LLM перед каждым чтением |
| 5 | Разные виды знания | Observation, claim, hypothesis, decision, procedure и unknown не сливаются в один score |
| 6 | Актуальность относительно мира | Материальные live anchors; история не аннулируется сменой HEAD |
| 7 | Точное происхождение | Source event/revision/span, доступный оригинал, сохранённые числа и исключения |
| 8 | Противоречие и пересмотр | Ревизии, альтернативы и контрдоказательство вместо last-write-wins |
| 9 | Область до использования | Поиск и раскрытие в выбранном project/workspace, не чужой top-k |
| 10 | Данные не создают полномочий | Goal/config/tool permissions отдельно от текста памяти |
| 11 | Сохранение без лишней формы | Capture до классификации; неизвестный смысл допустим |
| 12 | Связность и продолжение | Эпизоды, решения, попытки и адресные связи, не только отдельные chunks |
| 13 | Отбор пригодного после поиска | Один compiler учитывает состояние и применимость; similarity не доказательство |
| 14 | Постепенное раскрытие | Короткий packet и handles с источником и текущей областью |
| 15 | Контекст под решение | Цель, критерии, ограничения, unknowns и следующий шаг на реальной границе модели |
| 16 | Понимание проекта | Карта назначения, подсистем и ресурсов, не только vector index |
| 17 | Холодный старт и обновление | Доступные anchors и non-Git scope; без выдуманной ревизии |
| 18 | Структура и поведение | Static dependency, co-change и causal hypothesis различаются |
| 19 | Предсказание и калибровка | Ожидаемое наблюдение до действия, затем сопоставление с исходом |
| 20 | Негативная память до действия | Своевременный совет; конкретное принуждение отдельно в host |
| 21 | Связь действия с исходом | Версия метода, попытка, фактическое действие и критерий; cue overlap не использование |
| 22 | Честное завершение | Реальные критерии и gaps; один exit 0 не закрывает всю задачу |
| 23 | Dreamer предлагает преобразования | Реальное finite model job и обычное применение результата, не произвольный SQL |
| 24 | Разные виды забывания | Exposure, withdrawal, revision, erasure отдельно; restore учитывает известные удаления |
| 25 | Процедурное обучение | Preconditions, метод, примеры, исключения и следующий consumer |
| 26 | Метаобучение и перенос | Тот же job/attempt путь; опыт улучшения помогает следующему улучшению |
| 27 | Наблюдаемость | Связный trace и views; квитанция не заменяет действия |
| 28 | Восстановление | Stable identity, минимальный spool, claim и external readback |
| 29 | Власть человека | Явные goal/config/control; score не создаёт новых прав |
| 30 | Малый интерфейс агента | Несколько операций; служебные сведения собирает adapter |
| 31 | Проверка реальных отказов | Различающие сквозные ситуации, не сертификат по форме |
| 32 | Лёгкий инструментальный Governor | Demand-start, один memory writer и нужное независимое наблюдение |
| 33 | Заменяемость хранения | Private Store, native DB, export; не универсальный KV с компенсациями |
| 34 | Улучшение не удостоверяет себя | Provisional use отдельно от доказанного выигрыша на будущих случаях |

Поздняя [UL Part C](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md#L1433-L1468) отменяет ручное approval детерминированных UL-артефактов. Полезная автономность не должна исчезать из-за требования полного эксперимента до каждой подсказки. При этом записанный кандидат не превращается автоматически в установленный факт или новое разрешение.

## 4. Что точно не переносить, что извлечь из V2

### 4.1 Капсулы и поддерживаемость по наличию форм

[I2.20](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/architecture/I02-20-module-contract-kit-crate-context-capsule-and-module-test-capsule.md) прямо допускает cell не как crate; обвинять его в обязательном crate на понятие неточно. Реальная избыточность — обязательные `ModuleContractKit + CrateContextCapsule + ModuleTestCapsule`, contract digest, proof ceiling, replacement boundary и срок квалификации независимо от полезности готового кода.

Берём ясную ответственность, интерфейс и реальный consumer. Не переносим отдельный продукт, удостоверяющий, что другой продукт разрешено считать поддерживаемым. `AUDIT-MAP` не является новой капсулой.

### 4.2 Уведомление с общей admission-церемонией

В [notification_plan_admission.rs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliotd/src/notification_plan_admission.rs#L1-L380) ради NotificationState строится CanonicalWriteEnvelope, вычисляются plan/admission/request digests, повторно читается тот же generated catalogue, затем вновь проверяется hash. Комментарий уточняет: clock/deadline меняют identity, а настоящие repeat guards опираются на БД и ключ проблемы, не этот digest.

[request_hash.rs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/storage/eliot-store-api/src/request_hash.rs#L1-L175) показывает общий конверт scope/task/manifests/security/proof/head. Это не криптографическая подпись и не независимая проверка смысла. V3 использует keyed problem state, условный update и фактическую доставку; подробные найденные control-разрывы — §22.

### 4.3 Полезный normalizer внутри ненужной обвязки

[Новый cue normalizer](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/smart/eliot-cue-normalizer/src/normalize.rs#L1-L510) даёт полезные правила: одна функция для capture/query, исходное написание отдельно от сравнения, case folding только по определённой семантике, неподдерживаемая форма не означает равенства. Не нужен NormalizationEnvelope с policy/fence/input/result digests вокруг обычной функции в процессе.

Некоторые absolute/drive/UNC формы объявлены Unsupported в выбранном helper, но original value сохраняется. Нельзя из этого вывести потерю raw capture или запретить все реальные абсолютные host paths в V3. Adapter разрешает путь относительно настоящего base; поисковые aliases не становятся exact identity. Старый consumer продолжает пользоваться другим алгоритмом — §22.6.

### 4.4 Донорские части по полезной обязанности

| Семейство | Не импортировать | Что действительно извлечь |
|---|---|---|
| Host/Kernel | Hot replacement, generations, registry/epoch choreography | Ownership процесса, planned exit, ограниченный restart |
| ORS/redb | Вторую семантическую БД и общий recovery engine | Unknown acknowledgement, durable intake, external readback |
| Storage bridge | Отдельный процесс и named-operation language | Parameterized queries, conditional writes, native DB |
| Contract/capsule tooling | Certificates/read receipts/manifest matrices | Понятный контракт и конкретные edge cases |
| Dreamer families | Сервис/пакет на каждую мыслительную операцию | Extract/reconcile, dissent, процедуры, source changes |
| Notification | Универсальную digest/admission систему | Dedup проблемы, ack отдельно от resolution |
| Cues | Криптографическое замыкание pure transformations | Lossless source и одинаковое сравнение при записи/чтении |
| Agent fabric | Второй swarm/provider scheduler в памяти | Реальные host events и ссылки на task/attempt |

Это решения для V3, не удаления V2 без проверки. У 79 ORS tables разные обязанности; нельзя объявить их эквивалентом одной очереди. Снятие ненужных владельцев делает ненужной часть таблиц, а не наоборот.

## 5. Исправления Claude и собственных ранних утверждений

| Утверждение/схема | Корректная граница |
|---|---|
| BM25 был только в V1 | В V2 есть вызываемый FTS path и `search::score`; live качество отдельно не измерялось |
| Весь Dreamer всегда отказывает | Подтверждён normal resolver; curation имеет отдельный путь |
| 15 бинарных пакетов = 15 постоянных процессов | Manifest count не измеряет поставку |
| Таблица anchors закрыла функциональность | Проектное соответствие не working runtime |
| `DEFINE EVENT` реализует всю надёжность очереди | Атомарное enqueue не заменяет retry/cancel/unknown handling |
| `influence != none` достаточно | Quarantine/handle-only требуют реального правила выдачи |
| Одинаковая размерность = совместимые vectors | Важны encoder, preprocessing и content revision |
| Одна сохранившаяся ссылка оправдывает весь вывод | Не различены обязательные premises и альтернативные derivations |
| После N шагов каскада остальные записи валидны | Непросмотренный остаток не становится проверенным |
| Exit 0 означает всю задачу | Только реально покрытый критерий |
| Запрет слов Receipt/Lease/Fence решает сложность | Избыточность определяется функцией и владельцем, не названием |
| 50× сокращение доказано | Не измерено на сопоставимом продукте |

Ранее подтверждённые первичные ссылки: [FTS caller](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/canonical_store.rs#L2513-L2555), [SQL](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/surql/load_memory_search_fts_candidates.surql), [Dreamer resolver](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/controller.rs#L64-L84), [caller](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/lib.rs#L792-L806).

Собственные ошибки ранней V3: universal freshness выключала исторический опыт; ModelJob одновременно требовал Task и запрещал fake Task; backup обещал неопределённый короткий snapshot; описание одного направления controller выдавалось за доказательство отсутствия другого; подготовленная редакция оставалась локально. Эти ошибки исправляются в действующих договорах. Старые обещания не становятся истинными от добавления ещё одного отчёта.

## 6. Hy-Memory: что взять, где ограничить вывод

Hy уже позволяет выбрать model/совместимый endpoint: [config](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/config.py#L132-L214), [provider](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/agent/llm_provider.py#L309-L440). Поэтому свобода выбора не является только преимуществом Eliot. Writer weights, приложение и training evaluation — разные артефакты. [Статья](https://arxiv.org/html/2610.22196v1) не гарантирует произвольной модели результат специализированного writer.

Берём раздельные эпизоды и переносимый опыт, extraction отдельно от reconciliation, ограниченных кандидатов, реальную историю edits и законный результат no-proposal. Не берём отдельный store/service на каждый уровень, вечного агента для каждой операции и обязательный урок из каждого пакета.

[coding/writer.py](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/writer.py#L65-L205) пишет trace в `finally` после попытки extraction, а ошибку сохранения логирует. Chat raw-first не доказывает raw-first всех сценариев. Eliot сначала подтверждает capture, затем интерпретирует; prompt truncation не является политикой уничтожения оригинала.

[_crosslink](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/writer.py#L236-L280) связывает каждый experience со всеми fact IDs партии. Это соседство, не доказанная premise каждой мысли. Достаточно episode/batch ID для соседства и адресных evidence/live links для обоснования. Ограничения раскрытия результата определяются фактически переданными модели данными, не её заявлением «этот приватный кусок не использован».

В прежних выбранных [chat parser](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/agent/reconciler.py#L1900-L1930) и [coding UPDATE](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/reconciler.py#L450-L474) форма ID не всегда сопровождалась фактической проверкой candidate membership. Это source-level риск, не сообщение о live атаке. V3 адресует свои сохранённые targets обычным lookup, а не доверяет произвольному ID из prose.

## 7. SurrealDB: использовать готовые возможности

Одна primary БД обеспечивает текстовый и векторный поиск, связи и транзакции. Small scoped exact vector search — нормальная реализация векторов; ANN выбирается по реальной цене. Частный Store не требует универсального KV, AST или нового query language.

Официальный [Rust query API](https://surrealdb.com/docs/reference/rust/methods/query) различает transport success и ошибки statements; несвязанный параметр становится `NONE`. Нужны обязательные bindings, проверка ошибок и ожидаемого количества изменённых строк возле конкретного запроса. Не нужна отдельная платформа доказательств SQL.

Семантические ревизии — обычные records; logical export не сохраняет историю уже перезаписанного значения автоматически. Import проверяет фактическое содержимое и при необходимости достраивает derived indexes/jobs, не предполагая повтор всех исторических events. [Backup reference](https://surrealdb.com/docs/manage/self-hosted/backups-and-recovery).

[Similarity search](https://surrealdb.com/docs/learn/data-models/vector-search/similarity-search) и EXPLAIN описывают filtered plans и index-assisted prefiltering. Сначала проверяется выбранный запрос/сервер, затем добавляется fallback. Ограничение Python-донора не является автоматически ограничением SurrealDB. При этом даже правильная ANN-фильтрация не доказывает полноту знания.

D41 SurrealDB Agent Memory/Spectron — отдельный application tier, не встроенный бесплатный интеллект БД. Старый [no-SDK ADR](../ADR/0001-phase-a-dependency-boundaries.md) описывал тогдашнюю зависимость/релизную проблему, не вечное вето V3. Первичный выбор — официальный сетевой SDK с нужными features; другой клиент требует конкретной причины, а не церемонии отмены донора.

## 8. Controller и host: реальные границы, а не одинаковые слова

Прежний [integration document](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/96a0d5a6632cfbd541e804d7969d3e76e716bf6a/docs/eliot-memory-os-integration.md) обсуждал запрос контекста **из controller в память**, не готовый reverse API для inference. Отрицательный поиск по нескольким ключам не доказывает отсутствия всех методов. Выбираются реальные доступные text/embedding routes; описанные здесь имена не объявляются существующими RPC.

Memory владеет преобразованием и применением; controller — внешним исполнением/provider retries. Local claim, external request и applied memory mutation реально различаются, но не требуют трёх lifecycle engines. После падения worker сначала читается прежнее execution reference, а не покупается повторный inference. Accepted input не равно output; best-effort cancel не доказывает остановку или нулевую стоимость.

Maintenance не требует фиктивной coding Goal. Настоящая ограниченная synthesis Task допустима при таком executor contract. Ни обязательный fake Task на embedding, ни словесный запрет всех Task не нужны.

Официальные [Claude hooks](https://code.claude.com/docs/en/hooks#add-context-for-claude) отличают время hook от следующего model request. PreToolUse не означает, что совет прочитан до уже выбранного tool call. Advisory попадает на реальную границу решения; точное host enforcement отдельно, не искусственная блокировка каждого инструмента. Native hooks и SDK bridge с похожими fields не доказывают одинаковое поведение.

Старый текст может остаться в transcript. Новая context incarnation и изменённый совет допускают обновлённую выдачу; локальное withdrawal не отзывает уже переданные remote bytes.

## 9. Самообучение без самоудостоверения

Урок — ordinary memory revision, попытка — outcome с нужными ссылками, aggregate — view. Полезный условный совет можно использовать автоматически. Применимость и эмпирическая эффективность — разные вопросы; эксперимент перед каждой подсказкой остановил бы обучение.

Доставка, наблюдаемое действие, adherence, outcome и comparative benefit различаются. Вклад одного method/attempt/criterion учитывается один раз; replay, steps одного эпизода и summary-paraphrases не независимые случаи. Исправленный outcome заменяет прежний вклад с историей. Induction evidence объясняет происхождение правила, но не пользу правила до его существования.

В выбранном [MemOS L2](https://github.com/MemTensor/MemOS/blob/a7367d07e55db61099f7b4e2c1108bc5831a24f3/apps/memos-local-plugin/core/memory/l2/l2.ts#L371-L445) with-set включает associations/induction evidence. [Gain formula](https://github.com/MemTensor/MemOS/blob/a7367d07e55db61099f7b4e2c1108bc5831a24f3/apps/memos-local-plugin/core/memory/l2/gain.ts#L62-L133) при одинаковых наблюдаемых means 0,8, пяти without-cases и prior 0,5 веса пять даёт baseline 0,65, gain +0,15. Это арифметический контрпример causal-интерпретации, не запуск MemOS. Prior может ранжировать гипотезы, но не создавать отсутствующее сравнение.

Отсутствующая ошибка не pass, когда verifier не дошёл до target, смотрел другую ревизию или вернул неполный лог. Несвязанный network failure не опровергает каждый совет; успех одного критерия не скрывает остальные failures. Для широких утверждений нужны последующие сопоставимые случаи. Shadow фиксирует selection, не изменённое поведение. Недостаток статистики оставляет условное знание, а не запрещает чтение.

## 10. Надёжность без второй операционной системы

Historical evidence, live applicability и disclosure различаются без отдельного truth/policy engine. Локальный профиль задаёт проекты, capture/retention и разрешённые routes. Unknown applicability допускает условный совет; известная приватность учитывается на фактической передаче данных. Полный рекурсивный corpus walk не требуется каждому recall.

Stable ID, transaction, current claim и external readback устраняют конкретные ошибки. Signed learning proposals, per-helper policy digest, principal/grant graph и proof-of-reading — не нужны. Hash идентифицирует bytes/cache/backup, но не создаёт полномочий или понимания.

Spool подтверждает доставку исходного события, не его semantic truth. Простой backup имеет quiesced export, blobs и конечный cutoff staged input; новое событие принадлежит новому batch. Export-length pause честнее неопределённого «мгновенного snapshot». Нельзя ждать worker, удерживая нужный ему lock.

В 0.8 исправлен собственный избыточный запрет: выбранная владельцем копия может быть восстановлена при утрате части deletion history, с применением известных удалений и обозначением неизвестных. Primary data доступны до embeddings/maps. Отдельный selective-import продукт для обхода blanket запрета не нужен. Старые внешние jobs автоматически не запускаются: восстановление данных не равно повторению effects.

Один фактический supervisor наблюдает failure domain; при подходящем существующем host/controller второй не строится. Иначе малый demand-start режим того же бинаря владеет daemon+DB. Job Objects помогают custody, не изолируют от любого процесса того же OS user. Notification ack не resolution, heartbeat не progress, exit code не whole-task acceptance.

## 11. Доноры и аудиты: карта, не программа обязательных переносов

### 11.1 Что означает историческая инвентаризация

Сохраняется прежний учёт: 43 D-поверхности, 27 P-работ и 187 S-записей — 257 строк, не 257 гарантированно независимых источников. Draft/completed в реестре не означает прочитанную работу или reproduced experiment. Старый archive incomplete не возобновляется как issue factory V3.

Полный ZIP не перечитан в 0.10. Прежние сведения о нём опираются на соответствующие проходы и приложение Claude. Текущий реестр показывает направления переноса; свежие reads отмечаются в карте. Конкретная библиотека выбирается по consumer и цене, а не потому, что имя занесено в таблицу.

### 11.2 D01–D44

Строка — кандидатный механизм, не квалификация всех версий/лицензий. При реальном копировании кода проверяются конкретные условия. Старая нумерация сохранена.

| D | Донор | Полезный механизм и граница переноса |
|---|---|---|
| 01 | MemMachine | Derivative → исходный эпизод → нужные соседи в той же области |
| 02 | MemPalace | Event identity, одинаковые timestamps и повторные экспорты; не last duplicate wins |
| 03 | Subcog | Facets/RRF без read-side semantic mutation |
| 04 | MemOS local plugin | Retrieval по ситуации; gain не объявлять causal proof |
| 05 | Claude Code memory/tool search | Малый начальный индекс и раскрытие вместо вечного дампа |
| 06 | ClawVM | Сохранение необходимых смысловых единиц при сжатии |
| 07 | Pichay / demand paging | Цена повторного чтения; не строить paging OS заранее |
| 08 | Graphiti | Время действия, знания и отзыва отдельно; managed Zep не тот же артефакт |
| 09 | Hindsight | Проверка опор перед публикацией и пересмотр при их изменении |
| 10 | EverOS | Reconciliation пропущенных событий; replacement прежде retirement |
| 11 | EverMemOS historical | Episode/atomic facts/foresight; различать historical/current stacks |
| 12 | Cloudflare managed Agent Memory | Raw рядом с extracted; service не бесплатная library |
| 13 | Cloudflare Agents SDK Sessions | Immutable turns, branch-local compaction |
| 14 | SurrealFS | Source/indexer/content/profile revisions; не сама SurrealDB |
| 15 | MentisDB | Versioned procedures и source-linked reveal; проверить lifecycle |
| 16 | LangMem | Отдельный background submit/search, сохранение всех inputs при debounce, scoped prompt proposal и реальный no-change; §§23–24 |
| 17 | Letta Code current | Candidate/cancel и защита от позднего результата |
| 18 | Letta V1 archive | История по требованию и цена truncation; не current Code |
| 19 | Nocturne Memory | Stable node, revision, alias; review до разрушения источника |
| 20 | Mem0 OSS | Batch extraction/embeddings; отличать ошибку от пустого результата |
| 21 | OpenMemory historical MCP | Membership/access ideas с оговоркой о historical продукте |
| 22 | OpenMemory session CLI | Перенос сессий; roadmap не выполненный runtime |
| 23 | Cavira LongMemory | Узкие decay/supersedes/checkpoint, не смешивать с mem0 OpenMemory |
| 24 | ripgrep | Exact spans/offsets и простой первый source tool |
| 25 | ast-grep | Синтаксические patterns/координаты, не runtime proof |
| 26 | SCIP | Definitions/references с encoding и producer/source revision |
| 27 | GitHub Copilot Memory | Перепроверка citation; описание не открытый runtime |
| 28 | Docling | Parser реальной ingestion-задачи и page/element provenance |
| 29 | Docling Core | Document hierarchy и chunk metadata выбранного parser |
| 30 | DocETL | Raw/error/partial и retries, не новый general research engine |
| 31 | Vector / VRL | Сохранить событие при transform error; DSL только при необходимости |
| 32 | Kreuzberg v4 LTS | Native extraction/source mapping, точная версия и лицензия |
| 33 | Kreuzberg current | Не наследовать свойства другой версии по имени |
| 34 | Cedar | Policy backend только при оправданной сложности, не baseline V3 |
| 35 | OPA | Undefined/error/result; не второй policy owner |
| 36 | redb | Исторический durable spool; baseline V3 не требует второй БД |
| 37 | duroxide | Idempotent activity identity, не целый workflow runtime |
| 38 | Flawless | Unknown external outcome и retry/replay safety |
| 39 | FoundationDB testing | Будущие управляемые отказы, не тестовая платформа сейчас |
| 40 | Wasmtime | Изоляция реального недоверенного расширения при оправданной цене |
| 41 | SurrealDB Agent Memory / Spectron | Source-linked retrieval/scope; отдельный application tier |
| 42 | MAGMA | Ограниченные typed graph walks с фактическими фильтрами |
| 43 | A-MEM | Предложения evolution заметок, не model-authorized overwrite |
| 44 | Google Research Harness2 | Два цикла улучшения и раскрываемые реальные материалы; §§19,25. Не импортировать benchmark engine или считать cache новым экспериментом |

Hy-Memory отдельно углублён в §§6,16–18. Не нужно импортировать всех доноров, чтобы сохранить перечисленные свойства.

### 11.3 Исследование должно завершаться решением о продукте

MemGPT/HiAgent помогают понять подцели и раскрытие; LongMemEval/MemoryArena/Mem2Act — различить remembered/retrieved/action; LightMem/MemDelta — цену консолидации; ATMS — альтернативные опоры без обязательного комбинаторного движка; Meta-Harness/Harness2 — улучшение метода работы. Чужие benchmark scores не цели Eliot.

Достаточно указать пробел, конкретный mechanism/source, полезный consumer, ограничения и решение взять/не брать. Нет обязательного отдельного файла с 13 разделами каждой идее. Mature library не должна проходить больше церемоний, чем написанный с нуля аналог худшего качества.

## 12. All 29 original scenarios

Источник — [V2 A15](../architecture/A15-end-to-end-scenarios.md). Сохраняется смысл пользовательской ситуации, не физическая топология донора.

| A15 | Ситуация | Решение V3 |
|---|---|---|
| 1 | Новая область без Git | Реальные anchors и provisional scope, без выдуманного commit |
| 2 | Агент не знает, что искать | Orientation, полезный advisory и handles на границе решения |
| 3 | Плохо типизированное наблюдение | Сначала сохранить permitted raw |
| 4 | Ложное слияние/процедура | История и dissent сохраняются; производное влияние пересматривается |
| 5 | Изменение workspace без отчёта | Доступные независимые сигналы, gap и целевой resync |
| 6 | Разные объяснения | Источники и различающий следующий шаг, не голосование |
| 7 | Большой swarm audit | Уникальный охват/partial/gaps в памяти, рой в controller |
| 8 | Повтор известного провала | Своевременный applicable совет; точный host gate отдельно |
| 9 | Ложный guard | Challenge и сужение неверной части |
| 10 | Позднее poisoning | Отзыв реальных зависимостей и обоснованная новая ревизия |
| 11 | Injection из tool/model/document | Данные не полномочия; обычное применение по реальным targets |
| 12 | Отказ optional модуля | Незатронутые пути продолжаются; изоляция по реальной цене отказа |
| 13 | Governor падает | Без воспроизведения Kernel: внешний observer и pending/unknown recovery |
| 14 | Давление очереди/диска | Явный staged/rejected, доступный control и ограниченная работа |
| 15 | Repair не помогает | Остановить повтор того же ремонта и сохранить проблему |
| 16 | Compaction/restart | Новая incarnation, цель, обязательства, ошибки; discarded plan не оживает |
| 17 | Смена model/harness | Проверить нужные capabilities/applicability; история остаётся |
| 18 | Verifier отсутствует | Непроверенный критерий unknown, не успех |
| 19 | Пропущенное уведомление | Attention сохраняется; acknowledgement не resolution |
| 20 | Найден executable | Metadata не разрешение запуска; использовать реальный host tool путь |
| 21 | Privacy deletion | Withdrawal, purge controlled copies и внешние ограничения различаются |
| 22 | Старый backup | Известные удаления применяются; owner может восстановить выбранное при обозначенном пробеле history |
| 23 | Прерванная migration | Restart-based upgrade и явный результат, не весь live-generation stack |
| 24 | Код против Architecture | Grounded discrepancy и явная правка нужной стороны |
| 25 | Экспериментальный модуль | Подходящая ограниченная проверка, не arbitrary hot replacement |
| 26 | Рой пишет модули | Один manager/worktree и writer/область; процесс разработки не Memory OS |
| 27 | Локальный PASS, продукт FAIL | Не заявлять whole-product success; сохранить исход |
| 28 | Не хватает окна | Progressive reveal/decomposition, не молчаливое удаление исключений |
| 29 | Meta candidate пережил смену стека | Проверить применимость; старый score не новое доказательство |

Implementation S1–S32 и прежние 36 Cognition walkthroughs остаются в своих документах. Они не являются заявлением о выполненных продуктовых тестах.

## 13. Разработка и публикация без параллельной системы истины

Единица работы завершает полезный переход либо устраняет названный отказ. Не сначала все DTO, потом все handlers, затем proof registry и когда-нибудь реальный consumer. Один manager — один изменяемый worktree; read-only review не требует размножать рабочие копии.

Публикация означает GitHub commit/ref и фактическое чтение результата. Локальный ZIP не равен коммиту. Старый разрыв поставки 0.5 устранён в 0.6; нельзя сохранять его как нынешний blocker. Отсутствие локальных Git credentials не отменяет работающий GitHub API.

Исторические CI-дефекты: фиксированный каталог 11 V2 issues применялся к #5324; в одном Windows run reading receipt зависел от LF/CRLF. [Каталог](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/.github/work-unit-cohort.toml), [gate](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/scripts/work_unit_gate/doc_read_evidence.py#L1592-L1659), [run](https://github.com/UnknownAlienHuman/eliot-memory-os/actions/runs/39176892004). Это не универсальный диагноз каждого нового CI failure.

Не подставлять чужую issue, не выдумывать независимого reviewer, не повторять старый PASS для новых bytes. Изменения CI требуют отдельного явного решения; этот проход их не меняет. Branch commit не равен main merge. Подготовка документации не закрывает все старые active programmes и не мигрирует `workstreams/ACTIVE.toml`.

## 14. Минимальная рабочая конструкция

`capture` сохраняет observation и нужное намерение обработки; `store` использует native DB; `context` находит и отбирает полезный материал; Dreamer интерпретирует подходящий эпизод; `learning` связывает методы с последующими исходами; controller выполняет внешние действия. Наблюдение — реальный progress/result, не наличие сертификата.

Один app writer не устраняет concurrency: поздний worker и потерянный ответ всё ещё возможны. Но matching claim, ожидаемая revision и stable request ID не требуют Authority Epoch/PreparedTransition framework. Advisory не обязан быть уже доказанным универсальным методом, а читать память не значит исполнять записанную команду.

Когнитивная глубина — реконструкция, различение, условия, аналогия и пересмотр. Число процессов, рёбер, классов и повторных reflection не её мера.

## 15. Что пока не доказано

Нет полного построчного аудита миллионов строк, нового прочтения всего release ZIP/187 papers/всех donors, выполненного V3, Windows custody/restore, SurrealDB query/benchmark, controller inference или сравнительного LOC/RAM/latency. Каждый source finding имеет свою область; прежние synthetic probes — не новая live qualification.

O1–O6 в Implementation — точный host, controller routes, filesystem durability, Store schema/client, criterion и observer. Это не шесть платформ и не разрешение блокировать все полезные функции, пока не доказана каждая. Карта фиксирует оставшиеся связанные чтения, без фиктивного общего процента готовности.

## 16. Cognitive audit 0.3

Исторический результат: 0.2 подробнее описывала recovery, чем само понимание. Cognition определила вычисления внутри прежних modules: scoped current-value resolution, intended/observed/proposed, групповой lookup альтернатив вне top-k, карты с membership, finite refresh, three-valued applicability и criterion-specific outcomes.

[V1 §4.12](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Canonical_Master.md#412-deterministic-current-value-resolution) даёт смысл resolver, [UL mission](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md#L14-L120) — cues/реконструкцию/dirty tracking. Их старые DTO и тезис injection=usage не импортируются вместе с идеей.

Контрпример maps: три cited consumers неизменны, но появился четвёртый. Положительные ссылки не доказывают полный набор. View сохраняет examined scope/selection basis, а изменение membership делает dirty именно его. Не нужен query AST или полный rebuild после любого edit.

У необязательного Hy [canonical-state helper](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/system2_agent.py#L72-L346), выключенного по умолчанию, изолированный перенос принимал чужую цитату и пример `I use glasses` за личное использование. Это не production failure всего Hy. Вывод: роль user не исключает цитаты; general understanding не строится расширяющимся каталогом бытовых regex.

[DCPM](https://arxiv.org/html/2606.09483v1) полезна revision trajectories и offline abstraction, но её квадратичный межобластный sweep и chat benchmark не гарантируют engineering transfer. Два предшествующих chunks в [Hy §5.3](https://arxiv.org/html/2610.22196v1) относятся к reward annotation, не каждому production writer. [LongMemEval](https://arxiv.org/html/2410.10813v2) различает update/temporal/abstention; это failure categories, не обязательная онтология продукта.

## 17. Memory transition audit 0.4

Источники — Hy [fact_reconciler.py](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/fact_reconciler.py) и [store.py](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/store.py). Подробные координаты и исходные пробы сохранены в [историческом §17](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c28359fc2716f3b498ea512ca24a57801d18014c/docs/v3/AUDIT.md#17-memory-transition-audit-04).

| Находка | Малое решение |
|---|---|
| `_execute` снимает predecessor до history/model work и нового insert; отдельный autocommit | Подготовить вне transaction, затем атомарно revision+links+retirement+result |
| WorkingFact — whole trace/session, не atomic claim | Продолжение задачи обновляет progress, а не отменяет все прежние exceptions |
| Subject gate optional/default false | Не считать prompt безусловной runtime-гарантией всех режимов |
| После A→B удаление B может ошибочно вернуть A | Retired value не воскресает без нового основания или явного исправления replacement |
| Допустимо несколько родителей, ancestor query выбирает `LIMIT 1` | Frontier/visited и явная неполнота, не превращать graph в chain сортировкой |
| Lexical rerank только внутри dense pool | Independent exact/lexical candidates; векторный сбой не пустая память |
| Exact details хранятся вне searchable fields выбранного пути | Source-derived cues и адресный поиск/раскрытие |
| Нет diagnostic, потому что verifier не дошёл | Coverage/completeness критерия, не автоматический pass |

Прежняя SQLite-проба retirement-before-insert оставляла старую superseded и отсутствующую новую запись. Проба A/B→C→D возвращала A,C без B и без исчерпания depth. Это воспроизведение выбранных SQL-переходов в изоляции, не запуск Hy/SurrealDB или измерение recall. Простой finite traversal сохраняет нужную историю без provenance engine.

## 18. Cross-domain learning audit 0.5

Исторически подготовленный материал 0.5 опубликован в 0.6. Полный первоначальный отчёт с isolated controls — [§18 редакции 0.9](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/0a71fd7d1b784486ef38f66b11cdd15cc8f8f81e/docs/v3/AUDIT.md#18-cross-domain-learning-audit-05). Ни одна из этих проб не перезапускалась в 0.10.

Основные sources: [cross_domain_sweeper.py](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/cross_domain_sweeper.py) и [optional compaction](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/system2_tools.py#L84-L209).

**Existing core:** `_process_cluster` берёт первый ID множества старых targets, добавляет связи новым members без нового semantic matching/evidence read и пересмотра core text. Сортировка IDs делает выбор воспроизводимым, не осмысленным. Изолированная fake-graph проба A/core-A, B/core-B добавляла B→core-A без модели. V3 оставляет alternatives; сходство допускает navigation analogy, не подтверждённую premise.

**Нетранзитивность:** union-find объединяет подходящие пары. Synthetic angles 0°,40°,80° дают cosine соседей ≈0,766, крайних ≈0,174; порог0,70 всё равно создаёт одну компоненту. Кластер — конечный набор для рассмотрения, не доказанное общее правило. Можно использовать подмножество или вернуть no-change; полный clique-proof не нужен.

**Ложный предел:** `sweep` начинает с500 nodes, а `_fetch_basics_with_beh` перечитывает все подходящие без первоначальной membership. Для отсутствующего в первом `basic_map` источника prompt получает ID вместо текста. Две условные float32 матрицы10000×10000 требуют800000000bytes только под их entries; это арифметика, не измеренный OOM. V3 удерживает один finite input набор на job, ограничивает реально рассматриваемые пары и продолжает следующий участок без бесконечной обработки первого окна.

**No-change и feature:** null branch сам не сохраняет reuse решения; повторный прямой вызов в пробе снова вызвал модель. `_has_beh` не удостоверяет текущий abstractor/encoder. V3 применяет уже существующие job input/method identities и completed no-change; меняется derived representation, не обязательно все original embeddings. Отдельное behavioral space — опция по полезным пропускам, не обязательная цена каждого observation.

**Compaction:** shared evidence/raw-source и высокий cosine могут снять второй текст без сохранения особых условий. Опция default false. Synthetic identical vectors для правил retry read-only и не повторять unknown side effect разрешили merge в выбранной функции. Это контрпример достаточности условия, не поведение реального encoder. Общий источник содержит разные правила/контрпримеры; сохраняются условия, не только IDs источников.

Все исправления используют ordinary revisions, finite jobs, indexed candidate retrieval, адресные source links и existing transaction. Нет ConceptualStore, merge daemon или отдельного планировщика «самоэволюции».

## 19. Harness2: рекурсия для Eliot, не новый агентный runtime

D44 прочитан на `1cfe254e...`; механизмы и исходный source map остаются в [историческом §19](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/0a71fd7d1b784486ef38f66b11cdd15cc8f8f81e/docs/v3/AUDIT.md#19-harness2-рекурсия-для-eliot-не-новый-агентный-runtime). Текущая дополнительная проверка — §25.6.

### 19.1 Два объекта обучения

Task-local **Propose–Probe–Compose** меняет способ выполнения конкретной задачи по execution contrasts. Cross-task reflection сохраняет, как диагностировать и улучшать метод, для следующего improvement cycle. Это не просто библиотека финальных ответов. Improvement recipe фиксирован внутри сравнения; следующий task не наследует весь прошлый специфический harness. Веса моделей не меняются.

### 19.2 Где механизм реализован

| Source | Роль |
|---|---|
| [recursion.py](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/recursion.py) | General/domain proposals, execution probes, compose, parallel/sequential |
| [selection.py](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/selection.py) | Выбор deliverable и отдельная reflection cue/lesson/evidence |
| [library.py](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/library.py) | Выбранный harness, EXPERIENCE.md и индекс для будущего обращения |
| [ledger.py](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/ledger.py) | Rollout/improvement labels и attempts/cached, не один recursion=один call |
| [schedule.py](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/schedule.py#L390-L560) | Реальный caller библиотеки, recursion, selection и reflection |
| [EXPERIMENTS.md](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/docs/EXPERIMENTS.md) | Экспериментальные режимы, пределы воспроизведения и отдельное judging |

Parallel k — ширина, не бесконечная рекурсивная глубина. Sequential получает composed tree следующей итерации, который не обязательно объективно лучше. Shape validation изменений не semantic proof.

### 19.3 Что нельзя механически переносить

Final selection pool исключает reference outputs; k=1 выбирает единственный final без нового model judge. Compose может сохранить input tree — поэтому это не обязательная мутация. Однако V3 должен явно иметь baseline/no-change среди допустимых adoption результатов, не считать любой final улучшением.

R=4k включает kbase+2kprobes+kfinals; P=3k — два типа proposal и compose. Selection/reflection и attempts считаются отдельно, cache меняет новую фактическую стоимость. Один rollout может содержать много API/tool calls. Такой benchmark workload не назначается каждому эпизоду памяти.

Reflection field presence не доказывает grounding/causal benefit. Нового полезного experience может не быть. Network/public grading information в benchmark setup ограничивает интерпретацию результатов; руководство сообщает о validation rollout, скачавшем rubric. Это не доказательство загрязнения всех результатов. Eliot не копирует unrestricted benchmark executor ради обычного extraction.

### 19.4 Применение в V3

Обычная method revision, ограниченный job и controller исполняют task-local proposal/probe/compose. Ordinary lesson хранит cue, attempted change, observed contrast, conditions и когда полезно повторить способ улучшения. Будущий Dreamer извлекает подходящий урок. Не требуется ReflectionStore, отдельная library DB, рекурсивный swarm или новый runtime.

Cheap repeatable сравнение полезно; повтор irreversible effects ради эксперимента не становится допустимым автоматически. При недостатке данных можно оставить conditional suggestion/no-change. Подробная реализация — [Cognition §6.7](COGNITION.md#67-two-recursive-loops-from-harness2).

## 20. Где проектировщик сам вернул бюрократию и что изменено

| Собственный перегиб | Исправление |
|---|---|
| Old no-SDK ADR стал обязательным veto | Official network SDK сначала; проверяется конкретная новая проблема |
| Wider reuse требовал независимого эксперимента каждый раз | Automatic provisional transfer отдельно от широкого effectiveness claim |
| Operation family грозила стать вторым generic ledger | Mutation readback рядом с owning record/job; отдельная запись только при реальной нужде |
| Свой supervisor независимо от существующего покрытия | Один настоящий owner; reuse или небольшой standalone observer |
| Enterprise owner/principal vocabulary | Local projects/routes/retention, не grant graph |
| Provenance превращалась во whole-corpus walk | Проверка релевантных выбранных зависимостей и affected views |
| Fingerprint language провоцировал per-helper hashing | Hash только для настоящих bytes/cache/backup |
| «Сначала qualify всё» блокировало независимую пользу | Проверять фактическую capability перед заявлением её готовности |
| Restore ждал недоступной полной deletion history | Owner-selected recovery с известными ограничениями, отдельно от replay effects |
| Наблюдаемость требовала разрешения показать результат | Основная польза отдельно от optional logging и diagnostic writes |

Не заменяем один аппарат другим: запрет терминов, approval helpers, 13 разделов каждой идеи и произвольный LOC ceiling заставят лишь переименовать старые формы. Проверяем назначение, state owner, реальную ошибку, consumer и наличие готовой библиотеки. История audits остаётся в Git; повтор каждого старого статуса в новом документе не делает решение качественнее.

## 21. Порядок следующей работы

Карта A01–A14 хранит прочитанные места и следующий связанный путь, не signatures/permissions/workflow. Главный критерий: если запись полезна, кто её создаёт, кто действительно читает и что меняется в следующем действии? Дополнительная проверка не должна сама становиться предпосылкой существования данных.

После source-level выводов о notification/cue/context основной фокус перемещён на experience producer, нормальный packet consumer, skill paths и поведение донора Harness2 на реальных inputs. Не нужно каждый проход начинать с уже разобранного определения normalizer или увеличивать число diagnostic crates.

## 22. Connected control and context audit 0.7

Полный прежний отчёт с диапазонами и counterchecks: [§22 редакции0.9](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/0a71fd7d1b784486ef38f66b11cdd15cc8f8f81e/docs/v3/AUDIT.md#22-connected-control-and-context-audit-07).

### 22.1 Безусловный отказ control

Названные broker acknowledge/cancel/reconcile dispatch-ветви вызывают общий gate, который после actor/session checks неизбежно возвращает `HumanApprovalActionDigestUnverifiable`; у него нет требуемого digest. [broker lib](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-user-broker/src/lib.rs#L2380-L2520). Это не «все API всего продукта отключены», а проверенный no-success path.

Ниже [launch_notify_acknowledge](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-user-broker/src/lib.rs#L1835-L1915) строит строку, выбрасывает её и возвращает non-completion, потому что canonical owner — daemon. Снятие одного gate не чинит missing intake stitch. V3 даёт прямое operation-specific управление собственной записью, не зависимое от toast/model/Critical-approval producer. Request cancel не объявляется наблюдаемой остановкой external effect.

### 22.2 Повтор проблемы и цена истории

Notification emitter подавляет existing matching key/fence, включая resolved. `NotificationStore::upsert` отдельно отказывает resolved и materially different draft. Простое удаление exists-check даст IdentityConflict вместо update. Нужны problem key, episode, source event и seen revision, не новые grants. Старый ack не гасит новую проблему; dismissal не техническое recovery.

[surreal_notification.rs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/storage/eliot-store-surreal-adapter/src/apply/surreal_notification.rs#L1-L610) проигрывает всю прежнюю историю перед каждым принятым lifecycle leg и пишет растущий массив обратно. Для N=1000 одношаговых принятых updates это499500 прежних legs и500500 serialized entries, не измерение времени. Revision CAS в SQL есть — lost update не заявлялся. V3 current-row+append history в одной транзакции; replay — recovery, не ordinary update.

### 22.3 Optional enrichment и ложное delivered

Retained MCP сначала получает primary success, затем некоторые обычные branches могут отдать общую ошибку из-за enrichment `?`. Есть исключения для admitted packets и отдельных telemetry writes. V3 не переписывает известный исход эффекта из-за optional decoration.

[InjectionPlanner](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/ul/injection.rs#L190-L590) пишет `delivered` до insertion в ответ и восстанавливает suppression из receipts. Receipt failure пропускает полезный item; crash после receipt до send может надолго подавить неполученное. Это source-order inference, не transport fault injection. Достаточно фактически наблюдённого handoff и малого presentation cache; новой delivery-proof системы не надо.

### 22.4 Старый реальный matcher и широкий loader

Цепочка dispatcher→InjectionPlanner→CueIndexService пользуется прежней lossy normalization, хотя отдельная новая A-11 семья существует. ASCII-перенос показал слияние `Parser::read`/`parser::read`, `Type.method`/`Type::method`, UNC/relative и rooted/relative forms. Это string-key collisions, не утверждение о любой OS/language pair. Exact resource identity отделяется от advisory aliases.

После максимум8 совпадений planner загружает до10000 project records с payload. SQL имеет caps и `truncated`, поэтому «полностью безграничный запрос» было бы неточно. Правильное решение — hydrate выбранных IDs/необходимых альтернатив, не cache поверх лишнего whole-project read.

Counterchecks сохранены: валидный DirPath уже требует Prefix, path segment boundary полезна, notification CAS есть, и не каждый telemetry failure ломает каждый ответ. Не надо исправлять несуществующий дефект, прочитав только нижнюю функцию.

## 23. Working memory without global gates 0.8

Полный исходный отчёт: [§23 редакции0.9](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/0a71fd7d1b784486ef38f66b11cdd15cc8f8f81e/docs/v3/AUDIT.md#23-working-memory-without-global-gates-08).

### 23.1 Лимит страницы стал запретом пользоваться памятью

[Store loaders](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/canonical_store.rs#L2385-L2500) при `truncated=true` возвращают PolicyViolation для cue rows, sources и session receipts сверх10000. Это не continuation. При whole-project hydration unrelated corpus growth может отключить small relevant lookup. Увеличивать потолок или чистить квитанции ради поиска — симптоматический обход. Primary queries/ID lookup и paged broad scans устраняют причину.

### 23.2 Граф и общий порядок не должны стоять перед прямой пользой

[ActivationEngine](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/ul/activation.rs#L1-L300) читает readiness, загружает graph и пишет observability до возврата expansion. Порог500 касается graph branch, не всех видов поиска. Однако готовые direct matches не должны зависеть от достаточного общего числа edges и успешной записи trace.

[Projection claim SQL](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/surql/claim_cognitive_projection_project.surql) блокирует более позднюю запись проекта любой более ранней non-applied, независимо от family/target. Blocked/retry head мешает независимой работе того же проекта; другие проекты могут продолжаться. V3 сохраняет порядок настоящих зависимостей, не всего project lifecycle.

### 23.3 Cache не определяет существование памяти

Stale/missing CueShard честно отмечается, но не возвращает сохранённые primary сведения. `boot_sent` Boolean и hydration из receipts в рассмотренном пути могут фиксировать даже not_onboarded orientation и не дать новой карте обновить ту же сессию. Иные reset callers не объявлены отсутствующими по всему repo. V3 primary reads независимы; cache отражает показанные revisions, не вечное разрешение больше не ориентировать.

### 23.4 D16 LangMem: фон отдельно, observations не выбрасывать

На `48e3c11f` [reflection.py](https://github.com/langchain-ai/langmem/blob/48e3c11f5bb527282c7d5339c6a87a0b35abccfc/src/langmem/reflection.py) показывает submit/Future, отдельный worker и search без ожидания reflection. Это полезная развязка. Но basic background guide использует `await` перед возвратом; название не делает execution неблокирующим.

Delayed guide передаёт текущую пару сообщений, а новый PendingTask заменяет прежний payload без слияния. Полный контекст должен прийти от caller/сохранённой истории. V3 coalesces сигналы, не observations, и читает действительно необработанный эпизод. Нет второй ReflectionStore/очереди и бесконечного откладывания на непрерывном потоке.

### 23.5 Собственная поправка recovery

В0.7 я требовал isolation восстановленной копии до current deletion history либо нового selective import, а serving — после derived reconciliation. Это превращало утрату auxiliary metadata в запрет владельцу использовать целые данные. Исправлено: explicit owner restore, известные удаления, ясный пробел history, доступный primary read и background rebuild. Старые effects не replay автоматически; memory access и повтор действий — разные вопросы.

## 24. From an episode to useful learned behavior — 0.9

Подробный прошлый source/probe report: [§24 редакции0.9](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/0a71fd7d1b784486ef38f66b11cdd15cc8f8f81e/docs/v3/AUDIT.md#24-from-an-episode-to-useful-learned-behavior--09). Он касается выбранного retained experience пути, не всех V2 producers и skills.

### 24.1 DTO не заменяет интерпретацию

[semantic_memory.rs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/semantic_memory.rs#L1-L250) получает заполненный VerifiedEpisodeProjection, проверяет cause/outcome/verifier/conditions и строит Case. MCP действительно передаёт `input.episode`. Это приёмник структурированного материала, не автоматический raw-event interpreter. Отсутствие cause/cue может дать NothingToLearn, хотя полезная последовательность событий ещё остаётся.

[I12.21](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/architecture/I12-21-memory-ecology-residual-experience-and-transfer.md) и [I12.24](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/architecture/I12-24-meta-learning-and-improvement-delivery.md) дают нужный смысл переноса, но задают дорогие campaign/overlay/activation/closure формы. Reconstructed cases доступны в IncludeCaseCandidates — неверно утверждать универсальную недоступность любого опыта до ActiveProcedure. Для V3 один эпизод/коррекция может создать provisional note без лестницы регистрации.

### 24.2 Условие и заполненная форма не доказывают понимания

`condition_matches` использует75% token overlap, а applicability corpus включает текст unknowns и requested checks. ASCII-пробы дали true для `database transaction committed` против `database transaction not committed`, `run cargo check` против просьбы её запустить и APIv2 против APIv1 из-за short-token filter. Это isolated rule behavior, не запуск Rust. `AnalogyOnly` и `PartiallyApplicable` в прочитанном branch order недостижимы; earlier returns разбирают случаи.

`decision_sufficient` по непустым семи категориям+evidence способен вызвать inferred MemoryNeed=None и пустой recall. Explicit requested_need переопределяет это; unknowns отдельно могут дать RequireProbe. Counterchecks не отменяют основной вывод: field presence не полнота знания, запрос проверки не её результат, similarity не истинность. Unknown допустимо показать как условие, а не скрыть полезный метод.

### 24.3 Поздний опыт исчезает из выбранного reader

[semantic_records_by_kind.surql](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/surql/semantic_records_by_kind.surql) выбирает oldest512 physical records по revision/sequence, без continuation. Поздние уроки/коррекции могут храниться, но не попадать в этот path. Recall затем truncate≤3 до applicability; подходящий четвёртый уже не рассматривается. V3 separates candidate examination/final packet budget и читает current searchable records, не oldest prefix.

### 24.4 Несовпадающая идентичность уроков и поддержки

Projection key cases по project+job, patterns по normalized invariant core может скрыть разные outputs/conditions. Физические записи не удаляются, но used logical projection теряет различие. В обратную сторону repeated case_refs клонируются abstraction handler, а cases.len становится support. Нужны lesson identity/revision и source event identity, не новый identity framework. Общий batch и одинаковая фраза не доказывают одного смысла; replay не независимый case.

### 24.5 LangMem: обработать реальный no-change

В D16 [stateless.py](https://github.com/langchain-ai/langmem/blob/48e3c11f5bb527282c7d5339c6a87a0b35abccfc/src/langmem/prompts/stateless.py) trajectory/optional feedback/current prompt приводят к компактному model proposal. [Prompt contract](https://github.com/langchain-ai/langmem/blob/48e3c11f5bb527282c7d5339c6a87a0b35abccfc/src/langmem/prompts/prompt.py) разрешает update_prompt=false и пустой new_prompt, но показанные invoke/ainvoke возвращают new_prompt без проверки flag. Дальнейшая потеря текста зависит от caller; полный donor/model не запускался. V3 `keep` сохраняет метод, меняется named instruction, а не весь system prompt.

### 24.6 Рабочая петля

[Cognition §6.8](COGNITION.md#68-one-episode-to-a-useful-next-attempt): реальные события или прямое исправление → нужная интерпретация → searchable provisional lesson → ordinary next context → наблюдаемый исход. Missing cause/verifier остаётся unknown, не повод сочинять поля или выбросить эпизод. No-change не создаёт обязательного reflection текста.

## 25. Real experience input and normal context 0.10

**Текущий проход, 20 октября2026.** Прочитаны связанные V2 `context.rs`, фактический compile handler, skill registry/filter/proof functions и их MCP dispatch; capture `eliot.observe`; Harness2 `context.py`1–260 и весь `proposer.py`. Дальнейшие conclusions ниже — source-level, не продуктовый запуск.

### 25.1 Обычный consumer существует, но связан с посторонней готовностью

Вопрос0.9 «как опыт попадает в обычный packet» уточнён по реальному caller. [dispatch_compile_packet_l3](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-app/src/mcp_stdio/task_handlers.rs#L195-L460) передаёт `PacketExperienceSource::Cases` в `ContextCompiler::compile_plan`; [attach_packet_plan_sources](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/context.rs#L680-L730) вызывает ExperienceRetrievalService и записывает `packet.experience_priors`. Поэтому утверждение «consumer есть только у ручного experience_recall» было бы неверно.

Проблема в ветвлении handler: **cases читаются лишь после успешного `revision_bound_packet_enrichment` карты проекта**. При `PacketEnrichmentUnavailable` сборщик подставляет `Cases(Vec::new())`, не прочитав сохранённый опыт. Другие ошибки могут прервать compile. Это конкретная ненужная зависимость: ошибка карты превращается в отсутствие опыта независимо от его реального наличия.

**Решение V3:** lesson lookup выполняется независимо. Карта добавляет ориентацию, но не выдаёт право читать случаи. Не нужна дополнительная fallback-платформа или новый readiness state; достаточно вынести независимый read из условной ветви. В Cognition §5.2 это задано как обычная компоновка источников.

### 25.2 Новый опыт скрыт штатным режимом

[Formation](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/semantic_memory.rs#L45-L140) создаёт `ReconstructedCase`. Default `MemoryExposureMode` — `MatureExperienceOnly`; [exposure_allows](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/semantic_memory.rs#L1008-L1025) допускает в этом режиме только TransferValidated/ProcedureCandidate/ActiveProcedure. Именно source-compatibility нового producer со стандартным reader должна проверяться, не только наличие обоих типов.

Handler сопоставляет IncludeCaseCandidates с CertificationTreatment и готовит measurement. Этот режим **может** получить активный packet: [admission](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/context.rs#L1047-L1082) делает counterfactual только ShadowEvaluation при соответствующем gate. Поэтому нет оснований говорить, что любой candidate всегда заблокирован. Подтверждено другое: обычное использование свежего урока связано с maturity/exposure режимом, а его обход — с экспериментальной ветвью.

**V3:** useful provisional advice — нормальный продуктовый путь, не certification exception. Эксперимент может отдельно выключать memory для сравнения, но не определяет ordinary access. Проверка эффективности остаётся отдельной задачей, не prerequisite чтения.

### 25.3 Публичный навык иногда является демонстрацией вместо сохранённого метода

Прочитан [mcp_stdio/skill.rs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-app/src/mcp_stdio/skill.rs). `dispatch_skill_list` создаёт active card с новым SkillId и candidate с названием `MCP skill candidate`; он не читает stored cards. `dispatch_skill_inspect` принимает ID, но строит `mcp_active_skill(id, Active)`, а не загружает этот record. Estimate/filter используют ту же шаблонную конструкцию.

Это не вывод по комментарию или имени: такое поведение прямо находится в handler functions. Dispatcher содержит named маршруты к этим handlers. Scope вывода — retained MCP skill surface на указанном V2, не все потенциальные skill API или deployments.

**Для V3:** list/open обслуживают настоящие memory records. Неизвестный ID даёт отсутствие записи, а не правдоподобную карточку. Демо может быть примером вне продуктового read path. Для этого не нужен RegistryVerifier: надо заменить фабрикацию обычным чтением.

### 25.4 «Execution proof» создаётся с заранее выбранным успехом

В том же файле `dispatch_skill_execution_proof` разбирает label input и вызывает constructor с **новым ProjectId**, постоянным шагом `inspect-scope`, выходом `MCP skill proof output`, verifier строкой `just verify` и `SkillExecutionOutcome::Succeeded`. Затем передаёт объект в `write_skill_execution_proof_to_memory`, пишет локальный report и возвращает его. В этом handler нет исполнения навыка или verifier.

[Engine proof constructor/write](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/skill.rs#L680-L735) переносит полученные значения в record и подаёт observation writer. Найденный wrapper вызывает этот writer, не реальный tool runner. Named dispatcher также ведёт к handler. Поэтому проблема — не просто «высокий confidence»: **демонстрационный успешный исход формируется на callable product path и направляется в слой записи**.

**Граница доказательства:** приложение/БД не запускались. Возможный нижний refusal, actual credentials или иной caller могут не дать сохранить record. Не заявляется воспроизведённое загрязнение deployed памяти. Но сам успешный результат не основан на наблюдавшемся выполнении в рассмотренной функции, независимо от того, примет ли его Store.

**V3:** host передаёт фактический tool/check result и известную task/session/call связь. Явный отчёт агента или пользователя тоже полезен, но остаётся отчётом названного источника, не превращается в независимо выполненный verifier. Нет причины генерировать другой project или фиктивные completed steps ради заполнения DTO. Отсутствие наблюдения допускает сохранение partial/unknown; оно не останавливает полезный recall. Это обычные исходные данные, не новый proof protocol.

### 25.5 Выбранный skill ID ещё не доставленная процедура

[SkillDistractorFilterService::procedural_packet](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/skill.rs#L640-L685) возвращает included/excluded IDs, activation decisions, required verifier names и warnings. Самих ordered_steps/purpose в этом view нет. [compile_with_skills](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/context.rs#L515-L551) присоединяет этот view, но рассмотренный основной MCP handler вызывает compile_plan с cases. Отсутствие других возможных expanders по всему репозиторию не утверждается.

Есть и ненужное сцепление чтения с исполнением: `SkillActivationGate` не включает метод при отсутствующих execution inputs/verifier; `missing_verifier` требует непустого required plan. Это может быть условием автоматического исполнения, но не обязательным условием показать человеку/агенту способ работы. `activate` устанавливает last_verified_at после проверок наличия refs, не после выполнения verifier внутри этой функции.

**V3:** packet содержит полезную инструкцию и материальное условие/исключение, плюс handle подробностей. Full action recipe можно раскрыть по требованию через existing open. Execution prerequisites не блокируют чтение conditional advice. Оценивать следует actual rendered text, не весь административный SkillCardV2 перед выдачей нескольких IDs. Отдельный skill-delivery runtime не требуется.

### 25.6 Harness2: настоящие материалы по требованию и предел cache

[context.py](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/context.py#L1-L260) строит task/source/rollouts/deliverables/harness/library tree; короткая mission указывает, где читать. Layout отражает существующие категории. Это практический механизм для Dreamer: начать с нужного вопроса и ограниченного набора ссылок, раскрывать реальные материалы, а не нагружать каждый prompt всем архивом.

«Full trajectory» в этом source означает последовательность, а отдельные observations получают `obs_trunc`, переданный adapter. Names-only deliverables тоже явно отличаются от contents. Нельзя превратить красивый index в обещание, что модель увидела все bytes. Полная копия library tree в каждом context уместна как donor implementation choice, но не обязательна для большой памяти Eliot; existing open/controller workspace adapter достаточно.

[proposer.py](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/proposer.py) создаёт отдельную temporary workspace на попытку, копирует inputs, извлекает выбранный edited subtree до cleanup. Это уменьшает случайное наследование local residue между попытками. Сам tool/provider executor остаётся у нашего controller; отдельный subprocess manager в Memory OS ради копирования донора не нужен.

В `_call_fingerprint` включены label, mission, system, context path и contents, но **не ChannelSpec.model/effort/channel**. `_cached` читает response/workspace, не проверяя model metadata, хотя `_write_audit` её сохраняет. При повторном использовании того же audit directory и тех же inputs с изменённой конфигурацией модели можно вернуть старый ответ. Это следует из caller+key+reader, не воспроизведение оплаченного вызова. Документация донора рекомендует новый runs directory при смене модели; такой способ разделения уменьшает риск. Нельзя на этой находке объявлять все опубликованные эксперименты смешанными.

**Малое решение:** execution cache сравнивает actual request settings либо разделяется run namespace. Старый proposal может быть сознательно переиспользован как старое знание, но не маркируется новым запуском другой модели и не даёт ещё одно независимое подтверждение. Хешировать всё ещё сильнее, строить certificate service или инвалидировать всю память при смене Dreamer не нужно.

### 25.7 Что найдено на стороне capture и чего пока не найдено

Дополнительно прочитан [dispatch_observe, verification.rs1–245](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-app/src/mcp_stdio/verification.rs#L1-L245). Реальный capture-first handler сохраняет переданные observations без обязательного task и не отбрасывает capture только из-за отсутствия cue. Это полезный контрпример утверждению, что весь V2 input обязательно проходит готовый VerifiedEpisodeProjection.

При этом handler требует bound project; taskless или cue-less материал помечается cold, и cue_bindings не добавляются в индексируемое поле. Он возвращает candidate commitment, не вызывает в прочитанном теле ExperienceFormation. Из этого нельзя вывести отсутствие всех downstream workers; найден только конкретный предел пути. Поиски типов/сервисов дали declarations, MCP inputs, tests и consumer, но не достаточное основание для глобального «автоматического извлечения нет нигде».

**Для реализации V3:** adapter сохраняет события с доступной ассоциацией; ordinary job обрабатывает нужную непроработанную часть episode. Не нужно требовать полного task contract или самостоятельного заполнения causal fields агентом. Missing correlation оставляет запись в известной сессии, а не привязывает её к последней задаче наугад. Real result, scoped lesson, actual next-context text — достаточная связная конструкция без дополнительного gate.

### 25.8 Изменения и проверка

Cognition §§5.2,6.7,6.8 теперь описывают independent lesson read, содержательную выдачу метода, реальные inputs вместо synthetic proof и reuse execution cache без подмены происхождения. Architecture и Implementation не переписываются: эти уточнения реализуют уже выбранный путь и не создают новых owners.

Аудит сводит прежние находки, сохраняя их подробные immutable версии, и добавляет этот раздел. Карта отмечает actual packet/skill/capture reads и оставшиеся code paths. Не добавлены новая таблица критериев, permission service, тестовая фабрика или модельный вызов перед каждым tool.

**Фактически выполнено:** чтение названных исходников, проверка связей через dispatcher/writer и review изменённых документов; runtime/model/DB/Windows не запускались. Новых isolated probes в этом проходе не было. Нет независимого субагентного review, полной повторной проверки архива, всего skill subsystem или всех Harness2 adapters. Конкретные результаты публикации и проверки diff сообщаются в PR, а не выводятся из написанного текста.
