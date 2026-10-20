# Eliot Memory OS V3 — сводный аудит документации и архитектуры

**Редакция 0.19 · 20 октября 2026 · документация до переписывания продукта.**

**Новый результат — [§32](#32-host-capture-and-non-destructive-continuation-019):** прочитаны ранее пропущенные claude-mem и OpenHands Software Agent SDK. Проверены реальные hook handlers, захват до фоновой обработки, выдача контекста и границы сжатия по связям вызовов/результатов. В реестр добавлены D45–D46; исходные D01–D44 не перенумерованы. Субагенты в этой сессии не запущены: доступного вызова их исполнения не оказалось. Это самостоятельное чтение, не независимая проверка четырьмя агентами.

**Результат 0.17 — [§31](#31-real-interpretation-not-validation-shaped-learning-017):** прослежены сохранение наблюдения и следующий projection worker V2, фактический вход Dreamer и его локальная «модельная» стадия. Обновление индексов не оказалось интерпретацией, а проверка пустого draft — вызовом модели. Для сравнения прочитан реальный extraction-путь D20 Mem0. Решение V3 — соединённая работа с исходным эпизодом, настоящим controller response и обычной памятью, без добавления нового слоя удостоверений.

**Результат 0.16 — [§30](#30-everos-and-evermemos-anticipation-and-evidence-coverage-016):** сопоставлены историческая статья EverMemOS и действующий EverOS. Проверены default-off Foresight и стандартный search consumer, полная загрузка области в AGENTIC, отдельный multi-round retrieval и разделение foreground/background embeddings. Для Eliot уточнены условное предвосхищение в обычном контексте, выборка участников выбранной группы, покрытие частей вопроса и доступность интерактивного поиска. Новых сервисов и обязательного модельного маршрутизатора нет.

**Результат 0.15 — [§29](#29-magma-and-letta-relations-and-continuation-015):** прочитаны D42 MAGMA и действующий D17 Letta Code. MAGMA полезна выбором отношений под вопрос, но её рассмотренный query path делает полный проход даже при готовых результатах, повторно кодирует тексты, отсекает промежуточные узлы по словам и неверно объединяет несколько типов связей. Letta показывает отдельный рабочий путь сжатия контекста и отдельную reflection-подготовку. Для Eliot выбраны адресное раскрытие нужной связи и сводка продолжения без второго graph/context runtime.

Этот файл остаётся общим аудитом. В 0.15 прежние разделы сведены по механизмам, а не удалены как «закрытые»: сохранены 34 требования, 29 исходных сценариев, D01–D44, основные находки, ограничения и решения. Это **редакционная консолидация, не побайтное сохранение**. Полные формулировки, диапазоны чтения и прежние изолированные пробы доступны в неизменных [0.14](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/841c807659727cd7fb5730331190ee27cd50f47d/docs/v3/AUDIT.md), [0.9](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/0a71fd7d1b784486ef38f66b11cdd15cc8f8f81e/docs/v3/AUDIT.md), [0.4](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c28359fc2716f3b498ea512ca24a57801d18014c/docs/v3/AUDIT.md) и [ранней редакции](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/3512f6e4f4c9ce59ba2959193e92c0728fadf00c/docs/v3/AUDIT.md). Их эксперименты не выдаются за выполненные заново.

[Architecture](ARCHITECTURE.md) — назначение и границы; [Implementation](IMPLEMENTATION.md) — устройство; [Cognition](COGNITION.md) — алгоритмы; [AUDIT-MAP](AUDIT-MAP.md) — реально прочитанное и следующие вопросы. Проектные решения здесь не являются реализованным V3.

## 1. Источники, решения и границы проверки

| Источник | Прочитанная версия и роль |
|---|---|
| V1 | `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`: исходные требования и донор |
| V2 | `5aac094834fb5635921b550c821cb933a1196105`: замороженные нормативы и код |
| База текущей документации | `815f51e5a6839263ce6e310a42392c7810eb8218`, PR #5325 |
| Claude audit | Приложенный `eliot-documentation-audit(1)(1).md`, редакция 4: предложения и исторические измерения, не безошибочный норматив |
| Архив | [audit-2026-10-16-incomplete](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete): материалы исследования, не обязательный backlog V3 |
| Hy-Memory | `7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a`: выбранные writer/reconciliation/store/System 2 пути |
| MemOS local plugin | `a7367d07e55db61099f7b4e2c1108bc5831a24f3`: выбранные L2/gain функции |
| Eliot Swarm Controller | `96a0d5a6632cfbd541e804d7969d3e76e716bf6a`: прежняя ограниченная проверка integration document |
| Harness2 D44 | `1cfe254e8d25b15f37048c3730134686abe60335`; [статья 2610.14224v1](https://arxiv.org/html/2610.14224v1) |
| LangMem D16 | `48e3c11f5bb527282c7d5339c6a87a0b35abccfc`: reflection/extraction и prompt optimization |
| Hindsight D09 | `c5f585f8f8568ed0677eb2e70fe830c4c483e2a2`: consolidation, views, выбранные retain и host paths |
| MemMachine D01 | `d5a39a8e774e977fb1e6c22efb03555c4e51e05e`: declarative/event retrieval, semantic ingestion и выбранный storage |
| Graphiti D08 | `3cc723cd292eb5c2ac5ea2c5539270b8e1b6389f`: edge extraction/resolution/temporal helpers |
| A-MEM D43 | `ceffb860f0712bbae97b184d440df62bc910ca8d`: библиотека `agiresearch/A-mem`; отдельно [статья v11](https://arxiv.org/html/2502.12110v11) |
| Nocturne D19 | `1858957bf797722a9b731fb197bd9530f7ae67e4`: модели, реальные MCP read/alias и renderer |
| Subcog D03 | `0cd2d4f0cff04938c9f865353fbfefa1b4e3f754`: recall/fusion, выбранные consolidation/lifecycle functions |
| MAGMA D42 | `467cb70b67ac337b22fdb42194d37c04ad701b62`: README и связанный `memory/query_engine.py`; [статья v1](https://arxiv.org/html/2601.03236v1) отдельно от source findings |
| Letta Code D17 | ref `e8073d4e475ab7f56e76f9aaeea81a7618a92575`, возвращённый connector: local compaction/backend/store и выбранная reflection-подготовка; не весь прежний Letta server |
| EverOS D10 | `c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18`: текущие docs, foresight strategy, HTTP/service/search paths, episode recaller, выбранный multi-round loop и embedding provider/factory (§30) |
| EverMemOS D11 | [Статья 2601.02163v1](https://arxiv.org/html/2601.02163v1), 5 января 2026: исторический MemCell/MemScene/Foresight design; соответствующий исторический runtime здесь не квалифицирован |
| Mem0 OSS D20 | `0724291bd864cf807e88ee8981c8226644e8fb42`: текущий синхронный `Memory.add`, extraction/persistence и formatter сообщений; не managed platform и не весь AsyncMemory (§31) |
| claude-mem D45 | `9e4f313a89236f7fb593a639a77ee02e21e94469`, commit 19.10.2026: hooks, observation/spool/context handlers и выбранный generator caller; не все provider/DB paths (§32) |
| OpenHands Software Agent SDK D46 | `0996c33916c2a977ea9fe38deee660ff0e1389f2`: condenser, view/event и tool-call boundaries, реальный message-preparation helper; не весь агентный runtime (§32) |

Владелец требует новый V3 после документации: самообучение, понимание, модульность, гибкость, лёгкость и заменяемый Dreamer. Принятые проектные направления — local-first Rust, demand-start, SurrealDB server child и модельные маршруты через controller без собственного роя. Конкретные будущие SDK/API и параметры не объявляются уже работающими.

Различаем факт исходника, вывод из порядка операций, отдельную пробу и установленный продукт. Поиск имени — навигация, не доказательство отсутствия всех альтернатив. Прочитанный prompt — не выполненный фоновый агент. Ревизии идентифицируют источники аудита, а не назначают обязательные зависимости.

## 2. Где началось разрастание

### 2.1 Масштаб и предел арифметики

Исторический подсчёт первого прохода:

| Показатель | V1 | V2 |
|---|---:|---:|
| Rust-файлы | 139 | 2 472 |
| Физические строки Rust, включая комментарии/пустые/inline tests | 172 579 | 2 638 670 |
| Tracked files | Не пересчитано | 4 999 |
| Cargo manifests | Не пересчитано | 199 |
| Package manifests под bins | Не пересчитано | 15 |
| Markdown | Не пересчитано | 850 файлов / 47 012 строк |
| Python | Не пересчитано | 150 файлов / 144 845 строк |
| TOML | Не пересчитано | 421 файл / 587 866 строк |

Package не равен постоянно работающему процессу, physical LOC — production logic. Деление 2 638 670 на 50 даёт около 52 773 строк, но не бюджет законченного V3. Оценки «26,5 тысячи кода плюс 15 тысяч тестов» и «60–100 раз» не подтверждены одинаковым функциональным знаменателем. Считать надо весь необходимый controller, SQL, адаптеры, эксплуатацию и model calls.

### 2.2 V1 — тоже донор, не идеальный runtime

[V1 Production Architecture](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Rust_Governor_Production_Architecture_v1_0.md#L1-L155) полезно отделяет инструментальный Governor от модели и использует серверную БД. Но уже содержит redb Control WAL, leases, proof bookkeeping и продвижение policy/skills/retrieval. Малую топологию берём отдельно от церемонии.

### 2.3 V2 сделала сложную запись универсальной

[I1.2](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/architecture/I01-02-required-processes-of-the-first-complete-runtime.md) разделяет Host, Kernel, daemon, Watchdog, storage bridge и SurrealDB; blob capability допускает co-location. [I5.6](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/architecture/I05-06-admission-and-staging.md) задаёт 18 шагов scope/task/fence/provenance, digests, ORS staging, ordering, transaction, receipts и outbox с повторными проверками. Это цена выбранной топологии, не природа записи памяти.

**V3:** убрать ненужные границы, оставить доменный вызов, проверку настоящего входа, нужную транзакцию и identity повтора. Сохранить distributed pipeline и удалить случайные проверки — способ создать новые компенсации.

### 2.4 Петля роста

Понятие получает тип → отдельного владельца/lifecycle → копии состояния → shape-PASS вместо consumer → квитанцию незавершённости → восстановление самой квитанции. При этом [I17.11](../architecture/I17-11-delivery-depth-d3-grounded-smart-understanding.md) уже допускал полезную глубину до всей необязательной широты. Причины надо разделять: дорогая доктрина, её неверное чтение, отсутствующая проводка и фиктивное поведение.

## 3. The 34 preserved requirements

Основания: [Canonical Master](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Canonical_Master.md), [Production Architecture](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Rust_Governor_Production_Architecture_v1_0.md), [Understanding Layer](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md).

| № | Требование | Сохраняемый смысл и малый механизм |
|---|---|---|
| 1 | Независимость от модели, провайдера и host | Общая память и реальные адаптеры; совместимый интерфейс не одинаковое качество |
| 2 | Внешняя когнитивная петля | Наблюдение → контекст → действие/исход → изменение следующей работы |
| 3 | Автономность понимания | Автоматические карты и provisional методы без approval каждой записи |
| 4 | Экономия токенов и операций | Exact/lexical, совместимые vectors, batching и раскрытие; без LLM перед каждым чтением |
| 5 | Разные виды знания | Observation, claim, hypothesis, decision, procedure и unknown различаются |
| 6 | Актуальность относительно мира | Материальные live anchors; история не исчезает при смене HEAD |
| 7 | Точное происхождение | Source event/revision/span, оригинал, числа и исключения |
| 8 | Противоречие и пересмотр | Ревизии, альтернативы и контрдоказательство вместо last-write-wins |
| 9 | Область до использования | Поиск и раскрытие в выбранном project/workspace |
| 10 | Данные не полномочия | Goal/config/tool permissions отдельно от текста памяти |
| 11 | Сохранение без лишней формы | Capture до классификации; неизвестный смысл допустим |
| 12 | Связность и продолжение | Эпизоды, решения, попытки и адресные связи |
| 13 | Отбор пригодного после поиска | Один compiler учитывает состояние и применимость; similarity не доказательство |
| 14 | Постепенное раскрытие | Короткий packet и source handles |
| 15 | Контекст под решение | Цель, критерии, ограничения, unknowns и следующий шаг на реальной границе модели |
| 16 | Понимание проекта | Назначение, подсистемы, ресурсы и последствия, не только vector index |
| 17 | Холодный старт/обновление | Доступные anchors и non-Git scope, без выдуманной ревизии |
| 18 | Структура и поведение | Static dependency, co-change и causal hypothesis различаются |
| 19 | Предсказание и калибровка | Ожидание до действия и сопоставление с наблюдением |
| 20 | Негативная память до действия | Своевременный совет; точное host enforcement отдельно |
| 21 | Действие и исход | Версия метода, попытка, фактическое действие и критерий |
| 22 | Честное завершение | Реальные критерии и gaps, не один exit 0 |
| 23 | Dreamer преобразует память | Finite model job и обычное применение результата |
| 24 | Разные виды забывания | Exposure, withdrawal, revision и erasure отдельно |
| 25 | Процедурное обучение | Метод, условия, примеры, исключения и следующий consumer |
| 26 | Метаобучение и перенос | Опыт улучшения помогает следующему улучшению через те же jobs/attempts |
| 27 | Наблюдаемость | Реальные события и views, не квитанция вместо действия |
| 28 | Восстановление | Stable identity, малый spool, claim и external readback |
| 29 | Власть человека | Явные goal/config/control; score не создаёт прав |
| 30 | Малый интерфейс | Несколько операций; служебную metadata собирает adapter |
| 31 | Реальные отказы | Различающие сквозные ситуации, не сертификаты формы |
| 32 | Лёгкий Governor | Demand-start, один memory writer и нужное независимое наблюдение |
| 33 | Заменяемость хранения | Private Store, native DB и export, не универсальный KV |
| 34 | Улучшение не удостоверяет себя | Provisional use отдельно от доказанного выигрыша на будущих случаях |

Поздняя [UL Part C](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md#L1433-L1468) отменяла approval детерминированных UL-артефактов. Автономность не должна исчезнуть из-за эксперимента перед каждой подсказкой. Это не превращает гипотезу в факт или новое разрешение.

## 4. Что точно не переносить, что извлечь из V2

[I2.20](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/architecture/I02-20-module-contract-kit-crate-context-capsule-and-module-test-capsule.md) не требует crate на каждую cell. Его реальный перегиб — обязательная триада ContractKit/ContextCapsule/TestCapsule, digest, proof ceiling и срок квалификации независимо от пользы кода. Берём понятную ответственность и consumer, не отдельный продукт для разрешения считать другой продукт поддерживаемым.

[Notification admission](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliotd/src/notification_plan_admission.rs#L1-L380) повторно читает generated catalogue и вычисляет несколько digests ради локального state update. Clock/deadline меняют request identity; реальный repeat guard — БД и ключ проблемы. [Общий hash](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/storage/eliot-store-api/src/request_hash.rs#L1-L175) не подпись и не доказательство смысла. Убрать конверт вместе с ненужной межпроцессной границей.

[Новый cue normalizer](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/smart/eliot-cue-normalizer/src/normalize.rs#L1-L510) полезен сохранением исходной формы и единым сравнением capture/query. Policy/fence/input/result digest envelope вокруг pure helper не нужен. Unsupported absolute/UNC формы здесь сохраняют original value: это не доказательство потери raw capture. Реальный старый consumer использует другую normalization (§22).

| Семейство | Не импортировать | Полезный остаток |
|---|---|---|
| Host/Kernel | Hot generations, registry/epoch choreography | Ownership процесса, planned exit, ограниченный restart |
| ORS/redb | Вторую смысловую БД и общий recovery engine | Durable intake, unknown acknowledgement/effect |
| Storage bridge | Отдельный процесс и query language | Native parameterized queries/transactions |
| Capsules/tooling | Certificates, manifests как критерий готовности | Короткий контракт и реальные edge cases |
| Dreamer families | Crate/service на каждую мысль | Extraction, reconciliation, dissent, процедуры |
| Notifications | Digest/admission церемонию | Problem dedup, ack отдельно от resolution |
| Agent fabric | Второй swarm/provider scheduler | Host events и external task/attempt refs |

У 79 ORS tables неодинаковые обязанности. Они не объявляются «одной очередью»: сначала снимается ненужная роль старой топологии. Это решения для нового продукта, не команда удалять непроверенный V2 runtime.

## 5. Исправления Claude и собственных ранних утверждений

| Прежнее утверждение | Коррекция |
|---|---|
| BM25 только в V1 | В V2 есть вызываемый FTS path; качество отдельно не измерялось |
| Весь Dreamer всегда отказывает | Подтверждён normal resolver; curation — другой путь |
| Manifest count = постоянные процессы | Не измеренная топология |
| Таблица anchors означает готовность | Это проектное соответствие, не runtime |
| DB event — вся надёжная очередь | Enqueue не заменяет retry/cancel/unknown |
| Равная dimension — совместимые vectors | Важны encoder/preprocessing/content |
| Одна оставшаяся citation оправдывает синтез | Нужны реальные premises/alternative derivations |
| Ограниченный каскад проверил весь остаток | Непросмотренное не становится подтверждённым |
| Exit 0 означает whole task | Только покрытый критерий |
| Запрет слов Lease/Fence/Receipt решает сложность | Причина и consumer важнее имени |
| 50× уже доказано | Не измерено на одинаковом продукте |

Сохранённые source findings: [FTS caller](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/canonical_store.rs#L2513-L2555), [FTS SQL](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/surql/load_memory_search_fts_candidates.surql), [normal Dreamer resolver](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/controller.rs#L64-L84).

Собственные ошибки: universal freshness выключала историю; ModelJob требовал Task и одновременно запрещал fake Task; backup обещал неопределённый snapshot; описание одного направления controller выдавалось за доказательство отсутствия другого; подготовленные документы оставались локально. Исправляются действующие договоры, не добавляются оправдательные квитанции.

## 6. Hy-Memory: что взять, где ограничить вывод

Hy уже допускает model/endpoint selection: [config](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/config.py#L132-L214), [provider](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/agent/llm_provider.py#L309-L440). Writer weights, application и [training paper](https://arxiv.org/html/2610.22196v1) — разные артефакты. Любая модель с похожим prompt не наследует опубликованное качество.

Берём episodes отдельно от transferable experience, extraction отдельно от reconciliation, адресные кандидаты и no-proposal. Не переносим store/service на уровень и обязательный урок из каждой порции.

[Coding writer](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/writer.py#L65-L205) сохраняет trace в `finally` после extraction, а ошибку записи логирует. Chat raw-first не квалифицирует все coding paths. В Eliot первичное сохранение независимо от интерпретации.

[_crosslink](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/writer.py#L236-L280) связывает каждый experience со всеми facts партии. Это соседство, не premise каждой мысли. Episode/batch ID подходит для навигации, evidence адресуются отдельно. Разрешённое раскрытие зависит от фактически переданного модели материала, не только её citations.

Прежние parser/UPDATE findings касаются выбранных проверок target membership, не live атаки и не всех режимов. Обычный lookup существующих targets достаточен; универсальная платформа полномочий не нужна.

## 7. SurrealDB: использовать готовые возможности

Одна БД уже предоставляет полнотекст, векторы, связи и транзакции. Small scoped exact vector search допустим; ANN выбирается по цене. Private Store не требует собственного AST, neutral KV и компенсирующего query framework.

[SDK query API](https://surrealdb.com/docs/reference/rust/methods/query): transport success не ошибки statements; нужны обязательные bindings и проверка реально изменённых строк рядом с запросом. Семантическая история — обычные revision records; export не восстанавливает перезаписанное прошлое автоматически. [Backup/import](https://surrealdb.com/docs/manage/self-hosted/backups-and-recovery) проверяются по фактическим данным, не предположению о повторе всех старых table events.

[Filtered vector search](https://surrealdb.com/docs/learn/data-models/vector-search/similarity-search) исследуется на выбранном server/schema/query/EXPLAIN. Ограничение Python-донора не переносится в SurrealDB по аналогии. Правильный query plan также не обещает полной смысловой полноты.

D41 Agent Memory/Spectron — отдельное приложение, не встроенное понимание БД. [Старый no-SDK ADR](../ADR/0001-phase-a-dependency-boundaries.md) — историческое решение, не veto V3. Первым выбран официальный network SDK; замена требует конкретной проблемы, не церемонии отмены донора.

## 8. Controller и host: реальные границы

[Прежний integration document](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/96a0d5a6632cfbd541e804d7969d3e76e716bf6a/docs/eliot-memory-os-integration.md) описывал controller→memory context, не готовый memory→controller inference API. Ограниченный поиск не доказывает глобального отсутствия метода. Реальные text/embedding routes выбираются при реализации.

Memory владеет намерением преобразования и применением, controller — provider execution/retries. Local claim, external request и applied revision — разные сведения, не три сервиса. После падения worker сначала readback прежнего execution; acceptance не output, best-effort cancel не нулевая стоимость.

Maintenance не требует fake coding Goal. Настоящая synthesis Task допустима, когда нужна executor. [Claude hooks](https://code.claude.com/docs/en/hooks) различают hook и model-decision boundary. Совет в PreToolUse не обязательно меняет уже выбранный call. Negative memory advisory по умолчанию; конкретное host enforcement отдельно.

Старый контекст может оставаться в transcript. Current incarnation и материально новый совет допускают новую выдачу; локальное withdrawal не удаляет раскрытые provider bytes. Letta compaction уточняет эту границу в §29.

## 9. Самообучение без самоудостоверения

Урок — revision, попытка — outcome, aggregate — view. Provisional use не ждёт доказательства универсального выигрыша. Delivery, action, adherence, criterion outcome и comparative benefit различаются. Replay, paraphrase и несколько steps одного эпизода не независимая поддержка. Correction заменяет вклад с историей.

В выбранном [MemOS L2](https://github.com/MemTensor/MemOS/blob/a7367d07e55db61099f7b4e2c1108bc5831a24f3/apps/memos-local-plugin/core/memory/l2/l2.ts#L371-L445) with-set включает induction associations. [Gain](https://github.com/MemTensor/MemOS/blob/a7367d07e55db61099f7b4e2c1108bc5831a24f3/apps/memos-local-plugin/core/memory/l2/gain.ts#L62-L133) при равных observed means 0,8, пяти without-cases и prior 0,5 веса пять даёт +0,15. Это арифметика, не causal lift и не live запуск. Heuristic ranking допустим, выдуманное сравнительное доказательство — нет.

Отсутствующий diagnostic не pass, если verifier не дошёл до consumer, видел другую revision или неполный вывод. Сетевой отказ не опровергает все предложенные методы. Shadow фиксирует выбор, не изменённое действие. Недостаток статистики оставляет полезную гипотезу, а не выключает память.

## 10. Надёжность без второй операционной системы

Historical evidence, live applicability и disclosure различаются обычными полями/связями. Local configuration задаёт проекты, capture/retention и routes; не нужен principal/grant graph. Stable IDs, транзакции, current claim и readback решают конкретные ошибки. Signed proposals и proof-of-reading не решают смысловую задачу.

Spool подтверждает сохранённый input, не semantic truth. Backup имеет quiesced export, blobs, конечный staged cutoff и новый batch для поступающих событий. Export-length pause честнее неизвестного «мгновенного snapshot»; нельзя ждать worker под его lock.

Owner-selected restore работает даже при утраченном фрагменте deletion history: применяются известные удаления, неизвестное обозначается, primary доступно до derived rebuild. Старые external jobs автоматически не replay. Нужное независимое наблюдение не означает два собственных supervisor; Job Objects помогают custody, не защищают от любого unrestricted процесса того же OS user.

## 11. Доноры и аудиты: карта, не обязательная программа переносов

Исторический реестр: 43 D-поверхности, 27 P-работ, 187 S-записей — 257 строк, не 257 независимых прочитанных источников. Добавленные D44–D46 сохраняют старые IDs. Архив и все upstreams целиком не перечитаны. Конкретное копирование кода требует условий соответствующей версии; исследование механизма не импортирует продукт. Сверка охвата в [AUDIT-MAP](AUDIT-MAP.md) остаётся отдельной от решения использовать механизм.

### 11.2 D01–D44

Заголовок сохраняет исторический anchor; D45–D46 добавлены ниже без перенумерации прежних строк.

| D | Донор | Решение/механизм |
|---|---|---|
| 01 | MemMachine | Derivative→episode→ремонт; дешёвое разбиение и реальные ingestion callers. Не oldest-prefix и не messages×categories (§§26–27) |
| 02 | MemPalace | Event identity, равные timestamps, повторные exports; не last duplicate wins |
| 03 | Subcog | Native arms/RRF, сохранённые summary sources. Score не confidence; lifecycle arithmetic отдельно (§28) |
| 04 | MemOS local plugin | Retrieval по ситуации; gain не causal proof |
| 05 | Claude Code memory/tool search | Малый индекс и раскрытие вместо постоянного дампа |
| 06 | ClawVM | Сохранение значимых смысловых единиц при сокращении |
| 07 | Pichay / demand paging | Цена повторного чтения; не paging OS заранее |
| 08 | Graphiti | Duplicate/contradiction candidates и temporal intervals; не весь managed Zep (§26) |
| 09 | Hindsight | Facet update, saved questions, retention без собственного echo; conditional delta (§§26–27) |
| 10 | EverOS | Пропущенные события и replacement прежде retirement; 0.16: actual foresight/search wiring, scoped group fetch, question coverage и foreground embeddings (§30) |
| 11 | EverMemOS historical | Episodes/facts/foresight статьи v1 отдельно от нынешнего EverOS; качественные foresight cases не измеренный coding benefit (§30) |
| 12 | Cloudflare managed Agent Memory | Raw рядом с derived; service не бесплатная library |
| 13 | Cloudflare Agents SDK Sessions | Immutable turns, branch-local compaction |
| 14 | SurrealFS | Source/indexer/content identities; не сама SurrealDB |
| 15 | MentisDB | Versioned procedures и source reveal; lifecycle ещё проверить |
| 16 | LangMem | Submit/search отдельно, coalesce без потери inputs, no-change обработан (§§23–24) |
| 17 | Letta Code current | Свежая 0.15: реальный local compaction caller и отдельная reflection-подготовка. Continuation не durable lesson; не второй host (§29) |
| 18 | Letta V1 archive | История по требованию и truncation; в 0.15 не выдана за current Code |
| 19 | Nocturne Memory | Stable node/revision/alias и короткие recall clues, не обязательный boot/persona (§28) |
| 20 | Mem0 OSS | 0.17: реальный single extraction и batch persistence; tool results теряются в выбранном formatter, parse failure неотличим от empty result; не перенос hosted scores или ADD-only как весь resolver (§31) |
| 21 | OpenMemory historical MCP | Membership/access ideas historical продукта |
| 22 | OpenMemory session CLI | Перенос сессий; roadmap не runtime |
| 23 | Cavira LongMemory | Decay/supersedes/checkpoint; не смешивать с mem0 |
| 24 | ripgrep | Exact source spans и простой source tool |
| 25 | ast-grep | Синтаксические patterns, не runtime proof |
| 26 | SCIP | Definitions/references и source/producer/encoding |
| 27 | GitHub Copilot Memory | Citation recheck; описание не открытый runtime |
| 28 | Docling | Нужная ingestion и page/element provenance |
| 29 | Docling Core | Иерархия документа и chunk metadata |
| 30 | DocETL | Raw/error/partial, не новый general research engine |
| 31 | Vector / VRL | Сохранить событие при transform error; DSL по нужде |
| 32 | Kreuzberg v4 LTS | Native extraction, конкретная версия/лицензия |
| 33 | Kreuzberg current | Не наследовать свойства иной версии по имени |
| 34 | Cedar | Только при реальной сложности policy, не baseline |
| 35 | OPA | Undefined/error/result; не второй policy owner |
| 36 | redb | Historical spool; baseline не требует второй БД |
| 37 | duroxide | Activity identity как идея, не workflow runtime |
| 38 | Flawless | Unknown effect и retry/replay |
| 39 | FoundationDB testing | Будущие управляемые отказы, не тестовая платформа сейчас |
| 40 | Wasmtime | Изоляция реального недоверенного расширения при нужной цене |
| 41 | SurrealDB Agent Memory / Spectron | Source-linked retrieval; отдельное приложение |
| 42 | MAGMA | Свежая 0.15: отношения под вопрос, реальный query/traversal/packing; не полные scans и hardcoded dataset routing (§29) |
| 43 | A-MEM | Evolution реально индексируемых описаний и связей; library/paper различаются (§28) |
| 44 | Harness2 | Два improvement loops и реальные раскрываемые материалы; cache не новый опыт (§§19,25) |
| 45 | claude-mem | Hook→локальное сохранение→фоновая работа; стабильный неизменённый контекст и адресные уточнения. Не копировать весь Bun/SQLite/provider runtime или подавление ценных событий ради цены inference (§32) |
| 46 | OpenHands Software Agent SDK | Разрез по связанным tool calls/results и производная View над исходными событиями. Не копировать второй host, provider-specific ограничения в общую память или пустой summary как успешное сокращение (§32) |

Hy-Memory отдельно углублён в §§6,16–18. MemGPT/HiAgent, LongMemEval/MemoryArena/Mem2Act, LightMem/MemDelta, ATMS и Meta-Harness исследуются по пробелу продукта, не ради обязательных карточек. Достаточны source, механизм, consumer, цена и решение взять/не брать. Самописный аналог не должен проходить легче зрелой библиотеки только потому, что донору назначена лишняя церемония.

## 12. All 29 original scenarios

Источник — [V2 A15](../architecture/A15-end-to-end-scenarios.md). Сохраняется пользовательский смысл, не старая топология.

| A15 | Ситуация | Решение V3 |
|---|---|---|
| 1 | Новая область без Git | Реальные anchors и provisional scope |
| 2 | Агент не знает, что искать | Orientation, совет и handles на границе решения |
| 3 | Неопределённый тип наблюдения | Сначала permitted raw |
| 4 | Ложное слияние/процедура | История/dissent, пересмотр производного влияния |
| 5 | Workspace изменён без отчёта | Доступные сигналы, gap и целевой resync |
| 6 | Разные объяснения | Источники и различающий шаг, не голосование |
| 7 | Большой swarm audit | Уникальный охват/gaps в памяти; рой у controller |
| 8 | Повтор известного провала | Applicable advice; точный host gate отдельно |
| 9 | Ложный guard | Challenge и сужение неверной части |
| 10 | Позднее poisoning | Пересмотр реальных зависимостей и новая обоснованная revision |
| 11 | Injection из данных | Данные не полномочия; действительные targets |
| 12 | Optional failure | Незатронутая польза продолжается |
| 13 | Governor падает | Внешний observer, pending/unknown recovery без Kernel clone |
| 14 | Давление диска/очереди | Явный staged/rejected и доступный control |
| 15 | Неэффективный repair | Остановить тот же retry, сохранить проблему |
| 16 | Compaction/restart | Цель/обязательства/ошибки, новая incarnation; discarded plan не оживает |
| 17 | Смена модели/host | Проверить нужные capabilities; сохранить историю |
| 18 | Нет verifier | Критерий unknown, не успех |
| 19 | Пропущено уведомление | Attention сохраняется; ack не resolution |
| 20 | Найден executable | Metadata не permission; реальный host путь |
| 21 | Privacy deletion | Withdrawal/purge и внешние ограничения различаются |
| 22 | Старый backup | Известные удаления, owner-selected restore с обозначенным gap |
| 23 | Прерванная migration | Restart-based upgrade и явный результат |
| 24 | Код против Architecture | Grounded discrepancy, правка нужной стороны |
| 25 | Экспериментальный модуль | Ограниченное подходящее сравнение, не hot-replacement matrix |
| 26 | Рой пишет модули | Один manager/worktree и writer/область вне Memory OS |
| 27 | Локальный PASS, продукт FAIL | Не заявлять общий успех |
| 28 | Мало окна | Reveal/decomposition, не молчаливое удаление exceptions |
| 29 | Meta candidate после смены стека | Применимость заново, старый score не новое evidence |

Implementation S1–S32 и 36 прежних cognitive walkthroughs остаются в своих документах. Это проектные ситуации, не выполненные тесты.

## 13. Разработка и публикация

Единица работы заканчивает полезный переход, а не семейство DTO и будущих заглушек. Один manager — один изменяемый worktree. Публикация — настоящий GitHub commit/ref, не локальный ZIP. Исторический разрыв 0.5 устранён; работающий GitHub API не объявляется read-only из-за локальной сети.

Старые CI-находки относились к конкретным runs: fixed cohort из 11 issues и LF/CRLF-зависимость reading receipt. [Cohort](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/.github/work-unit-cohort.toml), [gate](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/scripts/work_unit_gate/doc_read_evidence.py#L1592-L1659). Они не объясняют автоматически каждый новый failure. Не подставлять чужую issue, не выдумывать независимого reviewer, не переиспользовать старый PASS. Этот проход CI и ACTIVE registry не меняет.

## 14. Минимальная рабочая конструкция

Capture сохраняет observation и необходимую работу; Store использует native DB; context находит полезное; Dreamer интерпретирует; learning связывает метод с будущим outcome; controller исполняет внешнее. Matching claim/revision устраняет позднюю запись без Authority Epoch framework. Advisory не обязан быть универсально доказан; чтение метода не его исполнение. Число рёбер, сервисов и reflection не мера понимания.

## 15. Что пока не доказано

Нет полного построчного аудита V2, повторного чтения всего ZIP/всех papers/donors, работающего V3 или сравнительного LOC/RAM/latency. O1–O6 в Implementation — конкретные host/controller/Store/platform choices, не разрешения заблокировать другие функции. Карта показывает точный остаток без фиктивного процента готовности.

## 16. Cognitive audit 0.3

0.2 подробнее описывала recovery, чем вычисления понимания. Добавлены scoped current resolution, intended/observed/proposed, lookup альтернатив вне top-k, membership views, finite refresh, three-valued applicability и criterion-specific outcomes внутри существующих modules. [V1 §4.12](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Canonical_Master.md#412-deterministic-current-value-resolution) и [UL mission](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md#L14-L120) дают смысл, не обязательные старые DTO.

Новый consumer делает карту неполной без изменения старых cited files: нужны scope/membership, не полный rebuild. В optional/default-off [Hy helper](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/system2_agent.py#L72-L346) прежняя изолированная проба принимала цитату `I use glasses` за состояние пользователя. Не весь Hy deployment: user-role не исключает quoted/example content.

[DCPM](https://arxiv.org/html/2606.09483v1) полезна trajectories/offline abstraction, не квадратичным sweep как обязательной нормой. Два preceding chunks [Hy §5.3](https://arxiv.org/html/2610.22196v1) относятся к reward annotation, не каждому production writer. [LongMemEval](https://arxiv.org/html/2410.10813v2) различает update/temporal/abstention, не задаёт универсальную онтологию Eliot.

## 17. Memory transition audit 0.4

Источник — Hy [fact reconciler](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/fact_reconciler.py) и [store](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/store.py).

| Проверенный механизм | Решение |
|---|---|
| Retirement прежде model/history/new insert, отдельный autocommit | Подготовить снаружи, атомарно publish revision/links/retirement/result |
| Session progress вместо atomic claim | Продолжение не отменяет все старые исключения |
| Optional subject gate | Prompt не безусловная гарантия каждого режима |
| После A→B удалён B | A не воскресает без основания |
| Несколько родителей, ancestor LIMIT 1 | Frontier/visited и явная неполнота |
| Lexical rerank после dense threshold | Независимые exact/lexical кандидаты |
| Exact details не searchable | Source-derived cues и адресное раскрытие |
| Verifier не дошёл до consumer | Missing diagnostic не pass |

Прежняя SQL-проба оставляла retired predecessor без successor; другая A/B→C→D пропускала B без исчерпания depth. Это изолированные переходы, не полный runtime или recall benchmark. Подробности сохранены в исторических редакциях.

## 18. Cross-domain learning audit 0.5

[Hy sweeper](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/cross_domain_sweeper.py) и [optional compaction](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/system2_tools.py#L84-L209):

- Existing-core branch выбирает первый set element и добавляет связи без нового semantic matching. Сортировка исправляет порядок, не смысл. Alternatives сохраняются; association не evidence.
- Union-find создаёт компоненту из попарной близости, которая не транзитивна. Прежние synthetic углы 0/40/80 градусов это показывали. Компонента — кандидаты, не доказанный общий принцип; clique-proof также не нужен.
- Начальные 500 узлов не ограничивают повторное перечисление всех behavioral nodes. В prompt для отсутствующего source может попасть лишь ID. Две условные float32 матрицы 10000×10000 требуют 800000000bytes без прочих расходов; это арифметика, не measured OOM.
- Null branch не переиспользует no-change локально; `_has_beh` не означает текущий abstractor/encoder. Existing job input/method identity решает reuse без новой negative-result БД.
- Default-off compaction использует shared sources+cosine для снятия второй формулировки без проверки исключения. Прежняя synthetic пара read-only retry/unknown side effect показывала недостаточность условия, не качество настоящего encoder.

V3 удерживает finite inputs, нужные пары и продолжение; обновляет derived representation по назначению; сохраняет конкретные условия и independent cases. Дополнительное behavioral пространство опционально по реальным пропускам. Нет ConceptualStore/merge daemon/самостоятельного планировщика самоэволюции.

## 19. Harness2: рекурсия для Eliot, не новый агентный runtime

[recursion.py](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/recursion.py), [selection](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/selection.py), [library](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/library.py), [ledger](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/ledger.py), [schedule caller](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/schedule.py#L390-L560) и [experiment guide](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/docs/EXPERIMENTS.md) проверялись отдельно от опубликованных scores.

Task-local Propose–Probe–Compose меняет способ конкретной работы. Cross-task lesson улучшает способ будущей диагностики/улучшения. Recipe стабилен внутри сравнения; следующий task не наследует весь прежний специфический harness. Веса моделей не меняются.

Final pool исключает reference outputs; Compose всё же может оставить input tree. Eliot явно сохраняет baseline/no-change. Sequential latest composition не обязательно better. R=4k/P=3k — экспериментальная структура, не число всех API calls: selection/reflection/retries/cache отдельно. Не назначать её каждому событию памяти.

Reflection fields не causal proof. Guide сообщает о validation rollout, скачавшем публичный rubric; это ограничение setup, не доказательство загрязнения всех результатов. Existing memory/attempt/jobs/controller реализуют два цикла без ReflectionStore, другого executor и рекурсивного роя. Необратимые действия не повторяются ради проверки без подходящего разрешённого сценария.

## 20. Где проектировщик сам вернул бюрократию и что изменено

| Мой перегиб | Исправление |
|---|---|
| Old SDK veto | Сначала официальный сетевой SDK; конкретная проблема меняет решение |
| Эксперимент перед каждым transfer | Automatic provisional advice отдельно от benefit claim |
| Второй generic operation ledger | Readback у настоящего owning record/job |
| Свой supervisor всегда | Один реально покрывающий failure domain owner |
| Enterprise principal/grant vocabulary | Local projects/routes/retention |
| Whole-corpus provenance walk | Релевантные выбранные источники и affected views |
| Per-helper digests | Hash для actual bytes/cache/backup, не понимания |
| Сначала qualify всё | Реальная capability, не veto остальных |
| Restore требует потерянный журнал | Owner-selected recovery с честным gap |
| Optional telemetry разрешает выдачу | Полезный результат отдельно от его измерения |

Запрет слов, approval каждой функции и произвольный LOC ceiling создадут лишь переименование старых конструкций. Проверяем назначение, state owner, consumer и готовый native механизм. Нужная транзакция не бюрократия; слои вокруг неё могут ею быть.

## 21. Порядок следующей работы

Карта A01–A14 — навигация прочитанного, не runtime registry. Главный вопрос: кто действительно создаёт полезные данные, кто читает и что меняется в следующем действии? Source-level findings не заменяют связанный путь. Следующее чтение должно закрывать такой пробел, не повторять уже разобранный normalizer ради счётчика.

## 22. Connected control and context audit 0.7

[Полная историческая запись](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/0a71fd7d1b784486ef38f66b11cdd15cc8f8f81e/docs/v3/AUDIT.md#22-connected-control-and-context-audit-07).

**Control.** Названные broker acknowledge/cancel/reconcile ветви заканчиваются общим `HumanApprovalActionDigestUnverifiable`, не имея success path. [Gate](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-user-broker/src/lib.rs#L2380-L2520). Ниже [ack launcher](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-user-broker/src/lib.rs#L1835-L1915) создаёт/выбрасывает строку и сообщает, что запись принадлежит daemon. Удаление первого gate не соединяет второй разрыв. Нужен прямой operation-specific call, не proof producer.

**Notification recurrence.** Existing matching key/fence подавляет emission, включая resolved; upsert отдельно отказывает resolved/different draft. Нельзя просто убрать exists-check: будет IdentityConflict. Problem/episode/seen revision различаются. Ack старого не гасит новое. [Persistence](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/storage/eliot-store-surreal-adapter/src/apply/surreal_notification.rs#L1-L610) проигрывает всю историю перед update и переписывает массив. N=1000 принятых legs — 499500 прежних replay и 500500 serialized entries; не latency measurement. SQL CAS присутствует. Current row+append history в одной транзакции устраняет повторную работу.

**Optional enrichment.** Некоторые обычные MCP branches после primary success отдают generic error из-за последующего enrichment `?`; исключения для части packets/telemetry уже есть. Сбой украшения не должен означать отсутствие произошедшего эффекта. [InjectionPlanner](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/ul/injection.rs#L190-L590) пишет delivered до вставки в ответ и восстанавливает suppression из receipts. Receipt failure подавляет пользу, crash-before-send может оставить ложную доставку. Это source-order вывод, не transport fault injection. Нужны наблюдённый handoff и малый presentation cache.

**Cue path.** Реальный retained caller использует старую lossy normalization, несмотря на новый crate. Прежние ASCII-пробы сливают case-distinct symbols, `Type.method`/`Type::method`, UNC/relative и rooted/relative keys. Это string collisions, не универсальное равенство во всех OS/languages. После ≤8 matches loader выбирает до10000 project payloads. Hydrate нужных IDs/alternatives вместо cache поверх лишнего whole-project read. Counterchecks: DirPath contract уже требует Prefix, segment boundary полезна, не каждый telemetry failure ломает всё.

## 23. Working memory without global gates 0.8

[Полная запись](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/0a71fd7d1b784486ef38f66b11cdd15cc8f8f81e/docs/v3/AUDIT.md#23-working-memory-without-global-gates-08).

[Store loaders](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/canonical_store.rs#L2385-L2500) при truncated возвращают PolicyViolation сверх10000, не continuation. Рост несвязанных данных может выключить малый lookup. Увеличение потолка не решение: primary indexed queries и pages.

[ActivationEngine](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/ul/activation.rs#L1-L300) ставит graph readiness/запись observability перед expansion; порог500 касается graph branch, не всего поиска. Direct matches должны возвращаться без этих зависимостей. [Projection queue](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/surql/claim_cognitive_projection_project.surql) блокирует поздние jobs любой ранней non-applied строкой проекта независимо от target. Сохранять порядок только настоящих зависимостей.

Missing/stale cue cache и permanent `boot_sent` не определяют существование primary памяти. Неудачная первая orientation не должна скрывать новую карту всю сессию. Scope выводов ограничен прочитанными callers; иные resets не объявлены отсутствующими глобально.

LangMem [reflection executor](https://github.com/langchain-ai/langmem/blob/48e3c11f5bb527282c7d5339c6a87a0b35abccfc/src/langmem/reflection.py): separate submit/Future и search полезны; guide с `await` не становится неблокирующим от названия. Delayed payload заменяется, а не объединяется. Coalesce сигналы, сохранять observations и обрабатывать actual unprocessed episode.

В0.8 удалён мой blanket restore quarantine до полной current deletion history/derived readiness. Владелец может восстановить выбранные данные с известными удалениями/неизвестным gap; старые внешние эффекты отдельно от доступа к памяти.

## 24. From an episode to useful learned behavior — 0.9

[Полная запись](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/0a71fd7d1b784486ef38f66b11cdd15cc8f8f81e/docs/v3/AUDIT.md#24-from-an-episode-to-useful-learned-behavior--09).

[Formation](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/semantic_memory.rs#L1-L250) получает заполненный VerifiedEpisodeProjection; MCP передаёт input.episode. Это настоящий приёмник, не автоматическое понимание raw событий. Missing cause/cue может дать NothingToLearn, хотя последовательность полезна. Maturity ladder дорога, но IncludeCaseCandidates уже разрешает reconstructed cases — универсальный запрет не заявляется.

Applicability по75% token overlap путает отрицание/упоминание проверки/короткие версии. Прежние пробы: committed/not committed, просьба run cargo check и APIv1/v2 совпали. Branch order делает AnalogyOnly/PartiallyApplicable недостижимыми. Заполненные семь TaskMeaning fields+evidence могут вывести MemoryNeed=None; explicit requested_need переопределяет. Unknowns иногда дают RequireProbe. Нужны наблюдения и условный совет, не prover естественного языка.

[Semantic loader](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/surql/semantic_records_by_kind.surql) читает oldest512 без continuation. Recall обрезает до3 до applicability. Late corrections и подходящий четвёртый теряются в этом path. Candidate scan не final packet budget.

Case projection по project+job и pattern по normalized core скрывают разные условия; duplicate case_refs, наоборот, повышают cases.len support. Нужны lesson identity/revision и independent source ID, не identity framework.

LangMem [stateless](https://github.com/langchain-ai/langmem/blob/48e3c11f5bb527282c7d5339c6a87a0b35abccfc/src/langmem/prompts/stateless.py) получает proposal из trajectory/feedback/current prompt. [Contract](https://github.com/langchain-ai/langmem/blob/48e3c11f5bb527282c7d5339c6a87a0b35abccfc/src/langmem/prompts/prompt.py) разрешает false+empty no-change, а выбранные invoke возвращают new_prompt без флага. Последующее уничтожение зависит от caller. Eliot keep сохраняет текст; одна полезная интерпретация даёт обычный searchable lesson.

## 25. Real experience input and normal context 0.10

[Полная запись](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/841c807659727cd7fb5730331190ee27cd50f47d/docs/v3/AUDIT.md#25-real-experience-input-and-normal-context-010).

Обычный consumer **существует**: [compile handler](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-app/src/mcp_stdio/task_handlers.rs#L195-L460) передаёт cases в context compiler/experience_priors. Но читает их лишь при успешной map enrichment; unavailable map подставляет empty cases. Чтение урока должно быть независимо от карты.

Formation создаёт ReconstructedCase, default MatureExperienceOnly исключает его; IncludeCaseCandidates связан с CertificationTreatment. Этот режим всё же может дать active packet. Исправление — нормальный provisional use, не новый обход через эксперимент.

[MCP skill](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-app/src/mcp_stdio/skill.rs) list/inspect строит template cards вместо чтения stored methods. Execution-proof handler конструирует новый ProjectId, `inspect-scope`, `MCP skill proof output`, `just verify`, Succeeded без исполнения и передаёт writer. Lower Store может отказать; live загрязнение не воспроизводилось. Ошибка — сама фабрикация успешного результата на callable path. Реальные события/report source заменяют её без нового ProofVerifier.

[Procedural packet](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/skill.rs#L640-L735) содержит IDs/activation/verifier/warnings, не шаги метода. Отсутствующий execution verifier не должен запрещать прочитать условный совет. Useful instruction+exception и actual open достаточны; existence refs не фактическая проверка.

Harness2 [context](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/context.py#L1-L260) даёт короткую mission и раскрываемые реальные материалы. Observation truncation и names-only не означают full bytes. [Proposer](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/proposer.py) использует temporary workspace; его cache key не включает model/effort/channel и reader не сравнивает model metadata. Новый run directory, рекомендованный донором, смягчает риск. Reuse допустим как старый proposal, не новый запуск иной модели/независимый исход.

Реальный [eliot.observe](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-app/src/mcp_stdio/verification.rs#L1-L245) сохраняет taskless/cueless input в bound project. Это контрпример глобальному «capture нет». В его теле не найден вызов ExperienceFormation; все downstream workers этим не исключены. Actual capture→interpretation scheduling остаётся в карте.

## 26. Donor mechanisms for useful memory 0.12

[Полный source map и прежние решения](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/841c807659727cd7fb5730331190ee27cd50f47d/docs/v3/AUDIT.md#26-donor-mechanisms-for-useful-memory-012).

**Hindsight.** [Prompts](https://github.com/vectorize-io/hindsight/blob/c5f585f8f8568ed0677eb2e70fe830c4c483e2a2/hindsight-api-slim/hindsight_api/engine/consolidation/prompts.py) и [consolidator](https://github.com/vectorize-io/hindsight/blob/c5f585f8f8568ed0677eb2e70fe830c4c483e2a2/hindsight-api-slim/hindsight_api/engine/consolidation/consolidator.py) обновляют один аспект по existing candidates и пакетируют совместимый материал/embeddings. Optional triage/dedup добавляют вызовы; не весь pipeline «один call». Update target selection не обязательно answer reranking. Донорская observation — синтез, не raw. Запрет вычислений в particular fact prompt не переносится как запрет Dreamer рассуждать.

[Saved mental-model query](https://github.com/vectorize-io/hindsight/blob/c5f585f8f8568ed0677eb2e70fe830c4c483e2a2/hindsight-docs/docs/developer/api/mental-models.mdx) даёт question-shaped project view. В доноре ручная курация/optional auto-refresh; Eliot не наследует approval. Документированная write-time stale detection пропускает deletion, а некоторые tagged views читают untagged без invalidation. Использовать existing source changes; last useful view/direct reads не блокируются.

**MemMachine.** [Declarative retrieval](https://github.com/MemMachine/MemMachine/blob/d5a39a8e774e977fb1e6c22efb03555c4e51e05e/packages/server/src/memmachine_server/episodic_memory/declarative_memory/declarative_memory.py) идёт derivative→source episode→предшествующие/последующие события; facade callers проверены. Это один backend. Берём восстановление ремонта/результата и source dedup, не всю topology и не embedding-before-write как primary capture guarantee.

**Graphiti.** [EntityEdge](https://github.com/getzep/graphiti/blob/3cc723cd292eb5c2ac5ea2c5539270b8e1b6389f/graphiti_core/edges.py) различает valid/invalid/expired; [resolution](https://github.com/getzep/graphiti/blob/3cc723cd292eb5c2ac5ea2c5539270b8e1b6389f/graphiti_core/utils/maintenance/edge_operations.py) выбирает duplicates и broader contradictions отдельно. Смена A→B затрагивает один аспект при разных endpoints. Exact-text fast path не сравнивает interval в этой ветви: при историческом кандидате A→B→A возможна ошибка identity. Upstream filters не полностью проверены, поэтому это условная helper-находка, не reproduced end-to-end defect. Native records/intervals, не universal ontology runtime.

## 27. Episodes, incremental learning and memory feedback 0.13

[Полный отчёт](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/841c807659727cd7fb5730331190ee27cd50f47d/docs/v3/AUDIT.md#27-episodes-incremental-learning-and-memory-feedback-013).

MemMachine TextSegmenter/TextDeriver выполняют обычное разбиение/форматирование, не generative episode reasoning. Source event, search chunk и working episode различаются. Default500codepoints не закон V3; session/task/call links помогают без модели на каждом разрезе.

Реальный SemanticMemory background worker вызывает [ingestion](https://github.com/MemMachine/MemMachine/blob/d5a39a8e774e977fb1e6c22efb03555c4e51e05e/packages/server/src/memmachine_server/semantic_memory/semantic_ingestion.py#L130-L300) для каждого message×category. [LLM helper](https://github.com/MemMachine/MemMachine/blob/d5a39a8e774e977fb1e6c22efb03555c4e51e05e/packages/server/src/memmachine_server/semantic_memory/semantic_llm.py) превращает missing parsed response в empty commands; context overflow и успех другой category могут пометить UID ingested. SQL marker относится к set+history, не category. Это не доказательство удаления raw. Сохранённая новая связная часть и relevant current lessons дают обычный finite job; failed parse не no-change.

[PostgreSQL update context](https://github.com/MemMachine/MemMachine/blob/d5a39a8e774e977fb1e6c22efb03555c4e51e05e/packages/server/src/memmachine_server/semantic_memory/storage/sqlalchemy_pgvector_semantic.py#L330-L395) без vector options выбирает oldest first page default50. Увеличение лимита не находит поздний нужный факт. Dedup удаляет старые features до embedding/replacement отдельными commits: использовать уже выбранную атомарную замену, не новый recovery manager.

Hindsight [content.ts](https://github.com/vectorize-io/hindsight/blob/c5f585f8f8568ed0677eb2e70fe830c4c483e2a2/hindsight-integrations/opencode/src/content.ts) исключает известные injected memory blocks перед retain и recall query; [реальный hook](https://github.com/vectorize-io/hindsight/blob/c5f585f8f8568ed0677eb2e70fe830c4c483e2a2/hindsight-integrations/opencode/src/hooks.ts#L130-L235) это вызывает. Новые corrections/tools сохраняются, собственная вставка не fresh evidence. Plugin читает user/assistant text, не все tool results; whole plugin не coding capture.

[Retain orchestration](https://github.com/vectorize-io/hindsight/blob/c5f585f8f8568ed0677eb2e70fe830c4c483e2a2/hindsight-api-slim/hindsight_api/engine/retain/orchestrator.py#L1830-L2110) различает append/snapshot, условный delta, force_reextract и общий streaming pipeline. Не все backends дают одинаковый delta, полный HTTP/worker commit path не прочитан. Eliot native events просто добавляются и интерпретируются диапазонами; хвост не заменяет весь документ. Краткое «продолжай» использует goal/resources/исходные turns, не обязательного query-rewriter. Fusion/interleave — обычные функции, не новые движки.

## 28. Associations and useful forgetting 0.14

[Полная запись с диапазонами](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/841c807659727cd7fb5730331190ee27cd50f47d/docs/v3/AUDIT.md#28-associations-and-useful-forgetting-014).

**A-MEM.** [Статья v11](https://arxiv.org/html/2502.12110v11) использует enriched representation и evolution descriptions/links. [Библиотека](https://github.com/agiresearch/A-mem/blob/ceffb860f0712bbae97b184d440df62bc910ca8d/agentic_memory/memory_system.py) отдельно от experiment repo: add_note не вызывает analyze_content, indexed document — original content, context/tags metadata. Изменение неиспользуемой metadata само не улучшает retrieval.

find_related_memories возвращает result positions, process_memory применяет их к порядку общего словаря: адресуются не обязательно прочитанные моделью заметки. search_agentic добавляет neighbors после k direct hits, затем возвращает первые k. Neighbor metadata меняется в памяти без немедленного Chroma update; поздняя consolidation не полностью проверена. В Eliot реальные IDs, реально индексируемое описание и related candidates до packing, не дополнительная система доказательств.

**Nocturne.** [Models](https://github.com/Dataojitori/nocturne_memory/blob/1858957bf797722a9b731fb197bd9530f7ae67e4/backend/db/models.py) различают stable node, content version и path. [Renderer](https://github.com/Dataojitori/nocturne_memory/blob/1858957bf797722a9b731fb197bd9530f7ae67e4/backend/system_views.py) даёт useful selected content и child When-to-recall handles; MCP caller проверен. `disclosure` — подсказка когда вспомнить, не ACL. Несколько входов к одному lesson без копий. Не переносить [prompt doctrine](https://github.com/Dataojitori/nocturne_memory/blob/1858957bf797722a9b731fb197bd9530f7ae67e4/docs/system_prompt_en.md): mandatory boot, first-person-only, zero-conflict и fixed node count. Graph transactions не прочитаны целиком.

**Subcog.** [Recall](https://github.com/zircote/subcog/blob/0cd2d4f0cff04938c9f865353fbfefa1b4e3f754/src/services/recall.rs) действительно объединяет native arms, MCP caller есть. Max-normalized1 — relative, не confidence. [Lifecycle service](https://github.com/zircote/subcog/blob/0cd2d4f0cff04938c9f865353fbfefa1b4e3f754/src/services/consolidation.rs) фиксирует importance=.5; [score](https://github.com/zircote/subcog/blob/0cd2d4f0cff04938c9f865353fbfefa1b4e3f754/src/models/consolidation.rs) имеет floor.25, Archive<.2 недостижим. Это алгебра, не live запуск. LRU access не долговременная история; namespace-size heuristic не обнаруженные смысловые contradictions.

Lifecycle consolidate и actual LLM consolidate_memories различаются; последняя имеет callers/source writes. Не вся консолидация фиктивна. No-op link_memories документирован, другие edge writes есть. Fallback all-pairs mesh создаёт n(n−1) направленных связей; summary/source или несколько полезных relations дешевле. Low usage не falsehood/erase: меньше proactive detail, history доступна. Новый опыт может добавить к тому же Nginx-уроку вход SPA/config path без переписывания первоначального события.

## 29. MAGMA and Letta: relations and continuation 0.15

**Новый проход.** Изучены другие роли памяти: почему обход связи добавляет ответу недостающее основание и что нужно сохранять при вытеснении старой переписки из окна. Ни четыре графа MAGMA, ни полный agent runtime Letta не предлагаются как новые компоненты Eliot.

### 29.1 MAGMA: полезная идея — идти по отношению, нужному вопросу

[README](https://github.com/FredJiang0324/MAGMA/blob/467cb70b67ac337b22fdb42194d37c04ad701b62/README.md) и [статья v1](https://arxiv.org/html/2601.03236v1) рассматривают semantic, temporal, causal и entity relations. В прочитанном [query_engine.py](https://github.com/FredJiang0324/MAGMA/blob/467cb70b67ac337b22fdb42194d37c04ad701b62/memory/query_engine.py#L260-L470) тип вопроса определяет предпочтительные links и глубину. Это содержательная идея: «что было после» требует порядка событий, «какой consumer затронут» — структурной связи, «почему изменили» — основания решения.

**Решение Eliot:** обычные typed links в той же SurrealDB, запрос от найденного source/resource к конкретному недостающему соседу. Прямого ответа достаточно — expansion не нужен. Обязательный LLM-router перед каждым recall, четыре БД, universal ontology и второй graph server не требуются. Модельная гипотеза причинности остаётся гипотезой, даже когда хранится как causal link.

### 29.2 Читать надо вызываемый алгоритм, не соседнюю реализацию из статьи

Фактический [QueryEngine.query](https://github.com/FredJiang0324/MAGMA/blob/467cb70b67ac337b22fdb42194d37c04ad701b62/memory/query_engine.py#L700-L875) получает vector, keyword и scan candidates, объединяет RRF, затем при включённом expanded retrieval вызывает `_adaptive_graph_traversal`. В том же файле есть `_probabilistic_beam_search` с intent weights, но данный caller вызывает **не его**. Наличие метода с названием Algorithm1 само не доказывает, что рассматриваемый endpoint исполняет именно его. Другие callers по всему проекту этим не исключены.

Есть конкретная ошибка в [_get_neighbors](https://github.com/FredJiang0324/MAGMA/blob/467cb70b67ac337b22fdb42194d37c04ad701b62/memory/query_engine.py#L1190-L1280). При непустом наборе предпочтений сначала проверяется наличие TEMPORAL, затем через `elif` SEMANTIC и CAUSAL. `multi_hop` передаёт все три; первая ветвь поэтому фильтрует как temporal, а не объединяет разрешённые типы. Особые CONTEXT_NEIGHBOR проходят отдельно — нельзя назвать это полным отсутствием любой поперечной связи.

**Не нужен repair-router поверх router.** В Eliot тип/подтип и направление отношения — обычные параметры запроса. Несколько нужных типов объединяются явным условием выбора, а не взаимоисключающими ветвями классификатора. Код для одного реального вида связи предпочтительнее универсальной схемы с неверной композицией.

### 29.3 Промежуточный узел не обязан повторять слова вопроса

В [_adaptive_graph_traversal](https://github.com/FredJiang0324/MAGMA/blob/467cb70b67ac337b22fdb42194d37c04ad701b62/memory/query_engine.py#L1100-L1280) сосед попадает в очередь только после `_lightweight_keyword_filter`, совпадения query vocabulary и ограничений similarity/drop. Значимый промежуточный объект с иной формулировкой может быть отрезан прежде, чем алгоритм увидит дальнейший ответ. Это вывод о данном условии, не измерение качества MAGMA в целом.

Проектный пример Eliot: «почему экспорт зависает» → обработчик команды → удерживаемая транзакция → ожидание worker. Два средних узла могут не содержать слова «экспорт». Они полезны из-за конкретной связи, не из-за повторения исходной фразы. Разрешить нужный адресный переход не означает обходить весь граф: scope, выбранный relation и конечная порция уже ограничивают работу.

**Наше решение:** искать anchors обычным retrieval; раскрывать структурно обоснованную связь, когда она помогает конкретному вопросу; ранжировать полезный результат и объясняющую цепочку вместе. Не требовать monotonic cosine или lexical match на каждом промежуточном шаге. Поиск соседей не становится самостоятельным автономным агентом.

### 29.4 Ограничение выдачи не ограничивает фактическую работу

Название `_scan_all_nodes` — «fallback», но `query()` вызывает его независимо от того, нашлись ли vector/keyword hits. Сам helper проходит все узлы. `_get_neighbors` при каждом раскрытии перебирает всю коллекцию links. `_adaptive_graph_traversal` заново кодирует anchor/neighbor content через encoder, хотя другие части файла умеют обращаться к сохранённому embedding. Ветвь имеет пределы глубины, соседей и до400 encodings; она **не бесконечна**. Это счётчик обращений к encoder, не доказанные400 платных API calls: способ исполнения encoder отдельно не квалифицирован.

Перенос whole implementation заставил бы ускорять полный scan кэшем и потом чинить кэш. Eliot уже имеет indexed lexical/vector lookup, сохранённые совместимые embeddings и адресные relations. Использовать их напрямую дешевле по числу повторных операций; конкретная latency/RAM не измерялась. Source text не меняется — его сохранённое совместимое представление можно использовать повторно. Нет нужды создавать вторую копию графа ради обхода.

### 29.5 Раскрытая причина должна дойти до ответа

После отбора top nodes `query()` вызывает `_expand_qa_context`, который добавляет ANSWERED_BY/RESPONSE_TO и соответствующий следующий turn. Затем снова выполняется `top_nodes[:top_k]`. Если первоначальные результаты заполнили k, добавленные ответы могут оказаться за срезом. Это конкретный порядок, аналогичный разобранному A-MEM, не отсутствие любых полезных session summaries: они передаются formatter отдельно.

Eliot формирует semantic units **до** финального packing: вопрос+нужный ответ, failed action+repair, утверждение+существенное исключение. Можно кратко передать вывод и source handles, но не считать раскрытие реализованным лишь потому, что сосед был вычислен и затем выброшен. Предел задаётся реальным размером контекста; не требуется фиксированная квота каждому типу узлов.

В `_identify_target_sessions` также виден literal dictionary вроде month→session numbers и тематических слов→фиксированных sessions. Его влияние на все текущие callers здесь не установлено. Это не универсальный temporal resolver и не код для копирования в продукт. Eliot использует время и источники собственного материала. Benchmark-oriented constants не становятся законами памяти.

### 29.6 Letta Code: сжать рабочее окно — не обучить долговременную память

Изучен современный `letta-ai/letta-code`, не прежний D18 server. В [local-backend.ts](https://github.com/letta-ai/letta-code/blob/e8073d4e475ab7f56e76f9aaeea81a7618a92575/src/backend/local/local-backend.ts#L680-L950) реальный caller получает план, вызывает summarizer и затем меняет conversation store. Sliding mode сохраняет часть недавних сообщений, заменяя предыдущую часть summary; при конкретной невозможности sliding planning/достаточного сокращения предусмотрен all path. Нельзя выводить готовность всего донорского host из одного helper, но здесь planner действительно вызывается.

[Compaction code](https://github.com/letta-ai/letta-code/blob/e8073d4e475ab7f56e76f9aaeea81a7618a92575/src/backend/local/compaction.ts) хранит разные prompts для all/sliding. Они просят сохранить goal, существенные детали, ошибки и lookup hints. Перед summarizer длинные tool returns и иногда общий transcript сокращаются с маркировкой. Поэтому summary — **производное представление выбранной части**, а не полная первичная история и не новое независимое evidence. Ошибка генерации не изображается выполненной смысловой работой. Все replay/storage ветви не проверены; гарантия вечного сохранения всего исходного host transcript здесь не заявляется.

**Для Eliot:** continuation card отвечает «что мы делаем, что реально произошло, что ещё открыто, что нужно следующим». Долговременный метод отвечает «что пригодится в другой подходящей попытке». Это разные purpose одной memory/view, не два сервиса. Compaction не должно само создавать permanent lesson или увеличивать его support. Сохранённые Eliot source events остаются адресуемыми; host может получить краткое продолжение и раскрывать детали по мере нужды.

Хост/controller владеет собственным token window и сжатием переписки. Eliot не начинает второе независимое удаление/repacking того же transcript и не требует разрешения на продолжение после summary. Он подаёт доступные цели, решения, текущие ограничения и handles на поддерживаемой host boundary.

### 29.7 Letta reflection: брать фактический материал, не второй цикл управления агентами

[Reflection prompt](https://github.com/letta-ai/letta-code/blob/e8073d4e475ab7f56e76f9aaeea81a7618a92575/src/agent/subagents/builtin/reflection-v2.md) направлен на reusable workflows, ошибки поведения и долговременные сведения, а не копию текущего task status. [Reflection transcript helper](https://github.com/letta-ai/letta-code/blob/e8073d4e475ab7f56e76f9aaeea81a7618a92575/src/cli/helpers/reflection-transcript.ts#L1-L250) описывает source message IDs, tool call/result fields, unreflected и replay slices, отдельный selector prompt. Это содержимое реального исходника, **не доказательство завершённого автоматического scheduling**: полный соответствующий caller в этом проходе не прочитан.

[reflection-runs.ts](https://github.com/letta-ai/letta-code/blob/e8073d4e475ab7f56e76f9aaeea81a7618a92575/src/agent/reflection-runs.ts) реально различает Code-managed localMemfs path и server cutover; явная команда может enqueue cloud reflection без нового model turn. Поэтому одна надпись «cloud required» у низкого API не доказывает, что никакой локальной reflection вообще нет. Серверное исполнение по этой квитанции не проверено.

Eliot берёт подходящие already-saved episode slices и relevant methods через собственный existing job. Старый материал можно намеренно переосмыслить для аналогии/противоречия, но replay не новый observed success. Если работа и новый диапазон уже известны, отдельный модельный селектор всех бесед не обязателен. Provider execution остаётся у controller; ещё один subagent scheduler, memory filesystem и cloud ownership protocol внутри памяти не создаются.

Не переносим prompt-пожелание всегда разрешать противоречие в пользу latest evidence как универсальный last-write-wins. Новый input может быть старым импортом, цитатой или другим scope. Сохраняются уже заданные distinctions времени/перспективы/источника. Одна редкая серьёзная ошибка тоже может дать полезный совет; повторяемость не admission gate.

### 29.8 Связный механизм без новых слоёв

Пример — проектное решение, не runtime результат. При вопросе о зависшем backup обычный поиск находит прежний эпизод. Нужная связь раскрывает, что worker ждал lock, удерживаемый вызывающей стороной. Compiler сохраняет это основание рядом с советом, а подробный trace оставляет в `open`. После смены окна continuation view помнит незавершённую правку и фактический результат последнего запуска. Долговременный урок о порядке ожидания хранится отдельно по назначению и обновляется новым реальным исходом, не повтором summary.

Реализация укладывается в `context` (indexed retrieval, relation expansion, semantic packing), `memory` (source-linked views) и уже существующие `jobs`/controller для нужной интерпретации. Удаляется обязанность полных scans, повторного encoding и второго управления transcript, а не добавляется контролёр, разрешающий эти операции.

### 29.9 Охват, ограничения и следующий шаг

Свежепрочитаны MAGMA README, paper methods и query_engine selected ranges с фактическим query→adaptive→neighbor→packing путём; Letta compaction planner/summarizer, actual local backend caller, выбранные local-store ranges, reflection prompt, transcript helper и command ownership/enqueue. Отдельный probabilistic search не назван исполнителем прочитанного query. Полный server-side reflection, application всех local-store replay events и archived Letta D18 не квалифицированы.

Несколько попыток получить предполагаемые reflection paths оказались неудачными; после проверки имён через code search прочитаны реально существующие helper/command files. Неуспешные fetches не засчитаны как чтение и не использованы как доказательство отсутствия функции. Точно так же локальная сеть не дала загрузить рабочую копию: публикация идёт доступным GitHub API, без выдуманного локального diff-check.

Новых runtime, model, database, synthetic или продуктовых тестов не запускалось; нет независимого субагентного review. Следующий конкретный источник — полезная автоматическая адресация/предвосхищение из D10/D11 EverOS/EverMemOS либо ещё не завершённый Eliot capture→interpretation trigger. Выбор определяется пробелом продукта, а не обязанностью импортировать очередного донора.

## 30. EverOS and EverMemOS: anticipation and evidence coverage 0.16

**20 октября 2026; база документации `48a62245`.** Текущий EverOS прочитан на `c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18`; историческая статья EverMemOS — отдельно. Сходные имена типов не устанавливают одинаковый runtime или одинаковые результаты.

### 30.1 Две версии источника, а не одна обещанная система

[EverMemOS 2601.02163v1, §§3.2–3.5](https://arxiv.org/html/2601.02163v1) описывает MemCell с Episode, Atomic Facts, Foresight и source metadata; MemScenes группируют материал для последующего раскрытия. Foresight имеет временную область, а chat context дополнен профилем и подходящими прогнозами. В §3.5/Appendix A.1 авторы прямо отделяют это от обычной количественной оценки episodes-only: Foresight показан качественными примерами, не измеренным предотвращением ошибок coding-агента.

Нынешние [architecture](https://github.com/EverMind-AI/EverOS/blob/c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18/docs/architecture.md) и [write/index/read guide](https://github.com/EverMind-AI/EverOS/blob/c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18/docs/how-memory-works.md) описывают Markdown-память, SQLite state, derived index и offline strategies. MemCell/Foresight здесь тоже существуют; это не повод объявлять старую схему целиком исчезнувшей или текущую реализацию подтверждением всех свойств статьи. Часть алгоритмов импортируется из отдельных `everalgo` packages, исходники которых в этом проходе не прочитаны. Топология донора не меняет выбранную SurrealDB/Rust основу Eliot.

### 30.2 Предвосхищение без потребителя остаётся платной записью

В [extract_foresight.py](https://github.com/EverMind-AI/EverOS/blob/c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18/src/everos/memory/strategies/extract_foresight.py) фактический decorator задаёт `enabled=False`. Автор объясняет: один LLM call на user sender на MemCell создаёт данные, которые стандартная выдача не потребляет. Тело функции действительно обходит user senders, вызывает extractor отдельно для каждого и пакетирует запись по owner. Сохраняются parent/session, Evidence и отдельный Foresight, опционально start/end/duration. Исправленная фильтрация `ChatMessage` не обращается к отсутствующему role у tool-result; прежний crash из комментария не выдаётся за нынешний дефект.

Проверена не только эта декларация. [HTTP route](https://github.com/EverMind-AI/EverOS/blob/c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18/src/everos/entrypoints/api/routes/search.py) вызывает [service.search](https://github.com/EverMind-AI/EverOS/blob/c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18/src/everos/service/search.py), который создаёт [SearchManager](https://github.com/EverMind-AI/EverOS/blob/c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18/src/everos/memory/search/manager.py). User path формирует episodes/profile/unprocessed, agent path — cases/skills/unprocessed. Foresight recaller и поле его выдачи в этом построении отсутствуют. Это конкретный стандартный consumer, не исчерпывающий поиск каждого возможного custom reader или доказательство невозможности прочитать сохранённый Markdown.

**Для Eliot:** существующая интерпретация эпизода может сохранить условную будущую потребность или риск рядом с основанием, а обычный `context` показывает его при релевантном решении. Уже явный план не требует ещё одного предсказательного вызова. Формат «при этих условиях полезно проверить X, поскольку в эпизоде Y произошло Z» даёт действие и ограничение; отдельная ForesightDatabase или бесконечный predictor на каждом сообщении не нужны. Без пути до контекста генератор не считается законченной когнитивной функцией.

### 30.3 Срок прогноза не превращается в факт исполнения

Это **наше проектное различие**, а не найденный end-to-end дефект EverOS. В записи отделяются исходно названная дата, модельная оценка периода полезности и наблюдённый исход. Истечение inferred window может уменьшить навязчивую выдачу, но не отменить явное обязательство или доказать изменение мира.

Пример: «мигрировать в пятницу» без результата в субботу означает неизвестный статус миграции. Это не «миграция состоялась», не бесконечное повторение тревоги и не основание забыть требование. При следующей связанной работе полезен адресный статус/проверка; реальный результат или изменение цели обновляет прежнюю запись. Existing attention dedup, time comparison и обычный context suffices; отдельный timer/expiry runtime не требуется. [Cognition §7](COGNITION.md#7-attention-prediction-and-cognitive-failure).

### 30.4 Раскрыть выбранную группу, не загрузить сначала всю область

В настоящем `_search_episodes` [manager](https://github.com/EverMind-AI/EverOS/blob/c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18/src/everos/memory/search/manager.py#L330-L490) режим `AGENTIC` вызывает [search_episodes_agentic](https://github.com/EverMind-AI/EverOS/blob/c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18/src/everos/memory/search/agentic.py). До cluster selection эта функция получает cluster snapshot и `fetch_all_for_owner(where)`. [Реализация recaller](https://github.com/EverMind-AI/EverOS/blob/c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18/src/everos/memory/search/recall/episode.py) вызывает `episode_repo.scan(where)` без limit, материализуя всю подходящую область. `where` сохраняется: это не утверждение о чтении всех проектов без фильтра.

Далее полная коллекция передаётся imported cluster helper. Предел финальных результатов не ограничивает уже загруженные данные. Константа child_candidates=100000 здесь sentinel для retrieval, а не измеренные сто тысяч API calls. Обычные KEYWORD/VECTOR/HYBRID paths отдельные; их нельзя обвинять в этом prefetch по аналогии.

**Малое решение Eliot:** группа помогает найти связанные эпизоды, но их IDs выбираются до hydration; native query читает нужных участников. Existing views/links достаточны. Тематическая близость не означает одну текущую истину и не добавляет независимое подтверждение. Не переносить полный in-memory corpus и затем строить cache для его ускорения. [Cognition §5.3](COGNITION.md#53-recover-the-episode-not-just-the-matching-fragment).

### 30.5 Разные части вопроса нельзя заменять голосованием похожих запросов

У текущего EverOS есть отдельный `LLM_MULTIROUND`, вызываемый тем же manager, не тождественный `AGENTIC`. В [llm_multiround.py](https://github.com/EverMind-AI/EverOS/blob/c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18/src/everos/memory/search/llm_multiround.py#L700-L1005) каждый sub-query получает свои sparse/dense candidates и свой RRF block. Decider видит исходный вопрос, блоки и сохранённое core; indices переводятся обратно в реальные IDs. Есть предел rounds и остановка после отсутствия новых core/следующих queries. Это реально вызываемый цикл, но его модельные решения и качество здесь не запускались.

Полезен принцип **сохранять роль найденного источника в ответе**. Источник, найденный только вопросом об исключении, не хуже от того, что десять общих перефразировок его не нашли. Для Eliot конкретный missing aspect обосновывает адресное раскрытие или дополнительный поиск; дорогая модельная доработка остаётся отдельным конечным запросом, не допуском перед каждым чтением.

Есть важная граница обещания «всё core и по источнику на каждый sub-query». Фактический finalizer при `core_overflow=false` ограничивает core по top_k, а per-query guarantee заполняет лишь оставшиеся места. Полное core может занять весь бюджет, и последующая «гарантия» ничего не добавит. Это не само по себе ошибка соблюдения лимита; ошибка была бы заявить полноту после потери единственного нужного основания. Несколько удачных intermediate selections не равны delivered coverage.

В Eliot сборщик сохраняет необходимые premises/исключения, делает qualified compression или показывает оставшийся пробел и `open`. Не назначается обязательная квота каждому искусственному sub-query. Model sufficiency, отсутствие новых hits и исчерпание бюджета — разные причины остановки, а не три доказательства полного ответа. [Cognition §5.7](COGNITION.md#57-cover-the-missing-aspect-not-more-copies-of-the-same-answer).

### 30.6 Фоновая работа не должна занимать всю интерактивную ёмкость

В [embedding provider](https://github.com/EverMind-AI/EverOS/blob/c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18/src/everos/component/embedding/openai_provider.py) `embed_query` передаёт отдельный semaphore в тот же `_embed_chunk`; batch writes используют write semaphore. [Factory](https://github.com/EverMind-AI/EverOS/blob/c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18/src/everos/component/embedding/factory.py) действительно передаёт оба параметра, а прочитанный search path вызывает `embed_query`. Это не только release-note рекомендация. Разделение снимает ожидание за локальной write-очередью, но не гарантирует отсутствие задержек у самого endpoint; максимумы двух групп суммируются.

**Eliot:** использовать уже существующие возможности controller для foreground/background или ограничить background dispatch так, чтобы запросу оставалась ёмкость в общем лимите. Batching сохранённых совместимых inputs уменьшает давление. Недоступный vector path не выключает exact/lexical. Не заводить второго provider scheduler и не считать разделённые очереди дополнительной квотой сервиса. [Cognition §5.1](COGNITION.md#51-independent-candidates-not-a-dense-only-lexical-reranker).

### 30.7 Что изменено и предел проверки

Изменены конкретные механизмы Cognition §§5.1,5.3,5.7,7 и source decisions; D10/D11 и карта уточнены. Architecture 0.6, Implementation 0.11, исходные 34 требования, 29 A15 cases и 36 cognitive walkthroughs не перерабатываются этим донором. Предыдущие находки не объявляются заново проверенными. Новых record families, сервисов, approval stages и runtime dependencies нет.

Прочитаны current README/docs; foresight strategy; HTTP→service→SearchManager; agentic и episode recaller; multi-round header и actual loop/finalizer; embedding provider/factory. Не прочитаны все OME jobs, `everalgo` extraction/ranking internals, полный persistent intake/recovery и исторический runtime статьи. Поэтому декларации о rebuildability, отсутствие всех custom consumers и качество предсказаний глобально не квалифицированы. Несовпадение имён/версий и неудачный fetch не заменяют такой проверки.

Это source reading и проектные выводы: доноры, модели, БД, benchmarks, synthetic tests и Rust/Clippy не запускались; независимого субагентного review нет. Предыдущий CI run 39431478163 проверен отдельно и завершился failure; причина не приписывается автоматически старым CI-находкам. Новая публикация и её фактический workflow status отражаются в PR. Следующий приоритет карты — реальный Eliot capture→interpretation trigger и оставшаяся исходная автономность, не очередной обязательный memory runtime.

## 31. Real interpretation, not validation-shaped learning 0.17

**20 октября 2026; база документации `966650aa`.** Новое чтение V2 `5aac0948` продолжает незакрытый вопрос §25.7: что происходит после сохранения реального наблюдения и какие данные в действительности интерпретирует Dreamer. D20 Mem0 на `0724291b` рассмотрен как конкретный работающий по исходнику extraction path, не как обещание качества или готовая замена Eliot.

### 31.1 После capture действительно есть работа — но это проекции

[dispatch_observe](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-app/src/mcp_stdio/verification.rs#L20-L155) передаёт observation payload как `ClaimPropose` в `WriterHandle::submit`. В [writer.rs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/writer.rs#L2005-L2410) обработчик вызывает `store.apply_write_envelope`; после принятой записи `handle_store_receipt` отмечает commit и уведомляет настроенный `projection_notifier`. Это реальный вызов, не только объявленный интерфейс.

[Coordinator](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-engine/src/cognitive_projection.rs#L260-L530) выполняет очередь через `background_step` → `process_claimed_lease` → `process_family`. Последний исчерпывающе разбирает Search, Cue, DependencyDirty; Utility возвращает отказ до Phase 2. Эти ветви перестраивают/обновляют поиск, cues и зависимости. Они не вызывают модель и не формируют опыт из исходного эпизода.

**Вывод ограничен этой цепочкой:** post-commit maintenance существует, но это не найденный автоматический Dreamer producer. Не заявляется отсутствие любого другого scheduler во всём V2. Полная регистрация всех workers и альтернативные daemon paths ещё не прочитаны. Полезное свойство сохранено: notification здесь служит ускоряющим сигналом поверх durable работы, а не основанием объявить raw потерянным при заполненном канале.

В V3 searchable capture и смысловая интерпретация остаются разными полезными операциями. Завершение индексации не должно помечать эпизод интерпретированным; наоборот, отсутствие модели не должно откатывать уже сохранённое и доступное наблюдение. Второй coordinator для удостоверения этого различия не нужен.

### 31.2 Снять ранний отказ недостаточно: дальше нет модельной интерпретации

В [main.rs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/main.rs#L25-L95) staged input направляется в `service.submit`, а отсутствие input — в `service.status`. Успешно отданный status не доказывает исполненного inference. В [реальном submit](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/lib.rs#L740-L810) Curation отделён ранней ветвью; остальные классы проходят `resolve_cycle_inputs`, bundle и `run_admitted_pipeline`.

Ранее найденный [resolve_cycle_inputs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/controller.rs#L58-L88) после проверки аргументов безусловно возвращает Err об отсутствующем Governor-resolved material. `controller.rs` в этом бинаре — внутренний pure cycle, **не** доказанный вызов внешнего `eliot-swarm-controller`.

Новый предметный результат — что находится дальше этого отказа. [model_stage.rs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/model_stage.rs#L45-L220) сам строит `StructuredModelDraft` с пустыми `claims` и `non_material_claims`. `run_admitted_model` вызывает только `draft.validate()`, пересчитывает digest и возвращает тот же draft. В этой реализации нет provider call, controller execution или чтения полученного извне модельного ответа. `raw_output_digest` вычислен из job/question/scope/request, не из bytes ответа модели.

Это не утверждение, что deployed процесс уже сохранял фиктивный результат: non-Curation путь ранее останавливается, Curation имеет отдельный carrier. Это показывает, почему замена одного Err на Ok не восстанавливает продукт. Дальнейшая функция с названием «model» всё равно не совершает требуемого преобразования. Нужен настоящий вызов над данными, а не ещё один адаптер допуска к этой локальной проверке.

### 31.3 Ссылки на материал не заменили сам материал

[admitted_material.rs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/admitted_material.rs#L1-L310) формирует пустой reference manifest. Evidence handles включаются в bundle обычно с `bytes=0` и hash строки handle; отдельный первый Orientation handle описывает локально построенный frame, не загруженный source. Memory/architecture/implementation/conformance handles переходят в omissions, если уже не перечислены как evidence. `PartialForScope` честно обозначает неполноту, но не создаёт доступ к содержимому.

В [v1_model_of](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/admitted_material.rs#L465-L550) поле `statement` получает `job.exact_question.clone()`: вопрос оказывается единственной гипотезой. Последующий residue помечен Partial, а не подтверждённым фактом. Следовательно, проблема не обязательно в завышенном epistemic статусе; **полезного модельного ответа вообще не появилось**.

Для V3 источник передаётся как реальный нужный текст/структурированное событие либо как handle с реально доступным модели `open`. Один hash, имя файла или ID не считается прочитанным содержимым. Исправление — загрузить выбранный эпизод и нужные existing lessons через обычный Store; не строить новую систему доказательств чтения.

### 31.4 Проверялась форма операции, а не её смысл

В [usage_of и preservation_of](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/admitted_material.rs#L365-L455) первая функция подставляет бюджетные пределы в usage, включая положительные model_calls/attempts/candidates; вторая ставит всем перечисленным измерениям `passed=true, known=true` с оговоркой о candidate-only сохранении handles. `run_admitted_pipeline` передаёт в validation наблюдаемое время `Some(0)`. Эти значения характеризуют собранную локальную форму, не измеренные inference, смысловую сохранность исходного эпизода или реальную длительность обработки.

Нельзя расширять вывод до «весь учёт провайдера подделан»: отдельный `ModelRouteUsage::measured` принимает явное число calls, а найденный вызов в `dispatch_stage.rs` передаёт 0. Есть и явные Partial/candidate-only ограничения. Именно сосуществование этих разных смыслов под именами model/usage/preservation опасно для дальнейшего разработчика.

В существующем [тесте owner_model_call_runs_exactly_once_per_admission](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/model_stage.rs#L515-L560) счётчик считает вызов closure над локальной валидацией. Такой тест проверяет ровно свою функцию, но не наличие inference. Исходник не доказывает намерений автора или историю возникновения дефекта; он доказывает несовпадение проверенной операции с продуктовым смыслом её названия.

**Решение:** удалить подменяющие смысл формы из V3-пути, а не добавить проверяющий их проверяющего. Фактический controller result и известное usage приходят от исполнителя. Неизвестное остаётся неизвестным. Детерминированное сохранение прямой поправки пользователя полезно без LLM и называется именно сохранением поправки, а не успешно выполненным модельным обучением.

### 31.5 D20 Mem0: реальное извлечение короче аппарата его удостоверения

Текущий [README](https://github.com/mem0ai/mem0/blob/0724291bd864cf807e88ee8981c8226644e8fb42/README.md#L55-L85) описывает ADD-only алгоритм и прямо относит свои benchmark scores к managed platform с недоступными в OSS оптимизациями. Числа не переносятся на библиотеку или Eliot. Устаревшая формулировка docstring про UPDATE/DELETE также не важнее фактически вызываемого тела.

Прослежен [Memory.add → _add_to_vector_store](https://github.com/mem0ai/mem0/blob/0724291bd864cf807e88ee8981c8226644e8fb42/mem0/memory/main.py#L840-L1110): берутся recent messages и похожие существующие memories, формируется текст и вызывается настоящий `self.llm.generate_response`. Затем тексты результата пакетно embedding/persist; в выдачу ADD включаются подтверждённые этой ветвью сохранённые records. Это реальная по исходнику передача материала и обработка ответа, не renderer статуса. Синхронный метод не объявляется автоматическим background worker.

**Берём:** компактное преобразование нового материала вместе с относящейся памятью, один явный extraction call на такую порцию, пакетирование совместимых последующих операций. **Не берём целиком:** отдельные vector/history/entity stores, hosted показатели, обязательный ADD-only как решение current-state Eliot или приравнивание agent narration к наблюдённому результату. Сохранение истории и адресная поправка обычного lesson уже согласованы; ещё один update/delete framework не требуется.

### 31.6 У простого донора тоже нужно проверять настоящий вход и неуспех

В вызываемом [parse_messages](https://github.com/mem0ai/mem0/blob/0724291bd864cf807e88ee8981c8226644e8fb42/mem0/memory/utils.py#L62-L80) выводятся только textual system/user/assistant. `content=None` пропускается, и role `tool` не имеет ветви даже при наличии content. Значит, обычное tool-result сообщение и связь call/result не входят в этот extraction text. Host может заранее переложить их в другой текст или иметь иной путь; эта находка не утверждает потери каждого инструмента во всех интеграциях Mem0. Для coding-памяти Eliot adapter сохраняет и рендерит реальные результаты с доступными call IDs, не требует модели угадывать выполнение по рассказу агента.

В том же [extraction block](https://github.com/mem0ai/mem0/blob/0724291bd864cf807e88ee8981c8226644e8fb42/mem0/memory/main.py#L930-L1010) provider exception уже поднимается как `LLMError` — это полезный countercheck. Но ошибка разбора ответа логируется и превращается в `extracted_memories=[]`; далее исходные messages сохраняются и API возвращает пустой результат, как при законном отсутствии новых фактов. Ошибка и no-change различаются в логе, но не в этом возвращаемом результате. В V3 такой случай остаётся причиной незавершённой интерпретации существующего job, не успешным завершением диапазона.

Это также не готовый raw-first capture: normal path выполняет embedding/search/model до завершающего `save_messages`, а `infer=False` всё ещё получает embedding до `_create_memory`. Внешний host может сохранять оригинал независимо, однако сам рассмотренный helper этого не гарантирует. Сначала сохранить событие в Eliot, затем интерпретировать — уже выбранное простое решение; дополнительный admission протокол не нужен.

### 31.7 Конкретная соединённая реализация V3

Ниже **проектное применение**, не найденный готовый V2 API и не выполненный V3. Оно уточняет существующие [Implementation §§3,5,7](IMPLEMENTATION.md#3-host-interface-and-experience-intake) и [Cognition §6.8](COGNITION.md#68-one-episode-to-a-useful-next-attempt), не создаёт новых владельцев.

| Операция | Кто и что реально делает |
|---|---|
| Сохранить | `capture` записывает исходное событие и необходимый pending intent в той же primary transaction. Session/call/source identity достаточно; не выдумывается отдельный task ради формы |
| Взять материал | Уже существующий job worker получает сохранённую необработанную часть эпизода и небольшой подходящий контекст. Job обслуживается обычным startup/polling; wake ускоряет работу, но не является её единственной памятью |
| Интерпретировать | Adapter controller передаёт выбранное содержимое действительной модели и получает её ответ. Tool results не исчезают в chat-only formatter. Прямая явная поправка может обойти этот вызов, не притворяясь inference |
| Сохранить и использовать вывод | Обычный memory write сохраняет полезные lessons/amendments либо настоящий keep и обработанный диапазон. `context`/`open` читают эти же записи. Дополнительные embeddings и views не держат primary advice закрытым |

Worker не должен ждать, когда другой будущий сервис заполнит причинность, готовый урок или «доказательство понимания»: извлечение этих полезных сведений и есть его работа. Отсутствующее основание остаётся неизвестным. После новых событий coalescing меняет сигнал/следующий диапазон, не удаляет ещё не разобранные observations. Повторная индексация не запускает бесконечное переобучение той же порции. Эти правила используют уже предусмотренные source IDs и job progress, не новые сертификаты полноты.

Пример: host сохранил изменение API, фактический failed check, ремонт consumer и следующий результат. Dreamer получает эту последовательность, а не четыре hash строки; может выделить «перед изменением сигнатуры проверить consumers» с существенным ограничением. Следующее обращение к этому API получает сам совет через обычный контекст. JSON parse error оставляет интерпретацию незавершённой, но исходные события всё равно доступны. Это содержательная работа от входа до следующего действия, не цепь локальных PASS над пустыми носителями.

### 31.8 Охват и оставшийся вопрос

Свежие V2 reads: observe 1–260; writer 1–320,1000–1340,1570–1840,1910–2470; cognitive_projection 1–690; Dreamer main 1–230, lib 1–240 и640–850, controller 1–170, model_stage 1–540, admitted_material 1–555. Navigation в MCP и dispatch показывает направления, но не заменяет полного чтения регистрации или альтернативных workers. Исходная блокировка и отсутствие содержательной работы за ней различены; Curation не объединён с non-Curation.

Свежие D20 reads: README45–135, Memory main 1–250,480–1120,1170–1255 и utils1–130; не весь AsyncMemory, retrieval, entity cleanup или hosted platform. Следующий связанный вопрос — конкретный production controller route и другой реальный producer, если он нужен для оценки донора; затем возвращение к исходной автономности и долговременному использованию уроков. Нельзя вновь отмечать «модель подключена» только по наличию `ModelRouteRequest`.

Продукт, модель, БД, Rust/Clippy, synthetic probes и donor benchmarks не запускались; независимого субагентного review нет. Тестовый исходник прочитан как свидетельство того, что он считает, не как новая тестовая программа. Новых services, stores, dependencies, workflow gates или runtime изменений нет. Architecture, Implementation и Cognition не переписываются ради повторения уже принятых правил; конкретный разбор и соединение сведены здесь. Публикация и реальный CI status отражаются в PR, не подменяются сертификатом чтения.

## 32. Host capture and non-destructive continuation 0.19

**20 октября 2026; база `815f51e5`.** В ответ на просьбу о субагентах проверены доступные инструменты/исполнители; вызова запуска GPT Luna или другого подходящего субагента в этой сессии нет. Новые агенты не созданы и независимое review не заявляется. Вместо имитации параллельной проверки выполнено предметное чтение двух пропущенных доноров: D45 claude-mem и D46 OpenHands Software Agent SDK. Другие ранее названные направления не отмечаются завершёнными.

### 32.1 claude-mem: полезна развязка захвата и дорогой обработки

На `9e4f313a` прочитаны [архитектура](https://github.com/thedotmack/claude-mem/blob/9e4f313a89236f7fb593a639a77ee02e21e94469/docs/public/architecture/overview.mdx), настоящая [регистрация hooks](https://github.com/thedotmack/claude-mem/blob/9e4f313a89236f7fb593a639a77ee02e21e94469/plugin/hooks/hooks.json), [observation handler](https://github.com/thedotmack/claude-mem/blob/9e4f313a89236f7fb593a639a77ee02e21e94469/src/cli/handlers/observation.ts) и [spool handoff](https://github.com/thedotmack/claude-mem/blob/9e4f313a89236f7fb593a639a77ee02e21e94469/src/cli/spool-hook-event.ts). PostToolUse и PostToolUseFailure ведут в observation. В worker-ветви сохраняются реальные input/result, session, agent и tool-use IDs, затем `HookSpool.enqueue` вызывается **до** best-effort nudge. Handler не ждёт запуска модели или готовности semantic worker. Выход hook всё же может подождать ограниченный poke до250мс: «никакого ожидания вообще» было бы неточно.

Есть отдельная server-ветвь с сетевым `recordEvent` и собственными правилами ошибок/fallback. Вывод о локальном spool нельзя распространять на все режимы. Низкоуровневые file durability primitives HookSpool не проверены, поэтому исходный комментарий «durable» не является нашим power-loss испытанием.

В [GeneratorRunner](https://github.com/thedotmack/claude-mem/blob/9e4f313a89236f7fb593a639a77ee02e21e94469/src/services/worker/session/GeneratorRunner.ts#L140-L240) прочитан настоящий выбор provider и вызов `agent.startSession` с состоянием очереди. Это не полный просмотр транспортного запроса/ответа каждой модели и не доказательство ровно одного model call на событие. Достаточно установить полезную границу: приём источника и дорогое толкование не одна синхронная операция.

**Для Eliot:** сохранять исходный event обычным Store либо уже предусмотренным spool при его недоступности; будить существующий worker; читать необработанный связный диапазон для интерпретации. Не переносить Express/Bun, SQLite+Chroma, все provider adapters и remote-spool protocol вместе с этой идеей. Не нужна вторая очередь над уже сохранённым pending intent.

### 32.2 Экономить интерпретацию, не терять работу субагентов по умолчанию

В [should-skip-agent-observation.ts](https://github.com/thedotmack/claude-mem/blob/9e4f313a89236f7fb593a639a77ee02e21e94469/src/shared/should-skip-agent-observation.ts) описана нагрузка от fan-out: много дочерних tool events вызывают дорогое наблюдение и давят на квоту. В коде есть общий переключатель и список типов для пропуска subagent events **до** записи через hook. Важный countercheck: default toggle выключен, список пуст, поэтому нельзя говорить «claude-mem всегда выбрасывает работу субагентов». Event считается дочерним при нужной комбинации agent ID/type, не по одному случайному полю.

**Выбор V3:** различать разрешённый захват исходников и решение тратить inference. Сохранённая работа конкретного ребёнка с его session/call связями может быть полезной даже без немедленного отдельного урока. Coalescing объединяет поводы/диапазоны обработки, не независимые события и не все дети в один причинный эпизод. Повторы транспорта можно убрать по настоящей identity, а read-back собственной памяти — не считать новым подтверждением. Явное исключение владельцем источника остаётся исключением, но обычное исчерпание модельного бюджета не должно молча подменять capture policy.

Это не поручение строить собственный swarm manager. Владелец исполнения остаётся controller/host; Eliot получает уже известные идентификаторы и реальные результаты. Частоту interpretation регулирует существующая фоновая работа, а не классификатор перед каждым tool.

### 32.3 Стабильный контекст дешевле постоянного пересоздания, но не запрещает поправки

[Коммит claude-mem от19.10.2026](https://github.com/thedotmack/claude-mem/commit/9e4f313a89236f7fb593a639a77ee02e21e94469) переносит Antigravity injection с каждого PreInvocation на SessionStart. Авторы связывают динамические повторные вставки с потерей prefix cache; их численные замеры не воспроизводились и не считаются обещанным выигрышем Eliot.

Проверено настоящее поведение Claude-ветви: hooks регистрируют `context` на startup/clear/compact, но не resume; [context handler](https://github.com/thedotmack/claude-mem/blob/9e4f313a89236f7fb593a639a77ee02e21e94469/src/cli/handlers/context.ts#L170-L260) дополнительно возвращает пустой результат на resume, чтобы не менять прежний prefix. Отдельный file-context hook остаётся; этот early return не доказывает отсутствия всех последующих путей выдачи нового знания.

**Наше применение:** не переписывать неизменённую orientation и не добавлять бессодержательные timestamps на каждом вызове модели. При реальном изменении важного метода или появлении результата подавать небольшое актуальное дополнение на поддерживаемой границе решения. Не копировать blanket правило «на resume ничего нового»: новая поправка может иметь больший смысл, чем сохранение старого cache. Отправлять дельту или current view — работа существующего `context`, а не CachePermissionService. Эффект на стоимость зависит от конкретного host/provider и не установлен одним чтением.

### 32.4 OpenHands: разрез определяется связями событий, не десятью репликами

На `0996c339` прочитаны [condenser documentation](https://github.com/OpenHands/software-agent-sdk/blob/0996c33916c2a977ea9fe38deee660ff0e1389f2/openhands-sdk/openhands/sdk/context/condenser/README.md), [LLMSummarizingCondenser](https://github.com/OpenHands/software-agent-sdk/blob/0996c33916c2a977ea9fe38deee660ff0e1389f2/openhands-sdk/openhands/sdk/context/condenser/llm_summarizing_condenser.py), [ToolCallMatchingProperty](https://github.com/OpenHands/software-agent-sdk/blob/0996c33916c2a977ea9fe38deee660ff0e1389f2/openhands-sdk/openhands/sdk/context/view/properties/tool_call_matching.py) и [ToolLoopAtomicityProperty](https://github.com/OpenHands/software-agent-sdk/blob/0996c33916c2a977ea9fe38deee660ff0e1389f2/openhands-sdk/openhands/sdk/context/view/properties/tool_loop_atomicity.py). `_get_forgotten_events` выбирает начало/конец через допустимые manipulation indices. Pending set конкретных call IDs не позволяет разрезать незавершённую пару action/result; отдельные правила учитывают provider-specific непрерывные tool loops и сохранённый prefix. Это обычная обработка событий, не модельный поиск границы каждого сообщения.

Реальное применение condenser найдено в [prepare_llm_messages/aprepare_llm_messages](https://github.com/OpenHands/software-agent-sdk/blob/0996c33916c2a977ea9fe38deee660ff0e1389f2/openhands-sdk/openhands/sdk/agent/utils.py#L570-L700): helper вызывает condense/acondense и возвращает изменённую View либо событие Condensation. Полный runtime всех агентов не запускался. Поиск symbol использовался только для нахождения этой функции.

**Eliot:** при подготовке эпизода держать связанные действия и результаты вместе по их настоящим IDs, учитывая interleaving нескольких вызовов. Фиксированное «примерно10 реплик» из прежнего предложения — возможный размер порции, не смысловая граница. Большой результат можно адресно сократить с handle к исходнику; недостающий результат остаётся неизвестным и не блокирует сохранение всех остальных событий.

Provider-specific требования к сериализованному transcript не становятся общими запретами памяти. OpenHands может удалить orphan из модельной View ради формата API; Eliot не обязан удалять исходное наблюдение без пары. Для его понимания не требуется собирать скрытое рассуждение модели или переносить checksums thinking blocks в собственный формат событий.

### 32.5 Сжатие — новая View, не уничтожение источника и не новое evidence

В [Condensation.apply](https://github.com/OpenHands/software-agent-sdk/blob/0996c33916c2a977ea9fe38deee660ff0e1389f2/openhands-sdk/openhands/sdk/event/condenser.py) забываемые IDs фильтруются из списка для модели, а summary добавляется как производное событие. Документированный исходный журнал остаётся append-only. Полезно разделение источника и рабочего представления, но Eliot не нужен второй журнал рядом с его уже сохранёнными observations: он хранит source range/handles в обычной continuation view.

Есть конкретная граница корректности. `_generate_condensation` и async-вариант извлекают текст только из первого content block. При пустом content или первом не-TextContent `summary` остаётся None, однако возвращается объект с непустыми forgotten IDs. Пустая строка также не отклоняется. `RollingCondenser` возвращает этот объект без проверки содержательной непустоты, а `Condensation.apply` сначала убирает названные события и лишь при наличии summary metadata вставляет сводку. Поэтому **в этом пути допустимо сокращение рабочего контекста без полезного заменяющего текста**. Исходный журнал этим не стирается; частота такого ответа модели и дальнейшее восстановление во всём приложении не проверены. Это source-level последовательность, не reproduced deployment incident.

**Прямое решение V3:** не подменять существующую полезную continuation view пустым или неразобранным ответом. Это проверка результата обычной функции, не LLM-оценщик качества и не proof service. При реальном исчерпании окна нельзя просто снова послать заведомо слишком большой prompt: хост выбирает поддерживаемое сокращение/новый handoff, а Eliot предоставляет доступные цель, недавние факты и source handles с честным обозначением неполноты. Старые sources остаются читаемыми. Успешное создание summary не повышает support долговременного урока.

### 32.6 Что берём и чего не создаём

| Нужная работа | Механизм внутри существующей V3 |
|---|---|
| Принять реальный результат, пока модель недоступна | Сохранить event; существующий job интерпретирует позже. Nudge ускоряет, не удостоверяет сохранение |
| Учесть работу нескольких агентов без взрыва inference | Идентичности потоков и диапазоны исходных событий; batching выбранного материала, не обязательный model call на каждый hook |
| Не повторять один дамп бесконечно | Повторно использовать неизменённую orientation; показывать содержательно новые уточнения, не текущую дату ради новизны |
| Подготовить связный эпизод | Соотнести actual call/result IDs и границы работы; incomplete input не удаляется ради красивого протокола |
| Продолжить после сжатия | Производная view с источниками; не пустая замена и не второй владелец host context window |

Эти применения уточняют [Implementation §§3,5](IMPLEMENTATION.md#3-host-interface-and-experience-intake) и [Cognition §5.6](COGNITION.md#56-continuation-is-not-durable-learning), где owners уже определены. В этот проход они не переписываются ради повторения принципов. Нет новой службы допуска, отдельного scheduler, второй БД, обязательного self-reflection и тестовой инфраструктуры.

### 32.7 Охват и честный остаток

claude-mem: архитектурное описание, hook registry, observation handler и spool handoff целиком; skip-agent helper; context1–260; GeneratorRunner1–260; название/содержимое свежего cache-related commit. Полный HookSpool fs implementation, provider response processing, все runtime modes и итоговое измерение стоимости не проверены. Две цели захвата и интерпретации различены, но весь продукт не объявлен прошедшим аудит.

OpenHands: condenser README, token helpers, LLMSummarizingCondenser, Condensation.apply, matching/loop properties; RollingCondenser70–300 и actual message-preparation helper в agent/utils. Чтение соседних tool-argument функций не засчитано как аудит всего agent runtime. BatchAtomicity и другие downstream provider constraints отдельно не проверены. Доноры, модельные ответы, БД и продуктовые/синтетические тесты не запускались.

Попытки получить архив/локальную копию не дали проверенного полного корпуса; missing work-system report от14.10 тоже не найден поиском по имени. Найденный соседний отчёт о донорах controller не подставлен вместо него. Полная исходная автономность, controller request/result и все старые аудиты остаются открытыми по карте. Из46 нумерованных поверхностей15 теперь имеют конкретные source findings,3 — doc/paper treatment,28 — прежний неподтверждённый comparable review; это не процент завершённости и не полный объединённый список источников владельца.

Независимых субагентных заключений нет. Запись результатов в GitHub подтверждает публикацию, не запуск V3 или автоматическое слияние PR. Работа с кодом продукта по-прежнему следует после документации.
