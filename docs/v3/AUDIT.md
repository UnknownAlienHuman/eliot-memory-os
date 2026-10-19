# Eliot Memory OS V3 — сводный аудит документации и архитектуры

**Редакция 0.6 · 19 октября 2026 · документация до переписывания продукта.**

В этой редакции опубликованное ранее состояние V3 сверяется с V1/V2, собственными усложнениями проектировщика и новым донором Harness2. Включён подготовленный, но не опубликованный ранее материал 0.5 о переносе опыта. [Architecture](ARCHITECTURE.md) — манифест; [Implementation](IMPLEMENTATION.md) — устройство продукта; [Cognition](COGNITION.md) — алгоритмы внутри тех же модулей; [AUDIT-MAP](AUDIT-MAP.md) — запрошенная владельцем карта прочитанного и оставшегося.

**Диагноз:** сокращать нужно число независимых владельцев, обязательных переходов и повторных вычислений, а не способность помнить, понимать и учиться. В V2 простая операция часто обслуживает инфраструктуру собственных доказательств. В ранней V3 часть этой логики вернулась в виде наследуемого запрета SDK, общего продвижения опыта, чрезмерных требований к проверке и второго учёта операций. Эти решения исправлены, а не только перечислены как чужие ошибки.

Разделы 1–17 сведены заново: повторяющиеся административные отчёты сокращены, существенные находки и матрицы сохранены. Это не заявление о побайтном сохранении старого аудита. Его полный текст и прежние проверки доступны на [c28359fc](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c28359fc2716f3b498ea512ca24a57801d18014c/docs/v3/AUDIT.md); более ранняя подробная редакция — на [3512f6e](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/3512f6e4f4c9ce59ba2959193e92c0728fadf00c/docs/v3/AUDIT.md). Сохранённый §18 — отчёт подготовки 0.5, не новое выполнение её проб. Новые результаты текущего прохода находятся в §§19–21 и карте аудита.

## 1. Источники, решения и границы проверки

| Источник | Версия и действительная роль |
|---|---|
| V1 | `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`: Canonical Master, Production Architecture, Understanding Layer; исходные требования и донор |
| V2 | `5aac094834fb5635921b550c821cb933a1196105`: замороженные нормативы, код, инструменты и незавершённые программы |
| Опубликованная V3 перед проходом | `c28359fc2716f3b498ea512ca24a57801d18014c`: редакция 0.4, PR #5325 |
| Подготовленная 0.5 | Приложенный `eliot-v3-documentation-0.5.zip`: полный Cognition, навигация, патч и §18; до этого прохода не находилась в ветке |
| Аудит Claude | Приложенный `eliot-documentation-audit(1)(1).md`, редакция 4; предложения, сообщённые решения и исторические измерения, не безошибочный норматив |
| Архив 16.10 | [audit-2026-10-16-incomplete](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete); сырьё аудитов/доноров, не обязательная программа V3 |
| Hy-Memory | `7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a`: выбранные writer/reconciler/store/System 2 пути предыдущих проходов; §18 расширяет перенос |
| MemOS local plugin | `a7367d07e55db61099f7b4e2c1108bc5831a24f3`: выбранные `l2.ts` и `gain.ts`, не весь продукт |
| Controller | `96a0d5a6632cfbd541e804d7969d3e76e716bf6a`: унаследованная ограниченная проверка интеграции; старые adapter findings сохраняют свои pins |
| Harness2 | `1cfe254e8d25b15f37048c3730134686abe60335`, commit от 14.10.2026; новое чтение алгоритмов, selection/reflection, library, ledger и experiments |
| Статья Harness2 | [2610.14224v1](https://arxiv.org/html/2610.14224v1), 09.10.2026; методы двух циклов и пределы интерпретации |

Прямое поручение владельца: V1/V2 — доноры, V3 — с нуля после документации; сохранить самообучение, когницию, модульность, гибкость и лёгкость; Dreamer может быть любой подходящей моделью. Приложение Claude сообщает дополнительные решения: demand-start, SurrealDB child, модели/эмбеддинги через controller, векторы в полном продукте, английская проектная документация и отсутствие собственного роя. Точные SDK версии, API и пороги не объявляются одобренными или реализованными только потому, что предложены здесь.

**Проверка источника ≠ квалификация продукта.** Различаются прочитанный код, исторический вывод другого прохода, логический контрпример, изолированная проба и живое выполнение. Наличие файла, поля или `ok` не доказывает законченный пользовательский путь. Полный построчный аудит миллионов строк и новое чтение всех доноров здесь не заявлены.

В текущем проходе подтверждены полный каталог GitHub write-actions, `permissions.push` и успешная запись не присоединённого к дереву blob. Поэтому продолжающегося запрета записи нет. Недоступность сети локальной VM или материализации текста не является отсутствием GitHub write-доступа. Прежний результат 0.5 остался локальным: этот разрыв поставки исправляется реальной публикацией, не повторением обещания.

## 2. Где началось разрастание

### 2.1 Масштаб: сохраняем метод измерения, не обещаем коэффициент

Следующие числа — из первого прохода на указанном V2, не новый полный пересчёт.

| Показатель | V1 | V2 |
|---|---:|---:|
| Rust-файлы | 139 | 2 472 |
| Физические строки Rust с комментариями, пустыми строками и inline tests | 172 579 | 2 638 670 |
| Tracked files | Не пересчитано | 4 999 |
| Cargo package manifests | Не пересчитано | 199 |
| Package manifests под bins | Не пересчитано | 15 |
| Markdown | Не пересчитано | 850 файлов / 47 012 строк |
| Python | Не пересчитано | 150 файлов / 144 845 строк |
| TOML | Не пересчитано | 421 файл / 587 866 строк |

Package не равен постоянно запущенному процессу. Большой каталог не автоматически бесполезен: восстановление и история тоже реализуют требования. Метод подсчёта учитывает последнюю непустую строку без завершающего перевода; это объясняло отличие в одну строку от Claude.

Деление 2 638 670 на 50 даёт примерно 52 773 физических строки. Это арифметика, не доказанный бюджет V3. Оценки «26,5 тысячи кода плюс 15 тысяч тестов» и «60–100 раз меньше» не проверены на одинаковой функциональной границе. Считать нужно также обязательный код controller, адаптеры, SQL, процессы, скрипты, сборку и эксплуатацию.

### 2.2 V1: полезная топология уже несла дорогую доктрину

Свежепрочитанное [V1 Production Architecture, §0–1](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Rust_Governor_Production_Architecture_v1_0.md#L1-L155) правильно отделяет инструментальный Governor от модели, использует серверную БД и отвергает NATS/Temporal/вторую графовую БД. Но рядом уже предписывает redb Control WAL, leases, proof bookkeeping, проверяемое продвижение policy/skills/retrieval и набор полномочий Governor.

Поэтому нельзя объявить V1 идеальной маленькой системой, испорченной только V2. Хорошее разделение ответственности надо взять отдельно от её церемонии. Статические правила V1 о конкретной модели, backend и проверках не становятся вечными ограничениями нового проекта.

### 2.3 V2: контракт делает межпроцессную проверку универсальной

[I1.2](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/architecture/I01-02-required-processes-of-the-first-complete-runtime.md) разделяет Host, Kernel, daemon, Watchdog, storage bridge и SurrealDB; blob capability может быть co-located или отдельной по нужде. Важно не приписывать этому тексту обязательный отдельный blob executable: он прямо допускает внутреннюю способность.

[I5.6](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/architecture/I05-06-admission-and-staging.md) описывает 18 шагов записи: scope/task/fence/provenance, mutation/admission digests, ORS staging, ordering, DB transaction, receipt reconciliation и outbox. Kernel повторно проверяет план и manifest, storage bridge — класс/область/эффект. Это следствие выбранной топологии, а не природное требование записи памяти.

**Для V3:** снять ненужные границы процессов; оставить один typed domain call, проверку реального входа, stable retry identity и нужную транзакцию. Не пытаться вырезать все проверки из прежнего distributed pipeline, продолжая сохранять сам pipeline.

### 2.4 Замкнутая петля роста

Понятие получает тип → тип получает владельца, реестр и lifecycle → состояния копируются → локальный shape-PASS заменяет полезный consumer → ложное «готово» лечат новой квитанцией и процедурой → правила требуют новых инструментов и собственного восстановления.

Запрет в конце документа не отменяет сотни страниц обязательных форм. Но и тезис «агенты буквально исполнили всё правильно» неверен: например, [I17.11](../architecture/I17-11-delivery-depth-d3-grounded-smart-understanding.md) уже позволял D3a до необязательной широты D2. Нужно различать дорогую доктрину, неправильное чтение и реальный пропущенный runtime-переход.

## 3. The 34 preserved requirements

Основания: [Canonical Master](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Canonical_Master.md), [Production Architecture](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Rust_Governor_Production_Architecture_v1_0.md), [Understanding Layer](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md). Это сохранение смысла требований, не утверждение о работающем V3.

| № | Требование | Компактное решение и сохраняемая граница |
|---|---|---|
| 1 | Независимость от модели, провайдера и host | Общая память и реальные адаптеры; равный протокол не обещает равное качество |
| 2 | Внешняя когнитивная петля | Наблюдение → контекст → действие/исход → изменение следующей работы |
| 3 | Автономность понимания | Автоматические карты и provisional методы без approval каждой записи |
| 4 | Экономия токенов и операций | Exact/lexical, совместимые vectors, batching, раскрытие; без LLM перед каждым чтением |
| 5 | Разные виды знания | Observation, claim, hypothesis, decision, procedure, unknown не сливаются в один score |
| 6 | Актуальность относительно мира | Проверка материальных live anchors; история не аннулируется сменой HEAD |
| 7 | Точное происхождение | Source event/revision/span и доступный оригинал; сохраняются числа и исключения |
| 8 | Противоречие и пересмотр | Ревизии, альтернативы и контрдоказательство вместо last-write-wins |
| 9 | Область до использования | Поиск и раскрытие в разрешённом project/workspace; не чужой top-k |
| 10 | Данные не создают полномочий | Goal/config/tool permissions отдельно от текста памяти |
| 11 | Сохранение без лишней формы | Capture до классификации; неизвестный смысл допустим |
| 12 | Связность и продолжение | Эпизоды, решения, попытки и адресные связи, не только независимые chunks |
| 13 | Допуск пригодного после поиска | Применимость и состояние проверяет один compiler; similarity не доказательство |
| 14 | Постепенное раскрытие | Короткий packet и handles с источником и текущим scope |
| 15 | Контекст под решение | Цель, критерии, ограничения, unknowns и следующий шаг на реальной границе модели |
| 16 | Понимание проекта | Карта назначения, подсистем и ресурсов, а не только vector index |
| 17 | Холодный старт и обновление | Доступные anchors и non-Git scope; не выдумывать отсутствующую ревизию |
| 18 | Структура и поведение | Static dependency, co-change и causal hypothesis остаются различными |
| 19 | Предсказание и калибровка | Ожидаемое наблюдение до действия и сопоставление с исходом |
| 20 | Негативная память до действия | Своевременный совет; точное ограничение только через реальный host gate |
| 21 | Связь действия с исходом | Версия метода, попытка, фактическое действие и критерий; cue overlap не использование |
| 22 | Честное завершение | Реальные критерии и gaps; один exit 0 не закрывает всю задачу |
| 23 | Dreamer предлагает преобразования | Реальный finite model job, source/target checks; не произвольный SQL |
| 24 | Разные виды забывания | Exposure, withdrawal, revision, erasure отдельно; restore учитывает удаления |
| 25 | Процедурное обучение | Preconditions, метод, примеры, исключения и следующий consumer |
| 26 | Метаобучение и перенос | Тот же job/attempt путь; опыт улучшения помогает следующему улучшению |
| 27 | Наблюдаемость | Связный trace и views; квитанция не заменяет наблюдаемого действия |
| 28 | Восстановление | Стабильная identity, минимальный spool, claim и external readback |
| 29 | Власть человека | Явные goal/config/control; score не создаёт новых прав |
| 30 | Малый интерфейс агента | Несколько операций; служебную metadata собирает adapter |
| 31 | Проверка реальных отказов | Сквозные различающие ситуации, не сертификат по форме |
| 32 | Лёгкий инструментальный Governor | Demand-start, один memory writer, нужное независимое наблюдение |
| 33 | Заменяемость хранения | Private Store, native DB и экспорт; не универсальный KV с компенсациями |
| 34 | Улучшение не удостоверяет себя | Provisional use отдельно от доказанного выигрыша на будущих случаях |

Поздняя [UL Part C](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md#L1433-L1468) отменяла ручное approval детерминированных UL-артефактов. Полезную автономность нельзя потерять, требуя полного исследования эффективности до всякой подсказки. Это не разрешение модели менять права или объявлять любую гипотезу истиной.

## 4. Что точно не переносить, что извлечь из V2

### 4.1 Обязательная триада капсул — бюрократия прямо в нормативе

В [I2.20](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/architecture/I02-20-module-contract-kit-crate-context-capsule-and-module-test-capsule.md) `FunctionalCapabilityCell` прямо **не обязана быть crate**, а два файла на crate не требуются по умолчанию. Значит, эти обвинения были бы неточными.

Реальная избыточность другая: `ModuleContractKit + CrateContextCapsule + ModuleTestCapsule` объявлены обязательными независимо от качества кода и количества тестов. В manifest входят contract digest, proof ceiling, replacement boundary, latency-profile с machine/toolchain/cache fingerprint и qualification expiry. Агент получает отдельный продукт, который должен обслуживать прежде полезной памяти.

**Берём:** ясную ответственность, понятный вход/выход, ошибки и реальный consumer. **Не берём:** обязательный комплект метаартефактов и статус поддержки, определяемый наличием комплекта. Карта аудита не является новой версией такой триады.

### 4.2 Простая запись уведомления проходит через инфраструктуру доказательств

Свежепрочитаны [notification_plan_admission.rs, 1–245](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliotd/src/notification_plan_admission.rs#L1-L245) и [тело функции, 245–380](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliotd/src/notification_plan_admission.rs#L245-L380).

Для NotificationState строится общий CanonicalWriteEnvelope, считается digest набора manifests, `prepare()` вычисляет request/plan/admission digests, затем **повторно читается тот же generated catalogue** для проверки поддержки. Далее собирается CanonicalRequestView и снова проверяется request hash. Пустые proof refs, security chain и lists тоже проходят универсальную схему.

Комментарии этого файла прямо оговаривают: identity содержит clock/deadline, поэтому hash меняется между вызовами; реальные repeat guards смотрят на состояние БД и ключ underlying problem, не на этот digest. Полные вызывающие notification emit paths в этом проходе ещё не трассированы, поэтому **не заявляется воспроизведённая повторная отправка**. Подтверждена структурная цена и ограниченность заявленного свойства.

**Малое решение:** keyed problem/notification state, один условный domain update, отдельные delivered/acknowledged/resolved и исходящий job при реальной доставке. Не нужны два catalogue reads, plan digest closure и копирование transport context ради локального обновления. Повторное чтение generated table одного build не становится независимым смысловым доказательством.

[request_hash.rs, 1–175](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/storage/eliot-store-api/src/request_hash.rs#L1-L175) показывает, как scope/task/effect, manifests, security/proof chains и heads вошли в общий hash. Это не подпись и не полномочие. В V3 такой межпроцессный договор устраняется вместе с ненужными процессами; стабильные IDs, сравнение входа и DB revision остаются.

### 4.3 Cue normalizer: полезные правила внутри чрезмерной обвязки

Прочитаны [public entrypoints](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/smart/eliot-cue-normalizer/src/lib.rs), [normalize.rs, 1–280](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/smart/eliot-cue-normalizer/src/normalize.rs#L1-L280) и [derive_key/path helpers, 280–510](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/smart/eliot-cue-normalizer/src/normalize.rs#L280-L510).

**Ценно:** capture/fire вызывают одну функцию; исходное написание сохраняется; comparison form отделена; case folding применяется только по явной семантике; неподдерживаемая форма не выдаётся за установленное равенство. Это конкретные знания донора, не причина импортировать весь crate graph.

**Избыточно для нового pure helper:** NormalizationEnvelope с input/result digests, PolicyBinding с owner/scope/StateFence/profile/digest, canonical cue/key digests и повторная nested validation. Проверка входного размера полезна; доказательство целостности собственной строки после обычного вызова в том же процессе не делает нормализацию правильнее.

`has_special_path_shape` отвергает абсолютные/drive/UNC и другие формы в выбранном helper. `run` превращает Unsupported в результат с сохранённым observed value; это не доказательство потери capture. В V3 adapter должен явно различать исходный путь, его workspace-relative форму и сравнение. Не переносим механический запрет всех абсолютных путей на реальные host events и не приводим всякий Unicode/символ к lower case ради удобства.

### 4.4 Остальные границы удаления

| Старое семейство | Не переносить как продукт V3 | Что полезно как донор |
|---|---|---|
| Host/Kernel generations | Горячую замену, registry builds, epoch/manifest choreography | Реальное ownership процесса, restart intensity, различие planned exit/failure |
| ORS/redb | Вторую семантическую память и общий recovery engine | Потерянный acknowledgement, durable intake, unknown external outcome |
| Storage bridge | Отдельный процесс и универсальный named-operation language | Fixed parameterized queries, conditional write, native DB features |
| Contract/capsule/tooling | Reading certificates, proof matrices, generated inventories как цель | Короткий contract и реальные воспроизводимые edge cases |
| Dreamer families | Crate/service на каждую мыслительную операцию | Extract/reconcile, dissent, procedures, source revision handling |
| Notification state | Универсальную admission/digest церемонию | Dedup underlying problem; acknowledgement не resolution |
| Cue families | Manifest/envelope closure для pure функции | Lossless source и единая capture/query нормализация |
| Agent fabric | Второй swarm, supervisor и provider scheduler в Memory OS | Реальные host events и external task/attempt references |

Это решения о переносе в V3, не команда удалить непроверенный V2 runtime сейчас. ORS имеет разные обязанности: его 79 таблиц нельзя честно назвать просто одной очередью. Удаляется потребность в старых ролях, а не только таблицы по счётчику.

## 5. Исправления Claude и прежних собственных утверждений

| Утверждение или схема | Исправление |
|---|---|
| BM25 есть только в V1 | В V2 есть вызываемый FTS path и `search::score`; живое качество отдельно не доказано |
| Весь Dreamer всегда отказывает | Доказан normal resolver; curation имеет другой путь |
| Бинарь = постоянный процесс | Manifest count не является измеренной топологией |
| Всё «закрыто» таблицей anchors | Это соответствие проекту, не runtime success |
| `DEFINE EVENT` даёт надёжную очередь целиком | Может атомарно создать job; retry/cancel/unknown остаются приложению |
| Один статус или `influence != none` | Карантин/handle-only требуют явного правила выдачи |
| Одинаковая dimension означает совместимые embeddings | Нужны encoder/preprocessing/content identities |
| Осталась одна citation — синтез снова верен | Не различены AND-premises, alternative derivation и простые citations |
| Ограничили каскад N — остальные валидны | Неисследованный хвост не становится корректным |
| Один exit 0 = VERIFIED_COMPLETE | Только реально покрытый критерий |
| Approval каждого helper/таблицы и запрещённый словарь | Это новая бюрократия; причина и consumer важнее имени/лимита строк |
| 50× уже доказано | Пока гипотеза на несопоставимых оценках |

Источники сохранённых фактов: [V2 FTS caller](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/canonical_store.rs#L2513-L2555), [FTS SQL](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/crates/eliot-store/src/surql/load_memory_search_fts_candidates.surql#L40-L62), [normal Dreamer resolver](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/controller.rs#L64-L84), [caller](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/bins/eliot-dreamer/src/lib.rs#L792-L806). Это ранее проверенные source findings, не новый полный runtime audit.

Наши собственные исправления тоже сохраняются: universal source freshness могла выключать исторический опыт; ModelJob одновременно требовал Task и запрещал fake Task; backup обещал короткую неопределённую snapshot boundary; context integration document ошибочно трактовался как доказательство отсутствия любого обратного API; заявленная 0.2 не была опубликована вовремя. Исправлялись договоры и согласованность документов, а не добавлялись оправдательные квитанции.

## 6. Hy-Memory: механизмы, а не целый runtime

Настраиваемая модель/совместимый endpoint у донора уже существуют. Заменяемость модели не является исключительной особенностью Eliot. Специализированные writer weights, само приложение и training evaluation — разные артефакты. [Config](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/config.py#L132-L214), [provider](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/agent/llm_provider.py#L309-L440).

| Берём | Не переносим |
|---|---|
| Эпизодные факты отдельно от переносимого опыта | По сервису и store на каждый уровень |
| Extraction отдельно от reconciliation | Подгонку нового события под удобный прежний label |
| Конечные кандидаты и target checks | Prompt как единственную защиту чужого ID |
| Diff history по реальному источнику | Восстановление всех потерянных промежуточных edits из final diff |
| Фоновую пакетную индукцию | Вечный autonomous runtime для каждой операции |
| Корректный no-proposal | Обязательный урок из каждого события |

Ранее прочитанный [coding writer](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/writer.py#L65-L205) сохраняет trace в `finally` после попытки extraction и лишь логирует ошибку сохранения. Поэтому raw-first одного chat-пути не гарантирует raw-first всего Hy. V3 подтверждает preservation до дорогого толкования.

[_crosslink](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/writer.py#L236-L280) связывает каждый experience со всеми fact IDs партии. Batch membership годится для соседства, но не доказывает каждую premise. Для соседства достаточно episode/batch ID; evidence и live requirements адресуются отдельно. При этом раскрытие модельного результата всё ещё ограничено фактически переданным ей материалом, а не только списком её цитат.

В прежних проверках parser/UPDATE выявлены ограниченные source-level риски: форма ID проверяется не всегда вместе с membership; отсутствующий scoped predecessor не должен открывать произвольный upsert. [Chat parser](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/agent/reconciler.py#L1900-L1930), [coding UPDATE](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/reconciler.py#L450-L474). Это не сообщение о воспроизведённой атаке или утечке.

Авторские результаты [writer paper v1](https://arxiv.org/html/2610.22196v1) остаются результатами заданного эксперимента, не гарантиями любой модели с похожим prompt. Берём оценку памяти через последующую задачу, контроль роста и разделение writer/reader. Не строим training platform и не называем self-reported memory IDs эквивалентом supervised attribution.

## 7. SurrealDB: использовать готовое, а не компенсировать выдуманный дефект

Одна primary БД уже даёт полнотекст, векторы, связи и транзакции. Small scoped exact vector search — полноценные векторы; HNSW выбирается по задаче, а не ради чек-листа возможностей. Private Store не обязан быть универсальным нейтральным KV.

SDK query возвращает результаты отдельных statements; транспортный успех не означает их успеха. Проверять bindings, ошибки и cardinality надо рядом с конкретным запросом. Это не новый SQL-proof language. [Query reference](https://surrealdb.com/docs/reference/rust/methods/query).

Приложение хранит семантические ревизии обычными записями: логический export не заменяет историю перезаписанной строки. Import проверяет реальные результаты и примиряет необходимые jobs/indexes, не предполагая, что historical table events повторились. [Export](https://surrealdb.com/docs/reference/cli/db/commands/export), [backup](https://surrealdb.com/docs/manage/self-hosted/backups-and-recovery).

Документация [similarity search](https://surrealdb.com/docs/learn/data-models/vector-search/similarity-search) описывает filtered plans и index-assisted prefiltering. Сначала смотреть конкретный server/schema/query/EXPLAIN, затем выбирать fallback. Наличие внешнего Filter не доказывает отсутствие внутренней фильтрации. Документация — не запуск нашей конкретной версии и не полнота semantic recall.

SurrealDB Agent Memory/Spectron — отдельный application tier, не встроенное бесплатное Rust-понимание самой БД. Проверять его механизмы можно; импорт целого runtime поверх Eliot не следует из совпадающего имени. Старый запрет SDK Phase A снят как **наследуемое вето**, а не опровергнут задним числом: первичный V3 выбор — официальный сетевой SDK с конкретной проверкой реальной dependency graph при реализации.

## 8. Controller и host: два направления и настоящий момент чтения

[Controller integration на 96a0d5a](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/96a0d5a6632cfbd541e804d7969d3e76e716bf6a/docs/eliot-memory-os-integration.md) описывал requested/not implemented вызов контекста **из controller в память**. Это не спецификация готового **из памяти в controller** text/embedding API. Ограниченный поиск не доказывает глобального отсутствия пригодного метода. Реальные методы и первый маршрут ещё выбираются.

Eliot владеет намерением изменить память и условием применения результата; controller — внешним исполнением и provider retries. Local claim, external request и DB mutation identity различаются, но не требуют трёх новых state-machine сервисов. Worker restart сначала читает сохранённый execution reference. Accepted input не равно inference result, отмена не означает нулевую стоимость.

Maintenance не требует fake coding Goal. Легитимная ограниченная synthesis Task допустима, когда её действительно требует executor. Вытеснить реальный Task API выдуманным запретом «никаких Task» было бы такой же ошибкой, как создавать фиктивный Task для каждого embedding.

[Claude hook reference](https://code.claude.com/docs/en/hooks#add-context-for-claude) отделяет момент hook от следующего model request. Advisory должен попасть до решения модели; exact pending-action gate — другой механизм. Не блокируем все инструменты ради дополнительного хода. Native hooks и SDK bridge с ограниченными metadata не являются одинаковыми поверхностями.

Старый context может остаться в transcript; fresh incarnation сбрасывает dedup, новая ревизия должна показывать актуальную применимость. Нельзя обещать удаление ранее переданного контекста из модели.

## 9. Самообучение: полезная автономность без самоудостоверения

Процедура — обычная memory revision, попытка — связанный outcome, агрегат — вычисление. Локальная полезная подсказка и условный перенос в другой разрешённый контекст могут применяться автоматически. Проверка применимости не является доказательством измеренного выигрыша; требование сравнительного эксперимента перед каждым применением было нашим избыточным ограничением.

Сохраняются отдельные delivery, observed action, adherence, criterion outcome и comparative benefit. Один вклад на procedure revision/attempt/criterion; повтор hook, несколько steps и correction не увеличивают независимый support. Примеры индукции не могли воспользоваться правилом, которого тогда ещё не было.

В ранее выбранном [MemOS L2](https://github.com/MemTensor/MemOS/blob/a7367d07e55db61099f7b4e2c1108bc5831a24f3/apps/memos-local-plugin/core/memory/l2/l2.ts#L371-L445) with-set включает associations и induction evidence. [Gain formula](https://github.com/MemTensor/MemOS/blob/a7367d07e55db61099f7b4e2c1108bc5831a24f3/apps/memos-local-plugin/core/memory/l2/gain.ts#L62-L133) с одинаковыми наблюдаемыми mean 0,8 и пятью without-примерами даёт baseline 0,65 и gain +0,15 из-за prior 0,5 с весом пять. Это арифметический контрпример интерпретации gain как наблюдаемого causal lift, не запуск MemOS и не отказ от эвристик для provisional ranking.

Для API-критерия важно, прошла ли проверка нужный consumer на нужной ревизии. Если compiler упал раньше или лог обрезан, отсутствие искомой ошибки не является успехом. Не наказывать метод за несвязанный network failure и не скрывать другой реальный failure ради приятного выбранного score.

Для утверждений о широком улучшении нужны сопоставимые будущие случаи и независимая проверка, отдельно от материала индукции. A/B меняет оцениваемый advisory, не цель пользователя и обязательные ограничения. Shadow показывает selection, не реальное изменившееся действие. Отсутствие достаточной статистики оставляет полезную условную гипотезу, а не вечный запрет использовать память.

## 10. Надёжность и приватность без второй ОС

Разделяем historical evidence, live applicability и disclosure. Это значения и связи, не универсальный grant calculus. В локальном профиле достаточно выбранных projects, capture/retention preferences и разрешённых model routes. Источники группируются по совместимому раскрытию; local-only материал не посылается на remote route и не становится public от отсутствия citation.

Нужные проверки остаются: source identity, transaction, stale claim, неизвестный external effect, реальные permissions и credentials. Не нужны signed learning proposals, proof-of-reading, per-helper policy digest, глобальный principal graph и отдельный сервис отзыва доверия.

Небольшой spool подтверждает сохранённый input, а не смысловую память. Backup имеет конечный cutoff, quiesced DB export, blobs и запечатанный input batch. Новые события относятся к новому batch. Пауза записи на время экспорта честнее несуществующего короткого snapshot primitive. Не ждать worker под нужным ему mutex.

Текущие ограничения replay/delete хранятся вне откатываемой копии; physical purge и withdrawal различаются. Восстановленный pending job мог выполниться после cutoff: сначала external readback. Если вместе с устройством утрачен current deletion history, checksum не устанавливает актуальность; recovery остаётся изолированным или применяется явный новый selective import. Это предел гарантии, не повод создавать external attestation service.

Независимость Watchdog требует внешнего наблюдения за failure domain, но не автоматически нового обязательного демона в каждой среде. Если существующий host/controller реально обеспечивает custody/health Eliot, повторный supervisor не строится. Иначе используется маленький demand-start режим того же бинаря. Standalone supervisor+daemon+DB — три процесса; это не enterprise Host/Kernel/generation stack.

Job Object и CLI label не изолируют от произвольного unrestricted процесса того же OS user. Правильный вывод — назвать границу и использовать реальные host permissions, не умножать поля безопасности. Notification acknowledgement не resolution, heartbeat не progress, exit 0 не вся приёмка.

## 11. Доноры и аудиты: карта, а не обязательный backlog

### 11.1 Архивная карта и нынешнее чтение

Сохраняется прежняя инвентаризация: 43 D-поверхности, 27 P-работ и 187 S-записей — 257 строк, не обязательно 257 независимых источников. Заполненный статус не доказывает прочитанную статью или выполненный эксперимент. Архив оставался incomplete; задача V3 не наследует запрет отказывать донору без текущего полезного потребителя.

В текущем проходе заново проверены metadata релиза и доступность write API, а не байты всего ZIP. Повторная загрузка release assets в среду не удалась; выводы об их содержании ниже опираются на прежний аудит и приложенный Claude, а не притворяются новым полным чтением 968 entries. В карте A12 явно остаётся предметное повторное чтение shortlist/transfer decisions. Это ограничение чтения не мешает публиковать уже имеющиеся документы через работающий GitHub API.

### 11.2 Исторические 43 поверхности и новый D44

Строка означает кандидатный механизм, не свежую квалификацию всех версий/лицензий. Копирование кода требует конкретного проверенного upstream pin/license. Идею можно отклонить, если она не уменьшает работу или риск на полезном пути.

| D | Донор | Что брать или проверять; что не импортировать целиком |
|---|---|---|
| 01 | MemMachine | Derivative → эпизод → ограниченные соседи в той же области |
| 02 | MemPalace | Stable event IDs, одинаковые timestamps, повторные экспорты; не last duplicate wins |
| 03 | Subcog | Facets и RRF; без read-side semantic mutation |
| 04 | MemOS local plugin | Retrieval по ситуации; L2/gain не считать causal proof |
| 05 | Claude Code memory/tool search | Малый стартовый индекс и раскрытие, не вечный дамп |
| 06 | ClawVM | Сохранение необходимых смысловых единиц при сокращении |
| 07 | Pichay / demand paging | Цена повторного чтения, не paging OS заранее |
| 08 | Graphiti | Раздельное время действия/знания/отзыва; не managed Zep как тот же код |
| 09 | Hindsight | Проверка источников перед публикацией и пересмотр опор |
| 10 | EverOS | Reconciliation пропусков; новая версия готова до снятия старой |
| 11 | EverMemOS historical | Episode/atomic facts/foresight; не смешивать версии продукта |
| 12 | Cloudflare managed Agent Memory | Raw рядом с extracted; managed service не бесплатная library |
| 13 | Cloudflare Agents SDK Sessions | Immutable turns и branch-local compaction overlays |
| 14 | SurrealFS | Source/indexer/content/profile revision, не вся SurrealDB |
| 15 | MentisDB | Версии skills/procedures и source-linked reveal; проверить lifecycle |
| 16 | LangMem | Extraction/diff и кандидаты prompts; не queue/runtime целиком |
| 17 | Letta Code current | Candidate/cancel и защита от позднего результата |
| 18 | Letta V1 archive | История по требованию, цена truncation; не current Code |
| 19 | Nocturne Memory | Stable node, revision, path alias; review до разрушения |
| 20 | Mem0 OSS | Batch extraction/embeddings, ошибка отдельно от пустого результата |
| 21 | OpenMemory historical MCP | Membership/access ideas с оговорками historical продукта |
| 22 | OpenMemory session CLI | Перенос сессий; roadmap не runtime |
| 23 | Cavira LongMemory | Узкие decay/supersedes/checkpoints; не mem0 OpenMemory |
| 24 | ripgrep | Exact source spans/offsets, простой первый source tool |
| 25 | ast-grep | Синтаксические паттерны и координаты, не runtime proof |
| 26 | SCIP | Definitions/references с encoding и producer/source revision |
| 27 | GitHub Copilot Memory | Перепроверка citation, не открытый runtime по одному описанию |
| 28 | Docling | Document parsing при нужном ingestion, page/element provenance |
| 29 | Docling Core | Hierarchy/chunk metadata выбранного parser |
| 30 | DocETL | Raw/error/partial и retries, не general research engine |
| 31 | Vector / VRL | Сохранение события при transform error; DSL только при потребности |
| 32 | Kreuzberg v4 LTS | Native extraction/source mapping, точная ветка и лицензия |
| 33 | Kreuzberg current | Не переносить свойства другой версии по имени |
| 34 | Cedar | Policy backend только при реальной сложности; не baseline V3 |
| 35 | OPA | Undefined/error/result; не второй policy owner |
| 36 | redb | Исторический durable spool; baseline V3 использует файлы, не вторую БД |
| 37 | duroxide | Idempotent activity identity как идея, не workflow runtime |
| 38 | Flawless | Unknown outcome и различие retry/replay |
| 39 | FoundationDB testing | Будущие управляемые отказы, не тестовая платформа сейчас |
| 40 | Wasmtime | Изоляция реального недоверенного расширения при оправданной цене |
| 41 | SurrealDB Agent Memory / Spectron | Source-linked retrieval и scope; отдельный application tier |
| 42 | MAGMA | Ограниченные типизированные graph walks с реальными фильтрами |
| 43 | A-MEM | Предложения evolution заметок/связей, не model-authorized overwrite |
| 44 | Google Research Harness2 | Два цикла Propose–Probe–Compose / improvement experience; source-read в этом проходе; перенос механизма, не benchmark runtime |

Hy-Memory остаётся отдельно углублённым донором §§6,16–18. Старые D-номера не перенумерованы; D44 добавлен, а не выдан за прежнюю архивную строку. Вся карта не объявляется заново прочитанной.

### 11.3 Применение списка исследований

MemGPT/HiAgent полезны для подцелей и раскрытия; LongMemEval/MemoryArena/Mem2Act — для различения сохранённого, найденного и выполненного; LightMem/MemDelta — для цены консолидации и контрольных сравнений; ATMS — для понимания альтернативных опор без обязательного комбинаторного движка; Meta-Harness и Harness2 — для исследования улучшения способа работы. Чужие числа не становятся целями Eliot.

Карточке достаточно назвать пробел, source function, полезное преобразование, ограничения и consumer. Не нужен обязательный отдельный документ с 13 полями каждой идее. «Не требуется для выбранного пути» — законный результат чтения. Самописная реализация должна объяснять преимущество перед зрелой библиотекой, а не проходить легче заимствования только потому, что для донора построены лишние гейты.

## 12. All 29 original scenarios

Источник — [V2 A15](../architecture/A15-end-to-end-scenarios.md). Сохраняется пользовательский смысл, не старая топология. Каждая строка — будущая ситуация продукта, не выполненный live test.

| A15 | Ситуация | Решение и граница V3 |
|---|---|---|
| 1 | Новая область без Git | Доступные anchors, узкий provisional scope, без выдуманного commit |
| 2 | Агент не знает, что искать | Своевременный advisory, orientation и handles |
| 3 | Плохо типизированное наблюдение | Сначала сохранить permitted raw |
| 4 | Ложное слияние/процедура Dreamer | Сохранить события и dissent; пересмотреть производное влияние |
| 5 | Workspace меняется без отчёта | Доступные независимые сигналы, gap, ограниченный resync |
| 6 | Разные объяснения агентов | Источники и различающий шаг, не голосование |
| 7 | Большой swarm audit | Уникальный охват и partial/gaps в памяти; рой у controller |
| 8 | Повтор известного провала | Applicable advice/exact gate; timing не подменяется именем hook |
| 9 | Ложный guard | Challenge и сужение неверной части |
| 10 | Позднее poisoning | Отзыв реальных зависимостей, quarantine и новая обоснованная ревизия |
| 11 | Injection из документа/tool/model | Данные не права; app проверяет target и допустимое преобразование |
| 12 | Отказ optional модуля | Незатронутые пути продолжаются; изоляция по реальной цене отказа |
| 13 | Governor упал, Kernel жив | Kernel не воспроизводится; внешний observer и честное pending/unknown recovery |
| 14 | Давление очереди/диска | Ограничения, staged/rejected и доступный control |
| 15 | Repair повторяется без пользы | Остановить тот же ремонт, сохранить проблему и уведомить |
| 16 | Compaction/restart | Новая incarnation, цель/обязательства/ошибки; discarded plan не оживает |
| 17 | Смена model/harness | Capability/applicability recheck; история сохраняется |
| 18 | Verifier отсутствует | Соответствующий критерий unknown |
| 19 | Уведомление пропущено | Attention остаётся до решения, ack не resolution |
| 20 | Setup нашёл executable | Metadata отдельно от права запуска; не исполнять даже probe автоматически |
| 21 | Privacy deletion | Withdrawal, controlled purge и внешние копии различаются |
| 22 | Старый backup | Current restrictions до serving, uncertainty не маскируется |
| 23 | Прерванная migration | Restart-based upgrade с понятным результатом, не весь V2 live migration |
| 24 | Код против Architecture | Grounded discrepancy; явная правка нужного источника |
| 25 | Экспериментальный модуль | Ограниченный data/isolated comparison; не arbitrary hot replacement |
| 26 | Рой пишет модули | Один manager/worktree и writer/область; процесс разработки вне Memory OS |
| 27 | Локальный PASS, продукт FAIL | Не заявлять whole-product success; сохранить реальный исход |
| 28 | Недостаточное окно | Progressive reveal/decomposition; исключения не выбрасываются молча |
| 29 | Meta candidate пережил смену стека | Проверить применимость; старый score не становится новым доказательством |

Implementation сохраняет S1–S26, Cognition — 30 прежних ситуаций и дополнительные случаи рекурсии. Это не отдельные test engines.

## 13. Процесс разработки и публикация

Одна рабочая единица завершает полезный переход либо устраняет конкретный отказ. Не строить все DTO, потом handlers, потом доказательства и когда-нибудь consumer. Один manager — один изменяемый worktree; root отвечает за согласованность; read-only review не требует размножать рабочие копии.

Публикация — конкретные байты в GitHub и readback commit/ref. Локальный ZIP и подготовленный отчёт не равны коммиту. По текущей проверке write API работает; уже сохранён `AUDIT-MAP.md` коммитом `6ef12c1aa796200337dc0590156f0fe7a636dc8d`. Карта сама по себе не заменяет публикации исправлений 0.5/0.6.

Исторические CI-проблемы остаются отдельно: локальное применение фиксированного V2 каталога 11 issues к #5324 и подтверждённая в старом Windows run зависимость reading receipt от LF/CRLF. [Каталог](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/.github/work-unit-cohort.toml), [membership gate](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/scripts/work_unit_gate/doc_read_evidence.py#L1592-L1659), [старый run](https://github.com/UnknownAlienHuman/eliot-memory-os/actions/runs/39176892004). Нельзя автоматически назначить эту причину каждому новому красному запуску.

Не подставлять чужую issue, не подписывать выдуманное чтение и не выдавать собственную повторную проверку за независимого GPT Luna. CI и его validators сейчас не меняются. Необходимая последующая корректировка старого gate должна быть отдельным явным изменением, а не тайным обходом. Право записать ветку уже есть; слияние и успешная проверка — отдельные факты.

## 14. Простая предлагаемая конструкция

Capture сохраняет наблюдение и follow-up intent; Store использует native DB; context независимо ищет и разрешает текущие группы; Dreamer преобразует конечные inputs; learning связывает методы с будущими исходами; controller исполняет внешнюю работу. Policy — небольшая local configuration, не архитектура выдачи полномочий. Observer следит за реальным failure domain, не за наличием квитанции.

Один app writer не означает отсутствие concurrency checks: поздний worker и неизвестный provider result всё ещё возможны. Но они решаются matching claim, expected revision и stable request ID, а не импортом всей Authority Epoch/PreparedTransition системы.

Рекурсивное обучение использует те же records и jobs. Больше cognitive depth не требует больше процессов. Обычное совпадение/чтение не требует вызова модели; условный перенос может быть автоматическим, а доказанный выигрыш остаётся более сильным отдельным утверждением.

## 15. Границы результата

Ни одна редакция этих документов не реализует V3. Не выполнены полный аудит всех V1/V2 source paths, новое чтение 187 исследований/всех upstream, полный Hy/MemOS/Harness2 запуск, Windows custody, SurrealDB backup/query test, controller inference или измерение новых LOC/RAM/latency. Прежние изолированные пробы имеют только свой описанный охват.

Следующие O1–O6 — конкретные interface/version/implementation choices, не шесть новых платформ: host timing; controller methods; Windows file durability; совместимая Store schema/client; outcome criterion; независимое наблюдение. Карта показывает, что уже читалось, что пока только inherited finding, и следующий точный source path. Нет ложного общего процента «готовности аудита».

## 16. Cognitive audit 0.3

Сохраняется итог проверки 0.3 на базе `da441352`: 0.2 лучше описывала хранение и восстановление, чем сами вычисления понимания. Поэтому добавлен единый Cognition внутри прежних модулей, а не WorldModelService или OntologyManager.

Ключевые механизмы: current-value resolution по subject/aspect/perspective/scope/time, не рангу поиска; дочитывание активных альтернатив по группе; различие intended/observed; карта учитывает membership новых consumers, а не только старые citations; одна finite running orientation и coalesced successor; applicable/inapplicable/unknown; criterion-specific outcome, а не reward всему packet; запрет самоподкрепления через повтор summary.

[V1 §4.12](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Canonical_Master.md#412-deterministic-current-value-resolution) дал смысл deterministic resolution, [UL mission](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/b5c84d4e53292dbc8996917c63448d5ee96c4bc7/docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md#L14-L120) — реконструкцию и dirty views. Старые DTO/лимиты и тезис injection=usage не импортируются вместе с идеей.

В необязательном Hy [canonical-state helper](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/system2_agent.py#L72-L346), выключенном по умолчанию на pin, изолированная проба принимала `The example sentence is: I use glasses.` и `He said, 'I use glasses'.` за личное использование. Это helper test, не полный пользовательский Hy failure. Роль user не устраняет возможность цитирования. V3 сохраняет контекст утверждения, а не растущий список бытовых regex.

[DCPM v1](https://arxiv.org/html/2606.09483v1) полезна траекториями и offline abstraction; hierarchy не становится process hierarchy, квадратичные pair sweeps не переносятся без границ. [Hy writer §5.3](https://arxiv.org/html/2610.22196v1) описывает два предшествующих chunks в reward annotation, не универсальное production writer правило. [LongMemEval v2](https://arxiv.org/html/2410.10813v2) различает update/temporal/abstention: это разные failure cases, а не новая предметная онтология ядра.

## 17. Memory transition audit 0.4

Сохраняются source findings 0.4 на Hy `7b7fd...` и их ограниченные пробы. [Fact reconciler](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/fact_reconciler.py), [Store](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/coding/store.py).

| Находка | Граница и решение |
|---|---|
| Retirement до insertion | `_execute` снимает predecessor, затем history/model work, затем insert; Store retirement — отдельный autocommit. Изолированная SQLite-пауза оставляла старую superseded и отсутствующего successor. V3 публикует revision/links/retirement/result атомарно |
| Progress summary ≠ atomic claim | WorkingFact описывает trace/session; продолжение задачи не отменяет все прежние факты/исключения |
| Subject gate не безусловен | `_SUBJECT_GATE_DEFAULT=False` и условный helper; prompt не runtime guarantee каждого режима |
| Successor withdrawn | Недоопределённый собственный V3 случай: A не становится current просто после удаления B; нужны оставшиеся основания/новая revision либо unknown |
| История несколько родителей, reader один | `_get_fact_ancestors_sync` выбирает `ORDER BY created_at ASC LIMIT 1`; проба A/B→C→D возвращала A,C без B и без исчерпания depth. V3 — visited/frontier и явная неполнота |
| Lexical rerank зависит от dense pool | Выбранный `search_facts` сначала требует vector collection и threshold, потом реранжирует оставшихся. V3 independent exact/lexical; это не обвинение всех Hy retrieval modes |
| Точное значение спрятано в details | Текст details не входит в тот embedding/lexical rerank; сохранение не гарантирует находимость. Нужен searchable cue/source path |
| Отсутствующий diagnostic | Verifier мог не дойти до consumer. Нужен target coverage/completeness, не автоматический pass |

Ни SQL-контрпример, ни synthetic candidate membership не являются запуском полного donor/V3 pipeline или benchmark recall. Полная прежняя запись с координатами и границами доступна в [историческом §17](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c28359fc2716f3b498ea512ca24a57801d18014c/docs/v3/AUDIT.md#17-memory-transition-audit-04). Все перечисленные решения остаются в Cognition, несмотря на сокращение повторяющейся прозы аудита.

## 18. Cross-domain learning audit 0.5

> Исторический отчёт подготовленной 0.5 сохранён ниже. Описанные пробы относятся к тому проходу; текущая 0.6 публикует материал и не выдаёт его за заново выполненные эксперименты.

**19 октября 2026; предложенное продолжение опубликованной V3 `c28359fc2716f3b498ea512ca24a57801d18014c`.** Проверен межобластный перенос и сжатие обобщений, а не повторена проверка coding replacement из §17. Основной новый источник — `hy_memory/pipelines/cross_domain_sweeper.py` целиком на Hy `7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a` (Git blob `700423e9b85b5351bcfcc0c87d09856dae898b70`), плюс функция `run_existing_schema_compaction` и её настройки в `system2_tools.py` на том же pin (blob `9bf7527b702e4b635e14a4d75cba2972becd323d`). Поиск по default branch использовался только для навигации; выводы ниже сделаны по закреплённому исходнику.

**Главный вывод:** похожесть, полезное обобщение, допустимая связь с существующим правилом и доказанный перенос — четыре разных результата. Можно дешёво найти кандидатов и автоматически выдать условную аналогию. Нельзя из одного соседства автоматически делать подтверждённое правило, снимать исходные различия или считать новый графовый edge новым независимым успехом. Нужен конечный путь внутри существующих модулей, а не ещё одна «система самоэволюции».

### 18.1 Где именно теряется смысл

| Проверенный путь | Наблюдение исходника / граница вывода | Решение V3 |
|---|---|---|
| `_process_cluster`, existing-core branch | Берётся первый элемент множества существующих targets; членам кластера добавляются edges без нового смыслового сопоставления | Несколько targets остаются альтернативами; конкретное присоединение требует адресного основания |
| `_scan_collisions` | Union-find превращает цепь подходящих пар в компоненту; все пары внутри неё не обязаны подходить | Компонента — лишь пакет кандидатов, не класс эквивалентных правил |
| `sweep` → `_fetch_basics_with_beh` | Первоначальный `limit=500` не передаётся в повторное перечисление и матрицы | Один конечный набор IDs/revisions на задание; явное продолжение охвата |
| `_process_cluster`, new-core branch | Для отсутствующего в `basic_map` узла в prompt подставляется ID вместо содержания | Загрузить допустимые исходные записи либо явно сократить/отложить набор до вызова модели |
| `_process_cluster`, null branch | Повторный вызов с теми же данными вновь вызывает модель; в этой ветви нет записи решения «нет нового обобщения» | `no_change` — завершённый результат обычного job на конкретных inputs/profile |
| `_ensure_beh_embeddings` | Повторная работа пропускается по `_has_beh`; этот marker сам по себе не идентифицирует метод получения представления | Использовать существующую привязку производного материала к input/method profile, не вечный Boolean |
| Optional schema compaction | Shared evidence/raw source и высокий cosine разрешают снять второй текст без проверки исключений | Общий источник не доказывает равенство утверждений; сначала проверить, что действительно сохраняется |

Это source-level находки и проектные контрпримеры. Они не измеряют частоту ошибок в установленном Hy и не объявляют весь upstream неработоспособным.

### 18.2 Существующее обобщение выбирается без проверки нового смысла

В [existing-core ветви](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/cross_domain_sweeper.py#L518-L593) собираются targets всех членов, затем используется `list(existing_core_ids)[0]`. Это не смысловая политика выбора при наличии нескольких разных cores. Даже замена множества сортированным списком устранила бы только зависимость выбора от порядка, но не отсутствие основания.

Далее недостающие связи добавляются к выбранному target. В этой ветви нет вызова индукции, пересмотра текста core или чтения исходных evidence для такого пересмотра. Может измениться его source-label, но это не проверка содержания. В новой-core ветви, напротив, есть модельный синтез и наследование evidence. Равный счётчик «merged» скрывает существенно разные преобразования.

**Изолированная проба:** два члена A/B уже связаны с разными core-A/core-B; внешние графовые и модельные вызовы заменены явными заглушками. Выбранные переходы исходной ветви добавили `B → core-A`, вернули один merge, не вызвали модель и не прочитали evidence. Текст выбранного core остался прежним. Это воспроизведение управления выбранной ветви, не тест реального GraphStore, качества модели или поведения других вызывающих путей.

**Для Eliot:** присоединение нового случая — отдельное утверждение о связи. Если оно точно проверяется по уже известному ключу, значению, условиям и источнику, не нужен LLM. Если нужен смысловой анализ, он выполняется одним ограниченным заданием. Сходство может создать навигационную аналогию без повышения support; оно не создаёт подтверждённую опору. Исходные процедуры остаются самостоятельными, а общий принцип не переписывает их условия. [Cognition §6.4](COGNITION.md#64-cross-domain-induction-without-forced-unification).

### 18.3 Связная компонента — не доказательство общего правила

[Поиск коллизий](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/cross_domain_sweeper.py#L414-L509) объединяет пары с высоким behavioral cosine и низким content cosine. На синтетических behavioral-векторах с углами 0°, 40° и 80° соседние пары имеют cosine около 0,766, а крайняя — около 0,174. При пороге 0,70 и ортогональных content-векторах получаются две разрешённые пары и одна компонента из трёх узлов.

Проба выполнила выбранную логику сканирования с заданными векторами. Она не моделировала качество реального embedding provider. Математический результат ожидаем: попарная близость не транзитивна. Ошибка возникает не от самого union-find, а при использовании его компоненты как уже обоснованного смыслового объединения, особенно в ветви без повторной интерпретации.

**Малое решение:** компонента даёт ограниченный список кандидатов; каждая предлагаемая связь/обобщение называет свои фактические опоры, различия и условия. Допустимо пропустить часть элементов или не создать общий принцип. Не нужно исправлять это обязательным полным попарным доказательством, новой онтологией или собственной ML-платформой.

В [DCPM §2.3](https://arxiv.org/html/2606.09483v1) collision scan и последующая модельная индукция описаны раздельно. Эта концепция полезна; экспериментальные результаты статьи не квалифицируют любую более позднюю ветвь кода, которая присоединяет новые узлы к старому core без того же преобразования. Параметры статьи также не являются автоматически значениями defaults выбранного pin.

### 18.4 Лимит в первой функции не ограничивает весь путь

В [начале `sweep`](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/cross_domain_sweeper.py#L187-L207) читается до 500 active L6 nodes. Но [_fetch_basics_with_beh](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/cross_domain_sweeper.py#L361-L406) заново выбирает все active L6 с behavioral embedding, без передачи первого списка или его предела. `_scan_collisions(basics)` строит матрицы из повторной выборки, а не из аргумента `basics`.

**Изолированная проба:** передан список из одного узла, fake fetch вернул три; сканировались три, и все три вошли в результат. Так проверен разрыв набора, а не реальный объём пользовательского графа. Если во втором наборе есть записи за пределами первоначальных 500, последующий `basic_map` может не содержать их текстов. В [сборке prompt](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/cross_domain_sweeper.py#L595-L608) тогда используется сам ID. В пробе модельная заглушка получила `Schema B: missing-b` вместо содержательной записи.

Масштабирование также выходит за первый предел. Только две float32-матрицы N×N при условных N=10 000 требуют 800 000 000 байт, примерно 763 MiB. Это арифметика размеров массивов, не измерение RSS Hy: дополнительные embeddings, mask, индексы совпадений и промежуточные данные сюда не входят. Никакого утверждения о фактических 10 000 узлах или OOM у пользователя нет.

**Для V3:** существующий job удерживает конечную membership по IDs/revisions. Детальные reads, feature lookup и prompt не расширяют её неявно; отсутствующий/недоступный материал явно меняет состояние работы до dispatch. Ограничиваются не только исходные узлы, но и рассматриваемые пары, объём prompt и число выходных связей. Продолжение с курсором/областью в том же job-механизме не объявляет частичный проход полным. Не обрабатывать один и тот же первый блок бесконечно, оставляя хвост без обслуживания. [Cognition §6.5](COGNITION.md#65-bound-the-whole-induction-not-only-its-first-query).

### 18.5 «Ничего нового» должно экономить следующий вызов

[Null-ветвь](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/cross_domain_sweeper.py#L602-L612) возвращает нулевые счётчики. Два последовательных прямых вызова выбранной ветви на одинаковых inputs вызвали модельную заглушку дважды. Это показывает отсутствие локального reuse именно здесь, а не доказывает отсутствие любого throttling или журнала в полном приложении.

У V3 уже есть no-change и stable job identity; их нужно применить и к поиску межобластных закономерностей, а не только к картам файлов. Успешное отсутствие обобщения завершает обычное задание на точных input/method revisions. Новые evidence, изменившийся профиль метода, существенное контрдоказательство или разрешённый запрос дают основание пересмотреть его. Unavailable/invalid/partial — не «ничего не найдено» и не постоянное исключение источников из будущей работы. Служебный просмотр результата и изменение timestamp не должны сами создавать новый semantic job.

Для [behavioral cache](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/cross_domain_sweeper.py#L302-L341) `_has_beh` сообщает о наличии прошлого представления, но эта проверка не доказывает его соответствие выбранному сейчас abstractor/prompt/encoder. Это не утверждение, что любой контент Hy мутирует под тем же ID или что весь upstream не умеет смену моделей. В Eliot применяется существующая привязка производного текста и вектора к реальному content/method profile. Смена abstractor затрагивает его производные материалы, а не автоматически все исходные embeddings. [Cognition §6.6](COGNITION.md#66-reuse-no-change-and-version-derived-features).

### 18.6 Общий источник не делает два вывода дубликатами

В [optional compaction](https://github.com/Tencent-Hunyuan/Hy-Memory/blob/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a/hy_memory/pipelines/system2_tools.py#L84-L209) проверяются пересечение evidence IDs, raw source IDs и cosine. После переноса evidence один текст остаётся, а другой получает `superseded`. Видимой проверки сохранения его отдельных условий/исключений в этом решении нет. Настройка `_S2_SCHEMA_COMPACTION_ENABLED` в изученном исходнике **false по умолчанию**.

**Изолированная проба:** опция включена только в стенде; даны одинаковые синтетические vectors и общий source. Два текста различают разрешённый retry read-only запроса и запрет слепого retry эффекта с неизвестным исходом. Выбранная логика разрешила merge и сняла вторую запись. Это контрпример достаточности условия, не результат реального embedding provider и не частота ошибочных merge в обычной установке. Мы не запускали весь Hy и не включали опцию у владельца.

**Решение:** exact replay/equivalence можно дедуплицировать детерминированно. Смысловое сжатие сохраняет не только evidence-ссылки, но и различающиеся условия и исключения. Если эквивалентность не установлена, обе записи остаются доступными как самостоятельные квалифицированные утверждения; навигационное соседство допустимо без снятия одной. Один источник способен содержать конфликт, альтернативы или несколько разных правил, а не только многократное подтверждение одного.

### 18.7 Конечный путь переноса вместо фреймворка самоэволюции

Предлагаемый consumer: перед неоднозначным повтором операции агент получает аналогичный прошлый случай и точное различающее условие — можно ли безопасно повторить действие либо сначала нужен readback. Он не получает общее «повторяй после timeout», выведенное из смешанных read/write случаев.

В существующих модулях достаточно последовательности: выбрать ограниченные допустимые процедуры → найти потенциальные соответствия → сопоставить роли действий, предусловия и контрпримеры → выдать точную аналогию, новое provisional обобщение или no-change → атомарно сохранить только названное преобразование → проверить применимость и исход в следующем контексте. Исходные процедуры/эпизоды не уничтожаются. Не нужны отдельный conceptual-store, semantic merge daemon, психологический профиль пользователя или ещё один планировщик.

Два пространства представлений у Hy — возможный способ отбора, не обязательная цена каждого observation. V3 сначала использует имеющийся lexical/vector поиск по процедурам; отдельный behavioral feature оправдывается только конкретными пропусками переноса. Полезное обобщение может быть условным и включаться локально автоматически. Проверка оснований не возвращает approval каждого кандидата; поддержка при этом не растёт от числа парафраз и повторных связей.

### 18.8 Что проверено и что подготовлено

Выполнены изолированные Python-пробы выбранных control-flow ветвей с fake graph/model и заданными vectors: выход за входную membership; нетранзитивная цепь близостей; existing-core присоединение без индукции; ID вместо текста; повтор null-решения; optional compaction при разных условиях. Служебные imports, комментарии, logging и неисполняемые ветви сокращены; эти пробы не выдаются за побайтно неизменённый полный runtime. Аритметика матриц не является benchmark.

Подготовлены изменения только Cognition, этой главы общего аудита и V3 navigation. Предыдущие 34 требования, 29 A15 cases и 43 donor rows не редактируются. Добавлены восемь будущих walkthroughs; это не тестовая фабрика V3. Code, schema, зависимости, CI, ACTIVE registry и main не менялись. Нового независимого субагентного review, живого Hy/SurrealDB/controller прогона и доказанного коэффициента сокращения нет.

Проверка источников и подготовка patch не означают публикацию нового GitHub commit. Фактический статус файлов/patch и их проверки сообщаются отдельно; прежние PASS и review statements относятся к прежним байтам.

## 19. Harness2: рекурсия для Eliot, не новый агентный runtime

**Новый донор D44.** Прочитан код `google-research/harness2@1cfe254e8d25b15f37048c3730134686abe60335` — commit от 14.10.2026; статья [2610.14224v1](https://arxiv.org/html/2610.14224v1) опубликована 09.10.2026. Это новое чтение текущего прохода, не строка из архива 16.10. Код имеет Apache-2.0 headers; сторонние benchmarks/substrates имеют собственные условия. Изучение не является запуском модели или воспроизведением результатов авторов.

### 19.1 Два разных объекта улучшения

Внутри задачи Harness2 изменяет способ исполнения: **Propose → Probe → Compose**. Между задачами он сохраняет опыт того, **как улучшать способ исполнения**. Следующая задача начинает с общей базовой конфигурации, а не механически наследует все настройки предыдущей; накопленный improvement harness направляет новый поиск. Он фиксирован внутри task-level сравнения и обновляется после него. Веса моделей не меняются. Это существенное отличие от простой библиотеки готовых ответов или бесконечной команды «попробуй ещё раз».

Статья прямо отличает adoption от verified optimality и указывает, что поведенческий контраст без ground truth ограничен стохастичностью и общими ошибками моделей. Для Eliot полезна возможность улучшаться без универсального внешнего верификатора, но не разрешение называть любой выбранный вариант доказанно лучшим.

### 19.2 Что именно делает код

| Файл на закреплённом SHA | Прочитанный механизм | Значение для Eliot |
|---|---|---|
| [core/recursion.py](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/recursion.py) | General/invariant и domain proposals, execution probes, composition; parallel и sequential modes | Сравнивать конкретные способы работы по наблюдаемым последствиям, не по красоте prompt |
| [core/selection.py](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/selection.py) | Анонимный выбор существующего deliverable; затем reflect_adoption и извлечение cue/lesson/evidence | Выбор результата и извлечение transferable improvement lesson — разные стадии |
| [core/library.py](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/library.py) | Adopted harness + EXPERIENCE.md, индекс, разделение библиотек | Урок должен объяснять, когда, что и почему менять; выбранный artifact можно раскрыть отдельно |
| [core/ledger.py](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/ledger.py) | Экспериментальные R=4k/P=3k, labels, cached/attempts; selection/reflection отдельно | Учитывать все реальные расходы; не выдавать один recursion step за один API call |
| [core/schedule.py, 390–560](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/harness2/core/schedule.py#L390-L560) | Передаёт library в recursion, строит finals pool, вызывает reflection при enabled library/успешном выборе и добавляет experience | Проверен реальный consumer библиотеки, а не только определение класса |
| [docs/EXPERIMENTS.md](https://github.com/google-research/harness2/blob/1cfe254e8d25b15f37048c3730134686abe60335/docs/EXPERIMENTS.md) | Режимы, порядок задач внутри domain, библиотека, воспроизводимость, отдельное baseline judging и ограничения web access | Не копировать настройки benchmark как безопасные/дешёвые defaults продукта |

В parallel режиме k задаёт ширину предложений/композиций; это не глубина бесконечного дерева. Sequential передаёт composed tree и накопленные наблюдения в следующий шаг. `_run_stage` валидирует форму изменений и может сохранить исходное дерево при ошибке/отсутствии изменения. Это проверка пригодности интерфейса, не доказательство улучшения задачи.

### 19.3 Важное ограничение: финальный выбор не включает reference outputs

`selection_pool` явно игнорирует переданный base и возвращает только `agg1..aggk` либо `c1..ck`. При k=1 `trivial_selection` возвращает единственный final без модельного выбора. Это **не означает**, что Compose всегда меняет код: сама композиция может сохранить базовое дерево. Но отдельный фактический reference output не является кандидатом на этой стадии выбора.

**Для Eliot:** текущий baseline/no-change остаётся допустимым результатом adoption. Ни proxy-выбор модели, ни успешно записанный artifact не доказывают превосходства. Если изменённые кандидаты хуже либо сравнение неинформативно, можно оставить исходное и не писать обязательный положительный урок. Не добавляем отдельный approval комитет: это обычная ветвь существующего решения.

При последовательном уточнении текущим становится composed tree, а не обязательно объективно более успешный. Поэтому история предложений/контрастов полезна, но глубина рекурсии сама по себе не должна повышать confidence.

### 19.4 Опыт улучшения не равен обязательному «улучшению найдено»

`reflect_adoption` читает выбранный harness, reference/candidate traces, edits и решения. `_distil` извлекает cue/lesson/evidence, optional confidence и edits; `has_experience` проверяет непустые необходимые строки. Эти проверки не являются независимым доказательством grounding или causal effect — качество semantic reflection всё ещё зависит от модели и наблюдений.

Берём форму **ситуация → попытка изменения → наблюдаемый контраст → ограничение → когда полезно повторить этот способ улучшения**. Сохраняем не только успешные snippets, но и реальные counterexamples/no-change. Не требуем выдумывать experience, если материала нет. Повторная доставка той же reflection не создаёт новый независимый опыт и не запускает бесконечную self-summary петлю.

### 19.5 Цена одной рекурсии и ограничения эксперимента

R=4k включает k base, 2k probes и k finals; P=3k — INV, DOM и composition. Ledger отдельно считает попытки; selection/reflection находятся вне этих двух чисел. Кэшированные reference executions учитываются в структуре опыта, поэтому это не гарантированное количество новых оплаченных вызовов. Один agent rollout или improvement session тоже может содержать несколько модельных запросов и tools.

Таким образом, k=1 — не «один недорогой вызов»: это базовая схема четырёх прогонов и трёх стадий улучшения с возможной reflection; реальная стоимость зависит от executor, кэша, retries и дальнейших вызовов. В Eliot нет обязанности выполнять такую схему для каждого события. Один релевантный кандидат, дешёвое сравнение memory recipe на одинаковом материале или завершённый no-change могут быть достаточны.

Experiment guide сообщает, что public grading materials доступны через сеть и один validation Codex rollout сам скачал rubric; release не ограничивает network и использует отключённый Codex sandbox. Это ограничение данного experiment setup, **не доказательство загрязнения всех опубликованных результатов**. Статический фильтр grader verdicts в подготовленном контексте не запрещает получение материала через другой канал. Eliot не наследует unrestricted executor ради обычной обработки памяти.

### 19.6 Минимальная реализация наших двух циклов

**Текущая задача:** выбрать конкретный наблюдаемый недостаток и текущую method revision → предложить ограниченное изменение → сравнить на подходящем повторяемом материале/копии или разрешённом исполнении через controller → составить вариант либо оставить baseline → сохранить выбранный метод и контраст. General/domain направления полезны как два вида гипотез, не два обязательных агента на любую задачу.

**Следующие задачи:** обычная memory procedure хранит lesson о способе диагностики/улучшения и ссылки на реальные попытки. Dreamer перед следующей работой извлекает релевантные lessons: как выбрать проверку, что менять первым, чего не объединять. Это улучшает саму стратегию последующей генерации/сопоставления, а не только текст ответа.

`memory`, `learning`, `jobs` и controller уже обеспечивают всё необходимое. Дополнительные fields нужны только для реально используемых связей attempt/method/parent work и remaining budget. Не строим ReflectionStore, RecursionServer, отдельную library DB, workflow engine или по процессу на уровень. Никакой рекурсии ради самой рекурсии и replay внешнего необратимого действия ради сравнения.

Подробный consumer — [Cognition §6.7](COGNITION.md#67-two-recursive-loops-from-harness2), общая граница — [Implementation §7.4](IMPLEMENTATION.md#74-recursive-improvement-from-harness2). Метод и его исходы версионируются; права, исходная цель и критерии сравнения не подменяются candidate. Полезный условный совет может применяться автоматически, не получая ложного статуса «доказанное общее улучшение».

## 20. Где проектировщик сам вернул бюрократию и что изменено

Это разбор собственных V3 решений, а не перечень чужих недостатков. Часть возникла из правильного желания не потерять данные, но была выражена сильнее необходимого.

| Перегиб опубликованной V3 | Почему мешал | Реальная правка |
|---|---|---|
| Старый no-SDK ADR требует отдельного снятия запрета | Донор вновь становится действующим нормативом; поощряется собственный protocol client | Implementation §1.3 выбирает обычный официальный network SDK сначала; конкретный новый defect может изменить выбор без церемонии снятия V2 вето |
| Любое более широкое reuse требует independent comparison | Применимость перепутана с доказательством эффективности; условный полезный опыт остаётся локальным без причины | Architecture §7 и Implementation §7.2 разрешают automatic provisional transfer в подходящей разрешённой ситуации; сравнение нужно для сильного effectiveness claim |
| Отдельное operation family легко становится универсальным ledger | Каждую read/helper/notification проводят через второй lifecycle | Mutation result хранится рядом с owning record/job, если этого достаточно; отдельная строка только по реальной необходимости readback |
| Один собственный supervisor как безусловная поставка | Даже существующий подходящий host supervisor не исключал дублирование | Один фактический owner; reuse только при реальной независимой coverage, иначе малый standalone mode |
| Общий owner/organization/policy vocabulary | Провоцирует grant graph и multi-tenant платформу для локального пользователя | Local project/config + routes/retention; никакого общего principal calculus в baseline |
| «Проверить происхождение» без ограничения стоимости | Можно реализовать полный рекурсивный corpus walk на каждом чтении | Только релевантные выбранные зависимости, memoization и affected views; неполнота честна, не второй lineage engine |
| Fingerprint/manifest язык без ограничения назначения | Агент снова хеширует каждый внутренний объект и создаёт proofs | Implementation §2.4: hashes для реальных bytes/cache/backup; normalizer и notification не требуют digest closure |
| Сотни повторяющихся объяснений статуса | Сводный аудит сам превращается в постоянно растущий административный журнал | Исторические версии сохранены в Git; текущая редакция сведена, source findings и все исходные матрицы оставлены |
| «Сначала квалифицировать всё» | Неработающий route одного типа может остановить независимые полезные функции | Capability-specific реальные проверки перед заявлением её готовности, не общий запрет на работу |

### 20.1 Что не удаляем под видом простоты

Stable event ID предотвращает дубли; expected revision и current claim — позднюю запись; реальные permissions и credentials защищают границы; source refs позволяют исправить ошибочный вывод; deletion restrictions предотвращают replay удалённого известного события; checksum реального backup проверяет его bytes. Это конкретные данные и операции, не enterprise ceremony.

Отказ от криптобюрократии не означает самописный crypto, публикацию секретов или отсутствие транзакций. Нужный контроль ставится один раз у реальной границы. Hash не даёт прав; policy field не sandbox. Отсутствие надёжной гарантии у внешнего executor указывается прямо, а не «доказывается» JSON-квитанцией.

### 20.2 Не заменить один контролирующий аппарат другим

Не переносим из Claude запрет слов Receipt/Fence/Lease как главный тест правильности, approval каждой таблицы/helper, обязательные 13 разделов карточки и произвольные цифры LOC как физический закон. Иначе агенты будут переименовывать те же схемы и дробить файлы.

Рабочая проверка проще: что делает функция для пользователя; кто владеет состоянием; какой named failure она устраняет; не делает ли библиотека/БД то же; появился ли второй owner; виден ли реальный consumer. Код будущего продукта должен отвечать на это поведением, а документация — не заказывать лишний слой заранее.

### 20.3 Не превращать карту аудита в новый продукт

Карта A01–A14 хранит прочитанные места, границы и следующие действия. Она не меняет права, не запускает workflow, не имеет подписей/read receipts и не является критерием runtime support. Один источник может дать решение «не брать». Повтор чтения нужен по изменениям или конкретному пробелу, не ради роста счётчика покрытия.

## 21. Что сделано в текущем проходе и что дальше

**Новые чтения:** V1 Production Architecture §0–1; V2 I1.2, I5.6, I2.20 и Phase A ADR; notification admission до тела функции и request hash 1–175; cue entrypoints и normalize до derive/path helpers; Architecture и substantive Implementation V3; приложенные 0.5 и Claude donor/anti-bureaucracy предложения; Harness2 README, recursion, selection/reflection, library, ledger, выбранный schedule caller, experiment guide и методы статьи.

**Ограничено:** notification emit callers и фактическая доставка ещё не прослежены полностью; весь ORS, migrations, installation, tool adapters и controller не перечитаны; полный release ZIP повторно не загружен. Это не мешает назвать конкретные уже проверенные лишние слои, но не позволяет заявить полный source audit. В [AUDIT-MAP](AUDIT-MAP.md) эти строки остаются открытыми с точным следующим чтением.

**Документационные изменения:** Architecture и Implementation убирают собственные перегибы; Cognition получает 0.5 transfer semantics и два recursive loops; AUDIT сохраняет прежние ключевые finding families, 34 требования, 29 A15 scenarios, 43 старых donor IDs и добавляет D44; map и navigation обновлены. §18 сохраняет отдельный отчёт прежних synthetic probes без выдачи их за новые эксперименты.

Следующий наиболее ценный проход — связать notification identity/callers/DB write и реально потребляемый capture/context, затем разложить ORS/process lifecycle по ненужным ролям и полезным failure cases. Параллельно по карте возвращаться к неохваченным требованиям обучения и донорским shortlist, а не снова начинать весь аудит с README.

Проверки текстов, ссылок, публикации и CI сообщаются в PR по факту. Не выполнялись продуктовые тесты, новый model inference, полный Harness2/Hy pipeline или независимое субагентное review. Изменения документации не означают слияние в main и не закрывают всю задачу #5324.
