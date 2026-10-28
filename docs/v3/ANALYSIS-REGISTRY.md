# Eliot V3 — реестр анализа

**Сверка: 2026-10-28. Рабочая документация PR #5325; не merged authority и не runtime gate.**

Это единственный активный реестр V3. Здесь хранятся текущие разрывы, решения,
границы проверки и следующий шаг. Контракты принадлежат своим документам;
[AUDIT](AUDIT.md) и [AUDIT-MAP](AUDIT-MAP.md) хранят обоснования и источники.
Хронология остаётся в Git и issue/PR, а не в журнале внутри реестра.

Для продолжения прочитайте таблицу этапов и строки своей задачи. Не загружайте
все документы и весь реестр в каждый агентный контекст.

## Documentation stages

Работа идёт в существующих issue #5324 / PR #5325. Этап — не требование создать
отдельные issue, PR, сервис, проверяющий framework или новый реестр.

| Этап | Статус | Изменяемая область / следующий шаг | Критерий завершения |
|---|---|---|---|
| D0. Установить версии и владельцев | `CHECKED` source | Зафиксированы снимки ниже; перед новой интеграционной правкой обновить их. | Рабочая V3-ветка, V2 donor, отдельный Store PR и controller не смешаны. |
| D1. Исправить вход и маршруты чтения | `REVIEW_PENDING` | AGENTS, WORKFLOW, START, root/docs/V3 README и ARCHITECTURE_CONTRACT сокращены до правил и ссылок. | Независимый читатель по одной задаче находит owner section и следующий шаг; не получает обязательный стек книг или V2-инструкцию для V3. Изменения пока не слиты. |
| D2. Согласовать нормативные документы с controller | `OPEN` — следующий | Architecture §0/§10; Implementation §0/§9/§11; Cognition §0; Inference Contract; controller #199. Удалить устаревшие утверждения о полностью отсутствующем L0/L1 и проверить реальный mutation/auth/result API. | Все затронутые владельцы согласованы с одним проверенным controller snapshot. Отсутствие inference отделено от наличия foundation. Никакого переноса старой модели receipts/binding по названию issue. |
| D3. Упростить конструкцию и порядок реализации | `OPEN` | Проверить дубли backup/restore между четырьмя контрактами; назначить каждому правилу один owner, остальным дать ссылки. Разделить минимальный старт Base и позднюю qualification. | Для каждого сохранённого механизма названы caller, owner, result/unknown и consumer; ненужные процессы/таблицы/обвязки удалены. Полная backup/inference qualification не становится условием написания первого capture/open пути. |
| D4. Свести Store-контракт и оба набора assets | `OPEN` | Implementation §4–6, `store/`, #5326 / PR #5327; исправлять source только в его owning task. Начать с R-174 ниже. | У каждого поля, запроса и ограничения есть writer/reader; design assets и production source не выдаются за один артефакт. Компиляция, семантика DDL и live qualification отмечены отдельно. |
| D5. Проверить сохранение требований и сценарии | `OPEN` | По AUDIT-MAP пройти capture→restart→open/context, correction→history→consumer, learning→later use, отказ/unknown, privacy/erase и backup/restore. | Ни одно исходное требование не исчезло при сокращении; в каждом сценарии названы владелец, устойчивое состояние, отказ и потребитель. Вывод основан на конкретных разделах/исходниках, не на количестве документов. |
| D6. Интеграция документации | `BLOCKED` | Независимое ревью, точный финальный diff, применимые doc/link checks и существующий merge gate; разрешить его реальную несовместимость с V3 в owning scope. | Проверен финальный кандидат; обязательные проверки и независимая интеграция выполнены. Никаких фиктивных receipts, снятия protection или незаявленных CI-изменений. |

D2–D5 допускают ограниченные параллельные read-only проверки. Изменение общих
файлов выполняет один writer. Закрывайте этап по его результату, а не потому,
что добавлена строка или создан PR. Runtime implementation — отдельная задача;
эти этапы не создают обязательную фабрику аудита перед каждой строкой кода.

## Snapshot and evidence limits

| Объект | Проверенный снимок | Что установлено |
|---|---|---|
| Memory `main` | `5aac094834fb5635921b550c821cb933a1196105` | Интеграционная база; retained V2. |
| V3 документация до этого изменения | `abec550fb61d90db7bf0168a2191f9697a70a5c8`, PR #5325 open | Architecture draft.19 / Implementation draft.42 / Cognition draft.23 / Contract 0.18 — исходные drafts, не доказанная синхронизация. |
| Store source | `c5154b0ea352980279cd0d46ca3353148d4c8027`, PR #5327 open | Отдельный schema/query crate; не интегрирован в документационную ветку и не является готовым Store. |
| Controller | `2bbde3a0cafd48d57e7ade8fc723a90e1fbc4685` | Проверены roadmap, API и dispatch маршрутизатора; runtime здесь не запускался. |

`CHECKED` означает только названную проверку источника. `DECIDED` — выбранный
дизайн, `PARTIAL` — неполное покрытие, `OPEN` — нерешённый вопрос, `BLOCKED` —
конкретная зависимость, `REVIEW_PENDING` — изменение требует независимого ревью.
`NOT QUALIFIED` не превращается в runtime PASS после проверки текста или SHA.
Наследованные source/design выводы ниже не являются повторным аудитом в этом проходе.

## Controller dependency

Проверенный [roadmap](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/2bbde3a0cafd48d57e7ade8fc723a90e1fbc4685/docs/roadmap.md)
уже отмечает L0/L1 реализованными. Поэтому старое «V2 specification-only,
L0.1–L1.11 unchecked» больше не является текущим фактом.

В проверенном [Router::handle](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/2bbde3a0cafd48d57e7ade8fc723a90e1fbc4685/crates/eliot-daemon/src/router.rs#L163-L195)
нет `inference.*` dispatch. [API](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/2bbde3a0cafd48d57e7ade8fc723a90e1fbc4685/docs/spec/api.md#L47-L58)
хранит command bindings непосредственно, прочие writes — в `writes`; старый
план «reuse write_receipts» нельзя считать существующим интерфейсом.

| ID | Текущее решение / разрыв | Следующее действие |
|---|---|---|
| R-123 | Старый controller pin `613ea6b5` — исторический дизайн, не current main. | D2: сверять текущие API/source, не восстанавливать V1. |
| R-130 | Foundation присутствует по roadmap и source; полный runtime здесь не проверен. | D2: убрать ложную очередь «сначала реализовать L0/L1». |
| R-131 | #200 описывает прежнюю allocator/pointer модель; сам номер issue не доказывает применимость к текущей реализации. | D2: проверить актуальные generation/command semantics; не навязывать старую модель автоматически. |
| R-048 | Memory inference `BLOCKED`: в проверенном Router отсутствуют его методы; совместимость Contract 0.18 не установлена. | D2: согласовать narrow interface с controller #199. Base не блокировать. |
| R-126 | Прежний выбор durable state требует сверки с нынешними commands/`writes`. | D2: использовать реального владельца mutation identity, не второй ledger. |

Это источник для пересмотра, не errata-контракт. До D2 противоречащие controller
утверждения в четырёх drafts не использовать как основание для реализации
inference. Исправление должно попасть непосредственно в owning documents.

## New documentation and source findings

| ID | Наблюдение | Решение / оставшаяся работа |
|---|---|---|
| R-172 | Входные страницы одновременно предписывали прямое чтение V3 и общий обязательный V2 reader. | D1: область V2-блоков явно ограничена donor edits; existing merge gate не отменён. Проверить независимым чтением. |
| R-173 | Default reading order заставлял читать несколько книг и audit; индексы копировали backup/schema/controller детали. | D1: task→owner-section маршруты; подробности остаются у владельцев, audit читается по вопросу. |
| R-174 | Store PR #5327 имеет source-level разрывы, перечисленные ниже. | D4 / #5326: исправить owning source и сверить контракт; не объявлять готовый Store по hash/manifest. |
| R-175 | Retained `workstreams/ACTIVE.toml` всё ещё кодирует старые V2 programmes как active. | Агентам запрещено возобновлять их по этому признаку. D6: отдельно проверить consumers перед машинной миграцией; не заявлять, что prose freeze изменил инструменты. |
| R-176 | Формула «все drafts synchronized» скрывала устаревшие controller prerequisites. | Удалена из entry pages; R-024 открыт до D2–D5. |
| R-177 | Slice 0 объединяет запуск, Store, полный набор отказов, backup/restore/rotation до первого полезного Base. | D3: разложить production increments и позднюю qualification, сохранив обязательные инварианты безопасности. |

### R-174: exact Store follow-up

Проверять на source PR #5327, не редактировать его файлы через документационный PR.

- В [queries.rs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c5154b0ea352980279cd0d46ca3353148d4c8027/crates/storage/eliot-v3-store-schema/src/queries.rs)
  используются parent constants `SMALL_READ`, `PAGE_READ`, `BACKUP_PAGE`,
  `SCHEMA_READ`, но import перечисляет только четыре типа. Исправить разрешение
  имён и выполнить минимальную компиляцию/Clippy; компилятор здесь не запускался.
- `ObservationInsert` использует `SMALL_READ.max_input_bytes = 16 KiB`, хотя DDL
  допускает inline body до 65,536 символов плюс metadata. `OpenMemoryCurrent` и
  `OpenMemoryHistory` имеют result budget 64 KiB при content/snapshot limits
  262,144/393,216 символов. Согласовать query-specific byte bounds с фактически
  допустимыми объектами и JSON overhead, не поднять все пределы вслепую.
- Bounds в `QuerySpec` — metadata, не исполняющийся limiter. Source содержит
  strings/assets без подключённого Store client. Сверить реальные bind/decode,
  response caps, mutation transaction и consumer, прежде чем заявлять enforcement.
- Design pack намеренно оставляет cross-field assertions и live expected catalog
  непроверенными; source PR уже содержит такие ASSERT и выводит catalog definitions
  из своих DDL-строк. Это разные evidence levels, не доказанное серверное INFO
  readback. D4 должен выбрать один поддерживаемый asset owner и явную границу проверки.

## Retained product decisions and gaps

Стабильные R-идентификаторы сохранены, в том числе прежние группировки. Подробная
предыдущая формулировка доступна в
[проверенном предшественнике реестра](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/abec550fb61d90db7bf0168a2191f9697a70a5c8/docs/v3/ANALYSIS-REGISTRY.md),
а не во втором активном документе. Следующие строки — выбранный design backlog,
не подтверждённый runtime и не отдельный график разработки.

| ID | Сохранённая граница / незакрытый разрыв | Этап документации |
|---|---|---|
| R-001 | Host/controller исполняет внешнюю работу; Memory владеет памятью. | D3, D5 |
| R-002 | Supervisor/daemon/Store/candidate: запуск и отказ ещё не квалифицированы. | D3, D5 |
| R-003 | Work address: project/workspace + task или actor/session; не path/branch. | D5 |
| R-004 | Prepared/emitted/used packet — разные факты; нужен реальный host consumer. | D5 |
| R-005 | Correction атомарно сохраняет observation/history/current/result. | D4, D5 |
| R-006 | Шесть Base tables; assets не равны исполняющемуся Store. | D4 |
| R-007 | Exact current/history handles без fall-forward/resurrection. | D5 |
| R-008 | Conjunctive/alternative/advisory grounds; циклы и erasure ещё проверить. | D5 |
| R-009 | Direct/exact/lexical/vector/relation arms независимы; bounded readers. | D4, D5 |
| R-010 | Recipe revision заморожена в job и должна менять later context. | D5 |
| R-011 | Origin/reuse/disclosure независимы; scope проверяется в реальном пути. | D4, D5 |
| R-012 | Claude capture profile — design, нужен installed-build путь. | D5 |
| R-013 | Context должен действительно пересечь host boundary. | D5 |
| R-019 | Backup/restore: exact cut, fence, terminal records, lease, rollback. | D3, D5 |
| R-020 | Erasure: все контролируемые copies/roots/backups; внешний provider отдельно. | D5 |
| R-021 | Improvement исправляет наблюдаемый failed edge, не intelligence score. | D5 |
| R-022 | Disagreement сохраняет alternatives/grounds и различающий observation. | D5 |
| R-023 | Daemon public control; supervisor privileged effects; status из readback. | D3, D5 |
| R-025 | Interpretation запускается по committed input/correction/question. | D3, D5 |
| R-026 | Один active + coalesced successor; waiting не означает retry. | D3, D5 |
| R-028–R-045 | Recipe bootstrap, attribution, coverage, vectors, commitments, bounded reads, consolidation/split/forgetting и typed results. | D3, D5 |
| R-071–R-081 | V2 capture/spool/packet/broad-read findings — donor observations, не V3 support. | D5 |
| R-082 | Surreal Rust SDK baseline `NOT SELECTED`; пересмотр только по реальной потребности. | D3 |
| R-083 | SurrealDB 3.3.4 asset identity ≠ Windows runtime qualification. | D4, D5 |
| R-084–R-100 | Store transport, roles, schema, durability, fixed DTOs: design, не runtime. | D3–D5 |
| R-101/R-107 | Brief spool cut + replay barrier; проверить in-flight и crash. | D5 |
| R-102–R-106 | Process/listener/peer identity, mutual IPC, cancellation-safe socket owner. | D5 |
| R-108–R-116 | Privileged lifecycle, rollback, ACL, rotation и generation backpressure. | D3, D5 |
| R-150 | Schema identity: wrapper/DDL/catalog; полная transaction не квалифицирована. | D4 |
| R-151 | Canonical string IDs + explicit projections/DTOs; без generic codec. | D4 |
| R-152 | Base FTS analyzer/index/query: source/design evidence, не live qualification. | D4 |
| R-153 | Optional UNIQUE: canonical NONE; concurrency остаётся непроверенной. | D4 |
| R-154 | Numbered FTS score; zero-score match не отбрасывать. | D4 |
| R-155 | Bounded lexical snapshot; не durable cross-call BM25 cursor. | D4, D5 |
| R-156 | Plain INFO owned maps; exact live catalog strings ещё проверить. | D4 |
| R-157 | Bounded streaming restore lease, не handle на каждый part одновременно. | D5 |
| R-158 | OS-random Base IDs, canonical prefix/encoding; это не время. | D4 |
| R-159 | Derived unique keys: domain + length-prefixed components. | D4 |
| R-160 | Field guards не заменяют operation/digest/cross-row invariants. | D4 |
| R-161 | Индексы обслуживают конкретных readers; планы требуют проверки. | D4 |
| R-162 | Work-address columns, не scan/parse binding_json для continuation. | D4 |
| R-163 | Exact DEFINE FIELD grammar: не угадывать syntax. | D4 |
| R-164 | READONLY разрешает first/same assignment; не владеет identity. | D4 |
| R-165 | ASSERT: per-field и cross-field evidence разделены. | D4 |
| R-166 | PARAM/index-cancel tests не квалифицируют весь DDL wrapper. | D4 |
| R-167 | Bound metadata через production client остаётся `NOT QUALIFIED`. | D4 |
| R-168 | EXPLAIN — evidence для конкретной версии/данных, не источник истины. | D4 |
| R-169 | `store/0001-base.surql` — design candidate. | D4 |
| R-170 | `store/queries-base.surql` — fixed read candidates. | D4 |
| R-171 | Capture/revision/job mutation scripts и cross-field enforcement ещё не замкнуты. | D4 |

## Retained inference and recovery design

Эти решения требуют D2 до реализации. Они не утверждают, что нынешний controller
уже предоставляет предложенную схему, credentials или методы.

| ID | Сохранённая граница / незакрытый разрыв |
|---|---|
| R-047 | Memory semantic job и controller physical call имеют разных владельцев. |
| R-053 | Narrow Memory caller; никаких owner/Agent/automation/plugin fallback. |
| R-117 | Stable caller identity должна переживать rotation/rollback. |
| R-125 | Pre-send mutation identity, exact replay/conflict; сверить реальный controller API. |
| R-128/R-129 | Fixed restore inventory и явный history gap. |
| R-132 | Retention ограничена сохранёнными backup/dependencies. |
| R-133 | External-ID state нельзя откатить вместе со Store. |
| R-134 | Cancel/release/retention нуждаются в устойчивом pre-send identity и readback. |
| R-135 | Private credential publication с точным owner. |
| R-136 | Cut должен disposition каждый внешний mutation ID. |
| R-137 | Caller cleanup и owner break-glass не взаимозаменяемы. |
| R-138 | Membership tombstone не равен сохранению или удалению content. |
| R-139 | In-cut dependent copies остаются защищены до снятия dependency. |
| R-141 | Plan digest не содержит себя и поздние manifest/part digests. |
| R-144 | Abort/retire terminal facts переживают cleanup, но не доказывают erasure. |
| R-147 | Daemon mutation/backup owner; supervisor candidate/cutover; проверить lock order. |
| R-148 | Final backup directory впервые виден с fence, не пустой reservation. |
| R-149 | Неограниченный all-part handle set `SUPERSEDED` решением R-157. |

## Development and synchronization

| ID | Состояние |
|---|---|
| R-058–R-067 | Сохраняется вывод против bureaucracy: connected behavior, один ledger, cheap preflight, без object family на каждое существительное. D3 проверяет применение. |
| R-049 | Code first; minimum fmt/changed-package Clippy; broad qualification после assembled product. Пропущенный check не PASS. |
| R-059 | Исправлять owner text вместо append-only пояснений. |
| R-024 | `OPEN`: полная нормативная синхронизация не подтверждена; нужны D2–D5. |
| R-076 | `PARTIAL`: Base независим от inference по design; Store assets/source требуют D4. |

## Source coverage

S-001–S-089 остаются наследованными свидетельствами в AUDIT/AUDIT-MAP и Git;
их прежний `CHECKED` не означает повторной проверки или квалификации донора целиком.
S-056/S-057/S-058/S-073 описывают прежний controller snapshot, а не текущую готовность.
S-084–S-087 — exact-tag Surreal parser/field/UNIQUE/PARAM/INFO/FTS evidence;
S-088/S-089 — design и candidate assets. Они не доказывают конечный Store wrapper.

| ID | Проверено в этом проходе | Граница |
|---|---|---|
| S-090 | Memory main, PR #5325 state/head, entry pages и существующий registry на снимках выше. | Навигация/authority и воспроизводимые противоречия, не полный runtime audit. |
| S-091 | Controller pinned roadmap/API/Router на `2bbde3a0`. | L0/L1 уже присутствует; inference dispatch отсутствует; live execution не выполнялся. |
| S-092 | Store PR #5327 metadata и schema/query source на `c5154b0`. | R-174 source review; compile/DDL execution не выполнялись. |
| S-093 | Entry-point candidate и сохранённые V2 reading blocks. | Требуется независимое ревью D1 и final-tree checks D6; не product proof. |

## Integration blockers

У прежнего documentation head `abec550f` run
[40545730770](https://github.com/UnknownAlienHuman/eliot-memory-os/actions/runs/40545730770)
завершился failure. Предыдущая диагностика: `EMPTY_DOCUMENTATION_EVIDENCE`,
MergeCompile skipped; отдельно отмечался SurrealDB provisioning failure.
Это baseline evidence, не результат проверки нового candidate. Новый head должен
получить собственные результаты; status брать из CI, не из этой таблицы.

Независимое ревью и интеграция не выполнены этим изменением. V2 router/gate не
переписан; workflow/protection/runtime source не меняются. Отсутствующие проверки,
полный граф ссылок retained tree и runtime qualification не объявлять пройденными.
