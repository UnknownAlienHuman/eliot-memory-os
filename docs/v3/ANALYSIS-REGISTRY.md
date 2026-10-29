# Eliot V3 — реестр анализа

**Сверка: 2026-10-29. Рабочая документация PR #5325; не merged authority и не runtime gate.**

Единственный активный реестр V3: текущие решения, разрывы, границы проверки и следующий
шаг. Контракты принадлежат своим документам; [AUDIT](AUDIT.md) и
[AUDIT-MAP](AUDIT-MAP.md) хранят обоснования/источники. Хронология — в Git и issue/PR.
Для продолжения читайте этап и строки своей задачи, не весь каталог.

## Documentation stages

Работа продолжается в issue #5324 / PR #5325. Этап не требует отдельного issue, PR,
сервиса, проверяющего framework или второго реестра. Runtime — отдельная задача.

| Этап | Статус | Изменяемая область / следующий шаг | Критерий завершения |
|---|---|---|---|
| D0. Установить версии и владельцев | `CHECKED` source | Снимки ниже; обновить перед изменением внешнего контракта. | V3 working branch, V2 donor, Store source и controller не смешаны. |
| D1. Исправить вход и маршруты чтения | `REVIEW_PENDING` | AGENTS/WORKFLOW/START и индексы сокращены; Store route теперь ведёт к одному source owner. | Независимый читатель находит owner section без обязательного стека книг и V2-инструкций для V3. |
| D2. Согласовать нормативные документы с controller | `REVIEW_PENDING` | Четыре owner drafts и #199 исправлены; foundation отделён от предложенного Memory API. | Независимо проверить source mapping, scoped методы и оставленные решения. Controller acceptance/runtime не подразумеваются. |
| D3. Упростить конструкцию и порядок реализации | `PARTIAL` | Physical backup и порядок реализации имеют одного owner; docs SQL retired. AUDIT сокращён до причин выбора, historical evidence и маршрутов, без второй runtime-инструкции. | Проверить оставшиеся механизмы на caller/owner/result/consumer и сохранение требований. |
| D4. Свести Store-контракт и assets | `PARTIAL` | R-183: в Implementation §4.7.1–3 выбраны time/reuse/support/influence/job codecs и единый history envelope. Далее #5326/#5327: DDL/DTO/query/bounds и caller/readback; отдельный code task, не prose PR. | Один source owner; каждый field/query/limit соединён с writer/reader. Source defects не закрыты правкой prose; compile, DDL execution и runtime разделены. |
| D5. Проверить требования и сценарии | `PARTIAL` | AUDIT-MAP: 63 якоря, 8 границ, T01–T37 и 7 маршрутов. AUDIT: дополнительно все 34 требования и A15-1–29 ведут к current owners; старые imperatives устранены. Далее retained-tree inbound pass и независимое чтение сценариев, включая выбранные R-183 codecs. | Сверка записанного корпуса не объявляется повторным чтением недоступных первоисточников или runtime proof. Все известные требования имеют route; реализация выбранных codecs и source defects остаются D4. |
| D6. Интеграция документации | `BLOCKED` | Независимое ревью, финальный diff, применимые doc/link checks и существующий merge gate. | Проверен именно финальный кандидат; нет фиктивных receipts, снятия protection или незаявленных CI-изменений. |

Read-only проверки можно разделять; общие файлы меняет один writer. REVIEW_PENDING
не означает независимую приёмку. OPEN-решение блокирует только затронутую capability,
не всю работу над Base. Не строить runtime через документационный PR.

## Snapshot and evidence limits

| Объект | Проверенный снимок | Граница |
|---|---|---|
| Memory integration base | `5aac094834fb5635921b550c821cb933a1196105` | Retained V2; PR #5325 не слит. |
| V3 parent этой правки | `2090eefc2da28e4f7e201592a4bbdb1c556d5626` | Проверены Store и cognitive contracts для R-183; выбранные codecs не являются реализованной схемой. |
| Store source | `c5154b0ea352980279cd0d46ca3353148d4c8027`, PR #5327 | Head PR перепроверен; occurrence/reuse/state DDL сопоставлен с контрактом. Исходники не менялись, compiler/runtime не запускались. |
| SurrealDB | `v3.3.4` / `1ac2b1dba7cd177621a4cf5d507caebeb2414395` | Наследованный D4 source finding; этот проход не перепроверял upstream и не запускал движок. |
| Controller | `5891cb706d1708bda28b2bd64be6d7996a6e2bdb` | Наследованный D2 snapshot; этот проход не заявляет новую проверку controller main. |

CHECKED — только названная source/text проверка. DECIDED — выбранный дизайн;
PARTIAL — неполное покрытие; BLOCKED — конкретная зависимость. NOT QUALIFIED никогда
не превращается в runtime PASS от проверки текста, SHA или upstream test.

## Controller dependency

[Inference §0](INFERENCE-CONTRACT.md#0-authority-and-prerequisites) содержит точные
ссылки на проверенные controller sources и таблицу «есть → требуется».

| ID | Текущее решение / разрыв | Следующее действие |
|---|---|---|
| R-123 | Исторический `613ea6b5` больше не задаёт controller архитектуру. | Перепроверять pinned source при изменении интеграции. |
| R-130 | L0/L1 присутствуют по roadmap/source; Memory inference отсутствует отдельно. | Не возвращать foundation в очередь Memory. |
| R-131 | Старый #200 касается Agent binding; one-shot не создаёт Agent/binding. | Не менять и не закрывать чужой lifecycle issue на основании этого вывода. |
| R-048 | Inference BLOCKED runtime: нет Memory principal/handlers. Contract 0.19 — предложение. | #199: согласовать scoped capability; Base не блокировать. |
| R-126 | Существующий SQLite writer и commands/writes namespace; call + binding — одна transaction. | Не вводить write_receipts/второй ledger или два независимых commits. |
| R-178 | Routing key и floor/skew API старого draft не подтверждены. | #199: выбрать issuance/recovery, DTO/limits/adapter до включения. |
| R-179 | Direct RPC ID literal; Memory сохраняет canonical uppercase ULID до send. | Retry сохраняет ID/spelling/payload, не заменяет unknown новым ID. |
| R-180 | Auxiliary restore/lost reply требует read-only lookup, а не existence probe через mutation. | Proposed inference.write.get поверх writes; проверить scope/retention в #199. |

Контракт не объявляет нерешённые issuance/recovery, DTO/limits и adapter готовыми.
Номер issue и prose revision не принимают решения за controller owner.

## Documentation and source findings

| ID | Наблюдение | Решение / остаток |
|---|---|---|
| R-172 | Entry pages смешивали прямое V3 чтение и обязательный V2 reader. | D1 ограничил V2-блоки donor edits; merge gate не отменён. |
| R-173 | Reading stack и копии механизмов раздували контекст. | Task→owner routes; audit по вопросу. D3 убрал повтор physical backup. |
| R-174 | Store source PR имеет imports/bounds/enforcement/catalog разрывы. | Точные действия ниже; source не исправлен документационной правкой. |
| R-175 | ACTIVE.toml всё ещё содержит старые V2 active programmes. | Не возобновлять их; перед машинной миграцией отдельно проверить consumers. |
| R-176 | Blanket «drafts synchronized» скрывал несовместимые prerequisites. | Owning sections исправлены; полная сверка требований остаётся D5. |
| R-177 | Slice 0 требовал полный maintenance/crash campaign до первого Base. | §11 задаёт connected increments; устаревшая инструкция Store README заменена ссылкой на §11. |
| R-181 | Последовательные backup pages не устанавливают coherent cut. | Implementation §8 удерживает mutation/replay quiesce; spool lock краткий. Runtime не проверен. |
| R-195 | Retained AUDIT продолжал предписывать SDK, Agent/Task inference, daemon-owned Store, branch-address и отдельный график с inference до maintenance. | Эти указания заменены ссылками на фактических owners; старые решения/source trace сохранены по pinned history. Аудит не пятый нормативный документ. Требуется независимое чтение, не runtime proof. |

## Scenario preservation

Исходные требования и ссылки находятся в [AUDIT-MAP](AUDIT-MAP.md), правила — у owners
ниже. Статус этих правок — design / review pending; runtime enforcement не заявлен.

| ID | Найденный разрыв | Исправление / следующий шаг |
|---|---|---|
| R-189 | SEC-01/MEM-01 требовали permitted capture, но не определяли exclusion перед spool/blob/IPC. | Implementation §7.1: admission до durable custody, policy revision/limitations, без unredacted shadow и переписывания same-ID replay. При реализации проверить relay/import/daemon и stricter-policy replay. |
| R-190 | Data/instruction boundary и исключение injected echo оставались в карте, а не в алгоритме. | Cognition §6.4–6.5/§9.2: attributed evidence, closed effects, exact source validation; packet lineage не independent support. Реальные host lineage/packet DTO ещё подключить. |
| R-191 | Restore сохранял deletion notices, но мог вернуть отозванный метод из старого active row. | Implementation §10/§8.2: typed suppression в существующем outside-root notice path; publish-before-ack, projection reconciliation, current-notice checks. Кодек/atomic file protocol ещё реализовать; не строить второй registry. |
| R-192 | Карта всё ещё предписывала legacy controller Operation; часть later capabilities была сведена к названиям без consumer/failure. | AUDIT-MAP §6 и AUDIT §9/§33/§38 направляют в current Inference owner; Operation — только historical trace, synchronized-draft claim удалён. Cognition §15 сохраняет later consumers; runtime остаётся отдельной работой. |
| R-193 | WDG-01/02/T14 не имели конкретного наблюдателя зависшего daemon. | Implementation §2.1: existing supervisor, finite health/recovery, separate alive/progress/outcome, no uncertain-effect retry. Реальные deadline/custody/status paths ещё реализовать. |
| R-194 | Пустой/частичный retrieval и budget metadata могли быть приняты за полноту/измерение. | Cognition §6.2/§8: examined scope/cut, unavailable/truncation отдельно; reserved/measured/unknown usage. Проверить итоговые DTO/consumers вместе с R-183. |
| R-196 | Дополнительные 34 требования и A15-1–29 оставались в AUDIT с собственными краткими предписаниями, без current owner routes. | Все номера/названия сохранены и адресованы; эти наборы не подменены 63 якорями Claude или семью объединёнными сценариями. A15-22 использует уже существующий §8.2 isolated owner recovery при missing notice continuity, без объявления неизвестной истории сохранённой. |

D5 не отменяет D4: выбранные в R-183 codecs ещё требуется реализовать вместе с
writers/readers. Notice/packet поля остаются у существующих владельцев, не нового
Store/service/proof framework. Сценарии допускают ограниченный source review без
заявления о полном архивном корпусе.

## Store reconciliation

Правила принадлежат [Implementation §4–7](IMPLEMENTATION.md#4-migration-0001-and-schema-authority).
Исполняемые assets принадлежат одному Store source owner в #5326/#5327. Две расходящиеся
SQL-копии из docs удалены; [Store navigation](store/README.md) сохраняет ссылки на точный
исторический pack. Это не принятие текущего source и не потеря его открытых дефектов.

| ID | Проверенный разрыв | Исправленная граница / следующий шаг |
|---|---|---|
| R-182 | Оба query набора используют FOR UPDATE с таблицей. Exact 3.3.4 cases явно отклоняют non-record targets. | §6: разрешить внутренний record ID в одной transaction, перепроверить identity/state/CAS; не обещать predicate lock. #5326 заменяет неверные statements и проверяет actual conflict behavior. |
| R-183 | Enum vocabulary и представления расходились. | `DECIDED / SOURCE_OPEN`: Implementation §4.7.1–3 задаёт один набор значений и переходов; source candidate ещё несовместим. Ни aliases, ни готовность runtime не заявлены. |
| R-184 | READONLY при create мешает coalescing/freeze-at-claim; claim query не фиксирует вход и точную authority. | §4.7.3: frozen tuple при первом claim; attempt — claim generation, не счётчик provider calls; stale settlement отвергается. Source DDL/claim/readback ещё исправить. |
| R-185 | Row limits/character asserts не гарантируют wire-byte bounds; допустимый объект может не помещаться в exact open/history/backup. | §4.5: field/object/request/row/page/response caps с JSON overhead; каждый admitted объект читается без truncation. #5326 назначает concrete caps и enforcement. |
| R-186 | History flattened в docs, snapshot_json в source; current open теряет часть qualification/method fields. | §4.7 выбирает `{format:1,memory:...}` с полным revision DTO, включая reuse membership. Decoder не достраивает из current; source format/DTO ещё реализовать. |
| R-187 | Lexical SQL фильтрует origin project, но не является полным public policy/qualification path; receipt-time cursor не change feed. | §5: scope до arm limits, exact-revision hydration, явные coverage/cut; selected reuse нельзя разрешать без membership. Реальный consumer ещё отсутствует. |
| R-188 | expected_catalog возвращает собственные DDL-строки; probe RETURN true не доказывает Store capability. | §4.1: expected canonical projection проверяется exact engine, а не текущей DB. §5: readiness через real capture/readback, без отдельной probe-ledger системы. |

### R-174: exact Store follow-up

Проверять на [source PR #5327](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5327),
не менять его runtime через PR #5325.

- [queries.rs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c5154b0ea352980279cd0d46ca3353148d4c8027/crates/storage/eliot-v3-store-schema/src/queries.rs)
  использует SMALL_READ/PAGE_READ/BACKUP_PAGE/SCHEMA_READ без parent-constant imports.
  Это source finding; компилятор здесь не запускался.
- ObservationInsert input cap 16 KiB меньше разрешённого inline body 65,536 символов
  плюс metadata. OpenMemoryCurrent/History result cap 64 KiB меньше разрешённых
  content/snapshot 262,144/393,216 символов. ClaimJob возвращает большой frozen input
  под тем же малым cap. Исправить query-specific byte budgets, не поднять все пределы.
- QuerySpec bounds — metadata. Bind/transport/decode, complete mutation transactions и
  actual consumer не подключены; hash и inspect не доказывают enforcement.
- [expected_catalog](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c5154b0ea352980279cd0d46ca3353148d4c8027/crates/storage/eliot-v3-store-schema/src/lib.rs#L416-L451)
  сопоставляет names с исходными DDL lines. Live server-canonical INFO projection ещё
  отсутствует. Cross-field ASSERT в source тоже не квалифицирован целиком.

<a id="r-183-representation-choices-still-open"></a>
### R-183: selected representations and source follow-up

**Дизайн выбран; исходники не исправлены.** Различия зафиксированы в
[retired design](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c2b7402c3fedc51ccb3fb881173e028ffcbdac44/docs/v3/store/0001-base.surql)
и [source candidate](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c5154b0ea352980279cd0d46ca3353148d4c8027/crates/storage/eliot-v3-store-schema/assets/migrations/0001_base.surql).
Значения и правила принадлежат Implementation, не этой таблице.

| Область | Единственный owner | Остаток для #5326/#5327 |
|---|---|---|
| Occurrence time | [§4.7.1](IMPLEMENTATION.md#471-occurrence-time) | Разделить resolution/certainty; сохранить source/offset и optional signed UTC projection в capture/open/backup. Не превращать date/unknown-zone в точный instant. |
| Reuse и состояния памяти | [§4.7.2](IMPLEMENTATION.md#472-reuse-and-guidance-states) | Ввести bounded reuse_projects, одинаковые enums в DDL/DTO/history; scope до LIMIT и current policy перед delivery. Не alias owner_projects/contested/advisory. |
| Job lifecycle | [§4.7.3](IMPLEMENTATION.md#473-job-state-and-claim-ownership) | Waiting/reconcile держит active slot; fenced reclaim/settle сохраняет call ID. Partial/failed/cleanup не маскируются под complete/no_change. |
| History | [§4.7](IMPLEMENTATION.md#47-tables-immutable-fields-and-assertions) | Один versioned envelope с полным semantic revision; запрет current-row reconstruction, согласованные byte caps. |

Следующий source-проход обновляет owning DDL, queries, DTO/validators, expected catalog и
digests совместно, затем запускает минимум fmt/Clippy. Реальный Store client должен
исполнять проверки; строки схемы не дают runtime PASS. Старый pack не импортировать,
второй codec/migration registry не создавать. Concrete byte caps, полные transactions,
packet/notice codecs и inference DTO/credential decisions этим решением не закрыты.

## Retained product decisions and gaps

R-идентификаторы сохранены. Подробная исходная формулировка доступна в Git, включая
[предшественник](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/abec550fb61d90db7bf0168a2191f9697a70a5c8/docs/v3/ANALYSIS-REGISTRY.md).
Это design backlog, не runtime PASS и не параллельный график разработки.

| ID | Сохранённая граница / незакрытый разрыв | Этап |
|---|---|---|
| R-001 | Host/controller исполняет внешнюю работу; Memory владеет памятью. | D3, D5 |
| R-002 | Supervisor/daemon/Store/candidate: custody/restart не квалифицированы. | D3, D5 |
| R-003 | Work address project/workspace + task или actor/session; не path/branch. | D5 |
| R-004 | Packet exact bytes/revisions/gaps; prepared/emitted/use различны. | D5 |
| R-005 | Correction сохраняет history и CAS current/result атомарно. | D4, D5 |
| R-006 | Шесть Base tables; candidates не доказывают connected Store. | D4 |
| R-007 | Исторический handle не падает вперёд на current revision. | D5 |
| R-008 | Complete conjunctive/alternative grounds; cycles не добавляют support. | D5 |
| R-009 | Independent retrieval arms, union, scope до limits. | D4, D5 |
| R-010 | Method revision потребляется поздним context/request. | D5 |
| R-011 | Origin/reuse/disclosure независимы. | D5 |
| R-012 | Host capture требует installed-contract qualification. | D5 |
| R-013 | Context действительно пересекает host boundary. | D5 |
| R-019 | Backup exact cut/fence/terminal/lease/rollback. Physical owner — Implementation §8. | D3, D5 |
| R-020 | Erasure всех controlled copies/roots/backups; provider отдельно. | D5 |
| R-021 | Improvement исправляет наблюдаемый failed edge, не intelligence score. | D5 |
| R-022 | Disagreement сохраняет alternatives/grounds и различающий observation. | D5 |
| R-023 | Public daemon control; supervisor privileged effects; status из readback. | D3, D5 |
| R-025 | Interpretation по committed input/correction/question, не по reads/cleanup. | D3, D5 |
| R-026 | Один active + coalesced successor; waiting не retry. | D4, D5 |
| R-028–R-045 | Recipe bootstrap, attribution, coverage, vectors, commitments, bounded reads, consolidation/split/forgetting, typed results. | D3, D5 |
| R-071–R-081 | V2 capture/spool/packet/broad-read defects — donor facts, не V3 support. | D5 |
| R-082 | Surreal Rust SDK baseline NOT SELECTED; пересмотр по конкретной потребности. | D3 |
| R-083 | SurrealDB 3.3.4 asset identity не равен Windows qualification. | D4, D5 |
| R-084–R-100 | Store transport/roles/schema/durability/DTOs: design, не runtime. | D3–D5 |
| R-101/R-107 | Brief spool cut + replay barrier; in-flight/crash не проверены. | D5 |
| R-102–R-106 | Process/listener/peer identity, mutual IPC, cancellation-safe socket. | D5 |
| R-108–R-116 | Privileged lifecycle, rollback, ACL, rotation, generation backpressure. | D3, D5 |
| R-150 | Wrapper/DDL/canonical catalog identity; complete migration не квалифицирована. | D4 |
| R-151 | Canonical string IDs + explicit optional presence/value DTOs; без generic codec. | D4 |
| R-152 | FTS analyzer/index/query source/design не равны live proof. | D4 |
| R-153 | Optional UNIQUE: canonical NONE; concurrency не проверена. | D4 |
| R-154 | Numbered FTS score; zero-score match не отбрасывать. | D4 |
| R-155 | Bounded lexical snapshot, не durable cross-call cursor. | D4, D5 |
| R-156 | Plain INFO owned maps; live canonical strings ещё проверить. | D4 |
| R-157 | Bounded streaming lease, не все part handles одновременно. | D5 |
| R-158 | OS-random Base IDs, canonical prefix/encoding; это не время. | D4 |
| R-159 | Derived keys: domain + length-prefixed components. | D4 |
| R-160 | Field guards не заменяют operation/digest/cross-row invariants. | D4 |
| R-161 | Индексы обслуживают named readers; проверить реальные планы. | D4 |
| R-162 | Work-address columns, не scan/parse binding_json. | D4 |
| R-163 | Exact DEFINE FIELD grammar; не угадывать syntax. | D4 |
| R-164 | READONLY first/same assignment; не владелец identity или claim transition. | D4 |
| R-165 | ASSERT: per-field и cross-field evidence разделены. | D4 |
| R-166 | PARAM/index-cancel tests не квалифицируют весь wrapper. | D4 |
| R-167 | Bound metadata через production client NOT QUALIFIED. | D4 |
| R-168 | EXPLAIN — version/dataset evidence, не истина. | D4 |
| R-169 | Docs migration RETIRED как второй asset owner; исходник сохранён по pinned history выше. | D4 |
| R-170 | Docs query corpus RETIRED; source owner не освобождён от исправления unsupported queries. | D4 |
| R-171 | Capture/revision/job transactions и cross-field enforcement ещё не замкнуты. | D4 |

## Retained inference and recovery design

Эти свойства принадлежат текущим owner drafts и требуют реализации/проверки.
Они не утверждают наличие соответствующих controller таблиц, credentials или методов.

| ID | Сохранённая граница / разрыв |
|---|---|
| R-047 | Memory semantic job и controller physical call — разные владельцы. |
| R-053 | Narrow caller; без owner/Agent/automation/plugin fallback. |
| R-117 | Stable caller переживает rotation/rollback. |
| R-125 | Pre-send canonical mutation ID, exact replay/conflict; текущий writer. |
| R-128/R-129 | Fixed post-cut inventory и явный history gap. |
| R-132 | Retention ограничена retained backups/dependencies. |
| R-133 | External-ID state нельзя откатить со Store. |
| R-134 | Auxiliary mutations требуют pre-send identity и read-only readback. |
| R-135 | Private credential publication; exact issuance/recovery ещё выбрать в #199. |
| R-136 | Cut disposition для каждого external mutation ID. |
| R-137 | Caller cleanup не заменяет owner break-glass. |
| R-138 | Membership tombstone не равен content retention/erasure. |
| R-139 | In-cut dependent copies защищены до снятия dependency. |
| R-141 | Plan digest не включает себя и поздние manifest/part digests. |
| R-144 | Terminal records переживают cleanup, но не доказывают erasure. |
| R-147 | Daemon mutation/backup owner; supervisor candidate/cutover; lock order. |
| R-148 | Final directory впервые виден с fence, не пустым reservation. |
| R-149 | All-part handle set SUPERSEDED решением R-157. |

## Development and synchronization

| ID | Состояние |
|---|---|
| R-058–R-067 | Connected behavior, один ledger, cheap preflight, без object family на noun. D3 проверяет оставшуюся конструкцию. |
| R-049 | Code first; minimum fmt/changed-package Clippy; broad qualification после assembled product. |
| R-059 | Исправлять owner text, не append-only errata. |
| R-024 | PARTIAL: recorded requirements, включая 34/A15-29, имеют current owner routes; AUDIT больше не задаёт конкурирующий механизм. R-183 выбран в design; source alignment, полные архивы, retained inbound graph и независимое review не закрыты. |
| R-076 | PARTIAL: Base/inference separation сохранена; реализация Store codecs и source completion остаются D4. |

## Source coverage

S-001–S-089 — наследованные evidence в AUDIT/AUDIT-MAP/Git, не повторный аудит и не
квалификация донора целиком. S-056/S-057/S-058/S-073 — исторический controller snapshot.
S-084–S-087 — exact-tag Surreal evidence; S-088/S-089 — design/assets, не полный wrapper.

| ID | Проверено | Граница |
|---|---|---|
| S-090 | Memory main/PR state, entry pages и registry до D1. | Навигация, не runtime audit. |
| S-091 | Controller roadmap/API/Router на 2bbde3a0. | Предыдущий source snapshot, не текущий moving main. |
| S-092 | Store schema/query source c5154b0 и PR metadata. | R-174; compile/DDL не запускались. |
| S-093 | D1 entry pages и retained V2 routing blocks. | Независимое D1/D6 review ещё требуется. |
| S-094 | Controller 5891cb70: roadmap/API/Router/auth/Store writes. | Source-only; Memory handlers отсутствуют в проверенном dispatch. |
| S-095 | Четыре owner drafts после D2/D3 правки. | Proposed boundary; independent review/D5 не заявлены. |
| S-096 | SurrealDB 1ac2b1db: for_update.surql и for_update_locked_read.surql, ссылки Implementation §6. | Exact-tag expected errors и record-ID target cases прочитаны, не исполнены здесь. |
| S-097 | Docs pack c2b7402 против source DDL/query/catalog c5154b0. | Найдены R-182–R-188; удаление дубля не квалифицирует source. |
| S-098 | Полный AUDIT-MAP на 03114308: 63 якоря, 8 границ, T01–T37, 47 донорских строк и поздний §6. | Сверка записанного корпуса с current owners; первичные недоступные архивы и доноры не перечитывались. |
| S-099 | Implementation/Cognition после scenario repair и требовательные normal/failure routes. | Design changes R-189–R-194; существующий ledger/исторический корпус сохранены, независимое review и runtime не заявлены. |
| S-100 | AUDIT на ec9a8e59 целиком: §1–14, retained §16–38, 34 требования и A15-1–29; current Implementation §8.2 и Cognition §15. | R-195/R-196: source/text reconciliation. Primary archives, historical donor code и runtime повторно не проверялись. |
| S-101 | R-183: current Implementation/Cognition на 2090eefc, PR #5327 head и DDL occurrence/reuse/state на c5154b0. | Design/source comparison, tuple/transition counterexamples; no compiler, live DB, independent review или новый controller audit. |

## Integration blockers

CI и independent review относятся к точному candidate head. Предыдущие диагностические
EMPTY_DOCUMENTATION_EVIDENCE / skipped MergeCompile / provisioner failure не являются
результатами нового head; актуальный результат берётся из PR/CI.

Required merge evidence не сфабрикован. V2 router, workflow/protection и runtime source
не меняются. Нет независимой агентной приёмки, полной проверки inbound links retained
tree, Rust/Windows/Surreal runtime qualification. Проверенный текст — не выполненный код.
