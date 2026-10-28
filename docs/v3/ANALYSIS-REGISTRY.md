# Eliot V3 — реестр анализа

**Сверка: 2026-10-28. Рабочая документация PR #5325; не merged authority и не runtime gate.**

Единственный активный реестр V3: текущие решения, разрывы, границы проверки и следующий
шаг. Контракты принадлежат своим документам; [AUDIT](AUDIT.md) и
[AUDIT-MAP](AUDIT-MAP.md) хранят обоснования/источники. Хронология — в Git и issue/PR.
Для продолжения читайте этап и строки своей задачи, не весь каталог.

## Documentation stages

Работа продолжается в issue #5324 / PR #5325. Этап не требует отдельного issue, PR,
сервиса, проверяющего framework или второго реестра. Runtime — отдельная задача.

| Этап | Статус | Изменяемая область / следующий шаг | Критерий завершения |
|---|---|---|---|
| D0. Установить версии и владельцев | `CHECKED` source | Снимки ниже; обновить перед следующим изменением внешнего контракта. | V3 working branch, V2 donor, Store source и controller не смешаны. |
| D1. Исправить вход и маршруты чтения | `REVIEW_PENDING` | Сокращённые AGENTS/WORKFLOW/START и индексы; проверить task routes на финальном кандидате. | Независимый читатель находит owner section без обязательного стека книг и V2-инструкций для V3. |
| D2. Согласовать нормативные документы с controller | `REVIEW_PENDING` | Четыре owner drafts исправлены: foundation существует, inference отсутствует; текущий `commands`/`writes` и Owner/Agent отделены от предлагаемого Memory API. #199 должен ссылаться на этот контракт, не копировать старую foundation-модель. | Независимо проверить source mapping, новые scoped методы и явно оставленные решения. Нет заявленной совместимости с несуществующим handler; controller acceptance/runtime не подразумеваются. |
| D3. Упростить конструкцию и порядок реализации | `PARTIAL` | Физический backup/restore перенесён к одному владельцу Implementation §8; inference хранит только external cut/retention, Cognition — семантику. §11 отделяет минимальный Store/capture/open от maintenance и полной qualification. | Проверить оставшиеся механизмы на caller/owner/result/consumer и отсутствие потерянных требований; независимое ревью разделения ответственности ещё нужно. |
| D4. Свести Store-контракт и оба набора assets | `OPEN` — следующий | Implementation §4–6, `store/`, #5326 / PR #5327; начать с R-174. Не менять runtime через prose PR. | Однозначны field/query/limit writer и reader; design и production assets не смешаны; compile, DDL execution и live qualification разделены. |
| D5. Проверить требования и сценарии | `OPEN` | AUDIT-MAP: capture→restart→open/context, correction→history→consumer, learning→later use, unknown/privacy/erase, backup/restore. Дополнительно проверить inbound anchors после сокращения повторов. | Каждый исходный requirement прослежен к текущему owner; сценарий называет состояние, отказ и потребителя. Никаких выводов по числу документов. |
| D6. Интеграция документации | `BLOCKED` | Независимое ревью, финальный diff, применимые doc/link checks и существующий merge gate. | Проверен именно финальный кандидат; нет фиктивных receipts, снятия protection или незаявленных CI-изменений. |

Read-only проверки можно разделять; общие файлы меняет один writer. REVIEW_PENDING
означает выполненную правку, а не независимую приёмку. OPEN-решения внешнего интерфейса
блокируют его включение, не всю работу над Base.

## Snapshot and evidence limits

| Объект | Проверенный снимок | Граница |
|---|---|---|
| Memory integration base | `5aac094834fb5635921b550c821cb933a1196105` | Retained V2; PR #5325 не слит. |
| V3 parent этой правки | `eb0ac09105400b41f5ea208fdf57896758afa22a` | Рабочая ветка #5325 после D1; не runtime. |
| Store source | `c5154b0ea352980279cd0d46ca3353148d4c8027`, PR #5327 | Предыдущий source review R-174; код не перенесён в prose branch и здесь не компилировался. |
| Controller | `5891cb706d1708bda28b2bd64be6d7996a6e2bdb` | Прочитаны roadmap, API, Router principal/dispatch/auth, Store schema; runtime здесь не запускался. |

CHECKED — только названная source/text проверка. DECIDED — выбранный дизайн;
PARTIAL — неполное покрытие; BLOCKED — конкретная зависимость. NOT QUALIFIED никогда
не превращается в runtime PASS от проверки текста, SHA или upstream test.

## Controller dependency

[Inference §0](INFERENCE-CONTRACT.md#0-authority-and-prerequisites) содержит точные
ссылки на проверенные controller sources и единственную таблицу «есть → требуется».
Четыре owner drafts теперь направляют к этой границе вместо повторения внешнего roadmap.

| ID | Текущее решение / разрыв | Следующее действие |
|---|---|---|
| R-123 | Исторический `613ea6b5` больше не задаёт текущую controller архитектуру. Новый source snapshot указан выше, не плавающий pin. | Перепроверять источник при следующем изменении интеграции. |
| R-130 | L0/L1 присутствуют по roadmap/source; отсутствие Memory inference не равно отсутствию foundation. | Не возвращать foundation в очередь Memory. |
| R-131 | Старый #200 касается Agent binding; one-shot не создаёт Agent/binding. Его закрытие не является автоматическим условием Memory API. | Не менять и не закрывать чужой lifecycle issue на основании этого вывода. |
| R-048 | Inference `BLOCKED` runtime: нет Memory principal/handlers. Contract 0.19 — предложение расширения, не доступный API. | #199: согласовать и реализовать scoped capability; Base не блокировать. |
| R-126 | Использовать существующий SQLite writer, `commands`/`writes` namespace checks; call + mutation binding публикуются одной transaction. | Не вводить `write_receipts`/второй ledger и не разносить receipt/call по двум commits. |
| R-178 | Старый draft предполагал готовые routing key и mutation floor/skew API. В проверенных текущих интерфейсах это не установлено. | #199: выбрать secret issuance/recovery и конкретные DTO/limits/adapter. Пока выбор не сделан, inference не включать. |
| R-179 | Direct RPC ID — literal key; CLI использует uppercase ULID. Повторная нормализация может изменить identity. | Memory сохраняет одну canonical uppercase форму до отправки; retry не меняет её и не выдаёт новый ID для unknown. |
| R-180 | Для auxiliary lost-reply/restore не хватало read-only lookup: повтор mutation мог first-admit отсутствующий старый ID. | Предложен scoped `inference.write.get` поверх `writes`, без нового хранилища. Проверить DTO/retention и foreign-principal отказ при реализации #199. |

Оставшиеся решения — не скрытая готовность. Контракт явно требует выбора credential
issuance/recovery, closed DTO/byte bounds и одного реального profile/adapter до включения.
Ни номер issue, ни prose revision не принимают эти решения за controller owner.

## Documentation and source findings

| ID | Наблюдение | Решение / остаток |
|---|---|---|
| R-172 | Entry pages смешивали прямое чтение V3 и обязательный V2 reader. | D1 ограничил V2-блоки donor edits; required merge gate не отменён. |
| R-173 | Default reading stack и копии механизмов раздували контекст. | Task→owner routes; audit по вопросу. D3 убирает повтор физического backup из Architecture/Cognition/Inference. |
| R-174 | Store source PR имеет конкретные разрывы ниже. | D4 / #5326; source не исправлен этой документационной правкой. |
| R-175 | ACTIVE.toml всё ещё содержит старые V2 active programmes. | Не возобновлять их по этому признаку. Перед машинной миграцией проверить consumers отдельно. |
| R-176 | Blanket «drafts synchronized» скрывал несовместимые controller prerequisites. | Исправлены owning sections; полная синхронизация/requirement preservation остаётся D5, не заявлена. |
| R-177 | Slice 0 требовал полный maintenance/crash campaign до первого Base пути. | Implementation §11: минимальный Store → capture/restart → context → maintenance → inference. Безопасность текущего пути не откладывается; полная qualification не блокирует написание первого пути. |
| R-181 | Последовательные backup SELECT pages сами по себе не устанавливают coherent cut. | Implementation §8 явно удерживает canonical mutation/replay quiesce на экспорт; spool lock только на краткий cut, relay затем stage post-cut. Проверить этот путь при реализации maintenance. |

### R-174: exact Store follow-up

Проверять owning source PR #5327; не редактировать его код через PR #5325.

- [queries.rs](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c5154b0ea352980279cd0d46ca3353148d4c8027/crates/storage/eliot-v3-store-schema/src/queries.rs)
  использует SMALL_READ/PAGE_READ/BACKUP_PAGE/SCHEMA_READ без parent-constant imports.
  Это source finding; компилятор здесь не запускался.
- ObservationInsert имеет input cap 16 KiB при разрешённом inline body 65,536 символов
  плюс metadata. OpenMemoryCurrent/History имеют result cap 64 KiB при content/snapshot
  262,144/393,216 символов. Нужны query-specific byte bounds с UTF-8/JSON overhead,
  не слепое повышение всех limits и не тихое усечение exact open.
- QuerySpec bounds — metadata, не limiter. Проверить bind/transport/decode и реальный
  consumer; strings/assets без Store client не доказывают enforcement.
- Design pack оставляет cross-field assertions и live catalog непроверенными; source
  содержит ASSERT и выводит definitions из собственных DDL-строк. Это не серверное
  INFO readback. Выбрать одного asset owner, сверить полные transactions и evidence.

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
| R-026 | Один active + coalesced successor; waiting не retry. | D3, D5 |
| R-028–R-045 | Recipe bootstrap, attribution, coverage, vectors, commitments, bounded reads, consolidation/split/forgetting, typed results. | D3, D5 |
| R-071–R-081 | V2 capture/spool/packet/broad-read defects — donor facts, не V3 support. | D5 |
| R-082 | Surreal Rust SDK baseline NOT SELECTED; пересмотр по конкретной потребности. | D3 |
| R-083 | SurrealDB 3.3.4 asset identity не равен Windows qualification. | D4, D5 |
| R-084–R-100 | Store transport/roles/schema/durability/DTOs: design, не runtime. | D3–D5 |
| R-101/R-107 | Brief spool cut + replay barrier; in-flight/crash не проверены. | D5 |
| R-102–R-106 | Process/listener/peer identity, mutual IPC, cancellation-safe socket. | D5 |
| R-108–R-116 | Privileged lifecycle, rollback, ACL, rotation, generation backpressure. | D3, D5 |
| R-150 | Wrapper/DDL/catalog identity; complete migration не квалифицирована. | D4 |
| R-151 | Canonical string IDs + explicit projections/DTOs; без generic codec. | D4 |
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
| R-164 | READONLY first/same assignment; не владелец identity. | D4 |
| R-165 | ASSERT: per-field и cross-field evidence разделены. | D4 |
| R-166 | PARAM/index-cancel tests не квалифицируют весь wrapper. | D4 |
| R-167 | Bound metadata через production client NOT QUALIFIED. | D4 |
| R-168 | EXPLAIN — version/dataset evidence, не истина. | D4 |
| R-169 | store/0001-base.surql — design candidate. | D4 |
| R-170 | store/queries-base.surql — fixed read candidates. | D4 |
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
| R-024 | PARTIAL: controller mapping и physical-backup ownership исправлены; D5 полного requirement/scenario review не выполнен. |
| R-076 | PARTIAL: Base/inference separation исправлена; Store assets/source требуют D4. |

## Source coverage

S-001–S-089 — наследованные evidence в AUDIT/AUDIT-MAP/Git, не повторный аудит и не
квалификация донора целиком. S-056/S-057/S-058/S-073 — исторический controller snapshot.
S-084–S-087 — exact-tag Surreal evidence; S-088/S-089 — design/assets, не полный wrapper.

| ID | Проверено | Граница |
|---|---|---|
| S-090 | Memory main/PR state, entry pages и registry до D1. | Навигация, не runtime audit. |
| S-091 | Controller roadmap/API/Router на 2bbde3a0. | Предыдущий source snapshot, не текущий moving main. |
| S-092 | Store schema/query source c5154b0 и PR metadata. | Наследованный R-174; compile/DDL не запускались. |
| S-093 | D1 entry pages и retained V2 routing blocks. | Независимое D1/D6 review ещё требуется. |
| S-094 | Controller 5891cb70: roadmap L0/L1, API literal IDs/commands/writes, Router principal/dispatch/auth, Store writes DDL. | Source-only. Memory handlers отсутствуют в проверенном dispatch; no runtime execution. |
| S-095 | Четыре owner drafts после D2/D3 правки. | Удалены ложные prerequisites и дубли физических backup rules; интерфейс остаётся proposed, независимый review/D5 не заявлены. |

## Integration blockers

CI и independent review относятся к точному candidate head. Предыдущие диагностические
EMPTY_DOCUMENTATION_EVIDENCE / skipped MergeCompile / provisioner failure не являются
результатами нового head; актуальный результат берётся из PR/CI.

Required merge evidence не сфабрикован. V2 router, workflow/protection и runtime source
не меняются. Нет независимой агентной приёмки, полной проверки inbound links retained
tree, Rust/Windows/Surreal runtime qualification. Проверенный текст — не выполненный код.
