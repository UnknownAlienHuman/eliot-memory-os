# Eliot V3 — реестр анализа

**2026-11-04. Действующий план документации и открытых разрывов. Реализация не принята.**

Это единственный реестр V3. Правила — в [четырёх контрактах](../ARCHITECTURE_CONTRACT.md),
исходники/команды — в [DEVELOPMENT](DEVELOPMENT.md), требования — в [AUDIT-MAP](AUDIT-MAP.md).
История R/S-записей сохранена в [срезе до сокращения](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/6f71bd08a82bf46d16fa8eee582f913bfd768b13/docs/v3/ANALYSIS-REGISTRY.md).
Сокращение журнала не закрывает ни одного runtime-дефекта. Читать строку своей задачи,
а не все прошлые отчёты. CHECKED означает только названную проверку; DECIDED — выбранное
правило; SOURCE_OPEN — его реализация ещё не принята; MERGED — только факт слияния.

## Documentation stages

**Приоритет: законченный контракт → связанная реализация. Не очередная миграция V2 tools.**
Работать от текущего `main`. Закрытые слиянием документационные writer-ветки
не возобновлять; актуальный head проверять перед новой правкой. Открытое/закрытое состояние issue #5324 не является результатом приёмки.

| Этап | Состояние | Что продолжать / критерий завершения |
|---|---|---|
| D0. Версии и владельцы | `CHECKED` на снимках ниже | Проверять новую внешнюю версию только при изменении зависимого контракта. Не смешивать донор, дизайн и поддержку runtime. |
| D1. Вход и маршруты | `IMPLEMENTED / REVIEW_PENDING` | START → задача → owner → исходник/проверка. Независимая проверка всего instruction chain ещё открыта; новых индексов для неё не нужно. |
| D2. Controller | `DESIGN / EXTERNAL_OPEN` | Предложенный Memory API отделён от существующей foundation. Issuance/DTO/adapter решает controller owner перед inference, не перед Base. |
| D3. Простая реализация | `DECIDED / SOURCE_OPEN` для первого пути | [Implementation §11](IMPLEMENTATION.md#11-implementation-sequence): один рабочий путь, один runtime package при появлении caller, никаких пустых будущих слоёв. |
| D4. Store | `DESIGN_UPDATED / SOURCE_OPEN` | Реализовать выбранные capture/replay/open/revision и byte bounds в #5326/#5327. Проверки схемы не подменяют работающий клиент. |
| D5. Сценарии | `PARTIAL` | Адресный current-work путь выбран в [Cognition §2–6](COGNITION.md#2-current-work-reconstruction): task/session slots, отдельные commitments, exact-revision grounds и packet states. Нет расширения пустой задачи до сессии или подмены plan выполненным progress. Остальные сценарии и runtime открыты. |
| D6. Интеграция | `MERGED / CHECKS_OPEN` для предыдущих правок | Общий CI и независимая приёмка не становятся PASS от слияния. Проверять изменённый текст/ссылки и фактический результат CI без нового proof framework. |

### Implementation handoff

Первое поручение остаётся [#5326 / Store PR #5327](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5327):
исправить assets, выполнить минимальный fmt/Clippy, затем отдельным increment связать
[inline capture → commit/readback → exact open](IMPLEMENTATION.md#72-capture-command-commit-and-replay).
[§11.1](IMPLEMENTATION.md#111-source-placement-and-handoff) различает source candidate и
ещё не созданный runtime. Production ingress требует [durable-before-send](IMPLEMENTATION.md#75-durable-ingress-and-replay),
но первый disposable Store путь не ждёт inference, полного backup campaign или R-207.

Для Slice 2 уже выбраны [прямая revision](IMPLEMENTATION.md#741-command-body-and-revision-projection),
[адреса текущей работы](COGNITION.md#2-current-work-reconstruction) и
[packet/handoff](COGNITION.md#641-base-packet-encoding). Writer адреса, scoped lookup,
полная current projection и renderer должны использовать одни правила, не независимые
эвристики. Source map указывает сопутствующие запросы; это не расширяет первое поручение
до всего Slice 2. [Notices](IMPLEMENTATION.md#101-notice-command-and-durable-encoding) и
[Base backup](IMPLEMENTATION.md#83-base-format-and-complete-inventory) остаются последующим
Slice 3; их реализация, config allowlist и Windows durability открыты.

Следующая документационная сверка — конечные episode/coverage и attribution из
Cognition §4/12: фактический исход отдельно от повторного отчёта, предложенного метода
и приёмки внешней задачи. Проверять существующие требования AUDIT-MAP, без нового
реестра, evaluator DSL или V2 tooling programme. Общий проход не блокирует Store/capture.

## Snapshot and evidence limits

| Источник | Зафиксировано | Предел вывода |
|---|---|---|
| Memory main | `7feacb252cc1e5ea422e907a045da1c6fa9995ae`, перечитан 2026-11-04 | Документационная база и предыдущие слияния, не работоспособность V3. |
| Store PR #5327, чтение 2026-11-04 | Head `a040bd408be39afa9789561595d2cac8bef177b3`; дополнительно прочитаны memory/history DDL и `queries.rs` 210–315 | В перечне 31 queries нет полной create/revise transaction; старые поля, projections и временные ASSERT ещё согласовать. Это чтение source, не компиляция, execution или полный аудит PR. |
| SurrealDB | `v3.3.4` / `1ac2b1dba7cd177621a4cf5d507caebeb2414395` | Наследованные exact-tag findings; upstream и Windows/RocksDB здесь повторно не квалифицировались. |
| Controller | `5891cb706d1708bda28b2bd64be6d7996a6e2bdb`, наблюдение 2026-10-28 | Не текущий moving main. Его поддержку повторно проверяет владелец inference-задачи. |
| Claude hooks | [Официальный контракт](https://code.claude.com/docs/en/hooks#add-context-for-claude), прочитан 2026-11-04 | Документированные output fields и replay контекста; версия установленного хоста и фактическая доставка здесь не проверялись. |

## Controller dependency

Owner — [Inference §0](INFERENCE-CONTRACT.md#0-authority-and-prerequisites) и controller #199.
R-048/R-123/R-130/R-131: foundation и Memory inference различны; не создавать Agent/Goal/
Task binding для one-shot и не возвращать L0/L1 в очередь Memory. R-126: переиспользовать
существующий SQLite writer и commands/writes, не вторую mutation-ledger систему.
R-178/R-179/R-180: точные DTO/limits/credential issuance и recovery ещё требуют решения
controller owner; literal mutation ID сохраняется до send, unknown не заменяется новым ID,
restore использует read-only lookup, не mutation-probe. **Блокируется inference, не Base.**

## Documentation and source findings

| ID | Действующее решение / остаток |
|---|---|
| R-172/R-173/R-195/R-197/R-199 | Вход, вложенные инструкции, аудит и маршруты отделены от обязательств V2. Читать owner по задаче; независимое semantic review остаётся открытым. |
| R-175/R-176/R-204 | Старые active programmes и сохранённые отчёты не являются V3 roadmap. Blanket «всё согласовано» запрещён; исторические источники доступны в Git. |
| R-177/R-202 | Asset repair не равен всему Slice 0. Порядок и source handoff теперь конкретны; будущие capabilities не требуют предварительных каркасов. |
| R-198/R-200/R-201 | Предыдущие docs слиты, задача зарегистрирована, synthetic descriptor удалён только из active directory. Остались реальные integration checks, не повторная регистрация/создание реестра. |
| R-203 | Прежний main CI вернул UNKNOWN/OMITTED, Surreal provisioning также сообщал ошибку. Не считать успешный bootstrap компиляцией/Clippy продукта; конкретный блокирующий run разбирать отдельно. |
| R-205/R-206 | Pure V3 reading отвязан от ненужных V2 inputs; удалены 56 дублирующих индексов. Повторно эти патчи не применять. |
| R-207 | Дальнейшее обслуживание V2 tooling **отложено**. Исправлять только доказанную зависимость текущей V3 задачи; остаток ниже. |

## Legacy consumer migration

P1–P3 и per-target projections P4 уже слиты (#5332–#5335). Чтение, reference checks и
навигация V3 не требуют неиспользуемого V2 каталога; реальные mixed references проверяются.

| Остаток | Решение |
|---|---|
| P4: `Justfile`, `verify.ps1`, repository-policy, closure/capsule consumers | `DEFERRED`, не NEXT. Не модернизировать всю систему ради удаления документов. Конкретная ошибка, мешающая текущему increment, получает минимальное исправление существующего owner. |
| P5: 627 retained fragments и связанные материалы | `DEFERRED`. Не нужны для чтения/реализации V3; сохранены, пока есть реальные потребители. Удалять освобождённый набор с immutable donor link и проверкой ссылок, а не переписывать каждого потребителя. |

Required checks не отключать; skipped historical audit не выдавать за PASS. Пять прежних
ошибок V2 references в runtime_supervision.rs, skill_lifecycle.rs и eliot-ors/src/status.rs
остаются незакрытыми (точные diagnostics — в PR #5333), без новых исключений. Их полная проверка — не критерий содержательной готовности первого V3 пути.

## Scenario preservation

[AUDIT-MAP](AUDIT-MAP.md) сохраняет 63 исходных якоря, T01–T37 и маршруты;
[AUDIT](AUDIT.md) — дополнительные 34 требования и A15-1–29. Этот проход не заявляет
повторное чтение недоступных первоисточников или независимую приёмку всего корпуса.

| ID | Что должно остаться при реализации |
|---|---|
| R-189 | Exclusions до spool/blob/IPC; строгий current policy повторно проверяется перед replay. Failed custody не равна erasure; публикация spool не обходит закрытую admission boundary. |
| R-190 | `DECIDED / SOURCE_OPEN`: [Cognition §2/6](COGNITION.md#2-current-work-reconstruction) связывает current-work slots и commitment membership с packet. Plan имеет отдельную роль; commitment/method qualifiers не теряются. Перед выдачей проверяются current revision, work slot, роль и notices. Source writer/lookup/renderer и реальная выдача остаются открыты. |
| R-191 | `DECIDED / SOURCE_OPEN`: [§10.1–10.4](IMPLEMENTATION.md#101-notice-command-and-durable-encoding) задают NoticeV1, точный target/scope, отмену только названного отзыва, erasure replay keys и непрерывность через существующий installation checkpoint. Нет зеркальной Store-ревизии ради флага. Удаление current не переизбирает history и не обнуляет счётчик. Реализация, Windows durability и полная cleanup-инвентаризация открыты. |
| R-192/R-196 | Поздние capabilities и все требования сохраняют owner routes; старый Operation/SDK путь не возвращается через rationale. |
| R-193 | Supervisor различает alive/responsive/progress/outcome; конечный recovery budget, без retry неизвестного внешнего эффекта. |
| R-194 | Coverage packet различает complete/partial/unavailable/disabled/not_requested по arm; пустые units не скрывают сбой. 32 KiB считается после host wrapping/escaping; token budget требует настоящего counter. Usage unknown не равен нулю. |

## Store reconciliation

Owner — [Implementation §4–7](IMPLEMENTATION.md#4-migration-0001-and-schema-authority),
исходники — [Store map](store/README.md). SQL-дубликаты в docs не восстанавливать.

| ID | Выбрано / что требуется в исходниках |
|---|---|
| R-171 | `DECIDED / SOURCE_OPEN`: [§7.2–7.5](IMPLEMENTATION.md#72-capture-command-commit-and-replay) задают полный CaptureCommandV1, точную event projection и единый owner dispatch. Stream identity теперь включает workspace. Native redelivery возвращает сохранённую occurrence, не новый proposed ID; поздний forbidden/erased/damaged open не разрешает новую mutation. Source fields, complete transaction, decoder и custody/readback ещё реализовать. |
| R-174/R-182 | Исправить imports и table-target `FOR UPDATE`; native record-ID разрешать и перепроверять внутри одной transaction (§6). UNIQUE/CAS не обещают predicate lock. |
| R-183/R-186 | `DECIDED / SOURCE_OPEN`: [§7.4.1](IMPLEMENTATION.md#741-command-body-and-revision-projection) задаёт MemoryChangeV1 и полный MemoryRevisionV1 для current/history/hash/backup. Optional omission удаляет поле; grounds принадлежат новой exact revision, не наследуются молча. Текущие notice overlays вне immutable hash. Полная transaction, DTO/DDL/projections и consumer ещё реализовать. |
| R-184 | Pending coalesces; первый claim фиксирует tuple, последующие claims меняют generation, не исходный смысл или unknown call ID. Полная claim/settle реализация остаётся открытой. |
| R-185 | `DECIDED / SOURCE_OPEN`: [§4.5.1](IMPLEMENTATION.md#451-first-base-limits) задаёт ingress/revision limits; [§7.4.1](IMPLEMENTATION.md#741-command-body-and-revision-projection) — bounded change body и переход на существующий blob path выше inline cap; [§8.4](IMPLEMENTATION.md#84-bounds-outcomes-and-connected-check) — Base backup/restore. Узкая конфигурация не делает старые данные нечитаемыми; overflow не разрешает truncation/eviction. Job/inference aggregate limits ещё отдельная работа. |
| R-187 | `DECIDED / SOURCE_OPEN`: task/session addresses включают workspace; reuse не membership, пустой task lookup не расширяет scope. Grounds читаются для выбранной exact revision, failed/truncated не пустой набор. Receipt-time cursor не change feed. Lookup/projections/decoder и ограничения реального reader ещё реализовать. |
| R-188 | Expected catalog — canonical INFO clean exact-engine run, не копия DDL lines и не снимок проверяемой active DB. Probe true не заменяет capture/open. |

### R-174: exact Store follow-up

В существующем `crates/storage/eliot-v3-store-schema` сначала исправить imports и
fmt/Clippy; затем migration/wrapper, complete query, projection/decoder, bounds и digests
менять вместе. Исторические source caps были меньше разрешённых body/history/frozen
input; `QuerySpec` сам ничего не ограничивает. Live catalog, весь wrapper, ASSERT и
concurrency ещё не квалифицированы. `inspect` не запускает сетевой Store.

<a id="r-183-representation-choices-still-open"></a>
### R-183: selected representations and source follow-up

В [§4.7](IMPLEMENTATION.md#47-tables-immutable-fields-and-assertions) остаются точные
representations: исходное время отдельно от UTC projection; explicit reuse_projects;
независимые support/exposure/influence; claim generation и frozen tuple; versioned history.
Новые capture digests/operation result в §7 используют ту же observation, не новую таблицу.
Нет автоматических aliases или permissive fallback для старого source pack.

## Retained product decisions and gaps

Все исходные R-001–R-171 доступны в закреплённом срезе выше. Сводка **незакрытой** реализации:

| IDs / область | Owner и следующий содержательный результат |
|---|---|
| R-001–R-013, R-021–R-026, R-028–R-045 | Capture, work binding, correction, applicability/grounds, retrieval, packet и exact history: [Cognition](COGNITION.md). Base packing и packet/handoff описаны в §6; source writer/renderer/реальная выдача и проверки на установленном хосте остаются открыты. Не создавать копии контрактов в отдельном DTO-документе. |
| R-002/R-023/R-083–R-116 | [Implementation §1–3, §6–8](IMPLEMENTATION.md#1-runtime-and-installation): process/credential admission, IPC, source custody, replay/recovery, coherent cut и rotation. Дизайн не Windows runtime evidence. |
| R-019/R-020/R-101/R-107/R-141/R-144/R-147–R-149/R-157/R-181 | `DECIDED / SOURCE_OPEN` для [Base backup/restore](IMPLEMENTATION.md#8-backup-set-owner-and-lifecycle): один cut, шесть явных table counts, полная closure тел/spool/notices, manifest-last, terminal-before-delete и same-generation cutover readback. Неполный export не продолжается на новых данных. Source exporter/importer, config allowlist, реальный restart и Windows custody не приняты; inference-format остаётся отдельной capability. |
| R-071–R-081 | Донорские capture/spool/packet/broad-read дефекты не объявлены исправленными в V2 и не оправдывают перенос его runtime. |
| R-082/R-150–R-170 | [Store contract](IMPLEMENTATION.md#4-migration-0001-and-schema-authority): fixed bound queries, roles, IDs, absence, canonical schema, indexes и full decoder. SDK не выбран; source/parser findings не равны execution. |

## Retained inference and recovery design

R-047/R-053/R-117/R-125/R-128–R-139: stable scoped caller, pre-send identity, exact
unknown readback, fixed-window inventory, retention bound by backups, credential recovery,
private copy cleanup и external debt принадлежат [Inference contract](INFERENCE-CONTRACT.md).
Они требуют controller agreement и реализации; не строить в Base второй provider stack,
Agent lifecycle, mutation ledger или recovery service. R-149's unbounded handle set
заменён bounded streaming lease R-157, а не оставлен вторым вариантом.

## Development and synchronization

R-049/R-058–R-067: production code first, minimum changed-package fmt/Clippy после
связанного increment; широкие кампании после собранного продукта. R-059: править owner,
не append-only errata. R-024/R-076 остаются PARTIAL: сохранение требований и выбор codecs
не означают source completion, полные первичные архивы или независимую приёмку.

## Source coverage

S-001–S-107 и предыдущие check counts — исторические evidence в закреплённом срезе,
[AUDIT](AUDIT.md), [AUDIT-MAP](AUDIT-MAP.md) и PR, не повторно исполненные результаты.
Сопоставлены current-work/retrieval/packet и owning identity, revision, guidance-state,
exact-open правила. CORE-01/CTX-01/T25 остаются в прежних маршрутах AUDIT-MAP; новые
правила не заявляют повторного чтения всего первичного корпуса. Локальные копии трёх
изменяемых файлов сверены с Git blob SHA текущего main; это не полный checkout.
Точные проверки diff/anchors и независимое review относятся только к кандидату в PR.
Внешние API, весь Store PR, Rust/Clippy, Store/Windows runtime здесь не перепроверены.

## Integration blockers

Документация предыдущих increment находится в main. Нет основания снова держать всю
реализацию до завершения V2 tool migration. При этом прежние failures не исчезли:
R-200 final reading evidence/review и R-203 UNKNOWN completion остаются открытыми.
Новая правка проверяет собственный candidate; исторические receipts/PASS не подделывать.

### Integration tooling follow-up

Не изменять stable issue body ради очередного progress update и не создавать новый
catalogue/checker. При фактическом CI blocker прочитать failed step, исправить конкретного
owner в согласованном scope и проверить его результат. Нельзя менять protections или
пропускать чужую обязательную проверку под видом успеха. Слияние, ограниченная проверка
документов и готовность продукта — разные результаты.
