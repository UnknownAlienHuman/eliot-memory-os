# Eliot V3 — реестр анализа

**2026-11-06. Действующий план документации и открытых разрывов. Реализация не принята.**

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
| D1. Вход и маршруты | `SCOPED_CHECK / REVIEW_IN_PR` | Проверены START → task map → development и root → crates → storage. Маршруты разделены по операциям; локальная source-правка не требует всех §4–7. Определены конец навигации и выбор одной проверки. Итоговое независимое review — в PR; прочие source families и machine evidence не объявлены проверенными. |
| D2. Controller | `DESIGN / EXTERNAL_OPEN` | Предложенный Memory API отделён от существующей foundation. Issuance/DTO/adapter решает controller owner перед inference, не перед Base. |
| D3. Простая реализация | `DECIDED / SOURCE_OPEN` для первого пути | [Implementation §11](IMPLEMENTATION.md#11-implementation-sequence): один рабочий путь, один runtime package при появлении caller, никаких пустых будущих слоёв. |
| D4. Store | `DESIGN_UPDATED / SOURCE_OPEN` | Реализовать выбранные capture/replay/open/revision и byte bounds в #5326/#5327. Проверки схемы не подменяют работающий клиент. |
| D5. Сценарии | `DESIGN_UPDATED / SOURCE_OPEN` | [#5348 / PR #5349](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5349): старые требования/дефекты + V3 + KB → исправить owners → проверить связность/diff. Рабочая модель, Dreamer/research, injection и outcome learning; уточнены целостность выбранной цепи при packing и временные оси. [Источники §5.1–5.3](AUDIT-MAP.md#53-restore-useful-behavior-from-the-old-design); [Cognition](COGNITION.md), [Implementation §7/11](IMPLEMENTATION.md#7-core-operations-and-host). Runtime/измерения открыты. |
| D6. Интеграция | `MERGED / CHECKS_OPEN` для предыдущих правок | Общий CI и независимая приёмка не становятся PASS от слияния. Проверять изменённый текст/ссылки и фактический результат CI без нового proof framework. |

### Implementation handoff

Первым остаётся [#5326 / Store PR #5327](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5327):
assets + minimum fmt/Clippy, затем [inline capture → open](IMPLEMENTATION.md#72-capture-command-commit-and-replay).
Production ingress — [durable-before-send](IMPLEMENTATION.md#75-durable-ingress-and-replay);
disposable путь не ждёт inference/backup/R-207. Далее [§11](IMPLEMENTATION.md#11-implementation-sequence):
Slice 2 revision/work/context, Slice 3 notices/backup. Не расширять asset scope и не создавать
конкурирующего writer. R-185 codecs/limits нужны до своей capability. D1 routes — review-in-PR;
возвращаться к ним лишь при конкретном сбое.

## Snapshot and evidence limits

| Источник | Зафиксировано | Предел вывода |
|---|---|---|
| Memory main | `1c19f33dbd8ca5278cea283ccecfaa073b9f8ac9`, remote перечитан 2026-11-06 | База #5348; V3 owners и прямые consumers, не полный аудит V1/V2 или работающий runtime. |
| Knowledge base | `fe7c0c80e2536515ce234fc9d8f3adb4eb0ca689`, 2026-11-06 | Прочитаны synthesis, relevant records/extracts; выбранные primary sections, donor functions/licenses и hooks пересверены в [AUDIT-MAP §5.1–5.3](AUDIT-MAP.md#53-restore-useful-behavior-from-the-old-design); даты/недоступные первоисточники отмечены там. Результаты не воспроизводились. |
| Store PR #5327, чтение 2026-11-04 | Head `a040bd408be39afa9789561595d2cac8bef177b3`; дополнительно прочитаны memory/history DDL и `queries.rs` 210–315 | В перечне 31 queries нет полной create/revise transaction; старые поля, projections и временные ASSERT ещё согласовать. Это чтение source, не компиляция, execution или полный аудит PR. |
| SurrealDB | `v3.3.4` / `1ac2b1dba7cd177621a4cf5d507caebeb2414395` | Наследованные exact-tag findings; upstream и Windows/RocksDB здесь повторно не квалифицировались. |
| Controller | `5891cb706d1708bda28b2bd64be6d7996a6e2bdb`, наблюдение 2026-10-28 | Не текущий moving main. Его поддержку повторно проверяет владелец inference-задачи. |
| Host hooks | Claude: start/prompt/tool-result и PostToolBatch пересверены 2026-11-06; Codex: предыдущее чтение 2026-11-05 | [Точный mapping](COGNITION.md#651-first-claude-output-boundary). Документированный callback не означает поддержку установленного продукта; первым adapter остаётся Claude. |

## Controller dependency

[Inference §0](INFERENCE-CONTRACT.md#0-authority-and-prerequisites), controller #199:
R-048/R-123/R-130/R-131 отделяют существующую foundation от Memory inference;
R-126 переиспользует SQLite commands/writes. R-178/R-179/R-180 оставляют controller owner
точные DTO/limits, issuance и recovery. Их протоколы — в owner contract.
**Открыта inference-интеграция, Base от неё не зависит.**

## Documentation and source findings

| ID | Действующее решение / остаток |
|---|---|
| R-172/R-173/R-195/R-197/R-199 | D1 сократил маршруты storage/correction/retrieval/learning; конец навигации и scoped checks заданы. Review — в PR; generated V2 blocks/reader не менялись, весь корпус не принят. |
| R-175/R-176/R-204 | Исторические programmes/отчёты сохранены в Git; они не V3 roadmap и не основание считать всё согласованным. |
| R-177/R-202 | Asset repair — часть Slice 0. Connected порядок задан в §11; предварительные каркасы будущих capabilities не нужны. |
| R-198/R-200/R-201 | Предыдущие docs слиты; assignment зарегистрирован, synthetic descriptor удалён из active directory. Открыты integration checks, не повторная регистрация. |
| R-203 | PR #5349, `7df04bf`, [run 42195044680](https://github.com/UnknownAlienHuman/eliot-memory-os/actions/runs/42195044680): `Verify shared documentation evidence` → повторный `ROUTE_RECEIPT_MISMATCH`. Local candidate check проходил; причина не установлена. Integration owner сверяет реальные route inputs того же дерева; prose scope не меняет checker/CI. Local PASS не remote PASS. |
| R-205/R-206 | Убраны ненужные V2 reading inputs и 56 дублирующих индексов. Не повторять эти патчи. |
| R-207 | Обслуживание V2 tooling отложено; исправлять только доказанный blocker текущего V3 increment. |

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
| R-189 | [Capture policy](IMPLEMENTATION.md#71-capture-policy-before-durable-custody) действует до payload custody и при replay; staged/failed custody не обходит admission и не доказывает erasure. |
| R-190 | `DECIDED / SOURCE_OPEN`: [Cognition §2/8/12](COGNITION.md#22-prepare-knowledge-for-use) — рабочая модель, Dreamer/research, cue activation, исходные anchors при повторном сжатии и outcome repair. Source consumers открыты. |
| R-191 | `DECIDED / SOURCE_OPEN`: [NoticeV1 и erasure](IMPLEMENTATION.md#101-notice-command-and-durable-encoding) выбраны; source, Windows durability и полный cleanup inventory открыты. |
| R-192/R-196 | Поздние capabilities сохраняют owner routes; legacy Operation/SDK путь не возвращается. |
| R-193 | [Supervisor](IMPLEMENTATION.md#21-liveness-and-bounded-recovery): независимое наблюдение, конечный recovery budget, без retry неизвестного эффекта. |
| R-194 | [Cognition §6/8.2](COGNITION.md#6-retrieval-and-context): baseline/update, presentation dependencies после сокращения, time cues, qualified knowledge/dedup/optional telemetry. Source/host путь открыт; 2 KiB/latency — неизмеренные цели. |

## Store reconciliation

Owner — [Implementation §4–7](IMPLEMENTATION.md#4-migration-0001-and-schema-authority),
исходники — [Store map](store/README.md). SQL-дубликаты в docs не восстанавливать.

| ID | Выбрано / что требуется в исходниках |
|---|---|
| R-171 | `DECIDED / SOURCE_OPEN`: [§7.2–7.5](IMPLEMENTATION.md#72-capture-command-commit-and-replay). Реализовать complete transaction, source-field mapping, decoder и custody/readback. |
| R-174/R-182 | [§6](IMPLEMENTATION.md#6-transactions-and-durable-files): исправить imports/table-target FOR UPDATE; record-ID перепроверять внутри transaction. UNIQUE/CAS не predicate lock. |
| R-183/R-186 | `DECIDED / SOURCE_OPEN`: [§7.4.1](IMPLEMENTATION.md#741-command-body-and-revision-projection). Открыты atomic transaction, согласованные DTO/DDL/current/history/hash/backup и consumer. |
| R-184 | [Cognition §4/9.2](COGNITION.md#4-episode-membership-and-coverage) владеет coverage/no_change. Claim/settle и purpose codecs ещё реализовать; replay не новый опыт. |
| R-185 | `DECIDED / SOURCE_OPEN`: Base [bounds](IMPLEMENTATION.md#451-first-base-limits), [change body](IMPLEMENTATION.md#741-command-body-and-revision-projection), [backup](IMPLEMENTATION.md#84-bounds-outcomes-and-connected-check) выбраны. Job/inference aggregate limits открыты. |
| R-187 | `DECIDED / SOURCE_OPEN`: [work/grounds](COGNITION.md#2-current-work-reconstruction) и [queries](IMPLEMENTATION.md#5-fixed-query-corpus) выбраны; реальный lookup, projections/decoder и reader bounds открыты. |
| R-188 | [Expected catalog](IMPLEMENTATION.md#41-bundle-identity-and-catalog) строится из clean exact-engine INFO. Source/DDL и RETURN true не заменяют фактический capture/open. |

### R-174: exact Store follow-up

Менять assets в существующем `crates/storage/eliot-v3-store-schema`: imports/Clippy,
затем согласованно migration/wrapper/query/decoder/bounds/digests. Source caps были меньше
body/history/frozen input; QuerySpec сам их не ограничивает. Live catalog, wrapper, ASSERT
и concurrency не квалифицированы; `inspect` не запускает сетевой Store.

<a id="r-183-representation-choices-still-open"></a>
### R-183: selected representations and source follow-up

[§4.7](IMPLEMENTATION.md#47-tables-immutable-fields-and-assertions) и
[§7.4.1](IMPLEMENTATION.md#741-command-body-and-revision-projection) владеют representation/
history/hash. Source pack ещё согласовать; implicit aliases/fallback не разрешены.

## Retained product decisions and gaps

Все исходные R-001–R-171 доступны в закреплённом срезе выше. Сводка **незакрытой** реализации:

| IDs / область | Owner и следующий содержательный результат |
|---|---|
| R-001–R-013, R-021–R-026, R-028–R-045 | [Cognition](COGNITION.md): capture/work/revision/context/history определены; writer, renderer и установленный host ещё не приняты. |
| R-002/R-023/R-083–R-116 | [Implementation §1–3/6–8](IMPLEMENTATION.md#1-runtime-and-installation): runtime/admission, custody/replay, cutover/rotation открыты; Windows evidence нет. |
| R-019/R-020/R-101/R-107/R-141/R-144/R-147–R-149/R-157/R-181 | `DECIDED / SOURCE_OPEN`: [backup/restore](IMPLEMENTATION.md#8-backup-set-owner-and-lifecycle). Exporter/importer, config allowlist, restart и Windows custody открыты; inference format отдельно. |
| R-071–R-081 | Исторические V2 capture/spool/packet/broad-read дефекты не объявлены исправленными; перенос V2 runtime не выбран. |
| R-082/R-150–R-170 | [Store contract](IMPLEMENTATION.md#4-migration-0001-and-schema-authority) выбран; SDK не выбран, source/parser findings не execution. |

## Retained inference and recovery design

R-047/R-053/R-117/R-125/R-128–R-139 — [Inference contract](INFERENCE-CONTRACT.md):
controller agreement и реализация открыты; IDs, readback, retention/cleanup принадлежат
этому owner, не новой Base-подсистеме. R-149 заменён bounded streaming lease R-157.

## Development and synchronization

R-049/R-058–R-067: production code first, minimum changed-package fmt/Clippy после
связанного increment; широкие кампании после собранного продукта. R-059: править owner,
не append-only errata. R-024/R-076 остаются PARTIAL: сохранение требований и выбор codecs
не означают source completion, полные первичные архивы или независимую приёмку.

## Source coverage

S-001–S-107/counts — исторические. #5348: owners/consumers, A4/A6/A7/I7/I12,
InjectionPlanner, A-Mem/AgentRunbook и исследования контекста/времени.
[AUDIT-MAP §5.1–5.3](AUDIT-MAP.md#53-restore-useful-behavior-from-the-old-design)
различает primary/KB-only/недоступное. PR checks/review не квалифицируют весь архив,
Rust/Clippy или runtime.

## Integration blockers

Предыдущие docs в main; V2 migration не блокирует всю реализацию. R-200 final reading/
review и R-203 остаются открытыми. Проверять собственный candidate, не наследовать PASS.

### Integration tooling follow-up

[WORKFLOW](../../WORKFLOW.md) владеет интеграцией: не менять stable issue body/checker/
protections ради прохождения; конкретный failed step исправляет его owner в своём scope.
Слияние, doc checks и готовность продукта — разные результаты.
