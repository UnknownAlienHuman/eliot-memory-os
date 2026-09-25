# ELIOT Memory OS: почему работа стоит и как её доделать

Системный аудит репозитория, Issue и реальной работы агентов, плюс рабочее руководство для агентов.

- Проверено на: `main@2eaa864cf6a2e2e94d2f4a066e8dcf8f3e0590a6` (2026-09-24 16:50 UTC).
- Норматив: пара `sha256:3ea4dc34…05ea` (Architecture `4.5-draft`, Implementation `0.29-draft`).
- Данные GitHub выгружены 2026-09-25 00:05 UTC: 900 Issue (480 открыто), 1598 PR, 3725 комментариев.
- Статус документа: аудит и рабочие правила. Нормативом он не является. Где он расходится с канонической парой, прав `docs/ARCHITECTURE_CONTRACT.md` и пара.

---

## 0. Коротко

1. **Продукт ни разу не запускался целиком.** Operational Spine Proof 1 (I17.6) не выполнялся ни разу. Живой установки на Windows тоже не было (#11: «never-run installation»). Для сравнения: 1098 влитых PR и 1,63 млн строк Rust.
2. **Агенты пишут код, но не могут закрыть Issue. Это следствие правил, а не лени моделей.** С 13 сентября действует порядок владельца «сначала весь код, тесты потом». Поэтому любой пункт приёмки, которому нужен хотя бы юнит-тест, уходит в `TEST-PHASE`. Тестовая фаза не наступает, и Issue закрыть нельзя. С 19 сентября влито 397 PR и закрыто 35 Issue; с 22 сентября — 122 PR и 4 Issue.
3. **Заявления «code-complete» почти всегда опровергаются.** Было 68 таких заявлений и 67 опровержений перекрёстной проверкой; опровергнуто 624 пункта чек-листов. Типичные причины: ссылка на неверную строку, «production caller» оказался тестом или заглушкой, валидатор проверяет не то. Цикл «влить → опровергнуть → переделать» повторяется неделями на одних и тех же Issue (#18, #19, #77, #204 и другие).
4. **Main красный, и этого никто не видит.** CI на PR не запускается с 30 августа. Факты на `2eaa864`:
   - `cargo check --workspace --all-targets` для Windows-таргета падает (E0382, поломка с 22.09). Исправлено в PR #2501.
   - На Linux не компилируются 40 из 187 крейтов — весь runtime.
   - В переносимых крейтах падают **58 тестов в 17 тест-таргетах**, в том числе `eliot-governor`, `eliot-kernel-core`, `eliot-store-api`, `eliot-store-memory`. PR #2503 исправляет 36 из них.
   - `just quick` красный как минимум в 6 шагах из 25:
     - 3 документационных гейта (исправлено в PR #2502);
     - `fmt-check`: 131 файл;
     - `check`;
     - **41 жёсткое нарушение архитектурных границ**, например `eliotd` напрямую зависит от 7 Dreamer-крейтов.
5. **Каждый четвёртый audit-Issue описывает код, которого на main уже нет.** 262 «I*-audit» Issue сгенерированы по инвентарю, без чтения кода. В 65 из 244 проверенных 70% утверждений «X отсутствует» (117 из 167) называют символы или крейты, которые на `main` есть.
6. **Работа идёт вширь, против канонического порядка.** Канон требует: сначала OSP1 и D0/D1, никакого массового роя пишущих агентов до OSP1 (I17.13), при росте активности без роста результата — сокращать объём (I17.1, I17.17). На деле 16 сентября открыто 262 «audit»-Issue сразу по всем главам. Параллельно делаются D3 (Dreamer, cognitive), D4 (backup/restore — 20+ Issue) и D5 (swarm, research).
7. **Новый стек отрезан от агентов.** Все четыре хоста (Claude Code, Claude Desktop, Codex, OpenCode) запускают **старый** `eliot-governor.exe mcp stdio` из `crates/eliot-app`. Новый `eliot-agent-bridge` → Kernel → `eliotd` не подключён ни к одному хосту. Весь объём новой работы не имеет потребителя.
8. **Обязательный протокол чтения доков съедает контекст и промахивается.** На любую правку выдаётся 85–150 КБ «обязательного» чтения (23–53 документа). Параметр `--topic` выборку не сужает. Нужный фрагмент в пакет при этом может не попасть: для #204 это I7.20, контракт ошибок для агентов. Сами Issue — ещё 4,7 МБ текста (тела и комментарии) с противоречащими друг другу статусами.

**Главная рекомендация.** Остановить ширину и пройти **одну вертикаль OSP1** через новый front door. Каждый PR должен идти с исполненным тестом-дискриминатором. Main держать зелёным. Разделить приёмку на «проверяется `cargo test`» (закрывает Issue) и «нужен живой Windows» (один чек-лист в #11). Подробности — в разделах 3–5.

---

## 1. Что именно проверено (воспроизводимо)

### 1.1 Сборка

| Проверка | Команда | Результат на `2eaa864` |
|---|---|---|
| Метаданные | `cargo metadata --locked --no-deps` | OK (1.97.1 ставится через `rust-toolchain.toml`) |
| Workspace, Windows-таргет (кросс-проверка с Linux) | `CARGO_FEATURE_PURE=1 cargo check --locked --workspace --all-targets --keep-going --target x86_64-pc-windows-msvc` | **1 ошибка**: `eliot-platform-windows/src/tests.rs:1602 E0382` (с `dc3696ea`, 22.09). Исправление — **PR #2501** |
| Workspace, Linux | `cargo check --locked --workspace --all-targets --keep-going` | **Не собираются** `eliot-platform-windows` (28 ошибок: ре-экспорт Windows-only элементов без `cfg`), `eliot-store` (безусловные вызовы `eliot_windows_ipc::credential_*`, `process_is_alive`), bin `eliot-process-guardian`. Из-за них на Linux не проверяются **40 крейтов**: весь runtime (`eliotd`, `eliot-kernel`, `eliot-host`, `eliot-store-surreal*`, `eliot-agent-bridge`, …). Так было всегда: 25.08 было 12 ошибок, 31.08 уже 27 |

`CARGO_FEATURE_PURE=1` нужен из-за `blake3`: его build-script под MSVC-таргетом ищет `cl.exe`. Переменная переключает его на переносимую Rust-реализацию. Это годится только для check, на релиз не влияет.

### 1.2 Тесты (переносимые крейты, Linux, 147 крейтов)

`cargo test --locked --workspace --exclude <40 Windows-only> --no-fail-fast`: **5035 passed, 58 failed** в 497 тест-бинарниках. Первый плохой коммит найден `git bisect run` (полная таблица — приложение Б).

| Крейт / таргет | Падает | Причина | Первый плохой коммит |
|---|---|---|---|
| `eliot-store-api` (4 таргета) | 9 | каталог операций вырос с 26 до 33, счётчик в тестах не обновили | `f904e633` (#325), далее #2392/#2398/#2407 |
| `eliot-store-memory` (`--lib`, `memory_store_clone`) | 17 | тестовые хелперы меняют план после `bind_issue18_digests`, отсюда `TransitionDigestMismatch` | `81782f52` (#2456). Заголовок «fix(gate): close root HOLD clippy findings», а внутри семантическое изменение `PreparedTransition` на +2211/−694 строк |
| `eliot-governor --lib` (`owner_closure_provider`) | 6 | `GrantGraph` не строится (`AuthorityError`) | `8114a99b` (#2100, «restore proof-phase test source») |
| `eliot-authority --test grant_closure_delegation` | 3 | `GrantNotNarrower("grant-leaf")`. Отложенный тест «восстановлен байт-в-байт» и ни разу не проходил | с появления (#2100) |
| `eliot-kernel-core --lib` | 1 | после рестарта не возвращается `RecoveryUnavailable` (grant activation) | `ca84b712` (#974 backup-link) |
| `eliot-protocol --test backup` | 3 | `duplicate field archive_id`, неверный выбор cutover | B-BACKUP (#954) |
| `eliot-dreamer-self-query` | 9 | фикстура с произвольным `pair_key`; контракт теперь его пересчитывает | `01b01b9c` (#223) |
| `eliot-cognitive-quality` | 2 | **продуктовый баг**: одинаковые `coverage_digest` двух проекций отвергаются как «duplicate digest» | #259 |
| `eliot-epistemic-context-provider` | 1 | в контракте появилось обязательное `owner`, негативный тест не доходит до своей проверки | #38 |
| `eliot-improvement --test learning_closure` | 1 | source-guard `async` срабатывает на слово «asynchronously» в doc-комментарии | `fb99c25c` (#1866) |
| `eliot-types --test cue_kind_legacy_boundary` | 2 | дрейф замороженных digest-манифестов чужих файлов | `7bdfe575` (#66) |
| `eliot-blob-api --test residency_contract` | 1 | в фикстуре скалярная эпоха `4`, контракт ждёт `{lineage_id, sequence}` (#64) | красный ≥ 18.09 |
| `eliot-wasm-runtime --test typed_runtime` | 1 | конкурентный `AdmissionBlockedDraining` | красный ≥ 18.09 (#760) |

**PR #2503** исправляет 36 падений из 58: всё это дрейф фикстур, продуктовое поведение не меняется. Оставшиеся 22 требуют решения владельца и отписаны в соответствующих Issue.

Вывод: тесты пишутся, но **не запускаются** («`cargo test` не запускался согласно owner order» — в сотнях отчётов). Поэтому main накапливает красные тесты даже в ядре: Governor, Kernel, Store. Типичная ситуация: семантическое изменение в #18 влито под заголовком «clippy fix» без единого прогона `cargo test -p eliot-store-memory`, а этот крейт собирается и тестируется на Linux за секунды.

### 1.3 Гейты `just quick` (Python-часть, на Linux)

| Гейт | На `2eaa864` | Действие |
|---|---|---|
| `docs_router.py check` | FAIL: `status.md` без маршрута (заметка агента из #2415) | PR #2502 |
| `verify-doc-code-conformance.py` | FAIL DCC-004: 2 скрипта без строки в `scripts/README.md` | PR #2502 |
| `code_navigation.py check` | FAIL: индекс пакетов устарел (184 → 187 крейтов) | PR #2502 |
| `docs_closure_audit.py` | PASS на полной истории, **FAIL (errors=3) на shallow-клоне** | облачным агентам сначала выполнить `git fetch --unshallow` |
| `verify-agent-route-bundles.py` | FAIL: нет `jsonschema` | `pip install --require-hashes -r scripts/requirements-verification.txt` |
| `audit-architecture-boundaries.py` | **FAIL: hard=41** (11 запрещённых прямых зависимостей runtime-корней, 30 неучтённых прямых запусков процессов) | владельцам: #18 (`eliotd` → 7 Dreamer-крейтов с #1540, 15.09), #22 (`eliot-native-worker` → claude/codex/opencode с #1457), #15/#19 (`eliot-kernel` → `eliot-store-surreal-adapter` с #2029) |
| `fmt-check` (`cargo fmt --all -- --check`) | **FAIL: 131 файл** не соответствует rustfmt закреплённого тулчейна 1.97.1 (edition 2024). Файлы форматируют вручную или без edition, а общий гейт не запускают | PR #2504 |
| `check` (`cargo check --workspace --all-targets`) | Windows-таргет: E0382 (PR #2501); Linux: 40 крейтов | см. 1.1 |
| `normative` | не запускался: нужен `pwsh` | — |
| остальные self-test/verify | PASS | — |

Итог: из 25 шагов `just quick` на main красные как минимум 6: `docs-router`, `doc-code-conformance`, `code-navigation`, `architecture-boundaries`, `fmt-check`, `check`. Все поломки появились за последние 10–14 дней и прошли в main, потому что гейт не запускается ни перед мерджем, ни в CI.

### 1.4 Поток работы в цифрах

| Метрика | Значение |
|---|---|
| Открытых Issue | 480. Из них 262 «I*-audit» открыты одним днём, 16.09 |
| PR влито / закрыто без мерджа | 1098 / 497 (31% работы выброшено) |
| С 19.09: влито PR / закрыто Issue | 397 / 35 |
| С 22.09: влито PR / закрыто Issue | 122 / 4 |
| Статусы открытых Issue по аудиту 23.09 | PARTIAL 265, NOT-STARTED 153, CODE-COMPLETE 60 |
| Заявлений «code-complete» / опровержений | 68 / 67 (624 опровергнутых пункта) |
| Пункты `TEST-PHASE` в последних отчётах | 354, из них ~299 без упоминания live/Windows/Pulse, то есть проверяемы обычным `cargo test` (эвристика) |
| Issue, где все TEST-PHASE-пункты — обычные тесты | 90 из 127 |
| Объём текста Issue | тела 2,9 МБ + комментарии 1,8 МБ по открытым Issue |
| Медиана / p90 тела Issue | 4,3 КБ / 10,7 КБ, максимум 30 КБ |
| Issue с ≥5 влитыми PR и всё ещё открытых | 50 (#18: 41 PR, #19: 32, #77: 23, #22: 26) |
| CI на PR | не запускается с 30.08, все workflow — `workflow_dispatch` |

---

## 2. Почему агенты не закрывают Issue: корневые причины

Причины связаны между собой. По отдельности каждая выглядит мелкой, вместе они дают бег на месте.

### R1. «Сначала весь код, тесты потом» + TEST-PHASE = закрыть нельзя by design

- Порядок владельца, как он записан в отчётах агентов: «User ordering remains all product code first, tests afterwards», «cargo test не запускался согласно owner order», «Tests are minimal by owner order». Такие отчёты идут массово с 13.09.
- Канон предписывает обратное:
  - I18.23: «Worker flow: **run discriminator**; change only declared module/support scope; **run module proof**».
  - I17.4: «bug repair starts with a discriminator that fails on the exact old path… merge requires live proof at the lowest real boundary able to discriminate».
  - I17.1: «discriminator before repair; real runtime proof before broad abstraction».
- Следствие. Пункт «A2 идентичность дайджестов на 4 слоях» (#18) — это обычная byte-equality фикстура. Он помечен TEST-PHASE наравне с живой установкой на Windows. В итоге TEST-PHASE объединяет две разные вещи: «нужен `cargo test`» и «нужен живой Windows».
- Вторичный эффект: 58 красных тестов на main. Тесты пишутся, их не запускают, они не проходят, и этого никто не видит.
- Третий эффект: реальные дефекты находят только чтением кода, и то постфактум. Пример на `main@2eaa864`: в `bins/eliotd/src/daemon_runtime.rs` `run_testd_owner_drain` держит `composition.lock()` через `await` Kernel-IO. Arm обработки активации в `run_loop` сам ждёт тот же lock внутри тела `select!` — единственного места, где опрашивается future TestD. Это deadlock ядра `eliotd`, найденный аудитом 24.09 в #839 и до сих пор не исправленный. Его ловит один `#[tokio::test]` с Kernel-заглушкой, которая «висит».

### R2. Критерии приёмки завязаны на живой Windows, недоступный агентам

- 137 Issue упоминают live-доказательство, 66 — Windows, 25 — Product Pulse. #11 (живая установка и D0/D1 Pulse) — хаб: на него прямо ссылаются 14 открытых Issue, косвенно — большинство.
- Облачные агенты (Codex/Jules/Claude на Linux) не могут ни установить сервис, ни даже собрать 40 runtime-крейтов. Поэтому любой Issue с «Product Pulse through #11» у них вечно открыт.
- Живые прогоны делает только владелец на своей машине. Последний прогон установки был около 14.09 (rc11, #1352/#1375). После этого — только код.

### R3. Два продукта: хосты работают со старым, вся работа идёт в новый

- `integrations/claude/eliot/.mcp.json`, `plugin/eliot-governor/.mcp.json` (Codex), `integrations/claude/claude-desktop/mcpb/manifest.json`, `integrations/opencode/opencode.json` запускают `eliot-governor … mcp stdio`, то есть legacy-фасад `crates/eliot-app`.
- Новый путь `eliot-agent-bridge` → Kernel → `eliotd` → store не подключён ни к одному хосту. Даже в репозитории нет ни одного теста, который поднимает Kernel, `eliotd` и store вместе. У legacy такой тест есть: `crates/eliot-app/tests/first_working_loop.rs::first_working_loop_end_to_end`, `#[ignore]`, требует развёрнутый runtime.
- #1189 («retire eliot-app… as one closure») закрыт 16.09 как completed, хотя legacy остаётся единственным живым MCP-сервером.
- Канон (I17.8) описывает два трека, которые сходятся на D1: value/recovery и runtime-extraction. Value-трек фактически брошен, а extraction не доведён до потребителя.

### R4. Нарушен канонический порядок поставки (D0 → D1 → OSP1 → D2…D5)

- I17.13: «No large autonomous **mutating** swarm is admitted before Operational Spine Proof 1 and the memory rehabilitation gate».
- I17.17 перечисляет запреты: механизм, который «delays the recovery gate or Operational Spine Proof 1», или который «increases forms/tests/reports without product delta».
- I17.1: «If activity grows while verified product/recovery deltas do not, the default response is scope reduction, reuse, simplification or mechanism review — not stricter ceremony or a larger speculative backlog».
- Факт: волны W1–W4 и MGR-A/B параллельно ведут backup/restore (D4, #949–#975), Dreamer (D3, #702 закрыт, `eliotd` зависит от Dreamer-крейтов), learning overlays (D3, #1862–#1869), swarm (D5), research (D5), WinUI (D2). Сам spine (OSP1) не запускался.
- Прямая архитектурная цена: `eliotd::daemon_runtime::run` вызывает `attach_dreamer_intake(...)?`, `attach_dreamer_model(...)?` и `attach_agent_fabric(...)?` **до** `report_ready`. Ошибка экспериментального D3/D5-компонента не даст ядру Governor стать ready. Это противоречит A2.3 (optional Modules не блокируют готовность) и исключению Dreamer из workstream core-daemons.

### R5. Нет обратной связи: CI выключен, гейты не запускаются, main краснеет

- Все workflow — `workflow_dispatch`. Последний PR-прогон был 30.08, последний ручной — 17.09.
- Гейты `just quick` требуют `pwsh` и `just`, у облачных агентов на Linux их нет. Локально на Windows гейт перед мерджем тоже не запускают: за 10 дней появилось 6 поломок гейтов.
- «Pre-existing failure» стало нормой: E0382 из #1352 держался три дня, его упомянули как «предсуществующий» как минимум 6 раз разные агенты, и никто не исправил.

### R6. Протокол чтения документации дорогой и неточный

- `docs_read.py read --path X` на типовые пути выдаёт 23–53 обязательных документа объёмом 84–150 КБ (≈25–40 тыс. токенов). Цифры для однострочной правки теста и для `docs/PROJECT_MAP.md` — в приложении Г.
- `--topic` не сужает выборку, он может только добавить маршруты по ключевым словам (`docs_router_core.matched_routes`).
- Фрагменты, на которые ссылается конкретный Issue, в пакет не попадают. Пример: для `bins/eliot-agent-bridge/src/kernel_activation_client.rs` (#204) в пакете нет `I07-20-agent-facing-error-contract.md`, хотя именно его нарушение нашла перекрёстная проверка.
- Канон сам требует это измерять: I0.7 `ContractSurfaceProfile` — «Growth of this surface without Product or Recovery delta triggers simplification… not another documentation campaign».

### R7. Issue превратились во вторую спецификацию

- 4,7 МБ текста по открытым Issue — больше, чем Implementation (1 МБ) и Architecture (150 КБ) вместе.
- В одном Issue по 3–5 «текущих» статусов: аудит v1, аудит v2 от 23.09, прогресс W1/W2, «Код завершён», «Перекрёстная проверка… опровергнуты». Агент не знает, какой из них верный.
- Чек-листы с доказательствами вида `file.rs:1234` устаревают после следующего мерджа. Отсюда треть опровержений («cited line is a blank line / an error-message literal / unrelated test»).
- **262 «I*-audit» Issue (16.09) сгенерированы по автоматическому «inventory», без чтения кода.** В разделах «Code today» 167 утверждений вида «не найден `X`» с конкретным идентификатором; **117 из них (70%) называют символы или крейты, которые на `main` есть**. Это 65 Issue: например `InstrumentRunner` и `eliot-testd` в #1813, `RecoveryPayloadEnvelope` в #1925, `KernelExecutionManifest` в #1884, `RouteFingerprint` в #1901 (приложение Д). Агент, который верит такому тексту, строит второй владелец того, что уже есть.
- Устаревшие утверждения в телах Issue. Примеры:
  - #1716: «ECXF без зависимых» — неверно после #2472.
  - PROJECT_MAP: Dreamer-Issue #461/#1098/#1100 «open» — на деле закрыты или являются PR.
  - #1189 закрыт, legacy жив.
  - Родитель F-DENY #710 закрыт, а 12 дочерних #930–#941 в NOT-STARTED.
- Дубли и пересечения, по которым пишут разные агенты: #64 ≈ #1795; #1713 ≈ #1925; #325 ≈ #1741 ≈ #1915 ≈ #370; #1812 ≈ #1851; #1219 ≈ #1687 ≈ #1966; #1141 ≈ #1716 ≈ #1871; #1746 ≈ #1807 ≈ #8; #1719 ≈ #1227 ≈ #1858; #1968 ≈ #1890 ≈ #1876; #1967 ≈ #1892.

### R8. Операционный шум: контрольные артефакты, квитанции, дублирующие мерджи

- В main попадали `PUSHED`, `CHECKLIST*.json`, `REPORT*.md`, `VERIFY.md`, `PLAN-1942.md` (убраны в #2499). `status.md` остаётся до PR #2502.
- Коммиты-квитанции: «record push receipt», «record pushed head for W1 attempt 2». Squash-заголовок берётся из последнего коммита, поэтому PR с кодом #204 называется «chore(204): record push receipt».
- #2497 — пустой повторный мердж той же ветки, что и #2496.
- Параллельные писатели в одном файле: `bins/eliot-agent-bridge/src/main.rs` в #1942 и #204 в один час. «root `REPORT.md` belongs to #66» — контрольные файлы разных задач конфликтуют в одном дереве.
- Имена веток `issue/204-W1-2` не соответствуют `branch_policy` (`<kind>/<issue>-<slug>`).

### R9. «Проводка ради чек-листа» вместо поведения

- Критерий «есть production caller» провоцирует такие вызовы: адаптер создаётся в composition root и тут же выбрасывается (`let _context = adapter.dreamer_route_context()?; Ok(())`). В коде это сопровождается комментариями «No thread, no transport, no `start()` contour or run-loop change», «A fresh startup catalogue is empty, so this marks nothing today».
- Такая «проводка» не доказывает поведения, но добавляет точки отказа в readiness (см. R4).
- Правильная замена — тест через публичный вход, который наблюдает эффект (см. раздел 4).

### R10. Инфраструктурные ловушки для облачных агентов

- 40 крейтов не компилируются на Linux (см. 1.1). Решение для check: кросс-проверка `--target x86_64-pc-windows-msvc`. Тесты этих крейтов можно только скомпилировать, запустить нельзя.
- `Justfile` задаёт `set shell := ["pwsh", …]`, а `scripts/verify.sh` делегирует в `pwsh`. На Linux без PowerShell 7 ни `just quick`, ни `verify` не работают.
- Shallow clone (depth 50) ломает `docs_closure_audit.py`.
- `CARGO_INCREMENTAL` по умолчанию плюс debug-info: полный тестовый прогон занимает больше 30 ГБ `target/`. Облачная квота кончается («No space left on device»). Используйте `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`.

---

## 3. План: как доделать быстро

### 3.0 Решения владельца (без них агенты будут бегать по кругу)

1. **Отменить «тесты потом».** Заменить на правило I18.23: каждый PR содержит один исполненный тест-дискриминатор (падал до, проходит после) и `cargo test -p <каждый затронутый крейт>`. Матрицы и кампании по-прежнему не нужны: START.md прав про церемонии, но тест — не церемония.
2. **Заморозить ширину.** Все Issue классов D2–D5 (P3–P6: ≈384 шт., см. приложение А) пометить `parked:after-osp1` и не выдавать агентам. Исключение — если Issue чинит красный тест или гейт на main.
3. **Выбрать front door для OSP1.** Рекомендую перевести один хост (Claude Code) с `eliot-governor mcp stdio` на новый стек (`eliot-agent-bridge` → Kernel → `eliotd`) за флагом. Альтернатива — осознанно вести OSP1 через legacy (value-трек I17.8) и мигрировать позже. Решение должно быть явным: сейчас его нет.
4. **Минимальный автоматический CI на PR.** Это расходится с текущим AGENTS.md («Change workflows only when requested»), поэтому решает владелец. Минимальный набор:
   - Linux: Python-гейты, `cargo check --target x86_64-pc-windows-msvc --workspace --all-targets`, `cargo test` переносимых крейтов.
   - Windows-runner: `cargo test -p` затронутых runtime-крейтов.

   Без CI main будет краснеть при любой дисциплине.
5. **Живая сессия по расписанию.** Раз в N дней владелец на своей Windows-машине прогоняет живой чек-лист #11. Агенты готовят к ней скрипты и списки. Это единственный путь закрывать live-пункты.

### 3.1 Этапы

| Этап | Цель | Выход (проверяемо) |
|---|---|---|
| **P0 — зелёный main** | Windows all-targets check, 58 тестов, гейты `just quick`, 41 hard-нарушение | `cargo check` (оба таргета) + `cargo test` переносимых крейтов + `just quick` без FAIL |
| **P1 — OSP1** | одна вертикаль: host → front door → Kernel → `eliotd` → store → verifier → finish → restart → recall | один воспроизводимый прогон по I17.6 с артефактами в #11 |
| **P2 — D0/D1 hardening** | корректность спайна: epoch lineage, ORS envelopes, unknown-commit, supervision | тесты уровня T1–T3 на каждом ребре |
| **P3** | D2 (модули, генерации, WASM, UI, второй агентский маршрут), legacy-retire после cutover, сквозные (логирование, serde-deny, unsafe) | по одному, только после P1 |
| **P4 / P5 / P6** | D3 smart / D4 meta, backup / D5 swarm, research | после OSP1 и memory-rehabilitation gate |

### 3.2 Критический путь OSP1 (I17.6) и владельцы

| Шаг I17.6 | Что нужно | Issue (владелец) | Состояние (по коду и отчётам) |
|---|---|---|---|
| 0. Повторяемый стенд | поднять Host/Kernel/store/Surreal/`eliotd` на одной машине без ручной магии | #907, #909, #911, #915; #1375 (reset, есть) | ядро harness частично есть; провизионеры не готовы |
| 0'. Идентичность прогона | `eliot system snapshot` связывает source/build/runtime/store | #1850 | частично (`eliot-bootstrap`) |
| 1. attach/resume Session | активация: bridge → Kernel ticket → `eliotd` → typed result | #66, #203, #204, #839, #1115, #8, #1746 | код в main; исполненных тестов нет; перекрёстные проверки находили потери данных (исправлялось в #2495) |
| 1'. хост → новый front door | MCP-конфиг хоста на `eliot-agent-bridge`; legacy — редирект или отказ | #342, #77, #1858, #1719 | **не начато** на уровне конфигов хостов |
| 2–3. цель, TaskContract, WorkScope | task binding и WorkScope | #1787/#1788/#1789 (частично влиты), #1746 | код есть, тестов нет |
| 4. компактный Active View | `eliot.packet` → минимальная сборка (D3a exact-record) | #1940, #1947; T11-композиция в #18 | recall-диспозиции влиты (#2479) |
| 5. обратимая Material-правка под authority | canonical write → receipt | #1874, #1927, #63, #19, #10 | 7 named mutations; digest-совпадение между слоями не доказано, а store-memory сейчас красный по digest |
| 6. verifier на точном артефакте | dev-fast профиль через InstrumentRunner/testd | #1802, #1813, #1814, (#456) | TestD-путь есть (#325), dev-fast профиля нет |
| 7. strict finish | acceptance из TaskContract, а не из списка тестов | #325, #1915 | P1-находка 24.09: acceptance берётся из `verifier_plan.required_test_ids` |
| 8. записать урок | observation capture → canonical record | #1929, #1940 | частично |
| 9–10. restart и resume без потерь | supervision lease, demand start, unknown-commit recovery | #88, #1751, #1690 | не доказано |
| 11. recall урока в следующем шаге | recall disposition → Active View | #1940, #1947 | частично |
| Живой прогон | всё выше на одной установке | **#11** | ни разу |

**Порядок исполнения.** Шаги 0 и 0' идут параллельно с P0. Затем 1' + 1 (вход) → 5 (запись) → 6–7 (проверка и финиш) → 9–10 (рестарт) → 4, 8, 11 (память). Каждый шаг закрывается интеграционным тестом на Windows по образцу `first_working_loop_end_to_end` (`#[ignore]`, запуск через harness). Только потом — живой прогон #11.

---

## 4. Как работать агенту (правила)

### 4.1 Перед началом

1. `git status --short --branch`; `git rev-parse HEAD`. База — текущий `main`. Облачный агент: `git fetch --unshallow`.
2. Взять **один** Issue из P0/P1 (приложение А). Issue из P3–P6 не брать, если только он не чинит красный тест или гейт.
3. Прочитать тело Issue. Из комментариев — **последний** статус и последнюю перекрёстную проверку или аудит; более ранние статусы — история. При противоречии прав код на `main`.
4. Документация:
   - выполнить `python scripts/docs_read.py read --path … --topic …` (протокол обязателен, receipt в PR);
   - **сначала** прочитать фрагменты, на которые ссылается Issue (I-разделы в его теле), затем — пункты пакета, относящиеся к изменяемому контракту;
   - в PR честно перечислить, что прочитано. Не писать «прочитано всё», если это не так.

### 4.2 Доказательства (заменяют line-anchor чек-листы)

- **Каждый пункт приёмки = имя теста + команда + строка результата.** Пример: `A3 → crates/governor/eliot-canonical/tests/finish_gate.rs::stale_verifier_is_rejected`, `cargo test -p eliot-canonical --test finish_gate` → `test result: ok. 8 passed`.
- **Дискриминатор:** покажите, что тест падает на старом коде. Сделать это можно через `git stash`, или приложив вывод до изменения.
- **«Production caller»** доказывается тестом через публичный вход (CLI, IPC-фрейм или функцию composition root), где наблюдается эффект. Одного факта, что вызов существует, недостаточно. Не добавляйте «attach»-вызовы, которые создают адаптер и выбрасывают его.
- Ссылки на код — `путь::функция` (опционально `@sha`). Номера строк в чек-листах не использовать.
- **Live-пункты** (SCM, установка, Product Pulse, живой хост) не блокируют Issue: перенести их одной строкой в живой чек-лист #11 со ссылкой. Закрыть Issue, когда все пункты, проверяемые `cargo test`, зелёные.

### 4.3 Проверки (по месту изменения)

Linux (облако):

```bash
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
# переносимые крейты (147 из 187): полноценно
cargo test --locked -p <crate>
# Windows-only runtime-крейты (40): только компиляция, включая тесты
CARGO_FEATURE_PURE=1 cargo check --locked -p <crate> --all-targets --target x86_64-pc-windows-msvc
# гейты (без pwsh)
python scripts/docs_router.py check --root .
python scripts/verify-doc-code-conformance.py --root .
python scripts/code_navigation.py check --root .
python scripts/docs_shards.py verify --root .
python scripts/audit-architecture-boundaries.py      # hard=0 для ваших пакетов
```

Windows (машина владельца или runner): `just quick`, затем `cargo test --locked -p <crate>` для каждого затронутого крейта.

Правило **«не хуже main»** недостаточно. Если ваш крейт красный на main, его починка входит в вашу задачу или получает отдельный P0-Issue. «Pre-existing» можно написать один раз со ссылкой на Issue-владельца.

### 4.4 PR

- Один Issue — одна ветка `<kind>/<issue>-<slug>` — один PR. Заголовок PR — осмысленный: squash берёт его в main.
- В дереве только файлы задачи. `REPORT*.md`, `CHECKLIST*.json`, `PUSHED`, `VERIFY.md`, `PLAN*.md`, `status.md` — вне репозитория, в каталоге контроллера.
- Нет коммитов-квитанций. Нет повторного мерджа той же ветки.
- Шаблон `.github/pull_request_template.md` заполнять фактами. Раздел Proof — со строками `test result`.

### 4.5 Запреты (частые причины опровержений)

- Не выводить acceptance-множество из того, что проверяет verifier (#325).
- Не выбрасывать детали отказа между слоями, то есть не превращать `Unknown` в `Mismatch` или в строку (#204, #1352).
- Не объявлять `PreservedIntact` по отсутствию сигнатуры повреждения (#10).
- Не добавлять зависимости runtime-корней (`bins/*`) на D3–D5-крейты: `audit-architecture-boundaries.py` должен оставаться hard=0.
- Не менять оракул или тест, чтобы он принял новый вывод без отдельного ревью (I18.23).

---

## 5. Какой информации не хватает в Issue: шаблон v2

Главное: **текущее состояние живёт в теле Issue** (редактируется), а комментарии — история. Предлагаемая структура (≤ 8 КБ):

```markdown
## Current state (main@<sha>, <date>)          ← единственный актуальный статус
Priority: P0|P1|P2|P3–P6 · Class: SPINE|LIVE|ENABLER|D2|D3|D4|D5|LEGACY|CROSS
Exists on main: <путь::функция> …  (без номеров строк)
Missing: <1–5 пунктов>
Next step: <одна конкретная правка>
Verify: `cargo test -p <crate> --test <file>` (сейчас: FAIL/PASS/absent)

## Causal property / owner / scope               ← как сейчас, коротко
## Acceptance
### A-code (закрывают Issue; каждый пункт = тест)
- [ ] A1 … → test `<crate>/tests/<file>.rs::<name>` (to write | exists)
### A-live (не блокируют; перенесены в #11 checklist)
- A-L1 … → #11 item N
## Dependencies (только открытые, с причиной)
## Canonical fragments (2–5 точных ссылок I-/A-разделов)
```

Добавить в каждый Issue:

1. **Команда проверки и её текущий результат.** Сейчас их нет почти ни в одном Issue.
2. **Имена тестов для каждого пункта приёмки** (существующих или тех, что надо написать).
3. **Разделение A-code / A-live.**
4. **Приоритет и класс поставки** со ссылкой на I17.
5. **Список пересекающихся Issue и кто владеет общим файлом**, чтобы не было двух писателей.
6. **Точные фрагменты норматива** (2–5), а не полный роутинг.

---

## 6. Что сделано в рамках этого аудита

| PR | Суть | Проверка |
|---|---|---|
| #2501 | `eliot-platform-windows/src/tests.rs`: `descriptor_digest.clone()`. Кросс-проверка workspace all-targets под Windows-таргетом снова без ошибок | `cargo check --target x86_64-pc-windows-msvc -p eliot-platform-windows --all-targets` |
| #2502 | удалён `status.md`, 2 строки в `scripts/README.md`, пересобраны индексы пакетов: `docs_router`, DCC, `code_navigation` снова PASS | Python-гейты |
| #2503 | 36 из 58 падающих тестов переносимых крейтов: дрейф фикстур, продукт не меняется | `cargo test -p …` по 10 таргетам |
| #2504 | `cargo fmt --all` (131 файл), гейт `fmt-check` снова зелёный | `cargo fmt --all -- --check` |
| этот PR | этот отчёт и руководство (`docs/operations/AGENT_DELIVERY_GUIDE.md`) | `docs_router`, DCC |

После мерджа #2501–#2504 на main остаются красными:
- 22 теста из приложения Б (нужны решения владельцев, отписаны в Issue);
- 41 hard-нарушение архитектурных границ (приложение В);
- 40 крейтов, не собирающихся на Linux (#1893);
- `normative` (нужен `pwsh`).

Комментарии «Системный разбор 2026-09-25» оставлены во всех открытых Issue. В каждом: приоритет по этому плану, проверенные факты (тесты, гейты, сборка, устаревшие утверждения, пересечения) и следующий шаг.

---

## Приложения

- **А.** Классификация открытых Issue по этапам (P1…P6).
- **Б.** Падающие тесты и первый плохой коммит.
- **В.** Жёсткие нарушения архитектурных границ.
- **Г.** Размер обязательного чтения по путям.
- **Д.** «Code today» в audit-Issue устарел или неверен.
- **Е.** Пересечения и дубли.

### А. Классификация открытых Issue

Легенда: **P1** — критический путь OSP1; **P1-LIVE** — живые проверки на Windows-машине владельца; **P1-ENABLER** — стенд и инструменты, без которых P1 не проверить; **P2** — D0/D1 hardening; **P3** — D2, legacy-retire и сквозные задачи; **P4** — D3 (smart, cognitive, Dreamer); **P5** — D4 (backup/restore, revocation, meta); **P6** — D5 (swarm, research, remote). CC — было заявление code-complete; RF — была перекрёстная проверка с опровержением; TP — пункты TEST-PHASE (cargo-testable / live, эвристика).


#### P1 (34)

| Issue | Класс | Заголовок | влитых PR | флаги |
|---|---|---|---|---|
| #7 | SPINE | [integration/claude] Reconcile MCP response, bridge completion, and UI terminal state | 4 |  |
| #8 | SPINE | [agent-context] Make attach/discovery task-bound, freshness-aware, and output-bounded | 4 | CC RF TP 9/0 |
| #10 | SPINE | [storage/regression] Preserve record-like strings in arbitrary JSON payloads | 8 | CC RF |
| #11 | LIVE | [runtime/live] Establish the current Windows SystemService installation and D0/D1 Produc | 51 | TP 0/1 |
| #18 | SPINE | [core/governor] Close eliotd ownership and retire legacy eliot-app semantics | 41 | CC RF TP 6/6 |
| #19 | SPINE | [storage/daemon] Close the store-bridge, BlobStore-owner, and Surreal process-generation | 32 | CC RF TP 4/2 |
| #63 | SPINE | [governor/store] Recompute the canonical request hash across eliotd → Kernel → store | 7 |  |
| #66 | SPINE | [daemon/activation] Return typed semantic-resolution failure instead of silently re-clai | 12 | CC RF TP 1/2 |
| #77 | SPINE | [agent-bridge/protocol] Integrate real Kernel host-request binding and correlated execut | 23 | CC RF TP 0/2 |
| #88 | SPINE | [daemon/supervision] Renew the eliotd SupervisionLease from observed progress, not Store | 3 |  |
| #203 | SPINE | [kernel/activation] Consume one terminal semantic result without timeout collapse | 3 | TP 1/0 |
| #204 | SPINE | [agent-bridge/activation] Map typed negatives and prove the real activation edge | 8 | CC RF TP 11/4 |
| #325 | SPINE | [governor/finish] Published finish contract carries caller-supplied evidence that I7.9 f | 3 | CC RF TP 7/0 |
| #342 | SPINE | [work-unit/agent-bridge] Freeze real Kernel host-request port cutover | 5 |  |
| #839 | SPINE | [B-ACTIVATION-PROJECTION] Wire the typed Governor activation projection into the eliotd  | 15 | CC RF |
| #907 | ENABLER | [D-INT-CORE] Build the bounded integration harness state machine | 4 |  |
| #909 | ENABLER | [D-INT-STORE] Add the authenticated isolated SurrealDB 3.1.4 provisioner | 2 |  |
| #911 | ENABLER | [D-INT-RUNTIME] Add the isolated Windows runtime topology provisioner | 2 |  |
| #1115 | SPINE | [kernel/activation] Accept, persist and replay typed semantic-resolution results | 3 | CC RF TP 2/0 |
| #1690 | SPINE | [I14-audit] Add durable unknown-commit recovery to canonical writes | 2 | TP 0/0 |
| #1719 | LIVE | [release] The Windows bundle still builds eliot-governor from the legacy eliot-app crate | 0 |  |
| #1746 | SPINE | [I7-audit] Implement authenticated session, scope, and task-contract admission | 0 |  |
| #1751 | SPINE | [I1-audit] Implement the demand-start activation and lease-driven idle-drain lifecycle | 0 |  |
| #1802 | SPINE | [I18-audit] Implement the canonical dev-fast profile and evidence receipt path | 0 |  |
| #1813 | SPINE | [I10-audit] Add governed Instrument Plane ownership instead of ad hoc verification route | 0 |  |
| #1814 | SPINE | [I10-audit] Enforce typed InstrumentSpec admission before any tool launch | 0 |  |
| #1850 | SPINE | [I17-audit] Establish a current evidence snapshot before any recovery claim | 0 |  |
| #1858 | LEGACY | [I19-audit] Reject the old entrypoint or redirect it through the canonical route | 0 |  |
| #1874 | SPINE | [I5-audit] Add the required active operational-spine mutation and receipt surface | 0 |  |
| #1901 | SPINE | [I18-audit] Add host-route acceptance proof for the working end-to-end path | 0 |  |
| #1915 | SPINE | [I18-audit] Make incomplete verification outcomes non-promotable through FinishService | 0 |  |
| #1927 | SPINE | [I5-audit] Introduce deterministic PreparedTransition admission before store execution | 1 | TP 0/0 |
| #1940 | SPINE | [I7-audit] Return server-derived memory dispositions and bound recall receipts | 2 | CC RF TP 0/1 |
| #1947 | SPINE | [I12-audit] Implement canonical RetrievalPlan and RecallDisposition outputs | 2 | CC RF TP 0/1 |

#### P1-LIVE (13)

| Issue | Класс | Заголовок | влитых PR | флаги |
|---|---|---|---|---|
| #1135 | LIVE | [user-broker/runtime] Prove Kernel registration, session-bound launch, and credential re | 1 | TP 0/1 |
| #1227 | LIVE | [release/windows] Bind the signed bundle to current runtime generations and remove legac | 1 |  |
| #1301 | LIVE | [platform-windows/installation] rc4 install fails: runtime registry file created without | 1 | TP 1/0 |
| #1306 | LIVE | [installation] rollback of service registration: after deleting EliotWatchdog, recover f | 1 |  |
| #1325 | LIVE | [installation] first install with signed activation intent cannot roll back after servic | 0 | TP 0/1 |
| #1339 | LIVE | [installation/watchdog] rc9 registry redb lock: second apply query-reconcile vs watchdog | 2 | TP 1/0 |
| #1352 | LIVE | [host/platform-windows] rc11 (with #1347): EliotHost DACL now correct but Host self-insp | 3 | CC RF TP 0/0 |
| #1375 | LIVE | [installation/dev] One-command developer reset so a fresh install always works (owner de | 2 |  |
| #1388 | LIVE | [watchdog/installation] Watchdog registry/approval fixtures emit Null Host service_contr | 2 |  |
| #1537 | LIVE | T2-S08W: Reconcile and complete the existing Watchdog recovery/containment demonstration | 1 |  |
| #1771 | LIVE | [I3-audit] Make installation profile selection govern paths and supervision | 0 |  |
| #1847 | LIVE | [I16-audit] Add structured crash and recovery evidence for the unproven Windows runtime | 0 |  |
| #1900 | LIVE | [I18-audit] Implement Windows installer, update, and uninstall release proof | 0 |  |

#### P1-ENABLER (6)

| Issue | Класс | Заголовок | влитых PR | флаги |
|---|---|---|---|---|
| #250 | ENABLER | [integrations] Add one manual verification entrypoint for all agent host surfaces | 1 |  |
| #905 | ENABLER | [D-INT-INV] Derive the exact ignored-test denominator and environment requirements | 5 |  |
| #915 | ENABLER | [D-INT-WORKFLOW] Add the manual isolated integration workflow | 3 |  |
| #1231 | ENABLER | [docs/onboarding] Align START.md with current authority, documentation routing, and proo | 5 |  |
| #1893 | ENABLER | [I1-audit] Preserve the Linux portability boundary in platform interfaces | 0 |  |
| #1914 | ENABLER | [I18-audit] Add versioned local/CI verification profiles with shared evidence receipts | 0 |  |

#### P2 (43)

| Issue | Класс | Заголовок | влитых PR | флаги |
|---|---|---|---|---|
| #64 | SPINE | [kernel/authority] Unify scalar AuthorityEpoch with lineage-aware epoch identity | 9 |  |
| #216 | SPINE | [bootstrap/evidence] Replace the flat snapshot with five-domain support and invalidation | 3 |  |
| #267 | SPINE | [process-evidence/sink] Stream policy-bound process output into immutable evidence objec | 1 |  |
| #269 | SPINE | [process-evidence/ors] Retain only immutable stream locator and coverage recovery state | 1 |  |
| #271 | SPINE | [process-evidence/consumers] Migrate runtime and Instrument consumers to typed stream ev | 0 |  |
| #297 | SPINE | [process-evidence/blob-adapter] Adapt the process-stream sink port to the single-owner B | 1 |  |
| #370 | SPINE | [agent/contracts] Make worker results candidate-only and reserve task completion for Gov | 8 | CC RF TP 1/0 |
| #448 | SPINE | [core/host] Make all Host recovery journals power-loss durable on Windows | 3 |  |
| #456 | SPINE | [testd/evidence] Consume typed process streams through immutable source readback | 0 |  |
| #458 | SPINE | [watchdog/reconciliation] Export protected spool through the Governor canonical path | 5 |  |
| #1128 | SPINE | [instrument/providers] Compose the typed Instrument adapter registry behind eliot-testd | 1 |  |
| #1713 | SPINE | [I5-audit] Implement ORS recovery envelopes and acceptance-pending durability | 0 |  |
| #1739 | SPINE | [I7-audit] Implement all eight canonical MCP operations through the bridge | 0 |  |
| #1741 | SPINE | [I7-audit] Implement strict candidate-only finish and Kernel-derived completion proof | 0 |  |
| #1743 | SPINE | [I7-audit] Produce canonical agent-facing error envelopes on every failure path | 0 |  |
| #1744 | SPINE | [I7-audit] Generate MCP schemas from shared canonical contract types | 0 |  |
| #1750 | SPINE | [I1-audit] Restore independent Watchdog service installation and SCM supervision | 1 | TP 0/1 |
| #1754 | SPINE | [I8-audit] Add the watchdog-owned physically separate `watchdog.redb` intent spool | 1 |  |
| #1787 | SPINE | [I4-audit] Implement WorkScope identity resolution and guarded revalidation | 1 | CC RF |
| #1788 | SPINE | [I4-audit] Build deterministic privacy-bounded bootstrap discovery | 1 |  |
| #1789 | SPINE | [I4-audit] Enforce material-readiness gates using typed onboarding state | 1 | CC RF |
| #1790 | SPINE | [I4-audit] Implement canonical cold-start readiness compilation and single-flight leases | 0 |  |
| #1795 | SPINE | [I6-audit] Replace bare authority counters with typed epoch lineage identities | 0 |  |
| #1805 | SPINE | [I18-audit] Bind instrument results to exact executable identities | 1 |  |
| #1812 | SPINE | [I10-audit] Implement the admitted Windows ProcessExecutor path before product launch | 0 |  |
| #1851 | SPINE | [I17-audit] Make the Windows guardian the sole ProcessExecutor reference path | 0 |  |
| #1852 | SPINE | [I17-audit] Replace synthetic verification and private command maps with dev-fast | 0 |  |
| #1853 | SPINE | [I17-audit] Bind Kernel result delivery to durable unknown-outcome recovery | 0 |  |
| #1876 | SPINE | [I7-audit] Bind module handshake claims to catalog, generation, and capability evidence | 0 |  |
| #1877 | SPINE | [I7-audit] Implement application-owned session lifecycle independent of transport reconn | 0 |  |
| #1885 | SPINE | [I1-audit] Gate effect-capable restart on exact unexpired operation leases | 0 |  |
| #1886 | SPINE | [I1-audit] Add HostStateJournal as the exclusive Host process-lineage store | 0 |  |
| #1887 | SPINE | [I1-audit] Separate Host-managed dependency liveness from store semantic readiness | 0 |  |
| #1888 | SPINE | [I1-audit] Enforce Windows Job Object and identity isolation at process launch | 0 |  |
| #1890 | SPINE | [I1-audit] Implement compatibility handshakes and rollback fencing | 0 |  |
| #1892 | SPINE | [I1-audit] Enforce startup ordering and authority caps before front-door readiness | 0 | TP 0/0 |
| #1925 | SPINE | [I5-audit] Implement complete opaque ORS staging and recovery envelopes | 1 | TP 0/0 |
| #1929 | SPINE | [I5-audit] Implement task-binding admission and safe unbound observation capture | 2 | TP 0/0 |
| #1933 | SPINE | [I5-audit] Add bounded store-client generations and unknown-write receipt recovery | 2 |  |
| #1967 | SPINE | [I1-audit] Implement the canonical startup sequence and readiness gates | 2 |  |
| #1968 | SPINE | [I1-audit] Gate every process handshake on the full compatibility envelope | 3 |  |
| #1972 | SPINE | [I1-audit] Enforce Kernel-unavailable admission and recovery-view behavior | 2 | TP 0/0 |
| #2380 | SPINE | [I4.7] Complete receipt-bound WorkScope transitions and visible partial recovery | 1 |  |

#### P3 — после OSP1 (257)

- **CROSS** (45): #708, #726, #740, #742, #744, #789, #791, #885, #889, #891, #893, #895, #897, #899, #901, #929, #930, #931, #932, #933, #934, #936, #937, #938, #941, #976, #977, #978, #980, #981, #982, #984, #985, #1133, #1229, #1810, #1836, #1837, #1838, #1840, #1842, #1843, #1844, #1845, #1846
- **D2** (143): #21, #22, #332, #738, #756, #758, #760, #764, #870, #903, #939, #979, #1108, #1112, #1137, #1187, #1191, #1213, #1221, #1678, #1679, #1680, #1681, #1682, #1684, #1685, #1686, #1688, #1689, #1691, #1692, #1693, #1694, #1695, #1700, #1701, #1703, #1720, #1721, #1740, #1745, #1747, #1753, #1755, #1756, #1757, #1758, #1759, #1760, #1761, #1772, #1773, #1774, #1775, #1776, #1777, #1779, #1780, #1781, #1782, #1783, #1784, #1785, #1791, #1792, #1793, #1796, #1798, #1806, #1807, #1809, #1811, #1815, #1816, #1817, #1818, #1819, #1823, #1824, #1830, #1831, #1832, #1833, #1834, #1839, #1841, #1854, #1872, #1875, #1878, #1879, #1880, #1881, #1882, #1883, #1884, #1891, #1896, #1897, #1898, #1899, #1913, #1917, #1918, #1919, #1920, #1922, #1923, #1926, #1930, #1931, #1932, #1934, #1935, #1936, #1937, #1939, #1941, #1942, #1943, #1944, #1945, #1946, #1950, #1951, #1952, #1953, #1954, #1956, #1957, #1958, #1959, #1961, #1962, #1964, #1965, #1969, #1970, #1971, #2383, #2384, #2385, #2386
- **ENABLER** (19): #327, #520, #690, #748, #837, #838, #844, #846, #852, #1225, #1233, #1267, #1696, #1803, #1804, #1855, #1902, #1903, #1921
- **LEGACY** (50): #39, #40, #67, #74, #78, #228, #251, #369, #371, #706, #783, #787, #835, #860, #862, #864, #866, #868, #876, #878, #880, #946, #989, #990, #1025, #1027, #1067, #1140, #1141, #1142, #1143, #1144, #1145, #1146, #1147, #1148, #1193, #1219, #1261, #1270, #1687, #1709, #1716, #1856, #1857, #1859, #1860, #1861, #1871, #1966

#### P4 — D3 (62)

- **D3** (62): #38, #41, #43, #45, #196, #217, #223, #233, #238, #246, #259, #261, #262, #638, #673, #762, #829, #830, #935, #940, #965, #969, #970, #973, #1722, #1724, #1725, #1726, #1727, #1728, #1729, #1730, #1731, #1733, #1734, #1735, #1742, #1778, #1797, #1801, #1862, #1863, #1864, #1865, #1866, #1867, #1868, #1869, #1894, #1905, #1906, #1907, #1908, #1909, #1911, #1912, #1924, #1938, #1948, #1949, #2381, #2382

#### P5 — D4 (34)

- **D4** (34): #686, #688, #942, #943, #944, #949, #950, #951, #952, #953, #954, #955, #956, #957, #958, #959, #960, #961, #962, #963, #964, #974, #975, #983, #1110, #1138, #1732, #1794, #1849, #1873, #1889, #1904, #1910, #2100

#### P6 — D5 (31)

- **D5** (31): #24, #265, #481, #484, #485, #486, #487, #501, #1126, #1376, #1683, #1699, #1702, #1762, #1763, #1764, #1765, #1766, #1767, #1768, #1769, #1820, #1821, #1822, #1825, #1826, #1827, #1828, #1829, #1835, #1963
### Б. Падающие тесты на `main@2eaa864` (переносимые крейты, Linux) и первый плохой коммит

Первые плохие коммиты найдены через `git bisect run` (оракул — тест-таргет) или по контрольным точкам 18/21/23/24.09.

| Таргет | Падает | Первый плохой коммит / с какого момента красный | Issue-владелец | В PR #2503 |
|---|---|---|---|---|
| eliot-store-api (4 таргета, счётчик каталога) | 9 | `f904e633` 22.09 «storage: add canonical finish decision mutation» (#325), затем #2392/#2398/#2407 | #19, #325 | исправлено |
| eliot-store-memory `--lib` | 10 | `81782f52` 23.09 #2456 «fix(gate): close root HOLD clippy findings for issue 18-a4»: под этим заголовком влито изменение `PreparedTransition` на +2211/−694 строк | #18, #63 | 9 из 10 |
| eliot-store-memory `memory_store_clone` | 7 | `81782f52` (#2456) | #18 | исправлено |
| eliot-blob-api `residency_contract` | 1 | красный как минимум с 18.09 (миграция `EpochId` #64) | #64, #19 | исправлено |
| eliot-epistemic-context-provider | 1 | контракт получил обязательное `owner` | #38 | исправлено |
| eliot-dreamer-self-query | 9 | `01b01b9c` 22.09 (#223 B lane: пересчёт `pair_key`) | #223, #262 | исправлено |
| eliot-improvement `learning_closure` case_58 | 1 | `fb99c25c` 24.09 (#1866): слово «asynchronously» ловится source-guard `async` | #1866 | исправлено |
| eliot-governor `--lib` owner_closure_provider | 6 | `8114a99b` 22.09 «work/2100: restore proof-phase test source…» | #2100, #1732 | нет — нужно решение владельца |
| eliot-authority `grant_closure_delegation` | 3 | красный с появления (#2100) | #2100, #1110 | нет |
| eliot-kernel-core `--lib` grant activation restart | 1 | `ca84b712` 23.09 «feat(backup-link): prepare exact backup dependency links (#974)» | #974, #2100 | нет |
| eliot-protocol `--test backup` | 3 | B-BACKUP-волна | #954, #960 | нет |
| eliot-types `cue_kind_legacy_boundary` | 2 | `7bdfe575` 23.09 (#66, #2431) — дрейф замороженных digest-манифестов | #706, #835 | нет |
| eliot-cognitive-quality | 2 | продуктовый баг: одинаковые `coverage_digest` отвергаются как duplicate | #259 | нет |
| eliot-wasm-runtime `typed_runtime` | 1 | красный как минимум с 18.09 | #760 | нет |

Итого: 58 падений. PR #2503 исправляет 36 (дрейф фикстур); 22 требуют решения владельца.

### В. Жёсткие нарушения архитектурных границ (`python scripts/audit-architecture-boundaries.py`, hard=41)

| Правило | Пакет | Суть |
|---|---|---|
| `runtime_root_forbidden_direct_dependency` | `eliot-kernel` #15 | Direct dependency 'eliot-store-surreal-adapter' violates the runtime-root boundary. |
| `runtime_root_forbidden_direct_dependency` | `eliot-native-worker` #22 | Direct dependency 'eliot-agent-claude' violates the runtime-root boundary. |
| `runtime_root_forbidden_direct_dependency` | `eliot-native-worker` #22 | Direct dependency 'eliot-agent-codex' violates the runtime-root boundary. |
| `runtime_root_forbidden_direct_dependency` | `eliot-native-worker` #22 | Direct dependency 'eliot-agent-opencode' violates the runtime-root boundary. |
| `runtime_root_forbidden_direct_dependency` | `eliotd` #18 | Direct dependency 'eliot-dreamer-bundle' violates the runtime-root boundary. |
| `runtime_root_forbidden_direct_dependency` | `eliotd` #18 | Direct dependency 'eliot-dreamer-candidate-validation' violates the runtime-root boundary. |
| `runtime_root_forbidden_direct_dependency` | `eliotd` #18 | Direct dependency 'eliot-dreamer-claim-grounding' violates the runtime-root boundary. |
| `runtime_root_forbidden_direct_dependency` | `eliotd` #18 | Direct dependency 'eliot-dreamer-contracts' violates the runtime-root boundary. |
| `runtime_root_forbidden_direct_dependency` | `eliotd` #18 | Direct dependency 'eliot-dreamer-memory-revision' violates the runtime-root boundary. |
| `runtime_root_forbidden_direct_dependency` | `eliotd` #18 | Direct dependency 'eliot-dreamer-probe-plan' violates the runtime-root boundary. |
| `runtime_root_forbidden_direct_dependency` | `eliotd` #18 | Direct dependency 'eliot-dreamer-rival-model' violates the runtime-root boundary. |
| `untracked_direct_process_launch` | `eliot-host`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 877 (construct, test-gated, cfg=['test'], item |
| `untracked_direct_process_launch` | `eliot-host`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 1013 (construct, test-gated, cfg=['test', 'win |
| `untracked_direct_process_launch` | `eliot-host`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 2144 (construct, test-gated, cfg=['test', 'win |
| `untracked_direct_process_launch` | `eliot-host`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 2738 (construct, test-gated, cfg=['test'], ite |
| `untracked_direct_process_launch` | `eliot-host`  | Direct std/tokio process launch is outside a declared process owner and has no exact debt record. |
| `untracked_direct_process_launch` | `eliot-store-surreal`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 1126 (construct, test-gated, cfg=['test'], ite |
| `untracked_direct_process_launch` | `eliot-git-bridge`  | Direct std/tokio process launch is outside a declared process owner and has no exact debt record. |
| `untracked_direct_process_launch` | `eliot-app`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 993 (construct, production, item='run_worker') |
| `untracked_direct_process_launch` | `eliot-app`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 1211 (construct, production, item='validate_bo |
| `untracked_direct_process_launch` | `eliot-app`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 1312 (construct, production, item='current_win |
| `untracked_direct_process_launch` | `eliot-engine`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 406 (construct, production, item='probe'): let |
| `untracked_direct_process_launch` | `eliot-engine`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 408 (construct, test-gated, cfg=['test'], item |
| `untracked_direct_process_launch` | `eliot-engine`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 575 (construct, production, item='run_process' |
| `untracked_direct_process_launch` | `eliot-engine`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 1638 (construct, test-gated, cfg=['test'], ite |
| `untracked_direct_process_launch` | `eliot-engine`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 198 (construct, test-gated, cfg=['test'], item |
| `untracked_direct_process_launch` | `eliot-store`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 230 (construct, test-gated, cfg=['all', 'featu |
| `untracked_direct_process_launch` | `eliot-windows-ipc`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 1488 (raw-launch, production, item='spawn_name |
| `untracked_direct_process_launch` | `eliot-testd-core`  | Direct std/tokio process launch is outside a declared process owner and has no exact debt record. |
| `untracked_direct_process_launch` | `eliot-verifier`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 920 (construct, test-gated, cfg=['test'], item |
| `untracked_direct_process_launch` | `eliot-host-state`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 1958 (construct, test-gated, cfg=['test', 'win |
| `untracked_direct_process_launch` | `eliot-installation`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 3428 (construct, test-gated, cfg=['test', 'win |
| `untracked_direct_process_launch` | `eliot-ipc`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 3812 (construct, test-gated, cfg=['test', 'win |
| `untracked_direct_process_launch` | `eliot-kernel-service`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 2244 (construct, test-gated, cfg=['test'], ite |
| `untracked_direct_process_launch` | `eliot-runtime-status`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 5211 (construct, test-gated, cfg=['test'], ite |
| `untracked_direct_process_launch` | `eliot-store-surreal-adapter`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 2416 (construct, test-gated, cfg=['test', 'win |
| `untracked_direct_process_launch` | `eliot-store-surreal-adapter`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 3619 (construct, test-gated, cfg=['all', 'test |
| `untracked_direct_process_launch` | `eliot-store-surreal-adapter`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 215 (construct, production, item='spawn_provid |
| `untracked_direct_process_launch` | `eliot-store-surreal-adapter`  | Direct std/tokio process launch is outside a declared process owner and has no exact debt record. |
| `untracked_direct_process_launch` | `eliot-store-surreal-adapter`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 691 (construct, test-gated, cfg=['all', 'test' |
| `untracked_direct_process_launch` | `eliot-live-canary`  | Direct process launch outside a declared process owner missed by the legacy constructor gate has no exact debt record: line 4533 (construct, test-gated, cfg=['test', 'win |
### Г. Размер обязательного чтения (`docs_read.py read --path X`)

| Путь | Обязательных элементов | Байт пакета |
|---|---|---|
| `bins/eliotd/src/lib.rs` | 23 | 83 957 |
| `crates/storage/eliot-store-api/src/payload_authority.rs` | 39 | 117 124 |
| `crates/smart/eliot-context-admission/src/lib.rs` | 36 | 96 395 |
| `crates/kernel/eliot-ors/src/lib.rs` | 39 | 143 869 |
| `bins/eliot-kernel/src/lib.rs` | 37 | 137 324 |
| `crates/governor/eliot-finish/src/lib.rs` | 24 | 85 426 |
| `bins/eliot-agent-bridge/src/kernel_activation_client.rs` | 47 | 150 690 (без I07-20) |
| `crates/kernel/eliot-platform-windows/src/tests.rs` (однострочная правка теста) | 53 | ≈150 000 |
| `docs/PROJECT_MAP.md` | 24 | 98 902 |

### Д. «Code today» в audit-Issue устарел или неверен

Автоматическая проверка: в разделе «Code today» 244 открытых «I*-audit» Issue найдено 167 утверждений вида «инвентарь не находит `X`» с конкретным идентификатором. **117 из них (70%) указывают на символы или крейты, которые на `main` есть** (65 Issue). Часть появилась уже после создания Issue, часть была неверна изначально: Issue сгенерированы по «inventory», без чтения кода. Перед работой по такому Issue раздел «Code today» нужно перепроверить по коду. Примеры:

| Issue | Заявлено как отсутствующее | На main есть |
|---|---|---|
| #1813 [I10-audit] Add governed Instrument Plane ownership instead  | `InstrumentProfileResolver`, `InstrumentRunner`, `TestExecutionPlane`, `eliot-testd` | `InstrumentRunner`, `TestExecutionPlane`, `eliot-testd` |
| #1925 [I5-audit] Implement complete opaque ORS staging and recover | `PreparedTransition`, `RecoveryPayloadEnvelope` | `PreparedTransition`, `RecoveryPayloadEnvelope` |
| #1875 [I7-audit] Implement durable EventEnvelope replay, persisten | `DeliveryOutcome`, `EventAckReceipt`, `EventEnvelope`, `Frame`, `OperationOutcome` | `DeliveryOutcome`, `EventAckReceipt`, `EventEnvelope`, `Frame`, `OperationOutcome` |
| #1884 [I1-audit] Persist and enforce immutable KernelExecutionMani | `AuthorityHandoffRecord`, `KernelExecutionManifest`, `ProcessStartReplayRecord` | `AuthorityHandoffRecord`, `KernelExecutionManifest`, `ProcessStartReplayRecord` |
| #1894 [I2-audit] Generate mandatory contract, context, and test ca | `CrateContextCapsule`, `ModuleContractKit`, `ModuleTestCapsule`, `module.toml` | `CrateContextCapsule`, `ModuleContractKit`, `ModuleTestCapsule` |
| #1901 [I18-audit] Add host-route acceptance proof for the working  | `RouteFingerprint` | `RouteFingerprint` |
| #1764 [I21-audit] Add the AllowedReferenceManifest firewall before | `AllowedReferenceManifest`, `eliot-dreamer-research-synthesis`, `eliot-mod-research`, `eliot-research-exchange`, `eliot-research-exchange-api` | `AllowedReferenceManifest`, `eliot-dreamer-research-synthesis`, `eliot-mod-research`, `eliot-research-exchange`, `eliot-research-exchange-api` |
| #1874 [I5-audit] Add the required active operational-spine mutatio | `WriteReceipt`, `WriteSubmission` | `WriteReceipt` |
| #1690 [I14-audit] Add durable unknown-commit recovery to canonical | `WriteReceipt` | `WriteReceipt` |
| #1739 [I7-audit] Implement all eight canonical MCP operations thro | `coordinate`, `finish`, `observe`, `packet`, `state` | `finish`, `observe`, `packet`, `state`, `verify` |
| #1851 [I17-audit] Make the Windows guardian the sole ProcessExecut | `ProcessExecutor` | `ProcessExecutor` |
| #1926 [I5-audit] Add Kernel WriteCoordinator reservations and per- | `AdmissionReservation`, `WriteReceipt`, `WriterReservationToken` | `AdmissionReservation`, `WriteReceipt`, `WriterReservationToken` |

### Е. Пересечения и дубли (один писатель на кластер)

| Кластер | Issue |
|---|---|
| Эпоха с lineage | #64, #1795 (дубль), #1968 |
| ORS recovery envelopes | #1713, #1925 (дубль), #269 |
| Strict finish | #325, #1741, #1915, #370, #1809 |
| Единый ProcessExecutor | #1812, #1851, #748, #267/#269/#271/#297, закрытый #100 |
| Legacy-конфигурация | #1219, #1687, #1966 |
| Backup/ECXF/memory-store: подключить или удалить | #1141, #1716 (утверждение о «владельце без зависимостей» устарело после #2472), #1871, #1872 |
| Session, scope, task admission | #8, #1746, #1807, #66/#203/#204/#839/#1115 |
| Legacy-вход и релизный bundle | #1719, #1227, #1858, #18 (W11/W12), закрытый #1189 |
| Handshake и совместимость | #1968, #1890, #1876 |
| Startup и readiness | #1967, #1892, #1972 |
| Health и lifecycle | #1970, #1891 |
| Admission saga | #1678, #1701 |
| Instrument plane | #1813, #1814, #1128, #1802, #1852 |
