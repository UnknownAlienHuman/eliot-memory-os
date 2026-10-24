# Eliot V3 — реестр анализа

**Статус на 2026-10-24 · нормативная база draft.4/draft.17/draft.7; controller `38db378c`; старые I9.4/I9.10/I3.6/I10.11; активный рабочий реестр, не runtime gate.**

Этот файл отвечает на четыре вопроса:

1. что именно проверено;
2. на каком основании;
3. какое решение принято или какой разрыв найден;
4. что проверять следующим.

[Architecture](ARCHITECTURE.md), [Implementation](IMPLEMENTATION.md) и [Cognition](COGNITION.md) — нормативный проект. [AUDIT](AUDIT.md) — доказательная база и итоговый разбор. [AUDIT-MAP](AUDIT-MAP.md) — стабильная матрица исходных требований, исторических аудитов и доноров. **Этот файл — единственный активный реестр дальнейшего анализа.**

## 1. Статусы и правила

| Статус | Значение |
|---|---|
| `CHECKED` | Указанный source/design scope прочитан и согласован с выводом. Не означает работающий runtime. |
| `DECIDED` | Для V3 выбрано конкретное решение; код ещё не проверен. |
| `PARTIAL` | Прочитан связанный путь/часть донора, но остаётся существенный непроверенный edge. |
| `GAP` | В выбранном producer→operation→result→consumer пути отсутствует необходимая связь. |
| `OPEN` | Решение/источник ещё требует проверки. |
| `BLOCKED` | Нужный источник недоступен. |
| `NOT SELECTED` | Механизм не нужен выбранной конструкции; это не полный аудит донора. |

Правила:

- строка называет точный объект, а не тему вообще;
- README, search hit, DTO, fixture или receipt не дают `CHECKED` для runtime;
- исправление документа даёт `DECIDED`/`CHECKED` для design, не `IMPLEMENTED`;
- `IMPLEMENTED` появится только после реального кода и наблюдаемого input→operation→result→consumer;
- подробная историческая хронология остаётся в Git/AUDIT; здесь — активное состояние;
- новый проход обновляет существующую строку либо добавляет материальный новый риск, а не отдельный отчёт.

## 2. Активная матрица V3

| ID | Объект | Проверенный scope | Статус | Решение / разрыв | Следующее действие |
|---|---|---|---|---|---|
| R-001 | Граница продукта и владельцы | Architecture §§1–3; Implementation §§1–3; старые I9.1/I9.3/T12 | `CHECKED` | Host/controller владеет внешними задачами/инструментами; Eliot — памятью и собственными finite jobs. Controller владеет route/provider execution, но не Memory job/publication. | Не возвращать Task/Attempt или provider stack внутрь Memory без нового реального consumer. |
| R-002 | Локальная process family и idle drain | Implementation §§1,10,12; V2 I1.5/I14.22; Windows primitives прежних проходов | `DECIDED` | Один supervisor, daemon и SurrealDB child; конечный drain; explicit shutdown не запускает DreamCycle. | Реализовать/проверить Windows lifetime, mutex, Job Object и cutover. |
| R-003 | Точный continuation address | Architecture §3.3; Implementation §§3.1,4.3,7; Cognition §2 | `DECIDED` | Project/workspace + реальный task либо actor/session; branch/path/HEAD — состояние. | Проверить два workspaces, branch switch, fork, transfer и late result. |
| R-004 | Context packet identity | Implementation §§5.5,6.2; Cognition §6 | `DECIDED` | Packet хранит фактически отрисованные revisions; handoff/use различены; отсутствие correlation не блокирует память. | Реализовать coherent hydration и host correlation без agent ACK-формы. |
| R-005 | Прямая структурированная поправка | Implementation §§5.1,5.3–5.4 | `DECIDED` | Correction observation + revision/history + saved result в одной caller-owned transaction; replay не применяет правку повторно. | Реализовать один command path и conflict/readback. |
| R-006 | Шесть таблиц и Store operations | Implementation §§4–5 | `PARTIAL` | Общая схема и операции определены; SQL/indexes не выполнены. | Реализовать migration/query files и проверить планы/объём чтения. |
| R-007 | Revision/history/current state | Architecture §4.3; Implementation §§4.3–4.5,5.3; Cognition §§3,8 | `DECIDED` | Exact version handle; current/history не подменяют друг друга; split не перенаправляет старые handles. | Реализовать atomic publication/historical reads и restart readback. |
| R-008 | Compound grounds и propagation | Architecture §4.5; Implementation §8.5; Cognition §3.2 | `PARTIAL` | Required groups, alternative groups и advisory support разделены; targeted propagation выбрана. | Реализовать reducer/reverse traversal; проверить cycles, erase и concurrent changes. |
| R-009 | Retrieval arms и packet grouping | Implementation §§5.5,7–8; Cognition §6 | `PARTIAL` | Exact/lexical/vector/relation arms независимы; grouping не merge IDs/evidence. | Проверить реальные tokens/plans/bytes, OR noise и exception outside top-k. |
| R-010 | Реальный consumer processing method | Implementation §§5.2,9.2,10.3; Cognition §§7,9.2 | `DECIDED` | Job freezes exact recipe revision; request builder вставляет её в один text inference request. | Реализовать и показать изменившийся следующий request/context после revision. |
| R-011 | Cross-project reuse и disclosure | Architecture §4.4; Implementation §§4.3,5.5; Cognition §9.4; R-050 | `DECIDED` | Origin отдельно от reuse scope. Shared method не расширяет disclosure его sources; instance facts не становятся общими. | Реализовать local/selected/owner queries и deterministic inference-disclosure reduction. |
| R-012 | Native hook → observation | Implementation §6.1; Claude hook docs; claude-mem selected path | `PARTIAL` | IDs/representations/final-message distinction определены; donor теряет `last_assistant_message` в выбранном path. | Проверить installed payload/version и один реальный relay. |
| R-013 | Native context delivery | Implementation §6.2; Claude hook contracts | `PARTIAL` | Next-model boundaries и bounded JSON output выбраны; write != acceptance/use. | Проверить installed serialization, overflow, resume/child и duplicate boundary. |
| R-014 | Controller Task/agent result route | Controller `38db378c`: TaskSpec/claim/dispatch/Claude result | `PARTIAL` | Годится для agent work, но требует Task/requirement/Attempt/binding и не выбран для one-shot Memory inference. R-027/R-046 остаются его gaps. | Сохранить optional richer route; не использовать как baseline `episode_learning`. |
| R-015 | Batch embeddings contract | Implementation §9.3; Mem0/provider docs прежних проходов | `GAP` | `EmbeddingClient` и target `inference.embed` определены; метода нет в inspected controller catalog. | Реализовать controller route и per-item result; затем Memory handler/query arm. |
| R-016 | Research request→report→source | Research `7c034569` selected callers; Implementation §9.4 | `PARTIAL` | Реальные run/status/report/section/citation operations найдены; R-031/R-032 не исправлены. | Исправить Research owners и квалифицировать один профиль. |
| R-017 | Project structure и Eliot self-view | Implementation §8.3; old structure adapter scope | `PARTIAL` | Scoped versioned views выбраны; structural tool/deployment не квалифицирован. | Проверить два checkouts, late result и affected-view refresh. |
| R-018 | Document→representation→open | Docling/Core selected paths; Implementation §8.4 | `PARTIAL` | Original bytes, retained representation, excerpts и exact open определены; decode/asset path не выполнен. | Реальная conversion/readback с partial pages/images и cost bounds. |
| R-019 | Backup/restore | Implementation §12; Surreal/V2 restore reads прежних проходов | `PARTIAL` | Native logical export + blobs + fresh candidate restore выбраны. | Выполнить Base round-trip и Windows cutover. |
| R-020 | Erasure и reappearance | Architecture §4.7; Implementation §12.1; Cognition §14; R-051 | `PARTIAL` | Withdrawal, exposure, refutation и physical erase разделены. Durable controller inference copy является controlled duplicate, пока owner не предоставляет release/cleanup. | Реализовать reference traversal, backups/spool/late result cleanup и controller result release/readback limit. |
| R-021 | Recursive improvement | Architecture §7; Cognition §11 | `PARTIAL` | Исправляется конкретный failed edge; no global intelligence score/mandatory grader. | Выполнить connected request→revision→next context после R-048/R-050. |
| R-022 | Disagreement/anticipation | Architecture §8; Cognition §12 | `CHECKED` | Alternatives + grounds + cheapest discriminating observation; no voting; expiry != outcome. | Реализовать ordinary records after core path. |
| R-023 | Direct control/status/inbox | Implementation §13; R-050 | `DECIDED` | Статус выводится из actual composition/jobs/results. Route profile availability/locality и missing usage отображаются как факты, без separate readiness registry. | Реализовать configure/off/pause/cancel/status/inbox и inference profile visibility. |
| R-024 | Normative-document consistency | Architecture draft.4; Implementation draft.17; Cognition draft.7; README 24.10; R-050/R-051 | `PARTIAL` | Task lifecycle удалён и one-shot route согласован, но route profile/privacy/budget/result cleanup пока названы общо и не сведены в один нормативный контракт. | Синхронизировать Architecture/Implementation/Cognition/README после этого registry decision. |
| R-025 | Что запускает интерпретацию | Implementation §§5.1,10.5 | `DECIDED` | New relevant input/correction/question; accounting/read/embedding completion не self-trigger. | Проверить enqueue callers и absence of loops. |
| R-026 | Active/pending job и eligibility | Implementation §§4.6,5.2,10.5 | `DECIDED` | Один active + coalesced pending target; first queued time сохраняется; waiting не retry. | Проверить continuous arrivals, two projects, off/idle/background и shutdown. |
| R-027 | Controller result→public artifact handle | Controller `5b6b5bee/38db378c` result writers/projection | `GAP` | `agent.result`/assembly сохраняют nested artifact refs, public projection их теряет. | Исправить owner projection для agent route; новый `inference.text` должен сразу вернуть usable result readback. |
| R-028 | Первый recipe bootstrap | Implementation §10.3; Cognition §7.2 | `DECIDED` | Реальный bundled text сохраняется при enable purpose; restart/upgrade не затирает изменённый method. | Реализовать unique purpose address и first enable. |
| R-029 | Outcome→next decision | Implementation §10.4; Cognition §9.3 | `DECIDED` | Один current contribution на method revision/attempt/criterion; context и learning — consumers. | Реализовать reducer и correction/contradiction cases. |
| R-030 | Multi-stream/late events/coverage | Implementation §10.1; Cognition §4 | `DECIDED` | Per-stream bounds and supplied-vs-covered distinction; no global high-water mark. | Проверить late child, partial body, omitted handle и successor. |
| R-031 | Research MCP request decoder | Research `7c034569` MCP/service parser | `GAP` | MCP old shape rejects newer selected method/model request before capable service. | Связать discovery/MCP с current application decoder. |
| R-032 | Research citation depends on active index | Research `7c034569` citation reader | `GAP` | Known retained citation can fail before source bytes if search projection changed. | Read saved representation/range directly under existing access. |
| R-033 | Useful Base/layers/light extensions | Old A2.3/I2.19/I6.4; Architecture §3; Implementation §2 | `DECIDED` | One package start, acyclic modules, Base and independent vertical increments; no module platform. | При коде контролировать imports/features/startup and Base without extensions. |
| R-034 | Encoder→derived vector→context | Implementation §§5.4,8.2,9.3 | `DECIDED` | Separate query/document role, effective space, partial batch; semantic revision unchanged. | После R-015 выполнить one connected semantic query. |
| R-035 | Architecture overconstraints | Full normative rereads from prior passes; old route/privacy pass | `DECIDED` | Unknown attribution/grounds no longer global blockers. Privacy and cost keep narrow deterministic checks; they do not restore Governor/capability evidence/fingerprint platforms. | Не превращать missing metadata в permission gate outside the actual external-send boundary. |
| R-036 | Commitment lifecycle | Architecture §8; Implementation surface/control; old A7.5/A11.5 | `DECIDED` | Ordinary memory item; context/inbox readers; ACK/due/expiry do not resolve. | Реализовать explicit create/update/read; notifications later. |
| R-037 | Stable work identity and scoped facts | Architecture §3.3; Implementation §3.1; Cognition §§2–3 | `DECIDED` | Project/workspace/task identity separated from branch/location/version/time. | Реальный attach/capture/query/late result path. |
| R-038 | Resource/version/representation continuity | Architecture §4.2; Implementation §4.7; Cognition §4 | `DECIDED` | Dirty bytes retained; rename/copy links do not rewrite old IDs; equal bytes != same source. | Проверить partial read after edit/move and conversions. |
| R-039 | Decision frame→lexical query | Implementation §8.1 | `DECIDED` | Focused question + exact cues; native OR candidate arm; no LLM query planner. | Выполнить actual query/tokens/noise/empty input. |
| R-040 | Bounded source reading | Implementation §§5.6,7.2,8.4 | `DECIDED` | Metadata/excerpt first, selected ranges next; row limit != byte/decode limit. | Реальные file/Store readers, UTF-8 range and long JSON/line. |
| R-041 | Automatic work and drain | Implementation §§1.3,10.5; R-050 | `DECIDED` | off/idle/background; finite drain; stopped process waits next use/external wake. Automatic model work additionally requires an inference profile that explicitly permits automatic use. | Реализовать one automatic episode path after manual path. |
| R-042 | Curation result consumer | Cognition §§8,10 | `DECIDED` | Output must change normal context/open/method request; unread report not completion. | Проверить same relevant request before/after revision. |
| R-043 | Consolidation/split without ID merge | Cognition §8 | `DECIDED` | Replay/grouping/revision/new synthesis/split distinct; sources survive. | Реализовать ordinary curation publication and historical handles. |
| R-044 | Forgetting changes reader | Cognition §14; Mem0 selected mutation/reader trace | `DECIDED` | Current reader uses current revision links; rare/unused not false. | Проверить correction after restart and scoped negative memory. |
| R-045 | First episode recipe/result | Cognition §7; old I9.4/I9.5/I9.7/I9.10; Hy-Memory extractor path | `DECIDED` | Concrete instruction, zero-or-more changes, typed result, valid no-change and explicit partial/error. | Run only after R-048/R-050; then useful/no-change/partial/malformed/conflict cases. |
| R-046 | Claude terminal body durability | Controller Claude stream/result path | `GAP` | Current agent route keeps result body in boot-local bounded LRU before page capture. | Fix in controller adapter if optional agent route is used; unrelated to new direct inference result path. |
| R-047 | One inference without second task manager | Old I9.1/I9.3/T12; controller Task path; Architecture/Implementation 24.10 | `CHECKED` design / `NOT IMPLEMENTED` runtime | One Memory job owns input/coverage/publication; controller one-shot inference owns external model execution only. | Implement R-048/R-050; do not create Task/Attempt or direct provider stack in Memory. |
| R-048 | Controller `inference.text` / `inference.embed` | Current method catalog/source at controller `38db378c`; code search | `GAP` | Narrow methods are absent in inspected current catalog. Existing `Route` is agent/workspace-oriented and cannot be reused unchanged as the inference profile. | Implement closed one-shot methods plus the minimal profile in R-050, dedup, durable result/readback and unknown outcome without Task/Attempt. |
| R-049 | Code-first and test timing | User direction; Implementation §14; README | `DECIDED` | Production path first, minimum build/Clippy per coherent increment; no speculative test platform. Full automated suite after connected product implementation. | During coding record minimal Clippy; later build tests around specified observable paths. |
| R-050 | Minimal inference profile, privacy and budget | Old I9.4/I9.10/I3.6/I10.11; old `RuntimeRoute`; controller `config::Route`/example `38db378c` | `DECIDED` design / `NOT IMPLEMENTED` runtime | Use a separate static `InferenceProfile`, not agent `Route`, untyped `native_options` or old Governor registry. Minimum fields: adapter/connection ref/model, `local|external`, automatic-use flag, max input bytes/output tokens/timeout/concurrency, no implicit fallback. Memory request carries `local_only|external_allowed`; local-only input cannot use an external profile. Controller freezes the resolved profile snapshot/revision and returns requested/observed route facts plus usage/cost as value-or-unknown. | Синхронизировать нормативные документы, затем определить controller config/contract и Memory disclosure reduction. |
| R-051 | Inference result copy lifecycle and erasure | Controller public artifact/method catalog `38db378c`; Memory §12 | `GAP` | Inspected public artifact surface has get/read/parts/assemble, but no release/delete path. A durable inference result copied into Memory would otherwise remain a second controlled content copy indefinitely. | Controller must retain until Memory durably copies/acknowledges, then make the operation-owned copy releasable/cleanable. Erasure reports incomplete until that copy is gone; do not add a general retention graph. |

## 3. Source coverage

| ID | Источник | Статус | Граница вывода |
|---|---|---|---|
| S-001 | V1 Canonical Master | `CHECKED` для ранее прочитанного полного документа до §40 | Requirements read; не полный code audit V1. |
| S-002 | V2 Architecture/Implementation selected sections | `PARTIAL` | Много разделов перечитано по конкретным вопросам; весь 20k-line корпус не объявлен свежо проверенным. |
| S-003 | Claude audit revision 4 | `CHECKED` как предоставленный полный текст | Использован как source of ideas, не автоматический норматив. |
| S-004 | ELIOT audit v9 | `CHECKED` как предоставленный текст | Historical findings не перезапускались на каждом новом SHA. |
| S-005 | Swarm audit 2026-10-06 | `CHECKED` как предоставленный текст | Controller ownership отделён от Memory. |
| S-006 | August architecture audit | `CHECKED` как предоставленный текст | Proof/policy machinery не перенесена автоматически. |
| S-007 | LLM problems report | `CHECKED` как предоставленный текст | Failure classes mapped; incidents not reproduced. |
| S-008 | Release ZIP `audit-2026-10-16-incomplete` | `BLOCKED` | Metadata известно; полный 968-file semantic review не заявлен. |
| S-009 | `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | `BLOCKED` | Полный текст отсутствует. |
| S-010 | Donors D01–D47, Hy-Memory, Mem0, Docling, Research, controller | `PARTIAL` | Findings относятся к exact paths/revisions; ни один продукт не квалифицирован целиком. |
| S-011 | Independent subagent review | `OPEN` | В этом проходе независимого subagent review не было. |
| S-012 | Consolidated failure audit 2026-08-05 | `PARTIAL` | Проверен named curation preview path; historical counts/runtime not reproduced. |
| S-013 | Текущий controller inference boundary | `CHECKED` для Task/claim/dispatch/Claude path и method catalog на `38db378c` | Установлена цена Task lifecycle и отсутствие narrow inference methods; provider/live routes не запускались. |
| S-014 | Route/privacy/budget/result-lifecycle pass | `CHECKED` для old I9.4/I9.10/I3.6/I10.11, old route registry, controller config/Route/artifact public catalog | Установлены минимально сохраняемые требования и отсутствие ready inference profile/result-release. Это не полный security audit или live provider qualification. |

### Источники прохода 2026-10-24 — inference route profile

Прочитаны:

- старые `I09-04-dreamer-input-bundle.md`, `I09-10-model-routing.md`, `I03-06-model-route-and-portfolio-policy.md`, `I10-11-external-model-bridges.md` и `I10-04-codex-app-server-profile.md`;
- старый `RuntimeRoute`/route fingerprint implementation;
- controller `38db378c` `config/controller.example.toml`, `config::Route`, mutation/read method catalog и public artifact surface;
- текущие V3 Architecture/Implementation/Cognition/registry на `10f864d7`.

Установлено:

1. старые требования содержат полезные четыре инварианта: bounded input/output, privacy locality, requested/observed route distinction и запрет silent materially different fallback;
2. старые policy/route/fingerprint/capability evidence/portfolio structures значительно шире первого one-shot consumer и не должны возвращаться;
3. controller current `Route` предназначен для agent runtimes: alias/runtime/module artifact, workspace/native options and binding concurrency; у него нет narrow inference semantics;
4. переиспользование этого `Route` через `native_options` смешало бы workspace/session/tool semantics с one-shot model call;
5. начальный `InferenceProfile` должен быть обычной статической config record, не dynamic registry;
6. two-state request privacy `local_only|external_allowed` сохраняет нужную old I9.4 границу без taxonomy engine;
7. source/project disclosure cannot be silently omitted to make a remote route pass; route mismatch yields a specific waiting/rejected result or explicit local profile selection;
8. initial profile has no fallback ladder. Unavailable/over-budget route remains unavailable rather than changing provider, model, locality or billing;
9. automatic learning requires both Memory automatic mode and profile `allow_automatic=true`;
10. controller records profile snapshot/revision and requested/observed route/model; usage/cost unavailable remains unknown, not zero;
11. inspected artifact surface has public read operations and assembly, but no reviewed release/delete operation for a copied inference body;
12. therefore durable readback and eventual cleanup are separate requirements; Memory erasure cannot claim completion while its controller-owned copy remains.

Отброшенные средства:

- old Governor `RuntimeRoute`, capability registry, route evidence and fingerprint matrix;
- role-cardinality/privacy admission envelope for every internal Memory job;
- model-generated route classifier, fallback portfolio or per-call approval;
- untyped provider/secret fields in Memory or `native_options` as the inference contract;
- silent omission of protected sources;
- silent provider/model/locality fallback;
- a general artifact retention graph in Memory.

Проектные контрпримеры, не прогоны:

- project is `local_only`, profile was reconfigured from local to remote before first admission;
- mixed input contains one stricter local-only source; dropping it would change the cognitive question;
- automatic curation selects an expensive/manual-only profile;
- provider returns another model behind an alias;
- usage/cost is absent and gets counted as zero;
- controller completes inference, Memory copies the result, then user erases the episode while controller retains its artifact;
- profile unavailable: implementation silently falls back to another provider;
- retry after lost reply uses same profile name but a different resolved profile snapshot.

## 4. Решения, которые не открываются без нового основания

- не переносить V1/V2 runtime и compatibility facades;
- не создавать второй task manager, swarm, research engine или semantic DB;
- не создавать provider/credential/router stack внутри Memory при выбранном controller owner;
- не использовать controller Task/Attempt для обычного one-shot memory inference;
- не переиспользовать agent `Route`/workspace/native session contract как generic inference profile;
- не возвращать old Governor route/capability/fingerprint platform;
- не создавать permanent Dreamer process/model loop;
- не блокировать capture/read из-за inference, vectors, graph, map или telemetry;
- не использовать similarity как authority/truth/applicability proof;
- не считать fixture, receipt, stored ID или shape-valid object работающей функцией;
- не создавать SkillRegistry/OutcomeStore/TruthRegistry/PacketStore;
- не требовать promotion/experiment/approval для каждой provisional lesson;
- не строить universal plugin/query/workflow framework до второго реального consumer;
- не менять production behavior ради ложного тестового ожидания;
- не объявлять source/donor/runtime coverage шире фактически прочитанного/наблюдаемого.

## 5. Очередь

| Priority | Работа | Закрывает |
|---|---|---|
| P1 | Синхронизировать Architecture/Implementation/Cognition/README с R-050/R-051: static inference profile, two-state disclosure, finite limits, no fallback, result acknowledgement/release | R-020, R-024, R-035, R-041, R-047–R-051 |
| P1 | В controller определить `inference.text`/`inference.embed`, отдельный `InferenceProfile`, method policy, dedup, frozen profile snapshot, durable result/readback и narrow release/cleanup без Task/Attempt | R-015, R-027, R-048, R-050, R-051 |
| P1 | В Memory определить project/source disclosure inheritance and reduction; protected input is not silently dropped and external mismatch is not no-change | R-011, R-020, R-045, R-050, R-051 |
| P1 | Затем реализовывать Base Slices 1–2: lifecycle, capture, revisions, exact/lexical context/open, maintenance | R-001–R-013, R-019–R-026, R-033, R-036–R-040 |
| P1 | После Base реализовать one connected learning path через controller inference: recipe→retained request/result→decode→revision→next context | R-010, R-021, R-028–R-030, R-041–R-045, R-047–R-051 |
| P2 | Исправить optional controller agent-result projection/source retention только для реального agent-route consumer | R-014, R-027, R-046 |
| P2 | Реализовать vector handler/query после `inference.embed` | R-015, R-034, R-050 |
| P2 | Исправить Research parser/citation reader и подключить один профиль | R-016, R-031, R-032 |
| P2 | Реализовать Docling/project-view/grounds paths как независимые increments | R-008, R-017, R-018, R-038, R-040 |
| P3 | Получить недоступные ZIP/report | S-008, S-009 |
| P3 | Углублять донора только под незакрытый выбранный механизм | S-010 |
| Final | После connected implementation построить/запустить full test suite; во время разработки только minimum relevant build/Clippy | R-049 |

## 6. Последние изменения

| Дата / baseline | Изменение |
|---|---|
| 2026-10-23 / `2ee24de2` | Первый конкретный `episode_learning` recipe и typed result. |
| 2026-10-23 / `2ab45985` | Прослежен controller TaskPrompt/result path; подтверждены R-027/R-046. |
| 2026-10-24 / `d97b9bfb` | Установлено, что controller Task lifecycle избыточен для one-shot learning; временно выбран direct TextInferenceClient. |
| 2026-10-24 / `10f864d7` | Provider stack оставлен у controller; выбраны narrow `inference.text`/`inference.embed`; normative docs синхронизированы. |
| 2026-10-24 / current route-profile pass | Из old privacy/budget/routing требований оставлены bounded input/output, locality, requested/observed route и no silent fallback. Выбраны static `InferenceProfile`, two-state disclosure и explicit result release; добавлены R-050/R-051. |
